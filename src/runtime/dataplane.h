// ============================================================================
// dataplane.h - VGWW data plane orchestrator.
//
// Thread topology (design spec section 4):
//   RX/TX thread (1) : ReadPackets -> classify -> dispatch. ARP and ICMP-to-
//                      gateway are answered inline; TCP frames are copied into
//                      pool blocks and pushed to per-worker SPSC rings; the
//                      adapter runs in bypass LISTEN mode so the host keeps
//                      working untouched.
//   Worker threads(N): pump xtcp shards (OnPacket/PollAckTimers); xtcp emits
//                      response packets through StackBackend into the calling
//                      worker's TX ring; the RX/TX thread drains all rings.
//   Control thread(1): neighbor-table Tick (drain/age/publish snapshots).
//
// Scope: ARP + ICMP answering/relay (relay::IcmpRelay), and the transparent
// TCP relay: accepted flows are dialled upstream and bridged to the client by
// relay::TcpRelay (relay/tcp_relay.{h,cpp}, wired in
// runtime/dataplane.cpp:2036-2100 DrainAccepts).
// ============================================================================
#pragma once

#include "bridge/bridge.h"
#include "core/config.h"
#include "driver/idriver_client.h"
#include "net/ip_addr.h"

#include <array>
#include <atomic>
#include <cstddef>
#include <memory>
#include <string>
#include <vector>

namespace vgww {
    namespace runtime {

        /// batch142: the data plane's DUID text parser, exposed so every entry
        /// that must COMPARE DUIDs can compare them by VALUE. The DHCPv6
        /// duplicate check used to compare the POSTed text against the
        /// canonical text the snapshot returns, so any other legal spelling
        /// (upper case, '-' / '.' separators, no separators) slipped past
        /// "binding exists" and the store - keyed by the PARSED bytes -
        /// silently upserted, replacing the existing binding.
        bool ParseDuidText(const std::string& text, std::vector<uint8_t>& out);

        /// Canonical colon-separated lowercase hex text for a DUID (the same
        /// spelling GetDhcp6Bindings() reports).
        std::string FormatDuidText(const std::vector<uint8_t>& duid);

        class Dataplane final {
        public:
            /// `lease_file` anchors DHCP lease persistence; production passes
            /// a path derived from the config file location so leases survive
            /// restarts from any working directory (tests use the default).
            explicit Dataplane(const core::Config& config,
                               const std::string& lease_file = "leases.json");
            ~Dataplane();

            Dataplane(const Dataplane&) = delete;
            Dataplane& operator=(const Dataplane&) = delete;

            /// Test seam: injects an in-memory driver client BEFORE Start().
            /// Production leaves this unset - Start() opens NdisrdClient.
            void SetDriverClient(std::unique_ptr<driver::IDriverClient> client);

            // ------------------------------------------------------------------
            // L2 bridge (S3-Task3). Temporary wiring: Task 4 binds these to
            // the config file; until then tests drive them directly. The
            // bridge is disabled unless SetBridgeConfig enables it, so all
            // pre-bridge behavior is bit-for-bit unchanged by default.
            // ------------------------------------------------------------------

            /// Bridge wiring for the next Start(); call BEFORE Start().
            void SetBridgeConfig(const bridge::BridgeConfig& config);

            /// Current bridge state (stopped/running/failed).
            bridge::BridgeState GetBridgeState() const noexcept;

            /// batch34x: why the bridge last went to kFailed (empty when it
            /// never failed, or after a clean stop). RunBridgeLoop reports a
            /// machine reason ("port disappeared" / the driver read error);
            /// before this the only copy went to stderr, so the UI could say
            /// "bridge failed" but never which of the two happened.
            std::string GetBridgeError() const;

            /// Number of learned MACs (0 when the bridge is not running).
            size_t GetBridgeMacCount() const;
            /// batch34h: MAC-table evictions (a full table pushes the oldest
            /// entry out; that device then floods until it speaks again).
            uint64_t GetBridgeMacEvictions() const;

            /// batch34i: ARP/NDP learns REFUSED because the pending neighbour
            /// map hit kMaxPendingNeighbors. The guard stops a spoof flood, but
            /// while it is saturated a legitimate new device cannot resolve at
            /// all - previously with no trace anywhere.
            uint64_t GetNeighborRejections() const;

            /// Brings up driver mode, threads and the stack. Returns false on
            /// failure with `error` describing the reason.
            bool Start(std::string& error);

            /// Signals shutdown and joins every thread in reverse creation
            /// order; resets adapter mode so the host network stays intact.
            void Stop() noexcept;

            /// batch25a: the last Start()/Stop() failure text (empty after a
            /// successful call). Thread-safe: the UI publisher reads it while
            /// the command worker drives the lifecycle.
            std::string LastError() const;

            /// batch25a: lock-free lifecycle probe for the snapshot publisher
            /// (GetLifecycleCounts() must only be called while quiescent).
            bool IsRunning() const noexcept;

            /// Lifecycle telemetry / test seam: sizes of the containers a
            /// clean Stop() must reset to zero before the next Start().
            struct LifecycleCounts {
                size_t rx_rings = 0;       ///< RX-ring objects
                size_t tx_rings = 0;       ///< TX-ring objects
                size_t io_contexts = 0;    ///< per-worker asio contexts
                size_t udp_tables = 0;     ///< per-worker UDP NAT tables
                size_t icmp_relays = 0;    ///< per-worker ICMP relay slots
                size_t relay_registry = 0; ///< tracked TcpRelay strong refs
                size_t workers = 0;        ///< worker thread objects
                bool running = false;
                bool shutdown_incomplete = false;  ///< sticky after a timeout
            };
            /// Contract: call only when no Start()/Stop() is in flight - the
            /// lifecycle owner is single-threaded and the container sizes are
            /// read without synchronization (the lifecycle test calls it
            /// after Stop() returns; S1-T17).
            LifecycleCounts GetLifecycleCounts() const noexcept;

            /// P2-9: the adapter Start() actually bound after hint resolution.
            /// Read-only diagnostic surface for the UI (device + friendly
            /// name); `bound` is false before a successful Start and after
            /// Stop, or when resolution failed. Thread-safe: the strings are
            /// copied under the binding guard, so the publisher may read
            /// this while the plane runs.
            struct AdapterBinding {
                bool bound = false;
                std::string friendly_name;  ///< UTF-8, may be empty
                std::string device;         ///< UTF-8 device path / GUID
                /// batch24 P2-9b: link diagnostics sampled when the binding
                /// succeeded (OperStatus + media connect + unicast IPv4). A
                /// disconnected USB NIC is the production failure this exposes.
                bool is_up = false;
                bool media_connected = false;
                std::vector<driver::AdapterIpv4Address> ipv4;
                /// batch33 C: the real connection type (IP_ADAPTER_ADDRESSES::
                /// IfType) and the unicast IPv6 list. Copied verbatim from the
                /// bound AdapterEntry; a failed enumeration leaves the defaults
                /// (0 / empty), which the UI renders as "other" / "none".
                uint32_t if_type = 0;
                std::vector<std::string> ipv6;
                /// True when at least one bound IPv4 address shares the
                /// configured gateway subnet, or when the gateway/mask makes
                /// the check meaningless (fail-open).
                bool gateway_in_subnet = true;
            };
            AdapterBinding GetAdapterBinding() const;

            /// Read-only adapter inventory for the Settings picker (friendly
            /// name + device path + link state + IPv4). Injected test clients
            /// keep exactly the entries they supplied; the production client
            /// refreshes the link/IP snapshot from GetAdaptersAddresses when
            /// this is called.
            struct AdapterInfo {
                std::string friendly_name;  ///< UTF-8, may be empty
                std::string device;         ///< UTF-8 device path / GUID
                bool is_up = false;
                bool media_connected = false;
                std::vector<driver::AdapterIpv4Address> ipv4;
                /// batch33 C: connection type + unicast IPv6 (see
                /// AdapterBinding; defaults when the enumeration failed).
                uint32_t if_type = 0;
                std::vector<std::string> ipv6;
            };
            std::vector<AdapterInfo> GetAdapters() const;

            /// Cooperative stop with a bounded per-thread wait (H2). On
            /// timeout the stuck thread is NOT terminated and nothing it can
            /// touch is freed; the dataplane enters a sticky "shutdown
            /// incomplete" state and refuses subsequent Start(). Returns
            /// false in that case with `error` describing it.
            bool Stop(std::string& error) noexcept;

            struct Stats {
                std::atomic<uint64_t> rx_frames{0};
                std::atomic<uint64_t> rx_dropped{0};       ///< malformed/unroutable
                std::atomic<uint64_t> tx_frames{0};
                std::atomic<uint64_t> arp_replies{0};
                std::atomic<uint64_t> icmp_replies{0};
                std::atomic<uint64_t> host_passthrough{0}; ///< re-injected frames
                std::atomic<uint64_t> tcp_accepted{0};
                std::atomic<uint64_t> mac_misses{0};       ///< Tx without neighbor
                std::atomic<uint64_t> rate_limited{0};     ///< dropped by rate cap
                std::atomic<uint64_t> rx_vlan_frames{0};   ///< tagged frames accepted (tag stripped)
                std::atomic<uint64_t> thread_errors{0};    ///< escaped thread exceptions
                std::atomic<uint64_t> icmp_tag_exhausted{0}; ///< relay tag pool full
                std::atomic<uint64_t> tx_vlan_frames{0};   ///< downlink frames re-tagged
                std::atomic<uint64_t> portmap_send_dropped{0}; ///< WAN->LAN queue over its hard cap (C5)
                /// batch94: source MACs refused by the per-window rate table
                /// cap. The table is keyed by source MAC, so a forged-source
                /// flood would otherwise grow it without bound inside one
                /// 1-second window (memory and a per-tick scan in
                /// ThroughputBps). Non-zero means the table is saturated.
                std::atomic<uint64_t> rate_table_dropped{0};
            };

            const Stats& GetStats() const noexcept;

            /// batch31 P1-4 test seam: the internal processing latency (us) of
            /// every gateway-answered ICMP echo, measured from "reply built" to
            /// "reply handed to the driver" (the red anchor asserts its p95;
            /// the real-NIC ping also includes the driver/NIC round trip).
            /// Oldest first; empty before the first echo.
            std::vector<uint64_t> IcmpProcessingLatencyUs() const;

            /// batch94 test seam: how many source MACs the CURRENT (not yet
            /// published) rate window is tracking. Used to assert the table is
            /// bounded under a forged-source flood, where every frame would
            /// otherwise insert a brand-new key.
            size_t PendingRateTableSize() const noexcept;

            /// One second-window snapshot of a LAN client's throughput.
            struct ClientRate {
                net::IpAddress ip{};        ///< last known LAN address
                std::array<uint8_t, 6> mac{};  ///< client MAC
                uint64_t up_bps = 0;        ///< bytes/s off the wire toward WAN
                uint64_t down_bps = 0;      ///< bytes/s toward the client
                uint64_t last_seen_s = 0;   ///< seconds since last activity
                bool lan = true;            ///< inside the gateway's own subnet
            };

            /// Latest published per-client throughput snapshot (empty before
            /// the first 1 s window completes).
            std::vector<ClientRate> ClientRates() const;

            /// Aggregate LAN throughput right now: sums every client's window
            /// bytes over the window duration (total upload/download per
            /// second across the virtual gateway).
            struct Throughput {
                uint64_t up_bps = 0;
                uint64_t down_bps = 0;
            };
            Throughput ThroughputBps() const noexcept;

            /// vgww's own health (what the dashboard cares about: this
            /// process's CPU pressure and memory, not the whole machine).
            struct SystemStats {
                double proc_cpu_percent = 0.0;  ///< vgww process CPU % (per whole machine; may exceed 100 across cores)
                uint32_t cpu_cores = 0;         ///< logical processors (for scaling context)
                uint64_t proc_ws_bytes = 0;     ///< vgww working set bytes
                uint64_t proc_virt_bytes = 0;   ///< vgww virtual memory bytes
            };
            SystemStats GetSystem() const noexcept;

            // ------------------------------------------------------------------
            // DHCPv4 (S2). The server is assembled only in main mode with
            // `config.dhcp.enabled`; in bypass every accessor degrades to an
            // empty/false result instead of touching a non-existent server.
            // ------------------------------------------------------------------

            /// One active DHCP lease for the WebUI (static bindings included).
            struct LeaseView {
                std::string mac;
                std::string ip;
                uint32_t expires_in_s = 0;
                bool is_static = false;
                std::string hostname;  ///< client-reported (option 12)
            };

            /// Snapshot of current leases; empty when not assembled.
            std::vector<LeaseView> GetLeases() const;

            /// One DHCP static binding view for the WebUI.
            struct BindingView {
                std::string mac;
                std::string ip;
                std::string hostname;
            };

            /// Snapshot of every static binding (config + runtime merged).
            std::vector<BindingView> GetDhcpBindings() const;

            /// Adds/updates a runtime static binding (WebUI). Returns false on
            /// invalid mac/ip or when no DHCP server is assembled.
            bool SetDhcpBinding(const std::string& mac, const std::string& ip,
                                const std::string& hostname = std::string());

            /// Removes a runtime static binding. Returns false when absent or
            /// when no DHCP server is assembled.
            bool RemoveDhcpBinding(const std::string& mac);

            /// batch137: atomic re-key (`old_mac` dropped, `mac` bound) in one
            /// store transaction. The UI edit form used to post a remove
            /// followed by an add; each could be refused on its own, leaving
            /// the client's binding deleted. `old_mac` may be empty or name a
            /// binding that does not exist, in which case this is a plain add.
            bool ReplaceDhcpBinding(const std::string& old_mac,
                                    const std::string& mac, const std::string& ip,
                                    const std::string& hostname = std::string());

            /// Test seam / status surface: true once Start() assembled the
            /// DHCPv4 server (main mode + dhcp.enabled). Bypass must be false.
            bool DhcpActive() const noexcept;

            /// Number of active leases (0 when not assembled).
            size_t DhcpLeaseCount() const noexcept;

            /// batch34f: port-forwarding runtime health. The rules live in
            /// RuleStore (the UI lists them), but whether an acceptor actually
            /// EXISTS for each rule is only known here - a WAN port that could
            /// not be bound used to be invisible, so a rule looked active
            /// while nothing was forwarded.
            struct PortmapStats {
                uint64_t accepted = 0;
                uint64_t dial_failed = 0;
                uint64_t accept_errors = 0;
                uint64_t bind_failed = 0;
                /// Ports that failed to bind (newest last, capped).
                std::vector<uint16_t> failed_ports;
            };
            PortmapStats GetPortmapStats() const;

            /// batch33z: the two DHCPv4 faults that used to be invisible.
            /// Both are cumulative (monotonic) so the UI can report deltas.
            /// `PoolExhaustedCount`: a DISCOVER found no free pool address
            /// (the client silently gets no IP). `PersistFailureCount`:
            /// the lease file could not be written, so mappings will NOT
            /// survive a restart. 0 when no server is assembled.
            uint64_t DhcpPoolExhaustedCount() const noexcept;
            uint64_t DhcpPersistFailureCount() const noexcept;
            /// batch34j: times the DHCPv4 anti-storm rate map was cleared
            /// wholesale (protection lost for every client, briefly).
            uint64_t DhcpRateLimitResets() const noexcept;
            /// batch34j: same for DHCPv6.
            uint64_t Dhcp6RateLimitResets() const noexcept;
            /// batch34j: UDP relay flows pushed out by the capacity cap (each
            /// eviction kills an in-flight conversation).
            uint64_t UdpFlowEvictions() const;

            /// batch146 diagnostics: how many times the control loop rebuilt
            /// the parsed firewall / rate-limit snapshots. The rebuild walks
            /// every rule and re-parses its text (ParseMac, IPv6 literal,
            /// DUID), so doing it on every 100 ms tick burned CPU in
            /// proportion to the rule count even when nothing had changed.
            /// It is now driven by RuleStore::Rev(); a steadily rising count
            /// while the rule set is idle means that gate regressed.
            uint64_t RuleSnapshotRefreshCount() const noexcept;

            /// batch306 diagnostics: how many times a worker actually scanned
            /// the TCP relay registry to reclaim finished relays. The scan is
            /// gated on a "a relay finished" flag, so an idle data plane must
            /// not move this counter - the old code walked the whole registry
            /// on EVERY worker-loop iteration.
            uint64_t RegistrySweepCount() const noexcept;

            /// batch311 diagnostics: total conn_id -> relay index entries.
            /// Every finished relay must be dropped by the next sweep; a
            /// growing count with no live connections means the erase path
            /// regressed (one leaked entry per finished connection).
            std::size_t RegistryIndexSize();

            // ------------------------------------------------------------------
            // DHCPv6 (S2-Task8). Assembly rule = v4 gate plus the IPv6 switch:
            // main mode + ipv6.enabled + ipv6.dhcpv6.enabled. In bypass every
            // accessor degrades to an empty/false result.
            // ------------------------------------------------------------------

            /// One active DHCPv6 lease for the WebUI.
            struct Lease6View {
                std::string duid;  ///< client DUID, colon-separated hex
                uint32_t iaid = 0;
                std::string ip;
                uint32_t expires_in_s = 0;
                bool is_static = false;
                std::string hostname;
            };

            /// Snapshot of current v6 leases; empty when not assembled.
            std::vector<Lease6View> GetLeases6() const;

            /// One DHCPv6 static binding view for the WebUI.
            struct Binding6View {
                std::string duid;  ///< colon-separated hex
                std::string ip;
                std::string hostname;
            };

            /// Snapshot of every v6 static binding (config + runtime merged).
            std::vector<Binding6View> GetDhcp6Bindings() const;

            /// Adds/updates a runtime v6 static binding (WebUI). Returns false
            /// on invalid DUID/address or when no v6 server is assembled.
            bool SetDhcp6Binding(const std::string& duid, const std::string& ip,
                                 const std::string& hostname = std::string());

            /// Removes a runtime v6 static binding. Returns false when absent
            /// or when no v6 server is assembled.
            bool RemoveDhcp6Binding(const std::string& duid);

            /// batch137: atomic re-key for v6, sibling of
            /// ReplaceDhcpBinding. `old_duid` may be empty or absent.
            bool ReplaceDhcp6Binding(const std::string& old_duid,
                                     const std::string& duid, const std::string& ip,
                                     const std::string& hostname = std::string());

            /// Test seam / status surface: true once Start() assembled the
            /// DHCPv6 server (main + ipv6.enabled + ipv6.dhcpv6.enabled).
            bool Dhcp6Active() const noexcept;

            /// Number of active v6 leases (0 when not assembled).
            size_t Dhcp6LeaseCount() const noexcept;

            /// batch127: O(1) count of v6 static bindings (0 when not
            /// assembled). The status surface needs only the size, so it must
            /// not pay for a full GetDhcp6Bindings() copy per poll.
            size_t Dhcp6BindingCount() const noexcept;

        private:
            struct Impl;
            const core::Config& config_;
            std::unique_ptr<Impl> impl_;
        };

    }  // namespace runtime
}  // namespace vgww
