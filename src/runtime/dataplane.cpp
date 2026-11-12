// ============================================================================
// dataplane.cpp - Data plane implementation (pimpl; xtcp types stay here).
// ============================================================================
#include <winsock2.h>
#include <ws2ipdef.h>
#include <windows.h>
#include <psapi.h>

#include "dsp/classifier.h"
#include "dsp/spsc_ring.h"
#include "driver/installer.h"
#include "driver/ndisrd_client.h"
#include "core/handler_guard.h"
#include "net/eth.h"
#include "ndisapi/Common.h"
#include "proto/arp.h"
#include "proto/dhcp.h"
#include "proto/dhcp6.h"
#include "proto/icmp.h"
#include "proto/ndp.h"
#include "proto/udp.h"
#include "relay/icmp_relay.h"
#include "relay/portmap_manager.h"
#include "relay/tcp_relay.h"
#include "relay/udp_relay.h"
#include "runtime/worker_budget.h"
#include "tables/neighbors.h"
#include "tables/rate_limiter.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <functional>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include "web/web_api.h"

#include <xtcp/buf/bufref.h>
#include <xtcp/core/stack.h>
#include <xtcp/ndi.h>

namespace vgww {
    namespace runtime {

        namespace {

            using dsp::FrameClass;
            using dsp::FrameView;
            using net::WireMac;

            /// Complete outbound frame handed from workers to the TX drainer.
            typedef std::vector<uint8_t> TxFrame;

            /// G-5 F4: UTF-8 rendering for diagnostics (never throws).
            std::string WideToUtf8(const std::wstring& in) {
                if (in.empty()) {
                    return std::string();
                }
                const int need = ::WideCharToMultiByte(
                    CP_UTF8, 0, in.data(), static_cast<int>(in.size()), nullptr,
                    0, nullptr, nullptr);
                if (need <= 0) {
                    return std::string();
                }
                std::string out(static_cast<size_t>(need), '\0');
                ::WideCharToMultiByte(CP_UTF8, 0, in.data(),
                                      static_cast<int>(in.size()), out.data(),
                                      need, nullptr, nullptr);
                return out;
            }

            /// G-5 F4: renders adapter candidates for diagnostics as
            /// "<friendly> => <\DEVICE\{GUID}>"; an entry without a friendly
            /// name degrades to the device path alone.
            std::string RenderAdapterCandidates(
                const std::vector<driver::AdapterEntry>& adapters) {
                std::string out;
                for (size_t i = 0; i < adapters.size(); ++i) {
                    if (i > 0) {
                        out += ", ";
                    }
                    if (!adapters[i].friendly_name.empty()) {
                        out += WideToUtf8(adapters[i].friendly_name) + " => " +
                               WideToUtf8(adapters[i].name);
                    } else {
                        out += WideToUtf8(adapters[i].name);
                    }
                }
                return out;
            }

            /// Ring payload for the RX->worker direction: an owned pool block
            /// holding the IP datagram (Ethernet header already stripped).
            struct RxItem {
                xtcp::buf::BufRef packet;
                dsp::FrameClass cls = dsp::FrameClass::kOther;
            };

            /// Worker index sentinel for threads that do not own a ring.
            inline constexpr uint32_t kNoRing = 0xFFFFFFFFu;

            /// FNV-1a over the 6 MAC bytes: hash for the per-client telemetry
            /// map (core::MacAddress is a plain std::array with no std::hash).
            struct MacAddressHash {
                size_t operator()(const core::MacAddress& mac) const noexcept {
                    uint64_t h = 1469598103934665603ull;
                    for (const uint8_t b : mac) {
                        h ^= b;
                        h *= 1099511628211ull;
                    }
                    return static_cast<size_t>(h);
                }
            };

            // Set on each worker thread so StackBackend::Tx knows which TX
            // ring to use. The xtcp emit path runs synchronously inside
            // OnPacket/PollAckTimers; PollAckTimers itself sweeps ALL shards
            // under per-shard locks from every worker (a timer may fire here
            // for a foreign shard), so state/recv handlers must re-serialize
            // onto the owning worker - see NotifyPeerFin's io_context post.
            thread_local uint32_t t_worker_index = kNoRing;

        }  // namespace

        // ------------------------------------------------------------------
        // Impl: everything concrete lives here.
        // ------------------------------------------------------------------
        struct Dataplane::Impl {
            struct Backend final : public xtcp::ndi::Backend {
                Impl* owner = nullptr;

                void SetRxHandler(xtcp::ndi::RxHandler handler) noexcept override {
                    (void)handler;  // unused: the RX thread calls OnPacket directly
                }

                xtcp::ndi::BackendCaps Caps() const noexcept override {
                    return xtcp::ndi::kCapNone;  // software segmentation for now
                }

                bool Tx(xtcp::ndi::Packet&& packet) noexcept override {
                    return owner->EmitFromStack(std::move(packet));
                }

                UInt32 TxBatch(xtcp::ndi::Packet* packets, UInt32 count) noexcept override {
                    UInt32 accepted = 0;
                    for (UInt32 i = 0; i < count; ++i) {
                        if (!Tx(std::move(packets[i]))) {
                            break;
                        }
                        ++accepted;
                    }
                    return accepted;
                }
            };

            explicit Impl(const core::Config& cfg, const std::string& lease_path)
                : config(cfg), lease_file(lease_path) {
                backend.owner = this;
                stats = &owned_stats;
                // batch208: prime the cache once so /api/system reports the
                // TRUE service state even when the sampling thread never runs
                // (the data plane may not be Started, or Start may fail).
                SampleDriverService();
            }

            /// batch208: refresh the cached ndisrd service state. Runs on the
            /// control thread's 1 s cadence and once at construction; the
            /// test seam, when installed, replaces the SCM query.
            void SampleDriverService() noexcept {
                bool is_running = false;
                try {
                    is_running = driver_service_probe_
                                     ? driver_service_probe_()
                                     : driver::NdisrdServiceRunning();
                } catch (...) {
                    is_running = false;
                }
                ndisrd_service_running_.store(is_running);
            }

            const core::Config& config;
            /// DHCP persistence path (ctor-anchored; production derives it
            /// from the config file location so leases survive a restart from
            /// a different working directory).
            std::string lease_file;
            Dataplane::Stats* stats = nullptr;
            /// H2: statistics live inside Impl so the deliberate leak on an
            /// incomplete shutdown also keeps this object alive; the `stats`
            /// pointer stays for all existing call sites.
            Dataplane::Stats owned_stats;
            tables::NeighborTable neighbors;

            // ------------------------------------------------------------------
            // Per-client byte accounting (device list + per-second rates).
            //   * Single writer: the RX/TX thread only (every frame classified
            //     by DispatchFrame, plus TX-ring frames drained in RxTxLoop).
            //     No locks on the hot path.
            //   * Once per second the RX/TX thread swaps the live map for a
            //     fresh one and atomically publishes the finished window as an
            //     immutable shared_ptr; web_api reads that snapshot only.
            // ==================================================================
            struct ClientCounter {
                uint64_t up_bytes = 0;    ///< LAN client -> WAN in this window
                uint64_t down_bytes = 0;  ///< WAN -> LAN client in this window
            };
            typedef std::unordered_map<core::MacAddress, ClientCounter,
                                       MacAddressHash>
                ClientRateMap;
            struct ClientRatesSnapshot {
                ClientRateMap by_mac;
                double window_s = 1.0;    ///< duration of the measured window
                std::chrono::steady_clock::time_point sampled_at{};
            };
            ClientRateMap live_rates_;    // RX/TX thread only
            std::shared_ptr<ClientRatesSnapshot> published_rates_ =
                std::make_shared<ClientRatesSnapshot>();
            std::chrono::steady_clock::time_point rate_window_start_ =
                std::chrono::steady_clock::now();
            // ------------------------------------------------------------------

            // vgww-process health sampling state (control thread only). The dashboard
            // cares about THIS process's load, not the whole machine's, so the
            // system totals only serve as the denominator for proc CPU %.
            uint64_t last_sys_kernel_ = 0;
            uint64_t last_sys_user_ = 0;
            uint64_t last_proc_kernel_ = 0;
            uint64_t last_proc_user_ = 0;
            bool have_sys_sample_ = false;
            std::atomic<double> sys_proc_cpu_percent_{0.0};
            std::atomic<uint32_t> sys_cpu_cores_{0};
            std::atomic<uint64_t> sys_proc_ws_bytes_{0};
            std::atomic<uint64_t> sys_proc_virt_bytes_{0};
            /// batch208: ndisrd service state, sampled by the control thread
            /// once per second (and once in the constructor) so the WebUI's
            /// /api/system never performs an SCM round-trip per request.
            std::atomic<bool> ndisrd_service_running_{false};
            /// batch208 test seam: overrides the SCM query above. Empty in
            /// production (the real NdisrdServiceRunning is used).
            std::function<bool()> driver_service_probe_;

            Backend backend;

            // Bypass (LISTEN) mode: the single Ndisrd handle both observes the
            // adapter and injects host frames; no second TUNNEL-bypass handle.
            std::unique_ptr<driver::IDriverClient> client;  // injected or Ndisrd
            const driver::AdapterEntry* adapter = nullptr;
            /// P2-9: immutable copy of the adapter resolved by Start(), for
            /// the read-only UI diagnostic. Guarded because the snapshot
            /// publisher thread reads it concurrently.
            mutable std::mutex adapter_binding_mutex_;
            Dataplane::AdapterBinding adapter_binding_;
            /// batch25a: last lifecycle failure (read by the UI publisher).
            mutable std::mutex last_error_mutex_;
            std::string last_error_;
            void SetLastError(const std::string& error) {
                std::lock_guard<std::mutex> lock(last_error_mutex_);
                last_error_ = error;
            }
            std::string GetLastError() const {
                std::lock_guard<std::mutex> lock(last_error_mutex_);
                return last_error_;
            }
            /// Read-only inventory cache (friendly/device/link/IP). Guarded by
            /// adapter_binding_mutex_ so the snapshot publisher never touches
            /// the lifecycle-owned client pointer after Stop()/Start().
            std::vector<driver::AdapterEntry> adapter_entries_;
            /// Batch-24-D: a SECOND driver handle used solely for MSTCP
            /// injection (delivering a synthesized reply to the LOCAL host
            /// stack). The primary LISTEN handle does not reliably deliver
            /// SendPacketsToMstcp to MSTCP - d2d79c4 observed the reply count
            /// climb while the host ping still timed out. This handle is
            /// opened WITHOUT any intercept mode so its injection is never
            /// re-intercepted. Null for injected test clients or when the
            /// second open fails; FlushBatch then falls back to the primary.
            std::unique_ptr<driver::IDriverClient> up_client;
            const driver::AdapterEntry* up_adapter = nullptr;
            /// Owns the kernel event armed with the driver. RAII: when a
            /// later start step fails (or the object dies) the handle is
            /// closed - the pre-fix code leaked one event per failed start.
            std::unique_ptr<void, decltype(&::CloseHandle)> rx_event{
                nullptr, &::CloseHandle};

            // ----- L2 bridge (S3-Task3) ----------------------------------
            // Upstream is the primary adapter (config.adapter unless the
            // bridge config names another); downstream is the bridge peer
            // read by the bridge thread. Each adapter keeps exactly one
            // reader (RX thread upstream, bridge thread downstream).
            bridge::BridgeConfig bridge_cfg_;
            bridge::MacTable bridge_table_;
            std::mutex bridge_table_mutex_;
            std::atomic<bridge::BridgeState> bridge_state_{
                bridge::BridgeState::kStopped};
            /// batch34x: reason for the last kFailed transition (bridge thread
            /// writes, UI/web reads). Guarded by its own mutex so a reader can
            /// never see a half-written string while the loop reports.
            mutable std::mutex bridge_error_mutex_;
            std::string bridge_error_;
            std::atomic<bool> bridge_active_{false};
            bridge::BridgeLoopRuntime bridge_loop_rt_;
            std::thread bridge_thread_;
            std::unique_ptr<void, decltype(&::CloseHandle)> bridge_event_{
                nullptr, &::CloseHandle};
            /// Driver handles snapshot at StartBridge; driver calls always
            /// re-resolve the entry by handle (the vector may shrink on
            /// hot-removal, so entry pointers are never retained).
            void* bridge_upstream_handle_ = nullptr;
            void* bridge_downstream_handle_ = nullptr;
            uint32_t bridge_saved_filter_up_ = 0;
            uint32_t bridge_saved_filter_down_ = 0;
            bool bridge_mode_up_ = false;
            bool bridge_filter_up_ = false;
            bool bridge_mode_down_ = false;
            bool bridge_filter_down_ = false;
            /// Sticky refusal after a bridge join timeout (H2 analogue:
            /// a detached bridge thread may still touch the client).
            bool bridge_broken_ = false;
            std::mutex bridge_queue_mutex_;
            std::deque<std::vector<uint8_t>> bridge_control_queue_;
            static constexpr size_t kBridgeControlQueueCap = 1024;
            std::atomic<uint64_t> bridge_forwarded_{0};
            std::atomic<uint64_t> bridge_dropped_{0};

            std::unique_ptr<xtcp::XtcpStack> stack;
            uint32_t worker_count = 0;
            std::vector<std::unique_ptr<dsp::SpscRing<RxItem>>> rx_rings;
            std::vector<std::unique_ptr<dsp::SpscRing<TxFrame>>> tx_rings;

            // Per-worker upstream I/O: each worker owns one io_context so
            // relay socket completions fire on the flow's own thread.
            std::vector<std::unique_ptr<asio::io_context>> io_contexts;

            // Accepted flows waiting for their upstream dial (mimt callbacks
            // run under the shard lock - they only enqueue here).
            std::vector<std::mutex> accept_mutexes;
            std::vector<std::vector<std::shared_ptr<xtcp::mimt::MimtFlow>>>
                pending_accepts;

            // Deferred teardowns (failed dials / finished relays). graceful=true
            // CLOSEs (FIN to the client); false ABORTs (RST).
            struct TeardownRequest {
                UInt64 conn_id;
                bool graceful;
            };
            std::vector<std::mutex> abort_mutexes;
            std::vector<std::vector<TeardownRequest>> pending_teardowns_;

            // Strong refs keeping live relays alive between callbacks; swept
            // (finished entries removed) during DrainAccepts.
            std::vector<std::mutex> registry_mutexes;
            std::vector<std::vector<std::shared_ptr<relay::TcpRelay>>> relay_registry_;
            /// batch311: conn_id -> relay index over relay_registry_. The FIN
            /// handler used to scan the whole per-worker registry (up to
            /// max_conns = 4096) for the matching ConnId(), so a connection
            /// churn flood cost O(live) per close under the registry mutex.
            /// Entries are inserted/erased under the same mutex as the vector.
            std::vector<std::unordered_map<UInt64, std::weak_ptr<relay::TcpRelay>>>
                relay_index_;
            /// batch306: set when a relay finishes (on its owning worker).
            /// SweepRegistry only scans when set - the old code walked the
            /// whole registry on every loop iteration, at a cost
            /// proportional to the live connection count.
            std::vector<std::unique_ptr<std::atomic<bool>>> registry_dirty;
            std::atomic<uint64_t> registry_sweeps_{0};

            // Per-worker UDP NAT tables (owner-thread only, no locks).
            std::vector<std::unique_ptr<relay::UdpFlowTable>> udp_tables;

            // Per-worker raw ICMP sockets for echo relay (id-NAT).
            std::vector<std::shared_ptr<relay::IcmpRelay>> icmp_relays;

            /// Frame-level DHCPv4 server (control-plane rate). Assembled by
            /// StartAll only when main mode and `config.dhcp.enabled`; stays
            /// null in bypass so nothing is persisted or swept.
            std::unique_ptr<dhcp::DhcpServer> dhcp_;

            /// Frame-level DHCPv6 server (S2-Task8). Same rule plus
            /// `ipv6.enabled && ipv6.dhcpv6.enabled`; null in bypass.
            std::unique_ptr<dhcp6::Dhcp6Server> dhcp6_;

            /// v6 persistence path derived from the v4 one: production passes
            /// "<config>.leases.json", the spec section 5.2 store is
            /// "<config>.leases6.json". Unconventional paths keep the suffix
            /// appended so the two stores never collide.
            std::string LeaseFile6() const {
                static const std::string kSuffix = ".leases.json";
                const size_t pos = lease_file.rfind(kSuffix);
                if (std::string::npos == pos ||
                    pos + kSuffix.size() != lease_file.size()) {
                    return lease_file + ".leases6";
                }
                return lease_file.substr(0, pos) + ".leases6.json";
            }

            /// Firewall ban targets pre-parsed by the control thread into
            /// hash sets. batch305: the hot path used to scan EVERY ban per
            /// frame (kMaxBans = 4096): up to 4096 six-byte memcmps for a MAC
            /// ban, or 4096 strcmps against a per-frame snprintf'd source
            /// address for an IPv4 ban. One lookup per frame now, and the
            /// v4/v6 targets are published together - the old two snapshots
            /// could be observed at two different revisions.
            struct BanIndex final {
                std::unordered_set<net::WireMac, net::WireMacHash> macs;
                std::unordered_set<uint32_t> ipv4;  ///< inet_addr convention
                std::unordered_set<net::IpAddress, net::IpAddressHash> ipv6;

                bool Empty() const noexcept {
                    return macs.empty() && ipv4.empty() && ipv6.empty();
                }
            };
            std::shared_ptr<const BanIndex> ban_index_snapshot_ =
                std::make_shared<const BanIndex>();

            // Rate-limit rules (parsed once per refresh so the hot path never
            // parses text) + the token-bucket engine. Buckets live only on the
            // RX/TX loop thread; the control thread swaps the rule snapshot
            // through RateLimiter::SetRules (atomic publishing via shared_ptr).
            tables::RateLimiter rate_limiter_;

            /// batch146: monotonic count of parsed-snapshot rebuilds (see
            /// Dataplane::RuleSnapshotRefreshCount). Written only by the
            /// control thread; read by diagnostics from any thread.
            std::atomic<uint64_t> rule_snapshot_refreshes_{0};
            /// batch146: the RuleStore::Rev() the published snapshots were
            /// built from, plus a "never built yet" flag (rev 0 is a legal
            /// value, so it cannot double as the sentinel).
            uint64_t published_rule_rev_ = 0;
            bool rules_published_ = false;

            /// Per-client ARP probe throttle for neighbor-miss recovery. On
            /// stack emit the neighbor entry may have aged out (Tick, 20 min
            /// idle): dropping the frame alone makes a static-IP client
            /// unreachable for pure inbound traffic forever, because TCP
            /// retransmits never re-learn the MAC. Probe once per client per
            /// 500 ms; the miss path is cold so a small mutexed map is fine.
            struct ArpProbeCache {
                std::mutex mutex;
                std::unordered_map<uint32_t, uint64_t> last_us;  // v4 (host int)
                std::unordered_map<net::IpAddress, uint64_t,
                                   net::IpAddressHash>
                    v6_last_us;  // v6 NS probes (16-byte key)
            };
            ArpProbeCache arp_probe_cache_;

            // ------------------------------------------------------------------
            // batch31 P1-4: opt-in ICMP latency trace (`VGWW_LAT_TRACE=1`).
            // The gateway-answered echo path is timed in three segments so the
            // fix is chosen from measurements, never guessed:
            //   wait    = how long the RX thread slept on the driver event
            //             before the batch carrying the request was read;
            //   read->build = classification + echo-reply construction;
            //   build->flush = the SendPacketsToMstcp IOCTL (plus, before the
            //             batch31 fix, the REST OF THE KERNEL-QUEUE DRAIN: the
            //             reply used to wait for up to 64x rx_batch frames).
            // RX/TX-thread only (no atomics needed): the same thread reads the
            // batch, builds the reply and flushes it.
            // ------------------------------------------------------------------
            bool lat_trace = false;
            uint64_t lat_wait_us = 0;
            uint64_t lat_read_us = 0;
            uint64_t lat_build_us = 0;
            uint16_t lat_seq = 0;

            /// batch31 P1-4: ALWAYS-ON internal processing latency of a
            /// gateway-answered echo (reply built -> reply flushed). Kept in a
            /// small lock-free ring so the red anchor can assert the internal
            /// path without a real NIC, and so the trace can report the same
            /// number the test measures.
            static constexpr uint32_t kIcmpLatRing = 128;
            std::array<uint64_t, kIcmpLatRing> icmp_proc_us_{};
            std::atomic<uint32_t> icmp_proc_written_{0};
            /// Reply-build timestamps of the CURRENT batch (fixed capacity:
            /// one RX batch is at most perf.rx_batch, capped at 4096 by config
            /// validation, so no reply is ever dropped from the measurement).
            std::array<uint64_t, 4096> icmp_pending_us_{};
            uint32_t icmp_pending_count_ = 0;

            static uint64_t NowUs() noexcept {
                return static_cast<uint64_t>(
                    std::chrono::duration_cast<std::chrono::microseconds>(
                        std::chrono::steady_clock::now().time_since_epoch())
                        .count());
            }

            void LatTraceIcmp(uint16_t seq) noexcept {
                const uint64_t now = NowUs();
                if (icmp_pending_count_ < icmp_pending_us_.size()) {
                    icmp_pending_us_[icmp_pending_count_++] = now;
                }
                if (lat_trace) {
                    lat_build_us = now;
                    lat_seq = seq;
                }
            }

            void LatTraceFlush() noexcept {
                if (0 == icmp_pending_count_) {
                    return;
                }
                const uint64_t done = NowUs();
                for (uint32_t i = 0; i < icmp_pending_count_; ++i) {
                    const uint32_t slot = icmp_proc_written_.fetch_add(
                        1, std::memory_order_acq_rel);
                    icmp_proc_us_[slot % kIcmpLatRing] = done - icmp_pending_us_[i];
                }
                if (lat_trace && 0 != lat_build_us) {
                    std::fprintf(stderr,
                                 "[lat] seq=%u wait_us=%llu build_us=%llu "
                                 "flush_us=%llu total_us=%llu\n",
                                 static_cast<unsigned>(lat_seq),
                                 static_cast<unsigned long long>(lat_wait_us),
                                 static_cast<unsigned long long>(lat_build_us -
                                                                 lat_read_us),
                                 static_cast<unsigned long long>(done -
                                                                 lat_build_us),
                                 static_cast<unsigned long long>(done -
                                                                 lat_read_us));
                    // Measurement mode only: the process is force-killed by the
                    // harness, so an unflushed block-buffered stderr would lose
                    // every line.
                    std::fflush(stderr);
                }
                lat_build_us = 0;
                icmp_pending_count_ = 0;
            }

            /// Copy of the recorded internal echo-processing durations (oldest
            /// first). Used by the P1-4 red anchor and by the report tooling.
            std::vector<uint64_t> IcmpProcLatencyUs() const {
                const uint32_t total =
                    icmp_proc_written_.load(std::memory_order_acquire);
                const uint32_t count =
                    total < kIcmpLatRing ? total : kIcmpLatRing;
                std::vector<uint64_t> out;
                out.reserve(count);
                for (uint32_t i = total - count; i < total; ++i) {
                    out.push_back(icmp_proc_us_[i % kIcmpLatRing]);
                }
                return out;
            }

            /// batch94: current rate-window table occupancy (RX/TX thread
            /// writes it; the counter is monotonic and the size is only read
            /// from tests after the flood has been drained).
            size_t PendingRateTableSize() const {
                return live_rates_.size();
            }

            /// Last driver IOCTL failure text already reported, so a dead
            /// driver or detached NIC warns exactly once instead of spamming
            /// the console every 200 ms poll.
            std::string last_ioctl_warn_;

            /// WAN->LAN send requests from the port-map manager thread,
            /// flushed on worker 0 (stack emit requires a worker context).
            struct PortmapSendItem {
                uint64_t conn_id;
                core::PoolVector<uint8_t> data;
            };
            struct PortmapSendQueue {
                std::mutex mutex;
                std::deque<PortmapSendItem> items;
            };
            std::shared_ptr<PortmapSendQueue> portmap_send_queue_;
            /// C5: set when the LanSender rejected a packet (queue at cap);
            /// DrainPortmapSends clears it and asks the port-map manager to
            /// resume its paused WAN reads once the queue fully drains.
            std::atomic<bool> portmap_need_resume_{false};
            /// C5: hard cap on WAN->LAN queued bytes-toward-the-stack. A slow
            /// LAN client must not let the queue grow without bound; past the
            /// cap the manager's WAN read chain is told to pause (false).
            static constexpr size_t kPortmapSendQueueCap = 1024;

            /// C8: a wire-direction batch that knows its egress adapter
            /// handle. Control-plane replies must leave VGWW through the port
            /// that received the request - a frame from the bridge downstream
            /// port is answered out of the downstream adapter, everything
            /// else out of the primary adapter (non-bridge: primary only).
            struct PortBatch {
                void* handle = nullptr;  ///< egress adapter handle
                std::vector<INTERMEDIATE_BUFFER> items;
            };
            /// Down (toward the wire) and up (toward MSTCP) batches split
            /// per bridge port.
            struct WireBatches {
                PortBatch primary;
                PortBatch downstream;
                PortBatch& For(uint32_t in_port) noexcept {
                    return (bridge::kBridgePortDown == in_port) ? downstream
                                                                 : primary;
                }
            };

            /// Periodic unsolicited RA (RFC 4861 section 6.2.4): the control loop
            /// raises the flag on its schedule; the RX/TX loop (the only
            /// thread allowed to append to down_batch) emits the frame.
            std::atomic<bool> periodic_ra_due{false};

            /// Drains queued manager sends; must run on a worker thread.
            void DrainPortmapSends() {
                if (!portmap_send_queue_) {
                    return;
                }
                std::deque<PortmapSendItem> batch;
                {
                    std::lock_guard<std::mutex> lock(portmap_send_queue_->mutex);
                    batch.swap(portmap_send_queue_->items);
                }
                for (auto& item : batch) {
                    if (stack->Send(item.conn_id, item.data.data(),
                                    static_cast<UInt32>(item.data.size()))) {
                        continue;
                    }
                    // Send() is false either when the peer window is full OR
                    // when the connection no longer exists (already closed /
                    // reaped by the xtcp stack). Re-queuing a dead connection
                    // spins this drain forever on a worker thread; only
                    // re-queue live connections and drop the rest (counted).
                    if (xtcp::core::TcpState::kClosed ==
                        stack->ConnectionState(item.conn_id)) {
                        ++stats->rx_dropped;
                        continue;
                    }
                    // Peer window full: re-queue at the tail, bounded by the
                    // hard cap - past it the manager is told to pause its WAN
                    // reads (its own backpressure), so the queue stays finite
                    // and the dropped count tells the story (C5).
                    std::lock_guard<std::mutex> lock(
                        portmap_send_queue_->mutex);
                    if (portmap_send_queue_->items.size() <
                        kPortmapSendQueueCap) {
                        portmap_send_queue_->items.push_back(std::move(item));
                    } else {
                        ++stats->portmap_send_dropped;
                    }
                }
                // C5: once the queue fully drains after a rejection, tell the
                // port-map manager to resume its paused WAN receive chains.
                if (portmap_need_resume_.exchange(false,
                                                  std::memory_order_relaxed)) {
                    std::lock_guard<std::mutex> lock(
                        portmap_send_queue_->mutex);
                    if (portmap_send_queue_->items.empty()) {
                        relay::PortMapManager::Instance()
                            .ResumePausedWanReads();
                    } else {
                        // Still backlogged: keep the flag set for the next
                        // drain pass.
                        portmap_need_resume_.store(true,
                                                   std::memory_order_relaxed);
                    }
                }
            }

            /// Runs a data-plane thread body behind a fatal-error firewall.
            /// An exception escaping a background thread would call
            /// std::terminate and kill the whole gateway; instead the event
            /// is counted, `running` is flipped so every loop unwinds, and
            /// Stop() stays joinable.
            template <typename Fn>
            void RunGuarded(const char* what, Fn&& fn) noexcept {
                try {
                    fn();
                } catch (const std::exception& ex) {
                    ++stats->thread_errors;
                    std::fprintf(stderr, "[vgww] %s thread fatal: %s\n", what,
                                 ex.what());
                    running.store(false);
                } catch (...) {
                    ++stats->thread_errors;
                    std::fprintf(stderr, "[vgww] %s thread fatal: unknown\n",
                                 what);
                    running.store(false);
                }
            }

            std::atomic<bool> running{false};
            /// batch31 P1-4: the timer resolution this Start() requested, so
            /// the matching timeEndPeriod runs exactly once.
            static constexpr UINT kTimerPeriodMs = 1;
            bool timer_period_active_ = false;

            /// True when the driver client came through the test seam;
            /// injected clients survive a clean Stop() so a restart reuses
            /// the same double (production clients are re-opened).
            bool client_injected_ = false;

            /// Test seam (SetDialCompletionProbeForTest): runs at the top of
            /// every upstream dial completion body, inside its guard.
            std::function<void()> dial_completion_probe_;

            /// batch99: periodic lease snapshot cadence (both families).
            std::atomic<int64_t> lease_dump_interval_ms_{60000};

            /// batch100: the last Stop() finished teardown but could not write
            /// a lease document, so the mappings it held are gone for good.
            bool stop_persist_failed_ = false;

            /// H2: sticky flag - a stop timed out and a thread may still run
            /// inside driver/stack code. Start() must refuse afterwards
            /// because the state was intentionally left untouched.
            bool shutdown_incomplete_ = false;

            std::thread rx_tx_thread;
            std::vector<std::thread> workers;
            std::thread control_thread;

            // ----- lifecycle -------------------------------------------------
            /// Network-order prefix mask (core::FormatIpv4/ParseIpv4 keep the
            /// first octet in the low byte, so /24 is 0x00FFFFFF).
            static uint32_t PrefixMask(uint8_t prefix_len) noexcept {
                if (0 == prefix_len) {
                    return 0;
                }
                if (prefix_len >= 32) {
                    return 0xFFFFFFFFu;
                }
                return (1u << prefix_len) - 1u;
            }

            /// True when one bound IPv4 address shares the configured gateway
            /// subnet. An unset gateway/mask keeps the check fail-open; a
            /// bound adapter with no IPv4 is reported by ipv4.empty() instead.
            bool GatewayInSubnet(const driver::AdapterEntry& entry) const {
                if (0 == config.gateway.ipv4 || 0 == config.gateway.mask) {
                    return true;
                }
                if (entry.ipv4.empty()) {
                    return true;
                }
                for (const driver::AdapterIpv4Address& address : entry.ipv4) {
                    const uint32_t mask = PrefixMask(address.prefix_len);
                    if ((address.address & mask) ==
                        (config.gateway.ipv4 & mask)) {
                        return true;
                    }
                }
                return false;
            }

            /// Copy the client inventory under the guard (caller owns the
            /// lifecycle; the publisher only reads the copy).
            void CacheAdapterEntries() {
                std::vector<driver::AdapterEntry> entries;
                if (client) {
                    entries = client->Adapters();
                }
                std::lock_guard<std::mutex> lock(adapter_binding_mutex_);
                adapter_entries_ = std::move(entries);
            }

            /// P2-9: publish/clear the diagnostic binding under the guard so
            /// the publisher thread only ever sees a consistent copy.
            void SetAdapterBinding(const driver::AdapterEntry& entry) {
                const bool link_up = entry.is_up && entry.media_connected;
                const bool in_subnet = GatewayInSubnet(entry);
                {
                    std::lock_guard<std::mutex> lock(adapter_binding_mutex_);
                    adapter_binding_.bound = true;
                    adapter_binding_.friendly_name =
                        WideToUtf8(entry.friendly_name);
                    adapter_binding_.device = WideToUtf8(entry.name);
                    adapter_binding_.is_up = entry.is_up;
                    adapter_binding_.media_connected = entry.media_connected;
                    adapter_binding_.ipv4 = entry.ipv4;
                    adapter_binding_.if_type = entry.if_type;
                    adapter_binding_.ipv6 = entry.ipv6;
                    adapter_binding_.gateway_in_subnet = in_subnet;
                }
                if (!link_up || entry.ipv4.empty() || !in_subnet) {
                    // The exact production trap: a localized alias resolves to
                    // a disconnected USB NIC, every feature then silently
                    // fails. Leave a trace in the console log as well as the
                    // banner/diagnostic line.
                    std::fprintf(
                        stderr,
                        "[vgww] warning: bound adapter \"%s\" (%s) link=%s "
                        "ipv4=%zu gateway_in_subnet=%s\n",
                        WideToUtf8(entry.friendly_name).c_str(),
                        WideToUtf8(entry.name).c_str(),
                        link_up ? "up" : "down", entry.ipv4.size(),
                        in_subnet ? "yes" : "no");
                }
            }
            void ClearAdapterBinding() {
                std::lock_guard<std::mutex> lock(adapter_binding_mutex_);
                adapter_binding_ = Dataplane::AdapterBinding{};
            }

            bool StartAll(std::string& error) try {
                if (shutdown_incomplete_) {
                    error = "dataplane start refused: previous stop was "
                            "incomplete (process restart required)";
                    return false;
                }
                if (running.load()) {
                    error = "dataplane already running";
                    return false;
                }
                if (!StateIsEmpty()) {
                    error = "dataplane start refused: state not empty "
                            "(previous stop incomplete)";
                    return false;
                }
                if (bridge_broken_) {
                    error = "dataplane start refused: previous bridge stop "
                            "was incomplete (process restart required)";
                    return false;
                }
                xtcp::buf::InitPools();
                // A new start invalidates any previous diagnostic binding; it
                // is republished only after every start step succeeded.
                ClearAdapterBinding();

                if (!client) {
                    // Production path: bind the real WinpkFilter client.
                    client = driver::NdisrdClient::Open(error);
                    if (!client) {
                        return false;
                    }
                }
                // Publish the inventory even when the hint below fails: the
                // Settings picker must be able to show the real candidates.
                CacheAdapterEntries();
                const std::wstring hint =
                    driver::WidenAdapterHint(config.adapter);
                bool adapter_ambiguous = false;
                adapter = client->FindAdapter(hint, &adapter_ambiguous);
                if (nullptr == adapter) {
                    error = "no adapter matches: \"" + config.adapter + "\". ";
                    if (client->Adapters().empty()) {
                        // Zero binding is a different failure: say so instead
                        // of printing an empty candidate list (G-5 F4/D8).
                        error += "No adapters are bound to the ndisrd driver; "
                                 "reinstall it with --install-driver";
                    } else {
                        error += "Available adapters: " +
                                 RenderAdapterCandidates(client->Adapters()) +
                                 "; use --adapter=<name> or edit \"adapter\" "
                                 "in the config file";
                    }
                    return false;
                }
                if (adapter_ambiguous) {
                    error = "adapter matching is ambiguous: \"" +
                            config.adapter +
                            "\" matches more than one adapter; use a more "
                            "specific hint or the full \\DEVICE\\{GUID} "
                            "path. Matching adapters: " +
                            RenderAdapterCandidates(client->Adapters());
                    return false;
                }

                // Batch-24-D: open the dedicated host-bound (MSTCP) injection
                // handle for the production driver. Test-injected clients keep
                // the single-handle fallback so the boundary double is
                // unaffected (up_adapter stays = adapter).
                if (nullptr == up_client && !client_injected_) {
                    std::string up_err;
                    auto second = driver::NdisrdClient::Open(up_err);
                    if (second) {
                        const driver::AdapterEntry* sec =
                            second->FindAdapter(hint);
                        if (nullptr != sec) {
                            up_client = std::move(second);
                            up_adapter = sec;
                        }
                    }
                }
                if (nullptr == up_adapter) {
                    up_adapter = adapter;  // fallback: the primary handle
                }

                // Bypass (LISTEN) mode: the adapter is never intercepted, so the
                // primary handle's SendPacketsToMstcp already reaches the
                // host stack directly. No second handle is needed.
                if (!client->SetAdapterMode(*adapter,
                                            driver::kRecvListen |
                                                driver::kSentListen |
                                                driver::kFilterDirect,
                                            error)) {
                    return false;
                }

                rx_event.reset(::CreateEventW(nullptr, FALSE, FALSE, nullptr));
                if (!rx_event) {
                    error = "CreateEvent failed";
                    return false;
                }
                // batch31 P1-4: opt-in latency trace (measurement only; the
                // default path stays byte-identical).
                lat_trace = ::GetEnvironmentVariableW(L"VGWW_LAT_TRACE",
                                                      nullptr, 0) != 0;
                if (!client->ArmRxEvent(*adapter, rx_event.get(), error)) {
                    // The member outlives this call, so RAII alone does NOT
                    // close the handle on an early return: close explicitly
                    // or every failed start leaks one event (M5).
                    rx_event.reset();
                    return false;
                }

                // L2 bridge (S3-Task3, optional): a second adapter in
                // promiscuous mode plus the bridge thread. Any failure
                // rolls back in reverse order and fails Start with no
                // half-initialized residue.
                if (bridge_cfg_.enabled) {
                    if (!StartBridge(error)) {
                        rx_event.reset();
                        return false;
                    }
                }

                // Worker count is capped by the xtcp shard count: worker i
                // pumps shard i, keeping every flow single-threaded.
                worker_count =
                    config.perf.workers > xtcp::XtcpStack::kShardCount
                        ? xtcp::XtcpStack::kShardCount
                        : ((0 == config.perf.workers) ? 1 : config.perf.workers);
                for (uint32_t i = 0; i < worker_count; ++i) {
                    rx_rings.push_back(
                        dsp::SpscRing<RxItem>::Create(config.perf.ring_capacity));
                    tx_rings.push_back(
                        dsp::SpscRing<TxFrame>::Create(config.perf.ring_capacity));
                    io_contexts.push_back(std::make_unique<asio::io_context>());
                }
                accept_mutexes = std::vector<std::mutex>(worker_count);
                pending_accepts.resize(worker_count);
                abort_mutexes = std::vector<std::mutex>(worker_count);
                pending_teardowns_.resize(worker_count);
                registry_mutexes = std::vector<std::mutex>(worker_count);
                relay_registry_.resize(worker_count);
                relay_index_.resize(worker_count);
                registry_dirty.reserve(worker_count);
                // batch330: pre-size the per-worker hot containers. Growing
                // them on the data path reallocates while the registry/accept
                // mutex is held (a 4096-entry std::vector reallocation is a
                // memcpy of every shared_ptr) and, for the hash index, forces
                // rehash spikes exactly when the connection count climbs.
                // max_conns caps the live relays, so this is a hard bound.
                for (uint32_t i = 0; i < worker_count; ++i) {
                    const size_t per_worker =
                        runtime::PerWorkerReserve(config.perf.max_conns,
                                                 worker_count);
                    pending_accepts[i].reserve(per_worker);
                    pending_teardowns_[i].reserve(per_worker);
                    relay_registry_[i].reserve(per_worker);
                    relay_index_[i].reserve(per_worker);
                }
                for (uint32_t i = 0; i < worker_count; ++i) {
                    registry_dirty.push_back(
                        std::make_unique<std::atomic<bool>>(false));
                    udp_tables.push_back(std::make_unique<relay::UdpFlowTable>(
                        config.perf.udp_flow_cap, std::chrono::seconds(60)));

                    // Raw ICMP socket per worker. Opening one requires admin
                    // rights; without them we degrade gracefully - the relay
                    // slot stays null and client pings are not relayed, but
                    // the gateway keeps running.
                    std::shared_ptr<relay::IcmpRelay> icmp_relay;
                    std::error_code icmp_err;
                    asio::ip::icmp::socket icmp_socket(*io_contexts[i]);
                    icmp_socket.open(asio::ip::icmp::v4(), icmp_err);
                    if (!icmp_err) {
                        icmp_relay =
                            std::make_shared<relay::IcmpRelay>(
                                std::move(icmp_socket));
                        icmp_relay->ArmReceive(
                            [this, i](const uint8_t* pkt, size_t len) {
                                HandleIcmpReply(i, pkt, len);
                            });
                    }
                    icmp_relays.push_back(std::move(icmp_relay));
                }

                stack = std::make_unique<xtcp::XtcpStack>(&backend);
                stack->SetMaxConnections(config.perf.max_conns);
                stack->StartMimt([this](std::shared_ptr<xtcp::mimt::MimtFlow> flow) {
                    // Runs under the shard lock: enqueue only, no stack API
                    // re-entry allowed here (see stack.h RecvHandler warning).
                    // The flow's SHARD decides its owner: worker
                    // (shard % worker_count) both drains the accept queue and
                    // pumps the shard via DispatchMimt(shard), so every relay
                    // callback fires on exactly one thread.
                    const uint32_t idx =
                        xtcp::XtcpStack::ShardIndexOf(flow->ConnId()) %
                        worker_count;
                    if (idx < worker_count) {
                        std::lock_guard<std::mutex> lock(accept_mutexes[idx]);
                        // Bound the backlog: each parked flow buffers up to
                        // 1 MiB while we dial (<=10 s). Beyond this we RST
                        // instead of letting a SYN flood pin gigabytes.
                        static constexpr size_t kMaxPendingAccepts = 64;
                        if (pending_accepts[idx].size() >=
                            kMaxPendingAccepts) {
                            flow->Close();
                            return;
                        }
                        pending_accepts[idx].push_back(std::move(flow));
                        ++stats->tcp_accepted;  // counted only when actually queued
                    }
                });
                // Port-forwarding enforcement: route stack callbacks for
                // reverse-NAT connections to the manager (unknown conn_ids
                // are ignored inside the manager).
                stack->SetRecvHandlerChecked(
                    [](UInt64 conn_id, const Byte* data, UInt32 len) {
                        return relay::PortMapManager::Instance().OnStackData(
                            conn_id, data, len);
                    });
                stack->SetStateHandler(
                    [this](UInt64 conn_id, xtcp::core::TcpState state) {
                        relay::PortMapManager::Instance().OnStackState(
                            conn_id, static_cast<int>(state));
                        if (xtcp::core::TcpState::kCloseWait == state) {
                            // The client half-closed (its FIN): propagate the
                            // half-close to the owning relay so the upstream
                            // socket shuts its send direction (FIN to the
                            // server) instead of hanging or being RST later.
                            NotifyPeerFin(conn_id);
                        }
                    });

                // DHCPv4 (S2): assemble only in main mode with the service
                // enabled. Bypass must never assemble, persist or sweep - a
                // client that points at VGWW manually keeps its own DHCP.
                if (core::AddressServicesEnabled(config) && config.dhcp.enabled) {
                    dhcp_ = std::make_unique<dhcp::DhcpServer>(config);
                    size_t dropped = 0;
                    const auto outcome = dhcp_->LoadLeases(
                        lease_file, std::chrono::steady_clock::now(),
                        &dropped);
                    // batch34b: a corrupt/oversized/future-schema file used
                    // to be reported as "no lease file", hiding the fact that
                    // every persisted mapping was discarded.
                    const char* status =
                        outcome == dhcp::DhcpServer::LoadOutcome::kRestored
                            ? "leases restored"
                            : (outcome ==
                                       dhcp::DhcpServer::LoadOutcome::kNoFile
                                   ? "no lease file"
                                   : (outcome == dhcp::DhcpServer::LoadOutcome::
                                                      kUnreadable
                                          ? "LEASE FILE NOT READABLE (a "
                                            "scanner may hold it) - "
                                            "persistence paused, file kept"
                                          : "LEASE FILE UNREADABLE - mappings "
                                            "lost"));
                    std::fprintf(stderr,
                                 "[vgww] dhcp: v4 server assembled (%s)\n",
                                 status);
                    if (dropped > 0) {
                        std::fprintf(stderr,
                                     "[vgww] dhcp: %zu persisted lease(s) "
                                     "dropped as stale/invalid\n",
                                     dropped);
                    }
                } else {
                    std::fprintf(stderr,
                                 "[vgww] dhcp: v4 server not assembled "
                                 "(bypass mode or dhcp.enabled=false)\n");
                }
                // DHCPv6 (S2-Task8): the v4 gate plus the IPv6 switch; the
                // pool default (prefix::1000-::1FFF) is resolved by the server.
                if (core::AddressServicesEnabled(config) && config.ipv6.enabled &&
                    config.ipv6.dhcpv6.enabled) {
                    dhcp6_ = std::make_unique<dhcp6::Dhcp6Server>(config);
                    size_t dropped6 = 0;
                    const auto outcome6 = dhcp6_->LoadLeases(
                        LeaseFile6(), std::chrono::steady_clock::now(),
                        &dropped6);
                    // batch34c: same fix as v4 - a corrupt/oversized/future
                    // file must not be reported as a clean first run.
                    const char* status6 =
                        outcome6 == dhcp6::Dhcp6Server::LoadOutcome::kRestored
                            ? "leases restored"
                            : (outcome6 ==
                                       dhcp6::Dhcp6Server::LoadOutcome::kNoFile
                                   ? "no lease file"
                                   : (outcome6 == dhcp6::Dhcp6Server::
                                                      LoadOutcome::kUnreadable
                                          ? "LEASE FILE NOT READABLE (a "
                                            "scanner may hold it) - "
                                            "persistence paused, file kept"
                                          : "LEASE FILE UNREADABLE - mappings "
                                            "lost"));
                    std::fprintf(stderr,
                                 "[vgww] dhcp6: v6 server assembled (%s)\n",
                                 status6);
                    if (dropped6 > 0) {
                        std::fprintf(stderr,
                                     "[vgww] dhcp6: %zu persisted lease(s) "
                                     "dropped as stale/invalid\n",
                                     dropped6);
                    }
                } else {
                    std::fprintf(stderr,
                                 "[vgww] dhcp6: v6 server not assembled "
                                 "(bypass mode, ipv6.enabled=false or "
                                 "ipv6.dhcpv6.enabled=false)\n");
                }
                // Port-forwarding engine (WAN acceptors + reverse relays).
                // WAN->LAN forwarding: the manager thread has no worker context, so
                // its Send requests are queued here and flushed on worker 0
                // (the only thread allowed to drive the stack emit path).
                // A false return (peer window full) re-queues for retry.
                portmap_send_queue_ =
                    std::make_shared<PortmapSendQueue>();
                relay::PortMapManager::Instance().Start(
                    stack.get(), config,
                    [this, queue = portmap_send_queue_](
                        uint64_t conn_id, const uint8_t* data,
                        uint32_t len) -> bool {
                        // C5: the WAN->LAN queue is a HARD cap. Over it the
                        // packet is dropped+counted and the manager's WAN
                        // read chain is paused (false) until the queue drains.
                        std::lock_guard<std::mutex> lock(queue->mutex);
                        if (queue->items.size() >= kPortmapSendQueueCap) {
                            ++stats->portmap_send_dropped;
                            portmap_need_resume_.store(
                                true, std::memory_order_relaxed);
                            return false;
                        }
                        queue->items.push_back(
                            {conn_id,
                             core::PoolVector<uint8_t>(data, data + len)});
                        return true;
                    },
                    [this](uint64_t conn_id, bool graceful) {
                        // Route the teardown to the shard-owning worker so
                        // the emitted RST/FIN runs under a valid TX ring
                        // (see DrainAborts).
                        const uint32_t shard =
                            static_cast<uint32_t>(conn_id >> 56);
                        const uint32_t worker = shard % worker_count;
                        if (worker >=
                            static_cast<uint32_t>(abort_mutexes.size())) {
                            return;
                        }
                        std::lock_guard<std::mutex> lock(
                            abort_mutexes[worker]);
                        pending_teardowns_[worker].push_back(
                            {conn_id, graceful});
                    });
                running.store(true);
                // batch31 P1-4: Windows' default timer resolution is 15.6 ms,
                // which rounds every WaitForSingleObject timeout up to it - a
                // configured 10 ms RX poll really waited ~15.6 ms (measured:
                // p95 31 ms). Ask for 1 ms while the data plane runs; the
                // matching timeEndPeriod is in StopAll.
                timer_period_active_ =
                    0 == ::timeBeginPeriod(kTimerPeriodMs);

                // Announce the virtual gateway before traffic flows.
                std::array<uint8_t, proto::kArpFrameLen> gratuitous{};
                proto::BuildGratuitousAnnouncement(config.gateway.ipv4,
                                                   config.gateway.mac, gratuitous);
                PortBatch boot;
                boot.handle = adapter->handle;
                AppendDown(boot, gratuitous.data(), gratuitous.size());
                FlushBatch(*adapter, boot.items, true);

                workers.reserve(worker_count);
                for (uint32_t i = 0; i < worker_count; ++i) {
                    workers.emplace_back([this, i] {
                        RunGuarded("worker", [this, i] { WorkerLoop(i); });
                    });
                }
                control_thread = std::thread([this] {
                    RunGuarded("control", [this] { ControlLoop(); });
                });
                rx_tx_thread = std::thread([this] {
                    RunGuarded("rx", [this] { RxTxLoop(); });
                });
                SetAdapterBinding(*adapter);
                return true;
            } catch (const std::exception& ex) {
                // An exception while arming the start path (ring/thread/stack
                // allocation) must not leak the rx_event handle nor leave
                // `running` latched for a half-built plane (S1-T17).
                AbortBridge();
                // C3: PortMapManager::Start ran before this point; a leaked
                // manager thread would keep accepting WAN connections and a
                // retry Start would re-assign its joinable thread ->
                // std::terminate.
                relay::PortMapManager::Instance().Stop();
                rx_event.reset();
                dhcp_.reset();  // half-built start: no server survives
                dhcp6_.reset();
                up_client.reset();
                up_adapter = nullptr;
                running.store(false);
                if (timer_period_active_) {
                    ::timeEndPeriod(kTimerPeriodMs);
                    timer_period_active_ = false;
                }
                error = std::string("dataplane start failed: ") + ex.what();
                return false;
            } catch (...) {
                AbortBridge();
                relay::PortMapManager::Instance().Stop();
                rx_event.reset();
                dhcp_.reset();
                dhcp6_.reset();
                up_client.reset();
                up_adapter = nullptr;
                running.store(false);
                if (timer_period_active_) {
                    ::timeEndPeriod(kTimerPeriodMs);
                    timer_period_active_ = false;
                }
                error = "dataplane start failed: unknown exception";
                return false;
            }

            /// H2 per-thread cooperative-exit budget. 5s covers an in-flight
            /// relay (retry drain + FIN half-close); a thread that misses it
            /// is abandoned, never terminated: TerminateThread cannot make
            /// the thread's reachable objects safe to free.
            static constexpr uint32_t kThreadJoinTimeoutMs = 5000;

            /// Waits up to kThreadJoinTimeoutMs for `t` to exit and joins it
            /// when it did. Returns false WITHOUT touching the thread when it
            /// did not; the caller must detach it and keep every object the
            /// thread can reach alive (H2).
            static bool WaitThread(std::thread& t) noexcept {
                if (WAIT_OBJECT_0 ==
                    ::WaitForSingleObject(t.native_handle(),
                                          kThreadJoinTimeoutMs)) {
                    t.join();
                    return true;
                }
                return false;
            }

            /// All thread/ring/table containers empty? Start() asserts this
            /// so a Stop->Start cycle can never append onto stale state (H3).
            bool StateIsEmpty() const noexcept {
                return rx_rings.empty() && tx_rings.empty() &&
                       io_contexts.empty() && udp_tables.empty() &&
                       icmp_relays.empty() && relay_registry_.empty() &&
                       relay_index_.empty() && registry_dirty.empty() &&
                       accept_mutexes.empty() && pending_accepts.empty() &&
                       abort_mutexes.empty() && pending_teardowns_.empty() &&
                       registry_mutexes.empty() && workers.empty() &&
                       !rx_tx_thread.joinable() &&
                       !control_thread.joinable() && nullptr == stack &&
                       !portmap_send_queue_ && nullptr == adapter &&
                       nullptr == up_client && nullptr == rx_event &&
                       nullptr == dhcp_ &&
                       nullptr == dhcp6_ && !bridge_thread_.joinable() &&
                       nullptr == bridge_event_ && !bridge_broken_ &&
                       bridge::BridgeState::kStopped ==
                           bridge_state_.load();
            }

            /// Cooperative shutdown (H2). Every loop polls `running`; a
            /// thread that does not exit within kThreadJoinTimeoutMs makes
            /// Stop return false and NO thread-reachable object is freed
            /// (no TerminateThread + free = no UAF). Clean stops reset every
            /// container so the next Start begins from an empty state (H3).
            bool StopAll(std::string& error) noexcept try {
                if (shutdown_incomplete_) {
                    error = "dataplane stop incomplete: process restart "
                            "required";
                    return false;
                }
                const auto t0 = std::chrono::steady_clock::now();
                auto mark = [&](const char* what) {
                    std::fprintf(stderr, "[vgww] stop: %s at %lldms\n", what,
                                 static_cast<long long>(
                                     std::chrono::duration_cast<
                                         std::chrono::milliseconds>(
                                         std::chrono::steady_clock::now() - t0)
                                         .count()));
                };
                mark("begin");
                running.store(false);
                // Portmap first: its thread consumes the send queue and
                // drives the stack; joining it before the dataplane threads
                // removes the cross-thread shutdown dependency.
                relay::PortMapManager::Instance().Stop();
                mark("portmap joined");
                if (rx_event) {
                    ::SetEvent(rx_event.get());  // wake the RX thread
                }
                if (bridge_event_) {
                    bridge::StopBridgeLoop(bridge_loop_rt_);
                    ::SetEvent(bridge_event_.get());  // wake bridge thread
                }
                bool clean = true;
                if (rx_tx_thread.joinable() && !WaitThread(rx_tx_thread)) {
                    rx_tx_thread.detach();  // never TerminateThread (H2)
                    clean = false;
                }
                mark("rx_tx joined");
                for (std::thread& worker : workers) {
                    if (worker.joinable() && !WaitThread(worker)) {
                        worker.detach();
                        clean = false;
                    }
                }
                workers.clear();
                mark("workers joined");
                if (control_thread.joinable() &&
                    !WaitThread(control_thread)) {
                    control_thread.detach();
                    clean = false;
                }
                mark("control joined");
                if (bridge_thread_.joinable() && !JoinBridgeThread()) {
                    clean = false;  // H2: detached, objects stay alive
                }
                mark("bridge joined");

                if (!clean) {
                    // A thread may still run inside driver/stack code: free
                    // NOTHING it can touch. Leave rx_event open (a foreign
                    // wait may be parked on it), leave the client attached
                    // and the adapter mode untouched. If the process exits
                    // while the thread runs, ~Dataplane() leaks Impl on
                    // purpose - the OS reclaims it.
                    shutdown_incomplete_ = true;
                    error = "dataplane stop incomplete: a thread did not "
                            "exit within timeout; restart refused (process "
                            "restart required)";
                    return false;
                }

                // Persist the DHCPv4 leases before any object is torn down: a
                // restart then keeps address mappings stable. Reached only on
                // a clean stop, so no live thread can touch the server.
                bool lease_persist_failed = false;
                std::string lease_persist_error;
                if (dhcp_) {
                    if (!dhcp_->DumpLeases(lease_file,
                                           std::chrono::steady_clock::now())) {
                        lease_persist_failed = true;
                        lease_persist_error +=
                            "dhcp: lease dump failed on stop: " + lease_file;
                        std::fprintf(stderr,
                                     "[vgww] dhcp: lease dump failed on stop: "
                                     "%s\n",
                                     lease_file.c_str());
                    }
                    dhcp_.reset();
                }

                // Persist the DHCPv6 leases with the same clean-stop rule so
                // a restart keeps v6 address mappings stable.
                if (dhcp6_) {
                    if (!dhcp6_->DumpLeases(LeaseFile6(),
                                            std::chrono::steady_clock::now())) {
                        if (lease_persist_failed) {
                            lease_persist_error += "; ";
                        }
                        lease_persist_failed = true;
                        lease_persist_error +=
                            "dhcp6: lease dump failed on stop: " +
                            LeaseFile6();
                        std::fprintf(stderr,
                                     "[vgww] dhcp6: lease dump failed on stop: "
                                     "%s\n",
                                     LeaseFile6().c_str());
                    }
                    dhcp6_.reset();
                }
                // batch100: the teardown itself succeeded, so Stop() still
                // returns true - but a dirty lease document must not look
                // like a clean shutdown. The sticky flag survives the server
                // teardown; the text is attached after the success path's
                // final error.clear() below.
                stop_persist_failed_ = lease_persist_failed;

                if (nullptr != adapter && nullptr != client) {
                    std::string ignored;
                    client->ResetAdapterMode(*adapter, ignored);
                    // Bridge shutdown (reverse order): reset the downstream
                    // mode, then restore both saved promiscuous filters.
                    // A vanished adapter is skipped, never dereferenced.
                    if (bridge_mode_down_) {
                        const driver::AdapterEntry* downstream =
                            FindByHandle(bridge_downstream_handle_);
                        if (nullptr != downstream) {
                            client->ResetAdapterMode(*downstream, ignored);
                        }
                        bridge_mode_down_ = false;
                    }
                    if (bridge_filter_up_) {
                        client->SetHwPacketFilter(*adapter,
                                                  bridge_saved_filter_up_,
                                                  ignored);
                        bridge_filter_up_ = false;
                    }
                    if (bridge_filter_down_) {
                        const driver::AdapterEntry* downstream =
                            FindByHandle(bridge_downstream_handle_);
                        if (nullptr != downstream) {
                            client->SetHwPacketFilter(
                                *downstream, bridge_saved_filter_down_,
                                ignored);
                        }
                        bridge_filter_down_ = false;
                    }
                    bridge_mode_up_ = false;
                }
                rx_event.reset();
                bridge_event_.reset();
                mark("teardown begin");
                stack.reset();
                // H2/H3 order: every socket-owning container must die BEFORE
                // the io_context that owns its asio service. Destroying an
                // io_context while a socket/relay still references it is a
                // use-after-free (caught by the lifecycle test as a segfault
                // when io_contexts.clear() ran first).
                relay_registry_.clear();  // upstream TCP sockets
                relay_index_.clear();
                registry_dirty.clear();
                icmp_relays.clear();      // raw ICMP sockets
                udp_tables.clear();       // per-flow UDP sockets
                io_contexts.clear();      // last: contexts outlive no socket
                accept_mutexes.clear();
                pending_accepts.clear();
                abort_mutexes.clear();
                pending_teardowns_.clear();
                registry_mutexes.clear();
                rx_rings.clear();
                tx_rings.clear();
                portmap_send_queue_.reset();
                worker_count = 0;
                // Bridge counts reset so the next Start begins empty (H3).
                bridge_upstream_handle_ = nullptr;
                bridge_downstream_handle_ = nullptr;
                {
                    std::lock_guard<std::mutex> lock(bridge_queue_mutex_);
                    bridge_control_queue_.clear();
                }
                bridge_table_.Clear();
                bridge_forwarded_.store(0);
                bridge_dropped_.store(0);
                MarkBridgeStopped();
                periodic_ra_due.store(false);
                live_rates_.clear();
                std::atomic_store(&published_rates_,
                                  std::make_shared<ClientRatesSnapshot>());
                std::atomic_store(&ban_index_snapshot_,
                                  std::make_shared<const BanIndex>());
                if (!client_injected_) {
                    client.reset();
                }
                up_client.reset();
                up_adapter = nullptr;
                adapter = nullptr;
                ClearAdapterBinding();
                error.clear();
                // batch100: a clean teardown with a failed lease snapshot is
                // reported through the error text (Stop still returns true:
                // the plane did stop). StopPersistFailed() keeps the verdict
                // readable after the servers are gone.
                if (lease_persist_failed) {
                    error = lease_persist_error;
                }
                // batch31 P1-4: release the 1 ms timer resolution exactly once,
                // after every thread that relied on it is joined.
                if (timer_period_active_) {
                    ::timeEndPeriod(kTimerPeriodMs);
                    timer_period_active_ = false;
                }
                mark("teardown done");
                return true;
            } catch (const std::exception& ex) {
                // The teardown touches virtual driver calls and allocating
                // snapshots; a throw inside noexcept would terminate. Report
                // the failure instead (S1-T17); StateIsEmpty() keeps the
                // half-torn state from being restarted.
                error = std::string("dataplane stop teardown failed: ") +
                        ex.what();
                return false;
            } catch (...) {
                error = "dataplane stop teardown failed: unknown exception";
                return false;
            }

            // ----- L2 bridge (S3-Task3) --------------------------------------
            /// Re-resolves a live adapter entry by driver handle; null when
            /// the adapter vanished (hot-removal) so driver calls are
            /// skipped instead of crashing.
            const driver::AdapterEntry* FindByHandle(void* handle) const {
                if (nullptr == handle || nullptr == client) {
                    return nullptr;
                }
                for (const driver::AdapterEntry& entry : client->Adapters()) {
                    if (entry.handle == handle) {
                        return &entry;
                    }
                }
                return nullptr;
            }

            /// Brings the bridge up after the primary assembly point.
            /// Order: save both filters -> bridge modes -> promiscuous
            /// filters -> downstream event+arm -> table+thread. Any step
            /// failing rolls back everything already applied (reverse).
            bool StartBridge(std::string& error) {
                static constexpr uint32_t kBridgeMode =
                    driver::kSentListen | driver::kRecvListen |
                    driver::kFilterDirect | driver::kLoopbackBlock;
                static constexpr uint32_t kPromiscuous = 0x00000020;
                const std::wstring down_hint =
                    driver::WidenAdapterHint(bridge_cfg_.downstream);
                const driver::AdapterEntry* downstream = nullptr;
                bool down_ambiguous = false;
                downstream = client->FindAdapter(down_hint, &down_ambiguous);
                if (nullptr == downstream) {
                    error = "bridge: no adapter matches downstream \"" +
                            bridge_cfg_.downstream +
                            "\". Available adapters: " +
                            RenderAdapterCandidates(client->Adapters());
                    return false;
                }
                if (down_ambiguous) {
                    error = "bridge: adapter matching is ambiguous for "
                            "downstream \"" +
                            bridge_cfg_.downstream +
                            "\"; use a more specific hint or the full "
                            "\\DEVICE\\{GUID} path";
                    return false;
                }
                const driver::AdapterEntry* upstream = adapter;
                if (!bridge_cfg_.upstream.empty()) {
                    const std::wstring up_hint =
                        driver::WidenAdapterHint(bridge_cfg_.upstream);
                    bool up_ambiguous = false;
                    upstream = client->FindAdapter(up_hint, &up_ambiguous);
                    if (nullptr == upstream) {
                        error = "bridge: no adapter matches upstream \"" +
                                bridge_cfg_.upstream +
                                "\". Available adapters: " +
                                RenderAdapterCandidates(client->Adapters());
                        return false;
                    }
                    if (up_ambiguous) {
                        error = "bridge: adapter matching is ambiguous for "
                                "upstream \"" +
                                bridge_cfg_.upstream +
                                "\"; use a more specific hint or the full "
                                "\\DEVICE\\{GUID} path";
                        return false;
                    }
                }
                if (upstream->handle == downstream->handle) {
                    error = "bridge: upstream and downstream resolve to the "
                            "same adapter";
                    return false;
                }
                uint32_t saved_up = 0;
                uint32_t saved_down = 0;
                if (!client->GetHwPacketFilter(*upstream, saved_up, error)) {
                    error =
                        "bridge: cannot save upstream filter: " + error;
                    return false;
                }
                if (!client->GetHwPacketFilter(*downstream, saved_down,
                                               error)) {
                    error =
                        "bridge: cannot save downstream filter: " + error;
                    return false;
                }
                bridge_saved_filter_up_ = saved_up;
                bridge_saved_filter_down_ = saved_down;
                bridge_upstream_handle_ = upstream->handle;
                bridge_downstream_handle_ = downstream->handle;
                if (!client->SetAdapterMode(*upstream, kBridgeMode, error)) {
                    error = "bridge: cannot set upstream mode: " + error;
                    RollbackBridge();
                    return false;
                }
                bridge_mode_up_ = true;
                if (!client->SetAdapterMode(*downstream, kBridgeMode, error)) {
                    error = "bridge: cannot set downstream mode: " + error;
                    RollbackBridge();
                    return false;
                }
                bridge_mode_down_ = true;
                if (!client->SetHwPacketFilter(*upstream, kPromiscuous,
                                               error)) {
                    error =
                        "bridge: cannot set upstream filter: " + error;
                    RollbackBridge();
                    return false;
                }
                bridge_filter_up_ = true;
                if (!client->SetHwPacketFilter(*downstream, kPromiscuous,
                                               error)) {
                    error =
                        "bridge: cannot set downstream filter: " + error;
                    RollbackBridge();
                    return false;
                }
                bridge_filter_down_ = true;
                // The primary adapter is already armed on rx_event; the
                // bridge arms the downstream adapter (ArmRxEvent x2 total).
                bridge_event_.reset(
                    ::CreateEventW(nullptr, FALSE, FALSE, nullptr));
                if (!bridge_event_) {
                    error = "bridge: CreateEvent failed";
                    RollbackBridge();
                    return false;
                }
                if (!client->ArmRxEvent(*downstream, bridge_event_.get(),
                                        error)) {
                    error = "bridge: cannot arm downstream event: " + error;
                    RollbackBridge();
                    return false;
                }
                try {
                    bridge_table_.Reset(bridge_cfg_.mac_table_size);
                } catch (const std::exception& ex) {
                    error = std::string("bridge: table alloc failed: ") +
                            ex.what();
                    RollbackBridge();
                    return false;
                } catch (...) {
                    error = "bridge: table alloc failed";
                    RollbackBridge();
                    return false;
                }
                {
                    std::lock_guard<std::mutex> lock(bridge_queue_mutex_);
                    bridge_control_queue_.clear();
                }
                bridge_forwarded_.store(0);
                bridge_dropped_.store(0);
                bridge_loop_rt_.stop_requested.store(false);
                bridge_active_.store(true);
                bridge_state_.store(bridge::BridgeState::kRunning);
                try {
                    bridge_thread_ = std::thread([this] {
                        RunGuarded("bridge", [this] { BridgeThreadLoop(); });
                    });
} catch (...) {
                    error = "bridge: cannot start bridge thread";
                    RollbackBridge();
                    MarkBridgeStopped();
                    return false;
                }
                return true;
            }

            /// Reverse-order undo of StartBridge (noexcept): close the event,
            /// restore saved filters, reset applied modes. Missing adapters
            /// (hot-removal mid-start) are skipped.
            void RollbackBridge() noexcept {
                try {
                    bridge_event_.reset();
                    std::string ignored;
                    if (bridge_filter_down_) {
                        const driver::AdapterEntry* downstream =
                            FindByHandle(bridge_downstream_handle_);
                        if (nullptr != downstream) {
                            client->SetHwPacketFilter(
                                *downstream, bridge_saved_filter_down_,
                                ignored);
                        }
                        bridge_filter_down_ = false;
                    }
                    if (bridge_filter_up_) {
                        const driver::AdapterEntry* upstream =
                            FindByHandle(bridge_upstream_handle_);
                        if (nullptr != upstream) {
                            client->SetHwPacketFilter(
                                *upstream, bridge_saved_filter_up_, ignored);
                        }
                        bridge_filter_up_ = false;
                    }
                    if (bridge_mode_down_) {
                        const driver::AdapterEntry* downstream =
                            FindByHandle(bridge_downstream_handle_);
                        if (nullptr != downstream) {
                            client->ResetAdapterMode(*downstream, ignored);
                        }
                        bridge_mode_down_ = false;
                    }
                    if (bridge_mode_up_) {
                        const driver::AdapterEntry* upstream =
                            FindByHandle(bridge_upstream_handle_);
                        if (nullptr != upstream) {
                            client->ResetAdapterMode(*upstream, ignored);
                        }
                        bridge_mode_up_ = false;
                    }
                } catch (...) {
                    // Rollback is best-effort; Start already failed.
                }
            }

            /// Signals the bridge thread and joins it within the H2 budget.
            /// False on timeout (thread detached, objects kept alive).
            bool JoinBridgeThread() noexcept {
                if (!bridge_thread_.joinable()) {
                    return true;
                }
                bridge::StopBridgeLoop(bridge_loop_rt_);
                if (bridge_event_) {
                    ::SetEvent(bridge_event_.get());  // wake the wait
                }
                if (WaitThread(bridge_thread_)) {
                    return true;
                }
                bridge_thread_.detach();  // never TerminateThread (H2)
                return false;
            }

            /// Best-effort bridge teardown for failed starts (noexcept).
            /// A join timeout detaches but marks `bridge_broken_` so the
            /// next Start() is refused while a thread may still run.
            void AbortBridge() noexcept try {
                if (!JoinBridgeThread()) {
                    bridge_broken_ = true;
                }
                RollbackBridge();
                MarkBridgeStopped();
            } catch (...) {
                bridge_broken_ = true;
            }

            /// Sink adapter: forwards one decided frame peer-ward. Null or
            /// vanished peers count a drop instead of crashing.
            bool SendBridgeFrame(void* peer_handle, const uint8_t* data,
                                 size_t len) {
                static constexpr size_t kMaxFrameBytes = 1514;
                if (nullptr == peer_handle || nullptr == data || 0 == len ||
                    len > kMaxFrameBytes) {
                    return false;
                }
                INTERMEDIATE_BUFFER ib;
                std::memset(&ib, 0, sizeof(ib));
                ib.m_dwDeviceFlags = PACKET_FLAG_ON_SEND;
                ib.m_hAdapter = peer_handle;
                ib.m_Length = static_cast<DWORD>(len);
                std::memcpy(ib.m_IBuffer, data, len);
                std::string error;
                try {
                    return client->SendPacketsToAdapter(peer_handle, &ib, 1,
                                                        error);
                } catch (...) {
                    return false;
                }
            }

            /// Shared classify path (RX thread + bridge sink): learn, decide
            /// with bridge::LearnAndDecide, and send bridge/flood actions
            /// peer-ward. Returns the action for the control-plane split.
            bridge::BridgeAction BridgeTrip(const uint8_t* data, size_t len,
                                            uint32_t in_port) {
                net::WireMac gateway{};
                std::memcpy(gateway.data(), config.gateway.mac.data(),
                            net::kMacAddrLen);
                bridge::BridgeAction action = bridge::BridgeAction::kDrop;
                try {
                    action = bridge::LearnAndDecide(
                        bridge_table_, bridge_table_mutex_, data, len,
                        in_port, gateway);
                } catch (...) {
                    return bridge::BridgeAction::kDrop;
                }
                if (bridge::BridgeAction::kBridgeUnicast == action ||
                    bridge::BridgeAction::kBridgeFlood == action ||
                    bridge::BridgeAction::kControlAndFlood == action) {
                    void* peer = (bridge::kBridgePortUp == in_port)
                                     ? bridge_downstream_handle_
                                     : bridge_upstream_handle_;
                    if (nullptr == FindByHandle(peer)) {
                        peer = nullptr;  // vanished mid-flight: drop
                    }
                    if (SendBridgeFrame(peer, data, len)) {
                        ++bridge_forwarded_;
                    } else {
                        ++bridge_dropped_;
                    }
                }
                return action;
            }

            /// BridgeFrameSink target (bridge thread): bridge/flood actions
            /// go peer-ward (upstream); control actions are queued for the
            /// RX thread, which runs them through DispatchFrame with
            /// from_bridge=true so they are never re-flooded.
            void OnBridgeFrame(const uint8_t* data, size_t len,
                               uint32_t in_port,
                               bridge::BridgeAction action) {
                if (bridge::BridgeAction::kBridgeUnicast == action ||
                    bridge::BridgeAction::kBridgeFlood == action ||
                    bridge::BridgeAction::kControlAndFlood == action) {
                    void* peer =
                        (bridge::kBridgePortUp == in_port)
                            ? bridge_downstream_handle_
                            : bridge_upstream_handle_;
                    if (nullptr == FindByHandle(peer)) {
                        peer = nullptr;  // vanished mid-flight: drop
                    }
                    if (SendBridgeFrame(peer, data, len)) {
                        ++bridge_forwarded_;
                    } else {
                        ++bridge_dropped_;
                    }
                }
                if (bridge::BridgeAction::kControlOnly == action ||
                    bridge::BridgeAction::kControlAndFlood == action) {
                    static constexpr size_t kMaxFrameBytes = 1514;
                    if (nullptr != data && 0 != len &&
                        len <= kMaxFrameBytes) {
                        std::lock_guard<std::mutex> lock(bridge_queue_mutex_);
                        if (bridge_control_queue_.size() <
                            kBridgeControlQueueCap) {
                            bridge_control_queue_.emplace_back(data,
                                                               data + len);
                        } else {
                            ++bridge_dropped_;
                        }
                    } else {
                        ++bridge_dropped_;
                    }
                    if (rx_event) {
                        ::SetEvent(rx_event.get());  // wake the RX thread
                    }
                }
            }

            /// batch36: single choke point for the bridge -> kStopped
            /// transition. Every clean-stop/revert path runs through here so
            /// the failure reason is cleared exactly once - a reader must
            /// never pair kStopped (or a fresh kRunning) with a stale
            /// failure reason from an earlier run.
            void MarkBridgeStopped() noexcept {
                {
                    std::lock_guard<std::mutex> lock(bridge_error_mutex_);
                    bridge_error_.clear();
                }
                bridge_active_.store(false);
                bridge_state_.store(bridge::BridgeState::kStopped);
            }

            /// Bridge thread body: polls the downstream adapter through
            /// RunBridgeLoop; any fatal exit halts the bridge (failed,
            /// visible) while the dataplane keeps running.
            void BridgeThreadLoop() {
                struct Sink final : public bridge::BridgeFrameSink {
                    Impl* owner = nullptr;
                    void OnBridgeFrame(const uint8_t* data, size_t len,
                                       uint32_t in_port,
                                       bridge::BridgeAction action) override {
                        owner->OnBridgeFrame(data, len, in_port, action);
                    }
                };
                Sink sink;
                sink.owner = this;
                net::WireMac gateway{};
                std::memcpy(gateway.data(), config.gateway.mac.data(),
                            net::kMacAddrLen);
                // batch36: shared fatal-exit handler - publishes the reason
                // BEFORE flipping to kFailed (so a reader that observes
                // kFailed always has a matching explanation), then stops the
                // bridge. Used by both the pre-loop "port already gone" check
                // and the RunBridgeLoop fatal exit, so they can never
                // diverge in what they publish.
                auto FailBridge = [this](bridge::BridgeLoopExit exit,
                                         const std::string& why) {
                    std::fprintf(stderr, "[vgww] bridge: %s (%s)\n",
                                 bridge::BridgeLoopExit::kReadError == exit
                                     ? "read error, bridge halted"
                                     : "port disappeared, bridge halted",
                                 why.c_str());
                    {
                        std::lock_guard<std::mutex> lock(bridge_error_mutex_);
                        bridge_error_ =
                            (bridge::BridgeLoopExit::kReadError == exit)
                                ? "bridge read error: " + why
                                : "bridge port disappeared";
                    }
                    bridge_active_.store(false);
                    bridge_state_.store(bridge::BridgeState::kFailed);
                };
                // Snapshot the entry: the Adapters() vector may shrink on
                // hot-removal, so no entry pointer is retained.
                const driver::AdapterEntry* live =
                    FindByHandle(bridge_downstream_handle_);
                if (nullptr == live) {
                    FailBridge(bridge::BridgeLoopExit::kPortGone,
                               "downstream gone before thread start");
                    return;
                }
                const driver::AdapterEntry local = *live;
                auto wait = [this](uint32_t timeout_ms) -> bool {
                    return WAIT_OBJECT_0 == ::WaitForSingleObject(
                        bridge_event_.get(), timeout_ms);
                };
                std::string detail;
                const bridge::BridgeLoopExit exit = bridge::RunBridgeLoop(
                    *client, local, bridge::kBridgePortDown, bridge_table_,
                    bridge_table_mutex_, gateway, bridge_loop_rt_, sink,
                    wait, detail);
                if (bridge::BridgeLoopExit::kStopped != exit) {
                    FailBridge(exit, detail);
                }
            }

            /// Moves queued downstream control frames into DispatchFrame
            /// (RX thread, once per iteration). C8: those frames carry
            /// in_port=kBridgePortDown, so their replies land in the
            /// downstream batch (egress via the downstream adapter).
            void DrainBridgeControl(WireBatches& down, WireBatches& up) {
                std::deque<std::vector<uint8_t>> pending;
                {
                    std::lock_guard<std::mutex> lock(bridge_queue_mutex_);
                    if (bridge_control_queue_.empty()) {
                        return;
                    }
                    pending.swap(bridge_control_queue_);
                }
                for (const std::vector<uint8_t>& frame : pending) {
                    static constexpr size_t kMaxFrameBytes = 1514;
                    if (frame.empty() || frame.size() > kMaxFrameBytes) {
                        ++stats->rx_dropped;
                        continue;
                    }
                    INTERMEDIATE_BUFFER ib;
                    std::memset(&ib, 0, sizeof(ib));
                    std::memcpy(ib.m_IBuffer, frame.data(), frame.size());
                    ib.m_Length = static_cast<DWORD>(frame.size());
                    ib.m_dwDeviceFlags = PACKET_FLAG_ON_RECEIVE;
                    ib.m_hAdapter = bridge_downstream_handle_;
                    ++stats->rx_frames;
                    DispatchFrame(ib, down, up,
                                  bridge::kBridgePortDown,
                                  true /* from_bridge */);
                }
            }

            // ----- stack egress ----------------------------------------------
            /// Probes a missing/stale neighbor so the client re-announces its MAC:
            /// IPv4 via an ARP request, IPv6 via a Neighbor Solicitation
            /// (RFC 4861 section 4.3, solicited-node multicast). Runs on any worker
            /// via the matching worker's TX ring; the probe is throttled per
            /// client address (500 ms) and per worker slot. The frame is
            /// queued like any downlink frame, so the RX/TX thread emits it
            /// with the rest of the batch (no lock on the hot path beyond
            /// the small miss-side cache).
            /// batch300: the allocating body. The noexcept wrapper below
            /// turns an allocation failure into a dropped probe instead of
            /// std::terminate (ProbeArpFor runs inside noexcept handlers).
            void ProbeArpForImpl(const net::IpAddress& dst_ip) {
                if (kNoRing == t_worker_index ||
                    t_worker_index >= worker_count) {
                    return;
                }
                const auto now = std::chrono::steady_clock::now();
                const uint64_t us = static_cast<uint64_t>(
                    std::chrono::duration_cast<std::chrono::microseconds>(
                        now.time_since_epoch())
                        .count());
                if (dst_ip.IsV4()) {
                    uint8_t v4[4];
                    dst_ip.ToV4Wire(v4);
                    const uint32_t probe_ip = static_cast<uint32_t>(v4[0]) |
                                              (static_cast<uint32_t>(v4[1]) << 8) |
                                              (static_cast<uint32_t>(v4[2]) << 16) |
                                              (static_cast<uint32_t>(v4[3]) << 24);
                    {
                        std::lock_guard<std::mutex> lock(arp_probe_cache_.mutex);
                        // Keep the miss-side cache bounded: a long-lived gate
                        // with many ever-seen clients must not grow without
                        // limit (esp. if a /24 is scanned). Drop-all is fine -
                        // the table only throttles probe frequency.
                        if (arp_probe_cache_.last_us.size() >= 4096) {
                            arp_probe_cache_.last_us.clear();
                        }
                        auto& last = arp_probe_cache_.last_us[probe_ip];
                        if (us - last < 500000) {
                            return;
                        }
                        last = us;
                    }
                    std::array<uint8_t, proto::kArpFrameLen> req{};
                    proto::BuildArpFrame(req.data(), proto::ArpOperation::kRequest,
                                         config.gateway.mac, config.gateway.ipv4,
                                         net::kBroadcastMac, probe_ip);
                    TxFrame frame(req.begin(), req.end());
                    if (!tx_rings[t_worker_index]->Push(std::move(frame))) {
                        ++stats->rx_dropped;  // ring full: probe dropped
                    }
                    return;
                }
                // IPv6: NS probe throttled on the same cadence.
                {
                    std::lock_guard<std::mutex> lock(arp_probe_cache_.mutex);
                    if (arp_probe_cache_.v6_last_us.size() >= 4096) {
                        arp_probe_cache_.v6_last_us.clear();
                    }
                    auto& last = arp_probe_cache_.v6_last_us[dst_ip];
                    if (us - last < 500000) {
                        return;
                    }
                    last = us;
                }
                const auto ll = proto::LinkLocalFromMac(config.gateway.mac);
                std::vector<uint8_t> ns;
                proto::BuildNeighborSolicitationFrame(
                    dst_ip.bytes.data(), config.gateway.mac, ll.data(), ns);
                TxFrame frame(std::move(ns));
                if (!tx_rings[t_worker_index]->Push(std::move(frame))) {
                    ++stats->rx_dropped;  // ring full: probe dropped
                }
            }

            void ProbeArpFor(const net::IpAddress& dst_ip) noexcept {
                try {
                    ProbeArpForImpl(dst_ip);
                } catch (...) {
                    ++stats->rx_dropped;  // probe dropped: the next miss retries
                }
            }

            /// Builds a full Ethernet frame around a stack-emitted IP packet
            /// and queues it on the calling worker's TX ring.
            /// batch300: the allocating body. Backend::Tx is noexcept in the
            /// xtcp interface, so an allocation failure must be caught here:
            /// the frame is dropped (TCP retransmits) instead of terminating.
            bool EmitFromStackImpl(xtcp::ndi::Packet&& packet) {
                if (nullptr == packet.data || packet.len < 20 ||
                    kNoRing == t_worker_index || t_worker_index >= worker_count) {
                    ++stats->rx_dropped;
                    return true;  // consume-and-drop: TCP recovers via retransmit
                }
                const uint8_t* ip = packet.data;

                net::IpAddress dst_ip;
                if (0x86DD == packet.eth_type) {
                    if (packet.len < 40) {
                        ++stats->rx_dropped;
                        return true;
                    }
                    dst_ip = net::IpAddress::FromV6(ip + 24);
                } else {
                    dst_ip = net::IpAddress::FromV4BigEndian(ip + 16);
                }
                auto snap = neighbors.Snapshot();
                const tables::NeighborEntry* entry = snap->Find(dst_ip);
                if (nullptr == entry) {
                    ++stats->mac_misses;
                    ProbeArpFor(dst_ip);
                    return true;  // drop: TCP retransmits once ARP resolves
                }

                TxFrame frame(net::kEthernetHeaderLen + packet.len);
                net::BuildEthHeader(frame.data(), entry->mac, config.gateway.mac,
                                    packet.eth_type);
                std::memcpy(frame.data() + net::kEthernetHeaderLen, ip, packet.len);

                if (tx_rings[t_worker_index]->Push(TxFrame(std::move(frame)))) {
                    ++stats->tx_frames;
                } else {
                    ++stats->rx_dropped;  // ring full: frame vanished uncounted
                }
                return true;  // consumed
            }

            bool EmitFromStack(xtcp::ndi::Packet&& packet) noexcept {
                try {
                    return EmitFromStackImpl(std::move(packet));
                } catch (...) {
                    ++stats->rx_dropped;  // frame dropped: TCP retransmits
                    return true;          // consume-and-drop contract
                }
            }

            // ----- RX/TX thread ----------------------------------------------
            void RxTxLoop() {
                std::vector<INTERMEDIATE_BUFFER> ib_read(config.perf.rx_batch);
                // C8: wire-direction batches parameterized by bridge port.
                WireBatches down;  // toward the wire
                WireBatches up;    // toward MSTCP
                down.primary.handle = adapter->handle;
                up.primary.handle = adapter->handle;
                down.downstream.handle = bridge_downstream_handle_;
                up.downstream.handle = bridge_downstream_handle_;

                while (running.load()) {
                    const uint64_t wake_us = NowUs();
                    const DWORD waited =
                        ::WaitForSingleObject(rx_event.get(),
                                              config.perf.rx_poll_ms);
                    const uint64_t after_wait_us = NowUs();
                    if (lat_trace && WAIT_OBJECT_0 == waited) {
                        // How long the thread sat before the event woke it: the
                        // "wake-up granularity" segment of the latency budget.
                        lat_wait_us = after_wait_us - wake_us;
                    }

                    // Drain the kernel queue completely (bounded by batches).
                    for (int round = 0; round < 64; ++round) {
                        std::string err;
                        const uint32_t n =
                            client->ReadPackets(adapter->handle, ib_read.data(),
                                                config.perf.rx_batch, err);
                        if (0 == n) {
                            // Mostly just an empty queue, but a genuine
                            // IOCTL failure must not vanish silently: report
                            // each distinct error text once.
                            if (!err.empty() && last_ioctl_warn_ != err) {
                                last_ioctl_warn_ = err;
                                std::fprintf(stderr, "[vgww] driver: %s\n",
                                             err.c_str());
                            }
                            break;
                        }
                        for (uint32_t k = 0; k < n; ++k) {
                            INTERMEDIATE_BUFFER& ib = ib_read[k];
                            ++stats->rx_frames;
                            if (lat_trace) {
                                lat_read_us = NowUs();
                            }
                            DispatchFrame(ib, down, up);
                        }
                        // batch31 P1-4 (root cause): a control-plane reply
                        // built here used to wait for the WHOLE kernel-queue
                        // drain (up to 64 x rx_batch frames) plus the worker
                        // TX-ring drain before its SendPacketsToMstcp IOCTL
                        // ran, so ping latency grew with unrelated traffic.
                        // Eager flush sends the replies of THIS batch at once.
                        // Trade-off: one extra IOCTL per non-empty batch under
                        // heavy load; `perf.rx_flush_eager=false` restores the
                        // old cross-round batching (throughput over latency).
                        if (config.perf.rx_flush_eager) {
                            FlushPortBatch(down.primary, true);
                            FlushPortBatch(down.downstream, true);
                            FlushPortBatch(up.primary, false);
                            FlushPortBatch(up.downstream, false);
                            LatTraceFlush();
                        }
                    }

                    // Bridge handoff: downstream control frames queued by
                    // the bridge thread re-enter DispatchFrame here with
                    // from_bridge=true (control only, never re-flooded).
                    if (bridge_active_.load()) {
                        DrainBridgeControl(down, up);
                    }

                    // Drain every worker TX ring into the downstream batch.
                    TxFrame frame;
                    for (uint32_t i = 0; i < worker_count; ++i) {
                        while (1 == tx_rings[i]->PopBatch(&frame, 1)) {
                            // Downlink rate limit: cap bytes handed to each
                            // client. Only fully-synthesized Ethernet frames
                            // arrive here (dst MAC at [0..5]); a frame too
                            // short to parse is forwarded untouched.
                            if (frame.size() >= net::kMacAddrLen) {
                                net::WireMac dst{};
                                std::memcpy(dst.data(), frame.data(),
                                            net::kMacAddrLen);
                                if (!rate_limiter_.AllowDownlink(
                                        dst, frame.size(),
                                        std::chrono::steady_clock::now())) {
                                    ++stats->rate_limited;
                                    continue;  // drop: TCP retransmits as needed
                                }
                            }
                            // Per-client down-rate accounting: every frame we
                            // push toward the wire belongs to its destination
                            // MAC (skipped for broadcast/group destinations).
                            if (frame.size() >= net::kEthernetHeaderLen) {
                                core::MacAddress dst;
                                std::memcpy(dst.data(), frame.data(),
                                            net::kMacAddrLen);
                                if (!net::IsGroupAddress(dst)) {
                                    // batch94: same cap as the uplink path.
                                    // TX destinations are normally learned
                                    // neighbours, but the guard keeps both
                                    // insert sites identical so the table bound
                                    // holds no matter which direction floods.
                                    if (live_rates_.size() >=
                                            ::vgww::core::limits::kMaxNeighbors &&
                                        live_rates_.find(dst) ==
                                            live_rates_.end()) {
                                        ++stats->rate_table_dropped;
                                    } else {
                                        live_rates_[dst].down_bytes +=
                                            frame.size();
                                    }
                                }
                            }
                            // C8 data-plane return path: a bridged reply to a
                            // client learned on the downstream port must leave
                            // through that adapter. The worker TX ring carries
                            // no port tag, so the egress is resolved from the
                            // frame's destination MAC via the bridge MAC table.
                            // Group MACs are never learned (nullopt) and a
                            // non-bridge dataplane has an empty/inactive table,
                            // so both fall back to the primary adapter
                            // (byte-identical non-bridge behavior).
                            // NOTE: bind by POINTER. A `PortBatch&` rebind via
                            // assignment would copy-assign the struct, clobbering
                            // down.primary's handle+items (never do that here).
                            PortBatch* egress = &down.primary;
                            if (bridge_active_.load() &&
                                frame.size() >= net::kMacAddrLen) {
                                net::WireMac dst{};
                                std::memcpy(dst.data(), frame.data(),
                                            net::kMacAddrLen);
                                std::optional<uint32_t> learned;
                                {
                                    std::lock_guard<std::mutex> lock(
                                        bridge_table_mutex_);
                                    learned = bridge_table_.Lookup(dst);
                                }
                                if (learned.has_value() &&
                                    bridge::kBridgePortDown ==
                                        learned.value()) {
                                    egress = &down.downstream;
                                }
                            }
                            AppendDown(*egress, frame.data(), frame.size());
                        }
                    }
                    FlushPortBatch(down.primary, true);
                    FlushPortBatch(down.downstream, true);
                    FlushPortBatch(up.primary, false);
                    FlushPortBatch(up.downstream, false);
                    LatTraceFlush();


                    // Periodic unsolicited RA (flag raised by ControlLoop).
                    // Address services only: a bypass bridge never advertises
                    // itself as a router (S2 spec section 3).
                    if (periodic_ra_due.exchange(false) && config.ipv6.enabled &&
                        core::AddressServicesEnabled(config)) {
                        const auto ll =
                            proto::LinkLocalFromMac(config.gateway.mac);
                        std::vector<uint8_t> ra;
                        proto::BuildRouterAdvertisementFrame(
                            config.gateway.mac, ll.data(),
                            config.ipv6.ula_prefix.data(),
                            config.ipv6.prefix_len, config.ipv6.ra_lifetime_s,
                            true, true, adapter ? adapter->mtu : 0,
                            config.ipv6.dns, ra);
                        AppendDown(down.primary, ra.data(), ra.size());
                        FlushPortBatch(down.primary, true);
                    }

                    // Publish the finished second-window of per-client rates:
                    // swap the live map out and publish it immutably (web_api
                    // reads this snapshot; the next second starts fresh).
                    const auto now = std::chrono::steady_clock::now();
                    if (now - rate_window_start_ >= std::chrono::seconds(1)) {
                        auto snapshot =
                            std::make_shared<ClientRatesSnapshot>();
                        const double window_s = static_cast<double>(
                            std::chrono::duration_cast<std::chrono::milliseconds>(
                                now - rate_window_start_)
                                .count()) /
                            1000.0;
                        snapshot->window_s = window_s > 0.0 ? window_s : 1.0;
                        snapshot->sampled_at = now;
                        snapshot->by_mac = std::move(live_rates_);
                        live_rates_ = ClientRateMap{};
                        std::atomic_store(&published_rates_,
                                          std::move(snapshot));
                        rate_window_start_ = now;
                    }
                }
            }

            void DispatchFrame(INTERMEDIATE_BUFFER& ib, WireBatches& down,
                               WireBatches& up,
                               uint32_t in_port = bridge::kBridgePortUp,
                               bool from_bridge = false) {
                const uint8_t* data = ib.m_IBuffer;
                size_t len = ib.m_Length;
                // batch205: m_Length comes from the kernel driver and is a
                // DWORD with no bound of its own. Every consumer below
                // (classifier, VLAN memmove, ARP/ICMP/DHCP parsers, relay
                // copies) trusts it as a length into m_IBuffer, which is a
                // fixed MAX_ETHER_FRAME array. A reported length past that
                // array reads out of bounds, so clamp against the real buffer
                // size before anything touches the frame. The TX path
                // (AppendDown) already refuses len > its cap; the RX path did
                // not, which is the asymmetry this closes.
                if (len > MAX_ETHER_FRAME) {
                    ++stats->rx_dropped;
                    return;
                }
                const bool inbound =
                    (PACKET_FLAG_ON_RECEIVE == ib.m_dwDeviceFlags);

                // Per-client up-rate accounting (single writer: RX/TX thread).
                // Any frame arriving from the wire counts toward its source
                // MAC; broadcast/multicast sources are skipped (not a client).
                if (inbound && len >= net::kEthernetHeaderLen) {
                    core::MacAddress src;
                    std::memcpy(src.data(), data + 6, net::kMacAddrLen);
                    if (!net::IsGroupAddress(src)) {
                        // batch94: the table is keyed by source MAC and lives
                        // for one 1-second window. A forged-source flood (a
                        // new MAC per frame) would otherwise insert without
                        // bound - memory growth plus a per-tick scan in
                        // ThroughputBps. Refuse NEW keys once the table is at
                        // its cap; existing keys keep accumulating normally,
                        // so real clients are unaffected. kMaxNeighbors is the
                        // right ceiling: this table only ever serves MACs the
                        // neighbour table could hold (it has the same bound).
                        if (live_rates_.size() >= ::vgww::core::limits::kMaxNeighbors &&
                            live_rates_.find(src) == live_rates_.end()) {
                            ++stats->rate_table_dropped;
                        } else {
                            live_rates_[src].up_bytes += len;
                        }
                    }
                }

                // 802.1Q access-trunk: strip the configured VID's tag before
                // classification. Downstream code (classifier, DHCP/ARP/ICMP/
                // relay) assumes a plain 14-byte Ethernet II header, so this
                // memmove normalizes a tagged frame into the untagged form.
                // A frame from any OTHER VLAN is isolated (dropped) instead of
                // being misinterpreted - single-VLAN gateway semantics.
                if (config.vlan.enabled() && inbound && len >=
                        net::kVlanEthernetHeaderLen &&
                    data[12] == ((net::kEthertypeVlan8021Q >> 8) & 0xFF) &&
                    data[13] == (net::kEthertypeVlan8021Q & 0xFF)) {
                    const uint16_t tci =
                        static_cast<uint16_t>((data[14] << 8) | data[15]);
                    const uint16_t vid = static_cast<uint16_t>(tci & 0x0FFF);
                    if (vid == config.vlan.id) {
                        // Layout: dst(6) src(6) | TPID(2) TCI(2) | inner
                        // ethertype(2) | payload. The inner frame starts at
                        // offset 16; sliding it to offset 12 drops the 4-byte
                        // tag and restores a plain 14-byte Ethernet II header.
                        std::memmove(
                            ib.m_IBuffer + static_cast<size_t>(net::kMacAddrLen) * 2,
                            ib.m_IBuffer + static_cast<size_t>(net::kMacAddrLen) * 2 +
                                net::kVlanTagLen,
                            len - static_cast<size_t>(net::kMacAddrLen) * 2 -
                                net::kVlanTagLen);
                        len -= net::kVlanTagLen;
                        ib.m_Length = static_cast<DWORD>(len);
                        ++stats->rx_vlan_frames;
                    } else {
                        ++stats->rx_dropped;  // other VLAN: isolated
                        return;
                    }
                }

                // L2 bridge split (S3-Task3): after VLAN normalization,
                // before classification. Gateway frames stay control-only;
                // broadcast/IPv6 multicast go both paths (control plane
                // continues below while BridgeTrip already flooded the
                // peer); other unicast is bridged only and must never leak
                // into the MSTCP passthrough; short frames drop. Frames
                // handed back from the bridge thread (from_bridge) take the
                // control path only so they are never re-flooded.
                if (inbound && bridge_active_.load() && !from_bridge) {
                    const bridge::BridgeAction bridge_action =
                        BridgeTrip(data, len, in_port);
                    if (bridge::BridgeAction::kDrop == bridge_action) {
                        ++stats->rx_dropped;
                        return;
                    }
                    if (bridge::BridgeAction::kBridgeUnicast ==
                            bridge_action ||
                        bridge::BridgeAction::kBridgeFlood == bridge_action) {
                        return;  // bridged only; skip the control plane
                    }
                }

                FrameView view;
                bool classified = dsp::ClassifyFrame(data, len, view);
                if (!classified) {
                    // Unparseable frame. Under LISTEN the driver already
                    // forwards a HOST-SENT original, so re-emitting it here
                    // would DUPLICATE it on the wire; only the inbound-
                    // unparseable legacy path keeps forwarding toward the
                    // wire. Gateway-relevant frames are always classifiable,
                    // so this never affects ARP/ICMP handling.
                    if (inbound) {
                        AppendCopy(down.For(in_port).items, ib);
                    }
                    ++stats->host_passthrough;
                    return;
                }
                if (!inbound) {
                    if (FrameClass::kArp == view.cls) {
                        proto::ArpView arp;
                        std::array<uint8_t, proto::kArpFrameLen> reply{};
                        if (proto::ParseArpFrame(data, len, arp)) {
                            neighbors.Learn(net::IpAddress::FromV4NetOrder(arp.sender_ip),
                                            arp.sender_mac);
                            if (proto::BuildGatewayArpReply(arp, config.gateway.ipv4,
                                                            config.gateway.mac, reply)) {
                                AppendDown(up.For(in_port), reply.data(), reply.size());
                                ++stats->arp_replies;
                                return;
                            }
                        }
                    } else if (FrameClass::kIcmpV4 == view.cls) {
                        const uint8_t* ip = data + net::kEthernetHeaderLen;
                        const size_t ip_len = len - net::kEthernetHeaderLen;
                        if (ip_len >= 20) {
                            uint32_t dst_net = 0;
                            std::memcpy(&dst_net, ip + 16, 4);
                            if (dst_net == config.gateway.ipv4) {
                                proto::IcmpEchoView echo;
                                if (proto::ParseIcmpEcho(ip, ip_len, echo) &&
                                    proto::kIcmpEchoRequest == echo.type) {
                                    // Stack buffer: zero heap allocation (ARP
                                    // uses the same pattern via std::array;
                                    // see arp.cpp:69).
                                    std::array<uint8_t, proto::kMaxEchoReplyFrameBytes> reply;
                                    const size_t reply_len =
                                        proto::BuildEchoReplyFrame(ip, ip_len,
                                                                   config.gateway.mac,
                                                                   view.eth.src,
                                                                   reply);
                                    if (reply_len > 0) {
                                        AppendDown(up.For(in_port), reply.data(),
                                                   reply_len);
                                    }
                                    ++stats->icmp_replies;
                                    LatTraceIcmp(echo.sequence);
                                    neighbors.Learn(
                                        net::IpAddress::FromV4BigEndian(ip + 12),
                                        view.eth.src);
                                    return;
                                }
                            }
                        }
                    }
                    // Host-originated frame the gateway does not answer: under
                    // LISTEN the driver already forwarded the original, so it
                    // must NOT be re-injected toward the wire (that would
                    // duplicate it). Only the frame's statistics are recorded.
                    ++stats->host_passthrough;
                    return;
                }

                // Firewall enforcement: drop frames from banned MACs/IPs
                // before any other processing (lock-free snapshot read; the
                // loop performs no heap allocations at all). batch305: the
                // snapshot is a hash index - the old code scanned every ban
                // per frame (kMaxBans = 4096).
                {
                    auto bans = std::atomic_load(&ban_index_snapshot_);
                    if (!bans->Empty()) {
                        if (!bans->macs.empty() &&
                            0 != bans->macs.count(view.eth.src)) {
                            ++stats->rx_dropped;
                            return;
                        }
                        if (len >= net::kEthernetHeaderLen + 20) {
                            const uint8_t* ip =
                                data + net::kEthernetHeaderLen;
                            if (4 == (ip[0] >> 4)) {
                                // inet_addr convention: first octet in the
                                // low byte (core::ParseIpv4's result).
                                const uint32_t src4 =
                                    static_cast<uint32_t>(ip[12]) |
                                    (static_cast<uint32_t>(ip[13]) << 8) |
                                    (static_cast<uint32_t>(ip[14]) << 16) |
                                    (static_cast<uint32_t>(ip[15]) << 24);
                                if (!bans->ipv4.empty() &&
                                    0 != bans->ipv4.count(src4)) {
                                    ++stats->rx_dropped;
                                    return;
                                }
                            } else if (6 == (ip[0] >> 4) &&
                                       len >= net::kEthernetHeaderLen + 40) {
                                if (!bans->ipv6.empty()) {
                                    const auto v6src =
                                        net::IpAddress::FromV6(ip + 8);
                                    if (0 != bans->ipv6.count(v6src)) {
                                        ++stats->rx_dropped;
                                        return;
                                    }
                                }
                            }
                        }
                    }
                }

                // Passive learning: sender MAC/IP pairs cover static clients.
                if (FrameClass::kArp == view.cls) {
                    proto::ArpView arp;
                    if (proto::ParseArpFrame(data, len, arp)) {
                        neighbors.Learn(net::IpAddress::FromV4NetOrder(arp.sender_ip),
                                        arp.sender_mac);
                    }
                } else if (len >= net::kEthernetHeaderLen + 20) {
                    const uint8_t* ip = data + net::kEthernetHeaderLen;
                    if (4 == (ip[0] >> 4)) {
                        neighbors.Learn(net::IpAddress::FromV4BigEndian(ip + 12),
                                        view.eth.src);
                    } else if (6 == (ip[0] >> 4) &&
                               len >= net::kEthernetHeaderLen + 40) {
                        neighbors.Learn(net::IpAddress::FromV6(ip + 8), view.eth.src);
                    }
                }

                // Uplink rate limit: cap how many bytes each client may push
                // toward the gateway. Control frames (ARP/DHCP/ICMP) are exempt
                // so clients never lose their network configuration while a
                // data cap is active.
                if (FrameClass::kArp != view.cls &&
                    FrameClass::kDhcpV4 != view.cls &&
                    FrameClass::kIcmpV4 != view.cls &&
                    FrameClass::kIcmpV6 != view.cls &&
                    !rate_limiter_.AllowUplink(view.eth.src, len,
                                               std::chrono::steady_clock::now())) {
                    ++stats->rate_limited;
                    return;
                }

                switch (view.cls) {
                    case FrameClass::kArp: {
                        proto::ArpView arp;
                        std::array<uint8_t, proto::kArpFrameLen> reply{};
                        if (proto::ParseArpFrame(data, len, arp) &&
                            proto::BuildGatewayArpReply(arp, config.gateway.ipv4,
                                                        config.gateway.mac, reply)) {
                            AppendDown(down.For(in_port), reply.data(), reply.size());
                            ++stats->arp_replies;
                            break;
                        }
                        AppendCopy(up.For(in_port).items, ib);  // not ours: keep MSTCP informed
                        ++stats->host_passthrough;
                        break;
                    }

                    case FrameClass::kIcmpV4: {
                        const uint8_t* ip = data + net::kEthernetHeaderLen;
                        const size_t ip_len = len - net::kEthernetHeaderLen;
                        uint32_t dst_net = 0;
                        std::memcpy(&dst_net, ip + 16, 4);
                        proto::IcmpEchoView echo;
                        if (dst_net == config.gateway.ipv4 &&
                            proto::ParseIcmpEcho(ip, ip_len, echo) &&
                            proto::kIcmpEchoRequest == echo.type) {
                            // Stack buffer: zero heap allocation (ARP uses the
                            // same pattern via std::array; see arp.cpp:69).
                            std::array<uint8_t, proto::kMaxEchoReplyFrameBytes> reply;
                            const size_t reply_len = proto::BuildEchoReplyFrame(
                                ip, ip_len, config.gateway.mac,
                                view.eth.src, reply);
                            if (reply_len > 0) {
                                AppendDown(down.For(in_port), reply.data(),
                                           reply_len);
                            }
                            ++stats->icmp_replies;
                            LatTraceIcmp(echo.sequence);
                            break;
                        }
                        if (proto::ParseIcmpEcho(ip, ip_len, echo) &&
                            proto::kIcmpEchoRequest == echo.type) {
                            // Relay toward the internet via a worker.
                            xtcp::buf::BufRef buf =
                                xtcp::buf::BufRef::Acquire(
                                    static_cast<UInt32>(ip_len));
                            if (!buf.IsEmpty()) {
                                std::memcpy(buf.Data(), ip, ip_len);
                                buf.SetLen(static_cast<UInt32>(ip_len));
                                const uint64_t hash = dsp::SymmetricFlowHash(view);
                                const uint32_t worker =
                                    static_cast<uint32_t>(hash % worker_count);
                                if (!rx_rings[worker]->Push(
                                        RxItem{std::move(buf), FrameClass::kIcmpV4})) {
                                    ++stats->rx_dropped;  // ring full: drop-not-grow
                                }
                                break;
                            }
                        }
                        AppendCopy(up.For(in_port).items, ib);  // other ICMP: host handles
                        ++stats->host_passthrough;
                        break;
                    }

                    case FrameClass::kTcpV4:
                    case FrameClass::kTcpV6: {
                        const size_t ip_offset = net::kEthernetHeaderLen;
                        const size_t ip_len = len - ip_offset;
                        xtcp::buf::BufRef buf =
                            xtcp::buf::BufRef::Acquire(static_cast<UInt32>(ip_len));
                        if (buf.IsEmpty()) {
                            ++stats->rx_dropped;  // pool exhausted: drop-not-grow
                            break;
                        }
                        std::memcpy(buf.Data(), data + ip_offset, ip_len);
                        buf.SetLen(static_cast<UInt32>(ip_len));

                        const uint64_t hash = dsp::SymmetricFlowHash(view);
                        const uint32_t worker =
                            static_cast<uint32_t>(hash % worker_count);
                        if (!rx_rings[worker]->Push(
                                RxItem{std::move(buf), FrameClass::kTcpV4})) {
                            ++stats->rx_dropped;  // ring full: drop-not-grow
                        }
                        break;
                    }

                    case FrameClass::kUdpV4: {
                        const size_t ip_offset = net::kEthernetHeaderLen;
                        const size_t ip_len = len - ip_offset;
                        xtcp::buf::BufRef buf =
                            xtcp::buf::BufRef::Acquire(static_cast<UInt32>(ip_len));
                        if (buf.IsEmpty()) {
                            ++stats->rx_dropped;
                            break;
                        }
                        std::memcpy(buf.Data(), data + ip_offset, ip_len);
                        buf.SetLen(static_cast<UInt32>(ip_len));
                        const uint64_t hash = dsp::SymmetricFlowHash(view);
                        const uint32_t worker =
                            static_cast<uint32_t>(hash % worker_count);
                        if (!rx_rings[worker]->Push(
                                RxItem{std::move(buf), FrameClass::kUdpV4})) {
                            ++stats->rx_dropped;  // ring full: drop-not-grow
                        }
                        break;
                    }

                    case FrameClass::kUdpV6: {
                        // IPv6 UDP: relayed through a host UDP socket exactly
                        // like v4 (the UdpRelay supports both families).
                        const size_t ip_offset = net::kEthernetHeaderLen;
                        const size_t ip_len = len - ip_offset;
                        xtcp::buf::BufRef buf =
                            xtcp::buf::BufRef::Acquire(static_cast<UInt32>(ip_len));
                        if (buf.IsEmpty()) {
                            ++stats->rx_dropped;
                            break;
                        }
                        std::memcpy(buf.Data(), data + ip_offset, ip_len);
                        buf.SetLen(static_cast<UInt32>(ip_len));
                        const uint64_t hash = dsp::SymmetricFlowHash(view);
                        const uint32_t worker =
                            static_cast<uint32_t>(hash % worker_count);
                        if (!rx_rings[worker]->Push(
                                RxItem{std::move(buf), FrameClass::kUdpV6})) {
                            ++stats->rx_dropped;  // ring full: drop-not-grow
                        }
                        break;
                    }

                    case FrameClass::kDhcpV4: {
                        // Bypass (no server assembled): keep the host's own
                        // DHCP path intact - the frame goes up to MSTCP.
                        if (!dhcp_) {
                            AppendCopy(up.For(in_port).items, ib);
                            ++stats->host_passthrough;
                            break;
                        }
                        proto::DhcpView dhcp;
                        if (!proto::ParseDhcpFrame(data, len, dhcp)) {
                            ++stats->rx_dropped;
                            break;
                        }
                        // Per-MAC anti-storm budget before any reply work; a
                        // silent drop is correct (clients retry slowly).
                        if (!dhcp_->AllowFrame(
                                dhcp.client_mac,
                                std::chrono::steady_clock::now())) {
                            ++stats->rx_dropped;
                            break;
                        }
                        if (proto::kDhcpMsgInform == dhcp.msg_type) {
                            // Printer/VoIP restore their config via
                            // DHCPINFORM: they already hold an address and
                            // only need the network options (router/DNS/
                            // subnet). Answer with an ACK carrying the same
                            // options, no your-IP assignment.
                            std::vector<uint8_t> reply;
                            proto::BuildDhcpReplyFrame(
                                proto::kDhcpMsgAck, dhcp.xid,
                                config.gateway.mac, dhcp.client_mac, 0,
                                config.gateway.ipv4, config.gateway.mask,
                                config.dhcp.lease_seconds, config.dhcp.dns,
                                "", reply);
                            AppendDown(down.For(in_port), reply.data(), reply.size());
                            break;
                        }
                        if (proto::kDhcpMsgDiscover == dhcp.msg_type ||
                            proto::kDhcpMsgRequest == dhcp.msg_type) {
                            // OFFER pins the address briefly; only an ACK
                            // grants the full lease (an abandoned offer must
                            // not drain the pool for a whole lease term).
                            const dhcp::DhcpServer::OfferStage stage =
                                (proto::kDhcpMsgRequest == dhcp.msg_type)
                                    ? dhcp::DhcpServer::OfferStage::kAck
                                    : dhcp::DhcpServer::OfferStage::kOffer;
                            // F2: option 50 (requested address) is honoured
                            // before the round-robin walk.
                            const uint32_t offered = dhcp_->Acquire(
                                dhcp.client_mac,
                                std::chrono::steady_clock::now(), stage,
                                dhcp.hostname, dhcp.requested_ip);
                            if (0 != offered) {
                                const uint8_t reply_type =
                                    (proto::kDhcpMsgRequest == dhcp.msg_type)
                                        ? proto::kDhcpMsgAck
                                        : proto::kDhcpMsgOffer;
                                std::vector<uint8_t> reply;
                                proto::BuildDhcpReplyFrame(
                                    reply_type, dhcp.xid, config.gateway.mac,
                                    dhcp.client_mac, offered,
                                    config.gateway.ipv4, config.gateway.mask,
                                    config.dhcp.lease_seconds, config.dhcp.dns,
                                    dhcp.hostname, reply);
                                AppendDown(down.For(in_port), reply.data(), reply.size());
                            }
                            break;  // no address available: stay silent
                        }
                        if (proto::kDhcpMsgRelease == dhcp.msg_type) {
                            // F6: option 54 (server-id) is checked by Release;
                            // a foreign id keeps the lease.
                            dhcp_->Release(dhcp.client_mac, dhcp.server_id);
                            break;
                        }
                        if (proto::kDhcpMsgDecline == dhcp.msg_type &&
                            0 != dhcp.requested_ip) {
                            // F3: client detected an address conflict - park
                            // it (the ownership check lives in Decline).
                            dhcp_->Decline(dhcp.client_mac, dhcp.requested_ip,
                                           std::chrono::steady_clock::now());
                        }
                        break;
                    }

                    case FrameClass::kDhcpV6: {
                        // Bypass (no v6 server assembled): keep the host's own
                        // DHCPv6 path intact - the frame goes up to MSTCP.
                        if (!dhcp6_) {
                            AppendCopy(up.For(in_port).items, ib);
                            ++stats->host_passthrough;
                            break;
                        }
                        proto::Dhcp6View dhcp6_view;
                        if (!proto::ParseDhcp6Frame(data, len, dhcp6_view)) {
                            ++stats->rx_dropped;
                            break;
                        }
                        // Rate limit, state machine and frame build live in
                        // the server; the reply unicasts back to the client's
                        // link-local source.
                        std::vector<uint8_t> reply6;
                        if (dhcp6_->HandleFrame(
                                dhcp6_view, view.eth.src, dhcp6_view.src_ip,
                                std::chrono::steady_clock::now(), reply6)) {
                            AppendDown(down.For(in_port), reply6.data(),
                                       reply6.size());
                        }
                        break;
                    }

                    case FrameClass::kIcmpV6: {
                        // IPv6 control plane: RS -> RA, NS -> NA, echo to
                        // the gateway answered locally. Frames start with the
                        // Ethernet header; IPv6 fixed header is 40 bytes.
                        if (len < net::kEthernetHeaderLen + 40 + 4) {
                            ++stats->rx_dropped;
                            break;
                        }
                        const uint8_t* ip6 = data + net::kEthernetHeaderLen;
                        const uint8_t* icmp6 = ip6 + 40;
                        const uint16_t payload_len =
                            static_cast<uint16_t>((ip6[4] << 8) | ip6[5]);
                        const uint8_t type = icmp6[0];
                        // The hop-limit-255 rule is exclusively a Neighbor
                        // Discovery constraint (RFC 4861 section 7.1.1/7.1.2): ND
                        // messages (RS/RA/NS/NA/Redirect - types 133-137)
                        // MUST arrive with hop limit 255, anything else was
                        // routed from off-link. ICMPv6 echo (RFC 4443) has no
                        // such requirement - clients ping the gateway with
                        // the RA-advertised hop limit (typically 64).
                        const bool nd_message =
                            type >= proto::kIcmpV6RouterSolicitation &&
                            type <= proto::kIcmpV6Redirect;
                        if (nd_message && 255 != ip6[7]) {
                            ++stats->rx_dropped;
                            break;
                        }
                        const auto ll_addr = proto::LinkLocalFromMac(
                            config.gateway.mac);

                        // Gateway's own addresses (for NS matching).
                        std::array<uint8_t, 16> ula{};
                        std::memcpy(ula.data(), config.ipv6.ula_prefix.data(),
                                    8);
                        // EUI-64 IID from the gateway MAC.
                        ula[8] = static_cast<uint8_t>(config.gateway.mac[0] ^ 0x02);
                        ula[9] = config.gateway.mac[1];
                        ula[10] = config.gateway.mac[2];
                        ula[11] = 0xFF;
                        ula[12] = 0xFE;
                        ula[13] = config.gateway.mac[3];
                        ula[14] = config.gateway.mac[4];
                        ula[15] = config.gateway.mac[5];

                        if (proto::kIcmpV6RouterSolicitation == type &&
                            core::AddressServicesEnabled(config) &&
                            config.ipv6.enabled) {
                            std::vector<uint8_t> ra;
                            proto::BuildRouterAdvertisementFrame(
                                config.gateway.mac, ll_addr.data(),
                                config.ipv6.ula_prefix.data(),
                                config.ipv6.prefix_len,
                                config.ipv6.ra_lifetime_s, true, true,
                                adapter->mtu, config.ipv6.dns, ra);
                            AppendDown(down.For(in_port), ra.data(), ra.size());
                            break;
                        }
                        if (proto::kIcmpV6NeighborSolicitation == type &&
                            len >= net::kEthernetHeaderLen + 40 + 24) {
                            // Target address sits at ICMPv6 offset 8..23.
                            const uint8_t* target = icmp6 + 8;
                            const bool ours =
                                0 == std::memcmp(target, ll_addr.data(), 16) ||
                                0 == std::memcmp(target, ula.data(), 16);
                            if (ours) {
                                // DAD probe (source ::): answer with a
                                // MULTICAST NA (solicited=false) so every
                                // tentative node hears the conflict
                                // (RFC 4861 section 7.2.4). A unicast reply to ::
                                // would be dropped and the attacker could
                                // steal the gateway address.
                                static constexpr uint8_t kUnspecified[16] = {};
                                const bool dad =
                                    0 == std::memcmp(ip6 + 8, kUnspecified, 16);
                                std::array<uint8_t, 16> na_dst{};
                                net::WireMac na_mac{};
                                bool solicited = true;
                                if (dad) {
                                    na_dst = {0xFF, 0x02, 0, 0, 0, 0, 0, 0,
                                              0,    0,    0, 0, 0, 0, 0, 0x01};
                                    na_mac = {0x33, 0x33, 0x00,
                                              0x00, 0x00, 0x01};
                                    solicited = false;
                                } else {
                                    std::memcpy(na_dst.data(), ip6 + 8, 16);
                                    na_mac = view.eth.src;
                                }
                                std::vector<uint8_t> na;
                                proto::BuildNeighborAdvertisementFrame(
                                    target, config.gateway.mac,
                                    na_dst.data(), na_mac, solicited, na);
                                AppendDown(down.For(in_port), na.data(), na.size());
                                break;
                            }
                        }
                        if (proto::kIcmpV6EchoRequest == type) {
                            // Answer pings addressed to the gateway itself;
                            // relay other targets once v6 relays land.
                            // The IP header's payload_len is attacker
                            // controlled: refuse to echo past the actual
                            // frame (truncated packet would read OOB).
                            const bool ours =
                                0 == std::memcmp(ip6 + 24, ll_addr.data(), 16) ||
                                0 == std::memcmp(ip6 + 24, ula.data(), 16);
                            if (ours && net::kEthernetHeaderLen + 40 +
                                                payload_len <=
                                            len) {
                                std::vector<uint8_t> reply;
                                proto::BuildEchoReplyV6Frame(
                                    ip6, payload_len + 40, config.gateway.mac,
                                    view.eth.src, reply);
                                AppendDown(down.For(in_port), reply.data(), reply.size());
                                ++stats->icmp_replies;
                                break;
                            }
                            if (ours) {
                                ++stats->rx_dropped;  // truncated echo
                                break;
                            }
                        }
                        AppendCopy(up.For(in_port).items, ib);  // rest: host handles
                        ++stats->host_passthrough;
                        break;
                    }

                    default:
                        AppendCopy(up.For(in_port).items, ib);  // rest: host handles
                        ++stats->host_passthrough;
                        break;
                }
            }

            // ----- worker / control threads -----------------------------------
            void WorkerLoop(uint32_t index) {
                t_worker_index = index;
                std::vector<RxItem> items(config.perf.rx_batch);
                auto last_sweep = std::chrono::steady_clock::now();
                while (running.load()) {
                    const size_t n =
                        rx_rings[index]->PopBatch(items.data(), items.size());
                    for (size_t k = 0; k < n; ++k) {
                        if (dsp::FrameClass::kUdpV4 == items[k].cls) {
                            HandleUdp(index, items[k].packet);
                        } else if (dsp::FrameClass::kIcmpV4 == items[k].cls) {
                            HandleIcmp(index, items[k].packet);
                        } else if (dsp::FrameClass::kUdpV6 == items[k].cls) {
                            HandleUdpV6(index, items[k].packet);
                        } else {
                            stack->OnPacket(std::move(items[k].packet));
                        }
                    }
                    // Sweep ONLY our own shards: the reclaim path closes
                    // flows (MimtFlow::Close(), which fires this relay's
                    // pending completions synchronously). Sweeping a foreign
                    // shard would run those callbacks - and the relay's
                    // socket work - on this thread while the flow's owner
                    // polls the same socket: an asio cross-thread violation.
                    // Shard-affine polling keeps reclaim on the owner worker
                    // (shard 0 also owns the global fragment/qdisc tails).
                    for (uint32_t s = index; s < xtcp::XtcpStack::kShardCount;
                         s += worker_count) {
                        stack->PollAckTimers(s);
                    }
                    // MimtFlow completions (AsyncRead/Write/Close callbacks)
                    // fire here - without this the relays never advance.
                    // Shard affinity: this worker owns shards
                    // {index, index+worker_count, ...}; flows accepted on
                    // those shards were queued to THIS worker (see StartMimt),
                    // so dispatching only our shards keeps every relay
                    // callback on a single thread.
                    for (uint32_t s = index; s < xtcp::XtcpStack::kShardCount;
                         s += worker_count) {
                        stack->DispatchMimt(s);
                    }
                    DrainAccepts(index);
                    DrainAborts(index);
                    // Upstream socket completions fire here, on this same
                    // thread - flow affinity without locks (design spec section 4).
                    io_contexts[index]->poll();
                    if (0 == index) {
                        DrainPortmapSends();  // manager WAN->LAN forwarding
                    }
                    const auto now = std::chrono::steady_clock::now();
                    if (now - last_sweep > std::chrono::seconds(5)) {
                        udp_tables[index]->Sweep(now);
                        // One worker owns the DHCP sweep so N workers do not
                        // contend on the server mutex every cycle.
                        if (0 == index && dhcp_) {
                            dhcp_->Sweep(now);
                        }
                        if (0 == index && dhcp6_) {
                            dhcp6_->Sweep(now);
                        }
                        last_sweep = now;
                    }
                    if (0 == n) {
                        std::this_thread::sleep_for(
                            std::chrono::microseconds(200));
                    }
                }
                t_worker_index = kNoRing;
            }

            /// Worker-side ICMP echo relay: rewrite the identifier to a
            /// globally unique tag, send via the raw socket; replies come
            /// back through HandleIcmpReply on the same worker.
            void HandleIcmp(uint32_t index, xtcp::buf::BufRef& packet) {
                const uint8_t* ip = packet.Data();
                const uint32_t len = packet.Len();
                // IPv4-only handler: the v6 bytes layout differs completely
                // (no IHL, addresses live at different offsets). A v6 frame
                // must never be decoded as IPv4 here (the reply handler has
                // the same gate).
                if (len < 28 || 4 != (ip[0] >> 4)) {
                    ++stats->rx_dropped;
                    return;
                }
                const size_t ihl = static_cast<size_t>(ip[0] & 0x0F) * 4;
                // batch126 (C9 same-shape sweep of the DHCP fix): IHL must be
                // 20..60. Without it ihl=0 made `icmp` point at the IPv4 header
                // and the relay forwarded the whole datagram as an ICMP
                // segment (ip[0] became the "type" byte).
                if (!proto::IsLegalIpv4HeaderLength(ihl)) {
                    ++stats->rx_dropped;
                    return;
                }
                const uint8_t* icmp = ip + ihl;
                if (len < ihl + proto::kIcmpHeaderLen) {
                    ++stats->rx_dropped;  // truncated ICMP header
                    return;
                }
                if (icmp[0] != proto::kIcmpEchoRequest) {
                    return;  // other ICMP types to the gateway: not a drop
                }
                // batch297: the driver reports the PADDED frame length. The
                // IP total length is the authoritative datagram size; using
                // `len` here relayed the Ethernet padding as ICMP payload (a
                // 0-payload ping came back 18 bytes larger). Same rule as
                // HandleUdp's UDP-length clamp.
                size_t icmp_len = 0;
                if (!proto::IcmpSegmentLength(ip, len, icmp_len)) {
                    ++stats->rx_dropped;  // truncated/inconsistent datagram
                    return;
                }
                relay::IcmpRelay::TagEntry entry;
                entry.client_ip = net::IpAddress::FromV4BigEndian(ip + 12);
                entry.original_id =
                    static_cast<uint16_t>((icmp[4] << 8) | icmp[5]);
                // Client MAC comes from the neighbor table (learned passively
                // when the request crossed the RX thread).
                auto snap = neighbors.Snapshot();
                const tables::NeighborEntry* neighbor =
                    snap->Find(entry.client_ip);
                if (nullptr == neighbor) {
                    ++stats->mac_misses;
                    ProbeArpFor(entry.client_ip);  // aged-out: re-learn the MAC
                    return;  // client MAC unknown: cannot build the reply frame
                }
                entry.client_mac = neighbor->mac;
                if (index >= icmp_relays.size() ||
                    nullptr == icmp_relays[index]) {
                    ++stats->rx_dropped;  // relay disabled (no raw socket):
                                          // reject BEFORE tagging, so a
                                          // disabled relay never occupies a
                                          // tag slot.
                    return;
                }
                const auto now = std::chrono::steady_clock::now();
                const uint16_t tag =
                    relay::IcmpRelay::TagAllocator::Instance().Allocate(entry,
                                                                        now);
                if (0 == tag) {
                    // Tag 0 is the allocator's "pool full" signal (it is
                    // never handed out): rewriting the client id to 0 would
                    // emit a request whose reply can never match. Skip it
                    // and count (a flood signal operators care about).
                    ++stats->icmp_tag_exhausted;
                    return;
                }
                // Rebuild the ICMP segment with the tagged identifier.
                std::vector<uint8_t> seg(icmp, icmp + icmp_len);
                seg[0] = proto::kIcmpEchoRequest;
                seg[4] = static_cast<uint8_t>(tag >> 8);
                seg[5] = static_cast<uint8_t>(tag & 0xFF);
                seg[2] = 0;
                seg[3] = 0;
                const uint16_t ck = net::InternetChecksum(seg.data(), seg.size());
                seg[2] = static_cast<uint8_t>(ck >> 8);
                seg[3] = static_cast<uint8_t>(ck & 0xFF);
                const std::array<uint8_t, 4> dst{ip[16], ip[17], ip[18],
                                                 ip[19]};
                icmp_relays[index]->SendEchoRequest(seg.data(), seg.size(),
                                                    dst);
            }

            /// Matches an echo reply tag and rebuilds the frame toward the
            /// LAN client.
            void HandleIcmpReply(uint32_t index, const uint8_t* pkt, size_t len) {
                if (len < 28 || (pkt[0] >> 4) != 4) {
                    return;
                }
                const size_t ihl = static_cast<size_t>(pkt[0] & 0x0F) * 4;
                // batch126: same IHL guard as HandleIcmp (C9 same-shape).
                if (!proto::IsLegalIpv4HeaderLength(ihl)) {
                    return;
                }
                if (len < ihl + 8) {
                    return;
                }
                const uint8_t* icmp = pkt + ihl;
                if (icmp[0] != proto::kIcmpEchoReply) {
                    return;
                }
                // Validate the datagram BEFORE spending the tag (D18: verify
                // preconditions, then mutate). The tag is one-shot, so a
                // malformed or truncated reply carrying a live tag must not
                // burn it - the real reply would then be dropped.
                size_t segment_len = 0;
                if (!proto::IcmpSegmentLength(pkt, len, segment_len)) {
                    return;  // truncated/inconsistent datagram
                }
                const uint16_t tag =
                    static_cast<uint16_t>((icmp[4] << 8) | icmp[5]);
                relay::IcmpRelay::TagEntry entry;
                if (!relay::IcmpRelay::TagAllocator::Instance().Consume(
                        tag, entry, std::chrono::steady_clock::now())) {
                    return;  // unknown/expired tag: not ours
                }
                std::array<uint8_t, 4> client_wire{};
                client_wire[0] = entry.client_ip.bytes[12];
                client_wire[1] = entry.client_ip.bytes[13];
                client_wire[2] = entry.client_ip.bytes[14];
                client_wire[3] = entry.client_ip.bytes[15];
                // ONE implementation of the reply rewrite lives in proto
                // (RelayEchoReplyToClient): it takes the ICMP segment length
                // from the IP total length, so the driver's Ethernet padding
                // is never forwarded to the client as ICMP payload.
                std::vector<uint8_t> frame;
                if (!proto::RelayEchoReplyToClient(
                        pkt, len, client_wire.data(), config.gateway.mac,
                        entry.client_mac, entry.original_id, frame)) {
                    return;  // malformed or not a reply
                }
                if (tx_rings[index]->Push(TxFrame(std::move(frame)))) {
                    ++stats->tx_frames;
                } else {
                    ++stats->rx_dropped;  // ring full: reply vanished uncounted
                }
            }

            /// Worker-side UDP dispatch: NAT lookup + upstream send, and the
            /// return-path frame builder wired to the relay callback.
            void HandleUdpV6(uint32_t index, xtcp::buf::BufRef& packet) {
                const uint8_t* ip = packet.Data();  // IPv6 header (L3 buffer)
                const uint32_t len = packet.Len();
                // The IPv6 payload length is the authoritative datagram
                // size: the capture can extend past it, and bytes past
                // the declared datagram are not ours to forward.
                size_t segment_len = 0;
                if (!proto::UdpSegmentLengthV6(ip, len, segment_len)) {
                    ++stats->rx_dropped;
                    return;
                }
                proto::UdpView uv;
                // Parse INSIDE the declared datagram: reading the UDP
                // header out of bytes past `segment_len` would invent a
                // four-tuple the sender never wrote.
                if (!proto::ParseUdp(ip + 40, segment_len, uv)) {
                    ++stats->rx_dropped;
                    return;
                }
                relay::UdpRelay::FlowKey key;
                key.client_ip = net::IpAddress::FromV6(ip + 8);
                key.remote_ip = net::IpAddress::FromV6(ip + 24);
                key.client_port = uv.sport;
                key.remote_port = uv.dport;
                auto relay =
                    udp_tables[index]->GetOrCreate(key, *io_contexts[index]);
                if (nullptr == relay) {
                    ++stats->rx_dropped;
                    return;
                }
                // batch295: the handler captures the flow key, which is fixed
                // for this relay's lifetime - installing it per packet made every
                // forwarded datagram allocate (the lambda exceeds std::function's
                // small buffer). Install it once.
                if (!relay->on_remote_data) {
                    relay->on_remote_data =
                        [this, index, key](const uint8_t* payload, size_t plen) {
                            TxFrame frame;
                            auto snap = neighbors.Snapshot();
                            const tables::NeighborEntry* entry =
                                snap->Find(key.client_ip);
                            if (nullptr == entry) {
                                ++stats->mac_misses;
                                ProbeArpFor(key.client_ip);  // aged-out: re-learn
                                return;
                            }
                            proto::BuildUdpFrameV6(
                                frame, entry->mac, config.gateway.mac,
                                key.remote_ip.bytes.data(), key.remote_port,
                                key.client_ip.bytes.data(), key.client_port, payload,
                                plen);
                            if (tx_rings[index]->Push(TxFrame(std::move(frame)))) {
                                ++stats->tx_frames;
                            } else {
                                ++stats->rx_dropped;  // ring full: reply vanished
                            }
                        };
                }
                // Send at most the datagram the sender declared, and
                // never more than the datagram itself (not the capture).
                const size_t avail = segment_len - proto::kUdpHeaderLen;
                const size_t declared =
                    (uv.length >= proto::kUdpHeaderLen)
                        ? (static_cast<size_t>(uv.length) -
                           proto::kUdpHeaderLen)
                        : 0;
                relay->SendToRemote(ip + 40 + proto::kUdpHeaderLen,
                                   (std::min)(declared, avail));
            }

            void HandleUdp(uint32_t index, xtcp::buf::BufRef& packet) {
                const uint8_t* ip = packet.Data();
                const uint32_t len = packet.Len();
                // The IPv4 total length is the authoritative datagram
                // size: the link layer pads short frames and the driver
                // reports that padded length, so a buffer-derived bound
                // would forward the padding as UDP payload. The helper
                // also judges the IHL (batch126 rule, same as ICMP).
                size_t ihl = 0;
                size_t segment_len = 0;
                if (!proto::UdpSegmentLengthV4(ip, len, ihl, segment_len)) {
                    ++stats->rx_dropped;
                    return;
                }
                proto::UdpView uv;
                // Defense-in-depth: the classifier forwards fragmented UDP to
                // the host, but if a fragment ever reaches the relay handler
                // it must be dropped, never sent upstream as a truncated
                // datagram (MF or a non-zero offset).
                const uint16_t frag =
                    static_cast<uint16_t>((ip[6] & 0x1F) << 8) | ip[7];
                // C2: the MF bit (byte 6, 0x20) is masked out of the
                // offset-high nibble by the & 0x1F - a FIRST fragment
                // (offset 0, MF=1) has frag==0 and must still be dropped.
                if (0 != (ip[6] & 0x20) || 0 != (frag & 0x1FFF)) {
                    ++stats->rx_dropped;
                    return;
                }
                // Parse inside the declared datagram, not the capture.
                if (!proto::ParseUdp(ip + ihl, segment_len, uv)) {
                    ++stats->rx_dropped;
                    return;
                }
                relay::UdpRelay::FlowKey key;
                key.client_ip = net::IpAddress::FromV4BigEndian(ip + 12);
                key.remote_ip = net::IpAddress::FromV4BigEndian(ip + 16);
                key.client_port = uv.sport;
                key.remote_port = uv.dport;
                auto relay =
                    udp_tables[index]->GetOrCreate(key, *io_contexts[index]);
                if (nullptr == relay) {
                    ++stats->rx_dropped;
                    return;
                }
                // batch295: the handler captures the flow key, which is fixed
                // for this relay's lifetime - installing it per packet made every
                // forwarded datagram allocate (the lambda exceeds std::function's
                // small buffer). Install it once.
                if (!relay->on_remote_data) {
                    relay->on_remote_data =
                        [this, index, key](const uint8_t* payload, size_t plen) {
                            TxFrame frame;
                            auto snap = neighbors.Snapshot();
                            const tables::NeighborEntry* entry =
                                snap->Find(key.client_ip);
                            if (nullptr == entry) {
                                ++stats->mac_misses;
                                ProbeArpFor(key.client_ip);  // aged-out: re-learn
                                return;  // client MAC unknown: drop (probe re-learns)
                            }
                            if (key.remote_ip.IsV4()) {
                                const uint8_t src_wire[4] = {
                                    key.remote_ip.bytes[12], key.remote_ip.bytes[13],
                                    key.remote_ip.bytes[14], key.remote_ip.bytes[15]};
                                const uint8_t dst_wire[4] = {
                                    key.client_ip.bytes[12], key.client_ip.bytes[13],
                                    key.client_ip.bytes[14], key.client_ip.bytes[15]};
                                proto::BuildUdpFrame(frame, entry->mac,
                                                     config.gateway.mac, src_wire,
                                                     key.remote_port, dst_wire,
                                                     key.client_port, payload, plen);
                            } else {
                                proto::BuildUdpFrameV6(
                                    frame, entry->mac, config.gateway.mac,
                                    key.remote_ip.bytes.data(), key.remote_port,
                                    key.client_ip.bytes.data(), key.client_port,
                                    payload, plen);
                            }
                            if (tx_rings[index]->Push(TxFrame(std::move(frame)))) {
                                ++stats->tx_frames;
                            } else {
                                ++stats->rx_dropped;  // ring full: reply vanished
                            }
                        };
                }
                // Send at most the datagram the sender declared, and
                // never more than the datagram itself (not the capture).
                const size_t avail = segment_len - proto::kUdpHeaderLen;
                const size_t declared =
                    (uv.length >= proto::kUdpHeaderLen)
                        ? (static_cast<size_t>(uv.length) -
                           proto::kUdpHeaderLen)
                        : 0;
                relay->SendToRemote(ip + ihl + proto::kUdpHeaderLen,
                                   (std::min)(declared, avail));
            }

            // ----- relay plumbing ---------------------------------------------
            /// Converts an xtcp endpoint (addr[0] numeric, first octet in the
            /// HIGH byte) into an asio endpoint.
            static asio::ip::tcp::endpoint ToAsio(const xtcp::core::Endpoint& ep) {
                if (6 == ep.family) {
                    asio::ip::address_v6::bytes_type b{};
                    for (uint32_t i = 0; i < 4; ++i) {
                        b[i * 4 + 0] = static_cast<uint8_t>(ep.addr[i] >> 24);
                        b[i * 4 + 1] = static_cast<uint8_t>(ep.addr[i] >> 16);
                        b[i * 4 + 2] = static_cast<uint8_t>(ep.addr[i] >> 8);
                        b[i * 4 + 3] = static_cast<uint8_t>(ep.addr[i]);
                    }
                    return {asio::ip::make_address_v6(b), ep.port};
                }
                const asio::ip::address_v4::bytes_type b{
                    static_cast<uint8_t>(ep.addr[0] >> 24),
                    static_cast<uint8_t>(ep.addr[0] >> 16),
                    static_cast<uint8_t>(ep.addr[0] >> 8),
                    static_cast<uint8_t>(ep.addr[0])};
                return {asio::ip::make_address_v4(b), ep.port};
            }

            /// The client half-closed the connection (its FIN reached the
            /// stack): find the owning relay and propagate the half-close to
            /// its upstream socket. The FIN segment ran on the flow's worker
            /// (shard affinity), so the relay's socket is only ever touched
            /// by one thread - no additional asio synchronization.
            void NotifyPeerFin(UInt64 conn_id) {
                // batch311: use the SAME shard->worker mapping as the
                // accept path (StartMimt queues by
                // ShardIndexOf(conn_id) % worker_count); the raw high byte
                // only matches while xtcp keeps the shard index below
                // kShardCount.
                const uint32_t worker =
                    xtcp::XtcpStack::ShardIndexOf(conn_id) % worker_count;
                if (worker >= static_cast<uint32_t>(relay_registry_.size()) ||
                    worker >= static_cast<uint32_t>(io_contexts.size())) {
                    return;
                }
                std::shared_ptr<relay::TcpRelay> relay;
                {
                    std::lock_guard<std::mutex> lock(
                        registry_mutexes[worker]);
                    const auto it = relay_index_[worker].find(conn_id);
                    if (it != relay_index_[worker].end()) {
                        relay = it->second.lock();
                    }
                }
                if (!relay) {
                    return;
                }
                // Always move the socket touch onto the OWNER worker: this
                // state handler runs on whichever worker fed the FIN (feeding
                // = SymmetricFlowHash % worker_count, owner = shard %
                // worker_count - different hashes), so calling OnPeerFin here
                // would drive socket_ from a foreign thread while the owner
                // polls its own io_context -> concurrent asio use is UB.
                // Deferring via an io_context post + weak_ptr also turns a
                // concurrently torn-down relay into a no-op instead of a
                // use-after-free.
                auto weak = std::weak_ptr<relay::TcpRelay>(relay);
                asio::post(*io_contexts[worker], [weak]() {
                    if (auto live = weak.lock()) {
                        live->OnPeerFin();
                    }
                });
            }

            void QueueTeardown(uint32_t index, UInt64 conn_id, bool graceful) {
                std::lock_guard<std::mutex> lock(abort_mutexes[index]);
                pending_teardowns_[index].push_back(
                    {conn_id, graceful});
            }

            void DrainAborts(uint32_t index) {
                std::vector<TeardownRequest> reqs;
                {
                    std::lock_guard<std::mutex> lock(abort_mutexes[index]);
                    reqs.swap(pending_teardowns_[index]);
                }
                for (const auto& req : reqs) {
                    if (req.graceful) {
                        stack->Close(req.conn_id);   // FIN to the client
                    } else {
                        stack->Abort(req.conn_id);   // RST to the client
                    }
                }
            }

            /// Dials the original destination for every accepted flow and
            /// attaches a TcpRelay on success. Runs on the owning worker.
            void DrainAccepts(uint32_t index) {
                std::vector<std::shared_ptr<xtcp::mimt::MimtFlow>> flows;
                {
                    std::lock_guard<std::mutex> lock(accept_mutexes[index]);
                    flows.swap(pending_accepts[index]);
                }
                if (flows.empty()) {
                    SweepRegistry(index);
                    return;
                }
                for (auto& flow : flows) {
                    // shared_ptr keeps the socket alive across the async
                    // connect (a loop-local unique_ptr would dangle).
                    auto socket =
                        std::make_shared<asio::ip::tcp::socket>(*io_contexts[index]);
                    auto timer =
                        std::make_shared<asio::steady_timer>(*io_contexts[index]);
                    timer->expires_after(
                        std::chrono::milliseconds(config.perf.dial_timeout_ms));
                    // Dial timeout: closing the socket aborts the pending
                    // connect with operation_aborted.
                    timer->async_wait(
                        [socket](const std::error_code& err) {
                            if (!err && socket->is_open()) {
                                std::error_code ignored;
                                socket->close(ignored);
                            }
                        });
                    const auto destination = ToAsio(flow->Local());
                    socket->async_connect(
                        destination,
                        [this, index, flow, timer, socket, destination](
                            const std::error_code& err) mutable {
                            // One dial that cannot be attached (a throw here
                            // used to take down the WHOLE data plane, not
                            // just this connection) costs only that
                            // connection: the body is firewalled and a
                            // failure falls through to the RST below.
                            const bool body_ok = core::InvokeHandlerGuarded(
                                stats->handler_errors, [&] {
                                    if (dial_completion_probe_) {
                                        dial_completion_probe_();
                                    }
                                    timer->cancel();
                                    if (err) {
                                        QueueTeardown(index, flow->ConnId(),
                                                      false);  // RST client
                                        return;
                                    }
                                    relay::TcpRelay::Hooks hooks;
                                    hooks.on_finished =
                                        [this, index](UInt64 conn_id,
                                                      bool graceful) {
                                            // batch306: mark the registry for
                                            // one reclaim scan; an idle worker
                                            // must not walk it (see
                                            // SweepRegistry).
                                            registry_dirty[index]->store(
                                                true,
                                                std::memory_order_relaxed);
                                            // Upstream EOF -> CLOSE (FIN to
                                            // client); errors/resets -> ABORT
                                            // (RST).
                                            QueueTeardown(index, conn_id,
                                                          graceful);
                                        };
                                    auto relay =
                                        std::make_shared<relay::TcpRelay>(
                                            flow, std::move(*socket),
                                            std::move(hooks));
                                    {
                                        std::lock_guard<std::mutex> lock(
                                            registry_mutexes[index]);
                                        relay_registry_[index].push_back(relay);
                                        // Overwrite any stale entry for this
                                        // id: a finished relay is only dropped
                                        // by the next sweep, and the LIVE one
                                        // must win the FIN.
                                        relay_index_[index][relay->ConnId()] =
                                            relay;
                                    }
                                    // pumps keep it alive afterwards
                                    relay->Start();
                                });
                            if (!body_ok) {
                                // No relay owns this flow: RST the client
                                // instead of leaving it half-open forever.
                                core::InvokeHandlerGuarded(
                                    stats->handler_errors, [&] {
                                        QueueTeardown(index, flow->ConnId(),
                                                      false);
                                    });
                            }
                        });
                }
                SweepRegistry(index);
            }

            /// Drops registry entries whose relay already finished. batch306:
            /// only scans after a relay actually finished - the old code ran
            /// this on every worker-loop iteration, so an idle data plane
            /// burned CPU proportional to the live connection count.
            void SweepRegistry(uint32_t index) {
                if (!registry_dirty[index]->exchange(
                        false, std::memory_order_relaxed)) {
                    return;  // nothing finished since the last scan
                }
                registry_sweeps_.fetch_add(1, std::memory_order_relaxed);
                std::lock_guard<std::mutex> lock(registry_mutexes[index]);
                auto& list = relay_registry_[index];
                auto& by_id = relay_index_[index];
                list.erase(std::remove_if(list.begin(), list.end(),
                                          [&by_id](const std::shared_ptr<relay::TcpRelay>& r) {
                                              if (nullptr == r) {
                                                  return true;
                                              }
                                              if (!r->Finished()) {
                                                  return false;
                                              }
                                              // Drop the index entry only if it
                                              // still points at THIS relay: a
                                              // reused conn_id may already own
                                              // a newer entry.
                                              const auto it = by_id.find(r->ConnId());
                                              if (it != by_id.end()) {
                                                  const auto held = it->second.lock();
                                                  if (!held || held.get() == r.get()) {
                                                      by_id.erase(it);
                                                  }
                                              }
                                              return true;
                                          }),
                           list.end());
            }

            /// batch311 diagnostics: total conn_id -> relay index entries.
            std::size_t RegistryIndexSize() {
                std::size_t total = 0;
                for (std::size_t i = 0; i < relay_index_.size(); ++i) {
                    std::lock_guard<std::mutex> lock(registry_mutexes[i]);
                    total += relay_index_[i].size();
                }
                return total;
            }

            /// One-second sample of vgww's own health (Windows perf counters).
            void SampleSystem() {
                // Host system totals act only as the denominator for the
                // process CPU % below.
                FILETIME idle{}, kernel{}, user{};
                uint64_t sys_total = 0;
                if (GetSystemTimes(&idle, &kernel, &user)) {
                    const uint64_t k =
                        (static_cast<uint64_t>(kernel.dwHighDateTime) << 32) |
                        kernel.dwLowDateTime;
                    const uint64_t u =
                        (static_cast<uint64_t>(user.dwHighDateTime) << 32) |
                        user.dwLowDateTime;
                    sys_total = (k + u) - (last_sys_kernel_ + last_sys_user_);
                    last_sys_kernel_ = k;
                    last_sys_user_ = u;
                }
                // vgww's own CPU: process kernel+user over the same window.
                // Percent is measured against the WHOLE machine (a process can
                // exceed 100% on a multi-core host; the UI scales by cores).
                FILETIME create{}, exit{}, pkernel{}, puser{};
                if (GetProcessTimes(GetCurrentProcess(), &create, &exit,
                                     &pkernel, &puser)) {
                    const uint64_t pk =
                        (static_cast<uint64_t>(pkernel.dwHighDateTime) << 32) |
                        pkernel.dwLowDateTime;
                    const uint64_t pu =
                        (static_cast<uint64_t>(puser.dwHighDateTime) << 32) |
                        puser.dwLowDateTime;
                    if (have_sys_sample_ && sys_total > 0) {
                        const double proc_delta = static_cast<double>(
                            (pk - last_proc_kernel_) + (pu - last_proc_user_));
                        const double pct = 100.0 *
                            proc_delta / static_cast<double>(sys_total);
                        sys_proc_cpu_percent_.store(pct < 0.0 ? 0.0 : pct);
                    }
                    last_proc_kernel_ = pk;
                    last_proc_user_ = pu;
                }
                have_sys_sample_ = true;
                PROCESS_MEMORY_COUNTERS pmc{};
                pmc.cb = sizeof(pmc);
                if (K32GetProcessMemoryInfo(GetCurrentProcess(), &pmc,
                                            sizeof(pmc))) {
                    sys_proc_ws_bytes_.store(pmc.WorkingSetSize);
                    sys_proc_virt_bytes_.store(pmc.PagefileUsage);
                }
                SYSTEM_INFO si{};
                GetSystemInfo(&si);
                sys_cpu_cores_.store(si.dwNumberOfProcessors);
                // batch208: the WebUI's /api/system reads this cache instead
                // of opening the SCM on every poll.
                SampleDriverService();
            }

            void ControlLoop() {
                auto last_dump = std::chrono::steady_clock::now();
                auto last_sys_sample = std::chrono::steady_clock::now() -
                                       std::chrono::seconds(1);
                // Unsolicited RA cadence: lifetime/3, clamped to [60s, 600s]
                // so clients refresh default routes long before expiry.
                const uint32_t ra_lifetime = config.ipv6.ra_lifetime_s;
                const uint32_t ra_period_s =
                    ra_lifetime / 3 < 60 ? 60
                        : (ra_lifetime / 3 > 600 ? 600 : ra_lifetime / 3);
                auto last_ra = std::chrono::steady_clock::now() -
                               std::chrono::seconds(ra_period_s);
                while (running.load()) {
                    neighbors.Tick(std::chrono::steady_clock::now());
                    relay::IcmpRelay::TagAllocator::Instance().Sweep(
                        std::chrono::steady_clock::now());
                    // Firewall / rate-limit snapshot refresh (RCU publish):
                    // the control thread pre-parses the rules ONCE here so the
                    // hot path never touches text formatting or allocations.
                    //
                    // batch146: driven by RuleStore::Rev() instead of running
                    // on every 100 ms tick. The rebuild walks every rule and
                    // re-parses its text (ParseMac, an IPv6 literal parse), so
                    // the unconditional version burned CPU in proportion to the
                    // rule count for as long as the process ran, whether or not
                    // a rule had changed. Rev() is the store's monotonic
                    // mutation anchor (bumped under the same lock that
                    // publishes each snapshot, AFTER publishing it), so
                    // "rev unchanged" proves "snapshots unchanged" and a
                    // missed refresh is impossible: a rev bump is always
                    // followed by a tick that sees it.
                    const uint64_t rule_rev = web::RuleStore::Instance().Rev();
                    if (!rules_published_ || rule_rev != published_rule_rev_) {
                        published_rule_rev_ = rule_rev;
                        rules_published_ = true;
                        rule_snapshot_refreshes_.fetch_add(
                            1, std::memory_order_relaxed);
                        // ONE snapshot read feeds the whole ban index: the
                        // old code published the v4 and v6 lists separately,
                        // so a frame could observe two different revisions (a
                        // ban added in between landed in one list and not the
                        // other).
                        auto bans = web::RuleStore::Instance().BanSnapshot();
                        {
                            auto index = std::make_shared<BanIndex>();
                            index->macs.reserve(bans->size());
                            index->ipv4.reserve(bans->size());
                            index->ipv6.reserve(bans->size());
                            for (const auto& ban : *bans) {
                                if ("mac" == ban.kind) {
                                    core::MacAddress mac{};
                                    if (!core::ParseMac(ban.value, mac)) {
                                        continue;   // malformed rule: skip
                                    }
                                    index->macs.insert(mac);
                                } else if ("ip" == ban.kind) {
                                    bool v4_ok = false;
                                    const uint32_t v4 =
                                        core::ParseIpv4(ban.value, v4_ok);
                                    // Only the canonical dotted quad ever
                                    // matched the old per-frame strcmp; keep
                                    // any other spelling inert instead of
                                    // silently widening what it blocks.
                                    if (v4_ok &&
                                        core::FormatIpv4(v4) == ban.value) {
                                        index->ipv4.insert(v4);
                                        continue;
                                    }
                                    std::error_code ec;
                                    const auto addr =
                                        asio::ip::make_address_v6(ban.value, ec);
                                    if (ec) {
                                        continue;  // neither v4 nor v6 literal
                                    }
                                    const auto bytes = addr.to_bytes();
                                    index->ipv6.insert(
                                        net::IpAddress::FromV6(bytes.data()));
                                }
                            }
                            std::shared_ptr<const BanIndex> immutable =
                                std::move(index);
                            std::atomic_store(&ban_index_snapshot_,
                                              std::move(immutable));
                        }
                        // Refresh rate-limit rules: convert web text rules to MAC
                        // bytes once here so the data plane never parses strings.
                        {
                            auto web_rules =
                                web::RuleStore::Instance().RateLimitSnapshot();
                            auto parsed = std::make_shared<
                                std::vector<tables::RateLimitRule>>();
                            parsed->reserve(web_rules->size());
                            for (const auto& web_rule : *web_rules) {
                                core::MacAddress mac{};
                                if (!core::ParseMac(web_rule.mac, mac)) {
                                    continue;  // malformed rule: skip
                                }
                                tables::RateLimitRule rule;
                                std::copy(mac.begin(), mac.end(), rule.mac.begin());
                                rule.uplink_kbps = web_rule.uplink_kbps;
                                rule.downlink_kbps = web_rule.downlink_kbps;
                                parsed->push_back(std::move(rule));
                            }
                            rate_limiter_.SetRules(parsed);
                        }
                    }  // end change-driven rule refresh
                    const auto now = std::chrono::steady_clock::now();
                    if (config.ipv6.enabled &&
                        now - last_ra > std::chrono::seconds(ra_period_s)) {
                        periodic_ra_due.store(true);
                        last_ra = now;
                    }
                    const auto dump_interval = std::chrono::milliseconds(
                        lease_dump_interval_ms_.load(
                            std::memory_order_relaxed));
                    if (now - last_dump >= dump_interval) {
                        // batch99: BOTH lease tables ride the cadence. v4 used
                        // to be dumped only on a clean Stop, so a crash or a
                        // hard kill lost every v4 lease while v6 kept a 60 s
                        // snapshot. DumpLeases counts its own write failures.
                        if (dhcp_) {
                            dhcp_->DumpLeases(lease_file, now);
                        }
                        if (dhcp6_) {
                            dhcp6_->DumpLeases(LeaseFile6(), now);
                        }
                        last_dump = now;
                    }
                    if (now - last_sys_sample >= std::chrono::seconds(1)) {
                        SampleSystem();
                        last_sys_sample = now;
                    }
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                }
            }

            // ----- injection helpers ------------------------------------------
            /// Appends a freshly built frame to the downstream batch. When
            /// the access VLAN is enabled, every frame is re-tagged with its
            /// VID (the single choke point for ALL VGWW-generated replies:
            /// arp/dhcp/icmp/ndp/udp/tcp replies, EmitFromStack, probes and
            /// portmap send_to_lan). The 1510 cap (1514 m_IBuffer physical
            /// size minus the 4-byte tag) guarantees the tagged frame still
            /// fits the driver buffer.
            void AppendDown(PortBatch& batch,
                            const uint8_t* frame, size_t len) {
                // INTERMEDIATE_BUFFER::m_IBuffer is a fixed array; never let
                // a future builder (oversized DHCP options, RDNSS) overrun it.
                // With 802.1Q the tagged frame must still fit: 1514 rack minus
                // the 4-byte tag = 1510. No VGWW-generated control frame today
                // exceeds ~600 bytes.
                static constexpr size_t kMaxFrameBytes = 1514;
                const size_t cap =
                    config.vlan.enabled() ? kMaxFrameBytes - net::kVlanTagLen
                                          : kMaxFrameBytes;
                if (len > cap) {
                    ++stats->rx_dropped;
                    return;
                }
                std::vector<INTERMEDIATE_BUFFER>& items = batch.items;
                items.emplace_back();
                INTERMEDIATE_BUFFER& ib = items.back();
                // P2: emplace_back() value-initialises the POD INTERMEDIATE_BUFFER,
                // so the 1566-byte memset is not needed - only the m_Length bytes
                // of m_IBuffer are written below.
                ib.m_dwDeviceFlags = PACKET_FLAG_ON_SEND;
                // C8: the frame is tagged with its batch's egress handle so
                // the driver attributes it to the port it will actually leave.
                ib.m_hAdapter = batch.handle;
                if (config.vlan.enabled()) {
                    // Shift the 14-byte Ethernet header body back by 4 to make
                    // room, then splice TPID (0x8100) + TCI (PCP/DEI/VID).
                    std::memcpy(ib.m_IBuffer, frame, net::kEthernetHeaderLen);
                    ib.m_IBuffer[12] =
                        static_cast<uint8_t>(net::kEthertypeVlan8021Q >> 8);
                    ib.m_IBuffer[13] =
                        static_cast<uint8_t>(net::kEthertypeVlan8021Q & 0xFF);
                    ib.m_IBuffer[14] =
                        static_cast<uint8_t>((config.vlan.id & 0x0FFF) >> 8);
                    ib.m_IBuffer[15] =
                        static_cast<uint8_t>(config.vlan.id & 0x0FFF);
                    std::memcpy(ib.m_IBuffer + net::kVlanEthernetHeaderLen,
                                frame + net::kEthernetHeaderLen,
                                len - net::kEthernetHeaderLen);
                    ib.m_Length = static_cast<DWORD>(len + net::kVlanTagLen);
                    ++stats->tx_vlan_frames;
                } else {
                    ib.m_Length = static_cast<DWORD>(len);
                    std::memcpy(ib.m_IBuffer, frame, len);
                }
            }

            /// Appends a copy of an intercepted buffer to a batch.
            void AppendCopy(std::vector<INTERMEDIATE_BUFFER>& batch,
                            const INTERMEDIATE_BUFFER& src) {
                batch.push_back(src);
            }

            /// C8: flushes a port-parameterized batch to its own egress
            /// adapter; a vanished adapter falls back to the primary (the
            /// frame is never silently dropped).
            void FlushPortBatch(PortBatch& batch, bool downstream) {
                if (batch.items.empty()) {
                    return;
                }
                const driver::AdapterEntry* target =
                    FindByHandle(batch.handle);
                FlushBatch(target ? *target : *adapter, batch.items,
                           downstream);
            }

            /// Sends one batch; `downstream` picks the IOCTL direction.
            void FlushBatch(const driver::AdapterEntry& target,
                            std::vector<INTERMEDIATE_BUFFER>& batch, bool downstream) {
                if (batch.empty()) {
                    return;
                }
                std::string err;
                bool ok = false;
                if (downstream) {
                    ok = client->SendPacketsToAdapter(
                        target.handle, batch.data(),
                        static_cast<uint32_t>(batch.size()), err);
                } else if (nullptr != up_client && nullptr != up_adapter &&
                           nullptr != adapter &&
                           target.handle == adapter->handle) {
                    // Batch-24-D: a host-bound reply for the PRIMARY adapter is
                    // injected through the dedicated handle (the primary LISTEN
                    // handle's MSTCP injection is not delivered to the local
                    // stack). Bridge-downstream frames keep their own handle on
                    // the primary client.
                    ok = up_client->SendPacketsToMstcp(
                        up_adapter->handle, batch.data(),
                        static_cast<uint32_t>(batch.size()), err);
                } else {
                    ok = client->SendPacketsToMstcp(
                        target.handle, batch.data(),
                        static_cast<uint32_t>(batch.size()), err);
                }
                if (!ok && !err.empty() && last_ioctl_warn_ != err) {
                    last_ioctl_warn_ = err;
                    std::fprintf(stderr, "[vgww] driver: %s\n", err.c_str());
                }
                batch.clear();
            }
        };

        // ------------------------------------------------------------------
        // Dataplane facade
        // ------------------------------------------------------------------
        Dataplane::Dataplane(const core::Config& config,
                             const std::string& lease_file)
            : config_(config),
              impl_(new Impl(config, lease_file)) {}

        Dataplane::~Dataplane() {
            if (!impl_) {
                return;
            }
            std::string ignored;
            if (!impl_->StopAll(ignored)) {
                // H2: a thread may still be inside driver/stack code that
                // points into Impl. Destroying Impl would be a use-after-
                // free, so leak it deliberately; the OS reclaims at exit.
                (void)impl_.release();
            }
        }

        void Dataplane::SetDriverClient(
            std::unique_ptr<driver::IDriverClient> client) {
            impl_->client = std::move(client);
            impl_->up_client.reset();
            impl_->up_adapter = nullptr;
            impl_->client_injected_ = true;
            impl_->CacheAdapterEntries();
        }

        void Dataplane::SetBridgeConfig(const bridge::BridgeConfig& config) {
            impl_->bridge_cfg_ = config;
        }

        void Dataplane::SetDialCompletionProbeForTest(
            std::function<void()> probe) {
            if (impl_) {
                impl_->dial_completion_probe_ = std::move(probe);
            }
        }

        void Dataplane::SetLeaseDumpIntervalForTest(
            std::chrono::milliseconds interval) {
            if (impl_) {
                const int64_t ms = interval.count() > 0 ? interval.count() : 1;
                impl_->lease_dump_interval_ms_.store(ms,
                                                     std::memory_order_relaxed);
            }
        }

        bridge::BridgeState Dataplane::GetBridgeState() const noexcept {
            if (!impl_) {
                return bridge::BridgeState::kStopped;
            }
            return impl_->bridge_state_.load();
        }

        std::string Dataplane::GetBridgeError() const {
            if (!impl_) {
                return std::string();
            }
            std::lock_guard<std::mutex> lock(impl_->bridge_error_mutex_);
            return impl_->bridge_error_;
        }

        size_t Dataplane::GetBridgeMacCount() const {
            if (!impl_) {
                return 0;
            }
            std::lock_guard<std::mutex> lock(impl_->bridge_table_mutex_);
            return impl_->bridge_table_.Size();
        }

        uint64_t Dataplane::GetNeighborRejections() const {
            if (!impl_) {
                return 0;
            }
            return impl_->neighbors.RejectedCount();
        }

        uint64_t Dataplane::GetBridgeMacEvictions() const {
            if (!impl_) {
                return 0;
            }
            std::lock_guard<std::mutex> lock(impl_->bridge_table_mutex_);
            return impl_->bridge_table_.Evictions();
        }

        Dataplane::AdapterBinding Dataplane::GetAdapterBinding() const {
            if (!impl_) {
                return AdapterBinding{};
            }
            std::lock_guard<std::mutex> lock(impl_->adapter_binding_mutex_);
            return impl_->adapter_binding_;
        }

        std::string Dataplane::LastError() const {
            if (!impl_) {
                return std::string();
            }
            return impl_->GetLastError();
        }

        bool Dataplane::IsRunning() const noexcept {
            return impl_ != nullptr && impl_->running.load();
        }

        std::vector<Dataplane::AdapterInfo> Dataplane::GetAdapters() const {
            std::vector<AdapterInfo> out;
            if (!impl_) {
                return out;
            }
            std::vector<driver::AdapterEntry> entries;
            {
                std::lock_guard<std::mutex> lock(
                    impl_->adapter_binding_mutex_);
                entries = impl_->adapter_entries_;
            }
            if (!impl_->client_injected_) {
                // Live link/IP refresh; injected doubles keep the entries
                // they scripted (they have no OS interface to query).
                driver::RefreshAdapterStates(entries);
            }
            out.reserve(entries.size());
            for (const driver::AdapterEntry& entry : entries) {
                AdapterInfo info;
                info.friendly_name = WideToUtf8(entry.friendly_name);
                info.device = WideToUtf8(entry.name);
                info.is_up = entry.is_up;
                info.media_connected = entry.media_connected;
                info.ipv4 = entry.ipv4;
                info.if_type = entry.if_type;
                info.ipv6 = entry.ipv6;
                out.push_back(std::move(info));
            }
            return out;
        }

        bool Dataplane::Start(std::string& error) {
            const bool ok = impl_->StartAll(error);
            // batch101: the last stop's verdict is NOT cleared here. A live
            // config apply is Stop->Start, and the operator must still be able
            // to see that the previous stop lost its lease document. Only the
            // next clean stop lowers the flag.
            impl_->SetLastError(ok ? std::string() : error);
            return ok;
        }

        bool Dataplane::Stop(std::string& error) noexcept {
            if (!impl_) {
                error.clear();
                return true;
            }
            const bool ok = impl_->StopAll(error);
            impl_->SetLastError(ok ? std::string() : error);
            return ok;
        }

        void Dataplane::Stop() noexcept {
            std::string ignored;
            (void)Stop(ignored);
        }

        Dataplane::LifecycleCounts Dataplane::GetLifecycleCounts() const noexcept {
            LifecycleCounts counts;
            if (!impl_) {
                return counts;
            }
            counts.rx_rings = impl_->rx_rings.size();
            counts.tx_rings = impl_->tx_rings.size();
            counts.io_contexts = impl_->io_contexts.size();
            counts.udp_tables = impl_->udp_tables.size();
            counts.icmp_relays = impl_->icmp_relays.size();
            counts.relay_registry = 0;
            for (const auto& list : impl_->relay_registry_) {
                counts.relay_registry += list.size();
            }
            counts.workers = impl_->workers.size();
            counts.running = impl_->running.load();
            counts.shutdown_incomplete = impl_->shutdown_incomplete_;
            return counts;
        }

        const Dataplane::Stats& Dataplane::GetStats() const noexcept {
            return impl_->owned_stats;
        }

        std::vector<uint64_t> Dataplane::IcmpProcessingLatencyUs() const {
            if (!impl_) {
                return {};
            }
            return impl_->IcmpProcLatencyUs();
        }

        size_t Dataplane::PendingRateTableSize() const noexcept {
            if (!impl_) {
                return 0;
            }
            return impl_->PendingRateTableSize();
        }

        std::vector<Dataplane::ClientRate> Dataplane::ClientRates() const {
            std::vector<ClientRate> out;
            if (!impl_) {
                return out;
            }
            auto snapshot =
                std::atomic_load(&impl_->published_rates_);
            const double window_s = snapshot->window_s;
            auto neigh = impl_->neighbors.Snapshot();
            const auto now = std::chrono::steady_clock::now();
            out.reserve(neigh->Entries().size());
            for (const auto& [ip, entry] : neigh->Entries()) {
                // Only clients on the gateway's own LAN are real devices
                // behind it. The neighbor table also records WAN-side sources
                // (host passthrough / Hyper-V vEthernet traffic), which are
                // internal to this machine and never shown on the device list.
                // The SAME predicate reports the per-client `lan` flag below,
                // so the filter and the flag can never disagree (C6).
                if (!IsLanClientAddress(impl_->config, ip)) {
                    continue;
                }
                ClientRate rate;
                rate.ip = ip;
                rate.mac = entry.mac;
                rate.lan = true;  // IsLanClientAddress() just proved it
                rate.last_seen_s = static_cast<uint64_t>(
                    std::chrono::duration_cast<std::chrono::seconds>(
                        now - entry.last_seen)
                        .count());
                const auto it = snapshot->by_mac.find(entry.mac);
                if (snapshot->by_mac.end() != it && window_s > 0.001) {
                    rate.up_bps = static_cast<uint64_t>(
                        static_cast<double>(it->second.up_bytes) / window_s);
                    rate.down_bps = static_cast<uint64_t>(
                        static_cast<double>(it->second.down_bytes) / window_s);
                }
                out.push_back(std::move(rate));
            }
            return out;
        }

        Dataplane::Throughput Dataplane::ThroughputBps() const noexcept {
            Throughput t;
            if (!impl_) {
                return t;
            }
            auto snapshot = std::atomic_load(&impl_->published_rates_);
            const double window_s = snapshot->window_s;
            if (window_s <= 0.001) {
                return t;
            }
            uint64_t up = 0;
            uint64_t down = 0;
            for (const auto& [mac, counter] : snapshot->by_mac) {
                (void)mac;
                up += counter.up_bytes;
                down += counter.down_bytes;
            }
            t.up_bps = static_cast<uint64_t>(
                static_cast<double>(up) / window_s);
            t.down_bps = static_cast<uint64_t>(
                static_cast<double>(down) / window_s);
            return t;
        }

        Dataplane::SystemStats Dataplane::GetSystem() const noexcept {
            SystemStats s;
            if (!impl_) {
                return s;
            }
            s.proc_cpu_percent = impl_->sys_proc_cpu_percent_.load();
            s.cpu_cores = impl_->sys_cpu_cores_.load();
            s.proc_ws_bytes = impl_->sys_proc_ws_bytes_.load();
            s.proc_virt_bytes = impl_->sys_proc_virt_bytes_.load();
            s.ndisrd_service_running = impl_->ndisrd_service_running_.load();
            return s;
        }

        void Dataplane::SetDriverServiceProbeForTest(std::function<bool()> probe) {
            if (!impl_) {
                return;
            }
            impl_->driver_service_probe_ = std::move(probe);
            // Re-sample so the cache reflects the injected value right away
            // (a headless test may never Start() the data plane).
            impl_->SampleDriverService();
        }

        // ------------------------------------------------------------------
        // DHCPv4 facade (S2). Every accessor is safe when no server was
        // assembled (bypass or dhcp.enabled=false): it returns an empty or
        // false result instead of dereferencing a null server.
        // ------------------------------------------------------------------
        std::vector<Dataplane::LeaseView> Dataplane::GetLeases() const {
            std::vector<LeaseView> result;
            if (!impl_ || !impl_->dhcp_) {
                return result;
            }
            const auto raw =
                impl_->dhcp_->Leases(std::chrono::steady_clock::now());
            result.reserve(raw.size());
            for (const auto& entry : raw) {
                LeaseView view;
                view.mac = core::FormatMac(entry.mac);
                view.ip = core::FormatIpv4(entry.ip);
                view.expires_in_s = entry.expires_in_s;
                view.is_static = entry.is_static;
                view.hostname = entry.hostname;
                result.push_back(std::move(view));
            }
            return result;
        }

        std::vector<Dataplane::BindingView> Dataplane::GetDhcpBindings() const {
            std::vector<BindingView> result;
            if (!impl_ || !impl_->dhcp_) {
                return result;
            }
            const auto raw = impl_->dhcp_->StaticBindings();
            result.reserve(raw.size());
            for (const auto& entry : raw) {
                BindingView view;
                view.mac = core::FormatMac(entry.mac);
                view.ip = core::FormatIpv4(entry.ip);
                view.hostname = entry.hostname;
                result.push_back(std::move(view));
            }
            return result;
        }

        bool Dataplane::SetDhcpBinding(const std::string& mac,
                                       const std::string& ip,
                                       const std::string& hostname) {
            // batch137: a plain add is a re-key that names no old key.
            return ReplaceDhcpBinding(std::string(), mac, ip, hostname);
        }

        bool Dataplane::ReplaceDhcpBinding(const std::string& old_mac,
                                           const std::string& mac,
                                           const std::string& ip,
                                           const std::string& hostname) {
            if (!impl_ || !impl_->dhcp_) {
                return false;
            }
            core::MacAddress parsed{};
            if (!core::ParseMac(mac, parsed)) {
                return false;
            }
            bool ok = false;
            const uint32_t addr = core::ParseIpv4(ip, ok);
            if (!ok || 0 == addr) {
                return false;
            }
            net::WireMac wire{};
            std::copy(parsed.begin(), parsed.end(), wire.begin());
            net::WireMac old_wire{};
            if (!old_mac.empty()) {
                core::MacAddress old_parsed{};
                if (!core::ParseMac(old_mac, old_parsed)) {
                    return false;  // a malformed old key would silently no-op
                }
                std::copy(old_parsed.begin(), old_parsed.end(), old_wire.begin());
            }
            return impl_->dhcp_->ReplaceBinding(
                old_mac.empty() ? wire : old_wire, wire, addr, hostname);
        }

        bool Dataplane::RemoveDhcpBinding(const std::string& mac) {
            if (!impl_ || !impl_->dhcp_) {
                return false;
            }
            core::MacAddress parsed{};
            if (!core::ParseMac(mac, parsed)) {
                return false;
            }
            net::WireMac wire{};
            std::copy(parsed.begin(), parsed.end(), wire.begin());
            return impl_->dhcp_->RemoveBinding(wire);
        }

        bool Dataplane::DhcpActive() const noexcept {
            return impl_ && impl_->dhcp_ != nullptr;
        }

        size_t Dataplane::DhcpLeaseCount() const noexcept {
            if (!impl_ || !impl_->dhcp_) {
                return 0;
            }
            return impl_->dhcp_->LeaseCount();
        }

        Dataplane::PortmapStats Dataplane::GetPortmapStats() const {
            const auto& mgr = relay::PortMapManager::Instance();
            const auto& s = mgr.GetStats();
            PortmapStats out;
            out.accepted = s.accepted.load(std::memory_order_relaxed);
            out.dial_failed = s.dial_failed.load(std::memory_order_relaxed);
            out.accept_errors =
                s.accept_errors.load(std::memory_order_relaxed);
            out.bind_failed = s.bind_failed.load(std::memory_order_relaxed);
            out.handler_errors =
                s.handler_errors.load(std::memory_order_relaxed);
            out.loop_errors = s.loop_errors.load(std::memory_order_relaxed);
            out.rearm_errors = s.rearm_errors.load(std::memory_order_relaxed);
            out.escaped_handler_errors =
                s.escaped_handler_errors.load(std::memory_order_relaxed);
            out.failed_ports = mgr.FailedPorts();
            return out;
        }

        uint64_t Dataplane::DhcpPoolExhaustedCount() const noexcept {
            if (!impl_ || !impl_->dhcp_) {
                return 0;
            }
            return impl_->dhcp_->PoolExhaustedCount();
        }

        uint64_t Dataplane::DhcpDroppedLeaseCount() const noexcept {
            if (!impl_ || !impl_->dhcp_) {
                return 0;
            }
            return impl_->dhcp_->DroppedLeaseCount();
        }

        bool Dataplane::DhcpLeaseFileCorrupt() const noexcept {
            return impl_ && impl_->dhcp_ &&
                   impl_->dhcp_->LeaseFileCorrupt();
        }

        uint64_t Dataplane::DhcpParseRejectedCount() const noexcept {
            return proto::ParseRejectedCount();
        }

        uint64_t Dataplane::Dhcp6ParseRejectedCount() const noexcept {
            return proto::ParseRejected6Count();
        }

        uint64_t Dataplane::DhcpRateLimitResets() const noexcept {
            if (!impl_ || !impl_->dhcp_) {
                return 0;
            }
            return impl_->dhcp_->RateLimitResets();
        }

        uint64_t Dataplane::Dhcp6RateLimitResets() const noexcept {
            if (!impl_ || !impl_->dhcp6_) {
                return 0;
            }
            return impl_->dhcp6_->RateLimitResets();
        }

        uint64_t Dataplane::RuleSnapshotRefreshCount() const noexcept {
            if (!impl_) {
                return 0;
            }
            return impl_->rule_snapshot_refreshes_.load(
                std::memory_order_relaxed);
        }

        uint64_t Dataplane::RegistrySweepCount() const noexcept {
            if (!impl_) {
                return 0;
            }
            return impl_->registry_sweeps_.load(std::memory_order_relaxed);
        }

        std::size_t Dataplane::RegistryIndexSize() {
            if (!impl_) {
                return 0;
            }
            return impl_->RegistryIndexSize();
        }

        uint64_t Dataplane::UdpFlowEvictions() const {
            if (!impl_) {
                return 0;
            }
            uint64_t total = 0;
            for (const auto& table : impl_->udp_tables) {
                if (table) {
                    total += table->Evictions();
                }
            }
            return total;
        }

        uint64_t Dataplane::DhcpPersistFailureCount() const noexcept {
            if (!impl_ || !impl_->dhcp_) {
                return 0;
            }
            return impl_->dhcp_->PersistFailureCount();
        }

        bool Dataplane::DhcpPersistBlocked() const noexcept {
            if (!impl_ || !impl_->dhcp_) {
                return false;
            }
            return impl_->dhcp_->PersistBlocked();
        }

        // ------------------------------------------------------------------
        // DHCPv6 facade (S2-Task8). Mirrors the v4 contract: every accessor is
        // safe when no v6 server was assembled (bypass / ipv6 off / dhcpv6
        // off) and degrades to an empty or false result.
        // ------------------------------------------------------------------
        // P2: the ONE definition of "is this address on the gateway's own LAN".
        // The device list filters on it and ClientRate.lan reports it, so the
        // two can never disagree (C6). v4: inside gateway.ipv4/mask. v6: inside
        // the advertised ULA prefix (and only when IPv6 is on).
        bool IsLanClientAddress(const core::Config& config,
                                const net::IpAddress& ip) noexcept {
            if (ip.IsV4()) {
                uint8_t wire[4];
                ip.ToV4Wire(wire);
                const uint32_t host_ip =
                    static_cast<uint32_t>(wire[0]) |
                    (static_cast<uint32_t>(wire[1]) << 8) |
                    (static_cast<uint32_t>(wire[2]) << 16) |
                    (static_cast<uint32_t>(wire[3]) << 24);
                return (host_ip & config.gateway.mask) ==
                       (config.gateway.ipv4 & config.gateway.mask);
            }
            // v6 clients are LAN clients only when they sit inside the ULA
            // prefix RA advertises (SLAAC clients).
            if (!config.ipv6.enabled || config.ipv6.prefix_len > 64) {
                return false;
            }
            const auto& pfx = config.ipv6.ula_prefix;
            const uint32_t len = config.ipv6.prefix_len;
            for (uint32_t i = 0; i < len / 8; ++i) {
                if (pfx[i] != ip.bytes[i]) {
                    return false;
                }
            }
            if ((len % 8) != 0) {
                const uint32_t rem = len % 8;
                const uint8_t keep =
                    static_cast<uint8_t>(0xFFu << (8 - rem));
                if ((pfx[len / 8] & keep) != (ip.bytes[len / 8] & keep)) {
                    return false;
                }
            }
            return true;
        }

        // batch142: these two are declared in dataplane.h so the REST layer can
        // compare DUIDs by value instead of by spelling.
        /// DUID <-> colon-separated hex (WebUI surface).
        std::string FormatDuidText(const std::vector<uint8_t>& duid) {
                static const char* kHex = "0123456789abcdef";
                std::string out;
                out.reserve(duid.size() * 3);
                for (size_t i = 0; i < duid.size(); ++i) {
                    if (0 != i) out.push_back(':');
                    out.push_back(kHex[duid[i] >> 4]);
                    out.push_back(kHex[duid[i] & 0x0F]);
                }
                return out;
            }

            bool ParseDuidText(const std::string& text,
                               std::vector<uint8_t>& out) {
                out.clear();
                std::string hex;
                hex.reserve(text.size());
                for (const char c : text) {
                    if (':' == c || '-' == c || '.' == c) continue;
                    hex.push_back(c);
                }
                if (hex.empty() || 0 != (hex.size() % 2)) {
                    return false;
                }
                const auto val = [](char c) -> int {
                    if (c >= '0' && c <= '9') return c - '0';
                    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
                    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
                    return -1;
                };
                for (size_t i = 0; i < hex.size(); i += 2) {
                    const int hi = val(hex[i]);
                    const int lo = val(hex[i + 1]);
                    if (hi < 0 || lo < 0) {
                        return false;
                    }
                    out.push_back(static_cast<uint8_t>((hi << 4) | lo));
                }
                return out.size() <= proto::kDhcp6MaxDuidLen;
            }

        namespace {
            std::string FormatIpv6Text(const std::array<uint8_t, 16>& ip) {
                char buf[46] = {};
                if (nullptr == ::InetNtopA(AF_INET6, ip.data(), buf,
                                           static_cast<DWORD>(sizeof(buf)))) {
                    return std::string();
                }
                return std::string(buf);
            }

            bool ParseIpv6Text(const std::string& text,
                               std::array<uint8_t, 16>& out) {
                return 1 == ::InetPtonA(AF_INET6, text.c_str(), out.data());
            }
        }  // namespace

        std::vector<Dataplane::Lease6View> Dataplane::GetLeases6() const {
            std::vector<Lease6View> result;
            if (!impl_ || !impl_->dhcp6_) {
                return result;
            }
            const auto raw =
                impl_->dhcp6_->Leases(std::chrono::steady_clock::now());
            result.reserve(raw.size());
            for (const auto& entry : raw) {
                Lease6View view;
                view.duid = FormatDuidText(entry.duid);
                view.iaid = entry.iaid;
                view.ip = FormatIpv6Text(entry.ip);
                view.expires_in_s = entry.expires_in_s;
                view.is_static = entry.is_static;
                view.hostname = entry.hostname;
                result.push_back(std::move(view));
            }
            return result;
        }

        std::vector<Dataplane::Binding6View> Dataplane::GetDhcp6Bindings()
            const {
            std::vector<Binding6View> result;
            if (!impl_ || !impl_->dhcp6_) {
                return result;
            }
            const auto raw = impl_->dhcp6_->StaticBindings();
            result.reserve(raw.size());
            for (const auto& entry : raw) {
                Binding6View view;
                view.duid = FormatDuidText(entry.duid);
                view.ip = FormatIpv6Text(entry.ip);
                view.hostname = entry.hostname;
                result.push_back(std::move(view));
            }
            return result;
        }

        bool Dataplane::SetDhcp6Binding(const std::string& duid,
                                        const std::string& ip,
                                        const std::string& hostname) {
            // batch137: a plain add is a re-key that names no old key.
            return ReplaceDhcp6Binding(std::string(), duid, ip, hostname);
        }

        bool Dataplane::ReplaceDhcp6Binding(const std::string& old_duid,
                                            const std::string& duid,
                                            const std::string& ip,
                                            const std::string& hostname) {
            if (!impl_ || !impl_->dhcp6_) {
                return false;
            }
            std::vector<uint8_t> parsed;
            if (!ParseDuidText(duid, parsed) || parsed.empty()) {
                return false;
            }
            std::array<uint8_t, 16> addr{};
            if (!ParseIpv6Text(ip, addr)) {
                return false;
            }
            bool all_zero = true;
            for (const uint8_t b : addr) {
                all_zero = all_zero && (0 == b);
            }
            if (all_zero) {
                return false;
            }
            std::vector<uint8_t> old_parsed;
            if (!old_duid.empty()) {
                if (!ParseDuidText(old_duid, old_parsed) || old_parsed.empty()) {
                    return false;  // a malformed old key would silently no-op
                }
            }
            return impl_->dhcp6_->ReplaceBinding(
                old_duid.empty() ? parsed : old_parsed, parsed, addr, hostname);
        }

        bool Dataplane::RemoveDhcp6Binding(const std::string& duid) {
            if (!impl_ || !impl_->dhcp6_) {
                return false;
            }
            std::vector<uint8_t> parsed;
            if (!ParseDuidText(duid, parsed) || parsed.empty()) {
                return false;
            }
            return impl_->dhcp6_->RemoveBinding(parsed);
        }

        bool Dataplane::Dhcp6Active() const noexcept {
            return impl_ && impl_->dhcp6_ != nullptr;
        }

        size_t Dataplane::Dhcp6LeaseCount() const noexcept {
            if (!impl_ || !impl_->dhcp6_) {
                return 0;
            }
            return impl_->dhcp6_->LeaseCount();
        }

        bool Dataplane::Dhcp6PersistBlocked() const noexcept {
            if (!impl_ || !impl_->dhcp6_) {
                return false;
            }
            return impl_->dhcp6_->PersistBlocked();
        }

        uint64_t Dataplane::Dhcp6PersistFailureCount() const noexcept {
            if (!impl_ || !impl_->dhcp6_) {
                return 0;
            }
            return impl_->dhcp6_->PersistFailureCount();
        }

        uint64_t Dataplane::Dhcp6PoolExhaustedCount() const noexcept {
            if (!impl_ || !impl_->dhcp6_) {
                return 0;
            }
            return impl_->dhcp6_->PoolExhaustedCount();
        }

        uint64_t Dataplane::Dhcp6DroppedLeaseCount() const noexcept {
            if (!impl_ || !impl_->dhcp6_) {
                return 0;
            }
            return impl_->dhcp6_->DroppedLeaseCount();
        }

        bool Dataplane::Dhcp6LeaseFileCorrupt() const noexcept {
            return impl_ && impl_->dhcp6_ &&
                   impl_->dhcp6_->LeaseFileCorrupt();
        }

        bool Dataplane::StopPersistFailed() const noexcept {
            return impl_ && impl_->stop_persist_failed_;
        }

        size_t Dataplane::Dhcp6BindingCount() const noexcept {
            if (!impl_ || !impl_->dhcp6_) {
                return 0;
            }
            return impl_->dhcp6_->StaticBindingCount();
        }

    }  // namespace runtime
}  // namespace vgww
