// ============================================================================
// dhcp.h - Frame-level DHCPv4 server (RFC 2131 subset).
//
// Runs directly on intercepted broadcast frames (the kernel filter hands us
// UDP 67/68 before the host stack sees them). Implements the DISCOVER ->
// OFFER -> REQUEST -> ACK cycle plus RELEASE; static MAC bindings take
// priority over the dynamic pool.
//
// Wire format (fixed part 236 + magic 4 =240): op htype hlen hops
// xid(4) secs(2) flags(2) ciaddr(4) yiaddr(4) siaddr(4) giaddr(4)
// chaddr(16) sname(64) file(128) magic(4)=63:82:53:63, then TLV options.
// ============================================================================
#pragma once

#include "core/config.h"
#include "net/eth.h"
#include "proto/udp.h"

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace vgww {
    namespace proto {

        inline constexpr size_t kDhcpFixedLen = 240;
        inline constexpr size_t kDhcpFrameMin = net::kEthernetHeaderLen + 20 +
                                                kUdpHeaderLen + kDhcpFixedLen;
        inline constexpr uint8_t kDhcpMsgDiscover = 1;
        inline constexpr uint8_t kDhcpMsgOffer = 2;
        inline constexpr uint8_t kDhcpMsgRequest = 3;
        inline constexpr uint8_t kDhcpMsgDecline = 4;
        inline constexpr uint8_t kDhcpMsgAck = 5;
        inline constexpr uint8_t kDhcpMsgNak = 6;
        inline constexpr uint8_t kDhcpMsgRelease = 7;
        inline constexpr uint8_t kDhcpMsgInform = 8;

        // DHCP option codes (public: tests and the WebUI need them too).
        inline constexpr uint8_t kDhcpOptionSubnet = 1;
        inline constexpr uint8_t kDhcpOptionRouter = 3;
        inline constexpr uint8_t kDhcpOptionDns = 6;
        inline constexpr uint8_t kDhcpOptionHostname = 12;
        inline constexpr uint8_t kDhcpOptionRequestedIp = 50;
        inline constexpr uint8_t kDhcpOptionLeaseTime = 51;
        inline constexpr uint8_t kDhcpOptionMsgType = 53;
        inline constexpr uint8_t kDhcpOptionServerId = 54;
        inline constexpr uint8_t kDhcpOptionEnd = 255;

        struct DhcpView final {
            uint8_t op = 0;              ///< 1=request from client, 2=reply
            uint32_t xid = 0;            ///< transaction id (host order)
            net::WireMac client_mac{};
            uint8_t msg_type = 0;        ///< option 53 value
            uint32_t requested_ip = 0;   ///< option 50 (host-order numeric)
            uint32_t server_id = 0;      ///< option 54 (RELEASE check)
            std::string hostname;        ///< option 12 when present
        };

        /// Parses a full Ethernet+IP+UDP+DHCP frame. Returns false for
        /// malformed or non-DHCP frames. Strictly scoped to client requests:
        /// non-BOOTREQUEST op, non-Ethernet htype, hlen != 6, a destination
        /// port other than 67 or a UDP length that disagrees with the frame
        /// are rejected (F1).
        bool ParseDhcpFrame(const uint8_t* data, size_t len, DhcpView& out) noexcept;

        /// Cumulative count of frames dropped by ParseDhcpFrame. Monotonic
        /// (never reset); the status surface reports deltas.
        uint64_t ParseRejectedCount() noexcept;

        /// Builds a complete Ethernet+IP+UDP+DHCP reply frame. L2 unicasts
        /// to the client MAC; the IP layer broadcasts (clients have no
        /// address yet - RFC 2131 section 4.3.1 broadcast rule).
        void BuildDhcpReplyFrame(uint8_t msg_type, uint32_t xid,
                                 const net::WireMac& gateway_mac,
                                 const net::WireMac& client_mac,
                                 uint32_t your_ip, uint32_t server_ip,
                                 uint32_t subnet_mask, uint32_t lease_seconds,
                                 const std::vector<uint32_t>& dns_servers,
                                 const std::string& hostname,
                                 std::vector<uint8_t>& out_frame);

    }  // namespace proto

    namespace dhcp {

        /// One lease binding.
        struct Lease {
            uint32_t ip = 0;   ///< inet_addr numeric convention
            std::chrono::steady_clock::time_point expires;
            bool is_static = false;
            std::string hostname;  ///< client-reported (option 12), may be empty
        };

        /// Thread-safe lease manager (control-plane rate: a mutex is fine).
        class DhcpServer final {
        public:
            explicit DhcpServer(const core::Config& config);

            /// Returns the address to OFFER/ACK for this client, or 0 when
            /// none available. Static bindings win; the dynamic pool hands
            /// out the first free address and renews existing mappings.
            /// kOffer holds the address for a short window only (an un-ACKed
            /// offer must not pin a pool address for the whole lease term);
            /// kAck grants/renews the full lease.
            enum class OfferStage : uint8_t { kOffer, kAck };
            /// `hostname` is the client-reported option-12 name; an empty
            /// value (a renew that omits the option) preserves the learnt
            /// name instead of wiping it. `requested_ip` is option 50 (0 when
            /// absent): a free, in-pool, non-gateway address is honoured
            /// before the round-robin walk (F2).
            uint32_t Acquire(const net::WireMac& client_mac,
                             std::chrono::steady_clock::time_point now,
                             OfferStage stage = OfferStage::kAck,
                             const std::string& hostname = std::string(),
                             uint32_t requested_ip = 0);

            /// Rate-limits DHCP request frames per client MAC (anti-storm:
            /// a faulty or hostile client blasting DISCOVER/REQUEST otherwise
            /// burns CPU and pins the hold window, exhausting the pool).
            /// Returns true when the frame should be processed. Bounded map
            /// (drop-all when oversized), same cheap discipline as probes.
            bool AllowFrame(const net::WireMac& client_mac,
                            std::chrono::steady_clock::time_point now);

            /// Marks an address as bad after the client reported a conflict
            /// (DHCP DECLINE): it is skipped by the pool until the hold
            /// window elapses, preventing repeated assignment of a
            /// conflicting address.
            void Decline(const net::WireMac& client_mac, uint32_t ip,
                         std::chrono::steady_clock::time_point now);

            /// Releases the lease held by `client_mac` (DHCP RELEASE).
            /// `server_id` is the server-id echoed by the client (option 54);
            /// 0 means "not reported" and skips the check. A non-zero id that
            /// does not match this server keeps the lease (F6).
            void Release(const net::WireMac& client_mac,
                         uint32_t server_id = 0);

            /// Evicts expired dynamic leases; returns removed count.
            size_t Sweep(std::chrono::steady_clock::time_point now);

            /// Persists dynamic leases to a JSON file (crash/ restart keeps
            /// address mappings stable). Returns false on I/O failure.
            bool DumpLeases(const std::string& path,
                            std::chrono::steady_clock::time_point now);

            /// batch34b: WHY a load ended the way it did. The bool alone could
            /// not distinguish "first run, no file yet" (normal) from "the
            /// file exists but is corrupt/oversized/future-schema" (a real
            /// fault that silently discards every lease). Callers printed
            /// "no lease file" for ALL of them, hiding data loss.
            enum class LoadOutcome : uint8_t {
                kRestored,   ///< file read and parsed (some entries may
                             ///< still have been dropped as stale)
                kNoFile,     ///< absent: a normal first run
                kCorrupt,    ///< oversized, bad JSON or an unsupported
                             ///< schema version (the file IS preserved)
                kUnreadable  ///< exists but could not be opened even after
                             ///< bounded retries (transient lock/permission):
                             ///< nothing was parsed, so nothing may be
                             ///< overwritten by a later dump
            };

            /// Restores leases persisted by DumpLeases. Expired entries are
            /// skipped. Returns false when the file is missing/corrupt; use
            /// the outcome overload to tell those two apart.
            /// skipped. Returns false when the file is missing/corrupt.
            bool LoadLeases(const std::string& path,
                            std::chrono::steady_clock::time_point now);

            /// batch34b: same load, with the reason. `kRestored` means the
            /// file was consumed; `dropped` counts entries the state-
            /// consistency gate refused (stale, out-of-LAN, reserved, or
            /// malformed) so a caller can report silent data loss.
            LoadOutcome LoadLeases(const std::string& path,
                                    std::chrono::steady_clock::time_point now,
                                    size_t* dropped);

            size_t LeaseCount() const noexcept;

            /// Cumulative counters for the status surface: the dynamic pool
            /// had no free address to hand out (F5), and the lease file could
            /// not be persisted (F4). Monotonic; callers report deltas.
            uint64_t PoolExhaustedCount() const noexcept;
            uint64_t PersistFailureCount() const noexcept;
            /// batch119: cumulative lease entries dropped while loading the
            /// persisted document (malformed, expired, outside the LAN,
            /// reserved by a static binding, or a duplicate address in the
            /// file). Monotonic; surfaced so the loss is never silent.
            uint64_t DroppedLeaseCount() const noexcept;
            /// batch120: true after the lease document was found unreadable
            /// as DATA (corrupt/oversized/wrong schema) and preserved as
            /// `<path>.corrupt`; the persisted mappings did not survive.
            bool LeaseFileCorrupt() const noexcept;
            /// batch86: true while dumping is refused because the lease file
            /// could not be read at load time (a transient lock must not be
            /// answered by overwriting the possibly-valid document).
            bool PersistBlocked() const noexcept;
            /// batch34j: times the anti-storm rate-window map was cleared
            /// wholesale because it hit kMaxRateEntries.
            uint64_t RateLimitResets() const noexcept;
            /// batch114: cumulative lease-record probes performed by the
            /// pool walk. Exposed so a test can prove the walk is O(leases +
            /// pool_size) rather than O(pool_size * leases) without timing.
            uint64_t LeaseScanCount() const noexcept;

            /// One lease entry for the WebUI snapshot.
            struct LeaseEntry {
                net::WireMac mac;
                uint32_t ip = 0;
                uint32_t expires_in_s = 0;
                bool is_static = false;
                std::string hostname;  ///< client-reported (option 12)
            };

            /// Snapshot of all active leases (static bindings included).
            std::vector<LeaseEntry> Leases(
                std::chrono::steady_clock::time_point now) const;

            /// Adds or updates a runtime static binding (MAC -> IP), taking
            /// effect on the next Acquire. Returns false on out-of-pool IP.
            bool UpsertBinding(const net::WireMac& client_mac, uint32_t ip,
                           const std::string& hostname = std::string());

            /// batch137: re-keys a binding in ONE atomic step - "drop the
            /// binding for `old_mac`, then bind `client_mac`" either happens
            /// completely or not at all. The UI used to post a RemoveBinding
            /// followed by an UpsertBinding; each could be refused on its own
            /// (command queue full, the kMaxStaticBindings cap, an address
            /// collision, an out-of-subnet IP), leaving the old binding
            /// deleted and the new one unstored. `old_mac` may name a binding
            /// that does not exist (a config-only row, or a stale table): the
            /// call then behaves exactly like UpsertBinding.
            bool ReplaceBinding(const net::WireMac& old_mac,
                                const net::WireMac& client_mac, uint32_t ip,
                                const std::string& hostname = std::string());

            /// Removes a runtime static binding. Returns false when there is
            /// no such binding.
            bool RemoveBinding(const net::WireMac& client_mac);

            /// Snapshot of every static binding known to the server: runtime
            /// overrides merged over config bindings (mac, ip, hostname).
            struct StaticView {
                net::WireMac mac;
                uint32_t ip = 0;
                std::string hostname;
            };
            std::vector<StaticView> StaticBindings() const;

        private:
            /// A COPY of the config, not a reference: RemoveBinding must be
            /// able to drop a config-managed static binding from the live
            /// view, and the caller's config object is const. Mirrors the
            /// DHCPv6 server, which has always held a copy.
            core::Config config_;
            std::mutex mutex_;
            std::unordered_map<net::WireMac, Lease, net::WireMacHash> leases_;
            uint32_t next_dynamic_ = 0;  ///< pool cursor (host order)

            /// Runtime static bindings (WebUI-managed) merged over the config.
            struct Binding {
                uint32_t ip = 0;
                std::string hostname;
            };
            std::unordered_map<net::WireMac, Binding, net::WireMacHash>
                runtime_bindings_;

            /// Addresses reported conflicting (DECLINE): usable again after
            /// the hold window.
            std::unordered_map<uint32_t, std::chrono::steady_clock::time_point>
                declined_until_;

            /// Per-second DISCOVER/REQUEST budget per client MAC.
            struct RateWindow {
                uint64_t seconds = 0;  ///< window key (epoch seconds)
                size_t count = 0;      ///< frames seen in this window
            };
            std::unordered_map<net::WireMac, RateWindow, net::WireMacHash>
                rate_limit_;

            static constexpr size_t kMaxFramesPerSecond = 8;
            static constexpr size_t kMaxRateEntries = 4096;

            /// Status counters (F4/F5); atomic so the accessors stay noexcept.
            mutable std::atomic<uint64_t> persist_failures_{0};
            /// batch119: see DroppedLeaseCount().
            mutable std::atomic<uint64_t> dropped_leases_{0};
            /// batch120: see LeaseFileCorrupt().
            mutable std::atomic<bool> lease_file_corrupt_{false};
            /// batch85: set when LoadLeases could not even open the file. The
            /// document may be perfectly valid (a scanner held it for a
            /// moment), so the next snapshot must NOT overwrite it; every dump
            /// is refused until a new server instance reads the file
            /// successfully.
            mutable std::atomic<bool> persist_blocked_{false};
    /// batch34j: times the per-client rate window map was cleared wholesale
    /// because it hit kMaxRateEntries (anti-storm protection lost briefly).
    mutable std::atomic<uint64_t> rate_limit_resets_{0};
            std::atomic<uint64_t> pool_exhausted_{0};
            /// Throttle stamp for the pool-exhausted warning (epoch ms).
            std::atomic<uint64_t> last_pool_log_ms_{0};
            /// batch114: lease-record probes done by the pool walk.
            mutable std::atomic<uint64_t> lease_scans_{0};
        };

    }  // namespace dhcp
}  // namespace vgww
