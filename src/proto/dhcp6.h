// ============================================================================
// dhcp6.h - Frame-level DHCPv6 server (RFC 8415 subset).
//
// Runs on intercepted UDP 546/547 frames. Implements the SOLICIT ->
// ADVERTISE / REQUEST -> REPLY exchange plus RENEW, REBIND, RELEASE,
// DECLINE and INFORMATION-REQUEST, IA_NA + IAADDR address assignment from a
// ULA pool, DNS servers (option 23), DUID-LL server id, DUID-keyed static
// bindings, versioned persistence and a per-DUID rate limit.
//
// Wire format (RFC 8415 section 8): msg-type(1) transaction-id(3) options.
// Every option is code(2) length(2) data.
//
// v1 limitation (spec section 5.2): the server never probes an address with
// a Neighbor Solicitation before handing it out; a client-reported conflict
// (DECLINE) parks the address for 600 s instead.
// ============================================================================
#pragma once

#include "core/config.h"
#include "core/limits.h"
#include "net/eth.h"

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace vgww {
    namespace proto {

        inline constexpr uint16_t kDhcp6ClientPort = 546;
        inline constexpr uint16_t kDhcp6ServerPort = 547;

        // Message types (RFC 8415 section 7.3, subset).
        inline constexpr uint8_t kDhcp6MsgSolicit = 1;
        inline constexpr uint8_t kDhcp6MsgAdvertise = 2;
        inline constexpr uint8_t kDhcp6MsgRequest = 3;
        inline constexpr uint8_t kDhcp6MsgConfirm = 4;
        inline constexpr uint8_t kDhcp6MsgRenew = 5;
        inline constexpr uint8_t kDhcp6MsgRebind = 6;
        inline constexpr uint8_t kDhcp6MsgReply = 7;
        inline constexpr uint8_t kDhcp6MsgRelease = 8;
        inline constexpr uint8_t kDhcp6MsgDecline = 9;
        inline constexpr uint8_t kDhcp6MsgInformationRequest = 11;

        // Option codes (RFC 8415 section 21, subset).
        inline constexpr uint16_t kDhcp6OptClientId = 1;
        inline constexpr uint16_t kDhcp6OptServerId = 2;
        inline constexpr uint16_t kDhcp6OptIaNa = 3;
        inline constexpr uint16_t kDhcp6OptIaAddr = 5;
        inline constexpr uint16_t kDhcp6OptOro = 6;
        inline constexpr uint16_t kDhcp6OptElapsed = 8;
        inline constexpr uint16_t kDhcp6OptStatusCode = 13;
        inline constexpr uint16_t kDhcp6OptRapidCommit = 14;
        inline constexpr uint16_t kDhcp6OptDnsServers = 23;

        // Status codes (RFC 8415 section 21.13).
        inline constexpr uint16_t kDhcp6StatusSuccess = 0;
        inline constexpr uint16_t kDhcp6StatusUnspecFail = 1;
        inline constexpr uint16_t kDhcp6StatusNoAddrsAvail = 2;
        inline constexpr uint16_t kDhcp6StatusNoBinding = 3;
        inline constexpr uint16_t kDhcp6StatusNotOnLink = 4;
        inline constexpr uint16_t kDhcp6StatusUseMulticast = 5;

        /// Minimum frame: Ethernet(14) + IPv6(40) + UDP(8) + type(1)+xid(3).
        inline constexpr size_t kDhcp6FrameMin =
            net::kEthernetHeaderLen + 40 + 8 + 4;
        /// DUID length bound (RFC 8415 section 11.1: 1..128 octets).
        /// batch145: single-sourced with the ui/runtime text checks.
        inline constexpr size_t kDhcp6MaxDuidLen = core::limits::kMaxDuidBytes;
        /// IA_NA fixed part: IAID(4) + T1(4) + T2(4).
        inline constexpr size_t kDhcp6IaNaMin = 12;

        /// Parsed client request (offsets validated; no heap copies beyond
        /// the two DUIDs).
        struct Dhcp6View final {
            uint8_t msg_type = 0;
            uint32_t xid = 0;                   ///< 24-bit, host order
            bool has_client_id = false;
            std::vector<uint8_t> client_duid;   ///< option 1
            bool has_server_id = false;
            std::vector<uint8_t> server_duid;   ///< option 2
            bool has_ia_na = false;
            uint32_t iaid = 0;
            bool has_ia_addr = false;
            std::array<uint8_t, 16> ia_addr{};  ///< IAADDR inside IA_NA
            bool rapid_commit = false;          ///< option 14
            std::array<uint8_t, 16> src_ip{};   ///< IPv6 source (link-local)
            std::array<uint8_t, 16> dst_ip{};
        };

        /// Parses a full Ethernet+IPv6+UDP+DHCPv6 frame. Returns false for
        /// malformed frames, non-client messages and requests missing the
        /// mandatory IA_NA (RFC 8415 sections 18.2/18.3).
        bool ParseDhcp6Frame(const uint8_t* data, size_t len,
                             Dhcp6View& out) noexcept;

        /// batch122: cumulative count of frames dropped by ParseDhcp6Frame.
        /// Monotonic (never reset); the status surface reports deltas.
        uint64_t ParseRejected6Count() noexcept;

        /// Everything BuildDhcp6ReplyFrame needs. Keeping it in one struct
        /// avoids a 20-parameter function.
        struct Dhcp6Reply final {
            uint8_t msg_type = kDhcp6MsgReply;
            uint32_t xid = 0;
            std::vector<uint8_t> client_duid;
            std::vector<uint8_t> server_duid;
            bool rapid_commit = false;   ///< echo option 14 (rapid commit)
            bool with_ia_na = false;
            uint32_t iaid = 0;
            uint32_t t1 = 0;
            uint32_t t2 = 0;
            bool with_ia_addr = false;
            std::array<uint8_t, 16> ia_addr{};
            uint32_t preferred_s = 0;
            uint32_t valid_s = 0;
            bool with_status = false;   ///< option 13 (IA-level or top level)
            bool status_in_ia = false;  ///< true: inside IA_NA, false: top
            uint16_t status = kDhcp6StatusSuccess;
            bool with_dns = false;
            std::vector<std::array<uint8_t, 16>> dns;
        };

        /// Builds a complete Ethernet+IPv6+UDP+DHCPv6 reply frame with
        /// correct UDP checksum; L2 unicasts to `client_mac`.
        void BuildDhcp6ReplyFrame(const Dhcp6Reply& reply,
                                  const net::WireMac& gateway_mac,
                                  const net::WireMac& client_mac,
                                  const std::array<uint8_t, 16>& server_ip,
                                  const std::array<uint8_t, 16>& client_ip,
                                  std::vector<uint8_t>& out_frame);

    }  // namespace proto

    namespace dhcp6 {

        /// One dynamic/static lease binding.
        struct Lease {
            std::array<uint8_t, 16> ip{};
            uint32_t iaid = 0;
            std::chrono::steady_clock::time_point expires;
            bool is_static = false;
            std::string hostname;
        };

        /// Thread-safe DHCPv6 lease manager + state machine (control-plane
        /// rate: a mutex is fine).
        class Dhcp6Server final {
        public:
            /// The config is copied: tests build servers from temporaries.
            explicit Dhcp6Server(const core::Config& config);

            /// kOffer holds the address for a short window only (an ADVERTISE
            /// must not pin a pool address for the whole lease term); kAck
            /// grants/renews the full lease.
            enum class OfferStage : uint8_t { kOffer, kAck };

            /// Returns the address to ADVERTISE/REPLY for this client
            /// (DUID + IAID); all-zero means none available. Static bindings
            /// win; the dynamic pool hands out the first free address and
            /// renews existing mappings. `requested` (optional) is the
            /// IAADDR the client asked for: honoured when free and in-pool.
            std::array<uint8_t, 16> Acquire(
                const std::vector<uint8_t>& duid, uint32_t iaid,
                std::chrono::steady_clock::time_point now, OfferStage stage,
                const std::string& hostname = std::string(),
                const std::array<uint8_t, 16>* requested = nullptr);

            /// Rate-limits request frames per client DUID (8 msg/s).
            bool AllowFrame(const std::vector<uint8_t>& duid,
                            std::chrono::steady_clock::time_point now);

            /// Parks an address after a DECLINE (600 s) and drops the lease.
            void Decline(const std::vector<uint8_t>& duid, uint32_t iaid,
                         const std::array<uint8_t, 16>& ip,
                         std::chrono::steady_clock::time_point now);

            /// Releases the lease held by (duid, iaid). A non-empty
            /// `server_duid` that does not match this server keeps the lease
            /// (RFC 8415 section 18.3.7).
            void Release(const std::vector<uint8_t>& duid, uint32_t iaid,
                         const std::vector<uint8_t>& server_duid);

            /// Evicts expired dynamic leases; returns removed count.
            size_t Sweep(std::chrono::steady_clock::time_point now);

            /// Persists dynamic leases to a versioned JSON file (atomic
            /// temp+rename, FlushFileBuffers). Returns false on I/O failure.
            bool DumpLeases(const std::string& path,
                            std::chrono::steady_clock::time_point now);

            /// batch34c: same outcome contract as the v4 server (see
            /// DhcpServer::LoadOutcome). The bool alone reported a corrupt or
            /// future-schema file as "no lease file", hiding data loss.
            enum class LoadOutcome : uint8_t {
                kRestored,
                kNoFile,
                kCorrupt,
                kUnreadable  ///< exists but could not be opened even after
                             ///< bounded retries: nothing was parsed, so
                             ///< nothing may be overwritten by a later dump
            };

            /// Restores leases persisted by DumpLeases. Expired entries are
            /// skipped; a file over kMaxLeases6Bytes or corrupt returns false.
            bool LoadLeases(const std::string& path,
                            std::chrono::steady_clock::time_point now);

            /// batch34c: same load with the reason and the number of entries
            /// the state-consistency gate refused.
            LoadOutcome LoadLeases(const std::string& path,
                                   std::chrono::steady_clock::time_point now,
                                   size_t* dropped);

            size_t LeaseCount() const noexcept;

            /// Pool had no free address (RFC 8415 NoAddrsAvail) / persistence
            /// failed. Monotonic; callers report deltas.
            uint64_t PoolExhaustedCount() const noexcept;
            uint64_t PersistFailureCount() const noexcept;
            /// batch119: see DhcpServer::DroppedLeaseCount().
            uint64_t DroppedLeaseCount() const noexcept;
            /// batch120: see DhcpServer::LeaseFileCorrupt().
            bool LeaseFileCorrupt() const noexcept;
            /// batch86: see DhcpServer::PersistBlocked.
            bool PersistBlocked() const noexcept;
            /// batch34j: times the anti-storm rate-window map was cleared
            /// wholesale because it hit kMaxRateEntries.
            uint64_t RateLimitResets() const noexcept;
            /// batch114: cumulative lease-record probes performed by the
            /// pool walk. Exposed so a test can prove the walk is O(leases +
            /// pool_size) instead of O(pool_size * leases) without timing.
            uint64_t LeaseScanCount() const noexcept;

            struct LeaseEntry {
                std::vector<uint8_t> duid;
                uint32_t iaid = 0;
                std::array<uint8_t, 16> ip{};
                uint32_t expires_in_s = 0;
                bool is_static = false;
                std::string hostname;
            };
            /// Snapshot of all active leases (static bindings included,
            /// static entries first).
            std::vector<LeaseEntry> Leases(
                std::chrono::steady_clock::time_point now) const;

            /// Adds/updates a runtime static binding (DUID -> address).
            /// Returns false when the address is outside the prefix.
            bool UpsertBinding(const std::vector<uint8_t>& duid,
                               const std::array<uint8_t, 16>& ip,
                               const std::string& hostname = std::string());

            /// Removes a runtime static binding. Returns false when absent.
            bool RemoveBinding(const std::vector<uint8_t>& duid);

            /// batch137: atomic re-key, v6 sibling of
            /// DhcpServer::ReplaceBinding. Drops the binding for `old_duid`
            /// and stores `duid` -> `ip` in one lock, so a refused half can
            /// never delete the client's binding without storing the new one.
            /// `old_duid` may name a binding that does not exist.
            bool ReplaceBinding(const std::vector<uint8_t>& old_duid,
                                const std::vector<uint8_t>& duid,
                                const std::array<uint8_t, 16>& ip,
                                const std::string& hostname = std::string());

            /// Snapshot of every static binding known to the server: runtime
            /// overrides merged over config bindings.
            std::vector<core::Dhcp6StaticBinding> StaticBindings() const;

            /// batch127: O(1) count of the bindings StaticBindings() would
            /// return, WITHOUT materialising the vector. The status surface
            /// only needs the number; building every entry (three strings +
            /// a hex DUID format) per poll was pure waste.
            size_t StaticBindingCount() const;

            /// This server's DUID-LL (RFC 8415 section 11.3): type 3,
            /// hardware type 1, gateway MAC.
            const std::vector<uint8_t>& ServerDuid() const noexcept;

            /// Full server path for one parsed client message: rate limit ->
            /// state machine -> reply frame. Returns true when a reply is due
            /// (RELEASE and DECLINE are answered with a status REPLY).
            bool HandleFrame(const proto::Dhcp6View& view,
                             const net::WireMac& client_mac,
                             const std::array<uint8_t, 16>& client_ip,
                             std::chrono::steady_clock::time_point now,
                             std::vector<uint8_t>& out_reply);

        private:
            /// Lease key: DUID + IAID (RFC 8415 section 18.3.1).
            struct Key {
                std::vector<uint8_t> duid;
                uint32_t iaid = 0;
                bool operator==(const Key& other) const noexcept {
                    return iaid == other.iaid && duid == other.duid;
                }
            };
            struct KeyHash {
                size_t operator()(const Key& key) const noexcept;
            };

            struct Binding {
                std::array<uint8_t, 16> ip{};
                std::string hostname;
            };
            struct DuidHash {
                size_t operator()(const std::vector<uint8_t>& duid) const noexcept;
            };

            /// Last 8 bytes of an address as a big-endian index.
            static uint64_t IndexOf(const std::array<uint8_t, 16>& addr) noexcept;
            static void AddressAt(uint64_t index,
                                  const std::array<uint8_t, 16>& prefix,
                                  std::array<uint8_t, 16>& out) noexcept;

            /// Resolves the pool defaults (prefix::1000 - prefix::1FFF) when
            /// the config leaves them zero.
            void ResolvePool();

            /// True when `ip` lies inside the configured prefix.
            bool InPrefix(const std::array<uint8_t, 16>& ip) const noexcept;

            /// True when `ip` is reserved by a static binding (config or
            /// runtime) for a DUID other than `duid`.
            bool ReservedByStatic(const std::vector<uint8_t>& duid,
                                  const std::array<uint8_t, 16>& ip) const;

            core::Config config_;
            std::vector<uint8_t> server_duid_;
            std::array<uint8_t, 16> pool_prefix_{};
            uint64_t pool_start_index_ = 0;
            uint64_t pool_end_index_ = 0;
            uint64_t next_index_ = 0;  ///< pool cursor (IID space)

            mutable std::mutex mutex_;
            std::unordered_map<Key, Lease, KeyHash> leases_;
            std::unordered_map<std::vector<uint8_t>, Binding, DuidHash>
                runtime_bindings_;
            std::map<std::array<uint8_t, 16>,
                     std::chrono::steady_clock::time_point>
                declined_until_;

            struct RateWindow {
                uint64_t seconds = 0;
                size_t count = 0;
            };
            std::unordered_map<std::string, RateWindow> rate_limit_;
            static constexpr size_t kMaxFramesPerSecond = 8;
            static constexpr size_t kMaxRateEntries = 4096;

            mutable std::atomic<uint64_t> persist_failures_{0};
            /// batch119: see DroppedLeaseCount().
            mutable std::atomic<uint64_t> dropped_leases_{0};
            /// batch120: see LeaseFileCorrupt().
            mutable std::atomic<bool> lease_file_corrupt_{false};
            /// batch85: set when LoadLeases could not open the file; every
            /// dump is refused so a briefly locked (but valid) file is never
            /// overwritten.
            mutable std::atomic<bool> persist_blocked_{false};
    /// batch34j: times the per-client rate window map was cleared wholesale
    /// because it hit kMaxRateEntries (anti-storm protection lost briefly).
    mutable std::atomic<uint64_t> rate_limit_resets_{0};
            std::atomic<uint64_t> pool_exhausted_{0};
            mutable std::atomic<uint64_t> last_pool_log_ms_{0};
            /// batch114: lease-record probes done by the pool walk.
            mutable std::atomic<uint64_t> lease_scans_{0};
        };

    }  // namespace dhcp6
}  // namespace vgww
