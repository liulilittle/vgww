// ============================================================================
// config.h - VGWW runtime configuration model.
//
// Configuration is loaded from a JSON file (see docs/en/configuration.md)
// with optional command-line overrides. The parsed Config object is treated
// as IMMUTABLE for the whole process lifetime: workers read it lock-free
// (see design spec section 5.1 - zero locks on the data path).
//
// All addresses are stored in network byte order unless noted otherwise.
// ============================================================================
#pragma once

#include "core/limits.h"

#include <array>
#include <atomic>
#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace vgww {
    namespace core {

        /// A MAC address in transmission order (byte 0 first on the wire).
        typedef std::array<uint8_t, 6> MacAddress;

        /// One DHCP static binding: this MAC always receives this IP.
        struct StaticBinding {
            MacAddress mac{};
            uint32_t ip = 0;             ///< network byte order
            std::string hostname;         ///< optional, forwarded as option 12
        };

        struct GatewayConfig {
            uint32_t ipv4 = 0;            ///< virtual gateway IPv4, network order
            uint32_t mask = 0;            ///< LAN netmask, network order
            MacAddress mac{};             ///< virtual gateway MAC
        };

        struct DhcpConfig {
            bool enabled = false;
            uint32_t pool_start = 0;      ///< first dynamic lease, network order
            uint32_t pool_end = 0;        ///< last dynamic lease (inclusive), network order
            uint32_t lease_seconds = 86400;
            std::vector<uint32_t> dns;    ///< DNS servers handed to clients, network order
            std::vector<StaticBinding> static_bindings;
        };

        /// One DHCPv6 static binding: this DUID always receives this address.
        struct Dhcp6StaticBinding {
            std::vector<uint8_t> duid;      ///< DUID-LL/LLT/EN, 1..128 octets
            std::array<uint8_t, 16> ip{};   ///< inside the ULA prefix
            std::string hostname;           ///< optional, shown in the UI
        };

        /// Stateful DHCPv6 service (RFC 8415 subset, spec section 5.2).
        struct Dhcp6Config {
            bool enabled = false;
            std::array<uint8_t, 16> pool_start{};  ///< zero = derive ::1000
            std::array<uint8_t, 16> pool_end{};    ///< zero = derive ::1FFF
            uint32_t lease_seconds = 3600;
            std::vector<Dhcp6StaticBinding> static_bindings;
        };

        struct Ipv6Config {
            bool enabled = false;
            std::array<uint8_t, 16> ula_prefix{};  ///< ULA prefix, network order
            uint8_t prefix_len = 64;               ///< advertised prefix length
            uint32_t ra_lifetime_s = 1800;         ///< router lifetime in RA
            std::vector<std::array<uint8_t, 16>> dns;  ///< RDNSS v6 servers
            Dhcp6Config dhcpv6;                    ///< stateful DHCPv6 server
        };

        struct PerfConfig {
            uint32_t workers = 8;          ///< worker threads == xtcp shard count
            uint32_t rx_batch = 64;        ///< frames per ReadPackets call
            uint32_t max_conns = 4096;     ///< xtcp connection cap
            uint32_t udp_flow_cap = 8192;  ///< per-worker UDP flow table cap
            uint32_t ring_capacity = 4096; ///< SPSC ring descriptors per worker
            /// Upstream TCP dial timeout. On expiry the pending connect is
            /// aborted and the client receives RST (never a silent hang).
            uint32_t dial_timeout_ms = 10000;
            /// batch31 P1-4: flush each RX batch's control-plane replies
            /// immediately instead of waiting for the whole kernel-queue drain
            /// (up to 64 x rx_batch frames) plus the worker TX-ring drain. That
            /// wait was the measured ping-latency amplifier: a reply sat in the
            /// batch while unrelated frames were processed. TRUE = low latency
            /// (default, the user-visible ping case); FALSE = old behaviour,
            /// one fewer IOCTL per batch under bulk load.
            bool rx_flush_eager = true;
            /// batch31 P1-4: the RX thread's fallback wait on the driver event.
            /// The event is the fast path (sub-ms); this value is the WORST
            /// case when the driver does not signal it for a frame. It used to
            /// be a hardcoded 200 ms, which quantizes a late reply to ~200 ms -
            /// exactly the user-reported 372/187/151 ms pattern. 10 ms keeps
            /// the idle cost at 100 wakeups/s and bounds the worst case below
            /// the p95 < 10 ms target. Range [1, 200].
            uint32_t rx_poll_ms = 10;
        };

        struct WebConfig {
            /// batch20 P2 (user ruling): the Web UI is ON by default - a
            /// config without the key starts the server; only an explicit
            /// "enabled": false disables it. --web forces it on and --no-web
            /// forces it off (highest priority, see main.cpp).
            bool enabled = true;
            uint16_t port = 8080;          ///< management UI listen port
            /// Management UI listen address (e.g. "127.0.0.1"; loopback when
            /// unset). Empty is rejected at validation: the server never
            /// binds every interface implicitly.
            std::string bind = "127.0.0.1";
            /// When non-empty, every non-GET /api request must present
            /// "X-Auth-Token: <token>" (or an Authorization: Bearer header).
            /// Empty = open write access (lab use only).
            std::string token;
        };

        /// Optional single 802.1Q access VLAN (id 0 = disabled). When enabled,
        /// inbound frames tagged with this VID are stripped before the
        /// classifier and every VGWW-reply frame is re-tagged with it. Frames
        /// from other VLANs are isolated (dropped).
        struct VlanConfig {
            uint16_t id = 0;  ///< 1..4094 after validation; 0 = unset (feature off). Explicit 0/4095 are rejected at load.
            bool enabled() const noexcept { return id != 0; }
        };

        /// Optional built-in L2 bridge (S3-Task4; default off). No
        /// STP/RSTP is performed (spec section 6.1/12: single-path
        /// topologies only). Wired to the dataplane bridge loop by Task 3
        /// (`Dataplane::SetBridgeConfig`); the file schema lands here.
        struct BridgeConfig {
            bool enabled = false;
            std::string upstream;    ///< first adapter hint
            std::string downstream;  ///< second adapter hint
            uint32_t mac_table_size = limits::kDefaultMacTableSize;
        };

        /// Deployment mode (S2): gates the address-assignment services
        /// (DHCPv4/DHCPv6/RA). `bypass` (default) keeps today's behavior -
        /// clients point at VGWW manually, no address services run. `main`
        /// enables them (per-service wiring happens in later S2 tasks).
        enum class Mode { kBypass, kMain };

        /// Outcome of WriteFileAtomicDurable.
        enum class AtomicWriteOutcome : uint8_t {
            kOk = 0,
            kIoError = 1,         ///< open/write/flush/publish failed
            kValidationFailed = 2  ///< the validator rejected the temp file
        };

        /// Writes `data` to `path` atomically AND durably: a process-unique
        /// sibling temp -> write -> flush to the device -> [optional
        /// validation of the temp] -> atomic replace (bounded retry when the
        /// destination is transiently busy). A failed DEVICE FLUSH is a
        /// failure: publishing anyway would report durability the volume never
        /// provided, which is exactly how a "saved" set of rules/leases
        /// vanishes after a power cut. On failure the destination is left
        /// untouched and the temp file is removed.
        AtomicWriteOutcome WriteFileAtomicDurable(
            const std::string& path, const std::string& data,
            std::string& error,
            const std::function<bool(const std::string& temp_path)>&
                validator = std::function<bool(const std::string&)>());

        /// Test seam: replaces the device-flush step used by
        /// WriteFileAtomicDurable. `handle` is the OS file handle as an
        /// integer; returning false simulates a flush failure. Pass an empty
        /// function to restore the real FlushFileBuffers.
        void SetFileFlushHookForTest(std::function<bool(std::intptr_t)> hook);

        /// Test seam: runs just before a temp file is deleted on a failure
        /// path (after the writer closed its handle). A test can hold the file
        /// open here to prove the delete retries instead of leaking
        /// `<path>.tmp.<pid>.<seq>`. Pass an empty function to clear it.
        void SetPreDeleteHookForTest(
            std::function<void(const std::string& path)> hook);

        /// Moves `path` aside to `path + suffix`, replacing any previous
        /// aside copy (one bounded file, never a growing pile). Used to
        /// preserve a file a loader found unreadable so the next snapshot
        /// write cannot silently destroy the only evidence of the loss.
        /// Returns false when the source is missing or the rename fails.
        bool SetAsideFile(const std::string& path, const std::string& suffix);

        /// Test seam: simulates a failure to OPEN a persistent file for
        /// reading (`path` is the file the caller is about to open). Returning
        /// 0 lets the real open happen; a non-zero Win32 error code (e.g.
        /// ERROR_SHARING_VIOLATION == 32) simulates that attempt failing with
        /// that error. Shared by the config, rules and lease loaders so one
        /// seam can hold any of them un-openable.
            void SetConfigOpenFailureHookForTest(
                std::function<unsigned long(const std::string& path)> hook);

        /// P82 test seam: when set, ConfigFileLock takes a DIFFERENT mutex than
        /// the real one for the same path. Only a caller that takes the lock
        /// EXPLICITLY (outside the atomic writer) is then blocked - the
        /// internal write path keeps the real lock and never waits. Restores
        /// the real name when cleared.
        void SetConfigLockNameOverrideForTest(
            const std::function<std::string(const std::string& path)>&
                override);

        /// Returns the simulated open failure for `path` (0 = open normally).
        unsigned long SimulatedOpenFailure(const std::string& path);

        /// batch107 test seam: overrides ConfigFileLock's blocking wait
        /// (production default 30 s). Zero or negative restores the default.
        void SetConfigLockWaitForTest(std::chrono::milliseconds wait);

        struct Config {
            std::string adapter;           ///< adapter friendly name or GUID
            /// batch19 R4-P4: persisted native UI language code (BCP-47-ish,
            /// e.g. "zh-CN"/"en"/"ja"). Applied at startup via
            /// I18n::SetLangCode; an unknown value falls back to zh-CN.
            std::string ui_language = "zh-CN";
            /// batch20: UI scale override. "auto" follows the desktop DPI;
            /// otherwise one of "100".."500" (25-step) = an absolute percent.
            /// Invalid values normalise to "auto" on load.
            std::string ui_scale = "auto";
            /// batch22 A1: native appearance - "dark" (default, historical),
            /// "light", or "auto" (follow Windows AppsUseLightTheme). Invalid
            /// values normalise to "dark" on load.
            std::string theme = "dark";
            GatewayConfig gateway;
            DhcpConfig dhcp;
            Ipv6Config ipv6;
            PerfConfig perf;
            WebConfig web;
            VlanConfig vlan;
            BridgeConfig bridge;
            Mode mode = Mode::kBypass;     ///< bypass unless "mode":"main"

            /// Parses a configuration file. Returns nullopt and fills
            /// `error` on any problem (missing file, bad JSON, validation).
            static std::optional<Config> LoadFromFile(
                const std::string& path, std::string& error);

            /// Applies CLI overrides (e.g. --adapter=Ethernet). Returns false
            /// and fills `error` on malformed input.
            bool ApplyCliOverrides(const std::vector<std::string>& args,
                                   std::string& error);

            /// Serializes the config back to JSON. Keys match LoadFromFile
            /// exactly (mode/adapter/gateway/dhcp/ipv6/perf/web/vlan/bridge);
            /// the DHCP pool uses the primary `"pool": [start, end]` array.
            /// Keys the parser rejects at their default value are omitted:
            /// "pool" when either bound is 0 (0.0.0.0 is never a valid
            /// config IP) and "vlan" when id == 0 (reserved 802.1Q
            /// codepoint).
            std::string ToJsonString() const;

            /// Atomically writes ToJsonString() to `path`: same-directory
            /// `<path>.tmp` -> FlushFileBuffers -> MoveFileExW(
            /// MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH). Returns
            /// false with `error` on failure; a pre-existing file at `path`
            /// is left untouched and the tmp file is deleted.
            bool SaveToFile(const std::string& path, std::string& error) const;

            /// batch96: like SaveToFile(), but the DHCP static-binding lists
            /// belong to their runtime routes, so a settings save taken from a
            /// snapshot that predates a binding POST must not delete the
            /// bindings that reached disk in the meantime. Re-reads the
            /// document under the write locks and appends every binding this
            /// snapshot lacks; identity is the MAC (v4) / DUID (v6), and this
            /// snapshot wins when both sides carry the same one. A missing or
            /// unreadable document degrades to a plain save.
            bool SaveToFilePreservingBindings(const std::string& path,
                                              std::string& error) const;

            /// batch94: serialized read-modify-write of the document at
            /// `path`. Concurrent in-process writers of the same path (a
            /// binding route's load/upsert/save and a whole-document POST
            /// /api/config publish) take the same per-path lock, so neither
            /// can overwrite the other's just-published change with the
            /// stale snapshot it loaded earlier. Returns false when the file
            /// cannot be read or written; `mutate` runs while the lock is
            /// held, so it must be short and must not touch the same path.
            static bool UpdateFile(const std::string& path,
                                   const std::function<void(Config&)>& mutate,
                                   std::string& error);

            /// batch94: the per-path lock UpdateFile() holds. Whole-document
            /// publishers (POST /api/config) take it around their final
            /// atomic publish so a read-modify-write cannot interleave.
            static std::mutex& FileMutex(const std::string& path);
            /// Returns a process-unique sibling temp path for the atomic
            /// replace of `path`: `<path>.tmp.<pid>.<seq>`. The sequence is a
            /// SINGLE process-wide atomic defined once in config.cpp, so the
            /// UI writer (Config::SaveToFile) and the web writer
            /// (POST /api/config in web_api.cpp) - two different translation
            /// units - can never both start at 0 and collide on the same temp
            /// name (U1). Callers open this path "wb" and flush it, then
            /// publish it with PublishConfigTempFile(). On non-Windows the
            /// sequence suffix is omitted and the legacy `<path>.tmp` name is
            /// returned.
            static std::string MakeUniqueSiblingPath(const std::string& path);

            /// batch80: publishes `tmp` onto `path` with one atomic replace
            /// (MoveFileExW(REPLACE_EXISTING|WRITE_THROUGH)), retrying BRIEFLY
            /// when the destination is transiently busy.
            ///
            /// Unique temp names are not enough on their own. Two writers that
            /// hold DIFFERENT temp files still collapse onto the SAME
            /// destination, and Windows answers ERROR_ACCESS_DENIED for the
            /// loser of that overlap (measured: 13 failures in 40 runs of two
            /// concurrent writers, every one err=5 and the "atomic replace
            /// failed" one-shot path). The optimistic retry below turns that
            /// into success; a genuinely permanent failure still reports the
            /// error after the budget is spent. `tmp` is deleted on failure.
            /// Single shared implementation so the UI and web writers cannot
            /// drift apart (C9: one knowledge, one place).
            static bool PublishConfigTempFile(const std::string& tmp,
                                              const std::string& path,
                                              std::string& error);
        };

        /// batch95: process-exclusive lock for one config document, layered
        /// UNDER the in-process FileMutex (always taken in that order). Two
        /// VGWW processes can share one config path - a --headless WebUI run
        /// deliberately bypasses the single-instance gate - and their
        /// load->mutate->publish windows would otherwise overwrite each other
        /// across processes, which an in-process mutex cannot see. Windows: a
        /// named kernel mutex in the Local namespace (per login session; two
        /// sessions are not mutually excluded).
        class ConfigFileLock {
        public:
            /// `blocking=false` returns immediately with locked()==false when
            /// another owner holds the lock (used by tests and callers that
            /// prefer to report instead of wait). Blocking waits up to 30 s,
            /// then reports locked()==false rather than hanging a worker.
            explicit ConfigFileLock(const std::string& path,
                                    bool blocking = true);
            ~ConfigFileLock();
            ConfigFileLock(const ConfigFileLock&) = delete;
            ConfigFileLock& operator=(const ConfigFileLock&) = delete;
            bool locked() const { return locked_; }

        private:
            void* handle_ = nullptr;
            bool locked_ = false;
        };

        /// batch97: shared static-binding persistence for the HTTP routes
        /// (web_api) and the native UI commands (controller) - one knowledge,
        /// one place. Each is a locked read-modify-write of the config
        /// document: an empty path (no document configured), an unreadable or
        /// an unwritable file returns false with `error`. Upsert matches on
        /// the identity key (MAC / DUID); delete of an absent key succeeds.
        bool UpsertDhcpBinding(const std::string& path, const MacAddress& mac,
                               uint32_t ip, const std::string& hostname,
                               std::string& error);
        bool DeleteDhcpBinding(const std::string& path, const MacAddress& mac,
                               std::string& error);
        bool UpsertDhcp6Binding(const std::string& path,
                                const std::vector<uint8_t>& duid,
                                const std::array<uint8_t, 16>& ip,
                                const std::string& hostname,
                                std::string& error);
        bool DeleteDhcp6Binding(const std::string& path,
                                const std::vector<uint8_t>& duid,
                                std::string& error);

        /// Validates semantic constraints that span parsed fields (gateway
        /// shape, DHCP pool, ULA, perf/bridge ranges) plus the value ranges
        /// the JSON parser bounds at load time. Public since S4 Task 5: the
        /// UI settings draft validates programmatic configs before
        /// SaveConfigCmd writes them to disk (the parser is not in that
        /// path).
        bool ValidateConfig(const Config& config, std::string& error);

        /// True when this configuration runs the address-assignment services
        /// (DHCPv4/DHCPv6/RA). Gating consumers: S2 Tasks 2/5/6/7.
        bool AddressServicesEnabled(const Config& config) noexcept;

        /// Parses "AA:BB:CC:DD:EE:FF" (any separator or none) into bytes.
        /// Returns false on malformed input.
        bool ParseMac(const std::string& text, MacAddress& out) noexcept;

        /// Formats a MAC back to "AA:BB:CC:DD:EE:FF".
        std::string FormatMac(const MacAddress& mac);

        /// Parses dotted-quad IPv4 into network byte order. Returns 0 and
        /// sets `ok = false` on failure (0.0.0.0 is never a valid config IP).
        uint32_t ParseIpv4(const std::string& text, bool& ok) noexcept;

        /// Formats an IPv4 (network byte order) as dotted quad.
        std::string FormatIpv4(uint32_t ip) noexcept;

        /// Parses a literal IPv6 address (no "/prefix") into 16 wire-order
        /// bytes. Returns false on malformed input; "::" compression and
        /// mixed-case hex are accepted (same parser the config loader uses).
        bool ParseIpv6(const std::string& text,
                       std::array<uint8_t, 16>& out);

        /// Formats a 16-byte IPv6 address (network order) as eight lowercase
        /// hex groups "xxxx:xxxx:...:xxxx"; no "::" compression. Promoted
        /// from dhcp6.cpp (S4 Task 1) so core consumers share one formatter;
        /// the UI layer must not own it (vgww_core cannot depend on vgww_ui).
        std::string FormatIpv6(const std::array<uint8_t, 16>& addr);

        /// batch20 P2: the effective Web-UI switch, the single rule shared by
        /// main.cpp and the tests. Priority: --no-web (off) > --web (on) >
        /// config.web.enabled (default true).
        inline bool WebEnabledEffective(bool config_enabled, bool flag_web,
                                        bool flag_no_web) noexcept {
            if (flag_no_web) {
                return false;
            }
            if (flag_web) {
                return true;
            }
            return config_enabled;
        }

        /// True when a management-UI bind address is loopback-only:
        /// "localhost", 127.0.0.0/8 or ::1. Anything else is reachable from
        /// the LAN and therefore needs write authentication.
        inline bool WebBindIsLoopback(const std::string& bind) noexcept {
            if (bind.empty()) {
                return false;
            }
            std::string lower;
            lower.reserve(bind.size());
            for (const char c : bind) {
                lower.push_back(static_cast<char>(
                    (c >= 'A' && c <= 'Z') ? (c - 'A' + 'a') : c));
            }
            if ("localhost" == lower || "::1" == lower) {
                return true;
            }
            return 0 == lower.rfind("127.", 0);
        }

        /// The management UI accepts unauthenticated writes only when it is
        /// bound to loopback. A LAN-reachable bind with an empty token would
        /// let any host rewrite the config (and run the privileged actions).
        inline bool WebBindRequiresToken(const std::string& bind) noexcept {
            return !WebBindIsLoopback(bind);
        }


        /// batch22 A1: accepted native appearance values.
        inline bool IsValidThemeValue(const std::string& value) noexcept {
            return value == "dark" || value == "light" || value == "auto";
        }

        /// UI scale: "auto" or an absolute percent in the 25-step sequence
        /// 100,125,...,500 (17 options).
        inline bool IsValidUiScaleValue(const std::string& value) noexcept {
            if (value == "auto") {
                return true;
            }
            if (value.size() != 3) {
                return false;
            }
            int n = 0;
            for (const char c : value) {
                if (c < '0' || c > '9') {
                    return false;
                }
                n = n * 10 + (c - '0');
            }
            return n >= 100 && n <= 500 && (n % 25) == 0;
        }

        /// "auto" (or anything invalid) -> 0.0f = follow the desktop DPI;
        /// "200" -> 2.0f. The window treats 0 as "auto".
        inline float UiScaleValueToFactor(const std::string& value) noexcept {
            if (!IsValidUiScaleValue(value) || value == "auto") {
                return 0.0f;
            }
            int n = 0;
            for (const char c : value) {
                n = n * 10 + (c - '0');
            }
            return static_cast<float>(n) / 100.0f;
        }

    }  // namespace core
}  // namespace vgww
