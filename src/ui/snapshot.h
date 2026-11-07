// ============================================================================
// snapshot.h - immutable UI snapshots + command queue (S4.2 Task 4).
//
// Data flow: a single publisher thread polls a UiDataSource (500 ms stats /
// 1 s full status) and atomically swaps an immutable UiSnapshot; the UI thread
// only ever reads the current pointer. Mutations travel the other way through
// a FIFO CommandQueue executed by one worker thread, which then asks the
// publisher for an early refresh.
//
// Pointer-swap choice: C++17 has no std::atomic<std::shared_ptr<T>> (that is
// C++20), and the deprecated std::atomic_load/store free functions force a
// spinlock or a global lock table in the MSVC STL. A single-writer publisher
// with a short mutex around the swap is simpler and provably correct: the
// reader only copies the shared_ptr under the same lock (microseconds), and
// the snapshot object itself is immutable once published.
// ============================================================================
#pragma once

#include "bridge/bridge.h"
#include "core/config.h"
#include "runtime/dataplane.h"
#include "web/web_api.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <variant>
#include <vector>

namespace vgww {
    namespace ui {

        /// Scalar copy of ALL 14 Dataplane::Stats counters.
        /// batch34a: portmap_send_dropped used to be the one field left out
        /// (not mirrored), so a port-map relay whose WAN->LAN queue hit its
        /// hard cap dropped packets with NO user-visible trace. Dataplane::Stats
        /// holds atomics and is not copyable, so collectors must load every
        /// field individually.
        struct Counters {
            uint64_t rx_frames = 0;
            uint64_t rx_dropped = 0;
            uint64_t tx_frames = 0;
            uint64_t arp_replies = 0;
            uint64_t icmp_replies = 0;
            uint64_t host_passthrough = 0;
            uint64_t tcp_accepted = 0;
            uint64_t mac_misses = 0;
            uint64_t rate_limited = 0;
            uint64_t rx_vlan_frames = 0;
            uint64_t thread_errors = 0;
            uint64_t icmp_tag_exhausted = 0;
            uint64_t tx_vlan_frames = 0;
            /// batch34a: WAN->LAN queue over its hard cap (port-map relay).
            uint64_t portmap_send_dropped = 0;
        };

        /// Immutable copy of the effective configuration (formatted strings).
        struct ConfigView {
            std::string adapter;
            std::string mode;  ///< "bypass" | "main"
            std::string gateway_ip, gateway_mask, gateway_mac;
            bool dhcp_enabled = false;
            std::string dhcp_pool_start, dhcp_pool_end;
            uint32_t dhcp_lease_s = 0;
            std::vector<std::string> dhcp_dns;
            bool ipv6_enabled = false;
            std::string ula_prefix;
            uint8_t prefix_len = 0;
            uint32_t ra_lifetime_s = 0;
            std::vector<std::string> ipv6_dns;
            bool dhcp6_enabled = false;
            std::string dhcp6_pool_start, dhcp6_pool_end;
            uint32_t dhcp6_lease_s = 0;
            /// batch22 A6: these mirror core::PerfConfig defaults, so a
            /// snapshot that does not populate them still describes a valid
            /// configuration (the Settings page validates what it is shown).
            uint32_t perf_workers = 8;
            uint32_t perf_max_conns = 4096;
            /// batch28: upstream dial timeout (ms); the advanced settings row
            /// for it needs the current value to show and validate.
            uint32_t perf_dial_timeout_ms = 10000;
            uint16_t web_port = 0;
            std::string web_bind;
            bool web_enabled = false;
            uint16_t vlan_id = 0;
            bool bridge_enabled = false;
            std::string bridge_up, bridge_down;
            uint32_t bridge_table_size = 0;
            std::string config_path;
            /// batch20: "auto" or a 25-step percent string (100..500).
            std::string ui_scale = "auto";
            /// batch22 A1: native appearance ("dark" default / "light"/"auto").
            std::string theme = "dark";
        };

        /// One published, immutable view of the whole runtime state.
        struct UiSnapshot {
            uint64_t seq = 0;       ///< strictly monotonic (publisher is the only writer)
            uint64_t rules_rev = 0; ///< web::RuleStore::Rev() sample (monotonic anchor)
            std::chrono::steady_clock::time_point published_at{};
            ConfigView config;
            bool dataplane_running = false;
            std::string dataplane_error;
            /// P2-9: the adapter the data plane actually bound (read-only).
            /// `bound` is false on failure, so the error text stays
            /// authoritative there.
            vgww::runtime::Dataplane::AdapterBinding adapter_binding;
            /// batch24 P2-9b: read-only inventory for the Settings picker.
            std::vector<vgww::runtime::Dataplane::AdapterInfo> adapters;
            bool driver_running = false;
            uint64_t uptime_s = 0;
            bool dhcp_active = false;
            bool dhcp6_active = false;
            /// batch33z: cumulative DHCPv4 faults. Both used to be counted
            /// and logged to stderr but never surfaced: a client silently
            /// got no address (pool full) or the lease file silently failed
            /// to persist (mappings lost on restart). Monotonic.
            uint64_t dhcp_pool_exhausted = 0;
            uint64_t dhcp_persist_failures = 0;
            Counters counters;

            vgww::runtime::Dataplane::Throughput throughput;
            vgww::runtime::Dataplane::SystemStats system;
            std::vector<vgww::runtime::Dataplane::ClientRate> clients;
            std::vector<vgww::runtime::Dataplane::LeaseView> leases;
            std::vector<vgww::runtime::Dataplane::Lease6View> leases6;
            std::vector<vgww::runtime::Dataplane::BindingView> dhcp_bindings;
            std::vector<vgww::runtime::Dataplane::Binding6View> dhcp6_bindings;
            /// batch129: these three are ZERO-COPY views over the store's
            /// immutable snapshots (the publisher just shares the buffer; no
            /// per-rule string copy per UI tick).
            vgww::web::RuleList<vgww::web::PortMappingRule> portmaps;
            /// batch34f: port-forwarding runtime health. A rule in the list
            /// does NOT imply an acceptor exists (bind can fail silently).
            vgww::runtime::Dataplane::PortmapStats portmap_stats;
            vgww::web::RuleList<vgww::web::BanEntry> bans;
            vgww::web::RuleList<vgww::web::RateLimitRule> ratelimits;
            vgww::bridge::BridgeState bridge_state = vgww::bridge::BridgeState::kStopped;
            /// batch34x: why the bridge last failed (empty otherwise). The
            /// banner used to say only "bridge failed"; the machine reason
            /// (port disappeared vs. driver read error) went to stderr only.
            std::string bridge_error;
            size_t bridge_mac_count = 0;
            /// batch34h: cumulative MAC-table evictions. A non-zero value means
            /// the bridge is at capacity and older devices keep losing their
            /// port mapping (their traffic floods until they speak again).
            uint64_t bridge_mac_evictions = 0;
            /// batch34i: neighbour learns refused by the flood guard. While
            /// saturated, new devices cannot resolve at all.
            uint64_t neighbor_rejections = 0;
            /// batch34j: capacity-boundary faults that used to be silent.
            uint64_t dhcp_rate_limit_resets = 0;
            uint64_t dhcp6_rate_limit_resets = 0;
            uint64_t udp_flow_evictions = 0;
        };

        /// Why a successfully bound adapter still cannot carry traffic.
        enum class AdapterIssue {
            None,
            LinkDown,          ///< OperStatus down or media disconnected
            NoIpv4,            ///< the NIC has no unicast IPv4 address
            GatewayOutsideSubnet,  ///< configured gateway is not on any of its subnets
        };

        inline bool AdapterLinkConnected(
            const vgww::runtime::Dataplane::AdapterBinding& binding) noexcept {
            return binding.is_up && binding.media_connected;
        }

        inline AdapterIssue AdapterBindingIssue(
            const vgww::runtime::Dataplane::AdapterBinding& binding) noexcept {
            if (!binding.bound) {
                return AdapterIssue::None;
            }
            if (!AdapterLinkConnected(binding)) {
                return AdapterIssue::LinkDown;
            }
            if (binding.ipv4.empty()) {
                return AdapterIssue::NoIpv4;
            }
            if (!binding.gateway_in_subnet) {
                return AdapterIssue::GatewayOutsideSubnet;
            }
            return AdapterIssue::None;
        }

        /// Data source interface (real implementation reads
        /// Dataplane/RuleStore; tests use a fake). Implementations must not
        /// throw: an escaping exception is contained by the publisher
        /// (logged; a failed full collect falls back to the empty snapshot
        /// and a failed stats tick keeps the light fields stale - the
        /// publish still happens with a monotonic seq) so the publisher
        /// thread always survives.
        class UiDataSource {
        public:
            virtual ~UiDataSource() = default;

            /// Immutable configuration copy.
            virtual ConfigView ConfigSnapshot() = 0;

            /// Collects one full snapshot. `seq`/`published_at` are hints
            /// only: the publisher overwrites both before publishing, so a
            /// source neither must nor can control them. batch52: returns a
            /// non-const pointer so the publisher can tag and publish the
            /// collected object directly (no second deep copy per status tick).
            virtual std::shared_ptr<UiSnapshot> Collect(uint64_t seq) = 0;

            /// Stats-tick hook (append-only extension): refresh the light
            /// fields (counters/throughput/system) on the copy of the last
            /// snapshot. The default keeps the snapshot unchanged.
            virtual void CollectStats(UiSnapshot& snapshot) { (void)snapshot; }
        };

        /// Single background publisher: 500 ms stats / 1 s full status.
        class SnapshotPublisher final {
        public:
            SnapshotPublisher(UiDataSource& source,
                              std::chrono::milliseconds stats_every = std::chrono::milliseconds(500),
                              std::chrono::milliseconds status_every = std::chrono::milliseconds(1000));
            ~SnapshotPublisher();

            SnapshotPublisher(const SnapshotPublisher&) = delete;
            SnapshotPublisher& operator=(const SnapshotPublisher&) = delete;

            /// Idempotent: a second Start returns false (error set).
            bool Start(std::string& error);
            /// Idempotent; bounded join (1 s). On timeout the thread is left
            /// alive (never detached: it touches `this`) and an error is logged.
            void Stop() noexcept;
            /// Atomic read; never returns null (a pre-built empty snapshot
            /// member with seq 0 before the first publish).
            std::shared_ptr<const UiSnapshot> Load() const noexcept;
            /// Wakes the publisher to collect early (e.g. right after a
            /// command ran); a new seq is published immediately on the wake;
            /// the UI observes it within one 200 ms snapshot-timer period
            /// (window.cpp:23).
            void RequestRefreshAfter(std::chrono::milliseconds delay);

        private:
            void Run();
            void Publish(bool full);

            UiDataSource& source_;
            std::chrono::milliseconds stats_every_;
            std::chrono::milliseconds status_every_;

            mutable std::mutex load_mutex_;  ///< guards published_
            std::shared_ptr<const UiSnapshot> published_;
            std::shared_ptr<const UiSnapshot> empty_;

            std::thread thread_;
            std::atomic<bool> running_{false};
            std::atomic<bool> stop_{false};
            std::atomic<bool> finished_{false};
            std::atomic<uint64_t> seq_{0};

            std::mutex wait_mutex_;
            std::condition_variable wait_cv_;
            std::atomic<bool> refresh_requested_{false};
            std::optional<std::chrono::steady_clock::time_point> refresh_at_;

            std::mutex finish_mutex_;
            std::condition_variable finish_cv_;
        };

        // ------------------------------------------------------------------
        // Commands (UI thread -> worker thread).
        // ------------------------------------------------------------------

        struct AddPortMapCmd {
            std::string proto;
            uint16_t wan_port = 0;
            std::string lan_ip;
            uint16_t lan_port = 0;
        };
        struct RemovePortMapCmd {
            /// batch138: stable identity from PortMappingRule::id. The row the
            /// user clicked is identified by WHERE it came from, not by its
            /// position in a list that other writers keep changing.
            uint64_t id = 0;
            /// Legacy positional handle (still accepted when `id` is 0, e.g. a
            /// hand-built test command).
            size_t index = 0;
        };
        struct AddBanCmd {
            std::string kind;
            std::string value;
        };
        struct RemoveBanCmd {
            /// batch138: stable identity (see RemovePortMapCmd::id).
            uint64_t id = 0;
            size_t index = 0;
        };
        struct SetRateLimitCmd {
            std::string mac;
            uint32_t up_kbps = 0;
            uint32_t down_kbps = 0;
            /// batch136: when non-empty, the rule keyed by this MAC is removed
            /// in the SAME command. Editing a rule's MAC used to post a
            /// RemoveRateLimitCmd followed by a SetRateLimitCmd; either could
            /// be refused on its own (queue full / cap reached), leaving the
            /// client with its old cap deleted and no new one stored. One
            /// command makes the re-key all-or-nothing.
            std::string replace_mac;
        };
        struct RemoveRateLimitCmd {
            std::string mac;
        };
        struct AddDhcpBindingCmd {
            std::string mac, ip, hostname;
            /// batch137: when non-empty, the binding keyed by this MAC is
            /// dropped in the SAME command. Editing a binding's MAC used to
            /// post a RemoveDhcpBindingCmd followed by an AddDhcpBindingCmd;
            /// either could be refused on its own (queue full / cap / address
            /// collision), leaving the client's binding deleted with nothing
            /// stored in its place. One command makes the re-key atomic.
            std::string replace_mac;
        };
        struct RemoveDhcpBindingCmd {
            std::string mac;
        };
        struct AddDhcp6BindingCmd {
            std::string duid, ip, hostname;
            /// batch137: v6 sibling of AddDhcpBindingCmd::replace_mac.
            std::string replace_duid;
        };
        struct RemoveDhcp6BindingCmd {
            std::string duid;
        };
        struct SaveConfigCmd {
            vgww::core::Config config;
            /// batch38: invoked by the command worker with the outcome of the
            /// save+apply so a Web-triggered save can report the true result
            /// (the POST response is async). Empty for native settings saves.
            std::function<void(bool, const std::string&)> result_sink;
            /// batch42: a native settings save wants the UI-thread outcome
            /// toast (success) or reason toast (apply failure). False for
            /// Web-triggered saves, whose receipt is the apply-status store.
            bool native_feedback = false;
        };
        struct SetAutostartCmd {
            bool enabled = false;
        };
        /// batch19 R4-P4: persist the native UI language code to the config.
        struct SetLanguageCmd {
            std::string code;
        };
        /// batch25a: one-click start/stop of the data plane from the
        /// dashboard. The UI process owns the Dataplane object, so the
        /// command worker can call its lifecycle directly (no process spawn).
        struct StartServiceCmd {};
        struct StopServiceCmd {};
        /// Rebind after the user reconnects the adapter: stop (when running)
        /// and start again, re-resolving the adapter hint and link state.
        struct RecheckServiceCmd {};

        using Command = std::variant<AddPortMapCmd, RemovePortMapCmd, AddBanCmd, RemoveBanCmd,
                                     SetRateLimitCmd, RemoveRateLimitCmd,
                                     AddDhcpBindingCmd, RemoveDhcpBindingCmd,
                                     AddDhcp6BindingCmd, RemoveDhcp6BindingCmd,
                                     SaveConfigCmd, SetAutostartCmd,
                                     SetLanguageCmd, StartServiceCmd,
                                     StopServiceCmd, RecheckServiceCmd>;

        struct CommandResult {
            bool ok = false;
            std::wstring message;
            /// batch42: set when this result is a native settings save. The UI
            /// thread must toast the true outcome (success, or the failure
            /// reason), not the optimistic "saved" the page used to show.
            bool save_config = false;
        };

        /// Real executor lives in T5 (controller.cpp).
        class CommandExecutor {
        public:
            virtual ~CommandExecutor() = default;
            /// Executes one command. Must not throw: an escaping exception is
            /// contained by the queue and reported as
            /// CommandResult{ok=false, "internal error"} - exactly one result
            /// per accepted command still holds.
            virtual CommandResult Execute(const Command& cmd) = 0;
        };

        /// Single worker thread, strict FIFO. Post is non-blocking; the
        /// queue holds at most 64 pending commands and Post returns false
        /// when it is full (the UI shows a "busy" toast). Every accepted
        /// command yields exactly one result; Stop drains the queue first.
        class CommandQueue final {
        public:
            CommandQueue(CommandExecutor& executor, SnapshotPublisher& publisher);
            ~CommandQueue();

            CommandQueue(const CommandQueue&) = delete;
            CommandQueue& operator=(const CommandQueue&) = delete;

            bool Start(std::string& error);
            void Stop() noexcept;
            bool Post(Command cmd);
            std::vector<CommandResult> DrainResults();  ///< UI poll, <= 16 per call
            size_t pending() const noexcept;            ///< test anchor

        private:
            void Run();

            CommandExecutor& executor_;
            SnapshotPublisher& publisher_;

            mutable std::mutex mutex_;
            std::condition_variable cv_;
            std::deque<Command> queue_;
            std::vector<CommandResult> results_;
            bool running_ = false;
            bool stop_ = false;

            std::thread thread_;
            std::atomic<bool> finished_{false};
            std::mutex finish_mutex_;
            std::condition_variable finish_cv_;
        };

    }  // namespace ui
}  // namespace vgww
