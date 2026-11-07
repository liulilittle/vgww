// ============================================================================
// portmap_manager.h - Enforcement engine for WebUI port-forwarding rules.
//
// Model (standard router NAT semantics): an inbound connection accepted on
// the HOST (WAN side) is paired with a reverse TCP connection dialed from
// the gateway into the LAN client via the xtcp stack. The client sees the
// connection as coming from the gateway; the WAN peer sees the host port.
//
// Threading:
//   * The manager owns one io_context + thread for WAN-side sockets and
//     acceptors. Rule changes are picked up by polling the RuleStore
//     version: ApplyRules rebuilds only when that version moved (a failed
//     bind is still retried on later passes), so an unchanged rule set costs
//     one atomic read per poll.
//   * xtcp callbacks (recv/state) fire on WORKER threads under the shard
//     lock: they only enqueue into small mutex-guarded queues that this
//     thread drains. No blocking, no stack re-entry.
//
// Backpressure: if the WAN-side write queue for a relay exceeds a bound,
// RecvHandlerChecked returns false -> xtcp window 0 -> LAN client slows.
// ============================================================================
#pragma once

#include "core/allocator.h"
#include "core/config.h"
#include "web/web_api.h"

#include <asio.hpp>

#include <atomic>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace xtcp {
    class XtcpStack;
}

namespace vgww {
    namespace relay {

        class PortMapManager final {
        public:
            static PortMapManager& Instance() noexcept;

            /// Send hook: queues `data` for delivery to the LAN client over
            /// the xtcp connection. Injected by the data plane because the
            /// stack's emit path is only legal on a worker thread (the
            /// manager thread has no worker context).
            using LanSender = std::function<bool(uint64_t conn_id,
                                                 const uint8_t* data,
                                                 uint32_t len)>;
            /// Teardown hook: tears down an xtcp connection from the manager
            /// thread. Injected by the data plane: the stack's emit path
            /// (RST/FIN) is only legal on a worker thread with a TX ring, so
            /// the request is queued to the shard-owning worker instead of
            /// calling stack->Abort/Close here (which would silently drop the
            /// reset on kNoRing).
            using RelayTeardown = std::function<void(uint64_t conn_id,
                                                     bool graceful)>;
            /// Starts the manager thread and applies current rules.
            void Start(xtcp::XtcpStack* stack, const core::Config& config,
                       LanSender send_to_lan, RelayTeardown teardown);

            /// Stops acceptors and tears down all relays.
            void Stop() noexcept;

            /// Lifecycle counters (manager thread writes; atomic reads from
            /// tests/UI). `accepted` counts WAN accepts successfully paired
            /// with a LAN dial through the stack.
            struct Stats {
                std::atomic<uint64_t> accepted{0};
                std::atomic<uint64_t> dial_failed{0};
                std::atomic<uint64_t> accept_errors{0};
                /// batch34e: rules whose WAN port could not be opened/bound/
                /// listened (port already in use, permission denied, ...). The
                /// rule still exists in RuleStore and the UI shows it, but no
                /// traffic is ever forwarded - this used to be a bare
                /// continue with no counter, no log and no UI surface.
                std::atomic<uint64_t> bind_failed{0};
                /// C1: peak number of concurrent WAN async_write ops (manager
                /// thread writes; relaxed reads). ~=1 asserts the gate holds.
                std::atomic<uint64_t> wan_write_peak{0};
                std::atomic<uint64_t> wan_writes_outstanding{0};
                /// batch312: full ApplyRules rebuilds (the RuleStore version
                /// moved, or a failed bind is being retried). An idle manager
                /// must not move this counter - the old code rebuilt the
                /// wanted set on every RunLoop pass.
                std::atomic<uint64_t> apply_passes{0};
            };
            const Stats& GetStats() const noexcept { return stats_; }

            /// batch34e: WAN ports that failed to bind, newest last. Lets the
            /// UI name the exact port instead of showing a bare count.
            std::vector<uint16_t> FailedPorts() const;

            /// Test/telemetry seam: accept-loop objects still alive. A
            /// self-referencing (broken) loop chain never returns to zero;
            /// the weak-self design frees every loop as soon as its
            /// AcceptorEntry is erased (rule removed or Stop()).
            static size_t LiveAcceptLoops() noexcept;

            /// Test/telemetry: whether the manager thread is running
            /// (false after Start's catch-block rollback / Stop).
            bool IsRunning() const noexcept { return running_.load(); }

            /// Test seam: conn_id of the most recently accepted relay
            /// (0 when none) so tests can drive OnStackData/OnStackState.
            uint64_t LastRelayConnId() const noexcept {
                return last_relay_conn_id_.load(std::memory_order_relaxed);
            }

            /// C5: asks the manager to resume WAN receive chains that were
            /// paused by a false LanSender return (WAN->LAN queue drain
            /// signal; safe from any thread - the work is posted onto the
            /// manager's own io_context).
            void ResumePausedWanReads() noexcept;

            // ----- xtcp callbacks (worker threads, shard lock held) ----------
            /// Returns true when the data was queued for a known relay;
            /// false tells the stack to apply backpressure (window 0).
            bool OnStackData(uint64_t conn_id, const uint8_t* data, uint32_t len);
            /// Tracks connection lifecycle (established/closed/reset).
            void OnStackState(uint64_t conn_id, int state);

            /// Packets dropped because the send queue hit its hard cap
            /// (monotonic; exposed for diagnostics/tests).
            uint64_t DroppedPackets() const noexcept {
                return dropped_packets_.load(std::memory_order_relaxed);
            }

        private:
            PortMapManager() = default;

            struct Relay {
                std::shared_ptr<asio::ip::tcp::socket> wan;
                std::deque<core::PoolVector<uint8_t>> pending;  // lan -> wan
                bool established = false;
                bool closed = false;
                bool wan_read_armed = false;
                /// C1: at most one composed async_write in flight per socket
                /// (asio forbids concurrent composed ops on one socket).
                bool write_in_flight = false;
                /// C5: WAN->LAN backpressure - the receive chain is paused
                /// until RunLoop's resume probe re-arms it.
                bool wan_read_paused = false;
            };

            void RunLoop();
            void ApplyRules();
            void PumpOne(uint64_t conn_id, Relay& relay);
            void ArmWanRead(uint64_t conn_id, Relay& relay);
            void CloseRelay(uint64_t conn_id, Relay& relay);

            LanSender send_to_lan_;
            RelayTeardown teardown_;

            std::atomic<bool> running_{false};
            std::thread thread_;
            asio::io_context io_;
            using WorkGuard = asio::executor_work_guard<asio::io_context::executor_type>;
            std::unique_ptr<WorkGuard> work_;

            xtcp::XtcpStack* stack_ = nullptr;
            std::string gateway_ip_text_;  // dotted quad of the virtual GW

            // Acceptors keyed by "proto:wan_port".
            struct AcceptorEntry {
                std::shared_ptr<asio::ip::tcp::acceptor> acceptor;
                web::PortMappingRule rule;
                /// Strong ref anchoring the accept loop (H4). The loop's own
                /// lambda captures only a weak_ptr to itself, so this entry
                /// is the single owner: erasing it (rule removed or Stop())
                /// ends the chain with no cycle to leak.
                std::shared_ptr<std::function<void()>> loop;
            };
            std::map<std::string, AcceptorEntry> acceptors_;

            // conn_id -> relay state (manager thread only).
            std::map<uint64_t, Relay> relays_;

            // Queues fed from worker threads.
            Stats stats_;
            /// batch34e: WAN ports whose bind/listen failed (guarded; written
            /// by the manager thread, read by the status surface).
            mutable std::mutex failed_ports_mutex_;
            std::vector<uint16_t> failed_ports_;
            std::mutex queue_mutex_;
            std::deque<std::pair<uint64_t, core::PoolVector<uint8_t>>> data_queue_;
            std::deque<std::pair<uint64_t, int>> state_queue_;

            /// batch312: the RuleStore version the current acceptors were
            /// built from (manager thread only - no atomic needed).
            uint64_t applied_rule_rev_ = 0;
            bool have_applied_rules_ = false;
            std::atomic<uint64_t> dropped_packets_{0};
            std::atomic<uint64_t> last_relay_conn_id_{0};
        };

    }  // namespace relay
}  // namespace vgww
