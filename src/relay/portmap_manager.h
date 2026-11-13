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
#include "core/handler_guard.h"
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
#include <set>
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
                /// Completion bodies whose exception was swallowed by the
                /// firewall: that one connection was dropped, while the
                /// manager thread and the accept chain survive.
                std::atomic<uint64_t> handler_errors{0};
                /// Exceptions that escaped a completion handler out of
                /// io_context::run_for(). Must stay 0 - unwinding through
                /// asio's dispatch frame is undefined behaviour.
                std::atomic<uint64_t> escaped_handler_errors{0};
                /// Manager-thread iteration bodies that threw and were
                /// swallowed by the thread-body firewall: that pass was lost
                /// (rules/queue work retried next pass), the thread survived.
                /// Distinct from handler_errors (per-connection completions).
                std::atomic<uint64_t> loop_errors{0};
                /// Accept re-arms whose socket/accept allocation threw and was
                /// swallowed: the rule cannot re-arm (deaf until the rule set
                /// changes), but the manager thread survives.
                std::atomic<uint64_t> rearm_errors{0};
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

            /// Test seam: runs inside the accept completion body before the
            /// WAN socket is dialed. Throwing here proves the firewall holds
            /// and that the accept chain still re-arms.
            void SetAcceptProbeForTest(std::function<void()> probe) {
                accept_probe_ = std::move(probe);
            }

            /// Test seam: runs at the top of every manager-thread iteration,
            /// before the rule poll. Throwing here proves the thread-body
            /// firewall holds and the loop keeps running.
            void SetLoopProbeForTest(std::function<void()> probe) {
                loop_probe_ = std::move(probe);
            }

            /// Test seam: runs inside the guarded accept RE-ARM; throwing
            /// proves an arm failure cannot crash the manager thread.
            void SetAcceptRearmProbeForTest(std::function<void()> probe) {
                accept_rearm_probe_ = std::move(probe);
            }

            // ----- xtcp callbacks (worker threads, shard lock held) ----------
            /// Returns true when the data was queued for a known relay;
            /// false tells the stack to apply backpressure (window 0).
            bool OnStackData(uint64_t conn_id, const uint8_t* data, uint32_t len);
            /// Tracks connection lifecycle (established/closed/reset).
            void OnStackState(uint64_t conn_id, int state);

            /// Test/telemetry seam: current number of pending state events.
            /// Read-only observation of the state queue (guarded by the same
            /// mutex as OnStackState), used to assert dedup and the hard cap.
            size_t StateQueueDepth() {
                std::lock_guard<std::mutex> lock(queue_mutex_);
                return state_queue_.size();
            }

            /// Packets dropped because the send queue hit its hard cap
            /// (monotonic; exposed for diagnostics/tests).
            uint64_t DroppedPackets() const noexcept {
                return dropped_packets_.load(std::memory_order_relaxed);
            }

            /// P1: hard byte bound for ONE relay's LAN->WAN write queue. The
            /// transient 64-packet `data_queue_` bound above never applies to
            /// `Relay::pending`: RunLoop drains it on every pass, so its
            /// overflow branch can never fire while the WAN peer stalls and the
            /// per-relay queue grew without bound (OOM by a remote peer that
            /// simply stops reading). Over this cap a packet is dropped and
            /// counted instead. 256 KiB ~= 170 full-size frames: enough to ride
            /// out a normal receive-window stall without pinning memory.
            static constexpr size_t kMaxPendingBytes = 256 * 1024;

            /// Test/telemetry: the per-relay bound above.
            static constexpr size_t MaxPendingBytes() noexcept {
                return kMaxPendingBytes;
            }

            /// Test/telemetry: largest byte count ever queued in a single
            /// relay's `pending` (relaxed reads; monotonic peak).
            uint64_t PeakPendingBytes() const noexcept {
                return peak_pending_bytes_.load(std::memory_order_relaxed);
            }

            /// W11 D2: FIN-era retransmissions dropped after shutdown(SD_SEND)
            /// instead of being written to the shut WAN socket.
            uint64_t LateAfterFinDropped() const noexcept {
                return late_after_fin_dropped_.load(
                    std::memory_order_relaxed);
            }

            /// Packets dropped because a relay's `pending` reached
            /// kMaxPendingBytes (monotonic). Deliberately NOT added to the
            /// /api/status portmap_health object: its key set is a contract the
            /// dashboard reads, and this is an internal bound, not a health
            /// signal the UI acts on.
            uint64_t PendingDroppedPackets() const noexcept {
                return pending_dropped_.load(std::memory_order_relaxed);
            }

        private:
            PortMapManager() = default;

            struct Relay {
                std::shared_ptr<asio::ip::tcp::socket> wan;
                std::deque<core::PoolVector<uint8_t>> pending;  // lan -> wan
                /// P1: bytes currently queued in `pending`. Kept incrementally
                /// (emplace/pop paths only) so the bound check is O(1) rather
                /// than summing the deque per packet.
                size_t pending_bytes = 0;
                bool established = false;
                bool closed = false;
                bool wan_read_armed = false;
                /// C1: at most one composed async_write in flight per socket
                /// (asio forbids concurrent composed ops on one socket).
                bool write_in_flight = false;
                /// C5: WAN->LAN backpressure - the receive chain is paused
                /// until RunLoop's resume probe re-arms it.
                bool wan_read_paused = false;
                /// W11 D2: set once shutdown(SD_SEND) has been issued after a
                /// LAN half-close. Data arriving after this point is a FIN-era
                /// retransmission and must not be written to the shut socket.
                bool wan_send_shutdown = false;
            };

            void RunLoop();
            void ApplyRules();
            void PumpOne(uint64_t conn_id, Relay& relay);
            void ArmWanRead(uint64_t conn_id, Relay& relay);
            void CloseRelay(uint64_t conn_id, Relay& relay, bool graceful);

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
            /// W11 D3: last enqueued state per conn_id. The stack invokes the
            /// state handler for EVERY routed packet, so without this guard a
            /// steady stream of identical states would grow state_queue_
            /// without bound and serialize the workers on queue_mutex_.
            std::map<uint64_t, int> last_state_;
            /// W11 D2: LAN half-close intents, keyed by conn_id. Kept OUTSIDE
            /// state_queue_ so a saturated queue (kMaxQueuedStates) or the
            /// (conn_id,state) dedup can never swallow a FIN intent. Guarded
            /// by queue_mutex_ (inserted from worker callbacks, drained by the
            /// manager thread); the manager thread also erases entries lazily
            /// when the owning relay disappears.
            std::set<uint64_t> half_close_ids_;

            /// batch312: the RuleStore version the current acceptors were
            /// built from (manager thread only - no atomic needed).
            uint64_t applied_rule_rev_ = 0;
            bool have_applied_rules_ = false;
            std::atomic<uint64_t> dropped_packets_{0};
            /// P1: per-relay pending cap refusals and the observed peak queue
            /// depth (internal counters; see the accessors above).
            std::atomic<uint64_t> pending_dropped_{0};
            std::atomic<uint64_t> peak_pending_bytes_{0};
            std::atomic<uint64_t> last_relay_conn_id_{0};
            /// W11 D2: FIN-era retransmissions dropped after shutdown(SD_SEND)
            /// instead of being written to the shut WAN socket.
            std::atomic<uint64_t> late_after_fin_dropped_{0};
            std::function<void()> accept_probe_;
            std::function<void()> loop_probe_;
            std::function<void()> accept_rearm_probe_;
        };

    }  // namespace relay
}  // namespace vgww
