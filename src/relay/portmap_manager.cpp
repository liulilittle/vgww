// ============================================================================
// portmap_manager.cpp - Port-forwarding enforcement implementation.
// ============================================================================
#include "relay/portmap_manager.h"

#include <xtcp/core/stack.h>

#include <cstdio>

namespace vgww {
    namespace relay {

        namespace {
            // Backpressure bound for LAN->WAN data is the 64-packet queue
            // enforced in OnStackData (window 0 above it); each packet is at
            // most a link-frame worth of bytes, so memory stays bounded even
            // when the WAN socket stalls.

            int AsStateInt(xtcp::core::TcpState state) {
                return static_cast<int>(state);
            }

            std::atomic<size_t> g_live_accept_loops{0};

            /// Factory for instrumented accept loops: the custom deleter
            /// tracks lifetime so tests can assert the chain is fully freed.
            std::shared_ptr<std::function<void()>> MakeAcceptLoop() {
                std::function<void()>* loop = new std::function<void()>();
                g_live_accept_loops.fetch_add(1, std::memory_order_relaxed);
                return std::shared_ptr<std::function<void()>>(
                    loop,
                    [](std::function<void()>* fn) noexcept {
                        g_live_accept_loops.fetch_sub(
                            1, std::memory_order_relaxed);
                        delete fn;
                    });
            }
        }  // namespace

        PortMapManager& PortMapManager::Instance() noexcept {
            static PortMapManager manager;
            return manager;
        }

        size_t PortMapManager::LiveAcceptLoops() noexcept {
            return g_live_accept_loops.load(std::memory_order_relaxed);
        }

        void PortMapManager::Start(xtcp::XtcpStack* stack,
                                   const core::Config& config,
                                   LanSender send_to_lan,
                                   RelayTeardown teardown) {
            stack_ = stack;
            send_to_lan_ = std::move(send_to_lan);
            teardown_ = std::move(teardown);
            // Dotted quad of the virtual gateway (inet_addr numeric order).
            const uint32_t ip = config.gateway.ipv4;
            gateway_ip_text_ = std::to_string(ip & 0xFF) + "." +
                               std::to_string((ip >> 8) & 0xFF) + "." +
                               std::to_string((ip >> 16) & 0xFF) + "." +
                               std::to_string((ip >> 24) & 0xFF);

            // A restart must rebuild the acceptors even when the rule set
            // did not change: Stop() dropped them all (batch312).
            have_applied_rules_ = false;
            work_ = std::make_unique<WorkGuard>(io_.get_executor());
            running_.store(true);
            thread_ = std::thread([this] { RunLoop(); });
        }

        void PortMapManager::Stop() noexcept {
            if (!running_.exchange(false)) {
                return;
            }
            work_.reset();
            io_.stop();
            if (thread_.joinable()) {
                thread_.join();
            }
            // Cancel/close every WAN acceptor explicitly (pending
            // async_accept ops complete as aborted), then drop the relays.
            // Runs after the manager thread joined - no asio handler is
            // concurrent with this thread.
            for (auto& entry : acceptors_) {
                if (entry.second.acceptor) {
                    std::error_code ignored;
                    entry.second.acceptor->close(ignored);
                }
            }
            acceptors_.clear();
            relays_.clear();
            last_relay_conn_id_.store(0, std::memory_order_relaxed);
            {
                // Residual worker callbacks from the previous run must not
                // leak into the next one.
                std::lock_guard<std::mutex> lock(queue_mutex_);
                data_queue_.clear();
                state_queue_.clear();
            }
            // H4: io_context::stop() latches a terminated state; without
            // restart() every poll()/run_for() after the next Start returns
            // immediately and no completion is ever dispatched.
            io_.restart();
        }

        bool PortMapManager::OnStackData(uint64_t conn_id, const uint8_t* data,
                                         uint32_t len) {
            std::lock_guard<std::mutex> lock(queue_mutex_);
            // The queue bound is a HARD cap: over the limit the packet is
            // dropped (and counted) instead of being enqueued and only
            // REPORTED as overflow - a caller that ignored the return value
            // could otherwise grow the queue without bound.
            static constexpr size_t kMaxQueuedPackets = 64;
            // C6: check BEFORE enqueue. The old enqueue-then-test made the
            // 64th packet (already queued, queue now full) report false: the
            // stack applied window 0 and retransmitted a packet that WAS
            // accepted. Now the return value is the truth: true iff queued.
            if (data_queue_.size() >= kMaxQueuedPackets) {
                ++dropped_packets_;
                return false;   // window 0: the stack retransmits later
            }
            data_queue_.emplace_back(
                conn_id, core::PoolVector<uint8_t>(data, data + len));
            return true;
        }

        void PortMapManager::OnStackState(uint64_t conn_id, int state) {
            std::lock_guard<std::mutex> lock(queue_mutex_);
            state_queue_.emplace_back(conn_id, state);
        }

        void PortMapManager::RunLoop() {
            uint64_t tick = 0;
            while (running_.load()) {
                // 1. Poll the rule version. ApplyRules returns immediately
                //    unless the store version moved (or a failed bind is
                //    retried), so the poll frequency is not a cost
                //    multiplier (batch312).
                if (tick % 20 == 0) {
                    ApplyRules();
                }
                ++tick;

                // 2. Drain xtcp callbacks queued by workers.
                {
                    std::lock_guard<std::mutex> lock(queue_mutex_);
                    while (!state_queue_.empty()) {
                        auto [conn_id, state] = state_queue_.front();
                        state_queue_.pop_front();
                        const auto it = relays_.find(conn_id);
                        if (relays_.end() == it) continue;
                        // xtcp TcpState: kEstablished = 4; terminal states
                        // (kClosed = 0, kTimeWait = 10) tear the relay down.
                        if (state == 4) {
                            it->second.established = true;
                            PumpOne(conn_id, it->second);
                            ArmWanRead(conn_id, it->second);
                        } else if (state == 7) {
                            // kCloseWait: the WAN peer half-closed (its FIN
                            // reached the stack). Propagate the half-close:
                            // shut OUR send direction of the WAN socket so the
                            // peer's server drains then sees EOF; its replies
                            // still flow back through the receive pump. Runs
                            // on the manager thread that owns `io_` - the same
                            // thread that drives the wan socket - so asio
                            // needs no external synchronization.
                            const bool any =
                                nullptr != it->second.wan &&
                                it->second.wan->is_open();
                            if (any) {
                                std::error_code ignored;
                                it->second.wan->shutdown(
                                    asio::socket_base::shutdown_send, ignored);
                            }
                        } else if (state == 0 || state == 10) {
                            CloseRelay(conn_id, it->second);
                        }
                    }
                    while (!data_queue_.empty()) {
                        auto [conn_id, payload] = std::move(data_queue_.front());
                        data_queue_.pop_front();
                        const auto it = relays_.find(conn_id);
                        if (relays_.end() == it || !it->second.established) {
                            continue;
                        }
                        it->second.pending.emplace_back(std::move(payload));
                        PumpOne(conn_id, it->second);
                    }
                }

                // 3. Drive WAN-side async operations.
                io_.poll();
                io_.run_for(std::chrono::milliseconds(5));
                std::this_thread::sleep_for(std::chrono::microseconds(200));
            }
        }

        std::vector<uint16_t> PortMapManager::FailedPorts() const {
            std::lock_guard<std::mutex> lock(failed_ports_mutex_);
            return failed_ports_;
        }

        void PortMapManager::ApplyRules() {
            // batch312: the header contract is "rule changes are picked up by
            // polling the RuleStore version", but the body rebuilt the wanted
            // set, cleared failed_ports_ and re-scanned the acceptors on
            // EVERY RunLoop pass (~10/s) - allocating in proportion to the
            // rule count for the life of the process, exactly the pattern
            // batch146 removed from the data plane. Rev() is the store's
            // monotonic mutation anchor (bumped under the same lock that
            // publishes each snapshot), so "rev unchanged" proves "rules
            // unchanged".
            const uint64_t rev = web::RuleStore::Instance().Rev();
            if (have_applied_rules_ && rev == applied_rule_rev_) {
                // A failed bind IS retried on later passes even when the rule
                // set is unchanged: the WAN port may have been released by
                // another process. With no failures there is nothing to do.
                bool any_failed = false;
                {
                    std::lock_guard<std::mutex> lock(failed_ports_mutex_);
                    any_failed = !failed_ports_.empty();
                }
                if (!any_failed) {
                    return;
                }
            }
            have_applied_rules_ = true;
            applied_rule_rev_ = rev;
            ++stats_.apply_passes;
            // batch34e: recompute each pass so a port that became free (or a
            // removed rule) stops being reported.
            {
                std::lock_guard<std::mutex> lock(failed_ports_mutex_);
                failed_ports_.clear();
            }
            const auto rules = web::RuleStore::Instance().PortMaps();
            std::map<std::string, bool> wanted;
            for (const auto& rule : rules) {
                // UDP port-forwarding is NOT implemented yet (full-cone state
                // for the return path is a separate project). Silently binding
                // a TCP acceptor for a "udp" rule would both fake a feature
                // and squat the WAN port - skip it and let the mismatch be
                // visible rather than plausible-but-broken.
                if ("tcp" != rule.proto) {
                    continue;
                }
                const std::string key = rule.proto + ":" + std::to_string(rule.wan_port);
                wanted[key] = true;
                if (acceptors_.find(key) != acceptors_.end()) {
                    continue;
                }
                // Create a new acceptor for this rule.
                auto acceptor = std::make_shared<asio::ip::tcp::acceptor>(io_);
                asio::ip::tcp::endpoint endpoint(
                    asio::ip::make_address("0.0.0.0"), rule.wan_port);
                std::error_code err;
                acceptor->open(endpoint.protocol(), err);
                if (!err) {
                    acceptor->set_option(asio::socket_base::reuse_address(true), err);
                }
                if (!err) acceptor->bind(endpoint, err);
                // batch34l P0: an acceptor that is only open()+bind()ed is
                // NOT listening - accept(2) is refused and every WAN
                // connection is dropped. asio's async_accept does not
                // listen for you (start_accept_op goes straight to
                // AcceptEx), so the listen() call is mandatory here.
                if (!err) {
                    acceptor->listen(asio::socket_base::max_listen_connections,
                                      err);
                }
                if (err) {
                    // batch34e: the rule stays in RuleStore (the UI keeps
                    // showing it) but NO acceptor exists, so nothing is ever
                    // forwarded. Count it, log it, and remember the port so
                    // the surface can name it instead of failing silently.
                    ++stats_.bind_failed;
                    {
                        std::lock_guard<std::mutex> lock(failed_ports_mutex_);
                        failed_ports_.push_back(rule.wan_port);
                        constexpr size_t kMaxFailedPorts = 32;
                        if (failed_ports_.size() > kMaxFailedPorts) {
                            failed_ports_.erase(failed_ports_.begin());
                        }
                    }
                    std::fprintf(stderr,
                                 "[portmap] WAN port %u could not be opened "
                                 "(%s) - rule inactive\n",
                                 static_cast<unsigned>(rule.wan_port),
                                 err.message().c_str());
                    acceptor->close(err);
                    continue;
                }
                // Accept loop for this rule. H4: the loop lambda captures
                // only a WEAK ref to itself; the strong owner is
                // acceptors_[key].loop (erased with the rule), so the chain
                // can never form a reference cycle. A transient accept error
                // re-arms while the acceptor is open and running_.
                auto rule_copy = rule;
                std::weak_ptr<asio::ip::tcp::acceptor> weak = acceptor;
                auto loop = MakeAcceptLoop();
                std::weak_ptr<std::function<void()>> weak_loop = loop;
                *loop = [this, weak, rule_copy, weak_loop]() {
                    auto accepted =
                        std::make_shared<asio::ip::tcp::socket>(io_);
                    auto strong = weak.lock();
                    if (!strong || !running_.load()) {
                        return;
                    }
                    strong->async_accept(
                        *accepted,
                        [this, weak, rule_copy, accepted,
                         weak_loop](const std::error_code& err) {
                            if (err || !running_.load()) {
                                if (err) {
                                    ++stats_.accept_errors;
                                }
                                auto live = weak.lock();
                                if (live && live->is_open() &&
                                    running_.load()) {
                                    if (auto retry = weak_loop.lock()) {
                                        (*retry)();
                                    }
                                }
                                return;
                            }
                            if (auto live = weak.lock()) {
                                // Dial the LAN client through the xtcp stack:
                                // local = gateway virtual IP : ephemeral port.
                                xtcp::core::Endpoint local{};
                                local.family = 4;
                                local.port = 0;  // ephemeral
                                local.addr[0] = 0;  // filled below
                                // batch86: sscanf_s reports how many fields it
                                // actually converted, and the old code ignored
                                // that return. A short parse leaves the
                                // zero-initialised octets in place, so the dial
                                // would silently target 0.0.0.0 instead of
                                // failing - a plausible-but-broken endpoint.
                                // Every current producer (POST /api/portmap, the
                                // native form, and the rules-file loader) runs
                                // ParseIpv4 first, so this is a redundancy; it is
                                // written down because the failure mode is a
                                // wrong ADDRESS, not an error, and a fourth
                                // producer would inherit it silently.
                                {
                                    unsigned a[4] = {0, 0, 0, 0};
                                    const int got = sscanf_s(
                                        gateway_ip_text_.c_str(),
                                        "%u.%u.%u.%u", &a[0], &a[1], &a[2],
                                        &a[3]);
                                    if (4 != got) {
                                        // Reject the relay instead of dialing a
                                        // zero endpoint. Counted so the surface
                                        // can see it rather than dropping mute.
                                        std::error_code ignored;
                                        accepted->close(ignored);
                                        ++stats_.dial_failed;
                                        if (auto retry = weak_loop.lock()) {
                                            (*retry)();
                                        }
                                        return;
                                    }
                                    local.addr[0] = (a[0] << 24) |
                                                    (a[1] << 16) |
                                                    (a[2] << 8) | a[3];
                                }
                                xtcp::core::Endpoint remote{};
                                remote.family = 4;
                                {
                                    unsigned a[4] = {0, 0, 0, 0};
                                    const int got = sscanf_s(
                                        rule_copy.lan_ip.c_str(),
                                        "%u.%u.%u.%u", &a[0], &a[1], &a[2],
                                        &a[3]);
                                    if (4 != got) {
                                        std::error_code ignored;
                                        accepted->close(ignored);
                                        ++stats_.dial_failed;
                                        if (auto retry = weak_loop.lock()) {
                                            (*retry)();
                                        }
                                        return;
                                    }
                                    remote.addr[0] = (a[0] << 24) |
                                                     (a[1] << 16) |
                                                     (a[2] << 8) | a[3];
                                }
                                remote.port = rule_copy.lan_port;
                                const uint64_t conn_id =
                                    stack_->Connect(local, remote);
                                if (0 != conn_id) {
                                    Relay relay;
                                    relay.wan = accepted;
                                    relays_[conn_id] = std::move(relay);
                                    last_relay_conn_id_.store(
                                        conn_id, std::memory_order_relaxed);
                                    ++stats_.accepted;
                                } else {
                                    // Stack refused the reverse-NAT dial
                                    // (cap reached / bad endpoint): do not
                                    // leak the accepted WAN socket.
                                    std::error_code ignored;
                                    accepted->close(ignored);
                                    ++stats_.dial_failed;
                                }
                            }
                            if (auto retry = weak_loop.lock()) {
                                (*retry)();  // continue accepting
                            }
                        });
                };
                (*loop)();
                acceptors_[key] = {acceptor, rule, loop};
            }

            // Remove acceptors whose rules disappeared.
            for (auto it = acceptors_.begin(); it != acceptors_.end();) {
                if (wanted.find(it->first) == wanted.end()) {
                    std::error_code ignored;
                    it->second.acceptor->close(ignored);
                    it = acceptors_.erase(it);
                } else {
                    ++it;
                }
            }
        }

        void PortMapManager::PumpOne(uint64_t conn_id, Relay& relay) {
            if (relay.closed || relay.pending.empty() || relay.write_in_flight) {
                return;
            }
            if (!relay.wan || !relay.wan->is_open()) {
                CloseRelay(conn_id, relay);
                return;
            }
            auto& chunk = relay.pending.front();
            auto buffer = std::make_shared<core::PoolVector<uint8_t>>(std::move(chunk));
            relay.pending.pop_front();
            // C1: one composed async_write at a time per socket (asio forbids
            // concurrent composed ops on the same socket). While a write is
            // in flight the rest of the queue waits in `pending`; the write
            // completion pumps the next chunk, preserving FIFO order.
            relay.write_in_flight = true;
            const uint64_t inflight =
                stats_.wan_writes_outstanding.fetch_add(
                    1, std::memory_order_relaxed) + 1;
            uint64_t peak = stats_.wan_write_peak.load(std::memory_order_relaxed);
            while (peak < inflight &&
                   !stats_.wan_write_peak.compare_exchange_weak(
                       peak, inflight, std::memory_order_relaxed)) {
            }
            // Strong ref for asio: the callback reads through *relay.wan, and
            // a CloseRelay (state teardown or LAN RST) may erase relays_ while
            // this op is pending - without the capture, the socket dies under
            // the outstanding async_write and asio touches freed memory.
            auto socket = relay.wan;
            asio::async_write(
                *relay.wan, asio::buffer(*buffer),
                [this, conn_id, buffer, socket](const std::error_code& err,
                                                size_t) {
                    buffer->clear();
                    stats_.wan_writes_outstanding.fetch_sub(
                        1, std::memory_order_relaxed);
                    const auto it = relays_.find(conn_id);
                    if (relays_.end() == it) return;
                    it->second.write_in_flight = false;
                    if (err) {
                        CloseRelay(conn_id, it->second);
                        return;
                    }
                    PumpOne(conn_id, it->second);  // drain remaining queue
                });
        }

        void PortMapManager::ArmWanRead(uint64_t conn_id, Relay& relay) {
            if (relay.wan_read_armed || !relay.wan || !relay.wan->is_open()) {
                return;
            }
            relay.wan_read_armed = true;
            auto buffer = std::make_shared<core::PoolVector<uint8_t>>(16384);
            // Strong ref for asio (same lifetime argument as PumpOne): the
            // read completion touches the socket object, and CloseRelay can
            // erase relays_ while this op is pending.
            auto socket = relay.wan;
            relay.wan->async_read_some(
                asio::buffer(*buffer),
                [this, conn_id, buffer, socket](const std::error_code& err,
                                                size_t n) {
                    if (err || 0 == n) {
                        // WAN peer closed: tear the whole relay down.
                        const auto it = relays_.find(conn_id);
                        if (relays_.end() != it) {
                            CloseRelay(conn_id, it->second);
                        }
                        return;
                    }
                    // Forward toward the LAN client through the injected
                    // hook (the manager thread cannot call the stack
                    // directly - no worker context on the emit path).
                    // C5: a FALSE return means the WAN->LAN queue is full
                    // (data plane side) - PAUSE the receive chain hard: the
                    // read stays "armed" (so nothing re-arms) until the
                    // queue drains and the data plane signals
                    // ResumePausedWanReads(). A fast WAN can therefore never
                    // fill the send queue without bound.
                    if (send_to_lan_ &&
                        !send_to_lan_(conn_id, buffer->data(),
                                      static_cast<uint32_t>(n))) {
                        const auto it = relays_.find(conn_id);
                        if (relays_.end() == it) {
                            return;
                        }
                        it->second.wan_read_paused = true;
                        return;  // wan_read_armed stays true: hard pause
                    }
                    const auto it = relays_.find(conn_id);
                    if (relays_.end() == it || it->second.closed) {
                        return;
                    }
                    if (!socket->is_open()) return;
                    it->second.wan_read_armed = false;
                    it->second.wan_read_paused = false;
                    ArmWanRead(conn_id, it->second);  // continuous read loop
                });
        }

        void PortMapManager::ResumePausedWanReads() noexcept {
            if (!running_.load()) {
                return;
            }
            asio::post(io_, [this] {
                for (auto& kv : relays_) {
                    Relay& r = kv.second;
                    if (r.wan_read_paused) {
                        r.wan_read_paused = false;
                        r.wan_read_armed = false;
                        ArmWanRead(kv.first, r);
                    }
                }
            });
        }

        void PortMapManager::CloseRelay(uint64_t conn_id, Relay& relay) {
            relay.closed = true;
            if (relay.wan) {
                std::error_code ignored;
                relay.wan->close(ignored);
            }
            // RST the LAN client side. Must NOT call stack_->Abort here: the
            // manager thread has no TX ring, so the emitted reset would be
            // dropped (kNoRing) and the client would hang forever waiting for
            // a WAN-side close. Route it through the owning worker instead.
            if (teardown_) {
                teardown_(conn_id, false);
            }
            relays_.erase(conn_id);
        }

    }  // namespace relay
}  // namespace vgww
