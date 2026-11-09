// ============================================================================
// tcp_relay.cpp - Bidirectional pump implementation.
//
// Return-code contract (mimt.h): AsyncRead/AsyncWrite return synchronously
// when NO completion will ever fire - kClosed (flow gone) / kInvalid. Those
// must tear the relay down immediately, otherwise both pumps strand and the
// relay leaks in the registry forever. Transient congestion is different:
// kInFlight (sync, write queue full) and kWouldBlock (async completion, sink
// window full) mean "retry the same bytes later" - treating them as fatal
// used to RST every slow client mid-transfer.
//
// Teardown semantics: an upstream EOF (asio::error::eof) is a CLEAN end -
// the owner CLOSES the xtcp connection so the client receives a FIN. Every
// other error path aborts (RST). Flow-side kClosed means the client already
// reset: no FIN is needed.
// ============================================================================
#include "relay/tcp_relay.h"

#include <chrono>

namespace vgww {
    namespace relay {

        namespace {
            bool IsEof(const std::error_code& err) noexcept {
                return asio::error::eof == err;
            }
        }  // namespace

        TcpRelay::TcpRelay(std::shared_ptr<xtcp::mimt::MimtFlow> flow,
                           asio::ip::tcp::socket socket, Hooks hooks)
            : flow_(std::move(flow)),
              socket_(std::move(socket)),
              hooks_(std::move(hooks)) {}

        void TcpRelay::Start() {
            if (!RunCompletion([this] { PumpFlowToSocket(); })) {
                return;  // the read pump could not be armed: relay torn down
            }
            RunCompletion([this] { PumpSocketToFlow(); });
        }

        void TcpRelay::PumpFlowToSocket() {
            // Self-keepalive: the pump chain owns the relay.
            auto self = shared_from_this();
            const xtcp::mimt::Result r = flow_->AsyncRead(
                down_buf_.data(), static_cast<UInt32>(down_buf_.size()),
                [self](xtcp::mimt::Result ec, UInt32 n) {
                    self->RunCompletion([&] {
                        if (xtcp::mimt::Result::kOk != ec || 0 == n) {
                            // Client side closed/reset - nothing to FIN.
                            self->Finish(false);
                            return;
                        }
                        asio::async_write(
                            self->socket_,
                            asio::buffer(self->down_buf_.data(), n),
                            [self](const std::error_code& err, size_t) {
                                self->RunCompletion([&] {
                                    if (err) {
                                        self->Finish(IsEof(err));
                                        return;
                                    }
                                    self->PumpFlowToSocket();
                                });
                            });
                    });
                });
            if (xtcp::mimt::Result::kOk != r) {
                // Synchronous refusal: no completion was queued, so without
                // this check both pumps strand and the relay leaks forever.
                FinishFromFlow();
            }
        }

        void TcpRelay::PumpSocketToFlow() {
            auto self = shared_from_this();
            socket_.async_read_some(
                asio::buffer(up_buf_.data(), up_buf_.size()),
                [self](const std::error_code& err, size_t n) {
                    self->RunCompletion([&] {
                        if (err) {
                            // Upstream EOF is a clean end: the owner must CLOSE
                            // (FIN) the client connection, not RST it.
                            self->Finish(IsEof(err));
                            return;
                        }
                        self->WriteToFlow(static_cast<UInt32>(n));
                    });
                });
        }

        void TcpRelay::WriteToFlow(UInt32 len) {
            pending_up_len_ = len;
            auto self = shared_from_this();
            const xtcp::mimt::Result r = flow_->AsyncWrite(
                up_buf_.data(), len,
                [self](xtcp::mimt::Result ec, UInt32) {
                    self->RunCompletion([&] {
                        if (xtcp::mimt::Result::kWouldBlock == ec) {
                            // Sink window full (client reading slowly): transient.
                            // Hold the chunk for retry and keep the socket read
                            // PAUSED so a new arrival cannot overwrite the
                            // buffer underneath the bytes we still owe the flow.
                            self->retry_pending_ = true;
                            self->RetryPendingWrite();
                            return;
                        }
                        if (xtcp::mimt::Result::kOk != ec) {
                            self->Finish(false);  // client side gone
                            return;
                        }
                        // This write drained. If an earlier chunk is still held
                        // for retry (the flow was full when it arrived), reissue
                        // it NOW that the queue has slack - the socket read has
                        // stayed paused, so up_buf_ still holds those bytes.
                        // Waiting out the 20 ms backoff would risk a new read
                        // overwriting the buffer and losing the chunk, then
                        // duplicating the newer bytes in its place.
                        if (self->retry_pending_) {
                            self->retry_pending_ = false;
                            self->WriteToFlow(self->pending_up_len_);
                        } else {
                            self->PumpSocketToFlow();
                        }
                    });
                });
            if (xtcp::mimt::Result::kOk != r) {
                if (xtcp::mimt::Result::kInFlight == r) {
                    // Write queue full: hold the chunk, back off, and
                    // reissue once the queue drains (see the kOk branch).
                    retry_pending_ = true;
                    RetryPendingWrite();
                } else {
                    // kClosed/kInvalid: no completion was queued.
                    FinishFromFlow();
                }
            }
        }

        void TcpRelay::RetryPendingWrite() {
            auto self = shared_from_this();
            write_retry_timer_.expires_after(std::chrono::milliseconds(20));
            write_retry_timer_.async_wait(
                [this, self](const std::error_code& err) {
                    self->RunCompletion([&] {
                        // The kOk-drain path may already have reissued the held
                        // chunk; only retry while it is still outstanding and
                        // never reissue twice.
                        if (!err && !self->finished_ && self->retry_pending_) {
                            self->retry_pending_ = false;
                            self->WriteToFlow(self->pending_up_len_);
                        }
                    });
                });
        }

        void TcpRelay::OnPeerFin() {
            if (finished_) {
                return;  // already torn down: nothing left to half-close
            }
            // Propagate the half-close: our send direction (upstream) goes
            // down so the server sees EOF once it drains our data, while the
            // receive direction (its replies) keeps flowing back to the
            // client. asio shutdown_send does NOT abort a write already in
            // flight and flushes queued bytes before emitting FIN, so no
            // payload is lost here. The reply pump (server -> client) is the
            // receive direction and is unaffected.
            std::error_code ignored;
            socket_.shutdown(asio::socket_base::shutdown_send, ignored);
        }

        void TcpRelay::Finish(bool graceful) {
            if (finished_) {
                return;  // exactly-once teardown
            }
            finished_ = true;
            write_retry_timer_.cancel();
            std::error_code ignored;
            socket_.close(ignored);
            if (hooks_.on_finished) {
                hooks_.on_finished(flow_->ConnId(), graceful);
            }
            // `this` dies when the last pending callback's shared_ptr releases.
        }

        void TcpRelay::FinishFromFlow() {
            // The flow already terminated (client reset / stack reclaim):
            // there is nobody left to FIN, so always treat as non-graceful.
            Finish(false);
        }

    }  // namespace relay
}  // namespace vgww
