// ============================================================================
// tcp_relay.h - Bidirectional pump between a client flow and an upstream
// socket (the NAT core of VGWW).
//
// OWNERSHIP & THREADING (design spec section 4):
//   * One relay serves one client TCP connection. Every callback - MimtFlow
//     completions AND upstream socket completions - fires on the OWNING
//     WORKER thread (flow completions via DispatchMimt, socket completions
//     via that worker's io_context::poll). Zero locks.
//   * Lifetime = shared_ptr chain of pending callbacks. The relay keeps
//     itself alive with enable_shared_from_this; when both pumps stop the
//     last callback releases it. The owner may also hold weak references
//     for accounting.
//
// BACKPRESSURE (design spec section 6.2):
//   * flow -> socket: only ONE AsyncRead outstanding; the next read is
//     issued after asio finishes writing the previous chunk. If the socket
//     stalls, MimtFlow's rx queue fills, OnData returns false, xtcp shrinks
//     its window to zero and the CLIENT slows down. End-to-end.
//   * socket -> flow: only ONE async_read_some outstanding; the next read
//     is issued after AsyncWrite completes. AsyncWrite kWouldBlock/kNoBuffer
//     means the flow's write queue is full - we surface that by pausing the
//     socket read (kernel socket buffer fills -> peer slows down).
//
// TEARDOWN: either side closing/erroring tears down BOTH directions exactly
// once. The underlying xtcp connection is aborted through OnTeardown (RST to
// the client) unless it already finished cleanly.
// ============================================================================
#pragma once

#include <xtcp/mimt/mimt.h>

#include <asio.hpp>

#include <array>
#include <cstdint>
#include <memory>

namespace vgww {
    namespace relay {

        class TcpRelay final : public std::enable_shared_from_this<TcpRelay> {
        public:
            /// Sink for lifecycle events (owner bookkeeping / FIN vs RST delivery).
            struct Hooks {
                /// Called EXACTLY once when the relay finishes. `graceful`
                /// distinguishes a clean end (upstream EOF: the owner should
                /// CLOSE the xtcp connection, sending the client a FIN) from
                /// an error/reset (the owner should ABORT, sending an RST).
                std::function<void(UInt64 conn_id, bool graceful)> on_finished;
            };

            TcpRelay(std::shared_ptr<xtcp::mimt::MimtFlow> flow,
                     asio::ip::tcp::socket socket, Hooks hooks);

            /// Starts both pumps. Must be called exactly once, on the owning
            /// worker thread, right after construction.
            void Start();

            /// The client finished sending (its FIN reached us: the xtcp
            /// connection entered kCloseWait). Relay the half-close upstream:
            /// shut down OUR send direction so the server sees EOF once it
            /// drains our data, while the receive direction (its replies)
            /// keeps flowing back to the client. asio shutdown_send flushes
            /// queued bytes and does not abort an in-flight write, so no
            /// payload is lost. Idempotent.
            void OnPeerFin();

            UInt64 ConnId() const noexcept { return flow_->ConnId(); }

            /// True once the relay finished (both pumps stopped). The owner
            /// uses this to sweep its registry.
            bool Finished() const noexcept { return finished_; }

        private:
            void PumpFlowToSocket();
            void PumpSocketToFlow();
            void WriteToFlow(UInt32 len);
            void RetryPendingWrite();
            /// `graceful` = clean EOF path (owner sends FIN to the client);
            /// false = error/reset (owner sends RST).
            void Finish(bool graceful);
            void FinishFromFlow();  ///< flow-side end: client already gone

            std::shared_ptr<xtcp::mimt::MimtFlow> flow_;
            asio::ip::tcp::socket socket_;
            Hooks hooks_;

            // Relay buffers: 16 KiB chunks keep latency low while amortizing
            // syscall overhead; sized below xtcp's 64 KiB per-direction caps.
            std::array<uint8_t, 16384> down_buf_{};  // client -> internet
            std::array<uint8_t, 16384> up_buf_{};    // internet -> client
            // Zero-window backoff: a write refused by the flow (kInFlight /
            // kWouldBlock) is retried after a short delay instead of tearing
            // the connection down.
            asio::steady_timer write_retry_timer_{socket_.get_executor()};
            UInt32 pending_up_len_ = 0;
            /// True while the flow refused a chunk (kInFlight/kWouldBlock)
            /// and the bytes in up_buf_[0 .. pending_up_len_) are still
            /// owed to the flow. While set the socket read stays paused so
            /// a new arrival cannot overwrite the held bytes.
            bool retry_pending_ = false;
            bool finished_ = false;
        };

    }  // namespace relay
}  // namespace vgww
