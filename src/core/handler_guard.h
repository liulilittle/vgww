// ============================================================================
// handler_guard.h - exception firewall for completion handlers and thread
// bodies.
//
// One datagram that cannot be rebuilt (a frame builder hitting bad_alloc) or
// one HTTP request whose handler throws must cost THAT unit of work, not the
// whole process: an exception escaping an asio completion handler unwinds
// io_context::run()/poll(), and an exception escaping a std::thread body calls
// std::terminate. Both relay receive chains and the HTTP server therefore run
// their per-event work through this guard.
// ============================================================================
#pragma once

#include <atomic>
#include <cstdint>
#include <utility>

namespace vgww {
    namespace core {

        /// Runs `fn` and swallows anything it throws, counting the event.
        /// `noexcept` by construction: the caller is a completion handler or a
        /// thread body, where escaping is fatal. Returns false when the body
        /// threw, so a caller that owns a resource can tear it down instead of
        /// leaving a half-updated chain behind.
        template <typename Fn>
        bool InvokeHandlerGuarded(std::atomic<uint64_t>& errors,
                                  Fn&& fn) noexcept {
            try {
                fn();
                return true;
            } catch (...) {
                errors.fetch_add(1, std::memory_order_relaxed);
                return false;
            }
        }

        /// Runs the body of a DETACHED thread. A throw there calls
        /// std::terminate (the thread is its own entry point), so the
        /// exception is swallowed and reported through `on_failure` instead -
        /// e.g. publishing a failure result an operator can see. `on_failure`
        /// is firewalled too (a report path must not kill the process either).
        template <typename Body, typename OnFailure>
        void RunDetachedBodyGuarded(std::atomic<uint64_t>& errors,
                                    Body&& body,
                                    OnFailure&& on_failure) noexcept {
            try {
                body();
            } catch (...) {
                errors.fetch_add(1, std::memory_order_relaxed);
                InvokeHandlerGuarded(errors,
                                     std::forward<OnFailure>(on_failure));
            }
        }

    }  // namespace core
}  // namespace vgww
