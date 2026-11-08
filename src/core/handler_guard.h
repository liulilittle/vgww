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

namespace vgww {
    namespace core {

        /// Runs `fn` and swallows anything it throws, counting the event.
        /// `noexcept` by construction: the caller is a completion handler or a
        /// thread body, where escaping is fatal.
        template <typename Fn>
        void InvokeHandlerGuarded(std::atomic<uint64_t>& errors,
                                  Fn&& fn) noexcept {
            try {
                fn();
            } catch (...) {
                errors.fetch_add(1, std::memory_order_relaxed);
            }
        }

    }  // namespace core
}  // namespace vgww
