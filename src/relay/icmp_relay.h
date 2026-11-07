// ============================================================================
// icmp_relay.h - ICMP echo relay with identifier NAT.
//
// Model (openppp2-proven): each worker owns one raw ICMP socket. Outbound
// client pings get their 16-bit identifier rewritten to a GLOBALLY UNIQUE
// 32-bit tag (unique across workers, so replies always find the right
// worker/flow); inbound echo replies match by tag and are rebuilt toward the
// client. Tags expire after 3 seconds (one retransmission window is plenty).
//
// The gateway answering its OWN pings happens earlier, inline in the RX
// thread - this module only handles relayed pings.
// ============================================================================
#pragma once

#include "net/ip_addr.h"

#include <asio.hpp>

#include <array>
#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>
#include <unordered_map>

namespace vgww {
    namespace relay {

        class IcmpRelay final : public std::enable_shared_from_this<IcmpRelay> {
        public:
            /// One NAT entry: who pinged, under which original identity.
            struct TagEntry {
                net::IpAddress client_ip;
                uint16_t original_id = 0;
                std::array<uint8_t, 6> client_mac{};
                std::chrono::steady_clock::time_point expires;
            };

            /// Global tag allocator (cross-worker uniqueness). Thread-safe.
            class TagAllocator final {
            public:
                static TagAllocator& Instance() noexcept;

                /// Reserves a unique tag for `entry`; returns 0 when every tag
                /// is in flight (0 is reserved and never handed out).
                uint16_t Allocate(const TagEntry& entry,
                                  std::chrono::steady_clock::time_point now);

                /// Looks up and removes a tag; returns false when unknown or
                /// expired. `entry` is filled on hit.
                bool Consume(uint16_t tag, TagEntry& entry,
                             std::chrono::steady_clock::time_point now);

                /// Drops expired entries; returns removed count.
                size_t Sweep(std::chrono::steady_clock::time_point now);

                /// Tags currently in flight (telemetry/tests).
                size_t InFlight() const noexcept;

                /// Tags available for allocation. Invariant:
                /// InFlight() + Free() == kTagCapacity.
                size_t Free() const noexcept;

            private:
                TagAllocator();
                /// Usable tags: 1..65535 (0 is the "pool full" signal).
                static constexpr size_t kTagCapacity = 65535;
                mutable std::mutex mutex_;
                std::unordered_map<uint16_t, TagEntry> table_;
                // batch299: free-list. The old allocator walked the tag space
                // under this mutex until it found a free tag; with the table
                // full or nearly full that was up to 65k hash lookups per ping
                // (a flood turned every dropped ping into ~1 ms of CPU). The
                // free-list makes Allocate O(1) and keeps the pool exact:
                // every erase pushes, every insert pops.
                std::array<uint16_t, kTagCapacity> free_{};
                size_t free_count_ = 0;
            };

            IcmpRelay(asio::ip::icmp::socket socket);

            /// Sends a raw ICMP segment toward `dst` (network-order bytes).
            /// NO IP header here - Windows kernels add it for IPPROTO_ICMP
            /// raw sockets. Errors are swallowed: this runs on worker
            /// threads and an escaping exception would kill the process;
            /// ICMP loss is acceptable by design.
            void SendEchoRequest(const uint8_t* icmp_segment, size_t len,
                                 const std::array<uint8_t, 4>& dst);

            /// Arms the continuous receive loop; `on_reply` fires for every
            /// matched echo reply as a RAW IP PACKET (worker rebuilds frames).
            void ArmReceive(
                std::function<void(const uint8_t* ip_packet, size_t len)>
                    on_reply);

            /// Outcome of one async_receive completion, centralized so the
            /// pump loop's error policy is unit-testable.
            enum class ReceiveDecision : uint8_t {
                kProcess,      ///< datagram received: deliver then keep pumping
                kBackoffReArm, ///< transient error or zero-length datagram:
                               ///< re-arm shortly - never let one error kill
                               ///< the relay for good
                kStop          ///< socket closed / operation aborted: halt
            };
            static ReceiveDecision ClassifyReceive(
                const std::error_code& err, size_t n,
                bool socket_open) noexcept;

            asio::ip::icmp::socket& Socket() noexcept { return socket_; }

        private:
            /// (Re)arms the async receive. When `backoff` is set the re-arm
            /// happens after a short pause so a burst of socket resets does
            /// not busy-loop the worker.
            void PumpReceive(bool backoff);

            asio::ip::icmp::socket socket_;
            std::function<void(const uint8_t*, size_t)> on_reply_;
            std::array<uint8_t, 2048> recv_buf_{};
            asio::steady_timer retry_timer_{socket_.get_executor()};
        };

    }  // namespace relay
}  // namespace vgww
