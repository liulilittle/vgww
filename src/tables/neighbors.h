// ============================================================================
// neighbors.h - Unified L2 neighbor table for ARP (v4) and NDP (v6).
//
// Concurrency design (design spec section 5.1 / 7.6):
//   * READ path (workers, hot): one atomic load of an immutable snapshot
//     shared_ptr, then a hash lookup. Zero locks.
//   * WRITE path: Learn() is called by the RX thread only (single writer).
//     Updates land in a small mutex-guarded pending map; the control-plane
//     thread drains it on Tick(), ages stale entries, rebuilds the immutable
//     snapshot and publishes it atomically.
//   * Resolution misses are handled by DROP-AND-RETRY at the caller: the
//     frame is dropped (TCP retransmits), a resolve request is queued and
//     the control plane emits the ARP/NS probe. No worker ever blocks.
//
// Aging: entries untouched for kNeighborTimeoutMs are evicted on rebuild.
// ============================================================================
#pragma once

#include "core/limits.h"
#include "net/ip_addr.h"

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <unordered_map>

namespace vgww {
    namespace tables {

        /// Neighbor reachability states we track (subset of RFC 4861 STALE
        /// machinery - VGWW is passive-first with active probing on demand).
        enum class NeighborState : uint8_t {
            kLearned = 0,   ///< seen on the wire (passive learning)
            kResolved = 1,  ///< answer to our own probe
            kPending = 2,   ///< probe sent, awaiting reply
        };

        struct NeighborEntry final {
            std::array<uint8_t, 6> mac{};
            NeighborState state = NeighborState::kLearned;
            std::chrono::steady_clock::time_point last_seen{};
        };

        /// Immutable lookup structure published to workers.
        class NeighborSnapshot final {
        public:
            /// Returns nullptr when the address is unknown.
            const NeighborEntry* Find(const net::IpAddress& ip) const noexcept;

            /// Whole-table view for telemetry (device list). Returns a stable
            /// copy: callers must never mutate the entries.
            const std::unordered_map<net::IpAddress, NeighborEntry,
                                     net::IpAddressHash>&
            Entries() const noexcept {
                return map_;
            }

            friend class NeighborTable;  // rebuild path mutates map_ directly

        private:
            std::unordered_map<net::IpAddress, NeighborEntry, net::IpAddressHash> map_;
        };

        using NeighborSnapshotPtr = std::shared_ptr<const NeighborSnapshot>;

        class NeighborTable final {
        public:
            static constexpr uint64_t kNeighborTimeoutMs = 20 * 60 * 1000;  // RFC-ish 20min
            // Passive learning drains every Tick; between drains an attacker can
            // inject unlimited fabricated source IPs (ARP / IPv6 frames). Cap the
            // pending buffer so a spoofed flood cannot grow the RX-side map into
            // an OOM risk; learned entries already at the cap keep their slot
            // refreshed, only brand-new IPs are refused.
            static constexpr size_t kMaxPendingNeighbors = 50000;

            // H1: published-table cap (single-sourced in core/limits.h).
            // Overflow eviction keeps the NEWEST entries (last_seen order)
            // and counts every eviction (telemetry + tests).
            static constexpr size_t kMaxNeighbors = core::limits::kMaxNeighbors;

            NeighborTable() : current_(std::make_shared<NeighborSnapshot>()) {}

            /// RX thread only. Records src_ip -> src_mac from any intercepted
            /// frame (passive learning covers static-IP clients).
            void Learn(const net::IpAddress& ip,
                       const std::array<uint8_t, 6>& mac) noexcept;

            /// Control plane only. Drains pending updates, applies aging,
            /// rebuilds and publishes a fresh snapshot.
            void Tick(std::chrono::steady_clock::time_point now);

            /// Workers. Returns the latest published snapshot (one atomic load).
            NeighborSnapshotPtr Snapshot() const noexcept {
                return std::atomic_load(&current_);
            }

            /// Approximate pending-update count for telemetry.
            size_t PendingUpdates() const noexcept {
                std::lock_guard<std::mutex> lock(pending_mutex_);
                return pending_.size();
            }

            /// Published snapshot size (telemetry/tests).
            size_t Size() const noexcept {
                return std::atomic_load(&current_)->Entries().size();
            }

            /// Total entries evicted by the size cap since construction
            /// (monotonic; written only by the control-plane Tick()).
            uint64_t EvictedCount() const noexcept {
                return evictions_.load(std::memory_order_relaxed);
            }

            /// batch34i: Learn() calls REFUSED - the pending map was at
            /// kMaxPendingNeighbors and the IP was new (the ARP-spoof flood
            /// guard doing its job), or the pending-map allocation failed
            /// (batch300). Either way a legitimate new device cannot be
            /// resolved; the caller and the operator both used to be blind
            /// to it.
            uint64_t RejectedCount() const noexcept {
                return rejected_.load(std::memory_order_relaxed);
            }

        private:
            typedef std::unordered_map<net::IpAddress, NeighborEntry, net::IpAddressHash> PendingMap;

            mutable std::mutex pending_mutex_;   // RX writer vs control drainer
            PendingMap pending_;
            NeighborSnapshotPtr current_;        // atomic published snapshot
            std::atomic<uint64_t> evictions_{0};  // cap evictions (Tick writer)
            std::atomic<uint64_t> rejected_{0};   // Learn() refusals (RX writer)
            /// batch296: earliest last_seen in the PUBLISHED snapshot.
            /// Tick() only rebuilds when an update arrived or this instant
            /// has aged out; the idle tick used to copy the whole table
            /// (one heap node per neighbor) ten times a second.
            std::chrono::steady_clock::time_point oldest_ =
                std::chrono::steady_clock::time_point::max();
        };

    }  // namespace tables
}  // namespace vgww
