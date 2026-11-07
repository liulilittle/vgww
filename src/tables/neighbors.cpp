// ============================================================================
// neighbors.cpp - Snapshot rebuild and lookup implementation.
// ============================================================================
#include "tables/neighbors.h"

#include <algorithm>
#include <cstddef>
#include <vector>

namespace vgww {
    namespace tables {

        const NeighborEntry* NeighborSnapshot::Find(const net::IpAddress& ip) const noexcept {
            const auto it = map_.find(ip);
            return (map_.end() == it) ? nullptr : &it->second;
        }

        void NeighborTable::Learn(const net::IpAddress& ip,
                                  const std::array<uint8_t, 6>& mac) noexcept {
            // batch300: Learn is noexcept and runs on the RX thread; an
            // allocation failure escaping here would call std::terminate and
            // kill the whole gateway. Refuse the learn instead (the next
            // frame retries it).
            try {
                std::lock_guard<std::mutex> lock(pending_mutex_);
                if (pending_.size() >= kMaxPendingNeighbors &&
                    pending_.find(ip) == pending_.end()) {
                    // batch34i: count the refusal. While the guard is
                    // saturated a legitimate new device cannot be resolved at
                    // all, and that used to leave no trace anywhere.
                    rejected_.fetch_add(1, std::memory_order_relaxed);
                    return;  // flood guard: refuse brand-new IPs over the cap
                }
                NeighborEntry& entry = pending_[ip];
                entry.mac = mac;
                entry.state = NeighborState::kLearned;
                // last_seen stamped on Tick() with the control-plane clock,
                // which is also the aging clock - keeps comparisons
                // consistent.
            } catch (...) {
                rejected_.fetch_add(1, std::memory_order_relaxed);
            }
        }

        void NeighborTable::Tick(std::chrono::steady_clock::time_point now) {
            // batch296: the idle tick must not touch the heap. An empty
            // PendingMap still allocates its list sentinel, so check for
            // updates and the aging deadline BEFORE constructing it.
            bool has_updates = false;
            {
                std::lock_guard<std::mutex> lock(pending_mutex_);
                has_updates = !pending_.empty();
            }
            if (!has_updates &&
                now - oldest_ <=
                    std::chrono::milliseconds(kNeighborTimeoutMs)) {
                return;
            }

            // 1. Drain pending updates under the lock (fast: RX thread only
            //    appends; this is the only contention point and it is O(n)).
            PendingMap drained;
            {
                std::lock_guard<std::mutex> lock(pending_mutex_);
                if (!pending_.empty()) {
                    drained = std::move(pending_);
                    pending_.clear();
                }
            }

            // 2. Rebuild off-lock: copy current snapshot, merge updates, age.
            auto fresh = std::make_shared<NeighborSnapshot>();
            fresh->map_ = std::atomic_load(&current_)->map_;

            for (auto& pair : drained) {
                NeighborEntry& entry = fresh->map_[pair.first];
                entry.mac = pair.second.mac;
                entry.state = pair.second.state;
                entry.last_seen = now;
            }

            for (auto it = fresh->map_.begin(); it != fresh->map_.end();) {
                const uint64_t age_ms = static_cast<uint64_t>(
                    std::chrono::duration_cast<std::chrono::milliseconds>(
                        now - it->second.last_seen)
                        .count());
                if (age_ms > kNeighborTimeoutMs) {
                    it = fresh->map_.erase(it);
                } else {
                    ++it;
                }
            }

            // 2b. H1 published-table cap: evict the OLDEST entries (smallest
            //     last_seen; ties by address order for determinism) until the
            //     table fits. Entries merged above carry `now`, so they are
            //     the newest and survive. partial_sort keeps this O(n log k)
            //     even when a drained batch overflows the cap.
            if (fresh->map_.size() > kMaxNeighbors) {
                std::vector<std::pair<std::chrono::steady_clock::time_point,
                                      net::IpAddress>>
                    order;
                order.reserve(fresh->map_.size());
                for (const auto& pair : fresh->map_) {
                    order.emplace_back(pair.second.last_seen, pair.first);
                }
                const size_t excess = fresh->map_.size() - kMaxNeighbors;
                std::partial_sort(
                    order.begin(),
                    order.begin() + static_cast<std::ptrdiff_t>(excess),
                    order.end(),
                    [](const auto& a, const auto& b) {
                        if (a.first != b.first) {
                            return a.first < b.first;
                        }
                        return a.second < b.second;  // deterministic tie-break
                    });
                for (size_t i = 0; i < excess; ++i) {
                    fresh->map_.erase(order[i].second);
                }
                evictions_.fetch_add(excess, std::memory_order_relaxed);
            }

            // batch296: remember the earliest last_seen so the next idle
            // Tick can prove that nothing can have aged out.
            oldest_ = std::chrono::steady_clock::time_point::max();
            for (const auto& pair : fresh->map_) {
                if (pair.second.last_seen < oldest_) {
                    oldest_ = pair.second.last_seen;
                }
            }

            // 3. Publish atomically; workers pick it up on next Snapshot().
            std::atomic_store(&current_, NeighborSnapshotPtr(std::move(fresh)));
        }

    }  // namespace tables
}  // namespace vgww
