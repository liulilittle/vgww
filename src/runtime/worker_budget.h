// ============================================================================
// worker_budget.h - per-worker container sizing for the data plane.
//
// The relay registry, its conn_id index and the accept/teardown queues are
// per-worker and only grow on the data path. Growing them there reallocates
// while the owning mutex is held, and a std::unordered_map rehash at 4000
// entries is a visible latency spike exactly when connections ramp up. The
// hard bound is max_conns, so every container can be sized once at startup.
//
// The +kSlackPerWorker covers flows accepted before the registry insert runs
// (DrainAccepts holds a dial in flight) and teardowns queued for a relay that
// is not in the registry yet.
// ============================================================================
#pragma once

#include <cstddef>
#include <cstdint>

namespace vgww {
    namespace runtime {

        /// Slot count to reserve in each per-worker container.
        /// Never returns 0: a zero reserve would leave the very first push a
        /// reallocation, which is the spike this exists to avoid.
        inline size_t PerWorkerReserve(size_t max_conns,
                                      uint32_t workers) noexcept {
            constexpr size_t kSlackPerWorker = 64;
            if (0 == workers) {
                return kSlackPerWorker;
            }
            return (max_conns / workers) + kSlackPerWorker;
        }

    }  // namespace runtime
}  // namespace vgww
