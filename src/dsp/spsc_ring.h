// ============================================================================
// spsc_ring.h - Lock-free single-producer/single-consumer ring buffer.
//
// This is the ONLY cross-thread synchronization primitive on the VGWW data
// path (see docs/en/architecture.md section "Three killers"). The RX thread
// is the sole producer, each worker thread is the sole consumer of its own
// ring; the TX direction mirrors this with per-worker rings drained by the
// RX/TX thread.
//
// Design contract:
//   * Exactly one producer thread and one consumer thread at any time.
//   * Wait-free push/pop (single acquire/release pair per operation).
//   * Indices are FREE-RUNNING 64-bit counters; slots are addressed with
//     `index & mask_`. Fullness is `(tail - head) == capacity`, so every
//     slot is usable (no wasted sentinel slot) and ABA wraparound needs
//     2^64 operations - unreachable.
//   * Full-ring push returns false: the caller DROPS and counts. We never
//     block the RX thread (TCP recovers via retransmission, UDP is lossy by
//     design) - matches xtcp's drop-not-grow philosophy.
//   * Capacity is rounded up to a power of two; indexing wraps via mask.
// ============================================================================
#pragma once

// alignas(64) on the ring indices intentionally inserts padding between
// members to keep them on separate cache lines; MSVC warns about the very
// padding we asked for (C4324). Silence it for this header only.
#pragma warning(push)
#pragma warning(disable : 4324)

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <type_traits>
#include <utility>

namespace vgww {
    namespace dsp {

        namespace detail {
            // Pads a value to its own cache line so adjacent fields never share
            // a line (prevents false sharing between producer and consumer).
            template <typename T>
            struct alignas(64) CacheLinePadded {
                static_assert(alignof(T) <= 64, "T must not be over-aligned");
                T value;
                CacheLinePadded() noexcept(std::is_nothrow_default_constructible_v<T>) : value{} {}
                explicit CacheLinePadded(T v) noexcept : value(v) {}
            };
        }

        template <typename T>
        class SpscRing final {
        public:
            // Creates a ring holding at least `requested_capacity` elements
            // (rounded up to a power of two). Returns null on allocation
            // failure or zero request - callers treat that as fatal startup
            // error.
            static std::unique_ptr<SpscRing> Create(size_t requested_capacity) {
                if (0 == requested_capacity) {
                    return nullptr;
                }
                // Super-large guard: round up with overflow check.
                size_t capacity = 1;
                while (capacity < requested_capacity) {
                    if (capacity > (SIZE_MAX >> 1)) {
                        return nullptr;
                    }
                    capacity <<= 1;
                }
                if (capacity > SIZE_MAX / sizeof(T)) {
                    return nullptr;
                }
                // make_unique requires a public ctor; use raw new + unique_ptr.
                return std::unique_ptr<SpscRing>(new SpscRing(capacity));
            }

            ~SpscRing() {
                // Drain any remaining elements so their destructors run exactly
                // once (1:1 pairing discipline: every pushed element is either
                // popped or destroyed here, never both).
                const size_t head = head_.value.load(std::memory_order_relaxed);
                const size_t tail = tail_.value.load(std::memory_order_relaxed);
                for (size_t i = head; i != tail; ++i) {
                    SlotAt(i).~T();
                }
            }

            SpscRing(const SpscRing&) = delete;
            SpscRing& operator=(const SpscRing&) = delete;

            // Producer side. Returns true when the element was enqueued,
            // false when the ring is full (element ownership stays with the
            // caller, which drops it and bumps a drop counter).
            bool Push(T&& element) noexcept(std::is_nothrow_move_constructible_v<T>) {
                const size_t tail = tail_.value.load(std::memory_order_relaxed);
                // Acquire load pairs with the consumer's release store: seeing
                // an up-to-date head guarantees no unconsumed slot is hit.
                if (tail - head_.value.load(std::memory_order_acquire) == capacity_) {
                    return false;  // full
                }
                ::new (static_cast<void*>(&slots_[tail & mask_])) T(std::move(element));
                // Release store: publishes the slot contents before the index.
                tail_.value.store(tail + 1, std::memory_order_release);
                return true;
            }

            // Consumer side. Dequeues up to `max_out` elements into `out`,
            // returns how many were dequeued (may be 0 when empty). Batch pop
            // amortizes the index loads across many elements.
            size_t PopBatch(T* out, size_t max_out) noexcept(std::is_nothrow_move_assignable_v<T>) {
                const size_t head = head_.value.load(std::memory_order_relaxed);
                // Acquire load pairs with the producer's release store: slot
                // contents are visible before the tail index is read.
                const size_t tail = tail_.value.load(std::memory_order_acquire);
                size_t count = tail - head;
                if (count > max_out) {
                    count = max_out;
                }
                for (size_t i = 0; i < count; ++i) {
                    const size_t index = head + i;
                    out[i] = std::move(SlotAt(index));
                    SlotAt(index).~T();
                }
                if (count > 0) {
                    // Release store: marks slots as reusable only after their
                    // contents have been moved out.
                    head_.value.store(head + count, std::memory_order_release);
                }
                return count;
            }

            // Approximate size - relaxed loads, for stats/telemetry only.
            size_t SizeApprox() const noexcept {
                return tail_.value.load(std::memory_order_relaxed) -
                       head_.value.load(std::memory_order_relaxed);
            }

            size_t Capacity() const noexcept { return capacity_; }

        private:
            explicit SpscRing(size_t capacity)
                : capacity_(capacity),
                  mask_(capacity - 1),
                  storage_(::operator new[](capacity * sizeof(T)),
                           [](void* p) noexcept { ::operator delete[](p); }) {
                slots_ = reinterpret_cast<T*>(storage_.get());
            }

            T& SlotAt(size_t free_running_index) noexcept {
                return slots_[free_running_index & mask_];
            }

            const size_t capacity_;
            const size_t mask_;
            std::unique_ptr<void, void (*)(void*)> storage_;
            T* slots_ = nullptr;

            // Producer owns tail_, consumer owns head_; each on its own cache
            // line to avoid false sharing on the hot path. Both are FREE-
            // RUNNING counts of total enqueued/dequeued elements ever.
            detail::CacheLinePadded<std::atomic<size_t>> head_{};
            detail::CacheLinePadded<std::atomic<size_t>> tail_{};
        };

    }  // namespace dsp
}  // namespace vgww

#pragma warning(pop)
