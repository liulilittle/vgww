// ============================================================================
// test_spsc_ring.cpp - Unit + stress tests for the lock-free SPSC ring.
//
// Coverage:
//   * single-thread semantics: push/pop order, full/empty behavior
//   * power-of-two capacity rounding
//   * destructor pairing: every pushed element is destroyed exactly once
//   * concurrent SPSC stress: producer/consumer on two threads, strict FIFO
//     order verified via monotonic sequence numbers (causality, not wall time)
// ============================================================================
#include "dsp/spsc_ring.h"

#include <atomic>
#include <cstdio>
#include <thread>
#include <vector>

namespace {

    int g_failures = 0;

#define CHECK(cond)                                                        \
    do {                                                                   \
        if (!(cond)) {                                                     \
            std::fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__,  \
                         __LINE__, #cond);                                 \
            ++g_failures;                                                  \
        }                                                                  \
    } while (0)

    void TestBasicOrder() {
        auto ring = vgww::dsp::SpscRing<int>::Create(4);
        CHECK(nullptr != ring);
        CHECK(ring->Capacity() == 4);
        CHECK(ring->PopBatch(nullptr, 4) == 0);  // empty

        for (int i = 0; i < 4; ++i) {
            int value = i;
            CHECK(ring->Push(std::move(value)));
        }
        // Full now: the next push must be rejected, ownership stays with us.
        int rejected = 99;
        CHECK(!ring->Push(std::move(rejected)));
        CHECK(rejected == 99);

        int out[8];
        CHECK(ring->PopBatch(out, 8) == 4);
        for (int i = 0; i < 4; ++i) {
            CHECK(out[i] == i);  // strict FIFO
        }
    }

    void TestCapacityRounding() {
        auto ring = vgww::dsp::SpscRing<uint8_t>::Create(5);
        CHECK(nullptr != ring);
        CHECK(ring->Capacity() == 8);  // rounded to next power of two
    }

    /// Create(0) must return null: the header says callers treat it as a
    /// fatal startup error, and a zero-capacity ring would have mask_ == -1
    /// and be permanently full.
    void TestZeroCapacityRejected() {
        CHECK(nullptr == vgww::dsp::SpscRing<int>::Create(0));
        CHECK(nullptr == vgww::dsp::SpscRing<uint8_t>::Create(0));
    }

    /// Capacity 1 and 2 are the smallest legal sizes; the mask arithmetic must
    /// still wrap correctly (mask 0 and 1).
    void TestSmallestCapacities() {
        {
            auto ring = vgww::dsp::SpscRing<int>::Create(1);
            CHECK(nullptr != ring);
            CHECK(ring->Capacity() == 1);
            int v = 7;
            CHECK(ring->Push(std::move(v)));
            int again = 8;
            CHECK(!ring->Push(std::move(again)));   // full
            int out[1] = {0};
            CHECK(ring->PopBatch(out, 1) == 1);
            CHECK(out[0] == 7);
            CHECK(ring->PopBatch(out, 1) == 0);     // empty again
        }
        {
            auto ring = vgww::dsp::SpscRing<int>::Create(2);
            CHECK(nullptr != ring);
            CHECK(ring->Capacity() == 2);
            for (int i = 0; i < 2; ++i) {
                int v = i;
                CHECK(ring->Push(std::move(v)));
            }
            int full = 9;
            CHECK(!ring->Push(std::move(full)));
            int out[2] = {0, 0};
            CHECK(ring->PopBatch(out, 2) == 2);
            CHECK(out[0] == 0 && out[1] == 1);
        }
    }

    /// SizeApprox must report what is actually buffered, and PopBatch with
    /// max_out == 0 must consume nothing (guards the count clamp).
    void TestSizeApproxAndZeroPop() {
        auto ring = vgww::dsp::SpscRing<int>::Create(8);
        CHECK(nullptr != ring);
        CHECK(ring->SizeApprox() == 0);
        for (int i = 0; i < 5; ++i) {
            int v = i;
            CHECK(ring->Push(std::move(v)));
        }
        CHECK(ring->SizeApprox() == 5);

        int out[8] = {0};
        CHECK(ring->PopBatch(out, 0) == 0);   // asked for nothing
        CHECK(ring->SizeApprox() == 5);       // nothing consumed

        CHECK(ring->PopBatch(out, 3) == 3);
        CHECK(ring->SizeApprox() == 2);
        CHECK(out[0] == 0 && out[1] == 1 && out[2] == 2);

        // Wrap-around reuse: push more than capacity in total so the slot
        // indices reuse storage behind the free-running counters. The ring
        // still holds 2 elements here, so drain it first - pushing 8 into a
        // capacity-8 ring that already holds 2 must FAIL (that is the
        // contract), and this test is about wrap-around, not fullness.
        int drain[8] = {0};
        CHECK(ring->PopBatch(drain, 8) == 2);
        CHECK(ring->SizeApprox() == 0);
        for (int round = 0; round < 3; ++round) {
            for (int i = 0; i < 8; ++i) {
                int v = round * 8 + i;
                CHECK(ring->Push(std::move(v)));
            }
            int sink[8] = {0};
            CHECK(ring->PopBatch(sink, 8) == 8);
            for (int i = 0; i < 8; ++i) {
                CHECK(sink[i] == round * 8 + i);
            }
        }
    }

    struct Tracked {
        static std::atomic<int> live;
        int value;
        Tracked() : value(-1) { ++live; }  // default: needed for PopBatch arrays
        explicit Tracked(int v) : value(v) { ++live; }
        Tracked(Tracked&& other) noexcept : value(other.value) { ++live; }
        Tracked& operator=(Tracked&& other) noexcept {
            value = other.value;
            return *this;
        }
        ~Tracked() { --live; }
    };

    std::atomic<int> Tracked::live{0};

    void TestDestructorPairing() {
        {
            auto ring = vgww::dsp::SpscRing<Tracked>::Create(16);
            for (int i = 0; i < 10; ++i) {
                CHECK(ring->Push(Tracked(i)));
            }
            Tracked out[4];
            CHECK(ring->PopBatch(out, 4) == 4);
            // 6 remain inside; destructor must drain them exactly once.
        }
        CHECK(Tracked::live.load() == 0);
    }

    void TestConcurrentStress() {
        static constexpr uint64_t kCount = 1u << 20;
        auto ring = vgww::dsp::SpscRing<uint64_t>::Create(1024);

        std::atomic<bool> done{false};
        std::atomic<uint64_t> last_popped{0};
        std::atomic<uint64_t> popped_total{0};

        std::thread consumer([&] {
            uint64_t out[64];
            for (;;) {
                const size_t n = ring->PopBatch(out, 64);
                if (n > 0) {
                    for (size_t i = 0; i < n; ++i) {
                        // Strict FIFO: sequence numbers must advance by one.
                        CHECK(out[i] == last_popped.fetch_add(1) + 1);
                    }
                    popped_total.fetch_add(n);
                } else if (done.load(std::memory_order_acquire)) {
                    return;
                } else {
                    std::this_thread::yield();
                }
            }
        });

        std::thread producer([&] {
            uint64_t sent = 0;
            while (sent < kCount) {
                uint64_t seq = sent + 1;
                if (ring->Push(std::move(seq))) {
                    sent = seq;
                    continue;
                }
                std::this_thread::yield();  // full: retry same element
            }
            done.store(true, std::memory_order_release);
        });

        producer.join();
        consumer.join();
        CHECK(popped_total.load() == kCount);
    }

}  // namespace

int main() {
    TestBasicOrder();
    TestCapacityRounding();
    TestZeroCapacityRejected();
    TestSmallestCapacities();
    TestSizeApproxAndZeroPop();
    TestDestructorPairing();
    TestConcurrentStress();
    if (0 == g_failures) {
        std::puts("test_spsc_ring: ALL PASS");
        return 0;
    }
    std::fprintf(stderr, "test_spsc_ring: %d FAILURES\n", g_failures);
    return 1;
}
