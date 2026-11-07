// ============================================================================
// test_neighbors.cpp - Neighbor table: learning, aging, snapshot isolation.
// ============================================================================
#include "tables/neighbors.h"

#include <atomic>
#include <cstdio>
#include <thread>

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

    using vgww::net::IpAddress;
    using vgww::tables::NeighborEntry;
    using vgww::tables::NeighborState;
    using vgww::tables::NeighborTable;

    IpAddress MakeV4(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
        const uint8_t wire[4] = {a, b, c, d};
        return IpAddress::FromV4BigEndian(wire);
    }

    void TestLearnFind() {
        NeighborTable table;
        const auto now = std::chrono::steady_clock::now();
        const IpAddress ip = MakeV4(192, 168, 0, 101);
        const std::array<uint8_t, 6> mac{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01};

        CHECK(nullptr == table.Snapshot()->Find(ip));  // not yet learned
        table.Learn(ip, mac);
        // Unpublished until Tick.
        CHECK(nullptr == table.Snapshot()->Find(ip));
        table.Tick(now);
        const auto* entry = table.Snapshot()->Find(ip);
        CHECK(nullptr != entry);
        if (entry) {
            CHECK((entry->mac == mac));
        }
    }

    void TestAging() {
        NeighborTable table;
        const auto t0 = std::chrono::steady_clock::now();
        const IpAddress ip = MakeV4(10, 0, 0, 5);
        const std::array<uint8_t, 6> mac{1, 2, 3, 4, 5, 6};
        table.Learn(ip, mac);
        table.Tick(t0);
        CHECK(nullptr != table.Snapshot()->Find(ip));

        // Advance past the timeout without refreshing: eviction expected.
        const auto t1 = t0 + std::chrono::milliseconds(NeighborTable::kNeighborTimeoutMs + 1);
        table.Tick(t1);
        CHECK(nullptr == table.Snapshot()->Find(ip));
    }

    void TestRefreshKeepsAlive() {
        NeighborTable table;
        const auto t0 = std::chrono::steady_clock::now();
        const IpAddress ip = MakeV4(10, 0, 0, 7);
        const std::array<uint8_t, 6> mac{9, 8, 7, 6, 5, 4};
        table.Learn(ip, mac);
        table.Tick(t0);

        const auto t1 = t0 + std::chrono::milliseconds(NeighborTable::kNeighborTimeoutMs - 1000);
        table.Learn(ip, mac);  // refresh before expiry
        table.Tick(t1);
        CHECK(nullptr != table.Snapshot()->Find(ip));
    }

    void TestConcurrentLearnTickRead() {
        NeighborTable table;
        std::atomic<bool> stop{false};

        std::thread learner([&] {
            for (int i = 0; i < 20000; ++i) {
                const IpAddress ip = MakeV4(172, 16, 0, static_cast<uint8_t>(i & 0xFF));
                const std::array<uint8_t, 6> mac{0x02, 0x00, 0, 0,
                                                 static_cast<uint8_t>(i >> 8),
                                                 static_cast<uint8_t>(i & 0xFF)};
                table.Learn(ip, mac);
            }
            stop.store(true);
        });

        std::thread ticker([&] {
            auto now = std::chrono::steady_clock::now();
            while (!stop.load()) {
                table.Tick(now);
                now += std::chrono::milliseconds(1);
                std::this_thread::yield();
            }
            table.Tick(now);
        });
        learner.join();
        ticker.join();

        // Final state must contain every learned address (convergence).
        auto snap = table.Snapshot();
        int found = 0;
        for (int i = 0; i < 256; ++i) {
            if (nullptr != snap->Find(MakeV4(172, 16, 0, static_cast<uint8_t>(i)))) {
                ++found;
            }
        }
        CHECK(found == 256);
    }

void TestPendingCap() {
        NeighborTable table;
        const auto now = std::chrono::steady_clock::now();
        const std::array<uint8_t, 6> mac{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01};
        // Feed more unique IPs than the cap: the overflow must be refused and
        // pending must stay clamped at kMaxPendingNeighbors.
        const uint32_t n = NeighborTable::kMaxPendingNeighbors + 123u;
        for (uint32_t i = 0; i < n; ++i) {
            const uint8_t wire[4] = {
                static_cast<uint8_t>(i >> 16), static_cast<uint8_t>(i >> 8),
                static_cast<uint8_t>(i), 0x01};
            table.Learn(IpAddress::FromV4BigEndian(wire), mac);
        }
        CHECK(NeighborTable::kMaxPendingNeighbors == table.PendingUpdates());
        // batch34i: the refusals must be COUNTED. While the guard is saturated
        // a legitimate new device cannot be resolved at all - that used to
        // leave no trace in any counter, log or UI.
        CHECK(table.RejectedCount() == 123u);

        // An IP already at the cap still gets refreshed (no churn for an
        // established client whose slot would otherwise be stolen). H1 caps
        // the PUBLISHED table (see TestTableCap), so snapshot survival of the
        // flooded keys is no longer asserted here: refresh acceptance is
        // observable as the pending count staying clamped at the cap, and the
        // publish step must honor the published cap.
        const uint8_t wire[4] = {0, 0, 0, 0x01};
        table.Learn(IpAddress::FromV4BigEndian(wire), mac);
        CHECK(NeighborTable::kMaxPendingNeighbors == table.PendingUpdates());
        // Refreshing an EXISTING ip is not a refusal.
        CHECK(table.RejectedCount() == 123u);
        table.Tick(now);
        CHECK(NeighborTable::kMaxNeighbors == table.Size());
    }

    /// H1: published-table cap. Fills exactly kMaxNeighbors (two entries get
    /// distinct older last_seen values), verifies the boundary performs no
    /// eviction, then overflows twice (oldest-first eviction + monotonic
    /// counter) and finally proves an in-cap refresh neither grows the table
    /// nor evicts.
    void TestTableCap() {
        NeighborTable table;
        const auto t0 = std::chrono::steady_clock::now();

        // Two oldest entries with strictly increasing last_seen. Addresses
        // encode (10, 0, hi, lo) so 12 bits give 4096 unique v4 keys.
        const uint8_t oldest_wire[4] = {10, 0, 0, 0};
        const uint8_t second_oldest[4] = {10, 0, 0, 1};
        table.Learn(IpAddress::FromV4BigEndian(oldest_wire),
                    std::array<uint8_t, 6>{0x02, 0x00, 0x00, 0x00, 0x00, 0x01});
        table.Tick(t0);
        table.Learn(IpAddress::FromV4BigEndian(second_oldest),
                    std::array<uint8_t, 6>{0x02, 0x00, 0x00, 0x00, 0x00, 0x02});
        table.Tick(t0 + std::chrono::milliseconds(1));

        // Fill the remaining slots in one batch: they all carry the same
        // (newer) Tick timestamp, so the two roots above stay the oldest.
        for (size_t i = 2; i < NeighborTable::kMaxNeighbors; ++i) {
            const uint8_t wire[4] = {10, 0, static_cast<uint8_t>(i >> 8),
                                     static_cast<uint8_t>(i)};
            const std::array<uint8_t, 6> mac{
                0x02, 0x00, static_cast<uint8_t>(i >> 8),
                static_cast<uint8_t>(i), 0x00, 0x01};
            table.Learn(IpAddress::FromV4BigEndian(wire), mac);
        }
        table.Tick(t0 + std::chrono::milliseconds(2));

        // Boundary: exactly at the cap -> no eviction yet.
        CHECK(NeighborTable::kMaxNeighbors == table.Size());
        CHECK(0 == table.EvictedCount());

        // cap+1-th unique neighbor: stay at the cap, evict the OLDEST entry
        // ({10,0,0,0}, last_seen == t0).
        const uint8_t newest_wire[4] = {10, 0xFF, 0xFF, 0xFF};
        table.Learn(IpAddress::FromV4BigEndian(newest_wire),
                    std::array<uint8_t, 6>{0x02, 0xEE, 0x00, 0x00, 0x00, 0x01});
        table.Tick(t0 + std::chrono::milliseconds(3));
        CHECK(NeighborTable::kMaxNeighbors == table.Size());
        CHECK(1 == table.EvictedCount());
        CHECK(nullptr ==
              table.Snapshot()->Find(IpAddress::FromV4BigEndian(oldest_wire)));
        CHECK(nullptr != table.Snapshot()->Find(
                            IpAddress::FromV4BigEndian(newest_wire)));

        // Second overflow: monotonic counter, the next-oldest entry
        // ({10,0,0,1}, last_seen == t0+1ms) is the one dropped.
        const uint8_t newer_wire[4] = {10, 0xFF, 0xFF, 0xFE};
        table.Learn(IpAddress::FromV4BigEndian(newer_wire),
                    std::array<uint8_t, 6>{0x02, 0xEE, 0x00, 0x00, 0x00, 0x02});
        table.Tick(t0 + std::chrono::milliseconds(4));
        CHECK(NeighborTable::kMaxNeighbors == table.Size());
        CHECK(2 == table.EvictedCount());
        CHECK(nullptr == table.Snapshot()->Find(
                            IpAddress::FromV4BigEndian(second_oldest)));

        // Refresh 64 existing entries while exactly at the cap: no growth,
        // no eviction (an in-cap refresh must never displace any entry).
        for (size_t i = 0; i < 64; ++i) {
            const uint8_t wire[4] = {10, 0, 0,
                                     static_cast<uint8_t>(100 + i)};
            const std::array<uint8_t, 6> mac{0x02, 0x00, 0x00, 0, 0, 0x02};
            table.Learn(IpAddress::FromV4BigEndian(wire), mac);
            table.Tick(t0 + std::chrono::milliseconds(5 + i));
        }
        CHECK(NeighborTable::kMaxNeighbors == table.Size());
        CHECK(2 == table.EvictedCount());
    }

    /// batch243: the aging boundary. The contract is `age_ms > timeout`
    /// evicts, so an entry aged EXACTLY `kNeighborTimeoutMs` must survive.
    /// Without an exact-boundary probe, `>` / `>=` are indistinguishable -
    /// and `>=` would silently shave one tick off every entry's lifetime.
    void TestAgingBoundaryIsExclusive() {
        NeighborTable table;
        const auto t0 = std::chrono::steady_clock::now();
        const uint8_t wire[4] = {10, 0, 0, 7};
        const IpAddress ip = IpAddress::FromV4BigEndian(wire);
        table.Learn(ip, std::array<uint8_t, 6>{0x02, 0x00, 0x00, 0x00, 0x00, 0x07});
        table.Tick(t0);
        CHECK(nullptr != table.Snapshot()->Find(ip));

        const auto timeout =
            std::chrono::milliseconds(NeighborTable::kNeighborTimeoutMs);

        // Exactly at the timeout: still present (the comparison is strict).
        table.Tick(t0 + timeout);
        CHECK(nullptr != table.Snapshot()->Find(ip));

        // One millisecond past: evicted.
        table.Tick(t0 + timeout + std::chrono::milliseconds(1));
        CHECK(nullptr == table.Snapshot()->Find(ip));
    }

    /// batch243: Learn() must stamp kLearned. Every earlier case only checked
    /// the MAC (or presence), so a state forced to kPending stayed invisible -
    /// and a kPending entry means "probe sent, awaiting reply" to the rest of
    /// the control plane, which would suppress future probes for a neighbour
    /// that was in fact resolved passively.
    void TestLearnStampsLearnedState() {
        NeighborTable table;
        const auto t0 = std::chrono::steady_clock::now();
        const uint8_t wire[4] = {10, 0, 0, 9};
        const IpAddress ip = IpAddress::FromV4BigEndian(wire);
        const std::array<uint8_t, 6> mac{0x02, 0x00, 0x00, 0x00, 0x00, 0x09};
        table.Learn(ip, mac);
        table.Tick(t0);

        const NeighborEntry* entry = table.Snapshot()->Find(ip);
        CHECK(nullptr != entry);
        if (nullptr != entry) {
            CHECK(NeighborState::kLearned == entry->state);
            CHECK(entry->mac == mac);
        }

        // Re-learning an existing address keeps kLearned (not sticky kPending).
        table.Learn(ip, mac);
        table.Tick(t0 + std::chrono::milliseconds(5));
        entry = table.Snapshot()->Find(ip);
        CHECK(nullptr != entry);
        if (nullptr != entry) {
            CHECK(NeighborState::kLearned == entry->state);
        }
    }

}  // namespace

int main() {
    TestLearnFind();
    TestAging();
    TestRefreshKeepsAlive();
    TestConcurrentLearnTickRead();
    TestPendingCap();
    TestTableCap();
    TestAgingBoundaryIsExclusive();
    TestLearnStampsLearnedState();
    if (0 == g_failures) {
        std::puts("test_neighbors: ALL PASS");
        return 0;
    }
    std::fprintf(stderr, "test_neighbors: %d FAILURES\n", g_failures);
    return 1;
}
