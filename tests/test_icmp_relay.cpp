// ============================================================================
// test_icmp_relay.cpp - ICMP relay tag allocator semantics.
//
// Pins: tags are unique while live; Consume is one-shot (a replayed echo
// reply cannot consume twice); expired tags are rejected and swept; the
// allocator gives up (0) instead of overwriting live entries when full.
// ============================================================================
#include "relay/icmp_relay.h"

#include <cstdio>

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

    using namespace vgww::net;
    using TagAllocator = vgww::relay::IcmpRelay::TagAllocator;
    typedef vgww::relay::IcmpRelay::TagEntry TagEntry;
    using clock = std::chrono::steady_clock;

    TagEntry MakeEntry(uint8_t last_octet) {
        TagEntry e;
        const uint8_t wire[4] = {10, 0, 0, last_octet};
        e.client_ip = IpAddress::FromV4BigEndian(wire);
        e.original_id = 0x1234;
        e.client_mac = {0xAA, 0x11, 0x22, 0x33, 0x44, last_octet};
        return e;
    }

    void TestLifecycleAndReplay() {
        auto& alloc = TagAllocator::Instance();
        const auto t0 = clock::now();
        const TagEntry e1 = MakeEntry(1);
        const TagEntry e2 = MakeEntry(2);

        const uint16_t tag1 = alloc.Allocate(e1, t0);
        const uint16_t tag2 = alloc.Allocate(e2, t0);
        CHECK(0 != tag1);
        CHECK(0 != tag2);
        CHECK(tag1 != tag2);  // live tags are unique

        // First consume hits and returns the original NAT identity.
        TagEntry got{};
        CHECK(alloc.Consume(tag1, got, t0));
        CHECK(got.client_ip == e1.client_ip);
        CHECK(got.original_id == e1.original_id);
        // A replayed reply (old tag again) must fail: one-shot semantics.
        CHECK(!alloc.Consume(tag1, got, t0));
        // A tag the allocator has never handed out must fail too. (Beware: the
        // allocator hands tags out consecutively, so tag1+1 would BE tag2.)
        CHECK(!alloc.Consume(static_cast<uint16_t>(60000), got, t0));

        // An expired tag must not consume either. tags live for 3 seconds.
        CHECK(alloc.Consume(tag2, got, t0 + std::chrono::seconds(2)));
        CHECK(!alloc.Consume(tag2, got, t0 + std::chrono::seconds(5)));
    }

    void TestExpirySweep() {
        auto& alloc = TagAllocator::Instance();
        const clock::time_point t0 = clock::now() - std::chrono::seconds(30);
        const TagEntry e = MakeEntry(3);
        const uint16_t tag = alloc.Allocate(e, t0);  // already expired-ish
        CHECK(0 != tag);
        // Sweep removes by the stored 3s window.
        const size_t removed = alloc.Sweep(t0 + std::chrono::seconds(10));
        CHECK(1 == removed);
        TagEntry got{};
        CHECK(!alloc.Consume(tag, got, t0 + std::chrono::seconds(10)));
    }

    /// batch299: every released tag must return to the pool. The invariant
    /// InFlight() + Free() == 65535 holds after every operation, and a tag
    /// freed by Consume (hit or expired) or Sweep is handed out again.
    void TestFreeListReuseAfterConsume() {
        auto& alloc = TagAllocator::Instance();
        const auto t0 = clock::now();
        const uint16_t known = alloc.Allocate(MakeEntry(4), t0);
        CHECK(0 != known);
        size_t live = 1;
        while (0 != alloc.Allocate(MakeEntry(5), t0)) {
            if (++live > 70000) break;
        }
        CHECK(65535 == live);
        CHECK(0 == alloc.Allocate(MakeEntry(5), t0));   // pool is full
        CHECK(65535 == alloc.InFlight());
        CHECK(0 == alloc.Free());
        CHECK(alloc.InFlight() + alloc.Free() == 65535);

        TagEntry got{};
        CHECK(alloc.Consume(known, got, t0));
        CHECK(alloc.InFlight() + alloc.Free() == 65535);
        CHECK(1 == alloc.Free());
        // The freed tag must be reusable immediately (the old allocator also
        // erased the entry on Consume, so this preserves its semantics).
        CHECK(0 != alloc.Allocate(MakeEntry(6), t0));
        CHECK(alloc.InFlight() + alloc.Free() == 65535);

        alloc.Sweep(t0 + std::chrono::seconds(10));
        CHECK(0 == alloc.InFlight());
        CHECK(65535 == alloc.Free());
    }

    void TestFreeListReuseAfterExpiredConsume() {
        auto& alloc = TagAllocator::Instance();
        const auto t0 = clock::now();
        const uint16_t tag = alloc.Allocate(MakeEntry(7), t0);
        CHECK(0 != tag);
        TagEntry got{};
        // Expired: refused, but the slot must go back to the pool.
        CHECK(!alloc.Consume(tag, got, t0 + std::chrono::seconds(10)));
        CHECK(0 == alloc.InFlight());
        CHECK(65535 == alloc.Free());
    }

    void TestFreeListReuseAfterSweep() {
        auto& alloc = TagAllocator::Instance();
        const auto t0 = clock::now();
        CHECK(0 != alloc.Allocate(MakeEntry(8), t0));
        CHECK(1 == alloc.InFlight());
        CHECK(1 == alloc.Sweep(t0 + std::chrono::seconds(10)));
        CHECK(0 == alloc.InFlight());
        CHECK(65535 == alloc.Free());
        CHECK(0 != alloc.Allocate(MakeEntry(9), t0));
        alloc.Sweep(t0 + std::chrono::seconds(10));
        CHECK(65535 == alloc.Free());
    }

    void TestGiveUpWhenFull() {
        auto& alloc = TagAllocator::Instance();
        const clock::time_point t0 = clock::now();
        size_t live = 0;
        uint16_t tag = 0;
        // Fill every usable tag (65535; tag 0 is reserved). The allocator
        // must give up rather than overwrite a live entry.
        while (true) {
            tag = alloc.Allocate(MakeEntry(9), t0);
            if (0 == tag) {
                break;
            }
            ++live;
            if (live > 70000) {
                break;  // safety: something is broken if we never exhaust
            }
        }
        CHECK(live > 0);
        CHECK(live <= 65535);
    }

}  // namespace

int main() {
    TestLifecycleAndReplay();
    TestExpirySweep();
    TestFreeListReuseAfterConsume();
    TestFreeListReuseAfterExpiredConsume();
    TestFreeListReuseAfterSweep();
    TestGiveUpWhenFull();  // last: leaves the allocator table full
    if (0 == g_failures) {
        std::puts("test_icmp_relay: ALL PASS");
        return 0;
    }
    std::fprintf(stderr, "test_icmp_relay: %d FAILURES\n", g_failures);
    return 1;
}
