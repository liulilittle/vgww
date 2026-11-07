// ============================================================================
// test_rate_limiter.cpp - Per-client token-bucket admission semantics.
//
// Pins: empty rules pass everything; a zero kbps cap means no cap for that
// direction; an unconfigured client passes; a configured client bursts up to
// its capacity then must refill over time; uplink/downlink are independent.
// ============================================================================
#include "tables/rate_limiter.h"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <new>
#include <vector>

// batch301: one-shot allocation failure on the CALLING thread only, so the
// noexcept-survival test is deterministic.
static thread_local bool g_throw_next_alloc = false;

void* operator new(size_t size) {
    if (g_throw_next_alloc) {
        g_throw_next_alloc = false;
        throw std::bad_alloc();
    }
    void* p = std::malloc(size ? size : 1);
    if (nullptr == p) {
        throw std::bad_alloc();
    }
    return p;
}

void* operator new[](size_t size) { return ::operator new(size); }
void operator delete(void* p) noexcept { std::free(p); }
void operator delete[](void* p) noexcept { std::free(p); }
void operator delete(void* p, size_t) noexcept { std::free(p); }
void operator delete[](void* p, size_t) noexcept { std::free(p); }

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
    using namespace vgww::tables;
    using clock = std::chrono::steady_clock;

    const WireMac kMac{0xAA, 0x11, 0x22, 0x33, 0x44, 0x55};
    const WireMac kOther{0xBB, 0x11, 0x22, 0x33, 0x44, 0x55};

    void TestNoRules() {
        RateLimiter lr;
        const auto t0 = clock::now();
        CHECK(lr.AllowUplink(kMac, 1500, t0));
        CHECK(lr.AllowDownlink(kMac, 1500, t0));
        CHECK(lr.AllowUplink(kMac, 100000, t0));  // no policy: everything
    }

    void TestUnconfiguredClientPasses() {
        RateLimiter lr;
        auto rules = std::make_shared<const std::vector<RateLimitRule>>();
        const_cast<std::vector<RateLimitRule>&>(*rules).push_back(
            {kMac, 8, 8});
        lr.SetRules(rules);
        const auto t0 = clock::now();
        CHECK(lr.AllowUplink(kOther, 1500, t0));  // no rule for kOther: pass
    }

    void TestZeroKbpsMeansNoCap() {
        RateLimiter lr;
        auto rules = std::make_shared<const std::vector<RateLimitRule>>();
        const_cast<std::vector<RateLimitRule>&>(*rules).push_back(
            {kMac, 0, 0});  // both directions uncapped
        lr.SetRules(rules);
        const auto t0 = clock::now();
        CHECK(lr.AllowUplink(kMac, 100000, t0));
        CHECK(lr.AllowDownlink(kMac, 100000, t0));
    }

    void TestBucketRefill() {
        // 8 kbps == 1000 bytes/s. Capacity = max(1000 * 1.0s, 1500) = 1500.
        RateLimiter lr(RateLimiterParams{/*burst_seconds*/ 1.0,
                                         /*min_capacity_bytes*/ 1500});
        auto rules = std::make_shared<const std::vector<RateLimitRule>>();
        const_cast<std::vector<RateLimitRule>&>(*rules).push_back(
            {kMac, 8, 8});
        lr.SetRules(rules);

        const auto t0 = clock::now();
        // Fresh bucket starts full: the full burst headroom passes at once.
        CHECK(lr.AllowUplink(kMac, 1500, t0));
        // Now empty: nothing more until the refill.
        CHECK(!lr.AllowUplink(kMac, 1, t0));
        // 0.1 s later the bucket has ~100 bytes.
        const auto t1 = t0 + std::chrono::milliseconds(100);
        CHECK(lr.AllowUplink(kMac, 100, t1));
        CHECK(!lr.AllowUplink(kMac, 1, t1));  // spent again
        // Enough idle time refills to capacity (capped).
        const auto t2 = t0 + std::chrono::seconds(10);
        CHECK(lr.AllowUplink(kMac, 1500, t2));
        CHECK(!lr.AllowUplink(kMac, 1, t2));  // capped at capacity: still spent
        // Downlink is an independent bucket: an unspent downlink still has
        // its full headroom on first use.
        CHECK(lr.AllowDownlink(kMac, 1500, t0 + std::chrono::seconds(1)));
    }

    /// C7: a rule change must immediately re-derive the bucket's capacity and
    /// clamp any burst headroom built up under the OLD (higher) rate. An
    /// 8kbps bucket holds 2000 bytes of headroom; after the drop to 1kbps
    /// that surplus must not survive as an oversized burst.
    void TestRuleChangeRecalculatesCapacity() {
        // burst_seconds=2.0, min floor 100 B: 8kbps capacity = 2000 bytes,
        // 1kbps capacity = 250 bytes.
        RateLimiter lr(RateLimiterParams{2.0, 100});
        auto rules8 = std::make_shared<const std::vector<RateLimitRule>>();
        const_cast<std::vector<RateLimitRule>&>(*rules8).push_back(
            {kMac, 8, 8});
        lr.SetRules(rules8);
        const auto t0 = clock::now();
        // Touch: creates the bucket with the 8kbps capacity and 1999 spare.
        CHECK(lr.AllowUplink(kMac, 1, t0));

        const auto t1 = t0 + std::chrono::seconds(1);
        auto rules1 = std::make_shared<const std::vector<RateLimitRule>>();
        const_cast<std::vector<RateLimitRule>&>(*rules1).push_back(
            {kMac, 1, 1});
        lr.SetRules(rules1);

        const auto t2 = t1 + std::chrono::seconds(2);
        // Under the stale 2000-byte capacity the old headroom would admit a
        // 2000-byte burst; the recalculated 250-byte capacity must refuse it.
        CHECK(!lr.AllowUplink(kMac, 2000, t2));
        // The new headroom (250 B) is still granted.
        CHECK(lr.AllowUplink(kMac, 250, t2));
    }

    void TestIdleBucketsSwept() {
        // Buckets for clients that stopped talking must not accumulate
        // forever (slow memory leak on a busy LAN with rotating devices):
        // SweepIdle drops buckets idle past the TTL; a returning client
        // restarts full (fresh bucket), never throttled by stale state.
        RateLimiter lr(RateLimiterParams{1.0, 1500});
        auto rules = std::make_shared<const std::vector<RateLimitRule>>();
        const_cast<std::vector<RateLimitRule>&>(*rules).push_back(
            {kMac, 8, 8});
        lr.SetRules(rules);
        const auto t0 = clock::now();
        CHECK(lr.AllowUplink(kMac, 100, t0));
        CHECK(lr.BucketCount() == 1);
        // Nothing aged: sweep keeps the bucket.
        lr.SweepIdle(t0 + std::chrono::minutes(1));
        CHECK(lr.BucketCount() == 1);
        // Past the idle TTL: the bucket is reclaimed.
        lr.SweepIdle(t0 + std::chrono::minutes(16));
        CHECK(lr.BucketCount() == 0);
        // A returning client gets a fresh, full bucket (no stale throttling).
        CHECK(lr.AllowUplink(kMac, 1500, t0 + std::chrono::minutes(16)));
        CHECK(lr.BucketCount() == 1);
    }

    /// batch242: uplink and downlink are separate buckets with SEPARATE
    /// rates. Every earlier case configured the same number in both fields,
    /// so a swap (downlink reading uplink_kbps) went unnoticed.
    void TestDirectionsUseTheirOwnRate() {
        // burst_seconds=1, floor 100: 8kbps -> 1000 B, 80kbps -> 10000 B.
        RateLimiter lr(RateLimiterParams{1.0, 100});
        auto rules = std::make_shared<const std::vector<RateLimitRule>>();
        const_cast<std::vector<RateLimitRule>&>(*rules).push_back(
            {kMac, /*uplink_kbps*/ 8, /*downlink_kbps*/ 80});
        lr.SetRules(rules);
        const auto t0 = clock::now();

        // Uplink headroom is 1000: a 1001-byte frame must be refused.
        CHECK(lr.AllowUplink(kMac, 1000, t0));
        CHECK(!lr.AllowUplink(kMac, 1, t0));

        // Downlink headroom is 10000: the same 1001 bytes pass easily.
        CHECK(lr.AllowDownlink(kMac, 1001, t0));
        CHECK(lr.AllowDownlink(kMac, 8999, t0));
        CHECK(!lr.AllowDownlink(kMac, 1, t0));  // 10000 spent exactly

        // Swap the numbers: now uplink is the roomy direction.
        RateLimiter lr2(RateLimiterParams{1.0, 100});
        auto rules2 = std::make_shared<const std::vector<RateLimitRule>>();
        const_cast<std::vector<RateLimitRule>&>(*rules2).push_back(
            {kMac, /*uplink_kbps*/ 80, /*downlink_kbps*/ 8});
        lr2.SetRules(rules2);
        CHECK(lr2.AllowUplink(kMac, 10000, t0));
        CHECK(!lr2.AllowUplink(kMac, 1, t0));
        CHECK(lr2.AllowDownlink(kMac, 1000, t0));
        CHECK(!lr2.AllowDownlink(kMac, 1, t0));
    }

    /// A FRESH bucket has never been charged, so its `last` is default (epoch).
    /// Sweeping on `last` alone would reap it as ancient on the very first
    /// sweep - but a fresh bucket has not cost anything yet, so dropping it is
    /// harmless for accounting; keeping it is what stops a client that only
    /// ever burst once from being re-granted headroom after every sweep.
    void TestFreshBucketSurvivesSweep() {
        RateLimiter lr(RateLimiterParams{1.0, 1500});
        auto rules = std::make_shared<const std::vector<RateLimitRule>>();
        const_cast<std::vector<RateLimitRule>&>(*rules).push_back(
            {kMac, 8, 8});
        lr.SetRules(rules);
        const auto t0 = clock::now();

        // First admission creates a NON-fresh bucket.
        CHECK(lr.AllowUplink(kMac, 100, t0));
        CHECK(1 == lr.BucketCount());

        // A sweep well past the fresh epoch but within the TTL of `t0`
        // keeps it: `last` was stamped on the first admission.
        lr.SweepIdle(t0 + std::chrono::minutes(1));
        CHECK(1 == lr.BucketCount());

        // Now charge it empty and confirm the sweep does not silently refill
        // the headroom (a reap would hand out a fresh full bucket instead).
        CHECK(lr.AllowUplink(kMac, 1400, t0));
        CHECK(!lr.AllowUplink(kMac, 1, t0));
        lr.SweepIdle(t0 + std::chrono::minutes(1));
        CHECK(1 == lr.BucketCount());
        CHECK(!lr.AllowUplink(kMac, 1, t0));
    }

    /// The piggy-backed sweep must actually run. The earlier version of this
    /// test was blind: it kept calling AllowUplink for the SAME mac, so
    /// BucketFor's operator[] re-created the bucket on every call whether or
    /// not the sweep had reaped it. Observe a bucket that is never touched
    /// again instead.
    void TestPiggybackedSweepReclaims() {
        const WireMac idle{0xCC, 0x11, 0x22, 0x33, 0x44, 0x55};
        const WireMac busy{0xDD, 0x11, 0x22, 0x33, 0x44, 0x55};
        RateLimiter lr(RateLimiterParams{1.0, 1500});
        auto rules = std::make_shared<const std::vector<RateLimitRule>>();
        const_cast<std::vector<RateLimitRule>&>(*rules).push_back({idle, 8, 8});
        const_cast<std::vector<RateLimitRule>&>(*rules).push_back({busy, 8, 8});
        lr.SetRules(rules);

        const auto t0 = clock::now();
        CHECK(lr.AllowUplink(idle, 1, t0));   // creates the idle bucket
        CHECK(1 == lr.BucketCount());

        // Drive 1100 admissions for `busy` at a time PAST the idle TTL.
        // The piggy-backed sweep must reap `idle` while `busy` keeps its own
        // bucket alive (it is refreshed every call).
        const auto later = t0 + std::chrono::minutes(20);
        for (int i = 0; i < 1100; ++i) {
            CHECK(lr.AllowUplink(busy, 1, later));
        }
        // Only `busy` survives: the idle one was reclaimed by the cadence.
        CHECK(1 == lr.BucketCount());

        // Proof it was `idle` that went: touching it again recreates it.
        CHECK(lr.AllowUplink(idle, 1, later));
        CHECK(2 == lr.BucketCount());
    }
    /// C7 (the clamp itself): a rule DROP must clamp the stored tokens AT THE
    /// MOMENT of the change. The older case probes two seconds later, after a
    /// refill has already capped them - so removing the clamp inside the
    /// rule-change branch stayed invisible. Probe with elapsed == 0.
    void TestRuleChangeClampsImmediately() {
        // burst_seconds=2, floor 100: 8kbps -> 2000 B; 1kbps -> 250 B.
        RateLimiter lr(RateLimiterParams{2.0, 100});
        auto rules8 = std::make_shared<const std::vector<RateLimitRule>>();
        const_cast<std::vector<RateLimitRule>&>(*rules8).push_back({kMac, 8, 8});
        lr.SetRules(rules8);
        const auto t0 = clock::now();
        CHECK(lr.AllowUplink(kMac, 1, t0));   // bucket holds ~1999 tokens

        auto rules1 = std::make_shared<const std::vector<RateLimitRule>>();
        const_cast<std::vector<RateLimitRule>&>(*rules1).push_back({kMac, 1, 1});
        lr.SetRules(rules1);

        // SAME instant as the touch: elapsed == 0, so the refill branch adds
        // nothing and only the rule-change clamp can bound the tokens. The
        // new capacity is 250, so a 251-byte frame must be refused.
        CHECK(!lr.AllowUplink(kMac, 251, t0));
        CHECK(lr.AllowUplink(kMac, 250, t0));
    }

    /// A bucket whose `last` is in the future (clock skew) must not gain
    /// tokens: elapsed_s is negative and the refill is skipped. It must also
    /// not lose tokens.
    void TestNegativeElapsedIsIgnored() {
        RateLimiter lr(RateLimiterParams{1.0, 1500});
        auto rules = std::make_shared<const std::vector<RateLimitRule>>();
        const_cast<std::vector<RateLimitRule>&>(*rules).push_back({kMac, 8, 8});
        lr.SetRules(rules);

        const auto t0 = clock::now();
        CHECK(lr.AllowUplink(kMac, 1000, t0));   // 500 left
        // Go BACK in time: elapsed is negative, tokens must stay at 500.
        const auto back = t0 - std::chrono::seconds(5);
        CHECK(lr.AllowUplink(kMac, 500, back));  // exactly the remainder
        CHECK(!lr.AllowUplink(kMac, 1, back));
    }

    /// batch303: the index build keeps the FIRST rule for a duplicate MAC,
    /// exactly like the old linear scan (the web loader dedups, but the store
    /// API does not have to).
    void TestDuplicateRulesFirstWins() {
        RateLimiter lr(RateLimiterParams{1.0, 1500});
        auto rules = std::make_shared<const std::vector<RateLimitRule>>();
        auto& v = const_cast<std::vector<RateLimitRule>&>(*rules);
        v.push_back({kMac, 8, 8});        // first: 1000 B/s, capacity 1500
        v.push_back({kMac, 1000, 1000});  // second: must be ignored
        lr.SetRules(rules);
        const auto t0 = clock::now();
        CHECK(lr.AllowUplink(kMac, 1500, t0));   // exactly the capacity
        CHECK(!lr.AllowUplink(kMac, 1, t0));     // 8 kbps is in force
    }

    /// batch303: SetRules builds the index before publishing it. An allocation
    /// failure must leave the PREVIOUS index in force (no half-applied rules).
    void TestSetRulesAllocationFailureKeepsOldIndex() {
        RateLimiter lr(RateLimiterParams{1.0, 1500});
        auto rules = std::make_shared<const std::vector<RateLimitRule>>();
        const_cast<std::vector<RateLimitRule>&>(*rules).push_back({kMac, 8, 8});
        lr.SetRules(rules);
        const auto t0 = clock::now();
        CHECK(lr.AllowUplink(kMac, 1000, t0));   // 500 tokens left

        auto next = std::make_shared<const std::vector<RateLimitRule>>();
        const_cast<std::vector<RateLimitRule>&>(*next).push_back(
            {kMac, 1000, 1000});
        g_throw_next_alloc = true;
        bool threw = false;
        try {
            lr.SetRules(next);
        } catch (const std::bad_alloc&) {
            threw = true;
        }
        CHECK(threw);
        CHECK(!g_throw_next_alloc);
        // One second later the OLD 8 kbps rule must still apply: 500 + 1000
        // tokens, capped at the old 1500-byte capacity, so 2000 is refused.
        // (With the new 1000 kbps rule the capacity would be 125000.)
        CHECK(!lr.AllowUplink(kMac, 2000, t0 + std::chrono::seconds(1)));
    }

    /// batch301: Allow is noexcept and runs on the RX/TX thread. A bucket-map
    /// allocation failure used to call std::terminate; it must fail open (the
    /// packet passes) and leave the maps unchanged.
    void TestAllocationFailureFailsOpen() {
        RateLimiter lr;
        auto rules = std::make_shared<const std::vector<RateLimitRule>>();
        const_cast<std::vector<RateLimitRule>&>(*rules).push_back({kMac, 8, 8});
        lr.SetRules(rules);
        const auto t0 = clock::now();
        CHECK(0 == lr.BucketCount());
        g_throw_next_alloc = true;
        CHECK(lr.AllowUplink(kMac, 1500, t0));   // fail open, no terminate
        CHECK(!g_throw_next_alloc);              // the hook fired
        CHECK(0 == lr.BucketCount());            // no partial bucket
        // The next admission works normally (the bucket is created then).
        CHECK(lr.AllowUplink(kMac, 1500, t0));
        CHECK(1 == lr.BucketCount());
    }

}  // namespace

int main() {
    TestNoRules();
    TestUnconfiguredClientPasses();
    TestZeroKbpsMeansNoCap();
    TestBucketRefill();
    TestRuleChangeRecalculatesCapacity();
    TestIdleBucketsSwept();
    TestDirectionsUseTheirOwnRate();
    TestFreshBucketSurvivesSweep();
    TestPiggybackedSweepReclaims();
    TestRuleChangeClampsImmediately();
    TestNegativeElapsedIsIgnored();
    TestAllocationFailureFailsOpen();
    TestDuplicateRulesFirstWins();
    TestSetRulesAllocationFailureKeepsOldIndex();
    if (0 == g_failures) {
        std::puts("test_rate_limiter: ALL PASS");
        return 0;
    }
    std::fprintf(stderr, "test_rate_limiter: %d FAILURES\n", g_failures);
    return 1;
}
