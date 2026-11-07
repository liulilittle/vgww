// ============================================================================
// test_random.cpp - CSPRNG plumbing sanity.
//
// Pins: RandomHex emits exactly 2*byte_len lowercase hex characters; a zero
// length (and an oversized one) yields the empty string; two calls differ
// (128 bits of output, so a collision is cryptographic evidence of breakage
// rather than a flaky assertion); CsprngBytes fills distinct buffers.
// ============================================================================
#include "core/random.h"

#include <cstring>
#include <cstdio>
#include <string>
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

    bool IsLowerHex(const std::string& s) {
        for (const char c : s) {
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
                return false;
            }
        }
        return true;
    }

    void TestRandomHexShape() {
        const std::string t = vgww::core::RandomHex(16);
        CHECK(t.size() == 32);
        CHECK(IsLowerHex(t));
    }

    void TestRandomHexBounds() {
        CHECK(vgww::core::RandomHex(0).empty());
        CHECK(vgww::core::RandomHex(5000).empty());  // > kMaxHexBytes
    }

    void TestRandomHexDistinct() {
        const std::string a = vgww::core::RandomHex(16);
        const std::string b = vgww::core::RandomHex(16);
        CHECK(a != b);
    }

    void TestCsprngBytes() {
        std::vector<uint8_t> a(32, 0xAA);
        std::vector<uint8_t> b(32, 0x55);
        CHECK(vgww::core::CsprngBytes(a.data(), a.size()));
        CHECK(vgww::core::CsprngBytes(b.data(), b.size()));
        CHECK(0 != std::memcmp(a.data(), b.data(), a.size()));
        CHECK(vgww::core::CsprngBytes(nullptr, 0));   // no-op is success
        CHECK(!vgww::core::CsprngBytes(nullptr, 8));  // null with n>0
        CHECK(!vgww::core::CsprngBytes(a.data(), 2 * 1024 * 1024));  // > max
    }

}  // namespace

int main() {
    TestRandomHexShape();
    TestRandomHexBounds();
    TestRandomHexDistinct();
    TestCsprngBytes();
    if (0 == g_failures) {
        std::puts("test_random: ALL PASS");
        return 0;
    }
    std::fprintf(stderr, "test_random: %d FAILURES\n", g_failures);
    return 1;
}
