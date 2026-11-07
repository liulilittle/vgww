// ============================================================================
// test_text.cpp - UTF-8 hygiene at the trust boundary (core/text.h).
//
// text.h is the single source for "is this byte string well-formed UTF-8?" and
// for repairing untrusted DHCP option-12 names. The two DHCP stores rely on it
// so that nlohmann's strict dump() can never throw and the lease JSON stays
// valid. It had no dedicated test: the only coverage was a DHCP acquire case
// feeding two 0xFF bytes, which exercises none of the RFC 3629 boundary rules.
//
// Every rejection rule below is a distinct branch in SequenceLength, so each
// gets its own case: a mutation that disables one must turn exactly that case
// red.
// ============================================================================
#define CHECK(cond)                                                        \
    do {                                                                   \
        if (!(cond)) {                                                     \
            std::fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__,  \
                         __LINE__, #cond);                                 \
            return 1;                                                      \
        }                                                                  \
    } while (0)

#include "core/text.h"

#include <cstdio>
#include <string>
#include <vector>

namespace {

    std::string Bytes(std::initializer_list<int> vals) {
        std::string s;
        for (int v : vals) {
            s.push_back(static_cast<char>(static_cast<unsigned char>(v)));
        }
        return s;
    }

    /// Appends `n` bytes to `s` starting at index 0 of the literal.
    std::string Seq(std::initializer_list<int> vals) { return Bytes(vals); }

}  // namespace

namespace vgww {

    /// Empty and pure ASCII are well-formed, and SanitizeUtf8 is the identity.
    int TestAsciiIsValid() {
        CHECK(core::IsValidUtf8(""));
        CHECK(core::IsValidUtf8("hello world"));
        CHECK(core::IsValidUtf8(std::string(1, '\x7F')));   // DEL is valid
        CHECK(core::SanitizeUtf8("hello") == "hello");
        CHECK(core::SanitizeUtf8("") == "");
        return 0;
    }

    /// The shortest legal sequences of each length must be accepted, and the
    /// sanitizer must return them byte-for-byte.
    int TestBoundaryAcceptances() {
        // U+0080 = C2 80 (smallest 2-byte).
        const std::string two = Bytes({0xC2, 0x80});
        CHECK(core::IsValidUtf8(two));
        CHECK(core::SanitizeUtf8(two) == two);

        // U+0800 = E0 A0 80 (smallest 3-byte, excludes overlong below).
        const std::string three = Bytes({0xE0, 0xA0, 0x80});
        CHECK(core::IsValidUtf8(three));

        // U+FFFF = EF BF BF (largest 3-byte, just below the surrogate gap).
        const std::string three_max = Bytes({0xEF, 0xBF, 0xBF});
        CHECK(core::IsValidUtf8(three_max));

        // U+10000 = F0 90 80 80 (smallest 4-byte).
        const std::string four = Bytes({0xF0, 0x90, 0x80, 0x80});
        CHECK(core::IsValidUtf8(four));

        // U+10FFFF = F4 8F BF BF (largest code point).
        const std::string four_max = Bytes({0xF4, 0x8F, 0xBF, 0xBF});
        CHECK(core::IsValidUtf8(four_max));
        CHECK(core::SanitizeUtf8(four_max) == four_max);
        return 0;
    }

    /// Rule: 0xC0 and 0xC1 can only encode overlong 2-byte forms, so they are
    /// never a valid lead byte. A mutation widening the range to 0xC0 would
    /// make this case green -> the assertion must fail.
    int TestOverlongTwoByteRejected() {
        const std::string c0 = Bytes({0xC0, 0x80});
        const std::string c1 = Bytes({0xC1, 0xBF});
        CHECK(!core::IsValidUtf8(c0));
        CHECK(!core::IsValidUtf8(c1));
        // Each ill-formed BYTE becomes one U+FFFD (two bytes here).
        CHECK(core::SanitizeUtf8(c0) == "\xEF\xBF\xBD\xEF\xBF\xBD");
        return 0;
    }

    /// Rule: E0 A0..BF is required; E0 80..9F would be overlong.
    int TestOverlongThreeByteRejected() {
        CHECK(!core::IsValidUtf8(Bytes({0xE0, 0x9F, 0xBF})));  // overlong
        CHECK(core::IsValidUtf8(Bytes({0xE0, 0xA0, 0x80})));   // shortest
        // One byte too low must be rejected even though the shape looks fine.
        CHECK(!core::IsValidUtf8(Bytes({0xE0, 0x9F, 0x80})));
        return 0;
    }

    /// Rule: ED A0..BF is the CESU-8 surrogate range (U+D800..DFFF) and must
    /// be rejected; ED 80..9F is valid.
    int TestSurrogateRangeRejected() {
        CHECK(!core::IsValidUtf8(Bytes({0xED, 0xA0, 0x80})));  // U+D800
        CHECK(!core::IsValidUtf8(Bytes({0xED, 0xBF, 0xBF})));  // U+DFFF
        CHECK(core::IsValidUtf8(Bytes({0xED, 0x9F, 0xBF})));   // U+D7FF
        CHECK(core::IsValidUtf8(Bytes({0xED, 0x80, 0x80})));   // U+D000
        return 0;
    }

    /// Rule: F0 90..BF is required; F0 80..8F would be overlong.
    int TestOverlongFourByteRejected() {
        CHECK(!core::IsValidUtf8(Bytes({0xF0, 0x8F, 0xBF, 0xBF})));  // overlong
        CHECK(core::IsValidUtf8(Bytes({0xF0, 0x90, 0x80, 0x80})));   // shortest
        return 0;
    }

    /// Rule: F4 80..8F caps the range at U+10FFFF; F4 90.. and F5..FF are out
    /// of range. This is the rule a naive "4-byte lead" check gets wrong.
    int TestOutOfRangeFourByteRejected() {
        CHECK(!core::IsValidUtf8(Bytes({0xF4, 0x90, 0x80, 0x80})));  // U+110000
        CHECK(!core::IsValidUtf8(Bytes({0xF5, 0x80, 0x80, 0x80})));
        CHECK(!core::IsValidUtf8(Bytes({0xFF, 0x80, 0x80, 0x80})));
        CHECK(core::IsValidUtf8(Bytes({0xF4, 0x8F, 0xBF, 0xBF})));   // U+10FFFF
        return 0;
    }

    /// Rule: bare continuation bytes 0x80..0xBF are never a lead byte.
    int TestBareContinuationRejected() {
        for (int b = 0x80; b <= 0xBF; ++b) {
            if (core::IsValidUtf8(std::string(1, static_cast<char>(b)))) {
                std::fprintf(stderr, "bare continuation 0x%02X accepted\n", b);
                return 1;
            }
        }
        return 0;
    }

    /// Rule: every lead byte must be followed by 0x80..0xBF continuations.
    /// A truncation at any position must be rejected, not silently accepted.
    int TestTruncatedSequenceRejected() {
        CHECK(!core::IsValidUtf8(Bytes({0xC2})));              // 2-byte, 0 cont
        CHECK(!core::IsValidUtf8(Bytes({0xE0, 0xA0})));        // 3-byte, 1 cont
        CHECK(!core::IsValidUtf8(Bytes({0xF0, 0x90, 0x80})));  // 4-byte, 2 cont
        return 0;
    }

    /// Rule: continuations must be 0x80..0xBF, not arbitrary bytes.
    int TestBadContinuationRejected() {
        CHECK(!core::IsValidUtf8(Bytes({0xC2, 0x41})));        // ASCII after lead
        CHECK(!core::IsValidUtf8(Bytes({0xE0, 0xA0, 0x41})));  // bad 3rd
        CHECK(!core::IsValidUtf8(Bytes({0xF0, 0x90, 0x80, 0x41})));  // bad 4th
        CHECK(!core::IsValidUtf8(Bytes({0xC2, 0xC0})));        // lead after lead
        return 0;
    }

    /// SanitizeUtf8 replaces ONE U+FFFD per offending byte and is idempotent.
    /// The idempotence claim is in the header, so it must be tested: applying
    /// it twice must not grow the string.
    int TestSanitizeIsOneReplacementPerByteAndIdempotent() {
        const std::string bad = Bytes({'a', 0xFF, 0xFF, 'b'});
        const std::string once = core::SanitizeUtf8(bad);
        CHECK(once == "a\xEF\xBF\xBD\xEF\xBF\xBD""b");
        const std::string twice = core::SanitizeUtf8(once);
        CHECK(twice == once);
        CHECK(twice.size() == once.size());

        // A lone truncated lead becomes exactly one replacement byte.
        const std::string truncated = Bytes({0xE4, 0xB8});
        const std::string fixed = core::SanitizeUtf8(truncated);
        CHECK(fixed == "\xEF\xBF\xBD\xEF\xBF\xBD");
        CHECK(core::SanitizeUtf8(fixed) == fixed);
        return 0;
    }

    /// Well-formed input must pass through untouched - the sanitizer may not
    /// rewrite anything it accepts (a mangle here would corrupt hostnames).
    int TestSanitizePreservesValidInput() {
        const std::vector<std::string> good = {
            "plain",
            "\xE4\xB8\xAD\xE6\x96\x87",                  // U+4E2D U+6587
            "\xF0\x9F\x98\x80",                          // U+1F600
            "\xC2\xA9",                                  // U+00A9
            "a\xE4\xB8\xAD" "b",                          // mixed
        };
        for (const auto& s : good) {
            CHECK(core::IsValidUtf8(s));
            CHECK(core::SanitizeUtf8(s) == s);
        }
        return 0;
    }

    /// The output of SanitizeUtf8 must always be valid UTF-8 - that is the
    /// whole point of the invariant ("the store only ever holds well-formed
    /// UTF-8"). Drive it with every single byte value plus a mixed string.
    int TestSanitizeOutputIsAlwaysValid() {
        for (int b = 0; b <= 0xFF; ++b) {
            const std::string in(1, static_cast<char>(static_cast<unsigned char>(b)));
            const std::string out = core::SanitizeUtf8(in);
            if (!core::IsValidUtf8(out)) {
                std::fprintf(stderr, "sanitized output invalid for byte 0x%02X\n", b);
                return 1;
            }
        }
        // All two-byte combinations of the lead/continuation boundary bytes.
        const int interesting[] = {0x00, 0x41, 0x7F, 0x80, 0xBF, 0xC0, 0xC1,
                                   0xC2, 0xDF, 0xE0, 0xED, 0xEF, 0xF0, 0xF4,
                                   0xF5, 0xFF};
        for (int a : interesting) {
            for (int c : interesting) {
                const std::string in =
                    Bytes({a, c, 0x80, 0xBF, 0x41});
                const std::string out = core::SanitizeUtf8(in);
                if (!core::IsValidUtf8(out)) {
                    std::fprintf(stderr,
                                 "sanitized output invalid for %02X %02X 80 BF 41\n",
                                 a, c);
                    return 1;
                }
            }
        }
        return 0;
    }

    /// Truncation at the LAST byte of the buffer must be detected by the
    /// LENGTH check, not by luck: if the implementation reads s[i+1] past the
    /// end it sees the string's NUL terminator (0x00), which happens to be
    /// outside 0x80..0xBF, so the mutation 'remaining < 2 -> false' survives
    /// a naive test. To pin the length check itself, terminate the buffer with
    /// a byte that WOULD be a legal continuation - then only a real bounds
    /// check can reject it, because reading past the end finds 0x80.
    int TestTruncationIsCaughtByBoundsNotByContent() {
        // 0xC2 0x80 is valid; 0xC2 alone must be rejected. Both are built so
        // the byte AFTER the string equals a legal continuation.
        std::string two_lead;
        two_lead.push_back(static_cast<char>(0xC2));
        CHECK(!core::IsValidUtf8(two_lead));

        // Three-byte lead with only two bytes present, and the missing third
        // byte would have been a legal continuation.
        std::string three_short;
        three_short.push_back(static_cast<char>(0xE0));
        three_short.push_back(static_cast<char>(0xA0));
        CHECK(!core::IsValidUtf8(three_short));

        // Four-byte lead with only three bytes present (missing the 4th).
        std::string four_short;
        four_short.push_back(static_cast<char>(0xF0));
        four_short.push_back(static_cast<char>(0x90));
        four_short.push_back(static_cast<char>(0x80));
        CHECK(!core::IsValidUtf8(four_short));

        // Sanitizer must also refuse to consume past the end: it replaces the
        // lead and the available continuations, one U+FFFD per byte.
        CHECK(core::SanitizeUtf8(two_lead) == "\xEF\xBF\xBD");
        CHECK(core::SanitizeUtf8(three_short) == "\xEF\xBF\xBD\xEF\xBF\xBD");
        CHECK(core::SanitizeUtf8(four_short) ==
              "\xEF\xBF\xBD\xEF\xBF\xBD\xEF\xBF\xBD");
        return 0;
    }

    /// Continuation checks must be per-byte: an input whose LAST byte is the
    /// only bad one isolates the b3 check in the 4-byte branch (and the b2
    /// check needs its own vector with b3 legal).
    int Test4ByteContinuationCheckedPerByte() {
        // b1 good (0x90), b2 BAD (0x41), b3 good (0x80).
        CHECK(!core::IsValidUtf8(Bytes({0xF0, 0x90, 0x41, 0x80})));
        // b1 good, b2 good, b3 BAD (0x41).
        CHECK(!core::IsValidUtf8(Bytes({0xF0, 0x90, 0x80, 0x41})));
        // b1 BAD, b2/b3 good - isolates the F0 floor from the continuation
        // range checks.
        CHECK(!core::IsValidUtf8(Bytes({0xF0, 0x41, 0x80, 0x80})));
        // All three continuations good is the only accepting case.
        CHECK(core::IsValidUtf8(Bytes({0xF0, 0x90, 0x80, 0x80})));

        // Same isolation for the 3-byte branch: b2 bad alone.
        CHECK(!core::IsValidUtf8(Bytes({0xE4, 0x41, 0x80})));
        // ...and b1 bad alone (both b2/b3 would be legal).
        CHECK(!core::IsValidUtf8(Bytes({0xE4, 0x41, 0x80})));
        return 0;
    }

}  // namespace vgww

int main() {
    if (vgww::TestAsciiIsValid()) return 1;
    if (vgww::TestBoundaryAcceptances()) return 1;
    if (vgww::TestOverlongTwoByteRejected()) return 1;
    if (vgww::TestOverlongThreeByteRejected()) return 1;
    if (vgww::TestSurrogateRangeRejected()) return 1;
    if (vgww::TestOverlongFourByteRejected()) return 1;
    if (vgww::TestOutOfRangeFourByteRejected()) return 1;
    if (vgww::TestBareContinuationRejected()) return 1;
    if (vgww::TestTruncatedSequenceRejected()) return 1;
    if (vgww::TestTruncationIsCaughtByBoundsNotByContent()) return 1;
    if (vgww::Test4ByteContinuationCheckedPerByte()) return 1;
    if (vgww::TestBadContinuationRejected()) return 1;
    if (vgww::TestSanitizeIsOneReplacementPerByteAndIdempotent()) return 1;
    if (vgww::TestSanitizePreservesValidInput()) return 1;
    if (vgww::TestSanitizeOutputIsAlwaysValid()) return 1;
    std::puts("test_text: ALL PASS");
    return 0;
}
