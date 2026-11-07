// ============================================================================
// test_debug_state.cpp - batch249: debug_state.h (Utf16ToUtf8 + the DebugWrite
// overload set) had ZERO direct coverage although 18 product call sites depend
// on it for every string the UI debug channel emits.
//
// Scope note: detail::AppendUtf8 has exactly ONE caller (Utf16ToUtf8:63), and
// an exhaustive enumeration of Utf16ToUtf8's outputs shows the codepoint never
// exceeds U+10FFFF (the surrogate-pair maximum). The >0x10FFFF branch is
// therefore unreachable from the only call site and is NOT treated as a
// defect here; the tests below pin the reachable boundaries instead.
// ============================================================================
#include <cstdio>
#include <cstdint>
#include <string>
#include <vector>

#include "ui/debug/debug_state.h"

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

    using namespace vgww::ui;

    std::string Hex(const std::string& s) {
        static const char* kDigits = "0123456789ABCDEF";
        std::string out;
        for (unsigned char c : s) {
            if (!out.empty()) {
                out.push_back(' ');
            }
            out.push_back(kDigits[c >> 4]);
            out.push_back(kDigits[c & 0x0F]);
        }
        return out;
    }

    // --- UTF-8 byte-length classes (RFC 3629) -------------------------------

    void TestEmptyString() {
        CHECK(Utf16ToUtf8(L"").empty());
    }

    void TestAsciiIsOneByte() {
        CHECK(Utf16ToUtf8(L"A") == "A");
        CHECK(Utf16ToUtf8(L"abc") == "abc");
    }

    void TestOneByteUpperBoundary() {
        // U+007F is the last 1-byte scalar.
        CHECK(Hex(Utf16ToUtf8(L"\u007F")) == "7F");
        // U+0080 is the first 2-byte scalar.
        CHECK(Hex(Utf16ToUtf8(L"\u0080")) == "C2 80");
    }

    void TestTwoByteUpperBoundary() {
        // U+07FF is the last 2-byte scalar: 0xDF 0xBF.
        CHECK(Hex(Utf16ToUtf8(L"\u07FF")) == "DF BF");
        // U+0800 is the first 3-byte scalar: 0xE0 0xA0 0x80.
        CHECK(Hex(Utf16ToUtf8(L"\u0800")) == "E0 A0 80");
    }

    void TestThreeByteUpperBoundary() {
        // U+FFFF is the last 3-byte scalar (a valid noncharacter).
        CHECK(Hex(Utf16ToUtf8(L"\uFFFF")) == "EF BF BF");
    }

    void TestCjkEncodesAsThreeBytes() {
        // The canonical UI case: a CJK adapter name.
        CHECK(Hex(Utf16ToUtf8(L"\u7F51\u5361")) == "E7 BD 91 E5 8D A1");
    }

    // --- surrogate pairs (non-BMP) ------------------------------------------

    void TestSmallestSurrogatePair() {
        // U+10000 = D800 DC00 -> F0 90 80 80.
        std::wstring w;
        w.push_back(static_cast<wchar_t>(0xD800));
        w.push_back(static_cast<wchar_t>(0xDC00));
        CHECK(Hex(Utf16ToUtf8(w)) == "F0 90 80 80");
    }

    void TestLargestSurrogatePair() {
        // U+10FFFF = DBFF DFFF -> F4 8F BF BF. This is the RFC 3629 ceiling and
        // also the maximum this function can ever emit.
        std::wstring w;
        w.push_back(static_cast<wchar_t>(0xDBFF));
        w.push_back(static_cast<wchar_t>(0xDFFF));
        CHECK(Hex(Utf16ToUtf8(w)) == "F4 8F BF BF");
    }

    void TestKnownEmoji() {
        // U+1F600 = D83D DE00 -> F0 9F 98 80.
        std::wstring w;
        w.push_back(static_cast<wchar_t>(0xD83D));
        w.push_back(static_cast<wchar_t>(0xDE00));
        CHECK(Hex(Utf16ToUtf8(w)) == "F0 9F 98 80");
    }

    void TestSurrogatePairConsumesBothUnits() {
        // A pair followed by an ASCII char must yield 4+1 bytes, proving the
        // low surrogate was CONSUMED (not emitted separately).
        std::wstring w;
        w.push_back(static_cast<wchar_t>(0xD83D));
        w.push_back(static_cast<wchar_t>(0xDE00));
        w.push_back(L'A');
        CHECK(Hex(Utf16ToUtf8(w)) == "F0 9F 98 80 41");
    }

    // --- unpaired surrogates -> U+FFFD --------------------------------------

    void TestLoneHighSurrogateBecomesReplacement() {
        std::wstring w;
        w.push_back(static_cast<wchar_t>(0xD800));
        CHECK(Hex(Utf16ToUtf8(w)) == "EF BF BD");
    }

    void TestLoneHighSurrogateAtEndOfLongerString() {
        // The "i + 1 < w.size()" guard: a high surrogate in the LAST slot has
        // no low unit to peek at. It must degrade to U+FFFD, not read past.
        std::wstring w;
        w.push_back(L'A');
        w.push_back(static_cast<wchar_t>(0xD800));
        CHECK(Hex(Utf16ToUtf8(w)) == "41 EF BF BD");
    }

    void TestLoneLowSurrogateBecomesReplacement() {
        std::wstring w;
        w.push_back(static_cast<wchar_t>(0xDC00));
        CHECK(Hex(Utf16ToUtf8(w)) == "EF BF BD");
    }

    void TestHighSurrogateFollowedByNonLowBecomesReplacement() {
        // High surrogate then an ASCII char: the ASCII must survive.
        std::wstring w;
        w.push_back(static_cast<wchar_t>(0xD800));
        w.push_back(L'B');
        CHECK(Hex(Utf16ToUtf8(w)) == "EF BF BD 42");
    }

    void TestHighSurrogateFollowedByAnotherHighBecomesReplacement() {
        std::wstring w;
        w.push_back(static_cast<wchar_t>(0xD800));
        w.push_back(static_cast<wchar_t>(0xD801));
        CHECK(Hex(Utf16ToUtf8(w)) == "EF BF BD EF BF BD");
    }

    void TestSurrogateBoundaryValues() {
        // The exact edges of the surrogate range must be treated as surrogates.
        std::wstring hi_lo;
        hi_lo.push_back(static_cast<wchar_t>(0xD7FF));  // just below high range
        CHECK(Hex(Utf16ToUtf8(hi_lo)) == "ED 9F BF");

        std::wstring after_low;
        after_low.push_back(static_cast<wchar_t>(0xE000));  // just above low range
        CHECK(Hex(Utf16ToUtf8(after_low)) == "EE 80 80");
    }

    void TestOutputIsAlwaysValidUtf8() {
        // Every reachable input must produce structurally valid UTF-8: a
        // well-formed lead byte followed by the right number of 0x80..0xBF
        // continuations, never a 5/6-byte lead, never a truncation.
        std::vector<std::wstring> inputs;
        inputs.push_back(L"");
        inputs.push_back(L"ASCII only");
        inputs.push_back(L"\u00E9\u00FF");
        inputs.push_back(L"\u4E2D\u6587");
        std::wstring lone_hi;
        lone_hi.push_back(static_cast<wchar_t>(0xD800));
        inputs.push_back(lone_hi);
        std::wstring lone_lo;
        lone_lo.push_back(static_cast<wchar_t>(0xDFFF));
        inputs.push_back(lone_lo);
        std::wstring pair;
        pair.push_back(static_cast<wchar_t>(0xDBFF));
        pair.push_back(static_cast<wchar_t>(0xDFFF));
        inputs.push_back(pair);

        for (const std::wstring& in : inputs) {
            const std::string out = Utf16ToUtf8(in);
            std::size_t i = 0;
            bool ok = true;
            while (i < out.size() && ok) {
                const unsigned char b = static_cast<unsigned char>(out[i]);
                std::size_t need = 0;
                if (b < 0x80) {
                    need = 0;
                } else if ((b & 0xE0) == 0xC0) {
                    need = 1;
                } else if ((b & 0xF0) == 0xE0) {
                    need = 2;
                } else if ((b & 0xF8) == 0xF0) {
                    need = 3;
                } else {
                    ok = false;  // 0x80..0xBF as a lead, or a 5/6-byte lead
                }
                if (ok && i + need >= out.size() && need != 0) {
                    ok = false;  // truncated sequence
                }
                for (std::size_t k = 1; ok && k <= need; ++k) {
                    const unsigned char cc =
                        static_cast<unsigned char>(out[i + k]);
                    if ((cc & 0xC0) != 0x80) {
                        ok = false;
                    }
                }
                i += need + 1;
            }
            CHECK(ok);
            if (!ok) {
                std::fprintf(stderr, "  invalid UTF-8: %s\n", Hex(out).c_str());
            }
        }
    }

    // --- DebugWrite overload resolution -------------------------------------

    class RecordingSink final : public DebugStateSink {
    public:
        void WriteString(const char* key, const std::string& value) override {
            keys.push_back(key);
            kinds.push_back("string");
            text = value;
        }
        void WriteBool(const char* key, bool value) override {
            keys.push_back(key);
            kinds.push_back("bool");
            flag = value;
        }
        void WriteInt(const char* key, long long value) override {
            keys.push_back(key);
            kinds.push_back("int");
            integer = value;
        }
        void WriteDouble(const char* key, double value) override {
            keys.push_back(key);
            kinds.push_back("double");
            real = value;
        }
        void WriteDoubleArray(const char* key,
                              const std::vector<double>& values) override {
            keys.push_back(key);
            kinds.push_back("array");
            numbers = values;
        }

        std::vector<std::string> keys;
        std::vector<std::string> kinds;
        std::string text;
        bool flag = false;
        long long integer = 0;
        double real = 0.0;
        std::vector<double> numbers;
    };

    void TestDebugWriteString() {
        RecordingSink s;
        DebugWrite(s, "text", std::string("hi"));
        CHECK(s.kinds.size() == 1 && s.kinds[0] == "string");
        CHECK(s.text == "hi");
    }

    void TestDebugWriteWstringConvertsToUtf8() {
        RecordingSink s;
        DebugWrite(s, "wtext", std::wstring(L"\u7F51\u5361"));
        CHECK(s.kinds.size() == 1 && s.kinds[0] == "string");
        CHECK(Hex(s.text) == "E7 BD 91 E5 8D A1");
    }

    void TestDebugWriteNullCStringIsEmpty() {
        RecordingSink s;
        DebugWrite(s, "ptr", static_cast<const char*>(nullptr));
        CHECK(s.kinds.size() == 1 && s.kinds[0] == "string");
        CHECK(s.text.empty());
    }

    void TestDebugWriteBool() {
        RecordingSink s;
        DebugWrite(s, "checked", true);
        CHECK(s.kinds.size() == 1 && s.kinds[0] == "bool");
        CHECK(s.flag == true);
    }

    void TestDebugWriteInt() {
        RecordingSink s;
        DebugWrite(s, "caret", static_cast<long long>(42));
        CHECK(s.kinds.size() == 1 && s.kinds[0] == "int");
        CHECK(s.integer == 42);
    }

    void TestDebugWriteDouble() {
        RecordingSink s;
        DebugWrite(s, "progress", 0.5);
        CHECK(s.kinds.size() == 1 && s.kinds[0] == "double");
        CHECK(s.real == 0.5);
    }

    void TestDebugWriteDoubleArray() {
        RecordingSink s;
        const std::vector<double> widths = {10.0, 20.5, 30.0};
        DebugWrite(s, "widths", widths);
        CHECK(s.kinds.size() == 1 && s.kinds[0] == "array");
        CHECK(s.numbers == widths);
    }

    void TestDebugWriteFallbackStringifiesUnknownType() {
        // The catch-all template std::to_string()s anything without a typed
        // overload. An int (not long long) lands here by design.
        RecordingSink s;
        DebugWrite(s, "small", 7);
        CHECK(s.kinds.size() == 1 && s.kinds[0] == "string");
        CHECK(s.text == "7");
        // The KEY must survive the fallback path too, otherwise the value is
        // unaddressable in the emitted state object.
        CHECK(s.keys.size() == 1);
        if (s.keys.size() == 1) {
            CHECK(s.keys[0] == "small");
        }
    }

    void TestDebugWriteKeysAreForwarded() {
        RecordingSink s;
        DebugWrite(s, "alpha", true);
        DebugWrite(s, "beta", static_cast<long long>(1));
        CHECK(s.keys.size() == 2);
        if (s.keys.size() == 2) {
            CHECK(s.keys[0] == "alpha");
            CHECK(s.keys[1] == "beta");
        }
    }

}  // namespace

int main() {
    TestEmptyString();
    TestAsciiIsOneByte();
    TestOneByteUpperBoundary();
    TestTwoByteUpperBoundary();
    TestThreeByteUpperBoundary();
    TestCjkEncodesAsThreeBytes();
    TestSmallestSurrogatePair();
    TestLargestSurrogatePair();
    TestKnownEmoji();
    TestSurrogatePairConsumesBothUnits();
    TestLoneHighSurrogateBecomesReplacement();
    TestLoneHighSurrogateAtEndOfLongerString();
    TestLoneLowSurrogateBecomesReplacement();
    TestHighSurrogateFollowedByNonLowBecomesReplacement();
    TestHighSurrogateFollowedByAnotherHighBecomesReplacement();
    TestSurrogateBoundaryValues();
    TestOutputIsAlwaysValidUtf8();
    TestDebugWriteString();
    TestDebugWriteWstringConvertsToUtf8();
    TestDebugWriteNullCStringIsEmpty();
    TestDebugWriteBool();
    TestDebugWriteInt();
    TestDebugWriteDouble();
    TestDebugWriteDoubleArray();
    TestDebugWriteFallbackStringifiesUnknownType();
    TestDebugWriteKeysAreForwarded();

    if (0 == g_failures) {
        std::puts("test_debug_state: ALL PASS");
        return 0;
    }
    std::fprintf(stderr, "test_debug_state: %d FAILURES\n", g_failures);
    return 1;
}
