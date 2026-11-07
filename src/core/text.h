// ============================================================================
// text.h - UTF-8 hygiene for values that cross a trust boundary.
//
// Single-sourced helpers so the DHCP v4/v6 stores cannot drift apart
// (same-shape sweep, batch123). The lease/binding hostname is a display
// string: it is serialized into the lease JSON file by nlohmann::json and
// rendered by the WebUI. nlohmann's dump() runs in strict mode and THROWS
// type_error.316 on an ill-formed byte, and a JSON body must itself be valid
// UTF-8, so an ill-formed name must never enter the store.
//
//   * wire path (DHCP option 12)  - client is untrusted: SanitizeUtf8
//   * control path (WebUI / API)  - operator input: IsValidUtf8 -> reject
//
// Both paths converge on the invariant "the store only ever holds well-formed
// UTF-8", which is what makes DumpLeases and the API body total.
// ============================================================================
#pragma once

#include <cstddef>
#include <string>

namespace vgww::core {

    namespace text_detail {

        /// Length in bytes of the well-formed UTF-8 sequence starting at
        /// s[i], or 0 when the bytes there are not a well-formed sequence.
        /// Strict per RFC 3629: rejects overlong forms, CESU-8 surrogates
        /// (ED A0..BF) and code points above U+10FFFF (F4 90.. / F5..FF).
        inline std::size_t SequenceLength(const unsigned char* s,
                                          std::size_t n,
                                          std::size_t i) {
            const unsigned char b0 = s[i];
            if (b0 < 0x80) {
                return 1;
            }
            const std::size_t remaining = n - i;
            if (b0 >= 0xC2 && b0 <= 0xDF) {
                if (remaining < 2) return 0;
                const unsigned char b1 = s[i + 1];
                if (b1 < 0x80 || b1 > 0xBF) return 0;
                return 2;
            }
            if (b0 >= 0xE0 && b0 <= 0xEF) {
                if (remaining < 3) return 0;
                const unsigned char b1 = s[i + 1];
                const unsigned char b2 = s[i + 2];
                if (b2 < 0x80 || b2 > 0xBF) return 0;
                if (0xE0 == b0) {
                    return (b1 >= 0xA0 && b1 <= 0xBF) ? 3 : 0;
                }
                if (0xED == b0) {
                    return (b1 >= 0x80 && b1 <= 0x9F) ? 3 : 0;
                }
                return (b1 >= 0x80 && b1 <= 0xBF) ? 3 : 0;
            }
            if (b0 >= 0xF0 && b0 <= 0xF4) {
                if (remaining < 4) return 0;
                const unsigned char b1 = s[i + 1];
                const unsigned char b2 = s[i + 2];
                const unsigned char b3 = s[i + 3];
                if (b2 < 0x80 || b2 > 0xBF) return 0;
                if (b3 < 0x80 || b3 > 0xBF) return 0;
                if (0xF0 == b0) {
                    return (b1 >= 0x90 && b1 <= 0xBF) ? 4 : 0;
                }
                if (0xF4 == b0) {
                    return (b1 >= 0x80 && b1 <= 0x8F) ? 4 : 0;
                }
                return (b1 >= 0x80 && b1 <= 0xBF) ? 4 : 0;
            }
            return 0;  // 0x80..0xC1 (bare continuation / overlong) and 0xF5..0xFF
        }

    }  // namespace text_detail

    /// True when every byte of `in` belongs to a well-formed UTF-8 sequence.
    /// An empty string is valid.
    inline bool IsValidUtf8(const std::string& in) {
        const auto* s = reinterpret_cast<const unsigned char*>(in.data());
        const std::size_t n = in.size();
        std::size_t i = 0;
        while (i < n) {
            const std::size_t len = text_detail::SequenceLength(s, n, i);
            if (0 == len) {
                return false;
            }
            i += len;
        }
        return true;
    }

    /// Returns `in` unchanged when it is well-formed UTF-8, otherwise a copy
    /// where every ill-formed byte is replaced by U+FFFD (EF BF BD). One
    /// replacement per offending byte keeps the transform deterministic and
    /// idempotent: SanitizeUtf8(SanitizeUtf8(x)) == SanitizeUtf8(x). Used on
    /// the untrusted DHCP wire path, where a malformed client name must be
    /// recorded (and echoed) as valid UTF-8 instead of poisoning persistence.
    inline std::string SanitizeUtf8(const std::string& in) {
        const auto* s = reinterpret_cast<const unsigned char*>(in.data());
        const std::size_t n = in.size();
        std::string out;
        out.reserve(n);
        std::size_t i = 0;
        while (i < n) {
            const std::size_t len = text_detail::SequenceLength(s, n, i);
            if (0 == len) {
                out.append("\xEF\xBF\xBD");  // U+FFFD REPLACEMENT CHARACTER
                ++i;
                continue;
            }
            out.append(in, i, len);
            i += len;
        }
        return out;
    }

}  // namespace vgww::core
