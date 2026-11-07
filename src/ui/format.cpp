// ============================================================================
// format.cpp - pure formatting helpers (no I/O, no state).
// ============================================================================
#include "ui/format.h"

#include "ui/i18n.h"

#include <cmath>
#include <cstdio>

namespace vgww {
    namespace ui {

        namespace {

            constexpr std::size_t kUnitCount = 5;

            /// Binary unit suffixes, index = power of 1024.
            const wchar_t* const kUnits[kUnitCount] = {
                L"B", L"KiB", L"MiB", L"GiB", L"TiB"};

        }  // namespace

        std::wstring FormatCount(uint64_t value) {
            const std::wstring digits = std::to_wstring(value);
            const std::size_t n = digits.size();
            std::wstring out;
            out.reserve(n + n / 3);
            for (std::size_t i = 0; i < n; ++i) {
                if (i > 0 && (n - i) % 3 == 0) {
                    out.push_back(L',');
                }
                out.push_back(digits[i]);
            }
            return out;
        }

        std::wstring FormatBytes(uint64_t bytes) {
            if (bytes < 1024) {
                return std::to_wstring(bytes) + L" B";
            }
            double value = static_cast<double>(bytes);
            std::size_t unit = 0;
            while (unit + 1 < kUnitCount && value >= 1024.0) {
                value /= 1024.0;
                ++unit;
            }
            // Round to the displayed precision first so 1048575 B reads
            // "1.0 MiB" instead of "1024.0 KiB".
            double rounded = std::floor(value * 10.0 + 0.5) / 10.0;
            if (rounded >= 1024.0 && unit + 1 < kUnitCount) {
                rounded /= 1024.0;
                ++unit;
            }
            wchar_t buf[32] = {};
            std::swprintf(buf, 32, L"%.1f %s", rounded, kUnits[unit]);
            return buf;
        }

        std::wstring FormatBps(uint64_t bytes_per_second) {
            return FormatBytes(bytes_per_second) + L"/s";
        }

        namespace {
            /// batch37r (user): fixed clock text. Only the units that have
            /// been reached are shown, zero-padded, colon-separated:
            ///   < 1 min  -> SS
            ///   < 1 hour -> MM:SS
            ///   < 1 day  -> HH:MM:SS
            ///   else     -> DD:HH:MM:SS
            /// No localized unit words, so the column width never wobbles.
            ///
            /// batch51 (user): unified fixed HH:MM:SS everywhere (About
            /// uptime, dashboard uptime, device last-seen, lease time-left).
            /// Hours count total hours (no separate day bucket) and are
            /// zero-padded to at least two digits, so the shape never
            /// changes after a week of uptime.
            std::wstring FixedTimeText(uint64_t seconds) {
                wchar_t buf[48] = {};
                std::swprintf(
                    buf, 48, L"%02llu:%02llu:%02llu",
                    static_cast<unsigned long long>(seconds / 3600),
                    static_cast<unsigned long long>((seconds % 3600) / 60),
                    static_cast<unsigned long long>(seconds % 60));
                return buf;
            }
        }  // namespace

        std::wstring FormatAgo(uint64_t seconds) {
            return FixedTimeText(seconds);
        }

        std::wstring FormatUptime(uint64_t seconds) {
            return FixedTimeText(seconds);
        }

        std::wstring FormatExpiry(uint32_t seconds) {
            if (seconds == 0xFFFFFFFFu) {
                return L"static";  // UINT32_MAX marks a static lease
            }
            return std::to_wstring(seconds / 3600) + L"h " +
                   std::to_wstring((seconds % 3600) / 60) + L"m";
        }

        std::wstring FormatTimeLeft(uint32_t seconds) {
            // batch37l (user): the same fixed compact form as uptime/last-seen.
            return FixedTimeText(seconds);
        }

    }  // namespace ui
}  // namespace vgww
