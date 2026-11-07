// ============================================================================
// format.h - pure value formatters for the native UI (counts, byte sizes,
// rates, durations). All functions are deterministic and headless-testable.
// IPv6 address text is core::FormatIpv6 (core/config.h), not UI code: the
// core library must never depend on the UI layer.
// ============================================================================
#pragma once

#include <cstdint>
#include <string>

namespace vgww {
    namespace ui {

        /// "1234567" -> "1,234,567" (thousands separators).
        std::wstring FormatCount(uint64_t value);

        /// Binary (1024-based) size with one decimal above 1023 bytes:
        /// "1023 B", "1.5 KiB", "2.0 MiB" ... capped at TiB.
        std::wstring FormatBytes(uint64_t bytes);

        /// FormatBytes + "/s".
        std::wstring FormatBps(uint64_t bytes_per_second);

        /// batch51 (user): fixed HH:MM:SS ("00:00:05", "01:30:00") - the
        /// ONLY formatter for a last-activity timestamp. Hours count total
        /// hours and are zero-padded to at least two digits, so the shape
        /// never changes after a week of uptime. (batch30's "5 s ago"
        /// wording was retired in batch51.)
        std::wstring FormatAgo(uint64_t seconds);

        /// batch51 (user): the same fixed HH:MM:SS as FormatAgo - the ONLY
        /// formatter for an uptime. No localized unit words, so the column
        /// width never wobbles.
        std::wstring FormatUptime(uint64_t seconds);

        /// Coarse lease expiry as "Nh Nm" ("1h 0m"); UINT32_MAX - the static
        /// lease marker - renders as "static". UNUSED by the UI
        /// (FormatTimeLeft renders lease expiry); kept only for the historical
        /// format test, never call it for user-visible text.
        std::wstring FormatExpiry(uint32_t seconds);

        /// batch51 (user): remaining lease time in the same fixed HH:MM:SS as
        /// uptime/last-seen. UINT32_MAX (static) is never passed here.
        std::wstring FormatTimeLeft(uint32_t seconds);

    }  // namespace ui
}  // namespace vgww
