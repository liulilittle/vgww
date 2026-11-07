// ============================================================================
// page_util.h - shared page helpers (S5.2, T9 D4). Widen/Narrow/RelayoutHost/
// FormValue were inlined in every page file; this header is the single source
// (pages layer only; Narrow is out-of-line in page_util.cpp, the rest inline -
// no control or core contract change).
// ============================================================================
#pragma once

#include "ui/controls.h"  // Element, FormResult
#include "ui/i18n.h"
#include "ui/snapshot.h"

#include <windows.h>

#include <string>
#include <vector>

namespace vgww {
    namespace ui {

        /// batch31 P0-1: THE bytes -> wide conversion for every user-visible
        /// string that comes from the data plane. The data plane stores UTF-8
        /// (`WideToUtf8`, dataplane.cpp), so a per-byte cast turns a Chinese
        /// adapter name into mojibake. Decode as UTF-8 first; a byte string
        /// that is NOT valid UTF-8 (legacy ANSI configs, raw device paths)
        /// falls back to the historical per-byte widening, so no value is ever
        /// dropped and nothing throws.
        inline std::wstring Widen(const std::string& text) {
            if (text.empty()) {
                return std::wstring();
            }
            const int length = static_cast<int>(text.size());
            const int needed = ::MultiByteToWideChar(CP_UTF8,
                                                     MB_ERR_INVALID_CHARS,
                                                     text.data(), length,
                                                     nullptr, 0);
            if (needed <= 0) {
                // Invalid UTF-8: keep the old byte-wise widening (length ==
                // byte count) instead of dropping the value.
                return std::wstring(text.begin(), text.end());
            }
            std::wstring out(static_cast<std::size_t>(needed), L'\0');
            const int written = ::MultiByteToWideChar(
                CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), length, out.data(),
                needed);
            if (written <= 0) {
                return std::wstring(text.begin(), text.end());
            }
            return out;
        }

        /// Wide -> bytes (lossless for printable ASCII form values).
        std::string Narrow(const std::wstring& text);

        /// Immediate local relayout after a dialog opens/closes: the dialog
        /// card is a new visible subtree and PageContext carries no window
        /// handle, so the page re-arranges its host with its current bounds.
        inline void RelayoutHost(Element& host) {
            host.InvalidateLayout();
            host.Arrange(host.bounds());
        }

        /// Named form-field value; empty when the id is unknown.
        inline std::wstring FormValue(const FormResult& result, const char* id) {
            const auto it = result.values.find(id);
            return it != result.values.end() ? it->second : std::wstring();
        }

        /// batch26: ONE adapter-label builder shared by the Settings picker and
        /// the first-run wizard. Rows stay short: friendly name when unique,
        /// otherwise a short device marker (GUID prefix), the two-word link
        /// state, and at most the first IPv4 address (+N). The full device path
        /// is kept in `value` so saving/restoring never changes.
        struct AdapterLabelSource {
            std::wstring friendly;
            std::wstring device;
            bool connected = false;
            /// Pre-formatted "ip/prefix" entries.
            std::vector<std::wstring> ipv4;
        };

        struct AdapterLabel {
            std::wstring value;
            std::wstring label;
        };

        AdapterLabel MakeAdapterLabel(const AdapterLabelSource& source,
                                      int friendly_count, const I18n& i18n);

        /// batch29: ONE detected-adapter list for the Settings picker AND the
        /// first-run wizard (the sorting rule must never be written twice).
        struct AdapterChoice {
            std::wstring value;
            std::wstring label;
            bool connected = false;
            /// Ranking key - connected + IPv4 (0) beats connected without IPv4
            /// (1), which beats disconnected (2).
            int rank = 2;
        };

        /// Builds the detected-adapter choices from a snapshot: one row per
        /// adapter with a friendly name or device path, labelled by the shared
        /// MakeAdapterLabel, sorted most-usable first (stable inside a rank).
        std::vector<AdapterChoice> BuildAdapterChoices(const UiSnapshot& snapshot,
                                                       const I18n& i18n);

    }  // namespace ui
}  // namespace vgww
