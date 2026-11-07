// ============================================================================
// page_util.cpp - out-of-line definition for the shared page helper Narrow
// (S6 implementation migration). The header keeps the declaration; Widen /
// RelayoutHost / FormValue stay inline there (recon: too small / deliberately
// shared inlines - no migration benefit).
//
// batch31 P0-1: Widen (UTF-8 decode) and Narrow (UTF-8 encode) are now the
// ONLY byte<->wide pair in the UI. The former per-byte `Narrow` here and the
// second, UTF-8 `Narrow` in settings.cpp were two same-named functions with
// different semantics; the UTF-8 one won (it is the lossless direction for
// non-ASCII adapter names the user can pick and save).
// ============================================================================
#include "ui/pages/page_util.h"

#include "core/config.h"

#include <algorithm>
#include <utility>

namespace vgww {
    namespace ui {

        /// Wide -> UTF-8 bytes. Round-trips every non-ASCII form value (the
        /// adapter picker stores friendly names); an unpaired surrogate - the
        /// only value UTF-8 cannot represent - degrades to the historical
        /// per-byte cast instead of dropping the field.
        std::string Narrow(const std::wstring& text) {
            if (text.empty()) {
                return std::string();
            }
            const int length = static_cast<int>(text.size());
            const int needed = ::WideCharToMultiByte(CP_UTF8,
                                                     WC_ERR_INVALID_CHARS,
                                                     text.data(), length,
                                                     nullptr, 0, nullptr,
                                                     nullptr);
            if (needed <= 0) {
                std::string out;
                out.reserve(text.size());
                for (const wchar_t c : text) {
                    out.push_back(static_cast<char>(c));
                }
                return out;
            }
            std::string out(static_cast<std::size_t>(needed), '\0');
            ::WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(),
                                  length, out.data(), needed, nullptr, nullptr);
            return out;
        }

        namespace {
            /// "\\DEVICE\\{8B645B7B-...}" -> "adapter 8B645B7B..." (never the
            /// whole path). Without a GUID, the last path component is capped.
            std::wstring ShortDeviceLabel(const std::wstring& device,
                                          const I18n& i18n) {
                std::wstring tail;
                const auto open = device.find(L'{');
                const auto close = open == std::wstring::npos
                                       ? std::wstring::npos
                                       : device.find(L'}', open);
                if (open != std::wstring::npos && close != std::wstring::npos &&
                    close > open + 1) {
                    tail = device.substr(open + 1, close - open - 1);
                    if (tail.size() > 8) {
                        tail.resize(8);
                        tail += L"\u2026";
                    }
                } else {
                    const auto sep = device.find_last_of(L"\\/");
                    tail = sep == std::wstring::npos ? device
                                                     : device.substr(sep + 1);
                    if (tail.size() > 12) {
                        tail.resize(12);
                        tail += L"\u2026";
                    }
                }
                return std::wstring(i18n.T(Str::FormAdapter)) + L" " + tail;
            }

            std::wstring FirstIpv4(const std::vector<std::wstring>& ipv4) {
                if (ipv4.empty()) {
                    return std::wstring();
                }
                std::wstring out = ipv4.front();
                if (ipv4.size() > 1) {
                    out += L" +" + std::to_wstring(ipv4.size() - 1);
                }
                return out;
            }
        }  // namespace

        AdapterLabel MakeAdapterLabel(const AdapterLabelSource& source,
                                      int friendly_count, const I18n& i18n) {
            AdapterLabel out;
            const bool unique_name =
                !source.friendly.empty() && friendly_count <= 1;
            // The VALUE keeps the full unique path for duplicate/blank names;
            // only the visible label is shortened.
            out.value = unique_name ? source.friendly : source.device;
            out.label = unique_name ? source.friendly
                                    : ShortDeviceLabel(source.device, i18n);
            out.label += L" \u00B7 ";
            out.label += i18n.T(source.connected ? Str::SettingsAdapterLinkUp
                                                 : Str::SettingsAdapterLinkDown);
            // batch29 (main-agent ruling): the IPv4 tail belongs to a
            // CONNECTED adapter only. A disconnected NIC keeps its APIPA
            // (169.254.x.x) self-assigned address in the inventory, but showing
            // it in the picker is pure noise - it cannot carry traffic. The
            // address stays in the row for a connected adapter (+N suffixes).
            if (source.connected) {
                const std::wstring ip = FirstIpv4(source.ipv4);
                if (!ip.empty()) {
                    out.label += L" \u00B7 ";
                    out.label += ip;
                }
            }
            return out;
        }

        std::vector<AdapterChoice> BuildAdapterChoices(const UiSnapshot& snapshot,
                                                       const I18n& i18n) {
            // batch29: ONE list for the Settings picker AND the first-run
            // wizard (the sorting rule must never be written twice). The label
            // comes from MakeAdapterLabel (friendly name when unique, else a
            // short device marker + link state + first IPv4).
            const auto friendly_count = [&snapshot](const std::wstring& name) {
                int count = 0;
                for (const auto& info : snapshot.adapters) {
                    if (Widen(info.friendly_name) == name) {
                        ++count;
                    }
                }
                return count;
            };
            std::vector<AdapterChoice> choices;
            for (const auto& info : snapshot.adapters) {
                const std::wstring friendly = Widen(info.friendly_name);
                const std::wstring device = Widen(info.device);
                if (friendly.empty() && device.empty()) {
                    continue;
                }
                AdapterLabelSource source;
                source.friendly = friendly;
                source.device = device;
                source.connected = info.is_up && info.media_connected;
                for (const auto& address : info.ipv4) {
                    source.ipv4.push_back(
                        Widen(vgww::core::FormatIpv4(address.address)) + L"/" +
                        std::to_wstring(address.prefix_len));
                }
                AdapterLabel built =
                    MakeAdapterLabel(source, friendly_count(friendly), i18n);
                AdapterChoice choice;
                choice.value = std::move(built.value);
                choice.connected = source.connected;
                choice.rank = !choice.connected ? 2 : (info.ipv4.empty() ? 1 : 0);
                choice.label = std::move(built.label);
                choices.push_back(std::move(choice));
            }
            // Most usable first: connected + IPv4 (0) > connected without IPv4
            // (1) > disconnected (2). Stable, so detection order breaks ties.
            std::stable_sort(choices.begin(), choices.end(),
                             [](const AdapterChoice& a, const AdapterChoice& b) {
                                 return a.rank < b.rank;
                             });
            return choices;
        }

    }  // namespace ui
}  // namespace vgww
