// ============================================================================
// settings.cpp - settings page (S4.3 Task 10): a pure SettingsDraft mirrors
// the ConfigView into editable controls, Save validates the draft through
// core::ValidateConfig and posts SaveConfigCmd. Element ids follow the plan
// anchors (`settings.*`).
// ============================================================================
#include <winsock2.h>
#include <ws2ipdef.h>
#include <windows.h>

#include "ui/pages/page.h"
#include "ui/pages/page_util.h"

#include "ui/controller.h"

#include <array>
#include <cstdint>
#include <cwchar>
#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace vgww {
    namespace ui {

        namespace {

            /// batch29: a UI-safe adapter name. A stored device path
            /// (\DEVICE\{GUID}) must NEVER be printed in the diagnostic body
            /// (the user complaint): collapse it to "adapter <guid8>..." and cap
            /// any long friendly name, so one line stays under ~60 characters.
            std::wstring ShortAdapterName(const std::wstring& value,
                                          const I18n& i18n) {
                if (value.empty()) {
                    return std::wstring();
                }
                const auto open = value.find(L'{');
                const auto close = open == std::wstring::npos
                                       ? std::wstring::npos
                                       : value.find(L'}', open);
                if (open != std::wstring::npos && close != std::wstring::npos &&
                    close > open + 1) {
                    std::wstring tail =
                        value.substr(open + 1, close - open - 1);
                    if (tail.size() > 8) {
                        tail.resize(8);
                        tail += L"\u2026";
                    }
                    return std::wstring(i18n.T(Str::FormAdapter)) + L" " + tail;
                }
                if (value.size() > 24) {
                    return value.substr(0, 23) + L"\u2026";
                }
                return value;
            }

            /// Immediate local relayout after a dialog opens/closes (T8 D2).
            /// batch26: shared definition (page_util.h) - the local duplicate
            /// made the unqualified call ambiguous once both were included.
            /// batch31 P0-1: the local `Widen`/`Narrow` duplicates are gone too;
            /// page_util.h's UTF-8 `Widen` and page_util.cpp's UTF-8 `Narrow`
            /// are the only pair in the UI layer.

            std::wstring JoinList(const std::vector<std::string>& entries) {
                std::wstring out;
                for (const std::string& entry : entries) {
                    if (!out.empty()) {
                        out += L", ";
                    }
                    out += Widen(entry);
                }
                return out;
            }

            /// Splits a comma/space separated list; empty entries are dropped.
            std::vector<std::string> SplitList(const std::string& text) {
                std::vector<std::string> out;
                std::string current;
                for (const char c : text) {
                    if (c == ',' || c == ' ' || c == '\t') {
                        if (!current.empty()) {
                            out.push_back(current);
                            current.clear();
                        }
                        continue;
                    }
                    current.push_back(c);
                }
                if (!current.empty()) {
                    out.push_back(current);
                }
                return out;
            }

            /// Decimal text within [lo, hi]; an empty field reads as 0 (the
            /// range check then decides, e.g. web.port 0 is rejected by
            /// core::ValidateConfig with its specific message).
            bool ParseUint(const std::wstring& text, uint32_t lo, uint32_t hi,
                           uint32_t& out) {
                if (text.empty()) {
                    out = 0;
                    return true;
                }
                uint64_t value = 0;
                for (const wchar_t c : text) {
                    if (c < L'0' || c > L'9') {
                        return false;
                    }
                    value = value * 10 + static_cast<uint64_t>(c - L'0');
                    if (value > 0xFFFFFFFFull) {
                        return false;
                    }
                }
                if (value < lo || value > hi) {
                    return false;
                }
                out = static_cast<uint32_t>(value);
                return true;
            }

            bool ParseIpv4Text(const std::wstring& text, uint32_t& out) {
                if (text.empty()) {
                    out = 0;
                    return true;
                }
                bool ok = false;
                const uint32_t parsed = vgww::core::ParseIpv4(Narrow(text), ok);
                if (!ok) {
                    return false;
                }
                out = parsed;
                return true;
            }

            bool ParseIpv6Text(const std::wstring& text,
                               std::array<uint8_t, 16>& out) {
                if (text.empty()) {
                    out = {};
                    return true;
                }
                const std::wstring wide = text;
                return 1 == ::InetPtonW(AF_INET6, wide.c_str(), out.data());
            }

            /// Pure settings draft: one field per user-editable setting.
            /// Unset fields read as zero/empty and are judged by
            /// core::ValidateConfig, which yields the precise message.
            struct SettingsDraft {
                std::wstring mode = L"bypass";
                std::wstring adapter;
                std::wstring gateway_ip;
                std::wstring gateway_mask;
                std::wstring gateway_mac;
                bool dhcp_enabled = false;
                std::wstring dhcp_pool_start;
                std::wstring dhcp_pool_end;
                std::wstring dhcp_lease_hours;
                std::wstring dhcp_dns;
                bool ipv6_enabled = false;
                std::wstring ipv6_ula;
                std::wstring ipv6_prefix_len;
                std::wstring ipv6_ra_lifetime;
                std::wstring ipv6_dns;
                bool dhcp6_enabled = false;
                std::wstring dhcp6_pool_start;
                std::wstring dhcp6_pool_end;
                std::wstring dhcp6_lease_seconds;
                std::wstring web_port;
                std::wstring vlan_id;
                bool bridge_enabled = false;
                std::wstring bridge_up;
                std::wstring bridge_down;
                std::wstring bridge_table_size;
                /// batch20: "auto" or a 25-step percent string (100..500).
                std::wstring ui_scale = L"auto";
                /// batch22 A1: "dark" (default) / "light" / "auto".
                std::wstring theme = L"dark";
                /// batch22 A6: performance knobs (validated against the same
                /// model ranges ValidateConfig enforces).
                std::wstring perf_workers;
                std::wstring perf_max_conns;
                /// batch28: upstream dial timeout (ms). The spec's advanced
                /// "performance" section names it explicitly, so it is now an
                /// editable row with a plain-language hint.
                std::wstring perf_dial_timeout_ms;
                /// batch22 A8-2: the NEW Web token typed by the operator (empty
                /// means "keep the current one") plus the explicit-clear flag.
                std::wstring web_token;
                bool web_token_clear = false;
                /// batch20 P2: the persisted Web-UI switch (default on).
                bool web_enabled = true;

                static SettingsDraft FromConfig(const ConfigView& view);

                /// Applies the draft onto `out` and validates the result. The
                /// caller seeds `out` (the page starts from the on-disk file),
                /// so fields the draft does not own stay untouched.
                bool ToConfig(vgww::core::Config& out, std::wstring& err) const;

                bool Equals(const SettingsDraft& other) const;
            };

            SettingsDraft SettingsDraft::FromConfig(const ConfigView& view) {
                SettingsDraft draft;
                draft.mode = Widen(view.mode.empty() ? "bypass" : view.mode);
                draft.adapter = Widen(view.adapter);
                draft.gateway_ip = Widen(view.gateway_ip);
                draft.gateway_mask = Widen(view.gateway_mask);
                draft.gateway_mac = Widen(view.gateway_mac);
                draft.dhcp_enabled = view.dhcp_enabled;
                draft.dhcp_pool_start = Widen(view.dhcp_pool_start);
                draft.dhcp_pool_end = Widen(view.dhcp_pool_end);
                draft.dhcp_lease_hours = std::to_wstring(view.dhcp_lease_s / 3600u);
                draft.dhcp_dns = JoinList(view.dhcp_dns);
                draft.ipv6_enabled = view.ipv6_enabled;
                draft.ipv6_ula = Widen(view.ula_prefix);
                draft.ipv6_prefix_len = std::to_wstring(view.prefix_len);
                draft.ipv6_ra_lifetime = std::to_wstring(view.ra_lifetime_s);
                draft.ipv6_dns = JoinList(view.ipv6_dns);
                draft.dhcp6_enabled = view.dhcp6_enabled;
                draft.dhcp6_pool_start = Widen(view.dhcp6_pool_start);
                draft.dhcp6_pool_end = Widen(view.dhcp6_pool_end);
                draft.dhcp6_lease_seconds = std::to_wstring(view.dhcp6_lease_s);
                draft.web_port = std::to_wstring(view.web_port);
                draft.vlan_id = std::to_wstring(view.vlan_id);
                draft.bridge_enabled = view.bridge_enabled;
                draft.bridge_up = Widen(view.bridge_up);
                draft.bridge_down = Widen(view.bridge_down);
                draft.bridge_table_size = std::to_wstring(view.bridge_table_size);
                draft.ui_scale =
                    Widen(view.ui_scale.empty() ? "auto" : view.ui_scale);
                draft.theme = Widen(view.theme.empty() ? "dark" : view.theme);
                draft.perf_workers = std::to_wstring(view.perf_workers);
                draft.perf_max_conns = std::to_wstring(view.perf_max_conns);
                draft.perf_dial_timeout_ms =
                    std::to_wstring(view.perf_dial_timeout_ms);
                draft.web_enabled = view.web_enabled;
                return draft;
            }

            bool SettingsDraft::ToConfig(vgww::core::Config& out,
                                         std::wstring& err) const {
                const I18n& i18n = I18n::Instance();
                if (mode == L"main") {
                    out.mode = vgww::core::Mode::kMain;
                } else if (mode == L"bypass") {
                    out.mode = vgww::core::Mode::kBypass;
                } else {
                    err = i18n.T(Str::ErrModeValue);
                    return false;
                }
                out.adapter = Narrow(adapter);

                uint32_t ip_value = 0;
                uint32_t mask_value = 0;
                if (!ParseIpv4Text(gateway_ip, ip_value)) {
                    err = i18n.T(Str::ErrBanIp);
                    return false;
                }
                if (!ParseIpv4Text(gateway_mask, mask_value)) {
                    err = i18n.T(Str::ErrBanIp);
                    return false;
                }
                vgww::core::MacAddress mac_value{};
                if (!gateway_mac.empty() &&
                    !vgww::core::ParseMac(Narrow(gateway_mac), mac_value)) {
                    err = i18n.T(Str::ErrMacFormat);
                    return false;
                }
                out.gateway.ipv4 = ip_value;
                out.gateway.mask = mask_value;
                out.gateway.mac = mac_value;

                out.dhcp.enabled = dhcp_enabled;
                if (!ParseIpv4Text(dhcp_pool_start, out.dhcp.pool_start) ||
                    !ParseIpv4Text(dhcp_pool_end, out.dhcp.pool_end)) {
                    err = i18n.T(Str::ErrBanIp);
                    return false;
                }
                uint32_t hours_value = 0;
                if (!ParseUint(dhcp_lease_hours, 0, 8760, hours_value)) {
                    err = i18n.T(Str::ErrSettingsNumber);
                    return false;
                }
                out.dhcp.lease_seconds = hours_value * 3600u;
                out.dhcp.dns.clear();
                for (const std::string& entry : SplitList(Narrow(dhcp_dns))) {
                    bool ok = false;
                    const uint32_t dns = vgww::core::ParseIpv4(entry, ok);
                    if (!ok) {
                        err = i18n.T(Str::ErrDnsList);
                        return false;
                    }
                    out.dhcp.dns.push_back(dns);
                }

                out.ipv6.enabled = ipv6_enabled;
                std::array<uint8_t, 16> ula_value{};
                if (!ParseIpv6Text(ipv6_ula, ula_value)) {
                    err = i18n.T(Str::ErrUla);
                    return false;
                }
                out.ipv6.ula_prefix = ula_value;
                uint32_t prefix_value = 64;
                if (!ParseUint(ipv6_prefix_len, 0, 128, prefix_value)) {
                    err = i18n.T(Str::ErrSettingsNumber);
                    return false;
                }
                out.ipv6.prefix_len = static_cast<uint8_t>(prefix_value);
                uint32_t ra_value = 0;
                if (!ParseUint(ipv6_ra_lifetime, 0, 65535, ra_value)) {
                    err = i18n.T(Str::ErrSettingsNumber);
                    return false;
                }
                out.ipv6.ra_lifetime_s = ra_value;
                out.ipv6.dns.clear();
                for (const std::string& entry : SplitList(Narrow(ipv6_dns))) {
                    std::array<uint8_t, 16> addr{};
                    const std::wstring wide = Widen(entry);
                    if (1 != ::InetPtonW(AF_INET6, wide.c_str(), addr.data())) {
                        err = i18n.T(Str::ErrDnsList);
                        return false;
                    }
                    out.ipv6.dns.push_back(addr);
                }

                out.ipv6.dhcpv6.enabled = dhcp6_enabled;
                std::array<uint8_t, 16> pool6_start_value{};
                std::array<uint8_t, 16> pool6_end_value{};
                if (!ParseIpv6Text(dhcp6_pool_start, pool6_start_value) ||
                    !ParseIpv6Text(dhcp6_pool_end, pool6_end_value)) {
                    err = i18n.T(Str::ErrDhcp6Pool);
                    return false;
                }
                out.ipv6.dhcpv6.pool_start = pool6_start_value;
                out.ipv6.dhcpv6.pool_end = pool6_end_value;
                uint32_t seconds_value = 0;
                if (!ParseUint(dhcp6_lease_seconds, 60, 31536000, seconds_value)) {
                    err = i18n.T(Str::ErrSettingsNumber);
                    return false;
                }
                out.ipv6.dhcpv6.lease_seconds = seconds_value;

                uint32_t port_value = 0;
                if (!ParseUint(web_port, 0, 65535, port_value)) {
                    err = i18n.T(Str::ErrSettingsNumber);
                    return false;
                }
                out.web.port = static_cast<uint16_t>(port_value);

                uint32_t vlan_value = 0;
                if (!ParseUint(vlan_id, 0, 4095, vlan_value)) {
                    err = i18n.T(Str::ErrSettingsNumber);
                    return false;
                }
                out.vlan.id = static_cast<uint16_t>(vlan_value);

                out.bridge.enabled = bridge_enabled;
                out.bridge.upstream = Narrow(bridge_up);
                out.bridge.downstream = Narrow(bridge_down);
                uint32_t table_value = 0;
                if (!ParseUint(bridge_table_size, 0, 65536, table_value)) {
                    err = i18n.T(Str::ErrSettingsNumber);
                    return false;
                }
                out.bridge.mac_table_size = table_value;

                // batch20: the UI scale is an ASCII token ("auto"/"100".."500");
                // an unexpected value falls back to auto (ValidateConfig also
                // accepts both).
                // batch120: a wide-iterator range-construct narrows every code
                // unit to char (C4244) and truncates anything above U+00FF.
                // These two fields are ASCII tokens ("auto"/"100"), so Narrow()
                // states that intent and keeps UTF-8 correct if that ever
                // changes.
                const std::string ui_scale_token = Narrow(ui_scale);
                out.ui_scale = vgww::core::IsValidUiScaleValue(ui_scale_token)
                                   ? ui_scale_token
                                   : "auto";
                // batch22 A1: appearance token; an unexpected value falls back
                // to the historical dark look (ValidateConfig accepts both).
                const std::string theme_token = Narrow(theme);
                out.theme = vgww::core::IsValidThemeValue(theme_token)
                                ? theme_token
                                : "dark";
                // batch22 A6: the performance knobs accept exactly the model
                // ranges ValidateConfig enforces (workers [1,8],
                // max_conns [1,1048576]); an out-of-range value is refused here
                // with a range-specific message rather than being clamped
                // silently.
                const auto parse_u32 = [](const std::wstring& text,
                                          uint32_t& out_value) {
                    if (text.empty()) {
                        return false;
                    }
                    uint64_t value = 0;
                    for (const wchar_t c : text) {
                        if (c < L'0' || c > L'9') {
                            return false;
                        }
                        value = value * 10 + static_cast<uint64_t>(c - L'0');
                        if (value > 0xFFFFFFFFull) {
                            return false;
                        }
                    }
                    out_value = static_cast<uint32_t>(value);
                    return true;
                };
                uint32_t perf_workers_value = 0;
                if (!parse_u32(perf_workers, perf_workers_value)) {
                    err = i18n.T(Str::ErrSettingsNumber);
                    return false;
                }
                // Same bounds ValidateConfig enforces (workers == xtcp shard
                // count 8; conns == kMaxCap 1<<20).
                constexpr uint32_t kModelMaxWorkers = 8;
                if (perf_workers_value < 1 ||
                    perf_workers_value > kModelMaxWorkers) {
                    err = i18n.T(Str::ErrSettingsRange);
                    return false;
                }
                out.perf.workers = perf_workers_value;
                uint32_t perf_conns_value = 0;
                if (!parse_u32(perf_max_conns, perf_conns_value)) {
                    err = i18n.T(Str::ErrSettingsNumber);
                    return false;
                }
                if (perf_conns_value < 1 || perf_conns_value > (1u << 20)) {
                    err = i18n.T(Str::ErrSettingsRange);
                    return false;
                }
                out.perf.max_conns = perf_conns_value;
                uint32_t perf_dial_value = 0;
                if (!parse_u32(perf_dial_timeout_ms, perf_dial_value)) {
                    err = i18n.T(Str::ErrSettingsNumber);
                    return false;
                }
                // Same bound ValidateConfig enforces (1..3600000 ms).
                if (perf_dial_value < 1 || perf_dial_value > 3600000u) {
                    err = i18n.T(Str::ErrSettingsRange);
                    return false;
                }
                out.perf.dial_timeout_ms = perf_dial_value;
                // batch22 A8-2: token policy. `out` is seeded from the on-disk
                // file, so:
                //   explicit clear  -> "" (the operator confirmed it);
                //   a typed value   -> that value;
                //   empty + not cleared -> keep whatever was loaded (a save for
                //                          an unrelated setting must never wipe
                //                          the credential).
                // batch269: a typed value is the MORE RECENT intent, so it
                // outranks a pending clear. The old order checked the flag
                // first, so "confirm Clear, then type a replacement" silently
                // saved "" - the operator saw the field full and lost the
                // credential anyway.
                if (!web_token.empty()) {
                    // batch120: same narrow-range fix as the token fields
                    // above; the API token is ASCII and must stay byte-exact.
                    out.web.token = Narrow(web_token);
                } else if (web_token_clear) {
                    out.web.token.clear();
                }
                out.web.enabled = web_enabled;

                std::string error;
                if (!vgww::core::ValidateConfig(out, error)) {
                    err = Widen(error);
                    return false;
                }
                return true;
            }

            bool SettingsDraft::Equals(const SettingsDraft& other) const {
                return mode == other.mode && adapter == other.adapter &&
                       gateway_ip == other.gateway_ip &&
                       gateway_mask == other.gateway_mask &&
                       gateway_mac == other.gateway_mac &&
                       dhcp_enabled == other.dhcp_enabled &&
                       dhcp_pool_start == other.dhcp_pool_start &&
                       dhcp_pool_end == other.dhcp_pool_end &&
                       dhcp_lease_hours == other.dhcp_lease_hours &&
                       dhcp_dns == other.dhcp_dns &&
                       ipv6_enabled == other.ipv6_enabled &&
                       ipv6_ula == other.ipv6_ula &&
                       ipv6_prefix_len == other.ipv6_prefix_len &&
                       ipv6_ra_lifetime == other.ipv6_ra_lifetime &&
                       ipv6_dns == other.ipv6_dns &&
                       dhcp6_enabled == other.dhcp6_enabled &&
                       dhcp6_pool_start == other.dhcp6_pool_start &&
                       dhcp6_pool_end == other.dhcp6_pool_end &&
                       dhcp6_lease_seconds == other.dhcp6_lease_seconds &&
                       web_port == other.web_port && vlan_id == other.vlan_id &&
                       bridge_enabled == other.bridge_enabled &&
                       bridge_up == other.bridge_up &&
                       bridge_down == other.bridge_down &&
                       bridge_table_size == other.bridge_table_size &&
                       ui_scale == other.ui_scale &&
                       theme == other.theme &&
                       perf_workers == other.perf_workers &&
                       perf_max_conns == other.perf_max_conns &&
                       perf_dial_timeout_ms == other.perf_dial_timeout_ms &&
                       web_token == other.web_token &&
                       web_token_clear == other.web_token_clear &&
                       web_enabled == other.web_enabled;
            }

            class SettingsPage final : public Page {
            public:
                const char* id() const override { return "settings"; }
                Str title() const override { return Str::NavSettings; }
                void Build(Element& host, PageContext& ctx) override;
                void Update(const UiSnapshot& snapshot, I18n& i18n) override;
                bool ConfirmLeave(std::function<void()> proceed) override;

            private:
                SettingsDraft ReadDraft() const;
                void FillControls(const SettingsDraft& draft);
                void RefreshAdapterOptions(const UiSnapshot& snapshot,
                                           I18n& i18n);
                /// batch29: repaints the read-only device-path row after a
                /// picker change (the snapshot owns the full path).
                void RefreshAdapterPathRow();
                void RefreshDirty();
                void RefreshLabels(I18n& i18n);
                /// batch275: returns true only when the draft was accepted and
                /// a SaveConfigCmd was posted. Callers that intend to leave the
                /// page MUST gate on this - a refused draft leaves the operator
                /// on this page with the edits intact.
                bool Save();

                PageContext* ctx_ = nullptr;
                Element* host_ = nullptr;
                DialogHost* dialog_ = nullptr;
                BadgeElement* dirty_ = nullptr;
                Button* save_ = nullptr;
                /// batch39: re-entry guard for the Save button. The save
                /// stops/restarts the data plane, so a second click with no
                /// intervening edit must not post a second SaveConfigCmd. The
                /// guard is armed on save and disarmed by the next real user
                /// edit (dirty state), so an edit-then-save sequence always
                /// works (test A8: save -> type -> save).
                bool save_guard_armed_ = false;
                /// batch25a: "Common" / "Advanced" tier controls.
                Button* advanced_toggle_ = nullptr;
                Element* advanced_ = nullptr;
                Checkbox* internet_auto_ = nullptr;
                Checkbox* internet_manual_ = nullptr;
                /// batch25a: an explicit "Manual" pick must survive the 1 s
                /// snapshot refresh even when it changed no field (the preset
                /// is a UI intent, not a config value).
                bool internet_manual_chosen_ = false;
                SelectElement* mode_ = nullptr;
                /// batch20: the UI-scale select (17 absolute percent options).
                SelectElement* ui_scale_ = nullptr;
                SelectElement* theme_ = nullptr;
                /// batch22 A6: performance knobs.
                TextInputElement* perf_workers_ = nullptr;
                TextInputElement* perf_max_conns_ = nullptr;
                /// batch28: upstream dial timeout (ms).
                TextInputElement* perf_dial_timeout_ = nullptr;
                /// batch20: while the config is "auto", the select displays the
                /// effective percent; these track that so ReadDraft reports
                /// "auto" (not a false fixed value / false dirty) until the
                /// user actually picks a value.
                bool ui_scale_auto_display_ = false;
                std::wstring ui_scale_auto_token_;
                /// batch29 (user-reported): the adapter is a PURE select. The
                /// old free-text field is gone - `adapter_value_` is the single
                /// source of truth (written only by the picker), and the
                /// advanced tier shows the full device path read-only.
                std::wstring adapter_value_;
                /// batch29: the read-only "device path" row.
                Text* adapter_path_ = nullptr;
                /// batch29: "configured but not detected" hint (visible only
                /// while the saved value is missing from the detected list).
                Text* adapter_missing_hint_ = nullptr;
                /// batch29: "nothing detected - click Refresh" hint.
                Text* adapter_none_hint_ = nullptr;
                /// batch29: true when no adapter was detected at all (the save
                /// button is disabled in that state).
                bool adapters_empty_ = false;
                /// batch24 P2-9b: detected-adapter picker (selection only).
                SelectElement* adapter_pick_ = nullptr;
                /// batch24 P2-9: adapter resolution diagnostic line.
                Text* adapter_status_ = nullptr;
                TextInputElement* gateway_ip_ = nullptr;
                TextInputElement* gateway_mask_ = nullptr;
                TextInputElement* gateway_mac_ = nullptr;
                Checkbox* dhcp_enabled_ = nullptr;
                TextInputElement* dhcp_pool_start_ = nullptr;
                TextInputElement* dhcp_pool_end_ = nullptr;
                TextInputElement* dhcp_lease_hours_ = nullptr;
                TextInputElement* dhcp_dns_ = nullptr;
                Checkbox* ipv6_enabled_ = nullptr;
                TextInputElement* ipv6_ula_ = nullptr;
                TextInputElement* ipv6_prefix_len_ = nullptr;
                TextInputElement* ipv6_ra_lifetime_ = nullptr;
                TextInputElement* ipv6_dns_ = nullptr;
                Checkbox* dhcp6_enabled_ = nullptr;
                TextInputElement* dhcp6_pool_start_ = nullptr;
                TextInputElement* dhcp6_pool_end_ = nullptr;
                TextInputElement* dhcp6_lease_seconds_ = nullptr;
                TextInputElement* web_port_ = nullptr;
                Text* web_bind_ = nullptr;
                /// batch22 A8-2: write-only token field + its explicit clear
                /// action (see Build()). `token_clear_requested_` is the flag
                /// the confirmed clear sets; ToConfig acts on it.
                TextInputElement* token_ = nullptr;
                Element* token_clear_ = nullptr;
                bool token_clear_requested_ = false;
                /// batch20 P2: Web-UI enable switch.
                Checkbox* web_enabled_ = nullptr;
                TextInputElement* vlan_id_ = nullptr;
                Checkbox* bridge_enabled_ = nullptr;
                TextInputElement* bridge_up_ = nullptr;
                TextInputElement* bridge_down_ = nullptr;
                TextInputElement* bridge_table_size_ = nullptr;
                SettingsDraft applied_;
                std::string config_path_;
                bool initialized_ = false;
                std::vector<std::pair<Str, Text*>> labels_;
            };

            void SettingsPage::Build(Element& host, PageContext& ctx) {
                ctx_ = &ctx;
                host_ = &host;

                const auto changed = [this] { RefreshDirty(); };
                const auto changed_flag = [this](bool) { RefreshDirty(); };

                auto scroll = std::make_unique<ScrollView>(
                    std::make_unique<StackPanel>(Orientation::Vertical, 12.0f));
                scroll->id = "settings.scroll";
                // batch24 P0-1: the page host is a vertical StackPanel holding the
                // toolbar band and this scroller. Without the fill flag the
                // scroller is measured against the FULL host height and then
                // placed BELOW the toolbar, so its viewport bottom overflows the
                // host (and the client area) by toolbar_h + gap - the last page
                // rows could never be scrolled into view (user: "the interface
                // is cut off").
                // Claiming the leftover capacity makes view_h == host bottom - the
                // scroller's viewport now ends exactly at the client bottom.
                scroll->fill_remaining = true;
                ScrollView* scroller = static_cast<ScrollView*>(host.Add(std::move(scroll)));
                Element& form = *scroller->children().front();

                // batch27 D5-A: the save action used to float alone at the
                // top-left of the page, far from the form it saves ("it reads
                // like a page-title button"). It now sits in a footer bar at
                // the bottom-right of the form column, so the target is
                // unambiguous and it stays reachable without scrolling.
                // A GridLayout puts the [dirty][save] pair in a right-aligned
                // cell (a horizontal StackPanel cannot align along its main
                // axis, which is why Align::End alone would not work here).
                auto footer = std::make_unique<GridLayout>(
                    std::vector<ColumnSpec>{ColumnSpec::Star(),
                                            ColumnSpec::Fixed(360.0f)},
                    12.0f);
                footer->id = "settings.footer";
                GridLayout* footer_grid =
                    static_cast<GridLayout*>(host.Add(std::move(footer)));
                footer_grid->Add(std::make_unique<StackPanel>(
                    Orientation::Vertical, 0.0f, Padding{}));  // star filler
                auto bar = std::make_unique<StackPanel>(
                    Orientation::Horizontal, 12.0f, Padding{}, Align::End);
                StackPanel* bar_raw = static_cast<StackPanel*>(
                    footer_grid->Add(std::move(bar)));
                auto save = std::make_unique<Button>(
                    I18n::Instance().T(Str::CommonSave), ButtonStyle::Primary);
                save->id = "settings.save";
                save_ = static_cast<Button*>(bar_raw->Add(std::move(save)));
                save_->on_click = [this] { Save(); };
                dirty_ = static_cast<BadgeElement*>(bar_raw->Add(
                    std::make_unique<BadgeElement>(
                        I18n::Instance().T(Str::SettingsDirty),
                        BadgeKind::Warning)));
                dirty_->id = "settings.dirty";
                dirty_->visible = false;

                const auto add_group = [&](Element& parent, Str heading,
                                           const char* id) -> StackPanel* {
                    auto card = std::make_unique<Card>(
                        Padding{16.0f, 12.0f, 16.0f, 12.0f}, 8.0f);
                    card->id = id;
                    Card* raw = static_cast<Card*>(parent.Add(std::move(card)));
                    auto stack = std::make_unique<StackPanel>(Orientation::Vertical,
                                                              10.0f);
                    StackPanel* inner =
                        static_cast<StackPanel*>(raw->Add(std::move(stack)));
                    auto text = std::make_unique<Text>(I18n::Instance().T(heading),
                                                       FontToken::Section,
                                                       ColorToken::Text);
                    Text* label = static_cast<Text*>(inner->Add(std::move(text)));
                    labels_.push_back({heading, label});
                    // B1: fields go into the inner stack - Card arranges its
                    // direct children into ONE rect, which stacked every
                    // sibling on top of each other (the user-visible overlap).
                    return inner;
                };
                // batch28: every advanced field carries one plain-language
                // line saying WHAT CHANGES if you touch it (not a glossary of
                // the term). Small + dim, wrapped, id "<field>.hint".
                const auto add_hint = [&](Element& parent, Str hint,
                                          const char* id) {
                    auto text = std::make_unique<Text>(
                        I18n::Instance().T(hint), FontToken::Small,
                        ColorToken::TextDim, true);
                    text->id = std::string(id) + ".hint";
                    Text* raw = static_cast<Text*>(parent.Add(std::move(text)));
                    labels_.push_back({hint, raw});
                    return raw;
                };
                const auto add_text = [&](Element& parent, Str label, const char* id,
                                          Str hint = Str::_Count) {
                    auto group = std::make_unique<StackPanel>(Orientation::Vertical, 4.0f);
                    auto text = std::make_unique<Text>(I18n::Instance().T(label),
                                                       FontToken::BodyStrong,
                                                       ColorToken::Text);
                    Text* caption = static_cast<Text*>(group->Add(std::move(text)));
                    labels_.push_back({label, caption});
                    auto input = std::make_unique<TextInputElement>();
                    input->id = id;
                    TextInputElement* raw =
                        static_cast<TextInputElement*>(group->Add(std::move(input)));
                    raw->on_changed = changed;
                    if (hint != Str::_Count) {
                        add_hint(*group, hint, id);
                    }
                    parent.Add(std::move(group));
                    return raw;
                };
                const auto add_check = [&](Element& parent, Str label, const char* id,
                                           Str hint = Str::_Count) {
                    auto group = std::make_unique<StackPanel>(
                        Orientation::Vertical, 4.0f);
                    auto row = std::make_unique<StackPanel>(
                        Orientation::Horizontal, 8.0f);
                    auto text = std::make_unique<Text>(I18n::Instance().T(label),
                                                       FontToken::BodyStrong,
                                                       ColorToken::Text);
                    Text* caption = static_cast<Text*>(row->Add(std::move(text)));
                    labels_.push_back({label, caption});
                    auto box = std::make_unique<Checkbox>(false);
                    box->id = id;
                    Checkbox* raw = static_cast<Checkbox*>(row->Add(std::move(box)));
                    raw->on_changed = changed_flag;
                    group->Add(std::move(row));
                    if (hint != Str::_Count) {
                        add_hint(*group, hint, id);
                    }
                    parent.Add(std::move(group));
                    return raw;
                };
                const auto add_select = [&](Element& parent, Str label, const char* id,
                                            std::vector<std::pair<std::wstring,
                                                                  std::wstring>> options,
                                            Str hint = Str::_Count) {
                    auto group = std::make_unique<StackPanel>(Orientation::Vertical, 4.0f);
                    auto text = std::make_unique<Text>(I18n::Instance().T(label),
                                                       FontToken::BodyStrong,
                                                       ColorToken::Text);
                    Text* caption = static_cast<Text*>(group->Add(std::move(text)));
                    labels_.push_back({label, caption});
                    auto select = std::make_unique<SelectElement>();
                    select->id = id;
                    select->SetOptions(std::move(options));
                    SelectElement* raw =
                        static_cast<SelectElement*>(group->Add(std::move(select)));
                    raw->on_changed = changed;
                    if (hint != Str::_Count) {
                        add_hint(*group, hint, id);
                    }
                    parent.Add(std::move(group));
                    return raw;
                };
                const auto add_readonly = [&](Element& parent, Str label, const char* id) {
                    auto row = std::make_unique<StackPanel>(Orientation::Horizontal, 8.0f);
                    auto text = std::make_unique<Text>(I18n::Instance().T(label),
                                                       FontToken::BodyStrong,
                                                       ColorToken::Text);
                    Text* caption = static_cast<Text*>(row->Add(std::move(text)));
                    labels_.push_back({label, caption});
                    auto value = std::make_unique<Text>(L"-", FontToken::Body,
                                                        ColorToken::TextDim);
                    value->id = id;
                    Text* raw = static_cast<Text*>(row->Add(std::move(value)));
                    parent.Add(std::move(row));
                    return raw;
                };

                // ---- batch25a: "Common" tier (visible by default) ----------
                StackPanel* common =
                    add_group(form, Str::SettingsCommonGroup,
                              "settings.group.common");
                // batch29 (user-reported): "the adapter field must be a pure
                // selector box". The picker holds
                // ONLY detected adapters (no manual placeholder); the selection
                // is the single source of truth for the saved value.
                // The initial single row is the "nothing detected" placeholder;
                // it is replaced by the detected list on the first Update. Its
                // value is a sentinel (never empty, never a saved adapter).
                adapter_pick_ = add_select(
                    *common, Str::FormAdapterPick, "settings.adapter_pick",
                    {{L"__none__", I18n::Instance().T(Str::AdapterNoneDetected)}});
                adapter_pick_->on_changed = [this] {
                    if (adapter_pick_ == nullptr) {
                        return;
                    }
                    const std::wstring value =
                        adapter_pick_->selected_value();
                    // batch29: the "__none__" placeholder is not a value.
                    if (!value.empty() && value != L"__none__") {
                        adapter_value_ = value;
                        RefreshAdapterPathRow();
                    }
                    RefreshDirty();
                };
                // The configured-but-missing hint (hidden unless the saved
                // value is absent from the detected list).
                adapter_missing_hint_ =
                    static_cast<Text*>(common->Add(std::make_unique<Text>(
                        I18n::Instance().T(Str::AdapterNotDetectedHint),
                        FontToken::Small, ColorToken::Warning, true)));
                adapter_missing_hint_->id = "settings.adapter_missing";
                adapter_missing_hint_->visible = false;
                // "Nothing detected" hint: one plain sentence + what to do.
                adapter_none_hint_ =
                    static_cast<Text*>(common->Add(std::make_unique<Text>(
                        I18n::Instance().T(Str::AdapterNoneDetectedHint),
                        FontToken::Small, ColorToken::Warning, true)));
                adapter_none_hint_->id = "settings.adapter_none_hint";
                adapter_none_hint_->visible = false;
                // batch24 P2-9 (diagnostic visibility): show the data plane's
                // adapter resolution state right at the picker. Failures
                // (no match / ambiguity / link down) stay actionable.
                adapter_status_ = static_cast<Text*>(common->Add(std::make_unique<Text>(
                    L"", FontToken::Small, ColorToken::Warning, true)));
                adapter_status_->id = "settings.adapter_status";
                adapter_status_->visible = false;

                // "How other devices get online": one choice, two presets.
                // Automatic presets main mode + DHCP; Manual leaves every
                // advanced field exactly as it is.
                {
                    auto group = std::make_unique<StackPanel>(
                        Orientation::Vertical, 6.0f);
                    auto heading = std::make_unique<Text>(
                        I18n::Instance().T(Str::SettingsInternetMode),
                        FontToken::BodyStrong, ColorToken::Text);
                    labels_.push_back({Str::SettingsInternetMode,
                                       static_cast<Text*>(group->Add(
                                           std::move(heading)))});
                    const auto add_radio =
                        [&](Str label, const char* id) -> Checkbox* {
                        auto row = std::make_unique<StackPanel>(
                            Orientation::Horizontal, 8.0f);
                        auto box = std::make_unique<Checkbox>(false);
                        box->id = id;
                        box->SetRadioStyle(true);
                        Checkbox* raw = static_cast<Checkbox*>(
                            row->Add(std::move(box)));
                        auto caption = std::make_unique<Text>(
                            I18n::Instance().T(label), FontToken::Body,
                            ColorToken::Text);
                        labels_.push_back({label,
                                           static_cast<Text*>(row->Add(
                                               std::move(caption)))});
                        group->Add(std::move(row));
                        return raw;
                    };
                    internet_auto_ = add_radio(
                        Str::SettingsInternetAuto,
                        "settings.internet_mode.auto");
                    internet_manual_ = add_radio(
                        Str::SettingsInternetManual,
                        "settings.internet_mode.manual");
                    internet_auto_->on_changed = [this](bool on) {
                        if (!on) {
                            // Clicking the selected radio keeps it selected.
                            if (internet_auto_ != nullptr) {
                                internet_auto_->SetChecked(true);
                            }
                            return;
                        }
                        if (internet_manual_ != nullptr) {
                            internet_manual_->SetChecked(false);
                        }
                        internet_manual_chosen_ = false;
                        if (mode_ != nullptr) {
                            mode_->SetSelectedValueSilent(L"main");
                        }
                        if (dhcp_enabled_ != nullptr) {
                            dhcp_enabled_->SetChecked(true);
                        }
                        RefreshDirty();
                    };
                    internet_manual_->on_changed = [this](bool on) {
                        if (!on) {
                            if (internet_manual_ != nullptr) {
                                internet_manual_->SetChecked(true);
                            }
                            return;
                        }
                        if (internet_auto_ != nullptr) {
                            internet_auto_->SetChecked(false);
                        }
                        internet_manual_chosen_ = true;
                        RefreshDirty();
                    };
                    common->Add(std::move(group));
                }

                // ---- batch25a: collapsed "Advanced settings" tier ----------
                {
                    auto card = std::make_unique<Card>(
                        Padding{16.0f, 8.0f, 16.0f, 8.0f}, 8.0f);
                    card->id = "settings.group.advanced.header";
                    Card* raw = static_cast<Card*>(form.Add(std::move(card)));
                    auto stack = std::make_unique<StackPanel>(
                        Orientation::Vertical, 6.0f);
                    StackPanel* inner =
                        static_cast<StackPanel*>(raw->Add(std::move(stack)));
                    advanced_toggle_ = static_cast<Button*>(inner->Add(
                        std::make_unique<Button>(L"",
                                                 ButtonStyle::Secondary)));
                    advanced_toggle_->id = "settings.advanced.toggle";
                    advanced_toggle_->on_click = [this] {
                        if (advanced_ == nullptr) {
                            return;
                        }
                        advanced_->visible = !advanced_->visible;
                        RefreshLabels(I18n::Instance());
                        if (host_ != nullptr) {
                            RelayoutHost(*host_);
                        }
                    };
                    auto hint = std::make_unique<Text>(
                        I18n::Instance().T(Str::SettingsAdvancedHint),
                        FontToken::Small, ColorToken::TextDim, true);
                    labels_.push_back({Str::SettingsAdvancedHint,
                                       static_cast<Text*>(inner->Add(
                                           std::move(hint)))});
                }
                auto advanced = std::make_unique<StackPanel>(
                    Orientation::Vertical, 12.0f);
                advanced->id = "settings.advanced";
                advanced->visible = false;
                advanced_ = form.Add(std::move(advanced));
                StackPanel* adv = static_cast<StackPanel*>(advanced_);

                StackPanel* basic =
                    add_group(*adv, Str::FormGroupBasic, "settings.group.basic");
                mode_ = add_select(*basic, Str::FormMode, "settings.mode",
                                   {{L"bypass", L"bypass"}, {L"main", L"main"}},
                                   Str::SettingsHintMode);
                // batch29 (user-reported): NO editable adapter field any more.
                // The picker above is the only input; this row just shows the
                // full device path (read-only, dim SMALL text, tooltip carries
                // it) so a power user can verify WHICH device is bound without
                // ever typing a GUID. It is inert: not focusable, not part of
                // the dirty comparison (ReadDraft never reads it).
                {
                    auto row = std::make_unique<StackPanel>(
                        Orientation::Horizontal, 8.0f);
                    auto caption = std::make_unique<Text>(
                        I18n::Instance().T(Str::AdapterPathLabel),
                        FontToken::BodyStrong, ColorToken::Text);
                    labels_.push_back({Str::AdapterPathLabel,
                                       static_cast<Text*>(row->Add(
                                           std::move(caption)))});
                    auto value = std::make_unique<Text>(
                        L"-", FontToken::Small, ColorToken::TextDim);
                    value->id = "settings.adapter_path";
                    adapter_path_ = static_cast<Text*>(row->Add(std::move(value)));
                    basic->Add(std::move(row));
                }
                add_hint(*basic, Str::SettingsHintAdapter, "settings.adapter_path");
                vlan_id_ = add_text(*basic, Str::FormVlan, "settings.vlan_id",
                                    Str::SettingsHintVlan);

                StackPanel* gateway = add_group(*adv, Str::FormGroupGateway, "settings.group.gateway");
                gateway_ip_ = add_text(*gateway, Str::FormGatewayIp,
                                       "settings.gateway_ip",
                                       Str::SettingsHintGatewayIp);
                gateway_mask_ =
                    add_text(*gateway, Str::FormGatewayMask,
                             "settings.gateway_mask",
                             Str::SettingsHintGatewayMask);
                gateway_mac_ =
                    add_text(*gateway, Str::FormGatewayMac,
                             "settings.gateway_mac",
                             Str::SettingsHintGatewayMac);

                StackPanel* dhcp = add_group(*adv, Str::FormGroupDhcp, "settings.group.dhcp");
                dhcp_enabled_ = add_check(*dhcp, Str::FormDhcpEnabled,
                                          "settings.dhcp_enabled",
                                          Str::SettingsHintDhcpEnabled);
                dhcp_pool_start_ =
                    add_text(*dhcp, Str::FormPoolStart,
                             "settings.dhcp_pool_start",
                             Str::SettingsHintPoolStart);
                dhcp_pool_end_ = add_text(*dhcp, Str::FormPoolEnd,
                                          "settings.dhcp_pool_end",
                                          Str::SettingsHintPoolEnd);
                dhcp_lease_hours_ =
                    add_text(*dhcp, Str::FormLeaseHours,
                             "settings.dhcp_lease_hours",
                             Str::SettingsHintLeaseHours);
                dhcp_dns_ = add_text(*dhcp, Str::FormDns, "settings.dhcp_dns",
                                     Str::SettingsHintDns);

                StackPanel* ipv6 = add_group(*adv, Str::FormGroupIpv6, "settings.group.ipv6");
                ipv6_enabled_ = add_check(*ipv6, Str::FormIpv6Enabled,
                                          "settings.ipv6_enabled",
                                          Str::SettingsHintIpv6Enabled);
                ipv6_ula_ = add_text(*ipv6, Str::FormUla, "settings.ipv6_ula",
                                     Str::SettingsHintUla);
                ipv6_prefix_len_ =
                    add_text(*ipv6, Str::FormPrefixLen,
                             "settings.ipv6_prefix_len",
                             Str::SettingsHintPrefixLen);
                ipv6_ra_lifetime_ =
                    add_text(*ipv6, Str::FormRa, "settings.ipv6_ra_lifetime",
                             Str::SettingsHintRa);
                ipv6_dns_ = add_text(*ipv6, Str::FormDns, "settings.ipv6_dns",
                                     Str::SettingsHintIpv6Dns);
                dhcp6_enabled_ =
                    add_check(*ipv6, Str::FormDhcp6Enabled,
                              "settings.dhcp6_enabled",
                              Str::SettingsHintDhcp6Enabled);
                dhcp6_pool_start_ =
                    add_text(*ipv6, Str::FormPoolStart,
                             "settings.dhcp6_pool_start",
                             Str::SettingsHintDhcp6PoolStart);
                dhcp6_pool_end_ =
                    add_text(*ipv6, Str::FormPoolEnd,
                             "settings.dhcp6_pool_end",
                             Str::SettingsHintDhcp6PoolEnd);
                dhcp6_lease_seconds_ =
                    add_text(*ipv6, Str::FormLeaseSeconds,
                             "settings.dhcp6_lease_seconds",
                             Str::SettingsHintDhcp6Lease);

                StackPanel* web = add_group(*adv, Str::FormGroupWeb, "settings.group.web");
                web_port_ = add_text(*web, Str::FormWebPort, "settings.web_port",
                                     Str::SettingsHintWebPort);
                web_bind_ = add_readonly(*web, Str::FormWebBind, "settings.web_bind");
                add_hint(*web, Str::SettingsHintWebBind, "settings.web_bind");
                // batch22 A8-2: the token is now WRITE-ONLY editable. The
                // current secret is never displayed (it does not even reach the
                // snapshot); the field only carries a NEW value. Semantics:
                //   * empty field  -> keep the current token (no accidental
                //                     wipe when the operator edits other
                //                     settings);
                //   * non-empty    -> replace it;
                //   * "Clear"      -> explicit + confirmed, sets it to empty.
                token_ = add_text(*web, Str::FormToken, "settings.token",
                                  Str::SettingsHintToken);
                if (auto* token_input = dynamic_cast<TextInputElement*>(token_)) {
                    token_input->SetPlaceholder(
                        I18n::Instance().T(Str::FormTokenKeepHint));
                }
                {
                    auto clear_row =
                        std::make_unique<StackPanel>(Orientation::Horizontal, 8.0f);
                    StackPanel* row =
                        static_cast<StackPanel*>(web->Add(std::move(clear_row)));
                    auto clear =
                        std::make_unique<Button>(I18n::Instance().T(Str::CommonClear));
                    clear->id = "settings.token_clear";
                    token_clear_ = row->Add(std::move(clear));
                }
                if (auto* clear = dynamic_cast<Button*>(token_clear_)) {
                    clear->on_click = [this] {
                        if (dialog_ == nullptr) {
                            return;
                        }
                        // Confirmed action: a single click can never lose the
                        // credential silently.
                        dialog_->ShowConfirm(
                            Str::CommonClear, I18n::Instance().T(Str::ConfirmClearToken),
                            [this] {
                                token_clear_requested_ = true;
                                RefreshDirty();
                            });
                    };
                }
                // batch20 P2: the Web UI is on by default; this is the
                // persisted switch (the About row follows it).
                web_enabled_ =
                    add_check(*web, Str::FormWebEnabled,
                              "settings.web_enabled",
                              Str::SettingsHintWebEnabled);

                // batch22 A6: performance knobs. Both are validated against the model
                // ranges before the config is handed to SaveConfigCmd.
                StackPanel* perf = add_group(*adv, Str::FormGroupPerf,
                                             "settings.group.perf");
                perf_workers_ = add_text(*perf, Str::FormWorkers,
                                         "settings.perf_workers",
                                         Str::SettingsHintWorkers);
                perf_max_conns_ = add_text(*perf, Str::FormMaxConns,
                                           "settings.perf_max_conns",
                                           Str::SettingsHintMaxConns);
                // batch28: the spec names the dial timeout as part of the
                // "performance" group, so it is now editable here too (it was
                // config-file only).
                perf_dial_timeout_ = add_text(*perf, Str::FormDialTimeout,
                                              "settings.perf_dial_timeout",
                                              Str::SettingsHintDialTimeout);

                StackPanel* bridge = add_group(*adv, Str::FormGroupBridge, "settings.group.bridge");
                bridge_enabled_ =
                    add_check(*bridge, Str::FormBridgeEnabled,
                              "settings.bridge_enabled",
                              Str::SettingsHintBridgeEnabled);
                bridge_up_ = add_text(*bridge, Str::FormBridgeUp,
                                      "settings.bridge_up",
                                      Str::SettingsHintBridgeUp);
                bridge_down_ = add_text(*bridge, Str::FormBridgeDown,
                                        "settings.bridge_down",
                                        Str::SettingsHintBridgeDown);
                bridge_table_size_ =
                    add_text(*bridge, Str::FormBridgeTable,
                             "settings.bridge_table_size",
                             Str::SettingsHintBridgeTable);

                // batch20: the UI group (DPI / UI scale). 17 absolute percents
                // (25-step). "auto" is not a separate option: it is shown as
                // the nearest percent of the EFFECTIVE scale and only becomes
                // a fixed override once the user picks a value.
                StackPanel* ui_group = add_group(*adv, Str::SettingsUi,
                                                 "settings.group.ui");
                std::vector<std::pair<std::wstring, std::wstring>> scale_options;
                for (int pct = 100; pct <= 500; pct += 25) {
                    const std::wstring token = std::to_wstring(pct);
                    scale_options.push_back({token, token + L"%"});
                }
                const I18n& i18n = I18n::Instance();
                theme_ = add_select(*ui_group, Str::SettingsTheme,
                                    "settings.theme",
                                    {{L"dark", i18n.T(Str::ThemeDark)},
                                     {L"light", i18n.T(Str::ThemeLight)},
                                     {L"auto", i18n.T(Str::ThemeAuto)}},
                                    Str::SettingsHintTheme);
                theme_->on_changed = [this] {
                    if (theme_ == nullptr) {
                        return;
                    }
                    const std::wstring token = theme_->selected_value();
                    // batch120: wide-iterator range-construct narrows each
                    // wchar_t to char (C4244). The token is an ASCII identity
                    // ("dark"/"light"/"auto"); Narrow() says so and stays
                    // correct if a value above U+00FF ever appears.
                    const std::string narrow = Narrow(token);
                    // Apply immediately (Save() persists it): switch the active
                    // palette and repaint every page.
                    if (ctx_ != nullptr && ctx_->apply_theme) {
                        ctx_->apply_theme(narrow);
                    }
                    RefreshDirty();
                };
                ui_scale_ = add_select(*ui_group, Str::SettingsUiScale,
                                       "settings.ui_scale",
                                       std::move(scale_options),
                                       Str::SettingsHintUiScale);
                ui_scale_->on_changed = [this] {
                    if (ui_scale_ == nullptr) {
                        return;
                    }
                    const std::wstring token = ui_scale_->selected_value();
                    const std::string narrow = Narrow(token);
                    // A real pick turns the auto display into a fixed value.
                    ui_scale_auto_display_ = false;
                    // Apply immediately; Save() persists it.
                    if (ctx_ != nullptr && ctx_->apply_ui_scale &&
                        vgww::core::IsValidUiScaleValue(narrow)) {
                        ctx_->apply_ui_scale(
                            vgww::core::UiScaleValueToFactor(narrow));
                    }
                    RefreshDirty();
                };

                dialog_ = static_cast<DialogHost*>(
                    host.Add(std::make_unique<DialogHost>()));
                dialog_->id = "settings.dialog";
            }

            SettingsDraft SettingsPage::ReadDraft() const {
                const auto value = [](const TextInputElement* input) {
                    return input != nullptr ? input->value() : std::wstring();
                };
                SettingsDraft draft;
                if (mode_ != nullptr && !mode_->selected_value().empty()) {
                    draft.mode = mode_->selected_value();
                draft.web_enabled =
                    web_enabled_ == nullptr || web_enabled_->checked;
                if (ui_scale_ != nullptr) {
                    const std::wstring shown = ui_scale_->selected_value();
                    draft.ui_scale =
                        (ui_scale_auto_display_ && shown == ui_scale_auto_token_)
                            ? L"auto"
                            : shown;
                }
                }
                if (theme_ != nullptr) {
                    draft.theme = theme_->selected_value();
                }
                draft.perf_workers = value(perf_workers_);
                draft.perf_max_conns = value(perf_max_conns_);
                draft.perf_dial_timeout_ms = value(perf_dial_timeout_);
                // batch22 A8-2: the write-only token field + the clear flag
                // (never the current secret - it is not in the snapshot).
                {
                    auto* token_input =
                        dynamic_cast<TextInputElement*>(token_);
                    draft.web_token =
                        token_input != nullptr ? token_input->value()
                                               : std::wstring();
                }
                draft.web_token_clear = token_clear_requested_;
                draft.adapter = adapter_value_;
                draft.gateway_ip = value(gateway_ip_);
                draft.gateway_mask = value(gateway_mask_);
                draft.gateway_mac = value(gateway_mac_);
                draft.dhcp_enabled = dhcp_enabled_ != nullptr && dhcp_enabled_->checked;
                draft.dhcp_pool_start = value(dhcp_pool_start_);
                draft.dhcp_pool_end = value(dhcp_pool_end_);
                draft.dhcp_lease_hours = value(dhcp_lease_hours_);
                draft.dhcp_dns = value(dhcp_dns_);
                draft.ipv6_enabled = ipv6_enabled_ != nullptr && ipv6_enabled_->checked;
                draft.ipv6_ula = value(ipv6_ula_);
                draft.ipv6_prefix_len = value(ipv6_prefix_len_);
                draft.ipv6_ra_lifetime = value(ipv6_ra_lifetime_);
                draft.ipv6_dns = value(ipv6_dns_);
                draft.dhcp6_enabled = dhcp6_enabled_ != nullptr && dhcp6_enabled_->checked;
                draft.dhcp6_pool_start = value(dhcp6_pool_start_);
                draft.dhcp6_pool_end = value(dhcp6_pool_end_);
                draft.dhcp6_lease_seconds = value(dhcp6_lease_seconds_);
                draft.web_port = value(web_port_);
                draft.vlan_id = value(vlan_id_);
                draft.bridge_enabled = bridge_enabled_ != nullptr && bridge_enabled_->checked;
                draft.bridge_up = value(bridge_up_);
                draft.bridge_down = value(bridge_down_);
                draft.bridge_table_size = value(bridge_table_size_);
                return draft;
            }

            void SettingsPage::FillControls(const SettingsDraft& draft) {
                if (mode_ != nullptr) {
                    mode_->SetSelectedValueSilent(draft.mode);
                }
                if (ui_scale_ != nullptr) {
                    // The auto case is refined in Update() with the effective
                    // scale; here keep the select on a valid option.
                    ui_scale_->SetSelectedValueSilent(
                        draft.ui_scale == L"auto" ? L"100" : draft.ui_scale);
                }
                if (theme_ != nullptr) {
                    theme_->SetSelectedValueSilent(draft.theme);
                }
                if (perf_workers_ != nullptr) {
                    perf_workers_->SetValue(draft.perf_workers);
                }
                if (perf_max_conns_ != nullptr) {
                    perf_max_conns_->SetValue(draft.perf_max_conns);
                }
                if (perf_dial_timeout_ != nullptr) {
                    perf_dial_timeout_->SetValue(draft.perf_dial_timeout_ms);
                }
                if (web_enabled_ != nullptr) {
                    web_enabled_->checked = draft.web_enabled;
                }
                const auto set = [](TextInputElement* input, const std::wstring& text) {
                    if (input != nullptr) {
                        input->SetValue(text);
                    }
                };
                // batch29: the picker's value IS the draft value. FillControls
                // mirrors the snapshot here (only when the user has no unsaved
                // edits - see Update), so a legacy/complex value (device path)
                // survives verbatim.
                adapter_value_ = draft.adapter;
                set(gateway_ip_, draft.gateway_ip);
                set(gateway_mask_, draft.gateway_mask);
                set(gateway_mac_, draft.gateway_mac);
                if (dhcp_enabled_ != nullptr) {
                    dhcp_enabled_->checked = draft.dhcp_enabled;
                }
                set(dhcp_pool_start_, draft.dhcp_pool_start);
                set(dhcp_pool_end_, draft.dhcp_pool_end);
                set(dhcp_lease_hours_, draft.dhcp_lease_hours);
                set(dhcp_dns_, draft.dhcp_dns);
                if (ipv6_enabled_ != nullptr) {
                    ipv6_enabled_->checked = draft.ipv6_enabled;
                }
                set(ipv6_ula_, draft.ipv6_ula);
                set(ipv6_prefix_len_, draft.ipv6_prefix_len);
                set(ipv6_ra_lifetime_, draft.ipv6_ra_lifetime);
                set(ipv6_dns_, draft.ipv6_dns);
                if (dhcp6_enabled_ != nullptr) {
                    dhcp6_enabled_->checked = draft.dhcp6_enabled;
                }
                set(dhcp6_pool_start_, draft.dhcp6_pool_start);
                set(dhcp6_pool_end_, draft.dhcp6_pool_end);
                set(dhcp6_lease_seconds_, draft.dhcp6_lease_seconds);
                set(web_port_, draft.web_port);
                set(vlan_id_, draft.vlan_id);
                if (bridge_enabled_ != nullptr) {
                    bridge_enabled_->checked = draft.bridge_enabled;
                }
                set(bridge_up_, draft.bridge_up);
                set(bridge_down_, draft.bridge_down);
                set(bridge_table_size_, draft.bridge_table_size);
                // batch25a: derive the plain-language preset from the saved
                // configuration (automatic == main + DHCP). This never changes
                // any field by itself; it only reflects the current mode.
                if (internet_auto_ != nullptr && internet_manual_ != nullptr) {
                    const bool automatic =
                        !internet_manual_chosen_ && draft.mode == L"main" &&
                        draft.dhcp_enabled;
                    internet_auto_->SetChecked(automatic);
                    internet_manual_->SetChecked(!automatic);
                }
            }

            void SettingsPage::RefreshAdapterPathRow() {
                // The picker holds the authoritative value; the full device
                // path is re-resolved by RefreshAdapterOptions on the next
                // snapshot. Immediately after a pick, show the picked value so
                // the row never lags behind the selection.
                if (adapter_path_ == nullptr) {
                    return;
                }
                if (adapter_value_.empty()) {
                    adapter_path_->SetText(L"-");
                    adapter_path_->SetTooltip(std::wstring());
                    return;
                }
                adapter_path_->SetText(adapter_value_);
                adapter_path_->SetTooltip(adapter_value_);
            }

            void SettingsPage::RefreshAdapterOptions(const UiSnapshot& snapshot,
                                                     I18n& i18n) {
                if (adapter_pick_ == nullptr) {
                    return;
                }
                // batch29 (user-reported): ONE detected-adapter list, built and
                // sorted by the SAME helper the first-run wizard uses. The only
                // non-detected row is the "configured but missing" entry, which
                // keeps the saved value verbatim (never cleared).
                const std::vector<AdapterChoice> choices =
                    BuildAdapterChoices(snapshot, i18n);
                std::vector<std::pair<std::wstring, std::wstring>> options;
                for (const AdapterChoice& choice : choices) {
                    options.emplace_back(choice.value, choice.label);
                }
                // The saved value may be a friendly name OR a device path (old
                // configs differ); both must match their detected row.
                const std::wstring shown = adapter_value_;
                const auto row_for = [&snapshot](const std::wstring& hint)
                    -> const vgww::runtime::Dataplane::AdapterInfo* {
                    for (const auto& info : snapshot.adapters) {
                        if (Widen(info.friendly_name) == hint ||
                            Widen(info.device) == hint) {
                            return &info;
                        }
                    }
                    return nullptr;
                };
                std::wstring selected;
                bool matched = false;
                for (const AdapterChoice& choice : choices) {
                    if (!shown.empty() && shown == choice.value) {
                        selected = choice.value;
                        matched = true;
                    }
                }
                if (!shown.empty() && !matched) {
                    // Legacy hint (friendly name vs stored device path): resolve
                    // it to the detected row it names.
                    const auto* info = row_for(shown);
                    if (info != nullptr) {
                        const std::wstring device = Widen(info->device);
                        const std::wstring friendly =
                            Widen(info->friendly_name);
                        for (const AdapterChoice& choice : choices) {
                            if ((!device.empty() && choice.value == device) ||
                                (!friendly.empty() &&
                                 choice.value == friendly)) {
                                selected = choice.value;
                                matched = true;
                                break;
                            }
                        }
                    }
                }
                std::wstring selected_path;
                bool configured_missing = false;
                if (matched) {
                    const auto* info = row_for(selected);
                    if (info != nullptr) {
                        selected_path = Widen(info->device);
                    }
                }
                if (!shown.empty() && !matched) {
                    // Configured but NOT detected: first row, value preserved
                    // exactly as configured, selected by default.
                    configured_missing = true;
                    std::wstring name = shown;
                    if (name.size() > 24) {
                        name = name.substr(0, 23) + L"\u2026";
                    }
                    options.insert(options.begin(),
                                   {shown,
                                    i18n.Format(Str::AdapterNotDetectedFmt,
                                                {name})});
                    selected = shown;
                    selected_path = shown;
                }
                if (options.empty()) {
                    // Nothing detected and nothing configured: one informative
                    // row; the save button is disabled (see the Update tail).
                    options.emplace_back(L"__none__",
                                         i18n.T(Str::AdapterNoneDetected));
                    selected = L"__none__";
                }
                // batch33i: an EMPTY configured adapter (the first-run state)
                // used to leave `selected` empty, so the dropdown rendered as a
                // blank box even though the list below was full - the user could
                // not tell which adapter was in effect, and saving wrote the
                // empty value straight back. Default to the most usable
                // detected adapter (BuildAdapterChoices sorts best-first).
                if (selected.empty() && !choices.empty()) {
                    selected = choices.front().value;
                }
                adapters_empty_ = choices.empty();
                if (adapter_pick_->options() != options) {
                    adapter_pick_->SetOptions(options);
                }
                adapter_pick_->SetSelectedValueSilent(selected);
                if (adapter_missing_hint_ != nullptr) {
                    adapter_missing_hint_->visible = configured_missing;
                }
                if (adapter_none_hint_ != nullptr) {
                    adapter_none_hint_->visible = adapters_empty_;
                }
                if (adapter_path_ != nullptr) {
                    const bool none = selected.empty() ||
                                      selected == L"__none__";
                    adapter_path_->SetText(none ? L"-" : selected_path);
                    adapter_path_->SetTooltip(none ? std::wstring()
                                                   : selected_path);
                }
            }

void SettingsPage::RefreshDirty() {
                if (dirty_ == nullptr) {
                    return;
                }
                const bool dirty = !ReadDraft().Equals(applied_);
                // batch39: any real edit re-arms the Save button (the re-entry
                // guard only rejects a repeat click with no changed state).
                if (dirty) {
                    save_guard_armed_ = false;
                }
                if (dirty_->visible != dirty) {
                    dirty_->visible = dirty;
                    if (host_ != nullptr) {
                        RelayoutHost(*host_);
                    }
                }
            }

            void SettingsPage::Update(const UiSnapshot& snapshot, I18n& i18n) {
                RefreshLabels(i18n);
                config_path_ = snapshot.config.config_path;
                if (web_bind_ != nullptr) {
                    web_bind_->SetText(snapshot.config.web_bind.empty()
                                           ? i18n.T(Str::CommonNotSet)
                                           : Widen(snapshot.config.web_bind));
                }
                if (token_ != nullptr) {
                    // batch22 A8-2: the field is write-only - the runtime token
                    // never reaches the snapshot (and must never be displayed),
                    // so only the hint is (re)localized here. A value typed by
                    // the operator is NOT clobbered by a snapshot refresh.
                    token_->SetPlaceholder(i18n.T(Str::FormTokenKeepHint));
                }
                if (adapter_status_ != nullptr) {
                    // batch24 P2-9/P2-9b: failure/ambiguity text stays
                    // authoritative (it already lists the candidate adapters).
                    // On success the line shows the adapter actually bound,
                    // its link state and its IPv4 addresses; an unusable
                    // binding turns red and appends the actionable hint.
                    const bool has_error = !snapshot.dataplane_error.empty();
                    const std::wstring friendly =
                        Widen(snapshot.adapter_binding.friendly_name);
                    const std::wstring device =
                        Widen(snapshot.adapter_binding.device);
                    const bool has_binding =
                        !has_error && snapshot.adapter_binding.bound &&
                        (!friendly.empty() || !device.empty());
                    if (has_error) {
                        // batch29 fix (user complaint): NEVER paste the raw
                        // dataplane error here - it is English, lists every
                        // adapter + a --adapter= hint and overflows the line.
                        // Body = one localized short sentence; the technical
                        // detail is preserved in the tooltip only.
                        std::wstring name = friendly.empty() ? device : friendly;
                        if (name.empty()) {
                            name = adapter_value_;
                        }
                        adapter_status_->SetText(i18n.Format(
                            Str::SettingsAdapterErrorFmt,
                            {ShortAdapterName(name, i18n)}));
                        adapter_status_->SetColor(ColorToken::Warning);
                        adapter_status_->SetTooltip(
                            Widen(snapshot.dataplane_error));
                    } else if (has_binding) {
                        const std::wstring name =
                            friendly.empty() ? device : friendly;
                        const std::wstring path =
                            device.empty() ? friendly : device;
                        std::wstring ips;
                        for (const auto& address :
                             snapshot.adapter_binding.ipv4) {
                            if (!ips.empty()) {
                                ips += L", ";
                            }
                            ips += Widen(vgww::core::FormatIpv4(
                                address.address));
                            ips += L"/";
                            ips += std::to_wstring(address.prefix_len);
                        }
                        if (ips.empty()) {
                            ips = i18n.T(Str::SettingsAdapterIpNone);
                        }
                        const bool connected = AdapterLinkConnected(
                            snapshot.adapter_binding);
                        // batch28: the diagnostic line stays short ("the text
                        // is too long" was the user complaint: 89 chars with
                        // the whole \DEVICE\{GUID} inline). The full device path
                        // moves to the hover tooltip, so nothing is lost.
                        std::wstring line = i18n.Format(
                            Str::SettingsAdapterStatusShortFmt,
                            {name,
                             i18n.T(connected ? Str::SettingsAdapterLinkUp
                                              : Str::SettingsAdapterLinkDown),
                             ips});
                        std::wstring tip = i18n.Format(
                            Str::AboutDevicePathFmt, {path});
                        // batch29: the tooltip's FIRST line is the device path;
                        // a long \DEVICE\{GUID} is truncated to 60 characters
                        // (with an ellipsis) so the hover box stays readable.
                        {
                            const std::size_t newline = tip.find(L'\n');
                            const std::size_t line_len =
                                newline == std::wstring::npos ? tip.size()
                                                              : newline;
                            if (line_len > 60) {
                                tip = tip.substr(0, 59) + L"\u2026" +
                                      (newline == std::wstring::npos
                                           ? std::wstring()
                                           : tip.substr(newline));
                            }
                        }
                        const AdapterIssue issue =
                            AdapterBindingIssue(snapshot.adapter_binding);
                        if (AdapterIssue::None != issue) {
                            Str reason = Str::DataplaneAdapterDownFmt;
                            if (AdapterIssue::NoIpv4 == issue) {
                                reason = Str::DataplaneAdapterNoIpFmt;
                            } else if (AdapterIssue::GatewayOutsideSubnet ==
                                       issue) {
                                reason = Str::DataplaneAdapterSubnetFmt;
                            }
                            line += L"\n";
                            line += i18n.Format(reason, {name});
                        }
                        adapter_status_->SetTooltip(std::move(tip));
                        adapter_status_->SetText(std::move(line));
                        // batch27 D5-B: a healthy binding is neutral text; only
                        // a real problem (link down / no IPv4 / gateway outside
                        // the subnet) may use Warning, and a hard failure uses
                        // Danger. Warning used to mark the NORMAL line too,
                        // which made the real warnings indistinguishable.
                        adapter_status_->SetColor(
                            AdapterIssue::None == issue ? ColorToken::TextDim
                                                        : ColorToken::Warning);
                    }
                    adapter_status_->visible = has_error || has_binding;
                }
                const SettingsDraft from_snapshot =
                    SettingsDraft::FromConfig(snapshot.config);
                // batch22 fix1: the user-edit test must compare the controls
                // against the draft we LAST WROTE (applied_), never against the
                // incoming snapshot. Comparing with the snapshot made the first
                // (early / still-empty) fill look like unsaved user edits as
                // soon as the real data arrived, so the form stayed poisoned at
                // 0/"" forever and saving failed validation. With applied_ as
                // the baseline an early fill self-heals, while a genuine edit
                // (controls != what we wrote) still blocks the overwrite.
                // RefreshDirty() already uses exactly this baseline.
                const bool user_edited = initialized_ && !ReadDraft().Equals(applied_);
                applied_ = from_snapshot;
                if (!initialized_ || !user_edited) {
                    // No unsaved edits: mirror the newest snapshot.
                    FillControls(applied_);
                    initialized_ = true;
                }
                // batch20: "auto" shows the nearest percent of the EFFECTIVE
                // scale (the desktop scale while auto is in force).
                if (ui_scale_ != nullptr) {
                    std::wstring token = applied_.ui_scale;
                    ui_scale_auto_display_ = (token == L"auto");
                    if (ui_scale_auto_display_) {
                        const float effective =
                            (ctx_ != nullptr && ctx_->effective_ui_scale)
                                ? ctx_->effective_ui_scale()
                                : 1.0f;
                        int pct = static_cast<int>(effective * 100.0f + 0.5f);
                        pct = ((pct + 12) / 25) * 25;  // nearest 25-step
                        if (pct < 100) pct = 100;
                        if (pct > 500) pct = 500;
                        token = std::to_wstring(pct);
                        ui_scale_auto_token_ = token;
                    }
                    ui_scale_->SetSelectedValueSilent(token);
                }
                RefreshAdapterOptions(snapshot, i18n);
                // batch29: with NO detected adapter there is nothing sensible to
                // save - the save button is disabled and the hint says "click
                // Refresh in the top-right corner and try again". A configured
                // (but currently missing) adapter is NOT "empty": that state
                // keeps its value and stays saveable.
                if (save_ != nullptr) {
                    const bool none = adapters_empty_ && adapter_value_.empty();
                    save_->enabled = !none;
                }
                RefreshDirty();
            }

            void SettingsPage::RefreshLabels(I18n& i18n) {
                for (const auto& entry : labels_) {
                    entry.second->SetText(i18n.T(entry.first));
                }
                if (dirty_ != nullptr) {
                    dirty_->SetText(i18n.T(Str::SettingsDirty));
                }
                if (save_ != nullptr) {
                    save_->SetLabel(i18n.T(Str::CommonSave));
                }
                if (advanced_toggle_ != nullptr) {
                    const bool open =
                        advanced_ != nullptr && advanced_->visible;
                    advanced_toggle_->SetLabel(
                        std::wstring(i18n.T(Str::SettingsAdvancedGroup)) +
                        (open ? L"  \u25BE" : L"  \u25B8"));
                }
            }

            bool SettingsPage::Save() {
                if (ctx_ == nullptr || ctx_->controller == nullptr || dialog_ == nullptr) {
                    return false;
                }
                // batch39: drop a repeated save with no intervening edit (the
                // apply restarts the data plane and HTTP listener; two posts
                // would restart twice and rebroadcast the same toast).
                if (save_guard_armed_) {
                    return false;
                }
                save_guard_armed_ = true;
                // Seed the Config from the on-disk file: sections the snapshot
                // does not expose (perf details, static bindings, token) must
                // survive a UI save.
                vgww::core::Config config;
                if (!config_path_.empty()) {
                    std::string load_error;
                    if (auto loaded =
                            vgww::core::Config::LoadFromFile(config_path_, load_error)) {
                        config = *loaded;
                    }
                }
                const SettingsDraft draft = ReadDraft();
                std::wstring error;
                if (!draft.ToConfig(config, error)) {
                    // A plain button (not a dialog submit): the error layer can
                    // open immediately - nothing closes it afterwards.
                    // batch27 P1-10: every failure carries one actionable line
                    // ("what do I do now?") instead of a bare reason.
                    // batch275: nothing was posted, so the re-entry guard must
                    // be disarmed - otherwise a retry with no intervening edit
                    // would be dropped with no feedback at all.
                    save_guard_armed_ = false;
                    const I18n& i18n = I18n::Instance();
                    error += L"\n";
                    error += i18n.T(Str::SettingsSaveErrorHint);
                    dialog_->ShowMessage(Str::CommonError, error, Str::CommonOk);
                    RelayoutHost(*host_);
                    return false;
                }
                SubmitCommand(*ctx_, Command{SaveConfigCmd{config, nullptr, true}});
                applied_ = draft;
                // batch269: the pending-clear flag is CONSUMED by this save.
                // Leaving it set meant the next unrelated save wiped whatever
                // token the apply had just written (the flag outlived the
                // intent it encoded). The typed field is cleared for the same
                // reason: its value is now applied_, and leaving the text in
                // place would make the next save re-submit it.
                token_clear_requested_ = false;
                if (auto* token_input = dynamic_cast<TextInputElement*>(token_)) {
                    token_input->SetValue(std::wstring());
                }
                RefreshDirty();
                // batch42 (review): the outcome toast is produced by the app
                // tick once the async save+apply command result is drained -
                // success (CommonSaved) only when the apply really succeeded,
                // otherwise a Danger toast carrying the failure reason. The
                // old optimistic "Saved" here claimed success before the apply
                // ran, then a bare generic error arrived on rollback with the
                // actionable reason only on stderr.
                return true;
            }

            bool SettingsPage::ConfirmLeave(std::function<void()> proceed) {
                // batch27 P1-6: a page with edits that were never saved used to
                // drop them silently on a sidebar switch. Ask first: [Save]
                // [Don't save] [Cancel]. Cancel (and Esc) keep the operator on
                // this page with the edits intact.
                if (dialog_ == nullptr || host_ == nullptr ||
                    !initialized_ || ReadDraft().Equals(applied_)) {
                    return true;  // nothing to lose
                }
                const I18n& i18n = I18n::Instance();
                dialog_->ShowLeavePrompt(
                    i18n.T(Str::SettingsLeaveTitle),
                    i18n.T(Str::SettingsLeaveBody),
                    i18n.T(Str::CommonSave), i18n.T(Str::SettingsLeaveDiscard),
                    i18n.T(Str::CommonCancel),
                    [this, proceed] {
                        // batch275: [Save] must NOT leave the page when the
                        // draft is refused - the operator asked to keep these
                        // edits, so a failed save has to leave them on screen.
                        if (!Save()) {
                            return;
                        }
                        if (proceed) {
                            proceed();
                        }
                    },
                    [proceed] {
                        if (proceed) {
                            proceed();
                        }
                    });
                RelayoutHost(*host_);
                return false;
            }

        }  // namespace

        std::unique_ptr<Page> MakeSettingsPage() {
            return std::make_unique<SettingsPage>();
        }

    }  // namespace ui
}  // namespace vgww
