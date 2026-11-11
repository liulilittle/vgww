// ============================================================================
// dashboard.cpp - dashboard page (S4.3 Task 8): value tiles, the live client
// table and (batch25a) a plain-language status strip for non-technical users.
//
// Layout after batch33 (Win11 Task Manager performance page):
//   * top: one large three-state service strip (running / stopped / anomaly)
//     with the one-click start/stop action, the help entry and the recheck
//     action (anomaly only);
//   * ONE performance card: title + upper-bound range, a 168 px live
//     throughput curve, the "60 s / 0" time axis, the big send/receive
//     numbers and the adapter line (name / type / IPv4 / IPv6);
//   * two everyday cards only: connected devices and uptime (both are
//     navigation targets) - the old up/down cards and their mini curves were
//     removed because the big card already shows those numbers;
//   * everything professional lives in the collapsed "Detailed statistics"
//     block (default collapsed, no tile removed);
//   * the client table keeps its filter/sort toolbar in a bounded 220..420 px
//     band, and the WHOLE page body scrolls (dash.scroll) so a short window
//     can always reach the bottom.
//
// Element ids stay stable (`dash.*` / `page.dashboard.empty`) so the headless
// tests can find them.
// ============================================================================
#include "ui/pages/page.h"

#include "ui/console_log.h"
#include "ui/format.h"
#include "ui/pages/page_util.h"

#include <algorithm>
#include <cstdio>
#include <ctime>
#include <cwchar>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace vgww {
    namespace ui {

        namespace {

            /// batch28: the state strings carry a leading bullet glyph
            /// (filled dot + "running" / hollow dot + "stopped"). The
            /// dedicated StatusDotElement now
            /// paints that dot, so the text drops the glyph (the WORDS are
            /// unchanged - the i18n copy stays authoritative).
            std::wstring WithoutLeadingBullet(std::wstring text) {
                std::size_t start = 0;
                while (start < text.size() &&
                       (text[start] == L'\u25CF' || text[start] == L'\u25CB' ||
                        text[start] == L'\u2022' || text[start] == L' ')) {
                    ++start;
                }
                return text.substr(start);
            }

            /// Client address text. v4 addresses live in bytes[12..15] (wire
            /// order; core::FormatIpv4 wants the first octet in the low byte).
            std::wstring ClientIpText(const vgww::net::IpAddress& ip) {
                std::string text;
                if (ip.family == vgww::net::Family::kV6) {
                    text = vgww::core::FormatIpv6(ip.bytes);
                } else {
                    const uint32_t net =
                        static_cast<uint32_t>(ip.bytes[12]) |
                        (static_cast<uint32_t>(ip.bytes[13]) << 8) |
                        (static_cast<uint32_t>(ip.bytes[14]) << 16) |
                        (static_cast<uint32_t>(ip.bytes[15]) << 24);
                    text = vgww::core::FormatIpv4(net);
                }
                return Widen(text);
            }

            /// batch33 C/B: the connection type from the REAL IfType value
            /// (IP_ADAPTER_ADDRESSES::IfType), never a guess from the name.
            /// 0 (enumeration failed / not reported) reads as "other".
            Str ConnTypeKey(uint32_t if_type) {
                switch (if_type) {
                    case 6:    // IF_TYPE_ETHERNET_CSMACD
                        return Str::ConnTypeEthernet;
                    case 71:   // IF_TYPE_IEEE80211
                        return Str::ConnTypeWifi;
                    default:
                        return Str::ConnTypeOther;
                }
            }

            /// The IPv6 cell of the adapter line: the first real address, or
            /// "disabled" / "none". Nothing is invented when the list is empty.
            std::wstring Ipv6Cell(const UiSnapshot& snapshot, const I18n& i18n) {
                if (!snapshot.config.ipv6_enabled) {
                    return i18n.T(Str::DashAdapterIpv6Disabled);
                }
                if (snapshot.adapter_binding.ipv6.empty()) {
                    return i18n.T(Str::DashAdapterNoIpv6);
                }
                return Widen(snapshot.adapter_binding.ipv6.front());
            }

            /// "adapter / ethernet / 192.168.0.24/24 / fd00::1" - every field
            /// from the binding; unbound reads as the single sentence
            /// "no adapter connected".
            std::wstring AdapterLineText(const UiSnapshot& snapshot,
                                         const I18n& i18n) {
                const auto& binding = snapshot.adapter_binding;
                if (!binding.bound) {
                    return i18n.T(Str::DashAdapterNotBound);
                }
                std::wstring name = Widen(binding.friendly_name);
                if (name.empty()) {
                    // No friendly name: a SHORT device marker, never the whole
                    // "\DEVICE\{GUID}" path.
                    name = Widen(binding.device);
                    const auto open = name.find(L'{');
                    const auto close = open == std::wstring::npos
                                           ? std::wstring::npos
                                           : name.find(L'}', open);
                    if (open != std::wstring::npos && close > open + 1) {
                        std::wstring tail = name.substr(open + 1, close - open - 1);
                        if (tail.size() > 8) {
                            tail.resize(8);
                            tail += L"\u2026";
                        }
                        name = std::wstring(i18n.T(Str::FormAdapter)) + L" " +
                               tail;
                    } else if (name.size() > 24) {
                        name = name.substr(0, 23) + L"\u2026";
                    }
                }
                std::wstring ipv4;
                if (!binding.ipv4.empty()) {
                    ipv4 = Widen(vgww::core::FormatIpv4(
                               binding.ipv4.front().address)) +
                           L"/" +
                           std::to_wstring(binding.ipv4.front().prefix_len);
                } else {
                    ipv4 = i18n.T(Str::CommonNotSet);
                }
                std::wstring out = name;
                out += L" \u00B7 ";
                out += i18n.T(ConnTypeKey(binding.if_type));
                out += L" \u00B7 ";
                out += ipv4;
                out += L" \u00B7 ";
                out += Ipv6Cell(snapshot, i18n);
                return out;
            }

            /// Full hover text: the same fields without the shortening, so a
            /// truncated line still exposes every real value.
            std::wstring AdapterLineTooltip(const UiSnapshot& snapshot) {
                const auto& binding = snapshot.adapter_binding;
                if (!binding.bound) {
                    return std::wstring();
                }
                std::wstring out = Widen(binding.friendly_name);
                if (out.empty()) {
                    out = Widen(binding.device);
                }
                out += L"\n";
                out += Widen(binding.device);
                for (const auto& address : binding.ipv4) {
                    out += L"\n";
                    out += Widen(vgww::core::FormatIpv4(address.address)) +
                           L"/" + std::to_wstring(address.prefix_len);
                }
                for (const std::string& address : binding.ipv6) {
                    out += L"\n";
                    out += Widen(address);
                }
                return out;
            }

            /// Caption + value card, laid out like the Win11 Task Manager
            /// performance tiles: a small dim label, then the big number with
            /// its UNIT on the SAME line (the unit is a separate, one-step
            /// smaller dim Text so it never wraps to its own line), then the
            /// optional mini curve.
            class Tile final : public Card {
            public:
                Tile(Str caption, std::string value_id)
                    : Card(Padding{18.0f, 12.0f, 18.0f, 12.0f}, 10.0f) {
                    auto stack = std::make_unique<StackPanel>(Orientation::Vertical, 8.0f);
                    caption_ = static_cast<Text*>(stack->Add(std::make_unique<Text>(
                        I18n::Instance().T(caption), FontToken::Small,
                        ColorToken::TextDim)));
                    // The number + unit pair: one horizontal row so they always
                    // share a baseline and the unit follows the number's width.
                    auto value_row = std::make_unique<StackPanel>(
                        Orientation::Horizontal, 4.0f);
                    value_row->id = value_id + ".row";
                    auto value = std::make_unique<Text>(L"-", FontToken::Stat,
                                                        ColorToken::Text);
                    value->id = std::move(value_id);
                    value_ = static_cast<Text*>(
                        value_row->Add(std::move(value)));
                    auto unit = std::make_unique<Text>(L"", FontToken::Number,
                                                       ColorToken::TextDim);
                    unit->id = value_->id + ".unit";
                    unit_ = static_cast<Text*>(value_row->Add(std::move(unit)));
                    value_row_ =
                        static_cast<StackPanel*>(stack->Add(std::move(value_row)));
                    stack_ = static_cast<StackPanel*>(Add(std::move(stack)));
                }

                void SetCaption(Str caption) {
                    caption_->SetText(I18n::Instance().T(caption));
                }
                /// Plain value (no unit part): the number alone fills the row.
                void SetValue(std::wstring text) {
                    value_->SetText(std::move(text));
                    unit_->SetText(std::wstring());
                }
                /// Value + unit on ONE line (the Win11 Task Manager shape): the
                /// unit is a separate, one-step smaller dim Text so it can
                /// never wrap onto its own line. Only the rate/duration tiles
                /// use this; a free-text value ("Not set") keeps SetValue so a
                /// space inside the sentence is never mistaken for a unit.
                void SetValueWithUnit(std::wstring number, std::wstring unit) {
                    value_->SetText(std::move(number));
                    unit_->SetText(std::move(unit));
                }
                /// Hover text on the number: the exact value (and, for the
                /// rate cards, the sample time), so an operator can verify it.
                void SetValueTooltip(std::wstring text) {
                    value_->SetTooltip(std::move(text));
                }

                /// batch28: the mini throughput curve under the number (20 px,
                /// no ticks, no frame). Owned by the tile; nullptr for the
                /// tiles that do not get one.
                SparklineElement* SetMiniSpark(std::unique_ptr<SparklineElement> spark) {
                    spark_ = static_cast<SparklineElement*>(
                        stack_->Add(std::move(spark)));
                    return spark_;
                }

                /// batch33 D: an everyday tile is a navigation target. The
                /// whole card becomes clickable (hand cursor + hint tooltip).
                void SetClick(std::function<void()> run, Str hint) {
                    on_click_ = std::move(run);
                    hit_transparent = false;
                    SetTooltip(I18n::Instance().T(hint));
                }
                bool clickable() const noexcept {
                    return static_cast<bool>(on_click_);
                }
                CursorKind cursor_hint(Point) const noexcept override {
                    return on_click_ ? CursorKind::Hand : CursorKind::Arrow;
                }
                /// A clickable tile owns every point inside its box, so the
                /// label/number Texts inside cannot swallow the click.
                Element* HitTest(Point p) override {
                    if (on_click_ && visible && EffectivelyEnabled() &&
                        bounds().Contains(p)) {
                        return this;
                    }
                    return Card::HitTest(p);
                }
                bool OnMouseDown(Point p) override {
                    if (!on_click_ || !EffectivelyEnabled() ||
                        !bounds().Contains(p)) {
                        return false;
                    }
                    pressed_ = true;
                    return true;
                }
                bool OnMouseUp(Point p) override {
                    if (!pressed_) {
                        return false;
                    }
                    pressed_ = false;
                    if (!EffectivelyEnabled() || !bounds().Contains(p)) {
                        return false;
                    }
                    if (on_click_) {
                        on_click_();
                    }
                    return true;
                }

            protected:
                void ArrangeCore(Rect final_rect) override {
                    Card::ArrangeCore(final_rect);
                    // b28-legibility P3: the mini curve spans the card's
                    // CONTENT width (18 px padding each side), is 28 px high and
                    // sits 10 px under the number row - it used to be laid out
                    // by the stack flow and read as a short dash in a corner.
                    // Placing it here (after Card::ArrangeCore) wins over the
                    // flow arrangement.
                    if (spark_ != nullptr) {
                        float window_w = final_rect.w;
                        for (const Element* up = parent(); up != nullptr;
                             up = up->parent()) {
                            window_w = std::max(window_w, up->bounds().w);
                        }
                        spark_->visible = window_w >= 1100.0f;
                        if (spark_->visible && value_row_ != nullptr) {
                            const float x = final_rect.x + 18.0f;
                            const float w = std::max(
                                final_rect.w - 36.0f, 0.0f);
                            const float y = value_row_->bounds().y +
                                            value_row_->bounds().h + 10.0f;
                            spark_->Arrange(Rect{x, y, w, 28.0f});
                        }
                    }
                }

            private:
                Text* caption_ = nullptr;
                Text* value_ = nullptr;
                Text* unit_ = nullptr;
                StackPanel* value_row_ = nullptr;
                StackPanel* stack_ = nullptr;
                SparklineElement* spark_ = nullptr;
                std::function<void()> on_click_;
                bool pressed_ = false;
            };

            /// batch33 B: the Win11 Task Manager performance card. One vertical
            /// instrument block:
            ///   [throughput ................... upper range]
            ///   [         168 px throughput curve          ]
            ///   [60 s                                     0]
            ///   [* send  1.2 MiB/s] [* receive  3.4 MiB/s]
            ///   [adapter / ethernet / 192.168.0.24/24 / none]
            /// The whole card is one click target ("open the detailed
            /// statistics"), and the curve carries its own on_click too.
            class PerfCard final : public Card {
            public:
                PerfCard()
                    : Card(Padding{18.0f, 14.0f, 18.0f, 14.0f}, 10.0f) {
                    hit_transparent = false;
                    const I18n& i18n = I18n::Instance();
                    title_ = static_cast<Text*>(Add(std::make_unique<Text>(
                        i18n.T(Str::DashThroughput), FontToken::Section,
                        ColorToken::Text)));
                    title_->id = "dash.perf.title";
                    range_ = static_cast<Text*>(Add(std::make_unique<Text>(
                        L"", FontToken::Small, ColorToken::TextDim,
                        false, Align::End)));
                    range_->id = "dash.perf.range";
                    auto spark = std::make_unique<SparklineElement>();
                    spark->id = "dash.perf.spark";
                    spark->SetColor(ColorToken::Success);
                    // batch37q: Task Manager style - the wide chart has no
                    // bottom tick marks; its grid labels carry the scale.
                    spark->SetTickCount(0);
                    spark->SetPreferredHeight(kSparkHeight);
                    spark->SetAreaAlpha(0.30f);
                    spark_ = static_cast<SparklineElement*>(
                        Add(std::move(spark)));
                    axis_left_ = static_cast<Text*>(Add(std::make_unique<Text>(
                        i18n.T(Str::DashAxisSixty), FontToken::Micro,
                        ColorToken::TextDim)));
                    axis_left_->id = "dash.perf.axis.left";
                    axis_right_ = static_cast<Text*>(Add(std::make_unique<Text>(
                        i18n.T(Str::DashAxisZero), FontToken::Micro,
                        ColorToken::TextDim, false, Align::End)));
                    axis_right_->id = "dash.perf.axis.right";
                    // Two "big number" pairs, side by side.
                    send_dot_ = static_cast<Text*>(Add(std::make_unique<Text>(
                        std::wstring(L"\u25CF ") + i18n.T(Str::DashSend),
                        FontToken::Small, ColorToken::Accent)));
                    send_dot_->id = "dash.perf.up.label";
                    send_value_ = static_cast<Text*>(Add(std::make_unique<Text>(
                        L"-", FontToken::Title, ColorToken::Text)));
                    send_value_->id = "dash.perf.up";
                    send_unit_ = static_cast<Text*>(Add(std::make_unique<Text>(
                        L"", FontToken::Number, ColorToken::TextDim)));
                    send_unit_->id = "dash.perf.up.unit";
                    recv_dot_ = static_cast<Text*>(Add(std::make_unique<Text>(
                        std::wstring(L"\u25CF ") + i18n.T(Str::DashReceive),
                        FontToken::Small, ColorToken::Success)));
                    recv_dot_->id = "dash.perf.down.label";
                    recv_value_ = static_cast<Text*>(Add(std::make_unique<Text>(
                        L"-", FontToken::Title, ColorToken::Text)));
                    recv_value_->id = "dash.perf.down";
                    recv_unit_ = static_cast<Text*>(Add(std::make_unique<Text>(
                        L"", FontToken::Number, ColorToken::TextDim)));
                    recv_unit_->id = "dash.perf.down.unit";
                    adapter_ = static_cast<Text*>(Add(std::make_unique<Text>(
                        L"", FontToken::Small, ColorToken::TextDim)));
                    adapter_->id = "dash.perf.adapter";
                    SetTooltip(i18n.T(Str::DashPerfCardHint));
                }

                SparklineElement* spark() const noexcept { return spark_; }
                void SetOnClick(std::function<void()> run) {
                    on_click_ = std::move(run);
                }
                void SetRangeLabel(std::wstring text) {
                    range_->SetText(std::move(text));
                }
                void SetValues(std::wstring up_num, std::wstring up_unit,
                               std::wstring down_num, std::wstring down_unit) {
                    send_value_->SetText(std::move(up_num));
                    send_unit_->SetText(std::move(up_unit));
                    recv_value_->SetText(std::move(down_num));
                    recv_unit_->SetText(std::move(down_unit));
                }
                /// The adapter line: name, type, IPv4, IPv6. Never a raw
                /// device path in the body; the full text goes to the tooltip.
                void SetAdapterLine(std::wstring text, std::wstring tooltip) {
                    adapter_->SetText(std::move(text));
                    adapter_->SetTooltip(std::move(tooltip));
                }
                void SetAdapterDim(bool dim) {
                    adapter_->SetColor(dim ? ColorToken::TextDim
                                           : ColorToken::Text);
                }
                /// Exact values + sample time as the hover text of the two big
                /// numbers (an operator can verify the rounded instrument).
                void SetSampleTooltip(std::wstring up_text, std::wstring down_text) {
                    send_value_->SetTooltip(std::move(up_text));
                    recv_value_->SetTooltip(std::move(down_text));
                }
                void Relabel() {
                    const I18n& i18n = I18n::Instance();
                    title_->SetText(i18n.T(Str::DashThroughput));
                    axis_left_->SetText(i18n.T(Str::DashAxisSixty));
                    axis_right_->SetText(i18n.T(Str::DashAxisZero));
                    send_dot_->SetText(std::wstring(L"\u25CF ") +
                                       i18n.T(Str::DashSend));
                    recv_dot_->SetText(std::wstring(L"\u25CF ") +
                                       i18n.T(Str::DashReceive));
                    SetTooltip(i18n.T(Str::DashPerfCardHint));
                }

                CursorKind cursor_hint(Point) const noexcept override {
                    return CursorKind::Hand;
                }
                /// The card is one click target: the title/numbers/axis Texts
                /// inside must not swallow the click that means "open the
                /// detailed statistics".
                ///
                /// batch33g: the CURVE is the one exception. It is its own
                /// instrument - hovering it must show the current/peak/average
                /// readout (the status-strip curve has always done that). When
                /// the card claimed every point the window could only ask the
                /// card for its generic "click for details" hint, so the big
                /// curve's numbers were unreachable. Returning the curve here
                /// keeps both behaviours: hover -> curve data, click -> the
                /// curve's own on_click (OpenDetails, same as the card).
                Element* HitTest(Point p) override {
                    if (visible && EffectivelyEnabled() && bounds().Contains(p)) {
                        if (spark_ != nullptr && spark_->visible &&
                            spark_->bounds().Contains(p)) {
                            return spark_;
                        }
                        return this;
                    }
                    return Card::HitTest(p);
                }
                bool OnMouseDown(Point p) override {
                    if (!EffectivelyEnabled() || !bounds().Contains(p)) {
                        return false;
                    }
                    pressed_ = true;
                    return true;
                }
                bool OnMouseUp(Point p) override {
                    if (!pressed_) {
                        return false;
                    }
                    pressed_ = false;
                    if (!EffectivelyEnabled() || !bounds().Contains(p)) {
                        return false;
                    }
                    if (on_click_) {
                        on_click_();
                    }
                    return true;
                }

                static constexpr float kSparkHeight = 168.0f;
                static constexpr float kSparkCompact = 120.0f;
                static constexpr float kGap = 10.0f;

            protected:
                Size MeasureCore(Size available) override {
                    const float inner_w = std::max(
                        0.0f, available.w - padding().horizontal());
                    // batch33d: the curve tier MUST come from the same width the
                    // arrange pass uses (the window width), otherwise measure
                    // reserves no room for a curve that arrange then paints at
                    // 168 px - the card stayed ~144 px tall and the curve was
                    // drawn straight over the two cards underneath.
                    const float spark_h = SparkHeightFor(WindowWidth(available.w));
                    const Size title = title_->Measure(Size{inner_w, 1.0e9f});
                    const Size range = range_->Measure(Size{inner_w, 1.0e9f});
                    const Size axis = axis_left_->Measure(Size{inner_w, 1.0e9f});
                    const Size up = send_value_->Measure(Size{inner_w, 1.0e9f});
                    const Size down = recv_value_->Measure(Size{inner_w, 1.0e9f});
                    const Size adapter =
                        adapter_->Measure(Size{inner_w, 1.0e9f});
                    const float numbers_h = std::max(up.h, down.h) +
                                            std::max(send_dot_->desired().h,
                                                     recv_dot_->desired().h) +
                                            6.0f;
                    const float h = padding().vertical() +
                                    std::max(title.h, range.h) + kGap +
                                    spark_h + (spark_h > 0.0f ? kGap : 0.0f) +
                                    axis.h + kGap + numbers_h + kGap +
                                    adapter.h;
                    return Size{std::max(inner_w, 0.0f) +
                                    padding().horizontal(),
                                h};
                }

                void ArrangeCore(Rect final_rect) override {
                    const float left = final_rect.x + padding().l;
                    const float inner_w = std::max(
                        0.0f, final_rect.w - padding().horizontal());
                    float y = final_rect.y + padding().t;
                    // Title left, range right, on one line.
                    const Size title = title_->Measure(Size{inner_w, 1.0e9f});
                    const Size range = range_->Measure(Size{inner_w, 1.0e9f});
                    const float title_h = std::max(title.h, range.h);
                    title_->Arrange(Rect{left, y, title.w, title_h});
                    range_->Arrange(Rect{left + std::max(inner_w - range.w, 0.0f),
                                         y, std::min(range.w, inner_w), title_h});
                    y += title_h + kGap;
                    // The big curve. batch33l: the tier follows the CARD's inner
                    // width (what the curve actually gets), identical to the
                    // number MeasureCore used - see WindowWidth().
                    const float spark_h = SparkHeightFor(WindowWidth(inner_w));
                    spark_->SetPreferredHeight(spark_h > 0.0f ? spark_h
                                                             : kSparkHeight);
                    spark_->visible = spark_h > 0.0f;
                    if (spark_->visible) {
                        spark_->Arrange(Rect{left, y, inner_w, spark_h});
                        y += spark_h + kGap;
                    }
                    // Time axis: "60 s" left, "0" right.
                    const Size axis = axis_left_->Measure(Size{inner_w, 1.0e9f});
                    const Size axis_r = axis_right_->Measure(Size{inner_w, 1.0e9f});
                    const float axis_h = std::max(axis.h, axis_r.h);
                    axis_left_->Arrange(Rect{left, y, axis.w, axis_h});
                    axis_right_->Arrange(
                        Rect{left + std::max(inner_w - axis_r.w, 0.0f), y,
                             std::min(axis_r.w, inner_w), axis_h});
                    y += axis_h + kGap;
                    // The two big numbers side by side, each a label above the
                    // value+unit pair (Task Manager shape).
                    const float half = std::max((inner_w - 24.0f) * 0.5f, 0.0f);
                    const auto place_metric = [&](Text* label, Text* value,
                                                  Text* unit, float x) {
                        const Size l = label->Measure(Size{half, 1.0e9f});
                        label->Arrange(Rect{x, y, half, l.h});
                        const Size v = value->Measure(Size{half, 1.0e9f});
                        const Size u = unit->Measure(Size{half, 1.0e9f});
                        const float vy = y + l.h + 2.0f;
                        value->Arrange(Rect{x, vy, std::min(v.w, half), v.h});
                        unit->Arrange(
                            Rect{x + std::min(v.w, half) + 4.0f, vy,
                                 std::min(u.w, std::max(half - v.w - 4.0f,
                                                        0.0f)),
                                 u.h});
                        return vy + std::max(v.h, u.h);
                    };
                    const float left_bottom =
                        place_metric(send_dot_, send_value_, send_unit_, left);
                    const float right_bottom = place_metric(
                        recv_dot_, recv_value_, recv_unit_,
                        left + half + 24.0f);
                    y = std::max(left_bottom, right_bottom) + kGap;
                    // Adapter line, full width (ellipsized by the renderer).
                    const Size adapter =
                        adapter_->Measure(Size{inner_w, 1.0e9f});
                    adapter_->Arrange(Rect{left, y, inner_w,
                                           std::min(adapter.h,
                                                    std::max(final_rect.y +
                                                                 final_rect.h -
                                                                 padding().b - y,
                                                             0.0f))});
                }

            private:
                /// batch33d: ONE width drives the curve tier. The arrange pass
                /// has always used the widest ancestor box (the window) rather
                /// than the card's inner width, so measure must use the exact
                /// same number or the reserved height and the painted height
                /// disagree (the 168 px curve overflowed a 144 px card).
                /// batch33l: the tier is chosen from the card's own inner width
                /// - the space the curve actually gets. Using the WINDOW width
                /// (batch33d) made a 496 px card inside a 700 px window still
                /// qualify for the 120 px tier, so the curve was painted into a
                /// box narrower than the tier assumed. Measure and arrange both
                /// call this with the same number (the card's inner width).
                float WindowWidth(float own_w) const noexcept {
                    return own_w;
                }

                /// batch33l: the thresholds are expressed in CARD INNER width
                /// (the space the curve actually gets), not window width.
                /// Calibrated against the real geometry measured on this app
                /// (window - 252 px of sidebar/margins - 36 px card padding):
                ///   1280 window -> 992 inner -> 168 px
                ///    900 window -> 612 inner -> 168 px
                ///    880 window -> 592 inner -> 120 px
                ///    800 window -> 512 inner -> 120 px
                ///    700 window -> 460 inner -> hidden
                static float SparkHeightFor(float width) noexcept {
                    if (width >= 600.0f) {
                        return kSparkHeight;
                    }
                    if (width >= 500.0f) {
                        return kSparkCompact;
                    }
                    return 0.0f;
                }

                Text* title_ = nullptr;
                Text* range_ = nullptr;
                SparklineElement* spark_ = nullptr;
                Text* axis_left_ = nullptr;
                Text* axis_right_ = nullptr;
                Text* send_dot_ = nullptr;
                Text* send_value_ = nullptr;
                Text* send_unit_ = nullptr;
                Text* recv_dot_ = nullptr;
                Text* recv_value_ = nullptr;
                Text* recv_unit_ = nullptr;
                Text* adapter_ = nullptr;
                std::function<void()> on_click_;
                bool pressed_ = false;
            };
            /// batch25a: status text on the left, actions on the right. Hidden
            /// actions do not reserve space (the anomaly-only recheck button
            /// disappears completely in the healthy state).
            class StatusStrip final : public Element {
            public:
                StatusStrip() { hit_transparent = true; }

                Text* SetStatus(std::unique_ptr<Text> status) {
                    status_ = static_cast<Text*>(Element::Add(std::move(status)));
                    return status_;
                }
                void SetActions(Button* help, Button* recheck, Button* action,
                                Button* setup = nullptr) {
                    help_ = help;
                    recheck_ = recheck;
                    action_ = action;
                    setup_ = setup;
                }
                /// batch26: lightweight online-count badge, right-aligned next
                /// to the action buttons (the card already shows the number;
                /// the strip keeps only the short state sentence).
                void SetOnlineBadge(BadgeElement* badge) { online_ = badge; }
                /// batch28: the breathing status dot (before the short state
                /// word).
                void SetStatusDot(StatusDotElement* dot) { dot_ = dot; }
                /// batch33l (user: "one chart is enough"): the strip's miniature
                /// curve was a 4x smaller copy of the SAME data the performance
                /// card already plots - it carried no new information and ate
                /// 294 px of the row. It is gone; the strip now shows the one
                /// thing a non-technical user actually needs there: the gateway
                /// address other devices must be pointed at (previously buried
                /// in the Help dialog).
                void SetGatewayLine(Text* label, Text* value, Button* copy) {
                    gateway_label_ = label;
                    gateway_value_ = value;
                    gateway_copy_ = copy;
                }

            protected:
                Size MeasureCore(Size available) override {
                    float h = 0.0f;
                    for (const auto& child : children()) {
                        if (!child->visible) {
                            continue;
                        }
                        h = std::max(h, child->Measure(available).h);
                    }
                    return Size{std::max(0.0f, available.w), h};
                }

                void ArrangeCore(Rect final_rect) override {
                    constexpr float kGap = 10.0f;
                    float right = final_rect.x + final_rect.w;
                    const auto place = [&](Element* button) {
                        if (button == nullptr || !button->visible) {
                            return;
                        }
                        const Size d = button->Measure(Size{final_rect.w,
                                                            final_rect.h});
                        const float h = std::min(d.h, final_rect.h);
                        const float y =
                            final_rect.y + (final_rect.h - h) * 0.5f;
                        button->Arrange(
                            Rect{right - d.w, y, d.w, h});
                        right -= d.w + kGap;
                    };
                    place(action_);
                    place(setup_);
                    place(recheck_);
                    place(help_);
                    place(online_);

                    // batch28 (b28-legibility P4): the strip order is FIXED -
                    // [dot] [state word] [curve] [badge] [buttons], with 8 px
                    // between dot and word and 14 px before the curve. The dot,
                    // the word and the curve share one vertical centre so they
                    // read as one instrument row (the curve used to sit BEFORE
                    // the word, which made it look like a prefix).
                    const float center_y = final_rect.y + final_rect.h * 0.5f;
                    float left = final_rect.x;
                    if (dot_ != nullptr && dot_->visible) {
                        const Size d = dot_->Measure(
                            Size{final_rect.w, final_rect.h});
                        dot_->Arrange(Rect{left,
                                           center_y - d.h * 0.5f, d.w, d.h});
                        left += d.w + 8.0f;
                    }
                    // The state word takes its natural width first (it is short
                    // by design), then the curve follows.
                    float status_w = 0.0f;
                    if (status_ != nullptr) {
                        status_w = status_->Measure(Size{
                            std::max(right - left, 0.0f), final_rect.h}).w;
                        const float w = std::max(
                            0.0f, std::min(status_w, right - left));
                        status_->Arrange(
                            Rect{left, final_rect.y, w, final_rect.h});
                        left += w;
                    }
                    // batch33l: after the state word, the gateway line:
                    //   [gateway address (what other devices must enter)]
                    //   192.168.0.40  [copy]
                    // This replaced the miniature throughput curve, which only
                    // duplicated the performance card at 1/4 the size. The
                    // address is the one thing a non-technical user needs from
                    // this row (it used to be reachable only via Help).
                    if (gateway_value_ != nullptr) {
                        const float gap = 18.0f;
                        float x = left + gap;
                        const float room = std::max(right - x, 0.0f);
                        // Hide the whole group when the row cannot host it: the
                        // buttons on the right always win (they are actions).
                        const Size label_sz = gateway_label_ != nullptr
                                                  ? gateway_label_->Measure(
                                                        Size{room, final_rect.h})
                                                  : Size{};
                        const Size value_sz =
                            gateway_value_->Measure(Size{room, final_rect.h});
                        const Size copy_sz =
                            gateway_copy_ != nullptr
                                ? gateway_copy_->Measure(
                                      Size{room, final_rect.h})
                                : Size{};
                        const float group_w =
                            label_sz.w + 8.0f + value_sz.w + 10.0f + copy_sz.w;
                        const bool fits = group_w <= room && room > 0.0f;
                        if (gateway_label_ != nullptr) {
                            gateway_label_->visible = fits;
                        }
                        gateway_value_->visible = fits;
                        if (gateway_copy_ != nullptr) {
                            gateway_copy_->visible = fits;
                        }
                        if (fits) {
                            if (gateway_label_ != nullptr) {
                                gateway_label_->Arrange(
                                    Rect{x, final_rect.y, label_sz.w,
                                         final_rect.h});
                                x += label_sz.w + 8.0f;
                            }
                            gateway_value_->Arrange(
                                Rect{x, final_rect.y, value_sz.w,
                                     final_rect.h});
                            x += value_sz.w + 10.0f;
                            if (gateway_copy_ != nullptr) {
                                const float h =
                                    std::min(copy_sz.h, final_rect.h);
                                gateway_copy_->Arrange(Rect{
                                    x, center_y - h * 0.5f, copy_sz.w, h});
                            }
                        }
                    }
                }

            private:
                Text* status_ = nullptr;
                Button* help_ = nullptr;
                Button* recheck_ = nullptr;
                Button* action_ = nullptr;
                /// batch27 P1-5: the unconfigured-state "set it up for me".
                Button* setup_ = nullptr;
                BadgeElement* online_ = nullptr;
                /// batch28: breathing dot (optional).
                StatusDotElement* dot_ = nullptr;
                /// batch33l: gateway line (label + address + copy).
                Text* gateway_label_ = nullptr;
                Text* gateway_value_ = nullptr;
                Button* gateway_copy_ = nullptr;
            };

            /// S5-AESTH R2: the client-table area that stretches to the bottom
            /// of the content column. The table takes the whole available
            /// height (its own border/cells fill the panel) and the empty
            /// placeholder is centred inside that stretched region, so the
            /// zone under a short table no longer reads as dead space.
            class FillPanel final : public Element {
            public:
                FillPanel() { hit_transparent = true; }

                TableElement* SetTable(std::unique_ptr<TableElement> table) {
                    table_ =
                        static_cast<TableElement*>(Element::Add(std::move(table)));
                    return table_;
                }
                EmptyState* SetEmpty(std::unique_ptr<EmptyState> empty) {
                    empty_ =
                        static_cast<EmptyState*>(Element::Add(std::move(empty)));
                    return empty_;
                }
                /// batch33 F: switch from "stretch to the bottom" to a bounded
                /// band of [min_h, max_h] (the dashboard's page-scroll layout).
                void SetBoundedHeight(float min_h, float max_h) {
                    bounded_ = true;
                    min_h_ = std::min(min_h, max_h);
                    max_h_ = std::max(min_h, max_h);
                    fill_remaining = false;
                }

            protected:
                Size MeasureCore(Size available) override {
                    float natural = 0.0f;
                    if (table_ != nullptr) {
                        table_->Measure(available);
                        natural = std::max(natural, table_->desired().h);
                    }
                    if (empty_ != nullptr && empty_->visible) {
                        empty_->Measure(available);
                        natural = std::max(natural, empty_->desired().h);
                    }
                    if (bounded_) {
                        // batch33 F: a BOUNDED band (the dashboard table lives
                        // in a page ScrollView, so it must not claim the
                        // leftover height - it gets 220..420 px and scrolls
                        // inside that band).
                        const float h = std::min(std::max(natural, min_h_), max_h_);
                        return Size{available.w, h};
                    }
                    // Stretch to the bottom of the content column; grow past it
                    // only when the real content is taller than the available
                    // space (the table then keeps its natural height).
                    return Size{available.w, std::max(natural, available.h)};
                }

                void ArrangeCore(Rect final_rect) override {
                    if (table_ != nullptr) {
                        table_->Arrange(final_rect);
                    }
                    if (empty_ != nullptr && empty_->visible) {
                        const Size d = empty_->desired();
                        // batch27 D2: centre inside the region BELOW the table
                        // header band (the header is part of the empty surface),
                        // so the whitespace above and below the placeholder
                        // match instead of the old "glued to the header" look.
                        const float header_h =
                            (table_ != nullptr && table_->bounds().h > 0.0f)
                                ? TableElement::header_height()
                                : 0.0f;
                        const float top = final_rect.y + header_h;
                        const float region_h =
                            std::max(final_rect.h - header_h, 0.0f);
                        const float h = std::min(d.h, region_h);
                        empty_->Arrange(
                            Rect{final_rect.x + (final_rect.w - d.w) * 0.5f,
                                 top + (region_h - h) * 0.5f,
                                 d.w, h});
                    }
                }

            private:
                TableElement* table_ = nullptr;
                EmptyState* empty_ = nullptr;
                bool bounded_ = false;
                float min_h_ = 0.0f;
                float max_h_ = 0.0f;
            };

            class DashboardPage final : public Page {
            public:
                const char* id() const override { return "dashboard"; }
                Str title() const override { return Str::NavDashboard; }
                void Build(Element& host, PageContext& ctx) override;
                void Update(const UiSnapshot& snapshot, I18n& i18n) override;
                /// batch33 D: "mac=..." from a device row, or an empty intent
                /// (the performance card / a tile) - both open the detailed
                /// statistics and scroll them into view.
                void OnIntent(const std::string& intent) override;
                /// batch281: a refused start/stop leaves `dataplane_running`
                /// where it was, so the busy guard (armed on click) would never
                /// see its target state and the primary action stayed disabled
                /// forever. Release the guard so the operator can retry.
                void OnCommandFailed() override {
                    if (!busy_) {
                        return;
                    }
                    busy_ = false;
                    if (action_ != nullptr) {
                        action_->enabled = true;
                    }
                }

            private:
                void Relabel();
                void Relayout();
                void ShowHelp();
                void ShowSetup();
                void UpdateToggleLabel();
                /// batch33 D: expand the detailed statistics and scroll them
                /// into the viewport (the curve / card click target).
                void OpenDetails();
                /// batch33l: copy the gateway address from the status strip
                /// (the Help dialog's copy action, now one click away).
                void CopyGatewayAddress();
                void OpenRowMenu(const std::string& mac, Point at);

                PageContext* ctx_ = nullptr;
                Element* host_ = nullptr;

                // batch25a: plain-language status strip + actions.
                Text* status_ = nullptr;
                Button* action_ = nullptr;
                /// batch27 P1-5: one-click first-time setup entry point.
                Button* setup_ = nullptr;
                /// batch27 P1-9: a start/stop click disables the action until
                /// the service state actually changes (no double-fire).
                bool busy_ = false;
                /// The state the in-flight click asked for (busy_ only).
                bool busy_target_running_ = false;
                /// batch26: right-side online count badge on the status strip.
                BadgeElement* online_ = nullptr;
                /// batch28: breathing dot on the strip.
                StatusDotElement* dot_ = nullptr;
                /// batch33l: the gateway line that replaced the miniature curve
                /// (label + address + copy button).
                Text* gateway_label_ = nullptr;
                Text* gateway_value_ = nullptr;
                Button* gateway_copy_ = nullptr;
                Button* help_ = nullptr;
                Button* recheck_ = nullptr;
                DialogHost* dialog_ = nullptr;
                bool last_running_ = false;
                std::wstring help_address_;

                // batch33 F: the page-wide scroller.
                ScrollView* scroll_ = nullptr;
                // batch33 B: the Task Manager performance card.
                PerfCard* perf_ = nullptr;
                SparklineElement* perf_spark_ = nullptr;

                // batch33 D/E: the client-row context menu.
                ContextMenu* context_menu_ = nullptr;
                std::string menu_mac_;

                // Core (always visible) cards.
                Tile* clients_tile_ = nullptr;
                Tile* uptime_ = nullptr;
                /// batch29: true once the uptime tile carries a value; a
                /// stopped service then freezes it (no 1 Hz residual repaint).
                bool uptime_shown_ = false;
                /// batch29: true once the client table carries rows; a stopped
                /// service freezes the "last seen" cells (same reason).
                bool clients_rows_shown_ = false;
            /// batch132: the row count ACTUALLY painted. While the plane is
            /// stopped the table is frozen, so the tile and the empty state
            /// must describe these rows, not this tick's snapshot.
            std::size_t shown_count_ = 0;

                // Detailed statistics (collapsed by default; nothing removed).
                Element* details_ = nullptr;
                Button* details_toggle_ = nullptr;
                Tile* rx_ = nullptr;
                Tile* tx_ = nullptr;
                Tile* cpu_ = nullptr;
                Tile* mem_ = nullptr;
                // batch22 A7: identity / protocol row.
                Tile* gw_ = nullptr;
                Tile* ipv6_ = nullptr;
                Tile* tcp_ = nullptr;
                Tile* drops_ = nullptr;
                Tile* pass_ = nullptr;
                Tile* vlan_rx_ = nullptr;
                Tile* vlan_tx_ = nullptr;
                Tile* vmem_ = nullptr;

                TableElement* clients_ = nullptr;
                EmptyState* empty_ = nullptr;
                // batch22 A2: client-table view controls (mirrors the Web
                // dashboard's filter/sort semantics).
                SelectElement* filter_ = nullptr;
                SelectElement* sort_ = nullptr;
                SelectElement* dir_ = nullptr;
                enum class ClientFilter { All, Lan, Wan };
                enum class ClientSort { Rate, Up, Down, Seen };
                ClientFilter client_filter_ = ClientFilter::All;
                ClientSort client_sort_ = ClientSort::Rate;
                /// batch22 A2: language code the toolbar labels were built
                /// with; Relabel() only re-localizes when it changes.
                std::string view_lang_;
                bool sort_desc_ = true;  ///< Web default: busiest first
            };

            void DashboardPage::Build(Element& host, PageContext& ctx) {
                ctx_ = &ctx;
                host_ = &host;
                const I18n& i18n = I18n::Instance();

                // ---- batch25a: the single plain-language status strip ------
                auto status_card = std::make_unique<Card>(
                    Padding{18.0f, 14.0f, 18.0f, 14.0f}, 10.0f);
                status_card->id = "dash.status.bar";
                Card* status_card_raw =
                    static_cast<Card*>(host.Add(std::move(status_card)));
                auto strip = std::make_unique<StatusStrip>();
                StatusStrip* strip_raw =
                    static_cast<StatusStrip*>(status_card_raw->Add(
                        std::move(strip)));
                status_ = strip_raw->SetStatus(std::make_unique<Text>(
                    L"", FontToken::Title, ColorToken::TextDim));
                status_->id = "dash.status.text";

                // batch28 (user request): the static "dot + running" becomes a
                // live instrument - a breathing dot, the short state word, and
                // a tick-framed curve of the current throughput.
                dot_ = static_cast<StatusDotElement*>(strip_raw->Add(
                    std::make_unique<StatusDotElement>()));
                dot_->id = "dash.status.dot";
                dot_->SetColor(ColorToken::TextDim);
                strip_raw->SetStatusDot(dot_);

                // batch33l: the strip used to carry a miniature copy of the
                // throughput curve. The performance card plots the same data at
                // 4x the size, so the copy added nothing but visual noise; the
                // space now holds the gateway address (the single thing a
                // non-technical user needs from this row) plus a copy button.
                gateway_label_ = static_cast<Text*>(strip_raw->Add(
                    std::make_unique<Text>(i18n.T(Str::DashGateway),
                                           FontToken::Body,
                                           ColorToken::TextDim)));
                gateway_label_->id = "dash.status.gateway.label";
                gateway_value_ = static_cast<Text*>(strip_raw->Add(
                    std::make_unique<Text>(L"-", FontToken::BodyStrong,
                                           ColorToken::Text)));
                gateway_value_->id = "dash.status.gateway";
                gateway_copy_ = static_cast<Button*>(strip_raw->Add(
                    std::make_unique<Button>(i18n.T(Str::DashHelpCopy),
                                             ButtonStyle::Secondary)));
                gateway_copy_->id = "dash.status.gateway.copy";
                gateway_copy_->on_click = [this] { CopyGatewayAddress(); };
                strip_raw->SetGatewayLine(gateway_label_, gateway_value_,
                                          gateway_copy_);

                // batch26: the count left the sentence; a small badge on the
                // right keeps it glanceable without duplicating the card's
                // big number as prose. Neutral low-saturation by default.
                online_ = static_cast<BadgeElement*>(strip_raw->Add(
                    std::make_unique<BadgeElement>(L"", BadgeKind::Success)));
                online_->id = "dash.status.online";
                online_->visible = false;
                strip_raw->SetOnlineBadge(online_);

                help_ = static_cast<Button*>(strip_raw->Add(std::make_unique<Button>(
                    i18n.T(Str::DashHelp), ButtonStyle::Secondary)));
                help_->id = "dash.help";
                help_->on_click = [this] { ShowHelp(); };

                recheck_ = static_cast<Button*>(strip_raw->Add(std::make_unique<Button>(
                    i18n.T(Str::DashRecheck), ButtonStyle::Secondary)));
                recheck_->id = "dash.recheck";
                recheck_->visible = false;
                recheck_->on_click = [this] {
                    if (ctx_ == nullptr) {
                        return;
                    }
                    SubmitCommand(*ctx_, Command{RecheckServiceCmd{}});
                };

                action_ = static_cast<Button*>(strip_raw->Add(std::make_unique<Button>(
                    i18n.T(Str::DashStart), ButtonStyle::Primary)));
                action_->id = "dash.action";
                action_->on_click = [this] {
                    if (ctx_ == nullptr || busy_) {
                        return;
                    }
                    // batch27 P1-9: immediate feedback + no double-fire. The
                    // busy state ends when a snapshot shows the new service
                    // state (or the command is rejected as busy).
                    busy_ = true;
                    busy_target_running_ = !last_running_;
                    action_->enabled = false;
                    action_->SetLabel(I18n::Instance().T(
                        last_running_ ? Str::DashStopping : Str::DashStarting));
                    const bool posted = SubmitCommand(
                        *ctx_, last_running_ ? Command{StopServiceCmd{}}
                                             : Command{StartServiceCmd{}});
                    if (!posted) {
                        busy_ = false;
                        action_->enabled = true;
                        action_->SetLabel(I18n::Instance().T(
                            last_running_ ? Str::DashStop : Str::DashStart));
                    }
                };
                // batch27 P1-5: a beginner who has not configured anything gets
                // the fix right here - the primary action becomes "set it up for
                // me" (the first-run wizard) instead of sending them hunting in
                // Settings. Hidden unless the service is unconfigured.
                setup_ = static_cast<Button*>(strip_raw->Add(std::make_unique<Button>(
                    i18n.T(Str::DashSetup), ButtonStyle::Primary)));
                setup_->id = "dash.setup";
                setup_->visible = false;
                setup_->on_click = [this] { ShowSetup(); };
                strip_raw->SetActions(help_, recheck_, action_, setup_);

                // ---- batch33 F: the whole page body scrolls ------------------
                // Everything except the dialog goes into ONE vertical content
                // stack inside a ScrollView that claims the host's leftover
                // height, so a short window can always reach the bottom.
                auto scroll = std::make_unique<ScrollView>(
                    std::make_unique<StackPanel>(Orientation::Vertical, 12.0f,
                                                 Padding{}, Align::Stretch));
                scroll->id = "dash.scroll";
                scroll->fill_remaining = true;
                ScrollView* scroll_raw =
                    static_cast<ScrollView*>(host.Add(std::move(scroll)));
                scroll_ = scroll_raw;
                Element* content = scroll_raw->children().empty()
                                       ? nullptr
                                       : scroll_raw->children().front().get();
                StackPanel* body = static_cast<StackPanel*>(content);
                body->id = "dash.content";

                // ---- batch33 B: the Task Manager performance card -----------
                auto perf = std::make_unique<PerfCard>();
                perf->id = "dash.perf.card";
                perf_ = static_cast<PerfCard*>(body->Add(std::move(perf)));
                perf_spark_ = perf_->spark();
                perf_->SetOnClick([this] { OpenDetails(); });
                perf_spark_->on_click = [this] { OpenDetails(); };
                perf_spark_->SetClickHint(I18n::Instance().T(Str::DashPerfCardHint));

                // ---- two everyday cards: connected devices + uptime --------
                auto core = std::make_unique<GridLayout>(
                    std::vector<ColumnSpec>{ColumnSpec::Star(),
                                            ColumnSpec::Star()},
                    10.0f);
                core->id = "dash.core";
                GridLayout* core_grid =
                    static_cast<GridLayout*>(body->Add(std::move(core)));
                clients_tile_ = static_cast<Tile*>(core_grid->Add(
                    std::make_unique<Tile>(Str::DashClients, "dash.tile.clients")));
                uptime_ = static_cast<Tile*>(core_grid->Add(
                    std::make_unique<Tile>(Str::DashUptime, "dash.tile.uptime")));
                clients_tile_->SetClick(
                    [this] {
                        if (ctx_ != nullptr && ctx_->navigate_intent) {
                            ctx_->navigate_intent("leases", std::string());
                        } else if (ctx_ != nullptr && ctx_->navigate) {
                            ctx_->navigate("leases");
                        }
                    },
                    Str::DashTileClientsHint);
                uptime_->SetClick(
                    [this] {
                        if (ctx_ != nullptr && ctx_->navigate_intent) {
                            ctx_->navigate_intent("about", std::string());
                        } else if (ctx_ != nullptr && ctx_->navigate) {
                            ctx_->navigate("about");
                        }
                    },
                    Str::DashTileUptimeHint);

                // ---- detailed statistics (collapsed by default) -------------
                auto details_header =
                    std::make_unique<StackPanel>(Orientation::Horizontal, 8.0f);
                StackPanel* details_header_raw =
                    static_cast<StackPanel*>(body->Add(std::move(details_header)));
                details_toggle_ =
                    static_cast<Button*>(details_header_raw->Add(
                        std::make_unique<Button>(L"", ButtonStyle::Secondary)));
                details_toggle_->id = "dash.details.toggle";
                details_toggle_->on_click = [this] {
                    if (details_ == nullptr) {
                        return;
                    }
                    details_->visible = !details_->visible;
                    UpdateToggleLabel();
                    Relayout();
                };

                auto details = std::make_unique<StackPanel>(Orientation::Vertical,
                                                            10.0f);
                details->id = "dash.details";
                details->visible = false;
                details_ = body->Add(std::move(details));
                auto detail_grid = std::make_unique<GridLayout>(
                    std::vector<ColumnSpec>{ColumnSpec::Star(), ColumnSpec::Star(),
                                            ColumnSpec::Star(), ColumnSpec::Star()},
                    8.0f);
                GridLayout* details_grid = static_cast<GridLayout*>(
                    details_->Add(std::move(detail_grid)));
                rx_ = static_cast<Tile*>(
                    details_grid->Add(std::make_unique<Tile>(Str::DashRx, "dash.tile.rx")));
                tx_ = static_cast<Tile*>(
                    details_grid->Add(std::make_unique<Tile>(Str::DashTx, "dash.tile.tx")));
                cpu_ = static_cast<Tile*>(details_grid->Add(
                    std::make_unique<Tile>(Str::DashCpu, "dash.sys.cpu")));
                mem_ = static_cast<Tile*>(details_grid->Add(
                    std::make_unique<Tile>(Str::DashMem, "dash.sys.mem")));
                // batch22 A7: the identity / protocol row. Every value below is
                // read from a field the core model already publishes.
                gw_ = static_cast<Tile*>(details_grid->Add(
                    std::make_unique<Tile>(Str::DashGateway, "dash.gw")));
                ipv6_ = static_cast<Tile*>(details_grid->Add(
                    std::make_unique<Tile>(Str::DashIpv6Status, "dash.ipv6")));
                tcp_ = static_cast<Tile*>(details_grid->Add(
                    std::make_unique<Tile>(Str::DashTcp, "dash.tcp")));
                drops_ = static_cast<Tile*>(details_grid->Add(
                    std::make_unique<Tile>(Str::DashDrops, "dash.drops")));
                pass_ = static_cast<Tile*>(details_grid->Add(
                    std::make_unique<Tile>(Str::DashPass, "dash.pass")));
                vlan_rx_ = static_cast<Tile*>(details_grid->Add(
                    std::make_unique<Tile>(Str::DashVlanRx, "dash.vlan.rx")));
                vlan_tx_ = static_cast<Tile*>(details_grid->Add(
                    std::make_unique<Tile>(Str::DashVlanTx, "dash.vlan.tx")));
                vmem_ = static_cast<Tile*>(details_grid->Add(
                    std::make_unique<Tile>(Str::DashVmem, "dash.vmem")));

                // batch22 A2: filter + sort toolbar. Same control vocabulary as
                // Settings (SelectElement), so the look matches the rest of the
                // app; the option VALUES stay ASCII tokens while the labels are
                // localized.
                auto toolbar = std::make_unique<StackPanel>(Orientation::Horizontal, 8.0f);
                StackPanel* toolbar_raw = static_cast<StackPanel*>(body->Add(std::move(toolbar)));
                toolbar_raw->id = "dash.controls";
                filter_ = static_cast<SelectElement*>(toolbar_raw->Add(std::make_unique<SelectElement>()));
                filter_->id = "dash.filter";
                filter_->SetOptions({{L"all", i18n.T(Str::DashFilterAll)},
                                     {L"lan", i18n.T(Str::DashFilterLan)},
                                     {L"wan", i18n.T(Str::DashFilterWan)}});
                filter_->SetSelectedValueSilent(L"all");
                filter_->on_changed = [this] {
                    if (filter_ == nullptr) {
                        return;
                    }
                    const std::wstring value = filter_->selected_value();
                    client_filter_ = value == L"lan"
                                         ? ClientFilter::Lan
                                         : (value == L"wan" ? ClientFilter::Wan
                                                            : ClientFilter::All);
                    // batch331: an explicit view change must repaint even while
                    // the table is frozen by a stopped service. Update()'s
                    // rebuild gate is `dataplane_running ||
                    // !clients_rows_shown_`, and nothing else ever clears that
                    // flag - so a filter picked after Stop stayed inert until
                    // the service was restarted.
                    clients_rows_shown_ = false;
                };
                sort_ = static_cast<SelectElement*>(toolbar_raw->Add(std::make_unique<SelectElement>()));
                sort_->id = "dash.sort";
                sort_->SetOptions({{L"rate", i18n.T(Str::DashSortRate)},
                                   {L"up", i18n.T(Str::DashSortUp)},
                                   {L"down", i18n.T(Str::DashSortDown)},
                                   {L"seen", i18n.T(Str::DashSortSeen)}});
                sort_->SetSelectedValueSilent(L"rate");
                sort_->on_changed = [this] {
                    if (sort_ == nullptr) {
                        return;
                    }
                    const std::wstring value = sort_->selected_value();
                    client_sort_ = value == L"up"
                                       ? ClientSort::Up
                                       : (value == L"down"
                                              ? ClientSort::Down
                                              : (value == L"seen"
                                                     ? ClientSort::Seen
                                                     : ClientSort::Rate));
                    // batch331: same reason as the filter above - a sort picked
                    // while the service is stopped must still repaint.
                    clients_rows_shown_ = false;
                };
                dir_ = static_cast<SelectElement*>(toolbar_raw->Add(std::make_unique<SelectElement>()));
                dir_->id = "dash.sort.dir";
                dir_->SetOptions({{L"desc", i18n.T(Str::DashSortDesc)},
                                  {L"asc", i18n.T(Str::DashSortAsc)}});
                dir_->SetSelectedValueSilent(L"desc");
                dir_->on_changed = [this] {
                    if (dir_ == nullptr) {
                        return;
                    }
                    sort_desc_ = dir_->selected_value() != L"asc";
                    // batch331: same reason as the filter above - a direction
                    // flip picked while the service is stopped must repaint.
                    clients_rows_shown_ = false;
                };

                // batch33 F: the client table no longer claims the leftover
                // height (the ScrollView does); it gets a bounded band of
                // 220..420 px so a long list still scrolls INSIDE the table,
                // and once the table reaches its own end the wheel bubbles to
                // the page scroll (TableElement::OnWheel only consumes a real
                // move).
                auto fill = std::make_unique<FillPanel>();
                fill->id = "dash.table.panel";
                FillPanel* fill_raw = static_cast<FillPanel*>(body->Add(std::move(fill)));
                fill_raw->SetBoundedHeight(220.0f, 420.0f);
                clients_ = fill_raw->SetTable(std::make_unique<TableElement>());
                clients_->id = "dash.table.clients";
                // S5-AESTH P0-2: keep the reading columns generous and the
                // right-most size column a fixed narrow end so the header
                // never crowds the last cell (text is clipped per cell).
                // batch30: the widths follow the MEASURED content (batch29's
                // auto_width mechanism), so the now shorter "just now" /
                // "1 minute ago" activity column no longer reserves a fixed
                // 140 px weight.
                clients_->SetColumns(std::vector<TableColumn>{
                    TableColumn{"ip", Str::ColIp, 140.0f, Align::Start, 0.0f,
                                true},
                    TableColumn{"mac", Str::ColMac, 140.0f, Align::Start, 0.0f,
                                true},
                    TableColumn{"up", Str::ColUp, 90.0f, Align::End, 0.0f, true},
                    TableColumn{"down", Str::ColDown, 90.0f, Align::End, 0.0f,
                                true},
                    TableColumn{"seen", Str::ColLastSeen, 140.0f, Align::End,
                                0.0f, true},
                    TableColumn{"lan", Str::ColLan, 80.0f, Align::End, 0.0f,
                                true}});

                empty_ = fill_raw->SetEmpty(
                    std::make_unique<EmptyState>(Str::CommonEmpty));
                empty_->id = "page.dashboard.empty";
                empty_->visible = false;

                // batch33 E: the row context menu (overlay, no layout slot).
                // Added to the page host (not the scrolled content) so the card
                // is not clipped by the ScrollView viewport.
                auto menu = std::make_unique<ContextMenu>();
                menu->id = "dashboard.context_menu";
                context_menu_ = static_cast<ContextMenu*>(
                    host.Add(std::move(menu)));

                // batch33 D/E: a left click on a device row opens that
                // device's rate-limit page with the MAC pre-filled; a right
                // click opens the four-item menu.
                clients_->on_row_click = [this](const std::string& row_id) {
                    if (ctx_ == nullptr) {
                        return;
                    }
                    const std::string intent = "mac=" + row_id;
                    if (ctx_->navigate_intent) {
                        ctx_->navigate_intent("ratelimit", intent);
                    } else if (ctx_->navigate) {
                        ctx_->navigate("ratelimit");
                    }
                };
                clients_->on_row_context =
                    [this](const std::string& row_id, Point at) {
                        OpenRowMenu(row_id, at);
                    };

                // Modal host last: overlays paint above every page sibling.
                dialog_ = static_cast<DialogHost*>(
                    host.Add(std::make_unique<DialogHost>()));
                dialog_->id = "dash.dialog";

                UpdateToggleLabel();
            }

            void DashboardPage::OpenDetails() {
                if (details_ == nullptr) {
                    return;
                }
                if (!details_->visible) {
                    details_->visible = true;
                    UpdateToggleLabel();
                }
                Relayout();
                // batch33 F: scroll the revealed block into the viewport (the
                // curve click is the "show me the numbers" affordance).
                if (scroll_ != nullptr) {
                    scroll_->ScrollIntoView(details_);
                    Relayout();
                }
            }

            void DashboardPage::CopyGatewayAddress() {
                // batch33l: same clipboard + toast contract as the Help dialog's
                // copy action (one implementation, two entry points).
                if (help_address_.empty() || ctx_ == nullptr) {
                    return;
                }
                if (!console_log::CopyToClipboard(help_address_)) {
                    if (ctx_->toast) {
                        ctx_->toast(Str::ConsoleCopyFailed, ToastKind::Warning);
                    }
                    return;
                }
                if (ctx_->toast) {
                    ctx_->toast(Str::DashHelpCopied, ToastKind::Success);
                }
            }

            void DashboardPage::OnIntent(const std::string& intent) {
                (void)intent;  // the dashboard's only intent opens the details
                OpenDetails();
            }

            void DashboardPage::OpenRowMenu(const std::string& mac, Point at) {
                if (context_menu_ == nullptr) {
                    return;
                }
                menu_mac_ = mac;
                const I18n& i18n = I18n::Instance();
                std::vector<ContextMenu::Item> items;
                items.push_back(ContextMenu::Item{
                    i18n.T(Str::CtxMenuBanDevice), true, [this] {
                        if (ctx_ != nullptr && ctx_->navigate_intent) {
                            ctx_->navigate_intent("firewall",
                                                  "mac=" + menu_mac_);
                        } else if (ctx_ != nullptr && ctx_->navigate) {
                            ctx_->navigate("firewall");
                        }
                    }});
                items.push_back(ContextMenu::Item{
                    i18n.T(Str::CtxMenuLimitDevice), false, [this] {
                        if (ctx_ != nullptr && ctx_->navigate_intent) {
                            ctx_->navigate_intent("ratelimit",
                                                  "mac=" + menu_mac_);
                        } else if (ctx_ != nullptr && ctx_->navigate) {
                            ctx_->navigate("ratelimit");
                        }
                    }});
                items.push_back(ContextMenu::Item{
                    i18n.T(Str::CtxMenuViewLeases), false, [this] {
                        if (ctx_ != nullptr && ctx_->navigate_intent) {
                            ctx_->navigate_intent("leases",
                                                  "mac=" + menu_mac_);
                        } else if (ctx_ != nullptr && ctx_->navigate) {
                            ctx_->navigate("leases");
                        }
                    }});
                items.push_back(ContextMenu::Item{
                    i18n.T(Str::CtxMenuCopyMac), false, [this] {
                        if (!console_log::CopyToClipboard(Widen(menu_mac_))) {
                            if (ctx_ != nullptr && ctx_->toast) {
                                ctx_->toast(Str::ConsoleCopyFailed,
                                            ToastKind::Warning);
                            }
                            return;
                        }
                        if (ctx_ != nullptr && ctx_->toast) {
                            ctx_->toast(Str::CommonCopied, ToastKind::Success);
                        }
                    }});
                context_menu_->SetClientRect(host_ != nullptr ? host_->bounds()
                                                              : Rect{});
                context_menu_->Show(at, std::move(items));
                Relayout();
            }

            void DashboardPage::Update(const UiSnapshot& snapshot, I18n& i18n) {
                Relabel();
                last_running_ = snapshot.dataplane_running;

                // ---- three-state, plain-language service strip --------------
                const AdapterIssue issue =
                    AdapterBindingIssue(snapshot.adapter_binding);
                // The persisted binding is sampled at Start(); use the live
                // inventory when it contains the same device so unplugging the
                // cable after Start still flips the strip to the yellow state.
                bool live_link_ok = true;
                if (snapshot.adapter_binding.bound) {
                    for (const auto& info : snapshot.adapters) {
                        const bool same_device =
                            (!snapshot.adapter_binding.device.empty() &&
                             info.device == snapshot.adapter_binding.device);
                        const bool same_name =
                            (snapshot.adapter_binding.device.empty() &&
                             !snapshot.adapter_binding.friendly_name.empty() &&
                             info.friendly_name ==
                                 snapshot.adapter_binding.friendly_name);
                        if (same_device || same_name) {
                            live_link_ok = info.is_up && info.media_connected;
                            break;
                        }
                    }
                }
                const bool adapter_problem =
                    snapshot.dataplane_running &&
                    snapshot.adapter_binding.bound &&
                    (issue != AdapterIssue::None || !live_link_ok);
                const bool start_problem =
                    !snapshot.dataplane_running &&
                    !snapshot.dataplane_error.empty();
                const std::size_t connected = snapshot.clients.size();
                if (adapter_problem) {
                    status_->SetText(WithoutLeadingBullet(i18n.T(Str::DashStatusAdapterDown)));
                    status_->SetColor(ColorToken::Warning);
                    recheck_->visible = true;
                    if (online_ != nullptr) {
                        online_->visible = false;
                    }
                } else if (start_problem) {
                    status_->SetText(WithoutLeadingBullet(i18n.T(Str::DashStatusError)));
                    status_->SetColor(ColorToken::Warning);
                    recheck_->visible = true;
                    if (online_ != nullptr) {
                        online_->visible = false;
                    }
                } else if (snapshot.dataplane_running) {
                    // Short state only; the device count lives in the tile.
                    status_->SetText(WithoutLeadingBullet(i18n.T(Str::DashStatusRunningFmt)));
                    status_->SetColor(ColorToken::Success);
                    recheck_->visible = false;
                    if (online_ != nullptr) {
                        online_->SetText(std::to_wstring(connected) + L" · " +
                                         i18n.T(Str::SettingsAdapterLinkUp));
                        online_->SetKind(BadgeKind::Success);
                        online_->visible = true;
                    }
                } else {
                    status_->SetText(WithoutLeadingBullet(i18n.T(Str::DashStatusStopped)));
                    status_->SetColor(ColorToken::TextDim);
                    recheck_->visible = false;
                    if (online_ != nullptr) {
                        online_->visible = false;
                    }
                }
                // batch28: the instrument language - a running service gets the
                // breathing dot (Success) and a live curve; an anomaly gets a
                // steady Warning dot and a Warning curve; a stopped service is
                // steady and dim, and pushes nothing (the curve flattens).
                if (dot_ != nullptr) {
                    if (adapter_problem || start_problem) {
                        dot_->SetColor(ColorToken::Warning);
                        dot_->SetPulsing(false);
                    } else if (snapshot.dataplane_running) {
                        dot_->SetColor(ColorToken::Success);
                        dot_->SetPulsing(true);
                    } else {
                        dot_->SetColor(ColorToken::TextDim);
                        dot_->SetPulsing(false);
                    }
                }
                // batch33l: the strip's gateway line follows the live config
                // (empty/"0.0.0.0" reads as the localized "not set").
                if (gateway_value_ != nullptr) {
                    const std::wstring address =
                        snapshot.config.gateway_ip.empty() ||
                                snapshot.config.gateway_ip == "0.0.0.0"
                            ? i18n.T(Str::CommonNotSet)
                            : Widen(snapshot.config.gateway_ip);
                    if (gateway_value_->text() != address) {
                        gateway_value_->SetText(address);
                    }
                    if (gateway_copy_ != nullptr) {
                        gateway_copy_->enabled =
                            !snapshot.config.gateway_ip.empty() &&
                            snapshot.config.gateway_ip != "0.0.0.0";
                    }
                }
                if (perf_spark_ != nullptr) {
                    perf_spark_->SetColor(adapter_problem || start_problem
                                              ? ColorToken::Warning
                                              : ColorToken::Success);
                    perf_spark_->SetActive(snapshot.dataplane_running);
                    if (snapshot.dataplane_running) {
                        perf_spark_->Push(
                            static_cast<double>(snapshot.throughput.up_bps) +
                            static_cast<double>(snapshot.throughput.down_bps));
                    }
                }
                // batch27 P1-9: the busy state ends as soon as the snapshot
                // reports the state the click asked for.
                if (busy_ && snapshot.dataplane_running == busy_target_running_) {
                    busy_ = false;
                    action_->enabled = true;
                }
                if (!busy_) {
                    action_->SetLabel(i18n.T(snapshot.dataplane_running
                                                 ? Str::DashStop
                                                 : Str::DashStart));
                }
                // batch27 P1-5 / D6: an unusable (unconfigured) service shows
                // "set it up for me" as the single primary action; the start
                // button steps back to Secondary so the strip never carries two
                // competing primaries (start is Primary only while stopped and
                // configured).
                const bool unconfigured =
                    !snapshot.dataplane_running &&
                    (issue != AdapterIssue::None ||
                     (!snapshot.adapter_binding.bound &&
                      !snapshot.adapters.empty()) ||
                     !snapshot.dataplane_error.empty());
                if (setup_ != nullptr) {
                    setup_->visible = unconfigured;
                }
                action_->SetStyle(unconfigured || snapshot.dataplane_running
                                      ? ButtonStyle::Secondary
                                      : ButtonStyle::Primary);

                // ---- core values -------------------------------------------
                // batch33 B: the send/receive numbers live in the performance
                // card (the two standalone up/down cards and their mini curves
                // were removed - they duplicated the same data).
                {
                    const auto split_bps = [](uint64_t bps, std::wstring& num,
                                              std::wstring& unit) {
                        const std::wstring text = FormatBps(bps);
                        const std::size_t space = text.find_last_of(L' ');
                        if (space == std::wstring::npos) {
                            num = text;
                            unit.clear();
                            return;
                        }
                        num = text.substr(0, space);
                        unit = text.substr(space + 1);
                    };
                    std::wstring up_num;
                    std::wstring up_unit;
                    std::wstring down_num;
                    std::wstring down_unit;
                    split_bps(snapshot.throughput.up_bps, up_num, up_unit);
                    split_bps(snapshot.throughput.down_bps, down_num, down_unit);
                    if (perf_ != nullptr) {
                        perf_->SetValues(up_num, up_unit, down_num, down_unit);
                    }
                    // batch33 A/B: the range label follows the curve's own
                    // visible-window upper bound, so the number on screen is
                    // always the number the axis is painted with.
                    if (perf_spark_ != nullptr && perf_ != nullptr) {
                        perf_->SetRangeLabel(perf_spark_->range_label());
                    }
                }
                // batch33 B/C: the adapter line - name, type, IPv4, IPv6,
                // every value read from the real binding (never fabricated).
                if (perf_ != nullptr) {
                    perf_->SetAdapterLine(AdapterLineText(snapshot, i18n),
                                          AdapterLineTooltip(snapshot));
                    perf_->SetAdapterDim(!snapshot.adapter_binding.bound);
                }
                // batch28: the number carries the EXACT value (and the sample
                // time) as its hover tooltip, so an operator can verify what
                // the rounded instrument shows.
                {
                    // batch29 P1: "uptime" is the SERVICE session length. A
                    // stopped service must not keep re-writing the tile every
                    // second (that was the residual 1 Hz repaint after Stop):
                    // the last running value stays on screen until the service
                    // starts again.
                    if (snapshot.dataplane_running || !uptime_shown_) {
                        // batch30: one human time vocabulary ("1 h 1 min"),
                        // never the old "1h 1m 1s". A SINGLE unit ("4 s") is
                        // split so the unit keeps its dim one-step-smaller
                        // style on the same line; a two-unit value stays one
                        // text ("1 h 1 min" must not become "1 h 1" + "min").
                        const std::wstring text =
                            FormatUptime(snapshot.uptime_s);
                        const std::size_t space = text.find_last_of(L' ');
                        const bool single_unit =
                            space != std::wstring::npos && space > 0 &&
                            text.find_first_not_of(L"0123456789") == space;
                        if (single_unit) {
                            uptime_->SetValueWithUnit(text.substr(0, space),
                                                      text.substr(space + 1));
                        } else {
                            uptime_->SetValue(text);
                        }
                        uptime_shown_ = true;
                    }
                }
                // batch28: the number carries the EXACT value (and the sample
                // time) as its hover tooltip, so an operator can verify what
                // the rounded instrument shows.
                {
                    // The wall-clock sampling moment (HH:MM:SS) - what the
                    // operator compares against the device's own counters.
                    const std::time_t now = std::time(nullptr);
                    std::tm local{};
                    localtime_s(&local, &now);
                    wchar_t clock_text[16] = {};
                    std::swprintf(clock_text, 16, L"%02d:%02d:%02d",
                                  local.tm_hour, local.tm_min, local.tm_sec);
                    const std::wstring stamp = i18n.Format(
                        Str::DashSampleTimeFmt, {std::wstring(clock_text)});
                    if (perf_ != nullptr) {
                        perf_->SetSampleTooltip(
                            FormatCount(snapshot.throughput.up_bps) + L" B/s · " +
                                stamp,
                            FormatCount(snapshot.throughput.down_bps) +
                                L" B/s · " + stamp);
                    }
                }
                // ---- detailed statistics (still updated while collapsed) ---
                rx_->SetValue(FormatCount(snapshot.counters.rx_frames));
                tx_->SetValue(FormatCount(snapshot.counters.tx_frames));
                wchar_t cpu[32] = {};
                std::swprintf(cpu, 32, L"%.1f%%", snapshot.system.proc_cpu_percent);
                cpu_->SetValue(cpu);
                mem_->SetValue(FormatBytes(snapshot.system.proc_ws_bytes));
                // batch22 A7: identity / protocol row (see the field map in
                // Build()). No value is fabricated: an empty gateway string
                // becomes the localized "not set" placeholder.
                gw_->SetValue(snapshot.config.gateway_ip.empty()
                                  ? i18n.T(Str::CommonNotSet)
                                  : Widen(snapshot.config.gateway_ip));
                ipv6_->SetValue(i18n.T(snapshot.config.ipv6_enabled
                                           ? Str::CommonYes
                                           : Str::CommonNo));
                tcp_->SetValue(FormatCount(snapshot.counters.tcp_accepted));
                // batch34a: "dropped packets" must include the port-map relay
                // queue overruns. They used to be counted by the data plane and
                // never shown, so a stalled port-map download looked like a
                // network problem with no evidence on screen.
                // batch34i: two more loss sources that were counted but never
                // shown: a frame dropped for want of a neighbour entry
                // (mac_misses) and a learn refused by the flood guard while
                // the table is saturated (neighbor_rejections). Both mean the
                // device could not be resolved, which the operator reads as
                // "the network is flaky" with no evidence.
                // batch34j: three more capacity-boundary losses that were
                // counted nowhere: DHCP anti-storm window resets (v4/v6) and
                // UDP relay flows evicted by the capacity cap. All of them
                // make a client lose service for a moment.
                const uint64_t lost = snapshot.counters.rx_dropped +
                                      snapshot.counters.portmap_send_dropped +
                                      snapshot.counters.mac_misses +
                                      snapshot.neighbor_rejections +
                                      snapshot.udp_flow_evictions;
                drops_->SetValue(FormatCount(lost));
                {
                    std::wstring tip = i18n.T(Str::DashDropsBreakdown);
                    const std::wstring parts[6] = {
                        std::to_wstring(lost),
                        std::to_wstring(snapshot.counters.rx_dropped),
                        std::to_wstring(
                            snapshot.counters.portmap_send_dropped),
                        std::to_wstring(snapshot.counters.mac_misses),
                        std::to_wstring(snapshot.neighbor_rejections),
                        std::to_wstring(snapshot.udp_flow_evictions)};
                    for (const std::wstring& value : parts) {
                        const size_t at = tip.find(L"%s");
                        if (at != std::wstring::npos) {
                            tip.replace(at, 2, value);
                        }
                    }
                    drops_->SetValueTooltip(tip);
                }
                pass_->SetValue(FormatCount(snapshot.counters.host_passthrough));
                vlan_rx_->SetValue(FormatCount(snapshot.counters.rx_vlan_frames));
                vlan_tx_->SetValue(FormatCount(snapshot.counters.tx_vlan_frames));
                vmem_->SetValue(FormatBytes(snapshot.system.proc_virt_bytes));

                // The help popup is built from the current snapshot; remember
                // the address it should copy (empty/"0.0.0.0" = not set).
                help_address_ = Widen(snapshot.config.gateway_ip);
                if (help_address_ == L"0.0.0.0") {
                    help_address_.clear();
                }

                // batch22 A2: filter -> sort -> rows. The filter/sort state is
                // owned by the page; the semantics mirror the Web dashboard
                // (all/lan/wan, rate/up/down/activity, asc/desc).
                std::vector<const vgww::runtime::Dataplane::ClientRate*> filtered;
                filtered.reserve(snapshot.clients.size());
                for (const auto& client : snapshot.clients) {
                    if (client_filter_ == ClientFilter::Lan && !client.lan) {
                        continue;
                    }
                    if (client_filter_ == ClientFilter::Wan && client.lan) {
                        continue;
                    }
                    filtered.push_back(&client);
                }
                const auto key = [this](const vgww::runtime::Dataplane::ClientRate& c) {
                    switch (client_sort_) {
                        case ClientSort::Up:
                            return static_cast<double>(c.up_bps);
                        case ClientSort::Down:
                            return static_cast<double>(c.down_bps);
                        case ClientSort::Seen:
                            // "Activity": more recent = larger, so the desc
                            // order matches "busiest/latest first".
                            return static_cast<double>(
                                static_cast<uint64_t>(c.last_seen_s) == 0
                                    ? 0xFFFFFFFFu
                                    : 0xFFFFFFFFu - c.last_seen_s);
                        case ClientSort::Rate:
                        default:
                            return static_cast<double>(c.up_bps + c.down_bps);
                    }
                };
                // batch57: decorate before sorting. The comparator used to call
                // key() twice per comparison (a switch on the sort mode, run for
                // both operands) and, on the tie-break branch, FormatMac FOUR
                // times. FormatMac returns a 17-char std::string - one past
                // MSVC's small-object buffer - so every comparison allocated, on
                // the UI thread, at the tick rate. An idle panel (every rate 0)
                // compares equal on every pair, so the tie-break ran for
                // essentially the whole sort: measured 3975 allocations per tick
                // at 512 clients, all of it pure overhead.
                //
                // Sorting the raw MAC BYTES instead of the formatted text is
                // exactly equivalent: FormatMac is a fixed-width uppercase-hex
                // rendering with ':' at fixed positions, and ASCII orders the
                // hex digits ('0'-'9' < 'A'-'F') the same way their values are
                // ordered, so lexicographic string order == byte order.
                struct SortEntry {
                    double key = 0.0;
                    const vgww::runtime::Dataplane::ClientRate* client =
                        nullptr;
                };
                std::vector<SortEntry> entries;
                entries.reserve(filtered.size());
                for (const vgww::runtime::Dataplane::ClientRate* client :
                     filtered) {
                    entries.push_back(SortEntry{key(*client), client});
                }
                std::stable_sort(
                    entries.begin(), entries.end(),
                    [this](const SortEntry& a, const SortEntry& b) {
                        if (a.key == b.key) {
                            // Deterministic tie-break: MAC order.
                            return sort_desc_
                                       ? a.client->mac < b.client->mac
                                       : b.client->mac < a.client->mac;
                        }
                        return sort_desc_ ? a.key > b.key : a.key < b.key;
                    });

                std::vector<TableRow> rows;
                rows.reserve(entries.size());
                for (const SortEntry& entry : entries) {
                    const vgww::runtime::Dataplane::ClientRate* client =
                        entry.client;
                    TableRow row;
                    // batch90: format the MAC ONCE and reuse it. FormatMac
                    // returns a 17-char std::string, one past MSVC's 15-byte
                    // small-object buffer, so each call is a heap allocation
                    // on the UI thread at tick rate. The row id and the MAC
                    // cell are the same value, so formatting twice was pure
                    // duplication (512 avoidable allocations per tick at 512
                    // clients).
                    //
                    // The id takes ownership of the formatted text LAST: Widen
                    // needs to read it first, and assigning (rather than
                    // moving) it would allocate a second 17-byte string - the
                    // duplication this change removes.
                    std::string mac_text = vgww::core::FormatMac(client->mac);
                    // batch92: build the six cells with reserve + push_back
                    // instead of a braced initializer. A braced list of
                    // std::wstring constructs temporary elements and then
                    // COPIES them in, so every cell past the small-object
                    // buffer is allocated twice. Two of these six are (the IP
                    // text and the 17-char MAC). Measured at 512 clients:
                    // 9.04/client braced, 7.04/client here.
                    row.cells.clear();
                    row.cells.reserve(6);
                    row.cells.push_back(ClientIpText(client->ip));
                    row.cells.push_back(Widen(mac_text));
                    row.cells.push_back(FormatBps(client->up_bps));
                    row.cells.push_back(FormatBps(client->down_bps));
                    row.cells.push_back(FormatAgo(client->last_seen_s));
                    row.cells.push_back(i18n.T(client->lan ? Str::CommonYes
                                                          : Str::CommonNo));
                    row.row_id = std::move(mac_text);
                    rows.push_back(std::move(row));
                }
                const std::size_t shown = rows.size();
                // batch29 P1: the "last seen" cell is a live counter, so a
                // stopped service kept re-writing the table once a second -
                // the residual 1 Hz repaint after Stop. While the service is
                // stopped the last painted rows stay on screen (no new
                // activity exists to report); an explicit filter/sort or a
                // service restart refreshes them again. batch331: the filter,
                // sort and direction handlers now clear clients_rows_shown_
                // so that promise is actually kept.
                //
                // batch132: the placeholder and the tile used to be driven by
                // THIS tick's snapshot even when the rows above were frozen.
                // A stopped plane publishing an empty client list therefore
                // put "no clients" on screen directly above a table still
                // full of clients. Both now read the row count that is
                // actually painted (shown_count_), so the page can never
                // contradict itself.
                if (snapshot.dataplane_running || !clients_rows_shown_) {
                    clients_->SetRows(std::move(rows));
                    clients_rows_shown_ = true;
                    shown_count_ = shown;
                }
                // The tile counts what the current view shows (Web parity).
                clients_tile_->SetValue(FormatCount(shown_count_));
                empty_->visible = 0 == shown_count_;
                // batch27 D3/P2-21: one plain sentence + one action instead of
                // the bare "no data".
                // batch331: the dashboard has its own sentence now. It used to
                // borrow LeasesEmptyHint, which talks about DHCP addresses and
                // the Start button - a different page's data.
                empty_->SetMessage(Str::DashClientsEmpty);  // relabel on a language switch
            }

            void DashboardPage::Relabel() {
                const I18n& i18n = I18n::Instance();
                if (perf_ != nullptr) {
                    perf_->Relabel();
                }
                clients_tile_->SetCaption(Str::DashClients);
                uptime_->SetCaption(Str::DashUptime);
                help_->SetLabel(i18n.T(Str::DashHelp));
                recheck_->SetLabel(i18n.T(Str::DashRecheck));
                if (setup_ != nullptr) {
                    setup_->SetLabel(i18n.T(Str::DashSetup));
                }
                if (busy_) {
                    action_->SetLabel(i18n.T(last_running_ ? Str::DashStopping
                                                           : Str::DashStarting));
                } else {
                    action_->SetLabel(
                        i18n.T(last_running_ ? Str::DashStop : Str::DashStart));
                }
                UpdateToggleLabel();
                // batch22 A2: re-localize the view controls on a language
                // switch (labels only; the selected tokens stay).
                //
                // Guarded by the language code: Relabel() runs on EVERY Update,
                // and an unconditional SetOptions() would mark the control
                // dirty every tick - breaking the "a replayed identical
                // snapshot must not request a layout" invariant (and wasting
                // relayouts in the real app).
                const std::string lang = i18n.LangCode();
                if (lang == view_lang_) {
                    return;
                }
                view_lang_ = lang;
                if (filter_ != nullptr) {
                    const std::wstring keep = filter_->selected_value();
                    filter_->SetOptions({{L"all", i18n.T(Str::DashFilterAll)},
                                         {L"lan", i18n.T(Str::DashFilterLan)},
                                         {L"wan", i18n.T(Str::DashFilterWan)}});
                    filter_->SetSelectedValueSilent(keep);
                }
                if (sort_ != nullptr) {
                    const std::wstring keep = sort_->selected_value();
                    sort_->SetOptions({{L"rate", i18n.T(Str::DashSortRate)},
                                       {L"up", i18n.T(Str::DashSortUp)},
                                       {L"down", i18n.T(Str::DashSortDown)},
                                       {L"seen", i18n.T(Str::DashSortSeen)}});
                    sort_->SetSelectedValueSilent(keep);
                }
                if (dir_ != nullptr) {
                    const std::wstring keep = dir_->selected_value();
                    dir_->SetOptions({{L"desc", i18n.T(Str::DashSortDesc)},
                                      {L"asc", i18n.T(Str::DashSortAsc)}});
                    dir_->SetSelectedValueSilent(keep);
                }
                rx_->SetCaption(Str::DashRx);
                tx_->SetCaption(Str::DashTx);
                cpu_->SetCaption(Str::DashCpu);
                mem_->SetCaption(Str::DashMem);
                gw_->SetCaption(Str::DashGateway);
                ipv6_->SetCaption(Str::DashIpv6Status);
                tcp_->SetCaption(Str::DashTcp);
                drops_->SetCaption(Str::DashDrops);
                pass_->SetCaption(Str::DashPass);
                vlan_rx_->SetCaption(Str::DashVlanRx);
                vlan_tx_->SetCaption(Str::DashVlanTx);
                vmem_->SetCaption(Str::DashVmem);
            }

            void DashboardPage::UpdateToggleLabel() {
                if (details_toggle_ == nullptr) {
                    return;
                }
                const bool open = details_ != nullptr && details_->visible;
                details_toggle_->SetLabel(
                    std::wstring(I18n::Instance().T(Str::DashDetails)) +
                    (open ? L"  \u25BE" : L"  \u25B8"));
            }

            void DashboardPage::Relayout() {
                if (host_ != nullptr) {
                    RelayoutHost(*host_);
                }
            }

            void DashboardPage::ShowSetup() {
                // batch27 P1-5: prefer the shell's first-run wizard (it owns the
                // adapter list and the save+restart chain). A headless context
                // without the hook still gets somewhere useful: the Settings
                // page, which is where the adapter lives.
                if (ctx_ != nullptr && ctx_->open_setup) {
                    ctx_->open_setup();
                    return;
                }
                if (ctx_ != nullptr && ctx_->navigate) {
                    ctx_->navigate("settings");
                }
            }

            void DashboardPage::ShowHelp() {
                if (dialog_ == nullptr) {
                    return;
                }
                const I18n& i18n = I18n::Instance();
                std::wstring body = i18n.T(Str::DashHelpStep1);
                body += L"\n\n";
                if (help_address_.empty()) {
                    body += i18n.T(Str::DashHelpNoAddress);
                } else {
                    body += i18n.Format(Str::DashHelpStep2Fmt, {help_address_});
                }
                body += L"\n\n";
                body += i18n.T(Str::DashHelpStep3);
                body += L"\n\n";
                body += i18n.T(Str::DashHelpFootnote);
                dialog_->ShowMessageActionText(
                    i18n.T(Str::DashHelpTitle), body, i18n.T(Str::CommonClose),
                    i18n.T(Str::DashHelpCopy), [this] {
                        if (help_address_.empty() || ctx_ == nullptr) {
                            return;
                        }
                        if (!console_log::CopyToClipboard(help_address_)) {
                            if (ctx_->toast) {
                                ctx_->toast(Str::ConsoleCopyFailed,
                                            ToastKind::Warning);
                            }
                            return;
                        }
                        if (ctx_->toast) {
                            // batch27 P1-8: the short, unambiguous bubble.
                            ctx_->toast(Str::CommonCopied,
                                        ToastKind::Success);
                        }
                    });
                Relayout();
            }

        }  // namespace

        std::unique_ptr<Page> MakeDashboardPage() {
            return std::make_unique<DashboardPage>();
        }

    }  // namespace ui
}  // namespace vgww
