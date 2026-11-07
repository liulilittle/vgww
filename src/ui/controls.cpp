// ============================================================================
// controls.cpp - basic containers and controls (layout + interaction).
// ============================================================================
#include "ui/console_log.h"
#include "ui/controls.h"
#include "ui/format.h"
#include "ui/renderer.h"
#include "ui/theme.h"

#include <shellapi.h>

#include <algorithm>
#include <cassert>
#include <cstring>
#include <cwctype>
#include <cmath>
#include <utility>

namespace vgww {
    namespace ui {

        bool SetClipboardText(const std::wstring& text) {
            if (text.empty()) {
                return false;
            }
            // batch285: ONE clipboard funnel. The console log already owns the
            // failure-aware Win32 writer (with a test seam); the copy here
            // swallowed OpenClipboard/GlobalAlloc/SetClipboardData errors and
            // reported nothing, so the text input "copied" and CUT text that
            // never reached the clipboard.
            return console_log::CopyToClipboard(text);
        }

        namespace {

            constexpr float kUnboundedWidth = 1.0e9f;
            constexpr uint32_t kVkReturn = 0x0D;
            constexpr uint32_t kVkSpace = 0x20;
            constexpr uint32_t kVkLeft = 0x25;
            constexpr uint32_t kVkRight = 0x27;

            /// batch26: defined with the table helpers further down; needed by
            /// the LanguagePicker/Select paint paths which come first.
            std::wstring EllipsizeToWidth(const std::wstring& text,
                                          FontToken font, float max_width,
                                          bool can_measure_naturally);

            constexpr float kButtonPadX = 12.0f;
            constexpr float kButtonPadY = 6.0f;
            constexpr float kButtonMinW = 64.0f;
            constexpr float kButtonMinH = 32.0f;
            constexpr float kSegPadX = 10.0f;
            constexpr float kSegPadY = 6.0f;
            constexpr float kSegMinW = 64.0f;
            constexpr float kSegMinH = 32.0f;
            constexpr float kCheckboxBox = 16.0f;

            /// T7: Button hover background transition duration (seconds).
            constexpr float kHoverSeconds = 0.12f;
            /// T9: modal entrance duration (seconds).
            constexpr float kDialogOpenSeconds = 0.16f;
            /// T9: toast entrance duration (seconds).
            constexpr float kToastOpenSeconds = 0.18f;
            /// T9: page entrance duration (seconds).
            constexpr float kPageOpenSeconds = 0.18f;

            /// Linear interpolation between two colors (component-wise).
            Color LerpColor(const Color& a, const Color& b, float t) noexcept {
                return Color{a.r + (b.r - a.r) * t, a.g + (b.g - a.g) * t,
                             a.b + (b.b - a.b) * t, a.a + (b.a - a.a) * t};
            }

            /// Cubic ease-out: 1 - (1 - t)^3 (T9 entrance easing; overlaps the
            /// Button hover's own progress which stays linear-by-choice).
            float EaseOut(float t) noexcept {
                const float u = 1.0f - std::min(std::max(t, 0.0f), 1.0f);
                return 1.0f - u * u * u;
            }

            /// T9: render-time uniform scale of `rect` around its center by
            /// `scale`. Derives painted geometry only - never touches bounds or
            /// HitTest, so layout stays stable and the hit region never shrinks
            /// (the T9 hard constraint).
            Rect ScaledRect(const Rect& rect, float scale) noexcept {
                const float w = rect.w * scale;
                const float h = rect.h * scale;
                return Rect{rect.x + (rect.w - w) * 0.5f,
                            rect.y + (rect.h - h) * 0.5f, w, h};
            }

            /// Multiplies a color's RGB by `factor` (pressed feedback darkening).
            Color ScaleRgb(const Color& c, float factor) noexcept {
                return Color{c.r * factor, c.g * factor, c.b * factor, c.a};
            }

            /// batch33v: WCAG relative luminance and contrast ratio, used by
            /// the disabled-state check below. Kept here (not in theme.h)
            /// because only the paint path needs it.
            float RelativeLuminance(const Color& c) noexcept {
                const auto lin = [](float v) {
                    return v <= 0.03928f
                               ? v / 12.92f
                               : std::pow((v + 0.055f) / 1.055f, 2.4f);
                };
                return 0.2126f * lin(c.r) + 0.7152f * lin(c.g) +
                       0.0722f * lin(c.b);
            }
            /// batch33w: the subtle row-highlight overlay. A WHITE tint lifts a
            /// dark surface but does NOTHING on a light one (white over
            /// #EFEFF2 is 1.007:1 - the language picker hover vanished).
            /// Dark themes brighten, light themes darken.
            Color HoverOverlay(float dark_alpha, float light_alpha) noexcept {
                if (ActiveThemeIsLight()) {
                    return Color{0.0f, 0.0f, 0.0f, light_alpha};
                }
                return Color{1.0f, 1.0f, 1.0f, dark_alpha};
            }

            float ContrastRatio(const Color& a, const Color& b) noexcept {
                const float la = RelativeLuminance(a);
                const float lb = RelativeLuminance(b);
                return (std::max(la, lb) + 0.05f) /
                       (std::min(la, lb) + 0.05f);
            }

            /// batch17 P1-c (B-2) + batch33t: text colour for the warm/strong
            /// fills (Danger / Success / Warning). White failed AA on the
            /// DARK palette's bright fills, so it switched to #141414 -
            /// which is calibrated for the DARK palette ONLY.
            ///
            /// batch33t: the LIGHT palette uses deep fills (#C42B30 /
            /// #1E7A38 / #8A6100) where #141414 is just 3.28 / 3.42 /
            /// 3.33 - under AA 4.5:1 - while white is 5.62 / 5.39 / 5.54.
            /// A single hardcoded colour cannot serve both themes, so the
            /// helper now follows the active theme.
            Color WarmFillText() noexcept {
                static const Color dark_ink = ParseHexColor("#141414");
                static const Color light_ink = ParseHexColor("#FFFFFF");
                return ActiveThemeIsLight() ? light_ink : dark_ink;
            }

        }  // namespace

        // --- StackPanel ------------------------------------------------------

        StackPanel::StackPanel(Orientation orientation, float gap, Padding padding,
                               Align child_align)
            : orientation_(orientation), gap_(gap), padding_(padding),
              child_align_(child_align) {
            hit_transparent = true;  // containers never take hits themselves
        }

        void StackPanel::EnsureFlowMemos() {
            if (flow_memos_.size() != children_.size()) {
                // A rebuilt container (clear + re-add) changes the child
                // count; resetting the whole table guarantees a slot can
                // never answer for a different child object.
                flow_memos_.assign(children_.size(), ChildFlowMemos{});
            }
        }

        const Size* StackPanel::FlowMemoLookup(std::size_t index,
                                               const Element& child,
                                               Size avail) const noexcept {
            if (index >= flow_memos_.size() || !child.desired_valid()) {
                return nullptr;
            }
            const uint64_t gen = child.measure_gen();
            const uint64_t gen_key = TextMeasureGeneration();
            for (const ChildFlowMemo& memo : flow_memos_[index].slot) {
                if (memo.valid && memo.gen == gen && memo.gen_key == gen_key &&
                    memo.avail.w == avail.w && memo.avail.h == avail.h) {
                    return &memo.desired;
                }
            }
            return nullptr;
        }

        void StackPanel::FlowMemoStore(std::size_t index, const Element& child,
                                       Size avail, Size desired) noexcept {
            if (index >= flow_memos_.size()) {
                return;
            }
            ChildFlowMemo& slot0 = flow_memos_[index].slot[0];
            ChildFlowMemo& slot1 = flow_memos_[index].slot[1];
            if (slot0.valid && slot0.avail.w == avail.w &&
                slot0.avail.h == avail.h) {
                // Same key: refresh in place (MRU stays slot 0).
            } else if (slot1.valid && slot1.avail.w == avail.w &&
                       slot1.avail.h == avail.h) {
                const ChildFlowMemo previous = slot0;
                slot0 = slot1;
                slot1 = previous;
            } else {
                slot1 = slot0;
                slot0 = ChildFlowMemo{};
            }
            slot0.avail = avail;
            slot0.desired = desired;
            slot0.gen = child.measure_gen();
            slot0.gen_key = TextMeasureGeneration();
            slot0.valid = true;
        }

        void StackPanel::FlowMemoRefresh(std::size_t index,
                                         const Element& child) noexcept {
            if (index >= flow_memos_.size()) {
                return;
            }
            const uint64_t gen = child.measure_gen();
            for (ChildFlowMemo& memo : flow_memos_[index].slot) {
                if (memo.valid) {
                    memo.gen = gen;
                }
            }
        }

        namespace {
            /// B5-2: index of the first visible non-overlay child marked
            /// fill_remaining (children.size() when none); marked_count
            /// receives how many such children exist (the "at most one"
            /// discipline is asserted at the call sites; extras fall through
            /// as ordinary children either way).
            std::size_t FirstFillIndex(
                const std::vector<std::unique_ptr<Element>>& children,
                std::size_t& marked_count) noexcept {
                std::size_t index = children.size();
                marked_count = 0;
                for (std::size_t i = 0; i < children.size(); ++i) {
                    const Element& child = *children[i];
                    if (!child.visible || child.is_overlay() ||
                        !child.fill_remaining) {
                        continue;
                    }
                    if (marked_count == 0) {
                        index = i;
                    }
                    ++marked_count;
                }
                return index;
            }
        }  // namespace

        Size StackPanel::MeasureCore(Size available) {
            EnsureFlowMemos();
            const Size inner{std::max(0.0f, available.w - padding_.horizontal()),
                             std::max(0.0f, available.h - padding_.vertical())};
            // B5-2: at most one visible flow child may claim the remaining
            // main-axis capacity; it is measured last, against that capacity.
            std::size_t marked_count = 0;
            const std::size_t fill_index = FirstFillIndex(children_, marked_count);
            assert(marked_count <= 1 &&
                   "StackPanel: at most one visible fill_remaining child");
            float main = 0.0f;
            float cross = 0.0f;
            std::size_t count = 0;
            for (std::size_t i = 0; i < children_.size(); ++i) {
                if (i == fill_index) {
                    continue;  // measured last, against the leftover capacity
                }
                const std::unique_ptr<Element>& child = children_[i];
                if (!child->visible || child->is_overlay()) {
                    continue;  // overlays are arranged by the window, not here
                }
                // M9 (batch4): reuse the exact previously measured value when
                // the full key (available + child generation + hook
                // generation) still matches; otherwise measure as before.
                const Size* memo = FlowMemoLookup(i, *child, inner);
                const Size d = (memo != nullptr) ? *memo : child->Measure(inner);
                if (memo == nullptr) {
                    FlowMemoStore(i, *child, inner, d);
                }
                const float child_main =
                    (orientation_ == Orientation::Vertical) ? d.h : d.w;
                const float child_cross =
                    (orientation_ == Orientation::Vertical) ? d.w : d.h;
                main += child_main;
                cross = std::max(cross, child_cross);
                ++count;
            }
            if (fill_index < children_.size()) {
                // Capacity = inner main-axis minus every other visible flow
                // child's natural main minus one gap per additional flow
                // child (the marked child itself takes the last slot),
                // clamped >= 0. Overlays and hidden children never take one.
                const float inner_main = (orientation_ == Orientation::Vertical)
                                             ? inner.h
                                             : inner.w;
                const float capacity = std::max(
                    0.0f, inner_main - main - gap_ * static_cast<float>(count));
                const Size fill_avail =
                    (orientation_ == Orientation::Vertical)
                        ? Size{inner.w, capacity}
                        : Size{capacity, inner.h};
                const std::unique_ptr<Element>& child = children_[fill_index];
                const Size* memo = FlowMemoLookup(fill_index, *child, fill_avail);
                const Size d =
                    (memo != nullptr) ? *memo : child->Measure(fill_avail);
                if (memo == nullptr) {
                    FlowMemoStore(fill_index, *child, fill_avail, d);
                }
                const float child_main =
                    (orientation_ == Orientation::Vertical) ? d.h : d.w;
                const float child_cross =
                    (orientation_ == Orientation::Vertical) ? d.w : d.h;
                // Capped, never stretched: desired == arranged for the marker.
                main += std::min(child_main, capacity);
                cross = std::max(cross, child_cross);
                ++count;
            }
            if (count > 1) {
                main += gap_ * static_cast<float>(count - 1);
            }
            if (orientation_ == Orientation::Vertical) {
                return Size{cross + padding_.horizontal(),
                            main + padding_.vertical()};
            }
            return Size{main + padding_.horizontal(),
                        cross + padding_.vertical()};
        }

        void StackPanel::ArrangeCore(Rect final_rect) {
            EnsureFlowMemos();
            const Rect content{final_rect.x + padding_.l,
                               final_rect.y + padding_.t,
                               std::max(0.0f, final_rect.w - padding_.horizontal()),
                               std::max(0.0f, final_rect.h - padding_.vertical())};
            // B5-2: same single marked slot as MeasureCore.
            std::size_t marked_count = 0;
            const std::size_t fill_index = FirstFillIndex(children_, marked_count);
            assert(marked_count <= 1 &&
                   "StackPanel: at most one visible fill_remaining child");
            const Size avail{content.w, content.h};
            float capacity = 0.0f;
            if (fill_index < children_.size()) {
                // The capacity must be known before the marked child is
                // placed, and it depends on every other child's arranged
                // main, so probe those first (memo-backed, same as the
                // measure site), then arrange in child order.
                float other_main = 0.0f;
                std::size_t other_count = 0;
                for (std::size_t i = 0; i < children_.size(); ++i) {
                    if (i == fill_index) {
                        continue;
                    }
                    const std::unique_ptr<Element>& child = children_[i];
                    if (!child->visible || child->is_overlay()) {
                        continue;
                    }
                    const Size* memo = FlowMemoLookup(i, *child, avail);
                    const Size d = (memo != nullptr) ? *memo : child->Measure(avail);
                    if (memo == nullptr) {
                        FlowMemoStore(i, *child, avail, d);
                    }
                    other_main +=
                        (orientation_ == Orientation::Vertical) ? d.h : d.w;
                    ++other_count;
                }
                const float content_main = (orientation_ == Orientation::Vertical)
                                               ? content.h
                                               : content.w;
                capacity = std::max(
                    0.0f, content_main - other_main -
                              gap_ * static_cast<float>(other_count));
            }
            float cursor = (orientation_ == Orientation::Vertical) ? content.y
                                                                   : content.x;
            for (std::size_t i = 0; i < children_.size(); ++i) {
                const std::unique_ptr<Element>& child = children_[i];
                if (!child->visible) {
                    continue;
                }
                if (child->is_overlay()) {
                    // Modal overlay: fill the whole stack rect so the dialog
                    // is viewport-centred instead of flowing below the page.
                    child->Arrange(content);
                    continue;
                }
                Size d;
                float child_main;
                float child_cross;
                if (i == fill_index) {
                    const Size fill_avail =
                        (orientation_ == Orientation::Vertical)
                            ? Size{content.w, capacity}
                            : Size{capacity, content.h};
                    const Size* memo = FlowMemoLookup(i, *child, fill_avail);
                    d = (memo != nullptr) ? *memo : child->Measure(fill_avail);
                    if (memo == nullptr) {
                        FlowMemoStore(i, *child, fill_avail, d);
                    }
                    const float measured_main =
                        (orientation_ == Orientation::Vertical) ? d.h : d.w;
                    child_main = std::min(measured_main, capacity);
                    child_cross =
                        (orientation_ == Orientation::Vertical) ? d.w : d.h;
                } else {
                    // M9 (batch4): same full-key memo as MeasureCore's probe
                    // (E1); a hit skips the redundant re-measure and the
                    // child's own Arrange then hits its untouched
                    // single-slot cache.
                    const Size* memo = FlowMemoLookup(i, *child, avail);
                    d = (memo != nullptr) ? *memo : child->Measure(avail);
                    if (memo == nullptr) {
                        FlowMemoStore(i, *child, avail, d);
                    }
                    child_main =
                        (orientation_ == Orientation::Vertical) ? d.h : d.w;
                    child_cross =
                        (orientation_ == Orientation::Vertical) ? d.w : d.h;
                }
                Rect r;
                if (orientation_ == Orientation::Vertical) {
                    r.y = cursor;
                    r.h = child_main;
                    r.w = (child_align_ == Align::Stretch) ? content.w : child_cross;
                    r.x = content.x;
                    if (child_align_ == Align::Center) {
                        r.x += (content.w - child_cross) * 0.5f;
                    } else if (child_align_ == Align::End) {
                        r.x += content.w - child_cross;
                    }
                } else {
                    r.x = cursor;
                    r.w = child_main;
                    r.h = (child_align_ == Align::Stretch) ? content.h : child_cross;
                    r.y = content.y;
                    if (child_align_ == Align::Center) {
                        r.y += (content.h - child_cross) * 0.5f;
                    } else if (child_align_ == Align::End) {
                        r.y += content.h - child_cross;
                    }
                }
                  // batch19 R4-P2: a horizontal stack is a logical order; in
                  // RTL the children flow from the right (first child at the
                  // right edge). Mirroring the physical x here keeps HitTest
                  // consistent (it reads the arranged bounds).
                  if (orientation_ == Orientation::Horizontal &&
                      I18n::Instance().IsRtl()) {
                      r.x = content.x + content.w - (r.x - content.x) - r.w;
                  }
                  child->Arrange(r);
                  FlowMemoRefresh(i, *child);
                  cursor += child_main + gap_;
              }
          }

        void StackPanel::BeginEntrance() noexcept {
            entrance_t_ = 0.0f;
            RequestAnimationFrame();
        }

        void StackPanel::AdvanceAnimation(float dt_seconds) {
            if (dt_seconds <= 0.0f || entrance_t_ >= 1.0f) {
                return;  // settled: stay inactive (clock may self-stop)
            }
            entrance_t_ = std::min(1.0f, entrance_t_ + dt_seconds / kPageOpenSeconds);
        }

        bool StackPanel::HasActiveAnimation() const noexcept {
            return entrance_t_ < 1.0f;
        }

        void StackPanel::RenderChildren(RenderCtx& ctx) {
            if (entrance_t_ >= 1.0f) {
                Element::RenderChildren(ctx);
                return;  // settled: pixel-identical to the base path (alpha 1)
            }
            // T9 page fade: scope a render-time alpha (saved/restored) around
            // the subtree so it eases in without touching bounds/HitTest. The
            // page has no own chrome, so the whole fade rides this multiplier.
            const float previous = ctx.alpha();
            ctx.SetAlpha(previous * EaseOut(entrance_t_));
            Element::RenderChildren(ctx);
            ctx.SetAlpha(previous);
        }

        // --- GridLayout ------------------------------------------------------

        ColumnSpec ColumnSpec::Fixed(float px) noexcept {
            ColumnSpec spec;
            spec.fixed = px;
            return spec;
        }

        ColumnSpec ColumnSpec::Star(float weight) noexcept {
            ColumnSpec spec;
            spec.star = weight;
            return spec;
        }

        GridLayout::GridLayout(std::vector<ColumnSpec> cols, float gap,
                               Padding padding)
            : cols_(std::move(cols)), gap_(gap), padding_(padding) {
            hit_transparent = true;
        }

        std::vector<float> GridLayout::ColumnWidths(float available_width) const {
            std::vector<float> widths(cols_.size(), 0.0f);
            if (cols_.empty()) {
                return widths;
            }
            float fixed_sum = 0.0f;
            float star_sum = 0.0f;
            for (const ColumnSpec& c : cols_) {
                if (c.star > 0.0f) {
                    star_sum += c.star;
                } else {
                    fixed_sum += c.fixed;
                }
            }
            const float gaps = gap_ * static_cast<float>(cols_.size() - 1);
            const float remaining =
                std::max(0.0f, available_width - fixed_sum - gaps);
            for (std::size_t i = 0; i < cols_.size(); ++i) {
                widths[i] = (cols_[i].star > 0.0f)
                                ? remaining * cols_[i].star / star_sum
                                : cols_[i].fixed;
            }
            return widths;
        }

        void GridLayout::EnsureFlowMemos() {
            if (flow_memos_.size() != children_.size()) {
                flow_memos_.assign(children_.size(), ChildFlowMemos{});
            }
        }

        const Size* GridLayout::FlowMemoLookup(std::size_t index,
                                               const Element& child,
                                               Size avail) const noexcept {
            if (index >= flow_memos_.size() || !child.desired_valid()) {
                return nullptr;
            }
            const uint64_t gen = child.measure_gen();
            const uint64_t gen_key = TextMeasureGeneration();
            for (const ChildFlowMemo& memo : flow_memos_[index].slot) {
                if (memo.valid && memo.gen == gen && memo.gen_key == gen_key &&
                    memo.avail.w == avail.w && memo.avail.h == avail.h) {
                    return &memo.desired;
                }
            }
            return nullptr;
        }

        void GridLayout::FlowMemoStore(std::size_t index, const Element& child,
                                       Size avail, Size desired) noexcept {
            if (index >= flow_memos_.size()) {
                return;
            }
            ChildFlowMemo& slot0 = flow_memos_[index].slot[0];
            ChildFlowMemo& slot1 = flow_memos_[index].slot[1];
            if (slot0.valid && slot0.avail.w == avail.w &&
                slot0.avail.h == avail.h) {
                // Same key: refresh in place (MRU stays slot 0).
            } else if (slot1.valid && slot1.avail.w == avail.w &&
                       slot1.avail.h == avail.h) {
                const ChildFlowMemo previous = slot0;
                slot0 = slot1;
                slot1 = previous;
            } else {
                slot1 = slot0;
                slot0 = ChildFlowMemo{};
            }
            slot0.avail = avail;
            slot0.desired = desired;
            slot0.gen = child.measure_gen();
            slot0.gen_key = TextMeasureGeneration();
            slot0.valid = true;
        }

        void GridLayout::FlowMemoRefresh(std::size_t index,
                                         const Element& child) noexcept {
            if (index >= flow_memos_.size()) {
                return;
            }
            const uint64_t gen = child.measure_gen();
            for (ChildFlowMemo& memo : flow_memos_[index].slot) {
                if (memo.valid) {
                    memo.gen = gen;
                }
            }
        }

        Size GridLayout::MeasureCore(Size available) {
            EnsureFlowMemos();
            if (cols_.empty()) {
                return Size{padding_.horizontal(), padding_.vertical()};
            }
            const float inner_w =
                std::max(0.0f, available.w - padding_.horizontal());
            const float inner_h =
                std::max(0.0f, available.h - padding_.vertical());
            const std::vector<float> widths = ColumnWidths(inner_w);
            const std::size_t ncols = cols_.size();
            const std::size_t nrows =
                (ncols == 0) ? 0 : (children_.size() + ncols - 1) / ncols;
            std::vector<float> row_heights(nrows, 0.0f);
            for (std::size_t i = 0; i < children_.size(); ++i) {
                Element* child = children_[i].get();
                if (!child->visible) {
                    continue;
                }
                // B5-4: same four-element memo key as the StackPanel M9 child
                // memo; a hit hands out the exact previously measured value
                // and collapses the invalidate-pass double measure of the
                // untouched siblings.
                const Size avail{widths[i % ncols], inner_h};
                const Size* memo = FlowMemoLookup(i, *child, avail);
                const Size d = (memo != nullptr) ? *memo : child->Measure(avail);
                if (memo == nullptr) {
                    FlowMemoStore(i, *child, avail, d);
                }
                row_heights[i / ncols] = std::max(row_heights[i / ncols], d.h);
            }
            float total_w = padding_.horizontal();
            float total_h = padding_.vertical();
            for (const float w : widths) {
                total_w += w;
            }
            if (ncols > 1) {
                total_w += gap_ * static_cast<float>(ncols - 1);
            }
            for (const float h : row_heights) {
                total_h += h;
            }
            if (nrows > 1) {
                total_h += gap_ * static_cast<float>(nrows - 1);
            }
            return Size{total_w, total_h};
        }

        void GridLayout::ArrangeCore(Rect final_rect) {
            if (cols_.empty()) {
                return;
            }
            const Rect content{final_rect.x + padding_.l,
                               final_rect.y + padding_.t,
                               std::max(0.0f, final_rect.w - padding_.horizontal()),
                               std::max(0.0f, final_rect.h - padding_.vertical())};
            const std::vector<float> widths = ColumnWidths(content.w);
            const std::size_t ncols = cols_.size();
            const std::size_t nrows = (children_.size() + ncols - 1) / ncols;
            std::vector<float> row_heights(nrows, 0.0f);
            for (std::size_t i = 0; i < children_.size(); ++i) {
                const Element* child = children_[i].get();
                if (!child->visible) {
                    continue;
                }
                row_heights[i / ncols] =
                    std::max(row_heights[i / ncols], child->desired().h);
            }
            float y = content.y;
            for (std::size_t r = 0; r < nrows; ++r) {
                float x = content.x;
                for (std::size_t c = 0; c < ncols; ++c) {
                    const std::size_t i = r * ncols + c;
                    if (i >= children_.size()) {
                        break;
                    }
                    Element* child = children_[i].get();
                    if (!child->visible) {
                        continue;
                    }
                    if (child->is_overlay()) {
                        child->Arrange(content);
                        continue;
                    }
                    // batch19 R4-P2: grid columns mirror under RTL (logical
                    // column 0 lands at the physical right).
                    {
                        Rect gr{x, y, widths[c], row_heights[r]};
                        if (I18n::Instance().IsRtl()) {
                            gr.x = content.x + content.w - (x - content.x) -
                                   widths[c];
                        }
                        child->Arrange(gr);
                    }
                    // B5-4: re-sync the memo generation after the Arrange-time
                    // Measure (missing it would make the next pass MISS and
                    // re-run the sibling cores the memo exists to remove).
                    FlowMemoRefresh(i, *child);
                    x += widths[c] + gap_;
                }
                y += row_heights[r] + gap_;
            }
        }

        // --- Card ------------------------------------------------------------

        Card::Card(Padding padding, float radius)
            : padding_(padding), radius_(radius) {
            hit_transparent = true;
        }

        Size Card::MeasureCore(Size available) {
            const Size inner{std::max(0.0f, available.w - padding_.horizontal()),
                             std::max(0.0f, available.h - padding_.vertical())};
            float w = 0.0f;
            float h = 0.0f;
            for (const auto& child : children_) {
                if (!child->visible) {
                    continue;
                }
                const Size d = child->Measure(inner);
                w = std::max(w, d.w);
                h = std::max(h, d.h);
            }
            return Size{w + padding_.horizontal(), h + padding_.vertical()};
        }

        void Card::ArrangeCore(Rect final_rect) {
            const Rect content{final_rect.x + padding_.l,
                               final_rect.y + padding_.t,
                               std::max(0.0f, final_rect.w - padding_.horizontal()),
                               std::max(0.0f, final_rect.h - padding_.vertical())};
            ArrangeChildren(content);
        }

        // --- Separator -------------------------------------------------------

        Separator::Separator() {
            hit_transparent = true;
        }

        Size Separator::MeasureCore(Size available) {
            return Size{std::max(0.0f, available.w), 1.0f};
        }

        // --- Text ------------------------------------------------------------

        Text::Text(std::wstring text, FontToken font, ColorToken color, bool wrap,
                   Align align)
            : text_(std::move(text)), font_(font), color_(color), wrap_(wrap),
              align_(align) {}

        void Text::SetText(std::wstring text) {
            if (text == text_) {
                return;
            }
            // batch37b: a value refresh whose measured width is unchanged
            // ("5 s" -> "6 s", "1,230" -> "1,982") needs a repaint, not a
            // whole-page re-arrange. The dashboard used to relayout at the
            // snapshot rate (user: refresh stutter). Wrapped text re-flows with
            // its content, so it keeps the conservative path.
            const Size old_sz =
                wrap_ ? Size{0.0f, 0.0f}
                      : MeasureText(text_, font_, kUnboundedWidth);
            text_ = std::move(text);
            ++content_rev;
            const Size new_sz =
                wrap_ ? Size{0.0f, 0.0f}
                      : MeasureText(text_, font_, kUnboundedWidth);
            if (!wrap_ && new_sz.w == old_sz.w && new_sz.h == old_sz.h) {
                return;
            }
            InvalidateLayout();
        }

        void Text::SetColor(ColorToken color) {
            if (color == color_) {
                return;
            }
            color_ = color;
            ++content_rev;  // repaint (and keep the epoch change observable)
        }

        Size Text::MeasureCore(Size available) {
            // M3b: the natural (unbounded) measurement is memoised against
            // content_rev. SetText bumps that counter, so a text change always
            // invalidates the slot. The wrap arithmetic below still runs on
            // every pass: it depends on the available width, not the text.
            Size natural{};
            if (measure_memo_valid_ && measure_memo_rev_ == content_rev &&
                measure_memo_gen_ == TextMeasureGeneration()) {
                natural = measure_memo_sz_;
            } else {
                natural = MeasureText(text_, font_, kUnboundedWidth);
                measure_memo_sz_ = natural;
                measure_memo_rev_ = content_rev;
                measure_memo_gen_ = TextMeasureGeneration();
                measure_memo_valid_ = true;
            }
            if (!wrap_ || available.w <= 0.0f) {
                return natural;
            }
            const int lines =
                (natural.w > available.w)
                    ? static_cast<int>(
                          std::ceil(natural.w / available.w))
                    : 1;
            return Size{std::min(natural.w, available.w),
                        natural.h * static_cast<float>(lines)};
        }

        // --- Button ----------------------------------------------------------

        Button::Button(std::wstring label, ButtonStyle style)
            : label_(std::move(label)), style_(style) {}

        void Button::SetLabel(std::wstring label) {
            if (label == label_) {
                return;
            }
            label_ = std::move(label);
            ++content_rev;
            InvalidateLayout();
        }

        Size Button::MeasureCore(Size) {
            // M3b: the natural measurement is memoised against content_rev.
            // SetLabel bumps that counter, so a label change always
            // invalidates the slot.
            const Size text = [this] {
                if (measure_memo_valid_ && measure_memo_rev_ == content_rev &&
                    measure_memo_gen_ == TextMeasureGeneration()) {
                    return measure_memo_sz_;
                }
                const Size s = MeasureText(label_, FontToken::Body,
                                           kUnboundedWidth);
                measure_memo_sz_ = s;
                measure_memo_rev_ = content_rev;
                measure_memo_gen_ = TextMeasureGeneration();
                measure_memo_valid_ = true;
                return s;
            }();
            return Size{std::max(kButtonMinW, text.w + 2.0f * kButtonPadX),
                        std::max(kButtonMinH, text.h + 2.0f * kButtonPadY)};
        }

        void Button::Fire() {
            if (on_click) {
                on_click();
            }
        }

        bool Button::OnMouseDown(Point) {
            if (!EffectivelyEnabled()) {
                return false;
            }
            pressed_ = true;
            return true;
        }

        bool Button::OnMouseUp(Point p) {
            if (!pressed_) {
                return false;
            }
            pressed_ = false;
            if (EffectivelyEnabled() && bounds().Contains(p)) {
                Fire();
            }
            return true;
        }

        bool Button::OnKeyDown(uint32_t vk) {
            if (!EffectivelyEnabled()) {
                return false;
            }
            if (vk == kVkReturn || vk == kVkSpace) {
                Fire();
                return true;
            }
            return false;
        }

        // --- SegmentedControl (T3-F2) --------------------------------------

        SegmentedControl::SegmentedControl(std::vector<std::wstring> labels)
            : labels_(std::move(labels)) {}

        bool SegmentedControl::SetIndex(std::size_t index) {
            if (index >= labels_.size() || index == index_) {
                return false;
            }
            index_ = index;
            ++content_rev;
            if (on_changed) {
                on_changed(index_);
            }
            return true;
        }

        void SegmentedControl::SetSelected(std::size_t index) noexcept {
            if (index < labels_.size()) {
                index_ = index;
                ++content_rev;
            }
        }

        void SegmentedControl::SetLabels(std::vector<std::wstring> labels) {
            // M10-4: equality guard, same pattern as SetRows/SetText/SetLabel.
            // The leases page relabels every stats tick (leases.cpp Relabel);
            // without this guard every tick bumped content_rev -> the global
            // content epoch -> UiApp::Update RequestLayout (2 Hz whole-tree
            // relayout + full repaint). Equal payloads are a pure no-op - the
            // out-of-range index clamp below is unreachable in that case
            // (SetSelected guards its range; a successful SetLabels keeps
            // index_ < size).
            if (labels == labels_) {
                return;
            }
            labels_ = std::move(labels);
            if (index_ >= labels_.size()) {
                index_ = 0;  // selection preserved when still in range
            }
            ++content_rev;
            InvalidateLayout();  // labels can widen/narrow the control
        }

        int SegmentedControl::HitSegment(Point p) const noexcept {
            if (labels_.empty() || bounds_.w <= 0.0f ||
                !bounds_.Contains(p)) {
                return -1;
            }
            const float seg_w = bounds_.w / static_cast<float>(labels_.size());
            const std::size_t phys =
                static_cast<std::size_t>((p.x - bounds_.x) / seg_w);
            if (phys >= labels_.size()) {
                return -1;
            }
            // batch19 R4-P2: segments mirror under RTL.
            return I18n::Instance().IsRtl()
                       ? static_cast<int>(labels_.size() - 1 - phys)
                       : static_cast<int>(phys);
        }

        bool SegmentedControl::OnKeyDown(uint32_t vk) {
            if (!EffectivelyEnabled() || labels_.size() < 2) {
                return false;
            }
            std::size_t next = index_;
            if (vk == kVkRight) {
                next = (index_ + 1) % labels_.size();
            } else if (vk == kVkLeft) {
                next = (index_ + labels_.size() - 1) % labels_.size();
            } else {
                return false;
            }
            SetIndex(next);
            return true;
        }

        bool SegmentedControl::OnMouseDown(Point p) {
            if (!EffectivelyEnabled()) {
                return false;
            }
            const int hit = HitSegment(p);
            if (hit < 0) {
                return false;
            }
            SetIndex(static_cast<std::size_t>(hit));
            return true;
        }

        bool SegmentedControl::OnMouseMove(Point p) {
            const int hit = HitSegment(p);
            if (hit == hover_) {
                return false;
            }
            hover_ = hit;
            ++content_rev;  // hover is visual only: never consumes the move
            return false;
        }

        Size SegmentedControl::MeasureCore(Size) {
            float max_text_w = 0.0f;
            float text_h = 0.0f;
            for (const std::wstring& label : labels_) {
                const Size t = MeasureText(label, FontToken::Body,
                                           kUnboundedWidth);
                max_text_w = std::max(max_text_w, t.w);
                text_h = std::max(text_h, t.h);
            }
            const float seg_w = std::max(kSegMinW, max_text_w + 2.0f * kSegPadX);
            const float seg_h = std::max(kSegMinH, text_h + 2.0f * kSegPadY);
            return Size{seg_w * static_cast<float>(labels_.size()), seg_h};
        }

        void SegmentedControl::RenderCore(RenderCtx& ctx) {
            if (labels_.empty() || bounds_.w <= 0.0f || bounds_.h <= 0.0f) {
                return;
            }
            const bool is_enabled = EffectivelyEnabled();
            const float seg_w = bounds_.w / static_cast<float>(labels_.size());
            // batch18 U3 (container language): one quiet rounded frame and
            // surface around the whole control; the selected segment is the
            // single Accent rounded fill and the interior seams are 1 px
            // hairlines drawn ONLY between two unselected neighbours. The
            // batch17 per-segment Border stroke (four independent rounded
            // edges) produced double-line seams with background scallops and
            // a "frame pressing on the lines below" reading - removed.
            Color container = ColorFor(ColorToken::Panel);
            if (!is_enabled) {
                container.a = 0.45f;
            }
            ctx.FillRoundedRect(bounds_, g_theme.radius_sm, container);
            ctx.StrokeRoundedRect(bounds_, g_theme.radius_sm,
                                  ColorFor(ColorToken::Border), 1.0f);
            const bool rtl = I18n::Instance().IsRtl();
            for (std::size_t i = 0; i < labels_.size(); ++i) {
                // batch19 R4-P2: logical segment i paints at the mirrored
                // physical column under RTL.
                const std::size_t phys = rtl ? (labels_.size() - 1 - i) : i;
                const Rect seg{bounds_.x + seg_w * static_cast<float>(phys),
                               bounds_.y, seg_w, bounds_.h};
                Color text_color = ColorFor(ColorToken::Text);
                if (i == index_) {
                    Color fill = ColorFor(ColorToken::Accent);
                    if (!is_enabled) {
                        fill.a = 0.45f;
                    }
                    ctx.FillRoundedRect(seg, g_theme.radius_sm, fill);
                    text_color = Color{1.0f, 1.0f, 1.0f, 1.0f};
                } else if (static_cast<int>(i) == hover_) {
                    Color fill = ColorFor(ColorToken::PanelAlt);
                    if (!is_enabled) {
                        fill.a = 0.45f;
                    }
                    ctx.FillRoundedRect(seg, g_theme.radius_sm, fill);
                }
                if (!is_enabled) {
                    text_color = ColorFor(ColorToken::TextDim);
                }
                // Interior seam before segment i (i >= 1): a hairline only
                // when NEITHER neighbour is the selected segment (a selected
                // edge already carries the Accent fill boundary).
                if (i > 0 && static_cast<int>(i - 1) != index_ &&
                    static_cast<int>(i) != index_) {
                    ctx.FillRect(Rect{seg.x, seg.y, 1.0f, seg.h},
                                 ColorFor(ColorToken::Border));
                }
                ctx.DrawText(labels_[i], seg, FontToken::Body, text_color,
                             Align::Center);
            }
        }

        // --- LanguagePicker (batch19 R4-P4) ---------------------------------

        namespace {
            constexpr float kPickerRowH = 28.0f;
            wchar_t LowerW(wchar_t c) {
                return (c >= L'A' && c <= L'Z') ? static_cast<wchar_t>(c + 32)
                                                : c;
            }
        }  // namespace

        LanguagePicker::LanguagePicker() {
            hit_transparent = false;
            // batch24 P2-6: the search box now lives INSIDE the picker popup.
            // The editable text is an owned TextInputElement (member, never a
            // tree child) so the picker keeps its single hit surface and the
            // page no longer needs a standalone filter editor.
            search_ = std::make_unique<TextInputElement>();
            search_->id = "lang.search";
            search_->on_changed = [this] { SyncFilterFromSearch(); };
        }

        LanguagePicker::~LanguagePicker() = default;

        void LanguagePicker::SetLanguages(std::vector<Item> items,
                                          std::string current_code) {
            items_ = std::move(items);
            selected_code_ = std::move(current_code);
            filter_.clear();
            // batch62: the lowercased haystacks depend only on the item table,
            // which is replaced wholesale here - build them once instead of
            // re-lowercasing all entries on every keystroke.
            name_lc_.resize(items_.size());
            code_lc_.resize(items_.size());
            for (std::size_t i = 0; i < items_.size(); ++i) {
                name_lc_[i].clear();
                name_lc_[i].reserve(items_[i].name.size());
                for (const wchar_t c : items_[i].name) {
                    name_lc_[i].push_back(LowerW(c));
                }
                code_lc_[i].clear();
                code_lc_[i].reserve(items_[i].code.size());
                for (const char ch : items_[i].code) {
                    code_lc_[i].push_back(LowerW(static_cast<wchar_t>(
                        static_cast<unsigned char>(ch))));
                }
            }
            if (search_ != nullptr) {
                search_->SetValue(std::wstring());
            }
            expanded_ = false;
            search_focused_ = false;
            highlight_ = 0;
            view_top_ = 0;
            Recompute();
            ++content_rev;
            InvalidateLayout();
        }

        void LanguagePicker::SetFilter(std::wstring filter) {
            if (filter == filter_) {
                return;
            }
            filter_ = std::move(filter);
            if (search_ != nullptr) {
                search_->SetValue(filter_);  // silent echo (no re-entrancy)
            }
            highlight_ = 0;
            view_top_ = 0;
            Recompute();
            ++content_rev;
            InvalidateLayout();
            // batch20: the visible row count changes, so the in-layout height
            // does too - request a deterministic layout pass.
            RequestLayoutFrame();
        }

        void LanguagePicker::SyncFilterFromSearch() {
            if (search_ == nullptr) {
                return;
            }
            // Reuse SetFilter (which echoes back silently and requests layout);
            // guard against the echo re-entering here.
            const std::wstring value = search_->value();
            if (value != filter_) {
                SetFilter(value);
            } else {
                ++content_rev;  // caret moved within an unchanged filter
            }
        }

        void LanguagePicker::Recompute() {
            filtered_.clear();
            std::wstring needle;
            needle.reserve(filter_.size());
            for (const wchar_t c : filter_) {
                needle.push_back(LowerW(c));
            }
            for (std::size_t i = 0; i < items_.size(); ++i) {
                bool match = needle.empty();
                if (!match) {
                    // batch62: compare against the memoised lowercase forms.
                    if (i < name_lc_.size() &&
                        name_lc_[i].find(needle) != std::wstring::npos) {
                        match = true;
                    } else if (i < code_lc_.size() &&
                               code_lc_[i].find(needle) != std::wstring::npos) {
                        match = true;
                    }
                }
                if (match) {
                    filtered_.push_back(i);
                }
            }
            if (highlight_ >= filtered_.size()) {
                highlight_ = 0;
            }
            EnsureVisible();
        }

        void LanguagePicker::EnsureVisible() noexcept {
            const std::size_t n = filtered_.size();
            if (n == 0) {
                view_top_ = 0;
                highlight_ = 0;
                return;
            }
            if (highlight_ < view_top_) {
                view_top_ = highlight_;
            } else if (highlight_ >= view_top_ + kMaxRows) {
                view_top_ = highlight_ - kMaxRows + 1;
            }
            const std::size_t max_top = (n > kMaxRows) ? (n - kMaxRows) : 0;
            if (view_top_ > max_top) {
                view_top_ = max_top;
            }
        }

        std::string LanguagePicker::highlighted_code() const {
            if (highlight_ < filtered_.size()) {
                return items_[filtered_[highlight_]].code;
            }
            return std::string();
        }

        void LanguagePicker::SetExpanded(bool expanded) noexcept {
            if (expanded == expanded_) {
                return;
            }
            expanded_ = expanded;
            // batch24 P2-6: opening puts keyboard focus on the search row so
            // typing filters immediately; closing drops it.
            search_focused_ = expanded_;
            if (search_ != nullptr) {
                search_->OnFocus(expanded_);
            }
            if (expanded_) {
                Recompute();
            }
            ++content_rev;
            InvalidateLayout();
            // batch20: expanding/collapsing grows/shrinks this control IN the
            // flow (MeasureCore = kPickerRowH * (2 + rows)). Request the host
            // layout explicitly - the tick's content-epoch heuristic can miss
            // it, which left the expanded list painted over the content below.
            RequestLayoutFrame();
        }

        void LanguagePicker::OnFocus(bool focused) {
            if (focused == focused_) {
                return;
            }
            focused_ = focused;
            ++content_rev;
        }

        void LanguagePicker::SetCurrentCode(std::string code) {
            if (code == selected_code_) {
                return;
            }
            selected_code_ = std::move(code);
            ++content_rev;
        }

        void LanguagePicker::Activate(std::size_t filtered_index) {
            if (filtered_index >= filtered_.size()) {
                return;
            }
            selected_code_ = items_[filtered_[filtered_index]].code;
            expanded_ = false;
            search_focused_ = false;
            ++content_rev;
            InvalidateLayout();
            if (on_pick) {
                on_pick(selected_code_);
            }
        }

        Size LanguagePicker::MeasureCore(Size available) {
            const float rows =
                expanded_ ? static_cast<float>(
                                std::min(filtered_.size(), kMaxRows))
                          : 0.0f;
            // batch24 P2-6: the expanded popup carries a search row ABOVE the
            // result rows (collapsed box + search + rows).
            const float search_rows = expanded_ ? 1.0f : 0.0f;
            // batch27 D4: a preferred width caps the CROSS axis only (the
            // rows below stay the same width); the popup rows paint inside
            // bounds_, so both the collapsed box and the list shrink together.
            float w = std::max(available.w, 0.0f);
            if (preferred_w_ > 0.0f) {
                w = std::min(w, preferred_w_);
            }
            return Size{w, kPickerRowH * (1.0f + search_rows + rows)};
        }

        void LanguagePicker::RenderCore(RenderCtx& ctx) {
            if (bounds_.w <= 0.0f || bounds_.h <= 0.0f) {
                return;
            }
            const Rect box{bounds_.x, bounds_.y, bounds_.w, kPickerRowH};
            // batch20 C9 (same-type audit): the collapsed box follows the
            // SelectElement/TextInput contract - rounded (radius_sm) with the
            // InputBorder stroke (the picker has no focus state, so the
            // Select's accent focus stroke has no counterpart here). Only the
            // popup list below stays square.
            ctx.FillRoundedRect(box, g_theme.radius_sm,
                                ColorFor(ColorToken::Panel));
            ctx.StrokeRoundedRect(box, g_theme.radius_sm,
                                  focused_ ? ColorFor(ColorToken::Accent)
                                           : ColorFor(ColorToken::InputBorder),
                                  focused_ ? 2.0f : 1.0f);
            std::wstring label;
            for (const Item& it : items_) {
                if (it.code == selected_code_) {
                    label = it.name;
                    break;
                }
            }
            if (expanded_ && !filter_.empty()) {
                label = filter_;
            }
            const bool natural_measure =
                MeasureText(L"x", FontToken::Body, 1.0f).w <= 1.5f;
            ctx.DrawTextSingleLine(
                EllipsizeToWidth(label, FontToken::Body,
                                 std::max(box.w - 20.0f, 0.0f),
                                 natural_measure),
                Rect{box.x + 10.0f, box.y,
                     std::max(box.w - 20.0f, 0.0f), box.h},
                FontToken::Body, ColorFor(ColorToken::Text), Align::Start);
            if (!expanded_) {
                return;
            }
            // batch24 P2-6: the search row sits between the collapsed box and
            // the result list (its own box + placeholder/value + caret).
            DrawSearchRow(ctx);
            const std::size_t total = filtered_.size();
            const std::size_t top = (view_top_ < total) ? view_top_ : 0;
            const std::size_t rows = std::min(total - top, kMaxRows);
            const Rect list{bounds_.x, bounds_.y + 2.0f * kPickerRowH, bounds_.w,
                            kPickerRowH * static_cast<float>(rows)};
            // batch26: same restrained drop shadow as the Select popup.
            const Color shadow{0.0f, 0.0f, 0.0f, 0.18f};
            ctx.FillRoundedRect(Rect{list.x + 3.0f, list.y + list.h,
                                     list.w - 3.0f, 3.0f},
                                2.0f, shadow);
            ctx.FillRoundedRect(Rect{list.x + list.w, list.y + 3.0f, 3.0f,
                                     list.h - 3.0f},
                                2.0f, shadow);
            ctx.FillRect(list, ColorFor(ColorToken::PanelAlt));
            ctx.StrokeRect(list, ColorFor(ColorToken::TextDim), 1.0f);
            for (std::size_t r = 0; r < rows; ++r) {
                const std::size_t fi = top + r;  // filtered index (viewport)
                const Rect row{list.x, list.y + kPickerRowH * static_cast<float>(r),
                               list.w, kPickerRowH};
                const Item& it = items_[filtered_[fi]];
                if (it.code == selected_code_) {
                    // The CURRENT language row: the same restrained blue tint
                    // and the same small rounded accent pill as the Select
                    // popup. The keyboard highlight tint below is painted on
                    // top when it lands on this row (the two compose: a
                    // slightly brighter tint, the pill unaffected).
                    ctx.FillRect(row, Color{0.0f, 0.48f, 1.0f, 0.11f});
                    const bool rtl = I18n::Instance().IsRtl();
                    const float pill_h = std::min(20.0f, row.h - 8.0f);
                    const float pill_y = row.y + (row.h - pill_h) * 0.5f;
                    const float pill_w = 3.5f;
                    const float pill_x = rtl ? row.x + row.w - 6.0f - pill_w
                                             : row.x + 6.0f;
                    ctx.FillRoundedRect(Rect{pill_x, pill_y, pill_w, pill_h},
                                        2.0f, ColorFor(ColorToken::Accent));
                }
                if (fi == highlight_) {
                    ctx.FillRect(row, HoverOverlay(0.06f, 0.09f));
                }
                const std::wstring line = EllipsizeToWidth(
                    it.name + L"  (" +
                        std::wstring(it.code.begin(), it.code.end()) + L")",
                    FontToken::Body, std::max(row.w - 20.0f, 0.0f),
                    natural_measure);
                ctx.DrawTextSingleLine(
                    line, Rect{row.x + 10.0f, row.y,
                               std::max(row.w - 20.0f, 0.0f), row.h},
                    FontToken::Body,
                    fi == highlight_ ? ColorFor(ColorToken::AccentText)
                                     : ColorFor(ColorToken::Text),
                    Align::Start);
            }
        }

        void LanguagePicker::DrawSearchRow(RenderCtx& ctx) {
            const Rect row{bounds_.x, bounds_.y + kPickerRowH, bounds_.w,
                           kPickerRowH};
            ctx.FillRect(row, ColorFor(ColorToken::PanelAlt));
            const Rect field{row.x + 4.0f, row.y + 4.0f,
                             std::max(row.w - 8.0f, 0.0f),
                             std::max(row.h - 8.0f, 0.0f)};
            ctx.FillRoundedRect(field, g_theme.radius_sm,
                                ColorFor(ColorToken::Panel));
            const std::wstring& value =
                search_ != nullptr ? search_->value() : filter_;
            const bool placeholder = value.empty();
            const std::wstring& text =
                placeholder && search_ != nullptr ? search_->placeholder()
                                                  : value;
            ctx.ClipPush(field);
            ctx.DrawTextSingleLine(
                text, Rect{field.x + 8.0f, field.y,
                           std::max(field.w - 16.0f, 0.0f), field.h},
                FontToken::Body,
                placeholder ? ColorFor(ColorToken::TextDim)
                            : ColorFor(ColorToken::Text),
                Align::Start);
            if (search_focused_ && search_ != nullptr) {
                const std::size_t caret = search_->caret_index();
                const float prefix_w =
                    caret > 0
                        ? MeasureText(value.substr(0, caret), FontToken::Body,
                                      kUnboundedWidth)
                              .w
                        : 0.0f;
                const float cx = field.x + 8.0f + prefix_w;
                ctx.FillRect(Rect{cx, field.y + 4.0f, 1.0f,
                                  std::max(field.h - 8.0f, 1.0f)},
                             ColorFor(ColorToken::Text));
            }
            ctx.ClipPop();
        }

        bool LanguagePicker::OnWheel(int delta) {
            if (!expanded_ || delta == 0) {
                return false;
            }
            const std::size_t n = filtered_.size();
            if (n == 0) {
                return true;
            }
            if (delta > 0) {
                if (highlight_ > 0) {
                    --highlight_;
                }
            } else if (highlight_ + 1 < n) {
                ++highlight_;
            }
            EnsureVisible();
            ++content_rev;
            return true;
        }

        bool LanguagePicker::OnKeyDown(uint32_t vk) {
            if (!EffectivelyEnabled()) {
                return false;
            }
            if (vk == 0x1B) {  // Esc
                if (expanded_) {
                    expanded_ = false;
                    search_focused_ = false;
                    ++content_rev;
                    InvalidateLayout();
                    return true;
                }
                return false;
            }
            if (!expanded_) {
                if (vk == 0x0D || vk == 0x20) {  // Enter / Space open
                    SetExpanded(true);
                    return true;
                }
                return false;
            }
            // batch24 P2-6: while the in-popup search row is active, the pure
            // editing keys are routed to its editor (Up/Down/Enter/Esc stay as
            // list navigation/pick/close below).
            if (search_focused_ && search_ != nullptr) {
                switch (vk) {
                    case 0x20:  // Space
                    case 0x08:  // Backspace
                    case 0x2E:  // Delete
                    case 0x25:  // Left
                    case 0x27:  // Right
                    case 0x24:  // Home
                    case 0x23:  // End
                        if (search_->OnKeyDown(vk)) {
                            return true;
                        }
                        break;
                    default:
                        break;
                }
            }
            const std::size_t n = filtered_.size();
            if (vk == 0x28) {  // Down
                if (n > 0 && highlight_ + 1 < n) {
                    ++highlight_;
                    EnsureVisible();
                }
                ++content_rev;
                return true;
            }
            if (vk == 0x26) {  // Up
                if (highlight_ > 0) {
                    --highlight_;
                    EnsureVisible();
                }
                ++content_rev;
                return true;
            }
            if (vk == 0x0D) {  // Enter picks
                Activate(highlight_);
                return true;
            }
            return false;
        }

        bool LanguagePicker::OnMouseDown(Point p) {
            if (!EffectivelyEnabled() || !bounds_.Contains(p)) {
                return false;
            }
            const float rel = p.y - bounds_.y;
            if (rel <= kPickerRowH) {
                SetExpanded(!expanded_);
                return true;
            }
            if (expanded_) {
                // batch24 P2-6: the row just under the collapsed box is the
                // in-popup search field.
                if (rel <= 2.0f * kPickerRowH) {
                    search_focused_ = true;
                    if (search_ != nullptr) {
                        search_->OnFocus(true);
                    }
                    ++content_rev;
                    return true;
                }
                const std::size_t row = static_cast<std::size_t>(
                    (rel - 2.0f * kPickerRowH) / kPickerRowH);
                const std::size_t fi = view_top_ + row;
                if (row < kMaxRows && fi < filtered_.size()) {
                    highlight_ = fi;
                    Activate(fi);
                }
            }
            return true;
        }

        bool LanguagePicker::OnChar(wchar_t ch) {
            if (!EffectivelyEnabled() || !expanded_ || search_ == nullptr) {
                return false;
            }
            search_focused_ = true;
            const bool handled = search_->OnChar(ch);
            if (handled) {
                ++content_rev;
            }
            return handled;
        }

        std::wstring LanguagePicker::tooltip_text(Point p) const {
            if (!EffectivelyEnabled() || !bounds_.Contains(p)) {
                return std::wstring();
            }
            const auto overflows = [](const std::wstring& text,
                                      float available) {
                return !text.empty() && available > 0.0f &&
                       MeasureText(text, FontToken::Body, 1.0e9f).w >
                           available;
            };
            if (expanded_) {
                const float rel = p.y - bounds_.y;
                if (rel >= 2.0f * kPickerRowH) {
                    const std::size_t row = static_cast<std::size_t>(
                        (rel - 2.0f * kPickerRowH) / kPickerRowH);
                    const std::size_t fi = view_top_ + row;
                    if (row < kMaxRows && fi < filtered_.size()) {
                        const std::wstring& name = items_[filtered_[fi]].name;
                        return overflows(name, bounds_.w - 20.0f)
                                   ? name
                                   : std::wstring();
                    }
                }
            }
            for (const Item& item : items_) {
                if (item.code == selected_code_) {
                    return overflows(item.name, bounds_.w - 20.0f)
                               ? item.name
                               : std::wstring();
                }
            }
            return std::wstring();
        }

        // --- Checkbox --------------------------------------------------------

        Checkbox::Checkbox(bool checked) : checked(checked) {}

        void Checkbox::SetChecked(bool value) {
            if (checked == value) {
                return;
            }
            checked = value;
            ++content_rev;
        }

        void Checkbox::SetRadioStyle(bool on) {
            if (radio_ == on) {
                return;
            }
            radio_ = on;
            ++content_rev;
        }

        void Checkbox::Toggle() {
            checked = !checked;
            if (on_changed) {
                on_changed(checked);
            }
        }

        void Checkbox::ArrangeCore(Rect final_rect) {
            // batch33s: a flow row with child_align_ == Stretch hands the
            // control the row's full cross size (400x16 in the settings
            // radio row), which turned the 16 px box into an ellipse and
            // made the ring unreadable. A checkbox/radio is a fixed square:
            // keep the side and centre it on the row's cross axis.
            const float side = kCheckboxBox;
            const float x = final_rect.x +
                            (final_rect.w - side) * 0.5f;
            const float y = final_rect.y +
                            (final_rect.h - side) * 0.5f;
            // Element::Arrange already stored the stretched box in bounds_;
            // a control that paints a fixed square must narrow it itself.
            bounds_ = Rect{x, y, side, side};
        }

        Size Checkbox::MeasureCore(Size) {
            return Size{kCheckboxBox, kCheckboxBox};
        }

        bool Checkbox::OnMouseDown(Point) {
            if (!EffectivelyEnabled()) {
                return false;
            }
            pressed_ = true;
            return true;
        }

        bool Checkbox::OnMouseUp(Point p) {
            if (!pressed_) {
                return false;
            }
            pressed_ = false;
            if (EffectivelyEnabled() && bounds().Contains(p)) {
                Toggle();
            }
            return true;
        }

        bool Checkbox::OnKeyDown(uint32_t vk) {
            if (!EffectivelyEnabled()) {
                return false;
            }
            if (vk == kVkSpace) {
                Toggle();
                return true;
            }
            return false;
        }

        void Checkbox::OnFocus(bool focused) {
            if (focused == focused_) {
                return;
            }
            focused_ = focused;
            ++content_rev;  // focus ring is visual: repaint on change
        }

        // -------------------------------------------------------------------
        // Task 3: data controls and overlays.
        // -------------------------------------------------------------------

        namespace {

            constexpr float kUnboundedHeight = 1.0e9f;
            constexpr float kWheelStep = 48.0f;
            /// batch26 P1: one wheel notch (WHEEL_DELTA = 120) stays at 48 px,
            /// while a fast/high-resolution wheel event scales proportionally
            /// instead of crawling at 48 px per event.
            inline float WheelStepForDelta(int delta) noexcept {
                return kWheelStep * (std::fabs(static_cast<float>(delta)) /
                                     120.0f);
            }

            /// batch26: shorten a cell to `max_width` with a trailing ellipsis.
            /// Only called for the visible window and the result is memoised in
            /// CellMemo, so a steady frame performs no extra measuring.
            std::wstring EllipsizeToWidth(const std::wstring& text,
                                          FontToken font, float max_width,
                                          bool can_measure_naturally) {
                if (!can_measure_naturally) {
                    return text;
                }
                if (text.empty() || max_width <= 0.0f) {
                    return std::wstring();
                }
                constexpr float kUnbounded = 1.0e9f;
                if (MeasureText(text, font, kUnbounded).w <= max_width) {
                    return text;
                }
                const std::wstring ell = L"\u2026";
                if (MeasureText(ell, font, kUnbounded).w > max_width) {
                    return std::wstring();  // not even the ellipsis fits
                }
                std::size_t lo = 0;
                std::size_t hi = text.size();
                while (lo < hi) {
                    const std::size_t mid = lo + (hi - lo + 1) / 2;
                    if (MeasureText(text.substr(0, mid) + ell, font,
                                    kUnbounded)
                            .w <= max_width) {
                        lo = mid;
                    } else {
                        hi = mid - 1;
                    }
                }
                return text.substr(0, lo) + ell;
            }

            constexpr float kBannerHeight = 44.0f;
            constexpr float kBannerActionW = 180.0f;

            constexpr float kTableHeaderH = 40.0f;
            constexpr float kTableRowH = 28.0f;
            constexpr std::size_t kTableOverscan = 2;
            constexpr float kTableActionW = 56.0f;
            constexpr float kColumnInset = 4.0f;  ///< >= 8 pt spacing (A3)
            /// D5: half-width of the header boundary grab band (px).
            constexpr float kColumnResizeGrab = 6.0f;
            /// D5: smallest width a column may be dragged to (px).
            constexpr float kMinColumnW = 24.0f;
            constexpr float kSelectItemH = 28.0f;  ///< Select popup row (C4)

            constexpr uint32_t kVkBackspace = 0x08;
            constexpr uint32_t kVkDelete = 0x2E;
            constexpr uint32_t kVkEscape = 0x1B;
            constexpr uint32_t kVkUp = 0x26;
            constexpr uint32_t kVkDown = 0x28;
            constexpr uint32_t kVkHome = 0x24;
            constexpr uint32_t kVkEnd = 0x23;
            /// batch120: one source of truth for the navigation codes the two
            /// key handlers below share. They used to be re-declared inside
            /// each function, which shadowed these (C4459) and meant three
            /// places to edit for one key.
            constexpr uint32_t kVkPrior = 0x21;  // PageUp
            constexpr uint32_t kVkNext = 0x22;   // PageDown

            constexpr std::chrono::seconds kToastTtl{3};
            constexpr std::size_t kToastMax = 3;

        }  // namespace

        // --- ScrollView ------------------------------------------------------

        ScrollView::ScrollView(std::unique_ptr<Element> content) {
            Add(std::move(content));
        }

        Element* ScrollView::Content() const noexcept {
            return children_.empty() ? nullptr : children_.front().get();
        }

        void ScrollView::ClampOffset() noexcept {
            const float max_offset = std::max(0.0f, content_h_ - view_h_);
            offset_ = std::min(std::max(0.0f, offset_), max_offset);
        }

        void ScrollView::SetOffset(float offset) {
            offset_ = offset;
            ClampOffset();
            Element* content = Content();
            if (content != nullptr && view_h_ > 0.0f) {
                content->InvalidateLayout();
                // batch37g: the exact width ArrangeCore uses (viewport minus
                // the clip gutter). The old max(bounds_.w, desired) widened
                // the content by 1 px on every wheel tick and the next
                // relayout narrowed it again: visible left/right jitter.
                const float content_w = content_w_ > 0.0f
                                            ? content_w_
                                            : std::max(bounds_.w - 1.0f, 1.0f);
                content->Arrange(Rect{bounds_.x, bounds_.y - offset_,
                                      content_w, content_h_});
            }
        }

        Element* ScrollView::HitTest(Point p) {
            if (!visible || !EffectivelyEnabled()) {
                return nullptr;
            }
            // The viewport clips the content visually; hit-testing must match
            // that clip (U3), so points outside the box never reach content
            // that has scrolled off.
            if (!bounds_.Contains(p)) {
                return nullptr;
            }
            return Element::HitTest(p);
        }

        bool ScrollView::OnWheel(int delta) {
            if (delta == 0) {
                return false;
            }
            ++wheel_events_;
            const float step = WheelStepForDelta(delta);
            const float before = offset_;
            SetOffset(offset_ + (delta > 0 ? -step : step));
            // batch33 F: mirror the TableElement contract - an edge event that
            // cannot move must bubble instead of being swallowed.
            return offset_ != before;
        }

        bool ScrollView::OnKeyDown(uint32_t vk) {
            // batch33p (user: "no scrollbar - rely on the wheel and the arrow
            // keys"): the viewport scrolls from the keyboard. The window routes
            // WM_KEYDOWN to the focused element, and ScrollView::focusable()
            // is true, so clicking or tabbing into the content area is enough to
            // drive it. Only claim a key that actually moved the offset.
            const float page = std::max(view_h_ - kKeyScrollStep, kKeyScrollStep);
            const float before = offset_;
            switch (vk) {
                case kVkUp:
                    SetOffset(offset_ - kKeyScrollStep);
                    break;
                case kVkDown:
                    SetOffset(offset_ + kKeyScrollStep);
                    break;
                case kVkPrior:
                    SetOffset(offset_ - page);
                    break;
                case kVkNext:
                    SetOffset(offset_ + page);
                    break;
                case kVkHome:
                    SetOffset(0.0f);
                    break;
                case kVkEnd:
                    SetOffset(content_h_);
                    break;
                default:
                    return false;
            }
            return offset_ != before;
        }

        void ScrollView::ScrollIntoView(const Element* target) {
            if (target == nullptr) {
                return;
            }
            Element* content = Content();
            if (content == nullptr) {
                return;
            }
            // The content subtree is arranged contiguously at
            // (bounds_.y - offset_), so the target's offset inside the content
            // IS the scroll position that puts it at the viewport top. SetOffset
            // clamps into [0, content_h - view_h].
            const float target_top = target->bounds().y - content->bounds().y;
            SetOffset(offset_ + target_top);
        }

        Size ScrollView::MeasureCore(Size available) {
            Element* content = Content();
            if (content == nullptr) {
                content_h_ = 0.0f;
                return Size{available.w, available.h};
            }
            // batch33n: reserve the bottom inset INSIDE the content height, so
            // the last child never sits exactly on the clip boundary (its 1 px
            // border was being cut in half).
            content_h_ =
                content->Measure(Size{available.w, kUnboundedHeight}).h +
                content_bottom_inset_;
            const float h = (available.h > 0.0f && available.h < content_h_)
                                ? available.h
                                : content_h_;
            return Size{content->desired().w, h};
        }

        void ScrollView::ArrangeCore(Rect final_rect) {
            Element* content = Content();
            if (content == nullptr) {
                return;
            }
            view_h_ = final_rect.h;
            ClampOffset();
            // batch33n (user: "the border is a fatal problem"): the content is
            // laid out 1 px
            // NARROWER than the viewport. A child that fills the width (a form
            // input whose natural width equals the viewport) had its 1 px border
            // centred exactly on the clip edge, so the border was sliced in half
            // and the box looked "covered". The 1 px keeps the border inside.
            constexpr float kClipGutter = 1.0f;
            content_w_ = std::max(final_rect.w - kClipGutter, 1.0f);
            content->Arrange(Rect{final_rect.x, final_rect.y - offset_,
                                  content_w_, content_h_});
        }

        // --- TableElement ----------------------------------------------------

        TableElement::TableElement() {
            hit_transparent = false;
        }

        void TableElement::SetColumns(std::vector<TableColumn> cols) {
            if (cols == cols_) {
                return;
            }
            // D5: a user drag wins over the 500 ms snapshot tick re-sending the
            // same columns with the same base widths. Only a structural change
            // (id/header/align or column count) discards the user widths.
            const bool structure_same = StructureEquals(cols_, cols);
            cols_ = std::move(cols);
            // M3: the cell memo is indexed r * cols_.size() + c, so any real
            // column change (count or text) invalidates the whole grid - the
            // row-major indices, not just the widths, shift with the column
            // count. An equal payload never reaches here.
            ++row_gen_;
            cell_memos_.assign(rows_.size() * cols_.size(), CellMemo{});
            if (!structure_same) {
                user_resized_ = false;
                user_widths_.clear();
            }
            // batch37b: a column change re-arms the content-width freeze.
            natural_frozen_ = false;
            ++content_rev;
            InvalidateLayout();
        }

        bool TableElement::StructureEquals(const std::vector<TableColumn>& a,
                                           const std::vector<TableColumn>& b) noexcept {
            if (a.size() != b.size()) {
                return false;
            }
            for (std::size_t i = 0; i < a.size(); ++i) {
                if (a[i].id != b[i].id || a[i].header != b[i].header ||
                    a[i].align != b[i].align) {
                    return false;
                }
            }
            return true;
        }

        float TableElement::ColumnWidth(std::size_t index) const noexcept {
            if (index < resolved_widths_.size()) {
                return resolved_widths_[index];
            }
            if (index < cols_.size()) {
                return cols_[index].width;  // pre-Arrange fallback
            }
            return 0.0f;
        }

        Align TableElement::header_align(std::size_t i) const noexcept {
            // batch26 P0 (user: "they are all left aligned, so why is one right
            // aligned and another left aligned"):
            // header and data share ONE alignment source - the column's own
            // TableColumn::align. The old R5 blanket Start aligned every
            // caption left while numeric cells stayed right. The padding is
            // identical on both paths (kColumnInset on each side, see
            // RenderCore), so an End header ends on the same right edge as the
            // data without touching the column boundary.
            if (i >= cols_.size()) {
                return Align::Start;  // defensive: out-of-range
            }
            return cols_[i].align;
        }

        float TableElement::ColumnPhysicalX(std::size_t index) const noexcept {
            const std::size_t n = resolved_widths_.size();
            if (index >= n) {
                return bounds_.x;
            }
            if (!I18n::Instance().IsRtl()) {
                float x = bounds_.x;
                for (std::size_t k = 0; k < index; ++k) {
                    x += resolved_widths_[k];
                }
                return x;
            }
            float x = bounds_.x + bounds_.w;
            for (std::size_t k = 0; k <= index; ++k) {
                x -= resolved_widths_[k];
            }
            return x;
        }

        void TableElement::ResolveNaturalWidths() {
            const std::size_t n = cols_.size();
            if (n == 0) {
                natural_widths_.clear();
                natural_valid_ = false;
                natural_gen_ = row_gen_;
                return;
            }
            // Content unchanged (same rows, same columns): the measured widths
            // are still exact - never re-measure on a resize or a snapshot
            // tick that re-sends the same payload.
            if (natural_valid_ && natural_gen_ == row_gen_ &&
                natural_widths_.size() == n) {
                return;
            }
            // batch37b: keep the widths resolved for this column set. Live
            // cell values (and a client appear/disappear) must not resize
            // columns - that flickered the right-side columns on every
            // refresh. batch37e: but a measurement taken while the table was
            // still EMPTY is header-only; the first row population must
            // re-measure or every cell is clipped ("column widths are wrong").
            if (natural_frozen_ && natural_widths_.size() == n &&
                natural_rows_ != 0) {
                return;
            }
            natural_widths_.assign(n, 0.0f);
            const I18n& i18n = I18n::Instance();
            for (std::size_t i = 0; i < n; ++i) {
                float widest =
                    MeasureText(i18n.T(cols_[i].header), FontToken::Small,
                                kUnboundedWidth)
                        .w;
                for (const TableRow& row : rows_) {
                    if (i >= row.cells.size()) {
                        continue;
                    }
                    const float w =
                        MeasureText(row.cells[i], FontToken::Body,
                                    kUnboundedWidth)
                            .w;
                    if (w > widest) {
                        widest = w;
                    }
                }
                natural_widths_[i] = widest + 2.0f * kColumnInset;
            }
            natural_valid_ = true;
            natural_gen_ = row_gen_;
            natural_rows_ = rows_.size();
            natural_frozen_ = true;
        }

        void TableElement::ResolveWidths(float available_w) {
            const std::size_t n = cols_.size();
            resolved_widths_.assign(n, 0.0f);
            resolved_w_ = available_w;
            if (n == 0) {
                return;
            }
            const float avail = std::max(available_w, 0.0f);
            // A user drag stores absolute widths; renormalise them so the
            // columns still exactly fill the (possibly re-sized) table.
            if (user_resized_ && user_widths_.size() == n) {
                float sum = 0.0f;
                for (float w : user_widths_) {
                    sum += std::max(w, 0.0f);
                }
                if (sum > 0.0f) {
                    for (std::size_t i = 0; i < n; ++i) {
                        resolved_widths_[i] =
                            avail * std::max(user_widths_[i], 0.0f) / sum;
                    }
                    return;
                }
            }
            // Default: `TableColumn::width` is a weight; scale the base widths
            // so their sum is the available width (proportional fill).
            float base_sum = 0.0f;
            for (const TableColumn& c : cols_) {
                base_sum += std::max(c.width, 0.0f);
            }
            bool any_auto = false;
            for (const TableColumn& c : cols_) {
                any_auto = any_auto || c.auto_width;
            }
            if (any_auto) {
                // batch29: content-driven widths. Every auto column starts at
                // its measured content width (never narrower - the cell text
                // is not clipped by the layout), then the leftover width is
                // spread proportionally so the table still fills exactly.
                // When the content needs MORE than the available width the
                // surplus is taken from the non-first columns only (the first
                // column keeps its readable width), never below a small floor.
                ResolveNaturalWidths();
                float natural_sum = 0.0f;
                for (std::size_t i = 0; i < n; ++i) {
                    resolved_widths_[i] =
                        i < natural_widths_.size()
                            ? std::max(natural_widths_[i], 1.0f)
                            : std::max(cols_[i].width, 1.0f);
                    natural_sum += resolved_widths_[i];
                }
                if (natural_sum <= 0.0f) {
                    const float each = avail / static_cast<float>(n);
                    for (std::size_t i = 0; i < n; ++i) {
                        resolved_widths_[i] = each;
                    }
                    return;
                }
                if (natural_sum <= avail) {
                    // batch37e (user: "the column widths are wrong"): every
                    // column fits its content; the surplus goes to the LAST
                    // column only. Spreading it proportionally to the natural
                    // widths inflated every column (the MAC column grew from
                    // 150 to ~260 px) and left dead space inside each cell.
                    const float extra = avail - natural_sum;
                    const float each = extra / static_cast<float>(n);
                    for (std::size_t i = 0; i < n; ++i) {
                        resolved_widths_[i] += each;
                    }
                    ApplyColumnCaps();
                    return;
                }
                // Overflow: compress the non-first columns proportionally to
                // what they can give up, keeping the first column intact.
                float shrinkable = 0.0f;
                for (std::size_t i = 1; i < n; ++i) {
                    shrinkable += std::max(resolved_widths_[i] - 1.0f, 0.0f);
                }
                float need = natural_sum - avail;
                if (shrinkable > 0.0f && need > 0.0f) {
                    const float take = std::min(need, shrinkable);
                    for (std::size_t i = 1; i < n; ++i) {
                        const float give = std::max(resolved_widths_[i] - 1.0f,
                                                    0.0f);
                        resolved_widths_[i] -= take * give / shrinkable;
                    }
                    need -= take;
                }
                if (need > 0.0f) {
                    // Even the first column has to give: scale everything down
                    // proportionally (a genuinely too-narrow window).
                    const float scale = avail / std::max(natural_sum, 1.0f);
                    for (std::size_t i = 0; i < n; ++i) {
                        resolved_widths_[i] =
                            std::max(resolved_widths_[i] * scale, 1.0f);
                    }
                }
                ApplyColumnCaps();
                return;
            }
            if (base_sum <= 0.0f) {
                const float each = avail / static_cast<float>(n);
                for (std::size_t i = 0; i < n; ++i) {
                    resolved_widths_[i] = each;
                }
                return;
            }
            for (std::size_t i = 0; i < n; ++i) {
                resolved_widths_[i] =
                    avail * std::max(cols_[i].width, 0.0f) / base_sum;
            }
            // R4b: optional per-column `max_width` cap. Clamp every capped
            // column to its cap and re-distribute the released width to the
            // un-capped columns by weight, iterating until nothing changes -
            // the table keeps filling the available width exactly and the
            // proportions of the surviving columns are still weight-driven.
            ApplyColumnCaps();
        }

        /// batch27/batch29 bridge: the content-driven (`auto_width`) path used
        /// to `return` before the cap pass, so a `max_width` column was free to
        /// grow past its cap (a 3-char "tcp" column ended up as wide as a full
        /// IPv4 one). Both resolution strategies now finish here.
        void TableElement::ApplyColumnCaps() {
            const std::size_t n = cols_.size();
            if (cols_.empty()) {
                return;
            }
            for (int pass = 0; pass < static_cast<int>(n) + 4; ++pass) {
                float released = 0.0f;
                for (std::size_t i = 0; i < n; ++i) {
                    const float cap = cols_[i].max_width;
                    if (cap > 0.0f && resolved_widths_[i] > cap) {
                        released += resolved_widths_[i] - cap;
                        resolved_widths_[i] = cap;
                    }
                }
                if (released <= 0.001f) {
                    break;
                }
                float free_weight = 0.0f;
                for (std::size_t i = 0; i < n; ++i) {
                    const float cap = cols_[i].max_width;
                    const bool capped = cap > 0.0f && resolved_widths_[i] >= cap;
                    if (!capped) {
                        free_weight += std::max(cols_[i].width, 0.0f);
                    }
                }
                if (free_weight <= 0.0f) {
                    // Every active column hit its cap: nothing left to
                    // absorb the surplus, so the table simply cannot fill
                    // beyond the caps - redistribute to keep the total.
                    float total = 0.0f;
                    for (std::size_t i = 0; i < n; ++i) {
                        total += resolved_widths_[i];
                    }
                    if (total <= 0.0f) {
                        break;
                    }
                    for (std::size_t i = 0; i < n; ++i) {
                        resolved_widths_[i] +=
                            released * resolved_widths_[i] / total;
                    }
                    break;
                }
                for (std::size_t i = 0; i < n; ++i) {
                    const float cap = cols_[i].max_width;
                    const bool capped = cap > 0.0f && resolved_widths_[i] >= cap;
                    if (!capped) {
                        resolved_widths_[i] +=
                            released * std::max(cols_[i].width, 0.0f) / free_weight;
                    }
                }
            }
        }

        void TableElement::SetColumnWidthsForTest(std::vector<float> widths) {
            if (widths.size() != cols_.size() || cols_.empty()) {
                return;
            }
            user_widths_ = std::move(widths);
            user_resized_ = true;
            // Re-resolve immediately with the current arranged width so the
            // effect is observable without a real re-arrange; the ArrangeCore
            // width cache is refreshed inside ResolveWidths (resolved_w_).
            ResolveWidths(bounds_.w);
            InvalidateLayout();
        }

        void TableElement::SetColumnWidthForTest(std::size_t index, float width) {
            if (index >= cols_.size()) {
                return;
            }
            if (user_widths_.size() != cols_.size()) {
                // Seed from the currently resolved widths so untouched columns
                // keep their proportions (mirrors a user grab of one boundary).
                user_widths_ = resolved_widths_;
                if (user_widths_.size() != cols_.size()) {
                    user_widths_.assign(cols_.size(), 0.0f);
                }
            }
            user_widths_[index] = std::max(width, 0.0f);
            user_resized_ = true;
            ResolveWidths(bounds_.w);
            InvalidateLayout();
        }

        int TableElement::BoundaryAt(float x) const noexcept {
            if (cols_.size() < 2 || resolved_widths_.size() != cols_.size()) {
                return -1;
            }
            // batch19 R4-P2: boundaries follow the mirrored column order.
            const bool rtl = I18n::Instance().IsRtl();
            for (std::size_t i = 0; i + 1 < cols_.size(); ++i) {
                const float bx = rtl
                                     ? ColumnPhysicalX(i)
                                     : ColumnPhysicalX(i) + resolved_widths_[i];
                if (std::fabs(x - bx) <= kColumnResizeGrab) {
                    return static_cast<int>(i);
                }
            }
            return -1;
        }

        CursorKind TableElement::cursor_hint(Point p) const noexcept {
            // batch18 U2: a boundary drag owns the cursor until mouse-up (the
            // window's capture branch also resolves through here, so the
            // hint survives the pointer leaving the header band); otherwise
            // the header band over a column boundary - the exact same
            // kColumnResizeGrab slop as the click-grab hit - requests the
            // horizontal-resize cursor. Pure read: no state, no invalidation.
            if (resizing_) {
                return CursorKind::SizeWE;
            }
            if (p.y >= bounds_.y && p.y < bounds_.y + kTableHeaderH &&
                BoundaryAt(p.x) >= 0) {
                return CursorKind::SizeWE;
            }
            // batch33 spec D tail: a table whose rows navigate must show the
            // hand over a data row (the header band stays an arrow: it is not
            // a row and only its boundaries are draggable).
            if (on_row_click && !rows_.empty() && bounds_.Contains(p) &&
                p.y >= bounds_.y + kTableHeaderH) {
                const float rel = p.y - (bounds_.y + kTableHeaderH) + offset_;
                if (rel >= 0.0f &&
                    static_cast<std::size_t>(rel / kTableRowH) < rows_.size()) {
                    return CursorKind::Hand;
                }
            }
            return CursorKind::Arrow;
        }

        void TableElement::ApplyResize(float pointer_x) {
            if (!resizing_ || resize_col_ + 1 >= resolved_widths_.size()) {
                return;
            }
            if (user_widths_.size() != cols_.size()) {
                user_widths_ = resolved_widths_;
            }
            const float total = resize_start_left_ + resize_start_right_;
            const float min_w = std::min(kMinColumnW, total * 0.5f);
            // batch19 R4-P2: under RTL the pointer delta mirrors with the
            // column order (dragging left grows logical column i).
            float delta = pointer_x - resize_start_x_;
            if (I18n::Instance().IsRtl()) {
                delta = -delta;
            }
            float left = resize_start_left_ + delta;
            left = std::min(std::max(left, min_w), total - min_w);
            user_widths_[resize_col_] = left;
            user_widths_[resize_col_ + 1] = total - left;
            user_resized_ = true;
            ResolveWidths(bounds_.w);
        }

        void TableElement::AutoFitColumn(std::size_t index) {
            const std::size_t n = cols_.size();
            if (index >= n || bounds_.w <= 0.0f) {
                return;
            }
            ResolveNaturalWidths();
            if (index >= natural_widths_.size() ||
                resolved_widths_.size() != n) {
                return;
            }
            const float avail = std::max(bounds_.w, 1.0f);
            float want = std::max(natural_widths_[index], kMinColumnW);
            const float cap = cols_[index].max_width;
            if (cap > 0.0f) {
                want = std::min(want, cap);
            }
            const float reserve =
                n > 1 ? kMinColumnW * static_cast<float>(n - 1) : 0.0f;
            want = std::min(want, std::max(avail - reserve, kMinColumnW));
            // Seed from the current resolved widths so untouched columns keep
            // their proportions, then give the fitted column its content width
            // and rescale the rest into the remaining space.
            if (user_widths_.size() != n) {
                user_widths_ = resolved_widths_;
            }
            if (user_widths_.size() != n) {
                user_widths_.assign(n, 0.0f);
            }
            float others_old = 0.0f;
            for (std::size_t i = 0; i < n; ++i) {
                if (i != index) {
                    others_old += std::max(resolved_widths_[i], 0.0f);
                }
            }
            const float others_new = std::max(avail - want, 0.0f);
            for (std::size_t i = 0; i < n; ++i) {
                if (i == index) {
                    continue;
                }
                user_widths_[i] =
                    others_old > 0.0f
                        ? resolved_widths_[i] * others_new / others_old
                        : others_new / static_cast<float>(n > 1 ? n - 1 : 1);
            }
            user_widths_[index] = want;
            user_resized_ = true;
            ResolveWidths(avail);
            ++content_rev;
            InvalidateLayout();
        }

        bool TableElement::OnMouseDoubleClick(Point p) {
            // Standard list-view gesture: double-click the divider between two
            // header captions to fit the LEFT column to its content. The band
            // matches the drag hit zone (BoundaryAt) so both gestures agree.
            if (cols_.size() < 2 || resolved_widths_.size() != cols_.size()) {
                return false;
            }
            if (p.y < bounds_.y || p.y >= bounds_.y + kTableHeaderH) {
                return false;
            }
            const int boundary = BoundaryAt(p.x);
            if (boundary < 0) {
                return false;
            }
            AutoFitColumn(static_cast<std::size_t>(boundary));
            return true;
        }

        void TableElement::SetRows(std::vector<TableRow> rows) {
            ++set_rows_calls_;  // M10-1 seam: counts entries incl. short-circuits
            if (rows == rows_) {
                return;
            }
            rows_ = std::move(rows);
            // M3: a real data replacement invalidates every cell memo (the
            // row-major grid now describes different text). The equal-payload
            // short-circuit above keeps a 500 ms snapshot tick from paying for
            // this - it returns before the bump.
            ++row_gen_;
            cell_memos_.assign(rows_.size() * cols_.size(), CellMemo{});
            const float before_offset = offset_;
            if (offset_ > 0.0f) {
                const float max_offset = std::max(0.0f, content_height() - view_h_);
                offset_ = std::min(offset_, max_offset);
            }
            const bool offset_moved = offset_ != before_offset;
            // R4c: a shrunk dataset can leave the hovered row out of range
            // (RowAtPointer/render both guard against it, but the stale index
            // would resurrect on a later SetRows grow); clear it explicitly.
            if (hover_row_ >= static_cast<int>(rows_.size())) {
                hover_row_ = -1;
            }
            // batch72: an offset CLAMP moves every row under a stationary
            // pointer. Clearing only an out-of-RANGE index left the
            // highlight (and the row-action zones) on a row the pointer is
            // no longer over. Re-derive from the last pointer whenever the
            // offset actually moved.
            if (offset_moved) {
                RecomputeHoverRow();
            }
            ++content_rev;
            // batch37b: a data-only refresh with the same row count and stable
            // (frozen) content widths does not move any geometry - repaint the
            // table locally instead of invalidating the layout. The old
            // unconditional InvalidateLayout() re-arranged the whole page at
            // the dashboard refresh rate (~3/s) and produced 9-17 ms frames
            // (user: stutter).
            bool any_auto = false;
            for (const TableColumn& c : cols_) {
                any_auto = any_auto || c.auto_width;
            }
            const bool widths_stable = !any_auto || natural_frozen_;
            const bool first_population =
                any_auto && natural_rows_ == 0 && !rows_.empty();
            // batch37e: a row-count shrink can clamp the internal scroll
            // offset; every row moves then, so a whole-table layout (and
            // therefore a full table repaint) is required. Without it only the
            // hovered row band repainted and the old rows stayed visible.
            if (!widths_stable || first_population || offset_moved) {
                if (!widths_stable || first_population) {
                    // the first arrange can run before any row exists; that
                    // header-only measurement must re-arm when rows arrive.
                    natural_frozen_ = false;
                }
                InvalidateLayout();
            }
        }

        void TableElement::RecomputeHoverRow() noexcept {
            if (!has_pointer_ || rows_.empty()) {
                return;
            }
            const float rel =
                last_pointer_.y - (bounds_.y + kTableHeaderH) + offset_;
            int row = -1;
            if (rel >= 0.0f) {
                const std::size_t index =
                    static_cast<std::size_t>(rel / kTableRowH);
                if (index < rows_.size()) {
                    row = static_cast<int>(index);
                }
            }
            if (row == hover_row_) {
                return;
            }
            hover_row_ = row;
            // U1-D3: the (moved) hover highlight is a repaint, not a layout.
            // The caller already invalidated the layout (scroll); bump
            // content_rev so the repaint follows. NOTE (W11/G3): this
            // scroll-time re-derive does NOT itself union the pre-scroll
            // band - only the window's hover path (DispatchHoverMove) does.
            // The scroll repaint region is not a hover concern anyway: the
            // window's wheel path repaints the container's whole box
            // (W11 batch9 R4c/A), so no pre/post union is needed here.
            // W11 batch10/F3: this bump is kept OUT of F3's scope on purpose -
            // only the mouse-hover bump (OnMouseMove) is removed. The wheel
            // path's repaint face is handled by the window itself (W11 batch9
            // R4c/A repaints the container's raw box), so this bump is no
            // longer a ghosting fallback; removing it is a separate perf item
            // (same tick-relayout shape as F3, wheel path).
            ++content_rev;
        }

        void TableElement::SetRowActions(std::vector<Str> action_labels) {
            actions_ = std::move(action_labels);
            ++content_rev;
        }

        bool TableElement::row_danger(std::size_t index) const noexcept {
            return index < rows_.size() && rows_[index].danger;
        }

        float TableElement::content_height() const noexcept {
            return kTableHeaderH + static_cast<float>(rows_.size()) * kTableRowH;
        }

        void TableElement::SetOffset(float offset) {
            const float max_offset = std::max(0.0f, content_height() - view_h_);
            offset_ = std::min(std::max(0.0f, offset), max_offset);
            // W11 batch9 (R4c/B1): refresh the visible slice IMMEDIATELY (pure
            // index bookkeeping, no measuring) so the repaint this scroll
            // triggers - and the hover band's slice guard - see the
            // post-scroll window at once instead of waiting for the next
            // Arrange. The memo/text-layout window itself is still rebuilt by
            // the next Measure (InvalidateLayout below).
            RecomputeVisibleSlice();
            // R4c: a scroll moves the content under a stationary pointer, so
            // the hovered row must be re-derived from the last pointer - the
            // highlight would otherwise stick to the pre-scroll data row.
            RecomputeHoverRow();
            InvalidateLayout();  // the memoised layout window rebuilds on Measure
        }

        bool TableElement::OnWheel(int delta) {
            if (delta == 0) {
                return false;
            }
            const float before = offset_;
            SetOffset(offset_ + (delta > 0 ? -WheelStepForDelta(delta)
                                           : WheelStepForDelta(delta)));
            // batch33 F: only claim the wheel when the table actually moved. At
            // the top/bottom edge (or with no overflow at all) the event must
            // bubble to the enclosing page ScrollView - the old unconditional
            // `return true` swallowed the whole-page scroll, which is why a
            // small window could not be scrolled past the table.
            return offset_ != before;
        }

        bool TableElement::OnKeyDown(uint32_t vk) {
            // batch33p (user: "no scrollbar - rely on the wheel and the arrow
            // keys"): the table scrolls from the keyboard with the wheel's
            // contract. Up/Down move one row (so a row's bottom edge stays
            // reachable), PageUp/PageDown one viewport, Home/End to the ends.
            const float row_h = kTableRowH;
            const float page =
                std::max(view_h_ - kTableHeaderH - row_h, row_h);
            const float before = offset_;
            switch (vk) {
                case kVkUp:
                    SetOffset(offset_ - row_h);
                    break;
                case kVkDown:
                    SetOffset(offset_ + row_h);
                    break;
                case kVkPrior:
                    SetOffset(offset_ - page);
                    break;
                case kVkNext:
                    SetOffset(offset_ + page);
                    break;
                case kVkHome:
                    SetOffset(0.0f);
                    break;
                case kVkEnd:
                    SetOffset(content_height());
                    break;
                default:
                    return false;
            }
            // Same edge contract as OnWheel: a key that cannot move the table
            // must bubble to the enclosing page viewport.
            return offset_ != before;
        }

        std::size_t TableElement::RowIndex(const std::string& row_id) const
            noexcept {
            for (std::size_t i = 0; i < rows_.size(); ++i) {
                if (rows_[i].row_id == row_id) {
                    return i;
                }
            }
            return std::string::npos;
        }

        bool TableElement::ScrollToRow(const std::string& row_id) {
            const std::size_t index = RowIndex(row_id);
            if (index == std::string::npos) {
                return false;
            }
            SetOffset(static_cast<float>(index) * kTableRowH);
            // The intent asks for a temporary "look here" highlight: reuse the
            // hover band (the same paint path, so it cannot drift).
            hover_row_ = static_cast<int>(index);
            ++content_rev;
            InvalidateLayout();
            return true;
        }

        bool TableElement::OnMouseRightUp(Point p) {
            if (!EffectivelyEnabled() || !bounds_.Contains(p)) {
                return false;
            }
            // The header band has no row: let the event bubble (the page's
            // menu is a row menu only).
            if (p.y < bounds_.y + kTableHeaderH) {
                return false;
            }
            const float rel = p.y - (bounds_.y + kTableHeaderH) + offset_;
            if (rel < 0.0f) {
                return false;
            }
            const std::size_t index =
                static_cast<std::size_t>(rel / kTableRowH);
            if (index >= rows_.size()) {
                return false;
            }
            if (!on_row_context) {
                return false;
            }
            on_row_context(rows_[index].row_id, p);
            return true;
        }

        bool TableElement::OpenContextMenuForKeyboard() {
            if (!EffectivelyEnabled() || rows_.empty() || !on_row_context) {
                return false;
            }
            // The first fully visible row is the one a keyboard user is
            // reading. Paint it with the pointer's hover band so the menu's
            // owner is unambiguous, then anchor the card under that row.
            const std::size_t row = first_row_;
            if (row >= rows_.size()) {
                return false;
            }
            hover_row_ = static_cast<int>(row);
            ++content_rev;
            const float row_top = bounds_.y + kTableHeaderH +
                                  (static_cast<float>(row) * kTableRowH) -
                                  offset_;
            const Point at{bounds_.x + bounds_.w - 8.0f, row_top + kTableRowH};
            on_row_context(rows_[row].row_id, at);
            return true;
        }

        std::wstring TableElement::tooltip_text(Point p) const {
            if (!EffectivelyEnabled() || !bounds_.Contains(p) ||
                p.y < bounds_.y + kTableHeaderH || rows_.empty() ||
                cols_.empty()) {
                return std::wstring();
            }
            const float rel =
                p.y - (bounds_.y + kTableHeaderH) + offset_;
            if (rel < 0.0f) {
                return std::wstring();
            }
            // batch228: `rel` already carries offset_, and offset_ IS
            // first_row_ * kTableRowH (RecomputeVisibleSlice). Adding
            // first_row_ on top counts the scroll twice, so every scrolled
            // row resolved to a row several screens further down: its memo
            // was never filled, and the tooltip came back empty. This is the
            // same double-count the hover band used to have (R4c/C above);
            // the hit paths (OnMouseMove/OnMouseRightUp) have always used
            // the single-count form.
            const std::size_t row = static_cast<std::size_t>(rel / kTableRowH);
            if (row >= rows_.size()) {
                return std::wstring();
            }
            for (std::size_t col = 0; col < cols_.size(); ++col) {
                const float x = ColumnPhysicalX(col);
                if (p.x < x || p.x >= x + ColumnWidth(col)) {
                    continue;
                }
                if (col >= rows_[row].cells.size()) {
                    return std::wstring();
                }
                const std::size_t index = row * cols_.size() + col;
                if (index >= cell_memos_.size() ||
                    !cell_memos_[index].shown_valid) {
                    // No measured text yet: the cell cannot be ellipsized, so
                    // an actionable table still explains what a click does.
                    if (on_row_click || on_row_context) {
                        return I18n::Instance().T(Str::CtxMenuRowHint);
                    }
                    return std::wstring();
                }
                const std::wstring& raw = rows_[row].cells[col];
                if (cell_memos_[index].shown != raw) {
                    return raw;  // painted with "...": show the full text
                }
                // batch33 spec D tail: an ellipsis-free cell in a table whose
                // rows are actionable must still explain what a click / right
                // click does, otherwise the menu stays undiscoverable.
                if (on_row_click || on_row_context) {
                    return I18n::Instance().T(Str::CtxMenuRowHint);
                }
                return std::wstring();
            }
            return std::wstring();
        }

        void TableElement::RecomputeVisibleSlice() noexcept {
            // W11 batch9 (R4c/B1): the slice bookkeeping extracted from
            // LayoutVisibleRows - recomputes first_row_/visible_rows_ from
            // view_h_ and offset_ ONLY, never any MeasureText/memo work
            // (SetOffset must not add measurements; the memo window rebuild
            // stays lazy in LayoutVisibleRows).
            const float body_h = std::max(0.0f, view_h_ - kTableHeaderH);
            if (rows_.empty() || cols_.empty() || body_h <= 0.0f) {
                first_row_ = 0;
                visible_rows_ = 0;
                return;
            }
            first_row_ = static_cast<std::size_t>(offset_ / kTableRowH);
            if (first_row_ >= rows_.size()) {
                first_row_ = rows_.size() - 1;
            }
            const std::size_t fitting =
                static_cast<std::size_t>(std::ceil(body_h / kTableRowH));
            std::size_t count = fitting + kTableOverscan;
            if (first_row_ + count > rows_.size()) {
                count = rows_.size() - first_row_;
            }
            visible_rows_ = count;
        }

        void TableElement::LayoutVisibleRows(float view_h) {
            view_h_ = view_h;  // the slice helper reads the member
            text_layouts_ = 0;
            // M3: resize the position-indexed memo grid up front. cell_memos_
            // is indexed r * cols_.size() + c, so a SetColumns that shrank the
            // column count (or a direct row/column growth before SetRows ran)
            // would otherwise index out of bounds; the guard is a no-op in the
            // common case where SetRows/SetColumns already rebuilt it.
            const std::size_t cell_count = rows_.size() * cols_.size();
            if (cell_memos_.size() < cell_count) {
                cell_memos_.assign(cell_count, CellMemo{});
            }
            // Headers are measured on every pass and never memoised: their
            // text comes from i18n, so a language switch must re-measure them
            // (and the count is at most the column count, which is tiny).
            for (std::size_t i = 0; i < cols_.size(); ++i) {
                (void)MeasureText(I18n::Instance().T(cols_[i].header),
                                  FontToken::BodyStrong, ColumnWidth(i));
                ++text_layouts_;
            }
            RecomputeVisibleSlice();
            if (visible_rows_ == 0) {
                // Nothing measurable: no rows/columns or no body height (the
                // helper already reset first_row_/visible_rows_).
                return;
            }

            // M3: the per-cell memo is only reusable while the row identity
            // (row_gen_) and the QUANTISED column widths are unchanged. The
            // quantised comparison is what makes this collapse the sub-pixel
            // width drift (the raw resolved widths move by <0.001 f per frame,
            // but their 0.25 px buckets do not). SetOffset deliberately does
            // not bump row_gen_, so scrolling only measures the rows the
            // window newly exposes.
            bool window_valid = row_gen_ == cached_gen_ &&
                                cached_col_widths_.size() == cols_.size() &&
                                resolved_widths_.size() == cols_.size();
            if (window_valid) {
                for (std::size_t i = 0; i < cols_.size(); ++i) {
                    if (QuantizeLayoutWidth(resolved_widths_[i]) !=
                        cached_col_widths_[i]) {
                        window_valid = false;
                        break;
                    }
                }
            }
            if (!window_valid) {
                // The gate failed: every memo is suspect (the columns moved or
                // the data changed), so drop them all and re-measure the whole
                // visible window from scratch.
                for (CellMemo& memo : cell_memos_) {
                    memo.valid = false;
                }
            }
            const std::size_t cols = cols_.size();
            for (std::size_t row = first_row_;
                 row < first_row_ + visible_rows_; ++row) {
                const TableRow& data = rows_[row];
                for (std::size_t col = 0; col < cols; ++col) {
                    CellMemo& memo = cell_memos_[row * cols + col];
                    if (window_valid && memo.valid) {
                        // Memo hit: the measured size is known, so no DWrite
                        // round-trip happens for this cell this frame.
                        ++text_layouts_;
                        continue;
                    }
                    const std::wstring cell =
                        (col < data.cells.size()) ? data.cells[col]
                                                  : std::wstring();
                    memo.size =
                        MeasureText(cell, FontToken::Body, ColumnWidth(col));
                    memo.shown_valid = false;  // re-derive at paint time
                    memo.valid = true;
                    ++text_layouts_;
                }
            }
            if (!window_valid) {
                // Record the generation and the exact quantised widths this
                // window was measured at, so the next pass can compare.
                cached_gen_ = row_gen_;
                cached_col_widths_.clear();
                cached_col_widths_.reserve(cols_.size());
                for (std::size_t i = 0; i < cols_.size(); ++i) {
                    cached_col_widths_.push_back(
                        i < resolved_widths_.size()
                            ? QuantizeLayoutWidth(resolved_widths_[i])
                            : 0.0f);
                }
            }
        }

        Size TableElement::MeasureCore(Size available) {
            view_h_ = available.h;
            // D5: resolve the proportional column widths from the available
            // width so cell text is measured against the real column width.
            ResolveWidths(available.w);
            LayoutVisibleRows(view_h_);
            // D5: report the sum of the base weights as the natural width so a
            // Stretch parent (StackPanel/ContentHost) expands the table to the
            // full available width; the arranged width then drives the
            // proportional split. A fixed parent that honours the desired width
            // still gets a sane natural size.
            float total_w = 0.0f;
            for (const TableColumn& column : cols_) {
                total_w += std::max(column.width, 0.0f);
            }
            return Size{total_w, content_height()};
        }

        void TableElement::ArrangeCore(Rect final_rect) {
            // The Element-level cache is keyed by the available size, so a new
            // viewport height re-runs MeasureCore (and LayoutVisibleRows).
            view_h_ = final_rect.h;
            // D5: the arranged width is the authoritative "available width"
            // (a Stretch parent overrides the natural measure). MeasureCore
            // already resolved for this size; only a genuine width change here
            // (e.g. a fixed-size parent) re-resolves + rebuilds the layouts.
            // batch37e: a row-count change also re-resolves (the first arrange
            // may have measured an empty table; rows that arrived later must
            // contribute their cell widths).
            bool any_auto = false;
            for (const TableColumn& column : cols_) {
                any_auto = any_auto || column.auto_width;
            }
            const bool first_population =
                any_auto && natural_rows_ == 0 && !rows_.empty();
            if (std::fabs(resolved_w_ - final_rect.w) > 0.001f ||
                first_population) {
                ResolveWidths(final_rect.w);
                LayoutVisibleRows(view_h_);
            }
        }

        Rect TableElement::invalidation_bounds() const noexcept {
            // batch17 P2-a (audit H2): while a column-boundary drag is live,
            // ApplyResize -> ResolveWidths re-lays EVERY row, so the only
            // correct repaint region is the whole table box - the hover band
            // below is a hover-only hint and would ghost the rest of the
            // table (the window's captured-drag path reads this value).
            if (resizing_) {
                return bounds_;
            }
            // M4-F2: a hover move only changes one row's highlight, so the
            // repaint region is that row band, not the whole table. W11/G3:
            // this reads the CURRENT hover_row_, so the window's hover path
            // (DispatchHoverMove) captures this value BEFORE OnMouseMove runs
            // and again after, then invalidates the union - both the old and
            // the new strip clear (no hover ghost). The band is a hover
            // repaint hint, NOT the scroll surface: the window's wheel path
            // repaints the scrolling container's whole box (W11 batch9 R4c/A),
            // so it never reads this value for a scroll. Any other state
            // change (row set, columns, resize) falls back to the whole box:
            // returning the full bounds is always safe - the cull/render
            // path only ever shrinks the dirty region when it is provably
            // complete.
            if (hover_row_ < 0 || rows_.empty()) {
                return bounds_;
            }
            const std::size_t row = static_cast<std::size_t>(hover_row_);
            // The visible slice ([first_row_, first_row_ + visible_rows_)) is
            // laid out top-to-bottom starting below the header; an out-of-
            // window row cannot have highlight pixels, so treat it as "no
            // hover" rather than inventing geometry. (SetOffset refreshes the
            // slice immediately, W11 batch9 R4c/B1.)
            if (row < first_row_ || row >= first_row_ + visible_rows_) {
                return bounds_;
            }
            // W11 batch9 (R4c/C): absolute screen geometry - the same formula
            // RenderCore lays the row out with (bounds_.y + 40 + row*28 -
            // offset_). The previous (row - first_row_) * 28 form drifted up
            // by first_row_*28 once the table had been scrolled + arranged,
            // so the band missed the painted pixels.
            const float row_y =
                bounds_.y + kTableHeaderH +
                static_cast<float>(row) * kTableRowH - offset_;
            // The hover strip is drawn only inside the clipped body area; clip
            // the band so a partially scrolled row does not extend the dirty
            // rect past the table (the header+clip edge is already covered by
            // the table box in the "else" branch).
            const float top = std::max(row_y, bounds_.y + kTableHeaderH);
            const float bottom = std::min(row_y + kTableRowH, bounds_.y + bounds_.h);
            if (bottom <= top) {
                return bounds_;
            }
            return Rect{bounds_.x, top, bounds_.w, bottom - top};
        }

        bool TableElement::OnMouseMove(Point p) {
            // R4c: remember the last pointer so SetOffset can re-derive the
            // hovered row after a scroll (no new mouse motion required).
            last_pointer_ = p;
            has_pointer_ = true;
            // D5: a header-boundary drag owns the pointer until mouse-up.
            if (resizing_) {
                ApplyResize(p.x);
                return true;
            }
            int row = -1;
            if (p.y >= bounds_.y + kTableHeaderH) {
                const float rel = p.y - (bounds_.y + kTableHeaderH) + offset_;
                if (rel >= 0.0f) {
                    const std::size_t index =
                        static_cast<std::size_t>(rel / kTableRowH);
                    if (index < rows_.size()) {
                        row = static_cast<int>(index);
                    }
                }
            }
            if (row == hover_row_) {
                return false;
            }
            hover_row_ = row;
            // W11 batch10/F3: a hover row change is a pure repaint. Report
            // "repaint needed" and let the window invalidate the old row
            // union new row immediately (DispatchHoverMove reads this return
            // value; U1-D3/W11-G3) - do NOT bump content_rev here: the global
            // UiContentEpoch gate in UiApp::Update would turn every row
            // change into a whole-tree RequestLayout + full-window repaint on
            // the next snapshot tick (~2 Hz during a sweep). See
            // logs/b10-final-spec.md.
            return true;
        }

        bool TableElement::OnMouseDown(Point p) {
            if (!EffectivelyEnabled()) {
                return false;
            }
            // D5: header band -> a boundary grab starts a column resize.
            if (p.y >= bounds_.y && p.y < bounds_.y + kTableHeaderH) {
                const int boundary = BoundaryAt(p.x);
                if (boundary >= 0) {
                    resizing_ = true;
                    resize_col_ = static_cast<std::size_t>(boundary);
                    resize_start_x_ = p.x;
                    resize_start_left_ = ColumnWidth(resize_col_);
                    resize_start_right_ = ColumnWidth(resize_col_ + 1);
                    return true;
                }
                return false;  // header, off a boundary: not a row click
            }
            if (p.y < bounds_.y + kTableHeaderH) {
                return false;
            }
            const float rel = p.y - (bounds_.y + kTableHeaderH) + offset_;
            if (rel < 0.0f) {
                return false;
            }
            const std::size_t index = static_cast<std::size_t>(rel / kTableRowH);
            if (index >= rows_.size()) {
                return false;
            }
            const TableRow& row = rows_[index];
            if (!actions_.empty()) {
                const float zone_w = kTableActionW * static_cast<float>(actions_.size());
                const bool rtl = I18n::Instance().IsRtl();
                const float zone_x =
                    rtl ? bounds_.x : bounds_.x + bounds_.w - zone_w;
                const bool in_zone = rtl ? (p.x <= zone_x + zone_w) : (p.x >= zone_x);
                if (in_zone) {
                    std::size_t action =
                        static_cast<std::size_t>((p.x - zone_x) / kTableActionW);
                    if (action >= actions_.size()) {
                        action = actions_.size() - 1;
                    }
                    if (on_row_action) {
                        on_row_action(row.row_id, action);
                    }
                    return true;
                }
            }
            if (on_row_click) {
                on_row_click(row.row_id);
            }
            return true;
        }

        bool TableElement::OnMouseUp(Point) {
            if (!resizing_) {
                return false;
            }
            resizing_ = false;
            return true;
        }

        // --- TextInputElement ------------------------------------------------

        TextInputElement::TextInputElement() {
            hit_transparent = false;
        }

        void TextInputElement::SetValue(std::wstring value) {
            if (value == value_) {
                return;
            }
            value_ = std::move(value);
            caret_ = value_.size();
            sel_anchor_ = caret_;  // collapse any selection
            undo_stack_.clear();
            redo_stack_.clear();
            last_word_click_ = {};
            caret_visible_ = true;  // editing resets the blink phase (S5.19)
            ++content_rev;
            InvalidateLayout();
            // Programmatic set: no on_changed (documented).
        }

        void TextInputElement::SetPlaceholder(std::wstring text) {
            if (placeholder_ == text) {
                return;
            }
            placeholder_ = std::move(text);
            ++content_rev;  // visual only
        }

        std::wstring TextInputElement::SelectedText() const {
            const std::size_t lo = std::min(caret_, sel_anchor_);
            const std::size_t hi = std::max(caret_, sel_anchor_);
            if (hi <= lo) {
                return std::wstring();
            }
            return value_.substr(lo, hi - lo);
        }

        void TextInputElement::DeleteSelection() {
            const std::size_t lo = std::min(caret_, sel_anchor_);
            const std::size_t hi = std::max(caret_, sel_anchor_);
            if (hi <= lo) {
                return;
            }
            PushUndo();
            value_.erase(lo, hi - lo);
            caret_ = lo;
            sel_anchor_ = caret_;
            caret_visible_ = true;
            ++content_rev;
            InvalidateLayout();
            if (on_changed) {
                on_changed();
            }
        }

        bool TextInputElement::CopySelectionToClipboard() {
            const std::wstring sel = SelectedText();
            if (sel.empty()) {
                return false;
            }
            // batch285: report the write result; the old unconditional `true`
            // told the window a copy succeeded when nothing was written.
            return SetClipboardText(sel);
        }

        bool TextInputElement::CutSelectionToClipboard() {
            const std::wstring sel = SelectedText();
            if (sel.empty()) {
                return false;
            }
            // batch285: never destroy text that did not reach the clipboard.
            // The old order (write, delete, report success) lost the selection
            // whenever the clipboard was busy.
            if (!SetClipboardText(sel)) {
                return false;
            }
            DeleteSelection();
            return true;
        }

        PasteResult TextInputElement::PasteFromClipboard() {
            // batch288: the read is failure-aware now. Empty text is a real
            // "nothing to paste"; a false read means the clipboard was held
            // by another process and the window must report it instead of
            // looking like a no-op.
            std::wstring text;
            if (!console_log::ReadClipboardText(text)) {
                return PasteResult::Failed;
            }
            if (text.empty()) {
                return PasteResult::NothingToPaste;
            }
            InsertText(text);
            return PasteResult::Pasted;
        }

        bool TextInputElement::SelectAllText() {
            SetSelectionForTest(0, value_.size());
            return true;
        }
        void TextInputElement::InsertText(const std::wstring& text) {
            if (text.empty()) {
                return;
            }
            const std::size_t sel_lo = std::min(caret_, sel_anchor_);
            const std::size_t sel_hi = std::max(caret_, sel_anchor_);
            std::size_t sel_len = sel_hi - sel_lo;
            std::wstring filtered;
            filtered.reserve(text.size());
            for (wchar_t ch : text) {
                // batch113: keep every non-CONTROL character, not just ASCII.
                // This path is what PasteFromClipboard calls, and a clipboard
                // holds text the widget can already store: the IME commit path
                // (CommitComposition) inserts arbitrary Unicode, so the
                // ASCII-only filter here made "copy a CJK name from another
                // window, press Ctrl+V" silently paste NOTHING. The filter's
                // real job is dropping control characters (newlines/tabs from
                // a multi-line source), and that stays.
                if (ch >= 32 && ch != 127) {
                    filtered.push_back(ch);
                }
            }
            if (filtered.empty()) {
                return;
            }
            if (max_chars_ != 0) {
                const std::size_t used = value_.size() - sel_len;
                if (used >= max_chars_) {
                    return;
                }
                const std::size_t room = max_chars_ - used;
                if (filtered.size() > room) {
                    filtered.resize(room);
                }
            }
            PushUndo();
            if (sel_len > 0) {
                value_.erase(sel_lo, sel_len);
            }
            value_.insert(sel_lo, filtered);
            caret_ = sel_lo + filtered.size();
            sel_anchor_ = caret_;
            caret_visible_ = true;
            ++content_rev;
            InvalidateLayout();
            if (on_changed) {
                on_changed();
            }
        }

        void TextInputElement::InsertSpace() {
            const std::size_t sel_lo = std::min(caret_, sel_anchor_);
            const std::size_t sel_hi = std::max(caret_, sel_anchor_);
            const std::size_t sel_len = sel_hi - sel_lo;
            if (max_chars_ != 0 && value_.size() - sel_len >= max_chars_) {
                return;  // over the limit: no change, no event
            }
            PushUndo();
            if (sel_len > 0) {
                value_.erase(sel_lo, sel_len);
            }
            value_.insert(sel_lo, 1, L' ');
            caret_ = sel_lo + 1;
            sel_anchor_ = caret_;
            caret_visible_ = true;
            ++content_rev;
            InvalidateLayout();
            if (on_changed) {
                on_changed();
            }
        }

        bool TextInputElement::OnChar(wchar_t ch) {
            if (!EffectivelyEnabled() || ch < 32 || ch >= 127) {
                // Printable ASCII only on the raw WM_CHAR path; non-ASCII now
                // arrives through the IME commit path (batch24 P0-3), which
                // inserts any Unicode via CommitComposition.
                return false;
            }
            // R2: Space is inserted from OnKeyDown(VK_SPACE) so it works even
            // when the host loop does not translate VK_SPACE into a WM_CHAR
            // (a modal dialog can swallow it as default-button activation).
            // If the platform DOES translate it, the following WM_CHAR(0x20)
            // is swallowed here via the one-shot flag so the space inserts
            // exactly once. A direct OnChar(' ') (e.g. the debug type path)
            // with no preceding keydown still inserts normally.
            if (ch == L' ') {
                if (space_from_keydown_) {
                    space_from_keydown_ = false;
                    return true;  // already inserted on the keydown
                }
                InsertSpace();
                return true;
            }
            // D1 fix: replace the selection (if any) then insert at the caret,
            // not at the tail.
            const std::size_t sel_lo = std::min(caret_, sel_anchor_);
            const std::size_t sel_hi = std::max(caret_, sel_anchor_);
            const std::size_t sel_len = sel_hi - sel_lo;
            if (max_chars_ != 0 &&
                value_.size() - sel_len >= max_chars_) {
                return false;  // over the limit: rejected, no event
            }
            PushUndo();
            if (sel_len > 0) {
                value_.erase(sel_lo, sel_len);
            }
            value_.insert(sel_lo, 1, ch);
            caret_ = sel_lo + 1;
            sel_anchor_ = caret_;  // collapse any selection
            caret_visible_ = true;  // editing resets the blink phase (S5.19)
            ++content_rev;
            InvalidateLayout();
            if (on_changed) {
                on_changed();
            }
            return true;
        }

        bool TextInputElement::OnKeyDown(uint32_t vk) {
            if (!EffectivelyEnabled()) {
                return false;
            }
            // R2: Space is a printable character. Some host message loops do
            // not deliver WM_CHAR(0x20) for a modal dialog (the space can be
            // swallowed as a default-button activation), so insert it here on
            // the keydown; OnChar then ignores 0x20 so a platform that DOES
            // translate it cannot double-insert.
            if (vk == kVkSpace) {
                InsertSpace();
                space_from_keydown_ = true;  // swallow the paired WM_CHAR(0x20)
                return true;
            }
            if (vk == kVkBackspace) {
                // D1 fix: delete the selection, else the char before the caret.
                const std::size_t sel_lo = std::min(caret_, sel_anchor_);
                const std::size_t sel_hi = std::max(caret_, sel_anchor_);
                if (sel_hi > sel_lo) {
                    PushUndo();
                    value_.erase(sel_lo, sel_hi - sel_lo);
                    caret_ = sel_lo;
                    sel_anchor_ = caret_;
                    caret_visible_ = true;  // editing resets the blink phase
                    ++content_rev;
                    InvalidateLayout();
                    if (on_changed) {
                        on_changed();
                    }
                } else if (caret_ > 0) {
                    PushUndo();
                    value_.erase(caret_ - 1, 1);
                    --caret_;
                    sel_anchor_ = caret_;
                    caret_visible_ = true;  // editing resets the blink phase
                    ++content_rev;
                    InvalidateLayout();
                    if (on_changed) {
                        on_changed();
                    }
                }
                return true;
            }
            if (vk == kVkReturn) {
                if (on_submit) {
                    on_submit();  // exactly once per press
                }
                return true;
            }
            // G2: caret navigation keys (formerly the caret was tail-only).
            // batch19 R4-P2: the caret is logical; under RTL the physical
            // Left/Right and Home/End swap.
            const bool rtl = I18n::Instance().IsRtl();
            if (vk == kVkLeft) {
                if (rtl ? (caret_ < value_.size()) : (caret_ > 0)) {
                    caret_ += rtl ? 1 : -1;
                }
                sel_anchor_ = caret_;
                caret_visible_ = true;
                ++content_rev;
                return true;
            }
            if (vk == kVkRight) {
                if (rtl ? (caret_ > 0) : (caret_ < value_.size())) {
                    caret_ += rtl ? -1 : 1;
                }
                sel_anchor_ = caret_;
                caret_visible_ = true;
                ++content_rev;
                return true;
            }
            if (vk == kVkHome) {
                caret_ = rtl ? value_.size() : 0;
                sel_anchor_ = caret_;
                caret_visible_ = true;
                ++content_rev;
                return true;
            }
            if (vk == kVkEnd) {
                caret_ = rtl ? 0 : value_.size();
                sel_anchor_ = caret_;
                caret_visible_ = true;
                ++content_rev;
                return true;
            }
            if (vk == kVkDelete) {
                // OS Edit: Delete removes the selection first, otherwise the
                // character after the caret.
                const std::size_t sel_lo = std::min(caret_, sel_anchor_);
                const std::size_t sel_hi = std::max(caret_, sel_anchor_);
                if (sel_hi > sel_lo) {
                    PushUndo();
                    value_.erase(sel_lo, sel_hi - sel_lo);
                    caret_ = sel_lo;
                    sel_anchor_ = caret_;
                    caret_visible_ = true;
                    ++content_rev;
                    InvalidateLayout();
                    if (on_changed) {
                        on_changed();
                    }
                } else if (caret_ < value_.size()) {
                    PushUndo();
                    value_.erase(caret_, 1);
                    sel_anchor_ = caret_;
                    caret_visible_ = true;
                    ++content_rev;
                    InvalidateLayout();
                    if (on_changed) {
                        on_changed();
                    }
                }
                return true;
            }
            return false;
        }

        void TextInputElement::PushUndo() {
            EditSnapshot snap{value_, caret_, sel_anchor_};
            if (!undo_stack_.empty() &&
                undo_stack_.back().value == snap.value &&
                undo_stack_.back().caret == snap.caret &&
                undo_stack_.back().anchor == snap.anchor) {
                return;
            }
            undo_stack_.push_back(std::move(snap));
            if (undo_stack_.size() > 100) {
                undo_stack_.erase(undo_stack_.begin());
            }
            redo_stack_.clear();
        }

        bool TextInputElement::UndoEdit() {
            if (undo_stack_.empty()) {
                return false;
            }
            redo_stack_.push_back(EditSnapshot{value_, caret_, sel_anchor_});
            EditSnapshot snap = std::move(undo_stack_.back());
            undo_stack_.pop_back();
            value_ = std::move(snap.value);
            caret_ = std::min(snap.caret, value_.size());
            sel_anchor_ = std::min(snap.anchor, value_.size());
            caret_visible_ = true;
            ++content_rev;
            InvalidateLayout();
            if (on_changed) {
                on_changed();
            }
            return true;
        }

        bool TextInputElement::RedoEdit() {
            if (redo_stack_.empty()) {
                return false;
            }
            undo_stack_.push_back(EditSnapshot{value_, caret_, sel_anchor_});
            EditSnapshot snap = std::move(redo_stack_.back());
            redo_stack_.pop_back();
            value_ = std::move(snap.value);
            caret_ = std::min(snap.caret, value_.size());
            sel_anchor_ = std::min(snap.anchor, value_.size());
            caret_visible_ = true;
            ++content_rev;
            InvalidateLayout();
            if (on_changed) {
                on_changed();
            }
            return true;
        }

        void TextInputElement::ExtendSelectionTo(Point p) {
            caret_ = CaretFromX(p.x);
            caret_visible_ = true;
            ++content_rev;
        }
        void TextInputElement::EnsurePrefixWidths() const {
            // M7 (batch3): the cache is keyed by the WHOLE value string (not
            // its size) plus the measure-hook generation, so every write path
            // - programmatic SetValue, paste, insert, backspace, an
            // equal-length selection replacement - rebuilds, and a swapped
            // measure hook can never leave stale widths behind.
            if (prefix_src_ == value_ &&
                prefix_w_.size() == value_.size() + 1 &&
                prefix_gen_ == TextMeasureGeneration()) {
                return;
            }
            const std::size_t n = value_.size();
            prefix_w_.resize(n + 1);
            prefix_w_[0] = 0.0f;
            for (std::size_t i = 1; i <= n; ++i) {
                // Same measure call (same text/font/width) as the original
                // per-event scan: the cache changes WHEN prefixes are
                // measured, never HOW - the caret values stay bit-identical.
                prefix_w_[i] = MeasureText(value_.substr(0, i),
                                           FontToken::Body, kUnboundedWidth)
                                   .w;
            }
            prefix_src_ = value_;
            prefix_gen_ = TextMeasureGeneration();
        }

        std::size_t TextInputElement::CaretFromX(float x) const noexcept {
            // G2: map a click x (logical) to the nearest inter-character
            // boundary using the same text metric as the renderer. The text
            // starts at bounds_.x + 6 (the render inset in RenderCore).
            // batch19 R4-P2: the caret is logical; the physical click x maps
            // through the active reading direction. LTR: text starts at the
            // left inset and boundary i sits at origin + prefix_w[i]; RTL: the
            // text starts at the RIGHT inset and boundary i sits
            // origin_right - prefix_w[i].
            const bool rtl = I18n::Instance().IsRtl();
            const float origin = rtl ? (bounds_.x + bounds_.w - 6.0f)
                                     : (bounds_.x + 6.0f);
            if (rtl) {
                if (x >= origin) {
                    return 0;  // at/right of the logical start
                }
            } else if (x <= origin) {
                return 0;
            }
            EnsurePrefixWidths();  // M7: 0 measurements on unchanged input
            std::size_t best = rtl ? value_.size() : 0;
            float best_dist = std::fabs(x - (rtl ? (origin - prefix_w_[value_.size()])
                                                 : origin));
            for (std::size_t i = 1; i <= value_.size(); ++i) {
                const float boundary =
                    rtl ? (origin - prefix_w_[i]) : (origin + prefix_w_[i]);
                const float dist = std::fabs(x - boundary);
                if (dist < best_dist) {
                    best_dist = dist;
                    best = i;
                }
            }
            return best;
        }

        namespace {
            bool IsWordChar(wchar_t c) {
                return std::iswalnum(static_cast<std::wint_t>(c)) != 0 ||
                       c == L'_';
            }
            std::size_t PrevWordBoundary(const std::wstring& v, std::size_t i) {
                while (i > 0 && !IsWordChar(v[i - 1])) {
                    --i;
                }
                while (i > 0 && IsWordChar(v[i - 1])) {
                    --i;
                }
                return i;
            }
            std::size_t NextWordBoundary(const std::wstring& v, std::size_t i) {
                const std::size_t n = v.size();
                while (i < n && IsWordChar(v[i])) {
                    ++i;
                }
                while (i < n && !IsWordChar(v[i])) {
                    ++i;
                }
                return i;
            }
        }  // namespace

        bool TextInputElement::ExtendCaretKey(uint32_t vk, bool by_word) {
            if (!EffectivelyEnabled()) {
                return false;
            }
            constexpr uint32_t kLeft = 0x25;
            constexpr uint32_t kRight = 0x27;
            constexpr uint32_t kHome = 0x24;
            constexpr uint32_t kEnd = 0x23;
            const bool rtl = I18n::Instance().IsRtl();
            std::size_t next = caret_;
            bool handled = false;
            if (vk == kLeft || vk == kRight) {
                const int dir =
                    (vk == kRight) ? (rtl ? -1 : 1) : (rtl ? 1 : -1);
                if (by_word) {
                    next = dir < 0 ? PrevWordBoundary(value_, caret_)
                                   : NextWordBoundary(value_, caret_);
                } else {
                    const long moved = static_cast<long>(caret_) + dir;
                    next = moved < 0
                               ? 0
                               : std::min(static_cast<std::size_t>(moved),
                                          value_.size());
                }
                handled = true;
            } else if (vk == kHome) {
                next = rtl ? value_.size() : 0;
                handled = true;
            } else if (vk == kEnd) {
                next = rtl ? 0 : value_.size();
                handled = true;
            }
            if (!handled) {
                return false;
            }
            if (next != caret_) {
                caret_ = next;
                caret_visible_ = true;
                ++content_rev;
            }
            return true;  // Shift+nav is consumed even at the edge
        }

        bool TextInputElement::MoveCaretWord(uint32_t vk, bool extend) {
            if (!EffectivelyEnabled()) {
                return false;
            }
            constexpr uint32_t kLeft = 0x25;
            constexpr uint32_t kRight = 0x27;
            if (vk != kLeft && vk != kRight) {
                return false;
            }
            const bool rtl = I18n::Instance().IsRtl();
            const int dir = (vk == kRight) ? (rtl ? -1 : 1) : (rtl ? 1 : -1);
            const std::size_t next =
                dir < 0 ? PrevWordBoundary(value_, caret_)
                        : NextWordBoundary(value_, caret_);
            if (next == caret_) {
                return true;
            }
            caret_ = next;
            if (!extend) {
                sel_anchor_ = caret_;
            }
            caret_visible_ = true;
            ++content_rev;
            return true;
        }

        bool TextInputElement::DeleteWord(uint32_t vk) {
            if (!EffectivelyEnabled()) {
                return false;
            }
            constexpr uint32_t kBack = 0x08;
            constexpr uint32_t kDelete = 0x2E;
            if (vk != kBack && vk != kDelete) {
                return false;
            }
            const std::size_t lo = std::min(caret_, sel_anchor_);
            const std::size_t hi = std::max(caret_, sel_anchor_);
            // batch102: PushUndo() must come AFTER deciding that something is
            // actually deleted. It records a snapshot AND clears redo_stack_, so
            // calling it first meant a no-op Ctrl+Backspace at the start of the
            // text (or Ctrl+Delete at the end) destroyed the user's redo history
            // and fabricated an empty undo entry. The three real deletion paths
            // below each push their own snapshot.
            if (hi > lo) {
                PushUndo();
                value_.erase(lo, hi - lo);
                caret_ = lo;
            } else if (vk == kBack) {
                const std::size_t start = PrevWordBoundary(value_, caret_);
                if (start == caret_) {
                    return true;
                }
                PushUndo();
                value_.erase(start, caret_ - start);
                caret_ = start;
            } else {
                const std::size_t end = NextWordBoundary(value_, caret_);
                if (end == caret_) {
                    return true;
                }
                PushUndo();
                value_.erase(caret_, end - caret_);
            }
            sel_anchor_ = caret_;
            caret_visible_ = true;
            ++content_rev;
            InvalidateLayout();
            if (on_changed) {
                on_changed();
            }
            return true;
        }

        bool TextInputElement::OnMouseDoubleClick(Point p) {
            if (!EffectivelyEnabled()) {
                return false;
            }
            const std::size_t pos = CaretFromX(p.x);
            std::size_t lo = pos;
            std::size_t hi = pos;
            if (pos < value_.size() && IsWordChar(value_[pos])) {
                while (lo > 0 && IsWordChar(value_[lo - 1])) {
                    --lo;
                }
                while (hi < value_.size() && IsWordChar(value_[hi])) {
                    ++hi;
                }
            } else if (pos > 0 && IsWordChar(value_[pos - 1])) {
                while (lo > 0 && IsWordChar(value_[lo - 1])) {
                    --lo;
                }
                hi = pos;
                while (hi < value_.size() && IsWordChar(value_[hi])) {
                    ++hi;
                }
            } else if (pos < value_.size()) {
                hi = pos + 1;
            } else if (pos > 0) {
                lo = pos - 1;
            }
            sel_anchor_ = lo;
            caret_ = hi;
            dragging_ = false;
            caret_visible_ = true;
            last_word_click_ = std::chrono::steady_clock::now();
            last_word_click_pos_ = p;
            ++content_rev;
            return true;
        }
        bool TextInputElement::OnMouseDown(Point p) {
            if (!EffectivelyEnabled()) {
                return false;
            }
            const auto now = std::chrono::steady_clock::now();
            if (last_word_click_.time_since_epoch().count() != 0 &&
                now - last_word_click_ < std::chrono::milliseconds(500) &&
                std::fabs(p.x - last_word_click_pos_.x) < 4.0f &&
                std::fabs(p.y - last_word_click_pos_.y) < 4.0f) {
                // Triple click: select everything (OS Edit).
                sel_anchor_ = 0;
                caret_ = value_.size();
                dragging_ = false;
                caret_visible_ = true;
                last_word_click_ = {};
                ++content_rev;
                return true;
            }
            // G2: place the caret at the clicked character boundary and start
            // a drag selection from there.
            caret_ = CaretFromX(p.x);
            sel_anchor_ = caret_;
            dragging_ = true;
            caret_visible_ = true;  // a click brightens the caret immediately
            ++content_rev;
            return true;
        }

        bool TextInputElement::OnMouseMove(Point p) {
            if (!EffectivelyEnabled() || !dragging_) {
                return false;
            }
            const std::size_t next = CaretFromX(p.x);
            if (next == caret_) {
                return false;
            }
            caret_ = next;
            caret_visible_ = true;
            ++content_rev;
            return true;
        }

        bool TextInputElement::OnMouseUp(Point) {
            if (!dragging_) {
                return false;
            }
            dragging_ = false;
            ++content_rev;
            return true;
        }

        Size TextInputElement::MeasureCore(Size) {
            const Size text = MeasureText(value_, FontToken::Body, kUnboundedWidth);
            return Size{std::max(160.0f, text.w + 16.0f),
                        std::max(28.0f, text.h + 8.0f)};
        }

        // --- SelectElement ---------------------------------------------------

        namespace {
            /// batch33r (user: "the list renders wrong and the rows are wrong"):
            /// the visible domain a Select popup must stay inside. The popup is
            /// a TOP-LAYER surface - RenderOverlay paints it and HitTestOverlay
            /// hits it after every ancestor clip has been popped - so an
            /// enclosing ScrollView must NOT cap it. The wizard form lives in a
            /// 125 px scroll body: narrowing the domain to that body showed 3 of
            /// 5 adapters and pushed the top row over the closed trigger box.
            /// Only the window client (the topmost ancestor) constrains the
            /// list, which is exactly what paint and hit agree on.
            /// Degenerate ancestors are ignored (fail-open).
            Rect SelectVisibleDomain(const Element& element) noexcept {
                const Element* top = &element;
                while (top->parent() != nullptr) {
                    top = top->parent();
                }
                // A standalone control (no tree/window) has no known visible
                // domain: return an empty rect so PopupRect keeps the legacy
                // always-down geometry and never clamps against its own box.
                if (top == &element) {
                    return Rect{};
                }
                return top->bounds();
            }
        }  // namespace

        Rect SelectElement::PopupRect() const noexcept {
            const float item_h = kSelectItemH;
            const float list_w = (std::max)(bounds_.w, 160.0f);
            const float list_x = I18n::Instance().IsRtl()
                                     ? bounds_.x + bounds_.w - list_w
                                     : bounds_.x;
            const Rect domain = SelectVisibleDomain(*this);
            const bool has_domain = domain.w > 0.0f && domain.h > 0.0f;
            const float domain_top = has_domain ? domain.y : bounds_.y;
            const float domain_bottom = has_domain
                                            ? domain.y + domain.h
                                            : bounds_.y + bounds_.h +
                                                  item_h * static_cast<float>(
                                                      options_.size());
            const float below = domain_bottom - (bounds_.y + bounds_.h);
            const float above = bounds_.y - domain_top;
            // batch33f: CAP the list to what fits on the better side instead of
            // letting it grow and then clamping it back OVER the trigger box.
            // With 12 adapters the list was 336 px tall in a 281 px visible
            // card: the clamp put it on top of the closed box, so the user
            // could not see the current selection while picking another.
            const float room = (std::max)(below, above);
            std::size_t max_rows = options_.size();
            if (item_h > 0.0f && room > 0.0f) {
                const auto fits = static_cast<std::size_t>(room / item_h);
                max_rows = (std::min)(max_rows, fits);
            }
            // batch33f: never shrink below a usable window. In a small host
            // (a modal form, say) `room` can be under one row; capping to a
            // single row would hide every other option, so keep at least three
            // rows and let the clamp put the list inside the domain.
            const std::size_t min_rows =
                (std::min)(options_.size(), static_cast<std::size_t>(3));
            if (max_rows < min_rows) {
                max_rows = min_rows;
            }
            if (max_rows > kMaxPopupRows) {
                max_rows = kMaxPopupRows;
            }
            if (max_rows == 0) {
                max_rows = (std::min)(options_.size(),
                                      static_cast<std::size_t>(1));
            }
            popup_rows_ = max_rows;
            const std::size_t max_top =
                (options_.size() > max_rows) ? (options_.size() - max_rows) : 0;
            // batch68/71: PopupRect() is called from NINE places (paint, hit,
            // hover, tooltip, mouse), several of them BEFORE the paint of the
            // same frame. It therefore must be a pure geometry read: the only
            // state it may touch is the derived row-window CLAMP. The "bring
            // the selection into view" reveal is a decision, so it lives in
            // RevealSelectionNow(), which the selection/expand events call.
            // (batch68 put the reveal here behind a one-shot flag; a mouse pick
            // consumed that flag during OnMouseDown's PopupRect() call, which
            // re-scrolled the window between the click and the paint - the
            // click landed on one row and the list painted another.)
            if (popup_top_ > max_top) {
                popup_top_ = max_top;
            }
            const float list_h = item_h * static_cast<float>(max_rows);
            // Down by default; flip above the box only when the list does not
            // fit below and there is more room above.
            const bool flip_up = list_h > below && above > below;
            float list_y =
                flip_up ? (bounds_.y - list_h) : (bounds_.y + bounds_.h);
            if (has_domain) {
                list_y = (std::min)(list_y, domain_bottom - list_h);
                list_y = (std::max)(list_y, domain_top);
            }
            return Rect{list_x, list_y, list_w, list_h};
        }

        SelectElement::SelectElement() {
            hit_transparent = false;
        }

        void SelectElement::RevealSelectionNow() {
            if (!expanded_ || options_.empty()) {
                return;
            }
            // Reading the geometry once establishes popup_rows_ for the
            // CURRENT bounds; PopupRect() is now a pure read, so this call
            // cannot move the window out from under a click or a paint.
            (void)PopupRect();
            const std::size_t rows = popup_rows_ == 0 ? options_.size()
                                                      : popup_rows_;
            const std::size_t max_top =
                (options_.size() > rows) ? (options_.size() - rows) : 0;
            std::size_t selected_index = 0;
            for (std::size_t i = 0; i < options_.size(); ++i) {
                if (options_[i].first == selected_) {
                    selected_index = i;
                    break;
                }
            }
            // batch68: keep the wheel's position unless the selection would be
            // off-window - this runs on "the selection changed" only.
            if (popup_top_ > selected_index) {
                popup_top_ = selected_index;
            }
            if (popup_top_ > max_top) {
                popup_top_ = max_top;
            }
            if (selected_index >= popup_top_ + rows && max_top > 0) {
                popup_top_ = (std::min)(selected_index - rows + 1, max_top);
            }
        }

        void SelectElement::SetOptions(
            std::vector<std::pair<std::wstring, std::wstring>> value_label) {
            options_ = std::move(value_label);
            if (!selected_.empty()) {
                bool found = false;
                for (const auto& option : options_) {
                    if (option.first == selected_) {
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    selected_.clear();  // selection no longer exists
                }
            }
            expanded_ = false;
            // batch71: the option set (and possibly the selection) changed, so
            // the selected row must be inside the window again.
            RevealSelectionNow();
            ++content_rev;
            InvalidateLayout();
        }

        void SelectElement::SetSelectedValue(std::wstring value) {
            SetSelectedValueImpl(std::move(value), /*notify=*/true);
        }

        void SelectElement::SetSelectedValueSilent(std::wstring value) {
            SetSelectedValueImpl(std::move(value), /*notify=*/false);
        }

        void SelectElement::SetSelectedValueImpl(std::wstring value,
                                                 bool notify) {
            if (!options_.empty()) {
                bool found = false;
                for (const auto& option : options_) {
                    if (option.first == value) {
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    return;  // unknown option: ignored
                }
            }
            if (value == selected_) {
                return;
            }
            selected_ = std::move(value);
            // batch68/71: a selection change (keyboard arrow, programmatic set,
            // mouse pick) must bring the chosen row into the capped window.
            RevealSelectionNow();
            ++content_rev;
            InvalidateLayout();
            if (notify && on_changed) {
                on_changed();
            }
        }

        void SelectElement::SetExpanded(bool expanded) noexcept {
            if (expanded == expanded_) {
                return;
            }
            expanded_ = expanded;
            // batch68/71: opening (or re-opening) the list must show the current
            // choice.
            RevealSelectionNow();
            ++content_rev;
            InvalidateLayout();
        }

        bool SelectElement::DismissOverlay() {
            if (!expanded_) {
                return false;
            }
            SetExpanded(false);
            return true;
        }

        bool SelectElement::popup_anchored() const noexcept {
            if (!expanded_) {
                return true;  // nothing painted
            }
            const Rect popup = PopupRect();
            const float box_bottom = bounds_.y + bounds_.h;
            constexpr float kTolerance = 1.0f;
            const bool below =
                std::fabs(popup.y - box_bottom) <= kTolerance;
            const bool above =
                std::fabs((popup.y + popup.h) - bounds_.y) <= kTolerance;
            return below || above;
        }

        Element* SelectElement::HitTest(Point p) {
            if (expanded_) {
                if (PopupRect().Contains(p)) {
                    return this;  // expanded popup rows are hit-testable
                }
            }
            return Element::HitTest(p);
        }

        bool SelectElement::OnMouseDown(Point p) {
            if (!EffectivelyEnabled()) {
                return false;
            }
            focused_ = true;
            ++content_rev;
            if (expanded_ && bounds_.h > 0.0f) {
                // C4/batch24 P0-2: clicking one of the popup items selects it
                // and collapses the list. The popup geometry comes from the ONE
                // PopupRect() the renderer paints with, so a flipped-up list is
                // clickable at the same rows it is drawn at.
                const Rect popup = PopupRect();
                if (popup.Contains(p)) {
                    const float row = (p.y - popup.y) / kSelectItemH;
                    const std::size_t index =
                        popup_top_ + static_cast<std::size_t>(
                                         (std::max)(row, 0.0f));
                    if (row >= 0.0f && index < options_.size() &&
                        static_cast<std::size_t>(row) < popup_rows_) {
                        selected_ = options_[index].first;
                        hover_ = static_cast<int>(index);
                        // batch71: a MOUSE pick writes selected_ directly (no
                        // on_changed re-entry), so it must reveal by itself -
                        // otherwise picking a row in a scrolled-away part of a
                        // capped list left the new choice off-window.
                        RevealSelectionNow();
                        ++content_rev;
                        if (on_changed) {
                            on_changed();
                        }
                    }
                    SetExpanded(false);
                    return true;
                }
            }
            SetExpanded(!expanded_);
            return true;
        }

        bool SelectElement::OnMouseMove(Point p) {
            if (!EffectivelyEnabled() || !expanded_) {
                return false;
            }
            const Rect popup = PopupRect();
            int hover = -1;
            if (popup.Contains(p)) {
                const float row = (p.y - popup.y) / kSelectItemH;
                const std::size_t index =
                    popup_top_ +
                    static_cast<std::size_t>((std::max)(row, 0.0f));
                if (row >= 0.0f && index < options_.size() &&
                    static_cast<std::size_t>(row) < popup_rows_) {
                    hover = static_cast<int>(index);
                }
            }
            if (hover != hover_) {
                hover_ = hover;
                ++content_rev;
            }
            return true;
        }

        bool SelectElement::OnWheel(int delta) {
            if (!expanded_ || delta == 0 || options_.empty()) {
                return false;
            }
            // batch33f: the popup is capped to what fits, so the wheel scrolls
            // the row window. Only claim the event when the window really moved
            // (otherwise the enclosing page keeps the scroll).
            const std::size_t rows = popup_rows_ == 0 ? options_.size()
                                                      : popup_rows_;
            const std::size_t max_top =
                (options_.size() > rows) ? (options_.size() - rows) : 0;
            const std::size_t before = popup_top_;
            if (delta > 0) {
                popup_top_ = (popup_top_ > 0) ? popup_top_ - 1 : 0;
            } else if (popup_top_ < max_top) {
                ++popup_top_;
            }
            if (popup_top_ != before) {
                ++content_rev;
                return true;
            }
            return false;
        }

        void SelectElement::OnFocus(bool focused) {
            if (focused == focused_) {
                return;
            }
            focused_ = focused;
            ++content_rev;  // ring/emphasis changes: the element repaints
        }

        Rect SelectElement::invalidation_bounds() const noexcept {
            // Always box + popup, independent of the current expanded_ state.
            // A key toggle flips expanded_ before the caller reads the bounds,
            // so a state-dependent version would miss whichever region was
            // just vacated (the popup on collapse, the box on expand). The
            // union is the stable "before/after" geometry for both.
            // batch24 P0-2: the popup half is the SAME PopupRect() the render
            // and hit paths use, so a flipped-up list is fully invalidated.
            const Rect popup = PopupRect();
            const float x0 = (std::min)(bounds_.x, popup.x);
            const float y0 = (std::min)(bounds_.y, popup.y);
            const float x1 = (std::max)(bounds_.x + bounds_.w,
                                        popup.x + popup.w);
            const float y1 = (std::max)(bounds_.y + bounds_.h,
                                        popup.y + popup.h);
            return Rect{x0, y0, x1 - x0, y1 - y0};
        }

        bool SelectElement::OnKeyDown(uint32_t vk) {
            if (!EffectivelyEnabled()) {
                return false;
            }
            if (vk == kVkReturn || vk == kVkSpace) {
                SetExpanded(!expanded_);
                return true;
            }
            if (vk == kVkDown || vk == kVkUp) {
                if (!expanded_) {
                    SetExpanded(true);
                    return true;
                }
                if (options_.empty()) {
                    return true;
                }
                std::size_t index = 0;
                for (std::size_t i = 0; i < options_.size(); ++i) {
                    if (options_[i].first == selected_) {
                        index = i;
                        break;
                    }
                }
                if (vk == kVkDown) {
                    index = (index + 1) % options_.size();
                } else {
                    index = (index + options_.size() - 1) % options_.size();
                }
                SetSelectedValue(options_[index].first);
                return true;
            }
            return false;
        }

        Size SelectElement::MeasureCore(Size) {
            std::wstring label;
            for (const auto& option : options_) {
                if (option.first == selected_) {
                    label = option.second;
                    break;
                }
            }
            if (label.empty() && !options_.empty()) {
                label = options_.front().second;
            }
            // M3b: the derived label is memoised against content_rev.
            // SetOptions / SetSelectedValue both bump that counter, so a
            // different option or selection always invalidates the slot.
            if (measure_memo_valid_ && measure_memo_rev_ == content_rev &&
                measure_memo_gen_ == TextMeasureGeneration()) {
                return measure_memo_sz_;
            }
            const Size text =
                MeasureText(label, FontToken::Body, kUnboundedWidth);
            measure_memo_sz_ = Size{std::max(160.0f, text.w + 32.0f),
                                    std::max(28.0f, text.h + 8.0f)};
            measure_memo_rev_ = content_rev;
            measure_memo_gen_ = TextMeasureGeneration();
            measure_memo_valid_ = true;
            return measure_memo_sz_;
        }

        // --- ContextMenu (batch33 E) -----------------------------------------

        ContextMenu::ContextMenu() {
            hit_transparent = false;
            visible = true;  // arranged full-client; open_ gates everything
        }

        void ContextMenu::Show(Point at, std::vector<Item> items) {
            items_ = std::move(items);
            anchor_ = at;
            hover_ = -1;
            open_ = !items_.empty();
            open_t_ = 0.0f;
            ++content_rev;
            InvalidateLayout();
            if (open_) {
                RequestAnimationFrame();
                RequestLayoutFrame();
            }
        }

        void ContextMenu::Close() {
            if (!open_) {
                return;
            }
            open_ = false;
            hover_ = -1;
            ++content_rev;
            RequestLayoutFrame();
        }

        bool ContextMenu::DismissOverlay() {
            if (!open_) {
                return false;
            }
            Close();
            return true;
        }

        void ContextMenu::ArrangeCore(Rect final_rect) {
            // The menu takes no layout slot: the window arranges it over the
            // client area so the card can be positioned anywhere inside it.
            if (final_rect.w > 0.0f && final_rect.h > 0.0f) {
                client_ = final_rect;
            }
            if (client_.w <= 0.0f || client_.h <= 0.0f) {
                client_ = final_rect;
            }
        }

        Rect ContextMenu::MenuRect() const noexcept {
            const float width = kMaxWidth;
            float height = kPadY * 2.0f +
                           kItemHeight * static_cast<float>(items_.size());
            // Open to the bottom-right of the anchor; flip left/up when the
            // card would leave the client area, then clamp so it never paints
            // off-window.
            const Rect domain = (client_.w > 0.0f && client_.h > 0.0f)
                                    ? client_
                                    : bounds_;
            float x = anchor_.x;
            float y = anchor_.y;
            if (x + width > domain.x + domain.w) {
                x = anchor_.x - width;
            }
            if (y + height > domain.y + domain.h) {
                y = anchor_.y - height;
            }
            x = std::max(domain.x, std::min(x, domain.x + domain.w - width));
            y = std::max(domain.y, std::min(y, domain.y + domain.h - height));
            return Rect{x, y, width, height};
        }

        int ContextMenu::ItemAt(Point p) const noexcept {
            if (!open_ || items_.empty()) {
                return -1;
            }
            const Rect card = MenuRect();
            if (!card.Contains(p)) {
                return -1;
            }
            const float rel = p.y - (card.y + kPadY);
            if (rel < 0.0f) {
                return -1;
            }
            const int index = static_cast<int>(rel / kItemHeight);
            if (index < 0 || index >= static_cast<int>(items_.size())) {
                return -1;
            }
            return index;
        }

        void ContextMenu::Activate(int index) {
            if (index < 0 || index >= static_cast<int>(items_.size())) {
                return;
            }
            // Copy the callback out first: it may open a dialog / navigate,
            // which can retire the page subtree this menu lives in.
            std::function<void()> run = items_[static_cast<std::size_t>(index)].run;
            Close();
            if (run) {
                run();
            }
        }

        Rect ContextMenu::invalidation_bounds() const noexcept {
            if (!open_) {
                return Rect{};
            }
            // The menu is arranged over the whole client area (the "click
            // outside closes" capture), so a repaint must cover the whole
            // surface it owns.
            return client_.w > 0.0f && client_.h > 0.0f ? client_ : bounds_;
        }

        Element* ContextMenu::HitTest(Point p) {
            if (!open_ || !visible || !EffectivelyEnabled()) {
                return nullptr;
            }
            // batch34k P0: hit testing is a PURE QUERY. It used to call
            // Close() whenever the point was outside the card, but the window
            // runs HitTestTopmost from passive paths too - hover dispatch,
            // cursor-hint resolution and wheel routing - so merely moving the
            // mouse (or the OS asking for a cursor) dismissed the menu. The
            // "click outside closes" half of the contract is enforced by the
            // button-down path (DismissContextMenuOutside), which is the only
            // place a real click exists.
            return MenuRect().Contains(p) ? this : nullptr;
        }

        Element* ContextMenu::HitTestOverlay(Point p) {
            return HitTest(p);
        }

        bool ContextMenu::OnMouseDown(Point p) {
            if (!open_) {
                return false;
            }
            const int index = ItemAt(p);
            if (index < 0) {
                Close();
                return false;
            }
            hover_ = index;
            ++content_rev;
            return true;
        }

        bool ContextMenu::OnMouseUp(Point p) {
            if (!open_) {
                return false;
            }
            const int index = ItemAt(p);
            if (index < 0) {
                Close();
                return false;
            }
            Activate(index);
            return true;
        }

        bool ContextMenu::OnMouseMove(Point p) {
            if (!open_) {
                return false;
            }
            const int hover = ItemAt(p);
            if (hover != hover_) {
                hover_ = hover;
                ++content_rev;
            }
            return true;
        }

        bool ContextMenu::OnKeyDown(uint32_t vk) {
            if (!open_ || items_.empty()) {
                return false;
            }
            const int n = static_cast<int>(items_.size());
            switch (vk) {
                case kVkDown:
                    hover_ = hover_ < 0 ? 0 : (hover_ + 1) % n;
                    break;
                case kVkUp:
                    hover_ = hover_ < 0 ? n - 1 : (hover_ + n - 1) % n;
                    break;
                case kVkHome:
                    hover_ = 0;
                    break;
                case kVkEnd:
                    hover_ = n - 1;
                    break;
                case kVkReturn:
                case kVkSpace:
                    // Enter with nothing highlighted picks the first item:
                    // a keyboard user who opened the menu and pressed Enter
                    // means "the obvious one", not "nothing".
                    if (hover_ < 0) {
                        hover_ = 0;
                    }
                    Activate(hover_);
                    return true;
                default:
                    return false;
            }
            ++content_rev;
            return true;
        }

        void ContextMenu::AdvanceAnimation(float dt_seconds) {
            if (!open_ || dt_seconds <= 0.0f) {
                return;
            }
            open_t_ = std::min(1.0f, open_t_ + dt_seconds / kOpenSeconds);
            RequestElementRepaint(this);
        }

        bool ContextMenu::HasActiveAnimation() const noexcept {
            return open_ && open_t_ < 1.0f;
        }

        void ContextMenu::RenderOverlay(RenderCtx& ctx) {
            if (!open_ || items_.empty()) {
                return;
            }
            const Rect card = MenuRect();
            const float t = std::min(std::max(open_t_, 0.0f), 1.0f);
            // batch33x: the drop shadow must DARKEN the page. Using Bg as the
            // shadow colour is a no-op in the dark theme (#121212 over
            // #121212) and actively wrong in the light theme (#F5F5F7 is
            // nearly white - a white halo around the card). A shadow is
            // always black at low alpha; the page beneath supplies the tone.
            Color shadow{0.0f, 0.0f, 0.0f, 0.45f * t};
            ctx.FillRoundedRect(
                Rect{card.x + 2.0f, card.y + 3.0f, card.w, card.h},
                g_theme.radius_sm, shadow);
            Color panel = ColorFor(ColorToken::Panel);
            panel.a = t;
            ctx.FillRoundedRect(card, 8.0f, panel);
            Color border = ColorFor(ColorToken::Border);
            border.a = t;
            ctx.StrokeRoundedRect(card, 8.0f, border, 1.0f);
            const Color text_color = ColorFor(ColorToken::Text);
            const Color danger_color = ColorFor(ColorToken::Danger);
            const Color hover_bg = ColorFor(ColorToken::PanelAlt);
            for (std::size_t i = 0; i < items_.size(); ++i) {
                const float y = card.y + kPadY +
                                kItemHeight * static_cast<float>(i);
                const Rect row{card.x, y, card.w, kItemHeight};
                if (static_cast<int>(i) == hover_) {
                    ctx.FillRoundedRect(Rect{row.x + 4.0f, row.y + 1.0f,
                                             std::max(row.w - 8.0f, 0.0f),
                                             kItemHeight - 2.0f},
                                        g_theme.radius_sm, hover_bg);
                }
                const float pad_x = 12.0f;
                const Size measured = MeasureText(
                    items_[i].label, FontToken::Body,
                    std::max(row.w - 2.0f * pad_x, 0.0f));
                ctx.DrawTextSingleLine(
                    items_[i].label,
                    Rect{row.x + pad_x,
                         row.y + (kItemHeight - measured.h) * 0.5f,
                         std::max(row.w - 2.0f * pad_x, 0.0f), measured.h},
                    FontToken::Body,
                    items_[i].danger ? danger_color : text_color,
                    Align::Start);
            }
        }

        // --- SparklineElement / StatusDotElement (batch28) -------------------

        SparklineElement::SparklineElement() {
            hit_transparent = false;
        }

        double SparklineElement::LadderStep(double value) {
            // Binary ladder: 1 / 2 / 5 x 1024^n B/s. Binary steps keep the
            // painted label EXACTLY on the ladder ("1.0 KiB/s", "5.0 MiB/s"),
            // which a decimal ladder cannot do once it is rendered in KiB/MiB.
            if (!(value > 0.0)) {
                return 0.0;
            }
            double unit = 1.0;  // 1024^n
            while (unit < 1.0e15 && value > 5.0 * unit) {
                unit *= 1024.0;
            }
            for (const double m : {1.0, 2.0, 5.0}) {
                if (value <= m * unit) {
                    return m * unit;
                }
            }
            return 5.0 * unit;
        }
        void SparklineElement::Push(double value) {
            if (!(value >= 0.0)) {
                value = 0.0;  // NaN / negative -> flat
            }
            // batch33 A: EVERY push advances the ring, including a repeat of the
            // previous value. The old `back() == value` early return meant a
            // steady rate never produced a second column, so the "curve" stayed a
            // one-column stub. Ring eviction keeps the memory bounded.
            if (samples_.size() >= kCapacity) {
                samples_.erase(samples_.begin());
            }
            samples_.push_back(value);
            UpdateBounds();
            // batch29 P1: a new sample is ONE new column, painted immediately.
            // It must NOT bump content_rev (that would force the app's whole-
            // window content-epoch relayout + full repaint per snapshot tick)
            // and must not spin the animation clock: only the 120 ms bounds
            // ease, if one just started, needs frames.
            smoothing_pending_ = gear_t_ < 1.0f;
            RequestElementRepaint(this);
            if (smoothing_pending_) {
                RequestAnimationFrame();
            }
        }

        void SparklineElement::SetActive(bool active) {
            if (active == active_) {
                return;
            }
            active_ = active;
            if (!active_) {
                // Idle: the axis stays where it was (a stopped instrument keeps
                // its last bounds label), the curve flattens.
                samples_.clear();
                peak_ = 0.0;
                gear_t_ = 1.0f;
                from_lo_ = to_lo_;
                from_hi_ = to_hi_;
                flat_ = false;
                smoothing_pending_ = false;
            } else {
                RequestAnimationFrame();
            }
            ++content_rev;
        }

        void SparklineElement::SetColor(ColorToken color) {
            if (color == color_) {
                return;
            }
            color_ = color;
            ++content_rev;
        }

        void SparklineElement::SetTickCount(int count) {
            const int clamped = count < 0 ? 0 : (count > 32 ? 32 : count);
            if (clamped == tick_count_) {
                return;
            }
            tick_count_ = clamped;
            ++content_rev;
        }

        void SparklineElement::SetChromeVisible(bool show) {
            // batch120: the parameter used to be named `visible`, which
            // shadowed the base Element::visible flag this class also has
            // (C4458). Inside this function the name meant the argument, so
            // a future edit touching `visible` could silently target the
            // argument instead of the element flag.
            if (show == chrome_) {
                return;
            }
            chrome_ = show;
            ++content_rev;
        }

        void SparklineElement::SetAreaAlpha(float alpha) {
            const float clamped = alpha < 0.0f ? 0.0f : (alpha > 1.0f ? 1.0f : alpha);
            if (clamped == area_alpha_) {
                return;
            }
            area_alpha_ = clamped;
            ++content_rev;
        }

        void SparklineElement::SetPreferredHeight(float height) {
            const float clamped = height < 0.0f ? 0.0f : height;
            if (clamped == preferred_h_) {
                return;
            }
            preferred_h_ = clamped;
            ++content_rev;
            InvalidateLayout();
        }

        double SparklineElement::displayed(std::size_t i) const {
            return i < samples_.size() ? samples_[i] : 0.0;
        }

        void SparklineElement::UpdateBounds() noexcept {
            // batch33 A: the vertical mapping comes from the VISIBLE window
            // (the samples actually in the ring), never from a ladder step.
            // The 8 % headroom is applied at paint time (DisplayBounds), so the
            // stored bounds stay the true min/max and the labels can show them.
            double lo = 0.0;
            double hi = 0.0;
            bool first = true;
            for (const double v : samples_) {
                if (first) {
                    lo = v;
                    hi = v;
                    first = false;
                    continue;
                }
                if (v < lo) {
                    lo = v;
                }
                if (v > hi) {
                    hi = v;
                }
            }
            peak_ = hi;
            flat_ = !first && hi == lo;
            if (first) {
                return;  // no samples: keep the previous bounds (idle keeps axis)
            }
            if (to_hi_ == hi && to_lo_ == lo) {
                return;  // same window: no ease to start
            }
            // Start the 120 ms ease from whatever is on screen right now.
            double shown_lo = 0.0;
            double shown_hi = 0.0;
            DisplayBounds(shown_lo, shown_hi);
            from_lo_ = shown_lo;
            from_hi_ = shown_hi;
            to_lo_ = lo;
            to_hi_ = hi;
            gear_t_ = 0.0f;
        }

        void SparklineElement::DisplayBounds(double& lo, double& hi) const
            noexcept {
            const float t = std::min(std::max(gear_t_, 0.0f), 1.0f);
            lo = from_lo_ + (to_lo_ - from_lo_) * t;
            hi = from_hi_ + (to_hi_ - from_hi_) * t;
        }

        std::wstring SparklineElement::range_label() const {
            if (!chrome_) {
                return std::wstring();
            }
            // batch33 A: the UPPER bound of the visible window, as a human
            // value ("1.2 MiB/s"). A truly flat window appends the localized
            // "stable" word so the single number cannot read as a broken axis.
            std::wstring text = FormatBps(
                static_cast<uint64_t>(std::max(to_hi_, 0.0) + 0.5));
            if (flat_ && to_hi_ > 0.0) {
                text += L" \u00B7 ";
                text += I18n::Instance().T(Str::SparkStableSuffix);
            }
            return text;
        }

        std::wstring SparklineElement::lower_bound_label() const {
            if (!chrome_) {
                return std::wstring();
            }
            return FormatBps(static_cast<uint64_t>(std::max(to_lo_, 0.0) + 0.5));
        }

        bool SparklineElement::OnMouseDown(Point p) {
            if (!EffectivelyEnabled() || !bounds_.Contains(p) || !chrome_) {
                return false;
            }
            pressed_ = true;
            return true;
        }

        bool SparklineElement::OnMouseUp(Point p) {
            if (!pressed_) {
                return false;
            }
            pressed_ = false;
            if (!EffectivelyEnabled() || !bounds_.Contains(p)) {
                return false;
            }
            if (on_click) {
                on_click();
            }
            return true;
        }

        std::wstring SparklineElement::tooltip_text(Point p) const {
            if (!chrome_ || !EffectivelyEnabled() || !bounds_.Contains(p) ||
                !active_ || samples_.empty()) {
                return std::wstring();
            }
            const I18n& i18n = I18n::Instance();
            // batch29: "current X / peak Y / average Z" + a second "range W"
            // line.
            const double current = samples_.back();
            double sum = 0.0;
            for (const double sample : samples_) {
                sum += sample;
            }
            const double average =
                sum / static_cast<double>(samples_.size());
            std::wstring text = i18n.Format(
                Str::SparkCurrentPeakAvgFmt,
                {FormatBps(static_cast<uint64_t>(current + 0.5)),
                 FormatBps(static_cast<uint64_t>(peak_ + 0.5)),
                 FormatBps(static_cast<uint64_t>(average + 0.5))});
            text += L"\n";
            text += i18n.Format(Str::SparkRangeFmt, {range_label()});
            // batch33 spec D tail: a clickable curve says what the click does.
            if (on_click && !click_hint_.empty()) {
                text += L"\n";
                text += click_hint_;
            }
            return text;
        }

        void SparklineElement::AdvanceAnimation(float dt_seconds) {
            if (dt_seconds < 0.0f) {
                dt_seconds = 0.0f;
            }
            bool moving = false;
            // batch33 A: the SHAPE is immediate (raw samples are painted), so
            // the only animated thing is the 120 ms bounds ease. That is what
            // "the axis glides, the wave does not lag" means in practice.
            if (gear_t_ < 1.0f) {
                gear_t_ = std::min(1.0f, gear_t_ + dt_seconds / kGearSeconds);
                moving = true;
            }
            if (moving) {
                // batch29 P1: the window invalidates this element's own box
                // after the frame; bumping the global content epoch here would
                // turn a 120 ms ease into full-window relayouts on the next
                // snapshot tick.
                RequestElementRepaint(this);
            }
            smoothing_pending_ = moving;
        }

        bool SparklineElement::HasActiveAnimation() const noexcept {
            // Only while a visible difference is left to smooth or the gear is
            // still transitioning: a settled curve must let the frame clock stop
            // (idle cost contract).
            return active_ && smoothing_pending_;
        }

        Size SparklineElement::MeasureCore(Size available) {
            // b28-legibility P1/P3: the strip instrument is 280x36 (min
            // 180x32); the card mini curves are bare 28 px bands that take the
            // card's content width. batch33 B: the dashboard's performance card
            // asks for a taller framed instrument (168 px) that fills its
            // column.
            if (!chrome_) {
                return Size{available.w > 0.0f ? available.w : 220.0f,
                            preferred_h_ > 0.0f ? preferred_h_ : 28.0f};
            }
            if (preferred_h_ > 0.0f) {
                return Size{available.w > 0.0f ? available.w : 280.0f,
                            preferred_h_};
            }
            return Size{280.0f, 36.0f};
        }

        void SparklineElement::RenderCore(RenderCtx& ctx) {
            if (bounds_.w <= 0.0f || bounds_.h <= 0.0f) {
                return;
            }
            const Color curve = ColorFor(active_ ? color_ : ColorToken::TextDim);
            // batch37q (user: match Task Manager): the curve spans the card
            // edge to edge. The old 7 px horizontal inset left a visible
            // vertical end line inside the frame at the right edge, which
            // read as a stray tick.
            constexpr float kPadX = 1.0f;
            constexpr float kPadY = 5.0f;
            constexpr float kTickH = 3.0f;
            const float tick_band = tick_count_ > 0 ? kTickH : 0.0f;
            const Rect frame_inner{bounds_.x + kPadX, bounds_.y + kPadY,
                                   std::max(bounds_.w - 2.0f * kPadX, 0.0f),
                                   std::max(bounds_.h - 2.0f * kPadY - tick_band,
                                            1.0f)};
            // batch33e: the range label owns a BAND at the top of the frame and
            // the curve is drawn BELOW it. Painting the label first and the
            // columns after made the text unreadable on the 36 px strip (the
            // columns reached the top of the frame and covered it).
            float label_band = 0.0f;
            if (chrome_) {
                const std::wstring probe = range_label();
                if (!probe.empty()) {
                    const Size measured =
                        MeasureText(probe, FontToken::Small, 1.0e9f);
                    label_band = std::max(measured.h, 11.0f) + 3.0f;
                    // Never let the band eat the whole frame (a very short
                    // strip still needs a curve).
                    label_band = std::min(label_band,
                                          std::max(frame_inner.h * 0.6f, 0.0f));
                }
            }
            const Rect inner{frame_inner.x, frame_inner.y + label_band,
                             frame_inner.w,
                             std::max(frame_inner.h - label_band, 1.0f)};
            curve_area_ = inner;
            if (chrome_) {
                ctx.FillRoundedRect(bounds_, g_theme.radius_sm,
                                    ColorFor(ColorToken::Bg));
                ctx.StrokeRoundedRect(bounds_, g_theme.radius_sm,
                                      ColorFor(ColorToken::Border), 1.0f);
            }
            const float baseline = inner.y + inner.h;
            if (chrome_) {
                // FIXED horizontal grid at 25 / 50 / 75 % of the FRAME height
                // (1 px, GridLine). Their rects never depend on the data or on
                // the gear, so the axis cannot jitter.
                const Color grid = ColorFor(ColorToken::GridLine);
                for (const float pct : {0.25f, 0.5f, 0.75f}) {
                    const float y = bounds_.y + bounds_.h * pct;
                    ctx.FillRect(Rect{bounds_.x + kPadX, y,
                                      std::max(bounds_.w - 2.0f * kPadX, 0.0f),
                                      1.0f},
                                 grid);
                }
                // 0 axis along the bottom edge (Border).
                ctx.FillRect(Rect{inner.x, baseline - 1.0f, inner.w, 1.0f},
                             ColorFor(ColorToken::Border));
                // batch33k: NUMBERS on the interior grid lines. An axis without
                // values cannot be read, which is what made the graph feel like
                // a decoration instead of an instrument. Only the wide framed
                // card gets them (the 36 px strip has no room).
                if (inner.w >= 240.0f && inner.h >= 80.0f) {
                    double lo_v = 0.0;
                    double hi_v = 0.0;
                    DisplayBounds(lo_v, hi_v);
                    const double range_v = hi_v - lo_v;
                    const I18n& i18n = I18n::Instance();
                    (void)i18n;
                    for (const float pct : {0.25f, 0.5f, 0.75f}) {
                        // The grid line sits at pct of the FRAME height; the
                        // value at that height is the top of the range minus
                        // that fraction of the span.
                        const double frac_from_top =
                            (bounds_.y + bounds_.h * pct - inner.y) /
                            std::max(inner.h, 1.0f);
                        const double value =
                            hi_v - range_v * static_cast<double>(
                                              std::min(std::max(
                                                           frac_from_top, 0.0),
                                                       1.0));
                        const std::wstring tick = FormatBps(
                            static_cast<uint64_t>(std::max(value, 0.0) + 0.5));
                        const Size tm =
                            MeasureText(tick, FontToken::Micro, 1.0e9f);
                        // Right-aligned INSIDE the plot, on the grid line.
                        const float tw = std::min(tm.w, inner.w * 0.5f);
                        ctx.DrawTextSingleLine(
                            tick,
                            Rect{inner.x + inner.w - tw - 3.0f,
                                 bounds_.y + bounds_.h * pct - tm.h * 0.5f, tw,
                                 std::max(tm.h, 10.0f)},
                            FontToken::Micro,
                            ColorFor(ColorToken::RangeText), Align::End);
                    }
                }
                // Range label, TOP-LEFT (the right side carries the live
                // highlight head), 11 px, the brighter dim tone.
                const std::wstring label = range_label();
                if (!label.empty()) {
                    const Size measured =
                        MeasureText(label, FontToken::Small, 1.0e9f);
                    const float lw = std::min(measured.w + 2.0f,
                                              std::max(inner.w - 8.0f, 0.0f));
                    ctx.DrawTextSingleLine(
                        label,
                        Rect{inner.x + 4.0f, bounds_.y + 2.0f, lw,
                             std::max(measured.h, 11.0f)},
                        FontToken::Small, ColorFor(ColorToken::RangeText),
                        Align::Start);
                }
            }
            // Tick marks along the bottom edge (1 px wide, 3 px high, dim).
            if (tick_count_ > 0) {
                const float tick_y = bounds_.y + bounds_.h - kTickH - 1.0f;
                const Color tick = ColorFor(ColorToken::TextDim);
                const int n = tick_count_;
                for (int i = 0; i < n; ++i) {
                    const float t = n == 1 ? 0.0f
                                           : static_cast<float>(i) /
                                                 static_cast<float>(n - 1);
                    const float x = bounds_.x + 3.0f +
                                    t * std::max(bounds_.w - 6.0f, 0.0f);
                    ctx.FillRect(Rect{x, tick_y, 1.0f, kTickH}, tick);
                }
            }
            if (!active_ || samples_.empty()) {
                // Idle: one flat line hugging the baseline, nothing else.
                ctx.FillRect(Rect{inner.x, baseline - 2.0f, inner.w, 1.0f},
                             curve);
                return;
            }
            // Direction hint (b28-legibility P2): a faint 3-step fade along the
            // baseline, so "flows to the right" reads even in a static frame.
            {
                const Color border = ColorFor(ColorToken::Border);
                for (int i = 0; i < 3; ++i) {
                    Color c = border;
                    c.a = 0.55f - 0.15f * static_cast<float>(i);
                    const float seg = inner.w / 3.0f;
                    ctx.FillRect(Rect{inner.x + seg * static_cast<float>(i),
                                      baseline - 1.0f, seg, 1.0f},
                                 c);
                }
            }
            // batch33 A: the vertical mapping is the VISIBLE window's own
            // bounds, painted inside the inner box with an 8 % margin at both
            // ends (the spec's "never glued to the floor, never flush with the
            // ceiling" invariant). A flat window paints one vertical mid line.
            double shown_lo = 0.0;
            double shown_hi = 0.0;
            DisplayBounds(shown_lo, shown_hi);
            const double span = shown_hi - shown_lo;
            const bool paint_flat = span <= 0.0;
            constexpr float kEdgeMargin = 0.08f;   // 8 % top + 8 % bottom
            const float usable_h =
                std::max(inner.h * (1.0f - 2.0f * kEdgeMargin), 1.0f);
            const auto norm_of = [&](double value) {
                if (paint_flat || !(span > 0.0)) {
                    return 0.5;  // truly flat: vertical centre
                }
                double norm = (value - shown_lo) / span;
                if (norm < 0.0) {
                    norm = 0.0;
                }
                if (norm > 1.0) {
                    norm = 1.0;
                }
                return norm;
            };
            // The column height maps norm=0 to the 92 % line and norm=1 to the
            // 8 % line, so the painted top edge always stays inside
            // [inner.y + 8 %, inner.y + 92 %] - never glued to either edge.
            const auto column_h = [&](double value) {
                return inner.h * kEdgeMargin +
                       static_cast<float>(norm_of(value)) * usable_h;
            };
            // batch33j: SMOOTH rendering. The old code painted one 16 px block
            // per ring slot (60 slots across a 992 px card), which read as a
            // blocky bar chart - the opposite of the Task Manager performance
            // graph this card imitates. We now resample the ring at 1 logical
            // px and interpolate linearly between neighbouring samples, so the
            // curve is continuous and the area fill follows it exactly.
            const std::size_t shown = samples_.size();
            // batch33j: a PARTIALLY filled ring occupies only its share of the
            // frame (it grows from the left edge), so 3 samples on a 992 px card
            // stay a short stub instead of being stretched across the whole
            // width. A full ring spans exactly the frame.
            const float fill_frac =
                std::min(1.0f, static_cast<float>(shown) /
                                   static_cast<float>(kCapacity));
            const float plot_w =
                std::max(inner.w * std::max(fill_frac, 0.02f), 2.0f);
            const float x0 = inner.x;
            // Value at a fractional ring position (0 = oldest visible sample).
            const auto sample_at = [&](double pos) {
                if (shown == 0) {
                    return 0.0;
                }
                if (shown == 1) {
                    return displayed(samples_.size() - 1);
                }
                const double clamped =
                    std::min(std::max(pos, 0.0),
                             static_cast<double>(shown) - 1.0);
                const std::size_t i0 = static_cast<std::size_t>(clamped);
                const std::size_t i1 = std::min(i0 + 1, shown - 1);
                const double frac = clamped - static_cast<double>(i0);
                const double v0 = displayed(samples_.size() - shown + i0);
                const double v1 = displayed(samples_.size() - shown + i1);
                return v0 + (v1 - v0) * frac;
            };
            if (paint_flat) {
                // Truly flat window: ONE horizontal line at the mid height (the
                // spec's "flat only when truly flat"), never a baseline stroke.
                const float mid_y = inner.y + inner.h * 0.5f;
                ctx.FillRect(Rect{x0, mid_y, plot_w, 2.0f}, curve);
            }
            Color area = curve;
            area.a = area_alpha_;
            // batch79: one column per LOGICAL PIXEL bought no visible detail.
            // Every column paints the same 6 gradient bands plus a bridging
            // stroke, and that bridge already makes steep segments continuous
            // (batch33j), so the outline is identical under a coarser resample.
            // The old fixed 1 px step made the op count scale with the widget
            // WIDTH: measured 7075 FillRects/frame for a full 992x168 card vs
            // 730 for a 200x28 strip. Cap the column count instead; sample_at()
            // still interpolates, and the |prev_top - top| bridge still spans
            // whatever vertical distance one column covers.
            constexpr float kMaxColumns = 240.0f;
            const float kStep =
                std::max(1.0f, std::ceil(std::max(plot_w, 1.0f) / kMaxColumns));
            constexpr float kLineH = 2.5f;  // the crisp curve edge
            // batch33k: the fill is a VERTICAL GRADIENT, dense just under the
            // curve and almost gone at the baseline. A single flat alpha band is
            // the "cheap filled polygon" look; the Task Manager graph fades out
            // towards the floor.
            constexpr int kGradBands = 6;
            const float grad_top_a = std::min(area_alpha_ * 1.6f, 0.55f);
            const float grad_bottom_a = 0.02f;
            float prev_top = baseline;      // batch33j: stroke bridging state
            if (!paint_flat) {
                // batch79: named x_span so it cannot shadow the numeric `span`
                // (shown_hi - shown_lo) in the enclosing scope.
                const float x_span = std::max(plot_w - kStep, 0.0f);
                const float denom =
                    shown > 1 ? static_cast<float>(shown - 1) : 1.0f;
                const int slices =
                    static_cast<int>(std::ceil(plot_w / kStep));
                for (int i = 0; i < slices; ++i) {
                    const float x = x0 + static_cast<float>(i) * kStep;
                    const float w = std::min(kStep, x0 + plot_w - x);
                    if (w <= 0.0f) {
                        continue;
                    }
                    // Fractional ring position for this column's left edge.
                    const double pos =
                        static_cast<double>((x - x0) / std::max(x_span, 1.0f)) *
                        static_cast<double>(denom);
                    const float h =
                        std::max(column_h(sample_at(pos)), 0.0f);
                    const float top = baseline - h;
                    if (h >= 0.5f) {
                        // batch33k: split the column into horizontal bands and
                        // fade alpha from the curve downwards (gradient fill).
                        for (int b = 0; b < kGradBands; ++b) {
                            const float t0 =
                                static_cast<float>(b) /
                                static_cast<float>(kGradBands);
                            const float t1 =
                                static_cast<float>(b + 1) /
                                static_cast<float>(kGradBands);
                            const float by = top + h * t0;
                            const float bh = h * (t1 - t0);
                            if (bh <= 0.0f) {
                                continue;
                            }
                            Color band = curve;
                            band.a = grad_top_a +
                                     (grad_bottom_a - grad_top_a) * t0;
                            ctx.FillRect(Rect{x, by, w, bh}, band);
                        }
                    }
                    // batch33j: bridge to the PREVIOUS column's top so a steep
                    // segment is one continuous stroke. Painting only a fixed
                    // 2.5 px band around this column's own top left a visible
                    // staircase on every jump (measured: 87 vertical gaps).
                    const float link_top = std::min(top, prev_top);
                    const float link_h =
                        std::fabs(prev_top - top) + kLineH;
                    ctx.FillRect(Rect{x, link_top - kLineH * 0.5f, w, link_h},
                                 curve);
                    prev_top = top;
                }
            }
            // batch29: peak reference line - 1 px, 4 on / 4 off, same colour at
            // 45 % alpha. A flat window has no peak to mark.
            if (!paint_flat) {
                const float y = baseline - column_h(peak_);
                Color dash = curve;
                dash.a = 0.45f;
                constexpr float kDash = 4.0f;
                constexpr float kGap = 4.0f;
                for (float x = inner.x; x < inner.x + inner.w;
                     x += kDash + kGap) {
                    const float w = std::min(kDash, inner.x + inner.w - x);
                    if (w > 0.0f) {
                        ctx.FillRect(Rect{x, y, w, 1.0f}, dash);
                    }
                }
            }
            // Live head: a small solid block on the newest sample, so "data is
            // arriving" is visible at a glance (batch33j: it now sits exactly
            // on the curve's right end, at the resampled x).
            const float last_x = x0 + std::max(plot_w - 3.0f, 0.0f);
            const float last_h = column_h(samples_.back());
            ctx.FillRect(Rect{last_x,
                              std::max(baseline - last_h - kLineH, inner.y),
                              3.0f, 3.0f},
                         curve);
            // batch29: current-value tick - a 6x2 horizontal dash at the
            // right edge (next to the live head) so "where is it now" reads
            // even without hovering.
            ctx.FillRect(Rect{inner.x + std::max(inner.w - 6.0f, 0.0f),
                              std::max(baseline - last_h - 1.0f, inner.y),
                              6.0f, 2.0f},
                         curve);
        }
        StatusDotElement::StatusDotElement() {
            hit_transparent = true;
        }

        void StatusDotElement::SetColor(ColorToken color) {
            if (color == color_) {
                return;
            }
            color_ = color;
            ++content_rev;
        }

        void StatusDotElement::SetPulsing(bool pulsing) {
            if (pulsing == pulsing_) {
                return;
            }
            pulsing_ = pulsing;
            pulse_accum_ = 0.0f;
            pulse_step_pending_ = pulsing;  // the first frame after enabling
            if (!pulsing_) {
                alpha_ = 1.0f;  // steady state: always fully opaque
            } else {
                RequestAnimationFrame();
            }
            ++content_rev;
        }

        void StatusDotElement::AdvanceAnimation(float dt_seconds) {
            pulse_step_pending_ = false;  // cleared every frame, set on a step
            if (!pulsing_ || dt_seconds <= 0.0f) {
                return;
            }
            // batch63: keep the cycle and the shape, but only recompute the
            // alpha every kPulseStepSeconds (~15 fps) so the 12 px breathing
            // dot does not force a ~26 fps repaint of the dashboard. The phase
            // advances with the FULL dt every callback, so the cycle length and
            // the sine shape are unchanged - only the sampling density drops.
            pulse_accum_ += dt_seconds;
            if (pulse_accum_ + 1e-4f < kPulseStepSeconds) {
                return;  // not due yet: no content change, no repaint
            }
            // Keep the fractional remainder so the ~15 fps cadence does not
            // drift; the phase itself advances with the FULL dt below, so the
            // 1.2 s cycle stays exact regardless of the sampling step.
            pulse_accum_ -= kPulseStepSeconds;
            if (pulse_accum_ < 0.0f) {
                pulse_accum_ = 0.0f;
            }
            // Fold any accumulated delta into the phase (a clamped dt can be
            // larger than one frame; the fold keeps the cycle exact).
            phase_ += dt_seconds / kPulseSeconds;
            if (phase_ >= 1.0f) {
                phase_ -= std::floor(phase_);
            }
            // Sine ease 0.55 .. 1.0 (the text never moves).
            const float wave = 0.5f - 0.5f * std::cos(phase_ * 6.2831853f);
            alpha_ = 0.55f + 0.45f * wave;
            pulse_step_pending_ = true;  // this frame IS visible: repaint it
            ++content_rev;
        }

        bool StatusDotElement::HasActiveAnimation() const noexcept {
            // ONLY while pulsing: a stopped/failed app must fall back to zero
            // timer ticks (the "idle costs nothing" contract).
            return pulsing_;
        }

        Size StatusDotElement::MeasureCore(Size available) {
            (void)available;
            return Size{kSize, kSize};
        }

        void StatusDotElement::RenderCore(RenderCtx& ctx) {
            if (bounds_.w <= 0.0f || bounds_.h <= 0.0f) {
                return;
            }
            const float d = std::min(kSize, std::min(bounds_.w, bounds_.h));
            const Rect box{bounds_.x + (bounds_.w - d) * 0.5f,
                           bounds_.y + (bounds_.h - d) * 0.5f, d, d};
            Color glow = ColorFor(color_);
            glow.a = 0.22f * alpha_;
            // 1 px halo, then the solid dot (both round: radius_sm on a 12 px
            // box reads as a circle at every scale).
            ctx.FillRoundedRect(Rect{box.x - 1.0f, box.y - 1.0f, d + 2.0f,
                                     d + 2.0f},
                                (d + 2.0f) * 0.5f, glow);
            Color dot = ColorFor(color_);
            dot.a = alpha_;
            ctx.FillRoundedRect(box, d * 0.5f, dot);
        }

        BadgeElement::BadgeElement(std::wstring text, BadgeKind kind)
            : text_(std::move(text)), kind_(kind) {}

        void BadgeElement::SetText(std::wstring text) {
            if (text == text_) {
                return;
            }
            text_ = std::move(text);
            ++content_rev;
            InvalidateLayout();
        }

        void BadgeElement::SetKind(BadgeKind kind) noexcept {
            if (kind == kind_) {
                return;
            }
            kind_ = kind;
            ++content_rev;
        }

        Size BadgeElement::MeasureCore(Size) {
            // M3b: memoise the text's natural measurement against content_rev.
            // SetText / SetKind both bump that counter, so either change
            // invalidates the slot.
            if (measure_memo_valid_ && measure_memo_rev_ == content_rev &&
                measure_memo_gen_ == TextMeasureGeneration()) {
                const Size memo = measure_memo_sz_;
                return Size{memo.w + 16.0f, std::max(20.0f, memo.h + 6.0f)};
            }
            const Size text =
                MeasureText(text_, FontToken::Small, kUnboundedWidth);
            measure_memo_sz_ = text;
            measure_memo_rev_ = content_rev;
            measure_memo_gen_ = TextMeasureGeneration();
            measure_memo_valid_ = true;
            return Size{text.w + 16.0f, std::max(20.0f, text.h + 6.0f)};
        }

        ProgressBarElement::ProgressBarElement(float value)
            : value_(std::min(std::max(value, 0.0f), 1.0f)) {
            hit_transparent = true;
        }

        void ProgressBarElement::SetValue(float value) {
            const float clamped = std::min(std::max(value, 0.0f), 1.0f);
            if (clamped == value_) {
                return;
            }
            value_ = clamped;
            ++content_rev;
        }

        Size ProgressBarElement::MeasureCore(Size available) {
            return Size{available.w > 0.0f ? available.w : 120.0f, 8.0f};
        }

        // --- DialogHost ------------------------------------------------------

        namespace {

            /// Retire+sweep queue (analysis section 4.3 candidate 1): DialogHost
            /// closes move their subtree here instead of destroying it, and
            /// SweepRetiredDialogChrome() (app tick / ~DialogHost) destroys
            /// the entries once no widget event frame is on the stack. The
            /// queue is append-only between sweeps (repeated closes stack,
            /// never overwrite), so a single tick bounds the retired memory.
            using RetiredChrome = std::vector<std::unique_ptr<Element>>;

            RetiredChrome& RetiredChromeQueue() noexcept {
                // Heap-owned on purpose: retired subtrees may contain nested
                // DialogHost elements whose destructor sweeps back into this
                // queue; a function-static vector destroyed before process
                // exit would then be touched during static destruction (UB).
                static RetiredChrome* queue = new RetiredChrome;
                return *queue;
            }

        }  // namespace

        DialogHost::DialogHost() {
            hit_transparent = false;
            visible = false;
        }

        DialogHost::~DialogHost() {
            // Fallback sweep point: a dialog dies with its owning page tree,
            // guaranteed outside any widget event frame. Retire the leftover
            // subtree (if any) and destroy every retired subtree at once.
            Reset();
            SweepRetiredDialogChrome();
        }

        void DialogHost::Reset() {
            // Never destroy children_ here: their elements (buttons and their
            // on_click/std::function payloads) may still have frames on the
            // event stack while Close() runs - the exact self-destruct UB path.
            // Retire the subtree; SweepRetiredDialogChrome() frees it later.
            if (!children_.empty()) {
                RetiredChrome& retired = RetiredChromeQueue();
                for (auto& child : children_) {
                    if (child) {
                        retired.push_back(std::move(child));
                    }
                }
                children_.clear();
                // T5: retiring the subtree lowers the tree's content_rev SUM
                // without any element bumping; advance the structural epoch so
                // UiApp::Update cannot leave its cached sum stale-high and miss
                // a later in-Update bump (single-walk layout detection).
                ++UiTreeEpoch();
            }
            card_ = nullptr;
            body_ = nullptr;
            field_host_ = nullptr;
            footer_ = nullptr;
            scroll_ = nullptr;
            fields_.clear();
            on_ok_ = nullptr;
            on_submit_ = nullptr;
            mode_ = Mode::None;
            ++generation_;
            visible = false;
            open_t_ = 1.0f;  // settled: a closed host is never animating
            InvalidateLayout();
        }

        void DialogHost::BeginDialog(Str title, const std::wstring& body_text) {
            BeginDialogText(I18n::Instance().T(title), body_text);
        }

        void DialogHost::BeginDialogText(const std::wstring& title,
                                         const std::wstring& body_text) {
            Reset();
            Card* card = static_cast<Card*>(Add(
                std::make_unique<Card>(Padding{20.0f, 16.0f, 20.0f, 16.0f}, 8.0f)));
            card_ = card;
            StackPanel* stack = static_cast<StackPanel*>(card->Add(
                std::make_unique<StackPanel>(Orientation::Vertical, 12.0f, Padding{})));
            body_ = stack;
            stack->Add(std::make_unique<Text>(title, FontToken::Section,
                                              ColorToken::Text));
            if (!body_text.empty()) {
                stack->Add(std::make_unique<Text>(body_text, FontToken::Body,
                                                  ColorToken::TextDim, true));
            }
            // Field host is the scrollable body: a long form scrolls instead
            // of growing past the viewport and pushing the action row off
            // screen (the save/cancel truncation defect).
            auto fields = std::make_unique<StackPanel>(Orientation::Vertical,
                                                       10.0f, Padding{});
            field_host_ = fields.get();
            auto scroll = std::make_unique<ScrollView>(std::move(fields));
            // batch33n (user: "the downlink kbps border is covered"): keep a
            // few px under the
            // last field so its 1 px border is never sliced by the viewport
            // edge when the form is exactly viewport-height.
            scroll->SetContentBottomInset(6.0f);
            scroll_ = scroll.get();
            stack->Add(std::move(scroll));
            footer_ = static_cast<StackPanel*>(stack->Add(
                std::make_unique<StackPanel>(Orientation::Horizontal, 8.0f,
                                             Padding{0.0f, 4.0f, 0.0f, 0.0f})));
            visible = true;
            // T9 entrance: restart the fade/scale and spin the frame clock.
            open_t_ = 0.0f;
            RequestAnimationFrame();
        }

        StackPanel* DialogHost::FieldHost() {
            return field_host_ != nullptr ? field_host_ : body_;
        }

        StackPanel* DialogHost::AddButtonRow() {
            StackPanel* target = footer_ != nullptr ? footer_ : body_;
            auto row = std::make_unique<StackPanel>(Orientation::Horizontal, 8.0f,
                                                    Padding{});
            StackPanel* raw = static_cast<StackPanel*>(target->Add(std::move(row)));
            return raw;
        }

        void DialogHost::ShowMessage(Str title, std::wstring body_text, Str ok) {
            BeginDialog(title, body_text);
            StackPanel* row = AddButtonRow();
            Button* ok_button = static_cast<Button*>(row->Add(std::make_unique<Button>(
                I18n::Instance().T(ok), ButtonStyle::Primary)));
            ok_button->on_click = [this] { Confirm(); };
            mode_ = Mode::Message;
            InvalidateLayout();
        }

        void DialogHost::ShowConfirm(Str title, std::wstring body_text,
                                     std::function<void()> on_ok) {
            BeginDialog(title, body_text);
            StackPanel* row = AddButtonRow();
            Button* cancel = static_cast<Button*>(row->Add(std::make_unique<Button>(
                I18n::Instance().T(Str::CommonCancel))));
            cancel->on_click = [this] { Close(); };
            Button* ok_button = static_cast<Button*>(row->Add(std::make_unique<Button>(
                I18n::Instance().T(Str::CommonOk), ButtonStyle::Primary)));
            ok_button->on_click = [this] { Confirm(); };
            on_ok_ = std::move(on_ok);
            mode_ = Mode::Confirm;
            InvalidateLayout();
        }

        void DialogHost::ShowForm(Str title, std::vector<FormField> fields,
                                  std::function<void(const FormResult&)> on_submit) {
            BeginDialog(title, std::wstring());
            StackPanel* fields_box = FieldHost();
            for (const FormField& field : fields) {
                fields_box->Add(std::make_unique<Text>(I18n::Instance().T(field.label),
                                                       FontToken::BodyStrong,
                                                       ColorToken::Text));
                if (field.type == FormFieldType::Select) {
                    auto select = std::make_unique<SelectElement>();
                    select->SetOptions(field.options);
                    SelectElement* editor =
                        static_cast<SelectElement*>(fields_box->Add(std::move(select)));
                    std::wstring initial = field.initial;
                    if (initial.empty() && !field.options.empty()) {
                        initial = field.options.front().first;
                    }
                    if (!initial.empty()) {
                        editor->SetSelectedValue(initial);
                    }
                    fields_.push_back(FieldBinding{field.id, FormFieldType::Select,
                                                   editor});
                } else {
                    auto input = std::make_unique<TextInputElement>();
                    TextInputElement* editor =
                        static_cast<TextInputElement*>(fields_box->Add(std::move(input)));
                    editor->SetValue(field.initial);
                    fields_.push_back(FieldBinding{field.id, FormFieldType::Text,
                                                   editor});
                }
            }
            StackPanel* row = AddButtonRow();
            Button* cancel = static_cast<Button*>(row->Add(std::make_unique<Button>(
                I18n::Instance().T(Str::CommonCancel))));
            cancel->on_click = [this] { Close(); };
            Button* submit = static_cast<Button*>(row->Add(std::make_unique<Button>(
                I18n::Instance().T(Str::CommonSave), ButtonStyle::Primary)));
            submit->on_click = [this] { Confirm(); };
            on_submit_ = std::move(on_submit);
            mode_ = Mode::Form;
            InvalidateLayout();
        }

        void DialogHost::ShowMessageText(std::wstring title, std::wstring body_text,
                                         std::wstring ok) {
            BeginDialogText(title, body_text);
            StackPanel* row = AddButtonRow();
            Button* ok_button = static_cast<Button*>(row->Add(std::make_unique<Button>(
                std::move(ok), ButtonStyle::Primary)));
            ok_button->on_click = [this] { Confirm(); };
            mode_ = Mode::Message;
            InvalidateLayout();
        }

        void DialogHost::ShowMessageActionText(std::wstring title,
                                               std::wstring body_text,
                                               std::wstring ok_label,
                                               std::wstring action_label,
                                               std::function<void()> on_action) {
            BeginDialogText(title, body_text);
            StackPanel* row = AddButtonRow();
            Button* action = static_cast<Button*>(row->Add(
                std::make_unique<Button>(std::move(action_label),
                                         ButtonStyle::Secondary)));
            action->id = "dialog.action";
            action->on_click = [action_fn = std::move(on_action)]() mutable {
                if (action_fn) {
                    action_fn();
                }
            };
            Button* ok_button = static_cast<Button*>(row->Add(std::make_unique<Button>(
                std::move(ok_label), ButtonStyle::Primary)));
            ok_button->id = "dialog.ok";
            ok_button->on_click = [this] { Confirm(); };
            mode_ = Mode::Message;
            InvalidateLayout();
        }

        void DialogHost::ShowConfirmText(std::wstring title,
                                         std::wstring body_text,
                                         std::function<void()> on_ok) {
            BeginDialogText(title, body_text);
            StackPanel* row = AddButtonRow();
            Button* cancel = static_cast<Button*>(row->Add(std::make_unique<Button>(
                I18n::Instance().T(Str::CommonCancel))));
            cancel->on_click = [this] { Close(); };
            Button* ok_button = static_cast<Button*>(row->Add(std::make_unique<Button>(
                I18n::Instance().T(Str::CommonOk), ButtonStyle::Primary)));
            ok_button->on_click = [this] { Confirm(); };
            on_ok_ = std::move(on_ok);
            mode_ = Mode::Confirm;
            InvalidateLayout();
        }

        void DialogHost::ShowConfirmActionsText(
            std::wstring title, std::wstring body_text, std::wstring ok_label,
            std::wstring cancel_label, std::function<void()> on_ok,
            std::function<void()> on_cancel) {
            BeginDialogText(title, body_text);
            StackPanel* row = AddButtonRow();
            Button* cancel = static_cast<Button*>(row->Add(std::make_unique<Button>(
                std::move(cancel_label))));
            cancel->id = "dialog.cancel";
            cancel->on_click = [this, on_cancel = std::move(on_cancel)]() mutable {
                Close();
                if (on_cancel) {
                    on_cancel();
                }
            };
            Button* ok_button = static_cast<Button*>(row->Add(std::make_unique<Button>(
                std::move(ok_label), ButtonStyle::Primary)));
            ok_button->id = "dialog.ok";
            ok_button->on_click = [this] { Confirm(); };
            on_ok_ = std::move(on_ok);
            mode_ = Mode::Confirm;
            InvalidateLayout();
        }

        void DialogHost::ShowLeavePrompt(
            std::wstring title, std::wstring body, std::wstring save_label,
            std::wstring discard_label, std::wstring cancel_label,
            std::function<void()> on_save, std::function<void()> on_discard) {
            // batch27 P1-6: [don't save] [cancel] [save]. The save action is
            // the primary (right-most); cancel is the safe default focus
            // (window.cpp SyncDialogFocus keys off the dialog.cancel id).
            BeginDialogText(title, body);
            StackPanel* row = AddButtonRow();
            Button* discard = static_cast<Button*>(row->Add(std::make_unique<Button>(
                std::move(discard_label))));
            discard->id = "dialog.discard";
            discard->on_click = [this, on_discard = std::move(on_discard)]() mutable {
                Close();
                if (on_discard) {
                    on_discard();
                }
            };
            Button* cancel = static_cast<Button*>(row->Add(std::make_unique<Button>(
                std::move(cancel_label))));
            cancel->id = "dialog.cancel";
            cancel->on_click = [this] { Close(); };
            Button* save_button = static_cast<Button*>(row->Add(
                std::make_unique<Button>(std::move(save_label),
                                         ButtonStyle::Primary)));
            save_button->id = "dialog.save";
            save_button->on_click = [this, on_save = std::move(on_save)]() mutable {
                Close();
                if (on_save) {
                    on_save();
                }
            };
            mode_ = Mode::Confirm;
            InvalidateLayout();
        }

        void DialogHost::ShowFormText(std::wstring title,
                                      std::vector<FormField> fields,
                                      std::function<void(const FormResult&)> on_submit) {
            ShowFormActionsText(
                std::move(title), std::wstring(), std::move(fields),
                I18n::Instance().T(Str::CommonSave),
                I18n::Instance().T(Str::CommonCancel), std::move(on_submit));
        }

        void DialogHost::ShowFormActionsText(
            std::wstring title, std::wstring body_text,
            std::vector<FormField> fields, std::wstring submit_label,
            std::wstring cancel_label,
            std::function<void(const FormResult&)> on_submit,
            std::function<void()> on_cancel) {
            BeginDialogText(title, body_text);
            StackPanel* fields_box = FieldHost();
            for (const FormField& field : fields) {
                const std::wstring label =
                    field.label == Str::_Count
                        ? std::wstring(field.id.begin(), field.id.end())
                        : I18n::Instance().T(field.label);
                fields_box->Add(std::make_unique<Text>(
                    label, FontToken::BodyStrong, ColorToken::Text));
                if (field.type == FormFieldType::Select) {
                    auto select = std::make_unique<SelectElement>();
                    select->SetOptions(field.options);
                    SelectElement* editor =
                        static_cast<SelectElement*>(fields_box->Add(std::move(select)));
                    std::wstring initial = field.initial;
                    if (initial.empty() && !field.options.empty()) {
                        initial = field.options.front().first;
                    }
                    if (!initial.empty()) {
                        editor->SetSelectedValue(initial);
                    }
                    fields_.push_back(FieldBinding{field.id, FormFieldType::Select,
                                                   editor});
                } else {
                    auto input = std::make_unique<TextInputElement>();
                    TextInputElement* editor =
                        static_cast<TextInputElement*>(fields_box->Add(std::move(input)));
                    editor->SetValue(field.initial);
                    fields_.push_back(FieldBinding{field.id, FormFieldType::Text,
                                                   editor});
                }
            }
            StackPanel* row = AddButtonRow();
            Button* cancel = static_cast<Button*>(row->Add(std::make_unique<Button>(
                std::move(cancel_label))));
            cancel->id = "dialog.cancel";
            cancel->on_click = [this, on_cancel = std::move(on_cancel)]() mutable {
                Close();
                if (on_cancel) {
                    on_cancel();
                }
            };
            Button* submit = static_cast<Button*>(row->Add(std::make_unique<Button>(
                std::move(submit_label), ButtonStyle::Primary)));
            submit->id = "dialog.ok";
            submit->on_click = [this] { Confirm(); };
            on_submit_ = std::move(on_submit);
            mode_ = Mode::Form;
            InvalidateLayout();
        }

        void DialogHost::Close() {
            Reset();
        }
        void DialogHost::Confirm() {
            // Nested-show guard: snapshot the generation - any Show* issued
            // from inside the callback (same or new mode) bumps it through
            // Reset, so the tail Close must not destroy the fresh dialog (a
            // Form re-show would otherwise be submitted with empty fields, a
            // phantom submit). The callback object is moved out of the member
            // first, so it never gets cleared while its own operator() runs;
            // exactly-once boundary: one Confirm fires the old callback once.
            if (mode_ == Mode::None) {
                return;
            }
            const std::uint64_t g = generation_;
            const Mode m = mode_;
            if (m == Mode::Confirm) {
                std::function<void()> ok = std::move(on_ok_);
                if (ok) {
                    ok();
                }
            } else if (m == Mode::Form) {
                std::function<void(const FormResult&)> submit =
                    std::move(on_submit_);
                if (submit) {
                    submit(Collect());
                }
            }
            if (generation_ == g) {
                Close();
            }
        }

        void SweepRetiredDialogChrome() noexcept {
            // Swap out so the destruction happens off the queue: if an entry
            // destructor ever re-enters this function it finds an empty queue
            // (idempotent / reentrant-safe).
            RetiredChrome batch;
            batch.swap(RetiredChromeQueue());
            batch.clear();
        }

        std::size_t RetiredDialogChromeCount() noexcept {
            return RetiredChromeQueue().size();
        }

        FormResult DialogHost::Collect() const {
            FormResult result;
            for (const FieldBinding& binding : fields_) {
                if (binding.editor == nullptr) {
                    continue;
                }
                if (binding.type == FormFieldType::Select) {
                    const SelectElement* select =
                        static_cast<const SelectElement*>(binding.editor);
                    result.values[binding.id] = select->selected_value();
                } else {
                    const TextInputElement* input =
                        static_cast<const TextInputElement*>(binding.editor);
                    result.values[binding.id] = input->value();
                }
            }
            return result;
        }

        Element* DialogHost::form_field(const std::string& field_id) const noexcept {
            for (const FieldBinding& binding : fields_) {
                if (binding.id == field_id) {
                    return binding.editor;
                }
            }
            return nullptr;
        }

        bool DialogHost::OnKeyDown(uint32_t vk) {
            if (mode_ == Mode::None) {
                return false;
            }
            if (vk == kVkEscape) {
                Close();  // cancel: never fires ok/submit
                return true;
            }
            if (vk == kVkReturn) {
                Confirm();  // exactly once (mode is cleared by Close)
                return true;
            }
            return false;
        }

        Size DialogHost::MeasureCore(Size available) {
            if (card_ != nullptr) {
                const float max_w = std::max(0.0f, available.w - 64.0f);
                const float max_h = std::max(0.0f, available.h - 64.0f);
                // Measure the card unbounded first, then re-measure with the
                // viewport height as the budget so the scroll view absorbs the
                // overflow and the action row keeps its intrinsic height.
                card_->Measure(Size{max_w, kUnboundedHeight});
                const float want_h = card_->desired().h;
                if (want_h > max_h) {
                    card_->InvalidateLayout();
                    card_->Measure(Size{max_w, max_h});
                }
            }
            return Size{available.w, available.h};  // full-size modal overlay
        }

        void DialogHost::ArrangeCore(Rect final_rect) {
            if (card_ == nullptr) {
                return;
            }
            const Size desired = card_->desired();
            const float w = std::min(desired.w, std::max(0.0f, final_rect.w - 32.0f));
            const float h = std::min(desired.h, std::max(0.0f, final_rect.h - 32.0f));
            card_->Arrange(Rect{final_rect.x + (final_rect.w - w) * 0.5f,
                                final_rect.y + (final_rect.h - h) * 0.5f, w, h});
        }

        // --- ToastHost -------------------------------------------------------

        ToastHost::ToastHost() {
            hit_transparent = true;  // toasts never block clicks
        }

        void ToastHost::Show(Str text, ToastKind kind) {
            ToastEntry entry;
            entry.text = text;
            entry.kind = kind;
            entry.shown = std::chrono::steady_clock::now();
            entry.t = 0.0f;  // T9: slide/fade in
            toasts_.push_back(entry);
            if (toasts_.size() > kToastMax) {
                toasts_.erase(toasts_.begin());  // drop the oldest
            }
            ++content_rev;
            RequestAnimationFrame();  // T9 entrance: spin the frame clock
        }

        void ToastHost::ShowText(std::wstring text, ToastKind kind) {
            ToastEntry entry;
            entry.text = Str::_Count;
            entry.kind = kind;
            entry.raw_text = std::move(text);
            entry.shown = std::chrono::steady_clock::now();
            entry.t = 0.0f;  // T9: slide/fade in
            toasts_.push_back(entry);
            if (toasts_.size() > kToastMax) {
                toasts_.erase(toasts_.begin());  // drop the oldest
            }
            ++content_rev;
            RequestAnimationFrame();  // T9 entrance: spin the frame clock
        }

        void ToastHost::Clear() {
            if (toasts_.empty()) {
                return;
            }
            toasts_.clear();
            ++content_rev;
        }

        void ToastHost::Tick(std::chrono::steady_clock::time_point now) {
            const std::size_t before = toasts_.size();
            toasts_.erase(std::remove_if(toasts_.begin(), toasts_.end(),
                                         [now](const ToastEntry& entry) {
                                             return now - entry.shown >= kToastTtl;
                                         }),
                          toasts_.end());
            if (toasts_.size() != before) {
                ++content_rev;
            }
        }

        Size ToastHost::MeasureCore(Size available) {
            return Size{available.w, available.h};
        }

        void ToastHost::AdvanceAnimation(float dt_seconds) {
            if (dt_seconds <= 0.0f) {
                return;
            }
            const float step = dt_seconds / kToastOpenSeconds;
            for (ToastEntry& entry : toasts_) {
                if (entry.t < 1.0f) {
                    entry.t = std::min(1.0f, entry.t + step);
                }
            }
        }

        bool ToastHost::HasActiveAnimation() const noexcept {
            for (const ToastEntry& entry : toasts_) {
                if (entry.t < 1.0f) {
                    return true;
                }
            }
            return false;
        }

        // --- Sidebar ---------------------------------------------------------

        namespace {

            struct NavItem {
                const char* id;
                Str title;
            };

            /// Spec 7.2 order: dashboard, leases, portmap, firewall,
            /// ratelimit, bridge, settings, about; batch19 R3-2 appends the
            /// console page as the ninth entry.
            constexpr NavItem kNavItems[] = {
                {"dashboard", Str::NavDashboard}, {"leases", Str::NavLeases},
                {"portmap", Str::NavPortmap},     {"firewall", Str::NavFirewall},
                {"ratelimit", Str::NavRatelimit}, {"bridge", Str::NavBridge},
                {"settings", Str::NavSettings},   {"about", Str::NavAbout},
                {"console", Str::NavConsole},
            };
            constexpr std::size_t kNavCount = sizeof(kNavItems) / sizeof(kNavItems[0]);

        }  // namespace

        Sidebar::Sidebar() {
            hit_transparent = true;  // buttons take the hits
            auto panel = std::make_unique<StackPanel>(
                Orientation::Vertical, 4.0f,
                Padding{12.0f, 12.0f, 12.0f, 12.0f}, Align::Stretch);
            panel_ = panel.get();
            items_.reserve(kNavCount);
            buttons_.reserve(kNavCount);
            for (const NavItem& item : kNavItems) {
                items_.push_back(item.id);
                auto button =
                    std::make_unique<Button>(I18n::Instance().T(item.title));
                button->id = std::string("shell.nav.") + item.id;
                button->SetTextAlign(Align::Start);  // S5-AESTH: nav is left-anchored
                button->SetTextIndent(16.0f);  // gutter for the 3 px accent bar
                // batch17 P2-b (B-5): navigation items are a list, not
                // in-card buttons - no rest-state edge (and no per-page op
                // tax); hover/selection affordances stay unchanged.
                button->SetRestOutline(false);
                Button* raw = button.get();
                raw->on_click = [this, page_id = std::string(item.id)] {
                    if (on_navigate) {
                        on_navigate(page_id);
                    }
                };
                buttons_.push_back(raw);
                panel_->Add(std::move(button));
            }
            Add(std::move(panel));
        }

        std::size_t Sidebar::selected_index() const noexcept {
            for (std::size_t i = 0; i < items_.size(); ++i) {
                if (items_[i] == selected_) {
                    return i;
                }
            }
            return items_.size();
        }

        void Sidebar::SetSelected(std::string_view page_id) {
            for (const std::string& item : items_) {
                if (std::string_view(item) == page_id) {
                    if (selected_ == item) {
                        return;  // equal value: no-op (replay must not bump)
                    }
                    selected_.assign(item);
                    // M6: the accent bar is render-visible state; the change
                    // must travel the ContentRev wrapper so UiApp::Update's
                    // O(1) epoch gate sees it without a RequestLayout crutch.
                    ++content_rev;
                    return;
                }
            }
            if (selected_.empty()) {
                return;  // already cleared: no-op
            }
            selected_.clear();
            ++content_rev;
        }

        void Sidebar::SetLang(I18n& i18n) {
            for (std::size_t i = 0; i < buttons_.size() && i < kNavCount; ++i) {
                buttons_[i]->SetLabel(i18n.T(kNavItems[i].title));
            }
        }

        Button* Sidebar::item_button(std::size_t index) const noexcept {
            return index < buttons_.size() ? buttons_[index] : nullptr;
        }

        Size Sidebar::MeasureCore(Size available) {
            if (panel_ != nullptr) {
                panel_->Measure(Size{kWidth, available.h});
            }
            return Size{kWidth, available.h};
        }

        void Sidebar::ArrangeCore(Rect final_rect) {
            if (panel_ != nullptr) {
                panel_->Arrange(
                    Rect{final_rect.x, final_rect.y, kWidth, final_rect.h});
            }
        }

        // --- PageHeader ------------------------------------------------------

        PageHeader::PageHeader() {
            hit_transparent = true;
            // batch17 P2-b (B-8): the page title carries the Title token
            // (20/600) instead of Section (16/600) - the 48 px header row has
            // ample room (line height ~27) and Fluent page titles sit at
            // 20-28. Section stays for section headers and dialog titles.
            auto title =
                std::make_unique<Text>(L"", FontToken::Title, ColorToken::Text);
            title_ = title.get();
            title_->id = "shell.page.title";
            Add(std::move(title));
        }

        void PageHeader::SetTitle(std::wstring title) {
            if (title_ != nullptr) {
                title_->SetText(std::move(title));
            }
        }

        Size PageHeader::MeasureCore(Size available) {
            if (title_ != nullptr) {
                title_->Measure(Size{available.w, kHeight});
            }
            return Size{available.w, kHeight};
        }

        void PageHeader::ArrangeCore(Rect final_rect) {
            constexpr float kPad = 16.0f;
            if (title_ != nullptr) {
                title_->Arrange(Rect{final_rect.x + kPad, final_rect.y,
                                     std::max(final_rect.w - kPad * 2.0f, 0.0f),
                                     final_rect.h});
            }
        }

        // --- DriverBanner -----------------------------------------------------

        DriverBanner::DriverBanner() {
            hit_transparent = true;
            auto status = std::make_unique<Text>(
                L"", FontToken::BodyStrong, ColorToken::Warning);
            status_ = status.get();
            status_->id = "shell.banner.status";
            Add(std::move(status));

            auto reason = std::make_unique<Text>(
                L"", FontToken::Small, ColorToken::Warning, true);
            reason_ = reason.get();
            reason_->id = "shell.banner.reason";
            Add(std::move(reason));

            auto action = std::make_unique<Button>(
                I18n::Instance().T(Str::FixDriverLabel),
                ButtonStyle::DangerOutline);
            action_ = action.get();
            action_->id = "shell.fixdriver";
            action_->SetTextAlign(Align::Center);
            Add(std::move(action));
            visible = false;  // hidden until the dataplane fails
        }

        void DriverBanner::SetFailure(bool failed, std::wstring status,
                              std::wstring reason, bool show_action) {
            visible = failed;
            if (status_ != nullptr) {
                status_->SetText(std::move(status));
                status_->visible = failed && !status_->text().empty();
            }
            if (reason_ != nullptr) {
                reason_->SetText(std::move(reason));
                reason_->visible = failed && !reason_->text().empty();
            }
            if (action_ != nullptr) {
                // Independent of `failed`: the button's own visibility only
                // distinguishes repair-capable failures from adapter warnings
                // (the banner itself hides the whole row when not failed).
                action_->visible = show_action;
            }
        }

        void DriverBanner::SetLang(I18n& i18n) {
            if (action_ != nullptr) {
                action_->SetLabel(i18n.T(Str::FixDriverLabel));
            }
        }

        Size DriverBanner::MeasureCore(Size available) {
            if (status_ != nullptr) {
                status_->Measure(Size{available.w, kBannerHeight});
            }
            if (reason_ != nullptr && reason_->visible) {
                reason_->Measure(Size{available.w, kBannerHeight});
            }
            if (action_ != nullptr && action_->visible) {
                action_->Measure(Size{kBannerActionW, kBannerHeight});
            }
            return Size{available.w, kBannerHeight};
        }

        void DriverBanner::ArrangeCore(Rect final_rect) {
            constexpr float kPad = 16.0f;
            constexpr float kGap = 12.0f;
            // Vertical baseline: centre every item in the banner height.
            const float mid = final_rect.y + kBannerHeight * 0.5f;

            // P5: the action owns the trailing edge; compute its box FIRST so
            // the reason band can be clamped and never runs under the button or
            // past the banner edge (a long Japanese reason used to do both).
            const bool rtl = I18n::Instance().IsRtl();
            const bool show_action =
                action_ != nullptr && action_->visible;
            const Size action_size =
                show_action ? action_->desired() : Size{0.0f, 0.0f};
            const float action_x =
                show_action
                    ? (rtl ? final_rect.x + kPad
                           : final_rect.x + final_rect.w - kPad -
                                 action_size.w)
                    : (rtl ? final_rect.x + kPad
                           : final_rect.x + final_rect.w - kPad);

            float x = final_rect.x + kPad;
            if (status_ != nullptr) {
                const Size d = status_->desired();
                status_->Arrange(
                    Rect{x, mid - d.h * 0.5f, d.w, d.h});
                x += d.w + kGap;
            }
            if (reason_ != nullptr && reason_->visible) {
                const float avail = (std::max)(action_x - kGap - x, 0.0f);
                if (avail > 0.0f) {
                    // Re-measure at the clamped width so the text WRAPS inside
                    // its band (the old code used the desired width, which is
                    // the single-line width for an unwrapped measure).
                    reason_->Measure(Size{avail, kBannerHeight});
                }
                const Size d = reason_->desired();
                const float w = (std::min)(d.w, avail);
                reason_->Arrange(Rect{x, mid - d.h * 0.5f, w, d.h});
                x += w + kGap;
            }
            if (action_ != nullptr) {
                action_->Arrange(Rect{action_x, mid - action_size.h * 0.5f,
                                      action_size.w, action_size.h});
            }
        }

        void DriverBanner::RenderChildren(RenderCtx& ctx) {
            // P5: clip the row's children to the banner frame.
            ctx.ClipPush(bounds_);
            Element::RenderChildren(ctx);
            ctx.ClipPop();
        }

        void DriverBanner::RenderCore(RenderCtx& ctx) {
            // One amber-outlined row under the header (warning tint on a
            // quiet fill; the action keeps its own red accent).
            ctx.FillRoundedRect(bounds_, g_theme.radius_sm,
                                ColorFor(ColorToken::Panel));
            // batch17 P1-b: same rounded-edge fix as Card/Button.
            ctx.StrokeRoundedRect(bounds_, g_theme.radius_sm,
                                  ColorFor(ColorToken::Warning), 1.0f);
        }

        // --- EmptyState ------------------------------------------------------

        EmptyState::EmptyState(Str message)
            : Text(L"", FontToken::Body, ColorToken::Text, false,
                   Align::Center) {
            SetMessage(message);
        }

        void EmptyState::SetMessage(Str message) {
            key_ = message;
            SetText(I18n::Instance().T(message));
        }

        Size EmptyState::MeasureCore(Size available) {
            // The glyph band sits on top of the message line, so the whole
            // placeholder is taller than a bare text line.
            const Size text = Text::MeasureCore(available);
            return Size{text.w, text.h + kGlyphH};
        }

        void EmptyState::RenderCore(RenderCtx& ctx) {
            if (text().empty() || bounds_.w <= 0.0f || bounds_.h <= 0.0f) {
                return;
            }
            // S5-AESTH P2: a dim empty-set glyph centred above the message.
            const Rect glyph{bounds_.x, bounds_.y,
                             bounds_.w, std::min(kGlyphH, bounds_.h)};
            ctx.DrawText(L"\u2205", glyph, FontToken::Body,
                         ColorFor(ColorToken::TextDim), Align::Center);
            const Rect msg{bounds_.x, bounds_.y + kGlyphH, bounds_.w,
                           std::max(bounds_.h - kGlyphH, 0.0f)};
            ctx.DrawText(text(), msg, font(), ColorFor(color()), Align::Center);
        }

        // ====================================================================
        // T8-F2: RenderCore for every visual control. Layout/measure and the
        // interaction semantics are untouched; this is the paint layer only.
        // ====================================================================

        void Text::RenderCore(RenderCtx& ctx) {
            if (text_.empty() || bounds_.w <= 0.0f || bounds_.h <= 0.0f) {
                return;
            }
            if (!wrap_) {
                // batch26: a single-line label that does not fit gets an
                // ellipsis (and Text::tooltip_text exposes the full string).
                // Multi-line (wrap_) text keeps its wrapping behaviour.
                const bool natural_measure =
                    MeasureText(L"x", font_, 1.0f).w <= 1.5f;
                ctx.DrawTextSingleLine(
                    EllipsizeToWidth(text_, font_, bounds_.w,
                                     natural_measure),
                    bounds_, font_, ColorFor(color_), align_);
                return;
            }
            ctx.DrawText(text_, bounds_, font_, ColorFor(color_), align_);
        }

        std::wstring Text::tooltip_text(Point) const {
            if (text_.empty() || bounds_.w <= 0.0f) {
                return std::wstring();
            }
            // The fixed test measure seam ignores the width limit; skip there so
            // every pre-existing text expectation stays untouched.
            if (MeasureText(L"x", font_, 1.0f).w > 1.5f) {
                return std::wstring();
            }
            return MeasureText(text_, font_, 1.0e9f).w > bounds_.w + 0.5f
                       ? text_
                       : std::wstring();
        }

        void Separator::RenderCore(RenderCtx& ctx) {
            ctx.FillRect(bounds_, ColorFor(ColorToken::Border));
        }

        void Card::RenderCore(RenderCtx& ctx) {
            // T9: the entrance scale derives the painted rect only (default 1.0
            // is pixel-identical to the previous behaviour).
            const Rect r = ScaledRect(bounds_, render_scale_);
            ctx.FillRoundedRect(r, radius_, ColorFor(ColorToken::Panel));
            // batch17 P1-b (B-1): the 1 px edge must follow the rounded
            // corners (a square StrokeRect left 5 px background-coloured
            // notches in all four corners).
            ctx.StrokeRoundedRect(r, radius_, ColorFor(ColorToken::Border),
                                  1.0f);
        }

        bool Button::OnMouseMove(Point p) {
            const bool inside = bounds_.Contains(p);
            if (inside != hover_) {
                hover_ = inside;
                ++content_rev;  // hover state is visual only: never consumes
                // T7: a hover change starts (or reverses) the background
                // transition. The clock self-stops once the target is reached.
                RequestAnimationFrame();
            }
            return false;
        }

        void Button::OnFocus(bool focused) {
            if (focused == focused_) {
                return;
            }
            focused_ = focused;
            ++content_rev;  // the focus ring is visual: repaint on change
        }

        void Button::AdvanceAnimation(float dt_seconds) {
            if (dt_seconds <= 0.0f) {
                return;
            }
            const float target = hover_ ? 1.0f : 0.0f;
            if (hover_t_ == target) {
                return;  // already settled: stay inactive (clock may self-stop)
            }
            const float step = dt_seconds / kHoverSeconds;
            if (hover_t_ < target) {
                hover_t_ = std::min(target, hover_t_ + step);
            } else {
                hover_t_ = std::max(target, hover_t_ - step);
            }
        }

        bool Button::HasActiveAnimation() const noexcept {
            return hover_t_ != (hover_ ? 1.0f : 0.0f);
        }

        void Button::RenderCore(RenderCtx& ctx) {
            const bool is_enabled = EffectivelyEnabled();
            // T7: the rest and hover fills are interpolated by hover_t_ so the
            // background eases in/out; only colors change (no layout impact).
            Color rest = ColorFor(ColorToken::Panel);
            Color hover_fill = rest;
            Color text_color = ColorFor(ColorToken::Text);
            if (ButtonStyle::Primary == style_) {
                rest = ColorFor(ColorToken::Accent);
                hover_fill = ColorFor(ColorToken::AccentHover);
                text_color = Color{1.0f, 1.0f, 1.0f, 1.0f};
            } else if (ButtonStyle::Danger == style_) {
                rest = ColorFor(ColorToken::Danger);
                hover_fill = rest;  // Danger keeps its fill on hover
                text_color = Color{1.0f, 1.0f, 1.0f, 1.0f};
            } else if (ButtonStyle::DangerOutline == style_) {
                // S5-AESTH: a loud solid-red "repair" button reads as alarm;
                // the outlined variant keeps the danger affordance (red text +
                // a 2 px accent edge) on a quiet fill.
                rest = ColorFor(ColorToken::Panel);
                hover_fill = ColorFor(ColorToken::PanelAlt);
                text_color = ColorFor(ColorToken::Danger);
            } else {  // Secondary
                rest = ColorFor(ColorToken::Panel);
                hover_fill = ColorFor(ColorToken::PanelAlt);
            }
            const float t = is_enabled ? hover_t_ : 0.0f;
            Color fill = LerpColor(rest, hover_fill, t);
            // T7 pressed feedback: darken the (possibly mid-transition) fill
            // while the pointer is held down; released returns to normal.
            if (pressed_ && is_enabled) {
                fill = ScaleRgb(fill, 0.82f);
            }
            if (!is_enabled) {
                text_color = ColorFor(ColorToken::TextDim);
                // batch33v: a 45% fill keeps the disabled look, but in the
                // LIGHT theme a Primary fill (Accent #0066CC) blended over
                // Bg (#F5F5F7) becomes a pale blue where TextDim is only
                // 3.16:1 - under AA 4.5:1. The dashboard Start/Stop button
                // hits exactly this while a command is in flight.
                // Lowering the alpha (not raising it) is the fix: a fainter
                // fill moves toward the page colour, so the muted label
                // gains contrast AND reads as more disabled. 0.20 clears
                // 4.5:1 for every style in both themes.
                fill.a = 0.45f;
                const Color blended = Color{
                    fill.r * fill.a + g_theme.bg.r * (1.0f - fill.a),
                    fill.g * fill.a + g_theme.bg.g * (1.0f - fill.a),
                    fill.b * fill.a + g_theme.bg.b * (1.0f - fill.a), 1.0f};
                if (ContrastRatio(text_color, blended) < 4.5f) {
                    fill.a = 0.20f;
                }
            }
            ctx.FillRoundedRect(bounds_, g_theme.radius_sm, fill);
            if (ButtonStyle::DangerOutline == style_) {
                // Quiet outline + a 2 px danger edge on the LEADING side: the
                // physical left in LTR, mirrored to the right edge under RTL
                // (batch19 P3: same leading-side rule as the nav accent bar).
                ctx.StrokeRoundedRect(bounds_, g_theme.radius_sm,
                                      ColorFor(ColorToken::Border), 1.0f);
                const float danger_x = I18n::Instance().IsRtl()
                                           ? bounds_.x + bounds_.w - 2.0f
                                           : bounds_.x;
                ctx.FillRect(Rect{danger_x, bounds_.y, 2.0f, bounds_.h},
                             ColorFor(ColorToken::Danger));
            }
            // batch17 P1-b/P2-b (B-5): a Secondary button carries its 1 px
            // edge at rest too (unless the host opted out - sidebar nav
            // items, which follow the navigation list language). Inside a
            // Card the fill equals the card fill, so without the rest-state
            // edge the control read as plain text; the hover edge for the
            // other styles is unchanged.
            if (hover_ || (rest_outline_ && ButtonStyle::Secondary == style_)) {
                ctx.StrokeRoundedRect(bounds_, g_theme.radius_sm,
                                      ColorFor(ColorToken::Border), 1.0f);
            }
            // T7 focus ring: a 2 px edge drawn on top when focused
            // (immediate, no interpolation). batch17 P1-b (B-4): the ring
            // colour is Text (white) - on the Primary/Danger fills the old
            // accent-on-accent ring was invisible, and the rounded stroke
            // removes its former corner pins. Visible on every style
            // (white on accent >= 4.5, white on panel far higher).
            // batch18 U4: the ring is opt-in (focus_ring_, default false) -
            // the user design language has no focus border; the paint path
            // is retained, only the condition gates it.
            if (focus_ring_ && focused_ && is_enabled) {
                ctx.StrokeRoundedRect(bounds_, g_theme.radius_sm,
                                      ColorFor(ColorToken::Text), 2.0f);
            }
            // batch19 R4-P2: a Start-aligned label (sidebar nav) keeps its
            // accent gutter on the right under RTL.
            Rect text_rect{bounds_.x + text_indent_, bounds_.y,
                           std::max(bounds_.w - text_indent_, 0.0f),
                           bounds_.h};
            if (text_align_ == Align::Start && I18n::Instance().IsRtl()) {
                text_rect = Rect{bounds_.x, bounds_.y,
                                 std::max(bounds_.w - text_indent_, 0.0f),
                                 bounds_.h};
            }
            ctx.DrawText(label_, text_rect, FontToken::Body, text_color,
                         text_align_);
        }

        void Checkbox::RenderCore(RenderCtx& ctx) {
            // T7: immediate pressed feedback - the box darkens while held.
            Color fill = checked ? ColorFor(ColorToken::Accent)
                                 : ColorFor(ColorToken::Panel);
            if (pressed_ && EffectivelyEnabled()) {
                fill = ScaleRgb(fill, 0.82f);
            }
            if (radio_) {
                // batch25a: a real radio look (round target) while reusing
                // the checkbox hit/keyboard contract and the same palette.
                const float radius = std::min(bounds_.w, bounds_.h) * 0.5f;
                ctx.FillRoundedRect(bounds_, radius, fill);
                // batch33s (user: the settings radio group looks broken):
                // the ring used ColorToken::Border (#2E2E2E) on a Bg
                // (#121212) card - 1.38:1, under WCAG 1.4.11's 3:1 for a
                // control boundary - so an UNCHECKED radio had no visible
                // circle at all and the group read as a bullet list.
                // InputBorder is the palette token meant for control
                // boundaries (3.67:1 here); a checked radio keeps the
                // accent fill, so only the empty state needed the change.
                ctx.StrokeRoundedRect(
                    bounds_, radius,
                    checked ? ColorFor(ColorToken::Border)
                            : ColorFor(ColorToken::InputBorder),
                    1.0f);
                if (checked) {
                    const float inset = radius * 0.45f;
                    ctx.FillRoundedRect(
                        Rect{bounds_.x + inset, bounds_.y + inset,
                             bounds_.w - inset * 2.0f,
                             bounds_.h - inset * 2.0f},
                        std::max(0.0f, radius - inset),
                        Color{1.0f, 1.0f, 1.0f, 1.0f});
                }
            } else {
                ctx.FillRect(bounds_, fill);
                ctx.StrokeRect(bounds_, ColorFor(ColorToken::Border), 1.0f);
                if (checked) {
                    ctx.DrawText(L"\u2713", bounds_, FontToken::Small,
                                 Color{1.0f, 1.0f, 1.0f, 1.0f}, Align::Center);
                }
            }
            // T7 M1: focus ring (matches Button's), drawn on top when focused.
            // batch18 U4: opt-in, same contract as Button (default off).
            if (focus_ring_ && focused_ && EffectivelyEnabled()) {
                if (radio_) {
                    ctx.StrokeRoundedRect(
                        bounds_, std::min(bounds_.w, bounds_.h) * 0.5f,
                        ColorFor(ColorToken::Accent), 2.0f);
                } else {
                    ctx.StrokeRect(bounds_, ColorFor(ColorToken::Accent), 2.0f);
                }
            }
        }

        void ScrollView::RenderChildren(RenderCtx& ctx) {
            ctx.ClipPush(bounds_);
            Element::RenderChildren(ctx);
            ctx.ClipPop();
            // batch33p (user: "main window must not show a scrollbar - rely on
            // the mouse wheel and the arrow keys"): the scroll thumb is gone.
            // Scrolling itself is unchanged (wheel + keyboard + ScrollIntoView);
            // only the 4 px visual indicator that used to sit on the trailing
            // edge was removed, so the content column is clean.
        }

        void TableElement::RenderCore(RenderCtx& ctx) {
            // Fixed header bar with the column captions.
            const Rect header{bounds_.x, bounds_.y, bounds_.w, kTableHeaderH};
            if (header.w > 0.0f && header.h > 0.0f) {
                ctx.FillRect(header, ColorFor(ColorToken::PanelAlt));
            }
            for (std::size_t i = 0; i < cols_.size(); ++i) {
                const float cw = ColumnWidth(i);
                const float cx = ColumnPhysicalX(i);  // R4-P2: RTL mirrors
                ctx.DrawText(I18n::Instance().T(cols_[i].header),
                             Rect{cx + kColumnInset, bounds_.y,
                                  std::max(cw - 2.0f * kColumnInset, 0.0f),
                                  kTableHeaderH},
                             FontToken::Small, ColorFor(ColorToken::TextDim),
                             header_align(i));
                // U1-D2: a thin divider at each interior column boundary. RTL:
                // the boundary sits at the left edge of logical column i.
                if (i + 1 < cols_.size()) {
                    const float bx = I18n::Instance().IsRtl() ? cx : cx + cw;
                    ctx.FillRect(
                        Rect{bx, bounds_.y + 6.0f, 1.0f,
                             std::max(kTableHeaderH - 12.0f, 1.0f)},
                        ColorFor(ColorToken::Border));
                }
            }
            // T12-F1 A3: a separator line under the header band.
            ctx.FillRect(Rect{bounds_.x,
                              bounds_.y + kTableHeaderH - 1.0f,
                              bounds_.w, 1.0f},
                         ColorFor(ColorToken::Border));
            // Scrollable rows, clipped to the body area below the header.
            const Rect body{bounds_.x, bounds_.y + kTableHeaderH, bounds_.w,
                            std::max(bounds_.h - kTableHeaderH, 0.0f)};
            if (body.w <= 0.0f || body.h <= 0.0f || rows_.empty()) {
                return;
            }
            ctx.ClipPush(body);
            // batch26: derived lazily at paint time (visible cells only) so the
            // layout path's measure-lookup budget is untouched. The headless
            // fixed-width measure seam ignores limits (its probe reports more
            // than the requested 1 px), in which case the original text is
            // painted unchanged for every pre-existing expectation.
            const bool measure_clamps =
                MeasureText(L"x", FontToken::Body, 1.0f).w <= 1.5f;
            const float first_row_y =
                body.y - (offset_ - static_cast<float>(first_row_) * kTableRowH);
            float row_y = first_row_y;
            for (std::size_t i = 0; i < visible_rows_ &&
                                    first_row_ + i < rows_.size();
                 ++i) {
                const std::size_t index = first_row_ + i;
                const Rect row_rect{bounds_.x, row_y, bounds_.w, kTableRowH};
                if (ctx.CulledOut(row_rect)) {
                    row_y += kTableRowH;
                    continue;
                }
                const bool hovered = (static_cast<int>(index) == hover_row_);
                if (hovered) {
                    ctx.FillRect(row_rect, ColorFor(ColorToken::PanelAlt));
                }
                for (std::size_t j = 0;
                     j < cols_.size() && j < rows_[index].cells.size(); ++j) {
                    const float cw = ColumnWidth(j);
                    const float cell_x = ColumnPhysicalX(j);  // R4-P2 mirror
                    // batch26: paint the memoised ellipsized form (never a
                    // raw over-wide string that could read as columns run
                    // together). The memo
                    // index is the same row-major grid LayoutVisibleRows filled.
                    // batch66: reference the string that will actually be
                    // drawn instead of copying it. The old shape built a
                    // std::wstring per cell (copy out of rows_) and then
                    // assigned memo.shown over it (a second allocation), so
                    // every painted cell cost two heap blocks per frame - on
                    // the dashboard that is dozens of allocations per paint,
                    // ~17 times a second. Both sources outlive the call: rows_
                    // and cell_memos_ are only replaced by SetRows/SetColumns,
                    // which never run inside RenderCore.
                    const std::wstring* cell_text = &rows_[index].cells[j];
                    const std::size_t memo_index =
                        index * cols_.size() + j;
                    if (memo_index < cell_memos_.size()) {
                        CellMemo& memo = cell_memos_[memo_index];
                        // batch58: the batch37b frozen-width fast path keeps
                        // the layout on a data-only refresh, so SetRows' memo
                        // reset is never repaired by LayoutVisibleRows. Falling
                        // back to the raw string here painted over-wide cells
                        // un-ellipsized (columns appeared to run together).
                        // Rebuild the memo from the same measurement the layout
                        // path would take; a later LayoutVisibleRows pass then
                        // sees it valid and reuses it.
                        if (!memo.valid) {
                            memo.size = MeasureText(rows_[index].cells[j],
                                                    FontToken::Body, cw);
                            memo.valid = true;
                            memo.shown_valid = false;
                        }
                        if (!memo.shown_valid) {
                            memo.shown = EllipsizeToWidth(
                                rows_[index].cells[j], FontToken::Body,
                                std::max(cw - 2.0f * kColumnInset, 0.0f),
                                measure_clamps);
                            memo.shown_valid = true;
                        }
                        cell_text = &memo.shown;
                    }
                    ctx.DrawText(*cell_text,
                                 Rect{cell_x + kColumnInset, row_y,
                                      std::max(cw - 2.0f * kColumnInset, 0.0f),
                                      kTableRowH},
                                 FontToken::Body,
                                 rows_[index].danger
                                     ? ColorFor(ColorToken::Danger)
                                     : ColorFor(ColorToken::Text),
                                 cols_[j].align);
                }
                if (hovered && !actions_.empty()) {
                    const float zone_w =
                        kTableActionW * static_cast<float>(actions_.size());
                    // batch19 R4-P2: the row-action zone mirrors in RTL.
                    const float zone_x = I18n::Instance().IsRtl()
                                             ? bounds_.x
                                             : bounds_.x + bounds_.w - zone_w;
                    for (std::size_t a = 0; a < actions_.size(); ++a) {
                        const Rect zone{zone_x + kTableActionW *
                                                     static_cast<float>(a),
                                        row_y, kTableActionW, kTableRowH};
                        ctx.FillRoundedRect(zone, g_theme.radius_sm,
                                            ColorFor(ColorToken::Accent));
                        ctx.DrawText(I18n::Instance().T(actions_[a]), zone,
                                     FontToken::Small,
                                     Color{1.0f, 1.0f, 1.0f, 1.0f},
                                     Align::Center);
                    }
                }
                row_y += kTableRowH;
            }
            ctx.ClipPop();
        }

        void TextInputElement::OnFocus(bool focused) {
            if (focused == focused_) {
                return;
            }
            focused_ = focused;
            // Reset the phase on both focus and blur so a refocus starts with
            // a bright caret (S5.19); while blurred the caret is never drawn.
            caret_visible_ = true;
            // batch24 P0-3 (IME lifecycle): leaving the field abandons any
            // in-flight composition - a preedit must never outlive its focus
            // (a stale composition on a refocused/other field is corruption).
            composition_.clear();
            composition_caret_ = 0;
            ++content_rev;
        }

        void TextInputElement::SetCompositionForTest(std::wstring text,
                                                     std::size_t caret) {
            if (caret > text.size()) {
                caret = text.size();
            }
            composition_ = std::move(text);
            composition_caret_ = caret;
            caret_visible_ = true;  // keep the preedit caret solid while editing
            ++content_rev;
            InvalidateLayout();
        }

        void TextInputElement::ClearComposition() {
            if (composition_.empty()) {
                return;
            }
            composition_.clear();
            composition_caret_ = 0;
            ++content_rev;
            InvalidateLayout();
        }

        void TextInputElement::CommitComposition(std::wstring result) {
            composition_.clear();
            composition_caret_ = 0;
            if (!result.empty()) {
                // Replace the selection (or insert at the caret), accepting any
                // Unicode - the IME path must not go through the ASCII filter.
                const std::size_t sel_lo = std::min(caret_, sel_anchor_);
                const std::size_t sel_hi = std::max(caret_, sel_anchor_);
                const std::size_t sel_len = sel_hi - sel_lo;
                // batch101: the three other insertion paths (InsertText,
                // InsertSpace, OnChar) both honour max_chars_ and record an
                // undo step. This one did neither, so for a CJK user - whose
                // ONLY way to enter text is this path, since OnChar rejects
                // non-ASCII - a capped field accepted unbounded input and
                // Ctrl+Z did not undo the commit.
                if (max_chars_ != 0) {
                    const std::size_t used = value_.size() - sel_len;
                    if (used >= max_chars_) {
                        ++content_rev;
                        InvalidateLayout();
                        return;
                    }
                    const std::size_t room = max_chars_ - used;
                    if (result.size() > room) {
                        result.resize(room);
                    }
                }
                PushUndo();
                if (sel_len > 0) {
                    value_.erase(sel_lo, sel_len);
                }
                value_.insert(sel_lo, result);
                caret_ = sel_lo + result.size();
                sel_anchor_ = caret_;
                caret_visible_ = true;
                if (on_changed) {
                    on_changed();
                }
            }
            ++content_rev;
            InvalidateLayout();
        }

        bool TextInputElement::OnCaretBlinkTick() noexcept {
            caret_visible_ = !caret_visible_;
            ++content_rev;
            return true;
        }

        void TextInputElement::RenderCore(RenderCtx& ctx) {
            // batch18 U1: the input box joins the station's rounded-corner
            // language (radius_sm, same as buttons/badges) - the square fill
            // and stroke read as a foreign language next to the r=6 buttons.
            ctx.FillRoundedRect(bounds_, g_theme.radius_sm,
                                ColorFor(ColorToken::Panel));
            // T7: a focused input highlights its border (immediate) so the
            // active field is unmistakable; blur restores the quiet border.
            // batch17 P1-c (B-2/D3): the quiet border is InputBorder
            // (#6E6E6E, 3.27 vs panel, WCAG 1.4.11) - the decorative Border
            // token was only 1.23.
            ctx.StrokeRoundedRect(bounds_, g_theme.radius_sm,
                                  focused_ ? ColorFor(ColorToken::Accent)
                                           : ColorFor(ColorToken::InputBorder),
                                  focused_ ? 2.0f : 1.0f);
            ctx.ClipPush(bounds_);
            const Rect text_rect{bounds_.x + 6.0f, bounds_.y,
                                 std::max(bounds_.w - 12.0f, 0.0f), bounds_.h};
            // batch17 P1-d (B-3): the value is a single line (NO_WRAP layout:
            // DrawTextSingleLine). While focused, the text is shifted left by
            // just enough to keep the caret inside the right padding, so a
            // long value scrolls under the caret instead of wrapping into a
            // clipped second line with an invisible caret (the caret used to
            // be clipped away entirely). Blur/ellipsis remains a P3 item.
            float shift = 0.0f;
            float caret_x = 0.0f;
            if (focused_) {
                const std::wstring prefix = value_.substr(0, caret_);
                const Size prefix_size =
                    MeasureText(prefix, FontToken::Body, kUnboundedWidth);
                // batch19 R4-P2: caret grows from the logical leading edge -
                // the right edge under RTL - and the scroll clamp mirrors.
                if (I18n::Instance().IsRtl()) {
                    caret_x = bounds_.x + bounds_.w - 6.0f - prefix_size.w;
                    const float left_limit = bounds_.x + 6.0f;
                    if (caret_x < left_limit) {
                        shift = left_limit - caret_x;  // > 0: pull text right
                        caret_x = left_limit;
                    }
                } else {
                    caret_x = bounds_.x + 6.0f + prefix_size.w;
                    const float right_limit = bounds_.x + bounds_.w - 6.0f;
                    if (caret_x > right_limit) {
                        shift = right_limit - caret_x;  // < 0: pull left
                        caret_x = right_limit;
                    }
                }
            }
            // batch37i (user: "drag selection does nothing"): the selection
            // state existed but was never PAINTED - a drag looked like a plain
            // click. Draw the highlight behind the text, using the same prefix
            // metrics and the same horizontal shift as the caret.
            const std::size_t sel_lo = std::min(caret_, sel_anchor_);
            const std::size_t sel_hi = std::max(caret_, sel_anchor_);
            if (sel_hi > sel_lo) {
                // M7 prefix cache: no re-layout of every prefix on each paint.
                EnsurePrefixWidths();
                const float lo_w = prefix_w_[sel_lo];
                const float hi_w = prefix_w_[sel_hi];
                float x0 = 0.0f;
                float x1 = 0.0f;
                if (I18n::Instance().IsRtl()) {
                    const float base_r = text_rect.x + text_rect.w + shift;
                    x0 = base_r - hi_w;
                    x1 = base_r - lo_w;
                } else {
                    const float base = text_rect.x + shift;
                    x0 = base + lo_w;
                    x1 = base + hi_w;
                }
                // batch37q (user: focus looks wrong): only the FOCUSED input
                // paints the blue selection; an unfocused field keeps a dim
                // gray selection (the OS HideSelection behaviour), so the blue
                // border unambiguously shows which field has the caret. The
                // gray is deliberately light enough to stay visible on the
                // dark input background (0.45 of InputBorder was too faint).
                Color sel = focused_ ? ColorFor(ColorToken::Accent)
                                     : ColorFor(ColorToken::InputBorder);
                sel.a = focused_ ? 0.35f : 0.65f;
                ctx.FillRect(Rect{x0, bounds_.y + 4.0f,
                                  std::max(x1 - x0, 1.0f),
                                  std::max(bounds_.h - 8.0f, 1.0f)},
                             sel);
            }
            ctx.DrawTextSingleLine(
                value_, Rect{text_rect.x + shift, text_rect.y, text_rect.w,
                             text_rect.h},
                FontToken::Body,
                EffectivelyEnabled() ? ColorFor(ColorToken::Text)
                                     : ColorFor(ColorToken::TextDim));
            // batch24 P0-3 (IME): an active preedit is drawn inline at the
            // insertion point (underlined) with its own caret, pushing the
            // trailing value right - the standard inline composition look.
            if (!composition_.empty()) {
                const std::wstring prefix = value_.substr(0, caret_);
                const std::wstring suffix = value_.substr(caret_);
                const float base_x = text_rect.x + shift;
                const float prefix_w =
                    MeasureText(prefix, FontToken::Body, kUnboundedWidth).w;
                const float comp_x = base_x + prefix_w;
                const float comp_w = MeasureText(composition_, FontToken::Body,
                                                 kUnboundedWidth)
                                         .w;
                ctx.DrawTextSingleLine(
                    prefix, Rect{base_x, text_rect.y, text_rect.w,
                                 text_rect.h},
                    FontToken::Body, ColorFor(ColorToken::Text));
                ctx.DrawTextSingleLine(
                    composition_,
                    Rect{comp_x, text_rect.y, text_rect.w, text_rect.h},
                    FontToken::Body, ColorFor(ColorToken::Text));
                ctx.FillRect(Rect{comp_x, bounds_.y + bounds_.h - 5.0f,
                                  comp_w, 1.0f},
                             ColorFor(ColorToken::Accent));
                const std::wstring comp_prefix = composition_.substr(
                    0, composition_caret_);
                const float comp_caret_x =
                    comp_x + MeasureText(comp_prefix, FontToken::Body,
                                         kUnboundedWidth)
                                .w;
                ctx.FillRect(Rect{comp_caret_x, bounds_.y + 4.0f, 1.0f,
                                  std::max(bounds_.h - 8.0f, 1.0f)},
                             ColorFor(ColorToken::Text));
                ctx.DrawTextSingleLine(
                    suffix, Rect{comp_x + comp_w, text_rect.y, text_rect.w,
                                 text_rect.h},
                    FontToken::Body, ColorFor(ColorToken::Text));
                ctx.ClipPop();
                return;
            }
            // batch20 item 1: dim hint while empty (the About language filter had
            // no caption, so an empty box looked like an unexplained editor).
            if (value_.empty() && !placeholder_.empty()) {
                ctx.DrawTextSingleLine(
                    placeholder_,
                    Rect{text_rect.x, text_rect.y, text_rect.w, text_rect.h},
                    FontToken::Body, ColorFor(ColorToken::TextDim),
                    Align::Start);
            }
            if (focused_ && caret_visible_) {
                ctx.FillRect(Rect{caret_x, bounds_.y + 4.0f, 1.0f,
                                  std::max(bounds_.h - 8.0f, 1.0f)},
                             ColorFor(ColorToken::Text));
            }
            ctx.ClipPop();
        }

        void SelectElement::DrawCollapsed(RenderCtx& ctx) {
            std::wstring label;
            for (const auto& option : options_) {
                if (option.first == selected_) {
                    label = option.second;
                    break;
                }
            }
            if (label.empty() && !options_.empty()) {
                label = options_.front().second;
            }
            // batch19 terminal (user clarification of R7): ONLY the popup list
            // is square. The collapsed box stays rounded with the same
            // radius_sm contract as TextInput (R7 had wrongly squared the box
            // too). The focus accent stroke is preserved.
            ctx.FillRoundedRect(bounds_, g_theme.radius_sm,
                                ColorFor(ColorToken::Panel));
            // batch17 P1-c (B-2/D3): same InputBorder contract as TextInput
            // (colour/width), rounded like the fill.
            ctx.StrokeRoundedRect(bounds_, g_theme.radius_sm,
                                  focused_ ? ColorFor(ColorToken::Accent)
                                           : ColorFor(ColorToken::InputBorder),
                                  focused_ ? 2.0f : 1.0f);
            // batch17 P1-d (B-3/D5.3): the collapsed label is a NO_WRAP
            // single line and the text paint is clipped to the box. Without
            // the clip a long option label wrapped into a second line that
            // painted over the content below the select (audit B-3 images).
            // The border above stays outside the clip, so its 2 px focus
            // stroke is not shaved.
            ctx.ClipPush(bounds_);
            const std::wstring collapsed_label =
                EllipsizeToWidth(label, FontToken::Body,
                                 std::max(bounds_.w - 32.0f, 0.0f),
                                 MeasureText(L"x", FontToken::Body, 1.0f).w <=
                                     1.5f);
            ctx.DrawTextSingleLine(
                collapsed_label,
                Rect{bounds_.x + 10.0f, bounds_.y,
                     std::max(bounds_.w - 32.0f, 0.0f), bounds_.h},
                FontToken::Body,
                focused_ ? ColorFor(ColorToken::Accent)
                         : ColorFor(ColorToken::Text));
            ctx.DrawText(L"\u25BE",
                         Rect{bounds_.x + bounds_.w - 22.0f, bounds_.y, 16.0f,
                              bounds_.h},
                         FontToken::Small, ColorFor(ColorToken::TextDim),
                         Align::Center);
            ctx.ClipPop();
        }

        void SelectElement::DrawPopup(RenderCtx& ctx) {
            const float item_h = kSelectItemH;
            // batch24 P0-2: EXACT same geometry the hit/mouse paths use
            // (PopupRect flips the list above the box near the window/scroll
            // bottom so every option stays on-screen and clickable).
            const Rect list = PopupRect();
            const float list_x = list.x;
            const float list_y = list.y;
            const float list_w = list.w;
            // batch19 R7 (user call, overrides batch17 P2-b): the popup panel
            // is square (the row items were already FillRect; the rounded
            // outer panel clipped them into the "square rows in a rounded
            // frame" look the user rejected). Same rect, no rounding.
            ctx.FillRect(list, ColorFor(ColorToken::PanelAlt));
            // U1-D1: the popup border was ColorToken::Border (#2E2E2E), whose
            // luminance is only ~3.5% above the PanelAlt (#252525) fill - on a
            // dark theme the outline was essentially invisible, reading as "no
            // border". Keep the higher-contrast dim text tone so the dropdown
            // edge is clearly drawn (now a square outline).
            ctx.StrokeRect(list, ColorFor(ColorToken::TextDim), 1.0f);
            // batch33f: paint the CAPPED window of rows (the list scrolls
            // instead of growing past the visible domain).
            const std::size_t total = options_.size();
            const std::size_t top = (popup_top_ < total) ? popup_top_ : 0;
            const std::size_t rows =
                (std::min)(total - top, popup_rows_ == 0 ? total : popup_rows_);
            for (std::size_t r = 0; r < rows; ++r) {
                const std::size_t i = top + r;
                const Rect item{list_x,
                                list_y + item_h * static_cast<float>(r),
                                list_w, item_h};
                const bool selected = options_[i].first == selected_;
                if (selected) {
                    // Restrained row tint (never a full saturated block).
                    ctx.FillRect(item, Color{0.0f, 0.48f, 1.0f, 0.11f});
                    // batch19 terminal (aesthetic rework): the selection
                    // marker is the shell sidebar's short rounded pill, not a
                    // full-height 3 px bar. ~3.5 px wide, <= 20 px tall,
                    // radius 2, vertically centred, inset ~6 px from the
                    // leading edge (mirrored under RTL).
                    const bool rtl = I18n::Instance().IsRtl();
                    const float pill_h = std::min(20.0f, item.h - 8.0f);
                    const float pill_y = item.y + (item.h - pill_h) * 0.5f;
                    const float pill_w = 3.5f;
                    const float pill_x = rtl ? item.x + item.w - 6.0f - pill_w
                                             : item.x + 6.0f;
                    ctx.FillRoundedRect(Rect{pill_x, pill_y, pill_w, pill_h},
                                        2.0f, ColorFor(ColorToken::Accent));
                } else if (static_cast<int>(i) == hover_) {
                    ctx.FillRect(item, HoverOverlay(0.05f, 0.09f));
                }
                const std::wstring row_label = EllipsizeToWidth(
                    options_[i].second, FontToken::Body,
                    std::max(list_w - 20.0f, 0.0f),
                    MeasureText(L"x", FontToken::Body, 1.0f).w <= 1.5f);
                ctx.DrawText(row_label,
                             Rect{item.x + 12.0f, item.y,
                                  std::max(list_w - 20.0f, 0.0f), item_h},
                             FontToken::Body,
                             // batch17 P1-c (B-2): accent text on
                             // panel_alt failed AA (3.82); AccentText
                             // #66B2FF is 6.84 there.
                             selected ? ColorFor(ColorToken::AccentText)
                                      : ColorFor(ColorToken::Text));
            }
        }

        void SelectElement::RenderCore(RenderCtx& ctx) {
            DrawCollapsed(ctx);
            if (expanded_) {
                DrawPopup(ctx);
            }
        }

        void SelectElement::DrawPopupShadow(RenderCtx& ctx) {
            const Rect list = PopupRect();
            const Color shadow{0.0f, 0.0f, 0.0f, 0.20f};
            ctx.FillRoundedRect(Rect{list.x + 3.0f, list.y + list.h,
                                     list.w - 3.0f, 3.0f},
                                2.0f, shadow);
            ctx.FillRoundedRect(Rect{list.x + list.w, list.y + 3.0f, 3.0f,
                                     list.h - 3.0f},
                                2.0f, shadow);
        }

        void SelectElement::RenderOverlay(RenderCtx& ctx) {
            // Top-layer popup: drawn again after the content pass, free of any
            // ancestor (ScrollView) clip, so a long list is never cut off (G9).
            if (!visible || !EffectivelyEnabled() || !expanded_) {
                return;
            }
            DrawPopupShadow(ctx);
            DrawPopup(ctx);
        }

        Element* SelectElement::HitTestOverlay(Point p) {
            if (!visible || !EffectivelyEnabled() || !expanded_) {
                return nullptr;
            }
            // Mirrors RenderOverlay: the popup is a top-layer surface, so it
            // wins over a later sibling that Element::HitTest would pick.
            // batch24 P0-2: PopupRect() keeps hit and paint identical.
            return PopupRect().Contains(p) ? this : nullptr;
        }

        std::wstring SelectElement::tooltip_text(Point p) const {
            if (!EffectivelyEnabled()) {
                return std::wstring();
            }
            const auto overflows = [](const std::wstring& text,
                                      float available) {
                return !text.empty() && available > 0.0f &&
                       MeasureText(text, FontToken::Body, 1.0e9f).w >
                           available;
            };
            if (expanded_ && PopupRect().Contains(p)) {
                const float row = (p.y - PopupRect().y) / kSelectItemH;
                const std::size_t index =
                    popup_top_ +
                    static_cast<std::size_t>((std::max)(row, 0.0f));
                if (row >= 0.0f && index < options_.size() &&
                    static_cast<std::size_t>(row) <
                        (popup_rows_ == 0 ? options_.size() : popup_rows_)) {
                    const std::wstring& label = options_[index].second;
                    return overflows(label, PopupRect().w - 20.0f)
                               ? label
                               : std::wstring();
                }
            }
            for (const auto& option : options_) {
                if (option.first == selected_) {
                    return overflows(option.second, bounds_.w - 32.0f)
                               ? option.second
                               : std::wstring();
                }
            }
            return std::wstring();
        }

        void BadgeElement::RenderCore(RenderCtx& ctx) {
            // A stretched parent (page-header row, dashboard stack) must not
            // blow the pill up: paint at the content height, vertically
            // centered inside the given bounds (T12-F1 A1).
            const Size text = MeasureText(text_, FontToken::Small,
                                          kUnboundedWidth);
            const float content_h = std::max(20.0f, text.h + 6.0f);
            const float paint_h = std::min(content_h, bounds_.h);
            const Rect pill{bounds_.x,
                            bounds_.y +
                                std::max((bounds_.h - paint_h) * 0.5f, 0.0f),
                            bounds_.w, paint_h};
            Color fill = ColorFor(ColorToken::PanelAlt);
            switch (kind_) {
                case BadgeKind::Accent:
                    fill = ColorFor(ColorToken::Accent);
                    break;
                case BadgeKind::Success:
                    fill = ColorFor(ColorToken::Success);
                    break;
                case BadgeKind::Warning:
                    fill = ColorFor(ColorToken::Warning);
                    break;
                case BadgeKind::Danger:
                    fill = ColorFor(ColorToken::Danger);
                    break;
                default:
                    break;
            }
            ctx.FillRoundedRect(pill, g_theme.radius_sm, fill);
            // batch17 P1-c (B-2): white text failed WCAG AA on the warm
            // fills; they get the dark warm-fill text instead. Accent and
            // PanelAlt badges keep white.
            const bool warm = kind_ == BadgeKind::Success ||
                              kind_ == BadgeKind::Warning ||
                              kind_ == BadgeKind::Danger;
            ctx.DrawText(text_, pill, FontToken::Small,
                         warm ? WarmFillText() : ColorFor(ColorToken::Text),
                         Align::Center);
        }

        void ProgressBarElement::RenderCore(RenderCtx& ctx) {
            ctx.FillRect(bounds_, ColorFor(ColorToken::PanelAlt));
            const float filled = std::max(bounds_.w * value_, 0.0f);
            if (filled > 0.0f) {
                ctx.FillRect(Rect{bounds_.x, bounds_.y, filled, bounds_.h},
                             ColorFor(ColorToken::Accent));
            }
        }

        void DialogHost::RenderCore(RenderCtx& ctx) {
            if (Mode::None == mode_) {
                return;
            }
            const float e = EaseOut(open_t_);
            // Full-size dimmer over everything below the dialog; its alpha
            // ramps 0 -> 0.5 as the modal enters (T9 entrance).
            ctx.FillRect(bounds_, Color{0.0f, 0.0f, 0.0f, 0.5f * e});
            if (card_ != nullptr && card_->visible) {
                // Render-time scale 0.96 -> 1.0 around the card center; the
                // card's real bounds/HitTest stay at the settled geometry. The
                // card paints itself (scaled chrome) in the child pass right
                // after this, so no unscaled redraw covers the entrance.
                card_->SetRenderScale(0.96f + 0.04f * e);
            }
        }

        void DialogHost::AdvanceAnimation(float dt_seconds) {
            if (dt_seconds <= 0.0f || open_t_ >= 1.0f) {
                return;  // settled: stay inactive (clock may self-stop)
            }
            open_t_ = std::min(1.0f, open_t_ + dt_seconds / kDialogOpenSeconds);
        }

        bool DialogHost::HasActiveAnimation() const noexcept {
            return open_t_ < 1.0f;
        }

        void DialogHost::RenderOverlay(RenderCtx& ctx) {
            // Top layer: one full draw of the modal (dimmer + card + subtree),
            // after every page sibling, so page text can never pierce it (G4).
            // The content pass skipped this subtree via renders_on_top(), so
            // the translucent dimmer is composited exactly once.
            if (Mode::None == mode_) {
                return;
            }
            RenderCore(ctx);
            RenderChildren(ctx);
        }

        Element* DialogHost::HitTestOverlay(Point p) {
            if (Mode::None == mode_) {
                return nullptr;
            }
            // Inside the card the normal subtree hit test resolves the actual
            // control (buttons/fields stay clickable); outside the card the
            // dimmer swallows the point so the masked page stays inert.
            if (card_ != nullptr && card_->visible &&
                card_->bounds().Contains(p)) {
                if (Element* hit = Element::HitTest(p)) {
                    return hit;
                }
            }
            return this;
        }

        void Sidebar::RenderChildren(RenderCtx& ctx) {
            Element::RenderChildren(ctx);
            // Selected item: a 3 px accent bar flush with the selected button's
            // LEFT edge (inside the blue selection box, just before the label).
            // U1-D5: the bar used to be pinned to
            // bounds_.x + 6 (the sidebar's outer gutter), which sat ~6 px left of
            // the button and read as "outside the box".
            const std::size_t index = selected_index();
            if (index < buttons_.size() && buttons_[index] != nullptr &&
                buttons_[index]->visible && buttons_[index]->bounds().w > 0.0f) {
                const Rect item = buttons_[index]->bounds();
                // batch19 R4-P2: the accent bar mirrors to the item's right
                // edge under RTL.
                const float bar_x =
                    I18n::Instance().IsRtl()
                        ? item.x + item.w - 4.0f - kIndicatorWidth
                        : item.x + 4.0f;
                const Rect bar{bar_x, item.y + 6.0f, kIndicatorWidth,
                                std::max(item.h - 12.0f, 4.0f)};
                ctx.FillRoundedRect(bar, 1.5f, ColorFor(ColorToken::Accent));
            }
        }

        void ToastHost::RenderCore(RenderCtx& ctx) {
            constexpr float kToastW = 240.0f;
            constexpr float kToastH = 36.0f;
            constexpr float kToastGap = 8.0f;
            constexpr float kToastMargin = 16.0f;
            const float right = bounds_.x + bounds_.w;
            const float bottom = bounds_.y + bounds_.h;
            for (std::size_t i = 0; i < toasts_.size(); ++i) {
                const ToastEntry& entry = toasts_[toasts_.size() - 1 - i];
                const float y = bottom - kToastMargin - kToastH -
                                static_cast<float>(i) * (kToastH + kToastGap);
                // T9 entrance: slide in from +24 px (eased) toward the settled
                // x; the alpha ramps with the same eased progress. Both are
                // render-time only - the toast never enters the layout.
                  const float e = EaseOut(entry.t);
                  // batch19 R4-P2: toasts anchor to the left in RTL.
                  const bool rtl = I18n::Instance().IsRtl();
                  const float base_x = rtl
                                           ? bounds_.x + kToastMargin
                                           : right - kToastMargin - kToastW;
                  const float x = base_x + (rtl ? -24.0f : 24.0f) * (1.0f - e);
                const Rect toast{x, y, kToastW, kToastH};
                Color fill = ColorFor(ColorToken::Panel);
                switch (entry.kind) {
                    case ToastKind::Success:
                        fill = ColorFor(ColorToken::Success);
                        break;
                    case ToastKind::Warning:
                        fill = ColorFor(ColorToken::Warning);
                        break;
                    case ToastKind::Danger:
                        fill = ColorFor(ColorToken::Danger);
                        break;
                    default:
                        break;
                }
                fill.a *= e;  // T9: fade in with the slide
                ctx.FillRoundedRect(toast, g_theme.radius_sm, fill);
                const std::wstring label = entry.raw_text.empty()
                                               ? I18n::Instance().T(entry.text)
                                               : entry.raw_text;
                // batch17 P1-c (B-2): dark text on the warm fills (same
                // WCAG pair table as Badge); Info keeps the normal text.
                const bool warm = entry.kind == ToastKind::Success ||
                                  entry.kind == ToastKind::Warning ||
                                  entry.kind == ToastKind::Danger;
                Color text_color = warm ? WarmFillText()
                                        : ColorFor(ColorToken::Text);
                text_color.a *= e;
                ctx.DrawText(label, toast, FontToken::Body, text_color,
                             Align::Center);
            }
        }

        void ToastHost::RenderOverlay(RenderCtx& ctx) {
            // Top layer, painted last (the shell adds toasts after dialogs) so
            // notifications always sit above a modal.
            RenderCore(ctx);
        }

        // --- LinkElement (batch19 terminal) --------------------------------
        namespace {
            constexpr float kLinkArrowGap = 4.0f;

            long long DefaultOpenExternalUrl(const std::wstring& url) {
                const HINSTANCE r = ::ShellExecuteW(nullptr, L"open", url.c_str(),
                                                    nullptr, nullptr,
                                                    SW_SHOWNORMAL);
                return static_cast<long long>(reinterpret_cast<INT_PTR>(r));
            }
        }  // namespace

        std::function<long long(const std::wstring&)>& OpenExternalUrlHandler() {
            static std::function<long long(const std::wstring&)> handler =
                DefaultOpenExternalUrl;
            return handler;
        }

        LinkElement::LinkElement(std::wstring text, std::wstring url)
            : text_(std::move(text)), url_(std::move(url)) {}

        void LinkElement::SetText(std::wstring text) {
            if (text_ == text) {
                return;
            }
            text_ = std::move(text);
            InvalidateLayout();
        }

        void LinkElement::SetUrl(std::wstring url) { url_ = std::move(url); }

        void LinkElement::Activate() {
            const long long result = OpenExternalUrlHandler()(url_);
            if (on_activate) {
                on_activate(url_, result);
            }
        }

        bool LinkElement::OnMouseDown(Point) {
            pressed_ = true;
            return true;  // a hyperlink is never disabled
        }

        bool LinkElement::OnMouseUp(Point p) {
            if (!pressed_) {
                return false;
            }
            pressed_ = false;
            if (bounds_.Contains(p)) {
                Activate();
            }
            return true;
        }

        bool LinkElement::OnMouseMove(Point p) {
            const bool inside = bounds_.Contains(p);
            if (inside != hover_) {
                hover_ = inside;
                ++content_rev;  // hover underline/brighten are visual only
                RequestAnimationFrame();  // batch27: ease the colour
            }
            return false;
        }

        // batch27 P1-15: identical easing to Button::AdvanceAnimation, so the
        // hover transition duration is one shared constant (kHoverSeconds).
        void LinkElement::AdvanceAnimation(float dt_seconds) {
            if (dt_seconds <= 0.0f) {
                return;
            }
            const float target = hover_ ? 1.0f : 0.0f;
            if (hover_t_ == target) {
                return;
            }
            const float step = dt_seconds / kHoverSeconds;
            if (hover_t_ < target) {
                hover_t_ = std::min(target, hover_t_ + step);
            } else {
                hover_t_ = std::max(target, hover_t_ - step);
            }
        }

        bool LinkElement::HasActiveAnimation() const noexcept {
            return hover_t_ != (hover_ ? 1.0f : 0.0f);
        }

        bool LinkElement::OnKeyDown(uint32_t vk) {
            if (vk == kVkReturn || vk == kVkSpace) {
                Activate();
                return true;
            }
            return false;
        }

        void LinkElement::OnFocus(bool focused) {
            if (focused_ == focused) {
                return;
            }
            focused_ = focused;
            ++content_rev;  // focus underline is visual only
        }

        Size LinkElement::MeasureCore(Size) {
            const Size t = MeasureText(text_, FontToken::Body, kUnboundedWidth);
            const Size arrow =
                MeasureText(L"\u2197", FontToken::Small, kUnboundedWidth);
            const float w = t.w + (arrow.w > 0.0f ? kLinkArrowGap + arrow.w : 0.0f);
            return Size{w, (std::max)(t.h, arrow.h)};
        }

        void LinkElement::RenderCore(RenderCtx& ctx) {
            const Color accent = ColorFor(ColorToken::Accent);
            // Hover brightens the accent (spec: brighten); focus also
            // underlines.
            // batch27 P1-15: the brighten eases over kHoverSeconds like the
            // Button fill (one shared hover duration across control families).
            const Color text_color =
                LerpColor(accent, ScaleRgb(accent, 1.15f), hover_t_);
            const Size t = MeasureText(text_, FontToken::Body, kUnboundedWidth);
            ctx.DrawText(text_, Rect{bounds_.x, bounds_.y, t.w, bounds_.h},
                         FontToken::Body, text_color, Align::Start);
            float right = bounds_.x + t.w;
            const Size arrow =
                MeasureText(L"\u2197", FontToken::Small, kUnboundedWidth);
            if (arrow.w > 0.0f) {
                const float ax = bounds_.x + t.w + kLinkArrowGap;
                ctx.DrawText(L"\u2197", Rect{ax, bounds_.y, arrow.w, bounds_.h},
                             FontToken::Small, text_color, Align::Start);
                right = ax + arrow.w;
            }
            if (underlined()) {
                ctx.FillRect(Rect{bounds_.x, bounds_.y + bounds_.h - 1.0f,
                                  right - bounds_.x, 1.0f},
                             text_color);
            }
            if (focus_ring_ && focused_) {
                ctx.StrokeRect(bounds_, ColorFor(ColorToken::Text), 2.0f);
            }
        }

    }  // namespace ui
}  // namespace vgww
