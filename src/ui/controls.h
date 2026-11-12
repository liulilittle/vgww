// ============================================================================
// controls.h - basic containers and controls (S4.2 Task 2): StackPanel,
// GridLayout, Card, Separator, Text, Button, Checkbox. Data controls
// (Table/ScrollView/TextInput/Select/Badge/ProgressBar/Dialog/ToastHost)
// arrive with Task 3 in this same header.
// ============================================================================
#pragma once

#include "ui/element.h"
#include "ui/i18n.h"

#include <chrono>
#include <cstddef>
#include <functional>
#include <map>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace vgww {
    namespace ui {

        // batch24 P2-6: LanguagePicker (defined before TextInputElement below)
        // owns an internal search editor; forward declaration + out-of-line
        // destructor keep the unique_ptr member legal with the incomplete type.
        class TextInputElement;

        /// batch37i: shared CF_UNICODETEXT helpers (text fields + console).
        /// batch285: reports whether the text reached the clipboard. The
        /// old void signature let callers assume success (and Cut delete the
        /// selection) after a write that never happened.
        bool SetClipboardText(const std::wstring& text);

        enum class Orientation { Horizontal, Vertical };

        struct Padding {
            float l = 0.0f;
            float t = 0.0f;
            float r = 0.0f;
            float b = 0.0f;
            float horizontal() const noexcept { return l + r; }
            float vertical() const noexcept { return t + b; }
        };

        enum class Align { Start, Center, End, Stretch };

        /// Single-axis container: main axis = sum of child desired + gap *
        /// (n - 1) + padding; cross axis = max child + padding. Children are
        /// stretched on the cross axis unless `child_align` says otherwise.
        class StackPanel : public Element {
        public:
            explicit StackPanel(Orientation orientation, float gap = 0.0f,
                                Padding padding = {},
                                Align child_align = Align::Stretch);
            Orientation orientation() const noexcept { return orientation_; }
            float gap() const noexcept { return gap_; }
            const Padding& padding() const noexcept { return padding_; }
            Align child_align() const noexcept { return child_align_; }

            /// T9 page entrance: starts a fade-in (progress 0) and spins the
            /// frame clock. Render-time only: children/bounds are untouched.
            void BeginEntrance() noexcept;
            /// T9 test anchor: entrance progress in [0, 1] (1 = settled).
            float entrance_progress() const noexcept { return entrance_t_; }

            /// T9: advances the fade-in over `kPageOpenSeconds`; the frame
            /// clock stops once settled.
            void AdvanceAnimation(float dt_seconds) override;
            bool HasActiveAnimation() const noexcept override;

        protected:
            Size MeasureCore(Size available) override;
            void ArrangeCore(Rect final_rect) override;
            void RenderChildren(RenderCtx& ctx) override;

        private:
            /// M9 (batch4): per-child measurement memo consulted by BOTH
            /// StackPanel sites - MeasureCore's child probe (controls.cpp:92)
            /// and ArrangeCore's placement probe (controls.cpp:129). A hit
            /// means: the child cache is valid, no MeasureCore ran since the
            /// entry was stored or refreshed, the measure-hook generation is
            /// unchanged and the FULL available size equals the key, so the
            /// stored value was measured at exactly this available. Two slots
            /// per child absorb the inner != content alternation (the stack
            /// not filled to its available); a single slot degrades to the
            /// un-memoized behaviour (fallback Measure), never to a wrong
            /// value.
            struct ChildFlowMemo {
                Size avail{};          ///< full available-size key
                Size desired{};        ///< child->Measure(avail) result at store
                uint64_t gen = 0;      ///< child measure_gen at store/refresh
                uint64_t gen_key = 0;  ///< TextMeasureGeneration at store
                bool valid = false;
            };
            struct ChildFlowMemos {
                ChildFlowMemo slot[2];
            };

            /// Measured value for `avail` when the memo still holds, else
            /// nullptr (the caller falls back to child->Measure).
            const Size* FlowMemoLookup(std::size_t index, const Element& child,
                                       Size avail) const noexcept;
            /// Store a freshly measured value (rotates the two slots).
            void FlowMemoStore(std::size_t index, const Element& child,
                               Size avail, Size desired) noexcept;
            /// After child->Arrange: re-sync the entries' generation so the
            /// Arrange-time Measure (at the final rect size) does not
            /// invalidate a value that is still the exact measurement for its
            /// own key.
            void FlowMemoRefresh(std::size_t index, const Element& child) noexcept;
            /// Keeps flow_memos_ sized to children_ (a rebuilt container
            /// swaps its children wholesale; a size mismatch resets every
            /// memo so no slot can ever answer for a different child object).
            void EnsureFlowMemos();

            Orientation orientation_;
            float gap_;
            Padding padding_;
            Align child_align_;
            /// M9 (batch4): one entry per children_ index; see ChildFlowMemo.
            std::vector<ChildFlowMemos> flow_memos_;
            /// T9 entrance progress [0, 1]; 1 = settled (no fade).
            float entrance_t_ = 1.0f;
        };

        /// One grid column: fixed pixels (star == 0) or a proportional share
        /// of the leftover width.
        struct ColumnSpec {
            float fixed = 0.0f;
            float star = 0.0f;
            static ColumnSpec Fixed(float px) noexcept;
            static ColumnSpec Star(float weight = 1.0f) noexcept;
        };

        /// Row-major grid: children fill cells left to right, top to bottom.
        /// Column widths = fixed sum + star shares of the remainder; row
        /// heights = max desired height in the row.
        class GridLayout : public Element {
        public:
            explicit GridLayout(std::vector<ColumnSpec> cols, float gap = 0.0f,
                                Padding padding = {});
            const std::vector<ColumnSpec>& cols() const noexcept { return cols_; }
            float gap() const noexcept { return gap_; }
            const Padding& padding() const noexcept { return padding_; }

        protected:
            Size MeasureCore(Size available) override;
            void ArrangeCore(Rect final_rect) override;

        private:
            std::vector<float> ColumnWidths(float available_width) const;

            /// B5-4: per-child measurement memo, the same four-element key as
            /// the StackPanel M9 memo (full available size + child
            /// desired_valid + child measure_gen + TextMeasureGeneration). A
            /// hit hands out a value previously measured at exactly this
            /// available size; a miss falls back to the unchanged Measure.
            /// Defined locally on purpose: the batch4-verified StackPanel
            /// implementation stays untouched (audit 4.2: "implement the four
            /// equivalent helpers in place").
            struct ChildFlowMemo {
                Size avail{};          ///< full available-size key
                Size desired{};        ///< child->Measure(avail) result at store
                uint64_t gen = 0;      ///< child measure_gen at store/refresh
                uint64_t gen_key = 0;  ///< TextMeasureGeneration at store
                bool valid = false;
            };
            struct ChildFlowMemos {
                ChildFlowMemo slot[2];
            };

            const Size* FlowMemoLookup(std::size_t index, const Element& child,
                                       Size avail) const noexcept;
            void FlowMemoStore(std::size_t index, const Element& child,
                               Size avail, Size desired) noexcept;
            /// After child->Arrange: re-sync the entries' generation so the
            /// Arrange-time Measure (at the final cell size) does not
            /// invalidate a value that is still the exact measurement for its
            /// own key.
            void FlowMemoRefresh(std::size_t index, const Element& child) noexcept;
            /// Keeps flow_memos_ sized to children_ (a rebuilt grid resets
            /// every memo so no slot can answer for a different child).
            void EnsureFlowMemos();

            std::vector<ColumnSpec> cols_;
            float gap_;
            Padding padding_;
            /// B5-4: one entry per children_ index; see ChildFlowMemo.
            std::vector<ChildFlowMemos> flow_memos_;
        };

        /// Padded surface (visual chrome is drawn by the renderer, T6).
        class Card : public Element {
        public:
            explicit Card(Padding padding = {}, float radius = 8.0f);
            const Padding& padding() const noexcept { return padding_; }
            float radius() const noexcept { return radius_; }

            /// T9: render-time uniform scale of the card chrome around its
            /// center (1.0 = settled). Purely a paint-time derivation - bounds
            /// and HitTest stay at the arranged geometry, so a dialog entrance
            /// can pop the card without disturbing layout.
            void SetRenderScale(float scale) noexcept { render_scale_ = scale; }

        protected:
            Size MeasureCore(Size available) override;
            void ArrangeCore(Rect final_rect) override;
            void RenderCore(RenderCtx& ctx) override;

        private:
            Padding padding_;
            float radius_;
            float render_scale_ = 1.0f;
        };

        /// One-pixel horizontal rule.
        class Separator : public Element {
        public:
            Separator();

        protected:
            Size MeasureCore(Size available) override;
            void RenderCore(RenderCtx& ctx) override;
        };

        /// Single-style text block with optional wrapping and horizontal
        /// alignment. SetText() bumps content_rev and invalidates the layout.
        class Text : public Element {
        public:
            explicit Text(std::wstring text, FontToken font = FontToken::Body,
                          ColorToken color = ColorToken::Text, bool wrap = false,
                          Align align = Align::Start);
            void SetText(std::wstring text);
            /// batch24 P2-9b: switch the text colour (e.g. Warning -> Danger
            /// when the bound adapter is unusable).
            void SetColor(ColorToken color);
            const std::wstring& text() const noexcept { return text_; }
            FontToken font() const noexcept { return font_; }
            ColorToken color() const noexcept { return color_; }
            bool wrap() const noexcept { return wrap_; }
            Align align() const noexcept { return align_; }
            /// batch26: full text when the painted line does not fit.
            std::wstring tooltip_text(Point) const override;

            const char* debug_role() const override { return "Text"; }
            /// batch27: expose the text/colour role so the audit channel can
            /// verify semantic colour usage (e.g. a healthy diagnostic line is
            /// neutral, never Warning) without reading pixels.
            void debug_state(DebugStateSink& s) const override {
                DebugWrite(s, "text", text_);
                DebugWrite(s, "color",
                           static_cast<long long>(static_cast<int>(color_)));
                DebugWrite(s, "font",
                           static_cast<long long>(static_cast<int>(font_)));
                DebugWrite(s, "wrap", wrap_);
            }

        protected:
            Size MeasureCore(Size available) override;
            void RenderCore(RenderCtx& ctx) override;

        private:
            std::wstring text_;
            FontToken font_;
            ColorToken color_;
            bool wrap_;
            Align align_;
            /// M3b: single-slot natural-measure memo keyed by content_rev.
            /// Only the unconstrained (kUnboundedWidth) measurement is cached;
            /// the wrap arithmetic below still runs every frame. SetText bumps
            /// content_rev, which invalidates the token automatically.
            /// B5-1: the measure-hook generation is part of the key too, so a
            /// hook swap (renderer Init/Shutdown) can never serve an old-hook
            /// value once MeasureCore is re-run.
            uint64_t measure_memo_rev_ = 0;
            uint64_t measure_memo_gen_ = 0;
            Size measure_memo_sz_{};
            bool measure_memo_valid_ = false;
        };

        enum class ButtonStyle { Primary, Secondary, Danger, DangerOutline };

        /// Push button: fires on_click exactly once per completed click
        /// (mouse down+up inside) or Enter/Space key press while focused.
        class Button : public Element {
        public:
            explicit Button(std::wstring label,
                            ButtonStyle style = ButtonStyle::Secondary);
            std::function<void()> on_click;
            void SetLabel(std::wstring label);
            const std::wstring& label() const noexcept { return label_; }
            /// batch27 D6: a Button's visual weight can change at runtime (the
            /// dashboard's start/stop action is Primary only while stopped -
            /// the strip never carries two competing primary buttons).
            void SetStyle(ButtonStyle style) noexcept {
                if (style == style_) {
                    return;
                }
                style_ = style;
                ++content_rev;
            }
            ButtonStyle style() const noexcept { return style_; }
            /// S5-AESTH: sidebar nav labels are left-aligned; the default
            /// (buttons inside dialogs/forms) stays centered.
            void SetTextAlign(Align align) noexcept { text_align_ = align; }
            Align text_align() const noexcept { return text_align_; }
            /// Left gutter for Start-aligned labels (sidebar nav: keeps the
            /// 3 px selection bar from sitting on the first glyph).
            void SetTextIndent(float px) noexcept { text_indent_ = px; }
            /// batch17 P2-b (B-5): whether a Secondary button paints its
            /// 1 px rest-state edge. Default true - an in-card Secondary
            /// button's fill equals the card fill and needs the boundary to
            /// read as a control. The sidebar's navigation list opts out
            /// (list items follow the navigation language, and the rest edge
            /// would add one op per item on every page).
            void SetRestOutline(bool on) noexcept { rest_outline_ = on; }
            bool rest_outline() const noexcept { return rest_outline_; }
            /// batch18 U4: whether a focused button paints its 2 px white
            /// focus ring. Default false (user design call: no focus border);
            /// the paint path stays in the code and per-control accessibility
            /// scenarios may re-enable it.
            void SetFocusRing(bool on) noexcept { focus_ring_ = on; }
            bool focus_ring() const noexcept { return focus_ring_; }

            bool focusable() const override { return true; }
            /// batch26 P1: clickable controls advertise the hand cursor (the
            /// disabled state keeps the arrow).
            CursorKind cursor_hint(Point) const noexcept override {
                return EffectivelyEnabled() ? CursorKind::Hand
                                            : CursorKind::Arrow;
            }
            bool OnMouseDown(Point p) override;
            bool OnMouseUp(Point p) override;
            bool OnKeyDown(uint32_t vk) override;
            bool OnMouseMove(Point p) override;
            void OnFocus(bool focused) override;
            /// T7: smooths the hover background over `kHoverSeconds`; the
            /// frame clock advances this and stops once the target is reached.
            void AdvanceAnimation(float dt_seconds) override;
            bool HasActiveAnimation() const noexcept override;

            /// Test/debug seam: hover interpolation progress in [0, 1]
            /// (0 = rest fill, 1 = hover fill).
            float hover_progress() const noexcept { return hover_t_; }
            bool hovered() const noexcept { return hover_; }
            bool focused() const noexcept { return focused_; }

            const char* debug_role() const override { return "Button"; }
            void debug_state(DebugStateSink& s) const override {
                DebugWrite(s, "label", label_);
                // batch27: expose the visual weight so the audit/debug channel
                // can verify "at most one primary per surface" without pixels.
                DebugWrite(s, "style", static_cast<long long>(
                                          static_cast<int>(style_)));
                DebugWrite(s, "pressed", pressed_);
                DebugWrite(s, "hover", hover_);
                DebugWrite(s, "hover_progress", static_cast<double>(hover_t_));
                DebugWrite(s, "focused", focused_);
                DebugWrite(s, "focus_ring", focus_ring_);
                DebugWrite(s, "has_active_animation", HasActiveAnimation());
            }

        protected:
            Size MeasureCore(Size available) override;
            void RenderCore(RenderCtx& ctx) override;

        private:
            void Fire();

            std::wstring label_;
            ButtonStyle style_;
            Align text_align_ = Align::Center;
            float text_indent_ = 0.0f;
            bool pressed_ = false;
            bool hover_ = false;
            /// M3b: single-slot natural-measure memo keyed by content_rev
            /// (SetLabel bumps it, so the token self-invalidates). B5-1: the
            /// measure-hook generation is part of the key too.
            uint64_t measure_memo_rev_ = 0;
            uint64_t measure_memo_gen_ = 0;
            Size measure_memo_sz_{};
            bool measure_memo_valid_ = false;
            /// T7: hover background transition progress in [0, 1]; driven by the
            /// window frame clock (AdvanceAnimation) toward hover_?1:0.
            float hover_t_ = 0.0f;
            /// T7 focus ring: set by window focus (OnFocus), drawn immediately.
            bool focused_ = false;
            /// batch17 P2-b (B-5): Secondary rest-state edge (see
            /// SetRestOutline). Default true.
            bool rest_outline_ = true;
            /// batch18 U4: the focus ring is opt-in (see SetFocusRing).
            bool focus_ring_ = false;
        };

        /// Single-choice segmented control (T3-F2): N >= 2 fixed segments of
        /// equal width. Focusable; Left/Right cycles the selection with
        /// wrap-around; a click selects the segment under the pointer.
        /// on_changed fires exactly once per user selection change; disabled
        /// makes the whole control inert.
        class SegmentedControl : public Element {
        public:
            explicit SegmentedControl(std::vector<std::wstring> labels);

            std::size_t index() const noexcept { return index_; }
            const std::vector<std::wstring>& labels() const noexcept {
                return labels_;
            }
            /// User-facing selection change: fires on_changed exactly once per
            /// actual change; no-change and out-of-range requests are no-ops.
            bool SetIndex(std::size_t index);
            /// Programmatic selection (initialization/restore): never fires
            /// on_changed; out-of-range is ignored.
            void SetSelected(std::size_t index) noexcept;
            /// Refreshes the segment labels (language switch); the selection
            /// is preserved when still in range, else reset to 0.
            void SetLabels(std::vector<std::wstring> labels);

            std::function<void(std::size_t)> on_changed;

            bool focusable() const override { return true; }
            bool OnKeyDown(uint32_t vk) override;
            bool OnMouseDown(Point p) override;
            bool OnMouseMove(Point p) override;

        protected:
            Size MeasureCore(Size available) override;
            void RenderCore(RenderCtx& ctx) override;

        private:
            /// Segment index under `p`, or -1 when outside the control.
            int HitSegment(Point p) const noexcept;

            std::vector<std::wstring> labels_;
            std::size_t index_ = 0;
            int hover_ = -1;

        public:
            const char* debug_role() const override { return "Segmented"; }
            void debug_state(DebugStateSink& s) const override {
                DebugWrite(s, "index", static_cast<long long>(index_));
            }
        };

        /// Checkbox: `checked` flips exactly once per click or Space press;
        /// on_changed receives the new value.
        class Checkbox : public Element {
        public:
            explicit Checkbox(bool checked = false);
            bool checked = false;
            std::function<void(bool)> on_changed;
            /// batch25a: programmatic state change that repaints (the public
            /// `checked` field stays raw for existing call sites).
            void SetChecked(bool value);
            /// batch25a: draw the box as a radio circle. The checkbox keeps
            /// its toggle semantics; exclusive groups enforce the selection.
            void SetRadioStyle(bool on);
            bool radio_style() const noexcept { return radio_; }

            bool focusable() const override { return true; }
            bool OnMouseDown(Point p) override;
            bool OnMouseUp(Point p) override;
            bool OnKeyDown(uint32_t vk) override;
            void OnFocus(bool focused) override;

        protected:
            Size MeasureCore(Size available) override;
            /// batch33s: a stretched flow row must not turn the control into an
            /// ellipse. A 16 px box stretched to the row height painted as
            /// 16x17.34 (a rounded rect, not a circle). Keep it square and
            /// centred on the row's cross axis.
            void ArrangeCore(Rect final_rect) override;
            void RenderCore(RenderCtx& ctx) override;

        private:
            void Toggle();

            bool pressed_ = false;
            bool focused_ = false;
            bool radio_ = false;
            /// batch18 U4: the focus ring is opt-in (see SetFocusRing).
            bool focus_ring_ = false;

        public:
            const char* debug_role() const override { return "Checkbox"; }
            bool pressed() const noexcept { return pressed_; }
            bool focused() const noexcept { return focused_; }
            /// batch18 U4: same opt-in focus-ring contract as Button.
            void SetFocusRing(bool on) noexcept { focus_ring_ = on; }
            bool focus_ring() const noexcept { return focus_ring_; }
            void debug_state(DebugStateSink& s) const override {
                DebugWrite(s, "checked", checked);
            }
        };

        // -------------------------------------------------------------------
        // Task 3 additions: data controls and overlays.
        // -------------------------------------------------------------------

        /// Vertical scroller around a single owned content element (added at
        /// construction). Wheel scrolling clamps to [0, content_h - view_h].
        class ScrollView : public Element {
        public:
            explicit ScrollView(std::unique_ptr<Element> content);
            void SetOffset(float offset);
            float offset() const noexcept { return offset_; }
            float content_height() const noexcept { return content_h_; }
            float view_height() const noexcept { return view_h_; }
            /// Number of wheel events consumed (monotonic, for tests).
            std::size_t wheel_events() const noexcept { return wheel_events_; }
            /// batch33n: extra space kept BELOW the content so the last child's
            /// bottom edge (its 1 px border) is never clipped by the viewport
            /// edge. A form whose content height equals the viewport height used
            /// to lose the bottom border of its last input - the box looked
            /// "covered" even though the geometry was exact.
            void SetContentBottomInset(float inset) noexcept {
                content_bottom_inset_ = std::max(inset, 0.0f);
            }
            float content_bottom_inset() const noexcept {
                return content_bottom_inset_;
            }

            bool OnWheel(int delta) override;
            /// batch33p (user: "no scrollbar - rely on the wheel and the arrow
            /// keys"): keyboard scrolling. Up/Down move one line, PageUp/PageDown
            /// one viewport, Home/End jump to the ends. Returns true only when
            /// the offset actually moved, so an unconsumed key keeps bubbling.
            /// NOTE: the viewport is deliberately NOT focusable - putting it in
            /// the Tab chain would make every page add a tab stop that paints no
            /// focus ring. The window instead routes the keys to the container
            /// nearest the pointer (RouteKey fallback), exactly like the wheel.
            bool OnKeyDown(uint32_t vk) override;
            /// batch34x: opt this viewport into RouteKey's pointer-nearest
            /// keyboard fallback without naming the concrete type there.
            bool IsScrollContainer() const noexcept override { return true; }
            /// One keyboard scroll step in logical pixels.
            static constexpr float kKeyScrollStep = 48.0f;
            /// batch33 F: scroll so `target` (a descendant) sits at the top of
            /// the viewport, clamped to [0, content_h - view_h]. Used by the
            /// dashboard's "open the details" intent.
            void ScrollIntoView(const Element* target);
            /// Scroll content is clipped to the viewport: points outside the
            /// ScrollView box never hit (U3 keeps the base-class outside-probe
            /// from reaching clipped-off content).
            Element* HitTest(Point p) override;

        protected:
            Size MeasureCore(Size available) override;
            void ArrangeCore(Rect final_rect) override;
            void RenderChildren(RenderCtx& ctx) override;

        private:
            Element* Content() const noexcept;
            void ClampOffset() noexcept;

            float offset_ = 0.0f;
            float content_h_ = 0.0f;
            float view_h_ = 0.0f;
            /// batch37g: the content width last used by ArrangeCore (viewport
            /// minus the 1 px clip gutter). SetOffset must use the SAME width;
            /// the raw viewport width shifted every scrolled frame by 1 px.
            float content_w_ = 0.0f;
            std::size_t wheel_events_ = 0;
            /// batch33n: space reserved under the content (see the setter).
            float content_bottom_inset_ = 0.0f;

        public:
            const char* debug_role() const override { return "ScrollView"; }
            void debug_state(DebugStateSink& s) const override {
                DebugWrite(s, "offset", static_cast<double>(offset_));
            }
        };

        struct TableColumn {
            std::string id;
            Str header = Str::_Count;
            /// D5: relative width weight (was a fixed pixel width). The table
            /// scales the weights so the columns fill the arranged width; the
            /// proportions between columns are preserved. A single column
            /// therefore fills the whole table.
            float width = 100.0f;
            Align align = Align::Start;
            /// R4b: optional hard cap on the column's resolved width. When
            /// > 0 the column is clamped to this many px after the
            /// proportional fill and the released surplus is re-distributed
            /// to the un-capped columns by weight, so the table still fills
            /// the available width exactly. 0 (default) means no cap.
            float max_width = 0.0f;
            /// batch29: derive this column's share from the MEASURED content
            /// (widest cell / header + 2 x column inset) instead of the fixed
            /// `width` weight. When any column sets it, the table resolves
            /// every width from content; the natural widths are cached against
            /// the row/column content revision, so an unchanged table never
            /// re-measures.
            bool auto_width = false;

            /// S5.19: SetColumns must skip re-layout when the payload is
            /// unchanged (the snapshot tick rebuilds identical columns every
            /// 500ms; content equality is the no-op signal).
            bool operator==(const TableColumn& other) const noexcept {
                return id == other.id && header == other.header &&
                       width == other.width && align == other.align &&
                       max_width == other.max_width &&
                       auto_width == other.auto_width;
            }
        };

        struct TableRow {
            std::string row_id;
            std::vector<std::wstring> cells;
            bool danger = false;

            /// S5.19: SetRows must skip re-layout when the payload is
            /// unchanged (the snapshot tick rebuilds identical rows every
            /// 500ms; content equality is the no-op signal).
            bool operator==(const TableRow& other) const noexcept {
                return row_id == other.row_id && cells == other.cells &&
                       danger == other.danger;
            }
        };

        /// Virtualized data table: only visible rows (plus 2 overscan rows)
        /// get cell text layouts, so a 1000-row table stays cheap. The table
        /// scrolls itself (offset/viewport = its arranged height).
        class TableElement : public Element {
        public:
            TableElement();
            void SetColumns(std::vector<TableColumn> cols);
            void SetRows(std::vector<TableRow> rows);
            /// Per-row action buttons (labels); hit zones always exist, the
            /// buttons are only painted for the hovered row (T6).
            void SetRowActions(std::vector<Str> action_labels);
            std::function<void(const std::string& row_id, std::size_t action_index)> on_row_action;
            std::function<void(const std::string& row_id)> on_row_click;
            /// batch33 E: right-click on a data row (the row id + the client
            /// point of the click, so the page can open a ContextMenu there).
            std::function<void(const std::string& row_id, Point at)> on_row_context;

            /// Rows that actually got cell text layouts in the last measure.
            std::size_t visible_row_count() const noexcept { return visible_rows_; }
            std::size_t first_visible_row() const noexcept { return first_row_; }
            /// Number of cell text layouts established in the last measure.
            std::size_t text_layout_count() const noexcept { return text_layouts_; }
            std::size_t row_count() const noexcept { return rows_.size(); }
            /// batch22 A2 test seam: the current rows in display order (used to
            /// assert the dashboard's client filter/sort result).
            const std::vector<TableRow>& rows() const noexcept { return rows_; }
            /// M10-1 test/perf seam: number of SetRows() entries, including
            /// the equal-payload short-circuit returns. Lets the page-level
            /// bucket-key short-circuit be observed: the count stops growing
            /// once the page skips the rebuild entirely.
            std::size_t set_rows_calls() const noexcept { return set_rows_calls_; }
            bool row_danger(std::size_t index) const noexcept;
            int hover_row() const noexcept { return hover_row_; }

            /// Batch19 R5: the horizontal alignment the HEADER band paints
            /// column `i` with. Column captions are always left-anchored
            /// (Align::Start) so a right-aligned data column no longer drags
            /// its caption to the column's right edge. Data cells keep
            /// `TableColumn::align` (unchanged). RenderCore calls this exact
            /// function, so the seam and the painted pixels cannot drift.
            Align header_align(std::size_t i) const noexcept;

            /// D5: per-column widths actually used for layout/render, resolved
            /// from `TableColumn::width` as weights against the table's
            /// arranged width (so the columns always fill the table). Empty
            /// before the first Arrange.
            const std::vector<float>& resolved_widths() const noexcept {
                return resolved_widths_;
            }

            void SetOffset(float offset);
            float offset() const noexcept { return offset_; }
            /// batch33 D: index of the row whose row_id equals `row_id`
            /// (npos when absent).
            std::size_t RowIndex(const std::string& row_id) const noexcept;
            /// batch33 D: scroll so `row_id` is the first visible row AND mark
            /// it as the hovered row (the temporary "look here" highlight the
            /// leases intent asks for). Returns false when the row is absent.
            bool ScrollToRow(const std::string& row_id);
            /// batch27 D2: the fixed header band height (0 when nothing is
            /// painted). FillPanel centres its empty placeholder below it.
            static constexpr float header_height() noexcept { return 40.0f; }
            float content_height() const noexcept;
            float view_height() const noexcept { return view_h_; }

            /// T8 debug seam: sets explicit column widths (interpreted like a
            /// user drag: absolute, then renormalised to the arranged width).
            /// An empty/ mismatched vector is ignored. Re-resolves immediately
            /// (ResolveWidths(bounds_.w)) so the effect is visible without a
            /// real re-arrange, and invalidates layout.
            void SetColumnWidthsForTest(std::vector<float> widths);
            /// T8 debug seam: per-index width override (single column).
            void SetColumnWidthForTest(std::size_t index, float width);
            const std::vector<float>& user_widths() const noexcept {
                return user_widths_;
            }
            bool user_resized() const noexcept { return user_resized_; }

            bool OnWheel(int delta) override;
            /// batch33p: keyboard scrolling with the same contract as the wheel
            /// (Up/Down one row, PageUp/PageDown one viewport, Home/End to the
            /// ends; false when the offset did not move, so the key bubbles to
            /// the enclosing page viewport). The window routes the keys here via
            /// the pointer-nearest container fallback in RouteKey.
            bool OnKeyDown(uint32_t vk) override;
            /// batch34y: the single scroll-container predicate.
            bool IsScrollContainer() const noexcept override { return true; }
            /// batch33 E: right-button release on a data row fires
            /// on_row_context (row id + the click point) and consumes the
            /// event. Header band / empty area: not consumed (the window then
            /// bubbles it up the parent chain).
            bool OnMouseRightUp(Point p) override;
            /// batch321: keyboard path to the row menu. Targets the first
            /// fully visible row, paints it with the same hover band a pointer
            /// uses and runs on_row_context. False when there is no row or the
            /// table has no row menu.
            bool OpenContextMenuForKeyboard() override;
            bool OnMouseMove(Point p) override;
            bool OnMouseDown(Point p) override;
            bool OnMouseUp(Point p) override;
            /// batch332 P1: a column resize that never saw its mouse-up (the
            /// release went to another window / the app hid to the tray) used
            /// to keep resizing_ true, so every later hover re-applied
            /// ApplyResize and the SizeWE cursor stuck. Aborts the grab.
            void CancelDrag() noexcept override {
                resizing_ = false;
                resize_col_ = 0;
                resize_start_x_ = 0.0f;
                resize_start_left_ = 0.0f;
                resize_start_right_ = 0.0f;
            }
            /// batch37e (user): double-clicking a header divider auto-fits that
            /// column to its measured content width (standard list behaviour).
            bool OnMouseDoubleClick(Point p) override;
            /// batch37e: fit column `index` to its content width, keeping the
            /// table width by rescaling the other columns proportionally.
            void AutoFitColumn(std::size_t index);

            /// batch26: raw cell text when the painted cell was ellipsized.
            std::wstring tooltip_text(Point p) const override;

            /// batch18 U2: the header column-resize boundaries (and an active
            /// boundary drag) request the horizontal-resize cursor, matching
            /// the click-grab domain exactly (same kColumnResizeGrab band).
            /// Pure read-only: no state, no invalidation.
            CursorKind cursor_hint(Point p) const noexcept override;

            /// M4-F2/W11-G3/R4c: only the hovered row repaints while moving
            /// the pointer inside the table, instead of the whole box. This
            /// value is a single band (the CURRENT hover_row_) in absolute
            /// screen coordinates - the same formula RenderCore lays the rows
            /// out with - so the band always matches the painted pixels; the
            /// window captures it before and after OnMouseMove and invalidates
            /// the union, so the old + new row strips both clear. It is a
            /// hover repaint hint only: the window's wheel path repaints the
            /// scrolling container's whole box (W11 batch9 R4c/A) instead of
            /// reading this, and other structural changes (row set, columns,
            /// resize) still fall back to the base bounds() here.
            Rect invalidation_bounds() const noexcept override;

        protected:
            Size MeasureCore(Size available) override;
            void ArrangeCore(Rect final_rect) override;
            void RenderCore(RenderCtx& ctx) override;

        private:
            void LayoutVisibleRows(float view_h);
            /// W11 batch9 (R4c/B1): recompute first_row_/visible_rows_ from
            /// view_h_/offset_ only - pure index bookkeeping, no measuring and
            /// no memo work. SetOffset calls this so the repaint a scroll
            /// triggers (and the hover band's slice guard) sees the fresh
            /// slice immediately; LayoutVisibleRows calls it before rebuilding
            /// the memo window.
            void RecomputeVisibleSlice() noexcept;
            /// D5: recompute resolved_widths_ from the base/weight widths and
            /// (when the user has dragged) the retained user widths.
            void ResolveWidths(float available_w);
            /// D5: apply a header-boundary drag to the current pointer x,
            /// stealing the delta from the right neighbour (total preserved).
            void ApplyResize(float pointer_x);
            /// D5: index of the column whose right boundary is within the grab
            /// band of `x` (header band only); -1 when none. The last column's
            /// right edge is the table edge and is not draggable.
            int BoundaryAt(float x) const noexcept;
            float ColumnWidth(std::size_t index) const noexcept;
            /// batch19 R4-P2: physical left x of logical column `index` (RTL
            /// mirrors the column order; logical 0 lands at the right edge).
            float ColumnPhysicalX(std::size_t index) const noexcept;
            static bool StructureEquals(const std::vector<TableColumn>& a,
                                        const std::vector<TableColumn>& b) noexcept;
            /// R4c: recompute hover_row_ from the last pointer position against
            /// the current offset (a scroll moves content under a stationary
            /// pointer). Clears to -1 when the pointer no longer covers a row.
            void RecomputeHoverRow() noexcept;
            /// batch29: measured content width of each column (widest cell or
            /// header, plus 2 x kColumnInset), cached against row_gen_.
            void ResolveNaturalWidths();
            /// R4b: clamp `max_width` columns and redistribute the released
            /// width to the un-capped ones. Shared by the weight path and the
            /// content-driven (`auto_width`) path so a cap always holds.
            void ApplyColumnCaps();

            std::vector<TableColumn> cols_;
            std::vector<TableRow> rows_;
            std::vector<Str> actions_;
            /// D5: per-column widths actually used (== arranged width).
            std::vector<float> resolved_widths_;
            /// D5: width the current resolved_widths_/text layouts were built
            /// for; ArrangeCore only re-resolves when it actually differs.
            float resolved_w_ = -1.0f;
            /// D5: user-dragged absolute widths (renormalised on resize).
            std::vector<float> user_widths_;
            bool user_resized_ = false;
            bool resizing_ = false;
            std::size_t resize_col_ = 0;
            float resize_start_x_ = 0.0f;
            float resize_start_left_ = 0.0f;
            float resize_start_right_ = 0.0f;
            std::size_t first_row_ = 0;
            std::size_t visible_rows_ = 0;
            std::size_t text_layouts_ = 0;
            /// M10-1: SetRows() entry counter (test/perf seam only; never
            /// read by any production path).
            std::size_t set_rows_calls_ = 0;
            int hover_row_ = -1;
            /// R4c: the last pointer fed to OnMouseMove (valid while
            /// has_pointer_ is true), so SetOffset can re-resolve the hovered
            /// row after a scroll without any new mouse motion.
            Point last_pointer_{};
            bool has_pointer_ = false;
            float offset_ = 0.0f;
            float view_h_ = 0.0f;
            /// M3: position-indexed cell measurement memo (row-major, absolute
            /// row index r * cols_.size() + c). A cell's measured size depends
            /// only on its text and its column width, so the memo stays valid
            /// for as long as the row data and the quantised column widths do.
            /// `valid` (never the size) distinguishes "measured" from "not
            /// yet": an empty cell measures to Size{0,0} and would otherwise
            /// look unmeasured forever.
            struct CellMemo {
                Size size{};
                bool valid = false;
                /// batch26: the cell text as painted (ellipsized when it does
                /// not fit its column), cached with the same width/row key as
                /// `size` so the render pass does no measuring.
                std::wstring shown;
                /// True once `shown` has been derived for the current
                /// width/row generation (lazily, from the render pass, so the
                /// layout path keeps its exact measure-lookup budget).
                bool shown_valid = false;
            };
            std::vector<CellMemo> cell_memos_;
            /// M3: bumped when the rows are actually replaced or the column
            /// set actually changes. An equal-payload re-set short-circuits and
            /// leaves it alone, so the 500 ms snapshot tick costs nothing.
            std::uint32_t row_gen_ = 0;
            /// M3: the quantised column widths the current memos were measured
            /// at (compared against QuantizeLayoutWidth(resolved_widths_[i])).
            std::vector<float> cached_col_widths_;
            /// M3: the row_gen_ the cached widths/memos belong to. Seeded to
            /// UINT32_MAX so the very first pass (row_gen_ == 0) can never fake
            /// a gate hit on the 0 == 0 comparison.
            std::uint32_t cached_gen_ = UINT32_MAX;
            /// batch29: measured natural widths per column (content-driven
            /// auto_width), plus the content revision they were measured at.
            /// Reused while neither the rows nor the columns changed.
            std::vector<float> natural_widths_;
            std::uint32_t natural_gen_ = UINT32_MAX;
            bool natural_valid_ = false;
            /// batch37b: content-sized widths are resolved once per row
            /// POPULATION (column set + row count) and then frozen. Live cell
            /// values change constantly (a bandwidth cell "9.0 KiB/s" ->
            /// "586 B/s"); re-measuring on every tick shifted the right-side
            /// columns by 1-3 px on each refresh (user: flicker). A row-count
            /// change (client appears/disappears) or SetColumns re-arms it.
            std::size_t natural_rows_ = 0;
            bool natural_frozen_ = false;

        public:
            const char* debug_role() const override { return "Table"; }
            void debug_state(DebugStateSink& s) const override {
                DebugWrite(s, "rows", static_cast<long long>(rows_.size()));
                DebugWrite(s, "offset", static_cast<double>(offset_));
                DebugWrite(s, "first_visible", static_cast<long long>(first_row_));
                std::vector<double> resolved(resolved_widths_.begin(),
                                             resolved_widths_.end());
                DebugWrite(s, "resolved_widths", resolved);
                std::vector<double> user(user_widths_.begin(),
                                         user_widths_.end());
                DebugWrite(s, "user_widths", user);
                DebugWrite(s, "user_resized", user_resized_);
                DebugWrite(s, "resizing", resizing_);
                DebugWrite(s, "hover_row", static_cast<long long>(hover_row_));
            }
        };

        /// batch19 terminal: clickable hyperlink text (About-page Telegram
        /// group link). Accent-colored label with a trailing arrow glyph, a
        /// hand
        /// cursor on hover, a hover/focus underline, Tab focus with Enter/Space
        /// activation, and the same opt-in focus-ring contract as Button.
        /// Activate() opens the URL through OpenExternalUrlHandler() and then
        /// reports (url, result) through on_activate, so the caller can toast a
        /// ShellExecuteW failure (result <= 32). Never disabled, never editable.
        class LinkElement : public Element {
        public:
            LinkElement(std::wstring text, std::wstring url);
            std::function<void(const std::wstring&, long long)> on_activate;
            const std::wstring& text() const noexcept { return text_; }
            const std::wstring& url() const noexcept { return url_; }
            void SetText(std::wstring text);
            void SetUrl(std::wstring url);
            bool hovered() const noexcept { return hover_; }
            /// batch27 P1-15: links now ease their hover exactly like Button
            /// (same kHoverSeconds), so the three hoverable control families
            /// share one transition.
            float hover_progress() const noexcept { return hover_t_; }
            /// Hover or focus paints the underline.
            bool underlined() const noexcept { return hover_ || focused_; }
            void SetFocusRing(bool on) noexcept { focus_ring_ = on; }
            bool focus_ring() const noexcept { return focus_ring_; }
            /// Single entry point for mouse, keyboard and code paths.
            void Activate();

            bool focusable() const override { return true; }
            CursorKind cursor_hint(Point) const noexcept override {
                return CursorKind::Hand;
            }
            bool OnMouseDown(Point p) override;
            bool OnMouseUp(Point p) override;
            bool OnMouseMove(Point p) override;
            bool OnKeyDown(uint32_t vk) override;
            void OnFocus(bool focused) override;
            /// batch27 P1-15: same easing as Button::AdvanceAnimation.
            void AdvanceAnimation(float dt_seconds) override;
            bool HasActiveAnimation() const noexcept override;

            /// batch35a: a link is an interactive control (focusable, clickable,
            /// carries a label), so the automation API must be able to address
            /// it by role like Button/TextInput/Select. Without this it
            /// inherited the base role "Element" and FindByRole("Link") could
            /// never see it.
            const char* debug_role() const override { return "Link"; }

        protected:
            Size MeasureCore(Size available) override;
            void RenderCore(RenderCtx& ctx) override;

        private:
            std::wstring text_;
            std::wstring url_;
            bool hover_ = false;
            bool focused_ = false;
            bool pressed_ = false;
            bool focus_ring_ = false;
            /// batch27 P1-15: hover interpolation progress in [0, 1].
            float hover_t_ = 0.0f;
        };

        /// batch19: process-wide "open this URL" hook. Defaults to
        /// ShellExecuteW(nullptr, L"open", ...); tests replace it to capture the
        /// URL and to simulate the failure return (<= 32).
        std::function<long long(const std::wstring&)>& OpenExternalUrlHandler();

        /// batch19 R4-P4: searchable language picker (native). Owns a filter
        /// string + a bounded, filtered list of {name, code} languages; supports
        /// wheel/Up/Down/Enter/Esc and mouse row picking. Drawn square (R7
        /// contract, same as Select). The picker echoes the current language and
        /// reports a pick through on_pick (the caller applies SetLangCode).
        class LanguagePicker : public Element {
        public:
            struct Item {
                std::wstring name;
                std::string code;
            };
            static constexpr std::size_t kMaxRows = 8;

            LanguagePicker();
            ~LanguagePicker();
            void SetLanguages(std::vector<Item> items, std::string current_code);
            void SetFilter(std::wstring filter);
            const std::wstring& filter() const noexcept { return filter_; }
            /// Number of matches for the current filter (the full set; the
            /// view is a scrolling viewport of kMaxRows over it).
            std::size_t filtered_count() const noexcept {
                return filtered_.size();
            }
            /// Index of the first visible row in the scrolling viewport.
            std::size_t view_top() const noexcept { return view_top_; }
            /// Code highlighted by the keyboard (empty when no match).
            std::string highlighted_code() const;
            /// batch24 P2-6: the search box is now part of the picker popup
            /// (rendered at its top while expanded) instead of a separate
            /// page-level editor. The editable text is owned by an internal
            /// TextInputElement (a member, deliberately NOT a tree child, so a
            /// consumer page cannot see or hit it); keyboard text is routed
            /// here while the picker is expanded + the search row is active.
            TextInputElement* search_editor() const noexcept {
                return search_.get();
            }
            bool search_active() const noexcept { return search_focused_; }
            /// Current language code (echo of the last SetLanguages/pick).
            const std::string& selected_code() const noexcept {
                return selected_code_;
            }
            void SetExpanded(bool expanded) noexcept;
            bool expanded() const noexcept { return expanded_; }
            /// batch27 D4: preferred width. The About page passes ~320 px so a
            /// one-line language chooser stops stretching across the whole
            /// card (0 = fill the available width, the legacy behaviour).
            void SetPreferredWidth(float px) noexcept {
                if (px == preferred_w_) {
                    return;
                }
                preferred_w_ = px;
                InvalidateLayout();
            }
            float preferred_width() const noexcept { return preferred_w_; }
            /// Echo the active language without resetting the filter/expanded
            /// state (used by the About page tick after a switch).
            void SetCurrentCode(std::string code);
            std::function<void(const std::string& code)> on_pick;

            bool focusable() const override { return true; }
            CursorKind cursor_hint(Point) const noexcept override {
                return EffectivelyEnabled() ? CursorKind::Hand
                                            : CursorKind::Arrow;
            }
            /// batch26 P1-10: the picker now paints an accent focus ring and
            /// clears it on blur, like Select/Button.
            void OnFocus(bool focused) override;
            bool focused() const noexcept { return focused_; }
            bool OnMouseDown(Point p) override;
            bool OnWheel(int delta) override;
            bool OnKeyDown(uint32_t vk) override;
            /// batch24 P2-6: printable input feeds the in-popup search editor.
            bool OnChar(wchar_t ch) override;
            /// batch26: full language name for the hovered/collapsed row.
            std::wstring tooltip_text(Point p) const override;

        protected:
            Size MeasureCore(Size available) override;
            void RenderCore(RenderCtx& ctx) override;

        private:
            void Recompute();
            void Activate(std::size_t filtered_index);
            /// Scroll the viewport so `highlight_` stays visible.
            void EnsureVisible() noexcept;
            /// batch24 P2-6: draw the in-popup search row (placeholder / value
            /// / caret) at the top of the expanded list.
            void DrawSearchRow(RenderCtx& ctx);
            /// batch24 P2-6: pull the editor's text into filter_ (no-op when
            /// unchanged) and request the host layout, mirroring SetFilter.
            void SyncFilterFromSearch();

            std::vector<Item> items_;
            /// batch62: lowercased `name`/`code` per item, built once when the
            /// table is replaced. The filter used to lowercase every item on
            /// every keystroke (one heap string per language per character).
            /// Same length as items_; rebuilt only in SetLanguages.
            std::vector<std::wstring> name_lc_;
            std::vector<std::wstring> code_lc_;
            std::vector<std::size_t> filtered_;
            std::wstring filter_;
            std::string selected_code_;
            std::size_t highlight_ = 0;
            std::size_t view_top_ = 0;
            bool expanded_ = false;
            /// batch26 P1-10: collapsed-box focus ring state.
            bool focused_ = false;
            /// batch24 P2-6: in-popup search editor (member, not a tree child).
            std::unique_ptr<TextInputElement> search_;
            /// True while the search row has keyboard focus (typing filters).
            bool search_focused_ = false;
            /// batch27 D4: preferred width (0 = fill available).
            float preferred_w_ = 0.0f;

        public:
            const char* debug_role() const override { return "LanguagePicker"; }
            void debug_state(DebugStateSink& s) const override {
                DebugWrite(s, "expanded", expanded_);
                DebugWrite(s, "filtered", static_cast<long long>(filtered_.size()));
                DebugWrite(s, "highlight",
                           static_cast<long long>(highlight_));
                DebugWrite(s, "code", selected_code_);
            }
        };

        /// Single-line editor. Only printable ASCII input is accepted (no
        /// IME; documented S4.2 limitation), the caret is the tail position.
        class TextInputElement : public Element {
        public:
            TextInputElement();
            /// Programmatic set: does not fire on_changed.
            void SetValue(std::wstring value);
            /// batch20 item 1: dim hint drawn while the value is empty (the About
            /// language filter had no caption and read as a mystery box).
            void SetPlaceholder(std::wstring text);
            const std::wstring& placeholder() const noexcept {
                return placeholder_;
            }
            const std::wstring& value() const noexcept { return value_; }
            std::function<void()> on_changed;
            std::function<void()> on_submit;
            /// 0 = unlimited.
            void SetMaxChars(std::size_t max_chars) noexcept { max_chars_ = max_chars; }
            std::size_t max_chars() const noexcept { return max_chars_; }
            std::size_t caret_index() const noexcept { return caret_; }

            bool focusable() const override { return true; }
            /// W11 batch6 G-4: the editor requests the I-beam cursor; the
            /// window's WM_SETCURSOR maps CursorKind::Text to IDC_IBEAM.
            /// batch18 U2: the point parameter is ignored (the whole box is
            /// text); the fresh WM_SETCURSOR point is only needed by
            /// position-sensitive overrides (TableElement boundaries).
            CursorKind cursor_hint(Point) const noexcept override {
                return CursorKind::Text;
            }
            bool OnChar(wchar_t ch) override;
            bool OnKeyDown(uint32_t vk) override;
            void OnFocus(bool focused) override;
            bool OnCaretBlinkTick() noexcept override;
            /// G2: click/drag caret placement + selection.
            bool OnMouseDown(Point p) override;
            bool OnMouseMove(Point p) override;
            bool OnMouseUp(Point p) override;
            /// batch332 P1: a drag-select that never saw its mouse-up kept
            /// dragging_ true, so every later hover moved the caret and grew
            /// the selection. Aborts the drag; the current selection (caret +
            /// anchor) is left exactly as-is.
            void CancelDrag() noexcept override { dragging_ = false; }

            /// Caret blink phase: true = the caret is drawn while focused.
            bool caret_visible() const noexcept { return caret_visible_; }
            /// Selection anchor index (== caret_ when there is no selection).
            std::size_t selection_anchor() const noexcept { return sel_anchor_; }
            /// R3 clipboard support (driven by the window, which owns the OS
            /// clipboard): true when a non-empty selection exists.
            bool HasSelection() const noexcept { return caret_ != sel_anchor_; }
            /// The selected substring (empty when nothing is selected).
            std::wstring SelectedText() const;
            /// Delete the current selection (no-op when empty); fires
            /// on_changed once when something was removed.
            void DeleteSelection();
            /// Replace the current selection (or insert at the caret) with
            /// `text`; printable-ASCII filtered; fires on_changed once.
            void InsertText(const std::wstring& text);
            // batch37i: clipboard capability used by the window's Ctrl keys.
            bool CopySelectionToClipboard() override;
            bool CutSelectionToClipboard() override;
            PasteResult PasteFromClipboard() override;
            bool SelectAllText() override;
            // batch37n: OS Edit basics - undo/redo, Shift+click, triple click.
            bool UndoEdit();
            bool RedoEdit();
            void ExtendSelectionTo(Point p);
            // batch37k: standard edit semantics (Shift/Ctrl navigation and
            // word delete). k is the physical key; RTL mapping is internal.
            bool OnMouseDoubleClick(Point p) override;
            bool ExtendCaretKey(uint32_t vk, bool by_word);
            bool MoveCaretWord(uint32_t vk, bool extend);
            bool DeleteWord(uint32_t vk);
            bool EditMenuTarget() const override { return true; }
            bool CanUndoEdit() const override { return !undo_stack_.empty(); }
            bool CanRedoEdit() const override { return !redo_stack_.empty(); }
            /// batch115: history depths, exposed so a test can prove both
            /// stacks stay bounded while the user cycles Undo/Redo.
            std::size_t UndoDepth() const noexcept { return undo_stack_.size(); }
            std::size_t RedoDepth() const noexcept { return redo_stack_.size(); }
            bool HasTextSelection() const override {
                return caret_ != sel_anchor_;
            }
            bool HasTextContent() const override { return !value_.empty(); }
            /// batch24 P0-3 (IME): the active composition (preedit) string and
            /// its caret index inside it. While non-empty the editor renders
            /// the preedit inline (underlined) at the insertion point instead
            /// of the plain tail caret. SetCompositionForTest is the component
            /// test seam the window's WM_IME_COMPOSITION handler also drives.
            void SetCompositionForTest(std::wstring text, std::size_t caret = 0);
            void ClearComposition();
            bool has_composition() const noexcept { return !composition_.empty(); }
            const std::wstring& composition() const noexcept {
                return composition_;
            }
            std::size_t composition_caret() const noexcept {
                return composition_caret_;
            }
            /// Commit an IME result string: replace the selection (or insert
            /// at the caret) with `result`, clear the preedit and fire
            /// on_changed. Accepts any Unicode (unlike the ASCII WM_CHAR path).
            void CommitComposition(std::wstring result);
            /// T8 debug seam: programmatically set the selection (both indices
            /// clamp to [0, value_.size()]); resets the caret blink phase to
            /// visible and invalidates layout, matching an edit/focus path.
            void SetSelectionForTest(std::size_t anchor, std::size_t caret) {
                if (caret > value_.size()) caret = value_.size();
                if (anchor > value_.size()) anchor = value_.size();
                caret_ = caret;
                sel_anchor_ = anchor;
                caret_visible_ = true;
                ++content_rev;
                InvalidateLayout();
            }

        protected:
            Size MeasureCore(Size available) override;
            void RenderCore(RenderCtx& ctx) override;

        private:
            /// Nearest inter-character boundary for a click x.
            std::size_t CaretFromX(float x) const noexcept;

            /// M7 (batch3): (re)builds prefix_w_ when the value string or the
            /// installed measure hook changed. Same measure call sequence the
            /// pre-cache CaretFromX loop ran per event.
            void EnsurePrefixWidths() const;

            /// R2: insert a space at the caret (replacing any selection),
            /// invoked from OnKeyDown(VK_SPACE) so it works even when the host
            /// loop does not deliver WM_CHAR(0x20) inside a modal dialog.
            void InsertSpace();

            std::wstring value_;
            /// batch20 item 1: dim hint drawn while value_ is empty.
            std::wstring placeholder_;
            /// batch24 P0-3: IME preedit string + its caret (empty = none).
            std::wstring composition_;
            std::size_t composition_caret_ = 0;
            std::size_t caret_ = 0;
            /// Anchor of a drag selection; == caret_ when nothing is selected.
            std::size_t sel_anchor_ = 0;
            bool dragging_ = false;
            std::size_t max_chars_ = 0;
            bool focused_ = false;
            /// Caret blink phase (S5.19): starts visible; OnCaretBlinkTick
            /// flips it every 500 ms, every edit/focus path resets it to
            /// true so the caret brightens immediately on input.
            bool caret_visible_ = true;
            /// R2: set when OnKeyDown(VK_SPACE) inserted a space, so the paired
            /// WM_CHAR(0x20) is swallowed instead of double-inserting.
            bool space_from_keydown_ = false;
            /// batch37n: OS Edit undo/redo snapshots. PushUndo runs before a
            /// user edit; undo/redo move the snapshot between the two stacks.
            struct EditSnapshot {
                std::wstring value;
                std::size_t caret = 0;
                std::size_t anchor = 0;
            };
            void PushUndo();
            std::vector<EditSnapshot> undo_stack_;
            std::vector<EditSnapshot> redo_stack_;
            /// Triple click = double-click word select + a third press within
            /// the OS double-click time at the same point.
            std::chrono::steady_clock::time_point last_word_click_{};
            Point last_word_click_pos_{};
            /// M7 (batch3): lazy caret-prefix width cache. prefix_w_[i] holds
            /// the measured width of value_.substr(0, i) (prefix_w_[0] = 0),
            /// built with the exact per-prefix MeasureText sequence the
            /// original CaretFromX ran on every event. Rebuilt only when the
            /// value or the measure hook changes (prefix_src_ full-string
            /// compare covers every write path, including equal-length
            /// replacement; prefix_gen_ covers hook swaps). `mutable` because
            /// EnsurePrefixWidths runs from const noexcept CaretFromX.
            mutable std::vector<float> prefix_w_;
            mutable std::wstring prefix_src_;
            mutable uint64_t prefix_gen_ = 0;

        public:
            const char* debug_role() const override { return "TextInput"; }
            void debug_state(DebugStateSink& s) const override {
                DebugWrite(s, "value", value_);
                DebugWrite(s, "caret", static_cast<long long>(caret_));
                DebugWrite(s, "max_chars", static_cast<long long>(max_chars_));
                DebugWrite(s, "focused", focused_);
                DebugWrite(s, "selection_anchor",
                           static_cast<long long>(sel_anchor_));
                DebugWrite(s, "caret_visible", caret_visible_);
                DebugWrite(s, "composition", composition_);
            }
        };

        /// Dropdown; expansion state is element state so T6 can draw the
        /// popup. Unknown values are ignored when options exist.
        class SelectElement : public Element {
        public:
            SelectElement();
            void SetOptions(std::vector<std::pair<std::wstring, std::wstring>> value_label);
            void SetSelectedValue(std::wstring value);
            /// batch20 item 8: programmatic selection WITHOUT on_changed. A
            /// snapshot refresh / auto-display update must never look like a
            /// user pick (the Settings page entering used to re-apply the UI
            /// scale through on_changed).
            void SetSelectedValueSilent(std::wstring value);
            const std::wstring& selected_value() const noexcept { return selected_; }
            const std::vector<std::pair<std::wstring, std::wstring>>& options() const noexcept {
                return options_;
            }
            void SetExpanded(bool expanded) noexcept;
            bool expanded() const noexcept { return expanded_; }
            /// batch33 E: Esc closes the popup list (Element::DismissOverlay).
            bool DismissOverlay() override;
            /// batch27 P0-3: true when the painted popup is still exactly
            /// anchored to the trigger box (touching its bottom or its top).
            /// A page scroll can clamp the list against the viewport while the
            /// trigger moved, leaving the list visually detached; the window
            /// collapses such a popup instead of stranding it mid-page.
            bool popup_anchored() const noexcept;
            std::function<void()> on_changed;

            bool focusable() const override { return true; }
            CursorKind cursor_hint(Point) const noexcept override {
                return EffectivelyEnabled() ? CursorKind::Hand
                                            : CursorKind::Arrow;
            }
            bool OnMouseDown(Point p) override;
            bool OnMouseMove(Point p) override;
            /// batch33f: a capped popup scrolls with the wheel (it no longer
            /// grows past the visible domain). Returns true only when the
            /// visible row window actually moved.
            bool OnWheel(int delta) override;
            /// batch33f: index of the first painted option row.
            std::size_t popup_top() const noexcept { return popup_top_; }
            /// batch33f: how many option rows the popup currently shows.
            std::size_t popup_visible_rows() const noexcept {
                return popup_rows_;
            }
            /// Upper bound on the popup height in rows (a 12-adapter list used
            /// to paint 336 px and get clamped over the trigger).
            static constexpr std::size_t kMaxPopupRows = 8;
            bool OnKeyDown(uint32_t vk) override;
            /// T7 (M4): tracks window focus so the collapsed box draws its
            /// focus ring and - crucially - clears it on blur (previously the
            /// ring stuck on: only OnMouseDown ever set focused_).
            void OnFocus(bool focused) override;
            bool focused() const noexcept { return focused_; }
            /// T7/I2: the region the element (and its expanded popup) paints.
            /// Equals bounds() when collapsed; the collapsed box unioned with
            /// the popup list when expanded. The window invalidates this so a
            /// keyboard expand/collapse repaints the popup, not just the box.
            Rect invalidation_bounds() const noexcept override;
            /// While expanded, the popup list is part of the hit zone (U3):
            /// clicks/moves on the rows reach this element instead of dying
            /// outside its own bounds.
            Element* HitTest(Point p) override;
            /// The popup is painted in the top layer (unclipped) so a
            /// ScrollView viewport cannot cut it off (G9).
            void RenderOverlay(RenderCtx& ctx) override;
            /// Hit mirror for the top-layer popup, ignoring ancestor clips.
            Element* HitTestOverlay(Point p) override;
            /// batch26: full option label for the hovered popup row (or the
            /// selected label when collapsed) - Select rows may be clipped.
            std::wstring tooltip_text(Point p) const override;

            /// batch24 P0-2 test seam: the exact popup list geometry the
            /// renderer/hit/mouse paths use (flipped up when it does not fit
            /// below in the window/ScrollView visible domain).
            Rect popup_rect() const noexcept { return PopupRect(); }

        protected:
            Size MeasureCore(Size available) override;
            void RenderCore(RenderCtx& ctx) override;

        private:
            void DrawCollapsed(RenderCtx& ctx);
            void DrawPopup(RenderCtx& ctx);
            /// batch26: a restrained 3 px drop shadow under/right of the
            /// top-layer list (painted only by RenderOverlay, so the content
            /// pass never double-composites it).
            void DrawPopupShadow(RenderCtx& ctx);

            /// batch24 P0-2: the ONE popup geometry used by render, hit test,
            /// mouse routing and invalidation (hit and paint must be the same
            /// source). The list opens DOWNWARD when it fits between the box
            /// and the visible domain bottom (window client bottom, narrowed by
            /// every enclosing ScrollView viewport), otherwise it flips UP
            /// above the box; it is finally clamped into the domain so no row
            /// can ever paint off-window (the old always-down geometry left the
            /// theme list's lower options unreachable - user: "I could not find
            /// the theme setting").
            Rect PopupRect() const noexcept;

            /// batch20 item 8: shared body for the notifying / silent setters.
            void SetSelectedValueImpl(std::wstring value, bool notify);

            /// batch68/71: bring the selected row into the capped popup window.
            /// Called ONLY by the events that change the selection or open the
            /// list - never from PopupRect(), which nine call sites use for
            /// paint/hit/hover/tooltip and must stay a pure geometry read.
            void RevealSelectionNow();

            std::vector<std::pair<std::wstring, std::wstring>> options_;
            std::wstring selected_;
            bool expanded_ = false;
            bool focused_ = false;
            int hover_ = -1;
            /// batch33f: first option row painted/hit in the popup. A list with
            /// more rows than fit is capped (kMaxPopupRows) and scrolled instead
            /// of being clamped back over its own trigger box. `mutable` because
            /// PopupRect() is the single geometry source for paint/hit/mouse and
            /// it is the place that normalises this window (clamping it to the
            /// capped row count and keeping the selected row visible).
            mutable std::size_t popup_top_ = 0;
            /// Number of rows the capped popup can show at the current geometry
            /// (set by PopupRect, read by paint/hit/wheel).
            mutable std::size_t popup_rows_ = 0;
            /// M3b: single-slot memo for the derived label's natural measurement,
            /// keyed by content_rev. SetOptions / SetSelectedValue both bump
            /// that counter, so a selection change is always a re-measure.
            /// B5-1: the measure-hook generation is part of the key too.
            uint64_t measure_memo_rev_ = 0;
            uint64_t measure_memo_gen_ = 0;
            Size measure_memo_sz_{};
            bool measure_memo_valid_ = false;

        public:
            const char* debug_role() const override { return "Select"; }
            void debug_state(DebugStateSink& s) const override {
                DebugWrite(s, "selected", selected_);
                DebugWrite(s, "expanded", expanded_);
            }
        };

        enum class BadgeKind { Neutral, Accent, Success, Warning, Danger };

        /// batch28 (user-requested "professional device" feel, modelled on the
        /// Win11 Task Manager performance page): a slim frame with a LIVE
        /// throughput curve inside. The renderer has no line primitive
        /// (FillRect / FillRoundedRect / StrokeRect / StrokeRoundedRect /
        /// DrawText / ClipPush / ClipPop only) and adding one would touch the
        /// renderer, the draw-op serializer and every recording test, so the
        /// curve is a vertical-bar AREA chart: one 2 px column per sample
        /// (oldest left, newest right), filled from the curve's y down to the
        /// baseline, with a 1 px fully opaque cap on top of every column to
        /// read as a crisp curve edge.
        ///
        /// SCALE CONTRACT (batch33, supersedes the b28 fixed-ladder mapping -
        /// there is ONE contract, the ladder no longer decides the curve):
        ///   * the grid lines sit at 25 / 50 / 75 % of the frame and never move;
        ///   * the curve is normalised against the VISIBLE window's own min/max
        ///     (`lo` / `hi`) with 8 % headroom at both ends, so the lowest
        ///     column never touches the baseline and the highest never touches
        ///     the frame top - a real network rate therefore never reads as a
        ///     flat line;
        ///   * a truly flat window (min == max) draws ONE vertical mid line;
        ///   * a bounds change eases linearly over 120 ms; the SHAPE of the
        ///     curve is immediate (the raw samples are never smoothed away);
        ///   * `current_scale()` keeps returning the upper bound (hi) for tests
        ///     and text, `lower_bound_label()` the lower one.
        class SparklineElement : public Element {
        public:
            SparklineElement();
            /// Appends one sample; the ring keeps at most kCapacity values and
            /// drops the OLDEST (memory never grows).
            void Push(double value);
            /// false = idle: only the frame, the grid and a flat baseline line
            /// (colour TextDim); no area, no curve, no highlight dot.
            void SetActive(bool active);
            bool active() const noexcept { return active_; }
            void SetColor(ColorToken color);
            ColorToken color() const noexcept { return color_; }
            /// Tick marks along the bottom edge (0 disables them - the card
            /// mini curves use that).
            void SetTickCount(int count);
            int tick_count() const noexcept { return tick_count_; }
            /// Frame/chrome on or off: the card mini curves are bare area +
            /// top line with no background box, no grid, no range label.
            void SetChromeVisible(bool visible);
            bool chrome_visible() const noexcept { return chrome_; }
            /// Area fill alpha (default 0.10 for the strip, the card mini
            /// curves use 0.18 at most).
            void SetAreaAlpha(float alpha);
            /// batch33 B: a fixed height for the framed instrument (the
            /// dashboard's 168 px performance curve). 0 = the historical
            /// 36 px strip / 28 px bare band.
            void SetPreferredHeight(float height);
            /// Optional click action (the strip curve jumps to "detailed
            /// statistics"); the element stays hit-transparent for hovering.
            std::function<void()> on_click;
            /// batch33 spec D tail: the "click to see ..." sentence appended to
            /// the hover tooltip when the curve is clickable, so the affordance
            /// is discoverable without guessing (empty = no hint line).
            void SetClickHint(std::wstring hint) { click_hint_ = std::move(hint); }
            const std::wstring& click_hint() const noexcept { return click_hint_; }
            bool OnMouseDown(Point p) override;
            bool OnMouseUp(Point p) override;
            /// batch33 spec D tail: a clickable curve must advertise itself.
            /// Without this the pointer stayed a plain arrow over an element
            /// that does react to a click.
            CursorKind cursor_hint(Point) const noexcept override {
                return on_click ? CursorKind::Hand : CursorKind::Arrow;
            }
            /// Hover text: "current X, peak Y" (empty when idle).
            std::wstring tooltip_text(Point p) const override;
            /// The upper bound of the visible window (B/s), painted in the
            /// frame's top-left corner. Headless-assertable; empty for the bare
            /// card curves.
            std::wstring range_label() const;
            /// batch33e: the box the CURVE is actually drawn in (inside the
            /// frame padding, below the range-label band). The label used to be
            /// painted first and the columns were then painted over it, so on a
            /// 36 px strip the text was unreadable exactly when data existed.
            /// The label now owns a band at the top and this rect is what is
            /// left; empty before the first Render.
            Rect curve_area() const noexcept { return curve_area_; }
            /// batch33 A: the lower bound of the visible window, same format.
            std::wstring lower_bound_label() const;
            /// True when the visible window is genuinely flat (min == max), in
            /// which case the range label carries the "stable" suffix.
            bool window_flat() const noexcept { return flat_; }

            static constexpr std::size_t kCapacity = 60;
            std::size_t sample_count() const noexcept { return samples_.size(); }
            /// The current UPPER bound (hi) of the visible window (B/s); 0 when
            /// idle/empty.
            double current_scale() const noexcept { return to_hi_; }
            /// batch33 A: the current LOWER bound (lo) of the visible window.
            double lower_bound() const noexcept { return to_lo_; }
            double last_sample() const noexcept {
                return samples_.empty() ? 0.0 : samples_.back();
            }
            /// Largest sample currently in the ring.
            double peak_sample() const noexcept { return peak_; }
            /// Test seam: the raw sample at display index `i` (0 = oldest).
            double displayed(std::size_t i) const;

            void AdvanceAnimation(float dt_seconds) override;
            bool HasActiveAnimation() const noexcept override;

            /// Ladder step for a raw magnitude (1/2/5 x 10^n). No longer drives
            /// the curve's vertical mapping (batch33); kept because the range
            /// TEXT uses it to round the bound to a readable value.
            static double LadderStep(double value);

        protected:
            Size MeasureCore(Size available) override;
            void RenderCore(RenderCtx& ctx) override;

        private:
            /// batch33 A: recompute the visible window's bounds (lo/hi) from the
            /// ring, start a 120 ms ease when they changed, and update `flat_`.
            void UpdateBounds() noexcept;
            /// Vertical mapping in force for painting: [from_lo_, from_hi_] eased
            /// to [to_lo_, to_hi_] over kGearSeconds.
            void DisplayBounds(double& lo, double& hi) const noexcept;

            std::vector<double> samples_;
            bool active_ = false;
            bool chrome_ = true;
            ColorToken color_ = ColorToken::Success;
            int tick_count_ = 6;
            float area_alpha_ = 0.28f;
            /// batch33 B: explicit framed height (0 = the historical 36 px).
            float preferred_h_ = 0.0f;
            /// batch33 A: the visible window's bounds - the target pair and the
            /// pair the current 120 ms ease started from.
            double to_lo_ = 0.0;
            double to_hi_ = 0.0;
            double from_lo_ = 0.0;
            double from_hi_ = 0.0;
            float gear_t_ = 1.0f;  ///< 0..1 through the 120 ms bounds ease
            bool flat_ = false;
            double peak_ = 0.0;
            bool smoothing_pending_ = false;
            bool pressed_ = false;
            std::wstring click_hint_;
            /// batch33e: the curve's own box (frame padding minus the label
            /// band). Set by RenderCore so tests can assert the label is clear.
            Rect curve_area_{};

        public:
            static constexpr float kGearSeconds = 0.12f;
            const char* debug_role() const override { return "Sparkline"; }
            void debug_state(DebugStateSink& s) const override {
                DebugWrite(s, "samples",
                           static_cast<long long>(samples_.size()));
                DebugWrite(s, "scale", to_hi_);
                DebugWrite(s, "lower", to_lo_);
                DebugWrite(s, "flat", flat_);
                DebugWrite(s, "active", active_);
                DebugWrite(s, "ticks", static_cast<long long>(tick_count_));
                DebugWrite(s, "color",
                           static_cast<long long>(static_cast<int>(color_)));
                DebugWrite(s, "range_label", range_label());
                DebugWrite(s, "lower_label", lower_bound_label());
            }
        };
        /// batch28: the status dot in front of the short state word. Running =
        /// a breathing pulse (alpha 0.55 <-> 1.0 over 1.2 s, text unaffected);
        /// stopped / warning = steady. It rides the existing frame clock and
        /// reports HasActiveAnimation() ONLY while running, so a stopped app
        /// returns to zero timer ticks (the idle-cost contract).
        class StatusDotElement : public Element {
        public:
            StatusDotElement();
            void SetColor(ColorToken color);
            ColorToken color() const noexcept { return color_; }
            void SetPulsing(bool pulsing);
            bool pulsing() const noexcept { return pulsing_; }
            /// Current dot alpha (0.55..1.0 while pulsing, 1.0 when steady).
            float dot_alpha() const noexcept { return alpha_; }

            static constexpr float kSize = 12.0f;
            static constexpr float kPulseSeconds = 1.2f;
            /// batch63 (user ruling: "keep it soft and stutter-free"): the dot
            /// is a 12 px breathing indicator, so it does not need the global
            /// 33 ms animation clock. Alpha is only RECOMPUTED every
            /// kPulseStepSeconds; the frame clock still runs (it is shared with
            /// other animations) but the pulse's own invalidation and
            /// content_rev bump are quantised to ~15 fps. The cycle length,
            /// the 0.55..1.0 sine shape and the phase advance stay untouched.
            static constexpr float kPulseStepSeconds = 1.0f / 15.0f;

            void AdvanceAnimation(float dt_seconds) override;
            bool HasActiveAnimation() const noexcept override;
            /// batch63: only the ~15 fps sample frames need a repaint, so the
            /// 12 px dot no longer invalidates itself on every 33 ms clock tick.
            bool AnimationNeedsRepaint() const noexcept override {
                return pulse_step_pending_;
            }

        protected:
            Size MeasureCore(Size available) override;
            void RenderCore(RenderCtx& ctx) override;

        private:
            ColorToken color_ = ColorToken::TextDim;
            bool pulsing_ = false;
            float phase_ = 0.0f;  ///< 0..1 through the pulse cycle
            float alpha_ = 1.0f;
            /// batch63: seconds accumulated since the last alpha recompute.
            float pulse_accum_ = 0.0f;
            /// batch63: true only on the frames whose alpha actually changed
            /// (drives AnimationNeedsRepaint, so the shared 33 ms clock can keep
            /// running without repainting the dot every tick).
            bool pulse_step_pending_ = false;

        public:
            const char* debug_role() const override { return "StatusDot"; }
            void debug_state(DebugStateSink& s) const override {
                DebugWrite(s, "pulsing", pulsing_);
                DebugWrite(s, "alpha", static_cast<double>(alpha_));
                DebugWrite(s, "color",
                           static_cast<long long>(static_cast<int>(color_)));
            }
        };

        class BadgeElement : public Element {
        public:
            explicit BadgeElement(std::wstring text, BadgeKind kind = BadgeKind::Neutral);
            void SetText(std::wstring text);
            const std::wstring& text() const noexcept { return text_; }
            void SetKind(BadgeKind kind) noexcept;
            BadgeKind kind() const noexcept { return kind_; }

        protected:
            Size MeasureCore(Size available) override;
            void RenderCore(RenderCtx& ctx) override;

        private:
            std::wstring text_;
            BadgeKind kind_;
            /// M3b: single-slot memo for the natural measurement, keyed by
            /// content_rev (SetText / SetKind both bump it). B5-1: the
            /// measure-hook generation is part of the key too.
            uint64_t measure_memo_rev_ = 0;
            uint64_t measure_memo_gen_ = 0;
            Size measure_memo_sz_{};
            bool measure_memo_valid_ = false;

        public:
            const char* debug_role() const override { return "Badge"; }
            void debug_state(DebugStateSink& s) const override {
                DebugWrite(s, "text", text_);
                DebugWrite(s, "kind",
                           static_cast<long long>(static_cast<int>(kind_)));
            }
        };

        /// batch33 E: a lightweight context menu (right-click actions on a
        /// table row). It owns no layout slot - MeasureCore returns {0,0} and
        /// it is arranged over the whole client area - and it paints in the
        /// window's top layer.
        ///
        /// Hit contract (standard "click outside closes AND the click still
        /// lands"): while open the menu captures the WHOLE window. A point
        /// inside the menu box resolves to the item under it; a point outside
        /// closes the menu and returns nullptr, so the same click continues to
        /// the element below.
        class ContextMenu : public Element {
        public:
            struct Item {
                std::wstring label;
                bool danger = false;
                std::function<void()> run;
            };

            ContextMenu();
            /// Opens at `at` (client coordinates: the anchor's bottom-right;
            /// flipped left/up when the card would leave the client area).
            void Show(Point at, std::vector<Item> items);
            void Close();
            bool open() const noexcept { return open_; }
            const std::vector<Item>& items() const noexcept { return items_; }
            /// The painted card geometry (test/render/hit share this source).
            Rect menu_rect() const noexcept { return MenuRect(); }
            /// Index of the item under `p`, -1 when outside the card.
            int ItemAt(Point p) const noexcept;
            /// Runs item `index` (closing first) - the click path and the
            /// debug/test seam use the same body.
            void Activate(int index);
            /// The client-area box the menu clamps itself into (set by the
            /// window's Arrange; defaults to bounds()).
            void SetClientRect(Rect client) noexcept { client_ = client; }

            static constexpr float kMaxWidth = 260.0f;
            static constexpr float kItemHeight = 30.0f;
            static constexpr float kPadY = 6.0f;

            bool is_overlay() const override { return true; }
            bool renders_on_top() const override { return true; }
            bool DismissOverlay() override;
            void RenderOverlay(RenderCtx& ctx) override;
            Element* HitTestOverlay(Point p) override;
            /// While open the whole window belongs to the menu (see the hit
            /// contract above); the content pass must not reach the page.
            Element* HitTest(Point p) override;
            CursorKind cursor_hint(Point) const noexcept override {
                return CursorKind::Arrow;
            }
            Rect invalidation_bounds() const noexcept override;

            bool OnMouseDown(Point p) override;
            bool OnMouseUp(Point p) override;
            bool OnMouseMove(Point p) override;
            /// batch321: keyboard navigation inside an open menu: Up/Down
            /// (wrapping), Home/End, Enter/Space activates the highlighted
            /// item. Esc is NOT consumed here - the window's overlay path
            /// closes the menu exactly like a click outside.
            bool OnKeyDown(uint32_t vk) override;
            int hover_index() const noexcept { return hover_; }

            void AdvanceAnimation(float dt_seconds) override;
            bool HasActiveAnimation() const noexcept override;
            /// Entrance progress in [0, 1] (1 = settled).
            float open_progress() const noexcept { return open_t_; }

        protected:
            Size MeasureCore(Size) override { return Size{0.0f, 0.0f}; }
            void ArrangeCore(Rect final_rect) override;
            // batch120: the popup list paints nothing of its own; the trigger box
            // and the list are drawn by ArrangeCore/child elements, so the ctx
            // parameter is intentionally unnamed (it used to warn C4100 in every
            // translation unit that included this header).
            void RenderCore(RenderCtx&) override {}

        private:
            Rect MenuRect() const noexcept;

            std::vector<Item> items_;
            bool open_ = false;
            int hover_ = -1;
            Point anchor_{};
            Rect client_{};
            float open_t_ = 1.0f;

        public:
            static constexpr float kOpenSeconds = 0.09f;
            const char* debug_role() const override { return "ContextMenu"; }
            void debug_state(DebugStateSink& s) const override {
                DebugWrite(s, "open", open_);
                DebugWrite(s, "items", static_cast<long long>(items_.size()));
                DebugWrite(s, "hover", static_cast<long long>(hover_));
            }
        };

        class ProgressBarElement : public Element {
        public:
            explicit ProgressBarElement(float value = 0.0f);
            /// Clamped to [0, 1].
            void SetValue(float value);
            float value() const noexcept { return value_; }

        protected:
            Size MeasureCore(Size available) override;
            void RenderCore(RenderCtx& ctx) override;

        private:
            float value_;

        public:
            const char* debug_role() const override { return "ProgressBar"; }
            void debug_state(DebugStateSink& s) const override {
                DebugWrite(s, "value", static_cast<double>(value_));
            }
        };

        enum class FormFieldType { Text, Select };

        struct FormField {
            std::string id;
            Str label = Str::_Count;
            FormFieldType type = FormFieldType::Text;
            std::wstring initial;
            std::vector<std::pair<std::wstring, std::wstring>> options;
        };

        struct FormResult {
            std::map<std::string, std::wstring> values;
        };

        /// Modal overlay: full-size dimmer + centered card. Esc cancels
        /// (never fires ok/submit); Enter confirms exactly once. Repeated
        /// Show calls reset the state instead of stacking.
        class DialogHost : public Element {
        public:
            enum class Mode { None, Message, Confirm, Form };

            DialogHost();
            /// Event-frame-external cleanup point: retires any leftover chrome
            /// and destroys previously retired subtrees. Never runs inside a
            /// widget event (runtime guarantee: dialogs are tree-owned and
            /// only die with the owning page).
            ~DialogHost();
            void ShowMessage(Str title, std::wstring body, Str ok);
            void ShowConfirm(Str title, std::wstring body, std::function<void()> on_ok);
            void ShowForm(Str title, std::vector<FormField> fields,
                          std::function<void(const FormResult&)> on_submit);
            /// T8 debug seam: raw-text dialog variants (arbitrary title/body,
            /// no Str key / i18n). The localized Show* paths stay unchanged.
            void ShowMessageText(std::wstring title, std::wstring body,
                                 std::wstring ok);
            /// batch25a: message dialog with one extra footer action (the
            /// help popup's [Copy]); OK still closes. The extra button is
            /// anchored as `dialog.action`, OK as `dialog.ok`.
            void ShowMessageActionText(std::wstring title, std::wstring body,
                                       std::wstring ok_label,
                                       std::wstring action_label,
                                       std::function<void()> on_action);
            void ShowConfirmText(std::wstring title, std::wstring body,
                                 std::function<void()> on_ok);
            /// batch24 P1-4: a two-button confirm with CUSTOM labels (the
            /// save->restart prompt: [restart now][later]). Same modal contract
            /// as
            /// ShowConfirm; cancel/Esc keep the current state.
            void ShowConfirmActionsText(std::wstring title, std::wstring body,
                                        std::wstring ok_label,
                                        std::wstring cancel_label,
                                        std::function<void()> on_ok,
                                        std::function<void()> on_cancel = {});
            /// batch27 P1-6: the three-way "unsaved changes" prompt
            /// [save][don't save][cancel]. Cancel (and Esc) only close; the
            /// save path runs `on_save` and the discard path `on_discard`.
            void ShowLeavePrompt(std::wstring title, std::wstring body,
                                 std::wstring save_label,
                                 std::wstring discard_label,
                                 std::wstring cancel_label,
                                 std::function<void()> on_save,
                                 std::function<void()> on_discard);
            void ShowFormText(std::wstring title, std::vector<FormField> fields,
                              std::function<void(const FormResult&)> on_submit);
            /// batch25b: form dialog with custom action labels (the first-run
            /// wizard: [save and start][skip]). Cancel still closes; on_cancel
            /// runs
            /// after the dialog retired so callers can resume their flow.
            void ShowFormActionsText(
                std::wstring title, std::wstring body_text,
                std::vector<FormField> fields, std::wstring submit_label,
                std::wstring cancel_label,
                std::function<void(const FormResult&)> on_submit,
                std::function<void()> on_cancel = {});
            void Close();
            bool open() const noexcept { return mode_ != Mode::None; }
            Mode mode() const noexcept { return mode_; }
            /// Full-window modal: must not consume a slot in the page flow.
            bool is_overlay() const override { return true; }
            /// The modal (dimmer + card + subtree) is painted in the top layer,
            /// above every page sibling (G4).
            bool renders_on_top() const override { return true; }
            /// Draws the whole modal subtree once (content pass skips it), so
            /// the translucent dimmer is never source-over composited twice.
            void RenderOverlay(RenderCtx& ctx) override;
            /// The dimmer swallows hits outside the card so the modal stays
            /// modal; inside the card the normal subtree hit test applies.
            Element* HitTestOverlay(Point p) override;

            /// Test anchor: editor element (TextInputElement or
            /// SelectElement) created for a form field id; nullptr if unknown.
            Element* form_field(const std::string& field_id) const noexcept;
            std::size_t form_field_count() const noexcept { return fields_.size(); }
            /// T9 test anchor: entrance progress in [0, 1] (1 = settled).
            float open_progress() const noexcept { return open_t_; }

            bool OnKeyDown(uint32_t vk) override;

            /// T9 entrance: the modal fades/scales in over `kDialogOpenSeconds`;
            /// the frame clock advances this and stops once settled.
            void AdvanceAnimation(float dt_seconds) override;
            bool HasActiveAnimation() const noexcept override;

        protected:
            Size MeasureCore(Size available) override;
            void ArrangeCore(Rect final_rect) override;
            void RenderCore(RenderCtx& ctx) override;

        private:
            struct FieldBinding {
                std::string id;
                FormFieldType type;
                Element* editor;
            };

            void Reset();
            void BeginDialog(Str title, const std::wstring& body_text);
            /// T8: raw-text variant of BeginDialog (no Str / i18n lookup).
            void BeginDialogText(const std::wstring& title,
                                 const std::wstring& body_text);
            StackPanel* FieldHost();
            StackPanel* AddButtonRow();
            void Confirm();
            FormResult Collect() const;

            Card* card_ = nullptr;
            StackPanel* body_ = nullptr;
            StackPanel* field_host_ = nullptr;
            StackPanel* footer_ = nullptr;
            ScrollView* scroll_ = nullptr;
            std::vector<FieldBinding> fields_;
            std::function<void()> on_ok_;
            std::function<void(const FormResult&)> on_submit_;
            Mode mode_ = Mode::None;
            /// Monotonic dialog generation: bumped by every Reset. Confirm()
            /// snapshots it and only tail-Closes when unchanged, so a Show*
            /// issued from inside the callback (any mode, same or new) keeps
            /// the freshly built dialog alive (nested-show guard).
            std::uint64_t generation_ = 0;
            /// T9 entrance progress [0, 1]: reset to 0 by BeginDialogText and
            /// eased to 1 by the frame clock. Drives the dimmer alpha ramp and
            /// the card scale (render-time geometry only; never bounds/HitTest).
            float open_t_ = 1.0f;

        public:
            const char* debug_role() const override { return "DialogHost"; }
            void debug_state(DebugStateSink& s) const override {
                DebugWrite(s, "mode",
                           static_cast<long long>(static_cast<int>(mode_)));
                DebugWrite(s, "open", open());
                DebugWrite(s, "field_count",
                           static_cast<long long>(fields_.size()));
                // T8: serialize each form field's current editor value.
                for (const FieldBinding& binding : fields_) {
                    const std::string key = "field:" + binding.id;
                    if (binding.type == FormFieldType::Select) {
                        const auto* se =
                            static_cast<const SelectElement*>(binding.editor);
                        DebugWrite(s, key.c_str(), se->selected_value());
                    } else {
                        const auto* ti =
                            static_cast<const TextInputElement*>(binding.editor);
                        DebugWrite(s, key.c_str(), ti->value());
                    }
                }
            }
        };

        /// Destroys subtrees retired by DialogHost closes (retire+sweep; the
        /// fix for the Button self-destruct UB: a button's frame stays alive
        /// until the event has fully unwound). Idempotent and reentrant.
        /// Call ONLY from a point with no widget event frames on the stack -
        /// the app tick (UiApp::OnTick) or the DialogHost destructor; never
        /// from Reset/BeginDialog or a widget/key callback.
        void SweepRetiredDialogChrome() noexcept;
        /// Number of retired subtrees still awaiting the next sweep (test
        /// anchor; bounds the retired memory across one tick).
        std::size_t RetiredDialogChromeCount() noexcept;

        enum class ToastKind { Info, Success, Warning, Danger };

        struct ToastEntry {
            Str text = Str::_Count;
            ToastKind kind = ToastKind::Info;
            std::chrono::steady_clock::time_point shown;
            /// T8: non-empty when shown via ShowText (arbitrary raw text); the
            /// render path prefers it over the localized Str key.
            std::wstring raw_text;
            /// T9 entrance progress [0, 1]: reset to 0 by Show/ShowText and
            /// eased to 1 by the frame clock. Drives the slide-in x offset and
            /// the alpha ramp (render-time only; never the layout).
            float t = 1.0f;
        };

        /// Bottom-right toast stack (T6 paints it): at most 3 entries - a
        /// fourth drops the oldest - and entries expire after 3 s once the
        /// app timer calls Tick(now). Never blocks clicks.
        class ToastHost : public Element {
        public:
            ToastHost();
            void Show(Str text, ToastKind kind = ToastKind::Info);
            /// T8 debug seam: show arbitrary raw text (no Str key / i18n).
            void ShowText(std::wstring text, ToastKind kind = ToastKind::Info);
            /// T8 debug seam: clear every active toast.
            void Clear();
            std::size_t active_count() const noexcept { return toasts_.size(); }
            void Tick(std::chrono::steady_clock::time_point now);
            const std::vector<ToastEntry>& toasts() const noexcept { return toasts_; }

            /// Toasts paint in the top layer, above dialogs (added last to the
            /// shell), so they are always visible.
            bool renders_on_top() const override { return true; }
            /// Draws the whole toast stack once in the top layer.
            void RenderOverlay(RenderCtx& ctx) override;

            /// T9 entrance: eases every entry's progress to 1 over
            /// `kToastOpenSeconds`; the frame clock stops once all settle.
            void AdvanceAnimation(float dt_seconds) override;
            bool HasActiveAnimation() const noexcept override;

            /// T9 test anchor: entrance progress of the newest entry (1.0 when
            /// the stack is empty).
            float newest_progress() const noexcept {
                return toasts_.empty() ? 1.0f : toasts_.back().t;
            }

        protected:
            Size MeasureCore(Size available) override;
            void RenderCore(RenderCtx& ctx) override;

        private:
            std::vector<ToastEntry> toasts_;

        public:
            const char* debug_role() const override { return "ToastHost"; }
            void debug_state(DebugStateSink& s) const override {
                DebugWrite(s, "active_count",
                           static_cast<long long>(toasts_.size()));
            }
        };

        // -------------------------------------------------------------------
        // Task 7 additions: shell chrome (sidebar / page header / empty state).
        // -------------------------------------------------------------------

        /// Left navigation rail (spec 7.2): 220 logical px wide, one button
        /// per page id, a 3 px accent bar marks the selected item (the
        /// renderer paints it from the selected()/indicator state). Clicks
        /// fire on_navigate with the page id.
        class Sidebar : public Element {
        public:
            Sidebar();

            static constexpr float kWidth = 220.0f;
            static constexpr float kIndicatorWidth = 3.0f;

            const std::vector<std::string>& items() const noexcept { return items_; }
            float width() const noexcept { return kWidth; }
            float indicator_width() const noexcept { return kIndicatorWidth; }
            /// Empty when nothing is selected.
            const std::string& selected() const noexcept { return selected_; }
            /// Index of the selected item; items().size() when none is set.
            std::size_t selected_index() const noexcept;
            /// Unknown ids clear the selection (no nav item matches).
            void SetSelected(std::string_view page_id);
            /// Relabels every item from the active language.
            void SetLang(I18n& i18n);

            /// Test anchor (nullptr when out of range).
            Button* item_button(std::size_t index) const noexcept;

            std::function<void(const std::string&)> on_navigate;

        protected:
            Size MeasureCore(Size available) override;
            void ArrangeCore(Rect final_rect) override;
            void RenderChildren(RenderCtx& ctx) override;

        private:
            std::vector<std::string> items_;
            std::vector<Button*> buttons_;
            StackPanel* panel_ = nullptr;
            std::string selected_;

        public:
            const char* debug_role() const override { return "Sidebar"; }
            void debug_state(DebugStateSink& s) const override {
                DebugWrite(s, "selected", selected_);
            }
        };

        /// 48 px page header: the current page title on the left. The failure
        /// status lives in the DriverBanner under the header (S5-AESTH R2:
        /// no in-header badge/reason, one single banner).
        class PageHeader : public Element {
        public:
            PageHeader();

            static constexpr float kHeight = 48.0f;
            float height() const noexcept { return kHeight; }

            void SetTitle(std::wstring title);
            Text* title_text() const noexcept { return title_; }

        protected:
            Size MeasureCore(Size available) override;
            void ArrangeCore(Rect final_rect) override;

        private:
            Text* title_ = nullptr;

        public:
            const char* debug_role() const override { return "PageHeader"; }
        };

        /// S5-AESTH R2: the single failure banner under the page header.
        /// One amber-outlined row: [status word (amber)] [reason (amber,
        /// secondary)] ... [repair button (DangerOutline, right)]. Everything
        /// shares one vertical baseline; the whole banner disappears when the
        /// dataplane is healthy.
        class DriverBanner : public Element {
        public:
            DriverBanner();

            static constexpr float kHeight = 44.0f;
            float height() const noexcept { return kHeight; }
            /// failed=false hides the whole banner. status/reason are the
            /// already-localized label texts. `show_action=false` hides the
            /// repair button (adapter warnings need a settings change, not a
            /// driver repair).
            void SetFailure(bool failed, std::wstring status,
                            std::wstring reason, bool show_action = true);
            void SetLang(I18n& i18n);

            Text* status_text() const noexcept { return status_; }
            Text* reason_text() const noexcept { return reason_; }
            Button* action_button() const noexcept { return action_; }

        protected:
            Size MeasureCore(Size available) override;
            void ArrangeCore(Rect final_rect) override;
            void RenderCore(RenderCtx& ctx) override;
            /// P5: children (the wrapped reason text) are clipped to the banner
            /// frame, so an over-long localized reason can never paint past the
            /// rounded border.
            void RenderChildren(RenderCtx& ctx) override;

        private:
            Text* status_ = nullptr;
            Text* reason_ = nullptr;
            Button* action_ = nullptr;
        };

        /// S5-AESTH P2: centered "no data" placeholder, now with a dim glyph above
        /// the text and a brighter main-colour label (the old dim grey read as
        /// too faint on the panel background).
        class EmptyState : public Text {
        public:
            explicit EmptyState(Str message);
            void SetMessage(Str message);
            Str message_key() const noexcept { return key_; }

        protected:
            Size MeasureCore(Size available) override;
            void RenderCore(RenderCtx& ctx) override;

        private:
            static constexpr float kGlyphH = 24.0f;
            Str key_ = Str::_Count;
        };

        /// R4a: stretches the content column to the bottom and centres the
        /// empty placeholder in the leftover space. Mirrors dashboard's
        /// S5-AESTH R2 pattern: MeasureCore claims max(natural, available.h)
        /// so a StackPanel arranges it over the full remaining height, and
        /// ArrangeCore puts the (possibly absent) table at the top and the
        /// empty state centred inside the panel. Shared so every data page
        /// gets the same empty-state behaviour instead of a thin band.
        class FillPanel : public Element {
        public:
            FillPanel() { hit_transparent = true; }

            /// Owns `table` (may be null for pages without a table, e.g. the
            /// bridge page); returns the borrowed pointer for column setup.
            TableElement* SetTable(std::unique_ptr<TableElement> table) {
                return table_ = static_cast<TableElement*>(Element::Add(std::move(table)));
            }
            EmptyState* SetEmpty(std::unique_ptr<EmptyState> empty) {
                return empty_ = static_cast<EmptyState*>(Element::Add(std::move(empty)));
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
                return Size{available.w, std::max(natural, available.h)};
            }

            void ArrangeCore(Rect final_rect) override {
                if (table_ != nullptr) {
                    table_->Arrange(final_rect);
                }
                if (empty_ != nullptr && empty_->visible) {
                    const Size d = empty_->desired();
                    // batch27 D2: when the table still paints its header band,
                    // the header belongs to the "empty" surface - centring the
                    // placeholder in the WHOLE panel left it visually glued to
                    // the header (unequal top/bottom whitespace). The usable
                    // region therefore starts below the header band.
                    const float header_h =
                        (table_ != nullptr && table_->bounds().h > 0.0f)
                            ? table_->header_height()
                            : 0.0f;
                    const float top = final_rect.y + header_h;
                    const float region_h =
                        std::max(final_rect.h - header_h, 0.0f);
                    // Clamp the centred box inside the panel so a very short
                    // viewport never pushes the placeholder off-screen.
                    const float w = std::min(d.w, final_rect.w);
                    const float h = std::min(d.h, region_h);
                    empty_->Arrange(Rect{
                        final_rect.x + (final_rect.w - w) * 0.5f,
                        top + (region_h - h) * 0.5f, w, h});
                }
            }

        private:
            TableElement* table_ = nullptr;
            EmptyState* empty_ = nullptr;
        };

    }  // namespace ui
}  // namespace vgww
