// ============================================================================
// console.cpp - scrollable console page (batch19 R3-2).
//
// Shows the process stdout/stderr captured by ui::console_log (a pipe dup'ed
// onto CRT fds 1/2 + a reader thread + a bounded line ring). The view follows
// the tail by default; a wheel-up detaches it, scrolling back to the bottom
// re-attaches. One DrawText per visible line keeps the frame cheap even with
// the full 2000-line ring.
// ============================================================================
#include "ui/pages/page.h"
#include "ui/pages/page_util.h"

#include "ui/console_log.h"
#include "ui/renderer.h"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <memory>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace vgww {
    namespace ui {

        namespace {

            /// Fixed-height log surface. batch28 D8: a long line now WRAPS
            /// (logs must stay fully readable) instead of being clipped at the
            /// card edge; one source line may therefore occupy several visual
            /// rows. `rows_` is the flattened display list of (source line,
            /// segment offset/length) entries and the scroll arithmetic indexes
            /// THAT list, so offset / kLineH still addresses exactly one painted
            /// row.
            class ConsoleLogView final : public Element {
            public:
                static constexpr float kLineH = 16.0f;
                static constexpr float kWheelStep = 48.0f;  // matches ScrollView

                ConsoleLogView() {
                    hit_transparent = false;
                    // The view owns its own scrolling; make the page's stack
                    // give it the remaining height.
                    fill_remaining = true;
                }

                void SetLines(std::vector<std::wstring> lines) {
                    if (lines == lines_) {
                        return;
                    }
                    // batch24 P2-7: the ring is a fixed 2000-line FIFO, so old
                    // lines expire as new ones arrive. While the view is
                    // DETACHED (the user scrolls up), re-anchor the top to the
                    // SAME source line TEXT it showed before, so expiration no
                    // longer pulls the reading position forward (an index
                    // anchor would drift by exactly the expired count).
                    std::wstring anchor;
                    float intra = 0.0f;
                    if (!follow_ && !rows_.empty()) {
                        const float first_f = std::floor(offset_ / kLineH);
                        const std::size_t first =
                            first_f > 0.0f ? static_cast<std::size_t>(first_f)
                                           : 0;
                        if (first < rows_.size() &&
                            rows_[first].line < lines_.size()) {
                            anchor = lines_[rows_[first].line];
                            intra = offset_ - first_f * kLineH;
                        }
                    }
                    lines_ = std::move(lines);
                    ++content_rev;
                    InvalidateLayout();
                    WrapLines(bounds_.w);
                    // batch70: rows_ was just rebuilt, so the stored row
                    // indices may now point at different text. Re-derive them
                    // from the remembered (line text, offset) identity.
                    RestoreSelectionIdentity();
                    if (follow_) {
                        offset_ = MaxOffset(bounds_.h);
                    } else if (!anchor.empty()) {
                        for (std::size_t i = 0; i < rows_.size(); ++i) {
                            if (rows_[i].line < lines_.size() &&
                                lines_[rows_[i].line] == anchor) {
                                offset_ =
                                    static_cast<float>(i) * kLineH + intra;
                                break;
                            }
                        }
                    }
                    Clamp(bounds_.h);
                }

                std::size_t line_count() const noexcept { return lines_.size(); }
                /// Painted rows (>= lines: a wrapped line spans several).
                std::size_t row_count() const noexcept { return rows_.size(); }
                float offset() const noexcept { return offset_; }
                float content_height() const noexcept {
                    return static_cast<float>(rows_.size()) * kLineH;
                }
                float view_height() const noexcept { return bounds_.h; }
                bool follow() const noexcept { return follow_; }
                std::size_t wheel_events() const noexcept {
                    return wheel_events_;
                }

                // batch37i (user: "the console output cannot be selected or
                // copied"): read-only text selection. Ctrl+C/A are routed by
                // the window through the generic Element clipboard hooks.
                bool focusable() const override { return true; }
                bool has_selection() const noexcept {
                    return sel_anchor_row_ >= 0 && sel_caret_row_ >= 0;
                }
                bool EditMenuTarget() const override { return true; }
                bool HasTextSelection() const override {
                    return has_selection();
                }
                bool HasTextContent() const override { return !rows_.empty(); }
                bool SelectAllText() override {
                    if (rows_.empty()) {
                        return false;
                    }
                    sel_anchor_row_ = 0;
                    sel_anchor_col_ = 0;
                    sel_caret_row_ = static_cast<int>(rows_.size()) - 1;
                    sel_caret_col_ = static_cast<int>(
                        RowText(rows_.size() - 1).size());
                    // batch70: select-all also needs a stable identity.
                    CaptureSelectionIdentity();
                    ++content_rev;
                    return true;
                }
                /// batch284: the TEXT of the current selection (empty when
                /// nothing is selected or the selection spans zero
                /// characters). `CopySelectionToClipboard` returns `false` for
                /// both "no selection" and "clipboard write failed", so the
                /// page cannot tell them apart through that bool alone - it
                /// needs the text to decide what to copy BEFORE writing.
                std::wstring SelectedText() const {
                    if (!has_selection()) {
                        return std::wstring();
                    }
                    int lo_r = sel_anchor_row_;
                    int lo_c = sel_anchor_col_;
                    int hi_r = sel_caret_row_;
                    int hi_c = sel_caret_col_;
                    if (hi_r < lo_r ||
                        (hi_r == lo_r && hi_c < lo_c)) {
                        std::swap(lo_r, hi_r);
                        std::swap(lo_c, hi_c);
                    }
                    lo_r = std::max(lo_r, 0);
                    hi_r = std::min(hi_r, static_cast<int>(rows_.size()) - 1);
                    std::wstring out;
                    for (int r = lo_r; r <= hi_r; ++r) {
                        const std::wstring_view text =
                            RowText(static_cast<std::size_t>(r));
                        // batch54: only the FIRST and LAST row of a multi-row
                        // selection are clipped at the caret; every row in
                        // between is copied in full. The old `r == hi_r ? hi_c
                        // : 0` also truncated the middle rows to nothing, so
                        // copying a multi-line selection kept just the last
                        // line (and emitted one blank line per skipped row).
                        const int from = (r == lo_r) ? lo_c : 0;
                        const int to = (r == hi_r) ? hi_c
                                                   : static_cast<int>(
                                                         text.size());
                        const std::size_t a = static_cast<std::size_t>(
                            std::min(std::max(from, 0),
                                     static_cast<int>(text.size())));
                        const std::size_t b = static_cast<std::size_t>(
                            std::min(std::max(to, 0),
                                     static_cast<int>(text.size())));
                        if (b > a) {
                            out.append(text.data() + a, b - a);
                        }
                        if (r < hi_r) {
                            out.push_back(L'\n');
                        }
                    }
                    return out;
                }

                bool CopySelectionToClipboard() override {
                    const std::wstring text = SelectedText();
                    if (text.empty()) {
                        return false;
                    }
                    // batch54: one clipboard funnel - the Copy button already
                    // writes through console_log::CopyToClipboard (which reports
                    // failure); a direct SetClipboardText here reported success
                    // even when the clipboard could not be opened.
                    return console_log::CopyToClipboard(text);
                }
                bool OnMouseDown(Point p) override {
                    if (!EffectivelyEnabled() || rows_.empty()) {
                        return false;
                    }
                    dragging_ = true;
                    const int row = RowAtY(p.y);
                    const int col = ColAtX(row, p.x);
                    sel_anchor_row_ = row;
                    sel_anchor_col_ = col;
                    sel_caret_row_ = row;
                    sel_caret_col_ = col;
                    // batch70: pin the endpoints to their source line TEXT.
                    CaptureSelectionIdentity();
                    ++content_rev;
                    return true;
                }
                bool OnMouseMove(Point p) override {
                    if (!dragging_ || rows_.empty()) {
                        return false;
                    }
                    const int row = RowAtY(p.y);
                    const int col = ColAtX(row, p.x);
                    if (row == sel_caret_row_ && col == sel_caret_col_) {
                        return false;
                    }
                    sel_caret_row_ = row;
                    sel_caret_col_ = col;
                    // batch70: the caret endpoint moved - refresh the identity
                    // so the next FIFO refresh re-derives THIS range.
                    CaptureSelectionIdentity();
                    ++content_rev;
                    return true;
                }
                bool OnMouseUp(Point) override {
                    if (!dragging_) {
                        return false;
                    }
                    dragging_ = false;
                    ++content_rev;
                    return true;
                }

                bool OnWheel(int delta) override {
                    if (delta == 0) {
                        return false;
                    }
                    ++wheel_events_;
                    const float before = offset_;
                    offset_ += (delta > 0 ? -kWheelStep : kWheelStep);
                    Clamp(bounds_.h);
                    // Re-attach only when the user reaches the bottom again.
                    follow_ = offset_ >= MaxOffset(bounds_.h) - 0.5f;
                    // batch34y: mirror the ScrollView/TableElement contract -
                    // an edge event that cannot move the offset must bubble
                    // instead of being swallowed, so an outer container can
                    // take over once this view is pinned at an end.
                    return offset_ != before;
                }

                /// User request: the console must scroll from the keyboard too,
                /// not just the wheel. Up/Down move one row, PageUp/PageDown one
                /// viewport, Home/End jump to the ends - the same six keys and
                /// the same step semantics as ScrollView::OnKeyDown, so the two
                /// viewports behave identically. Returns true only when the
                /// offset actually moved (an unconsumed key keeps bubbling).
                /// The window routes these keys to the container nearest the
                /// pointer, so ConsoleLogView must also be accepted by that
                /// fallback (see RouteKey) - it is not a ScrollView.
                bool OnKeyDown(uint32_t vk) override {
                    if (vk == 0x1B) {  // Esc clears the selection
                        if (!has_selection()) {
                            return false;
                        }
                        sel_anchor_row_ = -1;
                        sel_caret_row_ = -1;
                        ++content_rev;
                        return true;
                    }
                    constexpr uint32_t kVkUp = 0x26;
                    constexpr uint32_t kVkDown = 0x28;
                    constexpr uint32_t kVkPrior = 0x21;  // PageUp
                    constexpr uint32_t kVkNext = 0x22;   // PageDown
                    constexpr uint32_t kVkHome = 0x24;
                    constexpr uint32_t kVkEnd = 0x23;
                    const float page = std::max(bounds_.h - kLineH, kLineH);
                    const float before = offset_;
                    switch (vk) {
                        case kVkUp:
                            offset_ -= kLineH;
                            break;
                        case kVkDown:
                            offset_ += kLineH;
                            break;
                        case kVkPrior:
                            offset_ -= page;
                            break;
                        case kVkNext:
                            offset_ += page;
                            break;
                        case kVkHome:
                            offset_ = 0.0f;
                            break;
                        case kVkEnd:
                            offset_ = MaxOffset(bounds_.h);
                            break;
                        default:
                            return false;
                    }
                    ++key_events_;
                    Clamp(bounds_.h);
                    // Same follow rule as the wheel: the tail is re-attached
                    // only once the view is back at the bottom.
                    follow_ = offset_ >= MaxOffset(bounds_.h) - 0.5f;
                    return offset_ != before;
                }

                std::size_t key_events() const noexcept { return key_events_; }

                /// batch34y: the single scroll-container predicate - this
                /// surface owns a viewport (clip + offset + clamp), so it must
                /// take part in wheel bubbling, the wheel repaint box, the
                /// keyboard fallback and the popup viewport test exactly like
                /// ScrollView/TableElement do.
                bool IsScrollContainer() const noexcept override { return true; }

                const char* debug_role() const override { return "ConsoleLog"; }
                void debug_state(DebugStateSink& s) const override {
                    DebugWrite(s, "lines", static_cast<long long>(lines_.size()));
                    DebugWrite(s, "rows", static_cast<long long>(rows_.size()));
                    DebugWrite(s, "offset", static_cast<double>(offset_));
                    DebugWrite(s, "follow", follow_);
                    DebugWrite(s, "wheel_events",
                               static_cast<long long>(wheel_events_));
                    // batch59 seam: the drag caret, so the pointer->column
                    // mapping is assertable without reaching into the view.
                    DebugWrite(s, "sel_row",
                               static_cast<long long>(sel_caret_row_));
                    DebugWrite(s, "sel_col",
                               static_cast<long long>(sel_caret_col_));
                    if (!lines_.empty()) {
                        DebugWrite(s, "last_line", lines_.back());
                    }
                    // batch24 P2-7: the top-of-viewport line, so the detached
                    // re-anchor on ring expiration is assertable. batch28: the
                    // SOURCE line owning the first visible row.
                    if (!rows_.empty()) {
                        const float first_f = std::floor(offset_ / kLineH);
                        const std::size_t first =
                            first_f > 0.0f ? static_cast<std::size_t>(first_f)
                                           : 0;
                        if (first < rows_.size() &&
                            rows_[first].line < lines_.size()) {
                            DebugWrite(s, "first_line",
                                       lines_[rows_[first].line]);
                        }
                    }
                }

            protected:
                Size MeasureCore(Size available) override {
                    // Fill the card: the height comes from the parent stack.
                    return Size{std::max(0.0f, available.w),
                                std::max(0.0f, available.h)};
                }

                void ArrangeCore(Rect final_rect) override {
                    // batch28: the wrap points depend on the width; rebuild
                    // only when it actually changed (a height-only resize must
                    // not re-measure every line).
                    if (final_rect.w != wrap_width_) {
                        WrapLines(final_rect.w);
                    }
                    if (follow_) {
                        offset_ = MaxOffset(final_rect.h);
                    }
                    Clamp(final_rect.h);
                }

                void RenderCore(RenderCtx& ctx) override {
                    // batch73: painting must not move the scroll position.
                    // ArrangeCore (geometry) and SetLines (content) already
                    // re-anchor `offset_` while following the tail; repeating
                    // it here was a paint-time state write, so "what was drawn"
                    // and "what the window thinks is drawn" could diverge.
                    // The clamp stays: a stale offset from a shrink is still
                    // corrected.
                    Clamp(bounds_.h);
                    if (rows_.empty() || bounds_.w <= 0.0f ||
                        bounds_.h <= 0.0f) {
                        return;
                    }
                    ctx.ClipPush(bounds_);
                    int sel_lo_row = 0;
                    int sel_lo_col = 0;
                    int sel_hi_row = -1;
                    int sel_hi_col = 0;
                    if (has_selection()) {
                        sel_lo_row = sel_anchor_row_;
                        sel_lo_col = sel_anchor_col_;
                        sel_hi_row = sel_caret_row_;
                        sel_hi_col = sel_caret_col_;
                        if (sel_hi_row < sel_lo_row ||
                            (sel_hi_row == sel_lo_row &&
                             sel_hi_col < sel_lo_col)) {
                            std::swap(sel_lo_row, sel_hi_row);
                            std::swap(sel_lo_col, sel_hi_col);
                        }
                    }
                    Color sel_color = ColorFor(ColorToken::Accent);
                    sel_color.a = 0.35f;
                    // batch54: scratch reused across rows so a wrapped segment
                    // costs no allocation unless the row really is a substring.
                    std::wstring row_scratch;
                    const float first_f = std::floor(offset_ / kLineH);
                    const std::size_t first = static_cast<std::size_t>(
                        std::max(0.0f, first_f));
                    const std::size_t row_span =
                        static_cast<std::size_t>(
                            std::ceil(bounds_.h / kLineH)) + 2;
                    const std::size_t last =
                        std::min(rows_.size(), first + row_span);
                    for (std::size_t i = first; i < last; ++i) {
                        const float y = bounds_.y +
                                        static_cast<float>(i) * kLineH -
                                        offset_;
                        if (y + kLineH <= bounds_.y ||
                            y >= bounds_.y + bounds_.h) {
                            continue;
                        }
                        // ClipPush above is the hard guarantee: a glyph that
                        // still overflows (a single unbreakable token) can
                        // never paint past the card.
                        if (has_selection() &&
                            static_cast<int>(i) >= sel_lo_row &&
                            static_cast<int>(i) <= sel_hi_row) {
                            const std::wstring_view row_text = RowText(i);
                            const std::size_t a = static_cast<std::size_t>(
                                std::min(std::max(static_cast<int>(i) ==
                                                          sel_lo_row
                                                      ? sel_lo_col
                                                      : 0,
                                                  0),
                                         static_cast<int>(row_text.size())));
                            const std::size_t b = static_cast<std::size_t>(
                                std::min(std::max(static_cast<int>(i) ==
                                                          sel_hi_row
                                                      ? sel_hi_col
                                                      : static_cast<int>(
                                                            row_text.size()),
                                                  0),
                                         static_cast<int>(row_text.size())));
                            if (b > a) {
                                const float wa =
                                    MeasureText(std::wstring(
                                                    row_text.substr(0, a)),
                                                FontToken::Small, kUnbounded)
                                        .w;
                                const float wb =
                                    MeasureText(std::wstring(
                                                    row_text.substr(0, b)),
                                                FontToken::Small, kUnbounded)
                                        .w;
                                ctx.FillRect(Rect{bounds_.x + wa, y,
                                                  std::max(wb - wa, 1.0f),
                                                  kLineH},
                                             sel_color);
                            }
                        }
                        ctx.DrawTextSingleLine(
                            RowTextRef(i, row_scratch),
                            Rect{bounds_.x, y, bounds_.w, kLineH},
                            FontToken::Small, ColorFor(ColorToken::Text),
                            Align::Start);
                    }
                    ctx.ClipPop();
                }

            private:
                /// One painted row: which source line it belongs to and WHERE
                /// its (possibly truncated) text segment sits inside that line.
                /// batch54: it stores an offset/length VIEW, not a copy. The old
                /// `std::wstring text` duplicated the whole ring on every append
                /// (2000 heap copies per logged line, plus a permanent second
                /// copy of the entire log text). Rows never outlive `lines_`
                /// (WrapLines rebuilds them from it), so the view is safe.
                struct Row {
                    std::size_t line = 0;
                    std::size_t off = 0;
                    std::size_t len = 0;
                };

                static constexpr float kUnbounded = 1.0e9f;

                /// The text of painted row `r`, viewed in place inside lines_.
                /// batch54: no copy (see Row).
                std::wstring_view RowText(std::size_t r) const noexcept {
                    const Row& row = rows_[r];
                    return std::wstring_view(lines_[row.line]).substr(row.off,
                                                                      row.len);
                }

                /// Same text as a reference: a whole-line row (the common case)
                /// returns the ring's own string with no allocation at all; a
                /// wrapped segment is materialised into `scratch`, whose buffer
                /// is reused across the rows of one frame.
                const std::wstring& RowTextRef(std::size_t r,
                                               std::wstring& scratch) const {
                    const Row& row = rows_[r];
                    const std::wstring& src = lines_[row.line];
                    if (row.off == 0 && row.len == src.size()) {
                        return src;
                    }
                    scratch.assign(src, row.off, row.len);
                    return scratch;
                }

                /// True when the test measure seam is in force (it ignores the
                /// width clamp): wrapping then cannot be computed meaningfully
                /// and the lines stay one row each.
                static bool NaturalMeasureAvailable() {
                    return MeasureText(L"x", FontToken::Small, 1.0f).w <= 1.5f;
                }

                /// batch70: remember the selection endpoints by (source line
                /// TEXT, absolute offset in that line) so they survive the
                /// ring's FIFO churn. MUST be called after every event that
                /// moves the selection, while `rows_` still matches `lines_`.
                void CaptureSelectionIdentity() {
                    if (sel_anchor_row_ < 0 || sel_caret_row_ < 0 ||
                        static_cast<std::size_t>(sel_anchor_row_) >= rows_.size() ||
                        static_cast<std::size_t>(sel_caret_row_) >= rows_.size()) {
                        sel_identity_valid_ = false;
                        return;
                    }
                    const Row& a =
                        rows_[static_cast<std::size_t>(sel_anchor_row_)];
                    const Row& c =
                        rows_[static_cast<std::size_t>(sel_caret_row_)];
                    if (a.line >= lines_.size() || c.line >= lines_.size()) {
                        sel_identity_valid_ = false;
                        return;
                    }
                    sel_anchor_line_ = lines_[a.line];
                    sel_anchor_off_ =
                        a.off + static_cast<std::size_t>(
                                    std::max(sel_anchor_col_, 0));
                    sel_caret_line_ = lines_[c.line];
                    sel_caret_off_ =
                        c.off + static_cast<std::size_t>(
                                    std::max(sel_caret_col_, 0));
                    sel_identity_valid_ = true;
                }

                /// batch70: re-derive (row, col) from the remembered identity
                /// after `lines_`/`rows_` were rebuilt. Rows are searched by
                /// line text (the ring has no stable ids); an endpoint whose
                /// line expired is clamped to the nearest surviving row so the
                /// highlight stays visible instead of pointing at nothing.
                void RestoreSelectionIdentity() {
                    if (!sel_identity_valid_ || rows_.empty()) {
                        return;
                    }
                    const auto locate = [this](const std::wstring& text,
                                               std::size_t off) -> std::pair<int, int> {
                        for (std::size_t i = 0; i < rows_.size(); ++i) {
                            const Row& row = rows_[i];
                            if (row.line >= lines_.size()) {
                                continue;
                            }
                            if (lines_[row.line] != text) {
                                continue;
                            }
                            if (off >= row.off && off <= row.off + row.len) {
                                return {static_cast<int>(i),
                                        static_cast<int>(off - row.off)};
                            }
                        }
                        // The chosen line expired: keep the same distance from
                        // the tail so the user still sees a plausible place.
                        return {-1, 0};
                    };
                    const std::pair<int, int> a =
                        locate(sel_anchor_line_, sel_anchor_off_);
                    const std::pair<int, int> c =
                        locate(sel_caret_line_, sel_caret_off_);
                    if (a.first < 0 || c.first < 0) {
                        // Line gone: drop the selection rather than highlight
                        // an unrelated row.
                        sel_anchor_row_ = -1;
                        sel_caret_row_ = -1;
                        sel_identity_valid_ = false;
                        return;
                    }
                    sel_anchor_row_ = a.first;
                    sel_anchor_col_ = a.second;
                    sel_caret_row_ = c.first;
                    sel_caret_col_ = c.second;
                }

                /// Rebuilds `rows_` for `width`: greedy wrap at the widest
                /// prefix that fits, preferring a break after a space / after a
                /// CJK character; an unbreakable long token is hard-split so a
                /// single URL can never paint outside the card.
                /// batch53: the ring is a 2000-line FIFO and every captured
                /// stdout/stderr line lands here as ONE new element. Re-wrapping
                /// the whole ring measured every old line again (~14k DWrite
                /// layout probes for a single appended line, a multi-ms frame
                /// spike). A line's split is a pure function of (text, width),
                /// so memoise it: only NEW text is measured, unchanged lines
                /// reuse their split. The cache is dropped whenever the width
                /// or the text-measure implementation changes, so a stale split
                /// can never be painted.
                void WrapLines(float width) {
                    wrap_width_ = width;
                    rows_.clear();
                    rows_.reserve(lines_.size());
                    if (width <= 0.0f || !NaturalMeasureAvailable()) {
                        // Unmeasurable (test seam without the real measure):
                        // one row per line, nothing to memoise.
                        wrap_cache_.clear();
                        wrap_cache_width_ = width;
                        for (std::size_t i = 0; i < lines_.size(); ++i) {
                            rows_.push_back(
                                Row{i, 0, lines_[i].size()});
                        }
                        return;
                    }
                    const uint64_t gen = TextMeasureGeneration();
                    if (width != wrap_cache_width_ || gen != wrap_cache_gen_) {
                        wrap_cache_.clear();
                        wrap_cache_width_ = width;
                        wrap_cache_gen_ = gen;
                    }
                    for (std::size_t i = 0; i < lines_.size(); ++i) {
                        const std::wstring& text = lines_[i];
                        auto it = wrap_cache_.find(text);
                        if (it == wrap_cache_.end()) {
                            if (wrap_cache_.size() >= kMaxWrapCacheEntries) {
                                wrap_cache_.clear();
                            }
                            it = wrap_cache_
                                     .emplace(text, SplitCuts(text, width))
                                     .first;
                        }
                        // The cached cut list holds a copy-free offset list
                        // ({start, end, start, end, ...}), so emitting the rows
                        // copies no text at all.
                        const std::vector<std::size_t>& cuts = it->second;
                        for (std::size_t k = 0; k + 1 < cuts.size(); k += 2) {
                            rows_.push_back(Row{i, cuts[k],
                                                cuts[k + 1] - cuts[k]});
                        }
                    }
                }

                /// The row boundaries of one source line at `width`, as
                /// {start0, end0, start1, end1, ...} pairs. batch54: offsets,
                /// not substrings - the caller views them inside the ring's own
                /// string, so emitting a 2000-line ring copies no text.
                std::vector<std::size_t> SplitCuts(const std::wstring& text,
                                                   float width) const {
                    std::vector<std::size_t> cuts;
                    if (text.empty()) {
                        cuts.push_back(0);  // one empty row, start == end
                        cuts.push_back(0);
                        return cuts;
                    }
                    std::size_t start = 0;
                    while (start < text.size()) {
                        // Longest prefix that still fits (binary search).
                        std::size_t lo = start + 1;
                        std::size_t hi = text.size();
                        std::size_t best = start + 1;  // always advance
                        while (lo <= hi) {
                            const std::size_t mid = lo + (hi - lo) / 2;
                            if (MeasureText(text.substr(start, mid - start),
                                            FontToken::Small, kUnbounded)
                                    .w <= width) {
                                best = mid;
                                lo = mid + 1;
                            } else {
                                if (mid == 0) {
                                    break;
                                }
                                hi = mid - 1;
                            }
                        }
                        std::size_t end = best;
                        if (end < text.size()) {
                            // Prefer breaking at the last space/CJK boundary
                            // inside the fitting prefix so words stay whole.
                            const std::size_t floor_pos =
                                (end > start + 1) ? end : start + 1;
                            std::size_t cut = std::wstring::npos;
                            for (std::size_t k = floor_pos; k > start; --k) {
                                const wchar_t ch = text[k - 1];
                                if (ch == L' ' || ch == L'\t' || ch == L'-' ||
                                    ch == L',' || ch == L';' || ch == L'/' ||
                                    ch >= 0x2E80) {
                                    cut = k;
                                    break;
                                }
                            }
                            if (cut != std::wstring::npos && cut > start) {
                                end = cut;
                            }
                        }
                        if (end <= start) {
                            end = start + 1;  // never loop forever
                        }
                        cuts.push_back(start);
                        cuts.push_back(end);
                        start = end;
                        // A break at a space swallows the space (no leading
                        // blank row start).
                        while (start < text.size() && text[start] == L' ') {
                            ++start;
                        }
                    }
                    return cuts;
                }

                float MaxOffset(float view_h) const noexcept {
                    return std::max(0.0f, content_height() - view_h);
                }
                void Clamp(float view_h) noexcept {
                    offset_ = std::max(0.0f,
                                       std::min(offset_, MaxOffset(view_h)));
                }

                std::vector<std::wstring> lines_;
                std::vector<Row> rows_;
                /// Width `rows_` was wrapped for (rebuilt on a width change).
                float wrap_width_ = -1.0f;
                /// batch53: per-line split cache (key = source line text,
                /// value = its {start,end,...} row boundary pairs).
                /// Bounded: the ring holds 2000 lines, so 4096 distinct texts
                /// cover a full window of churn; past that the cache resets
                /// (a reset only costs re-measuring, never a wrong split).
                static constexpr std::size_t kMaxWrapCacheEntries = 4096;
                std::unordered_map<std::wstring, std::vector<std::size_t>>
                    wrap_cache_;
                float wrap_cache_width_ = -1.0f;
                std::uint64_t wrap_cache_gen_ = 0;
                float offset_ = 0.0f;
                bool follow_ = true;
                std::size_t wheel_events_ = 0;
                std::size_t key_events_ = 0;
                // batch37i: read-only selection (row/col in the WRAPPED text).
                int sel_anchor_row_ = -1;
                int sel_anchor_col_ = 0;
                int sel_caret_row_ = -1;
                int sel_caret_col_ = 0;
                bool dragging_ = false;
                // batch70: the ring is a FIFO, so a row INDEX is not stable
                // across SetLines (expired lines shift every survivor down by
                // one). Keep each endpoint as (source line TEXT, absolute
                // character offset in that line) - the same identity the
                // scroll anchor already uses - and re-derive (row, col) after
                // every refresh. Without this the highlight slid to a
                // different line and Ctrl+C copied text the user never picked.
                bool sel_identity_valid_ = false;
                std::wstring sel_anchor_line_;
                std::size_t sel_anchor_off_ = 0;
                std::wstring sel_caret_line_;
                std::size_t sel_caret_off_ = 0;

                /// batch59: one-row prefix-width memo behind ColAtX. Keyed by
                /// (row text, measure generation) exactly like the M7 caret
                /// cache; `mutable` because ColAtX is const.
                mutable std::vector<float> prefix_w_;
                mutable std::wstring prefix_src_;
                mutable std::uint64_t prefix_gen_ = 0;

                int RowAtY(float y) const noexcept {
                    if (rows_.empty()) {
                        return -1;
                    }
                    const float rel = y - bounds_.y + offset_;
                    int r = static_cast<int>(std::floor(rel / kLineH));
                    r = std::max(r, 0);
                    r = std::min(r, static_cast<int>(rows_.size()) - 1);
                    return r;
                }

                /// batch59: the nearest inter-character boundary of `row`,
                /// decided by the SAME midpoint scan as before. That scan
                /// measured every prefix (i = 1..n) on EVERY pointer event and
                /// a drag-select emits tens of events per second, so one
                /// 2000-char row cost n DWrite layouts plus O(n^2) character
                /// copies per event. The prefix table is a pure function of
                /// (row text, measure implementation), so memoise it exactly
                /// like TextInputElement::EnsurePrefixWidths (M7 batch3): the
                /// cache changes WHEN the prefixes are measured, never the
                /// values the scan compares.
                void EnsurePrefixWidths(int row) const {
                    const std::wstring_view text = RowText(row);
                    if (prefix_gen_ == TextMeasureGeneration() &&
                        prefix_w_.size() == text.size() + 1 &&
                        std::wstring_view(prefix_src_) == text) {
                        return;
                    }
                    prefix_src_.assign(text.data(), text.size());  // owned copy
                    prefix_w_.assign(text.size() + 1, 0.0f);
                    // Build the prefixes by appending one character at a time:
                    // same strings, O(n) copies instead of O(n^2).
                    std::wstring probe;
                    probe.reserve(text.size());
                    for (std::size_t i = 1; i <= text.size(); ++i) {
                        probe.push_back(text[i - 1]);
                        prefix_w_[i] =
                            MeasureText(probe, FontToken::Small, kUnbounded).w;
                    }
                    prefix_gen_ = TextMeasureGeneration();
                }

                int ColAtX(int row, float x) const {
                    if (row < 0 || row >= static_cast<int>(rows_.size())) {
                        return 0;
                    }
                    const std::wstring_view text = RowText(row);
                    const float rel = x - bounds_.x;
                    if (rel <= 0.0f) {
                        return 0;
                    }
                    EnsurePrefixWidths(row);
                    if (prefix_w_.size() != text.size() + 1) {
                        return 0;  // defensive: the table must match the row
                    }
                    float prev = 0.0f;
                    for (std::size_t i = 1; i <= text.size(); ++i) {
                        const float w = prefix_w_[i];
                        if (rel < (prev + w) * 0.5f) {
                            return static_cast<int>(i) - 1;
                        }
                        prev = w;
                    }
                    return static_cast<int>(text.size());
                }
            };

            class ConsolePage final : public Page {
            public:
                const char* id() const override { return "console"; }
                Str title() const override { return Str::NavConsole; }
                void Build(Element& host, PageContext& ctx) override;
                void Update(const UiSnapshot& snapshot, I18n& i18n) override;

            private:
                ConsoleLogView* view_ = nullptr;
                Button* copy_ = nullptr;
                Element* host_ = nullptr;
                /// batch116: the console was the only data page with no
                /// empty placeholder, so an empty ring rendered as a blank card
                /// indistinguishable from a broken view.
                EmptyState* empty_ = nullptr;
                /// batch126: evicted ring lines (possibly audit records).
                Text* dropped_hint_ = nullptr;
                std::uint64_t last_rev_ = 0;
            };

            void ConsolePage::Build(Element& host, PageContext& ctx) {
                host_ = &host;
                // batch20 item 7: the captured output could not be copied at all;
                // a Copy button puts the whole ring on the clipboard.
                auto bar = std::make_unique<StackPanel>(Orientation::Horizontal,
                                                        8.0f);
                auto copy = std::make_unique<Button>(
                    I18n::Instance().T(Str::ConsoleCopy),
                    ButtonStyle::Secondary);
                copy->id = "console.copy";
                copy_ = static_cast<Button*>(bar->Add(std::move(copy)));
                copy_->on_click = [this, &ctx] {
                    // batch37m (user: "the console is also a text box"): the
                    // Copy button honors the current selection; with no
                    // selection it keeps the legacy copy-the-whole-ring.
                    //
                    // batch284: choose the text BEFORE writing, then write it
                    // exactly once. The old `if (CopySelectionToClipboard())
                    // return;` treated a FAILED selection write as "nothing is
                    // selected" and retried with the entire ring - so one
                    // transient clipboard failure silently replaced the few
                    // lines the user had selected with the whole log.
                    std::wstring text =
                        view_ != nullptr ? view_->SelectedText() : std::wstring();
                    if (text.empty()) {
                        text = console_log::SnapshotText();
                    }
                    if (!console_log::CopyToClipboard(text) && ctx.toast) {
                        ctx.toast(Str::ConsoleCopyFailed, ToastKind::Warning);
                    }
                };
                host.Add(std::move(bar));
                auto dropped = std::make_unique<Text>(
                    I18n::Instance().T(Str::ConsoleDropped), FontToken::Small,
                    ColorToken::Warning, true);
                dropped->id = "console.dropped_hint";
                dropped->visible = false;
                dropped_hint_ = static_cast<Text*>(host.Add(std::move(dropped)));
                auto card = std::make_unique<Card>(
                    Padding{14.0f, 10.0f, 14.0f, 10.0f}, 8.0f);
                card->id = "console.panel";
                card->fill_remaining = true;
                auto view = std::make_unique<ConsoleLogView>();
                view->id = "console.view";
                view_ = static_cast<ConsoleLogView*>(card->Add(std::move(view)));
                empty_ = static_cast<EmptyState*>(card->Add(
                    std::make_unique<EmptyState>(Str::ConsoleEmptyHint)));
                empty_->id = "console.empty";
                host.Add(std::move(card));
            }

            void ConsolePage::Update(const UiSnapshot& snapshot, I18n& i18n) {
                if (copy_ != nullptr) {
                    copy_->SetLabel(i18n.T(Str::ConsoleCopy));
                }
                if (dropped_hint_ != nullptr) {
                    const bool dropped = snapshot.console_dropped > 0;
                    if (dropped_hint_->visible != dropped) {
                        dropped_hint_->visible = dropped;
                        RelayoutHost(*host_);
                    }
                    if (dropped) {
                        dropped_hint_->SetText(i18n.T(Str::ConsoleDropped));
                    }
                }
                if (view_ == nullptr) {
                    return;
                }
                // batch116: the placeholder follows the ring emptiness, so it
                // is refreshed on EVERY tick - deliberately placed BEFORE the
                // revision gate. On a fresh start the ring revision and
                // last_rev_ are both 0, so a gated-only update would return
                // early and leave the placeholder hidden on an empty console.
                const bool has_content = 0 != console_log::LineCount();
                if (empty_ != nullptr) {
                    const bool was_visible = empty_->visible;
                    empty_->visible = !has_content;
                    if (was_visible != empty_->visible && empty_->visible) {
                        empty_->SetMessage(Str::ConsoleEmptyHint);  // language
                    }
                }
                const std::uint64_t rev = console_log::Revision();
                if (rev == last_rev_) {
                    return;
                }
                // audit B F5: the 500 ms tick must not deep-copy the whole ring
                // when nothing was logged; the monotone revision gates it.
                last_rev_ = rev;
                view_->SetLines(console_log::Snapshot());
            }

        }  // namespace

        std::unique_ptr<Page> MakeConsolePage() {
            return std::make_unique<ConsolePage>();
        }

    }  // namespace ui
}  // namespace vgww
