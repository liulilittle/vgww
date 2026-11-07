// ============================================================================
// renderer.h - Direct2D/DirectWrite drawing adapter for the native UI
// (S4.2 Task 6).
//
// RenderCtx MUST be defined as a struct: element.h forward-declares
// `struct RenderCtx` and any `class` definition here would raise C4099
// (T2 handoff note).
//
// Coordinate contract: everything the element tree passes in is LOGICAL
// pixels (DIPs). The render target carries SetDpi(96 * scale), so D2D maps
// logical coordinates to physical pixels - no manual scaling anywhere.
//
// Text: MeasureText() is a DirectWrite text-layout measurement with a
// (text, font, max_width) layout cache; Initialize() injects it into the
// T2 seam ui::SetTextMeasure so element measurement matches rendering
// exactly (the built-in approximation is replaced at startup).
// ============================================================================
#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include "ui/controls.h"  // Align
#include "ui/element.h"   // Rect
#include "ui/theme.h"     // Color/FontToken/Size

#include <cstddef>
#include <cmath>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

namespace vgww {
    namespace ui {

        /// Quantises a layout width to a 0.25 px grid (rounded UP, so the
        /// cached layout is never narrower than the request - a floor would
        /// let text wrap one line early and over-estimate the height,
        /// drifting the vertical centring in DrawText).
        ///
        /// Why: the layout/measure cache keys used to carry the raw `rect.w`,
        /// and a table's resolved column widths drift by sub-pixel amounts on
        /// every frame (ArrangeCore's 0.001 f re-resolve gate), so every frame
        /// rebuilt every text layout. Bucketing the width collapses that
        /// jitter into one shared slot while a real 0.25 px step still misses.
        /// Single shared implementation on purpose: both controls.cpp (M3
        /// column-width gate) and renderer.cpp (M2 cache keys) live it here, as
        /// an inline in this header - an anonymous-namespace copy in
        /// renderer.cpp would not be visible across the TU boundary.
        inline float QuantizeLayoutWidth(float w) noexcept {
            return (w <= 0.0f) ? 0.0f : std::ceil(w * 4.0f) * 0.25f;
        }

        /// batch24 P1-5: a device-pixel-aligned stroke (logical centreline
        /// rect + logical width).
        struct DeviceStroke {
            Rect rect;
            float width = 1.0f;
        };

        /// batch24 P1-5: snap a stroke centreline to the PHYSICAL pixel grid so
        /// a 1 px logical line at a fractional DPI (125% -> 1.25 physical px)
        /// no longer anti-aliases across two device rows ("the downlink kbps
        /// bottom border is partly covered", measured as one bright row 110 vs
        /// two dim rows 84+77).
        /// The centreline snaps to a half physical pixel for an odd physical
        /// width (a 1 px line then covers exactly one row) and to an integer
        /// for an even width; the width becomes a whole number of physical
        /// pixels. `scale` is dpi/96 (<= 0 is a no-op passthrough).
        inline DeviceStroke SnapStrokeToDevicePixels(const Rect& rect,
                                                     float width,
                                                     float scale) noexcept {
            if (scale <= 0.0f) {
                return DeviceStroke{rect, width};
            }
            int width_phys = static_cast<int>(std::lround(width * scale));
            if (width_phys < 1) {
                width_phys = 1;
            }
            const bool odd = (width_phys % 2) != 0;
            const auto snap = [scale, odd](float logical) noexcept {
                const float phys = logical * scale;
                const float centre =
                    odd ? (std::floor(phys) + 0.5f) : std::round(phys);
                return centre / scale;
            };
            const float x0 = snap(rect.x);
            const float y0 = snap(rect.y);
            const float x1 = snap(rect.x + rect.w);
            const float y1 = snap(rect.y + rect.h);
            return DeviceStroke{Rect{x0, y0, (std::max)(x1 - x0, 0.0f),
                                     (std::max)(y1 - y0, 0.0f)},
                                static_cast<float>(width_phys) / scale};
        }

        /// One recorded draw primitive (headless rendering tests; T8-F2).
        struct DrawOp {
            enum class Kind {
                FillRect,
                FillRoundedRect,
                StrokeRect,
                /// batch17 P1-b: rounded-corner stroke (the "1 px edge along a
                /// rounded fill" primitive). `radius` carries the corner
                /// radius and `width` the stroke width; StrokeRect keeps its
                /// legacy encoding (stroke width in the `radius` slot).
                StrokeRoundedRect,
                DrawText,
                ClipPush,
                ClipPop
            };
            Kind kind = Kind::FillRect;
            Rect rect;
            Color color;
            float radius = 0.0f;
            std::wstring text;
            FontToken font = FontToken::Body;
            /// batch17 P1-b: explicit stroke width for StrokeRoundedRect.
            /// Defaults to 1.0 (no-op) so every pre-existing aggregate
            /// initializer and every other kind stays byte-identical in the
            /// serialized stream (DrawOpToJson emits `width` only when it
            /// differs from 1.0).
            float width = 1.0f;
        };

        /// Drawing surface for one window. Single-threaded (UI thread only).
        struct RenderCtx {
            RenderCtx();
            ~RenderCtx();
            RenderCtx(const RenderCtx&) = delete;
            RenderCtx& operator=(const RenderCtx&) = delete;

            /// Creates the D2D1 factory, the DWrite factory and the font
            /// formats, then installs the DWrite-backed measure function into
            /// ui::SetTextMeasure. Returns false with `error` on failure.
            bool Initialize(std::string& error);
            /// Releases every COM object and restores the built-in measure
            /// approximation. Idempotent.
            void Shutdown() noexcept;
            bool initialized() const noexcept { return initialized_; }

            /// DPI in dots per inch (96 == scale 1.0); clamped to [48, 768].
            void SetDpi(float dpi) noexcept;
            float dpi() const noexcept { return dpi_; }

            /// Acquires the HWND render target (creating or resizing it as
            /// needed) and begins drawing. Returns false when not initialized
            /// or the target cannot be created. It does NOT clear: the caller
            /// chooses a full (ClearFrame) or partial (ClearRect) clear so a
            /// dirty-rect repaint does not erase retained content (P3).
            bool BeginFrame(HWND hwnd);
            /// Clears the whole back buffer to the background color.
            void ClearFrame();
            /// Clears only `rect` (logical) to the background color: the
            /// dirty-rect path (P3). The target retains the previous frame
            /// (D2D1_PRESENT_OPTIONS_RETAIN_CONTENTS), so untouched regions
            /// stay valid.
            void ClearRect(const Rect& rect);
            /// True (once) when BeginFrame created, resized or recreated the
            /// render target, so its previous contents are undefined and the
            /// caller must take the full-clear path.
            bool ConsumeFullClearNeeded() noexcept;
            /// Ends the frame; a D2DERR_RECREATE_TARGET discards the target
            /// so the next BeginFrame rebuilds it.
            void EndFrame() noexcept;

            void FillRect(const Rect& rect, Color color);
            void FillRoundedRect(const Rect& rect, float radius, Color color);
            void StrokeRect(const Rect& rect, Color color, float width = 1.0f);
            /// batch37h: one antialiased line segment (caption glyphs). Width
            /// is in logical px; pass 1/scale for a crisp 1-device-pixel
            /// stroke at fractional DPI (the old staircase X read as a thick
            /// font "X" next to the native Win11 caption icons).
            void DrawLine(Point a, Point b, Color color, float width = 1.0f);
            /// batch17 P1-b: a stroke that follows a rounded rectangle's
            /// corners (D2D DrawRoundedRectangle), so a 1 px edge can no
            /// longer cut across a rounded fill's corners. The stroke is
            /// centred on the geometry edge exactly like StrokeRect; `radius`
            /// is clamped to half the smaller side.
            void StrokeRoundedRect(const Rect& rect, float radius, Color color,
                                   float width = 1.0f);
            void DrawText(const std::wstring& text, const Rect& rect,
                          FontToken font, Color color,
                          Align align = Align::Start);
            /// batch17 P1-d: like DrawText, but the LIVE path builds/looks up
            /// its text layout with DWRITE_WORD_WRAPPING_NO_WRAP, so a long
            /// single-line value never wraps into a clipped second line. The
            /// RECORDED path emits the identical Kind::DrawText op (the
            /// draw_ops JSON stream is byte-unchanged); the layout cache key
            /// carries a wrap bit so the two modes can never share an entry.
            /// MeasureText keeps its wrapping contract.
            void DrawTextSingleLine(const std::wstring& text, const Rect& rect,
                                    FontToken font, Color color,
                                    Align align = Align::Start);

            /// batch29 P2: text-paint cache for PARTIAL frames. A text whose
            /// (content, font, colour, rect, align, alpha) is identical to a
            /// submission from the previous frame AND whose rect does not
            /// intersect this frame's dirty region is not resubmitted: the
            /// render target retains the pixels (RETAIN_CONTENTS) and the
            /// dirty clip could not have drawn them anyway. A full-clear frame
            /// (target recreated/resized) always resubmits every text - the
            /// pixels are gone. Recording mode is untouched (test op streams
            /// stay complete). `full_clear` must be the Paint() verdict.
            void BeginTextFrame(const Rect& dirty, bool full_clear);
            void EndTextFrame() noexcept;
            /// Number of DrawText submissions skipped by the cache (never
            /// reset; 0 until a partial frame repeats an unchanged text).
            uint64_t TextCacheSkips() const noexcept { return text_cache_skips_; }

            void ClipPush(const Rect& rect);
            void ClipPop() noexcept;

            /// T9 entrance fade: a per-primitive color-alpha multiplier applied
            /// to every draw call (default 1.0 = no change). A container scopes
            /// it around its subtree; the value is saved/restored by the
            /// scoping element, and reset to 1.0 at each BeginRecord/BeginFrame.
            void SetAlpha(float alpha) noexcept { alpha_ = alpha; }
            float alpha() const noexcept { return alpha_; }

            /// Cull rect (perf): when active, Element::Render skips the
            /// RenderCore of any element whose bounds do not intersect it, so
            /// the D2D draw-call volume scales with the dirty region instead
            /// of the whole tree. It is a draw-skip hint only: it never clips
            /// pixels (ClipPush still does that) and test recording always
            /// clears it (BeginRecord) so the recorded tree stays whole.
            void SetCullRect(const Rect& rect) noexcept;
            void ClearCullRect() noexcept;
            bool HasCullRect() const noexcept { return cull_active_; }
            /// M4-F3: read-only view of the active cull rect. Undefined (all
            /// zeros / empty) while inactive, so callers must guard with
            /// HasCullRect(); tests use it to assert the window narrowed a
            /// dirty region instead of widening it.
            const Rect& cull_rect() const noexcept { return cull_rect_; }
            /// True when a cull rect is active and `bounds` does not intersect
            /// it (half-open intervals; a zero/negative extent on either side
            /// counts as no intersection). Always false while inactive.
            /// C1: the overlap test itself is Rect::Intersects (element.h) - the
            /// single shared half-open predicate also used by the window's
            /// dirty-vs-titlebar decision, so the two cannot drift. This is
            /// only its negation plus the inactive-cull gate.
            bool CulledOut(const Rect& bounds) const noexcept;

            /// Record mode (test seam): every primitive appends a DrawOp to
            /// ops() and returns without touching the likely-absent render
            /// target, so RenderCore is assertable headlessly. The op log is
            /// cleared by each BeginRecord().
            void BeginRecord() noexcept;
            void EndRecord() noexcept;
            const std::vector<DrawOp>& ops() const noexcept;
            bool recording() const noexcept { return recording_; }

            /// M5: total draw primitives submitted to this RenderCtx (recording
            /// AND live paths both count; distinct from ops().size(), which is
            /// the current recording buffer). Semantic: submitted-primitive
            /// count, NOT rasterized-call count - a recorded frame hands the
            /// draws over without touching D2D, but they still count. Never
            /// reset.
            uint64_t DrawOpCount() const noexcept { return draw_op_total_; }
            /// M5: total DrawText submissions (subset of DrawOpCount(); the
            /// other primitives do not touch it). Never reset.
            uint64_t DrawTextCount() const noexcept { return draw_text_total_; }

            /// M11: live-path fill commit decisions. One per flush of the
            /// pending same-colour FillRect run (a single-rect run counts
            /// too); the recording path never touches it, and the decision is
            /// observable headlessly (no render target required). Never reset.
            uint64_t LiveFillCommitCount() const noexcept {
                return live_fill_commits_;
            }
            /// M11: of LiveFillCommitCount(), the flushes committed as one
            /// multi-rect FillGeometry batch (run size >= 2). Counted
            /// headlessly as the batch decision; the geometry object itself
            /// is only built while a render target exists. Never reset.
            uint64_t LiveFillGeometryCommits() const noexcept {
                return live_fill_geometry_commits_;
            }
            /// M11: total rects carried by every batch flush (run size >= 2) -
            /// the rectangles that no longer reach FillRectangle one by one.
            /// Never reset.
            uint64_t LiveFillBatchRectCount() const noexcept {
                return live_fill_batch_rect_count_;
            }

            /// DirectWrite measurement; falls back to a local approximation
            /// when the factory is missing (never recurses through the seam).
            Size MeasureText(const std::wstring& text, FontToken font,
                             float max_width);

            /// Cache introspection (headless test seam; P1 perf work). These
            /// report the live layout/measurement cache state without touching
            /// the render target; after Initialize() they are exercisable with
            /// no hwnd (DrawText resolves its layout cache before the draw).
            size_t LayoutCacheSize() const noexcept;
            size_t LayoutCacheLookups() const noexcept;
            size_t LayoutCacheHits() const noexcept;
            size_t MeasureCacheSize() const noexcept;
            size_t MeasureCacheLookups() const noexcept;
            size_t MeasureCacheHits() const noexcept;

        private:
            /// batch17 P1-d: shared DrawText body. `wrap` selects the
            /// DWRITE_WORD_WRAPPING mode for the LIVE layout (and is part of
            /// the layout cache key); the recording path is unchanged and
            /// emits Kind::DrawText for both callers.
            void DrawTextImpl(const std::wstring& text, const Rect& rect,
                              FontToken font, Color color, Align align,
                              bool wrap);

            struct Impl;
            std::unique_ptr<Impl> impl_;

            /// batch29 P2: one text submission's identity (see BeginTextFrame).
            struct TextPaintKey {
                std::wstring text;
                Rect rect;
                Color color;
                FontToken font = FontToken::Body;
                Align align = Align::Start;
                bool wrap = true;
                float alpha = 1.0f;

                bool operator==(const TextPaintKey& other) const noexcept {
                    return text == other.text && rect.x == other.rect.x &&
                           rect.y == other.rect.y && rect.w == other.rect.w &&
                           rect.h == other.rect.h && color.r == other.color.r &&
                           color.g == other.color.g &&
                           color.b == other.color.b &&
                           color.a == other.color.a && font == other.font &&
                           align == other.align && wrap == other.wrap &&
                           alpha == other.alpha;
                }
                /// Cheap pre-filter so the per-frame lookup stays O(n) even on
                /// a dense page (the full comparison only runs on a hit).
                uint64_t Hash() const noexcept;
            };
            bool TextCachedOutsideDirty(const TextPaintKey& key) const;
            std::vector<TextPaintKey> text_prev_;
            std::vector<TextPaintKey> text_cur_;
            std::unordered_multimap<uint64_t, std::size_t> text_prev_index_;
            bool text_frame_active_ = false;
            bool text_frame_full_ = true;
            Rect text_frame_dirty_{};
            uint64_t text_cache_skips_ = 0;
            float dpi_ = 96.0f;
            bool initialized_ = false;
            std::vector<DrawOp> ops_;
            bool recording_ = false;
            Rect cull_rect_{};
            bool cull_active_ = false;
            float alpha_ = 1.0f;
            /// M5 primitive counters: monotonic totals of draw primitives
            /// submitted to this RenderCtx (recording + live paths both count;
            /// never reset).
            uint64_t draw_op_total_ = 0;
            uint64_t draw_text_total_ = 0;
            /// M11 live fill-run counters: monotonic totals of live-path
            /// commit decisions only (recording never counts; never reset).
            uint64_t live_fill_commits_ = 0;
            uint64_t live_fill_geometry_commits_ = 0;
            uint64_t live_fill_batch_rect_count_ = 0;
        };

    }  // namespace ui
}  // namespace vgww
