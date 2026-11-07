// ============================================================================
// renderer.cpp - Direct2D/DirectWrite implementation of RenderCtx
// (S4.2 Task 6).
// ============================================================================
#include "ui/renderer.h"

#include "ui/i18n.h"

#include <d2d1.h>
#include <d2d1_1.h>
#include <dwrite.h>
#include <wrl/client.h>

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <list>
#include <unordered_map>
#include <vector>

namespace vgww {
    namespace ui {

        namespace {

            constexpr float kMinDpi = 48.0f;
            constexpr float kMaxDpi = 768.0f;
            /// Layout cache cap: enough for a virtualized table screen. P1:
            /// overflow evicts the single least-recently-used layout (list
            /// tail, O(1)) so memory stays flat without a clear-everything
            /// storm; the measurement cache allows 4x that budget.
            constexpr size_t kMaxCachedLayouts = 512;
            constexpr float kLayoutMaxHeight = 4096.0f;
            constexpr wchar_t kFontFamily[] = L"Segoe UI";

            /// Layout/measure cache key. `align` is part of the layout key so
            /// a cached IDWriteTextLayout has its horizontal alignment baked in
            /// at creation; DrawText then no longer rewrites
            /// SetTextAlignment/SetParagraphAlignment on every frame (P1).
            /// The key owns its text copy, but it is only ever constructed on a
            /// cache miss - a hit is verified directly against the caller's
            /// string, so a lookup never copies it (P1 #6).
            struct CacheKey {
                std::wstring text;
                int font = 0;
                float size = 0.0f;
                int align = 0;
                /// batch17 P1-d: word-wrapping mode the layout was built with
                /// (1 = WRAP like every DrawText; 0 = NO_WRAP like
                /// DrawTextSingleLine). Part of the key so the two modes can
                /// never share a cached IDWriteTextLayout.
                int wrap = 1;
                /// batch19 R4-P2: reading direction baked into the layout
                /// (1 = RTL). Part of the key so an RTL and an LTR layout can
                /// never share a cache slot.
                int dir = 0;
                bool equals(const std::wstring& t, int f, float s, int a,
                            int w, int d) const noexcept {
                    if (text.size() != t.size()) return false;
                    return align == a && font == f && size == s &&
                           wrap == w && dir == d && text == t;
                }
            };

            D2D1_COLOR_F ToD2DColor(Color c) noexcept {
                return D2D1::ColorF(c.r, c.g, c.b, c.a);
            }

            D2D1_RECT_F ToD2DRect(const Rect& r) noexcept {
                return D2D1::RectF(r.x, r.y, r.x + r.w, r.y + r.h);
            }

            DWRITE_TEXT_ALIGNMENT ToDWriteAlign(Align align) noexcept {
                switch (align) {
                    case Align::Center: return DWRITE_TEXT_ALIGNMENT_CENTER;
                    case Align::End: return DWRITE_TEXT_ALIGNMENT_TRAILING;
                    case Align::Start:
                    case Align::Stretch:
                    default: return DWRITE_TEXT_ALIGNMENT_LEADING;
                }
            }

            /// Local approximation used only while the DWrite factory is
            /// absent (mirrors theme.cpp's documented fallback; kept local so
            /// the injected measure hook can never recurse into itself).
            Size ApproximateMeasure(const std::wstring& text, FontToken font,
                                    float max_width) noexcept {
                const FontSpec spec = FontFor(font);
                float width = 0.0f;
                for (const wchar_t ch : text) {
                    width += (ch < 0x80 ? 0.55f : 1.0f) * spec.size;
                }
                if (max_width > 0.0f && width > max_width) {
                    const float lines = std::ceil(width / max_width);
                    return Size{max_width, lines * spec.size * 1.35f};
                }
                return Size{width, spec.size * 1.35f};
            }

            /// 64-bit FNV-1a fingerprint over (text,font,size,align). It is
            /// only an index: every cache verifies the exact generic key on a
            /// hit, so a fingerprint collision degrades to an extra creation,
            /// never a wrong result. Hashing the caller's string without
            /// allocating is what removes the old per-lookup wstring copy.
            uint64_t CacheFingerprint(const std::wstring& text, int font,
                                      float size, int align,
                                      int wrap, int dir = 0) noexcept {
                uint64_t h = 1469598103934665603ull;  // FNV-1a offset basis
                const unsigned char* bytes =
                    reinterpret_cast<const unsigned char*>(text.data());
                const size_t count = text.size() * sizeof(wchar_t);
                for (size_t i = 0; i < count; ++i) {
                    h ^= bytes[i];
                    h *= 1099511628211ull;
                }
                auto mix = [&h](uint64_t v) {
                    h ^= v;
                    h *= 1099511628211ull;
                };
                mix(static_cast<uint64_t>(font));
                uint32_t bits = 0;
                std::memcpy(&bits, &size, sizeof(bits));
                mix(bits);
                mix(static_cast<uint64_t>(align));
                mix(static_cast<uint64_t>(wrap));
                mix(static_cast<uint64_t>(dir));
                return h;
            }

            /// M11 fill-run batching (live path only). Two rects may share one
            /// run only when their antialiased device-pixel footprints cannot
            /// touch: each pending rect is inflated by the fill margin and an
            /// arriving text footprint by the text margin before the shared
            /// half-open Rect::Intersects test. At scale >= 1 the fixed
            /// margins guarantee 2 * margin * scale >= 1 device px of AA
            /// coverage per side; below 1 (dpi clamp floor 48) both margins
            /// scale by (1/scale + 1.5) / 2.5 so the binding fill-text gap
            /// stays sufficient (audit A 9.2 judgement table). eps absorbs
            /// float round-off on exact-threshold gaps - the real table
            /// header's binding gap is the 3.0 px divider-to-caption gap.
            constexpr float kFillRunFillMargin = 1.0f;
            constexpr float kFillRunTextMargin = 1.5f;
            constexpr float kFillRunMarginEps = 1e-3f;
            /// Run cap: a pathological frame cannot grow the pending array
            /// without bound; reaching it flushes and starts a new run.
            constexpr size_t kMaxFillRun = 64;
            /// Batch geometry cache capacity (exact rect-list key, FIFO).
            constexpr size_t kMaxCachedFillRunGeometries = 8;

            Rect InflateRect(const Rect& r, float margin) noexcept {
                return Rect{r.x - margin, r.y - margin, r.w + 2.0f * margin,
                            r.h + 2.0f * margin};
            }

        }  // namespace

        struct RenderCtx::Impl {
            Microsoft::WRL::ComPtr<ID2D1Factory1> factory;
            Microsoft::WRL::ComPtr<IDWriteFactory> dwrite;
            Microsoft::WRL::ComPtr<ID2D1HwndRenderTarget> target;
            /// batch37b: tabular figures keep the advance of every digit equal,
            /// so a changing value ("1,230" -> "1,982", "4" -> "5") keeps its
            /// measured width and does not re-arrange the page on each refresh.
            Microsoft::WRL::ComPtr<IDWriteTypography> tabular;
            Microsoft::WRL::ComPtr<ID2D1SolidColorBrush> brush;
            std::vector<Microsoft::WRL::ComPtr<IDWriteTextFormat>> formats;
            /// Cached layout + the per-layout metrics captured once at
            /// creation. P1: `height` (DWRITE_TEXT_METRICS.height) depends only
            /// on text+font+width, never on alignment, so DrawText reads it off
            /// the entry instead of calling GetMetrics every frame (#5), and
            /// alignment is baked into the layout at creation so a hit performs
            /// no SetTextAlignment/SetParagraphAlignment either.
            struct LayoutEntry {
                Microsoft::WRL::ComPtr<IDWriteTextLayout> layout;
                float height = 0.0f;
            };
            /// Measurement cache entry: owns a copy of the key text, but only
            /// materialised on a miss, so a hit never copies the string (#6).
            /// The full key (text+font+limit) is kept so a hit is verified
            /// exactly: a fingerprint collision returns a miss, never a
            /// foreign measurement.
            struct MeasureEntry {
                Size size{};         ///< measured result (w,h)
                std::wstring text;   ///< owning key text (miss-allocated only)
                int font = 0;        ///< owning key font token
                float limit = 0.0f;  ///< the width the size was measured at
            };
            /// Layout LRU node. The owning key is verified against the caller's
            /// borrowed string on a hit, so lookups never copy text; the list
            /// front is most-recently-used and eviction pops the tail in O(1).
            struct LayoutSlot {
                uint64_t hash = 0;
                CacheKey key;
                LayoutEntry entry;
            };
            using LayoutList = std::list<LayoutSlot>;
            LayoutList layouts;  ///< MRU at the front
            std::unordered_map<uint64_t, LayoutList::iterator> layout_index;
            /// Measurement cache: fingerprint -> LRU slot (owning key verified
            /// on hit). The caller's exact `max_width` is stored in `limit` so a
            /// different limit is a different, verified key.
            /// batch60: this used to be a bare unordered_map evicted at
            /// `measures.begin()` - an ARBITRARY entry. Streaming dynamic text
            /// (dashboard counters) past the cap then evicted hot static labels
            /// too, so they were re-measured on the next frame. Same LRU shape
            /// as the layout cache: list front = MRU, tail = victim (O(1)).
            struct MeasureSlot {
                uint64_t hash = 0;
                MeasureEntry entry;
            };
            using MeasureList = std::list<MeasureSlot>;
            MeasureList measures;  ///< MRU at the front
            std::unordered_map<uint64_t, MeasureList::iterator> measure_index;
            std::vector<D2D1_RECT_F> clips;
            bool in_frame = false;
            bool measure_injected = false;
            /// P1 perf counters (headless-observable; maintained on every path
            /// so cache-hit semantics are assertable without a render target).
            uint64_t layout_lookups = 0;
            uint64_t layout_hits = 0;
            uint64_t measure_lookups = 0;
            uint64_t measure_hits = 0;
            /// P3: set when the target was (re)created or resized this frame,
            /// so its previous contents are undefined and the caller must
            /// full-clear instead of doing a dirty-rect clear.
            bool full_clear_needed = true;

            /// M11 live fill run: FillRects of one effective colour pending a
            /// single commit decision. Only the live path touches it (the
            /// recording branch returns before the planner). `fill_run_alpha`
            /// snapshots alpha_ at run start, so a SetAlpha() change is a
            /// literal barrier even though the baked effective colour already
            /// guarantees correctness on its own.
            std::vector<Rect> fill_run;
            Color fill_run_color{};
            float fill_run_alpha = 1.0f;
            /// M11 batch geometry cache: key = exact rect list, value = one
            /// path geometry with one closed figure per rect (ALTERNATE
            /// fill; a run can never contain overlapping figures). Owned by
            /// the factory, so it survives an EndFrame RECREATE_TARGET and is
            /// only dropped with the factory in Shutdown. FIFO eviction.
            struct FillRunGeometrySlot {
                std::vector<Rect> rects;
                Microsoft::WRL::ComPtr<ID2D1PathGeometry> geometry;
            };
            std::vector<FillRunGeometrySlot> fill_run_geometries;

            /// M11: per-side margins for the current DPI (judgement table in
            /// audit A 9.2): fixed at scale >= 1, scaled by
            /// (1/scale + 1.5) / 2.5 below 1 so the 1/scale AA budget stays
            /// covered.
            float FillMargin(float dpi) const noexcept {
                const float inv_scale = 96.0f / dpi;
                return inv_scale > 1.0f
                           ? kFillRunFillMargin * (inv_scale + 1.5f) / 2.5f
                           : kFillRunFillMargin;
            }
            float TextMargin(float dpi) const noexcept {
                const float inv_scale = 96.0f / dpi;
                return inv_scale > 1.0f
                           ? kFillRunTextMargin * (inv_scale + 1.5f) / 2.5f
                           : kFillRunTextMargin;
            }
            /// M11: true when `rect` (effective colour `color`, alpha `alpha`)
            /// cannot join the pending run: run full, colour/alpha drift, or
            /// an inflated footprint overlap with any pending rect.
            bool FillRunRejects(const Rect& rect, Color color, float alpha,
                                float dpi) const noexcept {
                if (fill_run.size() >= kMaxFillRun) {
                    return true;
                }
                if (!(fill_run_color.r == color.r &&
                      fill_run_color.g == color.g &&
                      fill_run_color.b == color.b &&
                      fill_run_color.a == color.a) ||
                    fill_run_alpha != alpha) {
                    return true;
                }
                const float margin = FillMargin(dpi) + kFillRunMarginEps;
                const Rect incoming = InflateRect(rect, margin);
                for (const Rect& pending : fill_run) {
                    if (InflateRect(pending, margin).Intersects(incoming)) {
                        return true;
                    }
                }
                return false;
            }
            /// M11: true when the arriving text footprint (inflated by the
            /// text margin) touches any pending rect (inflated by the fill
            /// margin). Text ink is budgeted at +1.5 px (bearing/quantisation
            /// rounding); beyond that the caller flushes first.
            bool FillRunTouchesText(const Rect& text_rect,
                                    float dpi) const noexcept {
                const Rect text =
                    InflateRect(text_rect, TextMargin(dpi) + kFillRunMarginEps);
                const float margin = FillMargin(dpi) + kFillRunMarginEps;
                for (const Rect& pending : fill_run) {
                    if (InflateRect(pending, margin).Intersects(text)) {
                        return true;
                    }
                }
                return false;
            }
            /// M11: drop the pending run without committing (frame / record
            /// boundaries; a leftover run there is an abnormal state).
            void DiscardFillRun() noexcept { fill_run.clear(); }
            /// M11: commit the pending run now. The commit decision is
            /// counted even headlessly; pixels are only touched while a
            /// target + brush exist. N == 1 keeps the legacy single
            /// FillRectangle path; N >= 2 commits one FillGeometry built from
            /// the exact rect list (cached), degrading to per-rect
            /// FillRectangle when the geometry cannot be built or allocated.
            /// noexcept: called from EndFrame/ClipPop/BeginFrame/Shutdown,
            /// which must never terminate on an allocation failure.
            void FlushFillRun(RenderCtx& ctx) noexcept {
                if (fill_run.empty()) {
                    return;
                }
                ++ctx.live_fill_commits_;
                if (fill_run.size() == 1) {
                    if (target && brush) {
                        brush->SetColor(ToD2DColor(fill_run_color));
                        target->FillRectangle(ToD2DRect(fill_run.front()),
                                              brush.Get());
                    }
                    fill_run.clear();
                    return;
                }
                ++ctx.live_fill_geometry_commits_;
                ctx.live_fill_batch_rect_count_ += fill_run.size();
                if (target && brush) {
                    ID2D1PathGeometry* geometry = nullptr;
                    try {
                        geometry = AcquireFillRunGeometry(fill_run);
                    } catch (...) {
                        geometry = nullptr;  // fall through: per-rect path
                    }
                    brush->SetColor(ToD2DColor(fill_run_color));
                    if (nullptr != geometry) {
                        target->FillGeometry(geometry, brush.Get());
                    } else {
                        // The batch geometry could not be built: degrade to
                        // the legacy per-rect path (pixel-identical), never
                        // drop a fill.
                        for (const Rect& r : fill_run) {
                            target->FillRectangle(ToD2DRect(r), brush.Get());
                        }
                    }
                }
                fill_run.clear();
            }
            /// M11: cached path geometry for the exact rect list, or null
            /// when it cannot be built. May throw only from the cache
            /// insertion vector (FlushFillRun guards).
            ID2D1PathGeometry* AcquireFillRunGeometry(
                const std::vector<Rect>& rects) {
                for (const FillRunGeometrySlot& slot : fill_run_geometries) {
                    if (SameRectList(slot.rects, rects)) {
                        return slot.geometry.Get();
                    }
                }
                if (!factory) {
                    return nullptr;
                }
                FillRunGeometrySlot fresh;
                fresh.rects = rects;  // may throw before the cache is touched
                Microsoft::WRL::ComPtr<ID2D1PathGeometry> geometry;
                if (FAILED(factory->CreatePathGeometry(&geometry)) ||
                    nullptr == geometry) {
                    return nullptr;
                }
                Microsoft::WRL::ComPtr<ID2D1GeometrySink> sink;
                if (FAILED(geometry->Open(&sink)) || nullptr == sink) {
                    return nullptr;
                }
                sink->SetFillMode(D2D1_FILL_MODE_ALTERNATE);
                for (const Rect& r : rects) {
                    sink->BeginFigure(D2D1::Point2F(r.x, r.y),
                                      D2D1_FIGURE_BEGIN_FILLED);
                    const D2D1_POINT_2F points[3] = {
                        D2D1::Point2F(r.x + r.w, r.y),
                        D2D1::Point2F(r.x + r.w, r.y + r.h),
                        D2D1::Point2F(r.x, r.y + r.h)};
                    sink->AddLines(points, 3);
                    sink->EndFigure(D2D1_FIGURE_END_CLOSED);
                }
                if (FAILED(sink->Close())) {
                    return nullptr;
                }
                fresh.geometry = geometry;
                if (fill_run_geometries.size() >=
                    kMaxCachedFillRunGeometries) {
                    fill_run_geometries.erase(fill_run_geometries.begin());
                }
                fill_run_geometries.push_back(std::move(fresh));
                return fill_run_geometries.back().geometry.Get();
            }
            /// M11: exact (bitwise) rect-list comparison for the cache key.
            static bool SameRectList(const std::vector<Rect>& a,
                                     const std::vector<Rect>& b) noexcept {
                if (a.size() != b.size()) {
                    return false;
                }
                for (size_t i = 0; i < a.size(); ++i) {
                    if (a[i].x != b[i].x || a[i].y != b[i].y ||
                        a[i].w != b[i].w || a[i].h != b[i].h) {
                        return false;
                    }
                }
                return true;
            }
        };

        RenderCtx::RenderCtx() : impl_(std::make_unique<Impl>()) {}

        RenderCtx::~RenderCtx() {
            Shutdown();
        }

        bool RenderCtx::Initialize(std::string& error) {
            error.clear();
            if (initialized_) {
                return true;
            }
            const HRESULT factory_hr = ::D2D1CreateFactory(
                D2D1_FACTORY_TYPE_SINGLE_THREADED,
                impl_->factory.GetAddressOf());
            if (FAILED(factory_hr)) {
                error = "D2D1CreateFactory failed (hr=0x" +
                        std::to_string(static_cast<unsigned long>(factory_hr)) +
                        ")";
                return false;
            }
            const HRESULT dwrite_hr = ::DWriteCreateFactory(
                DWRITE_FACTORY_TYPE_SHARED, __uuidof(IDWriteFactory),
                reinterpret_cast<IUnknown**>(impl_->dwrite.GetAddressOf()));
            if (FAILED(dwrite_hr)) {
                error = "DWriteCreateFactory failed";
                impl_->factory.Reset();
                return false;
            }
            impl_->formats.resize(static_cast<size_t>(FontToken::_Count));
            for (size_t i = 0; i < impl_->formats.size(); ++i) {
                const FontSpec spec = FontFor(static_cast<FontToken>(i));
                IDWriteTextFormat* format = nullptr;
                const HRESULT hr = impl_->dwrite->CreateTextFormat(
                    kFontFamily, nullptr,
                    static_cast<DWRITE_FONT_WEIGHT>(spec.weight),
                    DWRITE_FONT_STYLE_NORMAL, DWRITE_FONT_STRETCH_NORMAL,
                    spec.size, L"", &format);
                if (FAILED(hr) || nullptr == format) {
                    error = "CreateTextFormat failed";
                    impl_->formats.clear();
                    impl_->dwrite.Reset();
                    impl_->factory.Reset();
                    return false;
                }
                format->SetWordWrapping(DWRITE_WORD_WRAPPING_WRAP);
                impl_->formats[i].Attach(format);
            }
            {
                IDWriteTypography* typography = nullptr;
                if (SUCCEEDED(impl_->dwrite->CreateTypography(&typography)) &&
                    typography != nullptr) {
                    const DWRITE_FONT_FEATURE tabular_figures{
                        DWRITE_FONT_FEATURE_TAG_TABULAR_FIGURES, 1};
                    if (SUCCEEDED(typography->AddFontFeature(tabular_figures))) {
                        impl_->tabular.Attach(typography);
                    } else {
                        typography->Release();
                    }
                }
            }
            initialized_ = true;
            // Replace the T2 approximation with real DWrite metrics.
            SetTextMeasure([this](const std::wstring& text, FontToken font,
                                  float max_width) {
                return MeasureText(text, font, max_width);
            });
            impl_->measure_injected = true;
            return true;
        }

        void RenderCtx::Shutdown() noexcept {
            if (impl_ && impl_->measure_injected) {
                SetTextMeasure(nullptr);  // never leave a dangling hook
                impl_->measure_injected = false;
            }
            initialized_ = false;
            if (impl_) {
                impl_->layouts.clear();
                impl_->layout_index.clear();
                impl_->measures.clear();
                impl_->measure_index.clear();
                impl_->clips.clear();
                // M11: the pending run is dropped, and the batch geometry
                // cache must go with the factory that owns it.
                impl_->DiscardFillRun();
                impl_->fill_run_geometries.clear();
                impl_->brush.Reset();
                impl_->target.Reset();
                impl_->formats.clear();
                impl_->dwrite.Reset();
                impl_->factory.Reset();
                impl_->in_frame = false;
            }
        }

        void RenderCtx::SetDpi(float dpi) noexcept {
            dpi_ = std::min(std::max(dpi, kMinDpi), kMaxDpi);
            if (impl_ && impl_->target) {
                impl_->target->SetDpi(dpi_, dpi_);
            }
        }

        bool RenderCtx::BeginFrame(HWND hwnd) {
            // M11: a frame boundary discards the pending live fill run. The
            // normal stream already flushed it in EndFrame; a leftover run
            // here is an abnormal state and must never become a ghost commit.
            if (impl_) {
                impl_->DiscardFillRun();
            }
            if (!initialized_ || nullptr == hwnd) {
                return false;
            }
            alpha_ = 1.0f;  // T9: each frame starts with no fade multiplier
            RECT client{};
            ::GetClientRect(hwnd, &client);
            const UINT32 width =
                static_cast<UINT32>(std::max<LONG>(client.right, 1));
            const UINT32 height =
                static_cast<UINT32>(std::max<LONG>(client.bottom, 1));
            if (!impl_->target) {
                D2D1_RENDER_TARGET_PROPERTIES props = D2D1::RenderTargetProperties();
                props.dpiX = dpi_;
                props.dpiY = dpi_;
                const D2D1_HWND_RENDER_TARGET_PROPERTIES hwnd_props =
                    D2D1::HwndRenderTargetProperties(
                        hwnd, D2D1::SizeU(width, height),
                        D2D1_PRESENT_OPTIONS_RETAIN_CONTENTS);
                const HRESULT hr = impl_->factory->CreateHwndRenderTarget(
                    props, hwnd_props, &impl_->target);
                if (FAILED(hr)) {
                    impl_->target.Reset();
                    return false;
                }
                const HRESULT brush_hr = impl_->target->CreateSolidColorBrush(
                    D2D1::ColorF(D2D1::ColorF::White), &impl_->brush);
                if (FAILED(brush_hr)) {
                    impl_->target.Reset();
                    return false;
                }
                impl_->full_clear_needed = true;
            } else {
                const D2D1_SIZE_U current = impl_->target->GetPixelSize();
                if (current.width != width || current.height != height) {
                    (void)impl_->target->Resize(D2D1::SizeU(width, height));
                    impl_->full_clear_needed = true;
                }
            }
            impl_->target->SetDpi(dpi_, dpi_);
            impl_->target->BeginDraw();
            impl_->target->SetTransform(D2D1::Matrix3x2F::Identity());
            impl_->in_frame = true;
            return true;
        }

        void RenderCtx::ClearFrame() {
            // M11: commit the pending run first (paint before clear) - the
            // decision stays observable headlessly too.
            if (impl_) {
                impl_->FlushFillRun(*this);
            }
            if (recording_ || !impl_ || !impl_->target) {
                return;
            }
            impl_->target->Clear(ToD2DColor(ColorFor(ColorToken::Bg)));
        }

        void RenderCtx::ClearRect(const Rect& rect) {
            // P3 dirty-rect: repaint only the invalidated region and rely on
            // the retained back buffer (RETAIN_CONTENTS) for the rest.
            // M11: commit the pending run first (paint before clear).
            if (impl_) {
                impl_->FlushFillRun(*this);
            }
            if (recording_ || !impl_ || !impl_->target || !impl_->brush ||
                rect.w <= 0.0f || rect.h <= 0.0f) {
                return;
            }
            impl_->brush->SetColor(ToD2DColor(ColorFor(ColorToken::Bg)));
            impl_->target->FillRectangle(ToD2DRect(rect), impl_->brush.Get());
        }

        bool RenderCtx::ConsumeFullClearNeeded() noexcept {
            if (!impl_) {
                return true;
            }
            const bool needed = impl_->full_clear_needed;
            impl_->full_clear_needed = false;
            return needed;
        }

        void RenderCtx::EndFrame() noexcept {
            // M11: commit the pending live fill run before the early-return
            // guards, so the frame boundary is observable headlessly (the
            // header red anchor drives EndFrame without a render target).
            if (impl_) {
                impl_->FlushFillRun(*this);
            }
            if (!impl_ || !impl_->target || !impl_->in_frame) {
                return;
            }
            impl_->in_frame = false;
            // Defensive: close any clip the caller forgot to pop.
            while (!impl_->clips.empty()) {
                impl_->target->PopAxisAlignedClip();
                impl_->clips.pop_back();
            }
            const HRESULT hr = impl_->target->EndDraw();
            if (D2DERR_RECREATE_TARGET == hr) {
                // Device lost (resolution/GPU change): drop everything the
                // target owned; BeginFrame rebuilds it.
                impl_->brush.Reset();
                impl_->target.Reset();
                impl_->layouts.clear();
                impl_->layout_index.clear();
                impl_->full_clear_needed = true;
            }
        }

        void RenderCtx::FillRect(const Rect& rect, Color color) {
            ++draw_op_total_;
            color.a *= alpha_;
            if (recording_) {
                ops_.push_back(DrawOp{DrawOp::Kind::FillRect, rect, color,
                                      0.0f, {}, FontToken::Body});
                return;
            }
            if (!impl_) {
                return;
            }
            // M11: the live fill joins the pending same-colour run instead of
            // committing per primitive. The run harvests headlessly too (no
            // target needed): the counters observe the commit decision,
            // mirroring the M5 counters above. A rect that conflicts with the
            // run (colour/alpha drift, inflated overlap, cap) commits the run
            // first; the run then restarts with this rect.
            if (!impl_->fill_run.empty() &&
                impl_->FillRunRejects(rect, color, alpha_, dpi_)) {
                impl_->FlushFillRun(*this);
            }
            if (impl_->fill_run.empty()) {
                impl_->fill_run_color = color;
                impl_->fill_run_alpha = alpha_;
            }
            impl_->fill_run.push_back(rect);
        }

        void RenderCtx::FillRoundedRect(const Rect& rect, float radius,
                                        Color color) {
            ++draw_op_total_;
            color.a *= alpha_;
            if (recording_) {
                ops_.push_back(DrawOp{DrawOp::Kind::FillRoundedRect, rect,
                                      color, radius, {}, FontToken::Body});
                return;
            }
            // M11: a non-FillRect primitive never joins the run; it commits
            // the pending run first so the stream order is preserved.
            if (impl_) {
                impl_->FlushFillRun(*this);
            }
            if (!impl_ || !impl_->target || !impl_->brush) {
                return;
            }
            const float r = std::min(std::max(radius, 0.0f),
                                     std::min(rect.w, rect.h) * 0.5f);
            impl_->brush->SetColor(ToD2DColor(color));
            impl_->target->FillRoundedRectangle(
                D2D1::RoundedRect(ToD2DRect(rect), r, r), impl_->brush.Get());
        }

        void RenderCtx::StrokeRect(const Rect& rect, Color color, float width) {
            ++draw_op_total_;
            color.a *= alpha_;
            if (recording_) {
                ops_.push_back(DrawOp{DrawOp::Kind::StrokeRect, rect, color,
                                      width, {}, FontToken::Body});
                return;
            }
            // M11: commit the pending fill run before this stroke.
            if (impl_) {
                impl_->FlushFillRun(*this);
            }
            if (!impl_ || !impl_->target || !impl_->brush) {
                return;
            }
            impl_->brush->SetColor(ToD2DColor(color));
            // batch24 P1-5: device-pixel align the 1 px-ish outline so it
            // covers whole physical rows at fractional DPI (no half-shadow).
            const DeviceStroke snapped = SnapStrokeToDevicePixels(
                rect, std::max(width, 0.0f), dpi_ / 96.0f);
            impl_->target->DrawRectangle(ToD2DRect(snapped.rect),
                                         impl_->brush.Get(), snapped.width);
        }

        void RenderCtx::DrawLine(Point a, Point b, Color color, float width) {
            ++draw_op_total_;
            color.a *= alpha_;
            if (recording_) {
                // Title-bar chrome is intentionally outside the recorded
                // content stream (draw_ops has never contained the captions).
                return;
            }
            if (impl_) {
                impl_->FlushFillRun(*this);
            }
            if (!impl_ || !impl_->target || !impl_->brush) {
                return;
            }
            impl_->brush->SetColor(ToD2DColor(color));
            impl_->target->DrawLine(D2D1::Point2F(a.x, a.y),
                                    D2D1::Point2F(b.x, b.y),
                                    impl_->brush.Get(), std::max(width, 0.0f));
        }
        void RenderCtx::StrokeRoundedRect(const Rect& rect, float radius,
                                          Color color, float width) {
            ++draw_op_total_;
            color.a *= alpha_;
            if (recording_) {
                ops_.push_back(DrawOp{DrawOp::Kind::StrokeRoundedRect, rect,
                                      color, radius, {}, FontToken::Body,
                                      width});
                return;
            }
            // M11: commit the pending fill run before this stroke (same
            // barrier contract as StrokeRect).
            if (impl_) {
                impl_->FlushFillRun(*this);
            }
            if (!impl_ || !impl_->target || !impl_->brush) {
                return;
            }
            const float r = std::min(std::max(radius, 0.0f),
                                     std::min(rect.w, rect.h) * 0.5f);
            impl_->brush->SetColor(ToD2DColor(color));
            // batch24 P1-5: same device-pixel alignment for rounded outlines.
            const DeviceStroke snapped = SnapStrokeToDevicePixels(
                rect, std::max(width, 0.0f), dpi_ / 96.0f);
            impl_->target->DrawRoundedRectangle(
                D2D1::RoundedRect(ToD2DRect(snapped.rect), r, r),
                impl_->brush.Get(), snapped.width);
        }

        uint64_t RenderCtx::TextPaintKey::Hash() const noexcept {
            // FNV-1a over the identity fields (the text is the dominant term).
            uint64_t h = 1469598103934665603ull;
            const auto mix = [&h](uint64_t v) noexcept {
                h ^= v;
                h *= 1099511628211ull;
            };
            for (const wchar_t c : text) {
                mix(static_cast<uint64_t>(c));
            }
            const auto bits = [](float f) noexcept {
                uint32_t raw = 0;
                std::memcpy(&raw, &f, sizeof(raw));  // no aliasing violation
                return static_cast<uint64_t>(raw);
            };
            mix(bits(rect.x));
            mix(bits(rect.y));
            mix(bits(rect.w));
            mix(bits(rect.h));
            mix(bits(color.r));
            mix(bits(color.g));
            mix(bits(color.b));
            mix(bits(color.a));
            mix(bits(alpha));
            mix(static_cast<uint64_t>(font));
            mix(static_cast<uint64_t>(align));
            mix(wrap ? 1u : 0u);
            return h;
        }

        void RenderCtx::BeginTextFrame(const Rect& dirty, bool full_clear) {
            // Recording owns a complete op stream (tests assert it); the cache
            // is a LIVE-path only optimization.
            text_cur_.clear();
            text_frame_dirty_ = dirty;
            text_frame_full_ = full_clear;
            text_frame_active_ = !recording_;
        }

        void RenderCtx::EndTextFrame() noexcept {
            if (text_frame_active_) {
                text_prev_.swap(text_cur_);
                // Rebuild the hash index for the frame just committed, so the
                // NEXT frame's lookup is a hash probe instead of a linear scan.
                text_prev_index_.clear();
                text_prev_index_.reserve(text_prev_.size());
                for (std::size_t i = 0; i < text_prev_.size(); ++i) {
                    text_prev_index_.emplace(text_prev_[i].Hash(), i);
                }
            }
            text_cur_.clear();
            text_frame_active_ = false;
        }

        bool RenderCtx::TextCachedOutsideDirty(const TextPaintKey& key) const {
            if (text_frame_full_ ||
                (text_frame_dirty_.w <= 0.0f && text_frame_dirty_.h <= 0.0f) ||
                key.rect.Intersects(text_frame_dirty_)) {
                return false;
            }
            const uint64_t hash = key.Hash();
            const auto range = text_prev_index_.equal_range(hash);
            for (auto it = range.first; it != range.second; ++it) {
                if (it->second < text_prev_.size() &&
                    text_prev_[it->second] == key) {
                    return true;
                }
            }
            return false;
        }

        void RenderCtx::DrawText(const std::wstring& text, const Rect& rect,
                                 FontToken font, Color color, Align align) {
            DrawTextImpl(text, rect, font, color, align, /*wrap=*/true);
        }

        void RenderCtx::DrawTextSingleLine(const std::wstring& text,
                                           const Rect& rect, FontToken font,
                                           Color color, Align align) {
            DrawTextImpl(text, rect, font, color, align, /*wrap=*/false);
        }

        void RenderCtx::DrawTextImpl(const std::wstring& text, const Rect& rect,
                                     FontToken font, Color color, Align align,
                                     bool wrap) {
            // batch29 P2: partial-frame text-paint cache. The key is built
            // BEFORE the alpha multiplier (alpha_ is part of the key), and a
            // hit returns before the primitive counters so the metric reflects
            // real submissions only.
            if (text_frame_active_ && !recording_) {
                TextPaintKey key;
                key.text = text;
                key.rect = rect;
                key.color = color;
                key.font = font;
                key.align = align;
                key.wrap = wrap;
                key.alpha = alpha_;
                if (TextCachedOutsideDirty(key)) {
                    // Still keep it in the current frame's cache: the pixels
                    // remain valid for the next frame too.
                    text_cur_.push_back(key);
                    ++text_cache_skips_;
                    return;
                }
                text_cur_.push_back(key);
            }
            ++draw_op_total_;
            ++draw_text_total_;
            color.a *= alpha_;
            if (recording_) {
                ops_.push_back(DrawOp{DrawOp::Kind::DrawText, rect, color,
                                      0.0f, text, font});
                return;
            }
            // M11 stage 1: order the pending fill run against this text
            // footprint before the format/target guards can return, so the
            // flush decision is observable headlessly too. A run that would
            // overlap the footprint (inflated by the text margin) commits
            // first; an alpha snapshot change is a literal barrier. An empty
            // or zero-width text has no footprint and never splits a run.
            if (impl_ && !impl_->fill_run.empty()) {
                if (impl_->fill_run_alpha != alpha_ ||
                    (!text.empty() && rect.w > 0.0f &&
                     impl_->FillRunTouchesText(rect, dpi_))) {
                    impl_->FlushFillRun(*this);
                }
            }
            // The layout cache is resolved before the render-target check: in
            // the live path BeginFrame guarantees a target+brush, so the two
            // guards below never fire there, while headless callers (tests)
            // still observe real layout-cache hit/miss semantics.
            if (!impl_ || text.empty() || rect.w <= 0.0f ||
                impl_->formats.empty() || !impl_->dwrite) {
                return;
            }
            const size_t index = static_cast<size_t>(font);
            if (index >= impl_->formats.size()) {
                return;
            }
            // M2: quantise the layout width before it reaches the cache key.
            // The raw rect.w drifts by sub-pixel amounts every frame (the
            // table's ArrangeCore re-resolves above a 0.001 f gate), which
            // turned every frame into a full layout rebuild; bucketing to the
            // 0.25 px grid collapses that jitter into a single shared slot
            // while a genuine 0.25 px step still misses. The quantised width
            // is also the width the layout is created with, so key and layout
            // can never disagree.
            const float w_key = QuantizeLayoutWidth(rect.w);
            const int wrap_key = wrap ? 1 : 0;
            // batch19 R4-P2: RTL is resolved at this single point; the layout
            // cache key carries it so an RTL and an LTR layout never share.
            const int dir_key = I18n::Instance().IsRtl() ? 1 : 0;
            const uint64_t fingerprint = CacheFingerprint(
                text, static_cast<int>(font), w_key,
                static_cast<int>(align), wrap_key, dir_key);
            ++impl_->layout_lookups;
            Impl::LayoutEntry* entry = nullptr;
            const auto idx = impl_->layout_index.find(fingerprint);
            if (idx != impl_->layout_index.end()) {
                auto slot = idx->second;
                if (slot->key.equals(text, static_cast<int>(font), w_key,
                                     static_cast<int>(align), wrap_key,
                                     dir_key)) {
                    // LRU touch: move to the front (O(1)).
                    impl_->layouts.splice(impl_->layouts.begin(),
                                          impl_->layouts, slot);
                    entry = &slot->entry;
                    ++impl_->layout_hits;
                } else {
                    // Fingerprint collision: the slot holds a different key,
                    // so drop it and rebuild (never reuse a foreign layout).
                    impl_->layouts.erase(slot);
                    impl_->layout_index.erase(idx);
                }
            }
            if (entry == nullptr) {
                // P1: evict the least-recently-used entry (list tail, O(1)),
                // never clear the whole cache - a single dynamic-text miss
                // used to flush every cached static label and rebuild them the
                // next frame.
                if (impl_->layouts.size() >= kMaxCachedLayouts) {
                    const uint64_t victim_hash = impl_->layouts.back().hash;
                    impl_->layouts.pop_back();
                    impl_->layout_index.erase(victim_hash);
                }
                IDWriteTextLayout* layout = nullptr;
                const HRESULT hr = impl_->dwrite->CreateTextLayout(
                    text.c_str(), static_cast<UINT32>(text.size()),
                    impl_->formats[index].Get(), w_key, kLayoutMaxHeight,
                    &layout);
                if (FAILED(hr) || nullptr == layout) {
                    return;
                }
                if (impl_->tabular) {
                    layout->SetTypography(
                        impl_->tabular.Get(),
                        DWRITE_TEXT_RANGE{0, static_cast<UINT32>(text.size())});
                }
                Impl::LayoutSlot slot;
                slot.hash = fingerprint;
                // The key copy is only made here (on a miss), never on a hit.
                slot.key.text = text;
                slot.key.font = static_cast<int>(font);
                // M2: store the quantised width, never the raw rect.w - the
                // slot is keyed by it, so a later hit must verify against the
                // same bucket or the entry would be unreachable.
                slot.key.size = w_key;
                slot.key.align = static_cast<int>(align);
                slot.key.wrap = wrap_key;
                slot.key.dir = dir_key;
                slot.entry.layout.Attach(layout);
                // Alignment is baked in once at creation (the key carries it),
                // so a cache hit performs no per-frame attribute writes.
                // P2: reading direction first, then the (direction-relative)
                // LEADING/TRAILING alignment.
                slot.entry.layout->SetReadingDirection(
                    dir_key ? DWRITE_READING_DIRECTION_RIGHT_TO_LEFT
                            : DWRITE_READING_DIRECTION_LEFT_TO_RIGHT);
                slot.entry.layout->SetTextAlignment(ToDWriteAlign(align));
                slot.entry.layout->SetParagraphAlignment(
                    DWRITE_PARAGRAPH_ALIGNMENT_NEAR);
                // batch17 P1-d: bake the wrapping mode into the layout too
                // (the key already separates the two modes; this keeps the
                // created layout self-consistent with its key).
                slot.entry.layout->SetWordWrapping(
                    wrap ? DWRITE_WORD_WRAPPING_WRAP
                         : DWRITE_WORD_WRAPPING_NO_WRAP);
                // Vertical centring height, cached once; depends only on
                // text+font+width, not alignment.
                DWRITE_TEXT_METRICS tm{};
                if (SUCCEEDED(slot.entry.layout->GetMetrics(&tm))) {
                    slot.entry.height = tm.height;
                }
                impl_->layouts.push_front(std::move(slot));
                impl_->layout_index.emplace(fingerprint,
                                            impl_->layouts.begin());
                entry = &impl_->layouts.front().entry;
            }
            // M11 stage 2: the caller rect only budgets 1.5 px of vertical
            // ink; once the cached layout height is known, a run still
            // pending is committed first when the glyphs could underflow the
            // rect (draw_y growth is clamped), keeping the text above the
            // committed fills - the original stream order.
            if (!impl_->fill_run.empty() &&
                entry->height > rect.h + 0.5f) {
                impl_->FlushFillRun(*this);
            }
            // Live path only: a real draw needs the HWND target + brush, both
            // created by BeginFrame. Headless callers stop here after building
            // the cache entry above.
            if (!impl_->target || !impl_->brush) {
                return;
            }
            float draw_y = rect.y;
            if (entry->height > 0.0f && entry->height < rect.h) {
                draw_y += (rect.h - entry->height) * 0.5f;
            }
            impl_->brush->SetColor(ToD2DColor(color));
            impl_->target->DrawTextLayout(
                D2D1::Point2F(rect.x, draw_y), entry->layout.Get(),
                impl_->brush.Get(), D2D1_DRAW_TEXT_OPTIONS_NONE);
        }

        void RenderCtx::ClipPush(const Rect& rect) {
            ++draw_op_total_;
            if (recording_) {
                ops_.push_back(DrawOp{DrawOp::Kind::ClipPush, rect, {}, 0.0f,
                                      {}, FontToken::Body});
                return;
            }
            // M11: commit before the clip changes - pending rects were
            // submitted under the old clip.
            if (impl_) {
                impl_->FlushFillRun(*this);
            }
            if (!impl_ || !impl_->target) {
                return;
            }
            impl_->target->PushAxisAlignedClip(ToD2DRect(rect),
                                               D2D1_ANTIALIAS_MODE_ALIASED);
            impl_->clips.push_back(ToD2DRect(rect));
        }

        void RenderCtx::ClipPop() noexcept {
            ++draw_op_total_;
            if (recording_) {
                ops_.push_back(DrawOp{DrawOp::Kind::ClipPop, {}, {}, 0.0f,
                                      {}, FontToken::Body});
                return;
            }
            // M11: commit before the clip is popped (same reasoning as
            // ClipPush).
            if (impl_) {
                impl_->FlushFillRun(*this);
            }
            if (!impl_ || !impl_->target || impl_->clips.empty()) {
                return;
            }
            impl_->target->PopAxisAlignedClip();
            impl_->clips.pop_back();
        }

        void RenderCtx::SetCullRect(const Rect& rect) noexcept {
            // M11: a cull change is a barrier - the pending run commits
            // first (cull itself never changes pixels, but the task forbids
            // crossing a cull change; it also isolates the overlay pass).
            if (impl_) {
                impl_->FlushFillRun(*this);
            }
            cull_rect_ = rect;
            cull_active_ = true;
        }

        void RenderCtx::ClearCullRect() noexcept {
            if (impl_) {
                impl_->FlushFillRun(*this);
            }
            cull_rect_ = Rect{};
            cull_active_ = false;
        }

        bool RenderCtx::CulledOut(const Rect& bounds) const noexcept {
            if (!cull_active_) {
                return false;
            }
            // C1: the overlap test is the single shared predicate Rect::Intersects
            // (element.h); this is only its negation plus the inactive-cull gate
            // above. A degenerate box never intersects, so it is always culled
            // while a cull rect is active (matches the pre-C1 contract).
            return !bounds.Intersects(cull_rect_);
        }

        void RenderCtx::BeginRecord() noexcept {
            // M11: commit the pending live run first so it can never leak
            // into (or be lost across) a recording session.
            if (impl_) {
                impl_->FlushFillRun(*this);
            }
            ops_.clear();
            alpha_ = 1.0f;
            // The recording seam must always see the whole tree, so a cull
            // left over from a live paint can never prune a recorded op.
            ClearCullRect();
            recording_ = true;
        }

        void RenderCtx::EndRecord() noexcept {
            recording_ = false;
        }

        const std::vector<DrawOp>& RenderCtx::ops() const noexcept {
            return ops_;
        }

        Size RenderCtx::MeasureText(const std::wstring& text, FontToken font,
                                    float max_width) {
            if (!impl_ || !impl_->dwrite || impl_->formats.empty()) {
                return ApproximateMeasure(text, font, max_width);
            }
            // M2: quantise the measuring width on the same 0.25 px grid as the
            // layout cache, so two requests inside one bucket share a single
            // entry instead of one DWrite layout per sub-pixel drift. The
            // caller's original max_width still clamps the returned width
            // below - the bucket is a cache-key detail, never the reported
            // measurement.
            const float limit =
                QuantizeLayoutWidth(max_width > 0.0f ? max_width
                                                     : kLayoutMaxHeight);
            // MeasureText keeps its WRAP contract; the wrap bit is a pure
            // key-separation detail for the (separate) measurement map.
            const uint64_t fingerprint =
                CacheFingerprint(text, static_cast<int>(font), limit, 0, 1);
            ++impl_->measure_lookups;
            const auto cached = impl_->measure_index.find(fingerprint);
            if (cached != impl_->measure_index.end()) {
                auto slot = cached->second;
                Impl::MeasureEntry& entry = slot->entry;
                // Only a fingerprint indexes the table; verify the full owning
                // key (text+font+limit) kept from the miss that inserted it, so
                // a hash collision can never return a foreign measurement.
                if (entry.text.size() == text.size() &&
                    entry.font == static_cast<int>(font) &&
                    entry.limit == limit && entry.text == text) {
                    // LRU touch: move to the front (O(1); the iterator and the
                    // entry reference stay valid across splice).
                    impl_->measures.splice(impl_->measures.begin(),
                                           impl_->measures, slot);
                    ++impl_->measure_hits;
                    return entry.size;
                }
                // Fingerprint collision: the slot holds a different key, so
                // drop it and rebuild (never reuse a foreign measurement).
                impl_->measures.erase(slot);
                impl_->measure_index.erase(cached);
            }
            const size_t index = static_cast<size_t>(font);
            if (index >= impl_->formats.size() || text.empty()) {
                return Size{0.0f, 0.0f};
            }
            IDWriteTextLayout* layout = nullptr;
            const HRESULT hr = impl_->dwrite->CreateTextLayout(
                text.c_str(), static_cast<UINT32>(text.size()),
                impl_->formats[index].Get(), limit, kLayoutMaxHeight, &layout);
            if (FAILED(hr) || nullptr == layout) {
                return ApproximateMeasure(text, font, max_width);
            }
            if (impl_->tabular) {
                layout->SetTypography(
                    impl_->tabular.Get(),
                    DWRITE_TEXT_RANGE{0, static_cast<UINT32>(text.size())});
            }
            DWRITE_TEXT_METRICS metrics{};
            const HRESULT metrics_hr = layout->GetMetrics(&metrics);
            layout->Release();
            if (FAILED(metrics_hr)) {
                return ApproximateMeasure(text, font, max_width);
            }
            const Size out{
                max_width > 0.0f ? std::min(metrics.width, max_width)
                                 : metrics.width,
                metrics.height};
            if (impl_->measures.size() >= kMaxCachedLayouts * 4) {
                // batch60: evict the least-recently-used entry (list tail,
                // O(1)). Arbitrary eviction used to drop hot static labels
                // while dynamic text streamed through, so the next frame
                // re-measured them (proven red: 60/3600 hot lookups missed).
                const uint64_t victim_hash = impl_->measures.back().hash;
                impl_->measures.pop_back();
                impl_->measure_index.erase(victim_hash);
            }
            Impl::MeasureSlot slot;
            slot.hash = fingerprint;
            slot.entry.size = out;
            // The owning key copy is made only here, on a miss.
            slot.entry.text = text;
            slot.entry.font = static_cast<int>(font);
            slot.entry.limit = limit;
            impl_->measures.push_front(std::move(slot));
            impl_->measure_index[fingerprint] = impl_->measures.begin();
            return out;
        }

        size_t RenderCtx::LayoutCacheSize() const noexcept {
            return impl_ ? impl_->layouts.size() : 0;
        }
        size_t RenderCtx::LayoutCacheLookups() const noexcept {
            return impl_ ? impl_->layout_lookups : 0;
        }
        size_t RenderCtx::LayoutCacheHits() const noexcept {
            return impl_ ? impl_->layout_hits : 0;
        }
        size_t RenderCtx::MeasureCacheSize() const noexcept {
            return impl_ ? impl_->measures.size() : 0;
        }
        size_t RenderCtx::MeasureCacheLookups() const noexcept {
            return impl_ ? impl_->measure_lookups : 0;
        }
        size_t RenderCtx::MeasureCacheHits() const noexcept {
            return impl_ ? impl_->measure_hits : 0;
        }

    }  // namespace ui
}  // namespace vgww
