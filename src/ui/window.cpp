// ============================================================================
// window.cpp - window creation, DPI handling, input routing and painting
// (S4.2 Task 6).
// ============================================================================
#include "ui/window.h"

#include "core/handler_guard.h"
#include "ui/controls.h"
#include "ui/console_log.h"
#include "ui/i18n.h"
#include "ui/single_instance.h"
#include "ui/tray.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <cmath>
#include <unordered_set>
#include <vector>

#include <imm.h>

namespace vgww {
    namespace ui {

        // (batch20: kActivateMessage lives in single_instance.h)

        namespace {

            constexpr UINT_PTR kSnapshotTimerId = 1;
            constexpr UINT kSnapshotTimerMs = 200;
            /// Independent caret-blink timer (S5.19): the caret phase must
            /// advance on its own 500 ms cycle, not on the data-driven
            /// 200 ms snapshot tick.
            constexpr UINT_PTR kCaretBlinkTimerId = 2;
            constexpr UINT kCaretBlinkTimerMs = 500;
            /// On-demand animation frame clock (T3): kAnimationFrameMs, i.e.
            /// ~30 fps (one tick every 33 ms). The user ruling permits dropping
            /// to 15 fps but requires the motion to stay smooth, so 33 ms is the
            /// chosen point: it keeps transitions fluid while halving the timer
            /// rate versus 60 fps. Started only while an element animates and
            /// killed when the tree is quiescent, so an idle UI costs no timer
            /// ticks.
            constexpr UINT_PTR kAnimationTimerId = 3;
            constexpr UINT kAnimationFrameMs = 33;
            /// Wakes the pump after RequestExit() (DestroyWindow from WndProc).
            constexpr UINT kExitWakeMessage = WM_APP + 3;
            constexpr float kMinScale = 0.5f;
            constexpr float kResizeEdgeLogical = 8.0f;
            constexpr float kCaptionButtonW = 56.0f;

            /// Half-open interval overlap, delegated to the single shared
            /// predicate Rect::Intersects (element.h, M4/C1). Kept as a
            /// named alias so the call site below reads as a predicate and
            /// the "one implementation of half-open overlap" contract stays
            /// grep-able for audit.
            bool RectsIntersect(const Rect& a, const Rect& b) noexcept {
                return a.Intersects(b);
            }

            /// batch120: the six navigation keys that scroll a viewport (Up,
            /// Down, PageUp, PageDown, Home, End). RouteKey uses this to decide
            /// whether the pointer-nearest container fallback applies.
            ///
            /// Lives here rather than in window.h because window.cpp is its
            /// only caller: a static helper in a header is instantiated once
            /// per translation unit, and the other four includers compiled an
            /// unused copy (C4505).
            bool IsScrollKey(uint32_t vk) noexcept {
                return vk == 0x26u || vk == 0x28u || vk == 0x21u ||
                       vk == 0x22u || vk == 0x24u || vk == 0x23u;
            }

            /// M1 (batch2, plan C) H6: true when `node` and every ancestor up
            /// to the root are visible. The cached overlay set includes hidden
            /// nodes (existence path, H7); the hit path must re-apply the old
            /// FindOverlayHit `!visible` subtree prune per candidate (a hidden
            /// DialogHost with mode != None would otherwise self-hit).
            bool OverlayVisibleChain(const Element* node) noexcept {
                for (const Element* n = node; n != nullptr; n = n->parent()) {
                    if (!n->visible) {
                        return false;
                    }
                }
                return true;
            }

            /// Bounding box of two rects (either may be empty). Used to
            /// invalidate the "before -> after" geometry of a key mutation.
            Rect UnionRects(const Rect& a, const Rect& b) noexcept {
                if (a.w <= 0.0f || a.h <= 0.0f) {
                    return b;
                }
                if (b.w <= 0.0f || b.h <= 0.0f) {
                    return a;
                }
                const float x0 = std::min(a.x, b.x);
                const float y0 = std::min(a.y, b.y);
                const float x1 = std::max(a.x + a.w, b.x + b.w);
                const float y1 = std::max(a.y + a.h, b.y + b.h);
                return Rect{x0, y0, x1 - x0, y1 - y0};
            }

            /// batch17 P2-a (audit H2): the region a captured drag repaint
            /// must cover - the element's raw box widened to its own
            /// invalidation_bounds(). For a Table column resize that is the
            /// whole table box (ResolveWidths re-lays every row), for an
            /// expanded Select the box-union-popup, for a TextInput drag-
            /// select the input box. `bounds()` alone would be too narrow for
            /// the Select popup; `invalidation_bounds()` alone would be too
            /// narrow for a Table mid-hover (it returns the hover band).
            Rect CaptureWidestBounds(const Element* e) noexcept {
                return UnionRects(e->bounds(), e->invalidation_bounds());
            }

            /// batch65: the keyboard path needs the SAME widening rule as the
            /// content path (batch64): the hint may only ever enlarge the box.
            /// Reading it bare made an arrow-key scroll on a hovered table
            /// repaint the hovered 28 px row band while every row moved.
            Rect KeyInvalidationBounds(const Element* e) noexcept {
                return CaptureWidestBounds(e);
            }

            /// batch332 P1: abort every in-flight pointer drag in the tree.
            /// A control that latches "button is down" in OnMouseDown and only
            /// clears it in OnMouseUp would otherwise keep resizing a column /
            /// extending a selection after a mouse-up the window never saw
            /// (WM_KILLFOCUS: Alt+Tab or hide-to-tray; or a release that
            /// reached another window). Pre-order walk; CancelDrag is a no-op
            /// on controls that hold no drag state.
            void CancelDragsIn(Element* node) noexcept {
                if (node == nullptr) {
                    return;
                }
                node->CancelDrag();
                for (const auto& child : node->children()) {
                    CancelDragsIn(child.get());
                }
            }


            /// R3: clipboard helpers live in controls.cpp (shared with the
            /// console log); the window just calls ui::SetClipboardText.

        }  // namespace

        VgwwWindow::VgwwWindow() : titlebar_h_(DarkTheme().titlebar_h) {
            ApplyDpi(96.0f);
            // Install the animation-request seam so a control's status change
            // can spin up the ~16 ms clock. Single-window app: the last
            // constructed window owns the seam (accepted, see task notes).
            SetAnimationRequester([this] { RequestAnimationFrame(); });
            // batch20: controls that grow in-layout request a deterministic
            // layout pass through this seam (see LanguagePicker::SetExpanded).
            SetLayoutRequester([this] { RequestLayout(); });
            // batch29 P1/P2: a control whose pixels changed without changing
            // geometry (a new sparkline column) repaints only its own region.
            SetElementRepaintRequester(
                [this](Element* element) { InvalidateElement(element); });
        }

        VgwwWindow::~VgwwWindow() {
            SetAnimationRequester(nullptr);  // never leave a dangling hook
            SetLayoutRequester(nullptr);
            SetElementRepaintRequester(nullptr);
            if (hwnd_ && ::IsWindow(hwnd_)) {
                tray::Remove();
                ::DestroyWindow(hwnd_);
            }
            renderer_.Shutdown();
            if (small_icon_) {
                ::DestroyIcon(small_icon_);
            }
            if (big_icon_) {
                ::DestroyIcon(big_icon_);
            }
            if (com_initialized_) {
                ::CoUninitialize();
            }
        }

        void VgwwWindow::ApplyDpi(float dpi) noexcept {
            scale_ = std::max(dpi / 96.0f, kMinScale);
            dpi_ = 96.0f * scale_;
            renderer_.SetDpi(dpi_);
            // batch331: remember the desktop-driven scale while no fixed
            // override is in force, so SetUiScale(0) can restore it even
            // without a live HWND (headless tests / pre-Create).
            if (ui_scale_ <= 0.0f) {
                desktop_scale_ = scale_;
            }
        }

        void VgwwWindow::SetDpiForTest(float scale) noexcept {
            ApplyDpi(96.0f * scale);
        }

        void VgwwWindow::SetWorkAreaForTest(Size work) noexcept {
            work_area_override_ = work;
            has_work_area_override_ = true;
        }

        void VgwwWindow::ClearWorkAreaForTest() noexcept {
            has_work_area_override_ = false;
            work_area_override_ = Size{};
        }

        Size VgwwWindow::scaled_client_size() const noexcept {
            return Size{DarkTheme().min_window.w * scale_,
                        DarkTheme().min_window.h * scale_};
        }

        void VgwwWindow::LoadSavedGeometryForTest() {
            ui_state::WindowState saved;
            restored_ = ui_state::WindowState{};
            restore_pending_ = false;
            if (!ui_state::Load(saved)) {
                return;  // missing/corrupt: defaults, silently
            }
            // Work areas of every CURRENT monitor + the primary one. A saved
            // rect on an unplugged monitor fails the overlap test and gets
            // centred on the primary.
            std::vector<ui_state::RectI> areas;
            ui_state::RectI primary{};
            struct CollectCtx {
                std::vector<ui_state::RectI>* areas;
            } collect_ctx{&areas};
            ::EnumDisplayMonitors(
                nullptr, nullptr,
                [](HMONITOR monitor, HDC, LPRECT, LPARAM data) -> BOOL {
                    auto* ctx = reinterpret_cast<CollectCtx*>(data);
                    MONITORINFO info{};
                    info.cbSize = sizeof(info);
                    if (::GetMonitorInfoW(monitor, &info)) {
                        ctx->areas->push_back(ui_state::RectI{
                            info.rcWork.left, info.rcWork.top,
                            info.rcWork.right - info.rcWork.left,
                            info.rcWork.bottom - info.rcWork.top});
                    }
                    return TRUE;
                },
                reinterpret_cast<LPARAM>(&collect_ctx));
            {
                MONITORINFO info{};
                info.cbSize = sizeof(info);
                if (::GetMonitorInfoW(::MonitorFromPoint(POINT{0, 0},
                                                         MONITOR_DEFAULTTOPRIMARY),
                                      &info)) {
                    primary = ui_state::RectI{
                        info.rcWork.left, info.rcWork.top,
                        info.rcWork.right - info.rcWork.left,
                        info.rcWork.bottom - info.rcWork.top};
                }
            }
            if (has_work_area_override_) {
                primary = ui_state::RectI{
                    0, 0, static_cast<int>(work_area_override_.w),
                    static_cast<int>(work_area_override_.h)};
                areas.assign(1, primary);
            }
            if (primary.w <= 0 || primary.h <= 0) {
                return;
            }
            if (areas.empty()) {
                areas.push_back(primary);
            }
            const ui_state::WindowState sanitized =
                ui_state::RestoreWindowState(
                    saved, scale_, DarkTheme().min_window.w,
                    DarkTheme().min_window.h, areas, primary);
            if (!sanitized.valid) {
                return;  // too small / unusable: keep the design default
            }
            restored_ = sanitized;
            restore_pending_ = true;
        }

        void VgwwWindow::ApplyRestoredGeometry() noexcept {
            if (hwnd_ == nullptr || !restored_.valid) {
                return;
            }
            // batch30: a zoomed window owns its rect (the OS work area). A
            // late DPI-sync pass must not SetWindowPos the NORMAL rect back on
            // screen and silently un-maximize the restored window.
            if (::IsZoomed(hwnd_)) {
                return;
            }
            // The process is per-monitor-v2 aware (manifest + the explicit
            // SetProcessDpiAwarenessContext call), so SetWindowPos takes
            // PHYSICAL pixels: the stored position is already physical and the
            // stored LOGICAL size is multiplied by the CURRENT scale, which is
            // the spec's "clamp against the new DPI after a DPI change".
            ::SetWindowPos(hwnd_, nullptr, restored_.x, restored_.y,
                           static_cast<int>(restored_.w * scale_),
                           static_cast<int>(restored_.h * scale_),
                           SWP_NOZORDER | SWP_NOACTIVATE);
            // batch30: seed the "last normal rect" with the geometry we just
            // applied. A window that is restored MAXIMIZED never sees a normal
            // WM_MOVE/WM_SIZE, so without this seed a maximized exit would have
            // to fall back to GetWindowPlacement (which excludes the invisible
            // DWM border) and the position would drift on every launch.
            last_normal_rect_ = ui_state::RectI{
                restored_.x, restored_.y,
                static_cast<int>(restored_.w * scale_),
                static_cast<int>(restored_.h * scale_)};
        }
        void VgwwWindow::CaptureNormalRect() noexcept {
            if (hwnd_ == nullptr) {
                return;
            }
            if (::IsZoomed(hwnd_) || ::IsIconic(hwnd_)) {
                return;  // keep the last normal rect
            }
            RECT rect{};
            if (::GetWindowRect(hwnd_, &rect)) {
                last_normal_rect_ = ui_state::RectI{
                    rect.left, rect.top, rect.right - rect.left,
                    rect.bottom - rect.top};
            }
        }

        void VgwwWindow::SaveGeometryNow() {
            if (hwnd_ == nullptr) {
                return;
            }
            // batch28: persist the SAME rect origin the restore path feeds to
            // CreateWindowExW (GetWindowRect). GetWindowPlacement's
            // rcNormalPosition excludes the invisible DWM resize border, so
            // mixing the two shifted the window by the frame thickness on every
            // launch. A zoomed/minimised close uses the last normal rect
            // captured in WM_MOVE/WM_SIZE.
            RECT rect{};
            const bool normal_state =
                !::IsZoomed(hwnd_) && !::IsIconic(hwnd_);
            if (normal_state && ::GetWindowRect(hwnd_, &rect)) {
                // live normal rect
            } else if (last_normal_rect_.w > 0 && last_normal_rect_.h > 0) {
                rect.left = last_normal_rect_.x;
                rect.top = last_normal_rect_.y;
                rect.right = last_normal_rect_.x + last_normal_rect_.w;
                rect.bottom = last_normal_rect_.y + last_normal_rect_.h;
            } else {
                WINDOWPLACEMENT placement{};
                placement.length = sizeof(placement);
                if (!::GetWindowPlacement(hwnd_, &placement)) {
                    return;
                }
                rect = placement.rcNormalPosition;
            }
            ui_state::WindowState state;
            state.x = rect.left;
            state.y = rect.top;
            // Size is stored LOGICAL so a later DPI change re-scales it.
            state.w = static_cast<float>(rect.right - rect.left) / scale_;
            state.h = static_cast<float>(rect.bottom - rect.top) / scale_;
            state.valid = state.w > 0.0f && state.h > 0.0f;
            // batch30: remember the zoom state; the rect above is still the
            // last NORMAL one, so un-maximizing and the next launch both land
            // in the right place.
            state.maximized = ::IsZoomed(hwnd_) != FALSE;
            (void)ui_state::Save(state);
        }

        void VgwwWindow::ApplyAutoDpi() noexcept {
            // batch331: ONE source of truth for "follow the desktop": the
            // creation path and the back-to-auto override both call this.
            if (hwnd_ == nullptr) {
                // No live window: restore the remembered desktop scale
                // (Create() will re-derive it from the monitor anyway).
                ApplyDpi(96.0f * desktop_scale_);
                return;
            }
            // The monitor the window actually sits on, clamped to the legal
            // band a renderer accepts.
            const UINT monitor_dpi = ::GetDpiForWindow(hwnd_);
            if (monitor_dpi >= 48 && monitor_dpi <= 768) {
                ApplyDpi(static_cast<float>(monitor_dpi));
            }
        }

        void VgwwWindow::SetUiScale(float scale) {
            ui_scale_ = (scale > 0.0f) ? scale : 0.0f;
            // batch331: switching back to "auto" (scale <= 0) must RE-DERIVE the
            // scale from the desktop. The old early return left scale_ at the
            // last fixed value, so the settings page's "auto" pick changed
            // nothing on screen until the next launch. ApplyAutoDpi() is the
            // same desktop-DPI rule Create() applies (one rule, not two).
            if (ui_scale_ <= 0.0f) {
                ApplyAutoDpi();
                if (hwnd_ == nullptr) {
                    return;  // Create() will re-derive it from the monitor
                }
                const Size auto_target = scaled_client_size();
                ::SetWindowPos(hwnd_, nullptr, 0, 0,
                               static_cast<int>(auto_target.w),
                               static_cast<int>(auto_target.h),
                               SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE);
                Relayout();
                Invalidate();
                return;
            }
            ApplyDpi(96.0f * ui_scale_);
            if (hwnd_ == nullptr) {
                return;  // Create() sizes from scale_ (pending override)
            }
            const Size target = scaled_client_size();
            ::SetWindowPos(hwnd_, nullptr, 0, 0,
                           static_cast<int>(target.w), static_cast<int>(target.h),
                           SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE);
            Relayout();
            Invalidate();
        }

        Size VgwwWindow::ClampRestoredSizeToWorkArea(Size size) const noexcept {
            // batch229: ONE clamp for every path that re-derives the restored
            // geometry at the current scale. ui_state::RestoreWindowState
            // clamps against the work area at LOAD time, but the stored size
            // is LOGICAL, so a DPI raise re-inflates it; without this the
            // window grows past the screen. SPI_GETWORKAREA describes the
            // primary desktop and needs no window handle, so the headless
            // paths (which have a real desktop in the test harness) clamp the
            // same way the visible ones do.
            if (has_work_area_override_) {
                size.w = (std::min)(size.w, work_area_override_.w);
                size.h = (std::min)(size.h, work_area_override_.h);
                return size;
            }
            RECT work{};
            if (::SystemParametersInfoW(SPI_GETWORKAREA, 0, &work, 0)) {
                size.w = (std::min)(size.w,
                                    static_cast<float>(work.right - work.left));
                size.h = (std::min)(size.h,
                                    static_cast<float>(work.bottom - work.top));
            }
            return size;
        }

        Size VgwwWindow::DecideDpiChangedSizeForTest(float new_dpi,
                                                     Size suggested) {
            // Fixed override: our scale and design size win (P1-4).
            if (ui_scale_ > 0.0f) {
                ApplyDpi(96.0f * ui_scale_);
                last_size_request_ = scaled_client_size();
                return last_size_request_;
            }
            ApplyDpi(new_dpi);
            // P1-2: the creation-time sync still pending -> enforce the design
            // size at the NEW scale instead of the stale suggested rect.
            if (size_sync_pending_) {
                size_sync_pending_ = false;
                // batch28: a restored geometry keeps its LOGICAL size and is
                // re-derived at the new dpi (the spec's "clamp against the
                // new DPI after a DPI change"). Clamp to the monitor work area
                // so a raise never
                // pushes the window off-screen.
                if (restore_pending_ && restored_.valid) {
                    last_size_request_ = ClampRestoredSizeToWorkArea(
                        Size{restored_.w * scale_, restored_.h * scale_});
                    return last_size_request_;
                }
                last_size_request_ = scaled_client_size();
                return last_size_request_;
            }
            last_size_request_ = suggested;
            return suggested;
        }

        void VgwwWindow::TickDpiSyncFallbackForTest() {
            // P1-3: fire once, strictly later than the initial message drain
            // (the 2nd tick), and only when nothing consumed the flag yet.
            ++tick_sync_counter_;
            if (tick_sync_counter_ < 2 || !size_sync_pending_) {
                return;
            }
            size_sync_pending_ = false;
            // batch28: a restored geometry must survive this fallback too - it
            // used to resize back to the design size (measured: a restored
            // 1100x700 window came back at 980x640 after ~2 ticks).
            // batch229: the restored size must be clamped to the work area
            // EXACTLY like DecideDpiChangedSize does. ui_state::
            // RestoreWindowState clamps at LOAD time against the scale in
            // effect then (:202-203), but the stored size is LOGICAL; a DPI
            // raise multiplies it by the new scale and the window lands
            // larger than the screen (measured: a 0.75x-work-area window at
            // 200% asked for 3072x1656 on a 2048x1104 desktop).
            const Size target =
                (restored_.valid && !user_moved_window_)
                    ? ClampRestoredSizeToWorkArea(
                          Size{restored_.w * scale_, restored_.h * scale_})
                    : scaled_client_size();
            if (hwnd_ == nullptr) {
                last_size_request_ = target;
                return;
            }
            last_size_request_ = target;
            if (restored_.valid && !user_moved_window_) {
                ApplyRestoredGeometry();
            } else {
                ::SetWindowPos(hwnd_, nullptr, 0, 0,
                               static_cast<int>(target.w),
                               static_cast<int>(target.h),
                               SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE);
            }
            Relayout();
            Invalidate();
        }

        bool VgwwWindow::ApplyDesktopDpiForTest(float dpi) {
            if (ui_scale_ > 0.0f) {
                return false;  // fixed override ignores the desktop change
            }
            ApplyDpi(dpi);
            return true;
        }

        void VgwwWindow::OnCaretBlinkTickForTest(int count) noexcept {
            // Deterministic caret-phase advance. Forward the private timer
            // handler when a live hwnd exists; headless (the common test case)
            // its hwnd guard would early-return, so drive the focused element's
            // phase directly with the same stale-pointer guard. A negative
            // count is treated as zero.
            for (int i = 0; i < count; ++i) {
                if (hwnd_ != nullptr) {
                    OnCaretBlinkTick();
                    continue;
                }
                if (focused_ == nullptr) {
                    continue;
                }
                if (!ElementInTree(root_, focused_)) {
                    focused_ = nullptr;
                    continue;
                }
                focused_->OnCaretBlinkTick();
            }
        }

        bool VgwwWindow::PaintNowForTest() {
            // A real paint pass needs a live hwnd (BeginPaint/EndPaint);
            // headless is a clean blocked no-op so tests can assert the
            // contract instead of touching D2D.
            if (hwnd_ == nullptr) {
                return false;
            }
            Paint();
            return true;
        }

        bool VgwwWindow::Create(HINSTANCE instance, bool start_minimized,
                                std::string& error) {
            error.clear();
            if (hwnd_ != nullptr) {
                error = "window already created";
                return false;
            }
            // Reusable-retry reset: a prior failed Create() may have left the
            // animation clock latched active without a timer (B-4); clear it
            // before the new window owns hwnd_.
            animation_active_ = false;
            instance_ = instance;
            // Per-monitor v2: the manifest declares it, this covers hosts
            // that launched us with an inherited awareness context.
            (void)::SetProcessDpiAwarenessContext(
                DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
            const HRESULT com_hr =
                ::CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
            com_initialized_ = SUCCEEDED(com_hr);  // RPC_E_CHANGED_MODE: reuse

            WNDCLASSEXW wc{};
            wc.cbSize = sizeof(wc);
            wc.style = CS_HREDRAW | CS_VREDRAW | CS_DBLCLKS;
            wc.lpfnWndProc = &VgwwWindow::WndProcThunk;
            wc.hInstance = instance;
            wc.hCursor = ::LoadCursorW(nullptr, MAKEINTRESOURCEW(32512));  // IDC_ARROW
            wc.hbrBackground = nullptr;  // D2D clears every frame
            wc.lpszClassName = L"VgwwWindowClass";
            // A5: the application icon must reach the window class AND the
            // instance (taskbar/Alt-Tab); fall back to the stock application
            // icon when the painter failed.
            // batch332 P3: Create() is reusable-retry (see the reset above), so
            // a second call after a failed renderer_.Initialize would overwrite
            // these handles and leak the previous HICONs. Release them first
            // (same ownership the destructor already assumes).
            if (small_icon_ != nullptr) {
                ::DestroyIcon(small_icon_);
                small_icon_ = nullptr;
            }
            if (big_icon_ != nullptr) {
                ::DestroyIcon(big_icon_);
                big_icon_ = nullptr;
            }
            tray::MakeAppIcon(&small_icon_, &big_icon_);
            wc.hIcon = big_icon_ != nullptr
                           ? big_icon_
                           : ::LoadIconW(nullptr, MAKEINTRESOURCEW(32512));
            wc.hIconSm = small_icon_ != nullptr
                             ? small_icon_
                             : ::LoadIconW(nullptr, MAKEINTRESOURCEW(32512));
            if (0 == ::RegisterClassExW(&wc) &&
                ERROR_CLASS_ALREADY_EXISTS != ::GetLastError()) {
                error = "RegisterClassExW failed";
                return false;
            }

            ApplyDpi(static_cast<float>(::GetDpiForSystem()));
            // batch20: a pending fixed UI scale wins over the system DPI, so
            // the very first window is already the requested size.
            if (ui_scale_ > 0.0f) {
                ApplyDpi(96.0f * ui_scale_);
            }
            // batch28: the remembered geometry (validated against the CURRENT
            // work areas at the CURRENT dpi). Invalid -> design defaults.
            LoadSavedGeometryForTest();
            const int width = has_pending_restore()
                                  ? static_cast<int>(restored_.w * scale_)
                                  : static_cast<int>(
                                        DarkTheme().min_window.w * scale_);
            const int height = has_pending_restore()
                                   ? static_cast<int>(restored_.h * scale_)
                                   : static_cast<int>(
                                         DarkTheme().min_window.h * scale_);
            int pos_x = CW_USEDEFAULT;
            int pos_y = CW_USEDEFAULT;
            if (has_pending_restore()) {
                pos_x = restored_.x;
                pos_y = restored_.y;
            }
            hwnd_ = ::CreateWindowExW(
                0, wc.lpszClassName, I18n::Instance().T(Str::AppTitle),
                WS_OVERLAPPEDWINDOW & ~WS_CAPTION, pos_x, pos_y, width, height,
                nullptr, nullptr, instance, this);
            if (nullptr == hwnd_) {
                error = "CreateWindowExW failed";
                return false;
            }
            // batch20 item 2/P1: GetDpiForSystem() (used above, before the
            // window
            // existed) can report the PRIMARY/system DPI and leave the first
            // frame at 100% on a 125% desktop. Now that the hwnd exists, take
            // the DPI of the monitor it actually landed on. Then ALWAYS enforce
            // the 980x640 design size at the FINAL scale - the old code sized
            // the window before this correction, so a 125% desktop got a
            // 980x640 px window (784x512 logical viewport = "everything is
            // cut off / got smaller"). A FIXED ui_scale keeps its own DPI.
            if (ui_scale_ <= 0.0f) {
                ApplyAutoDpi();
            }
            {
                // batch28: a restored geometry wins over the design size - it
                // was already validated, but the scale may have changed after
                // the monitor DPI correction above, so re-derive the pixel size
                // from the stored LOGICAL one.
                const Size target =
                    has_pending_restore()
                        ? Size{restored_.w * scale_, restored_.h * scale_}
                        : scaled_client_size();
                size_sync_pending_ = true;  // P1: the first DPICHANGED must
                                            // not adopt the stale suggestion
                last_size_request_ = target;
                ::SetWindowPos(hwnd_, nullptr, 0, 0,
                               static_cast<int>(target.w),
                               static_cast<int>(target.h),
                               SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE);
                // batch30: seed the normal rect with the restored geometry. A
                // maximized restore (SW_MAXIMIZE below) never produces a normal
                // WM_MOVE/WM_SIZE, so the close-time save needs this value to
                // keep the "un-maximize goes back where it was" promise.
                if (has_pending_restore()) {
                    last_normal_rect_ = ui_state::RectI{
                        restored_.x, restored_.y,
                        static_cast<int>(target.w),
                        static_cast<int>(target.h)};
                }
            }
            if (!renderer_.Initialize(error)) {
                ::DestroyWindow(hwnd_);
                hwnd_ = nullptr;
                return false;
            }

            tray::SetCallbacks(tray::Callbacks{
                [this] {
                    ::ShowWindow(hwnd_, SW_SHOW);
                    ::SetForegroundWindow(hwnd_);
                },
                [this] { ::ShowWindow(hwnd_, SW_HIDE); },
                [this] {
                    // batch29: "Open dashboard" - show the window and let the
                    // app navigate (the window owns the show, the app the page).
                    ::ShowWindow(hwnd_, SW_SHOW);
                    ::SetForegroundWindow(hwnd_);
                    if (on_open_dashboard) {
                        on_open_dashboard();
                    }
                },
                [this](bool start) {
                    // batch28: the tray's start/stop item. The app decides and
                    // posts through the one command queue.
                    if (on_toggle_service) {
                        on_toggle_service(start);
                    }
                },
                [this] { RequestExit(); }});
            tray_active_ = tray::Add(
                hwnd_, big_icon_ ? big_icon_ : small_icon_,
                I18n::Instance().T(Str::AppTitle));
            if (!tray_active_) {
                std::fprintf(stderr,
                             "[ui] tray icon registration failed; closing the "
                             "window exits the app\n");
            }
            ::SendMessageW(hwnd_, WM_SETICON, ICON_BIG,
                           reinterpret_cast<LPARAM>(big_icon_));
            ::SendMessageW(hwnd_, WM_SETICON, ICON_SMALL,
                           reinterpret_cast<LPARAM>(small_icon_));
            // batch17 P1-a (audit H1): warm up the D3D/DXGI device + swapchain
            // AND the first-use D2D pipelines / cold text layouts while the
            // window is still HIDDEN, so the first *visible* frame is a
            // content frame instead of a ~150 ms device bring-up blank plus a
            // multi-ms first-draw pipeline compile. The warm-up frame draws
            // exactly the chrome the first real frame paints (root_ is still
            // null here), between BeginFrame/EndFrame; failure is silent
            // (Paint() already tolerates a target that cannot be created) and
            // paint_count_ / frame statistics are untouched (they live in
            // Paint()). The next (visible) paint still takes the full-clear
            // path: nothing has called Invalidate() yet, so app_triggered is
            // false there.
            if (renderer_.BeginFrame(hwnd_)) {
                RECT warm_client{};
                ::GetClientRect(hwnd_, &warm_client);
                renderer_.ClearFrame();
                DrawChrome(warm_client.right / scale_);
                renderer_.EndFrame();
            }
            if (start_minimized) {
                ::ShowWindow(hwnd_, SW_HIDE);
            } else if (has_pending_restore() && restored_.maximized) {
                // batch30: closed maximized -> open maximized. The NORMAL rect
                // was applied above, so un-maximizing returns exactly there.
                ::ShowWindow(hwnd_, SW_MAXIMIZE);
            } else {
                ::ShowWindow(hwnd_, SW_SHOW);
            }
            ::UpdateWindow(hwnd_);
            if (ShouldForegroundOnCreate(start_minimized)) {
                // S5.19 defect 2: a fresh launch must land in front of
                // already-open windows. The tray-restore path already
                // foregrounds (same pair); the startup path was missing it.
                // WS_EX_TOPMOST is deliberately NOT used (no permanent pin).
                ::BringWindowToTop(hwnd_);
                ::SetForegroundWindow(hwnd_);
                foreground_requested_ = true;
            }
            // G1/S1: give the window keyboard focus at startup so a
            // console-launched process (which may not already own the
            // foreground input queue) still gets a caret; the caret phase
            // itself is decoupled from ::GetFocus(), but real key input needs
            // this. Create previously never called SetFocus.
            ::SetFocus(hwnd_);
            error.clear();
            return true;
        }

        void VgwwWindow::RequestExit() noexcept {
            exit_requested_ = true;
            if (hwnd_) {
                ::PostMessageW(hwnd_, kExitWakeMessage, 0, 0);
            }
        }

        void VgwwWindow::HideToTray() {
            if (!tray_active_) {
                RequestExit();  // no tray icon: hiding would strand us
                return;
            }
            if (!balloon_shown_) {
                balloon_shown_ = true;
                tray::ShowBalloon(
                    I18n::Instance().T(Str::AppTitle),
                    I18n::Instance().T(Str::TrayBalloonBody));
            }
            if (on_close_to_tray) {
                on_close_to_tray();
            }
            if (hwnd_) {
                ::ShowWindow(hwnd_, SW_HIDE);
            }
            hidden_to_tray_ = true;
        }

        void VgwwWindow::HandleKillFocusForTest() {
            // Defensive: no half-pressed state survives focus loss, and hover
            // must not stick while unfocused (T6-F1 M3).
            mouse_capture_ = nullptr;
            // batch332 P1: a drag latched in a control (column resize, text
            // drag-select) must be aborted too. The release that would have
            // cleared it goes to the window that took activation, so without
            // this the control kept resizing / extending on every later hover.
            CancelDragsIn(root_);
            ClearHover();
            // batch26 P0: a popup left open while the app loses focus
            // (another window / Alt+Tab) used to stay on screen after
            // returning. Dismiss it exactly like an outside click.
            // batch322: context menus are popups too - they used to survive
            // the same activation loss (the list half was already handled).
            CloseContextMenus();
            CollapseExpandedPopups(nullptr);
            Invalidate();
        }

        void VgwwWindow::HandleCloseRequest() {
            if (!tray_active_) {
                RequestExit();  // no tray icon: hiding would strand us
                return;
            }
            if (on_close_requested) {
                on_close_requested();
                return;
            }
            HideToTray();  // legacy behaviour: close means hide to tray
        }

        bool VgwwWindow::PostUiDebug() noexcept {
            // No hwnd: either headless (unit test) or the window is gone. The
            // debug channel must run inline then - posting would queue a wake
            // no message loop will ever dispatch (Task 6 trap 1).
            if (hwnd_ == nullptr) {
                return false;
            }
            return FALSE != ::PostMessageW(hwnd_, kUiDebugMessage, 0, 0);
        }

        void VgwwWindow::Invalidate() noexcept {
            // U1 test seam: record every invalidation request even when there
            // is no hwnd, so headless tests can assert "how much" was asked to
            // repaint (D3 hover / D4 wheel locality). Purely additive - the
            // production path below is unchanged.
            ++invalidate_count_;
            last_invalidation_full_ = true;
            last_invalidated_rect_ = Rect{};
            invalidation_full_since_reset_ = true;
            if (hwnd_ && ::InvalidateRect(hwnd_, nullptr, FALSE)) {
                app_invalidate_pending_ = true;
            }
        }

        void VgwwWindow::InvalidateRect(Rect logical) noexcept {
            // U1 test seam (see Invalidate()): record the exact local rect.
            ++invalidate_count_;
            last_invalidation_full_ = false;
            last_invalidated_rect_ = logical;
            if (logical.w > 0.0f && logical.h > 0.0f) {
                Rect& u = invalidation_union_;
                if (u.w <= 0.0f || u.h <= 0.0f) {
                    u = logical;
                } else {
                    const float x0 = std::min(u.x, logical.x);
                    const float y0 = std::min(u.y, logical.y);
                    const float x1 = std::max(u.x + u.w, logical.x + logical.w);
                    const float y1 = std::max(u.y + u.h, logical.y + logical.h);
                    u = Rect{x0, y0, x1 - x0, y1 - y0};
                }
            }
            if (hwnd_) {
                RECT physical = InvalidateRectPixels(logical, scale_);
                if (::InvalidateRect(hwnd_, &physical, FALSE)) {
                    app_invalidate_pending_ = true;
                }
            }
        }

        void VgwwWindow::InvalidateElement(Element* e) {
            // Local invalidation (T2): only a live, visible element with a
            // non-empty box repaints. A stale/hidden/degenerate target is a
            // no-op - never widens to a full-window repaint.
            if (e == nullptr || !ElementInTree(root_, e)) {
                return;
            }
            InvalidateElementBox(e);
        }

        void VgwwWindow::InvalidateLiveElement(Element* e) {
            // batch55: the caller proved `e` is in the live tree (see the
            // header contract); skip the whole-tree liveness DFS.
            if (e == nullptr) {
                return;
            }
            InvalidateElementBox(e);
        }

        void VgwwWindow::InvalidateElementBox(Element* e) {
            if (!e->visible) {
                return;
            }
            // M4-F2: read the element's own invalidation_bounds() (virtual)
            // instead of the raw box, so a control that paints beyond its
            // bounds - an expanded Select popup, a hovered table row - gets
            // its real region repainted. The base class returns bounds(), so
            // every other element keeps exactly the previous behaviour.
            //
            // batch64/65 boundary: reading the hint BARE is allowed only on
            // the hover / local-highlight paths below (hover enter+leave, IME
            // caret, a right-click consumer). Any path where more than the
            // hover highlight moved - a content refresh, a keyboard scroll -
            // must widen with CaptureWidestBounds instead, because a Table's
            // hint is a strict SUBSET (one 28 px row) and the rest of the body
            // would stay stale. Do NOT widen this helper itself: the hover hot
            // path relies on the band being narrow (a dashboard row sweep
            // would otherwise repaint 1865 ops per row crossed).
            const Rect bounds = e->invalidation_bounds();
            if (bounds.w <= 0.0f || bounds.h <= 0.0f) {
                return;
            }
            InvalidateRect(bounds);
        }

        void VgwwWindow::RequestAnimationFrame() {
            // Decoupled from hwnd_ so the state machine is headless-testable:
            // the clock is "active" whenever at least one element is
            // animating, and the OS timer merely drives it when a window
            // exists.
            if (animation_active_) {
                return;
            }
            animation_active_ = true;
            last_animation_time_ = std::chrono::steady_clock::now();
            if (hwnd_ != nullptr) {
                if (0 == ::SetTimer(hwnd_, kAnimationTimerId,
                                    kAnimationFrameMs, nullptr)) {
                    animation_active_ = false;  // roll back: no timer, no clock
                }
            }
        }

        void VgwwWindow::StopAnimationFrame() noexcept {
            if (!animation_active_) {
                return;
            }
            if (hwnd_ != nullptr) {
                ::KillTimer(hwnd_, kAnimationTimerId);
            }
            animation_active_ = false;
        }

        void VgwwWindow::RunMessageLoop() {
            // Threading (T6 review M2): the UI shell owns no secondary thread.
            // RunMessageLoop - and every WndProc/timer/tray callback it
            // dispatches - runs on the calling thread (the process main thread
            // in the app entry point). There is no thread entry point that
            // needs a try/catch, but WndProc IS an OS-facing callback
            // (user32 calls it through DispatchMessageW): RunGuardedWndProc
            // firewalls the body so a throw never unwinds through user32. The
            // only background threads in the app are the T4/T5 snapshot
            // publisher and command worker, which already contain their own
            // exceptions (T4-F1 M4).
            if (nullptr == hwnd_) {
                return;
            }
            if (on_snapshot_tick) {
                ::SetTimer(hwnd_, kSnapshotTimerId, kSnapshotTimerMs, nullptr);
            }
            // S5.19: the caret blink timer runs for the window's lifetime -
            // no start/stop on focus switches; OnCaretBlinkTick repaints only
            // the focused input's bounds and only while the window has focus.
            ::SetTimer(hwnd_, kCaretBlinkTimerId, kCaretBlinkTimerMs, nullptr);
            MSG message{};
            while (!exit_requested_ &&
                   ::GetMessageW(&message, nullptr, 0, 0) > 0) {
                ::TranslateMessage(&message);
                ::DispatchMessageW(&message);
            }
            if (on_snapshot_tick) {
                ::KillTimer(hwnd_, kSnapshotTimerId);
            }
            ::KillTimer(hwnd_, kCaretBlinkTimerId);
            ::KillTimer(hwnd_, kAnimationTimerId);
            animation_active_ = false;
            if (hwnd_ && ::IsWindow(hwnd_)) {
                ::DestroyWindow(hwnd_);
            }
        }

        void VgwwWindow::SetRoot(Element* root) {
            // M1 (batch2, plan C) H1: a root swap changes the tree topology,
            // so the overlay-node cache must rebuild on the next access. The
            // bump is unconditional (including SetRoot(nullptr)) and runs
            // before any use of the new root_.
            NoteTreeStructureChanged();
            root_ = root;
            if (root_) {
                Relayout();  // initial arrange for the current client size
            }
            Invalidate();
            // W11 G-1: the tree may have started an entrance fade before this
            // window existed (UiApp composes the shell + initial page
            // pre-Create), when RequestAnimationFrame could only latch
            // animation_active_; Create()'s reusable-retry reset then cleared
            // that latch, so without this probe the first frame would freeze at
            // alpha 0 (blank content) until an unrelated event started a new
            // animation. A live window whose root contains a visible element
            // mid-animation must have the clock running.
            if (root_ != nullptr && !animation_active_ &&
                AnyActiveAnimation(root_)) {
                RequestAnimationFrame();
            }
        }

        void VgwwWindow::RequestLayout() {
            // M1 (batch2, plan C) H1: bump BEFORE the early return so a
            // headless / pre-SetRoot structural change still invalidates the
            // overlay-node cache.
            NoteTreeStructureChanged();
            const bool can_arrange =
                root_ != nullptr &&
                (hwnd_ != nullptr ||
                 (headless_client_w_ > 0.0f && headless_client_h_ > 0.0f));
            if (!can_arrange) {
                // Record the request: the app may ask before Create() (or
                // before SetRoot) and the test anchor must see it either way.
                ++layout_requests_;
                return;  // safe no-op: nothing to arrange yet
            }
            // batch29 P3: coalesce. A page switch fires several requests for
            // ONE change (router on_changed, the page's own InvalidateLayout,
            // the shell relabel). When nothing at all has changed since the
            // last arrange (layout/content/tree epochs unchanged), this
            // request is redundant - it performs no work and is not counted,
            // so layout_requests reports REAL arranges.
            if (UiLayoutEpoch() == arranged_layout_epoch_ &&
                UiTreeEpoch() == arranged_tree_epoch_ &&
                UiContentEpoch() == arranged_content_epoch_) {
                return;
            }
            ++layout_requests_;
            Relayout();
            Invalidate();
        }

        void VgwwWindow::RepaintChangedContent() {
            // batch29 P2/P3: a snapshot tick that only changed element CONTENT
            // still needs one re-arrange (text widths may have moved), but not
            // a whole-window repaint: reload the tree geometry, then invalidate
            // only the changed elements and their parents (a parent covers a
            // sibling that shifted because the text width changed). Falls back
            // to a full invalidate when nothing trackable changed.
            // batch37b: only re-arrange when the layout was actually
            // invalidated (a text/control reported a geometry change). A
            // content-only tick (sparkline sample, a table cell value with
            // frozen widths) just repaints the changed elements - the old
            // unconditional Relayout() re-arranged the whole tree at the
            // snapshot-tick rate and caused the user-visible stutter.
            const bool layout_changed =
                UiLayoutEpoch() != arranged_layout_epoch_ ||
                UiTreeEpoch() != arranged_tree_epoch_;
            if (layout_changed) {
                ++layout_requests_;
            }
            std::vector<Element*> changed;
            DrainContentDirtyElements(changed);
            std::vector<Rect> regions;
            regions.reserve(changed.size() * 4);
            // batch55: ONE tree walk marks every live dirty element, instead of
            // a whole-tree DFS per dirty element (twice - before and after the
            // re-arrange). With kMaxContentDirty = 4096 the old shape was
            // O(dirty x N); a tree DFS that only RECORDS which members of a
            // small `wanted` set it met is O(N + dirty). Liveness is still
            // decided per pass, so a re-arrange that tears an element down is
            // still detected by the second pass exactly as before.
            const std::unordered_set<const Element*> wanted(changed.begin(),
                                                           changed.end());
            std::unordered_set<const Element*> live;
            MarkLiveDirtyElements(root_, wanted, live);
            const auto add_region = [&regions](const Element* element) {
                if (element == nullptr) {
                    return;
                }
                // batch64: invalidation_bounds() is a *repaint* hint and may be
                // a strict SUBSET of the box - a hovered TableElement returns
                // only the hovered row band. Seeding a content repaint from it
                // repainted that one row and left every other row showing the
                // previous snapshot (the dashboard refreshes at ~2 Hz, so the
                // list froze exactly while it was being read). Same rule as
                // RefreshSubtreeBounds/CaptureWidestBounds: the hint may only
                // WIDEN the box, never replace it.
                const Rect r = CaptureWidestBounds(element);
                if (r.w > 0.0f && r.h > 0.0f) {
                    regions.push_back(r);
                }
            };
            for (Element* element : changed) {
                if (0 == live.count(element)) {
                    continue;
                }
                add_region(element);
                // A parent is needed only when geometry moved (a sibling may
                // have shifted). Content-only repaints stay at the element box
                // - widening these to large containers was most of the paint
                // cost behind the refresh stutter.
                if (layout_changed) {
                    add_region(element->parent());
                }
            }
            if (layout_changed && root_ != nullptr) {
                Relayout();  // re-arrange with the new text widths
                live.clear();
                MarkLiveDirtyElements(root_, wanted, live);
            }
            for (Element* element : changed) {
                if (0 == live.count(element)) {
                    continue;
                }
                add_region(element);       // old + new (shifted text)
                if (layout_changed) {
                    add_region(element->parent());
                }
            }
            if (regions.empty()) {
                Invalidate();
                return;
            }
            for (const Rect& region : regions) {
                InvalidateRect(region);
            }
        }

        void VgwwWindow::Relayout() {
            if (nullptr == root_) {
                return;
            }
            float width = 0.0f;
            float height = 0.0f;
            if (hwnd_ != nullptr) {
                RECT client{};
                ::GetClientRect(hwnd_, &client);
                width = client.right / scale_;
                height = client.bottom / scale_;
            } else if (headless_client_w_ > 0.0f && headless_client_h_ > 0.0f) {
                width = headless_client_w_;
                height = headless_client_h_;
            } else {
                // No size available (headless window without a client size):
                // record the observed epochs so a follow-up RequestLayout with
                // no new change still coalesces instead of re-requesting.
                arranged_layout_epoch_ = UiLayoutEpoch();
                arranged_tree_epoch_ = UiTreeEpoch();
                arranged_content_epoch_ = UiContentEpoch();
                return;
            }
            // Direct Arrange with the new size re-measures (T2-F1 semantics:
            // Measure is keyed by the available size; no InvalidateLayout).
            root_->Arrange(Rect{0.0f, titlebar_h_, width,
                                std::max(height - titlebar_h_, 0.0f)});
            arranged_layout_epoch_ = UiLayoutEpoch();
            arranged_tree_epoch_ = UiTreeEpoch();
            arranged_content_epoch_ = UiContentEpoch();
        }

        void VgwwWindow::ResizeForTest(float logical_w, float logical_h) {
            const float w = std::max(logical_w, 0.0f);
            const float h = std::max(logical_h, 0.0f);
            if (hwnd_ != nullptr) {
                // SetWindowPos sizes the OUTER window, so convert the wanted
                // LOGICAL client size to physical and add the current frame
                // delta: the resulting CLIENT area is w x h in logical pixels.
                RECT client{};
                ::GetClientRect(hwnd_, &client);
                RECT window{};
                ::GetWindowRect(hwnd_, &window);
                const int frame_w =
                    (window.right - window.left) - client.right;
                const int frame_h =
                    (window.bottom - window.top) - client.bottom;
                const int cw = static_cast<int>(w * scale_);
                const int ch = static_cast<int>(h * scale_);
                // SetWindowPos sizes the OUTER window; when the requested
                // client size differs, the resulting WM_SIZE has already run
                // Relayout for the new client (and Invalidate). A second
                // explicit Relayout/Invalidate in that case would re-arrange
                // the whole tree and re-post a full-window repaint for nothing,
                // so it is intentionally omitted (the WM_SIZE path is the single
                // arrange; Arrange is deterministic, so the final bounds are
                // unchanged). When the size is unchanged SetWindowPos emits no
                // WM_SIZE, so this debug seam must force one Invalidate itself
                // to preserve its "force a repaint" contract.
                const bool size_unchanged =
                    cw == client.right && ch == client.bottom;
                ::SetWindowPos(hwnd_, nullptr, 0, 0, cw + frame_w, ch + frame_h,
                               SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE);
                if (size_unchanged) {
                    Invalidate();
                }
                return;
            }
            // Headless: no hwnd to resize, so arrange the root with the
            // requested logical client size (below the title bar, matching the
            // window's layout contract) and record the layout request.
            if (root_ != nullptr) {
                root_->Arrange(Rect{0.0f, titlebar_h_, w,
                                    std::max(h - titlebar_h_, 0.0f)});
                ++layout_requests_;
                arranged_layout_epoch_ = UiLayoutEpoch();
                arranged_tree_epoch_ = UiTreeEpoch();
                arranged_content_epoch_ = UiContentEpoch();
            }
        }

        void VgwwWindow::DrawChrome(float client_w) {
            RenderCtx& ctx = renderer_;
            ctx.FillRect(Rect{0.0f, 0.0f, client_w, titlebar_h_},
                         ColorFor(ColorToken::Panel));
            ctx.DrawText(I18n::Instance().T(Str::AppTitle),
                         Rect{12.0f, 0.0f, std::max(client_w - 120.0f, 0.0f),
                              titlebar_h_},
                         FontToken::BodyStrong, ColorFor(ColorToken::Text),
                         Align::Start);
            const Color hover = ColorFor(ColorToken::PanelAlt);
            // batch33m (user: "when I look at the Windows 11 minimize,
            // maximize, restore and close buttons on screen, that is the style
            // I want"): draw the caption buttons the way Win11
            // does instead of centring a 20 px FONT glyph in a 56 px box.
            //   * glyphs are thin 1 px GEOMETRY (a 10 px line, a 10 px square,
            //     an X of two 45-degree lines) - no font, so no thick
            //     font-specific strokes and no missing-glyph boxes;
            //   * hover fills the whole button with a subtle tint;
            //   * the close button turns RED on hover (Win11's one destructive
            //     affordance), every other button keeps the neutral tint;
            //   * the glyph colour follows the hover state (bright on hover).
            const Color hover_neutral = ColorFor(ColorToken::PanelAlt);
            const Color hover_close = ColorFor(ColorToken::Danger);
            const Color glyph_idle = ColorFor(ColorToken::Text);
            const Color glyph_hover = ColorFor(ColorToken::Text);
            const bool hovers[3] = {caption_hover_.minimize,
                                    caption_hover_.maximize,
                                    caption_hover_.close};
            for (int i = 0; i < 3; ++i) {
                const Rect box = CaptionButtonRect(i);
                if (hovers[i]) {
                    ctx.FillRect(box, i == 2 ? hover_close : hover_neutral);
                }
                // Glyph geometry: a 10 x 10 logical box centred in the button.
                const float gx = box.x + (box.w - 10.0f) * 0.5f;
                const float gy = box.y + (box.h - 10.0f) * 0.5f;
                // batch37h: Win11 glyph strokes are one DEVICE pixel wide.
                // The old 1-logical-px staircase X read as a thick font X at
                // 125% DPI next to the native caption icons.
                const float px = 1.0f / std::max(scale_, 0.5f);
                const Color ink = (i == 2 && hovers[i]) ? Color{1, 1, 1, 1}
                                                        : glyph_idle;
                if (i == 0) {
                    // Minimize: one 10 x 1-device-px horizontal line.
                    ctx.FillRect(Rect{gx, gy + 4.5f, 10.0f, px}, ink);
                } else if (i == 1) {
                    // Maximize / restore, Win11 shape. When zoomed the front
                    // square is complete and the back one shows only its top
                    // and right edges; drawing two FULL squares (the old code)
                    // overlaps the edges and reads as a thick double frame
                    // instead of the native restore glyph.
                    if (IsZoomedNow()) {
                        ctx.StrokeRect(Rect{gx, gy + 2.0f, 7.5f, 7.5f}, ink,
                                       px);
                        ctx.DrawLine(Point{gx + 2.5f, gy},
                                     Point{gx + 9.5f, gy}, ink, px);
                        ctx.DrawLine(Point{gx + 9.5f, gy},
                                     Point{gx + 9.5f, gy + 7.0f}, ink, px);
                    } else {
                        ctx.StrokeRect(Rect{gx + 0.5f, gy + 0.5f, 9.0f, 9.0f},
                                       ink, px);
                    }
                } else {
                    // Close: two antialiased 1-device-px diagonals.
                    ctx.DrawLine(Point{gx, gy}, Point{gx + 9.5f, gy + 9.5f},
                                 ink, px);
                    ctx.DrawLine(Point{gx, gy + 9.5f}, Point{gx + 9.5f, gy},
                                 ink, px);
                }
            }
            (void)hover;
            (void)glyph_hover;
            ctx.FillRect(Rect{0.0f, titlebar_h_ - 1.0f, client_w, 1.0f},
                         ColorFor(ColorToken::Border));
        }

        void VgwwWindow::Paint() {
            PAINTSTRUCT ps{};
            ::BeginPaint(hwnd_, &ps);
            const bool perf = ::GetEnvironmentVariableW(L"VGWW_PERF", nullptr, 0) != 0;
            const auto t0 = std::chrono::steady_clock::now();
            if (renderer_.BeginFrame(hwnd_)) {
                RECT client{};
                ::GetClientRect(hwnd_, &client);
                // P3 dirty-rect: repaint only the region GDI marked invalid
                // (caret blink, hover) via ClearRect + a clip; a full-frame
                // invalidation (Invalidate/InvalidateRect(nullptr)), a
                // (re)created/resized target, or a SYSTEM exposure with no
                // pending app invalidation takes the full-clear path. The
                // target retains its previous contents (RETAIN_CONTENTS), so
                // untouched regions stay valid. The system-exposure clause is
                // T3: an occlusion-restore WM_PAINT can arrive with a mid-region
                // rcPaint while the discarded buffer would leave a ghost, so it
                // must clear fully.
                //
                // batch11 M12: a visible overlay no longer forces the
                // full-clear path. A partial frame draws the overlay pass
                // into the SAME dirty clip as the content clear (M2 - one
                // single-composite domain), and every overlay state/geometry
                // change invalidates at least the region it paints; the
                // wheel-over-a-scrolled-overlay case falls back to a full
                // invalidate (M2b). See HasVisibleOverlay and
                // SubtreeHasVisibleOverlay.
                const bool app_triggered = app_invalidate_pending_;
                app_invalidate_pending_ = false;
                const bool full = ShouldFullClear(
                    renderer_.ConsumeFullClearNeeded(), app_triggered,
                    ps.rcPaint, client);
                const Rect dirty{
                    static_cast<float>(ps.rcPaint.left) / scale_,
                    static_cast<float>(ps.rcPaint.top) / scale_,
                    static_cast<float>(ps.rcPaint.right - ps.rcPaint.left) /
                        scale_,
                    static_cast<float>(ps.rcPaint.bottom - ps.rcPaint.top) /
                        scale_};
                // T8 metrics: the last dirty region in logical pixels (the
                // rcPaint the OS handed us; the full-clear path may clear more).
                last_dirty_rect_ = dirty;
                PaintOrchestrate(full, dirty, client);
                renderer_.EndFrame();
            }
            ::EndPaint(hwnd_, &ps);
            ++paint_count_;
            if (perf) {
                const auto us = std::chrono::duration_cast<
                    std::chrono::microseconds>(std::chrono::steady_clock::now() - t0)
                                   .count();
                last_paint_us_ = static_cast<long long>(us);
                std::fprintf(stderr, "[perf] paint=%lldus\n",
                             static_cast<long long>(us));
            } else {
                last_paint_us_ = std::chrono::duration_cast<
                    std::chrono::microseconds>(std::chrono::steady_clock::now() - t0)
                                     .count();
            }
            // M5 frame statistics (spec): feed the paint duration + the interval
            // since the previous frame into RecordFrameStatistics. First frame:
            // last_paint_wall_us_ is -1, so interval <= 0 (anchor only, no
            // window push). VGWW_PERF print lines above are byte-unchanged.
            const auto now_us = std::chrono::duration_cast<
                std::chrono::microseconds>(
                std::chrono::steady_clock::now().time_since_epoch())
                                   .count();
            const long long interval_us =
                last_paint_wall_us_ < 0 ? -1 : now_us - last_paint_wall_us_;
            last_paint_wall_us_ = now_us;
            RecordFrameStatistics(last_paint_us_, interval_us);
        }

        void VgwwWindow::PaintOrchestrate(bool full, const Rect& dirty,
                                          const RECT& client) {
            // M5 (batch11 M12): moved verbatim out of Paint() - Paint()
            // computes the verdict above and this method owns the
            // clear -> clip/cull -> chrome -> content pass -> overlay pass
            // sequence. Paint() and PaintFrameForTest share it, so the
            // headless clip-structure assertions observe the production
            // sequence itself, not a mirror.
            // batch29 P2: arm the text-paint cache with this frame's dirty
            // domain; EndTextFrame (below) commits it for the next frame.
            renderer_.BeginTextFrame(dirty, full);
            if (full) {
                renderer_.ClearFrame();
            } else if (dirty.w > 0.0f && dirty.h > 0.0f) {
                renderer_.ClearRect(dirty);
                renderer_.ClipPush(dirty);
            }
            const bool rect_dirty = !full && dirty.w > 0.0f && dirty.h > 0.0f;
            // Tell the element tree which logical region is live so any
            // element whose bounds fall outside it skips its D2D calls; a
            // full repaint leaves the cull inactive so the whole tree
            // draws exactly as before (pixel-identical).
            if (rect_dirty) {
                renderer_.SetCullRect(dirty);
            } else {
                renderer_.ClearCullRect();
            }
            const float client_w = client.right / scale_;
            const Rect titlebar{0.0f, 0.0f, client_w, titlebar_h_};
            if (full || RectsIntersect(titlebar, dirty)) {
                DrawChrome(client_w);
            }
            if (root_) {
                // Content pass: Element::Render walks the tree but skips
                // renders_on_top children (dialogs/toasts), preserving the
                // ScrollView clip chain.
                root_->Render(renderer_);
                // U1-D1 + batch11 M12: the dirty-rect clip is popped before
                // the overlay pass, which then re-clips either to the SAME
                // dirty rect (partial frame - M2) or to the whole client
                // (full frame). The pre-M12 code always lifted the clip to
                // the whole client, because a dirty clip once chopped an
                // expanded popup's border ("dropdown draws no border"); that
                // was the U1-D1 fix, delivered at a time when overlay frames
                // were forced full anyway. M12 keeps an overlay frame partial
                // only when its changed pixels lie inside `dirty` by
                // construction (the invalidation surfaces cover box + popup,
                // and the wheel/scroll path falls back to a full invalidate -
                // M2b), so the dirty clip is exactly the single-composite
                // domain the partial clear established - it keeps translucent
                // composites from being source-over'd twice outside it
                // (U1-R1). The RETAIN_CONTENTS buffer outside `dirty` stays
                // valid because only `dirty` was cleared above.
                if (rect_dirty) {
                    renderer_.ClipPop();
                }
                const Rect client_rect{
                    0.0f, 0.0f, client.right / scale_,
                    client.bottom / scale_};
                // M12 M2: partial frames clip the overlay pass to the dirty
                // rect (the same domain the content pass was cleared and
                // drawn in); a full frame keeps the whole-client clip.
                const Rect overlay_clip = rect_dirty ? dirty : client_rect;
                // M5 phase marker: record where the overlay segment's
                // top-level clip lands in the recorded op stream (headless
                // structure assertions). Not recording: stays unset.
                overlay_phase_ops_index_ = renderer_.recording()
                                               ? renderer_.ops().size()
                                               : kOverlayPhaseUnset;
                renderer_.ClipPush(overlay_clip);
                // The overlay pass is never culled (its popups may exceed
                // their node bounds); drop the cull before it runs.
                renderer_.ClearCullRect();
                // Top layer: paint dialogs/toasts (and any nested Select
                // popup) above all content, in one pre-order DFS so toasts
                // (added last) end up on top of dialogs.
                RenderOverlays(renderer_, root_);
                DrawHoverTooltip(renderer_);
                renderer_.ClipPop();
            }
            renderer_.ClearCullRect();  // symmetric: never leaks past a frame
            renderer_.EndTextFrame();
        }

        void VgwwWindow::PaintFrameForTest(bool full, const Rect& dirty,
                                           const RECT& client_rc) {
            // M5 headless seam: the same orchestration Paint() runs between
            // BeginFrame/EndFrame, over the window's renderer_ (the caller
            // BeginRecord/EndRecord around it). No hwnd is touched.
            PaintOrchestrate(full, dirty, client_rc);
        }

        double VgwwWindow::fps() const noexcept {
            // M5: a static ("idle") page reports 0 fps. The wall-clock gap
            // since the last recorded frame is checked at READ time: once the
            // app stops painting, fps() returns 0 instead of the stale burst
            // average. Fewer than two intervals also yields 0 (no signal).
            const auto now_us = std::chrono::duration_cast<
                std::chrono::microseconds>(
                std::chrono::steady_clock::now().time_since_epoch())
                                   .count();
            if (last_paint_wall_us_ < 0 ||
                now_us - last_paint_wall_us_ > kIdleGapUs) {
                return 0.0;
            }
            if (frame_interval_len_ < 2) {
                return 0.0;
            }
            return 1000000.0 * static_cast<double>(frame_interval_len_) /
                   static_cast<double>(frame_interval_sum_us_);
        }

        void VgwwWindow::RecordFrameStatistics(long long paint_us,
                                               long long interval_us) noexcept {
            // M5: tracks one painted frame. paint_us over the budget is a
            // dropped frame; the interval feeds the 60-slot rolling fps window.
            // interval <= 0 (first frame) only sets the anchor; an interval
            // past kIdleGapUs clears the window (true idle gap).
            if (static_cast<uint64_t>(paint_us) > frame_time_max_us_) {
                frame_time_max_us_ = static_cast<uint64_t>(paint_us);
            }
            if (paint_us > kFrameBudgetUs) {
                ++over_budget_frames_;
            }
            if (interval_us <= 0) {
                return;  // first frame: nothing to window yet
            }
            if (interval_us > kIdleGapUs) {
                frame_interval_len_ = 0;
                frame_interval_sum_us_ = 0;
                return;
            }
            if (frame_interval_len_ < kFrameStatsWindow) {
                const int slot =
                    (frame_interval_head_ + frame_interval_len_) %
                    kFrameStatsWindow;
                frame_interval_hist_[slot] = interval_us;
                frame_interval_sum_us_ += interval_us;
                ++frame_interval_len_;
            } else {
                // Ring full: overwrite the oldest slot (the head), advance it.
                frame_interval_sum_us_ -=
                    frame_interval_hist_[frame_interval_head_];
                frame_interval_hist_[frame_interval_head_] = interval_us;
                frame_interval_sum_us_ += interval_us;
                frame_interval_head_ =
                    (frame_interval_head_ + 1) % kFrameStatsWindow;
            }
        }

        void VgwwWindow::RenderOverlays(RenderCtx& ctx, Element* node) {
            if (node == nullptr || !node->visible) {
                return;
            }
            node->RenderOverlay(ctx);
            // Keep descending even through a renders_on_top node: a DialogHost
            // may host a Select whose popup must also be painted unclipped.
            for (const auto& child : node->children()) {
                RenderOverlays(ctx, child.get());
            }
        }

        Element* VgwwWindow::FindOverlayHit(Point logical) const {
            // M1 (batch2, plan C): the cached sequence is already in
            // reverse-children post-order - the order the old recursive DFS
            // tested HitTestOverlay - so the first non-null wins. H6: a
            // candidate is reachable only when it and every ancestor are
            // visible (the old DFS pruned hidden subtrees; the flat cache does
            // not, because the existence path must keep hidden nodes).
            RefreshOverlayCacheIfStale();
            for (Element* node : overlay_nodes_) {
                if (!OverlayVisibleChain(node)) {
                    continue;
                }
                if (Element* hit = node->HitTestOverlay(logical)) {
                    return hit;
                }
            }
            return nullptr;
        }

        Element* VgwwWindow::HitTestTopmost(Point logical) const {
            if (root_ == nullptr) {
                return nullptr;
            }
            // The top-layer surface wins over the normal content hit: a later
            // sibling must not steal a click meant for an expanded Select
            // popup, and the open modal's dimmer must mask the page (G3/G9).
            if (Element* overlay = FindOverlayHit(logical)) {
                return overlay;
            }
            return root_->HitTest(logical);
        }

        Element* VgwwWindow::HitTestTopmostForTest(Point logical) const {
            return HitTestTopmost(logical);
        }

        CursorKind VgwwWindow::ResolveCursorHint(Point logical) const {
            // batch18 U2 (drag fallback): while an element owns the captured
            // pointer it also owns the cursor hint (the same liveness
            // contract as the capture routing at RouteClientPointer, plus
            // visibility) - a column-resize drag keeps SizeWE even after the
            // pointer leaves the header band.
            if (mouse_capture_ != nullptr &&
                ElementInTree(root_, mouse_capture_) &&
                mouse_capture_->visible) {
                return mouse_capture_->cursor_hint(logical);
            }
            // W11 batch6 G-4: the same overlay-first resolution every mouse
            // message uses; no hit (or no root) = the default arrow.
            // batch18 U2: the fresh logical point flows into the hint so a
            // position-sensitive control (the table's header boundaries)
            // can answer SizeWE.
            Element* hit = HitTestTopmost(logical);
            return hit != nullptr ? hit->cursor_hint(logical)
                                  : CursorKind::Arrow;
        }

        void VgwwWindow::RenderFrameForTest(RenderCtx& ctx) {
            if (root_ == nullptr) {
                return;
            }
            // ClearCullRect at entry: a cull left over from a prior partial
            // paint must never prune this whole-frame render (same contract
            // as BeginRecord).
            ctx.ClearCullRect();
            root_->Render(ctx);
            RenderOverlays(ctx, root_);
            // batch28: PaintOrchestrate paints the hover tooltip above the
            // overlay pass; this whole-frame seam must match it so the debug
            // channel can observe the tooltip (the shortened Settings line's
            // full device path) instead of reporting it as absent.
            DrawHoverTooltip(ctx);
        }

        bool VgwwWindow::FullClearForTest(bool target_recreated,
                                          bool app_triggered,
                                          const RECT& rcPaint,
                                          const RECT& client) const noexcept {
            // Read-only test mirror of Paint()'s full-clear verdict. batch11
            // M12 removed the former `|| HasVisibleOverlay()` clause, so this
            // mirrors ShouldFullClear alone (overlay frames may now clear
            // partially); overlay existence is observed through
            // HasVisibleOverlayForTest() instead. `rcPaint`/`client` are
            // physical pixels (raw RECTs), exactly as Paint passes them.
            return ShouldFullClear(target_recreated, app_triggered, rcPaint,
                                   client);
        }

        Rect VgwwWindow::CaptionButtonRect(int index) const noexcept {
            RECT client{};
            if (hwnd_) {
                ::GetClientRect(hwnd_, &client);
            }
            float width = client.right / scale_;
            if (hwnd_ == nullptr && headless_client_w_ > 0.0f) {
                // Headless: same logical width Relayout() arranges against, so
                // the caption geometry matches what DrawChrome paints.
                width = headless_client_w_;
            }
            // batch31 P0-3: three buttons, left to right
            //   0 = minimize, 1 = maximize/restore, 2 = close.
            // Each is one kCaptionButtonW wide; the strip is flush with the
            // client's right edge.
            const int clamped = index < 0 ? 0 : (index > 2 ? 2 : index);
            float x = width - kCaptionButtonW * static_cast<float>(3 - clamped);
            // batch19 R4-P2: caption buttons mirror to the left under RTL.
            if (I18n::Instance().IsRtl()) {
                x = width - x - kCaptionButtonW;
            }
            return Rect{x, 0.0f, kCaptionButtonW, titlebar_h_};
        }

        bool VgwwWindow::CaptionButtonAt(Point logical, int& index) const noexcept {
            for (int i = 0; i < 3; ++i) {
                if (CaptionButtonRect(i).Contains(logical)) {
                    index = i;
                    return true;
                }
            }
            return false;
        }

        bool VgwwWindow::IsZoomedNow() const noexcept {
            if (hwnd_ != nullptr) {
                return ::IsZoomed(hwnd_) != FALSE;
            }
            return zoomed_for_test_;
        }

        std::wstring VgwwWindow::CaptionGlyph(int index) const {
            switch (index) {
                case 0:
                    return L"\u2212";  // minimize (minus glyph)
                case 1:
                    // empty square when normal, restore square when maximized
                    // (restore affordance).
                    return IsZoomedNow() ? std::wstring(L"\u2750")
                                         : std::wstring(L"\u25A1");
                case 2:
                default:
                    return L"\u00D7";  // close (x)
            }
        }

        void VgwwWindow::ToggleMaximize() {
            const bool zoomed = IsZoomedNow();
            if (hwnd_ != nullptr) {
                ::ShowWindow(hwnd_, zoomed ? SW_RESTORE : SW_MAXIMIZE);
            }
            // Counters are headless-observable: the request is recorded even
            // without a live hwnd, so the double-click / button seams can
            // assert the exact toggle the production path performs.
            if (zoomed) {
                ++restore_requests_;
            } else {
                ++maximize_requests_;
            }
            zoomed_for_test_ = !zoomed;
            Invalidate();
        }

        bool VgwwWindow::HandleCaptionButtonClick(Point logical) {
            int index = -1;
            if (!CaptionButtonAt(logical, index)) {
                return false;
            }
            switch (index) {
                case 0:
                    if (hwnd_ != nullptr) {
                        ::ShowWindow(hwnd_, SW_MINIMIZE);
                    }
                    return true;
                case 1:
                    ToggleMaximize();
                    return true;
                case 2:
                default:
                    if (hwnd_ != nullptr) {
                        ::SendMessageW(hwnd_, WM_CLOSE, 0, 0);
                    }
                    return true;
            }
        }

        bool VgwwWindow::HandleTitlebarDoubleClick(Point logical) {
            if (logical.y < 0.0f || logical.y >= titlebar_h_) {
                return false;
            }
            int index = -1;
            if (CaptionButtonAt(logical, index)) {
                // A caption button owns its own semantics: a double click on
                // minimize/close must never maximize the window.
                return true;
            }
            ToggleMaximize();
            return true;
        }

        LRESULT VgwwWindow::HitTestNonClient(POINT screen) const noexcept {
            RECT window{};
            ::GetWindowRect(hwnd_, &window);
            const LONG px = screen.x - window.left;
            const LONG py = screen.y - window.top;
            const LONG width = window.right - window.left;
            const LONG height = window.bottom - window.top;
            const LONG edge =
                static_cast<LONG>(kResizeEdgeLogical * scale_);
            if (!::IsZoomed(hwnd_)) {
                const bool left = px < edge;
                const bool right = px >= width - edge;
                const bool top = py < edge;
                const bool bottom = py >= height - edge;
                if (top && left) return HTTOPLEFT;
                if (top && right) return HTTOPRIGHT;
                if (bottom && left) return HTBOTTOMLEFT;
                if (bottom && right) return HTBOTTOMRIGHT;
                if (left) return HTLEFT;
                if (right) return HTRIGHT;
                if (top) return HTTOP;
                if (bottom) return HTBOTTOM;
            }
            const float logical_x = px / scale_;
            const float logical_y = py / scale_;
            if (logical_y >= 0.0f && logical_y < titlebar_h_) {
                const Point p{logical_x, logical_y};
                int index = -1;
                if (!CaptionButtonAt(p, index)) {
                    return HTCAPTION;
                }
            }
            return HTCLIENT;
        }

        Element* VgwwWindow::FindOpenDialog() const {
            if (nullptr == root_) {
                return nullptr;
            }
            // M1 (batch2, plan C): walk the cached overlay-node set (replaces
            // the old full-tree LIFO DFS); open() stays live. The cache order is
            // reverse-children post-order, which for the at-most-one-open
            // invariant (modal dialogs never nest) matches the old DFS result.
            RefreshOverlayCacheIfStale();
            for (Element* element : overlay_nodes_) {
                if (auto* dialog = dynamic_cast<DialogHost*>(element)) {
                    // batch37h: only a VISIBLE dialog owns the keyboard. A
                    // dialog left open on a hidden page used to be returned
                    // here and SyncDialogFocus stole every key press from the
                    // visible page's text field.
                    if (dialog->open() && OverlayVisibleChain(element)) {
                        return element;
                    }
                }
            }
            return nullptr;
        }

        bool VgwwWindow::HasVisibleOverlay() const {
            // A top-layer surface (open dialog, active toast, expanded Select
            // popup) is currently visible. batch11 M12: this no longer forces
            // a full clear - a partial frame paints the overlay pass into the
            // SAME dirty clip as the content pass (one single-composite
            // domain, so no pixel is source-over'd twice), and the
            // invalidation surfaces guarantee the covered region is live. The
            // wheel path consults the container-relative
            // SubtreeHasVisibleOverlay instead; this whole-window predicate
            // remains for the observation seam (HasVisibleOverlayForTest).
            if (nullptr == root_) {
                return false;
            }
            // M1 (batch2, plan C): the overlay NODE SET is cached (structure
            // keyed); the predicates stay live so state-only changes (Select
            // expand, Toast Tick expiry) need no rebuild. Hidden nodes are
            // enumerated (H7: byte-equivalent to the old visible-blind DFS).
            RefreshOverlayCacheIfStale();
            for (Element* element : overlay_nodes_) {
                if (auto* dialog = dynamic_cast<DialogHost*>(element)) {
                    if (dialog->open()) {
                        return true;
                    }
                } else if (auto* toast = dynamic_cast<ToastHost*>(element)) {
                    if (toast->active_count() > 0) {
                        return true;
                    }
                } else if (auto* select = dynamic_cast<SelectElement*>(element)) {
                    if (select->expanded()) {
                        return true;
                    }
                } else if (auto* menu = dynamic_cast<ContextMenu*>(element)) {
                    if (menu->open()) {
                        return true;
                    }
                }
            }
            return false;
        }

        bool VgwwWindow::SubtreeHasVisibleOverlay(const Element* node) const
            noexcept {
            // M2b (batch11 M12, F1 fix). Same visibility prune as
            // RenderOverlays: a hidden node paints nothing, so its (possibly
            // live) predicate must not widen the repaint.
            if (node == nullptr || !node->visible) {
                return false;
            }
            if (auto* dialog = dynamic_cast<const DialogHost*>(node)) {
                if (dialog->open()) {
                    return true;
                }
            } else if (auto* toast = dynamic_cast<const ToastHost*>(node)) {
                if (toast->active_count() > 0) {
                    return true;
                }
            } else if (auto* select = dynamic_cast<const SelectElement*>(node)) {
                if (select->expanded()) {
                    return true;
                }
            } else if (auto* menu = dynamic_cast<const ContextMenu*>(node)) {
                if (menu->open()) {
                    return true;
                }
            }
            for (const auto& child : node->children()) {
                if (SubtreeHasVisibleOverlay(child.get())) {
                    return true;
                }
            }
            return false;
        }

        bool VgwwWindow::CollapseExpandedPopups(Element* keep) {
            if (root_ == nullptr) {
                return false;
            }
            RefreshOverlayCacheIfStale();
            bool any = false;
            for (Element* node : overlay_nodes_) {
                if (node == keep || !OverlayVisibleChain(node)) {
                    continue;
                }
                if (auto* select = dynamic_cast<SelectElement*>(node)) {
                    if (!select->expanded()) {
                        continue;
                    }
                    const Rect before = select->invalidation_bounds();
                    select->SetExpanded(false);
                    const Rect after = select->invalidation_bounds();
                    const Rect dirty = UnionRects(before, after);
                    if (dirty.w > 0.0f && dirty.h > 0.0f) {
                        InvalidateRect(dirty);
                    }
                    any = true;
                } else if (auto* picker =
                               dynamic_cast<LanguagePicker*>(node)) {
                    if (!picker->expanded()) {
                        continue;
                    }
                    // The picker grows in the flow, so the pre-collapse box is
                    // the whole expanded surface that must be repainted.
                    const Rect before = picker->bounds();
                    picker->SetExpanded(false);
                    if (before.w > 0.0f && before.h > 0.0f) {
                        InvalidateRect(UnionRects(before, picker->bounds()));
                    }
                    any = true;
                }
            }
            return any;
        }

        bool VgwwWindow::CloseContextMenus() {
            if (root_ == nullptr) {
                return false;
            }
            RefreshOverlayCacheIfStale();
            bool any = false;
            for (Element* node : overlay_nodes_) {
                auto* menu = dynamic_cast<ContextMenu*>(node);
                if (menu == nullptr || !menu->open() ||
                    !OverlayVisibleChain(node)) {
                    continue;
                }
                const Rect before = menu->invalidation_bounds();
                menu->Close();
                const Rect after = menu->invalidation_bounds();
                const Rect dirty = UnionRects(before, after);
                if (dirty.w > 0.0f && dirty.h > 0.0f) {
                    InvalidateRect(dirty);
                }
                any = true;
            }
            return any;
        }

        void VgwwWindow::NotifyClipboardFailed(bool paste) {
            if (on_clipboard_failed) {
                on_clipboard_failed(paste);
            }
        }

        void VgwwWindow::ShowEditContextMenu(Element* target, Point at) {
            if (edit_menu_ == nullptr || target == nullptr || root_ == nullptr) {
                return;
            }
            Element* surface = nullptr;
            for (Element* e = target; e != nullptr; e = e->parent()) {
                if (e->EditMenuTarget()) {
                    surface = e;
                    break;
                }
            }
            if (surface == nullptr) {
                return;
            }
            auto* input = dynamic_cast<TextInputElement*>(surface);
            const I18n& i18n = I18n::Instance();
            std::vector<ContextMenu::Item> items;
            const auto add = [&](Str label,
                                 std::function<void(Element*)> action) {
                items.push_back(ContextMenu::Item{
                    i18n.T(label), false,
                    [this, surface, action = std::move(action)] {
                        if (!ElementInTree(root_, surface)) {
                            return;
                        }
                        action(surface);
                        InvalidateElement(surface);
                    }});
            };
            if (input != nullptr && input->CanUndoEdit()) {
                add(Str::EditUndo, [](Element* e) {
                    if (auto* in = dynamic_cast<TextInputElement*>(e)) {
                        in->UndoEdit();
                    }
                });
            }
            if (input != nullptr && input->CanRedoEdit()) {
                add(Str::EditRedo, [](Element* e) {
                    if (auto* in = dynamic_cast<TextInputElement*>(e)) {
                        in->RedoEdit();
                    }
                });
            }
            if (input != nullptr && input->HasTextSelection()) {
                add(Str::EditCut, [this](Element* e) {
                    // batch287: a refused write must not look like a no-op.
                    if (!e->CutSelectionToClipboard() && e->HasTextSelection()) {
                        NotifyClipboardFailed(false);
                    }
                });
            }
            if (surface->HasTextSelection()) {
                add(Str::ConsoleCopy, [this](Element* e) {
                    // batch287: report a refused write instead of a silent no-op.
                    if (!e->CopySelectionToClipboard() && e->HasTextSelection()) {
                        NotifyClipboardFailed(false);
                    }
                });
            }
            // batch288: offer paste when the clipboard HAS text or when it
            // could not be read (the user then learns why it failed). A
            // readable, empty clipboard is the only case with nothing to do.
            bool offer_paste = false;
            if (input != nullptr) {
                std::wstring cb_text;
                offer_paste =
                    !console_log::ReadClipboardText(cb_text) || !cb_text.empty();
            }
            if (offer_paste) {
                add(Str::EditPaste, [this](Element* e) {
                    if (e->PasteFromClipboard() == PasteResult::Failed) {
                        NotifyClipboardFailed(true);
                    }
                });
            }
            if (input != nullptr && input->HasTextSelection()) {
                add(Str::CommonDelete, [](Element* e) {
                    if (auto* in = dynamic_cast<TextInputElement*>(e)) {
                        in->DeleteSelection();
                    }
                });
            }
            if (surface->HasTextContent()) {
                add(Str::EditSelectAll, [](Element* e) {
                    e->SelectAllText();
                });
            }
            if (items.empty()) {
                return;
            }
            edit_menu_->SetClientRect(root_->bounds());
            edit_menu_->Show(at, std::move(items));
            Invalidate();  // the menu is a top-layer surface
        }
        bool VgwwWindow::DismissContextMenuOutside(Point logical) {
            if (root_ == nullptr) {
                return false;
            }
            RefreshOverlayCacheIfStale();
            bool any = false;
            for (Element* node : overlay_nodes_) {
                auto* menu = dynamic_cast<ContextMenu*>(node);
                if (menu == nullptr || !menu->open() ||
                    !OverlayVisibleChain(node)) {
                    continue;
                }
                if (menu->menu_rect().Contains(logical)) {
                    continue;  // the click belongs to the menu itself
                }
                const Rect before = menu->invalidation_bounds();
                menu->Close();
                const Rect after = menu->invalidation_bounds();
                const Rect dirty = UnionRects(before, after);
                if (dirty.w > 0.0f && dirty.h > 0.0f) {
                    InvalidateRect(dirty);
                }
                any = true;
            }
            return any;
        }

        bool VgwwWindow::DismissExpandedPopupsOutside(Point logical) {
            if (root_ == nullptr) {
                return false;
            }
            RefreshOverlayCacheIfStale();
            // Find the expanded popup (if any) that owns the click point. Its
            // trigger box and its popup both count as "inside", so toggling or
            // picking stays with the control; everything else collapses.
            Element* keep = nullptr;
            for (Element* node : overlay_nodes_) {
                if (!OverlayVisibleChain(node) || !node->EffectivelyEnabled()) {
                    continue;
                }
                if (auto* select = dynamic_cast<SelectElement*>(node)) {
                    if (select->expanded() &&
                        (select->bounds().Contains(logical) ||
                         select->popup_rect().Contains(logical))) {
                        keep = node;
                    }
                } else if (auto* picker =
                               dynamic_cast<LanguagePicker*>(node)) {
                    if (picker->expanded() &&
                        picker->bounds().Contains(logical)) {
                        keep = node;
                    }
                }
            }
            return CollapseExpandedPopups(keep);
        }

        void VgwwWindow::RefreshOverlayCacheIfStale() const {
            const uint64_t epoch = UiTreeEpoch();
            if (cached_gen_ == kOverlayCacheSentinel ||
                structure_gen_ != cached_gen_ || epoch != cached_epoch_) {
                overlay_nodes_.clear();
                CacheOverlayNodes(root_);
                cached_gen_ = structure_gen_;
                cached_epoch_ = epoch;
            }
        }

        void VgwwWindow::CacheOverlayNodes(Element* node) const {
            if (node == nullptr) {
                return;
            }
            // Reverse-children post-order (mirrors FindOverlayHit's priority);
            // hidden subtrees are NOT pruned here (H7 existence path).
            const auto& children = node->children();
            for (auto it = children.rbegin(); it != children.rend(); ++it) {
                CacheOverlayNodes(it->get());
            }
            if (dynamic_cast<DialogHost*>(node) != nullptr ||
                dynamic_cast<ToastHost*>(node) != nullptr ||
                dynamic_cast<SelectElement*>(node) != nullptr ||
                dynamic_cast<ContextMenu*>(node) != nullptr ||
                dynamic_cast<LanguagePicker*>(node) != nullptr) {
                overlay_nodes_.push_back(node);
            }
        }

        std::size_t VgwwWindow::overlayNodeCountForTest() const {
            // Read through the same staleness guard the consumers use, so the
            // count reflects the cache they would see (not an independent walk).
            RefreshOverlayCacheIfStale();
            return overlay_nodes_.size();
        }

        void VgwwWindow::SetFocusElement(Element* element) {
            // T6-F1 review I1: a page/dialog rebuild may have destroyed the
            // focused element; drop the stale pointer before touching it.
            if (focused_ != nullptr && !ElementInTree(root_, focused_)) {
                focused_ = nullptr;
            }
            if (focused_ == element) {
                return;
            }
            Element* previous = focused_;
            if (focused_) {
                focused_->OnFocus(false);
            }
            focused_ = element;
            if (focused_) {
                focused_->OnFocus(true);
            }
            // T2 local invalidation: only the old and new focus rings need a
            // repaint (no whole-window Invalidate).
            InvalidateElement(previous);
            InvalidateElement(element);
        }

        void VgwwWindow::SyncDialogFocus() {
            // batch27 P1-14: a modal opens with the keyboard on the SAFE
            // button - Cancel when the dialog has one, otherwise the first
            // focusable control (a single-button message box). Never steals
            // focus from a control that is already inside the dialog (a form
            // field the user tabbed to stays focused).
            Element* dialog = FindOpenDialog();
            if (dialog == nullptr) {
                return;
            }
            if (focused_ != nullptr && ElementInTree(dialog, focused_) &&
                focused_->visible && focused_->enabled) {
                return;
            }
            // batch320: remember where focus came from so closing the modal
            // returns the keyboard there. Only an element OUTSIDE the dialog
            // is a restore target; focus already inside the dialog is the
            // dialog's own and must not overwrite the saved opener.
            if (focused_ == nullptr || !ElementInTree(dialog, focused_)) {
                focus_before_dialog_ =
                    (focused_ != nullptr && ElementInTree(root_, focused_) &&
                     focused_->visible && focused_->enabled)
                        ? focused_
                        : nullptr;
            }
            const std::vector<Element*> chain = FocusChain(*dialog);
            if (chain.empty()) {
                return;
            }
            Element* safe = chain.front();
            for (Element* candidate : chain) {
                if (candidate->id == "dialog.cancel") {
                    safe = candidate;
                    break;
                }
            }
            SetFocusElement(safe);
        }

        void VgwwWindow::RestoreFocusAfterDialogClosed() {
            if (focus_before_dialog_ == nullptr) {
                return;
            }
            if (FindOpenDialog() != nullptr) {
                return;  // another modal took over: keep the target for later
            }
            Element* target = focus_before_dialog_;
            focus_before_dialog_ = nullptr;
            // The opener may have been rebuilt or hidden while the modal was
            // open (page switch, language switch, a list refresh): never
            // resurrect focus on a dead element.
            if (!ElementInTree(root_, target) || !target->visible ||
                !target->enabled) {
                return;
            }
            SetFocusElement(target);
        }

        void VgwwWindow::CycleFocus(bool backward, Element* scope) {
            if (nullptr == scope) {
                scope = root_;
            }
            if (nullptr == scope) {
                return;
            }
            const std::vector<Element*> chain = FocusChain(*scope);
            if (chain.empty()) {
                SetFocusElement(nullptr);
                return;
            }
            // batch103: when nothing in this scope holds focus (a freshly
            // shown page, or focus dropped with the element), the next stop is
            // an ENTRY point, not "one past the first". The old code seeded
            // `index` to 0 in that case and then stepped, so the very first Tab
            // landed on chain[1] and chain[0] was unreachable until the cycle
            // wrapped. Shift+Tab from no focus is the mirror: it wraps to the
            // last stop.
            const auto it = std::find(chain.begin(), chain.end(), focused_);
            if (it == chain.end()) {
                SetFocusElement(chain[backward ? chain.size() - 1 : 0]);
                return;
            }
            const size_t index = static_cast<size_t>(it - chain.begin());
            const size_t next =
                backward ? (index + chain.size() - 1) % chain.size()
                         : (index + 1) % chain.size();
            SetFocusElement(chain[next]);
        }

        // --- batch24 P0-3: IME composition routing ---------------------------
        // The window owns the IME context (WM_IME_*); the focused editor owns
        // the preedit/commit state. These entry points are what WndProc calls
        // after reading the composition strings, and what tests drive directly
        // (no real IME available headless).

        // The LanguagePicker keeps its in-popup search box as a private member,
        // NOT a tree child, so focused_ names the picker container rather than
        // the editor. While that search row is active, TextInput-specific window
        // paths (IME commit, caret phase, edit shortcuts, IME anchor) must
        // resolve to the internal editor. C9 (tests/test_ui.cpp:18039) forbids
        // pointing focused_ at the editor, so this read-only resolver is the
        // single choke point instead. search_active() gates it: OnFocus alone
        // does not hand the picker IME focus.
        TextInputElement* VgwwWindow::FocusedTextInput() {
            if (focused_ != nullptr && !ElementInTree(root_, focused_)) {
                focused_ = nullptr;
            }
            if (auto* picker = dynamic_cast<LanguagePicker*>(focused_)) {
                if (picker->search_active()) {
                    return picker->search_editor();
                }
            }
            return dynamic_cast<TextInputElement*>(focused_);
        }

        void VgwwWindow::ImeStartComposition() {
            if (focused_ != nullptr && !ElementInTree(root_, focused_)) {
                focused_ = nullptr;
            }
            auto* input = FocusedTextInput();
            if (input == nullptr) {
                return;
            }
            input->SetCompositionForTest(std::wstring(), 0);
            InvalidateLiveElement(focused_);
        }

        void VgwwWindow::ImeUpdateComposition(const std::wstring& composition,
                                              std::size_t caret) {
            if (focused_ != nullptr && !ElementInTree(root_, focused_)) {
                focused_ = nullptr;
            }
            auto* input = FocusedTextInput();
            if (input == nullptr) {
                return;
            }
            input->SetCompositionForTest(composition, caret);
            InvalidateLiveElement(focused_);
        }

        void VgwwWindow::ImeCommitResult(const std::wstring& result) {
            if (focused_ != nullptr && !ElementInTree(root_, focused_)) {
                focused_ = nullptr;
            }
            auto* input = FocusedTextInput();
            if (input == nullptr) {
                return;
            }
            const Rect before = KeyInvalidationBounds(focused_);
            input->CommitComposition(result);
            const Rect after = KeyInvalidationBounds(focused_);
            InvalidateRect(UnionRects(before, after));
        }

        void VgwwWindow::ImeEndComposition() {
            if (focused_ != nullptr && !ElementInTree(root_, focused_)) {
                focused_ = nullptr;
            }
            auto* input = FocusedTextInput();
            if (input == nullptr) {
                return;
            }
            input->ClearComposition();
            InvalidateLiveElement(focused_);
        }

        void VgwwWindow::PlaceImeWindows() {
            // batch104: same stale-pointer guard the four ImeXxx entry points
            // apply. A dialog close retires its subtree and the tick destroys
            // it, so focused_ could name freed memory - and this function
            // dynamic_casts it BEFORE the hwnd_ check, i.e. even headless.
            if (focused_ != nullptr && !ElementInTree(root_, focused_)) {
                focused_ = nullptr;
            }
            auto* input = FocusedTextInput();
            if (input == nullptr || hwnd_ == nullptr) {
                return;
            }
            HIMC ctx = ::ImmGetContext(hwnd_);
            if (ctx == nullptr) {
                return;
            }
            const Rect b = input->bounds();
            POINT anchor{static_cast<LONG>(b.x * scale_),
                         static_cast<LONG>((b.y + b.h) * scale_)};
            ::ClientToScreen(hwnd_, &anchor);
            COMPOSITIONFORM cform{};
            cform.dwStyle = CFS_POINT;
            cform.ptCurrentPos = anchor;
            ::ImmSetCompositionWindow(ctx, &cform);
            // Microsoft Pinyin (TSF) may keep its candidate on the default
            // screen corner unless every candidate list is anchored.
            for (DWORD i = 0; i < 4; ++i) {
                CANDIDATEFORM cand{};
                cand.dwIndex = i;
                cand.dwStyle = CFS_CANDIDATEPOS;
                cand.ptCurrentPos = anchor;
                ::ImmSetCandidateWindow(ctx, &cand);
            }
            ::ImmReleaseContext(hwnd_, ctx);
        }

        void VgwwWindow::OnCaretBlinkTick() noexcept {
            // Element focus drives the caret phase, not the OS keyboard focus:
            // the phase used to be dropped whenever ::GetFocus() != hwnd_ (a
            // console-launched or tray-restored window frequently fails to hold
            // keyboard focus), which froze the caret on a static line (G1/S1).
            // The window still only repaints the focused input's bounds.
            if (nullptr == hwnd_ || nullptr == focused_) {
                return;
            }
            // Same stale-pointer guard as RouteKey/SetFocusElement: a dialog
            // teardown may have destroyed the focused element.
            if (!ElementInTree(root_, focused_)) {
                focused_ = nullptr;
                return;
            }
            if (focused_->OnCaretBlinkTick()) {
                // Local invalidation: only the input box repaints, not the
                // whole window (S5.19 dirty-rect direction).
                InvalidateRect(focused_->bounds());
            }
        }

        void VgwwWindow::OnAnimationTimer() {
            // A tick may arrive after the clock self-stopped (the timer
            // message was already queued); ignore it so it cannot advance a
            // frame or bump the counter past the real animation lifetime (B-2).
            if (!animation_active_) {
                return;
            }
            using clock = std::chrono::steady_clock;
            const auto now = clock::now();
            const float dt =
                std::chrono::duration<float>(now - last_animation_time_).count();
            last_animation_time_ = now;
            OnAnimationTimerForTest(dt);
        }

        void VgwwWindow::OnAnimationTimerForTest(float dt_seconds) {
            // Core frame logic with an explicit dt; never reads the wall clock
            // and (being hwnd-agnostic through Stop/Request) never depends on a
            // window, so the frame ordering is headless-testable.
            float dt = dt_seconds;
            if (dt < 0.0f) {
                dt = 0.0f;
            }
            if (dt > 0.1f) {
                dt = 0.1f;  // clamp: no jump after a drag/pause
            }
            ++animation_frames_;
            const bool active = AdvanceAnimations(dt);
            if (!active) {
                // Stop BEFORE the hook: a hook that starts a new animation
                // (RequestAnimationFrame) must not be swallowed by an active
                // flag that is about to be cleared, nor have its timer killed.
                StopAnimationFrame();
            }
            if (on_animation_frame) {
                on_animation_frame();
            }
        }

        bool VgwwWindow::AdvanceAnimations(float dt) {
            bool any = false;
            if (root_ != nullptr) {
                CollectAnimationActivity(root_, dt, any);
            }
            return any;
        }

        void VgwwWindow::CollectAnimationActivity(Element* node, float dt,
                                                  bool& any) {
            if (node == nullptr) {
                return;
            }
            // B3 (T7 confirmation): a hidden element is skipped - it is not
            // advanced and cannot mark `any`. This does NOT wrongly stop the
            // clock while OTHER visible elements still animate (they keep
            // `any` true), so a hidden subtree cannot freeze its siblings.
            // Residual (NOT fixed here): a hidden element that is the ONLY
            // animating one reports no activity, the clock self-stops, and a
            // later re-show does not re-request a frame - so its animation
            // stays where it was until unrelated input wakes it. There is no
            // unified Element::SetVisible hook to restart it (a global setter
            // is a framework change, out of T7 scope); recorded for follow-up.
            if (!node->visible) {
                return;
            }
            // Snapshot the children before AdvanceAnimation. The snapshot is
            // a framework-level tolerance contract: an element's
            // AdvanceAnimation MAY add or remove children in-frame
            // (`children_` is a vector of unique_ptr, so an in-place iterator
            // would dangle). No override does so today - StackPanel, Button,
            // ToastHost and DialogHost all advance scalars only - but the
            // snapshot plus a liveness guard below keep any future in-frame
            // child-table change from invalidating the walk.
            //
            // batch55: the guard used to be ElementInTree(root_, child), a
            // whole-tree DFS PER EDGE - O(N^2) for one frame over the whole
            // built tree (the router keeps every inactive page host in the
            // tree, and that DFS does not prune on `visible`). Measured on a
            // 1001-node chain: 501,500 node visits for ONE frame, on the 33 ms
            // animation clock that the dashboard's pulsing status dot keeps
            // running. batch56: the guard is now IsLiveElement(child), an O(1)
            // hash lookup on the pointer VALUE that never dereferences it - so
            // it answers "is this still an Element?" exactly as safely as the
            // DFS did, at O(1) instead of O(N).
            //
            // Semantics are the ORIGINAL snapshot semantics, deliberately:
            // the table is captured BEFORE the advances, so every pre-existing
            // child advances exactly once per frame and a child added in-frame
            // waits for the next frame (TestB56InFrameInsertionSemantics). An
            // index-based live-table walk is NOT equivalent: inserting at an
            // earlier index shifts an already-visited child into the next slot
            // (advanced twice) and pushes a tail survivor past the cap (never
            // advanced).
            //
            // Boundary (unchanged from the original shape, stated precisely):
            // an element that destroys ITSELF - which includes destroying any
            // ANCESTOR, since an ancestor owns the current node - during its own
            // AdvanceAnimation is NOT tolerated. The reason is the line right
            // after the call: `node->HasActiveAnimation()` (and the following
            // InvalidateLiveElement) read `node` again once its own advance has
            // returned, so a self-teardown is a use-after-free there. This is
            // exactly the pre-batch55 behaviour (which also read node after the
            // advance), i.e. no contract was narrowed. Note the DELETE-A-SIBLING
            // case is different and fully tolerated: the victim is never read
            // through its stored pointer, only checked with IsLiveElement.
            // No override does this today (DialogHost::Reset retires its subtree
            // into a queue instead of destroying it, and the sweep runs from
            // OnTick, never from inside this walk).
            // M8 (batch3): the snapshot lives in ONE reusable per-window
            // scratch buffer (water-level recursion) instead of a fresh
            // per-node vector, so after the first frames allocate nothing.
            const std::size_t base = anim_kids_scratch_.size();
            for (const auto& child : node->children()) {
                anim_kids_scratch_.push_back(child.get());
            }
            const std::size_t count = anim_kids_scratch_.size() - base;
            node->AdvanceAnimation(dt);
            if (node->HasActiveAnimation()) {
                any = true;
                // Local invalidation only: the animating element's bounds repaint
                // (a dirty rect, not a full window); a quiescent tree never
                // invalidates. batch55: liveness is structural here (we are
                // recursing down from root_), so this must not pay a tree DFS.
                // batch63: an element that reports no VISIBLE change this frame
                // keeps the clock but asks for no repaint (the default answers
                // true, so every pre-existing animation is unchanged).
                if (node->AnimationNeedsRepaint()) {
                    InvalidateLiveElement(node);
                }
            }
            for (std::size_t i = 0; i < count; ++i) {
                Element* child = anim_kids_scratch_[base + i];
                // Liveness guard: a sibling's AdvanceAnimation may have torn
                // this child down (its stored pointer is compared by value
                // only, never dereferenced). The child's own recursion restores
                // the buffer to its entry size, so [base, base + count) stays
                // valid here even when a deeper level reallocated the buffer.
                if (IsLiveElement(child)) {
                    CollectAnimationActivity(child, dt, any);
                }
            }
            anim_kids_scratch_.resize(base);
        }

        bool VgwwWindow::AnyActiveAnimation(const Element* node) const {
            // W11 G-1: mirrors CollectAnimationActivity's prune without any of
            // its side effects - hidden subtrees are skipped (a hidden animator
            // must not start the clock, B3 semantics) and nothing is advanced
            // or invalidated by this read-only probe.
            if (node == nullptr || !node->visible) {
                return false;
            }
            if (node->HasActiveAnimation()) {
                return true;
            }
            for (const auto& child : node->children()) {
                if (AnyActiveAnimation(child.get())) {
                    return true;
                }
            }
            return false;
        }

        bool VgwwWindow::AdvanceAnimationFrameForTest(float dt_seconds) {
            // Intentional: does not touch the OS timer or animation_frames_ so
            // headless tests exercise the pure frame-advance path only.
            return AdvanceAnimations(dt_seconds);
        }

        bool VgwwWindow::RouteKey(UINT message, WPARAM wparam) {
            if (nullptr == root_) {
                return false;
            }
            // Same stale-pointer guard as the hover cache (T6-F1 review I1):
            // Enter/Esc can close a dialog and destroy the focused element.
            if (focused_ != nullptr && !ElementInTree(root_, focused_)) {
                focused_ = nullptr;
            }
            // batch24 P0-3 (IME): VK_PROCESSKEY (0xE5) marks a key the IME is
            // currently processing. It must never reach the editor as a normal
            // key (the WM_IME_COMPOSITION messages carry the real edit); return
            // false so WndProc falls through to DefWindowProc/IME.
            if ((WM_KEYDOWN == message || WM_SYSKEYDOWN == message ||
                 WM_KEYUP == message || WM_SYSKEYUP == message) &&
                static_cast<uint32_t>(wparam) == 0xE5u) {
                return false;
            }
            // T7/I2: a consumed key can mutate a control's state (Segmented
            // selection, Checkbox toggle, Select expand, DialogHost Esc/Enter,
            // TextInput text/caret) with no mouse event behind it. RouteKey
            // used to leave the repaint to the caret-blink/debug channel.
            // The mutation geometry must be "before -> after": a modal close
            // sets the DialogHost visible=false and tears down its card, so
            // reading the *after* bounds would either be skipped (visible
            // guard) or read a collapsed Select box (popup dropped). RouteKey
            // therefore snapshots the target's bounds before OnKeyDown and
            // invalidates that union against the post-mutation bounds; when the target can
            // no longer be read (hidden/torn down) the pre-mutation snapshot
            // alone drives the local invalidation. Never a whole-window
            // Invalidate.
            const auto invalidate_rect = [this](const Rect& r) {
                if (r.w <= 0.0f || r.h <= 0.0f) {
                    return;
                }
                ++key_invalidations_;
                InvalidateRect(r);
            };
            const auto invalidate_change = [this, &invalidate_rect](
                                               Element* e, const Rect& old_r) {
                Rect r = old_r;
                if (e != nullptr && ElementInTree(root_, e) && e->visible) {
                    r = UnionRects(old_r, KeyInvalidationBounds(e));
                }
                invalidate_rect(r);
            };
            if (WM_KEYDOWN == message || WM_SYSKEYDOWN == message) {
                const uint32_t vk = static_cast<uint32_t>(wparam);
                // batch27 P1-14: a newly opened modal owns the keyboard - put
                // focus on its SAFE button before the first key is routed, so
                // Enter/Space act on the dialog instead of a page control that
                // still holds focus behind the mask. Tab is excluded: its own
                // branch below performs this first-entry step and then cycles
                // from there (otherwise the very first Tab would skip past the
                // safe button).
                if (VK_TAB != vk) {
                    SyncDialogFocus();
                }
                // batch26 P0: an expanded popup owns Esc. It closes the list
                // (and only the list) before any modal/dialog handling, so Esc
                // never performs a second, surprising exit on the same press.
                constexpr uint32_t kVkEscape = 0x1B;
                if (kVkEscape == vk && CollapseExpandedPopups(nullptr)) {
                    return true;
                }
                // batch33 E: an open context menu owns Esc too. The window asks
                // every overlay node in the top-layer order; the first that
                // consumes it closes only itself.
                if (kVkEscape == vk) {
                    RefreshOverlayCacheIfStale();
                    for (Element* node : overlay_nodes_) {
                        if (!OverlayVisibleChain(node)) {
                            continue;
                        }
                        auto* menu = dynamic_cast<ContextMenu*>(node);
                        if (menu == nullptr || !menu->open()) {
                            continue;
                        }
                        const Rect before = menu->invalidation_bounds();
                        if (menu->DismissOverlay()) {
                            const Rect after = menu->invalidation_bounds();
                            const Rect dirty = UnionRects(before, after);
                            if (dirty.w > 0.0f && dirty.h > 0.0f) {
                                InvalidateRect(dirty);
                            }
                            return true;
                        }
                    }
                }
                // batch321: while a context menu is open it owns the
                // navigation keys - a keyboard user drives the same row menu
                // a right click opens. Esc is handled above (DismissOverlay).
                {
                    RefreshOverlayCacheIfStale();
                    for (Element* node : overlay_nodes_) {
                        if (!OverlayVisibleChain(node)) {
                            continue;
                        }
                        auto* menu = dynamic_cast<ContextMenu*>(node);
                        if (menu == nullptr || !menu->open()) {
                            continue;
                        }
                        const Rect before = menu->invalidation_bounds();
                        if (menu->OnKeyDown(vk)) {
                            const Rect after = menu->invalidation_bounds();
                            invalidate_rect(UnionRects(before, after));
                            return true;
                        }
                        break;
                    }
                }
                // Modal dialogs get the key first (T3 handoff: Esc/Enter);
                // the dialog stays in scope so Tab can be scoped to it (U5).
                Element* dialog = FindOpenDialog();
                if (dialog != nullptr) {
                    // batch27 P1-14: Enter/Space belong to the FOCUSED button
                    // inside the dialog (that is what "focus lands on the safe
                    // button" is for). Only when no dialog button holds focus
                    // does the dialog itself act as the default (Enter=OK,
                    // Esc=cancel).
                    const bool is_activate = (VK_RETURN == vk || VK_SPACE == vk);
                    const bool focused_button_in_dialog =
                        is_activate && focused_ != nullptr &&
                        ElementInTree(dialog, focused_) &&
                        dynamic_cast<Button*>(focused_) != nullptr;
                    if (!focused_button_in_dialog) {
                        // Snapshot BEFORE OnKeyDown: Esc/Enter may Close/Reset
                        // the modal (visible -> false, card subtree torn down).
                        const Rect dialog_old = KeyInvalidationBounds(dialog);
                        if (dialog->OnKeyDown(vk)) {
                            invalidate_change(dialog, dialog_old);
                            return true;
                        }
                    }
                }
                // batch321: the keyboard's own context-menu gesture opens
                // the focused element's menu (the Menu key, or Shift+F10 -
                // the Windows convention). A modal owns the keyboard, so this
                // only runs when no dialog is open.
                if (dialog == nullptr && focused_ != nullptr) {
                    constexpr uint32_t kVkApps = 0x5Du;   // VK_APPS
                    constexpr uint32_t kVkF10 = 0x79u;    // VK_F10
                    const bool shift =
                        modifiers_injected_
                            ? (modifiers_override_ & 0x1u) != 0
                            : (::GetKeyState(VK_SHIFT) & 0x8000) != 0;
                    if (kVkApps == vk || (kVkF10 == vk && shift)) {
                        if (focused_->OpenContextMenuForKeyboard()) {
                            return true;
                        }
                    }
                }
                if (VK_TAB == vk) {
                    // batch322: Tab first dismisses every transient overlay (a
                    // row/context menu, an expanded select or language list).
                    // Without this the keyboard focus walked BEHIND an open
                    // overlay: Enter then activated a control the overlay was
                    // covering, and an expanded list kept floating over the page.
                    (void)CloseContextMenus();
                    (void)CollapseExpandedPopups(nullptr);
                    // U5: while a modal dialog is open, Tab cycles inside the
                    // dialog's subtree only - it must never escape to the
                    // masked page behind it. SetFocusElement already invalidates
                    // both the old and new focus rings. T8: a test-injected
                    // modifier mask overrides ::GetKeyState so Shift+Tab is
                    // deterministic headless.
                    const bool shift =
                        modifiers_injected_
                            ? (modifiers_override_ & 0x1u) != 0
                            : (::GetKeyState(VK_SHIFT) & 0x8000) != 0;
                    if (dialog != nullptr && (focused_ == nullptr ||
                                              !ElementInTree(dialog, focused_))) {
                        // batch27 P1-14: the first Tab enters the dialog on its
                        // SAFE button instead of a blind "first control".
                        SyncDialogFocus();
                    } else {
                        CycleFocus(shift, dialog);
                    }
                    return true;
                }
                // R3: clipboard shortcuts for a focused text field. Ctrl is
                // read from the injected mask (deterministic headless) or the
                // OS. Handled here because the window owns the OS clipboard.
                constexpr uint32_t kVkC = 0x43;  // 'C'
                constexpr uint32_t kVkX = 0x58;  // 'X'
                constexpr uint32_t kVkV = 0x56;  // 'V'
                constexpr uint32_t kVkA = 0x41;  // 'A'
                if (focused_ != nullptr) {
                    const bool ctrl =
                        modifiers_injected_
                            ? (modifiers_override_ & 0x2u) != 0
                            : (::GetKeyState(VK_CONTROL) & 0x8000) != 0;
                    if (ctrl) {
                        const Rect old_r = KeyInvalidationBounds(focused_);
                        bool handled = false;
                        if (kVkC == vk) {
                            // batch287: a recognized clipboard shortcut
                            // with a selection is OURS even when the write
                            // fails, so it cannot fall through to a
                            // destructive default handler.
                            const bool ok = focused_->CopySelectionToClipboard();
                            const bool had = focused_->HasTextSelection();
                            handled = ok || had;
                            if (!ok && had) {
                                NotifyClipboardFailed(false);
                            }
                        } else if (kVkX == vk) {
                            const bool ok = focused_->CutSelectionToClipboard();
                            const bool had = focused_->HasTextSelection();
                            handled = ok || had;
                            if (!ok && had) {
                                NotifyClipboardFailed(false);
                            }
                        } else if (kVkV == vk) {
                            const PasteResult r =
                                focused_->PasteFromClipboard();
                            handled = r == PasteResult::Pasted ||
                                      r == PasteResult::Failed;
                            if (r == PasteResult::Failed) {
                                NotifyClipboardFailed(true);
                            }
                        } else if (kVkA == vk) {
                            handled = focused_->SelectAllText();
                        }
                        if (handled) {
                            invalidate_change(focused_, old_r);
                            return true;
                        }
                    }
                }
                {
                    const bool shift =
                        modifiers_injected_
                            ? (modifiers_override_ & 0x1u) != 0
                            : (::GetKeyState(VK_SHIFT) & 0x8000) != 0;
                    const bool ctrl =
                        modifiers_injected_
                            ? (modifiers_override_ & 0x2u) != 0
                            : (::GetKeyState(VK_CONTROL) & 0x8000) != 0;
                    {
                        const Rect old_r =
                            focused_ != nullptr
                                ? KeyInvalidationBounds(focused_)
                                : Rect{};
                        bool classic = false;
                        if (focused_ != nullptr) {
                            if (ctrl && vk == 0x2D) {  // Ctrl+Insert = copy
                                const bool ok = focused_->CopySelectionToClipboard();
                                const bool had = focused_->HasTextSelection();
                                classic = ok || had;
                                if (!ok && had) {
                                    NotifyClipboardFailed(false);
                                }
                            } else if (shift && vk == 0x2D) {  // Shift+Insert
                                const PasteResult r =
                                    focused_->PasteFromClipboard();
                                classic = r == PasteResult::Pasted ||
                                          r == PasteResult::Failed;
                                if (r == PasteResult::Failed) {
                                    NotifyClipboardFailed(true);
                                }
                            } else if (shift && vk == 0x2E) {  // Shift+Delete
                                const bool ok = focused_->CutSelectionToClipboard();
                                const bool had = focused_->HasTextSelection();
                                classic = ok || had;
                                if (!ok && had) {
                                    NotifyClipboardFailed(false);
                                }
                            }
                        }
                        if (classic) {
                            invalidate_change(focused_, old_r);
                            return true;
                        }
                    }
                    if (auto* input = FocusedTextInput()) {
                        const Rect old_r = KeyInvalidationBounds(input);
                        bool handled = false;
                        if (ctrl && (vk == 0x5A || vk == 0x59)) {
                            handled = (vk == 0x5A) ? input->UndoEdit()
                                                   : input->RedoEdit();
                        } else if (ctrl && (vk == 0x25 || vk == 0x27)) {
                            handled = input->MoveCaretWord(vk, shift);
                        } else if (ctrl && (vk == 0x08 || vk == 0x2E)) {
                            handled = input->DeleteWord(vk);
                        } else if (shift &&
                                   (vk == 0x25 || vk == 0x27 || vk == 0x24 ||
                                    vk == 0x23)) {
                            handled = input->ExtendCaretKey(vk, ctrl);
                        }
                        if (handled) {
                            invalidate_change(input, old_r);
                            return true;
                        }
                    }
                }                if (focused_) {
                    Element* target = focused_;
                    // Snapshot BEFORE the mutation (e.g. Select collapse).
                    const Rect target_old = KeyInvalidationBounds(target);
                    if (target->OnKeyDown(vk)) {
                        // batch26 P0: opening another selector by keyboard
                        // keeps the one-popup invariant too.
                        if (dynamic_cast<SelectElement*>(target) != nullptr ||
                            dynamic_cast<LanguagePicker*>(target) != nullptr) {
                            CollapseExpandedPopups(target);
                        }
                        invalidate_change(target, target_old);
                        return true;
                    }
                }
                // batch33p (user: "no scrollbar - rely on the wheel and the
                // arrow keys"): nobody consumed the navigation key, so scroll
                // the container under the POINTER - the same container the
                // wheel would reach (RouteClientPointer's wheel bubble: the
                // nearest ScrollView/TableElement up the ancestor chain of the
                // hovered element). This is what makes the arrow keys work
                // without putting the viewport into the Tab chain. Only the
                // six scroll keys are considered; a text field that already
                // handled Left/Right/Home/End above never reaches this point.
                if (IsScrollKey(vk)) {
                    Element* anchor = HoveredForTest();
                    if (anchor == nullptr) {
                        anchor = focused_;
                    }
                    for (Element* e = anchor; e != nullptr; e = e->parent()) {
                        // batch34x: ask the element itself whether it scrolls
                        // from the keyboard instead of naming concrete types.
                        // The console log surface is neither a ScrollView nor a
                        // TableElement, so the old type check silently skipped
                        // it and the console could only be wheel-scrolled.
                        // batch34y: one predicate for "is this a scroll
                        // container" (see Element::IsScrollContainer).
                        if (!e->IsScrollContainer()) {
                            continue;
                        }
                        const Rect old_r = KeyInvalidationBounds(e);
                        if (e->OnKeyDown(vk)) {
                            invalidate_change(e, old_r);
                            return true;
                        }
                        break;  // nearest container declined: let it bubble out
                    }
                }
                return false;
            }
            if (WM_CHAR == message) {
                if (focused_) {
                    Element* target = focused_;
                    const Rect target_old = KeyInvalidationBounds(target);
                    if (target->OnChar(static_cast<wchar_t>(wparam))) {
                        // A consumed char edited the field: repaint its box
                        // now instead of waiting for the caret blink.
                        invalidate_change(target, target_old);
                        return true;
                    }
                }
            }
            if (WM_KEYUP == message || WM_SYSKEYUP == message) {
                // T8: key release. No control consumes a release today, so
                // this is a pipeline-only dispatch (dialog first, then the
                // focused element) that mirrors the WM_KEYDOWN routing.
                const uint32_t vk = static_cast<uint32_t>(wparam);
                Element* dialog = FindOpenDialog();
                if (dialog != nullptr && dialog->OnKeyUp(vk)) {
                    return true;
                }
                if (focused_ != nullptr && focused_->OnKeyUp(vk)) {
                    return true;
                }
                return false;
            }
            return false;
        }

        bool VgwwWindow::RouteClientPointer(UINT message, Point logical,
                                            int wheel_delta) {
            if (WM_MOUSEMOVE == message) {
                // While a button is held the captured element owns the move
                // (G2 drag-select in a text field); it must keep receiving the
                // pointer even when it leaves the element bounds.
                if (mouse_capture_ != nullptr &&
                    ElementInTree(root_, mouse_capture_)) {
                    // batch17 P2-a (audit H2): the captured drag repaints the
                    // captured element's region (before -> after union), not
                    // the whole window - the last remaining non-contract
                    // full-window invalidation. The widest(bounds,
                    // invalidation_bounds) box covers every capture producer:
                    // Table (whole table while resizing_), Select (box +
                    // popup), TextInput/Button/Segmented (own box). A
                    // non-visible or degenerate capture falls back to the
                    // previous full-window contract.
                    Element* capture = mouse_capture_;
                    const bool paintable = capture->visible;
                    const Rect pre =
                        paintable ? CaptureWidestBounds(capture) : Rect{};
                    capture->OnMouseMove(logical);
                    const Rect post =
                        paintable ? CaptureWidestBounds(capture) : Rect{};
                    const Rect dirty = UnionRects(pre, post);
                    if (dirty.w > 0.0f && dirty.h > 0.0f) {
                        InvalidateRect(dirty);
                    } else {
                        Invalidate();
                    }
                    return true;
                }
                DispatchHoverMove(HitTestTopmost(logical), logical);
                return true;
            }
            if (WM_MOUSEWHEEL == message) {
                // batch323: an open row/context menu owns the wheel. The card
                // is anchored to a row in CLIENT coordinates, so scrolling the
                // page behind it slides that row away and leaves the menu
                // pointing at unrelated content. Native menus ignore the wheel
                // for the same reason: consume it (no scroll, no dismissal).
                {
                    RefreshOverlayCacheIfStale();
                    for (Element* node : overlay_nodes_) {
                        auto* menu = dynamic_cast<ContextMenu*>(node);
                        if (menu != nullptr && menu->open() &&
                            OverlayVisibleChain(node)) {
                            return true;
                        }
                    }
                }
                bool consumed = false;
                Element* hit = HitTestTopmost(logical);
                if (hit != nullptr) {
                    consumed = hit->OnWheel(wheel_delta);
                }
                // B13 (batch13, 2026-10-16): an unconsumed wheel bubbles up to
                // the NEAREST scroll container (ScrollView/TableElement - the
                // same classes the repaint lookup below resolves from `hit`).
                // A control on top of a scrollable page (Select/TextInput/
                // Button/Checkbox/...) must not swallow the page scroll. The
                // walk starts at hit->parent() (hit's own OnWheel just ran)
                // and stops at the first container: both container classes
                // only decline a zero delta, which any outer ancestor would
                // decline too.
                //
                // The bubbling container C and the invalidation lookup's
                // "first container above hit" are provably the SAME object:
                // one predicate (Element::IsScrollContainer)
                // over one ancestor chain, first hit in both walks. Cases:
                // (1) hit is not a container - the bubble starts at
                // hit->parent() and the lookup at hit; the first hit is
                // identical (hit's own cast misses); (2) hit is a container
                // and consumed - no bubble, the lookup starts at hit, C==hit;
                // (3) hit is a container and declined - only possible for
                // delta==0, so nothing repaints either way; (4) nested
                // containers - both walks take the nearest. Premises: (a) the
                // same predicate on the same chain; (b) OnWheel never edits
                // the topology (ScrollView/TableElement::SetOffset only
                // InvalidateLayout + Arrange, never Add/remove); (c) the
                // invalidation guard below (ElementInTree(root_, container)
                // && visible) already covers a future retired/re-reset
                // container. Hence the invalidation semantics below (R4c
                // container box / M2b subtree-relative overlay / no global
                // HasVisibleOverlay) carry over UNCHANGED for the bubble.
                if (!consumed && hit != nullptr) {
                    for (Element* e = hit->parent(); e != nullptr;
                         e = e->parent()) {
                        if (e->IsScrollContainer()) {
                            consumed = e->OnWheel(wheel_delta);
                            break;
                        }
                    }
                }
                // batch27 P0-3: a page scroll moves the content under an open
                // Select popup. While the trigger is still on screen the list
                // follows it (batch11 M2b keeps that path repainting the whole
                // window). Once the trigger has scrolled COMPLETELY out of its
                // container, the clamped list would float detached over
                // unrelated content - dismiss it instead of stranding it.
                if (consumed) {
                    RefreshOverlayCacheIfStale();
                    for (Element* node : overlay_nodes_) {
                        auto* select = dynamic_cast<SelectElement*>(node);
                        if (select == nullptr || !select->expanded() ||
                            !OverlayVisibleChain(node)) {
                            continue;
                        }
                        const Rect box = select->bounds();
                        bool intersects_viewport = true;
                        for (Element* p = select->parent(); p != nullptr;
                             p = p->parent()) {
                            if (!p->IsScrollContainer()) {
                                continue;
                            }
                            const Rect vp = p->bounds();
                            const float x0 = std::max(box.x, vp.x);
                            const float y0 = std::max(box.y, vp.y);
                            const float x1 = std::min(box.x + box.w, vp.x + vp.w);
                            const float y1 = std::min(box.y + box.h, vp.y + vp.h);
                            intersects_viewport = x1 > x0 && y1 > y0;
                            break;
                        }
                        if (!intersects_viewport) {
                            CollapseExpandedPopups(nullptr);
                            break;
                        }
                    }
                }
                // Perf (U1-D4) / W11 batch9 (R4c): a wheel repaints ONLY when
                // the hit element (or the nearest scroll-container ancestor)
                // actually consumed it, and only the SCROLLING
                // CONTAINER's viewport - never the whole window. The hit is
                // usually a content child inside the ScrollView/Table; that
                // child's own bounds may be smaller than the viewport, so
                // invalidating only the child would leave a scroll ghost. Walk
                // up to the nearest ScrollView/Table and repaint its full
                // bounds() - the whole scrolled viewport. NOTE: this must use
                // the raw box, NOT InvalidateElement's invalidation_bounds():
                // a Table's override reports only the hovered row band (a
                // hover repaint hint), and a scroll shifts every row, so the
                // band left the rest of the viewport stale (R4c ghost). Falls
                // back to the hit element's own invalidation_bounds() for a
                // non-container wheel consumer, then to a full repaint only if
                // neither the hit element nor the nearest scroll-container
                // ancestor consumed the wheel.
                //
                // batch11 M12 M2b (F1): the ONE exception - when the scrolled
                // container's subtree contains a visible overlay (an expanded
                // Select popup moves with the content via SetOffset's
                // re-arrange), the frame invalidates the WHOLE window: the
                // viewport-only repaint would ghost the popup's out-of-
                // viewport old pixels and miss its new ones. The check is
                // subtree-relative (see SubtreeHasVisibleOverlay), so a Table
                // scroll stays local even when an unrelated Select elsewhere
                // on the page is expanded.
                if (consumed) {
                    Element* container = nullptr;
                    for (Element* e = hit; e != nullptr; e = e->parent()) {
                        if (e->IsScrollContainer()) {
                            container = e;
                            break;
                        }
                    }
                    if (container != nullptr) {
                        // Mirror InvalidateElement's live-visible guard: only
                        // a live, visible, non-degenerate box repaints.
                        if (ElementInTree(root_, container) &&
                            container->visible) {
                            const Rect box = container->bounds();
                            if (box.w > 0.0f && box.h > 0.0f) {
                                if (SubtreeHasVisibleOverlay(container)) {
                                    Invalidate();  // M2b: overlay moved
                                } else {
                                    InvalidateRect(box);
                                }
                            }
                        }
                    } else if (hit != nullptr) {
                        InvalidateElement(hit);
                    } else {
                        Invalidate();
                    }
                }
                return consumed;
            }
            if (WM_RBUTTONDOWN == message) {
                // batch33 E: a right press only prepares - it closes whatever
                // popup/menu is open and puts keyboard focus on the target.
                // The menu itself opens on the RELEASE (standard behaviour: a
                // right-drag does not spawn a menu).
                CloseContextMenus();
                DismissExpandedPopupsOutside(logical);
                Element* hit = HitTestTopmost(logical);
                if (hit != nullptr) {
                    Element* focus_target = hit;
                    while (focus_target != nullptr &&
                           !focus_target->focusable()) {
                        focus_target = focus_target->parent();
                    }
                    if (focus_target != nullptr) {
                        SetFocusElement(focus_target);
                    }
                }
                return hit != nullptr;
            }
            if (WM_RBUTTONUP == message) {
                // batch33 E: right-up opens a row's context menu. The hit gets
                // the first chance; an unconsumed event bubbles up the parent
                // chain so a nested cell still reaches its table.
                Element* hit = HitTestTopmost(logical);
                bool consumed = false;
                Element* consumer = nullptr;
                for (Element* e = hit; e != nullptr; e = e->parent()) {
                    if (e->OnMouseRightUp(logical)) {
                        consumed = true;
                        consumer = e;
                        break;
                    }
                }
                if (consumer != nullptr) {
                    InvalidateElement(consumer);
                }
                if (!consumed) {
                    // batch37o: a right click on a text surface (TextInput or
                    // the read-only console) opens the standard edit menu.
                    for (Element* e = hit; e != nullptr; e = e->parent()) {
                        if (e->EditMenuTarget()) {
                            ShowEditContextMenu(e, logical);
                            consumed = true;
                            break;
                        }
                    }
                }
                // A context menu that just opened needs an immediate repaint of
                // its whole capture surface (it is not in the content pass).
                if (consumed) {
                    RefreshOverlayCacheIfStale();
                    for (Element* node : overlay_nodes_) {
                        auto* menu = dynamic_cast<ContextMenu*>(node);
                        if (menu != nullptr && menu->open() &&
                            OverlayVisibleChain(node)) {
                            InvalidateElement(menu);
                        }
                    }
                }
                return consumed;
            }
            if (WM_LBUTTONDBLCLK == message) {
                // batch37e: standard list-view double-click. Windows sends
                // WM_LBUTTONDBLCLK instead of the second WM_LBUTTONDOWN, so the
                // second press never starts a drag; here it drives controls
                // that opt in (table header auto-fit).
                Element* hit = HitTestTopmost(logical);
                if (hit != nullptr && hit->OnMouseDoubleClick(logical)) {
                    // The control re-resolved its internals; repaint now (G5).
                    Invalidate();
                    return true;
                }
                return hit != nullptr;
            }
            if (WM_LBUTTONDOWN == message) {
                // batch26 P0: dismiss any open popup the click misses BEFORE
                // routing, so the same click still reaches the clicked
                // control (standard two-click behaviour: outside click closes
                // the list and activates what was clicked). Hit testing runs
                // after the collapse because the removed popup changes it.
                DismissExpandedPopupsOutside(logical);
                // batch34k P0: a real left click outside the card dismisses
                // the menu. Hit testing is a pure query now, so this is the
                // ONE place the "click outside closes" contract lives.
                DismissContextMenuOutside(logical);
                Element* hit = HitTestTopmost(logical);
                mouse_capture_ = hit;
                if (hit) {
                    Element* focus_target = hit;
                    while (focus_target != nullptr &&
                           !focus_target->focusable()) {
                        focus_target = focus_target->parent();
                    }
                    if (focus_target) {
                        SetFocusElement(focus_target);
                    }
                    // batch37n: Shift+click extends the text selection from
                    // the existing anchor (OS Edit).
                    const bool shift_click =
                        modifiers_injected_
                            ? (modifiers_override_ & 0x1u) != 0
                            : (::GetKeyState(VK_SHIFT) & 0x8000) != 0;
                    if (shift_click) {
                        if (auto* input =
                                dynamic_cast<TextInputElement*>(hit)) {
                            input->ExtendSelectionTo(logical);
                            Invalidate();
                            return true;
                        }
                    }
                    hit->OnMouseDown(logical);
                }
                // A click can toggle a checkbox/expand a select without
                // changing focus; repaint now, not on the next tick (G5).
                Invalidate();
                return hit != nullptr;
            }
            if (WM_LBUTTONUP == message) {
                Element* hit = HitTestTopmost(logical);
                Element* target = mouse_capture_;
                if (target != nullptr && !ElementInTree(root_, target)) {
                    target = nullptr;  // the tree changed under the press
                }
                if (!target) {
                    target = hit;
                }
                mouse_capture_ = nullptr;
                if (target) {
                    target->OnMouseUp(logical);
                }
                // batch332 P1: a release that reaches us must end EVERY
                // in-flight drag, not just the captured element's. When the
                // press element was lost (capture dropped, tree rebuilt) the
                // release routes elsewhere and the original control would keep
                // resizing / extending on later hovers. CancelDrag is a no-op
                // for a control that already cleared its own state above.
                CancelDragsIn(root_);
                Invalidate();  // button release / drag end must repaint (G5)
                return target != nullptr;
            }
            return false;
        }

        void VgwwWindow::RouteMouse(UINT message, int px, int py,
                                    int wheel_delta) {
            if (nullptr == root_ || nullptr == hwnd_) {
                return;
            }
            const Point logical{px / scale_, py / scale_};
            if (WM_MOUSEMOVE == message) {
                ArmClientLeaveTracking();
                // While a button is held the captured element owns the move
                // (G2 drag-select in a text field); it must keep receiving the
                // pointer even when it leaves the element bounds.
                if (mouse_capture_ != nullptr &&
                    ElementInTree(root_, mouse_capture_)) {
                    RouteClientPointer(message, logical, wheel_delta);
                    return;
                }
                if (caption_hover_.Update(CaptionButtonRect(0),
                                          CaptionButtonRect(1),
                                          CaptionButtonRect(2), logical)) {
                    // T2: only the caption buttons repaint, not the window.
                    for (int i = 0; i < 3; ++i) {
                        InvalidateRect(CaptionButtonRect(i));
                    }
                }
                if (logical.y < titlebar_h_) {
                    DispatchHoverMove(nullptr, logical);  // clear element hover
                    return;  // the title bar is non-client (HTCAPTION)
                }
                RouteClientPointer(message, logical, wheel_delta);
                return;
            }
            if (logical.y < titlebar_h_) {
                if (WM_LBUTTONDOWN == message) {
                    // batch26 P0: the title-bar band is outside every client
                    // popup; a click there dismisses an open list as well.
                    CollapseExpandedPopups(nullptr);
                }
                if (WM_LBUTTONUP == message) {
                    // batch31 P0-3: the three-button strip owns the click; a
                    // miss on the strip is a plain title-bar click (drag).
                    HandleCaptionButtonClick(logical);
                }
                return;
            }
            RouteClientPointer(message, logical, wheel_delta);
        }

        bool VgwwWindow::RouteMouseForTest(UINT message, Point logical,
                                           int wheel_delta) {
            if (nullptr == root_) {
                return false;  // mirrors RouteMouse's root_ guard; Invalidate()
                               // is itself a guarded no-op without hwnd_
            }
            return RouteClientPointer(message, logical, wheel_delta);
        }

        RECT InvalidateRectPixels(const Rect& logical, float scale) noexcept {
            const float x0 = logical.x * scale;
            const float y0 = logical.y * scale;
            const float x1 = (logical.x + logical.w) * scale;
            const float y1 = (logical.y + logical.h) * scale;
            RECT physical{};
            physical.left = static_cast<LONG>(std::floor(x0)) - 1;
            physical.top = static_cast<LONG>(std::floor(y0)) - 1;
            physical.right = static_cast<LONG>(std::ceil(x1)) + 1;
            physical.bottom = static_cast<LONG>(std::ceil(y1)) + 1;
            return physical;
        }

        bool ShouldFullClear(bool target_recreated, bool app_triggered,
                             const RECT& rcPaint, const RECT& client) noexcept {
            // T3: system distribution of WM_PAINT (exposure / occlusion
            // restore) without any pending app invalidation means the retained
            // buffer may have been discarded, so a partial clear could leave a
            // stale ghost - force the full-clear path. An app-triggered paint
            // whose dirty region stays strictly inside the client is safe to
            // clear locally.
            //
            // NOTE (batch2 spec, X-T2): this "reaches the client edge" rule is
            // deliberately NOT the cull intersection predicate. It decides
            // CLEAR scope (<= / >= inclusive edges), while RenderCtx::CulledOut
            // uses the half-open Rect::Intersects (element.h). Keeping them
            // separate is intentional: an edge-dirty paint must still clear the
            // full client, whereas culling must stay half-open so a cull rect
            // that merely touches an element's bottom edge does not drop it.
            if (target_recreated || !app_triggered) {
                return true;
            }
            return rcPaint.left <= 0 || rcPaint.top <= 0 ||
                   rcPaint.right >= client.right ||
                   rcPaint.bottom >= client.bottom;
        }

        std::uint64_t& ElementInTreeVisitCount() noexcept {
            static std::uint64_t visits = 0;
            return visits;
        }

        void MarkLiveDirtyElements(
            const Element* node,
            const std::unordered_set<const Element*>& wanted,
            std::unordered_set<const Element*>& live) noexcept {
            if (nullptr == node || live.size() >= wanted.size()) {
                return;  // everything found, or nothing to walk
            }
            if (wanted.count(node) != 0) {
                live.insert(node);
            }
            for (const auto& child : node->children()) {
                MarkLiveDirtyElements(child.get(), wanted, live);
            }
        }

        bool ElementInTree(const Element* root, const Element* needle) noexcept {
            ++ElementInTreeVisitCount();
            if (nullptr == root || nullptr == needle) {
                return false;
            }            if (root == needle) {
                return true;
            }
            for (const auto& child : root->children()) {
                if (ElementInTree(child.get(), needle)) {
                    return true;
                }
            }
            return false;
        }

        bool HoverTarget::Validate(const Element* root) noexcept {
            if (nullptr == element_) {
                return false;
            }
            if (!ElementInTree(root, element_)) {
                element_ = nullptr;  // stale (subtree destroyed): drop by value
                return false;
            }
            return true;
        }

        bool CaptionHover::Update(const Rect& minimize_rect,
                                  const Rect& maximize_rect,
                                  const Rect& close_rect,
                                  Point logical) noexcept {
            const bool over_minimize = minimize_rect.Contains(logical);
            const bool over_maximize = maximize_rect.Contains(logical);
            const bool over_close = close_rect.Contains(logical);
            if (over_minimize == minimize && over_maximize == maximize &&
                over_close == close) {
                return false;
            }
            minimize = over_minimize;
            maximize = over_maximize;
            close = over_close;
            return true;
        }

        bool CaptionHover::Clear() noexcept {
            if (!minimize && !maximize && !close) {
                return false;
            }
            minimize = false;
            maximize = false;
            close = false;
            return true;
        }

        void VgwwWindow::ArmClientLeaveTracking() noexcept {
            if (tracking_client_leave_ || nullptr == hwnd_) {
                return;
            }
            TRACKMOUSEEVENT track{};
            track.cbSize = sizeof(track);
            track.dwFlags = TME_LEAVE;
            track.hwndTrack = hwnd_;
            if (FALSE != ::TrackMouseEvent(&track)) {
                tracking_client_leave_ = true;
            }
        }

        void VgwwWindow::ArmNcLeaveTracking() noexcept {
            if (tracking_nc_leave_ || nullptr == hwnd_) {
                return;
            }
            TRACKMOUSEEVENT track{};
            track.cbSize = sizeof(track);
            track.dwFlags = TME_LEAVE | TME_NONCLIENT;
            track.hwndTrack = hwnd_;
            if (FALSE != ::TrackMouseEvent(&track)) {
                tracking_nc_leave_ = true;
            }
        }

        void VgwwWindow::DispatchHoverMove(Element* hit, Point logical) {
            // T6-F1 review I1: the cached target may have been destroyed since
            // the last move (DialogHost::Reset clears its subtree); validate
            // by pointer value before any dereference.
            hover_.Validate(root_);
            Element* previous = hover_.get();
            if (hit == previous) {
                if (hit != nullptr) {
                    // U1-D3/W11-G3: a nested hover target (e.g. a Table row)
                    // changes its own sub-hover state on move while the
                    // topmost element stays the same; OnMouseMove returns true
                    // exactly when the element wants a repaint. The repaint
                    // region must cover the state BEFORE and AFTER the call: a
                    // table's invalidation_bounds() switches from the old row
                    // band to the new one inside OnMouseMove, so reading it
                    // only afterwards (the pre-batch6 code) left the old
                    // band's highlight on screen - the "hover ghost". Capture
                    // the pre snapshot, run the move, then invalidate their
                    // union in one call.
                    const Rect pre = hit->invalidation_bounds();
                    if (hit->OnMouseMove(logical)) {
                        if (ElementInTree(root_, hit) && hit->visible) {
                            // Mirror InvalidateElement's live-visible guard;
                            // an OnMouseMove side effect may have detached
                            // the element. The pre snapshot stays valid then.
                            const Rect post = hit->invalidation_bounds();
                            const Rect dirty = UnionRects(pre, post);
                            if (dirty.w > 0.0f && dirty.h > 0.0f) {
                                InvalidateRect(dirty);
                            }
                        } else if (pre.w > 0.0f && pre.h > 0.0f) {
                            InvalidateRect(pre);
                        }
                    }
                }
                UpdateHoverTooltip(hit, logical);
                return;
            }
            // Target changed: the old element's hover state resets and the new
            // one's lights up, so both need a repaint now (G5) - waiting for
            // the data tick made hover feel laggy.
            if (previous != nullptr) {
                // A far-away point leaves every element's bounds, so row
                // hover state resets (T6 review M5).
                previous->OnMouseMove(Point{-1.0e6f, -1.0e6f});
            }
            hover_.Set(hit);
            if (hit != nullptr) {
                hit->OnMouseMove(logical);
            }
            // T2 local invalidation: only the old and new hovered elements
            // repaint (old -> new region only), never the whole window.
            InvalidateElement(previous);
            InvalidateElement(hit);
            UpdateHoverTooltip(hit, logical);
        }

        Rect VgwwWindow::HoverTooltipBox(const std::wstring& text,
                                         Point anchor) const {
            if (text.empty() || root_ == nullptr) {
                return Rect{0.0f, 0.0f, 0.0f, 0.0f};
            }
            constexpr float kMaxTextW = 380.0f;
            constexpr float kPadX = 9.0f;
            constexpr float kPadY = 7.0f;
            const Size measured =
                MeasureText(text, FontToken::Small, kMaxTextW);
            const float w = std::min(measured.w, kMaxTextW) + 2.0f * kPadX;
            const float h = measured.h + 2.0f * kPadY;
            const Rect client = root_->bounds();
            float x = anchor.x + 14.0f;
            float y = anchor.y + 20.0f;
            if (client.w > w) {
                x = std::min(std::max(x, 4.0f), client.w - w - 4.0f);
            }
            if (client.h > h) {
                y = std::min(std::max(y, 4.0f), client.h - h - 4.0f);
            }
            return Rect{x, y, w, h};
        }

        void VgwwWindow::UpdateHoverTooltip(Element* hit, Point logical) {
            std::wstring text;
            if (hit != nullptr && ElementInTree(root_, hit) && hit->visible) {
                // batch28: an explicit tooltip (e.g. the full adapter device
                // path behind a shortened diagnostic line) wins over the
                // truncation-derived one.
                text = hit->tooltip();
                if (text.empty()) {
                    text = hit->tooltip_text(logical);
                }
            }
            // batch37b: the tooltip follows the current hover (user report:
            // freezing the anchor when the text was unchanged left the box on
            // an older row). Repainting only the union of the OLD and NEW
            // boxes keeps it local - no full-window flicker and no ghost.
            if (text == hover_tooltip_ && logical.x == hover_tooltip_point_.x &&
                logical.y == hover_tooltip_point_.y) {
                return;
            }
            const Rect old_box =
                HoverTooltipBox(hover_tooltip_, hover_tooltip_point_);
            hover_tooltip_ = std::move(text);
            hover_tooltip_point_ = logical;
            const Rect new_box =
                HoverTooltipBox(hover_tooltip_, hover_tooltip_point_);
            if (new_box.x == old_box.x && new_box.y == old_box.y &&
                new_box.w == old_box.w && new_box.h == old_box.h) {
                return;
            }
            const Rect dirty = UnionRects(old_box, new_box);
            if (dirty.w > 0.0f && dirty.h > 0.0f) {
                InvalidateRect(dirty);
            }
        }

        void VgwwWindow::DrawHoverTooltip(RenderCtx& ctx) {
            if (hover_tooltip_.empty() || root_ == nullptr) {
                return;
            }
            constexpr float kPadX = 9.0f;
            constexpr float kPadY = 7.0f;
            const Rect box =
                HoverTooltipBox(hover_tooltip_, hover_tooltip_point_);
            ctx.FillRoundedRect(box, g_theme.radius_sm,
                                ColorFor(ColorToken::PanelAlt));
            ctx.StrokeRoundedRect(box, g_theme.radius_sm,
                                  ColorFor(ColorToken::InputBorder), 1.0f);
            ctx.DrawText(hover_tooltip_,
                         Rect{box.x + kPadX, box.y + kPadY,
                              std::max(box.w - 2.0f * kPadX, 0.0f),
                              std::max(box.h - 2.0f * kPadY, 0.0f)},
                         FontToken::Small, ColorFor(ColorToken::Text));
        }

        void VgwwWindow::ClearHover() {
            if (caption_hover_.Clear()) {
                // T2: the caption buttons, not the whole window, repaint.
                for (int i = 0; i < 3; ++i) {
                    InvalidateRect(CaptionButtonRect(i));
                }
            }
            hover_.Validate(root_);
            if (Element* target = hover_.get()) {
                target->OnMouseMove(Point{-1.0e6f, -1.0e6f});
                hover_.Set(nullptr);
                InvalidateElement(target);
            }
            if (!hover_tooltip_.empty()) {
                // batch37: repaint only the stale tooltip box, never the
                // whole window (see UpdateHoverTooltip).
                const Rect box =
                    HoverTooltipBox(hover_tooltip_, hover_tooltip_point_);
                hover_tooltip_.clear();
                if (box.w > 0.0f && box.h > 0.0f) {
                    InvalidateRect(box);
                }
            }
        }

        Element* VgwwWindow::HoverMoveForTest(Point logical) {
            DispatchHoverMove(HitTestTopmost(logical), logical);
            return hover_.get();
        }

        Element* VgwwWindow::HoveredForTest() const noexcept {
            Element* e = hover_.get();
            if (e == nullptr) {
                return nullptr;
            }
            // Never hand back a pointer a subtree teardown left dangling;
            // compare by value (T6-F1 review I1) without clearing the cache
            // from a const read (the next DispatchHoverMove will drop it).
            return ElementInTree(root_, e) ? e : nullptr;
        }

        LRESULT VgwwWindow::WndProc(HWND hwnd, UINT message, WPARAM wparam,
                                    LPARAM lparam) {
            if (tray::HandleWindowMessage(hwnd, message, wparam, lparam)) {
                return 0;
            }
            switch (message) {
                case WM_NCCALCSIZE: {
                    // Return 0 for both wParam values: TRUE = the whole window
                    // is client area (custom caption); FALSE = the proposed
                    // client rect stays unmodified (no non-client area).
                    if (wparam && ::IsZoomed(hwnd)) {
                        // A maximized window keeps the monitor work area so
                        // the taskbar stays visible.
                        auto* params =
                            reinterpret_cast<NCCALCSIZE_PARAMS*>(lparam);
                        MONITORINFO monitor{};
                        monitor.cbSize = sizeof(monitor);
                        if (::GetMonitorInfoW(
                                ::MonitorFromWindow(
                                    hwnd, MONITOR_DEFAULTTONEAREST),
                                &monitor)) {
                            params->rgrc[0] = monitor.rcWork;
                        }
                    }
                    return 0;
                }
                case WM_NCHITTEST: {
                    const POINT screen{
                        static_cast<short>(LOWORD(lparam)),
                        static_cast<short>(HIWORD(lparam))};
                    return HitTestNonClient(screen);
                }
                case WM_NCLBUTTONDBLCLK: {
                    // batch31 P0-3: a double click on the title bar toggles
                    // maximize/restore. Handled explicitly (never delegated to
                    // DefWindowProc's default, which would only maximize and
                    // could not be observed by the headless seams). A double
                    // click on a caption button is swallowed: that region has
                    // button semantics, not title-bar semantics.
                    POINT pt{static_cast<short>(LOWORD(lparam)),
                             static_cast<short>(HIWORD(lparam))};
                    ::ScreenToClient(hwnd, &pt);
                    const Point logical{pt.x / scale_, pt.y / scale_};
                    if (HandleTitlebarDoubleClick(logical)) {
                        return 0;
                    }
                    break;
                }
                case WM_GETMINMAXINFO: {
                    auto* info = reinterpret_cast<MINMAXINFO*>(lparam);
                    info->ptMinTrackSize.x = static_cast<LONG>(
                        DarkTheme().min_window.w * scale_);
                    info->ptMinTrackSize.y = static_cast<LONG>(
                        DarkTheme().min_window.h * scale_);
                    return 0;
                }
                case kActivateMessage: {
                    // batch20 P3 rework: a second launch asked us to surface
                    // (we may be hidden in the tray). The measured failure had
                    // visibility restored but the foreground NOT taken, so use
                    // the full window-manager ladder rather than a lone
                    // SetForegroundWindow.
                    //
                    // batch25b: SW_SHOW does not clear the minimized state, so
                    // a minimized instance must be restored first. A tray
                    // instance is simply hidden and still takes SW_SHOW.
                    if (::IsIconic(hwnd)) {
                        ::ShowWindow(hwnd, SW_RESTORE);
                    } else {
                        ::ShowWindow(hwnd, SW_SHOW);
                    }
                    ::SetWindowPos(hwnd, HWND_TOP, 0, 0, 0, 0,
                                   SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW);
                    ::BringWindowToTop(hwnd);
                    if (!::SetForegroundWindow(hwnd) ||
                        ::GetForegroundWindow() != hwnd) {
                        // The foreground lock (another app owns the input
                        // queue) can reject the transfer. Share this window
                        // thread's input queue with the current foreground
                        // thread and retry once; detach on every path below
                        // (there is no early return/throw between attach and
                        // detach).
                        const HWND foreground = ::GetForegroundWindow();
                        DWORD foreground_thread = 0;
                        if (foreground != nullptr) {
                            foreground_thread =
                                ::GetWindowThreadProcessId(foreground, nullptr);
                        }
                        const DWORD this_thread = ::GetCurrentThreadId();
                        bool attached = false;
                        if (foreground_thread != 0 &&
                            foreground_thread != this_thread) {
                            attached = ::AttachThreadInput(
                                           this_thread, foreground_thread,
                                           TRUE) != FALSE;
                        }
                        ::SetForegroundWindow(hwnd);
                        ::SetActiveWindow(hwnd);
                        if (attached) {
                            ::AttachThreadInput(this_thread, foreground_thread,
                                                FALSE);
                        }
                    } else {
                        ::SetActiveWindow(hwnd);
                    }
                    // P3: in an automated session (no user input) the
                    // foreground right cannot transfer; flash the taskbar so
                    // the operator still notices. The real double-click path
                    // is verified on a live desktop.
                    if (::GetForegroundWindow() != hwnd) {
                        FLASHWINFO info{};
                        info.cbSize = sizeof(info);
                        info.hwnd = hwnd;
                        info.dwFlags = FLASHW_TRAY | FLASHW_TIMERNOFG;
                        info.uCount = 0;
                        ::FlashWindowEx(&info);
                    }
                    return 0;
                }
                case WM_DPICHANGED: {
                    const float new_dpi = static_cast<float>(HIWORD(wparam));
                    const RECT* suggested =
                        reinterpret_cast<const RECT*>(lparam);
                    // P1: ONE decision point (shared with the headless anchor).
                    // A fixed ui_scale keeps our DPI+design size; auto adopts
                    // the suggested POSITION but uses the DESIGN size at the new
                    // scale while the creation-time sync is still pending - the
                    // OS-suggested rect is computed from the pre-change context
                    // and used to shrink us back to 980x640 (the measured
                    // "window does not grow on a 125% desktop" bug).
                    const Size suggested_size =
                        suggested ? Size{static_cast<float>(suggested->right -
                                                            suggested->left),
                                         static_cast<float>(suggested->bottom -
                                                            suggested->top)}
                                  : Size{0.0f, 0.0f};
                    // batch28: while a restored geometry is in effect and the
                    // user has not moved the window yet, EVERY DPI event keeps
                    // the restored position+size at the new scale. The
                    // creation-time WM_DPICHANGED (and its ghost follow-up) is
                    // computed from the pre-change context and carries a
                    // down-scaled suggested rect (measured: a saved 160,120
                    // came back at 128,96), so adopting it would silently move
                    // and shrink a restored window.
                    const Size target =
                        DecideDpiChangedSizeForTest(new_dpi, suggested_size);
                    if (restored_.valid && !user_moved_window_) {
                        ApplyRestoredGeometry();
                    } else if (suggested ||
                               (target.w > 0.0f && target.h > 0.0f)) {
                        ::SetWindowPos(
                            hwnd, nullptr,
                            suggested ? suggested->left : 0,
                            suggested ? suggested->top : 0,
                            static_cast<int>(target.w),
                            static_cast<int>(target.h),
                            (suggested ? 0 : SWP_NOMOVE) | SWP_NOZORDER |
                                SWP_NOACTIVATE);
                    }
                    Relayout();
                    Invalidate();
                    return 0;
                }
                case WM_SIZE:
                    // batch28: capture the normal window rect for the
                    // close-time geometry save. WM_MOVE arrives on a drag, so
                    // the pair covers both position and size.
                    CaptureNormalRect();
                    Relayout();
                    Invalidate();
                    return 0;
                case WM_MOVE:
                    CaptureNormalRect();
                    return 0;
                case WM_ERASEBKGND:
                    return 1;  // D2D clears the frame
                case WM_PAINT:
                    // P1 second rework: WM_PAINT must NOT consume the pending
                    // flag. The measured sequence is: Create resizes to
                    // 1225x800 -> the first paint (if it consumed) -> Windows
                    // then delivers the GHOST creation-time WM_DPICHANGED with
                    // a suggested rect computed from the old 96-dpi context
                    // (980x640) -> the auto branch adopted it and the window
                    // shrank back. The flag now survives until the DPICHANGED
                    // (or the 2nd-tick fallback) consumes it.
                    NotifyPaintForTest();
                    Paint();
                    return 0;                case WM_LBUTTONDOWN:
                case WM_LBUTTONDBLCLK:
                case WM_LBUTTONUP:
                case WM_MOUSEMOVE:
                case WM_RBUTTONDOWN:
                case WM_RBUTTONUP:
                    RouteMouse(message, static_cast<int>(
                                            static_cast<short>(LOWORD(lparam))),
                               static_cast<int>(
                                   static_cast<short>(HIWORD(lparam))),
                               0);
                    // batch320: a click that closed a modal gives the
                    // keyboard back to the control that opened it.
                    RestoreFocusAfterDialogClosed();
                    return 0;
                case WM_MOUSEWHEEL: {
                    POINT pt{static_cast<short>(LOWORD(lparam)),
                             static_cast<short>(HIWORD(lparam))};
                    ::ScreenToClient(hwnd, &pt);
                    RouteMouse(message, pt.x, pt.y,
                               static_cast<int>(GET_WHEEL_DELTA_WPARAM(wparam)));
                    return 0;
                }
                case WM_SETCURSOR:
                    // W11 batch6 G-4: in the client area the cursor follows
                    // the topmost hit's cursor_hint() (I-beam over text
                    // inputs, arrow everywhere else). Non-client regions
                    // (caption/border) fall through to DefWindowProcW so the
                    // system's resize/arrow cursors keep working. Numeric
                    // IDC_IBEAM/IDC_ARROW resource values (T6 trap: the IDC_*
                    // macros resolve to the A-variants without UNICODE).
                    if (LOWORD(lparam) == HTCLIENT) {
                        POINT pt{};
                        ::GetCursorPos(&pt);
                        ::ScreenToClient(hwnd, &pt);
                        const Point logical{pt.x / scale_, pt.y / scale_};
                        const CursorKind hint = ResolveCursorHint(logical);
                        ::SetCursor(::LoadCursorW(
                            nullptr,
                            MAKEINTRESOURCEW(CursorResourceIdForHint(hint))));
                        return TRUE;
                    }
                    break;
                case WM_MOUSELEAVE:
                    // Cursor left the client area: hover must not stick.
                    tracking_client_leave_ = false;
                    ClearHover();
                    return 0;
                case WM_NCMOUSEMOVE: {
                    // The caption (and the resize border) is non-client, so
                    // moves there arrive as WM_NCMOUSEMOVE in screen coords;
                    // mirror the hover state so leaving a caption button for
                    // the title bar clears its highlight (T6 review M5).
                    POINT pt{static_cast<short>(LOWORD(lparam)),
                             static_cast<short>(HIWORD(lparam))};
                    ::ScreenToClient(hwnd, &pt);
                    ArmNcLeaveTracking();
                    const Point logical{pt.x / scale_, pt.y / scale_};
                    if (caption_hover_.Update(CaptionButtonRect(0),
                                              CaptionButtonRect(1),
                                              CaptionButtonRect(2), logical)) {
                        // T2: only the caption buttons repaint.
                        for (int i = 0; i < 3; ++i) {
                            InvalidateRect(CaptionButtonRect(i));
                        }
                    }
                    return 0;
                }
                case WM_NCMOUSELEAVE:
                    tracking_nc_leave_ = false;
                    ClearHover();
                    return 0;
                case WM_KEYDOWN:
                case WM_SYSKEYDOWN:
                case WM_KEYUP:
                case WM_SYSKEYUP:
                case WM_CHAR: {
                    const bool key_handled = RouteKey(message, wparam);
                    // batch320: Esc/Enter may have closed a modal; give the
                    // keyboard back to the element that opened it.
                    RestoreFocusAfterDialogClosed();
                    if (key_handled) {
                        return 0;
                    }
                    break;
                }
                // batch24 P0-3 (IME): route the composition messages into the
                // focused editor. The default IME UI (candidate list) is left
                // to DefWindowProc via WM_IME_SETCONTEXT, so only the preedit
                // text/commit/end are consumed here.
                case WM_IME_REQUEST: {
                    // batch37u: TSF IMEs ask for the candidate/composition
                    // anchor instead of trusting ImmSetCandidateWindow alone.
                    // Answer in SCREEN coordinates (the real caret field).
                    // batch104: same stale-focus guard as the ImeXxx entry
                    // points; this branch dynamic_casts focused_ too.
                    if (focused_ != nullptr &&
                        !ElementInTree(root_, focused_)) {
                        focused_ = nullptr;
                    }
                    auto* input = FocusedTextInput();
                    if (input == nullptr || hwnd_ == nullptr) {
                        break;
                    }
                    const Rect b = input->bounds();
                    POINT anchor{static_cast<LONG>(b.x * scale_),
                                 static_cast<LONG>((b.y + b.h) * scale_)};
                    ::ClientToScreen(hwnd_, &anchor);
                    if (wparam == IMR_CANDIDATEWINDOW && lparam != 0) {
                        auto* cand =
                            reinterpret_cast<CANDIDATEFORM*>(lparam);
                        cand->dwStyle = CFS_CANDIDATEPOS;
                        cand->ptCurrentPos = anchor;
                        return 0;
                    }
                    if (wparam == IMR_COMPOSITIONWINDOW && lparam != 0) {
                        auto* comp =
                            reinterpret_cast<COMPOSITIONFORM*>(lparam);
                        comp->dwStyle = CFS_POINT;
                        comp->ptCurrentPos = anchor;
                        return 0;
                    }
                    break;
                }
                case WM_IME_SETCONTEXT:
                    // batch37p (user: floating IME preedit over the field): the
                    // app paints the composition INLINE inside the TextInput;
                    // suppress the OS floating composition window but keep the
                    // candidate list (ISC_SHOWUICANDIDATEWINDOW stays set).
                    // batch37p (user: floating IME preedit over the field): the
                    // app paints the composition INLINE inside the TextInput;
                    // suppress the OS floating composition window but keep the
                    // candidate list (ISC_SHOWUICANDIDATEWINDOW stays set).
                    lparam &= ~static_cast<LPARAM>(ISC_SHOWUICOMPOSITIONWINDOW);
                    return ::DefWindowProcW(hwnd, message, wparam, lparam);
                case WM_IME_STARTCOMPOSITION:
                    ImeStartComposition();
                    return 0;
                case WM_IME_COMPOSITION: {
                    HIMC himc = ::ImmGetContext(hwnd_);
                    if (himc != nullptr) {
                        if ((lparam & GCS_RESULTSTR) != 0L) {
                            const LONG bytes = ::ImmGetCompositionStringW(
                                himc, GCS_RESULTSTR, nullptr, 0);
                            std::wstring result;
                            if (bytes > 0) {
                                result.assign(
                                    static_cast<std::size_t>(bytes) /
                                        sizeof(wchar_t),
                                    L'\0');
                                ::ImmGetCompositionStringW(himc, GCS_RESULTSTR,
                                                           result.data(), bytes);
                            }
                            ImeCommitResult(result);
                        }
                        if ((lparam & GCS_COMPSTR) != 0L) {
                            const LONG bytes = ::ImmGetCompositionStringW(
                                himc, GCS_COMPSTR, nullptr, 0);
                            std::wstring comp;
                            if (bytes > 0) {
                                comp.assign(
                                    static_cast<std::size_t>(bytes) /
                                        sizeof(wchar_t),
                                    L'\0');
                                ::ImmGetCompositionStringW(himc, GCS_COMPSTR,
                                                           comp.data(), bytes);
                            }
                            const LONG cpos = ::ImmGetCompositionStringW(
                                himc, GCS_CURSORPOS, nullptr, 0);
                            ImeUpdateComposition(
                                comp,
                                cpos > 0 ? static_cast<std::size_t>(cpos) : 0);
                        }
                        ::ImmReleaseContext(hwnd_, himc);
                    }
                    PlaceImeWindows();
                    return 0;
                }
                case WM_IME_ENDCOMPOSITION:
                    ImeEndComposition();
                    return 0;
                case WM_IME_CHAR:
                    // batch37p (user): modern IMEs commit through GCS_RESULTSTR
                    // above. Committing the legacy WM_IME_CHAR as well made
                    // IMEs that send BOTH insert every character twice; ignore
                    // the legacy path.
                    return 0;
                case WM_SETFOCUS:
                    Invalidate();
                    return 0;
                case WM_KILLFOCUS:
                    HandleKillFocusForTest();
                    return 0;
                case WM_TIMER:
                    if (kSnapshotTimerId == wparam) {
                        // P1-3: one-shot, idempotent fallback on the 2nd tick.
                        TickDpiSyncFallbackForTest();
                        if (on_snapshot_tick) {
                            on_snapshot_tick();
                        }
                        // batch320: a page-driven Close (command result,
                        // refresh) has no input event to carry the restore.
                        RestoreFocusAfterDialogClosed();
                    } else if (kCaretBlinkTimerId == wparam) {
                        OnCaretBlinkTick();
                    } else if (kAnimationTimerId == wparam) {
                        OnAnimationTimer();
                    }
                    return 0;
                case WM_CLOSE:
                    HandleCloseRequest();
                    return 0;
                case kExitWakeMessage:
                    ::DestroyWindow(hwnd);
                    return 0;
                case kUiDebugMessage:
                    // Debug-channel wake: drain the controller's queued
                    // commands on this UI thread and fulfil their promises.
                    if (on_ui_debug) {
                        on_ui_debug();
                    }
                    return 0;
                case WM_DESTROY:
                    // batch28: remember where/how big the window was (normal
                    // rect only; a maximised window restores its normal size).
                    SaveGeometryNow();
                    tray::Remove();
                    hwnd_ = nullptr;
                    if (on_exit) {
                        on_exit();
                    }
                    ::PostQuitMessage(0);
                    return 0;
                default:
                    break;
            }
            return ::DefWindowProcW(hwnd, message, wparam, lparam);
        }

        LRESULT CALLBACK VgwwWindow::WndProcThunk(HWND hwnd, UINT message,
                                                  WPARAM wparam,
                                                  LPARAM lparam) {
            if (WM_NCCREATE == message) {
                auto* create = reinterpret_cast<CREATESTRUCTW*>(lparam);
                ::SetWindowLongPtrW(
                    hwnd, GWLP_USERDATA,
                    reinterpret_cast<LONG_PTR>(create->lpCreateParams));
            }
            auto* self = reinterpret_cast<VgwwWindow*>(
                ::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
            if (nullptr == self) {
                return ::DefWindowProcW(hwnd, message, wparam, lparam);
            }
            if (nullptr == self->hwnd_) {
                self->hwnd_ = hwnd;  // valid during CreateWindowExW messages
            }
            return self->RunGuardedWndProc(hwnd, message, wparam, lparam);
        }

        LRESULT VgwwWindow::RunGuardedWndProc(HWND hwnd, UINT message,
                                              WPARAM wparam,
                                              LPARAM lparam) noexcept {
            LRESULT result = 0;
            const bool body_ok = core::InvokeHandlerGuarded(
                handler_errors_, [&] {
                    result = WndProc(hwnd, message, wparam, lparam);
                });
            if (!body_ok) {
                // The message body failed (an allocation in a page handler,
                // a throwing callback): let the default procedure answer it
                // rather than unwinding through user32's dispatch frame.
                return ::DefWindowProcW(hwnd, message, wparam, lparam);
            }
            return result;
        }

        LRESULT VgwwWindow::RunSnapshotTimerTickForTest() {
            return RunGuardedWndProc(hwnd_, WM_TIMER, kSnapshotTimerId, 0);
        }

    }  // namespace ui
}  // namespace vgww
