// ============================================================================
// window.h - borderless per-monitor-DPI window with a self-drawn title bar
// (S4.2 Task 6).
//
// Threading: every window/tray/render call must happen on the UI thread.
// Create() runs STA (CoInitializeEx) before the window exists and returns
// false with `error` on any failure (never crashes).
//
// Routing contract (T2-F1 review M3): input never bypasses the element tree -
// mouse goes through Element::HitTest, keys go through FocusChain (or the
// open DialogHost first), so hidden/disabled subtrees stay unreachable.
//
// Layout contract (T2-F1): a resize re-arranges the root with the new size,
// which re-measures by design (Measure is keyed by the available size); no
// explicit InvalidateLayout call is needed or made.
//
// The root element is arranged BELOW the self-drawn title bar:
// {0, titlebar_h, client_w, client_h - titlebar_h} in logical pixels.
// ============================================================================
#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#include <windows.h>

// windows.h pulls in rpcndr.h's legacy `small`/`hyper` macros; they would
// silently rewrite ordinary identifiers in every TU that includes this header
// (tests/test_ui.cpp uses `small` as a variable name). Undef them here once.
#ifdef small
#undef small
#endif
#ifdef hyper
#undef hyper
#endif

#include "ui/element.h"
#include "ui/renderer.h"
#include "ui/ui_state.h"

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <unordered_set>
#include <vector>

namespace vgww {
    namespace ui {

        class ContextMenu;

        /// Caption-button hover state (pure; test seam for T6 review M5).
        /// Update() recomputes the flags from the pointer position, Clear()
        /// resets all three; each reports whether anything changed (repaint
        /// hint). batch31 P0-3: the caption now has three buttons
        /// (minimize / maximize-restore / close), so the middle one has its
        /// own flag.
        struct CaptionHover {
            bool minimize = false;
            bool maximize = false;
            bool close = false;

            bool Update(const Rect& minimize_rect, const Rect& maximize_rect,
                        const Rect& close_rect, Point logical) noexcept;
            bool Clear() noexcept;
        };

        /// batch31 P0-3: caption button order, left to right (RTL mirrors the
        /// whole strip). The numeric values are the `CaptionButtonRect`
        /// indices the tests and the paint path use.
        enum class CaptionButton : int {
            kMinimize = 0,
            kMaximize = 1,
            kClose = 2,
        };

        /// True when `needle` is `root` or one of its descendants. Only
        /// pointer values are compared, so a pointer to an already destroyed
        /// element is safe to test (T6-F1 review I1); a null root/needle is
        /// false.
        bool ElementInTree(const Element* root, const Element* needle) noexcept;

        /// batch55 test/diagnostic seam: how many NODES ElementInTree has
        /// VISITED since the last reset (a probe that stops early counts only
        /// what it walked). The call count alone cannot expose the cost: the
        /// animation walk calls the predicate once per tree EDGE, so "N-1
        /// calls" reads as linear per node while each call walks the whole
        /// tree again. UI thread only.
        std::uint64_t& ElementInTreeVisitCount() noexcept;

        /// batch55: one tree walk recording which members of `wanted` are
        /// present in the tree rooted at `node` (pointer identity only, no
        /// dereference of the members). This is the batched form of
        /// ElementInTree: asking it k times costs k whole-tree walks, this
        /// costs one. `wanted` is expected to be small (the dirty set).
        void MarkLiveDirtyElements(
            const Element* node,
            const std::unordered_set<const Element*>& wanted,
            std::unordered_set<const Element*>& live) noexcept;

        /// Full-clear verdict for one paint (T3, pure/test seam). Returns true
        /// when the whole back buffer must be cleared before drawing: the
        /// render target was (re)created, the paint was NOT triggered by this
        /// app's own pending invalidation (a system exposure / occlusion
        /// restore may have discarded the retained contents), or `rcPaint`
        /// touches any client edge. Otherwise a partial clear of `rcPaint` is
        /// safe. Coordinates are physical pixels (raw RECTs).
        bool ShouldFullClear(bool target_recreated, bool app_triggered,
                             const RECT& rcPaint, const RECT& client) noexcept;

        /// batch37d: physical invalidate rect for one logical dirty region.
        /// Rounds OUTWARD (floor/ceil) and adds a 1 px ring so an antialiased
        /// stroke drawn on the logical box edge (e.g. the hover tooltip
        /// border at 125% DPI) can never fall outside the cleared pixels and
        /// survive as a ghost sliver. Pure/test seam.
        RECT InvalidateRectPixels(const Rect& logical, float scale) noexcept;

        /// Cached hover target (test seam for T6-F1 review I1). The stored
        /// pointer is validated against the live tree before any dereference:
        /// an element destroyed by a subtree teardown (DialogHost::Reset) is
        /// dropped by value comparison, never called through.
        class HoverTarget {
        public:
            /// Stores the pointer without dereferencing it.
            void Set(Element* element) noexcept { element_ = element; }
            Element* get() const noexcept { return element_; }
            /// Drops the stored pointer when it is no longer inside `root`.
            /// Returns true when a live target is kept (false: cleared or
            /// never set).
            bool Validate(const Element* root) noexcept;

        private:
            Element* element_ = nullptr;
        };

        class VgwwWindow final {
        public:
            VgwwWindow();
            ~VgwwWindow();

            VgwwWindow(const VgwwWindow&) = delete;
            VgwwWindow& operator=(const VgwwWindow&) = delete;

            /// Creates the window (hidden when `start_minimized`), initializes
            /// the renderer and registers the tray icon. Returns false with
            /// `error` on failure; the object stays reusable for a retry.
            bool Create(HINSTANCE instance, bool start_minimized,
                        std::string& error);

            /// Message pump; returns when RequestExit()/tray-exit ran.
            void RunMessageLoop();

            /// Asks the loop to exit and destroy the window (UI thread).
            void RequestExit() noexcept;
            /// batch25b: the existing close-to-tray behaviour (first-close
            /// balloon + optional hook + SW_HIDE). With no tray icon it exits
            /// instead of stranding the process.
            void HideToTray();
            /// batch25b test seam: runs the exact WM_CLOSE decision path
            /// (custom on_close_requested hook when installed, otherwise the
            /// legacy hide-to-tray behaviour).
            void HandleCloseForTest() { HandleCloseRequest(); }
            /// batch27 P0-2 test seam: runs the exact WM_KILLFOCUS body (the
            /// WndProc case is a thin wrapper over this) so a headless test can
            /// assert that an expanded popup is dismissed on focus loss.
            void HandleKillFocusForTest();
            /// batch27 P0-3 test seam: the exact WM_MOUSEWHEEL body.
            bool HandleWheelForTest(Point logical, int wheel_delta) {
                return RouteClientPointer(WM_MOUSEWHEEL, logical, wheel_delta);
            }
            /// batch27 P0-4: closes every expanded popup (Select / language
            /// picker). Called by the shell before a page switch, so a list can
            /// never survive onto a page it does not belong to.
            void DismissAllPopups() {
                CollapseExpandedPopups(nullptr);
                // b28-legibility P5: a page switch must also drop the hover
                // tooltip (it used to survive onto the next page).
                ClearHover();
            }
            /// b28-legibility P5: drops the hover tooltip without touching the
            /// rest of the hover state (called when a state switch changes the
            /// instrument under a stationary pointer).
            void ClearHoverTooltip() {
                if (!hover_tooltip_.empty()) {
                    // batch37: local tooltip-box repaint, never the window.
                    const Rect box =
                        HoverTooltipBox(hover_tooltip_, hover_tooltip_point_);
                    hover_tooltip_.clear();
                    if (box.w > 0.0f && box.h > 0.0f) {
                        InvalidateRect(box);
                    }
                }
            }
            /// b28-legibility P5 test seam: the tooltip text currently queued
            /// for painting (empty = nothing).
            const std::wstring& hover_tooltip_for_test() const noexcept {
                return hover_tooltip_;
            }
            /// batch37b test seam: the anchor the tooltip is painted at. The
            /// tooltip must follow the current hover (user report: it stayed
            /// on an older row when the text was unchanged).
            Point hover_tooltip_point_for_test() const noexcept {
                return hover_tooltip_point_;
            }
            /// batch27 P1-14: puts keyboard focus on the dialog's SAFE button
            /// (Cancel when present, otherwise the first focusable control)
            /// unless focus is already inside the open dialog.
            void SyncDialogFocus();
            /// batch320: returns the keyboard to the element that had it
            /// before the modal opened. A closed dialog's own controls are
            /// retired, so without this the focus ring disappears and typing
            /// goes nowhere until the user clicks or tabs from scratch.
            void RestoreFocusAfterDialogClosed();
            /// batch27 P0-3 test seam: the popup geometry of an expanded
            /// Select after a page scroll (must follow its trigger).
            bool HasVisibleOverlayForTestPublic() const {
                return HasVisibleOverlay();
            }
            /// batch25b test seam: true once HideToTray() actually ran.
            bool hidden_to_tray() const noexcept { return hidden_to_tray_; }
            /// batch25b test seam: a real Create() registers the tray icon;
            /// headless tests set this to exercise the hide-to-tray path
            /// instead of the no-tray "exit" fallback.
            void SetTrayActiveForTest(bool active) noexcept {
                tray_active_ = active;
            }
            /// Test seam (S5.19): the guarded decision behind Create()-time
            /// foregrounding. SW_SHOW launches bring the window to the front
            /// (and steal input focus, which is the user intent); SW_HIDE
            /// (start_minimized) launches stay silent.
            static bool ShouldForegroundOnCreate(bool start_minimized) noexcept {
                return !start_minimized;
            }
            /// Test/audit seam (S5.19): true once Create() ran the
            /// BringWindowToTop/SetForegroundWindow foregrounding path.
            bool foreground_requested() const noexcept { return foreground_requested_; }
            /// Repaints on the next WM_PAINT.
            void Invalidate() noexcept;            /// Repaints only the given LOGICAL rect on the next WM_PAINT
            /// (local invalidation, S5.19 dirty-rect direction); converts to
            /// physical pixels via the current scale. Safe no-op pre-Create.
            void InvalidateRect(Rect logical) noexcept;

            /// Starts the ~16 ms animation frame clock (idempotent). No-op
            /// while the clock already runs. Installed as the global animation
            /// requester so a control can spin it up when it begins an
            /// animation; it self-stops once no element reports an active
            /// animation. The active state is decoupled from hwnd_ (a timer is
            /// only scheduled when a window exists); a SetTimer failure rolls
            /// the state back.
            void RequestAnimationFrame();
            /// Kills the animation frame clock (idempotent; safe no-op).
            void StopAnimationFrame() noexcept;
            bool animation_active() const noexcept { return animation_active_; }
            /// batch29 P1: the animation clock's period. The only animations
            /// left are a 1.2 s dot breath and a 120 ms gear ease, so 30 fps
            /// is indistinguishable while halving the frame count.
            static constexpr unsigned AnimationFrameIntervalMsForTest() noexcept {
                return 33u;
            }
            /// Debug/metric seam: frames advanced by the timer clock (the
            /// ForTest seam does not touch it).
            uint64_t animation_frames() const noexcept { return animation_frames_; }

            // -- T8 metrics seams (window-level counters; never reset). ------
            /// Completed Paint() passes (window-level; 0 headless).
            uint64_t paint_count() const noexcept { return paint_count_; }
            /// Duration of the last Paint() pass in microseconds (0 before one).
            long long last_paint_us() const noexcept { return last_paint_us_; }
            /// Last WM_PAINT dirty region in logical pixels ({0,0,0,0} before).
            const Rect& last_dirty_rect() const noexcept { return last_dirty_rect_; }

            /// M5 frame-statistics constants.
            /// ~16 ms frame budget (1/60 s) in microseconds.
            static constexpr long long kFrameBudgetUs = 16700;
            /// Idle-gap threshold: 5x the frame budget. Frames further apart
            /// than this are a true idle gap, not a slow frame; the statistics
            /// window is cleared and the anchor reset (the next frame starts a
            /// fresh burst).
            static constexpr long long kIdleGapUs = 5 * kFrameBudgetUs;
            /// Rolling window of frame intervals used to derive fps().
            static constexpr int kFrameStatsWindow = 60;

            /// M5: current frames per second from the rolling interval window.
            /// Returns 0.0 when the wall-clock gap since the last recorded
            /// frame exceeds kIdleGapUs (a static page reports 0 fps), or when
            /// fewer than two intervals have been recorded.
            double fps() const noexcept;
            /// M5: number of frames whose paint exceeded kFrameBudgetUs.
            uint64_t dropped_frames() const noexcept {
                return over_budget_frames_;
            }
            /// M5: largest single-frame paint duration in microseconds.
            uint64_t frame_time_max_us() const noexcept {
                return frame_time_max_us_;
            }
            /// M5: number of intervals currently in the rolling fps window
            /// (0 when idle/empty).
            uint64_t fps_samples() const noexcept {
                return static_cast<uint64_t>(frame_interval_len_);
            }

            // -- U1 invalidation-request seams (headless-observable) ----------
            /// Number of repaint requests (Invalidate/InvalidateRect/element)
            /// made so far. Headless-safe: recorded even without an hwnd.
            uint64_t invalidate_count() const noexcept { return invalidate_count_; }
            /// True if the most recent request was a full-window invalidate.
            bool last_invalidation_full() const noexcept {
                return last_invalidation_full_;
            }
            /// The rect of the most recent local (non-full) invalidation.
            const Rect& last_invalidated_rect() const noexcept {
                return last_invalidated_rect_;
            }
            /// batch29 P1 test seam: the union of every invalidation request
            /// since the last ResetInvalidationStatsForTest(), plus whether any
            /// of them was a full-window request. Used to prove an animation
            /// frame repaints only the status strip / sparkline region.
            void ResetInvalidationStatsForTest() noexcept {
                invalidation_union_ = Rect{};
                invalidation_full_since_reset_ = false;
            }
            const Rect& invalidation_union_for_test() const noexcept {
                return invalidation_union_;
            }
            bool invalidation_full_since_reset() const noexcept {
                return invalidation_full_since_reset_;
            }
            /// Tick passes backfilled by the app's snapshot timer (0 headless).
            uint64_t tick_count() const noexcept { return tick_count_; }
            /// Duration of the last backfilled tick in microseconds.
            long long last_tick_us() const noexcept { return last_tick_us_; }
            /// Backfills the tick counters from the app's OnTick (the window
            /// does not own the tick; the app calls this at the end of its
            /// tick so metrics/monotonic counters stay observable headless).
            void RecordTickForTest(long long tick_us) noexcept {
                ++tick_count_;
                last_tick_us_ = tick_us;
            }
            /// Test seam (mirrors RecordTickForTest): feeds one frame's paint
            /// duration and interval into the M5 statistics, exactly as the
            /// real Paint() tail does (counts a paint, refreshes the wall
            /// anchor, then updates fps/dropped/max). Headless tests drive it
            /// directly so fps/dropped/frame-time are deterministic.
            void RecordFrameForTest(long long paint_us,
                                    long long interval_us) noexcept {
                ++paint_count_;
                last_paint_us_ = paint_us;
                last_paint_wall_us_ = std::chrono::duration_cast<
                    std::chrono::microseconds>(
                    std::chrono::steady_clock::now().time_since_epoch())
                                         .count();
                RecordFrameStatistics(paint_us, interval_us);
            }
            /// Test seam (no OS timer): advances every visible element's
            /// animation by `dt_seconds`, invalidating only the animating
            /// element's bounds. Returns whether any animation is still active.
            bool AdvanceAnimationFrameForTest(float dt_seconds);
            /// Test seam: runs one frame's core logic with an explicit dt
            /// (never the wall clock) and no timer interaction - advances the
            /// tree, counts a frame, self-stops, and calls on_animation_frame
            /// in exactly the real timer path's order, so headless tests can
            /// pin the Stop-before-hook contract.
            void OnAnimationTimerForTest(float dt_seconds);
            /// Test seam (T8): runs `count` caret-blink phases exactly like the
            /// 500 ms caret timer (forwarding the private OnCaretBlinkTick), so
            /// a headless test can advance the caret phase deterministically
            /// without sleeping. Returns nothing; the focused input's
            /// caret_visible() reflects the flips.
            void OnCaretBlinkTickForTest(int count) noexcept;
            /// Test seam (T8): runs one real Paint() pass when a live hwnd
            /// exists, returning false (blocked) when headless. The real pixel
            /// path stays GUI-only; a headless call is a clean no-op.
            bool PaintNowForTest();

            /// Root element (NOT owned; must outlive the window). Arranges it
            /// immediately with the current client size (below the title bar).
            void SetRoot(Element* root);
            Element* root() const noexcept { return root_; }
            /// batch37o: the shell-level edit context menu (owned by the app
            /// tree). Right-clicking a TextInput/console opens it.
            void SetEditContextMenu(ContextMenu* menu) noexcept {
                edit_menu_ = menu;
            }

            /// Physical pixels -> logical pixels (scale >= 0.5, so no divide
            /// by zero; negative input returns a negative logical value).
            float ToLogical(int px) const noexcept { return px / scale_; }
            /// Test seam: sets the DPI from a scale factor (clamped >= 0.5).
            void SetDpiForTest(float scale) noexcept;

            /// batch329: pins the desktop work area used by the geometry
            /// restore and the DPI clamp so tests do not depend on the host
            /// monitor layout (a small CI work area rejects the restored size
            /// at load time, before the clamp is reached).
            void SetWorkAreaForTest(Size work) noexcept;
            void ClearWorkAreaForTest() noexcept;
            /// Test seam (T8): injects the modifier-key mask RouteKey reads
            /// for its Shift+Tab direction test, instead of the process-wide
            /// ::GetKeyState. bit 0 = Shift, bit 1 = Ctrl, bit 2 = Alt.
            void SetModifiersForTest(unsigned modifiers) noexcept {
                modifiers_override_ = modifiers;
                modifiers_injected_ = true;
            }
            /// Test seam (T8): drops the injection so RouteKey falls back to
            /// ::GetKeyState. MUST be called after an injected key op, else a
            /// live window would read a latched mask forever and real
            /// Shift+Tab would never reverse focus.
            void ResetModifiersForTest() noexcept {
                modifiers_override_ = 0;
                modifiers_injected_ = false;
            }
            unsigned modifiers_for_test() const noexcept {
                return modifiers_override_;
            }
            bool modifiers_injected_for_test() const noexcept {
                return modifiers_injected_;
            }

            /// Asks the window to re-arrange the root with the current client
            /// size and repaint. Safe no-op without a root or before Create();
            /// reentrant (Arrange is idempotent and no element can call back
            /// into the window). Any code that adds a visible subtree after
            /// the last arrange must trigger this - navigation, language
            /// switch, and dialogs (T8+ contract: after ShowForm/ShowConfirm/
            /// close), otherwise the new bounds stay zero until a resize
            /// (T7 review I1).
            void RequestLayout();
            /// batch29 P2/P3: re-arrange after a content-only snapshot change
            /// and repaint only the changed elements (+ their parents), never
            /// the whole window. Safe pre-Create (records the layout request;
            /// full invalidate fallback when nothing was tracked).
            void RepaintChangedContent();
            /// Test anchor: number of RequestLayout() requests (counted even
            /// before a window exists).
            std::size_t layout_requests() const noexcept { return layout_requests_; }
            /// Test/debug seam (Task 4): sets the CLIENT area to `logical_w` x
            /// `logical_h` LOGICAL pixels and re-arranges the root. With a real
            /// hwnd the outer window is resized (frame delta accounted for) so
            /// the next Relayout sees the new client size; headless (no hwnd)
            /// it arranges the root directly below the title bar and records a
            /// layout request. Negative extents clamp to zero. This is the
            /// `resize` debug op's real-window path (spec L124).
            void ResizeForTest(float logical_w, float logical_h);
            /// batch29: gives a headless window a client size so Relayout()
            /// can actually arrange the tree (the page-switch layout budget is
            /// only meaningful when the coalescing path runs). Production
            /// always has an hwnd; tests opt in explicitly.
            void SetHeadlessClientSizeForTest(float logical_w, float logical_h) {
                headless_client_w_ = logical_w;
                headless_client_h_ = logical_h;
            }
            /// Test seam (T6-F1 review I1): dispatches one client mouse move
            /// exactly like WM_MOUSEMOVE (HitTest + stale-hover validation)
            /// and returns the element currently tracked as hovered.
            Element* HoverMoveForTest(Point logical);
            /// Test seams (S6 U5): headless key routing + focus observation so
            /// modal Tab-scoping can be verified without a real window.
            bool RouteKeyForTest(UINT message, WPARAM wparam) {
                return RouteKey(message, wparam);
            }
            /// T7/I2 test seam: number of local element invalidations RouteKey
            /// requested after consuming a key (headless InvalidateRect is a
            /// no-op without an hwnd, so this mirrors the decision the real
            /// path takes when a window exists). Monotonic.
            std::size_t key_invalidations() const noexcept {
                return key_invalidations_;
            }
            void SetFocusForTest(Element* element) {
                SetFocusElement(element);
            }
            /// batch104: never hand back a pointer a dialog teardown left
            /// dangling. Same value-comparison contract HoveredForTest already
            /// honours, and the same guard the four ImeXxx entry points apply
            /// before touching focused_ (ElementInTree, no deref).
            Element* FocusedForTest() const noexcept {
                return ElementInTree(root_, focused_) ? focused_ : nullptr;
            }
            /// batch320: modal focus-restore seams. The sync remembers the
            /// element that had focus before the dialog took it; the restore
            /// gives it back after the dialog closes.
            void SyncDialogFocusForTest() { SyncDialogFocus(); }
            void RestoreFocusAfterDialogClosedForTest() {
                RestoreFocusAfterDialogClosed();
            }
            Element* FocusBeforeDialogForTest() const noexcept {
                return focus_before_dialog_;
            }
            /// batch24 P0-3 (IME): composition routing entry points. WndProc's
            /// WM_IME_* cases read the strings from the IME context and call
            /// these; tests drive them directly (no real IME needed) to prove
            /// the window routes preedit/commit/end into the focused editor.
            void ImeStartComposition();
            void ImeUpdateComposition(const std::wstring& composition,
                                      std::size_t caret);
            void ImeCommitResult(const std::wstring& result);
            void ImeEndComposition();
            /// batch37u: place the IMF composition/candidate windows at the
            /// focused editor (screen coordinates). TSF IMEs may also ask via
            /// WM_IME_REQUEST; both paths share this anchor.
            void PlaceImeWindows();
            /// Test/debug seam (I1d): the currently hovered element, or
            /// nullptr. Read-only: a cached pointer that a subtree teardown
            /// (DialogHost::Reset) left dangling is reported absent by value
            /// comparison, without mutating the cache from a const read.
            Element* HoveredForTest() const noexcept;
            /// Test seam (G3/G9): the overlay-first hit resolution RouteMouse
            /// uses for every pointer message. Prefers the top-layer hit
            /// (HitTestOverlay) over the normal tree hit.
            Element* HitTestTopmostForTest(Point logical) const;
            /// W11 batch6 G-4 test seams: the cursor kind the topmost hit at
            /// `logical` requests (HitTestTopmost -> cursor_hint(); Arrow
            /// when nothing is hit), and the Win32 resource id the live
            /// WM_SETCURSOR path would load for it (32513 = IDC_IBEAM,
            /// 32512 = IDC_ARROW). Both call the exact functions the live
            /// path uses, so the mapping can never drift from it.
            CursorKind CursorHintForTest(Point logical) const {
                return ResolveCursorHint(logical);
            }
            int CursorResourceForTest(Point logical) const {
                return CursorResourceIdForHint(ResolveCursorHint(logical));
            }
            /// Test seam (Task 3 review I1): routes one CLIENT-area pointer
            /// message exactly like RouteMouse - on WM_LBUTTONDOWN it sets
            /// mouse_capture_, moves focus to the nearest focusable ancestor,
            /// then dispatches OnMouseDown; WM_LBUTTONUP dispatches through the
            /// captured element (with a tree-liveness guard); WM_MOUSEMOVE is
            /// owned by the capture, else dispatches a hover move; WM_MOUSEWHEEL
            /// dispatches to the topmost hit, and an unconsumed wheel then
            /// bubbles up the parent() chain to the nearest
            /// ScrollView/TableElement (B13). It omits only the non-client
            /// caption/title-bar handling, which needs a real hwnd and physical
            /// coordinates. Safe without a window: root_==nullptr is a no-op and
            /// Invalidate() is a guarded no-op when hwnd_ is null. Returns the
            /// message's consumption (wheel: true iff the topmost hit or some
            /// ancestor on its parent() chain consumed the wheel - the first
            /// OnWheel returning true is the consumer; others: whether an
            /// element was dispatched to) so callers can mirror RouteMouse's
            /// observable effects.
            bool RouteMouseForTest(UINT message, Point logical,
                                   int wheel_delta = 0);
            /// Test seam (G3/G4/G9): draws one frame exactly like Paint()'s
            /// element passes - content traversal (Element::Render, which skips
            /// renders_on_top children) then the top-layer DFS. Records into
            /// `ctx`; callers BeginRecord/EndRecord around it.
            void RenderFrameForTest(RenderCtx& ctx);
            /// Test seam (batch2 M4 X-T1/R9; redefined by batch11 M12):
            /// read-only mirror of the full-clear verdict Paint() computes for
            /// one paint, i.e. the exact expression `ShouldFullClear(...)`.
            /// M12 removed the former `|| HasVisibleOverlay()` clause (overlay
            /// frames may now clear partially); overlay existence is observed
            /// through HasVisibleOverlayForTest(). It exists so a headless test
            /// can observe the verdict without a live hwnd (Paint itself is
            /// GUI-only). `rcPaint`/`client` are physical pixels (raw RECTs),
            /// exactly as Paint passes them.
            bool FullClearForTest(bool target_recreated, bool app_triggered,
                                  const RECT& rcPaint,
                                  const RECT& client) const noexcept;
            /// M4 (batch11 M12): read-only observation hole for "some
            /// top-layer surface is currently visible" - the predicate the
            /// full-clear verdict consulted before M12. M12 removed that
            /// clause (overlay frames may now clear partially), so the M1
            /// overlay-cache tests observe existence/visibility through this
            /// seam instead of FullClearForTest. Delegates to the same
            /// HasVisibleOverlay() the window uses internally.
            bool HasVisibleOverlayForTest() const { return HasVisibleOverlay(); }
            /// M5 (batch11 M12): headless-callable paint orchestration -
            /// exactly the clear -> clip/cull -> chrome -> content -> overlay
            /// sequence Paint() runs between BeginFrame/EndFrame. The
            /// GUI-only entry/exit (BeginPaint/EndPaint, BeginFrame) stays in
            /// Paint(); tests wrap this call in BeginRecord/EndRecord and
            /// assert the recorded clip structure. `dirty` is the logical
            /// dirty rect exactly as Paint computes it; `client_rc` is the
            /// raw physical client RECT.
            void PaintFrameForTest(bool full, const Rect& dirty,
                                   const RECT& client_rc);
            /// M5: the index into renderer().ops() of the overlay segment's
            /// top-level ClipPush recorded by the last PaintFrameForTest
            /// (kOverlayPhaseUnset when nothing was recorded).
            std::size_t overlayPhaseOpsIndexForTest() const noexcept {
                return overlay_phase_ops_index_;
            }
            /// Test seam (batch2 M1, plan C): the number of overlay host
            /// nodes in the structure cache, read through the same staleness
            /// guard the consumers use (reports what they would see). Not an
            /// independent count: reflects the rebuilt cache size.
            std::size_t overlayNodeCountForTest() const;
            float scale() const noexcept { return scale_; }
            float titlebar_height() const noexcept { return titlebar_h_; }

            // -- batch28: window position/size memory ------------------------
            /// Loads %LOCALAPPDATA%\VGWW\ui_state.json into the pending restore
            /// slot (invalid/missing/corrupt -> no pending restore). Headless
            /// safe: Create() calls it; tests may call it directly.
            void LoadSavedGeometryForTest();
            /// The sanitised geometry that the next creation/DPI sync will
            /// apply (invalid when nothing usable was stored or it was already
            /// consumed).
            bool has_pending_restore() const noexcept {
                return restore_pending_ && restored_.valid;
            }
            /// batch30: the saved window closed maximized, so the restore path
            /// must request SW_MAXIMIZE after applying the normal rect.
            bool pending_restore_maximized() const noexcept {
                return has_pending_restore() && restored_.maximized;
            }
            /// Restored position in PHYSICAL screen pixels (false when none).
            bool pending_restore_position(int& x, int& y) const noexcept {
                if (!has_pending_restore()) {
                    return false;
                }
                x = restored_.x;
                y = restored_.y;
                return true;
            }
            /// Persists the CURRENT normal window rect (no-op headless).
            /// Called from WM_DESTROY; exposed so a test can assert the
            /// round-trip through a temp path.
            void SaveGeometryNow();
            /// batch20: UI scale override. `scale` > 0 is an absolute factor
            /// (1.0..5.0) that wins over the desktop DPI and resizes the
            /// window to the 980x640 design size at that scale, keeping the
            /// top-left corner (minimal disturbance; centring would jump the
            /// window on every change). `scale` <= 0 returns to auto (follow
            /// the desktop DPI, size unchanged here). Safe pre-Create: the
            /// creation size and DPI honour a pending override.
            void SetUiScale(float scale);
            /// True while following the desktop DPI (no fixed override).
            bool ui_scale_auto() const noexcept { return ui_scale_ <= 0.0f; }
            /// The physical client size a fixed override targets (980x640
            /// logical at scale_) - headless test seam.
            Size scaled_client_size() const noexcept;
            /// batch20 WM_DPICHANGED decision, headless: a fixed override
            /// IGNORES the desktop change (returns false, scale unchanged);
            /// auto follows it (returns true after ApplyDpi).
            bool ApplyDesktopDpiForTest(float dpi);

            /// batch20 P1: the WM_DPICHANGED size decision, factored out so it
            /// is headless-testable. `suggested` is the OS-suggested size (the
            /// value the handler receives); the return value is the size we
            /// actually apply.
            Size DecideDpiChangedSizeForTest(float new_dpi, Size suggested);
            /// The last size a SetWindowPos-style decision requested (0x0 when
            /// none yet) - headless anchor for P1.
            const Size& last_size_request_for_test() const noexcept {
                return last_size_request_;
            }
            /// Marks the creation-time size sync as pending (Create sets it).
            void SetSizeSyncPendingForTest(bool pending) noexcept {
                size_sync_pending_ = pending;
            }
            bool size_sync_pending_for_test() const noexcept {
                return size_sync_pending_;
            }
            /// The WM_PAINT hook (P1: it must NOT consume the pending flag -
            /// the ghost creation-time WM_DPICHANGED arrives after the first
            /// paint and would then be adopted).
            void NotifyPaintForTest() noexcept { tick_sync_paint_seen_ = true; }
            /// The per-tick fallback (P1-3): runs once, strictly after the
            /// initial message drain (2nd tick), and only if the flag is still
            /// pending (no WM_DPICHANGED ever arrived).
            void TickDpiSyncFallbackForTest();

            HWND hwnd() const noexcept { return hwnd_; }
            RenderCtx& renderer() noexcept { return renderer_; }
            bool exit_requested() const noexcept { return exit_requested_; }
            bool tray_active() const noexcept { return tray_active_; }

            // App hooks (set before RunMessageLoop; UI thread only).
            /// batch25b: when set, WM_CLOSE is delegated to the app (which
            /// explains that the service keeps running and offers Keep/Quit).
            /// Empty keeps the legacy hide-to-tray path.
            std::function<void()> on_close_requested;
            std::function<void()> on_close_to_tray;
            std::function<void()> on_exit;
            std::function<void()> on_snapshot_tick;
            /// batch28: tray "Start service"/"Stop service" (true = start).
            /// The app posts the matching Command into the normal queue.
            std::function<void(bool)> on_toggle_service;
            /// batch29: tray "Open dashboard" (the window shows itself first,
            /// then calls this so the app can switch pages).
            std::function<void()> on_open_dashboard;
            /// Optional observation hook: called after each animation frame is
            /// advanced (default empty).
            std::function<void()> on_animation_frame;
            /// batch287: a copy/cut whose clipboard write was refused
            /// (another process holds the clipboard). The window has no
            /// toast host, so the shell turns this into the same warning
            /// the pages show. Paste is NOT reported: its `false` also
            /// means "clipboard empty", which is not a failure.
            std::function<void(bool paste)> on_clipboard_failed;

            /// Debug-channel wake (Task 6): the debug server's worker thread
            /// posts this to wake the UI thread, whose WndProc invokes
            /// `on_ui_debug` (the controller's DrainOnUiThread). Returns false
            /// when there is no live hwnd (headless test seam / window gone),
            /// so the caller degrades to inline execution instead of waiting
            /// forever on a promise nobody drains.
            bool PostUiDebug() noexcept;
            /// Invoked from WndProc on the debug wake message. Set by the
            /// owner wiring (UiDebugServer) to call DrainOnUiThread.
            std::function<void()> on_ui_debug;

            /// WndProc bodies whose exception was swallowed by the firewall
            /// (telemetry/tests). WndProcThunk is called by user32: a throw
            /// escaping it would unwind through DispatchMessage's frame, which
            /// is undefined behaviour, so the body is firewalled instead.
            uint64_t HandlerErrors() const noexcept {
                return handler_errors_.load(std::memory_order_relaxed);
            }

            /// Test seam: drives the guarded WM_TIMER snapshot path headless
            /// (the same entry user32 takes), so a throwing on_snapshot_tick
            /// can be shown to cost that one tick, not the process.
            LRESULT RunSnapshotTimerTickForTest();

        private:
            static constexpr UINT kUiDebugMessage = WM_APP + 5;
            /// M1 (batch2, plan C): never a real generation, so the first
            /// cache access always rebuilds (mirrors controls.h:545 UINT32_MAX).
            static constexpr uint64_t kOverlayCacheSentinel =
                ~static_cast<uint64_t>(0);

            static LRESULT CALLBACK WndProcThunk(HWND hwnd, UINT message,
                                                 WPARAM wparam, LPARAM lparam);
            LRESULT WndProc(HWND hwnd, UINT message, WPARAM wparam,
                            LPARAM lparam);
            /// Runs WndProc behind the exception firewall and falls back to
            /// DefWindowProc when the body threw, so user32 never sees a C++
            /// unwind. This is the single OS-facing window-procedure entry.
            LRESULT RunGuardedWndProc(HWND hwnd, UINT message, WPARAM wparam,
                                      LPARAM lparam) noexcept;

            void ApplyDpi(float dpi) noexcept;
            /// batch331: re-derives the scale from the desktop DPI, the ONE
            /// rule Create() and SetUiScale(0) share. With a live window it
            /// takes GetDpiForWindow (48..768); headless it restores the
            /// remembered desktop scale so a pre-Create override is not lost.
            void ApplyAutoDpi() noexcept;
            /// batch28: records the live window rect while the window is in
            /// its normal (not zoomed/iconic) state.
            void CaptureNormalRect() noexcept;
            /// batch28: re-applies the restored position+size at the CURRENT
            /// scale. The creation-time WM_DPICHANGED carries an OS-suggested
            /// rect computed from the pre-change DPI; adopting it would move a
            /// restored window (measured: saved 160,120 came back at 128,96)
            /// and shrink it. Called after every DPI decision while a restore
            /// is in effect.
            void ApplyRestoredGeometry() noexcept;
            /// batch229: clamps a re-derived (restored) client size to the
            /// primary work area. Every path that multiplies the stored
            /// LOGICAL size by the current scale must go through this, or a
            /// DPI raise grows the window past the screen.
            Size ClampRestoredSizeToWorkArea(Size size) const noexcept;
            void Relayout();
            void Paint();
            /// batch25b: WM_CLOSE decision (app hook or legacy hide-to-tray).
            void HandleCloseRequest();
            /// M5 (batch11 M12): Paint's orchestration between BeginFrame and
            /// EndFrame (clear -> clip/cull -> chrome -> content pass ->
            /// overlay pass). Shared verbatim with PaintFrameForTest so the
            /// headless clip-structure assertions observe the production
            /// sequence. Never touches the hwnd; the caller supplies the
            /// verdict (`full`), the logical dirty rect and the physical
            /// client RECT.
            void PaintOrchestrate(bool full, const Rect& dirty,
                                  const RECT& client);
            /// M5 (batch11 M12): no overlay-phase marker is set (not
            /// recording, or no root/overlay pass ran).
            static constexpr std::size_t kOverlayPhaseUnset =
                static_cast<std::size_t>(-1);
            /// M5: records one frame's paint duration and interval into the
            /// rolling statistics (fps window, max paint, dropped counter). An
            /// `interval_us <= 0` (first frame) only sets the anchor; an
            /// interval above kIdleGapUs clears the window as a true idle gap.
            void RecordFrameStatistics(long long paint_us,
                                       long long interval_us) noexcept;
            /// Overlay-first hit resolution: the top-layer hit wins, else the
            /// normal content hit (G3/G9). Used by every mouse message.
            Element* HitTestTopmost(Point logical) const;
            /// Pre-order DFS over the visible tree calling RenderOverlay on
            /// every node (top layer: dialogs, then toasts). It does NOT stop
            /// at a renders_on_top() node: a dialog's nested Select popup must
            /// also be painted unclipped.
            void RenderOverlays(RenderCtx& ctx, Element* node);
            void RouteMouse(UINT message, int px, int py, int wheel_delta);
            /// Client-area pointer routing shared by RouteMouse (after its
            /// non-client/title-bar handling) and RouteMouseForTest. `logical`
            /// is already in logical pixels; the caller guards root_/hwnd_.
            /// Returns the message's consumption (see RouteMouseForTest).
            bool RouteClientPointer(UINT message, Point logical, int wheel_delta);
            bool RouteKey(UINT message, WPARAM wparam);
            void SetFocusElement(Element* element);
            void CycleFocus(bool backward, Element* scope = nullptr);
            Element* FindOpenDialog() const;
            /// True when a top-layer surface (open dialog, active toast,
            /// expanded Select popup) is visible. batch11 M12: this no longer
            /// forces a full clear - on a partial frame the overlay pass is
            /// clipped to the SAME dirty rect as the content pass (M2, one
            /// single-composite domain), and the invalidation surfaces keep
            /// every covered region live. Consumers: the M2b wheel guard
            /// (via SubtreeHasVisibleOverlay) and the HasVisibleOverlayForTest
            /// observation seam.
            bool HasVisibleOverlay() const;
            /// batch11 M12 M2b (F1 fix): true when `node`'s visible subtree
            /// contains a VISIBLE top-layer node (expanded Select popup, open
            /// dialog, active toast). A wheel consumed by a scroll container
            /// moves such a popup with the content (SetOffset re-arranges the
            /// subtree); a viewport-only repaint would leave the part outside
            /// the viewport stale (ghost) or unpainted (missing), so that
            /// frame falls back to a full-window invalidate. Deliberately
            /// subtree-relative and live: a Table inside a scroll view stays
            /// local even when an unrelated Select elsewhere on the page is
            /// expanded, and the predicates are read live (no cache).
            bool SubtreeHasVisibleOverlay(const Element* node) const noexcept;
            /// batch26 P0: closes every visible expanded Select/LanguagePicker
            /// popup except `keep` (nullptr = close all). Returns true when at
            /// least one was open. Iterates the structure-keyed overlay cache
            /// (never the whole tree per frame) and repaints only the vacated
            /// regions.
            bool CollapseExpandedPopups(Element* keep);
            /// batch26 P0: closes every expanded popup whose trigger box +
            /// popup list does NOT contain `logical`. Used by the mouse-down
            /// sentinel BEFORE the click is routed, so the same click still
            /// reaches the clicked control (two-click semantics preserved).
            bool DismissExpandedPopupsOutside(Point logical);
            /// batch33 E: closes every OPEN context menu (right-press and page
            /// switches use it). Returns true when at least one was open.
            bool CloseContextMenus();
            /// batch287: forwards a refused clipboard write to the app.
            void NotifyClipboardFailed(bool paste);
            /// batch34k P0: the ONLY place a context menu is dismissed because
            /// a click landed outside its card. Hit testing is a pure query
            /// (hover/cursor/wheel call it), so the "click outside closes"
            /// half of the menu contract lives here, on the button-down path.
            /// Returns true when a menu was open and got closed.
            bool DismissContextMenuOutside(Point logical);
            /// batch37o: open the standard edit menu for a TextInput/console.
            void ShowEditContextMenu(Element* target, Point at);
            /// M1 (batch2, plan C): structure-keyed overlay-node cache.
            /// Bumps the structure generation; called from every entry point
            /// that can change the tree topology (SetRoot, RequestLayout).
            void NoteTreeStructureChanged() noexcept { ++structure_gen_; }
            /// Rebuilds `overlay_nodes_` when the structure generation or the
            /// element-tree epoch changed since the last build. O(1) when
            /// fresh; one O(N) DFS when stale (const + mutable memoisation).
            void RefreshOverlayCacheIfStale() const;
            /// DFS collector (reverse-children post-order, mirroring
            /// FindOverlayHit's priority) of DialogHost*/ToastHost*/
            /// SelectElement*/LanguagePicker* nodes. Includes hidden nodes
            /// (H7 existence path).
            void CacheOverlayNodes(Element* node) const;
            /// Reverse-children post-order overlay hit search over the cache
            /// (replaces the old full-tree recursive DFS). `logical` is in
            /// logical pixels; H6 re-applies the visible-ancestor prune.
            Element* FindOverlayHit(Point logical) const;
            /// One caret-blink phase (S5.19): asks the focused element to
            /// advance its phase and repaints only its bounds when it changed.
            void OnCaretBlinkTick() noexcept;
            /// One animation frame (kAnimationTimerId): computes the clamped
            /// dt, advances the tree, and stops the clock when nothing remains
            /// active.
            void OnAnimationTimer();
            /// Advances every visible element in the tree by `dt_seconds`,
            /// invalidating only animating elements' bounds. Returns whether
            /// any animation is still active.
            bool AdvanceAnimations(float dt_seconds);
            /// DFS helper: advances `node`, records activity into `any_active`,
            /// and recurses into visible children.
            void CollectAnimationActivity(Element* node, float dt, bool& any_active);
            /// W11 G-1: non-mutating DFS - true when any visible node is
            /// mid-animation (same visible-prune contract as
            /// CollectAnimationActivity, without its advance/invalidate side
            /// effects). Used by SetRoot to re-arm the frame clock for an
            /// entrance that started before the window existed.
            bool AnyActiveAnimation(const Element* node) const;

        public:
            // -- batch31 P0-3 caption-button seams (public: headless tests) --
            Rect CaptionButtonRect(int index) const noexcept;
            /// batch31 P0-3 test seam: the three caption-button rects (0 =
            /// minimize, 1 = maximize/restore, 2 = close).
            Rect CaptionButtonRectForTest(int index) const noexcept {
                return CaptionButtonRect(index);
            }
            /// batch31 P0-3: true when `logical` lies on a caption button, with
            /// its index written to `index`.
            bool CaptionButtonAt(Point logical, int& index) const noexcept;
            /// batch31 P0-3: live zoom state (IsZoomed; headless falls back to
            /// the toggle the seams recorded).
            bool IsZoomedNow() const noexcept;
            bool zoomed_for_test() const noexcept { return IsZoomedNow(); }
            /// batch31 P0-3: the glyph painted for one caption button
            /// (minimize minus, maximize square / restore restore-square,
            /// close x).
            std::wstring CaptionGlyph(int index) const;
            std::wstring caption_glyph_for_test(int index) const {
                return CaptionGlyph(index);
            }
            /// batch31 P0-3: maximize <-> restore (SW_MAXIMIZE / SW_RESTORE).
            void ToggleMaximize();
            /// batch31 P0-3: routes one title-bar click to its caption button;
            /// false when the point misses the strip (a plain drag click).
            bool HandleCaptionButtonClick(Point logical);
            /// batch31 P0-3: one title-bar double click (the WM_NCLBUTTONDBLCLK
            /// body). False when the point is not on the title bar.
            bool HandleTitlebarDoubleClick(Point logical);
            bool HandleCaptionButtonClickForTest(Point logical) {
                return HandleCaptionButtonClick(logical);
            }
            bool HandleTitlebarDoubleClickForTest(Point logical) {
                return HandleTitlebarDoubleClick(logical);
            }
            /// batch31 P0-3: toggle counters (monotonic, headless-observable).
            uint64_t maximize_requests() const noexcept {
                return maximize_requests_;
            }
            uint64_t restore_requests() const noexcept {
                return restore_requests_;
            }
            /// batch31 P0-3: the caption hover flags (repaint anchor).
            bool caption_hover_minimize_for_test() const noexcept {
                return caption_hover_.minimize;
            }
            bool caption_hover_maximize_for_test() const noexcept {
                return caption_hover_.maximize;
            }
            bool caption_hover_close_for_test() const noexcept {
                return caption_hover_.close;
            }
            /// batch31 P0-3: the exact WM_NCMOUSEMOVE hover body (headless
            /// anchor: the real path needs a live hwnd for the screen coords).
            bool UpdateCaptionHoverForTest(Point logical) {
                return caption_hover_.Update(CaptionButtonRect(0),
                                             CaptionButtonRect(1),
                                             CaptionButtonRect(2), logical);
            }
            /// batch31 P0-3: the exact WM_NCHITTEST verdict for a CLIENT-space
            /// logical point (headless: no live hwnd to hit test against).
            bool TitlebarIsCaptionForTest(Point logical) const noexcept {
                if (logical.y < 0.0f || logical.y >= titlebar_h_) {
                    return false;
                }
                int index = -1;
                return !CaptionButtonAt(logical, index);
            }

        private:
            LRESULT HitTestNonClient(POINT screen) const noexcept;
            void DrawChrome(float client_w);
            void ArmClientLeaveTracking() noexcept;
            void ArmNcLeaveTracking() noexcept;
            /// Resets caption + element hover (leave paths); repaints on change.
            void ClearHover();
            /// Forwards one hover move; a null hit clears the previous element.
            void DispatchHoverMove(Element* hit, Point logical);
            /// batch26: refreshes the hover tooltip text when it changed.
            /// batch37: only the union of the OLD and NEW tooltip boxes is
            /// invalidated. A full-window repaint here made sliding across a
            /// list (a different hint per row) flicker badly.
            void UpdateHoverTooltip(Element* hit, Point logical);
            /// batch26: paints the hover tooltip above the overlay pass.
            void DrawHoverTooltip(RenderCtx& ctx);
            /// batch37: the tooltip box geometry for `text` anchored at
            /// `anchor`. One formula shared by DrawHoverTooltip and the
            /// invalidation path, so they can never disagree. Empty rect when
            /// the text is empty or no root is bound.
            Rect HoverTooltipBox(const std::wstring& text, Point anchor) const;
            /// Local invalidation helper (T2): repaints only `e`'s bounds when
            /// `e` is in the live tree, visible and has a non-empty box; a
            /// no-op otherwise (never a full-window fallback).
            void InvalidateElement(Element* e);
            /// batch55: same repaint, for a caller that ALREADY knows `e` is in
            /// the live tree (it just recursed into it from the root). The
            /// liveness check above costs a whole-tree DFS, which the animation
            /// walk would otherwise pay once per animating node per frame -
            /// O(N^2) again through a second door. Callers must be able to
            /// prove liveness structurally; anything derived from a stored
            /// pointer must keep using InvalidateElement().
            void InvalidateLiveElement(Element* e);
            /// Shared tail of both helpers (visible/box guards + repaint).
            void InvalidateElementBox(Element* e);
            /// W11 batch6 G-4: the cursor kind for a logical point
            /// (overlay-first topmost hit via HitTestTopmost; no hit and no
            /// root = Arrow). Shared by the WM_SETCURSOR case and the
            /// headless test seams.
            CursorKind ResolveCursorHint(Point logical) const;
            /// W11 batch6 G-4: the one hint -> resource-id mapping
            /// (32513 = IDC_IBEAM, 32512 = IDC_ARROW; numeric forms, per the
            /// T6 non-UNICODE IDC_* macro trap), shared by WM_SETCURSOR and
            /// CursorResourceForTest so the numbers can never drift.
            /// batch18 U2 adds 32644 = IDC_SIZEWE (the table's header
            /// column-resize boundaries).
            static int CursorResourceIdForHint(CursorKind kind) noexcept {
                switch (kind) {
                    case CursorKind::Text:
                        return 32513;  // IDC_IBEAM
                    case CursorKind::SizeWE:
                        return 32644;  // IDC_SIZEWE
                    case CursorKind::Hand:
                        return 32649;  // IDC_HAND (batch19: hyperlinks)
                    default:
                        return 32512;  // IDC_ARROW
                }
            }

            HWND hwnd_ = nullptr;
            HINSTANCE instance_ = nullptr;
            Element* root_ = nullptr;
            Element* focused_ = nullptr;
            /// batch320: the element that had focus when the open modal took
            /// it; restored when the modal closes (validated before use).
            Element* focus_before_dialog_ = nullptr;
            Element* mouse_capture_ = nullptr;
            ContextMenu* edit_menu_ = nullptr;
            RenderCtx renderer_;
            /// batch26: hover tooltip (full text of a truncated label/cell).
            std::wstring hover_tooltip_;
            Point hover_tooltip_point_{};
            HICON small_icon_ = nullptr;
            HICON big_icon_ = nullptr;
            float dpi_ = 96.0f;
            float scale_ = 1.0f;
            /// batch331: the desktop-driven scale, remembered while a FIXED
            /// ui_scale_ override is in force so switching back to auto can
            /// restore it without a live HWND (headless tests, and the window
            /// before Create()).
            float desktop_scale_ = 1.0f;
            /// batch20: fixed UI scale override; <= 0 means auto (desktop DPI).
            float ui_scale_ = 0.0f;
            /// batch20 P1: set at Create; the first WM_DPICHANGED must use the
            /// DESIGN size at the new scale instead of the OS-suggested rect
            /// (that rect was computed from the pre-DPI-change context and is
            /// what shrank the window back to 980x640).
            bool size_sync_pending_ = false;
            /// Last requested physical size (headless P1 anchor).
            Size last_size_request_{};
            // batch329: test-only work area override (see SetWorkAreaForTest).
            Size work_area_override_{};
            bool has_work_area_override_ = false;
            /// batch28: restored geometry (invalid = use the design defaults).
            ui_state::WindowState restored_;
            bool restore_pending_ = false;
            /// batch28: the last NORMAL window rect (GetWindowRect semantics,
            /// physical px) seen while not zoomed/iconic. Saved on close so a
            /// zoomed exit still stores the restore size, and so the saved
            /// rect round-trips exactly (GetWindowPlacement's
            /// rcNormalPosition excludes the invisible DWM frame, which would
            /// shift the window on every launch).
            ui_state::RectI last_normal_rect_{};
            /// batch28: set once the operator moves/resizes the window by hand
            /// (WM_EXITSIZEMOVE), so a later DPI change stops re-applying the
            /// restored geometry.
            bool user_moved_window_ = false;
            /// P1-3: how many ticks the fallback has seen (fires at >= 2).
            int tick_sync_counter_ = 0;
            bool tick_sync_paint_seen_ = false;
            float titlebar_h_ = 40.0f;
            bool com_initialized_ = false;
            bool exit_requested_ = false;
            bool balloon_shown_ = false;
            std::atomic<uint64_t> handler_errors_{0};
            bool tray_active_ = false;
            /// batch25b: set when a close request actually hid the window
            /// (headless-observable; SW_HIDE itself is a no-op without hwnd).
            bool hidden_to_tray_ = false;
            CaptionHover caption_hover_;
            /// batch31 P0-3: headless zoom mirror + toggle counters. With a
            /// live hwnd IsZoomed is authoritative; the mirror only answers
            /// when no window exists (the glyph/toggle seams).
            bool zoomed_for_test_ = false;
            uint64_t maximize_requests_ = 0;
            uint64_t restore_requests_ = 0;
            HoverTarget hover_;  ///< last element fed OnMouseMove (validated)
            bool tracking_client_leave_ = false;
            bool tracking_nc_leave_ = false;
            bool foreground_requested_ = false;  ///< seen Create-time foregrounding
            std::size_t layout_requests_ = 0;
            /// batch29 P3: epochs observed by the last Relayout(), so a
            /// redundant RequestLayout (nothing changed) can be skipped.
            uint64_t arranged_layout_epoch_ = 0;
            uint64_t arranged_tree_epoch_ = 0;
            uint64_t arranged_content_epoch_ = 0;
            /// M1 (batch2, plan C): structural overlay-node cache. See
            /// RefreshOverlayCacheIfStale. `structure_gen_` is bumped on every
            /// topology-changing entry; the mutable trio is the memoised
            /// snapshot (sentinel-seeded so the first access always rebuilds).
            uint64_t structure_gen_ = 0;
            mutable std::vector<Element*> overlay_nodes_;
            mutable uint64_t cached_gen_ = kOverlayCacheSentinel;
            mutable uint64_t cached_epoch_ = kOverlayCacheSentinel;
            /// T7/I2: local invalidations requested by consumed keys (test
            /// seam for the headless no-op InvalidateRect path).
            std::size_t key_invalidations_ = 0;
            /// True while this app has a pending invalidation whose WM_PAINT
            /// has not run yet (T3). A WM_PAINT with this still false is a
            /// system exposure: the retained buffer may be invalid, so Paint
            /// must take the full-clear path (no occlusion ghost).
            bool app_invalidate_pending_ = false;
            /// Animation clock state (T3): true while kAnimationTimerId runs,
            /// last frame's timestamp for the dt, and a frame counter.
            /// T7 status of the T6-recorded limitations:
            ///  - B3 (a hidden element freezes): CONFIRMED harmless - skipping
            ///    the hidden subtree never stops the clock while another visible
            ///    element animates, so siblings are unaffected. The residual -
            ///    a hidden element that is the ONLY animator does not resume
            ///    when re-shown (no unified SetVisible hook) - remains and is
            ///    recorded in CollectAnimationActivity (framework change).
            ///  - B4 (tray-hidden app keeps the 16 ms clock): NOT changed here
            ///    (no hidden-window visibility probe); the clock only runs while
            ///    an element reports an active animation and self-stops on the
            ///    first quiescent frame.
            bool animation_active_ = false;
            std::chrono::steady_clock::time_point last_animation_time_{};
            uint64_t animation_frames_ = 0;
            /// batch29 test seam: a headless client size for Relayout().
            float headless_client_w_ = 0.0f;
            float headless_client_h_ = 0.0f;
            /// M8 (batch3) single-buffer water-level scratch for the per-frame
            /// children snapshot. batch55 retired its only user: the animation
            /// walk now re-reads the live child table by index, so no snapshot
            /// is taken. Kept with a note rather than silently deleted because
            /// any future per-frame snapshot walk should reuse THIS buffer
            /// (the allocation protocol above is still the right shape) instead
            /// of reintroducing a per-node vector.
            std::vector<Element*> anim_kids_scratch_;
            /// U1: local-invalidation observability seam. Headless (no hwnd)
            /// Invalidate()/InvalidateRect() are no-ops, so D3/D4 ("did the
            /// hover/wheel repaint exactly this region, not the whole window?")
            /// cannot be asserted. These record the MOST RECENT request
            /// regardless of hwnd; production semantics are unchanged (the OS
            /// call is still the only real effect).
            uint64_t invalidate_count_ = 0;
            bool last_invalidation_full_ = false;
            Rect last_invalidated_rect_{};
            /// batch29 P1: union of the invalidations since the last reset (the
            /// animation-frame locality anchor).
            Rect invalidation_union_{};
            bool invalidation_full_since_reset_ = false;
            /// T8 metrics: window-level counters (monotonic; never reset).
            uint64_t paint_count_ = 0;
            long long last_paint_us_ = 0;
            Rect last_dirty_rect_{};
            /// M5 (batch11 M12): overlay-phase marker - index into the
            /// renderer's recorded op stream where the overlay segment's
            /// top-level ClipPush was appended (kOverlayPhaseUnset outside a
            /// recording session). See PaintOrchestrate.
            std::size_t overlay_phase_ops_index_ = kOverlayPhaseUnset;
            /// M5 frame statistics: rolling 60-slot ring buffer of frame
            /// intervals (O(1) push via head/len/sum), the largest paint
            /// duration, and the dropped-frame counter (paint > kFrameBudgetUs).
            /// All headless-observable via RecordFrameForTest; 0 while no frame
            /// has been recorded.
            long long frame_interval_hist_[kFrameStatsWindow]{};
            int frame_interval_head_ = 0;
            int frame_interval_len_ = 0;
            long long frame_interval_sum_us_ = 0;
            uint64_t frame_time_max_us_ = 0;
            uint64_t over_budget_frames_ = 0;
            /// Wall-clock anchor of the last recorded frame (us since steady
            /// epoch); -1 before any frame. fps() reads the live gap against
            /// this to return 0 for a static (idle) page.
            long long last_paint_wall_us_ = -1;
            uint64_t tick_count_ = 0;
            long long last_tick_us_ = 0;
            /// T8: injected modifier mask (0 = read ::GetKeyState as before).
            /// bit 0 Shift, bit 1 Ctrl, bit 2 Alt.
            unsigned modifiers_override_ = 0;
            bool modifiers_injected_ = false;
        };

    }  // namespace ui
}  // namespace vgww
