// ============================================================================
// element.h - retained-mode element tree for the native UI (S4.2 Task 2).
//
// Elements form a tree of layout boxes: Measure -> Arrange -> Render. All
// layout and interaction logic is headless-testable; drawing only happens
// through the RenderCtx adapter (T6). Geometry: Size lives in theme.h (the
// text-measure seam needs it); Rect/Point live here.
// ============================================================================
#pragma once

#include "ui/theme.h"
#include "ui/debug/debug_state.h"

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace vgww {
    namespace ui {

        struct Point {
            float x = 0.0f;
            float y = 0.0f;
        };

        struct Rect {
            float x = 0.0f;
            float y = 0.0f;
            float w = 0.0f;
            float h = 0.0f;

            /// Half-open containment: left/top inclusive, right/bottom exclusive.
            bool Contains(Point p) const noexcept {
                return p.x >= x && p.x < x + w && p.y >= y && p.y < y + h;
            }
            /// M4/C1: the ONE half-open interval-overlap predicate. A degenerate
            /// rect on either side (w/h <= 0) never overlaps. Every overlap test
            /// in the UI layer routes through this: RenderCtx::CulledOut is its
            /// negation (plus the cull-active gate) and the window's
            /// dirty-vs-titlebar test calls it directly, so the two callers can
            /// never drift apart (batch2 A-2: a second implementation is banned).
            bool Intersects(const Rect& o) const noexcept {
                return w > 0.0f && h > 0.0f && o.w > 0.0f && o.h > 0.0f &&
                       x < o.x + o.w && o.x < x + w &&
                       y < o.y + o.h && o.y < y + h;
            }
            Size size() const noexcept { return Size{w, h}; }
        };

        /// Drawing adapter defined by the renderer (renderer.h, T6). Elements
        /// only forward it to RenderCore.
        struct RenderCtx;

        /// M6 (batch3): process-wide monotone CONTENT epoch. Every
        /// Element::content_rev increment also bumps this counter (the
        /// ContentRev wrapper enforces it type-level), so UiApp::Update() can
        /// detect "some element content changed since the cached sample" in
        /// O(1) instead of summing the whole tree. Deliberately SEPARATE from
        /// UiTreeEpoch: the window's overlay structure cache consumes the
        /// tree epoch (RefreshOverlayCacheIfStale) and must not be
        /// invalidated by content-only bumps. UI thread only.
        uint64_t& UiContentEpoch();

        class Element;

        /// batch56: process-wide registry of elements whose destructor has NOT
        /// started yet. Why it exists: a traversal that snapshots raw child
        /// pointers and then lets user code mutate the tree must be able to ask
        /// "is this pointer still an Element?" WITHOUT dereferencing it (a
        /// dereference would be use-after-free). The old answer was a whole-tree
        /// DFS per pointer (ElementInTree), which is O(N) each - O(N^2) inside a
        /// walk. A hash lookup on the pointer value is O(1) and never touches
        /// the object.
        /// Exact semantic (deliberately narrower than "in the tree"): an object
        /// is registered by its constructor and removed at the ENTRY of its
        /// destructor, so during a subtree teardown the dying parent reads as
        /// dead while its (still registered) children read as alive. That is
        /// sufficient here because a subtree being destroyed has already been
        /// detached from its parent's child table (erase destroys only after
        /// unlinking), so the walk can never reach it; and nothing runs the
        /// walk from a destructor. Do not use this as a substitute for
        /// ElementInTree when "in the tree" matters.
        /// Pointer <-> immortal singleton (never destroyed, so no static
        /// destruction-order hazard); UI thread only.
        /// NOT noexcept: the very first registration allocates the registry and
        /// a node may need to grow it, so an out-of-memory condition must
        /// propagate as bad_alloc (from the Element constructor) rather than
        /// being silently converted to terminate() by a false noexcept. Throwing
        /// here is safe: unordered_set::insert has the strong guarantee, and a
        /// half-constructed Element that already registered is still
        /// unregistered, because a throwing constructor still runs the
        /// destructors of its fully-constructed bases and members.
        void RegisterLiveElement(const Element* element);
        /// noexcept: erase() never allocates, and the destructor must not throw.
        void UnregisterLiveElement(const Element* element) noexcept;
        /// True when `element` is a currently constructed Element. Never
        /// dereferences `element`; a null pointer is false.
        bool IsLiveElement(const Element* element) noexcept;

        /// batch29 P2: records the element whose content changed so UiApp's
        /// Update can repaint only the affected region instead of forcing a
        /// whole-window layout + full repaint per snapshot tick. Called from
        /// ContentRev::operator++ (owner is wired by Element's constructor);
        /// UI thread only. The list is drained once per Update.
        void NoteElementContentChanged(Element* element);
        /// Moves the recorded dirty elements into `out` and clears the list.
        void DrainContentDirtyElements(std::vector<Element*>& out);

        /// M6 (batch3): wrapper for Element::content_rev. Every increment
        /// (prefix and postfix) also bumps UiContentEpoch(), so a content
        /// change can never bypass the O(1) Update() detection - the type
        /// enforces what a raw counter plus hand-written bump calls merely
        /// promised. It implicitly converts to uint64_t, so comparisons,
        /// memo keys and exact-value assertions keep their value semantics;
        /// assigning a raw integer does NOT compile, so any future writer
        /// must use the increment that carries the bump. batch29: the owning
        /// Element is recorded too (local repaint).
        struct ContentRev {
            uint64_t value = 0;
            Element* owner = nullptr;

            ContentRev& operator++() noexcept {
                ++value;
                ++UiContentEpoch();
                NoteElementContentChanged(owner);
                return *this;
            }
            ContentRev operator++(int) noexcept {
                ContentRev previous = *this;
                ++*this;
                return previous;
            }
            operator uint64_t() const noexcept { return value; }
        };

        /// W11 batch6 G-4: the OS cursor a hit element requests. Semantic
        /// names, deliberately NOT the Win32 IDC_* values: window.cpp owns
        /// the mapping to the actual cursor resources (IDC_IBEAM/IDC_ARROW/
        /// IDC_SIZEWE). Element's default is Arrow; text-entry controls
        /// override with Text; batch18 U2 adds SizeWE for the table's
        /// header column-resize boundaries.
        enum class CursorKind { Arrow, Text, SizeWE, Hand };

        /// Base class of every element. Layout is cached until
        /// InvalidateLayout() (bottom-up changes invalidate ancestors).
        /// batch288: the window must tell "nothing to paste" from "the clipboard
        /// could not be read". A plain bool conflated them, so a clipboard held by
        /// another process made Ctrl+V / the edit menu silently do nothing.
        enum class PasteResult { Pasted, NothingToPaste, Failed };

        class Element {
        public:
            /// batch29: wires ContentRev::owner so every content bump is
            /// attributable to this element (local repaint bookkeeping).
            /// batch56: also joins the process-wide liveness registry, so an
            /// already-destroyed pointer can be recognised in O(1) WITHOUT
            /// dereferencing it (see IsLiveElement).
            Element() {
                content_rev.owner = this;
                RegisterLiveElement(this);
            }
            virtual ~Element() { UnregisterLiveElement(this); }

            /// Appends `child` (takes ownership) and returns a borrowed pointer.
            Element* Add(std::unique_ptr<Element> child);
            const std::vector<std::unique_ptr<Element>>& children() const noexcept {
                return children_;
            }
            Element* parent() const noexcept { return parent_; }

            const Rect& bounds() const noexcept { return bounds_; }
            const Size& desired() const noexcept { return desired_; }

            /// M9 (batch4) read-only measurement-cache probes: `desired_valid`
            /// mirrors the cache-validity flag and `measure_gen` is a monotone
            /// counter bumped by every actual MeasureCore run. The StackPanel
            /// child-measure memo (controls.cpp) compares both (plus the full
            /// available-size key and ui::TextMeasureGeneration) before it
            /// hands out a previously measured value; a mismatch falls back to
            /// the unmodified Measure path.
            bool desired_valid() const noexcept { return desired_valid_; }
            uint64_t measure_gen() const noexcept { return measure_gen_; }

            std::string id;                 ///< test/debug anchor (interactive elements)
            bool visible = true;
            bool enabled = true;
            /// Never returns itself from HitTest (its children may still hit).
            bool hit_transparent = false;
            /// B5-2 (batch5): opt-in "claim the remaining main-axis capacity"
            /// marker consumed by StackPanel. At most one visible marked flow
            /// child per stack: it is offered what the other visible non
            /// overlay children leave over (minus the gaps) and is CAPPED to
            /// that capacity, never stretched beyond its own claim. Default
            /// false: every unmarked tree keeps its exact layout.
            bool fill_remaining = false;
            ContentRev content_rev;         ///< bumped on data change (repaint trigger)

            /// CDP-style debug seam: stable class tag for query/dedup.
            virtual const char* debug_role() const { return "Element"; }
            /// CDP-style debug seam: per-control scalar state. Base is empty.
            virtual void debug_state(DebugStateSink&) const {}

            /// Measures (cached by the available size) and returns the desired
            /// size; a different `available` re-measures instead of reusing
            /// the stale cache.
            Size Measure(Size available);
            /// Measures then arranges into `final_rect` (bounds become valid).
            void Arrange(Rect final_rect);
            /// Draws this element and its visible children.
            void Render(RenderCtx& ctx);
            /// Deepest hit under `p`. Hidden elements and effectively-disabled
            /// elements (a disabled ancestor makes the whole subtree inert) are
            /// never hit; hit_transparent elements return no self but their
            /// children may still hit. Points outside an element's own bounds
            /// still probe its children, so an expanded overlay popup painted
            /// beyond the parent box stays clickable (U3).
            virtual Element* HitTest(Point p);

            /// True when this element and every ancestor are enabled
            /// (a disabled element makes its whole subtree inert).
            bool EffectivelyEnabled() const noexcept;

            /// Invalidates the cached desired size on this element and every
            /// ancestor (children keep their caches).
            void InvalidateLayout();

            /// The region a state change on this element must repaint. The
            /// base class reports only the own box; controls that paint
            /// outside it (an expanded Select popup) override this to return
            /// the box + popup union. The window's local-invalidation path
            /// (InvalidateElement) reads this via the base pointer.
            ///
            /// M4/audit-A observation 2 rule: this region is ALSO the starting
            /// point
            /// of the M4-F1 subtree union (RefreshSubtreeBounds), which drives
            /// both the whole-subtree cull early-out and the HitTest fast
            /// reject. So any control that DRAWS or is HIT-TESTABLE beyond its
            /// own bounds MUST override this to include that out-of-box
            /// region - otherwise the cull path drops its pixels (a draw
            /// outside the union is still culled by the parent's subtree
            /// reject) and the hit path swallows the click. Failing to
            /// override is not a style issue: it is a correctness hole in
            /// two independent runtime paths.
            virtual Rect invalidation_bounds() const noexcept { return bounds(); }

            /// W11 batch6 G-4: which cursor the window should show while the
            /// pointer is over this element (WM_SETCURSOR resolves the
            /// overlay-first topmost hit through this). Default = Arrow;
            /// TextInputElement overrides with Text (I-beam). batch18 U2:
            /// the fresh logical point is passed through so a stateless
            /// override may vary by position (TableElement's header
            /// boundaries request SizeWE).
            virtual CursorKind cursor_hint(Point) const noexcept {
                return CursorKind::Arrow;
            }

            virtual bool focusable() const { return false; }

            /// Overlay elements (modal dialogs) are arranged over the whole
            /// client area and take no slot in the parent's flow layout.
            virtual bool is_overlay() const { return false; }

            /// True when this element (and its subtree) must be painted in the
            /// window's top layer instead of the normal content pass. The
            /// window's main traversal (Element::RenderChildren) skips such
            /// children; VgwwWindow::Paint draws them via RenderOverlay after
            /// the whole content tree. Distinct from is_overlay(), which only
            /// carries measure/arrange semantics.
            virtual bool renders_on_top() const { return false; }

            /// Draws this element's top-layer contribution. Called for every
            /// visible node by the window's overlay DFS after the main pass.
            /// The default draws nothing.
            virtual void RenderOverlay(RenderCtx&) {}

            /// Self-only overlay hit test: returns this when the point is on
            /// this element's top-layer surface, else nullptr. Ancestor clips
            /// are deliberately ignored so an expanded popup painted beyond a
            /// ScrollView viewport stays clickable. The window combines the
            /// per-node results (HitTestOverlay) before falling back to
            /// Element::HitTest.
            virtual Element* HitTestOverlay(Point) { return nullptr; }
            /// batch26: full text to show in the window tooltip for `p`, or
            /// empty when nothing is truncated. Default: no tooltip. Painted
            /// after the overlay pass; never hit-testable.
            virtual std::wstring tooltip_text(Point) const {
                return std::wstring();
            }
            /// batch28: an explicit hover tooltip that does not depend on
            /// truncation (e.g. a shortened diagnostic line whose full device
            /// path must stay reachable). Empty = none. The window prefers it
            /// over tooltip_text().
            void SetTooltip(std::wstring text) { tooltip_ = std::move(text); }
            const std::wstring& tooltip() const noexcept { return tooltip_; }

            /// batch33 E: closes this element's top-layer surface (an open
            /// context menu / an expanded Select popup). The window walks the
            /// overlay nodes on Esc and swallows the key when any of them
            /// consumed it. Default: nothing to dismiss.
            virtual bool DismissOverlay() { return false; }

            // Events: return true when consumed.
            virtual bool OnMouseDown(Point) { return false; }
            virtual bool OnMouseUp(Point) { return false; }
            virtual bool OnMouseMove(Point) { return false; }
            /// batch37e: a real double click (WM_LBUTTONDBLCLK). Windows sends
            /// this INSTEAD of the second button-down, so a control that wants
            /// double-click semantics overrides this rather than counting downs.
            virtual bool OnMouseDoubleClick(Point) { return false; }
            // batch37i: clipboard/select-all capability. Default = not editable.
            // The window routes Ctrl+C/X/V/A to these so read-only surfaces
            // (the console log) can implement copy/select without pretending
            // to be a text input.
            virtual bool CopySelectionToClipboard() { return false; }
            virtual bool CutSelectionToClipboard() { return false; }
            virtual PasteResult PasteFromClipboard() {
                return PasteResult::NothingToPaste;
            }
            virtual bool SelectAllText() { return false; }
            // batch37o: context-menu capability + state for the standard edit
            // menu. A read-only surface (console) opts in too, but only the
            // editable TextInput overrides undo/redo/cut/paste.
            virtual bool EditMenuTarget() const { return false; }
            virtual bool CanUndoEdit() const { return false; }
            virtual bool CanRedoEdit() const { return false; }
            virtual bool HasTextSelection() const { return false; }
            virtual bool HasTextContent() const { return false; }
            /// batch33 E: right-button release. A control that owns a
            /// contextual action (the tables) consumes it; the window bubbles
            /// an unconsumed right-up up the parent chain.
            virtual bool OnMouseRightUp(Point) { return false; }
            /// batch321: the keyboard's own context-menu gesture (Shift+F10
            /// or the Menu key) on the focused element. Returns true when it
            /// opened a menu.
            virtual bool OpenContextMenuForKeyboard() { return false; }
            virtual bool OnKeyDown(uint32_t) { return false; }
            /// Key release. Default: not consumed (no control consumes a key
            /// release today; the debug channel routes it through the same
            /// FocusChain so the release path is observable/testable).
            virtual bool OnKeyUp(uint32_t) { return false; }
            virtual bool OnChar(wchar_t) { return false; }
            virtual bool OnWheel(int) { return false; }
            /// True for elements that own a scrollable viewport: they clip
            /// their content, keep an offset, and both the wheel and the six
            /// navigation keys move that offset. This is the single predicate
            /// the window uses wherever it needs "the nearest scroll
            /// container" (wheel bubbling, wheel repaint box, keyboard
            /// fallback, Select-popup viewport test) - naming concrete types
            /// at those sites meant a new scrolling surface was silently
            /// excluded from all of them at once (batch34x: the console log).
            ///
            /// NOT the same as "consumes the wheel": SelectElement and
            /// LanguagePicker scroll their POPUP list but own no viewport, so
            /// they leave this false.
            virtual bool IsScrollContainer() const noexcept { return false; }
            virtual void OnFocus(bool) {}
            /// Periodic visual-phase tick driven by the window's caret blink
            /// timer (S5.19). Returns true when the element's appearance
            /// changed and the window should repaint just its bounds. The
            /// default reports no change; TextInputElement flips the caret
            /// visibility here.
            virtual bool OnCaretBlinkTick() noexcept { return false; }

            /// Advances this element's animation by one frame (`dt_seconds`).
            /// Default: no animation (empty implementation).
            virtual void AdvanceAnimation(float dt_seconds) { (void)dt_seconds; }
            /// True while an animation is in progress and the ~16 ms frame
            /// clock must keep running. Default: false.
            virtual bool HasActiveAnimation() const noexcept { return false; }
            /// batch63: true when the LAST AdvanceAnimation produced a VISIBLE
            /// change, so the window must repaint this element's box. The frame
            /// clock keeps running either way (the element still reports
            /// HasActiveAnimation), which lets a slow indicator decouple its
            /// update rate from the shared clock. Default TRUE: every existing
            /// animation keeps the exact per-frame invalidation it had before.
            virtual bool AnimationNeedsRepaint() const noexcept { return true; }

        protected:
            /// Leaf/container-specific measurement; called by Measure().
            virtual Size MeasureCore(Size available) = 0;
            /// Default: ArrangeChildren(final_rect).
            virtual void ArrangeCore(Rect final_rect);
            /// Rebuilds subtree_bounds_ bottom-up (M4-F1). Called at the end
            /// of Arrange(); reads invalidation_bounds() (overridable) and the
            /// children's cached unions, so it must run after ArrangeCore has
            /// placed the subtree.
            void RefreshSubtreeBounds();
            /// Cached subtree union when valid, else the own box (fail-open,
            /// M4-F1/C2): an unrefreshed subtree is never culled as a whole.
            Rect SubtreeBoundsOrSelf() const noexcept;
            virtual void RenderCore(RenderCtx&) {}
            /// Draws every visible child. ScrollView overrides it to clip its
            /// content between a ClipPush/ClipPop pair (T8-F2).
            virtual void RenderChildren(RenderCtx& ctx);
            /// Arranges every visible child into `content`.
            void ArrangeChildren(Rect content);

            std::vector<std::unique_ptr<Element>> children_;
            Rect bounds_;
            Size desired_;
            Size measured_size_;
            bool desired_valid_ = false;
            /// M9 (batch4): monotone per-element MeasureCore-run counter.
            /// Only ever incremented by Element::Measure when it actually
            /// re-measures; the StackPanel child memo keys on it.
            uint64_t measure_gen_ = 0;
            /// M4-F1: union of this element's cull-relevant region and every
            /// visible descendant's, refreshed bottom-up after each Arrange.
            /// Render/HitTest use it to cull whole subtrees at once. `mutable`
            /// so const callers can read the cached union. `subtree_valid_` is
            /// cleared by InvalidateLayout (like desired_valid_) and re-armed
            /// by the next Arrange pass; fail-open when invalid (C2).
            mutable Rect subtree_bounds_{};
            mutable bool subtree_valid_ = false;

        private:
            Element* parent_ = nullptr;
            /// batch28: explicit hover tooltip (see SetTooltip).
            std::wstring tooltip_;
        };

        /// Focusable elements in tree (pre-order) order. Hidden or disabled
        /// subtrees are skipped; the caller does Tab/Shift+Tab cycling over
        /// the returned list (T6 input routing).
        std::vector<Element*> FocusChain(Element& root);

        /// Animation-request seam (same shape as ui::SetTextMeasure): the
        /// window installs a requester at construction; a control that starts
        /// an animation calls RequestAnimationFrame() to have the window spin
        /// up its ~16 ms frame clock. `nullptr` installs a no-op.
        void SetAnimationRequester(std::function<void()> fn);
        /// Asks the installed requester (if any) for an animation frame.
        /// UI thread only; a missing requester is a safe no-op.
        void RequestAnimationFrame();

        /// Layout-request seam (batch20, same shape as the animation
        /// requester): the window installs a requester at construction; a
        /// control whose IN-LAYOUT size changed (a picker expanding its list)
        /// calls RequestLayoutFrame() so the host re-arranges deterministically
        /// instead of relying on the tick's content-epoch heuristic - that
        /// heuristic can be refreshed away and leave stale geometry (observed:
        /// the About picker's expanded list painted over the license line).
        void SetLayoutRequester(std::function<void()> fn);
        /// Asks the installed requester (if any) for a layout pass.
        /// UI thread only; a missing requester is a safe no-op.
        void RequestLayoutFrame();

        /// batch29 P1/P2: local-repaint seam. The window installs a requester
        /// that invalidates the given element's own region; controls whose
        /// pixels changed without a layout change (a new sparkline column)
        /// call this instead of bumping the global content epoch, so a
        /// snapshot tick no longer forces a whole-window repaint.
        void SetElementRepaintRequester(std::function<void(Element*)> fn);
        /// Asks the installed requester (if any) to repaint `element`.
        /// UI thread only; a missing requester is a safe no-op.
        void RequestElementRepaint(Element* element);

        /// Monotone structural epoch of the element tree. Every element's
        /// content_rev only ever grows, but the tree SUM can FALL when a node
        /// is removed; a monotone epoch bumped on such removals lets Update()
        /// detect a structural change it could not infer from the sum alone
        /// (T5 perf: single-walk layout detection). UI thread only.
        uint64_t& UiTreeEpoch();

        /// batch29 P3: monotone epoch bumped by EVERY Element::InvalidateLayout
        /// (and by Add). The window compares it with the value its last
        /// Relayout() observed, so a redundant RequestLayout (two callers for
        /// one change) no longer re-arranges the whole tree a second time.
        uint64_t& UiLayoutEpoch();

    }  // namespace ui
}  // namespace vgww
