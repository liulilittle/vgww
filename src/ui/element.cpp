// ============================================================================
// element.cpp - element tree mechanics: layout cache, hit testing, focus.
// ============================================================================
#include "ui/element.h"

#include "ui/renderer.h"

#include <unordered_set>

namespace vgww {
    namespace ui {

        namespace {

            /// Animation-request holder (same seam shape as SetTextMeasure).
            std::function<void()> g_animation_requester;

            /// batch29 P2: elements whose content changed since the last
            /// Update drain (UI thread only; hard-capped so a pathological
            /// headless run cannot grow it without bound).
            std::vector<Element*> g_content_dirty;
            constexpr std::size_t kMaxContentDirty = 4096;

            /// batch29 P1/P2: local-repaint requester (window-installed).
            std::function<void(Element*)> g_element_repaint_requester;

            void CollectFocusable(Element& element, std::vector<Element*>& out) {
                if (!element.visible || !element.enabled) {
                    return;  // hidden/disabled subtrees are not reachable by Tab
                }
                if (element.focusable()) {
                    out.push_back(&element);
                }
                for (const auto& child : element.children()) {
                    CollectFocusable(*child, out);
                }
            }

        }  // namespace

        Element* Element::Add(std::unique_ptr<Element> child) {
            child->parent_ = this;
            Element* raw = child.get();
            children_.push_back(std::move(child));
            // batch37g: a dynamic build (a dialog card, a context menu, a new
            // Select) must invalidate the window's overlay HIT cache, which is
            // keyed on this epoch. Without it a popup created after the last
            // cache build was painted but unclickable and unclosable.
            ++UiTreeEpoch();
            // M4-P3: appending a child may change this element's desired size,
            // so the layout cache on this element and every ancestor must be
            // dropped (the next Arrange re-measures with the new child set).
            InvalidateLayout();
            return raw;
        }

        Size Element::Measure(Size available) {
            const bool size_changed = available.w != measured_size_.w ||
                                      available.h != measured_size_.h;
            if (!desired_valid_ || size_changed) {
                desired_ = MeasureCore(available);
                measured_size_ = available;
                desired_valid_ = true;
                // M9 (batch4): an actual core run - invalidates every parent
                // child-measure memo that stored its value before this ran.
                ++measure_gen_;
            }
            return desired_;
        }

        bool Element::EffectivelyEnabled() const noexcept {
            for (const Element* e = this; e != nullptr; e = e->parent_) {
                if (!e->enabled) {
                    return false;
                }
            }
            return true;
        }

        void Element::Arrange(Rect final_rect) {
            bounds_ = final_rect;
            Measure(final_rect.size());
            ArrangeCore(final_rect);
            RefreshSubtreeBounds();
        }

        void Element::RefreshSubtreeBounds() {
            // Bottom-up union (M4-F1): the element's own box (always a
            // superset of everything it paints) widened by every visible
            // child's subtree union. Fail-open: a degenerate union falls back
            // to bounds_ so an empty rect can never poison the union into
            // over-rejecting.
            //
            // M4-F7 (audit-B blocking): the union must be seeded from bounds_,
            // NEVER from invalidation_bounds(). That override is a *repaint*
            // hint and may legitimately return a SUBSET of the box --
            // TableElement returns just the hovered row band while a row is
            // hovered. Seeding with it collapsed the cached union to one 28px
            // strip after any Arrange performed while hovering, and then
            // Element::HitTest's fast reject swallowed every other row:
            // culling changed hit results, breaking the core M4 contract
            // ("culling must not change hit results") and inverting C2's
            // fail-open direction (the
            // union is only ever allowed to grow). So the override is a
            // WIDENING term, never the seed.
            Rect u = invalidation_bounds();
            Rect v = bounds_;
            // Expand v until it also covers u (u may be a superset, e.g. an
            // expanded Select popup, or a subset, e.g. a table hover band).
            if (u.w > 0.0f && u.h > 0.0f) {
                const float x0 = (u.x < v.x) ? u.x : v.x;
                const float y0 = (u.y < v.y) ? u.y : v.y;
                const float x1 = (u.x + u.w > v.x + v.w) ? u.x + u.w : v.x + v.w;
                const float y1 = (u.y + u.h > v.y + v.h) ? u.y + u.h : v.y + v.h;
                v = Rect{x0, y0, x1 - x0, y1 - y0};
            }
            // Fail-open (C2): a degenerate own box keeps the widened rect, and
            // if that is somehow still degenerate the union is left as bounds_.
            if (v.w <= 0.0f || v.h <= 0.0f) {
                v = bounds_;
            }
            Rect merged = v;
            for (const auto& child : children_) {
                if (!child->visible) {
                    continue;
                }
                const Rect cs = child->SubtreeBoundsOrSelf();
                if (cs.w <= 0.0f || cs.h <= 0.0f) {
                    continue;  // degenerate child: skip, it cannot paint
                }
                const float x0 = (merged.x < cs.x) ? merged.x : cs.x;
                const float y0 = (merged.y < cs.y) ? merged.y : cs.y;
                const float x1 = (merged.x + merged.w > cs.x + cs.w)
                                     ? merged.x + merged.w
                                     : cs.x + cs.w;
                const float y1 = (merged.y + merged.h > cs.y + cs.h)
                                     ? merged.y + merged.h
                                     : cs.y + cs.h;
                merged = Rect{x0, y0, x1 - x0, y1 - y0};
            }
            subtree_bounds_ = merged;
            subtree_valid_ = true;
        }

        Rect Element::SubtreeBoundsOrSelf() const noexcept {
            if (subtree_valid_) {
                return subtree_bounds_;
            }
            // Fail-open (M4-F1/C2): an unrefreshed subtree must never be
            // culled as a whole, so report a region at least as large as the
            // own box.
            return bounds_;
        }

        void Element::ArrangeCore(Rect final_rect) {
            ArrangeChildren(final_rect);
        }

        void Element::ArrangeChildren(Rect content) {
            for (const auto& child : children_) {
                if (child->visible) {
                    child->Arrange(content);
                }
            }
        }

        void Element::Render(RenderCtx& ctx) {
            if (!visible) {
                return;
            }
            // Perf: when the window sets a cull rect (dirty-rect paint), skip
            // this element's own drawing when its bounds fall outside it. The
            // child recursion below still runs: a child may paint beyond the
            // parent box, and each child culls itself by its own bounds.
            if (!ctx.CulledOut(bounds_)) {
                RenderCore(ctx);
            }
            // M4-F1: whole-subtree reject. When the cached subtree union is
            // valid (refreshed by the last Arrange) and a cull rect is active
            // that the union misses, neither this element nor any descendant
            // can paint, so the walk stops here. Fail-open: an invalid union
            // (C2) never prunes, and no cull rect means CulledOut is always
            // false, so the tree is walked as before.
            if (subtree_valid_ && ctx.HasCullRect() && ctx.CulledOut(subtree_bounds_)) {
                return;
            }
            RenderChildren(ctx);
        }

        void Element::RenderChildren(RenderCtx& ctx) {
            for (const auto& child : children_) {
                // Top-layer children (modal dialogs, toasts) are painted by
                // VgwwWindow::Paint's overlay pass, never in the content pass;
                // skipping them here also keeps a translucent dimmer from being
                // source-over composited twice.
                if (child->renders_on_top()) {
                    continue;
                }
                child->Render(ctx);
            }
        }

        Element* Element::HitTest(Point p) {
            if (!visible || !EffectivelyEnabled()) {
                return nullptr;  // hidden/disabled: the whole subtree is inert
            }
            // M4-F1: subtree fast-reject. When the cached union (self +
            // painted descendants, refreshed by Arrange) is valid and the
            // point falls outside it, nothing in this subtree can be hit,
            // so the whole walk stops. Fail-open (C2): an invalid union
            // falls through to the full recursive probe. The union is a
            // superset of every child's own box, so this never swallows a
            // child hit that the bounds probe below would have found (U3
            // semantics preserved: an expanded popup outside the parent box
            // is inside the union).
            if (subtree_valid_ && !subtree_bounds_.Contains(p)) {
                return nullptr;
            }
            // Topmost first: children are painted after their parent.
            for (auto it = children_.rbegin(); it != children_.rend(); ++it) {
                if (Element* hit = (*it)->HitTest(p)) {
                    return hit;
                }
            }
            // A point outside this element's own box is still probed through
            // to the children (each decides by its own bounds), so an expanded
            // overlay popup painted beyond the parent box stays clickable
            // (U3). Hit-transparent elements never return self; neither does
            // an element that does not contain the point.
            if (!bounds_.Contains(p) || hit_transparent) {
                return nullptr;
            }
            return this;
        }

        void Element::InvalidateLayout() {
            ++UiLayoutEpoch();
            for (Element* e = this; e != nullptr; e = e->parent_) {
                e->desired_valid_ = false;
                // M4/F1: the cached subtree extent goes stale together with the
                // layout cache (a child may have been added, a popup expanded,
                // or the measure changed). Clearing it on the ancestor chain
                // keeps the conservative union from outliving the geometry it
                // summarises; Render/HitTest fall back to a full walk until
                // Arrange rebuilds it.
                e->subtree_valid_ = false;
            }
        }

        std::vector<Element*> FocusChain(Element& root) {
            std::vector<Element*> out;
            CollectFocusable(root, out);
            return out;
        }

        void SetAnimationRequester(std::function<void()> fn) {
            g_animation_requester = std::move(fn);
        }

        void RequestAnimationFrame() {
            if (g_animation_requester != nullptr) {
                g_animation_requester();
            }
        }

        void NoteElementContentChanged(Element* element) {
            if (element == nullptr ||
                g_content_dirty.size() >= kMaxContentDirty) {
                return;
            }
            g_content_dirty.push_back(element);
        }

        void DrainContentDirtyElements(std::vector<Element*>& out) {
            out.insert(out.end(), g_content_dirty.begin(), g_content_dirty.end());
            g_content_dirty.clear();
        }

        void SetElementRepaintRequester(std::function<void(Element*)> fn) {
            g_element_repaint_requester = std::move(fn);
        }

        void RequestElementRepaint(Element* element) {
            if (g_element_repaint_requester != nullptr) {
                g_element_repaint_requester(element);
            }
        }

        namespace {
            std::function<void()> g_layout_requester;
        }  // namespace

        void SetLayoutRequester(std::function<void()> fn) {
            g_layout_requester = std::move(fn);
        }

        void RequestLayoutFrame() {
            if (g_layout_requester != nullptr) {
                g_layout_requester();
            }
        }

        uint64_t& UiTreeEpoch() {
            static uint64_t epoch = 0;
            return epoch;
        }

        uint64_t& UiLayoutEpoch() {
            static uint64_t epoch = 0;
            return epoch;
        }

        uint64_t& UiContentEpoch() {
            static uint64_t epoch = 0;
            return epoch;
        }

        namespace {
            /// batch56: the liveness registry (see element.h).
            ///
            /// Deliberately IMMORTAL: heap-allocated once and never destroyed.
            /// A function-local static would be destroyed in reverse order of
            /// construction, which is only "after every Element" if no Element
            /// outlives it - and an Element at file scope in some future
            /// translation unit would make the registry die first, so its own
            /// destructor would touch freed memory. Never destroying it removes
            /// that question instead of reasoning about it. The cost is one
            /// container's worth of memory returned to the OS at process exit.
            std::unordered_set<const Element*>& LiveElements() {
                static std::unordered_set<const Element*>* live =
                    new std::unordered_set<const Element*>();
                return *live;
            }
        }  // namespace

        // Not noexcept on purpose: the first call allocates the registry and a
        // later one may grow it. Reporting bad_alloc is correct (see element.h);
        // a stray noexcept would turn that into std::terminate().
        void RegisterLiveElement(const Element* element) {
            if (element != nullptr) {
                LiveElements().insert(element);
            }
        }

        void UnregisterLiveElement(const Element* element) noexcept {
            if (element != nullptr) {
                LiveElements().erase(element);
            }
        }

        bool IsLiveElement(const Element* element) noexcept {
            if (element == nullptr) {
                return false;
            }
            return LiveElements().count(element) != 0;
        }

    }  // namespace ui
}  // namespace vgww
