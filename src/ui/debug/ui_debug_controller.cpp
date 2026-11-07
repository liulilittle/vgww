#include "ui/debug/ui_debug_controller.h"

#include "ui/app.h"
#include "ui/controls.h"
#include "ui/i18n.h"
#include "ui/pages/page.h"
#include "ui/router.h"
#include "ui/tray.h"
#include "ui/window.h"

#include <windows.h>  // VK_* key codes (NOMINMAX already set by window.h)

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <string>
#include <vector>

namespace vgww {
    namespace ui {

        namespace {

            /// Returns the command's options. Commands may carry them either
            /// nested under "opts" (the batch form) or as flat top-level
            /// fields (the concise form the input tests use); when there is no
            /// nested object the command itself is the option bag.
            nlohmann::json Opts(const nlohmann::json& cmd) {
                if (cmd.contains("opts") && cmd["opts"].is_object()) {
                    return cmd["opts"];
                }
                return cmd;
            }

            /// Named virtual-key lookup for the `key` op. Unknown -> 0.
            uint32_t KeyNameToVk(const std::string& name) noexcept {
                if (name == "Left") return VK_LEFT;
                if (name == "Right") return VK_RIGHT;
                if (name == "Up") return VK_UP;
                if (name == "Down") return VK_DOWN;
                if (name == "Home") return VK_HOME;
                if (name == "End") return VK_END;
                if (name == "Delete") return VK_DELETE;
                if (name == "Backspace") return VK_BACK;
                if (name == "Enter") return VK_RETURN;
                if (name == "Tab") return VK_TAB;
                if (name == "Space") return VK_SPACE;
                // batch33 E: Esc closes an open context menu / popup. Without
                // this name the debug `key` op resolved to VK 0, so the
                // "Esc closes the menu" contract could not be exercised over
                // the debug port at all (the unit test called OnKeyDown
                // directly and never noticed).
                if (name == "Escape" || name == "Esc") return VK_ESCAPE;
                return 0;
            }

            /// Decodes UTF-8 (the JSON wire encoding) into the UTF-16 text the
            /// controls store. Used by value_equals so non-ASCII values compare
            /// correctly instead of byte-widening each UTF-8 code unit.
            std::wstring Utf8ToWide(const std::string& s) {
                if (s.empty()) {
                    return std::wstring();
                }
                const int n = ::MultiByteToWideChar(
                    CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr,
                    0);
                if (n <= 0) {
                    return std::wstring();
                }
                std::wstring out(static_cast<std::size_t>(n), L'\0');
                ::MultiByteToWideChar(CP_UTF8, 0, s.data(),
                                      static_cast<int>(s.size()), out.data(),
                                      n);
                return out;
            }

            /// batch28: encodes UTF-16 text into the JSON wire encoding
            /// (UTF-8); the tray menu labels must travel as real UTF-8.
            std::string WideToUtf8(const std::wstring& s) {
                if (s.empty()) {
                    return std::string();
                }
                const int n = ::WideCharToMultiByte(
                    CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr,
                    0, nullptr, nullptr);
                if (n <= 0) {
                    return std::string();
                }
                std::string out(static_cast<std::size_t>(n), '\0');
                ::WideCharToMultiByte(CP_UTF8, 0, s.data(),
                                      static_cast<int>(s.size()), out.data(),
                                      n, nullptr, nullptr);
                return out;
            }

            /// Color channel (float 0..1, theme.h Color layout) -> two hex
            /// digits (0..255, clamped, rounded). A malformed color already
            /// holds opaque black, so this never sees an out-of-range value.
            std::string ToHexByte(float v) {
                int i = static_cast<int>(v * 255.0f + 0.5f);
                if (i < 0) {
                    i = 0;
                } else if (i > 255) {
                    i = 255;
                }
                const char kHex[] = "0123456789ABCDEF";
                std::string s;
                s.push_back(kHex[(i >> 4) & 0xF]);
                s.push_back(kHex[i & 0xF]);
                return s;
            }

            /// Serializes one recorded DrawOp (no pixels): kind, logical rect,
            /// #RRGGBB color, radius, text (UTF-8) and font. The op's position
            /// in the stream is the z-order ground truth (implicit by array
            /// index). `DrawOp`/`Color` follow renderer.h/theme.h exactly.
            nlohmann::json DrawOpToJson(const DrawOp& op) {
                nlohmann::json j = nlohmann::json::object();
                switch (op.kind) {
                case DrawOp::Kind::FillRect:
                    j["kind"] = "FillRect";
                    break;
                case DrawOp::Kind::FillRoundedRect:
                    j["kind"] = "FillRoundedRect";
                    break;
                case DrawOp::Kind::StrokeRect:
                    j["kind"] = "StrokeRect";
                    break;
                case DrawOp::Kind::StrokeRoundedRect:
                    j["kind"] = "StrokeRoundedRect";
                    break;
                case DrawOp::Kind::DrawText:
                    j["kind"] = "DrawText";
                    break;
                case DrawOp::Kind::ClipPush:
                    j["kind"] = "ClipPush";
                    break;
                case DrawOp::Kind::ClipPop:
                    j["kind"] = "ClipPop";
                    break;
                }
                j["rect"] = {op.rect.x, op.rect.y, op.rect.w, op.rect.h};
                j["color"] = "#" + ToHexByte(op.color.r) +
                             ToHexByte(op.color.g) + ToHexByte(op.color.b);
                if (!op.text.empty()) {
                    j["text"] = Utf16ToUtf8(op.text);
                }
                if (op.radius != 0.0f) {
                    j["radius"] = op.radius;
                }
                // batch17 P1-b: an explicit width is emitted only when it
                // differs from the 1.0 default, so every op of every other
                // kind (and every 1 px rounded stroke) serializes exactly as
                // before - the draw_ops JSON of existing surfaces is only
                // touched by the intentional StrokeRect -> StrokeRoundedRect
                // kind changes.
                if (op.width != 1.0f) {
                    j["width"] = op.width;
                }
                j["font"] = static_cast<int>(op.font);
                return j;
            }

            /// Standard half-open AABB intersection. `Rect` only provides
            /// Contains (element.h), and occlusion needs rect-vs-rect overlap
            /// for the spec's "later-drawn op whose rect overlaps the target"
            /// (spec L105-106). Touching edges do not count as overlap.
            bool RectsOverlap(const Rect& a, const Rect& b) noexcept {
                return !(a.x + a.w <= b.x || b.x + b.w <= a.x ||
                         a.y + a.h <= b.y || b.y + b.h <= a.y);
            }

            /// Exact field match used to locate the target element's own op
            /// run inside the full recorded frame. The key is exactly the
            /// task's (kind, rect, color, text, radius); font is deliberately
            /// not part of it. Float comparison is exact (no epsilon): the
            /// op stream is deterministic, so identical draws are bit-equal.
            bool SameDrawOp(const DrawOp& a, const DrawOp& b) noexcept {
                // batch17 P1-b: `width` participates for the new
                // StrokeRoundedRect kind (1 px vs 2 px focus ring); for every
                // pre-existing kind both sides keep the 1.0 default, so the
                // comparison is unchanged there by construction.
                return a.kind == b.kind && a.rect.x == b.rect.x &&
                       a.rect.y == b.rect.y && a.rect.w == b.rect.w &&
                       a.rect.h == b.rect.h && a.color.r == b.color.r &&
                       a.color.g == b.color.g && a.color.b == b.color.b &&
                       a.color.a == b.color.a && a.text == b.text &&
                       a.radius == b.radius && a.width == b.width;
            }

        }  // namespace

        UiDebugController::UiDebugController() = default;

        void UiDebugController::Bind(Element* root, VgwwWindow* window,
                                     Router* router, UiApp* app) {
            root_ = root;
            window_ = window;
            router_ = router;
            app_ = app;
        }

        nlohmann::json UiDebugController::RunOneCommand(
            const nlohmann::json& cmd) {
            if (!cmd.is_object()) {
                return {{"ok", false}, {"error", "command must be an object"}};
            }
            const auto it = cmd.find("op");
            if (it == cmd.end() || !it->is_string()) {
                return {{"ok", false}, {"error", "missing 'op'"}};
            }
            const std::string op = it->get<std::string>();
            if (op == "tree") {
                if (root_ == nullptr) {
                    return {{"ok", false}, {"op", op}, {"error", "no root bound"}};
                }
                std::string tree_error;
                nlohmann::json data = Tree(Opts(cmd), &tree_error);
                if (!tree_error.empty()) {
                    return {{"ok", false}, {"op", op}, {"error", tree_error}};
                }
                return {{"ok", true}, {"op", op}, {"data", std::move(data)}};
            }
            if (op == "query") {
                if (root_ == nullptr) {
                    return {{"ok", false}, {"op", op}, {"error", "no root bound"}};
                }
                return {{"ok", true}, {"op", op}, {"data", Query(Opts(cmd))}};
            }
            if (op == "state") {
                return {{"ok", true}, {"op", op}, {"data", State()}};
            }
            // Input ops share one envelope: a successful handler nests its
            // result under "data"; a failing handler makes the outer `ok`
            // false and hoists its `error` so callers can branch on `ok`.
            const auto input = [&](nlohmann::json result) -> nlohmann::json {
                if (result.value("ok", false)) {
                    return {{"ok", true}, {"op", op},
                            {"data", std::move(result)}};
                }
                nlohmann::json out = {{"ok", false}, {"op", op}};
                if (result.contains("error")) {
                    out["error"] = result["error"];
                }
                out["data"] = std::move(result);
                return out;
            };
            if (op == "click") return input(Click(Opts(cmd)));
            if (op == "dblclick") return input(DoubleClick(Opts(cmd)));
            if (op == "rclick") return input(RClick(Opts(cmd)));
            if (op == "mousedown") return input(MouseDown(Opts(cmd)));
            if (op == "mouseup") return input(MouseUp(Opts(cmd)));
            if (op == "move") return input(MouseMove(Opts(cmd)));
            if (op == "hover") return input(Hover(Opts(cmd)));
            // batch19 terminal: a FAITHFUL client-mouse replay. `realmouse`
            // routes one WM_MOUSEMOVE through VgwwWindow::RouteMouseForTest -
            // the exact client path the window procedure uses for a real mouse
            // move (hit test + hover dispatch + invalidation), unlike a
            // test-only hook. `dirty` then reports the recorded invalidation /
            // dirty rects, so a hover repaint region can be inspected without
            // any desktop input injection.
            if (op == "realmouse") {
                if (window_ == nullptr) {
                    return {{"ok", false}, {"op", op}, {"error", "no window bound"}};
                }
                const nlohmann::json o = Opts(cmd);
                const Point p{o.value("x", 0.0f), o.value("y", 0.0f)};
                const bool consumed = window_->RouteMouseForTest(WM_MOUSEMOVE, p);
                Element* h = window_->HoveredForTest();
                return {{"ok", true}, {"op", op},
                        {"data",
                         {{"consumed", consumed},
                          {"hover", h != nullptr ? std::string(h->id)
                                                 : std::string()}}}};
            }
            if (op == "dirty") {
                if (window_ == nullptr) {
                    return {{"ok", false}, {"op", op}, {"error", "no window bound"}};
                }
                const auto jr = [](const Rect& r) {
                    return nlohmann::json::array({r.x, r.y, r.w, r.h});
                };
                return {{"ok", true}, {"op", op},
                        {"data",
                         {{"invalidate_count", window_->invalidate_count()},
                          {"full", window_->last_invalidation_full()},
                          {"invalidated", jr(window_->last_invalidated_rect())},
                          {"dirty", jr(window_->last_dirty_rect())}}}};
            }
            if (op == "wheel") return input(Wheel(Opts(cmd)));
            if (op == "type") return input(Type(Opts(cmd)));
            if (op == "key") return input(Key(Opts(cmd)));
            if (op == "focus") return input(Focus(Opts(cmd)));
            // Control ops share the same envelope as the input ops (spec
            // L132): the handler result is nested under "data"; a failing
            // handler makes the outer `ok` false and hoists its `error`. An
            // assert that merely fails to hold stays data (outer ok true,
            // data.passed false), not an error (spec L130).
            if (op == "navigate") return input(Navigate(Opts(cmd)));
            if (op == "dialog") return input(Dialog(Opts(cmd)));
            if (op == "resize") return input(Resize(Opts(cmd)));
            if (op == "language") return input(Language(Opts(cmd)));
            if (op == "wait") return input(Wait(Opts(cmd)));
            if (op == "assert") return input(Assert(Opts(cmd)));
            // Render introspection ops use the same uniform envelope; each
            // handler returns {"ok",...} and a failure hoists `error`.
            if (op == "draw_ops") return input(DrawOps());
            if (op == "occlusion") return input(Occlusion(Opts(cmd)));
            if (op == "screenshot") return input(Screenshot(Opts(cmd)));
            // T8 ops (same envelope).
            if (op == "metrics") return input(Metrics());
            if (op == "render") return input(Render(Opts(cmd)));
            if (op == "tick") return input(Tick(Opts(cmd)));
            if (op == "drag") return input(Drag(Opts(cmd)));
            if (op == "select") return input(Select(Opts(cmd)));
            if (op == "column") return input(Column(Opts(cmd)));
            if (op == "toast") return input(Toast(Opts(cmd)));
            if (op == "set") return input(Set(Opts(cmd)));
            if (op == "dpi") return input(Dpi(Opts(cmd)));
            if (op == "tray") return input(Tray(Opts(cmd)));
            // Spec L132: even the unknown-command error envelope carries `op`.
            return {{"ok", false}, {"op", op}, {"error", "unknown command: " + op}};
        }

        nlohmann::json UiDebugController::SubmitBatch(
            const nlohmann::json& cmds) {
            if (!cmds.is_array()) {
                return {{"ok", false},
                        {"error", "commands must be an array"}};
            }
            nlohmann::json results = nlohmann::json::array();
            // Spec L132: every per-command envelope also carries `index` (the
            // command's position in the batch). Inject it at the wrapping
            // layer without touching the fields RunOneCommand produced.
            int index = 0;
            const auto with_index = [](nlohmann::json result, int i) {
                result["index"] = i;
                return result;
            };
            for (const auto& cmd : cmds) {
                // Headless test seam / dead window: there is no UI thread to
                // drain the queue, so run inline. Waiting on a promise here
                // would always time out (Task 6 trap 1).
                if (window_ == nullptr || window_->hwnd() == nullptr) {
                    results.push_back(with_index(RunOneCommand(cmd), index++));
                    continue;
                }
                auto pending = std::make_shared<PendingCommand>();
                pending->cmd = cmd;
                {
                    // Push BEFORE posting: a wake that drains the queue must
                    // already see this command, otherwise it could drain an
                    // empty queue and the future would never be fulfilled.
                    std::lock_guard<std::mutex> lk(queue_mutex_);
                    queue_.push_back(pending);
                }
                if (!WakeWindow()) {
                    // Post failed against a live hwnd (window tearing down):
                    // take the command back and run it inline instead of
                    // waiting for a drain that cannot come.
                    {
                        std::lock_guard<std::mutex> lk(queue_mutex_);
                        for (auto it = queue_.begin(); it != queue_.end();
                             ++it) {
                            if (*it == pending) {
                                queue_.erase(it);
                                break;
                            }
                        }
                    }
                    results.push_back(with_index(RunOneCommand(cmd), index++));
                    continue;
                }
                nlohmann::json result;
                std::future<nlohmann::json> fut = pending->result.get_future();
                // I2: the transport wait MUST exceed the `wait` op's own
                // polling ceiling (kWaitMaxMs), else a live `wait` with a
                // timeout in (kWaitMaxMs, kCommandWaitMs] would be aborted by
                // "ui-thread timeout" before its predicate can be met. The two
                // constants are tied on purpose (ui_debug_controller.h).
                if (fut.wait_for(std::chrono::milliseconds(kCommandWaitMs)) ==
                    std::future_status::ready) {
                    result = fut.get();
                } else {
                    result = {{"ok", false}, {"error", "ui-thread timeout"}};
                }
                results.push_back(with_index(std::move(result), index++));
            }
            return {{"results", std::move(results)}};
        }

        void UiDebugController::DrainOnUiThread() {
            // Design L86-88: drain a BOUNDED batch per wake and re-post the
            // remainder, so a large batch cannot stall repaint; the UI thread
            // is never parked here. Each command still gets its own envelope.
            std::deque<std::shared_ptr<PendingCommand>> pending;
            bool more = false;
            {
                std::lock_guard<std::mutex> lk(queue_mutex_);
                const std::size_t take =
                    std::min<std::size_t>(kDrainBatchMax, queue_.size());
                for (std::size_t i = 0; i < take; ++i) {
                    pending.push_back(queue_.front());
                    queue_.pop_front();
                }
                more = !queue_.empty();
            }
            for (auto& p : pending) {
                // RunOneCommand never throws; each command gets its own
                // envelope, so one bad command cannot poison the batch.
                p->result.set_value(RunOneCommand(p->cmd));
            }
            if (more) {
                // Re-post a wake so the message loop services the remainder
                // without ever blocking on a promise (bounded drain + repost).
                WakeWindow();
            }
        }

        bool UiDebugController::WakeWindow() {
            if (window_ == nullptr) {
                return false;
            }
            return window_->PostUiDebug();
        }

        nlohmann::json UiDebugController::Tree(const nlohmann::json& opts,
                                               std::string* error) {
            if (root_ == nullptr) {
                if (error != nullptr) {
                    *error = "no root bound";
                }
                return nlohmann::json::object();
            }
            const bool include_hidden =
                opts.contains("include_hidden") &&
                        opts["include_hidden"].is_boolean()
                    ? opts["include_hidden"].get<bool>()
                    : false;
            int max_depth = -1;  // < 0: unlimited
            if (opts.contains("max_depth") &&
                opts["max_depth"].is_number_integer()) {
                max_depth = opts["max_depth"].get<int>();
            }
            // I1c (spec L96): `subtree` re-roots serialization at the named
            // element instead of the controller's root_.
            const Element* tree_root = root_;
            if (opts.contains("subtree") && opts["subtree"].is_string()) {
                const std::string subtree_id =
                    opts["subtree"].get<std::string>();
                const auto hits = FindById(*root_, subtree_id);
                if (hits.empty()) {
                    if (error != nullptr) {
                        *error = "subtree not found: " + subtree_id;
                    }
                    return nlohmann::json::object();
                }
                tree_root = hits.front();
            }
            // I1a: the window's focused element (nullptr when headless / none).
            const Element* focused =
                window_ != nullptr ? window_->FocusedForTest() : nullptr;
            // I1b: one shared counter per tree so draw_index is the global
            // pre-order position within the serialized content pass.
            int draw_counter = 0;
            return SerializeElement(*tree_root, include_hidden, max_depth,
                                    focused, &draw_counter);
        }

        nlohmann::json UiDebugController::Query(const nlohmann::json& opts) {
            nlohmann::json hits = nlohmann::json::array();
            if (root_ == nullptr) {
                return hits;
            }
            if (opts.contains("by_id") && opts["by_id"].is_string()) {
                for (const Element* e :
                     FindById(*root_, opts["by_id"].get<std::string>())) {
                    hits.push_back(QueryHit(*e));
                }
            } else if (opts.contains("by_role") &&
                       opts["by_role"].is_string()) {
                for (const Element* e :
                     FindByRole(*root_, opts["by_role"].get<std::string>())) {
                    hits.push_back(QueryHit(*e));
                }
            } else if (opts.contains("by_text") &&
                       opts["by_text"].is_string()) {
                for (const Element* e :
                     FindByText(*root_, opts["by_text"].get<std::string>())) {
                    hits.push_back(QueryHit(*e));
                }
            }
            return hits;
        }

        nlohmann::json UiDebugController::State() {
            nlohmann::json st = nlohmann::json::object();
            if (window_ != nullptr) {
                st["scale"] = window_->scale();
                st["titlebar_height"] = window_->titlebar_height();
                st["layout_requests"] = window_->layout_requests();
                st["exit_requested"] = window_->exit_requested();
                Element* focused = window_->FocusedForTest();
                if (focused != nullptr && root_ != nullptr) {
                    st["focused_path"] = ElementPath(*root_, focused);
                } else {
                    st["focused_path"] = nullptr;
                }
                // I1d (spec L100): tray icon active.
                st["tray_active"] = window_->tray_active();
                // I1d (spec L99): the hovered element; prefer its id, fall
                // back to its root-relative path when anonymous, else null.
                Element* hovered = window_->HoveredForTest();
                if (hovered != nullptr && !hovered->id.empty()) {
                    st["hover"] = hovered->id;
                } else if (hovered != nullptr && root_ != nullptr) {
                    st["hover"] = ElementPath(*root_, hovered);
                } else {
                    st["hover"] = nullptr;
                }
            } else {
                st["tray_active"] = false;
                st["hover"] = nullptr;
            }
            // I1d (spec L100): an open DialogHost anywhere in the tree; false
            // when headless / no root (mirrors EvalCondition's dialog_open).
            bool dialog_open = false;
            if (root_ != nullptr) {
                for (const Element* e : FindByRole(*root_, "DialogHost")) {
                    const auto* d = dynamic_cast<const DialogHost*>(e);
                    if (d != nullptr && d->open()) {
                        dialog_open = true;
                        break;
                    }
                }
            }
            st["dialog_open"] = dialog_open;
            if (router_ != nullptr && router_->current() != nullptr) {
                st["page"] = router_->current()->id();
            }
            // Batch19 R4-P1: report the true runtime code (Lang() collapses
            // every non-zh language to "en", which broke RTL baseline checks).
            st["lang"] = I18n::Instance().LangCode();
            st["rtl"] = I18n::Instance().IsRtl();
            return st;
        }

        const Element* UiDebugController::ResolveTarget(
            const nlohmann::json& opts) const {
            if (root_ == nullptr) {
                return nullptr;
            }
            if (opts.contains("path") && opts["path"].is_array()) {
                const Element* cur = root_;
                for (const auto& step : opts["path"]) {
                    if (!step.is_number_integer() || cur == nullptr) {
                        return nullptr;
                    }
                    const std::size_t idx = step.get<std::size_t>();
                    if (idx >= cur->children().size()) {
                        return nullptr;
                    }
                    cur = cur->children()[idx].get();
                }
                return cur;
            }
            if (opts.contains("id") && opts["id"].is_string()) {
                const auto ids =
                    FindById(*root_, opts["id"].get<std::string>());
                return ids.empty() ? nullptr : ids.front();
            }
            return nullptr;
        }

        const Element* UiDebugController::ResolveTargetBy(
            const nlohmann::json& v) const {
            if (v.is_string()) {
                return ResolveTarget({{"id", v}});
            }
            if (v.is_object() && v.contains("id")) {
                return ResolveTarget(v);
            }
            return nullptr;
        }

        nlohmann::json UiDebugController::QueryHit(const Element& e) const {
            nlohmann::json j = nlohmann::json::object();
            j["path"] = ElementPath(*root_, &e);
            j["id"] = e.id.empty() ? nlohmann::json(nullptr)
                                   : nlohmann::json(e.id);
            j["role"] = e.debug_role();
            const Rect& b = e.bounds();
            j["rect"] = {b.x, b.y, b.w, b.h};
            return j;
        }

        bool UiDebugController::TargetPoint(const nlohmann::json& opts,
                                            Point& out,
                                            std::string& error) const {
            if (opts.contains("id") || opts.contains("path")) {
                const Element* e = ResolveTarget(opts);
                if (e == nullptr) {
                    error = "element not found";
                    return false;
                }
                const Rect& b = e->bounds();
                out = {b.x + b.w / 2.0f, b.y + b.h / 2.0f};
                return true;
            }
            if (opts.contains("x") && opts.contains("y") &&
                opts["x"].is_number() && opts["y"].is_number()) {
                out = {opts["x"].get<float>(), opts["y"].get<float>()};
                return true;
            }
            error = "need 'id' or 'x'+'y'";
            return false;
        }

        Element* UiDebugController::HitAt(Point p) const {
            if (window_ == nullptr) {
                return nullptr;
            }
            return window_->HitTestTopmostForTest(p);
        }

        void UiDebugController::DispatchPointer(const char* kind, Point p,
                                                int wheel_delta) {
            if (window_ == nullptr) {
                return;
            }
            // Route through the window's client-pointer seam so capture, focus
            // transfer and hover match a real WM_* message (Task 3 review I1),
            // instead of poking the topmost element directly.
            const std::string k(kind);
            UINT message = 0;
            if (k == "down") {
                message = WM_LBUTTONDOWN;
            } else if (k == "up") {
                message = WM_LBUTTONUP;
            } else if (k == "move") {
                message = WM_MOUSEMOVE;
            } else if (k == "wheel") {
                message = WM_MOUSEWHEEL;
            } else {
                return;
            }
            window_->RouteMouseForTest(message, p, wheel_delta);
        }

        nlohmann::json UiDebugController::Click(const nlohmann::json& opts) {
            Point p;
            std::string err;
            if (!TargetPoint(opts, p, err)) {
                return {{"ok", false}, {"error", err}};
            }
            if (window_ == nullptr) {
                return {{"ok", false}, {"error", "no window (input needs one)"}};
            }
            Element* hit = HitAt(p);
            if (hit == nullptr) {
                return {{"ok", true},
                        {"consumed", false},
                        {"reason", "no element at point"}};
            }
            // Dispatch exactly like RouteMouse: press captures + focuses, then
            // release fires through the capture. Role/id are reported from the
            // topmost hit resolved above (same point).
            window_->RouteMouseForTest(WM_LBUTTONDOWN, p);
            window_->RouteMouseForTest(WM_LBUTTONUP, p);
            return {{"ok", true},
                    {"consumed", true},
                    {"role", hit->debug_role()},
                    {"id", hit->id.empty() ? nlohmann::json(nullptr)
                                           : nlohmann::json(hit->id)}};
        }

        nlohmann::json UiDebugController::DoubleClick(const nlohmann::json& opts) {
            Point p;
            std::string err;
            if (!TargetPoint(opts, p, err)) {
                return {{"ok", false}, {"error", err}};
            }
            if (window_ == nullptr) {
                return {{"ok", false}, {"error", "no window (input needs one)"}};
            }
            Element* hit = HitAt(p);
            if (hit == nullptr) {
                return {{"ok", true},
                        {"consumed", false},
                        {"reason", "no element at point"}};
            }
            const bool consumed =
                window_->RouteMouseForTest(WM_LBUTTONDBLCLK, p);
            return {{"ok", true},
                    {"consumed", consumed},
                    {"role", hit->debug_role()},
                    {"id", hit->id.empty() ? nlohmann::json(nullptr)
                                           : nlohmann::json(hit->id)}};
        }

        nlohmann::json UiDebugController::RClick(const nlohmann::json& opts) {
            Point p;
            std::string err;
            if (!TargetPoint(opts, p, err)) {
                return {{"ok", false}, {"error", err}};
            }
            if (window_ == nullptr) {
                return {{"ok", false}, {"error", "no window (input needs one)"}};
            }
            Element* hit = HitAt(p);
            // Same two-message sequence as a real right click: press closes any
            // open popup and moves focus, release is what opens a row menu.
            // `consumed` reports the RELEASE, which is the event a page's
            // on_row_context answers.
            window_->RouteMouseForTest(WM_RBUTTONDOWN, p);
            const bool consumed = window_->RouteMouseForTest(WM_RBUTTONUP, p);
            return {{"ok", true},
                    {"consumed", consumed},
                    {"role", hit != nullptr ? nlohmann::json(hit->debug_role())
                                            : nlohmann::json(nullptr)},
                    {"id", (hit != nullptr && !hit->id.empty())
                               ? nlohmann::json(hit->id)
                               : nlohmann::json(nullptr)}};
        }

        nlohmann::json UiDebugController::MouseDown(const nlohmann::json& opts) {
            Point p;
            std::string err;
            if (!TargetPoint(opts, p, err)) {
                return {{"ok", false}, {"error", err}};
            }
            if (window_ == nullptr) {
                return {{"ok", false}, {"error", "no window"}};
            }
            DispatchPointer("down", p, 0);
            return {{"ok", true}};
        }

        nlohmann::json UiDebugController::MouseUp(const nlohmann::json& opts) {
            Point p;
            std::string err;
            if (!TargetPoint(opts, p, err)) {
                return {{"ok", false}, {"error", err}};
            }
            if (window_ == nullptr) {
                return {{"ok", false}, {"error", "no window"}};
            }
            DispatchPointer("up", p, 0);
            return {{"ok", true}};
        }

        nlohmann::json UiDebugController::MouseMove(const nlohmann::json& opts) {
            Point p;
            std::string err;
            if (!TargetPoint(opts, p, err)) {
                return {{"ok", false}, {"error", err}};
            }
            if (window_ == nullptr) {
                return {{"ok", false}, {"error", "no window"}};
            }
            DispatchPointer("move", p, 0);
            return {{"ok", true}};
        }

        nlohmann::json UiDebugController::Hover(const nlohmann::json& opts) {
            Point p;
            std::string err;
            if (!TargetPoint(opts, p, err)) {
                return {{"ok", false}, {"error", err}};
            }
            if (window_ == nullptr) {
                return {{"ok", false}, {"error", "no window"}};
            }
            Element* hit = window_->HoverMoveForTest(p);
            return {{"ok", true},
                    {"role", hit != nullptr ? nlohmann::json(hit->debug_role())
                                            : nlohmann::json(nullptr)},
                    {"id", (hit != nullptr && !hit->id.empty())
                               ? nlohmann::json(hit->id)
                               : nlohmann::json(nullptr)}};
        }

        nlohmann::json UiDebugController::Wheel(const nlohmann::json& opts) {
            int delta = 0;
            if (opts.contains("delta") && opts["delta"].is_number_integer()) {
                delta = opts["delta"].get<int>();
            }
            if (window_ == nullptr) {
                return {{"ok", false}, {"error", "no window"}};
            }
            // By id/path the scroller itself is the dispatch target: the
            // topmost hit under a ScrollView is its content child, which does
            // not consume the wheel.
            if (opts.contains("id") || opts.contains("path")) {
                Element* target = const_cast<Element*>(ResolveTarget(opts));
                if (target == nullptr) {
                    return {{"ok", false}, {"error", "element not found"}};
                }
                const bool consumed = target->OnWheel(delta);
                window_->Invalidate();
                return {{"ok", true}, {"consumed", consumed}};
            }
            // By x/y: route through the window exactly like a real
            // WM_MOUSEWHEEL (topmost hit), which reports consumption.
            Point p;
            std::string err;
            if (!TargetPoint(opts, p, err)) {
                return {{"ok", false}, {"error", err}};
            }
            if (HitAt(p) == nullptr) {
                return {{"ok", true}, {"consumed", false}};
            }
            const bool consumed =
                window_->RouteMouseForTest(WM_MOUSEWHEEL, p, delta);
            return {{"ok", true}, {"consumed", consumed}};
        }

        nlohmann::json UiDebugController::Type(const nlohmann::json& opts) {
            if (!opts.contains("text") || !opts["text"].is_string()) {
                return {{"ok", false}, {"error", "need 'text'"}};
            }
            Element* target = nullptr;
            if (opts.contains("id") || opts.contains("path")) {
                target = const_cast<Element*>(ResolveTarget(opts));
                if (target == nullptr) {
                    return {{"ok", false}, {"error", "element not found"}};
                }
            } else if (window_ != nullptr) {
                target = window_->FocusedForTest();
            }
            if (target == nullptr) {
                return {{"ok", false},
                        {"error", "no target: give 'id' or a focused window"}};
            }
            // Focus through the window when possible so a follow-up `key` op
            // routes to this element (RouteKey reads the window's focus).
            if (window_ != nullptr && target->focusable()) {
                window_->SetFocusForTest(target);
            } else {
                target->OnFocus(true);
            }
            const std::string text = opts["text"].get<std::string>();
            // T8 UTF-8 fix: decode the UTF-8 wire string into UTF-16 and send
            // one wchar per code unit (the old path byte-widened each UTF-8
            // code unit, garbling non-ASCII). `typed` counts only the chars the
            // control actually accepted (OnChar returned true); a control that
            // rejects non-ASCII (TextInput's printable-ASCII guard) reports a
            // truthful count instead of the byte length.
            const std::wstring wide = Utf8ToWide(text);
            int typed = 0;
            for (const wchar_t wch : wide) {
                if (target->OnChar(wch)) {
                    ++typed;
                }
            }
            if (window_ != nullptr) {
                window_->Invalidate();
            }
            return {{"ok", true}, {"typed", typed}};
        }

        nlohmann::json UiDebugController::Key(const nlohmann::json& opts) {
            uint32_t vk = 0;
            if (opts.contains("vk") && opts["vk"].is_number_integer()) {
                vk = opts["vk"].get<uint32_t>();
            } else if (opts.contains("name") && opts["name"].is_string()) {
                vk = KeyNameToVk(opts["name"].get<std::string>());
            }
            if (vk == 0) {
                return {{"ok", false}, {"error", "need 'vk' or known 'name'"}};
            }
            // T8: modifiers (shift/ctrl/alt) and action (down/up/press). The
            // modifier mask is injected into the window for the Tab direction
            // test; ctrl/alt have no consumer, so they are echoed, not acted on.
            unsigned mods = 0;
            nlohmann::json mods_out = nlohmann::json::array();
            if (opts.contains("modifiers") && opts["modifiers"].is_array()) {
                for (const auto& m : opts["modifiers"]) {
                    if (!m.is_string()) {
                        continue;
                    }
                    const std::string name = m.get<std::string>();
                    if (name == "shift") {
                        mods |= 0x1u;
                        mods_out.push_back("shift");
                    } else if (name == "ctrl") {
                        mods |= 0x2u;
                        mods_out.push_back("ctrl");
                    } else if (name == "alt") {
                        mods |= 0x4u;
                        mods_out.push_back("alt");
                    }
                }
            }
            const std::string action =
                opts.contains("action") && opts["action"].is_string()
                    ? opts["action"].get<std::string>()
                    : "down";
            if (action != "down" && action != "up" && action != "press") {
                return {{"ok", false}, {"error", "unknown action: " + action}};
            }
            if (window_ != nullptr) {
                window_->SetModifiersForTest(mods);
            }
            bool consumed = false;
            const auto route = [&](UINT msg) {
                if (window_ != nullptr) {
                    return window_->RouteKeyForTest(msg, vk);
                }
                if (root_ == nullptr) {
                    return false;
                }
                Element* focused = nullptr;
                const auto chain = FocusChain(*root_);
                if (!chain.empty()) {
                    focused = chain.front();
                }
                if (focused == nullptr) {
                    return false;
                }
                if (msg == WM_KEYUP) {
                    return focused->OnKeyUp(vk);
                }
                return focused->OnKeyDown(vk);
            };
            if (action == "down") {
                consumed = route(WM_KEYDOWN);
            } else if (action == "up") {
                consumed = route(WM_KEYUP);
            } else {  // press
                const bool down = route(WM_KEYDOWN);
                const bool up = route(WM_KEYUP);
                consumed = down || up;
            }
            if (window_ != nullptr) {
                // Reset the injected mask so a later real Shift+Tab is not
                // shadowed by a latched injection (falls back to GetKeyState).
                window_->ResetModifiersForTest();
                window_->Invalidate();
            }
            return {{"ok", true},
                    {"consumed", consumed},
                    {"vk", vk},
                    {"modifiers", std::move(mods_out)},
                    {"action", action}};
        }

        nlohmann::json UiDebugController::Focus(const nlohmann::json& opts) {
            if (!opts.contains("id") && !opts.contains("path")) {
                return {{"ok", false}, {"error", "need 'id'"}};
            }
            const Element* e = ResolveTarget(opts);
            if (e == nullptr) {
                return {{"ok", false}, {"error", "element not found"}};
            }
            if (!e->focusable()) {
                return {{"ok", false}, {"error", "element not focusable"}};
            }
            if (window_ == nullptr) {
                return {{"ok", false}, {"error", "no window"}};
            }
            window_->SetFocusForTest(const_cast<Element*>(e));
            return {{"ok", true},
                    {"focused", e->id.empty() ? nlohmann::json(nullptr)
                                              : nlohmann::json(e->id)}};
        }

        nlohmann::json UiDebugController::Navigate(const nlohmann::json& opts) {
            if (!opts.contains("page") || !opts["page"].is_string()) {
                return {{"ok", false}, {"error", "need 'page'"}};
            }
            if (router_ == nullptr) {
                return {{"ok", false}, {"error", "no router bound"}};
            }
            const std::string id = opts["page"].get<std::string>();
            // batch31 P0-2: capture the page BEFORE navigating. Clicking the
            // already-current tab must be a zero-side-effect no-op, so the
            // layout request below is issued only on a real page change.
            const Page* before = router_->current();
            const std::string before_id =
                before == nullptr ? std::string() : before->id();
            router_->Navigate(id);
            // Navigate silently ignores an unregistered id (Release); report
            // that as an error rather than a misleading ok (spec L122).
            if (router_->current() == nullptr ||
                id != router_->current()->id()) {
                return {{"ok", false}, {"error", "unknown page"}};
            }
            if (window_ != nullptr && id != before_id) {
                window_->RequestLayout();
            }
            return {{"ok", true}, {"page", router_->current()->id()}};
        }

        nlohmann::json UiDebugController::Dialog(const nlohmann::json& opts) {
            if (root_ == nullptr) {
                return {{"ok", false}, {"error", "no root bound"}};
            }
            if (!opts.contains("id")) {
                return {{"ok", false}, {"error", "specify dialog id"}};
            }
            const Element* e = ResolveTarget(opts);
            if (e == nullptr) {
                return {{"ok", false}, {"error", "element not found"}};
            }
            auto* dlg =
                const_cast<DialogHost*>(dynamic_cast<const DialogHost*>(e));
            if (dlg == nullptr) {
                return {{"ok", false}, {"error", "target is not a DialogHost"}};
            }
            // T8: action == show_message/show_confirm/show_form/close.
            const std::string action =
                opts.contains("action") && opts["action"].is_string()
                    ? opts["action"].get<std::string>()
                    : "close";
            const auto wstr = [](const nlohmann::json& o, const char* key)
                -> std::wstring {
                if (o.contains(key) && o[key].is_string()) {
                    return Utf8ToWide(o[key].get<std::string>());
                }
                return std::wstring();
            };
            if (action == "close") {
                dlg->Close();
                if (window_ != nullptr) {
                    window_->RequestLayout();
                }
                return {{"ok", true}, {"closed", true}, {"open", dlg->open()}};
            }
            if (action == "show_message") {
                dlg->ShowMessageText(wstr(opts, "title"), wstr(opts, "body"),
                                     wstr(opts, "ok"));
            } else if (action == "show_confirm") {
                dlg->ShowConfirmText(wstr(opts, "title"), wstr(opts, "body"),
                                     nullptr);
            } else if (action == "show_form") {
                std::vector<FormField> fields;
                if (opts.contains("fields") && opts["fields"].is_array()) {
                    for (const auto& f : opts["fields"]) {
                        if (!f.is_object()) {
                            continue;
                        }
                        FormField field;
                        field.id = f.value("id", std::string());
                        field.initial = wstr(f, "initial");
                        if (f.value("type", std::string("text")) == "select") {
                            field.type = FormFieldType::Select;
                            if (f.contains("options") && f["options"].is_array()) {
                                for (const auto& o : f["options"]) {
                                    if (o.is_object()) {
                                        field.options.emplace_back(
                                            wstr(o, "value"), wstr(o, "label"));
                                    }
                                }
                            }
                        }
                        fields.push_back(std::move(field));
                    }
                }
                dlg->ShowFormText(wstr(opts, "title"), std::move(fields),
                                  nullptr);
            } else {
                return {{"ok", false},
                        {"error", "unknown dialog action: " + action}};
            }
            if (window_ != nullptr) {
                window_->RequestLayout();
            }
            // Report the open state + per-field current values.
            nlohmann::json out = nlohmann::json::object();
            out["ok"] = true;
            out["open"] = dlg->open();
            out["mode"] = static_cast<int>(dlg->mode());
            nlohmann::json fields = nlohmann::json::object();
            if (opts.contains("fields") && opts["fields"].is_array()) {
                for (const auto& f : opts["fields"]) {
                    if (!f.is_object() || !f.contains("id")) {
                        continue;
                    }
                    const std::string id = f.value("id", std::string());
                    if (Element* editor = dlg->form_field(id)) {
                        if (const auto* ti =
                                dynamic_cast<const TextInputElement*>(editor)) {
                            fields[id] = Utf16ToUtf8(ti->value());
                        } else if (const auto* se =
                                       dynamic_cast<const SelectElement*>(editor)) {
                            fields[id] = Utf16ToUtf8(se->selected_value());
                        }
                    }
                }
            }
            out["fields"] = std::move(fields);
            return out;
        }

        nlohmann::json UiDebugController::Resize(const nlohmann::json& opts) {
            if (!opts.contains("w") || !opts.contains("h") ||
                !opts["w"].is_number() || !opts["h"].is_number()) {
                return {{"ok", false}, {"error", "need 'w' and 'h'"}};
            }
            if (root_ == nullptr) {
                return {{"ok", false}, {"error", "no root"}};
            }
            const float w = opts["w"].get<float>();
            const float h = opts["h"].get<float>();
            if (window_ != nullptr) {
                // Set the real client size (logical) through the window seam
                // so a live window relayouts instead of Relayout overwriting
                // the arrange from GetClientRect (spec L124).
                window_->ResizeForTest(w, h);
            } else {
                root_->Arrange({0.0f, 0.0f, w, h});
            }
            return {{"ok", true}, {"rect", {0.0f, 0.0f, w, h}}};
        }

        nlohmann::json UiDebugController::Language(const nlohmann::json& opts) {
            std::string lang;
            if (opts.contains("lang") && opts["lang"].is_string()) {
                lang = opts["lang"].get<std::string>();
            } else {
                return {{"ok", false}, {"error", "need 'lang'"}};
            }
            // Batch19 R4-P1 (audit A observation): any catalog language code
            // is accepted; the switch goes through the runtime mechanism so
            // RTL / fallback behavior is reachable end-to-end from the debug
            // channel. "translated" is false when en serves as the fallback.
            if (!I18n::IsKnownLanguageCode(lang)) {
                return {{"ok", false}, {"error", "unknown lang"}};
            }
            I18n& i18n = I18n::Instance();
            // "installed" = a language table is now active for this code (the
            // language identity switched). It is NOT a translation-coverage
            // guarantee: untranslated keys still show the en fallback text.
            const bool installed = i18n.SetLangCode(lang);
            if (app_ != nullptr) {
                app_->ApplyLanguage();
            }
            if (window_ != nullptr) {
                window_->RequestLayout();
            }
            return {{"ok", true},
                    {"lang", i18n.LangCode()},
                    {"installed", installed},
                    {"rtl", i18n.IsRtl()}};
        }

        bool UiDebugController::EvalCondition(const nlohmann::json& cond,
                                              std::string& why) const {
            if (!cond.is_object() || cond.empty()) {
                why = "empty condition";
                return false;
            }
            if (cond.contains("role_exists")) {
                if (!cond["role_exists"].is_string()) {
                    why = "role_exists must be a string";
                    return false;
                }
                const std::string role = cond["role_exists"].get<std::string>();
                const auto hits =
                    root_ != nullptr
                        ? FindByRole(*root_, role)
                        : std::vector<const Element*>{};
                if (!hits.empty()) {
                    return true;
                }
                why = "no role " + role;
                return false;
            }
            if (cond.contains("element_visible")) {
                const Element* e = ResolveTargetBy(cond["element_visible"]);
                if (e != nullptr && e->visible) {
                    return true;
                }
                why = "element not visible";
                return false;
            }
            if (cond.contains("element_absent")) {
                // True when the target does not resolve (id/path absent).
                const Element* e = ResolveTargetBy(cond["element_absent"]);
                if (e == nullptr) {
                    return true;
                }
                why = "element present";
                return false;
            }
            if (cond.contains("page_is")) {
                if (!cond["page_is"].is_string()) {
                    why = "page_is must be a string";
                    return false;
                }
                if (router_ != nullptr && router_->current() != nullptr &&
                    std::string(router_->current()->id()) ==
                        cond["page_is"].get<std::string>()) {
                    return true;
                }
                why = "page mismatch";
                return false;
            }
            if (cond.contains("dialog_open")) {
                const auto dls =
                    root_ != nullptr ? FindByRole(*root_, "DialogHost")
                                     : std::vector<const Element*>{};
                for (const Element* e : dls) {
                    const auto* d = dynamic_cast<const DialogHost*>(e);
                    if (d != nullptr && d->open()) {
                        return true;
                    }
                }
                why = "no open dialog";
                return false;
            }
            if (cond.contains("value_equals")) {
                const auto& vc = cond["value_equals"];
                const Element* e = ResolveTargetBy(vc);
                if (e == nullptr) {
                    why = "target not found";
                    return false;
                }
                // v1: only TextInput value equality is supported.
                const auto* ti = dynamic_cast<const TextInputElement*>(e);
                if (ti != nullptr) {
                    if (!vc.contains("value") || !vc["value"].is_string()) {
                        why = "value_equals needs a string 'value'";
                        return false;
                    }
                    const std::string want =
                        vc.value("value", std::string());
                    const std::wstring wv = Utf8ToWide(want);
                    if (ti->value() == wv) {
                        return true;
                    }
                    why = "value mismatch: want " + want;
                    return false;
                }
                why = "value_equals unsupported for this role";
                return false;
            }
            if (cond.contains("element_state_equals")) {
                // {id|path, key, value}: compares one serialized debug_state
                // entry (or a tree-level field like visible/enabled).
                const auto& c = cond["element_state_equals"];
                const Element* e = ResolveTargetBy(c);
                if (e == nullptr) {
                    why = "target not found";
                    return false;
                }
                if (!c.contains("key") || !c["key"].is_string()) {
                    why = "element_state_equals needs a 'key'";
                    return false;
                }
                const std::string key = c["key"].get<std::string>();
                // Tree-level bools are read directly.
                if (key == "visible") {
                    if (!c.contains("value") || !c["value"].is_boolean()) {
                        why = "visible comparison needs a bool 'value'";
                        return false;
                    }
                    if (e->visible == c["value"].get<bool>()) {
                        return true;
                    }
                    why = "visible mismatch";
                    return false;
                }
                if (key == "enabled") {
                    if (!c.contains("value") || !c["value"].is_boolean()) {
                        why = "enabled comparison needs a bool 'value'";
                        return false;
                    }
                    if (e->EffectivelyEnabled() == c["value"].get<bool>()) {
                        return true;
                    }
                    why = "enabled mismatch";
                    return false;
                }
                nlohmann::json state = nlohmann::json::object();
                JsonStateSink sink(state);
                e->debug_state(sink);
                if (!state.contains(key)) {
                    why = "no state key " + key;
                    return false;
                }
                if (!c.contains("value")) {
                    why = "element_state_equals needs a 'value'";
                    return false;
                }
                if (state[key] == c["value"]) {
                    return true;
                }
                why = "state mismatch for " + key;
                return false;
            }
            if (cond.contains("rect_equals")) {
                const auto& c = cond["rect_equals"];
                const Element* e = ResolveTargetBy(c);
                if (e == nullptr) {
                    why = "target not found";
                    return false;
                }
                const Rect& b = e->bounds();
                const float tol = c.value("tol", 0.001f);
                const auto within = [tol](float a, float want) {
                    return std::fabs(a - want) <= tol;
                };
                const bool ok = (!c.contains("x") || within(b.x, c["x"].get<float>())) &&
                                (!c.contains("y") || within(b.y, c["y"].get<float>())) &&
                                (!c.contains("w") || within(b.w, c["w"].get<float>())) &&
                                (!c.contains("h") || within(b.h, c["h"].get<float>()));
                if (ok) {
                    return true;
                }
                why = "rect mismatch";
                return false;
            }
            if (cond.contains("toast_present")) {
                if (root_ == nullptr) {
                    why = "no root";
                    return false;
                }
                const auto& c = cond["toast_present"];
                const auto hits = FindByRole(*root_, "ToastHost");
                if (hits.empty()) {
                    why = "no ToastHost";
                    return false;
                }
                const auto* host =
                    dynamic_cast<const ToastHost*>(hits.front());
                if (host == nullptr) {
                    why = "no ToastHost";
                    return false;
                }
                const std::string want =
                    c.is_string() ? c.get<std::string>()
                                  : c.value("text", std::string());
                for (const ToastEntry& t : host->toasts()) {
                    const std::wstring text =
                        t.raw_text.empty() ? I18n::Instance().T(t.text)
                                           : t.raw_text;
                    if (want.empty() || Utf16ToUtf8(text) == want) {
                        return true;
                    }
                }
                why = "no matching toast";
                return false;
            }
            if (cond.contains("metric_at_least")) {
                const auto& c = cond["metric_at_least"];
                if (!c.contains("key") || !c["key"].is_string() ||
                    !c.contains("value") || !c["value"].is_number()) {
                    why = "metric_at_least needs {key,value}";
                    return false;
                }
                const std::string key = c["key"].get<std::string>();
                const double want = c["value"].get<double>();
                double actual = 0.0;
                if (window_ == nullptr) {
                    actual = 0.0;
                } else if (key == "paint_count") {
                    actual = static_cast<double>(window_->paint_count());
                } else if (key == "tick_count") {
                    actual = static_cast<double>(window_->tick_count());
                } else if (key == "layout_requests") {
                    actual = static_cast<double>(window_->layout_requests());
                } else if (key == "animation_frames") {
                    actual = static_cast<double>(window_->animation_frames());
                } else {
                    why = "unknown metric " + key;
                    return false;
                }
                if (actual >= want) {
                    return true;
                }
                why = "metric " + key + " below threshold";
                return false;
            }
            why = "unsupported condition";
            return false;
        }
        nlohmann::json UiDebugController::Assert(const nlohmann::json& opts) {
            if (!opts.contains("condition")) {
                return {{"ok", false}, {"error", "need 'condition'"}};
            }
            std::string why;
            const bool passed = EvalCondition(opts["condition"], why);
            return {{"ok", true},
                    {"passed", passed},
                    {"why", passed ? nlohmann::json(nullptr)
                                   : nlohmann::json(why)}};
        }

        nlohmann::json UiDebugController::Wait(const nlohmann::json& opts) {
            if (!opts.contains("condition")) {
                return {{"ok", false}, {"error", "need 'condition'"}};
            }
            // T8: this op runs on the UI thread (or inline headless). It MUST
            // NOT sleep - a blocking wait parks the message loop and freezes
            // the caret/snapshot/animation timers, so a predicate that only
            // advances via a timer tick could never be satisfied. Instead the
            // predicate is evaluated once and the result returned immediately;
            // a caller that needs to observe a timer-driven change issues a
            // `tick` op (which advances the timers deterministically) followed
            // by another `wait`/`assert`. `timeout_ms` is accepted for
            // compatibility and reported back, but no time is spent waiting.
            constexpr long long kMaxWaitMs = kWaitMaxMs;
            long long timeout_ms = 2000;
            if (opts.contains("timeout_ms")) {
                if (!opts["timeout_ms"].is_number()) {
                    return {{"ok", false},
                            {"error", "timeout_ms must be a number"}};
                }
                timeout_ms =
                    static_cast<long long>(opts["timeout_ms"].get<double>());
            }
            if (timeout_ms < 0) {
                timeout_ms = 0;
            }
            if (timeout_ms > kMaxWaitMs) {
                timeout_ms = kMaxWaitMs;
            }
            std::string why;
            if (EvalCondition(opts["condition"], why)) {
                return {{"ok", true},
                        {"matched", true},
                        {"elapsed_ms", 0},
                        {"timeout_ms", timeout_ms}};
            }
            return {{"ok", true},
                    {"matched", false},
                    {"why", why},
                    {"timeout_ms", timeout_ms}};
        }

        nlohmann::json UiDebugController::DrawOps() {
            if (root_ == nullptr) {
                return {{"ok", false}, {"error", "no root bound"}};
            }
            if (window_ == nullptr) {
                return {{"ok", false},
                        {"error", "need a window for frame capture"}};
            }
            // A fresh record-mode frame is render-target independent (every
            // RenderCtx primitive appends an op and returns before touching
            // the - likely absent - D2D target), so this works headless.
            RenderCtx ctx;
            ctx.BeginRecord();
            window_->RenderFrameForTest(ctx);
            ctx.EndRecord();
            nlohmann::json arr = nlohmann::json::array();
            std::size_t index = 0;
            for (const auto& op : ctx.ops()) {
                nlohmann::json oj = DrawOpToJson(op);
                oj["index"] = static_cast<int>(index);  // recorded draw order
                arr.push_back(std::move(oj));
                ++index;
            }
            const int count = static_cast<int>(arr.size());
            return {{"ok", true}, {"count", count}, {"ops", std::move(arr)}};
        }

        nlohmann::json UiDebugController::Occlusion(const nlohmann::json& opts) {
            const bool has_xy = opts.contains("x") && opts.contains("y") &&
                                opts["x"].is_number() && opts["y"].is_number();
            const bool has_target = opts.contains("id") || opts.contains("path");

            // Point mode (existing contract, kept as a superset): the stack
            // of ops whose rect contains {x,y}, in draw order.
            if (!has_target) {
                if (window_ == nullptr || !has_xy) {
                    return {{"ok", false}, {"error", "need window + x + y"}};
                }
                RenderCtx ctx;
                ctx.BeginRecord();
                window_->RenderFrameForTest(ctx);
                ctx.EndRecord();
                const float x = opts["x"].get<float>();
                const float y = opts["y"].get<float>();
                nlohmann::json seq = nlohmann::json::array();
                std::size_t index = 0;
                for (const auto& op : ctx.ops()) {
                    // `draw_index` is the op's position in the ORIGINAL stream
                    // (z-order), independent of which ops are filtered out below.
                    const std::size_t draw_index = index++;
                    // Clip push/pop carry no drawn color and are not visual
                    // coverage; skip them (spec L105: later-drawn ops whose rect
                    // overlaps the target).
                    if (op.kind == DrawOp::Kind::ClipPush ||
                        op.kind == DrawOp::Kind::ClipPop) {
                        continue;
                    }
                    if (op.rect.Contains({x, y})) {
                        nlohmann::json oj = DrawOpToJson(op);
                        oj["index"] = static_cast<int>(draw_index);
                        seq.push_back(std::move(oj));
                    }
                }
                return {{"ok", true},
                        {"point", {x, y}},
                        {"coverage", std::move(seq)}};
            }

            // id/path mode (spec L105-106): for the target element, list the
            // later-drawn ops whose rect overlaps the target's rect.
            if (window_ == nullptr) {
                return {{"ok", false},
                        {"error", "need a window for frame capture"}};
            }
            const Element* target = ResolveTarget(opts);
            if (target == nullptr) {
                return {{"ok", false}, {"error", "element not found"}};
            }
            const Rect R = target->bounds();

            // Full frame (content DFS + overlay DFS), exactly like draw_ops.
            RenderCtx ctx;
            ctx.BeginRecord();
            window_->RenderFrameForTest(ctx);
            ctx.EndRecord();
            const std::vector<DrawOp>& ops = ctx.ops();

            // The target's own op run: render E alone, then locate that run
            // as a contiguous subsequence of the full frame. Render is a
            // deterministic DFS, so E's content ops are contiguous in the
            // frame; renders_on_top children are skipped by both passes.
            RenderCtx tctx;
            tctx.BeginRecord();
            const_cast<Element*>(target)->Render(tctx);
            tctx.EndRecord();
            const std::vector<DrawOp>& target_ops = tctx.ops();
            const std::size_t tsize = target_ops.size();

            const auto overlap_coverage = [&](std::size_t from_index) {
                nlohmann::json cov = nlohmann::json::array();
                for (std::size_t i = from_index; i < ops.size(); ++i) {
                    const DrawOp& op = ops[i];
                    if (op.kind == DrawOp::Kind::ClipPush ||
                        op.kind == DrawOp::Kind::ClipPop) {
                        continue;
                    }
                    if (!RectsOverlap(op.rect, R)) {
                        continue;
                    }
                    nlohmann::json oj = DrawOpToJson(op);
                    oj["index"] = static_cast<int>(i);
                    cov.push_back(std::move(oj));
                }
                return cov;
            };

            nlohmann::json out = nlohmann::json::object();
            out["ok"] = true;
            out["bounds"] = {R.x, R.y, R.w, R.h};

            // A target that draws nothing has no op run to anchor "later"; be
            // conservative and report every overlapping op with its index so
            // the caller can filter, flagged ambiguous.
            if (tsize == 0) {
                out["target_index"] = nullptr;
                out["coverage"] = overlap_coverage(0);
                out["ambiguous"] = true;
                out["note"] =
                    "target draws no ops; coverage lists every overlapping op";
                return out;
            }

            // First contiguous match of target_ops in ops, plus a full match
            // count so a repeated (ambiguous) target is reported honestly.
            std::size_t match = ops.size();
            int match_count = 0;
            if (tsize <= ops.size()) {
                for (std::size_t s = 0; s + tsize <= ops.size(); ++s) {
                    bool same = true;
                    for (std::size_t k = 0; k < tsize; ++k) {
                        if (!SameDrawOp(ops[s + k], target_ops[k])) {
                            same = false;
                            break;
                        }
                    }
                    if (same) {
                        if (match == ops.size()) {
                            match = s;
                        }
                        ++match_count;
                    }
                }
            }

            if (match == ops.size()) {
                // The op run was not located (e.g. a renders_on_top element
                // painted through RenderOverlay, whose op path differs from
                // E->Render). Conservative result: every overlapping op with
                // its index and no target range.
                out["target_index"] = nullptr;
                out["coverage"] = overlap_coverage(0);
                out["ambiguous"] = true;
                out["note"] = "target ops not found in frame; coverage lists "
                              "every overlapping op";
                return out;
            }

            const std::size_t target_last = match + tsize - 1;  // inclusive
            out["target_index"] = {static_cast<int>(match),
                                   static_cast<int>(target_last)};
            out["coverage"] = overlap_coverage(target_last + 1);
            if (match_count > 1) {
                out["ambiguous"] = true;
            }
            return out;
        }

        nlohmann::json UiDebugController::Metrics() {
            nlohmann::json out = nlohmann::json::object();
            if (window_ == nullptr) {
                out["ok"] = true;
                out["paint_count"] = 0;
                out["tick_count"] = 0;
                out["frame_time_us"] = 0;
                out["tick_time_us"] = 0;
                out["layout_requests"] = 0;
                out["animation_frames"] = 0;
                // M5: headless - every new statistic is a real 0 (no window,
                // no frame statistics, no recorded draws). Never fabricated.
                out["fps"] = 0.0;
                out["dropped_frames"] = 0;
                out["frame_time_max_us"] = 0;
                out["fps_samples"] = 0;
                out["draw_ops_total"] = 0;
                out["draw_text_total"] = 0;
                out["text_cache_skips"] = 0;
                out["layout_cache_size"] = 0;
                out["layout_cache_lookups"] = 0;
                out["layout_cache_hits"] = 0;
                out["measure_cache_size"] = 0;
                out["measure_cache_lookups"] = 0;
                out["measure_cache_hits"] = 0;
                return out;
            }
            out["ok"] = true;
            out["paint_count"] = window_->paint_count();
            out["tick_count"] = window_->tick_count();
            out["frame_time_us"] = window_->last_paint_us();
            out["tick_time_us"] = window_->last_tick_us();
            out["layout_requests"] = window_->layout_requests();
            out["animation_frames"] = window_->animation_frames();
            // M5: real frame statistics (never fabricated; a headless window
            // simply reports the counter baseline via the window, and a static
            // page reports fps 0 via the wall-clock idle check).
            out["fps"] = window_->fps();
            out["dropped_frames"] = window_->dropped_frames();
            out["frame_time_max_us"] = window_->frame_time_max_us();
            out["fps_samples"] = window_->fps_samples();
            const RenderCtx& r = window_->renderer();
            out["draw_ops_total"] = r.DrawOpCount();
            out["draw_text_total"] = r.DrawTextCount();
            // batch29 P2: DrawText submissions skipped by the partial-frame
            // text-paint cache (a live-path counter; the recorded stream is
            // always complete).
            out["text_cache_skips"] = r.TextCacheSkips();
            out["layout_cache_size"] = r.LayoutCacheSize();
            out["layout_cache_lookups"] = r.LayoutCacheLookups();
            out["layout_cache_hits"] = r.LayoutCacheHits();
            out["measure_cache_size"] = r.MeasureCacheSize();
            out["measure_cache_lookups"] = r.MeasureCacheLookups();
            out["measure_cache_hits"] = r.MeasureCacheHits();
            const Rect& d = window_->last_dirty_rect();
            out["dirty_rect"] = {d.x, d.y, d.w, d.h};
            out["scale"] = window_->scale();
            out["dpi"] = 96.0f * window_->scale();
            return out;
        }

        nlohmann::json UiDebugController::Render(const nlohmann::json& opts) {
            const std::string mode =
                opts.contains("mode") && opts["mode"].is_string()
                    ? opts["mode"].get<std::string>()
                    : "record";
            if (mode == "paint") {
                if (window_ == nullptr) {
                    return {{"ok", true}, {"blocked", true},
                            {"reason", "no window"}};
                }
                const auto t0 = std::chrono::steady_clock::now();
                const bool painted = window_->PaintNowForTest();
                const auto us = std::chrono::duration_cast<
                                    std::chrono::microseconds>(
                                    std::chrono::steady_clock::now() - t0)
                                    .count();
                if (!painted) {
                    return {{"ok", true}, {"blocked", true},
                            {"reason", "no hwnd"}};
                }
                return {{"ok", true}, {"mode", "paint"},
                        {"elapsed_ms", us / 1000},
                        {"paint_count", window_->paint_count()}};
            }
            if (mode != "record") {
                return {{"ok", false}, {"error", "unknown mode: " + mode}};
            }
            if (root_ == nullptr) {
                return {{"ok", false}, {"error", "no root bound"}};
            }
            if (window_ == nullptr) {
                return {{"ok", false},
                        {"error", "need a window for frame capture"}};
            }
            RenderCtx ctx;
            ctx.BeginRecord();
            const auto t0 = std::chrono::steady_clock::now();
            window_->RenderFrameForTest(ctx);
            const auto us =
                std::chrono::duration_cast<std::chrono::microseconds>(
                    std::chrono::steady_clock::now() - t0)
                    .count();
            ctx.EndRecord();
            return {{"ok", true}, {"mode", "record"},
                    {"ops_count", static_cast<long long>(ctx.ops().size())},
                    {"elapsed_ms", us / 1000}};
        }

        nlohmann::json UiDebugController::Tick(const nlohmann::json& opts) {
            if (!opts.contains("ms") || !opts["ms"].is_number_integer()) {
                return {{"ok", false}, {"error", "need integer 'ms'"}};
            }
            int ms = opts["ms"].get<int>();
            if (ms < 0) {
                ms = 0;
            }
            nlohmann::json out = nlohmann::json::object();
            out["ok"] = true;
            out["advanced_ms"] = ms;
            // Caret: floor(ms / 500) phase flips (the 500 ms caret timer).
            const int flips = ms / 500;
            if (window_ != nullptr) {
                window_->OnCaretBlinkTickForTest(flips);
            }
            out["caret_flipped"] = flips;
            // Animation: one frame with dt = ms/1000 (the 16 ms clock is a
            // cadence, not a fixed timestep; a single dt is deterministic and
            // headless-safe).
            if (window_ != nullptr) {
                window_->OnAnimationTimerForTest(
                    static_cast<float>(ms) / 1000.0f);
            }
            out["animations_advanced"] = window_ != nullptr;
            // Toast: advance the expiry clock by ms from now (delta-driven).
            if (root_ != nullptr) {
                const auto hits = FindByRole(*root_, "ToastHost");
                if (!hits.empty()) {
                    auto* host = const_cast<ToastHost*>(
                        dynamic_cast<const ToastHost*>(hits.front()));
                    if (host != nullptr) {
                        const std::size_t before = host->active_count();
                        host->Tick(std::chrono::steady_clock::now() +
                                   std::chrono::milliseconds(ms));
                        out["toasts_expired"] =
                            static_cast<long long>(before - host->active_count());
                    }
                }
            }
            if (out.contains("toasts_expired") == false) {
                out["toasts_expired"] = 0;
            }
            if (window_ != nullptr) {
                window_->Invalidate();
            }
            return out;
        }

        nlohmann::json UiDebugController::Drag(const nlohmann::json& opts) {
            Point from;
            Point to;
            std::string err;
            // from/to accept either a bare element id ({"from":"id"}) or an
            // object ({id|path|x,y}); run them through TargetPoint.
            const auto resolve_endpoint = [&](const char* key, Point& out,
                                              std::string& e) -> bool {
                if (!opts.contains(key)) {
                    e = std::string("need '") + key + "'";
                    return false;
                }
                nlohmann::json v = opts[key];
                if (v.is_string()) {
                    v = nlohmann::json{{"id", v.get<std::string>()}};
                } else if (!v.is_object()) {
                    e = std::string(key) + " must be an id string or object";
                    return false;
                }
                return TargetPoint(v, out, e);
            };
            if (!resolve_endpoint("from", from, err)) {
                return {{"ok", false}, {"error", err}};
            }
            if (!resolve_endpoint("to", to, err)) {
                return {{"ok", false}, {"error", err}};
            }
            if (window_ == nullptr) {
                return {{"ok", false}, {"error", "no window (input needs one)"}};
            }
            int steps = 5;
            if (opts.contains("steps") && opts["steps"].is_number_integer()) {
                steps = opts["steps"].get<int>();
            }
            if (steps < 1) {
                steps = 1;
            }
            nlohmann::json path = nlohmann::json::array();
            window_->RouteMouseForTest(WM_LBUTTONDOWN, from);
            bool consumed = true;
            for (int i = 1; i <= steps; ++i) {
                const float t = static_cast<float>(i) / static_cast<float>(steps);
                const Point p{from.x + (to.x - from.x) * t,
                              from.y + (to.y - from.y) * t};
                window_->RouteMouseForTest(WM_MOUSEMOVE, p);
                nlohmann::json step = {{"x", p.x}, {"y", p.y}};
                if (Element* hit = HitAt(p)) {
                    step["hit_role"] = hit->debug_role();
                    step["hit_id"] = hit->id.empty()
                                         ? nlohmann::json(nullptr)
                                         : nlohmann::json(hit->id);
                } else {
                    step["hit_role"] = nullptr;
                    step["hit_id"] = nullptr;
                }
                path.push_back(std::move(step));
            }
            window_->RouteMouseForTest(WM_LBUTTONUP, to);
            window_->Invalidate();
            return {{"ok", true},
                    {"consumed", consumed},
                    {"path", std::move(path)}};
        }

        nlohmann::json UiDebugController::Select(const nlohmann::json& opts) {
            if (root_ == nullptr) {
                return {{"ok", false}, {"error", "no root bound"}};
            }
            const Element* e = ResolveTarget(opts);
            if (e == nullptr) {
                return {{"ok", false}, {"error", "element not found"}};
            }
            auto* ti = const_cast<TextInputElement*>(
                dynamic_cast<const TextInputElement*>(e));
            if (ti == nullptr) {
                return {{"ok", false},
                        {"error", "target is not a TextInput"}};
            }
            std::size_t anchor = ti->selection_anchor();
            std::size_t caret = ti->caret_index();
            int anchor_i = static_cast<int>(anchor);
            int caret_i = static_cast<int>(caret);
            const int size = static_cast<int>(ti->value().size());
            if (opts.contains("anchor") && opts["anchor"].is_number_integer()) {
                anchor_i = opts["anchor"].get<int>();
            }
            if (opts.contains("caret") && opts["caret"].is_number_integer()) {
                caret_i = opts["caret"].get<int>();
            }
            if (anchor_i < 0) anchor_i = 0;
            if (caret_i < 0) caret_i = 0;
            if (anchor_i > size) anchor_i = size;
            if (caret_i > size) caret_i = size;
            ti->SetSelectionForTest(static_cast<std::size_t>(anchor_i),
                                    static_cast<std::size_t>(caret_i));
            const std::size_t lo = static_cast<std::size_t>(
                anchor_i < caret_i ? anchor_i : caret_i);
            const std::size_t hi = static_cast<std::size_t>(
                anchor_i < caret_i ? caret_i : anchor_i);
            const std::wstring sel = ti->value().substr(lo, hi - lo);
            if (window_ != nullptr) {
                window_->Invalidate();
            }
            return {{"ok", true},
                    {"anchor", ti->selection_anchor()},
                    {"caret", ti->caret_index()},
                    {"selection", Utf16ToUtf8(sel)},
                    {"caret_visible", ti->caret_visible()}};
        }

        nlohmann::json UiDebugController::Column(const nlohmann::json& opts) {
            if (root_ == nullptr) {
                return {{"ok", false}, {"error", "no root bound"}};
            }
            const Element* e = ResolveTarget(opts);
            if (e == nullptr) {
                return {{"ok", false}, {"error", "element not found"}};
            }
            auto* table = const_cast<TableElement*>(
                dynamic_cast<const TableElement*>(e));
            if (table == nullptr) {
                return {{"ok", false}, {"error", "target is not a Table"}};
            }
            const std::string action =
                opts.contains("action") && opts["action"].is_string()
                    ? opts["action"].get<std::string>()
                    : "read";
            if (action == "set") {
                if (opts.contains("widths") && opts["widths"].is_array()) {
                    std::vector<float> widths;
                    for (const auto& w : opts["widths"]) {
                        if (w.is_number()) {
                            widths.push_back(w.get<float>());
                        }
                    }
                    table->SetColumnWidthsForTest(std::move(widths));
                } else if (opts.contains("index") &&
                           opts["index"].is_number_integer() &&
                           opts.contains("width") &&
                           opts["width"].is_number()) {
                    table->SetColumnWidthForTest(
                        static_cast<std::size_t>(opts["index"].get<int>()),
                        opts["width"].get<float>());
                } else {
                    return {{"ok", false},
                            {"error", "need 'widths'[] or index+width"}};
                }
            } else if (action != "read") {
                return {{"ok", false}, {"error", "unknown action: " + action}};
            }
            if (window_ != nullptr) {
                window_->Invalidate();
            }
            nlohmann::json out = nlohmann::json::object();
            out["ok"] = true;
            out["action"] = action;
            out["resolved_widths"] = table->resolved_widths();
            out["user_widths"] = table->user_widths();
            out["user_resized"] = table->user_resized();
            return out;
        }

        nlohmann::json UiDebugController::Toast(const nlohmann::json& opts) {
            if (root_ == nullptr) {
                return {{"ok", false}, {"error", "no root bound"}};
            }
            ToastHost* host = nullptr;
            if (opts.contains("id") && opts["id"].is_string()) {
                const auto hits =
                    FindById(*root_, opts["id"].get<std::string>());
                if (!hits.empty()) {
                    host = const_cast<ToastHost*>(
                        dynamic_cast<const ToastHost*>(hits.front()));
                }
            } else {
                const auto hits = FindByRole(*root_, "ToastHost");
                if (!hits.empty()) {
                    host = const_cast<ToastHost*>(
                        dynamic_cast<const ToastHost*>(hits.front()));
                }
            }
            if (host == nullptr) {
                return {{"ok", false}, {"error", "no ToastHost found"}};
            }
            const std::string action =
                opts.contains("action") && opts["action"].is_string()
                    ? opts["action"].get<std::string>()
                    : "show";
            if (action == "show") {
                if (!opts.contains("text") || !opts["text"].is_string()) {
                    return {{"ok", false}, {"error", "show needs 'text'"}};
                }
                const std::wstring text =
                    Utf8ToWide(opts["text"].get<std::string>());
                ToastKind kind = ToastKind::Info;
                if (opts.contains("kind") && opts["kind"].is_string()) {
                    const std::string k = opts["kind"].get<std::string>();
                    if (k == "success") kind = ToastKind::Success;
                    else if (k == "warning") kind = ToastKind::Warning;
                    else if (k == "danger") kind = ToastKind::Danger;
                }
                host->ShowText(text, kind);
            } else if (action == "clear") {
                host->Clear();
            } else if (action == "state") {
                // read-only: fall through to the result below
            } else {
                return {{"ok", false}, {"error", "unknown action: " + action}};
            }
            const char* kKind[] = {"info", "success", "warning", "danger"};
            nlohmann::json toasts = nlohmann::json::array();
            for (const ToastEntry& t : host->toasts()) {
                const std::wstring text =
                    t.raw_text.empty() ? I18n::Instance().T(t.text)
                                       : t.raw_text;
                toasts.push_back({{"text", Utf16ToUtf8(text)},
                                  {"kind", kKind[static_cast<int>(t.kind)]}});
            }
            if (window_ != nullptr) {
                window_->Invalidate();
            }
            return {{"ok", true},
                    {"action", action},
                    {"active_count",
                     static_cast<long long>(host->active_count())},
                    {"toasts", std::move(toasts)}};
        }

        nlohmann::json UiDebugController::Set(const nlohmann::json& opts) {
            if (root_ == nullptr) {
                return {{"ok", false}, {"error", "no root bound"}};
            }
            Element* e = const_cast<Element*>(ResolveTarget(opts));
            if (e == nullptr) {
                return {{"ok", false}, {"error", "element not found"}};
            }
            bool touched = false;
            if (opts.contains("visible") && opts["visible"].is_boolean()) {
                e->visible = opts["visible"].get<bool>();
                touched = true;
            }
            if (opts.contains("enabled") && opts["enabled"].is_boolean()) {
                e->enabled = opts["enabled"].get<bool>();
                touched = true;
            }
            if (!touched) {
                return {{"ok", false},
                        {"error", "need 'visible' or 'enabled'"}};
            }
            e->InvalidateLayout();
            if (window_ != nullptr) {
                window_->RequestLayout();
                window_->Invalidate();
            }
            return {{"ok", true},
                    {"visible", e->visible},
                    {"enabled", e->enabled}};
        }

        nlohmann::json UiDebugController::Dpi(const nlohmann::json& opts) {
            if (!opts.contains("scale") || !opts["scale"].is_number()) {
                return {{"ok", false}, {"error", "need numeric 'scale'"}};
            }
            float scale = opts["scale"].get<float>();
            if (scale < 0.5f) {
                scale = 0.5f;
            }
            if (window_ == nullptr) {
                return {{"ok", false}, {"error", "no window"}};
            }
            window_->SetDpiForTest(scale);
            window_->RequestLayout();
            // Headless RequestLayout does not arrange (no hwnd). To keep the
            // arranged tree consistent with the new scale, re-arrange the root
            // to its current logical size (mirrors ResizeForTest's headless
            // path) when there is no hwnd.
            if (window_->hwnd() == nullptr && root_ != nullptr) {
                const Rect b = root_->bounds();
                if (b.w > 0.0f && b.h > 0.0f) {
                    root_->Arrange(b);
                }
            }
            return {{"ok", true},
                    {"scale", window_->scale()},
                    {"dpi", 96.0f * window_->scale()}};
        }

        nlohmann::json UiDebugController::Tray(const nlohmann::json& opts) {
            (void)opts;
            nlohmann::json out = nlohmann::json::object();
            out["ok"] = true;
            out["active"] = window_ != nullptr ? window_->tray_active() : false;
            // autostart reads HKCU; report null headless so a test never
            // depends on the host registry.
            out["autostart"] = (window_ != nullptr && window_->hwnd() != nullptr)
                                   ? nlohmann::json(tray::IsAutostartEnabled())
                                   : nlohmann::json(nullptr);
            // batch28: the menu items the next popup would show, built by the
            // same code (the popup is modal, so this is how the service label
            // is observable without opening it).
            nlohmann::json items = nlohmann::json::array();
            for (const auto& item : tray::MenuItems()) {
                items.push_back(nlohmann::json{
                    {"id", item.id},
                    {"label", WideToUtf8(item.label)},
                    {"checked", item.checked}});
            }
            out["items"] = std::move(items);
            return out;
        }

        namespace {

            /// Writes a big-endian 32-bit integer (PNG chunk length/CRC).
            void PushBE32(std::string& out, uint32_t v) {
                out.push_back(static_cast<char>((v >> 24) & 0xFF));
                out.push_back(static_cast<char>((v >> 16) & 0xFF));
                out.push_back(static_cast<char>((v >> 8) & 0xFF));
                out.push_back(static_cast<char>(v & 0xFF));
            }

            /// CRC-32 (PNG polynomial 0xEDB88320), table-free (small buffers).
            uint32_t PngCrc32(const std::string& data) {
                uint32_t crc = 0xFFFFFFFFu;
                for (unsigned char c : data) {
                    crc ^= c;
                    for (int k = 0; k < 8; ++k) {
                        crc = (crc >> 1) ^ (0xEDB88320u & (0u - (crc & 1u)));
                    }
                }
                return crc ^ 0xFFFFFFFFu;
            }

            /// Appends one PNG chunk (length, type, payload, CRC).
            void PushPngChunk(std::string& out, const char type[4],
                              const std::string& payload) {
                PushBE32(out, static_cast<uint32_t>(payload.size()));
                std::string crc_src;
                crc_src.append(type, 4);
                crc_src += payload;
                out.append(type, 4);
                out += payload;
                PushBE32(out, PngCrc32(crc_src));
            }

            /// Adler-32 over the raw deflate stream (zlib trailer).
            uint32_t Adler32(const std::string& data) {
                uint32_t a = 1, b = 0;
                for (unsigned char c : data) {
                    a = (a + c) % 65521u;
                    b = (b + a) % 65521u;
                }
                return (b << 16) | a;
            }

            /// Encodes 24-bit RGB pixels as a PNG using STORED (uncompressed)
            /// deflate blocks, so no compression library is needed. `rgb` is
            /// row-major, 3 bytes per pixel, `w` x `h`.
            std::string EncodePngRgb(const std::vector<unsigned char>& rgb,
                                     int w, int h) {
                std::string png;
                const unsigned char sig[8] = {0x89, 'P', 'N', 'G', '\r',
                                              '\n', 0x1A, '\n'};
                png.append(reinterpret_cast<const char*>(sig), 8);

                std::string ihdr;
                PushBE32(ihdr, static_cast<uint32_t>(w));
                PushBE32(ihdr, static_cast<uint32_t>(h));
                ihdr.push_back(8);   // bit depth
                ihdr.push_back(2);   // color type: truecolor RGB
                ihdr.push_back(0);   // compression
                ihdr.push_back(0);   // filter
                ihdr.push_back(0);   // interlace
                PushPngChunk(png, "IHDR", ihdr);

                // Raw scanlines: one filter byte (0) + RGB per row.
                std::string raw;
                raw.reserve(static_cast<std::size_t>(h) *
                            (1 + static_cast<std::size_t>(w) * 3));
                for (int y = 0; y < h; ++y) {
                    raw.push_back(0);
                    const std::size_t row = static_cast<std::size_t>(y) *
                                            static_cast<std::size_t>(w) * 3;
                    raw.append(reinterpret_cast<const char*>(rgb.data() + row),
                               static_cast<std::size_t>(w) * 3);
                }

                // zlib stream with stored deflate blocks (max 65535 per block).
                std::string z;
                z.push_back(0x78);  // CMF: deflate, 32K window
                z.push_back(0x01);  // FLG: (0x7801) no dict, fastest
                std::size_t pos = 0;
                while (pos < raw.size()) {
                    const std::size_t chunk =
                        std::min<std::size_t>(65535, raw.size() - pos);
                    const bool last = pos + chunk >= raw.size();
                    z.push_back(last ? 1 : 0);  // BFINAL/BTYPE=stored
                    const uint16_t len = static_cast<uint16_t>(chunk);
                    z.push_back(static_cast<char>(len & 0xFF));
                    z.push_back(static_cast<char>((len >> 8) & 0xFF));
                    z.push_back(static_cast<char>(~len & 0xFF));
                    z.push_back(static_cast<char>((~len >> 8) & 0xFF));
                    z.append(raw, pos, chunk);
                    pos += chunk;
                }
                PushBE32(z, Adler32(raw));
                PushPngChunk(png, "IDAT", z);
                PushPngChunk(png, "IEND", std::string());
                return png;
            }

            /// Captures the client area of `hwnd` via PrintWindow
            /// (PW_RENDERFULLCONTENT) into a 24-bit RGB buffer. Returns false
            /// when no pixels could be grabbed. GDI-only: no WinRT/WGC.
            bool CaptureClientRgb(HWND hwnd, std::vector<unsigned char>& rgb,
                                  int& w, int& h, std::string& method) {
                RECT rc{};
                if (!::GetClientRect(hwnd, &rc)) {
                    return false;
                }
                w = rc.right - rc.left;
                h = rc.bottom - rc.top;
                if (w <= 0 || h <= 0) {
                    return false;
                }
                HDC screen = ::GetDC(nullptr);
                if (screen == nullptr) {
                    return false;
                }
                HDC mem = ::CreateCompatibleDC(screen);
                BITMAPINFO bmi{};
                bmi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
                bmi.bmiHeader.biWidth = w;
                bmi.bmiHeader.biHeight = -h;  // top-down
                bmi.bmiHeader.biPlanes = 1;
                bmi.bmiHeader.biBitCount = 32;
                bmi.bmiHeader.biCompression = BI_RGB;
                void* bits = nullptr;
                HBITMAP bmp =
                    ::CreateDIBSection(screen, &bmi, DIB_RGB_COLORS, &bits,
                                       nullptr, 0);
                ::ReleaseDC(nullptr, screen);
                if (mem == nullptr || bmp == nullptr || bits == nullptr) {
                    if (bmp) ::DeleteObject(bmp);
                    if (mem) ::DeleteDC(mem);
                    return false;
                }
                const auto grab = [&]() {
                    const unsigned char* p =
                        static_cast<const unsigned char*>(bits);
                    rgb.resize(static_cast<std::size_t>(w) *
                               static_cast<std::size_t>(h) * 3);
                    for (std::size_t i = 0;
                         i < static_cast<std::size_t>(w) * h; ++i) {
                        rgb[i * 3 + 0] = p[i * 4 + 2];  // R
                        rgb[i * 3 + 1] = p[i * 4 + 1];  // G
                        rgb[i * 3 + 2] = p[i * 4 + 0];  // B
                    }
                };
                const auto all_black = [&]() {
                    for (std::size_t i = 0; i < rgb.size(); ++i) {
                        if (rgb[i] > 2) {
                            return false;
                        }
                    }
                    return true;
                };
                // Force one synchronous repaint so PrintWindow has fresh content.
                ::InvalidateRect(hwnd, nullptr, FALSE);
                ::UpdateWindow(hwnd);
                HGDIOBJ old = ::SelectObject(mem, bmp);
                constexpr UINT kPwRenderFullContent = 0x00000002;
                const BOOL pw = ::PrintWindow(hwnd, mem, kPwRenderFullContent);
                ::SelectObject(mem, old);
                if (pw) {
                    grab();
                    method = "printwindow";
                    if (!all_black()) {
                        ::DeleteObject(bmp);
                        ::DeleteDC(mem);
                        return true;
                    }
                }
                // PrintWindow returned black (D2D swapchain while occluded /
                // minimised): fall back to a screen-DC BitBlt of the same
                // client rect, which is correct whenever the window is visible.
                POINT org{0, 0};
                ::ClientToScreen(hwnd, &org);
                HDC screen2 = ::GetDC(nullptr);
                if (screen2 != nullptr) {
                    HDC mem2 = ::CreateCompatibleDC(screen2);
                    HGDIOBJ old2 = ::SelectObject(mem2, bmp);
                    const BOOL blt = ::BitBlt(mem2, 0, 0, w, h, screen2, org.x,
                                              org.y, SRCCOPY | CAPTUREBLT);
                    ::SelectObject(mem2, old2);
                    ::DeleteDC(mem2);
                    ::ReleaseDC(nullptr, screen2);
                    if (blt) {
                        grab();
                        method = "bitblt-screen";
                        if (!all_black()) {
                            ::DeleteObject(bmp);
                            ::DeleteDC(mem);
                            return true;
                        }
                    }
                }
                ::DeleteObject(bmp);
                ::DeleteDC(mem);
                return false;
            }

        }  // namespace

        nlohmann::json UiDebugController::Screenshot(const nlohmann::json& opts) {
            (void)opts;
            // T8: GDI PrintWindow capture (no WinRT). A live hwnd is required;
            // headless or a capture failure returns a blocked marker that never
            // fails the batch (spec L107-109: optional).
            if (window_ == nullptr || window_->hwnd() == nullptr) {
                return {{"ok", true}, {"blocked", true},
                        {"reason", "no hwnd"}};
            }
            std::vector<unsigned char> rgb;
            int w = 0;
            int h = 0;
            std::string method;
            if (!CaptureClientRgb(window_->hwnd(), rgb, w, h, method)) {
                return {{"ok", true}, {"blocked", true},
                        {"reason", "capture failed"}};
            }
            const std::string png = EncodePngRgb(rgb, w, h);
            const std::string path = "ui-debug-screenshot.png";
            std::ofstream out(path, std::ios::binary | std::ios::trunc);
            if (!out) {
                return {{"ok", true}, {"blocked", true},
                        {"reason", "cannot write png"}};
            }
            out.write(png.data(), static_cast<std::streamsize>(png.size()));
            out.close();
            return {{"ok", true}, {"path", path}, {"width", w},
                    {"height", h}, {"method", method}};
        }

    }  // namespace ui
}  // namespace vgww
