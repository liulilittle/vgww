// ============================================================================
// ui_debug_controller.h - UI-thread execution engine for the debug channel.
//
// Runs JSON commands against the live element tree / window on the UI thread
// (the window's message loop drains a queue). Binding is optional-headless:
// a null window still allows tree/query/serialize ops for unit tests.
// ============================================================================
#pragma once

#include "ui/debug/ui_debug_serialize.h"

#include <nlohmann/json.hpp>

#include <deque>
#include <future>
#include <memory>
#include <mutex>
#include <string>

namespace vgww {
    namespace ui {

        class VgwwWindow;
        class Router;
        class UiApp;

        /// Single-command executor for the CDP-style debug channel. The
        /// observe ops (`tree`/`query`/`state`) are implemented here; later
        /// tasks add input/control ops. All pointers are borrowed.
        class UiDebugController final {
        public:
            /// T8: `wait` no longer polls (it evaluates its predicate once and
            /// returns, so it never blocks the UI thread / freezes timers). The
            /// transport wait below still bounds how long SubmitBatch waits for
            /// a live UI-thread drain.
            static constexpr long long kWaitMaxMs = 10000;
            static constexpr long long kCommandWaitMs = kWaitMaxMs + 2000;
            /// T8: bounded drain - at most this many queued commands run per
            /// UI-thread wake; any remainder is re-posted (design L86-88), so
            /// a large batch cannot stall repaint. The transport wait
            /// (kCommandWaitMs) still bounds the total.
            static constexpr std::size_t kDrainBatchMax = 16;

            UiDebugController();

            /// Binds the live objects. All pointers are borrowed (must outlive
            /// the controller). Any of window/router/app may be null (headless
            /// unit tests); root is required for tree/query ops.
            void Bind(Element* root, VgwwWindow* window, Router* router,
                      UiApp* app);

            /// Executes one command (run on the UI thread). Never throws:
            /// malformed commands return {"ok":false,"error":...}. A known op
            /// returns {"ok":true,"op":<op>,"data":<result>}; an unimplemented
            /// op returns {"ok":false,"error":"unknown command: <op>"}.
            nlohmann::json RunOneCommand(const nlohmann::json& cmd);

            /// Runs one batch of commands. When the bound window has a live
            /// hwnd the commands are marshaled to the UI thread (queue +
            /// PostUiDebug wake + promise, bounded wait); otherwise - headless
            /// tests or a dead window - they run inline on the caller so
            /// nothing ever waits on a promise no UI thread will drain.
            /// Returns {"results":[...]}, each entry already the uniform
            /// per-command envelope from RunOneCommand.
            nlohmann::json SubmitBatch(const nlohmann::json& cmds);
            /// UI-thread pump: runs every queued command and fulfils its
            /// promise. Safe to call with an empty queue.
            void DrainOnUiThread();
            /// Posts a wake to the bound window. Returns false (no-op) when
            /// no window is bound or it has no live hwnd, so SubmitBatch can
            /// fall back to inline execution.
            bool WakeWindow();

            // Command implementations (each returns the raw result data).
            /// Serializes the tree (spec L92-96). `opts` may carry `include_hidden`,
            /// `max_depth` and `subtree` (an element id that re-roots the
            /// serialization). On failure (no root, or an unknown `subtree` id)
            /// returns an empty object and, when non-null, sets `*error`.
            nlohmann::json Tree(const nlohmann::json& opts,
                                std::string* error = nullptr);
            nlohmann::json Query(const nlohmann::json& opts);
            nlohmann::json State();

            // Input commands. Each returns a raw result object shaped
            // {"ok":<bool>, ...}; RunOneCommand wraps it into the per-command
            // envelope {"ok":<bool>,"op":<name>,"data":<result>} and hoists a
            // handler `error` to the envelope so callers see `ok`/`error` at
            // the top level.
            nlohmann::json Click(const nlohmann::json& opts);
            /// batch37e: WM_LBUTTONDBLCLK at a point (real double-click
            /// semantics; the OS sends this instead of a second button-down).
            nlohmann::json DoubleClick(const nlohmann::json& opts);
            /// batch33 E: right-button press+release at a point (or an
            /// element's centre). `mousedown`/`mouseup` only dispatch the LEFT
            /// button, so without this the context-menu path had no live
            /// window seam at all. Reports whether the RELEASE was consumed
            /// (that is the event which opens a row menu) plus the topmost hit.
            nlohmann::json RClick(const nlohmann::json& opts);
            nlohmann::json MouseDown(const nlohmann::json& opts);
            nlohmann::json MouseUp(const nlohmann::json& opts);
            nlohmann::json MouseMove(const nlohmann::json& opts);
            nlohmann::json Hover(const nlohmann::json& opts);
            nlohmann::json Wheel(const nlohmann::json& opts);
            nlohmann::json Type(const nlohmann::json& opts);
            nlohmann::json Key(const nlohmann::json& opts);
            nlohmann::json Focus(const nlohmann::json& opts);

            // Control commands. Each returns a raw result object shaped
            // {"ok":<bool>, ...}; RunOneCommand wraps it into the same uniform
            // per-command envelope as the input ops ({"ok","op","data"}), so a
            // control payload (passed/matched/page/rect) is read under "data"
            // and a failing handler hoists its `error` (spec L132). A failed
            // assert is data (outer ok true, data.passed false), not an error.
            nlohmann::json Navigate(const nlohmann::json& opts);
            nlohmann::json Dialog(const nlohmann::json& opts);
            nlohmann::json Resize(const nlohmann::json& opts);
            nlohmann::json Language(const nlohmann::json& opts);
            nlohmann::json Wait(const nlohmann::json& opts);
            nlohmann::json Assert(const nlohmann::json& opts);

            // Render introspection (spec L101-109). Each returns a raw result
            // object shaped {"ok":<bool>, ...} and is wrapped into the same
            // uniform per-command envelope ({"ok","op","data"}) as the
            // input/control ops, so the payload (ops/coverage/screenshot) is
            // read under "data". draw_ops/occlusion record a fresh frame via
            // VgwwWindow::RenderFrameForTest (record mode is render-target
            // independent, so it works headless); screenshot is a v1 no-pixel
            // stub that never fails the batch.
            nlohmann::json DrawOps();
            nlohmann::json Occlusion(const nlohmann::json& opts);
            nlohmann::json Screenshot(const nlohmann::json& opts);

            // T8 ops: metrics / render / tick / drag / select / column / toast
            // / set / dpi / tray. Same uniform envelope as every other op.
            /// Window/frame counters: paint/tick counts, timings, layout
            /// requests, recorded op count, animation frames, fps/dropped-frames
            /// and the renderer's draw/cache counters. Pure read. fps and
            /// dropped_frames are now REAL frame statistics (a static page reads
            /// 0 fps through the wall-clock idle check; headless stays 0) - cpu
            /// metrics are never fabricated.
            nlohmann::json Metrics();
            /// mode="record" (default): records one frame (render-target
            /// independent) and reports the op count + elapsed. mode="paint":
            /// a real Paint() pass (GUI only; headless reports blocked).
            nlohmann::json Render(const nlohmann::json& opts);
            /// Deterministic time advance (no sleep): caret phase (floor(ms/500)
            /// flips), one animation frame (dt=ms/1000) and toast expiry
            /// (Tick(now+ms)).
            nlohmann::json Tick(const nlohmann::json& opts);
            /// Aggregated pointer drag from/to via the window's client-pointer
            /// seam, recording the hit role/id at each step.
            nlohmann::json Drag(const nlohmann::json& opts);
            /// Sets a TextInput selection (anchor/caret) and reads it back.
            nlohmann::json Select(const nlohmann::json& opts);
            /// Table column widths: action "read"/"set".
            nlohmann::json Column(const nlohmann::json& opts);
            /// ToastHost: action "show"/"clear"/"state".
            nlohmann::json Toast(const nlohmann::json& opts);
            /// Writes visible/enabled on the target and reads it back.
            nlohmann::json Set(const nlohmann::json& opts);
            /// Sets the window DPI scale and re-arranges.
            nlohmann::json Dpi(const nlohmann::json& opts);
            /// Tray state (read-only: active/autostart).
            nlohmann::json Tray(const nlohmann::json& opts);

        private:
            /// Finds the element targeted by {"id":...}; nullptr when absent.
            const Element* ResolveTarget(const nlohmann::json& opts) const;
            /// Resolves a condition value that is either a bare id string or
            /// an object carrying {"id":...} / {"path":...} to an element.
            const Element* ResolveTargetBy(const nlohmann::json& v) const;
            /// Evaluates a condition object; sets `why` on mismatch.
            bool EvalCondition(const nlohmann::json& cond, std::string& why) const;
            /// Serializes one query match into a hit entry (path/id/role/rect).
            nlohmann::json QueryHit(const Element& e) const;

            /// Resolves opts to a logical point: {"id"/"path"} -> element
            /// center, else {"x","y"}. False + `error` when neither is valid.
            bool TargetPoint(const nlohmann::json& opts, Point& out,
                             std::string& error) const;
            /// Topmost (overlay-first) element at a logical point; nullptr
            /// without a window or when nothing is hit.
            Element* HitAt(Point p) const;
            /// Routes one pointer message through the window's topmost hit
            /// (kind: "down"/"up"/"move"/"wheel"), then invalidates.
            void DispatchPointer(const char* kind, Point p, int wheel_delta);

            Element* root_ = nullptr;
            VgwwWindow* window_ = nullptr;
            Router* router_ = nullptr;
            UiApp* app_ = nullptr;

            /// One command waiting for the UI thread. The promise is fulfilled
            /// by DrainOnUiThread; the shared_ptr keeps it alive if the waiter
            /// times out (a late drain may still set the value harmlessly).
            struct PendingCommand {
                nlohmann::json cmd;
                std::promise<nlohmann::json> result;
            };
            std::deque<std::shared_ptr<PendingCommand>> queue_;
            std::mutex queue_mutex_;
        };

    }  // namespace ui
}  // namespace vgww
