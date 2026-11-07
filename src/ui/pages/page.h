// ============================================================================
// page.h - page framework (S4.3 Task 7).
//
// A Page builds its element subtree into a host once (on first navigation)
// and then only updates it from immutable UiSnapshots. All page work happens
// on the UI thread and must never block it.
// ============================================================================
#pragma once

#include "ui/controls.h"
#include "ui/controller.h"
#include "ui/i18n.h"
#include "ui/snapshot.h"

#include <functional>
#include <string>
#include <string_view>
#include <utility>

namespace vgww {
    namespace ui {

        class Router;
        class UiController;

        /// Shared services handed to every page (shape frozen by the plan).
        struct PageContext {
            UiController* controller = nullptr;
            void (*navigate)(std::string_view) = nullptr;
            /// batch33 D: cross-page intent channel. Navigate to `id` and then
            /// hand `intent` to that page (a same-page call still delivers the
            /// intent). Empty in headless contexts that do not own a shell.
            std::function<void(std::string_view, std::string)> navigate_intent;
            std::function<void(Str, ToastKind)> toast;
            /// S5 GUI fix (G8): a page that changes I18n::Instance().SetLang()
            /// calls this to make the shell re-read every localized label
            /// immediately (UiApp::ApplyLanguage). Empty in headless contexts
            /// that do not own a UiApp; the app tick also applies a pending
            /// language change as a fallback.
            std::function<void()> apply_language;
            /// batch20: a page that changes the UI scale calls this with the
            /// new factor (0 = follow the desktop DPI). Empty in headless
            /// contexts; the window applies it immediately when bound.
            std::function<void(float)> apply_ui_scale;
            /// batch20: the effective UI scale (1.0 = 100%), used by the
            /// Settings page to display the desktop value while "auto".
            std::function<float()> effective_ui_scale;
            /// batch22 A1: a page that changes the appearance calls this with
            /// the requested mode ("dark"/"light"/"auto"); it returns the mode
            /// that is now active ("auto" resolves against the OS preference).
            /// Empty in headless contexts.
            std::function<std::string(const std::string&)> apply_theme;
            /// batch24 P1-4: a page that saved a config needing a restart asks
            /// this to relaunch the process (release the single-instance gate,
            /// spawn the child, exit). Empty in headless contexts (no-op).
            std::function<void()> restart_app;
            /// batch27 P1-5: a page can start the first-run setup flow that the
            /// shell owns (the dashboard's "set it up for me"). Empty in
            /// headless contexts that do not own a shell; the page then falls
            /// back to navigating to Settings.
            std::function<void()> open_setup;
        };

        /// One page of the shell. `title()` is a Str key so a language switch
        /// can relabel the header without rebuilding the page.
        class Page {
        public:
            virtual ~Page() = default;
            virtual const char* id() const = 0;
            virtual Str title() const = 0;
            virtual void Build(Element& host, PageContext& ctx) = 0;
            virtual void Update(const UiSnapshot& snapshot, I18n& i18n) = 0;
            /// batch33 D: a cross-page navigation carries an intent (e.g.
            /// "mac=AA:BB:.."), which the target page applies to its own
            /// controls (open a pre-filled form, scroll to a row, ...).
            /// Default: no intent handling.
            virtual void OnIntent(const std::string& intent) { (void)intent; }
            /// batch27 P1-6: the shell asks the CURRENT page before switching
            /// away. A page with unsaved edits returns false and arranges for
            /// `proceed` to run if the operator confirms (the shell does not
            /// navigate until then). Default: leaving is always fine.
            virtual bool ConfirmLeave(std::function<void()> proceed) {
                (void)proceed;
                return true;
            }
            /// batch281: a command this shell posted FAILED (the executor
            /// returned `ok == false`). Pages that arm an in-flight "busy"
            /// indicator on click use this to release it: a failed start/stop
            /// never reaches the state the click asked for, so waiting for a
            /// snapshot left the primary action disabled forever.
            /// Default: nothing.
            virtual void OnCommandFailed() {}
        };

        /// The app installs its router as the navigation target;
        /// PageContext::navigate is a plain function pointer (frozen shape),
        /// so the trampoline needs a target (single-window app: one router).
        void SetNavigateTarget(Router* router) noexcept;

        /// Builds the standard page context (navigate = trampoline above).
        PageContext MakePageContext(UiController* controller,
                                    std::function<void(Str, ToastKind)> toast);

        /// batch33 D: the intent trampoline's target (same one-router rule as
        /// SetNavigateTarget); empty = intents are dropped.
        void SetNavigateIntentTarget(Router* router) noexcept;
        /// Delivers `intent` to the router's current page after navigating.
        void NavigateIntentThunk(std::string_view id, std::string intent);

        /// U6: submits one command through the controller; when the command
        /// queue is full (Post returns false) the caller is surfaced a "busy"
        /// toast instead of the command being silently dropped. Returns
        /// whether the command was accepted.
        inline bool SubmitCommand(PageContext& ctx, Command cmd) {
            if (ctx.controller == nullptr) {
                return false;
            }
            if (ctx.controller->Post(std::move(cmd))) {
                return true;
            }
            if (ctx.toast) {
                ctx.toast(Str::CommonBusy, ToastKind::Warning);
            }
            return false;
        }

        /// Registration extension point: T8-T10 append their pages here.
        void RegisterAllPages(Router& router, PageContext& ctx);

    }  // namespace ui
}  // namespace vgww
