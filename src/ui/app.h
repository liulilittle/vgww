// ============================================================================
// app.h - shell assembly and message loop (S4.3 Task 7).
//
// UiApp owns the shell element tree (sidebar + page header + content host +
// toast overlay), the Router and the window. Compose() is the headless seam
// (tests arrange/hit-test the tree without creating a window); Run() adds the
// window, the tray and the 200 ms snapshot/language tick.
// ============================================================================
#pragma once

#include "ui/controller.h"
#include "ui/pages/page.h"
#include "ui/router.h"
#include "ui/window.h"
#include "core/config.h"

#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <utility>

namespace vgww {
    namespace ui {

        /// Autostart hook for DataplaneCommandExecutor (T5 seam; the entry
        /// point wires it): writes HKCU Run through the tray and keeps the
        /// tray menu check mark in sync, so a page-issued SetAutostartCmd
        /// behaves exactly like the tray menu item.
        CommandResult TrayAutostartHook(const SetAutostartCmd& cmd);

        class UiApp final {
        public:
            UiApp();
            ~UiApp();

            UiApp(const UiApp&) = delete;
            UiApp& operator=(const UiApp&) = delete;

            /// Builds the shell tree + router (no window); safe to call once.
            void Compose(UiController& controller, const UiSnapshot& first);

            /// Window + tray + message loop; returns the process exit code.
            /// `initial_page` (S5.20, from --ui-page) overrides the default
            /// home page; empty keeps the existing dashboard-first behaviour.
            int Run(HINSTANCE instance, UiController& controller,
                    const UiSnapshot& first, bool start_minimized,
                    const std::string& initial_page = {});

            // Shell accessors / test anchors.
            Element& root() noexcept { return *root_; }
            Router& router() noexcept { return *router_; }
            Sidebar& sidebar() noexcept { return *sidebar_; }
            PageHeader& header() noexcept { return *header_; }
            ToastHost& toasts() noexcept { return *toasts_; }
            Element& content() noexcept { return *content_; }
            /// Test anchor: the owned window (headless until Run creates it).
            VgwwWindow& window() noexcept { return window_; }

            /// Initial-screen ownership (T7 review M1): navigates to the
            /// first registered page when none is current; no-op without
            /// pages or when a page is already shown. Compose() calls it at
            /// the end; T11 may call it again after assembling its pages.
            /// S5.20: when `initial_page_` is set it wins over the default
            /// home page (unknown ids fall back to the first registered page).
            void NavigateInitialPage();

            /// Test anchor (S5.20): injects the --ui-page value before the
            /// first NavigateInitialPage() so the initial-screen navigation
            /// is testable headless. Run() sets this member itself; tests
            /// only.
            void SetInitialPageForTest(std::string id) {
                initial_page_ = std::move(id);
            }

            /// Applies one snapshot to the shell (header badge, current page).
            void Update(const UiSnapshot& snapshot);
            /// W11 batch4 M10-2-lite: adopts the caller's snapshot object
            /// (shared ownership, NO deep copy). The OnTick path passes the
            /// controller's freshly loaded shared_ptr, eliminating the second
            /// whole-snapshot copy that used to run on the UI thread on every
            /// new seq (former app.cpp:390). The const& overload above stays
            /// as the copy path (tests and one-off callers); the snapshot is
            /// immutable by contract, so sharing is safe.
            void Update(std::shared_ptr<const UiSnapshot> snapshot);
            /// W11 batch4 M10-2-lite test seam: the snapshot object the app
            /// currently holds (identity-assertable; nullptr before the first
            /// adopt/Update).
            const UiSnapshot* current_snapshot_for_test() const noexcept {
                return snapshot_.get();
            }
            /// Re-reads every localized label (sidebar, header, built pages).
            void ApplyLanguage();
            /// T8 test anchor: runs one app tick (the same path the 200 ms
            /// snapshot timer drives) so a headless test can verify the tick
            /// counters are backfilled into the window. Safe without a
            /// controller (the metrics backfill still runs).
            void OnTickForTest() { OnTick(); }

            /// batch42 test seam: drain pending command results and toast save
            /// outcomes WITHOUT the snapshot poll/reflect OnTick does. Tests
            /// that drive settings saves with a mock executor use this to get
            /// the result-driven toast without adopting a new snapshot (which
            /// would clobber the form back to the fixture values).
            void DrainCommandResultsForTest() { DrainCommandResults(); }

            /// batch22 B4: thread-safe entry point for the web API. The actual
            /// repair touches UI state (toasts, in-flight flag), so the request
            /// is latched here and serviced by OnTick() on the UI thread.
            void QueueDriverRepairFromWeb() {
                web_repair_requested_.store(true);
            }

            /// batch37t: thread-safe entry point for Web POST /api/config.
            /// The UI thread drains it in OnTick and posts the normal
            /// SaveConfigCmd, so validation, persistence and the live apply
            /// are exactly the native settings path.
            void QueueConfigSaveFromWeb(
                const core::Config& config,
                std::function<void(bool, const std::string&)> result_sink = {}) {
                {
                    std::lock_guard<std::mutex> lock(web_config_mutex_);
                    web_config_ = config;
                    web_config_result_ = std::move(result_sink);
                }
                web_config_pending_.store(true);
            }

            // -- batch25b test seams ----------------------------------------
            /// Runs the first-run decision exactly like Run() does. Returns
            /// true when the wizard was shown (the snapshot was unusable for
            /// a first run and this launch has not configured anything yet).
            bool MaybeShowFirstRunWizardForTest(const UiSnapshot& snapshot) {
                return MaybeShowFirstRunWizard(snapshot);
            }
            /// Runs the app-side WM_CLOSE decision (first close explains that
            /// the service keeps running; later closes hide directly).
            void HandleCloseRequestForTest() { OnCloseRequested(); }
            /// batch28: runs the exact tray start/stop handler Run() installs
            /// (true = start), so a headless test can assert it posts exactly
            /// one command through the normal queue.
            void ToggleServiceFromTrayForTest(bool start) {
                ToggleServiceFromTray(start);
            }
            /// batch29: runs the exact tray "Open dashboard" handler Run()
            /// installs (window visibility is the window's job; this is the
            /// page switch), so a headless test can assert the page changed.
            void OpenDashboardFromTrayForTest() { OpenDashboardFromTray(); }
            /// Current page id (headless seam for the tray test).
            std::string CurrentPageForTest() const {
                return router_ != nullptr && router_->current() != nullptr
                           ? std::string(router_->current()->id())
                           : std::string();
            }
            /// batch31 P0-2: runs the exact sidebar-click entry point
            /// (NavigateTo: popup dismissal, ConfirmLeave, router, on_changed)
            /// so a headless test can assert a same-tab click is a no-op.
            void NavigateToForTest(const std::string& id) { NavigateTo(id); }
            /// batch33 D: intent-carrying navigation through the same shell
            /// path (popup dismissal, ConfirmLeave, router, on_changed).
            void NavigateToIntentForTest(const std::string& id,
                                         const std::string& intent) {
                NavigateTo(id, intent);
            }

        private:
            std::atomic<bool> web_repair_requested_{false};
            std::atomic<bool> web_config_pending_{false};
            std::mutex web_config_mutex_;
            vgww::core::Config web_config_;
            std::function<void(bool, const std::string&)> web_config_result_;

            void OnTick();
            /// batch42: drain command results and toast save outcomes; callers
            /// must run it on the UI thread. OnTick calls it as part of the
            /// tick; the test seam calls it alone.
            bool DrainCommandResults();
            void NavigateTo(const std::string& id);
            /// batch33 D: navigate + deliver a cross-page intent to the target
            /// page (same ConfirmLeave / popup-dismissal path).
            void NavigateTo(const std::string& id, const std::string& intent);
            void UpdateHeaderTitle();
            /// C3: re-launch this exe elevated to install/re-grant the ndisrd
            /// driver, then inform the operator (toast). Batch16 F2.3: the
            /// elevated child and its wait run on a detached worker thread;
            /// OnTick() polls and toasts the outcome.
            void RequestDriverRepair();
            /// batch25b: first-run wizard + close-meaning prompt.
            bool MaybeShowFirstRunWizard(const UiSnapshot& snapshot);
            void SubmitFirstRun(const ConfigView& view,
                                const std::string& config_path,
                                const std::string& adapter,
                                const std::string& internet_mode);
            void OnCloseRequested();
            /// batch28: the ONE start/stop decision used by the tray item.
            void ToggleServiceFromTray(bool start);
            /// batch29: tray "Open dashboard" page switch.
            void OpenDashboardFromTray();

            /// State shared with the elevated-repair worker thread (the
            /// worker holds its own shared_ptr, so a closing app cannot be
            /// touched after destruction).
            struct RepairAsyncState {
                std::mutex mutex;
                bool done = false;
                bool ok = false;
                std::wstring summary;
            };

            UiController* controller_ = nullptr;
            std::unique_ptr<Element> root_;
            std::unique_ptr<Router> router_;
            Sidebar* sidebar_ = nullptr;
            PageHeader* header_ = nullptr;
            Element* content_ = nullptr;
            /// batch19 R4-P4: initial UI language from the config ("" = use the
            /// OS locale; an unknown code falls back to zh-CN).
            std::string initial_language_;
            /// batch20: initial fixed UI scale (0 = auto / follow desktop).
            float initial_ui_scale_ = 0.0f;

        public:
            void SetInitialLanguage(std::string code) {
                initial_language_ = std::move(code);
            }
            void SetInitialUiScale(float scale) { initial_ui_scale_ = scale; }

            /// batch24 P1-4: installs the save->restart handler (the entry
            /// point owns the single-instance gate + process spawn). Called
            /// before Run(); Compose() forwards PageContext::restart_app here.
            void SetRestartHandler(std::function<void()> handler) {
                restart_handler_ = std::move(handler);
            }

        private:
            std::function<void()> restart_handler_;
            DriverBanner* banner_ = nullptr;   ///< unified failure banner (R2)
            ToastHost* toasts_ = nullptr;
            /// batch25b: shell-level modal host (close prompt + first-run
            /// wizard). Page dialogs stay page-owned; this one is always in
            /// the right column's overlay layer.
            DialogHost* dialog_ = nullptr;
            bool first_run_decided_ = false;
            bool close_prompt_shown_ = false;
            /// P2: last banner visibility; a show/hide changes the content
            /// flow height, so that transition still needs a relayout.
            bool banner_was_visible_ = false;
            /// Perf (M6, batch3): last UiContentEpoch() sample seen by
            /// Update(); compared against the current value to decide whether
            /// any element's content changed since the cached sample. This
            /// replaces the old whole-tree content_rev sum (both the
            /// before/after double walk and the single-walk version): every
            /// content_rev increment bumps the epoch, so detection is O(1)
            /// and cannot be fooled by two different tree states summing to
            /// the same value.
            uint64_t last_content_epoch_ = 0;
            /// Perf (T5): last structural epoch seen by Update(); a subtree
            /// removal (DialogHost::Reset) lowers the tree sum but must still
            /// force a relayout, so the epoch is compared alongside the sum.
            uint64_t last_tree_epoch_ = 0;
            PageContext context_{};
            VgwwWindow window_;
            std::shared_ptr<const UiSnapshot> snapshot_;
            /// b28-legibility P5: last service state seen, so a state switch
            /// can drop a stale hover tooltip.
            bool last_service_running_ = false;
            bool last_service_running_known_ = false;
            vgww::ui::Lang language_ = vgww::ui::Lang::ZhCN;
            bool composed_ = false;
            std::string initial_page_;  ///< S5.20: --ui-page start page
            std::shared_ptr<RepairAsyncState> repair_state_;
            bool repair_in_flight_ = false;
        };

    }  // namespace ui
}  // namespace vgww
