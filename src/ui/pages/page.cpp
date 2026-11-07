// ============================================================================
// page.cpp - page framework helpers (S4.3 Task 7).
// ============================================================================
#include "ui/pages/page.h"

#include "ui/router.h"

#include <memory>
#include <utility>

namespace vgww {
    namespace ui {

        /// Page factories live with their page (S4.3 Task 8): page.cpp stays
        /// the single registration point without pulling the page classes
        /// into its include graph.
        std::unique_ptr<Page> MakeDashboardPage();
        std::unique_ptr<Page> MakeLeasesPage();
        std::unique_ptr<Page> MakePortmapPage();
        std::unique_ptr<Page> MakeFirewallPage();
        std::unique_ptr<Page> MakeRatelimitPage();
        std::unique_ptr<Page> MakeBridgePage();
        std::unique_ptr<Page> MakeSettingsPage();
        std::unique_ptr<Page> MakeAboutPage();
        std::unique_ptr<Page> MakeConsolePage();

        namespace {

            Router* g_navigate_target = nullptr;
            Router* g_navigate_intent_target = nullptr;

            void NavigateThunk(std::string_view id) {
                if (g_navigate_target != nullptr) {
                    g_navigate_target->Navigate(id);
                }
            }

        }  // namespace

        void SetNavigateTarget(Router* router) noexcept {
            g_navigate_target = router;
        }

        void SetNavigateIntentTarget(Router* router) noexcept {
            g_navigate_intent_target = router;
        }

        void NavigateIntentThunk(std::string_view id, std::string intent) {
            if (g_navigate_intent_target != nullptr) {
                g_navigate_intent_target->NavigateWithIntent(id,
                                                             std::move(intent));
            }
        }

        PageContext MakePageContext(UiController* controller,
                                    std::function<void(Str, ToastKind)> toast) {
            PageContext ctx;
            ctx.controller = controller;
            ctx.navigate = &NavigateThunk;
            ctx.navigate_intent = &NavigateIntentThunk;
            ctx.toast = std::move(toast);
            return ctx;
        }

        void RegisterAllPages(Router& router, PageContext& ctx) {
            (void)ctx;
            router.Register(MakeDashboardPage());
            router.Register(MakeLeasesPage());
            router.Register(MakePortmapPage());
            router.Register(MakeFirewallPage());
            router.Register(MakeRatelimitPage());
            router.Register(MakeBridgePage());
            router.Register(MakeSettingsPage());
            router.Register(MakeAboutPage());
            router.Register(MakeConsolePage());  // batch19 R3-2: 9th page
        }

    }  // namespace ui
}  // namespace vgww
