// ============================================================================
// ui_debug_server.h - CDP-style HTTP debug channel for the native UI.
//
// Default off. Started only when --ui-debug-port=<n> is passed. Binds
// 127.0.0.1 only. POST /debug executes a batch of UI commands on the UI
// thread and returns {results:[...]}.
// ============================================================================
#pragma once

#include "ui/debug/ui_debug_controller.h"

#include "web/http_server.h"

#include <cstdint>
#include <memory>
#include <string>

namespace vgww {
    namespace ui {

        class UiDebugServer final {
        public:
            UiDebugServer();
            ~UiDebugServer();

            UiDebugServer(const UiDebugServer&) = delete;
            UiDebugServer& operator=(const UiDebugServer&) = delete;

            /// Binds the controller. All pointers borrowed and must outlive the
            /// server; root is required for tree ops.
            void BindController(UiDebugController* controller);

            /// Starts the loopback server; returns false + error on bind fail.
            bool Start(uint16_t port, std::string& error);

            void Stop() noexcept;
            /// Bound port (0 before Start / after a failed Start). The host
            /// can pass 0 for an OS-assigned port only if HttpServer reports
            /// the real one; HttpServer currently stores the requested value,
            /// so callers should pass a concrete port (Task 6 deviation).
            uint16_t Port() const noexcept {
                return server_ ? server_->Port() : 0;
            }
            bool running() const noexcept { return Port() != 0; }

            web::Response HandleDebug(const web::Request& req);

        private:
            UiDebugController* controller_ = nullptr;
            std::unique_ptr<vgww::web::HttpServer> server_;
        };

    }  // namespace ui
}  // namespace vgww
