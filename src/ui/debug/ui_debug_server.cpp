#include "ui/debug/ui_debug_server.h"

#include <nlohmann/json.hpp>

namespace vgww {
    namespace ui {

        UiDebugServer::UiDebugServer()
            : server_(std::make_unique<vgww::web::HttpServer>()) {}

        UiDebugServer::~UiDebugServer() = default;

        void UiDebugServer::BindController(UiDebugController* controller) {
            controller_ = controller;
        }

        bool UiDebugServer::Start(uint16_t port, std::string& error) {
            if (controller_ == nullptr) {
                error = "no controller bound";
                return false;
            }
            server_->Route("POST", "/debug",
                           [this](const web::Request& req) {
                               return HandleDebug(req);
                           });
            server_->Route("GET", "/debug/health",
                           [](const web::Request&) {
                               return web::Response::Json("{\"ok\":true}");
                           });
            return server_->Start("127.0.0.1", port, error);
        }

        void UiDebugServer::Stop() noexcept { server_->Stop(); }

        web::Response UiDebugServer::HandleDebug(const web::Request& req) {
            if (controller_ == nullptr) {
                return web::Response::Error(503, "controller not bound");
            }
            nlohmann::json batch;
            try {
                batch = nlohmann::json::parse(req.body);
            } catch (const nlohmann::json::parse_error&) {
                return web::Response::Error(400, "invalid json body");
            }
            if (!batch.is_array()) {
                return web::Response::Error(
                    400, "body must be an array of commands");
            }
            const nlohmann::json out = controller_->SubmitBatch(batch);
            return web::Response::Json(out.dump());
        }

    }  // namespace ui
}  // namespace vgww
