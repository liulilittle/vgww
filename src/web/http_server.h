// ============================================================================
// http_server.h - Minimal embedded HTTP/1.1 server (asio, zero dependencies).
//
// Design goals (user mandate: lightweight, in-process, no external web
// server): single-digit-hundred-line core, no thread pool explosion (one
// acceptor thread + per-connection async on the SAME io_context), bounded
// request size, keep-alive optional.
//
// Routing: exact-path table {(method, path) -> handler}. Handlers return a
// Response synchronously; heavy work belongs in the data plane, not here.
// ============================================================================
#pragma once

#include "core/handler_guard.h"

#include <asio.hpp>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace vgww {
    namespace web {

        /// Marshal `in` into the body of a JSON string literal.
        ///
        /// This is the ONLY JSON string escaper in the codebase. It used to
        /// exist twice (HttpServer's error bodies and web_api's success
        /// bodies); the copies drifted and the API one kept DROPPING bytes
        /// below 0x20, which silently glued multi-line console output into a
        /// single run-on line. RFC 8259 section 7 has a lossless spelling for
        /// every byte, so the contract here is byte-for-byte round-trip.
        inline std::string JsonEscaped(const std::string& in) {
            static const char kHex[] = "0123456789abcdef";
            std::string out;
            out.reserve(in.size() + 8);
            for (const char c : in) {
                switch (c) {
                    case '"':
                        out += "\\\"";
                        continue;
                    case '\\':
                        out += "\\\\";
                        continue;
                    case '\b':
                        out += "\\b";
                        continue;
                    case '\f':
                        out += "\\f";
                        continue;
                    case '\n':
                        out += "\\n";
                        continue;
                    case '\r':
                        out += "\\r";
                        continue;
                    case '\t':
                        out += "\\t";
                        continue;
                    default:
                        break;
                }
                if (static_cast<unsigned char>(c) < 0x20) {
                    out += "\\u00";
                    out.push_back(kHex[(c >> 4) & 0x0F]);
                    out.push_back(kHex[c & 0x0F]);
                    continue;
                }
                out.push_back(c);
            }
            return out;
        }

        struct Request final {
            std::string method;                    ///< "GET" / "POST" / ...
            std::string path;                      ///< "/api/status"
            std::map<std::string, std::string> query;  ///< parsed ?a=b&c=d
            std::map<std::string, std::string> headers;
            std::string body;
        };

        struct Response final {
            int status = 200;
            std::string content_type = "application/json";
            std::vector<std::pair<std::string, std::string>> extra_headers;
            std::string body;

            static Response Json(const std::string& json, int status = 200);
            static Response Text(const std::string& text, int status = 200);
            static Response Error(int status, const std::string& message);
        };

        class HttpServer final {
        public:
            typedef std::function<Response(const Request&)> Handler;

            HttpServer();
            ~HttpServer();

            HttpServer(const HttpServer&) = delete;
            HttpServer& operator=(const HttpServer&) = delete;

            /// Registers a route. Later registrations win (allows overrides).
            void Route(const std::string& method, const std::string& path,
                       Handler handler);

            /// Write guard: when set, every non-GET request is first passed
            /// through `guard`; a non-null return is sent instead of running
            /// the handler (used for token auth on mutating API calls).
            void SetWriteGuard(std::function<Response(const Request&)> guard);

            /// Serves files from `root` for GET requests not matched by any
            /// route ("/" maps to "/index.html"). Path traversal is blocked.
            void ServeStatic(const std::string& root);

            /// Serves an in-memory asset (the embedded WebUI) for GET/HEAD
            /// requests. Checked BEFORE the static root, so a single-file
            /// distribution works with no www/ folder on disk.
            void ServeEmbedded(const std::string& path,
                               const std::string& body,
                               const std::string& content_type);

            /// Binds and starts the acceptor thread. Returns false on bind
            /// failure with `error` set.
            bool Start(const std::string& address, uint16_t port,
                       std::string& error);

            /// Stops accepting and closes the listen socket.
            void Stop() noexcept;

            uint16_t Port() const noexcept { return port_; }

            /// Per-event failures swallowed by the handler firewall: a
            /// connection or accepted socket that could not be served while
            /// the thread and the accept chain stayed intact.
            uint64_t HandlerErrors() const noexcept {
                return handler_errors_.load(std::memory_order_relaxed);
            }

            /// Exceptions that escaped a completion handler out of
            /// io_context::run(). Must stay 0: unwinding through asio's
            /// dispatch frame is undefined behaviour, so the firewall has to
            /// stop the exception first.
            uint64_t EscapedHandlerErrors() const noexcept {
                return escaped_errors_.load(std::memory_order_relaxed);
            }

            /// Test seam: runs inside the accept completion handler before
            /// the socket is queued. Throwing here proves the firewall holds
            /// and that the accept chain still re-arms.
            void SetAcceptProbeForTest(std::function<void()> probe) {
                accept_probe_ = std::move(probe);
            }

            /// Re-arm bodies (the next async_accept) that threw and were
            /// swallowed. Non-zero means the listener could not re-arm and is
            /// deaf until restart - the process and queued requests survive.
            uint64_t RearmErrors() const noexcept {
                return rearm_errors_.load(std::memory_order_relaxed);
            }

            /// Test seam: runs inside the guarded RE-ARM (never the initial
            /// arm); throwing proves an arm failure cannot crash the accept
            /// thread.
            void SetAcceptRearmProbeForTest(std::function<void()> probe) {
                accept_rearm_probe_ = std::move(probe);
            }

        private:
            void AcceptLoop();
            void StartAccept();
            void WorkerLoop();
            void HandleConnection(asio::ip::tcp::socket socket);
            bool ReadRequest(asio::ip::tcp::socket& socket, Request& out,
                             std::string& error,
                             std::chrono::steady_clock::time_point deadline);
            Response Dispatch(const Request& request);
            Response ServeFile(const std::string& path);

            std::function<Response(const Request&)> write_guard_;

            // P2: the io_context and acceptor are recreated per Start() so a
            // Stop() can tear the whole async accept machinery down with no
            // cross-thread close (see Stop/AcceptLoop). unique_ptr keeps the
            // acceptor bound to its own io_context without a fixed member
            // initialization order.
            std::unique_ptr<asio::io_context> io_;
            std::unique_ptr<asio::ip::tcp::acceptor> acceptor_;
            std::error_code ignored_error_;  ///< write-error sink (best effort)
            std::map<std::pair<std::string, std::string>, Handler> routes_;
            std::map<std::string, std::pair<std::string, std::string>> embedded_;
            std::string static_root_;
            std::thread accept_thread_;
            std::vector<std::thread> workers_;
            std::mutex conn_mutex_;
            std::condition_variable conn_cv_;
            std::deque<asio::ip::tcp::socket> conn_queue_;
            std::atomic<bool> running_{false};
            std::atomic<uint64_t> handler_errors_{0};
            std::atomic<uint64_t> escaped_errors_{0};
            std::atomic<uint64_t> rearm_errors_{0};
            std::function<void()> accept_probe_;
            std::function<void()> accept_rearm_probe_;
            uint16_t port_ = 0;
        };

    }  // namespace web
}  // namespace vgww
