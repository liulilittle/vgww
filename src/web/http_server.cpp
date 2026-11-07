// ============================================================================
// http_server.cpp - Embedded HTTP server implementation.
// ============================================================================
#include "web/http_server.h"
#include "core/limits.h"

#include <chrono>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <sstream>

namespace vgww {
    namespace web {

        namespace {
            inline constexpr size_t kMaxHeaderBytes = 16 * 1024;
            inline constexpr size_t kMaxBodyBytes = ::vgww::core::limits::kMaxConfigBytes;
            /// Per-connection total deadline and single-IO socket timeout.
            inline constexpr DWORD kIoTimeoutMs = 5000;

            /// Milliseconds left until `deadline`, clamped to >= 1 so a
            /// blocking socket call always receives a usable timeout.
            inline int64_t RemainingMs(
                std::chrono::steady_clock::time_point deadline) noexcept {
                const auto now = std::chrono::steady_clock::now();
                if (now >= deadline) {
                    return 1;
                }
                const int64_t ms =
                    std::chrono::duration_cast<std::chrono::milliseconds>(
                        deadline - now).count();
                return ms < 1 ? 1 : ms;
            }

            /// Applies a remaining-time budget to both socket directions, so
            /// a single recv/send can never outlive the connection deadline
            /// (pre-9b each call could consume a fresh kIoTimeoutMs).
            inline void SetIoTimeout(asio::ip::tcp::socket& socket,
                                     int64_t remaining_ms) noexcept {
                const DWORD timeout =
                    static_cast<DWORD>(remaining_ms < 1 ? 1 : remaining_ms);
                ::setsockopt(socket.native_handle(), SOL_SOCKET, SO_RCVTIMEO,
                             reinterpret_cast<const char*>(&timeout),
                             sizeof(timeout));
                ::setsockopt(socket.native_handle(), SOL_SOCKET, SO_SNDTIMEO,
                             reinterpret_cast<const char*>(&timeout),
                             sizeof(timeout));
            }

            std::string StatusText(int status) {
                switch (status) {
                    case 200: return "OK";
                    case 400: return "Bad Request";
                    case 401: return "Unauthorized";
                    case 403: return "Forbidden";
                    case 404: return "Not Found";
                    case 405: return "Method Not Allowed";
                    case 500: return "Internal Server Error";
                    default:  return "Unknown";
                }
            }

            std::string ContentTypeFor(const std::string& path) {
                static const std::map<std::string, std::string> table = {
                    {".html", "text/html; charset=utf-8"},
                    {".css", "text/css; charset=utf-8"},
                    {".js", "application/javascript; charset=utf-8"},
                    {".json", "application/json"},
                    {".png", "image/png"},
                    {".svg", "image/svg+xml"},
                    {".ico", "image/x-icon"},
                };
                const size_t dot = path.rfind('.');
                if (std::string::npos == dot) {
                    return "application/octet-stream";
                }
                const auto it = table.find(path.substr(dot));
                return (table.end() == it) ? "application/octet-stream"
                                           : it->second;
            }

            /// Hex digit value, or -1 when `c` is not a hex digit.
            int HexValue(char c) {
                if (c >= '0' && c <= '9') return c - '0';
                if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                return -1;
            }

            /// Percent-decodes a URL component. Returns false on malformed
            /// input (truncated or non-hex escape) so the caller can reject
            /// the request instead of crashing.
            /// When `plus_as_space` is true, '+' is decoded as ' '
            /// (query strings); for path components it stays literal.
            bool UrlDecode(const std::string& in,
                           std::string& out,
                           bool plus_as_space = true) {
                out.clear();
                out.reserve(in.size());

                for (size_t i = 0; i < in.size(); ++i) {
                    if ('%' == in[i]) {
                        if (i + 2 >= in.size()) {
                            return false;  // truncated escape
                        }

                        const int hi = HexValue(in[i + 1]);
                        const int lo = HexValue(in[i + 2]);
                        if (hi < 0 || lo < 0) {
                            return false;  // non-hex escape
                        }

                        out.push_back(static_cast<char>((hi << 4) | lo));
                        i += 2;
                    } else if (plus_as_space && '+' == in[i]) {
                        out.push_back(' ');
                    } else {
                        out.push_back(in[i]);
                    }
                }

                return true;
            }
        }  // namespace

        Response Response::Json(const std::string& json, int status) {
            Response r;
            r.status = status;
            r.content_type = "application/json";
            r.body = json;
            return r;
        }

        Response Response::Text(const std::string& text, int status) {
            Response r;
            r.status = status;
            r.content_type = "text/plain; charset=utf-8";
            r.body = text;
            return r;
        }

        Response Response::Error(int status, const std::string& message) {
            return Json("{\"error\":\"" + JsonEscaped(message) + "\"}", status);
        }

        HttpServer::HttpServer() = default;

        HttpServer::~HttpServer() {
            Stop();
        }

        void HttpServer::Route(const std::string& method,
                               const std::string& path, Handler handler) {
            routes_[{method, path}] = std::move(handler);
        }

        void HttpServer::SetWriteGuard(
            std::function<Response(const Request&)> guard) {
            write_guard_ = std::move(guard);
        }

        void HttpServer::ServeStatic(const std::string& root) {
            static_root_ = root;
        }

        void HttpServer::ServeEmbedded(const std::string& path,
                                       const std::string& body,
                                       const std::string& content_type) {
            embedded_[path] = {body, content_type};
        }

        bool HttpServer::Start(const std::string& address, uint16_t port,
                               std::string& error) {
            std::error_code err;
            const asio::ip::tcp::endpoint endpoint(
                asio::ip::make_address(address, err), port);
            if (err) {
                error = "bad address: " + address;
                return false;
            }
            // P2: fresh per-run async machinery. Stop() tears these down
            // after joining the accept thread, so a later Start() builds a
            // brand-new io_context/acceptor with no cross-run state.
            io_ = std::make_unique<asio::io_context>();
            acceptor_ = std::make_unique<asio::ip::tcp::acceptor>(*io_);
            acceptor_->open(endpoint.protocol(), err);
            if (!err) {
                acceptor_->set_option(asio::socket_base::reuse_address(true),
                                      err);
            }
            if (!err) {
                acceptor_->bind(endpoint, err);
            }
            if (err) {
                error = "bind failed: " + err.message();
                acceptor_.reset();
                io_.reset();
                return false;
            }
            acceptor_->listen(asio::socket_base::max_listen_connections, err);
            if (err) {
                error = "listen failed: " + err.message();
                acceptor_.reset();
                io_.reset();
                return false;
            }
            port_ = port;
            running_.store(true);
            accept_thread_ = std::thread([this] { AcceptLoop(); });
            // Two connection workers: one stalled client can no longer pin
            // the only handler (the acceptor keeps accepting).
            static constexpr size_t kConnectionWorkers = 2;
            workers_.reserve(kConnectionWorkers);
            for (size_t i = 0; i < kConnectionWorkers; ++i) {
                workers_.emplace_back([this] { WorkerLoop(); });
            }
            return true;
        }

        void HttpServer::Stop() noexcept {
            if (!running_.exchange(false)) {
                return;
            }
            // P2: the outstanding async_accept is interrupted from the accept
            // thread's own io_context. Closing the acceptor from this foreign
            // thread is not guaranteed to unblock a pending accept (and asio
            // objects are not thread-safe), so the close plus stop is posted
            // and runs on the accept thread; run() then returns and the thread
            // joins - it can never hang on an un-interrupted accept.
            if (io_) {
                try {
                    asio::post(*io_, [this] {
                        std::error_code ignored;
                        if (acceptor_) {
                            acceptor_->close(ignored);
                        }
                        // Park the context: run() returns after this handler
                        // even if the aborted accept completion is pending.
                        io_->stop();
                    });
                } catch (...) {
                    // Allocation failure while queuing the wake-up: stop the
                    // context directly (thread-safe). The acceptor is closed
                    // after the accept thread is joined below.
                    io_->stop();
                }
            }
            conn_cv_.notify_all();
            if (accept_thread_.joinable()) {
                accept_thread_.join();
            }
            // The accept thread is gone: the acceptor can now be closed with
            // no concurrent operation, whatever path stopped the context.
            if (acceptor_) {
                std::error_code ignored;
                acceptor_->close(ignored);
            }
            for (std::thread& worker : workers_) {
                if (worker.joinable()) {
                    worker.join();
                }
            }
            workers_.clear();
            {
                // No thread can enqueue past this point (acceptor and workers
                // joined): close every connection that never started being
                // served instead of leaving stale sockets for a later Start.
                std::lock_guard<std::mutex> lock(conn_mutex_);
                conn_queue_.clear();
            }
            acceptor_.reset();
            io_.reset();
        }

        void HttpServer::AcceptLoop() {
            StartAccept();
            io_->run();
        }

        void HttpServer::StartAccept() {
            // One outstanding async_accept at a time. The socket is kept alive
            // by the handler's shared_ptr until it is moved into the queue.
            auto socket = std::make_shared<asio::ip::tcp::socket>(*io_);
            acceptor_->async_accept(
                *socket,
                [this, socket](const std::error_code& err) {
                    if (err) {
                        // Transient error: keep accepting while running. Once
                        // Stop() parks the context this handler is not
                        // re-armed, so run() can return.
                        if (running_.load()) {
                            StartAccept();
                        }
                        return;
                    }
                    {
                        std::lock_guard<std::mutex> lock(conn_mutex_);
                        static constexpr size_t kMaxQueuedConnections = 64;
                        if (conn_queue_.size() >= kMaxQueuedConnections) {
                            std::error_code ignored;
                            socket->close(ignored);  // shed load, bounded
                        } else {
                            conn_queue_.push_back(std::move(*socket));
                        }
                    }
                    conn_cv_.notify_one();
                    if (running_.load()) {
                        StartAccept();
                    }
                });
        }

        void HttpServer::WorkerLoop() {
            for (;;) {
                asio::ip::tcp::socket socket(*io_);
                {
                    std::unique_lock<std::mutex> lock(conn_mutex_);
                    conn_cv_.wait(lock, [this] {
                        return !conn_queue_.empty() || !running_.load();
                    });
                    // Bounded stop: once Stop() clears running_ a worker must
                    // never drain the queue - it exits immediately and Stop()
                    // closes whatever is left (pre-9b up to 64 queued sockets
                    // were still served, stretching shutdown by minutes).
                    if (!running_.load()) {
                        return;
                    }
                    socket = std::move(conn_queue_.front());
                    conn_queue_.pop_front();
                }
                HandleConnection(std::move(socket));
            }
        }

        void HttpServer::HandleConnection(asio::ip::tcp::socket socket) {
            // Slowloris guard: every blocking read/write below is clamped to
            // the time left in this connection's budget, so one idle client
            // can pin a worker for at most ~kIoTimeoutMs in total.
            const auto deadline = std::chrono::steady_clock::now() +
                                  std::chrono::milliseconds(kIoTimeoutMs);
            SetIoTimeout(socket, kIoTimeoutMs);

            Request request;
            std::string error;
            if (!ReadRequest(socket, request, error, deadline)) {
                const Response bad = Response::Error(400, error);
                std::string out = "HTTP/1.1 400 Bad Request\r\nContent-Type: " +
                                  bad.content_type + "\r\nContent-Length: " +
                                  std::to_string(bad.body.size()) +
                                  "\r\nConnection: close\r\n"
                                  "X-Frame-Options: DENY\r\n"
                                  "X-Content-Type-Options: nosniff\r\n"
                                  "Cache-Control: no-store\r\n\r\n";
                // A HEAD request that fails before Dispatch (bad query
                // encoding, oversized path, ...) still must not get a body.
                if ("HEAD" != request.method) {
                    out += bad.body;
                }
                SetIoTimeout(socket, RemainingMs(deadline));
                asio::write(socket, asio::buffer(out), ignored_error_);
                return;
            }
            const Response response = Dispatch(request);
            // HEAD (RFC 9110 9.3.2) advertises the entity of the equivalent
            // GET - headers and Content-Length included - but never writes the
            // entity itself. One flag, applied at the single response choke
            // point below (routes / embedded asset / static file / errors).
            const bool head_request = "HEAD" == request.method;
            std::ostringstream out;
            out << "HTTP/1.1 " << response.status << ' '
                << StatusText(response.status) << "\r\n"
                << "Content-Type: " << response.content_type << "\r\n"
                << "Content-Length: " << response.body.size() << "\r\n"
                << "Connection: close\r\n";
            // Hardening defaults for a LAN-facing admin surface (single
            // choke point, written before extra_headers so a handler can
            // still override): never frame the UI (clickjacking), never
            // MIME-sniff bodies, and never let heuristic caching serve
            // stale polled state (/api/status is fetched every 2 s).
            out << "X-Frame-Options: DENY\r\n";
            out << "X-Content-Type-Options: nosniff\r\n";
            out << "Cache-Control: no-store\r\n";
            // Content-Security-Policy: the WebUI is a single inlined-code SPA
            // served from this same origin, so scripts/styles must stay
            // inline-capable ('unsafe-inline'), but everything else is locked
            // to 'self' - no third-party scripts, images, frames or objects.
            out << "Content-Security-Policy: default-src 'self'; "
                   "script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
                   "img-src 'self' data:; font-src 'self'; "
                   "connect-src 'self'; frame-ancestors 'none'; "
                   "object-src 'none'; base-uri 'self'; form-action 'self'\r\n";
            for (const auto& [key, value] : response.extra_headers) {
                out << key << ": " << value << "\r\n";
            }
            out << "\r\n";
            if (!head_request) {
                out << response.body;
            }
            SetIoTimeout(socket, RemainingMs(deadline));
            asio::write(socket, asio::buffer(out.str()), ignored_error_);
        }

        bool HttpServer::ReadRequest(asio::ip::tcp::socket& socket,
                                     Request& out, std::string& error,
                                     std::chrono::steady_clock::time_point deadline) {
            // Read until CRLFCRLF, then Content-Length body bytes. Every
            // blocking read is clamped to the remaining budget (SetIoTimeout)
            // so a trickle or stalled peer cannot extend the connection past
            // the deadline.
            std::string raw;
            char chunk[4096];
            size_t header_end = std::string::npos;
            while (raw.size() < kMaxHeaderBytes) {
                if (std::chrono::steady_clock::now() >= deadline) {
                    error = "request timeout";
                    return false;
                }
                SetIoTimeout(socket, RemainingMs(deadline));
                std::error_code err;
                const size_t n = socket.read_some(asio::buffer(chunk), err);
                if (err || 0 == n) {
                    error = "read failed";
                    return false;
                }
                raw.append(chunk, n);
                header_end = raw.find("\r\n\r\n");
                if (std::string::npos != header_end) {
                    break;
                }
            }
            if (std::string::npos == header_end) {
                error = "headers too large";
                return false;
            }

            std::istringstream head(raw.substr(0, header_end));
            std::string line;
            std::getline(head, line);
            if (!line.empty() && line.back() == '\r') {
                line.pop_back();
            }
            std::istringstream request_line(line);
            request_line >> out.method >> out.path;
            if (out.method.empty() || out.path.empty()) {
                error = "malformed request line";
                return false;
            }
            // batch97: RFC 9112 section 3 - the request-line is
            //   method SP request-target SP HTTP-version CRLF
            // `>>` stopped after two tokens and DISCARDED the rest, so the
            // HTTP-version was never looked at: "GET /x" (no version),
            // "GET /x GARBAGE" and "GET /x HTTP/9.9" were all dispatched as
            // normal requests. Read the version token and require the exact
            // "HTTP/1." form, and require that nothing follows it. A client
            // that omits or mangles the version disagrees with the server about
            // the message structure - the framing class batch85 fixed for
            // Content-Length.
            std::string http_version;
            request_line >> http_version;
            {
                const bool ok = 8 == http_version.size() &&
                                http_version.compare(0, 7, "HTTP/1.") == 0 &&
                                http_version[7] >= '0' &&
                                http_version[7] <= '9';
                if (!ok) {
                    error = "invalid http version";
                    return false;
                }
                // Nothing may follow the version on the request line.
                std::string trailing;
                if (request_line >> trailing) {
                    error = "malformed request line";
                    return false;
                }
            }
            // Super-large guard: cap path and query growth.
            if (out.path.size() > ::vgww::core::limits::kMaxHttpPathBytes) {
                error = "path too long";
                return false;
            }
            // Split the query string first, then decode the path part
            // unconditionally (U9): with or without a query, "/foo%20bar"
            // must resolve to the same decoded path.
            const size_t qmark = out.path.find('?');
            const std::string query_raw =
                (std::string::npos != qmark) ? out.path.substr(qmark + 1)
                                             : std::string();
            std::string decoded_path;
            if (!UrlDecode(out.path.substr(0, qmark), decoded_path, false)) {
                error = "malformed percent-encoding in path";
                return false;
            }
            out.path = decoded_path;
            if (std::string::npos != qmark) {
                std::istringstream query(query_raw);
                std::string pair;
                size_t query_pairs = 0;
                while (std::getline(query, pair, '&')) {
                    if (++query_pairs > ::vgww::core::limits::kMaxHttpQueryPairs) {
                        error = "query too many parameters";
                        return false;
                    }
                    const size_t eq = pair.find('=');
                    if (std::string::npos != eq) {
                        std::string key, value;
                        if (!UrlDecode(pair.substr(0, eq), key) ||
                            !UrlDecode(pair.substr(eq + 1), value)) {
                            error = "malformed percent-encoding in query";
                            return false;
                        }
                        if (key.size() > 256 || value.size() > 1024) {
                            error = "query param too long";
                            return false;
                        }
                        out.query[key] = value;
                    }
                }
            }
            while (std::getline(head, line)) {
                if (!line.empty() && line.back() == '\r') {
                    line.pop_back();
                }
                // batch99: the header block had no structural validation. A line
                // with no ':' was silently DROPPED (framing as if that field had
                // never been sent), whitespace before ':' turned "Content-Length"
                // into "content-length " (the lookup missed, so the body framed
                // as 0), and an obs-fold continuation line was folded into
                // nothing. Each let a peer send a field this server refuses to
                // understand yet still have the request dispatched - the same
                // smuggling class batch85 closed for a malformed Content-Length
                // value. RFC 9112 5.1 forbids whitespace between the field name
                // and the colon (MUST 400) and 5.2 obsoletes obs-fold in
                // requests (MUST 400 or replace with SP).
                //
                // Obs-fold needs no separate branch: a continuation line starts
                // with SP or HTAB, which is not a token character, so it fails
                // the field-name check below exactly like " Name: value" does.
                const size_t colon = line.find(':');
                if (std::string::npos == colon) {
                    error = "malformed header field";
                    return false;
                }
                // field-name = 1*tchar (RFC 9110 5.6.2): one or more token
                // characters. An empty name, a space, or a control byte is not
                // a field name, and accepting one would make the value below
                // unreachable through any normal lookup.
                {
                    bool name_ok = colon > 0;
                    for (size_t i = 0; name_ok && i < colon; ++i) {
                        const char c = line[i];
                        name_ok = (c >= 'a' && c <= 'z') ||
                                  (c >= 'A' && c <= 'Z') ||
                                  (c >= '0' && c <= '9') ||
                                  std::string::npos !=
                                      std::string("!#$%&'*+-.^_`|~").find(c);
                    }
                    if (!name_ok) {
                        error = "malformed header field name";
                        return false;
                    }
                }
                {
                    // Header names are case-insensitive (RFC 9110 5.1):
                    // normalize to lowercase so lookups are reliable.
                    std::string key = line.substr(0, colon);
                    for (char& c : key) {
                        c = static_cast<char>(std::tolower(
                            static_cast<unsigned char>(c)));
                    }
                    // There is no chunked decoder in this server, so a transfer
                    // coding that is not identity must not be silently ignored:
                    // RFC 9112 6.1 says a recipient that does not understand the
                    // coding answers 501, and TE together with Content-Length is
                    // the pair 6.3 forbids accepting. Rejecting at the framing
                    // layer is the conservative choice because no route can
                    // serve a chunked body at all.
                    if ("transfer-encoding" == key) {
                        error = "unsupported transfer-encoding";
                        return false;
                    }
                    // Field values may be preceded/followed by optional
                    // whitespace (RFC 9110 5.1); it is not part of the value.
                    std::string value = line.substr(colon + 1);
                    const size_t first = value.find_first_not_of(" \t");
                    const size_t last = value.find_last_not_of(" \t");
                    value = (std::string::npos == first)
                                ? std::string()
                                : value.substr(first, last - first + 1);
                    // batch98: a repeated field must not silently overwrite the
                    // earlier one. For Content-Length that is the classic
                    // request-smuggling shape (RFC 9112 section 6.3: differing
                    // values MUST be 400; even identical duplicates are only
                    // tolerated by some recipients, so this server refuses both
                    // rather than guessing which one the proxy used).
                    if (out.headers.end() != out.headers.find(key)) {
                        error = "duplicate header field";
                        return false;
                    }
                    out.headers[key] = value;
                }
            }

            size_t content_length = 0;
            const auto cl = out.headers.find("content-length");
            if (out.headers.end() != cl) {
                // batch85: RFC 9112 section 6.3 - a Content-Length that does not
                // match the ABNF (1*DIGIT) makes the framing invalid and the
                // recipient MUST treat it as an unrecoverable error, answering
                // 400 and closing. The bare strtoull() this replaced ignored
                // endptr, so "abc" framed as 0 (the request was DISPATCHED with
                // its real body silently discarded) and "12abc" framed as 12.
                // Overflow is also invalid rather than "body too large" - the
                // value is not a length at all.
                const std::string& raw_cl = cl->second;
                bool digits_only = !raw_cl.empty();
                for (const char c : raw_cl) {
                    if (c < '0' || c > '9') {
                        digits_only = false;
                        break;
                    }
                }
                if (!digits_only) {
                    error = "invalid content-length";
                    return false;
                }
                errno = 0;
                char* cl_end = nullptr;
                const unsigned long long parsed =
                    strtoull(raw_cl.c_str(), &cl_end, 10);
                if (ERANGE == errno || cl_end == raw_cl.c_str() ||
                    static_cast<size_t>(cl_end - raw_cl.c_str()) !=
                        raw_cl.size() ||
                    parsed > static_cast<unsigned long long>(SIZE_MAX)) {
                    error = "invalid content-length";
                    return false;
                }
                content_length = static_cast<size_t>(parsed);
            }
            if (content_length > kMaxBodyBytes) {
                error = "body too large";
                return false;
            }
            out.body = raw.substr(header_end + 4);
            while (out.body.size() < content_length) {
                if (std::chrono::steady_clock::now() >= deadline) {
                    error = "request timeout";
                    return false;
                }
                SetIoTimeout(socket, RemainingMs(deadline));
                std::error_code err;
                const size_t n = socket.read_some(asio::buffer(chunk), err);
                if (err || 0 == n) {
                    // Client promised more bytes than it sent: reject the
                    // request instead of padding the body with NULs.
                    error = "short body";
                    return false;
                }
                out.body.append(chunk, n);
            }
            out.body.resize(content_length);
            return true;
        }

        Response HttpServer::Dispatch(const Request& request) {
            // Mutating requests pass the write guard first (token auth).
            // HEAD is safe like GET (read-only); do not require a token.
            if ("GET" != request.method && "HEAD" != request.method &&
                write_guard_) {
                Response denied = write_guard_(request);
                if (denied.status != 200) {
                    return denied;
                }
            }
            const auto it = routes_.find({request.method, request.path});
            if (routes_.end() != it) {
                try {
                    return it->second(request);
                } catch (const std::exception& ex) {
                    // batch34r: never echo the exception text. `what()` for a
                    // JSON parser carries byte offsets, token names and library
                    // version strings, and for a parse failure the text is
                    // attacker-influenced - returning it is both an information
                    // leak and an injection surface. Log locally, answer
                    // generically.
                    std::fprintf(stderr, "[vgww] handler error on %s %s: %s\n",
                                 request.method.c_str(), request.path.c_str(),
                                 ex.what());
                    return Response::Error(500, "internal error");
                }
            }
            // HEAD is GET without the body (RFC 9110 9.3.2): serve the GET
            // handler's response when no explicit HEAD route exists and let
            // HandleConnection drop the entity. Without this, HEAD /api/status
            // would fall through to the static fallback and 404 instead of
            // advertising the JSON length with an empty body.
            //
            // batch34r: this must run BEFORE the 405 sweep. HEAD is implicitly
            // allowed wherever GET is, so treating it as a wrong method would
            // break every HEAD probe against a GET-only route.
            if ("HEAD" == request.method) {
                const auto git = routes_.find({"GET", request.path});
                if (routes_.end() != git) {
                    try {
                        return git->second(request);
                    } catch (const std::exception& ex) {
                        std::fprintf(
                            stderr, "[vgww] handler error on HEAD %s: %s\n",
                            request.path.c_str(), ex.what());
                        return Response::Error(500, "internal error");
                    }
                }
            }
            // batch34r: a path that IS registered under another method must
            // answer 405 with an Allow header (RFC 9110 15.5.6). Answering 404
            // claims the path does not exist, which hides a write handler from
            // legitimate clients and from security tooling.
            //
            // Only non-GET/HEAD requests reach this point (GET/HEAD fall
            // through to the embedded/static asset path below), so the scan
            // never sits on the hot read path.
            if ("GET" != request.method && "HEAD" != request.method) {
                std::string allow;
                for (const auto& entry : routes_) {
                    if (entry.first.second != request.path) {
                        continue;
                    }
                    if (!allow.empty()) {
                        allow += ", ";
                    }
                    allow += entry.first.first;
                }
                if (!allow.empty()) {
                    Response not_allowed =
                        Response::Error(405, "method not allowed");
                    not_allowed.extra_headers.emplace_back("Allow", allow);
                    return not_allowed;
                }
            }
            // Single-file distribution: serve the in-memory asset (the
            // embedded WebUI) before touching the disk fallback.
            if ("GET" == request.method || "HEAD" == request.method) {
                std::string rel = request.path;
                if ("/" == rel) {
                    rel = "/index.html";
                }
                const auto eit = embedded_.find(rel);
                if (embedded_.end() != eit) {
                    Response response;
                    response.status = 200;
                    response.content_type = eit->second.second;
                    response.body = eit->second.first;
                    return response;
                }
            }
            if (("GET" == request.method || "HEAD" == request.method) &&
                !static_root_.empty()) {
                return ServeFile(request.path);
            }
            return Response::Error(404, "no such route");
        }

        Response HttpServer::ServeFile(const std::string& url_path) {
            std::string relative = url_path;
            if ("/" == relative) {
                relative = "/index.html";
            }
            // Path traversal guard: reject any ".." path component.
            // Substring ".." would also block legitimate names like
            // "a..b.txt" - only a full component is traversal.
            // Normalise backslashes so Windows-style "..\ " is also caught.
            {
                std::string norm = relative;
                for (char& ch : norm) {
                    if ('\\' == ch) {
                        ch = '/';
                    }
                }

                std::istringstream segs(norm);
                std::string seg;
                while (std::getline(segs, seg, '/')) {
                    if (".." == seg) {
                        return Response::Error(403, "forbidden");
                    }
                }
            }

            const std::filesystem::path root(static_root_);
            const std::filesystem::path full = root / relative.substr(1);
            // batch100: containment must be decided on canonical paths compared
            // COMPONENT BY COMPONENT. The guard this replaced compared
            // root_name() and is_absolute() for EQUALITY, which a same-drive
            // absolute request path satisfies by construction - so
            // "GET /F:/Windows/win.ini" (no ".." anywhere) passed the check and
            // operator/ REPLACED the root, serving any file on that drive. A
            // string prefix test would be no better: it accepts "/srv/www-evil"
            // for root "/srv/www". Comparing whole components cannot.
            // weakly_canonical resolves "..", ".", Windows short names and
            // symlinks for the existing prefix, while still working for paths
            // that do not exist yet; any error is treated as an escape.
            {
                std::error_code cec;
                const std::filesystem::path canon_root =
                    std::filesystem::weakly_canonical(root, cec);
                const std::filesystem::path canon_full =
                    std::filesystem::weakly_canonical(full, cec);
                if (cec ||
                    std::distance(canon_root.begin(), canon_root.end()) >
                        std::distance(canon_full.begin(), canon_full.end()) ||
                    !std::equal(canon_root.begin(), canon_root.end(),
                                canon_full.begin())) {
                    return Response::Error(403, "forbidden");
                }
            }
            std::error_code ec;
            if (!std::filesystem::exists(full, ec) ||
                !std::filesystem::is_regular_file(full, ec)) {
                return Response::Error(404, "not found");
            }
            static constexpr uintmax_t kMaxFileBytes = 5u * 1024 * 1024;
            if (std::filesystem::file_size(full, ec) > kMaxFileBytes) {
                return Response::Error(404, "not found");
            }
            std::ifstream file(full, std::ios::binary);
            if (!file) {
                return Response::Error(404, "not found");
            }
            std::ostringstream body;
            body << file.rdbuf();
            Response response;
            response.status = 200;
            response.content_type = ContentTypeFor(full.string());
            response.body = body.str();
            return response;
        }

    }  // namespace web
}  // namespace vgww
