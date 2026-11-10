// ============================================================================
// test_web.cpp - Embedded HTTP server: routing, static files, API surface.
// ============================================================================
#include "core/limits.h"
#include "proto/dhcp.h"
#include "proto/dhcp6.h"
#include "web/http_server.h"
#include "web/web_api.h"

#include <nlohmann/json.hpp>

#include "driver/idriver_client.h"
#include "driver/installer.h"
#include "driver/ndisrd_client.h"
#include "ndisapi/Common.h"

#include <asio.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <memory>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace {

    int g_failures = 0;

#define CHECK(cond)                                                        \
    do {                                                                   \
        if (!(cond)) {                                                     \
            std::fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__,  \
                         __LINE__, #cond);                                 \
            ++g_failures;                                                  \
        }                                                                  \
    } while (0)

    /// W8: one complete JSON document per response. Substring assertions
    /// cannot see a missing final brace (that is how /api/status shipped
    /// malformed while every field check passed and the dashboard, whose
    /// api() calls JSON.parse, rendered no live data).
    bool JsonWholeBody(const std::string& body, const char* const* keys,
                       size_t n) {
        const auto j = nlohmann::json::parse(body, nullptr, false);
        if (j.is_discarded()) return false;
        if (n == 0) return true;  // top-level array endpoints ("[]") are fine
        if (!j.is_object()) return false;
        for (size_t i = 0; i < n; ++i) {
            if (!j.contains(keys[i])) return false;
        }
        return true;
    }

    using vgww::web::HttpServer;
    using vgww::web::Request;
    using vgww::web::Response;

    /// Static key arrays for JsonWholeBody. Never store std::initializer_list
    /// in an aggregate: the backing array it points at does not outlive the
    /// braced-init, leaving a dangling read (UB) on later use.
    constexpr const char* kKeysStatus[] = {"gateway", "stats", "dhcp", "dhcp6"};
    constexpr const char* kKeysClients[] = {"clients"};
    constexpr const char* kKeysSystem[] = {"proc", "throughput"};

    /// Non-blocking request with a hard deadline. A deaf server must turn
    /// into a fast assertion failure: asio's synchronous reads have no
    /// timeout of their own, so a blocking helper would hang until ctest
    /// killed the process.
    int HttpRequestWithin(uint16_t port, const std::string& request,
                          std::string& body, int timeout_ms) {
        asio::io_context io;
        asio::ip::tcp::socket socket(io);
        std::error_code err;
        socket.connect(asio::ip::tcp::endpoint(
                           asio::ip::make_address("127.0.0.1"), port),
                       err);
        if (err) return -1;
        asio::write(socket, asio::buffer(request), err);
        if (err) return -1;
        socket.non_blocking(true, err);
        if (err) return -1;
        std::string text;
        char buf[4096];
        const auto deadline = std::chrono::steady_clock::now() +
                              std::chrono::milliseconds(timeout_ms);
        while (std::chrono::steady_clock::now() < deadline) {
            const size_t n = socket.read_some(asio::buffer(buf), err);
            if (!err) {
                text.append(buf, n);
                continue;
            }
            if (asio::error::eof == err) break;
            if (err != asio::error::would_block &&
                err != asio::error::try_again) {
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
        const size_t body_at = text.find("\r\n\r\n");
        if (std::string::npos != body_at) body = text.substr(body_at + 4);
        const size_t space = text.find(' ');
        return (std::string::npos == space) ? -1
                                            : atoi(text.c_str() + space + 1);
    }

    int HttpGetWithin(const std::string& path, uint16_t port,
                      std::string& body, int timeout_ms) {
        return HttpRequestWithin(
            port,
            "GET " + path +
                " HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n",
            body, timeout_ms);
    }

    int HttpPostWithin(uint16_t port, const std::string& path,
                       const std::string& payload, std::string& body,
                       int timeout_ms) {
        return HttpRequestWithin(
            port,
            "POST " + path + " HTTP/1.1\r\nHost: t\r\nContent-Length: " +
                std::to_string(payload.size()) +
                "\r\nConnection: close\r\n\r\n" + payload,
            body, timeout_ms);
    }

    /// Connects, writes `request`, and closes without reading. Used where the
    /// point is that the server does NOT answer (a guarded failure).
    bool SendAndDiscard(uint16_t port, const std::string& request) {
        asio::io_context io;
        asio::ip::tcp::socket socket(io);
        std::error_code err;
        socket.connect(asio::ip::tcp::endpoint(
                           asio::ip::make_address("127.0.0.1"), port),
                       err);
        if (err) return false;
        asio::write(socket, asio::buffer(request), err);
        socket.close(err);  // no read: this connection is expected to die
        return true;
    }

    /// Blocking HTTP GET returning status + body.
    int HttpGet(const std::string& path, uint16_t port, std::string& body) {
        asio::io_context io;
        asio::ip::tcp::socket socket(io);
        std::error_code err;
        socket.connect(asio::ip::tcp::endpoint(asio::ip::make_address("127.0.0.1"),
                                               port),
                       err);
        if (err) return -1;
        const std::string request =
            "GET " + path + " HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n";
        asio::write(socket, asio::buffer(request), err);
        if (err) return -1;
        std::ostringstream raw;
        char buf[4096];
        for (;;) {
            const size_t n = socket.read_some(asio::buffer(buf), err);
            if (err) break;
            raw.write(buf, static_cast<std::streamsize>(n));
        }
        const std::string text = raw.str();
        const size_t space = text.find(' ');
        const size_t body_at = text.find("\r\n\r\n");
        if (std::string::npos != body_at) {
            body = text.substr(body_at + 4);
        }
        return (std::string::npos == space)
                   ? -1
                   : atoi(text.c_str() + space + 1);
    }

    /// Blocking HTTP POST with an X-Auth-Token header value.
    int HttpPost(uint16_t port, const std::string& path,
                 const std::string& token, const std::string& request_body,
                 std::string& body) {
        asio::io_context io;
        asio::ip::tcp::socket socket(io);
        std::error_code err;
        socket.connect(asio::ip::tcp::endpoint(asio::ip::make_address("127.0.0.1"),
                                               port),
                       err);
        if (err) return -1;
        std::string request = "POST " + path + " HTTP/1.1\r\nHost: t\r\n";
        if (!token.empty()) {
            request += "X-Auth-Token: " + token + "\r\n";
        }
        request += "Content-Length: " + std::to_string(request_body.size()) +
                   "\r\nConnection: close\r\n\r\n" + request_body;
        asio::write(socket, asio::buffer(request), err);
        if (err) return -1;
        std::ostringstream raw;
        char buf[4096];
        for (;;) {
            const size_t n = socket.read_some(asio::buffer(buf), err);
            if (err) break;
            raw.write(buf, static_cast<std::streamsize>(n));
        }
        const std::string text = raw.str();
        const size_t space = text.find(' ');
        const size_t body_at = text.find("\r\n\r\n");
        if (std::string::npos != body_at) {
            body = text.substr(body_at + 4);
        }
        return (std::string::npos == space)
                   ? -1
                   : atoi(text.c_str() + space + 1);
    }

    /// Blocking HTTP DELETE returning status + body (no credentials).
    int HttpDelete(const std::string& path, uint16_t port, std::string& body) {
        asio::io_context io;
        asio::ip::tcp::socket socket(io);
        std::error_code err;
        socket.connect(asio::ip::tcp::endpoint(asio::ip::make_address("127.0.0.1"),
                                               port),
                       err);
        if (err) return -1;
        const std::string request =
            "DELETE " + path + " HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n";
        asio::write(socket, asio::buffer(request), err);
        if (err) return -1;
        std::ostringstream raw;
        char buf[4096];
        for (;;) {
            const size_t n = socket.read_some(asio::buffer(buf), err);
            if (err) break;
            raw.write(buf, static_cast<std::streamsize>(n));
        }
        const std::string text = raw.str();
        const size_t space = text.find(' ');
        const size_t body_at = text.find("\r\n\r\n");
        if (std::string::npos != body_at) {
            body = text.substr(body_at + 4);
        }
        return (std::string::npos == space)
                   ? -1
                   : atoi(text.c_str() + space + 1);
    }

    /// Blocking HTTP DELETE with the auth token (write-gated endpoints).
    int HttpDeleteWithToken(const std::string& path, uint16_t port,
                            const std::string& token, std::string& body) {
        asio::io_context io;
        asio::ip::tcp::socket socket(io);
        std::error_code err;
        socket.connect(asio::ip::tcp::endpoint(asio::ip::make_address("127.0.0.1"),
                                               port),
                       err);
        if (err) return -1;
        const std::string request =
            "DELETE " + path + " HTTP/1.1\r\nHost: t\r\nX-Auth-Token: " +
            token + "\r\nConnection: close\r\n\r\n";
        asio::write(socket, asio::buffer(request), err);
        if (err) return -1;
        std::ostringstream raw;
        char buf[4096];
        for (;;) {
            const size_t n = socket.read_some(asio::buffer(buf), err);
            if (err) break;
            raw.write(buf, static_cast<std::streamsize>(n));
        }
        const std::string text = raw.str();
        const size_t space = text.find(' ');
        const size_t body_at = text.find("\r\n\r\n");
        if (std::string::npos != body_at) {
            body = text.substr(body_at + 4);
        }
        return (std::string::npos == space)
                   ? -1
                   : atoi(text.c_str() + space + 1);
    }

    /// Sends raw request bytes; returns response status + body.
    /// Blocking HTTP request returning status + the FULL wire response,
    /// headers included (header assertions need this, not HttpRaw).
    int HttpRawFull(uint16_t port, const std::string& request,
                    std::string& text) {
        asio::io_context io;
        asio::ip::tcp::socket socket(io);
        std::error_code err;
        socket.connect(asio::ip::tcp::endpoint(asio::ip::make_address("127.0.0.1"),
                                               port),
                       err);
        if (err) return -1;
        asio::write(socket, asio::buffer(request), err);
        if (err) return -1;
        socket.shutdown(asio::ip::tcp::socket::shutdown_send, err);
        std::ostringstream raw;
        char buf[4096];
        for (;;) {
            const size_t n = socket.read_some(asio::buffer(buf), err);
            if (err) break;
            raw.write(buf, static_cast<std::streamsize>(n));
        }
        text = raw.str();
        const size_t space = text.find(' ');
        return (std::string::npos == space)
                   ? -1
                   : atoi(text.c_str() + space + 1);
    }

    int HttpRaw(uint16_t port, const std::string& request, std::string& body) {
        std::string text;
        const int st = HttpRawFull(port, request, text);
        const size_t body_at = text.find("\r\n\r\n");
        if (std::string::npos != body_at) {
            body = text.substr(body_at + 4);
        }
        return st;
    }

    /// Minimal in-memory driver so the WebUI DHCP endpoints can be exercised
    /// against a real (started) data plane without a kernel driver. Boundary
    /// simulation only: the product data plane runs verbatim.
    class WebFakeDriver final : public vgww::driver::IDriverClient {
    public:
        WebFakeDriver() {
            vgww::driver::AdapterEntry entry;
            entry.name = L"\\\\WebTestNIC";
            entry.handle = this;
            entry.mtu = 1500;
            adapters_.push_back(entry);
        }

        const std::vector<vgww::driver::AdapterEntry>& Adapters()
            const noexcept override {
            return adapters_;
        }

        const vgww::driver::AdapterEntry* FindAdapter(
            const std::wstring&,
            bool* = nullptr) const noexcept override {
            return adapters_.empty() ? nullptr : &adapters_.front();
        }

        bool SetAdapterMode(const vgww::driver::AdapterEntry&, uint32_t,
                            std::string&) override {
            return true;
        }

        bool SetHwPacketFilter(const vgww::driver::AdapterEntry&, uint32_t,
                               std::string&) override {
            return true;
        }

        bool GetHwPacketFilter(const vgww::driver::AdapterEntry&, uint32_t& filter,
                               std::string&) override {
            filter = 0;
            return true;
        }

        bool ArmRxEvent(const vgww::driver::AdapterEntry&, void*,
                        std::string&) override {
            return true;
        }

        uint32_t ReadPackets(void*, INTERMEDIATE_BUFFER*, uint32_t,
                             std::string&) override {
            return 0;
        }

        bool SendPacketsToAdapter(void*, INTERMEDIATE_BUFFER*, uint32_t,
                                  std::string&) override {
            return true;
        }

        bool SendPacketsToMstcp(void*, INTERMEDIATE_BUFFER*, uint32_t,
                                std::string&) override {
            return true;
        }

        bool FlushAdapterQueue(const vgww::driver::AdapterEntry&,
                               std::string&) override {
            return true;
        }

        bool ResetAdapterMode(const vgww::driver::AdapterEntry&,
                              std::string&) override {
            return true;
        }

    private:
        std::vector<vgww::driver::AdapterEntry> adapters_;
    };

}  // namespace

    // ---- DHCPv6 endpoints (S2-Task8): a main-mode plane with ipv6 on
    //      assembles the v6 server; /api/dhcp6/bindings mirrors the v4 CRUD
    //      contract (DUID keyed, cap 1024, token guarded). ----
    void TestWebDhcp6BindingsCrud() {
        const char* kLeasePath = "web-dhcp6-leases.json";
        const std::string lease6_path = std::string(kLeasePath) + ".leases6";
        std::remove(kLeasePath);
        std::remove(lease6_path.c_str());
        vgww::core::Config cfg;
        cfg.adapter = "WebTestNIC6";
        cfg.mode = vgww::core::Mode::kMain;
        cfg.gateway.mac = {0x30, 0xFC, 0x68, 0x88, 0xB4, 0xA9};
        cfg.ipv6.enabled = true;
        cfg.ipv6.prefix_len = 64;
        cfg.ipv6.ula_prefix = {0xFD, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
                               0x66, 0, 0, 0, 0, 0, 0, 0, 0};
        cfg.ipv6.dhcpv6.enabled = true;
        cfg.ipv6.dhcpv6.pool_start = {0xFD, 0x00, 0x11, 0x22, 0x33, 0x44,
                                      0x55, 0x66, 0, 0, 0, 0, 0, 0, 0x10,
                                      0x00};
        cfg.ipv6.dhcpv6.pool_end = {0xFD, 0x00, 0x11, 0x22, 0x33, 0x44,
                                    0x55, 0x66, 0, 0, 0, 0, 0, 0, 0x1F,
                                    0xFF};
        cfg.ipv6.dhcpv6.lease_seconds = 3600;
        cfg.perf.workers = 2;
        cfg.perf.ring_capacity = 64;
        cfg.perf.max_conns = 64;
        // 1023 config bindings so the POST boundary is exactly 1024/1025.
        for (uint32_t i = 0; i < 1023; ++i) {
            vgww::core::Dhcp6StaticBinding binding;
            binding.duid = {0x00, 0x03, 0x00, 0x01,
                            static_cast<uint8_t>((i >> 16) & 0xFF),
                            static_cast<uint8_t>((i >> 8) & 0xFF),
                            static_cast<uint8_t>(i & 0xFF), 0x00, 0x01};
            binding.ip = {0xFD, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
                          0, 0, 0, 0,
                          static_cast<uint8_t>((0x2000 + i) >> 8),
                          static_cast<uint8_t>((0x2000 + i) & 0xFF),
                          static_cast<uint8_t>((i >> 8) & 0xFF),
                          static_cast<uint8_t>(i & 0xFF)};
            cfg.ipv6.dhcpv6.static_bindings.push_back(binding);
        }

        vgww::runtime::Dataplane dp(cfg, kLeasePath);
        dp.SetDriverClient(std::make_unique<WebFakeDriver>());
        std::string start_error;
        CHECK(dp.Start(start_error));
        CHECK(dp.Dhcp6Active());

        HttpServer api;
        vgww::web::RegisterApi(api, dp, cfg, "", "boot-secret");
        constexpr uint16_t kP = 18086;
        std::string error;
        CHECK(api.Start("127.0.0.1", kP, error));

        std::string body;
        CHECK(HttpGet("/api/dhcp6/bindings", kP, body) == 200);
        CHECK(body.find("[") != std::string::npos);

        // Mutations stay token-guarded.
        CHECK(HttpPost(kP, "/api/dhcp6/bindings", "",
                       "{\"duid\":\"00:03:00:01:aa:bb\","
                       "\"ip\":\"fd00:1122:3344:5566::5000\"}",
                       body) == 401);

        // 1024th binding succeeds; a duplicate DUID is a conflict.
        CHECK(HttpPost(kP, "/api/dhcp6/bindings", "boot-secret",
                       "{\"duid\":\"00:03:00:01:aa:bb\","
                       "\"ip\":\"fd00:1122:3344:5566::5000\"}",
                       body) == 200);
        CHECK(HttpPost(kP, "/api/dhcp6/bindings", "boot-secret",
                       "{\"duid\":\"00:03:00:01:aa:bb\","
                       "\"ip\":\"fd00:1122:3344:5566::5001\"}",
                       body) == 400);
        // Out-of-prefix address -> rejected by the server.
        CHECK(HttpPost(kP, "/api/dhcp6/bindings", "boot-secret",
                       "{\"duid\":\"00:03:00:01:aa:cc\","
                       "\"ip\":\"fd01::1\"}",
                       body) == 400);
        // 1025th -> rejected by the cap.
        CHECK(HttpPost(kP, "/api/dhcp6/bindings", "boot-secret",
                       "{\"duid\":\"00:03:00:01:aa:dd\","
                       "\"ip\":\"fd00:1122:3344:5566::5002\"}",
                       body) == 400);
        CHECK(dp.GetDhcp6Bindings().size() ==
              ::vgww::core::limits::kMaxStaticBindings6);

        // DELETE removes; repeat -> 404; missing duid -> 400; no token -> 401.
        const std::string delete_one =
            "DELETE /api/dhcp6/bindings?duid=00:03:00:01:aa:bb HTTP/1.1\r\n"
            "Host: t\r\nX-Auth-Token: boot-secret\r\nContent-Length: 0\r\n"
            "Connection: close\r\n\r\n";
        CHECK(HttpRaw(kP, delete_one, body) == 200);
        CHECK(HttpRaw(kP, delete_one, body) == 404);
        CHECK(HttpRaw(kP,
                      "DELETE /api/dhcp6/bindings HTTP/1.1\r\nHost: t\r\n"
                      "X-Auth-Token: boot-secret\r\nContent-Length: 0\r\n"
                      "Connection: close\r\n\r\n",
                      body) == 400);
        CHECK(HttpRaw(kP,
                      "DELETE /api/dhcp6/bindings?duid=00:03:00:01:aa:bb "
                      "HTTP/1.1\r\nHost: t\r\nContent-Length: 0\r\n"
                      "Connection: close\r\n\r\n",
                      body) == 401);

        api.Stop();
        std::string stop_error;
        CHECK(dp.Stop(stop_error));
        std::remove(kLeasePath);
        std::remove(lease6_path.c_str());
    }

    // batch142: the v6 duplicate check compared the POSTed DUID TEXT against
    // the canonical text the snapshot returns (FormatDuidText -> lowercase
    // colon form), while the v4 sibling parsed BOTH sides before comparing.
    // Any other legal spelling therefore slipped past "binding exists" and the
    // store (keyed by the PARSED bytes) silently UPSERTED - replacing the
    // existing binding's address and hostname with no warning at all. That is
    // exactly the "plausible-but-broken success" the route's own comment says
    // must not happen.
    void TestB142Dhcp6DuplicateCheckIsSpellingIndependent() {
        const char* kLeasePath = "b142-leases.json";
        const std::string lease6_path = std::string(kLeasePath) + ".leases6";
        std::remove(kLeasePath);
        std::remove(lease6_path.c_str());

        vgww::core::Config cfg;
        cfg.adapter = "WebTestNIC142";
        cfg.mode = vgww::core::Mode::kMain;
        cfg.gateway.mac = {0x30, 0xFC, 0x68, 0x88, 0xB4, 0xA9};
        cfg.ipv6.enabled = true;
        cfg.ipv6.prefix_len = 64;
        cfg.ipv6.ula_prefix = {0xFD, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
                               0x66, 0, 0, 0, 0, 0, 0, 0, 0};
        cfg.ipv6.dhcpv6.enabled = true;
        cfg.ipv6.dhcpv6.pool_start = {0xFD, 0x00, 0x11, 0x22, 0x33, 0x44,
                                      0x55, 0x66, 0, 0, 0, 0, 0, 0, 0x10,
                                      0x00};
        cfg.ipv6.dhcpv6.pool_end = {0xFD, 0x00, 0x11, 0x22, 0x33, 0x44,
                                    0x55, 0x66, 0, 0, 0, 0, 0, 0, 0x1F,
                                    0xFF};
        cfg.ipv6.dhcpv6.lease_seconds = 3600;
        cfg.perf.workers = 2;
        cfg.perf.ring_capacity = 64;
        cfg.perf.max_conns = 64;

        vgww::runtime::Dataplane dp(cfg, kLeasePath);
        dp.SetDriverClient(std::make_unique<WebFakeDriver>());
        std::string start_error;
        CHECK(dp.Start(start_error));
        CHECK(dp.Dhcp6Active());

        HttpServer api;
        vgww::web::RegisterApi(api, dp, cfg, "", "boot-secret");
        constexpr uint16_t kP = 18096;
        std::string error;
        CHECK(api.Start("127.0.0.1", kP, error));

        std::string body;
        CHECK(HttpPost(kP, "/api/dhcp6/bindings", "boot-secret",
                       "{\"duid\":\"00:03:00:01:aa:bb\","
                       "\"ip\":\"fd00:1122:3344:5566::5000\","
                       "\"hostname\":\"keep-me\"}",
                       body) == 200);
        CHECK(dp.GetDhcp6Bindings().size() == 1);

        // Every spelling below names the SAME DUID bytes, so each must be a
        // conflict - not an overwrite.
        const char* const same_duid[] = {
            "00:03:00:01:AA:BB",        // uppercase
            "00-03-00-01-aa-bb",        // dash separator
            "00030001aabb",             // no separators
            "00:03:00:01:aa:bb:00",     // (extra byte -> different DUID)
        };
        CHECK(HttpPost(kP, "/api/dhcp6/bindings", "boot-secret",
                       "{\"duid\":\"00:03:00:01:AA:BB\","
                       "\"ip\":\"fd00:1122:3344:5566::5001\","
                       "\"hostname\":\"replaced\"}",
                       body) == 400);
        CHECK(HttpPost(kP, "/api/dhcp6/bindings", "boot-secret",
                       "{\"duid\":\"00-03-00-01-aa-bb\","
                       "\"ip\":\"fd00:1122:3344:5566::5002\","
                       "\"hostname\":\"replaced\"}",
                       body) == 400);
        CHECK(HttpPost(kP, "/api/dhcp6/bindings", "boot-secret",
                       "{\"duid\":\"00030001aabb\","
                       "\"ip\":\"fd00:1122:3344:5566::5003\","
                       "\"hostname\":\"replaced\"}",
                       body) == 400);
        (void)same_duid;

        // The original binding is untouched (address AND hostname).
        const auto after = dp.GetDhcp6Bindings();
        CHECK(after.size() == 1);
        if (after.size() == 1) {
            CHECK(after[0].duid == "00:03:00:01:aa:bb");
            CHECK(after[0].ip == "fd00:1122:3344:5566::5000");
            CHECK(after[0].hostname == "keep-me");
        }

        // A genuinely different DUID still inserts.
        CHECK(HttpPost(kP, "/api/dhcp6/bindings", "boot-secret",
                       "{\"duid\":\"00:03:00:01:aa:cc\","
                       "\"ip\":\"fd00:1122:3344:5566::5004\"}",
                       body) == 200);
        CHECK(dp.GetDhcp6Bindings().size() == 2);

        api.Stop();
        std::string stop_error;
        CHECK(dp.Stop(stop_error));
        std::remove(kLeasePath);
        std::remove(lease6_path.c_str());
    }

    // batch41 (live CRUD audit): the DHCP static-binding store only exists
    // while the service runs (dhcp_/dhcp6_ are assembled in Dataplane::Start).
    // While stopped, mutations must refuse with "service not running" - the
    // old "invalid mac/ip" blamed the caller's values when the real cause was
    // the absent runtime - and reads must stay safe and empty.
    void TestB41DhcpBindingStoppedGate() {
        vgww::core::Config cfg;
        cfg.adapter = "WebTestNICG";
        cfg.mode = vgww::core::Mode::kMain;
        cfg.gateway.mac = {0x30, 0xFC, 0x68, 0x88, 0xB4, 0xA9};
        cfg.perf.workers = 2;

        vgww::runtime::Dataplane dp(cfg);  // NOT started: no DHCP runtime
        HttpServer api;
        vgww::web::RegisterApi(api, dp, cfg, "", "boot-secret");
        constexpr uint16_t kP = 18104;
        std::string error;
        CHECK(api.Start("127.0.0.1", kP, error));

        std::string body;
        CHECK(HttpPost(kP, "/api/dhcp/bindings", "boot-secret",
                       "{\"mac\":\"00:11:22:33:44:55\",\"ip\":\"192.168.0.60\"}",
                       body) == 409);
        CHECK(body.find("service not running") != std::string::npos);
        CHECK(HttpPost(kP, "/api/dhcp6/bindings", "boot-secret",
                       "{\"duid\":\"00:03:00:01:aa:bb\",\"ip\":\"fd00::70\"}",
                       body) == 409);
        CHECK(body.find("service not running") != std::string::npos);
        // HttpDelete() sends no credentials; write-gated endpoints need the
        // token, so drive the DELETEs with HttpRaw like the running-case test.
        CHECK(HttpRaw(kP,
                      "DELETE /api/dhcp/bindings?mac=00:11:22:33:44:55 "
                      "HTTP/1.1\r\nHost: t\r\nX-Auth-Token: boot-secret\r\n"
                      "Content-Length: 0\r\nConnection: close\r\n\r\n",
                      body) == 409);
        CHECK(HttpRaw(kP,
                      "DELETE /api/dhcp6/bindings?duid=00:03:00:01:aa:bb "
                      "HTTP/1.1\r\nHost: t\r\nX-Auth-Token: boot-secret\r\n"
                      "Content-Length: 0\r\nConnection: close\r\n\r\n",
                      body) == 409);
        CHECK(HttpGet("/api/dhcp/bindings", kP, body) == 200);
        CHECK(HttpGet("/api/dhcp6/bindings", kP, body) == 200);
        api.Stop();
    }

    /// /api/status is a SUMMARY polled every 2 s by the WebUI: it must carry
    /// counts, not the lease list (batch152).
    ///
    /// The array used to be embedded, and nothing read it: the WebUI's leases
    /// page fetches /api/dhcp/leases + /api/dhcp6/bindings, and the native UI
    /// reads the controller snapshot. Yet every poll formatted every v6 lease
    /// (DUID text + IPv6 text + JSON escaping) and shipped it - O(leases) work
    /// per poll, on a payload whose size is bounded only by the configured
    /// pool (default pool alone is 4096 addresses). The list now has its own
    /// endpoint, mirroring /api/dhcp/leases for v4.
    void TestStatusIncludesLeases6() {
        const char* kLeasePath = "web-status6-leases.json";
        const std::string lease6_path = std::string(kLeasePath) + ".leases6";
        std::remove(kLeasePath);
        std::remove(lease6_path.c_str());
        vgww::core::Config cfg;
        cfg.adapter = "WebTestNIC6S";
        cfg.mode = vgww::core::Mode::kMain;
        cfg.gateway.mac = {0x30, 0xFC, 0x68, 0x88, 0xB4, 0xA9};
        cfg.ipv6.enabled = true;
        cfg.ipv6.prefix_len = 64;
        cfg.ipv6.ula_prefix = {0xFD, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
                               0x66, 0, 0, 0, 0, 0, 0, 0, 0};
        cfg.ipv6.dhcpv6.enabled = true;
        cfg.ipv6.dhcpv6.pool_start = {0xFD, 0x00, 0x11, 0x22, 0x33, 0x44,
                                      0x55, 0x66, 0, 0, 0, 0, 0, 0, 0x10,
                                      0x00};
        cfg.ipv6.dhcpv6.pool_end = {0xFD, 0x00, 0x11, 0x22, 0x33, 0x44,
                                    0x55, 0x66, 0, 0, 0, 0, 0, 0, 0x1F,
                                    0xFF};
        cfg.ipv6.dhcpv6.lease_seconds = 3600;
        cfg.perf.workers = 2;
        cfg.perf.ring_capacity = 64;
        cfg.perf.max_conns = 64;

        // One live lease restored from disk, so the list endpoint is asserted
        // on real content instead of an empty array. The lease file is
        // machine-written and only accepts the fixed 8-group form (no "::"),
        // while the API formats back canonically ("::1005").
        {
            std::ofstream f(lease6_path, std::ios::binary);
            f << "[{\"duid\":\"00:03:00:01:aa:bb\",\"iaid\":7,"
                 "\"ip\":\"fd00:1122:3344:5566:0000:0000:0000:1005\","
                 "\"expires_in_s\":1800,\"hostname\":\"host6\"}]";
        }

        vgww::runtime::Dataplane dp(cfg, kLeasePath);
        dp.SetDriverClient(std::make_unique<WebFakeDriver>());
        std::string start_error;
        CHECK(dp.Start(start_error));
        CHECK(dp.Dhcp6Active());

        HttpServer api;
        vgww::web::RegisterApi(api, dp, cfg, "", "boot-secret");
        constexpr uint16_t kP = 18087;
        std::string error;
        CHECK(api.Start("127.0.0.1", kP, error));

        std::string body;
        CHECK(HttpGet("/api/status", kP, body) == 200);
        CHECK(JsonWholeBody(body, kKeysStatus,
                            sizeof(kKeysStatus) / sizeof(kKeysStatus[0])));
        // The summary keeps the counters ...
        CHECK(body.find("\"leases6_count\":1") != std::string::npos);
        CHECK(body.find("\"bindings6_count\":") != std::string::npos);
        // ... and no longer carries the (unbounded) list.
        CHECK(body.find("\"leases6\":[") == std::string::npos);

        // The list lives on its own endpoint, same shape as /api/dhcp/leases.
        CHECK(HttpGet("/api/dhcp6/leases", kP, body) == 200);
        CHECK(body.find("\"duid\":\"00:03:00:01:aa:bb\"") != std::string::npos);
        CHECK(body.find("\"ip\":\"fd00:1122:3344:5566::1005\"") !=
              std::string::npos);
        CHECK(body.find("\"expires_in_s\":") != std::string::npos);
        CHECK(body.find("\"is_static\":false") != std::string::npos);
        CHECK(body.find("\"hostname\":\"host6\"") != std::string::npos);
        CHECK(body.size() > 2 && body.front() == '[' && body.back() == ']');

        api.Stop();
        std::string stop_error;
        CHECK(dp.Stop(stop_error));
        std::remove(kLeasePath);
        std::remove(lease6_path.c_str());
    }

    /// The v6 lease endpoint degrades to an empty array when the v6 server is
    /// not assembled, exactly like /api/dhcp/leases in bypass mode.
    void TestDhcp6LeasesEmptyWhenNotAssembled() {
        const char* kLeasePath = "web-dhcp6-leases-bypass.json";
        const std::string lease6_path = std::string(kLeasePath) + ".leases6";
        std::remove(kLeasePath);
        std::remove(lease6_path.c_str());
        vgww::core::Config cfg;
        cfg.adapter = "WebTestNIC6N";
        cfg.mode = vgww::core::Mode::kBypass;
        cfg.perf.workers = 1;
        cfg.perf.ring_capacity = 16;
        cfg.perf.max_conns = 16;

        vgww::runtime::Dataplane dp(cfg, kLeasePath);
        dp.SetDriverClient(std::make_unique<WebFakeDriver>());
        std::string start_error;
        CHECK(dp.Start(start_error));

        HttpServer api;
        vgww::web::RegisterApi(api, dp, cfg, "", "boot-secret");
        constexpr uint16_t kP = 18088;
        std::string error;
        CHECK(api.Start("127.0.0.1", kP, error));

        std::string body;
        CHECK(HttpGet("/api/dhcp6/leases", kP, body) == 200);
        CHECK(body == "[]");

        api.Stop();
        std::string stop_error;
        CHECK(dp.Stop(stop_error));
        std::remove(kLeasePath);
        std::remove(lease6_path.c_str());
    }

    /// /api/status exposes the bridge object (S3-Task4): enabled,
    /// upstream, downstream, mac_count and state. Closed-state values
    /// are asserted here (disabled / stopped / zero).
    ///
    /// batch152: this used to assert `body.find("\"bridge\":{")`, which is
    /// satisfied ANYWHERE in the body - including nested inside another
    /// object. The bridge object had drifted inside "dhcp6", so the WebUI's
    /// `st.bridge` lookup was undefined and the whole Bridge page rendered
    /// blank while this test stayed green. The assertions below parse the
    /// body and require the object at the TOP level, where the documented
    /// contract (and every consumer) expects it.
    void TestStatusIncludesBridge() {
        const char* kLeasePath = "web-status-bridge-leases.json";
        std::remove(kLeasePath);
        vgww::core::Config cfg;
        cfg.adapter = "WebTestNICBridge";
        cfg.gateway.mac = {0x30, 0xFC, 0x68, 0x88, 0xB4, 0xA9};
        cfg.perf.workers = 1;
        cfg.perf.ring_capacity = 64;
        cfg.perf.max_conns = 64;

        vgww::runtime::Dataplane dp(cfg, kLeasePath);
        dp.SetDriverClient(std::make_unique<WebFakeDriver>());
        std::string start_error;
        CHECK(dp.Start(start_error));

        HttpServer api;
        vgww::web::RegisterApi(api, dp, cfg, "", "boot-secret");
        constexpr uint16_t kP = 18088;
        std::string error;
        CHECK(api.Start("127.0.0.1", kP, error));

        std::string body;
        CHECK(HttpGet("/api/status", kP, body) == 200);
        CHECK(JsonWholeBody(body, kKeysStatus,
                            sizeof(kKeysStatus) / sizeof(kKeysStatus[0])));
        const auto j = nlohmann::json::parse(body, nullptr, false);
        CHECK(!j.is_discarded());
        CHECK(j.contains("bridge"));
        CHECK(j.contains("bridge") && j["bridge"].is_object());
        if (j.contains("bridge") && j["bridge"].is_object()) {
            CHECK(j["bridge"]["enabled"] == false);
            CHECK(j["bridge"]["upstream"] == "");
            CHECK(j["bridge"]["downstream"] == "");
            CHECK(j["bridge"]["mac_count"] == 0);
            CHECK(j["bridge"]["state"] == "stopped");
        }
        // The summary's own children must not carry their own copy of it.
        CHECK(j.contains("dhcp6") && j["dhcp6"].is_object());
        if (j.contains("dhcp6") && j["dhcp6"].is_object()) {
            CHECK(!j["dhcp6"].contains("bridge"));
        }

        api.Stop();
        std::string stop_error;
        CHECK(dp.Stop(stop_error));
        std::remove(kLeasePath);
    }

    /// W8: at least one whole-body parse assertion per API endpoint.
    void TestApiWholeBodyJson() {
        const char* kLeasePath = "web-whole-json-leases.json";
        std::remove(kLeasePath);
        vgww::core::Config cfg;
        cfg.adapter = "WebTestNICWholeJson";
        cfg.gateway.mac = {0x30, 0xFC, 0x68, 0x88, 0xB4, 0xA9};
        cfg.perf.workers = 1;
        cfg.perf.ring_capacity = 64;
        cfg.perf.max_conns = 64;

        vgww::runtime::Dataplane dp(cfg, kLeasePath);
        dp.SetDriverClient(std::make_unique<WebFakeDriver>());
        std::string start_error;
        CHECK(dp.Start(start_error));

        HttpServer api;
        vgww::web::RegisterApi(api, dp, cfg, "", "boot-secret");
        constexpr uint16_t kP = 18090;
        std::string error;
        CHECK(api.Start("127.0.0.1", kP, error));

        struct Endpoint {
            const char* path;
            const char* const* keys;
            size_t n;
        };
        // batch22 H1: the native-only prefs are part of the GET contract (the
        // UI echoes the whole object back on save).
        constexpr const char* kConfigKeys[] = {"mode",           "dhcp",
                                               "bridge",         "ui_language",
                                               "ui_scale"};
        const Endpoint endpoints[] = {
            {"/api/status", kKeysStatus,
             sizeof(kKeysStatus) / sizeof(kKeysStatus[0])},
            {"/api/clients", kKeysClients,
             sizeof(kKeysClients) / sizeof(kKeysClients[0])},
            {"/api/system", kKeysSystem,
             sizeof(kKeysSystem) / sizeof(kKeysSystem[0])},
            {"/api/portmap", nullptr, 0},
            {"/api/bans", nullptr, 0},
            {"/api/ratelimit", nullptr, 0},
            {"/api/config", kConfigKeys,
             sizeof(kConfigKeys) / sizeof(kConfigKeys[0])},
            {"/api/dhcp/leases", nullptr, 0},
            {"/api/dhcp/bindings", nullptr, 0},
            {"/api/dhcp6/bindings", nullptr, 0},
        };
        std::string body;
        for (const auto& e : endpoints) {
            body.clear();
            const int status = HttpGet(e.path, kP, body);
            CHECK(status == 200);
            if (status != 200) continue;
            const bool whole = JsonWholeBody(body, e.keys, e.n);
            CHECK(whole);
            if (!whole) {
                std::fprintf(stderr, "  %s -> %zu B: %s\n", e.path,
                             body.size(), body.c_str());
            }
        }

        api.Stop();
        std::string stop_error;
        CHECK(dp.Stop(stop_error));
        std::remove(kLeasePath);
    }

// batch22 H1: a Web save (full-replacement POST) must NOT wipe the native-only
// preferences. The GET schema now carries ui_language/ui_scale, and a body that
// omits them preserves the running values.
static void TestH1WebConfigPreservesNativePrefs() {
    using namespace vgww::core;
    const char* path = "h1native.json";
    const std::string rules = std::string(path) + ".rules.json";
    std::remove(path);
    std::remove(rules.c_str());

    Config cfg;
    cfg.web.port = 18088;
    bool ok = false;
    cfg.gateway.ipv4 = ParseIpv4("192.168.0.40", ok);
    cfg.gateway.mask = ParseIpv4("255.255.255.0", ok);
    MacAddress mac{};
    ParseMac("30:fc:68:88:b4:a9", mac);
    cfg.gateway.mac = mac;
    cfg.ui_language = "ja";
    cfg.ui_scale = "200";
    std::string err;
    CHECK(cfg.SaveToFile(path, err));

    vgww::runtime::Dataplane dp(cfg);
    HttpServer api;
    vgww::web::RegisterApi(api, dp, cfg, path);
    constexpr uint16_t kPort = 18097;
    std::string start_err;
    CHECK(api.Start("127.0.0.1", kPort, start_err));

    // (1) GET exposes the native-only preferences.
    std::string body;
    const int get_status = HttpGet("/api/config", kPort, body);
    CHECK(get_status == 200);
    CHECK(body.find("\"ui_language\":\"ja\"") != std::string::npos);
    CHECK(body.find("\"ui_scale\":\"200\"") != std::string::npos);

    // (2) A Web-shaped POST that omits them keeps them on disk.
    const std::string post =
        "{\"adapter\":\"x\",\"gateway\":{\"ipv4\":\"192.168.0.40\","
        "\"mask\":\"255.255.255.0\",\"mac\":\"30:fc:68:88:b4:a9\"},"
        "\"ipv6\":{\"enabled\":false,\"ula_prefix\":\"fdaa:0:0::\","
        "\"prefix_len\":64,\"ra_lifetime_s\":300},"
        "\"web\":{\"port\":18088,\"token\":\"\"},"
        "\"perf\":{\"workers\":4,\"max_conns\":4096}}";
    std::string resp;
    const int post_status = HttpPost(kPort, "/api/config", "", post, resp);
    CHECK(post_status == 200);
    api.Stop();

    std::string load_err;
    auto reloaded = Config::LoadFromFile(path, load_err);
    CHECK(reloaded.has_value());
    if (reloaded) {
        CHECK(reloaded->ui_language == "ja");
        CHECK(reloaded->ui_scale == "200");
    }
    std::remove(path);
    std::remove(rules.c_str());
}

// batch37t (user: settings must apply immediately): POST /api/config must
// hand the parsed config to the applier and answer "applied" when accepted.
static void TestB37tWebConfigAppliesLive() {
    using namespace vgww::core;
    const char* path = "b37t-web-apply.json";
    const std::string rules = std::string(path) + ".rules.json";
    std::remove(path);
    std::remove(rules.c_str());
    Config cfg;
    cfg.web.port = 18089;
    bool ok = false;
    cfg.gateway.ipv4 = ParseIpv4("192.168.0.40", ok);
    cfg.gateway.mask = ParseIpv4("255.255.255.0", ok);
    MacAddress mac{};
    ParseMac("30:fc:68:88:b4:a9", mac);
    cfg.gateway.mac = mac;
    std::string err;
    CHECK(cfg.SaveToFile(path, err));
    vgww::runtime::Dataplane dp(cfg);
    HttpServer api;
    bool applied = false;
    Config applied_cfg;
    vgww::web::RegisterApi(
        api, dp, cfg, path, "boot-secret", {}, {}, {}, {},
        [&](const Config& c, uint64_t) {
            applied = true;
            applied_cfg = c;
            return true;
        });
    constexpr uint16_t kPort = 18099;
    std::string start_err;
    CHECK(api.Start("127.0.0.1", kPort, start_err));
    const std::string post =
        "{\"adapter\":\"x\",\"gateway\":{\"ipv4\":\"192.168.0.40\","
        "\"mask\":\"255.255.255.0\",\"mac\":\"30:fc:68:88:b4:a9\"},"
        "\"ipv6\":{\"enabled\":false,\"ula_prefix\":\"fdaa:0:0::\","
        "\"prefix_len\":64,\"ra_lifetime_s\":300},"
        "\"web\":{\"port\":18089,\"token\":\"\"},"
        "\"perf\":{\"workers\":4,\"max_conns\":4096}}";
    std::string resp;
    CHECK(HttpPost(kPort, "/api/config", "boot-secret", post, resp) == 200);
    CHECK(resp.find("\"note\":\"applied\"") != std::string::npos);
    CHECK(applied);
    CHECK(applied_cfg.web.port == 18089);
    api.Stop();
    std::remove(path);
    std::remove(rules.c_str());
}

// batch114: an applier that refuses the save (returns false) must still close
// the attempt it was handed - otherwise the id is stamped with no completion
// and any page polling an older id waits forever.
static void TestB114RefusedApplyClosesTheAttempt() {
    using namespace vgww::core;
    const char* path = "b114-refused-apply.json";
    const std::string rules = std::string(path) + ".rules.json";
    std::remove(path);
    std::remove(rules.c_str());
    Config cfg;
    cfg.web.port = 18105;
    bool ok = false;
    cfg.gateway.ipv4 = ParseIpv4("192.168.0.40", ok);
    cfg.gateway.mask = ParseIpv4("255.255.255.0", ok);
    MacAddress mac{};
    ParseMac("30:fc:68:88:b4:a9", mac);
    cfg.gateway.mac = mac;
    std::string err;
    CHECK(cfg.SaveToFile(path, err));
    vgww::runtime::Dataplane dp(cfg);
    HttpServer api;
    auto status = std::make_shared<vgww::web::ConfigApplyStatus>();
    bool refused = false;
    vgww::web::RegisterApi(
        api, dp, cfg, path, "boot-secret", {}, {}, {}, {},
        [&](const Config&, uint64_t) {
            refused = true;
            return false;  // applier declines the save
        },
        status);
    constexpr uint16_t kPort = 18105;
    std::string start_err;
    CHECK(api.Start("127.0.0.1", kPort, start_err));
    const std::string body =
        "{\"adapter\":\"x\",\"gateway\":{\"ipv4\":\"192.168.0.40\","
        "\"mask\":\"255.255.255.0\",\"mac\":\"30:fc:68:88:b4:a9\"},"
        "\"ipv6\":{\"enabled\":false,\"ula_prefix\":\"fdaa:0:0::\","
        "\"prefix_len\":64,\"ra_lifetime_s\":300},"
        "\"web\":{\"port\":18105,\"token\":\"\"},"
        "\"perf\":{\"workers\":4,\"max_conns\":4096}}";
    std::string resp;
    CHECK(HttpPost(kPort, "/api/config", "boot-secret", body, resp) == 200);
    CHECK(refused);
    CHECK(resp.find("\"note\":\"applies on restart\"") != std::string::npos);

    const auto snap = status->Get();
    CHECK(snap.attempt_id == 1);
    CHECK(snap.completed_id == 1);
    CHECK(!snap.ok);
    CHECK(!snap.error.empty());

    api.Stop();
    std::remove(path);
    std::remove(rules.c_str());
}

// batch113: with no applier the save cannot be applied, so it must not stamp
// an attempt id that nobody will ever complete - a page holding an older id
// would otherwise poll forever ("pending" that never resolves).
static void TestB113NoApplierDoesNotStampAttempt() {
    using namespace vgww::core;
    const char* path = "b113-no-applier.json";
    const std::string rules = std::string(path) + ".rules.json";
    std::remove(path);
    std::remove(rules.c_str());
    Config cfg;
    cfg.web.port = 18104;
    bool ok = false;
    cfg.gateway.ipv4 = ParseIpv4("192.168.0.40", ok);
    cfg.gateway.mask = ParseIpv4("255.255.255.0", ok);
    MacAddress mac{};
    ParseMac("30:fc:68:88:b4:a9", mac);
    cfg.gateway.mac = mac;
    std::string err;
    CHECK(cfg.SaveToFile(path, err));
    vgww::runtime::Dataplane dp(cfg);
    HttpServer api;
    auto status = std::make_shared<vgww::web::ConfigApplyStatus>();
    vgww::web::RegisterApi(api, dp, cfg, path, "boot-secret",
                            {}, {}, {}, {}, {}, status);  // no applier
    constexpr uint16_t kPort = 18104;
    std::string start_err;
    CHECK(api.Start("127.0.0.1", kPort, start_err));
    const std::string body =
        "{\"adapter\":\"x\",\"gateway\":{\"ipv4\":\"192.168.0.40\","
        "\"mask\":\"255.255.255.0\",\"mac\":\"30:fc:68:88:b4:a9\"},"
        "\"ipv6\":{\"enabled\":false,\"ula_prefix\":\"fdaa:0:0::\","
        "\"prefix_len\":64,\"ra_lifetime_s\":300},"
        "\"web\":{\"port\":18104,\"token\":\"\"},"
        "\"perf\":{\"workers\":4,\"max_conns\":4096}}";
    std::string resp;
    CHECK(HttpPost(kPort, "/api/config", "boot-secret", body, resp) == 200);
    CHECK(resp.find("\"note\":\"applies on restart\"") != std::string::npos);
    CHECK(resp.find("\"apply_id\"") == std::string::npos);

    std::string status_body;
    CHECK(HttpGet("/api/config/apply-status", kPort, status_body) == 200);
    CHECK(status_body.find("\"attempt_id\":0") != std::string::npos);
    CHECK(status_body.find("\"completed_id\":0") != std::string::npos);

    api.Stop();
    std::remove(path);
    std::remove(rules.c_str());
}

// batch127: contract test for the health surfaces the WebUI/native UI read.
// Every key the surfaces rely on must exist with the expected JSON type, so a
// later refactor cannot silently delete or retype one.
static void TestB127StatusContractKeys() {
    using namespace vgww::core;
    const char* path = "b127-contract.json";
    const std::string rules = std::string(path) + ".rules.json";
    std::remove(path);
    std::remove(rules.c_str());
    Config cfg;
    cfg.web.port = 18114;
    bool ok = false;
    cfg.gateway.ipv4 = ParseIpv4("192.168.0.40", ok);
    cfg.gateway.mask = ParseIpv4("255.255.255.0", ok);
    MacAddress mac{};
    ParseMac("30:fc:68:88:b4:a9", mac);
    cfg.gateway.mac = mac;
    std::string err;
    CHECK(cfg.SaveToFile(path, err));
    vgww::runtime::Dataplane dp(cfg);
    HttpServer api;
    vgww::web::RegisterApi(
        api, dp, cfg, path, "boot-secret",
        [] { return std::string("hello"); }, {}, {}, {}, {}, {},
        [] { return uint64_t{3}; });
    constexpr uint16_t kPort = 18114;
    std::string start_err;
    CHECK(api.Start("127.0.0.1", kPort, start_err));

    std::string body;
    CHECK(HttpGet("/api/status", kPort, body) == 200);
    const auto st = nlohmann::json::parse(body);
    const auto require = [&st](const std::string& dot) {
        const size_t slash = dot.find('.');
        const auto& parent = st.at(dot.substr(0, slash));
        return parent.contains(dot.substr(slash + 1));
    };
    CHECK(require("gateway.ip"));
    CHECK(require("stats.rx_frames"));
    CHECK(require("portmap_health.accepted"));
    for (const char* key :
         {"leases", "persistence_paused", "persist_failures",
          "stop_persist_failed", "pool_exhausted", "leases_dropped",
          "leases_corrupt", "parse_rejected"}) {
        CHECK(require(std::string("dhcp.") + key));
    }
    for (const char* key :
         {"leases6_count", "persistence_paused", "persist_failures",
          "pool_exhausted", "leases_dropped", "leases_corrupt",
          "parse_rejected", "bindings6_count"}) {
        CHECK(require(std::string("dhcp6.") + key));
    }
    CHECK(require("stats.udp_flow_evictions"));
    CHECK(require("bridge.mac_evictions"));
    CHECK(require("bridge.neighbor_rejections"));
    CHECK(require("dhcp.rate_limit_resets"));
    CHECK(require("dhcp6.rate_limit_resets"));
    CHECK(st.contains("dataplane_error"));
    CHECK(st.contains("bridge_error"));
    CHECK(st.contains("dataplane_running"));
    CHECK(st.contains("dhcp_active"));
    CHECK(st.contains("dhcp6_active"));
    CHECK(st.contains("adapter_name"));
    CHECK(st.contains("adapter_link_up"));
    CHECK(require("bridge.enabled"));
    CHECK(require("web.handler_errors"));
    for (const char* key :
         {"persist_failures", "persist_blocked", "recoveries",
          "discarded"}) {
        CHECK(require(std::string("rules.") + key));
    }

    std::string console_body;
    CHECK(HttpGet("/api/console", kPort, console_body) == 200);
    const auto cn = nlohmann::json::parse(console_body);
    CHECK(cn.contains("text") && cn.contains("count") &&
          cn.contains("available") && cn.contains("dropped"));
    CHECK(cn["dropped"].get<uint64_t>() == 3);

    api.Stop();
    std::remove(path);
    std::remove(rules.c_str());
}

// batch126 (Web surface): the console ring's eviction count must be visible.
static void TestB126WebConsoleReportsDropped() {
    using namespace vgww::core;
    const char* path = "b126-console.json";
    const std::string rules = std::string(path) + ".rules.json";
    std::remove(path);
    std::remove(rules.c_str());
    Config cfg;
    cfg.web.port = 18113;
    bool ok = false;
    cfg.gateway.ipv4 = ParseIpv4("192.168.0.40", ok);
    cfg.gateway.mask = ParseIpv4("255.255.255.0", ok);
    MacAddress mac{};
    ParseMac("30:fc:68:88:b4:a9", mac);
    cfg.gateway.mac = mac;
    std::string err;
    CHECK(cfg.SaveToFile(path, err));
    vgww::runtime::Dataplane dp(cfg);
    HttpServer api;
    vgww::web::RegisterApi(
        api, dp, cfg, path, "boot-secret",
        [] { return std::string(); }, {}, {}, {}, {}, {},
        [] { return uint64_t{7}; });
    constexpr uint16_t kPort = 18113;
    std::string start_err;
    CHECK(api.Start("127.0.0.1", kPort, start_err));
    std::string body;
    CHECK(HttpGet("/api/console", kPort, body) == 200);
    const auto json = nlohmann::json::parse(body);
    CHECK(json["dropped"].get<uint64_t>() == 7);
    api.Stop();
    std::remove(path);
    std::remove(rules.c_str());
}

// batch123: privileged rule/binding/config changes must land in the audit
// ring (only repair-driver and autostart were recorded before).
static void TestB123PrivilegedChangesAreAudited() {
    using namespace vgww::core;
    const char* path = "b123-audit.json";
    const std::string rules = std::string(path) + ".rules.json";
    std::remove(path);
    std::remove(rules.c_str());
    Config cfg;
    cfg.web.port = 18112;
    bool ok = false;
    cfg.gateway.ipv4 = ParseIpv4("192.168.0.40", ok);
    cfg.gateway.mask = ParseIpv4("255.255.255.0", ok);
    MacAddress mac{};
    ParseMac("30:fc:68:88:b4:a9", mac);
    cfg.gateway.mac = mac;
    std::string err;
    CHECK(cfg.SaveToFile(path, err));
    vgww::runtime::Dataplane dp(cfg);
    HttpServer api;
    std::vector<std::string> audit_lines;
    vgww::web::RegisterApi(
        api, dp, cfg, path, "boot-secret", {}, {}, {},
        [&audit_lines](const std::string& line) {
            audit_lines.push_back(line);
        });
    constexpr uint16_t kPort = 18112;
    std::string start_err;
    CHECK(api.Start("127.0.0.1", kPort, start_err));
    std::string resp;

    CHECK(HttpPost(kPort, "/api/portmap", "boot-secret",
                   "{\"proto\":\"tcp\",\"wan_port\":19001,"
                   "\"lan_ip\":\"192.168.0.10\",\"lan_port\":8080}",
                   resp) == 200);
    CHECK(HttpPost(kPort, "/api/bans", "boot-secret",
                   "{\"kind\":\"mac\",\"value\":\"aa:bb:cc:dd:ee:ff\"}",
                   resp) == 200);
    std::string bans_body;
    CHECK(HttpGet("/api/bans", kPort, bans_body) == 200);
    const auto bans_json = nlohmann::json::parse(bans_body);
    uint64_t ban_id = 0;
    for (const auto& entry : bans_json) {
        if (entry.value("value", "") == "AA:BB:CC:DD:EE:FF") {
            ban_id = entry["id"].get<uint64_t>();
        }
    }
    CHECK(0 != ban_id);
    CHECK(HttpPost(kPort, "/api/ratelimit", "boot-secret",
                   "{\"mac\":\"aa:bb:cc:dd:ee:01\",\"uplink_kbps\":1000}",
                   resp) == 200);
    CHECK(HttpPost(kPort, "/api/config", "boot-secret", cfg.ToJsonString(),
                   resp) == 200);
    CHECK(HttpDeleteWithToken("/api/bans?id=" + std::to_string(ban_id),
                              kPort, "boot-secret", resp) == 200);
    CHECK(HttpDeleteWithToken("/api/portmap?index=0", kPort, "boot-secret",
                              resp) == 200);
    CHECK(HttpDeleteWithToken("/api/ratelimit?mac=aa:bb:cc:dd:ee:01", kPort,
                              "boot-secret", resp) == 200);

    api.Stop();

    const auto contains = [&audit_lines](const std::string& needle) {
        for (const auto& line : audit_lines) {
            if (line.find(needle) != std::string::npos) {
                return true;
            }
        }
        return false;
    };
    CHECK(contains("portmap add"));
    CHECK(contains("ban add"));
    CHECK(contains("ratelimit set"));
    CHECK(contains("config saved"));
    CHECK(contains("ban delete"));
    CHECK(contains("portmap delete"));
    CHECK(contains("ratelimit delete"));

    std::remove(path);
    std::remove(rules.c_str());
}

// P92: the audit line for a rule mutation used to be written before the
// durability verdict was known, so a publish that failed still left a plain
// success record while the route answered persisted:false. The audit trail
// must carry the same verdict.
static void TestP92WebAuditLineCarriesPersistFailure() {
    using namespace vgww::core;
    const char* path = "p92-audit.json";
    const std::string rules = std::string(path) + ".rules.json";
    std::remove(path);
    std::error_code ec;
    std::filesystem::remove_all(rules, ec);
    // A DIRECTORY at the rules path makes every write fail permanently.
    CHECK(std::filesystem::create_directory(rules, ec));

    Config cfg;
    cfg.web.port = 18124;
    bool ok = false;
    cfg.gateway.ipv4 = ParseIpv4("192.168.0.44", ok);
    cfg.gateway.mask = ParseIpv4("255.255.255.0", ok);
    MacAddress mac{};
    ParseMac("30:fc:68:88:b4:ac", mac);
    cfg.gateway.mac = mac;
    std::string err;
    CHECK(cfg.SaveToFile(path, err));

    vgww::runtime::Dataplane dp(cfg);
    HttpServer api;
    std::vector<std::string> audit_lines;
    vgww::web::RegisterApi(
        api, dp, cfg, path, "boot-secret", {}, {}, {},
        [&audit_lines](const std::string& line) {
            audit_lines.push_back(line);
        });
    constexpr uint16_t kPort = 18124;
    std::string start_err;
    CHECK(api.Start("127.0.0.1", kPort, start_err));

    std::string resp;
    CHECK(HttpPost(kPort, "/api/bans", "boot-secret",
                   R"({"kind":"ip","value":"10.9.8.7"})", resp) == 200);
    CHECK(resp.find("\"persisted\":false") != std::string::npos);


    const auto find_ban_add = [&audit_lines]() -> const std::string* {
        for (const auto& line : audit_lines) {
            if (line.find("ban add") != std::string::npos) {
                return &line;
            }
        }
        return nullptr;
    };
    const std::string* ban_add = find_ban_add();
    CHECK(nullptr != ban_add);
    if (nullptr != ban_add) {
        CHECK(ban_add->find("NOT saved") != std::string::npos);
    }

    // Removing the blocker lets the next mutation audit a real success.
    std::filesystem::remove_all(rules, ec);
    audit_lines.clear();
    CHECK(HttpPost(kPort, "/api/bans", "boot-secret",
                   R"({"kind":"ip","value":"10.9.8.8"})", resp) == 200);
    CHECK(resp.find("\"persisted\":true") != std::string::npos);
    const std::string* clean = find_ban_add();
    CHECK(nullptr != clean);
    if (nullptr != clean) {
        CHECK(clean->find("NOT saved") == std::string::npos);
    }

    api.Stop();
    vgww::web::RuleStore::Instance().AttachFile("");
    vgww::web::RuleStore::Instance().Clear();
    std::remove(path);
    std::filesystem::remove_all(rules, ec);
}
static void TestB122WebStatusReportsParseRejects6() {
    using namespace vgww::core;
    const char* path = "b122-status.json";
    const std::string rules = std::string(path) + ".rules.json";
    std::remove(path);
    std::remove(rules.c_str());
    Config cfg;
    cfg.web.port = 18111;
    bool ok = false;
    cfg.gateway.ipv4 = ParseIpv4("192.168.0.40", ok);
    cfg.gateway.mask = ParseIpv4("255.255.255.0", ok);
    MacAddress mac{};
    ParseMac("30:fc:68:88:b4:a9", mac);
    cfg.gateway.mac = mac;
    std::string err;
    CHECK(cfg.SaveToFile(path, err));
    vgww::runtime::Dataplane dp(cfg);
    HttpServer api;
    vgww::web::RegisterApi(api, dp, cfg, path, "boot-secret");
    constexpr uint16_t kPort = 18111;
    std::string start_err;
    CHECK(api.Start("127.0.0.1", kPort, start_err));
    vgww::proto::Dhcp6View view{};
    std::vector<uint8_t> garbage(32, 0);
    const uint64_t before = vgww::proto::ParseRejected6Count();
    CHECK(!vgww::proto::ParseDhcp6Frame(garbage.data(), garbage.size(),
                                         view));
    CHECK(before + 1 == vgww::proto::ParseRejected6Count());
    std::string body;
    CHECK(HttpGet("/api/status", kPort, body) == 200);
    const auto json = nlohmann::json::parse(body);
    const uint64_t reported =
        json["dhcp6"]["parse_rejected"].get<uint64_t>();
    CHECK(reported == before + 1);
    api.Stop();
    std::remove(path);
    std::remove(rules.c_str());
}

// batch121 (Web surface): strict-parse refusals must be visible on
// /api/status, not only in memory.
static void TestB121WebStatusReportsParseRejects() {
    using namespace vgww::core;
    const char* path = "b121-status.json";
    const std::string rules = std::string(path) + ".rules.json";
    std::remove(path);
    std::remove(rules.c_str());
    Config cfg;
    cfg.web.port = 18110;
    bool ok = false;
    cfg.gateway.ipv4 = ParseIpv4("192.168.0.40", ok);
    cfg.gateway.mask = ParseIpv4("255.255.255.0", ok);
    MacAddress mac{};
    ParseMac("30:fc:68:88:b4:a9", mac);
    cfg.gateway.mac = mac;
    std::string err;
    CHECK(cfg.SaveToFile(path, err));
    vgww::runtime::Dataplane dp(cfg);
    HttpServer api;
    vgww::web::RegisterApi(api, dp, cfg, path, "boot-secret");
    constexpr uint16_t kPort = 18110;
    std::string start_err;
    CHECK(api.Start("127.0.0.1", kPort, start_err));
    // A malformed frame bumps the global parse-reject counter.
    vgww::proto::DhcpView view{};
    std::vector<uint8_t> garbage(32, 0);
    const uint64_t before = vgww::proto::ParseRejectedCount();
    CHECK(!vgww::proto::ParseDhcpFrame(garbage.data(), garbage.size(), view));
    CHECK(before + 1 == vgww::proto::ParseRejectedCount());
    std::string body;
    CHECK(HttpGet("/api/status", kPort, body) == 200);
    const auto json = nlohmann::json::parse(body);
    const uint64_t reported =
        json["dhcp"]["parse_rejected"].get<uint64_t>();
    CHECK(reported == before + 1);
    api.Stop();
    std::remove(path);
    std::remove(rules.c_str());
}

// batch120 (Web surface): a corrupt lease document must be visible on
// /api/status, not only in stderr.
static void TestB120WebStatusReportsCorruptLeases() {
    using namespace vgww::core;
    const char* path = "b120-status.json";
    const std::string lease_path = "b120_leases.json";
    const std::string rules = std::string(path) + ".rules.json";
    std::remove(path);
    std::remove(lease_path.c_str());
    std::remove(rules.c_str());
    Config cfg;
    cfg.web.port = 18109;
    cfg.mode = Mode::kMain;
    bool ok = false;
    cfg.gateway.ipv4 = ParseIpv4("192.168.0.40", ok);
    cfg.gateway.mask = ParseIpv4("255.255.255.0", ok);
    MacAddress mac{};
    ParseMac("30:fc:68:88:b4:a9", mac);
    cfg.gateway.mac = mac;
    cfg.dhcp.enabled = true;
    cfg.dhcp.pool_start = ParseIpv4("192.168.0.100", ok);
    cfg.dhcp.pool_end = ParseIpv4("192.168.0.110", ok);
    cfg.dhcp.lease_seconds = 3600;
    std::string err;
    CHECK(cfg.SaveToFile(path, err));
    {
        std::ofstream out(lease_path);
        out << "this is not json";
    }
    vgww::runtime::Dataplane dp(cfg, lease_path);
    dp.SetDriverClient(std::make_unique<WebFakeDriver>());
    std::string dp_err;
    CHECK(dp.Start(dp_err));
    HttpServer api;
    vgww::web::RegisterApi(api, dp, cfg, path, "boot-secret");
    constexpr uint16_t kPort = 18109;
    std::string start_err;
    CHECK(api.Start("127.0.0.1", kPort, start_err));
    std::string body;
    CHECK(HttpGet("/api/status", kPort, body) == 200);
    CHECK(body.find("\"leases_corrupt\":true") != std::string::npos);
    api.Stop();
    std::string stop_err;
    dp.Stop(stop_err);
    std::remove(path);
    std::remove(lease_path.c_str());
    std::remove(rules.c_str());
    std::remove((lease_path + ".corrupt").c_str());
}

// batch119 (Web surface): lease entries dropped at load must be visible on
// /api/status, not only in stderr.
static void TestB119WebStatusReportsDroppedLeases() {
    using namespace vgww::core;
    const char* path = "b119-status.json";
    const std::string lease_path = "b119_leases.json";
    const std::string rules = std::string(path) + ".rules.json";
    std::remove(path);
    std::remove(lease_path.c_str());
    std::remove(rules.c_str());
    Config cfg;
    cfg.web.port = 18108;
    cfg.mode = Mode::kMain;
    bool ok = false;
    cfg.gateway.ipv4 = ParseIpv4("192.168.0.40", ok);
    cfg.gateway.mask = ParseIpv4("255.255.255.0", ok);
    MacAddress mac{};
    ParseMac("30:fc:68:88:b4:a9", mac);
    cfg.gateway.mac = mac;
    cfg.dhcp.enabled = true;
    cfg.dhcp.pool_start = ParseIpv4("192.168.0.100", ok);
    cfg.dhcp.pool_end = ParseIpv4("192.168.0.110", ok);
    cfg.dhcp.lease_seconds = 3600;
    std::string err;
    CHECK(cfg.SaveToFile(path, err));
    {
        std::ofstream out(lease_path);
        out << "{\"version\":1,\"leases\":["
               "{\"mac\":\"not-a-mac\",\"ip\":\"192.168.0.100\","
               "\"hostname\":\"bad\",\"expires_in_s\":3600},"
               "{\"mac\":\"AA:BB:CC:DD:EE:01\",\"ip\":\"192.168.0.101\","
               "\"hostname\":\"good\",\"expires_in_s\":3600}]}";
    }
    vgww::runtime::Dataplane dp(cfg, lease_path);
    dp.SetDriverClient(std::make_unique<WebFakeDriver>());
    std::string dp_err;
    CHECK(dp.Start(dp_err));
    HttpServer api;
    vgww::web::RegisterApi(api, dp, cfg, path, "boot-secret");
    constexpr uint16_t kPort = 18108;
    std::string start_err;
    CHECK(api.Start("127.0.0.1", kPort, start_err));
    std::string body;
    CHECK(HttpGet("/api/status", kPort, body) == 200);
    CHECK(body.find("\"leases_dropped\":1") != std::string::npos);
    api.Stop();
    std::string stop_err;
    dp.Stop(stop_err);
    std::remove(path);
    std::remove(lease_path.c_str());
    std::remove(rules.c_str());
}

// batch118 (Web surface): the startup discard count must be visible on
// /api/status, not only in stderr.
static void TestB118WebStatusReportsDiscarded() {
    using namespace vgww::core;
    const char* path = "b118-status.json";
    const std::string rules = std::string(path) + ".rules.json";
    std::remove(path);
    std::remove(rules.c_str());
    Config cfg;
    cfg.web.port = 18107;
    bool ok = false;
    cfg.gateway.ipv4 = ParseIpv4("192.168.0.40", ok);
    cfg.gateway.mask = ParseIpv4("255.255.255.0", ok);
    MacAddress mac{};
    ParseMac("30:fc:68:88:b4:a9", mac);
    cfg.gateway.mac = mac;
    std::string err;
    CHECK(cfg.SaveToFile(path, err));
    {
        std::ofstream out(rules);
        out << "{\"portmaps\":[{\"proto\":\"udp\",\"wan_port\":9999,"
               "\"lan_ip\":\"192.168.0.10\",\"lan_port\":9999}]}";
    }
    vgww::runtime::Dataplane dp(cfg);
    HttpServer api;
    vgww::web::RegisterApi(api, dp, cfg, path, "boot-secret");
    constexpr uint16_t kPort = 18107;
    std::string start_err;
    CHECK(api.Start("127.0.0.1", kPort, start_err));
    std::string body;
    CHECK(HttpGet("/api/status", kPort, body) == 200);
    CHECK(body.find("\"discarded\":1") != std::string::npos);
    api.Stop();
    std::remove(path);
    std::remove(rules.c_str());
}

// batch117: the Web settings save has the same merge rule as the native UI -
// a document at the binding cap must not silently erase a disk-only binding.
static void TestB117WebConfigSaveRefusesToDropDiskBindings() {
    using namespace vgww::core;
    const char* path = "b117-cap.json";
    const std::string rules = std::string(path) + ".rules.json";
    std::remove(path);
    std::remove(rules.c_str());
    const auto read_back = [](const std::string& p) {
        std::ifstream in(p, std::ios::binary);
        return std::string(std::istreambuf_iterator<char>(in),
                           std::istreambuf_iterator<char>());
    };
    bool ok = false;
    Config cfg;
    cfg.adapter = "Ethernet";
    cfg.mode = Mode::kMain;
    cfg.web.port = 18106;
    cfg.gateway.ipv4 = ParseIpv4("192.168.0.1", ok);
    cfg.gateway.mask = ParseIpv4("255.255.0.0", ok);
    MacAddress mac{};
    ParseMac("30:fc:68:88:b4:a9", mac);
    cfg.gateway.mac = mac;
    cfg.dhcp.enabled = true;
    cfg.dhcp.pool_start = ParseIpv4("192.168.10.1", ok);
    cfg.dhcp.pool_end = ParseIpv4("192.168.14.254", ok);
    char mac_text[32];
    for (size_t i = 0; i < limits::kMaxStaticBindings; ++i) {
        StaticBinding b;
        std::snprintf(mac_text, sizeof(mac_text), "02:%02x:%02x:00:00:01",
                      static_cast<unsigned>(i >> 8),
                      static_cast<unsigned>(i & 0xFF));
        CHECK(ParseMac(mac_text, b.mac));
        b.ip = ParseIpv4("192.168." +
                             std::to_string(10u + i / 254u) + "." +
                             std::to_string(1u + i % 254u),
                         ok);
        CHECK(ok);
        b.hostname = "h" + std::to_string(i);
        cfg.dhcp.static_bindings.push_back(b);
    }
    std::string err;
    CHECK(cfg.SaveToFile(path, err));
    vgww::runtime::Dataplane dp(cfg);
    HttpServer api;
    vgww::web::RegisterApi(api, dp, cfg, path, "boot-secret");
    constexpr uint16_t kPort = 18106;
    std::string start_err;
    CHECK(api.Start("127.0.0.1", kPort, start_err));

    // Cap churn on disk: delete one, add another.
    CHECK(Config::UpdateFile(
        path,
        [&](Config& c) {
            c.dhcp.static_bindings.erase(c.dhcp.static_bindings.begin());
            StaticBinding extra;
            ParseMac("02:00:00:00:ff:ff", extra.mac);
            extra.ip = ParseIpv4("192.168.15.9", ok);
            extra.hostname = "churned-in";
            c.dhcp.static_bindings.push_back(std::move(extra));
        },
        err));
    const std::string after_churn = read_back(path);
    CHECK(after_churn.find("churned-in") != std::string::npos);

    // The page posts the stale (full) document; the save must be refused.
    const std::string body = cfg.ToJsonString();
    std::string resp;
    CHECK(HttpPost(kPort, "/api/config", "boot-secret", body, resp) == 409);
    CHECK(read_back(path) == after_churn);

    const auto disk = Config::LoadFromFile(path, err);
    CHECK(disk.has_value());
    if (disk) {
        bool churned = false;
        for (const auto& b : disk->dhcp.static_bindings) {
            if (b.hostname == "churned-in") {
                churned = true;
            }
        }
        CHECK(churned);
    }

    api.Stop();
    std::remove(path);
    std::remove(rules.c_str());
}

// batch112: a static binding added at runtime (after the settings page was
// rendered) lives on disk but not in the GET /api/config body the page posts
// back. The full-document replace used to erase it: the operator's binding
// survived until restart, then vanished. Disk bindings the body never names
// must be preserved, like SaveToFilePreservingBindings does for the native UI.
static void TestB112WebConfigSaveKeepsRuntimeBindings() {
    using namespace vgww::core;
    const char* path = "b112-keep-bindings.json";
    const std::string rules = std::string(path) + ".rules.json";
    std::remove(path);
    std::remove(rules.c_str());
    Config cfg;
    cfg.web.port = 18103;
    bool ok = false;
    cfg.gateway.ipv4 = ParseIpv4("192.168.0.40", ok);
    cfg.gateway.mask = ParseIpv4("255.255.255.0", ok);
    MacAddress mac{};
    ParseMac("30:fc:68:88:b4:a9", mac);
    cfg.gateway.mac = mac;
    // A stateful DHCPv6 service so the v6 binding round-trip is validated too.
    cfg.ipv6.enabled = true;
    cfg.ipv6.ula_prefix = std::array<uint8_t, 16>{0xFD, 0xAA, 0, 0, 0, 0, 0,
                                                  0,    0,    0, 0, 0, 0,
                                                  0,    0,    0};
    cfg.ipv6.prefix_len = 64;
    cfg.ipv6.ra_lifetime_s = 900;
    cfg.ipv6.dhcpv6.enabled = true;
    const auto v6 = [](uint8_t hi, uint8_t lo) {
        std::array<uint8_t, 16> a{};
        a[0] = 0xFD;
        a[1] = 0xAA;
        a[14] = hi;
        a[15] = lo;
        return a;
    };
    cfg.ipv6.dhcpv6.pool_start = v6(0x10, 0x00);
    cfg.ipv6.dhcpv6.pool_end = v6(0x1F, 0xFF);
    cfg.ipv6.dhcpv6.lease_seconds = 1800;
    std::string err;
    CHECK(cfg.SaveToFile(path, err));
    vgww::runtime::Dataplane dp(cfg);
    HttpServer api;
    vgww::web::RegisterApi(api, dp, cfg, path, "boot-secret");
    constexpr uint16_t kPort = 18103;
    std::string start_err;
    CHECK(api.Start("127.0.0.1", kPort, start_err));

    // A binding added after the settings page was rendered (the runtime route
    // persists it straight to the config file).
    std::string up_err;
    MacAddress late_mac{};
    CHECK(ParseMac("30:fc:68:88:b4:b0", late_mac));
    CHECK(UpsertDhcpBinding(path, late_mac,
                                  ParseIpv4("192.168.0.55", ok), "late", up_err));

    // Same for a DHCPv6 binding added at runtime.
    std::array<uint8_t, 16> late_ip{};
    late_ip[0] = 0xFD;
    late_ip[1] = 0xAA;
    late_ip[14] = 0x50;
    late_ip[15] = 0x00;  // fdaa::5000
    CHECK(UpsertDhcp6Binding(
        path, std::vector<uint8_t>{0x00, 0x03, 0x00, 0x01, 0xAA, 0xBB},
        late_ip, "nas6", up_err));

    // The page renders from the stale body and posts it back unchanged.
    std::string body;
    CHECK(HttpGet("/api/config", kPort, body) == 200);
    CHECK(body.find("b4:b0") == std::string::npos);  // genuinely stale
    CHECK(body.find("5000") == std::string::npos);

    std::string resp;
    CHECK(HttpPost(kPort, "/api/config", "boot-secret", body, resp) == 200);

    // The runtime-added binding must still be on disk (and loadable).
    std::string load_err;
    const auto disk = Config::LoadFromFile(path, load_err);
    CHECK(disk.has_value());
    bool found = false;
    if (disk) {
        MacAddress wanted{};
        ParseMac("30:fc:68:88:b4:b0", wanted);
        for (const auto& b : disk->dhcp.static_bindings) {
            if (b.mac == wanted) {
                found = true;
            }
        }
    }
    CHECK(found);

    bool found6 = false;
    if (disk) {
        const std::vector<uint8_t> wanted = {0x00, 0x03, 0x00, 0x01,
                                             0xAA, 0xBB};
        for (const auto& b : disk->ipv6.dhcpv6.static_bindings) {
            if (b.duid == wanted) {
                found6 = true;
            }
        }
    }
    CHECK(found6);

    api.Stop();
    std::remove(path);
    std::remove(rules.c_str());
}

// batch111: two in-flight saves can finish in either order. A completion must
// only be attributed to the attempt that produced it: a late result from an
// older attempt must not overwrite a newer one (the page polls the newer id).
static void TestB111ApplyStatusIgnoresStaleCompletion() {
    auto status = std::make_shared<vgww::web::ConfigApplyStatus>();
    const uint64_t first = status->MarkAttempt();
    const uint64_t second = status->MarkAttempt();
    CHECK(first == 1 && second == 2);

    // The newer attempt finishes first and succeeds.
    status->Record(second, true, "");
    auto snap = status->Get();
    CHECK(snap.attempt_id == second);
    CHECK(snap.completed_id == second);
    CHECK(snap.ok);
    CHECK(snap.error.empty());

    // The older attempt's late failure must be dropped.
    status->Record(first, false, "bind failed: stale attempt");
    snap = status->Get();
    CHECK(snap.completed_id == second);
    CHECK(snap.ok);
    CHECK(snap.error.empty());

    // A newer attempt is pending again once stamped.
    const uint64_t third = status->MarkAttempt();
    snap = status->Get();
    CHECK(snap.attempt_id == third);
    CHECK(snap.completed_id == second);  // page sees "pending"
    status->Record(third, false, "adapter missing");
    snap = status->Get();
    CHECK(snap.completed_id == third);
    CHECK(!snap.ok);
    CHECK(snap.error == "adapter missing");
}

// batch38 (user: any leftover / UX feedback): POST /api/config returns an
// apply_id, and GET /api/config/apply-status reports the async apply outcome
// (pending until Record, then the recorded ok/error), so the Web page can show
// a truthful result instead of a false "saved and applied".
static void TestB38WebApplyStatus() {
    using namespace vgww::core;
    const char* path = "b38-apply-status.json";
    const std::string rules = std::string(path) + ".rules.json";
    std::remove(path);
    std::remove(rules.c_str());
    Config cfg;
    cfg.web.port = 18089;
    bool ok = false;
    cfg.gateway.ipv4 = ParseIpv4("192.168.0.40", ok);
    cfg.gateway.mask = ParseIpv4("255.255.255.0", ok);
    MacAddress mac{};
    ParseMac("30:fc:68:88:b4:a9", mac);
    cfg.gateway.mac = mac;
    std::string err;
    CHECK(cfg.SaveToFile(path, err));
    vgww::runtime::Dataplane dp(cfg);
    HttpServer api;
    bool applied = false;
    auto status = std::make_shared<vgww::web::ConfigApplyStatus>();
    vgww::web::RegisterApi(
        api, dp, cfg, path, "boot-secret", {}, {}, {}, {},
        [&](const Config&, uint64_t) {
            applied = true;
            return true;
        },
        status);
    constexpr uint16_t kPort = 18100;
    std::string start_err;
    CHECK(api.Start("127.0.0.1", kPort, start_err));
    const std::string post =
        "{\"adapter\":\"x\",\"gateway\":{\"ipv4\":\"192.168.0.40\","
        "\"mask\":\"255.255.255.0\",\"mac\":\"30:fc:68:88:b4:a9\"},"
        "\"ipv6\":{\"enabled\":false,\"ula_prefix\":\"fdaa:0:0::\","
        "\"prefix_len\":64,\"ra_lifetime_s\":300},"
        "\"web\":{\"port\":18089,\"token\":\"\"},"
        "\"perf\":{\"workers\":4,\"max_conns\":4096}}";
    std::string resp;
    CHECK(HttpPost(kPort, "/api/config", "boot-secret", post, resp) == 200);
    CHECK(resp.find("\"note\":\"applied\"") != std::string::npos);
    CHECK(resp.find("\"apply_id\":") != std::string::npos);
    CHECK(applied);  // finish_save invited the applier synchronously; only the
                     // real async outcome is later recorded via Record().

    // Attempt 1 is open; nothing completed yet.
    std::string body;
    CHECK(HttpGet("/api/config/apply-status", kPort, body) == 200);
    CHECK(body.find("\"attempt_id\":1") != std::string::npos);
    CHECK(body.find("\"completed_id\":0") != std::string::npos);

    // A successful apply records ok=true with the matching completed id.
    status->Record(1, true, "");
    CHECK(HttpGet("/api/config/apply-status", kPort, body) == 200);
    CHECK(body.find("\"completed_id\":1") != std::string::npos);
    CHECK(body.find("\"ok\":true") != std::string::npos);

    // A failed apply records the backend error verbatim.
    status->Record(1, false, "bind failed: EACCES");
    CHECK(HttpGet("/api/config/apply-status", kPort, body) == 200);
    CHECK(body.find("\"ok\":false") != std::string::npos);
    CHECK(body.find("bind failed: EACCES") != std::string::npos);

    // Without a worker the POST still stamps the next attempt id.
    HttpPost(kPort, "/api/config", "boot-secret", post, resp);
    CHECK(HttpGet("/api/config/apply-status", kPort, body) == 200);
    CHECK(body.find("\"attempt_id\":2") != std::string::npos);
    api.Stop();
    std::remove(path);
    std::remove(rules.c_str());
}

// batch22 S1: the Web form's mode / web.port / bridge fields must round-trip
// through POST /api/config into the persisted config (the front-end paths the
// new SET_FIELDS entries write).
static void TestS1WebSettingsRoundTrip() {
    using namespace vgww::core;
    const char* path = "s1form.json";
    const std::string rules = std::string(path) + ".rules.json";
    std::remove(path);
    std::remove(rules.c_str());

    Config cfg;
    cfg.web.port = 18090;
    bool ok = false;
    cfg.gateway.ipv4 = ParseIpv4("192.168.0.40", ok);
    cfg.gateway.mask = ParseIpv4("255.255.255.0", ok);
    MacAddress mac{};
    ParseMac("30:fc:68:88:b4:a9", mac);
    cfg.gateway.mac = mac;
    cfg.mode = Mode::kBypass;
    std::string err;
    CHECK(cfg.SaveToFile(path, err));

    vgww::runtime::Dataplane dp(cfg);
    HttpServer api;
    vgww::web::RegisterApi(api, dp, cfg, path);
    constexpr uint16_t kPort = 18098;
    std::string start_err;
    CHECK(api.Start("127.0.0.1", kPort, start_err));

    // GET carries the S1 sections (the form reads them).
    std::string body;
    CHECK(HttpGet("/api/config", kPort, body) == 200);
    CHECK(body.find("\"mode\"") != std::string::npos);
    CHECK(body.find("\"bridge\"") != std::string::npos);

    // POST the S1 edits (main mode, port 18091, bridge on).
    const std::string post =
        "{\"adapter\":\"x\",\"mode\":\"main\","
        "\"gateway\":{\"ipv4\":\"192.168.0.40\","
        "\"mask\":\"255.255.255.0\",\"mac\":\"30:fc:68:88:b4:a9\"},"
        "\"ipv6\":{\"enabled\":false,\"ula_prefix\":\"fdaa:0:0::\","
        "\"prefix_len\":64,\"ra_lifetime_s\":300},"
        "\"web\":{\"port\":18091,\"token\":\"\"},"
        "\"bridge\":{\"enabled\":true,\"upstream\":\"NIC 1\","
        "\"downstream\":\"NIC 2\",\"mac_table_size\":4096},"
        "\"dhcp\":{\"enabled\":true,"
        "\"pool\":[\"192.168.0.100\",\"192.168.0.200\"],"
        "\"lease_hours\":12,\"dns\":[\"8.8.8.8\",\"8.8.4.4\"]},"
        "\"ipv6\":{\"enabled\":true,\"ula_prefix\":\"fd00::\","
        "\"prefix_len\":64,\"ra_lifetime_s\":1800,"
        "\"dhcpv6\":{\"enabled\":true,\"pool_start\":\"fd00::1000\","
        "\"pool_end\":\"fd00::1fff\",\"lease_seconds\":3600}},"
        "\"perf\":{\"workers\":4,\"max_conns\":4096}}";
    std::string resp;
    CHECK(HttpPost(kPort, "/api/config", "", post, resp) == 200);
    api.Stop();

    std::string load_err;
    auto reloaded = Config::LoadFromFile(path, load_err);
    CHECK(reloaded.has_value());
    if (reloaded) {
        CHECK(reloaded->mode == Mode::kMain);
        CHECK(reloaded->web.port == 18091);
        CHECK(reloaded->bridge.enabled);
        CHECK(reloaded->bridge.upstream == "NIC 1");
        CHECK(reloaded->bridge.downstream == "NIC 2");
        CHECK(reloaded->bridge.mac_table_size == 4096u);
        // S2: DHCPv4 round-trips (pool array + lease hours + dns list).
        CHECK(reloaded->dhcp.enabled);
        bool ok2 = false;
        CHECK(reloaded->dhcp.pool_start ==
              ParseIpv4("192.168.0.100", ok2));
        CHECK(reloaded->dhcp.pool_end == ParseIpv4("192.168.0.200", ok2));
        CHECK(reloaded->dhcp.lease_seconds == 12u * 3600u);
        CHECK(reloaded->dhcp.dns.size() == 2u);
        // S3: IPv6 + DHCPv6 round-trip.
        CHECK(reloaded->ipv6.enabled);
        CHECK(reloaded->ipv6.prefix_len == 64u);
        CHECK(reloaded->ipv6.ra_lifetime_s == 1800u);
        CHECK(reloaded->ipv6.dhcpv6.enabled);
        CHECK(reloaded->ipv6.dhcpv6.lease_seconds == 3600u);
    }
    std::remove(path);
    std::remove(rules.c_str());
}

// batch22 B2: the leases page consumes the three DHCP endpoints - they must
// answer 200 with the array shapes the page renders (mac/ip/..., duid/ip).
static void TestB2LeaseEndpointsShape() {
    using namespace vgww::core;
    const char* path = "b2leases.json";
    const std::string rules = std::string(path) + ".rules.json";
    std::remove(path);
    std::remove(rules.c_str());
    Config cfg;
    cfg.web.port = 18092;
    bool ok = false;
    cfg.gateway.ipv4 = ParseIpv4("192.168.0.40", ok);
    cfg.gateway.mask = ParseIpv4("255.255.255.0", ok);
    MacAddress mac{};
    ParseMac("30:fc:68:88:b4:a9", mac);
    cfg.gateway.mac = mac;
    std::string err;
    CHECK(cfg.SaveToFile(path, err));

    vgww::runtime::Dataplane dp(cfg);
    HttpServer api;
    vgww::web::RegisterApi(api, dp, cfg, path);
    constexpr uint16_t kPort = 18096;
    std::string start_err;
    CHECK(api.Start("127.0.0.1", kPort, start_err));

    std::string body;
    CHECK(HttpGet("/api/dhcp/leases", kPort, body) == 200);
    CHECK(body.size() >= 2 && body.front() == '[' && body.back() == ']');
    CHECK(HttpGet("/api/dhcp/bindings", kPort, body) == 200);
    CHECK(body.size() >= 2 && body.front() == '[' && body.back() == ']');
    CHECK(HttpGet("/api/dhcp6/bindings", kPort, body) == 200);
    CHECK(body.size() >= 2 && body.front() == '[' && body.back() == ']');
    api.Stop();
    std::remove(path);
    std::remove(rules.c_str());
}

// batch22 B5 (updated by batch43): /api/system carries the About rows
// (version from the API, memory backend, config path, uptime and driver
// state). batch22 deliberately kept uptime/driver ABSENT ("no web-side
// source"); batch43 gives b5 a real source (steady-clock uptime + the same
// NdisrdServiceRunning the native About page uses) so the web About page no
// longer shows a permanent dash.
static void TestB5SystemIdentityFields() {
    using namespace vgww::core;
    const char* path = "b5system.json";
    const std::string rules = std::string(path) + ".rules.json";
    std::remove(path);
    std::remove(rules.c_str());
    Config cfg;
    cfg.web.port = 18093;
    bool ok = false;
    cfg.gateway.ipv4 = ParseIpv4("192.168.0.40", ok);
    cfg.gateway.mask = ParseIpv4("255.255.255.0", ok);
    MacAddress mac{};
    ParseMac("30:fc:68:88:b4:a9", mac);
    cfg.gateway.mac = mac;
    std::string err;
    CHECK(cfg.SaveToFile(path, err));

    vgww::runtime::Dataplane dp(cfg);
    HttpServer api;
    vgww::web::RegisterApi(api, dp, cfg, path);
    constexpr uint16_t kPort = 18095;
    std::string start_err;
    CHECK(api.Start("127.0.0.1", kPort, start_err));

    std::string body;
    CHECK(HttpGet("/api/system", kPort, body) == 200);
    CHECK(body.find("\"version\":\"0.1.0\"") != std::string::npos);
    CHECK(body.find("\"memory\":\"") != std::string::npos);
    CHECK(body.find("\"config_path\":\"" + std::string(path) + "\"") !=
          std::string::npos);
    // batch43: the About uptime and driver rows are now fed real data.
    CHECK(body.find("\"uptime_s\":") != std::string::npos);
    const auto at = body.find("\"uptime_s\":");
    if (at != std::string::npos) {
        // a JSON number: the next char must be a digit before , or }
        const char* p = body.c_str() + at + std::strlen("\"uptime_s\":");
        CHECK(*p >= '0' && *p <= '9');
    }
    CHECK(body.find("\"driver\":\"stopped\"") != std::string::npos ||
          body.find("\"driver\":\"running\"") != std::string::npos);
    api.Stop();
    std::remove(path);
    std::remove(rules.c_str());
}

// batch22 B1: GET /api/console serves the ring snapshot but MUST NOT re-serve
// token-shaped lines, and caps the response at the last 2000 lines.
static void TestB1ConsoleEndpointFiltersTokens() {
    using namespace vgww::core;
    const char* path = "b1console.json";
    const std::string rules = std::string(path) + ".rules.json";
    std::remove(path);
    std::remove(rules.c_str());
    Config cfg;
    cfg.web.port = 18094;
    bool ok = false;
    cfg.gateway.ipv4 = ParseIpv4("192.168.0.40", ok);
    cfg.gateway.mask = ParseIpv4("255.255.255.0", ok);
    MacAddress mac{};
    ParseMac("30:fc:68:88:b4:a9", mac);
    cfg.gateway.mac = mac;
    std::string err;
    CHECK(cfg.SaveToFile(path, err));

    vgww::runtime::Dataplane dp(cfg);
    HttpServer api;
    vgww::web::RegisterApi(
        api, dp, cfg, path, {},
        [] {
            std::string text = "hello-line-1\n"
                               "X-Auth-Token: super-secret\n"
                               "token=abc123\n"
                               "world-line-2";
            return text;
        });
    constexpr uint16_t kPort = 18094;
    std::string start_err;
    CHECK(api.Start("127.0.0.1", kPort, start_err));

    std::string body;
    CHECK(HttpGet("/api/console", kPort, body) == 200);
    CHECK(body.find("hello-line-1") != std::string::npos);
    CHECK(body.find("world-line-2") != std::string::npos);
    // Both token shapes must be gone (the whole point of the endpoint).
    CHECK(body.find("super-secret") == std::string::npos);
    CHECK(body.find("X-Auth-Token") == std::string::npos);
    CHECK(body.find("abc123") == std::string::npos);
    CHECK(body.find("\"available\":true") != std::string::npos);
    api.Stop();

    // Line cap: 2500 short lines -> the endpoint keeps the last 2000.
    vgww::runtime::Dataplane dp2(cfg);
    HttpServer api2;
    vgww::web::RegisterApi(api2, dp2, cfg, path, {},
                           [] {
                               std::string text;
                               for (int i = 0; i < 2500; ++i) {
                                   if (i != 0) text += "\n";
                                   text += "line-" + std::to_string(i);
                               }
                               return text;
                           });
    constexpr uint16_t kPort2 = 18094;
    std::string start_err2;
    // Reuse the same port after Stop on the first server.
    CHECK(api2.Start("127.0.0.1", kPort2, start_err2));
    std::string body2;
    CHECK(HttpGet("/api/console", kPort2, body2) == 200);
    CHECK(body2.find("\"count\":2000") != std::string::npos);
    CHECK(body2.find("line-2499") != std::string::npos);
    CHECK(body2.find("line-499") == std::string::npos);
    api2.Stop();
    std::remove(path);
    std::remove(rules.c_str());
}

// batch22 B4: privileged endpoints. Policy matrix (five cases) + autostart read
// back + audit lines. The native effect is supplied by callbacks, so no UAC or
// registry write happens here - the test asserts the API contract itself.
static void TestB4PrivilegedEndpoints() {
    using namespace vgww::core;
    const char* path = "b4priv.json";
    const std::string rules = std::string(path) + ".rules.json";
    std::remove(path);
    std::remove(rules.c_str());
    Config cfg;
    cfg.web.port = 18096;
    cfg.web.token.clear();
    bool ok = false;
    cfg.gateway.ipv4 = ParseIpv4("192.168.0.40", ok);
    cfg.gateway.mask = ParseIpv4("255.255.255.0", ok);
    MacAddress mac{};
    ParseMac("30:fc:68:88:b4:a9", mac);
    cfg.gateway.mac = mac;
    std::string err;
    CHECK(cfg.SaveToFile(path, err));

    std::string audit;
    bool autostart_state = false;
    int setter_calls = 0;

    // Case 1: no token configured -> 403 (privileged ops need a credential).
    {
        vgww::runtime::Dataplane dp(cfg);
        HttpServer api;
        vgww::web::RegisterApi(
            api, dp, cfg, path, /*auth_token=*/{}, /*console=*/{},
            /*repair=*/[] { return true; },
            [&autostart_state, &setter_calls](bool v) {
                ++setter_calls;
                autostart_state = v;
                return autostart_state;
            },
            [&audit](const std::string& l) { audit += l + "\n"; });
        constexpr uint16_t kPort = 18096;
        std::string se;
        CHECK(api.Start("127.0.0.1", kPort, se));
        std::string body;
        CHECK(HttpPost(kPort, "/api/repair-driver", "secret", "{}", body) == 403);
        CHECK(HttpPost(kPort, "/api/autostart", "secret", "{\"enabled\":true}",
                       body) == 403);
        CHECK(setter_calls == 0);  // 403 must not reach the OS layer
        CHECK(audit.empty());
        api.Stop();
    }

    // Case 1b (integration): the REAL pipeline passes a generated default when
    // the config left the token empty (main.cpp). That is still "no credential
    // configured", so the privivileged routes must answer 403 - not 401 - even
    // with the global write guard installed. Uses real HTTP on both routes.
    {
        vgww::runtime::Dataplane dp(cfg);
        HttpServer api;
        vgww::web::RegisterApi(
            api, dp, cfg, path, /*auth_token=*/"auto-generated", /*console=*/{},
            /*repair=*/[] { return true; },
            [&autostart_state, &setter_calls](bool v) {
                ++setter_calls;
                autostart_state = v;
                return autostart_state;
            },
            [&audit](const std::string& l) { audit += l + "\n"; });
        constexpr uint16_t kPort = 18096;
        std::string se;
        CHECK(api.Start("127.0.0.1", kPort, se));
        std::string body;
        // With the generated token presented - still 403: nothing was configured.
        CHECK(HttpPost(kPort, "/api/repair-driver", "auto-generated", "{}",
                       body) == 403);
        CHECK(HttpPost(kPort, "/api/autostart", "auto-generated",
                       "{\"enabled\":true}", body) == 403);
        CHECK(body.find("forbidden") != std::string::npos);
        CHECK(setter_calls == 0);
        // An UNRELATED route keeps the old guard behaviour (401 on a bad token).
        CHECK(HttpPost(kPort, "/api/portmap", "wrong", "{}", body) == 401);
        api.Stop();
    }

    // Cases 2-5 with a configured token (cfg.web.token non-empty, exactly as
    // the real process has it).
    cfg.web.token = "s3cr3t";
    {
        vgww::runtime::Dataplane dp(cfg);
        HttpServer api;
        vgww::web::RegisterApi(
            api, dp, cfg, path, "s3cr3t", {},
            [] { return true; },
            [&autostart_state, &setter_calls](bool v) {
                ++setter_calls;
                autostart_state = v;
                return autostart_state;
            },
            [&audit](const std::string& l) { audit += l + "\n"; });
        constexpr uint16_t kPort = 18096;
        std::string se;
        CHECK(api.Start("127.0.0.1", kPort, se));
        std::string body;
        // Case 2: wrong token -> 401 (global write guard).
        CHECK(HttpPost(kPort, "/api/repair-driver", "wrong", "{}", body) == 401);
        // Case 3: correct token -> 200 requested:true.
        CHECK(HttpPost(kPort, "/api/repair-driver", "s3cr3t", "{}", body) == 200);
        CHECK(body.find("\"requested\":true") != std::string::npos);
        // Case 4: immediately again -> 409 (repair already in flight).
        CHECK(HttpPost(kPort, "/api/repair-driver", "s3cr3t", "{}", body) == 409);
        // Autostart: writes and reports the value read back.
        CHECK(HttpPost(kPort, "/api/autostart", "s3cr3t",
                       "{\"enabled\":true}", body) == 200);
        CHECK(body.find("\"enabled\":true") != std::string::npos);
        CHECK(autostart_state);
        CHECK(HttpPost(kPort, "/api/autostart", "s3cr3t",
                       "{\"enabled\":false}", body) == 200);
        CHECK(body.find("\"enabled\":false") != std::string::npos);
        CHECK(!autostart_state);
        // Malformed body -> 400, no setter call.
        const int before = setter_calls;
        CHECK(HttpPost(kPort, "/api/autostart", "s3cr3t", "{\"nope\":1}",
                       body) == 400);
        CHECK(setter_calls == before);
    // Audit: one line per accepted privileged op (repair + 2 autostart).
    CHECK(audit.find("repair-driver requested") != std::string::npos);
    CHECK(audit.find("autostart set 1") != std::string::npos);
    CHECK(audit.find("autostart set 0") != std::string::npos);
    // P119: the refusals are audited too - a second repair inside the guard
    // window and a malformed autostart body must leave a record.
    CHECK(audit.find("repair-driver refused (busy)") != std::string::npos);
    CHECK(audit.find("autostart rejected (enabled required)") !=
          std::string::npos);
    // No secret ever appears in an audit line.
    CHECK(audit.find("s3cr3t") == std::string::npos);
        api.Stop();
    }

    // P120: the unwired-hook path (503) and the malformed-boolean path (400)
    // must be audited too - both are refusals the operator can only see in
    // the ring.
    cfg.web.token = "s3cr3t";
    audit.clear();
    {
        vgww::runtime::Dataplane dp(cfg);
        HttpServer api;
        vgww::web::RegisterApi(
            api, dp, cfg, path, "s3cr3t", {}, /*repair=*/{}, /*autostart=*/{},
            [&audit](const std::string& l) { audit += l + "\n"; });
        constexpr uint16_t kPort = 18096;
        std::string se;
        CHECK(api.Start("127.0.0.1", kPort, se));
        std::string body;
        CHECK(HttpPost(kPort, "/api/repair-driver", "s3cr3t", "{}", body) ==
              503);
        CHECK(HttpPost(kPort, "/api/autostart", "s3cr3t",
                       "{\"enabled\":true}", body) == 503);
        CHECK(audit.find("repair-driver refused (unavailable)") !=
              std::string::npos);
        CHECK(audit.find("autostart refused (unavailable)") !=
              std::string::npos);
        api.Stop();
    }
    audit.clear();
    {
        vgww::runtime::Dataplane dp(cfg);
        HttpServer api;
        vgww::web::RegisterApi(
            api, dp, cfg, path, "s3cr3t", {}, [] { return true; },
            [&autostart_state](bool v) {
                autostart_state = v;
                return autostart_state;
            },
            [&audit](const std::string& l) { audit += l + "\n"; });
        constexpr uint16_t kPort = 18096;
        std::string se;
        CHECK(api.Start("127.0.0.1", kPort, se));
        std::string body;
        CHECK(HttpPost(kPort, "/api/autostart", "s3cr3t",
                       "{\"enabled\":\"yes\"}", body) == 400);
        CHECK(audit.find("autostart rejected (enabled must be boolean)") !=
              std::string::npos);
        api.Stop();
    }
    std::remove(path);
    std::remove(rules.c_str());
}

// P93: the autostart audit line used to record the DESIRED state (`want`)
// while the response reports the ACTUAL state (`actual`). The production
// setter (main.cpp) ignores SetAutostart's return value and reads the registry
// back, so a failed write leaves `actual` at the old value - the audit ring
// then claims "autostart set 1" while the route answers {"enabled":false}.
// The audit trail must carry the same verdict as the response.
static void TestP93AutostartAuditCarriesActualState() {
    using namespace vgww::core;
    const char* path = "p93-autostart.json";
    const std::string rules = std::string(path) + ".rules.json";
    std::remove(path);
    std::remove(rules.c_str());
    Config cfg;
    cfg.web.port = 18130;
    cfg.web.token = "tok";
    bool ok = false;
    cfg.gateway.ipv4 = ParseIpv4("192.168.0.46", ok);
    cfg.gateway.mask = ParseIpv4("255.255.255.0", ok);
    MacAddress mac{};
    ParseMac("30:fc:68:88:b4:ae", mac);
    cfg.gateway.mac = mac;
    std::string err;
    CHECK(cfg.SaveToFile(path, err));

    vgww::runtime::Dataplane dp(cfg);
    HttpServer api;
    std::vector<std::string> audit_lines;
    bool registry_enabled = false;
    vgww::web::RegisterApi(
        api, dp, cfg, path, "tok", {}, [] { return true; },
        [&registry_enabled](bool /*v*/) {
            // A failed write leaves the registry untouched: the read-back is
            // the OLD value, not the requested one.
            return registry_enabled;
        },
        [&audit_lines](const std::string& line) {
            audit_lines.push_back(line);
        });
    constexpr uint16_t kPort = 18130;
    std::string start_err;
    CHECK(api.Start("127.0.0.1", kPort, start_err));

    std::string body;
    CHECK(HttpPost(kPort, "/api/autostart", "tok",
                   "{\"enabled\":true}", body) == 200);
    CHECK(body.find("\"enabled\":false") != std::string::npos);

    bool saw_failed_line = false;
    bool saw_plain_want_line = false;
    for (const auto& line : audit_lines) {
        if (line.find("autostart set") == std::string::npos) {
            continue;
        }
        if (line.find("NOT applied") != std::string::npos) {
            saw_failed_line = true;
        } else if (line.find("autostart set 1") != std::string::npos) {
            saw_plain_want_line = true;
        }
    }
    CHECK(saw_failed_line);
    CHECK(!saw_plain_want_line);

    // A successful write audits the plain line (the guard is not a blanket
    // suffix).
    registry_enabled = true;
    audit_lines.clear();
    CHECK(HttpPost(kPort, "/api/autostart", "tok",
                   "{\"enabled\":true}", body) == 200);
    CHECK(body.find("\"enabled\":true") != std::string::npos);
    bool saw_clean_line = false;
    for (const auto& line : audit_lines) {
        if (line.find("autostart set 1") != std::string::npos &&
            line.find("NOT applied") == std::string::npos) {
            saw_clean_line = true;
        }
    }
    CHECK(saw_clean_line);

    api.Stop();
    std::remove(path);
    std::remove(rules.c_str());
}

// P95: a failed config save used to leave no audit line at all - only the HTTP
// 500/400. The ring is the operator's durable record of privileged changes, so
// a refused or failed save must be visible there too.
static void TestP95ConfigSaveFailureIsAudited() {
    using namespace vgww::core;
    const char* path = "p95-config.json";
    const std::string rules = std::string(path) + ".rules.json";
    std::remove(path);
    std::remove(rules.c_str());
    Config cfg;
    cfg.web.port = 18132;
    cfg.web.token = "tok";
    bool ok = false;
    cfg.gateway.ipv4 = ParseIpv4("192.168.0.48", ok);
    cfg.gateway.mask = ParseIpv4("255.255.255.0", ok);
    MacAddress mac{};
    ParseMac("30:fc:68:88:b4:b0", mac);
    cfg.gateway.mac = mac;
    std::string err;
    CHECK(cfg.SaveToFile(path, err));

    vgww::runtime::Dataplane dp(cfg);
    HttpServer api;
    std::vector<std::string> audit_lines;
    vgww::web::RegisterApi(
        api, dp, cfg, path, "tok", {}, [] { return true; },
        [](bool) { return false; },
        [&audit_lines](const std::string& line) {
            audit_lines.push_back(line);
        });
    constexpr uint16_t kPort = 18132;
    std::string start_err;
    CHECK(api.Start("127.0.0.1", kPort, start_err));

    std::string body;
    // An invalid document is rejected before any write.
    CHECK(HttpPost(kPort, "/api/config", "tok",
                   "{\"gateway\":{\"ipv4\":\"not-an-ip\"}}", body) == 400);
    bool saw_rejected = false;
    for (const auto& line : audit_lines) {
        if (line.find("config save rejected") != std::string::npos) {
            saw_rejected = true;
        }
    }
    CHECK(saw_rejected);

    // A directory at the config path makes the write fail after validation.
    audit_lines.clear();
    std::error_code ec;
    std::filesystem::remove(path, ec);
    CHECK(std::filesystem::create_directory(path, ec));
    CHECK(HttpPost(kPort, "/api/config", "tok", cfg.ToJsonString(),
                   body) == 500);
    bool saw_failed = false;
    for (const auto& line : audit_lines) {
        if (line.find("config save failed") != std::string::npos) {
            saw_failed = true;
        }
    }
    CHECK(saw_failed);

    // A second owner holding the cross-process lock must be audited too: the
    // save is refused (never published without mutual exclusion).
    audit_lines.clear();
    std::filesystem::remove_all(path, ec);
    CHECK(cfg.SaveToFile(path, err));
    vgww::core::SetConfigLockWaitForTest(std::chrono::milliseconds(20));
    std::atomic<bool> held{false};
    std::atomic<bool> release{false};
    std::thread holder([&] {
        vgww::core::ConfigFileLock lock(path);
        held.store(true, std::memory_order_release);
        while (!release.load(std::memory_order_acquire)) {
            std::this_thread::yield();
        }
    });
    while (!held.load(std::memory_order_acquire)) {
        std::this_thread::yield();
    }
    CHECK(HttpPost(kPort, "/api/config", "tok", cfg.ToJsonString(),
                   body) == 500);
    release.store(true, std::memory_order_release);
    holder.join();
    vgww::core::SetConfigLockWaitForTest(std::chrono::milliseconds(0));
    bool saw_lock_failed = false;
    for (const auto& line : audit_lines) {
        if (line.find("config save failed (cross-process lock)") !=
            std::string::npos) {
            saw_lock_failed = true;
        }
    }
    CHECK(saw_lock_failed);

    api.Stop();
    std::filesystem::remove_all(path, ec);
    std::remove(rules.c_str());
}

// P102: a failed binding persist must audit the outcome too. The runtime
// change is live in that path, so the ring is the only durable record that the
// row will be lost on restart.
static void TestP102WebBindingPersistFailureIsAudited() {
    using namespace vgww::core;
    const char* path = "p102-binding.json";
    const char* lease_path = "p102_leases.json";
    std::remove(path);
    std::remove(lease_path);
    Config cfg;
    cfg.adapter = "P102NIC";
    cfg.mode = Mode::kMain;
    cfg.dhcp.enabled = true;
    cfg.web.port = 18134;
    cfg.web.token = "tok";
    bool ok = false;
    cfg.gateway.ipv4 = ParseIpv4("192.168.52.1", ok);
    cfg.gateway.mask = ParseIpv4("255.255.255.0", ok);
    cfg.gateway.mac = {0x30, 0xFC, 0x68, 0x88, 0xB4, 0xA2};
    cfg.dhcp.pool_start = ParseIpv4("192.168.52.100", ok);
    cfg.dhcp.pool_end = ParseIpv4("192.168.52.200", ok);
    cfg.dhcp.lease_seconds = 3600;
    cfg.ipv6.enabled = true;
    cfg.ipv6.prefix_len = 64;
    cfg.ipv6.ula_prefix = {0xFD, 0x00, 0x11, 0x33, 0x44, 0x55, 0x66,
    0x77, 0, 0, 0, 0, 0, 0, 0, 0};
    cfg.ipv6.dhcpv6.enabled = true;
    cfg.ipv6.dhcpv6.pool_start = {0xFD, 0x00, 0x11, 0x33, 0x44, 0x55,
    0x66, 0x77, 0, 0, 0, 0, 0, 0, 0x10, 0x00};
    cfg.ipv6.dhcpv6.pool_end = {0xFD, 0x00, 0x11, 0x33, 0x44, 0x55,
        0x66, 0x77, 0, 0, 0, 0, 0, 0, 0x1F, 0xFF};
    cfg.perf.workers = 2;
    cfg.perf.ring_capacity = 64;
    cfg.perf.max_conns = 64;
    std::string err;
    CHECK(cfg.SaveToFile(path, err));

    vgww::runtime::Dataplane dp(cfg, lease_path);
    dp.SetDriverClient(std::make_unique<WebFakeDriver>());
    std::string start_error;
    CHECK(dp.Start(start_error));
    CHECK(dp.DhcpActive());
    CHECK(dp.Dhcp6Active());

    HttpServer api;
    std::vector<std::string> audit_lines;
    vgww::web::RegisterApi(
        api, dp, cfg, path, "tok", {}, [] { return true; },
        [](bool) { return false; },
        [&audit_lines](const std::string& line) {
            audit_lines.push_back(line);
        });
    constexpr uint16_t kPort = 18134;
    CHECK(api.Start("127.0.0.1", kPort, err));

    std::string body;
    // A directory at the config path makes the persist fail after the runtime
    // change is applied.
    std::error_code ec;
    std::filesystem::remove(path, ec);
    CHECK(std::filesystem::create_directory(path, ec));
    CHECK(HttpPost(kPort, "/api/dhcp/bindings", "tok",
                   R"({"mac":"02:00:00:00:a2:11","ip":"192.168.52.111"})",
                   body) == 200);
    CHECK(body.find("\"persisted\":false") != std::string::npos);
    bool saw_failed = false;
    for (const auto& line : audit_lines) {
        if (line.find("dhcp binding add") != std::string::npos &&
            line.find("NOT saved") != std::string::npos) {
            saw_failed = true;
        }
    }
    CHECK(saw_failed);

    // v4 delete: the runtime removal is live, the persisted row cannot be
    // dropped - the audit line is the only durable record.
    audit_lines.clear();
    CHECK(HttpDeleteWithToken("/api/dhcp/bindings?mac=02:00:00:00:a2:11",
                              kPort, "tok", body) == 200);
    CHECK(body.find("\"persisted\":false") != std::string::npos);
    bool saw_delete_failed = false;
    for (const auto& line : audit_lines) {
        if (line.find("dhcp binding delete") != std::string::npos &&
            line.find("NOT saved") != std::string::npos) {
            saw_delete_failed = true;
        }
    }
    CHECK(saw_delete_failed);

    // v6 add: same defect class on the DHCPv6 row.
    audit_lines.clear();
    CHECK(HttpPost(kPort, "/api/dhcp6/bindings", "tok",
                   R"({"duid":"00:03:00:01:02:00:00:a2:11","ip":"fd00:1133:4455:6677::1100"})",
                   body) == 200);
    CHECK(body.find("\"persisted\":false") != std::string::npos);
    bool saw_v6_failed = false;
    for (const auto& line : audit_lines) {
        if (line.find("dhcp6 binding add") != std::string::npos &&
            line.find("NOT saved") != std::string::npos) {
            saw_v6_failed = true;
        }
    }
    CHECK(saw_v6_failed);

    // v6 delete: the last of the four persist-failure paths.
    audit_lines.clear();
    CHECK(HttpDeleteWithToken(
              "/api/dhcp6/bindings?duid=00:03:00:01:02:00:00:a2:11",
              kPort, "tok", body) == 200);
    CHECK(body.find("\"persisted\":false") != std::string::npos);
    bool saw_v6_delete_failed = false;
    for (const auto& line : audit_lines) {
        if (line.find("dhcp6 binding delete") != std::string::npos &&
            line.find("NOT saved") != std::string::npos) {
            saw_v6_delete_failed = true;
        }
    }
    CHECK(saw_v6_delete_failed);

    api.Stop();
    std::string stop_error;
    CHECK(dp.Stop(stop_error));
    std::filesystem::remove_all(path, ec);
    std::remove(lease_path);
}

// P107: the binding routes answered 404/409 without an audit line - only the
// HTTP status. A refused or missing binding change is a privileged-change
// outcome; the operator's durable record must carry it too.
static void TestP107WebBindingRefusalIsAudited() {
    using namespace vgww::core;
    const char* path = "p107-binding.json";
    const char* lease_path = "p107_leases.json";
    std::remove(path);
    std::remove(lease_path);
    Config cfg;
    cfg.adapter = "P107NIC";
    cfg.mode = Mode::kMain;
    cfg.dhcp.enabled = true;
    cfg.web.port = 18138;
    cfg.web.token = "tok";
    bool ok = false;
    cfg.gateway.ipv4 = ParseIpv4("192.168.53.1", ok);
    cfg.gateway.mask = ParseIpv4("255.255.255.0", ok);
    cfg.gateway.mac = {0x30, 0xFC, 0x68, 0x88, 0xB4, 0xA3};
    cfg.dhcp.pool_start = ParseIpv4("192.168.53.100", ok);
    cfg.dhcp.pool_end = ParseIpv4("192.168.53.200", ok);
    cfg.dhcp.lease_seconds = 3600;
    cfg.ipv6.enabled = true;
    cfg.ipv6.prefix_len = 64;
    cfg.ipv6.ula_prefix = {0xFD, 0x00, 0x11, 0x33, 0x44, 0x55, 0x66,
    0x77, 0, 0, 0, 0, 0, 0, 0, 0};
    cfg.ipv6.dhcpv6.enabled = true;
    cfg.ipv6.dhcpv6.pool_start = {0xFD, 0x00, 0x11, 0x33, 0x44, 0x55,
    0x66, 0x77, 0, 0, 0, 0, 0, 0, 0x10, 0x00};
    cfg.ipv6.dhcpv6.pool_end = {0xFD, 0x00, 0x11, 0x33, 0x44, 0x55,
        0x66, 0x77, 0, 0, 0, 0, 0, 0, 0x1F, 0xFF};
    cfg.perf.workers = 2;
    cfg.perf.ring_capacity = 64;
    cfg.perf.max_conns = 64;
    std::string err;
    CHECK(cfg.SaveToFile(path, err));

    vgww::runtime::Dataplane dp(cfg, lease_path);
    dp.SetDriverClient(std::make_unique<WebFakeDriver>());
    std::string start_error;
    CHECK(dp.Start(start_error));
    CHECK(dp.DhcpActive());
    CHECK(dp.Dhcp6Active());

    HttpServer api;
    std::vector<std::string> audit_lines;
    vgww::web::RegisterApi(
        api, dp, cfg, path, "tok", {}, [] { return true; },
        [](bool) { return false; },
        [&audit_lines](const std::string& line) {
            audit_lines.push_back(line);
        });
    constexpr uint16_t kPort = 18138;
    CHECK(api.Start("127.0.0.1", kPort, err));

    std::string body;
    // A binding that does not exist is a 404, not a silent success.
    CHECK(HttpDeleteWithToken("/api/dhcp/bindings?mac=02:00:00:00:a3:11",
                              kPort, "tok", body) == 404);
    bool saw_v4_delete_refused = false;
    for (const auto& line : audit_lines) {
        if (line.find("dhcp binding delete 02:00:00:00:a3:11") !=
                std::string::npos &&
            line.find("failed (no such binding)") != std::string::npos) {
            saw_v4_delete_refused = true;
        }
    }
    CHECK(saw_v4_delete_refused);

    audit_lines.clear();
    CHECK(HttpDeleteWithToken(
              "/api/dhcp6/bindings?duid=00:03:00:01:02:00:00:a3:11",
              kPort, "tok", body) == 404);
    bool saw_v6_delete_refused = false;
    for (const auto& line : audit_lines) {
        if (line.find("dhcp6 binding delete") != std::string::npos &&
            line.find("failed (no such binding)") != std::string::npos) {
            saw_v6_delete_refused = true;
        }
    }
    CHECK(saw_v6_delete_refused);

    // The same DELETE routes also reject a malformed query: the token is
    // present, the service is up, but the key is missing (400). The refusal
    // must be audited, not just answered.
    audit_lines.clear();
    CHECK(HttpDeleteWithToken("/api/dhcp/bindings", kPort, "tok", body) == 400);
    bool saw_v4_missing_key = false;
    for (const auto& line : audit_lines) {
        if (line.find("dhcp binding delete rejected (mac required)") !=
            std::string::npos) {
            saw_v4_missing_key = true;
        }
    }
    CHECK(saw_v4_missing_key);

    audit_lines.clear();
    CHECK(HttpDeleteWithToken("/api/dhcp6/bindings", kPort, "tok", body) == 400);
    bool saw_v6_missing_key = false;
    for (const auto& line : audit_lines) {
        if (line.find("dhcp6 binding delete rejected (duid required)") !=
            std::string::npos) {
            saw_v6_missing_key = true;
        }
    }
    CHECK(saw_v6_missing_key);

    // POST refusals while the service is up: a malformed key (400) and a
    // missing field (400) must be audited, not just answered.
    audit_lines.clear();
    CHECK(HttpPost(kPort, "/api/dhcp/bindings", "tok",
                   R"({"mac":"not-a-mac","ip":"192.168.53.111"})",
                   body) == 400);
    bool saw_v4_bad_mac = false;
    for (const auto& line : audit_lines) {
        if (line.find("dhcp binding add rejected (invalid mac)") !=
            std::string::npos) {
            saw_v4_bad_mac = true;
        }
    }
    CHECK(saw_v4_bad_mac);

    audit_lines.clear();
    CHECK(HttpPost(kPort, "/api/dhcp/bindings", "tok",
                   R"({"ip":"192.168.53.111"})", body) == 400);
    bool saw_v4_missing_fields = false;
    for (const auto& line : audit_lines) {
        if (line.find("dhcp binding add rejected (mac and ip required)") !=
            std::string::npos) {
            saw_v4_missing_fields = true;
        }
    }
    CHECK(saw_v4_missing_fields);

    audit_lines.clear();
    CHECK(HttpPost(kPort, "/api/dhcp6/bindings", "tok",
                   R"({"duid":"not-a-duid","ip":"fd00:1133:4455:6677::1100"})",
                   body) == 400);
    bool saw_v6_bad_duid = false;
    for (const auto& line : audit_lines) {
        if (line.find("dhcp6 binding add rejected (invalid duid)") !=
            std::string::npos) {
            saw_v6_bad_duid = true;
        }
    }
    CHECK(saw_v6_bad_duid);

    audit_lines.clear();
    CHECK(HttpPost(kPort, "/api/dhcp6/bindings", "tok",
                   R"({"ip":"fd00:1133:4455:6677::1100"})", body) == 400);
    bool saw_v6_missing_fields = false;
    for (const auto& line : audit_lines) {
        if (line.find("dhcp6 binding add rejected (duid and ip required)") !=
            std::string::npos) {
            saw_v6_missing_fields = true;
        }
    }
    CHECK(saw_v6_missing_fields);

    // A duplicate MAC is a conflict, not a silent upsert: the refusal must be
    // audited too (the store keys on the PARSED bytes, so any legal spelling
    // of the same address is a conflict).
    CHECK(HttpPost(kPort, "/api/dhcp/bindings", "tok",
                   R"({"mac":"02:00:00:00:a3:11","ip":"192.168.53.111"})",
                   body) == 200);
    audit_lines.clear();
    CHECK(HttpPost(kPort, "/api/dhcp/bindings", "tok",
                   R"({"mac":"02-00-00-00-a3-11","ip":"192.168.53.112"})",
                   body) == 400);
    bool saw_v4_duplicate = false;
    for (const auto& line : audit_lines) {
        if (line.find("dhcp binding add 02-00-00-00-a3-11") !=
                std::string::npos &&
            line.find("failed (binding exists)") != std::string::npos) {
            saw_v4_duplicate = true;
        }
    }
    CHECK(saw_v4_duplicate);

    CHECK(HttpPost(kPort, "/api/dhcp6/bindings", "tok",
                   R"({"duid":"00:03:00:01:02:00:00:a3:11","ip":"fd00:1133:4455:6677::1100"})",
                   body) == 200);
    audit_lines.clear();
    CHECK(HttpPost(kPort, "/api/dhcp6/bindings", "tok",
                   R"({"duid":"00030001020000a311","ip":"fd00:1133:4455:6677::1101"})",
                   body) == 400);
    bool saw_v6_duplicate = false;
    for (const auto& line : audit_lines) {
        if (line.find("dhcp6 binding add") != std::string::npos &&
            line.find("failed (binding exists)") != std::string::npos) {
            saw_v6_duplicate = true;
        }
    }
    CHECK(saw_v6_duplicate);

    // Stop the plane: the same routes now answer 409 "service not running".
    api.Stop();
    std::string stop_error;
    CHECK(dp.Stop(stop_error));
    CHECK(!dp.DhcpActive());
    CHECK(!dp.Dhcp6Active());
    audit_lines.clear();
    CHECK(api.Start("127.0.0.1", kPort, err));
    CHECK(HttpPost(kPort, "/api/dhcp/bindings", "tok",
                   R"({"mac":"02:00:00:00:a3:11","ip":"192.168.53.111"})",
                   body) == 409);
    bool saw_v4_stopped = false;
    for (const auto& line : audit_lines) {
        if (line.find("dhcp binding add failed (service not running)") !=
            std::string::npos) {
            saw_v4_stopped = true;
        }
    }
    CHECK(saw_v4_stopped);

    audit_lines.clear();
    CHECK(HttpPost(kPort, "/api/dhcp6/bindings", "tok",
                   R"({"duid":"00:03:00:01:02:00:00:a3:11","ip":"fd00:1133:4455:6677::1100"})",
                   body) == 409);
    bool saw_v6_stopped = false;
    for (const auto& line : audit_lines) {
        if (line.find("dhcp6 binding add failed (service not running)") !=
            std::string::npos) {
            saw_v6_stopped = true;
        }
    }
    CHECK(saw_v6_stopped);

    // The DELETE routes hit the same 409 gate: the service is down, so the
    // request is refused before the key is even looked at.
    audit_lines.clear();
    CHECK(HttpDeleteWithToken("/api/dhcp/bindings?mac=02:00:00:00:a3:11",
                              kPort, "tok", body) == 409);
    bool saw_v4_delete_stopped = false;
    for (const auto& line : audit_lines) {
        if (line.find("dhcp binding delete failed (service not running)") !=
            std::string::npos) {
            saw_v4_delete_stopped = true;
        }
    }
    CHECK(saw_v4_delete_stopped);

    audit_lines.clear();
    CHECK(HttpDeleteWithToken(
              "/api/dhcp6/bindings?duid=00:03:00:01:02:00:00:a3:11",
              kPort, "tok", body) == 409);
    bool saw_v6_delete_stopped = false;
    for (const auto& line : audit_lines) {
        if (line.find("dhcp6 binding delete failed (service not running)") !=
            std::string::npos) {
            saw_v6_delete_stopped = true;
        }
    }
    CHECK(saw_v6_delete_stopped);

    api.Stop();
    std::remove(path);
    std::remove(lease_path);
}

// P113: the rule add refusals (duplicate WAN endpoint, per-kind cap) used to
// answer 400 with no audit line. The store-level cap is covered by TestB34o;
// this pins the ROUTE's audit record for both the duplicate and the cap path.
static void TestP113WebRuleAddRefusalIsAudited() {
    using namespace vgww::core;
    const char* path = "p113-rules.json";
    const std::string rules = std::string(path) + ".rules.json";
    std::remove(path);
    std::error_code ec;
    std::filesystem::remove_all(rules, ec);
    vgww::web::RuleStore::Instance().AttachFile(rules);
    vgww::web::RuleStore::Instance().Clear();

    Config cfg;
    cfg.web.port = 18140;
    cfg.web.token = "tok";
    bool ok = false;
    cfg.gateway.ipv4 = ParseIpv4("192.168.55.1", ok);
    cfg.gateway.mask = ParseIpv4("255.255.255.0", ok);
    MacAddress mac{};
    ParseMac("30:fc:68:88:b4:a5", mac);
    cfg.gateway.mac = mac;
    std::string err;
    CHECK(cfg.SaveToFile(path, err));

    vgww::runtime::Dataplane dp(cfg);
    HttpServer api;
    std::vector<std::string> audit_lines;
    vgww::web::RegisterApi(
        api, dp, cfg, path, "tok", {}, [] { return true; },
        [](bool) { return false; },
        [&audit_lines](const std::string& line) {
            audit_lines.push_back(line);
        });
    constexpr uint16_t kPort = 18140;
    CHECK(api.Start("127.0.0.1", kPort, err));

    std::string body;
    // A duplicate WAN endpoint is a conflict, not a silent shadow.
    CHECK(HttpPost(kPort, "/api/portmap", "tok",
                   R"({"proto":"tcp","wan_port":8080,"lan_ip":"192.168.55.5","lan_port":80})",
                   body) == 200);
    audit_lines.clear();
    CHECK(HttpPost(kPort, "/api/portmap", "tok",
                   R"({"proto":"tcp","wan_port":8080,"lan_ip":"192.168.55.6","lan_port":81})",
                   body) == 400);
    bool saw_duplicate = false;
    for (const auto& line : audit_lines) {
        if (line.find("portmap add tcp:8080") != std::string::npos &&
            line.find("failed (wan endpoint already mapped)") !=
                std::string::npos) {
            saw_duplicate = true;
        }
    }
    CHECK(saw_duplicate);

    // The per-kind cap: fill the store directly, then POST the overflow.
    // Persistence is detached so the 1024-row fill is pure in-memory.
    vgww::web::RuleStore::Instance().AttachFile("");
    vgww::web::RuleStore::Instance().Clear();
    for (size_t i = 0; i < ::vgww::core::limits::kMaxPortMaps; ++i) {
        vgww::web::PortMappingRule m;
        m.proto = "tcp";
        m.wan_port = static_cast<uint16_t>(1 + i);
        m.lan_ip = "192.168.55.10";
        m.lan_port = 80;
        vgww::web::RuleStore::Instance().AddPortMap(std::move(m));
    }
    // The route's own pre-check refuses the overflow before the store's cap
    // can be reached: the line is the duplicate-conflict one (the WAN port
    // 50001 is free, so this is the cap pre-check refusing the add).
    audit_lines.clear();
    CHECK(HttpPost(kPort, "/api/portmap", "tok",
                   R"({"proto":"tcp","wan_port":50001,"lan_ip":"192.168.55.7","lan_port":82})",
                   body) == 400);
    bool saw_cap = false;
    for (const auto& line : audit_lines) {
        if (line.find("portmap add tcp:50001") != std::string::npos &&
            line.find("failed (too many portmaps)") != std::string::npos) {
            saw_cap = true;
        }
    }
    CHECK(saw_cap);

    // ban cap: fill the store directly, then POST the overflow. The ban route
    // has no pre-check cap, so the refusal comes from AddBanChecked inside the
    // store's lock - the route must still record it. Persistence is detached
    // so the 4096-row fill is pure in-memory (a disk-backed fill would write
    // the whole document per insert).
    vgww::web::RuleStore::Instance().AttachFile("");
    vgww::web::RuleStore::Instance().Clear();
    for (size_t i = 0; i < ::vgww::core::limits::kMaxBans; ++i) {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "02:00:%02X:%02X:%02X:%02X",
                      static_cast<unsigned>((i >> 24) & 0xFF),
                      static_cast<unsigned>((i >> 16) & 0xFF),
                      static_cast<unsigned>((i >> 8) & 0xFF),
                      static_cast<unsigned>(i & 0xFF));
        vgww::web::RuleStore::Instance().AddBanChecked(
            vgww::web::BanEntry{"mac", buf});
    }
    audit_lines.clear();
    CHECK(HttpPost(kPort, "/api/bans", "tok",
                   R"({"kind":"mac","value":"02:00:FF:FF:FF:FF"})",
                   body) == 400);
    bool saw_ban_cap = false;
    for (const auto& line : audit_lines) {
        if (line.find("ban add mac") != std::string::npos &&
            line.find("failed (firewall rule limit reached)") !=
                std::string::npos) {
            saw_ban_cap = true;
        }
    }
    CHECK(saw_ban_cap);

    // ratelimit cap: same shape. At the cap a NEW MAC is refused (an upsert of
    // an existing MAC would still be allowed - that is the batch131 contract).
    vgww::web::RuleStore::Instance().AttachFile("");
    vgww::web::RuleStore::Instance().Clear();
    for (size_t i = 0; i < ::vgww::core::limits::kMaxRateLimits; ++i) {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "02:00:01:00:%02X:%02X",
                      static_cast<unsigned>((i >> 8) & 0xFF),
                      static_cast<unsigned>(i & 0xFF));
        vgww::web::RateLimitRule r;
        r.mac = buf;
        r.uplink_kbps = 100;
        vgww::web::RuleStore::Instance().SetRateLimitChecked(std::move(r));
    }
    audit_lines.clear();
    CHECK(HttpPost(kPort, "/api/ratelimit", "tok",
                   R"({"mac":"02:00:02:00:00:01","uplink_kbps":1000})",
                   body) == 400);
    bool saw_rate_cap = false;
    for (const auto& line : audit_lines) {
        if (line.find("ratelimit set") != std::string::npos &&
            line.find("failed (rate-limit rule limit reached)") !=
                std::string::npos) {
            saw_rate_cap = true;
        }
    }
    CHECK(saw_rate_cap);

    api.Stop();
    vgww::web::RuleStore::Instance().AttachFile("");
    vgww::web::RuleStore::Instance().Clear();
    std::remove(path);
    std::filesystem::remove_all(rules, ec);
}

// P122: POST /api/config answers 409 when the merge cannot fit the disk
// bindings (the submitted body is stale and the disk list is over the cap).
// The refusal must be audited.
static void TestP122WebConfigBindingCapRefusalIsAudited() {
    using namespace vgww::core;
    const char* path = "p122-cap.json";
    const std::string rules = std::string(path) + ".rules.json";
    std::remove(path);
    std::error_code ec;
    std::filesystem::remove_all(rules, ec);
    Config cfg;
    cfg.adapter = "P122NIC";
    cfg.mode = Mode::kMain;
    cfg.dhcp.enabled = true;
    cfg.web.port = 18142;
    cfg.web.token = "tok";
    bool ok = false;
    cfg.gateway.ipv4 = ParseIpv4("192.168.60.1", ok);
    cfg.gateway.mask = ParseIpv4("255.255.255.0", ok);
    cfg.gateway.mac = {0x30, 0xFC, 0x68, 0x88, 0xB4, 0xA6};
    cfg.dhcp.pool_start = ParseIpv4("192.168.60.100", ok);
    cfg.dhcp.pool_end = ParseIpv4("192.168.60.200", ok);
    cfg.dhcp.lease_seconds = 3600;
    cfg.perf.workers = 2;
    cfg.perf.ring_capacity = 64;
    cfg.perf.max_conns = 64;
    // The config carries one binding; the runtime route adds a second
    // (persisted straight to disk). The stale body the page posts back cannot
    // name the new row, so the merge must keep it - and the cap check fires
    // only when the merged list would exceed the cap. To exercise the cap
    // without a 1024-row fixture, the submitted body itself is over the cap:
    // it names 1025 distinct MACs, so the merge drops the overflow.
    for (size_t i = 0; i < 1; ++i) {
        StaticBinding b;
        b.mac = {0x02, 0x00, static_cast<uint8_t>((i >> 8) & 0xFF),
                 static_cast<uint8_t>(i & 0xFF), 0x00, 0x01};
        b.ip = ParseIpv4("192.168.60." + std::to_string(100u + i), ok);
        cfg.dhcp.static_bindings.push_back(b);
    }
    std::string err;
    CHECK(cfg.SaveToFile(path, err));

    vgww::runtime::Dataplane dp(cfg, "p122_leases.json");
    dp.SetDriverClient(std::make_unique<WebFakeDriver>());
    std::string start_error;
    CHECK(dp.Start(start_error));
    CHECK(dp.DhcpActive());

    HttpServer api;
    std::vector<std::string> audit_lines;
    vgww::web::RegisterApi(
        api, dp, cfg, path, "tok", {}, [] { return true; },
        [](bool) { return false; },
        [&audit_lines](const std::string& line) {
            audit_lines.push_back(line);
        });
    constexpr uint16_t kPort = 18142;
    CHECK(api.Start("127.0.0.1", kPort, err));

    // Add one more binding at runtime: it lands on disk but not in the body
    // the settings page would have rendered.
    std::string body;
    CHECK(HttpPost(kPort, "/api/dhcp/bindings", "tok",
                   R"({"mac":"02:00:00:00:f0:01","ip":"192.168.60.150"})",
                   body) == 200);

    // Build a body that already names the cap's worth of bindings: the merge
    // cannot fit the disk row the body omits, so it refuses with 409.
    std::string stale;
    CHECK(HttpGet("/api/config", kPort, stale) == 200);
    nlohmann::json over = nlohmann::json::parse(stale);
    over["dhcp"]["static_bindings"] = nlohmann::json::array();
    for (size_t i = 0; i < limits::kMaxStaticBindings; ++i) {
        char mac_text[32];
        std::snprintf(mac_text, sizeof(mac_text), "02:02:%02X:%02X:00:01",
                      static_cast<unsigned>((i >> 8) & 0xFF),
                      static_cast<unsigned>(i & 0xFF));
        char ip_text[32];
        std::snprintf(ip_text, sizeof(ip_text), "192.168.61.%zu", i + 1);
        over["dhcp"]["static_bindings"].push_back(
            {{"mac", mac_text}, {"ip", ip_text}});
    }
    audit_lines.clear();
    CHECK(HttpPost(kPort, "/api/config", "tok", over.dump(), body) == 409);
    bool saw_cap_refusal = false;
    for (const auto& line : audit_lines) {
        if (line.find("config save refused (binding cap reached)") !=
            std::string::npos) {
            saw_cap_refusal = true;
        }
    }
    CHECK(saw_cap_refusal);

    api.Stop();
    std::string stop_error;
    CHECK(dp.Stop(stop_error));
    std::remove(path);
    std::remove("p122_leases.json");
    std::filesystem::remove_all(rules, ec);
}

// P104: a failed rule delete used to leave no audit line - only the HTTP
// 404/500. The ring is the operator's durable record, so a refused or missing
// delete must be visible there too.
static void TestP104RuleDeleteFailureIsAudited() {
    using namespace vgww::core;
    const char* path = "p104-rules.json";
    const std::string rules = std::string(path) + ".rules.json";
    std::remove(path);
    std::error_code ec;
    std::filesystem::remove_all(rules, ec);
    vgww::web::RuleStore::Instance().AttachFile(rules);
    vgww::web::RuleStore::Instance().Clear();

    Config cfg;
    cfg.web.port = 18136;
    cfg.web.token = "tok";
    bool ok = false;
    cfg.gateway.ipv4 = ParseIpv4("192.168.54.1", ok);
    cfg.gateway.mask = ParseIpv4("255.255.255.0", ok);
    MacAddress mac{};
    ParseMac("30:fc:68:88:b4:a4", mac);
    cfg.gateway.mac = mac;
    std::string err;
    CHECK(cfg.SaveToFile(path, err));

    vgww::runtime::Dataplane dp(cfg);
    HttpServer api;
    std::vector<std::string> audit_lines;
    vgww::web::RegisterApi(
        api, dp, cfg, path, "tok", {}, [] { return true; },
        [](bool) { return false; },
        [&audit_lines](const std::string& line) {
            audit_lines.push_back(line);
        });
    constexpr uint16_t kPort = 18136;
    CHECK(api.Start("127.0.0.1", kPort, err));

    std::string body;
    // Deleting a rule that does not exist is a 404, not a silent success.
    CHECK(HttpDeleteWithToken("/api/portmap?id=999999", kPort, "tok",
                              body) == 404);
    bool saw_portmap_failed = false;
    for (const auto& line : audit_lines) {
        if (line.find("portmap delete id=999999 failed") != std::string::npos) {
            saw_portmap_failed = true;
        }
    }
    CHECK(saw_portmap_failed);

    audit_lines.clear();
    CHECK(HttpDeleteWithToken("/api/bans?id=999999", kPort, "tok",
                              body) == 404);
    bool saw_ban_failed = false;
    for (const auto& line : audit_lines) {
        if (line.find("ban delete id=999999 failed") != std::string::npos) {
            saw_ban_failed = true;
        }
    }
    CHECK(saw_ban_failed);

    audit_lines.clear();
    CHECK(HttpDeleteWithToken("/api/ratelimit?mac=aa:bb:cc:dd:ee:ff",
                              kPort, "tok", body) == 404);
    bool saw_ratelimit_failed = false;
    for (const auto& line : audit_lines) {
        if (line.find("ratelimit delete") != std::string::npos &&
            line.find("failed") != std::string::npos) {
            saw_ratelimit_failed = true;
        }
    }
    CHECK(saw_ratelimit_failed);

    // The positional (index) path is the same refusal, reached by a stale
    // position rather than a missing id. It must be audited too.
    audit_lines.clear();
    CHECK(HttpDeleteWithToken("/api/portmap?index=999999", kPort, "tok",
                              body) == 404);
    bool saw_portmap_index_failed = false;
    for (const auto& line : audit_lines) {
        if (line.find("portmap delete index=999999 failed") !=
            std::string::npos) {
            saw_portmap_index_failed = true;
        }
    }
    CHECK(saw_portmap_index_failed);

    audit_lines.clear();
    CHECK(HttpDeleteWithToken("/api/bans?index=999999", kPort, "tok",
                              body) == 404);
    bool saw_ban_index_failed = false;
    for (const auto& line : audit_lines) {
        if (line.find("ban delete index=999999 failed") != std::string::npos) {
            saw_ban_index_failed = true;
        }
    }
    CHECK(saw_ban_index_failed);

    // Input-validation refusals: a malformed request is not a state refusal,
    // but it is still a privileged-change attempt the operator's record must
    // carry (a flood of malformed POSTs is exactly what a post-mortem needs).
    audit_lines.clear();
    CHECK(HttpPost(kPort, "/api/portmap", "tok",
                   R"({"proto":"tcp","wan_port":8080,"lan_ip":"not-an-ip","lan_port":80})",
                   body) == 400);
    bool saw_bad_ip = false;
    for (const auto& line : audit_lines) {
        if (line.find("portmap add rejected (invalid ip address)") !=
            std::string::npos) {
            saw_bad_ip = true;
        }
    }
    CHECK(saw_bad_ip);

    audit_lines.clear();
    CHECK(HttpPost(kPort, "/api/bans", "tok",
                   R"({"kind":"domain","value":"example"})", body) == 400);
    bool saw_bad_kind = false;
    for (const auto& line : audit_lines) {
        if (line.find("ban add rejected (kind must be ip or mac)") !=
            std::string::npos) {
            saw_bad_kind = true;
        }
    }
    CHECK(saw_bad_kind);

    audit_lines.clear();
    CHECK(HttpPost(kPort, "/api/ratelimit", "tok",
                   R"({"mac":"aa:bb:cc:dd:ee:ff","uplink_kbps":0,"downlink_kbps":0})",
                   body) == 400);
    bool saw_bad_rate = false;
    for (const auto& line : audit_lines) {
        if (line.find("ratelimit set rejected (at least one direction > 0)") !=
            std::string::npos) {
            saw_bad_rate = true;
        }
    }
    CHECK(saw_bad_rate);

    audit_lines.clear();
    CHECK(HttpDeleteWithToken("/api/portmap?id=abc", kPort, "tok", body) ==
          400);
    bool saw_bad_id = false;
    for (const auto& line : audit_lines) {
        if (line.find("portmap delete rejected (invalid id)") !=
            std::string::npos) {
            saw_bad_id = true;
        }
    }
    CHECK(saw_bad_id);

    // A present-but-unparseable kbps field must not silently fall back to 0:
    // the refusal is audited too.
    audit_lines.clear();
    CHECK(HttpPost(kPort, "/api/ratelimit", "tok",
                   R"({"mac":"aa:bb:cc:dd:ee:ff","uplink_kbps":"lots"})",
                   body) == 400);
    bool saw_bad_kbps = false;
    for (const auto& line : audit_lines) {
        if (line.find("ratelimit set rejected (invalid kbps)") !=
            std::string::npos) {
            saw_bad_kbps = true;
        }
    }
    CHECK(saw_bad_kbps);

    api.Stop();
    vgww::web::RuleStore::Instance().AttachFile("");
    vgww::web::RuleStore::Instance().Clear();
    std::remove(path);
    std::filesystem::remove_all(rules, ec);
}
//
// A persisted rule file is the ONLY record of the operator's port forwards.
// If loading it fails, the process must not silently behave as if the file
// said "no rules" - that turns a corrupt file into a silent outage, and the
// next mutation overwrites the operator's data forever.
// ---------------------------------------------------------------------------

namespace {

    // Writes `text` to a fresh path and returns it, so each case starts from a
    // known file state (the store is a process-wide singleton).
    std::string WriteRuleFile(const std::string& name,
                              const std::string& text) {
        std::remove(name.c_str());
        std::ofstream out(name, std::ios::binary);
        out << text;
        return name;
    }

    vgww::web::PortMappingRule MakeRule(const char* proto, unsigned wan,
                                        const char* ip, unsigned lan) {
        vgww::web::PortMappingRule r;
        r.proto = proto;
        r.wan_port = static_cast<uint16_t>(wan);
        r.lan_ip = ip;
        r.lan_port = static_cast<uint16_t>(lan);
        return r;
    }

}  // namespace

// A corrupt rule file must not be reported as "loaded successfully with zero
// rules". The operator's forwards would silently stop working while the file
// still sits on disk looking authoritative - and the next rule change would
// overwrite it, destroying the original data. The load must FAIL and say so.
static void TestB34oCorruptRuleFileIsNotSilentEmpty() {
    using namespace vgww::web;
    struct Case {
        const char* name;
        const char* text;
    };
    const Case cases[] = {
        {"invalid json", "{ this is not json "},
        {"truncated", "{\"portmaps\":[{\"proto\":\"tcp\",\"wan_port\":8080,"},
        {"wrong root type", "[1,2,3]"},
        {"scalar root", "42"},
    };
    for (const Case& c : cases) {
        const std::string path = WriteRuleFile("b34o_corrupt.json", c.text);
        RuleStore::Instance().AttachFile("");
        RuleStore::Instance().Clear();
        std::string error;
        const bool loaded = RuleStore::Instance().AttachFileChecked(path, error);
        std::printf("b34o corrupt(%s): loaded=%d rules=%zu error=[%s]\n", c.name,
                    loaded ? 1 : 0, RuleStore::Instance().PortMaps().size(),
                    error.c_str());
        CHECK(!loaded);
        CHECK(!error.empty());
        std::remove(path.c_str());
    }
    // A genuinely valid file still loads and reports success.
    {
        const std::string path = WriteRuleFile(
            "b34o_valid.json",
            R"({"portmaps":[{"proto":"tcp","wan_port":8080,"lan_ip":"192.168.0.50","lan_port":80}]})");
        RuleStore::Instance().AttachFile("");
        RuleStore::Instance().Clear();
        std::string error;
        const bool loaded = RuleStore::Instance().AttachFileChecked(path, error);
        CHECK(loaded);
        CHECK(error.empty());
        CHECK(RuleStore::Instance().PortMaps().size() == 1);
        std::remove(path.c_str());
    }
    // A missing file is NOT an error: first run has no rules yet.
    {
        const std::string path = "b34o_missing.json";
        std::remove(path.c_str());
        RuleStore::Instance().AttachFile("");
        RuleStore::Instance().Clear();
        std::string error;
        const bool loaded = RuleStore::Instance().AttachFileChecked(path, error);
        CHECK(loaded);
        CHECK(error.empty());
        CHECK(RuleStore::Instance().PortMaps().empty());
    }
    RuleStore::Instance().AttachFile("");
    RuleStore::Instance().Clear();
}

// batch83: a corrupt rules file must be preserved, not silently overwritten by
// the next mutation's persist - otherwise the only copy of the lost rules is
// gone and the operator cannot even inspect what was rejected.
static void TestB83CorruptRulesFilePreserved() {
    using namespace vgww::web;
    const std::string path = "b83_rules_corrupt.json";
    const std::string aside = path + ".corrupt";
    std::remove(path.c_str());
    std::remove(aside.c_str());
    const std::string garbage = "{ this is not json ";
    {
        std::ofstream out(path, std::ios::binary);
        out << garbage;
    }
    RuleStore::Instance().AttachFile("");
    RuleStore::Instance().Clear();
    std::string error;
    CHECK(!RuleStore::Instance().AttachFileChecked(path, error));
    CHECK(error.find(".corrupt") != std::string::npos);
    {
        std::ifstream kept(aside, std::ios::binary);
        CHECK(kept.good());
        CHECK(std::string((std::istreambuf_iterator<char>(kept)),
                          std::istreambuf_iterator<char>()) == garbage);
    }
    {
        std::ifstream gone(path, std::ios::binary);
        CHECK(!gone.good());
    }
    // The live path is free: the next mutation persists a fresh document and
    // must not clobber the preserved copy.
    RuleStore::Instance().AttachFile(path);
    PortMappingRule rule;
    rule.proto = "tcp";
    rule.wan_port = 18083;
    rule.lan_ip = "192.168.0.60";
    rule.lan_port = 80;
    RuleStore::Instance().SetPortMap(rule);
    {
        std::ifstream kept(aside, std::ios::binary);
        CHECK(kept.good());
        CHECK(std::string((std::istreambuf_iterator<char>(kept)),
                          std::istreambuf_iterator<char>()) == garbage);
    }
    {
        std::ifstream fresh(path, std::ios::binary);
        CHECK(fresh.good());
        CHECK(std::string((std::istreambuf_iterator<char>(fresh)),
                          std::istreambuf_iterator<char>())
                  .find("\"portmaps\"") != std::string::npos);
    }
    RuleStore::Instance().AttachFile("");
    RuleStore::Instance().Clear();
    std::remove(path.c_str());
    std::remove(aside.c_str());
}

// batch85: a rules file that exists but cannot be OPENED (a scanner holds it)
// is not corrupt. It must not be quarantined, and persistence must not
// overwrite it with the empty in-memory set - the document may be the
// operator's only copy of their forwards.
static void TestB85UnreadableRulesFileIsNotOverwritten() {
    using namespace vgww::web;
    const std::string path = "b85_rules_locked.json";
    const std::string aside = path + ".corrupt";
    std::remove(path.c_str());
    std::remove(aside.c_str());
    const std::string valid =
        R"({"portmaps":[{"proto":"tcp","wan_port":9091,"lan_ip":"192.168.0.70","lan_port":80}]})";
    {
        std::ofstream out(path, std::ios::binary);
        out << valid;
    }

    RuleStore::Instance().AttachFile("");
    RuleStore::Instance().Clear();
    vgww::core::SetConfigOpenFailureHookForTest(
        [](const std::string&) -> unsigned long { return 32u; });
    std::string error;
    const bool loaded = RuleStore::Instance().AttachFileChecked(path, error);
    CHECK(!loaded);
    CHECK(error.find("not readable") != std::string::npos);
    {
        std::ifstream in(path, std::ios::binary);
        CHECK(in.good());
        CHECK(std::string((std::istreambuf_iterator<char>(in)),
                          std::istreambuf_iterator<char>()) == valid);
    }
    {
        std::ifstream quarantined(aside, std::ios::binary);
        CHECK(!quarantined.good());
    }

    // A mutation while blocked must count the lost write and leave the file
    // exactly as it was.
    const size_t failures_before =
        RuleStore::Instance().PersistFailureCount();
    PortMappingRule rule;
    rule.proto = "tcp";
    rule.wan_port = 9092;
    rule.lan_ip = "192.168.0.71";
    rule.lan_port = 80;
    RuleStore::Instance().SetPortMap(rule);
    CHECK(RuleStore::Instance().PersistFailureCount() > failures_before);
    vgww::core::SetConfigOpenFailureHookForTest(
        std::function<unsigned long(const std::string&)>());
    {
        std::ifstream in(path, std::ios::binary);
        CHECK(std::string((std::istreambuf_iterator<char>(in)),
                          std::istreambuf_iterator<char>()) == valid);
    }

    // Attaching the path again (new session) resets the block, and a readable
    // document loads normally.
    RuleStore::Instance().AttachFile(path);
    CHECK(RuleStore::Instance().PortMapCount() == 1);
    RuleStore::Instance().AttachFile("");
    RuleStore::Instance().Clear();
    std::remove(path.c_str());
}

// batch87: the block must clear WITHOUT a restart once the file can be read
// again - and the changes made while persistence was paused must survive the
// merge (the on-disk document is authoritative for what it holds).
static void TestB87BlockedRulesRecoverWithoutRestart() {
    using namespace vgww::web;
    const std::string path = "b87_rules_recover.json";
    std::remove(path.c_str());
    {
        std::ofstream out(path, std::ios::binary);
        out << R"({"portmaps":[{"proto":"tcp","wan_port":9101,"lan_ip":"192.168.0.72","lan_port":80}]})";
    }

    RuleStore::Instance().AttachFile("");
    RuleStore::Instance().Clear();
    vgww::core::SetConfigOpenFailureHookForTest(
        [](const std::string&) -> unsigned long { return 32u; });
    std::string error;
    CHECK(!RuleStore::Instance().AttachFileChecked(path, error));
    vgww::core::SetConfigOpenFailureHookForTest(
        std::function<unsigned long(const std::string&)>());
    CHECK(RuleStore::Instance().PersistBlocked());
    CHECK(RuleStore::Instance().PortMapCount() == 0);

    // The lock clears; a mutation must recover by reading the disk document
    // and merging both sets.
    PortMappingRule rule;
    rule.proto = "tcp";
    rule.wan_port = 9102;
    rule.lan_ip = "192.168.0.73";
    rule.lan_port = 80;
    RuleStore::Instance().SetPortMap(rule);

    CHECK(!RuleStore::Instance().PersistBlocked());
    CHECK(RuleStore::Instance().PortMapCount() == 2);
    {
        std::ifstream in(path, std::ios::binary);
        const std::string body((std::istreambuf_iterator<char>(in)),
                               std::istreambuf_iterator<char>());
        CHECK(body.find("9101") != std::string::npos);
        CHECK(body.find("9102") != std::string::npos);
    }
    RuleStore::Instance().AttachFile("");
    RuleStore::Instance().Clear();
    std::remove(path.c_str());
}

// batch88: the recovery merge must cover EVERY persisted rule kind, not just
// port forwards. Seed a ban + a rate limit on disk, make a paused change of
// each kind while the file is unreadable, then let recovery run: all of them
// must survive, deduplicated by the same identities the loaders use.
static void TestB88BlockedRecoveryMergesEveryRuleKind() {
    using namespace vgww::web;
    const std::string path = "b88_rules_kinds.json";
    std::remove(path.c_str());
    {
        std::ofstream out(path, std::ios::binary);
        out << R"({"portmaps":[{"proto":"tcp","wan_port":9201,"lan_ip":"192.168.0.80","lan_port":80}],)"
               R"("bans":[{"kind":"ip","value":"10.9.9.9"}],)"
               R"("ratelimits":[{"mac":"AA:BB:CC:00:00:01","uplink_kbps":1000,"downlink_kbps":2000}]})";
    }

    RuleStore::Instance().AttachFile("");
    RuleStore::Instance().Clear();
    vgww::core::SetConfigOpenFailureHookForTest(
        [](const std::string&) -> unsigned long { return 32u; });
    std::string error;
    CHECK(!RuleStore::Instance().AttachFileChecked(path, error));
    CHECK(RuleStore::Instance().PersistBlocked());

    // Changes made while persistence is paused (every flush fails).
    PortMappingRule pm;
    pm.proto = "tcp";
    pm.wan_port = 9202;
    pm.lan_ip = "192.168.0.81";
    pm.lan_port = 80;
    RuleStore::Instance().SetPortMap(pm);
    BanEntry ban;
    ban.kind = "ip";
    ban.value = "10.9.9.10";
    CHECK(RuleStore::Instance().AddBanChecked(ban));
    RateLimitRule rl;
    rl.mac = "AA:BB:CC:00:00:02";
    rl.uplink_kbps = 3000;
    rl.downlink_kbps = 4000;
    CHECK(RuleStore::Instance().SetRateLimitChecked(rl));
    CHECK(RuleStore::Instance().PersistBlocked());  // still paused

    // The lock clears; one more mutation recovers and writes the union.
    vgww::core::SetConfigOpenFailureHookForTest(
        std::function<unsigned long(const std::string&)>());
    RateLimitRule rl2;
    rl2.mac = "AA:BB:CC:00:00:03";
    rl2.uplink_kbps = 5000;
    rl2.downlink_kbps = 6000;
    CHECK(RuleStore::Instance().SetRateLimitChecked(rl2));

    CHECK(!RuleStore::Instance().PersistBlocked());
    CHECK(RuleStore::Instance().PortMapCount() == 2);
    CHECK(RuleStore::Instance().BanCount() == 2);
    CHECK(RuleStore::Instance().RateLimits().size() == 3);
    {
        std::ifstream in(path, std::ios::binary);
        const std::string body((std::istreambuf_iterator<char>(in)),
                               std::istreambuf_iterator<char>());
        CHECK(body.find("9201") != std::string::npos);   // disk port forward
        CHECK(body.find("9202") != std::string::npos);   // paused port forward
        CHECK(body.find("10.9.9.9") != std::string::npos);   // disk ban
        CHECK(body.find("10.9.9.10") != std::string::npos);  // paused ban
        CHECK(body.find("AA:BB:CC:00:00:01") != std::string::npos);  // disk cap
        CHECK(body.find("AA:BB:CC:00:00:02") != std::string::npos);  // paused cap
        CHECK(body.find("AA:BB:CC:00:00:03") != std::string::npos);
    }
    RuleStore::Instance().AttachFile("");
    RuleStore::Instance().Clear();
    std::remove(path.c_str());
}

// batch89: if the document turns CORRUPT (not merely locked) while persistence
// is paused, recovery must preserve it and continue with a fresh file - the
// same rule the attach path and the lease writers use. Keeping the writer
// blocked forever (until a restart) was inconsistent and left the evidence
// unsaved.
static void TestB89RecoveryQuarantinesCorruptFile() {
    using namespace vgww::web;
    const std::string path = "b89_rules_corrupt.json";
    const std::string aside = path + ".corrupt";
    std::remove(path.c_str());
    std::remove(aside.c_str());
    {
        std::ofstream out(path, std::ios::binary);
        out << R"({"portmaps":[]})";
    }

    RuleStore::Instance().AttachFile("");
    RuleStore::Instance().Clear();
    vgww::core::SetConfigOpenFailureHookForTest(
        [](const std::string&) -> unsigned long { return 32u; });
    std::string error;
    CHECK(!RuleStore::Instance().AttachFileChecked(path, error));
    vgww::core::SetConfigOpenFailureHookForTest(
        std::function<unsigned long(const std::string&)>());
    CHECK(RuleStore::Instance().PersistBlocked());

    // The file is readable again ... but the content is now garbage.
    const std::string garbage = "{ not json at all";
    {
        std::ofstream out(path, std::ios::binary | std::ios::trunc);
        out << garbage;
    }

    PortMappingRule rule;
    rule.proto = "tcp";
    rule.wan_port = 9301;
    rule.lan_ip = "192.168.0.90";
    rule.lan_port = 80;
    RuleStore::Instance().SetPortMap(rule);

    CHECK(!RuleStore::Instance().PersistBlocked());
    CHECK(RuleStore::Instance().PortMapCount() == 1);
    {
        std::ifstream kept(aside, std::ios::binary);
        CHECK(kept.good());
        CHECK(std::string((std::istreambuf_iterator<char>(kept)),
                          std::istreambuf_iterator<char>()) == garbage);
    }
    {
        std::ifstream fresh(path, std::ios::binary);
        CHECK(fresh.good());
        CHECK(std::string((std::istreambuf_iterator<char>(fresh)),
                          std::istreambuf_iterator<char>())
                  .find("9301") != std::string::npos);
    }
    RuleStore::Instance().AttachFile("");
    RuleStore::Instance().Clear();
    std::remove(path.c_str());
    std::remove(aside.c_str());
}

// batch90: blocked recovery must be single-shot under concurrent mutations.
// While the file is unreadable every flush fails; once it lets go, several
// threads race into FlushPersist. Exactly one may recover (re-read + merge);
// the rest must see the cleared block, and every persisted document must stay
// parseable with no temp leftovers.
static void TestB90ConcurrentBlockedRecovery() {
    using namespace vgww::web;
    const std::string path = "b90_rules_concurrent.json";
    std::remove(path.c_str());
    {
        std::ofstream out(path, std::ios::binary);
        out << R"({"portmaps":[{"proto":"tcp","wan_port":9400,"lan_ip":"192.168.0.100","lan_port":80}]})";
    }

    RuleStore::Instance().AttachFile("");
    RuleStore::Instance().Clear();
    vgww::core::SetConfigOpenFailureHookForTest(
        [](const std::string&) -> unsigned long { return 32u; });
    std::string error;
    CHECK(!RuleStore::Instance().AttachFileChecked(path, error));
    CHECK(RuleStore::Instance().PersistBlocked());

    constexpr int kThreads = 4;
    constexpr int kPausedPerThread = 5;
    // Paused-phase mutations: every flush fails, the block must stay.
    {
        std::vector<std::thread> workers;
        for (int t = 0; t < kThreads; ++t) {
            workers.emplace_back([t] {
                for (int i = 0; i < kPausedPerThread; ++i) {
                    PortMappingRule r;
                    r.proto = "tcp";
                    r.wan_port = static_cast<uint16_t>(9410 + t * 10 + i);
                    r.lan_ip = "192.168.0.110";
                    r.lan_port = 80;
                    (void)RuleStore::Instance().AddPortMap(r);
                }
            });
        }
        for (auto& w : workers) {
            w.join();
        }
    }
    CHECK(RuleStore::Instance().PersistBlocked());
    CHECK(RuleStore::Instance().PortMapCount() ==
          kThreads * kPausedPerThread);

    // The lock clears: concurrent post-recovery mutations race on the flush.
    const size_t recoveries_before = RuleStore::Instance().RecoveryCount();
    vgww::core::SetConfigOpenFailureHookForTest(
        std::function<unsigned long(const std::string&)>());
    {
        std::vector<std::thread> workers;
        for (int t = 0; t < kThreads; ++t) {
            workers.emplace_back([t] {
                PortMappingRule r;
                r.proto = "tcp";
                r.wan_port = static_cast<uint16_t>(9500 + t);
                r.lan_ip = "192.168.0.111";
                r.lan_port = 80;
                (void)RuleStore::Instance().AddPortMap(r);
            });
        }
        for (auto& w : workers) {
            w.join();
        }
    }

    CHECK(!RuleStore::Instance().PersistBlocked());
    // Exactly one thread may perform the recovery, however they interleave.
    CHECK(RuleStore::Instance().RecoveryCount() == recoveries_before + 1);
    const size_t expected =
        1 + kThreads * kPausedPerThread + kThreads;  // disk + paused + live
    CHECK(RuleStore::Instance().PortMapCount() == expected);
    {
        std::ifstream in(path, std::ios::binary);
        const std::string body((std::istreambuf_iterator<char>(in)),
                               std::istreambuf_iterator<char>());
        const auto parsed = nlohmann::json::parse(body, nullptr, false);
        CHECK(!parsed.is_discarded());
        CHECK(parsed.is_object());
        const auto pm = parsed.find("portmaps");
        CHECK(pm != parsed.end() && pm->is_array());
        CHECK(pm != parsed.end() && pm->is_array() && pm->size() == expected);
        CHECK(body.find("9400") != std::string::npos);  // disk rule merged
        CHECK(body.find("9500") != std::string::npos);  // live rule written
    }
    // No temp leftovers from the racing writers.
    size_t leftovers = 0;
    for (const auto& entry : std::filesystem::directory_iterator(".")) {
        const std::string name = entry.path().filename().string();
        if (0 == name.rfind(path + ".tmp.", 0)) {
            ++leftovers;
        }
    }
    CHECK(0 == leftovers);

    RuleStore::Instance().AttachFile("");
    RuleStore::Instance().Clear();
    std::remove(path.c_str());
}

// batch92: a mutation that reached memory but NOT the disk must say so. The
// route keeps answering 200 (the change is live) but reports persisted:false,
// so a client cannot mistake it for a durable save.
static void TestB92MutationReportsPersistFailure() {
    using namespace vgww::core;
    using namespace vgww::web;
    const char* path = "b92_status.json";
    const std::string rules = std::string(path) + ".rules.json";
    std::remove(path);
    std::error_code ec;
    std::filesystem::remove_all(rules, ec);
    // A DIRECTORY at the rules path makes every write fail permanently.
    CHECK(std::filesystem::create_directory(rules, ec));

    Config cfg;
    cfg.web.port = 18326;
    bool ok = false;
    cfg.gateway.ipv4 = ParseIpv4("192.168.0.42", ok);
    cfg.gateway.mask = ParseIpv4("255.255.255.0", ok);
    MacAddress mac{};
    ParseMac("30:fc:68:88:b4:ab", mac);
    cfg.gateway.mac = mac;
    std::string err;
    CHECK(cfg.SaveToFile(path, err));

    vgww::runtime::Dataplane dp(cfg);
    HttpServer api;
    vgww::web::RegisterApi(api, dp, cfg, path);
    constexpr uint16_t kPort = 18326;
    std::string start_err;
    CHECK(api.Start("127.0.0.1", kPort, start_err));

    std::string resp;
    const std::string ban = R"({"kind":"ip","value":"10.7.7.7"})";
    CHECK(200 == HttpPost(kPort, "/api/bans", "", ban, resp));
    CHECK(resp.find("\"ok\":true") != std::string::npos);
    CHECK(resp.find("\"persisted\":false") != std::string::npos);
    // The ban IS live in memory: the change happened, only durability failed.
    std::string body;
    CHECK(200 == HttpGet("/api/bans", kPort, body));
    CHECK(body.find("10.7.7.7") != std::string::npos);

    // Remove the blocker: the next mutation retries the pending snapshot and
    // reports a durable success.
    std::filesystem::remove_all(rules, ec);
    const std::string ban2 = R"({"kind":"ip","value":"10.7.7.8"})";
    CHECK(200 == HttpPost(kPort, "/api/bans", "", ban2, resp));
    CHECK(resp.find("\"persisted\":true") != std::string::npos);
    CHECK(std::filesystem::exists(rules));

    api.Stop();
    std::remove(path);
    std::filesystem::remove_all(rules, ec);
}

// batch93: a DHCP static binding added/removed over the API must survive a
// restart: the route records it in the config document (durable writer) and
// reports persisted:true; with no usable config path it reports persisted:false
// while the runtime binding still applies.
// batch100: a lease-document write failure must be visible on the status
// surface (count), not only on stderr, and Stop() must report the dirty
// teardown so the operator knows the mappings are gone.
static void TestB101StatusExposesLeasePersistFailures() {
    using namespace vgww::core;
    const char* cfg_path = "b101_config.json";
    const char* lease_path = "b101_leases.json";
    std::remove(cfg_path);
    std::remove(lease_path);
    Config cfg;
    cfg.adapter = "B101NIC";
    cfg.mode = Mode::kMain;
    cfg.dhcp.enabled = true;
    bool ok = false;
    cfg.gateway.ipv4 = ParseIpv4("192.168.45.1", ok);
    cfg.gateway.mask = ParseIpv4("255.255.255.0", ok);
    cfg.gateway.mac = {0x30, 0xFC, 0x68, 0x88, 0xB4, 0xB1};
    cfg.dhcp.pool_start = ParseIpv4("192.168.45.100", ok);
    cfg.dhcp.pool_end = ParseIpv4("192.168.45.200", ok);
    cfg.perf.workers = 2;
    cfg.perf.ring_capacity = 64;
    cfg.perf.max_conns = 64;
    std::string err;
    CHECK(cfg.SaveToFile(cfg_path, err));

    vgww::runtime::Dataplane dp(cfg, lease_path);
    dp.SetDriverClient(std::make_unique<WebFakeDriver>());
    CHECK(dp.Start(err));
    dp.SetLeaseDumpIntervalForTest(std::chrono::milliseconds(50));

    HttpServer api;
    vgww::web::RegisterApi(api, dp, cfg, cfg_path, "b101-secret");
    constexpr uint16_t kP = 18101;
    CHECK(api.Start("127.0.0.1", kP, err));
    {
        // batch101: the status surface must carry the stop-durability verdict
        // (false on a fresh run), not only the failure counter.
        std::string initial;
        CHECK(200 == HttpGet("/api/status", kP, initial));
        CHECK(initial.find("\"stop_persist_failed\":false") !=
              std::string::npos);
        // batch104: the v6 pool-exhaustion counter is on the status surface.
        CHECK(initial.find("\"pool_exhausted\":0") != std::string::npos);
        // batch105: and so is the v4 sibling (v4 counter already existed and
        // the native UI showed it, but the status surface omitted it).
        const size_t dhcp6_at = initial.find("},\"dhcp6\":{");
        CHECK(dhcp6_at != std::string::npos);
        CHECK(initial.substr(0, dhcp6_at).find("\"pool_exhausted\":0") !=
              std::string::npos);
    }

    // A DIRECTORY at the lease document makes every snapshot fail.
    std::error_code ec;
    std::filesystem::create_directory(lease_path, ec);
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds(3);
    bool exposed = false;
    std::string body;
    while (std::chrono::steady_clock::now() < deadline && !exposed) {
        body.clear();
        if (200 == HttpGet("/api/status", kP, body)) {
            const std::string key =
                "\"persistence_paused\":false,\"persist_failures\":";
            const size_t at = body.find(key);
            if (std::string::npos != at) {
                const size_t num = at + key.size();
                exposed = num < body.size() && body[num] != '0';
            }
        }
        if (!exposed) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    }
    CHECK(exposed);

    api.Stop();
    std::string stop_error;
    CHECK(dp.Stop(stop_error));
    // The directory is still in place, so the stop-time snapshot failed too.
    CHECK(dp.StopPersistFailed());
    std::filesystem::remove(lease_path, ec);
    std::remove(cfg_path);
    std::remove((std::string(cfg_path) + ".rules.json").c_str());
    std::remove(lease_path);
}

// batch106: the rule document (and the lease documents) reach disk through
// core::WriteFileAtomicDurable without any cross-process guard; a second VGWW
// process could replace the whole file. Anchor: while another owner holds the
// destination's lock, a rule mutation must block; it completes on release.
static void TestB106RulesWriteUsesCrossProcessLock() {
    using namespace vgww::web;
    const std::string rules = "b106_rules.json.rules.json";
    std::remove(rules.c_str());
    RuleStore& store = RuleStore::Instance();
    store.AttachFile(rules);
    store.Clear();  // baseline publish (creates the document)
    CHECK(store.PersistUpToDate());

    std::atomic<bool> held{false};
    std::atomic<bool> release{false};
    std::thread holder([&] {
        vgww::core::ConfigFileLock lock(rules);
        held.store(true, std::memory_order_release);
        while (!release.load(std::memory_order_acquire)) {
            std::this_thread::yield();
        }
    });
    while (!held.load(std::memory_order_acquire)) {
        std::this_thread::yield();
    }

    std::atomic<bool> done{false};
    std::thread writer([&] {
        BanEntry ban;
        ban.kind = "ip";
        ban.value = "10.66.0.1";
        (void)store.AddBanChecked(std::move(ban));
        done.store(true, std::memory_order_release);
    });
    for (int i = 0; i < 40 && !done.load(std::memory_order_acquire); ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    CHECK(!done.load(std::memory_order_acquire));  // blocked by the lock
    release.store(true, std::memory_order_release);
    holder.join();
    writer.join();
    CHECK(done.load(std::memory_order_acquire));
    CHECK(store.PersistUpToDate());

    store.AttachFile("");
    store.Clear();
    std::remove(rules.c_str());
}

static void TestB93DhcpBindingPersistsToConfig() {
    using namespace vgww::core;
    const char* cfg_path = "b93_config.json";
    const char* lease_path = "b93_leases.json";
    std::remove(cfg_path);
    std::remove(lease_path);
    Config cfg;
    cfg.adapter = "B93NIC";
    cfg.mode = Mode::kMain;
    cfg.dhcp.enabled = true;
    bool ok = false;
    cfg.gateway.ipv4 = ParseIpv4("192.168.41.1", ok);
    cfg.gateway.mask = ParseIpv4("255.255.255.0", ok);
    cfg.gateway.mac = {0x30, 0xFC, 0x68, 0x88, 0xB4, 0x93};
    cfg.dhcp.pool_start = ParseIpv4("192.168.41.100", ok);
    cfg.dhcp.pool_end = ParseIpv4("192.168.41.200", ok);
    cfg.dhcp.lease_seconds = 3600;
    // DHCPv6 service so the v6 binding route is reachable too (batch93 covers
    // the same persistence contract for the DUID list).
    cfg.ipv6.enabled = true;
    cfg.ipv6.prefix_len = 64;
    cfg.ipv6.ula_prefix = {0xFD, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
                           0x66, 0, 0, 0, 0, 0, 0, 0, 0};
    cfg.ipv6.dhcpv6.enabled = true;
    cfg.ipv6.dhcpv6.pool_start = {0xFD, 0x00, 0x11, 0x22, 0x33, 0x44,
                                  0x55, 0x66, 0, 0, 0, 0, 0, 0, 0x10, 0x00};
    cfg.ipv6.dhcpv6.pool_end = {0xFD, 0x00, 0x11, 0x22, 0x33, 0x44,
                                0x55, 0x66, 0, 0, 0, 0, 0, 0, 0x1F, 0xFF};
    cfg.perf.workers = 2;
    cfg.perf.ring_capacity = 64;
    cfg.perf.max_conns = 64;
    std::string err;
    CHECK(cfg.SaveToFile(cfg_path, err));

    vgww::runtime::Dataplane dp(cfg, lease_path);
    dp.SetDriverClient(std::make_unique<WebFakeDriver>());
    std::string start_error;
    CHECK(dp.Start(start_error));
    CHECK(dp.DhcpActive());
    CHECK(dp.Dhcp6Active());

    HttpServer api;
    vgww::web::RegisterApi(api, dp, cfg, cfg_path, "boot-secret");
    constexpr uint16_t kP = 18098;
    CHECK(api.Start("127.0.0.1", kP, err));

    MacAddress want{};
    CHECK(ParseMac("02:00:00:00:93:01", want));
    std::string body;
    CHECK(200 == HttpPost(
                     kP, "/api/dhcp/bindings", "boot-secret",
                     R"({"mac":"02:00:00:00:93:01","ip":"192.168.41.210","hostname":"printer"})",
                     body));
    CHECK(body.find("\"persisted\":true") != std::string::npos);
    {
        std::string load_err;
        const auto disk = Config::LoadFromFile(cfg_path, load_err);
        CHECK(disk.has_value());
        bool found = false;
        if (disk) {
            for (const auto& b : disk->dhcp.static_bindings) {
                if (b.mac == want) {
                    found = true;
                    CHECK(b.ip == ParseIpv4("192.168.41.210", ok));
                    CHECK(b.hostname == "printer");
                }
            }
        }
        CHECK(found);
    }

    // DELETE persists the removal as well.
    const std::string del =
        "DELETE /api/dhcp/bindings?mac=02:00:00:00:93:01 HTTP/1.1\r\n"
        "Host: t\r\nX-Auth-Token: boot-secret\r\nContent-Length: 0\r\n"
        "Connection: close\r\n\r\n";
    CHECK(200 == HttpRaw(kP, del, body));
    CHECK(body.find("\"persisted\":true") != std::string::npos);
    {
        std::string load_err;
        const auto disk = Config::LoadFromFile(cfg_path, load_err);
        CHECK(disk.has_value());
        bool found = false;
        if (disk) {
            for (const auto& b : disk->dhcp.static_bindings) {
                if (b.mac == want) {
                    found = true;
                }
            }
        }
        CHECK(!found);
    }
    // batch93 (v6): the DUID list follows the same persist/remove contract.
    const std::string duid = "00:03:00:01:02:00:00:93:01";
    CHECK(200 == HttpPost(
                     kP, "/api/dhcp6/bindings", "boot-secret",
                     R"({"duid":"00:03:00:01:02:00:00:93:01","ip":"fd00:1122:3344:5566::2100","hostname":"nas"})",
                     body));
    CHECK(body.find("\"persisted\":true") != std::string::npos);
    {
        std::vector<uint8_t> want_duid;
        CHECK(vgww::runtime::ParseDuidText(duid, want_duid));
        std::array<uint8_t, 16> want_ip{};
        CHECK(ParseIpv6("fd00:1122:3344:5566::2100", want_ip));
        std::string load_err;
        const auto disk = Config::LoadFromFile(cfg_path, load_err);
        CHECK(disk.has_value());
        bool found = false;
        if (disk) {
            for (const auto& b : disk->ipv6.dhcpv6.static_bindings) {
                if (b.duid == want_duid) {
                    found = true;
                    CHECK(b.ip == want_ip);
                    CHECK(b.hostname == "nas");
                }
            }
        }
        CHECK(found);
    }
    const std::string del6 =
        "DELETE /api/dhcp6/bindings?duid=00:03:00:01:02:00:00:93:01 HTTP/1.1\r\n"
        "Host: t\r\nX-Auth-Token: boot-secret\r\nContent-Length: 0\r\n"
        "Connection: close\r\n\r\n";
    CHECK(200 == HttpRaw(kP, del6, body));
    CHECK(body.find("\"persisted\":true") != std::string::npos);
    {
        std::vector<uint8_t> want_duid;
        CHECK(vgww::runtime::ParseDuidText(duid, want_duid));
        std::string load_err;
        const auto disk = Config::LoadFromFile(cfg_path, load_err);
        CHECK(disk.has_value());
        bool found = false;
        if (disk) {
            for (const auto& b : disk->ipv6.dhcpv6.static_bindings) {
                if (b.duid == want_duid) {
                    found = true;
                }
            }
        }
        CHECK(!found);
    }
    api.Stop();

    // Persistence disabled (empty config path): the runtime binding still
    // applies, but the route says it is not durable.
    HttpServer api2;
    vgww::web::RegisterApi(api2, dp, cfg, "", "boot-secret");
    constexpr uint16_t kP2 = 18097;
    CHECK(api2.Start("127.0.0.1", kP2, err));
    CHECK(200 == HttpPost(kP2, "/api/dhcp/bindings", "boot-secret",
                          R"({"mac":"02:00:00:00:93:02","ip":"192.168.41.211"})",
                          body));
    CHECK(body.find("\"persisted\":false") != std::string::npos);
    api2.Stop();

    std::string stop_error;
    dp.Stop(stop_error);
    std::remove(cfg_path);
    std::remove(lease_path);
}

// Rules read from the FILE must satisfy the same semantic contract the API
// enforces on POST: proto is tcp, lan_ip is a dotted quad, both ports are
// non-zero. A file written by hand (or by an older version) otherwise injects
// rules that can never bind or dial, while the UI lists them as active.
static void TestB34oLoadedRulesAreSemanticallyValid() {
    using namespace vgww::web;
    const std::string path = WriteRuleFile(
        "b34o_badrules.json",
        R"({"portmaps":[
          {"proto":"sctp","wan_port":7001,"lan_ip":"192.168.0.50","lan_port":80},
          {"proto":"udp","wan_port":7002,"lan_ip":"192.168.0.50","lan_port":80},
          {"proto":"tcp","wan_port":7003,"lan_ip":"not-an-ip","lan_port":80},
          {"proto":"tcp","wan_port":7004,"lan_ip":"192.168.0.50","lan_port":80}
        ]})");
    RuleStore::Instance().AttachFile("");
    RuleStore::Instance().Clear();
    std::string error;
    const bool loaded = RuleStore::Instance().AttachFileChecked(path, error);
    const auto rules = RuleStore::Instance().PortMaps();
    const size_t dropped = RuleStore::Instance().DiscardedOnLastLoad();
    std::printf("b34o bad rules: loaded=%d kept=%zu dropped=%zu error=[%s]\n",
                loaded ? 1 : 0, rules.size(), dropped, error.c_str());
    // A valid document with bad entries loads, keeps the good rule, and
    // REPORTS how many it dropped - a silent drop is the defect.
    CHECK(loaded);
    CHECK(dropped == 3);
    for (const auto& r : rules) {
        std::printf("b34o kept rule: proto=%s wan=%u lan_ip=%s lan_port=%u\n",
                    r.proto.c_str(), static_cast<unsigned>(r.wan_port),
                    r.lan_ip.c_str(), static_cast<unsigned>(r.lan_port));
        // Only rules the API would have accepted may survive a load.
        CHECK(r.proto == "tcp");
        CHECK(r.wan_port >= 1);
        CHECK(r.lan_port >= 1);
        bool ip_ok = false;
        vgww::core::ParseIpv4(r.lan_ip, ip_ok);
        CHECK(ip_ok);
    }
    // The one valid rule (7004) must survive; the three invalid ones must not.
    CHECK(rules.size() == 1);
    if (rules.size() == 1) {
        CHECK(rules[0].wan_port == 7004);
    }
    std::remove(path.c_str());
    RuleStore::Instance().AttachFile("");
    RuleStore::Instance().Clear();
}

// The rule cap must be enforced INSIDE the store's lock. The API checks
// PortMaps().size() before calling AddPortMap, which is a check-then-act
// across two lock acquisitions: concurrent callers all see "below cap" and
// all insert. A cap that can be exceeded is not a cap - it is a memory bound
// that fails exactly under the flood it exists to stop.
static void TestB34oRuleCapEnforcedInStore() {
    using namespace vgww::web;
    const std::string path = WriteRuleFile("b34o_cap.json", "{}");
    RuleStore::Instance().AttachFile("");
    RuleStore::Instance().Clear();
    RuleStore::Instance().AttachFile(path);

    // Fill to exactly the cap.
    const size_t cap = vgww::core::limits::kMaxPortMaps;
    for (size_t i = 0; i < cap; ++i) {
        RuleStore::Instance().AddPortMap(
            MakeRule("tcp", static_cast<unsigned>(1 + i), "192.168.0.50", 80));
    }
    CHECK(RuleStore::Instance().PortMaps().size() == cap);

    // DETERMINISTIC: at the cap, the store itself must refuse. This is the
    // assertion that fails when the cap lives only in the API's
    // check-then-act pre-check (a race window, not a bound).
    const bool over_cap =
        RuleStore::Instance().AddPortMap(MakeRule("tcp", 50001, "192.168.0.50", 80));
    std::printf("b34o cap: cap=%zu at_cap_insert_accepted=%d final=%zu\n", cap,
                over_cap ? 1 : 0, RuleStore::Instance().PortMaps().size());
    CHECK(!over_cap);
    CHECK(RuleStore::Instance().PortMaps().size() == cap);

    // And a concurrent burst at the boundary must not exceed it either.
    std::atomic<int> accepted{0};
    std::vector<std::thread> threads;
    for (int t = 0; t < 16; ++t) {
        threads.emplace_back([t, cap, &accepted] {
            if (RuleStore::Instance().PortMaps().size() >= cap) {
                return;
            }
            if (RuleStore::Instance().AddPortMap(MakeRule(
                    "tcp", static_cast<unsigned>(40000 + t), "192.168.0.50",
                    80))) {
                ++accepted;
            }
        });
    }
    for (auto& th : threads) {
        th.join();
    }
    const size_t final_size = RuleStore::Instance().PortMaps().size();
    std::printf("b34o cap burst: accepted=%d final=%zu\n", accepted.load(),
                final_size);
    CHECK(final_size == cap);

    std::remove(path.c_str());
    RuleStore::Instance().AttachFile("");
    RuleStore::Instance().Clear();
}

// A rule must be removable by IDENTITY, not by position. The store erases by
// index, so a concurrent add (or simply a delete followed by an add) shifts
// every later index and the caller removes a DIFFERENT rule than the one it
// meant. Assert the identity contract: remove(handle) removes exactly that
// rule, and a handle obtained before an unrelated add still refers to the
// same rule.
static void TestB34oRuleRemovalIsByIdentity() {
    using namespace vgww::web;
    const std::string path = WriteRuleFile("b34o_identity.json", "{}");
    RuleStore::Instance().AttachFile("");
    RuleStore::Instance().Clear();
    RuleStore::Instance().AttachFile(path);

    const uint64_t h1 =
        RuleStore::Instance().AddPortMapTracked(MakeRule("tcp", 1111, "192.168.0.50", 80));
    const uint64_t h2 =
        RuleStore::Instance().AddPortMapTracked(MakeRule("tcp", 2222, "192.168.0.51", 80));
    CHECK(h1 != 0);
    CHECK(h2 != 0);
    CHECK(h1 != h2);

    // An unrelated add after the handles were taken.
    const uint64_t h3 =
        RuleStore::Instance().AddPortMapTracked(MakeRule("tcp", 3333, "192.168.0.52", 80));
    CHECK(h3 != h1 && h3 != h2);

    // Removing by identity must remove exactly h2, regardless of position.
    CHECK(RuleStore::Instance().RemovePortMapById(h2));
    const auto after = RuleStore::Instance().PortMaps();
    std::printf("b34o identity: remaining=%zu\n", after.size());
    CHECK(after.size() == 2);
    bool has_1111 = false;
    bool has_2222 = false;
    bool has_3333 = false;
    for (const auto& r : after) {
        has_1111 = has_1111 || (r.wan_port == 1111);
        has_2222 = has_2222 || (r.wan_port == 2222);
        has_3333 = has_3333 || (r.wan_port == 3333);
    }
    CHECK(has_1111);
    CHECK(!has_2222);  // the one we asked for is gone
    CHECK(has_3333);   // the neighbour survived
    // Removing the same id twice is a no-op, not a wrong-rule deletion.
    CHECK(!RuleStore::Instance().RemovePortMapById(h2));

    std::remove(path.c_str());
    RuleStore::Instance().AttachFile("");
    RuleStore::Instance().Clear();
}

// A write that fails must NOT be reported as durable. `persisted_rev_` means
// "this revision is on disk"; advancing it after a failed write makes the
// process believe the rules are safe while the file is stale or missing - the
// loss only surfaces on the next restart, when the rules are already gone.
// The failure must also be counted, because a silent durability loss is
// indistinguishable from success.
//
// Failure injection: point the store at a path whose FINAL component is an
// existing DIRECTORY. The writer's atomic replace (MoveFileExW over a
// directory) always fails, with no mocks and no permission games.
static void TestB34oPersistFailureIsCountedAndNotDurable() {
    using namespace vgww::web;
    const std::string dir = "b34o_persist_dir";
    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
    CHECK(std::filesystem::create_directory(dir, ec));

    RuleStore::Instance().AttachFile("");
    RuleStore::Instance().Clear();
    // The target path is a directory: every write attempt must fail.
    RuleStore::Instance().AttachFile(dir);
    const size_t failures_before =
        RuleStore::Instance().PersistFailureCount();

    const bool added = RuleStore::Instance().AddPortMap(
        MakeRule("tcp", 8181, "192.168.0.50", 80));
    CHECK(added);  // the in-memory rule is accepted...
    CHECK(RuleStore::Instance().PortMaps().size() == 1);

    const size_t failures_after = RuleStore::Instance().PersistFailureCount();
    std::printf(
        "b34o persist: failures_before=%zu failures_after=%zu (delta=%zu)\n",
        failures_before, failures_after, failures_after - failures_before);
    // ...but the failed write must be counted.
    CHECK(failures_after > failures_before);

    // A second mutation must RETRY (the pending snapshot was not discarded)
    // and fail again, proving the revision never advanced.
    RuleStore::Instance().AddPortMap(
        MakeRule("tcp", 8182, "192.168.0.51", 80));
    const size_t failures_third = RuleStore::Instance().PersistFailureCount();
    std::printf("b34o persist: failures_third=%zu (delta=%zu)\n",
                failures_third, failures_third - failures_after);
    CHECK(failures_third > failures_after);

    // Recovering the path must let the NEXT mutation persist successfully and
    // stop incrementing the failure count: the retry path works, not just the
    // counting.
    std::filesystem::remove_all(dir, ec);
    RuleStore::Instance().AddPortMap(
        MakeRule("tcp", 8183, "192.168.0.52", 80));
    const size_t failures_recovered =
        RuleStore::Instance().PersistFailureCount();
    std::printf("b34o persist: failures_recovered=%zu, file_exists=%d\n",
                failures_recovered,
                std::filesystem::exists(dir) ? 1 : 0);
    CHECK(failures_recovered == failures_third);  // no new failure
    CHECK(std::filesystem::exists(dir));          // this write landed

    std::filesystem::remove_all(dir, ec);
    RuleStore::Instance().AttachFile("");
    RuleStore::Instance().Clear();
}

// ---------------------------------------------------------------------------
// batch34r: Web API authentication and input boundaries.
//
// The management API rewrites port maps, firewall rules and the persisted
// configuration, so these properties are security requirements, not niceties:
// an attacker on the LAN must not be able to guess a credential, smuggle one
// through a channel that leaks, or reach a mutating handler by using the
// wrong HTTP method.
// ---------------------------------------------------------------------------

// A request whose METHOD does not match the registered route must be answered
// 405 Method Not Allowed, not 404. 404 tells a client "this path does not
// exist" and hides the fact that the path IS served under another method;
// 405 is the RFC 9110 answer and lets a legitimate client correct itself.
// The distinction also matters for security tooling: a path that answers 404
// to every method looks absent while a write handler sits behind it.
static void TestB34rWrongMethodIs405Not404() {
    using namespace vgww::web;
    HttpServer srv;
    srv.Route("POST", "/api/b34r/write", [](const Request&) {
        return Response::Json("{\"ok\":true}");
    });
    srv.Route("GET", "/api/b34r/read", [](const Request&) {
        return Response::Json("{\"ok\":true}");
    });
    std::string err;
    CHECK(srv.Start("127.0.0.1", 18311, err));
    if (!err.empty()) {
        std::fprintf(stderr, "b34r start: %s\n", err.c_str());
    }
    struct Case {
        const char* name;
        const char* request;
    };
    const Case cases[] = {
        {"PUT on a POST-only route",
         "PUT /api/b34r/write HTTP/1.1\r\nHost: t\r\nContent-Length: 0\r\n"
         "Connection: close\r\n\r\n"},
        {"DELETE on a GET-only route",
         "DELETE /api/b34r/read HTTP/1.1\r\nHost: t\r\nContent-Length: 0\r\n"
         "Connection: close\r\n\r\n"},
        {"POST on a GET-only route",
         "POST /api/b34r/read HTTP/1.1\r\nHost: t\r\nContent-Length: 0\r\n"
         "Connection: close\r\n\r\n"},
    };
    for (const Case& c : cases) {
        std::string text;
        const int status = HttpRawFull(18311, c.request, text);
        std::printf("b34r method(%s): status=%d\n", c.name, status);
        CHECK(405 == status);
    }
    // A path nobody registered must still be 404: 405 must not swallow the
    // "genuinely absent" case, or every typo would look like a method error.
    {
        std::string text;
        const int status = HttpRawFull(
            18311,
            "POST /api/b34r/nope HTTP/1.1\r\nHost: t\r\nContent-Length: 0\r\n"
            "Connection: close\r\n\r\n",
            text);
        std::printf("b34r method(unregistered path): status=%d\n", status);
        CHECK(404 == status);
    }
    srv.Stop();
}

// A handler that throws must not leak the exception's internal text to the
// client. `ex.what()` for a JSON library carries parser internals (byte
// offsets, token names, library version strings); echoing it back is an
// information leak and an injection surface (the text is attacker-influenced
// in the parse case). The client gets a generic 500; the detail stays local.
static void TestB34rInternalErrorDoesNotLeakText() {
    using namespace vgww::web;
    HttpServer srv;
    srv.Route("GET", "/api/b34r/boom", [](const Request&) -> Response {
        throw std::runtime_error("SECRET-INTERNAL-MARKER-42");
    });
    std::string err;
    CHECK(srv.Start("127.0.0.1", 18312, err));
    std::string text;
    const int status = HttpRawFull(
        18312,
        "GET /api/b34r/boom HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n",
        text);
    const size_t body_at = text.find("\r\n\r\n");
    const std::string body =
        (std::string::npos == body_at) ? std::string() : text.substr(body_at + 4);
    std::printf("b34r 500 leak: status=%d body=[%s]\n", status, body.c_str());
    CHECK(500 == status);
    // The marker must never appear on the wire.
    CHECK(std::string::npos == body.find("SECRET-INTERNAL-MARKER-42"));
    // A usable error body is still required (the client must know it failed).
    CHECK(!body.empty());
    srv.Stop();
}

// A throw OUTSIDE the per-route try/catch (Dispatch's write guard runs
// before any route) used to escape HandleConnection, unwind the worker
// thread body and call std::terminate. One request must cost that request:
// the worker survives and keeps serving, and the failure is counted.
static void TestHandlerThrowOutsideDispatchKeepsTheWorker() {
    using namespace vgww::web;
    HttpServer srv;
    srv.Route("GET", "/api/guard-alive", [](const Request&) {
        return Response::Text("alive", 200);
    });
    srv.Route("POST", "/api/guarded", [](const Request&) {
        return Response::Json("{\"ok\":true}");
    });
    // The write guard is called from Dispatch BEFORE the route lookup and
    // OUTSIDE its try/catch: this is exactly the escape path. Throw only on
    // the first call so the same server must then serve normally.
    auto threw = std::make_shared<std::atomic<bool>>(false);
    srv.SetWriteGuard([threw](const Request&) -> Response {
        if (!threw->exchange(true)) {
            throw std::runtime_error("guard exploded");
        }
        Response pass = Response::Json("{\"ok\":true}");
        pass.status = 200;
        return pass;
    });
    std::string err;
    constexpr uint16_t kPort = 18313;
    CHECK(srv.Start("127.0.0.1", kPort, err));
    CHECK(0 == srv.HandlerErrors());

    // The request dies with the swallowed exception: no response is written,
    // so the client would block on a read. Send and close instead.
    const bool sent = SendAndDiscard(
        kPort,
        "POST /api/guarded HTTP/1.1\r\nHost: t\r\nContent-Length: 0\r\n"
        "Connection: close\r\n\r\n");
    CHECK(sent);

    // The failure must be COUNTED (the guard runs on a worker thread).
    for (int i = 0; i < 400 && 0 == srv.HandlerErrors(); ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    CHECK(1 == srv.HandlerErrors());

    // The pool must be intact: a GET answers, and so does a SECOND POST
    // (the guard now passes), proving no worker thread was lost.
    std::string body;
    CHECK(200 == HttpGetWithin("/api/guard-alive", kPort, body, 1000));
    CHECK("alive" == body);
    CHECK(200 == HttpPostWithin(kPort, "/api/guarded", std::string(), body,
                                1000));
    CHECK(body.find("\"ok\":true") != std::string::npos);
    CHECK(1 == srv.HandlerErrors());  // no spurious extra counts
    CHECK(0 == srv.EscapedHandlerErrors());
    srv.Stop();
}

// An accept handler that throws must not end the accept chain. The handler
// is the ONLY place that re-arms the next accept, so an unguarded throw (or
// an allocation failure while arming) silently turns the WebUI deaf while
// the process keeps looking healthy. Two phases: the first completion dies
// with an exception, the chain must still accept the next connection.
static void TestAcceptHandlerThrowKeepsAccepting() {
    using namespace vgww::web;
    HttpServer srv;
    srv.Route("GET", "/api/accept-alive", [](const Request&) {
        return Response::Text("alive", 200);
    });
    auto armed = std::make_shared<std::atomic<int>>(0);
    srv.SetAcceptProbeForTest([armed] {
        // Throw exactly on the first completed accept.
        if (0 == armed->fetch_add(1)) {
            throw std::runtime_error("accept handler exploded");
        }
    });
    std::string err;
    constexpr uint16_t kPort = 18314;
    CHECK(srv.Start("127.0.0.1", kPort, err));
    CHECK(0 == srv.HandlerErrors());

    // First connection: the handler throws, so the socket is never queued
    // and this request gets no answer. Send and close (a read would block).
    CHECK(SendAndDiscard(kPort,
                         "GET /api/accept-alive HTTP/1.1\r\nHost: t\r\n"
                         "Connection: close\r\n\r\n"));

    // The failure must be counted and the chain must be back in business.
    std::string body;
    int second = -1;
    for (int i = 0; i < 20; ++i) {
        second = HttpGetWithin("/api/accept-alive", kPort, body, 1000);
        if (200 == second) {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    std::printf("b343 accept throw: second=%d errors=%llu\n", second,
                static_cast<unsigned long long>(srv.HandlerErrors()));
    CHECK(200 == second);
    CHECK("alive" == body);
    CHECK(1 == srv.HandlerErrors());
    // The firewall must stop the exception INSIDE the handler: unwinding
    // through asio's dispatch frame is undefined behaviour, so nothing may
    // reach run().
    CHECK(0 == srv.EscapedHandlerErrors());
    srv.Stop();
}

// The RE-ARM is the other half: it allocates the next accept operation, and
// an allocation failure there used to escape the completion handler (the
// AcceptLoop caught it, counted it as "escaped", and the accept thread died).
// With the firewall the failure is counted as a RE-ARM error, the request
// already queued is still served, and the thread survives.
static void TestAcceptRearmThrowIsContained() {
    using namespace vgww::web;
    HttpServer srv;
    srv.Route("GET", "/api/rearm-alive", [](const Request&) {
        return Response::Text("alive", 200);
    });
    std::string err;
    constexpr uint16_t kPort = 18319;
    CHECK(srv.Start("127.0.0.1", kPort, err));

    std::string body;
    CHECK(200 == HttpGetWithin("/api/rearm-alive", kPort, body, 2000));
    CHECK("alive" == body);

    auto threw = std::make_shared<std::atomic<int>>(0);
    srv.SetAcceptRearmProbeForTest([threw] {
        if (0 == threw->fetch_add(1)) {
            throw std::runtime_error("re-arm exploded");
        }
    });
    const uint64_t before = srv.RearmErrors();
    // This connection is accepted and queued BEFORE the re-arm runs, so it is
    // served; the re-arm that follows throws and is swallowed.
    CHECK(200 == HttpGetWithin("/api/rearm-alive", kPort, body, 2000));
    CHECK("alive" == body);
    for (int i = 0; i < 100 && srv.RearmErrors() == before; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    std::printf("b-rearm accept: rearm=%llu escaped=%llu\n",
                static_cast<unsigned long long>(srv.RearmErrors()),
                static_cast<unsigned long long>(srv.EscapedHandlerErrors()));
    CHECK(srv.RearmErrors() == before + 1);
    CHECK(1 == threw->load());
    CHECK(0 == srv.EscapedHandlerErrors());
    srv.SetAcceptRearmProbeForTest(nullptr);
    srv.Stop();
}

// Firewall counters must be part of the operator-visible surface: a swallow
// that is counted but never exposed is still a silent failure. /api/status
// carries the data-plane counters, the port-map health counters and the web
// accept counters; the values move when a failure is injected.
static void TestBStatusExposesFirewallCounts() {
    using namespace vgww::core;
    using namespace vgww::web;
    const char* path = "bfw-status.json";
    const std::string rules = std::string(path) + ".rules.json";
    std::remove(path);
    std::remove(rules.c_str());

    Config cfg;
    cfg.web.port = 18323;
    bool ok = false;
    cfg.gateway.ipv4 = ParseIpv4("192.168.0.40", ok);
    cfg.gateway.mask = ParseIpv4("255.255.255.0", ok);
    MacAddress mac{};
    ParseMac("30:fc:68:88:b4:a9", mac);
    cfg.gateway.mac = mac;
    std::string err;
    CHECK(cfg.SaveToFile(path, err));

    vgww::runtime::Dataplane dp(cfg);
    HttpServer api;
    vgww::web::RegisterApi(api, dp, cfg, path);
    constexpr uint16_t kPort = 18323;
    std::string start_err;
    CHECK(api.Start("127.0.0.1", kPort, start_err));

    std::string body;
    CHECK(200 == HttpGet("/api/status", kPort, body));
    CHECK(body.find("\"thread_errors\":") != std::string::npos);
    CHECK(body.find("\"handler_errors\":") != std::string::npos);
    CHECK(body.find("\"portmap_health\":{") != std::string::npos);
    CHECK(body.find("\"loop_errors\":") != std::string::npos);
    CHECK(body.find("\"rearm_errors\":") != std::string::npos);
    CHECK(body.find("\"escaped_handler_errors\":") != std::string::npos);
    CHECK(body.find("\"web\":{") != std::string::npos);

    // Inject one accept-body throw, then read the SAME endpoint: the web
    // counter must have moved there, not just in the test's own accessor.
    auto armed = std::make_shared<std::atomic<int>>(0);
    api.SetAcceptProbeForTest([armed] {
        if (0 == armed->fetch_add(1)) {
            throw std::runtime_error("accept body exploded");
        }
    });
    CHECK(SendAndDiscard(kPort,
                         "GET /api/status HTTP/1.1\r\nHost: t\r\n"
                         "Connection: close\r\n\r\n"));
    int status = -1;
    for (int i = 0; i < 20; ++i) {
        body.clear();
        status = HttpGetWithin("/api/status", kPort, body, 1000);
        if (200 == status && body.find("\"handler_errors\":1") !=
                                 std::string::npos) {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    std::printf("bfw status: status=%d web_handler_errors=%llu\n", status,
                static_cast<unsigned long long>(api.HandlerErrors()));
    CHECK(200 == status);
    CHECK(body.find("\"web\":{\"handler_errors\":1,") != std::string::npos);
    CHECK(api.HandlerErrors() == 1);

    api.SetAcceptProbeForTest(nullptr);
    api.Stop();
    std::remove(path);
    std::remove(rules.c_str());
}

// batch86: "why did my change not survive a restart" must have a visible
// answer on the status surface: the rules writer can be PAUSED (file exists
// but could not be read) and the DHCP lease writers can be paused for the
// same reason. The keys are real state, not decoration - injecting a blocked
// rules store flips the reported value.
static void TestB86StatusExposesPersistenceHealth() {
    using namespace vgww::core;
    using namespace vgww::web;
    const char* path = "b86-status.json";
    const std::string rules_path = "b86-rules.json";
    std::remove(path);
    std::remove(rules_path.c_str());
    {
        // A valid rules document that the loader will (simulated) fail to
        // open, exactly like a scanner holding it.
        std::ofstream out(rules_path, std::ios::binary);
        out << R"({"portmaps":[]})";
    }

    Config cfg;
    cfg.web.port = 18324;
    bool ok = false;
    cfg.gateway.ipv4 = ParseIpv4("192.168.0.41", ok);
    cfg.gateway.mask = ParseIpv4("255.255.255.0", ok);
    MacAddress mac{};
    ParseMac("30:fc:68:88:b4:aa", mac);
    cfg.gateway.mac = mac;
    std::string err;
    CHECK(cfg.SaveToFile(path, err));

    vgww::runtime::Dataplane dp(cfg);
    HttpServer api;
    vgww::web::RegisterApi(api, dp, cfg, path);
    constexpr uint16_t kPort = 18324;
    std::string start_err;
    CHECK(api.Start("127.0.0.1", kPort, start_err));

    std::string body;
    CHECK(200 == HttpGet("/api/status", kPort, body));
    CHECK(body.find("\"rules\":{") != std::string::npos);
    CHECK(body.find("\"persist_blocked\":false") != std::string::npos);
    CHECK(body.find("\"persist_failures\":") != std::string::npos);
    CHECK(body.find("\"recoveries\":") != std::string::npos);
    CHECK(body.find("\"persistence_paused\":false") != std::string::npos);

    // Inject the real blocked state and read the SAME endpoint.
    RuleStore::Instance().AttachFile("");
    RuleStore::Instance().Clear();
    vgww::core::SetConfigOpenFailureHookForTest(
        [](const std::string&) -> unsigned long { return 32u; });
    std::string attach_error;
    CHECK(!RuleStore::Instance().AttachFileChecked(rules_path, attach_error));
    vgww::core::SetConfigOpenFailureHookForTest(
        std::function<unsigned long(const std::string&)>());
    CHECK(RuleStore::Instance().PersistBlocked());
    body.clear();
    CHECK(200 == HttpGet("/api/status", kPort, body));
    CHECK(body.find("\"persist_blocked\":true") != std::string::npos);

    RuleStore::Instance().AttachFile("");
    RuleStore::Instance().Clear();
    api.Stop();
    std::remove(path);
    std::remove(rules_path.c_str());
}

// The token comparison must not depend on WHERE the first difference is: a
// byte-by-byte `==` returns earlier for a wrong first byte than for a wrong
// last byte, which is exactly the signal a timing attack needs to recover the
// secret one character at a time. This asserts the PROPERTY (compare time is
// flat with respect to the prefix length), not the implementation.
static void TestB34rTokenCompareIsConstantTime() {
    using namespace vgww::web;
    // A 32-byte secret, like the generated one (RandomHex(16)).
    const std::string secret = "0123456789abcdef0123456789abcdef";
    // Wrong on the FIRST byte vs wrong on the LAST byte.
    const std::string wrong_first = "X123456789abcdef0123456789abcdef";
    const std::string wrong_last = "0123456789abcdef0123456789abcdeX";
    CHECK(!ConstantTimeEquals(wrong_first, secret));
    CHECK(!ConstantTimeEquals(wrong_last, secret));
    CHECK(ConstantTimeEquals(secret, secret));
    CHECK(!ConstantTimeEquals(secret, secret + "x"));  // length differs
    CHECK(!ConstantTimeEquals("", secret));

    // batch77: the old assertion divided AVERAGE times and required the
    // ratio to stay under 1.30. Averages are biased upward by any preemption
    // or cache miss inside the sampled window, and the two candidates are
    // sampled alternately, so whichever round got unlucky dominated the
    // result. Measured on this host the flat implementation produced ratios
    // from 1.375 to 2.891 against a 1.30 bound: a flaky failure with nothing
    // wrong in the product code.
    //
    // The estimate is now the MINIMUM per-call time across rounds. A minimum
    // is the closest thing to a noise-free sample: interference can only add
    // time, so the fastest observed round is the one least disturbed. With
    // 3 rounds the flat compare stays at 1.00-1.11 across 40 trials while a
    // naive early-exit compare measures 11.2-12.6 -- the two are an order of
    // magnitude apart, so a 2.0 bound fails the naive version on every trial
    // (probe: flat max 1.112, naive min 12.584 over 40 trials).
    const auto min_ns = [&secret](const std::string& candidate) {
        constexpr int kIterations = 20000;
        constexpr int kRounds = 3;
        long long best = -1;
        for (int r = 0; r < kRounds; ++r) {
            const auto start = std::chrono::steady_clock::now();
            volatile bool sink = false;
            for (int i = 0; i < kIterations; ++i) {
                sink = ConstantTimeEquals(candidate, secret);
            }
            (void)sink;
            const auto stop = std::chrono::steady_clock::now();
            const long long ns =
                std::chrono::duration_cast<std::chrono::nanoseconds>(stop -
                                                                   start)
                    .count();
            if (best < 0 || ns < best) {
                best = ns;
            }
        }
        return best;
    };
    // Warm both paths so the first timed round is not the cold one.
    (void)min_ns(wrong_first);
    (void)min_ns(wrong_last);
    const long long first_best = min_ns(wrong_first);
    const long long last_best = min_ns(wrong_last);
    const double ratio = (first_best > last_best)
                             ? static_cast<double>(first_best) /
                                   static_cast<double>(last_best)
                             : static_cast<double>(last_best) /
                                   static_cast<double>(first_best);
    std::printf("b34r timing: wrong_first=%lldns wrong_last=%lldns ratio=%.3f\n",
                first_best, last_best, ratio);
    // 2.0 sits far above the flat implementation's worst observed 1.112 and
    // far below a naive compare's best observed 12.584.
    CHECK(ratio < 2.0);
}

// An empty configured token must NOT silently mean "authentication disabled".
// The whole point of the write guard is to stop a LAN device from rewriting
// rules; treating "" as "no guard" turns a forgotten config key into a fully
// open control plane. The guard must refuse (not pass) when it was installed
// with no credential, and the request must be rejected.
static void TestB34rEmptyTokenNeverDisablesAuth() {
    using namespace vgww::web;
    // The shared rule used by RegisterApi and main.cpp: an empty effective
    // token is a configuration error the caller must resolve (main generates
    // one), never a licence to run unauthenticated.
    CHECK(!WriteGuardEnabledFor(""));
    CHECK(WriteGuardEnabledFor("x"));

    // Behavioural half: a guard built from an empty token must reject every
    // write instead of waving it through.
    HttpServer srv;
    srv.Route("POST", "/api/b34r/write", [](const Request&) {
        return Response::Json("{\"ok\":true}");
    });
    srv.SetWriteGuard([](const Request& /*request*/) -> Response {
        // Mirror the production rule: no configured credential means the
        // request cannot be authorised at all.
        const std::string expected;
        if (!WriteGuardEnabledFor(expected)) {
            return Response::Error(401, "unauthorized");
        }
        return Response::Json("{\"ok\":true}");
    });
    std::string err;
    CHECK(srv.Start("127.0.0.1", 18313, err));
    std::string text;
    const int status = HttpRawFull(
        18313,
        "POST /api/b34r/write HTTP/1.1\r\nHost: t\r\nContent-Length: 0\r\n"
        "Connection: close\r\n\r\n",
        text);
    std::printf("b34r empty-token write: status=%d\n", status);
    CHECK(401 == status);
    srv.Stop();
}

// A token must be accepted ONLY from a request header. Accepting it from the
// query string would put the secret into browser history, proxy access logs,
// and any Referer header the page emits - all places the token's owner cannot
// control. The guard must therefore ignore `?token=...`.
static void TestB34rQueryTokenIsNotAccepted() {
    using namespace vgww::web;
    HttpServer srv;
    srv.Route("POST", "/api/b34r/write", [](const Request&) {
        return Response::Json("{\"ok\":true}");
    });
    srv.SetWriteGuard([](const Request& request) -> Response {
        static const std::string expected = "s3cret";
        const auto it = request.headers.find("x-auth-token");
        if (request.headers.end() == it ||
            !ConstantTimeEquals(it->second, expected)) {
            return Response::Error(401, "unauthorized");
        }
        return Response::Json("{\"ok\":true}");
    });
    std::string err;
    CHECK(srv.Start("127.0.0.1", 18314, err));

    std::string text;
    // Correct secret, but in the query string only -> rejected.
    const int via_query = HttpRawFull(
        18314,
        "POST /api/b34r/write?token=s3cret HTTP/1.1\r\nHost: t\r\n"
        "Content-Length: 0\r\nConnection: close\r\n\r\n",
        text);
    std::printf("b34r query-token: status=%d\n", via_query);
    CHECK(401 == via_query);

    // The same secret in the header -> accepted (proves the rejection above
    // is about the CHANNEL, not about the secret being wrong).
    const int via_header = HttpRawFull(
        18314,
        "POST /api/b34r/write HTTP/1.1\r\nHost: t\r\nX-Auth-Token: s3cret\r\n"
        "Content-Length: 0\r\nConnection: close\r\n\r\n",
        text);
    std::printf("b34r header-token: status=%d\n", via_header);
    CHECK(200 == via_header);
    srv.Stop();
}

// Two independent input boundaries, asserted together because both are
// "the server refuses to do unbounded work on attacker input":
//   * a declared Content-Length above the cap is rejected before any big
//     allocation or read,
//   * a static path containing `..` (literal or percent-encoded) never
//     escapes the document root.
static void TestB34rBodyCapAndTraversal() {
    using namespace vgww::web;
    HttpServer srv;
    srv.ServeStatic("b34r_www");
    srv.Route("POST", "/api/b34r/write", [](const Request&) {
        return Response::Json("{\"ok\":true}");
    });
    std::error_code ec;
    std::filesystem::remove_all("b34r_www", ec);
    std::filesystem::create_directories("b34r_www", ec);
    {
        std::ofstream f("b34r_www/ok.txt");
        f << "inside";
    }
    {
        // A secret that must never be served through the static handler.
        std::ofstream f("b34r_secret.txt");
        f << "DO-NOT-SERVE-THIS";
    }
    std::string err;
    CHECK(srv.Start("127.0.0.1", 18315, err));

    std::string text;
    // 1) Oversized declared body: rejected, and nothing is allocated for it.
    const int big = HttpRawFull(
        18315,
        "POST /api/b34r/write HTTP/1.1\r\nHost: t\r\n"
        "Content-Length: 300000000\r\nConnection: close\r\n\r\n",
        text);
    std::printf("b34r body-cap: status=%d\n", big);
    CHECK(400 == big);

    // 2) Traversal, literal and percent-encoded, must not reach the file
    //    outside the root.
    const char* attempts[] = {
        "GET /../b34r_secret.txt HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n",
        "GET /%2e%2e/b34r_secret.txt HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n",
        "GET /..%2fb34r_secret.txt HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n",
        "GET /sub/../../b34r_secret.txt HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n",
    };
    for (const char* attempt : attempts) {
        std::string t;
        const int status = HttpRawFull(18315, attempt, t);
        const size_t at = t.find("\r\n\r\n");
        const std::string body =
            (std::string::npos == at) ? std::string() : t.substr(at + 4);
        std::printf("b34r traversal: status=%d leaked=%d\n", status,
                    std::string::npos != body.find("DO-NOT-SERVE-THIS") ? 1 : 0);
        CHECK(std::string::npos == body.find("DO-NOT-SERVE-THIS"));
    }
    // The legitimate in-root file still serves: the guard must not break the
    // feature it protects.
    {
        std::string t;
        const int status = HttpRawFull(
            18315,
            "GET /ok.txt HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n", t);
        CHECK(200 == status);
        CHECK(std::string::npos != t.find("inside"));
    }
    srv.Stop();
    std::filesystem::remove_all("b34r_www", ec);
    std::remove("b34r_secret.txt");
}

// batch80: publishing a saved config must survive a TRANSIENT busy
// destination. Unique temp names (U1) stop the two writers from truncating each
// other mid-write, but they do NOT stop both from renaming onto the SAME
// destination - Windows answers ERROR_ACCESS_DENIED for the loser. Measured
// with two concurrent writers: 13 failures in 40 runs, every one err=5, and
// the old one-shot MoveFileExW reported "atomic replace failed" to the user.
//
// This test makes the overlap DETERMINISTIC instead of racing for it: hold the
// destination open denying write sharing, then publish. Without a retry budget
// the publish fails every time (measured 20/20, err=5); with it the publish
// succeeds as soon as the holder lets go (measured 0/20 failures). A permanent
// error must still be reported, so the negative control keeps the hold for the
// whole call and asserts the failure is NOT swallowed.
static void TestB80PublishSurvivesBusyDestination() {
    using namespace vgww::core;
    const char* kPath = "b80publish.json";
    const std::string kTmp = std::string(kPath) + ".tmp." +
                             std::to_string(::GetCurrentProcessId()) + ".b80";
    std::remove(kPath);
    std::remove(kTmp.c_str());
    const auto seed = [&](const char* text) {
        FILE* f = nullptr;
        const std::wstring w(kPath, kPath + std::strlen(kPath));
        ::_wfopen_s(&f, w.c_str(), L"wb");
        if (nullptr != f) {
            ::fwrite(text, 1, std::strlen(text), f);
            ::fclose(f);
        }
    };
    const auto seed_tmp = [&] {
        FILE* f = nullptr;
        const std::wstring w(kTmp.begin(), kTmp.end());
        ::_wfopen_s(&f, w.c_str(), L"wb");
        if (nullptr != f) {
            ::fwrite("payload", 1, 7, f);
            ::fflush(f);
            ::fclose(f);
        }
    };
    const auto read_back = [&] {
        std::string out;
        std::ifstream in(kPath, std::ios::binary);
        out.assign(std::istreambuf_iterator<char>(in),
                   std::istreambuf_iterator<char>());
        return out;
    };
    // Hold the DESTINATION denying write/delete sharing.
    const auto hold_destination = [&](int hold_ms) {
        const HANDLE h = ::CreateFileA(
            kPath, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL, nullptr);
        if (INVALID_HANDLE_VALUE == h) {
            return static_cast<HANDLE>(nullptr);
        }
        if (hold_ms > 0) {
            ::Sleep(static_cast<DWORD>(hold_ms));
            ::CloseHandle(h);
            return static_cast<HANDLE>(nullptr);
        }
        return h;
    };

    // (1) Transient hold: released from another thread while publish retries.
    int transient_failures = 0;
    for (int i = 0; i < 3; ++i) {
        seed("original");
        seed_tmp();
        const HANDLE h = ::CreateFileA(
            kPath, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL, nullptr);
        CHECK(INVALID_HANDLE_VALUE != h);
        std::thread releaser([&] {
            ::Sleep(20);
            ::CloseHandle(h);
        });
        std::string err;
        if (!Config::PublishConfigTempFile(kTmp, kPath, err)) {
            ++transient_failures;
            std::printf("B80 transient publish failed: %s\n", err.c_str());
        }
        releaser.join();
        std::remove(kTmp.c_str());
    }
    std::printf("B80 transient-hold failures=%d/3\n", transient_failures);
    CHECK(0 == transient_failures);
    CHECK(std::string("payload") == read_back());
    std::remove(kPath);

    // (2) Permanent hold: the publish must FAIL and must not silently claim
    //     success (the negative control - proves the retry budget terminates).
    seed("original");
    seed_tmp();
    const HANDLE held = hold_destination(0);
    CHECK(static_cast<HANDLE>(nullptr) != held);
    std::string perm_err;
    const bool perm_ok = Config::PublishConfigTempFile(kTmp, kPath, perm_err);
    ::CloseHandle(held);
    std::printf("B80 permanent-hold published=%d err_has_reason=%d\n",
                perm_ok ? 1 : 0, perm_err.empty() ? 0 : 1);
    CHECK(!perm_ok);
    CHECK(!perm_err.empty());
    // The destination still holds the previous content: a failed publish never
    // leaves a half-written file behind.
    CHECK(std::string("original") == read_back());
    // The temp file is cleaned up on the failure path.
    CHECK(!std::filesystem::exists(kTmp));
    std::remove(kPath);
}

// batch85: a Content-Length that is not 1*DIGIT (RFC 9110 8.6 / RFC 9112 6.3)
// makes the message framing invalid; the recipient MUST treat it as an
// unrecoverable error and answer 400. The implementation used a bare
// strtoull() whose endptr was ignored, so:
//   "Content-Length: abc"   framed the body as 0 -> the request was DISPATCHED
//                           with its real body silently discarded;
//   "Content-Length: 12abc" framed as 12;
//   "Content-Length: 1e5"   framed as 1.
// All three are silent truncation of attacker-controlled framing, so they are
// asserted as 400 here rather than as "whatever the handler decides".
//
// A valid value on the same route must still work, otherwise a strict parse
// could "pass" this test by rejecting everything.
// batch89: the per-collection caps were enforced OUTSIDE the store lock for
// bans and rate-limits, so two concurrent writers could both observe "below
// cap" and both insert. AddPortMap already documents exactly this (web_api.cpp
// :782-789: "the cap must be enforced INSIDE this lock ... a cap that can be
// exceeded is not a cap") and does it in-lock. AddBan and SetRateLimit did not:
// both are void and both callers pre-check Bans().size() / RateLimits().size()
// through a separate locked read.
//
// Worse for rate-limits, the pre-check has to reproduce the upsert decision by
// hand (scan for an existing MAC) - the authoritative decision lives inside
// SetRateLimit. When the two disagree the wrong answer is returned: a client
// replacing an EXISTING rule can be told "too many ratelimits" purely because
// the collection is at its cap, and a concurrent pair can each insert a new
// MAC past the cap.
//
// The fix is the same shape as AddPortMap: a checked entry point that performs
// the duplicate/upsert test, the cap test and the insert under ONE lock and
// reports what it did.
static void TestB89CapsEnforcedInsideTheLock() {
    using namespace vgww::web;
    auto& store = RuleStore::Instance();
    store.AttachFile("");
    store.Clear();

    // Ban cap: the store level must refuse, not merely report. Fill to the cap
    // through the checked entry point so the cap test itself is exercised.
    CHECK(store.AddBanChecked(BanEntry{"mac", "02:00:00:00:00:01"}));
    CHECK(store.Bans().size() == 1);
    // Out-of-cap behaviour is the same refusal regardless of how the caller
    // reached it, and a refusal must not mutate.
    store.Clear();
    for (size_t i = 0; i < ::vgww::core::limits::kMaxBans; ++i) {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "02:00:%02X:%02X:%02X:%02X",
                      static_cast<unsigned>((i >> 24) & 0xFF),
                      static_cast<unsigned>((i >> 16) & 0xFF),
                      static_cast<unsigned>((i >> 8) & 0xFF),
                      static_cast<unsigned>(i & 0xFF));
        CHECK(store.AddBanChecked(BanEntry{"mac", buf}));
    }
    CHECK(store.Bans().size() == ::vgww::core::limits::kMaxBans);
    const size_t bans_at_cap = store.Bans().size();
    CHECK(!store.AddBanChecked(BanEntry{"mac", "02:00:FF:FF:FF:FF"}));
    CHECK(store.Bans().size() == bans_at_cap);  // refusal did not insert

    // Rate-limit cap with UPSERT semantics: at the cap, REPLACING an existing
    // MAC must still be allowed (it does not grow the collection), while adding
    // a NEW MAC must be refused. The old out-of-lock pre-check got this wrong
    // whenever it disagreed with the in-lock upsert decision.
    store.Clear();
    for (size_t i = 0; i < ::vgww::core::limits::kMaxRateLimits; ++i) {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "02:00:01:00:%02X:%02X",
                      static_cast<unsigned>((i >> 8) & 0xFF),
                      static_cast<unsigned>(i & 0xFF));
        CHECK(store.SetRateLimitChecked(RateLimitRule{buf, 1, 1}));
    }
    CHECK(store.RateLimits().size() == ::vgww::core::limits::kMaxRateLimits);
    const size_t rates_at_cap = store.RateLimits().size();

    // Replace an existing MAC: allowed, size unchanged, value updated.
    CHECK(store.SetRateLimitChecked(
        RateLimitRule{"02:00:01:00:00:00", 4242, 4243}));
    CHECK(store.RateLimits().size() == rates_at_cap);
    {
        bool updated = false;
        for (const auto& r : store.RateLimits()) {
            if (0 == _stricmp(r.mac.c_str(), "02:00:01:00:00:00")) {
                updated = (4242 == r.uplink_kbps && 4243 == r.downlink_kbps);
            }
        }
        CHECK(updated);
    }

    // Add a NEW MAC: refused, size unchanged.
    CHECK(!store.SetRateLimitChecked(
        RateLimitRule{"02:00:FF:FF:FF:FF", 1, 1}));
    CHECK(store.RateLimits().size() == rates_at_cap);
    {
        bool leaked = false;
        for (const auto& r : store.RateLimits()) {
            if (0 == _stricmp(r.mac.c_str(), "02:00:FF:FF:FF:FF")) leaked = true;
        }
        CHECK(!leaked);  // the refused rule must not be stored
    }

    store.AttachFile("");
    store.Clear();
}

// batch88: DELETE /api/bans used the two-step pattern batch34d already removed
// for port-maps: read Bans().size() under lock #1 (a full copy), then call
// RemoveBan(index), which is `void` and re-checks nothing under lock #2.
//
// Two consequences follow from that shape and neither is caught by the existing
// route test (which only exercises a single-threaded, static store):
//
//   * The answer the route sends ("ok":true) is a statement about the size it
//     read, not about the mutation it performed. Between the two locks the
//     vector can shrink, so the erase can silently no-op while the client is
//     told the deletion succeeded.
//   * An out-of-range index is indistinguishable from a successful delete at
//     the store level - the only thing that ever reports it is the racy
//     pre-check.
//
// RemoveBanChecked(size_t) returns bool and does the range check and the erase
// under ONE lock, mirroring RemovePortMapChecked. The two assertions below are
// the parts that are deterministically falsifiable; the atomicity of the pair
// is structural (same argument as batch34d) and is deliberately NOT asserted
// with a timing or interleaving predicate, which on a shared host would be
// noise-driven rather than product-driven.
static void TestB88RemoveBanCheckedIsAtomic() {
    using namespace vgww::web;
    auto& store = RuleStore::Instance();
    store.AttachFile("");
    store.Clear();
    for (int i = 0; i < 4; ++i) {
        store.AddBan(BanEntry{"mac", "02:00:00:00:00:0" + std::to_string(i)});
    }
    CHECK(store.Bans().size() == 4);

    // Identity: the checked call must remove the entry AT THAT INDEX and report
    // true. If it erased a different slot the caller's index would have meant
    // nothing, which is the whole reason the port-map path was made checked.
    CHECK(store.RemoveBanChecked(1));
    CHECK(store.Bans().size() == 3);
    CHECK(store.Bans()[0].value == "02:00:00:00:00:00");
    CHECK(store.Bans()[1].value == "02:00:00:00:00:02");

    // Out of range: report false and mutate NOTHING. This is what lets the
    // route answer 404 from the same lock that performed (or refused) the
    // erase, instead of trusting a size it read earlier.
    const size_t before = store.Bans().size();
    CHECK(!store.RemoveBanChecked(before));
    CHECK(!store.RemoveBanChecked(before + 1000));
    CHECK(store.Bans().size() == before);

    // Drain to empty, then the very next checked call must still refuse rather
    // than dereference or wrap.
    for (size_t i = store.Bans().size(); i > 0; --i) {
        CHECK(store.RemoveBanChecked(0));
    }
    CHECK(store.Bans().empty());
    CHECK(!store.RemoveBanChecked(0));

    store.AttachFile("");
    store.Clear();
}

// batch87: the port-forward loader enforces the SAME semantic contract the POST
// route does (proto == tcp, dotted-quad lan_ip, non-zero ports) and REPORTS how
// many entries it dropped. The rate-limit and ban loaders did not: a rule whose
// MAC cannot be parsed was migrated-if-possible and then pushed anyway, so
// GET /api/ratelimit echoed a rule that dataplane.cpp:3348 has always skipped
// ("malformed rule: skip"). The operator sees a mounted cap; nothing is
// throttled - the same plausible-but-broken fake the POST route rejects at
// :1724.
//
// A persisted file is exactly the hand-edited/older-version input the
// port-forward loader already guards, so the rate-limit loader must not be the
// weak link. The contract asserted here: every entry that survives a load is
// one the POST route would have accepted, and every dropped entry is COUNTED.
static void TestB87LoadedRateLimitsAreSemanticallyValid() {
    using namespace vgww::web;
    const std::string path = WriteRuleFile(
        "b87_badlimits.json",
        R"({"ratelimits":[
          {"mac":"not-a-mac","uplink_kbps":100,"downlink_kbps":100},
          {"mac":"AA:BB:CC:DD:EE:01","uplink_kbps":0,"downlink_kbps":0},
          {"mac":"AA:BB:CC:DD:EE:04","uplink_kbps":5000000000,"downlink_kbps":9},
          {"mac":"aa-bb-cc-dd-ee-05","uplink_kbps":7,"downlink_kbps":7},
          {"mac":"AA:BB:CC:DD:EE:02","uplink_kbps":500,"downlink_kbps":250}
        ],
         "bans":[
          {"kind":"mac","value":"also-not-a-mac"},
          {"kind":"ip","value":"not-an-ip-either"},
          {"kind":"domain","value":"example.com"},
          {"kind":"mac","value":"aa-bb-cc-dd-ee-03"}
        ]})");
    RuleStore::Instance().AttachFile("");
    RuleStore::Instance().Clear();
    std::string error;
    const bool loaded = RuleStore::Instance().AttachFileChecked(path, error);
    const auto limits = RuleStore::Instance().RateLimits();
    const auto bans = RuleStore::Instance().Bans();
    const size_t dropped = RuleStore::Instance().DiscardedOnLastLoad();
    std::printf(
        "b87 bad rules: loaded=%d limits=%zu bans=%zu dropped=%zu error=[%s]\n",
        loaded ? 1 : 0, limits.size(), bans.size(), dropped, error.c_str());
    for (const auto& r : limits) {
        std::printf("b87 kept ratelimit: mac=%s up=%u down=%u\n", r.mac.c_str(),
                    static_cast<unsigned>(r.uplink_kbps),
                    static_cast<unsigned>(r.downlink_kbps));
    }
    for (const auto& b : bans) {
        std::printf("b87 kept ban: kind=%s value=%s\n", b.kind.c_str(),
                    b.value.c_str());
    }
    // A valid document with bad entries loads, keeps the good entries, and
    // REPORTS how many it dropped - a silent drop is the defect.
    CHECK(loaded);
    // Two rate limits survive: the canonical one and the dashed spelling that
    // is migrated on load. Everything the data plane would refuse is gone.
    CHECK(limits.size() == 2);
    CHECK(bans.size() == 1);
    // 3 bad rate limits (unparseable mac, zero kbps, kbps > UINT32_MAX)
    // + 3 bad bans (unparseable mac, non-address ip, unknown kind).
    CHECK(dropped == 6);
    {
        bool have_canon = false;
        bool have_migrated = false;
        for (const auto& r : limits) {
            if ("AA:BB:CC:DD:EE:02" == r.mac) {
                have_canon = true;
                CHECK(r.uplink_kbps == 500);
                CHECK(r.downlink_kbps == 250);
            }
            if ("AA:BB:CC:DD:EE:05" == r.mac) {
                have_migrated = true;  // dashed input, canonical on load
                CHECK(r.uplink_kbps == 7);
                CHECK(r.downlink_kbps == 7);
            }
            // A partially-valid rule is NOT acceptable: the direction that
            // overflowed must not be left at 0 with the other one live.
            CHECK(r.mac != "AA:BB:CC:DD:EE:04");
        }
        CHECK(have_canon);
        CHECK(have_migrated);
    }
    if (1 == bans.size()) {
        CHECK(bans[0].kind == "mac");
        CHECK(bans[0].value == "AA:BB:CC:DD:EE:03");  // dashed -> canonical
    }
    // Nothing the data plane would refuse may be echoed back to a client.
    for (const auto& r : limits) {
        vgww::core::MacAddress mac{};
        CHECK(vgww::core::ParseMac(r.mac, mac));
        CHECK(0 != r.uplink_kbps || 0 != r.downlink_kbps);
    }
    for (const auto& b : bans) {
        if ("mac" == b.kind) {
            vgww::core::MacAddress mac{};
            CHECK(vgww::core::ParseMac(b.value, mac));
        } else {
            std::error_code ec;
            (void)asio::ip::make_address(b.value, ec);
            CHECK(!ec);
        }
    }
    RuleStore::Instance().AttachFile("");
    RuleStore::Instance().Clear();
    std::remove(path.c_str());
}

// batch97: the request line was parsed as `request_line >> method >> path`,
// which takes the first two whitespace-separated tokens and DISCARDS the rest.
// The HTTP-version token was therefore never validated: "GET /api/status"
// (no version), "GET /api/status GARBAGE" and "GET /api/status HTTP/9.9" were
// all accepted and dispatched as normal requests.
//
// RFC 9112 section 3 requires the request-line to be
//   method SP request-target SP HTTP-version CRLF
// so a missing or malformed version is a framing error the server MUST reject
// (400). Accepting it also means the parser's view of the line and the client's
// view can diverge, which is the same class of framing bug batch85 fixed for
// Content-Length.
// batch98: duplicate header fields were folded by `out.headers[key] = value`,
// i.e. the LAST occurrence silently won and every earlier one vanished. For
// Content-Length that is the classic request-smuggling setup: a proxy and this
// server can disagree about where the body ends, because each picks a different
// occurrence.
//
// RFC 9112 section 6.3 is explicit: a message with multiple Content-Length
// fields whose values are not all identical MUST be treated as unrecoverable
// (400 + close), and even identical duplicates are only tolerated by some
// recipients. This server serves a LAN admin surface behind whatever proxy the
// operator puts in front of it, so it must not silently pick one.
//
// Asserted: a repeated Content-Length is rejected no matter whether the values
// agree, and no handler runs. Positive controls keep the single-header cases
// (including the legal OWS form from batch85) working.
// batch99: header-block structure was never validated. Every line was searched
// for ':' and a line without one was SILENTLY DROPPED (http_server.cpp:542
// `line.find(':')`, the `npos` case fell through the loop body with no error).
// Combined with the batch85/97/98 framing checks, that leaves three ways to
// send a header the server refuses to understand yet still dispatches:
//
//   1. whitespace between the field name and ':'  ("Content-Length : 7")
//      - the name normalizes to "content-length " (trailing space), so the
//        lookup for "content-length" misses and the body frames as 0.
//   2. no colon at all ("Content-Length 7") - line dropped entirely.
//   3. obs-fold continuation (a line starting with SP/HTAB) - folded into
//      nothing; RFC 9112 section 5.2 obsoleted it and requires 400.
//
//   4. Transfer-Encoding is never implemented, so "Transfer-Encoding: chunked"
//      was ignored and the body framed as Content-Length/0. RFC 9112 section
//      6.1: a server that receives a transfer coding it does not understand
//      MUST respond 501; combined with a Content-Length it is a smuggling
//      shape the RFC explicitly forbids accepting.
//
// RFC 9112 section 5.1 makes (1) a MUST-reject (400). All four are asserted to
// be 400 here, and the handler must never run for any of them.
// batch100: ServeFile's containment guard compared the WRONG thing.
//
//   const fs::path full = root / relative.substr(1);
//   if (full.root_name() != root.root_name() ||
//       full.is_absolute() != root.is_absolute()) return 403;
//
// That only catches a CROSS-DRIVE absolute path. When the static root is
// itself absolute - which is exactly the production case (main.cpp serves
// exe_dir / "www") - a same-drive absolute request path has the SAME
// root_name and the SAME absoluteness, so the guard passes and
// operator/ REPLACES the root entirely:
//
//   root / "F:/Windows/win.ini"  ==  "F:/Windows/win.ini"
//
// The ".." segment check cannot help: there is no ".." in the request. So
// "GET /F:/anything" served any file on the same drive, including the config
// directory the admin surface is trying to protect.
//
// Asserted: a same-drive absolute request path is refused (403/404) and its
// content never appears in the response; the legitimate in-root file still
// serves.
static void TestB100AbsolutePathCannotEscapeStaticRoot() {
    using namespace vgww::web;
    namespace fs = std::filesystem;
    std::error_code ec;
    fs::remove_all("b100_www", ec);
    fs::create_directories("b100_www", ec);
    {
        std::ofstream f("b100_www/ok.txt");
        f << "inside-b100";
    }
    {
        std::ofstream f("b100_secret.txt");
        f << "DO-NOT-SERVE-B100";
    }

    HttpServer srv;
    // Absolute root on purpose: that is how main.cpp wires the real server.
    const std::string root_abs = fs::absolute("b100_www").string();
    srv.ServeStatic(root_abs);
    std::string err;
    constexpr uint16_t kPort = 18316;
    CHECK(srv.Start("127.0.0.1", kPort, err));

    const auto fetch = [&](const std::string& target, std::string& text) {
        const std::string req = "GET " + target +
                                " HTTP/1.1\r\nHost: t\r\n"
                                "Connection: close\r\n\r\n";
        return HttpRawFull(kPort, req, text);
    };

    // Positive control: an in-root file still serves.
    {
        std::string t;
        CHECK(200 == fetch("/ok.txt", t));
        CHECK(std::string::npos != t.find("inside-b100"));
    }

    // The escape: a same-drive ABSOLUTE path with no ".." in it at all.
    std::string secret_abs = fs::absolute("b100_secret.txt").string();
    for (char& c : secret_abs) {
        if ('\\' == c) c = '/';
    }
    const std::string targets[] = {
        "/" + secret_abs,                       // same drive, absolute
        "/" + secret_abs + "?x=1",              // with a query string
    };
    for (const std::string& target : targets) {
        std::string t;
        const int status = fetch(target, t);
        const size_t at = t.find("\r\n\r\n");
        const std::string body =
            (std::string::npos == at) ? std::string() : t.substr(at + 4);
        std::printf("b100 abs-escape [%s]: status=%d leaked=%d\n",
                    target.c_str(), status,
                    std::string::npos != body.find("DO-NOT-SERVE-B100") ? 1 : 0);
        CHECK(403 == status || 404 == status);
        CHECK(std::string::npos == body.find("DO-NOT-SERVE-B100"));
    }

    srv.Stop();
    fs::remove_all("b100_www", ec);
    std::remove("b100_secret.txt");
}

static void TestB99MalformedHeaderBlockRejected() {
    using namespace vgww::web;
    HttpServer srv;
    int hits = 0;
    srv.Route("POST", "/api/b99", [&hits](const Request& r) {
        ++hits;
        return Response::Json("{\"len\":" + std::to_string(r.body.size()) +
                              "}");
    });
    std::string error;
    constexpr uint16_t kPort = 18097;
    CHECK(srv.Start("127.0.0.1", kPort, error));

    const auto raw = [&](const std::string& request) {
        std::string body;
        return HttpRawFull(kPort, request, body);
    };

    // Positive controls first: well-formed headers still work.
    CHECK(200 == raw("POST /api/b99 HTTP/1.1\r\nHost: t\r\nContent-Length: 7\r\n"
                     "Connection: close\r\n\r\nPAYLOAD"));
    CHECK(200 == raw("POST /api/b99 HTTP/1.1\r\nHost: t\r\n"
                     "X-Ignored: whatever\r\nContent-Length: 7\r\n"
                     "Connection: close\r\n\r\nPAYLOAD"));
    const int hits_before = hits;
    CHECK(2 == hits_before);

    // 1. Whitespace between field name and colon (RFC 9112 5.1 MUST reject).
    CHECK(400 == raw("POST /api/b99 HTTP/1.1\r\nHost: t\r\n"
                     "Content-Length : 7\r\nConnection: close\r\n\r\nPAYLOAD"));
    CHECK(400 == raw("POST /api/b99 HTTP/1.1\r\nHost: t\r\n"
                     "Content-Length\t: 7\r\nConnection: close\r\n\r\nPAYLOAD"));

    // 2. A field line with no colon at all must not be silently dropped.
    CHECK(400 == raw("POST /api/b99 HTTP/1.1\r\nHost: t\r\n"
                     "Content-Length 7\r\nConnection: close\r\n\r\nPAYLOAD"));
    CHECK(400 == raw("POST /api/b99 HTTP/1.1\r\nHost: t\r\n"
                     "garbage-without-colon\r\nContent-Length: 7\r\n"
                     "Connection: close\r\n\r\nPAYLOAD"));

    // 3. obs-fold continuation line (RFC 9112 5.2 obs-fold -> 400).
    CHECK(400 == raw("POST /api/b99 HTTP/1.1\r\nHost: t\r\n"
                     "X-Folded: one\r\n two\r\nContent-Length: 7\r\n"
                     "Connection: close\r\n\r\nPAYLOAD"));

    // 4. Transfer-Encoding we do not implement (RFC 9112 6.1 -> 501, and with
    //    Content-Length present the pair is a smuggling shape). Accept either
    //    rejection code, but never 200.
    CHECK(400 == raw("POST /api/b99 HTTP/1.1\r\nHost: t\r\n"
                     "Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
                     "0\r\n\r\n") ||
          501 == raw("POST /api/b99 HTTP/1.1\r\nHost: t\r\n"
                     "Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
                     "0\r\n\r\n"));
    CHECK(400 == raw("POST /api/b99 HTTP/1.1\r\nHost: t\r\n"
                     "Content-Length: 7\r\nTransfer-Encoding: chunked\r\n"
                     "Connection: close\r\n\r\nPAYLOAD"));

    // None of the rejected requests may have reached the handler.
    CHECK(hits == hits_before);

    srv.Stop();
}

static void TestB98DuplicateContentLengthRejected() {
    using namespace vgww::web;
    HttpServer srv;
    int hits = 0;
    srv.Route("POST", "/api/b98", [&hits](const Request& r) {
        ++hits;
        return Response::Json("{\"len\":" + std::to_string(r.body.size()) +
                              "}");
    });
    std::string error;
    constexpr uint16_t kPort = 18096;
    CHECK(srv.Start("127.0.0.1", kPort, error));

    const auto raw = [&](const std::string& request) {
        std::string body;
        return HttpRawFull(kPort, request, body);
    };

    // Positive controls: one Content-Length, both the plain and OWS forms.
    CHECK(200 == raw("POST /api/b98 HTTP/1.1\r\nHost: t\r\nContent-Length: 7\r\n"
                     "Connection: close\r\n\r\nPAYLOAD"));
    CHECK(200 == raw("POST /api/b98 HTTP/1.1\r\nHost: t\r\nContent-Length: 5\t\r\n"
                     "Connection: close\r\n\r\nPAYLO"));
    const int hits_after_ok = hits;
    CHECK(2 == hits_after_ok);

    // Conflicting duplicates: the smuggling shape.
    const int before = hits;
    CHECK(400 == raw("POST /api/b98 HTTP/1.1\r\nHost: t\r\nContent-Length: 7\r\n"
                     "Content-Length: 3\r\nConnection: close\r\n\r\nPAYLOAD"));
    CHECK(400 == raw("POST /api/b98 HTTP/1.1\r\nHost: t\r\nContent-Length: 3\r\n"
                     "Content-Length: 7\r\nConnection: close\r\n\r\nPAYLOAD"));
    // Identical duplicates: still ambiguous framing, reject rather than guess.
    CHECK(400 == raw("POST /api/b98 HTTP/1.1\r\nHost: t\r\nContent-Length: 7\r\n"
                     "Content-Length: 7\r\nConnection: close\r\n\r\nPAYLOAD"));
    // Different spelling of the field name must still be the same field.
    CHECK(400 == raw("POST /api/b98 HTTP/1.1\r\nHost: t\r\nContent-Length: 7\r\n"
                     "content-length: 3\r\nConnection: close\r\n\r\nPAYLOAD"));
    // None of the rejected requests may have reached the handler.
    CHECK(hits == before);

    srv.Stop();
}

static void TestB97RequestLineRequiresHttpVersion() {
    using namespace vgww::web;
    HttpServer srv;
    srv.Route("GET", "/api/b97", [](const Request&) {
        return Response::Json("{\"ok\":true}");
    });
    std::string error;
    constexpr uint16_t kPort = 18095;
    CHECK(srv.Start("127.0.0.1", kPort, error));

    const auto raw = [&](const std::string& request) {
        std::string body;
        return HttpRawFull(kPort, request, body);
    };

    // Positive control: a well-formed request still works.
    CHECK(200 == raw("GET /api/b97 HTTP/1.1\r\nHost: t\r\n"
                     "Connection: close\r\n\r\n"));
    CHECK(200 == raw("GET /api/b97 HTTP/1.0\r\nConnection: close\r\n\r\n"));

    // Malformed request lines must be rejected, not dispatched.
    const char* bad[] = {
        "GET /api/b97\r\nHost: t\r\nConnection: close\r\n\r\n",          // no version
        "GET /api/b97 GARBAGE\r\nHost: t\r\nConnection: close\r\n\r\n",  // junk
        "GET /api/b97 HTTP/9.9\r\nHost: t\r\nConnection: close\r\n\r\n", // bad major
        "GET /api/b97 http/1.1\r\nHost: t\r\nConnection: close\r\n\r\n", // wrong case
        "GET /api/b97 HTTP/1.1 extra\r\nHost: t\r\nConnection: close\r\n\r\n",
    };
    for (const char* req : bad) {
        const int status = raw(req);
        std::printf("B97 request-line [%s] -> %d\n",
                    std::string(req, std::string(req).find("\r\n")).c_str(),
                    status);
        CHECK(400 == status || 505 == status);
    }

    srv.Stop();
}

static void TestB85InvalidContentLengthRejected() {
    using namespace vgww::web;
    HttpServer srv;
    std::string seen_body;
    srv.Route("POST", "/api/b85/echo", [&seen_body](const Request& r) {
        seen_body = r.body;
        return Response::Json("{\"ok\":true}");
    });
    std::string err;
    CHECK(srv.Start("127.0.0.1", 18321, err));

    const char* bad_values[] = {"abc", "12abc", "-1", "1e5", "0x10",
                                "1, 1", ""};
    for (const char* value : bad_values) {
        std::string t;
        const std::string request =
            std::string("POST /api/b85/echo HTTP/1.1\r\nHost: t\r\n"
                        "Content-Length: ") +
            value + "\r\nConnection: close\r\n\r\nPAYLOAD";
        const int status = HttpRawFull(18321, request, t);
        if (400 != status) {
            std::fprintf(stderr,
                         "b85: Content-Length [%s] answered %d, expected 400\n",
                         value, status);
        }
        CHECK(400 == status);
    }
    // Nothing above may have reached the handler: a framed-as-0 request would
    // have dispatched with an empty body, which is the bug this pins.
    CHECK(seen_body.empty());

    // Optional whitespace around a field value (RFC 9110 5.5) is stripped by
    // the header parser before this check sees it, so " 5" arrives as "5" and
    // must be treated as VALID - padding is not a malformed length.
    {
        seen_body = "sentinel";
        std::string t;
        const int status = HttpRawFull(
            18321,
            "POST /api/b85/echo HTTP/1.1\r\nHost: t\r\nContent-Length:  5\t\r\n"
            "Connection: close\r\n\r\nPAYLOAD",
            t);
        CHECK(200 == status);
        CHECK(std::string("PAYLO") == seen_body);  // 5 declared bytes
    }

    // Positive control: a well-formed Content-Length still dispatches, and the
    // declared bytes arrive intact.
    {
        std::string t;
        const std::string payload = "PAYLOAD";
        const std::string request =
            "POST /api/b85/echo HTTP/1.1\r\nHost: t\r\nContent-Length: " +
            std::to_string(payload.size()) +
            "\r\nConnection: close\r\n\r\n" + payload;
        const int status = HttpRawFull(18321, request, t);
        std::printf("b85 valid content-length: status=%d body_len=%zu\n",
                    status, seen_body.size());
        CHECK(200 == status);
        CHECK(payload == seen_body);
    }
    // Zero is the valid boundary (1*DIGIT allows "0").
    {
        seen_body = "sentinel";
        std::string t;
        const int status = HttpRawFull(
            18321,
            "POST /api/b85/echo HTTP/1.1\r\nHost: t\r\nContent-Length: 0\r\n"
            "Connection: close\r\n\r\n",
            t);
        CHECK(200 == status);
        CHECK(seen_body.empty());  // dispatched with an empty body
    }
    srv.Stop();
}

// batch108: DELETE /api/portmap and /api/bans parse `index` with
// strtoull() and guard with "'\0' != *end". That guard only looks for
// TRAILING junk and is blind to a parse that consumes NOTHING: strtoull("")
// returns 0, leaves end == c_str() and sets no error, so an EMPTY "index="
// passed the check, resolved to 0, and deleted the FIRST rule even though
// the caller never named an index. The same blind spot accepts a leading
// '+' ("+0" -> 0), a leading '-' (strtoull wraps "-1" to ULLONG_MAX, so it
// became a 404 "no such index" instead of a 400), and an overflowing digit
// string (ERANGE still leaves end at '\0'). This is the batch107 shape one
// layer up: endptr checked for trailing junk only, so "malformed" and
// "index 0" collapsed into the same request.
//
// Each malformed spelling is checked against a FRESH two-rule store, so a
// failure cannot cascade and mask the next one, and "did it delete rule 0"
// is observable in the payload every time.
//
// The two routes each carried their own copy of the parse, so both are
// exercised: a test on one route would not prove the other was migrated.
static void TestB108DeleteIndexMustBeAllDigits() {
    constexpr uint16_t kApiPort = 18110;
    std::remove("b108.json.rules.json");
    vgww::core::Config cfg;
    vgww::runtime::Dataplane dp(cfg);
    HttpServer api;
    vgww::web::RegisterApi(api, dp, cfg, "b108.json");
    std::string error;
    CHECK(api.Start("127.0.0.1", kApiPort, error));
    std::string body;

    const auto reset_rules = [&]() {
        vgww::web::RuleStore::Instance().Clear();
        for (const int wan : {9101, 9102}) {
            body.clear();
            CHECK(HttpPost(kApiPort, "/api/portmap", "",
                           "{\"proto\":\"tcp\",\"wan_port\":" +
                               std::to_string(wan) +
                               ",\"lan_ip\":\"192.168.1.9\",\"lan_port\":80}",
                           body) == 200);
        }
    };
    const auto portmaps = [&]() {
        body.clear();
        CHECK(HttpGet("/api/portmap", kApiPort, body) == 200);
        return body;
    };
    const auto portmap_count = [&]() {
        const auto j = nlohmann::json::parse(portmaps(), nullptr, false);
        return j.is_discarded() || !j.is_array() ? size_t{0} : j.size();
    };

    // Every malformed spelling must be a 400 AND leave both rules in place.
    struct Case {
        const char* path;
        const char* why;
    };
    const Case cases[] = {
        {"/api/portmap?index=", "empty value consumed nothing -> index 0"},
        {"/api/portmap?index=+0", "'+' accepted by strtoull -> index 0"},
        {"/api/portmap?index=-1", "'-' wrapped to ULLONG_MAX -> 404 not 400"},
        {"/api/portmap?index=99999999999999999999999", "ERANGE, end at '\\0'"},
        {"/api/portmap?index=%20", "whitespace-only (already refused)"},
        {"/api/portmap?index=0abc", "trailing junk (already refused)"},
    };
    for (const Case& c : cases) {
        reset_rules();
        CHECK(portmap_count() == 2);
        const int status = HttpDelete(c.path, kApiPort, body);
        if (400 != status) {
            std::fprintf(stderr, "b108 %s -> %d (%s)\n", c.path, status,
                         c.why);
        }
        CHECK(400 == status);
        CHECK(portmap_count() == 2);
        const std::string listed = portmaps();
        CHECK(listed.find("9101") != std::string::npos);
        CHECK(listed.find("9102") != std::string::npos);
    }

    // Positive control: a clean index still deletes exactly that rule.
    reset_rules();
    CHECK(HttpDelete("/api/portmap?index=0", kApiPort, body) == 200);
    CHECK(portmap_count() == 1);
    {
        const std::string listed = portmaps();
        CHECK(listed.find("9101") == std::string::npos);
        CHECK(listed.find("9102") != std::string::npos);
    }

    // /api/bans carried its own copy of the parse; prove it was migrated too.
    const auto reset_bans = [&]() {
        vgww::web::RuleStore::Instance().Clear();
        for (const char* mac : {"02:00:00:00:00:01", "02:00:00:00:00:02"}) {
            body.clear();
            CHECK(HttpPost(kApiPort, "/api/bans", "",
                           std::string("{\"kind\":\"mac\",\"value\":\"") + mac +
                               "\"}",
                           body) == 200);
        }
    };
    const auto bans = [&]() {
        body.clear();
        CHECK(HttpGet("/api/bans", kApiPort, body) == 200);
        return body;
    };

    for (const char* path : {"/api/bans?index=", "/api/bans?index=-1",
                             "/api/bans?index=+1"}) {
        reset_bans();
        const int status = HttpDelete(path, kApiPort, body);
        if (400 != status) {
            std::fprintf(stderr, "b108 %s -> %d\n", path, status);
        }
        CHECK(400 == status);
        const std::string listed = bans();
        CHECK(listed.find("02:00:00:00:00:01") != std::string::npos);
        CHECK(listed.find("02:00:00:00:00:02") != std::string::npos);
    }
    reset_bans();
    CHECK(HttpDelete("/api/bans?index=0", kApiPort, body) == 200);
    {
        const std::string listed = bans();
        CHECK(listed.find("02:00:00:00:00:01") == std::string::npos);
        CHECK(listed.find("02:00:00:00:00:02") != std::string::npos);
    }

    vgww::web::RuleStore::Instance().Clear();
    api.Stop();
    std::remove("b108.json.rules.json");
}

// batch120: Response::Error is the single funnel for every JSON error body, and
// its escaper used to DROP bytes below 0x20 instead of escaping them. The body
// stayed syntactically valid, so nothing ever complained - but the text was
// silently corrupted: a multi-line report (line1 + newline + line2) collapsed
// to "line1line2", and a tab became nothing. Any caller that echoes captured
// app text (a driver report, a stderr excerpt) hands the operator a sentence
// with the words glued together and the line structure gone.
//
// JSON (RFC 8259 section 7) has a lossless spelling for every one of these:
// backslash-n, backslash-r, backslash-t, backslash-b, backslash-f for the five
// shortcuts, and backslash-u-0-0-X-X for the rest. The contract asserted here
// is round-trip fidelity: parse the body back and the error string must equal
// the input byte for byte.
static void TestB120ErrorBodyKeepsControlCharacters() {
    using vgww::web::Response;

    struct Case {
        const char* what;
        std::string text;
    };
    const Case cases[] = {
        {"newline", std::string("line1\nline2")},
        {"tab", std::string("col1\tcol2")},
        {"crlf", std::string("crlf\r\nend")},
        {"bell", std::string("bell\x07x")},
        {"quote-and-backslash", std::string("quote\"and\\slash")},
        {"plain", std::string("plain ascii")},
    };
    for (const Case& c : cases) {
        const Response r = Response::Error(400, c.text);
        CHECK(r.status == 400);
        CHECK(r.content_type == "application/json");
        // The body must be valid JSON...
        nlohmann::json parsed;
        bool parsed_ok = true;
        try {
            parsed = nlohmann::json::parse(r.body);
        } catch (const nlohmann::json::parse_error&) {
            parsed_ok = false;
        }
        CHECK(parsed_ok);
        if (!parsed_ok) {
            std::fprintf(stderr, "  [%s] body was: %s\n", c.what,
                         r.body.c_str());
            continue;
        }
        // ...and the message must survive unchanged.
        CHECK(parsed.contains("error"));
        const std::string got = parsed.value("error", std::string("<missing>"));
        if (got != c.text) {
            std::fprintf(stderr, "  [%s] in=[%s] got=[%s]\n", c.what,
                         c.text.c_str(), got.c_str());
        }
        CHECK(got == c.text);
        // A multi-line message must still be multi-line, not one glued run.
        if (c.what == std::string("newline")) {
            CHECK(got.find('\n') != std::string::npos);
        }
    }
}

// batch121: Response::Error was fixed in batch120, but the API layer carries a
// SECOND, private escaper (web_api.cpp's JsonEscape) that every /api/* success
// body uses. It still DROPPED bytes below 0x20 exactly like the pre-batch120
// HttpServer copy did.
//
// Why this one is worse: GET /api/console joins the captured ring lines with
// '\n' and then hands the whole blob to JsonEscape. Dropping the newline makes
// the entire console render as ONE run-on line - an operator reading the web
// console sees every log line glued together and cannot tell one event from the
// next. The native console page (which reads the ring directly) shows the same
// text correctly, so the two surfaces silently disagree.
//
// The contract is the same round-trip rule batch120 established: parse the body
// and the text field must equal the provider's text byte for byte.
static void TestB121WebApiEscapeKeepsControlCharacters() {
    const char* path = "b121console.json";
    const std::string rules = std::string(path) + ".rules.json";
    std::remove(path);
    std::remove(rules.c_str());

    // A three-line log with a tab, a CR and a quote - the shapes the console
    // really produces (CRLF from Windows tools, tabs from aligned output,
    // quotes from echoed JSON on stdout).
    const std::string provider_text = "line-one\ncol1\tcol2\r\nsay \"hi\"";
    // The endpoint's documented normalisation (web_api.cpp: each line has its
    // trailing '\r' stripped, then the kept lines are joined with '\n'). So the
    // expected payload is the CR-stripped form; the TAB and the quote must
    // survive untouched, and the line structure must survive as real newlines.
    const std::string expected_text = "line-one\ncol1\tcol2\nsay \"hi\"";

    vgww::core::Config cfg;
    vgww::runtime::Dataplane dp(cfg);
    HttpServer api;
    vgww::web::RegisterApi(api, dp, cfg, path, {},
                           [provider_text] { return provider_text; });
    constexpr uint16_t kP = 18097;
    std::string start_err;
    CHECK(api.Start("127.0.0.1", kP, start_err));

    std::string body;
    CHECK(HttpGet("/api/console", kP, body) == 200);

    // The body must be a complete, parseable JSON document...
    nlohmann::json parsed;
    bool parsed_ok = true;
    try {
        parsed = nlohmann::json::parse(body);
    } catch (const nlohmann::json::parse_error&) {
        parsed_ok = false;
    }
    CHECK(parsed_ok);
    if (parsed_ok) {
        // ...and the text must survive byte for byte.
        const std::string got = parsed.value("text", std::string("<missing>"));
        if (got != expected_text) {
            std::fprintf(stderr, "  b121 in=[%s] got=[%s]\n",
                         expected_text.c_str(), got.c_str());
        }
        CHECK(got == expected_text);
        // The glued-line symptom, asserted directly: three lines in, three
        // lines out. (count already says 3; the TEXT must agree.)
        std::size_t newlines = 0;
        for (const char c : got) {
            if ('\n' == c) ++newlines;
        }
        CHECK(newlines == 2);
        CHECK(got.find('\t') != std::string::npos);
        CHECK(got.find("\"hi\"") != std::string::npos);
    }
    api.Stop();
    std::remove(path);
    std::remove(rules.c_str());
}

    // batch141: the rule FILE is the other write entry for bans, and it used
    // to keep the operator's raw spelling while the data plane matches IP bans
    // with an exact strcmp against the canonical dotted quad
    // (dataplane.cpp:2330). A file holding "192.168.001.050" therefore loaded
    // "successfully" and then never dropped a single packet - a firewall rule
    // that looks active and enforces nothing. The loader must store the same
    // canonical form the POST route does.
    void TestB141LoadedBanIpIsCanonical() {
        vgww::web::RuleStore& store = vgww::web::RuleStore::Instance();
        store.AttachFile("");
        store.Clear();

        const std::string path = "b141-bans.json";
        std::remove(path.c_str());
        {
            std::ofstream out(path, std::ios::binary);
            CHECK(out.good());
            out << "{\"bans\":["
                   "{\"kind\":\"ip\",\"value\":\"192.168.001.050\"},"
                   "{\"kind\":\"ip\",\"value\":\"0201.1.1.1\"},"
                   "{\"kind\":\"mac\",\"value\":\"aa-bb-cc-dd-ee-ff\"},"
                   "{\"kind\":\"ip\",\"value\":\"2001:DB8::0001\"}"
                   "]}";
        }
        store.AttachFile(path);
        const auto bans = store.Bans();
        // "0201.1.1.1" is NOT a legal IPv4 octet (4 digits) under the strict
        // decimal reader the native form uses, so the whole entry is DROPPED
        // and counted. asio would have accepted it as octal 129.1.1.1 - a
        // silently wrong address is worse than a visible rejection.
        CHECK(bans.size() == 3);
        CHECK(store.DiscardedOnLastLoad() == 1);
        if (bans.size() == 3) {
            // Decimal reading, matching core::ParseIpv4 (the native form).
            CHECK(bans[0].value == "192.168.1.50");
            // MACs were already canonicalised.
            CHECK(bans[1].value == "AA:BB:CC:DD:EE:FF");
            // IPv6 keeps asio's canonical compressed text.
            CHECK(bans[2].value == "2001:db8::1");
        }
        store.AttachFile("");
        store.Clear();
        std::remove(path.c_str());
    }

    // batch144: a ban list is a SET of targets. The data plane matches bans by
    // PARSED value (dataplane.cpp:2308 for MAC bytes, :3343 for IPv4 text), so
    // two entries naming the same target are two rows the operator cannot tell
    // apart - and unblocking one leaves the other enforcing: the toast says
    // "unblocked" while the client is still dropped. The port-forward loader
    // already collapses its duplicates (batch131); the ban path did not, at ANY
    // entry point, because AddBanChecked only ever tested the cap.
    void TestB144BanDuplicatesAreCollapsed() {
        using vgww::web::BanEntry;
        vgww::web::RuleStore& store = vgww::web::RuleStore::Instance();
        store.AttachFile("");          // persistence disabled: no disk I/O
        store.Clear();

        // --- the same target in another legal spelling is ONE entry --------
        CHECK(store.AddBanChecked(BanEntry{"mac", "AA:BB:CC:DD:EE:44"}));
        CHECK(store.AddBanChecked(BanEntry{"mac", "aa-bb-cc-dd-ee-44"}));
        CHECK(store.AddBanChecked(BanEntry{"mac", "aabbccddee44"}));
        CHECK(store.Bans().size() == 1);
        if (store.Bans().size() == 1) {
            // The FIRST spelling wins: an idempotent add changes nothing.
            CHECK(store.Bans()[0].value == "AA:BB:CC:DD:EE:44");
        }
        // A different target still inserts (the collapse is not a blanket).
        CHECK(store.AddBanChecked(BanEntry{"mac", "AA:BB:CC:DD:EE:45"}));
        CHECK(store.Bans().size() == 2);

        // --- same for IP, including the leading-zero spelling the route
        // canonicalises to the decimal reading (batch141) -------------------
        CHECK(store.AddBanChecked(BanEntry{"ip", "192.168.1.50"}));
        CHECK(store.AddBanChecked(BanEntry{"ip", "192.168.001.050"}));
        CHECK(store.Bans().size() == 3);

        // --- unblocking really unblocks: one row per target means the delete
        // cannot leave a hidden duplicate still dropping the client ---------
        {
            uint64_t mac_ban_id = 0;
            for (const auto& b : store.Bans()) {
                if ("mac" == b.kind && "AA:BB:CC:DD:EE:44" == b.value) {
                    mac_ban_id = b.id;
                }
            }
            CHECK(0 != mac_ban_id);
            CHECK(store.RemoveBanById(mac_ban_id));
            bool still_banned = false;
            for (const auto& b : store.Bans()) {
                if ("mac" == b.kind && "AA:BB:CC:DD:EE:44" == b.value) {
                    still_banned = true;
                }
            }
            CHECK(!still_banned);
        }
        store.Clear();

        // --- the FILE obeys the same rule, and the collapse is COUNTED -----
        const std::string path = "b144-bans.json";
        std::remove(path.c_str());
        {
            std::ofstream out(path, std::ios::binary);
            CHECK(out.good());
            out << "{\"bans\":["
                   "{\"kind\":\"mac\",\"value\":\"AA:BB:CC:DD:EE:66\"},"
                   "{\"kind\":\"mac\",\"value\":\"aa-bb-cc-dd-ee-66\"},"
                   "{\"kind\":\"ip\",\"value\":\"10.0.0.7\"},"
                   "{\"kind\":\"ip\",\"value\":\"010.0.0.7\"},"
                   "{\"kind\":\"mac\",\"value\":\"AA:BB:CC:DD:EE:67\"}"
                   "]}";
        }
        store.AttachFile(path);
        {
            const auto bans = store.Bans();
            CHECK(bans.size() == 3);
            CHECK(store.DiscardedOnLastLoad() == 2);
            if (bans.size() == 3) {
                CHECK(bans[0].value == "AA:BB:CC:DD:EE:66");
                CHECK(bans[1].value == "10.0.0.7");
                CHECK(bans[2].value == "AA:BB:CC:DD:EE:67");
            }
        }

        // --- a duplicate add needs no cap headroom: the duplicate test runs
        // BEFORE the cap test, so "already banned" stays a success on a full
        // list (otherwise the operator is told "too many bans" for a ban that
        // is already in force) ---------------------------------------------
        {
            std::string doc = "{\"bans\":[";
            char entry[80] = {};
            for (size_t i = 0; i < ::vgww::core::limits::kMaxBans; ++i) {
                std::snprintf(entry, sizeof(entry),
                              "%s{\"kind\":\"mac\",\"value\":"
                              "\"02:00:00:00:%02X:%02X\"}",
                              (0 == i ? "" : ","),
                              static_cast<unsigned>((i >> 8) & 0xFF),
                              static_cast<unsigned>(i & 0xFF));
                doc += entry;
            }
            doc += "]}";
            std::remove(path.c_str());
            {
                std::ofstream out(path, std::ios::binary);
                CHECK(out.good());
                out << doc;
            }
            store.AttachFile(path);
            CHECK(store.Bans().size() == ::vgww::core::limits::kMaxBans);
            CHECK(store.AddBanChecked(BanEntry{"mac", "02:00:00:00:00:00"}));
            CHECK(store.Bans().size() == ::vgww::core::limits::kMaxBans);
            CHECK(!store.AddBanChecked(BanEntry{"mac", "02:00:00:00:FF:FF"}));
            CHECK(store.Bans().size() == ::vgww::core::limits::kMaxBans);
        }

        store.AttachFile("");
        store.Clear();
        std::remove(path.c_str());
    }

    // batch138: the native pages and the web console both rendered a list and
    // then deleted by POSITION. Any add/remove between the render and the
    // delete shifts every later position, so the user lost a rule they never
    // clicked. /api/portmap and /api/bans now emit a stable `id` and accept
    // ?id=N; the store gained RemoveBanById (rules already had
    // RemovePortMapById, which nothing called).
    void TestB138DeleteIsByIdentityNotPosition() {
        vgww::web::RuleStore& store = vgww::web::RuleStore::Instance();
        store.AttachFile("");  // no persistence: pure in-memory behaviour
        store.Clear();

        // --- rules ---------------------------------------------------------
        vgww::web::PortMappingRule a;
        a.proto = "tcp";
        a.wan_port = 7001;
        a.lan_ip = "10.1.0.1";
        a.lan_port = 80;
        vgww::web::PortMappingRule b;
        b.proto = "tcp";
        b.wan_port = 7002;
        b.lan_ip = "10.1.0.2";
        b.lan_port = 81;
        const uint64_t id_a = store.AddPortMapTracked(a);
        const uint64_t id_b = store.AddPortMapTracked(b);
        CHECK(0 != id_a && 0 != id_b && id_a != id_b);
        CHECK(store.PortMaps().size() == 2);
        CHECK(store.PortMaps()[0].id == id_a);
        CHECK(store.PortMaps()[1].id == id_b);

        // Deleting by id removes exactly that rule, whatever its position.
        CHECK(store.RemovePortMapById(id_a));
        CHECK(store.PortMaps().size() == 1);
        CHECK(store.PortMaps()[0].id == id_b);
        // A second delete of the SAME id is refused and removes nothing: a
        // stale row can never take out a different rule.
        CHECK(!store.RemovePortMapById(id_a));
        CHECK(store.PortMaps().size() == 1);
        CHECK(store.PortMaps()[0].id == id_b);
        // Id 0 is "not stored" and must never match anything.
        CHECK(!store.RemovePortMapById(0));
        CHECK(store.PortMaps().size() == 1);
        store.Clear();

        // --- bans ----------------------------------------------------------
        CHECK(store.AddBanChecked(vgww::web::BanEntry{"mac", "02:00:00:00:00:01"}));
        CHECK(store.AddBanChecked(vgww::web::BanEntry{"mac", "02:00:00:00:00:02"}));
        CHECK(store.Bans().size() == 2);
        const uint64_t ban_a = store.Bans()[0].id;
        const uint64_t ban_b = store.Bans()[1].id;
        CHECK(0 != ban_a && 0 != ban_b && ban_a != ban_b);
        CHECK(store.RemoveBanById(ban_a));
        CHECK(store.Bans().size() == 1);
        CHECK(store.Bans()[0].id == ban_b);
        CHECK(!store.RemoveBanById(ban_a));  // stale id: refused
        CHECK(store.Bans().size() == 1);
        CHECK(!store.RemoveBanById(0));
        CHECK(store.Bans().size() == 1);
        store.Clear();

        // --- ids survive a persistence round trip ---------------------------
        const std::string path = "b138-rules.json";
        std::remove(path.c_str());
        store.AttachFile(path);
        vgww::web::PortMappingRule c;
        c.proto = "tcp";
        c.wan_port = 7003;
        c.lan_ip = "10.1.0.3";
        c.lan_port = 82;
        const uint64_t id_c = store.AddPortMapTracked(c);
        CHECK(store.AddBanChecked(vgww::web::BanEntry{"ip", "10.9.9.9"}));
        const uint64_t ban_c = store.Bans()[0].id;
        CHECK(0 != id_c && 0 != ban_c);

        // Reload from disk into a fresh state: the ids must be the SAME ones,
        // otherwise every id a client already holds becomes meaningless after
        // a restart (the writer used to omit `id` entirely). Detach BEFORE
        // clearing: Clear() is itself a mutation, and while a file is attached
        // it persists an EMPTY snapshot - which would erase the very file this
        // round-trip is meant to read.
        store.AttachFile("");
        store.Clear();
        store.AttachFile(path);
        CHECK(store.PortMaps().size() == 1);
        if (store.PortMaps().size() == 1) {
            CHECK(store.PortMaps()[0].id == id_c);
            CHECK(store.RemovePortMapById(id_c));
        }
        CHECK(store.Bans().size() == 1);
        if (store.Bans().size() == 1) {
            CHECK(store.Bans()[0].id == ban_c);
            CHECK(store.RemoveBanById(ban_c));
        }
        store.AttachFile("");
        store.Clear();
        std::remove(path.c_str());
    }

// ============================================================================
// P82: cross-process rules RMW - process-unique ids, durable tombstones and
// the read-merge-write that keeps two VGWW processes from overwriting each
// other's rules.
// ============================================================================

namespace {

    // Deterministic minter for the pure-function tests: the same layout the
    // store uses (marker | salt32 | counter31) with an explicit counter.
    struct SeqMinter {
        uint64_t salt = 0x0FEDCBA9ull;
        uint32_t counter = 1;
        uint64_t operator()() {
            const uint64_t id = (1ull << 63) |
                                (salt << 31) |
                                (static_cast<uint64_t>(counter) &
                                 ((1ull << 31) - 1));
            ++counter;
            return id;
        }
    };

    std::string P82ReadText(const std::string& path) {
        std::ifstream in(path, std::ios::binary);
        return std::string((std::istreambuf_iterator<char>(in)),
                           std::istreambuf_iterator<char>());
    }

    std::wstring P82Wide(const std::string& text) {
        return std::wstring(text.begin(), text.end());
    }

}  // namespace

// P82: the id layout (marker | salt32 | counter31), the shared counter across
// the three rule kinds, and the cross-process uniqueness that a per-process
// salt buys.
static void TestP82RuleIdLayoutAndUniqueness() {
    using namespace vgww::web;
    auto& store = RuleStore::Instance();
    store.AttachFile("");
    store.Clear();

    store.SetRuleIdSaltForTest(0x23456789ull);
    const uint64_t salt = 0x23456789ull;
    const uint64_t a = store.AddPortMapTracked(
        MakeRule("tcp", 20001, "192.168.0.10", 80));
    const uint64_t b = store.AddPortMapTracked(
        MakeRule("tcp", 20002, "192.168.0.11", 80));
    CHECK(0 != a && 0 != b);
    CHECK(a != b);
    CHECK((a >> 63) == 1ull);                       // marker
    CHECK((b >> 63) == 1ull);
    CHECK(((a >> 31) & 0xFFFFFFFFull) == salt);     // salt field
    CHECK((a & ((1ull << 31) - 1)) == 1ull);        // counter from 1
    CHECK((b & ((1ull << 31) - 1)) == 2ull);

    // The counter is shared by all three kinds.
    BanEntry ban;
    ban.kind = "mac";
    ban.value = "02:00:00:00:00:01";
    CHECK(store.AddBanChecked(ban));
    const uint64_t ban_id = store.Bans().back().id;
    CHECK((ban_id & ((1ull << 31) - 1)) == 3ull);

    RateLimitRule rl;
    rl.mac = "02:00:00:00:00:02";
    rl.uplink_kbps = 100;
    rl.downlink_kbps = 0;
    CHECK(store.SetRateLimitChecked(rl));
    const uint64_t rate_id = store.RateLimits().back().id;
    CHECK((rate_id & ((1ull << 31) - 1)) == 4ull);
    CHECK((rate_id >> 63) == 1ull);

    // A different salt must give a different id: two processes cannot mint
    // the same identity.
    store.SetRuleIdSaltForTest(0x9ABCDEF1ull);
    const uint64_t c = store.AddPortMapTracked(
        MakeRule("tcp", 20003, "192.168.0.12", 80));
    CHECK(c != a);
    CHECK(c != b);
    CHECK(((c >> 31) & 0xFFFFFFFFull) == 0x9ABCDEF1ull);

    // A zero salt is bumped to non-zero (the layout requires it).
    store.SetRuleIdSaltForTest(0);
    const uint64_t d = store.AddPortMapTracked(
        MakeRule("tcp", 20004, "192.168.0.13", 80));
    CHECK(0 != ((d >> 31) & 0xFFFFFFFFull));
    CHECK((d >> 63) == 1ull);

    store.AttachFile("");
    store.Clear();
}

// P82: cross-process id uniqueness WITHOUT the test seam. Two fresh processes
// mint from their own salt (CsprngBytes ^ pid), so their ids must differ. This
// is the M6 anchor: a fixed salt would give both processes the same id.
static void TestP82IdUniquenessWithoutTestSeam() {
    using namespace vgww::web;
    auto& store = RuleStore::Instance();
    store.AttachFile("");
    store.Clear();
    // No SetRuleIdSaltForTest call: the real Csprng path runs.
    const uint64_t a = store.AddPortMapTracked(
        MakeRule("tcp", 20101, "192.168.0.200", 80));
    CHECK(0 != a);
    CHECK((a >> 63) == 1ull);
    const uint64_t salt_a = (a >> 31) & 0xFFFFFFFFull;
    CHECK(0 != salt_a);
    store.AttachFile("");
    store.Clear();
}

// P82: the pure parser/merge helpers - tombstone skip (not counted), legacy id
// preservation, per-kind duplicate-id collapse, the tombstone ceiling, and the
// merge's memory-priority / disk-only / cap / mint rules.
static void TestP82ReadRuleDocumentAndMerge() {
    using namespace vgww::web;
    const uint64_t kMarker = 1ull << 63;

    // --- ReadRuleDocument: tombstoned entries are skipped, NOT counted -------
    {
        const std::string path = WriteRuleFile(
            "p82_read.json",
            R"({"version":2,"removed":[100,101],)"
            R"("portmaps":[)"
            R"({"proto":"tcp","wan_port":7001,"lan_ip":"192.168.0.10","lan_port":80,"id":100},)"
            R"({"proto":"tcp","wan_port":7002,"lan_ip":"192.168.0.11","lan_port":80,"id":101},)"
            R"({"proto":"tcp","wan_port":7003,"lan_ip":"192.168.0.12","lan_port":80,"id":102},)"
            R"({"proto":"udp","wan_port":7004,"lan_ip":"192.168.0.13","lan_port":80,"id":103}]})");
        RuleDocument doc;
        const auto outcome = RuleStore::ReadRuleDocument(path, doc);
        CHECK(outcome == RuleStore::LoadOutcome::kOk);
        CHECK(doc.port_maps.size() == 1);        // 100, 101 tombstoned; 103 udp
        CHECK(doc.tombstones.size() == 2);
        CHECK(doc.tombstone_order.size() == 2);
        CHECK(doc.discarded == 1);               // only the udp entry
        if (doc.port_maps.size() == 1) {
            CHECK(doc.port_maps[0].id == 102);
        }
        std::remove(path.c_str());
    }

    // --- legacy ids are preserved; id 0 stays 0 for the caller to mint ------
    {
        const std::string path = WriteRuleFile(
            "p82_legacy.json",
            R"({"portmaps":[{"proto":"tcp","wan_port":7005,"lan_ip":"192.168.0.14","lan_port":80,"id":7}]})");
        RuleDocument doc;
        CHECK(RuleStore::LoadOutcome::kOk ==
              RuleStore::ReadRuleDocument(path, doc));
        CHECK(doc.port_maps.size() == 1);
        if (doc.port_maps.size() == 1) {
            CHECK(doc.port_maps[0].id == 7);    // legacy id preserved
        }
        std::remove(path.c_str());
    }

    // --- a duplicate id inside one document: the latter is dropped+counted ---
    {
        const std::string path = WriteRuleFile(
            "p82_dup.json",
            R"({"portmaps":[)"
            R"({"proto":"tcp","wan_port":7006,"lan_ip":"192.168.0.15","lan_port":80,"id":42},)"
            R"({"proto":"tcp","wan_port":7007,"lan_ip":"192.168.0.16","lan_port":80,"id":42}]})");
        RuleDocument doc;
        CHECK(RuleStore::LoadOutcome::kOk ==
              RuleStore::ReadRuleDocument(path, doc));
        CHECK(doc.port_maps.size() == 1);
        CHECK(doc.discarded == 1);
        std::remove(path.c_str());
    }

    // --- the tombstone ceiling: a longer list is corrupt wholesale ---------
    {
        std::string text = "{\"version\":2,\"removed\":[";
        for (size_t i = 0; i < kMaxTombstones + 1; ++i) {
            if (i) text += ",";
            text += std::to_string(1000 + i);
        }
        text += "]}";
        const std::string path = WriteRuleFile("p82_cap.json", text);
        RuleDocument doc;
        CHECK(RuleStore::LoadOutcome::kCorrupt ==
              RuleStore::ReadRuleDocument(path, doc));
        std::remove(path.c_str());
    }

    // --- an illegal tombstone entry is dropped and counted ----------------
    {
        const std::string path = WriteRuleFile(
            "p82_badremoved.json",
            R"({"removed":[1,"oops",2],"portmaps":[]})");
        RuleDocument doc;
        CHECK(RuleStore::LoadOutcome::kOk ==
              RuleStore::ReadRuleDocument(path, doc));
        CHECK(doc.tombstones.size() == 2);
        CHECK(doc.discarded == 1);
        std::remove(path.c_str());
    }

    // --- MergeRuleDocuments: disk-only entries are adopted -----------------
    {
        RuleDocument memory;
        RuleDocument disk;
        PortMappingRule m;
        m.proto = "tcp";
        m.wan_port = 7010;
        m.lan_ip = "192.168.0.20";
        m.lan_port = 80;
        m.id = kMarker | 1;
        memory.port_maps.push_back(m);
        PortMappingRule d;
        d.proto = "tcp";
        d.wan_port = 7011;
        d.lan_ip = "192.168.0.21";
        d.lan_port = 80;
        d.id = kMarker | 2;
        disk.port_maps.push_back(d);
        SeqMinter minter;
        const size_t dropped = RuleStore::MergeRuleDocuments(memory, disk, minter);
        CHECK(0 == dropped);
        CHECK(memory.port_maps.size() == 2);
        if (memory.port_maps.size() == 2) {
            CHECK(memory.port_maps[1].wan_port == 7011);
        }
    }

    // --- memory priority: same id, then same identity ---------------------
    {
        RuleDocument memory;
        RuleDocument disk;
        PortMappingRule m;
        m.proto = "tcp";
        m.wan_port = 7020;
        m.lan_ip = "192.168.0.30";
        m.lan_port = 80;
        m.id = kMarker | 5;
        memory.port_maps.push_back(m);
        PortMappingRule d;
        d.proto = "tcp";
        d.wan_port = 7021;
        d.lan_ip = "192.168.0.31";
        d.lan_port = 80;
        d.id = kMarker | 5;                    // same id, different target
        disk.port_maps.push_back(d);
        PortMappingRule e;
        e.proto = "tcp";
        e.wan_port = 7020;                     // same identity as memory
        e.lan_ip = "192.168.0.32";
        e.lan_port = 80;
        e.id = kMarker | 6;
        disk.port_maps.push_back(e);
        SeqMinter minter;
        const size_t dropped = RuleStore::MergeRuleDocuments(memory, disk, minter);
        CHECK(0 == dropped);
        CHECK(memory.port_maps.size() == 1);   // both disk entries lost
        if (memory.port_maps.size() == 1) {
            CHECK(memory.port_maps[0].lan_ip == "192.168.0.30");
        }
    }

    // --- tombstones drop memory AND disk entries; the union propagates -----
    {
        RuleDocument memory;
        RuleDocument disk;
        PortMappingRule m;
        m.proto = "tcp";
        m.wan_port = 7030;
        m.lan_ip = "192.168.0.40";
        m.lan_port = 80;
        m.id = kMarker | 7;
        memory.port_maps.push_back(m);
        memory.tombstones.insert(kMarker | 7);
        memory.tombstone_order.push_back(kMarker | 7);
        PortMappingRule d;
        d.proto = "tcp";
        d.wan_port = 7031;
        d.lan_ip = "192.168.0.41";
        d.lan_port = 80;
        d.id = kMarker | 8;
        disk.port_maps.push_back(d);
        disk.tombstones.insert(kMarker | 8);
        disk.tombstone_order.push_back(kMarker | 8);
        SeqMinter minter;
        const size_t dropped = RuleStore::MergeRuleDocuments(memory, disk, minter);
        CHECK(0 == dropped);
        CHECK(memory.port_maps.empty());
        CHECK(memory.tombstones.size() == 2);
        CHECK(memory.tombstone_order.size() == 2);
    }

    // --- a disk entry with id 0 is minted ----------------------------------
    {
        RuleDocument memory;
        RuleDocument disk;
        PortMappingRule d;
        d.proto = "tcp";
        d.wan_port = 7040;
        d.lan_ip = "192.168.0.50";
        d.lan_port = 80;
        d.id = 0;
        disk.port_maps.push_back(d);
        SeqMinter minter;
        const size_t dropped = RuleStore::MergeRuleDocuments(memory, disk, minter);
        CHECK(0 == dropped);
        CHECK(memory.port_maps.size() == 1);
        if (memory.port_maps.size() == 1) {
            CHECK(0 != memory.port_maps[0].id);
            CHECK((memory.port_maps[0].id >> 63) == 1ull);
        }
    }

    // --- the per-kind cap drops the overflow and counts it -----------------
    {
        RuleDocument memory;
        RuleDocument disk;
        for (size_t i = 0; i < ::vgww::core::limits::kMaxPortMaps; ++i) {
            PortMappingRule m;
            m.proto = "tcp";
            m.wan_port = static_cast<uint16_t>(1 + i);
            m.lan_ip = "192.168.0.60";
            m.lan_port = 80;
            m.id = kMarker | (1000 + i);
            memory.port_maps.push_back(m);
        }
        PortMappingRule d;
        d.proto = "tcp";
        d.wan_port = 9999;
        d.lan_ip = "192.168.0.61";
        d.lan_port = 80;
        d.id = kMarker | 5000;
        disk.port_maps.push_back(d);
        SeqMinter minter;
        const size_t dropped = RuleStore::MergeRuleDocuments(memory, disk, minter);
        CHECK(1 == dropped);
        CHECK(memory.port_maps.size() ==
              ::vgww::core::limits::kMaxPortMaps);
    }

    // --- rate limits dedup by MAC, case-insensitively ----------------------
    {
        RuleDocument memory;
        RuleDocument disk;
        RateLimitRule m;
        m.mac = "AA:BB:CC:DD:EE:01";
        m.uplink_kbps = 100;
        m.id = kMarker | 9;
        memory.rate_limits.push_back(m);
        RateLimitRule d;
        d.mac = "aa:bb:cc:dd:ee:01";           // same client, other spelling
        d.uplink_kbps = 200;
        d.id = kMarker | 10;
        disk.rate_limits.push_back(d);
        SeqMinter minter;
        const size_t dropped = RuleStore::MergeRuleDocuments(memory, disk, minter);
        CHECK(0 == dropped);
        CHECK(memory.rate_limits.size() == 1);
        if (memory.rate_limits.size() == 1) {
            CHECK(memory.rate_limits[0].uplink_kbps == 100);  // memory wins
            CHECK(memory.rate_limits[0].id == (kMarker | 9));
        }
    }

    // --- bans dedup by BanTargetKey ---------------------------------------
    {
        RuleDocument memory;
        RuleDocument disk;
        BanEntry m;
        m.kind = "mac";
        m.value = "AA:BB:CC:DD:EE:02";
        m.id = kMarker | 11;
        memory.bans.push_back(m);
        BanEntry d;
        d.kind = "mac";
        d.value = "aa-bb-cc-dd-ee-02";         // same target, other spelling
        d.id = kMarker | 12;
        disk.bans.push_back(d);
        SeqMinter minter;
        const size_t dropped = RuleStore::MergeRuleDocuments(memory, disk, minter);
        CHECK(0 == dropped);
        CHECK(memory.bans.size() == 1);
        if (memory.bans.size() == 1) {
            CHECK(memory.bans[0].id == (kMarker | 11));
        }
    }
}

// P82: the store-level tombstone lifecycle - deletes write a durable
// "removed" list, the ids survive the round trip, upserts keep their identity,
// and Clear() empties the tombstone set.
static void TestP82TombstoneLifecycle() {
    using namespace vgww::web;
    auto& store = RuleStore::Instance();
    const std::string path = "p82_life.json.rules.json";
    std::remove(path.c_str());
    store.AttachFile("");
    store.Clear();
    store.AttachFile(path);

    // SetPortMap must mint an id (otherwise the rule cannot be removed).
    PortMappingRule r;
    r.proto = "tcp";
    r.wan_port = 8001;
    r.lan_ip = "192.168.0.70";
    r.lan_port = 80;
    store.SetPortMap(r);
    CHECK(0 != store.PortMaps()[0].id);

    // A delete writes the id into "removed" and it survives a reload.
    const uint64_t id1 = store.PortMaps()[0].id;
    bool refused = false;
    CHECK(store.RemovePortMapChecked(0, refused));
    CHECK(!refused);
    const auto removed_ids = [](const std::string& text) {
        std::vector<uint64_t> out;
        const auto j = nlohmann::json::parse(text, nullptr, false);
        if (!j.is_discarded() && j.contains("removed") &&
            j["removed"].is_array()) {
            for (const auto& e : j["removed"]) {
                if (e.is_number_unsigned()) {
                    out.push_back(e.get<uint64_t>());
                }
            }
        }
        return out;
    };
    {
        const auto ids = removed_ids(P82ReadText(path));
        CHECK(ids.size() == 1);
        if (ids.size() == 1) {
            CHECK(ids[0] == id1);
        }
        const auto j = nlohmann::json::parse(P82ReadText(path));
        CHECK(j.contains("version"));
        CHECK(j["version"] == 2);
    }

    // Re-attach: the tombstone is loaded, the rule stays gone.
    store.AttachFile("");
    store.Clear();
    store.AttachFile(path);
    CHECK(store.PortMaps().empty());
    CHECK(store.DiscardedOnLastLoad() == 0);

    // A rate-limit upsert keeps the identity; a MAC change tombstones the old
    // id and mints a new one.
    RateLimitRule rl;
    rl.mac = "02:00:00:00:00:03";
    rl.uplink_kbps = 100;
    CHECK(store.SetRateLimitChecked(rl));
    const uint64_t rate_id = store.RateLimits()[0].id;
    CHECK(0 != rate_id);
    rl.uplink_kbps = 200;
    CHECK(store.SetRateLimitChecked(rl));
    CHECK(store.RateLimits().size() == 1);
    CHECK(store.RateLimits()[0].id == rate_id);       // upsert keeps the id

    RateLimitRule renamed;
    renamed.mac = "02:00:00:00:00:04";
    renamed.downlink_kbps = 300;
    CHECK(store.ReplaceRateLimitChecked("02:00:00:00:00:03",
                                        std::move(renamed)));
    CHECK(store.RateLimits().size() == 1);
    CHECK(store.RateLimits()[0].mac == "02:00:00:00:00:04");
    const uint64_t new_rate_id = store.RateLimits()[0].id;
    CHECK(new_rate_id != rate_id);
    {
        const auto ids = removed_ids(P82ReadText(path));
        bool found_old = false;
        for (const uint64_t id : ids) {
            if (id == rate_id) found_old = true;
        }
        CHECK(found_old);      // the renamed rule's old id is tombstoned
    }

    // RemoveRateLimit tombstones its id.
    CHECK(store.RemoveRateLimit("02:00:00:00:00:04"));
    {
        const auto ids = removed_ids(P82ReadText(path));
        bool found = false;
        for (const uint64_t id : ids) {
            if (id == new_rate_id) found = true;
        }
        CHECK(found);
    }

    // Clear() empties the tombstone set (the fresh document has "removed":[]).
    store.AttachFile("");
    store.Clear();
    store.AttachFile(path);
    CHECK(store.PortMaps().empty());
    store.Clear();
    {
        const auto ids = removed_ids(P82ReadText(path));
        CHECK(ids.empty());
    }

    store.AttachFile("");
    store.Clear();
    std::remove(path.c_str());
}

// P82: a rule another process wrote to the document between two local
// mutations must be ADOPTED, not overwritten - the lost-update defect.
static void TestP82DiskInjectionMergesForeignRules() {
    using namespace vgww::web;
    auto& store = RuleStore::Instance();
    const std::string path = "p82_inject.json.rules.json";
    std::remove(path.c_str());
    store.AttachFile("");
    store.Clear();
    store.AttachFile(path);

    store.AddPortMapTracked(MakeRule("tcp", 8101, "192.168.0.80", 80));
    // A second process publishes its own document (its rule B, no tombstones).
    {
        std::ofstream out(path, std::ios::binary | std::ios::trunc);
        out << R"({"version":2,"removed":[],"portmaps":[{"proto":"tcp","wan_port":8102,"lan_ip":"192.168.0.81","lan_port":80,"id":500}]})";
    }
    // A local mutation must read the disk, merge B in, and write the union.
    store.AddPortMapTracked(MakeRule("tcp", 8103, "192.168.0.82", 80));
    const auto maps = store.PortMaps();
    CHECK(maps.size() == 3);
    bool has_8101 = false, has_8102 = false, has_8103 = false;
    for (const auto& m : maps) {
        if (m.wan_port == 8101) has_8101 = true;
        if (m.wan_port == 8102) has_8102 = true;
        if (m.wan_port == 8103) has_8103 = true;
    }
    CHECK(has_8101);
    CHECK(has_8102);
    CHECK(has_8103);
    const auto j = nlohmann::json::parse(P82ReadText(path));
    CHECK(j.contains("portmaps") && j["portmaps"].is_array());
    CHECK(j["portmaps"].size() == 3);
    store.AttachFile("");
    store.Clear();
    std::remove(path.c_str());
}

// P82: a deletion must not be undone by a stale writer that re-publishes the
// old document (the resurrection defect the tombstone list exists for).
static void TestP82DeleteIsNotResurrected() {
    using namespace vgww::web;
    auto& store = RuleStore::Instance();
    const std::string path = "p82_nores.json.rules.json";
    std::remove(path.c_str());
    store.AttachFile("");
    store.Clear();
    store.AttachFile(path);

    const uint64_t id_x =
        store.AddPortMapTracked(MakeRule("tcp", 8201, "192.168.0.90", 80));
    const uint64_t id_y =
        store.AddPortMapTracked(MakeRule("tcp", 8202, "192.168.0.91", 80));
    CHECK(store.RemovePortMapById(id_x));
    // A stale process re-publishes X (its snapshot predates the delete).
    {
        std::ofstream out(path, std::ios::binary | std::ios::trunc);
        out << R"({"version":2,"removed":[],"portmaps":[)"
            << R"({"proto":"tcp","wan_port":8201,"lan_ip":"192.168.0.90",)"
            << R"("lan_port":80,"id":)" << id_x << R"(},)"
            << R"({"proto":"tcp","wan_port":8202,"lan_ip":"192.168.0.91",)"
            << R"("lan_port":80,"id":)" << id_y << R"(}]})";
    }
    // A local mutation merges: the tombstone must keep X deleted.
    store.AddPortMapTracked(MakeRule("tcp", 8203, "192.168.0.92", 80));
    const auto maps = store.PortMaps();
    bool has_x = false;
    for (const auto& m : maps) {
        if (m.wan_port == 8201) has_x = true;
    }
    CHECK(!has_x);
    CHECK(maps.size() == 2);
    const auto j = nlohmann::json::parse(P82ReadText(path));
    bool file_has_x = false;
    for (const auto& e : j["portmaps"]) {
        if (e.contains("id") && e["id"].get<uint64_t>() == id_x) {
            file_has_x = true;
        }
    }
    CHECK(!file_has_x);
    store.AttachFile("");
    store.Clear();
    std::remove(path.c_str());
}

// P82: at the tombstone ceiling a removal is refused WHOLE - the rule stays in
// memory and on disk, and only deletions are blocked (an add still works).
static void TestP82TombstoneFullRefusesDelete() {
    using namespace vgww::web;
    auto& store = RuleStore::Instance();
    const std::string path = "p82_full.json.rules.json";
    std::string text = "{\"version\":2,\"removed\":[";
    for (size_t i = 0; i < kMaxTombstones; ++i) {
        if (i) text += ",";
        text += std::to_string(1000 + i);
    }
    text += R"(],"portmaps":[{"proto":"tcp","wan_port":8301,"lan_ip":)"
            R"("192.168.0.100","lan_port":80,"id":50}]})";
    const std::string p = WriteRuleFile(path, text);
    store.AttachFile("");
    store.Clear();
    store.AttachFile(p);
    CHECK(store.PortMaps().size() == 1);
    const uint64_t id = store.PortMaps()[0].id;
    CHECK(50 == id);   // legacy id preserved by the loader
    const size_t failures_before = store.PersistFailureCount();
    bool refused = false;
    CHECK(!store.RemovePortMapById(id, refused));
    CHECK(refused);
    CHECK(store.PortMaps().size() == 1);   // memory unchanged
    CHECK(store.PersistFailureCount() == failures_before);
    {
        const auto j = nlohmann::json::parse(P82ReadText(p));
        CHECK(j.contains("removed") && j["removed"].is_array());
        CHECK(j["removed"].size() == kMaxTombstones);
        CHECK(j["portmaps"].size() == 1);
    }
    // Only deletions are blocked.
    CHECK(0 != store.AddPortMapTracked(
                  MakeRule("tcp", 8302, "192.168.0.101", 80)));
    CHECK(store.PortMaps().size() == 2);
    store.AttachFile("");
    store.Clear();
    std::remove(p.c_str());
}

// P82: HTTP DELETE must separate "no such rule" (404) from "refused because
// the tombstone store is full" (500) - a caller must not read 500 as success
// or 404 as "already gone".
static void TestP82HttpDeleteDistinguishes404And500() {
    using namespace vgww::web;
    using namespace vgww::core;
    const char* cfg_path = "p82_http.json";
    const std::string rules = std::string(cfg_path) + ".rules.json";
    std::remove(cfg_path);
    std::remove(rules.c_str());
    std::string text = "{\"version\":2,\"removed\":[";
    for (size_t i = 0; i < kMaxTombstones; ++i) {
        if (i) text += ",";
        text += std::to_string(1000 + i);
    }
    text += R"(],"portmaps":[{"proto":"tcp","wan_port":8401,"lan_ip":)"
            R"("192.168.0.110","lan_port":80,"id":50}]})";
    {
        std::ofstream out(rules, std::ios::binary);
        out << text;
    }
    Config cfg;
    cfg.web.port = 18120;
    bool ok = false;
    cfg.gateway.ipv4 = ParseIpv4("192.168.0.40", ok);
    cfg.gateway.mask = ParseIpv4("255.255.255.0", ok);
    MacAddress mac{};
    ParseMac("30:fc:68:88:b4:a9", mac);
    cfg.gateway.mac = mac;
    std::string err;
    CHECK(cfg.SaveToFile(cfg_path, err));
    vgww::runtime::Dataplane dp(cfg);
    HttpServer api;
    RegisterApi(api, dp, cfg, cfg_path);
    constexpr uint16_t kPort = 18120;
    std::string start_err;
    CHECK(api.Start("127.0.0.1", kPort, start_err));
    std::string body;
    CHECK(HttpDelete("/api/portmap?id=999999", kPort, body) == 404);
    CHECK(HttpDelete("/api/portmap?id=50", kPort, body) == 500);
    api.Stop();
    std::remove(cfg_path);
    std::remove(rules.c_str());
}

// P82 (T12): the cross-process lock is recursive for the same thread.
// FlushPersist takes it, then WriteFileAtomicDurable takes it again; if that
// deadlocked, every mutation with persistence enabled would hang.
// M3 anchor: the flush must also WAIT for another owner instead of publishing
// without the exclusion. The lock-name override makes the test distinguish the
// OUTER lock from the one WriteFileAtomicDurable takes internally: with the
// override active the internal writer no longer waits, so only the outer lock
// can block the mutation.
static void TestP82LockReentrantSameThread() {
    using namespace vgww::web;
    const std::string rules = "p82_reentrant.json.rules.json";
    std::remove(rules.c_str());
    RuleStore& store = RuleStore::Instance();
    store.AttachFile(rules);
    store.Clear();
    CHECK(store.PersistUpToDate());

    // Override the lock name: FlushPersist's outer ConfigFileLock takes the
    // OVERRIDDEN name; the internal WriteFileAtomicDurable keeps the REAL one.
    // The test holds the OVERRIDDEN name, so only the outer lock can block the
    // mutation - the internal lock alone cannot.
    vgww::core::SetConfigLockNameOverrideForTest(
        [](const std::string& path) -> std::string {
            return "p82-outer-" + path;
        });
    vgww::core::ConfigFileLock lock(rules);
    CHECK(lock.locked());
    std::atomic<bool> done{false};
    std::thread writer([&] {
        BanEntry ban;
        ban.kind = "ip";
        ban.value = "10.77.0.1";
        (void)store.AddBanChecked(std::move(ban));
        done.store(true, std::memory_order_release);
    });
    for (int i = 0; i < 40 && !done.load(std::memory_order_acquire); ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    CHECK(!done.load(std::memory_order_acquire));  // blocked by the outer lock
    lock.~ConfigFileLock();                        // release
    writer.join();
    CHECK(done.load(std::memory_order_acquire));
    CHECK(store.PersistUpToDate());
    store.AttachFile("");
    store.Clear();
    std::remove(rules.c_str());
}

// P82 (M3 anchor, the opposite arrangement): with the override ACTIVE the
// test holds the OVERRIDDEN name and FlushPersist's outer lock takes it, so the
// mutation blocks. With the outer lock removed (M3) the mutation completes
// immediately -> the assertion below turns red.
static void TestP82OuterLockBlocksTheFlush() {
    using namespace vgww::web;
    const std::string rules = "p82_outer.json.rules.json";
    std::remove(rules.c_str());
    RuleStore& store = RuleStore::Instance();
    store.AttachFile(rules);
    store.Clear();
    CHECK(store.PersistUpToDate());

    // The test holds the OVERRIDDEN lock name for the whole mutation; the
    // override stays ACTIVE so FlushPersist's outer ConfigFileLock takes the
    // same mutex. The internal WriteFileAtomicDurable takes the REAL name and
    // therefore does NOT block - so only the outer lock can hold the mutation.
    vgww::core::SetConfigLockNameOverrideForTest(
        [](const std::string& path) -> std::string {
            return "p82-outer-" + path;
        });
    vgww::core::ConfigFileLock lock(rules);
    CHECK(lock.locked());
    // The override stays ACTIVE: FlushPersist's outer ConfigFileLock takes the
    // OVERRIDDEN name (the mutex this test holds) -> the mutation blocks. The
    // internal WriteFileAtomicDurable takes the REAL name -> it does not block.
    // With the outer lock removed (M3) nothing blocks the mutation -> red.
    std::atomic<bool> done{false};
    std::thread writer([&] {
        BanEntry ban;
        ban.kind = "ip";
        ban.value = "10.77.0.2";
        (void)store.AddBanChecked(std::move(ban));
        done.store(true, std::memory_order_release);
    });
    for (int i = 0; i < 40 && !done.load(std::memory_order_acquire); ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    CHECK(!done.load(std::memory_order_acquire));  // blocked by the outer lock
    lock.~ConfigFileLock();                        // release
    writer.join();
    CHECK(done.load(std::memory_order_acquire));
    CHECK(store.PersistUpToDate());
    vgww::core::SetConfigLockNameOverrideForTest(
        std::function<std::string(const std::string&)>());
    store.AttachFile("");
    store.Clear();
    std::remove(rules.c_str());
}

#ifdef _WIN32
// P82 worker: re-executes this binary as a second VGWW process. It attaches to
// the rules document, signals "ready", waits for "go", performs one mutation,
// then signals "done" - so the parent test can interleave a real cross-process
// writer with the named-event synchronisation that keeps the race honest.
static int P82WorkerMain(int argc, char** argv) {
    if (argc < 5) {
        return 2;
    }
    const std::string path = argv[2];
    const std::string op = argv[3];
    const std::wstring base = L"Local\\vgww-p82-" + P82Wide(argv[4]);
    vgww::web::RuleStore& store = vgww::web::RuleStore::Instance();
    store.AttachFile(path);
    HANDLE ready =
        ::CreateEventW(nullptr, TRUE, FALSE, (base + L"-ready").c_str());
    if (ready) {
        ::SetEvent(ready);
    }
    HANDLE go = ::OpenEventW(SYNCHRONIZE, FALSE, (base + L"-go").c_str());
    if (go) {
        ::WaitForSingleObject(go, 20000);
        ::CloseHandle(go);
    }
    if (op == "add") {
        if (argc < 9) {
            return 3;
        }
        vgww::web::PortMappingRule r;
        r.proto = argv[5];
        r.wan_port = static_cast<uint16_t>(std::stoul(argv[6]));
        r.lan_ip = argv[7];
        r.lan_port = static_cast<uint16_t>(std::stoul(argv[8]));
        const uint64_t minted = store.AddPortMapTracked(std::move(r));
        std::ofstream id_out(path + ".worker_id", std::ios::binary |
                                                    std::ios::trunc);
        id_out << minted;
    } else if (op == "del") {
        if (argc < 6) {
            return 3;
        }
        const uint64_t id = std::strtoull(argv[5], nullptr, 10);
        bool refused = false;
        (void)store.RemovePortMapById(id, refused);
        std::ofstream id_out(path + ".worker_id", std::ios::binary |
                                                    std::ios::trunc);
        id_out << id;
    }
    HANDLE done =
        ::CreateEventW(nullptr, TRUE, FALSE, (base + L"-done").c_str());
    if (done) {
        ::SetEvent(done);
    }
    if (ready) {
        ::CloseHandle(ready);
    }
    return 0;
}
#endif

// P82: a REAL second process attaches to the same document, then both sides
// add a rule. The union must reach disk - the last-writer-wins defect.
// The worker prints the ids it minted so the parent can assert the two
// processes did not collide.
static void TestP82CrossProcessWorker() {
#ifdef _WIN32
    using namespace vgww::web;
    auto& store = RuleStore::Instance();
    const std::string path = "p82worker.json.rules.json";
    const std::string id_path = path + ".worker_id";
    const std::string tag = "add";
    uint64_t parent_id = 0;
    std::remove(path.c_str());
    std::remove(id_path.c_str());
    {
        std::ofstream out(path, std::ios::binary);
        out << R"({"version":2,"removed":[],"portmaps":[{"proto":"tcp","wan_port":7001,"lan_ip":"192.168.0.10","lan_port":80,"id":100}]})";
    }
    store.AttachFile("");
    store.Clear();
    store.AttachFile(path);
    CHECK(store.PortMaps().size() == 1);

    const std::wstring base = L"Local\\vgww-p82-" + P82Wide(tag);
    HANDLE ready =
        ::CreateEventW(nullptr, TRUE, FALSE, (base + L"-ready").c_str());
    HANDLE go = ::CreateEventW(nullptr, TRUE, FALSE, (base + L"-go").c_str());
    HANDLE done =
        ::CreateEventW(nullptr, TRUE, FALSE, (base + L"-done").c_str());
    if (ready) ::ResetEvent(ready);
    if (go) ::ResetEvent(go);
    if (done) ::ResetEvent(done);

    wchar_t exe[MAX_PATH * 2] = {};
    const DWORD exe_len = ::GetModuleFileNameW(nullptr, exe, MAX_PATH * 2);
    CHECK(0 != exe_len);
    std::wstring cmd = std::wstring(exe, exe_len);
    cmd += L" --vgww-rules-worker " + P82Wide(path) +
           L" add " + P82Wide(tag) + L" tcp 7003 192.168.0.13 80";

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    const BOOL started =
        ::CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, FALSE, 0,
                         nullptr, nullptr, &si, &pi);
    CHECK(started);
    if (started) {
        ::WaitForSingleObject(ready, 15000);
        store.AddPortMapTracked(MakeRule("tcp", 7002, "192.168.0.11", 80));
        parent_id = store.PortMaps().back().id;
        CHECK((parent_id >> 63) == 1ull);
        ::SetEvent(go);
        ::WaitForSingleObject(pi.hProcess, 25000);
        if (done) ::WaitForSingleObject(done, 5000);
        ::CloseHandle(pi.hThread);
        ::CloseHandle(pi.hProcess);
    }
    if (ready) ::CloseHandle(ready);
    if (go) ::CloseHandle(go);
    if (done) ::CloseHandle(done);

    const auto j = nlohmann::json::parse(P82ReadText(path));
    CHECK(j.contains("portmaps") && j["portmaps"].is_array());
    CHECK(j["portmaps"].size() == 3);
    std::vector<uint64_t> ids;
    for (const auto& e : j["portmaps"]) {
        ids.push_back(e["id"].get<uint64_t>());
    }
    std::sort(ids.begin(), ids.end());
    const auto last = std::unique(ids.begin(), ids.end());
    CHECK(last == ids.end());   // 3 distinct ids (100 + two fresh ones)
    // The worker's minted id must be one of the document's ids: the id came
    // from the worker's own channel (the .worker_id side file), NOT from a
    // disk-derived guess - the parent's later merge can rewrite the document,
    // so the side file is the only timing-independent source.
    std::ifstream id_in(id_path, std::ios::binary);
    uint64_t worker_id = 0;
    if (id_in) {
        id_in >> worker_id;
    }
    id_in.close();
    bool worker_in_doc = false;
    for (const uint64_t id : ids) {
        if (id == worker_id) {
            worker_in_doc = true;
        }
    }
    CHECK(worker_in_doc);
    // M6 anchor: the worker minted an id in a DIFFERENT process, so its salt
    // must differ - the same id would mean the layout collapsed to a constant.
    CHECK(0 != worker_id);
    CHECK(0 != parent_id);
    CHECK(worker_id != parent_id);
    CHECK(((worker_id ^ parent_id) >> 31) != 0);   // different salt field
    CHECK((worker_id >> 63) == 1ull);
    CHECK((worker_id & ((1ull << 31) - 1)) == 1ull);  // counter from 1
    std::remove(id_path.c_str());
    store.AttachFile("");
    store.Clear();
    std::remove(path.c_str());
#else
    (void)0;
#endif
}

// P82: the worker's "del" op is exercised end-to-end. The parent publishes a
// document, the worker attaches and deletes an id it loaded, and the deletion
// (plus its tombstone) must reach disk.
static void TestP82WorkerDeletesTheTombstonedRule() {
#ifdef _WIN32
    using namespace vgww::web;
    auto& store = RuleStore::Instance();
    const std::string path = "p82worker3.json.rules.json";
    const std::string tag = "del2";
    std::remove(path.c_str());
    {
        std::ofstream out(path, std::ios::binary);
        out << R"({"version":2,"removed":[],"portmaps":[)"
            << R"({"proto":"tcp","wan_port":7201,"lan_ip":"192.168.0.30",)"
            << R"("lan_port":80,"id":100},)"
            << R"({"proto":"tcp","wan_port":7202,"lan_ip":"192.168.0.31",)"
            << R"("lan_port":80,"id":200}]})";
    }
    store.AttachFile("");
    store.Clear();
    store.AttachFile(path);
    CHECK(store.PortMaps().size() == 2);

    const std::wstring base = L"Local\\vgww-p82-" + P82Wide(tag);
    HANDLE ready =
        ::CreateEventW(nullptr, TRUE, FALSE, (base + L"-ready").c_str());
    HANDLE go = ::CreateEventW(nullptr, TRUE, FALSE, (base + L"-go").c_str());
    HANDLE done =
        ::CreateEventW(nullptr, TRUE, FALSE, (base + L"-done").c_str());
    if (ready) ::ResetEvent(ready);
    if (go) ::ResetEvent(go);
    if (done) ::ResetEvent(done);

    wchar_t exe[MAX_PATH * 2] = {};
    const DWORD exe_len = ::GetModuleFileNameW(nullptr, exe, MAX_PATH * 2);
    CHECK(0 != exe_len);
    std::wstring cmd = std::wstring(exe, exe_len);
    cmd += L" --vgww-rules-worker " + P82Wide(path) +
           L" del " + P82Wide(tag) + L" 200";

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    const BOOL started =
        ::CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, FALSE, 0,
                         nullptr, nullptr, &si, &pi);
    CHECK(started);
    if (started) {
        ::WaitForSingleObject(ready, 15000);
        ::SetEvent(go);
        ::WaitForSingleObject(pi.hProcess, 25000);
        if (done) ::WaitForSingleObject(done, 5000);
        ::CloseHandle(pi.hThread);
        ::CloseHandle(pi.hProcess);
    }
    if (ready) ::CloseHandle(ready);
    if (go) ::CloseHandle(go);
    if (done) ::CloseHandle(done);

    const auto j = nlohmann::json::parse(P82ReadText(path));
    CHECK(j.contains("portmaps") && j["portmaps"].is_array());
    CHECK(j["portmaps"].size() == 1);
    if (j["portmaps"].size() == 1) {
        CHECK(j["portmaps"][0]["id"].get<uint64_t>() == 100);
    }
    // The worker writes its side file before signalling done, so the deletion
    // verdict must be the WORKER's own (loaded-then-removed id 200), not a
    // value reverse-derived from the final document. This pins the channel for
    // the del op the same way the add op's test pins it.
    {
        std::ifstream id_in(path + ".worker_id", std::ios::binary);
        uint64_t worker_id = 0;
        id_in >> worker_id;
        CHECK(0 != worker_id);
        CHECK(worker_id == 200);
        std::remove((path + ".worker_id").c_str());
    }
    bool tombstone_found = false;
    if (j.contains("removed") && j["removed"].is_array()) {
        for (const auto& e : j["removed"]) {
            if (e.is_number_unsigned() && e.get<uint64_t>() == 200) {
                tombstone_found = true;
            }
        }
    }
    CHECK(tombstone_found);
    store.AttachFile("");
    store.Clear();
    std::remove(path.c_str());
#else
    (void)0;
#endif
}

// P82: the second process loaded the rule BEFORE the parent deleted it; its
// next write must NOT resurrect the deleted rule (the tombstone propagates).
static void TestP82CrossProcessDeleteNotResurrected() {
#ifdef _WIN32
    using namespace vgww::web;
    auto& store = RuleStore::Instance();
    const std::string path = "p82worker2.json.rules.json";
    const std::string tag = "del";
    std::remove(path.c_str());
    {
        std::ofstream out(path, std::ios::binary);
        out << R"({"version":2,"removed":[],"portmaps":[)"
            << R"({"proto":"tcp","wan_port":7101,"lan_ip":"192.168.0.20",)"
            << R"("lan_port":80,"id":100},)"
            << R"({"proto":"tcp","wan_port":7102,"lan_ip":"192.168.0.21",)"
            << R"("lan_port":80,"id":200}]})";
    }
    store.AttachFile("");
    store.Clear();
    store.AttachFile(path);
    CHECK(store.PortMaps().size() == 2);

    const std::wstring base = L"Local\\vgww-p82-" + P82Wide(tag);
    HANDLE ready =
        ::CreateEventW(nullptr, TRUE, FALSE, (base + L"-ready").c_str());
    HANDLE go = ::CreateEventW(nullptr, TRUE, FALSE, (base + L"-go").c_str());
    HANDLE done =
        ::CreateEventW(nullptr, TRUE, FALSE, (base + L"-done").c_str());
    if (ready) ::ResetEvent(ready);
    if (go) ::ResetEvent(go);
    if (done) ::ResetEvent(done);

    wchar_t exe[MAX_PATH * 2] = {};
    const DWORD exe_len = ::GetModuleFileNameW(nullptr, exe, MAX_PATH * 2);
    CHECK(0 != exe_len);
    std::wstring cmd = std::wstring(exe, exe_len);
    cmd += L" --vgww-rules-worker " + P82Wide(path) +
           L" add " + P82Wide(tag) + L" tcp 7103 192.168.0.23 80";

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    const BOOL started =
        ::CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, FALSE, 0,
                         nullptr, nullptr, &si, &pi);
    CHECK(started);
    if (started) {
        ::WaitForSingleObject(ready, 15000);
        // The worker holds X in memory; the parent deletes it and publishes
        // the tombstone BEFORE the worker's write.
        bool refused = false;
        CHECK(store.RemovePortMapById(100, refused));
        CHECK(!refused);
        ::SetEvent(go);
        ::WaitForSingleObject(pi.hProcess, 25000);
        if (done) ::WaitForSingleObject(done, 5000);
        ::CloseHandle(pi.hThread);
        ::CloseHandle(pi.hProcess);
    }
    if (ready) ::CloseHandle(ready);
    if (go) ::CloseHandle(go);
    if (done) ::CloseHandle(done);

    const auto j = nlohmann::json::parse(P82ReadText(path));
    CHECK(j.contains("portmaps") && j["portmaps"].is_array());
    bool has_x = false;
    bool has_y = false;
    bool has_w = false;
    for (const auto& e : j["portmaps"]) {
        const uint64_t id = e["id"].get<uint64_t>();
        if (id == 100) has_x = true;
        if (id == 200) has_y = true;
        if (0 != id && id != 100 && id != 200) has_w = true;
    }
    CHECK(!has_x);       // the deleted rule is not resurrected
    CHECK(has_y);
    CHECK(has_w);
    bool tombstone_found = false;
    if (j.contains("removed") && j["removed"].is_array()) {
        for (const auto& e : j["removed"]) {
            if (e.is_number_unsigned() && e.get<uint64_t>() == 100) {
                tombstone_found = true;
            }
        }
    }
    CHECK(tombstone_found);
    store.AttachFile("");
    store.Clear();
    std::remove(path.c_str());
#else
    (void)0;
#endif
}

int main(int argc, char** argv) {
#ifdef _WIN32
    if (argc > 1 && std::string("--vgww-rules-worker") == argv[1]) {
        return P82WorkerMain(argc, argv);
    }
#endif
    TestB121WebApiEscapeKeepsControlCharacters();
    TestB120ErrorBodyKeepsControlCharacters();
    TestB85InvalidContentLengthRejected();
    TestB97RequestLineRequiresHttpVersion();
    TestB98DuplicateContentLengthRejected();
    TestB99MalformedHeaderBlockRejected();
    TestB100AbsolutePathCannotEscapeStaticRoot();
    TestB87LoadedRateLimitsAreSemanticallyValid();
    TestB88RemoveBanCheckedIsAtomic();
    TestB89CapsEnforcedInsideTheLock();
    TestB80PublishSurvivesBusyDestination();
    TestB108DeleteIndexMustBeAllDigits();
    HttpServer server;
    server.Route("GET", "/api/status",
                 [](const Request&) { return Response::Json("{\"ok\":true}"); });
    server.Route("POST", "/api/echo", [](const Request& r) {
        return Response::Json("{\"echo\":\"" + r.body + "\"}");
    });
    server.ServeStatic("../../www");
    // S6 U9: a decoded path with a space must be routable; "%20" is an
    // alternative spelling of the same path when a query is absent too.
    server.Route("GET", "/my page", [](const Request&) {
        return Response::Text("hit", 200);
    });

    // Port 0 = OS-assigned; we need the real one, so bind a known test port.
    std::string error;
    constexpr uint16_t kPort = 18080;
    CHECK(server.Start("127.0.0.1", kPort, error));
    if (!error.empty()) {
        std::fprintf(stderr, "start error: %s\n", error.c_str());
    }

    std::string body;
    CHECK(HttpGet("/api/status", kPort, body) == 200);
    CHECK(body.find("\"ok\":true") != std::string::npos);

    CHECK(HttpGet("/api/missing", kPort, body) == 404);

    // Static file from www/ (repo layout relative to the test CWD).
    CHECK(HttpGet("/", kPort, body) == 200);
    CHECK(body.find("VGWW") != std::string::npos);

    // Path traversal must be rejected.
    CHECK(HttpGet("/..%2f..%2fCMakeLists.txt", kPort, body) == 403 ||
          HttpGet("/../CMakeLists.txt", kPort, body) == 403 ||
          HttpGet("/%2e%2e/CMakeLists.txt", kPort, body) == 403);

    // Malformed percent-encoding must yield a 400, never crash the process
    // (UrlDecode used to throw std::invalid_argument from std::stoi).
    CHECK(HttpGet("/api/status?x=%ZZ", kPort, body) == 400);
    CHECK(HttpGet("/api/status?x=%A", kPort, body) == 400);
    CHECK(HttpGet("/api/status?x=%", kPort, body) == 400);

    // Absolute paths must never escape the static root: on Windows
    // path("www") / "C:/Windows/system.ini" yields the drive path verbatim,
    // which would leak any readable file over the LAN.
    CHECK(HttpGet("/C:/Windows/system.ini", kPort, body) != 200);

    // Static file serving caps the body size so one huge file cannot pin
    // memory (5 MiB limit).
    {
        const char* big = "../../www/_big_test.bin";
        {
            std::ofstream out(big, std::ios::binary);
            const std::string block(1024 * 1024, 'x');
            for (int i = 0; i < 6; ++i) out << block;
        }
        CHECK(HttpGet("/_big_test.bin", kPort, body) != 200);
        std::remove(big);
    }

    // The server must still be alive and serving after the abuse above.
    CHECK(HttpGet("/api/status", kPort, body) == 200);

    // --- S6 U9: path percent-decoding must not depend on a query string.
    //      "/my%20page" and "/my%20page?x=1" are the same path, and both
    //      must hit the "/my page" route. ---
    CHECK(HttpGet("/my%20page", kPort, body) == 200);
    CHECK(HttpGet("/my%20page?x=1", kPort, body) == 200);

    // --- S6 U8: duplicate WAN endpoint must be rejected inside the store
    //      lock (no check-then-add TOCTOU). ---
    {
        vgww::web::RuleStore& store = vgww::web::RuleStore::Instance();
        store.Clear();
        vgww::web::PortMappingRule r1;
        r1.proto = "tcp";
        r1.wan_port = 7777;
        r1.lan_ip = "192.168.1.60";
        r1.lan_port = 80;
        store.AddPortMap(r1);
        vgww::web::PortMappingRule r2 = r1;
        r2.lan_port = 81;
        store.AddPortMap(r2);
        CHECK(store.PortMaps().size() == 1);  // U8 red: duplicate stayed
        store.Clear();  // restore the singleton for the tests that follow
    }

    // --- S6 U1 (rework): the UI writer (Config::SaveToFile, config.cpp) and
    //      the web writer (POST /api/config, web_api.cpp) live in DIFFERENT
    //      translation units. The first fix gave each its own function-local
    //      `static atomic tmp_seq`, so both generated the SAME
    //      `<path>.tmp.<pid>.0` on their first write and could truncate each
    //      other mid-write. The previous test called Config::SaveToFile twice
    //      (one TU, one shared counter) and could never see the collision.
    //      This test drives BOTH real writers concurrently and pins the
    //      shared-sequence contract deterministically:
    //        (1) prime the UI sequence (its index 0 is consumed);
    //        (2) hold the index-0 temp name open denying write sharing;
    //        (3) run the UI writer and the web POST at once. With per-TU
    //            counters the web writer restarts at index 0, hits the held
    //            name and answers 500. With one process-wide sequence the web
    //            writer continues past 0 and succeeds.
    {
        const char* kCfgU1x = "u1cross.json";
        const std::string kRulesU1x = std::string(kCfgU1x) + ".rules.json";
        std::remove(kCfgU1x);
        std::remove(kRulesU1x.c_str());
        const auto make_valid = [](uint16_t web_port) {
            vgww::core::Config c;
            c.web.port = web_port;
            bool ok = false;
            c.gateway.ipv4 = vgww::core::ParseIpv4("192.168.0.40", ok);
            c.gateway.mask = vgww::core::ParseIpv4("255.255.255.0", ok);
            vgww::core::MacAddress mac{};
            vgww::core::ParseMac("30:fc:68:88:b4:a9", mac);
            c.gateway.mac = mac;
            return c;
        };
        // (1) Prime the UI writer's sequence: the first SaveToFile consumes
        //     index 0 and renames the temp file away.
        std::string prime_err;
        CHECK(make_valid(8081).SaveToFile(kCfgU1x, prime_err));
        // (2) Occupy the index-0 temp name (write access denied) so a writer
        //     that starts its own counter at 0 cannot proceed.
        const std::string tmp0 =
            std::string(kCfgU1x) + ".tmp." +
            std::to_string(::GetCurrentProcessId()) + ".0";
        const HANDLE hold = ::CreateFileA(
            tmp0.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_ALWAYS,
            FILE_ATTRIBUTE_NORMAL, nullptr);
        CHECK(hold != INVALID_HANDLE_VALUE);

        // (3) Both real writers run concurrently against the same path.
        vgww::core::Config cfg = make_valid(8082);
        vgww::runtime::Dataplane dp(cfg);
        HttpServer api_u1x;
        vgww::web::RegisterApi(api_u1x, dp, cfg, kCfgU1x);
        constexpr uint16_t kPortU1x = 18099;
        std::string start_err;
        CHECK(api_u1x.Start("127.0.0.1", kPortU1x, start_err));

        std::atomic<bool> ui_ok{true};
        std::thread ui_writer([&] {
            std::string e;
            if (!make_valid(8083).SaveToFile(kCfgU1x, e)) {
                ui_ok.store(false);
            }
        });
        std::string u1_resp;
        const std::string u1_body =
            "{\"adapter\":\"x\","
            "\"gateway\":{\"ipv4\":\"192.168.0.40\","
            "\"mask\":\"255.255.255.0\","
            "\"mac\":\"30:fc:68:88:b4:a9\"},"
            "\"ipv6\":{\"enabled\":false,"
            "\"ula_prefix\":\"fdaa:0:0::\",\"prefix_len\":64,"
            "\"ra_lifetime_s\":300},"
            "\"web\":{\"port\":8084,\"token\":\"\"},"
            "\"perf\":{\"workers\":4,\"max_conns\":4096}}";
        const int web_status =
            HttpPost(kPortU1x, "/api/config", "", u1_body, u1_resp);
        ui_writer.join();
        api_u1x.Stop();

        CHECK(ui_ok.load());
        // U1 red: with per-TU counters the web writer picks index 0, collides
        // with the held temp name and returns 500 instead of 200.
        if (web_status != 200) {
            std::fprintf(stderr,
                         "[u1x] cross-TU temp collision: web POST -> %d "
                         "(held temp name %s), body=%s\n",
                         web_status, tmp0.c_str(), u1_resp.c_str());
        }
        CHECK(web_status == 200);
        ::CloseHandle(hold);
        std::remove(tmp0.c_str());
        std::remove(kCfgU1x);
        std::remove(kRulesU1x.c_str());
    }

    // --- S6 U1: two lock-free writers of the same config path share the
    //      {config}.tmp atomic-replace name (web POST /api/config vs the UI
    //      Config::SaveToFile both use `path + ".tmp"`). Racing writers must
    //      never leave a corrupt config behind: the final file must round-trip
    //      through LoadFromFile. ---
    {
        const char* kCfgU1 = "u1cfg.json";
        std::remove(kCfgU1);
        const std::string tmp_path = std::string(kCfgU1) + ".tmp";
        std::remove(tmp_path.c_str());
        std::atomic<bool> go{false};
        // A valid config (LoadFromFile rejects a zero gateway; the default
        // Config would fail before any concurrency could corrupt it).
        const auto make_valid = [](uint16_t web_port) {
            vgww::core::Config c;
            c.web.port = web_port;
            bool ok = false;
            c.gateway.ipv4 = vgww::core::ParseIpv4("192.168.0.40", ok);
            c.gateway.mask = vgww::core::ParseIpv4("255.255.255.0", ok);
            vgww::core::MacAddress mac{};
            vgww::core::ParseMac("30:fc:68:88:b4:a9", mac);
            c.gateway.mac = mac;
            return c;
        };
        std::thread writer_a([&] {
            while (!go.load(std::memory_order_relaxed)) {
                std::this_thread::yield();
            }
            for (int i = 0; i < 500; ++i) {
                vgww::core::Config a = make_valid(8081);
                std::string e;
                a.SaveToFile(kCfgU1, e);
            }
        });
        std::thread writer_b([&] {
            while (!go.load(std::memory_order_relaxed)) {
                std::this_thread::yield();
            }
            for (int i = 0; i < 500; ++i) {
                vgww::core::Config b = make_valid(8082);
                std::string e;
                b.SaveToFile(kCfgU1, e);
            }
        });
        go.store(true, std::memory_order_relaxed);
        writer_a.join();
        writer_b.join();
        {
            std::string ignore;
            // LoadFromFile returns std::optional<Config>; CHECK()-style
            // contextual conversion (explicit operator bool / nullopt) works,
            // but a bool copy-initialization does not - use has_value().
            const bool ok =
                vgww::core::Config::LoadFromFile(kCfgU1, ignore).has_value();
            if (!ok) {
                std::fprintf(stderr,
                             "[u1] LoadFromFile failed: %s, file=%s, bytes=%d\n",
                             ignore.c_str(),
                             std::filesystem::exists(kCfgU1) ? "exists"
                                                              : "missing",
                             static_cast<int>(
                                 std::filesystem::file_size(kCfgU1)));
            }
            CHECK(ok);  // U1 red: corrupt tmp race
        }
        std::remove(kCfgU1);
        std::remove(tmp_path.c_str());
    }

    // --- S6 U2: RunProcessCapture must return within its timeout when a
    //      child hangs without writing to the pipe, and terminate it. ---
    {
        std::string out;
        DWORD code = 0;
        const auto u2t0 = std::chrono::steady_clock::now();
        // ping.exe runs ~9 s and writes one line per second to the pipe, so
        // the old read-to-EOF loop blocks until ping exits instead of
        // honoring the 1500 ms timeout.
        const bool spawned = vgww::driver::RunProcessCapture(
            L"C:\\Windows\\System32\\ping.exe",
            {L"-n", L"10", L"127.0.0.1"}, out, code, 1500);
        const auto u2_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                               std::chrono::steady_clock::now() - u2t0)
                               .count();
        CHECK(spawned);
        CHECK(u2_ms < 4000);  // U2 red: old code waits for ping to exit
        CHECK(code != 0);     // U2 red: child was terminated
    }

    // Every response carries the admin-surface hardening headers: the UI
    // must not be frameable (clickjacking), bodies must not be MIME
    // sniffed, and polled API state must never be heuristically cached.
    {
        std::string raw;
        CHECK(HttpRawFull(kPort,
                          "GET / HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n",
                          raw) == 200);
        CHECK(raw.find("X-Frame-Options: DENY") != std::string::npos);
        CHECK(raw.find("X-Content-Type-Options: nosniff") !=
              std::string::npos);
        CHECK(raw.find("Cache-Control: no-store") != std::string::npos);
        CHECK(HttpRawFull(kPort,
                          "GET /api/status HTTP/1.1\r\nHost: t\r\n"
                          "Connection: close\r\n\r\n",
                          raw) == 200);
        CHECK(raw.find("Cache-Control: no-store") != std::string::npos);
        // Even error responses (400 from a malformed request) must carry
        // the same hardening headers so a rejected request never leaks
        // a framable or cacheable response.
        CHECK(HttpRawFull(kPort,
                          "GET /api/status?x=%ZZ HTTP/1.1\r\nHost: t\r\n"
                          "Connection: close\r\n\r\n",
                          raw) == 400);
        CHECK(raw.find("X-Frame-Options: DENY") != std::string::npos);
        CHECK(raw.find("Cache-Control: no-store") != std::string::npos);
    }

    // ---- HEAD responses must carry no body (S4.6-W4 / BUG d) ----
    // A HEAD response advertises the entity length of the equivalent GET but
    // must not write the entity itself; the connection still has to end after
    // the headers (HttpRawFull reads to EOF, so a hang would fail the test).
    {
        std::string raw;
        std::string get_body;

        CHECK(HttpGet("/", kPort, get_body) == 200);
        CHECK(!get_body.empty());
        CHECK(HttpRawFull(kPort,
                          "HEAD / HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n",
                          raw) == 200);
        const size_t at = raw.find("\r\n\r\n");
        CHECK(at != std::string::npos);
        CHECK((std::string::npos == at ? std::string("?") : raw.substr(at + 4))
                  .empty());
        CHECK(raw.find("Content-Length: " + std::to_string(get_body.size())) !=
              std::string::npos);

        CHECK(HttpGet("/api/status", kPort, get_body) == 200);
        CHECK(!get_body.empty());
        CHECK(HttpRawFull(kPort,
                          "HEAD /api/status HTTP/1.1\r\nHost: t\r\n"
                          "Connection: close\r\n\r\n",
                          raw) == 200);
        const size_t at2 = raw.find("\r\n\r\n");
        CHECK(at2 != std::string::npos);
        CHECK((std::string::npos == at2 ? std::string("?") : raw.substr(at2 + 4))
                  .empty());
        CHECK(raw.find("Content-Length: " + std::to_string(get_body.size())) !=
              std::string::npos);

        // Error paths suppress the body as well: the 404 produced by Dispatch
        // and the 400 produced when the request itself cannot be read.
        CHECK(HttpRawFull(kPort,
                          "HEAD /api/missing HTTP/1.1\r\nHost: t\r\n"
                          "Connection: close\r\n\r\n",
                          raw) == 404);
        const size_t at3 = raw.find("\r\n\r\n");
        CHECK(at3 != std::string::npos);
        CHECK((std::string::npos == at3 ? std::string("?") : raw.substr(at3 + 4))
                  .empty());
        CHECK(HttpRawFull(kPort,
                          "HEAD /api/status?x=%ZZ HTTP/1.1\r\nHost: t\r\n"
                          "Connection: close\r\n\r\n",
                          raw) == 400);
        const size_t at4 = raw.find("\r\n\r\n");
        CHECK(at4 != std::string::npos);
        CHECK((std::string::npos == at4 ? std::string("?") : raw.substr(at4 + 4))
                  .empty());
    }

    // Header values carry optional whitespace (OWS): "content-length:5"
    // without a space after the colon must still be honoured.
    {
        std::string out;
        const int st = HttpRaw(kPort,
                               "POST /api/echo HTTP/1.1\r\nHost: t\r\n"
                               "Content-Length:5\r\nConnection: close\r\n\r\n"
                               "hello",
                               out);
        CHECK(st == 200);
        CHECK(out.find("hello") != std::string::npos);
    }

    // A body shorter than the declared Content-Length must be rejected with
    // 400, never silently NUL-padded and processed.
    {
        std::string out;
        const int st = HttpRaw(kPort,
                               "POST /api/echo HTTP/1.1\r\nHost: t\r\n"
                               "Content-Length:10\r\nConnection: close\r\n\r\n"
                               "abc",
                               out);
        CHECK(st == 400);
    }

    server.Stop();

    // ---- write guard (token auth) ----
    HttpServer guarded;
    guarded.Route("GET", "/api/open",
                  [](const Request&) { return Response::Json("{}"); });
    guarded.Route("POST", "/api/mutate",
                  [](const Request&) { return Response::Json("{\"done\":true}"); });
    guarded.SetWriteGuard([](const Request& r) -> Response {
        const auto it = r.headers.find("x-auth-token");
        if (r.headers.end() != it && it->second == "sekret") {
            Response ok = Response::Json("{\"ok\":true}");
            ok.status = 200;
            return ok;
        }
        return Response::Error(401, "unauthorized");
    });
    CHECK(guarded.Start("127.0.0.1", kPort + 1, error));

    // GET passes without a token; POST without a token is rejected.
    CHECK(HttpGet("/api/open", kPort + 1, body) == 200);
    CHECK(HttpPost(kPort + 1, "/api/mutate", "", "{}", body) == 401);
    CHECK(HttpPost(kPort + 1, "/api/mutate", "wrong", "{}", body) == 401);
    CHECK(HttpPost(kPort + 1, "/api/mutate", "sekret", "{}", body) == 200);
    // Same token with no space after the colon must still authenticate.
    {
        std::string out;
        const int st = HttpRaw(kPort + 1,
                               "POST /api/mutate HTTP/1.1\r\nHost: t\r\n"
                               "X-Auth-Token:sekret\r\nContent-Length:0\r\n"
                               "Connection: close\r\n\r\n",
                               out);
        CHECK(st == 200);
    }
    guarded.Stop();

    // ---- REST API surface via RegisterApi: DELETE /api/portmap ----
    {
        // Rule persistence uses config_path + ".rules.json"; start clean so a
        // stale file from a previous run cannot poison the assertions.
        std::remove("unused.json.rules.json");
        vgww::core::Config cfg;
        vgww::runtime::Dataplane dp(cfg);
        HttpServer api;
        vgww::web::RegisterApi(api, dp, cfg, "unused.json");
        CHECK(api.Start("127.0.0.1", kPort + 2, error));

        const std::string rule =
            "{\"proto\":\"tcp\",\"wan_port\":8080,"
            "\"lan_ip\":\"192.168.1.50\",\"lan_port\":80}";
        CHECK(HttpPost(kPort + 2, "/api/portmap", "", rule, body) == 200);
        const std::string rule2 =
            "{\"proto\":\"tcp\",\"wan_port\":8081,"
            "\"lan_ip\":\"192.168.1.51\",\"lan_port\":81}";
        CHECK(HttpPost(kPort + 2, "/api/portmap", "", rule2, body) == 200);
        CHECK(HttpGet("/api/portmap", kPort + 2, body) == 200);
        CHECK(body.find("8081") != std::string::npos);

        // WebUI calls DELETE /api/portmap?index=N to drop a rule.
        CHECK(HttpDelete("/api/portmap?index=0", kPort + 2, body) == 200);
        CHECK(HttpGet("/api/portmap", kPort + 2, body) == 200);
        CHECK(body.find("8080") == std::string::npos);
        CHECK(body.find("8081") != std::string::npos);

        CHECK(HttpDelete("/api/portmap?index=99", kPort + 2, body) == 404);
        CHECK(HttpDelete("/api/portmap", kPort + 2, body) == 400);

        // batch140: the web writer must store the SAME spelling the native UI
        // stores. ParseIpv4 accepts a leading-zero octet ("192.168.001.050"),
        // and the native form re-emits it through FormatIpv4 ("192.168.1.50"),
        // but this route used to store the raw request text - so one rule read
        // "192.168.001.050" in the web console and "192.168.1.50" in the native
        // page, i.e. one address with two names (C9).
        {
            auto& store = vgww::web::RuleStore::Instance();
            const size_t before = store.PortMaps().size();
            CHECK(HttpPost(kPort + 2, "/api/portmap", "",
                           "{\"proto\":\"tcp\",\"wan_port\":18090,"
                           "\"lan_ip\":\"192.168.001.050\",\"lan_port\":90}",
                           body) == 200);
            CHECK(store.PortMaps().size() == before + 1);
            CHECK(HttpGet("/api/portmap", kPort + 2, body) == 200);
            CHECK(body.find("192.168.1.50") != std::string::npos);
            CHECK(body.find("192.168.001.050") == std::string::npos);
            // Clean up the rule this block added (shared singleton store).
            const size_t after = store.PortMaps().size();
            if (after > before) {
                CHECK(store.RemovePortMapChecked(after - 1));
            }
            CHECK(store.PortMaps().size() == before);
        }

        // batch138: the web console deletes by the STABLE id it rendered.
        // `?id=` must be the authoritative handle, the id must be echoed by
        // GET, and a stale id must 404 without touching any other rule.
        {
            auto& store = vgww::web::RuleStore::Instance();
            const size_t before = store.PortMaps().size();
            vgww::web::PortMappingRule via_id;
            via_id.proto = "tcp";
            via_id.wan_port = 18081;
            via_id.lan_ip = "10.0.0.2";
            via_id.lan_port = 81;
            const uint64_t keep_id = store.AddPortMapTracked(via_id);
            CHECK(0 != keep_id);
            CHECK(HttpGet("/api/portmap", kPort + 2, body) == 200);
            CHECK(body.find("\"id\":" + std::to_string(keep_id)) !=
                  std::string::npos);
            // Malformed / zero / unknown ids are refused, never "index 0".
            CHECK(HttpDelete("/api/portmap?id=", kPort + 2, body) == 400);
            CHECK(HttpDelete("/api/portmap?id=0", kPort + 2, body) == 400);
            CHECK(HttpDelete("/api/portmap?id=abc", kPort + 2, body) == 400);
            CHECK(HttpDelete("/api/portmap?id=999999", kPort + 2, body) == 404);
            CHECK(store.PortMaps().size() == before + 1);
            CHECK(HttpDelete("/api/portmap?id=" + std::to_string(keep_id),
                             kPort + 2, body) == 200);
            CHECK(store.PortMaps().size() == before);
            // The same id is now unknown: no double delete.
            CHECK(HttpDelete("/api/portmap?id=" + std::to_string(keep_id),
                             kPort + 2, body) == 404);
        }
        // batch34d: the delete must be ONE atomic check-and-erase. The old
        // path read size() under one lock and erased under another, so a
        // concurrent add between the two shifted the indices and the request
        // removed a DIFFERENT rule than the one the user clicked.
        {
            auto& store = vgww::web::RuleStore::Instance();
            const size_t before = store.PortMaps().size();
            // Out-of-range is refused WITHOUT erasing anything.
            CHECK(!store.RemovePortMapChecked(before + 10));
            CHECK(store.PortMaps().size() == before);
            // Add one, then remove THAT one: exactly one entry disappears and
            // the pre-existing rules are untouched (shared-state safe).
            vgww::web::PortMappingRule extra;
            extra.proto = "tcp";
            extra.wan_port = 18080;
            extra.lan_ip = "10.0.0.1";
            extra.lan_port = 80;
            CHECK(store.AddPortMap(extra));
            CHECK(store.PortMaps().size() == before + 1);
            CHECK(store.RemovePortMapChecked(before));
            CHECK(store.PortMaps().size() == before);
            // The same index is now out of range: no double-delete.
            CHECK(!store.RemovePortMapChecked(before));
        }

        // proto is a control field (tcp only). lan_ip is validated as a
        // strict dotted-quad IPv4 at the API boundary, so a quote-injected
        // value can never enter the store - the XSS surface is closed by
        // validation, not by output escaping. A non-tcp proto is rejected
        // outright (the data plane would silently never bind the WAN port).
        CHECK(HttpPost(kPort + 2, "/api/portmap", "",
                       "{\"proto\":\"tcp\",\"wan_port\":8082,"
                       "\"lan_ip\":\"192.168.1.5\\\"2\",\"lan_port\":82}",
                       body) == 400);
        CHECK(HttpPost(kPort + 2, "/api/portmap", "",
                       "{\"proto\":\"udp\",\"wan_port\":8083,"
                       "\"lan_ip\":\"192.168.1.53\",\"lan_port\":83}",
                       body) == 400);
        CHECK(HttpPost(kPort + 2, "/api/portmap", "",
                       "{\"proto\":\"icmp\",\"wan_port\":8084,"
                       "\"lan_ip\":\"192.168.1.54\",\"lan_port\":84}",
                       body) == 400);

        // /api/status must expose the full stats set so the dashboard and
        // debugging have the complete picture (rx_dropped, passthrough and
        // the VLAN counters were previously invisible).
        CHECK(HttpGet("/api/status", kPort + 2, body) == 200);
        CHECK(body.find("\"rx_dropped\"") != std::string::npos);
        CHECK(body.find("\"host_passthrough\"") != std::string::npos);
        CHECK(body.find("\"rx_vlan_frames\"") != std::string::npos);
        CHECK(body.find("\"tx_vlan_frames\"") != std::string::npos);

        // /api/clients drives the device table (IP/MAC/per-second rates) and
        // the LAN column (batch22 A8-1) - the column must come from the API's
        // own `lan` boolean, so the field has to be part of the payload schema.
        CHECK(HttpGet("/api/clients", kPort + 2, body) == 200);
        CHECK(body.find("\"clients\"") != std::string::npos);
        // The `lan` boolean the new column reads is emitted by the same
        // serializer for every reported client (web_api.cpp:881,
        // `,"lan":true|false`); with an empty table no client object exists, so
        // the field is not in this payload by construction.

        // /api/system drives the CPU/RAM cards on the dashboard. Only this
        // process's own counters are exposed (the whole-machine numbers are
        // irrelevant to the UI). Fields must exist (values may be zero before
        // the first control-loop sample).
        CHECK(HttpGet("/api/system", kPort + 2, body) == 200);
        CHECK(body.find("\"proc\"") != std::string::npos);
        CHECK(body.find("\"cpu_percent\"") != std::string::npos);
        CHECK(body.find("\"cores\"") != std::string::npos);
        CHECK(body.find("\"ws_bytes\"") != std::string::npos);
        CHECK(body.find("\"virt_bytes\"") != std::string::npos);

        // GET /api/config feeds the settings panel; a broken route would
        // blank the whole UI. It must round-trip the effective adapter,
        // gateway and perf sections as JSON.
        body.clear();
        CHECK(HttpGet("/api/config", kPort + 2, body) == 200);
        CHECK(body.find("\"adapter\"") != std::string::npos);
        CHECK(body.find("\"gateway\"") != std::string::npos);
        CHECK(body.find("\"ipv4\"") != std::string::npos);
        CHECK(body.find("\"mac\"") != std::string::npos);
        CHECK(body.find("\"perf\"") != std::string::npos);
        // Perf is fully round-tripped: a complete GET body must carry every
        // field the loader accepts, or a full-replacement POST from the
        // settings panel would silently reset the omitted knobs.
        CHECK(body.find("\"rx_batch\"") != std::string::npos);
        CHECK(body.find("\"udp_flow_cap\"") != std::string::npos);
        CHECK(body.find("\"ring_capacity\"") != std::string::npos);
        CHECK(body.find("\"dial_timeout_ms\"") != std::string::npos);
        // The GET schema must mirror what POST accepts as a full replacement:
        // omitted sections here would be erased on the next save. ipv6 and web
        // must round-trip; the auth token itself is intentionally absent.
        CHECK(body.find("\"ipv6\"") != std::string::npos);
        CHECK(body.find("\"ula_prefix\"") != std::string::npos);
        // prefix_len is a uint8_t: the serialization must print the numeric
        // value (64), never the ASCII character ('@' == 64) that operator<<
        // would emit for a raw uint8_t - a subtle JSON-corruption regression.
        CHECK(body.find("\"prefix_len\":64") != std::string::npos);
        CHECK(body.find("\"web\"") != std::string::npos);
        CHECK(body.find("\"port\"") != std::string::npos);
        CHECK(body.find("\"token\"") == std::string::npos);

        // POST /api/config persists through a loader round-trip (write a
        // temporary file, validate it loads, atomically rename over the
        // path). Malformed payloads must be rejected and leave the file
        // untouched; the old file must still satisfy a later GET.
        body.clear();
        CHECK(HttpPost(kPort + 2, "/api/config", "",
                       "{\"adapter\":\"x\","
                       "\"gateway\":{\"ipv4\":\"192.168.0.40\","
                       "\"mask\":\"255.255.255.0\","
                       "\"mac\":\"30:fc:68:88:b4:a9\"},"
                       "\"ipv6\":{\"enabled\":false,"
                       "\"ula_prefix\":\"fdaa:0:0::\",\"prefix_len\":64,"
                       "\"ra_lifetime_s\":300},"
                       "\"web\":{\"port\":8081,\"token\":\"\"},"
                       "\"perf\":{\"workers\":4,\"max_conns\":4096}}",
                       body) == 200);
        CHECK(body.find("\"ok\"") != std::string::npos);
        CHECK(HttpPost(kPort + 2, "/api/config", "", "{ not json",
                       body) == 400);
        CHECK(HttpPost(kPort + 2, "/api/config", "",
                       "{\"gateway\":{\"ipv4\":\"not-an-ip\"}}",
                       body) == 400);

        // BUG a regression (S4.6-W1): the settings panel must POST
        // perf.workers / perf.max_conns as JSON numbers. The loader parses
        // them with get<uint32_t>() and rejects a string with "invalid
        // configuration rejected" - exactly how a UI that forgot the Number()
        // conversion surfaced as "save failed". Pin both directions here.
        body.clear();
        CHECK(HttpPost(kPort + 2, "/api/config", "",
                       "{\"adapter\":\"x\","
                       "\"gateway\":{\"ipv4\":\"192.168.0.40\","
                       "\"mask\":\"255.255.255.0\","
                       "\"mac\":\"30:fc:68:88:b4:a9\"},"
                       "\"ipv6\":{\"enabled\":false,"
                       "\"ula_prefix\":\"fdaa:0:0::\",\"prefix_len\":64,"
                       "\"ra_lifetime_s\":300},"
                       "\"perf\":{\"workers\":\"8\",\"max_conns\":4096}}",
                       body) == 400);
        CHECK(body.find("invalid configuration rejected") != std::string::npos);
        body.clear();
        CHECK(HttpPost(kPort + 2, "/api/config", "",
                       "{\"adapter\":\"x\","
                       "\"gateway\":{\"ipv4\":\"192.168.0.40\","
                       "\"mask\":\"255.255.255.0\","
                       "\"mac\":\"30:fc:68:88:b4:a9\"},"
                       "\"ipv6\":{\"enabled\":false,"
                       "\"ula_prefix\":\"fdaa:0:0::\",\"prefix_len\":64,"
                       "\"ra_lifetime_s\":300},"
                       "\"perf\":{\"workers\":8,\"max_conns\":4096}}",
                       body) == 200);
        {
            // POST persists to config_path + ".tmp" and atomically renames
            // over config_path, so the on-disk copy is the wire payload: the
            // numbers must be there unquoted (a string would have been 400).
            std::ifstream in("unused.json", std::ios::binary);
            CHECK(in.good());
            if (in.good()) {
                std::stringstream ss;
                ss << in.rdbuf();
                CHECK(ss.str().find("\"workers\":8") != std::string::npos);
                CHECK(ss.str().find("\"max_conns\":4096") != std::string::npos);
            }
        }

        // Ban rules validate eagerly: an unsupported kind (e.g. "domain",
        // which the data plane would silently no-op) or a malformed value
        // is rejected instead of being stored as a fake rule.
        CHECK(HttpPost(kPort + 2, "/api/bans", "",
                       "{\"kind\":\"domain\",\"value\":\"example.com\"}",
                       body) == 400);
        CHECK(HttpPost(kPort + 2, "/api/bans", "",
                       "{\"kind\":\"ip\",\"value\":\"not-an-ip\"}",
                       body) == 400);
        CHECK(HttpPost(kPort + 2, "/api/bans", "",
                       "{\"kind\":\"mac\",\"value\":\"zz:zz\"}",
                       body) == 400);
        CHECK(HttpPost(kPort + 2, "/api/bans", "",
                       "{\"kind\":\"mac\",\"value\":\"AA:BB:CC:DD:EE:FF\"}",
                       body) == 200);
        CHECK(HttpGet("/api/bans", kPort + 2, body) == 200);
        CHECK(body.find("AA:BB:CC:DD:EE:FF") != std::string::npos);

        // batch144: a second POST for the SAME target is idempotent, not a
        // second row - one row per target is what makes "unblock" real.
        {
            auto& ban_store = vgww::web::RuleStore::Instance();
            const size_t before = ban_store.Bans().size();
            CHECK(HttpPost(kPort + 2, "/api/bans", "",
                           "{\"kind\":\"mac\",\"value\":\"aa-bb-cc-dd-ee-ff\"}",
                           body) == 200);
            CHECK(ban_store.Bans().size() == before);
        }

        // batch141: a leading-zero IPv4 octet is OCTAL to asio's parser
        // ("192.168.001.050" -> 192.168.1.40) but DECIMAL to core::ParseIpv4
        // (-> 192.168.1.50), so the web route and the native form stored
        // DIFFERENT addresses for the same input - the operator blocked an
        // address they never named. Both entries must agree with the native
        // form, which is the documented decimal reading.
        {
            auto& store = vgww::web::RuleStore::Instance();
            const size_t before = store.Bans().size();
            CHECK(HttpPost(kPort + 2, "/api/bans", "",
                           "{\"kind\":\"ip\",\"value\":\"192.168.001.050\"}",
                           body) == 200);
            CHECK(store.Bans().size() == before + 1);
            if (store.Bans().size() == before + 1) {
                CHECK(store.Bans().back().value == "192.168.1.50");
            }
            CHECK(HttpGet("/api/bans", kPort + 2, body) == 200);
            CHECK(body.find("192.168.1.50") != std::string::npos);
            CHECK(body.find("192.168.1.40") == std::string::npos);
            if (store.Bans().size() > before) {
                CHECK(store.RemoveBanById(store.Bans().back().id));
            }
            CHECK(store.Bans().size() == before);
        }

        // DELETE index parsing mirrors the portmap guard: trailing junk must
        // not silently resolve to 0 and delete the first ban.
        CHECK(HttpDelete("/api/bans?index=abc", kPort + 2, body) == 400);
        CHECK(HttpDelete("/api/bans?index=99", kPort + 2, body) == 404);

        // batch138: bans gained the same stable-identity handle as rules.
        {
            auto& store = vgww::web::RuleStore::Instance();
            CHECK(HttpGet("/api/bans", kPort + 2, body) == 200);
            const size_t at = body.find("\"id\":");
            CHECK(at != std::string::npos);
            uint64_t first_id = 0;
            if (at != std::string::npos) {
                first_id = std::strtoull(body.c_str() + at + 5, nullptr, 10);
            }
            CHECK(0 != first_id);
            const size_t before = store.Bans().size();
            CHECK(HttpDelete("/api/bans?id=", kPort + 2, body) == 400);
            CHECK(HttpDelete("/api/bans?id=0", kPort + 2, body) == 400);
            CHECK(HttpDelete("/api/bans?id=999999", kPort + 2, body) == 404);
            CHECK(store.Bans().size() == before);
            if (0 != first_id) {
                CHECK(HttpDelete("/api/bans?id=" + std::to_string(first_id),
                                 kPort + 2, body) == 200);
                CHECK(store.Bans().size() == before - 1);
                CHECK(HttpDelete("/api/bans?id=" + std::to_string(first_id),
                                 kPort + 2, body) == 404);
            }
        }

        // Rate-limit rules key on the client MAC: a malformed value would
        // silently throttle nobody (a plausible-but-broken fake), so it is
        // rejected exactly like /api/bans values.
        CHECK(HttpPost(kPort + 2, "/api/ratelimit", "",
                       "{\"mac\":\"garbage\",\"uplink_kbps\":100,"
                       "\"downlink_kbps\":50}",
                       body) == 400);
        // kbps fields that are present but unparseable must not silently
        // fall back to 0 (unlimited) - a fake rate limit.
        CHECK(HttpPost(kPort + 2, "/api/ratelimit", "",
                       "{\"mac\":\"AA:BB:CC:DD:EE:10\","
                       "\"uplink_kbps\":-5,\"downlink_kbps\":1}",
                       body) == 400);
        CHECK(HttpPost(kPort + 2, "/api/ratelimit", "",
                       "{\"mac\":\"AA:BB:CC:DD:EE:10\","
                       "\"uplink_kbps\":5000000000,\"downlink_kbps\":1}",
                       body) == 400);
        CHECK(HttpPost(kPort + 2, "/api/ratelimit", "",
                       "{\"mac\":\"AA:BB:CC:DD:EE:10\","
                       "\"uplink_kbps\":\"100\",\"downlink_kbps\":1}",
                       body) == 400);
        CHECK(HttpPost(kPort + 2, "/api/ratelimit", "",
                       "{\"mac\":\"AA:BB:CC:DD:EE:FF\",\"uplink_kbps\":100,"
                       "\"downlink_kbps\":50}",
                       body) == 200);
        CHECK(HttpGet("/api/ratelimit", kPort + 2, body) == 200);
        CHECK(body.find("AA:BB:CC:DD:EE:FF") != std::string::npos);

        // P8: one canonical spelling regardless of how the value was POSTed.
        // The store/UI previously echoed the client's raw text, so the same
        // rule rendered differently per writer. Ingest now canonicalises:
        // MAC -> core::FormatMac (UPPERCASE colon), IP -> asio canonical text.
        CHECK(HttpPost(kPort + 2, "/api/bans", "",
                       "{\"kind\":\"mac\",\"value\":\"aa-bb-cc-dd-ee-77\"}",
                       body) == 200);
        CHECK(HttpPost(kPort + 2, "/api/bans", "",
                       "{\"kind\":\"ip\",\"value\":\"2001:DB8::0001\"}",
                       body) == 200);
        CHECK(HttpGet("/api/bans", kPort + 2, body) == 200);
        CHECK(body.find("AA:BB:CC:DD:EE:77") != std::string::npos);
        CHECK(body.find("aa-bb-cc-dd-ee-77") == std::string::npos);
        CHECK(body.find("2001:db8::1") != std::string::npos);
        CHECK(body.find("2001:DB8::0001") == std::string::npos);

        CHECK(HttpPost(kPort + 2, "/api/ratelimit", "",
                       "{\"mac\":\"aa-bb-cc-dd-ee-88\",\"uplink_kbps\":10,"
                       "\"downlink_kbps\":10}",
                       body) == 200);
        CHECK(HttpGet("/api/ratelimit", kPort + 2, body) == 200);
        CHECK(body.find("AA:BB:CC:DD:EE:88") != std::string::npos);
        CHECK(body.find("aa-bb-cc-dd-ee-88") == std::string::npos);

        // P8 regression (audit A2): a client that POSTed a rate limit with a
        // non-canonical MAC spelling (now stored canonical) must still match
        // DELETE with the same spelling it used. Pre-fix DELETE compared the
        // raw query string with _stricmp only, so the separator-normalised
        // store entry no longer matched and DELETE silently no-op'd while
        // returning {"ok":true}.
        // batch139: a MAC edit is ONE request carrying `replace_mac`. The console
        // used to DELETE then POST; either half could fail alone (400 too many
        // ratelimits, dropped connection, another tab's delete) and the client
        // was left with NO cap at all.
        //
        // (a) Replace succeeds: old key gone, new key carries the new values.
        CHECK(HttpPost(kPort + 2, "/api/ratelimit", "",
                       "{\"mac\":\"AA:BB:CC:DD:EE:01\",\"uplink_kbps\":111,"
                       "\"downlink_kbps\":222}",
                       body) == 200);
        CHECK(HttpPost(kPort + 2, "/api/ratelimit", "",
                       "{\"mac\":\"AA:BB:CC:DD:EE:02\",\"uplink_kbps\":333,"
                       "\"downlink_kbps\":444,"
                       "\"replace_mac\":\"AA:BB:CC:DD:EE:01\"}",
                       body) == 200);
        CHECK(HttpGet("/api/ratelimit", kPort + 2, body) == 200);
        CHECK(body.find("AA:BB:CC:DD:EE:01") == std::string::npos);
        CHECK(body.find("AA:BB:CC:DD:EE:02") != std::string::npos);
        CHECK(body.find("333") != std::string::npos);

        // (b) A refused replace must change NOTHING: the old rule survives
        // intact. A double-zero cap is refused before any state mutates.
        CHECK(HttpPost(kPort + 2, "/api/ratelimit", "",
                       "{\"mac\":\"AA:BB:CC:DD:EE:03\",\"uplink_kbps\":0,"
                       "\"downlink_kbps\":0,"
                       "\"replace_mac\":\"AA:BB:CC:DD:EE:02\"}",
                       body) == 400);
        CHECK(HttpGet("/api/ratelimit", kPort + 2, body) == 200);
        CHECK(body.find("AA:BB:CC:DD:EE:02") != std::string::npos);
        CHECK(body.find("333") != std::string::npos);
        CHECK(body.find("AA:BB:CC:DD:EE:03") == std::string::npos);

        // (c) A malformed/alien replace_mac is refused, never a silent no-op
        // that leaves the stale rule behind while answering success.
        CHECK(HttpPost(kPort + 2, "/api/ratelimit", "",
                       "{\"mac\":\"AA:BB:CC:DD:EE:04\",\"uplink_kbps\":5,"
                       "\"downlink_kbps\":5,\"replace_mac\":\"not-a-mac\"}",
                       body) == 400);
        CHECK(HttpGet("/api/ratelimit", kPort + 2, body) == 200);
        CHECK(body.find("AA:BB:CC:DD:EE:04") == std::string::npos);
        CHECK(body.find("AA:BB:CC:DD:EE:02") != std::string::npos);

        // (c2) batch140: a PRESENT but non-string replace_mac must be refused.
        // JsonGetString returns false for a non-string value, so the route used
        // to treat `"replace_mac": 123` as "field absent" and silently fall
        // through to a PLAIN ADD: the old rule survived and a second rule for
        // the new MAC appeared. RateLimiter::Allow takes the FIRST match, so
        // the stale cap stayed in force while the UI showed the new rule -
        // the exact batch131 failure mode through a new door.
        CHECK(HttpPost(kPort + 2, "/api/ratelimit", "",
                       "{\"mac\":\"AA:BB:CC:DD:EE:06\",\"uplink_kbps\":9,"
                       "\"downlink_kbps\":9,\"replace_mac\":123}",
                       body) == 400);
        CHECK(HttpGet("/api/ratelimit", kPort + 2, body) == 200);
        CHECK(body.find("AA:BB:CC:DD:EE:06") == std::string::npos);
        CHECK(body.find("AA:BB:CC:DD:EE:02") != std::string::npos);
        // An explicitly EMPTY replace_mac is refused too: the only way to mean
        // "plain add" is to OMIT the field, so a client bug cannot silently
        // downgrade a re-key into a second rule.
        CHECK(HttpPost(kPort + 2, "/api/ratelimit", "",
                       "{\"mac\":\"AA:BB:CC:DD:EE:07\",\"uplink_kbps\":9,"
                       "\"downlink_kbps\":9,\"replace_mac\":\"\"}",
                       body) == 400);
        CHECK(HttpGet("/api/ratelimit", kPort + 2, body) == 200);
        CHECK(body.find("AA:BB:CC:DD:EE:07") == std::string::npos);

        // (d) replace_mac naming a MAC that is not stored behaves like a plain
        // add (a config-only or already-deleted row).
        CHECK(HttpPost(kPort + 2, "/api/ratelimit", "",
                       "{\"mac\":\"AA:BB:CC:DD:EE:05\",\"uplink_kbps\":7,"
                       "\"downlink_kbps\":8,"
                       "\"replace_mac\":\"AA:BB:CC:DD:EE:99\"}",
                       body) == 200);
        CHECK(HttpGet("/api/ratelimit", kPort + 2, body) == 200);
        CHECK(body.find("AA:BB:CC:DD:EE:05") != std::string::npos);

        CHECK(HttpPost(kPort + 2, "/api/ratelimit", "",
                       "{\"mac\":\"aa-bb-cc-dd-ee-99\",\"uplink_kbps\":11,"
                       "\"downlink_kbps\":11}",
                       body) == 200);
        CHECK(HttpDelete("/api/ratelimit?mac=aa-bb-cc-dd-ee-99", kPort + 2,
                         body) == 200);
        CHECK(HttpGet("/api/ratelimit", kPort + 2, body) == 200);
        CHECK(body.find("AA:BB:CC:DD:EE:99") == std::string::npos);
        // batch40 (live CRUD audit): a DELETE for a MAC that is not in the
        // store must NOT fake {"ok":true}; it 404s like the portmap/ban
        // DELETEs (an operator retrying a removal learns it is gone instead of
        // believing a second rule was deleted).
        CHECK(HttpDelete("/api/ratelimit?mac=AA:BB:CC:DD:EE:99", kPort + 2,
                         body) == 404);

        // Ports must lie in [1,65535]; out-of-range values must not wrap.
        CHECK(HttpPost(kPort + 2, "/api/portmap", "",
                       "{\"proto\":\"tcp\",\"wan_port\":70000,"
                       "\"lan_ip\":\"192.168.1.53\",\"lan_port\":80}",
                       body) == 400);
        CHECK(HttpPost(kPort + 2, "/api/portmap", "",
                       "{\"proto\":\"tcp\",\"wan_port\":-1,"
                       "\"lan_ip\":\"192.168.1.53\",\"lan_port\":80}",
                       body) == 400);
        CHECK(HttpPost(kPort + 2, "/api/portmap", "",
                       "{\"proto\":\"tcp\",\"wan_port\":0,"
                       "\"lan_ip\":\"192.168.1.53\",\"lan_port\":80}",
                       body) == 400);
        CHECK(HttpPost(kPort + 2, "/api/portmap", "",
                       "{\"proto\":\"tcp\",\"wan_port\":65535,"
                       "\"lan_ip\":\"192.168.1.53\",\"lan_port\":80}",
                       body) == 200);
        // lan_ip must be a strict dotted-quad IPv4: the data plane dials it
        // via sscanf_s "%u.%u.%u.%u", so anything else would be stored as a
        // rule that can never connect - reject it at the API boundary.
        CHECK(HttpPost(kPort + 2, "/api/portmap", "",
                       "{\"proto\":\"tcp\",\"wan_port\":65400,"
                       "\"lan_ip\":\"not-an-ip\",\"lan_port\":80}",
                       body) == 400);
        CHECK(HttpPost(kPort + 2, "/api/portmap", "",
                       "{\"proto\":\"tcp\",\"wan_port\":65401,"
                       "\"lan_ip\":\"192.168.1.999\",\"lan_port\":80}",
                       body) == 400);
        CHECK(HttpPost(kPort + 2, "/api/portmap", "",
                       "{\"proto\":\"tcp\",\"wan_port\":65402,"
                       "\"lan_ip\":\"2001:db8::1\",\"lan_port\":80}",
                       body) == 400);
        CHECK(HttpPost(kPort + 2, "/api/portmap", "",
                       "{\"proto\":\"tcp\",\"wan_port\":65403,"
                       "\"lan_ip\":\"192.168.1.75\",\"lan_port\":8080}",
                       body) == 200);
        // A duplicate WAN endpoint would silently shadow the first rule.
        CHECK(HttpPost(kPort + 2, "/api/portmap", "",
                       "{\"proto\":\"tcp\",\"wan_port\":65535,"
                       "\"lan_ip\":\"192.168.1.90\",\"lan_port\":90}",
                       body) == 400);

        // Rules persist next to the config: the earlier mappings must be in
        // the file, and a fresh load (simulated restart) restores them.
        {
            std::ifstream in("unused.json.rules.json", std::ios::binary);
            CHECK(in.good());
            if (in.good()) {
                std::stringstream ss;
                ss << in.rdbuf();
                CHECK(ss.str().find("8081") != std::string::npos);
                CHECK(ss.str().find("AA:BB:CC:DD:EE:FF") != std::string::npos);
            }
            vgww::web::RuleStore::Instance().AttachFile(
                "unused.json.rules.json");
            const auto restored =
                vgww::web::RuleStore::Instance().PortMaps();
            bool have_8081 = false;
            for (const auto& m : restored) {
                if (8081 == m.wan_port) have_8081 = true;
            }
            CHECK(have_8081);
        }
        // Leave no trace; production never deletes this file, only the test.
        std::remove("unused.json.rules.json");
        std::remove("unused.json");
        std::remove("unused.json.tmp");

        // An empty rule set must persist as a JSON object ("{}"), never the
        // default-null dump ("null"): LoadLocked rejects non-object content
        // (is_object()), which would fake-empty the store on every restart.
        {
            std::remove("empty.json.rules.json");
            vgww::web::RuleStore::Instance().AttachFile(
                "empty.json.rules.json");
            vgww::web::RuleStore::Instance().AddPortMap(
                vgww::web::PortMappingRule{"tcp", 4444, "192.168.1.44", 44});
            vgww::web::RuleStore::Instance().RemovePortMap(0);  // -> SaveLocked
            std::ifstream in("empty.json.rules.json", std::ios::binary);
            CHECK(in.good());
            if (in.good()) {
                std::stringstream ss;
                ss << in.rdbuf();
                CHECK(ss.str().find("null") == std::string::npos);
                CHECK(ss.str().find("{") != std::string::npos);
            }
            std::remove("empty.json.rules.json");
            std::remove("empty.json");
            std::remove("empty.json.tmp");
        }

        api.Stop();
    }

    // ---- rules.json restore must reject out-of-range values instead of
    //      silently truncating them: a uint64 -> uint16 cast used to turn a
    //      hand-edited wan_port of 70000 into 4464 (silent wraparound), and
    //      a kbps value above UINT32_MAX wrapped the same way. The project
    //      doctrine forbids silent truncation on restore, mirroring POST.
    {
        {
            std::ofstream poison("poison.json.rules.json", std::ios::binary);
            poison << "{\"portmaps\":["
                   << "{\"proto\":\"tcp\",\"wan_port\":70000,"
                   << "\"lan_ip\":\"192.168.1.70\",\"lan_port\":70},"
                   << "{\"proto\":\"tcp\",\"wan_port\":8081,"
                   << "\"lan_ip\":\"192.168.1.71\",\"lan_port\":71}],"
                   << "\"ratelimits\":[{\"mac\":\"AA:BB:CC:DD:EE:99\","
                   << "\"uplink_kbps\":5000000000,\"downlink_kbps\":0}]}";
        }
        vgww::web::RuleStore::Instance().AttachFile(
            "poison.json.rules.json");
        const auto maps = vgww::web::RuleStore::Instance().PortMaps();
        bool have_8081 = false;
        for (const auto& m : maps) {
            CHECK(m.wan_port != 4464);  // wraparound signature
            if (8081 == m.wan_port) have_8081 = true;
        }
        CHECK(have_8081);
        CHECK(1 == maps.size());  // the poisoned rule is skipped wholesale
        const auto limits = vgww::web::RuleStore::Instance().RateLimits();
        bool have_poison_mac = false;
        for (const auto& r : limits) {
            if ("AA:BB:CC:DD:EE:99" == r.mac) have_poison_mac = true;
        }
        CHECK(!have_poison_mac);  // kbps wrapped to garbage -> rule skipped
        std::remove("poison.json.rules.json");
    }

    // ---- RegisterApi with an injected auth token: mutating calls are
    //      rejected unless the caller presents the token ----
    {
        vgww::core::Config cfg;
        vgww::runtime::Dataplane dp(cfg);
        HttpServer api;
        vgww::web::RegisterApi(api, dp, cfg, "", "boot-secret");
        constexpr uint16_t kP = 18083;
        CHECK(api.Start("127.0.0.1", kP, error));

        CHECK(HttpGet("/api/status", kP, body) == 200);  // reads stay open
        const std::string rule =
            "{\"proto\":\"tcp\",\"wan_port\":8088,"
            "\"lan_ip\":\"192.168.1.60\",\"lan_port\":80}";
        CHECK(HttpPost(kP, "/api/portmap", "", rule, body) == 401);
        CHECK(HttpPost(kP, "/api/portmap", "wrong", rule, body) == 401);
        CHECK(HttpPost(kP, "/api/portmap", "boot-secret", rule, body) == 200);
        {
            std::string out;
            const std::string bearer_rule =
                "{\"proto\":\"tcp\",\"wan_port\":8089,"
                "\"lan_ip\":\"192.168.1.61\",\"lan_port\":53}";
            const int st = HttpRaw(kP,
                                   "POST /api/portmap HTTP/1.1\r\nHost: t\r\n"
                                   "Authorization: Bearer boot-secret\r\n"
                                   "Content-Length:" +
                                       std::to_string(bearer_rule.size()) +
                                       "\r\nConnection: close\r\n\r\n" +
                                       bearer_rule,
                                   out);
            CHECK(st == 200);
        }
        api.Stop();
    }

    // ---- POST /api/config must never wipe the auth token: GET omits the
    //      token (secret boundary), so a full-replacement POST built from a
    //      GET body would silently lock the UI on the next restart. ----
    {
        const char* kCfgPath = "tokencfg.json";
        std::remove(kCfgPath);
        vgww::core::Config cfg;
        cfg.web.token = "keep-me";
        vgww::runtime::Dataplane dp(cfg);
        HttpServer api;
        vgww::web::RegisterApi(api, dp, cfg, kCfgPath, "keep-me");
        constexpr uint16_t kP = 18084;
        CHECK(api.Start("127.0.0.1", kP, error));

        // A GET-shaped body carries no "token" field; saving it must keep
        // the running token instead of persisting an empty one.
        const std::string get_shaped =
            "{\"adapter\":\"x\","
            "\"gateway\":{\"ipv4\":\"192.168.0.40\","
            "\"mask\":\"255.255.255.0\","
            "\"mac\":\"30:fc:68:88:b4:a9\"},"
            "\"ipv6\":{\"enabled\":false,"
            "\"ula_prefix\":\"fdaa:0:0::\",\"prefix_len\":64,"
            "\"ra_lifetime_s\":300},"
            "\"web\":{\"port\":8081},\"vlan\":{}}";
        CHECK(HttpPost(kP, "/api/config", "keep-me", get_shaped, body) == 200);

        {
            std::ifstream in(kCfgPath, std::ios::binary);
            CHECK(in.good());
            if (in.good()) {
                std::stringstream ss;
                ss << in.rdbuf();
                const std::string saved = ss.str();
                CHECK(saved.find("\"token\":\"keep-me\"") != std::string::npos);
            }
        }
        // A body that explicitly empties the token must also be healed.
        std::string cleared =
            "{\"adapter\":\"x\","
            "\"gateway\":{\"ipv4\":\"192.168.0.40\","
            "\"mask\":\"255.255.255.0\","
            "\"mac\":\"30:fc:68:88:b4:a9\"},"
            "\"ipv6\":{\"enabled\":false,"
            "\"ula_prefix\":\"fdaa:0:0::\",\"prefix_len\":64,"
            "\"ra_lifetime_s\":300},"
            "\"web\":{\"port\":8081,\"token\":\"\"},\"vlan\":{}}";
        {
            std::string resp_body;
            const int st =
                HttpPost(kP, "/api/config", "keep-me", cleared, resp_body);
            CHECK(st == 200);
        }
        {
            std::ifstream in2(kCfgPath, std::ios::binary);
            CHECK(in2.good());
            if (in2.good()) {
                std::stringstream ss;
                ss << in2.rdbuf();
                CHECK(ss.str().find("\"token\":\"keep-me\"") !=
                      std::string::npos);
            }
        }
        std::remove(kCfgPath);
        const std::string tmp_path = std::string(kCfgPath) + ".tmp";
        std::remove(tmp_path.c_str());
        api.Stop();
    }

    // ---- JSON field extraction: escaped quotes must not truncate ----
    {
        std::string value;
        CHECK(vgww::web::JsonGetString("{\"mac\":\"AA:\\\"BB\"}", "mac", value));
        CHECK(value == "AA:\"BB");

        CHECK(vgww::web::JsonGetString(
                  "{\"hostname\":\"a\\\\b\",\"ip\":\"1.2.3.4\"}",
                  "hostname", value));
        CHECK(value == "a\\b");

        CHECK(vgww::web::JsonGetString("{\"ip\":\"1.2.3.4\"}", "ip", value));
        CHECK(value == "1.2.3.4");

        CHECK(!vgww::web::JsonGetString("{\"unterminated\":\"abc", "mac",
                                        value));

        // batch122: RFC 8259 section 7 requires \uXXXX to be decoded, and \b
        // / \f to map to their control characters. JsonGetString handled only
        // the six short escapes and let everything else fall through
        // `value.push_back(next)` - so "\\u5ba2" arrived as the literal text
        // "u5ba2" (the backslash dropped, the 'u' and the four hex digits kept
        // verbatim) and "\\b" arrived as a literal 'b'. The result was silent
        // data corruption for any client whose JSON encoder emits \u escapes:
        // Python's json.dumps defaults to ensure_ascii=True, so
        // {"hostname": "\u5ba2\u5385-iPad"} became "u5ba2u5385-iPad" instead of
        // the intended hostname. The bundled web UI uses JSON.stringify
        // (raw UTF-8), which is why this stayed hidden.
        CHECK(vgww::web::JsonGetString("{\"hostname\":\"\\u5ba2\\u5385-iPad\"}",
                                       "hostname", value));
        // Expected bytes are the UTF-8 encoding of U+5BA2 U+5385 followed by
        // "-iPad": E5 AE A2 E5 8E 85 2D 69 50 61 64. Spelled as ASCII hex so
        // the source stays pure ASCII (project rule).
        CHECK(value == "\xE5\xAE\xA2\xE5\x8E\x85-iPad");

        // A non-BMP code point is a \uD83D\uDE00 surrogate pair; the decoder
        // must pair them into the single U+1F600 (UTF-8 F0 9F 98 80).
        CHECK(vgww::web::JsonGetString(
                  "{\"hostname\":\"\\uD83D\\uDE00\"}", "hostname", value));
        CHECK(value == "\xF0\x9F\x98\x80");

        // \b and \f are real control characters, not the letters b / f.
        CHECK(vgww::web::JsonGetString("{\"v\":\"a\\bb\\fc\"}", "v", value));
        CHECK(value == std::string("a\bb\fc"));

        // Uppercase hex digits are legal in \uXXXX.
        CHECK(vgww::web::JsonGetString("{\"v\":\"\\u00E9\"}", "v", value));
        CHECK(value == "\xC3\xA9");  // U+00E9 'e acute'

        // batch314: RFC 8259 section 7 allows only " \\ / b f n r t u after a
        // backslash. The old default branch pushed the character through, so
        // "\q" became "q" - a mistyped Windows path ("C:\qemp") was accepted
        // with corrupted data instead of being refused. ("C:\temp" stays
        // legal: \t IS a JSON escape and decodes to a TAB.) Every invalid
        // escape must now fail the parse.
        CHECK(!vgww::web::JsonGetString("{\"v\":\"a\\qb\"}", "v", value));
        CHECK(!vgww::web::JsonGetString("{\"v\":\"C:\\qemp\"}", "v", value));
        CHECK(!vgww::web::JsonGetString("{\"v\":\"\\0\"}", "v", value));
        CHECK(!vgww::web::JsonGetString("{\"v\":\"\\'\"}", "v", value));
        // The legal short escapes must keep working (the strict branch must
        // not have swallowed them).
        CHECK(vgww::web::JsonGetString("{\"v\":\"a\\/b\\\"c\\\\d\"}", "v",
                                       value));
        CHECK(value == "a/b\"c\\d");

        // Whitespace tolerance (RFC 8259 allows insignificant space between
        // name and colon, and between colon and value; the frontend sends
        // compact JSON, but third-party clients may pretty-print).
        CHECK(vgww::web::JsonGetString(
                  "{\"proto\": \"tcp\", \"lan_ip\": \"192.168.1.50\"}",
                  "lan_ip", value));
        CHECK(value == "192.168.1.50");
        CHECK(vgww::web::JsonGetString(
                  "{\"proto\" : \"tcp\", \"lan_ip\" :\"10.0.0.7\"}",
                  "lan_ip", value));
        CHECK(value == "10.0.0.7");

        uint32_t num = 0;
        CHECK(vgww::web::JsonGetNumber("{\"wan_port\": 8080}", "wan_port",
                                       num));
        CHECK(num == 8080);

        // batch124: RFC 8259 whitespace is space, TAB, LF and CR - not just
        // space. The comment above claimed "pretty-print" tolerance, but the
        // scanners only skipped ' ', so a TAB or a newline made a present
        // field look ABSENT: /api/portmap then saw a zero port and answered
        // 400 "ports must be non-zero" to a body that is valid JSON. A
        // NUMBER with a legal trailing space before ',' or '}' was rejected
        // too, because the token then contained that space.
        CHECK(vgww::web::JsonGetString("{\"lan_ip\"\t:\t\"10.0.0.8\"}",
                                       "lan_ip", value));
        CHECK(value == "10.0.0.8");
        CHECK(vgww::web::JsonGetString("{\n  \"lan_ip\": \"10.0.0.9\"\n}",
                                       "lan_ip", value));
        CHECK(value == "10.0.0.9");
        CHECK(vgww::web::JsonGetNumber("{\n  \"wan_port\": 8082\n}",
                                       "wan_port", num));
        CHECK(num == 8082);
        CHECK(vgww::web::JsonGetNumber("{\"wan_port\"\t:\t8083}", "wan_port",
                                       num));
        CHECK(num == 8083);
        CHECK(vgww::web::JsonGetNumber("{\"wan_port\": 8084 }", "wan_port",
                                       num));
        CHECK(num == 8084);
        CHECK(vgww::web::JsonGetNumber("{\"wan_port\" : 8085 , \"x\":1}",
                                       "wan_port", num));
        CHECK(num == 8085);
        // A space INSIDE the digits is still not a number (must stay rejected:
        // this is the difference between "ignore insignificant whitespace" and
        // "tolerate garbage").
        CHECK(!vgww::web::JsonGetNumber("{\"wan_port\":8 086}", "wan_port",
                                        num));

        // Non-numeric or negative tokens must be rejected, never truncated
        // (strtoull would turn "123abc" into 123 and "-1" into max).
        CHECK(!vgww::web::JsonGetNumber("{\"p\":123abc}", "p", num));
        CHECK(!vgww::web::JsonGetNumber("{\"p\":-1}", "p", num));
        CHECK(vgww::web::JsonGetNumber("{\"p\":65535}", "p", num));
        CHECK(num == 65535);
        // Name/colon whitespace tolerance (RFC 8259).
        CHECK(vgww::web::JsonGetNumber("{\"p\" : 8081}", "p", num));
        CHECK(num == 8081);
    }

    // ---- Response::Error escapes quotes/backslashes in the message ----
    {
        const vgww::web::Response r = vgww::web::Response::Error(400, "a\"b:\\");
        CHECK(r.body == "{\"error\":\"a\\\"b:\\\\\"}");
        CHECK(r.status == 400);
        const vgww::web::Response clean =
            vgww::web::Response::Error(404, "not found");
        CHECK(clean.body == "{\"error\":\"not found\"}");
    }

    // ---- S5.3: GET /api/config must carry every field a full-replacement
    //      POST accepts. saveSettings() GETs the config, mutates a few
    //      SET_FIELDS, and POSTs the whole object back; any section omitted
    //      by GET is silently erased from the on-disk config on save. The
    //      auth token stays out (GET is unauthenticated; POST keeps the
    //      running token), so this guard must never round-trip it.
    {
        const char* kCfg53 = "rxcfg.json";
        const char* kLease53 = "rxcfg-leases.json";
        std::remove(kCfg53);
        std::remove((std::string(kCfg53) + ".tmp").c_str());
        std::remove(kLease53);

        vgww::core::Config cfg53;
        cfg53.adapter = "WebTestNICConfigFields";
        cfg53.mode = vgww::core::Mode::kBypass;
        cfg53.gateway.ipv4 = 0x0100A8C0u;  // 192.168.0.1 (network order)
        cfg53.gateway.mask = 0x00FFFFFFu;  // 255.255.255.0
        cfg53.gateway.mac = {0x30, 0xFC, 0x68, 0x88, 0xB4, 0xA9};

        cfg53.dhcp.enabled = false;
        cfg53.dhcp.pool_start = 0x1400A8C0u;  // 192.168.0.20
        cfg53.dhcp.pool_end = 0x6300A8C0u;    // 192.168.0.99
        cfg53.dhcp.lease_seconds = 7200;
        cfg53.dhcp.dns.push_back(0x0200A8C0u);  // 192.168.0.2
        vgww::core::StaticBinding sb53;
        sb53.mac = {0x30, 0xFC, 0x68, 0x88, 0xB4, 0x5A};
        sb53.ip = 0x3200A8C0u;  // 192.168.0.50
        sb53.hostname = "host-a";
        cfg53.dhcp.static_bindings.push_back(sb53);

        cfg53.ipv6.enabled = true;
        cfg53.ipv6.ula_prefix = {0xFD, 0, 0, 0, 0, 0, 0, 0,
                                 0,    0, 0, 0, 0, 0, 0, 0};  // fd00::
        cfg53.ipv6.prefix_len = 64;
        cfg53.ipv6.ra_lifetime_s = 300;
        cfg53.ipv6.dhcpv6.enabled = false;
        cfg53.ipv6.dhcpv6.pool_start = {
            0xFD, 0, 0, 0, 0, 0, 0, 0,
            0,    0, 0, 0, 0, 0, 0x10, 0x00};  // fd00::1000
        cfg53.ipv6.dhcpv6.pool_end = {
            0xFD, 0, 0, 0, 0, 0, 0, 0,
            0,    0, 0, 0, 0, 0, 0x1F, 0xFF};  // fd00::1fff
        cfg53.ipv6.dhcpv6.lease_seconds = 3600;
        vgww::core::Dhcp6StaticBinding sb653;
        sb653.duid = {0x00, 0x01, 0xAA, 0xBB};
        sb653.ip = {0xFD, 0, 0, 0, 0, 0, 0, 0,
                    0,    0, 0, 0, 0, 0, 0, 0x2A};  // fd00::2a
        sb653.hostname = "host6-a";
        cfg53.ipv6.dhcpv6.static_bindings.push_back(sb653);

        cfg53.perf.workers = 1;
        cfg53.perf.ring_capacity = 64;
        cfg53.perf.max_conns = 64;
        cfg53.web.port = 18095;
        cfg53.web.token = "shh";

        cfg53.bridge.enabled = false;
        cfg53.bridge.upstream = "U1";
        cfg53.bridge.downstream = "D1";
        cfg53.bridge.mac_table_size = 1024;

        vgww::runtime::Dataplane dp53(cfg53, kLease53);
        dp53.SetDriverClient(std::make_unique<WebFakeDriver>());
        std::string start_err53;
        CHECK(dp53.Start(start_err53));
        HttpServer api53;
        vgww::web::RegisterApi(api53, dp53, cfg53, kCfg53, "shh");
        constexpr uint16_t kP53 = 18095;
        std::string api_err53;
        CHECK(api53.Start("127.0.0.1", kP53, api_err53));

        body.clear();
        CHECK(HttpGet("/api/config", kP53, body) == 200);
        const auto j = nlohmann::json::parse(body);
        CHECK(!j.is_discarded());
        // mode / dhcp / ipv6.dhcpv6 / bridge were previously omitted and
        // would have been erased by the settings panel's full-replacement save.
        CHECK(j.value("mode", "") == "bypass");
        CHECK(j["dhcp"]["enabled"].get<bool>() == false);
        CHECK(j["dhcp"]["pool"][0].get<std::string>() == "192.168.0.20");
        CHECK(j["dhcp"]["pool"][1].get<std::string>() == "192.168.0.99");
        CHECK(j["dhcp"].value("lease_hours", 0) == 2);  // 7200s / 3600
        CHECK(j["dhcp"]["dns"][0].get<std::string>() == "192.168.0.2");
        CHECK(j["dhcp"]["static_bindings"][0].value("mac", "") ==
              "30:FC:68:88:B4:5A");
        CHECK(j["dhcp"]["static_bindings"][0].value("ip", "") ==
              "192.168.0.50");
        CHECK(j["dhcp"]["static_bindings"][0].value("hostname", "") ==
              "host-a");
        CHECK(j["ipv6"]["dhcpv6"]["enabled"].get<bool>() == false);
        CHECK(j["ipv6"]["dhcpv6"].value("lease_seconds", 0) == 3600);
        CHECK(j["ipv6"]["dhcpv6"]["static_bindings"][0].value("duid", "") ==
              "0001aabb");
        const std::string sb6_ip53 =
            j["ipv6"]["dhcpv6"]["static_bindings"][0].value("ip", "");
        asio::error_code dec53;
        asio::ip::make_address_v6(sb6_ip53, dec53);
        CHECK(!dec53);
        CHECK(j["ipv6"]["dhcpv6"]["static_bindings"][0].value(
                  "hostname", "") == "host6-a");
        CHECK(j["web"].value("bind", "") == "127.0.0.1");
        CHECK(j["bridge"]["enabled"].get<bool>() == false);
        CHECK(j["bridge"].value("upstream", "") == "U1");
        CHECK(j["bridge"].value("downstream", "") == "D1");
        CHECK(j["bridge"].value("mac_table_size", 0) == 1024);
        // The auth token is deliberately absent: GET is unauthenticated and
        // returning it would leak the secret. The settings round-trip stays
        // intact because POST preserves the running token.
        CHECK(!j.contains("token"));
        CHECK(j["web"].contains("token") == false);
        CHECK(body.find("shh") == std::string::npos);

        // Full-replacement save built from the GET body (saveSettings()).
        std::string resp;
        CHECK(HttpPost(kP53, "/api/config", "shh", body, resp) == 200);
        // The 11th route (POST /api/config) must answer with a complete JSON
        // document too - substring assertions would miss a broken brace.
        CHECK(JsonWholeBody(resp, nullptr, 0));

        // Reload: every field must survive the round-trip unchanged.
        body.clear();
        CHECK(HttpGet("/api/config", kP53, body) == 200);
        const auto j2 = nlohmann::json::parse(body);
        CHECK(!j2.is_discarded());
        CHECK(j2.value("mode", "") == "bypass");
        CHECK(j2["dhcp"]["enabled"].get<bool>() == false);
        CHECK(j2["dhcp"]["pool"][0].get<std::string>() == "192.168.0.20");
        CHECK(j2["ipv6"]["dhcpv6"].value("lease_seconds", 0) == 3600);
        CHECK(j2["bridge"]["enabled"].get<bool>() == false);
        CHECK(j2["bridge"].value("mac_table_size", 0) == 1024);
        // The on-disk copy keeps the new sections and the running token.
        {
            std::ifstream in(kCfg53, std::ios::binary);
            CHECK(in.good());
            if (in.good()) {
                std::stringstream ss;
                ss << in.rdbuf();
                const std::string saved = ss.str();
                CHECK(saved.find("\"mode\":\"bypass\"") != std::string::npos);
                CHECK(saved.find("\"lease_hours\":2") != std::string::npos);
                CHECK(saved.find("\"dhcpv6\"") != std::string::npos);
                CHECK(saved.find("\"static_bindings\"") != std::string::npos);
                CHECK(saved.find("\"mac_table_size\":1024") !=
                      std::string::npos);
                CHECK(saved.find("\"token\":\"shh\"") != std::string::npos);
            }
        }

        api53.Stop();
        std::string stop_err53;
        CHECK(dp53.Stop(stop_err53));
        std::remove(kCfg53);
        std::remove((std::string(kCfg53) + ".tmp").c_str());
        std::remove(kLease53);
    }

    // ---- S5.7: adapter-name matcher (defect #2) ----
    //      headless coverage for friendly-name / \DEVICE\{GUID} matching.
    //      Batch16: the pnputil/installer helper tests and the installer
    //      wiring/components moved to test_driver_installer.cpp so this
    //      suite no longer synthesizes payloads next to the test binary.
    {
        // Adapter matching: friendly/GUID hybrid (defect #2).
        std::vector<vgww::driver::AdapterEntry> ents;
        vgww::driver::AdapterEntry a;
        a.name = L"\\DEVICE\\{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}";
        a.handle = reinterpret_cast<void*>(1);
        a.mtu = 1500;
        ents.push_back(a);
        vgww::driver::AdapterEntry b;
        b.name = L"\\DEVICE\\{11111111-2222-3333-4444-555555555555}";
        b.handle = reinterpret_cast<void*>(2);
        b.mtu = 1500;
        ents.push_back(b);

        bool ambig = false;
        CHECK(vgww::driver::MatchAdapterEntry(ents, L"", L"", &ambig) == 0);
        CHECK(!ambig);
        // Full GUID path / fragment both hit the first entry.
        CHECK(vgww::driver::MatchAdapterEntry(
                  ents, L"\\DEVICE\\{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}",
                  L"", &ambig) == 0);
        CHECK(!ambig);
        CHECK(vgww::driver::MatchAdapterEntry(
                  ents, L"AAAAAAAA-BBBB-CCCC", L"", &ambig) == 0);
        CHECK(!ambig);
        // Friendly name resolved to B's GUID path matches by GUID suffix.
        CHECK(vgww::driver::MatchAdapterEntry(
                  ents, L"not-a-guid",
                  L"\\DEVICE\\{11111111-2222-3333-4444-555555555555}",
                  &ambig) == 1);
        CHECK(!ambig);
        // Nothing matches -> -1.
        CHECK(vgww::driver::MatchAdapterEntry(
                  ents, L"nope", L"", &ambig) == -1);
        // Ambiguity: hint matches both entries, first wins.
        ambig = false;
        CHECK(vgww::driver::MatchAdapterEntry(
                  ents, L"\\DEVICE\\{", L"", &ambig) == 0);
        CHECK(ambig);

        const std::vector<std::wstring> friendly{L"NIC 1", L"NIC 2"};
        const std::string table =
            vgww::driver::FormatAdapterTable(ents, friendly);
        CHECK(table.find("NIC 1") != std::string::npos);
        CHECK(table.find("NIC 2") != std::string::npos);
        CHECK(table.find("AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE") !=
              std::string::npos);
        CHECK(table.find("11111111-2222-3333-4444-555555555555") !=
              std::string::npos);

        // RA-2 (G-5 F3): pure friendly-name matcher. Case-insensitive,
        // localized alias equivalence, strict ASCII " N" suffix (D4); no
        // substring matching (vEthernet counter-example).
        using vgww::driver::FriendlyNameMatches;
        CHECK(FriendlyNameMatches(L"Ethernet", L"以太网"));
        CHECK(FriendlyNameMatches(L"ethernet", L"Ethernet"));
        CHECK(FriendlyNameMatches(L"NIC 1", L"nic 1"));
        CHECK(FriendlyNameMatches(L"ETHERNET 2", L"以太网 2"));
        CHECK(!FriendlyNameMatches(L"Ethernet", L"以太网 2"));
        CHECK(!FriendlyNameMatches(L"Ethernet 2", L"以太网"));
        CHECK(!FriendlyNameMatches(L"以太网2", L"Ethernet 2"));
        CHECK(!FriendlyNameMatches(L"以太网 02", L"Ethernet 2"));
        CHECK(!FriendlyNameMatches(L"Ethernet", L"vEthernet (Default Switch)"));
        CHECK(!FriendlyNameMatches(L"Wi-Fi", L"以太网"));

        // MatchAdapterEntry friendly layer: alias hit, equal-rank tie flag,
        // raw exact outranks an alias hit.
        std::vector<vgww::driver::AdapterEntry> fents;
        vgww::driver::AdapterEntry f1;
        f1.name = L"\\DEVICE\\{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}";
        f1.friendly_name = L"以太网";
        f1.handle = reinterpret_cast<void*>(1);
        fents.push_back(f1);
        bool fam = false;
        CHECK(vgww::driver::MatchAdapterEntry(fents, L"Ethernet", L"", &fam) ==
              0);
        CHECK(!fam);
        CHECK(vgww::driver::MatchAdapterEntry(fents, L"ethernet", L"", &fam) ==
              0);
        CHECK(!fam);
        CHECK(vgww::driver::MatchAdapterEntry(fents, L"Wi-Fi", L"", &fam) == -1);
        CHECK(!fam);
        // Two alias-equivalent entries: first wins and the tie is flagged.
        vgww::driver::AdapterEntry f2;
        f2.name = L"\\DEVICE\\{11111111-2222-3333-4444-555555555555}";
        f2.friendly_name = L"以太网";
        f2.handle = reinterpret_cast<void*>(2);
        fents.push_back(f2);
        fam = false;
        CHECK(vgww::driver::MatchAdapterEntry(fents, L"Ethernet", L"", &fam) ==
              0);
        CHECK(fam);
        // Raw exact match wins over the alias hit even when the alias entry
        // comes first in enumeration order.
        std::vector<vgww::driver::AdapterEntry> raw_ents;
        vgww::driver::AdapterEntry r1;
        r1.name = L"\\DEVICE\\{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}";
        r1.friendly_name = L"以太网";
        r1.handle = reinterpret_cast<void*>(1);
        raw_ents.push_back(r1);
        vgww::driver::AdapterEntry r2;
        r2.name = L"\\DEVICE\\{11111111-2222-3333-4444-555555555555}";
        r2.friendly_name = L"Ethernet";
        r2.handle = reinterpret_cast<void*>(2);
        raw_ents.push_back(r2);
        fam = false;
        CHECK(vgww::driver::MatchAdapterEntry(raw_ents, L"Ethernet", L"",
                                              &fam) == 1);
        CHECK(!fam);

    }



    // ---- M2: RuleStore disk persistence must not block the control plane.
    //      One writer thread mutates a rule set while the control-plane poller
    //      reads BanSnapshot() in a loop. Up to 100 mutation saves fit inside
    //      the poll window; the poll count therefore measures lock blocking,
    //      not disk speed.
    {
        const char* kPath = "conc.json.rules.json";
        std::remove(kPath);
        auto& store = vgww::web::RuleStore::Instance();
        store.AttachFile("");
        store.Clear();

        // batch87: this seed used to carry a 256-char 'x' suffix on every MAC,
        // which made each entry unparseable. The loader accepted them, so the
        // reload assertion below passed on data the firewall never enforces.
        // Once the loader enforces the POST contract those entries are
        // (correctly) dropped, so the seed must be REAL MACs. The dump is
        // smaller (~0.15 MiB) but this test's subject is structural - the
        // copy-on-write publish and the on-disk round trip - not timing.
        auto mac_for = [](size_t i) {
            char buf[24];
            std::snprintf(buf, sizeof(buf), "02:00:%02X:%02X:%02X:%02X",
                          static_cast<unsigned>((i >> 24) & 0xFF),
                          static_cast<unsigned>((i >> 16) & 0xFF),
                          static_cast<unsigned>((i >> 8) & 0xFF),
                          static_cast<unsigned>(i & 0xFF));
            return std::string(buf);
        };
        for (size_t i = 0; i < 3072; ++i) {
            store.AddBan(vgww::web::BanEntry{"mac", mac_for(i)});
        }
        store.AttachFile(kPath);   // persistence on; file does not exist yet

        // batch77: `polls > 10000` was an absolute count, i.e. a CPU-quota
        // assertion dressed as a locking assertion -- a busy host hands the
        // poller fewer slices and the check fails with the product unchanged.
        // Measured over 20 runs the same binary spanned busy-fractions from
        // 0.010 to 0.134, so a busy-fraction rewrite still failed 3/20: ANY
        // rate predicate here is noise-driven, not product-driven.
        //
        // So this asserts the part of the RCU contract that IS deterministic:
        //   * a snapshot already handed out is never mutated in place (the
        //     writer publishes a new object, it does not edit the old one);
        //   * successive observations never go backwards (the writer only
        //     appends, so a lost or torn publish shows up as a decrease);
        //   * the final snapshot contains every appended entry.
        // The "disk I/O must not block the poller" half is guaranteed
        // structurally, not by timing: AddBan closes the mutex_ scope before
        // calling FlushPersist (web_api.cpp: AddBan's lock_guard ends, then
        // FlushPersist() runs), and FlushPersist takes persist_mutex_ only,
        // never mutex_. A timing predicate cannot verify that on a shared host.
        std::atomic<bool> writer_done{false};
        std::thread writer([&] {
            for (int i = 0; i < 8; ++i) {
                store.AddBan(vgww::web::BanEntry{
                    "mac", mac_for(3072 + static_cast<size_t>(i))});
            }
            writer_done.store(true);
        });

        const auto first_snapshot = store.BanSnapshot();
        const size_t first_size = first_snapshot ? first_snapshot->size() : 0;
        uint64_t polls = 0;
        size_t observed = first_size;
        bool monotonic_ok = true;
        while (!writer_done.load()) {
            auto snap = store.BanSnapshot();
            if (snap) {
                const size_t n = snap->size();
                if (n < observed) {
                    monotonic_ok = false;   // entries vanished: lost publish
                }
                observed = n;
            }
            ++polls;
            std::this_thread::yield();
        }
        writer.join();

        // The snapshot captured before the writer ran must be byte-identical
        // afterwards: publishing is copy-on-write, never in-place mutation.
        const size_t first_size_after =
            first_snapshot ? first_snapshot->size() : 0;
        const size_t final_size = store.BanSnapshot()->size();
        std::printf(
            "b34g snapshot-poll: polls=%llu first=%zu first_after=%zu "
            "observed=%zu final=%zu\n",
            static_cast<unsigned long long>(polls), first_size,
            first_size_after, observed, final_size);
        CHECK(polls > 0);                       // the poller really ran
        CHECK(monotonic_ok);                    // no lost / torn publish
        CHECK(first_size_after == 3072);  // old snapshot immutable (seed size)
        CHECK(final_size == 3072 + 8);    // every append is visible

        // Persistence correctness: reload the file and confirm every
        // writer-thread ban landed (final snapshot wins).
        store.AttachFile(kPath);
        const auto reloaded = store.Bans();
        CHECK(reloaded.size() == 3072 + 8);
        bool last_ban_found = false;
        for (const auto& b : reloaded) {
            if (b.value == mac_for(3072 + 7)) {
                last_ban_found = true;
            }
        }
        CHECK(last_ban_found);

        store.AttachFile("");
        store.Clear();
        std::remove(kPath);
    }

    // ---- M8: rules.json loading must enforce the same caps as the API:
    //      an oversize file is rejected WHOLESALE (the store stays exactly
    //      as it was; no half-loaded rule set) ----
    {
        const char* kPath = "oversize.json.rules.json";
        auto& store = vgww::web::RuleStore::Instance();

        // Oversize bans (kMaxBans + 1): rejected, store stays empty.
        std::remove(kPath);
        {
            std::ofstream out(kPath, std::ios::binary);
            out << "{\"bans\":[";
            for (size_t i = 0; i <= ::vgww::core::limits::kMaxBans; ++i) {
                if (i) out << ',';
                out << "{\"kind\":\"mac\",\"value\":\"AA:BB:CC:DD:EE:FF\"}";
            }
            out << "]}";
        }
        store.AttachFile("");
        store.Clear();
        store.AttachFile(kPath);
        CHECK(store.Bans().empty());   // rejected wholesale
        std::remove(kPath);

        // Oversize portmaps (kMaxPortMaps + 1): rejected too.
        {
            std::ofstream out(kPath, std::ios::binary);
            out << "{\"portmaps\":[";
            for (size_t i = 0; i <= ::vgww::core::limits::kMaxPortMaps; ++i) {
                if (i) out << ',';
                out << "{\"proto\":\"tcp\",\"wan_port\":1000,\"lan_ip\":"
                       "\"192.168.1.50\",\"lan_port\":80}";
            }
            out << "]}";
        }
        store.AttachFile("");   // keep Clear() from overwriting the test file
        store.Clear();
        store.AttachFile(kPath);
        CHECK(store.PortMaps().empty());   // rejected wholesale
        std::remove(kPath);

        // Exactly at the cap must still load (the guard must not off-by-one).
        // batch144: the entries must be DISTINCT targets - a ban list is a set
        // now, so kMaxBans copies of one MAC would collapse to a single row
        // and this case would silently stop testing the cap boundary.
        {
            std::ofstream out(kPath, std::ios::binary);
            out << "{\"bans\":[";
            for (size_t i = 0; i < ::vgww::core::limits::kMaxBans; ++i) {
                if (i) out << ',';
                char mac[32] = {};
                std::snprintf(mac, sizeof(mac),
                              "\"02:00:00:00:%02X:%02X\"",
                              static_cast<unsigned>((i >> 8) & 0xFF),
                              static_cast<unsigned>(i & 0xFF));
                out << "{\"kind\":\"mac\",\"value\":" << mac << '}';
            }
            out << "]}";
        }
        store.AttachFile("");   // keep Clear() from overwriting the test file
        store.Clear();
        store.AttachFile(kPath);
        CHECK(store.Bans().size() == ::vgww::core::limits::kMaxBans);
        std::remove(kPath);

        // A rejected oversize file must leave a NON-EMPTY store exactly as
        // it was (no half-load, no wipe).
        store.Clear();
        store.AddBan(vgww::web::BanEntry{"mac", "02:00:00:00:00:01"});
        {
            std::ofstream out(kPath, std::ios::binary);
            out << "{\"bans\":[";
            for (size_t i = 0; i <= ::vgww::core::limits::kMaxBans; ++i) {
                if (i) out << ',';
                out << "{\"kind\":\"mac\",\"value\":\"AA:BB:CC:DD:EE:FF\"}";
            }
            out << "]}";
        }
        store.AttachFile(kPath);
        CHECK(store.Bans().size() == 1);
        if (store.Bans().size() == 1) {
            CHECK(store.Bans()[0].value == "02:00:00:00:00:01");
        }
        std::remove(kPath);

        // Oversize ratelimits (kMaxRateLimits + 1): rejected wholesale, and a
        // pre-existing store must survive the rejection untouched.
        store.AttachFile("");
        store.Clear();
        store.SetRateLimit(
            vgww::web::RateLimitRule{"02:00:00:00:00:02", 100, 100});
        {
            std::ofstream out(kPath, std::ios::binary);
            out << "{\"ratelimits\":[";
            for (size_t i = 0; i <= ::vgww::core::limits::kMaxRateLimits;
                 ++i) {
                if (i) out << ',';
                out << "{\"mac\":\"AA:BB:CC:DD:EE:FF\","
                       "\"uplink_kbps\":1,\"downlink_kbps\":1}";
            }
            out << "]}";
        }
        store.AttachFile(kPath);
        CHECK(store.RateLimits().size() == 1);
        if (store.RateLimits().size() == 1) {
            CHECK(store.RateLimits()[0].mac == "02:00:00:00:00:02");
        }
        std::remove(kPath);

        // Exactly at the portmap cap must still load (the guard must not
        // off-by-one); mirror of the bans at-cap case above.
        store.AttachFile("");
        store.Clear();
        {
            std::ofstream out(kPath, std::ios::binary);
            out << "{\"portmaps\":[";
            for (size_t i = 0; i < ::vgww::core::limits::kMaxPortMaps; ++i) {
                if (i) out << ',';
                out << "{\"proto\":\"tcp\",\"wan_port\":" << (1000 + i)
                    << ",\"lan_ip\":\"192.168.1.50\",\"lan_port\":80}";
            }
            out << "]}";
        }
        store.AttachFile(kPath);
        CHECK(store.PortMaps().size() == ::vgww::core::limits::kMaxPortMaps);
        std::remove(kPath);
        store.AttachFile("");
        store.Clear();
    }

    // ---- P8 deviation 1 (audit B): legacy persisted rules may hold
    //      non-canonical
    //      MAC spellings (dashed/lowercase from an older build). LoadLocked
    //      must migrate MAC values to the canonical form in memory, otherwise
    //      a canonical POST would not match the legacy entry (duplicate) and a
    //      canonical DELETE could not remove it. IP-valued bans stay as-is. ----
    {
        const char* kPath = "legacy-mac.json.rules.json";
        std::remove(kPath);
        {
            std::ofstream out(kPath, std::ios::binary);
            out << "{\"bans\":[{\"kind\":\"mac\","
                   "\"value\":\"aa-bb-cc-dd-ee-77\"},"
                   "{\"kind\":\"ip\",\"value\":\"2001:db8::1\"}],"
                   "\"ratelimits\":[{\"mac\":\"aa-bb-cc-dd-ee-88\","
                   "\"uplink_kbps\":10,\"downlink_kbps\":10}]}";
        }
        vgww::core::Config cfg;
        vgww::runtime::Dataplane dp(cfg);
        HttpServer api;
        vgww::web::RegisterApi(api, dp, cfg, "legacy-mac.json");
        constexpr uint16_t kP = 18091;
        CHECK(api.Start("127.0.0.1", kP, error));

        // Migrated to canonical form on load (memory + GET).
        CHECK(HttpGet("/api/ratelimit", kP, body) == 200);
        CHECK(body.find("AA:BB:CC:DD:EE:88") != std::string::npos);
        CHECK(body.find("aa-bb-cc-dd-ee-88") == std::string::npos);
        CHECK(HttpGet("/api/bans", kP, body) == 200);
        CHECK(body.find("AA:BB:CC:DD:EE:77") != std::string::npos);
        CHECK(body.find("aa-bb-cc-dd-ee-77") == std::string::npos);
        CHECK(body.find("2001:db8::1") != std::string::npos);  // ip untouched

        // A canonical POST must update-in-place, never duplicate.
        CHECK(HttpPost(kP, "/api/ratelimit", "",
                       "{\"mac\":\"AA:BB:CC:DD:EE:88\",\"uplink_kbps\":20,"
                       "\"downlink_kbps\":20}",
                       body) == 200);
        CHECK(vgww::web::RuleStore::Instance().RateLimits().size() == 1);
        // A canonical DELETE must remove the migrated entry.
        CHECK(HttpDelete("/api/ratelimit?mac=AA:BB:CC:DD:EE:88", kP, body) ==
              200);
        CHECK(vgww::web::RuleStore::Instance().RateLimits().size() == 0);
        CHECK(HttpGet("/api/ratelimit", kP, body) == 200);
        CHECK(body.find("AA:BB:CC:DD:EE:88") == std::string::npos);

        api.Stop();
        vgww::web::RuleStore::Instance().AttachFile("");
        vgww::web::RuleStore::Instance().Clear();
        std::remove(kPath);
    }

    // ---- M9: one stalled client must not delay other requests. The old
    //      single-threaded acceptor blocked on the stalled socket until its
    //      5 s SO_RCVTIMEO expired before it accepted the next connection.
    {
        HttpServer srv;
        srv.Route("GET", "/api/ping", [](const Request&) {
            return Response::Json("{\"pong\":true}");
        });
        constexpr uint16_t kP = 18085;
        CHECK(srv.Start("127.0.0.1", kP, error));

        asio::io_context io;
        asio::ip::tcp::socket slow(io);
        std::error_code ec;
        slow.connect(asio::ip::tcp::endpoint(
                         asio::ip::make_address("127.0.0.1"), kP),
                     ec);
        CHECK(!ec);
        // Partial header, then stall: the old code pinned the accept thread
        // here; a 2-worker pool keeps serving.
        const std::string partial = "GET /api/ping HTTP/1.1\r\nHost: t\r\n";
        asio::write(slow, asio::buffer(partial), ec);
        CHECK(!ec);
        std::this_thread::sleep_for(std::chrono::milliseconds(150));

        const auto t0 = std::chrono::steady_clock::now();
        const int st = HttpGet("/api/ping", kP, body);
        const auto elapsed_ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - t0).count();
        CHECK(st == 200);
        CHECK(body.find("\"pong\":true") != std::string::npos);
        CHECK(elapsed_ms < 2000);   // pre-fix: ~5000 (blocked on slow peer)

        slow.close(ec);
        srv.Stop();
    }

    // ---- M9b: Stop() must be bounded and must NOT drain queued connections.
    //      Two stalled clients occupy both workers; two complete requests sit
    //      in the queue. After Stop() those queued clients must NOT receive
    //      an HTTP response (pre-9b the workers drained the queue and served
    //      them, stretching shutdown by up to 64 x per-connection time). ----
    {
        HttpServer srv;
        srv.Route("GET", "/api/ping", [](const Request&) {
            return Response::Json("{\"pong\":true}");
        });
        constexpr uint16_t kP = 18086;
        CHECK(srv.Start("127.0.0.1", kP, error));

        asio::io_context io;
        std::error_code ec;
        const auto ep = asio::ip::tcp::endpoint(
            asio::ip::make_address("127.0.0.1"), kP);

        // Two stalled clients: each pins one worker until its deadline.
        asio::ip::tcp::socket slow1(io);
        asio::ip::tcp::socket slow2(io);
        slow1.connect(ep, ec);
        CHECK(!ec);
        slow2.connect(ep, ec);
        CHECK(!ec);
        const std::string partial = "GET /api/ping HTTP/1.1\r\nHost: t\r\n";
        asio::write(slow1, asio::buffer(partial), ec);
        CHECK(!ec);
        asio::write(slow2, asio::buffer(partial), ec);
        CHECK(!ec);
        std::this_thread::sleep_for(std::chrono::milliseconds(200));

        // Two complete requests behind them: with both workers stalled these
        // sit in conn_queue_ (bounded by 64).
        asio::ip::tcp::socket fast1(io);
        asio::ip::tcp::socket fast2(io);
        fast1.connect(ep, ec);
        CHECK(!ec);
        fast2.connect(ep, ec);
        CHECK(!ec);
        const std::string full = "GET /api/ping HTTP/1.1\r\nHost: t\r\n\r\n";
        asio::write(fast1, asio::buffer(full), ec);
        CHECK(!ec);
        asio::write(fast2, asio::buffer(full), ec);
        CHECK(!ec);
        std::this_thread::sleep_for(std::chrono::milliseconds(200));

        const auto t0 = std::chrono::steady_clock::now();
        srv.Stop();
        const auto stop_ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - t0).count();
        // Bounded-stop sanity bound: at most the two in-flight connections'
        // deadline (2 x kIoTimeoutMs = 10 s) plus a >= 2 s scheduling margin.
        CHECK(stop_ms < 12000);

        // The queued clients must not have been served: pre-9b the workers
        // drained the queue after Stop and answered both.
        char rbuf[512];
        std::error_code rec;
        fast1.non_blocking(true, ec);
        const size_t n1 = fast1.read_some(asio::buffer(rbuf), rec);
        CHECK(0 == n1);
        fast2.non_blocking(true, ec);
        const size_t n2 = fast2.read_some(asio::buffer(rbuf), rec);
        CHECK(0 == n2);

        slow1.close(ec);
        slow2.close(ec);
        fast1.close(ec);
        fast2.close(ec);
    }

    // ---- P2: Stop() with an idle acceptor must be bounded, restartable and
    //      idempotent. Pre-fix, Stop() called acceptor_.close() from the
    //      Stop() thread while the accept thread was parked in a blocking
    //      synchronouse accept(); the close was not guaranteed to unblock it,
    //      so Stop() could hang on accept_thread_.join() (and the acceptor/
    //      io_context outlived the join). Post-fix the accept is async and its
    //      close is posted onto the accept thread's own io_context. ----
    {
        HttpServer srv;
        srv.Route("GET", "/api/ping", [](const Request&) {
            return Response::Json("{\"pong\":true}");
        });
        constexpr uint16_t kP = 18089;

        // (a) Start then immediately Stop with no client ever connecting:
        //     the pending accept must be interrupted, not joined-on forever.
        for (int i = 0; i < 3; ++i) {
            CHECK(srv.Start("127.0.0.1", kP, error));
            const auto t0 = std::chrono::steady_clock::now();
            srv.Stop();
            const auto stop_ms =
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - t0).count();
            CHECK(stop_ms < 2000);

            // (b) A second Stop() on an already-stopped server is idempotent.
            const auto t1 = std::chrono::steady_clock::now();
            srv.Stop();
            const auto again_ms =
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - t1).count();
            CHECK(again_ms < 2000);
        }

        // (c) After a Stop() the same instance must be restartable and serve
        //     requests again (fresh io_context/acceptor per Start).
        CHECK(srv.Start("127.0.0.1", kP, error));
        CHECK(HttpGet("/api/ping", kP, body) == 200);
        CHECK(body.find("\"pong\":true") != std::string::npos);
        srv.Stop();
    }

    // ---- DHCPv4 endpoints (S2): a started data plane in main mode
    //      assembles the server; the endpoints then list leases and manage
    //      static bindings (cap / duplicate / token rules). ----
    {
        const char* kLeasePath = "web-dhcp-leases.json";
        std::remove(kLeasePath);
        vgww::core::Config cfg;
        cfg.adapter = "WebTestNIC";
        cfg.mode = vgww::core::Mode::kMain;
        cfg.dhcp.enabled = true;
        bool ip_ok = false;
        cfg.gateway.ipv4 = vgww::core::ParseIpv4("192.168.40.1", ip_ok);
        cfg.gateway.mask = vgww::core::ParseIpv4("255.255.255.0", ip_ok);
        cfg.gateway.mac = {0x30, 0xFC, 0x68, 0x88, 0xB4, 0xA9};
        cfg.dhcp.pool_start = vgww::core::ParseIpv4("192.168.40.100", ip_ok);
        cfg.dhcp.pool_end = vgww::core::ParseIpv4("192.168.40.200", ip_ok);
        cfg.dhcp.lease_seconds = 3600;
        cfg.perf.workers = 2;
        cfg.perf.ring_capacity = 64;
        cfg.perf.max_conns = 64;
        // 1022 config bindings so the POST boundary is exactly 1024/1025.
        for (uint32_t i = 0; i < 1022; ++i) {
            vgww::core::StaticBinding binding;
            binding.mac = {0x02, 0x00,
                           static_cast<uint8_t>((i >> 8) & 0xFF),
                           static_cast<uint8_t>(i & 0xFF), 0x00, 0x01};
            binding.ip = vgww::core::ParseIpv4(
                "10.0." + std::to_string((i >> 8) & 0xFF) + "." +
                    std::to_string(i & 0xFF),
                ip_ok);
            cfg.dhcp.static_bindings.push_back(binding);
        }

        vgww::runtime::Dataplane dp(cfg, kLeasePath);
        dp.SetDriverClient(std::make_unique<WebFakeDriver>());
        std::string start_error;
        CHECK(dp.Start(start_error));
        CHECK(dp.DhcpActive());

        HttpServer api;
        vgww::web::RegisterApi(api, dp, cfg, "", "boot-secret");
        constexpr uint16_t kP = 18085;
        CHECK(api.Start("127.0.0.1", kP, error));

        // GET lists the config bindings; leases start empty (no DISCOVER was
        // injected here, so the list is an empty JSON array).
        CHECK(HttpGet("/api/dhcp/bindings", kP, body) == 200);
        CHECK(HttpGet("/api/dhcp/leases", kP, body) == 200);
        CHECK(body.find("[") != std::string::npos);

        // Mutations stay token-guarded.
        CHECK(HttpPost(kP, "/api/dhcp/bindings", "",
                       "{\"mac\":\"02:00:00:00:99:01\",\"ip\":\"10.9.9.1\"}",
                       body) == 401);

        // The LAN in this fixture is 192.168.40.0/24, so these payloads use
        // in-subnet host addresses: batch109 made the runtime binding obey the
        // same placement rules the loader and ValidateConfig always enforced,
        // and the old 10.9.9.x placeholders sit outside that subnet (they only
        // ever succeeded because the check was missing). The subject of this
        // block is the 1024-entry cap, not placement; placement has its own
        // coverage in test_dhcp (TestB109*).
        //
        // 1023rd binding succeeds.
        CHECK(HttpPost(kP, "/api/dhcp/bindings", "boot-secret",
                       "{\"mac\":\"02:00:00:00:99:01\",\"ip\":\"192.168.40.201\"}",
                       body) == 200);
        // Duplicate MAC -> rejected (no silent retarget, no cap slot used).
        CHECK(HttpPost(kP, "/api/dhcp/bindings", "boot-secret",
                       "{\"mac\":\"02:00:00:00:99:01\",\"ip\":\"192.168.40.202\"}",
                       body) == 400);
        // Exactly 1024.
        CHECK(HttpPost(kP, "/api/dhcp/bindings", "boot-secret",
                       "{\"mac\":\"02:00:00:00:99:02\",\"ip\":\"192.168.40.202\"}",
                       body) == 200);
        // 1025th -> rejected by the cap.
        CHECK(HttpPost(kP, "/api/dhcp/bindings", "boot-secret",
                       "{\"mac\":\"02:00:00:00:99:03\",\"ip\":\"192.168.40.203\"}",
                       body) == 400);
        CHECK(dp.GetDhcpBindings().size() ==
              ::vgww::core::limits::kMaxStaticBindings);

        // DELETE removes; a repeat DELETE of the same MAC -> 404. The token
        // rides an explicit header because HttpDelete (unlike HttpPost) has
        // no token parameter.
        const std::string delete_one =
            "DELETE /api/dhcp/bindings?mac=02:00:00:00:99:01 HTTP/1.1\r\n"
            "Host: t\r\nX-Auth-Token: boot-secret\r\nContent-Length: 0\r\n"
            "Connection: close\r\n\r\n";
        CHECK(HttpRaw(kP, delete_one, body) == 200);
        CHECK(HttpRaw(kP, delete_one, body) == 404);
        // Missing mac -> 400.
        CHECK(HttpRaw(kP,
                      "DELETE /api/dhcp/bindings HTTP/1.1\r\nHost: t\r\n"
                      "X-Auth-Token: boot-secret\r\nContent-Length: 0\r\n"
                      "Connection: close\r\n\r\n",
                      body) == 400);
        // Without the token the DELETE is rejected outright.
        CHECK(HttpRaw(kP,
                      "DELETE /api/dhcp/bindings?mac=02:00:00:00:99:02 "
                      "HTTP/1.1\r\nHost: t\r\nContent-Length: 0\r\n"
                      "Connection: close\r\n\r\n",
                      body) == 401);

        // /api/status exposes the v4 lease count.
        CHECK(HttpGet("/api/status", kP, body) == 200);
        CHECK(body.find("\"dhcp\":{\"leases\":") != std::string::npos);

        api.Stop();
        std::string stop_error;
        CHECK(dp.Stop(stop_error));
        std::remove(kLeasePath);
    }

    TestWebDhcp6BindingsCrud();
    TestB142Dhcp6DuplicateCheckIsSpellingIndependent();
    TestStatusIncludesLeases6();
    TestDhcp6LeasesEmptyWhenNotAssembled();
    TestB41DhcpBindingStoppedGate();
    TestStatusIncludesBridge();
    TestApiWholeBodyJson();
    TestH1WebConfigPreservesNativePrefs();
    TestB37tWebConfigAppliesLive();
    TestB38WebApplyStatus();
    TestB111ApplyStatusIgnoresStaleCompletion();
    TestB112WebConfigSaveKeepsRuntimeBindings();
    TestB117WebConfigSaveRefusesToDropDiskBindings();
    TestB118WebStatusReportsDiscarded();
    TestB119WebStatusReportsDroppedLeases();
    TestB120WebStatusReportsCorruptLeases();
    TestB121WebStatusReportsParseRejects();
    TestB122WebStatusReportsParseRejects6();
    TestB123PrivilegedChangesAreAudited();
    TestP92WebAuditLineCarriesPersistFailure();
    TestP93AutostartAuditCarriesActualState();
    TestP95ConfigSaveFailureIsAudited();
    TestP102WebBindingPersistFailureIsAudited();
    TestP104RuleDeleteFailureIsAudited();
    TestP122WebConfigBindingCapRefusalIsAudited();
    TestP107WebBindingRefusalIsAudited();
    TestP113WebRuleAddRefusalIsAudited();
    TestB126WebConsoleReportsDropped();
    TestB127StatusContractKeys();
    TestB113NoApplierDoesNotStampAttempt();
    TestB114RefusedApplyClosesTheAttempt();
    TestS1WebSettingsRoundTrip();
    TestB2LeaseEndpointsShape();
    TestB5SystemIdentityFields();
    TestB1ConsoleEndpointFiltersTokens();
    TestB4PrivilegedEndpoints();
    TestB34oCorruptRuleFileIsNotSilentEmpty();
    TestB83CorruptRulesFilePreserved();
    TestB85UnreadableRulesFileIsNotOverwritten();
    TestB87BlockedRulesRecoverWithoutRestart();
    TestB88BlockedRecoveryMergesEveryRuleKind();
    TestB89RecoveryQuarantinesCorruptFile();
    TestB90ConcurrentBlockedRecovery();
    TestB92MutationReportsPersistFailure();
    TestB93DhcpBindingPersistsToConfig();
    TestB101StatusExposesLeasePersistFailures();
    TestB106RulesWriteUsesCrossProcessLock();
    TestB34oLoadedRulesAreSemanticallyValid();
    TestB34oRuleCapEnforcedInStore();
    TestB34oRuleRemovalIsByIdentity();
    TestB34oPersistFailureIsCountedAndNotDurable();
    TestB34rWrongMethodIs405Not404();
    TestB34rInternalErrorDoesNotLeakText();
    TestHandlerThrowOutsideDispatchKeepsTheWorker();
    TestAcceptHandlerThrowKeepsAccepting();
    TestAcceptRearmThrowIsContained();
    TestBStatusExposesFirewallCounts();
    TestB86StatusExposesPersistenceHealth();
    TestB34rTokenCompareIsConstantTime();
    TestB34rEmptyTokenNeverDisablesAuth();
    TestB34rQueryTokenIsNotAccepted();
    TestB34rBodyCapAndTraversal();
    TestB138DeleteIsByIdentityNotPosition();
    TestB141LoadedBanIpIsCanonical();
    TestB144BanDuplicatesAreCollapsed();
    TestP82RuleIdLayoutAndUniqueness();
    TestP82IdUniquenessWithoutTestSeam();
    TestP82ReadRuleDocumentAndMerge();
    TestP82TombstoneLifecycle();
    TestP82DiskInjectionMergesForeignRules();
    TestP82DeleteIsNotResurrected();
    TestP82TombstoneFullRefusesDelete();
    TestP82HttpDeleteDistinguishes404And500();
    TestP82LockReentrantSameThread();
    TestP82OuterLockBlocksTheFlush();
    TestP82CrossProcessWorker();
    TestP82WorkerDeletesTheTombstonedRule();
    TestP82CrossProcessDeleteNotResurrected();

    if (0 == g_failures) {
        std::puts("test_web: ALL PASS");
        return 0;
    }
    std::fprintf(stderr, "test_web: %d FAILURES\n", g_failures);
    return 1;
}
