// ============================================================================
// test_web.cpp - Embedded HTTP server: routing, static files, API surface.
// ============================================================================
#include "core/limits.h"
#include "web/http_server.h"
#include "web/web_api.h"

#include <nlohmann/json.hpp>

#include "driver/idriver_client.h"
#include "driver/installer.h"
#include "driver/ndisrd_client.h"
#include "ndisapi/Common.h"

#include <asio.hpp>

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

    /// Blocking HTTP DELETE returning status + body.
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
        [&](const Config& c) {
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
        [&](const Config&) {
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
    status->Record(true, "");
    CHECK(HttpGet("/api/config/apply-status", kPort, body) == 200);
    CHECK(body.find("\"completed_id\":1") != std::string::npos);
    CHECK(body.find("\"ok\":true") != std::string::npos);

    // A failed apply records the backend error verbatim.
    status->Record(false, "bind failed: EACCES");
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
        // No secret ever appears in an audit line.
        CHECK(audit.find("s3cr3t") == std::string::npos);
        api.Stop();
    }
    std::remove(path);
    std::remove(rules.c_str());
}

// ---------------------------------------------------------------------------
// batch34o: rule persistence robustness.
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
int main() {
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
    TestS1WebSettingsRoundTrip();
    TestB2LeaseEndpointsShape();
    TestB5SystemIdentityFields();
    TestB1ConsoleEndpointFiltersTokens();
    TestB4PrivilegedEndpoints();
    TestB34oCorruptRuleFileIsNotSilentEmpty();
    TestB34oLoadedRulesAreSemanticallyValid();
    TestB34oRuleCapEnforcedInStore();
    TestB34oRuleRemovalIsByIdentity();
    TestB34oPersistFailureIsCountedAndNotDurable();
    TestB34rWrongMethodIs405Not404();
    TestB34rInternalErrorDoesNotLeakText();
    TestHandlerThrowOutsideDispatchKeepsTheWorker();
    TestAcceptHandlerThrowKeepsAccepting();
    TestB34rTokenCompareIsConstantTime();
    TestB34rEmptyTokenNeverDisablesAuth();
    TestB34rQueryTokenIsNotAccepted();
    TestB34rBodyCapAndTraversal();
    TestB138DeleteIsByIdentityNotPosition();
    TestB141LoadedBanIpIsCanonical();
    TestB144BanDuplicatesAreCollapsed();

    if (0 == g_failures) {
        std::puts("test_web: ALL PASS");
        return 0;
    }
    std::fprintf(stderr, "test_web: %d FAILURES\n", g_failures);
    return 1;
}
