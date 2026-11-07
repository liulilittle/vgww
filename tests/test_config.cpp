// ============================================================================
// test_config.cpp - Configuration parsing, validation and helpers.
// ============================================================================
#include "core/config.h"

#include <cstdio>
#include <direct.h>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>
#include <windows.h>

namespace {

    using vgww::core::Config;

    int g_failures = 0;

#define CHECK(cond)                                                        \
    do {                                                                   \
        if (!(cond)) {                                                     \
            std::fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__,  \
                         __LINE__, #cond);                                 \
            ++g_failures;                                                  \
        }                                                                  \
    } while (0)

    bool WriteFile(const std::string& path, const std::string& content) {
        std::ofstream out(path);
        if (!out) return false;
        out << content;
        return true;
    }

    void TestMacRoundTrip() {
        vgww::core::MacAddress mac{};
        CHECK(vgww::core::ParseMac("30:fc:68:88:b4:a9", mac));
        CHECK((mac == vgww::core::MacAddress{0x30, 0xfc, 0x68, 0x88, 0xb4, 0xa9}));
        CHECK(vgww::core::FormatMac(mac) == "30FC6888B4A9" ||
              vgww::core::FormatMac(mac) == "30:FC:68:88:B4:A9");
        // Separators are optional; lowercase accepted.
        CHECK(vgww::core::ParseMac("30fc6888b4a9", mac));
        // Malformed inputs must fail cleanly.
        CHECK(!vgww::core::ParseMac("30:fc:68:88:b4", mac));
        CHECK(!vgww::core::ParseMac("30:fc:68:88:b4:a9:aa", mac));
        CHECK(!vgww::core::ParseMac("zz:fc:68:88:b4:a9", mac));
    }

    void TestIpv4Helpers() {
        bool ok = false;
        const uint32_t ip = vgww::core::ParseIpv4("192.168.0.40", ok);
        CHECK(ok);
        // Network byte order for 192.168.0.40 is 0xC0A80028.
        CHECK(ip == 0x28'00'A8'C0u);
        CHECK(vgww::core::FormatIpv4(ip) == "192.168.0.40");
        vgww::core::ParseIpv4("256.1.1.1", ok);
        CHECK(!ok);
        vgww::core::ParseIpv4("1.2.3", ok);
        CHECK(!ok);
        vgww::core::ParseIpv4("a.b.c.d", ok);
        CHECK(!ok);
    }

    void TestLoadValidConfig() {
        const std::string path = "test_config_valid.json";
        // NOTE: keep raw strings OUT of macro arguments - the MSVC traditional
        // preprocessor mis-parses them. Assign first, assert separately.
        const std::string json_text = R"({
            "adapter": "Ethernet",
            "gateway": { "ipv4": "192.168.0.40", "mask": "255.255.255.0",
                         "mac": "30:fc:68:88:b4:a9" },
            "perf": { "workers": 4 }
        })";
        const bool wrote = WriteFile(path, json_text);
        CHECK(wrote);
        std::string error;
        auto config = Config::LoadFromFile(path, error);
        CHECK(config.has_value());
        if (config) {
            CHECK(config->gateway.ipv4 == 0x28'00'A8'C0u);
            CHECK(config->perf.workers == 4);  // override applied
            CHECK(config->perf.rx_batch == 64);  // default preserved
            // M3: hardened per-worker UDP flow table default (was 65536).
            CHECK(config->perf.udp_flow_cap == 8192);
        }
        std::remove(path.c_str());
    }

    void TestValidation() {
        std::string error;
        // Missing gateway section must be rejected.
        error.clear();
        const std::string path2 = "test_config_no_gateway.json";
        CHECK(WriteFile(path2, "{}"));
        CHECK(!Config::LoadFromFile(path2, error).has_value());
        std::remove(path2.c_str());
    }

    // ---------------------------------------------------------------------
    // Config validation probes (A9). Every rejected case below MUST fail
    // with a config error - none of them are acceptable at startup.
    // ---------------------------------------------------------------------

    struct LoadResult {
        bool wrote = false;
        std::optional<Config> config;
        std::string error;
    };

    LoadResult LoadFromText(const std::string& path, const std::string& text) {
        LoadResult r;
        r.wrote = WriteFile(path, text);
        if (r.wrote) {
            r.config = Config::LoadFromFile(path, r.error);
            std::remove(path.c_str());
        }
        return r;
    }

    // A valid LAN skeleton (gateway). `extra` is appended
    // as additional sibling JSON sections before the closing brace.
    std::string Skeleton(const std::string& extra) {
        std::string out =
            R"({"gateway":{"ipv4":"192.168.0.40","mask":"255.255.255.0","mac":"30:fc:68:88:b4:a9"})";
        if (!extra.empty()) {
            out += "," + extra;
        }
        out += "}";
        return out;
    }

    void TestPerfValidation() {
        const auto reject = [](const std::string& perf) {
            const auto r = LoadFromText("test_cfg_perf.json",
                                        Skeleton("\"perf\":" + perf));
            CHECK(r.wrote);
            CHECK(!r.config.has_value());
        };
        // Every perf field must be > 0; workers bounded by the shard count.
        reject(R"({"ring_capacity":0})");
        reject(R"({"rx_batch":0})");
        reject(R"({"max_conns":0})");
        reject(R"({"udp_flow_cap":0})");
        reject(R"({"workers":0})");
        reject(R"({"workers":9})");
        reject(R"({"dial_timeout_ms":0})");
        reject(R"({"udp_flow_cap":65537})");   // M3: new ceiling
        // Explicit upper sanity bounds.
        reject(R"({"ring_capacity":1048577})");
        reject(R"({"rx_batch":4097})");
        reject(R"({"dial_timeout_ms":3600001})");

        // The old default (65536) stays loadable: cap = old default.
        const auto cap_ok = LoadFromText(
            "test_cfg_perf.json", Skeleton(R"("perf":{"udp_flow_cap":65536})"));
        CHECK(cap_ok.wrote);
        CHECK(cap_ok.config.has_value());
        if (cap_ok.config) {
            CHECK(cap_ok.config->perf.udp_flow_cap == 65536);
        }

        // All minimums accepted.
        const auto ok = LoadFromText(
            "test_cfg_perf.json",
            Skeleton(R"("perf":{"workers":1,"rx_batch":1,"max_conns":1,"udp_flow_cap":1,"ring_capacity":1,"dial_timeout_ms":1})"));
        CHECK(ok.wrote);
        CHECK(ok.config.has_value());
        if (ok.config) {
            CHECK(ok.config->perf.ring_capacity == 1);
            CHECK(ok.config->perf.workers == 1);
            CHECK(ok.config->perf.udp_flow_cap == 1);
        }
    }

    std::string GatewayJson(const std::string& ipv4, const std::string& mask) {
        return "{\"gateway\":{\"ipv4\":\"" + ipv4 + "\",\"mask\":\"" + mask +
               "\",\"mac\":\"30:fc:68:88:b4:a9\"}}";
    }

    void TestGatewayValidation() {
        const auto reject = [](const std::string& json) {
            const auto r = LoadFromText("test_cfg_gateway.json", json);
            CHECK(r.wrote);
            CHECK(!r.config.has_value());
        };
        // A zero mask accepts every subnet; a host-style netmask
        // (0.255.255.255) would collide with the 0.0.0.0/30 check; here we
        // use the classic non-contiguous 255.255.0.255.
        reject(GatewayJson("192.168.0.40", "0.0.0.0"));
        reject(GatewayJson("192.168.0.40", "255.255.0.255"));
        reject(GatewayJson("192.168.0.40", "255.0.255.0"));
        reject(GatewayJson("0.0.0.0", "255.255.255.0"));

        // Valid masks (255.255.255.0, 255.255.0.0) accepted.
        const auto ok = LoadFromText(
            "test_cfg_gateway.json",
            GatewayJson("192.168.0.40", "255.255.0.0"));
        CHECK(ok.wrote);
        CHECK(ok.config.has_value());

        // Non-byte-aligned contiguous prefixes (/25, /30, /31) are legal:
        // the old byte-order-invariant mask&(mask+1) check wrongly rejected
        // them (e.g. 255.255.255.128 -> 0x80FFFFFF & (+1) != 0).
        const char* valid_masks[] = {"255.255.255.128", "255.255.255.252",
                                     "255.255.255.254"};
        for (const char* mask : valid_masks) {
            const auto r = LoadFromText(
                "test_cfg_gateway.json", GatewayJson("192.168.0.40", mask));
            CHECK(r.wrote);
            CHECK(r.config.has_value());
            if (r.config) {
                bool ok2 = false;
                CHECK(vgww::core::ParseIpv4(mask, ok2) == r.config->gateway.mask);
                CHECK(ok2);
            }
        }
    }

    void TestIpv6Validation() {
        const auto reject = [](const std::string& ipv6) {
            const auto r = LoadFromText("test_cfg_ipv6.json",
                                        Skeleton("\"ipv6\":" + ipv6));
            CHECK(r.wrote);
            CHECK(!r.config.has_value());
        };
        // A 0 router lifetime revokes the RA default route; >65535 cannot
        // fit the 16-bit RA field.
        reject(R"({"enabled":true,"ula_prefix":"fdaa:0:0::/48","ra_lifetime_s":0})");
        reject(R"({"enabled":true,"ula_prefix":"fdaa:0:0::/48","ra_lifetime_s":70000})");
        // IPv6 enabled requires a valid ULA prefix (SLAAC source).
        reject(R"({"enabled":true})");
        reject(R"({"enabled":true,"ula_prefix":"garbage","ra_lifetime_s":1800})");
        // Prefix length must agree with the ULA text suffix and stay <= 64.
        reject(R"({"enabled":true,"ula_prefix":"fdaa:0:0::/48","prefix_len":64})");
        reject(R"({"enabled":true,"ula_prefix":"fdaa:0:0::/48","prefix_len":65})");
        reject(R"({"enabled":true,"ula_prefix":"fdaa:0:0::/120","ra_lifetime_s":1800})");
        // Host bits beyond the prefix length must be zero.
        reject(R"({"enabled":true,"ula_prefix":"fdaa:0:0:1::/48","ra_lifetime_s":1800})");
        // Only ULA (fc00::/7) prefixes are routable on this gateway.
        reject(R"({"enabled":true,"ula_prefix":"2001:db8::/32","ra_lifetime_s":1800})");

        // A valid ULA + lifetime is accepted and the bytes are wired through.
        const auto ok = LoadFromText(
            "test_cfg_ipv6.json",
            Skeleton(
                R"("ipv6":{"enabled":true,"ula_prefix":"fdaa:0:0::/48","ra_lifetime_s":65535})"));
        CHECK(ok.wrote);
        CHECK(ok.config.has_value());
        if (ok.config) {
            const auto& p = ok.config->ipv6.ula_prefix;
            CHECK(p[0] == 0xFD);
            CHECK(p[1] == 0xAA);
            CHECK(p[2] == 0 && p[3] == 0 && p[4] == 0 && p[5] == 0);
            CHECK(ok.config->ipv6.prefix_len == 48);
            CHECK(ok.config->ipv6.ra_lifetime_s == 65535);
        }

        // A bare prefix + explicit prefix_len key also works.
        const auto no_slash = LoadFromText(
            "test_cfg_ipv6.json",
            Skeleton(R"("ipv6":{"enabled":true,"ula_prefix":"fd00::","prefix_len":64})"));
        CHECK(no_slash.wrote);
        CHECK(no_slash.config.has_value());
        if (no_slash.config) {
            CHECK(no_slash.config->ipv6.ula_prefix[0] == 0xFD);
            CHECK(no_slash.config->ipv6.prefix_len == 64);
        }

        // RDNSS: up to 3 full v6 addresses are accepted and byte-preserved.
        const auto dns_ok = LoadFromText(
            "test_cfg_ipv6.json",
            Skeleton(
                R"("ipv6":{"enabled":true,"ula_prefix":"fd00::/64","dns":["fd00::53","fe80::1"]})"));
        CHECK(dns_ok.wrote);
        CHECK(dns_ok.config.has_value());
        if (dns_ok.config) {
            CHECK(dns_ok.config->ipv6.dns.size() == 2);
            CHECK(dns_ok.config->ipv6.dns[0][0] == 0xFD);
            CHECK(dns_ok.config->ipv6.dns[0][15] == 0x53);
            CHECK(dns_ok.config->ipv6.dns[1][0] == 0xFE);
            CHECK(dns_ok.config->ipv6.dns[1][15] == 0x01);
        }
        // An empty dns list is allowed (no RDNSS => today's behavior).
        const auto empty_dns = LoadFromText(
            "test_cfg_ipv6.json",
            Skeleton(
                R"("ipv6":{"enabled":true,"ula_prefix":"fd00::/64","dns":[]})"));
        CHECK(empty_dns.wrote);
        CHECK(empty_dns.config.has_value());
        if (empty_dns.config) {
            CHECK(empty_dns.config->ipv6.dns.empty());
        }
        // An unspecified address (::) must be skipped, not advertised.
        const auto zero_dns = LoadFromText(
            "test_cfg_ipv6.json",
            Skeleton(
                R"("ipv6":{"enabled":true,"ula_prefix":"fd00::/64","dns":["::","fd00::1"]})"));
        CHECK(zero_dns.wrote);
        CHECK(zero_dns.config.has_value());
        if (zero_dns.config) {
            CHECK(zero_dns.config->ipv6.dns.size() == 1);
            CHECK(zero_dns.config->ipv6.dns[0][0] == 0xFD);
        }
        // Reject: more than 3, a "/length" suffix, malformed, non-string.
        const auto reject_dns = [&](const std::string& dns) {
            const auto r = LoadFromText(
                "test_cfg_ipv6.json",
                Skeleton(R"("ipv6":{"enabled":true,"ula_prefix":"fd00::/64","dns":)"
                            + dns + "}"));
            CHECK(r.wrote);
            CHECK(!r.config.has_value());
        };
        reject_dns(R"(["fd00::1","fd00::2","fd00::3","fd00::4"])");
        reject_dns(R"(["fd00::1/64"])");
        reject_dns(R"(["garbage"])");
        reject_dns(R"([42])");
        reject_dns(R"("fd00::1")");
    }

    void TestVlanValidation() {
        // A valid single access VLAN must load and preserve its id.
        const auto ok = LoadFromText(
            "test_cfg_vlan.json", Skeleton(R"("vlan":{"id":100})"));
        CHECK(ok.wrote);
        CHECK(ok.config.has_value());
        if (ok.config) {
            CHECK(ok.config->vlan.id == 100);
            CHECK(ok.config->vlan.enabled());
        }
        // Absent section = disabled, id stays 0.
        const auto absent = LoadFromText("test_cfg_vlan.json", Skeleton(""));
        CHECK(absent.wrote);
        CHECK(absent.config.has_value());
        if (absent.config) {
            CHECK(!absent.config->vlan.enabled());
        }
        // Lower boundary: 1 is the smallest valid, explicit id (the example
        // file ships with id:1 - a 0 there would be rejected at load).
        const auto lo = LoadFromText(
            "test_cfg_vlan.json", Skeleton(R"("vlan":{"id":1})"));
        CHECK(lo.wrote);
        CHECK(lo.config.has_value());
        if (lo.config) {
            CHECK(lo.config->vlan.id == 1);
            CHECK(lo.config->vlan.enabled());
        }
        // Out-of-range and reserved ids must be rejected, never accepted.
        const auto reject = [](const std::string& vlan) {
            const auto r = LoadFromText(
                "test_cfg_vlan.json", Skeleton("\"vlan\":" + vlan));
            CHECK(r.wrote);
            CHECK(!r.config.has_value());
        };
        reject(R"({"id":0})");          // 0x000 reserved (untagged)
        reject(R"({"id":4095})");       // 0xFFF reserved
        reject(R"({"id":4096})");       // out of 12-bit range
        reject(R"({"id":65535})");      // way out of range
        reject(R"({"id":-1})");
        reject(R"("100")");             // not an object
        reject(R"({"id":"100"})");      // not an integer
    }

    void TestWebPortValidation() {
        const auto reject = [](const uint32_t port) {
            const std::string json =
                Skeleton("\"web\":{\"port\":" + std::to_string(port) + "}");
            const auto r = LoadFromText("test_cfg_web.json", json);
            CHECK(r.wrote);
            CHECK(!r.config.has_value());
        };
        // Ephemeral (0) or privileged (1..1023) ports are not allowed for
        // the management UI; > 65535 cannot fit uint16.
        reject(0);
        reject(80);
        reject(1023);
        reject(70000);

        const auto lo = LoadFromText("test_cfg_web.json",
                                     Skeleton(R"("web":{"port":1024})"));
        CHECK(lo.wrote);
        CHECK(lo.config.has_value());
        if (lo.config) {
            CHECK(lo.config->web.port == 1024);
        }

        const auto hi = LoadFromText("test_cfg_web.json",
                                     Skeleton(R"("web":{"port":65535})"));
        CHECK(hi.wrote);
        CHECK(hi.config.has_value());
        if (hi.config) {
            CHECK(hi.config->web.port == 65535);
        }
    }

    void TestStringAndDnsSuperLargeCaps() {
        std::string a256(256, 'a');
        std::string a257(257, 'a');
        const auto okA = LoadFromText("test_cfg_a256.json",
            Skeleton("\"adapter\":\"" + a256 + "\""));
        CHECK(okA.wrote);
        CHECK(okA.config.has_value());
        const auto badA = LoadFromText("test_cfg_a257.json",
            Skeleton("\"adapter\":\"" + a257 + "\""));
        CHECK(badA.wrote);
        CHECK(!badA.config.has_value());
        const auto okT = LoadFromText("test_cfg_t256.json",
            Skeleton("\"web\":{\"port\":8080,\"token\":\"" + a256 + "\"}"));
        CHECK(okT.wrote);
        CHECK(okT.config.has_value());
        const auto badT = LoadFromText("test_cfg_t257.json",
            Skeleton("\"web\":{\"port\":8080,\"token\":\"" + a257 + "\"}"));
        CHECK(badT.wrote);
        CHECK(!badT.config.has_value());
    }

    void TestLongUtf8PathConversion() {
        // The UTF-8 -> UTF-16 conversion runs BEFORE the file is opened, so a
        // missing file still exercises the buffer sizing. The old code did
        // resize(wlen - 1) and then wrote wlen elements: a 1-element overflow
        // that only ASan can see (SSO hides short inputs).
        std::string path;
        for (int i = 0; i < 40; ++i) {
            path += "\xE5\xAD\x90\xE7\x9B\xAE/";  // "subdir/" x40
        }
        path += "missing_config.json";
        std::string error;
        const auto cfg = Config::LoadFromFile(path, error);
        CHECK(!cfg.has_value());
        CHECK(!error.empty());
        // Empty input exercises the wlen <= 0 early-out.
        error.clear();
        CHECK(!Config::LoadFromFile("", error).has_value());
    }

    // ---------------------------------------------------------------------
    // config.mode (S2 Task 1): optional "mode": "bypass" | "main".
    // Absent = bypass (current behavior); anything else is rejected.
    // ---------------------------------------------------------------------

    void TestModeDefaultsToBypass() {
        const auto r = LoadFromText("test_cfg_mode.json", Skeleton(""));
        CHECK(r.wrote);
        CHECK(r.config.has_value());
        if (r.config) {
            CHECK(r.config->mode == vgww::core::Mode::kBypass);
            CHECK(!vgww::core::AddressServicesEnabled(*r.config));
        }
    }

    void TestModeMainParsed() {
        const auto r = LoadFromText("test_cfg_mode.json",
                                    Skeleton(R"("mode":"main")"));
        CHECK(r.wrote);
        CHECK(r.config.has_value());
        if (r.config) {
            CHECK(r.config->mode == vgww::core::Mode::kMain);
            CHECK(vgww::core::AddressServicesEnabled(*r.config));
        }
    }

    void TestModeRejectsUnknownValue() {
        // Exact lowercase only: empty, case variants and garbage are
        // rejected with a mode-specific error.
        const char* bad_modes[] = {"", "MAIN", "Main", "foo", "bypass "};
        for (const char* value : bad_modes) {
            const std::string text =
                Skeleton(std::string("\"mode\":\"") + value + "\"");
            const auto r = LoadFromText("test_cfg_mode.json", text);
            CHECK(r.wrote);
            CHECK(!r.config.has_value());
            CHECK(r.error.find("mode") != std::string::npos);
        }
    }

    void TestModeRejectsNonString() {
        // Numbers, booleans, objects, arrays and null must all fail with a
        // non-empty error (never silently fall back to bypass).
        const char* bad_values[] = {"1", "true", "{}", "[]", "null"};
        for (const char* value : bad_values) {
            const auto r = LoadFromText(
                "test_cfg_mode.json",
                Skeleton(std::string("\"mode\":") + value));
            CHECK(r.wrote);
            CHECK(!r.config.has_value());
            CHECK(!r.error.empty());
        }
    }

    // ---------------------------------------------------------------------
    // dhcp section (S2 Task 2): schema restored from d6c7dd5. The section is
    // parsed in both modes; pool semantics are enforced only in main mode.
    // ---------------------------------------------------------------------

    void TestDhcpConfigParsed() {
        const std::string section =
            R"("dhcp":{"enabled":true,"pool":["192.168.0.100","192.168.0.200"],"lease_hours":12})";
        const auto r = LoadFromText("test_cfg_dhcp.json", Skeleton(section));
        CHECK(r.wrote);
        CHECK(r.config.has_value());
        if (r.config) {
            bool ok = false;
            const uint32_t start = vgww::core::ParseIpv4("192.168.0.100", ok);
            CHECK(ok);
            const uint32_t end = vgww::core::ParseIpv4("192.168.0.200", ok);
            CHECK(ok);
            CHECK(r.config->dhcp.enabled);
            CHECK(r.config->dhcp.pool_start == start);
            CHECK(r.config->dhcp.pool_end == end);
            CHECK(r.config->dhcp.lease_seconds == 12 * 3600u);
        }

        // Malformed shapes are rejected (never silently ignored).
        const auto not_object =
            LoadFromText("test_cfg_dhcp.json", Skeleton(R"("dhcp":[])"));
        CHECK(not_object.wrote);
        CHECK(!not_object.config.has_value());
        const auto wrong_enabled = LoadFromText(
            "test_cfg_dhcp.json",
            Skeleton(R"("dhcp":{"enabled":"yes"})"));
        CHECK(wrong_enabled.wrote);
        CHECK(!wrong_enabled.config.has_value());
    }

    void TestDhcpPoolArrayRejectsBadEntry() {
        // The "pool": [start,end] array form must hard-error on a malformed
        // entry like the pool_start/pool_end compatibility keys do - the
        // regression silently swallowed JsonToIpv4 failures and left a
        // 0.0.0.0 bound that failed later with a confusing error.
        const auto bad = LoadFromText(
            "test_cfg_dhcp.json",
            Skeleton(R"("dhcp":{"pool":["192.168.0.100","bad"]})"));
        CHECK(bad.wrote);
        CHECK(!bad.config.has_value());
        CHECK(!bad.error.empty());
    }

    void TestDhcpLeaseHoursBounds() {
        const char* bad[] = {"0", "8761"};
        for (const char* hours : bad) {
            const auto r = LoadFromText(
                "test_cfg_dhcp.json",
                Skeleton(std::string("\"dhcp\":{\"lease_hours\":") + hours +
                         "}"));
            CHECK(r.wrote);
            CHECK(!r.config.has_value());
            CHECK(r.error.find("lease_hours") != std::string::npos);
        }
        // A non-numeric value is a hard error too (never a silent default).
        const auto wrong_type = LoadFromText(
            "test_cfg_dhcp.json", Skeleton(R"("dhcp":{"lease_hours":"12"})"));
        CHECK(wrong_type.wrote);
        CHECK(!wrong_type.config.has_value());
        // Both bounds are inclusive.
        const auto lo = LoadFromText(
            "test_cfg_dhcp.json", Skeleton(R"("dhcp":{"lease_hours":1})"));
        CHECK(lo.wrote);
        CHECK(lo.config.has_value());
        if (lo.config) {
            CHECK(lo.config->dhcp.lease_seconds == 3600u);
        }
        const auto hi = LoadFromText(
            "test_cfg_dhcp.json", Skeleton(R"("dhcp":{"lease_hours":8760})"));
        CHECK(hi.wrote);
        CHECK(hi.config.has_value());
        if (hi.config) {
            CHECK(hi.config->dhcp.lease_seconds == 8760u * 3600u);
        }
    }

    void TestDhcpDnsCapRejected() {
        // One over kMaxDhcpDns (4) is a hard error, not a silent truncation.
        const std::string five =
            R"("dhcp":{"dns":["192.168.0.1","192.168.0.2","192.168.0.3","192.168.0.4","192.168.0.5"]})";
        const auto over = LoadFromText("test_cfg_dhcp.json", Skeleton(five));
        CHECK(over.wrote);
        CHECK(!over.config.has_value());
        CHECK(!over.error.empty());

        // The cap itself is accepted.
        const std::string four =
            R"("dhcp":{"dns":["192.168.0.1","192.168.0.2","192.168.0.3","192.168.0.4"]})";
        const auto ok = LoadFromText("test_cfg_dhcp.json", Skeleton(four));
        CHECK(ok.wrote);
        CHECK(ok.config.has_value());
        if (ok.config) {
            CHECK(ok.config->dhcp.dns.size() == 4);
        }
    }

    void TestDhcpStaticBindingDuplicates() {
        // Same IP twice (distinct MACs).
        const std::string dup_ip =
            R"("dhcp":{"static_bindings":[)"
            R"({"mac":"30:fc:68:88:b4:01","ip":"192.168.0.50"},)"
            R"({"mac":"30:fc:68:88:b4:02","ip":"192.168.0.50"}]})";
        const auto ip = LoadFromText("test_cfg_dhcp.json", Skeleton(dup_ip));
        CHECK(ip.wrote);
        CHECK(!ip.config.has_value());

        // Same MAC twice (distinct IPs).
        const std::string dup_mac =
            R"("dhcp":{"static_bindings":[)"
            R"({"mac":"30:fc:68:88:b4:01","ip":"192.168.0.50"},)"
            R"({"mac":"30:fc:68:88:b4:01","ip":"192.168.0.51"}]})";
        const auto mac = LoadFromText("test_cfg_dhcp.json", Skeleton(dup_mac));
        CHECK(mac.wrote);
        CHECK(!mac.config.has_value());

        // A binding that equals the gateway is always rejected.
        const std::string gw_binding =
            R"("dhcp":{"static_bindings":[)"
            R"({"mac":"30:fc:68:88:b4:01","ip":"192.168.0.40"}]})";
        const auto gw = LoadFromText("test_cfg_dhcp.json", Skeleton(gw_binding));
        CHECK(gw.wrote);
        CHECK(!gw.config.has_value());
    }

    void TestDhcpStaticHostnameTooLong() {
        const auto section = [](size_t len) {
            return std::string(R"("dhcp":{"static_bindings":[)"
                               R"({"mac":"30:fc:68:88:b4:01","ip":"192.168.0.50","hostname":")") +
                   std::string(len, 'a') + "\"}]}";
        };

        const auto over = LoadFromText("test_cfg_dhcp.json", Skeleton(section(254)));
        CHECK(over.wrote);
        CHECK(!over.config.has_value());

        // 253 characters is the accepted maximum.
        const auto ok = LoadFromText("test_cfg_dhcp.json", Skeleton(section(253)));
        CHECK(ok.wrote);
        CHECK(ok.config.has_value());
        if (ok.config) {
            CHECK(ok.config->dhcp.static_bindings.size() == 1);
            CHECK(ok.config->dhcp.static_bindings[0].hostname.size() == 253);
        }
    }

    void TestDhcpValidationModeScoped() {
        // Pool outside the gateway subnet (192.168.0.0/24).
        const std::string outside =
            R"("dhcp":{"enabled":true,"pool":["10.0.0.100","10.0.0.200"]})";
        const auto bypass = LoadFromText("test_cfg_dhcp.json", Skeleton(outside));
        CHECK(bypass.wrote);
        CHECK(bypass.config.has_value());
        if (bypass.config) {
            bool ok = false;
            CHECK(bypass.config->dhcp.pool_start ==
                  vgww::core::ParseIpv4("10.0.0.100", ok));
            CHECK(ok);
        }
        const auto main = LoadFromText(
            "test_cfg_dhcp.json",
            Skeleton(outside + R"(,"mode":"main")"));
        CHECK(main.wrote);
        CHECK(!main.config.has_value());
        CHECK(!main.error.empty());

        // A pool containing the gateway, and a reversed pool, are main-only
        // violations as well.
        const std::string contains_gw =
            R"("dhcp":{"enabled":true,"pool":["192.168.0.30","192.168.0.50"]})";
        const std::string reversed =
            R"("dhcp":{"enabled":true,"pool":["192.168.0.200","192.168.0.100"]})";
        for (const std::string* section : {&contains_gw, &reversed}) {
            const auto skip =
                LoadFromText("test_cfg_dhcp.json", Skeleton(*section));
            CHECK(skip.wrote);
            CHECK(skip.config.has_value());
            const auto reject = LoadFromText(
                "test_cfg_dhcp.json",
                Skeleton(*section + R"(,"mode":"main")"));
            CHECK(reject.wrote);
            CHECK(!reject.config.has_value());
        }

        // enabled=true without a pool key: main rejects (empty pool), bypass
        // parses it (pool semantics skipped).
        const std::string no_pool = R"("dhcp":{"enabled":true})";
        const auto no_pool_bypass =
            LoadFromText("test_cfg_dhcp.json", Skeleton(no_pool));
        CHECK(no_pool_bypass.wrote);
        CHECK(no_pool_bypass.config.has_value());
        const auto no_pool_main = LoadFromText(
            "test_cfg_dhcp.json", Skeleton(no_pool + R"(,"mode":"main")"));
        CHECK(no_pool_main.wrote);
        CHECK(!no_pool_main.config.has_value());
    }

    void TestDhcp6ConfigParsed() {
        // Pool semantics are enforced in main mode only (mirrors dhcp v4), so
        // the accepted case carries mode:main.
        const std::string ok_section =
            R"("ipv6":{"enabled":true,"ula_prefix":"fd00::/64","dhcpv6":)"
            R"({"enabled":true,"pool_start":"fd00::1000",)"
            R"("pool_end":"fd00::1fff","lease_seconds":7200,)"
            R"("static_bindings":[{)"
            R"("duid":"0003000100ff","ip":"fd00::5000","hostname":"nas"}]}},)"
            R"("mode":"main")";
        const auto ok = LoadFromText("test_cfg_dhcp6.json", Skeleton(ok_section));
        CHECK(ok.wrote);
        CHECK(ok.config.has_value());
        if (ok.config) {
            const auto& d6 = ok.config->ipv6.dhcpv6;
            CHECK(d6.enabled);
            CHECK(d6.pool_start[0] == 0xFD && d6.pool_start[14] == 0x10 &&
                  d6.pool_start[15] == 0x00);
            CHECK(d6.pool_end[14] == 0x1F && d6.pool_end[15] == 0xFF);
            CHECK(d6.lease_seconds == 7200u);
            CHECK(d6.static_bindings.size() == 1);
            if (d6.static_bindings.size() == 1) {
                const auto& b = d6.static_bindings[0];
                CHECK(b.duid.size() == 6);
                CHECK(b.duid[0] == 0x00 && b.duid[1] == 0x03 &&
                      b.duid[5] == 0xFF);
                CHECK(b.ip[0] == 0xFD && b.ip[14] == 0x50 && b.ip[15] == 0x00);
                CHECK(b.hostname == "nas");
            }
        }

        // Defaults: both pool keys absent stays zero in the config; the server
        // derives prefix::1000 - prefix::1FFF (spec section 5.2).
        const auto defaults = LoadFromText(
            "test_cfg_dhcp6.json",
            Skeleton(R"("ipv6":{"enabled":true,"ula_prefix":"fd00::/64",)"
                     R"("dhcpv6":{"enabled":true}},"mode":"main")"));
        CHECK(defaults.wrote);
        CHECK(defaults.config.has_value());
        if (defaults.config) {
            const auto& d6 = defaults.config->ipv6.dhcpv6;
            for (const uint8_t b : d6.pool_start) CHECK(b == 0);
            for (const uint8_t b : d6.pool_end) CHECK(b == 0);
            CHECK(d6.lease_seconds == 3600u);
            CHECK(d6.static_bindings.empty());
        }

        const auto reject = [](const std::string& d6) {
            const auto r = LoadFromText(
                "test_cfg_dhcp6.json",
                Skeleton(R"("ipv6":{"enabled":true,"ula_prefix":"fd00::/64",)"
                         R"("dhcpv6":)" + d6 + R"(},"mode":"main")"));
            CHECK(r.wrote);
            CHECK(!r.config.has_value());
            CHECK(!r.error.empty());
        };
        // Malformed shapes and out-of-range lifetimes are hard errors.
        reject(R"([])");
        reject(R"({"enabled":"yes"})");
        reject(R"({"enabled":true,"lease_seconds":59})");
        reject(R"({"enabled":true,"lease_seconds":31536001})");
        reject(R"({"enabled":true,"lease_seconds":"3600"})");
        // Pool outside the ULA prefix / reversed / suffixed / malformed.
        reject(R"({"enabled":true,"pool_start":"fd01::1000","pool_end":"fd01::1fff"})");
        reject(R"({"enabled":true,"pool_start":"fd00::2000","pool_end":"fd00::1000"})");
        reject(R"({"enabled":true,"pool_start":"fd00::1000/64"})");
        reject(R"({"enabled":true,"pool_start":"garbage"})");
        // DUID must be an even-length hex string of 1..128 octets.
        reject(R"({"enabled":true,"static_bindings":[{"duid":"00030","ip":"fd00::5000"}]})");
        reject(R"({"enabled":true,"static_bindings":[{"duid":"000300zz","ip":"fd00::5000"}]})");
        reject(R"({"enabled":true,"static_bindings":[{"duid":"","ip":"fd00::5000"}]})");
        reject(R"({"enabled":true,"static_bindings":[{"duid":42,"ip":"fd00::5000"}]})");
        {
            std::string too_long =
                R"({"enabled":true,"static_bindings":[{"duid":")";
            too_long += std::string(258, 'a');  // 129 octets
            too_long += R"(","ip":"fd00::5000"}]})";
            reject(too_long);
        }
        // Duplicates, out-of-prefix bindings and oversized hostnames.
        reject(R"({"enabled":true,"static_bindings":[)"
               R"({"duid":"00030001aa","ip":"fd00::5000"},)"
               R"({"duid":"00030001aa","ip":"fd00::5001"}]})");
        reject(R"({"enabled":true,"static_bindings":[)"
               R"({"duid":"00030001aa","ip":"fd00::5000"},)"
               R"({"duid":"00030001bb","ip":"fd00::5000"}]})");
        reject(R"({"enabled":true,"static_bindings":[{"duid":"00030001aa","ip":"fd01::5000"}]})");
        reject(R"({"enabled":true,"static_bindings":[{"duid":"00030001aa","ip":"fd00::5000","hostname":")"
               + std::string(254, 'h') + R"("}]})");
        // Super-large guard: one over kMaxStaticBindings6 (1024).
        {
            std::string many = R"({"enabled":true,"static_bindings":[)";
            for (size_t i = 0; i < 1025; ++i) {
                if (i) many += ",";
                char buf[80];
                std::snprintf(buf, sizeof(buf),
                              R"({"duid":"%08x","ip":"fd00::%x"})",
                              static_cast<unsigned>(i),
                              static_cast<unsigned>(0x5000 + i));
                many += buf;
            }
            many += "]}";
            reject(many);
        }
        // The cap itself (1024) is accepted.
        {
            std::string cap = R"({"enabled":true,"static_bindings":[)";
            for (size_t i = 0; i < 1024; ++i) {
                if (i) cap += ",";
                char buf[80];
                std::snprintf(buf, sizeof(buf),
                              R"({"duid":"%08x","ip":"fd00::%x"})",
                              static_cast<unsigned>(i),
                              static_cast<unsigned>(0x5000 + i));
                cap += buf;
            }
            cap += "]}";
            const auto r = LoadFromText(
                "test_cfg_dhcp6.json",
                Skeleton(R"("ipv6":{"enabled":true,"ula_prefix":"fd00::/64",)"
                         R"("dhcpv6":)" + cap + R"(},"mode":"main")"));
            CHECK(r.wrote);
            CHECK(r.config.has_value());
            if (r.config) {
                CHECK(r.config->ipv6.dhcpv6.static_bindings.size() == 1024);
            }
        }
        // Bypass parses the section but does not enforce pool semantics.
        const auto bypass = LoadFromText(
            "test_cfg_dhcp6.json",
            Skeleton(R"("ipv6":{"enabled":true,"ula_prefix":"fd00::/64",)"
                     R"("dhcpv6":{"enabled":true,"pool_start":"fd01::1000"}})"));
        CHECK(bypass.wrote);
        CHECK(bypass.config.has_value());
    }

}  // namespace

    // ----- S3-Task4: bridge section ------------------------------------

    /// Absent bridge section: disabled, default table size, empty ports.
    void TestBridgeConfigDefaults() {
        const auto r = LoadFromText("test_cfg_bridge.json", Skeleton(""));
        CHECK(r.wrote);
        CHECK(r.config.has_value());
        if (r.config) {
            CHECK(!r.config->bridge.enabled);
            CHECK(r.config->bridge.mac_table_size == 4096);
            CHECK(r.config->bridge.upstream.empty());
            CHECK(r.config->bridge.downstream.empty());
        }
    }

    /// A complete bridge section parses verbatim.
    void TestBridgeConfigParse() {
        const auto r = LoadFromText(
            "test_cfg_bridge.json",
            Skeleton(R"("bridge":{"enabled":true,"upstream":"NIC 1","downstream":"NIC 2","mac_table_size":1024})"));
        CHECK(r.wrote);
        CHECK(r.config.has_value());
        if (r.config) {
            CHECK(r.config->bridge.enabled);
            CHECK(r.config->bridge.upstream == "NIC 1");
            CHECK(r.config->bridge.downstream == "NIC 2");
            CHECK(r.config->bridge.mac_table_size == 1024);
        }
    }

    /// Upstream and downstream must differ; the error names the section.
    void TestBridgeRejectsSamePorts() {
        const auto r = LoadFromText(
            "test_cfg_bridge.json",
            Skeleton(R"("bridge":{"enabled":true,"upstream":"NIC 1","downstream":"NIC 1"})"));
        CHECK(r.wrote);
        CHECK(!r.config.has_value());
        CHECK(r.error.find("bridge") != std::string::npos);
    }

    /// Enabled bridges need both ports named.
    void TestBridgeRejectsEmptyPorts() {
        const auto empty_down = LoadFromText(
            "test_cfg_bridge.json",
            Skeleton(R"("bridge":{"enabled":true,"upstream":"NIC 1","downstream":""})"));
        CHECK(empty_down.wrote);
        CHECK(!empty_down.config.has_value());
        CHECK(empty_down.error.find("bridge") != std::string::npos);
        const auto empty_up = LoadFromText(
            "test_cfg_bridge.json",
            Skeleton(R"("bridge":{"enabled":true,"upstream":"","downstream":"NIC 2"})"));
        CHECK(empty_up.wrote);
        CHECK(!empty_up.config.has_value());
        CHECK(empty_up.error.find("bridge") != std::string::npos);
    }

    /// Table size bounds: 0 and >65536 rejected; 1 and 65536 accepted.
    void TestBridgeMacTableSizeBounds() {
        const auto reject = [](const std::string& size) {
            const auto r = LoadFromText(
                "test_cfg_bridge.json",
                Skeleton("\"bridge\":{\"enabled\":true,\"upstream\":\"NIC "
                         "1\",\"downstream\":\"NIC 2\",\"mac_table_size\":" +
                         size + "}"));
            CHECK(r.wrote);
            CHECK(!r.config.has_value());
        };
        reject("0");
        reject("65537");
        const auto accept = [](const std::string& size, uint32_t want) {
            const auto r = LoadFromText(
                "test_cfg_bridge.json",
                Skeleton("\"bridge\":{\"enabled\":true,\"upstream\":\"NIC "
                         "1\",\"downstream\":\"NIC 2\",\"mac_table_size\":" +
                         size + "}"));
            CHECK(r.wrote);
            CHECK(r.config.has_value());
            if (r.config) {
                CHECK(r.config->bridge.mac_table_size == want);
            }
        };
        accept("1", 1);
        accept("65536", 65536);
    }

void TestExampleConfigRoundTrip() {
        // The checked-in sample config must stay loadable and valid, so the
        // template cannot rot into an unaddressable example. A missing
        // example is an explicit failure, never a silent skip (S3-Task4-F1):
        // the ctest WORKING_DIRECTORY registration below guarantees the
        // probe resolves to the repository sample.
        {
            std::ifstream probe("../../config.example.json");
            if (!probe.good()) {
                std::fprintf(stderr,
                             "TestExampleConfigRoundTrip: "
                             "../../config.example.json not found\n");
                CHECK(false);
                return;
            }
        }
        std::string error;
        auto config = Config::LoadFromFile("../../config.example.json", error);
        CHECK(config.has_value());
        // The shipped bridge section stays disabled with spec values.
        if (config) {
            CHECK(!config->bridge.enabled);
            CHECK(config->bridge.upstream == "NIC 1");
            CHECK(config->bridge.downstream == "NIC 2");
            CHECK(config->bridge.mac_table_size == 4096);
            // RA-6 (G-5 D1 regression lock; no red): the shipped example now
            // names the machine's real NIC ("NIC 1"); zh-CN resolvability is
            // covered by the alias matrix in test_web (RA-2).
            CHECK(config->adapter == "NIC 1");
        }
    }

// ---------------------------------------------------------------------------
// T5: Config::ToJsonString / SaveToFile / public ValidateConfig + the
// pool_start/pool_end loader compatibility.
// ---------------------------------------------------------------------------

/// Full non-default config for the T5 round-trip/save tests. Every field
/// differs from its default so a serializer that drops a key fails the
/// round-trip assertions.
vgww::core::Config MakeFullConfig() {
    using vgww::core::Config;
    Config c;
    c.adapter = "Ethernet 2";
    c.mode = vgww::core::Mode::kMain;
    bool ok = false;
    c.gateway.ipv4 = vgww::core::ParseIpv4("192.168.50.1", ok);
    CHECK(ok);
    c.gateway.mask = vgww::core::ParseIpv4("255.255.255.0", ok);
    CHECK(ok);
    CHECK(vgww::core::ParseMac("aa:bb:cc:dd:ee:ff", c.gateway.mac));
    c.dhcp.enabled = true;
    c.dhcp.pool_start = vgww::core::ParseIpv4("192.168.50.100", ok);
    CHECK(ok);
    c.dhcp.pool_end = vgww::core::ParseIpv4("192.168.50.200", ok);
    CHECK(ok);
    c.dhcp.lease_seconds = 7200;
    c.dhcp.dns.push_back(vgww::core::ParseIpv4("1.1.1.1", ok));
    CHECK(ok);
    c.dhcp.dns.push_back(vgww::core::ParseIpv4("8.8.8.8", ok));
    CHECK(ok);
    vgww::core::StaticBinding b;
    CHECK(vgww::core::ParseMac("30:fc:68:88:b4:01", b.mac));
    b.ip = vgww::core::ParseIpv4("192.168.50.10", ok);
    CHECK(ok);
    b.hostname = "printer";
    c.dhcp.static_bindings.push_back(b);
    // fdaa::<last two bytes> helper (ULA prefix / pools / bindings / DNS).
    const auto v6 = [](uint8_t hi, uint8_t lo) {
        std::array<uint8_t, 16> a{};
        a[0] = 0xFD;
        a[1] = 0xAA;
        a[14] = hi;
        a[15] = lo;
        return a;
    };
    c.ipv6.enabled = true;
    c.ipv6.ula_prefix = v6(0, 0);  // fdaa::/64
    c.ipv6.prefix_len = 64;
    c.ipv6.ra_lifetime_s = 900;
    c.ipv6.dns.push_back(v6(0, 0x53));  // fdaa::53
    c.ipv6.dhcpv6.enabled = true;
    c.ipv6.dhcpv6.pool_start = v6(0x10, 0x00);  // fdaa::1000
    c.ipv6.dhcpv6.pool_end = v6(0x1F, 0xFF);    // fdaa::1fff
    c.ipv6.dhcpv6.lease_seconds = 1800;
    vgww::core::Dhcp6StaticBinding b6;
    b6.duid = {0x00, 0x03, 0x00, 0x01, 0xAA, 0xBB};
    b6.ip = v6(0x50, 0x00);  // fdaa::5000
    b6.hostname = "nas";
    c.ipv6.dhcpv6.static_bindings.push_back(b6);
    c.perf.workers = 4;
    c.perf.rx_batch = 32;
    c.perf.max_conns = 1024;
    c.perf.udp_flow_cap = 2048;
    c.perf.ring_capacity = 1024;
    c.perf.dial_timeout_ms = 5000;
    c.web.port = 9090;
    c.web.token = "s3cret";
    c.vlan.id = 42;
    c.bridge.enabled = true;
    c.bridge.upstream = "NIC 1";
    c.bridge.downstream = "NIC 2";
    c.bridge.mac_table_size = 512;
    return c;
}

void TestConfigJsonRoundTrip() {
    const vgww::core::Config original = MakeFullConfig();
    const std::string json = original.ToJsonString();
    CHECK(!json.empty());
    // The parser's primary spellings are pinned: mode string, pool array,
    // full 8-group IPv6 text (core::FormatIpv6) and bare hex DUID.
    const std::string mode_key = "\"mode\":\"main\"";
    CHECK(json.find(mode_key) != std::string::npos);
    const std::string pool_key =
        "\"pool\":[\"192.168.50.100\",\"192.168.50.200\"]";
    CHECK(json.find(pool_key) != std::string::npos);
    const std::string duid_key = "\"duid\":\"00030001aabb\"";
    CHECK(json.find(duid_key) != std::string::npos);

    const std::string path = "test_cfg_roundtrip.json";
    CHECK(WriteFile(path, json));
    std::string error;
    const auto loaded = Config::LoadFromFile(path, error);
    std::remove(path.c_str());
    CHECK(loaded.has_value());
    if (!loaded) {
        std::fprintf(stderr, "round-trip load error: %s\n", error.c_str());
        return;
    }
    const vgww::core::Config& c = *loaded;
    CHECK(c.adapter == original.adapter);
    CHECK(c.mode == original.mode);
    CHECK(c.gateway.ipv4 == original.gateway.ipv4);
    CHECK(c.gateway.mask == original.gateway.mask);
    CHECK(c.gateway.mac == original.gateway.mac);
    CHECK(c.dhcp.enabled == original.dhcp.enabled);
    CHECK(c.dhcp.pool_start == original.dhcp.pool_start);
    CHECK(c.dhcp.pool_end == original.dhcp.pool_end);
    CHECK(c.dhcp.lease_seconds == original.dhcp.lease_seconds);
    CHECK(c.dhcp.dns == original.dhcp.dns);
    CHECK(c.dhcp.static_bindings.size() == 1);
    if (c.dhcp.static_bindings.size() == 1) {
        CHECK(c.dhcp.static_bindings[0].mac ==
              original.dhcp.static_bindings[0].mac);
        CHECK(c.dhcp.static_bindings[0].ip ==
              original.dhcp.static_bindings[0].ip);
        CHECK(c.dhcp.static_bindings[0].hostname ==
              original.dhcp.static_bindings[0].hostname);
    }
    CHECK(c.ipv6.enabled == original.ipv6.enabled);
    CHECK(c.ipv6.ula_prefix == original.ipv6.ula_prefix);
    CHECK(c.ipv6.prefix_len == original.ipv6.prefix_len);
    CHECK(c.ipv6.ra_lifetime_s == original.ipv6.ra_lifetime_s);
    CHECK(c.ipv6.dns == original.ipv6.dns);
    CHECK(c.ipv6.dhcpv6.enabled == original.ipv6.dhcpv6.enabled);
    CHECK(c.ipv6.dhcpv6.pool_start == original.ipv6.dhcpv6.pool_start);
    CHECK(c.ipv6.dhcpv6.pool_end == original.ipv6.dhcpv6.pool_end);
    CHECK(c.ipv6.dhcpv6.lease_seconds ==
          original.ipv6.dhcpv6.lease_seconds);
    CHECK(c.ipv6.dhcpv6.static_bindings.size() == 1);
    if (c.ipv6.dhcpv6.static_bindings.size() == 1) {
        CHECK(c.ipv6.dhcpv6.static_bindings[0].duid ==
              original.ipv6.dhcpv6.static_bindings[0].duid);
        CHECK(c.ipv6.dhcpv6.static_bindings[0].ip ==
              original.ipv6.dhcpv6.static_bindings[0].ip);
        CHECK(c.ipv6.dhcpv6.static_bindings[0].hostname ==
              original.ipv6.dhcpv6.static_bindings[0].hostname);
    }
    CHECK(c.perf.workers == original.perf.workers);
    CHECK(c.perf.rx_batch == original.perf.rx_batch);
    CHECK(c.perf.max_conns == original.perf.max_conns);
    CHECK(c.perf.udp_flow_cap == original.perf.udp_flow_cap);
    CHECK(c.perf.ring_capacity == original.perf.ring_capacity);
    CHECK(c.perf.dial_timeout_ms == original.perf.dial_timeout_ms);
    CHECK(c.web.port == original.web.port);
    CHECK(c.web.token == original.web.token);
    CHECK(c.vlan.id == original.vlan.id);
    CHECK(c.bridge.enabled == original.bridge.enabled);
    CHECK(c.bridge.upstream == original.bridge.upstream);
    CHECK(c.bridge.downstream == original.bridge.downstream);
    CHECK(c.bridge.mac_table_size == original.bridge.mac_table_size);

    // Defaults must round-trip too: vlan.id 0 and a zero DHCP pool are not
    // writable keys (the loader rejects id 0 and 0.0.0.0), so the serializer
    // omits them and the reload keeps the defaults.
    vgww::core::Config plain;
    bool ok = false;
    plain.gateway.ipv4 = vgww::core::ParseIpv4("192.168.0.1", ok);
    CHECK(ok);
    plain.gateway.mask = vgww::core::ParseIpv4("255.255.255.0", ok);
    CHECK(ok);
    CHECK(vgww::core::ParseMac("30:fc:68:88:b4:a9", plain.gateway.mac));
    const std::string plain_json = plain.ToJsonString();
    CHECK(plain_json.find("\"vlan\"") == std::string::npos);
    CHECK(plain_json.find("\"pool\"") == std::string::npos);
    const std::string plain_path = "test_cfg_roundtrip_plain.json";
    CHECK(WriteFile(plain_path, plain_json));
    error.clear();
    const auto plain_loaded = Config::LoadFromFile(plain_path, error);
    std::remove(plain_path.c_str());
    CHECK(plain_loaded.has_value());
    if (plain_loaded) {
        CHECK(plain_loaded->vlan.id == 0);
        CHECK(plain_loaded->dhcp.pool_start == 0);
        CHECK(plain_loaded->dhcp.pool_end == 0);
        CHECK(plain_loaded->mode == vgww::core::Mode::kBypass);
    }
}

// P7: ToJsonString emits dhcp.lease_hours = lease_seconds / 3600 with integer
// division. A non-whole-hour lease_seconds would be silently truncated and
// would not survive a ToJsonString -> LoadFromFile round-trip. Serialization
// must reject it explicitly (ValidateConfig already rejects such configs, but
// serialization must not rely on a prior Validate and NDEBUG strips asserts).
void TestToJsonStringRejectsNonWholeHourLease() {
    {
        vgww::core::Config c = MakeFullConfig();
        c.dhcp.lease_seconds = 5400;  // 1.5 h: previously truncated to 1
        bool threw = false;
        std::string what;
        try {
            static_cast<void>(c.ToJsonString());
        } catch (const std::invalid_argument& e) {
            threw = true;
            what = e.what();
        } catch (...) {
            threw = true;
        }
        CHECK(threw);
        CHECK(what.find("lease_seconds") != std::string::npos);
    }
    // A whole-hour value stays lossless and serializes as before.
    {
        vgww::core::Config c = MakeFullConfig();
        c.dhcp.lease_seconds = 7200;
        bool threw = false;
        std::string json;
        try {
            json = c.ToJsonString();
        } catch (...) {
            threw = true;
        }
        CHECK(!threw);
        CHECK(json.find("\"lease_hours\":2") != std::string::npos);
    }
    // A zero lease is a whole number of hours (0): not rejected here.
    {
        vgww::core::Config c = MakeFullConfig();
        c.dhcp.lease_seconds = 0;
        bool threw = false;
        try {
            static_cast<void>(c.ToJsonString());
        } catch (...) {
            threw = true;
        }
        CHECK(!threw);
    }
}

void TestConfigSaveAtomic() {
    const vgww::core::Config original = MakeFullConfig();
    const std::string path = "test_cfg_save_atomic.json";
    std::remove(path.c_str());
    std::string error = "seed";
    CHECK(original.SaveToFile(path, error));
    CHECK(error.empty());
    // The tmp file was renamed onto the target, never left behind.
    {
        std::ifstream tmp(path + ".tmp");
        CHECK(!tmp.good());
    }
    error.clear();
    const auto loaded = Config::LoadFromFile(path, error);
    CHECK(loaded.has_value());
    if (loaded) {
        CHECK(loaded->gateway.ipv4 == original.gateway.ipv4);
        CHECK(loaded->web.port == original.web.port);
    }

    // Failure 1: missing directory -> false + error, nothing created.
    error.clear();
    CHECK(!original.SaveToFile(
        "test_cfg_no_such_dir/sub/test_cfg_save_atomic.json", error));
    CHECK(!error.empty());

    // Failure 2: the target exists as a directory -> the rename cannot
    // replace it; the directory survives and no tmp file is left behind.
    const std::string blocked = "test_cfg_save_blocked";
    _rmdir(blocked.c_str());
    CHECK(0 == _mkdir(blocked.c_str()));
    error.clear();
    CHECK(!original.SaveToFile(blocked, error));
    CHECK(!error.empty());
    CHECK(0 == _rmdir(blocked.c_str()));  // still a directory
    {
        std::ifstream tmp(blocked + ".tmp");
        CHECK(!tmp.good());  // cleaned up on failure
    }

    // A pre-existing file keeps its bytes when a save to a bad path fails.
    const std::string keep = "test_cfg_keep.json";
    CHECK(WriteFile(keep, "SENTINEL"));
    error.clear();
    CHECK(!original.SaveToFile(
        "test_cfg_no_such_dir/sub/test_cfg_keep.json", error));
    CHECK(!error.empty());
    {
        std::ifstream in(keep);
        std::string content;
        in >> content;
        CHECK(content == "SENTINEL");
    }
    std::remove(keep.c_str());

    // A target held open without FILE_SHARE_DELETE must make the save fail
    // cleanly: no truncation, no tmp left behind, the original bytes survive.
    {
        const std::string locked = "test_cfg_locked.json";
        CHECK(WriteFile(locked, "ORIGINAL"));
        const HANDLE h = ::CreateFileA(
            locked.c_str(), GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL, nullptr);
        CHECK(h != INVALID_HANDLE_VALUE);
        std::string locked_error;
        const bool saved = original.SaveToFile(locked, locked_error);
        CHECK(!saved);
        CHECK(!locked_error.empty());
        ::CloseHandle(h);
        {
            std::ifstream in(locked);
            std::string content;
            in >> content;
            CHECK(content == "ORIGINAL");
        }
        {
            std::ifstream tmp(locked + ".tmp");
            CHECK(!tmp.good());  // cleaned up on failure
        }
        std::remove(locked.c_str());
    }

    // Mechanism pin for the atomic publish: a successful save REPLACES the
    // file object (tmp + rename). An in-place rewrite would keep the same
    // file identity and could leave a half-written target behind.
    {
        const std::string id_path = "test_cfg_identity.json";
        CHECK(WriteFile(id_path, "OLD"));
        const auto file_index = [](const std::string& p, uint64_t& index) {
            const HANDLE h = ::CreateFileA(
                p.c_str(), GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (INVALID_HANDLE_VALUE == h) {
                return false;
            }
            BY_HANDLE_FILE_INFORMATION info{};
            const bool ok = 0 != ::GetFileInformationByHandle(h, &info);
            ::CloseHandle(h);
            index = (static_cast<uint64_t>(info.nFileIndexHigh) << 32) |
                    info.nFileIndexLow;
            return ok;
        };
        uint64_t before = 0;
        uint64_t after = 0;
        CHECK(file_index(id_path, before));
        std::string id_error;
        CHECK(original.SaveToFile(id_path, id_error));
        CHECK(file_index(id_path, after));
        CHECK(after != before);  // replaced, not rewritten in place
        std::remove(id_path.c_str());
    }
    std::remove(path.c_str());
}

void TestValidateConfigPublic() {
    std::string error;
    const vgww::core::Config good = MakeFullConfig();
    CHECK(vgww::core::ValidateConfig(good, error));
    CHECK(error.empty());

    // Pool start > end.
    {
        vgww::core::Config c = good;
        bool ok = false;
        c.dhcp.pool_start = vgww::core::ParseIpv4("192.168.50.200", ok);
        CHECK(ok);
        c.dhcp.pool_end = vgww::core::ParseIpv4("192.168.50.100", ok);
        CHECK(ok);
        error.clear();
        CHECK(!vgww::core::ValidateConfig(c, error));
        CHECK(!error.empty());
    }
    // Port 0 (programmatic configs never pass the JSON parser).
    {
        vgww::core::Config c = good;
        c.web.port = 0;
        error.clear();
        CHECK(!vgww::core::ValidateConfig(c, error));
        const std::string needle = "web.port";
        CHECK(error.find(needle) != std::string::npos);
    }
    // Prefix length above the SLAAC cap.
    {
        vgww::core::Config c = good;
        c.ipv6.prefix_len = 65;
        error.clear();
        CHECK(!vgww::core::ValidateConfig(c, error));
        const std::string needle = "prefix_len";
        CHECK(error.find(needle) != std::string::npos);
    }
    // Pool outside the gateway subnet.
    {
        vgww::core::Config c = good;
        bool ok = false;
        c.dhcp.pool_start = vgww::core::ParseIpv4("10.0.0.100", ok);
        CHECK(ok);
        c.dhcp.pool_end = vgww::core::ParseIpv4("10.0.0.200", ok);
        CHECK(ok);
        error.clear();
        CHECK(!vgww::core::ValidateConfig(c, error));
        const std::string needle = "pool";
        CHECK(error.find(needle) != std::string::npos);
    }
    // Values the loader bounds at parse time must be refused here too, or a
    // saved config would fail to load on the next start.
    {
        vgww::core::Config c = good;
        c.vlan.id = 4095;
        error.clear();
        CHECK(!vgww::core::ValidateConfig(c, error));
    }
    {
        vgww::core::Config c = good;
        c.dhcp.lease_seconds = 5400;  // not a whole number of hours
        error.clear();
        CHECK(!vgww::core::ValidateConfig(c, error));
    }
    {
        vgww::core::Config c = good;
        c.adapter.assign(257, 'a');
        error.clear();
        CHECK(!vgww::core::ValidateConfig(c, error));
    }
    {
        vgww::core::Config c = good;
        c.web.token.assign(257, 't');
        error.clear();
        CHECK(!vgww::core::ValidateConfig(c, error));
    }
    // batch84: web.bind is checked the same way as web.token and adapter (both
    // already covered above), but its own bounds had NO test - the only
    // exercise was "bind as a JSON number" (a type error, not a range error).
    // The default is "127.0.0.1", so an empty or oversized bind can only come
    // from a programmatic write or an explicit JSON "", and either would make
    // the HTTP server bind somewhere unintended (or fail to resolve at all).
    {
        vgww::core::Config c = good;
        c.web.bind.clear();
        error.clear();
        CHECK(!vgww::core::ValidateConfig(c, error));
        CHECK(error.find("web.bind") != std::string::npos);
    }
    {
        vgww::core::Config c = good;
        c.web.bind.assign(257, 'b');  // one byte over the 256 cap
        error.clear();
        CHECK(!vgww::core::ValidateConfig(c, error));
        CHECK(error.find("web.bind") != std::string::npos);
    }
    {
        vgww::core::Config c = good;
        c.web.bind.assign(256, 'b');  // exactly the cap: must be accepted
        error.clear();
        CHECK(vgww::core::ValidateConfig(c, error));
    }
}

// batch105: the LOADER refuses an unusable DHCP list, but a PROGRAMMATIC
// Config could carry it through ValidateConfig, and the UI settings Save builds
// exactly such a Config (SettingsDraft::ToConfig -> SaveConfigCmd ->
// DoSaveConfig -> ValidateConfig -> SaveToFile).
//
// The loader rejects (config.cpp ParseDhcp / ParseIpv6):
//   * dhcp.dns entries that are loopback (127/8), group/broadcast (>=224/4),
//     the gateway itself, or the subnet network/broadcast address;
//   * dhcp.static_bindings duplicates (same ip or same mac), and an all-zero /
//     multicast gateway-style MAC on a binding;
//   * dhcp6 static bindings with an empty DUID or a DUID over 128 octets.
// ValidateConfig only re-checked COUNTS (dns <= kMaxDhcpDns, bindings <= cap).
// So a UI save with 127.0.0.1 as the resolver reported SUCCESS, wrote the file,
// and that same file then FAILED TO LOAD on the next start - the product
// refusing to read a config it had just written and called "saved".
//
// Asserted: every value the loader refuses is also refused by the programmatic
// validator, and the plain valid config still passes.
static void TestB105ProgrammaticConfigObeysLoaderRules() {
    std::string error;
    const vgww::core::Config good = MakeFullConfig();
    CHECK(vgww::core::ValidateConfig(good, error));
    CHECK(error.empty());

    bool ok = false;
    const auto ip = [&ok](const char* text) {
        return vgww::core::ParseIpv4(text, ok);
    };

    // ---- dhcp.dns: values no client can use as a resolver ----------------
    const char* unusable_dns[] = {
        "127.0.0.1",        // loopback
        "127.10.20.30",     // loopback range
        "224.0.0.1",        // multicast
        "239.1.1.1",        // multicast (admin scope)
        "255.255.255.255",  // limited broadcast
        "192.168.50.255",   // subnet broadcast
        "192.168.50.1",     // the gateway itself
    };
    for (const char* text : unusable_dns) {
        vgww::core::Config c = good;
        c.dhcp.dns.clear();
        c.dhcp.dns.push_back(ip(text));
        CHECK(ok);
        error.clear();
        if (vgww::core::ValidateConfig(c, error)) {
            std::fprintf(stderr,
                         "b105: programmatic dhcp.dns accepted unusable "
                         "resolver %s\n",
                         text);
        }
        CHECK(!vgww::core::ValidateConfig(c, error));
        CHECK(!error.empty());
    }

    // ---- dhcp.static_bindings: identity and placement --------------------
    {
        vgww::core::Config c = good;
        c.dhcp.static_bindings[0].mac = vgww::core::MacAddress{};
        error.clear();
        CHECK(!vgww::core::ValidateConfig(c, error));   // all-zero MAC
    }
    {
        vgww::core::Config c = good;
        c.dhcp.static_bindings[0].mac[0] = 0x01;        // multicast bit
        error.clear();
        CHECK(!vgww::core::ValidateConfig(c, error));
    }
    {
        vgww::core::Config c = good;
        c.dhcp.static_bindings[0].ip = c.gateway.ipv4;
        error.clear();
        CHECK(!vgww::core::ValidateConfig(c, error));   // bound == gateway
    }
    {
        vgww::core::Config c = good;
        c.dhcp.static_bindings[0].ip = 0;
        error.clear();
        CHECK(!vgww::core::ValidateConfig(c, error));   // 0.0.0.0
    }
    {
        vgww::core::Config c = good;
        c.dhcp.static_bindings[0].ip = ip("192.168.51.10");
        CHECK(ok);
        error.clear();
        CHECK(!vgww::core::ValidateConfig(c, error));   // outside the subnet
    }
    {
        vgww::core::Config c = good;
        c.dhcp.static_bindings[0].ip = ip("192.168.50.255");
        CHECK(ok);
        error.clear();
        CHECK(!vgww::core::ValidateConfig(c, error));   // subnet broadcast
    }
    {
        vgww::core::Config c = good;
        vgww::core::StaticBinding dup = c.dhcp.static_bindings[0];
        dup.mac[5] = static_cast<uint8_t>(dup.mac[5] ^ 0xFF);
        c.dhcp.static_bindings.push_back(dup);          // same ip, other mac
        error.clear();
        CHECK(!vgww::core::ValidateConfig(c, error));   // duplicate address
    }
    {
        vgww::core::Config c = good;
        vgww::core::StaticBinding dup = c.dhcp.static_bindings[0];
        dup.ip = ip("192.168.50.11");
        CHECK(ok);
        c.dhcp.static_bindings.push_back(dup);          // same mac, other ip
        error.clear();
        CHECK(!vgww::core::ValidateConfig(c, error));   // duplicate mac
    }
    {
        vgww::core::Config c = good;
        c.dhcp.static_bindings[0].hostname.assign(254, 'h');
        error.clear();
        CHECK(!vgww::core::ValidateConfig(c, error));   // hostname too long
    }

    // ---- dhcpv6 static bindings: DUID bounds -----------------------------
    {
        vgww::core::Config c = good;
        CHECK(!c.ipv6.dhcpv6.static_bindings.empty());
        c.ipv6.dhcpv6.static_bindings[0].duid.clear();
        error.clear();
        CHECK(!vgww::core::ValidateConfig(c, error));   // empty DUID
    }
    {
        vgww::core::Config c = good;
        c.ipv6.dhcpv6.static_bindings[0].duid.assign(129, 0xAB);
        error.clear();
        CHECK(!vgww::core::ValidateConfig(c, error));   // DUID over 128 octets
    }

    // batch135: the v4 loop above asserts BOTH uniqueness rules (same ip, same
    // mac), but the v6 block only checked DUID bounds. The JSON parser rejects
    // duplicates (config.cpp:698-710), so `ValidateConfig` is the only gate for
    // PROGRAMMATIC configs - the UI settings draft (settings.cpp:463) and
    // SaveConfigCmd (controller.cpp:312) both go straight to it. With no rule
    // here, a UI save could persist two bindings on one address or two
    // addresses for one DUID, and the next start would refuse the file it had
    // just written and reported "saved".
    {
        vgww::core::Config c = good;
        vgww::core::Dhcp6StaticBinding dup =
            c.ipv6.dhcpv6.static_bindings[0];
        dup.duid[5] = static_cast<uint8_t>(dup.duid[5] ^ 0xFF);
        c.ipv6.dhcpv6.static_bindings.push_back(dup);  // same ip, other duid
        error.clear();
        if (vgww::core::ValidateConfig(c, error)) {
            std::fprintf(stderr,
                         "b135: programmatic dhcpv6 accepted a duplicate "
                         "bound address\n");
        }
        CHECK(!vgww::core::ValidateConfig(c, error));
        CHECK(!error.empty());
    }
    {
        vgww::core::Config c = good;
        vgww::core::Dhcp6StaticBinding dup =
            c.ipv6.dhcpv6.static_bindings[0];
        dup.ip[15] = static_cast<uint8_t>(dup.ip[15] + 1);
        c.ipv6.dhcpv6.static_bindings.push_back(dup);  // same duid, other ip
        error.clear();
        if (vgww::core::ValidateConfig(c, error)) {
            std::fprintf(stderr,
                         "b135: programmatic dhcpv6 accepted a duplicate "
                         "duid\n");
        }
        CHECK(!vgww::core::ValidateConfig(c, error));
        CHECK(!error.empty());
    }
    // Out-of-prefix placement is already refused by ValidateConfig (:1253,
    // inside the DHCPv6-services block) and by the parser, so it is NOT
    // re-asserted here: adding a second copy of that rule would be two sources
    // of truth for one invariant (C6), and a test for it would pass with or
    // without the batch135 change (it is covered by the existing reject cases
    // at :777).

    // The harm, stated as a round trip: a config the validator accepts must be
    // loadable. Before the fix the first case below saved fine and could not be
    // read back.
    {
        vgww::core::Config c = good;
        c.dhcp.dns.clear();
        c.dhcp.dns.push_back(ip("127.0.0.1"));
        CHECK(ok);
        error.clear();
        if (vgww::core::ValidateConfig(c, error)) {
            const std::string path = "b105_roundtrip.json";
            std::string save_error;
            CHECK(c.SaveToFile(path, save_error));
            std::string load_error;
            const auto reloaded = vgww::core::Config::LoadFromFile(path, load_error);
            CHECK(!reloaded.has_value());   // the product refuses its own file
            std::remove(path.c_str());
        }
    }
}

// batch106: a CLI override is a THIRD way to produce a Config, and it is
// applied AFTER the only load-time validation.
//
// main.cpp does:
//   auto config = Config::LoadFromFile(path, error);   // validates
//   config->ApplyCliOverrides(args, error);            // does NOT validate
// and ApplyCliOverrides assigns the raw flag value:
//   if (arg.rfind("--adapter=", 0) == 0) adapter = arg.substr(10);
// No length check. ValidateConfig bounds adapter to kMaxAdapterBytes (256) and
// the loader refuses anything longer, so `--adapter=<257 chars>` produced a
// running Config the product cannot read back: ToJsonString writes the
// over-long name, and the next start fails at the loader with
// "adapter name too long".
//
// The same shape batch105 fixed for the UI entry (programmatic Config) and
// batch34l fixed for the JSON entry: an entry point that can produce data the
// authoritative validator rejects. Asserted here at the unit level, where the
// override is applied and then validated - exactly what main must do.
static void TestB106CliOverrideMustValidate() {
    using vgww::core::Config;

    const vgww::core::Config base = MakeFullConfig();
    std::string error;

    // A legal override stays legal and is actually applied.
    {
        Config c = base;
        const std::vector<std::string> args = {"--adapter=Ethernet 3"};
        CHECK(c.ApplyCliOverrides(args, error));
        CHECK(c.adapter == "Ethernet 3");
        error.clear();
        CHECK(vgww::core::ValidateConfig(c, error));
    }
    // An over-long adapter must not survive as a Config the validator rejects.
    // Either the override itself refuses it, or it is accepted here and the
    // caller's ValidateConfig catches it - but the RESULTING config must never
    // be "valid enough to save, invalid on reload". The contract asserted is:
    // applying an override never yields a config that fails the validator
    // without the override having reported an error.
    {
        Config c = base;
        const std::vector<std::string> args = {"--adapter=" +
                                               std::string(300, 'a')};
        const bool applied = c.ApplyCliOverrides(args, error);
        const bool override_error = !applied || !error.empty();
        error.clear();
        const bool config_ok = vgww::core::ValidateConfig(c, error);
        std::printf("b106: overlong adapter applied=%d override_error=%d "
                    "config_ok=%d\n",
                    applied ? 1 : 0, override_error ? 1 : 0,
                    config_ok ? 1 : 0);
        // The bad value must be reported at the point it enters the config,
        // not left for a later save/load cycle to discover.
        CHECK(override_error);
        // A refused override leaves the config untouched, so it stays VALID:
        // the invariant is "never rejected silently", not "always corrupt".
        CHECK(config_ok);
        CHECK(c.adapter == base.adapter);
    }
    // Control: exactly the cap is accepted by the validator.
    {
        Config c = base;
        const std::vector<std::string> args = {"--adapter=" +
                                               std::string(256, 'a')};
        CHECK(c.ApplyCliOverrides(args, error));
        error.clear();
        CHECK(vgww::core::ValidateConfig(c, error));
    }
    // Control: one byte over the cap is refused.
    {
        Config c = base;
        const std::vector<std::string> args = {"--adapter=" +
                                               std::string(257, 'a')};
        const bool applied = c.ApplyCliOverrides(args, error);
        CHECK(!applied || !error.empty());
    }
}

// batch84: web.bind bounds through the JSON path.
//
// HONEST LIMIT: this does NOT independently guard the loader's own early check
// (config.cpp:776-781). Config::LoadFromFile calls ValidateConfig at the end
// (config.cpp:1660), which repeats the same two conditions, so removing the
// early check alone leaves the load still rejected - verified by mutation:
// deleting the loader's copy left every assertion here green. The early check
// is a redundancy whose only observable effect is a more specific error
// message, not a separately falsifiable behaviour. What this exercise DOES
// pin is the end-to-end contract a user cares about: an empty or oversized
// web.bind never yields a loaded config, and exactly 256 bytes still loads
// and round-trips.
void TestB84WebBindBounds() {
    const auto load_section = [](const std::string& section) {
        return LoadFromText("test_cfg_b84_bind.json", Skeleton(section));
    };
    {
        const auto r = load_section(R"("web":{"bind":""})");
        CHECK(r.wrote);
        if (r.config.has_value()) {
            std::fprintf(stderr, "b84: empty web.bind accepted by the loader\n");
        }
        CHECK(!r.config.has_value());
        CHECK(!r.error.empty());
    }
    {
        const std::string long_bind(257, 'b');
        const auto r =
            load_section("\"web\":{\"bind\":\"" + long_bind + "\"}");
        CHECK(r.wrote);
        if (r.config.has_value()) {
            std::fprintf(stderr,
                         "b84: oversized web.bind (%zu) accepted by the loader\n",
                         long_bind.size());
        }
        CHECK(!r.config.has_value());
        CHECK(!r.error.empty());
    }
    {
        // The accepted edge: exactly the cap, and the value round-trips.
        const std::string cap_bind(256, 'b');
        const auto r =
            load_section("\"web\":{\"bind\":\"" + cap_bind + "\"}");
        CHECK(r.wrote);
        CHECK(r.config.has_value());
        if (r.config) {
            CHECK(r.config->web.bind == cap_bind);
        }
    }
}

void TestExampleDhcpPoolKeys() {
    // config.example.json uses the pool_start/pool_end spelling; the loader
    // must accept it (both keys present) and wire the same bytes as the
    // "pool" array form.
    {
        std::ifstream probe("../../config.example.json");
        if (!probe.good()) {
            std::fprintf(stderr,
                         "TestExampleDhcpPoolKeys: "
                         "../../config.example.json not found\n");
            CHECK(false);
            return;
        }
    }
    std::string error;
    const auto cfg =
        Config::LoadFromFile("../../config.example.json", error);
    CHECK(cfg.has_value());
    if (!cfg) {
        std::fprintf(stderr, "example load error: %s\n", error.c_str());
        return;
    }
    bool ok = false;
    CHECK(cfg->dhcp.pool_start ==
          vgww::core::ParseIpv4("192.168.0.100", ok));
    CHECK(ok);
    CHECK(cfg->dhcp.pool_end == vgww::core::ParseIpv4("192.168.0.200", ok));
    CHECK(ok);
    CHECK(cfg->dhcp.pool_start != 0 && cfg->dhcp.pool_end != 0);

    // One key without the other is a hard error, never a silent half pool.
    const auto only_start = LoadFromText(
        "test_cfg_poolkey.json",
        Skeleton(R"("dhcp":{"pool_start":"192.168.0.100"})"));
    CHECK(only_start.wrote);
    CHECK(!only_start.config.has_value());
    CHECK(!only_start.error.empty());
    const auto only_end = LoadFromText(
        "test_cfg_poolkey.json",
        Skeleton(R"("dhcp":{"pool_end":"192.168.0.200"})"));
    CHECK(only_end.wrote);
    CHECK(!only_end.config.has_value());

    // Both keys together parse to the same bytes as the array form.
    const auto both = LoadFromText(
        "test_cfg_poolkey.json",
        Skeleton(R"("dhcp":{"pool_start":"192.168.0.100",)"
                 R"("pool_end":"192.168.0.200"})"));
    CHECK(both.wrote);
    CHECK(both.config.has_value());
    if (both.config) {
        ok = false;
        CHECK(both.config->dhcp.pool_start ==
              vgww::core::ParseIpv4("192.168.0.100", ok));
        CHECK(ok);
        CHECK(both.config->dhcp.pool_end ==
              vgww::core::ParseIpv4("192.168.0.200", ok));
        CHECK(ok);
    }
    // A malformed compat value is rejected (never silently zero).
    const auto malformed = LoadFromText(
        "test_cfg_poolkey.json",
        Skeleton(R"("dhcp":{"pool_start":"garbage",)"
                 R"("pool_end":"192.168.0.200"})"));
    CHECK(malformed.wrote);
    CHECK(!malformed.config.has_value());
}

    /// G-5 fix2: every flag advertised by PrintUsageString() must be
    /// consumable by Config::ApplyCliOverrides (main strips argv[0] before
    /// the call). --headless was accepted by ParseStartupOptions but
    /// rejected here, so `vgww.exe --headless` exited 1 with "unknown
    /// argument" despite the fallback config loading fine.
    /// (Batch14: early-exit flags --version/--help/--install-driver/--uninstall-driver
    /// never reach this call by design; the full table-driven usage x parse x whitelist parity harness lives in tests/test_main.cpp.)
    void TestApplyCliOverridesUsageFlags() {
        {
            Config config;
            std::string error;
            const std::vector<std::string> args{"--headless"};
            CHECK(config.ApplyCliOverrides(args, error));
            CHECK(error.empty());
        }
        {
            Config config;
            std::string error;
            const std::vector<std::string> args{"--headless", "--minimized",
                                                "--no-web"};
            CHECK(config.ApplyCliOverrides(args, error));
        }
        {
            // Lock: an unknown flag must stay rejected (no silent swallow).
            Config config;
            std::string error;
            const std::vector<std::string> args{"--definitely-not-a-flag"};
            CHECK(!config.ApplyCliOverrides(args, error));
            CHECK(!error.empty());
        }
    }

// batch19 R4-P4: the persisted UI language (ui_language) - default zh-CN when
// absent, survives a SaveToFile -> LoadFromFile round-trip, and an unknown
// code is preserved verbatim (the UI falls back at apply time).
void TestUiLanguagePersistence() {
    using namespace vgww::core;
    {
        // absent ui_language (an older config) -> default zh-CN.
        Config base = MakeFullConfig();
        std::string json = base.ToJsonString();
        // Remove the emitted ui_language field (either comma side) to emulate
        // an older config file.
        bool removed = false;
        for (const std::string frag :
             {std::string(",\"ui_language\":\"zh-CN\""),
              std::string("\"ui_language\":\"zh-CN\",")}) {
            const auto pos = json.find(frag);
            if (pos != std::string::npos) {
                json.erase(pos, frag.size());
                removed = true;
                break;
            }
        }
        CHECK(removed);
        CHECK(json.find("ui_language") == std::string::npos);
        const std::string path = "test_cfg_uilang_default.json";
        CHECK(WriteFile(path, json));
        std::string error;
        auto c = Config::LoadFromFile(path, error);
        CHECK(c.has_value());
        CHECK(c.has_value() && c->ui_language == "zh-CN");
        std::remove(path.c_str());
    }
    {
        Config c = MakeFullConfig();
        c.ui_language = "ja";
        const std::string path = "test_cfg_uilang_rt.json";
        std::string error;
        CHECK(c.SaveToFile(path, error));
        auto loaded = Config::LoadFromFile(path, error);
        CHECK(loaded.has_value() && loaded->ui_language == "ja");
        std::remove(path.c_str());
    }
    {
        // unknown code is preserved verbatim (the UI falls back at apply).
        Config base = MakeFullConfig();
        base.ui_language = "zz";
        const std::string path = "test_cfg_uilang_bad.json";
        std::string error;
        CHECK(base.SaveToFile(path, error));
        auto c = Config::LoadFromFile(path, error);
        CHECK(c.has_value() && c->ui_language == "zz");
        std::remove(path.c_str());
    }
}

// batch20: the UI scale config token. "auto" is the default; a 25-step
// percent (100..500) round-trips; an invalid token normalises to "auto"
// (never an error - the desktop DPI stays a sane default).
// batch22 A1: native appearance ("dark" default / "light" / "auto").
void TestThemePersistence() {
    using namespace vgww::core;
    CHECK(Config{}.theme == "dark");
    CHECK(IsValidThemeValue("dark"));
    CHECK(IsValidThemeValue("light"));
    CHECK(IsValidThemeValue("auto"));
    CHECK(!IsValidThemeValue(""));
    CHECK(!IsValidThemeValue("Dark"));
    CHECK(!IsValidThemeValue("system"));

    {
        Config base = MakeFullConfig();
        base.theme = "light";
        const std::string path = "test_cfg_theme_roundtrip.json";
        std::string error;
        CHECK(base.SaveToFile(path, error));
        auto c = Config::LoadFromFile(path, error);
        CHECK(c.has_value() && c->theme == "light");
        std::remove(path.c_str());
    }
    {
        // Absent field (an older config) -> the historical dark look.
        Config base = MakeFullConfig();
        std::string json = base.ToJsonString();
        const auto pos = json.find(",\"theme\":\"dark\"");
        CHECK(pos != std::string::npos);
        if (pos != std::string::npos) {
            json.erase(pos, std::string(",\"theme\":\"dark\"").size());
        }
        const std::string path = "test_cfg_theme_default.json";
        CHECK(WriteFile(path, json));
        std::string error;
        auto c = Config::LoadFromFile(path, error);
        CHECK(c.has_value() && c->theme == "dark");
        std::remove(path.c_str());
    }
    {
        // A bad value normalises instead of failing the load.
        Config base = MakeFullConfig();
        std::string json = base.ToJsonString();
        const auto pos = json.find(",\"theme\":\"dark\"");
        CHECK(pos != std::string::npos);
        if (pos != std::string::npos) {
            json.replace(pos, std::string(",\"theme\":\"dark\"").size(),
                         ",\"theme\":\"neon\"");
        }
        const std::string path = "test_cfg_theme_bad.json";
        CHECK(WriteFile(path, json));
        std::string error;
        auto c = Config::LoadFromFile(path, error);
        CHECK(c.has_value() && c->theme == "dark");
        std::remove(path.c_str());
    }
}

void TestUiScalePersistence() {
    using namespace vgww::core;
    CHECK(Config{}.ui_scale == "auto");
    CHECK(IsValidUiScaleValue("auto"));
    CHECK(IsValidUiScaleValue("100"));
    CHECK(IsValidUiScaleValue("125"));
    CHECK(IsValidUiScaleValue("500"));
    CHECK(!IsValidUiScaleValue("101"));
    CHECK(!IsValidUiScaleValue("99"));
    CHECK(!IsValidUiScaleValue("050"));
    CHECK(!IsValidUiScaleValue(""));
    CHECK(!IsValidUiScaleValue("600"));
    CHECK(UiScaleValueToFactor("auto") == 0.0f);
    CHECK(UiScaleValueToFactor("200") == 2.0f);
    CHECK(UiScaleValueToFactor("bad") == 0.0f);

    {
        Config base = MakeFullConfig();
        base.ui_scale = "200";
        const std::string path = "test_cfg_uiscale_roundtrip.json";
        std::string error;
        CHECK(base.SaveToFile(path, error));
        auto c = Config::LoadFromFile(path, error);
        CHECK(c.has_value() && c->ui_scale == "200");
        std::remove(path.c_str());
    }
    {
        // Absent field (an older config) -> auto.
        Config base = MakeFullConfig();
        std::string json = base.ToJsonString();
        const auto pos = json.find(",\"ui_scale\":\"auto\"");
        CHECK(pos != std::string::npos);
        if (pos != std::string::npos) {
            json.erase(pos, std::string(",\"ui_scale\":\"auto\"").size());
        }
        const std::string path = "test_cfg_uiscale_default.json";
        CHECK(WriteFile(path, json));
        std::string error;
        auto c = Config::LoadFromFile(path, error);
        CHECK(c.has_value() && c->ui_scale == "auto");
        std::remove(path.c_str());
    }
    {
        // Bad value -> auto (not a load failure).
        Config base = MakeFullConfig();
        std::string json = base.ToJsonString();
        const auto pos = json.find("\"ui_scale\":\"auto\"");
        CHECK(pos != std::string::npos);
        if (pos != std::string::npos) {
            json.replace(pos, std::string("\"ui_scale\":\"auto\"").size(),
                         "\"ui_scale\":\"123\"");
        }
        const std::string path = "test_cfg_uiscale_bad.json";
        CHECK(WriteFile(path, json));
        std::string error;
        auto c = Config::LoadFromFile(path, error);
        CHECK(c.has_value() && c->ui_scale == "auto");
        std::remove(path.c_str());
    }
}

// ---------------------------------------------------------------------------
// batch34l: configuration validation boundaries.
//
// Every case below asserts a REQUIREMENT, never an implementation detail or a
// specific error string: an invalid configuration must be REJECTED and the
// rejection must be EXPLAINABLE (non-empty error) so the operator can act on
// it. A silently accepted invalid value is the defect these cases guard.
// ---------------------------------------------------------------------------

// A value of the wrong JSON type must never be silently ignored: the operator
// wrote it, so it either takes effect or the load fails. Silently skipping it
// means the running process differs from the file on disk.
void TestB34lWrongTypeRejected() {
    struct Case {
        const char* name;
        const char* section;
    };
    const Case cases[] = {
        {"dhcp.dns as a bare string", R"("dhcp":{"dns":"192.168.0.1"})"},
        {"dhcp.dns entry not an IP", R"("dhcp":{"dns":["garbage"]})"},
        {"dhcp.static_bindings as object",
         R"("dhcp":{"static_bindings":{"a":1}})"},
        {"dhcp.pool as string", R"("dhcp":{"pool":"192.168.0.100"})"},
        {"dhcp.pool wrong arity",
         R"("dhcp":{"pool":["192.168.0.100","192.168.0.110","192.168.0.120"]})"},
        {"web.token as number", R"("web":{"token":12345})"},
        {"web.bind as number", R"("web":{"bind":12345})"},
        {"adapter as number", R"("adapter":42)"},
        {"ipv6.dhcpv6.static_bindings as string",
         R"("ipv6":{"enabled":false,"dhcpv6":{"static_bindings":"x"}})"},
    };
    for (const Case& c : cases) {
        const auto r = LoadFromText("test_cfg_b34l_type.json",
                                    Skeleton(c.section));
        CHECK(r.wrote);
        if (r.config.has_value()) {
            std::fprintf(stderr,
                         "b34l: silently accepted wrong type: %s\n", c.name);
        }
        CHECK(!r.config.has_value());
        CHECK(!r.error.empty());
    }
}

// A JSON number that is not a whole number must not be silently truncated
// into an integer field: 64.9 workers is not "64 workers", it is a typo.
void TestB34lFractionalIntegerRejected() {
    const char* sections[] = {
        R"("perf":{"workers":4.7})",
        R"("perf":{"rx_batch":64.9})",
        R"("perf":{"max_conns":4096.5})",
        R"("perf":{"udp_flow_cap":8192.5})",
        R"("perf":{"ring_capacity":4096.5})",
        R"("perf":{"dial_timeout_ms":1.5})",
        R"("perf":{"rx_poll_ms":10.5})",
        R"("web":{"port":8080.9})",
        R"("vlan":{"id":100.7})",
        R"("bridge":{"mac_table_size":4096.9})",
        R"("dhcp":{"lease_hours":12.5})",
        R"("ipv6":{"enabled":false,"prefix_len":64.5})",
        R"("ipv6":{"enabled":false,"ra_lifetime_s":1800.5})",
        R"("ipv6":{"enabled":false,"dhcpv6":{"lease_seconds":3600.5}})",
    };
    for (const char* section : sections) {
        const auto r = LoadFromText("test_cfg_b34l_frac.json",
                                    Skeleton(section));
        CHECK(r.wrote);
        if (r.config.has_value()) {
            std::fprintf(stderr,
                         "b34l: silently truncated fractional value: %s\n",
                         section);
        }
        CHECK(!r.config.has_value());
        CHECK(!r.error.empty());
    }
}

// A JSON boolean is not a number and must not be accepted as one.
void TestB34lBooleanAsIntegerRejected() {
    const auto r =
        LoadFromText("test_cfg_b34l_bool.json", Skeleton(R"("dhcp":{"lease_hours":true})"));
    CHECK(r.wrote);
    CHECK(!r.config.has_value());
    CHECK(!r.error.empty());
}

// The dynamic pool must never hand out the subnet's network or broadcast
// address: those are not host addresses, and a client configured with one
// cannot communicate. The /31 and /32 cases are the documented exceptions
// (no network/broadcast concept), so they are not asserted here.
void TestB34lPoolExcludesReservedAddresses() {
    const char* pool_literals[] = {
        R"("dhcp":{"enabled":true,"pool":["192.168.0.250","192.168.0.255"]})",
        R"("dhcp":{"enabled":true,"pool":["192.168.0.0","192.168.0.10"]})",
    };
    for (const char* pool : pool_literals) {
        const auto r = LoadFromText(
            "test_cfg_b34l_pool.json",
            Skeleton(std::string(pool) + R"(,"mode":"main")"));
        CHECK(r.wrote);
        if (r.config.has_value()) {
            std::fprintf(stderr,
                         "b34l: pool accepted a reserved address: %s\n", pool);
        }
        CHECK(!r.config.has_value());
        CHECK(!r.error.empty());
    }
}

// A DHCP static binding must not be the network or broadcast address either:
// same reason as the dynamic pool, and it is reserved forever rather than
// just for one lease.
void TestB34lStaticBindingExcludesReservedAddresses() {
    const char* literals[] = {
        R"("dhcp":{"static_bindings":[{"mac":"30:fc:68:88:b4:01","ip":"192.168.0.255"}]})",
        R"("dhcp":{"static_bindings":[{"mac":"30:fc:68:88:b4:01","ip":"192.168.0.0"}]})",
    };
    for (const char* section : literals) {
        const auto r = LoadFromText("test_cfg_b34l_bind.json",
                                    Skeleton(section));
        CHECK(r.wrote);
        if (r.config.has_value()) {
            std::fprintf(
                stderr,
                "b34l: static binding accepted a reserved address: %s\n",
                section);
        }
        CHECK(!r.config.has_value());
        CHECK(!r.error.empty());
    }
}

// The gateway MAC is the identity every client's ARP cache resolves the
// default gateway to. An all-zero or group (multicast/broadcast) address is
// not a usable unicast identity and must be refused rather than silently
// producing a gateway nobody can reach.
void TestB34lGatewayMacMustBeUnicast() {
    const char* macs[] = {"00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF",
                          "01:00:5E:00:00:01"};
    for (const char* mac : macs) {
        const std::string json =
            "{\"gateway\":{\"ipv4\":\"192.168.0.40\",\"mask\":\"255.255.255.0\","
            "\"mac\":\"" + std::string(mac) + "\"}}";
        const auto r = LoadFromText("test_cfg_b34l_mac.json", json);
        CHECK(r.wrote);
        if (r.config.has_value()) {
            std::fprintf(stderr,
                         "b34l: gateway accepted a non-unicast MAC: %s\n", mac);
        }
        CHECK(!r.config.has_value());
        CHECK(!r.error.empty());
    }
    // A locally-administered unicast MAC (02:...) is legitimate and must
    // still load: the check is "unicast", not "globally administered".
    const auto ok = LoadFromText(
        "test_cfg_b34l_mac_ok.json",
        R"({"gateway":{"ipv4":"192.168.0.40","mask":"255.255.255.0","mac":"02:00:00:00:00:01"}})");
    CHECK(ok.wrote);
    CHECK(ok.config.has_value());
}

// ---------------------------------------------------------------------------
// batch34m: configuration SELF-CONSISTENCY.
//
// batch34l covered "is this value legal on its own". These cases cover
// "every value is legal, but the COMBINATION silently disables a feature the
// operator asked for, or hands clients something unusable". A config that
// loads must mean what it says: if the operator writes enabled:true, the
// feature must actually run, or the load must fail with an explanation.
// ---------------------------------------------------------------------------

// `vlan` is enabled by a non-zero `id` (VlanConfig::enabled() == id != 0), and
// the documented way to disable it is to omit `id` or the whole section. So a
// section that says `enabled: true` without an id is a config that asks for
// VLAN tagging and silently gets none - the operator believes traffic is
// isolated when it is not. Either honour the flag or refuse the file.
void TestB34mVlanEnabledWithoutIdRejected() {
    const auto r = LoadFromText("test_cfg_b34m_vlan.json",
                                Skeleton(R"("vlan":{"enabled":true})"));
    CHECK(r.wrote);
    if (r.config.has_value()) {
        std::fprintf(stderr,
                     "b34m: vlan.enabled=true accepted with no id "
                     "(feature silently off, vlan.id=%u)\n",
                     static_cast<unsigned>(r.config->vlan.id));
    }
    CHECK(!r.config.has_value());
    CHECK(!r.error.empty());

    // The documented enable path must still work.
    const auto ok = LoadFromText("test_cfg_b34m_vlan_ok.json",
                                 Skeleton(R"("vlan":{"enabled":true,"id":100})"));
    CHECK(ok.wrote);
    CHECK(ok.config.has_value());
    if (ok.config) {
        CHECK(ok.config->vlan.enabled());
    }
}

// `ipv6.dhcpv6.enabled` only takes effect when `ipv6.enabled` is also true
// (dataplane.cpp:977 gates assembly on both). A config that enables the
// DHCPv6 server while IPv6 is off therefore asks for a service that never
// runs. The documentation says it "requires ipv6.enabled", so the loader must
// enforce that instead of accepting a no-op.
void TestB34mDhcpv6RequiresIpv6() {
    const char* sections[] = {
        R"("ipv6":{"enabled":false,"dhcpv6":{"enabled":true}})",
        R"("mode":"main","ipv6":{"enabled":false,"dhcpv6":{"enabled":true}})",
    };
    for (const char* section : sections) {
        const auto r = LoadFromText("test_cfg_b34m_d6.json", Skeleton(section));
        CHECK(r.wrote);
        if (r.config.has_value()) {
            std::fprintf(stderr,
                         "b34m: dhcpv6 enabled while ipv6 disabled accepted: "
                         "%s\n",
                         section);
        }
        CHECK(!r.config.has_value());
        CHECK(!r.error.empty());
    }
    // The consistent combination must still load.
    const auto ok = LoadFromText(
        "test_cfg_b34m_d6_ok.json",
        Skeleton(R"("ipv6":{"enabled":true,"ula_prefix":"fd00::/64","dhcpv6":{"enabled":true}})"));
    CHECK(ok.wrote);
    CHECK(ok.config.has_value());
    if (ok.config) {
        CHECK(ok.config->ipv6.dhcpv6.enabled);
    }
}

// The DHCPv4 `dns` list is handed to clients verbatim as option 6. An address
// no client can use as a resolver (loopback, group/broadcast, the gateway
// itself) makes name resolution fail for every device on the LAN, and the
// failure is invisible in the config file. Duplicates are NOT a defect: they
// are harmless (the client queries the same server twice at most) and
// config.example.json ships one, so they stay accepted.
void TestB34mDhcpDnsMustBeUsable() {
    const char* unusable[] = {
        R"("dhcp":{"dns":["127.0.0.1"]})",        // loopback
        R"("dhcp":{"dns":["224.0.0.1"]})",        // multicast
        R"("dhcp":{"dns":["239.1.1.1"]})",        // multicast (admin scope)
        R"("dhcp":{"dns":["255.255.255.255"]})",  // limited broadcast
        R"("dhcp":{"dns":["192.168.0.255"]})",    // subnet broadcast
        R"("dhcp":{"dns":["192.168.0.40"]})",     // the gateway itself
    };
    for (const char* section : unusable) {
        const auto r = LoadFromText("test_cfg_b34m_dns.json",
                                    Skeleton(section));
        CHECK(r.wrote);
        if (r.config.has_value()) {
            std::fprintf(
                stderr,
                "b34m: dhcp.dns accepted an unusable resolver: %s\n",
                section);
        }
        CHECK(!r.config.has_value());
        CHECK(!r.error.empty());
    }
    // Duplicates and ordinary public resolvers stay accepted.
    const auto dup = LoadFromText(
        "test_cfg_b34m_dns_dup.json",
        Skeleton(R"("dhcp":{"dns":["8.8.8.8","8.8.8.8"]})"));
    CHECK(dup.wrote);
    CHECK(dup.config.has_value());
    const auto normal = LoadFromText(
        "test_cfg_b34m_dns_ok.json",
        Skeleton(R"("dhcp":{"dns":["8.8.8.8","192.168.0.1"]})"));
    CHECK(normal.wrote);
    CHECK(normal.config.has_value());
}

// `perf.rx_batch` frames are produced per read, but they are buffered in a
// ring of `perf.ring_capacity` entries (dataplane.cpp:859-861). When one batch
// is larger than the ring, the producer can never enqueue a full batch, so
// frames are dropped under load - and the RX push sites ignore Push()'s
// return value (dataplane.cpp:2367/2393/2412/2433), so the drop is invisible.
// The combination is therefore a silent throughput cap and must be refused.
void TestB34mRxBatchMustFitRing() {
    const auto r = LoadFromText(
        "test_cfg_b34m_ring.json",
        Skeleton(R"("perf":{"rx_batch":4096,"ring_capacity":1})"));
    CHECK(r.wrote);
    if (r.config.has_value()) {
        std::fprintf(stderr,
                     "b34m: rx_batch=%u accepted with ring_capacity=%u "
                     "(a batch can never fit the ring)\n",
                     static_cast<unsigned>(r.config->perf.rx_batch),
                     static_cast<unsigned>(r.config->perf.ring_capacity));
    }
    CHECK(!r.config.has_value());
    CHECK(!r.error.empty());

    // batch <= ring stays legal, including the equal case.
    const char* ok_sections[] = {
        R"("perf":{"rx_batch":64,"ring_capacity":64})",
        R"("perf":{"rx_batch":64,"ring_capacity":4096})",
        R"("perf":{"rx_batch":1,"ring_capacity":1})",
    };
    for (const char* section : ok_sections) {
        const auto ok = LoadFromText("test_cfg_b34m_ring_ok.json",
                                     Skeleton(section));
        CHECK(ok.wrote);
        CHECK(ok.config.has_value());
    }
}

// batch20 P2 (user ruling): the Web UI is ON by default - a missing key starts
// the server, only an explicit "enabled":false disables it; --no-web beats
// --web beats the config value.
void TestB20WebEnabledDefault() {
    using namespace vgww::core;
    CHECK(Config{}.web.enabled);

    // Missing "web" section -> still enabled.
    Config base = MakeFullConfig();
    std::string json = base.ToJsonString();
    // Drop the whole "web" member INCLUDING the separating comma (the web
    // object has no nested object, so the first '}' closes it).
    std::size_t pos = json.find(",\"web\":{");
    std::size_t erase_len = 0;
    if (pos != std::string::npos) {
        erase_len = json.find('}', pos) - pos + 1;
    } else {
        pos = json.find("\"web\":{");
        if (pos != std::string::npos) {
            erase_len = json.find('}', pos) - pos + 1;
        }
    }
    CHECK(pos != std::string::npos);
    if (pos != std::string::npos && erase_len > 0) {
        json.erase(pos, erase_len);
    }
    const std::string path = "test_cfg_web_missing.json";
    CHECK(WriteFile(path, json));
    {
        std::string error;
        auto c = Config::LoadFromFile(path, error);
        CHECK(c.has_value());
        CHECK(c.has_value() && c->web.enabled);
    }
    // Explicit false -> disabled, and it round-trips.
    {
        Config off = MakeFullConfig();
        off.web.enabled = false;
        const std::string p2 = "test_cfg_web_off.json";
        std::string error;
        CHECK(off.SaveToFile(p2, error));
        CHECK(off.ToJsonString().find("\"enabled\":false") != std::string::npos);
        auto c = Config::LoadFromFile(p2, error);
        CHECK(c.has_value() && !c->web.enabled);
        std::remove(p2.c_str());
    }
    std::remove(path.c_str());

    // Priority rule (shared by main.cpp and the tests).
    CHECK(WebEnabledEffective(true, false, false));
    CHECK(WebEnabledEffective(false, true, false));   // --web forces on
    CHECK(!WebEnabledEffective(true, false, true));   // --no-web forces off
    CHECK(!WebEnabledEffective(true, true, true));    // --no-web wins
}

int main() {
    TestUiLanguagePersistence();
    TestUiScalePersistence();
    TestThemePersistence();
    TestB20WebEnabledDefault();
    TestMacRoundTrip();
    TestIpv4Helpers();
    TestLoadValidConfig();
    TestValidation();
    TestPerfValidation();
    TestGatewayValidation();
    TestIpv6Validation();
    TestVlanValidation();
    TestWebPortValidation();
    TestStringAndDnsSuperLargeCaps();
    TestLongUtf8PathConversion();
    TestModeDefaultsToBypass();
    TestModeMainParsed();
    TestModeRejectsUnknownValue();
    TestModeRejectsNonString();
    TestDhcpConfigParsed();
    TestDhcpPoolArrayRejectsBadEntry();
    TestDhcpLeaseHoursBounds();
    TestDhcpDnsCapRejected();
    TestDhcpStaticBindingDuplicates();
    TestDhcpStaticHostnameTooLong();
    TestDhcpValidationModeScoped();
    TestDhcp6ConfigParsed();
    TestBridgeConfigDefaults();
    TestBridgeConfigParse();
    TestBridgeRejectsSamePorts();
    TestBridgeRejectsEmptyPorts();
    TestBridgeMacTableSizeBounds();
    TestExampleConfigRoundTrip();
    TestConfigJsonRoundTrip();
    TestToJsonStringRejectsNonWholeHourLease();
    TestConfigSaveAtomic();
    TestValidateConfigPublic();
    TestB105ProgrammaticConfigObeysLoaderRules();
    TestB106CliOverrideMustValidate();
    TestExampleDhcpPoolKeys();
    TestApplyCliOverridesUsageFlags();
    TestB34lWrongTypeRejected();
    TestB34lFractionalIntegerRejected();
    TestB34lBooleanAsIntegerRejected();
    TestB34lPoolExcludesReservedAddresses();
    TestB34lStaticBindingExcludesReservedAddresses();
    TestB34lGatewayMacMustBeUnicast();
    TestB34mVlanEnabledWithoutIdRejected();
    TestB34mDhcpv6RequiresIpv6();
    TestB34mDhcpDnsMustBeUsable();
    TestB34mRxBatchMustFitRing();
    TestB84WebBindBounds();
    if (0 == g_failures) {
        std::puts("test_config: ALL PASS");
        return 0;
    }
    std::fprintf(stderr, "test_config: %d FAILURES\n", g_failures);
    return 1;
}
