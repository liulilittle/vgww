// ============================================================================
// config.cpp - JSON configuration loading and validation.
// ============================================================================
#include "core/config.h"
#include "core/limits.h"

#include <nlohmann/json.hpp>

#include <winsock2.h>
#include <windows.h>
#include <io.h>
#include <iphlpapi.h>
#include <algorithm>
#include <atomic>

#include <charconv>
#include <chrono>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <stdexcept>

namespace vgww {
    namespace core {

        namespace {

            using nlohmann::json;

            /// Parses an IPv6 address with an optional "/length" suffix into
            /// 16 wire-order bytes (declared early; defined below with the
            /// helper it uses).
            bool ParseIpv6Address(const std::string& text,
                                  std::array<uint8_t, 16>& out,
                                  int& out_prefix_len);

            /// Network -> host byte order (portable, no winsock dependency).
            inline uint32_t HostOrder(uint32_t net) noexcept {
                return ((net & 0x000000FFu) << 24) | ((net & 0x0000FF00u) << 8) |
                       ((net & 0x00FF0000u) >> 8) | ((net & 0xFF000000u) >> 24);
            }

            // ---- Semantic validation bounds ---------------------------------
            // Each bound exists because the value is consumed by a fixed-size
            // container downstream (SPSC ring, RA 16-bit field, uint32 field).
            constexpr uint32_t kMaxWorkers = 8;          // == xtcp shard count
            constexpr uint32_t kMaxRxBatch = 4096;
            constexpr uint32_t kMaxCap = 1u << 20;       // conns / flows / rings
            /// Upper bound for perf.udp_flow_cap: the old default 65536 stays
            /// configurable, but 1048576 (the generic kMaxCap) allowed a
            /// multi-GiB worst case across 8 workers.
            constexpr uint32_t kMaxUdpFlowCap = 65536;
            constexpr uint32_t kMaxDialTimeoutMs = 3600000u;  // one hour
            constexpr uint32_t kMaxLeaseHours = 8760;    // one year of hours
            constexpr uint32_t kMaxPrefixLen = 64;       // SLAAC interface ID
            constexpr uint32_t kMaxRouterLifetimeS = 65535;  // 16-bit RA field
            constexpr size_t kMaxDuidLen = 128;           // RFC 8415 DUID-LL/LLT/EN cap
            constexpr uint32_t kMinWebPort = 1024;       // no privileged/ephemeral
            constexpr uint32_t kMaxWebPort = 65535;
            constexpr uint32_t kMinVlanId = 1;           // 0 = untagged (reserved)
            constexpr uint32_t kMaxVlanId = 4094;        // 0xFFF reserved

            /// Converts a JSON string like "192.168.0.40" to network order.
            bool JsonToIpv4(const json& node, uint32_t& out) {
                if (!node.is_string()) {
                    return false;
                }
                bool ok = false;
                out = ParseIpv4(node.get<std::string>(), ok);
                return ok;
            }

            bool JsonToMac(const json& node, MacAddress& out) {
                if (!node.is_string()) {
                    return false;
                }
                return ParseMac(node.get<std::string>(), out);
            }

            /// batch34l: a JSON number that is not a whole number is a typo,
            /// not a request to truncate. `get<uint32_t>()` silently
            /// truncates 64.9 to 64, so every integer field routes through
            /// this helper: it rejects fractions, negatives and anything
            /// outside [lo, hi], and always explains itself.
            bool ReadInteger(const json& node, const char* what, uint32_t lo,
                             uint32_t hi, uint32_t& out, std::string& error) {
                if (!node.is_number()) {
                    error = std::string(what) + " must be a number";
                    return false;
                }
                if (node.is_number_unsigned()) {
                    const uint64_t v = node.get<uint64_t>();
                    if (v < static_cast<uint64_t>(lo) ||
                        v > static_cast<uint64_t>(hi)) {
                        error = std::string(what) + " is out of range";
                        return false;
                    }
                    out = static_cast<uint32_t>(v);
                    return true;
                }
                // Signed integer or floating point: compare in double space so
                // negatives and huge values fail cleanly instead of wrapping.
                const double d = node.get<double>();
                // Range first: this rejects 1e30 and negatives before any
                // integer cast could overflow.
                if (d < static_cast<double>(lo) || d > static_cast<double>(hi)) {
                    error = std::string(what) + " is out of range";
                    return false;
                }
                // A float that happens to hold an exact integer value (e.g.
                // 4096.0) is still accepted: JSON writers emit that form
                // routinely and the intent is unambiguous. 64.9 is a typo.
                if (d != static_cast<double>(static_cast<long long>(d))) {
                    error = std::string(what) +
                            " must be a whole number (no fraction)";
                    return false;
                }
                out = static_cast<uint32_t>(d);
                return true;
            }

            /// batch34l: a value the operator wrote must never be silently
            /// ignored. When a key is present but of the wrong JSON type, the
            /// load fails instead of leaving the default in place (which
            /// would make the running process differ from the file).
            bool RequireString(const json& node, const char* what,
                               std::string& out, std::string& error) {
                if (!node.is_string()) {
                    error = std::string(what) + " must be a string";
                    return false;
                }
                out = node.get<std::string>();
                return true;
            }

            bool RequireBool(const json& node, const char* what, bool& out,
                             std::string& error) {
                if (!node.is_boolean()) {
                    error = std::string(what) + " must be a boolean";
                    return false;
                }
                out = node.get<bool>();
                return true;
            }

            void ParseGateway(const json& root, Config& config, std::string& error) {
                const auto it = root.find("gateway");
                if (it == root.end() || !it->is_object()) {
                    error = "missing required object: gateway";
                    return;
                }
                if (!JsonToIpv4(it->at("ipv4"), config.gateway.ipv4) ||
                    !JsonToIpv4(it->at("mask"), config.gateway.mask) ||
                    !JsonToMac(it->at("mac"), config.gateway.mac)) {
                    error = "gateway.ipv4 / gateway.mask / gateway.mac malformed";
                }
            }

            /// Optional "mode": "bypass" | "main" (absent = bypass). Strict:
            /// only the exact lowercase strings are accepted; any other type
            /// or value is a startup error (never a silent fallback).
            void ParseMode(const json& root, Config& config, std::string& error) {
                const auto it = root.find("mode");
                if (it == root.end()) {
                    return;  // absent: keep the default (bypass)
                }
                if (!it->is_string()) {
                    error = "mode must be \"bypass\" or \"main\"";
                    return;
                }
                const std::string value = it->get<std::string>();
                if ("bypass" == value) {
                    config.mode = Mode::kBypass;
                } else if ("main" == value) {
                    config.mode = Mode::kMain;
                } else {
                    error = "mode must be \"bypass\" or \"main\"";
                }
            }

            /// Fills `out` with the host's active IPv4 DNS servers (project
            /// numeric convention: first octet in the LOW byte). Used when no
            /// DNS is configured: without a resolver the DHCP clients cannot
            /// do name resolution and the router is effectively broken out of
            /// the box.
            void FillDefaultDns(std::vector<uint32_t>& out) {
                ULONG size = 0;
                if (NO_ERROR !=
                    GetAdaptersAddresses(AF_INET,
                                         GAA_FLAG_SKIP_ANYCAST |
                                             GAA_FLAG_SKIP_MULTICAST |
                                             GAA_FLAG_SKIP_FRIENDLY_NAME,
                                         nullptr, nullptr, &size)) {
                    if (0 == size) {
                        return;
                    }
                }
                std::vector<BYTE> buffer(size);
                const PIP_ADAPTER_ADDRESSES aa =
                    reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());
                if (NO_ERROR !=
                    GetAdaptersAddresses(AF_INET,
                                         GAA_FLAG_SKIP_ANYCAST |
                                             GAA_FLAG_SKIP_MULTICAST |
                                             GAA_FLAG_SKIP_FRIENDLY_NAME,
                                         nullptr, aa, &size)) {
                    return;
                }
                for (PIP_ADAPTER_ADDRESSES it = aa; it; it = it->Next) {
                    if (IfOperStatusUp != it->OperStatus) {
                        continue;
                    }
                    for (PIP_ADAPTER_DNS_SERVER_ADDRESS dns =
                             it->FirstDnsServerAddress;
                         dns; dns = dns->Next) {
                        if (AF_INET != dns->Address.lpSockaddr->sa_family) {
                            continue;
                        }
                        const auto* sin = reinterpret_cast<const sockaddr_in*>(
                            dns->Address.lpSockaddr);
                        const uint8_t* b = reinterpret_cast<const uint8_t*>(
                            &sin->sin_addr.S_un.S_addr);
                        if (0 == b[0] && 0 == b[1] && 0 == b[2] && 0 == b[3]) {
                            continue;  // unspecified
                        }
                        out.push_back(static_cast<uint32_t>(b[0]) |
                                      (static_cast<uint32_t>(b[1]) << 8) |
                                      (static_cast<uint32_t>(b[2]) << 16) |
                                      (static_cast<uint32_t>(b[3]) << 24));
                        if (out.size() >= limits::kMaxDhcpDns) {
                            return;  // cap: a handful of servers is plenty
                        }
                    }
                }
            }

            /// Restores the d6c7dd5 "dhcp" section schema. Always parsed
            /// (also in bypass mode, so a later switch to main needs no
            /// rewrite); pure pool/gateway semantics live in ValidateConfig
            /// and run in main mode only.
            void ParseDhcp(const json& root, Config& config, std::string& error) {
                const auto it = root.find("dhcp");
                if (it == root.end()) {
                    return;  // DHCP section is optional; defaults apply.
                }
                if (!it->is_object()) {
                    error = "dhcp must be an object";
                    return;
                }
                if (const auto e = it->find("enabled"); e != it->end()) {
                    if (!RequireBool(*e, "dhcp.enabled", config.dhcp.enabled,
                                     error)) {
                        return;
                    }
                }
                if (const auto e = it->find("pool"); e != it->end()) {
                    // A present "pool" key must be exactly the two-element
                    // array form; any other shape is a hard error (a silently
                    // ignored pool means DHCP hands out nothing).
                    if (!e->is_array() || e->size() != 2) {
                        error = "dhcp.pool must be a two-element array "
                                "[start, end]";
                        return;
                    }
                    // Same discipline as the pool_start/pool_end spelling
                    // below: a malformed pool entry is a hard error, never a
                    // silent 0.0.0.0 bound.
                    const bool ok_start =
                        JsonToIpv4((*e)[0], config.dhcp.pool_start);
                    const bool ok_end =
                        JsonToIpv4((*e)[1], config.dhcp.pool_end);
                    if (!ok_start || !ok_end) {
                        error = "dhcp.pool malformed ipv4 entry";
                        return;
                    }
                } else if (it->find("pool_start") != it->end() ||
                           it->find("pool_end") != it->end()) {
                    // Compatibility spelling (config.example.json): two
                    // string keys. Both must be present and valid - a
                    // half-configured pool is a hard error, never a silent
                    // 0.0.0.0 bound.
                    const auto start = it->find("pool_start");
                    const auto end = it->find("pool_end");
                    if (start == it->end() || end == it->end() ||
                        !start->is_string() || !end->is_string()) {
                        error = "dhcp.pool_start and dhcp.pool_end must both "
                                "be present";
                        return;
                    }
                    bool ok_start = false;
                    bool ok_end = false;
                    config.dhcp.pool_start =
                        ParseIpv4(start->get<std::string>(), ok_start);
                    config.dhcp.pool_end =
                        ParseIpv4(end->get<std::string>(), ok_end);
                    if (!ok_start || !ok_end) {
                        error = "dhcp.pool_start / dhcp.pool_end malformed";
                        return;
                    }
                }
                if (const auto e = it->find("lease_hours"); e != it->end()) {
                    // Bounded: 0 makes DHCP leases expire instantly and a
                    // value >= 1193047 overflows the uint32 lease_seconds
                    // field when multiplied by 3600. Cap at one year.
                    uint32_t hours = 0;
                    if (!ReadInteger(*e, "dhcp.lease_hours", 1, kMaxLeaseHours,
                                     hours, error)) {
                        return;
                    }
                    config.dhcp.lease_seconds = hours * 3600u;
                }
                if (const auto e = it->find("dns"); e != it->end()) {
                    // A present "dns" key must be an array: a bare string is
                    // a typo, and silently ignoring it would leave the host
                    // resolver in place while the file claims otherwise.
                    if (!e->is_array()) {
                        error = "dhcp.dns must be an array of IPv4 addresses";
                        return;
                    }
                    // Strict cap: every configured resolver must be honored
                    // (silent truncation hides a client-visible mismatch).
                    if (e->size() > limits::kMaxDhcpDns) {
                        error = "dhcp.dns too many entries";
                        return;
                    }
                    for (const auto& entry : *e) {
                        uint32_t ip = 0;
                        // Every entry must be a valid IPv4 address: a
                        // garbage entry is a typo, and skipping it would
                        // hand clients a resolver list the operator never
                        // asked for.
                        if (!JsonToIpv4(entry, ip)) {
                            error = "dhcp.dns entry malformed ipv4";
                            return;
                        }
                        // Skip the unspecified address: handing clients a
                        // 0.0.0.0 resolver is a silent misconfiguration.
                        if (ip != 0) {
                            // batch34m: an address no client can use as a
                            // resolver makes name resolution fail for every
                            // device on the LAN, invisibly. The list is handed
                            // to clients verbatim as option 6, so reject the
                            // categories that are never a usable resolver:
                            // loopback (127/8), group/broadcast (224/4 and
                            // 255.255.255.255), and the gateway itself (which
                            // runs no resolver in this build).
                            const uint32_t host = HostOrder(ip);
                            const uint8_t first =
                                static_cast<uint8_t>(host >> 24);
                            if (first == 127) {
                                error = "dhcp.dns entry is a loopback address";
                                return;
                            }
                            if (first >= 224) {
                                error = "dhcp.dns entry is a multicast or "
                                        "broadcast address";
                                return;
                            }
                            if (ip == config.gateway.ipv4) {
                                error = "dhcp.dns entry is the gateway itself "
                                        "(it runs no DNS resolver)";
                                return;
                            }
                            // The LAN subnet's own broadcast and network
                            // addresses are not hosts either: a client sending
                            // a query there reaches nobody.
                            {
                                const uint32_t hmask =
                                    HostOrder(config.gateway.mask);
                                const uint32_t host_bits = ~hmask;
                                if (host_bits > 1u) {
                                    const uint32_t net = host & hmask;
                                    const uint32_t bcast = net | host_bits;
                                    if (host == net || host == bcast) {
                                        error =
                                            "dhcp.dns entry is the subnet "
                                            "network or broadcast address";
                                        return;
                                    }
                                }
                            }
                            config.dhcp.dns.push_back(ip);
                        }
                    }
                }
                if (config.dhcp.dns.empty()) {
                    // Without a configured resolver the DHCP clients get no
                    // DNS option and name resolution fails entirely. Fall
                    // back to the host's active DNS servers.
                    FillDefaultDns(config.dhcp.dns);
                }
                if (const auto e = it->find("static_bindings");
                    e != it->end()) {
                    // A present key must be an array: an object or a string
                    // here is a typo that would otherwise leave every static
                    // reservation silently unapplied.
                    if (!e->is_array()) {
                        error = "dhcp.static_bindings must be an array";
                        return;
                    }
                    for (const auto& entry : *e) {
                        StaticBinding binding;
                        if (!JsonToMac(entry.at("mac"), binding.mac) ||
                            !JsonToIpv4(entry.at("ip"), binding.ip)) {
                            error = "dhcp.static_bindings entry malformed";
                            return;
                        }
                        // Semantic validation: a bound address must be
                        // distinct from the gateway, unique across bindings,
                        // and inside the gateway subnet so it is actually
                        // reachable on the LAN side.
                        if (binding.ip == config.gateway.ipv4) {
                            error = "dhcp.static_bindings: bound address equals the gateway";
                            return;
                        }
                        for (const auto& prev : config.dhcp.static_bindings) {
                            if (prev.ip == binding.ip) {
                                error = "dhcp.static_bindings: duplicate bound address";
                                return;
                            }
                            if (prev.mac == binding.mac) {
                                error = "dhcp.static_bindings: duplicate mac address";
                                return;
                            }
                        }
                        if (0 != config.gateway.mask &&
                            ((binding.ip & config.gateway.mask) !=
                             (config.gateway.ipv4 & config.gateway.mask))) {
                            error = "dhcp.static_bindings: bound address outside the gateway subnet";
                            return;
                        }
                        // batch34l: the subnet's network and broadcast
                        // addresses are not host addresses. A client bound to
                        // one of them can never communicate, and the
                        // reservation is permanent. /31 and /32 have no
                        // network/broadcast concept, so they are exempt.
                        {
                            const uint32_t hmask =
                                HostOrder(config.gateway.mask);
                            const uint32_t host_bits = ~hmask;
                            // /31 and /32: host_bits is 0 or 1.
                            if (host_bits > 1u) {
                                const uint32_t hip = HostOrder(binding.ip);
                                const uint32_t net = hip & hmask;
                                const uint32_t bcast = net | host_bits;
                                if (hip == net || hip == bcast) {
                                    error =
                                        "dhcp.static_bindings: bound address "
                                        "is the subnet network or broadcast "
                                        "address";
                                    return;
                                }
                            }
                        }
                        // Super-large guard: token-driven cap.
                        if (config.dhcp.static_bindings.size() >=
                            limits::kMaxStaticBindings) {
                            error = "dhcp.static_bindings: too many bindings";
                            return;
                        }
                        if (const auto h = entry.find("hostname");
                            h != entry.end() && h->is_string()) {
                            binding.hostname = h->get<std::string>();
                            if (binding.hostname.size() > ::vgww::core::limits::kMaxHostnameBytes) {
                                error = "dhcp.static_bindings: hostname too long";
                                return;
                            }
                        }
                        config.dhcp.static_bindings.push_back(
                            std::move(binding));
                    }
                }
            }

            void ParseIpv6(const json& root, Config& config, std::string& error) {
                const auto it = root.find("ipv6");
                if (it == root.end()) {
                    return;
                }
                if (!it->is_object()) {
                    error = "ipv6 must be an object";
                    return;
                }
                if (const auto e = it->find("enabled"); e != it->end()) {
                    if (!RequireBool(*e, "ipv6.enabled", config.ipv6.enabled,
                                     error)) {
                        return;
                    }
                }
                // ULA prefix, wire-order bytes: either an address with an
                // embedded "/len" ("fdaa:0:0::/48") or a bare address whose
                // length comes from the prefix_len key (default 64). This is
                // the prefix advertised in RA / matched in NS (see
                // src/runtime/dataplane.cpp).
                int text_len = -1;  // prefix length parsed from the text
                if (const auto e = it->find("ula_prefix"); e != it->end()) {
                    if (!e->is_string()) {
                        error = "ipv6.ula_prefix must be a string";
                        return;
                    }
                    if (!ParseIpv6Address(e->get<std::string>(),
                                          config.ipv6.ula_prefix, text_len)) {
                        error = "ipv6.ula_prefix malformed (expected an IPv6 "
                                "address such as \"fdaa:0:0::\", optionally "
                                "with \"/length\")";
                        return;
                    }
                }
                if (const auto e = it->find("prefix_len"); e != it->end()) {
                    uint32_t requested = 0;
                    if (!ReadInteger(*e, "ipv6.prefix_len", 1, kMaxPrefixLen,
                                     requested, error)) {
                        return;
                    }
                    if (text_len >= 0 &&
                        static_cast<uint32_t>(text_len) != requested) {
                        error = "ipv6.ula_prefix \"/len\" conflicts with "
                                "ipv6.prefix_len";
                        return;
                    }
                    text_len = static_cast<int>(requested);
                }
                if (const auto e = it->find("ra_lifetime_s"); e != it->end()) {
                    uint32_t lifetime = 0;
                    if (!ReadInteger(*e, "ipv6.ra_lifetime_s", 1,
                                     kMaxRouterLifetimeS, lifetime, error)) {
                        return;
                    }
                    if (lifetime < 1 || lifetime > kMaxRouterLifetimeS) {
                        error = "ipv6.ra_lifetime_s must be in [1, 65535]";
                        return;
                    }
                    config.ipv6.ra_lifetime_s = lifetime;                }
                if (text_len >= 0) {
                    // The embedded "/len" suffix is bound exactly like the
                    // prefix_len key: SLAAC hosts need 64 bits for the IID.
                    if (text_len < 1 ||
                        static_cast<uint32_t>(text_len) > kMaxPrefixLen) {
                        error = "ipv6.ula_prefix length must be in [1, 64]";
                        return;
                    }
                    config.ipv6.prefix_len =
                        static_cast<uint8_t>(text_len);
                }
                if (const auto e = it->find("dns"); e != it->end()) {
                    // RDNSS servers handed to SLAAC clients (RFC 8106). Each
                    // must be a full address without a "/len" suffix; more
                    // than 3 makes no sense on a LAN and is rejected.
                    if (!e->is_array() || e->size() > 3) {
                        error = "ipv6.dns must be an array of at most 3 "
                                "IPv6 addresses";
                        return;
                    }
                    for (size_t i = 0; i < e->size(); ++i) {
                        if (!(*e)[i].is_string()) {
                            error = "ipv6.dns entries must be strings";
                            return;
                        }
                        std::array<uint8_t, 16> addr{};
                        int suffix = -1;
                        if (!ParseIpv6Address((*e)[i].get_ref<
                                                  const std::string&>(),
                                              addr, suffix) ||
                            suffix >= 0) {
                            error = "ipv6.dns[" + std::to_string(i) +
                                    "] must be a full IPv6 address "
                                    "(no \"/length\" suffix)";
                            return;
                        }
                        // Skip the unspecified address (::): an all-zero
                        // RDNSS entry is a silent misconfiguration.
                        bool all_zero = true;
                        for (const uint8_t b : addr) {
                            all_zero = all_zero && (0 == b);
                        }
                        if (all_zero) {
                            continue;
                        }
                        config.ipv6.dns.push_back(addr);
                    }
                }
                if (const auto d = it->find("dhcpv6"); d != it->end()) {
                    // Stateful DHCPv6 server (RFC 8415 subset). Addresses are
                    // parsed here; prefix membership and pool ordering are
                    // enforced in ValidateConfig once the ULA prefix is final.
                    if (!d->is_object()) {
                        error = "ipv6.dhcpv6 must be an object";
                        return;
                    }
                    if (const auto e = d->find("enabled"); e != d->end()) {
                        if (!RequireBool(*e, "ipv6.dhcpv6.enabled",
                                         config.ipv6.dhcpv6.enabled, error)) {
                            return;
                        }
                    }
                    const auto parse_full_addr =
                        [&error](const json& node,
                                 std::array<uint8_t, 16>& out,
                                 const std::string& what) {
                            if (!node.is_string()) {
                                error = "ipv6.dhcpv6." + what +
                                        " must be a string";
                                return false;
                            }
                            int suffix = -1;
                            if (!ParseIpv6Address(
                                    node.get_ref<const std::string&>(), out,
                                    suffix) ||
                                suffix >= 0) {
                                error = "ipv6.dhcpv6." + what +
                                        " must be a full IPv6 address "
                                        "(no \"/length\" suffix)";
                                return false;
                            }
                            return true;
                        };
                    if (const auto e = d->find("pool_start"); e != d->end()) {
                        if (!parse_full_addr(*e,
                                             config.ipv6.dhcpv6.pool_start,
                                             "pool_start")) {
                            return;
                        }
                    }
                    if (const auto e = d->find("pool_end"); e != d->end()) {
                        if (!parse_full_addr(*e, config.ipv6.dhcpv6.pool_end,
                                             "pool_end")) {
                            return;
                        }
                    }
                    if (const auto e = d->find("lease_seconds");
                        e != d->end()) {
                        // Same bound as dhcp.lease_hours (one year): below a
                        // minute the pool churns, beyond a year is pointless.
                        uint32_t seconds = 0;
                        if (!ReadInteger(*e, "ipv6.dhcpv6.lease_seconds", 60,
                                         kMaxLeaseHours * 3600u, seconds,
                                         error)) {
                            return;
                        }
                        config.ipv6.dhcpv6.lease_seconds = seconds;
                    }
                    if (const auto e = d->find("static_bindings");
                        e != d->end()) {
                        if (!e->is_array()) {
                            error = "ipv6.dhcpv6.static_bindings must be an "
                                    "array";
                            return;
                        }
                        const auto hexval = [](char c) -> int {
                            if (c >= '0' && c <= '9') return c - '0';
                            if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
                            if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
                            return -1;
                        };
                        for (const auto& entry : *e) {
                            Dhcp6StaticBinding binding;
                            const auto duid = entry.find("duid");
                            if (duid == entry.end() || !duid->is_string()) {
                                error = "ipv6.dhcpv6.static_bindings: duid "
                                        "must be a hex string";
                                return;
                            }
                            const std::string text =
                                duid->get<std::string>();
                            if (text.empty() || 0 != (text.size() % 2)) {
                                error = "ipv6.dhcpv6.static_bindings: duid "
                                        "must be an even-length hex string";
                                return;
                            }
                            for (const char c : text) {
                                if (hexval(c) < 0) {
                                    error = "ipv6.dhcpv6.static_bindings: "
                                            "duid must be a hex string";
                                    return;
                                }
                            }
                            binding.duid.reserve(text.size() / 2);
                            for (size_t i = 0; i < text.size(); i += 2) {
                                binding.duid.push_back(static_cast<uint8_t>(
                                    (hexval(text[i]) << 4) |
                                    hexval(text[i + 1])));
                            }
                            if (binding.duid.size() > kMaxDuidLen) {
                                error = "ipv6.dhcpv6.static_bindings: duid "
                                        "longer than 128 octets";
                                return;
                            }
                            const auto ip_node = entry.find("ip");
                            if (ip_node == entry.end()) {
                                error = "ipv6.dhcpv6.static_bindings: ip "
                                        "must be a full IPv6 address";
                                return;
                            }
                            if (!parse_full_addr(*ip_node, binding.ip,
                                                 "static_bindings ip")) {
                                return;
                            }
                            for (const auto& prev :
                                 config.ipv6.dhcpv6.static_bindings) {
                                if (prev.ip == binding.ip) {
                                    error = "ipv6.dhcpv6.static_bindings: "
                                            "duplicate bound address";
                                    return;
                                }
                                if (prev.duid == binding.duid) {
                                    error = "ipv6.dhcpv6.static_bindings: "
                                            "duplicate duid";
                                    return;
                                }
                            }
                            if (config.ipv6.dhcpv6.static_bindings.size() >=
                                limits::kMaxStaticBindings6) {
                                error = "ipv6.dhcpv6.static_bindings: too "
                                        "many bindings";
                                return;
                            }
                            if (const auto h = entry.find("hostname");
                                h != entry.end() && h->is_string()) {
                                binding.hostname = h->get<std::string>();
                                if (binding.hostname.size() > ::vgww::core::limits::kMaxHostnameBytes) {
                                    error = "ipv6.dhcpv6.static_bindings: "
                                            "hostname too long";
                                    return;
                                }
                            }
                            config.ipv6.dhcpv6.static_bindings.push_back(
                                std::move(binding));
                        }
                    }
                }
            }

                        void ParseWeb(const json& root, Config& config, std::string& error) {
                const auto it = root.find("web");
                if (it == root.end()) {
                    return;
                }
                if (!it->is_object()) {
                    error = "web must be an object";
                    return;
                }
                // batch20 P2: absent "enabled" keeps the default (true).
                if (const auto e = it->find("enabled"); e != it->end()) {
                    if (!e->is_boolean()) {
                        error = "web.enabled must be a boolean";
                        return;
                    }
                    config.web.enabled = e->get<bool>();
                }
                if (const auto e = it->find("port"); e != it->end()) {
                    // Parse as a bounded integer: values > 65535 and
                    // fractional ports fail loudly here instead of silently
                    // truncating into the uint16 field.
                    uint32_t port = 0;
                    if (!ReadInteger(*e, "web.port", kMinWebPort, kMaxWebPort,
                                     port, error)) {
                        return;
                    }
                    config.web.port = static_cast<uint16_t>(port);
                }
                if (const auto e = it->find("token"); e != it->end()) {
                    if (!RequireString(*e, "web.token", config.web.token,
                                       error)) {
                        return;
                    }
                    if (config.web.token.size() > limits::kMaxTokenBytes) {
                        error = "web.token too long";
                        return;
                    }
                }
                if (const auto e = it->find("bind"); e != it->end()) {
                    if (!RequireString(*e, "web.bind", config.web.bind,
                                       error)) {
                        return;
                    }
                    if (config.web.bind.empty() ||
                        config.web.bind.size() > limits::kMaxAdapterBytes) {
                        error = "web.bind must be non-empty and at most "
                                "256 bytes";
                        return;
                    }
                }
            }

            void ParseVlan(const json& root, Config& config, std::string& error) {
                const auto it = root.find("vlan");
                if (it == root.end()) {
                    return;  // absent = disabled
                }
                if (!it->is_object()) {
                    error = "vlan must be an object";
                    return;
                }
                if (const auto e = it->find("id"); e != it->end()) {
                    // Parse as a bounded integer: values outside the 12-bit
                    // C-VLAN range must fail loudly instead of silently
                    // truncating into the uint16 field or into the reserved
                    // codepoints.
                    uint32_t id = 0;
                    if (!ReadInteger(*e, "vlan.id", kMinVlanId, kMaxVlanId, id,
                                     error)) {
                        return;
                    }
                    config.vlan.id = static_cast<uint16_t>(id);
                }
                // batch34m: VLAN is enabled by a non-zero `id`
                // (VlanConfig::enabled()); there is no separate flag in the
                // model. A section that asks for `"enabled": true` without an
                // id would silently tag nothing, leaving the operator
                // convinced traffic is isolated when it is not. Refuse the
                // combination instead of accepting a no-op.
                if (const auto e = it->find("enabled"); e != it->end()) {
                    bool enabled = false;
                    if (!RequireBool(*e, "vlan.enabled", enabled, error)) {
                        return;
                    }
                    if (enabled && 0 == config.vlan.id) {
                        error = "vlan.enabled is true but vlan.id is missing "
                                "(VLAN tagging is enabled by a non-zero id)";
                        return;
                    }
                    if (!enabled && 0 != config.vlan.id) {
                        error = "vlan.enabled is false but vlan.id is set "
                                "(omit the id to disable VLAN tagging)";
                        return;
                    }
                }
            }

            void ParseBridge(const json& root, Config& config,
                             std::string& error) {
                const auto it = root.find("bridge");
                if (it == root.end()) {
                    return;  // absent = disabled
                }
                if (!it->is_object()) {
                    error = "bridge must be an object";
                    return;
                }
                if (const auto e = it->find("enabled"); e != it->end()) {
                    if (!RequireBool(*e, "bridge.enabled", config.bridge.enabled,
                                     error)) {
                        return;
                    }
                }
                if (const auto e = it->find("upstream"); e != it->end()) {
                    if (!RequireString(*e, "bridge.upstream",
                                       config.bridge.upstream, error)) {
                        return;
                    }
                    if (config.bridge.upstream.size() >
                        limits::kMaxAdapterBytes) {
                        error = "bridge.upstream too long";
                        return;
                    }
                }
                if (const auto e = it->find("downstream"); e != it->end()) {
                    if (!RequireString(*e, "bridge.downstream",
                                       config.bridge.downstream, error)) {
                        return;
                    }
                    if (config.bridge.downstream.size() >
                        limits::kMaxAdapterBytes) {
                        error = "bridge.downstream too long";
                        return;
                    }
                }
                if (const auto e = it->find("mac_table_size");
                    e != it->end()) {
                    uint32_t size = 0;
                    if (!ReadInteger(*e, "bridge.mac_table_size", 1,
                                     static_cast<uint32_t>(
                                         limits::kMaxMacTableSize),
                                     size, error)) {
                        return;
                    }
                    config.bridge.mac_table_size = size;
                }
            }

            void ParsePerf(const json& root, Config& config, std::string& error) {
                const auto it = root.find("perf");
                if (it == root.end()) {
                    return;
                }
                if (!it->is_object()) {
                    error = "perf must be an object";
                    return;
                }
                // batch34l: every numeric field goes through ReadInteger so a
                // fractional or non-numeric value is rejected instead of being
                // silently truncated by get<uint32_t>(). The value RANGES are
                // enforced by ValidateConfig, which also covers programmatic
                // configs that never pass through this parser.
                constexpr uint32_t kAny = 0xFFFFFFFFu;
                if (const auto e = it->find("workers"); e != it->end()) {
                    if (!ReadInteger(*e, "perf.workers", 0, kAny,
                                     config.perf.workers, error)) {
                        return;
                    }
                }
                if (const auto e = it->find("rx_batch"); e != it->end()) {
                    if (!ReadInteger(*e, "perf.rx_batch", 0, kAny,
                                     config.perf.rx_batch, error)) {
                        return;
                    }
                }
                if (const auto e = it->find("max_conns"); e != it->end()) {
                    if (!ReadInteger(*e, "perf.max_conns", 0, kAny,
                                     config.perf.max_conns, error)) {
                        return;
                    }
                }
                if (const auto e = it->find("udp_flow_cap"); e != it->end()) {
                    if (!ReadInteger(*e, "perf.udp_flow_cap", 0, kAny,
                                     config.perf.udp_flow_cap, error)) {
                        return;
                    }
                }
                if (const auto e = it->find("ring_capacity"); e != it->end()) {
                    if (!ReadInteger(*e, "perf.ring_capacity", 0, kAny,
                                     config.perf.ring_capacity, error)) {
                        return;
                    }
                }
                if (const auto e = it->find("dial_timeout_ms"); e != it->end()) {
                    if (!ReadInteger(*e, "perf.dial_timeout_ms", 0, kAny,
                                     config.perf.dial_timeout_ms, error)) {
                        return;
                    }
                }
                // batch31 P1-4: latency-vs-batching switch (default true).
                if (const auto e = it->find("rx_flush_eager"); e != it->end()) {
                    if (!RequireBool(*e, "perf.rx_flush_eager",
                                     config.perf.rx_flush_eager, error)) {
                        return;
                    }
                }
                if (const auto e = it->find("rx_poll_ms"); e != it->end()) {
                    if (!ReadInteger(*e, "perf.rx_poll_ms", 0, kAny,
                                     config.perf.rx_poll_ms, error)) {
                        return;
                    }
                }
            }

            /// Parses an IPv6 address (compressed "::" form) with an optional
            /// "/length" suffix into 16 wire-order bytes. `out_prefix_len`
            /// receives the parsed length, or -1 when the text has no suffix.
            bool ParseIpv6Address(const std::string& text,
                                  std::array<uint8_t, 16>& out,
                                  int& out_prefix_len) {
                out_prefix_len = -1;
                std::string addr = text;
                if (const size_t slash = text.find('/');
                    slash != std::string::npos) {
                    addr = text.substr(0, slash);
                    const std::string suffix = text.substr(slash + 1);
                    if (suffix.empty()) {
                        return false;
                    }
                    int value = 0;
                    for (const char c : suffix) {
                        if (c < '0' || c > '9' || value > 128) {
                            return false;
                        }
                        value = value * 10 + (c - '0');
                    }
                    out_prefix_len = value;
                }
                if (addr.empty()) {
                    return false;
                }

                const auto hexval = [](char c) -> int {
                    if (c >= '0' && c <= '9') return c - '0';
                    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                    return -1;
                };
                // Fills `groups` with `count` colon-separated hex groups
                // (no "::" allowed inside).
                const auto parse_groups = [&hexval](
                                              const std::string& s,
                                              uint16_t* groups,
                                              int& count) -> bool {
                    count = 0;
                    size_t pos = 0;
                    while (pos <= s.size()) {
                        const size_t colon = s.find(':', pos);
                        const size_t end =
                            (std::string::npos == colon) ? s.size() : colon;
                        if (end == pos) {
                            return false;  // empty group outside "::"
                        }
                        const std::string part = s.substr(pos, end - pos);
                        if (part.size() > 4 || count >= 8) {
                            return false;
                        }
                        uint16_t value = 0;
                        for (const char c : part) {
                            const int h = hexval(c);
                            if (h < 0) {
                                return false;
                            }
                            value = static_cast<uint16_t>(
                                (value << 4) | static_cast<uint16_t>(h));
                        }
                        groups[count++] = value;
                        if (std::string::npos == colon) {
                            break;
                        }
                        pos = end + 1;
                    }
                    return true;
                };

                const auto emit = [](std::array<uint8_t, 16>& out,
                                     const uint16_t* groups, int start,
                                     int count) {
                    for (int i = 0; i < count; ++i) {
                        const int idx = start + i;
                        out[static_cast<size_t>(idx) * 2] =
                            static_cast<uint8_t>(groups[i] >> 8);
                        out[static_cast<size_t>(idx) * 2 + 1] =
                            static_cast<uint8_t>(groups[i] & 0xFF);
                    }
                };

                const size_t dc = addr.find("::");
                if (std::string::npos == dc) {
                    uint16_t groups[8] = {};
                    int count = 0;
                    if (!parse_groups(addr, groups, count) || 8 != count) {
                        return false;
                    }
                    emit(out, groups, 0, 8);
                    return true;
                }
                uint16_t pre[8] = {}, post[8] = {};
                int pre_n = 0, post_n = 0;
                const std::string left = addr.substr(0, dc);
                const std::string right = addr.substr(dc + 2);
                if (!left.empty() && !parse_groups(left, pre, pre_n)) {
                    return false;
                }
                if (!right.empty() && !parse_groups(right, post, post_n)) {
                    return false;
                }
                const int zeros = 8 - (pre_n + post_n);
                if (zeros < 1) {
                    return false;  // "::" must stand for >= 1 zero group
                }
                emit(out, pre, 0, pre_n);
                emit(out, post, pre_n + zeros, post_n);
                return true;
            }

        }  // namespace

        /// Validates semantic constraints that span parsed fields.
        /// Returns false and sets `error` on the first violation. Public
        /// since S4 Task 5 (declared in config.h): the UI settings draft
        /// validates programmatic configs before they are written to disk.
        bool ValidateConfig(const Config& config, std::string& error) {
            // A zero gateway or zero netmask makes every LAN check pass
            // for anything - both are fatal misconfigurations.
            if (0 == config.gateway.ipv4) {
                error = "gateway.ipv4 must not be 0.0.0.0";
                return false;
            }
            if (0 == config.gateway.mask) {
                error = "gateway.mask must not be 0.0.0.0";
                return false;
            }
            // batch34l: the gateway MAC is the identity every client's ARP
            // cache resolves the default gateway to. All-zero is unset and a
            // group (multicast/broadcast) address is never a valid source
            // identity, so both are refused instead of producing a gateway
            // that nobody can reach. The multicast bit is the low bit of the
            // first octet; a locally-administered unicast MAC (02:...) stays
            // legal.
            {
                const MacAddress& gm = config.gateway.mac;
                bool all_zero = true;
                for (const uint8_t b : gm) {
                    all_zero = all_zero && (0 == b);
                }
                if (all_zero) {
                    error = "gateway.mac must not be 00:00:00:00:00:00";
                    return false;
                }
                if (0 != (gm[0] & 0x01)) {
                    error = "gateway.mac must be a unicast address (the "
                            "multicast bit is set)";
                    return false;
                }
            }
            // The mask must be a contiguous run of 1s (a /N form). Checked
            // in host-order space: the stored value keeps the first octet in
            // the LOW byte (inet_addr convention, ParseIpv4), where the
            // classic mask & (mask+1)==0 test only holds for byte-aligned
            // prefixes. (~h & (~h+1)) is zero exactly when h's leading 1-run
            // has no gap, so /25-/31 (e.g. 255.255.255.128) pass while
            // non-contiguous masks fail; mask==0 is rejected above and /32
            // (~h==0) passes.
            const uint32_t h = HostOrder(config.gateway.mask);
            if (0 != (~h & (~h + 1))) {
                error = "gateway.mask must be a contiguous 1-bit prefix "
                        "(e.g. 255.255.255.0)";
                return false;
            }

            // DHCP pool semantics apply only when the address services
            // actually run (main mode): bypass parses the section but
            // serves nothing, so a pool that does not match today's LAN
            // must not block startup (spec section 3).
            if (AddressServicesEnabled(config) && config.dhcp.enabled) {
                const uint32_t lan =
                    config.gateway.ipv4 & config.gateway.mask;
                const auto in_lan = [&](uint32_t ip) {
                    return (ip & config.gateway.mask) == lan;
                };
                if (config.dhcp.pool_start == 0 ||
                    config.dhcp.pool_end == 0 ||
                    !in_lan(config.dhcp.pool_start) ||
                    !in_lan(config.dhcp.pool_end) ||
                    HostOrder(config.dhcp.pool_start) >
                        HostOrder(config.dhcp.pool_end)) {
                    error = "dhcp.pool is empty or outside the LAN subnet";
                    return false;
                }
                const uint32_t gw = HostOrder(config.gateway.ipv4);
                if (HostOrder(config.dhcp.pool_start) <= gw &&
                    gw <= HostOrder(config.dhcp.pool_end)) {
                    error = "dhcp.pool must not contain the gateway address";
                    return false;
                }
                // batch34l: the subnet's network and broadcast addresses are
                // not assignable hosts. Handing one out leaves that client
                // unable to communicate at all, and the failure is silent on
                // the wire. /31 and /32 have no network/broadcast concept and
                // are exempt (host_bits <= 1).
                const uint32_t hmask = HostOrder(config.gateway.mask);
                const uint32_t host_bits = ~hmask;
                if (host_bits > 1u) {
                    const uint32_t start_h =
                        HostOrder(config.dhcp.pool_start);
                    const uint32_t end_h = HostOrder(config.dhcp.pool_end);
                    const uint32_t net = start_h & hmask;
                    const uint32_t bcast = net | host_bits;
                    if (start_h == net || start_h == bcast ||
                        end_h == net || end_h == bcast) {
                        error = "dhcp.pool must not include the subnet "
                                "network or broadcast address";
                        return false;
                    }
                }
            }

            // batch34m: the stateful DHCPv6 server only runs when IPv6 itself
            // is enabled (dataplane.cpp:977 gates assembly on both), and the
            // documentation states the requirement. A config that enables the
            // server while IPv6 is off asks for a service that never starts;
            // accepting it hides the mismatch until a client fails to get an
            // address.
            if (config.ipv6.dhcpv6.enabled && !config.ipv6.enabled) {
                error = "ipv6.dhcpv6.enabled requires ipv6.enabled "
                        "(the DHCPv6 server only runs with IPv6 on)";
                return false;
            }

            // IPv6 SLAAC needs a routable ULA to advertise.
            if (config.ipv6.enabled) {
                bool zero = true;
                for (const uint8_t b : config.ipv6.ula_prefix) {
                    zero = zero && (0 == b);
                }
                if (zero) {
                    error = "ipv6.ula_prefix is required when ipv6 is "
                            "enabled";
                    return false;
                }
                if (0xFC != (config.ipv6.ula_prefix[0] & 0xFE)) {
                    error = "ipv6.ula_prefix must be a ULA (fc00::/7) "
                            "prefix";
                    return false;
                }
                // Host bits beyond the prefix length would leak part of a
                // /64-style address into the advertised prefix.
                const uint32_t plen = config.ipv6.prefix_len;
                for (uint32_t bit = plen; bit < 128; ++bit) {
                    const uint8_t byte =
                        config.ipv6.ula_prefix[bit / 8];
                    const uint8_t bitmask = static_cast<uint8_t>(
                        1u << (7 - (bit % 8)));
                    if (0 != (byte & bitmask)) {
                        error = "ipv6.ula_prefix has host bits set beyond "
                                "the prefix length";
                        return false;
                    }
                }
            }

            // Stateful DHCPv6: when the service actually runs (main mode)
            // the pool must sit inside the advertised ULA prefix and be
            // ordered. Both bounds left zero mean "derive ::1000-::1FFF"
            // (spec section 5.2) and are checked by the server itself.
            if (AddressServicesEnabled(config) &&
                config.ipv6.dhcpv6.enabled) {
                const auto& d6 = config.ipv6.dhcpv6;
                const auto is_zero =
                    [](const std::array<uint8_t, 16>& a) {
                        for (const uint8_t b : a) {
                            if (0 != b) return false;
                        }
                        return true;
                    };
                const bool start_zero = is_zero(d6.pool_start);
                const bool end_zero = is_zero(d6.pool_end);
                if (start_zero != end_zero) {
                    error = "ipv6.dhcpv6 pool bounds must both be set or "
                            "both left default";
                    return false;
                }
                const uint32_t plen = config.ipv6.prefix_len;
                const auto in_prefix =
                    [&config, plen](const std::array<uint8_t, 16>& ip) {
                        for (uint32_t bit = 0; bit < plen; ++bit) {
                            const uint8_t mask = static_cast<uint8_t>(
                                1u << (7 - (bit % 8)));
                            if ((ip[bit / 8] & mask) !=
                                (config.ipv6.ula_prefix[bit / 8] &
                                 mask)) {
                                return false;
                            }
                        }
                        return true;
                    };
                if (!start_zero) {
                    if (d6.pool_end < d6.pool_start) {
                        error = "ipv6.dhcpv6.pool_end must not precede "
                                "pool_start";
                        return false;
                    }
                    if (!in_prefix(d6.pool_start) ||
                        !in_prefix(d6.pool_end)) {
                        error = "ipv6.dhcpv6 pool must be inside "
                                "ipv6.ula_prefix";
                        return false;
                    }
                }
                for (const auto& b : d6.static_bindings) {
                    if (!in_prefix(b.ip)) {
                        error = "ipv6.dhcpv6.static_bindings: bound "
                                "address outside ipv6.ula_prefix";
                        return false;
                    }
                }
            }

            // perf: every ring/table/socket-batch size must be usable.
            // ring_capacity = 0 makes SpscRing::Create return null and the
            // dataplane dereferences it on every frame (startup crash).
            const auto range = [](uint32_t v, uint32_t lo, uint32_t hi) {
                return v >= lo && v <= hi;
            };
            if (!range(config.perf.workers, 1, kMaxWorkers)) {
                error = "perf.workers must be in [1, 8] (xtcp shard "
                        "count)";
                return false;
            }
            if (!range(config.perf.rx_batch, 1, kMaxRxBatch)) {
                error = "perf.rx_batch must be in [1, 4096]";
                return false;
            }
            if (!range(config.perf.max_conns, 1, kMaxCap)) {
                error = "perf.max_conns must be in [1, 1048576]";
                return false;
            }
            if (!range(config.perf.udp_flow_cap, 1, kMaxUdpFlowCap)) {
                error = "perf.udp_flow_cap must be in [1, 65536]";
                return false;
            }
            if (!range(config.perf.ring_capacity, 1, kMaxCap)) {
                error = "perf.ring_capacity must be in [1, 1048576]";
                return false;
            }
            // batch34m: one RX read produces up to `rx_batch` frames, but they
            // are buffered in a ring of `ring_capacity` entries
            // (dataplane.cpp:859-861). If a batch cannot fit, the producer can
            // never drain a full read into the ring, and the RX push sites
            // ignore Push()'s false return (dataplane.cpp:2367/2393/2412/2433)
            // - so the overflow is silently dropped under load. Refuse the
            // combination instead of shipping an invisible throughput cap.
            if (config.perf.rx_batch > config.perf.ring_capacity) {
                error = "perf.rx_batch must not exceed perf.ring_capacity "
                        "(a full read batch must fit the ring)";
                return false;
            }
            if (!range(config.perf.dial_timeout_ms, 1,
                       kMaxDialTimeoutMs)) {
                error = "perf.dial_timeout_ms must be in [1, 3600000]";
                return false;
            }
            // batch31 P1-4: the RX fallback wait bounds the worst-case ping.
            if (!range(config.perf.rx_poll_ms, 1, 200)) {
                error = "perf.rx_poll_ms must be in [1, 200]";
                return false;
            }

            // L2 bridge (S3-Task4): single-path only, no STP. An
            // enabled bridge needs two distinct named ports; the table
            // size was range-checked at parse time and re-checked here
            // so programmatic configs get the same refusal.
            if (config.bridge.enabled) {
                if (config.bridge.upstream.empty() ||
                    config.bridge.downstream.empty()) {
                    error = "bridge.upstream and bridge.downstream must "
                            "both be set when bridge.enabled is true";
                    return false;
                }
                if (config.bridge.upstream == config.bridge.downstream) {
                    error = "bridge.upstream and bridge.downstream must "
                            "differ";
                    return false;
                }
            }
            if (0 == config.bridge.mac_table_size ||
                config.bridge.mac_table_size >
                    limits::kMaxMacTableSize) {
                error = "bridge.mac_table_size must be in [1, 65536]";
                return false;
            }

            // Value ranges the JSON parser bounds at load time. A
            // programmatic Config (UI settings draft -> SaveConfigCmd) never
            // passes the parser, and a value the loader would reject must
            // never be written back to disk.
            if (config.adapter.size() > limits::kMaxAdapterBytes) {
                error = "adapter name too long";
                return false;
            }
            if (config.web.port < kMinWebPort ||
                config.web.port > kMaxWebPort) {
                error = "web.port must be in [1024, 65535] (privileged and "
                        "ephemeral ports rejected)";
                return false;
            }
            if (config.web.token.size() > limits::kMaxTokenBytes) {
                error = "web.token too long";
                return false;
            }
            if (config.web.bind.empty() ||
                config.web.bind.size() > limits::kMaxAdapterBytes) {
                error = "web.bind must be non-empty and at most 256 bytes";
                return false;
            }
            if (0 != config.vlan.id &&
                (config.vlan.id < kMinVlanId ||
                 config.vlan.id > kMaxVlanId)) {
                error = "vlan.id must be in [1, 4094] (0 and 4095 are "
                        "reserved 802.1Q codepoints)";
                return false;
            }
            if (config.ipv6.prefix_len < 1 ||
                config.ipv6.prefix_len > kMaxPrefixLen) {
                error = "ipv6.prefix_len must be in [1, 64] (SLAAC hosts "
                        "build a 64-bit interface ID)";
                return false;
            }
            if (config.ipv6.ra_lifetime_s < 1 ||
                config.ipv6.ra_lifetime_s > kMaxRouterLifetimeS) {
                error = "ipv6.ra_lifetime_s must be in [1, 65535]";
                return false;
            }
            if (config.ipv6.dns.size() > 3) {
                error = "ipv6.dns too many entries";
                return false;
            }
            if (config.dhcp.lease_seconds < 3600 ||
                config.dhcp.lease_seconds > kMaxLeaseHours * 3600u ||
                0 != (config.dhcp.lease_seconds % 3600u)) {
                error = "dhcp.lease_seconds must be a whole number of hours "
                        "in [1, 8760]";
                return false;
            }
            if (config.dhcp.dns.size() > limits::kMaxDhcpDns) {
                error = "dhcp.dns too many entries";
                return false;
            }
            if (config.dhcp.static_bindings.size() >
                limits::kMaxStaticBindings) {
                error = "dhcp.static_bindings: too many bindings";
                return false;
            }
            if (config.ipv6.dhcpv6.lease_seconds < 60 ||
                config.ipv6.dhcpv6.lease_seconds > kMaxLeaseHours * 3600u) {
                error = "ipv6.dhcpv6.lease_seconds must be in "
                        "[60, 31536000]";
                return false;
            }
            if (config.ipv6.dhcpv6.static_bindings.size() >
                limits::kMaxStaticBindings6) {
                error = "ipv6.dhcpv6.static_bindings: too many bindings";
                return false;
            }

            // batch105: a PROGRAMMATIC Config must obey the same semantic rules
            // the loader enforces, or the product writes a file it then refuses
            // to read. The UI settings Save builds a Config directly
            // (SettingsDraft::ToConfig -> SaveConfigCmd -> DoSaveConfig), which
            // only passes through this function - never through the JSON
            // loader. Before this block, a resolver of 127.0.0.1 validated
            // clean, SaveToFile wrote it, and the next start failed with
            // "dhcp.dns entry is a loopback address". The value it rejected is
            // never usable by a client either, so both paths must refuse it.
            if (AddressServicesEnabled(config) && config.dhcp.enabled) {
                const uint32_t hmask = HostOrder(config.gateway.mask);
                const uint32_t host_bits = ~hmask;
                const uint32_t gw_host = HostOrder(config.gateway.ipv4);
                for (const uint32_t ip : config.dhcp.dns) {
                    // 0.0.0.0 means "no resolver configured" in this config
                    // (the loader skips it), so it stays accepted here.
                    if (0 == ip) {
                        continue;
                    }
                    const uint32_t host = HostOrder(ip);
                    const uint8_t first = static_cast<uint8_t>(host >> 24);
                    if (first == 127) {
                        error = "dhcp.dns entry is a loopback address";
                        return false;
                    }
                    if (first >= 224) {
                        error = "dhcp.dns entry is a multicast or "
                                "broadcast address";
                        return false;
                    }
                    if (ip == config.gateway.ipv4) {
                        error = "dhcp.dns entry is the gateway itself "
                                "(it runs no DNS resolver)";
                        return false;
                    }
                    if (host_bits > 1u) {
                        const uint32_t net = host & hmask;
                        const uint32_t bcast = net | host_bits;
                        if (host == net || host == bcast) {
                            error = "dhcp.dns entry is the subnet "
                                    "network or broadcast address";
                            return false;
                        }
                    }
                }
                // Static bindings: the same identity/placement rules the parser
                // applies. A reservation that collides with the gateway, sits
                // outside the LAN, or repeats another binding is permanent and
                // silently ineffective once served.
                for (std::size_t i = 0; i < config.dhcp.static_bindings.size();
                     ++i) {
                    const StaticBinding& b = config.dhcp.static_bindings[i];
                    bool all_zero = true;
                    for (const uint8_t byte : b.mac) {
                        all_zero = all_zero && (0 == byte);
                    }
                    if (all_zero) {
                        error = "dhcp.static_bindings: mac must not be "
                                "00:00:00:00:00:00";
                        return false;
                    }
                    if (0 != (b.mac[0] & 0x01)) {
                        error = "dhcp.static_bindings: mac must be a unicast "
                                "address (the multicast bit is set)";
                        return false;
                    }
                    if (0 == b.ip) {
                        error = "dhcp.static_bindings: bound address must not "
                                "be 0.0.0.0";
                        return false;
                    }
                    if (b.ip == config.gateway.ipv4) {
                        error = "dhcp.static_bindings: bound address equals "
                                "the gateway";
                        return false;
                    }
                    if ((b.ip & config.gateway.mask) !=
                        (config.gateway.ipv4 & config.gateway.mask)) {
                        error = "dhcp.static_bindings: bound address outside "
                                "the gateway subnet";
                        return false;
                    }
                    if (host_bits > 1u) {
                        const uint32_t hip = HostOrder(b.ip);
                        const uint32_t net = hip & hmask;
                        const uint32_t bcast = net | host_bits;
                        if (hip == net || hip == bcast) {
                            error = "dhcp.static_bindings: bound address is "
                                    "the subnet network or broadcast address";
                            return false;
                        }
                    }
                    if (b.hostname.size() > ::vgww::core::limits::kMaxHostnameBytes) {
                        error = "dhcp.static_bindings: hostname too long";
                        return false;
                    }
                    for (std::size_t j = 0; j < i; ++j) {
                        if (config.dhcp.static_bindings[j].ip == b.ip) {
                            error = "dhcp.static_bindings: duplicate bound "
                                    "address";
                            return false;
                        }
                        if (config.dhcp.static_bindings[j].mac == b.mac) {
                            error = "dhcp.static_bindings: duplicate mac "
                                    "address";
                            return false;
                        }
                    }
                }
                (void)gw_host;
            }
            // DHCPv6 DUID bounds: the parser rejects an empty or over-long DUID,
            // and a binding keyed on one can never match a real client.
            //
            // batch135: the v4 loop above also enforces BOTH uniqueness rules
            // (one address, one DUID); this block only checked the DUID bounds.
            // The JSON parser rejects duplicates (ParseDhcp, :698-710), but a
            // PROGRAMMATIC config - the UI settings draft (settings.cpp:463) and
            // SaveConfigCmd (controller.cpp:312) - reaches only this validator.
            // Without the rules here a UI save could persist two bindings on one
            // address or two addresses for one DUID, and the next start would
            // refuse the file the product had just written and called "saved".
            // Placement is NOT re-checked here: :1253 already refuses a binding
            // outside the ULA prefix; a second copy of that rule (with a
            // different enabling condition) would be two sources of truth for
            // one invariant (C6).
            for (std::size_t i = 0;
                 i < config.ipv6.dhcpv6.static_bindings.size(); ++i) {
                const Dhcp6StaticBinding& b =
                    config.ipv6.dhcpv6.static_bindings[i];
                if (b.duid.empty()) {
                    error = "ipv6.dhcpv6.static_bindings: duid must not be "
                            "empty";
                    return false;
                }
                if (b.duid.size() > kMaxDuidLen) {
                    error = "ipv6.dhcpv6.static_bindings: duid longer than 128 "
                            "octets";
                    return false;
                }
                if (b.hostname.size() > ::vgww::core::limits::kMaxHostnameBytes) {
                    error = "ipv6.dhcpv6.static_bindings: hostname too long";
                    return false;
                }
                for (std::size_t j = 0; j < i; ++j) {
                    if (config.ipv6.dhcpv6.static_bindings[j].ip == b.ip) {
                        error = "ipv6.dhcpv6.static_bindings: duplicate bound "
                                "address";
                        return false;
                    }
                    if (config.ipv6.dhcpv6.static_bindings[j].duid == b.duid) {
                        error = "ipv6.dhcpv6.static_bindings: duplicate duid";
                        return false;
                    }
                }
            }

            return true;
        }

        bool AddressServicesEnabled(const Config& config) noexcept {
            return Mode::kMain == config.mode;
        }

        std::optional<Config> Config::LoadFromFile(const std::string& path,
                                                   std::string& error) {
            json root;

#ifdef _WIN32
            // Long-path aware open via wide API + \\?\ prefix (32767).
            std::string raw;
            bool raw_ok = false;

            {
                // UTF-8 -> wide
                int wlen = ::MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, nullptr, 0);

                if (wlen > 0)
                {
                    // wlen INCLUDES the terminating NUL: size the buffer for
                    // every element the API writes, then drop the NUL.
                    // (resize(wlen - 1) + write of wlen elements overflowed.)
                    std::wstring wpath(static_cast<size_t>(wlen), L'\0');
                    ::MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, wpath.data(), wlen);
                    wpath.pop_back();  // drop the terminator; size stays wlen-1

                    // Prepend \\?\ for long absolute paths if needed.
                    if (wpath.size() >= 260 && wpath.rfind(L"\\\\?\\", 0) != 0)
                    {
                        if (wpath.size() >= 2 && wpath[1] == L':')
                        {
                            wpath = L"\\\\?\\" + wpath;
                        }
                        else if (wpath.rfind(L"\\\\", 0) == 0)
                        {
                            wpath = L"\\\\?\\UNC\\" + wpath.substr(2);
                        }
                        else
                        {
                            wchar_t absBuf[32767];
                            DWORD len = ::GetFullPathNameW(wpath.c_str(), 32767, absBuf, nullptr);

                            if (0 != len && len < 32767)
                            {
                                wpath.assign(absBuf, len);

                                if (wpath.rfind(L"\\\\?\\", 0) != 0)
                                {
                                    if (wpath.size() >= 2 && wpath[1] == L':')
                                    {
                                        wpath = L"\\\\?\\" + wpath;
                                    }
                                    else if (wpath.rfind(L"\\\\", 0) == 0)
                                    {
                                        wpath = L"\\\\?\\UNC\\" + wpath.substr(2);
                                    }
                                }
                            }
                        }
                    }

                    FILE* f = nullptr;

                    if (0 == ::_wfopen_s(&f, wpath.c_str(), L"rb") && nullptr != f)
                    {
                        ::fseek(f, 0, SEEK_END);
                        long sz = ::ftell(f);
                        ::fseek(f, 0, SEEK_SET);

                        if (sz >= 0)
                        {
                            constexpr long kConfigCap = static_cast<long>(limits::kMaxConfigBytes);
                            if (sz > kConfigCap)
                            {
                                error = "config too large";
                                ::fclose(f);
                                return std::nullopt;
                            }
                            raw.resize(static_cast<size_t>(sz));
                            size_t got = ::fread(raw.data(), 1, raw.size(), f);
                            raw.resize(got);
                            raw_ok = true;
                        }

                        ::fclose(f);
                    }
                }
            }

            if (raw_ok)
            {
                try
                {
                    root = json::parse(raw);
                }
                catch (const std::exception& ex)
                {
                    error = std::string("JSON parse failed: ") + ex.what();
                    return std::nullopt;
                }
            }
            else
            {
                std::ifstream stream(path, std::ios::binary | std::ios::ate);

                if (!stream)
                {
                    error = "cannot open config file: " + path;
                    return std::nullopt;
                }

                auto sz = stream.tellg();
                constexpr std::streamoff kConfigCap2 = static_cast<std::streamoff>(limits::kMaxConfigBytes);
                if (sz > kConfigCap2)
                {
                    error = "config too large";
                    return std::nullopt;
                }
                stream.seekg(0, std::ios::beg);

                try
                {
                    stream >> root;
                }
                catch (const std::exception& ex)
                {
                    error = std::string("JSON parse failed: ") + ex.what();
                    return std::nullopt;
                }
            }
#else
            std::ifstream stream(path, std::ios::binary | std::ios::ate);

            if (!stream)
            {
                error = "cannot open config file: " + path;
                return std::nullopt;
            }

            {
                auto sz = stream.tellg();
                constexpr std::streamoff kConfigCap3 = static_cast<std::streamoff>(limits::kMaxConfigBytes);
                if (sz > kConfigCap3)
                {
                    error = "config too large";
                    return std::nullopt;
                }
                stream.seekg(0, std::ios::beg);
            }

            try
            {
                stream >> root;
            }
            catch (const std::exception& ex)
            {
                error = std::string("JSON parse failed: ") + ex.what();
                return std::nullopt;
            }
#endif
            if (!root.is_object()) {
                error = "config root must be a JSON object";
                return std::nullopt;
            }

            Config config;
            try {
                if (const auto e = root.find("adapter"); e != root.end()) {
                    // batch34l: a present "adapter" must be a string. A number
                    // or object here is a typo; silently ignoring it would
                    // start the process on a different NIC than the file says.
                    if (!RequireString(*e, "adapter", config.adapter, error)) {
                        return std::nullopt;
                    }
                    if (config.adapter.size() > limits::kMaxAdapterBytes) {
                        error = "adapter name too long";
                        return std::nullopt;
                    }
                }
                // batch19 R4-P4: optional persisted UI language (unknown codes
                // fall back to zh-CN at apply time; only the length is bounded).
                if (const auto e = root.find("ui_language");
                    e != root.end()) {
                    if (!RequireString(*e, "ui_language", config.ui_language,
                                       error)) {
                        return std::nullopt;
                    }
                    if (config.ui_language.size() > 64) {
                        error = "ui_language too long";
                        return std::nullopt;
                    }
                }
                // batch20: UI scale override ("auto" or a 25-step percent
                // 100..500). An out-of-set STRING value falls back to "auto"
                // (documented: the desktop DPI remains a sane default), but a
                // non-string value is a typo and is rejected.
                if (const auto e = root.find("ui_scale"); e != root.end()) {
                    std::string raw_scale;
                    if (!RequireString(*e, "ui_scale", raw_scale, error)) {
                        return std::nullopt;
                    }
                    config.ui_scale = IsValidUiScaleValue(raw_scale) ? raw_scale : "auto";
                }
                // batch22 A1: appearance ("dark" default keeps the historical
                // look; "light"; "auto" follows Windows AppsUseLightTheme).
                // Same rule as ui_scale: a bad string normalises, a non-string
                // value is rejected.
                if (const auto e = root.find("theme"); e != root.end()) {
                    std::string raw_theme;
                    if (!RequireString(*e, "theme", raw_theme, error)) {
                        return std::nullopt;
                    }
                    config.theme = IsValidThemeValue(raw_theme) ? raw_theme : "dark";
                }
                ParseGateway(root, config, error);
                if (!error.empty()) {
                    return std::nullopt;
                }
                ParseMode(root, config, error);
                if (!error.empty()) {
                    return std::nullopt;
                }
                ParseDhcp(root, config, error);
                if (!error.empty()) {
                    return std::nullopt;
                }
                ParseIpv6(root, config, error);
                if (!error.empty()) {
                    return std::nullopt;
                }
                ParsePerf(root, config, error);
                if (!error.empty()) {
                    return std::nullopt;
                }
                ParseWeb(root, config, error);
                if (!error.empty()) {
                    return std::nullopt;
                }
                ParseVlan(root, config, error);
                if (!error.empty()) {
                    return std::nullopt;
                }
                ParseBridge(root, config, error);
                if (!error.empty()) {
                    return std::nullopt;
                }
            } catch (const std::exception& ex) {
                // Missing keys via at(), wrong types via get<T>() - both throw.
                error = std::string("config structure invalid: ") + ex.what();
                return std::nullopt;
            }

            if (!ValidateConfig(config, error)) {
                return std::nullopt;
            }
            return config;
        }

        bool Config::ApplyCliOverrides(const std::vector<std::string>& args,
                                       std::string& error) {
            for (size_t i = 0; i < args.size(); ++i) {
                const std::string& arg = args[i];
                static constexpr char kAdapter[] = "--adapter=";
                static constexpr char kConfig[] = "--config=";

                if (arg.rfind(kAdapter, 0) == 0) {
                    // batch106: main applies these overrides AFTER the only
                    // load-time validation (main.cpp: LoadFromFile validates,
                    // then ApplyCliOverrides). Assigning the raw flag value
                    // therefore produced a running Config that ValidateConfig
                    // rejects and the loader refuses on the next start -
                    // "--adapter=<300 chars>" saved fine and then failed with
                    // "adapter name too long". Every other entry point (JSON
                    // loader, UI draft) bounds this value; refuse it here too
                    // so the error names the flag the operator typed.
                    const std::string value = arg.substr(sizeof(kAdapter) - 1);
                    if (value.size() > limits::kMaxAdapterBytes) {
                        error = "adapter name too long (--adapter is limited "
                                "to 256 bytes)";
                        return false;
                    }
                    adapter = value;
                } else if (arg.rfind(kConfig, 0) == 0) {
                    // Consumed by the caller before LoadFromFile; ignore here.
                } else if ("--config" == arg) {
                    // Accept "--config path" form; consume the following value.
                    if (i + 1 < args.size()) {
                        const std::string& nxt = args[i + 1];
                        if (!nxt.empty() && nxt.rfind("--", 0) != 0) {
                            ++i;
                        }
                    }
                } else if (arg == "--web-only") {
                    // Management UI without the data plane; consumed by main.
                } else if (arg == "--web") {
                    // Enable the optional WebUI (HttpServer); consumed by main.
                } else if (arg == "--no-web") {
                    // Disable WebUI entirely (headless service); by main.
                } else if (arg == "--headless") {
                    // Run without the native UI (console stats loop);
                    // consumed by main (StartupOptions.headless).
                } else if (arg == "--console") {
                    // Keep console window in WINDOWS subsystem; consumed by main.
                } else if (arg == "--minimized") {
                    // Start minimized to tray (autostart); consumed by main.
                } else if (arg == "--ui-page" ||
                           arg.rfind("--ui-page=", 0) == 0) {
                    // S5.20: direct-page CLI flag. The value is parsed and
                    // consumed by main (StartupOptions.ui_page); accepted
                    // here so the argument is not rejected as unknown.
                } else if (arg == "--ui-debug-port" ||
                           arg.rfind("--ui-debug-port=", 0) == 0) {
                    // Task 7: UI debug channel. The value is parsed and
                    // consumed by main (StartupOptions.ui_debug_port);
                    // accepted here so the argument is not rejected as
                    // unknown.
                } else if (arg == "--version") {
                    // Handled by main before config load.
                } else if (arg == "--help") {
                    // Handled by main.
                } else {
                    error = "unknown argument: " + arg;
                    return false;
                }
            }

            return true;
        }

        namespace {

#ifdef _WIN32
            /// UTF-8 -> UTF-16 with the \\?\ long-path prefix for absolute
            /// paths >= MAX_PATH (mirrors the web_api.cpp atomic-write
            /// helper).
            std::wstring ToWideLongPath(const std::string& path) {
                const int wlen =
                    ::MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1,
                                          nullptr, 0);
                if (wlen <= 0) {
                    return std::wstring();
                }
                std::wstring wpath(static_cast<size_t>(wlen), L'\0');
                ::MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1,
                                      wpath.data(), wlen);
                wpath.pop_back();  // wlen included the terminator
                if (wpath.size() >= 260 && wpath.rfind(L"\\\\?\\", 0) != 0) {
                    if (wpath.size() >= 2 && wpath[1] == L':') {
                        wpath = L"\\\\?\\" + wpath;
                    } else if (wpath.rfind(L"\\\\", 0) == 0) {
                        wpath = L"\\\\?\\UNC\\" + wpath.substr(2);
                    } else {
                        wchar_t abs_buf[32767];
                        const DWORD len = ::GetFullPathNameW(
                            wpath.c_str(), 32767, abs_buf, nullptr);
                        if (0 != len && len < 32767) {
                            wpath.assign(abs_buf, len);
                            if (wpath.size() >= 2 && wpath[1] == L':') {
                                wpath = L"\\\\?\\" + wpath;
                            } else if (wpath.rfind(L"\\\\", 0) == 0) {
                                wpath = L"\\\\?\\UNC\\" + wpath.substr(2);
                            }
                        }
                    }
                }
                return wpath;
            }
#endif

            /// Bare lowercase hex (no separators) as the loader expects.
            std::string DuidHex(const std::vector<uint8_t>& duid) {
                static const char* kHex = "0123456789abcdef";
                std::string out;
                out.reserve(duid.size() * 2);
                for (const uint8_t b : duid) {
                    out.push_back(kHex[b >> 4]);
                    out.push_back(kHex[b & 0x0F]);
                }
                return out;
            }

        }  // namespace

        std::string Config::ToJsonString() const {
            json root;
            root["mode"] = (Mode::kMain == mode) ? "main" : "bypass";
            root["adapter"] = adapter;
            root["ui_language"] = ui_language;
                root["ui_scale"] = ui_scale;
                root["theme"] = theme;
            root["gateway"] = json{{"ipv4", FormatIpv4(gateway.ipv4)},
                                   {"mask", FormatIpv4(gateway.mask)},
                                   {"mac", FormatMac(gateway.mac)}};

            json dhcp_json;
            dhcp_json["enabled"] = dhcp.enabled;
            if (0 != dhcp.pool_start && 0 != dhcp.pool_end) {
                // 0.0.0.0 is never a valid config IP: a zero bound means the
                // pool is unset, so the key is omitted (the loader defaults
                // to zero).
                dhcp_json["pool"] = json::array(
                    {FormatIpv4(dhcp.pool_start), FormatIpv4(dhcp.pool_end)});
            }
            // P7: lease_hours is whole-hour on the wire; a non-multiple of
            // 3600 s would be silently truncated and would not survive a
            // ToJsonString -> load round-trip. Reject it at serialization
            // rather than emitting a lossy value (ValidateConfig already
            // rejects such configs, but serialization must not depend on a
            // prior Validate call, and NDEBUG strips any assert).
            if (0u != (dhcp.lease_seconds % 3600u)) {
                throw std::invalid_argument(
                    "dhcp.lease_seconds must be a whole number of hours");
            }
            dhcp_json["lease_hours"] = dhcp.lease_seconds / 3600u;
            json dhcp_dns = json::array();
            for (const uint32_t ip : dhcp.dns) {
                dhcp_dns.push_back(FormatIpv4(ip));
            }
            dhcp_json["dns"] = std::move(dhcp_dns);
            json dhcp_bindings = json::array();
            for (const auto& binding : dhcp.static_bindings) {
                json entry = {{"mac", FormatMac(binding.mac)},
                              {"ip", FormatIpv4(binding.ip)}};
                if (!binding.hostname.empty()) {
                    entry["hostname"] = binding.hostname;
                }
                dhcp_bindings.push_back(std::move(entry));
            }
            dhcp_json["static_bindings"] = std::move(dhcp_bindings);
            root["dhcp"] = std::move(dhcp_json);

            json ipv6_json;
            ipv6_json["enabled"] = ipv6.enabled;
            // Full 8-group form (core::FormatIpv6); the parser accepts it and
            // the length comes from the separate prefix_len key.
            ipv6_json["ula_prefix"] = FormatIpv6(ipv6.ula_prefix);
            ipv6_json["prefix_len"] = ipv6.prefix_len;
            ipv6_json["ra_lifetime_s"] = ipv6.ra_lifetime_s;
            json ipv6_dns = json::array();
            for (const auto& addr : ipv6.dns) {
                ipv6_dns.push_back(FormatIpv6(addr));
            }
            ipv6_json["dns"] = std::move(ipv6_dns);
            json dhcpv6_json;
            dhcpv6_json["enabled"] = ipv6.dhcpv6.enabled;
            dhcpv6_json["pool_start"] =
                FormatIpv6(ipv6.dhcpv6.pool_start);
            dhcpv6_json["pool_end"] = FormatIpv6(ipv6.dhcpv6.pool_end);
            dhcpv6_json["lease_seconds"] = ipv6.dhcpv6.lease_seconds;
            json dhcpv6_bindings = json::array();
            for (const auto& binding : ipv6.dhcpv6.static_bindings) {
                json entry = {{"duid", DuidHex(binding.duid)},
                              {"ip", FormatIpv6(binding.ip)}};
                if (!binding.hostname.empty()) {
                    entry["hostname"] = binding.hostname;
                }
                dhcpv6_bindings.push_back(std::move(entry));
            }
            dhcpv6_json["static_bindings"] = std::move(dhcpv6_bindings);
            ipv6_json["dhcpv6"] = std::move(dhcpv6_json);
            root["ipv6"] = std::move(ipv6_json);

            root["perf"] = json{{"workers", perf.workers},
                                {"rx_batch", perf.rx_batch},
                                {"max_conns", perf.max_conns},
                                {"udp_flow_cap", perf.udp_flow_cap},
                                {"ring_capacity", perf.ring_capacity},
                                {"dial_timeout_ms", perf.dial_timeout_ms},
                                {"rx_flush_eager", perf.rx_flush_eager},
                                {"rx_poll_ms", perf.rx_poll_ms}};
            root["web"] = json{{"enabled", web.enabled},
                               {"port", web.port},
                               {"bind", web.bind},
                               {"token", web.token}};
            if (0 != vlan.id) {
                // id 0 is a reserved 802.1Q codepoint the parser rejects;
                // omitting the section means "disabled" on reload.
                root["vlan"] = json{{"id", vlan.id}};
            }
            root["bridge"] = json{{"enabled", bridge.enabled},
                                  {"upstream", bridge.upstream},
                                  {"downstream", bridge.downstream},
                                  {"mac_table_size", bridge.mac_table_size}};
            return root.dump();
        }

        std::string Config::MakeUniqueSiblingPath(const std::string& path) {
            // U1 root-cause fix: ONE process-wide sequence shared by every
            // atomic config writer. A per-translation-unit function-local
            // static (as the earlier fix used) makes config.cpp's SaveToFile
            // and web_api.cpp's POST /api/config start at 0 independently and
            // generate the SAME `<path>.tmp.<pid>.0`, so the two writers can
            // truncate each other mid-write. Both callers route through this
            // single method, hence this single counter, hence globally unique
            // names.
            static std::atomic<std::uint64_t> tmp_seq{0};
            const std::uint64_t seq =
                tmp_seq.fetch_add(1, std::memory_order_relaxed);
#ifdef _WIN32
            return path + ".tmp." + std::to_string(::GetCurrentProcessId()) +
                   "." + std::to_string(seq);
#else
            (void)seq;
            return path + ".tmp";
#endif
        }

        bool Config::PublishConfigTempFile(const std::string& tmp,
                                           const std::string& path,
                                           std::string& error) {
#if defined(_WIN32)
            // batch80: unique temp names never covered the DESTINATION. Two
            // writers with distinct temp files still publish to the same path,
            // and Windows fails the loser of that overlap with
            // ERROR_ACCESS_DENIED (measured: 13/40 runs of the concurrent U1x
            // scenario failed here, always err=5). Retry the transient cases a
            // bounded number of times; a permanent error still fails after the
            // budget, and the temp file is always removed on failure.
            const std::wstring wtmp = ToWideLongPath(tmp);
            const std::wstring wpath = ToWideLongPath(path);
            if (wtmp.empty() || wpath.empty()) {
                error = "config path conversion failed";
                ::DeleteFileW(wtmp.c_str());
                return false;
            }
            // batch80: a fixed attempt count is a poor budget - measured
            // Sleep(0) yields run at ~39/ms, so even a "generous" eight
            // attempts covers only ~0.2 ms and loses to any real overlap.
            // Bound by TIME and escalate the pause instead: the loser of an
            // overlapping publish only waits for the winner's rename, but a
            // busy destination (an indexer, AV scanner, another writer) can
            // hold it for milliseconds. The first attempts yield immediately
            // (the common uncontended case never enters the loop at all), then
            // the pause grows so a long hold does not burn CPU.
            const auto publish_deadline = std::chrono::steady_clock::now() +
                                          std::chrono::milliseconds(200);
            DWORD last_error = ERROR_SUCCESS;
            for (int attempt = 0;; ++attempt) {
                if (::MoveFileExW(wtmp.c_str(), wpath.c_str(),
                                  MOVEFILE_REPLACE_EXISTING |
                                      MOVEFILE_WRITE_THROUGH)) {
                    return true;
                }
                last_error = ::GetLastError();
                const bool transient = ERROR_ACCESS_DENIED == last_error ||
                                       ERROR_SHARING_VIOLATION == last_error ||
                                       ERROR_LOCK_VIOLATION == last_error;
                if (!transient ||
                    std::chrono::steady_clock::now() >= publish_deadline) {
                    break;
                }
                ::Sleep(attempt < 4 ? 0 : 1);
            }
            error = "atomic replace failed: " + path +
                    " (error " + std::to_string(last_error) + ")";
            ::DeleteFileW(wtmp.c_str());
            return false;
#else
            (void)tmp;
            (void)path;
            error = "atomic replace requires Windows";
            return false;
#endif
        }

        bool Config::SaveToFile(const std::string& path,
                                std::string& error) const {
            error.clear();
            if (path.empty()) {
                error = "empty config path";
                return false;
            }
            const std::string data = ToJsonString();
#ifdef _WIN32
            // U1: unique temp name per write, shared process-wide with the
            // web worker's POST /api/config (see MakeUniqueSiblingPath); a
            // shared {config}.tmp would let one writer truncate the other
            // mid-write. The atomic rename below still publishes a complete
            // file.
            const std::string tmp = MakeUniqueSiblingPath(path);
            const std::wstring wtmp = ToWideLongPath(tmp);
            if (wtmp.empty()) {
                error = "config path conversion failed";
                return false;
            }
            FILE* f = nullptr;
            if (0 != ::_wfopen_s(&f, wtmp.c_str(), L"wb") || nullptr == f) {
                error = "cannot open temporary file: " + tmp;
                return false;
            }
            const size_t written = ::fwrite(data.data(), 1, data.size(), f);
            ::fflush(f);
            // Durability: fflush drains the CRT buffer only; FlushFileBuffers
            // pushes the tmp bytes to the volume BEFORE the atomic rename
            // publishes them (same discipline as web_api.cpp's writer).
            const intptr_t os_handle = ::_get_osfhandle(::_fileno(f));
            if (-1 != os_handle) {
                (void)::FlushFileBuffers(
                    reinterpret_cast<HANDLE>(os_handle));
            }
            const int close_ok = ::fclose(f);
            if (written != data.size() || 0 != close_ok) {
                ::DeleteFileW(wtmp.c_str());
                error = "short write to temporary file: " + tmp;
                return false;
            }
            if (!PublishConfigTempFile(tmp, path, error)) {
                return false;
            }
            return true;
#else
            error = "SaveToFile requires Windows";
            return false;
#endif
        }

        bool ParseMac(const std::string& text, MacAddress& out) noexcept {
            uint8_t byte = 0;
            size_t nibbles = 0;
            size_t bytes = 0;
            for (const char c : text) {
                int value = -1;
                if (c >= '0' && c <= '9') value = c - '0';
                else if (c >= 'a' && c <= 'f') value = c - 'a' + 10;
                else if (c >= 'A' && c <= 'F') value = c - 'A' + 10;
                else if (c == ':' || c == '-' || c == '.') continue;
                else return false;
                byte = static_cast<uint8_t>((byte << 4) | value);
                if (++nibbles == 2) {
                    if (bytes >= out.size()) return false;
                    out[bytes++] = byte;
                    byte = 0;
                    nibbles = 0;
                }
            }
            return nibbles == 0 && bytes == out.size();
        }

        std::string FormatMac(const MacAddress& mac) {
            static const char* kHex = "0123456789ABCDEF";
            std::string out;
            out.reserve(17);
            for (size_t i = 0; i < mac.size(); ++i) {
                if (i > 0) out.push_back(':');
                out.push_back(kHex[mac[i] >> 4]);
                out.push_back(kHex[mac[i] & 0x0F]);
            }
            return out;
        }

        uint32_t ParseIpv4(const std::string& text, bool& ok) noexcept {
            ok = false;
            uint32_t result = 0;
            int octets = 0;
            size_t pos = 0;
            while (pos <= text.size()) {
                const size_t dot = text.find('.', pos);
                const std::string part =
                    text.substr(pos, (std::string::npos == dot) ? std::string::npos : dot - pos);
                if (part.empty() || part.size() > 3) return 0;
                int value = 0;
                for (const char c : part) {
                    if (c < '0' || c > '9') return 0;
                    value = value * 10 + (c - '0');
                }
                if (value > 255) return 0;
                result = (result << 8) | static_cast<uint32_t>(value);
                ++octets;
                if (std::string::npos == dot) break;
                pos = dot + 1;
            }
            if (octets != 4) return 0;
            ok = true;
            // Host order accumulation -> network byte order result.
            uint32_t net = 0;
            net |= (result & 0xFF000000u) >> 24;
            net |= (result & 0x00FF0000u) >> 8;
            net |= (result & 0x0000FF00u) << 8;
            net |= (result & 0x000000FFu) << 24;
            return net;
        }

        std::string FormatIpv4(uint32_t ip) noexcept {
            // Convention: `ip` holds the address in NETWORK order, i.e. its
            // numeric value matches inet_addr(): first octet in the LOW byte.
            std::ostringstream out;
            out << (ip & 0xFF) << '.' << ((ip >> 8) & 0xFF) << '.'
                << ((ip >> 16) & 0xFF) << '.' << ((ip >> 24) & 0xFF);
            return out.str();
        }

        std::string FormatIpv6(const std::array<uint8_t, 16>& a) {
            static const char* kHex = "0123456789abcdef";
            std::string out;
            out.reserve(39);
            for (size_t g = 0; g < 8; ++g) {
                if (0 != g) {
                    out.push_back(':');
                }
                const uint16_t v = static_cast<uint16_t>(
                    (a[2 * g] << 8) | a[2 * g + 1]);
                for (int shift = 12; shift >= 0; shift -= 4) {
                    out.push_back(kHex[(v >> shift) & 0x0F]);
                }
            }
            return out;
        }

    }  // namespace core
}  // namespace vgww
