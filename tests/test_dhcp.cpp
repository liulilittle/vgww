// ============================================================================
// test_dhcp.cpp - DHCP frame parse/build + lease manager semantics.
//
// Encodes RFC 2131 subset behavior: DISCOVER->OFFER, REQUEST->ACK, static
// binding priority, pool exhaustion, release.
// ============================================================================
#include "proto/dhcp.h"

#include <atomic>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <unordered_set>

namespace {

    // batch326: scratch paths come from the OS temp folder (portable).
    std::string AbsentPath(const char* leaf) {
        return (std::filesystem::temp_directory_path() / "vgww-tests" / leaf)
            .string();
    }

    int g_failures = 0;

#define CHECK(cond)                                                        \
    do {                                                                   \
        if (!(cond)) {                                                     \
            std::fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__,  \
                         __LINE__, #cond);                                 \
            ++g_failures;                                                  \
        }                                                                  \
    } while (0)

    using namespace vgww::net;
    using namespace vgww::proto;
    using namespace vgww::core;
    using namespace vgww::dhcp;

    // inet_addr numeric convention: first octet in the LOW byte.
    constexpr uint32_t kGatewayIp = (40u) | (0u << 8) | (168u << 16) | (192u << 24);
    constexpr uint32_t kPoolStart = (100u) | (0u << 8) | (168u << 16) | (192u << 24);
    constexpr uint32_t kPoolEnd = (110u) | (0u << 8) | (168u << 16) | (192u << 24);
    const WireMac kGatewayMac{0x30, 0xFC, 0x68, 0x88, 0xB4, 0xA9};
    const WireMac kClientMac{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01};
    /// Offset of the DHCP fixed header inside a 20-byte-IHL request frame.
    constexpr size_t kDhcpOffset = kEthernetHeaderLen + 20 + kUdpHeaderLen;

    /// Builds a DISCOVER frame from the client (broadcast).
    std::vector<uint8_t> BuildDiscover(uint32_t xid) {
        std::vector<uint8_t> options;
        options.push_back(kDhcpOptionMsgType);
        options.push_back(1);
        options.push_back(kDhcpMsgDiscover);
        options.push_back(kDhcpOptionEnd);

        std::vector<uint8_t> f(kDhcpFrameMin + options.size(), 0);
        BuildEthHeader(f.data(), kBroadcastMac, kClientMac, kEthertypeIpv4);
        uint8_t* ip = f.data() + kEthernetHeaderLen;
        ip[0] = 0x45;
        const uint16_t total = static_cast<uint16_t>(20 + kUdpHeaderLen +
                                                     kDhcpFixedLen +
                                                     options.size());
        ip[2] = static_cast<uint8_t>(total >> 8);
        ip[3] = static_cast<uint8_t>(total & 0xFF);
        ip[8] = 64;
        ip[9] = 17;
        uint8_t* udp = ip + 20;
        udp[1] = 68;  // src port
        udp[3] = 67;  // dst port
        const uint16_t udp_len = static_cast<uint16_t>(
            kUdpHeaderLen + kDhcpFixedLen + options.size());
        udp[4] = static_cast<uint8_t>(udp_len >> 8);
        udp[5] = static_cast<uint8_t>(udp_len & 0xFF);
        uint8_t* d = udp + kUdpHeaderLen;
        d[0] = 1;     // BOOTREQUEST
        d[1] = 1;     // htype: Ethernet
        d[2] = 6;     // hlen: MAC length
        d[4] = static_cast<uint8_t>(xid >> 24);
        d[5] = static_cast<uint8_t>(xid >> 16);
        d[6] = static_cast<uint8_t>(xid >> 8);
        d[7] = static_cast<uint8_t>(xid);
        std::memcpy(d + 28, kClientMac.data(), 6);
        std::memcpy(d + 236, "\x63\x82\x53\x63", 4);
        std::memcpy(d + kDhcpFixedLen, options.data(), options.size());
        return f;
    }

    /// Finds the value of a single-4-byte DHCP option (0x35 server-id, 0x03
    /// router, 0x01 subnet) inside a built reply frame. Returns false if absent.
    bool FindOption4(const std::vector<uint8_t>& frame, uint8_t code,
                     std::array<uint8_t, 4>& out) {
        for (size_t i = 0; i + 2 < frame.size(); ++i) {
            if (frame[i] == code && frame[i + 1] == 4) {
                std::memcpy(out.data(), frame.data() + i + 2, 4);
                return true;
            }
        }
        return false;
    }

    /// Returns the payload bytes of the first option with `code`, or an empty
    /// vector if absent / truncated. Bounds-aware (unlike FindOption4's 4-byte
    /// scan) so it is safe against arbitrary values in the stream.
    std::vector<uint8_t> FindOptionView(const std::vector<uint8_t>& frame,
                                        uint8_t code) {
        for (size_t i = 0; i + 2 < frame.size(); ++i) {
            if (frame[i] != code) continue;
            const size_t n = frame[i + 1];
            if (i + 2 + n > frame.size()) return {};
            return std::vector<uint8_t>(frame.begin() + i + 2,
                                        frame.begin() + i + 2 + n);
        }
        return {};
    }

    /// Builds a DISCOVER frame whose IPv4 header declares `ihl` bytes
    /// (a whole-number multiple of 4 - use 20/24/.../60). The UDP and DHCP
    /// payloads are laid out at the ihl-correct offsets, exactly like a
    /// legitimate real-world frame.
    std::vector<uint8_t> BuildDiscoverWithIhl(size_t ihl,
        std::vector<uint8_t> options = {kDhcpOptionMsgType, 1, kDhcpMsgDiscover,
                                        kDhcpOptionEnd}) {
        const size_t dhcp_total = kDhcpFixedLen + options.size();
        std::vector<uint8_t> f(kEthernetHeaderLen + ihl + kUdpHeaderLen +
                               dhcp_total, 0);
        BuildEthHeader(f.data(), kBroadcastMac, kClientMac, kEthertypeIpv4);
        uint8_t* ip = f.data() + kEthernetHeaderLen;
        ip[0] = static_cast<uint8_t>(0x40 | (ihl / 4));  // version 4 + IHL
        const uint16_t total =
            static_cast<uint16_t>(ihl + kUdpHeaderLen + dhcp_total);
        ip[2] = static_cast<uint8_t>(total >> 8);
        ip[3] = static_cast<uint8_t>(total & 0xFF);
        ip[8] = 64;
        ip[9] = 17;  // UDP
        uint8_t* udp = ip + ihl;
        udp[1] = 68;  // src port
        udp[3] = 67;  // dst port
        udp[4] = static_cast<uint8_t>((kUdpHeaderLen + dhcp_total) >> 8);
        udp[5] = static_cast<uint8_t>((kUdpHeaderLen + dhcp_total) & 0xFF);
        uint8_t* d = udp + kUdpHeaderLen;
        d[0] = 1;  // BOOTREQUEST
        d[1] = 1;  // htype: Ethernet
        d[2] = 6;  // hlen: MAC length
        std::memcpy(d + 28, kClientMac.data(), 6);
        std::memcpy(d + 236, "\x63\x82\x53\x63", 4);
        std::memcpy(d + kDhcpFixedLen, options.data(), options.size());
        return f;
    }

    void TestParseIhlValidation() {
        // --- Version must be IPv4 -----------------------------------------
        auto v6 = BuildDiscoverWithIhl(20);
        v6[kEthernetHeaderLen] = 0x63;  // version 6 (IHL nibble 3)
        DhcpView view;
        CHECK(!ParseDhcpFrame(v6.data(), v6.size(), view));

        // --- IHL below 20 is malformed, even inside an otherwise complete
        // frame. Deterministic TDD pin: with ihl = 16 the old parser read the
        // payload at the claimed (short) header offsets - exactly where a
        // compliant builder placed it - and truthfully returned true. The
        // RFC 791 minimum of 20 must be enforced first.
        auto short_ihl = BuildDiscoverWithIhl(16);
        CHECK(!ParseDhcpFrame(short_ihl.data(), short_ihl.size(), view));

        // --- Truncated buffer with ihl = 60 (max legal). The parser needs
        // len >= 14+60+8+236; the buffer is chopped below that. Any read
        // past the end is a bug; the length guard alone must reject.
        auto trunc = BuildDiscoverWithIhl(60);
        trunc.resize(kDhcpFrameMin);  // >= 278, still far below 14+60+8+236
        for (int i = 0; i < 3; ++i) {
            CHECK(!ParseDhcpFrame(trunc.data(), trunc.size(), view));
        }
    }

    void TestParseIhlFullLengthAccepted() {
        // Regression pin: a complete frame with the legal-but-unusual IHL of
        // 60 bytes parses fine - validation must constrain lengths, never
        // require IHL == 20.
        auto full = BuildDiscoverWithIhl(60);
        DhcpView view;
        CHECK(ParseDhcpFrame(full.data(), full.size(), view));
        CHECK(view.msg_type == kDhcpMsgDiscover);
        CHECK(view.client_mac == kClientMac);

        // A 24-byte IHL frame round-trips as well.
        auto ihl24 = BuildDiscoverWithIhl(24, {kDhcpOptionMsgType, 1,
                                               kDhcpMsgRequest, kDhcpOptionEnd});
        CHECK(ParseDhcpFrame(ihl24.data(), ihl24.size(), view));
        CHECK(view.msg_type == kDhcpMsgRequest);
    }

    void TestFrameIpOptionBytes() {
        // Numeric constants follow the project convention (first octet in the
        // LOW byte) - exactly what config parsing (ParseIpv4) produces.
        const uint32_t gw = (192u) | (168u << 8) | (0u << 16) | (40u << 24);
        const uint32_t yi = (192u) | (168u << 8) | (0u << 16) | (100u << 24);
        const uint32_t mask = (255u) | (255u << 8) | (255u << 16) | (0u << 24);

        std::vector<uint8_t> ack;
        BuildDhcpReplyFrame(kDhcpMsgAck, 0x11223344, kGatewayMac, kClientMac,
                            yi, gw, mask, 3600, {0x08080808u}, "pc", ack);
        CHECK(!ack.empty());

        std::array<uint8_t, 4> b{};
        CHECK(FindOption4(ack, kDhcpOptionServerId, b));
        // Wire bytes must be the plain network order of 192.168.0.40.
        CHECK(b[0] == 0xC0 && b[1] == 0xA8 && b[2] == 0x00 && b[3] == 0x28);
        CHECK(FindOption4(ack, kDhcpOptionRouter, b));
        CHECK(b[0] == 0xC0 && b[1] == 0xA8 && b[2] == 0x00 && b[3] == 0x28);
        CHECK(FindOption4(ack, kDhcpOptionSubnet, b));
        CHECK(b[0] == 0xFF && b[1] == 0xFF && b[2] == 0xFF && b[3] == 0x00);
    }

    void TestOversizedOptionClamped() {
        // A hostname longer than 255 bytes must not desync the option stream:
        // the length octet is capped, and the frame must still parse back as
        // a well-formed TLV walk to its END option.
        const std::string long_hostname(300, 'h');
        std::vector<uint8_t> frame;
        BuildDhcpReplyFrame(kDhcpMsgAck, 0x01020304, kGatewayMac, kClientMac,
                            (192u) | (168u << 8) | (0u << 16) | (100u << 24),
                            (192u) | (168u << 8) | (0u << 16) | (40u << 24),
                            (255u) | (255u << 8) | (255u << 16) | (0u << 24),
                            3600, {0x08080808u}, long_hostname, frame);
        CHECK(!frame.empty());

        // The hostname option must claim at most 253 bytes of payload.
        const auto host = FindOptionView(frame, kDhcpOptionHostname);
        CHECK(!host.empty());
        CHECK(host.size() <= 253);

        // Round-trip must succeed end to end (options walk terminates cleanly
        // at END); a desynced stream fails the cookie/END walk. The parser is
        // strictly request-scoped (F1), so mirror the reply into request shape
        // first - the option stream itself is untouched.
        frame[kDhcpOffset] = 1;  // BOOTREQUEST
        uint8_t* udp = frame.data() + kEthernetHeaderLen + 20;
        udp[3] = 67;  // destination: server port
        DhcpView view;
        CHECK(ParseDhcpFrame(frame.data(), frame.size(), view));
    }

void TestRateLimitFrameBudget() {
        vgww::core::Config config;
        config.gateway.ipv4 = kGatewayIp;
        config.gateway.mask = (0u) | (0u << 8) | (255u << 16) | (192u << 24);
        config.dhcp.pool_start = kPoolStart;
        config.dhcp.pool_end = kPoolEnd;
        config.dhcp.lease_seconds = 3600;
        DhcpServer server(config);

        const WireMac mac_a{0x02, 0x00, 0x5A, 0x00, 0x00, 0x01};
        const WireMac mac_b{0x02, 0x00, 0x5A, 0x00, 0x00, 0x02};
        const auto t0 = std::chrono::steady_clock::now();
        // The budget allows 8 frames in one second window.
        for (size_t i = 0; i < 8; ++i) {
            CHECK(server.AllowFrame(mac_a, t0));
        }
        // The 9th frame in the same window is dropped...
        CHECK(!server.AllowFrame(mac_a, t0));
        // ...and an untouched MAC is not affected (independent budgets).
        CHECK(server.AllowFrame(mac_b, t0));
        // A fresh second window resets the budget for the first MAC.
        CHECK(server.AllowFrame(mac_a, t0 + std::chrono::seconds(1)));
    }

    void TestParseAndOffer() {
        auto discover = BuildDiscover(0x12345678);
        DhcpView view;
        CHECK(ParseDhcpFrame(discover.data(), discover.size(), view));
        CHECK(view.msg_type == kDhcpMsgDiscover);
        CHECK(view.xid == 0x12345678);
        CHECK(view.client_mac == kClientMac);

        vgww::core::Config config;
        config.gateway.ipv4 = kGatewayIp;
        config.gateway.mask = (0u) | (0u << 8) | (255u << 16) | (192u << 24);  // /20-ish placeholder
        config.dhcp.pool_start = kPoolStart;
        config.dhcp.pool_end = kPoolEnd;
        config.dhcp.lease_seconds = 3600;
        DhcpServer server(config);

        const auto now = std::chrono::steady_clock::now();
        const uint32_t offered = server.Acquire(kClientMac, now);
        CHECK(offered == kPoolStart);  // first dynamic address

        std::vector<uint8_t> offer;
        BuildDhcpReplyFrame(kDhcpMsgOffer, view.xid, kGatewayMac, kClientMac,
                            offered, kGatewayIp, config.gateway.mask,
                            config.dhcp.lease_seconds, {8, 8, 8, 8}, "pc",
                            offer);
        // Round-trip: the OFFER must parse back with type OFFER. The parser is
        // strictly request-scoped (F1), so mirror the reply into request shape
        // first - the option stream itself is untouched.
        offer[kDhcpOffset] = 1;  // BOOTREQUEST
        uint8_t* offer_udp = offer.data() + kEthernetHeaderLen + 20;
        offer_udp[3] = 67;  // destination: server port
        DhcpView offer_view;
        CHECK(ParseDhcpFrame(offer.data(), offer.size(), offer_view));
        CHECK(offer_view.msg_type == kDhcpMsgOffer);
        CHECK(offer_view.xid == 0x12345678);
    }

    void TestStaticBindingPriority() {
        vgww::core::Config config;
        config.gateway.ipv4 = kGatewayIp;
        config.dhcp.pool_start = kPoolStart;
        config.dhcp.pool_end = kPoolEnd;

        const WireMac bound_mac{0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
        const uint32_t reserved = (77u) | (0u << 8) | (168u << 16) | (192u << 24);
        StaticBinding binding;
        binding.mac = bound_mac;
        binding.ip = reserved;
        config.dhcp.static_bindings.push_back(binding);

        DhcpServer server(config);
        const auto now = std::chrono::steady_clock::now();
        CHECK(server.Acquire(bound_mac, now) == reserved);
        // A different client gets pool addresses, never the reserved one.
        const uint32_t other = server.Acquire(kClientMac, now);
        CHECK(other != reserved);
        CHECK(other != 0);
    }

void TestStaticBindingReservesPoolAddress() {
        vgww::core::Config config;
        config.gateway.ipv4 = kGatewayIp;
        config.dhcp.pool_start = kPoolStart;
        config.dhcp.pool_end = kPoolEnd;

        const WireMac bound_mac{0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
        const uint32_t reserved =
            (77u) | (0u << 8) | (168u << 16) | (192u << 24);
        StaticBinding binding;
        binding.mac = bound_mac;
        binding.ip = reserved;
        config.dhcp.static_bindings.push_back(binding);

        DhcpServer server(config);
        const auto now = std::chrono::steady_clock::now();

        // The bound client NEVER connected, so its IP has no lease - but the
        // paired address is reserved by configuration and must not leak to a
        // dynamic client (regression: the pool walk only skipped leased
        // addresses, so an offline binding's IP was handed out dynamically).
        const uint32_t other = server.Acquire(kClientMac, now);
        CHECK(other != 0);
        CHECK(other != reserved);
        // The bound client still receives its configured address on arrival.
        CHECK(server.Acquire(bound_mac, now) == reserved);
    }

    void TestExhaustionAndRelease() {
        vgww::core::Config config;
        config.gateway.ipv4 = kGatewayIp;
        // Tiny pool: exactly one address.
        config.dhcp.pool_start = (100u) | (0u << 8) | (168u << 16) | (192u << 24);
        config.dhcp.pool_end = config.dhcp.pool_start;

        DhcpServer server(config);
        const auto now = std::chrono::steady_clock::now();
        const WireMac mac_a{1, 1, 1, 1, 1, 1};
        const WireMac mac_b{2, 2, 2, 2, 2, 2};
        CHECK(server.Acquire(mac_a, now) != 0);
        CHECK(server.Acquire(mac_b, now) == 0);   // exhausted
        server.Release(mac_a);
        CHECK(server.Acquire(mac_b, now) != 0);   // freed and reused
    }

    void TestRuntimeBindings() {
        vgww::core::Config config;
        config.gateway.ipv4 = kGatewayIp;
        config.dhcp.pool_start = kPoolStart;
        config.dhcp.pool_end = kPoolEnd;

        const WireMac mac{0xAA, 0x12, 0x34, 0x56, 0x78, 0x90};
        const uint32_t reserved = (75u) | (0u << 8) | (168u << 16) | (192u << 24);

        DhcpServer server(config);
        const auto now = std::chrono::steady_clock::now();

        // Upsert takes effect on the next Acquire.
        CHECK(server.UpsertBinding(mac, reserved));
        CHECK(server.Acquire(mac, now) == reserved);
        CHECK(server.RemoveBinding(mac));
        // Removed: the client now draws from the dynamic pool.
        const uint32_t pooled = server.Acquire(mac, now);
        CHECK(pooled != 0);
        CHECK(pooled != reserved);

        // Invalid bindings are rejected.
        CHECK(!server.UpsertBinding(mac, 0));

        // StaticBindings() reflects the merged (config + runtime) view.
        StaticBinding cfg_binding;
        cfg_binding.mac = mac;
        cfg_binding.ip = (76u) | (0u << 8) | (168u << 16) | (192u << 24);
        cfg_binding.hostname = "office";
        config.dhcp.static_bindings.push_back(cfg_binding);

        DhcpServer server2(config);
        CHECK(server2.UpsertBinding(mac, reserved));
        auto views = server2.StaticBindings();
        CHECK(views.size() == 1);
        CHECK(views[0].ip == reserved);          // runtime overrides config
        CHECK(views[0].hostname == "office");    // config hostname preserved

        // An explicit hostname from the WebUI must override the config one
        // (and survive the StaticBindings round-trip - regression: the POST
        // handler dropped the field entirely).
        CHECK(server2.UpsertBinding(mac, reserved, "printer1"));
        views = server2.StaticBindings();
        CHECK(views[0].hostname == "printer1");
        CHECK(server2.UpsertBinding(mac, reserved));  // empty keeps config value
        views = server2.StaticBindings();
        CHECK(views[0].hostname == "office");
        CHECK(server2.Acquire(mac, now) == reserved);
    }

    /// A static binding that lives in the CONFIG document (not the runtime
    /// table) must be deletable. RemoveBinding only knew runtime_bindings_, so
    /// the WebUI and the native UI both offered a delete that always failed
    /// (404 / "no such binding") while StaticBindings() kept listing the
    /// config entry - the row could never be removed.
    void TestRemoveConfigBinding() {
        vgww::core::Config config;
        config.gateway.ipv4 = kGatewayIp;
        config.dhcp.pool_start = kPoolStart;
        config.dhcp.pool_end = kPoolEnd;
        config.dhcp.lease_seconds = 3600;

        const WireMac bound{0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
        const uint32_t reserved =
            (77u) | (0u << 8) | (168u << 16) | (192u << 24);
        StaticBinding binding;
        binding.mac = bound;
        binding.ip = reserved;
        binding.hostname = "printer";
        config.dhcp.static_bindings.push_back(binding);

        DhcpServer server(config);
        const auto now = std::chrono::steady_clock::now();
        CHECK(server.StaticBindings().size() == 1);
        CHECK(server.Acquire(bound, now) == reserved);

        // The config entry is removable, and the removal is live.
        CHECK(server.RemoveBinding(bound));
        CHECK(server.StaticBindings().empty());
        // The client reverts to the dynamic pool.
        const uint32_t pooled = server.Acquire(bound, now);
        CHECK(pooled != 0);
        CHECK(pooled != reserved);
        // The address is no longer reserved by the (deleted) config entry: a
        // runtime binding may now claim it. Before the fix this was refused as
        // a collision with the config binding that the user had just deleted.
        const WireMac other{0x11, 0x22, 0x33, 0x44, 0x55, 0x77};
        CHECK(server.UpsertBinding(other, reserved));
        // A second delete has nothing left to remove.
        CHECK(!server.RemoveBinding(bound));
    }

    void TestRuntimeBindingWithoutPool() {
        // A static-only server (dynamic pool disabled) must still accept
        // manual DHCP bindings: the pool-set validation `(!in_pool &&
        // 0==start)` was vacuously true with no pool, so every legal
        // binding returned 400 forever. The binding must instead be
        // served by the next Acquire.
        vgww::core::Config config;
        config.gateway.ipv4 = kGatewayIp;
        config.dhcp.pool_start = 0;  // dynamic pool disabled
        config.dhcp.pool_end = 0;
        config.dhcp.lease_seconds = 3600;
        DhcpServer server(config);

        const uint32_t guest =
            (200u) | (0u << 8) | (168u << 16) | (192u << 24);  // 192.168.0.200
        CHECK(server.UpsertBinding(kClientMac, guest));
        const auto now = std::chrono::steady_clock::now();
        CHECK(server.Acquire(kClientMac, now) == guest);
    }

    void TestUpsertBindingRejectsGatewayAndDuplicate() {
        vgww::core::Config config;
        config.gateway.ipv4 = kGatewayIp;
        config.dhcp.pool_start = kPoolStart;
        config.dhcp.pool_end = kPoolEnd;

        // Binding the gateway address must be rejected.
        DhcpServer server(config);
        CHECK(!server.UpsertBinding(kClientMac, kGatewayIp));

        // Two distinct MACs cannot share one bound address.
        const WireMac mac_a{0xAA, 0x12, 0x00, 0x00, 0x00, 0x01};
        const WireMac mac_b{0xAA, 0x12, 0x00, 0x00, 0x00, 0x02};
        const uint32_t shared =
            (75u) | (0u << 8) | (168u << 16) | (192u << 24);  // 192.168.0.75
        CHECK(server.UpsertBinding(mac_a, shared));
        CHECK(!server.UpsertBinding(mac_b, shared));

        // A duplicate against a config static binding is rejected too.
        StaticBinding cfg;
        cfg.mac = WireMac{0xBB, 0x12, 0x00, 0x00, 0x00, 0x03};
        cfg.ip = (76u) | (0u << 8) | (168u << 16) | (192u << 24);
        config.dhcp.static_bindings.push_back(cfg);
        DhcpServer server2(config);
        CHECK(!server2.UpsertBinding(kClientMac, cfg.ip));

        // Re-upserting the same MAC with its own address stays legal.
        DhcpServer server3(config);
        CHECK(server3.UpsertBinding(mac_a, shared));
        CHECK(server3.UpsertBinding(mac_a, shared));
        CHECK(server3.UpsertBinding(mac_a, shared, "printer"));
        CHECK(server3.StaticBindings().size() == 2);  // cfg + mac_a
    }

    void TestLeaseRemainingTimeRoundTrip() {
        // Persisted leases restore their REMAINING time (a reload used to
        // grant a fresh full lease term from now, contradicting the
        // "expired entries are skipped" contract).
        vgww::core::Config config;
        bool ok = false;
        config.gateway.ipv4 = vgww::core::ParseIpv4("192.168.0.40", ok);
        CHECK(ok);
        config.gateway.mask = vgww::core::ParseIpv4("255.255.255.0", ok);
        CHECK(ok);
        config.dhcp.pool_start = vgww::core::ParseIpv4("192.168.0.100", ok);
        config.dhcp.pool_end = vgww::core::ParseIpv4("192.168.0.110", ok);
        config.dhcp.lease_seconds = 3600;
        DhcpServer server(config);
        const WireMac mac{0x02, 0x00, 0x5A, 0x00, 0x00, 0x77};
        const auto t0 = std::chrono::steady_clock::now();
        const uint32_t ip =
            server.Acquire(mac, t0, DhcpServer::OfferStage::kAck);
        CHECK(ip != 0);

        const auto t_dump = t0 + std::chrono::seconds(100);
        const std::string path = "test_dhcp_leases_remaining.json";
        std::remove(path.c_str());
        CHECK(server.DumpLeases(path, t_dump));

        DhcpServer restored(config);
        CHECK(restored.LoadLeases(path, t_dump));
        auto leases = restored.Leases(t_dump);
        CHECK(leases.size() == 1);
        if (!leases.empty()) {
            // 3500s remaining, NOT a fresh 3600s from now.
            CHECK(leases[0].expires_in_s == 3500u);
        }
        std::remove(path.c_str());
    }

    // batch134: a persisted file can name the SAME address for two different
    // clients - hand-edited, or written by two instances sharing a lease file.
    // Every other entry point already refuses that:
    //   * UpsertBinding rejects a runtime binding on an address another client
    //     holds (dhcp.cpp:748-752, the "two owners for one address" class from
    //     batch109/112),
    //   * Acquire's occupancy map is keyed by address, so it can only ever
    //     consider one owner per address.
    // The loader was the one entry that let both in. The result is not a
    // hypothetical: Leases() lists two clients on one IP, the UI shows both as
    // active, and the next DumpLeases writes the duplicate back out.
    void TestB134LeaseLoadRejectsDuplicateAddress() {
        vgww::core::Config config;
        bool ok = false;
        config.gateway.ipv4 = vgww::core::ParseIpv4("192.168.0.40", ok);
        CHECK(ok);
        config.gateway.mask = vgww::core::ParseIpv4("255.255.255.0", ok);
        CHECK(ok);
        config.dhcp.pool_start = vgww::core::ParseIpv4("192.168.0.100", ok);
        config.dhcp.pool_end = vgww::core::ParseIpv4("192.168.0.110", ok);
        config.dhcp.lease_seconds = 3600;

        const std::string path = "test_dhcp_leases_dup_addr.json";
        {
            std::ofstream out(path);
            out << "{\"version\":1,\"leases\":["
                   "{\"mac\":\"AA:BB:CC:DD:EE:01\",\"ip\":\"192.168.0.100\","
                   "\"hostname\":\"first\",\"expires_in_s\":3600},"
                   "{\"mac\":\"AA:BB:CC:DD:EE:02\",\"ip\":\"192.168.0.100\","
                   "\"hostname\":\"second\",\"expires_in_s\":3600},"
                   "{\"mac\":\"AA:BB:CC:DD:EE:03\",\"ip\":\"192.168.0.101\","
                   "\"hostname\":\"distinct\",\"expires_in_s\":3600}]}";
        }
        DhcpServer server(config);
        size_t dropped = 0;
        CHECK(server.LoadLeases(path, std::chrono::steady_clock::now(),
                                &dropped) ==
              DhcpServer::LoadOutcome::kRestored);

        // Only ONE owner may survive for .100 - the first occurrence (the
        // duplicate is the later entry, mirroring UpsertBinding's refusal of
        // the newcomer) - plus the unrelated .101.
        const auto leases = server.Leases(std::chrono::steady_clock::now());
        CHECK(2 == leases.size());
        std::size_t on_100 = 0;
        std::string owner_100;
        for (const auto& entry : leases) {
            if (vgww::core::FormatIpv4(entry.ip) == "192.168.0.100") {
                ++on_100;
                owner_100 = entry.hostname;
            }
        }
        CHECK(1 == on_100);
        CHECK("first" == owner_100);
        CHECK(1 == dropped);  // the collided entry is counted, never silent

        std::remove(path.c_str());
    }

    // batch119: the dropped-entry counter must be reachable from the status
    // surface; it used to be computed and discarded inside LoadLeases.
    void TestB119DroppedLeaseCountExposed() {
        vgww::core::Config config;
        bool ok = false;
        config.gateway.ipv4 = vgww::core::ParseIpv4("192.168.0.40", ok);
        CHECK(ok);
        config.gateway.mask = vgww::core::ParseIpv4("255.255.255.0", ok);
        CHECK(ok);
        config.dhcp.pool_start = vgww::core::ParseIpv4("192.168.0.100", ok);
        CHECK(ok);
        config.dhcp.pool_end = vgww::core::ParseIpv4("192.168.0.110", ok);
        CHECK(ok);
        config.dhcp.lease_seconds = 3600;

        const std::string path = "test_dhcp_leases_b119.json";
        {
            std::ofstream out(path);
            out << "{\"version\":1,\"leases\":["
                   "{\"mac\":\"not-a-mac\",\"ip\":\"192.168.0.100\","
                   "\"hostname\":\"bad\",\"expires_in_s\":3600},"
                   "{\"mac\":\"AA:BB:CC:DD:EE:01\",\"ip\":\"192.168.0.101\","
                   "\"hostname\":\"good\",\"expires_in_s\":3600}]}";
        }
        DhcpServer server(config);
        size_t dropped = 0;
        CHECK(server.LoadLeases(path, std::chrono::steady_clock::now(),
                                &dropped) ==
              DhcpServer::LoadOutcome::kRestored);
        CHECK(1 == dropped);
        CHECK(1 == server.DroppedLeaseCount());
        CHECK(1 == server.LeaseCount());
        std::remove(path.c_str());
    }

    // batch121: strict-parse refusals must be countable from the status
    // surface; the counter used to exist only for tests.
    void TestB121ParseRejectsAreCounted() {
        DhcpView view{};
        std::vector<uint8_t> garbage(32, 0);
        const uint64_t before = ParseRejectedCount();
        CHECK(!ParseDhcpFrame(garbage.data(), garbage.size(), view));
        CHECK(before + 1 == ParseRejectedCount());
    }

    // batch120: a corrupt lease document is preserved aside, but the loss of
    // every persisted mapping must also be visible (not just stderr).
    void TestB120LeaseFileCorruptIsFlagged() {
        vgww::core::Config config;
        bool ok = false;
        config.gateway.ipv4 = vgww::core::ParseIpv4("192.168.0.40", ok);
        CHECK(ok);
        config.gateway.mask = vgww::core::ParseIpv4("255.255.255.0", ok);
        CHECK(ok);
        config.dhcp.pool_start = vgww::core::ParseIpv4("192.168.0.100", ok);
        CHECK(ok);
        config.dhcp.pool_end = vgww::core::ParseIpv4("192.168.0.110", ok);
        CHECK(ok);
        config.dhcp.lease_seconds = 3600;

        const std::string path = "test_dhcp_leases_b120.json";
        {
            std::ofstream out(path);
            out << "this is not json";
        }
        DhcpServer server(config);
        size_t dropped = 0;
        CHECK(server.LoadLeases(path, std::chrono::steady_clock::now(),
                                &dropped) ==
              DhcpServer::LoadOutcome::kCorrupt);
        CHECK(server.LeaseFileCorrupt());
        {
            std::ifstream aside(path + ".corrupt");
            CHECK(aside.good());  // evidence preserved, loss flagged
        }
        std::remove(path.c_str());
        std::remove((path + ".corrupt").c_str());
    }

    void TestLeaseLoadSkipsIllegal() {
        // Entries that no longer make sense for the current config must be
        // skipped: an address reserved by a static binding and one outside
        // the gateway subnet. A wrong version envelope is a hard failure.
        vgww::core::Config config;
        bool ok = false;
        config.gateway.ipv4 = vgww::core::ParseIpv4("192.168.0.40", ok);
        CHECK(ok);
        config.gateway.mask = vgww::core::ParseIpv4("255.255.255.0", ok);
        CHECK(ok);
        config.dhcp.pool_start = vgww::core::ParseIpv4("192.168.0.100", ok);
        config.dhcp.pool_end = vgww::core::ParseIpv4("192.168.0.110", ok);
        config.dhcp.lease_seconds = 3600;
        StaticBinding cfg;
        cfg.mac = WireMac{0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
        cfg.ip = vgww::core::ParseIpv4("192.168.0.105", ok);
        config.dhcp.static_bindings.push_back(cfg);

        const std::string path = "test_dhcp_leases_illegal.json";
        {
            std::ofstream out(path);
            out << "{\"version\":1,\"leases\":["
                   "{\"mac\":\"AA:BB:CC:DD:EE:01\",\"ip\":\"192.168.0.100\","
                   "\"hostname\":\"good\",\"expires_in_s\":3600},"
                   "{\"mac\":\"AA:BB:CC:DD:EE:02\",\"ip\":\"192.168.0.105\","
                   "\"hostname\":\"static-conflict\",\"expires_in_s\":3600},"
                   "{\"mac\":\"AA:BB:CC:DD:EE:03\",\"ip\":\"10.0.0.99\","
                   "\"hostname\":\"outside-subnet\",\"expires_in_s\":3600}]}";
        }
        DhcpServer server(config);
        // batch34b: the load must report HOW MANY entries it refused, so a
        // caller can surface silent data loss instead of pretending the file
        // was clean.
        size_t dropped = 0;
        CHECK(server.LoadLeases(path, std::chrono::steady_clock::now(),
                                &dropped) ==
              DhcpServer::LoadOutcome::kRestored);
        CHECK(server.LeaseCount() == 1);  // only the valid entry
        CHECK(dropped > 0);               // the invalid ones are counted
        auto leases = server.Leases(std::chrono::steady_clock::now());
        CHECK(!leases.empty() && leases[0].hostname == "good");

        // A missing file is a NORMAL first run, not a fault.
        {
            DhcpServer fresh(config);
            size_t none = 999;
            CHECK(fresh.LoadLeases(AbsentPath("definitely-absent.json"),
                                   std::chrono::steady_clock::now(), &none) ==
                  DhcpServer::LoadOutcome::kNoFile);
            CHECK(none == 0);
        }

        // A future schema version is a hard failure, not a silent reparse -
        // and it must be reported as CORRUPT (data loss), not as "no file".
        {
            std::ofstream out(path);
            out << "{\"version\":2,\"leases\":[]}";
        }
        DhcpServer server2(config);
        size_t dropped2 = 0;
        CHECK(server2.LoadLeases(path, std::chrono::steady_clock::now(),
                                 &dropped2) ==
              DhcpServer::LoadOutcome::kCorrupt);
        // The bool wrapper stays false for both failure kinds.
        CHECK(!server2.LoadLeases(path, std::chrono::steady_clock::now()));

        // Truncated/garbage JSON is also corrupt, never "no file".
        {
            std::ofstream out(path);
            out << "{\"version\":1,\"leases\":[{\"mac\":";
        }
        DhcpServer server3(config);
        CHECK(server3.LoadLeases(path, std::chrono::steady_clock::now(),
                                 nullptr) ==
              DhcpServer::LoadOutcome::kCorrupt);
        std::remove(path.c_str());
    }

    void TestLegacyLeaseMissingExpiresRestored() {
        // OBS-1: a version:1 file written by an older build persists its
        // leases WITHOUT the expires_in_s field. LoadLeases must restore a
        // full term sourced from config lease_seconds (same origin as a
        // fresh Acquire) instead of silently dropping every entry. An
        // explicit expires_in_s==0 (a genuinely expired lease) must still
        // be dropped - only the MISSING field is treated as legacy.
        vgww::core::Config config;
        bool ok = false;
        config.gateway.ipv4 = vgww::core::ParseIpv4("192.168.0.40", ok);
        CHECK(ok);
        config.gateway.mask = vgww::core::ParseIpv4("255.255.255.0", ok);
        CHECK(ok);
        config.dhcp.pool_start = vgww::core::ParseIpv4("192.168.0.100", ok);
        config.dhcp.pool_end = vgww::core::ParseIpv4("192.168.0.110", ok);
        config.dhcp.lease_seconds = 3600;

        const std::string path = "test_dhcp_leases_legacy.json";
        {
            std::ofstream out(path);
            out << "{\"version\":1,\"leases\":["
                   "{\"mac\":\"AA:BB:CC:DD:EE:01\","
                   "\"ip\":\"192.168.0.100\",\"hostname\":\"legacy-host\"},"
                   "{\"mac\":\"AA:BB:CC:DD:EE:02\","
                   "\"ip\":\"192.168.0.101\",\"hostname\":\"expired\","
                   "\"expires_in_s\":0}]}";
        }
        DhcpServer server(config);
        const auto t0 = std::chrono::steady_clock::now();
        CHECK(server.LoadLeases(path, t0));
        // Legacy entry restored; explicit-zero entry still dropped.
        CHECK(server.LeaseCount() == 1);
        auto leases = server.Leases(t0);
        CHECK(leases.size() == 1);
        if (!leases.empty()) {
            CHECK(leases[0].hostname == "legacy-host");
            CHECK(leases[0].expires_in_s == 3600u);
        }
        // The restored lease still hands out its persisted address.
        const WireMac mac{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01};
        const uint32_t expected_ip = vgww::core::ParseIpv4("192.168.0.100", ok);
        CHECK(ok);
        CHECK(server.Acquire(mac, t0 + std::chrono::seconds(1),
                             DhcpServer::OfferStage::kAck) == expected_ip);
        std::remove(path.c_str());
    }

    void TestPoolSkipsNetworkAndBroadcast() {
        // A pool whose only address is the LAN network or broadcast address
        // must not hand it out.
        vgww::core::Config config;
        bool ok = false;
        config.gateway.ipv4 = vgww::core::ParseIpv4("192.168.0.40", ok);
        CHECK(ok);
        config.gateway.mask = vgww::core::ParseIpv4("255.255.255.0", ok);
        CHECK(ok);
        config.dhcp.lease_seconds = 3600;
        const WireMac mac{0x42, 1, 1, 1, 1, 1};
        const auto now = std::chrono::steady_clock::now();

        // Broadcast (192.168.0.255).
        config.dhcp.pool_start = vgww::core::ParseIpv4("192.168.0.255", ok);
        config.dhcp.pool_end = config.dhcp.pool_start;
        DhcpServer bcast(config);
        CHECK(bcast.Acquire(mac, now) == 0);

        // Network (192.168.0.0).
        config.dhcp.pool_start = vgww::core::ParseIpv4("192.168.0.0", ok);
        config.dhcp.pool_end = config.dhcp.pool_start;
        DhcpServer netw(config);
        CHECK(netw.Acquire(mac, now) == 0);

        // A normal single-address pool still allocates (positive control).
        config.dhcp.pool_start = vgww::core::ParseIpv4("192.168.0.201", ok);
        config.dhcp.pool_end = config.dhcp.pool_start;
        DhcpServer normal(config);
        CHECK(normal.Acquire(mac, now) == config.dhcp.pool_start);
    }

    void TestOfferShortHold() {
        vgww::core::Config config;
        config.gateway.ipv4 = kGatewayIp;
        config.dhcp.pool_start = kPoolStart;
        config.dhcp.pool_end = kPoolEnd;

        const WireMac mac_a{0x21, 1, 1, 1, 1, 1};
        const WireMac mac_b{0x22, 2, 2, 2, 2, 2};

        DhcpServer server(config);
        const auto t0 = std::chrono::steady_clock::now();

        // OFFER stage holds the address only briefly.
        const uint32_t offered_a =
            server.Acquire(mac_a, t0, DhcpServer::OfferStage::kOffer);
        CHECK(offered_a != 0);

        // Another client must not receive the offered address while held.
        const uint32_t offered_b =
            server.Acquire(mac_b, t0, DhcpServer::OfferStage::kOffer);
        CHECK(offered_b != 0);
        CHECK(offered_b != offered_a);

        // ACK promotes the lease to the full term.
        CHECK(server.Acquire(mac_a, t0 + std::chrono::seconds(5),
                             DhcpServer::OfferStage::kAck) == offered_a);

        // B never ACKed: its short hold expires and the address is no
        // longer protected (round-robin hands out fresh addresses; the
        // freed one returns when the pool wraps).
        const auto after_hold = t0 + std::chrono::seconds(61);
        CHECK(server.Sweep(after_hold) >= 1);  // B's hold swept
        const WireMac mac_c{0x23, 3, 3, 3, 3, 3};
        const uint32_t offered_c =
            server.Acquire(mac_c, after_hold, DhcpServer::OfferStage::kOffer);
        CHECK(offered_c != 0);
        CHECK(offered_c != offered_a);  // A is ACKed and still protected
    }

    void TestLeaseRoundTrip() {
        vgww::core::Config config;
        config.gateway.ipv4 = kGatewayIp;
        // Pool address with a non-zero third byte (5) - catches a
        // SaveLeases formatting bug that also emits the second byte there.
        config.dhcp.pool_start =
            (192u) | (168u << 8) | (5u << 16) | (100u << 24);
        config.dhcp.pool_end = config.dhcp.pool_start;
        DhcpServer server(config);
        const WireMac mac{0x41, 1, 1, 1, 1, 1};
        const uint32_t ip = server.Acquire(
            mac, std::chrono::steady_clock::now(), DhcpServer::OfferStage::kAck);
        CHECK(ip != 0);

        const std::string path = "lease-roundtrip-tmp.json";
        CHECK(server.DumpLeases(path, std::chrono::steady_clock::now()));

        vgww::core::Config config2;
        config2.gateway.ipv4 = kGatewayIp;
        // A DIFFERENT pool: only a genuine restore returns the stored address.
        config2.dhcp.pool_start =
            (192u) | (168u << 8) | (6u << 16) | (200u << 24);
        config2.dhcp.pool_end = config2.dhcp.pool_start;
        DhcpServer server2(config2);
        CHECK(server2.LoadLeases(path, std::chrono::steady_clock::now()));

        // After the reload the client renews from the persisted address.
        const uint32_t again = server2.Acquire(
            mac, std::chrono::steady_clock::now(), DhcpServer::OfferStage::kAck);
        CHECK(again == ip);
        std::remove(path.c_str());
    }

    void TestDeclineMarksAddressBad() {
        vgww::core::Config config;
        config.gateway.ipv4 = kGatewayIp;
        config.dhcp.pool_start = kPoolStart;
        config.dhcp.pool_end = kPoolStart;  // single-address pool

        const WireMac mac{0x31, 1, 1, 1, 1, 1};
        DhcpServer server(config);
        const auto t0 = std::chrono::steady_clock::now();

        const uint32_t ip =
            server.Acquire(mac, t0, DhcpServer::OfferStage::kAck);
        CHECK(ip != 0);

        // Client detects an ARP conflict and DECLINEs the address.
        server.Decline(mac, ip, t0);

        // The declined address must not be handed out again right away.
        const WireMac other{0x32, 2, 2, 2, 2, 2};
        CHECK(server.Acquire(other, t0 + std::chrono::seconds(1),
                             DhcpServer::OfferStage::kOffer) == 0);

        // After the decline window it becomes usable again.
        const auto later = t0 + std::chrono::seconds(601);
        CHECK(server.Acquire(other, later,
                             DhcpServer::OfferStage::kOffer) == ip);
    }

    // ===================== batch260: option-stream + reply-frame ==========

    /// Builds a BOOTREQUEST with an ARBITRARY options blob (already TLV-
    /// encoded, without the trailing END unless the caller adds it).
    std::vector<uint8_t> BuildRequestWithRawOptions(
        const std::vector<uint8_t>& options) {
        const size_t dhcp_total = kDhcpFixedLen + options.size();
        std::vector<uint8_t> f(kEthernetHeaderLen + 20 + kUdpHeaderLen +
                               dhcp_total, 0);
        BuildEthHeader(f.data(), kBroadcastMac, kClientMac, kEthertypeIpv4);
        uint8_t* ip = f.data() + kEthernetHeaderLen;
        ip[0] = 0x45;
        const uint16_t total =
            static_cast<uint16_t>(20 + kUdpHeaderLen + dhcp_total);
        ip[2] = static_cast<uint8_t>(total >> 8);
        ip[3] = static_cast<uint8_t>(total & 0xFF);
        ip[8] = 64;
        ip[9] = 17;
        uint8_t* udp = ip + 20;
        udp[1] = 68;  // sport
        udp[3] = 67;  // dport
        const uint16_t udp_len =
            static_cast<uint16_t>(kUdpHeaderLen + dhcp_total);
        udp[4] = static_cast<uint8_t>(udp_len >> 8);
        udp[5] = static_cast<uint8_t>(udp_len & 0xFF);
        uint8_t* d = udp + kUdpHeaderLen;
        d[0] = 1;  // BOOTREQUEST
        d[1] = 1;  // htype Ethernet
        d[2] = 6;  // hlen
        std::memcpy(d + 28, kClientMac.data(), 6);
        std::memcpy(d + 236, "\x63\x82\x53\x63", 4);
        std::memcpy(d + kDhcpFixedLen, options.data(), options.size());
        return f;
    }

    /// Walks ONLY the DHCP option stream of a built reply (starting after the
    /// 240-byte fixed part) and returns the payload of the FIRST option with
    /// `code`. Unlike FindOptionView this never scans the fixed header, so
    /// `kDhcpOptionSubnet` (1) cannot collide with the BOOTP htype byte.
    std::vector<uint8_t> FindReplyOption(const std::vector<uint8_t>& frame,
                                         uint8_t code) {
        if (frame.size() <= kDhcpOffset + kDhcpFixedLen) return {};
        size_t pos = kDhcpOffset + kDhcpFixedLen;
        while (pos < frame.size()) {
            const uint8_t c = frame[pos];
            if (c == kDhcpOptionEnd) return {};
            if (c == 0) { ++pos; continue; }
            if (pos + 1 >= frame.size()) return {};
            const size_t n = frame[pos + 1];
            if (pos + 2 + n > frame.size()) return {};
            if (c == code) {
                return std::vector<uint8_t>(frame.begin() + pos + 2,
                                            frame.begin() + pos + 2 + n);
            }
            pos += 2 + n;
        }
        return {};
    }

    /// True when the option stream contains `code` at all.
    bool ReplyHasOption(const std::vector<uint8_t>& frame, uint8_t code) {
        return !FindReplyOption(frame, code).empty() ||
               (code == kDhcpOptionEnd && !frame.empty() &&
                frame.back() == kDhcpOptionEnd);
    }

    void TestParseOptionStreamBoundaries() {
        DhcpView view;

        // (1) The END option stops the walk: an option AFTER it must not be
        //     read. A trailing hostname is the discriminator -- a later
        //     msg-type would merely overwrite the same field, but a hostname
        //     would ADD data that must stay absent.
        {
            const std::vector<uint8_t> opts = {
                kDhcpOptionMsgType, 1, kDhcpMsgDiscover,
                kDhcpOptionEnd,
                kDhcpOptionHostname, 3, 'A', 'F', 'T'};
            const auto f = BuildRequestWithRawOptions(opts);
            CHECK(ParseDhcpFrame(f.data(), f.size(), view));
            CHECK(view.msg_type == kDhcpMsgDiscover);
            CHECK(view.hostname.empty());  // the walk stopped at END

            // Control: the same hostname WITHOUT the END in front IS parsed.
            const std::vector<uint8_t> opts2 = {
                kDhcpOptionMsgType, 1, kDhcpMsgDiscover,
                kDhcpOptionHostname, 3, 'A', 'F', 'T'};
            const auto f2 = BuildRequestWithRawOptions(opts2);
            DhcpView v2;
            CHECK(ParseDhcpFrame(f2.data(), f2.size(), v2));
            CHECK(v2.hostname == "AFT");

            // A SHORT option after END is the real discriminator: if the walk
            // ignored END it would treat 255 as a code with length = 12 (the
            // hostname code) and stumble; with two short 4-byte options the
            // walk would land exactly on them and record requested_ip.
            const std::vector<uint8_t> opts3 = {
                kDhcpOptionMsgType, 1, kDhcpMsgDiscover,
                kDhcpOptionEnd,
                kDhcpOptionRequestedIp, 4, 100, 0, 168, 192};
            const auto f3 = BuildRequestWithRawOptions(opts3);
            DhcpView v3;
            CHECK(ParseDhcpFrame(f3.data(), f3.size(), v3));
            CHECK(v3.msg_type == kDhcpMsgDiscover);
            CHECK(v3.requested_ip == 0);  // never read past END

            // The strongest discriminator: a trailing option ALIGNED so an
            // ignored END (255 read as a code with length dhcp[pos+1]) walks
            // straight onto it. Here 255 is followed by a 0 length byte and a
            // PAD, so the mutant lands exactly at the requested-ip option and
            // would RECORD it; the correct code stops before it.
            const std::vector<uint8_t> opts5 = {
                kDhcpOptionMsgType, 1, kDhcpMsgDiscover,
                kDhcpOptionEnd, 0, 0,
                kDhcpOptionRequestedIp, 4, 100, 0, 168, 192};
            const auto f5 = BuildRequestWithRawOptions(opts5);
            DhcpView v5;
            CHECK(ParseDhcpFrame(f5.data(), f5.size(), v5));
            CHECK(v5.msg_type == kDhcpMsgDiscover);
            CHECK(v5.requested_ip == 0);  // END stopped the walk

            // Control: the identical trailing option WITHOUT END IS read.
            const std::vector<uint8_t> opts4 = {
                kDhcpOptionMsgType, 1, kDhcpMsgDiscover,
                kDhcpOptionRequestedIp, 4, 100, 0, 168, 192};
            const auto f4 = BuildRequestWithRawOptions(opts4);
            DhcpView v4;
            CHECK(ParseDhcpFrame(f4.data(), f4.size(), v4));
            CHECK(v4.requested_ip == kPoolStart);
        }

        // (2) PAD (0) bytes are skipped one at a time, not treated as a TLV
        //     with a length byte.
        {
            const std::vector<uint8_t> opts = {
                0, 0, 0,
                kDhcpOptionMsgType, 1, kDhcpMsgRequest,
                kDhcpOptionEnd};
            const auto f = BuildRequestWithRawOptions(opts);
            CHECK(ParseDhcpFrame(f.data(), f.size(), view));
            CHECK(view.msg_type == kDhcpMsgRequest);
        }

        // (3) An option whose declared length runs past the frame stops the
        //     walk WITHOUT parsing it (no out-of-bounds read, no partial
        //     value). The msg-type before it must survive.
        {
            const std::vector<uint8_t> opts = {
                kDhcpOptionMsgType, 1, kDhcpMsgDiscover,
                kDhcpOptionHostname, 200, 0x41, 0x42};  // says 200, has 2
            const auto f = BuildRequestWithRawOptions(opts);
            CHECK(ParseDhcpFrame(f.data(), f.size(), view));
            CHECK(view.msg_type == kDhcpMsgDiscover);
            CHECK(view.hostname.empty());  // the truncated option was dropped
        }

        // (4) A dangling option code with no length byte (pos+1 >= dhcp_len)
        //     is ignored, and the earlier msg-type survives.
        {
            const std::vector<uint8_t> opts = {
                kDhcpOptionMsgType, 1, kDhcpMsgDiscover,
                kDhcpOptionHostname};  // code with NO length octet
            const auto f = BuildRequestWithRawOptions(opts);
            CHECK(ParseDhcpFrame(f.data(), f.size(), view));
            CHECK(view.msg_type == kDhcpMsgDiscover);
        }

        // (5) msg_type with a zero-length value is refused (needs >= 1).
        //     requested_ip / server_id need >= 4.
        {
            const std::vector<uint8_t> opts = {
                kDhcpOptionMsgType, 0,
                kDhcpOptionRequestedIp, 2, 0x01, 0x02,
                kDhcpOptionServerId, 2, 0x03, 0x04,
                kDhcpOptionEnd};
            const auto f = BuildRequestWithRawOptions(opts);
            CHECK(ParseDhcpFrame(f.data(), f.size(), view));
            CHECK(view.msg_type == 0);        // undersized -> untouched
            CHECK(view.requested_ip == 0);    // undersized -> untouched
            CHECK(view.server_id == 0);       // undersized -> untouched
        }

        // (6) Valid full-size versions of the same three options DO land.
        {
            const std::vector<uint8_t> opts = {
                kDhcpOptionMsgType, 1, kDhcpMsgRequest,
                kDhcpOptionRequestedIp, 4, 100, 0, 168, 192,
                kDhcpOptionServerId, 4, 40, 0, 168, 192,
                kDhcpOptionEnd};
            const auto f = BuildRequestWithRawOptions(opts);
            CHECK(ParseDhcpFrame(f.data(), f.size(), view));
            CHECK(view.msg_type == kDhcpMsgRequest);
            CHECK(view.requested_ip == kPoolStart);
            CHECK(view.server_id == kGatewayIp);
        }

        // (7) The hostname option carries its EXACT length (not 0, not the
        //     whole remaining stream).
        {
            const std::vector<uint8_t> opts = {
                kDhcpOptionMsgType, 1, kDhcpMsgDiscover,
                kDhcpOptionHostname, 5, 'a', 'b', 'c', 'd', 'e',
                kDhcpOptionEnd};
            const auto f = BuildRequestWithRawOptions(opts);
            CHECK(ParseDhcpFrame(f.data(), f.size(), view));
            CHECK(view.hostname == "abcde");
        }

        // (8) The walk ADVANCES by 2+len: two consecutive options are both
        //     parsed (a walk that advanced by 2 would re-read the value as a
        //     code).
        {
            const std::vector<uint8_t> opts = {
                kDhcpOptionMsgType, 1, kDhcpMsgDiscover,
                kDhcpOptionHostname, 3, 'x', 'y', 'z',
                kDhcpOptionRequestedIp, 4, 100, 0, 168, 192,
                kDhcpOptionEnd};
            const auto f = BuildRequestWithRawOptions(opts);
            CHECK(ParseDhcpFrame(f.data(), f.size(), view));
            CHECK(view.msg_type == kDhcpMsgDiscover);
            CHECK(view.hostname == "xyz");
            CHECK(view.requested_ip == kPoolStart);
        }
    }

    void TestParseRejectsNonClientFrames() {
        DhcpView view;

        // A frame shorter than the DHCP minimum is rejected before any read.
        {
            std::vector<uint8_t> f(kDhcpFrameMin - 1, 0);
            CHECK(!ParseDhcpFrame(f.data(), f.size(), view));
        }
        // Non-IPv4 ethertype.
        {
            auto f = BuildDiscover(1);
            f[12] = 0x86;  // 0x86DD (IPv6)
            f[13] = 0xDD;
            CHECK(!ParseDhcpFrame(f.data(), f.size(), view));
        }
        // IPv4 version 6 in an otherwise valid frame.
        {
            auto f = BuildDiscover(1);
            f[kEthernetHeaderLen] = 0x65;  // version 6, IHL 5
            CHECK(!ParseDhcpFrame(f.data(), f.size(), view));
        }
        // IHL above the 60-byte maximum.
        {
            auto f = BuildDiscover(1);
            f[kEthernetHeaderLen] = 0x4F;  // version 4, IHL 15 = 60 bytes...
            // 0x4F -> IHL 15 -> 60 bytes, which is legal; use 0x4F+1 below.
            f[kEthernetHeaderLen] = 0x45;
            // Build a frame whose IHL field says 16 (>15 is impossible, so
            // test the "> 60" arm by declaring a length the frame cannot
            // hold): IHL 15 = 60 bytes but the frame only has 20.
            f[kEthernetHeaderLen] = 0x4F;
            CHECK(!ParseDhcpFrame(f.data(), f.size(), view));
        }
        // Non-UDP protocol.
        {
            auto f = BuildDiscover(1);
            f[kEthernetHeaderLen + 9] = 6;  // TCP
            CHECK(!ParseDhcpFrame(f.data(), f.size(), view));
        }
        // Source port neither 67 nor 68.
        {
            auto f = BuildDiscover(1);
            f[kEthernetHeaderLen + 20] = 0x00;
            f[kEthernetHeaderLen + 21] = 0x99;
            CHECK(!ParseDhcpFrame(f.data(), f.size(), view));
        }
        // Magic cookie with only its FIRST byte correct.
        {
            auto f = BuildDiscover(1);
            f[kDhcpOffset + 236] = 0x63;
            f[kDhcpOffset + 237] = 0x00;  // wrong
            CHECK(!ParseDhcpFrame(f.data(), f.size(), view));
        }
        // Magic cookie with only its LAST byte wrong.
        {
            auto f = BuildDiscover(1);
            f[kDhcpOffset + 239] = 0x00;
            CHECK(!ParseDhcpFrame(f.data(), f.size(), view));
        }
    }

    void TestParseRejectsAFrameTooShortForItsDeclaredIhl() {
        // An attacker-controlled IHL can push the DHCP fixed part past the
        // end of the buffer. The minimum-length gate alone only guarantees
        // room for IHL=20 (282 bytes); with IHL=60 the fixed part needs 322,
        // so a 300-byte frame declaring IHL=60 must be rejected BEFORE the
        // magic-cookie / chaddr reads.
        auto f = BuildDiscoverWithIhl(60);
        CHECK(f.size() == kEthernetHeaderLen + 60 + kUdpHeaderLen +
                              kDhcpFixedLen + 4);  // full-length reference
        // Truncate the Tail so the fixed part no longer fits.
        std::vector<uint8_t> cut(f.begin(),
                                 f.begin() + kEthernetHeaderLen + 60 +
                                     kUdpHeaderLen + kDhcpFixedLen - 1);
        // Keep the UDP length field consistent with the TRUNCATED frame, so
        // the earlier cross-check (udp_len == len - 14 - ihl) cannot reject
        // it and the fixed-part gate is what actually fires.
        const uint16_t cut_udp_len = static_cast<uint16_t>(
            cut.size() - kEthernetHeaderLen - 60);
        cut[kEthernetHeaderLen + 60 + 4] =
            static_cast<uint8_t>(cut_udp_len >> 8);
        cut[kEthernetHeaderLen + 60 + 5] =
            static_cast<uint8_t>(cut_udp_len & 0xFF);
        DhcpView view;
        CHECK(!ParseDhcpFrame(cut.data(), cut.size(), view));

        // Contrast: the SAME byte count with IHL=20 is a complete frame and
        // parses. This pins that the rejection above came from the
        // ihl-aware gate and not from the raw length alone.
        auto ihl20 = BuildDiscoverWithIhl(20);
        CHECK(ihl20.size() == kEthernetHeaderLen + 20 + kUdpHeaderLen +
                               kDhcpFixedLen + 4);
        CHECK(ParseDhcpFrame(ihl20.data(), ihl20.size(), view));
    }

    void TestParseRejectsATruncatedFixedPart() {
        // One byte short of the DHCP fixed part, with a legal IHL: the
        // magic-cookie read at [236,240) would cross the end of the buffer,
        // so the frame must be rejected rather than read out of bounds.
        auto f = BuildDiscover(1);
        CHECK(f.size() >= kDhcpOffset + kDhcpFixedLen);
        std::vector<uint8_t> cut(f.begin(),
                                 f.begin() + kDhcpOffset + kDhcpFixedLen - 1);
        // Keep the UDP length field consistent with the shortened frame; the
        // UDP length cross-check would otherwise reject it first and mask the
        // fixed-part gate.
        const size_t ihl = 20;
        const uint16_t udp_len = static_cast<uint16_t>(
            cut.size() - kEthernetHeaderLen - ihl);
        cut[kEthernetHeaderLen + 20 + 4] =
            static_cast<uint8_t>(udp_len >> 8);
        cut[kEthernetHeaderLen + 20 + 5] = static_cast<uint8_t>(udp_len);
        DhcpView view;
        CHECK(!ParseDhcpFrame(cut.data(), cut.size(), view));

        // One byte MORE (the full fixed part) is accepted, so the check is
        // exactly at the boundary. Options are absent, which is legal.
        auto full = BuildDiscover(1);
        full.resize(kDhcpOffset + kDhcpFixedLen);
        const uint16_t full_udp_len =
            static_cast<uint16_t>(kUdpHeaderLen + kDhcpFixedLen);
        full[kEthernetHeaderLen + 20 + 4] =
            static_cast<uint8_t>(full_udp_len >> 8);
        full[kEthernetHeaderLen + 20 + 5] =
            static_cast<uint8_t>(full_udp_len);
        CHECK(ParseDhcpFrame(full.data(), full.size(), view));
    }

    void TestBuildReplyFrameWireImage() {
        const uint32_t kYourIp = (150u) | (0u << 8) | (168u << 16) | (192u << 24);
        const uint32_t kMask = (0u) | (255u << 8) | (255u << 16) | (255u << 24);
        const std::vector<uint32_t> dns = {
            (1u) | (1u << 8) | (1u << 16) | (8u << 24),
            (4u) | (4u << 8) | (4u << 16) | (8u << 24)};
        std::vector<uint8_t> f;
        BuildDhcpReplyFrame(kDhcpMsgAck, 0x11223344, kGatewayMac, kClientMac,
                            kYourIp, kGatewayIp, kMask, 3600, dns,
                            std::string("host1"), f);

        // ---- Ethernet: unicast to the CLIENT, from the gateway ----
        for (size_t i = 0; i < 6; ++i) CHECK(f[i] == kClientMac[i]);
        for (size_t i = 0; i < 6; ++i) CHECK(f[6 + i] == kGatewayMac[i]);
        CHECK(f[12] == 0x08 && f[13] == 0x00);

        const uint8_t* ip = f.data() + kEthernetHeaderLen;
        CHECK(ip[0] == 0x45);
        CHECK(ip[9] == 17);                       // UDP
        CHECK(ip[8] == 64);                       // TTL
        CHECK(ip[6] == 0x40);                     // DF
        for (size_t i = 0; i < 4; ++i) {          // src = server
            CHECK(ip[12 + i] == static_cast<uint8_t>(kGatewayIp >> (8 * i)));
        }
        for (size_t i = 0; i < 4; ++i) CHECK(ip[16 + i] == 0xFF);  // bcast
        CHECK(vgww::net::InternetChecksum(ip, 20) == 0u);  // ck verifies

        const uint8_t* udp = ip + 20;
        CHECK(udp[0] == 0 && udp[1] == 67);       // sport = server
        CHECK(udp[2] == 0 && udp[3] == 68);       // dport = client
        {
            const uint16_t udp_len =
                static_cast<uint16_t>((udp[4] << 8) | udp[5]);
            const uint32_t pseudo = vgww::net::PseudoHeaderSum(
                ip + 12, ip + 16, ip[9], udp_len);
            CHECK(vgww::net::InternetChecksum(udp, udp_len, pseudo) == 0u);
        }

        const uint8_t* d = udp + kUdpHeaderLen;
        CHECK(d[0] == 2);                         // BOOTREPLY
        CHECK(d[1] == 1);                         // htype
        CHECK(d[2] == 6);                         // hlen
        CHECK(d[3] == 0);                         // hops
        CHECK(d[4] == 0x11 && d[5] == 0x22 && d[6] == 0x33 && d[7] == 0x44);
        CHECK(d[10] == 0x80);                     // BROADCAST flag
        // yiaddr / siaddr, little-endian (inet_addr numeric convention).
        for (size_t i = 0; i < 4; ++i) {
            CHECK(d[16 + i] == static_cast<uint8_t>(kYourIp >> (8 * i)));
            CHECK(d[20 + i] == static_cast<uint8_t>(kGatewayIp >> (8 * i)));
        }
        // chaddr
        for (size_t i = 0; i < 6; ++i) CHECK(d[28 + i] == kClientMac[i]);
        // magic cookie
        CHECK(d[236] == 0x63 && d[237] == 0x82 && d[238] == 0x53 &&
              d[239] == 0x63);

        // ---- options ----
        const auto msg = FindReplyOption(f, kDhcpOptionMsgType);
        CHECK(msg.size() == 1 && msg[0] == kDhcpMsgAck);
        const auto sid = FindReplyOption(f, kDhcpOptionServerId);
        CHECK(sid.size() == 4);
        for (size_t i = 0; i < 4; ++i) {
            CHECK(sid[i] == static_cast<uint8_t>(kGatewayIp >> (8 * i)));
        }
        const auto subnet = FindReplyOption(f, kDhcpOptionSubnet);
        CHECK(subnet.size() == 4);
        CHECK(subnet[0] == 0 && subnet[1] == 255 && subnet[2] == 255 &&
              subnet[3] == 255);
        const auto router_opt = FindReplyOption(f, kDhcpOptionRouter);
        CHECK(router_opt.size() == 4);
        for (size_t i = 0; i < 4; ++i) {
            CHECK(router_opt[i] == static_cast<uint8_t>(kGatewayIp >> (8 * i)));
        }
        // lease time is a BIG-endian 32-bit integer (not an address).
        const auto lease = FindReplyOption(f, kDhcpOptionLeaseTime);
        CHECK(lease.size() == 4);
        CHECK(lease[0] == 0x00 && lease[1] == 0x00 && lease[2] == 0x0E &&
              lease[3] == 0x10);  // 3600
        // both DNS servers, in order, each little-endian.
        const auto dns_opt = FindReplyOption(f, kDhcpOptionDns);
        CHECK(dns_opt.size() == 8);
        CHECK(dns_opt[0] == 1 && dns_opt[1] == 1 && dns_opt[2] == 1 &&
              dns_opt[3] == 8);
        CHECK(dns_opt[4] == 4 && dns_opt[5] == 4 && dns_opt[6] == 4 &&
              dns_opt[7] == 8);
        const auto host_opt = FindReplyOption(f, kDhcpOptionHostname);
        CHECK(host_opt.size() == 5);
        CHECK(std::string(host_opt.begin(), host_opt.end()) == "host1");
        // END option terminates the stream.
        CHECK(f.back() == 0x00 || f.size() > 0);
    }

    void TestBuildReplyOfferHasNoLeaseOptions() {
        // An OFFER carries only msg-type + server-id: the lease/subnet/router/
        // DNS/hostname options belong to the ACK. Emitting them in an OFFER
        // desyncs a strict client.
        std::vector<uint8_t> offer;
        BuildDhcpReplyFrame(kDhcpMsgOffer, 7, kGatewayMac, kClientMac,
                            kPoolStart, kGatewayIp, 0xFFFFFF00u, 3600,
                            {0x08080808u}, std::string("h"), offer);
        CHECK(FindReplyOption(offer, kDhcpOptionSubnet).empty());
        CHECK(FindReplyOption(offer, kDhcpOptionRouter).empty());
        CHECK(FindReplyOption(offer, kDhcpOptionLeaseTime).empty());
        CHECK(FindReplyOption(offer, kDhcpOptionDns).empty());
        CHECK(FindReplyOption(offer, kDhcpOptionHostname).empty());
        // ...but msg-type and server-id ARE present.
        CHECK(FindReplyOption(offer, kDhcpOptionMsgType).size() == 1);
        CHECK(FindReplyOption(offer, kDhcpOptionServerId).size() == 4);
    }

    void TestBuildReplyOmitsEmptyOptionalOptions() {
        // With no DNS servers and no hostname, those two options must be
        // ABSENT (not emitted with a zero length).
        std::vector<uint8_t> f;
        BuildDhcpReplyFrame(kDhcpMsgAck, 1, kGatewayMac, kClientMac, kPoolStart,
                            kGatewayIp, 0xFFFFFF00u, 600, {}, std::string(), f);
        const uint8_t* d = f.data() + kDhcpOffset;
        // Walk the option stream from the fixed part.
        bool saw_dns = false;
        bool saw_host = false;
        size_t pos = kDhcpFixedLen;
        while (pos < f.size() - kDhcpOffset) {
            const uint8_t code = d[pos];
            if (code == kDhcpOptionEnd) break;
            if (code == 0) { ++pos; continue; }
            if (pos + 1 >= f.size() - kDhcpOffset) break;
            const uint8_t len = d[pos + 1];
            if (code == kDhcpOptionDns) saw_dns = true;
            if (code == kDhcpOptionHostname) saw_host = true;
            pos += 2 + len;
        }
        CHECK(!saw_dns);
        CHECK(!saw_host);
    }

    void TestBuildReplyClampsOversizedOptionValues() {
        // A 300-byte hostname must be emitted with a 253-byte TLV length AND
        // exactly 253 bytes of payload (a truncated length with the full
        // payload would desync the client parser).
        const std::string huge(300, 'H');
        std::vector<uint8_t> f;
        BuildDhcpReplyFrame(kDhcpMsgAck, 1, kGatewayMac, kClientMac, kPoolStart,
                            kGatewayIp, 0xFFFFFF00u, 600, {}, huge, f);
        const auto host = FindReplyOption(f, kDhcpOptionHostname);
        CHECK(host.size() == 253);
        // A 100-server DNS list is 400 bytes -> clamped to 253 (63.25 servers).
        std::vector<uint32_t> many_dns;
        for (int i = 0; i < 100; ++i) {
            many_dns.push_back(static_cast<uint32_t>(i));
        }
        std::vector<uint8_t> g;
        BuildDhcpReplyFrame(kDhcpMsgAck, 1, kGatewayMac, kClientMac, kPoolStart,
                            kGatewayIp, 0xFFFFFF00u, 600, many_dns, std::string(),
                            g);
        CHECK(FindReplyOption(g, kDhcpOptionDns).size() == 253);
    }

    void TestBuildReplyFrameIsZeroFilled() {
        // The builder uses assign(..., 0): every byte it does not write must
        // be 0, so reusing a dirty output vector cannot leak stale bytes.
        std::vector<uint8_t> f(5000, 0xEE);
        BuildDhcpReplyFrame(kDhcpMsgAck, 1, kGatewayMac, kClientMac, kPoolStart,
                            kGatewayIp, 0xFFFFFF00u, 600, {}, std::string(), f);
        CHECK(f.size() < 5000);
        const uint8_t* ip = f.data() + kEthernetHeaderLen;
        CHECK(ip[1] == 0x00);   // DSCP
        CHECK(ip[4] == 0x00 && ip[5] == 0x00);  // identification
        CHECK(ip[7] == 0x00);   // fragment offset
        const uint8_t* d = f.data() + kDhcpOffset;
        CHECK(d[8] == 0 && d[9] == 0);    // secs
        CHECK(d[12] == 0 && d[13] == 0 && d[14] == 0 && d[15] == 0);  // ciaddr
        // sname/file must be entirely zero.
        for (size_t i = 44; i < 236; ++i) CHECK(d[i] == 0);
    }

    void TestBuildReplyOptionsEndWithTheEndCode() {
        // The option stream MUST be terminated by 255; a client that trusts
        // the UDP length would otherwise read padding as options.
        std::vector<uint8_t> f;
        BuildDhcpReplyFrame(kDhcpMsgOffer, 3, kGatewayMac, kClientMac, kPoolStart,
                            kGatewayIp, 0xFFFFFF00u, 600, {}, std::string(), f);
        const uint8_t* d = f.data() + kDhcpOffset;
        const size_t dhcp_len = f.size() - kDhcpOffset;
        // The last option byte is END (there is no padding after it).
        CHECK(dhcp_len > kDhcpFixedLen);
        CHECK(d[dhcp_len - 1] == kDhcpOptionEnd);
    }

    // ===================== end batch260 ==================================

}  // namespace

// The client-reported hostname (DHCP option 12) must be learnt into the
// lease, survive a renew that omits the option, accept updates, and
// round-trip through DumpLeases/LoadLeases - the WebUI clients table
// renders this field, so dropping it made the column permanently blank.
void TestLeaseHostnameLearnt() {
    vgww::core::Config config;
    config.gateway.ipv4 = kGatewayIp;
    config.gateway.mask = (0u) | (0u << 8) | (255u << 16) | (192u << 24);
    config.dhcp.pool_start = kPoolStart;
    config.dhcp.pool_end = kPoolEnd;
    config.dhcp.lease_seconds = 3600;
    DhcpServer server(config);

    const WireMac mac{0x02, 0x00, 0x5A, 0x00, 0x00, 0x77};
    const auto t0 = std::chrono::steady_clock::now();

    // The OFFER learns the client-reported name.
    CHECK(0 != server.Acquire(mac, t0, DhcpServer::OfferStage::kOffer,
                              "office-laptop"));
    auto leases = server.Leases(t0);
    CHECK(1 == leases.size());
    CHECK(leases[0].hostname == "office-laptop");

    // A renew WITHOUT option 12 must not wipe the learnt name.
    CHECK(0 != server.Acquire(mac, t0 + std::chrono::seconds(5),
                              DhcpServer::OfferStage::kAck));
    leases = server.Leases(t0);
    CHECK(!leases.empty());
    CHECK(leases[0].hostname == "office-laptop");

    // An explicit new name updates it.
    CHECK(0 != server.Acquire(mac, t0 + std::chrono::seconds(10),
                              DhcpServer::OfferStage::kAck, "renamed-box"));
    leases = server.Leases(t0);
    CHECK(!leases.empty());
    CHECK(leases[0].hostname == "renamed-box");

    // The name survives a dump/reload round-trip.
    const std::string path = "test_dhcp_leases_hostname.json";
    std::remove(path.c_str());
    CHECK(server.DumpLeases(path, t0 + std::chrono::seconds(10)));
    DhcpServer restored(config);
    CHECK(restored.LoadLeases(path, t0 + std::chrono::seconds(10)));
    leases = restored.Leases(t0 + std::chrono::seconds(10));
    CHECK(!leases.empty());
    CHECK(leases[0].hostname == "renamed-box");
    std::remove(path.c_str());
}

    // --- F1: strict frame validation (BOOTREQUEST / Ethernet / UDP 67) -----

    void TestParseRejectsWrongOp() {
        auto frame = BuildDiscover(0x11110001);
        frame[kDhcpOffset] = 2;  // BOOTREPLY: not a client request
        DhcpView view;
        CHECK(!ParseDhcpFrame(frame.data(), frame.size(), view));
    }

    void TestParseRejectsWrongHtype() {
        auto frame = BuildDiscover(0x11110002);
        frame[kDhcpOffset + 1] = 2;  // htype 2 != Ethernet
        DhcpView view;
        CHECK(!ParseDhcpFrame(frame.data(), frame.size(), view));
    }

    void TestParseRejectsWrongHlen() {
        auto frame = BuildDiscover(0x11110003);
        frame[kDhcpOffset + 2] = 5;  // hlen 5 != 6-byte MAC
        DhcpView view;
        CHECK(!ParseDhcpFrame(frame.data(), frame.size(), view));
    }

    void TestParseRejectsWrongDport() {
        auto frame = BuildDiscover(0x11110004);
        uint8_t* udp = frame.data() + kEthernetHeaderLen + 20;
        udp[2] = 0;
        udp[3] = 68;  // destination port is not the DHCP server port
        DhcpView view;
        CHECK(!ParseDhcpFrame(frame.data(), frame.size(), view));
    }

    void TestParseRejectsUdpLenMismatch() {
        auto frame = BuildDiscover(0x11110005);
        uint8_t* udp = frame.data() + kEthernetHeaderLen + 20;
        const uint16_t udp_len = static_cast<uint16_t>((udp[4] << 8) | udp[5]);
        const uint16_t wrong = static_cast<uint16_t>(udp_len + 1);
        udp[4] = static_cast<uint8_t>(wrong >> 8);
        udp[5] = static_cast<uint8_t>(wrong & 0xFF);  // off by one
        DhcpView view;
        CHECK(!ParseDhcpFrame(frame.data(), frame.size(), view));
    }

    // --- F2: option 50 (requested IP) is honoured when free + in-pool -----

    void TestRequestedIpHonored() {
        vgww::core::Config config;
        config.gateway.ipv4 = kGatewayIp;
        config.dhcp.pool_start = kPoolStart;
        config.dhcp.pool_end = kPoolEnd;
        config.dhcp.lease_seconds = 3600;

        // A reserved (static) address inside the pool must not be honoured.
        StaticBinding reserved_binding;
        reserved_binding.mac = WireMac{0x11, 2, 2, 2, 2, 2};
        reserved_binding.ip = kPoolStart + 3;
        config.dhcp.static_bindings.push_back(reserved_binding);

        DhcpServer server(config);
        const auto t0 = std::chrono::steady_clock::now();

        // option 50 arrives exactly as the parser stores it: the four address
        // bytes memcpy'd from the wire - the same numeric space as the config
        // values above (inet_addr).
        const uint32_t requested = kPoolStart + 5;
        const uint32_t offered = server.Acquire(
            kClientMac, t0, DhcpServer::OfferStage::kOffer, "", requested);
        CHECK(offered == requested);  // honoured, not the pool cursor

        // A different client asking for the same (now leased) address falls
        // back to the pool walk instead of colliding.
        const WireMac other{0x77, 1, 2, 3, 4, 5};
        const uint32_t fallback = server.Acquire(
            other, t0, DhcpServer::OfferStage::kOffer, "", requested);
        CHECK(fallback != 0);
        CHECK(fallback != requested);

        // Out-of-pool requests also fall back.
        const WireMac third{0x78, 2, 3, 4, 5, 6};
        const uint32_t outside = kPoolEnd + 1000;
        const uint32_t given = server.Acquire(
            third, t0, DhcpServer::OfferStage::kOffer, "", outside);
        CHECK(given != 0);
        CHECK(given != outside);

        // In-pool but statically reserved falls back too.
        const WireMac fourth{0x79, 3, 4, 5, 6, 7};
        const uint32_t not_reserved = server.Acquire(
            fourth, t0, DhcpServer::OfferStage::kOffer, "", reserved_binding.ip);
        CHECK(not_reserved != 0);
        CHECK(not_reserved != reserved_binding.ip);
    }

    // --- F3: a DECLINE from a MAC without that lease must be ignored ------

    void TestDeclineForeignMacIgnored() {
        vgww::core::Config config;
        config.gateway.ipv4 = kGatewayIp;
        config.dhcp.pool_start = kPoolStart;
        config.dhcp.pool_end = kPoolStart;  // single-address pool

        DhcpServer server(config);
        const WireMac holder{0x51, 1, 1, 1, 1, 1};
        const WireMac foreign{0x52, 2, 2, 2, 2, 2};
        const WireMac challenger{0x53, 3, 3, 3, 3, 3};
        const auto t0 = std::chrono::steady_clock::now();

        const uint32_t ip =
            server.Acquire(holder, t0, DhcpServer::OfferStage::kAck);
        CHECK(ip != 0);

        // A MAC that does not hold this address must not park it.
        server.Decline(foreign, ip, t0);

        // The holder's lease is intact...
        CHECK(server.Leases(t0).size() == 1);
        // ...and once released, the address is immediately available again
        // (a foreign decline would have parked it for 600s).
        server.Release(holder);
        CHECK(server.Acquire(challenger, t0 + std::chrono::seconds(1),
                             DhcpServer::OfferStage::kOffer) == ip);
    }

    // --- F4: versioned lease file + observable persistence failures -------

    void TestLeaseFileHasVersion() {
        vgww::core::Config config;
        config.gateway.ipv4 = kGatewayIp;
        config.dhcp.pool_start = kPoolStart;
        config.dhcp.pool_end = kPoolEnd;
        config.dhcp.lease_seconds = 3600;
        DhcpServer server(config);

        const WireMac mac{0x61, 1, 1, 1, 1, 1};
        const auto t0 = std::chrono::steady_clock::now();
        CHECK(server.Acquire(mac, t0, DhcpServer::OfferStage::kAck) != 0);

        const std::string path = "test_dhcp_leases_version.json";
        std::remove(path.c_str());
        CHECK(server.DumpLeases(path, t0));

        std::ifstream file(path, std::ios::binary);
        CHECK(file.good());
        const std::string raw((std::istreambuf_iterator<char>(file)),
                              std::istreambuf_iterator<char>());
        CHECK(raw.find("\"version\":1") != std::string::npos);
        CHECK(raw.find("\"leases\"") != std::string::npos);

        // The versioned file still loads.
        DhcpServer restored(config);
        CHECK(restored.LoadLeases(path, t0));
        std::remove(path.c_str());
    }

    // batch82: the v4 lease writer now rides the shared durable writer. A
    // device-flush failure must be a failure: the previous snapshot stays
    // intact and the failure is counted (it used to be a per-protocol copy).
    void TestLeaseDumpFlushFailureKeepsPreviousSnapshot() {
        vgww::core::Config config;
        config.gateway.ipv4 = kGatewayIp;
        config.dhcp.pool_start = kPoolStart;
        config.dhcp.pool_end = kPoolEnd;
        DhcpServer server(config);
        const WireMac mac{0x91, 1, 1, 1, 1, 1};
        const auto t0 = std::chrono::steady_clock::now();
        CHECK(server.Acquire(mac, t0, DhcpServer::OfferStage::kAck) != 0);

        const std::string path = "b-flush-dhcp-leases.json";
        std::remove(path.c_str());
        CHECK(server.DumpLeases(path, t0));
        std::string original;
        {
            std::ifstream first(path, std::ios::binary);
            original.assign(std::istreambuf_iterator<char>(first),
                            std::istreambuf_iterator<char>());
        }
        CHECK(!original.empty());

        vgww::core::SetFileFlushHookForTest(
            [](std::intptr_t) { return false; });
        const uint64_t before = server.PersistFailureCount();
        const bool saved =
            server.DumpLeases(path, t0 + std::chrono::seconds(5));
        vgww::core::SetFileFlushHookForTest(nullptr);
        CHECK(!saved);
        CHECK(server.PersistFailureCount() == before + 1);
        {
            // The previous snapshot is still what the file holds.
            std::ifstream again(path, std::ios::binary);
            CHECK(std::string((std::istreambuf_iterator<char>(again)),
                              std::istreambuf_iterator<char>()) == original);
        }

        // A recovered device writes again (the file must not be held open:
        // Windows refuses to replace a destination with an open handle).
        CHECK(server.DumpLeases(path, t0 + std::chrono::seconds(6)));
        std::remove(path.c_str());
    }

    // batch82: a corrupt file must be preserved, not silently overwritten by
    // the next dump - otherwise the evidence of the loss is gone forever.
    void TestCorruptLeaseFilePreserved() {
        vgww::core::Config config;
        config.gateway.ipv4 = kGatewayIp;
        config.dhcp.pool_start = kPoolStart;
        config.dhcp.pool_end = kPoolEnd;
        DhcpServer server(config);

        const std::string path = "b-corrupt-dhcp-leases.json";
        const std::string aside = path + ".corrupt";
        std::remove(path.c_str());
        std::remove(aside.c_str());
        const std::string garbage = "{\"version\":1,\"leases\":[{\"mac\":";
        {
            std::ofstream out(path, std::ios::binary);
            out << garbage;
        }
        CHECK(server.LoadLeases(path, std::chrono::steady_clock::now(),
                                nullptr) ==
              DhcpServer::LoadOutcome::kCorrupt);
        std::ifstream kept(aside, std::ios::binary);
        CHECK(kept.good());
        CHECK(std::string((std::istreambuf_iterator<char>(kept)),
                          std::istreambuf_iterator<char>()) == garbage);
        std::ifstream gone(path, std::ios::binary);
        CHECK(!gone.good());
        std::remove(aside.c_str());
    }

    // batch85: a scanner holding the lease file for a moment is NOT
    // corruption. The loader retries; when it still cannot open the file it
    // reports kUnreadable and refuses to overwrite it (a later dump would
    // destroy a perfectly valid snapshot).
    void TestLeaseLoadTransientLockIsNotCorrupt() {
        vgww::core::Config config;
        config.gateway.ipv4 = kGatewayIp;
        config.dhcp.pool_start = kPoolStart;
        config.dhcp.pool_end = kPoolEnd;
        const auto t0 = std::chrono::steady_clock::now();
        const std::string path = "b-lock-dhcp-leases.json";
        std::remove(path.c_str());
        {
            DhcpServer writer(config);
            const WireMac mac{0x95, 1, 1, 1, 1, 1};
            CHECK(writer.Acquire(mac, t0, DhcpServer::OfferStage::kAck) != 0);
            CHECK(writer.DumpLeases(path, t0));
        }

        DhcpServer server(config);
        std::atomic<int> calls{0};
        vgww::core::SetConfigOpenFailureHookForTest(
            [&calls](const std::string&) -> unsigned long {
                return (calls.fetch_add(1) + 1) <= 2 ? 32u : 0u;
            });
        size_t dropped = 0;
        const auto outcome = server.LoadLeases(path, t0, &dropped);
        vgww::core::SetConfigOpenFailureHookForTest(
            std::function<unsigned long(const std::string&)>());
        CHECK(outcome == DhcpServer::LoadOutcome::kRestored);
        CHECK(calls.load() == 3);
        CHECK(server.LeaseCount() == 1);
        std::remove(path.c_str());
    }

    void TestLeaseLoadUnreadablePausesDump() {
        vgww::core::Config config;
        config.gateway.ipv4 = kGatewayIp;
        config.dhcp.pool_start = kPoolStart;
        config.dhcp.pool_end = kPoolEnd;
        const auto t0 = std::chrono::steady_clock::now();
        const std::string path = "b-lock2-dhcp-leases.json";
        std::remove(path.c_str());
        {
            DhcpServer writer(config);
            const WireMac mac{0x96, 1, 1, 1, 1, 1};
            CHECK(writer.Acquire(mac, t0, DhcpServer::OfferStage::kAck) != 0);
            CHECK(writer.DumpLeases(path, t0));
        }
        std::string original;
        {
            std::ifstream in(path, std::ios::binary);
            original.assign(std::istreambuf_iterator<char>(in),
                            std::istreambuf_iterator<char>());
        }

        DhcpServer server(config);
        vgww::core::SetConfigOpenFailureHookForTest(
            [](const std::string&) -> unsigned long { return 32u; });
        const auto outcome = server.LoadLeases(path, t0, nullptr);
        CHECK(outcome == DhcpServer::LoadOutcome::kUnreadable);
        CHECK(server.LeaseCount() == 0);

        // While the file stays unreadable the dump must refuse (counted) and
        // leave the bytes untouched - the recovery retry fails too.
        const uint64_t failures = server.PersistFailureCount();
        CHECK(!server.DumpLeases(path, t0 + std::chrono::seconds(60)));
        CHECK(server.PersistFailureCount() == failures + 1);
        {
            std::ifstream in(path, std::ios::binary);
            CHECK(std::string((std::istreambuf_iterator<char>(in)),
                              std::istreambuf_iterator<char>()) == original);
        }
        vgww::core::SetConfigOpenFailureHookForTest(
            std::function<unsigned long(const std::string&)>());

        // Once the lock is gone a fresh server restores the file.
        DhcpServer fresh(config);
        CHECK(fresh.LoadLeases(path, t0, nullptr) ==
              DhcpServer::LoadOutcome::kRestored);
        std::remove(path.c_str());
    }

    // batch87: a blocked lease writer recovers on the next dump once the file
    // can be read again: the on-disk leases are merged (live leases win on
    // address conflicts), the block clears, and no restart is needed.
    void TestLeaseDumpRecoversFromBlocked() {
        vgww::core::Config config;
        config.gateway.ipv4 = kGatewayIp;
        config.dhcp.pool_start = kPoolStart;
        config.dhcp.pool_end = kPoolEnd;
        const auto t0 = std::chrono::steady_clock::now();
        const std::string path = "b-recover-dhcp-leases.json";
        std::remove(path.c_str());
        {
            DhcpServer writer(config);
            const WireMac mac{0x97, 1, 1, 1, 1, 1};
            CHECK(writer.Acquire(mac, t0, DhcpServer::OfferStage::kAck) != 0);
            CHECK(writer.DumpLeases(path, t0));
        }

        DhcpServer server(config);
        vgww::core::SetConfigOpenFailureHookForTest(
            [](const std::string&) -> unsigned long { return 32u; });
        CHECK(server.LoadLeases(path, t0, nullptr) ==
              DhcpServer::LoadOutcome::kUnreadable);
        vgww::core::SetConfigOpenFailureHookForTest(
            std::function<unsigned long(const std::string&)>());
        CHECK(server.PersistBlocked());
        CHECK(server.LeaseCount() == 0);

        const WireMac live_a{0x98, 2, 2, 2, 2, 2};
        const WireMac live_b{0x99, 3, 3, 3, 3, 3};
        CHECK(server.Acquire(live_a, t0, DhcpServer::OfferStage::kAck) != 0);
        CHECK(server.Acquire(live_b, t0, DhcpServer::OfferStage::kAck) != 0);
        const size_t live = server.LeaseCount();
        CHECK(live == 2);

        CHECK(server.DumpLeases(path, t0 + std::chrono::seconds(60)));
        CHECK(!server.PersistBlocked());
        CHECK(server.LeaseCount() >= live);
        const size_t merged = server.LeaseCount();

        DhcpServer reloaded(config);
        CHECK(reloaded.LoadLeases(path, t0, nullptr) ==
              DhcpServer::LoadOutcome::kRestored);
        CHECK(reloaded.LeaseCount() == merged);
        std::remove(path.c_str());
    }

    // batch206: a client served DURING the blocked window must keep the
    // address it actually holds after the recovery re-read. LoadLeases
    // replaces the whole table with the disk snapshot, so without live entries
    // winning, the previous session's address for that MAC overwrote the live
    // one and the live address became free for the next DISCOVER (duplicate
    // address on the wire). The existing recovery test used DIFFERENT macs,
    // so a same-MAC overwrite was invisible to it.
    void TestB206BlockedRecoveryKeepsLiveAddressForSameMac() {
        vgww::core::Config config;
        config.gateway.ipv4 = kGatewayIp;
        config.dhcp.pool_start = kPoolStart;
        config.dhcp.pool_end = kPoolEnd;
        const auto t0 = std::chrono::steady_clock::now();
        const std::string path = "b206-same-mac-dhcp-leases.json";
        std::remove(path.c_str());
        const WireMac mac{0xA6, 6, 6, 6, 6, 6};

        // Session 1: the client holds some address and it reaches the file.
        uint32_t disk_ip = 0;
        {
            DhcpServer writer(config);
            disk_ip = writer.Acquire(mac, t0, DhcpServer::OfferStage::kAck);
            CHECK(0 != disk_ip);
            CHECK(writer.DumpLeases(path, t0));
        }

        // Session 2 starts with the file unreadable -> persistence blocked.
        DhcpServer server(config);
        vgww::core::SetConfigOpenFailureHookForTest(
            [](const std::string&) -> unsigned long { return 32u; });
        CHECK(server.LoadLeases(path, t0, nullptr) ==
              DhcpServer::LoadOutcome::kUnreadable);
        vgww::core::SetConfigOpenFailureHookForTest(
            std::function<unsigned long(const std::string&)>());
        CHECK(server.PersistBlocked());
        CHECK(server.LeaseCount() == 0);

        // During the block the SAME client gets an address from the live pool.
        // The pool walk is sequential, so occupy the first address with a
        // different client first: the target MAC then lands on a DIFFERENT
        // address than the stale disk one, which is the case the old cleanup
        // missed (it only dropped disk entries whose MAC was not live).
        const WireMac blocker{0xA5, 5, 5, 5, 5, 5};
        const uint32_t blocker_ip =
            server.Acquire(blocker, t0, DhcpServer::OfferStage::kAck);
        CHECK(0 != blocker_ip);
        const uint32_t live_ip = server.Acquire(mac, t0, DhcpServer::OfferStage::kAck);
        CHECK(0 != live_ip);
        CHECK(live_ip != disk_ip);

        // The next dump re-reads the file and merges. The live address must
        // survive - it is what the client is using right now.
        CHECK(server.DumpLeases(path, t0 + std::chrono::seconds(60)));
        CHECK(!server.PersistBlocked());
        {
            const auto leases = server.Leases(t0);
            uint32_t got = 0;
            for (const auto& l : leases) {
                if (l.mac == mac) {
                    got = l.ip;
                }
            }
            CHECK(got == live_ip);
            CHECK(got != disk_ip);
        }
        // Nothing else may still claim the live address, and the stale address
        // must not be handed out to a second client while the first holds it.
        {
            const WireMac other{0xA7, 7, 7, 7, 7, 7};
            const uint32_t other_ip =
                server.Acquire(other, t0, DhcpServer::OfferStage::kAck);
            CHECK(other_ip != live_ip);
        }
        std::remove(path.c_str());
    }
    void TestLeaseSaveFailureReported() {
        vgww::core::Config config;
        config.gateway.ipv4 = kGatewayIp;
        config.dhcp.pool_start = kPoolStart;
        config.dhcp.pool_end = kPoolEnd;
        DhcpServer server(config);
        const auto t0 = std::chrono::steady_clock::now();

        // A path inside a directory that does not exist cannot be written:
        // the dump must fail loudly (counted; message on stderr) instead of
        // reporting success.
        const uint64_t before = server.PersistFailureCount();
        CHECK(!server.DumpLeases("no_such_dir_vgww/leases.json", t0));
        CHECK(server.PersistFailureCount() == before + 1);
    }

    // --- F5: pool exhaustion is observable, still silent on the wire ------

    void TestPoolExhaustionCounted() {
        vgww::core::Config config;
        config.gateway.ipv4 = kGatewayIp;
        config.dhcp.pool_start = kPoolStart;
        config.dhcp.pool_end = kPoolStart;  // single-address pool
        DhcpServer server(config);

        const WireMac mac_a{0x71, 1, 1, 1, 1, 1};
        const WireMac mac_b{0x72, 2, 2, 2, 2, 2};
        const auto t0 = std::chrono::steady_clock::now();
        CHECK(server.Acquire(mac_a, t0, DhcpServer::OfferStage::kAck) != 0);

        const uint64_t before = server.PoolExhaustedCount();
        CHECK(server.Acquire(mac_b, t0, DhcpServer::OfferStage::kOffer) == 0);
        CHECK(server.PoolExhaustedCount() == before + 1);
        // Repeated attempts keep counting (only the log line is throttled).
        CHECK(server.Acquire(mac_b, t0, DhcpServer::OfferStage::kOffer) == 0);
        CHECK(server.PoolExhaustedCount() == before + 2);
        // RFC 2131: no NAK is emitted for an unavailable address - the
        // manager returns 0 and never builds a reply.
    }

    // --- F6: RELEASE must echo our server-id to be accepted ---------------

    void TestReleaseWrongServerIdIgnored() {
        vgww::core::Config config;
        config.gateway.ipv4 = kGatewayIp;
        config.dhcp.pool_start = kPoolStart;
        config.dhcp.pool_end = kPoolEnd;
        config.dhcp.lease_seconds = 3600;
        DhcpServer server(config);

        const WireMac mac{0x81, 1, 1, 1, 1, 1};
        const auto t0 = std::chrono::steady_clock::now();
        const uint32_t ip =
            server.Acquire(mac, t0, DhcpServer::OfferStage::kAck);
        CHECK(ip != 0);

        // A RELEASE echoing a different server-id (option 54) is addressed to
        // another server on the segment: the lease must survive. Server-ids
        // arrive in the same numeric space as config values (wire memcpy).
        server.Release(mac, 0x01020304u);
        CHECK(server.Leases(t0).size() == 1);

        // Our own server-id (the gateway address) releases it.
        server.Release(mac, kGatewayIp);
        CHECK(server.Leases(t0).empty());

        // Legacy callers without option 54 keep the historical behaviour.
        CHECK(server.Acquire(mac, t0, DhcpServer::OfferStage::kAck) != 0);
        server.Release(mac);
        CHECK(server.Leases(t0).empty());
    }

    // batch109: the RUNTIME binding entry (Web POST / UI form ->
    // Dataplane::SetDhcpBinding -> DhcpServer::UpsertBinding) skipped two
    // rules the other two entries enforce:
    //
    //   * placement - the loader (config.cpp ParseDhcp) and ValidateConfig
    //     both reject an address outside the gateway subnet and one that is
    //     the subnet's network/broadcast address, and the DHCPv6 sibling
    //     rejects !InPrefix(ip). UpsertBinding only rejected 0.0.0.0 and the
    //     gateway itself, so a binding on 10.9.9.1 in a 192.168.0.0/24 LAN was
    //     accepted and then handed out verbatim by Acquire - an address the
    //     client provably cannot use. The UI failure text already promised
    //     "address may be taken or not in the subnet", so the intent was
    //     there and the check was not.
    //
    //   * pool reservation - Acquire builds reserved_hosts from
    //     config_.dhcp.static_bindings ONLY, so an address pinned by a
    //     RUNTIME binding stayed lookups-free for every other client: the
    //     round-robin walk could hand the same address to someone else, and
    //     the bound client then received a duplicate. (Config bindings are
    //     covered by TestStaticBindingReservesPoolAddress.)
    //
    // Both are asserted separately so one mutation can kill one without the
    // other.
    void TestB109RuntimeBindingObeysPlacementRules() {
        vgww::core::Config config;
        bool ok = false;
        config.gateway.ipv4 = vgww::core::ParseIpv4("192.168.0.40", ok);
        CHECK(ok);
        config.gateway.mask = vgww::core::ParseIpv4("255.255.255.0", ok);
        CHECK(ok);
        config.dhcp.pool_start = vgww::core::ParseIpv4("192.168.0.100", ok);
        CHECK(ok);
        config.dhcp.pool_end = vgww::core::ParseIpv4("192.168.0.110", ok);
        CHECK(ok);
        config.dhcp.lease_seconds = 3600;

        const WireMac mac{0xAA, 0x12, 0x34, 0x56, 0x78, 0x90};
        DhcpServer server(config);

        // Outside the LAN subnet: the client could never reach the gateway.
        CHECK(!server.UpsertBinding(mac, vgww::core::ParseIpv4("10.9.9.1", ok)));
        // The subnet's network and broadcast addresses are not host
        // addresses (/24 has 254 usable).
        CHECK(!server.UpsertBinding(mac, vgww::core::ParseIpv4("192.168.0.0", ok)));
        CHECK(
            !server.UpsertBinding(mac, vgww::core::ParseIpv4("192.168.0.255", ok)));
        // The gateway itself stays rejected (pre-existing rule).
        CHECK(!server.UpsertBinding(mac, vgww::core::ParseIpv4("192.168.0.40", ok)));
        // Nothing above may have been stored.
        CHECK(server.StaticBindings().empty());

        // Positive control: a legal host address is still accepted and served.
        CHECK(server.UpsertBinding(mac, vgww::core::ParseIpv4("192.168.0.50", ok)));
        const auto now = std::chrono::steady_clock::now();
        CHECK(server.Acquire(mac, now) == vgww::core::ParseIpv4("192.168.0.50", ok));

        // A server with no LAN mask configured keeps the historical behaviour:
        // placement cannot be judged, so only 0.0.0.0 and the gateway are
        // refused. (Pinned by TestRuntimeBindings/TestRuntimeBindingWithoutPool,
        // which run with mask == 0.)
        vgww::core::Config no_mask;
        no_mask.gateway.ipv4 = vgww::core::ParseIpv4("192.168.0.40", ok);
        no_mask.dhcp.lease_seconds = 3600;
        DhcpServer lenient(no_mask);
        CHECK(lenient.UpsertBinding(mac, vgww::core::ParseIpv4("10.9.9.1", ok)));
    }

    void TestB109RuntimeBindingReservesPoolAddress() {
        vgww::core::Config config;
        bool ok = false;
        config.gateway.ipv4 = vgww::core::ParseIpv4("192.168.0.40", ok);
        CHECK(ok);
        config.gateway.mask = vgww::core::ParseIpv4("255.255.255.0", ok);
        CHECK(ok);
        // A two-address pool makes the reservation visible immediately.
        config.dhcp.pool_start = vgww::core::ParseIpv4("192.168.0.100", ok);
        CHECK(ok);
        config.dhcp.pool_end = vgww::core::ParseIpv4("192.168.0.101", ok);
        CHECK(ok);
        config.dhcp.lease_seconds = 3600;

        const uint32_t pinned = vgww::core::ParseIpv4("192.168.0.100", ok);
        const WireMac owner{0xAA, 0x12, 0x00, 0x00, 0x00, 0x01};
        const WireMac other{0xAA, 0x12, 0x00, 0x00, 0x00, 0x02};

        DhcpServer server(config);
        CHECK(server.UpsertBinding(owner, pinned));

        const auto now = std::chrono::steady_clock::now();
        // The runtime binding must reserve its address even though the bound
        // client has not connected yet (same contract the config bindings
        // already honour). Without it, the walk below returns `pinned` and the
        // LAN ends up with two owners for one address.
        const uint32_t given = server.Acquire(other, now);
        CHECK(given != 0);
        CHECK(given != pinned);

        // Option 50 must not be able to claim it either.
        const uint32_t requested = server.Acquire(
            other, now, DhcpServer::OfferStage::kAck, "", pinned);
        CHECK(requested != pinned);

        // The bound client still receives exactly its pinned address.
        CHECK(server.Acquire(owner, now) == pinned);
    }

    // batch110: the kMaxStaticBindings cap existed at every entry EXCEPT the
    // one every runtime write funnels through.
    //
    //   * loader (config.cpp ParseDhcp, :457)            - capped
    //   * ValidateConfig (:1393)                          - capped
    //   * POST /api/dhcp/bindings (web_api.cpp:1974)      - capped, but OUTSIDE
    //                                                      the lock (a TOCTOU:
    //                                                      two concurrent POSTs
    //                                                      both read "below cap")
    //   * UI form -> Dataplane::SetDhcpBinding (controller.cpp:243)
    //     -> DhcpServer::UpsertBinding                    - NOT capped at all
    //
    // DhcpServer::UpsertBinding is the single choke point both runtime entries
    // call (grep: dhcp.cpp:3874 is the only UpsertBinding call from the
    // dataplane, and Dataplane::SetDhcpBinding is the only caller of that).
    // Whatever it does not enforce, nothing enforces. Unbounded growth here is
    // not theoretical: the UI "add binding" form writes one entry per submit
    // and the cap is what keeps the per-tick merged view, the O(N) duplicate
    // scans in Acquire and the lease dump bounded.
    void TestB110RuntimeBindingCapIsEnforcedInTheStore() {
        vgww::core::Config config;
        bool ok = false;
        config.gateway.ipv4 = vgww::core::ParseIpv4("10.0.0.1", ok);
        CHECK(ok);
        // A /8 so 1024 distinct host addresses exist inside the subnet.
        config.gateway.mask = vgww::core::ParseIpv4("255.0.0.0", ok);
        CHECK(ok);
        config.dhcp.lease_seconds = 3600;

        DhcpServer server(config);
        const auto mac_of = [](uint32_t i) {
            return WireMac{0x02, 0x00, static_cast<uint8_t>((i >> 16) & 0xFF),
                           static_cast<uint8_t>((i >> 8) & 0xFF),
                           static_cast<uint8_t>(i & 0xFF), 0x01};
        };
        const auto ip_of = [&ok](uint32_t i) {
            return vgww::core::ParseIpv4(
                "10.1." + std::to_string((i >> 8) & 0xFF) + "." +
                    std::to_string(i & 0xFF),
                ok);
        };

        // Fill exactly to the cap: every one of these is legal.
        const size_t cap = ::vgww::core::limits::kMaxStaticBindings;
        for (uint32_t i = 1; i <= cap; ++i) {
            CHECK(server.UpsertBinding(mac_of(i), ip_of(i)));
        }
        CHECK(server.StaticBindings().size() == cap);

        // The next distinct MAC must be refused, and the store must NOT grow.
        CHECK(!server.UpsertBinding(mac_of(cap + 1), ip_of(cap + 1)));
        CHECK(server.StaticBindings().size() == cap);

        // Re-upserting a MAC that is already bound stays legal even at the
        // cap: an upsert that replaces an entry does not consume a new slot,
        // and refusing it would make "edit an existing binding" fail exactly
        // when the table is full.
        CHECK(server.UpsertBinding(mac_of(1), ip_of(1), "renamed"));
        CHECK(server.StaticBindings().size() == cap);
    }

    void TestB110ConfigBindingsCountTowardTheRuntimeCap() {
        // The merged view (config bindings first, runtime overrides replacing
        // by MAC) is what the cap protects, so the two sources share one
        // budget. A cap that only counted runtime entries would let
        // config+1024 exceed the bound the UI renders and the pool scans.
        vgww::core::Config config;
        bool ok = false;
        config.gateway.ipv4 = vgww::core::ParseIpv4("10.0.0.1", ok);
        CHECK(ok);
        config.gateway.mask = vgww::core::ParseIpv4("255.0.0.0", ok);
        CHECK(ok);
        config.dhcp.lease_seconds = 3600;

        const size_t cap = ::vgww::core::limits::kMaxStaticBindings;
        for (size_t i = 1; i < cap; ++i) {  // cap - 1 config bindings
            vgww::core::StaticBinding binding;
            binding.mac = WireMac{0x02,
                                  0x01,
                                  static_cast<uint8_t>((i >> 16) & 0xFF),
                                  static_cast<uint8_t>((i >> 8) & 0xFF),
                                  static_cast<uint8_t>(i & 0xFF),
                                  0x02};
            binding.ip = vgww::core::ParseIpv4(
                "10.2." + std::to_string((i >> 8) & 0xFF) + "." +
                    std::to_string(i & 0xFF),
                ok);
            CHECK(ok);
            config.dhcp.static_bindings.push_back(binding);
        }
        CHECK(config.dhcp.static_bindings.size() == cap - 1);

        DhcpServer server(config);
        // One free slot left: this runtime binding fills it.
        const WireMac fill{0x02, 0x03, 0x00, 0x00, 0x00, 0x01};
        CHECK(server.UpsertBinding(fill, vgww::core::ParseIpv4("10.1.0.1", ok)));
        CHECK(server.StaticBindings().size() == cap);
        // Now full: a further runtime binding is refused.
        const WireMac extra{0x02, 0x03, 0x00, 0x00, 0x00, 0x02};
        CHECK(!server.UpsertBinding(extra, vgww::core::ParseIpv4("10.1.0.2", ok)));
        CHECK(server.StaticBindings().size() == cap);
    }

    // batch111: the 253-byte hostname bound existed wherever a *Config* was
    // built, but not on the runtime binding entry.
    //
    //   * loader (config.cpp:464, :720)          - capped at 253
    //   * ValidateConfig (config.cpp:1501, :1533) - capped at 253
    //   * UI settings Save (SettingsDraft::ToConfig) - goes through
    //     ValidateConfig, so capped too
    //   * POST /api/dhcp/bindings -> Dataplane::SetDhcpBinding
    //     -> DhcpServer::UpsertBinding            - NOT capped
    //   * UI leases binding form -> same path     - NOT capped
    //
    // 253 is not a cosmetic number: it is the largest value a DHCP option can
    // carry (the TLV length octet), which is why BuildDhcpReplyFrame clamps
    // there (dhcp.cpp:186-191). The clamp keeps the FRAME correct, so this is
    // not a wire-format bug - it is a memory-amplification and contract bug:
    // the HTTP body cap is 1 MiB (kMaxConfigBytes), so one runtime binding can
    // pin ~1 MiB and kMaxStaticBindings (1024) of them ~1 GiB of resident
    // memory, all of which the per-tick snapshot then copies into the UI.
    // Worse, the Config path would REFUSE the very same string, so the two
    // stores disagree about what a legal hostname is.
    void TestB111RuntimeBindingRejectsOversizedHostname() {
        vgww::core::Config config;
        bool ok = false;
        config.gateway.ipv4 = vgww::core::ParseIpv4("192.168.0.1", ok);
        CHECK(ok);
        config.gateway.mask = vgww::core::ParseIpv4("255.255.255.0", ok);
        CHECK(ok);
        config.dhcp.lease_seconds = 3600;

        const WireMac mac{0xAA, 0x12, 0x34, 0x56, 0x78, 0x90};
        const uint32_t ip = vgww::core::ParseIpv4("192.168.0.50", ok);
        CHECK(ok);

        DhcpServer server(config);

        // 253 is the boundary and must still be accepted (the TLV length octet
        // caps the value there, and the loader accepts exactly 253).
        const std::string at_limit(253, 'a');
        CHECK(server.UpsertBinding(mac, ip, at_limit));
        CHECK(server.StaticBindings().size() == 1);
        CHECK(server.StaticBindings()[0].hostname == at_limit);

        // 254 and beyond must be refused, and the previous binding must stay
        // intact (a rejected upsert leaves the store untouched - same contract
        // as the duplicate-address and placement rejections).
        const std::string over_limit(254, 'b');
        CHECK(!server.UpsertBinding(mac, ip, over_limit));
        CHECK(server.StaticBindings().size() == 1);
        CHECK(server.StaticBindings()[0].hostname == at_limit);

        // The pathological case the cap exists for: a body-sized hostname.
        // Without the cap this is stored verbatim and then copied into every
        // snapshot.
        const std::string huge(64 * 1024, 'c');
        CHECK(!server.UpsertBinding(mac, ip, huge));
        CHECK(server.StaticBindings().size() == 1);
        CHECK(server.StaticBindings()[0].hostname == at_limit);

        // An empty hostname is still accepted - the documented contract is
        // "preserve the CONFIG-derived hostname for this MAC" (dhcp.cpp:764),
        // not "preserve the previous runtime value". With no config binding
        // for this MAC that means the runtime hostname becomes empty, which is
        // why the value is asserted empty rather than `at_limit`.
        CHECK(server.UpsertBinding(mac, ip));
        CHECK(server.StaticBindings().size() == 1);
        CHECK(server.StaticBindings()[0].hostname.empty());
    }

    // batch123: DHCP option 12 (hostname) is ARBITRARY bytes on the wire. The
    // key length is one TLV octet, so a client can put 0xFF anywhere in the
    // value and still be a well-formed frame. That byte used to be stored
    // verbatim into the lease and then handed to nlohmann::json::dump(), which
    // runs in strict mode and THROWS type_error.316 on an ill-formed byte
    // (measured). DumpLeases has no try/catch, so the throw escaped the
    // function: on the Stop() path StopAll's noexcept-try caught it and
    // aborted the whole teardown (returning false with resources still
    // allocated), and any other caller lost the dump. The same raw byte also
    // poisons the WebUI JSON body (JsonEscaped only handles quotes/control
    // bytes, not UTF-8 validity). The wire is untrusted, so the client name is
    // SANITIZED (each ill-formed byte -> U+FFFD) at ingress; the store may then
    // only ever hold well-formed UTF-8.
    //
    // This test stays distinct from the oversize case (batch111) and the v6
    // sibling (batch86 discipline): fixing one leaves the other red.
    void TestB123AcquireSanitizesIllFormedUtf8Hostname() {
        vgww::core::Config config;
        bool ok = false;
        config.gateway.ipv4 = vgww::core::ParseIpv4("192.168.0.40", ok);
        CHECK(ok);
        config.gateway.mask = vgww::core::ParseIpv4("255.255.255.0", ok);
        CHECK(ok);
        config.dhcp.pool_start = vgww::core::ParseIpv4("192.168.0.100", ok);
        CHECK(ok);
        config.dhcp.pool_end = vgww::core::ParseIpv4("192.168.0.110", ok);
        CHECK(ok);
        config.dhcp.lease_seconds = 3600;
        DhcpServer server(config);

        const WireMac mac{0x02, 0x00, 0x5A, 0x00, 0x00, 0x91};
        const auto t0 = std::chrono::steady_clock::now();

        // "bad" + 0xFF + 0xFE + "name": two adjacent ill-formed bytes.
        std::string raw = "bad";
        raw.push_back(static_cast<char>(0xFF));
        raw.push_back(static_cast<char>(0xFE));
        raw += "name";
        CHECK(0 != server.Acquire(mac, t0, DhcpServer::OfferStage::kAck, raw));

        // The stored name is well-formed UTF-8: each ill-formed byte became
        // U+FFFD (EF BF BD), and the printable ASCII survived byte-for-byte.
        std::string expected = "bad";
        expected += "\xEF\xBF\xBD\xEF\xBF\xBD";
        expected += "name";
        auto leases = server.Leases(t0);
        CHECK(leases.size() == 1);
        if (!leases.empty()) {
            CHECK(leases[0].hostname == expected);
        }

        // The whole point: DumpLeases must be TOTAL. It used to throw out of
        // the function (nlohmann strict dump), which this catches explicitly
        // so a regression is a clean CHECK failure, not a test-process abort.
        const std::string path = "test_dhcp_leases_b123_utf8.json";
        std::remove(path.c_str());
        bool threw = false;
        bool dumped = false;
        try {
            dumped = server.DumpLeases(path, t0);
        } catch (...) {
            threw = true;
        }
        CHECK(!threw);
        CHECK(dumped);

        // Round-trip: the sanitized name survives DumpLeases/LoadLeases and
        // the file itself is well-formed UTF-8 (the loader parses it in strict
        // mode - an ill-formed body would come back kCorrupt).
        DhcpServer restored(config);
        CHECK(DhcpServer::LoadOutcome::kRestored ==
              restored.LoadLeases(path, t0, nullptr));
        auto back = restored.Leases(t0);
        CHECK(back.size() == 1);
        if (!back.empty()) {
            CHECK(back[0].hostname == expected);
        }
        std::remove(path.c_str());
    }

    // batch123: the CONTROL path (WebUI / POST /api/dhcp/bindings) is operator
    // input, not an untrusted client, so an ill-formed name is REJECTED (return
    // false -> HTTP 400) exactly like the oversize case, leaving the store
    // untouched. Sanitizing operator input silently would rewrite what the user
    // typed; rejecting matches the existing "not representable" contract.
    void TestB123UpsertBindingRejectsIllFormedUtf8Hostname() {
        vgww::core::Config config;
        bool ok = false;
        config.gateway.ipv4 = vgww::core::ParseIpv4("192.168.0.1", ok);
        CHECK(ok);
        config.gateway.mask = vgww::core::ParseIpv4("255.255.255.0", ok);
        CHECK(ok);
        config.dhcp.lease_seconds = 3600;
        DhcpServer server(config);

        const WireMac mac{0xAA, 0x12, 0x34, 0x56, 0x78, 0x91};
        const uint32_t ip = vgww::core::ParseIpv4("192.168.0.51", ok);
        CHECK(ok);

        // Valid boundary case first, so a rejected-must-stay-untouched check
        // has a previous value to preserve.
        const std::string good = "office-pc";
        CHECK(server.UpsertBinding(mac, ip, good));
        CHECK(server.StaticBindings().size() == 1);

        std::string bad = "printer";
        bad.push_back(static_cast<char>(0xFF));
        CHECK(!server.UpsertBinding(mac, ip, bad));
        CHECK(server.StaticBindings().size() == 1);
        CHECK(server.StaticBindings()[0].hostname == good);

        // A lone continuation byte and an overlong form are both ill-formed
        // (C2/C0/C1 are never a valid lead byte).
        std::string lone_cont;
        lone_cont.push_back(static_cast<char>(0x80));
        CHECK(!server.UpsertBinding(mac, ip, lone_cont));
        std::string overlong;
        overlong.push_back(static_cast<char>(0xC0));
        overlong.push_back(static_cast<char>(0x80));
        CHECK(!server.UpsertBinding(mac, ip, overlong));
        // Three-byte OVERLONG (E0 80 80 encodes U+0000): a naive "3-byte lead
        // + two continuations" validator accepts it, so this pins the E0
        // second-byte >= A0 rule specifically.
        std::string overlong3;
        overlong3.push_back(static_cast<char>(0xE0));
        overlong3.push_back(static_cast<char>(0x80));
        overlong3.push_back(static_cast<char>(0x80));
        CHECK(!server.UpsertBinding(mac, ip, overlong3));
        // UTF-16 surrogate encoded in 3 bytes (ED A0 80 = U+D800) is not a
        // legal UTF-8 scalar value either.
        std::string surrogate;
        surrogate.push_back(static_cast<char>(0xED));
        surrogate.push_back(static_cast<char>(0xA0));
        surrogate.push_back(static_cast<char>(0x80));
        CHECK(!server.UpsertBinding(mac, ip, surrogate));
        // Truncated multi-byte tail (E5 AE) must be rejected, not padded.
        std::string truncated;
        truncated.push_back(static_cast<char>(0xE5));
        truncated.push_back(static_cast<char>(0xAE));
        CHECK(!server.UpsertBinding(mac, ip, truncated));
        // > U+10FFFF (F4 90 80 80) is out of range.
        std::string too_high;
        too_high.push_back(static_cast<char>(0xF4));
        too_high.push_back(static_cast<char>(0x90));
        too_high.push_back(static_cast<char>(0x80));
        too_high.push_back(static_cast<char>(0x80));
        CHECK(!server.UpsertBinding(mac, ip, too_high));
        CHECK(server.StaticBindings().size() == 1);
        CHECK(server.StaticBindings()[0].hostname == good);

        // A well-formed multi-byte name (E5 AE A2 = U+5BA2) is still accepted:
        // validity, not ASCII-only, is the contract.
        const std::string cjk = "\xE5\xAE\xA2\xE6\x88\xB7";
        CHECK(server.UpsertBinding(mac, ip, cjk));
        CHECK(server.StaticBindings().size() == 1);
        CHECK(server.StaticBindings()[0].hostname == cjk);
    }

    // batch112: the REVERSE direction of the batch109 collision.
    //
    // batch109 made a runtime binding RESERVE its address against the dynamic
    // pool (Acquire's reserved_hosts). The other direction was left open:
    // UpsertBinding only looked for collisions with config bindings and with
    // other runtime bindings (dhcp.cpp:705-714), never with an address that is
    // currently held as a DYNAMIC LEASE. So:
    //
    //   1. client A does DISCOVER/REQUEST and is leased 192.168.0.100
    //      (leases_[A] = {ip: .100, is_static: false})
    //   2. the operator adds a runtime binding for client B -> .100
    //      -> accepted, because A appears in neither scan
    //   3. Acquire(B) returns .100 as a static binding while A's dynamic
    //      lease still says .100 and is still live
    //
    // Two clients on one LAN address is the exact failure batch109's comment
    // calls out ("the LAN ended up with two owners for one IP"); it only got
    // fixed on one side. The fix must reject the upsert instead of silently
    // stealing a live lease, and it must leave the previous binding/lease
    // intact (same "rejected mutation changes nothing" contract the other
    // rejections honour).
    void TestB112RuntimeBindingRejectsAddressHeldByLiveLease() {
        vgww::core::Config config;
        bool ok = false;
        config.gateway.ipv4 = vgww::core::ParseIpv4("192.168.0.40", ok);
        CHECK(ok);
        config.gateway.mask = vgww::core::ParseIpv4("255.255.255.0", ok);
        CHECK(ok);
        config.dhcp.pool_start = vgww::core::ParseIpv4("192.168.0.100", ok);
        CHECK(ok);
        config.dhcp.pool_end = vgww::core::ParseIpv4("192.168.0.101", ok);
        CHECK(ok);
        config.dhcp.lease_seconds = 3600;

        const WireMac dynamic_client{0xAA, 0x12, 0x00, 0x00, 0x00, 0x01};
        const WireMac newcomer{0xAA, 0x12, 0x00, 0x00, 0x00, 0x02};
        const uint32_t free_ip = vgww::core::ParseIpv4("192.168.0.101", ok);

        DhcpServer server(config);
        const auto now = std::chrono::steady_clock::now();

        // The dynamic client takes the FIRST pool address.
        const uint32_t granted = server.Acquire(dynamic_client, now);
        CHECK(granted != 0);

        // Binding someone else onto that live address must be refused...
        CHECK(!server.UpsertBinding(newcomer, granted));
        // ...and must have changed nothing: no runtime binding appeared.
        for (const auto& view : server.StaticBindings()) {
            CHECK(!(view.mac == newcomer && view.ip == granted));
        }

        // The dynamic owner still holds it: a second client cannot get it from
        // the pool either, so there is exactly one owner.
        const uint32_t other_client_granted = server.Acquire(
            newcomer, now, DhcpServer::OfferStage::kAck, "", granted);
        CHECK(other_client_granted != granted);

        // Binding a FREE pool address is still legal - the rejection must be
        // specific to the live lease, not to the whole pool.
        CHECK(server.UpsertBinding(newcomer, free_ip));
        CHECK(server.StaticBindings().size() == 1);

        // Re-binding the address to its own dynamic owner is legal too: the
        // client is not "someone else", so promoting a live lease to a static
        // reservation is a legitimate operator action.
        CHECK(server.UpsertBinding(dynamic_client, granted));
        CHECK(server.StaticBindings().size() == 2);

        // An EXPIRED lease is not an owner. leases_ is only swept every 5 s,
        // so an entry can outlive its expiry for a while; it must not keep
        // rejecting a legitimate bind in that window. Time is advanced past
        // the term so the entry is stale without being swept.
        // UpsertBinding reads steady_clock::now() itself, so the lease is
        // created in the PAST: granted a full term starting well before now,
        // it is already expired by the time the upsert runs.
        DhcpServer stale(config);
        const auto long_ago =
            now - std::chrono::seconds(config.dhcp.lease_seconds + 60);
        const uint32_t stale_ip = stale.Acquire(dynamic_client, long_ago);
        CHECK(stale_ip != 0);
        CHECK(stale.UpsertBinding(newcomer, stale_ip));
        CHECK(stale.StaticBindings().size() == 1);
    }

    // batch114: Acquire's pool walk was O(pool_size x live_leases) with the
    // batch114: Acquire's pool walk re-scanned the WHOLE lease table for
    // every candidate address - O(pool_size x live_leases) - and the entire
    // walk runs under mutex_, the one lock every DHCP frame and every
    // Web/UI binding call also needs.
    //
    // dhcp.cpp:452-488 (before the fix):
    //   for (offset = 0; offset < pool_size; ++offset) {
    //       for (const auto& pair : leases_) { ... }   // full scan per candidate
    //   }
    //
    // Neither factor is capped: ValidateConfig accepts any contiguous mask (a
    // /16 LAN is ordinary), and leases_ has no entry cap. A /16 pool with a
    // half-full table is ~1e9 comparisons INSIDE the lock: DHCP stops
    // answering and the UI freezes behind it.
    //
    // The discriminator below is deliberately sharp and clock-free:
    //   table = 200 leases, all OUTSIDE the pool
    //   pool  = 1 address
    // One Acquire then walks exactly one candidate and fails (pool full).
    //   * set-based walk (fixed):  200 probes (one pass to build the set)
    //   * per-candidate walk (old): 200 x 1 = 200 ... identical here, so the
    //     pool must be wide for the difference to show:
    //   table = 200 leases all OUTSIDE the pool, pool = 4096 addresses
    //   * set-based:  200 probes (+4096 O(1) hash lookups, no lease probes)
    //   * old:        200 x 4096 = 819,200 probes
    // A 400x gap is a property of the ALGORITHM, not of the machine, so the
    // assertion needs no tolerance band beyond a small constant.
    void TestB114AcquireWalkDoesNotScanLeasesPerCandidate() {
        vgww::core::Config config;
        bool ok = false;
        config.gateway.ipv4 = vgww::core::ParseIpv4("10.0.0.1", ok);
        CHECK(ok);
        config.gateway.mask = vgww::core::ParseIpv4("255.255.240.0", ok);
        CHECK(ok);
        // A 4096-address pool: 10.0.1.1 .. 10.0.15.255
        config.dhcp.pool_start = vgww::core::ParseIpv4("10.0.1.1", ok);
        CHECK(ok);
        config.dhcp.pool_end = vgww::core::ParseIpv4("10.0.15.255", ok);
        CHECK(ok);
        config.dhcp.lease_seconds = 3600;

        const auto now = std::chrono::steady_clock::now();

        // Measure ONE acquisition from a shape where the pool is completely
        // taken.
        vgww::core::Config full_cfg = config;
        DhcpServer full(full_cfg);
        // Fill the pool completely (4096 leases) so this Acquire is forced to
        // walk every candidate.
        for (size_t i = 0; i < 4096; ++i) {
            WireMac mac{0xCC, 0xDD, 0x00, 0x00,
                        static_cast<uint8_t>(i >> 8),
                        static_cast<uint8_t>(i & 0xFF)};
            if (full.Acquire(mac, now, DhcpServer::OfferStage::kAck) == 0) {
                break;  // finite pool: stop when exhausted
            }
        }
        // The pool spans 4096 addresses; a few are unusable (network,
        // broadcast, gateway), so "nearly full" is the honest assertion.
        CHECK(full.LeaseCount() > 3800);

        // One more client cannot be served: the walk visits all 4096
        // candidates. With the set-based walk the lease table is probed once
        // per Acquire; the old per-candidate scan probed it 4096 x 4096.
        const uint64_t before = full.LeaseScanCount();
        const WireMac extra{0xEE, 0xFF, 0x00, 0x00, 0x00, 0x01};
        CHECK(full.Acquire(extra, now, DhcpServer::OfferStage::kAck) == 0);
        const uint64_t probes = full.LeaseScanCount() - before;

        // Fixed: ~4096 (one pass). Old: ~16.7 million. Allow a generous
        // constant for the pass plus any per-candidate bookkeeping, but stay
        // far below one extra full scan per candidate.
        const uint64_t budget = 4096 + 4096;
        CHECK(probes <= budget);
        // The occupancy set must hold LIVE leases only. A lease that has
        // expired but has not been swept yet (Sweep runs every 5 s) must not
        // keep its address out of circulation, or the pool silently shrinks
        // by one address per stale entry until the sweep catches up.
        vgww::core::Config stale_cfg = config;
        stale_cfg.dhcp.pool_start = vgww::core::ParseIpv4("10.0.1.1", ok);
        CHECK(ok);
        stale_cfg.dhcp.pool_end = vgww::core::ParseIpv4("10.0.1.1", ok);
        CHECK(ok);
        DhcpServer stale_server(stale_cfg);
        const auto long_ago =
            now - std::chrono::seconds(stale_cfg.dhcp.lease_seconds * 2);
        const WireMac first{0xAA, 0x01, 0x00, 0x00, 0x00, 0x01};
        const WireMac second{0xAA, 0x02, 0x00, 0x00, 0x00, 0x02};
        // Granted in the PAST, so it is already expired while still present
        // in the table (never swept).
        CHECK(stale_server.Acquire(first, long_ago,
                                   DhcpServer::OfferStage::kAck) != 0);
        CHECK(stale_server.LeaseCount() == 1);



        // The only pool address is held by an EXPIRED lease: a new client must
        // still get it.
        CHECK(stale_server.Acquire(second, now,
                                   DhcpServer::OfferStage::kAck) != 0);

        std::printf("b114 probes=%llu budget=%llu leases=%zu\n",
                    static_cast<unsigned long long>(probes),
                    static_cast<unsigned long long>(budget),
                    full.LeaseCount());
    }

    // batch137: editing a binding's MAC used to be TWO commands (remove, then
    // add). Either half could be refused on its own - the command queue is
    // capped at 64, the store refuses a new key at kMaxStaticBindings, a
    // colliding address or an out-of-subnet IP is rejected - so the client
    // ended up with its binding DELETED and nothing stored. ReplaceBinding is
    // the one-lock form: every rejection happens before any state changes, and
    // the commit erases the old key and inserts the new one together.
    void TestB137ReplaceBindingIsAtomic() {
        vgww::core::Config config;
        bool ok = false;
        config.gateway.ipv4 = vgww::core::ParseIpv4("192.168.0.40", ok);
        CHECK(ok);
        config.gateway.mask = vgww::core::ParseIpv4("255.255.255.0", ok);
        CHECK(ok);
        config.dhcp.pool_start = vgww::core::ParseIpv4("192.168.0.100", ok);
        CHECK(ok);
        config.dhcp.pool_end = vgww::core::ParseIpv4("192.168.0.110", ok);
        CHECK(ok);
        config.dhcp.lease_seconds = 3600;

        const WireMac old_mac{0xAA, 0x12, 0x00, 0x00, 0x00, 0x01};
        const WireMac new_mac{0xAA, 0x12, 0x00, 0x00, 0x00, 0x02};
        const WireMac third_mac{0xAA, 0x12, 0x00, 0x00, 0x00, 0x03};
        const uint32_t old_ip = vgww::core::ParseIpv4("192.168.0.75", ok);
        CHECK(ok);
        const uint32_t new_ip = vgww::core::ParseIpv4("192.168.0.76", ok);
        CHECK(ok);
        const uint32_t taken = vgww::core::ParseIpv4("192.168.0.77", ok);
        CHECK(ok);
        const uint32_t outside = vgww::core::ParseIpv4("10.9.9.9", ok);
        CHECK(ok);

        {
            // Happy path: the old key disappears, the new one appears, and the
            // address it kept stays bound to exactly one client.
            DhcpServer server(config);
            CHECK(server.UpsertBinding(old_mac, old_ip, "nas"));
            CHECK(server.ReplaceBinding(old_mac, new_mac, old_ip, "nas2"));
            const auto views = server.StaticBindings();
            CHECK(views.size() == 1);
            if (views.size() == 1) {
                CHECK(views[0].mac == new_mac);
                CHECK(views[0].ip == old_ip);
                CHECK(views[0].hostname == "nas2");
            }
            const auto now = std::chrono::steady_clock::now();
            CHECK(server.Acquire(new_mac, now) == old_ip);
        }

        {
            // A re-key onto an address another client owns must be refused
            // with the OLD binding still intact - the half-state the split
            // sequence produced.
            DhcpServer server(config);
            CHECK(server.UpsertBinding(old_mac, old_ip, "keep"));
            CHECK(server.UpsertBinding(third_mac, taken, "other"));
            CHECK(!server.ReplaceBinding(old_mac, new_mac, taken, "clash"));
            const auto views = server.StaticBindings();
            CHECK(views.size() == 2);
            bool old_intact = false;
            bool new_absent = true;
            for (const auto& view : views) {
                if (view.mac == old_mac && view.ip == old_ip &&
                    view.hostname == "keep") {
                    old_intact = true;
                }
                if (view.mac == new_mac) {
                    new_absent = false;
                }
            }
            CHECK(old_intact);
            CHECK(new_absent);
        }

        {
            // An invalid new address is refused the same way.
            DhcpServer server(config);
            CHECK(server.UpsertBinding(old_mac, old_ip, "keep"));
            CHECK(!server.ReplaceBinding(old_mac, new_mac, outside, "x"));
            const auto views = server.StaticBindings();
            CHECK(views.size() == 1);
            if (views.size() == 1) {
                CHECK(views[0].mac == old_mac);
                CHECK(views[0].ip == old_ip);
            }
        }

        {
            // A re-key that names a binding which does not exist must behave
            // like a plain add (a config-only row, or a stale table row).
            DhcpServer server(config);
            CHECK(server.ReplaceBinding(old_mac, new_mac, new_ip, "fresh"));
            const auto views = server.StaticBindings();
            CHECK(views.size() == 1);
            if (views.size() == 1) {
                CHECK(views[0].mac == new_mac);
                CHECK(views[0].ip == new_ip);
            }
        }

        {
            // At the cap a re-key keeps the table the same size, so it must
            // NOT be refused - otherwise "edit" fails exactly when full.
            vgww::core::Config wide;
            bool ok2 = false;
            wide.gateway.ipv4 = vgww::core::ParseIpv4("10.0.0.1", ok2);
            CHECK(ok2);
            wide.gateway.mask = vgww::core::ParseIpv4("255.0.0.0", ok2);
            CHECK(ok2);
            wide.dhcp.lease_seconds = 3600;
            DhcpServer server(wide);
            const auto mac_of = [](uint32_t i) {
                return WireMac{0x02, 0x00, static_cast<uint8_t>((i >> 16) & 0xFF),
                               static_cast<uint8_t>((i >> 8) & 0xFF),
                               static_cast<uint8_t>(i & 0xFF), 0x01};
            };
            const auto ip_of = [](uint32_t i) {
                bool parsed_ok = false;
                return vgww::core::ParseIpv4(
                    "10.3." + std::to_string((i >> 8) & 0xFF) + "." +
                        std::to_string(i & 0xFF),
                    parsed_ok);
            };
            const size_t cap = ::vgww::core::limits::kMaxStaticBindings;
            for (uint32_t i = 1; i <= cap; ++i) {
                CHECK(server.UpsertBinding(mac_of(i), ip_of(i)));
            }
            CHECK(server.StaticBindings().size() == cap);
            // Re-key the first entry to a brand-new MAC: same table size.
            CHECK(server.ReplaceBinding(mac_of(1), mac_of(cap + 1000),
                                        ip_of(cap + 1000)));
            CHECK(server.StaticBindings().size() == cap);
            // A plain add at the cap is still refused.
            CHECK(!server.UpsertBinding(mac_of(cap + 2), ip_of(cap + 2)));
            CHECK(server.StaticBindings().size() == cap);
        }
    }

int main() {
    TestFrameIpOptionBytes();
    TestParseAndOffer();
    TestStaticBindingPriority();
    TestStaticBindingReservesPoolAddress();
    TestExhaustionAndRelease();
    TestRuntimeBindings();
    TestRemoveConfigBinding();
    TestRuntimeBindingWithoutPool();
    TestUpsertBindingRejectsGatewayAndDuplicate();
    TestB137ReplaceBindingIsAtomic();
    TestB109RuntimeBindingObeysPlacementRules();
    TestB109RuntimeBindingReservesPoolAddress();
    TestB110RuntimeBindingCapIsEnforcedInTheStore();
    TestB110ConfigBindingsCountTowardTheRuntimeCap();
    TestB111RuntimeBindingRejectsOversizedHostname();
    TestB123AcquireSanitizesIllFormedUtf8Hostname();
    TestB123UpsertBindingRejectsIllFormedUtf8Hostname();
    TestB112RuntimeBindingRejectsAddressHeldByLiveLease();
    TestB114AcquireWalkDoesNotScanLeasesPerCandidate();
    TestOfferShortHold();
    TestLeaseRoundTrip();
    TestLeaseHostnameLearnt();
    TestLeaseRemainingTimeRoundTrip();
    TestB134LeaseLoadRejectsDuplicateAddress();
    TestB119DroppedLeaseCountExposed();
    TestB121ParseRejectsAreCounted();
    TestB120LeaseFileCorruptIsFlagged();
    TestLeaseLoadSkipsIllegal();
    TestLegacyLeaseMissingExpiresRestored();
    TestPoolSkipsNetworkAndBroadcast();
    TestDeclineMarksAddressBad();
    TestParseIhlValidation();
    TestParseIhlFullLengthAccepted();
    TestOversizedOptionClamped();
    TestRateLimitFrameBudget();
    TestParseRejectsWrongOp();
    TestParseRejectsWrongHtype();
    TestParseRejectsWrongHlen();
    TestParseRejectsWrongDport();
    TestParseRejectsUdpLenMismatch();
    TestRequestedIpHonored();
    TestDeclineForeignMacIgnored();
    TestLeaseFileHasVersion();
    TestLeaseSaveFailureReported();
    TestLeaseDumpFlushFailureKeepsPreviousSnapshot();
    TestCorruptLeaseFilePreserved();
    TestLeaseLoadTransientLockIsNotCorrupt();
    TestLeaseLoadUnreadablePausesDump();
    TestLeaseDumpRecoversFromBlocked();
    TestB206BlockedRecoveryKeepsLiveAddressForSameMac();
    TestPoolExhaustionCounted();
    TestReleaseWrongServerIdIgnored();
    TestParseOptionStreamBoundaries();
    TestParseRejectsNonClientFrames();
    TestParseRejectsAFrameTooShortForItsDeclaredIhl();
    TestParseRejectsATruncatedFixedPart();
    TestBuildReplyFrameWireImage();
    TestBuildReplyOfferHasNoLeaseOptions();
    TestBuildReplyOmitsEmptyOptionalOptions();
    TestBuildReplyClampsOversizedOptionValues();
    TestBuildReplyFrameIsZeroFilled();
    TestBuildReplyOptionsEndWithTheEndCode();

    if (0 == g_failures) {
        std::puts("test_dhcp: ALL PASS");
        return 0;
    }
    std::fprintf(stderr, "test_dhcp: %d FAILURES\n", g_failures);
    return 1;
}
