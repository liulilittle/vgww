// ============================================================================
// test_dhcp6.cpp - DHCPv6 frame parse/build + stateful server semantics.
//
// Encodes the RFC 8415 subset: SOLICIT->ADVERTISE, REQUEST->REPLY, RENEW,
// REBIND, RELEASE, DECLINE (park 600s), INFORMATION-REQUEST, rapid commit,
// static DUID bindings, pool exhaustion (NoAddrsAvail), versioned lease
// persistence and the per-DUID rate limit.
// ============================================================================
#include "proto/dhcp6.h"

#include "core/text.h"

#include "dsp/classifier.h"
#include "net/checksum.h"
#include "proto/ndp.h"
#include "proto/udp.h"

#include <atomic>
#include <cstdio>
#include <cstring>
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <vector>

namespace {

    // batch326: scratch paths come from the OS temp folder (portable).
    // P139: every document this process writes gets its OWN directory
    // under the temp root, keyed by pid. A shared "vgww-tests" leaf let
    // parallel instances write and delete the same lease file, which is
    // exactly the cross-talk that turned this suite red under a parallel run.
    std::string ScratchDir() {
        const std::string leaf = "vgww-tests-dhcp6-" +
                                 std::to_string(::GetCurrentProcessId());
        const std::filesystem::path dir =
            std::filesystem::temp_directory_path() / leaf;
        std::error_code ec;
        std::filesystem::create_directories(dir, ec);
        return dir.string();
    }

    std::string ScratchFile(const char* name) {
        return (std::filesystem::path(ScratchDir()) / name).string();
    }

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
    using namespace vgww::dhcp6;

    const WireMac kGatewayMac{0x30, 0xFC, 0x68, 0x88, 0xB4, 0xA9};
    const WireMac kClientMac{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01};
    const std::array<uint8_t, 16> kPrefix = {
        0xFD, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0, 0, 0, 0, 0, 0, 0, 0};
    const std::array<uint8_t, 16> kPoolStart = {
        0xFD, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0, 0, 0, 0, 0, 0,
        0x10, 0x00};
    const std::array<uint8_t, 16> kPoolEnd = {
        0xFD, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0, 0, 0, 0, 0, 0,
        0x1F, 0xFF};
    const std::array<uint8_t, 16> kClientLl = {
        0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0xAA, 0xBB, 0xCC, 0xFF, 0xFE, 0xDD,
        0xEE, 0x01};
    const std::array<uint8_t, 16> kMulticast = {
        0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x00, 0x02};
    const WireMac kDhcp6MulticastMac{0x33, 0x33, 0x00, 0x01, 0x00, 0x02};

    const std::vector<uint8_t> kClientDuid = {0x00, 0x03, 0x00, 0x01, 0xAA,
                                              0xBB, 0xCC, 0xDD, 0xEE, 0x01};
    const std::vector<uint8_t> kOtherDuid = {0x00, 0x03, 0x00, 0x01, 0xAA,
                                             0xBB, 0xCC, 0xDD, 0xEE, 0x02};
    const std::vector<uint8_t> kStaticDuid = {0x00, 0x03, 0x00, 0x01, 0x11,
                                              0x22, 0x33, 0x44, 0x55, 0x66};
    /// The gateway DUID derived from kGatewayMac (DUID-LL, RFC 8415 11.2).
    const std::vector<uint8_t> kServerDuid = {0x00, 0x03, 0x00, 0x01, 0x30,
                                              0xFC, 0x68, 0x88, 0xB4, 0xA9};

    const std::array<uint8_t, 16> kDns1 = {
        0xFD, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0, 0, 0, 0, 0, 0, 0,
        0x53};
    const std::array<uint8_t, 16> kDns2 = {
        0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0A};

    constexpr size_t kDhcp6Offset =
        kEthernetHeaderLen + 40 + kUdpHeaderLen;  // 62

    void PushU16(std::vector<uint8_t>& v, uint16_t x) {
        v.push_back(static_cast<uint8_t>(x >> 8));
        v.push_back(static_cast<uint8_t>(x & 0xFF));
    }

    void PushU32(std::vector<uint8_t>& v, uint32_t x) {
        v.push_back(static_cast<uint8_t>(x >> 24));
        v.push_back(static_cast<uint8_t>((x >> 16) & 0xFF));
        v.push_back(static_cast<uint8_t>((x >> 8) & 0xFF));
        v.push_back(static_cast<uint8_t>(x & 0xFF));
    }

    void PushOption(std::vector<uint8_t>& out, uint16_t code,
                    const std::vector<uint8_t>& data) {
        PushU16(out, code);
        PushU16(out, static_cast<uint16_t>(data.size()));
        out.insert(out.end(), data.begin(), data.end());
    }

    /// IA_NA payload: IAID(4) T1(4) T2(4) + optional IAADDR.
    std::vector<uint8_t> IaNaPayload(uint32_t iaid, bool with_addr,
                                     const std::array<uint8_t, 16>* addr) {
        std::vector<uint8_t> v;
        PushU32(v, iaid);
        PushU32(v, 0);  // T1 (client hint, ignored)
        PushU32(v, 0);  // T2
        if (with_addr && nullptr != addr) {
            std::vector<uint8_t> ia_addr(addr->begin(), addr->end());
            PushU32(ia_addr, 3600);  // preferred
            PushU32(ia_addr, 3600);  // valid
            PushOption(v, kDhcp6OptIaAddr, ia_addr);
        }
        return v;
    }

    /// Builds a full client request frame (UDP 546 -> 547) with the given
    /// raw DHCPv6 payload bytes.
    std::vector<uint8_t> BuildFrameRaw(const std::vector<uint8_t>& payload,
                                       const std::array<uint8_t, 16>& src,
                                       uint16_t sport, uint16_t dport,
                                       uint16_t udp_len_override = 0) {
        std::vector<uint8_t> frame;
        BuildUdpFrameV6(frame, kDhcp6MulticastMac, kClientMac, src.data(),
                        sport, kMulticast.data(), dport, payload.data(),
                        payload.size());
        if (0 != udp_len_override) {
            uint8_t* udp = frame.data() + kEthernetHeaderLen + 40;
            udp[4] = static_cast<uint8_t>(udp_len_override >> 8);
            udp[5] = static_cast<uint8_t>(udp_len_override & 0xFF);
        }
        return frame;
    }

    /// Builds a full client request frame with an explicit IPv6 destination
    /// (used to exercise the RFC 8415 16 multicast-only rule).
    std::vector<uint8_t> BuildFrameRawTo(const std::vector<uint8_t>& payload,
                                         const std::array<uint8_t, 16>& src,
                                         const std::array<uint8_t, 16>& dst) {
        std::vector<uint8_t> frame;
        BuildUdpFrameV6(frame, kDhcp6MulticastMac, kClientMac, src.data(),
                        kDhcp6ClientPort, dst.data(), kDhcp6ServerPort,
                        payload.data(), payload.size());
        return frame;
    }

    /// Builds a client request with the standard option set.
    std::vector<uint8_t> BuildRequest(
        uint8_t msg_type, uint32_t xid, const std::vector<uint8_t>& duid,
        bool with_ia, uint32_t iaid, bool with_addr,
        const std::array<uint8_t, 16>* addr, bool rapid,
        const std::vector<uint8_t>& server_duid = std::vector<uint8_t>(),
        bool with_oro = false) {
        std::vector<uint8_t> payload;
        payload.push_back(msg_type);
        payload.push_back(static_cast<uint8_t>((xid >> 16) & 0xFF));
        payload.push_back(static_cast<uint8_t>((xid >> 8) & 0xFF));
        payload.push_back(static_cast<uint8_t>(xid & 0xFF));
        PushOption(payload, kDhcp6OptClientId, duid);
        if (!server_duid.empty()) {
            PushOption(payload, kDhcp6OptServerId, server_duid);
        }
        if (with_ia) {
            PushOption(payload, kDhcp6OptIaNa,
                       IaNaPayload(iaid, with_addr, addr));
        }
        if (rapid) {
            PushOption(payload, kDhcp6OptRapidCommit, {});
        }
        if (with_oro) {
            std::vector<uint8_t> oro;
            PushU16(oro, kDhcp6OptDnsServers);
            PushOption(payload, kDhcp6OptOro, oro);
        }
        return BuildFrameRaw(payload, kClientLl, kDhcp6ClientPort,
                             kDhcp6ServerPort);
    }

    struct ParsedReply {
        uint8_t msg_type = 0;
        uint32_t xid = 0;
        bool has_client_id = false;
        std::vector<uint8_t> client_duid;
        bool has_server_id = false;
        std::vector<uint8_t> server_duid;
        bool has_ia = false;
        uint32_t iaid = 0;
        uint32_t t1 = 0;
        uint32_t t2 = 0;
        bool has_addr = false;
        std::array<uint8_t, 16> addr{};
        uint32_t preferred = 0;
        uint32_t valid = 0;
        bool has_status = false;
        uint16_t status = 0;
        bool ia_status = false;
        bool top_status = false;
        std::vector<std::array<uint8_t, 16>> dns;
        bool rapid_commit = false;
        uint16_t sport = 0;
        uint16_t dport = 0;
    };

    uint32_t ReadU32(const uint8_t* p) {
        return (static_cast<uint32_t>(p[0]) << 24) |
               (static_cast<uint32_t>(p[1]) << 16) |
               (static_cast<uint32_t>(p[2]) << 8) |
               static_cast<uint32_t>(p[3]);
    }

    /// Walks an option stream strictly (test-side, independent of the
    /// implementation's parser).
    bool WalkOptions(const uint8_t* p, size_t len, ParsedReply& out,
                     bool inside_ia) {
        size_t pos = 0;
        while (pos + 4 <= len) {
            const uint16_t code = static_cast<uint16_t>((p[pos] << 8) | p[pos + 1]);
            const uint16_t olen =
                static_cast<uint16_t>((p[pos + 2] << 8) | p[pos + 3]);
            pos += 4;
            if (pos + olen > len) {
                return false;
            }
            const uint8_t* data = p + pos;
            switch (code) {
                case kDhcp6OptClientId:
                    out.has_client_id = true;
                    out.client_duid.assign(data, data + olen);
                    break;
                case kDhcp6OptServerId:
                    out.has_server_id = true;
                    out.server_duid.assign(data, data + olen);
                    break;
                case kDhcp6OptIaNa:
                    if (olen >= 12) {
                        out.has_ia = true;
                        out.iaid = ReadU32(data);
                        out.t1 = ReadU32(data + 4);
                        out.t2 = ReadU32(data + 8);
                        if (!WalkOptions(data + 12, olen - 12, out, true)) {
                            return false;
                        }
                    }
                    break;
                case kDhcp6OptIaAddr:
                    if (olen >= 24) {
                        std::memcpy(out.addr.data(), data, 16);
                        out.has_addr = true;
                        out.preferred = ReadU32(data + 16);
                        out.valid = ReadU32(data + 20);
                    }
                    break;
                case kDhcp6OptStatusCode:
                    if (olen >= 2) {
                        out.has_status = true;
                        out.status = static_cast<uint16_t>((data[0] << 8) | data[1]);
                        out.ia_status = inside_ia;
                        out.top_status = !inside_ia;
                    }
                    break;
                case kDhcp6OptRapidCommit:
                    out.rapid_commit = true;
                    break;
                case kDhcp6OptDnsServers:
                    for (size_t i = 0; i + 16 <= olen; i += 16) {
                        std::array<uint8_t, 16> a{};
                        std::memcpy(a.data(), data + i, 16);
                        out.dns.push_back(a);
                    }
                    break;
                default:
                    break;
            }
            pos += olen;
        }
        return pos == len;
    }

    /// Extracts and validates the DHCPv6 payload of a reply frame.
    bool ParseReply(const std::vector<uint8_t>& frame, ParsedReply& out) {
        out = ParsedReply{};
        if (frame.size() < kDhcp6Offset + 4) {
            return false;
        }
        const uint8_t* ip = frame.data() + kEthernetHeaderLen;
        if (0x60 != (ip[0] & 0xF0) || 17 != ip[6]) {
            return false;
        }
        const uint8_t* udp = ip + 40;
        out.sport = static_cast<uint16_t>((udp[0] << 8) | udp[1]);
        out.dport = static_cast<uint16_t>((udp[2] << 8) | udp[3]);
        const uint16_t ulen = static_cast<uint16_t>((udp[4] << 8) | udp[5]);
        if (ulen < 4 || kEthernetHeaderLen + 40 + ulen != frame.size()) {
            return false;
        }
        const uint8_t* payload = udp + kUdpHeaderLen;
        out.msg_type = payload[0];
        out.xid = (static_cast<uint32_t>(payload[1]) << 16) |
                  (static_cast<uint32_t>(payload[2]) << 8) |
                  static_cast<uint32_t>(payload[3]);
        return WalkOptions(payload + 4, ulen - kUdpHeaderLen - 4, out, false);
    }

    Config MakeConfig() {
        Config c;
        c.mode = Mode::kMain;
        c.gateway.mac = kGatewayMac;
        c.ipv6.enabled = true;
        c.ipv6.ula_prefix = kPrefix;
        c.ipv6.prefix_len = 64;
        c.ipv6.dhcpv6.enabled = true;
        c.ipv6.dhcpv6.pool_start = kPoolStart;
        c.ipv6.dhcpv6.pool_end = kPoolEnd;
        c.ipv6.dhcpv6.lease_seconds = 3600;
        c.ipv6.dns = {kDns1, kDns2};
        return c;
    }

    bool IsZeroAddr(const std::array<uint8_t, 16>& a) {
        for (const uint8_t b : a) {
            if (0 != b) return false;
        }
        return true;
    }

    bool InPool(const std::array<uint8_t, 16>& a) {
        return 0 == std::memcmp(a.data(), kPrefix.data(), 8) &&
               a[14] >= 0x10 && a[14] <= 0x1F;
    }

    // --- 1. strict parse: truncation / option bounds / DUID bounds --------
    void TestParseDhcp6Malformed() {
        Dhcp6View view;
        auto ok = BuildRequest(kDhcp6MsgSolicit, 0x010203, kClientDuid, true,
                               1, false, nullptr, false);
        CHECK(ParseDhcp6Frame(ok.data(), ok.size(), view));
        CHECK(view.msg_type == kDhcp6MsgSolicit);
        CHECK(view.xid == 0x010203);
        CHECK(view.client_duid == kClientDuid);
        CHECK(view.has_ia_na);
        CHECK(view.iaid == 1);

        // Truncated below the minimum frame size.
        CHECK(!ParseDhcp6Frame(ok.data(), kDhcp6FrameMin - 1, view));

        // UDP length disagrees with the frame (F1 discipline).
        auto bad_len = BuildFrameRaw(
            {kDhcp6MsgSolicit, 0, 0, 1, 0, 1, 0, 0, 0x00}, kClientLl,
            kDhcp6ClientPort, kDhcp6ServerPort, 4);
        CHECK(!ParseDhcp6Frame(bad_len.data(), bad_len.size(), view));

        // Option length runs past the end of the buffer.
        std::vector<uint8_t> payload = {kDhcp6MsgSolicit, 0, 0, 2};
        PushU16(payload, kDhcp6OptClientId);
        PushU16(payload, 200);  // claims 200 bytes, none follow
        auto over = BuildFrameRaw(payload, kClientLl, kDhcp6ClientPort,
                                  kDhcp6ServerPort);
        CHECK(!ParseDhcp6Frame(over.data(), over.size(), view));

        // Zero-length DUID is dropped.
        std::vector<uint8_t> zero_duid = {kDhcp6MsgSolicit, 0, 0, 3};
        PushOption(zero_duid, kDhcp6OptClientId, {});
        PushOption(zero_duid, kDhcp6OptIaNa, IaNaPayload(1, false, nullptr));
        auto zd = BuildFrameRaw(zero_duid, kClientLl, kDhcp6ClientPort,
                                kDhcp6ServerPort);
        CHECK(!ParseDhcp6Frame(zd.data(), zd.size(), view));

        // Over-long DUID (>128 octets) is dropped.
        std::vector<uint8_t> big_duid = {kDhcp6MsgSolicit, 0, 0, 4};
        PushOption(big_duid, kDhcp6OptClientId,
                   std::vector<uint8_t>(129, 0xAB));
        PushOption(big_duid, kDhcp6OptIaNa, IaNaPayload(1, false, nullptr));
        auto bd = BuildFrameRaw(big_duid, kClientLl, kDhcp6ClientPort,
                                kDhcp6ServerPort);
        CHECK(!ParseDhcp6Frame(bd.data(), bd.size(), view));

        // A REQUEST without IA_NA is rejected (RFC 8415 requires one).
        auto no_ia = BuildRequest(kDhcp6MsgRequest, 0x010204, kClientDuid,
                                  false, 0, false, nullptr, false);
        CHECK(!ParseDhcp6Frame(no_ia.data(), no_ia.size(), view));

        // Non-link-local source is dropped (clients are link-scoped).
        std::array<uint8_t, 16> global_src = kPrefix;
        global_src[15] = 0x99;
        auto wrong_src = BuildFrameRaw(
            {kDhcp6MsgSolicit, 0, 0, 5, 0, 1, 0, 10, 0, 0, 0, 1, 0, 0, 0, 1},
            global_src, kDhcp6ClientPort, kDhcp6ServerPort);
        CHECK(!ParseDhcp6Frame(wrong_src.data(), wrong_src.size(), view));

        // Wrong destination port (not the server port) is dropped.
        auto wrong_port = BuildRequest(kDhcp6MsgSolicit, 0x010205, kClientDuid,
                                       true, 1, false, nullptr, false);
        {
            uint8_t* udp = wrong_port.data() + kEthernetHeaderLen + 40;
            udp[3] = 0x22;  // 547 (0x0223) -> 546 (0x0222)
        }
        CHECK(!ParseDhcp6Frame(wrong_port.data(), wrong_port.size(), view));
    }

    // --- 2. reply layout (bytes) ------------------------------------------
    void TestBuildReplyLayout() {
        const auto server_ll = vgww::proto::LinkLocalFromMac(kGatewayMac);
        Dhcp6Reply reply;
        reply.msg_type = kDhcp6MsgReply;
        reply.xid = 0x0A0B0C;
        reply.client_duid = kClientDuid;
        reply.server_duid = {0x00, 0x03, 0x00, 0x01, 0x30, 0xFC,
                             0x68, 0x88, 0xB4, 0xA9};
        reply.with_ia_na = true;
        reply.iaid = 0x11223344;
        reply.t1 = 1800;
        reply.t2 = 2880;
        reply.with_ia_addr = true;
        reply.ia_addr = kPoolStart;
        reply.preferred_s = 3600;
        reply.valid_s = 3600;
        reply.with_dns = true;
        reply.dns = {kDns1, kDns2};

        std::vector<uint8_t> frame;
        BuildDhcp6ReplyFrame(reply, kGatewayMac, kClientMac, server_ll,
                             kClientLl, frame);
        CHECK(frame.size() >= kDhcp6Offset + 4);

        // Ethernet: to the client, from the gateway.
        CHECK(0 == std::memcmp(frame.data(), kClientMac.data(), 6));
        CHECK(0 == std::memcmp(frame.data() + 6, kGatewayMac.data(), 6));
        CHECK(frame[12] == 0x86 && frame[13] == 0xDD);

        const uint8_t* ip = frame.data() + kEthernetHeaderLen;
        CHECK(0x60 == (ip[0] & 0xF0));
        CHECK(ip[6] == 17);   // UDP
        CHECK(ip[7] == 64);   // hop limit
        CHECK(0 == std::memcmp(ip + 8, server_ll.data(), 16));
        CHECK(0 == std::memcmp(ip + 24, kClientLl.data(), 16));

        ParsedReply parsed;
        CHECK(ParseReply(frame, parsed));
        CHECK(parsed.msg_type == kDhcp6MsgReply);
        CHECK(parsed.xid == 0x0A0B0C);
        CHECK(parsed.sport == kDhcp6ServerPort);
        CHECK(parsed.dport == kDhcp6ClientPort);
        CHECK(parsed.has_client_id && parsed.client_duid == kClientDuid);
        CHECK(parsed.has_server_id && parsed.server_duid == reply.server_duid);
        CHECK(parsed.has_ia && parsed.iaid == 0x11223344);
        CHECK(parsed.t1 == 1800 && parsed.t2 == 2880);
        CHECK(parsed.has_addr && parsed.addr == kPoolStart);
        CHECK(parsed.preferred == 3600 && parsed.valid == 3600);
        CHECK(parsed.dns.size() == 2 && parsed.dns[0] == kDns1 &&
              parsed.dns[1] == kDns2);

        // F1: overfilling the DNS list must not inflate option 23 past the
        // compiled-in budget; only the leading entries are written and the
        // option length matches the truncated count.
        reply.dns = {kDns1, kDns2, kDns1, kDns2, kDns1, kDns2};
        std::vector<uint8_t> capped_frame;
        BuildDhcp6ReplyFrame(reply, kGatewayMac, kClientMac, server_ll,
                             kClientLl, capped_frame);
        ParsedReply capped;
        CHECK(ParseReply(capped_frame, capped));
        CHECK(capped.dns.size() == vgww::core::limits::kMaxDhcp6Dns);
        CHECK(capped.dns[0] == kDns1 && capped.dns[1] == kDns2);

        // UDP checksum verifies over the IPv6 pseudo-header.
        const uint8_t* udp = ip + 40;
        const uint16_t ulen = static_cast<uint16_t>((udp[4] << 8) | udp[5]);
        const uint32_t pseudo =
            PseudoHeaderSum6(ip + 8, ip + 24, 17, ulen);
        CHECK(0 == InternetChecksum(udp, ulen, pseudo));

        // NoAddrsAvail form: IA_NA status inside, no IAADDR.
        Dhcp6Reply fail;
        fail.msg_type = kDhcp6MsgAdvertise;
        fail.xid = 0x0A0B0D;
        fail.client_duid = kClientDuid;
        fail.server_duid = reply.server_duid;
        fail.with_ia_na = true;
        fail.iaid = 7;
        fail.with_status = true;
        fail.status = kDhcp6StatusNoAddrsAvail;
        fail.status_in_ia = true;
        std::vector<uint8_t> fail_frame;
        BuildDhcp6ReplyFrame(fail, kGatewayMac, kClientMac, server_ll,
                             kClientLl, fail_frame);
        ParsedReply fp;
        CHECK(ParseReply(fail_frame, fp));
        CHECK(fp.msg_type == kDhcp6MsgAdvertise);
        CHECK(fp.has_ia && !fp.has_addr);
        CHECK(fp.has_status && fp.status == kDhcp6StatusNoAddrsAvail &&
              fp.ia_status);
    }

    // --- 3. SOLICIT -> ADVERTISE ------------------------------------------
    void TestSolicitAdvertise() {
        Dhcp6Server server(MakeConfig());
        const auto now = std::chrono::steady_clock::now();
        auto frame = BuildRequest(kDhcp6MsgSolicit, 0x100001, kClientDuid, true,
                                  1, false, nullptr, false);
        Dhcp6View view;
        CHECK(ParseDhcp6Frame(frame.data(), frame.size(), view));
        std::vector<uint8_t> reply;
        CHECK(server.HandleFrame(view, kClientMac, kClientLl, now, reply));
        ParsedReply parsed;
        CHECK(ParseReply(reply, parsed));
        CHECK(parsed.msg_type == kDhcp6MsgAdvertise);
        CHECK(parsed.xid == 0x100001);
        CHECK(parsed.has_client_id && parsed.client_duid == kClientDuid);
        CHECK(parsed.has_server_id && parsed.server_duid == server.ServerDuid());
        CHECK(parsed.has_ia && parsed.iaid == 1);
        CHECK(parsed.has_addr && InPool(parsed.addr));
        CHECK(parsed.t1 == 1800 && parsed.t2 == 2880);
        CHECK(!parsed.has_status);  // success: no status option
        CHECK(server.LeaseCount() == 1);

        // A repeated SOLICIT is idempotent (same address, no second lease).
        std::vector<uint8_t> again;
        CHECK(server.HandleFrame(view, kClientMac, kClientLl, now, again));
        ParsedReply parsed2;
        CHECK(ParseReply(again, parsed2));
        CHECK(parsed2.has_addr && parsed2.addr == parsed.addr);
        CHECK(server.LeaseCount() == 1);

        // F2: a zero pool derives prefix::1000 - prefix::1FFF (spec 5.2).
        Config derived = MakeConfig();
        derived.ipv6.dhcpv6.pool_start = {};
        derived.ipv6.dhcpv6.pool_end = {};
        Dhcp6Server derived_server(derived);
        std::vector<uint8_t> derived_reply;
        CHECK(derived_server.HandleFrame(view, kClientMac, kClientLl, now,
                                         derived_reply));
        ParsedReply derived_parsed;
        CHECK(ParseReply(derived_reply, derived_parsed));
        CHECK(derived_parsed.has_addr && InPool(derived_parsed.addr));
        CHECK(derived_parsed.addr[14] == 0x10 &&
              derived_parsed.addr[15] == 0x00);
        CHECK(derived_server.LeaseCount() == 1);
    }

    // --- batch324: the pool-walk branch sanitizes the hostname -------------
    void TestAcquireWalkSanitizesHostname() {
        Dhcp6Server server(MakeConfig());
        const auto now = std::chrono::steady_clock::now();
        const std::string raw("host\xFFname", 9);
        const std::string want = SanitizeUtf8(raw);
        CHECK(want != raw);
        const auto addr = server.Acquire(kClientDuid, 5, now,
                                         Dhcp6Server::OfferStage::kAck, raw);
        CHECK(server.LeaseCount() == 1);
        const auto leases = server.Leases(now);
        CHECK(leases.size() == 1);
        CHECK(leases[0].ip == addr);
        CHECK(leases[0].hostname == want);
    }

    // --- 4. rapid commit ---------------------------------------------------
    void TestRapidCommit() {
        Dhcp6Server server(MakeConfig());
        const auto now = std::chrono::steady_clock::now();
        auto frame = BuildRequest(kDhcp6MsgSolicit, 0x100002, kClientDuid, true,
                                  2, false, nullptr, /*rapid=*/true);
        Dhcp6View view;
        CHECK(ParseDhcp6Frame(frame.data(), frame.size(), view));
        CHECK(view.rapid_commit);
        std::vector<uint8_t> reply;
        CHECK(server.HandleFrame(view, kClientMac, kClientLl, now, reply));
        ParsedReply parsed;
        CHECK(ParseReply(reply, parsed));
        CHECK(parsed.msg_type == kDhcp6MsgReply);  // committed immediately
        CHECK(parsed.rapid_commit);
        CHECK(parsed.has_addr && InPool(parsed.addr));
        // The lease carries the full term, not the short offer hold.
        auto leases = server.Leases(now);
        CHECK(leases.size() == 1);
        CHECK(leases[0].expires_in_s > 60);
    }

    // P3: RFC 8415 21.14 requires the Rapid Commit option (14) to carry
    // option-len 0. A non-zero length must be rejected, not silently accepted:
    // accepting it lets a malformed SOLICIT skip the two-message handshake.
    void TestParseDhcp6RejectsNonEmptyRapidCommit() {
        Dhcp6View view;
        std::vector<uint8_t> p = {kDhcp6MsgSolicit, 0, 0, 90};
        PushOption(p, kDhcp6OptClientId, kClientDuid);
        // Hand-built option 14 with option-len 4: {0,14, 0,4, 0,0,0,0}.
        p.push_back(0);
        p.push_back(14);
        p.push_back(0);
        p.push_back(4);
        p.push_back(0);
        p.push_back(0);
        p.push_back(0);
        p.push_back(0);
        auto f = BuildFrameRaw(p, kClientLl, kDhcp6ClientPort,
                               kDhcp6ServerPort);
        const uint64_t before = ParseRejected6Count();
        CHECK(!ParseDhcp6Frame(f.data(), f.size(), view));
        CHECK(!view.rapid_commit);
        CHECK(before + 1 == ParseRejected6Count());
        // Control: the same SOLICIT with a zero-length option 14 parses.
        std::vector<uint8_t> ok = {kDhcp6MsgSolicit, 0, 0, 91};
        PushOption(ok, kDhcp6OptClientId, kClientDuid);
        PushOption(ok, kDhcp6OptRapidCommit, {});
        auto g = BuildFrameRaw(ok, kClientLl, kDhcp6ClientPort,
                               kDhcp6ServerPort);
        CHECK(ParseDhcp6Frame(g.data(), g.size(), view));
        CHECK(view.rapid_commit);
    }

    // --- 5. REQUEST -> REPLY ----------------------------------------------
    void TestRequestReply() {
        Dhcp6Server server(MakeConfig());
        const auto now = std::chrono::steady_clock::now();

        auto sol = BuildRequest(kDhcp6MsgSolicit, 0x100003, kClientDuid, true,
                                3, false, nullptr, false);
        Dhcp6View sol_view;
        CHECK(ParseDhcp6Frame(sol.data(), sol.size(), sol_view));
        std::vector<uint8_t> adv;
        CHECK(server.HandleFrame(sol_view, kClientMac, kClientLl, now, adv));
        ParsedReply adv_parsed;
        CHECK(ParseReply(adv, adv_parsed));
        CHECK(adv_parsed.has_addr);

        // The client requests the advertised address.
        auto req = BuildRequest(kDhcp6MsgRequest, 0x100004, kClientDuid, true,
                                3, true, &adv_parsed.addr, false,
                                server.ServerDuid());
        Dhcp6View req_view;
        CHECK(ParseDhcp6Frame(req.data(), req.size(), req_view));
        CHECK(req_view.has_ia_addr && req_view.ia_addr == adv_parsed.addr);
        std::vector<uint8_t> reply;
        CHECK(server.HandleFrame(req_view, kClientMac, kClientLl, now, reply));
        ParsedReply parsed;
        CHECK(ParseReply(reply, parsed));
        CHECK(parsed.msg_type == kDhcp6MsgReply);
        CHECK(parsed.xid == 0x100004);
        CHECK(parsed.has_addr && parsed.addr == adv_parsed.addr);
        CHECK(!parsed.has_status);
        CHECK(server.LeaseCount() == 1);

        // A REQUEST without a prior SOLICIT still gets an address.
        auto cold = BuildRequest(kDhcp6MsgRequest, 0x100005, kOtherDuid, true,
                                 9, false, nullptr, false, server.ServerDuid());
        Dhcp6View cold_view;
        CHECK(ParseDhcp6Frame(cold.data(), cold.size(), cold_view));
        std::vector<uint8_t> cold_reply;
        CHECK(server.HandleFrame(cold_view, kClientMac, kClientLl, now,
                                 cold_reply));
        ParsedReply cold_parsed;
        CHECK(ParseReply(cold_reply, cold_parsed));
        CHECK(cold_parsed.has_addr && InPool(cold_parsed.addr));
        CHECK(cold_parsed.addr != adv_parsed.addr);
        CHECK(server.LeaseCount() == 2);
    }

    // --- 6. RENEW ----------------------------------------------------------
    void TestRenew() {
        Dhcp6Server server(MakeConfig());
        const auto t0 = std::chrono::steady_clock::now();
        auto req = BuildRequest(kDhcp6MsgRequest, 0x100006, kClientDuid, true,
                                4, false, nullptr, false, server.ServerDuid());
        Dhcp6View req_view;
        CHECK(ParseDhcp6Frame(req.data(), req.size(), req_view));
        std::vector<uint8_t> first;
        CHECK(server.HandleFrame(req_view, kClientMac, kClientLl, t0, first));
        ParsedReply first_parsed;
        CHECK(ParseReply(first, first_parsed));
        CHECK(first_parsed.has_addr);

        const auto t1 = t0 + std::chrono::seconds(100);
        auto renew = BuildRequest(kDhcp6MsgRenew, 0x100007, kClientDuid, true, 4,
                                  true, &first_parsed.addr, false,
                                  server.ServerDuid());
        Dhcp6View renew_view;
        CHECK(ParseDhcp6Frame(renew.data(), renew.size(), renew_view));
        std::vector<uint8_t> reply;
        CHECK(server.HandleFrame(renew_view, kClientMac, kClientLl, t1, reply));
        ParsedReply parsed;
        CHECK(ParseReply(reply, parsed));
        CHECK(parsed.msg_type == kDhcp6MsgReply);
        CHECK(parsed.has_addr && parsed.addr == first_parsed.addr);
        CHECK(server.LeaseCount() == 1);
        // The lease was extended from t1 (full term again).
        auto leases = server.Leases(t1);
        CHECK(leases.size() == 1);
        CHECK(leases[0].expires_in_s > 3500);
    }

    // --- 7. REBIND (no server-id) -----------------------------------------
    void TestRebind() {
        Dhcp6Server server(MakeConfig());
        const auto t0 = std::chrono::steady_clock::now();
        auto req = BuildRequest(kDhcp6MsgRequest, 0x100008, kClientDuid, true,
                                5, false, nullptr, false, server.ServerDuid());
        Dhcp6View req_view;
        CHECK(ParseDhcp6Frame(req.data(), req.size(), req_view));
        std::vector<uint8_t> first;
        CHECK(server.HandleFrame(req_view, kClientMac, kClientLl, t0, first));
        ParsedReply first_parsed;
        CHECK(ParseReply(first, first_parsed));

        // REBIND carries no Server Identifier (the server may have moved).
        auto rebind = BuildRequest(kDhcp6MsgRebind, 0x100009, kClientDuid, true,
                                   5, true, &first_parsed.addr, false);
        Dhcp6View rebind_view;
        CHECK(ParseDhcp6Frame(rebind.data(), rebind.size(), rebind_view));
        CHECK(rebind_view.server_duid.empty());
        std::vector<uint8_t> reply;
        CHECK(server.HandleFrame(rebind_view, kClientMac, kClientLl,
                                 t0 + std::chrono::seconds(50), reply));
        ParsedReply parsed;
        CHECK(ParseReply(reply, parsed));
        CHECK(parsed.msg_type == kDhcp6MsgReply);
        CHECK(parsed.has_addr && parsed.addr == first_parsed.addr);
        CHECK(server.LeaseCount() == 1);
    }

    // --- 8. RELEASE --------------------------------------------------------
    void TestRelease() {
        Dhcp6Server server(MakeConfig());
        const auto t0 = std::chrono::steady_clock::now();
        auto req = BuildRequest(kDhcp6MsgRequest, 0x10000A, kClientDuid, true,
                                6, false, nullptr, false, server.ServerDuid());
        Dhcp6View req_view;
        CHECK(ParseDhcp6Frame(req.data(), req.size(), req_view));
        std::vector<uint8_t> first;
        CHECK(server.HandleFrame(req_view, kClientMac, kClientLl, t0, first));
        CHECK(server.LeaseCount() == 1);

        // A RELEASE addressed to another server (foreign server-id) is
        // ignored: our binding survives.
        auto foreign = BuildRequest(kDhcp6MsgRelease, 0x10000B, kClientDuid,
                                    true, 6, false, nullptr, false,
                                    kOtherDuid);
        Dhcp6View foreign_view;
        CHECK(ParseDhcp6Frame(foreign.data(), foreign.size(), foreign_view));
        std::vector<uint8_t> ignored;
        CHECK(!server.HandleFrame(foreign_view, kClientMac, kClientLl, t0,
                                  ignored));
        CHECK(server.LeaseCount() == 1);

        // Our own server-id releases the lease and answers with a Reply
        // carrying a top-level Success status.
        auto release = BuildRequest(kDhcp6MsgRelease, 0x10000C, kClientDuid,
                                    true, 6, false, nullptr, false,
                                    server.ServerDuid());
        Dhcp6View release_view;
        CHECK(ParseDhcp6Frame(release.data(), release.size(), release_view));
        std::vector<uint8_t> reply;
        CHECK(server.HandleFrame(release_view, kClientMac, kClientLl, t0,
                                 reply));
        ParsedReply parsed;
        CHECK(ParseReply(reply, parsed));
        CHECK(parsed.msg_type == kDhcp6MsgReply);
        CHECK(parsed.has_status && parsed.status == kDhcp6StatusSuccess &&
              parsed.top_status);
        CHECK(server.LeaseCount() == 0);
    }

    // --- 9. DECLINE parks the address for 600 s ---------------------------
    void TestDeclineParks() {
        Config config = MakeConfig();
        config.ipv6.dhcpv6.pool_end = kPoolStart;  // single-address pool
        Dhcp6Server server(config);
        const auto t0 = std::chrono::steady_clock::now();
        auto req = BuildRequest(kDhcp6MsgRequest, 0x10000D, kClientDuid, true,
                                7, false, nullptr, false, server.ServerDuid());
        Dhcp6View req_view;
        CHECK(ParseDhcp6Frame(req.data(), req.size(), req_view));
        std::vector<uint8_t> first;
        CHECK(server.HandleFrame(req_view, kClientMac, kClientLl, t0, first));
        ParsedReply first_parsed;
        CHECK(ParseReply(first, first_parsed));
        CHECK(first_parsed.addr == kPoolStart);

        auto decline = BuildRequest(kDhcp6MsgDecline, 0x10000E, kClientDuid, true,
                                    7, true, &first_parsed.addr, false,
                                    server.ServerDuid());
        Dhcp6View decline_view;
        CHECK(ParseDhcp6Frame(decline.data(), decline.size(), decline_view));
        std::vector<uint8_t> reply;
        CHECK(server.HandleFrame(decline_view, kClientMac, kClientLl, t0,
                                 reply));
        ParsedReply parsed;
        CHECK(ParseReply(reply, parsed));
        CHECK(parsed.msg_type == kDhcp6MsgReply);
        CHECK(parsed.has_status && parsed.status == kDhcp6StatusSuccess);
        CHECK(server.LeaseCount() == 0);

        // A different client must not receive the parked address...
        std::array<uint8_t, 16> got{};
        got = server.Acquire(kOtherDuid, 1, t0 + std::chrono::seconds(1),
                             Dhcp6Server::OfferStage::kAck);
        CHECK(IsZeroAddr(got));
        // ...until the 600 s hold elapses.
        got = server.Acquire(kOtherDuid, 1, t0 + std::chrono::seconds(601),
                             Dhcp6Server::OfferStage::kAck);
        CHECK(got == kPoolStart);
    }

    // --- 10. INFORMATION-REQUEST -> DNS only ------------------------------
    void TestInformationRequest() {
        Dhcp6Server server(MakeConfig());
        const auto now = std::chrono::steady_clock::now();
        auto frame = BuildRequest(kDhcp6MsgInformationRequest, 0x10000F,
                                  kClientDuid, false, 0, false, nullptr, false,
                                  std::vector<uint8_t>(), /*oro=*/true);
        Dhcp6View view;
        CHECK(ParseDhcp6Frame(frame.data(), frame.size(), view));
        CHECK(!view.has_ia_na);
        std::vector<uint8_t> reply;
        CHECK(server.HandleFrame(view, kClientMac, kClientLl, now, reply));
        ParsedReply parsed;
        CHECK(ParseReply(reply, parsed));
        CHECK(parsed.msg_type == kDhcp6MsgReply);
        CHECK(!parsed.has_ia);
        CHECK(parsed.dns.size() == 2 && parsed.dns[0] == kDns1 &&
              parsed.dns[1] == kDns2);
        CHECK(server.LeaseCount() == 0);
    }

    // --- 11. pool exhaustion -> NoAddrsAvail ------------------------------
    void TestPoolExhaustion() {
        Config config = MakeConfig();
        config.ipv6.dhcpv6.pool_end = kPoolStart;  // single-address pool
        Dhcp6Server server(config);
        const auto t0 = std::chrono::steady_clock::now();

        auto first = BuildRequest(kDhcp6MsgRequest, 0x100010, kClientDuid, true,
                                  8, false, nullptr, false, server.ServerDuid());
        Dhcp6View first_view;
        CHECK(ParseDhcp6Frame(first.data(), first.size(), first_view));
        std::vector<uint8_t> first_reply;
        CHECK(server.HandleFrame(first_view, kClientMac, kClientLl, t0,
                                 first_reply));
        ParsedReply first_parsed;
        CHECK(ParseReply(first_reply, first_parsed));
        CHECK(first_parsed.has_addr && first_parsed.addr == kPoolStart);

        // The second client gets an explicit NoAddrsAvail status instead of
        // a silent drop.
        const uint64_t before = server.PoolExhaustedCount();
        auto second = BuildRequest(kDhcp6MsgSolicit, 0x100011, kOtherDuid, true,
                                   8, false, nullptr, false);
        Dhcp6View second_view;
        CHECK(ParseDhcp6Frame(second.data(), second.size(), second_view));
        std::vector<uint8_t> second_reply;
        CHECK(server.HandleFrame(second_view, kClientMac, kClientLl, t0,
                                 second_reply));
        ParsedReply second_parsed;
        CHECK(ParseReply(second_reply, second_parsed));
        CHECK(second_parsed.msg_type == kDhcp6MsgAdvertise);
        CHECK(second_parsed.has_ia && !second_parsed.has_addr);
        CHECK(second_parsed.has_status &&
              second_parsed.status == kDhcp6StatusNoAddrsAvail &&
              second_parsed.ia_status);
        CHECK(server.PoolExhaustedCount() == before + 1);
    }

    // --- 12. static DUID binding wins -------------------------------------
    void TestStaticBindingPriority() {
        Config config = MakeConfig();
        Dhcp6StaticBinding binding;
        binding.duid = kStaticDuid;
        binding.ip = kPrefix;
        binding.ip[15] = 0x42;  // inside the prefix, outside the pool
        binding.hostname = "fixed-printer";
        config.ipv6.dhcpv6.static_bindings.push_back(binding);
        Dhcp6Server server(config);
        const auto now = std::chrono::steady_clock::now();

        std::array<uint8_t, 16> got =
            server.Acquire(kStaticDuid, 1, now, Dhcp6Server::OfferStage::kAck);
        CHECK(got == binding.ip);

        // The bound address is reserved even before the client asks.
        std::array<uint8_t, 16> other =
            server.Acquire(kOtherDuid, 1, now, Dhcp6Server::OfferStage::kAck);
        CHECK(!IsZeroAddr(other));
        CHECK(other != binding.ip);
        CHECK(InPool(other));

        auto frame = BuildRequest(kDhcp6MsgSolicit, 0x100012, kStaticDuid, true,
                                  1, false, nullptr, false);
        Dhcp6View view;
        CHECK(ParseDhcp6Frame(frame.data(), frame.size(), view));
        std::vector<uint8_t> reply;
        CHECK(server.HandleFrame(view, kClientMac, kClientLl, now, reply));
        ParsedReply parsed;
        CHECK(ParseReply(reply, parsed));
        CHECK(parsed.has_addr && parsed.addr == binding.ip);

        // The static binding is visible through both accessors.
        const auto statics = server.StaticBindings();
        CHECK(statics.size() == 1 && statics[0].duid == kStaticDuid &&
              statics[0].ip == binding.ip &&
              statics[0].hostname == "fixed-printer");
        const auto leases = server.Leases(now);
        CHECK(!leases.empty() && leases[0].is_static);
    }

    // batch127: /api/status needs only the NUMBER of v6 static bindings, but
    // it called GetDhcp6Bindings().size() - which materialises the whole
    // vector (one Dhcp6StaticBinding per entry, each with three std::strings,
    // plus a FormatDuidText hex pass). Every status poll paid a full copy just
    // to read .size(). The O(1) count must agree with StaticBindings().size()
    // for BOTH sources (config bindings + runtime-only overrides) and must
    // never double-count a runtime override of a config binding.
    void TestStaticBindingCountIsO1AndConsistent() {
        Config config = MakeConfig();
        Dhcp6StaticBinding cfg;
        cfg.duid = kStaticDuid;
        cfg.ip = kPrefix;
        cfg.ip[15] = 0x42;
        cfg.hostname = "fixed-printer";
        config.ipv6.dhcpv6.static_bindings.push_back(cfg);

        Dhcp6Server server(config);
        // One config binding, no runtime overrides yet.
        CHECK(server.StaticBindingCount() == 1);
        CHECK(server.StaticBindingCount() == server.StaticBindings().size());

        // A runtime override of the SAME DUID is not a second binding.
        std::array<uint8_t, 16> ip = kPrefix;
        ip[15] = 0x42;
        CHECK(server.UpsertBinding(kStaticDuid, ip, "renamed"));
        CHECK(server.StaticBindingCount() == 1);
        CHECK(server.StaticBindingCount() == server.StaticBindings().size());

        // A runtime-only binding (no config entry) adds one.
        std::array<uint8_t, 16> ip2 = kPrefix;
        ip2[15] = 0x43;
        CHECK(server.UpsertBinding(kOtherDuid, ip2, "nas"));
        CHECK(server.StaticBindingCount() == 2);
        CHECK(server.StaticBindingCount() == server.StaticBindings().size());

        // Removal brings it back down.
        CHECK(server.RemoveBinding(kOtherDuid));
        CHECK(server.StaticBindingCount() == 1);
        CHECK(server.StaticBindingCount() == server.StaticBindings().size());

        // An empty server counts zero (no crash on an empty map).
        Dhcp6Server empty(MakeConfig());
        CHECK(empty.StaticBindingCount() == 0);
        CHECK(empty.StaticBindingCount() == empty.StaticBindings().size());
    }

    // --- 12b. runtime bindings reject duplicate / config-reserved IPs -----
    /// Same defect class as the v4 sibling: a static binding that lives in the
    /// CONFIG document (not the runtime table) must be deletable. RemoveBinding
    /// only knew runtime_bindings_, so the WebUI/native delete always failed
    /// while StaticBindings() kept listing the config entry.
    void TestRemoveConfigBinding6() {
        Config config = MakeConfig();
        Dhcp6StaticBinding cfg;
        cfg.duid = kStaticDuid;
        cfg.ip = kPrefix;
        cfg.ip[15] = 0x42;
        cfg.hostname = "fixed-printer";
        config.ipv6.dhcpv6.static_bindings.push_back(cfg);

        Dhcp6Server server(config);
        const auto now = std::chrono::steady_clock::now();
        CHECK(server.StaticBindings().size() == 1);
        CHECK(server.StaticBindingCount() == 1);
        CHECK(server.Acquire(kStaticDuid, 1, now,
                             Dhcp6Server::OfferStage::kAck) == cfg.ip);

        // The config entry is removable, and the removal is live.
        CHECK(server.RemoveBinding(kStaticDuid));
        CHECK(server.StaticBindings().empty());
        CHECK(server.StaticBindingCount() == 0);
        // The address is no longer reserved by the (deleted) config entry: a
        // runtime binding may now claim it.
        CHECK(server.UpsertBinding(kOtherDuid, cfg.ip, ""));
        // A second delete has nothing left to remove.
        CHECK(!server.RemoveBinding(kStaticDuid));
    }

    void TestUpsertBindingRejectsDuplicate() {        // Two distinct DUIDs cannot share one bound address; a config static
        // binding reserves its address; the owner re-upserting stays legal.
        Dhcp6Server server(MakeConfig());
        std::array<uint8_t, 16> ip = kPrefix;
        ip[15] = 0x42;  // fd00:1122:3344:5566::42
        CHECK(server.UpsertBinding(kClientDuid, ip, ""));
        CHECK(!server.UpsertBinding(kOtherDuid, ip, ""));
        CHECK(server.UpsertBinding(kClientDuid, ip, ""));  // owner, legal

        Config config = MakeConfig();
        Dhcp6StaticBinding cfg;
        cfg.duid = kStaticDuid;
        cfg.ip = ip;
        config.ipv6.dhcpv6.static_bindings.push_back(cfg);
        Dhcp6Server server2(config);
        CHECK(!server2.UpsertBinding(kOtherDuid, ip, ""));
        CHECK(server2.UpsertBinding(kStaticDuid, ip, ""));  // owner, legal
    }

    // --- 12c. pool never hands out the network / all-ones IID ------------
    void TestPoolSkipsNetworkIid() {
        // The /64 network address (IID all-zero) and the all-ones IID must
        // not be allocated from a pool covering them.
        Config config = MakeConfig();
        const auto now = std::chrono::steady_clock::now();

        config.ipv6.dhcpv6.pool_start = kPrefix;  // fd00:...::
        config.ipv6.dhcpv6.pool_end = kPrefix;
        Dhcp6Server nw(config);
        CHECK(IsZeroAddr(nw.Acquire(kClientDuid, 1, now,
                                    Dhcp6Server::OfferStage::kAck)));

        std::array<uint8_t, 16> ones = kPrefix;
        for (size_t i = 8; i < 16; ++i) {
            ones[i] = 0xFF;
        }
        config.ipv6.dhcpv6.pool_start = ones;
        config.ipv6.dhcpv6.pool_end = ones;
        Dhcp6Server allones(config);
        CHECK(IsZeroAddr(allones.Acquire(kOtherDuid, 2, now,
                                         Dhcp6Server::OfferStage::kAck)));

        // A normal single-address pool still allocates (positive control).
        config.ipv6.dhcpv6.pool_start = kPoolStart;
        config.ipv6.dhcpv6.pool_end = kPoolStart;
        Dhcp6Server normal(config);
        const std::array<uint8_t, 16> got =
            normal.Acquire(kClientDuid, 1, now, Dhcp6Server::OfferStage::kAck);
        CHECK(got == kPoolStart);
    }

    // --- 12d. lease reload skips stale / static-conflicting entries --------
    // batch134: same defect class as the v4 loader - a persisted file naming
    // one address for two different DUID+IAID pairs was accepted, even though
    // Acquire6's occupancy set is keyed by address and UpsertBinding rejects
    // the same collision. First occurrence wins; later ones are counted.
    void TestB134Leases6LoadRejectsDuplicateAddress() {
        Config config = MakeConfig();
        Dhcp6Server server(config);

        const std::string path = ScratchFile("test_dhcp6_leases_dup_addr.json");
        {
            std::ofstream out(path);
            out << "{\"version\":1,\"leases\":["
                   "{\"duid\":\"00:03:00:01:AA:BB:CC:DD:EE:01\",\"iaid\":1,"
                   "\"ip\":\"fd00:1122:3344:5566:0000:0000:0000:1000\","
                   "\"expires_in_s\":3600,\"hostname\":\"first\"},"
                   "{\"duid\":\"00:03:00:01:AA:BB:CC:DD:EE:02\",\"iaid\":2,"
                   "\"ip\":\"fd00:1122:3344:5566:0000:0000:0000:1000\","
                   "\"expires_in_s\":3600,\"hostname\":\"second\"},"
                   "{\"duid\":\"00:03:00:01:AA:BB:CC:DD:EE:03\",\"iaid\":3,"
                   "\"ip\":\"fd00:1122:3344:5566:0000:0000:0000:1001\","
                   "\"expires_in_s\":3600,\"hostname\":\"distinct\"}]}";
        }
        size_t dropped = 0;
        CHECK(server.LoadLeases(path, std::chrono::steady_clock::now(),
                                &dropped) ==
              Dhcp6Server::LoadOutcome::kRestored);

        const auto leases = server.Leases(std::chrono::steady_clock::now());
        CHECK(2 == leases.size());
        std::size_t on_1000 = 0;
        std::string owner_1000;
        for (const auto& entry : leases) {
            if (entry.ip[14] == 0x10 && entry.ip[15] == 0x00) {
                ++on_1000;
                owner_1000 = entry.hostname;
            }
        }
        CHECK(1 == on_1000);
        CHECK("first" == owner_1000);
        CHECK(1 == dropped);
        CHECK(1 == server.DroppedLeaseCount());  // batch119: surfaced, not silent

        std::error_code rm_ec_1;
        std::filesystem::remove(path, rm_ec_1);
    }

    // batch122: DHCPv6 parse refusals are counted like the v4 sibling.
    void TestB122ParseRejects6AreCounted() {
        Dhcp6View view{};
        std::vector<uint8_t> garbage(32, 0);
        const uint64_t before = ParseRejected6Count();
        CHECK(!ParseDhcp6Frame(garbage.data(), garbage.size(), view));
        CHECK(before + 1 == ParseRejected6Count());
    }

    // batch120: v6 sibling of TestB120LeaseFileCorruptIsFlagged.
    void TestB120Leases6FileCorruptIsFlagged() {
        Config config = MakeConfig();
        Dhcp6Server server(config);
        const std::string path = ScratchFile("test_dhcp6_leases_b120.json");
        {
            std::ofstream out(path);
            out << "{\"version\":99}";
        }
        size_t dropped = 0;
        CHECK(server.LoadLeases(path, std::chrono::steady_clock::now(),
                                &dropped) ==
              Dhcp6Server::LoadOutcome::kCorrupt);
        CHECK(server.LeaseFileCorrupt());
        {
            std::ifstream aside(path + ".corrupt");
            CHECK(aside.good());
        }
        std::error_code rm_ec_2;
        std::filesystem::remove(path, rm_ec_2);
        std::error_code rm_ec_3;
        std::filesystem::remove(path + ".corrupt", rm_ec_3);
    }

    void TestLeases6LoadSkipsIllegal() {
        Config config = MakeConfig();
        Dhcp6StaticBinding cfg;
        cfg.duid = kStaticDuid;
        cfg.ip = kPrefix;
        cfg.ip[15] = 0x50;  // fd00:1122:3344:5566::50
        config.ipv6.dhcpv6.static_bindings.push_back(cfg);
        Dhcp6Server server(config);

        const std::string path = ScratchFile("test_dhcp6_leases_illegal.json");
        {
            std::ofstream out(path);
            out << "{\"version\":1,\"leases\":["
                   "{\"duid\":\"00:03:00:01:AA:BB:CC:DD:EE:01\",\"iaid\":1,"
                   "\"ip\":\"fd00:1122:3344:5566:0000:0000:0000:1000\","
                   "\"expires_in_s\":3600,\"hostname\":\"good\"},"
                   "{\"duid\":\"00:03:00:01:AA:BB:CC:DD:EE:02\",\"iaid\":2,"
                   "\"ip\":\"fd00:1122:3344:5566:0000:0000:0000:0050\","
                   "\"expires_in_s\":3600,\"hostname\":\"static-conflict\"},"
                   "{\"duid\":\"00:03:00:01:AA:BB:CC:DD:EE:03\",\"iaid\":3,"
                   "\"ip\":\"fd01:1122:3344:5566:0000:0000:0000:1000\","
                   "\"expires_in_s\":3600,\"hostname\":\"outside-prefix\"}]}";
        }
        // batch34c: the v6 loader must report the same three outcomes as v4
        // and count the entries it refused.
        size_t dropped = 0;
        CHECK(server.LoadLeases(path, std::chrono::steady_clock::now(),
                                &dropped) ==
              Dhcp6Server::LoadOutcome::kRestored);
        CHECK(server.LeaseCount() == 1);  // only the valid entry survives
        CHECK(dropped > 0);               // the refused ones are counted
        auto leases = server.Leases(std::chrono::steady_clock::now());
        CHECK(!leases.empty() && leases[0].hostname == "good");

        // A missing file is a NORMAL first run, not a fault.
        {
            Dhcp6Server fresh(config);
            size_t none = 999;
            CHECK(fresh.LoadLeases(AbsentPath("absent6.json"),
                                   std::chrono::steady_clock::now(),
                                   &none) ==
                  Dhcp6Server::LoadOutcome::kNoFile);
            CHECK(none == 0);
        }

        // A future schema version is a hard failure, not a silent reparse -
        // and it must be CORRUPT (data loss), not "no file".
        {
            std::ofstream out(path);
            out << "{\"version\":2,\"leases\":[]}";
        }
        Dhcp6Server server2(config);
        size_t dropped2 = 0;
        CHECK(server2.LoadLeases(path, std::chrono::steady_clock::now(),
                                 &dropped2) ==
              Dhcp6Server::LoadOutcome::kCorrupt);
        CHECK(!server2.LoadLeases(path, std::chrono::steady_clock::now()));

        // Truncated JSON is corrupt too.
        {
            std::ofstream out(path);
            out << "{\"version\":1,\"leases\":[{\"duid\":";
        }
        Dhcp6Server server3(config);
        CHECK(server3.LoadLeases(path, std::chrono::steady_clock::now(),
                                 nullptr) ==
              Dhcp6Server::LoadOutcome::kCorrupt);
        std::error_code rm_ec_4;
        std::filesystem::remove(path, rm_ec_4);
    }

    // --- 12e. OBS-1: legacy v6 file missing expires_in_s is restored ------
    void TestLegacyLeaseMissingExpiresRestored6() {
        // OBS-1: a version:1 file written by an older build persists its
        // leases WITHOUT the expires_in_s field. LoadLeases must restore a
        // full term sourced from config.ipv6.dhcpv6.lease_seconds (same
        // origin as a fresh Acquire) instead of silently dropping every
        // entry. An explicit expires_in_s==0 (a genuinely expired lease)
        // must still be dropped - only the MISSING field is legacy.
        Config config = MakeConfig();
        Dhcp6Server server(config);

        const std::string path = ScratchFile("test_dhcp6_leases_legacy.json");
        {
            std::ofstream out(path);
            out << "{\"version\":1,\"leases\":["
                   "{\"duid\":\"00:03:00:01:AA:BB:CC:DD:EE:01\",\"iaid\":1,"
                   "\"ip\":\"fd00:1122:3344:5566:0000:0000:0000:1000\","
                   "\"hostname\":\"legacy-host\"},"
                   "{\"duid\":\"00:03:00:01:AA:BB:CC:DD:EE:02\",\"iaid\":2,"
                   "\"ip\":\"fd00:1122:3344:5566:0000:0000:0000:1001\","
                   "\"expires_in_s\":0,\"hostname\":\"expired\"}]}";
        }
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
        const std::array<uint8_t, 16> expected = {
            0xFD, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0, 0, 0, 0, 0, 0,
            0x10, 0x00};
        CHECK(server.Acquire(kClientDuid, 1, t0 + std::chrono::seconds(1),
                             Dhcp6Server::OfferStage::kAck) == expected);
        std::error_code rm_ec_5;
        std::filesystem::remove(path, rm_ec_5);
    }

    // --- 13. lease file round-trip (version + atomic replace) -------------
    void TestLeases6RoundTrip() {
        Config config = MakeConfig();
        Dhcp6Server server(config);
        const auto t0 = std::chrono::steady_clock::now();
        const std::array<uint8_t, 16> a =
            server.Acquire(kClientDuid, 1, t0, Dhcp6Server::OfferStage::kAck);
        const std::array<uint8_t, 16> b =
            server.Acquire(kOtherDuid, 2, t0, Dhcp6Server::OfferStage::kAck);
        CHECK(!IsZeroAddr(a) && !IsZeroAddr(b) && a != b);

        const std::string path = ScratchFile("test_dhcp6_leases_roundtrip.json");
        std::error_code rm_ec_6;
        std::filesystem::remove(path, rm_ec_6);
        std::error_code rm_ec_7;
        std::filesystem::remove(path + ".tmp", rm_ec_7);
        CHECK(server.DumpLeases(path, t0));

        std::ifstream file(path, std::ios::binary);
        CHECK(file.good());
        const std::string raw((std::istreambuf_iterator<char>(file)),
                              std::istreambuf_iterator<char>());
        CHECK(raw.find("\"version\":1") != std::string::npos);
        CHECK(raw.find("\"leases\"") != std::string::npos);
        std::ifstream tmp(path + ".tmp", std::ios::binary);
        CHECK(!tmp.good());  // the temp file was renamed away

        // A fresh server (different pool) restores the mappings.
        Config config2 = MakeConfig();
        config2.ipv6.dhcpv6.pool_start = kPrefix;
        config2.ipv6.dhcpv6.pool_end = kPrefix;
        config2.ipv6.dhcpv6.pool_start[15] = 0x00;
        config2.ipv6.dhcpv6.pool_end[15] = 0x00;
        Dhcp6Server restored(config2);
        CHECK(restored.LoadLeases(path, t0));
        CHECK(restored.LeaseCount() == 2);
        CHECK(restored.Acquire(kClientDuid, 1, t0,
                               Dhcp6Server::OfferStage::kAck) == a);
        CHECK(restored.Acquire(kOtherDuid, 2, t0,
                               Dhcp6Server::OfferStage::kAck) == b);
        std::error_code rm_ec_8;
        std::filesystem::remove(path, rm_ec_8);
    }

    // --- 13b. batch82: shared durable writer + corrupt-file preservation ---

    void TestLease6DumpFlushFailureKeepsPreviousSnapshot() {
        Config config = MakeConfig();
        Dhcp6Server server(config);
        const auto t0 = std::chrono::steady_clock::now();
        CHECK(!IsZeroAddr(server.Acquire(kClientDuid, 1, t0,
                                         Dhcp6Server::OfferStage::kAck)));

        const std::string path = ScratchFile("b-flush-dhcp6-leases.json");
        std::error_code rm_ec_9;
        std::filesystem::remove(path, rm_ec_9);
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
            std::ifstream again(path, std::ios::binary);
            CHECK(std::string((std::istreambuf_iterator<char>(again)),
                              std::istreambuf_iterator<char>()) == original);
        }

        CHECK(server.DumpLeases(path, t0 + std::chrono::seconds(6)));
        std::error_code rm_ec_10;
        std::filesystem::remove(path, rm_ec_10);
    }

    void TestCorruptLease6FilePreserved() {
        Dhcp6Server server(MakeConfig());
        const std::string path = ScratchFile("b-corrupt-dhcp6-leases.json");
        const std::string aside = path + ".corrupt";
        std::error_code rm_ec_11;
        std::filesystem::remove(path, rm_ec_11);
        std::error_code rm_ec_12;
        std::filesystem::remove(aside, rm_ec_12);
        const std::string garbage = "{\"version\":1,\"leases\":[{\"duid\":";
        {
            std::ofstream out(path, std::ios::binary);
            out << garbage;
        }
        CHECK(server.LoadLeases(path, std::chrono::steady_clock::now(),
                                nullptr) ==
              Dhcp6Server::LoadOutcome::kCorrupt);
        std::ifstream kept(aside, std::ios::binary);
        CHECK(kept.good());
        CHECK(std::string((std::istreambuf_iterator<char>(kept)),
                          std::istreambuf_iterator<char>()) == garbage);
        std::ifstream gone(path, std::ios::binary);
        CHECK(!gone.good());
        std::error_code rm_ec_13;
        std::filesystem::remove(aside, rm_ec_13);
    }

    // batch85: same discipline as v4 - a transient holder is retried, and a
    // file that still will not open is kUnreadable (kept, not overwritten).
    void TestLease6LoadTransientLockIsNotCorrupt() {
        Config config = MakeConfig();
        const auto t0 = std::chrono::steady_clock::now();
        const std::string path = ScratchFile("b-lock-dhcp6-leases.json");
        std::error_code rm_ec_14;
        std::filesystem::remove(path, rm_ec_14);
        {
            Dhcp6Server writer(config);
            CHECK(!IsZeroAddr(writer.Acquire(
                kClientDuid, 1, t0, Dhcp6Server::OfferStage::kAck)));
            CHECK(writer.DumpLeases(path, t0));
        }

        Dhcp6Server server(config);
        std::atomic<int> calls{0};
        vgww::core::SetConfigOpenFailureHookForTest(
            [&calls](const std::string&) -> unsigned long {
                return (calls.fetch_add(1) + 1) <= 2 ? 32u : 0u;
            });
        size_t dropped = 0;
        const auto outcome = server.LoadLeases(path, t0, &dropped);
        vgww::core::SetConfigOpenFailureHookForTest(
            std::function<unsigned long(const std::string&)>());
        CHECK(outcome == Dhcp6Server::LoadOutcome::kRestored);
        CHECK(calls.load() == 3);
        CHECK(server.LeaseCount() == 1);
        std::error_code rm_ec_15;
        std::filesystem::remove(path, rm_ec_15);
    }

    void TestLease6LoadUnreadablePausesDump() {
        Config config = MakeConfig();
        const auto t0 = std::chrono::steady_clock::now();
        const std::string path = ScratchFile("b-lock2-dhcp6-leases.json");
        std::error_code rm_ec_16;
        std::filesystem::remove(path, rm_ec_16);
        {
            Dhcp6Server writer(config);
            CHECK(!IsZeroAddr(writer.Acquire(
                kClientDuid, 1, t0, Dhcp6Server::OfferStage::kAck)));
            CHECK(writer.DumpLeases(path, t0));
        }
        std::string original;
        {
            std::ifstream in(path, std::ios::binary);
            original.assign(std::istreambuf_iterator<char>(in),
                            std::istreambuf_iterator<char>());
        }

        Dhcp6Server server(config);
        vgww::core::SetConfigOpenFailureHookForTest(
            [](const std::string&) -> unsigned long { return 32u; });
        const auto outcome = server.LoadLeases(path, t0, nullptr);
        CHECK(outcome == Dhcp6Server::LoadOutcome::kUnreadable);
        CHECK(server.LeaseCount() == 0);

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

        Dhcp6Server fresh(config);
        CHECK(fresh.LoadLeases(path, t0, nullptr) ==
              Dhcp6Server::LoadOutcome::kRestored);
        std::error_code rm_ec_17;
        std::filesystem::remove(path, rm_ec_17);
    }

    // batch87: blocked v6 lease writer recovers on the next dump.
    void TestLease6DumpRecoversFromBlocked() {
        Config config = MakeConfig();
        const auto t0 = std::chrono::steady_clock::now();
        const std::string path = ScratchFile("b-recover-dhcp6-leases.json");
        std::error_code rm_ec_18;
        std::filesystem::remove(path, rm_ec_18);
        {
            Dhcp6Server writer(config);
            CHECK(!IsZeroAddr(writer.Acquire(
                kClientDuid, 1, t0, Dhcp6Server::OfferStage::kAck)));
            CHECK(writer.DumpLeases(path, t0));
        }

        Dhcp6Server server(config);
        vgww::core::SetConfigOpenFailureHookForTest(
            [](const std::string&) -> unsigned long { return 32u; });
        CHECK(server.LoadLeases(path, t0, nullptr) ==
              Dhcp6Server::LoadOutcome::kUnreadable);
        vgww::core::SetConfigOpenFailureHookForTest(
            std::function<unsigned long(const std::string&)>());
        CHECK(server.PersistBlocked());

        CHECK(!IsZeroAddr(server.Acquire(kOtherDuid, 7, t0,
                                         Dhcp6Server::OfferStage::kAck)));
        const size_t live = server.LeaseCount();
        CHECK(live == 1);

        CHECK(server.DumpLeases(path, t0 + std::chrono::seconds(60)));
        CHECK(!server.PersistBlocked());
        const size_t merged = server.LeaseCount();
        CHECK(merged >= live);

        Dhcp6Server reloaded(config);
        CHECK(reloaded.LoadLeases(path, t0, nullptr) ==
              Dhcp6Server::LoadOutcome::kRestored);
        CHECK(reloaded.LeaseCount() == merged);
        std::error_code rm_ec_19;
        std::filesystem::remove(path, rm_ec_19);
    }

    // --- 14. oversized lease file is rejected (cap) -----------------------
    void TestLoadCap() {
        Config config = MakeConfig();
        Dhcp6Server server(config);
        const std::string path = ScratchFile("test_dhcp6_leases_oversized.json");
        {
            std::ofstream out(path, std::ios::binary);
            CHECK(out.good());
            std::vector<char> blob(
                static_cast<size_t>(vgww::core::limits::kMaxLeases6Bytes) + 1,
                'x');
            out.write(blob.data(), static_cast<std::streamsize>(blob.size()));
        }
        CHECK(!server.LoadLeases(path, std::chrono::steady_clock::now()));
        CHECK(server.LeaseCount() == 0);
        std::error_code rm_ec_20;
        std::filesystem::remove(path, rm_ec_20);

        // Corrupt JSON is rejected without loading anything.
        {
            std::ofstream out(path, std::ios::binary);
            out << "{\"version\":1,\"leases\":[{\"duid\":\"zz\"";
        }
        CHECK(!server.LoadLeases(path, std::chrono::steady_clock::now()));
        CHECK(server.LeaseCount() == 0);
        std::error_code rm_ec_21;
        std::filesystem::remove(path, rm_ec_21);
    }

    // --- 15. per-DUID rate limit ------------------------------------------
    void TestRateLimitPerDuid() {
        Dhcp6Server server(MakeConfig());
        const auto t0 = std::chrono::steady_clock::now();
        for (size_t i = 0; i < 8; ++i) {
            CHECK(server.AllowFrame(kClientDuid, t0));
        }
        CHECK(!server.AllowFrame(kClientDuid, t0));  // 9th frame dropped
        CHECK(server.AllowFrame(kOtherDuid, t0));    // other DUID unaffected
        CHECK(server.AllowFrame(kClientDuid, t0 + std::chrono::seconds(1)));

        // The same budget gates the message handler.
        Dhcp6Server server2(MakeConfig());
        auto frame = BuildRequest(kDhcp6MsgSolicit, 0x100013, kClientDuid, true,
                                  10, false, nullptr, false);
        Dhcp6View view;
        CHECK(ParseDhcp6Frame(frame.data(), frame.size(), view));
        for (size_t i = 0; i < 8; ++i) {
            std::vector<uint8_t> reply;
            CHECK(server2.HandleFrame(view, kClientMac, kClientLl, t0, reply));
        }
        std::vector<uint8_t> dropped;
        CHECK(!server2.HandleFrame(view, kClientMac, kClientLl, t0, dropped));
    }

    // --- 16. classifier: UDP 546/547 -> kDhcpV6 ---------------------------
    // ------------------------------------------------------------------
    // batch261: frame-header gates and option-layer edges that the earlier
    // suite never reached (each malformed sample used to be rejected by an
    // unrelated downstream guard first).
    // ------------------------------------------------------------------

    /// Flips one byte of a well-formed SOLICIT and expects a reject, with a
    /// positive control so a reject cannot come from the wrong guard.
    void TestParseDhcp6HeaderGates() {
        Dhcp6View view;
        const auto base = BuildRequest(kDhcp6MsgSolicit, 0x020304, kClientDuid,
                                       true, 1, false, nullptr, false);
        CHECK(ParseDhcp6Frame(base.data(), base.size(), view));
        CHECK(view.client_duid == kClientDuid);
        CHECK(view.has_ia_na && view.iaid == 1);

        // A null pointer is rejected instead of dereferenced.
        CHECK(!ParseDhcp6Frame(nullptr, base.size(), view));
        CHECK(!ParseDhcp6Frame(nullptr, 0, view));

        // Non-IPv6 EtherType (0x0800) is rejected even though every other
        // field is intact.
        {
            auto f = base;
            f[12] = 0x08;
            f[13] = 0x00;
            CHECK(!ParseDhcp6Frame(f.data(), f.size(), view));
            // Control: the unmodified EtherType parses.
            CHECK(ParseDhcp6Frame(base.data(), base.size(), view));
        }

        // IPv4 version nibble in the IPv6 header is rejected.
        {
            auto f = base;
            f[kEthernetHeaderLen] = 0x40;
            CHECK(!ParseDhcp6Frame(f.data(), f.size(), view));
        }

        // Non-UDP next header (TCP 0x06) is rejected.
        {
            auto f = base;
            f[kEthernetHeaderLen + 6] = 0x06;
            CHECK(!ParseDhcp6Frame(f.data(), f.size(), view));
            // Control: UDP next header parses.
            CHECK(ParseDhcp6Frame(base.data(), base.size(), view));
        }

        // Source must be link-local; a ULA source is rejected. This sample is
        // otherwise WELL FORMED (the old test's option bytes ran past the
        // payload, so it was rejected by the option guard, not this one).
        {
            const auto ull = BuildFrameRaw(
                {kDhcp6MsgSolicit, 0, 0, 6}, kPrefix, kDhcp6ClientPort,
                kDhcp6ServerPort);
            CHECK(!ParseDhcp6Frame(ull.data(), ull.size(), view));
            const auto llsrc = BuildFrameRaw(
                {kDhcp6MsgSolicit, 0, 0, 6}, kClientLl, kDhcp6ClientPort,
                kDhcp6ServerPort);
            CHECK(!ParseDhcp6Frame(llsrc.data(), llsrc.size(), view));  // no DUID
            // Full frame from a link-local source still parses.
            CHECK(ParseDhcp6Frame(base.data(), base.size(), view));
        }

        // Link-local boundary: fe80:: only. fe40::/feC0:: are not fe80::/10.
        {
            auto ok_ll = kClientLl;
            auto f = BuildRequest(kDhcp6MsgSolicit, 7, kClientDuid, true, 1,
                                  false, nullptr, false);
            CHECK(ParseDhcp6Frame(f.data(), f.size(), view));
            auto mk = [&](uint8_t b1) {
                auto g = BuildFrameRaw({kDhcp6MsgSolicit, 0, 0, 7, 0, 1, 0, 6,
                                        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01},
                                       ok_ll, kDhcp6ClientPort, kDhcp6ServerPort);
                g[kEthernetHeaderLen + 8 + 1] = b1;
                return g;
            };
            CHECK(ParseDhcp6Frame(mk(0x80).data(), mk(0x80).size(), view));
            CHECK(!ParseDhcp6Frame(mk(0x40).data(), mk(0x40).size(), view));
            CHECK(!ParseDhcp6Frame(mk(0xC0).data(), mk(0xC0).size(), view));
            // 0xA0: fe80::/10 -> top two bits 10, but bit 5 is set. A mask
            // widened to 0xE0 would reject this legitimate link-local.
            CHECK(ParseDhcp6Frame(mk(0xA0).data(), mk(0xA0).size(), view));
            // 0x9F: bits 10..., bit 5 clear -> link-local under 0xC0;
            // 0xE0 mask would also accept it. Both must agree here.
            CHECK(ParseDhcp6Frame(mk(0x9F).data(), mk(0x9F).size(), view));
            // Wrong first byte too.
            auto g = mk(0x80);
            g[kEthernetHeaderLen + 8] = 0xFD;
            CHECK(!ParseDhcp6Frame(g.data(), g.size(), view));
        }

        // Source port must be 546; a 545 source is rejected. (The old test
        // only flipped the DESTINATION port.) The payload carries a real
        // Client Identifier, so nothing downstream can reject instead.
        {
            auto mk_port = [&](uint16_t sport, uint16_t dport) {
                std::vector<uint8_t> p = {kDhcp6MsgSolicit, 0, 0, 8};
                PushOption(p, kDhcp6OptClientId, kClientDuid);
                return BuildFrameRaw(p, kClientLl, sport, dport);
            };
            CHECK(ParseDhcp6Frame(mk_port(kDhcp6ClientPort, kDhcp6ServerPort)
                                      .data(),
                                  mk_port(kDhcp6ClientPort, kDhcp6ServerPort)
                                      .size(),
                                  view));
            CHECK(!ParseDhcp6Frame(mk_port(545, kDhcp6ServerPort).data(),
                                   mk_port(545, kDhcp6ServerPort).size(),
                                   view));
            CHECK(!ParseDhcp6Frame(mk_port(kDhcp6ClientPort, 548).data(),
                                   mk_port(kDhcp6ClientPort, 548).size(),
                                   view));
            CHECK(!ParseDhcp6Frame(mk_port(kDhcp6ServerPort, kDhcp6ClientPort)
                                       .data(),
                                   mk_port(kDhcp6ServerPort, kDhcp6ClientPort)
                                       .size(),
                                   view));
        }

        // UDP length must equal the bytes actually held. The decisive sample
        // is SHORTER than the frame and cut exactly on the last option
        // boundary: without the cross-check the parser simply walks the
        // shorter window and accepts, so the check is the only rejecter.
        {
            const size_t ulen_off = kEthernetHeaderLen + 40 + 4;
            auto set_ulen = [&](std::vector<uint8_t>& f, uint16_t v) {
                f[ulen_off] = static_cast<uint8_t>(v >> 8);
                f[ulen_off + 1] = static_cast<uint8_t>(v & 0xFF);
            };
            // A payload of exactly one 14-byte option: declaring udp_len as
            // 8 + 14 is consistent; 8 + 4 drops the option (no Client ID ->
            // still rejected, by a DIFFERENT guard, so that is not used).
            std::vector<uint8_t> p = {kDhcp6MsgSolicit, 0, 0, 9};
            PushOption(p, kDhcp6OptClientId, kClientDuid);
            auto f = BuildFrameRaw(p, kClientLl, kDhcp6ClientPort,
                                   kDhcp6ServerPort);
            const uint16_t want = static_cast<uint16_t>(
                f.size() - kEthernetHeaderLen - 40);
            CHECK(ParseDhcp6Frame(f.data(), f.size(), view));

            // Two Client ID options: the SECOND one is what a shorter
            // udp_len hides. Hiding it is invisible unless it carried
            // different data, so the second DUID is distinct.
            std::vector<uint8_t> p2 = {kDhcp6MsgSolicit, 0, 0, 10};
            PushOption(p2, kDhcp6OptClientId, kClientDuid);
            PushOption(p2, kDhcp6OptClientId, kOtherDuid);
            auto f2 = BuildFrameRaw(p2, kClientLl, kDhcp6ClientPort,
                                    kDhcp6ServerPort);
            Dhcp6View full;
            CHECK(ParseDhcp6Frame(f2.data(), f2.size(), full));
            CHECK(full.client_duid == kOtherDuid);  // last one wins
            const uint16_t full_len = static_cast<uint16_t>(
                f2.size() - kEthernetHeaderLen - 40);
            const uint16_t cut_len = static_cast<uint16_t>(
                full_len - (4 + static_cast<uint16_t>(kOtherDuid.size())));
            set_ulen(f2, cut_len);
            CHECK(!ParseDhcp6Frame(f2.data(), f2.size(), view));

            // Short by one byte: the trailing byte cannot form an option
            // header, so the walk lands mid-stream.
            auto f3 = BuildFrameRaw(p, kClientLl, kDhcp6ClientPort,
                                    kDhcp6ServerPort);
            set_ulen(f3, static_cast<uint16_t>(want - 1));
            CHECK(!ParseDhcp6Frame(f3.data(), f3.size(), view));

            // One byte longer than the frame: the window overruns the buffer.
            auto f4 = BuildFrameRaw(p, kClientLl, kDhcp6ClientPort,
                                    kDhcp6ServerPort);
            set_ulen(f4, static_cast<uint16_t>(want + 1));
            CHECK(!ParseDhcp6Frame(f4.data(), f4.size(), view));
        }

        // Server-originated message types never parse: ADVERTISE and REPLY.
        {
            for (uint8_t mt : {kDhcp6MsgAdvertise, kDhcp6MsgReply}) {
                std::vector<uint8_t> payload = {mt, 0, 0, 9};
                PushOption(payload, kDhcp6OptClientId, kClientDuid);
                auto f = BuildFrameRaw(payload, kClientLl, kDhcp6ClientPort,
                                       kDhcp6ServerPort);
                CHECK(!ParseDhcp6Frame(f.data(), f.size(), view));
            }
            // Control: the same frame with SOLICIT parses.
            std::vector<uint8_t> payload = {kDhcp6MsgSolicit, 0, 0, 9};
            PushOption(payload, kDhcp6OptClientId, kClientDuid);
            auto f = BuildFrameRaw(payload, kClientLl, kDhcp6ClientPort,
                                   kDhcp6ServerPort);
            CHECK(ParseDhcp6Frame(f.data(), f.size(), view));
        }

        // src_ip / dst_ip are copied whole (all 16 bytes), not 15.
        {
            const auto f = BuildRequest(kDhcp6MsgSolicit, 0x0A0B0C, kClientDuid,
                                        true, 1, false, nullptr, false);
            Dhcp6View v;
            CHECK(ParseDhcp6Frame(f.data(), f.size(), v));
            CHECK(v.src_ip == kClientLl);
            CHECK(v.dst_ip == kMulticast);
        }
    }

    /// Option-layer edges: mandatory DUID, DUID bounds, IA_NA layout,
    /// IAADDR layout, trailing bytes.
    void TestParseDhcp6OptionEdges() {
        Dhcp6View view;

        // A SOLICIT WITHOUT any Client Identifier is rejected (RFC 8415 16.1).
        {
            const auto f = BuildFrameRaw({kDhcp6MsgSolicit, 0, 0, 20}, kClientLl,
                                         kDhcp6ClientPort, kDhcp6ServerPort);
            CHECK(!ParseDhcp6Frame(f.data(), f.size(), view));
            // Control: adding only the Client Identifier makes it parse.
            std::vector<uint8_t> payload = {kDhcp6MsgSolicit, 0, 0, 20};
            PushOption(payload, kDhcp6OptClientId, kClientDuid);
            auto g = BuildFrameRaw(payload, kClientLl, kDhcp6ClientPort,
                                   kDhcp6ServerPort);
            CHECK(ParseDhcp6Frame(g.data(), g.size(), view));
            CHECK(view.has_client_id);
        }

        // Server Identifier has the same 1..128 bound; empty and 129 reject.
        // P154 A1: SOLICIT must not carry a Server Identifier, so the bound
        // is exercised with REQUEST (which requires one, RFC 8415 16.4).
        {
            std::vector<uint8_t> p = {kDhcp6MsgRequest, 0, 0, 21};
            PushOption(p, kDhcp6OptClientId, kClientDuid);
            PushOption(p, kDhcp6OptServerId, {});
            PushOption(p, kDhcp6OptIaNa, IaNaPayload(1, false, nullptr));
            auto f = BuildFrameRaw(p, kClientLl, kDhcp6ClientPort,
                                   kDhcp6ServerPort);
            CHECK(!ParseDhcp6Frame(f.data(), f.size(), view));

            std::vector<uint8_t> p2 = {kDhcp6MsgRequest, 0, 0, 22};
            PushOption(p2, kDhcp6OptClientId, kClientDuid);
            PushOption(p2, kDhcp6OptServerId, std::vector<uint8_t>(129, 0x11));
            PushOption(p2, kDhcp6OptIaNa, IaNaPayload(1, false, nullptr));
            auto f2 = BuildFrameRaw(p2, kClientLl, kDhcp6ClientPort,
                                    kDhcp6ServerPort);
            CHECK(!ParseDhcp6Frame(f2.data(), f2.size(), view));

            // Control: a 128-byte server DUID (the documented maximum) parses.
            std::vector<uint8_t> p3 = {kDhcp6MsgRequest, 0, 0, 23};
            PushOption(p3, kDhcp6OptClientId, kClientDuid);
            PushOption(p3, kDhcp6OptServerId, std::vector<uint8_t>(128, 0x22));
            PushOption(p3, kDhcp6OptIaNa, IaNaPayload(1, false, nullptr));
            auto f3 = BuildFrameRaw(p3, kClientLl, kDhcp6ClientPort,
                                    kDhcp6ServerPort);
            CHECK(ParseDhcp6Frame(f3.data(), f3.size(), view));
            CHECK(view.server_duid.size() == 128);
        }

        // IA_NA shorter than its 12-byte fixed part is rejected.
        {
            for (size_t n : {size_t{0}, size_t{11}}) {
                std::vector<uint8_t> p = {kDhcp6MsgSolicit, 0, 0, 24};
                PushOption(p, kDhcp6OptClientId, kClientDuid);
                PushOption(p, kDhcp6OptIaNa, std::vector<uint8_t>(n, 0));
                auto f = BuildFrameRaw(p, kClientLl, kDhcp6ClientPort,
                                       kDhcp6ServerPort);
                CHECK(!ParseDhcp6Frame(f.data(), f.size(), view));
            }
            // Control: exactly 12 parses with no IAADDR.
            std::vector<uint8_t> p = {kDhcp6MsgSolicit, 0, 0, 25};
            PushOption(p, kDhcp6OptClientId, kClientDuid);
            PushOption(p, kDhcp6OptIaNa, IaNaPayload(0x55, false, nullptr));
            auto f = BuildFrameRaw(p, kClientLl, kDhcp6ClientPort,
                                   kDhcp6ServerPort);
            CHECK(ParseDhcp6Frame(f.data(), f.size(), view));
            CHECK(view.has_ia_na && !view.has_ia_addr);
            CHECK(view.iaid == 0x55);
        }

        // IAADDR shorter than its 24-byte fixed part is rejected.
        {
            for (uint16_t n : {uint16_t{0}, uint16_t{23}}) {
                std::vector<uint8_t> ia;
                PushU32(ia, 1);
                PushU32(ia, 0);
                PushU32(ia, 0);
                PushOption(ia, kDhcp6OptIaAddr, std::vector<uint8_t>(n, 0));
                std::vector<uint8_t> p = {kDhcp6MsgSolicit, 0, 0, 26};
                PushOption(p, kDhcp6OptClientId, kClientDuid);
                PushOption(p, kDhcp6OptIaNa, ia);
                auto f = BuildFrameRaw(p, kClientLl, kDhcp6ClientPort,
                                       kDhcp6ServerPort);
                CHECK(!ParseDhcp6Frame(f.data(), f.size(), view));
            }
            // Control: 24 bytes is enough and the address is copied verbatim.
            // Every byte is non-zero: a copy one byte short is then visible
            // in the LAST octet (a trailing zero would hide it).
            std::array<uint8_t, 16> every_byte_set{};
            for (size_t i = 0; i < every_byte_set.size(); ++i) {
                every_byte_set[i] = static_cast<uint8_t>(0xA0 + i);
            }
            std::vector<uint8_t> ia;
            PushU32(ia, 2);
            PushU32(ia, 0);
            PushU32(ia, 0);
            std::vector<uint8_t> addr(every_byte_set.begin(),
                                      every_byte_set.end());
            PushU32(addr, 3600);
            PushU32(addr, 3600);
            PushOption(ia, kDhcp6OptIaAddr, addr);
            std::vector<uint8_t> p = {kDhcp6MsgSolicit, 0, 0, 27};
            PushOption(p, kDhcp6OptClientId, kClientDuid);
            PushOption(p, kDhcp6OptIaNa, ia);
            auto f = BuildFrameRaw(p, kClientLl, kDhcp6ClientPort,
                                   kDhcp6ServerPort);
            CHECK(ParseDhcp6Frame(f.data(), f.size(), view));
            CHECK(view.has_ia_addr && view.ia_addr == every_byte_set);
            CHECK(view.ia_addr[15] == 0xAF);  // the octet a 15-byte copy drops
        }

        // An IAADDR whose declared length runs past the IA_NA payload is
        // rejected (invalid inner option).
        {
            std::vector<uint8_t> ia;
            PushU32(ia, 3);
            PushU32(ia, 0);
            PushU32(ia, 0);
            PushU16(ia, kDhcp6OptIaAddr);
            PushU16(ia, 40);  // claims 40 bytes, only 0 follow
            std::vector<uint8_t> p = {kDhcp6MsgSolicit, 0, 0, 28};
            PushOption(p, kDhcp6OptClientId, kClientDuid);
            PushOption(p, kDhcp6OptIaNa, ia);
            auto f = BuildFrameRaw(p, kClientLl, kDhcp6ClientPort,
                                   kDhcp6ServerPort);
            CHECK(!ParseDhcp6Frame(f.data(), f.size(), view));
        }

        // An IA_NA payload whose inner options do not consume it exactly is
        // rejected (trailing 3 bytes cannot hold another option header).
        {
            std::vector<uint8_t> ia = IaNaPayload(4, false, nullptr);
            ia.push_back(0xAA);
            ia.push_back(0xBB);
            ia.push_back(0xCC);
            std::vector<uint8_t> p = {kDhcp6MsgSolicit, 0, 0, 29};
            PushOption(p, kDhcp6OptClientId, kClientDuid);
            PushOption(p, kDhcp6OptIaNa, ia);
            auto f = BuildFrameRaw(p, kClientLl, kDhcp6ClientPort,
                                   kDhcp6ServerPort);
            CHECK(!ParseDhcp6Frame(f.data(), f.size(), view));
        }

        // Trailing bytes after the last complete option are rejected: the
        // option stream must be consumed exactly.
        {
            std::vector<uint8_t> p = {kDhcp6MsgSolicit, 0, 0, 30};
            PushOption(p, kDhcp6OptClientId, kClientDuid);
            p.push_back(0x00);  // 1 stray byte: too short for a header
            auto f = BuildFrameRaw(p, kClientLl, kDhcp6ClientPort,
                                   kDhcp6ServerPort);
            CHECK(!ParseDhcp6Frame(f.data(), f.size(), view));

            std::vector<uint8_t> p2 = {kDhcp6MsgSolicit, 0, 0, 31};
            PushOption(p2, kDhcp6OptClientId, kClientDuid);
            p2.push_back(0x00);
            p2.push_back(0x01);
            p2.push_back(0x00);  // 3 stray bytes
            auto f2 = BuildFrameRaw(p2, kClientLl, kDhcp6ClientPort,
                                    kDhcp6ServerPort);
            CHECK(!ParseDhcp6Frame(f2.data(), f2.size(), view));

            // Control: the exact stream parses.
            std::vector<uint8_t> p3 = {kDhcp6MsgSolicit, 0, 0, 32};
            PushOption(p3, kDhcp6OptClientId, kClientDuid);
            auto f3 = BuildFrameRaw(p3, kClientLl, kDhcp6ClientPort,
                                    kDhcp6ServerPort);
            CHECK(ParseDhcp6Frame(f3.data(), f3.size(), view));
        }

        // Every message type that requires IA_NA is enforced, and every one
        // that does not is accepted without it.
        // P154: RFC 8415 16.4/16.6/16.8/16.9 make the Server Identifier
        // mandatory for REQUEST/RENEW/RELEASE/DECLINE, while 16.2/16.5/16.7
        // forbid it for SOLICIT/CONFIRM/REBIND. The two groups therefore
        // need different frames to parse.
        {
            const std::vector<uint8_t> needs_sid = {kDhcp6MsgRequest,
                                                    kDhcp6MsgRenew,
                                                    kDhcp6MsgRelease,
                                                    kDhcp6MsgDecline};
            for (uint8_t mt : needs_sid) {
                std::vector<uint8_t> p = {mt, 0, 0, 33};
                PushOption(p, kDhcp6OptClientId, kClientDuid);
                PushOption(p, kDhcp6OptIaNa, IaNaPayload(1, false, nullptr));
                auto f = BuildFrameRaw(p, kClientLl, kDhcp6ClientPort,
                                       kDhcp6ServerPort);
                CHECK(!ParseDhcp6Frame(f.data(), f.size(), view));
                // Control: adding the Server Identifier makes each one parse.
                std::vector<uint8_t> p2 = {mt, 0, 0, 34};
                PushOption(p2, kDhcp6OptClientId, kClientDuid);
                PushOption(p2, kDhcp6OptServerId, kServerDuid);
                PushOption(p2, kDhcp6OptIaNa, IaNaPayload(1, false, nullptr));
                auto f2 = BuildFrameRaw(p2, kClientLl, kDhcp6ClientPort,
                                        kDhcp6ServerPort);
                CHECK(ParseDhcp6Frame(f2.data(), f2.size(), view));
            }
            const std::vector<uint8_t> needs_ia_no_sid = {kDhcp6MsgConfirm,
                                                          kDhcp6MsgRebind};
            for (uint8_t mt : needs_ia_no_sid) {
                std::vector<uint8_t> p = {mt, 0, 0, 33};
                PushOption(p, kDhcp6OptClientId, kClientDuid);
                auto f = BuildFrameRaw(p, kClientLl, kDhcp6ClientPort,
                                       kDhcp6ServerPort);
                CHECK(!ParseDhcp6Frame(f.data(), f.size(), view));
                // Control: adding IA_NA makes each one parse (no Server Id).
                std::vector<uint8_t> p2 = {mt, 0, 0, 34};
                PushOption(p2, kDhcp6OptClientId, kClientDuid);
                PushOption(p2, kDhcp6OptIaNa, IaNaPayload(1, false, nullptr));
                auto f2 = BuildFrameRaw(p2, kClientLl, kDhcp6ClientPort,
                                        kDhcp6ServerPort);
                CHECK(ParseDhcp6Frame(f2.data(), f2.size(), view));
            }
            const std::vector<uint8_t> free_of_ia = {kDhcp6MsgSolicit,
                                                     kDhcp6MsgInformationRequest};
            for (uint8_t mt : free_of_ia) {
                std::vector<uint8_t> p = {mt, 0, 0, 35};
                PushOption(p, kDhcp6OptClientId, kClientDuid);
                auto f = BuildFrameRaw(p, kClientLl, kDhcp6ClientPort,
                                       kDhcp6ServerPort);
                CHECK(!ParseDhcp6Frame(f.data(), f.size(), view) == false);
            }
        }
    }

    /// P154: RFC 8415 section 16 Server Identifier / IA rules and the
    /// CONFIRM/INFORMATION-REQUEST contracts.
    void TestP154ServerIdAndIaRules() {
        Dhcp6View view;
        const std::array<uint8_t, 16> kUnicast = {
            0xFD, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0, 0, 0, 0,
            0,    0,    0,    0x01};

        // A1 (16.2/16.5/16.7): SOLICIT/CONFIRM/REBIND must not carry a
        // Server Identifier - neither our own nor a foreign one.
        for (uint8_t mt : {kDhcp6MsgSolicit, kDhcp6MsgConfirm,
                           kDhcp6MsgRebind}) {
            const bool needs_ia = kDhcp6MsgSolicit != mt;
            for (const std::vector<uint8_t>* sid :
                 {&kServerDuid, &kOtherDuid}) {
                auto bad = BuildRequest(mt, 0x300001, kClientDuid, needs_ia, 1,
                                        false, nullptr, false, *sid);
                CHECK(!ParseDhcp6Frame(bad.data(), bad.size(), view));
            }
            // Positive control: the same message without one parses.
            auto ok = BuildRequest(mt, 0x300002, kClientDuid, needs_ia, 1,
                                   false, nullptr, false);
            CHECK(ParseDhcp6Frame(ok.data(), ok.size(), view));
        }

        // A2 (16.4/16.6/16.8/16.9): REQUEST/RENEW/RELEASE/DECLINE must carry
        // one. Missing it is rejected; our own Server Identifier parses.
        for (uint8_t mt : {kDhcp6MsgRequest, kDhcp6MsgRenew,
                           kDhcp6MsgRelease, kDhcp6MsgDecline}) {
            auto missing = BuildRequest(mt, 0x300003, kClientDuid, true, 1,
                                        false, nullptr, false);
            CHECK(!ParseDhcp6Frame(missing.data(), missing.size(), view));
            auto own = BuildRequest(mt, 0x300004, kClientDuid, true, 1, false,
                                    nullptr, false, kServerDuid);
            CHECK(ParseDhcp6Frame(own.data(), own.size(), view));
            CHECK(view.has_server_id && view.server_duid == kServerDuid);
        }

        // A3 (16.12): INFORMATION-REQUEST carrying any IA option is
        // discarded. IA_TA (4) and IA_PD (25) were previously swallowed by
        // the default branch, so they are exercised explicitly.
        {
            for (uint16_t ia_code :
                 {uint16_t{kDhcp6OptIaNa}, uint16_t{kDhcp6OptIaTa},
                  uint16_t{kDhcp6OptIaPd}}) {
                std::vector<uint8_t> p = {kDhcp6MsgInformationRequest, 0, 0,
                                          0x36};
                PushOption(p, kDhcp6OptClientId, kClientDuid);
                std::vector<uint8_t> ia;
                PushU32(ia, 7);
                PushU32(ia, 0);
                PushU32(ia, 0);
                PushOption(p, ia_code, ia);
                auto f = BuildFrameRaw(p, kClientLl, kDhcp6ClientPort,
                                       kDhcp6ServerPort);
                CHECK(!ParseDhcp6Frame(f.data(), f.size(), view));
            }
            // Positive control: an IA-less INFORMATION-REQUEST parses.
            auto ok = BuildRequest(kDhcp6MsgInformationRequest, 0x300005,
                                   kClientDuid, false, 0, false, nullptr,
                                   false, std::vector<uint8_t>(),
                                   /*oro=*/true);
            CHECK(ParseDhcp6Frame(ok.data(), ok.size(), view));
        }

        // A5 (16 last paragraph): SOLICIT/CONFIRM/REBIND/INFORMATION-REQUEST
        // must arrive on a multicast destination; the other four must not be
        // constrained by this rule.
        {
            for (uint8_t mt : {kDhcp6MsgSolicit, kDhcp6MsgConfirm,
                               kDhcp6MsgRebind,
                               kDhcp6MsgInformationRequest}) {
                std::vector<uint8_t> p = {mt, 0, 0, 0x37};
                PushOption(p, kDhcp6OptClientId, kClientDuid);
                if (kDhcp6MsgInformationRequest != mt) {
                    PushOption(p, kDhcp6OptIaNa,
                               IaNaPayload(1, false, nullptr));
                }
                auto unicast =
                    BuildFrameRawTo(p, kClientLl, kUnicast);
                CHECK(!ParseDhcp6Frame(unicast.data(), unicast.size(), view));
                auto group = BuildFrameRaw(p, kClientLl, kDhcp6ClientPort,
                                           kDhcp6ServerPort);
                CHECK(ParseDhcp6Frame(group.data(), group.size(), view));
            }
            // Control: a REQUEST to a unicast destination stays legal.
            std::vector<uint8_t> req = {kDhcp6MsgRequest, 0, 0, 0x38};
            PushOption(req, kDhcp6OptClientId, kClientDuid);
            PushOption(req, kDhcp6OptServerId, kServerDuid);
            PushOption(req, kDhcp6OptIaNa, IaNaPayload(1, false, nullptr));
            auto req_unicast = BuildFrameRawTo(req, kClientLl, kUnicast);
            CHECK(ParseDhcp6Frame(req_unicast.data(), req_unicast.size(), view));
        }

        // D1: two IA_NA options - the IAID and the IAADDR must come from the
        // SAME IA. The first IA wins, so iaid==1 with the first IA's address.
        {
            std::array<uint8_t, 16> wanted = kPoolStart;
            std::vector<uint8_t> p = {kDhcp6MsgSolicit, 0, 0, 0x39};
            PushOption(p, kDhcp6OptClientId, kClientDuid);
            PushOption(p, kDhcp6OptIaNa,
                       IaNaPayload(1, true, &wanted));
            PushOption(p, kDhcp6OptIaNa,
                       IaNaPayload(2, false, nullptr));
            auto f = BuildFrameRaw(p, kClientLl, kDhcp6ClientPort,
                                   kDhcp6ServerPort);
            CHECK(ParseDhcp6Frame(f.data(), f.size(), view));
            CHECK(view.has_ia_na);
            CHECK(view.iaid == 1);
            CHECK(view.has_ia_addr && view.ia_addr == wanted);
        }

        // A4 (16.12): INFORMATION-REQUEST with a foreign Server Identifier is
        // discarded; our own Server Identifier stays legal.
        {
            Dhcp6Server server(MakeConfig());
            const auto now = std::chrono::steady_clock::now();
            auto foreign = BuildRequest(kDhcp6MsgInformationRequest, 0x300006,
                                        kClientDuid, false, 0, false, nullptr,
                                        false, kOtherDuid, /*oro=*/true);
            Dhcp6View foreign_view;
            CHECK(ParseDhcp6Frame(foreign.data(), foreign.size(),
                                  foreign_view));
            std::vector<uint8_t> ignored;
            CHECK(!server.HandleFrame(foreign_view, kClientMac, kClientLl, now,
                                      ignored));

            Dhcp6Server own_server(MakeConfig());
            auto own = BuildRequest(kDhcp6MsgInformationRequest, 0x300007,
                                    kClientDuid, false, 0, false, nullptr,
                                    false, own_server.ServerDuid(),
                                    /*oro=*/true);
            Dhcp6View own_view;
            CHECK(ParseDhcp6Frame(own.data(), own.size(), own_view));
            std::vector<uint8_t> reply;
            CHECK(own_server.HandleFrame(own_view, kClientMac, kClientLl, now,
                                         reply));
            ParsedReply parsed;
            CHECK(ParseReply(reply, parsed));
            CHECK(parsed.msg_type == kDhcp6MsgReply);
            CHECK(parsed.dns.size() == 2);
        }

        // B' (18.3.3): a CONFIRM whose IA carries no IAADDR must not be
        // answered at all.
        {
            Dhcp6Server server(MakeConfig());
            const auto now = std::chrono::steady_clock::now();
            auto no_addr = BuildRequest(kDhcp6MsgConfirm, 0x300008, kClientDuid,
                                        true, 1, false, nullptr, false);
            Dhcp6View no_addr_view;
            CHECK(ParseDhcp6Frame(no_addr.data(), no_addr.size(),
                                  no_addr_view));
            CHECK(!no_addr_view.has_ia_addr);
            std::vector<uint8_t> ignored;
            CHECK(!server.HandleFrame(no_addr_view, kClientMac, kClientLl, now,
                                      ignored));

            // Positive control: with an in-prefix IAADDR a Reply is sent.
            std::array<uint8_t, 16> on_link = kPoolStart;
            auto with_addr = BuildRequest(kDhcp6MsgConfirm, 0x300009,
                                          kClientDuid, true, 1, true, &on_link,
                                          false);
            Dhcp6View with_addr_view;
            CHECK(ParseDhcp6Frame(with_addr.data(), with_addr.size(),
                                  with_addr_view));
            std::vector<uint8_t> reply;
            CHECK(server.HandleFrame(with_addr_view, kClientMac, kClientLl, now,
                                     reply));
            ParsedReply parsed;
            CHECK(ParseReply(reply, parsed));
            CHECK(parsed.msg_type == kDhcp6MsgReply);
            CHECK(parsed.has_status &&
                  parsed.status == kDhcp6StatusSuccess && parsed.top_status);
        }

        // C/E4: HandleFrame is public, so a directly built RELEASE view with
        // no Server Identifier must not fall through to Release()'s lenient
        // "empty server-id" deletion.
        {
            Dhcp6Server server(MakeConfig());
            const auto t0 = std::chrono::steady_clock::now();
            const auto held = server.Acquire(kClientDuid, 9, t0,
                                             Dhcp6Server::OfferStage::kAck);
            CHECK(!IsZeroAddr(held));
            CHECK(server.LeaseCount() == 1);
            Dhcp6View bare;
            bare.msg_type = kDhcp6MsgRelease;
            bare.xid = 0x30000A;
            bare.client_duid = kClientDuid;
            bare.has_ia_na = true;
            bare.iaid = 9;
            std::vector<uint8_t> ignored;
            CHECK(!server.HandleFrame(bare, kClientMac, kClientLl, t0,
                                      ignored));
            CHECK(server.LeaseCount() == 1);
        }
    }

    /// Build-side: preferred/valid byte order, rapid-commit option, and the
    /// IA_NA / IAADDR option nesting shape.
    void TestBuildReplyFrameByteOrder() {
        const auto server_ll = vgww::proto::LinkLocalFromMac(kGatewayMac);
        Dhcp6Reply reply;
        reply.msg_type = kDhcp6MsgReply;
        reply.xid = 0x0A0B0C;
        reply.client_duid = kClientDuid;
        reply.server_duid = {0x00, 0x03, 0x00, 0x01, 0x30, 0xFC,
                             0x68, 0x88, 0xB4, 0xA9};
        reply.with_ia_na = true;
        reply.iaid = 0x11223344;
        reply.t1 = 0x00000111;
        reply.t2 = 0x00000222;
        reply.with_ia_addr = true;
        reply.ia_addr = kPoolStart;
        // Distinct values with distinct byte patterns, so a swap is visible.
        reply.preferred_s = 0x11223344;
        reply.valid_s = 0x55667788;

        std::vector<uint8_t> frame;
        BuildDhcp6ReplyFrame(reply, kGatewayMac, kClientMac, server_ll,
                             kClientLl, frame);
        ParsedReply p;
        CHECK(ParseReply(frame, p));
        CHECK(p.preferred == 0x11223344);
        CHECK(p.valid == 0x55667788);

        // The IAADDR bytes sit at a known offset: 16 address bytes then two
        // big-endian u32. Read them straight off the wire.
        const uint8_t* payload = frame.data() + kEthernetHeaderLen + 40 +
                                 kUdpHeaderLen + 4;
        const size_t payload_len =
            frame.size() - kEthernetHeaderLen - 40 - kUdpHeaderLen - 4;
        size_t pos = 0;
        bool saw_ia = false;
        bool saw_addr = false;
        while (pos + 4 <= payload_len) {
            const uint16_t code = static_cast<uint16_t>((payload[pos] << 8) |
                                                        payload[pos + 1]);
            const uint16_t olen = static_cast<uint16_t>(
                (payload[pos + 2] << 8) | payload[pos + 3]);
            const uint8_t* v = payload + pos + 4;
            if (pos + 4 + olen > payload_len) { break; }
            if (kDhcp6OptIaNa == code) {
                saw_ia = true;
                size_t inner = 12;
                while (inner + 4 <= olen) {
                    const uint16_t ic = static_cast<uint16_t>(
                        (v[inner] << 8) | v[inner + 1]);
                    const uint16_t il =
                        static_cast<uint16_t>((v[inner + 2] << 8) |
                                              v[inner + 3]);
                    if (inner + 4 + il > olen) { break; }
                    if (kDhcp6OptIaAddr == ic && il >= 24) {
                        saw_addr = true;
                        CHECK(0 == std::memcmp(v + inner + 4, kPoolStart.data(),
                                               16));
                        const uint8_t* d = v + inner + 4 + 16;
                        CHECK(d[0] == 0x11 && d[1] == 0x22 && d[2] == 0x33 &&
                              d[3] == 0x44);  // preferred, big-endian
                        CHECK(d[4] == 0x55 && d[5] == 0x66 && d[6] == 0x77 &&
                              d[7] == 0x88);  // valid, big-endian
                    }
                    inner += 4 + il;
                }
            }
            pos += 4 + olen;
        }
        CHECK(saw_ia && saw_addr);

        // rapid_commit echoes as a zero-length option 14.
        Dhcp6Reply rc = reply;
        rc.rapid_commit = true;
        std::vector<uint8_t> rc_frame;
        BuildDhcp6ReplyFrame(rc, kGatewayMac, kClientMac, server_ll, kClientLl,
                             rc_frame);
        ParsedReply rp;
        CHECK(ParseReply(rc_frame, rp));
        CHECK(rp.rapid_commit);
        // Control: without the flag the option is absent.
        CHECK(!p.rapid_commit);

        // An empty client DUID and empty server DUID emit no option at all.
        Dhcp6Reply bare;
        bare.msg_type = kDhcp6MsgReply;
        bare.xid = 1;
        std::vector<uint8_t> bare_frame;
        BuildDhcp6ReplyFrame(bare, kGatewayMac, kClientMac, server_ll,
                             kClientLl, bare_frame);
        ParsedReply bp;
        CHECK(ParseReply(bare_frame, bp));
        CHECK(!bp.has_client_id && !bp.has_server_id && !bp.has_ia &&
              !bp.has_status && !bp.rapid_commit && bp.dns.empty());

        // with_dns but an empty list emits nothing.
        Dhcp6Reply nodns = reply;
        nodns.with_dns = true;
        nodns.dns.clear();
        std::vector<uint8_t> nd_frame;
        BuildDhcp6ReplyFrame(nodns, kGatewayMac, kClientMac, server_ll,
                             kClientLl, nd_frame);
        ParsedReply nd;
        CHECK(ParseReply(nd_frame, nd));
        CHECK(nd.dns.empty());

        // A top-level status (outside IA_NA) lands at the top level.
        Dhcp6Reply top = reply;
        top.with_ia_na = false;
        top.with_ia_addr = false;
        top.with_dns = false;
        top.with_status = true;
        top.status_in_ia = false;
        top.status = kDhcp6StatusNoBinding;
        std::vector<uint8_t> top_frame;
        BuildDhcp6ReplyFrame(top, kGatewayMac, kClientMac, server_ll, kClientLl,
                             top_frame);
        ParsedReply tp;
        CHECK(ParseReply(top_frame, tp));
        CHECK(tp.has_status && tp.top_status && !tp.ia_status);
        CHECK(tp.status == kDhcp6StatusNoBinding);
    }

    void TestClassifierDhcpV6() {
        vgww::dsp::FrameView view;
        auto client_to_server = BuildFrameRaw(
            {1, 0, 0, 1}, kClientLl, kDhcp6ClientPort, kDhcp6ServerPort);
        CHECK(vgww::dsp::ClassifyFrame(client_to_server.data(),
                                       client_to_server.size(), view));
        CHECK(view.cls == vgww::dsp::FrameClass::kDhcpV6);
        CHECK(view.src_port == kDhcp6ClientPort);
        CHECK(view.dst_port == kDhcp6ServerPort);

        auto server_to_client = BuildFrameRaw(
            {2, 0, 0, 1}, kClientLl, kDhcp6ServerPort, kDhcp6ClientPort);
        CHECK(vgww::dsp::ClassifyFrame(server_to_client.data(),
                                       server_to_client.size(), view));
        CHECK(view.cls == vgww::dsp::FrameClass::kDhcpV6);

        // Ordinary UDP on non-DHCPv6 ports must not be misclassified. The
        // frame still targets the v6 multicast group (ff02::1:2), so C9 sends
        // it to the host path (kOther) instead of NATing it as unicast.
        auto plain = BuildFrameRaw({0, 0, 0, 0}, kClientLl, 5000, 5001);
        CHECK(vgww::dsp::ClassifyFrame(plain.data(), plain.size(), view));
        CHECK(view.cls == vgww::dsp::FrameClass::kOther);

        // TCP on 547 stays TCP.
        std::vector<uint8_t> tcp(kEthernetHeaderLen + 40 + 20, 0);
        BuildEthHeader(tcp.data(), kClientMac, kGatewayMac, kEthertypeIpv6);
        tcp[kEthernetHeaderLen] = 0x60;
        tcp[kEthernetHeaderLen + 6] = 6;  // TCP
        tcp[kEthernetHeaderLen + 40 + 2] = 0x02;  // dst port 547
        tcp[kEthernetHeaderLen + 40 + 3] = 0x23;
        CHECK(vgww::dsp::ClassifyFrame(tcp.data(), tcp.size(), view));
        CHECK(view.cls == vgww::dsp::FrameClass::kTcpV6);
    }

// batch81: DumpLeases must not hold the lease mutex while it serializes and
// writes the file. That mutex is the one Acquire()/Decline()/Sweep() take on
// the RX and control threads, so disk I/O with FlushFileBuffers inside it
// stalls real DHCP frames: measured 86 ms of blocked renews at 4096 leases and
// 484 ms at 20000, against a 0.08-0.4 ms baseline with no dump running.
//
// The assertion is a SAME-PROCESS RATIO, not an absolute millisecond bound.
// Absolute time in this test is meaningless (batch78: the host's timer quantum
// and scheduler noise dominate it). Instead the same O(1) LeaseCount() probe
// runs twice in one process - once with no dump (baseline) and once while the
// dump is in flight - and we assert the dump window's worst wait is not an
// order of magnitude worse than the baseline. Both windows pay the same
// quantization and scheduling costs, so they cancel out in the ratio.
//
// LeaseCount() rather than Acquire() for the probe: it takes the same mutex_
// but does O(1) work, so its measured time IS the lock wait rather than the
// O(N) free-address scan Acquire() performs for a new lease.
static void TestB81DumpLeasesDoesNotStallLockHolders() {
    Config config = MakeConfig();
    config.ipv6.dhcpv6.pool_end[14] = 0x1F;  // 4096 addresses
    Dhcp6Server server(config);
    const auto now = std::chrono::steady_clock::now();
    // Long hostnames make the JSON build substantial - that build is exactly
    // the work that used to run under the lock. Clamped to the 253-byte
    // option ceiling: a longer name is refused by ReplaceBinding, and 4096
    // rows must also stay under kMaxLeasesBytes so the dump is ACCEPTED here
    // (P145-V6 refuses an unreadable document by design).
    const std::string filler(250, 'h');
    for (uint32_t i = 0; i < 4096; ++i) {
        const std::vector<uint8_t> duid = {
            0x00, 0x03, 0x00, 0x01, static_cast<uint8_t>(i >> 24),
            static_cast<uint8_t>(i >> 16), static_cast<uint8_t>(i >> 8),
            static_cast<uint8_t>(i)};
        server.Acquire(duid, 1, now, Dhcp6Server::OfferStage::kAck, filler);
    }
    CHECK(server.LeaseCount() > 3000);  // the window below needs a real map

    std::atomic<bool> started{false};
    std::atomic<bool> stop{false};
    std::atomic<long long> worst_us{0};
    std::atomic<long long> probes{0};
    std::thread prober([&] {
        while (!started.load(std::memory_order_acquire)) {
            std::this_thread::yield();
        }
        while (!stop.load(std::memory_order_acquire)) {
            const auto t0 = std::chrono::steady_clock::now();
            volatile size_t n = server.LeaseCount();
            (void)n;
            const long long dt =
                std::chrono::duration_cast<std::chrono::microseconds>(
                    std::chrono::steady_clock::now() - t0)
                    .count();
            long long prev = worst_us.load(std::memory_order_relaxed);
            while (dt > prev && !worst_us.compare_exchange_weak(prev, dt)) {
            }
            probes.fetch_add(1, std::memory_order_relaxed);
        }
    });
    started.store(true, std::memory_order_release);

    const std::string path = ScratchFile("test_b81_leases6.json");
    std::error_code rm_ec_22;
    std::filesystem::remove(path, rm_ec_22);
    std::error_code rm_ec_23;
    std::filesystem::remove(path + ".tmp", rm_ec_23);

    // Window 1 (baseline): no dump, just the probe contending with itself.
    while (probes.load(std::memory_order_relaxed) < 50) {
        std::this_thread::yield();
    }
    const auto b0 = std::chrono::steady_clock::now();
    while (std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::steady_clock::now() - b0)
               .count() < 150) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    const long long baseline_us = worst_us.exchange(0);
    const long long baseline_probes = probes.exchange(0);
    const long long baseline_us_window =
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - b0)
            .count();

    // Window 2: run the dump repeatedly while the probe keeps contending.
    bool all_dumped = true;
    long long dump_total_us = 0;
    for (int i = 0; i < 5; ++i) {
        const auto d0 = std::chrono::steady_clock::now();
        if (!server.DumpLeases(path, now)) {
            all_dumped = false;
        }
        dump_total_us +=
            std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now() - d0)
                .count();
    }
    const long long dump_us = worst_us.exchange(0);
    const long long dump_probes = probes.exchange(0);
    stop.store(true, std::memory_order_release);
    prober.join();

    std::printf(
        "B81 baseline_worst_us=%lld (probes=%lld)  dump_worst_us=%lld "
        "(probes=%lld) dump_total_us=%lld\n",
        baseline_us, baseline_probes, dump_us, dump_probes, dump_total_us);
    CHECK(all_dumped);
    CHECK(baseline_probes > 10);  // the baseline window must actually run
    CHECK(dump_probes > 10);
    // The lock hold must be a SMALL FRACTION of the dump, not the dump itself.
    //
    // This is the invariant that actually matters and it is scale-free: what
    // the fix changed is WHO the file write blocks. With the I/O under the
    // lock, one dump parks a lease reader for essentially the whole call
    // (measured 98-114 ms of a ~190 ms dump). With the lock released, the hold
    // is only the O(N) snapshot copy, which is a small slice of the same call.
    // Comparing the two windows of the SAME measure keeps this free of
    // absolute-time assumptions (batch78), and the 2/5 bound leaves a wide
    // margin in both directions: red measures ~0.5-0.6, green ~0.01-0.08.
    // The probe RATE is the direct measure of how much of the dump the reader
    // was locked out. Both windows run the SAME O(1) probe against the same
    // server, so the rates are comparable even though the windows differ in
    // length; normalizing by each window keeps this independent of how long
    // this host takes to do the I/O. Measured: the reader kept 146-170 k
    // probes while the lock covered the write (a ~380/s rate against a
    // ~1.7 M/s baseline), versus 5.7-7.7 M probes once the lock is released
    // early (a rate that matches the baseline).
    const double baseline_rate =
        static_cast<double>(baseline_probes) /
        static_cast<double>(baseline_us_window > 0 ? baseline_us_window : 1);
    const double dump_rate =
        static_cast<double>(dump_probes) /
        static_cast<double>(dump_total_us > 0 ? dump_total_us : 1);
    std::printf("B81 rate baseline=%.3f/us dump=%.3f/us ratio=%.2f\n",
                baseline_rate, dump_rate,
                dump_rate > 0.0 ? baseline_rate / dump_rate : 0.0);
    // 5x: red measures a 40x-400x drop; green stays within a small factor.
    CHECK(dump_rate * 5.0 > baseline_rate);
    std::error_code rm_ec_24;
    std::filesystem::remove(path, rm_ec_24);
    std::error_code rm_ec_25;
    std::filesystem::remove(path + ".tmp", rm_ec_25);
}

}  // namespace

    // batch110 (C7 same-shape sweep): the DHCPv6 runtime store had exactly the
    // same missing cap. Its web route checks kMaxStaticBindings6 out-of-lock
    // (web_api.cpp:2046) and the loader/ValidateConfig cap too, but
    // Dhcp6Server::UpsertBinding - the choke point the UI binding form also
    // reaches through Dataplane::SetDhcp6Binding - capped nothing.
    //
    // Asserted separately from the v4 case: a fix applied to only one of the
    // two siblings leaves the other entry open, and a single test on v4 would
    // stay green (batch86 "same-shape sites must be mutated one by one").
    void TestB110RuntimeBinding6CapIsEnforcedInTheStore() {
        vgww::core::Config config;
        config.ipv6.enabled = true;
        config.ipv6.ula_prefix = {0xFD, 0x00, 0x11, 0x22, 0x33, 0x44,
                                  0x55, 0x66, 0, 0, 0, 0, 0, 0, 0, 0};
        config.ipv6.prefix_len = 64;
        config.ipv6.dhcpv6.enabled = true;
        config.ipv6.dhcpv6.lease_seconds = 3600;

        Dhcp6Server server(config);
        const size_t cap = ::vgww::core::limits::kMaxStaticBindings6;

        const auto duid_of = [](uint32_t i) {
            return std::vector<uint8_t>{0x00, 0x03, 0x00, 0x01,
                                        static_cast<uint8_t>((i >> 24) & 0xFF),
                                        static_cast<uint8_t>((i >> 16) & 0xFF),
                                        static_cast<uint8_t>((i >> 8) & 0xFF),
                                        static_cast<uint8_t>(i & 0xFF)};
        };
        const auto ip_of = [](uint32_t i) {
            std::array<uint8_t, 16> addr{};
            addr[0] = 0xFD;
            addr[1] = 0x00;
            addr[2] = 0x11;
            addr[3] = 0x22;
            addr[4] = 0x33;
            addr[5] = 0x44;
            addr[6] = 0x55;
            addr[7] = 0x66;
            addr[12] = static_cast<uint8_t>((i >> 24) & 0xFF);
            addr[13] = static_cast<uint8_t>((i >> 16) & 0xFF);
            addr[14] = static_cast<uint8_t>((i >> 8) & 0xFF);
            addr[15] = static_cast<uint8_t>(i & 0xFF);
            return addr;
        };

        for (uint32_t i = 1; i <= cap; ++i) {
            CHECK(server.UpsertBinding(duid_of(i), ip_of(i), ""));
        }
        CHECK(server.StaticBindings().size() == cap);

        // One past the cap must be refused and must not grow the store.
        CHECK(!server.UpsertBinding(duid_of(cap + 1), ip_of(cap + 1), ""));
        CHECK(server.StaticBindings().size() == cap);

        // Editing an already-bound DUID stays legal at the cap.
        CHECK(server.UpsertBinding(duid_of(1), ip_of(1), "renamed6"));
        CHECK(server.StaticBindings().size() == cap);
    }

    // batch111 (C7 same-shape sweep): Dhcp6Server::UpsertBinding had the same
    // missing hostname bound. The v6 loader (config.cpp:720) and
    // ValidateConfig (:1533) both cap at 253, and the v6 lease dump copies the
    // hostname into JSON, so an unbounded runtime hostname is both a contract
    // split and a memory amplification here too.
    //
    // Separate assertions from the v4 case: fixing one sibling leaves the other
    // open, and a v4-only test stays green (batch86).
    void TestB111RuntimeBinding6RejectsOversizedHostname() {
        vgww::core::Config config;
        config.ipv6.enabled = true;
        config.ipv6.ula_prefix = {0xFD, 0x00, 0x11, 0x22, 0x33, 0x44,
                                  0x55, 0x66, 0, 0, 0, 0, 0, 0, 0, 0};
        config.ipv6.prefix_len = 64;
        config.ipv6.dhcpv6.enabled = true;
        config.ipv6.dhcpv6.lease_seconds = 3600;

        Dhcp6Server server(config);
        const std::vector<uint8_t> duid{0x00, 0x03, 0x00, 0x01,
                                        0xAA, 0xBB, 0xCC, 0xDD};
        std::array<uint8_t, 16> ip{};
        ip[0] = 0xFD;
        ip[1] = 0x00;
        ip[2] = 0x11;
        ip[3] = 0x22;
        ip[4] = 0x33;
        ip[5] = 0x44;
        ip[6] = 0x55;
        ip[7] = 0x66;
        ip[15] = 0x42;

        const std::string at_limit(253, 'a');
        CHECK(server.UpsertBinding(duid, ip, at_limit));
        CHECK(server.StaticBindings().size() == 1);
        CHECK(server.StaticBindings()[0].hostname == at_limit);

        const std::string over_limit(254, 'b');
        CHECK(!server.UpsertBinding(duid, ip, over_limit));
        CHECK(server.StaticBindings().size() == 1);
        CHECK(server.StaticBindings()[0].hostname == at_limit);

        const std::string huge(64 * 1024, 'c');
        CHECK(!server.UpsertBinding(duid, ip, huge));
        CHECK(server.StaticBindings().size() == 1);
        CHECK(server.StaticBindings()[0].hostname == at_limit);
    }

    // batch123 (same-shape sibling of the v4 fix): the v6 control path must
    // also refuse an ill-formed hostname. nlohmann::json::dump() throws
    // type_error.316 on an ill-formed byte, and the v6 dump runs on the 60 s
    // control cadence, so a bad name would make every dump throw (RunGuarded
    // then flips `running` false and stops the data plane). The v6 wire path
    // never carries a client hostname (Acquire is called with an empty name),
    // so only the control path needs the reject; the assertion is kept separate
    // from the v4 case so a v4-only fix stays red here (batch86).
    void TestB123UpsertBinding6RejectsIllFormedUtf8Hostname() {
        vgww::core::Config config;
        config.ipv6.enabled = true;
        config.ipv6.ula_prefix = {0xFD, 0x00, 0x11, 0x22, 0x33, 0x44,
                                  0x55, 0x66, 0, 0, 0, 0, 0, 0, 0, 0};
        config.ipv6.prefix_len = 64;
        config.ipv6.dhcpv6.enabled = true;
        config.ipv6.dhcpv6.lease_seconds = 3600;

        Dhcp6Server server(config);
        const std::vector<uint8_t> duid{0x00, 0x03, 0x00, 0x01,
                                        0xAA, 0xBB, 0xCC, 0xDD};
        std::array<uint8_t, 16> ip{};
        ip[0] = 0xFD;
        ip[1] = 0x00;
        ip[2] = 0x11;
        ip[3] = 0x22;
        ip[4] = 0x33;
        ip[5] = 0x44;
        ip[6] = 0x55;
        ip[7] = 0x66;
        ip[15] = 0x24;

        const std::string good = "office-nas";
        CHECK(server.UpsertBinding(duid, ip, good));
        CHECK(server.StaticBindings().size() == 1);

        std::string bad = "nas";
        bad.push_back(static_cast<char>(0xFF));
        CHECK(!server.UpsertBinding(duid, ip, bad));
        CHECK(server.StaticBindings().size() == 1);
        CHECK(server.StaticBindings()[0].hostname == good);

        // A well-formed multi-byte name is still accepted.
        const std::string cjk = "\xE5\xAE\xA2\xE6\x88\xB7";
        CHECK(server.UpsertBinding(duid, ip, cjk));
        CHECK(server.StaticBindings().size() == 1);
        CHECK(server.StaticBindings()[0].hostname == cjk);
    }

    // batch112 (C7 same-shape sweep): Dhcp6Server::UpsertBinding had the same
    // one-sided collision check. batch109 added the runtime->pool direction
    // (ReservedByStatic), but a live DYNAMIC lease on the requested address was
    // never consulted, so binding a second DUID onto an address already leased
    // to a client produced two owners for one address.
    //
    // Separate fixtures/assertions from the v4 case: fixing one sibling leaves
    // the other open, and a v4-only test stays green.
    void TestB112RuntimeBinding6RejectsAddressHeldByLiveLease() {
        vgww::core::Config config;
        config.ipv6.enabled = true;
        config.ipv6.ula_prefix = {0xFD, 0x00, 0x11, 0x22, 0x33, 0x44,
                                  0x55, 0x66, 0, 0, 0, 0, 0, 0, 0, 0};
        config.ipv6.prefix_len = 64;
        config.ipv6.dhcpv6.enabled = true;
        config.ipv6.dhcpv6.lease_seconds = 3600;
        // A two-address pool (IID 1..2) so the first Acquire is deterministic.
        config.ipv6.dhcpv6.pool_start = {0xFD, 0x00, 0x11, 0x22, 0x33, 0x44,
                                         0x55, 0x66, 0, 0, 0, 0, 0, 0, 0, 1};
        config.ipv6.dhcpv6.pool_end = {0xFD, 0x00, 0x11, 0x22, 0x33, 0x44,
                                       0x55, 0x66, 0, 0, 0, 0, 0, 0, 0, 2};

        Dhcp6Server server(config);
        const std::vector<uint8_t> holder_duid{0x00, 0x03, 0x00, 0x01,
                                               0xAA, 0x00, 0x00, 0x01};
        const std::vector<uint8_t> newcomer_duid{0x00, 0x03, 0x00, 0x01,
                                                 0xAA, 0x00, 0x00, 0x02};
        const auto now = std::chrono::steady_clock::now();

        const auto granted = server.Acquire(holder_duid, 1, now, Dhcp6Server::OfferStage::kAck);
        CHECK(!IsZeroAddr(granted));

        // Binding a second DUID onto the live lease's address must be refused
        // and must not create a runtime binding.
        CHECK(!server.UpsertBinding(newcomer_duid, granted));
        CHECK(server.StaticBindings().empty());

        // The pool must not hand the same address to a third client either.
        std::array<uint8_t, 16> requested = granted;
        const auto other = server.Acquire(newcomer_duid, 2, now,
                                          Dhcp6Server::OfferStage::kAck, "",
                                          &requested);
        CHECK(!(other == granted));

        // A free pool address is still bindable (the rejection is specific to
        // the live lease, not to the pool).
        std::array<uint8_t, 16> free_ip{};
        free_ip[0] = 0xFD;
        free_ip[1] = 0x00;
        free_ip[2] = 0x11;
        free_ip[3] = 0x22;
        free_ip[4] = 0x33;
        free_ip[5] = 0x44;
        free_ip[6] = 0x55;
        free_ip[7] = 0x66;
        free_ip[15] = 0x02;
        CHECK(server.UpsertBinding(newcomer_duid, free_ip));
        CHECK(server.StaticBindings().size() == 1);

        // Promoting the holder's OWN live lease to a static reservation stays
        // legal: the client is not "someone else".
        CHECK(server.UpsertBinding(holder_duid, granted));
        CHECK(server.StaticBindings().size() == 2);

        // An EXPIRED lease is not an owner. leases_ is only swept every 5 s,
        // so an entry can outlive its expiry for a while; it must not keep
        // rejecting a legitimate bind in that window. UpsertBinding reads
        // steady_clock::now() itself, so the lease is created in the PAST.
        Dhcp6Server stale(config);
        const auto long_ago =
            now - std::chrono::seconds(config.ipv6.dhcpv6.lease_seconds + 60);
        const auto stale_ip = stale.Acquire(holder_duid, 7, long_ago,
                                            Dhcp6Server::OfferStage::kAck);
        CHECK(!IsZeroAddr(stale_ip));
        CHECK(stale.UpsertBinding(newcomer_duid, stale_ip));
        CHECK(stale.StaticBindings().size() == 1);
    }


    // batch114 (C7 same-shape sweep of the v4 fix): the DHCPv6 pool walk also
    // rescanned every lease for every candidate address. The v6 pool is an
    // IID range whose size is user-configurable, so the quadratic shape is at
    // least as dangerous here. The discriminator is the same one used for v4:
    // fill the pool, then require that ONE exhausted acquisition probes the
    // lease table O(leases) times, not O(pool_size x leases).
    void TestB114Acquire6WalkDoesNotScanLeasesPerCandidate() {
        vgww::core::Config config;
        config.ipv6.enabled = true;
        config.ipv6.ula_prefix = {0xFD, 0x00, 0x11, 0x22, 0x33, 0x44,
                                  0x55, 0x66, 0, 0, 0, 0, 0, 0, 0, 0};
        config.ipv6.prefix_len = 64;
        config.ipv6.dhcpv6.enabled = true;
        config.ipv6.dhcpv6.lease_seconds = 3600;
        // A 1024-address IID pool (::1 .. ::400).
        config.ipv6.dhcpv6.pool_start = {0xFD, 0x00, 0x11, 0x22, 0x33, 0x44,
                                         0x55, 0x66, 0, 0, 0, 0, 0, 0, 0, 1};
        config.ipv6.dhcpv6.pool_end = {0xFD, 0x00, 0x11, 0x22, 0x33, 0x44,
                                       0x55, 0x66, 0, 0, 0, 0, 0, 0, 0x04, 0x00};

        Dhcp6Server server(config);
        const auto now = std::chrono::steady_clock::now();

        // Fill the pool.
        for (size_t i = 0; i < 1024; ++i) {
            std::vector<uint8_t> duid{0x00, 0x03, 0x00, 0x01,
                                      0xAA, static_cast<uint8_t>(i >> 8),
                                      static_cast<uint8_t>(i & 0xFF), 0x00};
            if (server.Acquire(duid, 1, now, Dhcp6Server::OfferStage::kAck)
                    .empty()) {
                break;
            }
        }
        const size_t leases = server.LeaseCount();
        CHECK(leases > 1000);

        // One more client cannot be served: the walk visits all candidates.
        const uint64_t before = server.LeaseScanCount();
        const std::vector<uint8_t> extra{0x00, 0x03, 0x00, 0x01,
                                         0xBB, 0x00, 0x00, 0x01};
        const auto denied =
            server.Acquire(extra, 1, now, Dhcp6Server::OfferStage::kAck);
        CHECK(IsZeroAddr(denied));
        const uint64_t probes = server.LeaseScanCount() - before;

        // Fixed: one pass over the leases (~leases). Old: ~leases x pool_size
        // (~1e6 here).
        const uint64_t budget = static_cast<uint64_t>(leases) + 4096;
        CHECK(probes <= budget);
        std::printf("b114v6 probes=%llu budget=%llu leases=%zu\n",
                    static_cast<unsigned long long>(probes),
                    static_cast<unsigned long long>(budget), leases);
    }
    // batch137: v6 sibling of TestB137ReplaceBindingIsAtomic. Editing a
    // binding's DUID was TWO commands (remove, then add); either half could be
    // refused alone, deleting the client's binding and storing nothing.
    // ReplaceBinding commits the drop and the insert under one lock.
    void TestB137ReplaceBinding6IsAtomic() {
        Config config = MakeConfig();
        const std::vector<uint8_t> old_duid{0x00, 0x03, 0x00, 0x01,
                                            0xAA, 0x00, 0x00, 0x01};
        const std::vector<uint8_t> new_duid{0x00, 0x03, 0x00, 0x01,
                                            0xAA, 0x00, 0x00, 0x02};
        const std::vector<uint8_t> third_duid{0x00, 0x03, 0x00, 0x01,
                                              0xAA, 0x00, 0x00, 0x03};
        auto addr_of = [](uint8_t last) {
            std::array<uint8_t, 16> a{};
            a[0] = 0xFD; a[1] = 0x00; a[2] = 0x11; a[3] = 0x22;
            a[4] = 0x33; a[5] = 0x44; a[6] = 0x55; a[7] = 0x66;
            a[15] = last;
            return a;
        };
        const auto old_ip = addr_of(0x11);
        const auto new_ip = addr_of(0x12);
        const auto taken = addr_of(0x13);

        {
            // Happy path: old key gone, new key present with the new name.
            Dhcp6Server server(config);
            CHECK(server.UpsertBinding(old_duid, old_ip, "nas"));
            CHECK(server.ReplaceBinding(old_duid, new_duid, old_ip, "nas2"));
            const auto views = server.StaticBindings();
            CHECK(views.size() == 1);
            if (views.size() == 1) {
                CHECK(views[0].duid == new_duid);
                CHECK(views[0].ip == old_ip);
                CHECK(views[0].hostname == "nas2");
            }
        }

        {
            // Re-key onto an address another DUID owns: refused, old intact.
            Dhcp6Server server(config);
            CHECK(server.UpsertBinding(old_duid, old_ip, "keep"));
            CHECK(server.UpsertBinding(third_duid, taken, "other"));
            CHECK(!server.ReplaceBinding(old_duid, new_duid, taken, "clash"));
            const auto views = server.StaticBindings();
            CHECK(views.size() == 2);
            bool old_intact = false;
            bool new_absent = true;
            for (const auto& view : views) {
                if (view.duid == old_duid && view.ip == old_ip &&
                    view.hostname == "keep") {
                    old_intact = true;
                }
                if (view.duid == new_duid) {
                    new_absent = false;
                }
            }
            CHECK(old_intact);
            CHECK(new_absent);
        }

        {
            // Out-of-prefix address: refused, old intact.
            Dhcp6Server server(config);
            CHECK(server.UpsertBinding(old_duid, old_ip, "keep"));
            std::array<uint8_t, 16> outside{};
            outside[0] = 0xFE;  // link-local, outside the ULA prefix
            outside[15] = 0x99;
            CHECK(!server.ReplaceBinding(old_duid, new_duid, outside, "x"));
            const auto views = server.StaticBindings();
            CHECK(views.size() == 1);
            if (views.size() == 1) {
                CHECK(views[0].duid == old_duid);
                CHECK(views[0].ip == old_ip);
            }
        }

        {
            // A re-key naming a missing binding behaves like a plain add.
            Dhcp6Server server(config);
            CHECK(server.ReplaceBinding(old_duid, new_duid, new_ip, "fresh"));
            const auto views = server.StaticBindings();
            CHECK(views.size() == 1);
            if (views.size() == 1) {
                CHECK(views[0].duid == new_duid);
                CHECK(views[0].ip == new_ip);
            }
        }

        {
            // At the cap a re-key keeps the table the same size: allowed.
            vgww::core::Config wide = MakeConfig();
            wide.ipv6.dhcpv6.pool_start = addr_of(0x00);
            wide.ipv6.dhcpv6.pool_end = addr_of(0x00);
            Dhcp6Server server(wide);
            const size_t cap = ::vgww::core::limits::kMaxStaticBindings6;
            auto duid_of = [](size_t i) {
                return std::vector<uint8_t>{0x00, 0x03, 0x00, 0x01,
                                            0x02,
                                            static_cast<uint8_t>((i >> 16) & 0xFF),
                                            static_cast<uint8_t>((i >> 8) & 0xFF),
                                            static_cast<uint8_t>(i & 0xFF)};
            };
            auto wide_addr_of = [](size_t i) {
                std::array<uint8_t, 16> a{};
                a[0] = 0xFD; a[1] = 0x00; a[2] = 0x11; a[3] = 0x22;
                a[4] = 0x33; a[5] = 0x44; a[6] = 0x55; a[7] = 0x66;
                a[13] = static_cast<uint8_t>((i >> 16) & 0xFF);
                a[14] = static_cast<uint8_t>((i >> 8) & 0xFF);
                a[15] = static_cast<uint8_t>(i & 0xFF);
                return a;
            };
            for (size_t i = 1; i <= cap; ++i) {
                CHECK(server.UpsertBinding(duid_of(i), wide_addr_of(i)));
            }
            CHECK(server.StaticBindings().size() == cap);
            CHECK(server.ReplaceBinding(duid_of(1), duid_of(cap + 1000),
                                        wide_addr_of(cap + 1000)));
            CHECK(server.StaticBindings().size() == cap);
            CHECK(!server.UpsertBinding(duid_of(cap + 2),
                                        wide_addr_of(cap + 2)));
            CHECK(server.StaticBindings().size() == cap);
        }
    }

    // batch: same defect class as the v4 sibling. StaticBindings() decided
    // "already listed" with a nested scan of the whole config list per runtime
    // entry - O(config x runtime) DUID comparisons under mutex_ (the lock
    // Acquire() takes on the RX thread). At the kMaxStaticBindings6 cap that is
    // ~1e6 compares per call, and the WebUI polls the binding list. The fix
    // builds one unordered_set of the config DUIDs so the inner test is O(1);
    // output order and content are unchanged.
    //
    // Same-process RATIO assertion (batch78: absolute time is meaningless on a
    // shared host). Nested scan: 512x512 vs 32x32 is a 256x jump. Fixed: 1024
    // vs 64 entries is a 16x jump. A 50x bound sits between them with margin.
    // Each measurement is the MINIMUM of three runs.
    void TestStaticBindings6MergeIsNotQuadratic() {
        const auto make_config = [](size_t n) {
            Config config = MakeConfig();
            for (size_t i = 1; i <= n; ++i) {
                Dhcp6StaticBinding b;
                b.duid = {0x00, 0x03, 0x00, 0x01, 0x01,
                          static_cast<uint8_t>((i >> 16) & 0xFF),
                          static_cast<uint8_t>((i >> 8) & 0xFF),
                          static_cast<uint8_t>(i & 0xFF)};
                b.ip = kPrefix;
                b.ip[13] = static_cast<uint8_t>((i >> 16) & 0xFF);
                b.ip[14] = static_cast<uint8_t>((i >> 8) & 0xFF);
                b.ip[15] = static_cast<uint8_t>(i & 0xFF);
                b.hostname = "cfg";
                config.ipv6.dhcpv6.static_bindings.push_back(b);
            }
            return config;
        };
        const auto fill_runtime = [](Dhcp6Server& server, size_t n) {
            for (size_t i = 1; i <= n; ++i) {
                const std::vector<uint8_t> duid = {
                    0x00, 0x03, 0x00, 0x01, 0x02,
                    static_cast<uint8_t>((i >> 16) & 0xFF),
                    static_cast<uint8_t>((i >> 8) & 0xFF),
                    static_cast<uint8_t>(i & 0xFF)};
                std::array<uint8_t, 16> ip = kPrefix;
                ip[12] = 0x01;  // distinct from the config range
                ip[13] = static_cast<uint8_t>((i >> 16) & 0xFF);
                ip[14] = static_cast<uint8_t>((i >> 8) & 0xFF);
                ip[15] = static_cast<uint8_t>(i & 0xFF);
                if (!server.UpsertBinding(duid, ip, "rt")) {
                    std::fprintf(stderr,
                                 "b-merge6 setup: upsert %zu refused\n", i);
                    ++g_failures;
                    return;
                }
            }
        };
        const auto time_calls = [](Dhcp6Server& server, int iters) {
            const auto t0 = std::chrono::steady_clock::now();
            size_t sink = 0;
            for (int i = 0; i < iters; ++i) {
                sink += server.StaticBindings().size();
            }
            const auto ns =
                std::chrono::duration_cast<std::chrono::nanoseconds>(
                    std::chrono::steady_clock::now() - t0)
                    .count();
            if (0 == sink) {
                std::fprintf(stderr, "b-merge6: empty view\n");
            }
            return ns;
        };
        const auto best_of = [&time_calls](Dhcp6Server& server, int iters,
                                           int reps) {
            long long best = -1;
            for (int r = 0; r < reps; ++r) {
                const long long ns = time_calls(server, iters);
                if (best < 0 || ns < best) {
                    best = ns;
                }
            }
            return best;
        };

        Config small_cfg = make_config(32);
        Dhcp6Server small(small_cfg);
        fill_runtime(small, 32);
        Config large_cfg = make_config(512);
        Dhcp6Server large(large_cfg);
        fill_runtime(large, 512);
        CHECK(small.StaticBindings().size() == 64);
        CHECK(large.StaticBindings().size() == 1024);

        constexpr int kSmallIters = 2000;
        constexpr int kLargeIters = 200;
        const long long small_ns = best_of(small, kSmallIters, 3);
        const long long large_ns = best_of(large, kLargeIters, 3);
        const double small_per =
            static_cast<double>(small_ns) / static_cast<double>(kSmallIters);
        const double large_per =
            static_cast<double>(large_ns) / static_cast<double>(kLargeIters);
        const double ratio = large_per / (small_per > 0.0 ? small_per : 1.0);
        std::printf(
            "b-merge6 small_per_ns=%.1f large_per_ns=%.1f ratio=%.1f\n",
            small_per, large_per, ratio);
        CHECK(ratio <= 50.0);
    }

    // batch: StaticBindingCount() had the SAME nested scan as StaticBindings()
    // - for every runtime entry it walked the whole config list to decide
    // "already counted". It only counts (no strings), so the cost is pure DUID
    // comparison, but a DUID is a std::vector<uint8_t> (a length check plus a
    // memcmp), so it is dearer per compare than a MAC. The merged view is
    // capped at kMaxStaticBindings6 (1024), so the worst legal shape is 512
    // config + 512 runtime = 262144 comparisons per call, all under mutex_ (the
    // lock Acquire() takes on the RX thread). /api/status polls this every 2 s
    // (web_api.cpp:2496-2497 -> dataplane.cpp:4570), i.e. MORE often than the
    // 3 s binding list. The fix builds one unordered_set of the config DUIDs
    // and turns the inner scan into an O(1) lookup; the returned count is
    // unchanged (config entries + runtime entries whose DUID is not in config).
    //
    // Same-process RATIO assertion (batch78: absolute time is meaningless on a
    // shared host). Nested scan: 512x512 vs 32x32 is a 256x jump. Fixed: 1024
    // vs 64 entries is a 16x jump. A 50x bound sits between them with margin.
    // Each measurement is the MINIMUM of three runs.
    void TestStaticBindingCount6IsNotQuadratic() {
        const auto make_config = [](size_t n) {
            Config config = MakeConfig();
            for (size_t i = 1; i <= n; ++i) {
                Dhcp6StaticBinding b;
                b.duid = {0x00, 0x03, 0x00, 0x01, 0x01,
                          static_cast<uint8_t>((i >> 16) & 0xFF),
                          static_cast<uint8_t>((i >> 8) & 0xFF),
                          static_cast<uint8_t>(i & 0xFF)};
                b.ip = kPrefix;
                b.ip[13] = static_cast<uint8_t>((i >> 16) & 0xFF);
                b.ip[14] = static_cast<uint8_t>((i >> 8) & 0xFF);
                b.ip[15] = static_cast<uint8_t>(i & 0xFF);
                b.hostname = "cfg";
                config.ipv6.dhcpv6.static_bindings.push_back(b);
            }
            return config;
        };
        const auto fill_runtime = [](Dhcp6Server& server, size_t n) {
            for (size_t i = 1; i <= n; ++i) {
                const std::vector<uint8_t> duid = {
                    0x00, 0x03, 0x00, 0x01, 0x02,
                    static_cast<uint8_t>((i >> 16) & 0xFF),
                    static_cast<uint8_t>((i >> 8) & 0xFF),
                    static_cast<uint8_t>(i & 0xFF)};
                std::array<uint8_t, 16> ip = kPrefix;
                ip[12] = 0x01;  // distinct from the config range
                ip[13] = static_cast<uint8_t>((i >> 16) & 0xFF);
                ip[14] = static_cast<uint8_t>((i >> 8) & 0xFF);
                ip[15] = static_cast<uint8_t>(i & 0xFF);
                if (!server.UpsertBinding(duid, ip, "rt")) {
                    std::fprintf(stderr,
                                 "b-count6 setup: upsert %zu refused\n", i);
                    ++g_failures;
                    return;
                }
            }
        };
        const auto time_calls = [](Dhcp6Server& server, int iters) {
            const auto t0 = std::chrono::steady_clock::now();
            size_t sink = 0;
            for (int i = 0; i < iters; ++i) {
                sink += server.StaticBindingCount();
            }
            const auto ns =
                std::chrono::duration_cast<std::chrono::nanoseconds>(
                    std::chrono::steady_clock::now() - t0)
                    .count();
            if (0 == sink) {
                std::fprintf(stderr, "b-count6: zero count\n");
            }
            return ns;
        };
        const auto best_of = [&time_calls](Dhcp6Server& server, int iters,
                                           int reps) {
            long long best = -1;
            for (int r = 0; r < reps; ++r) {
                const long long ns = time_calls(server, iters);
                if (best < 0 || ns < best) {
                    best = ns;
                }
            }
            return best;
        };

        Config small_cfg = make_config(32);
        Dhcp6Server small(small_cfg);
        fill_runtime(small, 32);
        Config large_cfg = make_config(512);
        Dhcp6Server large(large_cfg);
        fill_runtime(large, 512);
        CHECK(small.StaticBindingCount() == 64);
        CHECK(large.StaticBindingCount() == 1024);

        constexpr int kSmallIters = 20000;
        constexpr int kLargeIters = 2000;
        const long long small_ns = best_of(small, kSmallIters, 3);
        const long long large_ns = best_of(large, kLargeIters, 3);
        const double small_per =
            static_cast<double>(small_ns) / static_cast<double>(kSmallIters);
        const double large_per =
            static_cast<double>(large_ns) / static_cast<double>(kLargeIters);
        const double ratio = large_per / (small_per > 0.0 ? small_per : 1.0);
        std::printf(
            "b-count6 small_per_ns=%.1f large_per_ns=%.1f ratio=%.1f\n",
            small_per, large_per, ratio);
        CHECK(ratio <= 50.0);
    }

    // P145-A (v6): same defect class as the v4 loader - an entry that is not
    // an object, or a field whose JSON type is wrong, used to escape as an
    // nlohmann type_error before corrupt() ran, so the bad document was kept
    // on disk and never flagged. Every entry refusal must be contained.
    void TestP145Leases6EntryTypeErrorsAreContained() {
        Config config = MakeConfig();

        const auto run_case = [&config](const char* leaf, const char* document) {
            const std::string path = ScratchFile(leaf);
            std::error_code rm_a;
            std::filesystem::remove(path, rm_a);
            std::error_code rm_b;
            std::filesystem::remove(path + ".corrupt", rm_b);
            {
                std::ofstream out(path);
                out << document;
            }
            Dhcp6Server server(config);
            size_t dropped = 0;
            size_t thrown = 0;
            Dhcp6Server::LoadOutcome outcome =
                Dhcp6Server::LoadOutcome::kRestored;
            try {
                outcome = server.LoadLeases(path, std::chrono::steady_clock::now(),
                                            &dropped);
            } catch (...) {
                ++thrown;
            }
            CHECK(0 == thrown);
            CHECK(Dhcp6Server::LoadOutcome::kCorrupt == outcome ||
                  (Dhcp6Server::LoadOutcome::kRestored == outcome &&
                   dropped > 0));
            if (Dhcp6Server::LoadOutcome::kRestored == outcome) {
                CHECK(server.DroppedLeaseCount() > 0);
            } else {
                CHECK(server.LeaseFileCorrupt());
                std::ifstream aside(path + ".corrupt");
                CHECK(aside.good());
            }
            std::error_code rm_c;
            std::filesystem::remove(path, rm_c);
            std::error_code rm_d;
            std::filesystem::remove(path + ".corrupt", rm_d);
        };

        // (1) non-object entry.
        run_case("p145_leases6_non_object.json",
                 "{\"version\":1,\"leases\":[\"not-an-object\"]}");
        // (2) "duid" is a number (type_error.302 on item.value("duid", "")).
        run_case("p145_leases6_bad_duid_type.json",
                 "{\"version\":1,\"leases\":[{\"duid\":123,\"iaid\":1,"
                 "\"ip\":\"fd00:1122:3344:5566:0000:0000:0000:1000\"}]}");
        // (3) "iaid" is a string (type_error.302 on item.value("iaid", 0u)).
        run_case("p145_leases6_bad_iaid_type.json",
                 "{\"version\":1,\"leases\":[{\"duid\":\"00:03:00:01:AA:BB:CC:"
                 "DD:EE:01\",\"iaid\":\"seven\",\"ip\":\"fd00:1122:3344:5566:"
                 "0000:0000:0000:1000\"}]}");
        // (4) "ip" is a number.
        run_case("p145_leases6_bad_ip_type.json",
                 "{\"version\":1,\"leases\":[{\"duid\":\"00:03:00:01:AA:BB:CC:"
                 "DD:EE:01\",\"iaid\":1,\"ip\":7}]}");

        // (5) a good entry survives next to a refused one.
        {
            const std::string path =
                ScratchFile("p145_leases6_mixed.json");
            std::error_code rm_e;
            std::filesystem::remove(path, rm_e);
            std::error_code rm_f;
            std::filesystem::remove(path + ".corrupt", rm_f);
            {
                std::ofstream out(path);
                out << "{\"version\":1,\"leases\":["
                       "{\"duid\":\"00:03:00:01:AA:BB:CC:DD:EE:01\","
                       "\"iaid\":1,\"ip\":\"fd00:1122:3344:5566:0000:0000:"
                       "0000:1000\",\"expires_in_s\":3600,"
                       "\"hostname\":\"good\"},"
                       "{\"duid\":123,\"iaid\":2,\"ip\":\"fd00:1122:3344:5566:"
                       "0000:0000:0000:1001\"}]}";
            }
            Dhcp6Server server(config);
            size_t dropped = 0;
            size_t thrown = 0;
            Dhcp6Server::LoadOutcome outcome =
                Dhcp6Server::LoadOutcome::kRestored;
            try {
                outcome = server.LoadLeases(path, std::chrono::steady_clock::now(),
                                            &dropped);
            } catch (...) {
                ++thrown;
            }
            CHECK(0 == thrown);
            CHECK(Dhcp6Server::LoadOutcome::kRestored == outcome);
            CHECK(1 == server.LeaseCount());
            CHECK(1 == dropped);
            std::error_code rm_g;
            std::filesystem::remove(path, rm_g);
        }
    }

    // P145-E (v6): a persisted expires_in_s is an attacker/editor controlled
    // number with no ceiling; ~136 years of pinning one address starves the
    // pool forever. The loader must clamp it to
    // config.ipv6.dhcpv6.lease_seconds. (Pool membership is deliberately NOT
    // validated - a legitimately persisted lease survives a pool re-range,
    // see TestLeases6RoundTrip and the v4 sibling dhcp.cpp:1403-1409.)
    void TestP145Leases6ExpiresIsClampedToLeaseSeconds() {
        Config config = MakeConfig();
        Dhcp6Server server(config);

        const std::string path =
            ScratchFile("p145_leases6_expires_huge.json");
        std::error_code rm_h;
        std::filesystem::remove(path, rm_h);
        {
            std::ofstream out(path);
            out << "{\"version\":1,\"leases\":["
                   "{\"duid\":\"00:03:00:01:AA:BB:CC:DD:EE:01\",\"iaid\":1,"
                   "\"ip\":\"fd00:1122:3344:5566:0000:0000:0000:1000\","
                   "\"expires_in_s\":4294967295,\"hostname\":\"pinned\"}]}";
        }
        const auto t0 = std::chrono::steady_clock::now();
        size_t dropped = 0;
        CHECK(server.LoadLeases(path, t0, &dropped) ==
              Dhcp6Server::LoadOutcome::kRestored);
        CHECK(1 == server.LeaseCount());
        const auto leases = server.Leases(t0);
        CHECK(1 == leases.size());
        if (!leases.empty()) {
            CHECK(leases[0].expires_in_s <=
                  config.ipv6.dhcpv6.lease_seconds);
        }
        std::error_code rm_i;
        std::filesystem::remove(path, rm_i);
    }

    // P145-V3 (v6): the serving path has no policy ceiling, and pool
    // exhaustion is only reported when the ADDRESS space is gone.
    void TestP145V3Lease6ServesBeyondLegacyCap() {
        Config config = MakeConfig();
        config.ipv6.dhcpv6.pool_end[14] = 0xFF;
        config.ipv6.dhcpv6.pool_end[15] = 0xFF;
        Dhcp6Server server(config);
        const auto now = std::chrono::steady_clock::now();

        constexpr size_t kLegacyCap = 8192;
        size_t granted = 0;
        for (size_t i = 0; i < kLegacyCap + 1; ++i) {
            std::vector<uint8_t> duid{0x00, 0x03, 0x00, 0x01,
                                      0xCC,
                                      static_cast<uint8_t>((i >> 16) & 0xFF),
                                      static_cast<uint8_t>((i >> 8) & 0xFF),
                                      static_cast<uint8_t>(i & 0xFF)};
            if (!IsZeroAddr(server.Acquire(duid, 1, now,
                                           Dhcp6Server::OfferStage::kAck))) {
                ++granted;
            }
        }
        CHECK(kLegacyCap + 1 == granted);
        CHECK(server.LeaseCount() == kLegacyCap + 1);
        CHECK(0 == server.PoolExhaustedCount());

        // A brand-new client is still served (no sticky refusal).
        const std::vector<uint8_t> extra{0x00, 0x03, 0x00, 0x01, 0xDD, 0x00,
                                         0x00, 0x01};
        CHECK(!IsZeroAddr(server.Acquire(extra, 1, now,
                                            Dhcp6Server::OfferStage::kAck)));
        CHECK(kLegacyCap + 2 == server.LeaseCount());
        CHECK(0 == server.PoolExhaustedCount());
    }

    // P145-V2 (v6): the loader is the only path that can inject records no
    // pool bounds, so it is the only path with a load ceiling.
    void TestP145V2Leases6LoadIsBounded() {
        Config config = MakeConfig();
        const size_t limit = vgww::core::limits::kMaxLoadedLeases;
        const size_t extra = 4;
        const std::string path =
            ScratchFile("p145_v2_leases6_oversized_entries.json");
        std::error_code rm_a;
        std::filesystem::remove(path, rm_a);
        {
            std::ofstream out(path);
            out << "{\"version\":1,\"leases\":[";
            for (size_t i = 0; i < limit + extra; ++i) {
                if (i > 0) {
                    out << ",";
                }
                // Shortest legitimate entry, inside the ULA prefix and with a
                // UNIQUE address per record: only the load ceiling may refuse.
                char entry[96];
                std::snprintf(
                    entry, sizeof(entry),
                    "{\"duid\":\"00:03:00:01:AA:%02X:%02X:%02X\","
                    "\"iaid\":1,\"ip\":\"fd00:1122:3344:5566:0:%X:%X:%X\"}",
                    static_cast<unsigned>((i >> 16) & 0xFF),
                    static_cast<unsigned>((i >> 8) & 0xFF),
                    static_cast<unsigned>(i & 0xFF),
                    static_cast<unsigned>(((i >> 28) & 0xF)),
                    static_cast<unsigned>(((i >> 12) & 0xFFFF)),
                    static_cast<unsigned>((i & 0xFFF)));
                out << entry;
            }
            out << "]}";
        }

        Dhcp6Server server(config);
        size_t dropped = 0;
        size_t thrown = 0;
        Dhcp6Server::LoadOutcome outcome = Dhcp6Server::LoadOutcome::kRestored;
        try {
            outcome = server.LoadLeases(path, std::chrono::steady_clock::now(),
                                        &dropped);
        } catch (...) {
            ++thrown;
        }
        CHECK(0 == thrown);
        CHECK(Dhcp6Server::LoadOutcome::kRestored == outcome);
        CHECK(server.LeaseCount() <= limit);
        CHECK(dropped >= extra);

        // The serving path still works for a new client.
        const std::vector<uint8_t> fresh{0x00, 0x03, 0x00, 0x01, 0x7A, 0x00,
                                         0x00, 0x01};
        CHECK(!IsZeroAddr(server.Acquire(fresh, 1,
                                          std::chrono::steady_clock::now(),
                                          Dhcp6Server::OfferStage::kAck)));
        std::error_code rm_b;
        std::filesystem::remove(path, rm_b);
    }

    // P145-V1 (v6 sibling): a partially damaged document leaves evidence.
    // P145-V6 (v6 sibling): the reader refuses a document larger than
    // kMaxLeasesBytes, so the writer must never publish one. Otherwise a
    // large but legal table writes a file this build cannot restore, and
    // every restart discards every lease as corrupt.
    void TestP145V6Leases6DumpNeverWritesUnreadableFile() {
        Config config = MakeConfig();
        config.ipv6.dhcpv6.pool_start = kPrefix;
        config.ipv6.dhcpv6.pool_start[14] = 0x00;
        config.ipv6.dhcpv6.pool_start[15] = 0x00;
        config.ipv6.dhcpv6.pool_end = kPrefix;
        config.ipv6.dhcpv6.pool_end[14] = 0xFF;
        config.ipv6.dhcpv6.pool_end[15] = 0xFF;
        Dhcp6Server server(config);
        const auto now = std::chrono::steady_clock::now();

        const std::string path =
            ScratchFile("p145_v6_leases6_oversized.json");
        std::error_code rm_a;
        std::filesystem::remove(path, rm_a);
        std::error_code rm_b;
        std::filesystem::remove(path + ".corrupt", rm_b);

        // A small table first: this snapshot must survive the refused dump.
        const std::vector<uint8_t> first{0x00, 0x03, 0x00, 0x01, 0x02, 0x00,
                                         0x00, 0x00, 0x00, 0x01};
        CHECK(!IsZeroAddr(server.Acquire(first, 1, now,
                                         Dhcp6Server::OfferStage::kAck)));
        CHECK(server.DumpLeases(path, now));
        std::string before;
        {
            std::ifstream in(path, std::ios::binary);
            CHECK(in.good());
            before.assign((std::istreambuf_iterator<char>(in)),
                          std::istreambuf_iterator<char>());
        }
        CHECK(!before.empty());
        const uint64_t failures_before = server.PersistFailureCount();

        // Grow past the reader's byte cap. A v6 row is ~120 bytes; the table
        // cap itself is far larger, so only the byte cap can stop this.
        const size_t rows = vgww::core::limits::kMaxLeasesBytes / 100 + 1;
        size_t granted = 0;
        for (size_t i = 0; i < rows; ++i) {
            const std::vector<uint8_t> duid{
                0x00, 0x03, 0x00, 0x01, 0x02, 0x20,
                static_cast<uint8_t>((i >> 16) & 0xFF),
                static_cast<uint8_t>((i >> 8) & 0xFF),
                static_cast<uint8_t>(i & 0xFF),
                static_cast<uint8_t>((i >> 24) & 0xFF)};
            if (!IsZeroAddr(server.Acquire(duid, 1, now,
                                           Dhcp6Server::OfferStage::kAck))) {
                ++granted;
            }
        }
        CHECK(granted == rows);

        // The dump must be REFUSED rather than publishing an unreadable file.
        CHECK(!server.DumpLeases(path, now));
        CHECK(server.PersistFailureCount() > failures_before);

        // The previous good snapshot is untouched.
        std::string after;
        {
            std::ifstream in(path, std::ios::binary);
            CHECK(in.good());
            after.assign((std::istreambuf_iterator<char>(in)),
                         std::istreambuf_iterator<char>());
        }
        CHECK(after == before);

        // Core invariant: a file we kept on disk is one we can read back.
        Dhcp6Server reloaded(config);
        size_t dropped = 0;
        const auto outcome = reloaded.LoadLeases(path, now, &dropped);
        CHECK(Dhcp6Server::LoadOutcome::kRestored == outcome);
        CHECK(!reloaded.LeaseFileCorrupt());
        CHECK(reloaded.LeaseCount() >= 1);

        std::error_code rm_c;
        std::filesystem::remove(path, rm_c);
        std::error_code rm_d;
        std::filesystem::remove(path + ".corrupt", rm_d);
    }

    // P145-B2 (loader-side): a lease file may legally hold SEVERAL records
    // for one DUID (a v6 client owns one record per IAID, and the dump
    // writes them all). Loading such a file must keep every record: the
    // static path collapses them on demand, so the loader must NOT drop
    // them up front (that would silently lose a client's other IAIDs).
    void TestP145B2MultiIaidRecordsSurviveLoad() {
        Config config = MakeConfig();
        const std::string path =
            ScratchFile("p145_b2_multi_iaid_load.json");
        std::error_code rm_a;
        std::filesystem::remove(path, rm_a);
        {
            std::ofstream out(path);
            out << "{\"version\":1,\"leases\":["
                   "{\"duid\":\"00:03:00:01:AA:BB:CC:DD:EE:01\",\"iaid\":1,"
                   "\"ip\":\"fd00:1122:3344:5566:0000:0000:0000:1000\","
                   "\"expires_in_s\":3600,\"hostname\":\"one\"},"
                   "{\"duid\":\"00:03:00:01:AA:BB:CC:DD:EE:01\",\"iaid\":2,"
                   "\"ip\":\"fd00:1122:3344:5566:0000:0000:0000:1001\","
                   "\"expires_in_s\":3600,\"hostname\":\"two\"}]}";
        }
        Dhcp6Server server(config);
        size_t dropped = 0;
        CHECK(Dhcp6Server::LoadOutcome::kRestored ==
              server.LoadLeases(path, std::chrono::steady_clock::now(),
                                &dropped));
        CHECK(2 == server.LeaseCount());
        CHECK(0 == dropped);
        const auto leases = server.Leases(std::chrono::steady_clock::now());
        CHECK(2 == leases.size());
        std::error_code rm_b;
        std::filesystem::remove(path, rm_b);
    }

    // P145-B2 (static collapse, whole-table walk): with several records for
    // one DUID already in the table, a static Acquire must leave exactly ONE
    // record - a static record is never swept, so leftovers occupy slots
    // forever. Stopping the walk at the first match left the rest behind.
    void TestP145B2StaticCollapsesStrayDuidRecords() {
        Config config = MakeConfig();
        Dhcp6StaticBinding cfg;
        cfg.duid = kStaticDuid;
        cfg.ip = kPrefix;
        cfg.ip[15] = 0x42;
        cfg.hostname = "fixed-printer";
        config.ipv6.dhcpv6.static_bindings.push_back(cfg);
        Dhcp6Server server(config);
        const auto now = std::chrono::steady_clock::now();

        // Seed two DYNAMIC records for the bound DUID through the loader -
        // the real injection path (Acquire would take the static branch and
        // only ever create one record). The loader dedupes by address, not
        // by DUID, so both survive.
        const std::string path =
            ScratchFile("p145_b2_stray_duid_records.json");
        std::error_code rm_a;
        std::filesystem::remove(path, rm_a);
        {
            std::ofstream out(path);
            out << "{\"version\":1,\"leases\":["
                   "{\"duid\":\"00:03:00:01:11:22:33:44:55:66\","
                   "\"iaid\":1,\"ip\":\"fd00:1122:3344:5566:0000:0000:0000:"
                   "1000\",\"expires_in_s\":3600},"
                   "{\"duid\":\"00:03:00:01:11:22:33:44:55:66\","
                   "\"iaid\":2,\"ip\":\"fd00:1122:3344:5566:0000:0000:0000:"
                   "1001\",\"expires_in_s\":3600}]}";
        }
        size_t dropped = 0;
        CHECK(Dhcp6Server::LoadOutcome::kRestored ==
              server.LoadLeases(path, now, &dropped));
        CHECK(2 == server.LeaseCount());

        // The static branch must collapse both into ONE record on the
        // caller's key and return the bound address.
        CHECK(server.Acquire(kStaticDuid, 3, now,
                             Dhcp6Server::OfferStage::kAck) == cfg.ip);
        CHECK(1 == server.LeaseCount());

        // The surviving record is the static one, not a stale dynamic entry.
        const auto leases = server.Leases(now);
        CHECK(1 == leases.size());
        if (!leases.empty()) {
            CHECK(leases[0].is_static);
            CHECK(leases[0].ip == cfg.ip);
        }
        std::error_code rm_b;
        std::filesystem::remove(path, rm_b);
    }

    // P145-B2a: the exact-key fast path must not bypass the collapse. The
    // sibling test above calls Acquire with iaid=3, which matches NO loaded
    // record, so it only ever exercised the scan branch and let this defect
    // through. Here the caller's IAID is EXACTLY one of the loaded records:
    // `leases_.find(key)` hits, and an early return there left the other
    // same-DUID records behind - violating the function's own contract that
    // exactly ONE record may exist per DUID.
    void TestP145B2aExactIaidStillCollapsesStrays() {
        Config config = MakeConfig();
        Dhcp6StaticBinding cfg;
        cfg.duid = kStaticDuid;
        cfg.ip = kPrefix;
        cfg.ip[15] = 0x42;
        cfg.hostname = "fixed-printer";
        config.ipv6.dhcpv6.static_bindings.push_back(cfg);
        Dhcp6Server server(config);
        const auto now = std::chrono::steady_clock::now();

        const std::string path =
            ScratchFile("p145_b2a_exact_iaid_records.json");
        std::error_code rm_a;
        std::filesystem::remove(path, rm_a);
        {
            std::ofstream out(path);
            out << "{\"version\":1,\"leases\":["
                   "{\"duid\":\"00:03:00:01:11:22:33:44:55:66\","
                   "\"iaid\":1,\"ip\":\"fd00:1122:3344:5566:0000:0000:0000:"
                   "1000\",\"expires_in_s\":3600,\"hostname\":\"first\"},"
                   "{\"duid\":\"00:03:00:01:11:22:33:44:55:66\","
                   "\"iaid\":2,\"ip\":\"fd00:1122:3344:5566:0000:0000:0000:"
                   "1001\",\"expires_in_s\":3600,\"hostname\":\"second\"}]}";
        }
        size_t dropped = 0;
        CHECK(Dhcp6Server::LoadOutcome::kRestored ==
              server.LoadLeases(path, now, &dropped));
        CHECK(2 == server.LeaseCount());

        // IAID 2 matches the SECOND loaded record exactly.
        CHECK(server.Acquire(kStaticDuid, 2, now,
                             Dhcp6Server::OfferStage::kAck) == cfg.ip);
        CHECK(1 == server.LeaseCount());

        const auto leases = server.Leases(now);
        CHECK(1 == leases.size());
        if (!leases.empty()) {
            CHECK(leases[0].is_static);
            CHECK(leases[0].ip == cfg.ip);
        }
        std::error_code rm_b;
        std::filesystem::remove(path, rm_b);
    }

    // P145-B2a (carrier priority, RUNTIME binding, ORDER-INDEPENDENT MATRIX):
    // the sibling test above uses a CONFIG binding, whose branch always
    // rewrites the hostname (its else arm installs the configured one), so it
    // cannot observe which record the collapse carried. The RUNTIME branch
    // rewrites the hostname ONLY when the client reported one
    // (dhcp6.cpp:652-654, no else arm), and an empty hostname is the normal
    // DHCPv6 case (HandleFrame passes std::string(), dhcp6.cpp:1840/1858), so
    // the carrier's name survives and the CHOICE of carrier is observable.
    //
    // WHY A FOUR-ROW MATRIX AND NOT ONE CALL: leases_ is an unordered_map, so
    // its iteration order is UNSPECIFIED and "the first/last record" is not
    // predictable. A single call can therefore pass by luck - a broken
    // carrier choice ("take the last one visited") coincides with "take the
    // caller's own record" whenever that record happens to be visited last.
    // Probing EVERY iaid 1..4 on a FRESH server makes the two behaviours
    // distinguishable for ANY bucket order: a correct implementation pins the
    // caller's record 4/4 times, while last-wins pins the SAME record for all
    // four probes and so can match at most ONE of them.
    void TestP145B2aCarrierPinsCallerIaid() {
        const auto now = std::chrono::steady_clock::now();
        std::array<uint8_t, 16> bound_ip = kPrefix;
        bound_ip[14] = 0xF0;
        bound_ip[15] = 0xFF;

        constexpr uint32_t kRows = 4;
        size_t rows_pinned = 0;
        for (uint32_t iaid = 1; iaid <= kRows; ++iaid) {
            // A FRESH server per row: the first Acquire collapses the table,
            // so reusing one instance would leave nothing to collapse for the
            // later rows and the matrix would degenerate into the single-call
            // test this one replaced.
            Config config = MakeConfig();
            Dhcp6Server server(config);

            // Runtime binding only: the config list stays empty so the
            // runtime branch (the one WITHOUT a hostname else-arm) is taken.
            if (!server.UpsertBinding(kStaticDuid, bound_ip, "")) {
                continue;
            }

            char leaf[64];
            std::snprintf(leaf, sizeof(leaf), "p145_b2a_carrier_iaid%u.json",
                          static_cast<unsigned>(iaid));
            const std::string path = ScratchFile(leaf);
            std::error_code rm_a;
            std::filesystem::remove(path, rm_a);
            {
                std::ofstream out(path);
                out << "{\"version\":1,\"leases\":[";
                for (uint32_t row = 1; row <= kRows; ++row) {
                    if (row > 1) {
                        out << ",";
                    }
                    char entry[192];
                    std::snprintf(
                        entry, sizeof(entry),
                        "{\"duid\":\"00:03:00:01:11:22:33:44:55:66\","
                        "\"iaid\":%u,\"ip\":\"fd00:1122:3344:5566:0000:0000:"
                        "0000:%04X\",\"expires_in_s\":3600,"
                        "\"hostname\":\"HOST-iaid%u\"}",
                        static_cast<unsigned>(row),
                        static_cast<unsigned>(0x1000 + row),
                        static_cast<unsigned>(row));
                    out << entry;
                }
                out << "]}";
            }
            size_t dropped = 0;
            CHECK(Dhcp6Server::LoadOutcome::kRestored ==
                  server.LoadLeases(path, now, &dropped));
            CHECK(kRows == server.LeaseCount());

            // The EMPTY client hostname is the key input: the runtime branch
            // then leaves lease.hostname untouched, so the carrier's name is
            // what the assertion below observes.
            CHECK(server.Acquire(kStaticDuid, iaid, now,
                                 Dhcp6Server::OfferStage::kAck,
                                 std::string()) == bound_ip);
            CHECK(1 == server.LeaseCount());

            const auto leases = server.Leases(now);
            CHECK(1 == leases.size());
            if (!leases.empty()) {
                char want[32];
                std::snprintf(want, sizeof(want), "HOST-iaid%u",
                              static_cast<unsigned>(iaid));
                CHECK(leases[0].is_static);
                CHECK(leases[0].ip == bound_ip);
                // The caller's OWN record must be the carrier.
                CHECK(leases[0].hostname == want);
                if (leases[0].hostname == want) {
                    ++rows_pinned;
                }
            }
            std::error_code rm_b;
            std::filesystem::remove(path, rm_b);
        }
        // Report the matrix result so a partial match cannot be missed: a
        // correct implementation pins 4/4, a last-wins carrier at most 1/4.
        std::fprintf(stderr, "P145-B2a carrier matrix: rows pinned %zu/%u\n",
                     rows_pinned, static_cast<unsigned>(kRows));
        CHECK(rows_pinned == kRows);
    }

    void TestP145V1Leases6PartialCorruptionLeavesEvidence() {
        Config config = MakeConfig();
        const std::string path =
            ScratchFile("p145_v1_leases6_partial.json");
        std::error_code rm_a;
        std::filesystem::remove(path, rm_a);
        std::error_code rm_b;
        std::filesystem::remove(path + ".corrupt", rm_b);
        {
            std::ofstream out(path);
            out << "{\"version\":1,\"leases\":["
                   "{\"duid\":\"00:03:00:01:AA:BB:CC:DD:EE:01\",\"iaid\":1,"
                   "\"ip\":\"fd00:1122:3344:5566:0000:0000:0000:1000\","
                   "\"expires_in_s\":3600,\"hostname\":\"good\"},"
                   "{\"duid\":123,\"iaid\":2,"
                   "\"ip\":\"fd00:1122:3344:5566:0000:0000:0000:1001\"}]}";
        }
        Dhcp6Server server(config);
        size_t dropped = 0;
        const auto outcome = server.LoadLeases(
            path, std::chrono::steady_clock::now(), &dropped);
        CHECK(Dhcp6Server::LoadOutcome::kRestored == outcome);
        CHECK(1 == server.LeaseCount());
        CHECK(dropped >= 1);
        CHECK(server.LeaseFileCorrupt());
        {
            std::ifstream aside(path + ".corrupt", std::ios::binary);
            CHECK(aside.good());
            const std::string raw((std::istreambuf_iterator<char>(aside)),
                                  std::istreambuf_iterator<char>());
            CHECK(raw.find("\"duid\":123") != std::string::npos);
        }
        std::error_code rm_c;
        std::filesystem::remove(path, rm_c);
        std::error_code rm_d;
        std::filesystem::remove(path + ".corrupt", rm_d);
    }


    // P145-B2 (v6): the static branches inserted leases_[{duid, iaid}] with
    // an arbitrary client-chosen IAID and returned the bound address. The
    // entries are is_static, so Sweep never reclaims them: one static DUID
    // plus N IAIDs grew the table by N entries without limit. A static
    // binding is a property of the DUID, so it must own exactly ONE record.
    void TestP145StaticBindingOwnsOneLeasePerDuid() {
        Config config = MakeConfig();
        Dhcp6StaticBinding cfg;
        cfg.duid = kStaticDuid;
        cfg.ip = kPrefix;
        cfg.ip[15] = 0x42;
        cfg.hostname = "fixed-printer";
        config.ipv6.dhcpv6.static_bindings.push_back(cfg);
        Dhcp6Server server(config);
        const auto now = std::chrono::steady_clock::now();

        // Same DUID, 64 different IAIDs, plus the SAME address every time.
        std::array<uint8_t, 16> first{};
        for (uint32_t iaid = 1; iaid <= 64; ++iaid) {
            const std::array<uint8_t, 16> got = server.Acquire(
                kStaticDuid, iaid, now, Dhcp6Server::OfferStage::kAck);
            CHECK(got == cfg.ip);
            if (1 == iaid) {
                first = got;
            } else {
                CHECK(got == first);
            }
        }
        CHECK(1 == server.LeaseCount());

        // A runtime (WebUI) binding behaves the same way.
        Dhcp6Server rt_server(config);
        std::array<uint8_t, 16> rt_ip = kPrefix;
        rt_ip[15] = 0x43;
        CHECK(rt_server.UpsertBinding(kOtherDuid, rt_ip, ""));
        for (uint32_t iaid = 7; iaid < 20; ++iaid) {
            CHECK(rt_server.Acquire(kOtherDuid, iaid, now,
                                    Dhcp6Server::OfferStage::kAck) == rt_ip);
        }
        CHECK(1 == rt_server.LeaseCount());

        // P145-B1/B2 on the STATIC path: a static record is never swept, so
        // the ONLY unbounded-growth shape would be one record per client IAID.
        // After the DUID dedup a static binding owns exactly one record, and
        // the serving path has no policy ceiling (V3). This block pins that a
        // bound client renewing under many IAIDs never grows the table, and
        // that its bound address is still served (no spurious exhaustion).
        {
            Config cap_cfg = MakeConfig();
            cap_cfg.ipv6.dhcpv6.pool_end[14] = 0xFF;
            cap_cfg.ipv6.dhcpv6.pool_end[15] = 0xFF;
            Dhcp6StaticBinding late;
            late.duid = kStaticDuid;
            late.ip = kPrefix;
            late.ip[15] = 0x77;
            cap_cfg.ipv6.dhcpv6.static_bindings.push_back(late);
            Dhcp6Server cap_server(cap_cfg);
            for (uint32_t iaid = 1; iaid <= 256; ++iaid) {
                CHECK(cap_server.Acquire(kStaticDuid, iaid, now,
                                         Dhcp6Server::OfferStage::kAck) ==
                      late.ip);
            }
            CHECK(1 == cap_server.LeaseCount());
            CHECK(0 == cap_server.PoolExhaustedCount());
        }

        // P145-B3 explicit assertion: a static binding INSIDE the dynamic pool
        // reserves its address for its owner even before the owner asks. The
        // per-candidate ReservedByStatic scan was replaced with one pre-built
        // index set, so this pins that the set is complete (config AND runtime
        // sources) and that a competing client never receives those addresses.
        {
            Config pool_cfg = MakeConfig();
            Dhcp6StaticBinding in_pool;
            in_pool.duid = kStaticDuid;
            in_pool.ip = kPoolStart;  // first pool address
            in_pool.hostname = "in-pool-static";
            pool_cfg.ipv6.dhcpv6.static_bindings.push_back(in_pool);
            Dhcp6Server pool_server(pool_cfg);

            std::array<uint8_t, 16> rt_in_pool = kPoolStart;
            rt_in_pool[15] = 0x01;  // second pool address
            CHECK(pool_server.UpsertBinding(kOtherDuid, rt_in_pool, ""));

            const std::vector<uint8_t> third{0x00, 0x03, 0x00, 0x01, 0xEE,
                                             0x00, 0x00, 0x01};
            for (uint32_t iaid = 1; iaid <= 8; ++iaid) {
                const auto got = pool_server.Acquire(
                    third, iaid, now, Dhcp6Server::OfferStage::kAck);
                CHECK(!IsZeroAddr(got));
                CHECK(got != in_pool.ip);    // config binding reserved
                CHECK(got != rt_in_pool);    // runtime binding reserved
                CHECK(pool_server.Acquire(kStaticDuid, 1, now,
                                          Dhcp6Server::OfferStage::kAck) ==
                      in_pool.ip);
            }
        }

        // The static entry is still visible and still static.
        const auto leases = server.Leases(now);
        CHECK(1 == leases.size());
        if (!leases.empty()) {
            CHECK(leases[0].is_static);
            CHECK(leases[0].ip == cfg.ip);
        }
    }

    // W11-3: a SOLICIT without IA_NA must neither allocate a lease nor
    // answer with IA_NA (RFC 8415 18.3.1: addresses are only assigned in
    // response to an IA_NA / IA_TA option).
    void TestSolicitWithoutIaNaDoesNotLease() {
        Dhcp6Server server(MakeConfig());
        const auto now = std::chrono::steady_clock::now();
        auto frame = BuildRequest(kDhcp6MsgSolicit, 0x200001, kClientDuid,
                                  /*with_ia=*/false, 0, false, nullptr, false);
        Dhcp6View view;
        CHECK(ParseDhcp6Frame(frame.data(), frame.size(), view));
        CHECK(!view.has_ia_na);
        std::vector<uint8_t> reply;
        CHECK(server.HandleFrame(view, kClientMac, kClientLl, now, reply));
        CHECK(server.LeaseCount() == 0);
        ParsedReply parsed;
        CHECK(ParseReply(reply, parsed));
        CHECK(!parsed.has_ia);
    }

int main() {
    TestParseDhcp6Malformed();
    TestBuildReplyLayout();
    TestSolicitAdvertise();
    TestSolicitWithoutIaNaDoesNotLease();
    TestAcquireWalkSanitizesHostname();
    TestRapidCommit();
    TestParseDhcp6RejectsNonEmptyRapidCommit();
    TestRequestReply();
    TestRenew();
    TestRebind();
    TestRelease();
    TestDeclineParks();
    TestInformationRequest();
    TestPoolExhaustion();
    TestStaticBindingPriority();
    TestStaticBindingCountIsO1AndConsistent();
    TestRemoveConfigBinding6();
    TestUpsertBindingRejectsDuplicate();
    TestB137ReplaceBinding6IsAtomic();
    TestStaticBindings6MergeIsNotQuadratic();
    TestStaticBindingCount6IsNotQuadratic();
    TestB110RuntimeBinding6CapIsEnforcedInTheStore();
    TestB111RuntimeBinding6RejectsOversizedHostname();
    TestB123UpsertBinding6RejectsIllFormedUtf8Hostname();
    TestB112RuntimeBinding6RejectsAddressHeldByLiveLease();
    TestB114Acquire6WalkDoesNotScanLeasesPerCandidate();
    TestPoolSkipsNetworkIid();
    TestB134Leases6LoadRejectsDuplicateAddress();
    TestB120Leases6FileCorruptIsFlagged();
    TestB122ParseRejects6AreCounted();
    TestLeases6LoadSkipsIllegal();
    TestLegacyLeaseMissingExpiresRestored6();
    TestP145Leases6EntryTypeErrorsAreContained();
    TestP145Leases6ExpiresIsClampedToLeaseSeconds();
    TestP145V3Lease6ServesBeyondLegacyCap();
    TestP145V2Leases6LoadIsBounded();
    TestP145V1Leases6PartialCorruptionLeavesEvidence();
    TestP145V6Leases6DumpNeverWritesUnreadableFile();
    TestP145B2MultiIaidRecordsSurviveLoad();
    TestP145B2StaticCollapsesStrayDuidRecords();
    TestP145B2aExactIaidStillCollapsesStrays();
    TestP145B2aCarrierPinsCallerIaid();
    TestP145StaticBindingOwnsOneLeasePerDuid();
    TestLeases6RoundTrip();
    TestLease6DumpFlushFailureKeepsPreviousSnapshot();
    TestCorruptLease6FilePreserved();
    TestLease6LoadTransientLockIsNotCorrupt();
    TestLease6LoadUnreadablePausesDump();
    TestLease6DumpRecoversFromBlocked();
    TestB81DumpLeasesDoesNotStallLockHolders();
    TestLoadCap();
    TestRateLimitPerDuid();
    TestParseDhcp6HeaderGates();
    TestParseDhcp6OptionEdges();
    TestBuildReplyFrameByteOrder();
    TestP154ServerIdAndIaRules();
    TestClassifierDhcpV6();
    if (0 == g_failures) {
        std::puts("test_dhcp6: ALL PASS");
        return 0;
    }
    std::fprintf(stderr, "test_dhcp6: %d FAILURES\n", g_failures);
    return 1;
}
