// ============================================================================
// test_arp_icmp.cpp - ARP responder + ICMP echo reply correctness.
//
// Assertions encode RFC 826 responder semantics and the ICMP echo-reply
// symmetry (type flip, address swap, valid checksums).
// ============================================================================
#include "proto/arp.h"
#include "proto/icmp.h"
#include "proto/udp.h"

#include <array>
#include <cstdio>
#include <cstring>
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

    using namespace vgww::net;
    using namespace vgww::proto;

    // inet_addr numeric convention: first octet in the LOW byte.
    constexpr uint32_t kGatewayIp = (40u) | (0u << 8) | (168u << 16) | (192u << 24);
    constexpr uint32_t kClientIp = (101u) | (0u << 8) | (168u << 16) | (192u << 24);
    const WireMac kGatewayMac{0x30, 0xFC, 0x68, 0x88, 0xB4, 0xA9};
    const WireMac kClientMac{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01};

    std::vector<uint8_t> BuildArpRequest(uint32_t sender_ip, uint32_t target_ip) {
        std::vector<uint8_t> f(kArpFrameLen, 0);
        BuildArpFrame(f.data(), ArpOperation::kRequest, kClientMac, sender_ip,
                      kBroadcastMac, target_ip);
        return f;
    }

    void TestArpReplyForGateway() {
        auto request = BuildArpRequest(kClientIp, kGatewayIp);
        ArpView view;
        CHECK(ParseArpFrame(request.data(), request.size(), view));
        CHECK(ArpOperation::kRequest == view.operation);
        CHECK(view.target_ip == kGatewayIp);

        std::array<uint8_t, kArpFrameLen> reply{};
        CHECK(BuildGatewayArpReply(view, kGatewayIp, kGatewayMac, reply));

        ArpView reply_view;
        CHECK(ParseArpFrame(reply.data(), reply.size(), reply_view));
        CHECK(ArpOperation::kReply == reply_view.operation);
        CHECK(reply_view.sender_ip == kGatewayIp);
        CHECK(reply_view.target_ip == kClientIp);
        CHECK(reply_view.sender_mac == kGatewayMac);
        CHECK(reply_view.target_mac == kClientMac);

        // Requests for OTHER addresses must not be answered.
        auto other = BuildArpRequest(kClientIp, (1u) | (0u << 8) | (168u << 16) | (192u << 24));
        ParseArpFrame(other.data(), other.size(), view);
        std::array<uint8_t, kArpFrameLen> no_reply{};
        CHECK(!BuildGatewayArpReply(view, kGatewayIp, kGatewayMac, no_reply));
    }

    void TestGratuitousArp() {
        std::array<uint8_t, kArpFrameLen> frame{};
        BuildGratuitousAnnouncement(kGatewayIp, kGatewayMac, frame);
        ArpView view;
        CHECK(ParseArpFrame(frame.data(), frame.size(), view));
        CHECK(ArpOperation::kRequest == view.operation);
        CHECK(view.sender_ip == kGatewayIp);
        CHECK(view.target_ip == kGatewayIp);
        CHECK(IsBroadcast(view.target_mac));
    }

    /// Builds eth+ip+icmp echo request to the gateway with `payload` bytes.
    std::vector<uint8_t> BuildEchoRequest(size_t payload, uint16_t id, uint16_t seq) {
        const size_t icmp_len = kIcmpHeaderLen + payload;
        std::vector<uint8_t> f(kEthernetHeaderLen + kIpv4HeaderLenMin + icmp_len);
        BuildEthHeader(f.data(), kGatewayMac, kClientMac, kEthertypeIpv4);
        uint8_t* ip = f.data() + kEthernetHeaderLen;
        ip[0] = 0x45;
        const uint16_t total = static_cast<uint16_t>(kIpv4HeaderLenMin + icmp_len);
        ip[2] = static_cast<uint8_t>(total >> 8);
        ip[3] = static_cast<uint8_t>(total & 0xFF);
        ip[8] = 64;      // TTL
        ip[9] = 1;       // ICMP
        std::memcpy(ip + 12, &kClientIp, 4);
        std::memcpy(ip + 16, &kGatewayIp, 4);
        uint8_t* icmp = ip + kIpv4HeaderLenMin;
        icmp[0] = kIcmpEchoRequest;
        icmp[4] = static_cast<uint8_t>(id >> 8);
        icmp[5] = static_cast<uint8_t>(id & 0xFF);
        icmp[6] = static_cast<uint8_t>(seq >> 8);
        icmp[7] = static_cast<uint8_t>(seq & 0xFF);
        for (size_t i = 0; i < payload; ++i) {
            icmp[kIcmpHeaderLen + i] = static_cast<uint8_t>(i & 0xFF);
        }
        return f;
    }

    void TestEchoReply() {
        auto request = BuildEchoRequest(32, 0x1234, 7);
        const uint8_t* ip = request.data() + kEthernetHeaderLen;

        IcmpEchoView view;
        CHECK(ParseIcmpEcho(ip, request.size() - kEthernetHeaderLen, view));
        CHECK(kIcmpEchoRequest == view.type);
        CHECK(view.identifier == 0x1234);
        CHECK(view.sequence == 7);
        CHECK(view.payload_len == 32);

        std::vector<uint8_t> reply;
        BuildEchoReplyFrame(ip, request.size() - kEthernetHeaderLen, kGatewayMac,
                            kClientMac, reply);
        CHECK(reply.size() == request.size());

        EthHeaderView eth;
        CHECK(ParseEthHeader(reply.data(), reply.size(), eth));
        CHECK(eth.dst == kClientMac);
        CHECK(eth.src == kGatewayMac);

        const uint8_t* rip = reply.data() + kEthernetHeaderLen;
        IcmpEchoView rview;
        CHECK(ParseIcmpEcho(rip, reply.size() - kEthernetHeaderLen, rview));
        CHECK(kIcmpEchoReply == rview.type);
        CHECK(rview.identifier == 0x1234);
        CHECK(rview.sequence == 7);

        // Addresses swapped; checksum fields non-zero.
        CHECK(0 != rip[10] || 0 != rip[11]);          // IP checksum set
        const size_t ihl = (rip[0] & 0x0F) * 4;
        const uint8_t* ricmp = rip + ihl;
        CHECK(0 != ricmp[2] || 0 != ricmp[3]);        // ICMP checksum set

        // Verify the ICMP checksum independently: summing header+payload
        // WITH the checksum field included must yield zero (RFC 1071).
        uint32_t sum = 0;
        const size_t icmp_len = kIcmpHeaderLen + rview.payload_len;
        for (size_t i = 0; i < icmp_len; i += 2) {
            const uint16_t hi = ricmp[i];
            const uint16_t lo = (i + 1 < icmp_len) ? ricmp[i + 1] : 0;
            sum += static_cast<uint32_t>((hi << 8) | lo);
        }
        while (sum >> 16) {
            sum = (sum & 0xFFFFu) + (sum >> 16);
        }
        CHECK((~sum & 0xFFFFu) == 0);
    }

    /// batch126: the ICMP relay handlers in dataplane.cpp computed ihl from
    /// the wire nibble and used it to index into the frame WITHOUT checking
    /// the RFC 791 range. ihl = 0 made `ip + ihl` point at the IPv4 header
    /// itself, so the "ICMP type" byte read ip[0] and the relay forwarded the
    /// whole datagram (header included) as an ICMP segment. DHCP already
    /// enforced 20..60 (ParseDhcpFrame); the ICMP path was the unchecked
    /// same-shape sibling (C9). The rule is now a single shared helper so the
    /// two call sites cannot drift.
    void TestIpv4HeaderLengthValidation() {
        // Legal range boundaries (RFC 791: IHL is 5..15 words = 20..60).
        CHECK(vgww::proto::IsLegalIpv4HeaderLength(20));
        CHECK(vgww::proto::IsLegalIpv4HeaderLength(24));
        CHECK(vgww::proto::IsLegalIpv4HeaderLength(40));
        CHECK(vgww::proto::IsLegalIpv4HeaderLength(60));
        // Below the minimum: the old handlers accepted these.
        CHECK(!vgww::proto::IsLegalIpv4HeaderLength(0));
        CHECK(!vgww::proto::IsLegalIpv4HeaderLength(4));
        CHECK(!vgww::proto::IsLegalIpv4HeaderLength(16));
        CHECK(!vgww::proto::IsLegalIpv4HeaderLength(19));
        // Above the maximum a 4-bit IHL cannot even express, but the helper
        // is total: any value passed must be judged, not assumed.
        CHECK(!vgww::proto::IsLegalIpv4HeaderLength(64));
        CHECK(!vgww::proto::IsLegalIpv4HeaderLength(255));
        // Non-multiple-of-4 lengths cannot come from a 4-byte word count, and
        // no caller may rely on one.
        CHECK(!vgww::proto::IsLegalIpv4HeaderLength(21));
        CHECK(!vgww::proto::IsLegalIpv4HeaderLength(59));
    }

void TestRejectsMalformedOper() {        // RFC 826 defines exactly two operation codes (1=request, 2=reply).
        // Any other value is malformed and must not be parsed as a request:
        // answering it for the gateway would echo a garbage operand back at
        // the LAN.
        std::vector<uint8_t> f(kArpFrameLen, 0);
        BuildArpFrame(f.data(), ArpOperation::kRequest, kClientMac, kClientIp,
                      kBroadcastMac, kGatewayIp);
        f[kEthernetHeaderLen + 6] = 0x00;
        f[kEthernetHeaderLen + 7] = 0x03;  // oper = 3
        ArpView view;
        CHECK(!ParseArpFrame(f.data(), f.size(), view));

        f[kEthernetHeaderLen + 7] = 0x00;  // oper = 0
        CHECK(!ParseArpFrame(f.data(), f.size(), view));

        // A well-formed request still parses (positive control).
        auto good = BuildArpRequest(kClientIp, kGatewayIp);
        CHECK(ParseArpFrame(good.data(), good.size(), view));
        CHECK(ArpOperation::kRequest == view.operation);
    }

/// batch271: the ARP header's four fixed fields. Only `oper` had a rejection
/// test; `htype`, `ptype`, `hlen` and `plen` were never varied, so dropping
/// any of their comparisons would make ParseArpFrame decode a NON-Ethernet
/// or NON-IPv4 frame as if it were ARP-over-IPv4 - and the responder would
/// then answer with a fabricated gateway MAC for whatever bytes sat at the
/// IPv4 offsets.
void TestRejectsMalformedArpHeaderFields() {
    const auto fresh = [] {
        std::vector<uint8_t> f(kArpFrameLen, 0);
        BuildArpFrame(f.data(), ArpOperation::kRequest, kClientMac, kClientIp,
                      kBroadcastMac, kGatewayIp);
        return f;
    };
    ArpView view;

    // Negative control first: the unmodified frame must parse, so a later
    // "rejected" result is attributable to the byte we changed.
    {
        auto f = fresh();
        CHECK(ParseArpFrame(f.data(), f.size(), view));
        CHECK(ArpOperation::kRequest == view.operation);
        CHECK(view.sender_ip == kClientIp);
        CHECK(view.target_ip == kGatewayIp);
    }

    // htype: Ethernet(1) is the only accepted value.
    for (const uint16_t bad : {static_cast<uint16_t>(0),
                               static_cast<uint16_t>(2),
                               static_cast<uint16_t>(6),
                               static_cast<uint16_t>(0xFFFF)}) {
        auto f = fresh();
        f[kEthernetHeaderLen + 0] = static_cast<uint8_t>(bad >> 8);
        f[kEthernetHeaderLen + 1] = static_cast<uint8_t>(bad & 0xFF);
        CHECK(!ParseArpFrame(f.data(), f.size(), view));
    }

    // ptype: IPv4(0x0800) only. IPv6 0x86DD and a swapped pair must fail.
    for (const uint16_t bad : {static_cast<uint16_t>(0x86DD),
                               static_cast<uint16_t>(0x0008),
                               static_cast<uint16_t>(0),
                               static_cast<uint16_t>(0x0806)}) {
        auto f = fresh();
        f[kEthernetHeaderLen + 2] = static_cast<uint8_t>(bad >> 8);
        f[kEthernetHeaderLen + 3] = static_cast<uint8_t>(bad & 0xFF);
        CHECK(!ParseArpFrame(f.data(), f.size(), view));
    }

    // hlen: must equal the MAC length (6). 0/5/7/16 all rejected.
    for (const uint8_t bad : {static_cast<uint8_t>(0), static_cast<uint8_t>(5),
                              static_cast<uint8_t>(7),
                              static_cast<uint8_t>(16)}) {
        auto f = fresh();
        f[kEthernetHeaderLen + 4] = bad;
        CHECK(!ParseArpFrame(f.data(), f.size(), view));
    }

    // plen: must equal 4 (IPv4 address size).
    for (const uint8_t bad : {static_cast<uint8_t>(0), static_cast<uint8_t>(3),
                              static_cast<uint8_t>(5),
                              static_cast<uint8_t>(16)}) {
        auto f = fresh();
        f[kEthernetHeaderLen + 5] = bad;
        CHECK(!ParseArpFrame(f.data(), f.size(), view));
    }

    // Accepted-edge control: exactly 1/0x0800/6/4 parses.
    {
        auto f = fresh();
        CHECK(f[kEthernetHeaderLen + 0] == 0x00 &&
              f[kEthernetHeaderLen + 1] == 0x01);
        CHECK(f[kEthernetHeaderLen + 2] == 0x08 &&
              f[kEthernetHeaderLen + 3] == 0x00);
        CHECK(f[kEthernetHeaderLen + 4] == 6);
        CHECK(f[kEthernetHeaderLen + 5] == 4);
        CHECK(ParseArpFrame(f.data(), f.size(), view));
    }
}

/// batch271: `BuildArpFrame` has to write every field it claims to. The
/// existing tests only ever read the frame back through ParseArpFrame (which
/// validates the same constants), so a builder that swapped sender/target
/// or dropped the operation high byte would still round-trip.
void TestBuildArpFrameWireLayout() {
    std::vector<uint8_t> f(kArpFrameLen, 0xEE);  // pre-fill: nothing may stay
    const uint8_t sender_mac[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    const uint8_t target_mac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    const WireMac src{sender_mac[0], sender_mac[1], sender_mac[2],
                      sender_mac[3], sender_mac[4], sender_mac[5]};
    const WireMac dst{target_mac[0], target_mac[1], target_mac[2],
                      target_mac[3], target_mac[4], target_mac[5]};
    const uint32_t src_ip = 0x01020304u;
    const uint32_t dst_ip = 0xA1B2C3D4u;
    BuildArpFrame(f.data(), ArpOperation::kReply, src, src_ip, dst, dst_ip);

    // Ethernet header: dst MAC first, then src MAC, then 0x0806.
    for (int i = 0; i < 6; ++i) {
        CHECK(f[i] == target_mac[i]);
        CHECK(f[6 + i] == sender_mac[i]);
    }
    CHECK(f[12] == 0x08 && f[13] == 0x06);

    const size_t p = kEthernetHeaderLen;
    // htype 1, ptype 0x0800, hlen 6, plen 4 - read as absolute bytes.
    CHECK(f[p + 0] == 0x00 && f[p + 1] == 0x01);
    CHECK(f[p + 2] == 0x08 && f[p + 3] == 0x00);
    CHECK(f[p + 4] == 6);
    CHECK(f[p + 5] == 4);
    // oper = 2 (reply), big-endian.
    CHECK(f[p + 6] == 0x00 && f[p + 7] == 0x02);
    // sha, spa, tha, tpa in that order.
    for (int i = 0; i < 6; ++i) CHECK(f[p + 8 + i] == sender_mac[i]);
    CHECK(f[p + 14] == 0x04 && f[p + 15] == 0x03 &&
          f[p + 16] == 0x02 && f[p + 17] == 0x01);
    for (int i = 0; i < 6; ++i) CHECK(f[p + 18 + i] == target_mac[i]);
    CHECK(f[p + 24] == 0xD4 && f[p + 25] == 0xC3 &&
          f[p + 26] == 0xB2 && f[p + 27] == 0xA1);

    // A request flips ONLY the operation word.
    auto request = f;
    BuildArpFrame(request.data(), ArpOperation::kRequest, src, src_ip, dst,
                  dst_ip);
    CHECK(request[p + 6] == 0x00 && request[p + 7] == 0x01);
    for (size_t i = 0; i < f.size(); ++i) {
        if (i == p + 6 || i == p + 7) continue;
        CHECK(request[i] == f[i]);
    }

    // Pre-fill really was overwritten: the 0xEE sentinel is only meaningful
    // where the frame must NOT contain 0xEE (target_mac legitimately ends in
    // 0xEE, so a whole-frame scan would be a false positive).
    CHECK(f[kEthernetHeaderLen + 6] == 0x00);  // oper high byte
}

/// batch271: BuildGatewayArpReply's guards, each isolated.
void TestGatewayArpReplyGuards() {
    std::array<uint8_t, kArpFrameLen> out{};
    ArpView request;
    request.operation = ArpOperation::kRequest;
    request.sender_mac = kClientMac;
    request.sender_ip = kClientIp;
    request.target_ip = kGatewayIp;

    // (1) A REPLY must never be answered (that would be an ARP storm).
    {
        ArpView reply = request;
        reply.operation = ArpOperation::kReply;
        CHECK(!BuildGatewayArpReply(reply, kGatewayIp, kGatewayMac, out));
    }
    // (2) A request for any other IP must not be answered.
    {
        ArpView other = request;
        other.target_ip = kClientIp;
        CHECK(!BuildGatewayArpReply(other, kGatewayIp, kGatewayMac, out));
    }
    // (3) The matching request IS answered, and the reply targets the
    //     requester (tha = requester's MAC, tpa = requester's IP).
    {
        CHECK(BuildGatewayArpReply(request, kGatewayIp, kGatewayMac, out));
        ArpView reply;
        CHECK(ParseArpFrame(out.data(), out.size(), reply));
        CHECK(ArpOperation::kReply == reply.operation);
        CHECK(reply.sender_mac == kGatewayMac);
        CHECK(reply.sender_ip == kGatewayIp);
        CHECK(reply.target_mac == kClientMac);
        CHECK(reply.target_ip == kClientIp);
    }
    // (4) The target_ip comparison must be exact: one bit off is refused.
    {
        ArpView almost = request;
        almost.target_ip = kGatewayIp ^ 0x01000000u;
        CHECK(!BuildGatewayArpReply(almost, kGatewayIp, kGatewayMac, out));
    }
}

void TestUdpV6ZeroChecksumBecomesOxFFFF() {
        // RFC 8200 section 8.1: in IPv6 the UDP checksum is mandatory and the value
        // 0 is invalid; a computed 0 must be transmitted as 0xFFFF. This
        // payload word was chosen so the folded pseudo-header + UDP segment
        // sum lands on 0xFFFF (computed checksum 0).
        const std::array<uint8_t, 16> src = {
            0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01};
        const std::array<uint8_t, 16> dst = {
            0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01};
        const uint8_t payload[] = {0xED, 0x36};
        std::vector<uint8_t> frame;
        BuildUdpFrameV6(frame, kGatewayMac, kClientMac, src.data(), 53,
                        dst.data(), 5353, payload, sizeof(payload));
        const uint8_t* udp = frame.data() + kEthernetHeaderLen + 40;
        CHECK(udp[6] == 0xFF && udp[7] == 0xFF);
    }

}  // namespace

int main() {
    TestArpReplyForGateway();
    TestGratuitousArp();
    TestRejectsMalformedOper();
    TestRejectsMalformedArpHeaderFields();
    TestBuildArpFrameWireLayout();
    TestGatewayArpReplyGuards();
    TestEchoReply();
    TestIpv4HeaderLengthValidation();
    TestUdpV6ZeroChecksumBecomesOxFFFF();
    if (0 == g_failures) {
        std::puts("test_arp_icmp: ALL PASS");
        return 0;
    }
    std::fprintf(stderr, "test_arp_icmp: %d FAILURES\n", g_failures);
    return 1;
}
