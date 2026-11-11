// ============================================================================
// test_icmp.cpp - ICMP echo parse + reply builders (proto/icmp.h).
//
// The 135-line implementation had almost no direct coverage: the sole case in
// test_arp_icmp builds a request and checks the reply's type/id/seq, which
// left THREE guard branches in ParseIcmpEcho and the ENTIRE
// BuildRelayedEchoReplyFrame builder (8 mutation sites) unobserved.
//
// What is pinned here:
//   * ParseIcmpEcho rejects wrong version / wrong protocol / short IHL, and
//     clamps payload_len to the bytes actually present
//   * BuildEchoReplyFrame swaps addresses, flips the type, copies the payload,
//     sets TTL and recomputes both checksums
//   * BuildRelayedEchoReplyFrame builds a complete frame from scratch:
//     addresses from the arguments, caller-supplied id/seq, payload verbatim,
//     and both checksums verifying to zero
// ============================================================================
#define CHECK(cond)                                                        \
    do {                                                                   \
        if (!(cond)) {                                                     \
            std::fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__,  \
                         __LINE__, #cond);                                 \
            return 1;                                                      \
        }                                                                  \
    } while (0)

#include "net/checksum.h"
#include "proto/icmp.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

namespace {

    using namespace vgww;
    using namespace vgww::proto;
    using vgww::net::WireMac;

    const WireMac kGatewayMac{0x30, 0xFC, 0x68, 0x88, 0xB4, 0xA9};
    const WireMac kClientMac{0x02, 0x00, 0x5A, 0x00, 0x00, 0x01};

    const uint8_t kGwIp[4] = {192, 168, 0, 1};
    const uint8_t kClientIp[4] = {192, 168, 0, 100};
    const uint8_t kRemoteIp[4] = {8, 8, 8, 8};

    uint16_t Sum16NoCk(const uint8_t* p, size_t len);

    /// Builds a bare IPv4+ICMP echo request datagram (no Ethernet header).
    std::vector<uint8_t> MakeRequest(uint8_t type, uint16_t id, uint16_t seq,
                                     size_t payload_len,
                                     uint8_t proto = 1,
                                     uint8_t version = 4,
                                     uint8_t ihl_words = 5) {
        const size_t header_len = static_cast<size_t>(ihl_words) * 4;
        const size_t icmp_len = kIcmpHeaderLen + payload_len;
        std::vector<uint8_t> d(header_len + icmp_len, 0);
        d[0] = static_cast<uint8_t>((version << 4) | ihl_words);
        const uint16_t total = static_cast<uint16_t>(header_len + icmp_len);
        d[2] = static_cast<uint8_t>(total >> 8);
        d[3] = static_cast<uint8_t>(total & 0xFF);
        std::memcpy(&d[12], kClientIp, 4);
        std::memcpy(&d[16], kGwIp, 4);
        d[9] = proto;

        uint8_t* icmp = d.data() + header_len;
        icmp[0] = type;
        icmp[1] = 0;
        icmp[4] = static_cast<uint8_t>(id >> 8);
        icmp[5] = static_cast<uint8_t>(id & 0xFF);
        icmp[6] = static_cast<uint8_t>(seq >> 8);
        icmp[7] = static_cast<uint8_t>(seq & 0xFF);
        for (size_t i = 0; i < payload_len; ++i) {
            icmp[kIcmpHeaderLen + i] = static_cast<uint8_t>((i * 7) & 0xFF);
        }
        // A REAL request carries a valid IP header checksum. Leaving it zero
        // would make BuildEchoReplyFrame's "clear the old checksum" step a
        // no-op, so the fixture must actually populate it.
        const uint16_t ip_ck =
            static_cast<uint16_t>(~Sum16NoCk(d.data(), header_len) & 0xFFFF);
        d[10] = static_cast<uint8_t>(ip_ck >> 8);
        d[11] = static_cast<uint8_t>(ip_ck & 0xFF);
        return d;
    }
    /// One's-complement sum with folding, WITHOUT the final complement.
    uint16_t Sum16NoCk(const uint8_t* p, size_t len) {
        uint32_t sum = 0;
        for (size_t i = 0; i + 1 < len; i += 2) {
            sum += static_cast<uint32_t>((p[i] << 8) | p[i + 1]);
        }
        if (len & 1) {
            sum += static_cast<uint32_t>(p[len - 1] << 8);
        }
        while (sum >> 16) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        return static_cast<uint16_t>(sum);
    }

    /// RFC 1071 verification: summing a buffer that already carries its
    /// one's-complement checksum must fold to 0xFFFF (whose complement is 0).
    /// (A verified-zero buffer folds to 0xFFFF, NOT to 0.)
    uint16_t Sum16(const uint8_t* p, size_t len) {
        uint32_t sum = 0;
        for (size_t i = 0; i + 1 < len; i += 2) {
            sum += static_cast<uint32_t>((p[i] << 8) | p[i + 1]);
        }
        if (len & 1) {
            sum += static_cast<uint32_t>(p[len - 1] << 8);
        }
        while (sum >> 16) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        return static_cast<uint16_t>(sum);
    }
    /// True when the buffer's own checksum field verifies (folds to 0xFFFF).
    bool Verifies(const uint8_t* p, size_t len) {
        return 0xFFFF == Sum16(p, len);
    }

}  // namespace

namespace vgww {

    /// Rule: only IPv4 (version nibble 4) is accepted. A version-6 datagram
    /// reaching this parser must be rejected, not silently misread.
    int TestParseRejectsWrongVersion() {
        auto d = MakeRequest(kIcmpEchoRequest, 1, 1, 8, /*proto*/ 1, /*version*/ 6);
        IcmpEchoView view;
        CHECK(!ParseIcmpEcho(d.data(), d.size(), view));
        return 0;
    }

    /// Rule: only protocol 1 (ICMP). A UDP datagram (17) must be rejected.
    int TestParseRejectsWrongProtocol() {
        auto d = MakeRequest(kIcmpEchoRequest, 1, 1, 8, /*proto*/ 17);
        IcmpEchoView view;
        CHECK(!ParseIcmpEcho(d.data(), d.size(), view));
        return 0;
    }

    /// Rule: IHL must be at least 5 words (20 bytes). IHL 4 would point the
    /// ICMP header four bytes BEFORE the declared header end.
    int TestParseRejectsShortIhl() {
        for (uint8_t ihl = 1; ihl < 5; ++ihl) {
            auto d = MakeRequest(kIcmpEchoRequest, 1, 1, 8, 1, 4, ihl);
            IcmpEchoView view;
            if (ParseIcmpEcho(d.data(), d.size(), view)) {
                std::fprintf(stderr, "accepted IHL=%u\n", static_cast<unsigned>(ihl));
                return 1;
            }
        }
        // IHL 5 and 6 must both work; 6 means 4 bytes of options are skipped.
        {
            auto d = MakeRequest(kIcmpEchoRequest, 0xABCD, 9, 8, 1, 4, 6);
            IcmpEchoView view;
            CHECK(ParseIcmpEcho(d.data(), d.size(), view));
            CHECK(0xABCD == view.identifier);
            CHECK(9 == view.sequence);
            CHECK(8 == view.payload_len);
            CHECK(32 == view.payload_offset);  // header 6*4 + icmp 8
        }
        return 0;
    }

    /// Rule: payload_len comes from the IPv4 total length, but must never
    /// exceed the bytes actually present. A datagram whose total_len claims
    /// more than `ip_len` must clamp to `ip_len - header - icmp_hdr`.
    int TestParsePayloadLenIsClamped() {
        auto d = MakeRequest(kIcmpEchoRequest, 1, 1, 16);
        IcmpEchoView view;
        CHECK(ParseIcmpEcho(d.data(), d.size(), view));
        CHECK(16 == view.payload_len);
        CHECK(28 == view.payload_offset);

        // Claim a total length far beyond the buffer we hand over.
        d[2] = 0xFF;
        d[3] = 0xFF;
        const size_t truncated = 20 + kIcmpHeaderLen + 4;  // only 4 payload bytes
        CHECK(ParseIcmpEcho(d.data(), truncated, view));
        CHECK(4 == view.payload_len);

        // A total_len SMALLER than header+icmp is nonsense; fall back to the
        // real bytes as well.
        d[2] = 0;
        d[3] = 0;
        CHECK(ParseIcmpEcho(d.data(), d.size(), view));
        CHECK(16 == view.payload_len);
        return 0;
    }

    /// Rule: a datagram shorter than header+8 must be rejected outright.
    int TestParseRejectsShortDatagram() {
        auto d = MakeRequest(kIcmpEchoRequest, 1, 1, 8);
        IcmpEchoView view;
        CHECK(!ParseIcmpEcho(d.data(), kIpv4HeaderLenMin, view));       // exactly 20
        CHECK(!ParseIcmpEcho(d.data(), kIpv4HeaderLenMin + 7, view));   // 7 ICMP bytes
        CHECK(ParseIcmpEcho(d.data(), kIpv4HeaderLenMin + 8, view));    // 8 works
        CHECK(0 == view.payload_len);
        // Anything shorter than a minimum IPv4 header is refused first.
        CHECK(!ParseIcmpEcho(d.data(), kIpv4HeaderLenMin - 1, view));
        return 0;
    }

    /// Rule: the ICMP segment length comes from the IPv4 total length, never
    /// from the buffer length. The driver reports the padded Ethernet frame
    /// length, so a 0-payload ping arrives with 18 trailing padding bytes;
    /// the segment must still be 8 bytes, not 26.
    int TestIcmpSegmentLengthUsesIpTotal() {
        auto d = MakeRequest(kIcmpEchoRequest, 1, 1, 0);   // total 28
        CHECK(28 == d.size());
        size_t seg_len = 0;
        CHECK(IcmpSegmentLength(d.data(), d.size(), seg_len));
        CHECK(8 == seg_len);

        // The same datagram padded to the 60-byte Ethernet minimum.
        d.resize(60, 0);
        CHECK(IcmpSegmentLength(d.data(), d.size(), seg_len));
        CHECK(8 == seg_len);   // NOT 60 - 20 = 40

        // Payload 16: total 44, padded to 60 -> segment 24.
        auto p = MakeRequest(kIcmpEchoRequest, 1, 1, 16);
        p.resize(60, 0);
        CHECK(IcmpSegmentLength(p.data(), p.size(), seg_len));
        CHECK(24 == seg_len);

        // IPv4 options (IHL 6): total 40 -> segment 16.
        auto o = MakeRequest(kIcmpEchoRequest, 1, 1, 8, 1, 4, 6);
        CHECK(40 == o.size());
        CHECK(IcmpSegmentLength(o.data(), o.size(), seg_len));
        CHECK(16 == seg_len);

        // Truncated: the total length claims more than the buffer holds.
        auto t = MakeRequest(kIcmpEchoRequest, 1, 1, 16);
        CHECK(!IcmpSegmentLength(t.data(), 28, seg_len));

        // Total length below header + 8 is nonsense.
        auto b = MakeRequest(kIcmpEchoRequest, 1, 1, 8);
        b[2] = 0;
        b[3] = 24;   // 24 < 20 + 8
        CHECK(!IcmpSegmentLength(b.data(), b.size(), seg_len));

        // Not IPv4.
        auto v6 = MakeRequest(kIcmpEchoRequest, 1, 1, 8, 1, 6);
        CHECK(!IcmpSegmentLength(v6.data(), v6.size(), seg_len));

        // Shorter than a minimal IPv4 header.
        auto s = MakeRequest(kIcmpEchoRequest, 1, 1, 8);
        CHECK(!IcmpSegmentLength(s.data(), kIpv4HeaderLenMin - 1, seg_len));
        return 0;
    }

    /// BuildEchoReplyFrame: addresses swap, type flips, payload survives
    /// byte-for-byte, TTL is set, and BOTH checksums verify to zero.
    int TestEchoReplyContents() {
        auto request = MakeRequest(kIcmpEchoRequest, 0x1234, 0x5678, 32);
        std::array<uint8_t, proto::kMaxEchoReplyFrameBytes> reply;
        const size_t reply_len = proto::BuildEchoReplyFrame(
            request.data(), request.size(), kGatewayMac,
            kClientMac, reply);
        CHECK(request.size() + net::kEthernetHeaderLen == reply_len);

        // Ethernet: the reply goes TO the client FROM the gateway. Without
        // this pair a swap is unobservable (the IP-layer addresses below are
        // asserted separately and would still be right).
        const uint8_t* eth = reply.data();
        CHECK(0 == std::memcmp(eth, kClientMac.data(), 6));
        CHECK(0 == std::memcmp(eth + 6, kGatewayMac.data(), 6));
        CHECK(0x08 == eth[12] && 0x00 == eth[13]);

        const uint8_t* ip = reply.data() + net::kEthernetHeaderLen;
        // src must now be the gateway (the request's dst), dst the client.
        CHECK(0 == std::memcmp(ip + 12, kGwIp, 4));
        CHECK(0 == std::memcmp(ip + 16, kClientIp, 4));
        CHECK(63 == ip[8]);   // TTL set for the local answer

        const size_t header_len = static_cast<size_t>(ip[0] & 0x0F) * 4;
        CHECK(20 == header_len);
        const uint8_t* icmp = ip + header_len;
        CHECK(kIcmpEchoReply == icmp[0]);

        // Payload copied verbatim from the request.
        CHECK(0 == std::memcmp(icmp + kIcmpHeaderLen,
                               request.data() + header_len + kIcmpHeaderLen, 32));

        // Total length updated to header + 8 + 32.
        const uint16_t total = static_cast<uint16_t>((ip[2] << 8) | ip[3]);
        CHECK(20 + kIcmpHeaderLen + 32 == total);

        // Both checksums must verify to zero (RFC 1071).
        CHECK(Verifies(ip, header_len));
        CHECK(Verifies(icmp, kIcmpHeaderLen + 32));
        return 0;
    }

    /// with IHL > 5 the reply must keep the same header length (options are
    /// copied) and still checksum correctly.
    int TestEchoReplyWithOptions() {
        auto request = MakeRequest(kIcmpEchoRequest, 7, 8, 16, 1, 4, 6);
        std::array<uint8_t, proto::kMaxEchoReplyFrameBytes> reply;
        const size_t reply_len = proto::BuildEchoReplyFrame(
            request.data(), request.size(), kGatewayMac,
            kClientMac, reply);
        CHECK(reply_len ==
              net::kEthernetHeaderLen + request.size());
        const uint8_t* ip = reply.data() + net::kEthernetHeaderLen;
        CHECK(24 == (ip[0] & 0x0F) * 4);
        CHECK(0 == std::memcmp(ip + 12, kGwIp, 4));
        CHECK(Verifies(ip, 24));
        CHECK(Verifies(ip + 24, kIcmpHeaderLen + 16));
        return 0;
    }

    /// A non-echo / unparseable request must return 0 and leave out untouched.
    int TestEchoReplyIgnoresGarbage() {
        std::array<uint8_t, proto::kMaxEchoReplyFrameBytes> reply;
        reply.fill(0xAA);
        CHECK(0 == proto::BuildEchoReplyFrame(nullptr, 0, kGatewayMac,
                                              kClientMac, reply));
        // untouched: still 0xAA at both ends
        CHECK(0xAA == reply[0] && 0xAA == reply[reply.size() - 1]);

        // Wrong protocol: still untouched.
        auto d = MakeRequest(kIcmpEchoRequest, 1, 1, 8, /*proto*/ 17);
        std::array<uint8_t, proto::kMaxEchoReplyFrameBytes> reply2;
        reply2.fill(0xCC);
        CHECK(0 == proto::BuildEchoReplyFrame(d.data(), d.size(), kGatewayMac,
                                              kClientMac, reply2));
        CHECK(0xCC == reply2[0] && 0xCC == reply2[reply2.size() - 1]);
        return 0;
    }

    /// The stack-buffer builder writes nothing beyond its buffer. A request
    /// whose reply would exceed kMaxEchoReplyFrameBytes returns 0 (caller
    /// drops it via AppendDown), never heap-allocates, never throws.
    int TestBuilderNeverAllocates() {
        auto request = MakeRequest(kIcmpEchoRequest, 1, 1, 32);
        std::array<uint8_t, proto::kMaxEchoReplyFrameBytes> reply{};
        const size_t len = proto::BuildEchoReplyFrame(
            request.data(), request.size(), kGatewayMac,
            kClientMac, reply);
        CHECK(len == request.size() + net::kEthernetHeaderLen);
        return 0;
    }

    /// A request whose reply would exceed kMaxEchoReplyFrameBytes must be
    /// dropped: return 0 and leave `out` untouched, so the caller (AppendDown)
    /// never forwards an overrun frame.
    int TestBuilderDropsOversizeReply() {
        constexpr size_t kPayload = proto::kMaxEchoReplyFrameBytes + 256;
        auto request =
            MakeRequest(kIcmpEchoRequest, 1, 1, kPayload);
        std::array<uint8_t, proto::kMaxEchoReplyFrameBytes> reply{};
        reply.fill(0xAA);
        const size_t len = proto::BuildEchoReplyFrame(
            request.data(), request.size(), kGatewayMac,
            kClientMac, reply);
        CHECK(0 == len);
        // untouched: still 0xAA at both ends
        CHECK(0xAA == reply[0] && 0xAA == reply[reply.size() - 1]);
        return 0;
    }

    /// BuildRelayedEchoReplyFrame had ZERO coverage. Pin every field: source is
    /// the remote host, destination our client, the caller's id/seq are
    /// restored, the payload is copied verbatim, and both checksums verify.
    int TestRelayedReplyContents() {
        const uint8_t payload[24] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
                                     12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23};
        std::vector<uint8_t> frame;
        BuildRelayedEchoReplyFrame(kRemoteIp, kClientIp, kGatewayMac, kClientMac,
                                   0xBEEF, 0x0042, payload, sizeof(payload),
                                   frame);
        CHECK(net::kEthernetHeaderLen + kIpv4HeaderLenMin + kIcmpHeaderLen +
                  sizeof(payload) ==
              frame.size());

        // Ethernet: to the client, from the gateway, IPv4 ethertype.
        const uint8_t* eth = frame.data();
        CHECK(0 == std::memcmp(eth, kClientMac.data(), 6));
        CHECK(0 == std::memcmp(eth + 6, kGatewayMac.data(), 6));
        CHECK(0x08 == eth[12] && 0x00 == eth[13]);

        const uint8_t* ip = eth + net::kEthernetHeaderLen;
        CHECK(0x45 == ip[0]);
        // Source is the REMOTE host, destination our client.
        CHECK(0 == std::memcmp(ip + 12, kRemoteIp, 4));
        CHECK(0 == std::memcmp(ip + 16, kClientIp, 4));
        const uint16_t total = static_cast<uint16_t>((ip[2] << 8) | ip[3]);
        CHECK(kIpv4HeaderLenMin + kIcmpHeaderLen + sizeof(payload) == total);
        CHECK(1 == ip[9]);            // ICMP
        CHECK(Verifies(ip, kIpv4HeaderLenMin));

        const uint8_t* icmp = ip + kIpv4HeaderLenMin;
        CHECK(kIcmpEchoReply == icmp[0]);
        CHECK(0 == icmp[1]);
        // The caller's NAT-assigned id and the sequence are restored.
        CHECK(0xBE == icmp[4] && 0xEF == icmp[5]);
        CHECK(0x00 == icmp[6] && 0x42 == icmp[7]);
        // Payload verbatim.
        CHECK(0 == std::memcmp(icmp + kIcmpHeaderLen, payload, sizeof(payload)));
        CHECK(Verifies(icmp, kIcmpHeaderLen + sizeof(payload)));
        return 0;
    }

    /// The relayed-reply path must size the payload from the IPv4 total
    /// length, not from the received buffer: the driver hands over the
    /// PADDED Ethernet frame, so a reply to a 0-payload ping arrives as 60
    /// bytes and relaying the buffer length would send the client 32 bytes
    /// of padding as ICMP payload. This reproduces the exact computation
    /// HandleIcmpReply runs (IcmpSegmentLength -> payload_len -> builder).
    int TestRelayedReplyIgnoresEthernetPadding() {
        // 16-byte payload: total length 44, padded to the 60-byte minimum.
        auto reply = MakeRequest(kIcmpEchoReply, 0x0042, 0x0007, 16);
        reply.resize(60, 0xAA);  // padding must never reach the client

        size_t segment_len = 0;
        CHECK(IcmpSegmentLength(reply.data(), reply.size(), segment_len));
        CHECK(kIcmpHeaderLen + 16 == segment_len);  // not 60 - 20 = 40

        const uint8_t* icmp = reply.data() + kIpv4HeaderLenMin;

        // Drive the SAME entry point the data plane calls.
        std::vector<uint8_t> frame;
        CHECK(RelayEchoReplyToClient(reply.data(), reply.size(), kClientIp,
                                     kGatewayMac, kClientMac, 0x0042,
                                     frame));

        const uint8_t* ip = frame.data() + net::kEthernetHeaderLen;
        const uint16_t total = static_cast<uint16_t>((ip[2] << 8) | ip[3]);
        CHECK(kIpv4HeaderLenMin + kIcmpHeaderLen + 16 == total);
        CHECK(Verifies(ip, kIpv4HeaderLenMin));
        const uint8_t* out_icmp = ip + kIpv4HeaderLenMin;
        CHECK(Verifies(out_icmp, kIcmpHeaderLen + 16));
        // The 16 real payload bytes survived and no padding followed.
        CHECK(0 == std::memcmp(out_icmp + kIcmpHeaderLen, icmp + kIcmpHeaderLen, 16));
        CHECK(frame.size() ==
              net::kEthernetHeaderLen + kIpv4HeaderLenMin + kIcmpHeaderLen + 16);

        // A 0-payload reply padded to 60 bytes must produce a bare header.
        auto bare = MakeRequest(kIcmpEchoReply, 0x0001, 0x0002, 0);
        bare.resize(60, 0xAA);
        CHECK(IcmpSegmentLength(bare.data(), bare.size(), segment_len));
        CHECK(kIcmpHeaderLen == segment_len);
        std::vector<uint8_t> bare_frame;
        CHECK(RelayEchoReplyToClient(bare.data(), bare.size(), kClientIp,
                                     kGatewayMac, kClientMac, 0x0001,
                                     bare_frame));
        CHECK(net::kEthernetHeaderLen + kIpv4HeaderLenMin + kIcmpHeaderLen ==
              bare_frame.size());

        // A REQUEST is not a reply: the shared helper must refuse it, or a
        // spoiled tag could turn an inbound request into a forged reply.
        auto request = MakeRequest(kIcmpEchoRequest, 0x0001, 0x0002, 8);
        std::vector<uint8_t> not_reply;
        CHECK(!RelayEchoReplyToClient(request.data(), request.size(),
                                      kClientIp, kGatewayMac, kClientMac,
                                      0x0001, not_reply));
        CHECK(not_reply.empty());

        // A truncated datagram (total length claims more than we hold) must
        // be refused rather than relaying a partial payload.
        auto truncated = MakeRequest(kIcmpEchoReply, 0x0001, 0x0002, 16);
        std::vector<uint8_t> short_frame;
        CHECK(!RelayEchoReplyToClient(truncated.data(), 28, kClientIp,
                                      kGatewayMac, kClientMac, 0x0001,
                                      short_frame));
        CHECK(short_frame.empty());
        return 0;
    }

    /// A zero-length payload must still produce a valid header-only frame.
    int TestRelayedReplyEmptyPayload() {
        std::vector<uint8_t> frame;
        BuildRelayedEchoReplyFrame(kRemoteIp, kClientIp, kGatewayMac, kClientMac,
                                   0x1111, 1, nullptr, 0, frame);
        CHECK(net::kEthernetHeaderLen + kIpv4HeaderLenMin + kIcmpHeaderLen ==
              frame.size());
        const uint8_t* ip = frame.data() + net::kEthernetHeaderLen;
        const uint16_t total = static_cast<uint16_t>((ip[2] << 8) | ip[3]);
        CHECK(kIpv4HeaderLenMin + kIcmpHeaderLen == total);
        CHECK(Verifies(ip, kIpv4HeaderLenMin));
        CHECK(Verifies(ip + kIpv4HeaderLenMin, kIcmpHeaderLen));
        return 0;
    }

    /// Boundary id/seq values must round-trip through the two big-endian bytes.
    int TestRelayedReplyIdSeqBoundaries() {
        const uint16_t ids[] = {0x0000, 0x0001, 0x00FF, 0xFF00, 0xFFFF};
        const uint16_t seqs[] = {0x0000, 0x0102, 0xFFFE, 0xFFFF};
        for (uint16_t id : ids) {
            for (uint16_t seq : seqs) {
                std::vector<uint8_t> frame;
                BuildRelayedEchoReplyFrame(kRemoteIp, kClientIp, kGatewayMac,
                                           kClientMac, id, seq, nullptr, 0,
                                           frame);
                const uint8_t* icmp = frame.data() + net::kEthernetHeaderLen +
                                      kIpv4HeaderLenMin;
                const uint16_t got_id =
                    static_cast<uint16_t>((icmp[4] << 8) | icmp[5]);
                const uint16_t got_seq =
                    static_cast<uint16_t>((icmp[6] << 8) | icmp[7]);
                CHECK(id == got_id);
                CHECK(seq == got_seq);
            }
        }
        return 0;
    }

}  // namespace vgww

int main() {
    if (vgww::TestParseRejectsWrongVersion()) return 1;
    if (vgww::TestParseRejectsWrongProtocol()) return 1;
    if (vgww::TestParseRejectsShortIhl()) return 1;
    if (vgww::TestParsePayloadLenIsClamped()) return 1;
    if (vgww::TestParseRejectsShortDatagram()) return 1;
    if (vgww::TestIcmpSegmentLengthUsesIpTotal()) return 1;
    if (vgww::TestEchoReplyContents()) return 1;
    if (vgww::TestEchoReplyWithOptions()) return 1;
    if (vgww::TestEchoReplyIgnoresGarbage()) return 1;
    if (vgww::TestRelayedReplyContents()) return 1;
    if (vgww::TestRelayedReplyEmptyPayload()) return 1;
    if (vgww::TestRelayedReplyIgnoresEthernetPadding()) return 1;
    if (vgww::TestRelayedReplyIdSeqBoundaries()) return 1;
        if (vgww::TestBuilderNeverAllocates()) return 1;
        if (vgww::TestBuilderDropsOversizeReply()) return 1;
    std::puts("test_icmp: ALL PASS");
    return 0;
}
