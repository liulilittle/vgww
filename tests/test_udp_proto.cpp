// ============================================================================
// test_udp_proto.cpp - batch259: proto/udp.h had almost no instruction-level
// coverage. A 32-mutation sweep against the untouched implementation killed 2.
//
// The only two existing call sites never inspect the built frame:
//   * test_medium_fixes.cpp feeds a BuildUdpFrame output into the dataplane and
//     only checks that it was DROPPED (source-IP ban), so every header field
//     except the source address was free to change;
//   * test_arp_icmp.cpp pins exactly ONE byte pair (the RFC 8200 zero-checksum
//     promotion) and only when running under the arp_icmp target.
//
// This file asserts the COMPLETE wire image of both builders, field by field,
// and verifies both checksums by recomputing them from the emitted bytes.
// ============================================================================
#include "proto/udp.h"

#include "net/checksum.h"
#include "net/eth.h"

#include <cstdio>
#include <cstring>
#include <string>
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

    using vgww::net::kEthernetHeaderLen;
    using vgww::net::kEthertypeIpv4;
    using vgww::net::kEthertypeIpv6;
    using vgww::net::WireMac;
    using vgww::proto::BuildUdpFrame;
    using vgww::proto::BuildUdpFrameV6;
    using vgww::proto::kUdpHeaderLen;
    using vgww::proto::ParseUdp;
    using vgww::proto::UdpSegmentLengthV4;
    using vgww::proto::UdpSegmentLengthV6;
    using vgww::proto::UdpView;

    const WireMac kDstMac{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01};
    const WireMac kSrcMac{0x11, 0x22, 0x33, 0x44, 0x55, 0x66};

    // ===================== ParseUdp ========================================

    void TestParseUdpRejectsShortBuffers() {
        UdpView out;
        out.sport = 0xDEAD;  // must be untouched on failure
        const uint8_t seven[7] = {};
        CHECK(!ParseUdp(seven, 7, out));
        CHECK(out.sport == 0xDEAD);
        CHECK(!ParseUdp(nullptr, 0, out));
        CHECK(out.sport == 0xDEAD);
    }

    void TestParseUdpReadsBigEndianFields() {
        // sport=0x1234 dport=0x5678 length=0x9ABC checksum=0xDEF0
        const uint8_t hdr[8] = {0x12, 0x34, 0x56, 0x78,
                                0x9A, 0xBC, 0xDE, 0xF0};
        UdpView out;
        CHECK(ParseUdp(hdr, sizeof(hdr), out));
        CHECK(out.sport == 0x1234);
        CHECK(out.dport == 0x5678);
        CHECK(out.length == 0x9ABC);
    }

    void TestParseUdpAcceptsExactlyEightBytes() {
        const uint8_t hdr[8] = {0x00, 0x01, 0x00, 0x02, 0x00, 0x08, 0, 0};
        UdpView out;
        CHECK(ParseUdp(hdr, 8, out));  // 8 is the minimum, not excluded
        CHECK(out.sport == 1);
        CHECK(out.dport == 2);
        CHECK(out.length == 8);
    }

    void TestParseUdpToleratesATrailingPayload() {
        // Parsing must read only the first 8 bytes; a 20-byte buffer parses
        // the same header values.
        uint8_t buf[20] = {};
        buf[0] = 0xAB;
        buf[1] = 0xCD;
        buf[2] = 0x00;
        buf[3] = 0x35;
        buf[4] = 0x00;
        buf[5] = 0x14;
        UdpView out;
        CHECK(ParseUdp(buf, sizeof(buf), out));
        CHECK(out.sport == 0xABCD);
        CHECK(out.dport == 53);
        CHECK(out.length == 20);
    }

    // ===================== BuildUdpFrame (IPv4) ============================

    // Recomputes the IPv4 header checksum from the emitted bytes and checks it
    // folds to 0xFFFF (the standard "verify" trick).
    bool Ipv4ChecksumVerifies(const uint8_t* ip) {
        return vgww::net::InternetChecksum(ip, 20) == 0u;
    }

    // Recomputes the UDP checksum (pseudo-header + segment, checksum field
    // included) and checks it folds to 0xFFFF.
    bool UdpChecksumVerifiesV4(const uint8_t* ip) {
        const uint8_t* udp = ip + 20;
        const uint16_t udp_len =
            static_cast<uint16_t>((udp[4] << 8) | udp[5]);
        const uint32_t pseudo = vgww::net::PseudoHeaderSum(
            ip + 12, ip + 16, ip[9], udp_len);
        return vgww::net::InternetChecksum(udp, udp_len, pseudo) == 0u;
    }

    void TestBuildUdpFrameIpv4WireImage() {
        const uint8_t src_ip[4] = {192, 168, 1, 10};
        const uint8_t dst_ip[4] = {203, 0, 113, 7};
        const uint8_t payload[5] = {0xDE, 0xAD, 0xBE, 0xEF, 0x11};
        std::vector<uint8_t> frame;
        BuildUdpFrame(frame, kDstMac, kSrcMac, src_ip, 0x1234, dst_ip, 53,
                      payload, sizeof(payload));

        // ---- Ethernet header (14) ----
        CHECK(frame.size() == kEthernetHeaderLen + 20 + kUdpHeaderLen +
                                  sizeof(payload));
        for (size_t i = 0; i < 6; ++i) CHECK(frame[i] == kDstMac[i]);
        for (size_t i = 0; i < 6; ++i) CHECK(frame[6 + i] == kSrcMac[i]);
        CHECK(frame[12] == (kEthertypeIpv4 >> 8));
        CHECK(frame[13] == (kEthertypeIpv4 & 0xFF));

        const uint8_t* ip = frame.data() + kEthernetHeaderLen;
        // ---- IPv4 header (20) ----
        CHECK(ip[0] == 0x45);            // version 4, IHL 5 words
        CHECK(ip[1] == 0x00);            // DSCP/ECN
        // total length = 20 (IP) + 8 (UDP) + 5 (payload) = 33, read back
        // from the two emitted bytes so the check is not a constant compare.
        CHECK(static_cast<uint16_t>((ip[2] << 8) | ip[3]) == 33u);
        CHECK(ip[4] == 0 && ip[5] == 0); // identification
        CHECK(ip[6] == 0x40);            // DF
        CHECK(ip[7] == 0x00);            // fragment offset
        CHECK(ip[8] == 64);              // TTL
        CHECK(ip[9] == 17);              // protocol = UDP
        for (size_t i = 0; i < 4; ++i) CHECK(ip[12 + i] == src_ip[i]);
        for (size_t i = 0; i < 4; ++i) CHECK(ip[16 + i] == dst_ip[i]);
        CHECK(Ipv4ChecksumVerifies(ip));

        // ---- UDP header (8) ----
        const uint8_t* udp = ip + 20;
        CHECK(udp[0] == 0x12);           // sport 0x1234
        CHECK(udp[1] == 0x34);
        CHECK(udp[2] == 0x00);           // dport 53
        CHECK(udp[3] == 0x35);
        CHECK(static_cast<uint16_t>((udp[4] << 8) | udp[5]) == 13u);
        // ---- payload ----
        for (size_t i = 0; i < sizeof(payload); ++i) {
            CHECK(udp[kUdpHeaderLen + i] == payload[i]);
        }
        // ---- UDP checksum over the real bytes ----
        CHECK(UdpChecksumVerifiesV4(ip));
        // A UDP checksum of 0 would mean "no checksum" even in IPv4; the
        // pseudo-header makes that essentially impossible here, so just make
        // sure a non-zero value was actually written.
        CHECK(udp[6] != 0 || udp[7] != 0);
    }

    void TestBuildUdpFrameIpv4EmptyPayload() {
        const uint8_t src_ip[4] = {10, 0, 0, 1};
        const uint8_t dst_ip[4] = {10, 0, 0, 2};
        std::vector<uint8_t> frame;
        BuildUdpFrame(frame, kDstMac, kSrcMac, src_ip, 1, dst_ip, 2, nullptr,
                      0);
        CHECK(frame.size() == kEthernetHeaderLen + 20 + kUdpHeaderLen);
        const uint8_t* ip = frame.data() + kEthernetHeaderLen;
        CHECK(ip[2] == 0 && ip[3] == 28);  // 20 + 8
        const uint8_t* udp = ip + 20;
        CHECK(udp[4] == 0 && udp[5] == 8);
        CHECK(Ipv4ChecksumVerifies(ip));
        CHECK(UdpChecksumVerifiesV4(ip));
    }

    void TestBuildUdpFrameIpv4ReusesTheOutputBuffer() {
        // The builder must fully overwrite `out_frame` (resize + rewrite), so a
        // second, LARGER call leaves no stale bytes from the first.
        const uint8_t src_ip[4] = {1, 2, 3, 4};
        const uint8_t dst_ip[4] = {5, 6, 7, 8};
        std::vector<uint8_t> frame(200, 0xEE);  // pre-dirtied
        const uint8_t small[1] = {0x0A};
        BuildUdpFrame(frame, kDstMac, kSrcMac, src_ip, 10, dst_ip, 20, small,
                      sizeof(small));
        CHECK(frame.size() == kEthernetHeaderLen + 20 + kUdpHeaderLen + 1);

        const uint8_t big[4] = {1, 2, 3, 4};
        BuildUdpFrame(frame, kDstMac, kSrcMac, src_ip, 10, dst_ip, 20, big,
                      sizeof(big));
        CHECK(frame.size() == kEthernetHeaderLen + 20 + kUdpHeaderLen + 4);
        CHECK(Ipv4ChecksumVerifies(frame.data() + kEthernetHeaderLen));
    }

    void TestBuildUdpFrameIpv4ChecksumsChangeWithThePayload() {
        const uint8_t src_ip[4] = {192, 168, 1, 10};
        const uint8_t dst_ip[4] = {203, 0, 113, 7};
        const uint8_t a[4] = {1, 2, 3, 4};
        const uint8_t b[4] = {1, 2, 3, 5};  // one bit differs
        std::vector<uint8_t> fa, fb;
        BuildUdpFrame(fa, kDstMac, kSrcMac, src_ip, 1000, dst_ip, 2000, a, 4);
        BuildUdpFrame(fb, kDstMac, kSrcMac, src_ip, 1000, dst_ip, 2000, b, 4);
        const uint8_t* ua = fa.data() + kEthernetHeaderLen + 20;
        const uint8_t* ub = fb.data() + kEthernetHeaderLen + 20;
        CHECK(ua[6] != ub[6] || ua[7] != ub[7]);  // UDP checksum follows data
        CHECK(Ipv4ChecksumVerifies(fa.data() + kEthernetHeaderLen));
        CHECK(Ipv4ChecksumVerifies(fb.data() + kEthernetHeaderLen));
    }

    void TestBuildUdpFrameIpv4ChecksumFollowsThePorts() {
        // The pseudo-header covers ports only through the UDP segment; changing
        // a port MUST change the UDP checksum (and not the IPv4 one).
        const uint8_t src_ip[4] = {10, 1, 2, 3};
        const uint8_t dst_ip[4] = {10, 4, 5, 6};
        const uint8_t p[2] = {0xAA, 0xBB};
        std::vector<uint8_t> f1, f2;
        BuildUdpFrame(f1, kDstMac, kSrcMac, src_ip, 1111, dst_ip, 2222, p, 2);
        BuildUdpFrame(f2, kDstMac, kSrcMac, src_ip, 1111, dst_ip, 2223, p, 2);
        const uint8_t* ip1 = f1.data() + kEthernetHeaderLen;
        const uint8_t* ip2 = f2.data() + kEthernetHeaderLen;
        CHECK((ip1[20 + 6] != ip2[20 + 6]) ||
              (ip1[20 + 7] != ip2[20 + 7]));
        CHECK(ip1[10] == ip2[10] && ip1[11] == ip2[11]);  // IPv4 ck unchanged
        CHECK(UdpChecksumVerifiesV4(ip1));
        CHECK(UdpChecksumVerifiesV4(ip2));
    }

    // ===================== BuildUdpFrameV6 =================================

    bool UdpChecksumVerifiesV6(const uint8_t* ip) {
        const uint8_t* udp = ip + 40;
        const uint16_t udp_len = static_cast<uint16_t>((udp[4] << 8) | udp[5]);
        uint32_t pseudo = 0;
        const uint8_t* src = ip + 8;
        const uint8_t* dst = ip + 24;
        for (size_t i = 0; i < 16; i += 2) {
            pseudo += static_cast<uint32_t>((src[i] << 8) | src[i + 1]);
            pseudo += static_cast<uint32_t>((dst[i] << 8) | dst[i + 1]);
        }
        pseudo += static_cast<uint32_t>(udp_len);
        pseudo += 17;  // next header
        return vgww::net::InternetChecksum(udp, udp_len, pseudo) == 0u;
    }

    void TestBuildUdpFrameV6WireImage() {
        const uint8_t src[16] = {0xFE, 0x80, 0, 0, 0, 0, 0, 0,
                                 0,    0,    0, 0, 0, 0, 0, 0x01};
        const uint8_t dst[16] = {0xFF, 0x02, 0, 0, 0, 0, 0, 0,
                                 0,    0,    0, 0, 0, 0, 0, 0x02};
        const uint8_t payload[3] = {0x01, 0x02, 0x03};
        std::vector<uint8_t> frame;
        BuildUdpFrameV6(frame, kDstMac, kSrcMac, src, 0xABCD, dst, 0x0043,
                        payload, sizeof(payload));

        CHECK(frame.size() == kEthernetHeaderLen + 40 + kUdpHeaderLen +
                                  sizeof(payload));
        for (size_t i = 0; i < 6; ++i) CHECK(frame[i] == kDstMac[i]);
        for (size_t i = 0; i < 6; ++i) CHECK(frame[6 + i] == kSrcMac[i]);
        CHECK(frame[12] == (kEthertypeIpv6 >> 8));
        CHECK(frame[13] == (kEthertypeIpv6 & 0xFF));

        const uint8_t* ip = frame.data() + kEthernetHeaderLen;
        CHECK(ip[0] == 0x60);                     // version 6
        CHECK(ip[1] == 0 && ip[2] == 0 && ip[3] == 0);  // traffic class/flow
        const uint16_t plen =
            static_cast<uint16_t>(kUdpHeaderLen + sizeof(payload));
        CHECK(static_cast<uint16_t>((ip[4] << 8) | ip[5]) == 11u);
        CHECK(ip[6] == 17);                       // next header = UDP
        CHECK(ip[7] == 64);                       // hop limit
        for (size_t i = 0; i < 16; ++i) CHECK(ip[8 + i] == src[i]);
        for (size_t i = 0; i < 16; ++i) CHECK(ip[24 + i] == dst[i]);

        const uint8_t* udp = ip + 40;
        CHECK(udp[0] == 0xAB && udp[1] == 0xCD);  // sport
        CHECK(udp[2] == 0x00 && udp[3] == 0x43);  // dport 67
        CHECK(udp[4] == (plen >> 8) && udp[5] == (plen & 0xFF));
        for (size_t i = 0; i < sizeof(payload); ++i) {
            CHECK(udp[kUdpHeaderLen + i] == payload[i]);
        }
        CHECK(UdpChecksumVerifiesV6(ip));
    }

    void TestBuildUdpFrameV6EmptyPayload() {
        const uint8_t src[16] = {};
        const uint8_t dst[16] = {};
        std::vector<uint8_t> frame;
        BuildUdpFrameV6(frame, kDstMac, kSrcMac, src, 1, dst, 2, nullptr, 0);
        CHECK(frame.size() == kEthernetHeaderLen + 40 + kUdpHeaderLen);
        const uint8_t* ip = frame.data() + kEthernetHeaderLen;
        CHECK(ip[4] == 0 && ip[5] == 8);
        const uint8_t* udp = ip + 40;
        CHECK(udp[4] == 0 && udp[5] == 8);
        CHECK(UdpChecksumVerifiesV6(ip));
    }

    void TestBuildUdpFrameV6ZeroFillsTheHeader() {
        // The IPv6 builder uses assign(..., 0): every byte it does not
        // explicitly set must be 0, never leftover from a previous frame.
        const uint8_t src[16] = {1};
        const uint8_t dst[16] = {2};
        std::vector<uint8_t> frame(400, 0xEE);
        BuildUdpFrameV6(frame, kDstMac, kSrcMac, src, 1, dst, 2, nullptr, 0);
        CHECK(frame.size() == kEthernetHeaderLen + 40 + kUdpHeaderLen);
        const uint8_t* ip = frame.data() + kEthernetHeaderLen;
        CHECK(ip[1] == 0 && ip[2] == 0 && ip[3] == 0);
        CHECK(ip[8 + 1] == 0 && ip[8 + 15] == 0);   // address tail zero
        CHECK(ip[24 + 1] == 0 && ip[24 + 15] == 0);
    }

    void TestBuildUdpFrameV6ChecksumFollowsThePayload() {
        const uint8_t src[16] = {0xFE, 0x80};
        const uint8_t dst[16] = {0xFF, 0x02};
        const uint8_t a[2] = {0x11, 0x22};
        const uint8_t b[2] = {0x11, 0x23};
        std::vector<uint8_t> fa, fb;
        BuildUdpFrameV6(fa, kDstMac, kSrcMac, src, 100, dst, 200, a, 2);
        BuildUdpFrameV6(fb, kDstMac, kSrcMac, src, 100, dst, 200, b, 2);
        const uint8_t* ua = fa.data() + kEthernetHeaderLen + 40;
        const uint8_t* ub = fb.data() + kEthernetHeaderLen + 40;
        CHECK(ua[6] != ub[6] || ua[7] != ub[7]);
        CHECK(UdpChecksumVerifiesV6(fa.data() + kEthernetHeaderLen));
        CHECK(UdpChecksumVerifiesV6(fb.data() + kEthernetHeaderLen));
    }

    void TestBuildUdpFrameV6ChecksumFollowsTheAddresses() {
        // The IPv6 pseudo-header is a 16-bit SUM over both addresses, so
        // swapping src and dst cannot change the checksum (addition commutes).
        // What MUST change it is altering one address word, so pin BOTH: the
        // invariance (a property of the pseudo-header) and the sensitivity
        // (the addresses really are summed in).
        const uint8_t src[16] = {0xFE, 0x80, 0, 0, 0, 0, 0, 0,
                                 0,    0,    0, 0, 0, 0, 0, 1};
        const uint8_t dst[16] = {0xFF, 0x02, 0, 0, 0, 0, 0, 0,
                                 0,    0,    0, 0, 0, 0, 0, 1};
        const uint8_t p[4] = {1, 2, 3, 4};
        std::vector<uint8_t> f1, f2;
        BuildUdpFrameV6(f1, kDstMac, kSrcMac, src, 53, dst, 5353, p, 4);
        BuildUdpFrameV6(f2, kDstMac, kSrcMac, dst, 53, src, 5353, p, 4);
        const uint8_t* u1 = f1.data() + kEthernetHeaderLen + 40;
        const uint8_t* u2 = f2.data() + kEthernetHeaderLen + 40;
        CHECK(u1[6] == u2[6] && u1[7] == u2[7]);  // order-invariant
        CHECK(UdpChecksumVerifiesV6(f1.data() + kEthernetHeaderLen));
        CHECK(UdpChecksumVerifiesV6(f2.data() + kEthernetHeaderLen));

        // One changed byte in the DESTINATION address must move the checksum.
        uint8_t dst2[16];
        std::memcpy(dst2, dst, sizeof(dst2));
        dst2[15] ^= 0x01;
        std::vector<uint8_t> f3;
        BuildUdpFrameV6(f3, kDstMac, kSrcMac, src, 53, dst2, 5353, p, 4);
        const uint8_t* u3 = f3.data() + kEthernetHeaderLen + 40;
        CHECK(u1[6] != u3[6] || u1[7] != u3[7]);
        CHECK(UdpChecksumVerifiesV6(f3.data() + kEthernetHeaderLen));

        // Same for the SOURCE address.
        uint8_t src2[16];
        std::memcpy(src2, src, sizeof(src2));
        src2[15] ^= 0x02;
        std::vector<uint8_t> f4;
        BuildUdpFrameV6(f4, kDstMac, kSrcMac, src2, 53, dst, 5353, p, 4);
        const uint8_t* u4 = f4.data() + kEthernetHeaderLen + 40;
        CHECK(u1[6] != u4[6] || u1[7] != u4[7]);
        CHECK(UdpChecksumVerifiesV6(f4.data() + kEthernetHeaderLen));
    }

    void TestBuildUdpFrameV6PromotesAZeroChecksum() {
        // RFC 8200 section 8.1: a computed 0 must be emitted as 0xFFFF (a
        // transmitted 0 means "no checksum", which is illegal in IPv6).
        // This exact (addresses, ports, payload) tuple is the one already
        // pinned by test_arp_icmp.cpp: the folded pseudo-header + segment sum
        // lands on 0xFFFF, i.e. the computed checksum is 0.
        const uint8_t src[16] = {
            0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01};
        const uint8_t dst[16] = {
            0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01};
        const uint8_t payload[] = {0xED, 0x36};
        std::vector<uint8_t> frame;
        BuildUdpFrameV6(frame, kDstMac, kSrcMac, src, 53, dst, 5353, payload,
                        sizeof(payload));
        const uint8_t* udp = frame.data() + kEthernetHeaderLen + 40;
        CHECK(udp[6] == 0xFF);
        CHECK(udp[7] == 0xFF);
        // And the emitted (promoted) field still verifies.
        CHECK(UdpChecksumVerifiesV6(frame.data() + kEthernetHeaderLen));
    }

    // ===================== datagram length helpers =========================

    // Builds an IPv4 datagram of `ip_len` bytes (starting at the IP header,
    // no Ethernet) whose IHL nibble and total-length field are caller-set;
    // every byte starts as 0xAA so a leak of buffer bytes is visible.
    std::vector<uint8_t> MakeV4Datagram(size_t ip_len, uint8_t ihl_words,
                                        size_t total_len,
                                        uint8_t version = 4) {
        std::vector<uint8_t> d(ip_len, 0xAA);
        d[0] = static_cast<uint8_t>((version << 4) | (ihl_words & 0x0F));
        d[2] = static_cast<uint8_t>((total_len >> 8) & 0xFF);
        d[3] = static_cast<uint8_t>(total_len & 0xFF);
        d[9] = 17;  // UDP
        return d;
    }

    std::vector<uint8_t> MakeV6Packet(size_t ip_len, size_t payload_len,
                                      uint8_t version = 6) {
        std::vector<uint8_t> d(ip_len, 0xAA);
        d[0] = static_cast<uint8_t>(version << 4);
        d[4] = static_cast<uint8_t>((payload_len >> 8) & 0xFF);
        d[5] = static_cast<uint8_t>(payload_len & 0xFF);
        d[6] = 17;  // UDP
        return d;
    }

    void TestUdpSegmentLengthV4UsesTheIpTotalLength() {
        size_t hdr = 0;
        size_t seg = 0;
        // A 0-payload UDP datagram is 28 bytes and the link pads the frame
        // to the 60-byte minimum: the capture holds 46 bytes after the MAC
        // header, but the datagram ends at 28.
        auto bare = MakeV4Datagram(46, 5, 28);
        CHECK(UdpSegmentLengthV4(bare.data(), bare.size(), hdr, seg));
        CHECK(hdr == 20);
        CHECK(seg == 8);  // NOT 26 (the padding)

        auto padded = MakeV4Datagram(60, 5, 44);
        CHECK(UdpSegmentLengthV4(padded.data(), padded.size(), hdr, seg));
        CHECK(hdr == 20);
        CHECK(seg == 24);  // 8 header + 16 payload, not 40

        // IHL 6 (24-byte header with options) + 8-byte UDP header.
        auto options = MakeV4Datagram(60, 6, 32);
        CHECK(UdpSegmentLengthV4(options.data(), options.size(), hdr, seg));
        CHECK(hdr == 24);
        CHECK(seg == 8);
    }

    void TestUdpSegmentLengthV4RejectsMalformed() {
        size_t hdr = 0;
        size_t seg = 0;
        auto no_l4 = MakeV4Datagram(28, 5, 20);  // total ends at the IP header
        CHECK(!UdpSegmentLengthV4(no_l4.data(), no_l4.size(), hdr, seg));
        auto zero_total = MakeV4Datagram(28, 5, 0);
        CHECK(!UdpSegmentLengthV4(zero_total.data(), zero_total.size(), hdr, seg));
        auto ihl_zero = MakeV4Datagram(28, 0, 28);
        CHECK(!UdpSegmentLengthV4(ihl_zero.data(), ihl_zero.size(), hdr, seg));
        auto ihl_past_end = MakeV4Datagram(28, 15, 32);  // 60-byte header
        CHECK(!UdpSegmentLengthV4(ihl_past_end.data(), ihl_past_end.size(), hdr,
                                  seg));
        auto v6 = MakeV4Datagram(28, 5, 28, 6);
        CHECK(!UdpSegmentLengthV4(v6.data(), v6.size(), hdr, seg));
        auto short_buffer = MakeV4Datagram(19, 5, 19);
        CHECK(!UdpSegmentLengthV4(short_buffer.data(), short_buffer.size(), hdr,
                                  seg));
        CHECK(!UdpSegmentLengthV4(nullptr, 0, hdr, seg));
    }

    void TestUdpSegmentLengthV4ToleratesAShortCapture() {
        size_t hdr = 0;
        size_t seg = 0;
        // The datagram claims more than the capture holds: deliver what we
        // have, never bytes beyond the capture.
        auto truncated = MakeV4Datagram(28, 5, 100);
        CHECK(UdpSegmentLengthV4(truncated.data(), truncated.size(), hdr, seg));
        CHECK(hdr == 20);
        CHECK(seg == 8);
    }

    void TestUdpSegmentLengthV6UsesThePayloadLength() {
        size_t seg = 0;
        auto bare = MakeV6Packet(48, 8);
        CHECK(UdpSegmentLengthV6(bare.data(), bare.size(), seg));
        CHECK(seg == 8);
        // A capture that extends past the declared payload must not widen
        // the datagram: this is the IPv6 form of the padding leak.
        auto overlong = MakeV6Packet(60, 8);
        CHECK(UdpSegmentLengthV6(overlong.data(), overlong.size(), seg));
        CHECK(seg == 8);  // NOT 20
        auto big = MakeV6Packet(1500, 1400);
        CHECK(UdpSegmentLengthV6(big.data(), big.size(), seg));
        CHECK(seg == 1400);
    }

    void TestUdpSegmentLengthV6RejectsMalformed() {
        size_t seg = 0;
        auto no_l4 = MakeV6Packet(48, 0);  // payload length 0: jumbogram only
        CHECK(!UdpSegmentLengthV6(no_l4.data(), no_l4.size(), seg));
        auto short_udp = MakeV6Packet(48, 7);
        CHECK(!UdpSegmentLengthV6(short_udp.data(), short_udp.size(), seg));
        auto v4 = MakeV6Packet(48, 8, 4);
        CHECK(!UdpSegmentLengthV6(v4.data(), v4.size(), seg));
        auto short_buffer = MakeV6Packet(39, 8);
        CHECK(!UdpSegmentLengthV6(short_buffer.data(), short_buffer.size(), seg));
        CHECK(!UdpSegmentLengthV6(nullptr, 0, seg));
    }

    void TestUdpSegmentLengthV6ToleratesAShortCapture() {
        size_t seg = 0;
        auto truncated = MakeV6Packet(48, 100);
        CHECK(UdpSegmentLengthV6(truncated.data(), truncated.size(), seg));
        CHECK(seg == 8);
    }

}  // namespace

int main() {
    TestParseUdpRejectsShortBuffers();
    TestParseUdpReadsBigEndianFields();
    TestParseUdpAcceptsExactlyEightBytes();
    TestParseUdpToleratesATrailingPayload();

    TestUdpSegmentLengthV4UsesTheIpTotalLength();
    TestUdpSegmentLengthV4RejectsMalformed();
    TestUdpSegmentLengthV4ToleratesAShortCapture();
    TestUdpSegmentLengthV6UsesThePayloadLength();
    TestUdpSegmentLengthV6RejectsMalformed();
    TestUdpSegmentLengthV6ToleratesAShortCapture();

    TestBuildUdpFrameIpv4WireImage();
    TestBuildUdpFrameIpv4EmptyPayload();
    TestBuildUdpFrameIpv4ReusesTheOutputBuffer();
    TestBuildUdpFrameIpv4ChecksumsChangeWithThePayload();
    TestBuildUdpFrameIpv4ChecksumFollowsThePorts();

    TestBuildUdpFrameV6WireImage();
    TestBuildUdpFrameV6EmptyPayload();
    TestBuildUdpFrameV6ZeroFillsTheHeader();
    TestBuildUdpFrameV6ChecksumFollowsThePayload();
    TestBuildUdpFrameV6ChecksumFollowsTheAddresses();
    TestBuildUdpFrameV6PromotesAZeroChecksum();

    if (0 == g_failures) {
        std::puts("test_udp_proto: ALL PASS");
        return 0;
    }
    std::fprintf(stderr, "test_udp_proto: %d FAILURES\n", g_failures);
    return 1;
}
