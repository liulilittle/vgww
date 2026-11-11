// ============================================================================
// test_classifier.cpp - Frame classification + symmetric flow hashing.
//
// Frames are built synthetically (eth+ip+l4) so every byte is known; the
// symmetry assertion encodes the design invariant "both directions of one
// conversation MUST land on the same worker" (design spec section 4).
// ============================================================================
#include "dsp/classifier.h"

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

    using vgww::dsp::ClassifyFrame;
    using vgww::dsp::FrameClass;
    using vgww::dsp::FrameView;
    using vgww::dsp::SymmetricFlowHash;
    using vgww::net::BuildEthHeader;
    using vgww::net::WireMac;

    void PushU16(std::vector<uint8_t>& v, uint16_t x) {
        v.push_back(static_cast<uint8_t>(x >> 8));
        v.push_back(static_cast<uint8_t>(x & 0xFF));
    }

    /// Builds eth + IPv4 + L4 frame. `proto`: 1=ICMP 6=TCP 17=UDP.
    std::vector<uint8_t> BuildV4Frame(const uint8_t src[4], const uint8_t dst[4],
                                      uint16_t l4sport, uint16_t l4dport,
                                      uint8_t proto, size_t payload) {
        std::vector<uint8_t> f;
        f.reserve(vgww::net::kEthernetHeaderLen + 20 + (proto == 1 ? 0 : 8) + payload);
        const WireMac dstmac{0x30, 0xFC, 0x68, 0x88, 0xB4, 0xA9};
        const WireMac srcmac{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01};
        f.insert(f.end(), dstmac.begin(), dstmac.end());
        f.insert(f.end(), srcmac.begin(), srcmac.end());
        PushU16(f, 0x0800);

        const uint16_t total = static_cast<uint16_t>(20 + (proto == 1 ? 0 : 8) + payload);
        f.push_back(0x45);                    // version 4, IHL 5
        f.push_back(0x00);                    // DSCP
        PushU16(f, total);
        PushU16(f, 0x1234);                   // id
        PushU16(f, 0x4000);                   // flags DF
        f.push_back(64);                      // TTL
        f.push_back(proto);
        PushU16(f, 0);                        // checksum (not validated here)
        f.insert(f.end(), src, src + 4);
        f.insert(f.end(), dst, dst + 4);
        if (6 == proto || 17 == proto) {
            PushU16(f, l4sport);
            PushU16(f, l4dport);
        }
        f.insert(f.end(), payload, 0xAB);
        return f;
    }

    inline constexpr uint8_t kClientIp[4] = {192, 168, 0, 101};
    inline constexpr uint8_t kServerIp[4] = {93, 184, 216, 34};

    /// Builds eth + IPv6 fixed-header + UDP frame. `next_header` is 17=UDP.
    /// Header layout matches the classifier/parser: payload length at ip[4..5],
    /// next header ip[6], hop limit ip[7], src ip[8..23], dst ip[24..39].
    std::vector<uint8_t> BuildV6UdpFrame(const uint8_t src[16],
                                         const uint8_t dst[16],
                                         uint16_t sport, uint16_t dport,
                                         size_t payload = 16) {
        std::vector<uint8_t> f;
        f.reserve(vgww::net::kEthernetHeaderLen + 40 + 8 + payload);
        const WireMac dstmac{0x33, 0x33, 0x00, 0x00, 0x00, 0x01};
        const WireMac srcmac{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01};
        f.insert(f.end(), dstmac.begin(), dstmac.end());
        f.insert(f.end(), srcmac.begin(), srcmac.end());
        PushU16(f, 0x86DD);                       // ethertype IPv6
        f.push_back(0x60);                        // version 6
        f.push_back(0x00);                        // tc/flow label (hi)
        PushU16(f, 0);                            // flow label (lo)
        PushU16(f, 0);                            // payload length (set below)
        f.push_back(17);                          // next header: UDP
        f.push_back(64);                          // hop limit
        f.insert(f.end(), src, src + 16);
        f.insert(f.end(), dst, dst + 16);
        PushU16(f, sport);
        PushU16(f, dport);
        PushU16(f, static_cast<uint16_t>(8 + payload));
        PushU16(f, 0);                            // checksum (not validated)
        f.insert(f.end(), payload, 0xCD);
        const uint16_t plen = static_cast<uint16_t>(8 + payload);
        f[18] = static_cast<uint8_t>(plen >> 8);
        f[19] = static_cast<uint8_t>(plen & 0xFF);
        return f;
    }

    void TestTcpClassification() {
        auto frame = BuildV4Frame(kClientIp, kServerIp, 51000, 443, 6, 64);
        FrameView view;
        CHECK(ClassifyFrame(frame.data(), frame.size(), view));
        CHECK(FrameClass::kTcpV4 == view.cls);
        CHECK(view.src_port == 51000);
        CHECK(view.dst_port == 443);
        CHECK(view.ip_proto == 6);
        CHECK(view.l4_offset == vgww::net::kEthernetHeaderLen + 20);
    }

    void TestDhcpClassification() {
        auto frame = BuildV4Frame(kClientIp, kServerIp, 68, 67, 17, 300);
        FrameView view;
        CHECK(ClassifyFrame(frame.data(), frame.size(), view));
        CHECK(FrameClass::kDhcpV4 == view.cls);
    }

    void TestUdpAndIcmp() {
        auto udp = BuildV4Frame(kClientIp, kServerIp, 5300, 53, 17, 32);
        FrameView view;
        CHECK(ClassifyFrame(udp.data(), udp.size(), view));
        CHECK(FrameClass::kUdpV4 == view.cls);
        CHECK(view.dst_port == 53);

        auto icmp = BuildV4Frame(kClientIp, kServerIp, 0, 0, 1, 16);
        CHECK(ClassifyFrame(icmp.data(), icmp.size(), view));
        CHECK(FrameClass::kIcmpV4 == view.cls);
        // Symmetric with the v6 case in TestV6L4Classes: ICMP has no ports, so
        // its type/code/checksum bytes are never a four-tuple. Reading them
        // made src_port/dst_port carry the checksum, which differs per ping,
        // so SymmetricFlowHash scattered ONE conversation across workers.
        CHECK(0 == view.src_port);
        CHECK(0 == view.dst_port);
    }

    void TestMulticastAndBroadcast() {
        // IPv4 multicast / limited broadcast must NOT be NATed as unicast:
        // SSDP (239.255.255.250:1900) and NetBIOS (137/138) leak to the
        // uplink and never answer. They go to the host path (kOther).
        const uint8_t kMc[4] = {239, 255, 255, 250};
        const uint8_t kBc[4] = {255, 255, 255, 255};
        const uint8_t kUni[4] = {192, 168, 0, 99};
        const uint8_t kClient[4] = {192, 168, 0, 10};
        const uint8_t kZero[4] = {0, 0, 0, 0};
        FrameView view;

        auto mcast = BuildV4Frame(kClient, kMc, 51000, 1900, 17, 8);
        CHECK(ClassifyFrame(mcast.data(), mcast.size(), view));
        CHECK(FrameClass::kOther == view.cls);

        auto bcast = BuildV4Frame(kClient, kBc, 51000, 138, 17, 8);
        CHECK(ClassifyFrame(bcast.data(), bcast.size(), view));
        CHECK(FrameClass::kOther == view.cls);

        auto mcast_icmp = BuildV4Frame(kClient, kMc, 0, 0, 1, 8);
        CHECK(ClassifyFrame(mcast_icmp.data(), mcast_icmp.size(), view));
        CHECK(FrameClass::kOther == view.cls);

        // DHCP to 255.255.255.255:67 stays kDhcpV4 (it is the one legitimate
        // broadcast that the special case above must never hijack).
        auto dhcp = BuildV4Frame(kZero, kBc, 68, 67, 17, 240);
        CHECK(ClassifyFrame(dhcp.data(), dhcp.size(), view));
        CHECK(FrameClass::kDhcpV4 == view.cls);

        // Unicast UDP to 224/4-less addresses is untouched.
        auto uni = BuildV4Frame(kClient, kUni, 51000, 53, 17, 8);
        CHECK(ClassifyFrame(uni.data(), uni.size(), view));
        CHECK(FrameClass::kUdpV4 == view.cls);
    }

    void TestV4FragmentMf() {
        // First fragment of an IPv4 UDP/ICMP datagram (MF=1, offset=0) must
        // NOT be relayed as a complete datagram: the offset-high bits are zero
        // and only the MF bit (byte 6, 0x20) reveals it. Classify to kOther
        // (host path), mirroring an offset != 0 fragment.
        const uint8_t kDst[4] = {93, 184, 216, 34};
        FrameView view;
        {
            auto udp = BuildV4Frame(kClientIp, kDst, 51000, 53, 17, 32);
            udp[vgww::net::kEthernetHeaderLen + 6] = 0x20;  // MF=1, offset=0
            CHECK(ClassifyFrame(udp.data(), udp.size(), view));
            CHECK(FrameClass::kOther == view.cls);
        }
        {
            auto icmp = BuildV4Frame(kClientIp, kDst, 0, 0, 1, 16);
            icmp[vgww::net::kEthernetHeaderLen + 6] = 0x20;  // MF=1, offset=0
            CHECK(ClassifyFrame(icmp.data(), icmp.size(), view));
            CHECK(FrameClass::kOther == view.cls);
        }
        // A true first fragment with a NON-zero offset is already caught.
        {
            auto udp = BuildV4Frame(kClientIp, kDst, 51000, 53, 17, 32);
            udp[vgww::net::kEthernetHeaderLen + 6] = 0x21;  // MF + offset bit0
            CHECK(ClassifyFrame(udp.data(), udp.size(), view));
            CHECK(FrameClass::kOther == view.cls);
        }
    }

    void TestV6MulticastIsolation() {
        // IPv6 multicast UDP (mDNS ff02::fb:5353) must be isolated like its
        // v4 counterpart: the relay would otherwise NAT a group as unicast
        // and leak it to the uplink. bytes[0]==0xFF marks the v6 multicast
        // group (ff00::/8).
        const uint8_t src[16] = {0xFE, 0x80, 0, 0, 0, 0, 0, 0,
                                 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x01};
        const uint8_t kMdns[16] = {0xFF, 0x02, 0, 0, 0, 0, 0, 0,
                                   0, 0, 0, 0, 0, 0, 0, 0xFB};
        FrameView view;
        auto m = BuildV6UdpFrame(src, kMdns, 53000, 5353, 16);
        CHECK(ClassifyFrame(m.data(), m.size(), view));
        CHECK(FrameClass::kOther == view.cls);

        // Unicast v6 UDP stays relayable.
        const uint8_t kUni[16] = {0x20, 0x01, 0x48, 0x60, 0, 0, 0, 0,
                                  0, 0, 0, 0, 0, 0, 0, 0x34};
        auto u = BuildV6UdpFrame(src, kUni, 53000, 443, 16);
        CHECK(ClassifyFrame(u.data(), u.size(), view));
        CHECK(FrameClass::kUdpV6 == view.cls);

        // DHCPv6 Solicit to ff02::1:2 (ports 546/547) is the ONE legitimate
        // v6 multicast: the DHCPv6 upgrade must run BEFORE the multicast
        // isolation so kDhcpV6 is never diverted to kOther.
        const uint8_t kDhcp6Mcast[16] = {0xFF, 0x02, 0, 0, 0, 0, 0, 0,
                                         0, 0, 0, 0, 0, 0, 0x01, 0x02};
        auto d = BuildV6UdpFrame(src, kDhcp6Mcast, 546, 547, 64);
        CHECK(ClassifyFrame(d.data(), d.size(), view));
        CHECK(FrameClass::kDhcpV6 == view.cls);
    }

    void TestArpAndShortFrames() {
        std::vector<uint8_t> arp(14 + 28, 0);
        arp[12] = 0x08;
        arp[13] = 0x06;
        FrameView view;
        CHECK(ClassifyFrame(arp.data(), arp.size(), view));
        CHECK(FrameClass::kArp == view.cls);

        CHECK(!ClassifyFrame(arp.data(), 10, view));  // too short
    }

    /// batch34u: the L4 header must be bounded by the IPv4 TOTAL LENGTH, not
    /// by the received frame length. A 60-byte Ethernet minimum frame pads a
    /// short datagram with trailing bytes; reading ports out of that padding
    /// invents a four-tuple the sender never wrote, which can misclassify the
    /// frame (padding "ports" of 67/68 turn plain UDP into DHCPv4) and perturbs
    /// the flow hash that pins a conversation to one worker.
    ///
    /// The frame below declares total_len = 20 (header only, no L4 payload)
    /// yet arrives 60 bytes long, exactly like a minimum-size Ethernet frame.
    void TestPortsBoundedByIpTotalLength() {
        std::vector<uint8_t> f;
        const WireMac dstmac{0x30, 0xFC, 0x68, 0x88, 0xB4, 0xA9};
        const WireMac srcmac{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01};
        f.insert(f.end(), dstmac.begin(), dstmac.end());
        f.insert(f.end(), srcmac.begin(), srcmac.end());
        PushU16(f, 0x0800);
        f.push_back(0x45);   // version 4, IHL 5
        f.push_back(0x00);
        PushU16(f, 20);      // total length: header only, NO L4 bytes
        PushU16(f, 0x1234);  // id
        PushU16(f, 0x4000);  // DF
        f.push_back(64);     // TTL
        f.push_back(17);     // UDP
        PushU16(f, 0);
        f.insert(f.end(), kClientIp, kClientIp + 4);
        f.insert(f.end(), kServerIp, kServerIp + 4);
        // Padding that must never be read as a UDP header. 67/68 would
        // otherwise be promoted to DHCPv4.
        PushU16(f, 67);
        PushU16(f, 68);
        while (f.size() < 60) {
            f.push_back(0x00);
        }

        FrameView view;
        CHECK(ClassifyFrame(f.data(), f.size(), view));
        CHECK(FrameClass::kUdpV4 == view.cls);   // NOT kDhcpV4
        CHECK(0 == view.src_port);               // no invented four-tuple
        CHECK(0 == view.dst_port);
    }

    /// The same rule for a genuinely truncated L4 header: total_len says the
    /// datagram ends one byte into the UDP source port, so no port pair exists.
    void TestPartialL4HeaderNotRead() {
        auto f = BuildV4Frame(kClientIp, kServerIp, 67, 68, 17, 0);
        // total_len = 20 (IP) + 8 (UDP) in the builder; shrink it to 21 so
        // only one byte of the UDP header is inside the datagram.
        f[16] = 0;
        f[17] = 21;
        FrameView view;
        CHECK(ClassifyFrame(f.data(), f.size(), view));
        CHECK(FrameClass::kUdpV4 == view.cls);  // ports unknown, still UDP
        CHECK(0 == view.src_port);
        CHECK(0 == view.dst_port);
    }

    void TestSymmetricHash() {
        auto a = BuildV4Frame(kClientIp, kServerIp, 51000, 443, 6, 16);
        auto b = BuildV4Frame(kServerIp, kClientIp, 443, 51000, 6, 16);  // true reverse
        FrameView va, vb;
        CHECK(ClassifyFrame(a.data(), a.size(), va));
        CHECK(ClassifyFrame(b.data(), b.size(), vb));
        for (uint64_t salt = 0; salt < 8; ++salt) {
            CHECK(SymmetricFlowHash(va, salt) == SymmetricFlowHash(vb, salt));
        }
        // Different flows should (over many salts) spread - spot check that
        // two distinct flows differ for the default salt.
        auto c = BuildV4Frame(kClientIp, kServerIp, 51001, 443, 6, 16);
        FrameView vc;
        CHECK(ClassifyFrame(c.data(), c.size(), vc));
        CHECK(SymmetricFlowHash(va) != SymmetricFlowHash(vc));
    }

    /// Builds eth + IPv6 fixed header with an arbitrary next-header byte, so
    /// every L4 class the classifier claims can be reached. TCP/UDP get ports.
    std::vector<uint8_t> BuildV6Frame(const uint8_t src[16],
                                      const uint8_t dst[16],
                                      uint8_t next_header, uint16_t sport,
                                      uint16_t dport, size_t payload = 16) {
        std::vector<uint8_t> f;
        const WireMac dstmac{0x33, 0x33, 0x00, 0x00, 0x00, 0x01};
        const WireMac srcmac{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01};
        f.insert(f.end(), dstmac.begin(), dstmac.end());
        f.insert(f.end(), srcmac.begin(), srcmac.end());
        PushU16(f, 0x86DD);
        f.push_back(0x60);
        f.push_back(0x00);
        PushU16(f, 0);
        PushU16(f, 0);                    // payload length (set below)
        f.push_back(next_header);
        f.push_back(64);
        f.insert(f.end(), src, src + 16);
        f.insert(f.end(), dst, dst + 16);
        const bool has_ports = (6 == next_header || 17 == next_header);
        if (has_ports) {
            PushU16(f, sport);
            PushU16(f, dport);
            PushU16(f, 0);                // checksum
        }
        f.insert(f.end(), payload, 0xCD);
        const uint16_t plen = static_cast<uint16_t>(
            (has_ports ? 8 : 4) + payload);
        f[18] = static_cast<uint8_t>(plen >> 8);
        f[19] = static_cast<uint8_t>(plen & 0xFF);
        return f;
    }

    inline constexpr uint8_t kV6Client[16] = {0x20, 0x01, 0x48, 0x60, 0, 0, 0, 0,
                                              0, 0, 0, 0, 0, 0, 0x00, 0x01};
    inline constexpr uint8_t kV6Server[16] = {0x20, 0x01, 0x48, 0x60, 0, 0, 0, 0,
                                              0, 0, 0, 0, 0, 0, 0x00, 0x02};

    /// batch270: the IPv6 L4 class switch. `kIcmpV6` and `kTcpV6` had ZERO
    /// assertions in this file, so a wrong class or a dropped port read would
    /// have gone unnoticed.
    void TestV6L4Classes() {
        // ICMPv6 (58): returns EARLY, before ParseL4Ports, so no ports.
        {
            auto f = BuildV6Frame(kV6Client, kV6Server, 58, 0, 0);
            FrameView v;
            CHECK(ClassifyFrame(f.data(), f.size(), v));
            CHECK(FrameClass::kIcmpV6 == v.cls);
            CHECK(0 == v.src_port);
            CHECK(0 == v.dst_port);
        }
        // TCPv6 (6): ports are read exactly like UDP.
        {
            auto f = BuildV6Frame(kV6Client, kV6Server, 6, 51000, 443);
            FrameView v;
            CHECK(ClassifyFrame(f.data(), f.size(), v));
            CHECK(FrameClass::kTcpV6 == v.cls);
            CHECK(51000 == v.src_port);
            CHECK(443 == v.dst_port);
        }
        // UDPv6 (17) stays kUdpV6 on an arbitrary port pair.
        {
            auto f = BuildV6Frame(kV6Client, kV6Server, 17, 5353, 53);
            FrameView v;
            CHECK(ClassifyFrame(f.data(), f.size(), v));
            CHECK(FrameClass::kUdpV6 == v.cls);
            CHECK(5353 == v.src_port);
            CHECK(53 == v.dst_port);
        }
        // An unknown next header is kOther and returns before port parsing.
        {
            auto f = BuildV6Frame(kV6Client, kV6Server, 47, 0, 0);
            FrameView v;
            CHECK(ClassifyFrame(f.data(), f.size(), v));
            CHECK(FrameClass::kOther == v.cls);
            CHECK(0 == v.src_port);
        }
        // DHCPv6 matches when EITHER endpoint carries 546/547. Each arm is
        // exercised ALONE (the peer port is 9999), because a {546,547} pair
        // in both directions cannot distinguish "dst only" from "either
        // endpoint" - a regression to `dst_port == 546 || dst_port == 547`
        // would still pass.
        {
            const uint16_t pairs[][2] = {
                {546, 9999}, {547, 9999},   // client/server port on the SOURCE
                {9999, 546}, {9999, 547},   // ... on the DESTINATION
                {546, 547},  {547, 546}};   // the real handshake pairs
            for (const auto& p : pairs) {
                auto f = BuildV6Frame(kV6Client, kV6Server, 17, p[0], p[1]);
                FrameView v;
                CHECK(ClassifyFrame(f.data(), f.size(), v));
                CHECK(FrameClass::kDhcpV6 == v.cls);
            }
            // Neither port in {546,547} stays plain UDPv6. (546/548 would
            // still hit the src==546 arm - the four comparisons are an OR
            // over both endpoints.)
            auto f = BuildV6Frame(kV6Client, kV6Server, 17, 548, 549);
            FrameView v;
            CHECK(ClassifyFrame(f.data(), f.size(), v));
            CHECK(FrameClass::kUdpV6 == v.cls);
        }
    }

    /// batch270: IPv4 header-shape rejections that were never constructed.
    void TestV4HeaderRejections() {
        // IHL < 5 (here 4 => 16-byte header) must be rejected even though the
        // frame is long enough. With IHL 5 accepted, a regression to
        // `ihl < 4` would mis-parse.
        {
            auto f = BuildV4Frame(kClientIp, kServerIp, 1234, 80, 6, 16);
            f[vgww::net::kEthernetHeaderLen] = 0x44;  // version 4, IHL 4
            FrameView v;
            CHECK(!ClassifyFrame(f.data(), f.size(), v));
        }
        // Version 5 with an otherwise valid IHL is rejected.
        {
            auto f = BuildV4Frame(kClientIp, kServerIp, 1234, 80, 6, 16);
            f[vgww::net::kEthernetHeaderLen] = 0x55;  // version 5, IHL 5
            FrameView v;
            CHECK(!ClassifyFrame(f.data(), f.size(), v));
        }
        // IHL 6 (24-byte header) is ACCEPTED and moves l4_offset by 4.
        {
            auto f = BuildV4Frame(kClientIp, kServerIp, 1234, 80, 6, 16);
            const size_t ip0 = vgww::net::kEthernetHeaderLen;
            f[ip0] = 0x46;  // version 4, IHL 6
            // Slide the L4 header four bytes later by inserting a word after
            // the fixed 20 bytes, and grow total length to match.
            f.insert(f.begin() + static_cast<long>(ip0 + 20), {0, 0, 0, 0});
            const uint16_t new_total = static_cast<uint16_t>(
                ((f[ip0 + 2] << 8) | f[ip0 + 3]) + 4);
            f[ip0 + 2] = static_cast<uint8_t>(new_total >> 8);
            f[ip0 + 3] = static_cast<uint8_t>(new_total & 0xFF);
            FrameView v;
            CHECK(ClassifyFrame(f.data(), f.size(), v));
            CHECK(FrameClass::kTcpV4 == v.cls);
            CHECK(v.l4_offset == vgww::net::kEthernetHeaderLen + 24);
            CHECK(1234 == v.src_port);
            CHECK(80 == v.dst_port);
        }
        // An IPv4 protocol the classifier does not model (47 = GRE) is
        // kOther, and no ports are invented.
        {
            auto f = BuildV4Frame(kClientIp, kServerIp, 0, 0, 47, 16);
            FrameView v;
            CHECK(ClassifyFrame(f.data(), f.size(), v));
            CHECK(FrameClass::kOther == v.cls);
            CHECK(0 == v.src_port);
            CHECK(0 == v.dst_port);
        }
        // An unknown ethertype is kOther without touching the IP header.
        {
            auto f = BuildV4Frame(kClientIp, kServerIp, 1234, 80, 6, 16);
            f[12] = 0x88;  // ethertype 0x88CC (LLDP)
            f[13] = 0xCC;
            FrameView v;
            CHECK(ClassifyFrame(f.data(), f.size(), v));
            CHECK(FrameClass::kOther == v.cls);
            CHECK(0 == v.src_port);
        }
    }

    /// batch270: SymmetricFlowHash normalises by (ip, then port). When both
    /// endpoints share an IP the PORT decides the order, and that tie-break
    /// had no test: a regression to `dst_port <= src_port` (or comparing only
    /// IPs) would make the two directions hash differently.
    void TestSymmetricHashSameIpTieBreak() {
        const uint8_t same[4] = {10, 0, 0, 7};
        // Same IP, ports swapped between the two directions.
        auto a = BuildV4Frame(same, same, 40000, 40001, 17, 16);
        auto b = BuildV4Frame(same, same, 40001, 40000, 17, 16);
        FrameView va, vb;
        CHECK(ClassifyFrame(a.data(), a.size(), va));
        CHECK(ClassifyFrame(b.data(), b.size(), vb));
        CHECK(va.src_ip == va.dst_ip);
        for (uint64_t salt = 0; salt < 4; ++salt) {
            CHECK(SymmetricFlowHash(va, salt) == SymmetricFlowHash(vb, salt));
        }
        // Same IP AND same port on both ends: still deterministic.
        auto c = BuildV4Frame(same, same, 40002, 40002, 17, 16);
        FrameView vc;
        CHECK(ClassifyFrame(c.data(), c.size(), vc));
        CHECK(SymmetricFlowHash(vc, 0) == SymmetricFlowHash(vc, 0));
        // Distinct ports must not collide for the default salt.
        CHECK(SymmetricFlowHash(va) != SymmetricFlowHash(vc));
    }

    /// batch270: the hash must actually depend on every input it claims to
    /// mix. Changing ONLY the protocol or ONLY the salt has to change the
    /// result; a hash that ignored them would still be symmetric and would
    /// pass every assertion above.
    void TestSymmetricHashSensitivity() {
        auto tcp = BuildV4Frame(kClientIp, kServerIp, 51000, 443, 6, 16);
        auto udp = BuildV4Frame(kClientIp, kServerIp, 51000, 443, 17, 16);
        FrameView v6, v17;
        CHECK(ClassifyFrame(tcp.data(), tcp.size(), v6));
        CHECK(ClassifyFrame(udp.data(), udp.size(), v17));
        CHECK(v6.ip_proto != v17.ip_proto);
        CHECK(SymmetricFlowHash(v6, 0) != SymmetricFlowHash(v17, 0));
        CHECK(SymmetricFlowHash(v6, 0) != SymmetricFlowHash(v6, 1));
        CHECK(SymmetricFlowHash(v6, 1) != SymmetricFlowHash(v6, 2));
        // A different source address changes the hash.
        const uint8_t other[4] = {192, 168, 0, 102};
        auto moved = BuildV4Frame(other, kServerIp, 51000, 443, 6, 16);
        FrameView vm;
        CHECK(ClassifyFrame(moved.data(), moved.size(), vm));
        CHECK(SymmetricFlowHash(v6, 3) != SymmetricFlowHash(vm, 3));
    }

    /// batch270: the same-v4-multicast filter has to cover ICMP and TCP too,
    /// not just UDP. Only the UDP case was asserted before.
    void TestV4MulticastForAllL4Classes() {
        const uint8_t group[4] = {224, 0, 0, 251};
        for (uint8_t proto : {static_cast<uint8_t>(1), static_cast<uint8_t>(6),
                              static_cast<uint8_t>(17)}) {
            auto f = BuildV4Frame(kClientIp, group, 5353, 1900, proto, 16);
            FrameView v;
            CHECK(ClassifyFrame(f.data(), f.size(), v));
            CHECK(FrameClass::kOther == v.cls);
        }
        // 224/4 is the multicast block: 223 must NOT divert, 224 must.
        {
            const uint8_t edge[4] = {223, 255, 255, 255};
            auto f = BuildV4Frame(kClientIp, edge, 1234, 80, 6, 16);
            FrameView v;
            CHECK(ClassifyFrame(f.data(), f.size(), v));
            CHECK(FrameClass::kTcpV4 == v.cls);
        }
        {
            const uint8_t edge[4] = {224, 0, 0, 0};
            auto f = BuildV4Frame(kClientIp, edge, 1234, 80, 6, 16);
            FrameView v;
            CHECK(ClassifyFrame(f.data(), f.size(), v));
            CHECK(FrameClass::kOther == v.cls);
        }
        // 239 is the LAST multicast octet; 240 starts class E (reserved) and
        // must NOT be diverted. Sampling only 223/224 lets a mask widened to
        // 0xE0 (which also matches 240..255) pass.
        {
            const uint8_t last[4] = {239, 255, 255, 255};
            auto f = BuildV4Frame(kClientIp, last, 1234, 80, 6, 16);
            FrameView v;
            CHECK(ClassifyFrame(f.data(), f.size(), v));
            CHECK(FrameClass::kOther == v.cls);
        }
        {
            const uint8_t first_e[4] = {240, 0, 0, 1};
            auto f = BuildV4Frame(kClientIp, first_e, 1234, 80, 6, 16);
            FrameView v;
            CHECK(ClassifyFrame(f.data(), f.size(), v));
            CHECK(FrameClass::kTcpV4 == v.cls);
        }
    }

    /// batch270: IPv6 multicast isolation. Only UDPv6 was asserted before.
    ///
    /// ICMPv6 is deliberately EXCLUDED from the diversion: it returns at
    /// classifier.cpp:161 BEFORE the group filter at :217, so it keeps
    /// kIcmpV6 even when the destination is ff02::/8. That is the intended
    /// contract (the dataplane answers RS/NS/echo on the local IPv6 control
    /// path), so the `FrameClass::kIcmpV6 == out.cls` operand inside that
    /// `||` chain is UNREACHABLE - recorded as architecture debt, not
    /// asserted as a defect (rerouting it would break NDP).
    void TestV6MulticastForAllL4Classes() {
        const uint8_t group[16] = {0xFF, 0x02, 0, 0, 0, 0, 0, 0,
                                   0, 0, 0, 0, 0, 0, 0, 0x01};
        // TCPv6 and UDPv6 ARE diverted to the host path.
        for (uint8_t nh : {static_cast<uint8_t>(6), static_cast<uint8_t>(17)}) {
            auto f = BuildV6Frame(kV6Client, group, nh, 1234, 80);
            FrameView v;
            CHECK(ClassifyFrame(f.data(), f.size(), v));
            CHECK(FrameClass::kOther == v.cls);
        }
        // ICMPv6 to a group address keeps its class (early return).
        {
            auto f = BuildV6Frame(kV6Client, group, 58, 0, 0);
            FrameView v;
            CHECK(ClassifyFrame(f.data(), f.size(), v));
            CHECK(FrameClass::kIcmpV6 == v.cls);
        }
        // 0xFE is the last non-multicast first octet.
        {
            uint8_t edge[16] = {0xFE, 0x80, 0, 0, 0, 0, 0, 0,
                                0, 0, 0, 0, 0, 0, 0, 0x01};
            auto f = BuildV6Frame(kV6Client, edge, 17, 1234, 80);
            FrameView v;
            CHECK(ClassifyFrame(f.data(), f.size(), v));
            CHECK(FrameClass::kUdpV6 == v.cls);
        }
    }
}  // namespace

int main() {
    TestTcpClassification();
    TestDhcpClassification();
    TestUdpAndIcmp();
    TestArpAndShortFrames();
    TestMulticastAndBroadcast();
    TestV4FragmentMf();
    TestV6MulticastIsolation();
    TestPortsBoundedByIpTotalLength();
    TestPartialL4HeaderNotRead();
    TestSymmetricHash();
    TestV6L4Classes();
    TestV4HeaderRejections();
    TestSymmetricHashSameIpTieBreak();
    TestSymmetricHashSensitivity();
    TestV4MulticastForAllL4Classes();
    TestV6MulticastForAllL4Classes();
    if (0 == g_failures) {
        std::puts("test_classifier: ALL PASS");
        return 0;
    }
    std::fprintf(stderr, "test_classifier: %d FAILURES\n", g_failures);
    return 1;
}
