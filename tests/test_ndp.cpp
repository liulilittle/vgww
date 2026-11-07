// ============================================================================
// test_ndp.cpp - Router Advertisement frame layout per RFC 4861.
//
// Regression: the prefix-information option was written at offset 12 instead
// of 16 with a zero preferred lifetime - SLAAC clients derived a wrong subnet
// and immediately deprecated addresses (IPv6 control plane was unusable).
// ============================================================================
#define CHECK(cond)                                                        \
    do {                                                                   \
        if (!(cond)) {                                                     \
            std::fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, \
                         __LINE__, #cond);                                 \
            return 1;                                                      \
        }                                                                  \
    } while (0)

#include "proto/ndp.h"
#include "net/checksum.h"

#include <array>
#include <cstdio>
#include <vector>

namespace vgww {
    /// TestRaManagedOtherFlags: main mode serves addresses, so the RA must
    /// advertise M=1 (managed address config) and O=1 (other config); pure
    /// SLAAC stays at M=O=0 (RFC 4861 section 4.2).
    static int TestRaManagedOtherFlags() {
        const net::WireMac gw_mac{0x02, 0x00, 0x5A, 0xDE, 0xAD, 0xBE};
        const uint8_t ll_addr[16] = {
            0xFE, 0x80, 0, 0, 0, 0, 0, 0,
            0x00, 0x02, 0x5A, 0xFF, 0xFE, 0xDE, 0xAD, 0xBE};
        const uint8_t prefix[16] = {
            0xFD, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0, 0, 0, 0, 0, 0, 0, 0};
        const std::vector<std::array<uint8_t, 16>> dns{
            {0xFD, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
             0, 0, 0, 0, 0, 0, 0, 0x53}};

        std::vector<uint8_t> managed;
        proto::BuildRouterAdvertisementFrame(gw_mac, ll_addr, prefix, 64,
                                             1800, true, true, 1500, dns,
                                             managed);
        const uint8_t* icmp = managed.data() + net::kEthernetHeaderLen + 40;
        CHECK(icmp[5] == 0xC0);  // M=1 O=1

        std::vector<uint8_t> slaac;
        proto::BuildRouterAdvertisementFrame(gw_mac, ll_addr, prefix, 64,
                                             1800, false, false, 1500, dns,
                                             slaac);
        const uint8_t* icmp2 = slaac.data() + net::kEthernetHeaderLen + 40;
        CHECK(icmp2[5] == 0x00);  // M=0 O=0
        return 0;
    }

    /// TestRdnssLifetimeNonZero: RFC 8106 says a zero Lifetime means the
    /// client MUST NOT use the advertised resolver, so the option has to
    /// carry a real lifetime (the RA router lifetime, default 1800 s).
    static int TestRdnssLifetimeNonZero() {
        const net::WireMac gw_mac{0x02, 0x00, 0x5A, 0xDE, 0xAD, 0xBE};
        const uint8_t ll_addr[16] = {
            0xFE, 0x80, 0, 0, 0, 0, 0, 0,
            0x00, 0x02, 0x5A, 0xFF, 0xFE, 0xDE, 0xAD, 0xBE};
        const uint8_t prefix[16] = {
            0xFD, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0, 0, 0, 0, 0, 0, 0, 0};
        const std::vector<std::array<uint8_t, 16>> dns{
            {0xFD, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
             0, 0, 0, 0, 0, 0, 0, 0x53}};  // fd00:1122:3344:5566::53

        std::vector<uint8_t> ra;
        proto::BuildRouterAdvertisementFrame(gw_mac, ll_addr, prefix, 64,
                                             1800, false, false, 1500, dns, ra);
        // Layout: RA header 16 + prefix 32 + MTU 8 -> RDNSS at icmp+56.
        const uint8_t* icmp = ra.data() + net::kEthernetHeaderLen + 40;
        const uint8_t* rdnss = icmp + 56;
        CHECK(rdnss[0] == 25);
        CHECK(rdnss[1] == 3);  // 1 + 2*1 server
        const uint32_t lifetime =
            (static_cast<uint32_t>(rdnss[4]) << 24) |
            (static_cast<uint32_t>(rdnss[5]) << 16) |
            (static_cast<uint32_t>(rdnss[6]) << 8) |
            static_cast<uint32_t>(rdnss[7]);
        CHECK(lifetime == 1800);
        return 0;
    }

    int RunTests() {
        const net::WireMac gw_mac{0x02, 0x00, 0x5A, 0xDE, 0xAD, 0xBE};
        // ULA fd00:1122:3344:5566:: (network order on the wire).
        const uint8_t ll_addr[16] = {
            0xFE, 0x80, 0, 0, 0, 0, 0, 0,
            0x00, 0x02, 0x5A, 0xFF, 0xFE, 0xDE, 0xAD, 0xBE};
        const uint8_t prefix[16] = {
            0xFD, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0, 0, 0, 0, 0, 0, 0, 0};

        std::vector<uint8_t> frame;
        constexpr uint32_t kMtu = 1500;
        const std::vector<std::array<uint8_t, 16>> no_dns;
        proto::BuildRouterAdvertisementFrame(gw_mac, ll_addr, prefix, 64,
                                             1800, false, false, kMtu, no_dns,
                                             frame);

        // Frame = Ethernet(14) + IPv6(40) + ICMPv6 RA body(64):
        //   RA header 16 + prefix option 32 + MTU option 8 + SLLA option 8.
        CHECK(frame.size() == net::kEthernetHeaderLen + 40 + 64);

        const uint8_t* ip = frame.data() + net::kEthernetHeaderLen;
        const uint16_t payload_len =
            static_cast<uint16_t>((ip[4] << 8) | ip[5]);
        CHECK(payload_len == 64);
        CHECK(ip[6] == 58);   // ICMPv6
        CHECK(ip[7] == 255);  // router packets: hop limit 255

        const uint8_t* icmp = ip + 40;
        CHECK(icmp[0] == proto::kIcmpV6RouterAdvertisement);
        CHECK(icmp[4] == 64);  // cur hop limit advertised to clients
        CHECK(icmp[5] == 0x00);  // M=0 O=0: pure SLAAC, no Prf bits
        const uint16_t router_lifetime =
            static_cast<uint16_t>((icmp[6] << 8) | icmp[7]);
        CHECK(router_lifetime == 1800);
        CHECK(payload_len == 64);  // ICMP body length echoed in IPv6 header

        // IPv6 destination must be ff02::1 (all-nodes multicast): every host
        // on the link must receive the RA (regression: fe02::0 is not a
        // multicast group hosts join, so SLAAC never worked).
        const uint8_t* dst = ip + 24;
        const uint8_t kAllNodes[16] = {
            0xFF, 0x02, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0x01};
        CHECK(0 == std::memcmp(dst, kAllNodes, 16));

        // Prefix information option at icmp+16 (type 3, 32 bytes long).
        const uint8_t* opt = icmp + 16;
        CHECK(opt[0] == 3);
        CHECK(opt[1] == 4);           // 4 units of 8 bytes = 32
        CHECK(opt[2] == 64);          // prefix length
        CHECK(opt[3] == 0xC0);        // L=1 A=1 (SLAAC autonomous)

        // Valid AND preferred lifetimes must both be non-zero (24 h here).
        const auto read32 = [&opt](size_t at) {
            return (static_cast<uint32_t>(opt[at]) << 24) |
                   (static_cast<uint32_t>(opt[at + 1]) << 16) |
                   (static_cast<uint32_t>(opt[at + 2]) << 8) |
                   static_cast<uint32_t>(opt[at + 3]);
        };
        CHECK(read32(4) == 86400);   // valid lifetime
        CHECK(read32(8) == 86400);   // preferred lifetime (was 0!)

        // The advertised prefix must be byte-exact at offset 16..31.
        for (size_t i = 0; i < 16; ++i) {
            if (opt[16 + i] != prefix[i]) {
                std::fprintf(stderr,
                             "prefix mismatch at %zu: %02x != %02x\n", i,
                             opt[16 + i], prefix[i]);
                return 1;
            }
        }

        // MTU option at icmp+48 (type 5, one unit, value 1500).
        const uint8_t* mtu_opt = icmp + 48;
        CHECK(mtu_opt[0] == 5);
        CHECK(mtu_opt[1] == 1);
        const uint32_t mtu = (static_cast<uint32_t>(mtu_opt[4]) << 24) |
                             (static_cast<uint32_t>(mtu_opt[5]) << 16) |
                             (static_cast<uint32_t>(mtu_opt[6]) << 8) |
                             static_cast<uint32_t>(mtu_opt[7]);
        CHECK(mtu == 1500);

        // Source link-layer address option follows at icmp+56.
        const uint8_t* llopt = icmp + 56;
        CHECK(llopt[0] == 1);
        CHECK(llopt[1] == 1);
        CHECK(0 == std::memcmp(llopt + 2, gw_mac.data(), 6));

        // Checksum must verify to zero over the pseudo-header + segment.
        const uint32_t pseudo =
            net::PseudoHeaderSum6(ip + 8, ip + 24, 58, payload_len);
        const uint16_t ck = net::InternetChecksum(icmp, payload_len, pseudo);
        CHECK(ck == 0);

        // ---- RDNSS option (RFC 8106, type 25) ----
        // No DNS configured: frame layout is byte-identical to before (the
        // no-RDNSS compatibility case is the checks above).
        // Order after MTU: prefix(16..47) MTU(48..55) [RDNSS] SLLA(tail).
        const std::array<uint8_t, 16> dns1 = {
            0xFD, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0, 0, 0, 0, 0, 0, 0, 0x53};  // fd00:1122:3344:5566::53
        const std::array<uint8_t, 16> dns2 = {
            0xFE, 0x80, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0x0A};  // fe80::a
        std::vector<std::array<uint8_t, 16>> three{dns1, dns2,
                                                     {0x20, 0x01, 0x0D, 0xB8, 0, 0,
                                                      0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}};
        std::vector<uint8_t> ra_rdnss;
        proto::BuildRouterAdvertisementFrame(gw_mac, ll_addr, prefix, 64,
                                             1800, false, false, kMtu, three,
                                             ra_rdnss);
        // 16 header + 32 prefix + 8 MTU + 56 RDNSS(3 addrs) + 8 SLLA = 120.
        CHECK(ra_rdnss.size() == net::kEthernetHeaderLen + 40 + 120);

        const uint8_t* icmp3 = ra_rdnss.data() + net::kEthernetHeaderLen + 40;
        const uint16_t plen3 = static_cast<uint16_t>(
            (ra_rdnss.data()[net::kEthernetHeaderLen + 4] << 8) |
            ra_rdnss.data()[net::kEthernetHeaderLen + 5]);
        CHECK(plen3 == 120);
        // RDNSS option at icmp+56 (type 25, len = 1 + 2*3 = 7 units of 8).
        const uint8_t* rdnss = icmp3 + 56;
        CHECK(rdnss[0] == 25);
        CHECK(rdnss[1] == 7);
        // Addresses in wire order, contiguous after reserved(2)+lifetime(4).
        for (size_t i = 0; i < 3; ++i) {
            const std::array<uint8_t, 16>& srv = three[i];
            for (size_t j = 0; j < 16; ++j) {
                if (rdnss[8 + i * 16 + j] != srv[j]) {
                    std::fprintf(stderr,
                                 "rdnss addr %zu byte %zu: %02x != %02x\n", i,
                                 j, rdnss[8 + i * 16 + j], srv[j]);
                    return 1;
                }
            }
        }
        // SLLA now follows the RDNSS block at icmp+112.
        const uint8_t* slla = icmp3 + 112;
        CHECK(slla[0] == 1);
        CHECK(slla[1] == 1);
        CHECK(0 == std::memcmp(slla + 2, gw_mac.data(), 6));
        // Checksum over the longer body must still verify.
        const uint32_t pseudo3 =
            net::PseudoHeaderSum6(ra_rdnss.data() + net::kEthernetHeaderLen + 8,
                                  ra_rdnss.data() + net::kEthernetHeaderLen + 24,
                                  58, plen3);
        CHECK(net::InternetChecksum(icmp3, plen3, pseudo3) == 0);

        // A single-DNS RA must place RDNSS before SLLA (len = 3 units).
        std::vector<std::array<uint8_t, 16>> one{dns1};
        std::vector<uint8_t> ra_one;
        proto::BuildRouterAdvertisementFrame(gw_mac, ll_addr, prefix, 64,
                                             1800, false, false, kMtu, one,
                                             ra_one);
        CHECK(ra_one.size() == net::kEthernetHeaderLen + 40 + 88);
        const uint8_t* icmp1 = ra_one.data() + net::kEthernetHeaderLen + 40;
        const uint8_t* rdnss1 = icmp1 + 56;
        CHECK(rdnss1[0] == 25 && rdnss1[1] == 3);
        const uint8_t* slla1 = icmp1 + 80;
        CHECK(slla1[0] == 1 && slla1[1] == 1);

        // More than 3 servers must clamp to 3 (identical to the `three`
        // layout): the option is never truncated mid-address.
        std::vector<std::array<uint8_t, 16>> five{three};
        five.push_back(dns1);
        five.push_back(dns2);
        std::vector<uint8_t> ra_five;
        proto::BuildRouterAdvertisementFrame(gw_mac, ll_addr, prefix, 64,
                                             1800, false, false, kMtu, five,
                                             ra_five);
        CHECK(ra_five.size() == ra_rdnss.size());
        const uint8_t* icmp5 = ra_five.data() + net::kEthernetHeaderLen + 40;
        const uint8_t* rdnss5 = icmp5 + 56;
        CHECK(rdnss5[0] == 25 && rdnss5[1] == 7);
        for (size_t i = 0; i < 3; ++i) {
            CHECK(0 == std::memcmp(rdnss5 + 8 + i * 16, three[i].data(), 16));
        }

        // ---- Neighbor Solicitation probe (re-learning a stale v6 client) ----
        // RFC 4861 section 4.3: type 135, solicited-node multicast destination
        // ff02::1:ffXX:XXXX (lower 24 bits of the target), SLLA option.
        const uint8_t target[16] = {
            0xFD, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0, 0, 0, 0, 0x00, 0x00, 0xAB, 0xCD};  // ..:abcd last 24 bits
        std::vector<uint8_t> ns;
        proto::BuildNeighborSolicitationFrame(target, gw_mac, ll_addr, ns);
        CHECK(ns.size() == net::kEthernetHeaderLen + 40 + 32);  // 24+8 SLLA
        // Ethernet: solicited-node multicast MAC 33:33:ff:00:ab:cd (last 24
        // bits of the target = target bytes 13..15).
        CHECK(ns[0] == 0x33 && ns[1] == 0x33 && ns[2] == 0xFF);
        CHECK(ns[3] == 0x00 && ns[4] == 0xAB && ns[5] == 0xCD);
        // IPv6 dst = ff02::1:ffab:cd, next header 58.
        const uint8_t* ns_ip = ns.data() + net::kEthernetHeaderLen;
        CHECK(ns_ip[6] == 58 && ns_ip[7] == 255);
        CHECK(ns_ip[24] == 0xFF && ns_ip[25] == 0x02);
        CHECK(ns_ip[36] == 0x01 && ns_ip[37] == 0xFF && ns_ip[38] == 0xAB &&
              ns_ip[39] == 0xCD);
        CHECK(0 == std::memcmp(ns_ip + 8, ll_addr, 16));
        const uint16_t ns_plen = static_cast<uint16_t>((ns_ip[4] << 8) | ns_ip[5]);
        CHECK(ns_plen == 32);
        // ICMPv6 type 135 + target echo + SLLA option (type 1).
        const uint8_t* nsi = ns_ip + 40;
        CHECK(nsi[0] == 135);
        CHECK(0 == std::memcmp(nsi + 8, target, 16));
        CHECK(nsi[24] == 1 && nsi[25] == 1);
        CHECK(0 == std::memcmp(nsi + 26, gw_mac.data(), 6));
        // Checksum over the pseudo-header must verify.
        const uint32_t ns_pseudo = net::PseudoHeaderSum6(
            ns_ip + 8, ns_ip + 24, 58, ns_plen);
        CHECK(net::InternetChecksum(nsi, ns_plen, ns_pseudo) == 0);

        std::fprintf(stderr, "ndp: all checks passed\n");
        return 0;
    }

    /// batch34v: BuildEchoReplyV6Frame must bound its copy by the caller's
    /// buffer length, not by the attacker-controlled payload_len field in the
    /// IPv6 header. request_len says how many bytes are actually readable;
    /// payload_len only says how many the SENDER CLAIMED. Trusting the claim
    /// makes the function read past the caller's buffer (OOB read) and emit a
    /// reply built from adjacent memory.
    ///
    /// The frame below is a real 48-byte header (40 IPv6 + 8 ICMPv6) whose
    /// payload_len claims 65535. A function that honours request_len produces
    /// no reply at all; one that trusts payload_len copies 65575 bytes.
    static int TestEchoReplyV6RejectsLyingPayloadLen() {
        std::vector<uint8_t> request(48, 0);
        request[0] = 0x60;                       // version 6
        request[4] = 0xFF;                       // payload_len hi
        request[5] = 0xFF;                       // payload_len lo = 65535
        request[6] = 58;                         // next header: ICMPv6
        request[7] = 64;                         // hop limit
        for (size_t i = 0; i < 16; ++i) {        // src ::1
            request[8 + i] = 0;
        }
        request[23] = 0x01;
        const uint8_t gateway[16] = {            // dst = our link-local
            0xFE, 0x80, 0, 0, 0, 0, 0, 0,
            0x00, 0x02, 0x5A, 0xFF, 0xFE, 0xDE, 0xAD, 0xBE};
        for (size_t i = 0; i < 16; ++i) {
            request[24 + i] = gateway[i];
        }
        request[40] = 128;                       // ICMPv6 echo request

        const net::WireMac gw_mac{0x02, 0x00, 0x5A, 0xDE, 0xAD, 0xBE};
        const net::WireMac client_mac{0x02, 0x00, 0x00, 0x00, 0x00, 0x99};

        std::vector<uint8_t> reply;
        reply.push_back(0xAA);                   // sentinel: must stay untouched
        proto::BuildEchoReplyV6Frame(request.data(), request.size(), gw_mac,
                                     client_mac, reply);
        // Nothing to echo: the declared length does not fit the buffer.
        CHECK(reply.size() == 1);
        CHECK(reply[0] == 0xAA);

        // Sanity: a truthful length still produces the reply.
        request[4] = 0x00;
        request[5] = 0x08;                       // payload_len = 8 (ICMPv6 hdr)
        std::vector<uint8_t> ok_reply;
        proto::BuildEchoReplyV6Frame(request.data(), request.size(), gw_mac,
                                     client_mac, ok_reply);
        CHECK(ok_reply.size() == net::kEthernetHeaderLen + 40 + 8);
        const uint8_t* ok_ip = ok_reply.data() + net::kEthernetHeaderLen;
        CHECK(ok_ip[40] == 129);                 // echo reply
        // Addresses swapped: reply dst is the original src (::1).
        CHECK(0 == std::memcmp(ok_ip + 24, request.data() + 8, 16));

        std::fprintf(stderr, "ndp echo reply: bounds checks passed\n");
        return 0;
    }

    /// batch125: the batch34v guard bounded payload_len from ABOVE only.
    /// BuildEchoReplyV6Frame sizes out_frame as 14 + 40 + payload_len and then
    /// writes icmp[0..3] at ip+40 unconditionally, so payload_len < 4 (the
    /// ICMPv6 header is 4 bytes: type, code, checksum) leaves icmp pointing at
    /// or past the end of the vector and the four stores run OFF the buffer -
    /// a heap overflow reachable from the wire. A zero-length ICMPv6 payload is
    /// legal on the wire (RFC 4443 does not forbid an empty body), so the
    /// upper-bound-only check was not enough.
    ///
    /// Note the ASan-style proof: out_frame is a vector, so writing past it is
    /// detected here by keeping the reply at its capacity and asserting the
    /// function produced NO reply (it must refuse a too-short ICMPv6 segment
    /// rather than fabricating a 0-byte-body one).
    static int TestEchoReplyV6RejectsShortIcmpBody() {
        for (uint16_t bad : {uint16_t(0), uint16_t(1), uint16_t(2),
                             uint16_t(3)}) {
            std::vector<uint8_t> request(44, 0);  // 40 hdr + 4 readable
            request[0] = 0x60;                   // version 6
            request[4] = static_cast<uint8_t>(bad >> 8);
            request[5] = static_cast<uint8_t>(bad & 0xFF);
            request[6] = 58;                     // ICMPv6
            request[7] = 64;
            request[23] = 0x01;                  // src ::1
            const uint8_t gateway[16] = {
                0xFE, 0x80, 0, 0, 0, 0, 0, 0,
                0x00, 0x02, 0x5A, 0xFF, 0xFE, 0xDE, 0xAD, 0xBE};
            for (size_t i = 0; i < 16; ++i) {
                request[24 + i] = gateway[i];
            }
            const net::WireMac gw_mac{0x02, 0x00, 0x5A, 0xDE, 0xAD, 0xBE};
            const net::WireMac client_mac{0x02, 0x00, 0x00, 0x00, 0x00, 0x99};

            std::vector<uint8_t> reply;
            reply.push_back(0xAA);               // sentinel stays untouched
            proto::BuildEchoReplyV6Frame(request.data(), request.size(),
                                         gw_mac, client_mac, reply);
            // A malformed (too short) ICMPv6 segment must produce nothing.
            CHECK(reply.size() == 1);
            CHECK(reply[0] == 0xAA);
        }

        // Positive control: exactly 4 bytes (header only, empty body) is the
        // smallest legal ICMPv6 echo and must still be answered.
        std::vector<uint8_t> request(44, 0);
        request[0] = 0x60;
        request[4] = 0x00;
        request[5] = 0x04;                       // payload_len = 4
        request[6] = 58;
        request[7] = 64;
        request[23] = 0x01;
        const uint8_t gateway[16] = {
            0xFE, 0x80, 0, 0, 0, 0, 0, 0,
            0x00, 0x02, 0x5A, 0xFF, 0xFE, 0xDE, 0xAD, 0xBE};
        for (size_t i = 0; i < 16; ++i) {
            request[24 + i] = gateway[i];
        }
        request[40] = 128;                       // echo request
        const net::WireMac gw_mac2{0x02, 0x00, 0x5A, 0xDE, 0xAD, 0xBE};
        const net::WireMac client_mac2{0x02, 0x00, 0x00, 0x00, 0x00, 0x99};
        std::vector<uint8_t> ok_reply;
        proto::BuildEchoReplyV6Frame(request.data(), request.size(), gw_mac2,
                                     client_mac2, ok_reply);
        CHECK(ok_reply.size() == net::kEthernetHeaderLen + 40 + 4);
        const uint8_t* ok_ip = ok_reply.data() + net::kEthernetHeaderLen;
        CHECK(ok_ip[40] == 129);                 // echo reply

        std::fprintf(stderr, "ndp echo reply: short-body guard passed\n");
        return 0;
    }
}  // namespace vgww

int main() {
    if (0 != vgww::TestRaManagedOtherFlags()) {
        return 1;
    }
    if (0 != vgww::TestRdnssLifetimeNonZero()) {
        return 1;
    }
    if (0 != vgww::TestEchoReplyV6RejectsLyingPayloadLen()) {
        return 1;
    }
    if (0 != vgww::TestEchoReplyV6RejectsShortIcmpBody()) {
        return 1;
    }
    return vgww::RunTests();
}
