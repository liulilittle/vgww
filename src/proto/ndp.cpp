// ============================================================================
// ndp.cpp - NDP control-plane implementation.
// ============================================================================
#include "proto/ndp.h"

#include <algorithm>

namespace vgww {
    namespace proto {

        namespace {
            // IPv6 fixed header is 40 bytes; ICMPv6 header 4 bytes.
            inline constexpr size_t kIpv6HeaderLen = 40;
            inline constexpr size_t kIcmpV6HeaderLen = 4;
        }  // namespace

        std::array<uint8_t, 16> LinkLocalFromMac(const net::WireMac& mac) noexcept {
            std::array<uint8_t, 16> addr{};
            addr[0] = 0xFE;
            addr[1] = 0x80;
            // EUI-64 IID: MAC[0] with U/L bit flipped, then FF:FE, rest.
            addr[8] = static_cast<uint8_t>(mac[0] ^ 0x02);
            addr[9] = mac[1];
            addr[10] = mac[2];
            addr[11] = 0xFF;
            addr[12] = 0xFE;
            addr[13] = mac[3];
            addr[14] = mac[4];
            addr[15] = mac[5];
            return addr;
        }

        net::WireMac SolicitedNodeMac(const uint8_t addr[16]) noexcept {
            return net::WireMac{0x33, 0x33, 0xFF, addr[13], addr[14], addr[15]};
        }

        uint16_t IcmpV6Checksum(const uint8_t src[16], const uint8_t dst[16],
                                const uint8_t* segment, size_t len) noexcept {
            // RFC 2460 pseudo-header (src, dst, 32-bit length, zeros,
            // next-header). Reuses the shared accumulator so this file and
            // checksum.h cannot drift apart.
            const uint32_t sum = net::PseudoHeaderSum6(src, dst, 58, len);
            return net::InternetChecksum(segment, len, sum);
        }

        void BuildRouterAdvertisementFrame(
            const net::WireMac& gateway_mac, const uint8_t ll_addr[16],
            const uint8_t prefix[16], uint8_t prefix_len,
            uint32_t router_lifetime_s, bool managed, bool other, uint32_t mtu,
            const std::vector<std::array<uint8_t, 16>>& dns_servers,
            std::vector<uint8_t>& out_frame) {
            // RA body per RFC 4861 section 4.2/4.6: ICMPv6 header + flags (16)
            // + prefix information option (32) + MTU option when requested
            // (8) + optional RDNSS option (RFC 8106, 8+16*n) + SLLA option
            // (8). RDNSS carries at most 3 servers; a longer configured list
            // is clamped (capped window, never truncated mid-option).
            const size_t dns_count = std::min<size_t>(dns_servers.size(), 3);
            const size_t dns_bytes = dns_count ? 8 + 16 * dns_count : 0;
            const bool with_mtu = 0 != mtu;
            const size_t icmp_len = 16 + 32 + (with_mtu ? 8 : 0) + dns_bytes + 8;
            out_frame.assign(net::kEthernetHeaderLen + kIpv6HeaderLen + icmp_len,
                             0);
            uint8_t* frame = out_frame.data();

            // Ethernet: to the all-nodes multicast MAC.
            const net::WireMac dst_mac{0x33, 0x33, 0x00, 0x00, 0x00, 0x01};
            net::BuildEthHeader(frame, dst_mac, gateway_mac,
                                net::kEthertypeIpv6);

            // IPv6: src = gateway link-local, dst = ff02::1.
            uint8_t* ip = frame + net::kEthernetHeaderLen;
            ip[0] = 0x60;  // version 6, traffic class/DSCP 0
            ip[6] = 58;    // next-header: ICMPv6
            ip[7] = 255;   // hop limit
            std::memcpy(ip + 8, ll_addr, 16);
            const uint8_t all_nodes[16] = {0xFF, 0x02, 0, 0, 0, 0, 0, 0,
                                           0,    0,    0, 0, 0, 0, 0, 0x01};  // ff02::1
            std::memcpy(ip + 24, all_nodes, 16);
            const uint16_t payload_len = static_cast<uint16_t>(icmp_len);
            ip[4] = static_cast<uint8_t>(payload_len >> 8);
            ip[5] = static_cast<uint8_t>(payload_len & 0xFF);

            // ICMPv6 RA (type 134, code 0).
            uint8_t* icmp = ip + kIpv6HeaderLen;
            icmp[0] = kIcmpV6RouterAdvertisement;
            icmp[1] = 0;
            icmp[2] = 0;
            icmp[3] = 0;
            icmp[4] = 0x40;  // current hop limit 64
            icmp[5] = static_cast<uint8_t>((managed ? 0x80 : 0x00) |
                                           (other ? 0x40 : 0x00));
            icmp[6] = static_cast<uint8_t>(router_lifetime_s >> 8);
            icmp[7] = static_cast<uint8_t>(router_lifetime_s & 0xFF);
            // reachable time 0 (unspecified), retrans timer 0.

            // Prefix information option (type 3, length 4 units of 8 bytes).
            // Layout (RFC 4861 section 4.6.2): type|len|prefixlen|flags|
            //   valid(4..7)|preferred(8..11)|reserved(12..15)|prefix(16..31).
            uint8_t* opt = icmp + 16;
            opt[0] = 3;
            opt[1] = 4;
            opt[2] = prefix_len;
            opt[3] = 0xC0;  // L=1 (on-link), A=1 (autonomous / SLAAC)
            // Valid AND preferred lifetimes: 24 h. A zero preferred lifetime
            // would make clients deprecate the address immediately.
            const uint32_t lifetime = 86400;
            opt[4] = static_cast<uint8_t>(lifetime >> 24);
            opt[5] = static_cast<uint8_t>(lifetime >> 16);
            opt[6] = static_cast<uint8_t>(lifetime >> 8);
            opt[7] = static_cast<uint8_t>(lifetime);
            opt[8] = static_cast<uint8_t>(lifetime >> 24);
            opt[9] = static_cast<uint8_t>(lifetime >> 16);
            opt[10] = static_cast<uint8_t>(lifetime >> 8);
            opt[11] = static_cast<uint8_t>(lifetime);
            std::memcpy(opt + 16, prefix, 16);

            // MTU option (type 5, one 8-byte unit) when requested.
            uint8_t* opt_cursor = opt + 32;
            if (with_mtu) {
                uint8_t* mtu_opt = opt + 32;
                mtu_opt[0] = 5;
                mtu_opt[1] = 1;
                mtu_opt[2] = 0;
                mtu_opt[3] = 0;
                mtu_opt[4] = static_cast<uint8_t>(mtu >> 24);
                mtu_opt[5] = static_cast<uint8_t>(mtu >> 16);
                mtu_opt[6] = static_cast<uint8_t>(mtu >> 8);
                mtu_opt[7] = static_cast<uint8_t>(mtu);
                opt_cursor = opt + 40;
            }

            // RDNSS option (type 25) after MTU when DNS servers are supplied.
            // Layout (RFC 8106 section 5.1): type|len|reserved(2)|lifetime(4)|addr.
            // A zero Lifetime tells clients not to use the resolver, so the
            // field mirrors the RA router lifetime (default 1800 s).
            if (dns_count) {
                uint8_t* rdnss = opt_cursor;
                rdnss[0] = 25;
                rdnss[1] = static_cast<uint8_t>(1 + 2 * dns_count);  // 8-byte units
                rdnss[4] = static_cast<uint8_t>(router_lifetime_s >> 24);
                rdnss[5] = static_cast<uint8_t>(router_lifetime_s >> 16);
                rdnss[6] = static_cast<uint8_t>(router_lifetime_s >> 8);
                rdnss[7] = static_cast<uint8_t>(router_lifetime_s);
                for (size_t i = 0; i < dns_count; ++i) {
                    std::memcpy(rdnss + 8 + i * 16, dns_servers[i].data(), 16);
                }
                opt_cursor += 8 + 16 * dns_count;
            }

            // Source link-layer address option (type 1, length 1 unit).
            uint8_t* llopt = opt_cursor;
            llopt[0] = 1;
            llopt[1] = 1;
            std::memcpy(llopt + 2, gateway_mac.data(), net::kMacAddrLen);

            // Checksum over pseudo-header + segment.
            const uint16_t ck =
                IcmpV6Checksum(ip + 8, ip + 24, icmp, icmp_len);
            icmp[2] = static_cast<uint8_t>(ck >> 8);
            icmp[3] = static_cast<uint8_t>(ck & 0xFF);
        }

        void BuildNeighborSolicitationFrame(const uint8_t target_addr[16],
                                             const net::WireMac& gateway_mac,
                                             const uint8_t ll_addr[16],
                                             std::vector<uint8_t>& out_frame) {
            // NS body: ICMPv6 header (4) + reserved (4) + target (16) + SLLA
            // option (8) so the queried node learns us on the way back.
            const size_t icmp_len = 24 + 8;
            out_frame.assign(net::kEthernetHeaderLen + kIpv6HeaderLen + icmp_len,
                             0);
            uint8_t* frame = out_frame.data();
            // Solicited-node multicast (RFC 4291 section 2.7.1): ff02::1:ffXX:XXXX,
            // ethernet 33:33:ff:XX:XX:XX (lower 24 bits of the target).
            const net::WireMac eth_mc{0x33, 0x33, 0xFF, target_addr[13],
                                      target_addr[14], target_addr[15]};
            net::BuildEthHeader(frame, eth_mc, gateway_mac, net::kEthertypeIpv6);

            uint8_t* ip = frame + net::kEthernetHeaderLen;
            ip[0] = 0x60;
            ip[6] = 58;
            ip[7] = 255;
            std::memcpy(ip + 8, ll_addr, 16);  // src = gateway link-local
            uint8_t* d = ip + 24;
            d[0] = 0xFF;
            d[1] = 0x02;
            d[15] = target_addr[15];
            d[12] = 0x01;  // ff02::1:ff
            d[13] = 0xFF;
            d[14] = target_addr[14];
            const uint16_t payload_len = static_cast<uint16_t>(icmp_len);
            ip[4] = static_cast<uint8_t>(payload_len >> 8);
            ip[5] = static_cast<uint8_t>(payload_len & 0xFF);

            uint8_t* icmp = ip + kIpv6HeaderLen;
            icmp[0] = kIcmpV6NeighborSolicitation;
            icmp[1] = 0;
            icmp[2] = 0;
            icmp[3] = 0;
            std::memcpy(icmp + 8, target_addr, 16);
            uint8_t* llopt = icmp + 24;
            llopt[0] = 1;  // source link-layer address
            llopt[1] = 1;
            std::memcpy(llopt + 2, gateway_mac.data(), net::kMacAddrLen);

            const uint16_t ck =
                IcmpV6Checksum(ip + 8, ip + 24, icmp, icmp_len);
            icmp[2] = static_cast<uint8_t>(ck >> 8);
            icmp[3] = static_cast<uint8_t>(ck & 0xFF);
        }

        void BuildNeighborAdvertisementFrame(const uint8_t target_addr[16],
                                             const net::WireMac& gateway_mac,
                                             const uint8_t dst_addr[16],
                                             const net::WireMac& dst_mac,
                                             bool solicited,
                                             std::vector<uint8_t>& out_frame) {
            // NA body: ICMPv6 header (4) + flags/reserved (4) + target (16)
            // + target link-layer option (2 + 6).
            const size_t icmp_len = 24 + 8;
            out_frame.assign(net::kEthernetHeaderLen + kIpv6HeaderLen + icmp_len,
                             0);
            uint8_t* frame = out_frame.data();
            net::BuildEthHeader(frame, dst_mac, gateway_mac, net::kEthertypeIpv6);

            uint8_t* ip = frame + net::kEthernetHeaderLen;
            ip[0] = 0x60;
            ip[6] = 58;
            ip[7] = 255;
            std::memcpy(ip + 8, target_addr, 16);  // src = the queried address
            std::memcpy(ip + 24, dst_addr, 16);
            const uint16_t payload_len = static_cast<uint16_t>(icmp_len);
            ip[4] = static_cast<uint8_t>(payload_len >> 8);
            ip[5] = static_cast<uint8_t>(payload_len & 0xFF);

            uint8_t* icmp = ip + kIpv6HeaderLen;
            icmp[0] = kIcmpV6NeighborAdvertisement;
            icmp[1] = 0;
            icmp[2] = 0;
            icmp[3] = 0;
            icmp[4] = solicited ? 0xE0 : 0xA0;  // R=1 always (router); S per solicited; O=1
            std::memcpy(icmp + 8, target_addr, 16);
            uint8_t* llopt = icmp + 24;
            llopt[0] = 2;  // target link-layer address
            llopt[1] = 1;
            std::memcpy(llopt + 2, gateway_mac.data(), net::kMacAddrLen);

            const uint16_t ck =
                IcmpV6Checksum(ip + 8, ip + 24, icmp, icmp_len);
            icmp[2] = static_cast<uint8_t>(ck >> 8);
            icmp[3] = static_cast<uint8_t>(ck & 0xFF);
        }

        void BuildEchoReplyV6Frame(const uint8_t* request_ip, size_t request_len,
                                   const net::WireMac& gateway_mac,
                                   const net::WireMac& client_mac,
                                   std::vector<uint8_t>& out_frame) {
            if (request_len < kIpv6HeaderLen + kIcmpV6HeaderLen) {
                return;
            }
            const uint16_t payload_len =
                static_cast<uint16_t>((request_ip[4] << 8) | request_ip[5]);
            // batch34v: payload_len comes from the wire and is attacker
            // controlled; request_len is what the caller can actually read.
            // Without this bound the function allocated a reply sized by the
            // CLAIM and copied that many bytes out of a much shorter buffer
            // (out-of-bounds read, and the reply leaked adjacent memory).
            if (static_cast<size_t>(kIpv6HeaderLen) + payload_len > request_len) {
                return;
            }
            // batch125: the check above is an UPPER bound. The ICMPv6 header
            // (type, code, checksum) is 4 bytes and this function writes
            // icmp[0..3] unconditionally at ip+40, so payload_len < 4 would put
            // those stores off the end of out_frame (heap overflow reachable
            // from the wire; an empty ICMPv6 body is legal, so the upper bound
            // alone never rejects it). Refuse a segment too short to hold the
            // header instead of fabricating a reply.
            if (payload_len < kIcmpV6HeaderLen) {
                return;
            }
            out_frame.assign(net::kEthernetHeaderLen + kIpv6HeaderLen +
                                 payload_len,
                             0);
            uint8_t* frame = out_frame.data();
            net::BuildEthHeader(frame, client_mac, gateway_mac,
                                net::kEthertypeIpv6);
            uint8_t* ip = frame + net::kEthernetHeaderLen;
            std::memcpy(ip, request_ip, kIpv6HeaderLen + payload_len);
            // Swap addresses; flip type request -> reply.
            std::array<uint8_t, 16> tmp{};
            std::memcpy(tmp.data(), ip + 8, 16);
            std::memcpy(ip + 8, ip + 24, 16);
            std::memcpy(ip + 24, tmp.data(), 16);
            uint8_t* icmp = ip + kIpv6HeaderLen;
            icmp[0] = kIcmpV6EchoReply;
            icmp[2] = 0;
            icmp[3] = 0;
            const uint16_t ck =
                IcmpV6Checksum(ip + 8, ip + 24, icmp, payload_len);
            icmp[2] = static_cast<uint8_t>(ck >> 8);
            icmp[3] = static_cast<uint8_t>(ck & 0xFF);
        }

    }  // namespace proto
}  // namespace vgww
