// ============================================================================
// ndp.h - Userspace NDP control plane for the IPv6 gateway (RFC 4861 subset).
//
// VGWW announces itself as an IPv6 router via Router Advertisements and
// answers Neighbor Solicitations for its own addresses. Clients autoconfigure
// addresses from the advertised ULA prefix (SLAAC) and install a default
// route pointing at the gateway's link-local address.
//
// Wire facts used here:
//   * ICMPv6 checksum covers an IPv6 pseudo-header (src|dst|len|nh) plus
//     the ICMPv6 segment.
//   * All-nodes multicast: ff02::1 / 33:33:00:00:00:01.
//   * Link-local address from MAC (EUI-64): fe80:: + MAC with FF:FE inserted
//     and bit 1 of the first byte flipped.
// ============================================================================
#pragma once

#include "net/checksum.h"
#include "net/eth.h"
#include "net/ip_addr.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

namespace vgww {
    namespace proto {

        // ICMPv6 message types (RFC 4443 / RFC 4861).
        inline constexpr uint8_t kIcmpV6EchoRequest = 128;
        inline constexpr uint8_t kIcmpV6EchoReply = 129;
        inline constexpr uint8_t kIcmpV6RouterSolicitation = 133;
        inline constexpr uint8_t kIcmpV6RouterAdvertisement = 134;
        inline constexpr uint8_t kIcmpV6NeighborSolicitation = 135;
        inline constexpr uint8_t kIcmpV6NeighborAdvertisement = 136;
        inline constexpr uint8_t kIcmpV6Redirect = 137;

        /// Derives the gateway link-local address (fe80::/10 + EUI-64 IID)
        /// from its MAC. Returns the 16-byte wire-order address.
        std::array<uint8_t, 16> LinkLocalFromMac(const net::WireMac& mac) noexcept;

        /// Computes the solicited-node multicast MAC for a target address
        /// (33:33:FF:xx:xx:xx from the last 3 bytes).
        net::WireMac SolicitedNodeMac(const uint8_t addr[16]) noexcept;

        /// ICMPv6 checksum: fold the IPv6 pseudo-header plus the segment.
        uint16_t IcmpV6Checksum(const uint8_t src[16], const uint8_t dst[16],
                                const uint8_t* segment, size_t len) noexcept;

        /// Builds a Router Advertisement Ethernet frame announcing `prefix`
        /// (wire order, `prefix_len` bits) with router/prefix lifetimes.
        /// Sent to the all-nodes multicast address; source = gateway
        /// link-local. `managed`/`other` set the RA M/O flag bits (RFC 4861
        /// section 4.2): both are set when the gateway serves addresses (main mode)
        /// and clear for pure SLAAC. `mtu` != 0 appends an MTU option
        /// (RFC 4861 section 4.6.3) so SLAAC clients learn a link MTU smaller
        /// than
        /// 1500 when needed. `dns_servers` (max 3) appends an RDNSS option
        /// (RFC 8106, type 25) carrying v6 recursive DNS servers so
        /// SLAAC-only clients can resolve names; the option's Lifetime field
        /// mirrors `router_lifetime_s` (a zero lifetime would tell clients
        /// not to use the resolver). An empty list emits no RDNSS option and
        /// the frame is byte-identical to before.
        void BuildRouterAdvertisementFrame(
            const net::WireMac& gateway_mac, const uint8_t ll_addr[16],
            const uint8_t prefix[16], uint8_t prefix_len,
            uint32_t router_lifetime_s, bool managed, bool other, uint32_t mtu,
            const std::vector<std::array<uint8_t, 16>>& dns_servers,
            std::vector<uint8_t>& out_frame);

        /// Builds a Neighbor Solicitation frame targeting `target_addr` (wire
        /// order) sent to the solicited-node multicast address via the
        /// gateway link-local (`ll_addr`), carrying an SLLA option so the
        /// stale client learns our address in the answer cycle. Used to
        /// re-learn an aged neighbor (the v6 analogue of an ARP probe).
        void BuildNeighborSolicitationFrame(const uint8_t target_addr[16],
                                            const net::WireMac& gateway_mac,
                                            const uint8_t ll_addr[16],
                                            std::vector<uint8_t>& out_frame);

        /// Builds a Neighbor Advertisement frame answering a solicitation for
        /// `target_addr` (the gateway's own address). `solicited` sets the
        /// flag; destination is the soliciting node's address.
        void BuildNeighborAdvertisementFrame(const uint8_t target_addr[16],
                                             const net::WireMac& gateway_mac,
                                             const uint8_t dst_addr[16],
                                             const net::WireMac& dst_mac,
                                             bool solicited,
                                             std::vector<uint8_t>& out_frame);

        /// Builds an ICMPv6 Echo Reply Ethernet frame mirroring an echo
        /// request that targeted the gateway itself.
        void BuildEchoReplyV6Frame(const uint8_t* request_ip, size_t request_len,
                                   const net::WireMac& gateway_mac,
                                   const net::WireMac& client_mac,
                                   std::vector<uint8_t>& out_frame);

    }  // namespace proto
}  // namespace vgww
