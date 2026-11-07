// ============================================================================
// classifier.cpp - Frame classification implementation.
// ============================================================================
#include "dsp/classifier.h"

#include <cstring>

namespace vgww {
    namespace dsp {

        namespace {

            inline constexpr uint8_t kProtoIcmp = 1;
            inline constexpr uint8_t kProtoTcp = 6;
            inline constexpr uint8_t kProtoUdp = 17;
            inline constexpr uint8_t kProtoIcmpV6 = 58;

            inline constexpr uint16_t kDhcpServerPort = 67;
            inline constexpr uint16_t kDhcpClientPort = 68;
            inline constexpr uint16_t kDhcp6ServerPort = 547;
            inline constexpr uint16_t kDhcp6ClientPort = 546;

            // fmix64 finalizer (MurmurHash3): avalanche so sequential ports do
            // not collapse onto one worker (same rationale as xtcp scheduler).
            inline uint64_t Fmix64(uint64_t h) noexcept {
                h ^= h >> 33;
                h *= 0xFF51AFD7ED558CCDull;
                h ^= h >> 33;
                h *= 0xC4CEB9FE1A85EC53ull;
                h ^= h >> 33;
                return h;
            }

            // Minimal IPv4 header parse; fills ip fields + l4_offset.
            bool ParseIpv4Header(const uint8_t* data, size_t len, FrameView& out) {
                if (len < 20) {
                    return false;
                }
                const uint8_t version = data[0] >> 4;
                const uint8_t ihl = data[0] & 0x0F;
                if (4 != version || ihl < 5) {
                    return false;
                }
                const size_t header_len = static_cast<size_t>(ihl) * 4;
                if (len < header_len) {
                    return false;
                }
                const uint16_t total_len = static_cast<uint16_t>((data[2] << 8) | data[3]);
                out.ip_proto = data[9];
                const uint8_t src[4] = {data[12], data[13], data[14], data[15]};
                const uint8_t dst[4] = {data[16], data[17], data[18], data[19]};
                out.src_ip = net::IpAddress::FromV4BigEndian(src);
                out.dst_ip = net::IpAddress::FromV4BigEndian(dst);
                // Tolerate offload-padded frames: clamp to what we actually hold.
                out.ip_len = (total_len >= header_len && total_len <= len) ? total_len : len;
                out.ip_offset = net::kEthernetHeaderLen;
                out.l4_offset = net::kEthernetHeaderLen + header_len;
                return true;
            }

            // Minimal IPv6 fixed-header parse (no extension chain walk: NDP,
            // ICMPv6, TCP and UDP all arrive with next-header directly).
            bool ParseIpv6Header(const uint8_t* data, size_t len, FrameView& out) {
                if (len < 40) {
                    return false;
                }
                out.ip_proto = data[6];
                std::memcpy(out.src_ip.bytes.data(), data + 8, 16);
                std::memcpy(out.dst_ip.bytes.data(), data + 24, 16);
                out.src_ip.family = net::Family::kV6;
                out.dst_ip.family = net::Family::kV6;
                const uint16_t payload_len = static_cast<uint16_t>((data[4] << 8) | data[5]);
                out.ip_len = (40 + payload_len <= len) ? 40 + payload_len : len;
                out.ip_offset = net::kEthernetHeaderLen;
                out.l4_offset = net::kEthernetHeaderLen + 40;
                return true;
            }

            // Reads ports for TCP/UDP classes once the L4 header is reachable.
            //
            // batch34u: the bound is the IPv4/IPv6 declared datagram end, not
            // the received frame length. Ethernet pads short frames to the
            // 60-byte minimum, so a datagram that stops inside (or before) its
            // L4 header still arrives with bytes after it. Reading ports out of
            // that padding invents a four-tuple the sender never wrote: padding
            // "ports" of 67/68 promote plain UDP to DHCPv4 and the invented
            // ports perturb the flow hash that pins a conversation to a worker.
            void ParseL4Ports(const uint8_t* frame, size_t len, FrameView& out) {
                const size_t declared_end = out.ip_offset + out.ip_len;
                const size_t limit = declared_end < len ? declared_end : len;
                if (out.l4_offset + 4 > limit) {
                    return;
                }
                const uint8_t* l4 = frame + out.l4_offset;
                out.src_port = static_cast<uint16_t>((l4[0] << 8) | l4[1]);
                out.dst_port = static_cast<uint16_t>((l4[2] << 8) | l4[3]);
            }

        }  // namespace

        bool ClassifyFrame(const uint8_t* data, size_t len, FrameView& out) noexcept {
            out = FrameView{};
            if (!net::ParseEthHeader(data, len, out.eth)) {
                return false;
            }
            const uint8_t* ip = data + net::kEthernetHeaderLen;
            const size_t ip_cap = len - net::kEthernetHeaderLen;

            switch (out.eth.ethertype) {
                case net::kEthertypeArp:
                    out.cls = FrameClass::kArp;  // body parsed by the ARP module
                    return true;

                case net::kEthertypeIpv4: {
                    if (!ParseIpv4Header(ip, ip_cap, out)) {
                        return false;
                    }
                    // Fragmented IPv4 UDP cannot be relayed (the relay parses
                    // a single datagram): offset != 0 or MF means only part of
                    // the payload is here. Same for ICMP (its four-tuple and
                    // echo ID live in the first fragment, so a partial echo
                    // reply would otherwise be relayed truncated). Forward to
                    // the host instead. TCP fragments keep flowing to the
                    // stack, which reassembles them (RFC 791).
                    if (kProtoUdp == out.ip_proto || kProtoIcmp == out.ip_proto) {
                        const uint16_t frag =
                            static_cast<uint16_t>((ip[6] & 0x1F) << 8) | ip[7];
                        // C2: the MF bit (byte 6 bit5 = 0x20) is masked out by
                        // the & 0x1F above - a FIRST fragment (offset 0, MF=1)
                        // has frag==0 and was previously misread as a complete
                        // datagram. Test MF explicitly.
                        if (0 != (ip[6] & 0x20) || 0 != (frag & 0x1FFF)) {
                            out.cls = FrameClass::kOther;
                            return true;
                        }
                    }
                    switch (out.ip_proto) {
                        case kProtoIcmp:
                            out.cls = FrameClass::kIcmpV4;
                            break;  // fall through: multicast/broadcast filter
                        case kProtoTcp:
                            out.cls = FrameClass::kTcpV4;
                            break;
                        case kProtoUdp:
                            out.cls = FrameClass::kUdpV4;
                            break;
                        default:
                            out.cls = FrameClass::kOther;
                            return true;
                    }
                    break;
                }

                case net::kEthertypeIpv6: {
                    if (!ParseIpv6Header(ip, ip_cap, out)) {
                        return false;
                    }
                    switch (out.ip_proto) {
                        case kProtoIcmpV6:
                            out.cls = FrameClass::kIcmpV6;
                            return true;
                        case kProtoTcp:
                            out.cls = FrameClass::kTcpV6;
                            break;
                        case kProtoUdp:
                            out.cls = FrameClass::kUdpV6;
                            break;
                        default:
                            out.cls = FrameClass::kOther;
                            return true;
                    }
                    break;
                }

                default:
                    out.cls = FrameClass::kOther;
                    return true;
            }

            ParseL4Ports(data, len, out);

            // DHCP is UDP to ports 67/68 (client->server uses dst 67).
            if ((FrameClass::kUdpV4 == out.cls) &&
                (kDhcpServerPort == out.dst_port || kDhcpClientPort == out.dst_port ||
                 kDhcpServerPort == out.src_port || kDhcpClientPort == out.src_port)) {
                out.cls = FrameClass::kDhcpV4;
            }
            // DHCPv6 is UDP to the exact ports 546/547 (RFC 8415 section 7.2).
            // Both directions are claimed; any other UDP pair stays kUdpV6.
            if ((FrameClass::kUdpV6 == out.cls) &&
                (kDhcp6ServerPort == out.dst_port ||
                 kDhcp6ClientPort == out.dst_port ||
                 kDhcp6ServerPort == out.src_port ||
                 kDhcp6ClientPort == out.src_port)) {
                out.cls = FrameClass::kDhcpV6;
            }
            // LAN multicast/broadcast must never be NATed as unicast: SSDP,
            // NetBIOS and friends would leak onto the uplink and never answer
            // (no unicast peer exists to reply). DHCP above has already been
            // upgraded to kDhcpV4, so everything else addressed to an IPv4
            // multicast (224/4) or limited-broadcast (255.255.255.255) target
            // goes to the host path, which is where the gateway's own stack
            // can decide membership (IGMP etc). v4 octets live at [12..15].
            if ((FrameClass::kUdpV4 == out.cls || FrameClass::kIcmpV4 == out.cls ||
                 FrameClass::kTcpV4 == out.cls) &&
                (0xE0 == (out.dst_ip.bytes[12] & 0xF0) ||
                 (0xFF == out.dst_ip.bytes[12] && 0xFF == out.dst_ip.bytes[13] &&
                  0xFF == out.dst_ip.bytes[14] && 0xFF == out.dst_ip.bytes[15]))) {
                out.cls = FrameClass::kOther;
            }
            // C9: IPv6 multicast (ff00::/8, first octet 0xFF) leaks the same
            // way - mDNS ff02::fb, SSDPv6 ff02::c and LLMNR ff02::1:3 would be
            // NATed as unicast flows and never answered. DHCPv6 above already
            // claimed the one legitimate v6 multicast (ff02::1:2 to ports
            // 546/547), so everything else addressed to a v6 group goes to
            // the host path like its v4 counterpart.
            if ((FrameClass::kUdpV6 == out.cls || FrameClass::kIcmpV6 == out.cls ||
                 FrameClass::kTcpV6 == out.cls) &&
                0xFF == out.dst_ip.bytes[0]) {
                out.cls = FrameClass::kOther;
            }
            return true;
        }

        uint64_t SymmetricFlowHash(const FrameView& view, uint64_t flow_salt) noexcept {
            // Normalize direction: order the two endpoints so both directions
            // of the same conversation hash identically.
            const bool swap = view.dst_ip < view.src_ip ||
                              (view.dst_ip == view.src_ip && view.dst_port < view.src_port);
            const net::IpAddress& lo_ip = swap ? view.dst_ip : view.src_ip;
            const net::IpAddress& hi_ip = swap ? view.src_ip : view.dst_ip;
            const uint16_t lo_port = swap ? view.dst_port : view.src_port;
            const uint16_t hi_port = swap ? view.src_port : view.dst_port;

            uint64_t h = flow_salt ^ 0x9E3779B97F4A7C15ull;
            h ^= static_cast<uint64_t>(view.ip_proto) << 56;
            for (size_t i = 0; i < 16; i += 8) {
                uint64_t chunk = 0;
                std::memcpy(&chunk, &lo_ip.bytes[i], 8);
                h ^= chunk;
                h *= 0x100000001B3ull;
                std::memcpy(&chunk, &hi_ip.bytes[i], 8);
                h ^= chunk;
                h *= 0x100000001B3ull;
            }
            h ^= static_cast<uint64_t>(lo_port) << 16;
            h ^= static_cast<uint64_t>(hi_port);
            return Fmix64(h);
        }

    }  // namespace dsp
}  // namespace vgww
