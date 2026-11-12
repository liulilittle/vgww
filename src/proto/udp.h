// ============================================================================
// udp.h - UDP header parse/build for the return-path frame builder.
// ============================================================================
#pragma once

#include "net/checksum.h"
#include "net/eth.h"
#include "net/ip_addr.h"
// The IPv4 IHL predicate is single-sourced in icmp.h (batch126); the
// datagram-length helpers below must judge IHL exactly like the ICMP
// relay does, so they reuse it instead of duplicating the rule.
#include "proto/icmp.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

namespace vgww {
    namespace proto {

        inline constexpr size_t kUdpHeaderLen = 8;

        struct UdpView final {
            uint16_t sport = 0;   ///< host order
            uint16_t dport = 0;   ///< host order
            uint16_t length = 0;  ///< UDP total length (header+payload)
        };

        /// Parses the UDP header at `data` (8+ bytes).
        inline bool ParseUdp(const uint8_t* data, size_t len, UdpView& out) noexcept {
            if (len < kUdpHeaderLen) {
                return false;
            }
            out.sport = static_cast<uint16_t>((data[0] << 8) | data[1]);
            out.dport = static_cast<uint16_t>((data[2] << 8) | data[3]);
            out.length = static_cast<uint16_t>((data[4] << 8) | data[5]);
            return true;
        }

        /// Length of the UDP datagram (header + payload) inside an IPv4
        /// datagram, taken from the IP total length - the authoritative
        /// size. The link layer pads short frames to the 60-byte Ethernet
        /// minimum and the driver reports that padded length, so a
        /// buffer-derived bound would forward the padding as UDP payload
        /// (the same rule IcmpSegmentLength applies to ICMP).
        ///
        /// `out_header_len` receives the IHL in bytes. Rejects a malformed
        /// datagram: non-IPv4, illegal IHL, a header that does not fit, or
        /// a total length below ihl + 8 (no room for the UDP header).
        /// A total length ABOVE `ip_len` means the capture is shorter than
        /// the datagram, so the bound falls back to what was captured
        /// rather than inventing bytes that are not there.
        inline bool UdpSegmentLengthV4(const uint8_t* ip, size_t ip_len,
                                       size_t& out_header_len,
                                       size_t& out_len) noexcept {
            if (nullptr == ip || ip_len < kIpv4HeaderLenMin) {
                return false;
            }
            if (4 != (ip[0] >> 4)) {
                return false;
            }
            const size_t header_len =
                static_cast<size_t>(ip[0] & 0x0F) * 4;
            if (!IsLegalIpv4HeaderLength(header_len) ||
                header_len + kUdpHeaderLen > ip_len) {
                return false;
            }
            const size_t total_len =
                (static_cast<size_t>(ip[2]) << 8) |
                static_cast<size_t>(ip[3]);
            if (total_len < header_len + kUdpHeaderLen) {
                return false;
            }
            out_header_len = header_len;
            out_len = (total_len < ip_len ? total_len : ip_len) - header_len;
            return true;
        }

        /// Length of the UDP datagram inside an IPv6 packet, taken from
        /// the payload-length field (the authoritative size). Rejects a
        /// payload length below 8 (no room for the UDP header) and a
        /// non-IPv6 buffer. Payload length 0 (a jumbogram, RFC 2675) is
        /// rejected: VGWW carries no datagrams that large, and treating 0
        /// as "use the buffer" would forward padding bytes.
        /// A declared length above what was captured falls back to the
        /// captured bytes, exactly like the IPv4 helper.
        inline bool UdpSegmentLengthV6(const uint8_t* ip, size_t ip_len,
                                       size_t& out_len) noexcept {
            if (nullptr == ip || ip_len < 40) {
                return false;
            }
            if (6 != (ip[0] >> 4)) {
                return false;
            }
            const size_t payload_len =
                (static_cast<size_t>(ip[4]) << 8) |
                static_cast<size_t>(ip[5]);
            if (payload_len < kUdpHeaderLen) {
                return false;
            }
            const size_t held = ip_len - 40;
            if (held < kUdpHeaderLen) {
                return false;
            }
            out_len = payload_len < held ? payload_len : held;
            return true;
        }

        /// Builds a complete Ethernet+IPv4+UDP frame (checksums correct).
        /// `payload` is the UDP payload; addresses are wire-order byte arrays.
        inline void BuildUdpFrame(std::vector<uint8_t>& out_frame,
                                  const net::WireMac& dst_mac,
                                  const net::WireMac& src_mac,
                                  const uint8_t src_ip[4], uint16_t sport,
                                  const uint8_t dst_ip[4], uint16_t dport,
                                  const uint8_t* payload, size_t payload_len) {
            const size_t udp_len = kUdpHeaderLen + payload_len;
            // batch259: ZERO-FILL, like the IPv6 builder. resize() keeps the
            // previous contents, and the IPv4 header fields that stay 0 (DSCP,
            // identification, fragment offset) are never assigned below, so a
            // reused output buffer would transmit stale bytes from the last
            // frame built into it.
            out_frame.assign(net::kEthernetHeaderLen + 20 + udp_len, 0);
            uint8_t* frame = out_frame.data();
            net::BuildEthHeader(frame, dst_mac, src_mac, net::kEthertypeIpv4);
            uint8_t* ip = frame + net::kEthernetHeaderLen;
            ip[0] = 0x45;
            const uint16_t total = static_cast<uint16_t>(20 + udp_len);
            ip[2] = static_cast<uint8_t>(total >> 8);
            ip[3] = static_cast<uint8_t>(total & 0xFF);
            ip[6] = 0x40;  // DF
            ip[8] = 64;
            ip[9] = 17;    // UDP
            std::memcpy(ip + 12, src_ip, 4);
            std::memcpy(ip + 16, dst_ip, 4);
            uint8_t* udp = ip + 20;
            udp[0] = static_cast<uint8_t>(sport >> 8);
            udp[1] = static_cast<uint8_t>(sport & 0xFF);
            udp[2] = static_cast<uint8_t>(dport >> 8);
            udp[3] = static_cast<uint8_t>(dport & 0xFF);
            udp[4] = static_cast<uint8_t>(udp_len >> 8);
            udp[5] = static_cast<uint8_t>(udp_len & 0xFF);
            udp[6] = 0;
            udp[7] = 0;
            if (0 != payload_len) {
                std::memcpy(udp + kUdpHeaderLen, payload, payload_len);
            }
            const uint32_t pseudo =
                net::PseudoHeaderSum(ip + 12, ip + 16, 17, static_cast<uint16_t>(udp_len));
            const uint16_t udp_ck = net::InternetChecksum(udp, udp_len, pseudo);
            udp[6] = static_cast<uint8_t>(udp_ck >> 8);
            udp[7] = static_cast<uint8_t>(udp_ck & 0xFF);
            const uint16_t ip_ck = net::InternetChecksum(ip, 20);
            ip[10] = static_cast<uint8_t>(ip_ck >> 8);
            ip[11] = static_cast<uint8_t>(ip_ck & 0xFF);
        }

        /// Builds a complete Ethernet+IPv6+UDP frame (checksums correct).
        /// Addresses are 16-byte wire-order arrays.
        inline void BuildUdpFrameV6(std::vector<uint8_t>& out_frame,
                                    const net::WireMac& dst_mac,
                                    const net::WireMac& src_mac,
                                    const uint8_t src_ip[16], uint16_t sport,
                                    const uint8_t dst_ip[16], uint16_t dport,
                                    const uint8_t* payload,
                                    size_t payload_len) {
            const size_t udp_len = kUdpHeaderLen + payload_len;
            out_frame.assign(net::kEthernetHeaderLen + 40 + udp_len, 0);
            uint8_t* frame = out_frame.data();
            net::BuildEthHeader(frame, dst_mac, src_mac, net::kEthertypeIpv6);
            uint8_t* ip = frame + net::kEthernetHeaderLen;
            ip[0] = 0x60;
            const uint16_t total = static_cast<uint16_t>(udp_len);
            ip[4] = static_cast<uint8_t>(total >> 8);
            ip[5] = static_cast<uint8_t>(total & 0xFF);
            ip[7] = 64;  // hop limit
            ip[6] = 17;  // UDP
            std::memcpy(ip + 8, src_ip, 16);
            std::memcpy(ip + 24, dst_ip, 16);
            uint8_t* udp = ip + 40;
            udp[0] = static_cast<uint8_t>(sport >> 8);
            udp[1] = static_cast<uint8_t>(sport & 0xFF);
            udp[2] = static_cast<uint8_t>(dport >> 8);
            udp[3] = static_cast<uint8_t>(dport & 0xFF);
            udp[4] = static_cast<uint8_t>(udp_len >> 8);
            udp[5] = static_cast<uint8_t>(udp_len & 0xFF);
            if (0 != payload_len) {
                std::memcpy(udp + kUdpHeaderLen, payload, payload_len);
            }
            // IPv6 pseudo-header: src(16) + dst(16) + len32 + zeros24 + nh.
            uint32_t pseudo = 0;
            for (size_t i = 0; i < 16; i += 2) {
                pseudo += static_cast<uint32_t>((src_ip[i] << 8) | src_ip[i + 1]);
                pseudo += static_cast<uint32_t>((dst_ip[i] << 8) | dst_ip[i + 1]);
            }
            pseudo += static_cast<uint32_t>(udp_len);
            pseudo += 17;
            const uint16_t udp_ck =
                net::InternetChecksum(udp, udp_len, pseudo);
            // RFC 8200 section 8.1: in IPv6 the UDP checksum is mandatory and a
            // transmitted value of 0 means "no checksum" (illegal); a
            // computed 0 must be emitted as 0xFFFF.
            const uint16_t ck_wire = (0 == udp_ck) ? 0xFFFFu : udp_ck;
            udp[6] = static_cast<uint8_t>(ck_wire >> 8);
            udp[7] = static_cast<uint8_t>(ck_wire & 0xFF);
        }

    }  // namespace proto
}  // namespace vgww
