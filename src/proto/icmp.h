// ============================================================================
// icmp.h - ICMP echo responder (gateway self-defense) and frame builders.
//
// Scope: the virtual gateway answers pings addressed to ITSELF locally
// (TTL-1 semantics are irrelevant for a local answer); pings for other
// targets are relayed over a per-worker raw ICMP socket with id-NAT
// (relay/icmp_relay.{h,cpp}, wired in runtime/dataplane.cpp:485-498 for the
// socket and :1689-1756 for the send path; replies via HandleIcmpReply).
// ============================================================================
#pragma once

#include "net/eth.h"
#include "net/ip_addr.h"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace vgww {
    namespace proto {

        inline constexpr size_t kIcmpHeaderLen = 8;
        inline constexpr size_t kIpv4HeaderLenMin = 20;
        /// RFC 791: the IHL nibble counts 32-bit words, so a legal header is
        /// 20..60 bytes in 4-byte steps. Single-sourced (batch126) because the
        /// ICMP relay handlers index straight into the frame with the value;
        /// an unchecked ihl of 0 pointed them at the IPv4 header itself.
        inline constexpr size_t kIpv4HeaderLenMax = 60;

        /// True when `ihl` (already multiplied to bytes) is a legal IPv4
        /// header length. Total: every value is judged.
        inline bool IsLegalIpv4HeaderLength(size_t ihl) noexcept {
            return ihl >= kIpv4HeaderLenMin && ihl <= kIpv4HeaderLenMax &&
                   0 == (ihl % 4);
        }

        enum IcmpType : uint8_t {
            kIcmpEchoReply = 0,
            kIcmpEchoRequest = 8,
            kIcmpDestUnreachable = 3,
            kIcmpTimeExceeded = 11,
        };

        struct IcmpEchoView final {
            uint8_t type = 0;
            uint8_t code = 0;
            uint16_t identifier = 0;   ///< host order
            uint16_t sequence = 0;     ///< host order
            size_t payload_offset = 0; ///< within the IP datagram
            size_t payload_len = 0;
        };

        /// Parses the ICMP header of an IPv4 datagram (`ip` starts at the IP
        /// header). Returns false for non-ICMP or malformed datagrams.
        bool ParseIcmpEcho(const uint8_t* ip, size_t ip_len, IcmpEchoView& out) noexcept;

        /// Length of the ICMP segment inside an IPv4 datagram, taken from
        /// the IP total length (the authoritative datagram size). The link
        /// layer pads short frames to the 60-byte Ethernet minimum and the
        /// driver reports that padded length, so a buffer-derived length
        /// would relay padding as ICMP payload. Returns false for a
        /// malformed datagram (non-IPv4, illegal IHL, or a total length
        /// outside [ihl + 8, ip_len]).
        bool IcmpSegmentLength(const uint8_t* ip, size_t ip_len,
                               size_t& out_len) noexcept;

        /// Builds a full Ethernet+IPv4+ICMP echo-reply frame answering a
        /// request that was sent to the gateway itself.
        /// `request_ip` points at the IP header inside the incoming frame.
        void BuildEchoReplyFrame(const uint8_t* request_ip, size_t request_len,
                                 const net::WireMac& gateway_mac,
                                 const net::WireMac& client_mac,
                                 std::vector<uint8_t>& out_frame);

        /// Builds an Ethernet+IPv4+ICMP echo-REPLY frame for a RELAYED ping:
        /// the internet host at `remote_ip` answered us; deliver that answer
        /// to the LAN client as if it came straight from `remote_ip`.
        void BuildRelayedEchoReplyFrame(const uint8_t remote_ip[4],
                                        const uint8_t client_ip[4],
                                        const net::WireMac& gateway_mac,
                                        const net::WireMac& client_mac,
                                        uint16_t original_id, uint16_t seq,
                                        const uint8_t* payload,
                                        size_t payload_len,
                                        std::vector<uint8_t>& out_frame);

    }  // namespace proto
}  // namespace vgww
