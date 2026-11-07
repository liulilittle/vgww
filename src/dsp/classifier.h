// ============================================================================
// classifier.h - Frame classification and symmetric flow hashing.
//
// The RX thread runs this on every intercepted frame to decide:
//   1. WHICH worker owns the flow (SymmetricFlowHash - both directions of
//      a conversation land on the same worker, so per-flow state needs no
//      cross-thread synchronization),
//   2. WHAT protocol module processes it (FrameClass).
//
// Parsers here are minimal and self-contained: the driver layer must not
// depend on xtcp internals (xtcp re-parses TCP packets itself).
// ============================================================================
#pragma once

#include "net/eth.h"
#include "net/ip_addr.h"

#include <cstdint>

namespace vgww {
    namespace dsp {

        enum class FrameClass : uint8_t {
            kOther = 0,     ///< not ours (should rarely appear past the kernel filter)
            kArp = 1,       ///< ARP request/reply
            kDhcpV4 = 2,    ///< UDP 67/68 broadcast
            kIcmpV4 = 3,    ///< ICMP echo/errors
            kTcpV4 = 4,
            kUdpV4 = 5,
            kIcmpV6 = 6,    ///< NDP/RS/RA/echo v6
            kTcpV6 = 7,
            kUdpV6 = 8,
            kDhcpV6 = 9,    ///< UDP 546/547 (DHCPv6 client/server ports)
        };

        /// Parsed transport-relevant view of a frame (offsets into the raw
        /// frame buffer; payload length excludes all headers).
        struct FrameView final {
            FrameClass cls = FrameClass::kOther;
            net::EthHeaderView eth{};
            net::IpAddress src_ip{};
            net::IpAddress dst_ip{};
            uint16_t src_port = 0;   ///< host order; 0 when N/A
            uint16_t dst_port = 0;   ///< host order; 0 when N/A
            size_t ip_offset = 0;    ///< start of IP header within the frame
            size_t l4_offset = 0;    ///< start of L4 header within the frame
            size_t ip_len = 0;       ///< total IP datagram length
            uint8_t ip_proto = 0;    ///< IPPROTO_* value
        };

        /// Classifies one Ethernet frame. Returns false for frames too short
        /// or malformed to dispatch safely (caller drops + counts them).
        bool ClassifyFrame(const uint8_t* data, size_t len, FrameView& out) noexcept;

        /// Symmetric 5-tuple hash with fmix64 finalizer: swapping src/dst
        /// yields the SAME value, so both directions of a flow map to the
        /// same worker. `flow_salt` rotates assignment without breaking
        /// symmetry (used by tests / future rebalancing).
        uint64_t SymmetricFlowHash(const FrameView& view,
                                   uint64_t flow_salt = 0) noexcept;

    }  // namespace dsp
}  // namespace vgww
