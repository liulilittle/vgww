// ============================================================================
// arp.h - ARP frame parse/build and the gateway ARP responder.
//
// Frame layout (Ethernet + ARP, RFC 826):
//   eth(14) | htype(2)=1 | ptype(2)=0x0800 | hlen(1)=6 | plen(1)=4
//           | oper(2): 1=request 2=reply | sha(6) | spa(4) | tha(6) | tpa(4)
//
// The responder answers requests for the VIRTUAL GATEWAY IP with the virtual
// MAC. Requests for other addresses are ignored (the host stack never sees
// them anyway - the kernel filter only forwards ARP to us).
// ============================================================================
#pragma once

#include "net/eth.h"
#include "net/ip_addr.h"

#include <cstddef>
#include <cstdint>
#include <cstring>

namespace vgww {
    namespace proto {

        inline constexpr size_t kArpFrameLen = net::kEthernetHeaderLen + 28;

        enum class ArpOperation : uint16_t { kRequest = 1, kReply = 2 };

        struct ArpView final {
            ArpOperation operation = ArpOperation::kRequest;
            net::WireMac sender_mac{};
            uint32_t sender_ip = 0;   ///< inet_addr numeric convention
            net::WireMac target_mac{};
            uint32_t target_ip = 0;   ///< inet_addr numeric convention
        };

        /// Parses an Ethernet+ARP frame. Returns false for malformed frames.
        bool ParseArpFrame(const uint8_t* data, size_t len, ArpView& out) noexcept;

        /// Builds a complete Ethernet+ARP frame into `out` (kArpFrameLen).
        void BuildArpFrame(uint8_t* out, ArpOperation operation,
                           const net::WireMac& src_mac, uint32_t src_ip,
                           const net::WireMac& dst_mac, uint32_t dst_ip) noexcept;

        /// Gateway responder: when `request` asks for `gateway_ip`, produces
        /// a reply frame addressed back to the requester. Returns false when
        /// the frame is not an ARP request for the gateway.
        bool BuildGatewayArpReply(const ArpView& request, uint32_t gateway_ip,
                                  const net::WireMac& gateway_mac,
                                  std::array<uint8_t, kArpFrameLen>& out_frame) noexcept;

        /// Builds a gratuitous ARP announcement (update LAN caches after the
        /// virtual gateway appears or its address changes).
        void BuildGratuitousAnnouncement(uint32_t gateway_ip,
                                         const net::WireMac& gateway_mac,
                                         std::array<uint8_t, kArpFrameLen>& out_frame) noexcept;

    }  // namespace proto
}  // namespace vgww
