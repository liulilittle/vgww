// ============================================================================
// arp.cpp - ARP parse/build implementation.
// ============================================================================
#include "proto/arp.h"

namespace vgww {
    namespace proto {

        namespace {
            inline constexpr size_t kArpBodyOffset = net::kEthernetHeaderLen;
            inline constexpr uint16_t kHardwareTypeEthernet = 1;
            inline constexpr uint16_t kProtocolTypeIpv4 = 0x0800;
        }  // namespace

        bool ParseArpFrame(const uint8_t* data, size_t len, ArpView& out) noexcept {
            if (len < kArpFrameLen) {
                return false;
            }
            net::EthHeaderView eth;
            if (!net::ParseEthHeader(data, len, eth) ||
                net::kEthertypeArp != eth.ethertype) {
                return false;
            }
            const uint8_t* p = data + kArpBodyOffset;
            const uint16_t htype = static_cast<uint16_t>((p[0] << 8) | p[1]);
            const uint16_t ptype = static_cast<uint16_t>((p[2] << 8) | p[3]);
            const uint8_t hlen = p[4];
            const uint8_t plen = p[5];
            const uint16_t oper = static_cast<uint16_t>((p[6] << 8) | p[7]);
            if (kHardwareTypeEthernet != htype || kProtocolTypeIpv4 != ptype ||
                net::kMacAddrLen != hlen || 4 != plen) {
                return false;
            }
            // RFC 826 defines exactly two operation codes (1=request,
            // 2=reply). Anything else is malformed and must not collapse into
            // kRequest, or a garbage operand targeting the gateway IP would
            // get a gratuitous reply.
            if (1 != oper && 2 != oper) {
                return false;
            }
            out.operation = (2 == oper) ? ArpOperation::kReply : ArpOperation::kRequest;
            std::memcpy(out.sender_mac.data(), p + 8, net::kMacAddrLen);
            std::memcpy(&out.sender_ip, p + 14, 4);   // wire order == numeric convention
            std::memcpy(out.target_mac.data(), p + 18, net::kMacAddrLen);
            std::memcpy(&out.target_ip, p + 24, 4);
            return true;
        }

        void BuildArpFrame(uint8_t* out, ArpOperation operation,
                           const net::WireMac& src_mac, uint32_t src_ip,
                           const net::WireMac& dst_mac, uint32_t dst_ip) noexcept {
            net::BuildEthHeader(out, dst_mac, src_mac, net::kEthertypeArp);
            uint8_t* p = out + kArpBodyOffset;
            p[0] = 0x00; p[1] = 0x01;                 // htype: Ethernet
            p[2] = 0x08; p[3] = 0x00;                 // ptype: IPv4
            p[4] = net::kMacAddrLen;                  // hlen
            p[5] = 4;                                 // plen
            const uint16_t oper = (ArpOperation::kReply == operation) ? 2 : 1;
            p[6] = static_cast<uint8_t>(oper >> 8);
            p[7] = static_cast<uint8_t>(oper & 0xFF);
            std::memcpy(p + 8, src_mac.data(), net::kMacAddrLen);
            std::memcpy(p + 14, &src_ip, 4);
            std::memcpy(p + 18, dst_mac.data(), net::kMacAddrLen);
            std::memcpy(p + 24, &dst_ip, 4);
        }

        bool BuildGatewayArpReply(const ArpView& request, uint32_t gateway_ip,
                                  const net::WireMac& gateway_mac,
                                  std::array<uint8_t, kArpFrameLen>& out_frame) noexcept {
            if (ArpOperation::kRequest != request.operation ||
                request.target_ip != gateway_ip) {
                return false;
            }
            BuildArpFrame(out_frame.data(), ArpOperation::kReply, gateway_mac,
                          gateway_ip, request.sender_mac, request.sender_ip);
            return true;
        }

        void BuildGratuitousAnnouncement(uint32_t gateway_ip,
                                         const net::WireMac& gateway_mac,
                                         std::array<uint8_t, kArpFrameLen>& out_frame) noexcept {
            // Broadcast "who has gateway_ip? tell everyone" with spa=tpa:
            // hosts update their caches without a matching request.
            BuildArpFrame(out_frame.data(), ArpOperation::kRequest, gateway_mac,
                          gateway_ip, net::kBroadcastMac, gateway_ip);
        }

    }  // namespace proto
}  // namespace vgww
