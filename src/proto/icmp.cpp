// ============================================================================
// icmp.cpp - ICMP echo responder implementation.
// ============================================================================
#include "proto/icmp.h"

#include "net/checksum.h"

#include <cstring>

namespace vgww {
    namespace proto {

        namespace {
            inline constexpr uint8_t kProtoIcmp = 1;
        }  // namespace

        bool ParseIcmpEcho(const uint8_t* ip, size_t ip_len, IcmpEchoView& out) noexcept {
            if (ip_len < kIpv4HeaderLenMin) {
                return false;
            }
            const uint8_t version = ip[0] >> 4;
            const uint8_t ihl = ip[0] & 0x0F;
            if (4 != version || ihl < 5 || kProtoIcmp != ip[9]) {
                return false;
            }
            const size_t header_len = static_cast<size_t>(ihl) * 4;
            if (ip_len < header_len + kIcmpHeaderLen) {
                return false;
            }
            const uint8_t* icmp = ip + header_len;
            out.type = icmp[0];
            out.code = icmp[1];
            out.identifier = static_cast<uint16_t>((icmp[4] << 8) | icmp[5]);
            out.sequence = static_cast<uint16_t>((icmp[6] << 8) | icmp[7]);
            out.payload_offset = header_len + kIcmpHeaderLen;
            const uint16_t total_len = static_cast<uint16_t>((ip[2] << 8) | ip[3]);
            out.payload_len =
                (total_len >= header_len + kIcmpHeaderLen && total_len <= ip_len)
                    ? total_len - header_len - kIcmpHeaderLen
                    : ip_len - header_len - kIcmpHeaderLen;
            return true;
        }

        bool IcmpSegmentLength(const uint8_t* ip, size_t ip_len,
                               size_t& out_len) noexcept {
            if (ip_len < kIpv4HeaderLenMin) {
                return false;
            }
            if (4 != (ip[0] >> 4)) {
                return false;
            }
            const size_t header_len = static_cast<size_t>(ip[0] & 0x0F) * 4;
            if (!IsLegalIpv4HeaderLength(header_len) || header_len > ip_len) {
                return false;
            }
            const uint16_t total_len =
                static_cast<uint16_t>((ip[2] << 8) | ip[3]);
            if (total_len < header_len + kIcmpHeaderLen || total_len > ip_len) {
                return false;
            }
            out_len = total_len - header_len;
            return true;
        }

        void BuildEchoReplyFrame(const uint8_t* request_ip, size_t request_len,
                                 const net::WireMac& gateway_mac,
                                 const net::WireMac& client_mac,
                                 std::vector<uint8_t>& out_frame) {
            IcmpEchoView echo;
            if (!ParseIcmpEcho(request_ip, request_len, echo)) {
                return;
            }
            const uint8_t ihl = request_ip[0] & 0x0F;
            const size_t header_len = static_cast<size_t>(ihl) * 4;
            const size_t icmp_len = kIcmpHeaderLen + echo.payload_len;

            out_frame.resize(net::kEthernetHeaderLen + header_len + icmp_len);
            uint8_t* frame = out_frame.data();

            // Ethernet: reply to the client's MAC from the gateway MAC.
            net::BuildEthHeader(frame, client_mac, gateway_mac, net::kEthertypeIpv4);

            // IPv4: swap addresses; ident/flags/TTL copied, checksum rebuilt.
            uint8_t* ip_out = frame + net::kEthernetHeaderLen;
            std::memcpy(ip_out, request_ip, header_len);
            std::memcpy(ip_out + 12, request_ip + 16, 4);  // src = original dst
            std::memcpy(ip_out + 16, request_ip + 12, 4);  // dst = original src
            ip_out[8] = 63;                                // TTL 64 for local answer
            ip_out[10] = 0;
            ip_out[11] = 0;

            // ICMP: type flips to reply; identifier/sequence/payload copied.
            uint8_t* icmp_out = ip_out + header_len;
            std::memcpy(icmp_out, request_ip + header_len, icmp_len);
            icmp_out[0] = kIcmpEchoReply;
            icmp_out[2] = 0;
            icmp_out[3] = 0;

            // Checksums (ICMP first so the IP header covers the final bytes).
            const uint16_t icmp_ck = net::InternetChecksum(icmp_out, icmp_len);
            icmp_out[2] = static_cast<uint8_t>(icmp_ck >> 8);
            icmp_out[3] = static_cast<uint8_t>(icmp_ck & 0xFF);

            const uint16_t total_len = static_cast<uint16_t>(header_len + icmp_len);
            ip_out[2] = static_cast<uint8_t>(total_len >> 8);
            ip_out[3] = static_cast<uint8_t>(total_len & 0xFF);
            const uint16_t ip_ck = net::InternetChecksum(ip_out, header_len);
            ip_out[10] = static_cast<uint8_t>(ip_ck >> 8);
            ip_out[11] = static_cast<uint8_t>(ip_ck & 0xFF);
        }

        void BuildRelayedEchoReplyFrame(const uint8_t remote_ip[4],
                                        const uint8_t client_ip[4],
                                        const net::WireMac& gateway_mac,
                                        const net::WireMac& client_mac,
                                        uint16_t original_id, uint16_t seq,
                                        const uint8_t* payload,
                                        size_t payload_len,
                                        std::vector<uint8_t>& out_frame) {
            const size_t icmp_len = kIcmpHeaderLen + payload_len;
            out_frame.resize(net::kEthernetHeaderLen + kIpv4HeaderLenMin + icmp_len);
            uint8_t* frame = out_frame.data();
            net::BuildEthHeader(frame, client_mac, gateway_mac, net::kEthertypeIpv4);
            uint8_t* ip = frame + net::kEthernetHeaderLen;
            ip[0] = 0x45;
            const uint16_t total =
                static_cast<uint16_t>(kIpv4HeaderLenMin + icmp_len);
            ip[2] = static_cast<uint8_t>(total >> 8);
            ip[3] = static_cast<uint8_t>(total & 0xFF);
            ip[6] = 0x40;
            ip[8] = 63;   // one hop "consumed" by the gateway
            ip[9] = 1;    // ICMP
            std::memcpy(ip + 12, remote_ip, 4);   // src = pinging host
            std::memcpy(ip + 16, client_ip, 4);   // dst = our client
            uint8_t* icmp = ip + kIpv4HeaderLenMin;
            icmp[0] = kIcmpEchoReply;
            icmp[1] = 0;
            icmp[2] = 0;
            icmp[3] = 0;
            icmp[4] = static_cast<uint8_t>(original_id >> 8);
            icmp[5] = static_cast<uint8_t>(original_id & 0xFF);
            icmp[6] = static_cast<uint8_t>(seq >> 8);
            icmp[7] = static_cast<uint8_t>(seq & 0xFF);
            if (0 != payload_len) {
                std::memcpy(icmp + kIcmpHeaderLen, payload, payload_len);
            }
            const uint16_t icmp_ck = net::InternetChecksum(icmp, icmp_len);
            icmp[2] = static_cast<uint8_t>(icmp_ck >> 8);
            icmp[3] = static_cast<uint8_t>(icmp_ck & 0xFF);
            const uint16_t ip_ck = net::InternetChecksum(ip, kIpv4HeaderLenMin);
            ip[10] = static_cast<uint8_t>(ip_ck >> 8);
            ip[11] = static_cast<uint8_t>(ip_ck & 0xFF);
        }

        bool RelayEchoReplyToClient(const uint8_t* ip, size_t ip_len,
                                    const uint8_t client_ip[4],
                                    const net::WireMac& gateway_mac,
                                    const net::WireMac& client_mac,
                                    uint16_t original_id,
                                    std::vector<uint8_t>& out_frame) {
            out_frame.clear();
            size_t segment_len = 0;
            if (!IcmpSegmentLength(ip, ip_len, segment_len)) {
                return false;
            }
            const size_t header_len =
                static_cast<size_t>(ip[0] & 0x0F) * 4;
            const uint8_t* icmp = ip + header_len;
            if (kIcmpEchoReply != icmp[0]) {
                return false;
            }
            const uint16_t seq =
                static_cast<uint16_t>((icmp[6] << 8) | icmp[7]);
            const uint8_t remote_ip[4] = {ip[12], ip[13], ip[14], ip[15]};
            BuildRelayedEchoReplyFrame(remote_ip, client_ip, gateway_mac,
                                       client_mac, original_id, seq,
                                       icmp + kIcmpHeaderLen,
                                       segment_len - kIcmpHeaderLen,
                                       out_frame);
            return !out_frame.empty();
        }

    }  // namespace proto
}  // namespace vgww
