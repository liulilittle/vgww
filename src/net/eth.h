// ============================================================================
// eth.h - Ethernet II header parse/build helpers.
//
// Frames on the wire (and inside INTERMEDIATE_BUFFER.m_IBuffer) start with
// the 14-byte Ethernet II header: dst MAC(6) | src MAC(6) | EtherType(2).
// IEEE 802.3 LLC frames (EtherType < 1500) are not used by any VGWW code
// path and are classified as kOther.
// ============================================================================
#pragma once

#include <array>
#include <cstdint>
#include <cstring>

namespace vgww {
    namespace net {

        inline constexpr size_t kEthernetHeaderLen = 14;
        inline constexpr size_t kMacAddrLen = 6;

        inline constexpr uint16_t kEthertypeIpv4 = 0x0800;
        inline constexpr uint16_t kEthertypeArp = 0x0806;
        inline constexpr uint16_t kEthertypeIpv6 = 0x86DD;
        inline constexpr uint16_t kEthertypeVlan8021Q = 0x8100;

        /// An 802.1Q tag is TPID(2) + TCI(2) = 4 bytes after the 14-byte
        /// Ethernet header; a tagged frame has an 18-byte base header.
        inline constexpr size_t kVlanTagLen = 4;
        inline constexpr size_t kVlanEthernetHeaderLen =
            kEthernetHeaderLen + kVlanTagLen;

        typedef std::array<uint8_t, kMacAddrLen> WireMac;

        /// Broadcast MAC ff:ff:ff:ff:ff:ff.
        inline constexpr WireMac kBroadcastMac = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

        /// IPv6 all-nodes/NDP multicast prefix 33:33:*.
        inline constexpr std::array<uint8_t, 2> kIpv6MulticastMacPrefix = {0x33, 0x33};

        /// Hash for associative containers keyed by MAC.
        struct WireMacHash {
            size_t operator()(const WireMac& mac) const noexcept {
                uint64_t h = 0xcbf29ce484222325ull;
                for (uint8_t byte : mac) {
                    h ^= byte;
                    h *= 1099511628211ull;
                }
                return static_cast<size_t>(h);
            }
        };

        struct EthHeaderView final {
            WireMac dst{};
            WireMac src{};
            uint16_t ethertype = 0;  ///< host byte order
        };

        /// Parses a big-endian Ethernet II header. Returns false only when the
        /// buffer is shorter than 14 bytes. The EtherType is returned, NOT
        /// validated: an 802.3 LLC frame (EtherType < 1500) parses
        /// successfully and callers must classify it themselves (classifier.cpp
        /// maps unknown types to kOther; arp.cpp/dhcp.cpp/dhcp6.cpp compare
        /// against the specific type they expect).
        inline bool ParseEthHeader(const uint8_t* data, size_t len,
                                   EthHeaderView& out) noexcept {
            if (len < kEthernetHeaderLen) {
                return false;
            }
            std::memcpy(out.dst.data(), data, kMacAddrLen);
            std::memcpy(out.src.data(), data + 6, kMacAddrLen);
            out.ethertype = static_cast<uint16_t>((data[12] << 8) | data[13]);
            return true;
        }

        /// Writes a 14-byte Ethernet II header into `out`.
        inline void BuildEthHeader(uint8_t* out, const WireMac& dst,
                                   const WireMac& src, uint16_t ethertype) noexcept {
            std::memcpy(out, dst.data(), kMacAddrLen);
            std::memcpy(out + 6, src.data(), kMacAddrLen);
            out[12] = static_cast<uint8_t>(ethertype >> 8);
            out[13] = static_cast<uint8_t>(ethertype & 0xFF);
        }

        inline bool IsBroadcast(const WireMac& mac) noexcept {
            return mac == kBroadcastMac;
        }

        inline bool IsIpv6MulticastMac(const WireMac& mac) noexcept {
            return mac[0] == kIpv6MulticastMacPrefix[0] &&
                   mac[1] == kIpv6MulticastMacPrefix[1];
        }

        /// True for ANY Ethernet group address: the group bit is bit 0 of the
        /// first octet (IEEE 802). This covers broadcast (ff:ff:ff:ff:ff:ff),
        /// IPv6 multicast (33:33:xx:xx:xx:xx), IPv4 multicast
        /// (01:00:5e:xx:xx:xx) and every other group MAC.
        ///
        /// batch34w: the per-feature helpers above invite partial tests -
        /// code that checked only broadcast + IPv6 multicast silently treated
        /// IPv4 multicast (IGMP, mDNS, SSDP) as ordinary unicast. Anything
        /// that needs "is this a group address" must use THIS predicate; the
        /// narrower helpers stay for callers that genuinely need one family.
        inline bool IsGroupAddress(const WireMac& mac) noexcept {
            return 0 != (mac[0] & 0x01);
        }

    }  // namespace net
}  // namespace vgww
