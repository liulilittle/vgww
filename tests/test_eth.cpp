// ============================================================================
// test_eth.cpp - Ethernet II header parse/build + MAC predicates (net/eth.h).
//
// eth.h is the first thing every received frame touches. Its 104 lines had no
// dedicated test: the helpers were exercised only through protocol tests, and
// two of them (IsIpv6MulticastMac, IsBroadcast) are not called from src/ at
// all, so nothing pinned their behaviour.
//
// The load-bearing contracts:
//   * 14-byte header: dst(6) | src(6) | EtherType(2, big-endian)
//   * 802.1Q adds a 4-byte tag => 18-byte base header
//   * the group bit is bit 0 of the first octet (IEEE 802)
// ============================================================================
#define CHECK(cond)                                                        \
    do {                                                                   \
        if (!(cond)) {                                                     \
            std::fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__,  \
                         __LINE__, #cond);                                 \
            return 1;                                                      \
        }                                                                  \
    } while (0)

#include "net/eth.h"

#include <cstdio>
#include <cstring>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace vgww {

    /// Parse must read the three fields at the documented offsets, and must
    /// report the EtherType in HOST byte order (the header says so).
    int TestParseLayout() {
        uint8_t frame[14] = {};
        const uint8_t dst[6] = {0x30, 0xFC, 0x68, 0x88, 0xB4, 0xA9};
        const uint8_t src[6] = {0x02, 0x00, 0x5A, 0x00, 0x00, 0x01};
        std::memcpy(frame, dst, 6);
        std::memcpy(frame + 6, src, 6);
        frame[12] = 0x08;
        frame[13] = 0x00;

        net::EthHeaderView view;
        CHECK(net::ParseEthHeader(frame, sizeof(frame), view));
        CHECK(0 == std::memcmp(view.dst.data(), dst, 6));
        CHECK(0 == std::memcmp(view.src.data(), src, 6));
        CHECK(net::kEthertypeIpv4 == view.ethertype);

        // Big-endian read: 0x86DD is IPv6, NOT 0xDD86.
        frame[12] = 0x86;
        frame[13] = 0xDD;
        CHECK(net::ParseEthHeader(frame, sizeof(frame), view));
        CHECK(net::kEthertypeIpv6 == view.ethertype);
        CHECK(0xDD86 != view.ethertype);
        return 0;
    }

    /// A buffer shorter than 14 bytes must be rejected at every length, and the
    /// output must not be consulted. 13 bytes is the boundary.
    int TestParseLengthBoundary() {
        uint8_t frame[16] = {};
        frame[12] = 0x08;
        frame[13] = 0x06;
        net::EthHeaderView view;

        for (size_t len = 0; len < net::kEthernetHeaderLen; ++len) {
            view = net::EthHeaderView{};
            CHECK(!net::ParseEthHeader(frame, len, view));
        }
        CHECK(net::ParseEthHeader(frame, net::kEthernetHeaderLen, view));
        CHECK(net::kEthertypeArp == view.ethertype);
        CHECK(net::ParseEthHeader(frame, sizeof(frame), view));
        return 0;
    }

    /// Build and Parse must be exact inverses, including the EtherType.
    int TestBuildParseRoundTrip() {
        const net::WireMac dst = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
        const net::WireMac src = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
        const uint16_t types[] = {net::kEthertypeIpv4, net::kEthertypeArp,
                                  net::kEthertypeIpv6, net::kEthertypeVlan8021Q,
                                  0x0000, 0xFFFF};
        for (uint16_t t : types) {
            uint8_t out[14] = {};
            net::BuildEthHeader(out, dst, src, t);
            net::EthHeaderView view;
            CHECK(net::ParseEthHeader(out, sizeof(out), view));
            CHECK(view.dst == dst);
            CHECK(view.src == src);
            CHECK(view.ethertype == t);
        }
        return 0;
    }

    /// The group bit is bit 0 of octet 0 (IEEE 802). Every family below must be
    /// recognised, and unicast must not be.
    int TestGroupAddressPredicate() {
        struct Case {
            net::WireMac mac;
            bool group;
        };
        const Case cases[] = {
            {{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, true},   // broadcast
            {{0x33, 0x33, 0x00, 0x00, 0x00, 0x01}, true},   // IPv6 multicast
            {{0x01, 0x00, 0x5E, 0x00, 0x00, 0x01}, true},   // IPv4 multicast
            {{0x01, 0x80, 0xC2, 0x00, 0x00, 0x00}, true},   // STP
            {{0x01, 0x00, 0x0C, 0xCC, 0xCC, 0xCC}, true},   // CDP
            {{0x30, 0xFC, 0x68, 0x88, 0xB4, 0xA9}, false},  // unicast
            {{0x02, 0x00, 0x5A, 0x00, 0x00, 0x01}, false},  // unicast
            {{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, false},  // all-zero
            {{0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, false},  // 0xFE has bit0 clear
        };
        for (const auto& c : cases) {
            CHECK(net::IsGroupAddress(c.mac) == c.group);
        }
        return 0;
    }

    /// IsBroadcast must accept exactly ff:ff:ff:ff:ff:ff.
    int TestIsBroadcast() {
        CHECK(net::IsBroadcast(net::kBroadcastMac));
        const net::WireMac not_bcast[] = {
            {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE},
            {0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
            {0x33, 0x33, 0x00, 0x00, 0x00, 0x01},
            {0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
        };
        for (const auto& m : not_bcast) {
            CHECK(!net::IsBroadcast(m));
        }
        return 0;
    }

    /// IsIpv6MulticastMac accepts the 33:33 prefix only.
    int TestIsIpv6MulticastMac() {
        CHECK(net::IsIpv6MulticastMac(net::WireMac{0x33, 0x33, 0x00, 0x00, 0x00, 0x01}));
        CHECK(net::IsIpv6MulticastMac(net::WireMac{0x33, 0x33, 0xFF, 0x11, 0x22, 0x33}));
        CHECK(!net::IsIpv6MulticastMac(net::WireMac{0x33, 0x34, 0x00, 0x00, 0x00, 0x01}));
        CHECK(!net::IsIpv6MulticastMac(net::WireMac{0x01, 0x00, 0x5E, 0x00, 0x00, 0x01}));
        CHECK(!net::IsIpv6MulticastMac(net::kBroadcastMac));
        return 0;
    }

    /// WireMacHash must satisfy the one container property: equal keys hash
    /// equally. It must also spread distinct MACs (a constant hash would turn
    /// every lookup into a linear scan).
    int TestWireMacHash() {
        const net::WireMacHash hash;
        const net::WireMac a = {0x30, 0xFC, 0x68, 0x88, 0xB4, 0xA9};
        const net::WireMac a2 = {0x30, 0xFC, 0x68, 0x88, 0xB4, 0xA9};
        const net::WireMac b = {0x30, 0xFC, 0x68, 0x88, 0xB4, 0xAA};
        CHECK(a == a2);
        CHECK(hash(a) == hash(a2));
        CHECK(a != b);
        CHECK(hash(a) != hash(b));

        // Single-bit difference in the FIRST octet must also change the hash.
        const net::WireMac c = {0x31, 0xFC, 0x68, 0x88, 0xB4, 0xA9};
        CHECK(hash(a) != hash(c));

        // Real container round-trip over 128 distinct MACs.
        std::unordered_set<net::WireMac, net::WireMacHash> set;
        for (int i = 0; i < 128; ++i) {
            net::WireMac m = {0x02, 0x00, 0x00, 0x00, 0x00,
                              static_cast<uint8_t>(i)};
            set.insert(m);
        }
        CHECK(128 == set.size());
        return 0;
    }

    /// The VLAN constants must describe the actual 802.1Q layout: a tagged
    /// frame's EtherType sits at the same offset, and the base header grows by
    /// exactly the 4-byte tag.
    int TestVlanConstants() {
        // Compare through volatile locals so the constant folds do not trip
        // C4127 (both sides are compile-time constants otherwise).
        const volatile size_t eth_len = net::kEthernetHeaderLen;
        const volatile size_t mac_len = net::kMacAddrLen;
        const volatile size_t tag_len = net::kVlanTagLen;
        const volatile size_t vlan_len = net::kVlanEthernetHeaderLen;
        CHECK(14 == eth_len);
        CHECK(6 == mac_len);
        CHECK(4 == tag_len);
        CHECK(18 == vlan_len);
        CHECK(static_cast<size_t>(eth_len) + static_cast<size_t>(tag_len) ==
              static_cast<size_t>(vlan_len));

        // A VLAN frame carries 0x8100 where an untagged frame carries the
        // payload EtherType; Parse must surface it as-is.
        uint8_t frame[18] = {};
        frame[12] = 0x81;
        frame[13] = 0x00;
        frame[16] = 0x08;   // inner EtherType after TCI
        frame[17] = 0x00;
        net::EthHeaderView view;
        CHECK(net::ParseEthHeader(frame, sizeof(frame), view));
        CHECK(net::kEthertypeVlan8021Q == view.ethertype);
        return 0;
    }

}  // namespace vgww

int main() {
    if (vgww::TestParseLayout()) return 1;
    if (vgww::TestParseLengthBoundary()) return 1;
    if (vgww::TestBuildParseRoundTrip()) return 1;
    if (vgww::TestGroupAddressPredicate()) return 1;
    if (vgww::TestIsBroadcast()) return 1;
    if (vgww::TestIsIpv6MulticastMac()) return 1;
    if (vgww::TestWireMacHash()) return 1;
    if (vgww::TestVlanConstants()) return 1;
    std::puts("test_eth: ALL PASS");
    return 0;
}
