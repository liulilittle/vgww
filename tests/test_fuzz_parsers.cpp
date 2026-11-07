// ============================================================================
// test_fuzz_parsers.cpp - Deterministic mutation fuzzing of the frame
// parsers (no coverage guidance; fixed seed: every run reproduces).
//
// Seeds are valid ARP / ICMP / DHCP-classified / NDP / IPv6-UDP frames; each
// round applies random mutations (bit flips, truncation, byte overwrites,
// length-field corruption) and feeds the result to EVERY parser entry point.
// Surviving the whole corpus IS the assertion (an OOB read/write kills the
// process); CHECKs pin the classifier's post-conditions and the positive
// controls that prove the corpus still reaches every branch.
// ============================================================================
#include <winsock2.h>
#include <ws2ipdef.h>
#include <windows.h>

#include "bridge/bridge.h"
#include "dsp/classifier.h"
#include "net/eth.h"
#include "proto/arp.h"
#include "proto/dhcp.h"
#include "proto/dhcp6.h"
#include "proto/icmp.h"
#include "proto/ndp.h"
#include "proto/udp.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <optional>
#include <vector>

namespace {

    int g_failures = 0;

    // S3-Task6: per-decision hit counts for the L2 bridge hook below.
    // Indexed by BridgeAction enumerator order; printed at exit and
    // asserted non-zero so the fuzz stream provably reaches every branch.
    long long g_bridge_hits[5] = {0, 0, 0, 0, 0};

#define CHECK(cond)                                                        \
    do {                                                                   \
        if (!(cond)) {                                                     \
            std::fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__,  \
                         __LINE__, #cond);                                 \
            ++g_failures;                                                  \
        }                                                                  \
    } while (0)

    using namespace vgww::net;
    using namespace vgww::proto;

    const WireMac kGatewayMac{0x30, 0xFC, 0x68, 0x88, 0xB4, 0xA9};
    const WireMac kClientMac{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01};
    constexpr uint32_t kGatewayIp =
        (192u) | (0u << 8) | (168u << 16) | (40u << 24);
    constexpr uint32_t kClientIp =
        (192u) | (168u << 8) | (0u << 16) | (101u << 24);
    constexpr uint32_t kRemoteIp =
        (93u) | (184u << 8) | (216u << 16) | (34u << 24);

    // xorshift64*: deterministic, seedable, dependency-free.
    uint64_t g_rng = 0x5EED1234C0FFEE01ull;

    uint64_t NextRandom() {
        uint64_t x = g_rng;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        g_rng = x;
        return x * 0x2545F4914F6CDD1Dull;
    }

    size_t NextBelow(size_t n) {
        return (0 == n) ? 0 : static_cast<size_t>(NextRandom() % n);
    }

    std::vector<std::vector<uint8_t>> BuildSeedCorpus() {
        std::vector<std::vector<uint8_t>> seeds;

        // 1. ARP request for the gateway.
        {
            std::vector<uint8_t> f(kArpFrameLen, 0);
            BuildArpFrame(f.data(), ArpOperation::kRequest, kClientMac,
                          kClientIp, kBroadcastMac, kGatewayIp);
            seeds.push_back(std::move(f));
        }

        // 2. ICMP echo request to the gateway.
        {
            const size_t icmp_len = kIcmpHeaderLen + 32;
            std::vector<uint8_t> f(
                kEthernetHeaderLen + kIpv4HeaderLenMin + icmp_len, 0);
            BuildEthHeader(f.data(), kGatewayMac, kClientMac, kEthertypeIpv4);
            uint8_t* ip = f.data() + kEthernetHeaderLen;
            ip[0] = 0x45;
            const uint16_t total =
                static_cast<uint16_t>(kIpv4HeaderLenMin + icmp_len);
            ip[2] = static_cast<uint8_t>(total >> 8);
            ip[3] = static_cast<uint8_t>(total & 0xFF);
            ip[8] = 64;
            ip[9] = 1;
            std::memcpy(ip + 12, &kClientIp, 4);
            std::memcpy(ip + 16, &kGatewayIp, 4);
            ip[kIpv4HeaderLenMin] = kIcmpEchoRequest;
            seeds.push_back(std::move(f));
        }

        // 3. DHCPv4 DISCOVER: UDP 68 -> 67 (kDhcpV4 classifier branch; the
        //    full DHCP parser returns with S2).
        {
            const uint8_t src_ip[4] = {0, 0, 0, 0};
            const uint8_t dst_ip[4] = {255, 255, 255, 255};
            const uint8_t payload[4] = {1, 1, 6, 0};   // BOOTP op/htype/hlen/hops
            std::vector<uint8_t> f;
            BuildUdpFrame(f, kBroadcastMac, kClientMac, src_ip, 68, dst_ip, 67,
                          payload, sizeof(payload));
            seeds.push_back(std::move(f));
        }

        // 4. NDP neighbor solicitation (built by the product builder).
        {
            const auto ll = LinkLocalFromMac(kGatewayMac);
            std::vector<uint8_t> f;
            BuildNeighborSolicitationFrame(ll.data(), kGatewayMac, ll.data(),
                                           f);
            seeds.push_back(std::move(f));
        }

        // 5. IPv6 UDP (link-local src, multicast dst).
        {
            uint8_t src6[16] = {0xFE, 0x80};
            uint8_t dst6[16] = {0xFF, 0x02};
            const uint8_t payload[8] = {0xDE, 0xAD, 0xBE, 0xEF, 1, 2, 3, 4};
            std::vector<uint8_t> f;
            BuildUdpFrameV6(f, kGatewayMac, kClientMac, src6, 5000, dst6, 5001,
                            payload, sizeof(payload));
            seeds.push_back(std::move(f));
        }

        return seeds;
    }

    // The unmutated seeds must classify as intended (guards against a corpus
    // that silently stops exercising a branch).
    void PositiveControls(const std::vector<std::vector<uint8_t>>& seeds) {
        vgww::dsp::FrameView v;
        CHECK(vgww::dsp::ClassifyFrame(seeds[0].data(), seeds[0].size(), v));
        CHECK(v.cls == vgww::dsp::FrameClass::kArp);
        CHECK(vgww::dsp::ClassifyFrame(seeds[1].data(), seeds[1].size(), v));
        CHECK(v.cls == vgww::dsp::FrameClass::kIcmpV4);
        CHECK(vgww::dsp::ClassifyFrame(seeds[2].data(), seeds[2].size(), v));
        CHECK(v.cls == vgww::dsp::FrameClass::kDhcpV4);
        CHECK(vgww::dsp::ClassifyFrame(seeds[3].data(), seeds[3].size(), v));
        CHECK(v.cls == vgww::dsp::FrameClass::kIcmpV6);
        // Seed #5 is explicitly "IPv6 UDP with a multicast dst" - C9 must
        // keep it OFF the NAT path (no kUdpV6 leak); it is not DHCPv6.
        CHECK(vgww::dsp::ClassifyFrame(seeds[4].data(), seeds[4].size(), v));
        CHECK(v.cls == vgww::dsp::FrameClass::kOther);
    }

    void Mutate(std::vector<uint8_t>& frame) {
        const int op = static_cast<int>(NextBelow(4));
        switch (op) {
            case 0: {   // random bit flips
                const size_t flips = 1 + NextBelow(8);
                for (size_t i = 0; i < flips && !frame.empty(); ++i) {
                    frame[NextBelow(frame.size())] ^=
                        static_cast<uint8_t>(1u << NextBelow(8));
                }
                break;
            }
            case 1: {   // truncation
                if (frame.size() > 1) {
                    frame.resize(NextBelow(frame.size()));
                }
                break;
            }
            case 2: {   // overwrite with extreme bytes
                if (!frame.empty()) {
                    static const uint8_t kBytes[4] = {0x00, 0xFF, 0x7F, 0x80};
                    const size_t writes = 1 + NextBelow(4);
                    for (size_t i = 0; i < writes; ++i) {
                        frame[NextBelow(frame.size())] = kBytes[NextBelow(4)];
                    }
                }
                break;
            }
            default: {  // corrupt length-ish fields
                if (frame.size() >= kEthernetHeaderLen + 20) {
                    uint8_t* ip = frame.data() + kEthernetHeaderLen;
                    ip[2] = static_cast<uint8_t>(NextRandom());
                    ip[3] = static_cast<uint8_t>(NextRandom());
                    const size_t ihl =
                        static_cast<size_t>(ip[0] & 0x0F) * 4;
                    if (ihl >= 20 &&
                        frame.size() >= kEthernetHeaderLen + ihl + 8) {
                        uint8_t* udp = ip + ihl;
                        udp[4] = static_cast<uint8_t>(NextRandom());
                        udp[5] = static_cast<uint8_t>(NextRandom());
                    }
                }
                break;
            }
        }
    }

    void FuzzRound(std::vector<uint8_t> frame) {
        const uint8_t* data = frame.data();
        const size_t len = frame.size();

        vgww::dsp::FrameView view;
        if (vgww::dsp::ClassifyFrame(data, len, view)) {
            // Post-conditions of the classifier contract: no returned view
            // may point outside the frame it classified.
            CHECK(view.ip_offset <= len);
            CHECK(view.l4_offset <= len);
            CHECK(view.ip_offset <= view.l4_offset);
            CHECK(view.ip_len <= len - view.ip_offset);
        }

        // Feed every parser directly; over-reads are what the fuzzer hunts.
        ArpView arp{};
        (void)ParseArpFrame(data, len, arp);
        IcmpEchoView echo{};
        if (len >= kIpv4HeaderLenMin) {
            (void)ParseIcmpEcho(data, len, echo);
            (void)ParseIcmpEcho(data + kEthernetHeaderLen,
                                len - kEthernetHeaderLen, echo);
        }
        UdpView udp{};
        (void)ParseUdp(data, len, udp);
        if (len >= kUdpHeaderLen) {
            (void)ParseUdp(data + len - kUdpHeaderLen, kUdpHeaderLen, udp);
        }

        // DHCPv4 (Task 3) and DHCPv6 (Task 7) parsers: the same mutation
        // stream must never make them read past the frame. A successful
        // parse must describe a real client message inside the frame.
        DhcpView dhcp{};
        const bool dhcp_ok = ParseDhcpFrame(data, len, dhcp);
        if (dhcp_ok) {
            CHECK(len >= kDhcpFrameMin);
            CHECK(1 == dhcp.op);
        }
        Dhcp6View dhcp6{};
        const bool dhcp6_ok = ParseDhcp6Frame(data, len, dhcp6);
        if (dhcp6_ok) {
            CHECK(len >= kDhcp6FrameMin);
            const bool client_msg =
                kDhcp6MsgSolicit == dhcp6.msg_type ||
                kDhcp6MsgRequest == dhcp6.msg_type ||
                kDhcp6MsgConfirm == dhcp6.msg_type ||
                kDhcp6MsgRenew == dhcp6.msg_type ||
                kDhcp6MsgRebind == dhcp6.msg_type ||
                kDhcp6MsgRelease == dhcp6.msg_type ||
                kDhcp6MsgDecline == dhcp6.msg_type ||
                kDhcp6MsgInformationRequest == dhcp6.msg_type;
            CHECK(client_msg);
        }

        // L2 bridge decision (S3-Task6): the same mutation stream feeds the
        // pure DecideBridgeAction. The call must never crash, must return a
        // valid enumerator, and must drop short frames without touching the
        // frame body. known_port alternates on frame length parity so both
        // the unicast and flood branches are exercised without perturbing
        // the shared RNG stream.
        {
            bool group = false;
            if (len >= kMacAddrLen) {
                WireMac dst{};
                std::memcpy(dst.data(), data, kMacAddrLen);
                // batch240: this must use the SAME predicate the production
                // path uses. LearnAndDecide computes IsGroupAddress(dst), so a
                // hand-rolled "broadcast || 33:33 prefix" fuzzed a group value
                // the product never produces for IPv4 multicast
                // (01:00:5E:xx:xx:xx) - the fuzz fed group=false where the
                // real path passes true.
                group = IsGroupAddress(dst);
            }
            const std::optional<uint32_t> known =
                (0 == (len & 1)) ? std::optional<uint32_t>(1) : std::nullopt;
            const vgww::bridge::BridgeAction action =
                vgww::bridge::DecideBridgeAction(data, len, kGatewayMac,
                                                 group, known);
            switch (action) {
                case vgww::bridge::BridgeAction::kControlOnly:
                    ++g_bridge_hits[0];
                    break;
                case vgww::bridge::BridgeAction::kControlAndFlood:
                    ++g_bridge_hits[1];
                    break;
                case vgww::bridge::BridgeAction::kBridgeUnicast:
                    ++g_bridge_hits[2];
                    break;
                case vgww::bridge::BridgeAction::kBridgeFlood:
                    ++g_bridge_hits[3];
                    break;
                case vgww::bridge::BridgeAction::kDrop:
                    ++g_bridge_hits[4];
                    break;
                default:
                    CHECK(false);
                    break;
            }
            if (len < kEthernetHeaderLen) {
                CHECK(vgww::bridge::BridgeAction::kDrop == action);
            }
        }
    }

}  // namespace

int main() {
    const auto seeds = BuildSeedCorpus();
    PositiveControls(seeds);

    constexpr int kRounds = 20000;
    for (int round = 0; round < kRounds; ++round) {
        std::vector<uint8_t> frame = seeds[NextBelow(seeds.size())];
        const size_t mutations = 1 + NextBelow(3);
        for (size_t i = 0; i < mutations; ++i) {
            Mutate(frame);
        }
        FuzzRound(std::move(frame));
    }

    if (0 == g_failures) {
        std::printf("test_fuzz_parsers: %d deterministic rounds, ALL PASS\n",
                    kRounds);
        std::printf(
            "test_fuzz_parsers: bridge decisions "
            "control=%lld both=%lld unicast=%lld flood=%lld drop=%lld\n",
            g_bridge_hits[0], g_bridge_hits[1], g_bridge_hits[2],
            g_bridge_hits[3], g_bridge_hits[4]);
        for (int i = 0; i < 5; ++i) {
            CHECK(g_bridge_hits[i] > 0);
        }
        if (0 == g_failures) {
            return 0;
        }
    }
    std::fprintf(stderr, "test_fuzz_parsers: %d FAILURES\n", g_failures);
    return 1;
}
