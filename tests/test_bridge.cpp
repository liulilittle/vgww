// ============================================================================
// test_bridge.cpp - Built-in L2 bridge tests (S3).
//
// Task 1: driver-layer HwPacketFilter API. The NDIS OID exchange itself is
// driver-internal (no kernel driver in CI); these tests pin the IDriverClient
// contract with an in-memory fake: set/get round trip, default readback, and
// failure propagation.
// Task 2: MAC table + forwarding decision (headless).
// Task 3: bridge loop + dataplane integration + lifecycle/fault handling.
// The dual-adapter fake below drives the real Dataplane verbatim: frames
// injected on port A must surface on port B and vice versa, while gateway
// and control-plane semantics stay intact.
// ============================================================================
#include <winsock2.h>
#include <ws2ipdef.h>
#include <windows.h>

#include <asio.hpp>

#include "bridge/bridge.h"
#include "driver/idriver_client.h"
#include "driver/ndisrd_client.h"
#include "ndisapi/Common.h"
#include "net/checksum.h"
#include "net/eth.h"
#include "proto/arp.h"
#include "proto/udp.h"
#include "runtime/dataplane.h"

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <deque>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace {

    int g_failures = 0;

#define CHECK(cond)                                                        \
    do {                                                                   \
        if (!(cond)) {                                                     \
            std::fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__,  \
                         __LINE__, #cond);                                 \
            ++g_failures;                                                  \
        }                                                                  \
    } while (0)

    using vgww::driver::AdapterEntry;
    using vgww::driver::IDriverClient;

    /// NDIS packet filter bit enabling promiscuous reception
    /// (WDK ntddndis.h; used by the official ethernet_bridge example).
    constexpr uint32_t kPromiscuous = 0x00000020;

    /// Minimal in-memory driver double for the filter surface.
    class FakeDriverClient final : public IDriverClient {
    public:
        FakeDriverClient() {
            AdapterEntry entry;
            entry.name = L"\\\\TestNIC";
            entry.handle = this;
            entry.mtu = 1500;
            adapters_.push_back(entry);
        }

        void FailHwFilterSet(bool fail) { fail_hw_filter_set_ = fail; }
        uint32_t last_hw_filter() const { return hw_filter_; }

        // ----- IDriverClient ---------------------------------------------
        const std::vector<AdapterEntry>& Adapters() const noexcept override {
            return adapters_;
        }

        const AdapterEntry* FindAdapter(
            const std::wstring& hint,
            bool* out_ambiguous = nullptr) const noexcept override {
            bool amb = false;
            const int idx = vgww::driver::MatchAdapterEntry(
                adapters_, hint, std::wstring(), &amb);
            if (nullptr != out_ambiguous) {
                *out_ambiguous = amb;
            }
            return idx < 0 ? nullptr : &adapters_[static_cast<size_t>(idx)];
        }

        bool SetAdapterMode(const AdapterEntry&, uint32_t,
                            std::string&) override {
            return true;
        }

        bool ArmRxEvent(const AdapterEntry&, void*, std::string&) override {
            return true;
        }

        uint32_t ReadPackets(void*, INTERMEDIATE_BUFFER*, uint32_t,
                             std::string&) override {
            return 0;
        }

        bool SendPacketsToAdapter(void*, INTERMEDIATE_BUFFER*, uint32_t,
                                  std::string&) override {
            return true;
        }

        bool SendPacketsToMstcp(void*, INTERMEDIATE_BUFFER*, uint32_t,
                                std::string&) override {
            return true;
        }

        bool FlushAdapterQueue(const AdapterEntry&, std::string&) override {
            return true;
        }

        bool ResetAdapterMode(const AdapterEntry&, std::string&) override {
            return true;
        }

        bool SetHwPacketFilter(const AdapterEntry& adapter, uint32_t filter,
                               std::string& error) override {
            if (nullptr == adapter.handle) {
                error = "adapter handle is null";
                return false;
            }
            if (fail_hw_filter_set_) {
                error = "injected hw filter failure";
                return false;
            }
            hw_filter_ = filter;
            return true;
        }

        bool GetHwPacketFilter(const AdapterEntry& adapter, uint32_t& filter,
                               std::string& error) override {
            if (nullptr == adapter.handle) {
                error = "adapter handle is null";
                return false;
            }
            filter = hw_filter_;
            return true;
        }

    private:
        std::vector<AdapterEntry> adapters_;
        uint32_t hw_filter_ = 0;
        bool fail_hw_filter_set_ = false;
    };

    /// Set then get must round-trip the exact filter value.
    void TestSetHwPacketFilterRoundTrip() {
        FakeDriverClient fake;
        const AdapterEntry& adapter = fake.Adapters().front();
        std::string error;
        CHECK(fake.SetHwPacketFilter(adapter, kPromiscuous, error));
        CHECK(error.empty());
        uint32_t readback = 0;
        CHECK(fake.GetHwPacketFilter(adapter, readback, error));
        CHECK(readback == kPromiscuous);
        CHECK(fake.last_hw_filter() == kPromiscuous);
        // Re-setting is a plain overwrite (idempotent).
        CHECK(fake.SetHwPacketFilter(adapter, 0, error));
        CHECK(fake.GetHwPacketFilter(adapter, readback, error));
        CHECK(readback == 0);
    }

    /// Before any set, get reports the fake's original filter (zero).
    void TestGetHwPacketFilterDefault() {
        FakeDriverClient fake;
        const AdapterEntry& adapter = fake.Adapters().front();
        uint32_t readback = 0xFFFFFFFF;
        std::string error;
        CHECK(fake.GetHwPacketFilter(adapter, readback, error));
        CHECK(error.empty());
        CHECK(readback == 0);
        CHECK(fake.last_hw_filter() == 0);
    }

    /// Injected set failure must surface as false + error and leave the
    /// stored filter untouched (callers must not assume restore).
    void TestSetHwPacketFilterFailurePropagates() {
        FakeDriverClient fake;
        const AdapterEntry& adapter = fake.Adapters().front();
        std::string error;
        CHECK(fake.SetHwPacketFilter(adapter, kPromiscuous, error));
        CHECK(error.empty());

        fake.FailHwFilterSet(true);
        error.clear();
        CHECK(!fake.SetHwPacketFilter(adapter, 0, error));
        CHECK(!error.empty());
        CHECK(fake.last_hw_filter() == kPromiscuous);

        uint32_t readback = 0;
        CHECK(fake.GetHwPacketFilter(adapter, readback, error));
        CHECK(readback == kPromiscuous);
    }

    // ----- Task 2: MAC table + forwarding decision -----------------------

    using vgww::bridge::BridgeAction;
    using vgww::bridge::DecideBridgeAction;
    using vgww::bridge::MacTable;
    using vgww::net::WireMac;

    /// Unicast test MAC 02:00:00:00:00:XX.
    WireMac Mac(uint8_t last) {
        return WireMac{0x02, 0x00, 0x00, 0x00, 0x00, last};
    }

    std::array<uint8_t, vgww::net::kEthernetHeaderLen> FrameTo(
        const WireMac& dst) {
        std::array<uint8_t, vgww::net::kEthernetHeaderLen> frame{};
        std::memcpy(frame.data(), dst.data(), vgww::net::kMacAddrLen);
        return frame;
    }

    /// A learned source MAC resolves to the port it arrived on.
    void TestMacLearnAndLookup() {
        MacTable table;
        const WireMac a = Mac(0x01);
        table.Learn(a, 1, MacTable::TimePoint{});
        const std::optional<uint32_t> port = table.Lookup(a);
        CHECK(port.has_value());
        CHECK(port.value() == 1);
        CHECK(table.Size() == 1);
        CHECK(table.Capacity() == 4096);
    }

    /// MACs never learned must miss.
    void TestMacUnknownIsMiss() {
        MacTable table;
        CHECK(!table.Lookup(Mac(0x02)).has_value());
    }

    /// Over capacity the oldest entry is evicted; re-learning a known MAC
    /// refreshes it without growing the table.
    void TestMacTableCapEvictsOldest() {
        MacTable table(4);
        CHECK(table.Capacity() == 4);
        const auto t0 = MacTable::TimePoint{};
        table.Learn(Mac(0x10), 1, t0 + std::chrono::seconds(1));
        table.Learn(Mac(0x11), 2, t0 + std::chrono::seconds(2));
        table.Learn(Mac(0x12), 3, t0 + std::chrono::seconds(3));
        table.Learn(Mac(0x13), 4, t0 + std::chrono::seconds(4));
        // Refresh the oldest so it is no longer the eviction candidate.
        table.Learn(Mac(0x10), 1, t0 + std::chrono::seconds(5));
        table.Learn(Mac(0x14), 5, t0 + std::chrono::seconds(6));
        CHECK(table.Size() == 4);
        CHECK(!table.Lookup(Mac(0x11)).has_value());  // oldest (t=2s) evicted
        CHECK(table.Lookup(Mac(0x10)).value() == 1);  // refreshed, kept
        CHECK(table.Lookup(Mac(0x14)).value() == 5);
        // batch34h: the eviction must be COUNTED. An evicted MAC loses its
        // port mapping, so its traffic floods until it speaks again - a real
        // behaviour change that used to be invisible to the operator.
        CHECK(table.Evictions() == 1);
        // Same-MAC re-learn does not grow the table and is NOT an eviction.
        table.Learn(Mac(0x14), 5, t0 + std::chrono::seconds(7));
        CHECK(table.Size() == 4);
        CHECK(table.Evictions() == 1);
        // A second overflow counts again.
        table.Learn(Mac(0x15), 6, t0 + std::chrono::seconds(8));
        CHECK(table.Size() == 4);
        CHECK(table.Evictions() == 2);
    }

    /// Entries older than the aging window are removed; fresh ones survive.
    void TestMacTableAging() {
        MacTable table;
        const auto t0 = MacTable::TimePoint{};
        table.Learn(Mac(0x20), 1, t0);
        table.Learn(Mac(0x21), 2, t0 + std::chrono::seconds(5));
        const size_t removed = table.Age(t0 + std::chrono::seconds(11),
                                         std::chrono::seconds(10));
        CHECK(removed == 1);
        CHECK(!table.Lookup(Mac(0x20)).has_value());
        CHECK(table.Lookup(Mac(0x21)).value() == 2);
        CHECK(table.Size() == 1);
    }

    /// batch256: Age's comparison is STRICT ("older than max_age"), so an entry
    /// that is EXACTLY max_age old survives. Pinning the boundary keeps a
    /// ">= \" rewrite from ageing a device out one tick early.
    void TestMacTableAgingBoundaryIsStrict() {
        MacTable table;
        const auto t0 = MacTable::TimePoint{};
        table.Learn(Mac(0x30), 1, t0);

        // Exactly max_age -> still present.
        CHECK(table.Age(t0 + std::chrono::seconds(10),
                        std::chrono::seconds(10)) == 0);
        CHECK(table.Lookup(Mac(0x30)).has_value());
        CHECK(table.Size() == 1);

        // One tick past max_age -> removed.
        CHECK(table.Age(t0 + std::chrono::seconds(10) +
                            MacTable::Duration(std::chrono::nanoseconds(1)),
                        std::chrono::seconds(10)) == 1);
        CHECK(!table.Lookup(Mac(0x30)).has_value());
    }

    /// Frames addressed to the gateway MAC stay on the control plane only.
    void TestDecideGatewayMacControlOnly() {
        const WireMac gateway = Mac(0x30);
        const auto frame = FrameTo(gateway);
        CHECK(DecideBridgeAction(frame.data(), frame.size(), gateway, false,
                                 std::nullopt) == BridgeAction::kControlOnly);
        CHECK(DecideBridgeAction(frame.data(), frame.size(), gateway, false,
                                 uint32_t{2}) == BridgeAction::kControlOnly);
    }

    /// batch256: the gateway-MAC test runs BEFORE the group test, so a frame
    /// addressed to the gateway is control-only even if the caller's
    /// is_multicast_or_broadcast flag is (wrongly) true. DecideBridgeAction is
    /// pure and its caller computes that flag from the same destination, but
    /// the precedence is part of the contract: a gateway-addressed frame must
    /// never be flooded back onto the wire.
    void TestDecideGatewayMacOutranksTheGroupFlag() {
        const WireMac gateway = Mac(0x31);
        const auto frame = FrameTo(gateway);
        CHECK(DecideBridgeAction(frame.data(), frame.size(), gateway, true,
                                 std::nullopt) == BridgeAction::kControlOnly);
        CHECK(DecideBridgeAction(frame.data(), frame.size(), gateway, true,
                                 uint32_t{1}) == BridgeAction::kControlOnly);
        // Contrast: a non-gateway destination with the same flag floods.
        const auto other = FrameTo(Mac(0x32));
        CHECK(DecideBridgeAction(other.data(), other.size(), gateway, true,
                                 std::nullopt) ==
              BridgeAction::kControlAndFlood);
    }

    /// Broadcast and IPv6 multicast frames are delivered to both the control
    /// plane and the bridge flood path.
    void TestDecideBroadcastAndMulticastBothPaths() {
        const WireMac gateway = Mac(0x30);
        const auto bcast = FrameTo(vgww::net::kBroadcastMac);
        CHECK(DecideBridgeAction(bcast.data(), bcast.size(), gateway, true,
                                 std::nullopt) ==
              BridgeAction::kControlAndFlood);
        const WireMac mcast = WireMac{0x33, 0x33, 0x00, 0x00, 0x00, 0x01};
        const auto mframe = FrameTo(mcast);
        CHECK(DecideBridgeAction(mframe.data(), mframe.size(), gateway, true,
                                 std::nullopt) ==
              BridgeAction::kControlAndFlood);
    }

    /// batch34w: EVERY Ethernet group address must reach both paths.
    ///
    /// The group bit is bit 0 of the first octet, so 01:00:5E:xx:xx:xx
    /// (IPv4 multicast: mDNS 224.0.0.251, SSDP 239.255.255.250, IGMP) is a
    /// group address exactly like 33:33:xx (IPv6) and ff:ff:ff:ff:ff:ff.
    /// LearnAndDecide used to test only broadcast and the 33:33 prefix, so an
    /// IPv4 multicast frame fell through to "unknown unicast" and was flooded
    /// to the peer WITHOUT reaching the control plane - the gateway never saw
    /// IGMP membership reports, mDNS queries or SSDP discovery on the bridged
    /// segment, and those services silently stopped working.
    ///
    /// MacTable::Learn already refuses every group source via `mac[0] & 0x01`;
    /// the decision path must use the same rule.
    void TestLearnAndDecideTreatsAllGroupMacsAsFlood() {
        const WireMac gateway = Mac(0x30);
        MacTable table;
        std::mutex table_mutex;

        struct Case {
            const char* name;
            WireMac dst;
        };
        const Case cases[] = {
            {"broadcast", WireMac{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}},
            {"ipv6 multicast", WireMac{0x33, 0x33, 0x00, 0x00, 0x00, 0x01}},
            {"ipv4 multicast", WireMac{0x01, 0x00, 0x5E, 0x00, 0x00, 0xFB}},
            {"ipv4 multicast low", WireMac{0x01, 0x00, 0x5E, 0x7F, 0xFF, 0xFA}},
        };
        for (const Case& c : cases) {
            std::array<uint8_t, vgww::net::kEthernetHeaderLen> frame{};
            std::memcpy(frame.data(), c.dst.data(), vgww::net::kMacAddrLen);
            // A unicast source so the learn step has something to record.
            const WireMac src = Mac(0x11);
            std::memcpy(frame.data() + vgww::net::kMacAddrLen, src.data(),
                        vgww::net::kMacAddrLen);
            const BridgeAction action = LearnAndDecide(
                table, table_mutex, frame.data(), frame.size(),
                vgww::bridge::kBridgePortUp, gateway);
            if (BridgeAction::kControlAndFlood != action) {
                std::fprintf(stderr,
                             "CHECK failed: %s must be kControlAndFlood\n",
                             c.name);
                ++g_failures;
            }
        }

        // A group source MAC is never learned (same rule as MacTable::Learn).
        std::array<uint8_t, vgww::net::kEthernetHeaderLen> group_src{};
        const WireMac unicast_dst = Mac(0x55);
        std::memcpy(group_src.data(), unicast_dst.data(),
                    vgww::net::kMacAddrLen);
        const WireMac group = {0x01, 0x00, 0x5E, 0x00, 0x00, 0x01};
        std::memcpy(group_src.data() + vgww::net::kMacAddrLen, group.data(),
                    vgww::net::kMacAddrLen);
        LearnAndDecide(table, table_mutex, group_src.data(), group_src.size(),
                       vgww::bridge::kBridgePortUp, gateway);
        CHECK(!table.Lookup(group).has_value());
    }

    /// batch256: HAIRPIN. When the destination MAC was learned on the SAME port
    /// the frame arrived on, the frame needs no delivery at all: flooding it
    /// would send it straight back out the ingress port, and the peer send
    /// would duplicate it. LearnAndDecide must map that to kDrop.
    void TestLearnAndDecideHairpinDrops() {
        MacTable table;
        std::mutex table_mutex;
        const WireMac gateway = Mac(0x40);

        // Learn peer 0x41 on the DOWN port by sending a frame FROM it.
        const WireMac peer = Mac(0x41);
        std::array<uint8_t, vgww::net::kEthernetHeaderLen> learn{};
        std::memcpy(learn.data(), Mac(0x50).data(), vgww::net::kMacAddrLen);
        std::memcpy(learn.data() + vgww::net::kMacAddrLen, peer.data(),
                    vgww::net::kMacAddrLen);
        CHECK(LearnAndDecide(table, table_mutex, learn.data(), learn.size(),
                             vgww::bridge::kBridgePortDown, gateway) ==
              BridgeAction::kBridgeFlood);  // dst unknown -> flood
        CHECK(table.Lookup(peer).value() == vgww::bridge::kBridgePortDown);

        // Now a frame TO that peer, arriving on the SAME down port -> hairpin.
        const auto hairpin = FrameTo(peer);
        CHECK(LearnAndDecide(table, table_mutex, hairpin.data(),
                             hairpin.size(),
                             vgww::bridge::kBridgePortDown, gateway) ==
              BridgeAction::kDrop);

        // The SAME destination arriving on the OTHER port is a real unicast.
        CHECK(LearnAndDecide(table, table_mutex, hairpin.data(),
                             hairpin.size(),
                             vgww::bridge::kBridgePortUp, gateway) ==
              BridgeAction::kBridgeUnicast);
    }

    /// batch34w: IsGroupAddress is the single source of truth for "group
    /// address" (bit 0 of the first octet). Every family must be covered:
    /// a predicate that forgets IPv4 multicast makes callers treat IGMP /
    /// mDNS / SSDP frames as unicast, which is exactly the bug this replaced.
    void TestIsGroupAddressCoversEveryFamily() {
        struct Case {
            const char* name;
            WireMac mac;
            bool group;
        };
        const Case cases[] = {
            {"broadcast", {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, true},
            {"ipv6 all-nodes", {0x33, 0x33, 0x00, 0x00, 0x00, 0x01}, true},
            {"ipv6 solicited-node", {0x33, 0x33, 0xFF, 0x00, 0x00, 0x01}, true},
            {"ipv4 multicast 224.0.0.251", {0x01, 0x00, 0x5E, 0x00, 0x00, 0xFB},
             true},
            {"ipv4 multicast 239.255.255.250",
             {0x01, 0x00, 0x5E, 0x7F, 0xFF, 0xFA}, true},
            {"ipv4 multicast lowest", {0x01, 0x00, 0x5E, 0x00, 0x00, 0x00},
             true},
            {"unicast", {0x02, 0x00, 0x00, 0x00, 0x00, 0x01}, false},
            {"unicast all-zero", {0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, false},
            {"unicast near-group", {0x02, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, false},
        };
        for (const Case& c : cases) {
            if (vgww::net::IsGroupAddress(c.mac) != c.group) {
                std::fprintf(stderr, "CHECK failed: IsGroupAddress(%s)\n",
                             c.name);
                ++g_failures;
            }
        }
        // The narrower helpers must stay consistent with the general one:
        // anything they accept is a group address (the converse is not true,
        // which is precisely why callers must use IsGroupAddress).
        CHECK(vgww::net::IsGroupAddress(vgww::net::kBroadcastMac));
        CHECK(vgww::net::IsGroupAddress(
            WireMac{0x33, 0x33, 0x00, 0x00, 0x00, 0x01}));
        CHECK(vgww::net::IsGroupAddress(
            WireMac{0x01, 0x00, 0x5E, 0x00, 0x00, 0x01}));
    }

    /// Known unicast to a non-gateway MAC is bridged to the learned port.
    void TestDecideKnownUnicastBridges() {
        const WireMac gateway = Mac(0x30);
        const auto frame = FrameTo(Mac(0x40));
        CHECK(DecideBridgeAction(frame.data(), frame.size(), gateway, false,
                                 uint32_t{3}) == BridgeAction::kBridgeUnicast);
    }

    /// Unknown unicast to a non-gateway MAC floods the bridge ports.
    void TestDecideUnknownUnicastFloods() {
        const WireMac gateway = Mac(0x30);
        const auto frame = FrameTo(Mac(0x41));
        CHECK(DecideBridgeAction(frame.data(), frame.size(), gateway, false,
                                 std::nullopt) == BridgeAction::kBridgeFlood);
    }

    /// Frames shorter than an Ethernet header are dropped.
    void TestDecideShortFrameDrops() {
        const WireMac gateway = Mac(0x30);
        const uint8_t short_frame[vgww::net::kEthernetHeaderLen - 1] = {};
        CHECK(DecideBridgeAction(short_frame, sizeof(short_frame), gateway,
                                 false, std::nullopt) == BridgeAction::kDrop);
        CHECK(DecideBridgeAction(short_frame, 0, gateway, false,
                                 std::nullopt) == BridgeAction::kDrop);
        const auto frame = FrameTo(Mac(0x42));
        CHECK(DecideBridgeAction(frame.data(), frame.size(), gateway, false,
                                 std::nullopt) == BridgeAction::kBridgeFlood);
    }

    // ----- Task 3: bridge loop + dataplane integration -------------------

    using vgww::bridge::BridgeConfig;
    using vgww::bridge::BridgeFrameSink;
    using vgww::bridge::BridgeLoopExit;
    using vgww::bridge::BridgeLoopRuntime;
    using vgww::bridge::BridgeState;
    using vgww::bridge::HasPendingTimer;
    using vgww::bridge::RunBridgeLoop;
    using vgww::bridge::StopBridgeLoop;
    using vgww::runtime::Dataplane;

    /// Dual-adapter driver double (Task 3): per-adapter RX queues, sent
    /// capture, mode/filter recording, and fault injection for the bridge
    /// lifecycle tests. Port A (index 0) is the primary/control-plane
    /// adapter; port B (index 1) is the bridge downstream adapter.
    class FakeBridgeDriver final : public IDriverClient {
    public:
        static constexpr int kPortA = 0;
        static constexpr int kPortB = 1;

        FakeBridgeDriver() {
            AddAdapter(L"\\\\TestNIC-A",
                       reinterpret_cast<void*>(
                           static_cast<uintptr_t>(0xA110C0DEu)));
            AddAdapter(L"\\\\TestNIC-B",
                       reinterpret_cast<void*>(
                           static_cast<uintptr_t>(0xB110C0DEu)));
            view_[0] = adapters_;
            view_[1] = adapters_;
        }

        void FailHwFilterSet(bool fail) {
            std::lock_guard<std::mutex> lock(mutex_);
            fail_hw_filter_set_ = fail;
        }

        void FailModeSet(bool fail) {
            std::lock_guard<std::mutex> lock(mutex_);
            fail_mode_set_ = fail;
        }

        size_t FailReadAfter(size_t reads_before_failure) {
            std::lock_guard<std::mutex> lock(mutex_);
            const size_t previous = fail_after_;
            fail_after_ = reads_before_failure;
            return previous;
        }

        /// Queues one inbound frame on the given port.
        void InjectFrame(int port, const std::vector<uint8_t>& frame) {
            std::lock_guard<std::mutex> lock(mutex_);
            rx_queues_[port].push_back(frame);
        }

        /// Marks `port` as removed from the Adapters() enumeration while
        /// FindAdapter still resolves it (positions match kPortA/kPortB; the
        /// constructor adds "A" then "B"). A runtime hide is safe: the view
        /// in use by any concurrent caller is never modified in place (see
        /// the double-buffer Adapters() below). StartBridge completes, but
        /// the bridge thread's next enum poll observes the port gone.
        void HidePortFromEnumeration(int port) {
            std::lock_guard<std::mutex> lock(mutex_);
            const int active = view_index_.load(std::memory_order_acquire);
            const int inactive = 1 - active;
            view_[inactive].clear();
            for (size_t i = 0; i < adapters_.size(); ++i) {
                if (static_cast<int>(i) != port) {
                    view_[inactive].push_back(adapters_[i]);
                }
            }
            view_index_.store(inactive, std::memory_order_release);
        }

        /// Snapshot of frames handed to the given adapter.
        std::vector<std::vector<uint8_t>> SentOn(int port) const {
            std::lock_guard<std::mutex> lock(mutex_);
            return sent_[port];
        }

        /// Snapshot of frames handed to the host stack (must stay empty
        /// for pure bridge forwarding: no MSTCP leak).
        std::vector<std::vector<uint8_t>> MstcpFrames() const {
            std::lock_guard<std::mutex> lock(mutex_);
            return mstcp_frames_;
        }

        uint32_t GetFilter(int port) const {
            std::lock_guard<std::mutex> lock(mutex_);
            return filters_[port];
        }

        uint32_t GetMode(int port) const {
            std::lock_guard<std::mutex> lock(mutex_);
            return modes_[port];
        }

        size_t mode_set_count(int port) const {
            std::lock_guard<std::mutex> lock(mutex_);
            return mode_set_counts_[port];
        }

        size_t mode_reset_count(int port) const {
            std::lock_guard<std::mutex> lock(mutex_);
            return mode_reset_counts_[port];
        }

        size_t arm_count(int port) const {
            std::lock_guard<std::mutex> lock(mutex_);
            return arm_counts_[port];
        }

        // ----- IDriverClient -----------------------------------------
        const std::vector<AdapterEntry>& Adapters() const noexcept override {
            // Double-buffered: hide operates on the inactive copy and swaps
            // with a release store, so a live bridge thread iterating the
            // returned reference never sees it mutate in place.
            return view_[view_index_.load(std::memory_order_acquire)];
        }

        const AdapterEntry* FindAdapter(
            const std::wstring& hint,
            bool* out_ambiguous = nullptr) const noexcept override {
            bool amb = false;
            const int idx = vgww::driver::MatchAdapterEntry(
                adapters_, hint, std::wstring(), &amb);
            if (nullptr != out_ambiguous) {
                *out_ambiguous = amb;
            }
            return idx < 0 ? nullptr : &adapters_[static_cast<size_t>(idx)];
        }

        bool SetAdapterMode(const AdapterEntry& adapter, uint32_t flags,
                            std::string& error) override {
            std::lock_guard<std::mutex> lock(mutex_);
            const int idx = IndexOf(adapter.handle);
            if (idx < 0) {
                error = "unknown adapter handle";
                return false;
            }
            if (fail_mode_set_) {
                error = "injected mode set failure";
                return false;
            }
            modes_[idx] = flags;
            ++mode_set_counts_[idx];
            return true;
        }

        bool ArmRxEvent(const AdapterEntry& adapter, void*,
                        std::string& error) override {
            std::lock_guard<std::mutex> lock(mutex_);
            const int idx = IndexOf(adapter.handle);
            if (idx < 0) {
                error = "unknown adapter handle";
                return false;
            }
            ++arm_counts_[idx];
            return true;
        }

        uint32_t ReadPackets(void* handle, INTERMEDIATE_BUFFER* buffers,
                             uint32_t max_packets,
                             std::string& error) override {
            std::lock_guard<std::mutex> lock(mutex_);
            const int idx = IndexOf(handle);
            if (idx < 0) {
                error = "unknown adapter handle";
                return 0;
            }
            ++read_calls_;
            if (read_calls_ > fail_after_) {
                error = "injected read failure";
                return 0;
            }
            uint32_t n = 0;
            while (n < max_packets && !rx_queues_[idx].empty()) {
                INTERMEDIATE_BUFFER& ib = buffers[n];
                const std::vector<uint8_t>& frame = rx_queues_[idx].front();
                std::memset(&ib, 0, sizeof(ib));
                const size_t len = frame.size() < sizeof(ib.m_IBuffer)
                                       ? frame.size()
                                       : sizeof(ib.m_IBuffer);
                std::memcpy(ib.m_IBuffer, frame.data(), len);
                ib.m_Length = static_cast<DWORD>(len);
                ib.m_dwDeviceFlags = PACKET_FLAG_ON_RECEIVE;
                rx_queues_[idx].pop_front();
                ++n;
            }
            return n;
        }

        bool SendPacketsToAdapter(void* handle, INTERMEDIATE_BUFFER* buffers,
                                  uint32_t count, std::string& error) override {
            std::lock_guard<std::mutex> lock(mutex_);
            const int idx = IndexOf(handle);
            if (idx < 0) {
                error = "unknown adapter handle";
                return false;
            }
            for (uint32_t i = 0; i < count; ++i) {
                const INTERMEDIATE_BUFFER& ib = buffers[i];
                sent_[idx].emplace_back(ib.m_IBuffer,
                                        ib.m_IBuffer + ib.m_Length);
            }
            return true;
        }

        bool SendPacketsToMstcp(void*, INTERMEDIATE_BUFFER* buffers,
                                uint32_t count, std::string&) override {
            std::lock_guard<std::mutex> lock(mutex_);
            for (uint32_t i = 0; i < count; ++i) {
                const INTERMEDIATE_BUFFER& ib = buffers[i];
                mstcp_frames_.emplace_back(ib.m_IBuffer,
                                           ib.m_IBuffer + ib.m_Length);
            }
            return true;
        }

        bool FlushAdapterQueue(const AdapterEntry&, std::string&) override {
            return true;
        }

        bool ResetAdapterMode(const AdapterEntry& adapter,
                              std::string& error) override {
            std::lock_guard<std::mutex> lock(mutex_);
            const int idx = IndexOf(adapter.handle);
            if (idx < 0) {
                error = "unknown adapter handle";
                return false;
            }
            modes_[idx] = 0;
            ++mode_reset_counts_[idx];
            return true;
        }

        bool SetHwPacketFilter(const AdapterEntry& adapter, uint32_t filter,
                               std::string& error) override {
            std::lock_guard<std::mutex> lock(mutex_);
            const int idx = IndexOf(adapter.handle);
            if (idx < 0) {
                error = "unknown adapter handle";
                return false;
            }
            if (fail_hw_filter_set_) {
                error = "injected hw filter failure";
                return false;
            }
            filters_[idx] = filter;
            return true;
        }

        bool GetHwPacketFilter(const AdapterEntry& adapter, uint32_t& filter,
                               std::string& error) override {
            std::lock_guard<std::mutex> lock(mutex_);
            const int idx = IndexOf(adapter.handle);
            if (idx < 0) {
                error = "unknown adapter handle";
                return false;
            }
            filter = filters_[idx];
            return true;
        }

    private:
        static constexpr size_t kFailNever = static_cast<size_t>(-1);

        void AddAdapter(const wchar_t* name, void* handle) {
            AdapterEntry entry;
            entry.name = name;
            entry.handle = handle;
            entry.mtu = 1500;
            adapters_.push_back(entry);
        }

        int IndexOf(void* handle) const {
            for (size_t i = 0; i < adapters_.size(); ++i) {
                if (adapters_[i].handle == handle) {
                    return static_cast<int>(i);
                }
            }
            return -1;
        }

        std::vector<AdapterEntry> adapters_;
        // Double-buffered Adapters() enumeration view (FindAdapter still
        // resolves the full list). Only the inactive copy is ever mutated.
        std::vector<AdapterEntry> view_[2];
        std::atomic<int> view_index_{0};
        mutable std::mutex mutex_;
        std::deque<std::vector<uint8_t>> rx_queues_[2];
        std::vector<std::vector<uint8_t>> sent_[2];
        std::vector<std::vector<uint8_t>> mstcp_frames_;
        uint32_t filters_[2] = {0, 0};
        uint32_t modes_[2] = {0, 0};
        size_t mode_set_counts_[2] = {0, 0};
        size_t mode_reset_counts_[2] = {0, 0};
        size_t arm_counts_[2] = {0, 0};
        size_t read_calls_ = 0;
        size_t fail_after_ = kFailNever;
        bool fail_hw_filter_set_ = false;
        bool fail_mode_set_ = false;
    };

    /// batch256: RunBridgeLoop must NOT hand a kDrop frame to the sink.
    /// kDrop covers two very different cases -- a runt/short frame with no
    /// room for an Ethernet header, and a HAIRPIN frame whose destination was
    /// learned on the ingress port. Delivering either one to the sink sends a
    /// frame back out the port it arrived on (or delivers a frame nobody
    /// asked for). The loop only ever hands NON-dropped frames to the sink.
    class CountingSink final : public BridgeFrameSink {
    public:
        void OnBridgeFrame(const uint8_t*, size_t len, uint32_t in_port,
                           vgww::bridge::BridgeAction action) override {
            std::lock_guard<std::mutex> lock(mutex);
            ++count;
            last_len = len;
            last_action = action;
            last_port = in_port;
        }
        std::mutex mutex;
        int count = 0;
        size_t last_len = 0;
        uint32_t last_port = 0;
        vgww::bridge::BridgeAction last_action =
            vgww::bridge::BridgeAction::kDrop;
    };

    void TestRunBridgeLoopNeverDeliversDroppedFrames() {
        FakeBridgeDriver driver;
        const std::vector<AdapterEntry> adapters = driver.Adapters();
        CHECK(adapters.size() == 2);

        MacTable table;
        std::mutex table_mutex;
        const WireMac gateway = Mac(0x60);
        BridgeLoopRuntime runtime;
        CountingSink sink;

        // Frame 1: a runt (12 bytes = no room for a full Ethernet header).
        // LearnAndDecide maps it to kDrop, so the loop must not deliver it.
        driver.InjectFrame(FakeBridgeDriver::kPortB,
                           std::vector<uint8_t>(12, 0xAB));

        // Frame 2: a real frame TO the gateway MAC -> kControlOnly.
        const auto to_gateway = FrameTo(gateway);
        driver.InjectFrame(FakeBridgeDriver::kPortB,
                           std::vector<uint8_t>(to_gateway.begin(),
                                                to_gateway.end()));

        // Frame 3: unicast to an unknown destination -> kBridgeFlood.
        const auto to_unknown = FrameTo(Mac(0x61));
        driver.InjectFrame(FakeBridgeDriver::kPortB,
                           std::vector<uint8_t>(to_unknown.begin(),
                                                to_unknown.end()));

        std::string exit_detail;
        std::thread loop([&] {
            RunBridgeLoop(driver, adapters[1],
                          vgww::bridge::kBridgePortDown, table, table_mutex,
                          gateway, runtime, sink,
                          [](uint32_t) { return true; }, exit_detail);
        });

        const auto deadline =
            std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while (std::chrono::steady_clock::now() < deadline) {
            {
                std::lock_guard<std::mutex> lock(sink.mutex);
                if (sink.count >= 2) {
                    break;
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
        StopBridgeLoop(runtime);
        loop.join();

        std::lock_guard<std::mutex> lock(sink.mutex);
        // EXACTLY two: the gateway frame and the flood frame. The 12-byte runt
        // was dropped and must never reach the sink.
        CHECK(sink.count == 2);
    }

    vgww::core::Config MakeBridgeConfig() {
        vgww::core::Config cfg;
        cfg.adapter = "TestNIC-A";
        cfg.gateway.ipv4 = (192u) | (0u << 8) | (168u << 16) | (40u << 24);
        cfg.gateway.mask = (0u) | (0u << 8) | (255u << 16) | (255u << 24);
        cfg.gateway.mac = {0x30, 0xFC, 0x68, 0x88, 0xB4, 0xA9};
        cfg.perf.workers = 1;
        cfg.perf.ring_capacity = 64;
        cfg.perf.max_conns = 64;
        cfg.perf.dial_timeout_ms = 400;
        return cfg;
    }

    BridgeConfig MakeDualBridge(const char* up, const char* down) {
        BridgeConfig bc;
        bc.enabled = true;
        bc.upstream = up;
        bc.downstream = down;
        return bc;
    }

    template <typename Pred>
    bool WaitFor(Pred pred, int timeout_ms) {
        const auto deadline = std::chrono::steady_clock::now() +
                              std::chrono::milliseconds(timeout_ms);
        while (std::chrono::steady_clock::now() < deadline) {
            if (pred()) {
                return true;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
        return pred();
    }

    bool ContainsFrame(const std::vector<std::vector<uint8_t>>& frames,
                       const std::vector<uint8_t>& want) {
        for (const auto& f : frames) {
            if (f == want) {
                return true;
            }
        }
        return false;
    }

    /// Raw Ethernet II frame padded to `total_len` bytes.
    std::vector<uint8_t> EthFrame(const WireMac& dst, const WireMac& src,
                                  uint16_t ethertype, size_t total_len) {
        std::vector<uint8_t> f(total_len < vgww::net::kEthernetHeaderLen
                                   ? vgww::net::kEthernetHeaderLen
                                   : total_len,
                               0);
        std::memcpy(f.data(), dst.data(), vgww::net::kMacAddrLen);
        std::memcpy(f.data() + 6, src.data(), vgww::net::kMacAddrLen);
        f[12] = static_cast<uint8_t>(ethertype >> 8);
        f[13] = static_cast<uint8_t>(ethertype & 0xFF);
        return f;
    }

    /// ARP request for `target_ip` from `src_mac`/`sender_ip`, Ethernet
    /// destination `eth_dst` (broadcast or the gateway MAC).
    std::vector<uint8_t> ArpRequest(const WireMac& src_mac, uint32_t sender_ip,
                                    const WireMac& eth_dst,
                                    uint32_t target_ip) {
        std::array<uint8_t, vgww::proto::kArpFrameLen> out{};
        vgww::proto::BuildArpFrame(out.data(),
                                   vgww::proto::ArpOperation::kRequest, src_mac,
                                   sender_ip, eth_dst, target_ip);
        return std::vector<uint8_t>(out.begin(), out.end());
    }

    bool LifecycleEmpty(
        const vgww::runtime::Dataplane::LifecycleCounts& counts) {
        return 0 == counts.rx_rings && 0 == counts.tx_rings &&
               0 == counts.io_contexts && 0 == counts.udp_tables &&
               0 == counts.icmp_relays && 0 == counts.relay_registry &&
               0 == counts.workers && !counts.running &&
               !counts.shutdown_incomplete;
    }

    // ------------------------------------------------------------------
    // C8 data-plane return path: NAT/relay replies must egress the bridge
    // port the destination client is on (spec P6: a downstream client's
    // request is answered back out the downstream adapter). The worker TX
    // ring is drained on the RX/TX thread with no port tag, so the egress
    // is resolved from the frame's destination MAC via the bridge MAC table.
    // ------------------------------------------------------------------

    /// Blocking UDP echo server on 127.0.0.1:0; publishes the bound port so
    /// the caller can aim the client frame at it. Runs until `stop`.
    void RunUdpEchoServer(std::atomic<uint16_t>& port,
                          const std::atomic<bool>& stop) {
        asio::io_context io;
        asio::ip::udp::socket sock(io);
        std::error_code ec;
        sock.open(asio::ip::udp::v4(), ec);
        if (ec) {
            return;
        }
        sock.bind(
            asio::ip::udp::endpoint(asio::ip::make_address("127.0.0.1"), 0),
            ec);
        if (ec) {
            return;
        }
        port.store(sock.local_endpoint().port());
        sock.non_blocking(true);
        while (!stop.load()) {
            char buf[2048];
            asio::ip::udp::endpoint peer;
            std::error_code err;
            const size_t n =
                sock.receive_from(asio::buffer(buf), peer, 0, err);
            if (err == asio::error::would_block) {
                std::this_thread::sleep_for(std::chrono::milliseconds(2));
                continue;
            }
            if (err || 0 == n) {
                break;
            }
            std::error_code write_err;
            sock.send_to(asio::buffer(buf, n), peer, 0, write_err);
        }
    }

    /// UDP request frame client(src_mac/src_ip) -> 127.0.0.1:dport, Ethernet
    /// destination `dst_mac` (the gateway MAC, so the bridge treats it as a
    /// control/relay frame rather than a peer-forwarded one). The data-plane
    /// relay does not validate the ingress UDP checksum, so zero suffices.
    std::vector<uint8_t> BuildUdpRequestTo(const WireMac& src_mac,
                                           const WireMac& dst_mac,
                                           const uint8_t src_ip[4],
                                           uint16_t sport, uint16_t dport,
                                           const std::string& payload) {
        const size_t udp_len = vgww::proto::kUdpHeaderLen + payload.size();
        std::vector<uint8_t> f(
            vgww::net::kEthernetHeaderLen + 20 + udp_len, 0);
        vgww::net::BuildEthHeader(f.data(), dst_mac, src_mac,
                                  vgww::net::kEthertypeIpv4);
        uint8_t* ip = f.data() + vgww::net::kEthernetHeaderLen;
        ip[0] = 0x45;
        const uint16_t total = static_cast<uint16_t>(20 + udp_len);
        ip[2] = static_cast<uint8_t>(total >> 8);
        ip[3] = static_cast<uint8_t>(total & 0xFF);
        ip[8] = 64;
        ip[9] = 17;  // UDP
        std::memcpy(ip + 12, src_ip, 4);
        const uint8_t loopback[4] = {127, 0, 0, 1};
        std::memcpy(ip + 16, loopback, 4);
        uint8_t* udp = ip + 20;
        udp[0] = static_cast<uint8_t>(sport >> 8);
        udp[1] = static_cast<uint8_t>(sport & 0xFF);
        udp[2] = static_cast<uint8_t>(dport >> 8);
        udp[3] = static_cast<uint8_t>(dport & 0xFF);
        udp[4] = static_cast<uint8_t>(udp_len >> 8);
        udp[5] = static_cast<uint8_t>(udp_len & 0xFF);
        std::memcpy(udp + vgww::proto::kUdpHeaderLen, payload.data(),
                    payload.size());
        return f;
    }

    /// True when some captured frame is the relayed UDP reply toward
    /// `client_mac` from `server_port` carrying `marker`.
    bool ContainsUdpReplyTo(const std::vector<std::vector<uint8_t>>& frames,
                            const WireMac& client_mac, uint16_t server_port,
                            const std::string& marker) {
        for (const auto& f : frames) {
            if (f.size() < vgww::net::kEthernetHeaderLen + 20 +
                                    vgww::proto::kUdpHeaderLen +
                                    marker.size()) {
                continue;
            }
            if (0 != std::memcmp(f.data(), client_mac.data(),
                                 vgww::net::kMacAddrLen)) {
                continue;  // not addressed to this client
            }
            const uint8_t* ip = f.data() + vgww::net::kEthernetHeaderLen;
            if (ip[9] != 17) {
                continue;  // not UDP
            }
            const uint8_t* udp = ip + 20;
            const uint16_t sport =
                static_cast<uint16_t>((udp[0] << 8) | udp[1]);
            if (sport != server_port) {
                continue;
            }
            if (0 == std::memcmp(udp + vgww::proto::kUdpHeaderLen,
                                 marker.data(), marker.size())) {
                return true;
            }
        }
        return false;
    }

    /// True when some captured frame is an ARP reply (opcode 2) addressed to
    /// `client_mac` - i.e. the gateway's unicast answer to that client.
    bool ContainsArpReplyTo(const std::vector<std::vector<uint8_t>>& frames,
                            const WireMac& client_mac) {
        for (const auto& f : frames) {
            if (f.size() < vgww::proto::kArpFrameLen) {
                continue;
            }
            if (0 != std::memcmp(f.data(), client_mac.data(),
                                 vgww::net::kMacAddrLen)) {
                continue;  // not addressed to this client
            }
            if (0x08 != f[12] || 0x06 != f[13]) {
                continue;  // not ARP
            }
            if (0x00 != f[20] || 0x02 != f[21]) {
                continue;  // not a reply
            }
            return true;
        }
        return false;
    }

    /// C8 data-plane: a NAT/relay reply to a DOWNSTREAM client must egress
    /// the downstream adapter (PortB), not the primary/upstream adapter.
    void TestRelayReturnEgressesDownstreamPort() {
        const vgww::core::Config config = MakeBridgeConfig();
        Dataplane dataplane(config);
        auto fake = std::make_unique<FakeBridgeDriver>();
        FakeBridgeDriver* raw = fake.get();
        dataplane.SetDriverClient(std::move(fake));
        dataplane.SetBridgeConfig(MakeDualBridge("TestNIC-A", "TestNIC-B"));

        std::string error;
        CHECK(dataplane.Start(error));
        CHECK(WaitFor(
            [&] {
                return dataplane.GetBridgeState() == BridgeState::kRunning;
            },
            4000));

        std::atomic<uint16_t> echo_port{0};
        std::atomic<bool> echo_stop{false};
        std::thread echo([&] { RunUdpEchoServer(echo_port, echo_stop); });
        for (int i = 0; i < 200 && 0 == echo_port.load(); ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
        CHECK(0 != echo_port.load());
        if (0 == echo_port.load()) {
            echo_stop.store(true);
            echo.join();
            std::string stop_error;
            dataplane.Stop(stop_error);
            return;
        }

        // Client sits on the DOWNSTREAM port (B). Its request is injected
        // there; the reply (dst = this client MAC) must come back out B.
        const WireMac client = Mac(0xC8);
        const uint8_t client_ip[4] = {10, 0, 0, 9};
        const std::string marker = "PING-C8";
        const std::vector<uint8_t> request = BuildUdpRequestTo(
            client, config.gateway.mac, client_ip, 51000, echo_port.load(),
            marker);

        // Retransmit a few times: the first echo may arrive before the
        // neighbor snapshot (100 ms publish cadence) knows the client MAC,
        // in which case the relay drops it (mac_miss) and the client retries.
        bool downstream = false;
        bool upstream = false;
        for (int i = 0; i < 40 && !downstream; ++i) {
            raw->InjectFrame(FakeBridgeDriver::kPortB, request);
            WaitFor(
                [&] {
                    downstream = ContainsUdpReplyTo(
                        raw->SentOn(FakeBridgeDriver::kPortB), client,
                        echo_port.load(), marker);
                    upstream = ContainsUdpReplyTo(
                        raw->SentOn(FakeBridgeDriver::kPortA), client,
                        echo_port.load(), marker);
                    return downstream;
                },
                250);
        }
        CHECK(downstream);
        CHECK(!upstream);  // must NOT leak to the primary/upstream adapter

        // Regression (audit A D1): resolving the egress must NOT copy-assign
        // the PortBatch (that would clobber down.primary's handle+items). After
        // the downstream reply has exercised the egress branch, an UPSTREAM
        // control-plane reply (ARP answer to a client on the primary port A)
        // must still leave through A - and never through B. Under the buggy
        // `egress = down.downstream` copy, down.primary.handle is permanently
        // rewritten to B, so this ARP reply would be misdirected.
        const WireMac up_client = Mac(0xA1);
        const uint32_t up_client_ip = (10u) | (0u << 8) | (0u << 16) | (5u << 24);
        const std::vector<uint8_t> up_arp =
            ArpRequest(up_client, up_client_ip, vgww::net::kBroadcastMac,
                       config.gateway.ipv4);
        bool up_reply_on_a = false;
        for (int i = 0; i < 20 && !up_reply_on_a; ++i) {
            raw->InjectFrame(FakeBridgeDriver::kPortA, up_arp);
            WaitFor(
                [&] {
                    up_reply_on_a = ContainsArpReplyTo(
                        raw->SentOn(FakeBridgeDriver::kPortA), up_client);
                    return up_reply_on_a;
                },
                250);
        }
        CHECK(up_reply_on_a);
        CHECK(!ContainsArpReplyTo(raw->SentOn(FakeBridgeDriver::kPortB),
                                  up_client));  // no upstream reply leak to B
        // The downstream relay reply must still be confined to B.
        CHECK(!ContainsUdpReplyTo(raw->SentOn(FakeBridgeDriver::kPortA),
                                  client, echo_port.load(), marker));

        echo_stop.store(true);
        echo.join();
        std::string stop_error;
        CHECK(dataplane.Stop(stop_error));
        CHECK(stop_error.empty());
    }

    /// With the bridge disabled the dataplane must behave exactly as
    /// before: no bridge thread, no filter changes, no cross-port copy.
    void TestBridgeDisabledNoop() {
        const vgww::core::Config config = MakeBridgeConfig();
        Dataplane dataplane(config);
        auto fake = std::make_unique<FakeBridgeDriver>();
        FakeBridgeDriver* raw = fake.get();
        dataplane.SetDriverClient(std::move(fake));

        std::string error;
        CHECK(dataplane.Start(error));
        CHECK(error.empty());
        CHECK(dataplane.GetBridgeState() == BridgeState::kStopped);
        CHECK(dataplane.GetBridgeMacCount() == 0);

        const WireMac unknown = {0x02, 0, 0, 0, 0, 0xA1};
        const WireMac client = {0x02, 0, 0, 0, 0, 0xC1};
        raw->InjectFrame(FakeBridgeDriver::kPortA,
                         EthFrame(unknown, client, 0x0800, 60));
        std::this_thread::sleep_for(std::chrono::milliseconds(600));
        // No bridge: nothing may appear on the peer adapter.
        CHECK(raw->SentOn(FakeBridgeDriver::kPortB).empty());
        CHECK(dataplane.GetBridgeState() == BridgeState::kStopped);

        std::string stop_error;
        CHECK(dataplane.Stop(stop_error));
        CHECK(stop_error.empty());
        CHECK(raw->GetFilter(FakeBridgeDriver::kPortA) == 0);
        CHECK(raw->GetFilter(FakeBridgeDriver::kPortB) == 0);
    }

    /// An unresolvable downstream port must fail Start with the port name
    /// in the error and leave no half-initialized residue.
    void TestBridgeSecondAdapterMissingFails() {
        const vgww::core::Config config = MakeBridgeConfig();
        Dataplane dataplane(config);
        auto fake = std::make_unique<FakeBridgeDriver>();
        FakeBridgeDriver* raw = fake.get();
        dataplane.SetDriverClient(std::move(fake));
        dataplane.SetBridgeConfig(
            MakeDualBridge("TestNIC-A", "NoSuchPort-XYZ"));

        std::string error;
        CHECK(!dataplane.Start(error));
        CHECK(error.find("NoSuchPort-XYZ") != std::string::npos);
        CHECK(LifecycleEmpty(dataplane.GetLifecycleCounts()));
        CHECK(dataplane.GetBridgeState() == BridgeState::kStopped);
        CHECK(raw->GetFilter(FakeBridgeDriver::kPortA) == 0);
        CHECK(raw->GetFilter(FakeBridgeDriver::kPortB) == 0);

        std::string stop_error;
        CHECK(dataplane.Stop(stop_error));
    }

    /// Any bridge bring-up failure (filter set, mode set) must roll back
    /// in reverse order: filters restored, modes reset, events closed,
    /// lifecycle counts empty.
    void TestBridgeStartFailureNoResidue() {
        // Phase 1: promiscuous set fails after both modes were applied.
        {
            const vgww::core::Config config = MakeBridgeConfig();
            Dataplane dataplane(config);
            auto fake = std::make_unique<FakeBridgeDriver>();
            FakeBridgeDriver* raw = fake.get();
            dataplane.SetDriverClient(std::move(fake));
            dataplane.SetBridgeConfig(
                MakeDualBridge("TestNIC-A", "TestNIC-B"));
            raw->FailHwFilterSet(true);

            std::string error;
            CHECK(!dataplane.Start(error));
            CHECK(!error.empty());
            CHECK(raw->GetFilter(FakeBridgeDriver::kPortA) == 0);
            CHECK(raw->GetFilter(FakeBridgeDriver::kPortB) == 0);
            CHECK(raw->mode_reset_count(FakeBridgeDriver::kPortA) >= 1);
            CHECK(raw->mode_reset_count(FakeBridgeDriver::kPortB) >= 1);
            CHECK(LifecycleEmpty(dataplane.GetLifecycleCounts()));
            CHECK(dataplane.GetBridgeState() == BridgeState::kStopped);

            std::string stop_error;
            CHECK(dataplane.Stop(stop_error));
        }
        // Phase 2: mode set fails after the original filters were saved.
        {
            const vgww::core::Config config = MakeBridgeConfig();
            Dataplane dataplane(config);
            auto fake = std::make_unique<FakeBridgeDriver>();
            FakeBridgeDriver* raw = fake.get();
            dataplane.SetDriverClient(std::move(fake));
            dataplane.SetBridgeConfig(
                MakeDualBridge("TestNIC-A", "TestNIC-B"));
            raw->FailModeSet(true);

            std::string error;
            CHECK(!dataplane.Start(error));
            CHECK(!error.empty());
            CHECK(raw->GetFilter(FakeBridgeDriver::kPortA) == 0);
            CHECK(raw->GetFilter(FakeBridgeDriver::kPortB) == 0);
            CHECK(LifecycleEmpty(dataplane.GetLifecycleCounts()));

            std::string stop_error;
            CHECK(dataplane.Stop(stop_error));
        }
    }

    /// Unknown unicast crosses the bridge in both directions without
    /// leaking into the host stack (MSTCP).
    void TestBridgeForwardsUnknownUnicast() {
        const vgww::core::Config config = MakeBridgeConfig();
        Dataplane dataplane(config);
        auto fake = std::make_unique<FakeBridgeDriver>();
        FakeBridgeDriver* raw = fake.get();
        dataplane.SetDriverClient(std::move(fake));
        dataplane.SetBridgeConfig(
            MakeDualBridge("TestNIC-A", "TestNIC-B"));

        std::string error;
        CHECK(dataplane.Start(error));
        CHECK(WaitFor([&] {
            return dataplane.GetBridgeState() == BridgeState::kRunning;
        }, 4000));

        const WireMac u1 = {0x02, 0, 0, 0, 0, 0xA1};
        const WireMac c1 = {0x02, 0, 0, 0, 0, 0xC1};
        const std::vector<uint8_t> frame_a = EthFrame(u1, c1, 0x0800, 60);
        raw->InjectFrame(FakeBridgeDriver::kPortA, frame_a);
        CHECK(WaitFor(
            [&] {
                return ContainsFrame(raw->SentOn(FakeBridgeDriver::kPortB),
                                     frame_a);
            },
            4000));

        const WireMac u2 = {0x02, 0, 0, 0, 0, 0xA2};
        const WireMac c2 = {0x02, 0, 0, 0, 0, 0xC2};
        const std::vector<uint8_t> frame_b = EthFrame(u2, c2, 0x0800, 60);
        raw->InjectFrame(FakeBridgeDriver::kPortB, frame_b);
        CHECK(WaitFor(
            [&] {
                return ContainsFrame(raw->SentOn(FakeBridgeDriver::kPortA),
                                     frame_b);
            },
            4000));

        // Bridged frames stay on the wire: never re-injected into MSTCP.
        CHECK(raw->MstcpFrames().empty());
        // Both source MACs were learned.
        CHECK(dataplane.GetBridgeMacCount() >= 2);

        std::string stop_error;
        CHECK(dataplane.Stop(stop_error));
        CHECK(stop_error.empty());
    }

    /// A broadcast frame is answered by the control plane AND flooded to
    /// the peer port.
    void TestBroadcastGoesBothPaths() {
        const vgww::core::Config config = MakeBridgeConfig();
        Dataplane dataplane(config);
        auto fake = std::make_unique<FakeBridgeDriver>();
        FakeBridgeDriver* raw = fake.get();
        dataplane.SetDriverClient(std::move(fake));
        dataplane.SetBridgeConfig(
            MakeDualBridge("TestNIC-A", "TestNIC-B"));

        std::string error;
        CHECK(dataplane.Start(error));
        CHECK(WaitFor([&] {
            return dataplane.GetBridgeState() == BridgeState::kRunning;
        }, 4000));

        const WireMac client = {0x02, 0, 0, 0, 0, 0xC3};
        const uint32_t client_ip = (10u) | (0u << 8) | (0u << 16) | (5u << 24);
        const std::vector<uint8_t> request =
            ArpRequest(client, client_ip, vgww::net::kBroadcastMac,
                       config.gateway.ipv4);
        raw->InjectFrame(FakeBridgeDriver::kPortA, request);
        // Control plane answered (ARP reply) and the peer got the flood.
        CHECK(WaitFor(
            [&] { return dataplane.GetStats().arp_replies.load() > 0; },
            4000));
        CHECK(WaitFor(
            [&] {
                return ContainsFrame(raw->SentOn(FakeBridgeDriver::kPortB),
                                     request);
            },
            4000));

        std::string stop_error;
        CHECK(dataplane.Stop(stop_error));
        CHECK(stop_error.empty());
    }

    /// Frames to the gateway MAC stay on the control plane: the peer port
    /// must see no copy.
    void TestGatewayFrameNotBridged() {
        const vgww::core::Config config = MakeBridgeConfig();
        Dataplane dataplane(config);
        auto fake = std::make_unique<FakeBridgeDriver>();
        FakeBridgeDriver* raw = fake.get();
        dataplane.SetDriverClient(std::move(fake));
        dataplane.SetBridgeConfig(
            MakeDualBridge("TestNIC-A", "TestNIC-B"));

        std::string error;
        CHECK(dataplane.Start(error));
        CHECK(WaitFor([&] {
            return dataplane.GetBridgeState() == BridgeState::kRunning;
        }, 4000));

        const WireMac client = {0x02, 0, 0, 0, 0, 0xC4};
        const uint32_t client_ip = (10u) | (0u << 8) | (0u << 16) | (6u << 24);
        const std::vector<uint8_t> request =
            ArpRequest(client, client_ip, config.gateway.mac,
                       config.gateway.ipv4);
        raw->InjectFrame(FakeBridgeDriver::kPortA, request);
        // Control plane still answers gateway-directed frames ...
        CHECK(WaitFor(
            [&] { return dataplane.GetStats().arp_replies.load() > 0; },
            4000));
        // ... but nothing is bridged to the peer port.
        std::this_thread::sleep_for(std::chrono::milliseconds(400));
        CHECK(raw->SentOn(FakeBridgeDriver::kPortB).empty());

        std::string stop_error;
        CHECK(dataplane.Stop(stop_error));
        CHECK(stop_error.empty());
    }

    /// C8: control-plane replies must egress the port that received the
    /// request. An ARP request injected on the DOWNSTREAM port (PortB) must
    /// be answered out of PortB's wire - not the primary (upstream) adapter.
    void TestControlReplyEgressesDownstreamPort() {
        const vgww::core::Config config = MakeBridgeConfig();
        Dataplane dataplane(config);
        auto fake = std::make_unique<FakeBridgeDriver>();
        FakeBridgeDriver* raw = fake.get();
        dataplane.SetDriverClient(std::move(fake));
        dataplane.SetBridgeConfig(
            MakeDualBridge("TestNIC-A", "TestNIC-B"));

        std::string error;
        CHECK(dataplane.Start(error));
        CHECK(WaitFor([&] {
            return dataplane.GetBridgeState() == BridgeState::kRunning;
        }, 4000));

        const WireMac client = {0x02, 0, 0, 0, 0, 0xD1};
        const uint32_t client_ip = (10u) | (0u << 8) | (0u << 16) | (8u << 24);
        const std::vector<uint8_t> request =
            ArpRequest(client, client_ip, vgww::net::kBroadcastMac,
                       config.gateway.ipv4);
        raw->InjectFrame(FakeBridgeDriver::kPortB, request);

        // The gateway answers (arp_replies>0) and the REPLY (dst = the
        // client MAC, not broadcast) must appear on the DOWNSTREAM wire.
        CHECK(WaitFor(
            [&] {
                return dataplane.GetStats().arp_replies.load() > 0 &&
                       [&] {
                           for (const auto& f :
                                raw->SentOn(FakeBridgeDriver::kPortB)) {
                               if (f.size() >= vgww::net::kEthernetHeaderLen &&
                                   0 == std::memcmp(f.data(), client.data(),
                                                    vgww::net::kMacAddrLen)) {
                                   return true;
                               }
                           }
                           return false;
                       }();
            },
            4000));

        // The reply must NOT be handed to the primary/upstream adapter.
        const auto sent_a = raw->SentOn(FakeBridgeDriver::kPortA);
        for (const auto& f : sent_a) {
            CHECK(!(f.size() >= vgww::net::kEthernetHeaderLen &&
                    0 == std::memcmp(f.data(), client.data(),
                                     vgww::net::kMacAddrLen)));
        }

        std::string stop_error;
        CHECK(dataplane.Stop(stop_error));
        CHECK(stop_error.empty());
    }

    /// Stop restores both adapters' original filters and resets modes.
    /// Three Start/Stop cycles must leave no residue growth (symmetric
    /// create/close of the bridge event, joined thread, restored
    /// filters, reset modes).
    void TestBridgeStopRestoresFilter() {
        const vgww::core::Config config = MakeBridgeConfig();
        Dataplane dataplane(config);
        auto fake = std::make_unique<FakeBridgeDriver>();
        FakeBridgeDriver* raw = fake.get();
        dataplane.SetDriverClient(std::move(fake));
        dataplane.SetBridgeConfig(
            MakeDualBridge("TestNIC-A", "TestNIC-B"));

        CHECK(raw->GetFilter(FakeBridgeDriver::kPortA) == 0);
        CHECK(raw->GetFilter(FakeBridgeDriver::kPortB) == 0);

        for (int cycle = 1; cycle <= 3; ++cycle) {
            std::string error;
            CHECK(dataplane.Start(error));
            CHECK(WaitFor([&] {
                return dataplane.GetBridgeState() == BridgeState::kRunning;
            }, 4000));
            // Promiscuous active on both adapters while running.
            CHECK(WaitFor(
                [&] {
                    return raw->GetFilter(FakeBridgeDriver::kPortA) ==
                               kPromiscuous &&
                           raw->GetFilter(FakeBridgeDriver::kPortB) ==
                               kPromiscuous;
                },
                4000));
            // Each adapter armed exactly once per cycle (ArmRxEvent x2).
            CHECK(raw->arm_count(FakeBridgeDriver::kPortA) ==
                  static_cast<size_t>(cycle));
            CHECK(raw->arm_count(FakeBridgeDriver::kPortB) ==
                  static_cast<size_t>(cycle));

            std::string stop_error;
            CHECK(dataplane.Stop(stop_error));
            CHECK(stop_error.empty());
            CHECK(dataplane.GetBridgeState() == BridgeState::kStopped);
            CHECK(raw->GetFilter(FakeBridgeDriver::kPortA) == 0);
            CHECK(raw->GetFilter(FakeBridgeDriver::kPortB) == 0);
            CHECK(raw->mode_reset_count(FakeBridgeDriver::kPortA) >=
                  static_cast<size_t>(cycle));
            CHECK(raw->mode_reset_count(FakeBridgeDriver::kPortB) >=
                  static_cast<size_t>(cycle));
            CHECK(dataplane.GetBridgeMacCount() == 0);
        }
    }

    /// A vanished port halts the bridge (failed, visible) without taking
    /// down the dataplane; Stop stays idempotent afterwards.
    void TestPortDisappearStopsBridge() {
        const vgww::core::Config config = MakeBridgeConfig();
        Dataplane dataplane(config);
        auto fake = std::make_unique<FakeBridgeDriver>();
        FakeBridgeDriver* raw = fake.get();
        dataplane.SetDriverClient(std::move(fake));
        dataplane.SetBridgeConfig(
            MakeDualBridge("TestNIC-A", "TestNIC-B"));

        std::string error;
        CHECK(dataplane.Start(error));
        CHECK(WaitFor([&] {
            return dataplane.GetBridgeState() == BridgeState::kRunning;
        }, 4000));

        raw->FailReadAfter(0);
        CHECK(WaitFor([&] {
            return dataplane.GetBridgeState() == BridgeState::kFailed;
        }, 8000));
        // The dataplane itself survives a dead bridge port (no crash).
        CHECK(dataplane.GetLifecycleCounts().running);

        std::string stop_error;
        CHECK(dataplane.Stop(stop_error));
        CHECK(dataplane.GetBridgeState() == BridgeState::kStopped);
        // Stop is re-entrant and idempotent.
        std::string stop_again;
        CHECK(dataplane.Stop(stop_again));
        CHECK(dataplane.GetBridgeState() == BridgeState::kStopped);
    }

    /// batch36 guard: the in-loop kPortGone exit already publishes a reason,
    /// but the old "TestPortDisappearStopsBridge" actually exercised the read
    /// error path (FailReadAfter), so the port-gone reason mapping was never
    /// asserted. This pins it so the shared failure path cannot regress.
    void TestB36EarlyPortGonePublishesReason() {
        const vgww::core::Config config = MakeBridgeConfig();
        Dataplane dataplane(config);
        auto fake = std::make_unique<FakeBridgeDriver>();
        FakeBridgeDriver* raw = fake.get();
        dataplane.SetDriverClient(std::move(fake));
        dataplane.SetBridgeConfig(MakeDualBridge("TestNIC-A", "TestNIC-B"));
        // The downstream resolves at StartBridge (FindAdapter) but the
        // enumeration no longer reports it once the bridge thread polls:
        // the "gone before thread start" exit path, deterministically.
        raw->HidePortFromEnumeration(FakeBridgeDriver::kPortB);

        std::string error;
        CHECK(dataplane.Start(error));
        CHECK(WaitFor(
            [&] {
                return dataplane.GetBridgeState() == BridgeState::kFailed;
            },
            4000));
        // batch34x/36 invariant: kFailed always carries a matching reason.
        CHECK(dataplane.GetBridgeError().find("bridge port disappeared") !=
              std::string::npos);
        // The dataplane survives a dead bridge port (no bridge, no crash).
        CHECK(dataplane.GetLifecycleCounts().running);

        std::string stop_error;
        CHECK(dataplane.Stop(stop_error));
        CHECK(dataplane.GetBridgeState() == BridgeState::kStopped);
    }

    /// batch36b: the IN-LOOP kPortGone exit - RunBridgeLoop observes the
    /// enumerated adapter disappear and returns kPortGone - must publish the
    /// same "bridge port disappeared" reason through the shared FailBridge.
    /// (The early-path test above covers the same handler before the loop;
    /// this one drives the real RunBridgeLoop exit, both under the
    /// double-buffer hide which is safe to call while the loop polls.)
    void TestB36InLoopPortGonePublishesReason() {
        const vgww::core::Config config = MakeBridgeConfig();
        Dataplane dataplane(config);
        auto fake = std::make_unique<FakeBridgeDriver>();
        FakeBridgeDriver* raw = fake.get();
        dataplane.SetDriverClient(std::move(fake));
        dataplane.SetBridgeConfig(MakeDualBridge("TestNIC-A", "TestNIC-B"));

        std::string error;
        CHECK(dataplane.Start(error));
        CHECK(WaitFor(
            [&] {
                return dataplane.GetBridgeState() == BridgeState::kRunning;
            },
            4000));

        raw->HidePortFromEnumeration(FakeBridgeDriver::kPortB);
        CHECK(WaitFor(
            [&] {
                return dataplane.GetBridgeState() == BridgeState::kFailed;
            },
            8000));
        // batch34x/36 invariant: kFailed always carries a matching reason.
        CHECK(dataplane.GetBridgeError().find("bridge port disappeared") !=
              std::string::npos);
        // The dataplane survives a dead bridge port (no bridge, no crash).
        CHECK(dataplane.GetLifecycleCounts().running);

        std::string stop_error;
        CHECK(dataplane.Stop(stop_error));
        CHECK(dataplane.GetBridgeState() == BridgeState::kStopped);
    }

    /// batch36 defect: after a failed bridge is stopped cleanly, the stale
    /// reason must not survive into a later snapshot/Start pair. A reader
    /// pairing the state with the reason would otherwise keep reporting a
    /// failure that already ended (or pair the wrong reason with a fresh
    /// failure through the early-port-gone path).
    void TestB36BridgeErrorClearedOnCleanStop() {
        const vgww::core::Config config = MakeBridgeConfig();
        Dataplane dataplane(config);
        auto fake = std::make_unique<FakeBridgeDriver>();
        FakeBridgeDriver* raw = fake.get();
        dataplane.SetDriverClient(std::move(fake));
        dataplane.SetBridgeConfig(MakeDualBridge("TestNIC-A", "TestNIC-B"));

        std::string error;
        CHECK(dataplane.Start(error));
        CHECK(WaitFor(
            [&] {
                return dataplane.GetBridgeState() == BridgeState::kRunning;
            },
            4000));

        raw->FailReadAfter(0);
        CHECK(WaitFor(
            [&] {
                return dataplane.GetBridgeState() == BridgeState::kFailed;
            },
            8000));
        CHECK(dataplane.GetBridgeError().find("bridge read error") !=
              std::string::npos);

        std::string stop_error;
        CHECK(dataplane.Stop(stop_error));
        CHECK(dataplane.GetBridgeState() == BridgeState::kStopped);
        // Clean stop must clear the reason: no lingering failure.
        CHECK(dataplane.GetBridgeError().empty());
    }

    /// Group-address sources (broadcast/multicast) are never learned.
    void TestMacTableRejectsGroupAddress() {
        MacTable table;
        const auto now = MacTable::TimePoint{};
        table.Learn(vgww::net::kBroadcastMac, 0, now);
        table.Learn(WireMac{0x33, 0x33, 0x00, 0x00, 0x00, 0x01}, 1, now);
        table.Learn(WireMac{0x01, 0x00, 0x5E, 0x00, 0x00, 0x01}, 1, now);
        CHECK(table.Size() == 0);
        CHECK(!table.Lookup(vgww::net::kBroadcastMac).has_value());
        CHECK(!table.Lookup(WireMac{0x33, 0x33, 0x00, 0x00, 0x00, 0x01})
                   .has_value());
        // Ordinary unicast sources still learn.
        table.Learn(Mac(0x50), 2, now);
        CHECK(table.Size() == 1);
        CHECK(table.Lookup(Mac(0x50)).value() == 2);
    }

    /// Capacity clamps to [default, max]: zero selects the default, huge
    /// values clamp to the hard ceiling and the table never grows past it.
    void TestMacTableCapacityClamp() {
        CHECK(MacTable(0).Capacity() == 4096);
        CHECK(MacTable(70000).Capacity() ==
              vgww::core::limits::kMaxMacTableSize);
        MacTable table(vgww::core::limits::kMaxMacTableSize);
        CHECK(table.Capacity() == vgww::core::limits::kMaxMacTableSize);
        const auto t0 = MacTable::TimePoint{};
        for (size_t i = 0; i < vgww::core::limits::kMaxMacTableSize + 1; ++i) {
            const uint32_t hi = static_cast<uint32_t>(i >> 8);
            const uint32_t lo = static_cast<uint32_t>(i & 0xFF);
            const WireMac m = {0x02, 0x00, 0x00,
                               static_cast<uint8_t>((hi >> 8) & 0xFF),
                               static_cast<uint8_t>(hi & 0xFF),
                               static_cast<uint8_t>(lo & 0xFF)};
            table.Learn(m, 0, t0 + std::chrono::nanoseconds(i));
        }
        CHECK(table.Size() == vgww::core::limits::kMaxMacTableSize);
    }

    // ----- Task 6: table/decision coverage gaps + Backlog D6 ---------

    /// Re-learning refreshes port and timestamp without growth: a MAC that
    /// migrates ports updates its binding, and a same-port refresh keeps
    /// it alive past an aging pass that evicts an unrefreshed peer.
    void TestMacTableRepeatLearnRefreshes() {
        MacTable table;
        const auto t0 = MacTable::TimePoint{};
        table.Learn(Mac(0x60), 1, t0);
        table.Learn(Mac(0x61), 1, t0);  // control: never refreshed
        CHECK(table.Size() == 2);
        // Port migration: same MAC on a new port updates, size unchanged.
        table.Learn(Mac(0x60), 2, t0 + std::chrono::seconds(5));
        CHECK(table.Lookup(Mac(0x60)).value() == 2);
        CHECK(table.Size() == 2);
        // Same-port refresh at t0+9s; aging at t0+16s with a 10s window
        // evicts the control (age 16s) but keeps the refreshed entry
        // (age 7s, would be 11s and evicted without the refresh).
        table.Learn(Mac(0x60), 2, t0 + std::chrono::seconds(9));
        const size_t removed =
            table.Age(t0 + std::chrono::seconds(16), std::chrono::seconds(10));
        CHECK(removed == 1);
        CHECK(table.Size() == 1);
        CHECK(table.Lookup(Mac(0x60)).value() == 2);
        CHECK(!table.Lookup(Mac(0x61)).has_value());
    }

    /// batch307: eviction order is the LRU list (learn/refresh order).
    /// Exact order over three entries: refreshing A makes B the victim,
    /// then refreshing C makes A the victim.
    void TestB307MacTableEvictsLeastRecentlyRefreshed() {
        MacTable table(3);
        const auto t0 = MacTable::TimePoint{};
        table.Learn(Mac(0x70), 1, t0 + std::chrono::seconds(1));  // A
        table.Learn(Mac(0x71), 2, t0 + std::chrono::seconds(2));  // B
        table.Learn(Mac(0x72), 3, t0 + std::chrono::seconds(3));  // C
        table.Learn(Mac(0x70), 1, t0 + std::chrono::seconds(4));  // A refreshed
        table.Learn(Mac(0x73), 4, t0 + std::chrono::seconds(5));  // evicts B
        CHECK(table.Size() == 3);
        CHECK(!table.Lookup(Mac(0x71)).has_value());
        CHECK(table.Lookup(Mac(0x70)).value() == 1);
        CHECK(table.Lookup(Mac(0x72)).value() == 3);
        CHECK(table.Lookup(Mac(0x73)).value() == 4);
        CHECK(table.Evictions() == 1);
        table.Learn(Mac(0x72), 3, t0 + std::chrono::seconds(6));  // C refreshed
        table.Learn(Mac(0x74), 5, t0 + std::chrono::seconds(7));  // evicts A
        CHECK(table.Size() == 3);
        CHECK(!table.Lookup(Mac(0x70)).has_value());
        CHECK(table.Lookup(Mac(0x72)).value() == 3);
        CHECK(table.Lookup(Mac(0x73)).value() == 4);
        CHECK(table.Lookup(Mac(0x74)).value() == 5);
        CHECK(table.Evictions() == 2);
    }

    /// batch307: aging unlinks the removed entries, so the next capacity
    /// eviction still takes the true LRU tail (never a freed map node).
    void TestB307MacTableAgingKeepsLruConsistent() {
        MacTable table(3);
        const auto t0 = MacTable::TimePoint{};
        table.Learn(Mac(0x80), 1, t0);                            // A
        table.Learn(Mac(0x81), 2, t0 + std::chrono::seconds(1));  // B
        table.Learn(Mac(0x82), 3, t0 + std::chrono::seconds(2));  // C
        CHECK(table.Age(t0 + std::chrono::seconds(10),
                        std::chrono::seconds(8)) == 2);
        CHECK(table.Size() == 1);
        CHECK(table.Lookup(Mac(0x82)).value() == 3);
        table.Learn(Mac(0x83), 4, t0 + std::chrono::seconds(11));
        table.Learn(Mac(0x84), 5, t0 + std::chrono::seconds(12));
        CHECK(table.Size() == 3);
        table.Learn(Mac(0x85), 6, t0 + std::chrono::seconds(13));  // evicts C
        CHECK(table.Size() == 3);
        CHECK(!table.Lookup(Mac(0x82)).has_value());
        CHECK(table.Lookup(Mac(0x83)).value() == 4);
        CHECK(table.Lookup(Mac(0x84)).value() == 5);
        CHECK(table.Lookup(Mac(0x85)).value() == 6);
        CHECK(table.Evictions() == 1);
    }

    /// batch307: Clear/Reset drop every learned MAC and the LRU links with
    /// them (a bridge restart must not inherit stale pointers).
    void TestB307MacTableClearAndReset() {
        MacTable table(4);
        const auto t0 = MacTable::TimePoint{};
        table.Learn(Mac(0x90), 1, t0);
        table.Learn(Mac(0x91), 2, t0);
        table.Clear();
        CHECK(table.Size() == 0);
        CHECK(!table.Lookup(Mac(0x90)).has_value());
        table.Learn(Mac(0x92), 3, t0);   // links rebuilt after Clear
        CHECK(table.Lookup(Mac(0x92)).value() == 3);
        table.Reset(2);
        CHECK(table.Capacity() == 2);
        CHECK(table.Size() == 0);
        table.Learn(Mac(0x93), 4, t0);
        table.Learn(Mac(0x94), 5, t0);
        table.Learn(Mac(0x95), 6, t0);   // evicts 0x93
        CHECK(table.Size() == 2);
        CHECK(!table.Lookup(Mac(0x93)).has_value());
        CHECK(table.Evictions() == 1);
    }

    /// Exactly-14-byte frames (shortest legal Ethernet II) decide by
    /// branch and never drop; 13-byte frames drop on every branch, even
    /// gateway-addressed ones.
    void TestDecideLen14Boundary() {
        const WireMac gateway = Mac(0x30);
        const std::optional<uint32_t> known = uint32_t{5};
        const auto gw = FrameTo(gateway);
        CHECK(gw.size() == 14);
        CHECK(DecideBridgeAction(gw.data(), gw.size(), gateway, false, known) ==
              BridgeAction::kControlOnly);
        const auto bc = FrameTo(vgww::net::kBroadcastMac);
        CHECK(bc.size() == 14);
        CHECK(DecideBridgeAction(bc.data(), bc.size(), gateway, true,
                                 std::nullopt) ==
              BridgeAction::kControlAndFlood);
        const WireMac v6mcast = {0x33, 0x33, 0x00, 0x00, 0x00, 0x01};
        const auto mc = FrameTo(v6mcast);
        CHECK(DecideBridgeAction(mc.data(), mc.size(), gateway, true,
                                 std::nullopt) ==
              BridgeAction::kControlAndFlood);
        const auto ku = FrameTo(Mac(0x70));
        CHECK(DecideBridgeAction(ku.data(), ku.size(), gateway, false, known) ==
              BridgeAction::kBridgeUnicast);
        const auto uu = FrameTo(Mac(0x71));
        CHECK(DecideBridgeAction(uu.data(), uu.size(), gateway, false,
                                 std::nullopt) == BridgeAction::kBridgeFlood);
        // 13 bytes: gateway-addressed and broadcast both drop.
        std::array<uint8_t, 13> short_gw{};
        std::memcpy(short_gw.data(), gateway.data(), gateway.size());
        CHECK(vgww::bridge::DecideBridgeAction(
                  short_gw.data(), short_gw.size(), gateway, false, known) ==
              BridgeAction::kDrop);
        std::array<uint8_t, 13> short_bc{};
        std::memcpy(short_bc.data(), vgww::net::kBroadcastMac.data(),
                    vgww::net::kBroadcastMac.size());
        CHECK(vgww::bridge::DecideBridgeAction(
                  short_bc.data(), short_bc.size(), gateway, true,
                  std::nullopt) == BridgeAction::kDrop);
    }

    /// Illegal inputs never crash and always return a valid enumerator:
    /// all-zero dst (unicast, unknown -> flood / known -> unicast),
    /// all-0xFF dst (multicast flag -> both paths), null frame, absurd
    /// length against a short buffer, and empty storage.
    void TestDecideIllegalInputs() {
        const WireMac gateway = Mac(0x30);
        const WireMac zeros{};  // 00:..:00 is unicast, not a group address
        CHECK(!vgww::net::IsBroadcast(zeros));
        const auto fz = FrameTo(zeros);
        CHECK(DecideBridgeAction(fz.data(), fz.size(), gateway, false,
                                 std::nullopt) == BridgeAction::kBridgeFlood);
        CHECK(DecideBridgeAction(fz.data(), fz.size(), gateway, false,
                                   uint32_t{7}) ==
              BridgeAction::kBridgeUnicast);
        const WireMac ones = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
        const auto fo = FrameTo(ones);
        CHECK(DecideBridgeAction(fo.data(), fo.size(), gateway, true,
                                 std::nullopt) ==
              BridgeAction::kControlAndFlood);
        CHECK(vgww::bridge::DecideBridgeAction(nullptr, 0, gateway, false,
                                               std::nullopt) ==
              BridgeAction::kDrop);
        // Absurd length: only the 6-byte destination is ever read.
        CHECK(vgww::bridge::DecideBridgeAction(
                  fo.data(), static_cast<size_t>(-1), gateway, true,
                  std::nullopt) == BridgeAction::kControlAndFlood);
        const std::vector<uint8_t> empty;
        CHECK(vgww::bridge::DecideBridgeAction(empty.data(), empty.size(),
                                               gateway, false, std::nullopt) ==
              BridgeAction::kDrop);
    }

    /// Backlog D6: upstream and downstream resolving to the same adapter
    /// must refuse Start with a readable error and leave no residue.
    void TestBridgeUpstreamEqualsDownstreamRejected() {
        const vgww::core::Config config = MakeBridgeConfig();
        Dataplane dataplane(config);
        auto fake = std::make_unique<FakeBridgeDriver>();
        FakeBridgeDriver* raw = fake.get();
        (void)raw;
        dataplane.SetDriverClient(std::move(fake));
        dataplane.SetBridgeConfig(
            MakeDualBridge("TestNIC-A", "TestNIC-A"));
        std::string error;
        CHECK(!dataplane.Start(error));
        CHECK(!error.empty());
        CHECK(dataplane.GetBridgeState() == BridgeState::kStopped);
        CHECK(LifecycleEmpty(dataplane.GetLifecycleCounts()));
        std::string stop_error;
        CHECK(dataplane.Stop(stop_error));
    }

    /// S5.12: an adapter hint matching more than one adapter must refuse
    /// Start with a readable error instead of silently picking the first.
    void TestBridgeAdapterHintAmbiguousRejected() {
        vgww::core::Config config = MakeBridgeConfig();
        config.adapter = "TestNIC";  // matches \\TestNIC-A and \\TestNIC-B
        Dataplane dataplane(config);
        auto fake = std::make_unique<FakeBridgeDriver>();
        dataplane.SetDriverClient(std::move(fake));
        std::string error;
        CHECK(!dataplane.Start(error));
        const auto found = [](const std::string& hay, const char* needle) {
            return hay.find(needle) != std::string::npos;
        };
        CHECK(found(error, "ambig") || found(error, "multiple") ||
              found(error, "ambiguous"));
    }

}  // namespace

int main() {
    TestSetHwPacketFilterRoundTrip();
    TestGetHwPacketFilterDefault();
    TestSetHwPacketFilterFailurePropagates();
    TestMacLearnAndLookup();
    TestMacUnknownIsMiss();
    TestMacTableCapEvictsOldest();
    TestMacTableAging();
    TestDecideGatewayMacControlOnly();
    TestDecideBroadcastAndMulticastBothPaths();
    TestMacTableAgingBoundaryIsStrict();
    TestDecideGatewayMacOutranksTheGroupFlag();
    TestLearnAndDecideHairpinDrops();
    TestRunBridgeLoopNeverDeliversDroppedFrames();
    TestLearnAndDecideTreatsAllGroupMacsAsFlood();
    TestIsGroupAddressCoversEveryFamily();
    TestDecideKnownUnicastBridges();
    TestDecideUnknownUnicastFloods();
    TestDecideShortFrameDrops();
    TestBridgeDisabledNoop();
    TestBridgeSecondAdapterMissingFails();
    TestBridgeStartFailureNoResidue();
    TestBridgeForwardsUnknownUnicast();
    TestBroadcastGoesBothPaths();
    TestGatewayFrameNotBridged();
    TestControlReplyEgressesDownstreamPort();
    TestRelayReturnEgressesDownstreamPort();
    TestBridgeStopRestoresFilter();
    TestPortDisappearStopsBridge();
    TestB36EarlyPortGonePublishesReason();
    TestB36InLoopPortGonePublishesReason();
    TestB36BridgeErrorClearedOnCleanStop();
    TestMacTableRejectsGroupAddress();
    TestMacTableCapacityClamp();
    TestMacTableRepeatLearnRefreshes();
    TestB307MacTableEvictsLeastRecentlyRefreshed();
    TestB307MacTableAgingKeepsLruConsistent();
    TestB307MacTableClearAndReset();
    TestDecideLen14Boundary();
    TestDecideIllegalInputs();
    TestBridgeUpstreamEqualsDownstreamRejected();
    TestBridgeAdapterHintAmbiguousRejected();

    if (0 == g_failures) {
        std::puts("test_bridge: ALL PASS");
        return 0;
    }
    std::fprintf(stderr, "test_bridge: %d FAILURES\n", g_failures);
    return 1;
}
