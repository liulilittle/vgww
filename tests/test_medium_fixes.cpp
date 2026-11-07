// ============================================================================
// test_medium_fixes.cpp - Regression tests for the S1 medium-severity fixes.
//
// Self-contained in-memory driver (MediumDriver): the lifecycle suite owns
// its own TestDriverClient (Draft A) with a different fault-injection API;
// these tests must not redefine or depend on it. Product code runs verbatim
// against the driver boundary only (backtesting principle B1).
// ============================================================================
#include <winsock2.h>
#include <ws2ipdef.h>
#include <windows.h>

#include <asio.hpp>

#include "driver/idriver_client.h"
#include "ndisapi/Common.h"
#include "net/eth.h"
#include "proto/arp.h"
#include "proto/icmp.h"
#include "proto/udp.h"
#include "relay/icmp_relay.h"
#include "relay/portmap_manager.h"
#include "runtime/dataplane.h"
#include "tables/neighbors.h"
#include "web/web_api.h"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <functional>
#include <memory>
#include <mutex>
#include <new>
#include <string>
#include <thread>
#include <vector>

// ---------------------------------------------------------------------------
// Allocation counter: overrides the global operator new/delete so the M4
// zero-allocation assertion can count heap traffic during a burst window.
// new routes to malloc and delete to free (same process heap), which keeps
// the CRT/STL behavior intact.
// ---------------------------------------------------------------------------
static std::atomic<uint64_t> g_allocations{0};

// batch300: arm a one-shot allocation failure on the CALLING thread only, so
// the noexcept-survival tests are deterministic (background threads keep
// allocating normally).
static thread_local bool g_throw_next_alloc = false;

void* operator new(size_t size) {
    if (g_throw_next_alloc) {
        g_throw_next_alloc = false;
        throw std::bad_alloc();
    }
    g_allocations.fetch_add(1, std::memory_order_relaxed);
    void* p = std::malloc(size ? size : 1);
    if (nullptr == p) {
        throw std::bad_alloc();
    }
    return p;
}

void* operator new[](size_t size) { return ::operator new(size); }

void operator delete(void* p) noexcept { std::free(p); }
void operator delete[](void* p) noexcept { std::free(p); }
void operator delete(void* p, size_t) noexcept { std::free(p); }
void operator delete[](void* p, size_t) noexcept { std::free(p); }

void* operator new(size_t size, const std::nothrow_t&) noexcept {
    g_allocations.fetch_add(1, std::memory_order_relaxed);
    return std::malloc(size ? size : 1);
}

void* operator new[](size_t size, const std::nothrow_t&) noexcept {
    return ::operator new(size, std::nothrow);
}

void operator delete(void* p, const std::nothrow_t&) noexcept { std::free(p); }
void operator delete[](void* p, const std::nothrow_t&) noexcept { std::free(p); }

static uint64_t CountAllocations() {
    return g_allocations.load(std::memory_order_relaxed);
}

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
    using namespace vgww::net;
    using namespace vgww::proto;

    constexpr uint32_t kGatewayIp =
        (192u) | (0u << 8) | (168u << 16) | (40u << 24);   // 192.168.0.40
    constexpr uint32_t kClientIp =
        (192u) | (168u << 8) | (0u << 16) | (101u << 24);  // 192.168.0.101
    const WireMac kGatewayMac{0x30, 0xFC, 0x68, 0x88, 0xB4, 0xA9};
    const WireMac kClientMac{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01};
    // 127.0.0.1 in the same memcpy byte order as kGatewayIp.
    constexpr uint32_t kLoopbackIp =
        (127u) | (0u << 8) | (0u << 16) | (127u << 24);

    /// Minimal in-memory driver for the medium-fix suite.
    ///   * InjectNow: queue an inbound frame for the next ReadPackets;
    ///   * SentDown : capture everything sent toward the wire;
    ///   * arm_rx_event_ok: force ArmRxEvent failure (M5 rx_event leak).
    class MediumDriver final : public IDriverClient {
    public:
        MediumDriver() {
            AdapterEntry entry;
            entry.name = L"\\\\MediumTestNIC";
            entry.handle = this;   // any non-null unique value
            entry.mtu = 1500;
            adapters_.push_back(entry);
        }

        void InjectNow(std::vector<uint8_t> bytes) {
            std::lock_guard<std::mutex> lock(mutex_);
            inbound_.push_back(std::move(bytes));
        }

        /// batch295: allocation-free injection for the steady-state window.
        void ReserveInbound(size_t n) {
            std::lock_guard<std::mutex> lock(mutex_);
            inbound_.reserve(n);
        }
        void InjectMoved(std::vector<uint8_t>&& bytes) {
            std::lock_guard<std::mutex> lock(mutex_);
            inbound_.push_back(std::move(bytes));
        }

        const std::vector<std::vector<uint8_t>>& SentDown() const noexcept {
            return sent_down_;
        }

        /// Snapshot under the driver lock. The TX thread appends while tests
        /// poll, so the raw reference accessor must never be used for polling
        /// (a vector reallocation during a read is undefined behavior).
        std::vector<std::vector<uint8_t>> SentDownCopy() const {
            std::lock_guard<std::mutex> lock(mutex_);
            return sent_down_;
        }

        bool arm_rx_event_ok = true;

        /// M6: when set, the next ReadPackets call throws std::bad_alloc,
        /// simulating an allocation failure inside a background thread.
        /// Atomic: written by the test thread while the RX thread reads it.
        std::atomic<bool> throw_on_read{false};

        const std::vector<AdapterEntry>& Adapters() const noexcept override {
            return adapters_;
        }

        const AdapterEntry* FindAdapter(
            const std::wstring& hint,
            bool* = nullptr) const noexcept override {
            for (const AdapterEntry& adapter : adapters_) {
                if (hint.empty() ||
                    adapter.name.find(hint) != std::wstring::npos) {
                    return &adapter;
                }
            }
            return nullptr;
        }

        bool SetAdapterMode(const AdapterEntry&, uint32_t,
                            std::string&) override {
            return true;
        }

        bool SetHwPacketFilter(const AdapterEntry&, uint32_t, std::string&) override {
            return true;
        }

        bool GetHwPacketFilter(const AdapterEntry&, uint32_t& filter,
                               std::string&) override {
            filter = 0;
            return true;
        }

        bool ArmRxEvent(const AdapterEntry&, void*,
                        std::string& error) override {
            if (!arm_rx_event_ok) {
                error = "arm rx event refused (test)";
                return false;
            }
            return true;   // the RX loop polls on a 200 ms timeout
        }

        uint32_t ReadPackets(void*, INTERMEDIATE_BUFFER* buffers,
                             uint32_t max_packets, std::string&) override {
            if (throw_on_read) {
                throw std::bad_alloc();
            }
            std::lock_guard<std::mutex> lock(mutex_);
            uint32_t count = 0;
            while (count < max_packets && !inbound_.empty()) {
                const std::vector<uint8_t>& front = inbound_.front();
                if (front.size() > sizeof(buffers[count].m_IBuffer)) {
                    inbound_.erase(inbound_.begin());
                    continue;   // never overrun the driver buffer in tests
                }
                INTERMEDIATE_BUFFER& ib = buffers[count++];
                std::memset(&ib, 0, sizeof(ib));
                ib.m_dwDeviceFlags = PACKET_FLAG_ON_RECEIVE;
                ib.m_hAdapter = adapters_[0].handle;
                ib.m_Length = static_cast<DWORD>(front.size());
                std::memcpy(ib.m_IBuffer, front.data(), front.size());
                inbound_.erase(inbound_.begin());
            }
            return count;
        }

        bool SendPacketsToAdapter(void*, INTERMEDIATE_BUFFER* buffers,
                                  uint32_t count, std::string&) override {
            std::lock_guard<std::mutex> lock(mutex_);
            for (uint32_t i = 0; i < count; ++i) {
                sent_down_.emplace_back(
                    buffers[i].m_IBuffer,
                    buffers[i].m_IBuffer + buffers[i].m_Length);
            }
            return true;
        }

        bool SendPacketsToMstcp(void*, INTERMEDIATE_BUFFER* buffers,
                                uint32_t count, std::string&) override {
            std::lock_guard<std::mutex> lock(mutex_);
            for (uint32_t i = 0; i < count; ++i) {
                sent_up_.emplace_back(
                    buffers[i].m_IBuffer,
                    buffers[i].m_IBuffer + buffers[i].m_Length);
            }
            return true;
        }

        bool FlushAdapterQueue(const AdapterEntry&, std::string&) override {
            return true;
        }

        bool ResetAdapterMode(const AdapterEntry&, std::string&) override {
            return true;
        }

    private:
        std::vector<AdapterEntry> adapters_;
        mutable std::mutex mutex_;
        std::vector<std::vector<uint8_t>> inbound_;
        std::vector<std::vector<uint8_t>> sent_down_;
        std::vector<std::vector<uint8_t>> sent_up_;
    };

    vgww::core::Config MakeConfig() {
        vgww::core::Config cfg;
        cfg.adapter = "MediumTestNIC";
        cfg.gateway.ipv4 = kGatewayIp;
        cfg.gateway.mask = (255u << 24) | (255u << 16);   // 255.255.0.0 (/16)
        cfg.gateway.mac = kGatewayMac;
        cfg.perf.workers = 1;
        cfg.perf.rx_batch = 8;
        cfg.perf.ring_capacity = 256;
        cfg.perf.max_conns = 16;
        cfg.perf.dial_timeout_ms = 400;
        return cfg;
    }

    bool WaitFor(const std::function<bool()>& fn, int timeout_ms) {
        const auto deadline = std::chrono::steady_clock::now() +
                              std::chrono::milliseconds(timeout_ms);
        while (std::chrono::steady_clock::now() < deadline) {
            if (fn()) {
                return true;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
        return fn();
    }

    std::vector<uint8_t> BuildArpRequest(const WireMac& src_mac,
                                         uint32_t sender_ip) {
        std::vector<uint8_t> f(kArpFrameLen, 0);
        BuildArpFrame(f.data(), ArpOperation::kRequest, src_mac, sender_ip,
                      kBroadcastMac, kGatewayIp);
        return f;
    }

    /// batch295: IPv4 UDP request from the client to `dst_wire` (true wire
    /// order). The forward path never validates the UDP checksum, so zero
    /// is fine.
    std::vector<uint8_t> BuildUdpRequest(
        uint16_t sport, uint16_t dport,
        const std::array<uint8_t, 4>& dst_wire,
        const std::string& payload) {
        const size_t udp_len = 8 + payload.size();
        std::vector<uint8_t> f(kEthernetHeaderLen + kIpv4HeaderLenMin +
                               udp_len);
        BuildEthHeader(f.data(), kGatewayMac, kClientMac, kEthertypeIpv4);
        uint8_t* ip = f.data() + kEthernetHeaderLen;
        ip[0] = 0x45;
        const uint16_t total =
            static_cast<uint16_t>(kIpv4HeaderLenMin + udp_len);
        ip[2] = static_cast<uint8_t>(total >> 8);
        ip[3] = static_cast<uint8_t>(total & 0xFF);
        ip[8] = 64;
        ip[9] = 17;  // UDP
        std::memcpy(ip + 12, &kClientIp, 4);
        std::memcpy(ip + 16, dst_wire.data(), 4);
        uint8_t* udp = ip + kIpv4HeaderLenMin;
        udp[0] = static_cast<uint8_t>(sport >> 8);
        udp[1] = static_cast<uint8_t>(sport & 0xFF);
        udp[2] = static_cast<uint8_t>(dport >> 8);
        udp[3] = static_cast<uint8_t>(dport & 0xFF);
        udp[4] = static_cast<uint8_t>(udp_len >> 8);
        udp[5] = static_cast<uint8_t>(udp_len & 0xFF);
        std::memcpy(udp + 8, payload.data(), payload.size());
        return f;
    }

    /// batch295: IPv6 UDP request from the client to `dst` (16 bytes).
    /// The ingress path does not validate the UDP checksum; zero is fine.
    std::vector<uint8_t> BuildUdp6Request(
        uint16_t sport, uint16_t dport,
        const std::array<uint8_t, 16>& dst, const std::string& payload) {
        const size_t udp_len = 8 + payload.size();
        std::vector<uint8_t> f(kEthernetHeaderLen + 40 + udp_len);
        BuildEthHeader(f.data(), kGatewayMac, kClientMac, kEthertypeIpv6);
        uint8_t* ip = f.data() + kEthernetHeaderLen;
        ip[0] = 0x60;
        ip[4] = static_cast<uint8_t>(udp_len >> 8);
        ip[5] = static_cast<uint8_t>(udp_len & 0xFF);
        ip[6] = 17;  // next-header: UDP
        ip[7] = 64;  // hop limit
        const uint8_t src[16] = {0xFE, 0x80, 0, 0, 0, 0, 0, 0,
                                 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
                                 0x01};
        std::memcpy(ip + 8, src, 16);
        std::memcpy(ip + 24, dst.data(), 16);
        uint8_t* udp = ip + 40;
        udp[0] = static_cast<uint8_t>(sport >> 8);
        udp[1] = static_cast<uint8_t>(sport & 0xFF);
        udp[2] = static_cast<uint8_t>(dport >> 8);
        udp[3] = static_cast<uint8_t>(dport & 0xFF);
        udp[4] = static_cast<uint8_t>(udp_len >> 8);
        udp[5] = static_cast<uint8_t>(udp_len & 0xFF);
        std::memcpy(udp + 8, payload.data(), payload.size());
        return f;
    }

    bool HasFrameTo(const std::vector<std::vector<uint8_t>>& frames,
                    const WireMac& dst) {
        for (const auto& f : frames) {
            if (f.size() >= kMacAddrLen &&
                0 == std::memcmp(f.data(), dst.data(), kMacAddrLen)) {
                return true;
            }
        }
        return false;
    }

    std::string MacTextFor(uint32_t i) {
        char buf[18];
        std::snprintf(buf, sizeof(buf), "02:00:%02X:%02X:%02X:%02X",
                      (unsigned)((i >> 24) & 0xFF),
                      (unsigned)((i >> 16) & 0xFF),
                      (unsigned)((i >> 8) & 0xFF), (unsigned)(i & 0xFF));
        return buf;
    }

    // Defined below (batch305 uses it from the ban-matching case).
    std::vector<uint8_t> BuildEchoRequestTo(uint32_t dst_ip, size_t payload);

    // ------------------------------------------------------------------
    // M4a: ban matching correctness. The pre-fix toupper(char) call had UB
    // on high-bit bytes (hand-edited rules.json can inject them via AddBan,
    // which skips API validation).
    // ------------------------------------------------------------------
    void TestBanMatching() {
        auto& store = vgww::web::RuleStore::Instance();
        store.AttachFile("");     // persistence disabled: no disk I/O
        store.Clear();

        vgww::core::Config cfg = MakeConfig();
        auto drv = std::make_unique<MediumDriver>();
        MediumDriver* raw = drv.get();
        vgww::runtime::Dataplane dp(cfg);
        dp.SetDriverClient(std::move(drv));
        std::string error;
        CHECK(dp.Start(error));

        // Baseline: an ARP request from the client is answered.
        raw->InjectNow(BuildArpRequest(kClientMac, kClientIp));
        CHECK(WaitFor([&] { return HasFrameTo(raw->SentDownCopy(), kClientMac); },
                      2000));
        const size_t baseline_frames = raw->SentDownCopy().size();

        // A lowercase MAC ban must match the wire MAC (case-insensitive).
        store.AddBan(vgww::web::BanEntry{"mac", "aa:bb:cc:dd:ee:01"});
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
        // The counter is bumped at the TOP of the rebuild, so wait one more
        // tick before injecting: the frame must be judged by the published
        // snapshot, not by the one being replaced right now.
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        const uint64_t drops_before = dp.GetStats().rx_dropped.load();
        raw->InjectNow(BuildArpRequest(kClientMac, kClientIp));
        CHECK(WaitFor(
            [&] { return dp.GetStats().rx_dropped.load() > drops_before; },
            2000));
        CHECK(raw->SentDownCopy().size() == baseline_frames);   // no new reply
        store.RemoveBan(0);

        // A separator-free MAC text must match too (ParseMac semantics; the
        // old text comparison silently never matched this form).
        store.AddBan(vgww::web::BanEntry{"mac", "aabbccddee01"});
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
        const uint64_t drops_ns = dp.GetStats().rx_dropped.load();
        raw->InjectNow(BuildArpRequest(kClientMac, kClientIp));
        CHECK(WaitFor(
            [&] { return dp.GetStats().rx_dropped.load() > drops_ns; }, 2000));
        store.RemoveBan(0);

        // The malformed legacy entry (high-bit bytes) must be ignored, not
        // crash on toupper(char) UB - the pre-fix code called toupper with a
        // negative char.
        store.AddBan(vgww::web::BanEntry{"mac", "\xE9\xE9"});
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
        raw->InjectNow(BuildArpRequest(kClientMac, kClientIp));
        CHECK(WaitFor(
            [&] { return raw->SentDownCopy().size() > baseline_frames; }, 2000));
        store.RemoveBan(0);

        // An IPv4 ban matches the frame's source address.
        store.AddBan(vgww::web::BanEntry{"ip", "192.168.0.101"});
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
        const uint64_t drops2 = dp.GetStats().rx_dropped.load();
        const uint8_t src_ip[4] = {192, 168, 0, 101};
        const uint8_t dst_ip[4] = {93, 184, 216, 34};
        std::vector<uint8_t> udp;
        BuildUdpFrame(udp, kGatewayMac, kClientMac, src_ip, 51000, dst_ip, 53,
                      nullptr, 0);
        raw->InjectNow(udp);
        CHECK(WaitFor(
            [&] { return dp.GetStats().rx_dropped.load() > drops2; }, 2000));
        store.RemoveBan(0);

        // batch305: the ban snapshot is a hash index. 300 unrelated MAC
        // bans must not dilute the match (the old code scanned every entry
        // per frame), and a non-canonical IPv4 spelling must stay inert:
        // the old per-frame strcmp against the canonical dotted quad never
        // matched "192.168.000.101", so the index must not silently widen
        // what the operator blocked.
        for (int i = 0; i < 300; ++i) {
            char filler[32];
            std::snprintf(filler, sizeof(filler), "02:00:00:00:%02X:%02X",
                          (i >> 8) & 0xFF, i & 0xFF);
            store.AddBan(vgww::web::BanEntry{"mac", filler});
        }
        store.AddBan(vgww::web::BanEntry{"mac", "AA:BB:CC:DD:EE:01"});
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        const uint64_t drops_many = dp.GetStats().rx_dropped.load();
        raw->InjectNow(BuildArpRequest(kClientMac, kClientIp));
        CHECK(WaitFor(
            [&] { return dp.GetStats().rx_dropped.load() > drops_many; }, 2000));

        uint64_t mac_ban_id = 0;
        for (const auto& ban : store.Bans()) {
            if ("mac" == ban.kind && "AA:BB:CC:DD:EE:01" == ban.value) {
                mac_ban_id = ban.id;
            }
        }
        CHECK(0 != mac_ban_id);
        CHECK(store.RemoveBanById(mac_ban_id));

        store.AddBan(vgww::web::BanEntry{"ip", "192.168.000.101"});
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        const uint64_t replies_inert = dp.GetStats().icmp_replies.load();
        raw->InjectNow(BuildEchoRequestTo(kGatewayIp, 16));
        CHECK(WaitFor(
            [&] { return dp.GetStats().icmp_replies.load() > replies_inert; },
            2000));

        uint64_t noncanon_id = 0;
        for (const auto& ban : store.Bans()) {
            if ("ip" == ban.kind && "192.168.000.101" == ban.value) {
                noncanon_id = ban.id;
            }
        }
        CHECK(0 != noncanon_id);
        CHECK(store.RemoveBanById(noncanon_id));
        store.AddBan(vgww::web::BanEntry{"ip", "192.168.0.101"});
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        const uint64_t drops_canon = dp.GetStats().rx_dropped.load();
        const uint64_t replies_canon = dp.GetStats().icmp_replies.load();
        raw->InjectNow(BuildEchoRequestTo(kGatewayIp, 16));
        CHECK(WaitFor(
            [&] { return dp.GetStats().rx_dropped.load() > drops_canon; },
            2000));
        CHECK(dp.GetStats().icmp_replies.load() == replies_canon);

        store.AttachFile("");
        store.Clear();
        dp.Stop();
    }

    // ------------------------------------------------------------------
    // batch146: the control loop rebuilt the parsed firewall / rate-limit
    // snapshots on EVERY 100 ms tick - ten full passes per second over up to
    // kMaxBans entries, each re-running ParseMac and an IPv6 literal parse,
    // whether or not a single rule had changed. RuleStore already publishes a
    // monotonic Rev() for exactly this purpose; the loop simply never read it.
    // The refresh must be change-driven: frozen while the rule set is idle,
    // and still effective within one tick after every mutation.
    // ------------------------------------------------------------------
    void TestB146RuleRefreshIsChangeDriven() {
        auto& store = vgww::web::RuleStore::Instance();
        store.AttachFile("");   // persistence disabled: no disk I/O
        store.Clear();

        vgww::core::Config cfg = MakeConfig();
        auto drv = std::make_unique<MediumDriver>();
        MediumDriver* raw = drv.get();
        vgww::runtime::Dataplane dp(cfg);
        dp.SetDriverClient(std::move(drv));
        std::string error;
        CHECK(dp.Start(error));

        // The FIRST tick must publish the initial (empty) snapshots: the loop
        // cannot depend on a rev change to build its initial state.
        CHECK(WaitFor([&] { return dp.RuleSnapshotRefreshCount() >= 1; },
                      3000));

        // Idle: no rule changed, so nothing may be rebuilt. Pre-fix this grew
        // by one on every 100 ms tick.
        const uint64_t idle_base = dp.RuleSnapshotRefreshCount();
        std::this_thread::sleep_for(std::chrono::milliseconds(600));
        const uint64_t idle_growth =
            dp.RuleSnapshotRefreshCount() - idle_base;
        std::fprintf(stderr, "[b146] idle rebuilds in 600 ms: %llu\n",
                     (unsigned long long)idle_growth);
        CHECK(idle_growth == 0);

        // A ban must still be live within one tick.
        store.AddBan(vgww::web::BanEntry{"mac", "aa:bb:cc:dd:ee:01"});
        CHECK(WaitFor([&] { return dp.RuleSnapshotRefreshCount() > idle_base; },
                      2000));
        // The counter is bumped at the TOP of the rebuild, so wait one more
        // tick before injecting: the frame must be judged by the published
        // snapshot, not by the one being replaced right now.
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        const uint64_t drops_before = dp.GetStats().rx_dropped.load();
        raw->InjectNow(BuildArpRequest(kClientMac, kClientIp));
        CHECK(WaitFor(
            [&] { return dp.GetStats().rx_dropped.load() > drops_before; },
            2000));

        // ...and so must its removal: a snapshot that stopped refreshing would
        // keep dropping the client forever while the UI showed no ban.
        const uint64_t after_add = dp.RuleSnapshotRefreshCount();
        const size_t frames_before = raw->SentDownCopy().size();
        store.RemoveBan(0);
        CHECK(WaitFor([&] { return dp.RuleSnapshotRefreshCount() > after_add; },
                      2000));
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        raw->InjectNow(BuildArpRequest(kClientMac, kClientIp));
        CHECK(WaitFor(
            [&] { return raw->SentDownCopy().size() > frames_before; }, 2000));

        // The SAME rev drives the rate-limit rules too: one counter, three
        // consumers. A rate-limit-only change must also trigger a rebuild.
        const uint64_t after_remove = dp.RuleSnapshotRefreshCount();
        CHECK(store.SetRateLimitChecked(
            vgww::web::RateLimitRule{"aa:bb:cc:dd:ee:02", 1000, 1000}));
        CHECK(WaitFor(
            [&] { return dp.RuleSnapshotRefreshCount() > after_remove; },
            2000));

        std::string stop_error;
        CHECK(dp.Stop(stop_error));
        store.Clear();
        store.AttachFile("");
    }

    void InjectBurst(MediumDriver& drv, int frames) {
        for (int i = 0; i < frames; ++i) {
            drv.InjectNow(BuildArpRequest(kClientMac, kClientIp));
        }
    }

    // ------------------------------------------------------------------
    // M4b: per-frame heap traffic must NOT scale with the ban count. The
    // differential (4096 bans vs 64 bans, same burst) cancels the constant
    // control-loop noise. Pre-fix: ~2 allocations per ban per frame =>
    // 200 * 4096 * 2 >= 1.6M in the 4096-ban window alone.
    // ------------------------------------------------------------------
    void TestBanZeroAllocPerFrame() {
        auto& store = vgww::web::RuleStore::Instance();
        store.AttachFile("");
        store.Clear();
        for (uint32_t i = 0; i < 4096; ++i) {
            store.AddBan(vgww::web::BanEntry{"mac", MacTextFor(i)});
        }

        vgww::core::Config cfg = MakeConfig();
        cfg.perf.rx_batch = 32;
        auto drv = std::make_unique<MediumDriver>();
        MediumDriver* raw = drv.get();
        vgww::runtime::Dataplane dp(cfg);
        dp.SetDriverClient(std::move(drv));
        std::string error;
        CHECK(dp.Start(error));
        std::this_thread::sleep_for(std::chrono::milliseconds(400));

        // Warm-up: drain the first frames (neighbor learning, batch vector
        // growth) so the measured windows see steady-state code only.
        InjectBurst(*raw, 50);
        CHECK(WaitFor(
            [&] { return dp.GetStats().rx_frames.load() >= 50; }, 3000));
        std::this_thread::sleep_for(std::chrono::milliseconds(200));

        constexpr int kBurst = 200;
        const uint64_t base_frames = dp.GetStats().rx_frames.load();
        const uint64_t alloc_big = CountAllocations();
        InjectBurst(*raw, kBurst);
        CHECK(WaitFor(
            [&] {
                return dp.GetStats().rx_frames.load() >= base_frames + kBurst;
            },
            3000));
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        const uint64_t delta_big = CountAllocations() - alloc_big;

        // Shrink the rule set to 64 entries and repeat the identical burst.
        store.Clear();
        for (uint32_t i = 0; i < 64; ++i) {
            store.AddBan(vgww::web::BanEntry{"mac", MacTextFor(i)});
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(400));

        const uint64_t base_small = dp.GetStats().rx_frames.load();
        const uint64_t alloc_small = CountAllocations();
        InjectBurst(*raw, kBurst);
        CHECK(WaitFor(
            [&] {
                return dp.GetStats().rx_frames.load() >= base_small + kBurst;
            },
            3000));
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        const uint64_t delta_small = CountAllocations() - alloc_small;

        std::fprintf(stderr,
                     "[m4] allocations for %d frames: 4096 bans=%llu, "
                     "64 bans=%llu\n",
                     kBurst, (unsigned long long)delta_big,
                     (unsigned long long)delta_small);
        CHECK(delta_big < delta_small + 5000);   // no O(bans) heap traffic
        CHECK(delta_big < 100000);               // absolute sanity bound

        store.AttachFile("");
        store.Clear();
        dp.Stop();
    }
    // ------------------------------------------------------------------
    // batch295: the UDP forward path must install its return-path handler
    // ONCE per flow. The lambda captures the whole flow key, so assigning it
    // per packet exceeds std::function's small buffer and allocates on every
    // forwarded datagram. Measured pre-fix: one allocation per frame.
    // ------------------------------------------------------------------
    void TestB295UdpForwardInstallsHandlerOnce() {
        auto& store = vgww::web::RuleStore::Instance();
        store.AttachFile("");
        store.Clear();

        vgww::core::Config cfg = MakeConfig();
        cfg.perf.rx_batch = 32;
        cfg.perf.ring_capacity = 1024;
        auto drv = std::make_unique<MediumDriver>();
        MediumDriver* raw = drv.get();
        vgww::runtime::Dataplane dp(cfg);
        dp.SetDriverClient(std::move(drv));
        std::string error;
        CHECK(dp.Start(error));
        std::this_thread::sleep_for(std::chrono::milliseconds(400));

        // TEST-NET-1 has a default route, so the v4 relay's connect succeeds
        // and the synchronous send is dropped upstream: no async completion
        // can pollute the window. IPv6 has no default route here, so the v6
        // flow targets a silent loopback sink instead (bound, never read):
        // connect succeeds and no reply is ever produced.
        const std::array<uint8_t, 4> kUnroutable{192, 0, 2, 1};
        const std::array<uint8_t, 16> kSink6{0, 0, 0, 0, 0, 0, 0, 0,
                                             0, 0, 0, 0, 0, 0, 0, 1};
        constexpr uint16_t kSport = 51000;
        constexpr uint16_t kDport = 9;
        constexpr uint16_t kDport6 = 45681;

        asio::io_context sink_io;
        asio::ip::udp::socket sink6(sink_io);
        std::error_code sink_err;
        sink6.open(asio::ip::udp::v6(), sink_err);
        if (!sink_err) {
            sink6.bind(asio::ip::udp::endpoint(
                           asio::ip::make_address_v6("::1"), kDport6),
                       sink_err);
        }
        CHECK(!sink_err);

        // Warm-up: create both flows (socket + map node + first install).
        raw->InjectNow(BuildUdpRequest(kSport, kDport, kUnroutable, "WARM"));
        raw->InjectNow(BuildUdp6Request(kSport, kDport6, kSink6, "WARM"));
        CHECK(WaitFor([&] { return dp.GetStats().rx_frames.load() >= 2; },
                      3000));
        std::this_thread::sleep_for(std::chrono::milliseconds(200));

        // Two bursts of different size: the constant per-window noise cancels
        // in the difference, so what remains is the PER-FRAME cost. Pre-fix
        // the difference grew by roughly one allocation per extra frame.
        const auto measure = [&](int frames, bool v6) -> uint64_t {
            std::vector<std::vector<uint8_t>> batch;
            batch.reserve(static_cast<size_t>(frames));
            for (int i = 0; i < frames; ++i) {
                batch.push_back(
                    v6 ? BuildUdp6Request(kSport, kDport6, kSink6, "PING")
                       : BuildUdpRequest(kSport, kDport, kUnroutable, "PING"));
            }
            raw->ReserveInbound(batch.size());
            const uint64_t base = dp.GetStats().rx_frames.load();
            const uint64_t before = CountAllocations();
            for (auto& f : batch) {
                raw->InjectMoved(std::move(f));
            }
            CHECK(WaitFor(
                [&] {
                    return dp.GetStats().rx_frames.load() >=
                           base + static_cast<uint64_t>(frames);
                },
                8000));
            std::this_thread::sleep_for(std::chrono::milliseconds(250));
            return CountAllocations() - before;
        };

        constexpr int kB295Small = 200;
        constexpr int kB295Large = 600;
        const uint64_t v4_small = measure(kB295Small, false);
        const uint64_t v4_large = measure(kB295Large, false);
        const uint64_t v6_small = measure(kB295Small, true);
        const uint64_t v6_large = measure(kB295Large, true);

        std::fprintf(stderr,
                     "[b295] v4: %d frames=%llu, %d frames=%llu; v6: "
                     "%d frames=%llu, %d frames=%llu\n",
                     kB295Small, (unsigned long long)v4_small, kB295Large,
                     (unsigned long long)v4_large, kB295Small,
                     (unsigned long long)v6_small, kB295Large,
                     (unsigned long long)v6_large);
        // A per-frame allocation is the defect: 400 extra frames must not
        // add hundreds of allocations. The allowance covers drain noise.
        CHECK(v4_large < v4_small + 60);
        CHECK(v6_large < v6_small + 60);

        store.AttachFile("");
        store.Clear();
        dp.Stop();
    }
    // ------------------------------------------------------------------
    // batch296: NeighborTable::Tick runs on the 100 ms control loop. It used
    // to copy the whole published map and allocate a fresh snapshot on every
    // tick, even when nothing was learned and nothing aged out: with the
    // 4096-entry cap that is ~40k map-node allocations per second forever.
    // The idle tick must be allocation-free and still age entries out.
    // ------------------------------------------------------------------
    void TestB296NeighborTickIsIdleFree() {
        vgww::tables::NeighborTable table;
        const auto t0 = std::chrono::steady_clock::now();
        constexpr int kEntries = 512;
        for (int i = 0; i < kEntries; ++i) {
            const uint8_t wire[4] = {10, 0, static_cast<uint8_t>(i / 256),
                                     static_cast<uint8_t>(i % 256)};
            const std::array<uint8_t, 6> mac{
                0x02, 0x00, 0x00, 0x00, static_cast<uint8_t>(i / 256),
                static_cast<uint8_t>(i % 256)};
            table.Learn(vgww::net::IpAddress::FromV4BigEndian(wire), mac);
        }
        table.Tick(t0);  // publish
        CHECK(table.Size() == kEntries);

        const uint64_t before = CountAllocations();
        for (int i = 0; i < 200; ++i) {
            table.Tick(t0 + std::chrono::milliseconds(100 * (i + 1)));
        }
        const uint64_t delta = CountAllocations() - before;
        std::fprintf(stderr,
                     "[b296] 200 idle neighbor ticks over %d entries: "
                     "%llu allocation(s)\n",
                     kEntries, (unsigned long long)delta);
        // Pre-fix: one map copy (and a fresh snapshot) per tick => ~51200.
        CHECK(delta < 50);
        CHECK(table.Size() == kEntries);  // nothing aged out yet

        // Aging still runs: past the timeout the table must drain.
        table.Tick(t0 + std::chrono::milliseconds(
            vgww::tables::NeighborTable::kNeighborTimeoutMs + 1));
        CHECK(table.Size() == 0);
    }


    /// batch297: a 0-payload echo request whose Ethernet frame is padded to
    /// the 60-byte minimum. The driver reports the PADDED length (60), while
    /// the IP total length stays 28.
    std::vector<uint8_t> BuildPaddedEchoRequestTo(uint32_t dst_ip, uint16_t id,
                                                  uint16_t seq) {
        std::vector<uint8_t> f(60, 0);   // 14 eth + 28 ip + 18 padding
        BuildEthHeader(f.data(), kGatewayMac, kClientMac, kEthertypeIpv4);
        uint8_t* ip = f.data() + kEthernetHeaderLen;
        ip[0] = 0x45;
        const uint16_t total = kIpv4HeaderLenMin + kIcmpHeaderLen;   // 28
        ip[2] = static_cast<uint8_t>(total >> 8);
        ip[3] = static_cast<uint8_t>(total & 0xFF);
        ip[8] = 64;
        ip[9] = 1;   // ICMP
        std::memcpy(ip + 12, &kClientIp, 4);
        std::memcpy(ip + 16, &dst_ip, 4);
        uint8_t* icmp = ip + kIpv4HeaderLenMin;
        icmp[0] = kIcmpEchoRequest;
        icmp[4] = static_cast<uint8_t>(id >> 8);
        icmp[5] = static_cast<uint8_t>(id & 0xFF);
        icmp[6] = static_cast<uint8_t>(seq >> 8);
        icmp[7] = static_cast<uint8_t>(seq & 0xFF);
        return f;
    }

    // ------------------------------------------------------------------
    // batch297: the driver reports the PADDED Ethernet frame length. The
    // ICMP relay sized the relayed segment from that length, so a ping
    // with a payload shorter than 18 bytes carried the Ethernet padding as
    // payload: the remote host echoed it and the client received a reply
    // larger than it sent. The segment length must come from the IP total
    // length (the same rule HandleUdp already applies to the UDP length).
    // ------------------------------------------------------------------
    void TestB297RelayedPingDropsEthernetPadding() {
        bool can_raw = false;
        {
            asio::io_context io;
            asio::ip::icmp::socket probe(io);
            std::error_code ec;
            probe.open(asio::ip::icmp::v4(), ec);
            can_raw = !ec;
        }
        if (!can_raw) {
            std::fprintf(stderr,
                         "[b297] SKIP: raw ICMP socket unavailable "
                         "(run elevated to execute this case)\n");
            return;
        }

        vgww::core::Config cfg = MakeConfig();
        auto drv = std::make_unique<MediumDriver>();
        MediumDriver* raw = drv.get();
        vgww::runtime::Dataplane dp(cfg);
        dp.SetDriverClient(std::move(drv));
        std::string error;
        CHECK(dp.Start(error));

        // The relay needs the client MAC: learn it via ARP first.
        raw->InjectNow(BuildArpRequest(kClientMac, kClientIp));
        CHECK(WaitFor([&] { return dp.GetStats().arp_replies.load() > 0; },
                      2000));
        std::this_thread::sleep_for(std::chrono::milliseconds(250));

        // 0-payload echo request to loopback: IP total = 28, frame = 60.
        std::vector<uint8_t> ping = BuildPaddedEchoRequestTo(kLoopbackIp,
                                                             0x1234, 7);
        CHECK(60 == ping.size());
        raw->InjectNow(std::move(ping));

        // The relay tags and sends it; the local stack answers; the reply
        // is rebuilt toward the client and leaves through the driver.
        std::vector<uint8_t> reply;
        const bool got = WaitFor(
            [&] {
                for (const auto& f : raw->SentDownCopy()) {
                    if (f.size() < kEthernetHeaderLen + kIpv4HeaderLenMin +
                                      kIcmpHeaderLen) {
                        continue;
                    }
                    const uint8_t* ip = f.data() + kEthernetHeaderLen;
                    if (0x08 != f[12] || 0x00 != f[13] || 1 != ip[9] ||
                        kIcmpEchoReply != ip[kIpv4HeaderLenMin]) {
                        continue;
                    }
                    const uint16_t id = static_cast<uint16_t>(
                        (ip[kIpv4HeaderLenMin + 4] << 8) |
                        ip[kIpv4HeaderLenMin + 5]);
                    if (0x1234 == id) {
                        reply = f;
                        return true;
                    }
                }
                return false;
            },
            3000);
        CHECK(got);
        if (got) {
            const uint8_t* ip = reply.data() + kEthernetHeaderLen;
            const uint16_t total = static_cast<uint16_t>((ip[2] << 8) | ip[3]);
            std::fprintf(stderr, "[b297] reply frame=%zu ip_total=%u\n",
                         reply.size(), static_cast<unsigned>(total));
            // Pre-fix: 46 (28 + the 18 padding bytes echoed back).
            CHECK(kIpv4HeaderLenMin + kIcmpHeaderLen == total);
            CHECK(kEthernetHeaderLen + kIpv4HeaderLenMin + kIcmpHeaderLen ==
                  reply.size());
        }
        dp.Stop();
    }

    // ------------------------------------------------------------------
    // batch300: NeighborTable::Learn is noexcept and is called from the RX
    // thread (DispatchFrame). A pending-map allocation failure used to call
    // std::terminate and kill the whole gateway; it must be a refused learn
    // instead, and the table must stay usable.
    // ------------------------------------------------------------------
    void TestB300LearnSurvivesAllocationFailure() {
        vgww::tables::NeighborTable table;
        const uint8_t wire[4] = {10, 0, 0, 1};
        const std::array<uint8_t, 6> mac{0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
        const auto ip = vgww::net::IpAddress::FromV4BigEndian(wire);
        g_throw_next_alloc = true;
        table.Learn(ip, mac);   // must not throw / terminate
        CHECK(g_throw_next_alloc == false);   // the hook fired
        CHECK(0 == table.PendingUpdates());
        CHECK(1 == table.RejectedCount());
        // The table is still usable: the next learn succeeds.
        table.Learn(ip, mac);
        CHECK(1 == table.PendingUpdates());
        CHECK(1 == table.RejectedCount());
    }

    void TestPortMapQueueBound() {
        auto& pm = vgww::relay::PortMapManager::Instance();
        const uint64_t dropped_before = pm.DroppedPackets();
        const uint8_t payload[8] = {1, 2, 3, 4, 5, 6, 7, 8};
        size_t accepted = 0;
        for (int i = 0; i < 200; ++i) {
            const bool queued =
                pm.OnStackData(0xDEAD, payload, sizeof(payload));
            if (queued) {
                ++accepted;
            }
            // Exact boundary with an empty queue (cleared by the previous
            // Stop): the 64th call still reports true (check-before-enqueue:
            // 64 entries, queue not yet over the cap); the 65th is refused.
            if (62 == i) CHECK(queued);
            if (63 == i) CHECK(queued);
        }
        CHECK(64 == accepted);
        CHECK(pm.DroppedPackets() >= dropped_before + (200 - 64));

        // Boundary/edge semantics: the queue is at its cap now, so the very
        // next call must be refused outright, counted monotonically, and
        // must not disturb the queued entries (window 0 backpressure).
        const uint64_t dropped_at_cap = pm.DroppedPackets();
        CHECK(!pm.OnStackData(0xDEAD, payload, sizeof(payload)));
        CHECK(pm.DroppedPackets() == dropped_at_cap + 1);
    }

    std::vector<uint8_t> BuildEchoRequestTo(uint32_t dst_ip, size_t payload) {
        const size_t icmp_len = kIcmpHeaderLen + payload;
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
        ip[9] = 1;   // ICMP
        std::memcpy(ip + 12, &kClientIp, 4);
        std::memcpy(ip + 16, &dst_ip, 4);
        uint8_t* icmp = ip + kIpv4HeaderLenMin;
        icmp[0] = kIcmpEchoRequest;
        return f;
    }

    // ------------------------------------------------------------------
    // M10: when the global ICMP tag table is full, Allocate returns 0 and
    // the relay must SKIP the ping (and count it). Pre-fix the client id
    // was rewritten to the reserved tag 0 and sent out - a silent
    // black hole. This case needs a raw ICMP socket (the relay slot is
    // only created with the privilege); without it the test reports SKIP
    // instead of a false PASS (B1: declared simulation gap).
    // ------------------------------------------------------------------
    void TestIcmpTagExhaustion() {
        bool can_raw = false;
        {
            asio::io_context io;
            asio::ip::icmp::socket probe(io);
            std::error_code ec;
            probe.open(asio::ip::icmp::v4(), ec);
            can_raw = !ec;
        }
        if (!can_raw) {
            std::fprintf(stderr,
                         "[m10] SKIP: raw ICMP socket unavailable "
                         "(run elevated to execute this case)\n");
            return;
        }

        auto& store = vgww::web::RuleStore::Instance();
        store.AttachFile("");
        store.Clear();

        vgww::core::Config cfg = MakeConfig();
        auto drv = std::make_unique<MediumDriver>();
        MediumDriver* raw = drv.get();
        vgww::runtime::Dataplane dp(cfg);
        dp.SetDriverClient(std::move(drv));
        std::string error;
        CHECK(dp.Start(error));

        // The relay needs the client MAC: learn it via ARP first.
        raw->InjectNow(BuildArpRequest(kClientMac, kClientIp));
        CHECK(WaitFor([&] { return dp.GetStats().arp_replies.load() > 0; },
                      2000));
        std::this_thread::sleep_for(std::chrono::milliseconds(200));

        // Fill every usable tag (tag 0 stays reserved). Each entry lives 3 s,
        // so the injection below must happen well inside that window.
        auto& alloc = vgww::relay::IcmpRelay::TagAllocator::Instance();
        vgww::relay::IcmpRelay::TagEntry entry{};
        const auto now = std::chrono::steady_clock::now();
        size_t live = 0;
        while (0 != alloc.Allocate(entry, now)) {
            if (++live > 70000) {
                break;   // safety: the allocator must exhaust long before
            }
        }
        CHECK(live > 0);
        CHECK(0 == alloc.Allocate(entry, now));   // pool is full now

        constexpr uint32_t kRemoteIp =
            (93u) | (184u << 8) | (216u << 16) | (34u << 24);   // 93.184.216.34
        const uint64_t exhausted_before =
            dp.GetStats().icmp_tag_exhausted.load();
        raw->InjectNow(BuildEchoRequestTo(kRemoteIp, 16));
        CHECK(WaitFor(
            [&] {
                return dp.GetStats().icmp_tag_exhausted.load() >
                       exhausted_before;
            },
            1500));
        CHECK(dp.GetStats().icmp_tag_exhausted.load() > exhausted_before);

        // Leave the process-global table clean for any later test.
        alloc.Sweep(std::chrono::steady_clock::now() +
                    std::chrono::seconds(10));
        dp.Stop();
    }

    // ------------------------------------------------------------------
    // M5: a failed StartAll must not leak the armed rx_event handle. The
    // leaked handles only show while the Dataplane objects are still alive
    // (StopAll closes rx_event), so all planes stay alive until measured.
    // ------------------------------------------------------------------
    void TestRxEventNoLeakOnArmFailure() {
        // Warm up once so one-time process/handle setup is not counted.
        {
            vgww::core::Config cfg = MakeConfig();
            auto drv = std::make_unique<MediumDriver>();
            drv->arm_rx_event_ok = false;
            vgww::runtime::Dataplane dp(cfg);
            dp.SetDriverClient(std::move(drv));
            std::string error;
            CHECK(!dp.Start(error));
        }

        std::vector<vgww::core::Config> cfgs(16, MakeConfig());
        std::vector<std::unique_ptr<vgww::runtime::Dataplane>> planes;
        planes.reserve(cfgs.size());

        DWORD before = 0;
        CHECK(0 != ::GetProcessHandleCount(::GetCurrentProcess(), &before));
        for (size_t i = 0; i < cfgs.size(); ++i) {
            auto drv = std::make_unique<MediumDriver>();
            drv->arm_rx_event_ok = false;
            auto dp = std::make_unique<vgww::runtime::Dataplane>(cfgs[i]);
            dp->SetDriverClient(std::move(drv));
            std::string error;
            CHECK(!dp->Start(error));   // ArmRxEvent refuses -> Start false
            planes.push_back(std::move(dp));
        }
        DWORD after = 0;
        CHECK(0 != ::GetProcessHandleCount(::GetCurrentProcess(), &after));
        // 16 leaked rx_event handles would add >= 16; the RAII owner keeps
        // the delta at (near) zero.
        CHECK(after <= before + 2);

        planes.clear();   // Stop() runs; pre-fix leaks would close here
    }

    // ------------------------------------------------------------------
    // M6: an exception escaping a data-plane thread must not terminate the
    // process. Pre-fix this test never reaches its assertions: the RX thread
    // throws and std::terminate kills the test binary (ctest reports a
    // crash). Post-fix the event is counted and Stop() stays joinable.
    // ------------------------------------------------------------------
    void TestThreadExceptionFirewall() {
        vgww::core::Config cfg = MakeConfig();
        auto drv = std::make_unique<MediumDriver>();
        MediumDriver* raw = drv.get();
        vgww::runtime::Dataplane dp(cfg);
        dp.SetDriverClient(std::move(drv));
        std::string error;
        CHECK(dp.Start(error));

        raw->throw_on_read = true;   // next RX poll throws std::bad_alloc

        bool counted = false;
        for (int i = 0; i < 300; ++i) {   // up to 3 s (RX polls every 200 ms)
            if (dp.GetStats().thread_errors.load() > 0) {
                counted = true;
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        CHECK(counted);

        const auto t0 = std::chrono::steady_clock::now();
        std::string stop_error;
        CHECK(dp.Stop(stop_error));       // controlled shutdown, never a hang
        CHECK(stop_error.empty());
        const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::steady_clock::now() - t0).count();
        CHECK(ms < 6000);
    }

    // Second ArmRxEvent failure on the SAME plane (after a clean Stop reset
    // the adapter state): the failed-start path must stay leak-free too.
    void TestDoubleStartFailureNoLeak() {
        vgww::core::Config cfg = MakeConfig();
        auto drv = std::make_unique<MediumDriver>();
        drv->arm_rx_event_ok = false;
        vgww::runtime::Dataplane dp(cfg);
        dp.SetDriverClient(std::move(drv));

        DWORD before = 0;
        CHECK(0 != ::GetProcessHandleCount(::GetCurrentProcess(), &before));

        std::string error;
        CHECK(!dp.Start(error));
        CHECK(error.find("arm rx event refused") != std::string::npos);
        error.clear();
        CHECK(dp.Stop(error));   // clean the failed-start residue
        error.clear();
        CHECK(!dp.Start(error));   // second arm failure on the same plane
        CHECK(error.find("arm rx event refused") != std::string::npos);
        error.clear();
        CHECK(dp.Stop(error));

        DWORD after = 0;
        CHECK(0 != ::GetProcessHandleCount(::GetCurrentProcess(), &after));
        CHECK(after <= before + 2);
    }

    // Repeated StopAll on a plane whose Start never succeeded: must be
    // idempotent (no crash, no handle growth).
    void TestRepeatedStopOnFailedPlaneIsSafe() {
        vgww::core::Config cfg = MakeConfig();
        auto drv = std::make_unique<MediumDriver>();
        drv->arm_rx_event_ok = false;
        vgww::runtime::Dataplane dp(cfg);
        dp.SetDriverClient(std::move(drv));

        DWORD before = 0;
        CHECK(0 != ::GetProcessHandleCount(::GetCurrentProcess(), &before));

        std::string error;
        CHECK(!dp.Start(error));
        error.clear();
        CHECK(dp.Stop(error));
        error.clear();
        CHECK(dp.Stop(error));   // second stop: idempotent

        DWORD after = 0;
        CHECK(0 != ::GetProcessHandleCount(::GetCurrentProcess(), &after));
        CHECK(after <= before + 2);
    }

    // ------------------------------------------------------------------
    // batch128: the cap pre-checks on the WRITE paths called
    // PortMaps()/Bans() (full vector copies, strings included) just to read
    // .size(), and called them TWICE per request (once to scan for a
    // duplicate, once for the cap). The cap itself is enforced inside
    // AddPortMap/AddBanChecked under the lock (batch34o/batch89), so the
    // pre-check only needs a cheap count. O(1) counters must agree exactly
    // with the snapshot sizes at every stage.
    // ------------------------------------------------------------------
    void TestRuleStoreCountsAreConsistent() {
        auto& store = vgww::web::RuleStore::Instance();
        store.AttachFile("");  // persistence disabled: no disk I/O
        store.Clear();

        CHECK(0 == store.PortMapCount());
        CHECK(store.PortMapCount() == store.PortMaps().size());
        CHECK(0 == store.BanCount());
        CHECK(store.BanCount() == store.Bans().size());

        vgww::web::PortMappingRule rule;
        rule.proto = "tcp";
        rule.wan_port = 20001;
        rule.lan_ip = "192.168.0.60";
        rule.lan_port = 80;
        CHECK(store.AddPortMap(rule));
        CHECK(1 == store.PortMapCount());
        CHECK(store.PortMapCount() == store.PortMaps().size());

        // A rejected duplicate must not change the count.
        CHECK(!store.AddPortMap(rule));
        CHECK(1 == store.PortMapCount());
        CHECK(store.PortMapCount() == store.PortMaps().size());

        store.AddBan(vgww::web::BanEntry{"ip", "10.1.2.3"});
        CHECK(1 == store.BanCount());
        CHECK(store.BanCount() == store.Bans().size());

        // A second ban adds one; removal brings it back.
        store.AddBan(vgww::web::BanEntry{"mac", "AA:BB:CC:DD:EE:02"});
        CHECK(2 == store.BanCount());
        CHECK(store.BanCount() == store.Bans().size());
        store.RemoveBan(0);
        CHECK(1 == store.BanCount());
        CHECK(store.BanCount() == store.Bans().size());

        store.Clear();
        CHECK(0 == store.PortMapCount());
        CHECK(0 == store.BanCount());
    }

    // ------------------------------------------------------------------
    // batch129: the rule getters returned std::vector<T> BY VALUE, so every
    // reader (1 Hz reconciliation, each POST pre-check, each UI tick, each
    // GET) paid a deep copy with strings. They now return a zero-copy view
    // over an immutable snapshot. Two properties must hold:
    //   1) no copy: two reads without a mutation observe the SAME buffer;
    //   2) freshness: EVERY mutation path (add / remove / upsert / load /
    //      clear) republishes, otherwise the data plane and the WebUI would
    //      keep running on stale rules with no error anywhere.
    // ------------------------------------------------------------------
    void TestRuleStoreSnapshotsTrackMutations() {
        auto& store = vgww::web::RuleStore::Instance();
        store.AttachFile("");  // persistence disabled: no disk I/O
        store.Clear();

        vgww::web::PortMappingRule first;
        first.proto = "tcp";
        first.wan_port = 21001;
        first.lan_ip = "192.168.0.71";
        first.lan_port = 81;
        const uint64_t first_id = store.AddPortMapTracked(first);
        CHECK(first_id != 0);

        {
            const auto a = store.PortMaps();
            const auto b = store.PortMaps();
            CHECK(1 == a.size());
            CHECK(1 == b.size());
            // Zero-copy: both reads share one buffer.
            CHECK(&a[0] == &b[0]);
            CHECK("tcp" == a[0].proto);
            CHECK(21001 == a[0].wan_port);
            CHECK("192.168.0.71" == a[0].lan_ip);
            CHECK(81 == a[0].lan_port);
        }

        // A published view must NOT be mutated in place by a later write:
        // the data plane may still be iterating the old buffer.
        const auto before = store.PortMaps();
        vgww::web::PortMappingRule second;
        second.proto = "udp";
        second.wan_port = 21002;
        second.lan_ip = "192.168.0.72";
        second.lan_port = 82;
        CHECK(store.AddPortMap(second));
        CHECK(1 == before.size());            // old view unchanged
        CHECK(2 == store.PortMaps().size());  // new view sees both
        CHECK(21002 == store.PortMaps()[1].wan_port);

        // Removal republishes too - assert content, not just the size.
        CHECK(store.RemovePortMapById(first_id));
        {
            const auto after = store.PortMaps();
            CHECK(1 == after.size());
            CHECK(21002 == after[0].wan_port);
            CHECK("192.168.0.72" == after[0].lan_ip);
        }

        // Bans.
        store.AddBan(vgww::web::BanEntry{"ip", "10.9.9.1"});
        store.AddBan(vgww::web::BanEntry{"mac", "AA:BB:CC:DD:EE:09"});
        CHECK(2 == store.Bans().size());
        CHECK("mac" == store.Bans()[1].kind);
        store.RemoveBan(0);
        {
            const auto bans = store.Bans();
            CHECK(1 == bans.size());
            CHECK("AA:BB:CC:DD:EE:09" == bans[0].value);
        }

        // Rate limits: an upsert updates in place (same size) and a removal
        // republishes.
        store.SetRateLimit(
            vgww::web::RateLimitRule{"11:22:33:44:55:01", 100, 200});
        store.SetRateLimit(
            vgww::web::RateLimitRule{"11:22:33:44:55:01", 300, 400});
        {
            const auto rl = store.RateLimits();
            CHECK(1 == rl.size());
            CHECK(300 == rl[0].uplink_kbps);
            CHECK(400 == rl[0].downlink_kbps);
        }
        CHECK(store.RemoveRateLimit("11:22:33:44:55:01"));
        CHECK(0 == store.RateLimits().size());

        // Load path: a restart must republish too, otherwise the WebUI and
        // the data plane would run on an empty snapshot until the first edit.
        {
            char dir[MAX_PATH] = {0};
            if (0 != GetTempPathA(MAX_PATH, dir)) {
                const std::string path =
                    std::string(dir) + "vgww_rulestore_b129_" +
                    std::to_string(GetCurrentProcessId()) + ".json";
                {
                    std::ofstream out(path.c_str(), std::ios::binary);
                    out << "{\"portmaps\":[{\"proto\":\"tcp\","
                           "\"wan_port\":22001,\"lan_ip\":\"192.168.0.80\","
                           "\"lan_port\":8080}],"
                           "\"bans\":[{\"kind\":\"ip\","
                           "\"value\":\"10.9.9.2\"}],"
                           "\"ratelimits\":[{\"mac\":\"11:22:33:44:55:02\","
                           "\"uplink_kbps\":500,\"downlink_kbps\":600}]}";
                }
                std::string error;
                CHECK(store.AttachFileChecked(path, error));
                CHECK(1 == store.PortMaps().size());
                CHECK(22001 == store.PortMaps()[0].wan_port);
                CHECK("192.168.0.80" == store.PortMaps()[0].lan_ip);
                CHECK(1 == store.Bans().size());
                CHECK("10.9.9.2" == store.Bans()[0].value);
                CHECK(1 == store.RateLimits().size());
                CHECK(500 == store.RateLimits()[0].uplink_kbps);
                store.AttachFile("");
                std::remove(path.c_str());
            }
        }

        store.Clear();
        CHECK(0 == store.PortMaps().size());
        CHECK(0 == store.Bans().size());
        CHECK(0 == store.RateLimits().size());
        CHECK(store.PortMaps().empty());
        CHECK(store.Bans().empty());
        CHECK(store.RateLimits().empty());
    }

    // ------------------------------------------------------------------
    // batch131: the loader claimed (web_api.cpp "the file must satisfy the
    // SAME contract the POST route enforces") but only mirrored the FIELD
    // validation, not the UNIQUENESS rules:
    //   * POST /api/portmap refuses a second rule for the same WAN endpoint,
    //     yet the loader kept both. PortMapManager keys acceptors by
    //     "proto:wan_port", so the second copy could never bind - the UI
    //     listed a rule that was silently dead.
    //   * POST /api/ratelimit UPSERTS by MAC, yet the loader appended both.
    //     RateLimiter::Allow() takes the FIRST match, so the file's newer
    //     values were silently ignored (the stale cap stayed in force).
    // ------------------------------------------------------------------
    void TestRuleStoreLoadMirrorsWriteInvariants() {
        auto& store = vgww::web::RuleStore::Instance();
        store.AttachFile("");
        store.Clear();

        char dir[MAX_PATH] = {0};
        if (0 == GetTempPathA(MAX_PATH, dir)) {
            CHECK(false);
            return;
        }
        const std::string path = std::string(dir) + "vgww_rulestore_b131_" +
                                 std::to_string(GetCurrentProcessId()) +
                                 ".json";
        {
            std::ofstream out(path.c_str(), std::ios::binary);
            out << "{"
                   "\"portmaps\":["
                   "{\"proto\":\"tcp\",\"wan_port\":23001,"
                   "\"lan_ip\":\"192.168.0.91\",\"lan_port\":80},"
                   "{\"proto\":\"tcp\",\"wan_port\":23001,"
                   "\"lan_ip\":\"192.168.0.92\",\"lan_port\":81},"
                   "{\"proto\":\"tcp\",\"wan_port\":23002,"
                   "\"lan_ip\":\"192.168.0.93\",\"lan_port\":82}],"
                   "\"ratelimits\":["
                   "{\"mac\":\"11:22:33:44:55:11\","
                   "\"uplink_kbps\":100,\"downlink_kbps\":200},"
                   "{\"mac\":\"11:22:33:44:55:11\","
                   "\"uplink_kbps\":300,\"downlink_kbps\":400}]"
                   "}";
        }
        std::string error;
        CHECK(store.AttachFileChecked(path, error));

        // Duplicate WAN endpoint: the first occurrence keeps the endpoint
        // (mirrors POST's refusal of the later one).
        CHECK(2 == store.PortMaps().size());
        CHECK(23001 == store.PortMaps()[0].wan_port);
        CHECK("192.168.0.91" == store.PortMaps()[0].lan_ip);
        CHECK(23002 == store.PortMaps()[1].wan_port);
        CHECK("192.168.0.93" == store.PortMaps()[1].lan_ip);

        // Duplicate MAC: upsert semantics, so the LAST values win.
        CHECK(1 == store.RateLimits().size());
        CHECK("11:22:33:44:55:11" == store.RateLimits()[0].mac);
        CHECK(300 == store.RateLimits()[0].uplink_kbps);
        CHECK(400 == store.RateLimits()[0].downlink_kbps);

        // Both collapses are reported, never silent.
        CHECK(2 == store.DiscardedOnLastLoad());

        store.AttachFile("");
        std::remove(path.c_str());
        store.Clear();
    }

    // ------------------------------------------------------------------
    // batch136: editing a rate limit's MAC is "remove the old rule, add the
    // new one" - TWO independent commands in the UI (ratelimit.cpp), each of
    // which can be refused on its own:
    //   * SubmitCommand returns false when the command queue is full (it
    //     then only shows a "busy" toast), and
    //   * SetRateLimitChecked returns false at the kMaxRateLimits cap.
    // Any split leaves the store in the losing half-state: the old rule is
    // gone and the new one was never written, so the client silently loses
    // its cap. The store must expose ONE call that does both under a single
    // lock, and that call must be all-or-nothing.
    // ------------------------------------------------------------------
    void TestRuleStoreReplaceRateLimitIsAtomic() {
        auto& store = vgww::web::RuleStore::Instance();
        store.AttachFile("");
        store.Clear();

        CHECK(store.SetRateLimitChecked(
            vgww::web::RateLimitRule{"11:22:33:44:55:01", 100, 200}));
        CHECK(1 == store.RateLimits().size());

        // Happy path: one old MAC, one new MAC, both limits carried over.
        CHECK(store.ReplaceRateLimitChecked("11:22:33:44:55:01",
                                            vgww::web::RateLimitRule{
                                                "11:22:33:44:55:02", 300,
                                                400}));
        {
            const auto rules = store.RateLimits();
            CHECK(1 == rules.size());
            CHECK("11:22:33:44:55:02" == rules[0].mac);
            CHECK(300 == rules[0].uplink_kbps);
            CHECK(400 == rules[0].downlink_kbps);
        }

        // The OLD mac must be absent - a "replace" that left it behind would
        // keep throttling a client the operator just re-keyed.
        for (const auto& rule : store.RateLimits()) {
            CHECK(0 != _stricmp(rule.mac.c_str(), "11:22:33:44:55:01"));
        }

        // No old rule (a plain add through the same call) still works.
        CHECK(store.ReplaceRateLimitChecked(
            "", vgww::web::RateLimitRule{"11:22:33:44:55:03", 500, 600}));
        CHECK(2 == store.RateLimits().size());

        // All-or-nothing at the cap. Re-keying a DIFFERENT mac frees its own
        // slot, so it is allowed and the size stays at the cap.
        store.Clear();
        const std::size_t cap = ::vgww::core::limits::kMaxRateLimits;
        for (std::size_t i = 0; i < cap; ++i) {
            char mac[24];
            std::snprintf(mac, sizeof(mac), "02:00:00:%02X:%02X:%02X",
                          static_cast<unsigned>((i >> 16) & 0xFF),
                          static_cast<unsigned>((i >> 8) & 0xFF),
                          static_cast<unsigned>(i & 0xFF));
            CHECK(store.SetRateLimitChecked(
                vgww::web::RateLimitRule{mac,
                                         static_cast<uint32_t>(100 + i), 200}));
        }
        CHECK(cap == store.RateLimits().size());
        const std::string keep = store.RateLimits()[0].mac;
        CHECK(store.ReplaceRateLimitChecked(
            keep, vgww::web::RateLimitRule{"02:FF:FF:FF:FF:FE", 900, 900}));
        CHECK(cap == store.RateLimits().size());  // freed its own slot
        {
            bool old_gone = true;
            bool new_present = false;
            for (const auto& rule : store.RateLimits()) {
                if (0 == _stricmp(rule.mac.c_str(), keep.c_str())) {
                    old_gone = false;
                }
                if (0 == _stricmp(rule.mac.c_str(), "02:FF:FF:FF:FF:FE")) {
                    new_present = true;
                    CHECK(900 == rule.uplink_kbps);
                }
            }
            CHECK(old_gone);
            CHECK(new_present);
        }

        // A plain insert of a NEW mac at the cap is refused and changes
        // NOTHING (no slot freed, no partial write).
        CHECK(!store.ReplaceRateLimitChecked(
            "", vgww::web::RateLimitRule{"02:FF:FF:FF:FF:FF", 900, 900}));
        CHECK(cap == store.RateLimits().size());
        {
            bool added = false;
            for (const auto& rule : store.RateLimits()) {
                if (0 == _stricmp(rule.mac.c_str(), "02:FF:FF:FF:FF:FF")) {
                    added = true;
                }
            }
            CHECK(!added);
        }

        // An INVALID rule (both kbps zero) must also change nothing - in
        // particular it must not delete old_mac while refusing the new rule.
        {
            const std::string victim = store.RateLimits()[0].mac;
            const uint32_t victim_up = store.RateLimits()[0].uplink_kbps;
            CHECK(!store.ReplaceRateLimitChecked(
                victim, vgww::web::RateLimitRule{"02:FF:FF:FF:FF:FD", 0, 0}));
            CHECK(cap == store.RateLimits().size());
            bool victim_intact = false;
            for (const auto& rule : store.RateLimits()) {
                if (0 == _stricmp(rule.mac.c_str(), victim.c_str())) {
                    victim_intact = true;
                    CHECK(victim_up == rule.uplink_kbps);
                }
            }
            CHECK(victim_intact);
        }

        store.Clear();
        CHECK(store.RateLimits().empty());
    }

}  // namespace

int main() {
    TestRxEventNoLeakOnArmFailure();
    TestThreadExceptionFirewall();
    TestBanMatching();
    TestB146RuleRefreshIsChangeDriven();
    TestBanZeroAllocPerFrame();
    TestB295UdpForwardInstallsHandlerOnce();
    TestB296NeighborTickIsIdleFree();
    TestB297RelayedPingDropsEthernetPadding();
    TestB300LearnSurvivesAllocationFailure();
    TestPortMapQueueBound();
    TestRuleStoreCountsAreConsistent();
    TestRuleStoreSnapshotsTrackMutations();
    TestRuleStoreLoadMirrorsWriteInvariants();
    TestRuleStoreReplaceRateLimitIsAtomic();
    TestIcmpTagExhaustion();   // last: fills then sweeps the global tag table
    TestDoubleStartFailureNoLeak();
    TestRepeatedStopOnFailedPlaneIsSafe();
    if (0 == g_failures) {
        std::puts("test_medium_fixes: ALL PASS");
        return 0;
    }
    std::fprintf(stderr, "test_medium_fixes: %d FAILURES\n", g_failures);
    return 1;
}
