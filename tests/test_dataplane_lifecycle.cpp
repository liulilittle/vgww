// ============================================================================
// test_dataplane_lifecycle.cpp - H2/H3 lifecycle regression:
//   * Start -> Stop -> Start x3 must fully reset every container (rings,
//     io_contexts, UDP/ICMP tables, relay registry) and keep the process
//     handle count flat.
//   * A driver read that blocks forever must make Stop() return false and
//     must NOT TerminateThread + free the thread-reachable objects; the
//     dataplane refuses to Start again (shutdown_incomplete).
//   * An injected read failure must never crash and still stop cleanly.
// ============================================================================
#include <winsock2.h>
#include <ws2ipdef.h>
#include <windows.h>

#include "runtime/dataplane.h"

#include "driver/idriver_client.h"
#include "ndisapi/Common.h"
#include "proto/dhcp6.h"
#include "proto/udp.h"
#include "relay/portmap_manager.h"
#include "ui/controller.h"

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <deque>
#include <filesystem>
#include <fstream>
#include <io.h>
#include <memory>
#include <mutex>
#include <sstream>
#include <stdexcept>
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

    // ------------------------------------------------------------------
    // Driver double with fault injection (boundary simulation only; the
    // product data plane runs verbatim).
    //
    //   void SetBlockReads(bool block)
    //       true -> ReadPackets blocks until SetBlockReads(false).
    //   size_t FailReadAfter(size_t reads_before_failure)
    //       the (N+1)-th and later ReadPackets calls return 0 with an error
    //       string; returns the previous threshold.
    // ------------------------------------------------------------------
    class FakeDriverClient final : public IDriverClient {
    public:
        /// Primary (control-plane) adapter index; 1 is the bridge peer.
        static constexpr int kPortA = 0;
        static constexpr int kPortB = 1;

        FakeDriverClient() {
            AdapterEntry entry;
            entry.name = L"\\\\TestNIC";
            entry.handle = this;
            entry.mtu = 1500;
            adapters_.push_back(entry);
            AdapterEntry peer;
            peer.name = L"\\\\TestNIC-B";
            peer.handle = reinterpret_cast<void*>(
                static_cast<uintptr_t>(0xB110C0DEu));
            peer.mtu = 1500;
            adapters_.push_back(peer);
        }

        void SetBlockReads(bool block) {
            std::lock_guard<std::mutex> lock(mutex_);
            block_reads_ = block;
            if (!block_reads_) {
                cv_.notify_all();
            }
        }

        /// True once at least one ReadPackets call is parked on the block.
        bool WaitUntilReadBlocked(int timeout_ms) {
            std::unique_lock<std::mutex> lock(mutex_);
            return cv_.wait_for(lock, std::chrono::milliseconds(timeout_ms),
                                [this] { return blocked_reads_ > 0; });
        }

        size_t FailReadAfter(size_t reads_before_failure) {
            std::lock_guard<std::mutex> lock(mutex_);
            const size_t previous = fail_after_;
            fail_after_ = reads_before_failure;
            return previous;
        }

        /// Queues one inbound frame for the next ReadPackets call
        /// (primary adapter).
        void InjectFrame(const std::vector<uint8_t>& frame) {
            std::lock_guard<std::mutex> lock(mutex_);
            rx_queues_[kPortA].push_back(frame);
        }

        /// Queues one inbound frame on the given adapter index.
        void InjectFrameOn(int port, const std::vector<uint8_t>& frame) {
            std::lock_guard<std::mutex> lock(mutex_);
            rx_queues_[port].push_back(frame);
        }

        /// Snapshot of every frame the data plane handed to the adapters.
        std::vector<std::vector<uint8_t>> SentFrames() const {
            std::lock_guard<std::mutex> lock(mutex_);
            std::vector<std::vector<uint8_t>> all = sent_frames_[kPortA];
            all.insert(all.end(), sent_frames_[kPortB].begin(),
                       sent_frames_[kPortB].end());
            return all;
        }

        /// Snapshot of frames handed to one adapter index.
        std::vector<std::vector<uint8_t>> SentFramesOn(int port) const {
            std::lock_guard<std::mutex> lock(mutex_);
            return sent_frames_[port];
        }

        /// Number of currently visible adapters.
        size_t AdapterCount() const {
            std::lock_guard<std::mutex> lock(mutex_);
            return adapters_.size();
        }

        /// Simulates hot-removal of an adapter (port disappear injection).
        void RemoveAdapter(int port) {
            std::lock_guard<std::mutex> lock(mutex_);
            if (port >= 0 &&
                static_cast<size_t>(port) < adapters_.size()) {
                adapters_.erase(adapters_.begin() + port);
            }
        }

        /// Bridge filter surface: last value handed to SetHwPacketFilter
        /// on the primary adapter.
        uint32_t last_hw_filter() const {
            std::lock_guard<std::mutex> lock(mutex_);
            return hw_filters_[kPortA];
        }

        /// Reads the stored filter of one adapter index.
        uint32_t FilterOn(int port) const {
            std::lock_guard<std::mutex> lock(mutex_);
            return hw_filters_[port];
        }

        /// When set, SetHwPacketFilter fails without touching hw_filter_.
        void FailHwFilterSet(bool fail) {
            std::lock_guard<std::mutex> lock(mutex_);
            fail_hw_filter_set_ = fail;
        }

        /// When set, SendPacketsToAdapter throws - injects an exception into
        /// Start() AFTER PortMapManager::Start (the gratuitous boot flush).
        void FailSendPackets(bool fail) {
            std::lock_guard<std::mutex> lock(mutex_);
            fail_send_packets_ = fail;
        }

        // ----- IDriverClient ------------------------------------------
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

        bool SetHwPacketFilter(const AdapterEntry& adapter, uint32_t filter,
                               std::string& error) override {
            std::lock_guard<std::mutex> lock(mutex_);
            const int idx = IndexOf(adapter.handle);
            if (idx < 0) {
                error = "unknown adapter handle";
                return false;
            }
            if (fail_hw_filter_set_) {
                error = "injected hw filter set failure";
                return false;
            }
            hw_filters_[idx] = filter;
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
            filter = hw_filters_[idx];
            return true;
        }

        bool ArmRxEvent(const AdapterEntry&, void*, std::string&) override {
            return true;
        }

        uint32_t ReadPackets(void* handle, INTERMEDIATE_BUFFER* buffers,
                             uint32_t max_packets, std::string& error) override {
            std::unique_lock<std::mutex> lock(mutex_);
            const int idx = IndexOf(handle);
            if (idx < 0) {
                error = "unknown adapter handle";
                return 0;
            }
            ++read_calls_;
            if (block_reads_) {
                ++blocked_reads_;
                cv_.notify_all();
                cv_.wait(lock, [this] { return !block_reads_; });
                --blocked_reads_;
            }
            if (read_calls_ > fail_after_) {
                error = "injected read failure";
                return 0;
            }
            // Serve queued inbound frames (boundary simulation: the product
            // data plane classifies and dispatches them verbatim).
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
            if (fail_send_packets_) {
                throw std::runtime_error("injected send failure");
            }
            for (uint32_t i = 0; i < count; ++i) {
                const INTERMEDIATE_BUFFER& ib = buffers[i];
                sent_frames_[idx].emplace_back(ib.m_IBuffer,
                                               ib.m_IBuffer + ib.m_Length);
            }
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

    private:
        static constexpr size_t kFailNever = static_cast<size_t>(-1);

        int IndexOf(void* handle) const {
            for (size_t i = 0; i < adapters_.size(); ++i) {
                if (adapters_[i].handle == handle) {
                    return static_cast<int>(i);
                }
            }
            return -1;
        }

        std::vector<AdapterEntry> adapters_;
        mutable std::mutex mutex_;
        std::condition_variable cv_;
        bool block_reads_ = false;
        size_t blocked_reads_ = 0;
        size_t read_calls_ = 0;
        size_t fail_after_ = kFailNever;
        std::deque<std::vector<uint8_t>> rx_queues_[2];
        std::vector<std::vector<uint8_t>> sent_frames_[2];
        uint32_t hw_filters_[2] = {0, 0};
        bool fail_hw_filter_set_ = false;
        bool fail_send_packets_ = false;
    };

    vgww::core::Config MakeConfig() {
        vgww::core::Config cfg;
        cfg.adapter = "TestNIC";
        cfg.gateway.ipv4 = (192u) | (0u << 8) | (168u << 16) | (40u << 24);
        cfg.gateway.mask = (0u) | (0u << 8) | (255u << 16) | (255u << 24);
        cfg.gateway.mac = {0x30, 0xFC, 0x68, 0x88, 0xB4, 0xA9};
        cfg.perf.workers = 2;
        cfg.perf.ring_capacity = 64;
        cfg.perf.max_conns = 64;
        cfg.perf.dial_timeout_ms = 400;
        return cfg;
    }

    /// Builds an Ethernet+IPv4+UDP+DHCP DISCOVER (client 68 -> server 67).
    std::vector<uint8_t> MakeDhcpDiscover(const std::array<uint8_t, 6>& client,
                                          uint32_t xid) {
        std::vector<uint8_t> f;
        f.insert(f.end(), {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF});
        f.insert(f.end(), client.begin(), client.end());
        f.push_back(0x08);
        f.push_back(0x00);
        const size_t ip_at = f.size();
        f.push_back(0x45);
        f.push_back(0x00);
        const size_t total_at = f.size();
        f.push_back(0);
        f.push_back(0);
        f.push_back(0);
        f.push_back(0);
        f.push_back(0x40);
        f.push_back(0x00);
        f.push_back(64);
        f.push_back(17);  // UDP
        f.push_back(0);
        f.push_back(0);
        f.insert(f.end(), {0, 0, 0, 0});
        f.insert(f.end(), {0xFF, 0xFF, 0xFF, 0xFF});
        const size_t udp_at = f.size();
        f.push_back(0);
        f.push_back(68);  // sport
        f.push_back(0);
        f.push_back(67);  // dport
        f.push_back(0);
        f.push_back(0);
        f.push_back(0);
        f.push_back(0);
        f.push_back(1);  // op BOOTREQUEST
        f.push_back(1);  // htype Ethernet
        f.push_back(6);  // hlen
        f.push_back(0);  // hops
        f.push_back(static_cast<uint8_t>(xid >> 24));
        f.push_back(static_cast<uint8_t>(xid >> 16));
        f.push_back(static_cast<uint8_t>(xid >> 8));
        f.push_back(static_cast<uint8_t>(xid));
        f.push_back(0);  // secs
        f.push_back(0);
        f.push_back(0x80);  // flags: broadcast
        f.push_back(0);
        for (int i = 0; i < 16; ++i) f.push_back(0);  // ciaddr/yiaddr/siaddr/giaddr
        for (int i = 0; i < 16; ++i) {
            f.push_back(i < 6 ? client[static_cast<size_t>(i)] : 0);  // chaddr
        }
        for (int i = 0; i < 64; ++i) f.push_back(0);   // sname
        for (int i = 0; i < 128; ++i) f.push_back(0);  // file
        f.insert(f.end(), {0x63, 0x82, 0x53, 0x63});   // magic cookie
        f.insert(f.end(), {53, 1, 1});                 // option 53 = DISCOVER
        f.push_back(255);                              // end
        const uint16_t total = static_cast<uint16_t>(f.size() - ip_at);
        f[total_at] = static_cast<uint8_t>(total >> 8);
        f[total_at + 1] = static_cast<uint8_t>(total & 0xFF);
        const uint16_t udp_len = static_cast<uint16_t>(f.size() - udp_at);
        f[udp_at + 4] = static_cast<uint8_t>(udp_len >> 8);
        f[udp_at + 5] = static_cast<uint8_t>(udp_len & 0xFF);
        return f;
    }

    /// True when any captured frame is a DHCP reply (BOOTREPLY + magic).
    bool HasDhcpReply(const std::vector<std::vector<uint8_t>>& frames) {
        for (const auto& f : frames) {
            if (f.size() >= 14 + 20 + 8 + 240) {
                const uint8_t* d = f.data() + 14 + 20 + 8;
                if (2 == d[0] && 0x63 == d[236] && 0x82 == d[237] &&
                    0x53 == d[238] && 0x63 == d[239]) {
                    return true;
                }
            }
        }
        return false;
    }

    DWORD HandleCount() {
        DWORD count = 0;
        if (!::GetProcessHandleCount(::GetCurrentProcess(), &count)) {
            return 0;
        }
        return count;
    }

    bool CountsAreEmpty(
        const vgww::runtime::Dataplane::LifecycleCounts& counts) {
        return 0 == counts.rx_rings && 0 == counts.tx_rings &&
               0 == counts.io_contexts && 0 == counts.udp_tables &&
               0 == counts.icmp_relays && 0 == counts.relay_registry &&
               0 == counts.workers && !counts.running &&
               !counts.shutdown_incomplete;
    }

    void TestCleanRestartCycles() {
        // Named config: Dataplane stores a Config& (pre-existing semantics);
        // an inline temporary would dangle once the constructor returns.
        const vgww::core::Config config = MakeConfig();
        vgww::runtime::Dataplane dataplane(config);
        dataplane.SetDriverClient(std::make_unique<FakeDriverClient>());

        const DWORD handles_before = HandleCount();

        for (int cycle = 1; cycle <= 3; ++cycle) {
            std::string error;
            CHECK(dataplane.Start(error));
            if (!error.empty()) {
                std::fprintf(stderr, "[cycle %d] start error: %s\n", cycle,
                             error.c_str());
            }
            {
                const auto counts = dataplane.GetLifecycleCounts();
                CHECK(counts.running);
                CHECK(2 == counts.rx_rings);
                CHECK(2 == counts.tx_rings);
                CHECK(2 == counts.io_contexts);
                CHECK(2 == counts.udp_tables);
                CHECK(2 == counts.icmp_relays);
                CHECK(2 == counts.workers);
            }
            std::string stop_error;
            CHECK(dataplane.Stop(stop_error));
            CHECK(stop_error.empty());
            CHECK(CountsAreEmpty(dataplane.GetLifecycleCounts()));
        }

        // Threads joined, event closed, rings freed: no handle growth.
        const DWORD handles_after = HandleCount();
        CHECK(handles_after <= handles_before + 8);
    }

    /// batch25a: the dashboard's one-click start/stop/recheck commands drive
    /// the real lifecycle through the UI command executor (the same path the
    /// app uses; no process spawn, no fake control plane).
    void TestB25UiServiceCommands() {
        const vgww::core::Config config = MakeConfig();
        vgww::runtime::Dataplane dataplane(config);
        dataplane.SetDriverClient(std::make_unique<FakeDriverClient>());
        CHECK(!dataplane.IsRunning());
        CHECK(dataplane.LastError().empty());

        vgww::ui::DataplaneCommandExecutor executor(dataplane, "");

        std::string start_error;
        CHECK(dataplane.Start(start_error));
        CHECK(dataplane.IsRunning());

        auto stopped =
            executor.Execute(vgww::ui::Command{vgww::ui::StopServiceCmd{}});
        CHECK(stopped.ok);
        CHECK(!dataplane.IsRunning());
        CHECK(dataplane.LastError().empty());

        auto started =
            executor.Execute(vgww::ui::Command{vgww::ui::StartServiceCmd{}});
        CHECK(started.ok);
        CHECK(dataplane.IsRunning());

        auto rechecked =
            executor.Execute(vgww::ui::Command{vgww::ui::RecheckServiceCmd{}});
        CHECK(rechecked.ok);
        CHECK(dataplane.IsRunning());

        stopped = executor.Execute(vgww::ui::Command{vgww::ui::StopServiceCmd{}});
        CHECK(stopped.ok);
        CHECK(!dataplane.IsRunning());

        // Idempotent stop: a second click is a successful no-op.
        stopped = executor.Execute(vgww::ui::Command{vgww::ui::StopServiceCmd{}});
        CHECK(stopped.ok);
    }

    void TestBlockedReadRefusesRestart() {
        // Named config: Dataplane stores a Config& (pre-existing semantics);
        // an inline temporary would dangle once the constructor returns.
        const vgww::core::Config config = MakeConfig();
        vgww::runtime::Dataplane dataplane(config);
        auto fake = std::make_unique<FakeDriverClient>();
        FakeDriverClient* raw = fake.get();
        dataplane.SetDriverClient(std::move(fake));

        std::string error;
        CHECK(dataplane.Start(error));

        raw->SetBlockReads(true);
        CHECK(raw->WaitUntilReadBlocked(5000));

        const auto t0 = std::chrono::steady_clock::now();
        std::string stop_error;
        const bool clean = dataplane.Stop(stop_error);
        const auto elapsed_ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - t0)
                .count();

        CHECK(!clean);                 // bounded wait timed out
        CHECK(elapsed_ms >= 4000);     // waited the 5s budget, no premature free
        CHECK(!stop_error.empty());
        CHECK(dataplane.GetLifecycleCounts().shutdown_incomplete);
        CHECK(!dataplane.GetLifecycleCounts().running);
        // The rings/stack must still be alive for the stuck thread (H2):
        // every per-worker container survives a refused stop, not just the
        // RX rings.
        const auto stuck = dataplane.GetLifecycleCounts();
        CHECK(2 == stuck.rx_rings);
        CHECK(2 == stuck.tx_rings);
        CHECK(2 == stuck.io_contexts);
        CHECK(2 == stuck.udp_tables);
        CHECK(2 == stuck.icmp_relays);

        // Release the stuck read; the RX thread can now return.
        raw->SetBlockReads(false);
        std::this_thread::sleep_for(std::chrono::milliseconds(300));

        // Restart stays refused (sticky incomplete state).
        std::string start_error;
        CHECK(!dataplane.Start(start_error));
        CHECK(start_error.find("incomplete") != std::string::npos);
        std::fprintf(stderr,
                     "[blocked] stop_error=\"%s\" start_error=\"%s\"\n",
                     stop_error.c_str(), start_error.c_str());
    }

    void TestInjectedReadFailureStopsCleanly() {
        // Named config: Dataplane stores a Config& (pre-existing semantics);
        // an inline temporary would dangle once the constructor returns.
        const vgww::core::Config config = MakeConfig();
        vgww::runtime::Dataplane dataplane(config);
        auto fake = std::make_unique<FakeDriverClient>();
        FakeDriverClient* raw = fake.get();
        dataplane.SetDriverClient(std::move(fake));

        std::string error;
        CHECK(dataplane.Start(error));
        (void)raw->FailReadAfter(1);
        std::this_thread::sleep_for(std::chrono::milliseconds(500));

        std::string stop_error;
        CHECK(dataplane.Stop(stop_error));
        CHECK(stop_error.empty());
        CHECK(CountsAreEmpty(dataplane.GetLifecycleCounts()));
    }

    /// Main-mode DHCP config with a real pool (inet_addr numeric space via
    /// ParseIpv4 so the test never hand-rolls byte order).
    vgww::core::Config MakeDhcpMainConfig() {
        vgww::core::Config cfg = MakeConfig();
        cfg.mode = vgww::core::Mode::kMain;
        cfg.dhcp.enabled = true;
        bool ok = false;
        cfg.gateway.ipv4 = vgww::core::ParseIpv4("192.168.40.1", ok);
        cfg.gateway.mask = vgww::core::ParseIpv4("255.255.255.0", ok);
        cfg.dhcp.pool_start = vgww::core::ParseIpv4("192.168.40.100", ok);
        cfg.dhcp.pool_end = vgww::core::ParseIpv4("192.168.40.110", ok);
        cfg.dhcp.lease_seconds = 3600;
        return cfg;
    }

    /// Main-mode IPv6 config: ULA prefix + stateful DHCPv6 pool.
    vgww::core::Config MakeDhcp6MainConfig() {
        vgww::core::Config cfg = MakeConfig();
        cfg.mode = vgww::core::Mode::kMain;
        cfg.ipv6.enabled = true;
        cfg.ipv6.prefix_len = 64;
        cfg.ipv6.ula_prefix = {0xFD, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
                               0x66, 0, 0, 0, 0, 0, 0, 0, 0};
        cfg.ipv6.dhcpv6.enabled = true;
        cfg.ipv6.dhcpv6.pool_start = {0xFD, 0x00, 0x11, 0x22, 0x33, 0x44,
                                      0x55, 0x66, 0, 0, 0, 0, 0, 0, 0x10,
                                      0x00};
        cfg.ipv6.dhcpv6.pool_end = {0xFD, 0x00, 0x11, 0x22, 0x33, 0x44,
                                    0x55, 0x66, 0, 0, 0, 0, 0, 0, 0x1F,
                                    0xFF};
        cfg.ipv6.dhcpv6.lease_seconds = 3600;
        return cfg;
    }
    /// batch137: the UI edit form posts ONE command carrying the old key, and
    /// the data plane must drop the old binding and store the new one in a
    /// single store transaction. A REFUSED re-key must leave the old binding
    /// completely intact - the split remove+add sequence deleted it. This
    /// drives the real Dataplane (assembled DHCP server) through the same
    /// executor the UI uses.
    void TestB137ReplaceBindingThroughExecutorIsAtomic() {
        const vgww::core::Config config = MakeDhcpMainConfig();
        const std::string lease_path = "b137-replace-leases.json";
        std::remove(lease_path.c_str());

        vgww::runtime::Dataplane dataplane(config, lease_path);
        dataplane.SetDriverClient(std::make_unique<FakeDriverClient>());
        std::string start_error;
        CHECK(dataplane.Start(start_error));
        CHECK(dataplane.DhcpActive());

        vgww::ui::DataplaneCommandExecutor executor(dataplane, "");

        const auto add = executor.Execute(vgww::ui::Command{
            vgww::ui::AddDhcpBindingCmd{"02:00:00:00:00:11", "192.168.40.90",
                                        "nas"}});
        CHECK(add.ok);
        const auto before = dataplane.GetDhcpBindings();
        CHECK(before.size() == 1);

        // Happy re-key: old gone, new present with the new name.
        vgww::ui::AddDhcpBindingCmd rekey{"02:00:00:00:00:12", "192.168.40.90",
                                          "nas2"};
        rekey.replace_mac = "02:00:00:00:00:11";
        const auto applied = executor.Execute(vgww::ui::Command{rekey});
        CHECK(applied.ok);
        const auto after = dataplane.GetDhcpBindings();
        CHECK(after.size() == 1);
        if (after.size() == 1) {
            CHECK(0 == _stricmp(after[0].mac.c_str(), "02:00:00:00:00:12"));
            CHECK(after[0].hostname == "nas2");
        }

        // Refused re-key (out-of-subnet address): the binding must survive.
        vgww::ui::AddDhcpBindingCmd bad{"02:00:00:00:00:13", "10.9.9.9",
                                        "nope"};
        bad.replace_mac = "02:00:00:00:00:12";
        const auto refused = executor.Execute(vgww::ui::Command{bad});
        CHECK(!refused.ok);
        const auto intact = dataplane.GetDhcpBindings();
        CHECK(intact.size() == 1);
        if (intact.size() == 1) {
            CHECK(0 == _stricmp(intact[0].mac.c_str(), "02:00:00:00:00:12"));
            CHECK(intact[0].hostname == "nas2");
        }

        std::string stop_error;
        CHECK(dataplane.Stop(stop_error));
        std::remove(lease_path.c_str());
    }


    void PushDhcp6U16(std::vector<uint8_t>& v, uint16_t x) {
        v.push_back(static_cast<uint8_t>(x >> 8));
        v.push_back(static_cast<uint8_t>(x & 0xFF));
    }

    void PushDhcp6Option(std::vector<uint8_t>& out, uint16_t code,
                         const std::vector<uint8_t>& data) {
        PushDhcp6U16(out, code);
        PushDhcp6U16(out, static_cast<uint16_t>(data.size()));
        out.insert(out.end(), data.begin(), data.end());
    }

    /// Ethernet+IPv6+UDP DHCPv6 SOLICIT (client 546 -> server 547) with the
    /// mandatory CLIENTID and IA_NA.
    std::vector<uint8_t> MakeDhcp6Solicit(const std::array<uint8_t, 6>& client,
                                          uint32_t xid) {
        std::vector<uint8_t> payload;
        payload.push_back(vgww::proto::kDhcp6MsgSolicit);
        payload.push_back(static_cast<uint8_t>((xid >> 16) & 0xFF));
        payload.push_back(static_cast<uint8_t>((xid >> 8) & 0xFF));
        payload.push_back(static_cast<uint8_t>(xid & 0xFF));
        const std::vector<uint8_t> duid = {0x00, 0x03, 0x00, 0x01, client[0],
                                           client[1], client[2], client[3],
                                           client[4], client[5]};
        PushDhcp6Option(payload, vgww::proto::kDhcp6OptClientId, duid);
        const std::vector<uint8_t> ia = {0x00, 0x00, 0x00, 0x01, 0, 0, 0,
                                         0,    0,    0,    0,    0};
        PushDhcp6Option(payload, vgww::proto::kDhcp6OptIaNa, ia);

        const std::array<uint8_t, 16> src = {
            0xFE, 0x80, 0, 0, 0, 0, 0, 0, client[0], client[1], client[2],
            0xFF, 0xFE, client[3], client[4], client[5]};
        const std::array<uint8_t, 16> dst = {0xFF, 0x02, 0, 0, 0, 0, 0, 0,
                                             0,    0,    0, 0, 0, 1, 0, 2};
        const std::array<uint8_t, 6> dst_mac = {0x33, 0x33, 0x00,
                                                0x01, 0x00, 0x02};
        std::vector<uint8_t> frame;
        vgww::proto::BuildUdpFrameV6(
            frame, dst_mac, client, src.data(), vgww::proto::kDhcp6ClientPort,
            dst.data(), vgww::proto::kDhcp6ServerPort, payload.data(),
            payload.size());
        return frame;
    }

    /// Ethernet+IPv6+ICMPv6 Router Solicitation (hop limit 255, ff02::2).
    std::vector<uint8_t> MakeRouterSolicitation(
        const std::array<uint8_t, 6>& client) {
        const std::array<uint8_t, 16> src = {
            0xFE, 0x80, 0, 0, 0, 0, 0, 0, client[0], client[1], client[2],
            0xFF, 0xFE, client[3], client[4], client[5]};
        const std::array<uint8_t, 16> dst = {0xFF, 0x02, 0, 0, 0, 0, 0, 0,
                                             0,    0,    0, 0, 0, 0, 0, 2};
        const std::array<uint8_t, 6> dst_mac = {0x33, 0x33, 0x00,
                                                0x00, 0x00, 0x02};
        std::vector<uint8_t> f;
        f.insert(f.end(), dst_mac.begin(), dst_mac.end());
        f.insert(f.end(), client.begin(), client.end());
        f.push_back(0x86);
        f.push_back(0xDD);
        f.insert(f.end(), {0x60, 0x00, 0x00, 0x00});
        f.insert(f.end(), {0x00, 0x08, 58, 255});
        f.insert(f.end(), src.begin(), src.end());
        f.insert(f.end(), dst.begin(), dst.end());
        f.insert(f.end(), {133, 0, 0, 0, 0, 0, 0, 0});
        return f;
    }

    /// True when any captured frame is a DHCPv6 ADVERTISE to port 546.
    bool HasDhcp6Advertise(const std::vector<std::vector<uint8_t>>& frames) {
        for (const auto& f : frames) {
            constexpr size_t kUdpAt = 14 + 40;
            if (f.size() < kUdpAt + 8 + 4 + 8) continue;
            if (0x86 != f[12] || 0xDD != f[13]) continue;
            if (17 != f[14 + 6]) continue;  // IPv6 next header = UDP
            const uint8_t* udp = f.data() + kUdpAt;
            const uint16_t sport =
                static_cast<uint16_t>((udp[0] << 8) | udp[1]);
            const uint16_t dport =
                static_cast<uint16_t>((udp[2] << 8) | udp[3]);
            if (sport != vgww::proto::kDhcp6ServerPort ||
                dport != vgww::proto::kDhcp6ClientPort) {
                continue;
            }
            const uint8_t* d = udp + 8;
            if (d[0] == vgww::proto::kDhcp6MsgAdvertise) return true;
        }
        return false;
    }

    /// True when any captured frame is a Router Advertisement (ICMPv6 134).
    bool HasRouterAdvertisement(
        const std::vector<std::vector<uint8_t>>& frames) {
        for (const auto& f : frames) {
            if (f.size() < 14 + 40 + 4) continue;
            if (0x86 != f[12] || 0xDD != f[13]) continue;
            if (58 != f[14 + 6]) continue;  // IPv6 next header = ICMPv6
            if (134 == f[14 + 40]) return true;
        }
        return false;
    }

    /// Gate: bypass mode + dhcp.enabled=true must NOT assemble the server,
    /// must NOT answer a DISCOVER and must NOT create a lease file.
    void TestBypassDisablesDhcp() {
        vgww::core::Config config = MakeDhcpMainConfig();
        config.mode = vgww::core::Mode::kBypass;  // the only change vs main
        const std::filesystem::path scratch_dir =
            std::filesystem::temp_directory_path() / "vgww-tests";
        std::error_code scratch_ec;
        std::filesystem::create_directories(scratch_dir, scratch_ec);
        const std::string lease_path = (scratch_dir / "bypass-leases.json").string();
        const std::string log_path = (scratch_dir / "bypass-start.log").string();
        std::remove(lease_path.c_str());
        std::remove(log_path.c_str());

        vgww::runtime::Dataplane dataplane(config, lease_path);
        auto fake = std::make_unique<FakeDriverClient>();
        FakeDriverClient* raw = fake.get();
        dataplane.SetDriverClient(std::move(fake));

        // Capture stderr around Start so the gate notice is observable.
        FILE* log_file = nullptr;
        if (0 != ::fopen_s(&log_file, log_path.c_str(), "w")) {
            log_file = nullptr;
        }
        const int saved_fd = _dup(_fileno(stderr));
        if (nullptr != log_file && saved_fd >= 0) {
            _dup2(_fileno(log_file), _fileno(stderr));
        }
        std::string error;
        const bool started = dataplane.Start(error);
        std::fflush(stderr);
        if (nullptr != log_file && saved_fd >= 0) {
            _dup2(saved_fd, _fileno(stderr));
            _close(saved_fd);
            std::fclose(log_file);
        }
        CHECK(started);
        CHECK(!dataplane.DhcpActive());  // assembly count is zero
        CHECK(0 == dataplane.DhcpLeaseCount());

        // A DISCOVER on the wire must produce no reply.
        raw->InjectFrame(MakeDhcpDiscover({0x02, 0x00, 0x00, 0x00, 0x00, 0x42},
                                          0x11223344u));
        std::this_thread::sleep_for(std::chrono::milliseconds(700));
        CHECK(!HasDhcpReply(raw->SentFrames()));

        std::string stop_error;
        CHECK(dataplane.Stop(stop_error));
        CHECK(!std::ifstream(lease_path).good());  // bypass writes no file

        // The startup log names the bypass gate explicitly.
        std::ifstream in(log_path);
        const std::string text((std::istreambuf_iterator<char>(in)),
                               std::istreambuf_iterator<char>());
        CHECK(text.find("bypass") != std::string::npos);

        std::remove(lease_path.c_str());
        std::remove(log_path.c_str());
    }

    /// Main-mode DISCOVER -> OFFER, asserted byte for byte.
    void TestDhcpDiscoverGetsOffer() {
        const vgww::core::Config config = MakeDhcpMainConfig();
        const std::string lease_path = "offer-leases.json";
        std::remove(lease_path.c_str());

        vgww::runtime::Dataplane dataplane(config, lease_path);
        auto fake = std::make_unique<FakeDriverClient>();
        FakeDriverClient* raw = fake.get();
        dataplane.SetDriverClient(std::move(fake));

        std::string error;
        CHECK(dataplane.Start(error));
        CHECK(dataplane.DhcpActive());

        const std::array<uint8_t, 6> client = {0x02, 0x00, 0x00,
                                               0x00, 0x00, 0x42};
        const uint32_t xid = 0x12345678u;
        raw->InjectFrame(MakeDhcpDiscover(client, xid));

        const auto deadline =
            std::chrono::steady_clock::now() + std::chrono::seconds(4);
        while (std::chrono::steady_clock::now() < deadline &&
               !HasDhcpReply(raw->SentFrames())) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        const auto frames = raw->SentFrames();
        CHECK(HasDhcpReply(frames));

        for (const auto& f : frames) {
            constexpr size_t kDhcpAt = 14 + 20 + 8;
            if (f.size() < kDhcpAt + 240 || 2 != f[kDhcpAt]) continue;
            const uint8_t* d = f.data() + kDhcpAt;
            CHECK(0x63 == d[236] && 0x82 == d[237] && 0x53 == d[238] &&
                  0x63 == d[239]);                       // magic cookie
            CHECK(53 == d[240] && 1 == d[241] && 2 == d[242]);  // OFFER
            CHECK(static_cast<uint8_t>(xid >> 24) == d[4] &&
                  static_cast<uint8_t>(xid >> 16) == d[5] &&
                  static_cast<uint8_t>(xid >> 8) == d[6] &&
                  static_cast<uint8_t>(xid) == d[7]);    // xid echoed
            // yiaddr: first octet in the low byte of the inet_addr numeric,
            // so the wire bytes are [192,168,40,100] for pool_start.
            CHECK(192 == d[16] && 168 == d[17] && 40 == d[18] &&
                  100 == d[19]);
        }

        std::string stop_error;
        CHECK(dataplane.Stop(stop_error));
        std::remove(lease_path.c_str());
    }

    /// Stop() persists the lease table; a restart re-assembles the server.
    void TestLeasesDumpedOnStop() {
        const vgww::core::Config config = MakeDhcpMainConfig();
        const std::filesystem::path lease_dir =
            std::filesystem::temp_directory_path() / "vgww-tests";
        std::error_code lease_ec;
        std::filesystem::create_directories(lease_dir, lease_ec);
        const std::string lease_path = (lease_dir / "dump-leases.json").string();
        std::remove(lease_path.c_str());

        {
            vgww::runtime::Dataplane dataplane(config, lease_path);
            auto fake = std::make_unique<FakeDriverClient>();
            FakeDriverClient* raw = fake.get();
            dataplane.SetDriverClient(std::move(fake));
            std::string error;
            CHECK(dataplane.Start(error));
            CHECK(dataplane.DhcpActive());
            raw->InjectFrame(MakeDhcpDiscover({0x02, 0x00, 0x00, 0x00, 0x00,
                                               0x42},
                                              0xABCD0001u));
            std::this_thread::sleep_for(std::chrono::milliseconds(700));
            std::string stop_error;
            CHECK(dataplane.Stop(stop_error));
            CHECK(!dataplane.DhcpActive());  // torn down with the plane
        }

        std::ifstream in(lease_path, std::ios::binary);
        CHECK(in.good());
        if (in.good()) {
            std::stringstream ss;
            ss << in.rdbuf();
            CHECK(ss.str().find("\"version\"") != std::string::npos);
            CHECK(ss.str().find("02:00:00:00:00:42") != std::string::npos);
        }

        // Start -> Stop -> Start must rebuild the server (no stale state).
        {
            vgww::runtime::Dataplane dataplane(config, lease_path);
            dataplane.SetDriverClient(std::make_unique<FakeDriverClient>());
            std::string error;
            CHECK(dataplane.Start(error));
            CHECK(dataplane.DhcpActive());
            std::string stop_error;
            CHECK(dataplane.Stop(stop_error));
        }
        std::remove(lease_path.c_str());
    }

    /// Main-mode gate and damaged-file resilience: `dhcp.enabled = false`
    /// must not assemble a server (and must not write a lease file), while a
    /// corrupt lease file must degrade to an empty table without crashing.
    void TestDhcpDisabledAndCorruptLease() {
        {
            vgww::core::Config config = MakeDhcpMainConfig();
            config.dhcp.enabled = false;
            const std::string lease_path = "disabled-leases.json";
            std::remove(lease_path.c_str());

            vgww::runtime::Dataplane dataplane(config, lease_path);
            dataplane.SetDriverClient(std::make_unique<FakeDriverClient>());
            std::string error;
            CHECK(dataplane.Start(error));
            CHECK(!dataplane.DhcpActive());
            CHECK(0 == dataplane.DhcpLeaseCount());
            CHECK(dataplane.GetLeases().empty());
            std::string stop_error;
            CHECK(dataplane.Stop(stop_error));
            CHECK(!std::ifstream(lease_path).good());  // never assembled
            std::remove(lease_path.c_str());
        }

        {
            const vgww::core::Config config = MakeDhcpMainConfig();
            const std::string lease_path = "corrupt-leases.json";
            std::remove(lease_path.c_str());
            {
                std::ofstream out(lease_path, std::ios::binary);
                out << "{\"version\":1,\"leases\":[{\"mac\":\"NOT-A-MAC\"]";
            }

            vgww::runtime::Dataplane dataplane(config, lease_path);
            dataplane.SetDriverClient(std::make_unique<FakeDriverClient>());
            std::string error;
            CHECK(dataplane.Start(error));
            CHECK(dataplane.DhcpActive());       // server still comes up
            CHECK(0 == dataplane.DhcpLeaseCount());  // damaged rows dropped
            CHECK(dataplane.GetLeases().empty());
            std::string stop_error;
            CHECK(dataplane.Stop(stop_error));
            std::remove(lease_path.c_str());
        }
    }

    /// Main + ipv6.enabled=false: no DHCPv6 service is assembled and a
    /// SOLICIT is never answered (spec section 5.2: RA+DHCPv6 are off).
    void TestV6DisabledWhenIpv6Off() {
        vgww::core::Config config = MakeDhcp6MainConfig();
        config.ipv6.enabled = false;  // dhcpv6.enabled stays true
        const std::string lease_path = "v6off-leases.json";
        std::remove(lease_path.c_str());

        vgww::runtime::Dataplane dataplane(config, lease_path);
        auto fake = std::make_unique<FakeDriverClient>();
        FakeDriverClient* raw = fake.get();
        dataplane.SetDriverClient(std::move(fake));

        std::string error;
        CHECK(dataplane.Start(error));
        CHECK(!dataplane.Dhcp6Active());
        CHECK(0 == dataplane.Dhcp6LeaseCount());

        raw->InjectFrame(
            MakeDhcp6Solicit({0x02, 0x00, 0x00, 0x00, 0x00, 0x51}, 0x0A0B0C));
        std::this_thread::sleep_for(std::chrono::milliseconds(700));
        CHECK(!HasDhcp6Advertise(raw->SentFrames()));

        std::string stop_error;
        CHECK(dataplane.Stop(stop_error));
        CHECK(!dataplane.Dhcp6Active());
        std::remove(lease_path.c_str());
    }

    /// Main + ipv6 on: a SOLICIT through the dataplane yields an ADVERTISE
    /// from the assembled DHCPv6 server.
    void TestDhcp6SolicitViaDataplane() {
        const vgww::core::Config config = MakeDhcp6MainConfig();
        const std::string lease_path = "solicit6-leases.json";
        const std::string lease6_path = lease_path + ".leases6";
        std::remove(lease_path.c_str());
        std::remove(lease6_path.c_str());

        vgww::runtime::Dataplane dataplane(config, lease_path);
        auto fake = std::make_unique<FakeDriverClient>();
        FakeDriverClient* raw = fake.get();
        dataplane.SetDriverClient(std::move(fake));

        std::string error;
        CHECK(dataplane.Start(error));
        CHECK(dataplane.Dhcp6Active());

        raw->InjectFrame(
            MakeDhcp6Solicit({0x02, 0x00, 0x00, 0x00, 0x00, 0x61}, 0x112233));
        const auto deadline =
            std::chrono::steady_clock::now() + std::chrono::seconds(4);
        while (std::chrono::steady_clock::now() < deadline &&
               !HasDhcp6Advertise(raw->SentFrames())) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        CHECK(HasDhcp6Advertise(raw->SentFrames()));
        CHECK(1 == dataplane.Dhcp6LeaseCount());
        CHECK(!dataplane.GetLeases6().empty());

        std::string stop_error;
        CHECK(dataplane.Stop(stop_error));
        std::remove(lease_path.c_str());
        std::remove(lease6_path.c_str());
    }

    /// Carryover (Task6 review): an RS is answered with an RA only when
    /// ipv6.enabled is true.
    void TestRsNoRaWhenIpv6Disabled() {
        vgww::core::Config config = MakeDhcp6MainConfig();
        config.ipv6.enabled = false;
        const std::string lease_path = "rs-gate-leases.json";
        std::remove(lease_path.c_str());

        vgww::runtime::Dataplane dataplane(config, lease_path);
        auto fake = std::make_unique<FakeDriverClient>();
        FakeDriverClient* raw = fake.get();
        dataplane.SetDriverClient(std::move(fake));
        std::string error;
        CHECK(dataplane.Start(error));

        raw->InjectFrame(
            MakeRouterSolicitation({0x02, 0x00, 0x00, 0x00, 0x00, 0x71}));
        std::this_thread::sleep_for(std::chrono::milliseconds(700));
        CHECK(!HasRouterAdvertisement(raw->SentFrames()));

        std::string stop_error;
        CHECK(dataplane.Stop(stop_error));
        std::remove(lease_path.c_str());
    }

    /// Carryover (Task6 review): bypass never emits an RA even with
    /// ipv6.enabled and a valid RS.
    void TestBypassSendsNoRa() {
        vgww::core::Config config = MakeDhcp6MainConfig();
        config.mode = vgww::core::Mode::kBypass;
        const std::string lease_path = "bypass-ra-leases.json";
        std::remove(lease_path.c_str());

        vgww::runtime::Dataplane dataplane(config, lease_path);
        auto fake = std::make_unique<FakeDriverClient>();
        FakeDriverClient* raw = fake.get();
        dataplane.SetDriverClient(std::move(fake));
        std::string error;
        CHECK(dataplane.Start(error));
        CHECK(!dataplane.Dhcp6Active());

        raw->InjectFrame(
            MakeRouterSolicitation({0x02, 0x00, 0x00, 0x00, 0x00, 0x81}));
        std::this_thread::sleep_for(std::chrono::milliseconds(700));
        CHECK(!HasRouterAdvertisement(raw->SentFrames()));

        std::string stop_error;
        CHECK(dataplane.Stop(stop_error));
        std::remove(lease_path.c_str());
    }

    /// C3: a start that fails AFTER PortMapManager::Start (the gratuitous
    /// boot flush throws) must stop the manager - its acceptor thread must
    /// not leak and a clean retry must not hit std::terminate.
    void TestStartFailureStopsPortMapManager() {
        const vgww::core::Config config = MakeConfig();
        vgww::runtime::Dataplane dataplane(config);
        auto fake = std::make_unique<FakeDriverClient>();
        FakeDriverClient* raw = fake.get();
        dataplane.SetDriverClient(std::move(fake));

        raw->FailSendPackets(true);  // throws during the boot flush
        std::string error;
        CHECK(!dataplane.Start(error));
        CHECK(!error.empty());
        CHECK(!vgww::relay::PortMapManager::Instance().IsRunning());

        raw->FailSendPackets(false);
        std::string stop_error;
        CHECK(dataplane.Stop(stop_error));  // clean rollback
        CHECK(stop_error.empty());
        CHECK(dataplane.GetLifecycleCounts().running == false);
        CHECK(CountsAreEmpty(dataplane.GetLifecycleCounts()));

        std::string re_error;
        CHECK(dataplane.Start(re_error));  // clean retry, no terminate
        std::string re_stop;
        CHECK(dataplane.Stop(re_stop));
    }

}  // namespace

int main() {
    TestCleanRestartCycles();
    TestB25UiServiceCommands();
    TestB137ReplaceBindingThroughExecutorIsAtomic();
    TestBlockedReadRefusesRestart();
    TestInjectedReadFailureStopsCleanly();
    TestBypassDisablesDhcp();
    TestDhcpDiscoverGetsOffer();
    TestLeasesDumpedOnStop();
    TestDhcpDisabledAndCorruptLease();
    TestV6DisabledWhenIpv6Off();
    TestDhcp6SolicitViaDataplane();
    TestRsNoRaWhenIpv6Disabled();
    TestBypassSendsNoRa();
    TestStartFailureStopsPortMapManager();

    if (0 == g_failures) {
        std::puts("test_dataplane_lifecycle: ALL PASS");
        return 0;
    }
    std::fprintf(stderr, "test_dataplane_lifecycle: %d FAILURES\n", g_failures);
    return 1;
}
