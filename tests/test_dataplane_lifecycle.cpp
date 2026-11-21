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

#include <atomic>
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

    // P139: per-process scratch directory (pid leaf) so parallel
    // instances never write and delete the same lease/config file.
    std::string ScratchDir() {
        const std::string leaf = "vgww-tests-dpl-" +
                                 std::to_string(::GetCurrentProcessId());
        const std::filesystem::path dir =
            std::filesystem::temp_directory_path() / leaf;
        std::error_code ec;
        std::filesystem::create_directories(dir, ec);
        return dir.string();
    }

    std::string ScratchFile(const char* name) {
        return (std::filesystem::path(ScratchDir()) / name).string();
    }

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

        /// P148 A-1: makes ArmRxEvent fail, i.e. Start() bails out AFTER
        /// SetAdapterMode already put the adapter into LISTEN mode.
        void FailArmRxEvent(bool fail) {
            std::lock_guard<std::mutex> lock(mutex_);
            fail_arm_rx_event_ = fail;
        }

        int SetAdapterModeCalls() const {
            return set_mode_calls_.load(std::memory_order_relaxed);
        }

        int ResetAdapterModeCalls() const {
            return reset_mode_calls_.load(std::memory_order_relaxed);
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
            set_mode_calls_.fetch_add(1, std::memory_order_relaxed);
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

        bool ArmRxEvent(const AdapterEntry&, void*, std::string& error) override {
            std::lock_guard<std::mutex> lock(mutex_);
            if (fail_arm_rx_event_) {
                error = "injected arm rx event failure";
                return false;
            }
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
            reset_mode_calls_.fetch_add(1, std::memory_order_relaxed);
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
        bool fail_arm_rx_event_ = false;
        std::atomic<int> set_mode_calls_{0};
        std::atomic<int> reset_mode_calls_{0};
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
        const std::string lease_path = ScratchFile("b137-replace-leases.json");
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


    /// Builds an Ethernet+IPv4+UDP+DHCPv4 message (client 68 -> server 67)
    /// with option 53 = `msg_type` and, when non-zero, option 54 =
    /// `server_id` (P154 D3).
    std::vector<uint8_t> MakeDhcp4Request(const std::array<uint8_t, 6>& client,
                                          uint32_t xid, uint8_t msg_type,
                                          uint32_t server_id) {
        std::vector<uint8_t> f = MakeDhcpDiscover(client, xid);
        const size_t dhcp_at = 14 + 20 + 8;
        // Replace the {53,1,<type>} option block that MakeDhcpDiscover wrote.
        f.resize(dhcp_at + 240);
        const uint8_t options[] = {53, 1, msg_type};
        f.insert(f.end(), options, options + sizeof(options));
        if (0 != server_id) {
            f.push_back(54);
            f.push_back(4);
            f.push_back(static_cast<uint8_t>(server_id & 0xFF));
            f.push_back(static_cast<uint8_t>((server_id >> 8) & 0xFF));
            f.push_back(static_cast<uint8_t>((server_id >> 16) & 0xFF));
            f.push_back(static_cast<uint8_t>((server_id >> 24) & 0xFF));
        }
        f.push_back(255);
        const uint16_t total =
            static_cast<uint16_t>(f.size() - (14 + 20));
        f[16] = static_cast<uint8_t>(total >> 8);
        f[17] = static_cast<uint8_t>(total & 0xFF);
        const uint16_t udp_len = static_cast<uint16_t>(f.size() - (14 + 20));
        f[14 + 20 + 4] = static_cast<uint8_t>(udp_len >> 8);
        f[14 + 20 + 5] = static_cast<uint8_t>(udp_len & 0xFF);
        return f;
    }

    /// P154 D3 (RFC 2131 4.3.2): a DHCPREQUEST that selects another server
    /// (option 54 present and != ours) must not be ACKed and must not create
    /// a lease. A REQUEST without option 54 (INIT-REBOOT/RENEWING/REBINDING)
    /// stays legal and must still be ACKed.
    void TestP154V4RequestForForeignServerIsNotAcked() {
        const vgww::core::Config config = MakeDhcpMainConfig();
        const std::string lease_path = ScratchFile("p154-request-leases.json");
        std::remove(lease_path.c_str());

        vgww::runtime::Dataplane dataplane(config, lease_path);
        auto fake = std::make_unique<FakeDriverClient>();
        FakeDriverClient* raw = fake.get();
        dataplane.SetDriverClient(std::move(fake));
        std::string error;
        CHECK(dataplane.Start(error));
        CHECK(dataplane.DhcpActive());

        const std::array<uint8_t, 6> foreign_client = {0x02, 0x00, 0x00,
                                                       0x00, 0x00, 0x71};
        bool sid_ok = false;
        const uint32_t foreign_sid =
            vgww::core::ParseIpv4("192.168.40.2", sid_ok);
        CHECK(sid_ok && 0 != foreign_sid);
        raw->InjectFrame(MakeDhcp4Request(foreign_client, 0x51515151u, 3,
                                          foreign_sid));
        std::this_thread::sleep_for(std::chrono::milliseconds(700));
        CHECK(!HasDhcpReply(raw->SentFrames()));
        CHECK(0 == dataplane.DhcpLeaseCount());

        // Positive control: the same REQUEST without option 54 is legal.
        const std::array<uint8_t, 6> no_sid_client = {0x02, 0x00, 0x00,
                                                      0x00, 0x00, 0x72};
        raw->InjectFrame(
            MakeDhcp4Request(no_sid_client, 0x52525252u, 3, 0));
        const auto deadline =
            std::chrono::steady_clock::now() + std::chrono::seconds(4);
        while (std::chrono::steady_clock::now() < deadline &&
               !HasDhcpReply(raw->SentFrames())) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        CHECK(HasDhcpReply(raw->SentFrames()));
        CHECK(1 == dataplane.DhcpLeaseCount());

        // And a REQUEST naming THIS gateway is ACKed too.
        bool ok = false;
        const uint32_t own_sid = vgww::core::ParseIpv4("192.168.40.1", ok);
        CHECK(ok && 0 != own_sid);
        const std::array<uint8_t, 6> own_client = {0x02, 0x00, 0x00,
                                                   0x00, 0x00, 0x73};
        raw->InjectFrame(MakeDhcp4Request(own_client, 0x53535353u, 3, own_sid));
        const auto deadline2 =
            std::chrono::steady_clock::now() + std::chrono::seconds(4);
        while (std::chrono::steady_clock::now() < deadline2 &&
               2 != dataplane.DhcpLeaseCount()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        CHECK(2 == dataplane.DhcpLeaseCount());

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
        const std::string lease_path = ScratchFile("bypass-leases.json");
        const std::string log_path = ScratchFile("bypass-start.log");
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
        const std::string lease_path = ScratchFile("offer-leases.json");
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

    /// batch99: the crash window. v6 already snapshotted every 60 s while v4
    /// waited for a clean Stop, so an abrupt exit lost every v4 lease. With
    /// the cadence seam shortened, the document must appear WHILE the plane
    /// still runs (no Stop before the assertion).
    void TestB99V4LeasesDumpedPeriodically() {
        const vgww::core::Config config = MakeDhcpMainConfig();
        const std::string lease_path = ScratchFile("periodic-leases.json");
        std::remove(lease_path.c_str());

        vgww::runtime::Dataplane dataplane(config, lease_path);
        auto fake = std::make_unique<FakeDriverClient>();
        FakeDriverClient* raw = fake.get();
        dataplane.SetDriverClient(std::move(fake));
        dataplane.SetLeaseDumpIntervalForTest(std::chrono::milliseconds(50));
        std::string error;
        CHECK(dataplane.Start(error));
        CHECK(dataplane.DhcpActive());

        raw->InjectFrame(MakeDhcpDiscover({0x02, 0x00, 0x00, 0x00, 0x00, 0x43},
                                          0xAB990001u));
        const auto deadline =
            std::chrono::steady_clock::now() + std::chrono::seconds(5);
        bool dumped = false;
        while (std::chrono::steady_clock::now() < deadline && !dumped) {
            std::ifstream in(lease_path, std::ios::binary);
            if (in.good()) {
                std::stringstream ss;
                ss << in.rdbuf();
                dumped = ss.str().find("02:00:00:00:00:43") !=
                         std::string::npos;
            }
            if (!dumped) {
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }
        }
        CHECK(dumped);  // written periodically, not only on Stop

        std::string stop_error;
        CHECK(dataplane.Stop(stop_error));
        std::remove(lease_path.c_str());
    }

    /// batch101: a live config apply stops and restarts the plane. The stop's
    /// dirty lease write must stay visible AFTER the restart (P50 cleared the
    /// verdict on Start), and only a later clean stop may clear it.
    void TestB102StopDirtyVerdictSurvivesRestart() {
        const vgww::core::Config config = MakeDhcpMainConfig();
        const std::string lease_path = ScratchFile("b102-stop-dirty.json");
        std::remove(lease_path.c_str());
        vgww::runtime::Dataplane dataplane(config, lease_path);
        dataplane.SetDriverClient(std::make_unique<FakeDriverClient>());
        std::string error;
        CHECK(dataplane.Start(error));
        CHECK(dataplane.DhcpActive());
        {
            std::ofstream out(lease_path);
            out << "{\"version\":1,\"leases\":[]}";
        }
        const HANDLE held = ::CreateFileA(
            lease_path.c_str(), GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL, nullptr);
        CHECK(INVALID_HANDLE_VALUE != held);
        std::string stop_error;
        CHECK(dataplane.Stop(stop_error));
        CHECK(dataplane.StopPersistFailed());
        ::CloseHandle(held);

        // The apply path stops then starts: the verdict must survive so the
        // dashboard can show that the leases were lost on the way.
        error.clear();
        CHECK(dataplane.Start(error));
        CHECK(dataplane.StopPersistFailed());  // still dirty after restart

        // Only a clean stop clears it.
        std::string clean_error;
        CHECK(dataplane.Stop(clean_error));
        CHECK(clean_error.empty());
        CHECK(!dataplane.StopPersistFailed());
        std::remove(lease_path.c_str());
    }

    /// P147 P2-1: a second Stop() with nothing left to persist (dhcp_/dhcp6_
    /// were already reset by the first stop) must NOT overwrite the sticky
    /// verdict the first stop produced. Only an actual persist attempt may
    /// change the flag.
    void TestP147P21StickyPersistSurvivesSecondStop() {
        const vgww::core::Config config = MakeDhcpMainConfig();
        const std::string lease_path = ScratchFile("p147p21-second-stop.json");
        std::remove(lease_path.c_str());
        vgww::runtime::Dataplane dataplane(config, lease_path);
        dataplane.SetDriverClient(std::make_unique<FakeDriverClient>());
        std::string error;
        CHECK(dataplane.Start(error));
        CHECK(dataplane.DhcpActive());
        {
            std::ofstream out(lease_path);
            out << "{\"version\":1,\"leases\":[]}";
        }
        // No FILE_SHARE_DELETE: the atomic replace must fail at Stop.
        const HANDLE held = ::CreateFileA(
            lease_path.c_str(), GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL, nullptr);
        CHECK(INVALID_HANDLE_VALUE != held);
        std::string stop_error;
        CHECK(dataplane.Stop(stop_error));  // teardown fine, dump failed
        CHECK(!stop_error.empty());
        CHECK(dataplane.StopPersistFailed());
        ::CloseHandle(held);

        // Second stop without a restart: the servers are already gone, so no
        // persist is attempted. The first verdict must survive.
        std::string stop2_error;
        CHECK(dataplane.Stop(stop2_error));
        CHECK(dataplane.StopPersistFailed());
        std::remove(lease_path.c_str());
    }

    /// batch100: teardown succeeded but the lease document could not be
    /// written -> Stop() still returns true (the plane stopped), yet the loss
    /// must be observable: non-empty error text plus a sticky flag that
    /// survives the server teardown.
    void TestB100StopReportsLeaseDumpFailure() {
        const vgww::core::Config config = MakeDhcpMainConfig();
        const std::string lease_path = ScratchFile("b100-stop-dump.json");
        std::remove(lease_path.c_str());
        {
            vgww::runtime::Dataplane dataplane(config, lease_path);
            dataplane.SetDriverClient(std::make_unique<FakeDriverClient>());
            std::string error;
            CHECK(dataplane.Start(error));
            CHECK(dataplane.DhcpActive());
            {
                std::ofstream out(lease_path);
                out << "{\"version\":1,\"leases\":[]}";
            }
            // No FILE_SHARE_DELETE: the atomic replace must fail at Stop.
            const HANDLE held = ::CreateFileA(
                lease_path.c_str(), GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL, nullptr);
            CHECK(INVALID_HANDLE_VALUE != held);
            std::string stop_error;
            CHECK(dataplane.Stop(stop_error));  // teardown itself is fine
            CHECK(!stop_error.empty());         // durability is not
            CHECK(stop_error.find("lease dump failed on stop") !=
                  std::string::npos);
            CHECK(dataplane.StopPersistFailed());
            ::CloseHandle(held);
        }
        // A clean run starts with no verdict and clears it by writing.
        {
            vgww::runtime::Dataplane dataplane(config, lease_path);
            dataplane.SetDriverClient(std::make_unique<FakeDriverClient>());
            std::string error;
            CHECK(dataplane.Start(error));
            CHECK(!dataplane.StopPersistFailed());
            std::string stop_error;
            CHECK(dataplane.Stop(stop_error));
            CHECK(stop_error.empty());
            CHECK(!dataplane.StopPersistFailed());
        }
        std::remove(lease_path.c_str());
    }

    /// Stop() persists the lease table; a restart re-assembles the server.
    void TestLeasesDumpedOnStop() {
        const vgww::core::Config config = MakeDhcpMainConfig();
        const std::string lease_path = ScratchFile("dump-leases.json");
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
            // P155 P3-2: wait for the LEASE, not for a fixed 700 ms.
            // A fixed sleep is wasted time on a fast host and a false
            // failure on a loaded one; the observable state (the dynamic
            // lease count) is what the dump is about.
            for (int i = 0; i < 100 && 0 == dataplane.DhcpLeaseCount(); ++i) {
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
            CHECK(0 != dataplane.DhcpLeaseCount());
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

    // P155 P3-1 red proof: both legacy lease sites derive their directory
    // from the pid-free shared root `<temp>/vgww-tests` instead of the
    // per-process ScratchDir() (`vgww-tests-dpl-<pid>`), so two parallel
    // instances write and delete the same `dump-leases.json` /
    // `bypass-leases.json`.
    //
    // Behavioural witness: a sentinel with a marker body is planted at the
    // shared root under the exact name the legacy dump test uses. That test
    // starts with `std::remove(lease_path)` and later publishes its own lease
    // table to the same path; the marker body disappearing proves the legacy
    // site wrote the SHARED root. An isolated (ScratchFile) site would leave
    // the marker untouched.
    //
    // RED contract: on HEAD the marker is gone (shared write confirmed), so
    // the final CHECK is expected to FAIL until the sites are routed through
    // ScratchFile(). Falsifiability: routing either site through
    // ScratchFile() keeps the marker and turns that CHECK green.
    void TestP155P31LegacyLeaseSitesUseSharedRoot() {
        const std::filesystem::path shared_root =
            std::filesystem::temp_directory_path() / "vgww-tests";
        std::error_code ec;
        std::filesystem::create_directories(shared_root, ec);
        // P155 P3-1: the sentinel sits where the legacy dump site writes
        // when it still derives from the pid-free shared root. A site
        // routed through ScratchDir() writes a different path, so the
        // sentinel survives and the CHECK below is green.
        const std::filesystem::path sentinel = shared_root / "dump-leases.json";
        const std::string marker = "P155-P3-1-MARKER-NOT-A-LEASE-TABLE";
        std::error_code rm_ec;
        std::filesystem::remove(sentinel, rm_ec);
        {
            std::ofstream out(sentinel, std::ios::binary | std::ios::trunc);
            out << marker;
        }

        const std::string shared_path = shared_root.string();
        const std::string scratch_path = ScratchDir();
        CHECK(shared_path.find("vgww-tests-dpl-") == std::string::npos);
        CHECK(scratch_path.find("vgww-tests-dpl-") != std::string::npos);
        CHECK(scratch_path != shared_path);

        TestLeasesDumpedOnStop();

        std::string body;
        {
            std::ifstream in(sentinel, std::ios::binary);
            if (in.good()) {
                std::stringstream ss;
                ss << in.rdbuf();
                body = ss.str();
            }
        }
        std::fprintf(stderr,
                     "[p155-p3-1] marker_len=%zu sentinel_len=%zu\n",
                     marker.size(), body.size());
        CHECK(body == marker);
    }

    /// Main-mode gate and damaged-file resilience: `dhcp.enabled = false`
    /// must not assemble a server (and must not write a lease file), while a
    /// corrupt lease file must degrade to an empty table without crashing.
    void TestDhcpDisabledAndCorruptLease() {
        {
            vgww::core::Config config = MakeDhcpMainConfig();
            config.dhcp.enabled = false;
            const std::string lease_path = ScratchFile("disabled-leases.json");
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
            const std::string lease_path = ScratchFile("corrupt-leases.json");
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
        const std::string lease_path = ScratchFile("v6off-leases.json");
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
        const std::string lease_path = ScratchFile("solicit6-leases.json");
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
        const std::string lease_path = ScratchFile("rs-gate-leases.json");
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
        const std::string lease_path = ScratchFile("bypass-ra-leases.json");
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

    /// P147 P1-3/P1-4/P1-5: the facade readers run on web/UI threads while a
    /// concurrent StopAll resets `dhcp_`/`dhcp6_` and clears `udp_tables`.
    /// Without a lifecycle lock the null check and the dereference straddle a
    /// free (TOCTOU). The test keeps several readers hammering the facade
    /// while a writer cycles Stop/Start, and asserts every post-Stop read is a
    /// synchronised "no server" answer rather than freed memory.
    ///
    /// Anti-vacuity: the writer counts successful Stop calls whose immediate
    /// post-reset probe observed DhcpActive()==false, and the reader counts
    /// its completed batches; both must be non-zero or the test only proved
    /// that nothing ran.
    void TestP13ConcurrentFacadeVsLifecycle() {
        vgww::core::Config config = MakeDhcpMainConfig();
        // Both servers assembled: the v4 and v6 accessors share ONE lifecycle
        // lock, so the test must exercise both or half the lock domain is
        // never touched.
        config.ipv6 = MakeDhcp6MainConfig().ipv6;
        const std::string lease_path = ScratchFile("p147-concurrency-leases.json");
        std::remove(lease_path.c_str());
        std::remove((lease_path + ".leases6").c_str());

        vgww::runtime::Dataplane dataplane(config, lease_path);
        dataplane.SetDriverClient(std::make_unique<FakeDriverClient>());
        // Keep the control thread's periodic lease dump out of the way: it
        // writes the same files the Stop path dumps, and a disk-warm cache is
        // not what this test measures.
        dataplane.SetLeaseDumpIntervalForTest(std::chrono::hours(24));

        std::string start_error;
        CHECK(dataplane.Start(start_error));
        CHECK(dataplane.DhcpActive());
        CHECK(dataplane.Dhcp6Active());

        // Load the facade with real rows: an EMPTY lease table makes
        // GetLeases() finish inside the same scheduler slice as the null
        // check, so a Stop that frees the server right after can never
        // overlap the in-flight call and a missing facade lock stays
        // invisible (the first version of this test proved exactly that -
        // removing the lock from DhcpLeaseCount did not turn it red). With
        // 16 bindings every GetLeases() formats 32 strings and copies two
        // vectors while holding the pointer, which is the window an unlocked
        // reader actually needs to fault.
        for (int i = 0; i < 16; ++i) {
            char mac[32] = {0};
            char ip[32] = {0};
            std::snprintf(mac, sizeof(mac), "02:00:00:00:01:%02X", i + 1);
            std::snprintf(ip, sizeof(ip), "192.168.40.%d", 20 + i);
            CHECK(dataplane.ReplaceDhcpBinding(std::string(), mac, ip, "p13"));
        }

        std::atomic<bool> stop_flag{false};
        std::atomic<uint64_t> reader_batches{0};
        std::atomic<uint64_t> writer_cycles{0};
        std::atomic<bool> reader_state_bad{false};
        std::vector<std::thread> readers;
        for (int t = 0; t < 4; ++t) {
            readers.emplace_back([&dataplane, &stop_flag, &reader_batches,
                                  &reader_state_bad] {
                uint64_t local = 0;
                while (!stop_flag.load(std::memory_order_relaxed)) {
                    for (int i = 0; i < 1000; ++i) {
                        (void)dataplane.DhcpLeaseCount();
                        (void)dataplane.Dhcp6LeaseCount();
                        (void)dataplane.DhcpActive();
                        (void)dataplane.Dhcp6Active();
                        (void)dataplane.UdpFlowEvictions();
                        // P147 C-2 (W11-5 dual audit): GetLifecycleCounts()
                        // is NOT a concurrent surface. dataplane.h:167-170
                        // documents it as "call only when no Start()/Stop() is
                        // in flight": rx_rings/tx_rings/icmp_relays/
                        // relay_registry_/workers are read without any lock
                        // while ReleaseDataplaneContainers() (dataplane.cpp:
                        // 1349-1377) clears them outside dhcp_lifecycle_mu_.
                        // Calling it from these readers was a contract
                        // violation (real UB), not a coverage gain - the
                        // quiescent probe below now covers it instead.
                        if (!dataplane.GetLeases().empty() &&
                            !dataplane.DhcpActive()) {
                            reader_state_bad.store(true,
                                                    std::memory_order_relaxed);
                        }
                        // Row-bearing v6/v4 accessors: the formatting loop is
                        // the long window an unlocked reader needs.
                        (void)dataplane.GetDhcpBindings();
                        (void)dataplane.GetDhcp6Bindings();
                        (void)dataplane.Dhcp6BindingCount();
                        (void)dataplane.DhcpLeaseFileCorrupt();
                        (void)dataplane.Dhcp6LeaseFileCorrupt();
                        (void)dataplane.DhcpPoolExhaustedCount();
                        (void)dataplane.Dhcp6PoolExhaustedCount();
                        (void)dataplane.DhcpRateLimitResets();
                        (void)dataplane.Dhcp6RateLimitResets();
                    }
                    ++local;
                }
                reader_batches.store(local + 1, std::memory_order_relaxed);
            });
        }

        for (int cycle = 0; cycle < 100; ++cycle) {
            std::string stop_error;
            const bool stopped = dataplane.Stop(stop_error);
            CHECK(stopped);
            if (!stopped) {
                break;
            }
            // DWELL: hold the plane stopped while the readers keep hammering.
            // Without this the very next Start() re-allocates the block Stop
            // just freed at the SAME address, so an unlocked reader reads valid
            // memory and the UAF stays invisible (measured: removing the facade
            // lock kept the test green before this window existed). With it,
            // freed server memory stays deallocated for the whole window.
            std::this_thread::sleep_for(std::chrono::milliseconds(3));
            // Reading the row-bearing facade while the plane is down is the
            // window under test: `dhcp_` is gone, so an unlocked reader reads
            // freed memory while a locked one reports "no server".
            CHECK(!dataplane.DhcpActive());
            CHECK(!dataplane.Dhcp6Active());
            CHECK(0 == dataplane.DhcpLeaseCount());
            CHECK(0 == dataplane.Dhcp6LeaseCount());
            CHECK(0 == dataplane.UdpFlowEvictions());
            // P147 C-2: the lifecycle probe belongs HERE and nowhere else -
            // Stop() has returned, so the single-threaded lifecycle owner is
            // quiescent and the unlocked container reads are per contract
            // (dataplane.h:167-170). A clean Stop must reset every container
            // to zero before the next Start.
            const auto quiescent_counts = dataplane.GetLifecycleCounts();
            CHECK(quiescent_counts.udp_tables == 0);
            CHECK(quiescent_counts.rx_rings == 0);
            CHECK(quiescent_counts.tx_rings == 0);
            CHECK(quiescent_counts.icmp_relays == 0);
            CHECK(quiescent_counts.relay_registry == 0);
            CHECK(quiescent_counts.workers == 0);
            CHECK(quiescent_counts.running == false);
            CHECK(!quiescent_counts.shutdown_incomplete);
            CHECK(dataplane.GetLeases().empty());
            CHECK(dataplane.GetLeases6().empty());
            CHECK(dataplane.GetDhcpBindings().empty());
            CHECK(dataplane.GetDhcp6Bindings().empty());
            CHECK(0 == dataplane.Dhcp6BindingCount());
            writer_cycles.fetch_add(1, std::memory_order_relaxed);

            std::string restart_error;
            const bool restarted = dataplane.Start(restart_error);
            CHECK(restarted);
            if (!restarted) {
                break;
            }
            CHECK(dataplane.DhcpActive());
            CHECK(dataplane.Dhcp6Active());
        }

        stop_flag.store(true, std::memory_order_relaxed);
        for (std::thread& reader : readers) {
            reader.join();
        }

        CHECK(writer_cycles.load() == 100);
        CHECK(reader_batches.load() > 0);
        CHECK(!reader_state_bad.load());

        std::string stop_error;
        CHECK(dataplane.Stop(stop_error));
        if (!stop_error.empty()) {
            std::fprintf(stderr, "final stop error: %s\n",
                         stop_error.c_str());
        }
        std::remove(lease_path.c_str());
        std::remove((lease_path + ".leases6").c_str());
    }

    /// P147 P1-1 residual: a start failure AFTER every thread and container
    /// was created (std::bad_alloc from SetAdapterBinding's WideToUtf8 is the
    /// production trigger) must roll the plane back completely: no thread is
    /// left joinable, every container is empty, `running` is false, and a
    /// second Start() from the same object succeeds instead of being refused
    /// forever by StateIsEmpty(). The DHCP servers are assembled here (main
    /// mode + dhcp.enabled) so the rollback also has to drop dhcp_/dhcp6_,
    /// otherwise StateIsEmpty() refuses every later start.
    void TestStartFailureAfterThreadsRollsBack() {
        const vgww::core::Config config = MakeDhcpMainConfig();
        const std::string lease_path = ScratchFile("rollback-leases.json");
        std::remove(lease_path.c_str());
        std::remove((lease_path + ".leases6").c_str());
        vgww::runtime::Dataplane dataplane(config, lease_path);
        auto fake = std::make_unique<FakeDriverClient>();
        FakeDriverClient* raw = fake.get();
        dataplane.SetDriverClient(std::move(fake));

        bool throw_once = true;
        dataplane.SetStartPostThreadsProbeForTest([&throw_once] {
            if (throw_once) {
                throw std::bad_alloc();
            }
        });

        std::string error;
        CHECK(!dataplane.Start(error));
        CHECK(!error.empty());
        CHECK(!dataplane.IsRunning());
        CHECK(CountsAreEmpty(dataplane.GetLifecycleCounts()));
        CHECK(!vgww::relay::PortMapManager::Instance().IsRunning());
        CHECK(!dataplane.DhcpActive());
        CHECK(!dataplane.Dhcp6Active());

        // The whole plane must be restartable from the same object.
        throw_once = false;
        std::string re_error;
        CHECK(dataplane.Start(re_error));
        if (!re_error.empty()) {
            std::fprintf(stderr, "restart error: %s\n", re_error.c_str());
        }
        CHECK(dataplane.IsRunning());
        CHECK(dataplane.DhcpActive());
        std::string re_stop;
        CHECK(dataplane.Stop(re_stop));
        CHECK(re_stop.empty());
        CHECK(CountsAreEmpty(dataplane.GetLifecycleCounts()));
        (void)raw;
        std::remove(lease_path.c_str());
        std::remove((lease_path + ".leases6").c_str());
    }

    /// P148 A-1: a start that fails between SetAdapterMode and the first
    /// running thread must restore the adapter mode before returning. Without
    /// the guard the NIC stays in LISTEN-only mode while the UI reports a
    /// failed start, and ReleaseDataplaneContainers() nulls `adapter`, so the
    /// later Stop() can never repair it. A successful start must NOT reset
    /// early: Stop() owns exactly one reset.
    void TestP148A1FailedStartResetsAdapterMode() {
        {
            const vgww::core::Config config = MakeConfig();
            vgww::runtime::Dataplane dataplane(config);
            auto fake = std::make_unique<FakeDriverClient>();
            FakeDriverClient* raw = fake.get();
            dataplane.SetDriverClient(std::move(fake));

            // ArmRxEvent runs AFTER SetAdapterMode, so this failure happens
            // while the adapter is already in LISTEN mode.
            raw->FailArmRxEvent(true);
            std::string error;
            CHECK(!dataplane.Start(error));
            CHECK(!error.empty());
            CHECK(1 == raw->SetAdapterModeCalls());    // mode was applied
            CHECK(1 == raw->ResetAdapterModeCalls());  // and rolled back
            CHECK(!dataplane.IsRunning());
        }

        // Success path on a fresh object: the guard must stay disarmed and
        // Stop performs the single reset.
        {
            const vgww::core::Config config = MakeConfig();
            vgww::runtime::Dataplane dataplane(config);
            auto fake = std::make_unique<FakeDriverClient>();
            FakeDriverClient* raw = fake.get();
            dataplane.SetDriverClient(std::move(fake));

            std::string error;
            CHECK(dataplane.Start(error));
            CHECK(1 == raw->SetAdapterModeCalls());
            CHECK(0 == raw->ResetAdapterModeCalls());  // no early reset
            std::string stop_error;
            CHECK(dataplane.Stop(stop_error));
            CHECK(stop_error.empty());
            CHECK(1 == raw->ResetAdapterModeCalls());  // Stop's reset
            CHECK(CountsAreEmpty(dataplane.GetLifecycleCounts()));
        }
    }

    /// P148 A-6: the StartAll catch path must wake the RX thread before
    /// joining it, exactly like StopAll does. The poll interval is raised to
    /// 60 s so a missing wake turns the join into the 5 s budget timeout and
    /// the plane is left detached (shutdown_incomplete) - the CHECKs catch
    /// that without relying on wall-clock luck.
    void TestP148A6StartFailureWakesRxThread() {
        vgww::core::Config config = MakeConfig();
        config.perf.rx_poll_ms = 60000;
        vgww::runtime::Dataplane dataplane(config);
        dataplane.SetDriverClient(std::make_unique<FakeDriverClient>());

        dataplane.SetStartPostThreadsProbeForTest([] {
            // Every thread already exists at this point; give the RX loop
            // ample time to reach its (60 s) event wait, then unwind.
            std::this_thread::sleep_for(std::chrono::milliseconds(300));
            throw std::bad_alloc();
        });

        const auto t0 = std::chrono::steady_clock::now();
        std::string error;
        CHECK(!dataplane.Start(error));
        const auto elapsed_ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - t0)
                .count();
        CHECK(!error.empty());
        // P155 P3-2: the verdict is BEHAVIOURAL (error text, not running,
        // no incomplete shutdown, empty counts). A wall-clock upper bound
        // was removed: on a slow or loaded host a correct wake can take
        // longer than any fixed constant, so the old `elapsed_ms < 4000`
        // turned a slow-but-correct wake into a failure. The join budget
        // (kThreadJoinTimeoutMs) is an upper bound on a STUCK thread, not
        // on a correct one, and is already asserted in the P155 P3-2
        // behavioural scenario below.
        CHECK(!dataplane.IsRunning());
        CHECK(!dataplane.GetLifecycleCounts().shutdown_incomplete);
        CHECK(CountsAreEmpty(dataplane.GetLifecycleCounts()));
        std::fprintf(stderr, "[p148-a6] failed start joined in %lldms\n",
                     static_cast<long long>(elapsed_ms));

        // Clean rollback means a retry works from the same object.
        dataplane.SetStartPostThreadsProbeForTest({});
        std::string re_error;
        CHECK(dataplane.Start(re_error));
        std::string re_stop;
        CHECK(dataplane.Stop(re_stop));
        CHECK(re_stop.empty());
    }

    // P155 P3-2: the start-failure verdict must come from BEHAVIOUR, not from
    // a wall-clock bound. TestP148A6StartFailureWakesRxThread() also asserts
    // `elapsed_ms < 4000` (line ~1779), i.e. it measures the elapsed time of a
    // correct wake and fails when the machine is merely slow. That is a
    // flakiness source, not a defect oracle: the behavioural facts
    // (Start returned false, error non-empty, not running, clean rollback)
    // already distinguish a woken thread from a timed-out one - a woken thread
    // rolls back cleanly, a timed-out one sets shutdown_incomplete.
    //
    // RED contract: a slow-but-correct wake (probe sleeps past the old 4 s
    // bound, then throws) must be judged by behaviour alone and accepted. The
    // old timing gate rejects it, so the scenario fails on HEAD until that
    // gate is removed.
    // Falsifiability: deleting the behavioural CHECKs (or re-arming a timing
    // gate) makes the scenario fail again.
    void TestP155P32StartFailureVerdictIsBehavioural() {
        vgww::core::Config config = MakeConfig();
        config.perf.rx_poll_ms = 60000;
        vgww::runtime::Dataplane dataplane(config);
        dataplane.SetDriverClient(std::make_unique<FakeDriverClient>());
        // 4500 ms: past the old `elapsed_ms < 4000` gate, still far below the
        // 5000 ms join budget, so the wake is correct and the rollback clean.
        dataplane.SetStartPostThreadsProbeForTest([] {
            std::this_thread::sleep_for(std::chrono::milliseconds(4500));
            throw std::bad_alloc();
        });

        const auto t0 = std::chrono::steady_clock::now();
        std::string error;
        const bool started = dataplane.Start(error);
        const auto elapsed_ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - t0)
                .count();
        dataplane.SetStartPostThreadsProbeForTest({});

        std::fprintf(stderr,
                     "[p155-p3-2] elapsed=%lldms started=%d shutdown_incomplete=%d\n",
                     static_cast<long long>(elapsed_ms), started ? 1 : 0,
                     dataplane.GetLifecycleCounts().shutdown_incomplete ? 1 : 0);

        // Behavioural facts only - no timing gate.
        CHECK(!started);
        CHECK(!error.empty());
        CHECK(!dataplane.IsRunning());
        CHECK(!dataplane.GetLifecycleCounts().shutdown_incomplete);
        CHECK(CountsAreEmpty(dataplane.GetLifecycleCounts()));
        // A slow-but-correct wake must NOT be confused with a timed-out one:
        // the join completed inside the 5 s budget, so the plane rolled back
        // cleanly and is immediately restartable. The old timing gate
        // (`elapsed_ms < 4000`) would have rejected exactly this case.
        CHECK(elapsed_ms < 5000);

        // Clean rollback means a retry works from the same object.
        std::string re_error;
        CHECK(dataplane.Start(re_error));
        std::string re_stop;
        CHECK(dataplane.Stop(re_stop));
        CHECK(re_stop.empty());
    }

    /// P147 P1-3/P1-4: deterministic lifetime proof. A reader is parked INSIDE
    /// GetLeases()/GetLeases6() - after the null check, before the dereference
    /// - and a concurrent Stop() must not be able to free the server under it.
    ///
    /// With the lifecycle lock in place the Stop blocks until the read
    /// finishes: the parked reader completes cleanly and Stop joins afterwards.
    /// With the facade lock removed (mutation A) Stop frees the server while
    /// the reader is parked, and the read dereferences freed memory (wrong
    /// answer, page-heap fault, or a hang if the destructor blocks) - the
    /// CHECKs below fail instead of silently passing.
    void TestP13FacadeReaderCannotOutliveServer() {
        vgww::core::Config config = MakeDhcpMainConfig();
        config.ipv6 = MakeDhcp6MainConfig().ipv6;
        const std::string lease_path =
            ScratchFile("p147-parked-leases.json");
        std::remove(lease_path.c_str());
        std::remove((lease_path + ".leases6").c_str());

        vgww::runtime::Dataplane dataplane(config, lease_path);
        dataplane.SetDriverClient(std::make_unique<FakeDriverClient>());
        dataplane.SetLeaseDumpIntervalForTest(std::chrono::hours(24));

        std::string start_error;
        CHECK(dataplane.Start(start_error));
        CHECK(dataplane.DhcpActive());
        CHECK(dataplane.Dhcp6Active());
        CHECK(dataplane.ReplaceDhcpBinding(std::string(), "02:00:00:00:02:01",
                                           "192.168.40.20", "parked"));

        int stage = 0;
        std::mutex gate_mutex;
        std::condition_variable gate_cv;
        bool reader_parked = false;
        bool release_reader = false;
        std::atomic<int> probe_entries{0};
        dataplane.SetDhcpFacadeProbeForTest([&] {
            probe_entries.fetch_add(1, std::memory_order_relaxed);
            std::unique_lock<std::mutex> lock(gate_mutex);
            if (0 == stage) {
                stage = 1;
                reader_parked = true;
                gate_cv.notify_all();
                gate_cv.wait(lock, [&] { return release_reader; });
            }
        });

        std::vector<vgww::runtime::Dataplane::LeaseView> leases;
        std::vector<vgww::runtime::Dataplane::Lease6View> leases6;
        std::vector<vgww::runtime::Dataplane::BindingView> bindings;
        std::thread reader([&] {
            // The probe parks the first call; the other two read the same
            // live server once the gate opens.
            leases = dataplane.GetLeases();
            leases6 = dataplane.GetLeases6();
            bindings = dataplane.GetDhcpBindings();
        });

        {
            std::unique_lock<std::mutex> lock(gate_mutex);
            CHECK(gate_cv.wait_for(lock, std::chrono::seconds(10),
                                   [&] { return reader_parked; }));
        }

        std::atomic<bool> stop_done{false};
        bool stop_ok = false;
        std::thread stopper([&] {
            std::string stop_error;
            stop_ok = dataplane.Stop(stop_error);
            stop_done.store(true, std::memory_order_relaxed);
        });

        // The reader is still parked inside the facade: an unlocked Stop has
        // already freed the server by now. Give it a moment, then release.
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
        const bool stop_early = stop_done.load(std::memory_order_relaxed);
        {
            std::lock_guard<std::mutex> lock(gate_mutex);
            release_reader = true;
            stage = 2;
        }
        gate_cv.notify_all();

        reader.join();
        stopper.join();

        // Lock intact: Stop is serialised behind the read.
        CHECK(!stop_early);
        CHECK(stop_ok);
        CHECK(1 == probe_entries.load(std::memory_order_relaxed) ||
              2 == probe_entries.load(std::memory_order_relaxed));
        // The parked read observed a live server (the static binding is listed
        // by the binding accessor, not by Leases(), which reports dynamic
        // leases only) ...
        CHECK(bindings.size() == 1);
        CHECK(leases.size() <= 1);
        // ... and the plane is fully down afterwards.
        CHECK(!dataplane.DhcpActive());
        CHECK(0 == dataplane.DhcpLeaseCount());
        CHECK(dataplane.GetLeases().empty());

        dataplane.SetDhcpFacadeProbeForTest(nullptr);
        std::string start2;
        CHECK(dataplane.Start(start2));
        std::string stop2;
        CHECK(dataplane.Stop(stop2));
        std::remove(lease_path.c_str());
        std::remove((lease_path + ".leases6").c_str());
    }

    // P148 P2-3: `last_ioctl_warn_` is written by the RX thread (:2266) and
    // by FlushBatch (:4032) with no synchronisation; std::string assignment
    // frees the old buffer, so two concurrent writers are a heap corruption
    // (UAF on the reader side), not a benign data race.
    //
    // W5: a data race cannot be reproduced deterministically from a unit
    // test, and the two writers live inside a running dataplane TU whose
    // thread plumbing is not injectable. This test therefore does NOT claim
    // to demonstrate the race at runtime; it pins the fix structurally: both
    // assignments must sit inside `warn_lock(ioctl_warn_mutex_)`, and the
    // mutex must be a member of the plane. Deleting either lock_guard turns
    // this red (verified by mutation P148-mut-p23).
    void TestP148P23IoctlWarnRace() {
        wchar_t exe_path[MAX_PATH * 2] = {0};
        const DWORD exe_len =
            ::GetModuleFileNameW(nullptr, exe_path, MAX_PATH * 2);
        CHECK(exe_len > 0 && exe_len < MAX_PATH * 2);
        if (exe_len <= 0 || exe_len >= MAX_PATH * 2) {
            return;
        }
        namespace fs = std::filesystem;
        fs::path dir = fs::path(std::wstring(exe_path, exe_len)).parent_path();
        fs::path root;
        for (int i = 0; i < 8 && !dir.empty(); ++i) {
            std::error_code mec;
            if (fs::exists(dir / "src" / "runtime" / "dataplane.cpp", mec)) {
                root = dir;
                break;
            }
            if (!dir.has_parent_path()) break;
            dir = dir.parent_path();
        }
        CHECK(!root.empty());
        if (root.empty()) {
            return;
        }
        std::ifstream in(root / "src" / "runtime" / "dataplane.cpp",
                         std::ios::binary);
        CHECK(in.good());
        if (!in.good()) {
            return;
        }
        std::string text((std::istreambuf_iterator<char>(in)),
                         std::istreambuf_iterator<char>());

        // (1) The de-duplicator is still a member and the guard exists.
        CHECK(text.find("std::string last_ioctl_warn_;") != std::string::npos);
        CHECK(text.find("std::mutex ioctl_warn_mutex_;") != std::string::npos);

        // (2) Every `last_ioctl_warn_ = err;` store must be preceded by its
        // own `warn_lock(ioctl_warn_mutex_)` guard. The guard may wrap across
        // lines, so anchor on the declaration head and require the mutex name
        // inside the same guard window.
        size_t from = 0;
        int guarded_stores = 0;
        for (;;) {
            const size_t store = text.find("last_ioctl_warn_ = err;", from);
            if (store == std::string::npos) {
                break;
            }
            const size_t lock =
                text.rfind("std::lock_guard<std::mutex> warn_lock", store);
            CHECK(lock != std::string::npos);
            if (lock != std::string::npos) {
                const std::string between = text.substr(lock, store - lock);
                // The guard must name the warn mutex ...
                CHECK(between.find("ioctl_warn_mutex_") != std::string::npos);
                // ... and must be the *enclosing* one, not a stale guard from
                // the previous site: no other store may sit in between.
                CHECK(between.find("last_ioctl_warn_ = err;") ==
                      std::string::npos);
                ++guarded_stores;
            }
            from = store + 1;
        }
        // Exactly the two known writers, both guarded. A third unguarded
        // writer added later shows up as guarded_stores != 2.
        CHECK(2 == guarded_stores);
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
    TestP154V4RequestForForeignServerIsNotAcked();
    TestLeasesDumpedOnStop();
    TestB99V4LeasesDumpedPeriodically();
    TestB100StopReportsLeaseDumpFailure();
    TestB102StopDirtyVerdictSurvivesRestart();
    TestP147P21StickyPersistSurvivesSecondStop();
    TestDhcpDisabledAndCorruptLease();
    TestV6DisabledWhenIpv6Off();
    TestDhcp6SolicitViaDataplane();
    TestRsNoRaWhenIpv6Disabled();
    TestBypassSendsNoRa();
    TestStartFailureStopsPortMapManager();
    TestStartFailureAfterThreadsRollsBack();
    TestP13ConcurrentFacadeVsLifecycle();
    TestP13FacadeReaderCannotOutliveServer();
    TestP148P23IoctlWarnRace();
    TestP148A1FailedStartResetsAdapterMode();
    TestP148A6StartFailureWakesRxThread();
    TestP155P32StartFailureVerdictIsBehavioural();
    TestP155P31LegacyLeaseSitesUseSharedRoot();

    if (0 == g_failures) {
        std::puts("test_dataplane_lifecycle: ALL PASS");
        return 0;
    }
    std::fprintf(stderr, "test_dataplane_lifecycle: %d FAILURES\n", g_failures);
    return 1;
}
