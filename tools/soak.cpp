// ============================================================================
// tools/soak.cpp - Long-run soak/load harness (manual diagnostic, NOT ctest).
//
//   vgww_soak.exe [--seconds=N] [--flows=N] [--pps=N] [--workers=N]
//                 [--driver=fake|real] [--adapter=NAME] [--out=FILE]
//
// fake (default): an in-memory driver feeds scripted ARP + UDP churn at the
// requested pps, so the harness runs on any machine without the kernel
// driver. real: binds the production NdisrdClient and only OBSERVES live
// traffic (no injection into a live adapter).
//
// Every second it appends a CSV row (working set, private bytes, handle
// count, counters) to --out and at exit prints first/last deltas - the
// memory & handle curve requested by the S1 acceptance criteria.
// ============================================================================
#include <winsock2.h>
#include <ws2ipdef.h>
#include <windows.h>
#include <psapi.h>

#include <asio.hpp>

#include "driver/idriver_client.h"
#include "driver/ndisrd_client.h"
#include "ndisapi/Common.h"
#include "net/eth.h"
#include "proto/arp.h"
#include "proto/udp.h"
#include "runtime/dataplane.h"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace {

    using vgww::driver::AdapterEntry;
    using vgww::driver::IDriverClient;
    using namespace vgww::net;
    using namespace vgww::proto;

    constexpr uint32_t kGatewayIp =
        (192u) | (0u << 8) | (168u << 16) | (40u << 24);   // 192.168.0.40
    constexpr uint32_t kClientIpBase =
        (192u) | (168u << 8) | (1u << 16) | (10u << 24);   // 192.168.1.10
    const WireMac kGatewayMac{0x30, 0xFC, 0x68, 0x88, 0xB4, 0xA9};

    /// In-memory driver: scripted frames in, captured frames out.
    class SoakDriver final : public IDriverClient {
    public:
        SoakDriver() {
            AdapterEntry entry;
            entry.name = L"\\\\SoakNIC";
            entry.handle = this;
            entry.mtu = 1500;
            adapters_.push_back(entry);
        }

        void InjectNow(std::vector<uint8_t> bytes) {
            std::lock_guard<std::mutex> lock(mutex_);
            inbound_.push_back(std::move(bytes));
        }

        size_t PendingInbound() const {
            std::lock_guard<std::mutex> lock(mutex_);
            return inbound_.size();
        }

        uint64_t SentDownCount() const {
            std::lock_guard<std::mutex> lock(mutex_);
            return sent_down_;
        }

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
                        std::string&) override {
            return true;
        }

        uint32_t ReadPackets(void*, INTERMEDIATE_BUFFER* buffers,
                             uint32_t max_packets, std::string&) override {
            std::lock_guard<std::mutex> lock(mutex_);
            uint32_t count = 0;
            while (count < max_packets && !inbound_.empty()) {
                const std::vector<uint8_t>& front = inbound_.front();
                if (front.size() > sizeof(buffers[count].m_IBuffer)) {
                    inbound_.erase(inbound_.begin());
                    continue;
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

        bool SendPacketsToAdapter(void*, INTERMEDIATE_BUFFER*,
                                  uint32_t count, std::string&) override {
            std::lock_guard<std::mutex> lock(mutex_);
            sent_down_ += count;   // counters only: soak must not grow memory
            return true;
        }

        bool SendPacketsToMstcp(void*, INTERMEDIATE_BUFFER*,
                                uint32_t, std::string&) override {
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
        std::deque<std::vector<uint8_t>> inbound_;
        uint64_t sent_down_ = 0;
    };

    std::string ArgValue(int argc, char** argv, const char* name,
                         const std::string& fallback) {
        const std::string prefix = std::string(name) + "=";
        for (int i = 1; i < argc; ++i) {
            const std::string a = argv[i];
            if (a.rfind(prefix, 0) == 0) {
                return a.substr(prefix.size());
            }
        }
        return fallback;
    }

    std::vector<uint8_t> BuildArp(uint32_t sender_ip, const WireMac& mac) {
        std::vector<uint8_t> f(kArpFrameLen, 0);
        BuildArpFrame(f.data(), ArpOperation::kRequest, mac, sender_ip,
                      kBroadcastMac, kGatewayIp);
        return f;
    }

    std::vector<uint8_t> BuildUdp(uint32_t sender_ip, const WireMac& mac,
                                  uint16_t sport) {
        const uint8_t src_ip[4] = {
            static_cast<uint8_t>(sender_ip & 0xFF),
            static_cast<uint8_t>((sender_ip >> 8) & 0xFF),
            static_cast<uint8_t>((sender_ip >> 16) & 0xFF),
            static_cast<uint8_t>((sender_ip >> 24) & 0xFF)};
        const uint8_t dst_ip[4] = {192, 0, 2, 1};   // RFC 5737 TEST-NET-1
        std::vector<uint8_t> f;
        BuildUdpFrame(f, kGatewayMac, mac, src_ip, sport, dst_ip, 9, nullptr,
                      0);
        return f;
    }

    void PrintUsage() {
        std::printf(
            "vgww_soak --seconds=N --flows=N --pps=N --workers=N\n"
            "          --driver=fake|real --adapter=NAME --out=FILE\n");
    }

}  // namespace

int main(int argc, char** argv) {
    for (int i = 1; i < argc; ++i) {
        if (0 == std::strcmp(argv[i], "--help")) {
            PrintUsage();
            return 0;
        }
    }
    const std::string seconds_arg = ArgValue(argc, argv, "--seconds", "60");
    const std::string flows_arg = ArgValue(argc, argv, "--flows", "256");
    const std::string pps_arg = ArgValue(argc, argv, "--pps", "500");
    const std::string workers_arg = ArgValue(argc, argv, "--workers", "2");
    const int seconds = std::atoi(seconds_arg.c_str());
    const int flows = std::atoi(flows_arg.c_str());
    const int pps = std::atoi(pps_arg.c_str());
    const int workers = std::atoi(workers_arg.c_str());
    const bool use_real = ArgValue(argc, argv, "--driver", "fake") == "real";
    const std::string out_path = ArgValue(argc, argv, "--out", "soak.csv");
    const std::string adapter = ArgValue(argc, argv, "--adapter", "");
    if (seconds <= 0 || flows <= 0 || pps <= 0 || workers <= 0) {
        PrintUsage();
        return 2;
    }

    vgww::core::Config cfg;
    cfg.adapter = adapter;
    cfg.gateway.ipv4 = kGatewayIp;
    cfg.gateway.mask = (255u << 24) | (255u << 16);
    cfg.gateway.mac = kGatewayMac;
    cfg.perf.workers = static_cast<uint32_t>(workers);
    cfg.perf.rx_batch = 512;
    cfg.perf.ring_capacity = 4096;
    cfg.perf.max_conns = 4096;
    cfg.perf.udp_flow_cap = 8192;
    cfg.perf.dial_timeout_ms = 400;

    std::unique_ptr<vgww::driver::IDriverClient> driver;
    SoakDriver* fake = nullptr;
    std::string error;
    if (use_real) {
        driver = vgww::driver::NdisrdClient::Open(error);
        if (!driver) {
            std::fprintf(stderr, "soak: cannot open ndisrd: %s\n",
                         error.c_str());
            return 2;
        }
    } else {
        auto holder = std::make_unique<SoakDriver>();
        fake = holder.get();
        driver = std::move(holder);
    }

    // Pre-build the per-flow corpus: steady state must not allocate.
    std::vector<std::vector<uint8_t>> corpus;
    if (nullptr != fake) {
        for (int i = 0; i < flows; ++i) {
            const uint32_t ip =
                kClientIpBase + static_cast<uint32_t>(i & 0xFF);
            const WireMac mac{0x02, 0x00, 0x00, 0x00,
                              static_cast<uint8_t>((i >> 8) & 0xFF),
                              static_cast<uint8_t>(i & 0xFF)};
            if (i % 4 == 0) {
                corpus.push_back(BuildArp(ip, mac));
            } else {
                corpus.push_back(BuildUdp(
                    ip, mac, static_cast<uint16_t>(20000 + (i % 40000))));
            }
        }
    }

    vgww::runtime::Dataplane dp(cfg);
    dp.SetDriverClient(std::move(driver));
    if (!dp.Start(error)) {
        std::fprintf(stderr, "soak: dataplane start failed: %s\n",
                     error.c_str());
        return 3;
    }

    FILE* csv = nullptr;
    if (0 != ::fopen_s(&csv, out_path.c_str(), "wb")) {
        csv = nullptr;
    }
    if (nullptr == csv) {
        std::fprintf(stderr, "soak: cannot open %s\n", out_path.c_str());
        dp.Stop();
        return 3;
    }
    std::fprintf(csv, "elapsed_s,ws_bytes,private_bytes,handles,rx_frames,"
                      "tx_frames,rx_dropped,rate_limited\n");

    const auto t0 = std::chrono::steady_clock::now();
    auto next_sample = t0;
    size_t cursor = 0;
    unsigned long long first_ws = 0;
    unsigned long long first_handles = 0;
    unsigned long long last_ws = 0;
    unsigned long long last_handles = 0;
    int elapsed = 0;
    const int frames_per_tick = pps / 100 > 0 ? pps / 100 : 1;
    while (elapsed < seconds) {
        const auto now = std::chrono::steady_clock::now();
        elapsed = static_cast<int>(
            std::chrono::duration_cast<std::chrono::seconds>(now - t0)
                .count());
        if (nullptr != fake && fake->PendingInbound() < 8192) {
            for (int i = 0; i < frames_per_tick; ++i) {
                fake->InjectNow(corpus[cursor % corpus.size()]);
                ++cursor;
            }
        }
        if (now >= next_sample) {
            PROCESS_MEMORY_COUNTERS pmc{};
            pmc.cb = sizeof(pmc);
            K32GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc));
            DWORD handles = 0;
            ::GetProcessHandleCount(::GetCurrentProcess(), &handles);
            const auto& stats = dp.GetStats();
            std::fprintf(csv, "%d,%llu,%llu,%lu,%llu,%llu,%llu,%llu\n",
                         elapsed,
                         (unsigned long long)pmc.WorkingSetSize,
                         (unsigned long long)pmc.PagefileUsage,
                         (unsigned long)handles,
                         (unsigned long long)stats.rx_frames.load(),
                         (unsigned long long)stats.tx_frames.load(),
                         (unsigned long long)stats.rx_dropped.load(),
                         (unsigned long long)stats.rate_limited.load());
            if (0 == first_ws) {
                first_ws = (unsigned long long)pmc.WorkingSetSize;
                first_handles = (unsigned long long)handles;
            }
            last_ws = (unsigned long long)pmc.WorkingSetSize;
            last_handles = (unsigned long long)handles;
            next_sample = now + std::chrono::seconds(1);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    std::fclose(csv);

    dp.Stop();
    std::printf(
        "soak: %ds flows=%d pps=%d workers=%d driver=%s\n"
        "soak: ws delta=%lld bytes, handle delta=%lld\n"
        "soak: rx=%llu tx=%llu dropped=%llu rate_limited=%llu\n",
        seconds, flows, pps, workers, use_real ? "real" : "fake",
        static_cast<long long>(last_ws) - static_cast<long long>(first_ws),
        static_cast<long long>(last_handles) -
            static_cast<long long>(first_handles),
        (unsigned long long)dp.GetStats().rx_frames.load(),
        (unsigned long long)dp.GetStats().tx_frames.load(),
        (unsigned long long)dp.GetStats().rx_dropped.load(),
        (unsigned long long)dp.GetStats().rate_limited.load());
    return 0;
}
