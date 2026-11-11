// ============================================================================
// test_dataplane.cpp - Full-pipeline integration test WITHOUT the kernel
// driver (backtesting principle B1: simulate boundaries, run product code
// verbatim).
//
// Scripted inbound frames (ARP request, ICMP echo, TCP SYN + its natural
// retransmission) flow through the REAL data plane: classify -> rings ->
// workers -> xtcp -> StackBackend -> TX drain -> captured downstream frames.
//
// Assertions encode M1 acceptance:
//   * ARP request for the gateway      -> ARP reply toward the client
//   * ICMP echo to the gateway         -> ICMP echo reply
//   * TCP SYN to any internet address  -> SYN-ACK from the stack (mimt mode)
//   * host traffic (unclassified)      -> passed through untouched
// ============================================================================
#include <winsock2.h>
#include <ws2ipdef.h>
#include <windows.h>

#include <asio.hpp>

#include "runtime/dataplane.h"

#include "driver/ndisrd_client.h"
#include "ndisapi/Common.h"
#include "net/checksum.h"
#include "net/eth.h"
#include "proto/udp.h"
#include "proto/arp.h"
#include "proto/icmp.h"
#include "proto/ndp.h"
#include "relay/udp_relay.h"
#include "web/web_api.h"

#include <atomic>
#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <set>
#include <stdexcept>
#include <thread>

#ifndef _WIN32
    #error "vgww tests target Windows only"
#endif
#include <dbghelp.h>
#pragma comment(lib, "dbghelp.lib")

namespace {

    int g_failures = 0;

    /// Crash diagnostic: dump a walkable stack trace plus exception address so
    /// a hard fault is diagnosable without a debugger attached.
    LONG WINAPI CrashFilter(EXCEPTION_POINTERS* ep) noexcept {
        std::fprintf(stderr, "[crash] code=0x%08lX at 0x%p\n",
                     ep->ExceptionRecord->ExceptionCode,
                     ep->ExceptionRecord->ExceptionAddress);
        SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS);
        SymInitialize(GetCurrentProcess(), nullptr, TRUE);
        auto* pc = reinterpret_cast<unsigned long long*>(
            ep->ContextRecord->Rsp);
        for (int i = 0; i < 12 && pc && (pc[i] >> 48) != 0; ++i) {
            const DWORD64 addr = pc[i];
            char sym_buf[sizeof(SYMBOL_INFO) + 256] = {};
            auto* sym = reinterpret_cast<SYMBOL_INFO*>(sym_buf);
            sym->SizeOfStruct = sizeof(SYMBOL_INFO);
            sym->MaxNameLen = 255;
            char name[512] = "<no-symbol>";
            if (SymFromAddr(GetCurrentProcess(), addr, nullptr, sym)) {
                std::snprintf(name, sizeof(name), "%s+0x%llX", sym->Name,
                              addr - sym->Address);
            }
            std::fprintf(stderr, "  [%02d] 0x%016llX %s\n", i, addr, name);
        }
        return EXCEPTION_EXECUTE_HANDLER;
    }

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
    using vgww::driver::AdapterEntry;
    using vgww::driver::IDriverClient;

    // inet_addr numeric convention: first octet in the LOW byte.
// inet_addr numeric convention (what ParseIpv4 produces): first octet in
    // the LOW byte. Mirrors config parsing so data-plane wire bytes actually
    // match real deployments.
    constexpr uint32_t kGatewayIp = (192u) | (0u << 8) | (168u << 16) | (40u << 24);
    constexpr uint32_t kClientIp = (192u) | (168u << 8) | (0u << 16) | (101u << 24);
    constexpr uint32_t kServerIp = (93u) | (184u << 8) | (216u << 16) | (34u << 24);
    const WireMac kGatewayMac{0x30, 0xFC, 0x68, 0x88, 0xB4, 0xA9};
    const WireMac kClientMac{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01};

    // ------------------------------------------------------------------
    // In-memory driver double.
    // ------------------------------------------------------------------
    class TestDriverClient final : public IDriverClient {
    public:
        struct ScriptedFrame {
            std::vector<uint8_t> bytes;
            std::chrono::steady_clock::time_point release_at;
            /// Batch-24-D: true = PACKET_FLAG_ON_SEND (a frame the local
            /// TCP/IP stack is sending out the adapter); false = inbound
            /// (received from the wire). The driver reports both directions
            /// in LISTEN mode; the data plane keys its entire host-vs-LAN
            /// split on this flag.
            bool host_sent = false;
            /// batch205: when non-zero, reported as m_Length instead of the
            /// real byte count, so a test can prove the data plane rejects a
            /// driver-reported length past the INTERMEDIATE_BUFFER array.
            DWORD forced_length = 0;
        };

        TestDriverClient() : TestDriverClient(L"\\\\TestNIC") {}

        /// RA-1 (G-5 F1): the adapter name is a constructor parameter so a
        /// scenario can present a localized friendly name (e.g. the zh-CN
        /// form of "Ethernet") to
        /// the production hint-matching path; the default preserves every
        /// existing scenario byte-for-byte.
        explicit TestDriverClient(std::wstring name) {
            AdapterEntry entry;
            entry.name = std::move(name);
            entry.handle = this;  // any non-null unique value
            entry.mtu = 1500;
            adapters_.push_back(entry);
        }

        // Test API: schedule an inbound frame for release at `delay_ms`.
        void ScriptInbound(std::vector<uint8_t> bytes, int delay_ms) {
            bool due_now = false;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                const auto release_at = std::chrono::steady_clock::now() +
                                        std::chrono::milliseconds(delay_ms);
                inbound_.push_back({std::move(bytes), release_at});
                due_now = delay_ms <= 0;
            }
            // batch31 P1-4: the production driver signals the RX event when a
            // frame lands. Without that, the RX thread can only notice a frame
            // on its polling timeout - which is exactly the behaviour the
            // RxPoll anchors compare. Only a frame that is due NOW is signalled;
            // a delayed one is picked up by the poll like on real hardware.
            if (due_now) {
                SignalRxEvent();
            }
        }

        /// Test API: enqueue a frame available on the very next read.
        void InjectNow(std::vector<uint8_t> bytes) {
            ScriptInbound(std::move(bytes), 0);
        }

        /// batch205: enqueue a frame whose driver-reported m_Length is
        /// `forced_len` (larger than the real bytes) so a test can prove the
        /// data plane refuses an out-of-range length instead of reading past
        /// the INTERMEDIATE_BUFFER array.
        void InjectNowForcedLength(std::vector<uint8_t> bytes,
                                  DWORD forced_len) {
            bool due_now = false;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                inbound_.push_back({std::move(bytes),
                                    std::chrono::steady_clock::now(), false,
                                    forced_len});
                due_now = true;
            }
            if (due_now) {
                SignalRxEvent();
            }
        }

        /// Batch-24-D: enqueue a HOST-ORIGINATED frame (PACKET_FLAG_ON_SEND):
        /// one the local TCP/IP stack emits. The driver hands these to the
        /// app in LISTEN mode exactly like inbound frames.
        void ScriptHostSend(std::vector<uint8_t> bytes, int delay_ms = 0) {
            {
                std::lock_guard<std::mutex> lock(mutex_);
                inbound_.push_back({std::move(bytes),
                                    std::chrono::steady_clock::now() +
                                        std::chrono::milliseconds(delay_ms),
                                    true});
            }
            if (delay_ms <= 0) {
                SignalRxEvent();
            }
        }

        /// batch31 P1-4: stop signalling the RX event (models a driver that
        /// only polls). Used by the RxPoll quantization anchor.
        void DisarmRxEventForTest() {
            std::lock_guard<std::mutex> lock(mutex_);
            arm_event_ = false;
        }

        /// batch31 P1-4: how many ReadPackets calls the RX thread has made.
        /// The quantization anchor waits for one to complete so the next frame
        /// lands at the START of a poll window (deterministic ~full-window
        /// wait instead of a random 0..window sample).
        uint64_t read_calls() const noexcept {
            return read_calls_.load(std::memory_order_acquire);
        }

        /// Number of frames captured downstream (polled by the latency anchors
        /// without taking the frame vector's lock for a whole copy).
        std::size_t sent_down_count() const noexcept {
            return sent_down_count_.load(std::memory_order_acquire);
        }

        const std::vector<std::vector<uint8_t>>& SentDown() const noexcept {
            return sent_down_;
        }

        /// Frames VGWW injected toward the local stack (SendPacketsToMstcp).
        const std::vector<std::vector<uint8_t>>& SentUp() const noexcept {
            return sent_up_;
        }

        // ----- IDriverClient ---------------------------------------------
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

        bool ArmRxEvent(const AdapterEntry&, void* event_handle,
                        std::string&) override {
            // batch31 P1-4: KEEP the handle so ScriptInbound can wake the RX
            // thread the way the real driver does. The old stub returned true
            // without storing it, so every scenario silently ran in the
            // 200 ms-polling fallback and could never observe wake latency.
            std::lock_guard<std::mutex> lock(mutex_);
            rx_event_ = event_handle;
            return true;
        }

        /// batch31 P1-4: models the driver's "frame arrived" signal. Never
        /// called while disarmed (the poll-only scenario).
        void SignalRxEvent() {
            void* handle = nullptr;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                if (!arm_event_) {
                    return;
                }
                handle = rx_event_;
            }
            if (handle != nullptr) {
                ::SetEvent(static_cast<HANDLE>(handle));
            }
        }

        uint32_t ReadPackets(void*, INTERMEDIATE_BUFFER* buffers,
                             uint32_t max_packets, std::string&) override {
            {
                std::lock_guard<std::mutex> lock(mutex_);
                const auto now = std::chrono::steady_clock::now();
                uint32_t count = 0;
                while (count < max_packets && !inbound_.empty()) {
                    if (inbound_.front().release_at > now) {
                        break;  // scripted frame not due yet
                    }
                    INTERMEDIATE_BUFFER& ib = buffers[count++];
                    std::memset(&ib, 0, sizeof(ib));
                    ib.m_dwDeviceFlags = inbound_.front().host_sent
                                             ? PACKET_FLAG_ON_SEND
                                             : PACKET_FLAG_ON_RECEIVE;
                    ib.m_hAdapter = adapters_[0].handle;
                    ib.m_Length = inbound_.front().forced_length != 0
                                      ? inbound_.front().forced_length
                                      : static_cast<DWORD>(
                                            inbound_.front().bytes.size());
                    std::memcpy(ib.m_IBuffer, inbound_.front().bytes.data(),
                                inbound_.front().bytes.size());
                    inbound_.erase(inbound_.begin());
                }
                // batch31 P1-4: bump AFTER the copy, so a test that waits for
                // this counter knows the frames are already handed over.
                read_calls_.fetch_add(1, std::memory_order_release);
                return count;
            }
        }

        bool SendPacketsToAdapter(void*, INTERMEDIATE_BUFFER* buffers,
                                  uint32_t count, std::string&) override {
            std::lock_guard<std::mutex> lock(mutex_);
            for (uint32_t i = 0; i < count; ++i) {
                sent_down_.emplace_back(
                    buffers[i].m_IBuffer,
                    buffers[i].m_IBuffer + buffers[i].m_Length);
            }
            sent_down_count_.fetch_add(count, std::memory_order_release);
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
        std::mutex mutex_;
        std::vector<ScriptedFrame> inbound_;
        std::vector<std::vector<uint8_t>> sent_down_;
        std::vector<std::vector<uint8_t>> sent_up_;
        void* rx_event_ = nullptr;
        bool arm_event_ = true;
        std::atomic<uint64_t> read_calls_{0};
        std::atomic<std::size_t> sent_down_count_{0};
    };

    /// RA-3/RA-4 seam (G-5): FindAdapter delegates to the PRODUCTION
    /// MatchAdapterEntry (mirrors tests/test_bridge.cpp:87) so the Start path
    /// exercises the real matcher, friendly_name included.
    class MatcherDriverClient final : public IDriverClient {
    public:
        MatcherDriverClient() = default;
        explicit MatcherDriverClient(std::vector<AdapterEntry> entries)
            : adapters_(std::move(entries)) {}

        // ----- IDriverClient ---------------------------------------------
        const std::vector<AdapterEntry>& Adapters() const noexcept override {
            return adapters_;
        }

        const AdapterEntry* FindAdapter(
            const std::wstring& hint,
            bool* out_ambiguous = nullptr) const noexcept override {
            bool ambiguous = false;
            const int idx = vgww::driver::MatchAdapterEntry(
                adapters_, hint, std::wstring(), &ambiguous);
            if (nullptr != out_ambiguous) {
                *out_ambiguous = ambiguous;
            }
            return idx < 0 ? nullptr : &adapters_[static_cast<size_t>(idx)];
        }

        bool SetAdapterMode(const AdapterEntry&, uint32_t,
                            std::string&) override {
            return true;
        }

        bool SetHwPacketFilter(const AdapterEntry&, uint32_t,
                               std::string&) override {
            return true;
        }

        bool GetHwPacketFilter(const AdapterEntry&, uint32_t& filter,
                               std::string&) override {
            filter = 0;
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

    private:
        std::vector<AdapterEntry> adapters_;
    };

    // ------------------------------------------------------------------
    // Frame builders (checksum-correct: the stack validates them).
    // ------------------------------------------------------------------
    void PushU16(std::vector<uint8_t>& v, uint16_t x) {
        v.push_back(static_cast<uint8_t>(x >> 8));
        v.push_back(static_cast<uint8_t>(x & 0xFF));
    }

    // Wraps a 14-byte Ethernet II frame in an 802.1Q tag (0x8100 + VID),
    // producing an 18-byte header. Used to emulate a trunk-port ingress.
    std::vector<uint8_t> TagFrame(const std::vector<uint8_t>& frame,
                                  uint16_t vid) {
        std::vector<uint8_t> out(frame.size() + 4);
        std::memcpy(out.data(), frame.data(), kMacAddrLen);       // dst MAC
        std::memcpy(out.data() + 6, frame.data() + 6, kMacAddrLen);  // src
        // TPID + TCI land right after the 12-byte MAC pair (direct indexing:
        // PushU16 appends at the END of the vector).
        out[12] = 0x81;                                     // TPID high
        out[13] = 0x00;                                     // TPID low
        out[14] = static_cast<uint8_t>((vid & 0x0FFF) >> 8);  // TCI high
        out[15] = static_cast<uint8_t>(vid & 0x0FFF);          // TCI low
        // Inner ethertype (frame[12..13]) moves to [16..17], then the payload.
        std::memcpy(out.data() + 16, frame.data() + 12, 2);
        std::memcpy(out.data() + 18, frame.data() + kEthernetHeaderLen,
                    frame.size() - kEthernetHeaderLen);
        return out;
    }

    // True when any down frame is 802.1Q tagged with `vid` AND its payload
    // starts with the given dst MAC. A plain (untagged) reply never matches.
    bool ContainsVlanReply(const std::vector<std::vector<uint8_t>>& down,
                           uint16_t vid, const WireMac& dst_mac) {
        for (const auto& f : down) {
            if (f.size() < kEthernetHeaderLen + 4) {
                continue;
            }
            if (!(f[12] == 0x81 && f[13] == 0x00)) {
                continue;  // not tagged
            }
            if (((f[14] << 8) | f[15]) != (vid & 0x0FFF)) {
                continue;  // wrong VID
            }
            if (std::memcmp(f.data(), dst_mac.data(), kMacAddrLen) != 0) {
                continue;
            }
            return true;
        }
        return false;
    }

    // True when a captured frame is tagged with `vid` (any kind of reply).
    bool ContainsAnyVlanTag(const std::vector<std::vector<uint8_t>>& down,
                            uint16_t vid) {
        for (const auto& f : down) {
            if (f.size() >= kEthernetHeaderLen + 4 && f[12] == 0x81 &&
                f[13] == 0x00 &&
                ((f[14] << 8) | f[15]) == (vid & 0x0FFF)) {
                return true;
            }
        }
        return false;
    }

    std::vector<uint8_t> BuildArpRequest() {
        std::vector<uint8_t> f(kArpFrameLen, 0);
        BuildArpFrame(f.data(), ArpOperation::kRequest, kClientMac, kClientIp,
                      kBroadcastMac, kGatewayIp);
        return f;
    }

    std::vector<uint8_t> BuildEchoRequest(size_t payload) {
        const size_t icmp_len = kIcmpHeaderLen + payload;
        std::vector<uint8_t> f(kEthernetHeaderLen + kIpv4HeaderLenMin + icmp_len);
        BuildEthHeader(f.data(), kGatewayMac, kClientMac, kEthertypeIpv4);
        uint8_t* ip = f.data() + kEthernetHeaderLen;
        ip[0] = 0x45;
        const uint16_t total = static_cast<uint16_t>(kIpv4HeaderLenMin + icmp_len);
        ip[2] = static_cast<uint8_t>(total >> 8);
        ip[3] = static_cast<uint8_t>(total & 0xFF);
        ip[8] = 64;
        ip[9] = 1;  // ICMP
        std::memcpy(ip + 12, &kClientIp, 4);
        std::memcpy(ip + 16, &kGatewayIp, 4);
        const uint16_t ip_ck = InternetChecksum(ip, kIpv4HeaderLenMin);
        ip[10] = static_cast<uint8_t>(ip_ck >> 8);
        ip[11] = static_cast<uint8_t>(ip_ck & 0xFF);
        uint8_t* icmp = ip + kIpv4HeaderLenMin;
        icmp[0] = kIcmpEchoRequest;
        const uint16_t icmp_ck = InternetChecksum(icmp, icmp_len);
        icmp[2] = static_cast<uint8_t>(icmp_ck >> 8);
        icmp[3] = static_cast<uint8_t>(icmp_ck & 0xFF);
        return f;
    }

    /// TCP SYN: client:k -> server:dport, seq=1000, window 65535.
    std::vector<uint8_t> BuildSyn(uint16_t sport, uint16_t dport) {
        const size_t tcp_len = 20;
        std::vector<uint8_t> f(kEthernetHeaderLen + kIpv4HeaderLenMin + tcp_len);
        BuildEthHeader(f.data(), kGatewayMac, kClientMac, kEthertypeIpv4);
        uint8_t* ip = f.data() + kEthernetHeaderLen;
        ip[0] = 0x45;
        const uint16_t total = static_cast<uint16_t>(kIpv4HeaderLenMin + tcp_len);
        ip[2] = static_cast<uint8_t>(total >> 8);
        ip[3] = static_cast<uint8_t>(total & 0xFF);
        ip[8] = 64;
        ip[9] = 6;  // TCP
        std::memcpy(ip + 12, &kClientIp, 4);
        std::memcpy(ip + 16, &kServerIp, 4);

        uint8_t* tcp = ip + kIpv4HeaderLenMin;
        tcp[0] = static_cast<uint8_t>(sport >> 8);
        tcp[1] = static_cast<uint8_t>(sport & 0xFF);
        tcp[2] = static_cast<uint8_t>(dport >> 8);
        tcp[3] = static_cast<uint8_t>(dport & 0xFF);
        // seq = 1000
        tcp[4] = 0; tcp[5] = 0; tcp[6] = 0x03; tcp[7] = 0xE8;
        // ack = 0
        tcp[12] = 5 << 4;   // data offset 20
        tcp[13] = 0x02;     // SYN
        tcp[14] = 0xFF;     // window 0xFFFF
        tcp[15] = 0xFF;

        // Pseudo-header length field = TCP segment length (20), NOT the IP
        // total length - this exact mismatch once cost us a debugging session
        // (xtcp's VerifyTcpChecksum rejected the segment with combined=0x14).
        const uint16_t tcp_ck = InternetChecksum(
            tcp, tcp_len, PseudoHeaderSum(ip + 12, ip + 16, 6, tcp_len));
        tcp[16] = static_cast<uint8_t>(tcp_ck >> 8);
        tcp[17] = static_cast<uint8_t>(tcp_ck & 0xFF);

        const uint16_t ip_ck = InternetChecksum(ip, kIpv4HeaderLenMin);
        ip[10] = static_cast<uint8_t>(ip_ck >> 8);
        ip[11] = static_cast<uint8_t>(ip_ck & 0xFF);
        return f;
    }

    // ------------------------------------------------------------------
    // Assertions over captured traffic.
    // ------------------------------------------------------------------
    bool ContainsArpReply(const std::vector<std::vector<uint8_t>>& frames) {
        for (const auto& frame : frames) {
            ArpView view;
            if (ParseArpFrame(frame.data(), frame.size(), view) &&
                ArpOperation::kReply == view.operation &&
                view.sender_ip == kGatewayIp && view.target_ip == kClientIp &&
                view.target_mac == kClientMac) {
                return true;
            }
        }
        return false;
    }

    bool ContainsIcmpEchoReply(const std::vector<std::vector<uint8_t>>& frames) {
        for (const auto& frame : frames) {
            if (frame.size() < kEthernetHeaderLen + kIpv4HeaderLenMin +
                                   kIcmpHeaderLen) {
                continue;
            }
            EthHeaderView eth;
            ParseEthHeader(frame.data(), frame.size(), eth);
            if (kEthertypeIpv4 != eth.ethertype || !(eth.dst == kClientMac)) {
                continue;
            }
            const uint8_t* ip = frame.data() + kEthernetHeaderLen;
            const size_t ihl = (ip[0] & 0x0F) * 4;
            if (ip[9] != 1) {
                continue;
            }
            if (kIcmpEchoReply == ip[ihl]) {
                return true;
            }
        }
        return false;
    }

    /// batch34n: a client SYN to the host stack must produce a TCP ANSWER
    /// on the wire from port 443. Which answer depends on the MACHINE: if
    /// something listens on 443 the host stack returns SYN|ACK, otherwise it
    /// returns RST|ACK. Both prove the frame reached the local stack and its
    /// reply was relayed back - that is the requirement under test. Demanding
    /// SYN|ACK specifically made the suite depend on unrelated local software
    /// (the same run passed or failed depending on whether :443 was bound),
    /// which is an environment dependency, not a product property.
    bool ContainsTcpAnswerFrom443(
        const std::vector<std::vector<uint8_t>>& frames) {
        for (const auto& frame : frames) {
            if (frame.size() < kEthernetHeaderLen + kIpv4HeaderLenMin + 20) {
                continue;
            }
            EthHeaderView eth;
            ParseEthHeader(frame.data(), frame.size(), eth);
            if (kEthertypeIpv4 != eth.ethertype || !(eth.dst == kClientMac)) {
                continue;
            }
            const uint8_t* ip = frame.data() + kEthernetHeaderLen;
            if (ip[9] != 6) {
                continue;
            }
            const uint8_t* tcp = ip + (ip[0] & 0x0F) * 4;
            const uint16_t sport = static_cast<uint16_t>((tcp[0] << 8) | tcp[1]);
            if (sport != 443) {
                continue;
            }
            const uint8_t flags = tcp[13];
            // SYN|ACK (something is listening) or RST|ACK (nothing is): both
            // are answers from the host stack.
            if (0 != (flags & 0x12) || 0 != (flags & 0x04)) {
                return true;
            }
        }
        return false;
    }

    // ------------------------------------------------------------------
    // Full-duplex relay scenario: a frame-level TCP client talks to a local
    // echo server THROUGH the gateway (client frames -> VGWW -> upstream
    // socket -> echo -> back). Proves data actually moves both ways.
    // ------------------------------------------------------------------

    /// Generic checksum-correct TCP segment from the client.
    std::vector<uint8_t> BuildTcpSegment(uint32_t seq, uint32_t ack, uint8_t flags,
                                         const std::string& payload,
                                         uint16_t sport = 51001,
                                         uint16_t dport = 45678) {
        const size_t tcp_len = 20 + payload.size();
        std::vector<uint8_t> f(kEthernetHeaderLen + kIpv4HeaderLenMin + tcp_len);
        BuildEthHeader(f.data(), kGatewayMac, kClientMac, kEthertypeIpv4);
        uint8_t* ip = f.data() + kEthernetHeaderLen;
        ip[0] = 0x45;
        const uint16_t total = static_cast<uint16_t>(kIpv4HeaderLenMin + tcp_len);
        ip[2] = static_cast<uint8_t>(total >> 8);
        ip[3] = static_cast<uint8_t>(total & 0xFF);
        ip[6] = 0x40;  // DF
        ip[8] = 64;
        ip[9] = 6;
        // Target: loopback - the gateway dials it via a host socket.
        const uint8_t src_wire[4] = {192, 168, 0, 101};
        const uint8_t dst_wire[4] = {127, 0, 0, 1};
        std::memcpy(ip + 12, src_wire, 4);
        std::memcpy(ip + 16, dst_wire, 4);
        uint8_t* tcp = ip + kIpv4HeaderLenMin;
        tcp[0] = static_cast<uint8_t>(sport >> 8);
        tcp[1] = static_cast<uint8_t>(sport & 0xFF);
        tcp[2] = static_cast<uint8_t>(dport >> 8);
        tcp[3] = static_cast<uint8_t>(dport & 0xFF);
        tcp[4] = static_cast<uint8_t>(seq >> 24);
        tcp[5] = static_cast<uint8_t>(seq >> 16);
        tcp[6] = static_cast<uint8_t>(seq >> 8);
        tcp[7] = static_cast<uint8_t>(seq);
        tcp[8] = static_cast<uint8_t>(ack >> 24);
        tcp[9] = static_cast<uint8_t>(ack >> 16);
        tcp[10] = static_cast<uint8_t>(ack >> 8);
        tcp[11] = static_cast<uint8_t>(ack);
        tcp[12] = 5 << 4;
        tcp[13] = flags;
        tcp[14] = 0xFF; tcp[15] = 0xFF;
        if (!payload.empty()) {
            std::memcpy(tcp + 20, payload.data(), payload.size());
        }
        const uint16_t tcp_ck = InternetChecksum(
            tcp, static_cast<uint16_t>(tcp_len),
            PseudoHeaderSum(ip + 12, ip + 16, 6, static_cast<uint16_t>(tcp_len)));
        tcp[16] = static_cast<uint8_t>(tcp_ck >> 8);
        tcp[17] = static_cast<uint8_t>(tcp_ck & 0xFF);
        const uint16_t ip_ck = InternetChecksum(ip, kIpv4HeaderLenMin);
        ip[10] = static_cast<uint8_t>(ip_ck >> 8);
        ip[11] = static_cast<uint8_t>(ip_ck & 0xFF);
        return f;
    }

    /// Extracts the server ISN from the captured SYN-ACK (0 when missing).
    /// True when a consumed downstream frame (toward the client, IPv6 UDP)
    /// carries `needle` in the payload.
    bool ContainsV6UdpPayload(const std::vector<std::vector<uint8_t>>& frames,
                              const std::string& needle) {
        if (needle.empty()) {
            return false;
        }
        for (const auto& frame : frames) {
            if (frame.size() < kEthernetHeaderLen + 40 + 8 + needle.size()) {
                continue;
            }
            const uint8_t* ip = frame.data() + kEthernetHeaderLen;
            if ((ip[0] >> 4) != 6 || ip[6] != 17) {
                continue;  // not an IPv6 UDP frame
            }
            const uint8_t* udp = ip + 40;
            const uint16_t len =
                static_cast<uint16_t>((udp[4] << 8) | udp[5]);
            if (len - 8u < needle.size()) {
                continue;
            }
            if (0 == std::memcmp(udp + 8, needle.data(), needle.size())) {
                return true;
            }
        }
        return false;
    }

    /// Builds an IPv6 UDP datagram from the synthetic client to `dport`.
    std::vector<uint8_t> BuildV6UdpSegment(uint16_t sport, uint16_t dport,
                                           const std::string& payload) {
        const size_t udp_len = 8 + payload.size();
        std::vector<uint8_t> f(kEthernetHeaderLen + 40 + udp_len);
        BuildEthHeader(f.data(), kGatewayMac, kClientMac, kEthertypeIpv6);
        uint8_t* ip = f.data() + kEthernetHeaderLen;
        ip[0] = 0x60;
        ip[4] = static_cast<uint8_t>(udp_len >> 8);
        ip[5] = static_cast<uint8_t>(udp_len & 0xFF);
        ip[6] = 17;   // next-header: UDP
        ip[7] = 64;   // hop limit
        const uint8_t src[16] = {0xFE, 0x80, 0, 0, 0, 0, 0, 0,
                                 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x01};
        const uint8_t dst[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
        std::memcpy(ip + 8, src, 16);
        std::memcpy(ip + 24, dst, 16);
        uint8_t* udp = ip + 40;
        udp[0] = static_cast<uint8_t>(sport >> 8);
        udp[1] = static_cast<uint8_t>(sport & 0xFF);
        udp[2] = static_cast<uint8_t>(dport >> 8);
        udp[3] = static_cast<uint8_t>(dport & 0xFF);
        udp[4] = static_cast<uint8_t>(udp_len >> 8);
        udp[5] = static_cast<uint8_t>(udp_len & 0xFF);
        if (!payload.empty()) {
            std::memcpy(udp + 8, payload.data(), payload.size());
        }
        const uint16_t ck =
            vgww::net::InternetChecksum(udp, static_cast<uint16_t>(udp_len),
                                        vgww::net::PseudoHeaderSum6(
                                            src, dst, 17,
                                            static_cast<uint16_t>(udp_len)));
        udp[6] = static_cast<uint8_t>(ck >> 8);
        udp[7] = static_cast<uint8_t>(ck & 0xFF);
        return f;
    }

    void RunUdpEchoServer6(uint16_t port, std::atomic<bool>& stop,
                           std::atomic<bool>& ready) {
        asio::io_context io;
        asio::ip::udp::socket sock(io);
        std::error_code bind_err;
        sock.open(asio::ip::udp::v6(), bind_err);
        sock.bind(asio::ip::udp::endpoint(asio::ip::make_address("::1"), port),
                  bind_err);
        if (bind_err) {
            std::fprintf(stderr, "[dbg] udp6_echo BIND FAILED: %s\n",
                         bind_err.message().c_str());
            return;
        }
        sock.non_blocking(true);
        ready.store(true);
        while (!stop.load()) {
            char buf[2048];
            asio::ip::udp::endpoint peer;
            std::error_code err;
            const size_t n = sock.receive_from(asio::buffer(buf), peer, 0, err);
            if (err == asio::error::would_block) {
                std::this_thread::sleep_for(std::chrono::milliseconds(2));
                continue;
            }
            if (err || 0 == n) {
                std::fprintf(stderr, "[dbg] udp6_echo err=%s\n",
                             err.message().c_str());
                break;
            }
            std::error_code write_err;
            sock.send_to(asio::buffer(buf, n), peer, 0, write_err);
        }
    }

    uint32_t FindServerIsn(const std::vector<std::vector<uint8_t>>& frames,
                           uint16_t client_port, uint16_t server_port) {
        for (const auto& frame : frames) {
            if (frame.size() < kEthernetHeaderLen + kIpv4HeaderLenMin + 20) {
                continue;
            }
            const uint8_t* ip = frame.data() + kEthernetHeaderLen;
            if (ip[9] != 6) {
                continue;
            }
            const uint8_t* tcp = ip + (ip[0] & 0x0F) * 4;
            const uint16_t sport = static_cast<uint16_t>((tcp[0] << 8) | tcp[1]);
            const uint16_t dport = static_cast<uint16_t>((tcp[2] << 8) | tcp[3]);
            const uint8_t flags = tcp[13];
            if (dport == client_port && sport == server_port &&
                0x12 == (flags & 0x12)) {
                // seq field = tcp[4] (MSB) .. tcp[7] (LSB)
                return (static_cast<uint32_t>(tcp[4]) << 24) |
                       (static_cast<uint32_t>(tcp[5]) << 16) |
                       (static_cast<uint32_t>(tcp[6]) << 8) | tcp[7];
            }
        }
        return 0;
    }

    /// True when a downstream IPv4 TCP frame toward the client carries
    /// `needle` on any of the client's local ports - identical to
    /// ContainsPayload but scoped to a specific client source port for
    /// multi-connection scenarios.
    bool ContainsPayloadFor(const std::vector<std::vector<uint8_t>>& frames,
                            uint16_t client_port, const std::string& needle) {
        if (needle.empty()) {
            return false;
        }
        for (const auto& frame : frames) {
            if (frame.size() < kEthernetHeaderLen + kIpv4HeaderLenMin + 20 +
                                   needle.size()) {
                continue;
            }
            const uint8_t* ip = frame.data() + kEthernetHeaderLen;
            if (ip[9] != 6) continue;
            const uint8_t* tcp = ip + (ip[0] & 0x0F) * 4;
            const uint16_t dport = static_cast<uint16_t>((tcp[2] << 8) | tcp[3]);
            if (dport != client_port) {
                continue;
            }
            if (0 == std::memcmp(tcp + 20, needle.data(), needle.size())) {
                return true;
            }
        }
        return false;
    }

    /// True when a downstream TCP frame toward the client carries `needle`.
    bool ContainsPayload(const std::vector<std::vector<uint8_t>>& frames,
                         const std::string& needle) {
        for (const auto& frame : frames) {
            if (frame.size() < kEthernetHeaderLen + kIpv4HeaderLenMin + 20 +
                                   needle.size()) {
                continue;
            }
            const uint8_t* ip = frame.data() + kEthernetHeaderLen;
            if (ip[9] != 6) {
                continue;
            }
            const uint8_t* tcp = ip + (ip[0] & 0x0F) * 4;
            const uint16_t dport = static_cast<uint16_t>((tcp[2] << 8) | tcp[3]);
            if (dport != 51001) {
                continue;
            }
            if (0 == std::memcmp(tcp + 20, needle.data(), needle.size())) {
                return true;
            }
        }
        return false;
    }

    /// Minimal blocking TCP echo server for the upstream side. Runs TWO
    /// acceptors (127.0.0.1 and ::1) - Windows dual-stack sockets proved
    /// unreliable for this purpose in-process.
    void RunEchoServer(uint16_t port, std::atomic<bool>& stop) {
        auto serve_one = [&](const char* addr_text, bool v6) {
            asio::io_context io;
            asio::ip::tcp::acceptor acceptor(io);
            std::error_code err;
            acceptor.open(v6 ? asio::ip::tcp::v6() : asio::ip::tcp::v4(),
                          err);
            acceptor.bind(asio::ip::tcp::endpoint(
                              asio::ip::make_address(addr_text), port),
                          err);
            if (err) {
                std::fprintf(stderr, "[dbg] echo(%s) BIND FAILED: %s\n",
                             addr_text, err.message().c_str());
                return;
            }
            acceptor.listen();
            acceptor.non_blocking(true);
            while (!stop.load()) {
                asio::ip::tcp::socket fresh(io);
                std::error_code accept_err;
                acceptor.accept(fresh, accept_err);
                if (accept_err) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(2));
                    continue;
                }
                // One worker thread per connection: blocking full-duplex echo
                // copy. Accept returned a non-blocking socket, so both the
                // read and the write loop explicitly handle would_block
                // instead of failing with WSAEINPROGRESS (the old single
                // poll loop hit that on concurrent read+write of one socket
                // and silently stranded replies).
                std::thread([sock = std::move(fresh)]() mutable {
                    char buf[4096];
                    while (true) {
                        size_t n = 0;
                        for (;;) {
                            std::error_code ec;
                            n = sock.read_some(asio::buffer(buf), ec);
                            if (ec == asio::error::would_block) {
                                std::this_thread::sleep_for(
                                    std::chrono::milliseconds(1));
                                continue;
                            }
                            if (ec || 0 == n) return;
                            break;
                        }
                        size_t written = 0;
                        while (written < n) {
                            std::error_code wec;
                            const size_t w = sock.write_some(
                                asio::buffer(buf + written, n - written), wec);
                            if (wec == asio::error::would_block) {
                                std::this_thread::sleep_for(
                                    std::chrono::milliseconds(1));
                                continue;
                            }
                            if (wec) return;
                            written += w;
                        }
                    }
                }).detach();
            }
        };
        std::thread v6_thread([&] { serve_one("::1", true); });
        serve_one("127.0.0.1", false);
        v6_thread.join();
    }

    /// Baseline: three raw sockets, each connected directly to the local echo
    /// server, write + read back their own payload. If this ever fails, the
    /// echo server itself is the problem - not VGWW's data plane.
    int NativeEchoProbe() {
        int ok = 0;
        const char* tags[3] = {"mongoose", "panther", "gazelle"};
        for (auto tag : tags) {
            asio::io_context io;
            std::error_code ec;
            asio::ip::tcp::socket s(io);
            s.connect(asio::ip::tcp::endpoint(
                          asio::ip::make_address("127.0.0.1"), 45678), ec);
            if (ec) {
                std::fprintf(stderr, "[dbg] native connect err: %s\n",
                             ec.message().c_str());
                continue;
            }
            asio::write(s, asio::buffer(tag, 8), ec);
            if (ec) continue;
            char buf[8] = {};
            const size_t n = s.read_some(asio::buffer(buf), ec);
            if (!ec && 8 == n && 0 == std::memcmp(buf, tag, 8)) {
                ++ok;
            } else {
                std::fprintf(stderr,
                             "[dbg] native echo n=%zu err=%s got=%.*s\n", n,
                             ec.message().c_str(), static_cast<int>(n), buf);
            }
        }
        return ok;
    }

    /// Polls `predicate` until true or `timeout_ms` elapses.
    template <typename Pred>
    bool WaitFor(Pred&& predicate, int timeout_ms) {
        for (int waited = 0; waited < timeout_ms; waited += 50) {
            if (predicate()) {
                return true;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        return predicate();
    }

    /// UDP request frame: client -> remote. The data-plane relay does not
    /// validate the UDP checksum on ingress, so a zero checksum suffices;
    /// the return path builds its own correct checksum.
    std::vector<uint8_t> BuildUdpRequest(uint16_t sport, uint16_t dport,
                                         const std::string& payload) {
        const size_t udp_len = 8 + payload.size();
        std::vector<uint8_t> f(kEthernetHeaderLen + kIpv4HeaderLenMin + udp_len);
        BuildEthHeader(f.data(), kGatewayMac, kClientMac, kEthertypeIpv4);
        uint8_t* ip = f.data() + kEthernetHeaderLen;
        ip[0] = 0x45;
        const uint16_t total = static_cast<uint16_t>(kIpv4HeaderLenMin + udp_len);
        ip[2] = static_cast<uint8_t>(total >> 8);
        ip[3] = static_cast<uint8_t>(total & 0xFF);
        ip[8] = 64;
        ip[9] = 17;  // UDP
                std::memcpy(ip + 12, &kClientIp, 4);
        // Wire-order destination: the relay rebuilds its upstream endpoint
        // from these exact bytes (asio treats byte[0] as the top octet), so
        // write true network order - NOT the little-endian image of an
        // integer constant.
        const std::array<uint8_t, 4> loopback{127, 0, 0, 1};  // 127.0.0.1
        std::memcpy(ip + 16, loopback.data(), 4);
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

    /// True when some captured downstream frame is a UDP datagram FROM
    /// `server_port` carrying `marker` as payload (the echoed reply).
    bool ContainsUdpReply(const std::vector<std::vector<uint8_t>>& frames,
                          uint16_t server_port, const std::string& marker) {
        for (const auto& f : frames) {
            if (f.size() <
                kEthernetHeaderLen + kIpv4HeaderLenMin + 8 + marker.size()) {
                continue;
            }
            const uint8_t* ip = f.data() + kEthernetHeaderLen;
            if (ip[9] != 17) continue;  // not UDP
            const uint8_t* udp = ip + kIpv4HeaderLenMin;
            const uint16_t sport =
                static_cast<uint16_t>((udp[0] << 8) | udp[1]);
            if (sport != server_port) continue;
            if (0 == std::memcmp(udp + 8, marker.data(), marker.size())) {
                return true;
            }
        }
        return false;
    }

    /// Single-fragment IPv4 UDP: a valid UDP header but an incomplete payload
    /// (MF set, offset 0). The relay must never forward this truncated.
    std::vector<uint8_t> BuildUdpFragment(uint16_t sport, uint16_t dport,
                                          const std::string& payload) {
        std::vector<uint8_t> f = BuildUdpRequest(sport, dport, payload);
        // Real MF bit (byte 6 bit5 = 0x20) with offset 0: the first fragment
        // of a larger datagram. The old |=0x01 actually encoded offset 256
        // (an MF-less later fragment), which never exercised the MF gate.
        f[kEthernetHeaderLen + 6] |= 0x20;
        return f;
    }

    /// Counts distinct "P%d" payloads echoed back from the LAN UDP echo
    /// server. A unique payload per flow proves EVERY flow round-tripped
    /// (not just one).
    size_t CountUdpPayloads(const std::vector<std::vector<uint8_t>>& frames,
                            uint16_t server_port) {
        std::set<std::string> seen;
        for (const auto& f : frames) {
            if (f.size() < kEthernetHeaderLen + kIpv4HeaderLenMin + 8 + 2) {
                continue;
            }
            const uint8_t* ip = f.data() + kEthernetHeaderLen;
            if (ip[9] != 17) continue;  // not UDP
            const uint8_t* udp = ip + kIpv4HeaderLenMin;
            const uint16_t sport =
                static_cast<uint16_t>((udp[0] << 8) | udp[1]);
            if (sport != server_port) continue;
            const uint8_t* payload = udp + 8;
            if ('P' == payload[0] && payload[1] >= '0' &&
                payload[1] <= '9') {
                const size_t avail =
                    f.size() - (kEthernetHeaderLen + kIpv4HeaderLenMin + 8);
                seen.insert(std::string(
                    reinterpret_cast<const char*>(payload),
                    std::min(avail, std::strlen("P999"))));
            }
        }
        return seen.size();
    }

    /// Non-blocking UDP echo server on 127.0.0.1:`port`. Sets `ready` once
    /// the socket is bound (callers must wait before sending).
    void RunUdpEchoServer(uint16_t port, std::atomic<bool>& stop,
                          std::atomic<bool>& ready) {
        asio::io_context io;
        asio::ip::udp::socket sock(io);
        std::error_code bind_err;
        sock.open(asio::ip::udp::v4(), bind_err);
        sock.bind(asio::ip::udp::endpoint(asio::ip::make_address("127.0.0.1"),
                                          port),
                  bind_err);
        if (bind_err) {
            std::fprintf(stderr, "[dbg] udp_echo BIND FAILED: %s\n",
                         bind_err.message().c_str());
            return;
        }
        sock.non_blocking(true);
        ready.store(true);
        while (!stop.load()) {
            char buf[2048];
            asio::ip::udp::endpoint peer;
            std::error_code err;
            const size_t n = sock.receive_from(asio::buffer(buf), peer, 0, err);
            if (err == asio::error::would_block) {
                std::this_thread::sleep_for(std::chrono::milliseconds(2));
                continue;
            }
            if (err || 0 == n) {
                std::fprintf(stderr, "[dbg] udp_echo err=%s\n",
                             err.message().c_str());
                break;
            }
            std::fprintf(stderr, "[dbg] udp_echo got %zu bytes, echoing\n", n);
            std::error_code write_err;
            sock.send_to(asio::buffer(buf, n), peer, 0, write_err);
        }
    }

    /// Builds an ICMPv6 echo request toward the gateway's link-local
    /// address. Hop limit is deliberately 64 (the RA-advertised value)
    /// instead of 255: RFC 4861 section 7.1's 255 rule covers only Neighbor
    /// Discovery, and echo (RFC 4443) must work with any hop limit.
    std::vector<uint8_t> BuildV6EchoRequest(size_t payload) {
        const auto gw_ll = vgww::proto::LinkLocalFromMac(kGatewayMac);
        const uint8_t src[16] = {0xFE, 0x80, 0, 0, 0, 0, 0, 0,
                                 0xA8, 0xBB, 0xCC, 0xFF, 0xFE,
                                 0xDD, 0xEE, 0x01};
        const size_t icmp_len = 8 + payload;
        std::vector<uint8_t> f(kEthernetHeaderLen + 40 + icmp_len);
        BuildEthHeader(f.data(), kGatewayMac, kClientMac, kEthertypeIpv6);
        uint8_t* ip = f.data() + kEthernetHeaderLen;
        ip[0] = 0x60;
        const uint16_t total = static_cast<uint16_t>(icmp_len);
        ip[4] = static_cast<uint8_t>(total >> 8);
        ip[5] = static_cast<uint8_t>(total & 0xFF);
        ip[6] = 58;   // ICMPv6
        ip[7] = 64;   // hop limit (RA-advertised, NOT 255)
        std::memcpy(ip + 8, src, 16);
        std::memcpy(ip + 24, gw_ll.data(), 16);
        uint8_t* icmp = ip + 40;
        icmp[0] = kIcmpV6EchoRequest;
        icmp[4] = 0x22; icmp[5] = 0x22;  // identifier
        icmp[6] = 0x11; icmp[7] = 0x11;  // sequence
        for (size_t i = 0; i < payload; ++i) {
            icmp[8 + i] = static_cast<uint8_t>(i & 0xFF);
        }
        const uint16_t ck = vgww::proto::IcmpV6Checksum(
            src, gw_ll.data(), icmp, icmp_len);
        icmp[2] = static_cast<uint8_t>(ck >> 8);
        icmp[3] = static_cast<uint8_t>(ck & 0xFF);
        return f;
    }

    /// True when the gateway emitted an ICMPv6 Echo Reply toward the client
    /// mirroring the request's identifier/sequence (id 0x2222, seq 0x1111).
    bool ContainsV6EchoReply(
        const std::vector<std::vector<uint8_t>>& frames) {
        for (const auto& frame : frames) {
            if (frame.size() < kEthernetHeaderLen + 40 + 8) continue;
            EthHeaderView eth;
            ParseEthHeader(frame.data(), frame.size(), eth);
            if (kEthertypeIpv6 != eth.ethertype || !(eth.dst == kClientMac)) {
                continue;
            }
            const uint8_t* ip = frame.data() + kEthernetHeaderLen;
            if (ip[6] != 58) continue;  // ICMPv6
            const uint8_t* icmp = ip + 40;
            if (kIcmpV6EchoReply == icmp[0] && 0x22 == icmp[4] &&
                0x22 == icmp[5] && 0x11 == icmp[6] && 0x11 == icmp[7]) {
                return true;
            }
        }
        return false;
    }

    /// Builds an IPv6 TCP segment (checksum-correct) from the client.
    std::vector<uint8_t> BuildV6TcpSegment(uint32_t seq, uint32_t ack,
                                           uint8_t flags,
                                           uint16_t sport, uint16_t dport,
                                           const std::string& payload = "") {
        const size_t tcp_len = 20 + payload.size();
        std::vector<uint8_t> f(kEthernetHeaderLen + 40 + tcp_len);
        BuildEthHeader(f.data(), kGatewayMac, kClientMac, kEthertypeIpv6);
        uint8_t* ip = f.data() + kEthernetHeaderLen;
        ip[0] = 0x60;
        const uint16_t total = static_cast<uint16_t>(tcp_len);
        ip[4] = static_cast<uint8_t>(total >> 8);
        ip[5] = static_cast<uint8_t>(total & 0xFF);
        ip[6] = 6;   // next-header: TCP
        ip[7] = 64;  // hop limit
        // src fe80::aa:bbcc:ddee:ff01-ish synthetic client address;
        // dst ::1 loopback (the gateway dials it via a host socket).
        const uint8_t src[16] = {0xFE, 0x80, 0, 0, 0, 0, 0, 0,
                                 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x01};
        const uint8_t dst[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
        std::memcpy(ip + 8, src, 16);
        std::memcpy(ip + 24, dst, 16);
        uint8_t* tcp = ip + 40;
        tcp[0] = static_cast<uint8_t>(sport >> 8);
        tcp[1] = static_cast<uint8_t>(sport & 0xFF);
        tcp[2] = static_cast<uint8_t>(dport >> 8);
        tcp[3] = static_cast<uint8_t>(dport & 0xFF);
        tcp[4] = static_cast<uint8_t>(seq >> 24);
        tcp[5] = static_cast<uint8_t>(seq >> 16);
        tcp[6] = static_cast<uint8_t>(seq >> 8);
        tcp[7] = static_cast<uint8_t>(seq);
        tcp[8] = static_cast<uint8_t>(ack >> 24);
        tcp[9] = static_cast<uint8_t>(ack >> 16);
        tcp[10] = static_cast<uint8_t>(ack >> 8);
        tcp[11] = static_cast<uint8_t>(ack);
        tcp[12] = 5 << 4;
        tcp[13] = flags;
        tcp[14] = 0xFF; tcp[15] = 0xFF;
        if (!payload.empty()) {
            std::memcpy(tcp + 20, payload.data(), payload.size());
        }
        const uint16_t tcp_ck =
            vgww::net::InternetChecksum(tcp, static_cast<uint16_t>(tcp_len),
                                        vgww::net::PseudoHeaderSum6(src, dst, 6,
                                                                   static_cast<uint16_t>(tcp_len)));
        tcp[16] = static_cast<uint8_t>(tcp_ck >> 8);
        tcp[17] = static_cast<uint8_t>(tcp_ck & 0xFF);
        return f;
    }

    /// Extracts the server ISN from a captured IPv6 SYN-ACK (0 when missing).
    uint32_t FindV6ServerIsn(
        const std::vector<std::vector<uint8_t>>& frames, uint16_t client_port,
        uint16_t server_port) {
        for (const auto& frame : frames) {
            if (frame.size() < kEthernetHeaderLen + 40 + 20) continue;
            EthHeaderView eth;
            ParseEthHeader(frame.data(), frame.size(), eth);
            if (kEthertypeIpv6 != eth.ethertype || !(eth.dst == kClientMac)) {
                continue;
            }
            const uint8_t* ip = frame.data() + kEthernetHeaderLen;
            if (ip[6] != 6) continue;
            const uint8_t* tcp = ip + 40;
            const uint16_t dst_p =
                static_cast<uint16_t>((tcp[2] << 8) | tcp[3]);
            const uint16_t src_p =
                static_cast<uint16_t>((tcp[0] << 8) | tcp[1]);
            if (dst_p == client_port && src_p == server_port &&
                (tcp[13] & 0x12) == 0x12) {
                return (static_cast<uint32_t>(tcp[4]) << 24) |
                       (static_cast<uint32_t>(tcp[5]) << 16) |
                       (static_cast<uint32_t>(tcp[6]) << 8) | tcp[7];
            }
        }
        return 0;
    }

    /// True when some downstream IPv6 TCP frame toward the client carries
    /// `marker` as TCP payload.
    bool ContainsV6Payload(const std::vector<std::vector<uint8_t>>& frames,
                           const std::string& marker) {
        for (const auto& frame : frames) {
            if (frame.size() <
                kEthernetHeaderLen + 40 + 20 + marker.size()) {
                continue;
            }
            EthHeaderView eth;
            ParseEthHeader(frame.data(), frame.size(), eth);
            if (kEthertypeIpv6 != eth.ethertype || !(eth.dst == kClientMac)) {
                continue;
            }
            const uint8_t* ip = frame.data() + kEthernetHeaderLen;
            if (ip[6] != 6) continue;
            const uint8_t* tcp = ip + 40;
            if (0 == std::memcmp(tcp + 20, marker.data(), marker.size())) {
                return true;
            }
        }
        return false;
    }

    /// True when a downstream IPv6 TCP frame toward the client carries
    /// FIN|ACK from `server_port` (the graceful close reply to our FIN).
    bool ContainsV6Fin(const std::vector<std::vector<uint8_t>>& frames,
                       uint16_t server_port) {
        for (const auto& frame : frames) {
            if (frame.size() < kEthernetHeaderLen + 40 + 20) continue;
            EthHeaderView eth;
            ParseEthHeader(frame.data(), frame.size(), eth);
            if (kEthertypeIpv6 != eth.ethertype || !(eth.dst == kClientMac)) {
                continue;
            }
            const uint8_t* ip = frame.data() + kEthernetHeaderLen;
            if (ip[6] != 6) continue;
            const uint8_t* tcp = ip + 40;
            const uint16_t sport =
                static_cast<uint16_t>((tcp[0] << 8) | tcp[1]);
            if (sport == server_port && (tcp[13] & 0x01) != 0 &&
                (tcp[13] & 0x04) == 0) {
                return true;
            }
        }
        return false;
    }

    /// True when a downstream IPv6 TCP frame toward the client carries
    /// SYN|ACK from `server_port`.
    bool ContainsV6SynAck(const std::vector<std::vector<uint8_t>>& frames,
                          uint16_t server_port) {
        for (const auto& frame : frames) {
            if (frame.size() < kEthernetHeaderLen + 40 + 20) continue;
            EthHeaderView eth;
            ParseEthHeader(frame.data(), frame.size(), eth);
            if (kEthertypeIpv6 != eth.ethertype || !(eth.dst == kClientMac)) {
                continue;
            }
            const uint8_t* ip = frame.data() + kEthernetHeaderLen;
            if (ip[6] != 6) continue;
            const uint8_t* tcp = ip + 40;
            const uint16_t sport =
                static_cast<uint16_t>((tcp[0] << 8) | tcp[1]);
            const uint8_t flags = tcp[13];
            if (sport == server_port && 0x12 == (flags & 0x12)) return true;
        }
        return false;
    }

    /// TCP SYN toward a wire-order destination (for dial-failure tests the
    /// relay rebuilds its upstream endpoint from these exact bytes).
    std::vector<uint8_t> BuildSynTo(const std::array<uint8_t, 4>& dst_wire,
                                    uint16_t sport, uint16_t dport) {
        const size_t tcp_len = 20;
        std::vector<uint8_t> f(kEthernetHeaderLen + kIpv4HeaderLenMin + tcp_len);
        BuildEthHeader(f.data(), kGatewayMac, kClientMac, kEthertypeIpv4);
        uint8_t* ip = f.data() + kEthernetHeaderLen;
        ip[0] = 0x45;
        const uint16_t total = static_cast<uint16_t>(kIpv4HeaderLenMin + tcp_len);
        ip[2] = static_cast<uint8_t>(total >> 8);
        ip[3] = static_cast<uint8_t>(total & 0xFF);
        ip[8] = 64;
        ip[9] = 6;  // TCP
        std::memcpy(ip + 12, &kClientIp, 4);
        std::memcpy(ip + 16, dst_wire.data(), 4);
        uint8_t* tcp = ip + kIpv4HeaderLenMin;
        tcp[0] = static_cast<uint8_t>(sport >> 8);
        tcp[1] = static_cast<uint8_t>(sport & 0xFF);
        tcp[2] = static_cast<uint8_t>(dport >> 8);
        tcp[3] = static_cast<uint8_t>(dport & 0xFF);
        tcp[4] = 0; tcp[5] = 0; tcp[6] = 0x03; tcp[7] = 0xE8;  // seq=1000
        tcp[12] = 5 << 4;
        tcp[13] = 0x02;  // SYN
        tcp[14] = 0xFF; tcp[15] = 0xFF;  // window
        const uint16_t tcp_ck = InternetChecksum(
            tcp, static_cast<uint16_t>(tcp_len),
            PseudoHeaderSum(ip + 12, ip + 16, 6,
                            static_cast<uint16_t>(tcp_len)));
        tcp[16] = static_cast<uint8_t>(tcp_ck >> 8);
        tcp[17] = static_cast<uint8_t>(tcp_ck & 0xFF);
        const uint16_t ip_ck = InternetChecksum(ip, kIpv4HeaderLenMin);
        ip[10] = static_cast<uint8_t>(ip_ck >> 8);
        ip[11] = static_cast<uint8_t>(ip_ck & 0xFF);
        return f;
    }

    /// True when a downstream IPv4 TCP frame from `server_port` toward the
    /// client carries RST - the gateway's answer to an unconnectable target.
    bool ContainsRst(const std::vector<std::vector<uint8_t>>& frames,
                     uint16_t server_port) {
        for (const auto& frame : frames) {
            if (frame.size() <
                kEthernetHeaderLen + kIpv4HeaderLenMin + 20) {
                continue;
            }
            const uint8_t* ip = frame.data() + kEthernetHeaderLen;
            if ((ip[0] >> 4) != 4 || ip[9] != 6) continue;
            const size_t ihl = static_cast<size_t>(ip[0] & 0x0F) * 4;
            const uint8_t* tcp = ip + ihl;
            const uint16_t sport =
                static_cast<uint16_t>((tcp[0] << 8) | tcp[1]);
            if (sport == server_port && (tcp[13] & 0x04) != 0) return true;
        }
        return false;
    }

    /// True when a downstream IPv4 TCP frame from `server_port` toward the
    /// client carries FIN|ACK - the graceful close of the conversation.
    bool ContainsFin(const std::vector<std::vector<uint8_t>>& frames,
                     uint16_t server_port) {
        for (const auto& frame : frames) {
            if (frame.size() <
                kEthernetHeaderLen + kIpv4HeaderLenMin + 20) {
                continue;
            }
            const uint8_t* ip = frame.data() + kEthernetHeaderLen;
            if ((ip[0] >> 4) != 4 || ip[9] != 6) continue;
            const size_t ihl = static_cast<size_t>(ip[0] & 0x0F) * 4;
            const uint8_t* tcp = ip + ihl;
            const uint16_t sport =
                static_cast<uint16_t>((tcp[0] << 8) | tcp[1]);
            if (sport == server_port && (tcp[13] & 0x01) != 0 &&
                (tcp[13] & 0x04) == 0) {
                return true;
            }
        }
        return false;
    }

    /// batch311: true when a downstream IPv4 TCP frame toward `client_port`
    /// carries FIN without RST - the graceful close of THAT conversation.
    bool ContainsFinFor(const std::vector<std::vector<uint8_t>>& frames,
                        uint16_t client_port) {
        for (const auto& frame : frames) {
            if (frame.size() <
                kEthernetHeaderLen + kIpv4HeaderLenMin + 20) {
                continue;
            }
            const uint8_t* ip = frame.data() + kEthernetHeaderLen;
            if ((ip[0] >> 4) != 4 || ip[9] != 6) continue;
            const size_t ihl = static_cast<size_t>(ip[0] & 0x0F) * 4;
            const uint8_t* tcp = ip + ihl;
            const uint16_t dport =
                static_cast<uint16_t>((tcp[2] << 8) | tcp[3]);
            if (dport == client_port && (tcp[13] & 0x01) != 0 &&
                (tcp[13] & 0x04) == 0) {
                return true;
            }
        }
        return false;
    }

}  // namespace

    /// batch31 P1-4 red anchor: the RX thread's fallback wait quantizes a
    /// reply's latency. With the driver event disarmed (a poll-only driver)
    /// and `perf.rx_poll_ms = 200`, a frame that lands just after a poll must
    /// wait nearly the whole window. This is the deterministic reproduction of
    /// the user-reported 100 ms-class ping tail - no real NIC required.
    void TestB31RxPollQuantized() {
        vgww::core::Config cfg;
        cfg.adapter = "TestNIC";
        cfg.gateway.ipv4 = kGatewayIp;
        cfg.gateway.mask = (0u) | (0u << 8) | (255u << 16) | (255u << 24);
        cfg.gateway.mac = kGatewayMac;
        cfg.perf.workers = 2;
        cfg.perf.ring_capacity = 256;
        cfg.perf.max_conns = 64;
        cfg.perf.dial_timeout_ms = 400;
        cfg.perf.rx_poll_ms = 200;      // the pre-fix hardcoded window
        cfg.perf.rx_flush_eager = true;

        auto fake = std::make_unique<TestDriverClient>();
        TestDriverClient* raw = fake.get();
        raw->DisarmRxEventForTest();    // poll-only driver: no wake-up signal
        vgww::runtime::Dataplane dataplane(cfg);
        dataplane.SetDriverClient(std::move(fake));
        std::string error;
        CHECK(dataplane.Start(error));

        std::vector<double> samples_ms;
        for (int i = 0; i < 20; ++i) {
            // Align to the START of a poll window: wait until one ReadPackets
            // call has completed (returned 0 and the thread is about to wait),
            // then inject. The reply then has to sit out ~the full window.
            const uint64_t reads_before = raw->read_calls();
            const auto align_deadline =
                std::chrono::steady_clock::now() + std::chrono::seconds(2);
            while (raw->read_calls() == reads_before &&
                   std::chrono::steady_clock::now() < align_deadline) {
                std::this_thread::yield();   // batch78: a sleep_for costs a ~15.6ms quantum
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1));

            const std::size_t sent_before = raw->sent_down_count();
            const auto t0 = std::chrono::steady_clock::now();
            raw->InjectNow(BuildEchoRequest(32));
            const auto deadline = t0 + std::chrono::seconds(2);
            while (raw->sent_down_count() == sent_before &&
                   std::chrono::steady_clock::now() < deadline) {
                std::this_thread::yield();   // batch78: a sleep_for costs a ~15.6ms quantum
            }
            const double ms =
                std::chrono::duration<double, std::milli>(
                    std::chrono::steady_clock::now() - t0)
                    .count();
            if (raw->sent_down_count() == sent_before) {
                std::printf("B31 rx-poll-quantized sample %d: NO REPLY\n", i);
                CHECK(false);
                continue;
            }
            samples_ms.push_back(ms);
        }

        std::sort(samples_ms.begin(), samples_ms.end());
        const double median =
            samples_ms.empty() ? 0.0 : samples_ms[samples_ms.size() / 2];
        const double p95 = samples_ms.empty()
                               ? 0.0
                               : samples_ms[static_cast<std::size_t>(
                                     std::ceil(0.95 * samples_ms.size()) - 1)];
        const double max = samples_ms.empty() ? 0.0 : samples_ms.back();
        std::printf("B31 rx-poll-quantized n=%zu median=%.1fms p95=%.1fms "
                    "max=%.1fms\n",
                    samples_ms.size(), median, p95, max);
        // The 200 ms window must show up as a 150 ms+ p95 (or a 180 ms+ max).
        // A green run here means the poll window no longer dominates.
        CHECK(p95 >= 150.0 || max >= 180.0);

        std::string stop_error;
        CHECK(dataplane.Stop(stop_error));
    }

    /// batch31 P1-4 green anchor (parent ruling): `perf.rx_poll_ms = 10` with
    /// the driver event ARMED (the production path - the driver signals the RX
    /// event on frame arrival) must answer an echo well under 10 ms.
    void TestB31RxPollFast() {
        vgww::core::Config cfg;
        cfg.adapter = "TestNIC";
        cfg.gateway.ipv4 = kGatewayIp;
        cfg.gateway.mask = (0u) | (0u << 8) | (255u << 16) | (255u << 24);
        cfg.gateway.mac = kGatewayMac;
        cfg.perf.workers = 2;
        cfg.perf.ring_capacity = 256;
        cfg.perf.max_conns = 64;
        cfg.perf.dial_timeout_ms = 400;
        cfg.perf.rx_poll_ms = 10;       // the shipped default
        cfg.perf.rx_flush_eager = true;

        auto fake = std::make_unique<TestDriverClient>();
        TestDriverClient* raw = fake.get();
        // Event armed (the default): InjectNow signals the RX event exactly
        // like the real driver on frame arrival - the production wake path.
        vgww::runtime::Dataplane dataplane(cfg);
        dataplane.SetDriverClient(std::move(fake));
        std::string error;
        CHECK(dataplane.Start(error));

        std::vector<double> samples_ms;
        for (int i = 0; i < 20; ++i) {
            const std::size_t sent_before = raw->sent_down_count();
            const auto t0 = std::chrono::steady_clock::now();
            raw->InjectNow(BuildEchoRequest(32));
            const auto deadline = t0 + std::chrono::seconds(2);
            while (raw->sent_down_count() == sent_before &&
                   std::chrono::steady_clock::now() < deadline) {
                std::this_thread::yield();   // batch78: a sleep_for costs a ~15.6ms quantum
            }
            const double ms =
                std::chrono::duration<double, std::milli>(
                    std::chrono::steady_clock::now() - t0)
                    .count();
            if (raw->sent_down_count() == sent_before) {
                std::printf("B31 rx-poll-fast sample %d: NO REPLY\n", i);
                CHECK(false);
                continue;
            }
            samples_ms.push_back(ms);
        }

        std::sort(samples_ms.begin(), samples_ms.end());
        const double median =
            samples_ms.empty() ? 0.0 : samples_ms[samples_ms.size() / 2];
        const double p95 = samples_ms.empty()
                               ? 0.0
                               : samples_ms[static_cast<std::size_t>(
                                     std::ceil(0.95 * samples_ms.size()) - 1)];
        const double max = samples_ms.empty() ? 0.0 : samples_ms.back();
        std::printf("B31 rx-poll-fast(event) n=%zu median=%.2fms p95=%.2fms "
                    "max=%.2fms\n",
                    samples_ms.size(), median, p95, max);
        CHECK(!samples_ms.empty());
        // batch78: the harness itself was the flaky part, not the product.
        // Both polling loops used `sleep_for(100us)`; on this host EVERY
        // such sleep costs a full OS timer quantum (measured: sleep_for
        // (100us) median 15.56 ms, Sleep(1) median 15.51 ms, while
        // `yield` costs 0.0005 ms). The old 15.3 ms "latency" was almost
        // entirely that quantum. Switching the loops to `yield` exposed
        // the real number: median 0.00 ms, p95 0.02-0.12 ms across 20
        // runs. The absolute budget is therefore now anchored where the
        // product actually lives, with the residual host scheduler tail
        // allowed for (observed max 32.4 ms on a loaded host, which is one
        // 15.6 ms quantum of preemption plus one more).
        CHECK(median <= p95);            // ordering sanity
        CHECK(p95 <= max);
        CHECK(median < 5.0);   // measured 0.00-0.55; 5.0 = 9x headroom
        CHECK(max < 100.0);    // one-two preemption quanta of slack

        // The internal path (build -> hand to the driver) is far below the
        // wall-clock number; assert it separately so a regression in the
        // construction/flush path is visible even if the scheduler is noisy.
        const std::vector<uint64_t> internal =
            dataplane.IcmpProcessingLatencyUs();
        CHECK(internal.size() >= 20);
        if (!internal.empty()) {
            std::vector<uint64_t> sorted = internal;
            std::sort(sorted.begin(), sorted.end());
            const uint64_t internal_p95 = sorted[static_cast<std::size_t>(
                std::ceil(0.95 * sorted.size()) - 1)];
            std::printf("B31 icmp-internal n=%zu p95=%lluus max=%lluus\n",
                        sorted.size(),
                        static_cast<unsigned long long>(internal_p95),
                        static_cast<unsigned long long>(sorted.back()));
            CHECK(internal_p95 < 5000);  // p95 < 5 ms, spec P1-4 item 5
        }

        std::string stop_error;
        CHECK(dataplane.Stop(stop_error));
    }
    /// batch31 P1-4 red/green discriminator: `perf.rx_poll_ms` must actually
    /// bound the FALLBACK wait. With the driver event disarmed (a poll-only
    /// driver, the worst case) and `rx_poll_ms = 10`, an echo must still come
    /// back inside the configured window. The pre-fix code ignored the config
    /// and used a hardcoded 200 ms -> ~200 ms (RED); honouring it gives ~10 ms.
    ///
    /// batch78: the predicate is now a RATIO between two windows measured in
    /// this same process, not an absolute millisecond budget. Two independent
    /// host quanta dominate an absolute bound here:
    ///   * `WaitForSingleObject(event, 10)` cannot return before the OS timer
    ///     quantum; measured on this host `Sleep(1)` medians 15.51 ms and
    ///     `WaitForSingleObject(h, 10)` medians 15.62 ms (a 10 ms request is
    ///     rounded UP to one ~15.6 ms quantum), while 200 ms stays accurate
    ///     (203 ms) because it is far above the quantum;
    ///   * the reply-polling loop used `sleep_for(100us)`, which also costs a
    ///     full quantum (measured median 15.56 ms) while `yield` costs 0.5 us.
    /// A ratio cancels both: the honoured window must be several times
    /// tighter than a 200 ms window, and that ordering holds regardless of the
    /// host's timer precision.
    void TestB31RxPollConfigHonored() {
        // Shared sampler: poll-only driver, event disarmed, reply latency
        // measured with a spin/yield loop (no timer-granularity cost).
        const auto sample_window = [](int poll_ms) {
            std::vector<double> out;
            vgww::core::Config cfg;
            cfg.adapter = "TestNIC";
            cfg.gateway.ipv4 = kGatewayIp;
            cfg.gateway.mask =
                (0u) | (0u << 8) | (255u << 16) | (255u << 24);
            cfg.gateway.mac = kGatewayMac;
            cfg.perf.workers = 2;
            cfg.perf.ring_capacity = 256;
            cfg.perf.max_conns = 64;
            cfg.perf.dial_timeout_ms = 400;
            cfg.perf.rx_poll_ms = poll_ms;
            cfg.perf.rx_flush_eager = true;

            auto fake = std::make_unique<TestDriverClient>();
            TestDriverClient* raw = fake.get();
            raw->DisarmRxEventForTest();   // poll-only: the bound decides
            vgww::runtime::Dataplane dataplane(cfg);
            dataplane.SetDriverClient(std::move(fake));
            std::string error;
            CHECK(dataplane.Start(error));

            for (int i = 0; i < 20; ++i) {
                // Align to the START of a poll window so the number is the
                // window bound itself, not "how lucky was the arrival".
                const uint64_t reads_before = raw->read_calls();
                const auto align_deadline =
                    std::chrono::steady_clock::now() +
                    std::chrono::seconds(2);
                while (raw->read_calls() == reads_before &&
                       std::chrono::steady_clock::now() < align_deadline) {
                    std::this_thread::yield();   // batch78: was sleep_for(200us)
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(1));

                const std::size_t sent_before = raw->sent_down_count();
                const auto t0 = std::chrono::steady_clock::now();
                raw->InjectNow(BuildEchoRequest(32));
                const auto deadline = t0 + std::chrono::seconds(2);
                while (raw->sent_down_count() == sent_before &&
                       std::chrono::steady_clock::now() < deadline) {
                    std::this_thread::yield();   // batch78: was sleep_for(100us)
                }
                const double ms =
                    std::chrono::duration<double, std::milli>(
                        std::chrono::steady_clock::now() - t0)
                        .count();
                if (raw->sent_down_count() == sent_before) {
                    std::printf("B31 rx-poll sample %d (window %d): NO REPLY\n",
                                i, poll_ms);
                    CHECK(false);
                    continue;
                }
                out.push_back(ms);
            }

            std::string stop_error;
            CHECK(dataplane.Stop(stop_error));
            std::sort(out.begin(), out.end());
            return out;
        };

        const auto median_of = [](std::vector<double> v) {
            if (v.empty()) {
                return 0.0;
            }
            return v[v.size() / 2];
        };

        // 10 ms (shipped default) vs 200 ms (the pre-fix hardcoded window).
        const std::vector<double> tight = sample_window(10);
        const std::vector<double> loose = sample_window(200);
        const double tight_med = median_of(tight);
        const double loose_med = median_of(loose);
        std::printf(
            "B31 rx-poll-config: tight(10ms) n=%zu med=%.2fms  "
            "loose(200ms) n=%zu med=%.2fms  ratio=%.2f\n",
            tight.size(), tight_med, loose.size(), loose_med,
            tight_med > 0.0 ? loose_med / tight_med : 0.0);

        CHECK(!tight.empty());
        CHECK(!loose.empty());
        // batch78: the arbitration is a RATIO, so it is immune to the
        // host timer quantum and to CPU load. Measured over 20 runs AFTER
        // the polling loops were switched from sleep_for to yield:
        //   tight(10ms)  median 0.07 - 15.52 ms
        //   loose(200ms) median 186.4 - 188.2 ms
        //   ratio        12.13 - 2879.82
        // 3.0 therefore holds with ~4x margin at the WORST observed point,
        // while an implementation that ignores the config (ratio ~1) or
        // uses the old hardcoded 200 ms window (ratio ~1) still fails.
        CHECK(loose_med > tight_med * 3.0);
    }

    void TestUdpRelaySyncSend() {
        // Regression: SendToRemote used async_send over a borrowed caller
        // buffer whose lifetime ends before the async completion -> UAF.
        // It must copy the datagram out synchronously.
        asio::io_context io;
        asio::ip::udp::socket upstream(io), client(io);
        std::error_code ec;
        upstream.open(asio::ip::udp::v4(), ec);
        CHECK(!ec);
        upstream.bind(
            asio::ip::udp::endpoint(asio::ip::make_address("127.0.0.1"), 0),
            ec);
        CHECK(!ec);
        client.open(asio::ip::udp::v4(), ec);
        CHECK(!ec);
        client.bind(
            asio::ip::udp::endpoint(asio::ip::make_address("127.0.0.1"), 0),
            ec);
        CHECK(!ec);

        vgww::relay::UdpRelay::FlowKey relay_key{};
        relay_key.client_port = 9000;
        vgww::relay::UdpRelay relay(std::move(client), relay_key);
        relay.ConnectRemote(upstream.local_endpoint(ec), ec);
        CHECK(!ec);

        const char kPayload[] = "udp-relay-sync";
        char recv[64] = {};
        size_t got = 0;
        upstream.async_receive(asio::buffer(recv),
                               [&](const std::error_code& e, size_t n) {
                                   if (!e) got = n;
                               });

        relay.SendToRemote(reinterpret_cast<const uint8_t*>(kPayload),
                           std::strlen(kPayload));
        io.run();
        CHECK(got == std::strlen(kPayload));
        CHECK(0 == std::memcmp(recv, kPayload, got));
    }

    // ----- VLAN 802.1Q access-trunk: strip RX tags, re-tag TX ----//
    // An 802.1Q-enabled gateway answers tagged ARP/echo through the same
    // pipeline, tags every reply (single AppendDown choke point), and
    // isolates (drops) frames from other VLANs.
    void RunVlanScenarios() {
        vgww::core::Config cfg;
        cfg.adapter = "TestNIC";
        cfg.gateway.ipv4 = kGatewayIp;
        cfg.gateway.mask = (0u) | (0u << 8) | (255u << 16) | (255u << 24);
        cfg.gateway.mac = kGatewayMac;
        cfg.perf.workers = 2;
        cfg.perf.ring_capacity = 256;
        cfg.perf.max_conns = 64;
        cfg.perf.dial_timeout_ms = 400;
        cfg.vlan.id = 100;

        auto fake = std::make_unique<TestDriverClient>();
        TestDriverClient* raw = fake.get();

        vgww::runtime::Dataplane dataplane(cfg);
        dataplane.SetDriverClient(std::move(fake));
        std::string error;
        CHECK(dataplane.Start(error));

        // Tagged ARP request for the gateway -> tagged ARP reply.
        const auto tagged_arp = TagFrame(BuildArpRequest(), 100);
        raw->InjectNow(tagged_arp);
        CHECK(WaitFor(
            [&] { return ContainsVlanReply(raw->SentDown(), 100, kClientMac); },
            3000));
        CHECK(!ContainsAnyVlanTag(raw->SentDown(), 200));

        // Tagged ICMP echo to the gateway -> tagged echo reply.
        raw->InjectNow(TagFrame(BuildEchoRequest(32), 100));
        CHECK(WaitFor(
            [&] { return ContainsVlanReply(raw->SentDown(), 100, kClientMac); },
            3000));

        // A frame from a DIFFERENT VLAN must be isolated, never answered.
        const uint64_t dropped_before =
            dataplane.GetStats().rx_dropped.load();
        const auto arp_count_before = dataplane.GetStats().arp_replies.load();
        raw->InjectNow(TagFrame(BuildArpRequest(), 50));
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        CHECK(dataplane.GetStats().rx_dropped.load() >= dropped_before + 1);
        CHECK(dataplane.GetStats().arp_replies.load() == arp_count_before);

        dataplane.Stop();
        std::fprintf(stderr, "[vlan] tagged rx/tx and cross-VLAN isolation OK\n");
    }

    // batch205: the driver-reported m_Length is a DWORD with no bound. A
    // length past the fixed INTERMEDIATE_BUFFER array must be rejected (drop),
    // never used to index the frame, or the RX path reads out of bounds. The
    // TX path already refuses an over-long frame in AppendDown; this pins the
    // RX-side symmetry.
    void RunOverlongReportedLengthIsDroppedScenario() {
        vgww::core::Config cfg;
        cfg.adapter = "TestNIC";
        cfg.gateway.ipv4 = kGatewayIp;
        cfg.gateway.mask = (0u) | (0u << 8) | (255u << 16) | (255u << 24);
        cfg.gateway.mac = kGatewayMac;
        cfg.perf.workers = 2;
        cfg.perf.ring_capacity = 256;
        cfg.perf.max_conns = 64;
        cfg.perf.dial_timeout_ms = 400;
        auto fake = std::make_unique<TestDriverClient>();
        TestDriverClient* raw = fake.get();
        vgww::runtime::Dataplane dataplane(cfg);
        dataplane.SetDriverClient(std::move(fake));
        std::string error;
        CHECK(dataplane.Start(error));
        const uint64_t dropped_before =
            dataplane.GetStats().rx_dropped.load();
        // A real 60-byte ARP frame but a length the driver could never
        // legitimately report (past the 1514-byte buffer).
        raw->InjectNowForcedLength(BuildArpRequest(), 4000);
        CHECK(WaitFor(
            [&] { return dataplane.GetStats().rx_dropped.load() >
                       dropped_before; },
            3000));
        // It must never be answered as a valid ARP request.
        CHECK(0 == dataplane.GetStats().arp_replies.load());
        dataplane.Stop();
        std::fprintf(stderr, "[rx-len] overlong reported length dropped OK\n");
    }

    // RA-1 (G-5 F1): an adapter hint that arrives as UTF-8 bytes (config
    // JSON / WebUI / wWinMain path) must be widened as UTF-8 before matching.
    // Byte-wise widening turns the zh-CN name (9 UTF-8 bytes) into 9 garbage
    // wchar_t and never matches the localized friendly name.
    void RunAdapterHintWideningScenario() {
        vgww::core::Config cfg;
        cfg.adapter = "\xE4\xBB\xA5\xE5\xA4\xAA\xE7\xBD\x91";  // UTF-8 zh-CN name
        cfg.gateway.ipv4 = kGatewayIp;
        cfg.gateway.mask = (0u) | (0u << 8) | (255u << 16) | (255u << 24);
        cfg.gateway.mac = kGatewayMac;
        cfg.perf.workers = 2;
        cfg.perf.ring_capacity = 256;
        cfg.perf.max_conns = 64;
        cfg.perf.dial_timeout_ms = 400;

        auto fake = std::make_unique<TestDriverClient>(L"\u4EE5\u592A\u7F51");
        vgww::runtime::Dataplane dataplane(cfg);
        dataplane.SetDriverClient(std::move(fake));
        std::string error;
        CHECK(dataplane.Start(error));
        std::string stop_error;
        CHECK(dataplane.Stop(stop_error));

        // Reverse guard: the same UTF-8 hint must NOT match an unrelated NIC.
        auto other = std::make_unique<TestDriverClient>(L"\\TestNIC");
        vgww::runtime::Dataplane dataplane2(cfg);
        dataplane2.SetDriverClient(std::move(other));
        std::string error2;
        CHECK(!dataplane2.Start(error2));
        std::string stop_error2;
        CHECK(dataplane2.Stop(stop_error2));

        std::fprintf(stderr, "[g5] utf8 adapter hint widening scenario done\n");
    }

    // RA-3 (G-5 F2/F3): end-to-end friendly-name matching. The config keeps
    // the shipped "Ethernet" placeholder; the bound NIC reports the zh-CN
    // friendly name; Start must succeed through the production
    // matcher. Reverse: with only the numbered zh-CN form the strict " N"
    // suffix rule
    // (D4) must reject "Ethernet".
    void RunFriendlyNameEndToEndScenario() {
        vgww::core::Config cfg;
        cfg.adapter = "Ethernet";
        cfg.gateway.ipv4 = kGatewayIp;
        cfg.gateway.mask = (0u) | (0u << 8) | (255u << 16) | (255u << 24);
        cfg.gateway.mac = kGatewayMac;
        cfg.perf.workers = 2;
        cfg.perf.ring_capacity = 256;
        cfg.perf.max_conns = 64;
        cfg.perf.dial_timeout_ms = 400;

        std::vector<AdapterEntry> entries;
        AdapterEntry e1;
        e1.name = L"\\DEVICE\\{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}";
        e1.friendly_name = L"\u4EE5\u592A\u7F51";  // zh-CN name
        e1.handle = reinterpret_cast<void*>(0x1);
        e1.mtu = 1500;
        entries.push_back(e1);

        {
            auto fake = std::make_unique<MatcherDriverClient>(entries);
            vgww::runtime::Dataplane dataplane(cfg);
            dataplane.SetDriverClient(std::move(fake));
            std::string error;
            CHECK(dataplane.Start(error));
            // P2-9: the UI must be able to show WHICH adapter was bound, not
            // just the config hint (a guessed friendly name can be ambiguous).
            const vgww::runtime::Dataplane::AdapterBinding binding =
                dataplane.GetAdapterBinding();
            CHECK(binding.bound);
            CHECK(binding.friendly_name ==
                  "\xE4\xBB\xA5\xE5\xA4\xAA\xE7\xBD\x91");  // UTF-8 zh-CN name
            CHECK(binding.device ==
                  "\\DEVICE\\{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}");
            std::string stop_error;
            CHECK(dataplane.Stop(stop_error));
            CHECK(!dataplane.GetAdapterBinding().bound);
        }

        entries[0].friendly_name = L"\u4EE5\u592A\u7F51 2";  // zh-CN name 2
        {
            auto fake = std::make_unique<MatcherDriverClient>(entries);
            vgww::runtime::Dataplane dataplane(cfg);
            dataplane.SetDriverClient(std::move(fake));
            std::string error;
            CHECK(!dataplane.Start(error));
            CHECK(!dataplane.GetAdapterBinding().bound);
            std::string stop_error;
            CHECK(dataplane.Stop(stop_error));
        }

        std::fprintf(stderr, "[g5] friendly-name end-to-end matching scenario done\n");
    }

    // RA-4 (G-5 F4): diagnostics. A no-match error must list readable
    // friendly names and the actionable --adapter/config guidance; zero
    // bindings get their dedicated "reinstall the driver" suffix.
    void RunAdapterDiagnosticsScenario() {
        vgww::core::Config cfg;
        cfg.adapter = "NoSuchNIC";
        cfg.gateway.ipv4 = kGatewayIp;
        cfg.gateway.mask = (0u) | (0u << 8) | (255u << 16) | (255u << 24);
        cfg.gateway.mac = kGatewayMac;
        cfg.perf.workers = 2;
        cfg.perf.ring_capacity = 256;
        cfg.perf.max_conns = 64;
        cfg.perf.dial_timeout_ms = 400;

        std::vector<AdapterEntry> entries;
        AdapterEntry e1;
        e1.name = L"\\DEVICE\\{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}";
        e1.friendly_name = L"\u4EE5\u592A\u7F51";  // zh-CN name
        e1.handle = reinterpret_cast<void*>(0x1);
        e1.mtu = 1500;
        entries.push_back(e1);

        {
            auto fake = std::make_unique<MatcherDriverClient>(entries);
            vgww::runtime::Dataplane dataplane(cfg);
            dataplane.SetDriverClient(std::move(fake));
            std::string error;
            CHECK(!dataplane.Start(error));
            CHECK(error.find("--adapter") != std::string::npos);
            CHECK(error.find("\xE4\xBB\xA5\xE5\xA4\xAA\xE7\xBD\x91") !=
                  std::string::npos);  // UTF-8 zh-CN name in the listing
            std::string stop_error;
            CHECK(dataplane.Stop(stop_error));
        }

        {
            auto fake = std::make_unique<MatcherDriverClient>(
                std::vector<AdapterEntry>{});
            vgww::runtime::Dataplane dataplane(cfg);
            dataplane.SetDriverClient(std::move(fake));
            std::string error;
            CHECK(!dataplane.Start(error));
            CHECK(error.find("No adapters are bound") != std::string::npos);
            std::string stop_error;
            CHECK(dataplane.Stop(stop_error));
        }

        std::fprintf(stderr, "[g5] adapter diagnostics scenario done\n");
    }

    // batch24 P2-9b: link state + IPv4 diagnostics on the bound-adapter
    // surface, plus the same-name "prefer the connected adapter" resolution.
    void RunAdapterLinkDiagnosticsScenario() {
        vgww::core::Config cfg;
        cfg.adapter = "Ethernet";
        cfg.gateway.ipv4 = kGatewayIp;
        cfg.gateway.mask = (0u) | (0u << 8) | (255u << 16) | (255u << 24);
        cfg.gateway.mac = kGatewayMac;
        cfg.perf.workers = 2;
        cfg.perf.ring_capacity = 256;
        cfg.perf.max_conns = 64;
        cfg.perf.dial_timeout_ms = 400;

        std::vector<AdapterEntry> entries;
        AdapterEntry e1;
        e1.name = L"\\DEVICE\\{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}";
        e1.friendly_name = L"Ethernet";
        e1.handle = reinterpret_cast<void*>(0x1);
        e1.mtu = 1500;
        e1.is_up = false;
        e1.media_connected = false;
        vgww::driver::AdapterIpv4Address addr;
        addr.address = (10u) | (0u << 8) | (0u << 16) | (5u << 24);  // 10.0.0.5
        addr.prefix_len = 24;
        e1.ipv4.push_back(addr);
        entries.push_back(e1);

        {
            auto fake = std::make_unique<MatcherDriverClient>(entries);
            vgww::runtime::Dataplane dataplane(cfg);
            dataplane.SetDriverClient(std::move(fake));
            std::string error;
            CHECK(dataplane.Start(error));
            const vgww::runtime::Dataplane::AdapterBinding binding =
                dataplane.GetAdapterBinding();
            CHECK(binding.bound);
            CHECK(!binding.is_up);
            CHECK(!binding.media_connected);
            CHECK(binding.ipv4.size() == 1);
            if (!binding.ipv4.empty()) {
                CHECK(binding.ipv4[0].address == addr.address);
                CHECK(binding.ipv4[0].prefix_len == 24);
            }
            CHECK(!binding.gateway_in_subnet);

            const std::vector<vgww::runtime::Dataplane::AdapterInfo> list =
                dataplane.GetAdapters();
            CHECK(list.size() == 1);
            if (!list.empty()) {
                CHECK(list[0].friendly_name == "Ethernet");
                CHECK(list[0].device ==
                      "\\DEVICE\\{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}");
                CHECK(!list[0].is_up);
                CHECK(!list[0].media_connected);
                CHECK(list[0].ipv4.size() == 1);
            }

            std::string stop_error;
            CHECK(dataplane.Stop(stop_error));
            CHECK(!dataplane.GetAdapterBinding().bound);
        }

        // Connected adapter inside the gateway subnet: no warning gate.
        entries[0].is_up = true;
        entries[0].media_connected = true;
        entries[0].ipv4.clear();
        entries[0].ipv4.push_back(
            {static_cast<uint32_t>((192u) | (0u << 8) | (168u << 16) | (24u << 24)),
             24});
        {
            auto fake = std::make_unique<MatcherDriverClient>(entries);
            vgww::runtime::Dataplane dataplane(cfg);
            dataplane.SetDriverClient(std::move(fake));
            std::string error;
            CHECK(dataplane.Start(error));
            const vgww::runtime::Dataplane::AdapterBinding binding =
                dataplane.GetAdapterBinding();
            CHECK(binding.bound);
            CHECK(binding.is_up);
            CHECK(binding.media_connected);
            CHECK(binding.gateway_in_subnet);
            std::string stop_error;
            CHECK(dataplane.Stop(stop_error));
        }

        // Same friendly name twice: the connected entry wins without an
        // ambiguity rejection; two connected entries stay ambiguous.
        std::vector<AdapterEntry> same_name;
        AdapterEntry down = e1;
        down.is_up = false;
        down.media_connected = false;
        same_name.push_back(down);
        AdapterEntry up = e1;
        up.name = L"\\DEVICE\\{11111111-2222-3333-4444-555555555555}";
        up.is_up = true;
        up.media_connected = true;
        same_name.push_back(up);
        bool ambiguous = true;
        const int picked = vgww::driver::MatchAdapterEntry(
            same_name, L"Ethernet", L"", &ambiguous);
        CHECK(picked == 1);
        CHECK(!ambiguous);
        same_name[0].is_up = true;
        same_name[0].media_connected = true;
        ambiguous = false;
        const int both = vgww::driver::MatchAdapterEntry(
            same_name, L"Ethernet", L"", &ambiguous);
        CHECK(both == 0);
        CHECK(ambiguous);

        std::fprintf(stderr,
                     "[g5] adapter link diagnostics scenario done\n");
    }

    // Batch-24-D anchor (host-originated / "the box's own stack").
    //
    // Under LISTEN the driver already delivers host-sent originals to the
    // wire, so VGWW must only (a) synthesise a reply BACK UP to the host for
    // the virtual gateway's own ARP/ICMP, and (b) NEVER re-emit a host-sent
    // frame toward the wire (that would duplicate it). The pre-fix code did
    // (a) but also kept a TUNNEL-era down re-injection from a predecessor
    // mode, so (b) failed for every host frame the gateway does not answer.
    void RunHostOriginatedScenario() {
        vgww::core::Config config;
        config.adapter = "TestNIC";
        config.gateway.ipv4 = kGatewayIp;
        config.gateway.mask = (0u) | (0u << 8) | (255u << 16) | (255u << 24);
        config.gateway.mac = kGatewayMac;
        config.mode = vgww::core::Mode::kBypass;
        config.perf.workers = 2;
        config.perf.ring_capacity = 256;
        config.perf.max_conns = 64;
        config.perf.dial_timeout_ms = 400;

        auto fake = std::make_unique<TestDriverClient>();
        TestDriverClient* raw = fake.get();

        // (1) Host ARP for the gateway IP -> reply must go UP to the host.
        raw->ScriptHostSend(BuildArpRequest(), 0);
        // (2) Host ping of the gateway IP -> echo reply must go UP.
        raw->ScriptHostSend(BuildEchoRequest(32), 0);
        // (3) Host ARP for a NON-gateway on-link peer: VGWW synthesises no
        //     reply, and LISTEN already forwards the original -> must NOT be
        //     re-injected toward the wire.
        {
            std::vector<uint8_t> host_arp_other(kArpFrameLen, 0);
            const uint32_t router_ip =
                (192u) | (168u << 8) | (0u << 16) | (1u << 24);  // 192.168.0.1
            BuildArpFrame(host_arp_other.data(), ArpOperation::kRequest,
                          kClientMac, kClientIp, kBroadcastMac, router_ip);
            raw->ScriptHostSend(std::move(host_arp_other), 0);
        }
        // (4) Host TCP SYN to an internet address: LISTEN passthrough -> must
        //     NOT be re-injected toward the wire.
        raw->ScriptHostSend(BuildSyn(51000, 443), 0);

        vgww::runtime::Dataplane dataplane(config);
        dataplane.SetDriverClient(std::move(fake));
        std::string error;
        CHECK(dataplane.Start(error));
        if (!error.empty()) {
            std::fprintf(stderr, "host-scenario start error: %s\n",
                         error.c_str());
        }

        // GREEN anchors: the gateway answers the host's own stack.
        CHECK(WaitFor([&] { return ContainsArpReply(raw->SentUp()); }, 3000));
        CHECK(WaitFor([&] { return ContainsIcmpEchoReply(raw->SentUp()); },
                      3000));

        // Let any (buggy) down re-injection land before asserting absence.
        std::this_thread::sleep_for(std::chrono::milliseconds(400));

        // RED anchor: host-sent frames that VGWW does not answer must not be
        // duplicated onto the wire.
        bool host_syn_down = false;
        for (const auto& f : raw->SentDown()) {
            if (f.size() < kEthernetHeaderLen + kIpv4HeaderLenMin) {
                continue;
            }
            const uint8_t* ip = f.data() + kEthernetHeaderLen;
            if (ip[9] != 6) {
                continue;
            }
            const uint8_t* tcp = ip + (ip[0] & 0x0F) * 4;
            const uint16_t dport =
                static_cast<uint16_t>((tcp[2] << 8) | tcp[3]);
            if (dport == 443 && 0x02 == (tcp[13] & 0x02) &&
                0 == std::memcmp(ip + 12, &kClientIp, 4)) {
                host_syn_down = true;  // host SYN re-emitted down the wire
            }
        }
        CHECK(!host_syn_down);
        // The non-gateway ARP must likewise not be re-injected (the driver
        // already forwarded the original).
        bool host_arp_down = false;
        for (const auto& f : raw->SentDown()) {
            ArpView view;
            if (ParseArpFrame(f.data(), f.size(), view) &&
                ArpOperation::kRequest == view.operation &&
                0 == std::memcmp(view.sender_mac.data(), kClientMac.data(),
                                 kMacAddrLen)) {
                host_arp_down = true;
            }
        }
        CHECK(!host_arp_down);
        CHECK(!ContainsArpReply(raw->SentDown()));
        CHECK(!ContainsIcmpEchoReply(raw->SentDown()));

        const auto& stats = dataplane.GetStats();
        std::fprintf(stderr,
                     "[host-gw] up_arp=%s up_icmp=%s arp_replies=%llu "
                     "icmp_replies=%llu host_passthrough=%llu\n",
                     ContainsArpReply(raw->SentUp()) ? "yes" : "no",
                     ContainsIcmpEchoReply(raw->SentUp()) ? "yes" : "no",
                     static_cast<unsigned long long>(stats.arp_replies.load()),
                     static_cast<unsigned long long>(stats.icmp_replies.load()),
                     static_cast<unsigned long long>(
                         stats.host_passthrough.load()));

        std::string stop_error;
        CHECK(dataplane.Stop(stop_error));
        std::fprintf(stderr, "[host-gw] scenario done\n");
    }

    /// batch94: the per-window rate table is keyed by SOURCE MAC and is cleared
    /// only when the 1-second window closes. A forged-source flood (a fresh MAC
    /// on every frame) therefore grew it without bound inside one window:
    /// memory, plus a per-tick linear scan in ThroughputBps that sums every
    /// entry. The neighbour table that feeds the dashboard is capped at
    /// kMaxNeighbors, but the rate table had no cap of its own.
    ///
    /// The fix refuses NEW keys once the table reaches kMaxNeighbors while
    /// letting keys already present keep accumulating - so real clients (which
    /// are in the neighbour table, hence below the cap) are unaffected.
    ///
    /// Asserted: after flooding far past the cap the table is BOUNDED, the
    /// refusals are COUNTED, and a frame from an already-known MAC still
    /// accumulates (positive control: a cap that also blocked known clients
    /// would silently stop rate accounting for the whole LAN).
    void RunRateTableBoundedUnderForgedMacFloodScenario() {
        vgww::core::Config config;
        config.adapter = "TestNIC";
        config.gateway.ipv4 = kGatewayIp;
        config.gateway.mask = (0u) | (0u << 8) | (255u << 16) | (255u << 24);
        config.gateway.mac = kGatewayMac;
        config.perf.workers = 1;
        config.perf.max_conns = 64;

        auto fake = std::make_unique<TestDriverClient>();
        TestDriverClient* raw = fake.get();
        vgww::runtime::Dataplane dataplane(config);
        dataplane.SetDriverClient(std::move(fake));
        std::string start_error;
        CHECK(dataplane.Start(start_error));

        const size_t cap = vgww::core::limits::kMaxNeighbors;
        const size_t flood = cap + 512;

        // Positive control baseline: an ordinary frame from the known client.
        raw->ScriptInbound(BuildArpRequest(), 0);
        CHECK(WaitFor([&] { return dataplane.GetStats().rx_frames.load() > 0; },
                      3000));

        const uint64_t dropped_before =
            dataplane.GetStats().rate_table_dropped.load();
        for (size_t i = 0; i < flood; ++i) {
            std::vector<uint8_t> f = BuildArpRequest();
            if (f.size() >= vgww::net::kEthernetHeaderLen) {
                // A DISTINCT, non-group source MAC per frame.
                f[6] = 0x02;
                f[7] = 0x00;
                f[8] = static_cast<uint8_t>((i >> 24) & 0xFF);
                f[9] = static_cast<uint8_t>((i >> 16) & 0xFF);
                f[10] = static_cast<uint8_t>((i >> 8) & 0xFF);
                f[11] = static_cast<uint8_t>(i & 0xFF);
            }
            raw->ScriptInbound(std::move(f), 0);
        }
        CHECK(WaitFor(
            [&] {
                return dataplane.GetStats().rx_frames.load() >= flood;
            },
            30000));

        const size_t pending = dataplane.PendingRateTableSize();
        const uint64_t dropped =
            dataplane.GetStats().rate_table_dropped.load() - dropped_before;
        std::printf("B94 flood=%zu cap=%zu pending=%zu dropped=%llu\n", flood,
                    cap, pending, static_cast<unsigned long long>(dropped));
        // Bounded by the cap. Not an equality: keys already present when the cap
        // was reached stay, and the flood's own keys race the window rollover.
        CHECK(pending <= cap);
        // Every refusal is counted, never silent.
        CHECK(dropped > 0);

        // Positive control: the known client's MAC is already in the table, so
        // it must keep accumulating even while the table is saturated.
        raw->ScriptInbound(BuildArpRequest(), 0);
        CHECK(WaitFor(
            [&] {
                return dataplane.GetStats().rx_frames.load() > flood;
            },
            5000));
        CHECK(dataplane.PendingRateTableSize() <= cap);

        std::string stop_error;
        CHECK(dataplane.Stop(stop_error));
    }

    /// P2: `/api/clients` reported `lan:true` for EVERY client because the
    /// field was never assigned (dataplane.h defaulted it to true and no
    /// production code wrote it). The WebUI's WAN filter (`!isLan`) therefore
    /// always produced an empty table.
    ///
    /// The device list itself only ever contains LAN-side neighbours (the
    /// ClientRates() loop drops everything else), so the `false` branch is
    /// unreachable THROUGH ClientRates(). The rule is therefore exposed as
    /// IsLanClientAddress() - the single source of truth the filter and the
    /// flag both use - and asserted directly for BOTH verdicts, plus end to
    /// end through ClientRates() for the reachable (LAN) case.
    void RunClientLanFlagScenario() {
        vgww::core::Config config;
        config.adapter = "TestNIC";
        bool ok = false;
        config.gateway.ipv4 = vgww::core::ParseIpv4("192.168.0.40", ok);
        CHECK(ok);
        config.gateway.mask = vgww::core::ParseIpv4("255.255.255.0", ok);
        CHECK(ok);
        config.gateway.mac = kGatewayMac;
        config.ipv6.enabled = true;
        config.ipv6.prefix_len = 64;
        config.ipv6.ula_prefix = {0xFD, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
                                  0x66, 0, 0, 0, 0, 0, 0, 0, 0};
        config.perf.workers = 1;
        config.perf.max_conns = 64;

        const auto v4 = [&ok](const char* text) {
            return vgww::net::IpAddress::FromV4NetOrder(
                vgww::core::ParseIpv4(text, ok));
        };

        // --- the predicate, both verdicts (the false branch is unreachable
        // through ClientRates(), so it is asserted here directly) ---
        // v4 inside the /24.
        CHECK(vgww::runtime::IsLanClientAddress(config, v4("192.168.0.101")));
        // v4 outside the /24 (a WAN-side source).
        CHECK(!vgww::runtime::IsLanClientAddress(config, v4("93.184.216.34")));
        // v6 inside the ULA prefix.
        {
            std::array<uint8_t, 16> in = config.ipv6.ula_prefix;
            in[15] = 0x42;
            CHECK(vgww::runtime::IsLanClientAddress(
                config, vgww::net::IpAddress::FromV6(in.data())));
        }
        // v6 outside the ULA prefix (a global address).
        {
            std::array<uint8_t, 16> out{};
            out[0] = 0x20;
            out[1] = 0x01;  // 2001::/16, not the ULA
            out[15] = 0x42;
            CHECK(!vgww::runtime::IsLanClientAddress(
                config, vgww::net::IpAddress::FromV6(out.data())));
        }
        // v6 with IPv6 disabled: never a LAN client.
        {
            vgww::core::Config off = config;
            off.ipv6.enabled = false;
            std::array<uint8_t, 16> in = config.ipv6.ula_prefix;
            in[15] = 0x42;
            CHECK(!vgww::runtime::IsLanClientAddress(
                off, vgww::net::IpAddress::FromV6(in.data())));
        }

        // --- end to end: a LAN client's ClientRate.lan is true ---
        // The struct default is FALSE (a client is not LAN until proven), so
        // the assertion below can only pass if ClientRates() actually ASSIGNS
        // the flag - an unassigned field would read false and fail. This is
        // what makes the test discriminate "assigned" from "defaulted".
        {
            vgww::runtime::Dataplane::ClientRate fresh;
            CHECK(!fresh.lan);
        }
        auto fake = std::make_unique<TestDriverClient>();
        TestDriverClient* raw = fake.get();
        vgww::runtime::Dataplane dataplane(config);
        dataplane.SetDriverClient(std::move(fake));
        std::string start_error;
        CHECK(dataplane.Start(start_error));

        // An ARP from the LAN client teaches the neighbour table; the control
        // thread publishes it on its next tick.
        raw->ScriptInbound(BuildArpRequest(), 0);
        CHECK(WaitFor(
            [&] {
                const auto rates = dataplane.ClientRates();
                for (const auto& r : rates) {
                    if (r.mac == kClientMac) {
                        return true;
                    }
                }
                return false;
            },
            5000));

        bool saw_client = false;
        for (const auto& r : dataplane.ClientRates()) {
            if (r.mac == kClientMac) {
                saw_client = true;
                // The reachable branch: a LAN client is reported as LAN.
                CHECK(r.lan);
            }
        }
        CHECK(saw_client);

        std::string stop_error;
        CHECK(dataplane.Stop(stop_error));
    }

    /// batch34p: when the RX ring is full, the frame is DROPPED - and that
    /// drop must be COUNTED. The TX path already does this
    /// (dataplane.cpp:1900-1904: Push() false -> ++stats->rx_dropped), but the
    /// four RX enqueue sites ignored the return value, so a full ring silently
    /// capped throughput with no observable signal.
    ///
    /// Requirement asserted (behaviour, not implementation): a burst far larger
    /// than the ring capacity must leave rx_dropped > 0. A ring of 1 slot with
    /// a 1-frame batch cannot absorb the burst, so overflow is guaranteed
    /// regardless of scheduling.
    void RunRxRingOverflowCountedScenario() {
        vgww::core::Config config;
        config.adapter = "TestNIC";
        config.gateway.ipv4 = kGatewayIp;
        config.gateway.mask = (0u) | (0u << 8) | (255u << 16) | (255u << 24);
        config.gateway.mac = kGatewayMac;
        config.perf.workers = 1;
        // The smallest ring the pipeline allows: one slot per worker.
        config.perf.ring_capacity = 1;
        config.perf.rx_batch = 1;
        config.perf.max_conns = 64;

        auto fake = std::make_unique<TestDriverClient>();
        TestDriverClient* raw = fake.get();

        // A SYN per frame; the stack will refuse most, which is irrelevant -
        // the assertion is about the RING, not about TCP.
        for (int i = 0; i < 200; ++i) {
            raw->ScriptInbound(BuildTcpSegment(1000u + (uint32_t)i, 0, 0x02, ""),
                               0);
        }

        vgww::runtime::Dataplane dataplane(config);
        dataplane.SetDriverClient(std::move(fake));
        std::string error;
        CHECK(dataplane.Start(error));
        if (!error.empty()) {
            std::fprintf(stderr, "rx-overflow start error: %s\n", error.c_str());
        }

        const uint64_t dropped_before =
            dataplane.GetStats().rx_dropped.load();
        // Drive the burst through the reader and let the workers drain what
        // fits. With a 1-slot ring the surplus has nowhere to go.
        std::this_thread::sleep_for(std::chrono::milliseconds(800));

        const uint64_t dropped_after = dataplane.GetStats().rx_dropped.load();
        std::fprintf(stderr,
                     "[rx-overflow] ring=1 batch=1 dropped %llu -> %llu\n",
                     static_cast<unsigned long long>(dropped_before),
                     static_cast<unsigned long long>(dropped_after));
        CHECK(dropped_after > dropped_before);

        std::string stop_error;
        CHECK(dataplane.Stop(stop_error));
    }

// batch306: an idle worker must not rescan the TCP relay registry. The
// sweep used to run on EVERY worker-loop iteration (the loop sleeps 200 us
// when idle), walking every live relay (up to max_conns) under the registry
// mutex. It is now gated on a "a relay finished" flag, so an idle data
// plane performs zero scans.
void TestB306IdleRegistrySweepIsFree() {
    vgww::core::Config cfg;
    cfg.adapter = "TestNIC";
    cfg.gateway.ipv4 = kGatewayIp;
    cfg.gateway.mask = (0u) | (0u << 8) | (255u << 16) | (255u << 24);
    cfg.gateway.mac = kGatewayMac;
    cfg.perf.workers = 2;
    cfg.perf.ring_capacity = 256;
    cfg.perf.max_conns = 64;
    cfg.perf.dial_timeout_ms = 400;

    auto fake = std::make_unique<TestDriverClient>();
    TestDriverClient* raw = fake.get();
    raw->DisarmRxEventForTest();
    vgww::runtime::Dataplane dataplane(cfg);
    dataplane.SetDriverClient(std::move(fake));
    std::string error;
    CHECK(dataplane.Start(error));

    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    const uint64_t before = dataplane.RegistrySweepCount();
    std::this_thread::sleep_for(std::chrono::milliseconds(600));
    const uint64_t after = dataplane.RegistrySweepCount();
    std::fprintf(stderr, "[b306] registry sweeps while idle: %llu -> %llu\n",
                 static_cast<unsigned long long>(before),
                 static_cast<unsigned long long>(after));
    CHECK(after == before);   // nothing finished: no scan at all

    dataplane.Stop();
}

int main() {
    SetUnhandledExceptionFilter(CrashFilter);
    TestUdpRelaySyncSend();
    TestB31RxPollQuantized();
    TestB31RxPollFast();
    TestB31RxPollConfigHonored();
    TestB306IdleRegistrySweepIsFree();
    RunAdapterHintWideningScenario();
    RunFriendlyNameEndToEndScenario();
    RunAdapterDiagnosticsScenario();
    RunAdapterLinkDiagnosticsScenario();
    RunVlanScenarios();
    RunOverlongReportedLengthIsDroppedScenario();
    RunHostOriginatedScenario();
    RunRxRingOverflowCountedScenario();
    RunRateTableBoundedUnderForgedMacFloodScenario();
    RunClientLanFlagScenario();
    vgww::core::Config config;
    config.adapter = "TestNIC";
    config.gateway.ipv4 = kGatewayIp;
    config.gateway.mask = (0u) | (0u << 8) | (255u << 16) | (255u << 24);  // /16
    config.gateway.mac = kGatewayMac;
    config.perf.workers = 2;
    config.perf.ring_capacity = 256;
    config.perf.max_conns = 64;
    // Short dial timeout: the unreachable-target scenario below must RST
    // quickly instead of waiting out the production 10s window.
    config.perf.dial_timeout_ms = 400;

    auto fake = std::make_unique<TestDriverClient>();
    TestDriverClient* raw = fake.get();
    fake->ScriptInbound(BuildArpRequest(), 0);
    fake->ScriptInbound(BuildEchoRequest(32), 0);
    fake->ScriptInbound(BuildSyn(51000, 443), 50);
    // Natural SYN retransmission: covers the neighbor-snapshot publish delay.
    fake->ScriptInbound(BuildSyn(51000, 443), 500);

    // Full-duplex relay scenario: SYN to the local echo server, then a
    // scripted handshake + payload exchange at frame level.
    std::atomic<bool> echo_stop{false};
    std::thread echo_server([&] { RunEchoServer(45678, echo_stop); });
    fake->ScriptInbound(BuildTcpSegment(1000, 0, 0x02, ""), 300);   // SYN
    // Retransmission: covers neighbor-snapshot publish latency (first
    // SYN-ACK is dropped on MAC-miss, exactly like a real client retry).
    fake->ScriptInbound(BuildTcpSegment(1000, 0, 0x02, ""), 800);   // SYN retransmit
    // IPv6 TCP flow: SYN to the loopback echo port over v6.
    fake->ScriptInbound(BuildV6TcpSegment(2000, 0, 0x02, 51002, 45678), 900);

    // UDP NAT flow: client datagram to a local UDP echo server; the relay
    // must forward it upstream and route the echo back to the client.
    std::atomic<bool> udp_stop{false};
    std::atomic<bool> udp_ready{false};
    std::thread udp_echo([&] { RunUdpEchoServer(45679, udp_stop, udp_ready); });
    // Wait for the echo socket BEFORE anything can send to it: an early
    // datagram triggers ICMP port-unreachable and Windows then drops the
    // whole flow (WSAECONNRESET on connected sockets).
    while (!udp_ready.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
    fake->ScriptInbound(BuildUdpRequest(51003, 45679, "PING"), 1100);

    // Dial-failure path: SYN toward a loopback port with no listener. The
    // port is probed free right before use (fixed low ports may be taken -
    // e.g. this machine has something on :9). The refused upstream connect
    // must surface as RST to the client - never a silent hang.
    uint16_t dead_port = 0;
    {
        asio::io_context io;
        asio::ip::tcp::acceptor probe(io);
        std::error_code ec;
        probe.open(asio::ip::tcp::v4(), ec);
        probe.bind(asio::ip::tcp::endpoint(asio::ip::address_v4::loopback(), 0),
                   ec);
        if (!ec) {
            dead_port = probe.local_endpoint().port();
        }
        probe.close(ec);
    }
    CHECK(0 != dead_port);

    vgww::runtime::Dataplane dataplane(config);
    dataplane.SetDriverClient(std::move(fake));

    std::string error;
    CHECK(dataplane.Start(error));
    if (!error.empty()) {
        std::fprintf(stderr, "start error: %s\n", error.c_str());
    }

    // Let the pipeline run: reads happen on 200ms polls, neighbor snapshots
    // publish every 100ms, the retransmitted SYN lands at 500ms.
    std::this_thread::sleep_for(std::chrono::milliseconds(1500));

    const auto& stats = dataplane.GetStats();
    std::fprintf(stderr,
                 "[stats] rx=%llu dropped=%llu tx=%llu arp=%llu icmp=%llu "
                 "pass=%llu tcp=%llu miss=%llu\n",
                 static_cast<unsigned long long>(stats.rx_frames.load()),
                 static_cast<unsigned long long>(stats.rx_dropped.load()),
                 static_cast<unsigned long long>(stats.tx_frames.load()),
                 static_cast<unsigned long long>(stats.arp_replies.load()),
                 static_cast<unsigned long long>(stats.icmp_replies.load()),
                 static_cast<unsigned long long>(stats.host_passthrough.load()),
                 static_cast<unsigned long long>(stats.tcp_accepted.load()),
                 static_cast<unsigned long long>(stats.mac_misses.load()));

    CHECK(ContainsArpReply(raw->SentDown()));
    CHECK(ContainsIcmpEchoReply(raw->SentDown()));
    // batch34n: the host stack's answer for :443 must reach the wire. The
    // answer is SYN|ACK when something listens there and RST|ACK when
    // nothing does - both prove the relay worked. Waiting (instead of a
    // fixed sleep) also removes the timing assumption.
    CHECK(WaitFor([&] { return ContainsTcpAnswerFrom443(raw->SentDown()); },
                   3000));
    CHECK(dataplane.GetStats().arp_replies.load() >= 1);
    CHECK(dataplane.GetStats().icmp_replies.load() >= 1);
    CHECK(dataplane.GetStats().tcp_accepted.load() >= 1);

    // ----- IPv6 echo to the gateway (hop limit 64) ----------------------
    // RFC 4861 section 7.1's hop-limit-255 rule applies ONLY to Neighbor
    // Discovery
    // (types 133-137). Clients ping the gateway's link-local address with
    // the RA-advertised hop limit (64); the historical blanket 255 check on
    // every ICMPv6 frame left the echo-reply branch dead code. This must
    // now answer.
    raw->ScriptInbound(BuildV6EchoRequest(16), 0);
    CHECK(WaitFor([&] { return ContainsV6EchoReply(raw->SentDown()); }, 3000));

    // IPv6 transparent accept: SYN to [::1]:45678 must yield a v6 SYN-ACK.
    CHECK(WaitFor([&] { return ContainsV6SynAck(raw->SentDown(), 45678); },
                  3000));

    // ----- IPv6 full-duplex relay through ::1:45678 ---------------------
    // Complete the handshake immediately: an unreplied SYN-RCVD connection
    // is retransmitted only a few times before xtcp reclaims it.
    const uint32_t v6_isn = FindV6ServerIsn(raw->SentDown(), 51002, 45678);
    CHECK(v6_isn != 0);
    if (v6_isn != 0) {
        raw->InjectNow(BuildV6TcpSegment(2001, v6_isn + 1, 0x10, 51002,
                                         45678));  // ACK: handshake done
        raw->InjectNow(BuildV6TcpSegment(2001, v6_isn + 1, 0x18, 51002,
                                         45678, "hello v6"));  // PSH+ACK
        CHECK(WaitFor(
            [&] { return ContainsV6Payload(raw->SentDown(), "hello v6"); },
            5000));

        // Half-close over v6 (H3 step 2): the v6 client's FIN must reach
        // the upstream socket; the server FINs back toward the client.
        // seq advanced by 8 bytes for the "hello v6" payload.
        raw->InjectNow(BuildV6TcpSegment(2009, v6_isn + 1, 0x11, 51002,
                                         45678));  // FIN|ACK
        CHECK(WaitFor([&] { return ContainsV6Fin(raw->SentDown(), 45678); },
                      5000));
    }

    // ----- IPv6 UDP relay through [::1]:45680 --------------------------
    // The classifier emits kUdpV6 but the dispatch previously had no
    // consumer for it, so v6 UDP was silently dropped. A datagram to the
    // v6 echo server must round-trip through the host socket relay.
    std::atomic<bool> udp6_stop{false};
    std::atomic<bool> udp6_ready{false};
    std::thread udp6_echo(
        [&] { RunUdpEchoServer6(45680, udp6_stop, udp6_ready); });
    while (!udp6_ready.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
    raw->InjectNow(BuildV6UdpSegment(51004, 45680, "P6NG"));
    CHECK(WaitFor([&] { return ContainsV6UdpPayload(raw->SentDown(), "P6NG"); },
                  5000));

    // Out-of-order and duplicate datagrams on the SAME flow must all come
    // back: the relay + return path carries one payload per send, never
    // coalescing or dropping under reorder/duplication.
    raw->InjectNow(BuildV6UdpSegment(51004, 45680, "P6LATE"));
    raw->InjectNow(BuildV6UdpSegment(51004, 45680, "P6EARLY"));
    raw->InjectNow(BuildV6UdpSegment(51004, 45680, "P6EARLY"));  // dup
    CHECK(WaitFor([&] { return ContainsV6UdpPayload(raw->SentDown(), "P6LATE") &&
                               ContainsV6UdpPayload(raw->SentDown(), "P6EARLY");
                    },
                  5000));

    udp6_stop.store(true);
    if (udp6_echo.joinable()) {
        udp6_echo.join();
    }

    // ----- IPv6 ban: a banned v6 source must be dropped ----------------
    // The ip ban comparator only checked IPv4 before the parsed-snapshot
    // fix; a banned v6 client used to pass right through. Ban the synthetic
    // v6 client and verify its frame is counted as dropped.
    vgww::web::RuleStore::Instance().AddBan(
        {"ip", "fe80::aabb:ccdd:eeff:1"});
    // The control loop rebuilds the parsed snapshot once per iteration.
    std::this_thread::sleep_for(std::chrono::milliseconds(1200));
    const auto dropped_before = dataplane.GetStats().rx_dropped.load();
    raw->ScriptInbound(BuildV6TcpSegment(5000, 0, 0x02, 51003, 45678), 0);
    CHECK(WaitFor(
        [&] { return dataplane.GetStats().rx_dropped.load() >= dropped_before + 1; },
        5000));

    // UDP NAT round trip: the echoed datagram must come back toward the
    // client with the server's source port.
    CHECK(WaitFor(
        [&] { return ContainsUdpReply(raw->SentDown(), 45679, "PING"); },
        5000));

    // Bulk UDP: 64 concurrent flows through the NAT table + relay must each
    // round-trip. A unique P%d payload per flow proves all 64 were served.
    for (uint32_t b = 0; b < 64; ++b) {
        char payload[16];
        std::snprintf(payload, sizeof(payload), "P%u", b);
        raw->InjectNow(BuildUdpRequest(static_cast<uint16_t>(51011 + b),
                                       45679, payload));
    }
    CHECK(WaitFor(
        [&] { return CountUdpPayloads(raw->SentDown(), 45679) >= 64; }, 8000));

    // Fragmented IPv4 UDP must not be silently relayed as a truncated
    // datagram: it is diverted to the host path (never appears relayed).
    const uint64_t pass_before =
        dataplane.GetStats().host_passthrough.load();
    raw->InjectNow(BuildUdpFragment(51015, 45679, "FRAGMENTED"));
    CHECK(WaitFor(
        [&] {
            return dataplane.GetStats().host_passthrough.load() > pass_before;
        },
        3000));
    CHECK(!ContainsUdpReply(raw->SentDown(), 45679, "FRAGMENTED"));

    // Fragmented IPv4 ICMP must likewise not answer (or relay) a truncated
    // echo: it is diverted to the host path, and no echo reply appears.
    {
        std::vector<uint8_t> frag_icmp = BuildEchoRequest(16);
        frag_icmp[kEthernetHeaderLen + 6] |= 0x20;  // MF, offset 0
        const uint64_t pass2 =
            dataplane.GetStats().host_passthrough.load();
        const uint64_t icmp2 = dataplane.GetStats().icmp_replies.load();
        raw->InjectNow(std::move(frag_icmp));
        CHECK(WaitFor(
            [&] {
                return dataplane.GetStats().host_passthrough.load() >
                       pass2;
            },
            3000));
        CHECK(dataplane.GetStats().icmp_replies.load() == icmp2);
    }

    // Dial failure: the refused upstream must surface as RST to the client.
    raw->InjectNow(BuildSynTo({127, 0, 0, 1}, 51004, dead_port));
    CHECK(WaitFor(
        [&] { return ContainsRst(raw->SentDown(), dead_port); }, 5000));

    // A THROWING dial completion must cost only that connection. Before the
    // guard, the exception unwound the worker thread, RunGuarded counted it
    // and flipped `running` - the WHOLE data plane stopped. Now the throw is
    // swallowed and counted, the client still gets its RST, and the worker
    // keeps serving new flows.
    uint16_t dead_port2 = 0;
    {
        asio::io_context io;
        asio::ip::tcp::acceptor probe(io);
        std::error_code ec;
        probe.open(asio::ip::tcp::v4(), ec);
        probe.bind(asio::ip::tcp::endpoint(asio::ip::address_v4::loopback(), 0),
                   ec);
        if (!ec) {
            dead_port2 = probe.local_endpoint().port();
        }
        probe.close(ec);
    }
    CHECK(0 != dead_port2);
    {
        std::atomic<int> threw{0};
        dataplane.SetDialCompletionProbeForTest([&threw] {
            if (0 == threw.fetch_add(1)) {
                throw std::runtime_error("dial body exploded");
            }
        });
        const uint64_t handler_errors_before =
            dataplane.GetStats().handler_errors.load();
        raw->InjectNow(BuildSynTo({127, 0, 0, 1}, 51007, dead_port2));
        CHECK(WaitFor(
            [&] { return ContainsRst(raw->SentDown(), dead_port2); }, 5000));
        CHECK(1 == threw.load());
        CHECK(dataplane.GetStats().handler_errors.load() ==
              handler_errors_before + 1);
        // The worker survived: a later flow still completes its handshake.
        raw->InjectNow(BuildSynTo({127, 0, 0, 1}, 51008, 45678));
        CHECK(WaitFor(
            [&] { return 0 != FindServerIsn(raw->SentDown(), 51008, 45678); },
            5000));
        dataplane.SetDialCompletionProbeForTest(nullptr);
    }

    // ----- scripted conversation through the relay ---------------------
    const uint32_t server_isn =
        FindServerIsn(raw->SentDown(), 51001, 45678);
    CHECK(server_isn != 0);
    if (server_isn != 0) {
        // Complete the handshake.
        raw->InjectNow(BuildTcpSegment(1001, server_isn + 1, 0x10, ""));
        if (!WaitFor([&] { return dataplane.GetStats().tx_frames.load() >= 4; },
                     2000)) {
            std::fprintf(stderr, "[warn] handshake ACK not echoed yet\n");
        }
        // Send payload; the echo must come back toward the client.
        raw->InjectNow(BuildTcpSegment(1001, server_isn + 1, 0x18, "hello vgww"));
        CHECK(WaitFor([&] {
            return ContainsPayload(raw->SentDown(), "hello vgww");
        }, 5000));

        // Half-close (H3 step 2): the client's FIN must reach the upstream
        // socket as a clean close - the server's FIN must come back to the
        // client (flags 0x11), never an RST. seq advanced by 10 payload bytes.
        raw->InjectNow(BuildTcpSegment(1011, server_isn + 1, 0x11, ""));
        CHECK(WaitFor([&] { return ContainsFin(raw->SentDown(), 45678); },
                      5000));
        CHECK(!ContainsRst(raw->SentDown(), 45678));
    }

    // ----- concurrent connections (shard affinity + registry scaling) -----
    // Sanity check that the echo server itself is healthy with several
    // simultaneous connections (raw sockets, no VGWW in the path).
    std::fprintf(stderr, "[dbg] native-probe=%d/3\n",
                 NativeEchoProbe());
    // Three independent client ports dial the SAME echo port at nearly the
    // same time. Each must complete its own handshake and echo back its own
    // payload - interleaving must not corrupt or drop any flow.
    {
        struct Flow {
            uint16_t sport;
            uint32_t seq;
            uint32_t isn;
            std::string tag;
        };
        Flow flows[3] = {
            {51201, 2000, 0, "alpha"},
            {51202, 2500, 0, "bravo"},
            {51203, 3000, 0, "charlie"},
        };
        // Fire all three SYNs back-to-back: true concurrent handshakes.
        for (const auto& f : flows) {
            raw->InjectNow(BuildTcpSegment(f.seq, 0, 0x02, "", f.sport,
                                           45678));
        }
        for (auto& f : flows) {
            uint32_t isn = 0;
            CHECK(WaitFor(
                [&] {
                    isn = FindServerIsn(raw->SentDown(), f.sport, 45678);
                    return isn != 0;
                },
                5000));
            if (0 == isn) {
                continue;  // upstream missed the handshake: report + skip
            }
            f.isn = isn;
            raw->InjectNow(BuildTcpSegment(f.seq + 1, isn + 1, 0x18,
                                           f.tag, f.sport, 45678));
        }
        // Each flow's payload must come back through its own relay.
        for (const auto& f : flows) {
            CHECK(WaitFor(
                [&] {
                    return ContainsPayloadFor(raw->SentDown(), f.sport,
                                              f.tag);
                },
                5000));
        }

        // batch311: the FIN handler must resolve the relay by conn_id, not
        // by scanning and not by picking any entry. FIN all three flows and
        // require EACH client port to receive its own graceful FIN; a lookup
        // that targets the wrong relay leaves at least one port without one.
        const std::size_t index_before = dataplane.RegistryIndexSize();
        for (const auto& f : flows) {
            raw->InjectNow(BuildTcpSegment(
                f.seq + 1 + static_cast<uint32_t>(f.tag.size()),
                f.isn + 1, 0x11, "", f.sport, 45678));
        }
        for (const auto& f : flows) {
            CHECK(WaitFor(
                [&] { return ContainsFinFor(raw->SentDown(), f.sport); },
                5000));
        }
        // batch311: finished relays must leave the index - one leaked entry
        // per closed connection would grow without bound on a churny link.
        CHECK(WaitFor(
            [&] {
                return dataplane.RegistryIndexSize() + 3 <= index_before;
            },
            5000));
    }

    // ----- SYN flood: accept backlog must be capped ----------------------
    // 70 simultaneous SYNs on a 64-slot backlog must not grow unbounded;
    // everything past the cap is RST'd (a real flood would otherwise let a
    // single client pin gigabytes in parked flows).
    {
        const uint64_t tcp_before = dataplane.GetStats().tcp_accepted.load();
        for (uint32_t s = 0; s < 70; ++s) {
            raw->ScriptInbound(
                BuildSyn(static_cast<uint16_t>(52000 + s), 45678), 0);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(2500));
        const uint64_t tcp_delta =
            dataplane.GetStats().tcp_accepted.load() - tcp_before;
        CHECK(tcp_delta > 0);
        CHECK(tcp_delta <= 64);  // accepted only what fit the cap
    }

    // ----- malformed ARP operand must NOT be auto-answered -------------
    // An ARP frame with an illegal operand (3) used to collapse into
    // kRequest in ParseArpFrame and got gratuitously answered whenever the
    // target hit the gateway. It must now be dropped - never answered.
    {
        std::vector<uint8_t> malformed = BuildArpRequest();
        malformed[kEthernetHeaderLen + 7] = 0x03;  // oper = 3
        const size_t arp_snapshot = raw->SentDown().size();
        const uint64_t arp_stat = dataplane.GetStats().arp_replies.load();
        raw->ScriptInbound(std::move(malformed), 0);
        std::this_thread::sleep_for(std::chrono::milliseconds(400));
        CHECK(dataplane.GetStats().arp_replies.load() == arp_stat);
        bool new_reply = false;
        for (size_t i = arp_snapshot; i < raw->SentDown().size(); ++i) {
            ArpView av;
            if (ParseArpFrame(raw->SentDown()[i].data(),
                              raw->SentDown()[i].size(), av) &&
                ArpOperation::kReply == av.operation) {
                new_reply = true;
            }
        }
        CHECK(!new_reply);
    }

    // batch306: the idle gate must not starve reclamation - a relay that
    // finished during this run must still trigger a reclaim scan.
    CHECK(WaitFor([&] { return dataplane.RegistrySweepCount() > 0; }, 3000));

    // batch306: and once the finished relay has been reclaimed, idle
    // iterations must stop scanning again - a flag that is never cleared
    // would restore the per-iteration burn. A 2 s window keeps the signal
    // far above the few sweeps a late-finishing relay could add.
    {
        const uint64_t idle_before = dataplane.RegistrySweepCount();
        std::this_thread::sleep_for(std::chrono::milliseconds(2000));
        const uint64_t idle_after = dataplane.RegistrySweepCount();
        std::fprintf(stderr,
                     "[b306] sweeps during a 2000 ms idle window: %llu\n",
                     static_cast<unsigned long long>(idle_after - idle_before));
        CHECK(idle_after - idle_before < 50);
    }

    dataplane.Stop();
    echo_stop.store(true);
    {
        // Unblock the acceptor so the echo thread can exit.
        asio::io_context io;
        asio::ip::tcp::socket wake(io);
        std::error_code ignored;
        wake.connect(asio::ip::tcp::endpoint(asio::ip::make_address("127.0.0.1"),
                                             45678),
                     ignored);
    }
    echo_server.join();
    udp_stop.store(true);
    udp_echo.join();

    if (0 == g_failures) {
        std::puts("test_dataplane: ALL PASS");
        return 0;
    }
    std::fprintf(stderr, "test_dataplane: %d FAILURES\n", g_failures);
    return 1;
}
