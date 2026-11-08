// ============================================================================
// test_udp_relay.cpp - UDP flow table eviction/sweep must terminate flows.
//
// Regression: evicting (or sweeping) a flow only erased the table entry,
// leaving the pending async_receive alive - a "ghost" flow whose socket and
// callback chain leaked forever and kept forwarding stale return traffic.
// ============================================================================
#define CHECK(cond)                                                        \
    do {                                                                   \
        if (!(cond)) {                                                     \
            std::fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, \
                         __LINE__, #cond);                                 \
            return 1;                                                      \
        }                                                                  \
    } while (0)

#include "relay/udp_relay.h"

#include <asio.hpp>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <memory>
#include <stdexcept>
#include <thread>
#include <unordered_map>
#include <vector>

namespace vgww {
    /// C4 + batch325: the receive chain must survive the whole transient
    /// ICMP-unreachable family (Windows connected-UDP surfaces "port
    /// unreachable" as connection_reset/refused and "dest/net unreachable"
    /// as host_/network_*) and only end on terminal conditions
    /// (operation_aborted / bad_descriptor / a closed socket).
    int TestReceiveErrorRearm() {
        asio::io_context io;
        asio::ip::udp::socket sock(io);
        std::error_code err;
        sock.open(asio::ip::udp::v4(), err);
        CHECK(!err);
        relay::UdpRelay::FlowKey key{};
        key.client_ip = net::IpAddress::FromV4BigEndian(
            std::array<uint8_t, 4>{192, 168, 0, 9}.data());
        key.client_port = 5000;
        relay::UdpRelay relay(std::move(sock), key);

        CHECK(relay.ShouldRearm(std::error_code()));
        CHECK(relay.ShouldRearm(asio::error::connection_reset));
        CHECK(relay.ShouldRearm(asio::error::connection_aborted));
        CHECK(relay.ShouldRearm(asio::error::connection_refused));
        CHECK(relay.ShouldRearm(asio::error::network_unreachable));
        CHECK(relay.ShouldRearm(asio::error::host_unreachable));
        CHECK(relay.ShouldRearm(asio::error::network_down));
        CHECK(relay.ShouldRearm(asio::error::network_reset));
        CHECK(!relay.ShouldRearm(asio::error::operation_aborted));
        CHECK(!relay.ShouldRearm(asio::error::bad_descriptor));
        return 0;
    }

    /// Spins the loop until `done()` or a 2 s deadline; a datagram on
    /// loopback is delivered asynchronously even though send_to is
    /// synchronous, so a bare poll() can return before the completion.
    template <typename Pred>
    void PumpUntil(asio::io_context& io, Pred done) {
        const auto deadline =
            std::chrono::steady_clock::now() + std::chrono::seconds(2);
        while (!done() && std::chrono::steady_clock::now() < deadline) {
            io.poll();
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }

    /// The guard itself: never throws, counts every swallowed exception.
    int TestHandlerGuardSwallowsAndCounts() {
        std::atomic<uint64_t> errors{0};
        bool ran = false;
        ::vgww::core::InvokeHandlerGuarded(errors, [&ran] { ran = true; });
        CHECK(ran);
        CHECK(0 == errors.load());
        ::vgww::core::InvokeHandlerGuarded(errors, [] {
            throw std::runtime_error("frame build failed");
        });
        CHECK(1 == errors.load());
        ::vgww::core::InvokeHandlerGuarded(errors, [] { throw 42; });
        CHECK(2 == errors.load());
        return 0;
    }

    /// A handler that throws must cost one datagram, not the flow: the
    /// exception would otherwise escape io_context::poll(), unwind the
    /// worker thread and stop the whole data plane.
    int TestThrowingHandlerKeepsTheReceiveChain() {
        asio::io_context io;
        std::error_code err;

        asio::ip::udp::socket peer(io);
        peer.open(asio::ip::udp::v4(), err);
        CHECK(!err);
        peer.bind(asio::ip::udp::endpoint(
                      asio::ip::make_address_v4("127.0.0.1"), 0),
                  err);
        CHECK(!err);
        const asio::ip::udp::endpoint peer_ep = peer.local_endpoint(err);
        CHECK(!err);

        asio::ip::udp::socket local(io);
        local.open(asio::ip::udp::v4(), err);
        CHECK(!err);
        local.bind(asio::ip::udp::endpoint(
                       asio::ip::make_address_v4("127.0.0.1"), 0),
                   err);
        CHECK(!err);
        const asio::ip::udp::endpoint local_ep = local.local_endpoint(err);
        CHECK(!err);

        relay::UdpRelay::FlowKey key{};
        const std::array<uint8_t, 4> loop{127, 0, 0, 1};
        key.client_ip = net::IpAddress::FromV4BigEndian(loop.data());
        key.remote_ip = net::IpAddress::FromV4BigEndian(loop.data());
        key.client_port = 5000;
        key.remote_port = peer_ep.port();

        auto flow = std::make_shared<relay::UdpRelay>(std::move(local), key);
        flow->ConnectRemote(peer_ep, err);
        CHECK(!err);

        int calls = 0;
        size_t last_len = 0;
        flow->on_remote_data = [&calls, &last_len](const uint8_t*, size_t n) {
            ++calls;
            last_len = n;
            if (1 == calls) {
                throw std::runtime_error("frame build failed");
            }
        };
        flow->ArmReceive();

        const uint8_t first[4] = {1, 2, 3, 4};
        peer.send_to(asio::buffer(first, sizeof(first)), local_ep, 0, err);
        CHECK(!err);
        PumpUntil(io, [&calls] { return calls >= 1; });
        CHECK(1 == calls);                  // the throwing body did run
        CHECK(1 == flow->HandlerErrors());  // and was swallowed
        CHECK(flow->IsOpen());              // the socket stayed alive

        const uint8_t second[2] = {9, 9};
        peer.send_to(asio::buffer(second, sizeof(second)), local_ep, 0, err);
        CHECK(!err);
        PumpUntil(io, [&calls] { return calls >= 2; });
        CHECK(2 == calls);                  // the chain re-armed
        CHECK(2 == last_len);
        CHECK(1 == flow->HandlerErrors());  // and counted exactly once
        return 0;
    }

    int RunTests() {
        if (0 != TestHandlerGuardSwallowsAndCounts()) {
            return 1;
        }
        if (0 != TestThrowingHandlerKeepsTheReceiveChain()) {
            return 1;
        }
        if (0 != TestReceiveErrorRearm()) {
            return 1;
        }

        asio::io_context io;
        const net::IpAddress client =
            net::IpAddress::FromV4BigEndian(std::array<uint8_t, 4>{192, 168, 0, 9}.data());
        const net::IpAddress remote =
            net::IpAddress::FromV4BigEndian(std::array<uint8_t, 4>{8, 8, 8, 8}.data());

        relay::UdpRelay::FlowKey key_a{};
        key_a.client_ip = client;
        key_a.remote_ip = remote;
        key_a.client_port = 5000;
        key_a.remote_port = 53;

        relay::UdpRelay::FlowKey key_b = key_a;
        key_b.client_port = 5001;

        // Capacity 1: inserting B evicts A.
        relay::UdpFlowTable table(1, std::chrono::seconds(60));
        auto a = table.GetOrCreate(key_a, io);
        CHECK(nullptr != a);
        auto b = table.GetOrCreate(key_b, io);  // evicts A
        CHECK(nullptr != b);

        // Let the io_context run the aborted-receive completion.
        io.poll();

        // The evicted flow's socket MUST be closed: no ghost receives.
        CHECK(!a->IsOpen());
        // batch34j: the eviction must be COUNTED.
        CHECK(table.Evictions() == 1);

        // Sweep path: an idle flow disappears AND its socket closes.
        auto c = table.GetOrCreate(key_a, io);  // evicts B (capacity 1)
        CHECK(table.Evictions() == 2);
        CHECK(nullptr != c);

        // Hit path: the same key reuses the live flow (no rebuild), so the
        // original shared_ptr still owns the same open socket.
        auto hit = table.GetOrCreate(key_a, io);
        CHECK(hit.get() == c.get());
        CHECK(c->IsOpen());
        // A non-idle flow survives Sweep.
        CHECK(table.Sweep(std::chrono::steady_clock::now()) == 0);
        CHECK(c->IsOpen());

        const auto later = std::chrono::steady_clock::now() +
                           std::chrono::seconds(61);
        CHECK(table.Sweep(later) == 1);
        io.poll();
        CHECK(!c->IsOpen());
        // An idle Sweep is NOT a capacity eviction.
        CHECK(table.Evictions() == 2);

        // ---- LRU selection: at capacity the LEAST RECENTLY ACTIVE flow is
        //      evicted, and a table hit refreshes recency. A capacity-1 table
        //      cannot distinguish LRU from an arbitrary pick. ----
        {
            relay::UdpFlowTable lru(2, std::chrono::seconds(60));
            auto la = lru.GetOrCreate(key_a, io);
            auto lb = lru.GetOrCreate(key_b, io);
            CHECK(nullptr != la);
            CHECK(nullptr != lb);
            CHECK(2 == lru.Size());
            const auto now = std::chrono::steady_clock::now();
            la->Touch(now - std::chrono::seconds(2));
            lb->Touch(now - std::chrono::seconds(1));
            auto refreshed = lru.GetOrCreate(key_a, io);  // hit -> A is MRU
            CHECK(refreshed.get() == la.get());
            relay::UdpRelay::FlowKey key_c = key_a;
            key_c.client_port = 5002;
            auto lc = lru.GetOrCreate(key_c, io);         // full: evict LRU
            CHECK(nullptr != lc);
            CHECK(2 == lru.Size());
            CHECK(la->IsOpen());    // refreshed by the hit -> kept
            CHECK(!lb->IsOpen());   // least recently active -> evicted
            io.poll();
        }

        // ---- batch304: intrusive LRU. Three flows, touch order A, B, C;
        //      eviction takes the least recently active one, and a stale
        //      Touch on an evicted relay must not corrupt the list. ----
        {
            relay::UdpFlowTable lru3(3, std::chrono::seconds(60));
            relay::UdpRelay::FlowKey k1 = key_a;
            relay::UdpRelay::FlowKey k2 = key_a;
            k2.client_port = 6001;
            relay::UdpRelay::FlowKey k3 = key_a;
            k3.client_port = 6002;
            relay::UdpRelay::FlowKey k4 = key_a;
            k4.client_port = 6003;
            auto r1 = lru3.GetOrCreate(k1, io);
            auto r2 = lru3.GetOrCreate(k2, io);
            auto r3 = lru3.GetOrCreate(k3, io);
            CHECK(nullptr != r1 && nullptr != r2 && nullptr != r3);
            const auto now = std::chrono::steady_clock::now();
            r1->Touch(now - std::chrono::seconds(3));   // LRU
            r2->Touch(now - std::chrono::seconds(2));
            r3->Touch(now - std::chrono::seconds(1));   // MRU
            auto r4 = lru3.GetOrCreate(k4, io);         // evicts r1
            CHECK(nullptr != r4);
            CHECK(!r1->IsOpen());
            CHECK(r2->IsOpen());
            CHECK(r3->IsOpen());
            // A stale Touch on the evicted relay must be a no-op.
            r1->Touch(now);
            CHECK(3 == lru3.Size());
            // The next eviction takes r2 (now the LRU), not r3.
            auto r5 = lru3.GetOrCreate(k1, io);
            CHECK(nullptr != r5);
            CHECK(!r2->IsOpen());
            CHECK(r3->IsOpen());
            io.poll();
        }

        // capacity 0 disables forwarding outright and must not blow up the
        // eviction path (dereferencing end()).
        relay::UdpFlowTable zero(0, std::chrono::seconds(60));
        CHECK(nullptr == zero.GetOrCreate(key_a, io));

        // A v6 flow needs a v6 socket; GetOrCreate must succeed (a family
        // mismatch fails the connect and returns nullptr).
        const net::IpAddress client6 = net::IpAddress::FromV6(
            std::array<uint8_t, 16>{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0,
                                    0, 0, 0, 0, 0, 1}.data());
        relay::UdpRelay::FlowKey key6{};
        key6.client_ip = client6;
        key6.remote_ip = net::IpAddress::FromV6(
            std::array<uint8_t, 16>{0, 0, 0, 0, 0, 0, 0, 0,
                                    0, 0, 0, 0, 0, 0, 0, 1}.data());  // ::1
        key6.client_port = 5002;
        key6.remote_port = 53;
        relay::UdpFlowTable t6(4, std::chrono::seconds(60));
        CHECK(nullptr != t6.GetOrCreate(key6, io));
        io.poll();

        // ---- Oversized upstream datagram support ----
        // (a) Loopback physically carries a 4096-byte datagram as one
        //     unit (no hidden MTU fragmentation on the host).
        {
            asio::ip::udp::socket src(io,
                                      asio::ip::udp::endpoint(
                                          asio::ip::udp::v4(), 0));
            asio::ip::udp::socket dst(io,
                                      asio::ip::udp::endpoint(
                                          asio::ip::udp::v4(), 0));
            const asio::ip::udp::endpoint dst_ep(
                asio::ip::address_v4::loopback(),
                dst.local_endpoint().port());
            std::error_code err;
            src.connect(dst_ep, err);
            CHECK(!err);
            std::vector<uint8_t> big(4096, 0x42);
            const size_t sent = src.send(asio::buffer(big), 0, err);
            CHECK(!err);
            CHECK(sent == big.size());
            std::array<uint8_t, 8192> buf{};
            const size_t recvd = dst.receive(asio::buffer(buf), 0, err);
            CHECK(!err);
            CHECK(recvd == big.size());
        }
        // (b) The relay's receive buffer must be sized for the datagrams
        //     real clients expect intact (EDNS0 4096, DNSSEC, TFTP) - a
        //     regression down to 2048 silently truncates those replies.
        static_assert(relay::UdpRelay::kRecvBufBytes >= 4096,
                      "recv buffer must carry EDNS0/DFSSEC/TFTP datagrams");

        std::fprintf(stderr, "udp_relay: all checks passed\n");
        return 0;
    }

    /// batch316: the flow hash must SPREAD keys. The old hash folded the
    /// client port into bits 16..31 only, and MSVC's unordered_map derives
    /// the bucket from the low bits - so one client opening many source
    /// ports to ONE server (a DNS resolver, a game server) put every flow
    /// in one bucket (measured: 4096 flows -> max_bucket=4096) and every
    /// per-packet lookup walked the whole chain. A good hash over 4096 keys
    /// and >=4096 buckets cannot leave a bucket anywhere near 64 entries.
    int TestFlowHashSpreadsBuckets() {
        const auto max_bucket = [](const auto& m) {
            size_t worst = 0;
            for (size_t b = 0; b < m.bucket_count(); ++b) {
                if (m.bucket_size(b) > worst) worst = m.bucket_size(b);
            }
            return worst;
        };
        using Map = std::unordered_map<relay::UdpRelay::FlowKey, int,
                                       relay::UdpRelay::FlowKeyHash>;
        const auto make_key = [](uint8_t client_last, uint16_t client_port,
                                 uint16_t remote_port) {
            relay::UdpRelay::FlowKey key{};
            key.client_ip = net::IpAddress::FromV4BigEndian(
                std::array<uint8_t, 4>{192, 168, 0, client_last}.data());
            key.remote_ip = net::IpAddress::FromV4BigEndian(
                std::array<uint8_t, 4>{8, 8, 4, 4}.data());
            key.client_port = client_port;
            key.remote_port = remote_port;
            return key;
        };
        {
            // One client, one server, 4096 source ports - the DNS shape.
            Map m;
            m.reserve(4096);
            for (uint32_t i = 0; i < 4096; ++i) {
                m.emplace(make_key(9, static_cast<uint16_t>(40000 + i), 53), 1);
            }
            std::fprintf(stderr, "[b316] client-port buckets=%zu max=%zu\n",
                         m.bucket_count(), max_bucket(m));
            CHECK(max_bucket(m) <= 64);
        }
        {
            // One client, one server address, 4096 remote ports.
            Map m;
            m.reserve(4096);
            for (uint32_t i = 0; i < 4096; ++i) {
                m.emplace(make_key(9, 40000, static_cast<uint16_t>(1000 + i)), 1);
            }
            std::fprintf(stderr, "[b316] remote-port buckets=%zu max=%zu\n",
                         m.bucket_count(), max_bucket(m));
            CHECK(max_bucket(m) <= 64);
        }
        {
            // 4096 clients, one server.
            Map m;
            m.reserve(4096);
            for (uint32_t i = 0; i < 4096; ++i) {
                const uint8_t last = static_cast<uint8_t>((i & 0xFF) + 1);
                const uint16_t port = static_cast<uint16_t>(40000 + (i >> 8));
                m.emplace(make_key(last, port, 53), 1);
            }
            std::fprintf(stderr, "[b316] client-ip buckets=%zu max=%zu\n",
                         m.bucket_count(), max_bucket(m));
            CHECK(max_bucket(m) <= 64);
        }
        return 0;
    }
}  // namespace vgww

int main() {
    if (const int rc = vgww::RunTests()) return rc;
    return vgww::TestFlowHashSpreadsBuckets();
}
