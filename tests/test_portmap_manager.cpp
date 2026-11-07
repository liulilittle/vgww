// ============================================================================
// test_portmap_manager.cpp - H4 lifecycle regression:
//   * Start -> Stop -> Start must accept WAN connections again (io_context
//     needs restart() after stop()).
//   * The accept loop must not leak through a self-captured shared_ptr
//     cycle: LiveAcceptLoops() returns to 0 once the rule is gone/stopped.
//   * Stop() is idempotent (no hang, no double free).
// ============================================================================
#include <winsock2.h>
#include <ws2ipdef.h>
#include <windows.h>

#include <asio.hpp>
#include <xtcp/buf/bufref.h>
#include <xtcp/core/stack.h>
#include <xtcp/ndi.h>

#include "relay/portmap_manager.h"
#include "web/web_api.h"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <thread>

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

    /// inet_addr numeric convention (first octet in the LOW byte), matching
    /// the config parser and the manager's dotted-quad reconstruction.
    constexpr uint32_t kGatewayIp =
        (192u) | (0u << 8) | (168u << 16) | (40u << 24);

    /// Absorbs every stack-emitted packet: the manager's reverse dial only
    /// needs Connect() to return a conn id, not a real handshake.
    class NullBackend final : public xtcp::ndi::Backend {
    public:
        void SetRxHandler(xtcp::ndi::RxHandler) noexcept override {}
        xtcp::ndi::BackendCaps Caps() const noexcept override {
            return xtcp::ndi::kCapNone;
        }
        bool Tx(xtcp::ndi::Packet&&) noexcept override { return true; }
    };

    uint16_t ProbeFreePort() {
        asio::io_context io;
        asio::ip::tcp::acceptor probe(io);
        std::error_code ec;
        probe.open(asio::ip::tcp::v4(), ec);
        if (!ec) {
            probe.bind(asio::ip::tcp::endpoint(
                           asio::ip::address_v4::loopback(), 0),
                       ec);
        }
        uint16_t port = 0;
        if (!ec) {
            port = probe.local_endpoint().port();
        }
        probe.close(ec);
        return port;
    }

    bool TryConnect(uint16_t port) {
        asio::io_context io;
        asio::ip::tcp::socket sock(io);
        std::error_code ec;
        sock.connect(asio::ip::tcp::endpoint(
                         asio::ip::make_address("127.0.0.1"), port),
                     ec);
        return !ec;
    }

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

    void TestRestartAndLoopLifetime() {
        xtcp::buf::InitPools();

        NullBackend backend;
        xtcp::XtcpStack stack(&backend);
        stack.SetMaxConnections(16);

        vgww::core::Config config;
        config.gateway.ipv4 = kGatewayIp;
        config.gateway.mask = (0u) | (0u << 8) | (255u << 16) | (255u << 24);
        config.gateway.mac = {0x30, 0xFC, 0x68, 0x88, 0xB4, 0xA9};

        const uint16_t wan_port = ProbeFreePort();
        CHECK(0 != wan_port);
        vgww::web::RuleStore::Instance().AddPortMap(
            {"tcp", wan_port, "127.0.0.1", 45678});

        auto& manager = vgww::relay::PortMapManager::Instance();
        const auto send_to_lan = [](uint64_t, const uint8_t*, uint32_t) {
            return true;
        };
        const auto teardown = [](uint64_t, bool) {};

        // Cycle 1: bind, accept, dial.
        manager.Start(&stack, config, send_to_lan, teardown);
        CHECK(WaitFor([&] { return manager.LiveAcceptLoops() >= 1; }, 3000));
        CHECK(WaitFor([&] { return TryConnect(wan_port); }, 5000));
        CHECK(WaitFor(
            [&] { return manager.GetStats().accepted.load() >= 1; }, 5000));

        manager.Stop();
        // H4: the loop chain must be freed, not leaked through a cycle.
        CHECK(0 == manager.LiveAcceptLoops());
        manager.Stop();  // idempotent: no hang, no double free
        CHECK(0 == manager.LiveAcceptLoops());

        // Cycle 2 (H4): the recycled io_context must drive again after
        // io_.restart(); without it, async_accept never completes and the
        // accepted counter stays frozen.
        manager.Start(&stack, config, send_to_lan, teardown);
        CHECK(WaitFor([&] { return manager.LiveAcceptLoops() >= 1; }, 3000));
        CHECK(WaitFor([&] { return TryConnect(wan_port); }, 5000));
        CHECK(WaitFor(
            [&] { return manager.GetStats().accepted.load() >= 2; }, 5000));
        manager.Stop();
        CHECK(0 == manager.LiveAcceptLoops());

        vgww::web::RuleStore::Instance().RemovePortMap(0);
        std::fprintf(stderr,
                     "[portmap] accepted=%llu dial_failed=%llu errors=%llu\n",
                     static_cast<unsigned long long>(
                         manager.GetStats().accepted.load()),
                     static_cast<unsigned long long>(
                         manager.GetStats().dial_failed.load()),
                     static_cast<unsigned long long>(
                         manager.GetStats().accept_errors.load()));
    }

    /// C6: OnStackData must report the truth - a packet that was actually
    /// queued returns true, and only a packet refused by the hard cap is
    /// dropped+counted. The old enqueue-then-test report made the 64th packet
    /// (already queued) return false: the stack saw a spurious window-0.
    void TestOnStackDataBoundary() {
        auto& manager = vgww::relay::PortMapManager::Instance();
        manager.Stop();  // idle: the queue is drained nowhere, so it holds
        const uint64_t dropped_before = manager.DroppedPackets();
        uint8_t byte = 1;
        // Exactly 64 fit (the hard cap); every admission reports true.
        for (int i = 0; i < 64; ++i) {
            CHECK(manager.OnStackData(0x1234, &byte, 1));
        }
        // The 65th is TRULY refused (nothing enqueued) and counted.
        CHECK(!manager.OnStackData(0x1234, &byte, 1));
        CHECK(manager.DroppedPackets() == dropped_before + 1);
        std::fprintf(stderr, "[portmap] C6 on-stack boundary ok\n");
    }

    /// C1: one drain feeds two+ packets to the same WAN socket; asio forbids
    /// concurrent composed async_write on one socket. The write_in_flight_
    /// gate must keep at most ONE outstanding write per relay and preserve
    /// byte order (FIFO) end to end.
    void TestSingleOutstandingWanWrite() {
        xtcp::buf::InitPools();
        NullBackend backend;
        xtcp::XtcpStack stack(&backend);
        stack.SetMaxConnections(16);

        vgww::core::Config config;
        config.gateway.ipv4 = kGatewayIp;
        config.gateway.mask = (0u) | (0u << 8) | (255u << 16) | (255u << 24);
        config.gateway.mac = {0x30, 0xFC, 0x68, 0x88, 0xB4, 0xA9};

        const uint16_t wan_port = ProbeFreePort();
        CHECK(0 != wan_port);
        vgww::web::RuleStore::Instance().AddPortMap(
            {"tcp", wan_port, "127.0.0.1", 45678});

        auto& manager = vgww::relay::PortMapManager::Instance();
        manager.Stop();
        const auto send_to_lan = [](uint64_t, const uint8_t*, uint32_t) {
            return true;
        };
        const auto teardown = [](uint64_t, bool) {};

        manager.Start(&stack, config, send_to_lan, teardown);
        CHECK(WaitFor([&] { return manager.LiveAcceptLoops() >= 1; }, 3000));

        // batch74: same defect batch34q fixed further down, in a case that
        // was missed. The accept callback runs on the manager thread and can
        // complete before connect() returns, so a baseline sampled AFTER
        // connect() already contains the increment and the predicate
        // "accepted > before" then never fires on a healthy manager
        // (reproduced 2/20 standalone, 2/12 under ctest).
        //
        // Rather than sample the baseline earlier (batch34q's fix, still a
        // before/after delta across an async boundary), this waits on the
        // OBSERVABLE END STATE: Stop() zeroes last_relay_conn_id_, and the
        // accept path stores it before returning, so a non-zero id proves
        // THIS connect() was accepted - no sampling race, and no dependence
        // on counter history carried across Start/Stop cycles.
        asio::io_context io;
        asio::ip::tcp::socket client(io);
        std::error_code ec;
        client.connect(asio::ip::tcp::endpoint(
                           asio::ip::make_address("127.0.0.1"), wan_port),
                       ec);
        CHECK(!ec);
        CHECK(WaitFor([&] { return 0 != manager.LastRelayConnId(); }, 5000));
        const uint64_t conn_id = manager.LastRelayConnId();
        CHECK(0 != conn_id);

        // Established: the drain now pumps LAN->WAN data through the socket.
        manager.OnStackState(conn_id, 4);
        // Give the manager's RunLoop a few iterations to process the state
        // event (drain drops packets for not-yet-established relays).
        std::this_thread::sleep_for(std::chrono::milliseconds(300));

        // Inject many packets in rounds with pauses so the bounded data
        // queue drains between rounds; each round's burst must still only
        // start ONE outstanding async_write (the write_in_flight_ gate).
        std::vector<uint8_t> payload(256);
        std::vector<uint8_t> expected;
        uint64_t ordinal = 0;
        for (int round = 0; round < 8; ++round) {
            for (int i = 0; i < 32; ++i) {
                for (size_t j = 0; j < payload.size(); ++j) {
                    payload[j] = static_cast<uint8_t>((ordinal * 7 + j) & 0xFF);
                }
                if (manager.OnStackData(
                        conn_id, payload.data(),
                        static_cast<uint32_t>(payload.size()))) {
                    expected.insert(expected.end(), payload.begin(),
                                    payload.end());
                }
                ++ordinal;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(30));
        }
        CHECK(!expected.empty());

        std::vector<uint8_t> received;
        std::error_code rerr;
        client.non_blocking(true, rerr);
        CHECK(!rerr);
        const auto deadline =
            std::chrono::steady_clock::now() + std::chrono::seconds(10);
        while (received.size() < expected.size() &&
               std::chrono::steady_clock::now() < deadline) {
            std::array<uint8_t, 65536> buf{};
            std::error_code e;
            const size_t n = client.read_some(asio::buffer(buf), e);
            if (!e && n > 0) {
                received.insert(received.end(), buf.begin(),
                                buf.begin() + n);
            } else if (e == asio::error::would_block ||
                       e == asio::error::try_again) {
                std::this_thread::sleep_for(std::chrono::milliseconds(5));
            } else {
                break;
            }
        }
        CHECK(received.size() == expected.size());
        CHECK(received == expected);
        CHECK(manager.GetStats().wan_write_peak.load() <= 1);
        std::fprintf(stderr,
                     "[portmap] C1 peak-outstanding-writes=%llu sent=%llu "
                     "recvd=%llu\n",
                     static_cast<unsigned long long>(
                         manager.GetStats().wan_write_peak.load()),
                     static_cast<unsigned long long>(expected.size()),
                     static_cast<unsigned long long>(received.size()));

        manager.Stop();
        vgww::web::RuleStore::Instance().RemovePortMap(0);
    }

    /// C5: WAN->LAN backpressure. A LanSender returning false (peer window
    /// full / queue capped) must PAUSE the WAN receive chain - further WAN
    /// data must not be read (and buffered) until the queue drains. Once the
    /// sender accepts again, ResumePausedWanReads (the data plane's drain
    /// signal) re-arms the chain.
    void TestWanReadBackpressure() {
        xtcp::buf::InitPools();
        NullBackend backend;
        xtcp::XtcpStack stack(&backend);
        stack.SetMaxConnections(16);

        vgww::core::Config config;
        config.gateway.ipv4 = kGatewayIp;
        config.gateway.mask = (0u) | (0u << 8) | (255u << 16) | (255u << 24);
        config.gateway.mac = {0x30, 0xFC, 0x68, 0x88, 0xB4, 0xA9};

        const uint16_t wan_port = ProbeFreePort();
        CHECK(0 != wan_port);
        vgww::web::RuleStore::Instance().AddPortMap(
            {"tcp", wan_port, "127.0.0.1", 45678});

        std::atomic<bool> accepting{false};
        std::atomic<uint64_t> lan_calls{0};
        auto send_to_lan = [&](uint64_t, const uint8_t*, uint32_t) -> bool {
            lan_calls.fetch_add(1, std::memory_order_relaxed);
            return accepting.load(std::memory_order_relaxed);
        };
        const auto teardown = [](uint64_t, bool) {};

        auto& manager = vgww::relay::PortMapManager::Instance();
        manager.Stop();
        manager.Start(&stack, config, send_to_lan, teardown);
        CHECK(WaitFor([&] { return manager.LiveAcceptLoops() >= 1; }, 3000));

        // batch34q: read the baseline BEFORE connecting. The accept callback
        // runs on the manager thread and can complete before connect()
        // returns; a baseline sampled afterwards already contains the
        // increment, so the wait below could never succeed (flaky test).
        const uint64_t accepted_before = manager.GetStats().accepted.load();

        asio::io_context io;
        asio::ip::tcp::socket client(io);
        std::error_code ec;
        client.connect(asio::ip::tcp::endpoint(
                           asio::ip::make_address("127.0.0.1"), wan_port),
                       ec);
        CHECK(!ec);
        CHECK(WaitFor([&] {
            return manager.GetStats().accepted.load() > accepted_before;
        }, 5000));
        const uint64_t conn_id = manager.LastRelayConnId();

        manager.OnStackState(conn_id, 4);  // established -> ArmWanRead
        // Give the RunLoop time to process the state event (arm the read).
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
        // First WAN datagram: the sender rejects it -> the chain pauses.
        std::error_code send_err;
        client.send(asio::buffer("aaa", 3), 0, send_err);
        CHECK(!send_err);
        CHECK(WaitFor([&] { return lan_calls.load() >= 1; }, 3000));

        // More WAN data arrives while the LAN side is still full: the receive
        // chain must stay HARD-paused (no further send_to_lan_ invocation,
        // no matter how much data is buffered).
        client.send(asio::buffer("bbb", 3), 0, ec);
        CHECK(!ec);
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
        CHECK(lan_calls.load() == 1);

        // Queue drains (accepted): the drain signal re-arms the chain, which
        // consumes the buffered WAN datagram.
        accepting.store(true, std::memory_order_relaxed);
        manager.ResumePausedWanReads();
        CHECK(WaitFor([&] { return lan_calls.load() >= 2; }, 3000));

        manager.Stop();
        vgww::web::RuleStore::Instance().RemovePortMap(0);
    }

// batch83: the data plane implements TCP forwarding ONLY. A "udp" rule must
// never bind a TCP acceptor on the WAN port: that would both fake a feature the
// relay cannot honor and squat the port against a real UDP service.
//
// Three layers enforce this today (native form offers tcp only,
// POST /api/portmap answers 400 for non-tcp, ApplyRules skips non-tcp), but the
// manager layer - the one that actually owns the sockets - had NO test. Someone
// "helpfully" widening the accept path would bind a TCP listener for a UDP rule
// and every existing test would stay green.
//
// The assertion is deterministic, not timing based: LiveAcceptLoops() is a
// process-wide count of live accept chains, so a UDP-only rule set must leave it
// at 0 while a TCP rule drives it to 1.
void TestB83UdpRuleNeverBindsTcpAcceptor() {
    NullBackend backend;
    xtcp::XtcpStack stack(&backend);
    stack.SetMaxConnections(16);

    vgww::core::Config config;
    config.gateway.ipv4 = kGatewayIp;
    config.gateway.mask = (0u) | (0u << 8) | (255u << 16) | (255u << 24);
    config.gateway.mac = {0x30, 0xFC, 0x68, 0x88, 0xB4, 0xA9};

    auto& manager = vgww::relay::PortMapManager::Instance();
    manager.Stop();
    const auto send_to_lan = [](uint64_t, const uint8_t*, uint32_t) {
        return true;
    };
    const auto teardown = [](uint64_t, bool) {};

    vgww::web::RuleStore::Instance().AttachFile("");
    vgww::web::RuleStore::Instance().Clear();
    CHECK(0 == vgww::relay::PortMapManager::LiveAcceptLoops());

    // (1) A UDP-only rule must NOT create an accept chain, and must not even be
    //     reported as a failed bind (it is skipped by design, not attempted).
    const uint16_t udp_port = ProbeFreePort();
    CHECK(0 != udp_port);
    vgww::web::RuleStore::Instance().AddPortMap(
        {"udp", udp_port, "127.0.0.1", 45678});

    // batch312: bind_failed is cumulative across the process; assert the
    // DELTA so an earlier test that exercised a failed bind cannot break
    // this one (the rule must not even attempt a bind).
    const uint64_t bind_failed_before_udp =
        manager.GetStats().bind_failed.load();
    manager.Start(&stack, config, send_to_lan, teardown);
    // Give the manager the same window a real TCP rule needs to come up.
    const bool udp_spawned_a_loop =
        WaitFor([&] { return manager.LiveAcceptLoops() >= 1; }, 1500);
    const uint64_t bind_failed_udp =
        manager.GetStats().bind_failed.load() - bind_failed_before_udp;
    std::printf("B83 udp-only: accept_loops=%zu spawned=%d bind_failed=%llu\n",
                vgww::relay::PortMapManager::LiveAcceptLoops(),
                udp_spawned_a_loop ? 1 : 0,
                static_cast<unsigned long long>(bind_failed_udp));
    CHECK(!udp_spawned_a_loop);                       // no TCP acceptor
    CHECK(0 == vgww::relay::PortMapManager::LiveAcceptLoops());
    CHECK(0 == bind_failed_udp);                      // skipped, not attempted
    // NOTE: binding a UDP socket here to prove the port is "still free" would
    // be a DIFFERENT assertion with a different failure mode - ProbeFreePort()
    // reserves the port over TCP, so its UDP side has no reservation at all and
    // any unrelated process can hold it. What this test owns is the accept-chain
    // count above; port availability is not its contract.
    manager.Stop();
    CHECK(0 == vgww::relay::PortMapManager::LiveAcceptLoops());

    // (2) Positive control: the SAME manager with a TCP rule on the SAME port
    //     DOES create the chain. Without this the test above could pass simply
    //     because the manager never starts at all.
    vgww::web::RuleStore::Instance().Clear();
    vgww::web::RuleStore::Instance().AddPortMap(
        {"tcp", udp_port, "127.0.0.1", 45678});
    manager.Start(&stack, config, send_to_lan, teardown);
    const bool tcp_spawned_a_loop =
        WaitFor([&] { return manager.LiveAcceptLoops() >= 1; }, 3000);
    std::printf("B83 tcp-control: accept_loops=%zu spawned=%d\n",
                vgww::relay::PortMapManager::LiveAcceptLoops(),
                tcp_spawned_a_loop ? 1 : 0);
    CHECK(tcp_spawned_a_loop);
    manager.Stop();
    CHECK(0 == vgww::relay::PortMapManager::LiveAcceptLoops());

    vgww::web::RuleStore::Instance().Clear();
}

// batch86: the accept path dials the LAN client by parsing rule_copy.lan_ip
// with sscanf_s("%u.%u.%u.%u"). That return value used to be ignored: a short
// parse left the zero-initialised octets in place, so the stack was asked to
// connect to 0.0.0.0 instead of the rule being rejected - a plausible-but-broken
// endpoint rather than an error.
//
// Every shipped producer validates the address first (POST /api/portmap and the
// rules-file loader both run ParseIpv4, and the native form formats a parsed
// value), so this guard is a redundancy. It still has to be TESTED, because the
// failure mode is a wrong ADDRESS, not an error: a future fourth producer that
// writes RuleStore::AddPortMap directly - which performs no address validation,
// as this test does - would dial 0.0.0.0 silently and nothing would notice.
//
// Assertion shape: the WAN accept must happen (so the accept loop is provably
// alive and the rule was really matched), and then the DIAL must be refused and
// COUNTED, with `accepted` unchanged. Counting is what separates "rejected" from
// "silently did nothing".
void TestB86MalformedLanIpIsRefusedNotZeroDialed() {
    NullBackend backend;
    xtcp::XtcpStack stack(&backend);
    stack.SetMaxConnections(16);

    vgww::core::Config config;
    config.gateway.ipv4 = kGatewayIp;
    config.gateway.mask = (0u) | (0u << 8) | (255u << 16) | (255u << 24);
    config.gateway.mac = {0x30, 0xFC, 0x68, 0x88, 0xB4, 0xA9};

    auto& manager = vgww::relay::PortMapManager::Instance();
    manager.Stop();
    const auto send_to_lan = [](uint64_t, const uint8_t*, uint32_t) {
        return true;
    };
    const auto teardown = [](uint64_t, bool) {};

    vgww::web::RuleStore::Instance().AttachFile("");
    vgww::web::RuleStore::Instance().Clear();

    const uint16_t wan_port = ProbeFreePort();
    CHECK(0 != wan_port);
    // Bypass the route-layer validation on purpose: this is exactly the
    // "fourth producer" the guard exists for.
    vgww::web::RuleStore::Instance().AddPortMap(
        {"tcp", wan_port, "not-an-ip", 45678});

    const uint64_t dial_failed_before = manager.GetStats().dial_failed.load();
    const uint64_t accepted_before = manager.GetStats().accepted.load();

    manager.Start(&stack, config, send_to_lan, teardown);
    CHECK(WaitFor([&] { return manager.LiveAcceptLoops() >= 1; }, 3000));
    // Drive one accepted WAN connection through the dial path.
    CHECK(WaitFor([&] { return TryConnect(wan_port); }, 5000));
    const bool counted = WaitFor(
        [&] {
            return manager.GetStats().dial_failed.load() > dial_failed_before;
        },
        5000);
    std::printf(
        "B86 malformed lan_ip: accept_loops=%zu dial_failed=%llu "
        "(was %llu) accepted=%llu (was %llu)\n",
        vgww::relay::PortMapManager::LiveAcceptLoops(),
        static_cast<unsigned long long>(manager.GetStats().dial_failed.load()),
        static_cast<unsigned long long>(dial_failed_before),
        static_cast<unsigned long long>(manager.GetStats().accepted.load()),
        static_cast<unsigned long long>(accepted_before));
    CHECK(counted);  // the dial was refused AND observed
    CHECK(0 == manager.GetStats().accepted.load() - accepted_before);
    manager.Stop();
    CHECK(0 == vgww::relay::PortMapManager::LiveAcceptLoops());

    // Positive control: the same manager and port with a WELL-FORMED address
    // must reach the stack (conn_id != 0 -> accepted increments). Without this
    // the assertions above could pass because the dial never happens at all.
    vgww::web::RuleStore::Instance().Clear();
    vgww::web::RuleStore::Instance().AddPortMap(
        {"tcp", wan_port, "127.0.0.1", 45678});
    const uint64_t dial_failed_before_ok = manager.GetStats().dial_failed.load();
    manager.Start(&stack, config, send_to_lan, teardown);
    CHECK(WaitFor([&] { return manager.LiveAcceptLoops() >= 1; }, 3000));
    CHECK(WaitFor([&] { return TryConnect(wan_port); }, 5000));
    const bool dialed = WaitFor(
        [&] { return manager.GetStats().accepted.load() > accepted_before; },
        5000);
    std::printf(
        "B86 valid lan_ip: dial_failed=%llu (was %llu) accepted=%llu\n",
        static_cast<unsigned long long>(manager.GetStats().dial_failed.load()),
        static_cast<unsigned long long>(dial_failed_before_ok),
        static_cast<unsigned long long>(manager.GetStats().accepted.load()));
    CHECK(dialed);
    CHECK(0 == manager.GetStats().dial_failed.load() - dial_failed_before_ok);
    manager.Stop();
    CHECK(0 == vgww::relay::PortMapManager::LiveAcceptLoops());

    vgww::web::RuleStore::Instance().Clear();
}

/// batch312: ApplyRules is change-driven (RuleStore::Rev) instead of
/// rebuilding the wanted set on every RunLoop pass (~10/s, allocating in
/// proportion to the rule count for the life of the process), but a failed
/// bind must still be retried without a rule change - the WAN port may be
/// released by another process later.
void TestB312ApplyRulesIsChangeDriven() {
    NullBackend backend;
    xtcp::XtcpStack stack(&backend);
    stack.SetMaxConnections(16);

    vgww::core::Config config;
    config.gateway.ipv4 = kGatewayIp;
    config.gateway.mask = (0u) | (0u << 8) | (255u << 16) | (255u << 24);
    config.gateway.mac = {0x30, 0xFC, 0x68, 0x88, 0xB4, 0xA9};

    auto& manager = vgww::relay::PortMapManager::Instance();
    auto& store = vgww::web::RuleStore::Instance();
    manager.Stop();
    store.AttachFile("");
    store.Clear();

    const auto send_to_lan = [](uint64_t, const uint8_t*, uint32_t) {
        return true;
    };
    const auto teardown = [](uint64_t, bool) {};

    // (1) An unchanged (empty) rule set must not rebuild on every pass. The
    //     counter is cumulative across the process, so wait for THIS start's
    //     first pass (a delta), not for an absolute >= 1.
    const uint64_t passes_before_start =
        manager.GetStats().apply_passes.load();
    manager.Start(&stack, config, send_to_lan, teardown);
    CHECK(WaitFor([&] {
        return manager.GetStats().apply_passes.load() > passes_before_start;
    }, 3000));
    const uint64_t settled = manager.GetStats().apply_passes.load();
    std::this_thread::sleep_for(std::chrono::milliseconds(1500));
    const uint64_t idle = manager.GetStats().apply_passes.load();
    std::printf("B312 idle: apply_passes %llu -> %llu\n",
                static_cast<unsigned long long>(settled),
                static_cast<unsigned long long>(idle));
    CHECK(idle == settled);   // nothing changed: no rebuild at all

    // (2) A rule change must still be picked up within a poll.
    const uint16_t wan_port = ProbeFreePort();
    CHECK(0 != wan_port);
    store.AddPortMap({"tcp", wan_port, "127.0.0.1", 45678});
    CHECK(WaitFor([&] {
        return manager.GetStats().apply_passes.load() > idle;
    }, 3000));
    CHECK(WaitFor([&] { return vgww::relay::PortMapManager::LiveAcceptLoops() >= 1; }, 3000));
    const uint64_t after_add = manager.GetStats().apply_passes.load();
    std::this_thread::sleep_for(std::chrono::milliseconds(1500));
    CHECK(manager.GetStats().apply_passes.load() == after_add);

    manager.Stop();
    store.Clear();

    // (3) A failed bind must be retried WITHOUT a rule change: hold the port
    //     exclusively, let the manager fail to bind it, then release it. The
    //     manager must bind on a later pass and go quiet again afterwards.
    asio::io_context io;
    asio::ip::tcp::acceptor holder(io);
    std::error_code ec;
    holder.open(asio::ip::tcp::v4(), ec);
    CHECK(!ec);
    BOOL exclusive = TRUE;
    CHECK(0 == ::setsockopt(holder.native_handle(), SOL_SOCKET,
                            SO_EXCLUSIVEADDRUSE,
                            reinterpret_cast<const char*>(&exclusive),
                            sizeof(exclusive)));
    holder.bind(asio::ip::tcp::endpoint(asio::ip::address_v4::any(), 0), ec);
    CHECK(!ec);
    holder.listen(1, ec);
    CHECK(!ec);
    const uint16_t held_port = holder.local_endpoint().port();
    CHECK(0 != held_port);
    store.AddPortMap({"tcp", held_port, "127.0.0.1", 45678});

    const uint64_t bind_failed_before = manager.GetStats().bind_failed.load();
    manager.Start(&stack, config, send_to_lan, teardown);
    CHECK(WaitFor([&] {
        return manager.GetStats().bind_failed.load() > bind_failed_before;
    }, 3000));
    const uint64_t retrying = manager.GetStats().apply_passes.load();
    std::this_thread::sleep_for(std::chrono::milliseconds(1500));
    const uint64_t retried = manager.GetStats().apply_passes.load();
    std::printf("B312 retry: apply_passes %llu -> %llu bind_failed=%llu\n",
                static_cast<unsigned long long>(retrying),
                static_cast<unsigned long long>(retried),
                static_cast<unsigned long long>(
                    manager.GetStats().bind_failed.load()));
    CHECK(retried > retrying);   // failed bind keeps being retried

    holder.close(ec);
    CHECK(WaitFor([&] { return vgww::relay::PortMapManager::LiveAcceptLoops() >= 1; }, 5000));
    const uint64_t bound = manager.GetStats().apply_passes.load();
    std::this_thread::sleep_for(std::chrono::milliseconds(1500));
    CHECK(manager.GetStats().apply_passes.load() == bound);  // quiet again

    manager.Stop();
    store.Clear();
}

}  // namespace

int main() {
    TestOnStackDataBoundary();
    TestRestartAndLoopLifetime();
    TestSingleOutstandingWanWrite();
    TestWanReadBackpressure();
    TestB83UdpRuleNeverBindsTcpAcceptor();
    TestB86MalformedLanIpIsRefusedNotZeroDialed();
    TestB312ApplyRulesIsChangeDriven();   // last: it fails one bind on purpose

    if (0 == g_failures) {
        std::puts("test_portmap_manager: ALL PASS");
        return 0;
    }
    std::fprintf(stderr, "test_portmap_manager: %d FAILURES\n", g_failures);
    return 1;
}
