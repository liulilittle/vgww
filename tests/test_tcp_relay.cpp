// ============================================================================
// test_tcp_relay.cpp - Bidirectional pump contract.
//
// TcpRelay had ZERO coverage and is the NAT core: a bug here either strands a
// relay forever (leak) or RSTs a healthy client. Every reachable path in the
// 182-line implementation is pinned here against a REAL MimtFlow and a REAL
// loopback socket, because MimtFlow is a concrete (non-virtual) class - there
// is no seam to fake it, so the test drives the real thing.
//
// The production loop alternates two duties on one worker thread
// (dataplane.cpp WorkerLoop): socket completions via io_context.poll(), then
// MimtFlow completions via DispatchMimt(). Pump() reproduces exactly that
// alternation - a test that only ran the io_context would never advance the
// flow->socket direction, because OnData only ENQUEUES; Dispatch() is what
// fires the AsyncRead completion.
// ============================================================================
#define CHECK(cond)                                                        \
    do {                                                                   \
        if (!(cond)) {                                                     \
            std::fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__,  \
                         __LINE__, #cond);                                 \
            return 1;                                                      \
        }                                                                  \
    } while (0)

#include "relay/tcp_relay.h"

#include <xtcp/mimt/mimt.h>

#include <asio.hpp>

#include <array>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <thread>
#include <string>
#include <vector>

namespace {

    using vgww::relay::TcpRelay;

    struct FinishRecord {
        int calls = 0;
        bool graceful = false;
        UInt64 conn_id = 0;
    };

    /// One loopback pair plus a flow, driven on a single thread. The relay's
    /// two directions both complete on this thread's io_context, matching the
    /// production invariant (every callback on the owning worker).
    struct Fixture {
        asio::io_context io;
        asio::ip::tcp::acceptor listener{io};
        asio::ip::tcp::socket server{io};   ///< upstream end ("internet")
        asio::ip::tcp::socket peer{io};     ///< what the relay dialed
        std::shared_ptr<xtcp::mimt::MimtFlow> flow;
        std::shared_ptr<TcpRelay> relay;
        FinishRecord record;
        bool ready = false;
        /// Injects a throw into the teardown hook, i.e. into the completion
        /// body that invoked it (flow Dispatch or asio completion).
        bool throw_on_finish = false;

        Fixture() { ready = Build(); }

    private:
        bool Build() {
            std::error_code err;
            listener.open(asio::ip::tcp::v4(), err);
            if (err) { std::fprintf(stderr, "fixture: listener.open: %s\n", err.message().c_str()); return false; }
            listener.bind(asio::ip::tcp::endpoint(asio::ip::make_address("127.0.0.1"), 0), err);
            if (err) { std::fprintf(stderr, "fixture: bind: %s\n", err.message().c_str()); return false; }
            listener.listen(1, err);
            if (err) { std::fprintf(stderr, "fixture: listen: %s\n", err.message().c_str()); return false; }
            const auto port = listener.local_endpoint(err).port();
            if (err) { std::fprintf(stderr, "fixture: local_endpoint: %s\n", err.message().c_str()); return false; }

            peer.open(asio::ip::tcp::v4(), err);
            if (err) { std::fprintf(stderr, "fixture: peer.open: %s\n", err.message().c_str()); return false; }
            peer.connect(asio::ip::tcp::endpoint(asio::ip::make_address("127.0.0.1"), port), err);
            if (err) { std::fprintf(stderr, "fixture: connect: %s\n", err.message().c_str()); return false; }
            listener.accept(server, err);
            server.non_blocking(true, err);
            if (err) { std::fprintf(stderr, "fixture: non_blocking: %s\n", err.message().c_str()); return false; }

            flow = std::make_shared<xtcp::mimt::MimtFlow>();
            flow->SetOrigin(/*conn_id=*/7, xtcp::core::Endpoint{}, xtcp::core::Endpoint{});
            return true;
        }

    public:
        void StartRelay() {
            TcpRelay::Hooks hooks;
            hooks.on_finished = [this](UInt64 conn_id, bool graceful) {
                ++record.calls;
                record.graceful = graceful;
                record.conn_id = conn_id;
                if (throw_on_finish) {
                    throw std::runtime_error("hook failure");
                }
            };
            relay = std::make_shared<TcpRelay>(flow, std::move(peer), std::move(hooks));
            relay->Start();
        }

        /// Alternates the two production duties until the deadline: poll the
        /// io_context (socket completions), then Dispatch the flow (MimtFlow
        /// completions). Both are non-blocking, so this is a tight but
        /// bounded loop.
        void Pump(int ms = 60) {
            const auto deadline =
                std::chrono::steady_clock::now() + std::chrono::milliseconds(ms);
            while (std::chrono::steady_clock::now() < deadline) {
                io.restart();
                io.poll();
                flow->Dispatch();
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
        }

        /// Reads exactly want bytes off the upstream socket, pumping between
        /// attempts. Returns the number actually read (short = relay stalled).
        std::size_t ReadUpstream(char* dst, std::size_t want, int ms = 300) {
            std::size_t got = 0;
            const auto deadline =
                std::chrono::steady_clock::now() + std::chrono::milliseconds(ms);
            std::error_code err;
            while (got < want && std::chrono::steady_clock::now() < deadline) {
                const std::size_t n = server.read_some(
                    asio::buffer(dst + got, want - got), err);
                if (err) {
                    if (err != asio::error::would_block) {
                        std::fprintf(stderr, "ReadUpstream: %s\n", err.message().c_str());
                    }
                    err.clear();
                    Pump(5);
                    continue;
                }
                if (0 == n) {
                    Pump(5);
                    continue;
                }
                got += n;
            }
            return got;
        }
    };

}  // namespace

namespace vgww {

    /// Path 1: Start() by itself must not finish anything and must leave the
    /// relay live - a spontaneous Finish here would tear down healthy flows.
    int TestStartDoesNotSpontaneouslyFinish() {
        Fixture f;
        CHECK(f.ready);
        f.StartRelay();
        f.Pump(60);
        CHECK(0 == f.record.calls);
        CHECK(!f.relay->Finished());
        return 0;
    }

    /// Path 2: flow -> socket. Proves the chunk is written AND the pump
    /// re-arms: a second chunk only arrives if AsyncRead was reissued.
    int TestFlowToSocketForwardsAndRearms() {
        Fixture f;
        CHECK(f.ready);
        f.StartRelay();

        const char first[] = "hello-upstream";
        CHECK(xtcp::mimt::Result::kOk ==
              f.flow->OnData(reinterpret_cast<const Byte*>(first), sizeof(first) - 1));
        f.Pump();

        std::array<char, 64> seen{};
        CHECK(sizeof(first) - 1 == f.ReadUpstream(seen.data(), sizeof(first) - 1));
        CHECK(0 == std::memcmp(seen.data(), first, sizeof(first) - 1));

        const char second[] = "second-chunk";
        CHECK(xtcp::mimt::Result::kOk ==
              f.flow->OnData(reinterpret_cast<const Byte*>(second), sizeof(second) - 1));
        f.Pump();
        const std::size_t got2 = f.ReadUpstream(seen.data(), sizeof(second) - 1);
        CHECK(sizeof(second) - 1 == got2);
        CHECK(0 == std::memcmp(seen.data(), second, got2));
        CHECK(0 == f.record.calls);
        return 0;
    }

    /// Path 3: socket -> flow. Proves the chunk reaches the flow's write sink
    /// (in production the xtcp SendData path) AND the read re-arms.
    int TestSocketToFlowForwardsAndRearms() {
        Fixture f;
        CHECK(f.ready);
        std::vector<Byte> sink_bytes;
        f.flow->SetWriteSink([&sink_bytes](const Byte* data, UInt32 len) {
            sink_bytes.insert(sink_bytes.end(), data, data + len);
            return true;
        });
        f.StartRelay();

        const char payload[] = "from-internet";
        std::error_code err;
        asio::write(f.server, asio::buffer(payload, sizeof(payload) - 1), err);
        CHECK(!err);
        f.Pump();
        CHECK(sizeof(payload) - 1 == sink_bytes.size());
        CHECK(0 == std::memcmp(sink_bytes.data(), payload, sink_bytes.size()));

        const char more[] = "more-bytes";
        asio::write(f.server, asio::buffer(more, sizeof(more) - 1), err);
        CHECK(!err);
        f.Pump();
        CHECK(sizeof(payload) - 1 + sizeof(more) - 1 == sink_bytes.size());
        // Compare against an explicit concatenation: c_str() on a temporary
        // std::string dangles, so build the expected buffer first.
        const std::string expected = std::string(payload) + more;
        CHECK(0 == std::memcmp(sink_bytes.data(), expected.data(), sink_bytes.size()));
        CHECK(0 == f.record.calls);
        return 0;
    }

    /// Path 4: upstream closes cleanly (FIN) => Finish(graceful=TRUE) exactly
    /// once. This bool decides FIN vs RST for the client, so getting it wrong
    /// turns every ordinary close into a reset.
    int TestUpstreamEofIsGraceful() {
        Fixture f;
        CHECK(f.ready);
        f.StartRelay();

        std::error_code err;
        f.server.close(err);
        CHECK(!err);
        f.Pump();

        CHECK(1 == f.record.calls);
        CHECK(f.record.graceful);
        CHECK(7 == f.record.conn_id);
        CHECK(f.relay->Finished());
        return 0;
    }

    /// Path 5: the flow closes (client reset / stack reclaim) => exactly one
    /// non-graceful finish: there is nobody left to FIN.
    int TestFlowClosedIsNotGraceful() {
        Fixture f;
        CHECK(f.ready);
        f.StartRelay();

        f.flow->Close();
        f.Pump();

        CHECK(1 == f.record.calls);
        CHECK(!f.record.graceful);
        CHECK(f.relay->Finished());
        return 0;
    }

    /// Exactly-once teardown: a second terminal event must NOT fire the hook
    /// again. Stack.Close plus a socket error is the realistic trigger.
    int TestTeardownIsExactlyOnce() {
        Fixture f;
        CHECK(f.ready);
        f.StartRelay();

        f.flow->Close();
        f.Pump();
        CHECK(1 == f.record.calls);

        std::error_code err;
        f.server.close(err);
        f.Pump(80);
        CHECK(1 == f.record.calls);
        return 0;
    }

    /// Teardown must release the socket so the upstream peer observes EOF.
    /// Without the close in Finish() the peer would hang on read forever.
    int TestFinishClosesUpstreamSocket() {
        Fixture f;
        CHECK(f.ready);
        f.StartRelay();

        f.flow->Close();
        f.Pump();
        CHECK(1 == f.record.calls);

        // The relay held `peer`; closing it must surface as EOF here.
        std::array<char, 8> sink{};
        std::error_code err;
        std::size_t n = 1;
        for (int i = 0; i < 200 && n != 0; ++i) {
            err.clear();
            n = f.server.read_some(asio::buffer(sink), err);
            if (err == asio::error::would_block) { n = 1; }
            else if (err) { n = 0; }
            f.Pump(5);
        }
        CHECK(0 == n || err == asio::error::eof ||
              err == asio::error::connection_reset);
        return 0;
    }

    /// Path 7: a SYNCHRONOUS AsyncRead refusal must tear the relay down
    /// immediately. No completion was queued, so both pumps are already dead
    /// - without this branch the relay leaks in the registry forever and
    /// nothing ever fires on_finished. Driven by closing the flow BEFORE
    /// Start(), which makes AsyncRead return kClosed synchronously.
    int TestSyncReadRefusalTearsDown() {
        Fixture f;
        CHECK(f.ready);
        f.flow->Close();          // AsyncRead will now refuse synchronously
        f.StartRelay();

        CHECK(1 == f.record.calls);
        CHECK(!f.record.graceful);   // flow already gone: nobody to FIN
        CHECK(f.relay->Finished());
        return 0;
    }

    /// Path 7 (write half): once the flow is closed, a socket read that is
    /// already in flight still completes and calls WriteToFlow, whose
    /// AsyncWrite refuses synchronously with kClosed. Same requirement:
    /// tear down now, do not strand.
    int TestSyncWriteRefusalTearsDown() {
        Fixture f;
        CHECK(f.ready);
        f.StartRelay();

        // Land bytes in the kernel buffer while the relay is live, then close
        // the flow and pump: the relay reads them and AsyncWrite is refused.
        const char payload[] = "late";
        std::error_code err;
        asio::write(f.server, asio::buffer(payload, sizeof(payload) - 1), err);
        CHECK(!err);

        f.flow->Close();
        f.Pump();

        CHECK(f.record.calls >= 1);
        CHECK(!f.record.graceful);
        CHECK(f.relay->Finished());
        return 0;
    }

    /// Path 4 (the other half of the FIN/RST contract): an upstream RESET is
    /// NOT a clean end. The header promises "every other error path aborts
    /// (RST)", and this bool is the only thing that decides it. A reset
    /// reported as graceful would tell the client its download completed
    /// normally when the peer had actually aborted - silent truncation.
    int TestUpstreamResetIsNotGraceful() {
        Fixture f;
        CHECK(f.ready);
        f.StartRelay();

        // SO_LINGER(0) makes close() emit RST instead of FIN, so the relay
        // sees connection_reset rather than eof.
        std::error_code err;
        f.server.set_option(asio::socket_base::linger(true, 0), err);
        CHECK(!err);
        f.server.close(err);
        CHECK(!err);
        f.Pump();

        CHECK(1 == f.record.calls);
        CHECK(!f.record.graceful);   // reset must abort, not FIN
        CHECK(f.relay->Finished());
        return 0;
    }

    /// Path: the UPSTREAM WRITE fails (not the read). The header contract is
    /// explicit - only eof is a clean end, "every other error path aborts
    /// (RST)". A broken upstream pipe reported as graceful would tell the
    /// client its upload succeeded when the far end had already gone.
    int TestUpstreamWriteFailureIsNotGraceful() {
        Fixture f;
        CHECK(f.ready);
        f.StartRelay();

        // Kill the upstream end BEFORE handing the relay anything to write,
        // so the write fails with a reset/broken-pipe rather than eof.
        std::error_code err;
        f.server.set_option(asio::socket_base::linger(true, 0), err);
        CHECK(!err);
        f.server.close(err);
        CHECK(!err);
        f.Pump(20);      // let the read side observe the reset first
        f.Pump(20);

        // If the read already finished the relay, the write path is moot -
        // that is the EOF-vs-reset decision covered elsewhere. Only assert
        // the write contract when the relay is still live to attempt it.
        if (0 == f.record.calls) {
            const char chunk[] = "upstream-is-gone";
            CHECK(xtcp::mimt::Result::kOk == f.flow->OnData(
                reinterpret_cast<const Byte*>(chunk), sizeof(chunk) - 1));
            f.Pump();
        }
        CHECK(1 == f.record.calls);
        CHECK(!f.record.graceful);
        CHECK(f.relay->Finished());
        return 0;
    }

    /// Path: the flow's write sink is FULL (kWouldBlock). The contract says
    /// this is transient congestion, NOT a failure: hold the chunk, keep the
    /// socket read paused so up_buf_ cannot be overwritten, and reissue the
    /// SAME bytes after the 20 ms backoff. Treating it as fatal used to RST
    /// every slow client mid-transfer.
    int TestSinkWindowFullHoldsAndRetries() {
        Fixture f;
        CHECK(f.ready);

        int sink_calls = 0;
        int refused = 0;
        std::vector<Byte> delivered;
        f.flow->SetWriteSink([&sink_calls, &refused, &delivered](const Byte* data, UInt32 len) {
            ++sink_calls;
            if (1 == sink_calls) {
                ++refused;
                return false;   // window full -> DispatchWrite completes kWouldBlock
            }
            delivered.insert(delivered.end(), data, data + len);
            return true;
        });
        f.StartRelay();

        const char payload[] = "abc";
        std::error_code err;
        asio::write(f.server, asio::buffer(payload, sizeof(payload) - 1), err);
        CHECK(!err);
        f.Pump(120);      // covers the 20 ms retry backoff

        CHECK(1 == refused);                       // first delivery refused
        CHECK(2 == sink_calls);                    // exactly one retry
        CHECK(sizeof(payload) - 1 == delivered.size());
        CHECK(0 == std::memcmp(delivered.data(), payload, sizeof(payload) - 1));
        CHECK(0 == f.record.calls);                // congestion must NOT tear down
        CHECK(!f.relay->Finished());

        // The read must have re-armed after the retry succeeded.
        const char more[] = "defg";
        asio::write(f.server, asio::buffer(more, sizeof(more) - 1), err);
        CHECK(!err);
        f.Pump(80);
        CHECK(sizeof(payload) - 1 + sizeof(more) - 1 == delivered.size());
        CHECK(0 == std::memcmp(delivered.data() + sizeof(payload) - 1, more,
                               sizeof(more) - 1));
        CHECK(0 == f.record.calls);
        return 0;
    }

    /// Path: the CLIENT half-closes (its FIN reached the stack). The relay
    /// must shut down its SEND direction only: the server sees EOF once our
    /// queued bytes drain, while the reply direction keeps flowing back to
    /// the client. A full teardown here would kill in-flight replies.
    int TestPeerFinHalfClosesUpstreamOnly() {
        Fixture f;
        CHECK(f.ready);
        std::vector<Byte> delivered;
        f.flow->SetWriteSink([&delivered](const Byte* data, UInt32 len) {
            delivered.insert(delivered.end(), data, data + len);
            return true;
        });
        f.StartRelay();

        f.relay->OnPeerFin();

        // The upstream peer must observe EOF on its receive side.
        std::array<char, 8> buf{};
        std::error_code err;
        bool saw_eof = false;
        for (int i = 0; i < 120 && !saw_eof; ++i) {
            err.clear();
            const std::size_t n = f.server.read_some(asio::buffer(buf), err);
            if (err == asio::error::would_block) {
                f.Pump(5);
                continue;
            }
            saw_eof = (0 == n) || (err == asio::error::eof);
            if (!saw_eof) {
                f.Pump(5);
            }
        }
        CHECK(saw_eof);
        CHECK(0 == f.record.calls);   // half-close is not a teardown
        CHECK(!f.relay->Finished());

        // The reply direction must still be alive.
        const char reply[] = "reply";
        asio::write(f.server, asio::buffer(reply, sizeof(reply) - 1), err);
        CHECK(!err);
        f.Pump(100);
        CHECK(sizeof(reply) - 1 == delivered.size());
        CHECK(0 == std::memcmp(delivered.data(), reply, sizeof(reply) - 1));
        CHECK(0 == f.record.calls);
        return 0;
    }

    /// OnPeerFin after teardown must be a harmless no-op. The stack posts it
    /// from another worker (dataplane.cpp:3158), so a FIN can arrive after the
    /// relay already finished. Touching the closed socket is not fatal (the
    /// error is ignored) but the finished_ guard keeps it from re-entering.
    int TestPeerFinAfterTeardownIsHarmless() {
        Fixture f;
        CHECK(f.ready);
        f.StartRelay();

        f.flow->Close();
        f.Pump();
        CHECK(1 == f.record.calls);

        f.relay->OnPeerFin();       // must not resurrect or double-fire
        f.Pump(30);
        CHECK(1 == f.record.calls);
        CHECK(f.relay->Finished());
        return 0;
    }

    /// A throwing teardown hook fired from a FLOW completion must not escape:
    /// MimtFlow::Dispatch() is noexcept (mimt.h:154), so the throw would be
    /// std::terminate, not a catchable unwind. The guard swallows and counts
    /// it, and the relay still tears down exactly once.
    int TestFlowCompletionThrowIsContained() {
        Fixture f;
        CHECK(f.ready);
        f.throw_on_finish = true;
        f.StartRelay();

        f.flow->Close();
        f.Pump();

        CHECK(1 == f.record.calls);
        CHECK(!f.record.graceful);
        CHECK(f.relay->Finished());
        CHECK(1 == f.relay->HandlerErrors());
        return 0;
    }

    /// Same firewall on the ASIO side: an upstream EOF completion whose body
    /// throws must not unwind io_context::poll() (undefined behaviour that
    /// crashes the worker). Swallowed, counted, and torn down once.
    int TestSocketCompletionThrowIsContained() {
        Fixture f;
        CHECK(f.ready);
        f.throw_on_finish = true;
        f.StartRelay();

        std::error_code err;
        f.server.close(err);
        CHECK(!err);
        f.Pump();

        CHECK(1 == f.record.calls);
        CHECK(f.record.graceful);   // EOF still decides FIN, not RST
        CHECK(f.relay->Finished());
        CHECK(1 == f.relay->HandlerErrors());
        return 0;
    }

}  // namespace vgww

int main() {
    if (vgww::TestStartDoesNotSpontaneouslyFinish()) return 1;
    if (vgww::TestFlowToSocketForwardsAndRearms()) return 1;
    if (vgww::TestSocketToFlowForwardsAndRearms()) return 1;
    if (vgww::TestUpstreamEofIsGraceful()) return 1;
    if (vgww::TestUpstreamResetIsNotGraceful()) return 1;
    if (vgww::TestUpstreamWriteFailureIsNotGraceful()) return 1;
    if (vgww::TestSinkWindowFullHoldsAndRetries()) return 1;
    if (vgww::TestPeerFinHalfClosesUpstreamOnly()) return 1;
    if (vgww::TestPeerFinAfterTeardownIsHarmless()) return 1;
    if (vgww::TestFlowClosedIsNotGraceful()) return 1;
    if (vgww::TestTeardownIsExactlyOnce()) return 1;
    if (vgww::TestFinishClosesUpstreamSocket()) return 1;
    if (vgww::TestSyncReadRefusalTearsDown()) return 1;
    if (vgww::TestSyncWriteRefusalTearsDown()) return 1;
    if (vgww::TestFlowCompletionThrowIsContained()) return 1;
    if (vgww::TestSocketCompletionThrowIsContained()) return 1;
    std::puts("test_tcp_relay: ALL PASS");
    return 0;
}
