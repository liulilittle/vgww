// ============================================================================
// bridge.h - Built-in L2 bridge core (S3).
//
// Headless, I/O-free pieces shared by the bridge loop and the control plane:
//   - MacTable: learned source-MAC -> port map with a hard capacity, oldest
//     eviction, and steady-clock aging (same discipline as the S1 H1
//     neighbor table).
//   - DecideBridgeAction: pure forwarding decision for one received frame.
//
// No locks and no global state live here; callers own the locking and the
// actual packet delivery (control plane vs. bridge flood).
// ============================================================================
#pragma once

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "core/limits.h"
#include "driver/idriver_client.h"
#include "net/eth.h"

namespace vgww {
    namespace bridge {

        /// What the RX path must do with one received frame. A single value
        /// expresses dual delivery: kControlAndFlood means "hand the frame to
        /// the normal control-plane path AND flood it through the bridge".
        enum class BridgeAction {
            kControlOnly,      ///< gateway MAC: control plane only
            kControlAndFlood,  ///< broadcast / IPv6 multicast: both paths
            kBridgeUnicast,    ///< non-gateway unicast with a known port
            kBridgeFlood,      ///< non-gateway unicast with an unknown port
            kDrop,             ///< too short to be Ethernet II
        };

        /// Learned source-MAC table (one instance per bridge).
        class MacTable {
        public:
            using TimePoint = std::chrono::steady_clock::time_point;
            using Duration = std::chrono::steady_clock::duration;

            explicit MacTable(
                size_t capacity = core::limits::kDefaultMacTableSize);
            // batch307: the LRU list holds pointers into `entries_`; a copy or
            // move would leave them dangling. Callers use Clear()/Reset().
            MacTable(const MacTable&) = delete;
            MacTable& operator=(const MacTable&) = delete;
            MacTable(MacTable&&) = delete;
            MacTable& operator=(MacTable&&) = delete;

            /// Records `mac` as reachable via `port` at `now`. Broadcast and
            /// multicast source MACs are never learned. Re-learning a known
            /// MAC refreshes its port and timestamp without growing the table;
            /// a new MAC at capacity evicts the least recently learned or
            /// refreshed entry in O(1) (the old code scanned the whole table,
            /// up to 65,536 entries, on every new MAC at capacity).
            void Learn(const net::WireMac& mac, uint32_t port, TimePoint now);

            /// Returns the port last learned for `mac`, or nullopt on a miss.
            std::optional<uint32_t> Lookup(const net::WireMac& mac) const;

            /// Removes every entry idle for longer than `max_age` and returns
            /// how many were removed.
            size_t Age(TimePoint now, Duration max_age);

            /// batch307: forget every learned MAC and reset the eviction
            /// counter (bridge teardown).
            void Clear() noexcept;
            /// batch307: forget every MAC and adopt a new capacity (bridge
            /// restart). Capacity follows the constructor's clamp.
            void Reset(size_t capacity);

            size_t Size() const noexcept { return entries_.size(); }
            size_t Capacity() const noexcept { return capacity_; }
            /// batch34h: how many times a NEW MAC had to push an existing
            /// entry out because the table was full. Every eviction means that
            /// device's traffic starts flooding until it speaks again, which
            /// is a visible behaviour change - it used to happen silently.
            uint64_t Evictions() const noexcept { return evictions_; }

        private:
            struct Entry {
                net::WireMac mac{};
                uint32_t port = 0;
                TimePoint last_seen{};
                Entry* prev = nullptr;  ///< more recently learned neighbour
                Entry* next = nullptr;  ///< less recently learned neighbour
            };

            void LinkFront(Entry& entry) noexcept;
            void Unlink(Entry& entry) noexcept;
            void MoveToFront(Entry& entry) noexcept;

            size_t capacity_;
            uint64_t evictions_ = 0;
            Entry* head_ = nullptr;  ///< most recently learned or refreshed
            Entry* tail_ = nullptr;  ///< least recently learned or refreshed
            std::unordered_map<net::WireMac, Entry, net::WireMacHash> entries_;
        };

        /// Pure forwarding decision for a received frame (no I/O, no locks,
        /// no global state).
        ///
        /// Semantics (kept aligned with the Task 3 dispatch matrix):
        ///   - len < 14                  -> kDrop
        ///   - dst == gateway_mac        -> kControlOnly
        ///   - is_multicast_or_broadcast -> kControlAndFlood
        ///   - known_port.has_value()    -> kBridgeUnicast
        ///   - otherwise                 -> kBridgeFlood
        ///
        /// `known_port` is the MacTable lookup result for the destination; the
        /// caller performs the lookup so this function stays pure.
        BridgeAction DecideBridgeAction(
            const uint8_t* frame, size_t len, const net::WireMac& gateway_mac,
            bool is_multicast_or_broadcast,
            const std::optional<uint32_t>& known_port);

        /// MacTable port ids: 0 = upstream (primary adapter),
        /// 1 = downstream (bridge peer adapter).
        inline constexpr uint32_t kBridgePortUp = 0;
        inline constexpr uint32_t kBridgePortDown = 1;

        /// Bridge operational state (Task 3; surfaced to status/UI).
        enum class BridgeState {
            kStopped,  ///< disabled, never started, or cleanly stopped
            kRunning,  ///< bridge thread forwards between both adapters
            kFailed,   ///< port vanished or read failed; bridge halted,
                       ///< dataplane keeps running
        };

        /// Temporary bridge wiring (Task 3). Task 4 binds these fields to
        /// the config file (`bridge` section); until then tests drive them
        /// through Dataplane::SetBridgeConfig.
        struct BridgeConfig {
            bool enabled = false;
            /// Upstream adapter hint; empty selects the primary adapter.
            std::string upstream;
            /// Downstream adapter hint (required when enabled).
            std::string downstream;
            size_t mac_table_size = core::limits::kDefaultMacTableSize;
        };

        /// Caller-owned loop runtime (Task 3): the dataplane owns one
        /// instance for the process lifetime; RunBridgeLoop only flips it
        /// and never allocates or frees it.
        struct BridgeLoopRuntime {
            std::atomic<bool> stop_requested{false};
            std::atomic<bool> running{false};
            mutable std::mutex mutex;
            std::chrono::steady_clock::time_point next_age{};
        };

        /// How RunBridgeLoop exited.
        enum class BridgeLoopExit {
            kStopped,    ///< stop was requested
            kReadError,  ///< ReadPackets reported a driver error
            kPortGone,   ///< the local adapter vanished from Adapters()
        };

        /// Control-plane handoff for the bridge loop: RunBridgeLoop
        /// delivers every non-dropped frame here; the dataplane performs
        /// the peer send (bridge/flood actions) and/or enqueues the frame
        /// for its RX thread (control actions). Implementations must not
        /// throw; RunBridgeLoop survives a throwing sink but counts the
        /// frame as dropped.
        struct BridgeFrameSink {
            virtual ~BridgeFrameSink() = default;
            virtual void OnBridgeFrame(const uint8_t* data, size_t len,
                                       uint32_t in_port,
                                       BridgeAction action) = 0;
        };

        /// Learns the source MAC and decides the action for one frame
        /// (no I/O; table access under `table_mutex`). Shared by the
        /// bridge loop and the dataplane RX path so both classify
        /// identically. A known-unicast hairpin (destination learned back
        /// on the ingress port) maps to kDrop: the frame needs no
        /// delivery anywhere.
        BridgeAction LearnAndDecide(
            MacTable& table, std::mutex& table_mutex, const uint8_t* frame,
            size_t len, uint32_t in_port,
            const net::WireMac& gateway_mac);

        /// Blocking bridge poll loop over the `local` adapter (Task 3).
        /// Each pass: verify the port is still present, age the table when
        /// its timer is due, take one bounded wait slice, read one batch,
        /// and hand every non-dropped frame to `sink`. The wait return is
        /// advisory pacing only: the queue drains once per pass regardless
        /// (same discipline as the RX thread; fakes never signal events).
        /// Returns when StopBridgeLoop is requested (kStopped) or on the
        /// first fatal condition (`exit_detail` carries the driver text). Waiting is
        /// injected so the loop stays headless and unit-testable; the
        /// dataplane passes a WaitForSingleObject slice over its bridge
        /// event, which also bounds shutdown waits.
        BridgeLoopExit RunBridgeLoop(
            driver::IDriverClient& client,
            const driver::AdapterEntry& local, uint32_t local_port,
            MacTable& table, std::mutex& table_mutex,
            const net::WireMac& gateway_mac, BridgeLoopRuntime& runtime,
            BridgeFrameSink& sink,
            const std::function<bool(uint32_t)>& wait_readable,
            std::string& exit_detail);

        /// Cooperative stop: flips `stop_requested`; the loop wakes on its
        /// next wait slice (the dataplane additionally signals its bridge
        /// event so the wake is immediate).
        void StopBridgeLoop(BridgeLoopRuntime& runtime) noexcept;

        /// True while the loop is alive and still owns a pending MAC-aging
        /// deadline. The loop thread uses it to schedule Age(); the
        /// dataplane's bounded shutdown join relies on the loop's wait
        /// slice plus StopBridgeLoop rather than on this query.
        bool HasPendingTimer(const BridgeLoopRuntime& runtime) noexcept;

    }  // namespace bridge
}  // namespace vgww
