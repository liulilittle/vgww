// ============================================================================
// bridge.cpp - Built-in L2 bridge core (S3).
// ============================================================================
#include "bridge/bridge.h"

#include <algorithm>
#include <cstring>

// NOTE: windows.h must precede ndisapi/Common.h (it pulls WinIoctl.h,
// which needs the base Windows types first; same order as dataplane.cpp).
#include <winsock2.h>
#include <ws2ipdef.h>
#include <windows.h>

#include "ndisapi/Common.h"

namespace vgww {
    namespace bridge {

        MacTable::MacTable(size_t capacity)
            : capacity_(std::min(capacity == 0
                                     ? core::limits::kDefaultMacTableSize
                                     : capacity,
                                 core::limits::kMaxMacTableSize)) {}

        void MacTable::Learn(const net::WireMac& mac, uint32_t port,
                             TimePoint now) {
            // Group addresses (broadcast/multicast; bit 0 of the first octet)
            // are never valid source identities.
            if (net::IsGroupAddress(mac)) {
                return;
            }
            const auto known = entries_.find(mac);
            if (entries_.end() != known) {
                known->second.port = port;
                known->second.last_seen = now;
                MoveToFront(known->second);
                return;
            }
            if (entries_.size() >= capacity_) {
                if (nullptr == tail_) {
                    return;  // capacity 0: no entry to evict
                }
                // batch307: O(1) eviction. The tail is the least recently
                // learned or refreshed entry; the old code scanned the whole
                // table (up to kMaxMacTableSize = 65,536) on every new MAC at
                // capacity - a random-source-MAC flood saturated the bridge.
                const net::WireMac victim = tail_->mac;
                Unlink(*tail_);
                entries_.erase(victim);
                // batch34h: count it. An evicted MAC loses its port mapping,
                // so its next frames flood until it speaks again - a real
                // behaviour change that used to be completely invisible.
                ++evictions_;
            }
            Entry& entry = entries_[mac];
            entry.mac = mac;
            entry.port = port;
            entry.last_seen = now;
            LinkFront(entry);
        }

        void MacTable::LinkFront(Entry& entry) noexcept {
            entry.prev = nullptr;
            entry.next = head_;
            if (nullptr != head_) {
                head_->prev = &entry;
            }
            head_ = &entry;
            if (nullptr == tail_) {
                tail_ = &entry;
            }
        }

        void MacTable::Unlink(Entry& entry) noexcept {
            if (nullptr != entry.prev) {
                entry.prev->next = entry.next;
            } else {
                head_ = entry.next;
            }
            if (nullptr != entry.next) {
                entry.next->prev = entry.prev;
            } else {
                tail_ = entry.prev;
            }
            entry.prev = nullptr;
            entry.next = nullptr;
        }

        void MacTable::MoveToFront(Entry& entry) noexcept {
            if (head_ == &entry) {
                return;  // already the most recent
            }
            Unlink(entry);
            LinkFront(entry);
        }

        void MacTable::Clear() noexcept {
            entries_.clear();
            head_ = nullptr;
            tail_ = nullptr;
            evictions_ = 0;
        }

        void MacTable::Reset(size_t capacity) {
            Clear();
            capacity_ = std::min(capacity == 0
                                     ? core::limits::kDefaultMacTableSize
                                     : capacity,
                                 core::limits::kMaxMacTableSize);
        }

        std::optional<uint32_t> MacTable::Lookup(const net::WireMac& mac) const {
            const auto it = entries_.find(mac);
            if (entries_.end() == it) {
                return std::nullopt;
            }
            return it->second.port;
        }

        size_t MacTable::Age(TimePoint now, Duration max_age) {
            size_t removed = 0;
            for (auto it = entries_.begin(); it != entries_.end();) {
                if (now - it->second.last_seen > max_age) {
                    // batch307: unlink BEFORE the erase - the list must never
                    // hold a pointer to a freed map node (the next capacity
                    // eviction reads the tail).
                    Unlink(it->second);
                    it = entries_.erase(it);
                    ++removed;
                } else {
                    ++it;
                }
            }
            return removed;
        }

        BridgeAction DecideBridgeAction(
            const uint8_t* frame, size_t len, const net::WireMac& gateway_mac,
            bool is_multicast_or_broadcast,
            const std::optional<uint32_t>& known_port) {
            if (nullptr == frame || len < net::kEthernetHeaderLen) {
                return BridgeAction::kDrop;
            }
            net::WireMac dst{};
            std::memcpy(dst.data(), frame, net::kMacAddrLen);
            if (dst == gateway_mac) {
                return BridgeAction::kControlOnly;
            }
            if (is_multicast_or_broadcast) {
                return BridgeAction::kControlAndFlood;
            }
            if (known_port.has_value()) {
                return BridgeAction::kBridgeUnicast;
            }
            return BridgeAction::kBridgeFlood;
        }

        namespace {

            /// Frames per ReadPackets batch inside the bridge loop.
            constexpr uint32_t kBridgeReadBatch = 32;

            /// MAC aging cadence and entry lifetime (same order as the
            /// neighbor table discipline: minutes, not seconds).
            const std::chrono::seconds kBridgeAgeInterval(60);
            const std::chrono::seconds kBridgeMaxEntryAge(300);

            bool AdapterPresent(driver::IDriverClient& client,
                                const void* handle) {
                try {
                    for (const driver::AdapterEntry& adapter :
                         client.Adapters()) {
                        if (adapter.handle == handle) {
                            return true;
                        }
                    }
                } catch (...) {
                    return false;
                }
                return false;
            }

        }  // namespace

        BridgeAction LearnAndDecide(MacTable& table, std::mutex& table_mutex,
                                    const uint8_t* frame, size_t len,
                                    uint32_t in_port,
                                    const net::WireMac& gateway_mac) {
            if (nullptr == frame || len < net::kEthernetHeaderLen) {
                return BridgeAction::kDrop;
            }
            net::WireMac dst{};
            net::WireMac src{};
            std::memcpy(dst.data(), frame, net::kMacAddrLen);
            std::memcpy(src.data(), frame + net::kMacAddrLen,
                        net::kMacAddrLen);
            // batch34w: EVERY group address must take both paths, not just
            // broadcast and the 33:33 IPv6 prefix. The group bit is bit 0 of
            // the first octet (same rule MacTable::Learn already applies to
            // sources), so 01:00:5E:xx:xx:xx (IPv4 multicast: IGMP, mDNS,
            // SSDP) is a group address too. Missing it made those frames fall
            // through to "unknown unicast": flooded peer-ward but never handed
            // to the control plane, so the gateway never saw them.
            const bool group = net::IsGroupAddress(dst);
            std::optional<uint32_t> known = std::nullopt;
            try {
                std::lock_guard<std::mutex> lock(table_mutex);
                table.Learn(src, in_port,
                            std::chrono::steady_clock::now());
                known = table.Lookup(dst);
            } catch (...) {
                return BridgeAction::kDrop;
            }
            const BridgeAction action = DecideBridgeAction(
                frame, len, gateway_mac, group, known);
            if (BridgeAction::kBridgeUnicast == action &&
                known.has_value() && known.value() == in_port) {
                return BridgeAction::kDrop;  // hairpin: no delivery needed
            }
            return action;
        }

        BridgeLoopExit RunBridgeLoop(
            driver::IDriverClient& client,
            const driver::AdapterEntry& local, uint32_t local_port,
            MacTable& table, std::mutex& table_mutex,
            const net::WireMac& gateway_mac, BridgeLoopRuntime& runtime,
            BridgeFrameSink& sink,
            const std::function<bool(uint32_t)>& wait_readable,
            std::string& exit_detail) {
            runtime.running.store(true);
            {
                std::lock_guard<std::mutex> lock(runtime.mutex);
                runtime.next_age =
                    std::chrono::steady_clock::now() + kBridgeAgeInterval;
            }
            BridgeLoopExit exit = BridgeLoopExit::kStopped;
            std::vector<INTERMEDIATE_BUFFER> batch(kBridgeReadBatch);
            while (!runtime.stop_requested.load()) {
                if (!AdapterPresent(client, local.handle)) {
                    exit_detail = "bridge port disappeared";
                    exit = BridgeLoopExit::kPortGone;
                    break;
                }
                if (!HasPendingTimer(runtime)) {
                    try {
                        std::lock_guard<std::mutex> table_lock(table_mutex);
                        table.Age(std::chrono::steady_clock::now(),
                                  kBridgeMaxEntryAge);
                    } catch (...) {
                        // Aging is best-effort; a throwing table must not
                        // kill the forwarding loop.
                    }
                    try {
                        std::lock_guard<std::mutex> lock(runtime.mutex);
                        runtime.next_age = std::chrono::steady_clock::now() +
                                           kBridgeAgeInterval;
                    } catch (...) {
                    }
                }
                // Pacing slice only: the queue is always drained once per
                // pass, exactly like the RX thread (in-memory fakes never
                // signal the event; the return value is advisory).
                try {
                    wait_readable(200);
                } catch (...) {
                }
                if (runtime.stop_requested.load()) {
                    break;
                }
                std::string error;
                uint32_t n = 0;
                try {
                    n = client.ReadPackets(local.handle, batch.data(),
                                           kBridgeReadBatch, error);
                } catch (const std::exception& ex) {
                    error = ex.what();
                } catch (...) {
                    error = "unknown read error";
                }
                if (!error.empty()) {
                    exit_detail = error;
                    exit = BridgeLoopExit::kReadError;
                    break;
                }
                for (uint32_t k = 0; k < n; ++k) {
                    const uint8_t* data = batch[k].m_IBuffer;
                    const size_t len = batch[k].m_Length;
                    BridgeAction action = BridgeAction::kDrop;
                    try {
                        action = LearnAndDecide(table, table_mutex, data,
                                                len, local_port, gateway_mac);
                    } catch (...) {
                        continue;
                    }
                    if (BridgeAction::kDrop == action) {
                        continue;
                    }
                    try {
                        sink.OnBridgeFrame(data, len, local_port, action);
                    } catch (...) {
                        // A throwing sink counts as a dropped frame; the
                        // loop itself stays alive.
                    }
                }
            }
            runtime.running.store(false);
            return exit;
        }

        void StopBridgeLoop(BridgeLoopRuntime& runtime) noexcept {
            runtime.stop_requested.store(true);
        }

        bool HasPendingTimer(const BridgeLoopRuntime& runtime) noexcept {
            if (!runtime.running.load() || runtime.stop_requested.load()) {
                return false;
            }
            try {
                std::lock_guard<std::mutex> lock(runtime.mutex);
                return std::chrono::steady_clock::now() < runtime.next_age;
            } catch (...) {
                return false;
            }
        }

    }  // namespace bridge
}  // namespace vgww
