// ============================================================================
// udp_relay.h - Per-flow UDP NAT relay.
//
// One asio UDP socket per flow (openppp2-proven model): the flow key is the
// client 4-tuple, the upstream socket binds an ephemeral host port and
// async_sends to the original destination - traffic egresses through the
// HOST STACK so VPN routing applies (hard constraint).
//
// Sharding: each worker owns its own table; flows are hashed to workers by
// the same symmetric hash as TCP, so a flow's frames and its socket live on
// one thread. No locks on the data path.
//
// GC: entries refresh last_active on every packet; the owner sweeps expired
// flows periodically (single timeout, LRU-capped table).
// ============================================================================
#pragma once

#include "net/ip_addr.h"

#include <asio.hpp>

#include <array>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <unordered_map>

namespace vgww {
    namespace relay {

        class UdpFlowTable;  // batch304: UdpRelay::Touch splices the LRU list

        class UdpRelay final : public std::enable_shared_from_this<UdpRelay> {
        public:
            /// Identifies one client UDP flow (direction-normalized at the
            /// call site: always stored client->remote).
            struct FlowKey {
                net::IpAddress client_ip;
                uint16_t client_port = 0;
                net::IpAddress remote_ip;
                uint16_t remote_port = 0;

                friend bool operator==(const FlowKey& a, const FlowKey& b) noexcept {
                    return a.client_port == b.client_port &&
                           a.remote_port == b.remote_port &&
                           a.client_ip == b.client_ip &&
                           a.remote_ip == b.remote_ip;
                }
            };

            struct FlowKeyHash {
                size_t operator()(const FlowKey& key) const noexcept;
            };

            UdpRelay(asio::ip::udp::socket socket, const FlowKey& key);

            /// Sends `payload` toward the original destination.
            void SendToRemote(const uint8_t* payload, size_t len);

            /// Connects the upstream socket (connected-UDP receive filter).
            void ConnectRemote(const asio::ip::udp::endpoint& endpoint,
                               std::error_code& err) {
                remote_endpoint_ = endpoint;
                socket_.connect(endpoint, err);
            }

            /// C4: decides whether a receive completion with `err` should
            /// re-arm the receive chain. Success and the Windows connected-UDP
            /// transient errors (ICMP unreachable surfaces as
            /// connection_reset/aborted) re-arm; the terminal set
            /// (operation_aborted / bad_descriptor) ends the chain. The
            /// caller additionally refuses to re-arm when the socket closed.
            bool ShouldRearm(const std::error_code& err) const noexcept {
                if (!err) {
                    return true;
                }
                // batch325: the WHOLE ICMP-unreachable family is transient.
                // A connected UDP socket surfaces "port unreachable" as
                // connection_reset/refused and "dest/net unreachable" as
                // host/network_*; none of them mean the flow is dead. Ending
                // the chain here would leave a table entry that keeps
                // forwarding outbound datagrams but can never receive again
                // (the client's replies are silently dropped forever).
                return err == asio::error::connection_reset ||
                       err == asio::error::connection_aborted ||
                       err == asio::error::connection_refused ||
                       err == asio::error::network_unreachable ||
                       err == asio::error::host_unreachable ||
                       err == asio::error::network_down ||
                       err == asio::error::network_reset;
            }

            /// Arms one async_receive; completions fire via OnRemoteData.
            void ArmReceive();

            /// Invoked when the upstream socket receives a datagram; the
            /// callback rebuilds a frame toward the client.
            std::function<void(const uint8_t* data, size_t len)> on_remote_data;

            /// Refreshes recency and moves this relay to the MRU end of the
            /// owning table's LRU list (O(1)). Defined out of line because the
            /// table type is incomplete here.
            void Touch(std::chrono::steady_clock::time_point now) noexcept;
            /// The flow key this relay was created for (eviction lookup).
            const FlowKey& Key() const noexcept { return key_; }
            std::chrono::steady_clock::time_point LastActive() const noexcept {
                return last_active_;
            }
            asio::ip::udp::socket& Socket() noexcept { return socket_; }

            /// Closes the socket, aborting any pending async_receive. Must be
            /// called when a flow leaves the table (eviction or sweep):
            /// otherwise the shared_from_this keep-alive turns the flow into
            /// a ghost that leaks its socket and keeps forwarding traffic.
            void Shutdown() {
                std::error_code ignored;
                socket_.close(ignored);
            }

            bool IsOpen() const noexcept { return socket_.is_open(); }

            // Receive buffer sizing is a memory/coverage trade-off:
            // 8 KiB covers the datagrams real clients expect intact
            // (EDNS0 4096, DNSSEC, TFTP large blocks) at +6 KiB per flow.
            // Sizes above this get silently truncated by the kernel read; a
            // full 64 KiB would cost ~4 GiB at udp_flow_cap. Clients with
            // truly oversized datagrams must fall back to TCP (DNS already
            // does exactly that).
            static constexpr size_t kRecvBufBytes = 8192;

        private:
            friend class UdpFlowTable;

            void OnRemoteData(const std::error_code& err, size_t n);

            asio::ip::udp::socket socket_;
            asio::ip::udp::endpoint remote_endpoint_;
            asio::ip::udp::endpoint peer_endpoint_;  ///< filled on receive
            FlowKey key_;
            std::array<uint8_t, kRecvBufBytes> recv_buf_{};
            std::chrono::steady_clock::time_point last_active_;
            /// batch304: intrusive LRU links owned by the flow table. Touch()
            /// moves this relay to the MRU end in O(1); the table evicts the
            /// tail in O(1) instead of scanning every flow (up to 8192) on
            /// every new flow at capacity.
            UdpFlowTable* lru_owner_ = nullptr;
            UdpRelay* lru_prev_ = nullptr;
            UdpRelay* lru_next_ = nullptr;
        };

        /// Per-worker flow table (owner thread only).
        class UdpFlowTable final {
        public:
            using Clock = std::chrono::steady_clock;

            UdpFlowTable(size_t capacity, Clock::duration idle_timeout)
                : capacity_(capacity), idle_timeout_(idle_timeout) {}
            ~UdpFlowTable();

            /// batch304: moves `relay` to the MRU end. Called by
            /// UdpRelay::Touch on every packet (O(1)).
            void MoveToFront(UdpRelay& relay) noexcept;

            /// Returns the relay for `key`, creating it lazily. Returns null
            /// when the table is full (drop-not-grow).
            std::shared_ptr<UdpRelay> GetOrCreate(
                const UdpRelay::FlowKey& key, asio::io_context& io);

            /// Evicts idle flows; returns how many were removed.
            size_t Sweep(Clock::time_point now);

            size_t Size() const noexcept { return flows_.size(); }
            /// batch34j: flows pushed out by the capacity cap. Each eviction
            /// aborts an in-flight UDP conversation (its socket is closed), so
            /// the peer sees the flow die - previously with no counter.
            uint64_t Evictions() const noexcept { return evictions_; }

        private:
            void LinkFront(UdpRelay& relay) noexcept;
            void Unlink(UdpRelay& relay) noexcept;

            size_t capacity_;
            uint64_t evictions_ = 0;
            Clock::duration idle_timeout_;
            UdpRelay* lru_head_ = nullptr;  ///< most recently active
            UdpRelay* lru_tail_ = nullptr;  ///< least recently active
            std::unordered_map<UdpRelay::FlowKey, std::shared_ptr<UdpRelay>,
                               UdpRelay::FlowKeyHash>
                flows_;
        };

    }  // namespace relay
}  // namespace vgww
