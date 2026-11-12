// ============================================================================
// udp_relay.cpp - Per-flow UDP NAT implementation.
// ============================================================================
#include "relay/udp_relay.h"

namespace vgww {
    namespace relay {

        using Clock = std::chrono::steady_clock;

        size_t UdpRelay::FlowKeyHash::operator()(const UdpRelay::FlowKey& key) const noexcept {
            const net::IpAddressHash ip_hash;
            uint64_t h = ip_hash(key.client_ip);
            h ^= ip_hash(key.remote_ip) + 0x9E3779B97F4A7C15ull + (h << 6) + (h >> 2);
            // batch316: fold BOTH ports into the state, then avalanche. The
            // old `h ^= client_port << 16` left the low bits independent of
            // the client port, and MSVC's unordered_map derives the bucket
            // from those bits: one client opening many source ports to ONE
            // server (a DNS resolver, a game server) put every flow in one
            // bucket (measured: 4096 flows -> max_bucket=4096), turning the
            // per-packet flow lookup into a linear scan of the whole table.
            h ^= static_cast<uint64_t>(key.client_port) << 32;
            h ^= static_cast<uint64_t>(key.remote_port);
            h ^= h >> 33;
            h *= 0xFF51AFD7ED558CCDull;
            h ^= h >> 33;
            h *= 0xC4CEB9FE1A85EC53ull;
            h ^= h >> 33;
            return static_cast<size_t>(h);
        }

        UdpRelay::UdpRelay(asio::ip::udp::socket socket, const FlowKey& key)
            : socket_(std::move(socket)),
              key_(key),
              last_active_(Clock::now()) {}

        void UdpRelay::Touch(std::chrono::steady_clock::time_point now) noexcept {
            last_active_ = now;
            if (nullptr != lru_owner_) {
                lru_owner_->MoveToFront(*this);
            }
        }

        void UdpRelay::SendToRemote(const uint8_t* payload, size_t len) {
            Touch(Clock::now());
            // Synchronous send: the caller's buffer is a borrow of a data
            // plane pool block with a lifetime SHORTER than any async
            // completion, so async_send would have read already-recycled
            // memory (use-after-free). A synchronous send copies into the
            // kernel immediately and returns; UDP loss on error is by design.
            if (!socket_.is_open()) {
                return;
            }
            std::error_code ignored;
            socket_.send(asio::buffer(payload, len), 0, ignored);
        }

        void UdpRelay::ArmReceive() {
            // Ownership: the flow table holds the strong reference; the
            // pending receive keeps a shared_from_this so a concurrent
            // eviction cannot destroy the object mid-operation.
            auto self = shared_from_this();
            socket_.async_receive(
                asio::buffer(recv_buf_),
                [self](const std::error_code& err, size_t n) {
                    if (!err) {
                        // One datagram that cannot be rebuilt costs that
                        // datagram, not the worker thread.
                        ::vgww::core::InvokeHandlerGuarded(self->handler_errors_, [&] {
                            self->OnRemoteData(err, n);
                        });
                    }
                    // C4: a transient error (Windows connected-UDP surfaces
                    // ICMP Port Unreachable as connection_reset/aborted) must
                    // NOT end the chain - re-arm and keep the flow alive.
                    // Terminal conditions (socket closed, operation_aborted,
                    // bad_descriptor) end it. Guarded separately so a
                    // throwing delivery can never skip the re-arm.
                    ::vgww::core::InvokeHandlerGuarded(self->handler_errors_, [&] {
                        if (self->socket_.is_open() &&
                            self->ShouldRearm(err)) {
                            self->ArmReceive();
                        }
                    });
                });
        }

        void UdpRelay::OnRemoteData(const std::error_code& err, size_t n) {
            if (err || 0 == n) {
                return;
            }
            Touch(Clock::now());
            if (on_remote_data) {
                on_remote_data(recv_buf_.data(), n);
            }
        }

        std::shared_ptr<UdpRelay> UdpFlowTable::GetOrCreate(
            const UdpRelay::FlowKey& key, asio::io_context& io) {
            const auto it = flows_.find(key);
            if (it != flows_.end()) {
                it->second->Touch(Clock::now());
                return it->second;
            }
            asio::ip::udp::socket socket(io);
            std::error_code err;
            // The socket family MUST follow the flow: a v6 flow needs a v6
            // socket (binding an IPv4 socket and connecting the v6 remote
            // endpoint fails, silently killing all IPv6 UDP).
            if (key.remote_ip.IsV4()) {
                socket.open(asio::ip::udp::v4(), err);
                if (err) {
                    return nullptr;
                }
                socket.bind(
                    asio::ip::udp::endpoint(asio::ip::udp::v4(), 0), err);
            } else {
                socket.open(asio::ip::udp::v6(), err);
                if (err) {
                    return nullptr;
                }
                socket.bind(
                    asio::ip::udp::endpoint(asio::ip::udp::v6(), 0), err);
            }
            if (err) {
                return nullptr;
            }
            auto relay = std::make_shared<UdpRelay>(std::move(socket), key);
            // Connect-mode receive: only datagrams from the original
            // destination are delivered back to the client.
            if (key.remote_ip.IsV4()) {
                const asio::ip::address_v4::bytes_type dst{
                    key.remote_ip.bytes[12], key.remote_ip.bytes[13],
                    key.remote_ip.bytes[14], key.remote_ip.bytes[15]};
                relay->ConnectRemote(
                    asio::ip::udp::endpoint(asio::ip::make_address_v4(dst),
                                            key.remote_port),
                    err);
            } else {
                asio::ip::address_v6::bytes_type dst{};
                std::memcpy(dst.data(), key.remote_ip.bytes.data(), 16);
                relay->ConnectRemote(
                    asio::ip::udp::endpoint(asio::ip::make_address_v6(dst),
                                            key.remote_port),
                    err);
            }
            if (err) {
                return nullptr;
            }
            if (flows_.size() >= capacity_) {
                if (nullptr == lru_tail_) {
                    // capacity_ <= 0 disables all flows; drop without
                    // dereferencing an empty LRU list.
                    return nullptr;
                }
                // batch304: O(1) LRU eviction. The tail is the least recently
                // active flow; the old code scanned the whole table (up to
                // 8192 relays) on every new flow at capacity. Closing the
                // socket aborts the pending receive - without this the evicted
                // flow would live on as a ghost (leaked socket + stale
                // forwarding).
                UdpRelay* tail = lru_tail_;
                Unlink(*tail);
                const auto victim_it = flows_.find(tail->Key());
                if (victim_it != flows_.end()) {
                    auto victim = std::move(victim_it->second);
                    flows_.erase(victim_it);
                    victim->Shutdown();
                }
                // batch34j: count the eviction. Shutdown() aborts the pending
                // receive, so the peer UDP conversation dies with it.
                ++evictions_;
            }
            flows_.emplace(key, relay);
            LinkFront(*relay);
            relay->ArmReceive();
            return relay;
        }

        size_t UdpFlowTable::Sweep(std::chrono::steady_clock::time_point now) {
            size_t removed = 0;
            for (auto it = flows_.begin(); it != flows_.end();) {
                if (now - it->second->LastActive() > idle_timeout_) {
                    Unlink(*it->second);
                    auto victim = std::move(it->second);
                    it = flows_.erase(it);
                    victim->Shutdown();  // abort the pending receive
                    ++removed;
                } else {
                    ++it;
                }
            }
            return removed;
        }

        UdpFlowTable::~UdpFlowTable() {
            // A pending receive holds a shared_ptr, so a relay can outlive the
            // table; detach it so a later Touch() cannot splice into a dead
            // table.
            while (nullptr != lru_head_) {
                Unlink(*lru_head_);
            }
        }

        void UdpFlowTable::LinkFront(UdpRelay& relay) noexcept {
            relay.lru_owner_ = this;
            relay.lru_prev_ = nullptr;
            relay.lru_next_ = lru_head_;
            if (nullptr != lru_head_) {
                lru_head_->lru_prev_ = &relay;
            }
            lru_head_ = &relay;
            if (nullptr == lru_tail_) {
                lru_tail_ = &relay;
            }
        }

        void UdpFlowTable::Unlink(UdpRelay& relay) noexcept {
            if (relay.lru_owner_ != this) {
                return;  // already detached (or never linked)
            }
            if (nullptr != relay.lru_prev_) {
                relay.lru_prev_->lru_next_ = relay.lru_next_;
            } else {
                lru_head_ = relay.lru_next_;
            }
            if (nullptr != relay.lru_next_) {
                relay.lru_next_->lru_prev_ = relay.lru_prev_;
            } else {
                lru_tail_ = relay.lru_prev_;
            }
            relay.lru_owner_ = nullptr;
            relay.lru_prev_ = nullptr;
            relay.lru_next_ = nullptr;
        }

        void UdpFlowTable::MoveToFront(UdpRelay& relay) noexcept {
            if (relay.lru_owner_ != this || lru_head_ == &relay) {
                return;  // not ours, or already the most recent
            }
            if (nullptr != relay.lru_prev_) {
                relay.lru_prev_->lru_next_ = relay.lru_next_;
            } else {
                lru_head_ = relay.lru_next_;
            }
            if (nullptr != relay.lru_next_) {
                relay.lru_next_->lru_prev_ = relay.lru_prev_;
            } else {
                lru_tail_ = relay.lru_prev_;
            }
            relay.lru_prev_ = nullptr;
            relay.lru_next_ = lru_head_;
            if (nullptr != lru_head_) {
                lru_head_->lru_prev_ = &relay;
            }
            lru_head_ = &relay;
            if (nullptr == lru_tail_) {
                lru_tail_ = &relay;
            }
        }

    }  // namespace relay
}  // namespace vgww
