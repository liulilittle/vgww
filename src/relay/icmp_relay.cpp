// ============================================================================
// icmp_relay.cpp - ICMP relay implementation.
// ============================================================================
#include "relay/icmp_relay.h"

namespace vgww {
    namespace relay {

        IcmpRelay::TagAllocator& IcmpRelay::TagAllocator::Instance() noexcept {
            static TagAllocator instance;
            return instance;
        }

        IcmpRelay::TagAllocator::TagAllocator() {
            // Pre-fill the stack so the first tags handed out are 10000,
            // 10001, ... (the openppp2 rule); a stack pops the last element
            // first, so push 1..9999 and then 65535..10000.
            for (uint32_t tag = 1; tag <= 9999; ++tag) {
                free_[free_count_++] = static_cast<uint16_t>(tag);
            }
            for (uint32_t tag = 65535; tag >= 10000; --tag) {
                free_[free_count_++] = static_cast<uint16_t>(tag);
            }
        }

        uint16_t IcmpRelay::TagAllocator::Allocate(
            const TagEntry& entry,
            std::chrono::steady_clock::time_point now) {
            std::lock_guard<std::mutex> lock(mutex_);
            if (0 == free_count_) {
                // Every tag is in flight. Never steal a live one: its reply
                // would then be delivered to the wrong client.
                return 0;
            }
            const uint16_t tag = free_[--free_count_];
            TagEntry& slot = table_[tag];
            slot = entry;
            slot.expires = now + std::chrono::seconds(3);
            return tag;
        }

        bool IcmpRelay::TagAllocator::Consume(
            uint16_t tag, TagEntry& entry,
            std::chrono::steady_clock::time_point now) {
            std::lock_guard<std::mutex> lock(mutex_);
            const auto it = table_.find(tag);
            if (table_.end() == it) {
                return false;
            }
            if (it->second.expires < now) {
                table_.erase(it);
                free_[free_count_++] = tag;  // expired: back to the pool
                return false;
            }
            entry = it->second;
            table_.erase(it);  // one-shot: a reply consumes its tag
            free_[free_count_++] = tag;
            return true;
        }

        size_t IcmpRelay::TagAllocator::Sweep(
            std::chrono::steady_clock::time_point now) {
            std::lock_guard<std::mutex> lock(mutex_);
            size_t removed = 0;
            for (auto it = table_.begin(); it != table_.end();) {
                if (it->second.expires < now) {
                    free_[free_count_++] = it->first;
                    it = table_.erase(it);
                    ++removed;
                } else {
                    ++it;
                }
            }
            return removed;
        }

        size_t IcmpRelay::TagAllocator::InFlight() const noexcept {
            std::lock_guard<std::mutex> lock(mutex_);
            return table_.size();
        }

        size_t IcmpRelay::TagAllocator::Free() const noexcept {
            std::lock_guard<std::mutex> lock(mutex_);
            return free_count_;
        }

        IcmpRelay::IcmpRelay(asio::ip::icmp::socket socket)
            : socket_(std::move(socket)) {}

        void IcmpRelay::SendEchoRequest(const uint8_t* icmp_segment, size_t len,
                                        const std::array<uint8_t, 4>& dst) {
            if (len < 8 || !socket_.is_open()) {  // minimum ICMP echo header
                return;
            }
            std::error_code err;
            // bytes[0] is the top octet: the wire order matches asio's.
            const asio::ip::address_v4 addr(dst);
            socket_.send_to(asio::buffer(icmp_segment, len),
                            asio::ip::icmp::endpoint(addr, 0), 0, err);
            // Fire-and-forget: never propagate into the worker thread.
        }

        IcmpRelay::ReceiveDecision IcmpRelay::ClassifyReceive(
            const std::error_code& err, size_t n, bool socket_open) noexcept {
            if (0 < n && !err) {
                return ReceiveDecision::kProcess;
            }
            // A closed socket or a cancelled operation means the relay is
            // being torn down - re-arming would just spin. Everything else
            // is transient (raw ICMP sockets report things like
            // WSAECONNRESET after a port-unreachable) and must NOT kill the
            // receive loop.
            if (err == asio::error::operation_aborted ||
                err == asio::error::bad_descriptor || !socket_open) {
                return ReceiveDecision::kStop;
            }
            return ReceiveDecision::kBackoffReArm;
        }

        void IcmpRelay::ArmReceive(
            std::function<void(const uint8_t* ip_packet, size_t len)> on_reply) {
            on_reply_ = std::move(on_reply);
            PumpReceive(false);
        }

        void IcmpRelay::PumpReceive(bool backoff) {
            if (backoff) {
                // Brief pause between a transient error and the next receive
                // attempt so a burst of socket resets does not busy-loop the
                // worker thread.
                auto self = shared_from_this();
                retry_timer_.expires_after(std::chrono::milliseconds(10));
                retry_timer_.async_wait(
                    [this, self](const std::error_code& wait_err) {
                        if (wait_err) {
                            return;  // cancelled during shutdown
                        }
                        PumpReceive(false);
                    });
                return;
            }
            auto self = shared_from_this();
            socket_.async_receive(
                asio::buffer(recv_buf_),
                [this, self](const std::error_code& err, size_t n) {
                    const ReceiveDecision decision =
                        ClassifyReceive(err, n, self->socket_.is_open());
                    if (ReceiveDecision::kProcess == decision) {
                        // One reply that cannot be rebuilt costs that
                        // reply, not the worker thread.
                        ::vgww::core::InvokeHandlerGuarded(self->handler_errors_, [&] {
                            self->on_reply_(self->recv_buf_.data(), n);
                        });
                    }
                    if (ReceiveDecision::kStop == decision) {
                        return;  // teardown: never re-arm a dead socket
                    }
                    // n>0 (keep pumping) or a transient error/n==0 (pump
                    // after a short backoff): survive both. Guarded
                    // separately so a throwing delivery never skips it.
                    ::vgww::core::InvokeHandlerGuarded(self->handler_errors_, [&] {
                        self->PumpReceive(
                            ReceiveDecision::kBackoffReArm == decision);
                    });
                });
        }

    }  // namespace relay
}  // namespace vgww
