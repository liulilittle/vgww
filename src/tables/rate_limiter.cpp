// ============================================================================
// rate_limiter.cpp - Per-client token-bucket rate limiting.
//
// Bucket math: each direction keeps `capacity` tokens (bytes). Every admission
// check adds `elapsed * rate_bps` tokens (capped at capacity) then spends
// `len` if affordable. Capacity = max(rate * burst_seconds, min_capacity) so
// an idle client can always burst at least one frame. Buckets for clients
// that stop talking are reaped by SweepIdle (called on a cadence from Allow),
// so the maps stay bounded on a LAN whose clients come and go.
// ============================================================================
#include "tables/rate_limiter.h"

#include <algorithm>
#include <cmath>

namespace vgww {
    namespace tables {

        RateLimiter::RateLimiter(RateLimiterParams p) noexcept
            : params_(p) {
            up_buckets_.reserve(16);
            down_buckets_.reserve(16);
        }

        void RateLimiter::SetRules(
            std::shared_ptr<const std::vector<RateLimitRule>> rules) {
            // batch303: build the immutable MAC -> caps index ONCE here (the
            // control plane) so Allow() does one hash lookup per packet. The
            // FIRST rule for a MAC wins, matching the old linear scan.
            auto index = std::make_shared<RuleIndex>();
            if (rules) {
                index->reserve(rules->size());
                for (const RateLimitRule& rule : *rules) {
                    index->try_emplace(
                        rule.mac,
                        RuleCaps{rule.uplink_kbps, rule.downlink_kbps});
                }
            }
            std::atomic_store(
                &index_,
                std::shared_ptr<const RuleIndex>(std::move(index)));
        }

        double RateLimiter::RateBps(uint32_t kbps) const noexcept {
            return static_cast<double>(kbps) * 1000.0 / 8.0;
        }

        void RateLimiter::SweepIdle(
            std::chrono::steady_clock::time_point now) noexcept {
            const auto reap = [now](auto& map) {
                for (auto it = map.begin(); it != map.end();) {
                    // Fresh buckets have never been charged; after the first
                    // admission they carry a `last` refill instant.
                    if (!it->second.fresh &&
                        now - it->second.last > kIdleTtl) {
                        it = map.erase(it);
                    } else {
                        ++it;
                    }
                }
            };
            reap(up_buckets_);
            reap(down_buckets_);
        }

        size_t RateLimiter::MakeCapacity(double rate_bps) const noexcept {
            const double burst = rate_bps * params_.burst_seconds;
            return static_cast<size_t>(std::max(burst, static_cast<double>(
                                                           params_.min_capacity_bytes)));
        }

        RateLimiter::Bucket& RateLimiter::BucketFor(Direction dir,
                                                    const net::WireMac& mac) {
            if (Direction::Uplink == dir) {
                return up_buckets_[mac];
            }
            return down_buckets_[mac];
        }

        bool RateLimiter::AllowUplink(
            const net::WireMac& src, size_t len,
            std::chrono::steady_clock::time_point now) noexcept {
            return Allow(Direction::Uplink, src, len, now);
        }

        bool RateLimiter::AllowDownlink(
            const net::WireMac& dst, size_t len,
            std::chrono::steady_clock::time_point now) noexcept {
            return Allow(Direction::Downlink, dst, len, now);
        }

        bool RateLimiter::Allow(Direction dir, const net::WireMac& mac,
                                size_t len,
                                std::chrono::steady_clock::time_point now) noexcept {
            // Periodic housekeeping piggy-backed on the hot path (data-plane
            // thread only; the maps it mutates are this thread's own).
            if (0 == (++admission_count_ % kReapEveryN)) {
                SweepIdle(now);
            }

            auto index = std::atomic_load(&index_);
            if (!index || index->empty()) {
                return true;  // no policy: everything passes
            }
            const auto it = index->find(mac);
            if (it == index->end()) {
                return true;  // unconfigured client: no cap
            }
            const uint32_t kbps = (Direction::Uplink == dir)
                                      ? it->second.uplink_kbps
                                      : it->second.downlink_kbps;
            if (0 == kbps) {
                return true;  // explicit "no cap" for this direction
            }

            // batch301: Allow is noexcept and runs on the RX/TX thread; a
            // bucket-map allocation failure used to escape as std::terminate.
            // Fail open instead: a bucket we cannot allocate must not drop
            // traffic (the next admission retries the insert).
            Bucket* bucket = nullptr;
            try {
                bucket = &BucketFor(dir, mac);
            } catch (...) {
                return true;
            }
            const double rate = RateBps(kbps);
            if (bucket->fresh) {
                // Never touched before: start full so an idle client is never
                // throttled by stale state, and remember the refill instant.
                bucket->fresh = false;
                bucket->capacity = MakeCapacity(rate);
                bucket->rate_kbps = kbps;
                bucket->tokens = static_cast<double>(bucket->capacity);
                bucket->last = now;
            } else {
                // C7: a rule change re-derives the capacity. Without this an
                // old (higher-rate) bucket keeps its stale headroom - a client
                // whose cap dropped could still burst the old amount, and one
                // whose cap rose stays pinned to the old smaller capacity
                // until the 15-min idle sweep.
                if (bucket->rate_kbps != kbps) {
                    bucket->rate_kbps = kbps;
                    bucket->capacity = MakeCapacity(rate);
                    if (bucket->tokens > static_cast<double>(bucket->capacity)) {
                        bucket->tokens = static_cast<double>(bucket->capacity);
                    }
                }
                // Refill from the previous refill instant.
                const double elapsed_s =
                    std::chrono::duration<double>(now - bucket->last).count();
                bucket->last = now;
                if (elapsed_s > 0.0) {
                    bucket->tokens += elapsed_s * rate;
                    if (bucket->tokens > static_cast<double>(bucket->capacity)) {
                        bucket->tokens = static_cast<double>(bucket->capacity);
                    }
                }
            }

            if (bucket->tokens >= static_cast<double>(len)) {
                bucket->tokens -= static_cast<double>(len);
                return true;
            }
            return false;
        }

    }  // namespace tables
}  // namespace vgww
