// ============================================================================
// rate_limiter.h - Per-client token-bucket rate limiting.
//
// A client (identified by MAC) may have an uplink cap (bytes leaving the LAN)
// and a downlink cap (bytes entering the LAN). Each direction is an
// independent token bucket: tokens accumulate at `rate` and burst up to a
// configured headroom, so short bursts pass while long-term throughput is
// pinned to the configured rate.
//
// Threading: SetRules() is control-plane (called from the control loop, where
// a mutex protects the rule snapshot). AllowUplink/AllowDownlink are data-plane
// and MUST be called from the single RX/TX loop thread only; bucket state is
// held in caller-provided storage so no data-plane locking is introduced.
// ============================================================================
#pragma once

#include "net/eth.h"

#include <chrono>
#include <cstdint>
#include <memory>
#include <unordered_map>
#include <vector>

namespace vgww {
    namespace tables {

        /// Tunables for token-bucket capacity (burst headroom).
        struct RateLimiterParams {
            /// How many seconds of steady-state rate a subscriber may burst.
            double burst_seconds = 1.0;
            /// Absolute floor on bucket capacity (bytes): a single frame must
            /// always fit, otherwise even idle clients get dropped.
            size_t min_capacity_bytes = 1500;
        };

        /// One rate-limit rule: 0 kbps means "no cap" for that direction.
        struct RateLimitRule {
            net::WireMac mac{};  ///< client MAC
            uint32_t uplink_kbps = 0;
            uint32_t downlink_kbps = 0;
        };

        /// Thread-safe rule store + lock-free data-plane admission checks.
        class RateLimiter final {
        public:
            explicit RateLimiter(RateLimiterParams p = RateLimiterParams()) noexcept;
            ~RateLimiter() = default;

            /// Replaces the active rule set (control plane). Builds the
            /// immutable MAC -> caps index once and publishes it atomically;
            /// buckets for removed rules are evicted lazily. May throw on
            /// allocation failure (the caller is the control loop, behind
            /// RunGuarded).
            void SetRules(
                std::shared_ptr<const std::vector<RateLimitRule>> rules);

            /// Returns true when `len` bytes from `src` may transit uplink.
            /// Data-plane (RX/TX loop thread only).
            bool AllowUplink(const net::WireMac& src, size_t len,
                             std::chrono::steady_clock::time_point now) noexcept;

            /// Returns true when `len` bytes may transit downlink toward `dst`.
            /// Data-plane (RX/TX loop thread only).
            bool AllowDownlink(const net::WireMac& dst, size_t len,
                               std::chrono::steady_clock::time_point now) noexcept;

            /// Reclaims buckets idle past the TTL. Data-plane compatible (the
            /// RX/TX loop thread calls this on a cadence inside Allow).
            void SweepIdle(std::chrono::steady_clock::time_point now) noexcept;

            /// Number of live buckets (uplink + downlink) - test aid / health.
            size_t BucketCount() const noexcept {
                return up_buckets_.size() + down_buckets_.size();
            }

        private:
            enum class Direction : uint8_t { Uplink, Downlink };

            bool Allow(Direction dir, const net::WireMac& mac, size_t len,
                       std::chrono::steady_clock::time_point now) noexcept;

            /// One token bucket.
            struct Bucket {
                double tokens = 0.0;
                size_t capacity = 1500;  ///< bytes
                uint32_t rate_kbps = 0;  ///< rule rate the capacity was built for (C7)
                std::chrono::steady_clock::time_point last;
                bool fresh = true;  ///< never touched before
            };

            Bucket& BucketFor(Direction dir, const net::WireMac& mac);
            double RateBps(uint32_t kbps) const noexcept;
            size_t MakeCapacity(double rate_bps) const noexcept;

            /// Every N admissions, reap idle buckets (bounded maps).
            static constexpr uint32_t kReapEveryN = 1024;
            uint32_t admission_count_ = 0;
            static constexpr auto kIdleTtl = std::chrono::minutes(15);

            /// Per-MAC caps, built once per rule snapshot on the control
            /// plane. batch303: the data plane used to scan every rule per
            /// packet (the cap allows 4096); one hash lookup replaces it.
            struct RuleCaps {
                uint32_t uplink_kbps = 0;
                uint32_t downlink_kbps = 0;
            };
            using RuleIndex =
                std::unordered_map<net::WireMac, RuleCaps, net::WireMacHash>;

            const RateLimiterParams params_;
            std::shared_ptr<const RuleIndex> index_;
            std::unordered_map<net::WireMac, Bucket, net::WireMacHash> up_buckets_;
            std::unordered_map<net::WireMac, Bucket, net::WireMacHash> down_buckets_;
        };

    }  // namespace tables
}  // namespace vgww
