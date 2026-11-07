// ============================================================================
// ip_addr.h - Unified IPv4/IPv6 address value type used across all layers.
//
// Convention notes:
//   * IPv4 addresses are stored as the 4-byte big-endian wire sequence in
//     bytes[12..15] (IPv4-mapped layout), matching how frames carry them.
//   * The numeric-value convention follows inet_addr(): helper accessors
//     expose octets explicitly to avoid endianness bugs (see discover.md).
// ============================================================================
#pragma once

#include <array>
#include <cstdint>
#include <cstring>
#include <string>

namespace vgww {
    namespace net {

        /// Address family tag (kept tiny for hot-path keys).
        enum class Family : uint8_t { kV4 = 4, kV6 = 6 };

        /// Fixed-size IP address usable as an associative-container key.
        struct IpAddress final {
            Family family = Family::kV4;
            // Big-endian wire order: v4 uses bytes[12..15], v6 uses all 16.
            std::array<uint8_t, 16> bytes{};

            static IpAddress FromV4BigEndian(const uint8_t wire[4]) noexcept {
                IpAddress addr;
                addr.family = Family::kV4;
                addr.bytes[12] = wire[0];
                addr.bytes[13] = wire[1];
                addr.bytes[14] = wire[2];
                addr.bytes[15] = wire[3];
                return addr;
            }

            static IpAddress FromV4NetOrder(uint32_t net_order_value) noexcept {
                // Numeric value convention: first octet is the LOW byte.
                const uint8_t wire[4] = {
                    static_cast<uint8_t>(net_order_value & 0xFF),
                    static_cast<uint8_t>((net_order_value >> 8) & 0xFF),
                    static_cast<uint8_t>((net_order_value >> 16) & 0xFF),
                    static_cast<uint8_t>((net_order_value >> 24) & 0xFF),
                };
                return FromV4BigEndian(wire);
            }

            static IpAddress FromV6(const uint8_t wire[16]) noexcept {
                IpAddress addr;
                addr.family = Family::kV6;
                std::memcpy(addr.bytes.data(), wire, 16);
                return addr;
            }

            /// Writes the v4 wire bytes (network order) into `out4`.
            void ToV4Wire(uint8_t out4[4]) const noexcept {
                out4[0] = bytes[12];
                out4[1] = bytes[13];
                out4[2] = bytes[14];
                out4[3] = bytes[15];
            }

            bool IsV4() const noexcept { return Family::kV4 == family; }

            friend bool operator==(const IpAddress& a, const IpAddress& b) noexcept {
                return a.family == b.family && 0 == std::memcmp(a.bytes.data(),
                                                                b.bytes.data(), 16);
            }

            friend bool operator!=(const IpAddress& a, const IpAddress& b) noexcept {
                return !(a == b);
            }

            bool operator<(const IpAddress& other) const noexcept {
                if (family != other.family) {
                    return family < other.family;
                }
                return bytes < other.bytes;
            }
        };

        /// FNV-1a style hash over family+bytes, finished with the Murmur3
        /// fmix64 avalanche (the same finalizer the flow dispatcher uses).
        ///
        /// batch315: the avalanche is load-bearing for IPv4. v4 addresses live
        /// in bytes[12..15], so the second 8-byte chunk has ZERO low 32 bits
        /// and the raw FNV state's low 32 bits are identical for EVERY v4
        /// address. MSVC's unordered_map derives the bucket from the low bits,
        /// so all IPv4 keys landed in one bucket: 4,096 addresses produced
        /// bucket_count=4,096 with max_bucket=4,096, turning every lookup in
        /// the neighbour table and the UDP flow table into a linear scan
        /// (measured: 50,000 Learn() calls took 6.2 s instead of ~5 ms).
        struct IpAddressHash final {
            size_t operator()(const IpAddress& addr) const noexcept {
                uint64_t h = 1469598103934665603ull ^ static_cast<uint64_t>(addr.family);
                for (size_t i = 0; i < 16; i += 8) {
                    uint64_t chunk = 0;
                    std::memcpy(&chunk, &addr.bytes[i], 8);
                    h ^= chunk;
                    h *= 1099511628211ull;
                }
                h ^= h >> 33;
                h *= 0xFF51AFD7ED558CCDull;
                h ^= h >> 33;
                h *= 0xC4CEB9FE1A85EC53ull;
                h ^= h >> 33;
                return static_cast<size_t>(h);
            }
        };

    }  // namespace net
}  // namespace vgww
