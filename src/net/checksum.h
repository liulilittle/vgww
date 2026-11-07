// ============================================================================
// checksum.h - Internet checksum utilities (RFC 1071).
//
// Used by the ICMP responder (header+payload checksum) and by the UDP/TCP
// frame builders on the return path (pseudo-header included). xtcp computes
// its own segment checksums; these helpers serve VGWW's own frame builders.
// ============================================================================
#pragma once

#include <cstdint>
#include <cstddef>

namespace vgww {
    namespace net {

        /// RFC 1071 checksum over `len` bytes. Odd lengths are padded with a
        /// zero byte internally. `initial` carries a pre-computed partial sum
        /// (e.g. from a pseudo-header); folding completes inside.
        inline uint16_t InternetChecksum(const uint8_t* data, size_t len,
                                         uint32_t initial = 0) noexcept {
            uint32_t sum = initial;
            size_t i = 0;
            while (i + 1 < len) {
                sum += static_cast<uint32_t>((data[i] << 8) | data[i + 1]);
                i += 2;
            }
            if (i < len) {
                sum += static_cast<uint32_t>(data[i] << 8);
            }
            while (sum >> 16) {
                sum = (sum & 0xFFFFu) + (sum >> 16);
            }
            return static_cast<uint16_t>(~sum & 0xFFFFu);
        }

        /// Partial 16-bit-word sum of the IPv4 pseudo-header (src, dst, zero
        /// byte, protocol, upper-layer length). All inputs are wire order.
        /// Feed as `initial` to InternetChecksum() over the L4 segment.
        inline uint32_t PseudoHeaderSum(const uint8_t src[4], const uint8_t dst[4],
                                        uint8_t proto, uint16_t upper_len) noexcept {
            uint32_t sum = 0;
            sum += static_cast<uint32_t>((src[0] << 8) | src[1]);
            sum += static_cast<uint32_t>((src[2] << 8) | src[3]);
            sum += static_cast<uint32_t>((dst[0] << 8) | dst[1]);
            sum += static_cast<uint32_t>((dst[2] << 8) | dst[3]);
            sum += static_cast<uint32_t>(proto);
            sum += static_cast<uint32_t>(upper_len);
            return sum;
        }

        /// Partial 16-bit-word sum of the IPv6 pseudo-header
        /// (src(16) + dst(16) + length(4) + zeros(3) + next-header(1)).
        /// `upper_len` is the RFC 2460 32-bit length field, so it is taken as
        /// size_t and folded as two 16-bit words; a uint16_t parameter would
        /// silently truncate jumbogram lengths.
        inline uint32_t PseudoHeaderSum6(const uint8_t src[16],
                                         const uint8_t dst[16], uint8_t proto,
                                         size_t upper_len) noexcept {
            uint32_t sum = 0;
            for (size_t i = 0; i < 16; i += 2) {
                sum += static_cast<uint32_t>((src[i] << 8) | src[i + 1]);
                sum += static_cast<uint32_t>((dst[i] << 8) | dst[i + 1]);
            }
            sum += static_cast<uint32_t>((upper_len >> 16) & 0xFFFFu);
            sum += static_cast<uint32_t>(upper_len & 0xFFFFu);
            sum += static_cast<uint32_t>(proto);
            return sum;
        }


    }  // namespace net
}  // namespace vgww
