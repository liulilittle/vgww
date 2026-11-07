// ============================================================================
// test_checksum.cpp - RFC 1071 Internet checksum + pseudo-header accumulators.
//
// net/checksum.h is the checksum foundation under ICMP, DHCP, NDP and the
// dataplane's own frame builders. It had no dedicated test: the pseudo-header
// helpers were only exercised indirectly through protocol tests, and
// PseudoHeaderSum6 is not called from production at all (ndp.cpp hand-rolls an
// equivalent), so nothing pinned its contract.
//
// This file pins the contract directly, including the RFC 2460 32-bit length
// field that PseudoHeaderSum6 must accept.
// ============================================================================
#define CHECK(cond)                                                        \
    do {                                                                   \
        if (!(cond)) {                                                     \
            std::fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__,  \
                         __LINE__, #cond);                                 \
            return 1;                                                      \
        }                                                                  \
    } while (0)

#include "net/checksum.h"

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

namespace vgww {

    /// RFC 1071 worked example: the reference implementation's own test vector.
    /// Summing the checksum over the data again must yield 0xFFFF-style zero
    /// (RFC 1071 section 3), which is the property every caller relies on.
    int TestChecksumVerifiesToZero() {
        const std::uint8_t data[] = {0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7};
        const std::uint16_t ck = net::InternetChecksum(data, sizeof(data));
        // Re-running with the checksum inserted in place must verify to zero.
        std::uint8_t with_ck[sizeof(data) + 2];
        std::memcpy(with_ck, data, sizeof(data));
        with_ck[sizeof(data)] = static_cast<std::uint8_t>(ck >> 8);
        with_ck[sizeof(data) + 1] = static_cast<std::uint8_t>(ck & 0xFF);
        CHECK(0 == net::InternetChecksum(with_ck, sizeof(with_ck)));
        return 0;
    }

    /// RFC 1071 section 1 reference values (the canonical ones from the RFC).
    int TestChecksumRfcValues() {
        // RFC 1071 section 3: the sum of the example header before complement.
        // 0001 f203 f4f5 f6f7 -> 0xDDF2, checksum 0x220D.
        const std::uint8_t hdr[] = {0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7};
        CHECK(0x220D == net::InternetChecksum(hdr, sizeof(hdr)));

        // All zeroes: complement of zero is 0xFFFF.
        const std::uint8_t zeros[8] = {};
        CHECK(0xFFFF == net::InternetChecksum(zeros, sizeof(zeros)));

        // All ones: 0xFFFF * 4 folds to 0xFFFC + 3 = 0xFFFF -> complement 0x0000.
        const std::uint8_t ones[8] = {0xFF, 0xFF, 0xFF, 0xFF,
                                      0xFF, 0xFF, 0xFF, 0xFF};
        CHECK(0x0000 == net::InternetChecksum(ones, sizeof(ones)));
        return 0;
    }

    /// Odd lengths are padded with a zero byte (RFC 1071). An odd buffer and
    /// the same buffer with a trailing zero must produce the same checksum.
    int TestOddLengthPadding() {
        const std::uint8_t odd[] = {0x12, 0x34, 0x56};
        const std::uint8_t even[] = {0x12, 0x34, 0x56, 0x00};
        CHECK(net::InternetChecksum(odd, sizeof(odd)) ==
              net::InternetChecksum(even, sizeof(even)));

        // A single byte must be treated as (byte << 8), not (byte).
        const std::uint8_t one[] = {0xAB};
        const std::uint8_t one_padded[] = {0xAB, 0x00};
        CHECK(net::InternetChecksum(one, 1) == net::InternetChecksum(one_padded, 2));
        return 0;
    }

    /// A raw sum that still overflows after ONE carry fold (RFC 1071 requires
    /// folding until the sum fits in 16 bits). Buffer FF FF FF FF 00 01 sums
    /// to 0x1FFFF; folding once leaves 0x10000 which STILL overflows, so a
    /// single-pass implementation returns the wrong value.
    int TestCarryFoldsRepeatedly() {
        const std::uint8_t data[] = {0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x01};
        // raw = 0xFFFF + 0xFFFF + 0x0001 = 0x1FFFF
        // fold1 = 0xFFFF + 1 = 0x10000 (still 17 bits)
        // fold2 = 0x0000 + 1 = 0x0001 -> complement 0xFFFE
        CHECK(0xFFFE == net::InternetChecksum(data, sizeof(data)));
        // A single-pass fold would yield ~0x10000 -> 0xFFFF. Assert the
        // result is NOT that value, so the loop cannot be shortened to an if.
        CHECK(0xFFFF != net::InternetChecksum(data, sizeof(data)));
        return 0;
    }

    /// `initial` carries a partial sum: feeding the two halves separately must
    /// equal feeding the whole buffer at once.
    int TestInitialCarriesPartialSum() {
        const std::uint8_t whole[] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
        const std::uint16_t one_shot = net::InternetChecksum(whole, sizeof(whole));

        const std::uint32_t prefix = net::InternetChecksum(whole, 4);
        // InternetChecksum returns a COMPLEMENT, so to continue the sum we
        // must fold the raw partial sum, not the complement.
        std::uint32_t raw = 0;
        raw += static_cast<std::uint32_t>((whole[0] << 8) | whole[1]);
        raw += static_cast<std::uint32_t>((whole[2] << 8) | whole[3]);
        const std::uint16_t split =
            net::InternetChecksum(whole + 4, 2, raw);
        CHECK(one_shot == split);
        (void)prefix;
        return 0;
    }

    /// RFC 768/793: the IPv4 pseudo-header is src(4) + dst(4) + zero(1) +
    /// protocol(1) + length(2), all wire order. The protocol sits in the LOW
    /// byte of its 16-bit word (the zero byte is the high one).
    int TestIpv4PseudoHeaderLayout() {
        const std::uint8_t src[4] = {192, 168, 0, 1};
        const std::uint8_t dst[4] = {10, 0, 0, 2};

        // Manual sum with the protocol in the low byte.
        std::uint32_t expect = 0;
        expect += (192u << 8) | 168u;
        expect += (0u << 8) | 1u;
        expect += (10u << 8) | 0u;
        expect += (0u << 8) | 2u;
        expect += 17u;                 // protocol in the low byte
        expect += 1234u;               // upper-layer length

        CHECK(expect == net::PseudoHeaderSum(src, dst, 17, 1234));

        // The protocol must NOT be shifted into the high byte: doing so would
        // add 0x1100 instead of 0x0011, a difference of 0x10EF (mod 0xFFFF).
        CHECK(expect != net::PseudoHeaderSum(src, dst, 17, 1234) - 0x10EF);
        return 0;
    }

    /// A real UDP datagram verifies to zero once the pseudo-header is folded
    /// in (RFC 768). This is the exact property every frame builder relies on.
    int TestUdpVerifiesToZero() {
        // Minimal UDP header + "hi": src 1234, dst 53, len 10, cksum 0.
        std::uint8_t udp[10] = {0x04, 0xD2, 0x00, 0x35, 0x00, 0x0A, 0x00, 0x00,
                                'h',  'i'};
        const std::uint8_t src[4] = {192, 168, 1, 10};
        const std::uint8_t dst[4] = {8, 8, 8, 8};
        const std::uint32_t pseudo =
            net::PseudoHeaderSum(src, dst, 17, sizeof(udp));
        const std::uint16_t ck = net::InternetChecksum(udp, sizeof(udp), pseudo);
        udp[6] = static_cast<std::uint8_t>(ck >> 8);
        udp[7] = static_cast<std::uint8_t>(ck & 0xFF);
        CHECK(0 == net::InternetChecksum(udp, sizeof(udp), pseudo));
        return 0;
    }

    /// A real ICMPv6 Echo Request verifies to zero over the pseudo-header.
    /// This mirrors what ndp.cpp / the ICMPv6 path must produce.
    int TestIcmpV6VerifiesToZero() {
        std::uint8_t src[16] = {};
        std::uint8_t dst[16] = {};
        src[0] = 0xFE; src[1] = 0x80; src[15] = 0x01;   // fe80::1
        dst[0] = 0xFF; dst[1] = 0x02; dst[15] = 0x01;   // ff02::1

        // ICMPv6 Echo Request: type 128, code 0, checksum 0, id, seq, payload.
        std::uint8_t icmp[16] = {128, 0, 0, 0, 0x12, 0x34, 0x00, 0x01,
                                 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00};
        const std::uint32_t pseudo =
            net::PseudoHeaderSum6(src, dst, 58, sizeof(icmp));
        const std::uint16_t ck = net::InternetChecksum(icmp, sizeof(icmp), pseudo);
        icmp[2] = static_cast<std::uint8_t>(ck >> 8);
        icmp[3] = static_cast<std::uint8_t>(ck & 0xFF);
        CHECK(0 == net::InternetChecksum(icmp, sizeof(icmp), pseudo));
        return 0;
    }

    /// RFC 2460: the IPv6 pseudo-header length field is 32 bits. A payload
    /// above 65535 bytes (IPv6 jumbograms) must not silently truncate - the
    /// accumulator folds the length as two 16-bit words, exactly like the
    /// hand-rolled SumAddr version inside ndp.cpp.
    int TestIpv6PseudoLengthIs32Bit() {
        std::uint8_t src[16] = {};
        std::uint8_t dst[16] = {};
        src[15] = 1;
        dst[15] = 2;

        // For lengths below 65536 the high word is zero.
        const std::uint32_t small = net::PseudoHeaderSum6(src, dst, 58, 1000);
        CHECK(small == 1 + 2 + 58 + 1000);

        // 70000 = 1 * 65536 + 4464: the 32-bit field contributes BOTH words
        // 0x0001 and 0x1170, i.e. 1 + 4464 to the 16-bit accumulator.
        const std::uint32_t big = net::PseudoHeaderSum6(src, dst, 58, 70000);
        CHECK(big == 1 + 2 + 58 + 1 + 4464);

        // Truncating to the low 16 bits would drop the 0x0001 word entirely -
        // that must NOT match.
        CHECK(big != 1 + 2 + 58 + (70000u & 0xFFFFu));

        // A full 64 KiB boundary: 65536 contributes only the high word 0x0001.
        const std::uint32_t boundary =
            net::PseudoHeaderSum6(src, dst, 58, 65536);
        CHECK(boundary == 1 + 2 + 58 + 1);
        return 0;
    }

}  // namespace vgww

int main() {
    if (vgww::TestChecksumVerifiesToZero()) return 1;
    if (vgww::TestChecksumRfcValues()) return 1;
    if (vgww::TestOddLengthPadding()) return 1;
    if (vgww::TestCarryFoldsRepeatedly()) return 1;
    if (vgww::TestInitialCarriesPartialSum()) return 1;
    if (vgww::TestIpv4PseudoHeaderLayout()) return 1;
    if (vgww::TestUdpVerifiesToZero()) return 1;
    if (vgww::TestIcmpV6VerifiesToZero()) return 1;
    if (vgww::TestIpv6PseudoLengthIs32Bit()) return 1;
    std::puts("test_checksum: ALL PASS");
    return 0;
}
