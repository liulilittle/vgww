// ============================================================================
// test_ip_addr.cpp - IpAddress value type + hash contract (net/ip_addr.h).
//
// IpAddress is the key type for every address-keyed container in the project
// (flow tables, neighbours, UDP relay, dataplane). Its 100-line header had no
// dedicated test: the value semantics were only exercised indirectly, and the
// hash was never checked against the ONE property containers actually require
// - equal keys must hash equally.
//
// The byte layout is the load-bearing contract:
//   * v4 lives in bytes[12..15] (IPv4-mapped), preserving wire order
//   * FromV4NetOrder's "first octet in the LOW byte" convention matches
//     core/config.cpp ParseIpv4
// ============================================================================
#define CHECK(cond)                                                        \
    do {                                                                   \
        if (!(cond)) {                                                     \
            std::fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__,  \
                         __LINE__, #cond);                                 \
            return 1;                                                      \
        }                                                                  \
    } while (0)

#include "net/ip_addr.h"

#include <cstdio>
#include <cstring>
#include <set>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace vgww {

    /// v4 addresses must land in bytes[12..15] in wire order, with bytes[0..11]
    /// zero. A different placement silently breaks every range test.
    int TestV4ByteLayout() {
        const uint8_t wire[4] = {192, 168, 1, 10};
        const net::IpAddress a = net::IpAddress::FromV4BigEndian(wire);
        CHECK(a.IsV4());
        for (int i = 0; i < 12; ++i) {
            CHECK(0 == a.bytes[static_cast<size_t>(i)]);
        }
        CHECK(192 == a.bytes[12]);
        CHECK(168 == a.bytes[13]);
        CHECK(1 == a.bytes[14]);
        CHECK(10 == a.bytes[15]);

        uint8_t back[4] = {0, 0, 0, 0};
        a.ToV4Wire(back);
        CHECK(0 == std::memcmp(back, wire, 4));
        return 0;
    }

    /// FromV4NetOrder's convention: the FIRST octet is the LOW byte of the
    /// numeric value (this is what core::ParseIpv4 produces). Round-tripping
    /// through the wire bytes must give 192.168.1.10 for 0x0A01A8C0.
    int TestV4NetOrderConvention() {
        const uint32_t net_order = 0x0A01A8C0u;  // 192.168.1.10, first octet low
        const net::IpAddress a = net::IpAddress::FromV4NetOrder(net_order);
        CHECK(192 == a.bytes[12]);
        CHECK(168 == a.bytes[13]);
        CHECK(1 == a.bytes[14]);
        CHECK(10 == a.bytes[15]);

        // The two constructors must agree for the same address.
        const uint8_t wire[4] = {192, 168, 1, 10};
        CHECK(a == net::IpAddress::FromV4BigEndian(wire));

        // 0.0.0.0 and 255.255.255.255 are the boundary encodings.
        const net::IpAddress zero = net::IpAddress::FromV4NetOrder(0u);
        for (int i = 0; i < 16; ++i) {
            CHECK(0 == zero.bytes[static_cast<size_t>(i)]);
        }
        const net::IpAddress ones = net::IpAddress::FromV4NetOrder(0xFFFFFFFFu);
        for (int i = 12; i < 16; ++i) {
            CHECK(0xFF == ones.bytes[static_cast<size_t>(i)]);
        }
        return 0;
    }

    /// v6 uses all 16 bytes verbatim.
    int TestV6ByteLayout() {
        uint8_t wire[16] = {};
        wire[0] = 0xFE;
        wire[1] = 0x80;
        wire[15] = 0x01;
        const net::IpAddress a = net::IpAddress::FromV6(wire);
        CHECK(!a.IsV4());
        CHECK(net::Family::kV6 == a.family);
        CHECK(0 == std::memcmp(a.bytes.data(), wire, 16));
        return 0;
    }

    /// A v4 and a v6 address with identical trailing bytes must NOT compare
    /// equal - the family is part of the identity. Without this a map keyed by
    /// IpAddress would collide an IPv4 and an IPv6 endpoint.
    int TestFamilyIsPartOfIdentity() {
        uint8_t v6wire[16] = {};
        v6wire[12] = 192;
        v6wire[13] = 168;
        v6wire[14] = 1;
        v6wire[15] = 10;
        const net::IpAddress v6 = net::IpAddress::FromV6(v6wire);

        const uint8_t v4wire[4] = {192, 168, 1, 10};
        const net::IpAddress v4 = net::IpAddress::FromV4BigEndian(v4wire);

        // The 16 bytes are IDENTICAL; only the family differs.
        CHECK(0 == std::memcmp(v4.bytes.data(), v6.bytes.data(), 16));
        CHECK(v4 != v6);
        CHECK(!(v4 == v6));

        // Ordering must be total and family-first, so a std::set never sees
        // two "equal" elements.
        CHECK(v4 < v6);
        CHECK(!(v6 < v4));
        return 0;
    }

    /// operator== must compare the full 16 bytes, not just the v4 tail.
    int TestEqualityComparesAllBytes() {
        uint8_t a[16] = {};
        uint8_t b[16] = {};
        a[0] = 0x11;
        b[0] = 0x22;
        // Same trailing v4-shaped tail, different leading byte.
        a[15] = b[15] = 0x05;
        const net::IpAddress x = net::IpAddress::FromV6(a);
        const net::IpAddress y = net::IpAddress::FromV6(b);
        CHECK(x != y);

        // Identical bytes must be equal.
        const net::IpAddress z = net::IpAddress::FromV6(a);
        CHECK(x == z);
        return 0;
    }

    /// The ONLY property containers require: a == b implies hash(a) == hash(b).
    /// Also verifies the hash actually depends on both the family and the data
    /// (otherwise every key would collide into one bucket and lookups would
    /// degrade to O(n) - correctness survives, but the table becomes a list).
    int TestHashContract() {
        const net::IpAddressHash hash;

        const uint8_t w1[4] = {10, 0, 0, 1};
        const uint8_t w2[4] = {10, 0, 0, 2};
        const net::IpAddress a = net::IpAddress::FromV4BigEndian(w1);
        const net::IpAddress a2 = net::IpAddress::FromV4BigEndian(w1);
        const net::IpAddress b = net::IpAddress::FromV4BigEndian(w2);

        // a == a2  =>  hash(a) == hash(a2)
        CHECK(a == a2);
        CHECK(hash(a) == hash(a2));

        // Different addresses should (with overwhelming probability) differ.
        CHECK(a != b);
        CHECK(hash(a) != hash(b));

        // Family participates in the hash: a v4 and a v6 with the same 16
        // bytes must not collide if the implementation includes family.
        // (Containers stay correct either way because == distinguishes them,
        // but including it avoids a guaranteed collision pair.)
        uint8_t v6wire[16] = {};
        v6wire[12] = 10;
        v6wire[15] = 1;
        const net::IpAddress v6 = net::IpAddress::FromV6(v6wire);
        CHECK(v6 != a);
        CHECK(hash(v6) != hash(a));
        return 0;
    }

    /// A real container round-trip: insert a spread of addresses, look every
    /// one up, and confirm distinct addresses stay distinct.
    int TestUnorderedSetRoundTrip() {
        std::unordered_set<net::IpAddress, net::IpAddressHash> set;
        std::vector<net::IpAddress> inserted;
        for (int i = 0; i < 200; ++i) {
            const uint8_t wire[4] = {10, 0, static_cast<uint8_t>(i / 256),
                                     static_cast<uint8_t>(i % 256)};
            const net::IpAddress a = net::IpAddress::FromV4BigEndian(wire);
            set.insert(a);
            inserted.push_back(a);
        }
        CHECK(inserted.size() == set.size());
        for (const auto& a : inserted) {
            CHECK(1 == set.count(a));
        }
        // A never-inserted neighbour must be absent.
        const uint8_t missing[4] = {10, 0, 9, 9};
        CHECK(0 == set.count(net::IpAddress::FromV4BigEndian(missing)));
        return 0;
    }

    /// operator< must give a strict weak ordering usable by std::set/map:
    /// irreflexive, antisymmetric, and transitive over a sample.
    int TestOrderingIsStrictWeak() {
        std::vector<net::IpAddress> all;
        for (int i = 0; i < 40; ++i) {
            const uint8_t wire[4] = {172, 16, 0, static_cast<uint8_t>(i)};
            all.push_back(net::IpAddress::FromV4BigEndian(wire));
        }
        uint8_t v6wire[16] = {};
        v6wire[15] = 1;
        all.push_back(net::IpAddress::FromV6(v6wire));

        for (const auto& x : all) {
            CHECK(!(x < x));  // irreflexive
            for (const auto& y : all) {
                if (x == y) {
                    CHECK(!(x < y) && !(y < x));
                } else {
                    // exactly one direction
                    CHECK((x < y) != (y < x));
                }
            }
        }
        // std::set deduplicates: 41 distinct addresses -> 41 elements.
        std::set<net::IpAddress> ordered(all.begin(), all.end());
        CHECK(all.size() == ordered.size());
        return 0;
    }

    /// batch315: the hash must SPREAD keys, not just be consistent. The old
    /// hash left the low 32 bits of its state identical for every IPv4
    /// address (v4 lives in bytes[12..15], so the second 8-byte chunk has a
    /// zero low half). MSVC's unordered_map derives the bucket from those low
    /// bits, so 4,096 sequential v4 addresses produced ONE bucket of size
    /// 4,096 - every neighbour-table and UDP-flow lookup became a linear
    /// scan. The assertion is deterministic: a good hash over 4,096 keys and
    /// >=4,096 buckets cannot leave a bucket anywhere near 64 entries.
    int TestHashSpreadsIpv4Buckets() {
        {
            std::unordered_map<net::IpAddress, int, net::IpAddressHash> m;
            m.reserve(4096);
            for (uint32_t i = 0; i < 4096; ++i) {
                const uint8_t wire[4] = {
                    10, static_cast<uint8_t>((i >> 16) & 0xFF),
                    static_cast<uint8_t>((i >> 8) & 0xFF),
                    static_cast<uint8_t>(i & 0xFF)};
                m.emplace(net::IpAddress::FromV4BigEndian(wire), 1);
            }
            size_t max_bucket = 0;
            for (size_t b = 0; b < m.bucket_count(); ++b) {
                if (m.bucket_size(b) > max_bucket) {
                    max_bucket = m.bucket_size(b);
                }
            }
            std::fprintf(stderr, "[b315] v4 buckets=%zu max_bucket=%zu\n",
                         m.bucket_count(), max_bucket);
            CHECK(max_bucket <= 64);
        }
        {
            // IPv6 must keep spreading too (its bytes were already varied).
            std::unordered_map<net::IpAddress, int, net::IpAddressHash> m;
            m.reserve(4096);
            for (uint32_t i = 0; i < 4096; ++i) {
                uint8_t wire[16] = {0xFE, 0x80};
                wire[12] = static_cast<uint8_t>((i >> 24) & 0xFF);
                wire[13] = static_cast<uint8_t>((i >> 16) & 0xFF);
                wire[14] = static_cast<uint8_t>((i >> 8) & 0xFF);
                wire[15] = static_cast<uint8_t>(i & 0xFF);
                m.emplace(net::IpAddress::FromV6(wire), 1);
            }
            size_t max_bucket = 0;
            for (size_t b = 0; b < m.bucket_count(); ++b) {
                if (m.bucket_size(b) > max_bucket) {
                    max_bucket = m.bucket_size(b);
                }
            }
            std::fprintf(stderr, "[b315] v6 buckets=%zu max_bucket=%zu\n",
                         m.bucket_count(), max_bucket);
            CHECK(max_bucket <= 64);
        }
        return 0;
    }

}  // namespace vgww

int main() {
    if (vgww::TestV4ByteLayout()) return 1;
    if (vgww::TestV4NetOrderConvention()) return 1;
    if (vgww::TestV6ByteLayout()) return 1;
    if (vgww::TestFamilyIsPartOfIdentity()) return 1;
    if (vgww::TestEqualityComparesAllBytes()) return 1;
    if (vgww::TestHashContract()) return 1;
    if (vgww::TestUnorderedSetRoundTrip()) return 1;
    if (vgww::TestOrderingIsStrictWeak()) return 1;
    if (vgww::TestHashSpreadsIpv4Buckets()) return 1;
    std::puts("test_ip_addr: ALL PASS");
    return 0;
}
