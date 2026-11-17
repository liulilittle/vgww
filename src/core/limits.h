// ============================================================================
// limits.h - Centralized super-large guards (native white base).
//
// Single-sourced caps for files, lists, and API vectors to keep the
// pure C++ native GUI and data plane flat under super-large load.
// ============================================================================
#pragma once

#include <cstddef>
#include <cstdint>

namespace vgww::core::limits {

    // File payload caps (prevent OOM on super-large json).
    constexpr size_t kMaxConfigBytes = 1 * 1024 * 1024;   // 1MiB
    constexpr size_t kMaxLeasesBytes = 2 * 1024 * 1024;   // 2MiB
    constexpr size_t kMaxRulesBytes = 2 * 1024 * 1024;    // 2MiB

    // Collection caps (keep O(N) UI layout and scans cheap at 10k).
    constexpr size_t kMaxPortMaps = 1024;
    constexpr size_t kMaxBans = 4096;
    constexpr size_t kMaxRateLimits = 4096;
    constexpr size_t kMaxStaticBindings = 1024;
    constexpr size_t kMaxStatusEntries = 1024;
    constexpr size_t kMaxDhcpDns = 4;
    // DHCP hostname (option 12) value ceiling: one TLV length octet caps a
    // single option value at 255 bytes, and 253 is the length the loader /
    // ValidateConfig have always enforced for static bindings. Single-sourced
    // here so the config path, the runtime upsert, and the reply-frame clamp
    // cannot drift apart.
    constexpr size_t kMaxHostnameBytes = 253;
    // DHCPv6 (RFC 8415) caps; same numeric discipline as the v4 ones.
    // This is an ALIAS of kMaxLeasesBytes, not a second literal: both lease
    // stores enforce the same document-size policy, so tying the values keeps
    // "raise the cap" a single edit. The v4 and v6 read AND write paths each
    // name their own constant (dhcp.cpp uses kMaxLeasesBytes, dhcp6.cpp uses
    // kMaxLeases6Bytes), which is what keeps the two protocols' write cap and
    // read cap identical - the P145-V6 "never publish a file we cannot load"
    // invariant depends on that. COST of the alias: v6 cannot be tuned
    // independently; if a v6-specific cap is ever needed, turn this line back
    // into an independent literal (no other change is required, since all
    // three v6 uses - dump guard, stat cap and streamoff cap - already read
    // this name).
    constexpr size_t kMaxLeases6Bytes = kMaxLeasesBytes;
    // Bounds on the lease TABLE, single-sourced so the v4 and the v6 server
    // enforce identical numbers (same-shape discipline). Note that the
    // SERVING path is naturally bounded and needs no policy cap: a dynamic
    // lease must hold a unique in-pool address (so <= pool_size) and, after
    // the static DUID dedup, a static lease must correspond to a configured
    // binding (so <= kMaxStaticBindings / unique DUIDs). Only LOADING from
    // disk can inject records that are outside any pool (a legitimately
    // persisted lease survives a pool re-range), so the file loader is the
    // one place a ceiling is required.
    //
    // kMaxLoadedLeases - how many records a LEASE FILE may inject. Sized so
    // that the ceiling is REACHABLE inside the 2 MiB document cap: the
    // shortest well-formed v6 entry (DUID + IAID + address) is about 100
    // bytes, so 16384 records fit in ~1.6 MiB and a test can prove the gate
    // bites. It is also 4x the default DHCPv6 pool (4096). This is NOT a
    // service-capacity limit: Acquire never consults it, so a /16 serving
    // load is unaffected.
    constexpr size_t kMaxLoadedLeases = 16384;
    // kMaxLeaseTableHardCap - purely defensive hard ceiling for the serving
    // path. It covers every ordinary deployment (a v4 /16 pool is 65534
    // addresses and the v6 default pool is 4096, both far below it) and is
    // never reached by them. KNOWN LIMITATION: a mask shorter than /16 is
    // accepted by the config validator (it only requires a contiguous
    // prefix), so a /8-sized v4 pool can exceed this number; such a client
    // is then refused and reported through pool_exhausted rather than
    // growing the table without bound. The value exists so no future code
    // path can grow the table indefinitely.
    constexpr size_t kMaxLeaseTableHardCap = 262144;
    constexpr size_t kMaxStaticBindings6 = 1024;
    // RFC 8415 section 11.1: a DUID is 1..128 octets. Single-sourced because
    // THREE layers enforce it - the wire parser (proto), the store/Web parser
    // (runtime) and the native form's text check (ui) - and a value one layer
    // accepts must never be refused by another.
    constexpr size_t kMaxDuidBytes = 128;
    constexpr size_t kMaxDhcp6Dns = 4;
    // Neighbor-table cap (H1): the published L2 neighbor table holds at most
    // this many entries; a rebuild over the cap evicts the oldest entries
    // (smallest last_seen) and counts them. Bounds memory under a
    // forged-source (ARP / IPv6) flood.
    constexpr size_t kMaxNeighbors = 4096;
    // L2 bridge MAC table (S3): hard ceiling for learned source MACs; the
    // configured size defaults to 4096 and is clamped to this cap.
    constexpr size_t kMaxMacTableSize = 65536;
    constexpr size_t kDefaultMacTableSize = 4096;
    constexpr size_t kMaxAdapterBytes = 256;
    constexpr size_t kMaxTokenBytes = 256;
    constexpr size_t kMaxHttpPathBytes = 2048;
    constexpr size_t kMaxHttpQueryPairs = 64;

}  // namespace vgww::core::limits
