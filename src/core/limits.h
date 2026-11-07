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
    constexpr size_t kMaxLeases6Bytes = 2 * 1024 * 1024;  // 2MiB
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
