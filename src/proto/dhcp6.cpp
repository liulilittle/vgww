// ============================================================================
// dhcp6.cpp - DHCPv6 frame parse/build + stateful server implementation.
//
// Mirrors dhcp.cpp: strict F1-style frame validation, a DUID+IAID lease map,
// static bindings, versioned atomic persistence and a per-DUID rate limit.
// ============================================================================
#include "proto/dhcp6.h"

#include "core/config.h"
#include "core/limits.h"
#include "core/text.h"
#include "net/checksum.h"
#include "proto/ndp.h"
#include "proto/udp.h"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <set>
#include <sstream>
#include <string>
#include <unordered_set>

#ifdef _WIN32
#include <windows.h>
#include <io.h>
#endif

namespace vgww {
    namespace proto {

        namespace {

            /// batch122: cumulative DHCPv6 frames refused by ParseDhcp6Frame
            /// (v4 sibling: ParseRejectedCount). Surfaced so malformed v6
            /// clients are never a silent drop.
            std::atomic<uint64_t> g_parse_rejected6{0};

            inline uint16_t ReadU16(const uint8_t* p) noexcept {
                return static_cast<uint16_t>((p[0] << 8) | p[1]);
            }

            inline uint32_t ReadU32(const uint8_t* p) noexcept {
                return (static_cast<uint32_t>(p[0]) << 24) |
                       (static_cast<uint32_t>(p[1]) << 16) |
                       (static_cast<uint32_t>(p[2]) << 8) |
                       static_cast<uint32_t>(p[3]);
            }

            inline void PushU16(std::vector<uint8_t>& out, uint16_t value) {
                out.push_back(static_cast<uint8_t>(value >> 8));
                out.push_back(static_cast<uint8_t>(value & 0xFF));
            }

            inline void PushU32(std::vector<uint8_t>& out, uint32_t value) {
                out.push_back(static_cast<uint8_t>(value >> 24));
                out.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
                out.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
                out.push_back(static_cast<uint8_t>(value & 0xFF));
            }

            /// Clients are link-scoped: fe80::/10 only (RFC 8415 section 16).
            inline bool IsLinkLocal(const uint8_t* ip) noexcept {
                return 0xFE == ip[0] && 0x80 == (ip[1] & 0xC0);
            }

            /// Message types that must carry an IA_NA (RFC 8415 18.2.x).
            inline bool RequiresIaNa(uint8_t msg_type) noexcept {
                switch (msg_type) {
                    case kDhcp6MsgRequest:
                    case kDhcp6MsgConfirm:
                    case kDhcp6MsgRenew:
                    case kDhcp6MsgRebind:
                    case kDhcp6MsgRelease:
                    case kDhcp6MsgDecline:
                        return true;
                    default:
                        return false;
                }
            }

            /// Client -> server message types only (replies never parse).
            inline bool IsClientMessage(uint8_t msg_type) noexcept {
                switch (msg_type) {
                    case kDhcp6MsgSolicit:
                    case kDhcp6MsgRequest:
                    case kDhcp6MsgConfirm:
                    case kDhcp6MsgRenew:
                    case kDhcp6MsgRebind:
                    case kDhcp6MsgRelease:
                    case kDhcp6MsgDecline:
                    case kDhcp6MsgInformationRequest:
                        return true;
                    default:
                        return false;
                }
            }

        }  // namespace

        uint64_t ParseRejected6Count() noexcept {
            return g_parse_rejected6.load(std::memory_order_relaxed);
        }

        bool ParseDhcp6Frame(const uint8_t* data, size_t len,
                             Dhcp6View& out) noexcept {
            out = Dhcp6View{};
            const auto fail = []() noexcept {
                g_parse_rejected6.fetch_add(1, std::memory_order_relaxed);
                return false;
            };
            if (nullptr == data || len < kDhcp6FrameMin) {
                return fail();
            }
            net::EthHeaderView eth;
            if (!net::ParseEthHeader(data, len, eth) ||
                net::kEthertypeIpv6 != eth.ethertype) {
                return fail();
            }
            const uint8_t* ip = data + net::kEthernetHeaderLen;
            // IPv6 fixed header: version 6, next header UDP (RFC 8200).
            if (6 != (ip[0] >> 4) || 17 != ip[6]) {
                return fail();
            }
            const size_t l4_offset = net::kEthernetHeaderLen + 40;
            if (len < l4_offset + kUdpHeaderLen + 4) {
                return fail();
            }
            if (!IsLinkLocal(ip + 8)) {
                return fail();
            }
            const uint8_t* udp = data + l4_offset;
            const uint16_t sport = ReadU16(udp);
            const uint16_t dport = ReadU16(udp + 2);
            const uint16_t udp_len = ReadU16(udp + 4);
            // F1 discipline: 546 -> 547 only, and the UDP length must agree
            // with the bytes actually held.
            if (kDhcp6ClientPort != sport || kDhcp6ServerPort != dport) {
                return fail();
            }
            if (udp_len < kUdpHeaderLen + 4 ||
                static_cast<size_t>(udp_len) != len - l4_offset) {
                return fail();
            }
            const uint8_t* payload = udp + kUdpHeaderLen;
            const size_t payload_len = udp_len - kUdpHeaderLen;
            const uint8_t msg_type = payload[0];
            if (!IsClientMessage(msg_type)) {
                return fail();
            }
            out.msg_type = msg_type;
            out.xid = (static_cast<uint32_t>(payload[1]) << 16) |
                      (static_cast<uint32_t>(payload[2]) << 8) |
                      static_cast<uint32_t>(payload[3]);
            std::memcpy(out.src_ip.data(), ip + 8, 16);
            std::memcpy(out.dst_ip.data(), ip + 24, 16);

            // Strict option walk: every option must fit and the stream must
            // be consumed exactly (trailing bytes are malformed).
            size_t pos = 4;
            while (pos + 4 <= payload_len) {
                const uint16_t code = ReadU16(payload + pos);
                const uint16_t olen = ReadU16(payload + pos + 2);
                pos += 4;
                if (pos + olen > payload_len) {
                    return fail();
                }
                const uint8_t* value = payload + pos;
                switch (code) {
                    case kDhcp6OptClientId:
                        if (olen < 1 || olen > kDhcp6MaxDuidLen) {
                            return fail();
                        }
                        out.has_client_id = true;
                        out.client_duid.assign(value, value + olen);
                        break;
                    case kDhcp6OptServerId:
                        if (olen < 1 || olen > kDhcp6MaxDuidLen) {
                            return fail();
                        }
                        out.has_server_id = true;
                        out.server_duid.assign(value, value + olen);
                        break;
                    case kDhcp6OptIaNa: {
                        if (olen < kDhcp6IaNaMin) {
                            return fail();
                        }
                        out.has_ia_na = true;
                        out.iaid = ReadU32(value);
                        size_t inner = kDhcp6IaNaMin;
                        while (inner + 4 <= olen) {
                            const uint16_t icode = ReadU16(value + inner);
                            const uint16_t ilen = ReadU16(value + inner + 2);
                            inner += 4;
                            if (inner + ilen > olen) {
                                return fail();
                            }
                            if (kDhcp6OptIaAddr == icode) {
                                if (ilen < 24) {
                                    return fail();
                                }
                                std::memcpy(out.ia_addr.data(), value + inner,
                                            16);
                                out.has_ia_addr = true;
                            }
                            inner += ilen;
                        }
                        if (inner != olen) {
                            return fail();
                        }
                        break;
                    }
                    case kDhcp6OptRapidCommit:
                        out.rapid_commit = true;
                        break;
                    default:
                        break;
                }
                pos += olen;
            }
            if (pos != payload_len) {
                return fail();
            }
            if (!out.has_client_id) {
                return fail();  // RFC 8415 16.1: Client Identifier mandatory
            }
            if (RequiresIaNa(msg_type) && !out.has_ia_na) {
                return fail();
            }
            return true;
        }

        void BuildDhcp6ReplyFrame(const Dhcp6Reply& reply,
                                  const net::WireMac& gateway_mac,
                                  const net::WireMac& client_mac,
                                  const std::array<uint8_t, 16>& server_ip,
                                  const std::array<uint8_t, 16>& client_ip,
                                  std::vector<uint8_t>& out_frame) {
            std::vector<uint8_t> payload;
            payload.reserve(64 + 16 * reply.dns.size());
            payload.push_back(reply.msg_type);
            payload.push_back(static_cast<uint8_t>((reply.xid >> 16) & 0xFF));
            payload.push_back(static_cast<uint8_t>((reply.xid >> 8) & 0xFF));
            payload.push_back(static_cast<uint8_t>(reply.xid & 0xFF));
            const auto push_option =
                [&payload](uint16_t code, const std::vector<uint8_t>& value) {
                    PushU16(payload, code);
                    PushU16(payload, static_cast<uint16_t>(value.size()));
                    payload.insert(payload.end(), value.begin(), value.end());
                };

            if (!reply.client_duid.empty()) {
                push_option(kDhcp6OptClientId, reply.client_duid);
            }
            if (!reply.server_duid.empty()) {
                push_option(kDhcp6OptServerId, reply.server_duid);
            }
            if (reply.with_ia_na) {
                std::vector<uint8_t> ia;
                PushU32(ia, reply.iaid);
                PushU32(ia, reply.t1);
                PushU32(ia, reply.t2);
                if (reply.with_ia_addr) {
                    std::vector<uint8_t> ia_addr(reply.ia_addr.begin(),
                                                 reply.ia_addr.end());
                    PushU32(ia_addr, reply.preferred_s);
                    PushU32(ia_addr, reply.valid_s);
                    PushU16(ia, kDhcp6OptIaAddr);
                    PushU16(ia, static_cast<uint16_t>(ia_addr.size()));
                    ia.insert(ia.end(), ia_addr.begin(), ia_addr.end());
                }
                if (reply.with_status && reply.status_in_ia) {
                    std::vector<uint8_t> status;
                    PushU16(status, reply.status);
                    PushU16(ia, kDhcp6OptStatusCode);
                    PushU16(ia, static_cast<uint16_t>(status.size()));
                    ia.insert(ia.end(), status.begin(), status.end());
                }
                push_option(kDhcp6OptIaNa, ia);
            }
            if (reply.rapid_commit) {
                push_option(kDhcp6OptRapidCommit, {});
            }
            if (reply.with_status && !reply.status_in_ia) {
                std::vector<uint8_t> status;
                PushU16(status, reply.status);
                push_option(kDhcp6OptStatusCode, status);
            }
            if (reply.with_dns && !reply.dns.empty()) {
                // Clamp to the compiled-in RDNSS budget (limits.h): a caller
                // that fills the config directly must not inflate option 23
                // past ::vgww::core::limits::kMaxDhcp6Dns. Config parsing
                // already limits ipv6.dns, so this is defence in depth.
                const size_t dns_count = std::min(
                    reply.dns.size(), ::vgww::core::limits::kMaxDhcp6Dns);
                std::vector<uint8_t> dns;
                dns.reserve(16 * dns_count);
                for (size_t i = 0; i < dns_count; ++i) {
                    dns.insert(dns.end(), reply.dns[i].begin(),
                               reply.dns[i].end());
                }
                push_option(kDhcp6OptDnsServers, dns);
            }

            proto::BuildUdpFrameV6(out_frame, client_mac, gateway_mac,
                                   server_ip.data(), kDhcp6ServerPort,
                                   client_ip.data(), kDhcp6ClientPort,
                                   payload.data(), payload.size());
        }

    }  // namespace proto

    namespace dhcp6 {

        namespace {

            constexpr std::chrono::seconds kOfferHold{60};
            constexpr std::chrono::seconds kDeclineHold{600};

            inline bool IsZeroAddr(const std::array<uint8_t, 16>& a) noexcept {
                for (const uint8_t b : a) {
                    if (0 != b) {
                        return false;
                    }
                }
                return true;
            }

            /// Last 8 bytes (the IID) as a big-endian index. Pool math only
            /// touches the IID; the prefix is carried separately.
            inline uint64_t IidIndex(
                const std::array<uint8_t, 16>& addr) noexcept {
                uint64_t index = 0;
                for (size_t i = 8; i < 16; ++i) {
                    index = (index << 8) | addr[i];
                }
                return index;
            }

            inline void IidAddressAt(uint64_t index,
                                     const std::array<uint8_t, 16>& prefix,
                                     std::array<uint8_t, 16>& out) noexcept {
                out = prefix;
                for (size_t i = 0; i < 8; ++i) {
                    out[15 - i] = static_cast<uint8_t>(index & 0xFF);
                    index >>= 8;
                }
            }

            /// Binary DUID key for the rate-limit map (NUL-safe std::string).
            inline std::string DuidKey(const std::vector<uint8_t>& duid) {
                return std::string(duid.begin(), duid.end());
            }

            inline std::string FormatDuid(const std::vector<uint8_t>& duid) {
                static const char* kHex = "0123456789ABCDEF";
                std::string out;
                out.reserve(duid.size() * 3);
                for (size_t i = 0; i < duid.size(); ++i) {
                    if (0 != i) {
                        out.push_back(':');
                    }
                    out.push_back(kHex[duid[i] >> 4]);
                    out.push_back(kHex[duid[i] & 0x0F]);
                }
                return out;
            }

            bool ParseDuidText(const std::string& text,
                               std::vector<uint8_t>& out) {
                out.clear();
                int high = -1;
                for (const char c : text) {
                    if (c == ':' || c == '-') {
                        continue;
                    }
                    int value = -1;
                    if (c >= '0' && c <= '9') {
                        value = c - '0';
                    } else if (c >= 'a' && c <= 'f') {
                        value = c - 'a' + 10;
                    } else if (c >= 'A' && c <= 'F') {
                        value = c - 'A' + 10;
                    }
                    if (value < 0) {
                        return false;
                    }
                    if (high < 0) {
                        high = value;
                    } else {
                        out.push_back(
                            static_cast<uint8_t>((high << 4) | value));
                        high = -1;
                    }
                }
                return high < 0 && !out.empty() &&
                       out.size() <= proto::kDhcp6MaxDuidLen;
            }

            /// Parses the fixed 8-group form emitted by FormatIpv6 (the lease
            /// file is machine-written; hand-edited "::" is not required).
            bool ParseIpv6Text(const std::string& text,
                               std::array<uint8_t, 16>& out) {
                out.fill(0);
                size_t pos = 0;
                for (size_t g = 0; g < 8; ++g) {
                    const size_t colon = text.find(':', pos);
                    const size_t end =
                        (std::string::npos == colon) ? text.size() : colon;
                    const std::string part = text.substr(pos, end - pos);
                    if (part.empty() || part.size() > 4) {
                        return false;
                    }
                    uint16_t value = 0;
                    for (const char c : part) {
                        int h = -1;
                        if (c >= '0' && c <= '9') {
                            h = c - '0';
                        } else if (c >= 'a' && c <= 'f') {
                            h = c - 'a' + 10;
                        } else if (c >= 'A' && c <= 'F') {
                            h = c - 'A' + 10;
                        }
                        if (h < 0) {
                            return false;
                        }
                        value = static_cast<uint16_t>((value << 4) | h);
                    }
                    out[2 * g] = static_cast<uint8_t>(value >> 8);
                    out[2 * g + 1] = static_cast<uint8_t>(value & 0xFF);
                    if (std::string::npos == colon) {
                        return 7 == g;
                    }
                    pos = colon + 1;
                }
                return pos == text.size();
            }

        }  // namespace

        size_t Dhcp6Server::KeyHash::operator()(const Key& key) const noexcept {
            // FNV-1a over DUID + IAID.
            uint64_t h = 0xcbf29ce484222325ull;
            for (const uint8_t b : key.duid) {
                h ^= b;
                h *= 1099511628211ull;
            }
            h ^= key.iaid;
            h *= 1099511628211ull;
            return static_cast<size_t>(h);
        }

        size_t Dhcp6Server::DuidHash::operator()(
            const std::vector<uint8_t>& duid) const noexcept {
            uint64_t h = 0xcbf29ce484222325ull;
            for (const uint8_t b : duid) {
                h ^= b;
                h *= 1099511628211ull;
            }
            return static_cast<size_t>(h);
        }

        uint64_t Dhcp6Server::IndexOf(
            const std::array<uint8_t, 16>& addr) noexcept {
            return IidIndex(addr);
        }

        void Dhcp6Server::AddressAt(uint64_t index,
                                    const std::array<uint8_t, 16>& prefix,
                                    std::array<uint8_t, 16>& out) noexcept {
            IidAddressAt(index, prefix, out);
        }

        Dhcp6Server::Dhcp6Server(const core::Config& config)
            : config_(config) {
            // DUID-LL (RFC 8415 section 11.3): type 3, hwtype 1, gateway MAC.
            server_duid_ = {0x00, 0x03, 0x00, 0x01,
                            config_.gateway.mac[0], config_.gateway.mac[1],
                            config_.gateway.mac[2], config_.gateway.mac[3],
                            config_.gateway.mac[4], config_.gateway.mac[5]};
            ResolvePool();
        }

        void Dhcp6Server::ResolvePool() {
            pool_prefix_ = config_.ipv6.ula_prefix;
            std::array<uint8_t, 16> start = config_.ipv6.dhcpv6.pool_start;
            std::array<uint8_t, 16> end = config_.ipv6.dhcpv6.pool_end;
            if (IsZeroAddr(start) && IsZeroAddr(end)) {
                // Spec section 5.2 defaults: prefix::1000 - prefix::1FFF.
                start = pool_prefix_;
                end = pool_prefix_;
                start[14] = 0x10;
                start[15] = 0x00;
                end[14] = 0x1F;
                end[15] = 0xFF;
            }
            pool_start_index_ = IidIndex(start);
            pool_end_index_ = IidIndex(end);
            next_index_ = pool_start_index_;
        }

        bool Dhcp6Server::InPrefix(
            const std::array<uint8_t, 16>& ip) const noexcept {
            const uint32_t plen = config_.ipv6.prefix_len;
            for (uint32_t bit = 0; bit < plen; ++bit) {
                const uint8_t mask =
                    static_cast<uint8_t>(1u << (7 - (bit % 8)));
                if ((ip[bit / 8] & mask) !=
                    (pool_prefix_[bit / 8] & mask)) {
                    return false;
                }
            }
            return true;
        }

        bool Dhcp6Server::ReservedByStatic(
            const std::vector<uint8_t>& duid,
            const std::array<uint8_t, 16>& ip) const {
            for (const auto& binding : config_.ipv6.dhcpv6.static_bindings) {
                if (binding.ip == ip && binding.duid != duid) {
                    return true;
                }
            }
            for (const auto& binding : runtime_bindings_) {
                if (binding.second.ip == ip && binding.first != duid) {
                    return true;
                }
            }
            return false;
        }

        std::array<uint8_t, 16> Dhcp6Server::Acquire(
            const std::vector<uint8_t>& duid, uint32_t iaid,
            std::chrono::steady_clock::time_point now, OfferStage stage,
            const std::string& hostname,
            const std::array<uint8_t, 16>* requested) {
            std::lock_guard<std::mutex> lock(mutex_);
            // batch123 (same-shape sibling of the v4 fix): the lease hostname
            // is a display string that later crosses nlohmann's strict dump()
            // and the WebUI JSON body. Sanitize once at the trust boundary so
            // the store only holds well-formed UTF-8. Today the v6 wire never
            // carries a client hostname (callers pass an empty name), but the
            // guard keeps the invariant true if that changes.
            const std::string reported_name = core::SanitizeUtf8(hostname);
            const std::chrono::seconds term =
                (OfferStage::kOffer == stage)
                    ? std::min(kOfferHold,
                               std::chrono::seconds(
                                   config_.ipv6.dhcpv6.lease_seconds))
                    : std::chrono::seconds(config_.ipv6.dhcpv6.lease_seconds);
            const Key key{duid, iaid};

            // 1. Static bindings always win: runtime (WebUI) first, config.
            const auto runtime = runtime_bindings_.find(duid);
            if (runtime != runtime_bindings_.end()) {
                Lease& lease = leases_[key];
                lease.ip = runtime->second.ip;
                lease.is_static = true;
                lease.expires = now + term;
                if (!hostname.empty()) {
                    lease.hostname = reported_name;
                }
                return lease.ip;
            }
            for (const auto& binding : config_.ipv6.dhcpv6.static_bindings) {
                if (binding.duid == duid) {
                    Lease& lease = leases_[key];
                    lease.ip = binding.ip;
                    lease.is_static = true;
                    lease.expires = now + term;
                    if (!hostname.empty()) {
                        lease.hostname = reported_name;
                    } else {
                        lease.hostname = binding.hostname;
                    }
                    return lease.ip;
                }
            }

            // 2. Existing dynamic lease renews in place.
            const auto existing = leases_.find(key);
            if (existing != leases_.end() && !existing->second.is_static &&
                existing->second.expires > now) {
                existing->second.expires = now + term;
                if (!hostname.empty()) {
                    existing->second.hostname = reported_name;
                }
                return existing->second.ip;
            }

            // 3. Honour the client-requested IAADDR when it is free, in-pool
            // and not reserved (F2-style before the round-robin walk).
            if (nullptr != requested && !IsZeroAddr(*requested) &&
                InPrefix(*requested)) {
                const uint64_t req_index = IidIndex(*requested);
                if (0 != req_index && ~0ULL != req_index &&
                    req_index >= pool_start_index_ &&
                    req_index <= pool_end_index_ &&
                    !ReservedByStatic(duid, *requested)) {
                    bool usable = true;
                    for (const auto& pair : leases_) {
                        if (pair.second.expires > now &&
                            pair.second.ip == *requested) {
                            usable = false;
                            break;
                        }
                    }
                    if (usable) {
                        const auto bad = declined_until_.find(*requested);
                        if (bad != declined_until_.end()) {
                            if (bad->second > now) {
                                usable = false;
                            } else {
                                declined_until_.erase(bad);
                            }
                        }
                    }
                    if (usable) {
                        Lease& lease = leases_[key];
                        lease.ip = *requested;
                        lease.is_static = false;
                        lease.expires = now + term;
                        lease.hostname = reported_name;
                        next_index_ = req_index + 1;
                        return lease.ip;
                    }
                }
            }

            // 4. Walk the dynamic pool for the first free address. A
            // statically-bound address is reserved even while its client is
            // offline (static-vs-dynamic collision), and a DECLINEd address
            // stays parked for the hold window.
            if (pool_end_index_ >= pool_start_index_) {
                const uint64_t pool_size =
                    pool_end_index_ - pool_start_index_ + 1;
                // batch114 (C7 same-shape sweep of the v4 fix): the occupancy
                // set is built ONCE per Acquire instead of rescanning every
                // lease for every candidate address. The old shape was
                // O(pool_size x leases) - and for DHCPv6 the pool is an IID
                // range, so pool_size can be astronomically large - all of it
                // under mutex_. A host-set keeps this O(leases + pool_size).
                // The candidate identity is its IID index (the same value the
                // walk iterates), so the set is keyed on uint64_t instead of
                // introducing a 16-byte hash.
                std::unordered_set<uint64_t> occupied;
                occupied.reserve(leases_.size());
                for (const auto& pair : leases_) {
                    lease_scans_.fetch_add(1, std::memory_order_relaxed);
                    if (pair.second.expires > now) {
                        occupied.insert(IidIndex(pair.second.ip));
                    }
                }
                for (uint64_t offset = 0; offset < pool_size; ++offset) {
                    const uint64_t index =
                        pool_start_index_ +
                        ((next_index_ - pool_start_index_ + offset) %
                         pool_size);
                    std::array<uint8_t, 16> candidate{};
                    IidAddressAt(index, pool_prefix_, candidate);
                    bool taken = 0 != occupied.count(index);
                    if (!taken) {
                        const auto bad = declined_until_.find(candidate);
                        if (bad != declined_until_.end()) {
                            if (bad->second > now) {
                                taken = true;
                            } else {
                                declined_until_.erase(bad);
                            }
                        }
                    }
                    // The network address (IID all-zero) and the all-ones IID
                    // are never handed out.
                    if (0 == index || ~0ULL == index || taken ||
                        ReservedByStatic(duid, candidate)) {
                        continue;
                    }
                    Lease& lease = leases_[key];
                    lease.ip = candidate;
                    lease.is_static = false;
                    lease.expires = now + term;
                    lease.hostname = reported_name;
                    next_index_ = index + 1;
                    return lease.ip;
                }
            }

            // 5. Pool exhausted: observable (counted + throttled log).
            ++pool_exhausted_;
            constexpr uint64_t kPoolLogIntervalMs = 5000;
            const uint64_t now_ms = static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    now.time_since_epoch())
                    .count());
            uint64_t last = last_pool_log_ms_.load(std::memory_order_relaxed);
            if (now_ms >= last + kPoolLogIntervalMs &&
                last_pool_log_ms_.compare_exchange_strong(
                    last, now_ms, std::memory_order_relaxed)) {
                std::fprintf(
                    stderr, "[vgww] dhcp6: pool exhausted (%llu total)\n",
                    static_cast<unsigned long long>(
                        pool_exhausted_.load(std::memory_order_relaxed)));
            }
            return std::array<uint8_t, 16>{};
        }

        bool Dhcp6Server::AllowFrame(
            const std::vector<uint8_t>& duid,
            std::chrono::steady_clock::time_point now) {
            std::lock_guard<std::mutex> lock(mutex_);
            // Anti-storm: keep the miss-side map bounded the same way the v4
            // and probe caches are (drop-all when oversized).
            if (rate_limit_.size() >= kMaxRateEntries) {
                rate_limit_.clear();
                // batch34j: a full reset drops the anti-storm protection
                // for EVERY client, not just the new one. Count it.
                ++rate_limit_resets_;
            }
            const uint64_t sec = static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::seconds>(
                    now.time_since_epoch())
                    .count());
            RateWindow& win = rate_limit_[DuidKey(duid)];
            if (win.seconds != sec) {
                win.seconds = sec;
                win.count = 0;
            }
            if (win.count >= kMaxFramesPerSecond) {
                return false;
            }
            ++win.count;
            return true;
        }

        void Dhcp6Server::Decline(const std::vector<uint8_t>& duid,
                                  uint32_t iaid,
                                  const std::array<uint8_t, 16>& ip,
                                  std::chrono::steady_clock::time_point now) {
            std::lock_guard<std::mutex> lock(mutex_);
            if (IsZeroAddr(ip)) {
                return;
            }
            // F3 discipline: only the client actually holding this address
            // may park it (a spoofed DECLINE must not drain the pool).
            const auto it = leases_.find(Key{duid, iaid});
            if (it == leases_.end() || it->second.is_static ||
                it->second.ip != ip) {
                return;
            }
            leases_.erase(it);
            declined_until_[ip] = now + kDeclineHold;
        }

        void Dhcp6Server::Release(const std::vector<uint8_t>& duid,
                                  uint32_t iaid,
                                  const std::vector<uint8_t>& server_duid) {
            std::lock_guard<std::mutex> lock(mutex_);
            // F6 discipline: a RELEASE addressed to another server keeps our
            // binding. An empty server-id means "not reported" (lenient).
            if (!server_duid.empty() && server_duid != server_duid_) {
                return;
            }
            const auto it = leases_.find(Key{duid, iaid});
            if (it != leases_.end() && !it->second.is_static) {
                leases_.erase(it);
            }
        }

        size_t Dhcp6Server::Sweep(std::chrono::steady_clock::time_point now) {
            std::lock_guard<std::mutex> lock(mutex_);
            size_t removed = 0;
            for (auto it = leases_.begin(); it != leases_.end();) {
                if (!it->second.is_static && it->second.expires < now) {
                    it = leases_.erase(it);
                    ++removed;
                } else {
                    ++it;
                }
            }
            // Expired conflict holds free their addresses again.
            for (auto it = declined_until_.begin();
                 it != declined_until_.end();) {
                if (it->second < now) {
                    it = declined_until_.erase(it);
                } else {
                    ++it;
                }
            }
            return removed;
        }

        namespace {

#ifdef _WIN32
            inline std::wstring ToWideLongPath(const std::string& path) {
                int wlen = ::MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1,
                                                 nullptr, 0);
                if (wlen <= 0) {
                    return L"";
                }
                std::wstring wpath;
                wpath.resize(static_cast<size_t>(wlen - 1));
                ::MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1,
                                      wpath.data(), wlen);
                if (wpath.size() >= 260 && wpath.rfind(L"\\\\?\\", 0) != 0) {
                    if (wpath.size() >= 2 && wpath[1] == L':') {
                        wpath = L"\\\\?\\" + wpath;
                    } else if (wpath.rfind(L"\\\\", 0) == 0) {
                        wpath = L"\\\\?\\UNC\\" + wpath.substr(2);
                    } else {
                        wchar_t abs_buf[32767];
                        const DWORD len = ::GetFullPathNameW(
                            wpath.c_str(), 32767, abs_buf, nullptr);
                        if (0 != len && len < 32767) {
                            wpath.assign(abs_buf, len);
                            if (wpath.rfind(L"\\\\?\\", 0) != 0) {
                                if (wpath.size() >= 2 && wpath[1] == L':') {
                                    wpath = L"\\\\?\\" + wpath;
                                } else if (wpath.rfind(L"\\\\", 0) == 0) {
                                    wpath = L"\\\\?\\UNC\\" + wpath.substr(2);
                                }
                            }
                        }
                    }
                }
                return wpath;
            }
#endif

        }  // namespace

        bool Dhcp6Server::DumpLeases(
            const std::string& path,
            std::chrono::steady_clock::time_point now) {
            // batch85: never overwrite a file this server could not read.
            // batch87: retry the read; a successful again-read merges the
            // on-disk leases (live leases win on address conflicts) and clears
            // the block instead of requiring a restart.
            if (persist_blocked_.load(std::memory_order_relaxed)) {
                // batch87: retry the read; a successful re-read merges the
                // on-disk leases, but a DISK entry whose address a live client
                // already holds is dropped afterwards (one address, one owner,
                // batch134). The block clears without a restart.
                std::unordered_map<Key, Lease, KeyHash> live;
                {
                    std::lock_guard<std::mutex> lock(
                        const_cast<std::mutex&>(mutex_));
                    live = leases_;
                }
                size_t dropped = 0;
                const LoadOutcome outcome = LoadLeases(path, now, &dropped);
                if (LoadOutcome::kUnreadable == outcome) {
                    ++persist_failures_;
                    return false;
                }
                persist_blocked_.store(false, std::memory_order_relaxed);
                {
                    std::lock_guard<std::mutex> lock(
                        const_cast<std::mutex&>(mutex_));
                    // batch206: same defect and fix as the v4 sibling - the
                    // disk re-read replaces the table, so a client served
                    // during the blocked window must keep the address it
                    // actually holds; otherwise the stale disk mapping wins
                    // and the live address becomes free for a second client.
                    for (const auto& kv : live) {
                        leases_[kv.first] = kv.second;
                    }
                    std::set<std::array<uint8_t, 16>> live_ips;
                    for (const auto& kv : live) {
                        live_ips.insert(kv.second.ip);
                    }
                    for (auto it = leases_.begin(); it != leases_.end();) {
                        if (0 == live.count(it->first) &&
                            live_ips.end() != live_ips.find(it->second.ip)) {
                            it = leases_.erase(it);
                        } else {
                            ++it;
                        }
                    }
                }
            }
            // Acquire/Decline/Sweep mutate the map from the RX and control
            // threads.
            //
            // batch81: the lock covers ONLY the snapshot copy. Serializing and
            // writing the file used to run under mutex_ - the same lock the RX
            // and control threads take - i.e. disk I/O with FlushFileBuffers
            // inside a hot lock (D13). Measured on the runtime path
            // (dataplane.cpp dumps every 60 s): a concurrent lease read waited
            // up to 104 ms while the dump ran, against a 0.1-0.3 ms baseline
            // with no dump running. Copying just the fields the JSON needs
            // keeps the hold at O(N) memory movement and moves every syscall
            // outside the critical section.
            struct SnapshotEntry {
                std::vector<uint8_t> duid;
                uint32_t iaid = 0;
                std::array<uint8_t, 16> ip{};
                signed long long remaining_us = 0;
                std::string hostname;
            };
            std::vector<SnapshotEntry> snapshot;
            {
                std::lock_guard<std::mutex> lock(
                    const_cast<std::mutex&>(mutex_));
                snapshot.reserve(leases_.size());
                for (const auto& pair : leases_) {
                    if (pair.second.is_static || pair.second.expires < now) {
                        continue;
                    }
                    SnapshotEntry entry;
                    entry.duid = pair.first.duid;
                    entry.iaid = pair.first.iaid;
                    entry.ip = pair.second.ip;
                    entry.remaining_us =
                        std::chrono::duration_cast<std::chrono::microseconds>(
                            pair.second.expires - now)
                            .count();
                    entry.hostname = pair.second.hostname;
                    snapshot.push_back(std::move(entry));
                }
            }  // lock released here: everything below touches only `snapshot`
            std::ostringstream json;
            // Versioned envelope so a future schema change is detected
            // instead of silently mis-parsed.
            json << "{\"version\":1,\"leases\":[";
            bool first = true;
            for (const auto& entry : snapshot) {
                const uint32_t expires_in_s =
                    entry.remaining_us > 0
                        ? static_cast<uint32_t>(entry.remaining_us / 1000000)
                        : 0;
                // nlohmann builds the entry so a client-reported hostname is
                // JSON-escaped, never spliced raw into the stream.
                const nlohmann::json row = {
                    {"duid", FormatDuid(entry.duid)},
                    {"iaid", entry.iaid},
                    {"ip", core::FormatIpv6(entry.ip)},
                    {"expires_in_s", expires_in_s},
                    {"hostname", entry.hostname}};
                if (!first) {
                    json << ",";
                }
                first = false;
                json << row.dump();
            }
            json << "]}";
            // batch82: shared durable writer. Temp naming, the device flush
            // contract, the bounded publish retry and every failure path live
            // in ONE implementation (same one the v4 writer, the config and
            // the rule store use) instead of a per-protocol copy that can
            // drift - and that copy ignored nothing here, but had no unique
            // temp name and no publish retry (C6/C9). Failures stay observable
            // (counted + logged).
            const std::string data = json.str();
            std::string write_error;
            if (core::AtomicWriteOutcome::kOk !=
                core::WriteFileAtomicDurable(path, data, write_error)) {
                ++persist_failures_;
                std::fprintf(stderr,
                             "[vgww] dhcp6: lease dump failed: %s\n",
                             write_error.c_str());
                return false;
            }
            return true;
        }

        bool Dhcp6Server::LoadLeases(
            const std::string& path,
            std::chrono::steady_clock::time_point now) {
            size_t dropped = 0;
            return LoadOutcome::kRestored == LoadLeases(path, now, &dropped);
        }

        Dhcp6Server::LoadOutcome Dhcp6Server::LoadLeases(
            const std::string& path,
            std::chrono::steady_clock::time_point now,
            size_t* dropped_out) {
            if (dropped_out != nullptr) {
                *dropped_out = 0;
            }
            size_t dropped = 0;
            nlohmann::json parsed;

            // batch82: preserve a file the loader cannot read (see v4): the
            // next 60 s snapshot used to overwrite it, destroying both the
            // chance of manual recovery and the evidence of the loss.
            const auto corrupt = [&path, this]() {
                // batch206: same as the v4 sibling - a failed preserve must
                // pause persistence, not let the next dump overwrite the only
                // copy of the unreadable document.
                if (!core::SetAsideFile(path, ".corrupt")) {
                    persist_blocked_.store(true,
                                       std::memory_order_relaxed);
                    std::fprintf(stderr,
                                 "[vgww] dhcp6: corrupt lease file could not "
                                 "be preserved; persistence paused\n");
                    return LoadOutcome::kUnreadable;
                }
                lease_file_corrupt_.store(true, std::memory_order_relaxed);
                return LoadOutcome::kCorrupt;
            };

#ifdef _WIN32
            {
                const std::wstring wpath = ToWideLongPath(path);
                if (!wpath.empty()) {
                    FILE* f = nullptr;
                    // batch85: same discipline as v4 - retry a transient
                    // holder; classify "could not open" as kUnreadable, never
                    // as corruption, and stop writing so the file survives.
                    bool open_file_exists = true;
                    bool open_simulated = false;
                    unsigned long open_error = 0;
                    constexpr int kOpenAttempts = 3;

                    for (int attempt = 0;; ++attempt) {
                        const unsigned long simulated =
                            core::SimulatedOpenFailure(path);
                        const DWORD attrs = ::GetFileAttributesW(wpath.c_str());
                        open_file_exists = (INVALID_FILE_ATTRIBUTES != attrs);

                        if (0 == simulated) {
                            if (0 == ::_wfopen_s(&f, wpath.c_str(), L"rb") &&
                                nullptr != f) {
                                break;
                            }
                            open_simulated = false;
                            open_error = static_cast<unsigned long>(
                                ::GetLastError());
                        } else {
                            open_simulated = true;
                            open_error = simulated;
                        }

                        if (!open_file_exists || attempt + 1 >= kOpenAttempts) {
                            break;
                        }
                        ::Sleep(static_cast<DWORD>(attempt + 1));
                    }

                    if (nullptr == f && (open_file_exists || open_simulated)) {
                        if (open_file_exists && !open_simulated) {
                            const DWORD attrs =
                                ::GetFileAttributesW(wpath.c_str());
                            if (INVALID_FILE_ATTRIBUTES != attrs &&
                                0 != (attrs & FILE_ATTRIBUTE_DIRECTORY)) {
                                return corrupt();
                            }
                        }
                        persist_blocked_.store(true,
                                               std::memory_order_relaxed);
                        std::fprintf(stderr,
                                     "[vgww] dhcp6: lease file not readable "
                                     "(%s, error %lu); persistence paused so "
                                     "the file is not overwritten\n",
                                     path.c_str(), open_error);
                        return LoadOutcome::kUnreadable;
                    }

                    if (nullptr != f) {
                        ::fseek(f, 0, SEEK_END);
                        const long sz = ::ftell(f);
                        ::fseek(f, 0, SEEK_SET);
                        constexpr long kLeaseCap = static_cast<long>(
                            ::vgww::core::limits::kMaxLeases6Bytes);
                        // batch82: ftell == -1 is an I/O failure, not an
                        // empty file (an empty file would report "restored"
                        // while dropping everything the file held).
                        if (sz < 0) {
                            ::fclose(f);
                            return corrupt();
                        }
                        if (sz > kLeaseCap) {
                            ::fclose(f);
                            return corrupt();
                        }
                        std::string raw;
                        if (sz > 0) {
                            raw.resize(static_cast<size_t>(sz));
                            const size_t got =
                                ::fread(raw.data(), 1, raw.size(), f);
                            raw.resize(got);
                        }
                        ::fclose(f);
                        try {
                            if (!raw.empty()) {
                                parsed = nlohmann::json::parse(raw);
                            } else {
                                parsed = nlohmann::json::array();
                            }
                        } catch (...) {
                            return corrupt();
                        }
                        goto parsed_ok;
                    }
                }
            }
#endif
            {
                std::ifstream file(path, std::ios::binary | std::ios::ate);
                if (!file) {
                    return LoadOutcome::kNoFile;
                }
                const auto sz2 = file.tellg();
                constexpr std::streamoff kLeaseCap2 =
                    static_cast<std::streamoff>(
                        ::vgww::core::limits::kMaxLeases6Bytes);
                if (sz2 < 0) {
                    return corrupt();
                }
                if (sz2 > kLeaseCap2) {
                    return corrupt();
                }
                file.seekg(0, std::ios::beg);
                try {
                    file >> parsed;
                } catch (...) {
                    return corrupt();
                }
            }
#ifdef _WIN32
        parsed_ok:
#endif
            // Accept the versioned object form written by DumpLeases
            // ({"version":1,"leases":[...]}) and the bare-array form.
            if (parsed.is_object()) {
                const auto ver = parsed.find("version");
                if (ver == parsed.end() || !ver->is_number_integer() ||
                    ver->get<int>() != 1) {
                    return corrupt();  // schema changed: do not misparse
                }
                const auto it = parsed.find("leases");
                if (it == parsed.end() || !it->is_array()) {
                    return corrupt();
                }
                parsed = *it;
            }
            if (!parsed.is_array()) {
                return corrupt();
            }
            std::lock_guard<std::mutex> lock(mutex_);
            // batch134: one address, one owner (mirrors the v4 loader and
            // UpsertBinding). Without it a file naming one address for two
            // DUID+IAID pairs produced two "active" leases on it.
            //
            // Keyed by a 64-bit fold of the prefix-independent tail: the ULA
            // prefix is shared by construction (InPrefix was just enforced),
            // so the last 8 octets identify the address uniquely without
            // introducing a new 16-byte hash type.
            std::unordered_set<uint64_t> claimed_ips;
            claimed_ips.reserve(parsed.size());
            for (const auto& item : parsed) {
                Key key;
                if (!ParseDuidText(item.value("duid", ""), key.duid)) {
                    ++dropped;
                    continue;
                }
                key.iaid = item.value("iaid", 0u);
                std::array<uint8_t, 16> ip{};
                if (!ParseIpv6Text(item.value("ip", ""), ip)) {
                    ++dropped;
                    continue;
                }
                // OBS-1: a version:1 file written by an older build stores
                // its leases WITHOUT expires_in_s. Treat the MISSING field
                // as a legacy entry and restore a full term from
                // config_.ipv6.dhcpv6.lease_seconds (same origin as a fresh
                // Acquire). An explicit expires_in_s==0 is a genuinely
                // expired lease and stays dropped.
                uint32_t expires_in_s = 0;
                const auto ei = item.find("expires_in_s");
                if (ei == item.end()) {
                    expires_in_s = config_.ipv6.dhcpv6.lease_seconds;
                } else if (ei->is_number_unsigned()) {
                    expires_in_s = ei->get<uint32_t>();
                }
                // State-consistency gate: no remaining time, an address
                // outside the ULA prefix, or an address reserved by a config
                // static binding is dropped (contract: expired entries are
                // skipped).
                if (0 == expires_in_s || IsZeroAddr(ip) || !InPrefix(ip)) {
                    ++dropped;
                    continue;
                }
                bool reserved = false;
                for (const auto& b :
                     config_.ipv6.dhcpv6.static_bindings) {
                    if (b.ip == ip) {
                        reserved = true;
                        break;
                    }
                }
                if (reserved) {
                    ++dropped;
                    continue;
                }
                // batch134: a second client must not claim an address this
                // load already accepted (first wins, mirroring the v4 loader
                // and UpsertBinding's refusal of the newcomer).
                {
                    uint64_t tail = 0;
                    for (std::size_t k = 8; k < 16; ++k) {
                        tail = (tail << 8) | ip[k];
                    }
                    if (!claimed_ips.insert(tail).second) {
                        ++dropped;
                        continue;
                    }
                }
                Lease lease;
                lease.ip = ip;
                lease.is_static = false;
                lease.expires = now + std::chrono::seconds(expires_in_s);
                lease.hostname = item.value("hostname", "");
                leases_[key] = lease;
            }
            if (dropped_out != nullptr) {
                *dropped_out = dropped;
            }
            dropped_leases_.fetch_add(static_cast<uint64_t>(dropped),
                                      std::memory_order_relaxed);
            return LoadOutcome::kRestored;
        }

        size_t Dhcp6Server::LeaseCount() const noexcept {
            std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(mutex_));
            return leases_.size();
        }

        uint64_t Dhcp6Server::PoolExhaustedCount() const noexcept {
            return pool_exhausted_.load(std::memory_order_relaxed);
        }

        uint64_t Dhcp6Server::RateLimitResets() const noexcept {
            return rate_limit_resets_.load(std::memory_order_relaxed);
        }

        uint64_t Dhcp6Server::LeaseScanCount() const noexcept {
            return lease_scans_.load(std::memory_order_relaxed);
        }

        uint64_t Dhcp6Server::PersistFailureCount() const noexcept {
            return persist_failures_.load(std::memory_order_relaxed);
        }

        uint64_t Dhcp6Server::DroppedLeaseCount() const noexcept {
            return dropped_leases_.load(std::memory_order_relaxed);
        }

        bool Dhcp6Server::LeaseFileCorrupt() const noexcept {
            return lease_file_corrupt_.load(std::memory_order_relaxed);
        }

        bool Dhcp6Server::PersistBlocked() const noexcept {
            return persist_blocked_.load(std::memory_order_relaxed);
        }

        std::vector<Dhcp6Server::LeaseEntry> Dhcp6Server::Leases(
            std::chrono::steady_clock::time_point now) const {
            std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(mutex_));
            std::vector<LeaseEntry> result;
            result.reserve(leases_.size());
            for (const auto& pair : leases_) {
                LeaseEntry entry;
                entry.duid = pair.first.duid;
                entry.iaid = pair.first.iaid;
                entry.ip = pair.second.ip;
                entry.is_static = pair.second.is_static;
                entry.hostname = pair.second.hostname;
                if (pair.second.is_static) {
                    entry.expires_in_s = UINT32_MAX;  // never expires
                } else {
                    const auto remaining = pair.second.expires - now;
                    entry.expires_in_s =
                        remaining.count() > 0
                            ? static_cast<uint32_t>(
                                  std::chrono::duration_cast<
                                      std::chrono::seconds>(remaining)
                                      .count())
                            : 0;
                }
                result.push_back(std::move(entry));
            }
            // Deterministic order: static bindings first (the UI shows the
            // fixed assignments on top), then by address.
            std::sort(result.begin(), result.end(),
                      [](const LeaseEntry& a, const LeaseEntry& b) {
                          if (a.is_static != b.is_static) {
                              return a.is_static;
                          }
                          return a.ip < b.ip;
                      });
            return result;
        }

        bool Dhcp6Server::UpsertBinding(const std::vector<uint8_t>& duid,
                                        const std::array<uint8_t, 16>& ip,
                                        const std::string& hostname) {
            // batch137: one implementation for "add/update" and "re-key"; a
            // plain upsert is the re-key whose old and new key are the same.
            return ReplaceBinding(duid, duid, ip, hostname);
        }

        bool Dhcp6Server::ReplaceBinding(const std::vector<uint8_t>& old_duid,
                                         const std::vector<uint8_t>& duid,
                                         const std::array<uint8_t, 16>& ip,
                                         const std::string& hostname) {
            if (duid.empty() || duid.size() > proto::kDhcp6MaxDuidLen ||
                IsZeroAddr(ip) || !InPrefix(ip)) {
                return false;
            }
            // batch111 (C7 same-shape sweep of the v4 fix): 253 bytes is the
            // DHCP option-value ceiling, and the v6 loader (config.cpp:720)
            // and ValidateConfig (:1533) both refuse a longer hostname. A
            // runtime entry that accepts one makes the two stores disagree
            // about what a legal hostname is, and the lease dump copies the
            // value into JSON, so it is a memory amplification as well.
            // An empty hostname means "preserve the config-derived one"
            // (documented at the assignment below), so it stays valid.
            if (!hostname.empty() && hostname.size() > ::vgww::core::limits::kMaxHostnameBytes) {
                return false;  // hostname too long: not representable on the wire
            }
            // batch123 (same-shape sibling of the v4 fix): an ill-formed name
            // makes nlohmann::json::dump() throw type_error.316, and the v6
            // dump runs on the 60 s control cadence (dataplane.cpp:3403), so a
            // bad name would abort every dump (RunGuarded then stops the data
            // plane). This is a CONTROL path, so it is rejected like oversize.
            if (!hostname.empty() && !core::IsValidUtf8(hostname)) {
                return false;  // ill-formed UTF-8: not representable in JSON/UI
            }
            std::lock_guard<std::mutex> lock(mutex_);
            // A runtime binding must not collide with an address reserved by
            // a config static binding (different DUID) or by another runtime
            // binding - checked before any state mutates so a rejected
            // duplicate leaves the previous binding/lease intact. Re-upserting
            // the same DUID's own address stays legal.
            for (const auto& cfg : config_.ipv6.dhcpv6.static_bindings) {
                if (cfg.ip == ip && cfg.duid != duid) {
                    return false;
                }
            }
            for (const auto& rt : runtime_bindings_) {
                // batch137: in a re-key the OLD binding is dropped by this
                // same call, so it cannot collide with the new one.
                if (rt.first != duid && rt.first != old_duid &&
                    rt.second.ip == ip) {
                    return false;
                }
            }
            // batch112 (C7 same-shape sweep of the v4 fix): the reverse
            // direction of the batch109 collision. batch109 made a runtime
            // binding reserve its address against the pool
            // (ReservedByStatic), but a live DYNAMIC lease on that address was
            // never consulted, so binding a second DUID onto an address that
            // another client currently holds produced two owners for one
            // address. Only a LIVE lease held by a DIFFERENT DUID blocks the
            // upsert: promoting the holder's own lease to a static
            // reservation is a legitimate operator action.
            //
            // "Live" mirrors Acquire's own occupancy test (`expires > now`;
            // leases_ is swept every 5 s), so an expired-but-unswept entry
            // cannot reject a legitimate bind for a few seconds.
            //
            // No is_static filter here: a static lease is keyed by the DUID it
            // was granted to, so `live.first.duid != duid` already means it
            // belongs to someone else - and that someone's binding was caught
            // by the two scans above. Adding the filter changes no observable
            // behaviour (mutation-tested: 0 failures), i.e. it would be
            // duplicate knowledge rather than a guard.
            {
                const auto now = std::chrono::steady_clock::now();
                for (const auto& live : leases_) {
                    // batch137: a re-key hands the binding over, so a live
                    // lease held by the OLD client on the new address is the
                    // operator retargeting that client, not a collision.
                    if (live.first.duid != duid &&
                        live.first.duid != old_duid && live.second.ip == ip &&
                        live.second.expires > now) {
                        return false;
                    }
                }
            }
            // batch110 (C7 same-shape sweep of the v4 fix): the
            // kMaxStaticBindings6 cap was enforced by the loader
            // (config.cpp:712), ValidateConfig (:1404) and out-of-lock in the
            // web route (web_api.cpp:2046), but NOT here - the choke point the
            // UI binding form also reaches through
            // Dataplane::SetDhcp6Binding.
            //
            // The check sits in the same lock as the insert (batch89), and the
            // budget is the MERGED view (config bindings first, runtime entries
            // replacing them by DUID), because that merged list is what the UI
            // renders and what Acquire scans. A runtime entry that only
            // OVERRIDES a config binding takes no new slot, and re-upserting an
            // existing DUID stays legal at the cap so "edit a binding" does not
            // fail exactly when the table is full.
            bool already_bound = runtime_bindings_.end() !=
                                 runtime_bindings_.find(duid);
            if (!already_bound) {
                for (const auto& cfg : config_.ipv6.dhcpv6.static_bindings) {
                    if (cfg.duid == duid) {
                        already_bound = true;
                        break;
                    }
                }
            }
            if (!already_bound) {
                size_t merged = config_.ipv6.dhcpv6.static_bindings.size();
                for (const auto& rt : runtime_bindings_) {
                    // batch137: the re-key erases the OLD runtime entry, so it
                    // must not be counted against the cap - otherwise a re-key
                    // that keeps the table the same size would be refused.
                    if (rt.first == old_duid) {
                        continue;
                    }
                    bool in_config = false;
                    for (const auto& cfg :
                         config_.ipv6.dhcpv6.static_bindings) {
                        if (cfg.duid == rt.first) {
                            in_config = true;
                            break;
                        }
                    }
                    if (!in_config) {
                        ++merged;
                    }
                }
                if (merged >= ::vgww::core::limits::kMaxStaticBindings6) {
                    return false;  // the store is full
                }
            }
            Binding binding;
            binding.ip = ip;
            // An explicit hostname (WebUI) wins; otherwise preserve the
            // config-derived hostname when it exists.
            if (!hostname.empty()) {
                binding.hostname = hostname;
            } else {
                for (const auto& cfg : config_.ipv6.dhcpv6.static_bindings) {
                    if (cfg.duid == duid) {
                        binding.hostname = cfg.hostname;
                        break;
                    }
                }
            }
            // batch137: the re-key commits here - the old binding and its
            // leases go, the new one lands, all under this one lock.
            if (old_duid != duid) {
                runtime_bindings_.erase(old_duid);
                for (auto it = leases_.begin(); it != leases_.end();) {
                    if (it->first.duid == old_duid) {
                        it = leases_.erase(it);
                    } else {
                        ++it;
                    }
                }
            }
            runtime_bindings_[duid] = std::move(binding);
            // Force the next Acquire for this client to use the new address.
            for (auto it = leases_.begin(); it != leases_.end();) {
                if (it->first.duid == duid) {
                    it = leases_.erase(it);
                } else {
                    ++it;
                }
            }
            return true;
        }

        bool Dhcp6Server::RemoveBinding(const std::vector<uint8_t>& duid) {
            std::lock_guard<std::mutex> lock(mutex_);
            const auto it = runtime_bindings_.find(duid);
            if (it != runtime_bindings_.end()) {
                runtime_bindings_.erase(it);
                for (auto l = leases_.begin(); l != leases_.end();) {
                    if (l->first.duid == duid) {
                        l = leases_.erase(l);  // client reverts to the pool
                    } else {
                        ++l;
                    }
                }
                return true;
            }
            // Same defect class as the v4 sibling: a binding that lives in the
            // CONFIG document is listed by StaticBindings() and served by
            // Acquire, so its delete button must work. Only the runtime table
            // was consulted, so every config-managed row answered "no such
            // binding" forever.
            auto& list = config_.ipv6.dhcpv6.static_bindings;
            const auto cfg = std::find_if(
                list.begin(), list.end(),
                [&duid](const core::Dhcp6StaticBinding& b) {
                    return b.duid == duid;
                });
            if (cfg == list.end()) {
                return false;
            }
            list.erase(cfg);
            for (auto l = leases_.begin(); l != leases_.end();) {
                if (l->first.duid == duid) {
                    l = leases_.erase(l);  // client reverts to the pool
                } else {
                    ++l;
                }
            }
            return true;
        }

        std::vector<core::Dhcp6StaticBinding> Dhcp6Server::StaticBindings()
            const {
            std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(mutex_));
            std::vector<core::Dhcp6StaticBinding> result;
            // Config bindings first (fallback values), then runtime
            // overrides replace them by DUID.
            for (const auto& cfg : config_.ipv6.dhcpv6.static_bindings) {
                core::Dhcp6StaticBinding view = cfg;
                const auto rt = runtime_bindings_.find(cfg.duid);
                if (rt != runtime_bindings_.end()) {
                    view.ip = rt->second.ip;
                    if (!rt->second.hostname.empty()) {
                        view.hostname = rt->second.hostname;
                    }
                }
                result.push_back(std::move(view));
            }
            // batch: the "already listed" test used to be a nested scan of the
            // whole config list per runtime entry - O(config x runtime) DUID
            // comparisons, all under mutex_ (the lock Acquire() takes on the
            // RX thread). At the kMaxStaticBindings6 cap that is ~1e6 compares
            // per call, and the WebUI polls the binding list. One unordered_set
            // of the config DUIDs makes the inner test O(1); the output order
            // and content are unchanged.
            std::unordered_set<std::vector<uint8_t>, DuidHash> config_duids;
            config_duids.reserve(config_.ipv6.dhcpv6.static_bindings.size());
            for (const auto& cfg : config_.ipv6.dhcpv6.static_bindings) {
                config_duids.insert(cfg.duid);
            }
            for (const auto& rt : runtime_bindings_) {
                if (0 == config_duids.count(rt.first)) {
                    core::Dhcp6StaticBinding view;
                    view.duid = rt.first;
                    view.ip = rt.second.ip;
                    view.hostname = rt.second.hostname;
                    result.push_back(std::move(view));
                }
            }
            return result;
        }

        size_t Dhcp6Server::StaticBindingCount() const {
            // batch127: same merge rule as StaticBindings() but O(1) vector
            // growth and no per-entry strings. Count config entries, then add
            // runtime entries whose DUID is NOT already a config entry (a
            // runtime override replaces, never duplicates).
            std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(mutex_));
            size_t count = config_.ipv6.dhcpv6.static_bindings.size();
            // batch: the "already counted" test used to be a nested scan of the
            // whole config list per runtime entry - O(config x runtime) DUID
            // comparisons, all under mutex_ (the lock Acquire() takes on the
            // RX thread). At the kMaxStaticBindings6 cap that is ~1e6 compares
            // per call, and /api/status polls this every 2 s. One unordered_set
            // of the config DUIDs makes the inner test O(1); the returned count
            // is unchanged.
            std::unordered_set<std::vector<uint8_t>, DuidHash> config_duids;
            config_duids.reserve(config_.ipv6.dhcpv6.static_bindings.size());
            for (const auto& cfg : config_.ipv6.dhcpv6.static_bindings) {
                config_duids.insert(cfg.duid);
            }
            for (const auto& rt : runtime_bindings_) {
                if (0 == config_duids.count(rt.first)) {
                    ++count;
                }
            }
            return count;
        }

        const std::vector<uint8_t>& Dhcp6Server::ServerDuid() const noexcept {
            return server_duid_;
        }

        bool Dhcp6Server::HandleFrame(
            const proto::Dhcp6View& view, const net::WireMac& client_mac,
            const std::array<uint8_t, 16>& client_ip,
            std::chrono::steady_clock::time_point now,
            std::vector<uint8_t>& out_reply) {
            if (view.client_duid.empty()) {
                return false;
            }
            // Per-DUID anti-storm budget before any reply work; a silent
            // drop is correct (clients retry with backoff).
            if (!AllowFrame(view.client_duid, now)) {
                return false;
            }

            proto::Dhcp6Reply reply;
            reply.xid = view.xid;
            reply.client_duid = view.client_duid;
            reply.server_duid = server_duid_;
            reply.with_dns = !config_.ipv6.dns.empty();
            reply.dns = config_.ipv6.dns;
            const uint32_t lease_s = config_.ipv6.dhcpv6.lease_seconds;
            const std::array<uint8_t, 16>* requested =
                view.has_ia_addr ? &view.ia_addr : nullptr;
            const auto fill_ia = [&](const std::array<uint8_t, 16>& addr) {
                reply.with_ia_na = true;
                reply.iaid = view.iaid;
                reply.t1 = lease_s / 2;
                reply.t2 = lease_s * 4 / 5;
                if (IsZeroAddr(addr)) {
                    reply.with_status = true;
                    reply.status_in_ia = true;
                    reply.status = proto::kDhcp6StatusNoAddrsAvail;
                } else {
                    reply.with_ia_addr = true;
                    reply.ia_addr = addr;
                    reply.preferred_s = lease_s;
                    reply.valid_s = lease_s;
                }
            };

            switch (view.msg_type) {
                case proto::kDhcp6MsgSolicit: {
                    const bool rapid = view.rapid_commit;
                    const auto addr = Acquire(
                        view.client_duid, view.iaid, now,
                        rapid ? OfferStage::kAck : OfferStage::kOffer,
                        std::string(), requested);
                    reply.msg_type = rapid ? proto::kDhcp6MsgReply
                                           : proto::kDhcp6MsgAdvertise;
                    reply.rapid_commit = rapid;
                    fill_ia(addr);
                    break;
                }
                case proto::kDhcp6MsgRequest:
                case proto::kDhcp6MsgRenew:
                case proto::kDhcp6MsgRebind: {
                    // REQUEST/RENEW must be addressed to this server when a
                    // server-id is present; REBIND carries none by design.
                    if (proto::kDhcp6MsgRebind != view.msg_type &&
                        view.has_server_id &&
                        view.server_duid != server_duid_) {
                        return false;
                    }
                    const auto addr = Acquire(view.client_duid, view.iaid, now,
                                              OfferStage::kAck, std::string(),
                                              requested);
                    fill_ia(addr);
                    break;
                }
                case proto::kDhcp6MsgRelease: {
                    if (view.has_server_id &&
                        view.server_duid != server_duid_) {
                        return false;  // addressed to another server
                    }
                    Release(view.client_duid, view.iaid, view.server_duid);
                    reply.with_status = true;
                    reply.status_in_ia = false;
                    reply.status = proto::kDhcp6StatusSuccess;
                    break;
                }
                case proto::kDhcp6MsgDecline: {
                    if (view.has_server_id &&
                        view.server_duid != server_duid_) {
                        return false;
                    }
                    Decline(view.client_duid, view.iaid, view.ia_addr, now);
                    reply.with_status = true;
                    reply.status_in_ia = false;
                    reply.status = proto::kDhcp6StatusSuccess;
                    break;
                }
                case proto::kDhcp6MsgConfirm: {
                    // RFC 8415 18.3.3: top-level Success when the address is
                    // still on-link, NotOnLink otherwise. No lease change.
                    reply.with_status = true;
                    reply.status_in_ia = false;
                    reply.status =
                        (view.has_ia_addr && InPrefix(view.ia_addr))
                            ? proto::kDhcp6StatusSuccess
                            : proto::kDhcp6StatusNotOnLink;
                    break;
                }
                case proto::kDhcp6MsgInformationRequest: {
                    // DNS-only reply; no address assignment (RFC 8415 18.3.6).
                    break;
                }
                default:
                    return false;
            }
            proto::BuildDhcp6ReplyFrame(
                reply, config_.gateway.mac, client_mac,
                proto::LinkLocalFromMac(config_.gateway.mac), client_ip,
                out_reply);
            return true;
        }

    }  // namespace dhcp6
}  // namespace vgww
