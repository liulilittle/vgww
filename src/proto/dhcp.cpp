// ============================================================================
// dhcp.cpp - DHCP frame parse/build + lease manager implementation.
// ============================================================================
#include "proto/dhcp.h"
#include "core/limits.h"
#include "core/text.h"

#include <nlohmann/json.hpp>

#include "net/checksum.h"
#include "net/eth.h"
#include "proto/udp.h"

#ifdef _WIN32
#include <windows.h>
#include <io.h>
#endif

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <fstream>
#include <filesystem>
#include <sstream>
#include <unordered_map>
#include <unordered_set>

using namespace vgww::net;

namespace vgww {
    namespace proto {

        namespace {
            inline constexpr std::array<uint8_t, 4> kMagicCookie = {0x63, 0x82,
                                                                    0x53, 0x63};
            std::atomic<uint64_t> g_parse_rejected{0};
        }  // namespace

        uint64_t ParseRejectedCount() noexcept {
            return g_parse_rejected.load(std::memory_order_relaxed);
        }

        bool ParseDhcpFrame(const uint8_t* data, size_t len, DhcpView& out) noexcept {
            // F1: every strict-validation failure drops the frame and bumps
            // the counter (status surface reports the delta).
            const auto reject = []() noexcept {
                g_parse_rejected.fetch_add(1, std::memory_order_relaxed);
                return false;
            };
            if (len < kDhcpFrameMin) {
                return reject();
            }
            EthHeaderView eth;
            if (!ParseEthHeader(data, len, eth) ||
                net::kEthertypeIpv4 != eth.ethertype) {
                return reject();
            }
            const uint8_t* ip = data + net::kEthernetHeaderLen;
            const size_t ihl = static_cast<size_t>(ip[0] & 0x0F) * 4;
            // IPv4 version must be 4 and the header length legal (IHL is
            // measured in 32-bit words, minimum 5 = 20 bytes, maximum 60).
            // `ihl` indexes straight into the frame below - reject garbage
            // before it can point the UDP/DHCP reads outside the buffer.
            if (4 != (ip[0] >> 4) || ihl < 20 || ihl > 60) {
                return reject();
            }
            // The UDP header must fit at [data+14+ihl .. len).
            if (len < net::kEthernetHeaderLen + ihl + kUdpHeaderLen) {
                return reject();
            }
            if (ip[9] != 17) {  // UDP
                return reject();
            }
            const uint8_t* udp = ip + ihl;
            const uint16_t sport = static_cast<uint16_t>((udp[0] << 8) | udp[1]);
            if (sport != 68 && sport != 67) {
                return reject();
            }
            // F1: a server-bound request targets port 67, and the UDP length
            // must agree with the bytes actually held (an off-by-one length
            // desyncs every downstream offset assumption).
            const uint16_t dport = static_cast<uint16_t>((udp[2] << 8) | udp[3]);
            if (dport != 67) {
                return reject();
            }
            const uint16_t udp_len_field =
                static_cast<uint16_t>((udp[4] << 8) | udp[5]);
            if (static_cast<size_t>(udp_len_field) !=
                len - net::kEthernetHeaderLen - ihl) {
                return reject();
            }
            // The fixed part (236 bytes) + magic (4 bytes) must be fully
            // inside the frame; an attacker-controlled ihl may otherwise make
            // these reads (client MAC, magic cookie) cross the end of `len`.
            if (len < net::kEthernetHeaderLen + ihl + kUdpHeaderLen +
                          kDhcpFixedLen) {
                return reject();
            }
            const uint8_t* dhcp = udp + kUdpHeaderLen;
            // F1: only client BOOTREQUESTs over Ethernet with a 6-byte
            // hardware address are processed; anything else is dropped.
            if (1 != dhcp[0] || 1 != dhcp[1] || 6 != dhcp[2]) {
                return reject();
            }
            // op/htype/hlen/hops + xid at [4..7]
            out.op = dhcp[0];
            out.xid = (static_cast<uint32_t>(dhcp[4]) << 24) |
                      (static_cast<uint32_t>(dhcp[5]) << 16) |
                      (static_cast<uint32_t>(dhcp[6]) << 8) | dhcp[7];
            std::memcpy(out.client_mac.data(), dhcp + 28, net::kMacAddrLen);
            out.msg_type = 0;
            out.requested_ip = 0;
            out.server_id = 0;

            // Magic cookie at [236 .. 240) - immediately after the 236-byte
            // fixed header (RFC 2131: magic follows file field).
            if (!(dhcp[236] == kMagicCookie[0] &&
                  dhcp[237] == kMagicCookie[1] &&
                  dhcp[238] == kMagicCookie[2] &&
                  dhcp[239] == kMagicCookie[3])) {
                return reject();
            }
            size_t pos = kDhcpFixedLen;  // offset within the DHCP part (240 = after magic)
            const size_t dhcp_len = len - net::kEthernetHeaderLen - ihl -
                                    kUdpHeaderLen;
            while (pos < dhcp_len) {
                const uint8_t code = dhcp[pos];
                if (kDhcpOptionEnd == code) {
                    break;
                }
                if (0 == code) {  // PAD
                    ++pos;
                    continue;
                }
                if (pos + 1 >= dhcp_len) {
                    break;
                }
                const uint8_t opt_len = dhcp[pos + 1];
                if (pos + 2 + opt_len > dhcp_len) {
                    break;
                }
                const uint8_t* value = dhcp + pos + 2;
                switch (code) {
                    case kDhcpOptionMsgType:
                        if (opt_len >= 1) {
                            out.msg_type = value[0];
                        }
                        break;
                    case kDhcpOptionRequestedIp:
                        if (opt_len >= 4) {
                            std::memcpy(&out.requested_ip, value, 4);
                        }
                        break;
                    case kDhcpOptionServerId:
                        if (opt_len >= 4) {
                            std::memcpy(&out.server_id, value, 4);
                        }
                        break;
                    case kDhcpOptionHostname:
                        out.hostname.assign(
                            reinterpret_cast<const char*>(value), opt_len);
                        break;
                    default:
                        break;
                }
                pos += 2 + opt_len;
            }
            return true;
        }

        void BuildDhcpReplyFrame(uint8_t msg_type, uint32_t xid,
                                 const net::WireMac& gateway_mac,
                                 const net::WireMac& client_mac,
                                 uint32_t your_ip, uint32_t server_ip,
                                 uint32_t subnet_mask, uint32_t lease_seconds,
                                 const std::vector<uint32_t>& dns_servers,
                                 const std::string& hostname,
                                 std::vector<uint8_t>& out_frame) {
            // Options blob first so the total length is known up front.
            std::vector<uint8_t> options;
            auto push_option = [&options](uint8_t code,
                                          const std::vector<uint8_t>& value) {
                // A DHCP option's length octet caps a value at 255; values
                // longer than that (a config hostname or a DNS list) must be
                // truncated to 253 bytes so the TLV length always matches the
                // bytes actually emitted. Writing the full value with a
                // truncated length constant would desync the whole option
                // stream in the client's parser.
                const uint8_t len = static_cast<uint8_t>(
                    std::min<size_t>(value.size(), ::vgww::core::limits::kMaxHostnameBytes));
                options.push_back(code);
                options.push_back(len);
                options.insert(options.end(), value.begin(),
                              value.begin() + len);
            };
            auto push_u32 = [](uint32_t v) {
                return std::vector<uint8_t>{static_cast<uint8_t>(v >> 24),
                                            static_cast<uint8_t>(v >> 16),
                                            static_cast<uint8_t>(v >> 8),
                                            static_cast<uint8_t>(v)};
            };
            // IP addresses in this codebase are numeric with the first octet
            // in the LOW byte (the inet_addr convention; config parsing
            // produces this form). Writing them to the wire must therefore
            // emit the host's memory bytes (LSB first) - identical to a
            // memcpy of the value. Serializing them big-endian like a plain
            // integer byte-swaps every address.
            auto push_ip = [](uint32_t v) {
                return std::vector<uint8_t>{static_cast<uint8_t>(v),
                                            static_cast<uint8_t>(v >> 8),
                                            static_cast<uint8_t>(v >> 16),
                                            static_cast<uint8_t>(v >> 24)};
            };
            options.push_back(kDhcpOptionMsgType);
            options.push_back(1);
            options.push_back(msg_type);
            push_option(kDhcpOptionServerId, push_ip(server_ip));
            if (kDhcpMsgAck == msg_type) {
                push_option(kDhcpOptionSubnet, push_ip(subnet_mask));
                push_option(kDhcpOptionRouter, push_ip(server_ip));
                push_option(kDhcpOptionLeaseTime, push_u32(lease_seconds));
                if (!dns_servers.empty()) {
                    std::vector<uint8_t> dns_blob;
                    for (uint32_t dns : dns_servers) {
                        auto bytes = push_ip(dns);
                        dns_blob.insert(dns_blob.end(), bytes.begin(),
                                        bytes.end());
                    }
                    push_option(kDhcpOptionDns, dns_blob);
                }
                if (!hostname.empty()) {
                    std::vector<uint8_t> host(hostname.begin(), hostname.end());
                    push_option(kDhcpOptionHostname, host);
                }
            }
            options.push_back(kDhcpOptionEnd);

            const size_t dhcp_len = kDhcpFixedLen + options.size();
            const size_t udp_len = kUdpHeaderLen + dhcp_len;
            out_frame.assign(net::kEthernetHeaderLen + 20 + udp_len, 0);
            uint8_t* frame = out_frame.data();

            // Ethernet: unicast to the client MAC.
            BuildEthHeader(frame, client_mac, gateway_mac, net::kEthertypeIpv4);

            // IPv4: src = server (gateway), dst = limited broadcast.
            uint8_t* ip = frame + net::kEthernetHeaderLen;
            ip[0] = 0x45;
            const uint16_t total = static_cast<uint16_t>(20 + udp_len);
            ip[2] = static_cast<uint8_t>(total >> 8);
            ip[3] = static_cast<uint8_t>(total & 0xFF);
            ip[6] = 0x40;  // DF
            ip[8] = 64;    // TTL
            ip[9] = 17;    // UDP
            const uint32_t broadcast = 0xFFFFFFFFu;  // 255.255.255.255
            std::memcpy(ip + 12, &server_ip, 4);
            std::memcpy(ip + 16, &broadcast, 4);

            // UDP: server port 67 -> client port 68.
            uint8_t* udp = ip + 20;
            udp[0] = 0;
            udp[1] = 67;
            udp[2] = 0;
            udp[3] = 68;
            udp[4] = static_cast<uint8_t>(udp_len >> 8);
            udp[5] = static_cast<uint8_t>(udp_len & 0xFF);

            // DHCP fixed part.
            uint8_t* d = udp + kUdpHeaderLen;
            d[0] = 2;             // op: BOOTREPLY
            d[1] = 1;             // htype: Ethernet
            d[2] = 6;             // hlen
            d[3] = 0;             // hops
            d[4] = static_cast<uint8_t>(xid >> 24);
            d[5] = static_cast<uint8_t>(xid >> 16);
            d[6] = static_cast<uint8_t>(xid >> 8);
            d[7] = static_cast<uint8_t>(xid);
            d[10] = 0x80;         // flags: BROADCAST
            std::memcpy(d + 16, &your_ip, 4);      // yiaddr
            std::memcpy(d + 20, &server_ip, 4);    // siaddr
            std::memcpy(d + 28, client_mac.data(), net::kMacAddrLen);
            std::memcpy(d + 236, kMagicCookie.data(), 4);

            // Options.
            std::memcpy(d + kDhcpFixedLen, options.data(), options.size());

            // Checksums: UDP pseudo-header over the DHCP payload, then IP.
            const uint16_t udp_ck =
                net::InternetChecksum(udp, static_cast<uint16_t>(udp_len),
                                      net::PseudoHeaderSum(
                                          ip + 12, ip + 16, 17,
                                          static_cast<uint16_t>(udp_len)));
            udp[6] = static_cast<uint8_t>(udp_ck >> 8);
            udp[7] = static_cast<uint8_t>(udp_ck & 0xFF);
            const uint16_t ip_ck = net::InternetChecksum(ip, 20);
            ip[10] = static_cast<uint8_t>(ip_ck >> 8);
            ip[11] = static_cast<uint8_t>(ip_ck & 0xFF);
        }

    }  // namespace proto

    namespace dhcp {

        namespace {
            /// Network -> host byte order (inet_addr numeric convention).
            inline uint32_t ToHost(uint32_t net_order) noexcept {
                return ((net_order & 0x000000FFu) << 24) |
                       ((net_order & 0x0000FF00u) << 8) |
                       ((net_order & 0x00FF0000u) >> 8) |
                       ((net_order & 0xFF000000u) >> 24);
            }
            /// Host -> network byte order.
            inline uint32_t ToNet(uint32_t host_order) noexcept {
                return ToHost(host_order);  // byte swap is its own inverse
            }
        }  // namespace

        DhcpServer::DhcpServer(const core::Config& config)
            : config_(config) {
            // Seed the pool cursor at the first dynamic address (host order).
            next_dynamic_ = ToHost(config_.dhcp.pool_start);
        }

        uint32_t DhcpServer::Acquire(const net::WireMac& client_mac,
                                     std::chrono::steady_clock::time_point now,
                                     OfferStage stage,
                                     const std::string& hostname,
                                     uint32_t requested_ip) {
            std::lock_guard<std::mutex> lock(mutex_);

            // batch123: option 12 is arbitrary bytes from the wire. The lease
            // hostname is a display string that later crosses two strict
            // boundaries - nlohmann::json::dump() (throws type_error.316 on an
            // ill-formed byte, and DumpLeases has no try/catch) and the WebUI
            // JSON body (must be valid UTF-8). Sanitize ONCE here, at the
            // trust boundary, so the store only ever holds well-formed UTF-8:
            // both sinks are then total by construction. An empty value stays
            // empty (the "renew without option 12 keeps the learnt name"
            // contract). SanitizeUtf8 is identity for well-formed input, so
            // the common path is unchanged.
            const std::string reported_name = core::SanitizeUtf8(hostname);

            // Hold windows: an OFFER pins the address briefly so a client
            // that vanishes before REQUEST cannot drain the pool; DECLINEd
            // addresses stay unusable for ten minutes.
            constexpr std::chrono::seconds kOfferHold{60};
            constexpr std::chrono::seconds kDeclineHold{600};
            const std::chrono::seconds term =
                (OfferStage::kOffer == stage)
                    ? std::min(kOfferHold,
                               std::chrono::seconds(config_.dhcp.lease_seconds))
                    : std::chrono::seconds(config_.dhcp.lease_seconds);

            // 1. Static bindings always win: runtime (WebUI) first, then config.
            const auto runtime = runtime_bindings_.find(client_mac);
            if (runtime != runtime_bindings_.end()) {
                Lease& lease = leases_[client_mac];
                lease.ip = runtime->second.ip;
                lease.is_static = true;
                lease.expires = now + term;
                if (!hostname.empty()) {
                    lease.hostname = reported_name;
                }
                return runtime->second.ip;
            }
            for (const auto& binding : config_.dhcp.static_bindings) {
                if (binding.mac == client_mac) {
                    Lease& lease = leases_[client_mac];
                    lease.ip = binding.ip;
                    lease.is_static = true;
                    lease.expires = now + term;
                    if (!hostname.empty()) {
                        lease.hostname = reported_name;
                    }
                    return binding.ip;
                }
            }

            // 2. Existing dynamic lease renews in place.
            const auto existing = leases_.find(client_mac);
            if (existing != leases_.end() && !existing->second.is_static &&
                existing->second.expires > now) {
                existing->second.expires = now + term;
                if (!hostname.empty()) {
                    existing->second.hostname = reported_name;
                }
                return existing->second.ip;
            }

            // 3. Walk the dynamic pool for a free address (host-order math).
            const uint32_t start = ToHost(config_.dhcp.pool_start);
            const uint32_t end = ToHost(config_.dhcp.pool_end);
            if (0 == start || 0 == end || end < start) {
                return 0;
            }
            // The LAN network and broadcast addresses are never handed out
            // (a pool may legitimately span them).
            const uint32_t lan_host =
                ToHost(config_.gateway.ipv4 & config_.gateway.mask);
            const uint32_t bcast_host =
                lan_host | ~ToHost(config_.gateway.mask);
            const uint32_t pool_size = end - start + 1;
            // A statically-bound address is reserved even while the bound
            // client is OFFLINE: it must never be handed out dynamically,
            // otherwise the client returns to find its bound IP already
            // leased to someone else (static-vs-dynamic collision).
            std::unordered_set<uint32_t> reserved_hosts;
            for (const auto& binding : config_.dhcp.static_bindings) {
                reserved_hosts.insert(ToHost(binding.ip));
            }
            // batch109: entries pinned by a RUNTIME (Web/UI) binding reserve
            // their address too. Config bindings were already covered above,
            // but a runtime binding was not, so the walk below could hand the
            // same address to a second client and the LAN ended up with two
            // owners for one IP.
            for (const auto& rt : runtime_bindings_) {
                reserved_hosts.insert(ToHost(rt.second.ip));
            }

            // 3a. Honour option 50 (F2): a requested address that is free,
            // inside the pool, not reserved/static and not the gateway is
            // handed out before the round-robin walk. Occupied, out-of-pool
            // or declined addresses silently fall through to the walk.
            // `requested_ip` arrives in the same numeric space as the config
            // values (wire memcpy == inet_addr), so it is converted with
            // ToHost exactly like pool_start/pool_end above.
            if (0 != requested_ip) {
                const uint32_t req_host = ToHost(requested_ip);
                bool usable = req_host >= start && req_host <= end;
                if (usable) {
                    for (const auto& pair : leases_) {
                        if (ToHost(pair.second.ip) == req_host &&
                            pair.second.expires > now) {
                            usable = false;
                            break;
                        }
                    }
                }
                if (usable) {
                    // declined_until_ is keyed by the config-space form, the
                    // same value Acquire returns for a lease.
                    const auto bad = declined_until_.find(requested_ip);
                    if (bad != declined_until_.end()) {
                        if (bad->second > now) {
                            usable = false;
                        } else {
                            declined_until_.erase(bad);  // hold elapsed
                        }
                    }
                }
                if (usable && (0 != reserved_hosts.count(req_host) ||
                               req_host == ToHost(config_.gateway.ipv4) ||
                               req_host == lan_host ||
                               req_host == bcast_host)) {
                    usable = false;
                }
                if (usable) {
                    Lease& lease = leases_[client_mac];
                    lease.ip = ToNet(req_host);
                    lease.is_static = false;
                    lease.expires = now + term;
                    lease.hostname = reported_name;
                    next_dynamic_ = req_host + 1;
                    return lease.ip;
                }
            }
            // batch114: the occupancy set is built ONCE here instead of
            // rescanning the whole lease table for every candidate address.
            // The old shape was O(pool_size x leases) with both factors
            // uncapped (a /16 pool is ordinary; leases_ has no entry cap), and
            // it all ran under mutex_ - the same lock every DHCP frame and
            // every Web/UI binding call needs. A /16 pool with a half-full
            // table is ~1e9 comparisons inside the lock, i.e. the DHCP server
            // stops answering and the UI freezes behind it. One pass over
            // leases_ keeps this O(leases + pool_size).
            std::unordered_map<uint32_t, net::WireMac> occupied_hosts;
            occupied_hosts.reserve(leases_.size());
            for (const auto& pair : leases_) {
                lease_scans_.fetch_add(1, std::memory_order_relaxed);
                if (pair.second.expires > now) {
                    occupied_hosts.emplace(ToHost(pair.second.ip), pair.first);
                }
            }
            for (uint32_t offset = 0; offset < pool_size; ++offset) {
                const uint32_t candidate_host =
                    start + ((next_dynamic_ - start + offset) % pool_size);
                bool taken = 0 != occupied_hosts.count(candidate_host);

                // Skip addresses reported conflicting and still on hold.
                if (!taken) {
                    const auto bad = declined_until_.find(
                        ToNet(candidate_host));
                    if (bad != declined_until_.end()) {
                        if (bad->second > now) {
                            taken = true;
                        } else {
                            declined_until_.erase(bad);  // hold elapsed
                        }
                    }
                }
                if (taken || 0 != reserved_hosts.count(candidate_host) ||
                    candidate_host == ToHost(config_.gateway.ipv4) ||
                    candidate_host == lan_host ||
                    candidate_host == bcast_host) {
                    continue;
                }
                Lease& lease = leases_[client_mac];
                lease.ip = ToNet(candidate_host);  // store in network order
                lease.is_static = false;
                lease.expires = now + term;
                lease.hostname = reported_name;  // fresh lease: learn the reported name
                next_dynamic_ = candidate_host + 1;  // round-robin cursor
                return lease.ip;
            }
            // F5: pool exhausted - stay silent (RFC 2131: no NAK for a
            // merely-unavailable address) but make it observable: count it
            // and log at most once per kPoolLogIntervalMs.
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
                    stderr, "[vgww] dhcp: pool exhausted (%llu total)\n",
                    static_cast<unsigned long long>(
                        pool_exhausted_.load(std::memory_order_relaxed)));
            }
            return 0;
        }

        void DhcpServer::Decline(const net::WireMac& client_mac, uint32_t ip,
                                 std::chrono::steady_clock::time_point now) {
            std::lock_guard<std::mutex> lock(mutex_);
            if (0 == ip) {
                return;
            }
            // F3: only the client actually holding this address may park it.
            // A foreign MAC (buggy or spoofed) must not be able to knock
            // other clients' addresses out of the pool.
            const auto it = leases_.find(client_mac);
            if (it == leases_.end() || it->second.is_static ||
                it->second.ip != ip) {
                return;
            }
            // Drop the reporter's lease: it cannot use the address anyway.
            leases_.erase(it);
            declined_until_[ip] =
                now + std::chrono::seconds(600);  // RFC 2131 suggests long
        }

        void DhcpServer::Release(const net::WireMac& client_mac, uint32_t server_id) {
            std::lock_guard<std::mutex> lock(mutex_);
            // F6: a RELEASE carrying a server-id that is not ours (addressed
            // to a different server on the segment) must keep our binding.
            // Server-ids arrive in the same numeric space as config values
            // (wire memcpy == inet_addr); `0` means the client did not echo
            // one (legacy callers) and keeps the historical behaviour.
            if (0 != server_id && server_id != config_.gateway.ipv4) {
                return;
            }
            const auto it = leases_.find(client_mac);
            if (it != leases_.end() && !it->second.is_static) {
                leases_.erase(it);
            }
        }

        uint64_t DhcpServer::PoolExhaustedCount() const noexcept {
            return pool_exhausted_.load(std::memory_order_relaxed);
        }

        uint64_t DhcpServer::RateLimitResets() const noexcept {
            return rate_limit_resets_.load(std::memory_order_relaxed);
        }

        uint64_t DhcpServer::LeaseScanCount() const noexcept {
            return lease_scans_.load(std::memory_order_relaxed);
        }

        uint64_t DhcpServer::PersistFailureCount() const noexcept {
            return persist_failures_.load(std::memory_order_relaxed);
        }

        uint64_t DhcpServer::DroppedLeaseCount() const noexcept {
            return dropped_leases_.load(std::memory_order_relaxed);
        }

        bool DhcpServer::LeaseFileCorrupt() const noexcept {
            return lease_file_corrupt_.load(std::memory_order_relaxed);
        }

        bool DhcpServer::PersistBlocked() const noexcept {
            return persist_blocked_.load(std::memory_order_relaxed);
        }

        bool DhcpServer::AllowFrame(const net::WireMac& client_mac,
                                    std::chrono::steady_clock::time_point now) {
            std::lock_guard<std::mutex> lock(mutex_);
            // Anti-storm: a faulty/hostile client blasting DISCOVER/REQUEST
            // frames otherwise burns build/reply CPU and refreshes the hold
            // window on the pool address it is probing, stalling real
            // clients. Allow a small per-second budget per MAC; keep the
            // miss-side map bounded the same way the probe caches are.
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
            RateWindow& win = rate_limit_[client_mac];
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

        size_t DhcpServer::Sweep(std::chrono::steady_clock::time_point now) {
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

        size_t DhcpServer::LeaseCount() const noexcept {
            std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(mutex_));
            return leases_.size();
        }

        std::vector<DhcpServer::LeaseEntry> DhcpServer::Leases(
            std::chrono::steady_clock::time_point now) const {
            std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(mutex_));
            std::vector<LeaseEntry> result;
            result.reserve(leases_.size());
            for (const auto& pair : leases_) {
                LeaseEntry entry;
                entry.mac = pair.first;
                entry.ip = pair.second.ip;
                entry.is_static = pair.second.is_static;
                entry.hostname = pair.second.hostname;
                if (pair.second.is_static) {
                    entry.expires_in_s = UINT32_MAX;  // never expires
                } else {
                    const auto remaining = pair.second.expires - now;
                    entry.expires_in_s = remaining.count() > 0
                        ? static_cast<uint32_t>(
                              std::chrono::duration_cast<std::chrono::seconds>(
                                  remaining)
                                  .count())
                        : 0;
                }
                result.push_back(std::move(entry));
            }
            return result;
        }

        bool DhcpServer::UpsertBinding(const net::WireMac& client_mac,
                                       uint32_t ip,
                                       const std::string& hostname) {
            // batch137: one implementation for "add/update" and "re-key". A
            // plain upsert is the re-key whose old and new key are the same.
            return ReplaceBinding(client_mac, client_mac, ip, hostname);
        }

        bool DhcpServer::ReplaceBinding(const net::WireMac& old_mac,
                                        const net::WireMac& client_mac,
                                        uint32_t ip,
                                        const std::string& hostname) {
            // Static bindings are independent of the dynamic pool: the pool
            // walk already skips reserved addresses (see Acquire), so a
            // binding may live anywhere on the LAN - including outside the
            // pool range or on a pool-less (static-only) server. The null
            // address and the gateway address are invalid.
            if (0 == ip) {
                return false;  // 0.0.0.0 invalid
            }
            if (ip == config_.gateway.ipv4) {
                return false;  // the gateway itself can never be bound
            }
            // batch111: 253 bytes is the DHCP option-value ceiling (one length
            // octet), which is exactly where BuildDhcpReplyFrame clamps. The
            // loader (config.cpp:464) and ValidateConfig (:1501) both refuse a
            // longer hostname, so a runtime entry that accepts one makes the
            // two stores disagree about what a legal hostname is. It is also a
            // memory amplification: the HTTP body cap is kMaxConfigBytes
            // (1 MiB), so kMaxStaticBindings entries could pin ~1 GiB that the
            // per-tick snapshot then copies into the UI.
            //
            // An empty hostname means "preserve the existing one" (documented
            // at the assignment below), so it stays valid and is not a
            // too-long value.
            if (!hostname.empty() && hostname.size() > ::vgww::core::limits::kMaxHostnameBytes) {
                return false;  // hostname too long: not representable on the wire
            }
            // batch123: an ill-formed name cannot be stored - nlohmann::json
            // dump() throws type_error.316 on it and the WebUI JSON body must
            // be valid UTF-8. This is a CONTROL path (operator input from
            // POST /api/dhcp/bindings or the UI form), so it is REJECTED like
            // an oversize name rather than silently rewritten. Well-formed
            // multi-byte names (e.g. CJK) stay accepted.
            if (!hostname.empty() && !core::IsValidUtf8(hostname)) {
                return false;  // ill-formed UTF-8: not representable in JSON/UI
            }
            // batch109: enforce the placement rules the OTHER two entries
            // already enforce (config.cpp ParseDhcp and ValidateConfig both
            // reject an out-of-subnet binding and the subnet's network or
            // broadcast address; the DHCPv6 sibling rejects !InPrefix(ip)).
            // Without this, POST /api/dhcp/bindings and the UI form accepted a
            // binding on e.g. 10.9.9.1 in a 192.168.0.0/24 LAN, and Acquire
            // handed that address verbatim to the client - an address it
            // provably cannot reach. A zero mask means "no LAN configured",
            // so placement cannot be judged and only the checks above apply
            // (TestRuntimeBindings/TestRuntimeBindingWithoutPool rely on it).
            if (0 != config_.gateway.mask) {
                const uint32_t mask = config_.gateway.mask;
                if ((ip & mask) != (config_.gateway.ipv4 & mask)) {
                    return false;  // outside the gateway subnet
                }
                const uint32_t host = ToHost(ip);
                const uint32_t hmask = ToHost(mask);
                const uint32_t host_bits = ~hmask;
                // /31 and /32 have no network/broadcast concept.
                if (host_bits > 1u) {
                    const uint32_t net = host & hmask;
                    if (host == net || host == (net | host_bits)) {
                        return false;  // subnet network or broadcast address
                    }
                }
            }

            std::lock_guard<std::mutex> lock(mutex_);
            // A runtime binding must not collide with an address already
            // reserved by a config static binding (different MAC) or by
            // another runtime binding - checked before any state mutates so a
            // rejected duplicate leaves the previous binding/lease intact.
            // Re-upserting the same MAC's own address stays legal.
            for (const auto& cfg : config_.dhcp.static_bindings) {
                if (cfg.ip == ip && cfg.mac != client_mac) {
                    return false;
                }
            }
            for (const auto& rt : runtime_bindings_) {
                // batch137: in a re-key the OLD binding is removed by this
                // same call, so it cannot collide with the new one - a
                // binding that keeps its address while changing owner must
                // stay legal.
                if (rt.first != client_mac && rt.first != old_mac &&
                    rt.second.ip == ip) {
                    return false;
                }
            }
            // batch112: the reverse direction of the batch109 collision. A
            // runtime binding reserves its address against the dynamic pool,
            // but a DYNAMIC LEASE already held on that address was not
            // consulted, so binding someone else onto a live lease produced
            // two owners for one address (Acquire then served the same IP to
            // both). Only a LIVE lease held by a DIFFERENT client blocks the
            // upsert: promoting the current holder's own lease to a static
            // reservation is a legitimate operator action and stays legal.
            //
            // "Live" mirrors Acquire's own notion of occupancy
            // (`expires > now`, leases_ is swept every 5 s): an expired entry
            // that has not been swept yet is not an owner, so it must not be
            // able to reject a legitimate bind for a few seconds.
            //
            // No is_static filter here: a static lease is keyed by the client
            // it was granted to, so `live.first != client_mac` already means
            // it belongs to someone else - and that someone's binding was
            // caught by the two scans above. Adding the filter changes no
            // observable behaviour (mutation-tested: 0 failures), i.e. it
            // would be duplicate knowledge rather than a guard.
            {
                const auto now = std::chrono::steady_clock::now();
                for (const auto& live : leases_) {
                    // batch137: a re-key hands the binding over, so a live
                    // lease held by the OLD client on the new address is the
                    // operator retargeting that very client, not a collision.
                    if (live.first != client_mac && live.first != old_mac &&
                        live.second.ip == ip && live.second.expires > now) {
                        return false;
                    }
                }
            }
            // batch110: the kMaxStaticBindings cap was enforced at EVERY entry
            // except this one - the choke point both runtime writes funnel
            // through (Web POST /api/dhcp/bindings and the UI add-binding form
            // both end up in Dataplane::SetDhcpBinding -> here). The loader
            // (config.cpp:457) and ValidateConfig (:1393) cap, and the web
            // route caps out-of-lock, but nothing capped this store, so the UI
            // path could grow it without bound.
            //
            // The cap must live in the SAME lock as the insert (batch89): an
            // out-of-lock size read lets two concurrent writers both observe
            // "below cap".
            //
            // Budget is the MERGED view (config bindings first, runtime
            // entries replacing them by MAC), because that merged list is what
            // the UI renders, what Acquire scans and what the lease dump
            // serializes. A runtime entry that only OVERRIDES a config binding
            // does not consume a new slot, and re-upserting an existing MAC
            // stays legal even at the cap - otherwise "edit a binding" would
            // fail exactly when the table is full.
            bool already_bound = runtime_bindings_.end() !=
                                 runtime_bindings_.find(client_mac);
            if (!already_bound) {
                for (const auto& cfg : config_.dhcp.static_bindings) {
                    if (cfg.mac == client_mac) {
                        already_bound = true;
                        break;
                    }
                }
            }
            if (!already_bound) {
                size_t merged = config_.dhcp.static_bindings.size();
                for (const auto& rt : runtime_bindings_) {
                    // batch137: the re-key erases the OLD runtime entry, so it
                    // does not occupy a slot in the post-commit view. Without
                    // this the cap would reject a re-key that actually keeps
                    // the table the same size (or shrinks it).
                    if (rt.first == old_mac) {
                        continue;
                    }
                    bool in_config = false;
                    for (const auto& cfg : config_.dhcp.static_bindings) {
                        if (cfg.mac == rt.first) {
                            in_config = true;
                            break;
                        }
                    }
                    if (!in_config) {
                        ++merged;
                    }
                }
                if (merged >= ::vgww::core::limits::kMaxStaticBindings) {
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
                for (const auto& cfg : config_.dhcp.static_bindings) {
                    if (cfg.mac == client_mac) {
                        binding.hostname = cfg.hostname;
                        break;
                    }
                }
            }
            // batch137: the re-key commits here - the old binding and its
            // lease go, the new one lands, all under this one lock.
            if (old_mac != client_mac) {
                runtime_bindings_.erase(old_mac);
                leases_.erase(old_mac);
            }
            runtime_bindings_[client_mac] = std::move(binding);
            // Force the next Acquire for this client to use the new address.
            leases_.erase(client_mac);
            return true;
        }

        bool DhcpServer::RemoveBinding(const net::WireMac& client_mac) {
            std::lock_guard<std::mutex> lock(mutex_);
            const auto it = runtime_bindings_.find(client_mac);
            if (it != runtime_bindings_.end()) {
                runtime_bindings_.erase(it);
                leases_.erase(client_mac);  // client reverts to the dynamic pool
                return true;
            }
            // A binding that lives in the CONFIG document is just as real as a
            // runtime one: StaticBindings() lists it and Acquire serves it, so
            // the delete button the UI renders for that row must work. The
            // runtime table was the only source consulted, so every
            // config-managed row answered "no such binding" forever.
            auto& list = config_.dhcp.static_bindings;
            const auto cfg = std::find_if(
                list.begin(), list.end(),
                [&client_mac](const core::StaticBinding& b) {
                    return b.mac == client_mac;
                });
            if (cfg == list.end()) {
                return false;
            }
            list.erase(cfg);
            leases_.erase(client_mac);  // client reverts to the dynamic pool
            return true;
        }

        std::vector<DhcpServer::StaticView> DhcpServer::StaticBindings() const {
            std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(mutex_));
            std::vector<StaticView> result;
            // Config bindings first (fallback values), then runtime overrides
            // replace them by MAC.
            for (const auto& cfg : config_.dhcp.static_bindings) {
                StaticView view;
                view.mac = cfg.mac;
                view.ip = cfg.ip;
                view.hostname = cfg.hostname;
                const auto rt = runtime_bindings_.find(cfg.mac);
                if (rt != runtime_bindings_.end()) {
                    view.ip = rt->second.ip;
                    if (!rt->second.hostname.empty()) {
                        view.hostname = rt->second.hostname;
                    }
                }
                result.push_back(std::move(view));
            }
            for (const auto& rt : runtime_bindings_) {
                bool already = false;
                for (const auto& cfg : config_.dhcp.static_bindings) {
                    if (cfg.mac == rt.first) {
                        already = true;
                        break;
                    }
                }
                if (!already) {
                    StaticView view;
                    view.mac = rt.first;
                    view.ip = rt.second.ip;
                    view.hostname = rt.second.hostname;
                    result.push_back(std::move(view));
                }
            }
            return result;
        }

        namespace {

#ifdef _WIN32
            inline std::wstring ToWideLongPath(const std::string& path)
            {
                int wlen = ::MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, nullptr, 0);

                if (wlen <= 0)
                {
                    return L"";
                }

                std::wstring wpath;
                wpath.resize(static_cast<size_t>(wlen - 1));
                ::MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, wpath.data(), wlen);

                if (wpath.size() >= 260 && wpath.rfind(L"\\\\?\\", 0) != 0)
                {
                    if (wpath.size() >= 2 && wpath[1] == L':')
                    {
                        wpath = L"\\\\?\\" + wpath;
                    }
                    else if (wpath.rfind(L"\\\\", 0) == 0)
                    {
                        wpath = L"\\\\?\\UNC\\" + wpath.substr(2);
                    }
                    else
                    {
                        wchar_t absBuf[32767];
                        DWORD len = ::GetFullPathNameW(wpath.c_str(), 32767, absBuf, nullptr);

                        if (0 != len && len < 32767)
                        {
                            wpath.assign(absBuf, len);

                            if (wpath.rfind(L"\\\\?\\", 0) != 0)
                            {
                                if (wpath.size() >= 2 && wpath[1] == L':')
                                {
                                    wpath = L"\\\\?\\" + wpath;
                                }
                                else if (wpath.rfind(L"\\\\", 0) == 0)
                                {
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

        bool DhcpServer::DumpLeases(
            const std::string& path,
            std::chrono::steady_clock::time_point now) {
            // batch85: never overwrite a file this server could not read (it
            // may be a perfectly valid snapshot that was briefly locked).
            // batch87: retry the read first; once it succeeds the disk leases
            // are merged (LoadLeases keeps live leases and drops disk entries
            // whose address is already taken) and the block clears, so the
            // operator does not need a restart.
            if (persist_blocked_.load(std::memory_order_relaxed)) {
                // batch87: retry the read first. Live leases are snapshotted so
                // a DISK entry that names an address a live client already
                // holds can be dropped after the merge: one address, one owner
                // (batch134), even across the blocked-start recovery.
                std::unordered_map<net::WireMac, Lease, net::WireMacHash> live;
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
                    // batch206: LoadLeases REPLACED the whole table with the
                    // disk snapshot (leases_[mac] = lease), so a client that
                    // was issued an address DURING the blocked window (file
                    // briefly unreadable) lost it: the table went back to the
                    // previous session's mapping for that MAC, and the address
                    // that client actually holds became free for the next
                    // DISCOVER (duplicate address on the wire). The cleanup
                    // below only dropped a disk entry whose MAC is NOT live and
                    // whose address IS live-held - a MAC that is live on both
                    // sides was skipped, so the stale disk address silently
                    // won. Restore live entries over the freshly loaded ones:
                    // what the client is holding now is the truth, the disk is
                    // a best-effort recovery source.
                    for (const auto& kv : live) {
                        leases_[kv.first] = kv.second;
                    }
                    std::unordered_set<uint32_t> live_ips;
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
            // batch81: the lock covers ONLY the snapshot copy (same defect as
            // Dhcp6Server::DumpLeases - measured 86-484 ms of blocked renews
            // while the dump ran, versus a sub-millisecond baseline). Doing the
            // JSON build and the file write with FlushFileBuffers inside
            // mutex_ stalls every DHCP frame on the RX thread (D13).
            struct SnapshotEntry {
                net::WireMac mac{};
                uint32_t ip = 0;
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
                    entry.mac = pair.first;
                    entry.ip = pair.second.ip;
                    entry.remaining_us = std::chrono::duration_cast<
                                             std::chrono::microseconds>(
                                             pair.second.expires - now)
                                             .count();
                    entry.hostname = pair.second.hostname;
                    snapshot.push_back(std::move(entry));
                }
            }  // lock released: the remaining work touches no shared state
            std::ostringstream json;
            // F4: versioned envelope so a future schema change can be
            // detected instead of silently mis-parsed.
            json << "{\"version\":1,\"leases\":[";
            bool first = true;
            for (const auto& entry : snapshot) {
                char mac_text[18];
                std::snprintf(mac_text, sizeof(mac_text),
                              "%02X:%02X:%02X:%02X:%02X:%02X", entry.mac[0],
                              entry.mac[1], entry.mac[2], entry.mac[3],
                              entry.mac[4], entry.mac[5]);
                const uint32_t ip = entry.ip;
                const std::string ip_text =
                    (std::ostringstream() << ((ip & 0xFF)) << "."
                                          << ((ip >> 8) & 0xFF) << "."
                                          << ((ip >> 16) & 0xFF) << "."
                                          << ((ip >> 24) & 0xFF)).str();
                // Persist the REMAINING lifetime so a reload does not grant a
                // fresh full term to an entry that was near expiry (the
                // "expired entries are skipped" contract).
                const uint32_t expires_in_s =
                    entry.remaining_us > 0
                        ? static_cast<uint32_t>(entry.remaining_us / 1000000)
                        : 0;
                // nlohmann builds the entry so a client-reported hostname
                // (option 12, arbitrary bytes) is JSON-escaped, never
                // spliced raw into the stream.
                const nlohmann::json row = {
                    {"mac", std::string(mac_text)},
                    {"ip", ip_text},
                    {"expires_in_s", expires_in_s},
                    {"hostname", entry.hostname}};
                if (!first) json << ",";
                first = false;
                json << row.dump();
            }
            json << "]}";
            // Atomic replace: a plain truncating write leaves a torn file
            // if the process dies mid-dump, and LoadLeases would then drop
            // every lease that was recoverable. batch82: the temp+flush+
            // publish discipline is the SAME one the config, rules and (now)
            // the v6 lease writer use - one implementation, so a device flush
            // that fails is a failure in every writer instead of being
            // silently ignored here (S2) and there (C6/C9). Every failure
            // path is observable (counted and logged).
            const std::string data = json.str();
            std::string write_error;
            if (core::AtomicWriteOutcome::kOk !=
                core::WriteFileAtomicDurable(path, data, write_error)) {
                ++persist_failures_;
                std::fprintf(stderr,
                             "[vgww] dhcp: lease dump failed: %s\n",
                             write_error.c_str());
                return false;
            }
            return true;
        }

        bool DhcpServer::LoadLeases(
            const std::string& path,
            std::chrono::steady_clock::time_point now) {
            size_t dropped = 0;
            return LoadOutcome::kRestored == LoadLeases(path, now, &dropped);
        }

        DhcpServer::LoadOutcome DhcpServer::LoadLeases(
            const std::string& path,
            std::chrono::steady_clock::time_point now,
            size_t* dropped_out) {
            if (dropped_out != nullptr) {
                *dropped_out = 0;
            }
            size_t dropped = 0;
            nlohmann::json parsed;

            // batch82: a file the loader cannot read is preserved as
            // `<path>.corrupt` instead of being silently overwritten by the
            // next dump. Otherwise a torn/garbage file destroyed every future
            // restart's mappings AND erased the only evidence of the loss.
            const auto corrupt = [&path, this]() {
                // batch206: SetAsideFile can fail (the copy is held without a
                // delete share, the path is a directory, the cross-process
                // lock is unavailable). Reporting kCorrupt and letting the
                // 60 s dump write over the file then destroyed the ONLY
                // forensic copy. Pause persistence instead, exactly like the
                // rules path does (web_api.cpp checks the same return).
                if (!core::SetAsideFile(path, ".corrupt")) {
                    persist_blocked_.store(true,
                                       std::memory_order_relaxed);
                    std::fprintf(stderr,
                                 "[vgww] dhcp: corrupt lease file could not "
                                 "be preserved; persistence paused\n");
                    return LoadOutcome::kUnreadable;
                }
                lease_file_corrupt_.store(true, std::memory_order_relaxed);
                return LoadOutcome::kCorrupt;
            };

#ifdef _WIN32
            {
                std::wstring wpath = ToWideLongPath(path);

                if (!wpath.empty())
                {
                    FILE* f = nullptr;
                    // batch85: a scanner/indexer can hold the lease file for a
                    // few milliseconds. Opening it is idempotent, so retry a
                    // bounded number of times; if it still will not open, the
                    // document is NOT corrupt (it was never read) and must not
                    // be overwritten by the next snapshot.
                    bool open_file_exists = true;
                    bool open_simulated = false;
                    unsigned long open_error = 0;
                    constexpr int kOpenAttempts = 3;

                    for (int attempt = 0;; ++attempt)
                    {
                        const unsigned long simulated =
                            core::SimulatedOpenFailure(path);
                        const DWORD attrs = ::GetFileAttributesW(wpath.c_str());
                        open_file_exists = (INVALID_FILE_ATTRIBUTES != attrs);

                        if (0 == simulated)
                        {
                            if (0 == ::_wfopen_s(&f, wpath.c_str(), L"rb") &&
                                nullptr != f)
                            {
                                break;
                            }
                            open_simulated = false;
                            open_error = static_cast<unsigned long>(
                                ::GetLastError());
                        }
                        else
                        {
                            open_simulated = true;
                            open_error = simulated;
                        }

                        if (!open_file_exists || attempt + 1 >= kOpenAttempts)
                        {
                            break;
                        }
                        ::Sleep(static_cast<DWORD>(attempt + 1));
                    }

                    if (nullptr == f &&
                        (open_file_exists || open_simulated))
                    {
                        if (open_file_exists && !open_simulated)
                        {
                            // A directory can never become readable; that is
                            // a misconfiguration, not a transient lock.
                            const DWORD attrs =
                                ::GetFileAttributesW(wpath.c_str());
                            if (INVALID_FILE_ATTRIBUTES != attrs &&
                                0 != (attrs & FILE_ATTRIBUTE_DIRECTORY))
                            {
                                return corrupt();
                            }
                        }
                        persist_blocked_.store(true,
                                               std::memory_order_relaxed);
                        std::fprintf(stderr,
                                     "[vgww] dhcp: lease file not readable (%s, "
                                     "error %lu); persistence paused so the file "
                                     "is not overwritten\n",
                                     path.c_str(), open_error);
                        return LoadOutcome::kUnreadable;
                    }

                    if (nullptr != f)
                    {
                        ::fseek(f, 0, SEEK_END);
                        long sz = ::ftell(f);
                        ::fseek(f, 0, SEEK_SET);
                        constexpr long kLeaseCap = static_cast<long>(::vgww::core::limits::kMaxLeasesBytes);
                        // batch82: ftell == -1 is an I/O failure, not an empty
                        // file; treating it as empty reported "leases restored"
                        // while discarding everything the file held.
                        if (sz < 0)
                        {
                            ::fclose(f);
                            return corrupt();
                        }
                        if (sz > kLeaseCap)
                        {
                            ::fclose(f);
                            return corrupt();
                        }
                        std::string raw;

                        if (sz > 0)
                        {
                            raw.resize(static_cast<size_t>(sz));
                            size_t got = ::fread(raw.data(), 1, raw.size(), f);
                            raw.resize(got);
                        }

                        ::fclose(f);

                        try
                        {
                            if (!raw.empty())
                            {
                                parsed = nlohmann::json::parse(raw);
                            }
                            else
                            {
                                parsed = nlohmann::json::array();
                            }
                        }
                        catch (...)
                        {
                            return corrupt();
                        }

                        goto parsed_ok;
                    }
                }
            }
#endif
            {
                std::ifstream file(path, std::ios::binary | std::ios::ate);
                if (!file) return LoadOutcome::kNoFile;
                auto sz2 = file.tellg();
                constexpr std::streamoff kLeaseCap2 = static_cast<std::streamoff>(::vgww::core::limits::kMaxLeasesBytes);
                if (sz2 < 0) return corrupt();
                if (sz2 > kLeaseCap2) return corrupt();
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
            // F4: accept the versioned object form written by DumpLeases
            // ({"version":1,"leases":[...]}) as well as the legacy bare
            // array written by older builds.
            if (parsed.is_object()) {
                const auto ver = parsed.find("version");
                if (ver == parsed.end() || !ver->is_number_integer() ||
                    ver->get<int>() != 1) {
                    return corrupt();  // schema may have changed: don't misparse
                }
                const auto it = parsed.find("leases");
                if (it == parsed.end() || !it->is_array()) return corrupt();
                parsed = *it;
            }
            if (!parsed.is_array()) return corrupt();
            std::lock_guard<std::mutex> lock(mutex_);
            // batch134: one address, one owner. Every other entry point already
            // enforces this (UpsertBinding checks config bindings, runtime
            // bindings and live leases; Acquire keys its occupancy map by
            // address), but the loader did not: a file naming the same IP for
            // two MACs produced two "active" clients on one address, and the
            // next dump wrote the duplicate straight back out. Track the
            // addresses already accepted in THIS load and drop later
            // collisions, counting them like every other refusal.
            std::unordered_set<uint32_t> claimed_ips;
            claimed_ips.reserve(parsed.size());
            for (const auto& item : parsed) {
                net::WireMac mac{};
                if (!vgww::core::ParseMac(item.value("mac", ""), mac)) { ++dropped; continue; }
                Lease lease;
                // Parse dotted quad back to network order.
                std::string text = item.value("ip", "");
                int octets = 0;
                uint32_t value = 0, net_ip = 0;
                bool valid = true;
                size_t pos = 0;
                while (pos <= text.size() && valid) {
                    const size_t dot = text.find('.', pos);
                    const std::string part = text.substr(
                        pos, (std::string::npos == dot) ? std::string::npos
                                                        : dot - pos);
                    if (part.empty() || part.size() > 3) { valid = false; break; }
                    int v = 0;
                    for (char c : part) {
                        if (c < '0' || c > '9') { valid = false; break; }
                        v = v * 10 + (c - '0');
                    }
                    if (v > 255) { valid = false; break; }
                    value = (value << 8) | static_cast<uint32_t>(v);
                    ++octets;
                    if (std::string::npos == dot) break;
                    pos = dot + 1;
                }
                if (!valid || octets != 4) { ++dropped; continue; }
                net_ip = ((value & 0xFF) << 24) | ((value & 0xFF00) << 8) |
                         ((value & 0xFF0000) >> 8) | ((value & 0xFF000000) >> 24);
                // State-consistency gate: a lease whose address no longer fits
                // the running config (the gateway itself, outside the current
                // LAN subnet, or reserved by a config static binding) and an
                // entry with no remaining time are dropped - never re-granted
                // a fresh term. Strict pool-range membership is intentionally
                // NOT checked so a legitimately persisted lease survives a
                // pool re-range (pinned by TestLeaseRoundTrip).
                // OBS-1: a version:1 file written by an older build stores
                // its leases WITHOUT expires_in_s. Treat the MISSING field
                // as a legacy entry and restore a full term from
                // config_.dhcp.lease_seconds (same origin as a fresh
                // Acquire). An explicit expires_in_s==0 is a genuinely
                // expired lease and stays dropped.
                uint32_t expires_in_s = 0;
                const auto ei = item.find("expires_in_s");
                if (ei == item.end()) {
                    expires_in_s = config_.dhcp.lease_seconds;
                } else if (ei->is_number_unsigned()) {
                    expires_in_s = ei->get<uint32_t>();
                }
                if (0 == expires_in_s || 0 == net_ip ||
                    net_ip == config_.gateway.ipv4) {
                    ++dropped;
                    continue;
                }
                if (0 != config_.gateway.mask &&
                    ((net_ip & config_.gateway.mask) !=
                     (config_.gateway.ipv4 & config_.gateway.mask))) {
                    ++dropped;
                    continue;  // outside the current LAN
                }
                bool reserved = false;
                for (const auto& b : config_.dhcp.static_bindings) {
                    if (b.ip == net_ip) {
                        reserved = true;
                        break;
                    }
                }
                if (reserved) { ++dropped; continue; }
                // batch134: a second client must not claim an address this
                // load already accepted (first occurrence wins, mirroring
                // UpsertBinding's refusal of the newcomer).
                if (!claimed_ips.insert(net_ip).second) {
                    ++dropped;
                    continue;
                }
                lease.ip = net_ip;
                lease.is_static = false;
                lease.expires = now + std::chrono::seconds(expires_in_s);
                lease.hostname = item.value("hostname", "");
                leases_[mac] = lease;
            }
            if (dropped_out != nullptr) {
                *dropped_out = dropped;
            }
            dropped_leases_.fetch_add(static_cast<uint64_t>(dropped),
                                      std::memory_order_relaxed);
            return LoadOutcome::kRestored;
        }

    }  // namespace dhcp
}  // namespace vgww
