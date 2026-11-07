#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
// ============================================================================
// web_api.cpp - REST API implementation.
// ============================================================================
#include "web/web_api.h"

#include "core/config.h"
#include "core/limits.h"
#include "core/memory.h"
#include "driver/installer.h"

#include <asio.hpp>
#include <nlohmann/json.hpp>
#ifdef _WIN32
#include <windows.h>
#include <io.h>
#endif
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <set>
#include <sstream>

namespace vgww {
    namespace web {

        namespace {
            // The single JSON string escaper lives in http_server.h
            // (web::JsonEscaped). batch121: this file used to carry a private
            // copy that DROPPED every byte below 0x20, so GET /api/console
            // served the whole captured log as one run-on line (its lines are
            // joined with '\n' before escaping) and any echoed multi-line
            // report lost its structure. Keeping one implementation is the
            // actual fix: the two copies had silently drifted apart.

            /// Bridge state vocabulary for /api/status (S3-Task4).
            const char* BridgeStateName(
                vgww::bridge::BridgeState state) noexcept {
                switch (state) {
                    case vgww::bridge::BridgeState::kRunning:
                        return "running";
                    case vgww::bridge::BridgeState::kFailed:
                        return "failed";
                    default:
                        return "stopped";
                }
            }

            std::string IpToString(uint32_t net_order) {
                // inet_addr numeric convention: first octet in the LOW byte.
                std::ostringstream out;
                out << (net_order & 0xFF) << '.' << ((net_order >> 8) & 0xFF)
                    << '.' << ((net_order >> 16) & 0xFF) << '.'
                    << ((net_order >> 24) & 0xFF);
                return out.str();
            }

            /// P8: web-ingest canonicalisation. The rule store and the data
            /// plane compare MACs case-insensitively and by parsed bytes, so
            /// mixed-case / dashed spellings all "worked" - but GET and the
            /// UI then echoed whatever the client happened to send, so one
            /// rule could render differently depending on who wrote it.
            /// Normalise once at the write boundary to core::FormatMac's
            /// canonical UPPERCASE colon form. Only values that already
            /// validate are rewritten (callers keep their 400 on failure).
            std::string CanonicalMac(const core::MacAddress& mac) {
                return core::FormatMac(mac);
            }

            /// batch141: the ONE canonical spelling for a ban's IP value.
            ///
            /// IPv4 goes through core::ParseIpv4 (strict decimal dotted quad),
            /// NOT asio's parser: asio reads a leading-zero octet as OCTAL, so
            /// "192.168.001.050" became 192.168.1.40 there while the native
            /// form reads it as 192.168.1.50 - the operator blocked an address
            /// they never named. Anything else must be a literal IPv6 address.
            ///
            /// The data plane matches IPv4 bans with an exact strcmp against
            /// the canonical dotted quad it builds per frame
            /// (dataplane.cpp:2330), so a stored spelling that differs from
            /// this form is a rule that enforces nothing.
            bool CanonicalBanIp(const std::string& text, std::string& out) {
                bool v4_ok = false;
                const uint32_t parsed = core::ParseIpv4(text, v4_ok);
                if (v4_ok) {
                    out = core::FormatIpv4(parsed);
                    return true;
                }
                std::error_code ec;
                const asio::ip::address_v6 v6 =
                    asio::ip::make_address_v6(text, ec);
                if (ec) {
                    return false;
                }
                out = v6.to_string();
                return true;
            }

            /// batch144: the IDENTITY of a ban target, independent of
            /// spelling. The data plane never compares ban text - it parses
            /// each entry once per refresh (dataplane.cpp:3343 MAC bytes,
            /// :3370 IPv6 bytes) and matches the frame's parsed value - so
            /// "AA:BB:CC:DD:EE:44", "aa-bb-cc-dd-ee-44" and "aabbccddee44"
            /// are ONE ban. Storing them as separate rows produced a list the
            /// operator cannot read (three identical-looking entries) and,
            /// worse, a broken "Unblock": deleting one row left the others
            /// enforcing, so the UI reported success while the client stayed
            /// dropped. A value that is not a legal target for its kind has no
            /// identity beyond its own text (the loader drops those anyway).
            std::string BanTargetKey(const web::BanEntry& ban) {
                if ("mac" == ban.kind) {
                    core::MacAddress mac{};
                    if (core::ParseMac(ban.value, mac)) {
                        return core::FormatMac(mac);
                    }
                } else if ("ip" == ban.kind) {
                    std::string canonical;
                    if (CanonicalBanIp(ban.value, canonical)) {
                        return canonical;
                    }
                }
                return ban.value;
            }

            /// Two entries are the SAME ban when kind and target agree.
            bool SameBanTarget(const web::BanEntry& a, const web::BanEntry& b) {
                return a.kind == b.kind && BanTargetKey(a) == BanTargetKey(b);
            }

            /// Formats a LAN client address from the data-plane primitives:
            /// v4 uses the wire bytes at [12..15], v6 the full 16-byte blob.
            std::string JsonIp(const net::IpAddress& ip) {
                if (ip.IsV4()) {
                    uint8_t wire[4];
                    ip.ToV4Wire(wire);
                    std::ostringstream out;
                    out << static_cast<unsigned>(wire[0]) << '.'
                        << static_cast<unsigned>(wire[1]) << '.'
                        << static_cast<unsigned>(wire[2]) << '.'
                        << static_cast<unsigned>(wire[3]);
                    return out.str();
                }
                asio::ip::address_v6::bytes_type v6{};
                std::copy(ip.bytes.begin(), ip.bytes.end(), v6.begin());
                return asio::ip::make_address_v6(v6).to_string();
            }

            /// batch124: RFC 8259 section 2 defines insignificant whitespace
            /// as space, TAB, LF and CR. The hand-written readers below used
            /// to skip only ' ', so any TAB or newline (i.e. essentially every
            /// pretty-printed body from a third-party client) made a present
            /// field look ABSENT - and a NUMBER with a legal trailing space
            /// before ',' or '}' was rejected because the space was folded
            /// into the token. One helper so the string and number readers
            /// cannot drift apart (batch121 same-knowledge lesson).
            inline bool IsJsonWhitespace(char c) {
                return ' ' == c || '\t' == c || '\r' == c || '\n' == c;
            }
        }  // namespace

        bool JsonGetString(const std::string& body, const char* key,
                           std::string& out) {
            const std::string needle = "\"" + std::string(key) + "\"";
            const size_t at = body.find(needle);
            if (std::string::npos == at) return false;
            size_t scan = at + needle.size(); /* skip legal JSON whitespace after the key */
            while (scan < body.size() && IsJsonWhitespace(body[scan])) ++scan;
            if (scan >= body.size() || ':' != body[scan]) return false;
            ++scan;
            while (scan < body.size() && IsJsonWhitespace(body[scan])) ++scan;
            if (scan >= body.size() || '\"' != body[scan]) return false;
            const size_t start = scan + 1;
            // Scan to the closing quote, honouring backslash escapes so a
            // value like "a\"b" does not truncate at the escaped quote.
            //
            // batch122: RFC 8259 section 7 defines \uXXXX as the universal
            // escape and \b / \f as the remaining short escapes. They used to
            // fall through the switch into `value.push_back(next)`, so a
            // client that spells non-ASCII with \u escapes (Python's
            // json.dumps defaults to ensure_ascii=True; .NET and several
            // HTTP libraries do the same) had its text silently rewritten:
            // "\u5ba2" arrived as the literal characters u5ba2. The bundled
            // UI uses JSON.stringify, which emits raw UTF-8, so only
            // third-party clients tripped over it.
            std::string value;
            size_t i = start;
            auto hex_digit = [](char c) -> int {
                if (c >= '0' && c <= '9') return c - '0';
                if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                return -1;
            };
            auto append_utf8 = [](std::string& dst, uint32_t cp) {
                if (cp <= 0x7F) {
                    dst.push_back(static_cast<char>(cp));
                } else if (cp <= 0x7FF) {
                    dst.push_back(static_cast<char>(0xC0 | (cp >> 6)));
                    dst.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
                } else if (cp <= 0xFFFF) {
                    dst.push_back(static_cast<char>(0xE0 | (cp >> 12)));
                    dst.push_back(
                        static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
                    dst.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
                } else {
                    dst.push_back(static_cast<char>(0xF0 | (cp >> 18)));
                    dst.push_back(
                        static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
                    dst.push_back(
                        static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
                    dst.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
                }
            };
            while (i < body.size()) {
                const char c = body[i];
                if ('\\' == c && i + 1 < body.size()) {
                    const char next = body[i + 1];
                    if ('u' == next) {
                        // Four hex digits must follow; a malformed escape is a
                        // rejection, never a partial value.
                        if (i + 5 >= body.size()) return false;
                        uint32_t cp = 0;
                        for (size_t k = 0; k < 4; ++k) {
                            const int digit = hex_digit(body[i + 2 + k]);
                            if (digit < 0) return false;
                            cp = (cp << 4) | static_cast<uint32_t>(digit);
                        }
                        i += 6;
                        // A high surrogate must be followed by its low
                        // surrogate; combine the pair into one code point.
                        if (cp >= 0xD800 && cp <= 0xDBFF) {
                            if (i + 5 >= body.size() || '\\' != body[i] ||
                                'u' != body[i + 1]) {
                                return false;
                            }
                            uint32_t low = 0;
                            for (size_t k = 0; k < 4; ++k) {
                                const int digit = hex_digit(body[i + 2 + k]);
                                if (digit < 0) return false;
                                low = (low << 4) | static_cast<uint32_t>(digit);
                            }
                            if (low < 0xDC00 || low > 0xDFFF) return false;
                            i += 6;
                            cp = 0x10000 + ((cp - 0xD800) << 10) +
                                 (low - 0xDC00);
                        } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
                            // An unpaired low surrogate is not a character.
                            return false;
                        }
                        append_utf8(value, cp);
                        continue;
                    }
                    switch (next) {
                        case '"': value.push_back('"'); break;
                        case '\\': value.push_back('\\'); break;
                        case '/': value.push_back('/'); break;
                        case 'n': value.push_back('\n'); break;
                        case 't': value.push_back('\t'); break;
                        case 'r': value.push_back('\r'); break;
                        case 'b': value.push_back('\b'); break;
                        case 'f': value.push_back('\f'); break;
                        // batch314: RFC 8259 section 7 allows exactly these
                        // escapes and \uXXXX. Anything else used to fall
                        // through to push_back(next), so "\q" arrived as
                        // "q" and an unescaped Windows path like "C:\temp"
                        // silently turned into a TAB - a malformed request
                        // was accepted with corrupted data instead of being
                        // refused. Reject it, never rewrite it.
                        default: return false;
                    }
                    i += 2;
                    continue;
                }
                if ('"' == c) {
                    out = std::move(value);
                    return true;
                }
                value.push_back(c);
                ++i;
            }
            return false;  // unterminated string
        }

        /// Extracts an unsigned number field (no quotes in JSON). Accepts
        /// only all-digit tokens; a sign, letter, or overflow is rejected so
        /// callers never see silently-truncated values.
        bool JsonGetNumber(const std::string& body, const char* key,
                           uint32_t& out) {
            const std::string needle = "\"" + std::string(key) + "\"";
            const size_t at = body.find(needle);
            if (std::string::npos == at) return false;
            size_t start = at + needle.size(); /* skip legal whitespace up to the colon */
            while (start < body.size() && IsJsonWhitespace(body[start])) ++start;
            if (start >= body.size() || ':' != body[start]) return false;
            ++start;
            while (start < body.size() && IsJsonWhitespace(body[start])) ++start;
            const size_t end = body.find_first_of(",}\r\n", start);
            if (std::string::npos == end || start == end) return false;
            // batch124: a legal trailing space/tab before ',' or '}' must not
            // be folded into the numeric token (the token is digits only).
            size_t stop = end;
            while (stop > start && IsJsonWhitespace(body[stop - 1])) --stop;
            if (stop == start) return false;
            unsigned long long value = 0;
            for (size_t i = start; i < stop; ++i) {
                const char c = body[i];
                if (c < '0' || c > '9') return false;
                value = value * 10 + static_cast<unsigned long long>(c - '0');
                if (value > UINT32_MAX) return false;
            }
            out = static_cast<uint32_t>(value);
            return true;
        }

        /// batch108: parse a `?index=N` list position. Both rule DELETEs used
        /// to run strtoull() and then only refuse "'\0' != *end", which is
        /// blind to the opposite failure: strtoull("") consumes NOTHING and
        /// still returns 0 with no error, so "?index=" (and "+0") deleted the
        /// FIRST rule while the caller never named an index - a 200 that
        /// denied what the request said. A leading '-' passed too, because
        /// strtoull wraps "-1" to ULLONG_MAX (an out-of-range 404, not a
        /// 400), and an overflowing digit string leaves end at '\0' with
        /// ERANGE. Same shape as batch107's "--ui-debug-port": a strto*
        /// whose endptr is only half-checked turns a malformed input into a
        /// valid one. Here the whole token must be ASCII digits and must fit.
        bool ParseListIndex(const std::string& text, size_t& out) {
            if (text.empty()) return false;
            constexpr size_t kMax = static_cast<size_t>(-1);
            size_t value = 0;
            for (const char c : text) {
                if (c < '0' || c > '9') return false;
                const size_t digit = static_cast<size_t>(c - '0');
                // Refuse before multiplying, so the accumulated value can
                // never wrap (an overflowed index would address a rule that
                // was never asked for).
                if (value > (kMax - digit) / 10) return false;
                value = value * 10 + digit;
            }
            out = value;
            return true;
        }

        bool ConstantTimeEquals(const std::string& a,
                                const std::string& b) noexcept {
            // Fold every byte difference into one accumulator, then fold the
            // length difference in too. No early exit: the loop always runs
            // max(a,b) times, so the work done does not reveal where the
            // first mismatch is.
            const size_t n = a.size() > b.size() ? a.size() : b.size();
            unsigned char diff = 0;
            for (size_t i = 0; i < n; ++i) {
                const unsigned char ca =
                    i < a.size() ? static_cast<unsigned char>(a[i]) : 0u;
                const unsigned char cb =
                    i < b.size() ? static_cast<unsigned char>(b[i]) : 0u;
                diff |= static_cast<unsigned char>(ca ^ cb);
                // A missing byte must still count as a difference even when
                // the other side happens to be 0x00.
                if (i >= a.size() || i >= b.size()) {
                    diff |= 1u;
                }
            }
            return 0 == diff && a.size() == b.size();
        }

        RuleStore& RuleStore::Instance() noexcept {
            static RuleStore store;
            return store;
        }

        uint64_t RuleStore::Rev() const noexcept {
            return rev_.load(std::memory_order_seq_cst);
        }

        size_t RuleStore::DiscardedOnLastLoad() const noexcept {
            std::lock_guard<std::mutex> lock(mutex_);
            return discarded_rules_;
        }

        void RuleStore::Clear() {
            {
                std::lock_guard<std::mutex> lock(mutex_);

                port_maps_.clear();
                port_map_snapshot_ =
                    std::make_shared<std::vector<PortMappingRule>>(
                        port_maps_);
                bans_.clear();

                ban_snapshot_ =
                    std::make_shared<std::vector<BanEntry>>(bans_);

                rate_limits_.clear();

                rate_limit_snapshot_ =
                    std::make_shared<std::vector<RateLimitRule>>(
                        rate_limits_);

                StagePersistLocked();
            }
            FlushPersist();
        }

        void RuleStore::SetPortMap(PortMappingRule rule) {
            {
                std::lock_guard<std::mutex> lock(mutex_);

                port_maps_.push_back(std::move(rule));
                port_map_snapshot_ =
                    std::make_shared<std::vector<PortMappingRule>>(
                        port_maps_);

                StagePersistLocked();
            }
            FlushPersist();
        }

        void RuleStore::AttachFile(const std::string& path) {
            std::string ignored;
            (void)AttachFileChecked(path, ignored);
        }

        bool RuleStore::AttachFileChecked(const std::string& path,
                                          std::string& error) {
            error.clear();
            std::lock_guard<std::mutex> lock(mutex_);
            persist_path_ = path;
            if (path.empty()) {
                return true;  // persistence disabled: nothing to load
            }
            const LoadOutcome outcome = LoadLockedChecked();
            if (outcome == LoadOutcome::kOk) {
                return true;
            }
            if (outcome == LoadOutcome::kMissing) {
                // First run: the file does not exist yet. Not an error, and
                // the (empty) store is the correct state.
                return true;
            }
            // batch34o: the file exists but is unreadable or violates the rule
            // contract. Report it: silently continuing would run with zero
            // rules while the operator's file still looks authoritative, and
            // the next mutation would overwrite that file for good.
            error = "rules file is corrupt or invalid: " + path;
            return false;
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

                std::wstring wpath(static_cast<size_t>(wlen), L'\0');
                ::MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, wpath.data(), wlen);
                wpath.pop_back();  // wlen included the terminator

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

        void RuleStore::StagePersistLocked() {
            const uint64_t rev =
                rev_.fetch_add(1, std::memory_order_seq_cst) + 1;
            if (persist_path_.empty()) {
                return;   // persistence disabled: nothing to stage
            }
            auto pending = std::make_shared<PersistSnapshot>(
                PersistSnapshot{rev, port_maps_, bans_, rate_limits_});
            std::shared_ptr<const PersistSnapshot> immutable =
                std::move(pending);
            std::atomic_store(&pending_snapshot_, std::move(immutable));
        }

        void RuleStore::FlushPersist() {
            std::string path;
            {
                // Read the path under mutex_ (AttachFile owns it), then do
                // all serialization + I/O with NO lock held.
                std::lock_guard<std::mutex> lock(mutex_);
                path = persist_path_;
            }
            if (path.empty()) {
                return;
            }
            // One writer at a time; a late mutator that publishes while the
            // writer runs is picked up by the loop's final reload.
            std::lock_guard<std::mutex> writer(persist_mutex_);
            for (;;) {
                auto snapshot = std::atomic_load(&pending_snapshot_);
                if (!snapshot) {
                    return;
                }
                if (persisted_rev_.load(std::memory_order_seq_cst) >=
                    snapshot->rev) {
                    return;
                }
                // batch34o D5: `persisted_rev_` means "this rev IS on disk".
                // Advancing it after a failed write would report durability
                // that does not exist: the process keeps running with the
                // rules in memory while the file is stale or missing, and the
                // loss only surfaces on the next restart. Only a successful
                // write may advance it; a failure leaves pending_snapshot_
                // untouched so the NEXT mutation's FlushPersist retries.
                if (!WriteSnapshot(path, *snapshot)) {
                    // Report the FIRST failure loudly, then stay quiet: a
                    // full disk would otherwise emit one line per mutation.
                    // The counter stays available for a UI/tooling surface.
                    const size_t failures =
                        persist_failures_.fetch_add(
                            1, std::memory_order_relaxed) +
                        1;
                    if (1 == failures) {
                        std::fprintf(stderr,
                                     "[vgww] rule file write FAILED (%s): "
                                     "changes are in memory only and will be "
                                     "lost on restart\n",
                                     path.c_str());
                    }
                    return;  // keep pending: the next flush retries
                }
                persisted_rev_.store(snapshot->rev,
                                     std::memory_order_seq_cst);
            }
        }

        size_t RuleStore::PersistFailureCount() const noexcept {
            return persist_failures_.load(std::memory_order_relaxed);
        }

        bool RuleStore::WriteSnapshot(const std::string& path,
                                      const PersistSnapshot& snapshot) {
            // Start from an object, not the default null: an empty rule set
            // must persist as "{}" - LoadLocked rejects non-object JSON
            // (is_object()), so writing "null" would leave the store
            // fake-empty after every restart with zero rules.
            nlohmann::json j = nlohmann::json::object();
            for (const auto& m : snapshot.port_maps) {
                // batch138: persist the stable identity. LoadLocked already
                // READ an ""id"" field, but this writer never emitted one, so
                // every restart re-minted ids and any id the UI was holding
                // became meaningless. Bans gain the same field.
                j["portmaps"].push_back({{"proto", m.proto},
                                         {"wan_port", m.wan_port},
                                         {"lan_ip", m.lan_ip},
                                         {"lan_port", m.lan_port},
                                         {"id", m.id}});
            }
            for (const auto& b : snapshot.bans) {
                j["bans"].push_back(
                    {{"kind", b.kind}, {"value", b.value}, {"id", b.id}});
            }
            for (const auto& r : snapshot.rate_limits) {
                j["ratelimits"].push_back(
                    {{"mac", r.mac},
                     {"uplink_kbps", r.uplink_kbps},
                     {"downlink_kbps", r.downlink_kbps}});
            }
            const std::string tmp = path + ".tmp";
            std::string data = j.dump();

#ifdef _WIN32
            {
                std::wstring wtmp = ToWideLongPath(tmp);
                std::wstring wpath = ToWideLongPath(path);

                if (!wtmp.empty() && !wpath.empty())
                {
                    FILE* f = nullptr;

                    if (0 == ::_wfopen_s(&f, wtmp.c_str(), L"wb") && nullptr != f)
                    {
                        size_t written = ::fwrite(data.data(), 1, data.size(), f);
                        ::fflush(f);
                        // Durability: fflush drains the CRT buffer only;
                        // FlushFileBuffers pushes the tmp bytes to the
                        // volume BEFORE the atomic rename publishes them.
                        const intptr_t os_handle =
                            ::_get_osfhandle(::_fileno(f));
                        if (-1 != os_handle) {
                            (void)::FlushFileBuffers(
                                reinterpret_cast<HANDLE>(os_handle));
                        }
                        int close_ok = ::fclose(f);

                        if (written == data.size() && 0 == close_ok)
                        {
                            if (::MoveFileExW(wtmp.c_str(), wpath.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
                            {
                                return true;
                            }
                        }

                        ::DeleteFileW(wtmp.c_str());
                        return false;
                    }
                }
            }
            return false;  // path conversion or open failed
#endif
            {
                std::ofstream out(tmp, std::ios::binary);
                if (!out) {
                    return false;
                }
                out << data;
                out.flush();
                if (!out) {
                    return false;
                }
            }
            std::error_code ec;
            std::filesystem::rename(tmp, path, ec);
            if (ec) {
                std::filesystem::remove(tmp, ec);
                return false;
            }
            return true;
        }

        RuleStore::LoadOutcome RuleStore::LoadLockedChecked() {
            nlohmann::json j;

#ifdef _WIN32
            {
                std::wstring wpath = ToWideLongPath(persist_path_);

                if (!wpath.empty())
                {
                    FILE* f = nullptr;

                    if (0 != ::_wfopen_s(&f, wpath.c_str(), L"rb") || nullptr == f)
                    {
                        // The file could not be opened at all: distinguish
                        // "absent" (first run, fine) from "present but
                        // unreadable" (a real failure) by asking the FS.
                        const DWORD attrs = ::GetFileAttributesW(wpath.c_str());
                        if (INVALID_FILE_ATTRIBUTES == attrs) {
                            return LoadOutcome::kMissing;
                        }
                        return LoadOutcome::kCorrupt;
                    }
                    {
                        ::fseek(f, 0, SEEK_END);
                        long sz = ::ftell(f);
                        ::fseek(f, 0, SEEK_SET);
                        constexpr long kRuleCap = static_cast<long>(::vgww::core::limits::kMaxRulesBytes);
                        if (sz > kRuleCap)
                        {
                            ::fclose(f);
                            return LoadOutcome::kCorrupt;
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
                                j = nlohmann::json::parse(raw);
                            }
                            else
                            {
                                // An EMPTY file is not a valid rule document:
                                // a crash mid-write leaves exactly this state,
                                // and treating it as "no rules" would silently
                                // drop every forward. Our own writer always
                                // emits at least "{}".
                                return LoadOutcome::kCorrupt;
                            }
                        }
                        catch (...)
                        {
                            return LoadOutcome::kCorrupt;
                        }

                        goto load_ok;
                    }
                }
                return LoadOutcome::kMissing;
            }
#endif
            {
                std::ifstream in(persist_path_, std::ios::binary | std::ios::ate);
                if (!in) {
                    return LoadOutcome::kMissing;
                }
                auto sz2 = in.tellg();
                constexpr std::streamoff kRuleCap2 = static_cast<std::streamoff>(::vgww::core::limits::kMaxRulesBytes);
                if (sz2 > kRuleCap2) return LoadOutcome::kCorrupt;
                if (sz2 <= 0) return LoadOutcome::kCorrupt;
                in.seekg(0, std::ios::beg);
                try {
                    in >> j;
                } catch (...) {
                    return LoadOutcome::kCorrupt;
                }
            }
#ifdef _WIN32
        load_ok:
#endif
            if (!j.is_object()) {
                return LoadOutcome::kCorrupt;
            }
            // Super-large guard (mirrors the API-side caps): an oversize file
            // is rejected WHOLESALE before the store is touched - a partial
            // load would leave a half-state that neither the file nor the
            // previous store describes.
            const auto array_size = [&j](const char* key) -> size_t {
                const auto it = j.find(key);
                return (it != j.end() && it->is_array()) ? it->size() : 0;
            };
            if (array_size("portmaps") > ::vgww::core::limits::kMaxPortMaps ||
                array_size("bans") > ::vgww::core::limits::kMaxBans ||
                array_size("ratelimits") >
                    ::vgww::core::limits::kMaxRateLimits) {
                return LoadOutcome::kCorrupt;
            }
            port_maps_.clear();
            bans_.clear();
            rate_limits_.clear();
            size_t discarded = 0;  // batch34o: invalid entries dropped
            if (auto it = j.find("portmaps");
                it != j.end() && it->is_array()) {
                for (const auto& e : *it) {
                    PortMappingRule m;
                    if (e.contains("proto") && e["proto"].is_string()) {
                        m.proto = e["proto"].get<std::string>();
                    }
                    // Range-gate before narrowing: a silent uint64 -> uint16
                    // truncation would turn an out-of-range port into a
                    // DIFFERENT port (70000 -> 4464). Invalid fields stay 0,
                    // and the both-ports-nonzero check below skips the rule.
                    if (e.contains("wan_port") && e["wan_port"].is_number_unsigned()) {
                        const uint64_t port = e["wan_port"].get<uint64_t>();
                        if (port >= 1 && port <= 65535) {
                            m.wan_port = static_cast<uint16_t>(port);
                        }
                    }
                    if (e.contains("lan_ip") && e["lan_ip"].is_string()) {
                        m.lan_ip = e["lan_ip"].get<std::string>();
                    }
                    if (e.contains("lan_port") && e["lan_port"].is_number_unsigned()) {
                        const uint64_t port = e["lan_port"].get<uint64_t>();
                        if (port >= 1 && port <= 65535) {
                            m.lan_port = static_cast<uint16_t>(port);
                        }
                    }
                    // batch34o: the file must satisfy the SAME contract the
                    // POST route enforces, otherwise a hand-written (or
                    // older-version) file injects rules that can never bind or
                    // dial while the UI lists them as active. A bad ENTRY is
                    // skipped (the existing contract: one poisoned rule must
                    // not discard the operator's other forwards); the count is
                    // reported so the drop is never silent.
                    if ("tcp" != m.proto) {
                        ++discarded;
                        continue;
                    }
                    bool lan_ok = false;
                    vgww::core::ParseIpv4(m.lan_ip, lan_ok);
                    if (!lan_ok) {
                        ++discarded;
                        continue;
                    }
                    if (0 == m.wan_port || 0 == m.lan_port) {
                        ++discarded;
                        continue;
                    }
                    // batch131: the POST route refuses a SECOND rule for the
                    // same WAN endpoint (:1806), but this loader used to keep
                    // it. PortMapManager keys acceptors by "proto:wan_port"
                    // (portmap_manager.cpp:215), so the later copy can never
                    // bind: the UI listed a rule that was silently dead. The
                    // file contract is "the same contract the POST route
                    // enforces", so drop the duplicate and count it.
                    bool duplicate = false;
                    for (const auto& existing : port_maps_) {
                        if (existing.proto == m.proto &&
                            existing.wan_port == m.wan_port) {
                            duplicate = true;
                            break;
                        }
                    }
                    if (duplicate) {
                        ++discarded;
                        continue;
                    }
                    // Preserve identity across restarts when the file carries
                    // one; otherwise mint a fresh id from the same counter.
                    if (e.contains("id") && e["id"].is_number_unsigned()) {
                        m.id = e["id"].get<uint64_t>();
                        if (m.id >= next_rule_id_) {
                            next_rule_id_ = m.id + 1;
                        }
                    } else {
                        m.id = next_rule_id_++;
                    }
                    port_maps_.push_back(std::move(m));
                }
            }
            if (auto it = j.find("bans"); it != j.end() && it->is_array()) {
                // batch144: collapse duplicates exactly like the port-forward
                // loader does (batch131). The API cannot create them any more
                // (AddBanChecked is idempotent), but a file written by an older
                // version can still carry two spellings of one target - and
                // that is precisely the state where "Unblock" silently fails.
                // Keyed by the shared BanTargetKey so the file and the write
                // path agree on what "the same ban" means.
                std::set<std::string> seen_bans;
                for (const auto& e : *it) {
                    BanEntry b;
                    if (e.contains("kind") && e["kind"].is_string()) {
                        b.kind = e["kind"].get<std::string>();
                    }
                    if (e.contains("value") && e["value"].is_string()) {
                        b.value = e["value"].get<std::string>();
                    }
                    // P8 deviation 1 (audit B): migrate a legacy non-canonical
                    // MAC
                    // value (dashed/lowercase) to canonical form so a later
                    // canonical POST/DELETE matches. IP bans are left as-is.
                    // batch87: an entry the data plane will refuse (unparseable
                    // MAC, non-address IP, unknown kind) must be DROPPED here,
                    // not stored as a silent no-op. POST /api/bans rejects the
                    // same values at :1646-1668; a file that skips that gate
                    // would list a ban the firewall never enforces.
                    if ("mac" == b.kind) {
                        core::MacAddress m;
                        if (!core::ParseMac(b.value, m)) {
                            ++discarded;
                            continue;
                        }
                        b.value = CanonicalMac(m);
                    } else if ("ip" == b.kind) {
                        // batch141: canonicalise exactly like the POST route.
                        // The old code only VALIDATED and kept the raw spelling,
                        // claiming "POST canonicalises on write, so re-saving
                        // converges" - but WriteSnapshot writes b.value verbatim,
                        // so it never converged. The data plane strcmp's IPv4
                        // bans against the canonical dotted quad, so a file
                        // holding "192.168.001.050" loaded fine and then blocked
                        // nothing at all.
                        std::string canonical_ip;
                        if (!CanonicalBanIp(b.value, canonical_ip)) {
                            ++discarded;
                            continue;
                        }
                        b.value = std::move(canonical_ip);
                    } else {
                        ++discarded;
                        continue;
                    }
                    if (!seen_bans
                             .insert(b.kind + '\x1f' + BanTargetKey(b))
                             .second) {
                        ++discarded;   // same target, another spelling
                        continue;
                    }
                    // batch138: preserve the persisted identity, else mint one.
                    if (e.contains("id") && e["id"].is_number_unsigned()) {
                        b.id = e["id"].get<uint64_t>();
                        if (b.id >= next_ban_id_) {
                            next_ban_id_ = b.id + 1;
                        }
                    } else {
                        b.id = next_ban_id_++;
                    }
                    bans_.push_back(std::move(b));
                }
            }
            if (auto it = j.find("ratelimits");
                it != j.end() && it->is_array()) {
                for (const auto& e : *it) {
                    RateLimitRule r;
                    if (e.contains("mac") && e["mac"].is_string()) {
                        r.mac = e["mac"].get<std::string>();
                    }
                    // P8 deviation 1 (audit B): same legacy-MAC migration as
                    // bans. batch87: a MAC the data plane cannot parse is a
                    // rule that throttles nobody (dataplane.cpp:3348 skips it),
                    // so it must be dropped and counted here instead of being
                    // echoed by GET /api/ratelimit as if it were live. POST
                    // /api/ratelimit enforces the same gate at :1724.
                    {
                        core::MacAddress m;
                        if (!core::ParseMac(r.mac, m)) {
                            ++discarded;
                            continue;
                        }
                        r.mac = CanonicalMac(m);
                    }
                    // Same narrowing guard as the ports above: values beyond
                    // uint32 range must be dropped, never wrapped. batch87: an
                    // out-of-range value now drops the WHOLE entry. Leaving the
                    // field at 0 while the other direction is valid used to keep
                    // the rule with one direction silently unlimited, whereas
                    // POST /api/ratelimit answers 400 "invalid kbps".
                    bool kbps_ok = true;
                    if (e.contains("uplink_kbps") && e["uplink_kbps"].is_number_unsigned()) {
                        const uint64_t kbps = e["uplink_kbps"].get<uint64_t>();
                        if (kbps <= UINT32_MAX) {
                            r.uplink_kbps = static_cast<uint32_t>(kbps);
                        } else {
                            kbps_ok = false;
                        }
                    }
                    if (e.contains("downlink_kbps") && e["downlink_kbps"].is_number_unsigned()) {
                        const uint64_t kbps = e["downlink_kbps"].get<uint64_t>();
                        if (kbps <= UINT32_MAX) {
                            r.downlink_kbps = static_cast<uint32_t>(kbps);
                        } else {
                            kbps_ok = false;
                        }
                    }
                    if (!kbps_ok) {
                        ++discarded;
                        continue;
                    }
                    // Mirror POST semantics: at least one direction > 0.
                    // batch87: this used to skip silently, so a rule the POST
                    // route rejects answered 400 while a file carrying the same
                    // rule loaded with no trace. Count it.
                    if (0 == r.uplink_kbps && 0 == r.downlink_kbps) {
                        ++discarded;
                        continue;
                    }
                    // batch131: SetRateLimitChecked upserts by MAC, so the
                    // write API can never hold two rules for one client. The
                    // loader appended both, and RateLimiter::Allow() takes the
                    // FIRST match (rate_limiter.cpp:95-100), so the file's
                    // later (newer) values were silently ignored while the
                    // stale cap stayed in force. Mirror the upsert and count
                    // the collapse.
                    bool upserted = false;
                    for (auto& existing : rate_limits_) {
                        if (0 ==
                            _stricmp(existing.mac.c_str(), r.mac.c_str())) {
                            existing = std::move(r);
                            ++discarded;
                            upserted = true;
                            break;
                        }
                    }
                    if (!upserted) {
                        rate_limits_.push_back(std::move(r));
                    }
                }
            }
            port_map_snapshot_ =
                std::make_shared<std::vector<PortMappingRule>>(
                    port_maps_);

            ban_snapshot_ =
                std::make_shared<std::vector<BanEntry>>(bans_);

            rate_limit_snapshot_ =
                std::make_shared<std::vector<RateLimitRule>>(
                    rate_limits_);

            rev_.fetch_add(1, std::memory_order_seq_cst);

            // batch34o: a dropped entry is a config/file mismatch the operator
            // must be able to see. The count travels out through the store so
            // the caller can log it; silence here is how a hand-edited file
            // becomes an invisible outage.
            discarded_rules_ = discarded;
            return LoadOutcome::kOk;
        }

        RuleList<PortMappingRule> RuleStore::PortMaps() const {
            std::lock_guard<std::mutex> lock(mutex_);
            return RuleList<PortMappingRule>(port_map_snapshot_);
        }

        size_t RuleStore::PortMapCount() const noexcept {
            std::lock_guard<std::mutex> lock(mutex_);
            return port_maps_.size();
        }

        bool RuleStore::AddPortMap(PortMappingRule rule) {
            return 0 != AddPortMapTracked(std::move(rule));
        }

        uint64_t RuleStore::AddPortMapTracked(PortMappingRule rule) {
            uint64_t assigned = 0;
            bool duplicate = false;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                for (const auto& existing : port_maps_) {
                    if (existing.proto == rule.proto &&
                        existing.wan_port == rule.wan_port) {
                        duplicate = true;  // U8: reject in-lock (no TOCTOU)
                        break;
                    }
                }
                // batch34o: the cap must be enforced INSIDE this lock. The API
                // used to check PortMaps().size() first and then call in, so
                // concurrent callers all observed "below cap" and all
                // inserted; a cap that can be exceeded is not a cap.
                if (!duplicate &&
                    port_maps_.size() >= ::vgww::core::limits::kMaxPortMaps) {
                    duplicate = true;  // treated as a refusal by the caller
                }
                if (!duplicate) {
                    assigned = next_rule_id_++;
                    rule.id = assigned;
                    port_maps_.push_back(std::move(rule));
                    port_map_snapshot_ =
                        std::make_shared<std::vector<PortMappingRule>>(
                            port_maps_);
                    StagePersistLocked();
                }
            }
            if (!duplicate) {
                FlushPersist();  // disk I/O OUTSIDE mutex_
            }
            return assigned;
        }

        bool RuleStore::RemovePortMapById(uint64_t id) {
            if (0 == id) {
                return false;
            }
            bool changed = false;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                for (auto it = port_maps_.begin(); it != port_maps_.end();
                     ++it) {
                    if (it->id == id) {
                        port_maps_.erase(it);
                        port_map_snapshot_ =
                            std::make_shared<std::vector<PortMappingRule>>(
                                port_maps_);
                        StagePersistLocked();
                        changed = true;
                        break;
                    }
                }
            }
            if (changed) {
                FlushPersist();
            }
            return changed;
        }

        void RuleStore::RemovePortMap(size_t index) {
            (void)RemovePortMapChecked(index);
        }

        bool RuleStore::RemovePortMapChecked(size_t index) {
            bool changed = false;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                if (index < port_maps_.size()) {
                    port_maps_.erase(port_maps_.begin() +
                                     static_cast<ptrdiff_t>(index));
                    port_map_snapshot_ =
                        std::make_shared<std::vector<PortMappingRule>>(
                            port_maps_);
                    StagePersistLocked();
                    changed = true;
                }
            }
            if (changed) {
                FlushPersist();
            }
            return changed;
        }

        RuleList<BanEntry> RuleStore::Bans() const {
            std::lock_guard<std::mutex> lock(mutex_);
            return RuleList<BanEntry>(ban_snapshot_);
        }

        size_t RuleStore::BanCount() const noexcept {
            std::lock_guard<std::mutex> lock(mutex_);
            return bans_.size();
        }

        std::shared_ptr<const std::vector<BanEntry>> RuleStore::BanSnapshot() const {
            std::lock_guard<std::mutex> lock(mutex_);
            return ban_snapshot_;
        }

        void RuleStore::AddBan(BanEntry ban) {
            (void)AddBanChecked(std::move(ban));
        }

        bool RuleStore::AddBanChecked(BanEntry ban) {
            bool inserted = false;
            {
                std::lock_guard<std::mutex> lock(mutex_);

                // batch144: the list is a SET of targets, and the check comes
                // BEFORE the cap test on purpose. A duplicate means the
                // requested state ("this target is blocked") already holds, so
                // the add reports success and changes nothing - it neither
                // adds a row nor needs cap headroom. The old code appended
                // unconditionally, so the same MAC blocked twice became two
                // rows, and unblocking one left the other dropping the client.
                // Same rule for every entry point (Web POST, native form, and
                // the loader below) because they all funnel through here.
                for (const auto& existing : bans_) {
                    if (SameBanTarget(existing, ban)) {
                        return true;   // already in force: idempotent
                    }
                }

                // batch89: the cap is enforced INSIDE the lock, for the same
                // reason AddPortMap documents at :782: an out-of-lock
                // Bans().size() check lets two concurrent writers both observe
                // "below cap" and both insert.
                if (bans_.size() < ::vgww::core::limits::kMaxBans) {
                    // batch138: assign the stable identity under this same
                    // lock, exactly like AddPortMapTracked does for rules.
                    ban.id = next_ban_id_++;
                    bans_.push_back(std::move(ban));

                    ban_snapshot_ =
                        std::make_shared<std::vector<BanEntry>>(bans_);

                    StagePersistLocked();
                    inserted = true;
                }
            }
            if (inserted) {
                FlushPersist();
            }
            return inserted;
        }

        void RuleStore::RemoveBan(size_t index) {
            (void)RemoveBanChecked(index);
        }

        bool RuleStore::RemoveBanById(uint64_t id) {
            if (0 == id) {
                return false;
            }
            bool changed = false;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                for (auto it = bans_.begin(); it != bans_.end(); ++it) {
                    if (it->id == id) {
                        bans_.erase(it);
                        ban_snapshot_ =
                            std::make_shared<std::vector<BanEntry>>(bans_);
                        StagePersistLocked();
                        changed = true;
                        break;
                    }
                }
            }
            if (changed) {
                FlushPersist();
            }
            return changed;
        }

        bool RuleStore::RemoveBanChecked(size_t index) {
            bool changed = false;
            {
                std::lock_guard<std::mutex> lock(mutex_);

                if (index < bans_.size()) {
                    bans_.erase(bans_.begin() + static_cast<ptrdiff_t>(index));

                    ban_snapshot_ =
                        std::make_shared<std::vector<BanEntry>>(bans_);

                    StagePersistLocked();
                    changed = true;
                }
            }
            if (changed) {
                FlushPersist();
            }
            return changed;
        }

        RuleList<RateLimitRule> RuleStore::RateLimits() const {
            std::lock_guard<std::mutex> lock(mutex_);
            return RuleList<RateLimitRule>(rate_limit_snapshot_);
        }

        void RuleStore::SetRateLimit(RateLimitRule rule) {
            (void)SetRateLimitChecked(std::move(rule));
        }

        bool RuleStore::SetRateLimitChecked(RateLimitRule rule) {
            bool applied = false;
            {
                std::lock_guard<std::mutex> lock(mutex_);

                bool upserted = false;
                for (auto& existing : rate_limits_) {
                    if (0 == _stricmp(existing.mac.c_str(), rule.mac.c_str())) {
                        existing = std::move(rule);  // upsert

                        rate_limit_snapshot_ =
                            std::make_shared<std::vector<RateLimitRule>>(
                                rate_limits_);

                        StagePersistLocked();
                        upserted = true;
                        applied = true;
                        break;
                    }
                }

                if (!upserted) {
                    // batch89: only a NEW mac grows the collection, so only a
                    // NEW mac can be refused by the cap. Deciding this outside
                    // the lock required callers to re-implement this scan.
                    if (rate_limits_.size() <
                        ::vgww::core::limits::kMaxRateLimits) {
                        rate_limits_.push_back(std::move(rule));

                        rate_limit_snapshot_ =
                            std::make_shared<std::vector<RateLimitRule>>(
                                rate_limits_);

                        StagePersistLocked();
                        applied = true;
                    }
                }
            }
            if (applied) {
                FlushPersist();
            }
            return applied;
        }

        bool RuleStore::ReplaceRateLimitChecked(const std::string& old_mac,
                                                RateLimitRule rule) {
            // Mirrors SetRateLimitChecked's own validity contract: at least one
            // direction must be capped, otherwise the "rule" throttles nobody.
            if (0 == rule.uplink_kbps && 0 == rule.downlink_kbps) {
                return false;
            }
            bool applied = false;
            {
                std::lock_guard<std::mutex> lock(mutex_);

                // Does the NEW mac already own a slot? If yes this is an
                // upsert and never grows the collection. If no, a free slot is
                // required - the same rule SetRateLimitChecked applies.
                bool target_exists = false;
                for (const auto& existing : rate_limits_) {
                    if (0 == _stricmp(existing.mac.c_str(), rule.mac.c_str())) {
                        target_exists = true;
                        break;
                    }
                }
                // Removing old_mac frees its slot, so a re-key at the cap is
                // allowed as long as old_mac is really present and different.
                const bool frees_a_slot =
                    !old_mac.empty() &&
                    0 != _stricmp(old_mac.c_str(), rule.mac.c_str()) &&
                    [this, &old_mac] {
                        for (const auto& existing : rate_limits_) {
                            if (0 == _stricmp(existing.mac.c_str(),
                                              old_mac.c_str())) {
                                return true;
                            }
                        }
                        return false;
                    }();

                if (!target_exists && !frees_a_slot &&
                    rate_limits_.size() >=
                        ::vgww::core::limits::kMaxRateLimits) {
                    return false;  // would overrun the cap: change NOTHING
                }

                // From here on the operation always completes: the cap was
                // checked above, so no partial write is possible.
                if (frees_a_slot) {
                    for (auto it = rate_limits_.begin();
                         it != rate_limits_.end(); ++it) {
                        if (0 == _stricmp(it->mac.c_str(), old_mac.c_str())) {
                            rate_limits_.erase(it);
                            break;
                        }
                    }
                }
                bool upserted = false;
                for (auto& existing : rate_limits_) {
                    if (0 == _stricmp(existing.mac.c_str(), rule.mac.c_str())) {
                        existing = std::move(rule);
                        upserted = true;
                        break;
                    }
                }
                if (!upserted) {
                    rate_limits_.push_back(std::move(rule));
                }
                rate_limit_snapshot_ =
                    std::make_shared<std::vector<RateLimitRule>>(rate_limits_);
                StagePersistLocked();
                applied = true;
            }
            if (applied) {
                FlushPersist();
            }
            return applied;
        }

        bool RuleStore::RemoveRateLimit(const std::string& mac) {
            bool changed = false;
            {
                std::lock_guard<std::mutex> lock(mutex_);

                for (size_t i = 0; i < rate_limits_.size(); ++i) {
                    if (0 == _stricmp(rate_limits_[i].mac.c_str(),
                                      mac.c_str())) {
                        rate_limits_.erase(rate_limits_.begin() +
                                           static_cast<ptrdiff_t>(i));

                        rate_limit_snapshot_ =
                            std::make_shared<std::vector<RateLimitRule>>(
                                rate_limits_);

                        StagePersistLocked();
                        changed = true;
                        break;
                    }
                }
            }
            if (changed) {
                FlushPersist();
            }
            return changed;
        }

        std::shared_ptr<const std::vector<RateLimitRule>>
        RuleStore::RateLimitSnapshot() const {
            std::lock_guard<std::mutex> lock(mutex_);
            return rate_limit_snapshot_;
        }

        void RegisterApiLive(HttpServer& server,
                     runtime::Dataplane& dataplane,
                     const core::Config& config,
                     const std::string& config_path,
                     std::shared_ptr<AuthTokenState> auth_token,
                     ConsoleTextProvider console_provider,
                     RepairRequester repair_requester,
                     AutostartSetter autostart_setter,
                     AuditLog audit_log,
                     ConfigApplier config_applier,
                     std::shared_ptr<ConfigApplyStatus> apply_status) {
            // Persist rules next to the config so port-maps/bans/rate-limits
            // survive process restarts.
            {
                // batch34o: a corrupt rules file must be VISIBLE at startup.
                // It used to be swallowed and the process ran with zero rules
                // while the file still looked authoritative; the first rule
                // change then overwrote it. Report it on stderr (the operator's
                // only channel before the API is up) and keep serving with the
                // rules that could be read.
                std::string rules_error;
                const std::string rules_path =
                    config_path.empty() ? std::string{}
                                        : config_path + ".rules.json";
                if (!RuleStore::Instance().AttachFileChecked(rules_path,
                                                             rules_error)) {
                    std::fprintf(stderr, "[vgww] %s\n", rules_error.c_str());
                }
                const size_t dropped =
                    RuleStore::Instance().DiscardedOnLastLoad();
                if (0 != dropped) {
                    std::fprintf(stderr,
                                 "[vgww] %zu rule(s) (port-forward, ban or "
                                 "rate-limit) in %s were invalid and were "
                                 "skipped\n",
                                 dropped, rules_path.c_str());
                }
            }
            // Token auth for mutating calls (industrial default: a router
            // must not let every LAN device rewrite its configuration). The
            // caller may pass a generated default when the config left the
            // token empty.
            //
            // batch37s (user: settings must apply immediately): the credential
            // is LIVE. A settings save can rotate/clear it while the server is
            // running, so the guard reads a thread-safe snapshot per request
            // instead of capturing the startup value.
            //
            // batch22 B4 fix: the two PRIVILEGED routes must distinguish
            // "no credential is configured" (403) from "the credential is
            // wrong" (401). The caller's generated default would make the
            // global guard answer 401 for an empty config, hiding the real
            // condition, so the guard passes those two paths through and the
            // endpoints run the full check themselves. Every other route keeps
            // exactly the previous behaviour.
            const auto is_privileged_path = [](const Request& request) {
                return request.path == "/api/repair-driver" ||
                       request.path == "/api/autostart";
            };
            if (auth_token != nullptr) {
                server.SetWriteGuard(
                    [auth_token, is_privileged_path](const Request& request)
                        -> Response {
                        Response pass = Response::Json("{\"ok\":true}");
                        pass.status = 200;
                        if (is_privileged_path(request)) {
                            // Auth is decided inside the endpoint (403/401).
                            return pass;
                        }
                        const AuthTokenSnapshot state = auth_token->Get();
                        if (state.token.empty()) {
                            return pass;  // no credential configured
                        }
                        static constexpr char kHeader[] = "x-auth-token";
                        const auto it = request.headers.find(kHeader);
                        bool ok = request.headers.end() != it &&
                                  ConstantTimeEquals(it->second, state.token);
                        if (!ok) {
                            // Also accept the standard Bearer form.
                            const auto auth =
                                request.headers.find("authorization");
                            ok = request.headers.end() != auth &&
                                 auth->second.size() == 7 + state.token.size() &&
                                 0 == auth->second.compare(0, 7, "Bearer ") &&
                                 ConstantTimeEquals(
                                     auth->second.substr(7), state.token);
                        }
                        if (!ok) {
                            return Response::Error(401, "unauthorized");
                        }
                        return pass;
                    });
            }
            server.Route("GET", "/api/status",
                         [&dataplane, &config](const Request&) {
                             const auto& stats = dataplane.GetStats();
                             std::ostringstream json;
                             json << "{\"gateway\":{\"ip\":\""
                                  << IpToString(config.gateway.ipv4)
                                  << "\",\"ipv6\":" << (config.ipv6.enabled
                                                             ? "true"
                                                             : "false")
                                  << "},\"stats\":{\"rx_frames\":"
                                  << stats.rx_frames.load()
                                  << ",\"tx_frames\":" << stats.tx_frames.load()
                                  << ",\"tcp_accepted\":"
                                  << stats.tcp_accepted.load()
                                  << ",\"arp_replies\":"
                                  << stats.arp_replies.load()
                                  << ",\"icmp_replies\":"
                                  << stats.icmp_replies.load()
                                  << ",\"mac_misses\":"
                                  << stats.mac_misses.load()
                                  << ",\"rate_limited\":"
                                  << stats.rate_limited.load()
                                  << ",\"rx_dropped\":" << stats.rx_dropped.load()
                                  << ",\"host_passthrough\":"
                                  << stats.host_passthrough.load()
                                  << ",\"rx_vlan_frames\":"
                                  << stats.rx_vlan_frames.load()
                                  << ",\"tx_vlan_frames\":"
                                  << stats.tx_vlan_frames.load()
                                  << "},\"dhcp\":{\"leases\":"
                                  << dataplane.DhcpLeaseCount()
                                  // batch152: this endpoint is the dashboard's
                                  // 2 s poll, so its body must stay O(1) in
                                  // size. The v6 lease LIST used to be embedded
                                  // here (formatted DUID + IPv6 text per lease,
                                  // bounded only by the configured pool) and no
                                  // consumer read it; it now lives on
                                  // GET /api/dhcp6/leases, beside the v4 list.
                                  // Only the counters remain.
                                  << "},\"dhcp6\":{\"leases6_count\":"
                                  << dataplane.Dhcp6LeaseCount()
                                  << ",\"bindings6_count\":"
                                  << dataplane.Dhcp6BindingCount()
                                  // batch152: "bridge" is a TOP-LEVEL member.
                                  // It had drifted inside "dhcp6", so the
                                  // WebUI's st.bridge was undefined and the whole
                                  // Bridge page rendered blank - while the test,
                                  // which used a body-wide substring find, stayed
                                  // green.
                                  << "},\"bridge\":{\"enabled\":"
                                  << (config.bridge.enabled ? "true"
                                                            : "false")
                                  << ",\"upstream\":\""
                                  << JsonEscaped(config.bridge.upstream)
                                  << "\",\"downstream\":\""
                                  << JsonEscaped(config.bridge.downstream)
                                  << "\",\"mac_count\":"
                                  << dataplane.GetBridgeMacCount()
                                  << ",\"state\":\""
                                  << BridgeStateName(
                                         dataplane.GetBridgeState())
                                  << "\"}}";
                             return Response::Json(json.str());
                         });

            server.Route("GET", "/api/clients",
                         [&dataplane](const Request&) {
                             const auto clients = dataplane.ClientRates();
                             std::ostringstream json;
                             json << "{\"clients\":[";
                             for (size_t i = 0; i < clients.size(); ++i) {
                                 if (i != 0) {
                                     json << ",";
                                 }
                                 const auto& c = clients[i];
                                 char mac[18];
                                 std::snprintf(mac, sizeof(mac),
                                               "%02X:%02X:%02X:%02X:%02X:%02X",
                                               c.mac[0], c.mac[1], c.mac[2],
                                               c.mac[3], c.mac[4], c.mac[5]);
                                 json << "{\"ip\":\"" << JsonIp(c.ip)
                                      << "\",\"mac\":\"" << mac
                                      << "\",\"up_bps\":" << c.up_bps
                                      << ",\"down_bps\":" << c.down_bps
                                      << ",\"last_seen_s\":" << c.last_seen_s
                                      << ",\"lan\":" << (c.lan ? "true"
                                                               : "false")
                                      << "}";
                             }
                             json << "]}";
                             return Response::Json(json.str());
                         });

            // batch22 B4: privileged operations. Policy:
            //   * a privileged call with NO configured token is refused with 403
            //     (never expose driver repair / startup changes to a LAN that
            //     has no credential), instead of relying on the write guard;
            //   * a wrong/missing token is 401 (handled by the global write
            //     guard installed above because auth_token is non-empty);
            //   * a repair already in flight is 409.
            // batch22 B4 fix: full auth for the privileged routes.
            //   403 = the operator never configured a token (privileged
            //         operations stay refused - we do NOT invent a credential),
            //   401 = a credential exists but the request did not carry it.
            const auto privileged_denied =
                [auth_token](const Request& request) -> std::optional<Response> {
                const AuthTokenSnapshot state =
                    auth_token != nullptr ? auth_token->Get()
                                          : AuthTokenSnapshot{};
                if (!state.configured) {
                    return Response::Error(403, "forbidden");
                }
                std::string provided;
                if (const auto it = request.headers.find("x-auth-token");
                    it != request.headers.end()) {
                    provided = it->second;
                } else if (const auto auth =
                               request.headers.find("authorization");
                           auth != request.headers.end()) {
                    const std::string& value = auth->second;
                    if (value.size() >= 7 &&
                        value.compare(0, 7, "Bearer ") == 0) {
                        provided = value.substr(7);
                    }
                }
                if (!ConstantTimeEquals(provided, state.token)) {
                    return Response::Error(401, "unauthorized");
                }
                return std::nullopt;
            };
            auto audit = [audit_log](const std::string& line) {
                if (audit_log) audit_log(line);
            };
            auto repair_pending_until =
                std::make_shared<std::atomic<std::int64_t>>(0);  // steady ms
            server.Route(
                "POST", "/api/repair-driver",
                [privileged_denied, repair_requester, repair_pending_until,
                 audit](const Request& request) {
                    if (const auto denied = privileged_denied(request)) {
                        return *denied;  // 403 no credential / 401 wrong token
                    }
                    if (!repair_requester) {
                        return Response::Error(503, "unavailable");
                    }
                    const std::int64_t now = static_cast<std::int64_t>(
                        std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::steady_clock::now().time_since_epoch())
                            .count());
                    const std::int64_t until =
                        repair_pending_until->load(std::memory_order_acquire);
                    if (until > now) {
                        return Response::Error(409, "busy");
                    }
                    // 60 s guard window: a second call while the first repair is
                    // still running (UAC prompt / driver restart) is refused.
                    repair_pending_until->store(now + 60000,
                                                std::memory_order_release);
                    if (!repair_requester()) {
                        repair_pending_until->store(0, std::memory_order_release);
                        return Response::Error(409, "busy");
                    }
                    audit("repair-driver requested");
                    return Response::Json("{\"requested\":true}");
                });
            server.Route(
                "POST", "/api/autostart",
                [privileged_denied, autostart_setter, audit](
                    const Request& request) {
                    if (const auto denied = privileged_denied(request)) {
                        return *denied;  // 403 no credential / 401 wrong token
                    }
                    if (!autostart_setter) {
                        return Response::Error(503, "unavailable");
                    }
                    const std::size_t key = request.body.find("\"enabled\"");
                    if (key == std::string::npos) {
                        return Response::Error(400, "enabled required");
                    }
                    const std::size_t colon =
                        request.body.find(':', key + 9);
                    if (colon == std::string::npos) {
                        return Response::Error(400, "enabled required");
                    }
                    std::size_t v = colon + 1;
                    while (v < request.body.size() &&
                           (request.body[v] == ' ' ||
                            request.body[v] == '\t')) {
                        ++v;
                    }
                    bool want = false;
                    if (request.body.compare(v, 4, "true") == 0) {
                        want = true;
                    } else if (request.body.compare(v, 5, "false") != 0) {
                        return Response::Error(400, "enabled must be boolean");
                    }
                    const bool actual = autostart_setter(want);
                    audit(std::string("autostart set ") + (want ? "1" : "0"));
                    std::ostringstream out;
                    out << "{\"enabled\":" << (actual ? "true" : "false") << "}";
                    return Response::Json(out.str());
                });

            // batch22 B1: read-only console ring snapshot. Two guarantees:
            //   1. token-shaped lines are filtered out (the capture ring can
            //      contain a pasted/echoed X-Auth-Token; never re-serve secrets
            //      over the LAN) - same policy as the native About page's "the
            //      token never reaches the snapshot";
            //   2. at most the last 2000 lines (bounded response).
            server.Route("GET", "/api/console",
                         [console_provider](const Request&) {
                             if (!console_provider) {
                                 return Response::Json(
                                     "{\"text\":\"\",\"count\":0,"
                                     "\"available\":false}");
                             }
                             std::string all = console_provider();
                             std::vector<std::string> kept;
                             std::size_t start = 0;
                             while (start <= all.size()) {
                                 const std::size_t nl = all.find('\n', start);
                                 const std::size_t end =
                                     (nl == std::string::npos) ? all.size()
                                                               : nl;
                                 std::string line = all.substr(start, end - start);
                                 if (!line.empty() &&
                                     line.back() == '\r') {
                                     line.pop_back();
                                 }
                                 // Case-insensitive "token" filter.
                                 std::string lower;
                                 lower.reserve(line.size());
                                 for (const char c : line) {
                                     lower.push_back(static_cast<char>(
                                         ::tolower(static_cast<unsigned char>(c))));
                                 }
                                 if (lower.find("token") == std::string::npos &&
                                     lower.find("x-auth") == std::string::npos) {
                                     kept.push_back(line);
                                 }
                                 if (nl == std::string::npos) break;
                                 start = nl + 1;
                             }
                             const std::size_t kMaxLines = 2000;
                             const std::size_t from =
                                 kept.size() > kMaxLines ? kept.size() - kMaxLines
                                                         : 0;
                             std::string text;
                             for (std::size_t i = from; i < kept.size(); ++i) {
                                 if (!text.empty()) text += "\n";
                                 text += kept[i];
                             }
                             std::ostringstream out;
                             out << "{\"text\":\"" << JsonEscaped(text)
                                 << "\",\"count\":" << (kept.size() - from)
                                 << ",\"available\":true}";
                             return Response::Json(out.str());
                         });

            // The system endpoint is registered once at boot, so a
            // steady-clock anchor taken here is the service uptime base for the
            // About page (the native one measures from controller start).
            const auto system_boot_time = std::chrono::steady_clock::now();
            server.Route("GET", "/api/system",
                         [system_boot_time, &dataplane,
                          config_path](const Request&) {
                             const auto s = dataplane.GetSystem();
                             const auto tp = dataplane.ThroughputBps();
                             std::ostringstream json;
                             json << "{\"proc\":{\"cpu_percent\":";
                             json.precision(1);
                             json << std::fixed << s.proc_cpu_percent
                                  << ",\"cores\":" << s.cpu_cores
                                  << ",\"ws_bytes\":" << s.proc_ws_bytes
                                  << ",\"virt_bytes\":" << s.proc_virt_bytes
                                  << "},\"throughput\":{\"up_bps\":"
                                  << tp.up_bps << ",\"down_bps\":"
                                  << tp.down_bps << "}";
                             // batch22 B5: the About page's identity rows.
                             // version mirrors CMake's `project(vgww VERSION
                             // 0.1.0)` (the same literal main's banner and the
                             // native About page show).
                             json << ",\"version\":\"0.1.0\"";
                             json << ",\"memory\":\""
                                  << JsonEscaped(core::MemoryBackendName()) << " "
                                  << JsonEscaped(core::MemoryBackendVersion())
                                  << "\"";
                             json << ",\"config_path\":\""
                                  << JsonEscaped(config_path) << "\"";
                             // batch43 (About parity): the native page shows
                             // uptime + driver state; the web page used to show
                             // a permanent dash for both because the API emitted
                             // neither field (comment said "no web-side source
                             // exists"). Uptime is the same steady-clock base
                             // the dashboard uses; driver state is the same
                             // NdisrdServiceRunning the UI snapshot carries.
                             const uint64_t uptime_s = static_cast<uint64_t>(
                                 std::chrono::duration_cast<std::chrono::seconds>(
                                     std::chrono::steady_clock::now() -
                                     system_boot_time)
                                     .count());
                             const bool driver_ok =
                                 vgww::driver::NdisrdServiceRunning();
                             json << ",\"uptime_s\":" << uptime_s;
                             json << ",\"driver\":\""
                                  << (driver_ok ? "running" : "stopped") << "\"";
                             json << "}";
                             return Response::Json(json.str());
                         });

            server.Route(
                "GET", "/api/config", [&config](const Request&) {
                    // THE GET SCHEMA MUST MIRROR WHAT POST ACCEPTS: the UI
                    // reads this object, tweaks fields, and POSTs the whole
                    // thing back - POST is a full replacement. Any section
                    // omitted here is silently erased on the next save (e.g.
                    // mode/dhcp/ipv6.dhcpv6/bridge used to vanish the same
                    // way web.token would drop the auth token). No secrets
                    // go out: the token is deliberately absent.
                    std::ostringstream json;
                    json << "{\"mode\":\""
                         << (core::Mode::kMain == config.mode ? "main"
                                                              : "bypass")
                         << "\",\"adapter\":\"" << JsonEscaped(config.adapter)
                         << "\",\"gateway\":{\"ipv4\":\""
                         << IpToString(config.gateway.ipv4)
                         << "\",\"mask\":\""
                         << IpToString(config.gateway.mask)
                         << "\",\"mac\":\""
                         << core::FormatMac(config.gateway.mac) << "\"}";

                    // DHCPv4: pool/dns/static bindings round-trip so a
                    // full-replacement save never erases them.
                    json << ",\"dhcp\":{\"enabled\":"
                         << (config.dhcp.enabled ? "true" : "false");
                    if (0 != config.dhcp.pool_start &&
                        0 != config.dhcp.pool_end) {
                        json << ",\"pool\":[\""
                             << IpToString(config.dhcp.pool_start)
                             << "\",\"" << IpToString(config.dhcp.pool_end)
                             << "\"]";
                    }
                    json << ",\"lease_hours\":"
                         << (config.dhcp.lease_seconds / 3600u)
                         << ",\"dns\":[";
                    for (size_t i = 0; i < config.dhcp.dns.size(); ++i) {
                        if (i != 0) json << ",";
                        json << "\"" << IpToString(config.dhcp.dns[i])
                             << "\"";
                    }
                    json << "],\"static_bindings\":[";
                    for (size_t i = 0; i < config.dhcp.static_bindings.size();
                         ++i) {
                        if (i != 0) json << ",";
                        const auto& b = config.dhcp.static_bindings[i];
                        json << "{\"mac\":\"" << core::FormatMac(b.mac)
                             << "\",\"ip\":\"" << IpToString(b.ip) << "\"";
                        if (!b.hostname.empty()) {
                            json << ",\"hostname\":\""
                                 << JsonEscaped(b.hostname) << "\"";
                        }
                        json << "}";
                    }
                    json << "]}";

                    // batch22 H1: the native-only preferences must be part of
                    // the GET schema - the UI echoes the object back on save,
                    // so omitting them made every Web save reset the app
                    // language/scale to their defaults.
                    json << ",\"ui_language\":\"" << JsonEscaped(config.ui_language)
                         << "\"";
                    json << ",\"ui_scale\":\"" << JsonEscaped(config.ui_scale)
                         << "\"";
                    // batch22 A1: native appearance (dark|light|auto).
                    json << ",\"theme\":\"" << JsonEscaped(config.theme) << "\"";

                    json << ",\"ipv6\":{\"enabled\":"
                         << (config.ipv6.enabled ? "true" : "false");
                    {
                        asio::ip::address_v6::bytes_type p{};
                        std::copy(config.ipv6.ula_prefix.begin(),
                                  config.ipv6.ula_prefix.end(), p.begin());
                        json << ",\"ula_prefix\":\""
                             << asio::ip::make_address_v6(p).to_string()
                             << "\",\"prefix_len\":"
                             << static_cast<unsigned>(config.ipv6.prefix_len)
                             << ",\"ra_lifetime_s\":"
                             << config.ipv6.ra_lifetime_s << ",\"dns\":[";
                    }
                    // RDNSS servers: emit every configured address so the
                    // settings panel round-trips them (a missing section here
                    // would be silently erased by a full-replacement save).
                    for (size_t i = 0; i < config.ipv6.dns.size(); ++i) {
                        if (i != 0) json << ",";
                        asio::ip::address_v6::bytes_type d6{};
                        std::copy(config.ipv6.dns[i].begin(),
                                  config.ipv6.dns[i].end(), d6.begin());
                        json << "\""
                             << asio::ip::make_address_v6(d6).to_string()
                             << "\"";
                    }

                    // Stateful DHCPv6 (lease in seconds, matching the file
                    // schema and the settings panel control).
                    json << "],\"dhcpv6\":{\"enabled\":"
                         << (config.ipv6.dhcpv6.enabled ? "true" : "false")
                         << ",\"pool_start\":\"";
                    {
                        asio::ip::address_v6::bytes_type p6{};
                        std::copy(config.ipv6.dhcpv6.pool_start.begin(),
                                  config.ipv6.dhcpv6.pool_start.end(),
                                  p6.begin());
                        json << asio::ip::make_address_v6(p6).to_string()
                             << "\",\"pool_end\":\"";
                        std::copy(config.ipv6.dhcpv6.pool_end.begin(),
                                  config.ipv6.dhcpv6.pool_end.end(),
                                  p6.begin());
                        json << asio::ip::make_address_v6(p6).to_string()
                             << "\",\"lease_seconds\":"
                             << config.ipv6.dhcpv6.lease_seconds;
                    }
                    json << ",\"static_bindings\":[";
                    for (size_t i = 0;
                         i < config.ipv6.dhcpv6.static_bindings.size(); ++i) {
                        if (i != 0) json << ",";
                        const auto& b =
                            config.ipv6.dhcpv6.static_bindings[i];
                        json << "{\"duid\":\"";
                        static const char* kHex = "0123456789abcdef";
                        for (const uint8_t byte : b.duid) {
                            json << kHex[byte >> 4] << kHex[byte & 0x0F];
                        }
                        json << "\",\"ip\":\"";
                        asio::ip::address_v6::bytes_type bip{};
                        std::copy(b.ip.begin(), b.ip.end(), bip.begin());
                        json << asio::ip::make_address_v6(bip).to_string()
                             << "\"";
                        if (!b.hostname.empty()) {
                            json << ",\"hostname\":\""
                                 << JsonEscaped(b.hostname) << "\"";
                        }
                        json << "}";
                    }
                    // Close static_bindings + dhcpv6, then the ipv6 object
                    // (a missing brace made the whole document unparseable:
                    // the settings panel's JSON.parse would have blanked).
                    json << "]}";
                    json << "}";

                    json << ",\"perf\":{\"workers\":"
                         << config.perf.workers
                         << ",\"rx_batch\":" << config.perf.rx_batch
                         << ",\"max_conns\":" << config.perf.max_conns
                         << ",\"udp_flow_cap\":" << config.perf.udp_flow_cap
                         << ",\"ring_capacity\":"
                         << config.perf.ring_capacity
                         << ",\"dial_timeout_ms\":"
                         << config.perf.dial_timeout_ms
                         << "},\"web\":{\"port\":" << config.web.port
                         << ",\"bind\":\"" << JsonEscaped(config.web.bind)
                         << "\"}";
                    if (config.vlan.enabled()) {
                        json << ",\"vlan\":{\"id\":"
                             << static_cast<unsigned>(config.vlan.id) << "}";
                    } else {
                        json << ",\"vlan\":{}";
                    }
                    json << ",\"bridge\":{\"enabled\":"
                         << (config.bridge.enabled ? "true" : "false")
                         << ",\"upstream\":\""
                         << JsonEscaped(config.bridge.upstream)
                         << "\",\"downstream\":\""
                         << JsonEscaped(config.bridge.downstream)
                         << "\",\"mac_table_size\":"
                         << config.bridge.mac_table_size << "}}";
                    return Response::Json(json.str());
                });

            // batch38: the Web page polls this after POST /api/config to learn
            // the async apply's true outcome instead of trusting the "applied"
            // note unconditionally (a headless/UI apply can still fail on a
            // port conflict or an adapter error; the file was saved but the
            // live switch was rolled back).
            if (apply_status) {
                server.Route(
                    "GET", "/api/config/apply-status",
                    [apply_status](const Request&) {
                        const auto st = apply_status->Get();
                        std::ostringstream json;
                        json << "{\"attempt_id\":" << st.attempt_id
                             << ",\"completed_id\":" << st.completed_id
                             << ",\"ok\":" << (st.ok ? "true" : "false")
                             << ",\"error\":\"" << JsonEscaped(st.error) << "\"}";
                        return Response::Json(json.str());
                    });
            }

            server.Route("GET", "/api/portmap", [](const Request&) {
                std::ostringstream json;
                json << "[";
                bool first = true;
                for (const auto& rule : RuleStore::Instance().PortMaps()) {
                    if (!first) json << ",";
                    first = false;
                    // batch138: expose the stable identity so both clients can delete by
                    // id instead of by position (position shifts under a
                    // concurrent add and the user loses the wrong rule).
                    json << "{\"id\":" << rule.id << ",\"proto\":\""
                         << JsonEscaped(rule.proto) << "\",\"wan_port\":"
                         << rule.wan_port << ",\"lan_ip\":\""
                         << JsonEscaped(rule.lan_ip) << "\",\"lan_port\":"
                         << rule.lan_port << "}";
                }
                json << "]";
                return Response::Json(json.str());
            });

            server.Route("POST", "/api/portmap", [](const Request& request) {
                PortMappingRule rule;
                rule.proto = "tcp";
                std::string value;
                if (JsonGetString(request.body, "proto", value)) {
                    rule.proto = value;
                }
                // The data plane only implements TCP forwarding: accepting any
                // other proto would store a rule that NEVER binds a WAN port
                // while reporting success - a plausible-but-broken fake.
                if ("tcp" != rule.proto) {
                    return Response::Error(
                        400, "only tcp port-forwarding is supported");
                }
                if (!JsonGetString(request.body, "lan_ip", value)) {
                    return Response::Error(400, "lan_ip required");
                }
                // The data plane dials host sockets via sscanf_s "%u.%u.%u.%u"
                // (portmap_manager.cpp); a non-IPv4 value would be stored as a
                // rule that can never connect - a plausible-but-broken fake.
                // Validate a strict dotted-quad here, at the API boundary.
                {
                    bool ok = false;
                    const uint32_t parsed = vgww::core::ParseIpv4(value, ok);
                    if (!ok) {
                        return Response::Error(400, "invalid ip address");
                    }
                    // batch140: store the CANONICAL spelling, exactly like the
                    // native form (portmap.cpp re-emits FormatIpv4(parsed)).
                    // ParseIpv4 accepts a leading-zero octet, so keeping the raw
                    // text made one address render as "192.168.001.050" in the
                    // web console and "192.168.1.50" in the native page (C9:
                    // one datum, one name). The data plane re-parses this text
                    // with sscanf_s when dialing, so the canonical form is what
                    // it would have resolved to anyway.
                    rule.lan_ip = vgww::core::FormatIpv4(parsed);
                }
                uint32_t number = 0;
                if (JsonGetNumber(request.body, "wan_port", number)) {
                    if (number < 1 || number > 65535) {
                        return Response::Error(400, "port out of range");
                    }
                    rule.wan_port = static_cast<uint16_t>(number);
                }
                if (JsonGetNumber(request.body, "lan_port", number)) {
                    if (number < 1 || number > 65535) {
                        return Response::Error(400, "port out of range");
                    }
                    rule.lan_port = static_cast<uint16_t>(number);
                }
                if (0 == rule.wan_port || 0 == rule.lan_port) {
                    return Response::Error(400, "ports must be non-zero");
                }
                // ApplyRules keys acceptors by "proto:wan_port": a duplicate
                // WAN endpoint would silently shadow the earlier rule. The
                // pre-check below is a fast path; AddPortMap re-checks inside
                // its lock so concurrent web + UI writers cannot both slip a
                // duplicate through (U8).
                // batch128: one snapshot reused for the duplicate scan AND the
                // cap check; both are re-verified under AddPortMap's lock.
                const auto existing_rules = RuleStore::Instance().PortMaps();
                for (const auto& existing : existing_rules) {
                    if (existing.proto == rule.proto &&
                        existing.wan_port == rule.wan_port) {
                        return Response::Error(
                            400, "wan endpoint already mapped");
                    }
                }
                // Super-large guard: token-driven cap.
                if (RuleStore::Instance().PortMapCount() >= ::vgww::core::limits::kMaxPortMaps) {
                    return Response::Error(400, "too many portmaps");
                }
                if (!RuleStore::Instance().AddPortMap(std::move(rule))) {
                    return Response::Error(400, "wan endpoint already mapped");
                }
                return Response::Json("{\"ok\":true}");
            });

            server.Route("DELETE", "/api/portmap", [](const Request& request) {
                RuleStore& store = RuleStore::Instance();
                // batch138: id is the authoritative handle. A rule's POSITION
                // shifts whenever anything is added or removed, so a client
                // that rendered the list a moment ago could delete someone
                // else's rule. GET /api/portmap now emits id; index stays
                // supported for older clients but is checked and erased under
                // one lock (batch34d).
                if (const auto by_id = request.query.find("id");
                    request.query.end() != by_id) {
                    uint64_t id = 0;
                    if (!ParseListIndex(by_id->second, id) || 0 == id) {
                        return Response::Error(400, "invalid id");
                    }
                    if (!store.RemovePortMapById(id)) {
                        return Response::Error(404, "no such id");
                    }
                    return Response::Json("{\"ok\":true}");
                }
                const auto it = request.query.find("index");
                if (request.query.end() == it) {
                    return Response::Error(400, "index or id required");
                }
                size_t index = 0;
                // batch108: see ParseListIndex - the old strtoull + "'\0' !=
                // *end" guard accepted an EMPTY value (consumed nothing, index
                // 0) and a leading '+', so "?index=" deleted the first rule.
                if (!ParseListIndex(it->second, index)) {
                    return Response::Error(400, "invalid index");
                }
                // batch34d: one lock does the range check AND the erase. The
                // old two-step (size() then remove) let a concurrent add shift
                // the indices, so this request deleted a DIFFERENT rule.
                if (!store.RemovePortMapChecked(index)) {
                    return Response::Error(404, "no such index");
                }
                return Response::Json("{\"ok\":true}");
            });

            server.Route("GET", "/api/bans", [](const Request&) {
                std::ostringstream json;
                json << "[";
                bool first = true;
                for (const auto& ban : RuleStore::Instance().Bans()) {
                    if (!first) json << ",";
                    first = false;
                    json << "{\"id\":" << ban.id << ",\"kind\":\""
                         << JsonEscaped(ban.kind) << "\",\"value\":\""
                         << JsonEscaped(ban.value) << "\"}";
                }
                json << "]";
                return Response::Json(json.str());
            });

            server.Route("POST", "/api/bans", [](const Request& request) {
                BanEntry ban;
                if (!JsonGetString(request.body, "kind", ban.kind) ||
                    !JsonGetString(request.body, "value", ban.value)) {
                    return Response::Error(400, "kind and value required");
                }
                // The data plane enforces exactly these two kinds; accepting a
                // "domain"/"dns" rule would silently no-op (fake privilege).
                if ("ip" != ban.kind && "mac" != ban.kind) {
                    return Response::Error(400, "kind must be ip or mac");
                }
                // Validate the value NOW so a malformed entry never enters the
                // store as a silent no-op rule.
                if ("ip" == ban.kind) {
                    // batch141: one canonical spelling, shared with the loader.
                    std::string canonical_ip;
                    if (!CanonicalBanIp(ban.value, canonical_ip)) {
                        return Response::Error(400, "invalid ip address");
                    }
                    ban.value = std::move(canonical_ip);
                } else {
                    core::MacAddress m;
                    if (!core::ParseMac(ban.value, m)) {
                        return Response::Error(400, "invalid mac address");
                    }
                    // P8: canonical UPPERCASE colon form (matches /api/clients
                    // and the UI) instead of the client's raw spelling.
                    ban.value = CanonicalMac(m);
                }
                // batch89: the cap check and the insert happen inside ONE lock
                // (AddBanChecked). The old route read Bans().size() out here,
                // so a concurrent UI/web writer could pass its own check and
                // overrun the cap between this read and the insert.
                if (!RuleStore::Instance().AddBanChecked(std::move(ban))) {
                    return Response::Error(400, "too many bans");
                }
                return Response::Json("{\"ok\":true}");
            });

            server.Route("DELETE", "/api/bans", [](const Request& request) {
                RuleStore& store = RuleStore::Instance();
                // batch138: same id-first contract as /api/portmap.
                if (const auto by_id = request.query.find("id");
                    request.query.end() != by_id) {
                    uint64_t id = 0;
                    if (!ParseListIndex(by_id->second, id) || 0 == id) {
                        return Response::Error(400, "invalid id");
                    }
                    if (!store.RemoveBanById(id)) {
                        return Response::Error(404, "no such id");
                    }
                    return Response::Json("{\"ok\":true}");
                }
                const auto it = request.query.find("index");
                if (request.query.end() == it) {
                    return Response::Error(400, "index or id required");
                }
                // Mirror the portmap DELETE parsing: reject trailing junk so
                // "index=abc" cannot silently resolve to 0 and delete the
                // first ban - a plausible-but-broken fake success. batch108:
                // both routes now share ParseListIndex, because the old
                // hand-rolled guard here missed the empty and signed forms for
                // exactly the reason it missed them there.
                size_t index = 0;
                if (!ParseListIndex(it->second, index)) {
                    return Response::Error(400, "invalid index");
                }
                // batch88: one lock does the range check AND the erase (same
                // fix batch34d applied to port-maps). The old two-step read
                // Bans().size() under lock #1 and then erased under lock #2, so
                // a concurrent delete could make the erase a silent no-op while
                // this route still answered {"ok":true}.
                if (!store.RemoveBanChecked(index)) {
                    return Response::Error(404, "no such index");
                }
                return Response::Json("{\"ok\":true}");
            });

            server.Route("GET", "/api/ratelimit", [](const Request&) {
                std::ostringstream json;
                json << "[";
                bool first = true;
                for (const auto& rule : RuleStore::Instance().RateLimits()) {
                    if (!first) json << ",";
                    first = false;
                    json << "{\"mac\":\"" << JsonEscaped(rule.mac)
                         << "\",\"uplink_kbps\":" << rule.uplink_kbps
                         << ",\"downlink_kbps\":" << rule.downlink_kbps << '}';
                }
                json << "]";
                return Response::Json(json.str());
            });

            server.Route("POST", "/api/ratelimit", [](const Request& request) {
                RateLimitRule rule;
                if (!JsonGetString(request.body, "mac", rule.mac)) {
                    return Response::Error(400, "mac required");
                }
                // batch139: optional ""replace_mac"". When present the rule
                // keyed by that MAC is dropped in the SAME store transaction as
                // the new one is stored. The web console used to DELETE the old
                // rule and then POST the new one; either call could fail on its
                // own (400 too many ratelimits, network drop, another tab's
                // delete), leaving the client with NO cap at all - the exact
                // half-state the native UI stopped producing in batch136.
                std::string replace_mac;
                // batch140: PRESENCE is decided syntactically, not by the
                // parser's success. JsonGetString returns false for a non-string
                // value ("replace_mac": 123) and for an empty string, which the
                // old code read as "field absent" and then silently performed a
                // PLAIN ADD: the old rule survived and a second rule for the
                // new MAC appeared. RateLimiter::Allow takes the FIRST match, so
                // the stale cap stayed in force while the UI showed the new one
                // - the batch131 failure mode through a new door. Omitting the
                // field is the only way to mean "plain add"; if it is present it
                // must be a valid MAC.
                const bool replace_present =
                    std::string::npos !=
                    request.body.find("\"replace_mac\"");
                if (replace_present &&
                    !JsonGetString(request.body, "replace_mac", replace_mac)) {
                    return Response::Error(400, "invalid replace_mac");
                }
                const bool has_replace = replace_present;
                // The data plane keys rate limits by the client MAC; storing
                // an unparseable value would silently throttle nobody - a
                // plausible-but-broken fake. Validate like /api/bans does.
                {
                    core::MacAddress m;
                    if (!core::ParseMac(rule.mac, m)) {
                        return Response::Error(400, "invalid mac address");
                    }
                    // P8: canonical UPPERCASE colon form so GET/UI echo a
                    // single spelling however the MAC was posted.
                    rule.mac = CanonicalMac(m);
                }
                uint32_t number = 0;
                // A present-but-unparseable kbps field must not silently fall
                // back to 0 (unlimited): 5000000000 -> 0 would report success
                // while throttling nobody - a plausible-but-broken fake.
                if (request.body.find("\"uplink_kbps\"") != std::string::npos) {
                    if (!JsonGetNumber(request.body, "uplink_kbps", number)) {
                        return Response::Error(400, "invalid kbps");
                    }
                    rule.uplink_kbps = number;
                }
                if (request.body.find("\"downlink_kbps\"") != std::string::npos) {
                    if (!JsonGetNumber(request.body, "downlink_kbps", number)) {
                        return Response::Error(400, "invalid kbps");
                    }
                    rule.downlink_kbps = number;
                }
                if (0 == rule.uplink_kbps && 0 == rule.downlink_kbps) {
                    return Response::Error(400, "at least one direction > 0");
                }
                if (has_replace) {
                    // Canonicalise the OLD key too: the store compares with
                    // _stricmp, but a malformed key would silently match
                    // nothing and leave the stale rule in place while this
                    // request answered success.
                    core::MacAddress old_parsed;
                    if (!core::ParseMac(replace_mac, old_parsed)) {
                        return Response::Error(400, "invalid replace_mac");
                    }
                    if (!RuleStore::Instance().ReplaceRateLimitChecked(
                            CanonicalMac(old_parsed), std::move(rule))) {
                        return Response::Error(400, "too many ratelimits");
                    }
                    return Response::Json("{\"ok\":true}");
                }
                // batch89: the upsert decision, the cap test and the insert all
                // happen inside ONE lock, so replacing an existing MAC is never
                // mistaken for growth (it does not need cap headroom) and two
                // concurrent inserters cannot both slip past the cap.
                if (!RuleStore::Instance().SetRateLimitChecked(std::move(rule))) {
                    return Response::Error(400, "too many ratelimits");
                }
                return Response::Json("{\"ok\":true}");
            });

            server.Route("DELETE", "/api/ratelimit", [](const Request& request) {
                const auto it = request.query.find("mac");
                if (request.query.end() == it) {
                    return Response::Error(400, "mac required");
                }
                // P8 regression (audit A2): POST stores the MAC in canonical
                // form, so DELETE must canonicalise the query string too - else
                // a client reusing a non-canonical spelling (case/separator)
                // would silently no-op while getting {"ok":true}. Invalid text
                // is passed through unchanged (same no-op as before).
                std::string mac = it->second;
                core::MacAddress m;
                if (core::ParseMac(mac, m)) {
                    mac = CanonicalMac(m);
                }
                // batch40 (live CRUD audit): mirror the portmap/ban DELETEs -
                // a delete that matched nothing must NOT report success (the
                // old unconditional {"ok":true} was a plausible-but-broken fake
                // and inconsistent with the other rule lists).
                if (!RuleStore::Instance().RemoveRateLimit(mac)) {
                    return Response::Error(404, "no such index");
                }
                return Response::Json("{\"ok\":true}");
            });

            // ---- DHCPv4 (S2): lease snapshot + static-binding CRUD ----
            // Every endpoint degrades safely when no DHCP server is assembled
            // (bypass / dhcp.enabled=false): the lists are empty and mutations
            // fail loudly instead of pretending to work.
            server.Route("GET", "/api/dhcp/leases",
                         [&dataplane](const Request&) {
                             const auto leases = dataplane.GetLeases();
                             std::ostringstream json;
                             json << "[";
                             bool first = true;
                             for (const auto& lease : leases) {
                                 if (!first) json << ",";
                                 first = false;
                                 json << "{\"mac\":\"" << JsonEscaped(lease.mac)
                                      << "\",\"ip\":\"" << JsonEscaped(lease.ip)
                                      << "\",\"expires_in_s\":"
                                      << lease.expires_in_s << ",\"is_static\":"
                                      << (lease.is_static ? "true" : "false")
                                      << ",\"hostname\":\""
                                      << JsonEscaped(lease.hostname) << "\"}";
                             }
                             json << "]";
                             return Response::Json(json.str());
                         });

            server.Route("GET", "/api/dhcp/bindings",
                         [&dataplane](const Request&) {
                             const auto bindings = dataplane.GetDhcpBindings();
                             std::ostringstream json;
                             json << "[";
                             bool first = true;
                             for (const auto& binding : bindings) {
                                 if (!first) json << ",";
                                 first = false;
                                 json << "{\"mac\":\"" << JsonEscaped(binding.mac)
                                      << "\",\"ip\":\"" << JsonEscaped(binding.ip)
                                      << "\",\"hostname\":\""
                                      << JsonEscaped(binding.hostname) << "\"}";
                             }
                             json << "]";
                             return Response::Json(json.str());
                         });

            server.Route("POST", "/api/dhcp/bindings",
                         [&dataplane](const Request& request) {
                             // batch41 (live CRUD audit): while the service is
                             // stopped there is no DHCP server to bind into;
                             // say "service not running" instead of the old
                             // misleading "invalid mac/ip" (the values were
                             // valid - the runtime was not there).
                             if (!dataplane.DhcpActive()) {
                                 return Response::Error(409,
                                                        "service not running");
                             }
                             std::string mac, ip, hostname;
                             if (!JsonGetString(request.body, "mac", mac) ||
                                 !JsonGetString(request.body, "ip", ip)) {
                                 return Response::Error(400, "mac and ip required");
                             }
                             JsonGetString(request.body, "hostname", hostname);
                             core::MacAddress wanted{};
                             if (!core::ParseMac(mac, wanted)) {
                                 return Response::Error(400, "invalid mac");
                             }
                             // A duplicate MAC is a conflict, not a silent
                             // upsert: retargeting an existing client is the
                             // kind of plausible-but-broken success the UI
                             // cannot tell apart from a real update.
                             const auto existing = dataplane.GetDhcpBindings();
                             for (const auto& binding : existing) {
                                 core::MacAddress bound{};
                                 if (core::ParseMac(binding.mac, bound) &&
                                     bound == wanted) {
                                     return Response::Error(400, "binding exists");
                                 }
                             }
                             // Cap the store like every other rule list so a
                             // scripted POST flood cannot grow it unbounded.
                             if (existing.size() >=
                                 ::vgww::core::limits::kMaxStaticBindings) {
                                 return Response::Error(400, "too many bindings");
                            }
                            if (!dataplane.SetDhcpBinding(mac, ip, hostname)) {
                                // batch111: the store now also rejects a
                                // hostname longer than a DHCP option value,
                                // so name it instead of blaming only mac/ip.
                                return Response::Error(
                                    400, "invalid mac/ip or hostname too long");
                            }
                            return Response::Json("{\"ok\":true}");
                        });

            server.Route("DELETE", "/api/dhcp/bindings",
                         [&dataplane](const Request& request) {
                             if (!dataplane.DhcpActive()) {
                                 return Response::Error(409,
                                                        "service not running");
                             }
                             const auto it = request.query.find("mac");
                             if (request.query.end() == it) {
                                 return Response::Error(400, "mac required");
                             }
                             if (!dataplane.RemoveDhcpBinding(it->second)) {
                                 return Response::Error(404, "binding not found");
                             }
                             return Response::Json("{\"ok\":true}");
                         });

            // batch152: the v6 lease LIST moved off /api/status (which the
            // WebUI polls every 2 s) onto its own endpoint, mirroring
            // GET /api/dhcp/leases for v4: a top-level array, empty when the
            // v6 server is not assembled.
            server.Route("GET", "/api/dhcp6/leases",
                         [&dataplane](const Request&) {
                             const auto leases = dataplane.GetLeases6();
                             std::ostringstream json;
                             json << "[";
                             bool first = true;
                             for (const auto& lease : leases) {
                                 if (!first) json << ",";
                                 first = false;
                                 json << "{\"duid\":\""
                                      << JsonEscaped(lease.duid)
                                      << "\",\"iaid\":" << lease.iaid
                                      << ",\"ip\":\""
                                      << JsonEscaped(lease.ip)
                                      << "\",\"expires_in_s\":"
                                      << lease.expires_in_s
                                      << ",\"is_static\":"
                                      << (lease.is_static ? "true" : "false")
                                      << ",\"hostname\":\""
                                      << JsonEscaped(lease.hostname)
                                      << "\"}";
                             }
                             json << "]";
                             return Response::Json(json.str());
                         });

            // ---- DHCPv6 (S2-Task8): GET /api/dhcp6/leases above serves the
            // live lease list; static bindings get the same CRUD contract as
            // v4 (DUID keyed). Every endpoint degrades safely when no v6
            // server is assembled.
            server.Route("GET", "/api/dhcp6/bindings",
                         [&dataplane](const Request&) {
                             const auto bindings = dataplane.GetDhcp6Bindings();
                             std::ostringstream json;
                             json << "[";
                             bool first = true;
                             for (const auto& binding : bindings) {
                                 if (!first) json << ",";
                                 first = false;
                                 json << "{\"duid\":\""
                                      << JsonEscaped(binding.duid)
                                      << "\",\"ip\":\"" << JsonEscaped(binding.ip)
                                      << "\",\"hostname\":\""
                                      << JsonEscaped(binding.hostname) << "\"}";
                             }
                             json << "]";
                             return Response::Json(json.str());
                         });

            server.Route("POST", "/api/dhcp6/bindings",
                         [&dataplane](const Request& request) {
                             if (!dataplane.Dhcp6Active()) {
                                 return Response::Error(409,
                                                        "service not running");
                             }
                             std::string duid, ip, hostname;
                             if (!JsonGetString(request.body, "duid", duid) ||
                                 !JsonGetString(request.body, "ip", ip)) {
                                 return Response::Error(400,
                                                        "duid and ip required");
                             }
                             JsonGetString(request.body, "hostname", hostname);
                             // batch142: compare DUIDs by VALUE. The old check
                             // compared the POSTed text with the canonical text
                             // the snapshot returns, so any other legal spelling
                             // (upper case, '-' / '.' separators, no separators)
                             // slipped past "binding exists" and the store -
                             // keyed by the parsed bytes - silently upserted,
                             // replacing the existing binding's address and
                             // hostname. The v4 sibling always parsed both
                             // sides; this is the same rule, implemented once.
                             // ParseDuidText already refuses an empty text, so
                             // its false result covers "malformed" and "empty".
                             std::vector<uint8_t> wanted_duid;
                             if (!runtime::ParseDuidText(duid, wanted_duid)) {
                                 return Response::Error(400, "invalid duid");
                             }
                             const auto existing =
                                 dataplane.GetDhcp6Bindings();
                             for (const auto& binding : existing) {
                                 std::vector<uint8_t> bound_duid;
                                 if (runtime::ParseDuidText(binding.duid,
                                                            bound_duid) &&
                                     bound_duid == wanted_duid) {
                                     return Response::Error(400,
                                                            "binding exists");
                                 }
                             }
                             if (existing.size() >=
                                 ::vgww::core::limits::kMaxStaticBindings6) {
                                 return Response::Error(400, "too many bindings");
                            }
                            if (!dataplane.SetDhcp6Binding(duid, ip, hostname)) {
                                return Response::Error(
                                    400, "invalid duid/ip or hostname too long");
                            }
                            return Response::Json("{\"ok\":true}");
                        });

            server.Route("DELETE", "/api/dhcp6/bindings",
                         [&dataplane](const Request& request) {
                             if (!dataplane.Dhcp6Active()) {
                                 return Response::Error(409,
                                                        "service not running");
                             }
                             const auto it = request.query.find("duid");
                             if (request.query.end() == it) {
                                 return Response::Error(400, "duid required");
                             }
                             if (!dataplane.RemoveDhcp6Binding(it->second)) {
                                 return Response::Error(404, "binding not found");
                             }
                             return Response::Json("{\"ok\":true}");
                         });

            server.Route("POST", "/api/config",
                         [config_path, &config, config_applier, apply_status](
                             const Request& request) {
                             // Validate the submitted JSON is a loadable
                             // config before touching the file on disk.
                             std::string error;
                            // U1: unique temp name per write, taken from the
                            // SAME process-wide sequence the UI writer
                            // (Config::SaveToFile) uses. A per-TU counter
                            // here would restart at 0 and collide with the UI
                            // writer's `<path>.tmp.<pid>.0`. The atomic
                            // replace below still publishes a complete file.
                            const std::string tmp =
                                core::Config::MakeUniqueSiblingPath(
                                    config_path);
                             // The GET schema intentionally never emits the
                             // auth token (secret boundary). A full-replacement
                             // POST therefore arrives WITHOUT it - blindly
                             // persisting the body would wipe the token and
                             // lock everyone out on the next restart. Keep the
                             // running token when the body omits/empties it.
                             std::string body = request.body;
                             {
                                 try {
                                     nlohmann::json j =
                                         nlohmann::json::parse(request.body);
                                     if (j.contains("web") &&
                                         j["web"].is_object()) {
                                         const bool has_token =
                                             j["web"].contains("token") &&
                                             j["web"]["token"].is_string() &&
                                             !j["web"]["token"]
                                                  .get<std::string>()
                                                  .empty();
                                          if (!has_token &&
                                              !config.web.token.empty()) {
                                              j["web"]["token"] =
                                                  config.web.token;
                                              body = j.dump();
                                          }
                                      }
                                      // batch22 H1: the Web UI never edits the
                                      // native-only preferences, so a body
                                      // that omits them must PRESERVE the
                                      // running values instead of resetting
                                      // them (merge semantics for the keys the
                                      // GET schema exposes but the Web form
                                      // does not own).
                                      if (!j.contains("ui_language")) {
                                          j["ui_language"] = config.ui_language;
                                          body = j.dump();
                                      }
                                      if (!j.contains("ui_scale")) {
                                          j["ui_scale"] = config.ui_scale;
                                          body = j.dump();
                                      }
                                      // batch22 A1: the native appearance is a
                                      // native-only preference (the Web page has
                                      // its own theme); preserve it when the Web
                                      // form omits it.
                                      if (!j.contains("theme")) {
                                          j["theme"] = config.theme;
                                          body = j.dump();
                                      }
                                 } catch (const std::exception&) {
                                     body = request.body;  // malformed:
                                 }
                             }
                             // batch37t (user: settings must apply
                             // immediately): after the file is atomically
                             // replaced, hand the parsed config to the entry
                             // point. It queues the save on the UI/command
                             // thread and returns true; the actual apply then
                             // stops/restarts the HTTP server from that thread
                             // (never from this worker - self-join).
                             const auto finish_save = [&]() -> Response {
                                std::string load_error;
                                const auto applied = core::Config::LoadFromFile(
                                    config_path, load_error);
                                if (config_applier && applied.has_value() &&
                                    config_applier(*applied)) {
                                    // batch38: stamp the live-apply attempt so
                                    // the page can poll its outcome.
                                    if (apply_status) {
                                        const uint64_t apply_id =
                                            apply_status->MarkAttempt();
                                        return Response::Json(
                                            "{\"ok\":true,\"note\":\"applied\","
                                            "\"apply_id\":" +
                                            std::to_string(apply_id) + "}");
                                    }
                                    return Response::Json(
                                        "{\"ok\":true,\"note\":\"applied\"}");
                                }
                                return Response::Json(
                                    "{\"ok\":true,\"note\":\"applies on restart\"}");
                            };
 #ifdef _WIN32
                              {
                                  std::wstring wtmp = ToWideLongPath(tmp);

                                  if (!wtmp.empty())
                                  {
                                      FILE* f = nullptr;

                                      if (0 != ::_wfopen_s(&f, wtmp.c_str(), L"wb") || nullptr == f)
                                      {
                                          return Response::Error(500, "cannot open config");
                                      }

                                      size_t written = ::fwrite(body.data(), 1, body.size(), f);
                                      ::fflush(f);
                                      // Same durability rule as the rule
                                      // store: flush to the volume before
                                      // the atomic replace publishes tmp.
                                      {
                                          const intptr_t os_handle =
                                              ::_get_osfhandle(::_fileno(f));
                                          if (-1 != os_handle) {
                                              (void)::FlushFileBuffers(
                                                  reinterpret_cast<HANDLE>(
                                                      os_handle));
                                          }
                                      }
                                      int close_ok = ::fclose(f);

                                      if (written != body.size() || 0 != close_ok)
                                      {
                                          ::DeleteFileW(wtmp.c_str());
                                          return Response::Error(500, "config write failed");
                                      }
                                  }
                                  else
                                  {
                                      std::ofstream out(tmp, std::ios::binary);
                                      if (!out)
                                      {
                                          return Response::Error(500, "cannot open config");
                                      }
                                      out.write(body.data(),
                                                static_cast<std::streamsize>(body.size()));
                                      if (!out)
                                      {
                                          return Response::Error(500, "config write failed");
                                      }
                                  }
                              }
 #else
                              {
                                  std::ofstream out(tmp, std::ios::binary);
                                  if (!out) {
                                      return Response::Error(500, "cannot open config");
                                  }
                                  out.write(body.data(),
                                            static_cast<std::streamsize>(
                                                body.size()));
                                  if (!out) {
                                      return Response::Error(500, "config write failed");
                                  }
                              }
 #endif
                             // Round-trip through the loader rejects malformed
                             // configs and leaves the previous file intact.
                             std::string ignore;
#ifdef _WIN32
                             {
                                 std::wstring wtmp = ToWideLongPath(tmp);
                                 bool exists = false;

                                 if (!wtmp.empty())
                                 {
                                     DWORD attr = ::GetFileAttributesW(wtmp.c_str());
                                     exists = (INVALID_FILE_ATTRIBUTES != attr);
                                 }
                                 else
                                 {
                                     exists = std::filesystem::exists(tmp);
                                 }

                                 if (!exists || !core::Config::LoadFromFile(tmp, ignore))
                                 {
                                     std::error_code ec;

                                     if (!wtmp.empty())
                                     {
                                         ::DeleteFileW(wtmp.c_str());
                                     }
                                     else
                                     {
                                         std::filesystem::remove(tmp, ec);
                                     }

                                     return Response::Error(
                                         400, "invalid configuration rejected");
                                 }
                             }
#else
                             if (!std::filesystem::exists(tmp) ||
                                 !core::Config::LoadFromFile(tmp, ignore)) {
                                 std::error_code ec;
                                 std::filesystem::remove(tmp, ec);
                                 return Response::Error(
                                     400, "invalid configuration rejected");
                             }
#endif
                             // Atomic replace; the running process keeps its
                             // in-memory config until the next restart.
#ifdef _WIN32
                              {
                                  std::wstring wtmp = ToWideLongPath(tmp);

                                  if (!wtmp.empty())
                                  {
                                  // batch80: shared publisher (bounded retry
                                  // on the destination rename) so the web
                                  // writer and Config::SaveToFile cannot
                                  // drift apart (C9).
                                  std::string publish_error;
                                  if (core::Config::PublishConfigTempFile(
                                          tmp, config_path, publish_error))
                                  {
                                      return finish_save();
                                  }

                                      return Response::Error(500, "config save failed");
                                  }
                              }
#endif
                             std::error_code ec;
                             std::filesystem::rename(tmp, config_path, ec);
                             if (ec) {
                                 std::filesystem::remove(tmp);
                                 return Response::Error(500, "config save failed");
                             }
                             return finish_save();
                         });
        }

        void RegisterApi(HttpServer& server, runtime::Dataplane& dataplane,
                         const core::Config& config,
                         const std::string& config_path,
                         std::string auth_token,
                         ConsoleTextProvider console_provider,
                         RepairRequester repair_requester,
                         AutostartSetter autostart_setter,
                         AuditLog audit_log,
                         ConfigApplier config_applier,
                         std::shared_ptr<ConfigApplyStatus> apply_status) {
            // Fixed-token compatibility overload: freeze the same effective
            // credential and configured bit the old implementation used.
            auto state = std::make_shared<AuthTokenState>();
            const std::string effective =
                auth_token.empty() ? config.web.token : auth_token;
            state->Set(effective, !config.web.token.empty());
            RegisterApiLive(server, dataplane, config, config_path,
                            std::move(state), std::move(console_provider),
                            std::move(repair_requester),
                            std::move(autostart_setter),
                            std::move(audit_log),
                            std::move(config_applier),
                            std::move(apply_status));
        }

    }  // namespace web
}  // namespace vgww
