// ============================================================================
// web_api.h - REST API surface for the embedded WebUI.
//
// Wires the HTTP server to live gateway state:
//   GET  /api/status  -> gateway info, counters
//   GET  /api/config  -> sanitized runtime configuration
//   GET  /api/portmap -> port-forwarding rules      POST/DELETE mutate
//   GET  /api/bans    -> MAC/IP blocklist           POST/DELETE mutate
//
// Port-map and ban rules are held in a thread-safe RuleStore; enforcement
// hooks into the data plane at the classifier (bans) and listener (maps).
// ============================================================================
#pragma once

#include "runtime/dataplane.h"
#include "web/http_server.h"

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace vgww {
    namespace web {

        /// One port-forwarding rule (host port -> LAN client).
        struct PortMappingRule {
            std::string proto;       ///< "tcp" | "udp"
            uint16_t wan_port = 0;
            std::string lan_ip;
            uint16_t lan_port = 0;
            /// batch34o: stable identity assigned on insert (0 = not yet
            /// stored). Removal by id survives index shifts caused by other
            /// adds/removes; the trailing position keeps the existing
            /// aggregate initialisers valid.
            uint64_t id = 0;
        };

        /// One firewall block entry.
        struct BanEntry {
            std::string kind;   ///< "mac" | "ip"
            std::string value;
            /// batch138: stable identity assigned on insert (0 = not yet
            /// stored). Bans used to be deleted by POSITION, so any add between
            /// the snapshot the UI rendered and the delete that reaches the
            /// store redirected the removal onto a DIFFERENT ban. The trailing
            /// position keeps the existing aggregate initialisers valid.
            uint64_t id = 0;
        };

        /// One per-client rate limit rule. kbps 0 = no cap for that direction.
        struct RateLimitRule {
            std::string mac;  ///< client MAC "AA:BB:CC:DD:EE:FF"
            uint32_t uplink_kbps = 0;
            uint32_t downlink_kbps = 0;
            /// P82: stable identity assigned on insert (0 = not yet stored).
            /// Rate limits are deleted by MAC, but the identity is what the
            /// cross-process merge and the tombstone set key on; the trailing
            /// position keeps the existing aggregate initialisers valid.
            uint64_t id = 0;
        };

        /// P82: the tombstone ceiling. A rule document carries every deletion
        /// since the last compaction; past this bound the writer refuses new
        /// deletions (the loader rejects a longer list as corrupt, so exceeding
        /// it would brick the file on the next restart).
        constexpr size_t kMaxTombstones = 8192;

        /// P82: a parsed rule document - pure data, no singleton state. The
        /// load and merge helpers operate on this so their behaviour is
        /// testable without a RuleStore instance.
        struct RuleDocument {
            std::vector<PortMappingRule> port_maps;
            std::vector<BanEntry> bans;
            std::vector<RateLimitRule> rate_limits;
            /// Deleted rule ids (membership; the merge keys on this).
            std::set<uint64_t> tombstones;
            /// The same ids in the order they were deleted - the document's
            /// "removed" array is written in this order.
            std::vector<uint64_t> tombstone_order;
            /// Entries the parser dropped (invalid, duplicate identity or
            /// duplicate id). Tombstoned entries are NOT counted here.
            size_t discarded = 0;
        };

        /// batch129: a zero-copy, read-only VIEW over an immutable snapshot.
        ///
        /// The rule getters used to return `std::vector<T>` BY VALUE, so every
        /// reader (1 Hz rule reconciliation, each POST pre-check, each UI tick,
        /// each GET) paid a full deep copy - strings included. Returning
        /// `const std::vector<T>&` is NOT an option: the store mutates the
        /// vector under its mutex from other threads, so a reference would be
        /// a data race (rule 17: single authoritative writer + no cross-thread
        /// visibility assumptions).
        ///
        /// This view holds a `shared_ptr` to a CONST snapshot that writers
        /// replace wholesale (never mutate), so copying the view is one
        /// refcount bump and the elements can be read after the lock is
        /// dropped. It exposes the subset of the vector API the callers use,
        /// which keeps those call sites unchanged.
        template <typename T>
        class RuleList final {
        public:
            RuleList() : data_(std::make_shared<std::vector<T>>()) {}
            explicit RuleList(std::shared_ptr<std::vector<T>> data)
                : data_(std::move(data)) {}
            /// Take ownership of a plain vector (one move, no element copy).
            explicit RuleList(std::vector<T> data)
                : data_(std::make_shared<std::vector<T>>(std::move(data))) {}

            using const_iterator = typename std::vector<T>::const_iterator;
            const_iterator begin() const noexcept { return data_->begin(); }
            const_iterator end() const noexcept { return data_->end(); }
            std::size_t size() const noexcept { return data_->size(); }
            bool empty() const noexcept { return data_->empty(); }
            const T& operator[](std::size_t i) const { return (*data_)[i]; }
            const T& front() const { return data_->front(); }
            const T& back() const { return data_->back(); }

            /// Copy-on-write builders. These NEVER mutate a buffer that has
            /// already been published: the shared payload is cloned first, so
            /// concurrent readers of an older snapshot keep seeing it intact.
            /// Production code only reads these lists; the builders exist for
            /// snapshot assembly (UI tests and one-shot fixture setup).
            void push_back(const T& value) { Detach().push_back(value); }
            void push_back(T&& value) { Detach().push_back(std::move(value)); }
            void clear() { data_ = std::make_shared<std::vector<T>>(); }

        private:
            /// Replace the shared payload with a mutable copy we own, then
            /// hand back the mutable vector for the caller's single edit.
            /// The buffer is created non-const and is only reachable through
            /// the const accessors above, so mutating it here is well-defined
            /// (unlike const_cast on a genuinely const object).
            std::vector<T>& Detach() {
                if (data_.use_count() != 1) {
                    data_ = std::make_shared<std::vector<T>>(*data_);
                }
                return *data_;
            }

            std::shared_ptr<std::vector<T>> data_;
        };

        /// Thread-safe mutable rule store shared by the API and (later) the
        /// enforcement points.
        class RuleStore final {
        public:
            static RuleStore& Instance() noexcept;

            /// Associates a persistence file (loaded once) and reloads it.
            /// Rules survive process restarts; every later mutation rewrites
            /// the file atomically.
            void AttachFile(const std::string& path);

            /// batch34o: same as AttachFile but REPORTS the outcome. A missing
            /// file is success (first run); a file that exists but cannot be
            /// parsed or violates the rule contract is a failure with a
            /// non-empty `error`. Callers must surface it instead of behaving
            /// as if the operator had no rules.
            bool AttachFileChecked(const std::string& path, std::string& error);

            /// batch34o: how many persisted entries the last load dropped
            /// because they violated the rule contract. Non-zero means the
            /// file and the running rule set disagree.
            size_t DiscardedOnLastLoad() const noexcept;

            /// batch34o D5: how many rule-file writes FAILED so far. A failed
            /// write does not advance the persisted revision, so the next
            /// mutation retries - but the operator must be able to see that
            /// durability is broken (disk full, permission changed, path
            /// removed) instead of discovering it after a restart.
            size_t PersistFailureCount() const noexcept;

            /// batch86: true while rule persistence is paused because the
            /// file could not be read at attach time (it may be valid but
            /// briefly locked). The status surface reports it so "why did my
            /// change not survive a restart" has a visible cause.
            bool PersistBlocked() const noexcept;

            /// batch91: successful blocked->writable recoveries (exactly one
            /// per blockage, including the corrupt-file preservation path).
            size_t RecoveryCount() const noexcept;

            /// batch92: true when every staged rule revision is on disk (also
            /// true when persistence is disabled). Mutation responses report it
            /// so a caller can tell "applied in memory but not saved" apart
            /// from a durable success.
            bool PersistUpToDate() const noexcept;
            uint64_t Rev() const noexcept;
            // For monotonic anchor (B6): seq_cst load/store ensures
            // Binding::Poll never misses a bump across threads.

            void Clear();

            void SetPortMap(PortMappingRule rule);

            /// batch129: ZERO-COPY read access. Returns the immutable snapshot
            /// (one shared_ptr copy, no per-element deep copy, no string copy).
            /// Safe to keep after the lock: the buffer is shared and const, so
            /// concurrent writers publish a NEW snapshot instead of mutating
            /// this one. Same contract as BanSnapshot()/RateLimitSnapshot().
            RuleList<PortMappingRule> PortMaps() const;
            /// batch128: O(1) size of PortMaps(), under the same lock. The
            /// write paths need only the count for the cap pre-check; calling
            /// PortMaps().size() copied the whole vector (strings included),
            /// and they did it twice per request.
            size_t PortMapCount() const noexcept;
            /// Adds a port map. Returns false when a rule with the same
            /// "proto:wan_port" already exists (checked inside the lock, so
            /// concurrent web + UI writers cannot both slip past - U8).
            bool AddPortMap(PortMappingRule rule);
            /// batch34o: same as AddPortMap but returns a stable identity
            /// (0 on rejection). Rule identity is what callers must use for
            /// removal: positional indices shift whenever any rule is added
            /// or removed, so an index captured earlier can name a DIFFERENT
            /// rule later.
            uint64_t AddPortMapTracked(PortMappingRule rule);
            /// batch34o: removes by identity. Returns false when the id is
            /// unknown (already removed, or never existed) - never removes a
            /// different rule.
            bool RemovePortMapById(uint64_t id);
            /// P82: same removal with an explicit refusal channel. `refused`
            /// is set when the removal was NOT performed because the tombstone
            /// store is full (the caller must answer 500, not 404); it is
            /// always false when the return value is true.
            bool RemovePortMapById(uint64_t id, bool& refused);
            void RemovePortMap(size_t index);
            /// batch34d: check-and-erase under ONE lock. The API used to call
            /// PortMaps().size() (lock #1) and then RemovePortMap(index)
            /// (lock #2); a concurrent add between them shifted the indices and
            /// the user deleted a DIFFERENT rule than the one they clicked.
            /// Returns false when the index is out of range.
            bool RemovePortMapChecked(size_t index);
            /// P82: same, with the refusal channel (see RemovePortMapById).
            bool RemovePortMapChecked(size_t index, bool& refused);

            /// batch129: zero-copy immutable snapshot (see PortMaps()).
            RuleList<BanEntry> Bans() const;
            /// batch128: O(1) size of Bans(), same lock, no copy.
            size_t BanCount() const noexcept;
            void AddBan(BanEntry ban);
            /// batch89: cap + insert under ONE lock, mirroring AddPortMap.
            /// Returns false when the collection is at kMaxBans (nothing is
            /// inserted). AddBan is void, which forced every caller to check
            /// Bans().size() under a DIFFERENT lock - two writers could both
            /// see "below cap" and both insert.
            bool AddBanChecked(BanEntry ban);
            void RemoveBan(size_t index);
            /// batch138: removes by stable identity (never by position).
            /// Returns false when the id is unknown - a stale or already
            /// removed row can never delete a different ban.
            bool RemoveBanById(uint64_t id);
            /// P82: same removal with the refusal channel (tombstone full).
            bool RemoveBanById(uint64_t id, bool& refused);
            /// batch88: same contract as RemovePortMapChecked - the range check
            /// and the erase happen under ONE lock, and the returned bool is the
            /// truth about the mutation. RemoveBan's void return forced callers
            /// to pre-check the size under a DIFFERENT lock, so the answer could
            /// describe a vector that no longer existed by erase time.
            /// Returns false when the index is out of range (nothing removed).
            bool RemoveBanChecked(size_t index);
            /// P82: same, with the refusal channel (tombstone full).
            bool RemoveBanChecked(size_t index, bool& refused);

            /// Immutable snapshot for lock-free enforcement reads (RCU-style:
            /// the data plane polls this periodically, one atomic load).
            std::shared_ptr<const std::vector<BanEntry>> BanSnapshot() const;

            /// batch129: zero-copy immutable snapshot (see PortMaps()).
            RuleList<RateLimitRule> RateLimits() const;
            void SetRateLimit(RateLimitRule rule);   ///< upsert by MAC
            /// batch89: upsert decision, cap test and insert under ONE lock.
            /// Returns false when `rule.mac` is NEW and the collection is at
            /// kMaxRateLimits; replacing an existing MAC always succeeds
            /// because it does not grow the collection. The old out-of-lock
            /// pre-check had to re-implement the upsert scan by hand, so a
            /// client REPLACING a rule could be told "too many ratelimits".
            bool SetRateLimitChecked(RateLimitRule rule);
            /// P82: removes the rule keyed by `mac`. `refused` is set when the
            /// removal was NOT performed because the tombstone store is full.
            bool RemoveRateLimit(const std::string& mac);
            /// P82: same removal with the refusal channel (tombstone full).
            bool RemoveRateLimit(const std::string& mac, bool& refused);

            /// batch34o: the outcomes a load can have. `kMissing` is the
            /// first-run case and is NOT an error; `kCorrupt` means the file
            /// exists but cannot be trusted and must be reported; batch85
            /// `kUnreadable` means it exists but could not even be OPENED
            /// (transient lock/permission) - nothing was parsed, so it must
            /// neither be preserved-aside nor overwritten.
            enum class LoadOutcome { kOk, kMissing, kCorrupt, kUnreadable };

            /// P82: parses the rule document at `path` WITHOUT touching any
            /// singleton state. Entries whose id is in the document's tombstone
            /// list are skipped (and NOT counted in `discarded`); entries with
            /// no id keep id 0 (the caller mints one); a "removed" list longer
            /// than kMaxTombstones makes the whole document kCorrupt.
            static LoadOutcome ReadRuleDocument(const std::string& path,
                                                RuleDocument& doc);

            /// P82: merges `disk` into `memory` IN PLACE under the tombstone
            /// union. Memory entries win over disk entries with the same id or
            /// the same identity (proto+wan_port / BanTargetKey / MAC); a disk
            /// entry whose id is tombstoned is skipped; a disk-only entry with
            /// id 0 is minted through `mint_id`; entries beyond the per-kind
            /// cap are dropped. Returns the number of dropped disk entries.
            /// `memory.tombstones`/`tombstone_order` become the union.
            static size_t MergeRuleDocuments(
                RuleDocument& memory, const RuleDocument& disk,
                const std::function<uint64_t()>& mint_id);

            /// P82 test seam: forces the process id salt (and resets the
            /// shared counter) so id minting is deterministic. Zero is bumped
            /// to 1 (the salt must be non-zero).
            void SetRuleIdSaltForTest(uint64_t salt);

            /// batch136: replaces the rule keyed by `old_mac` with `rule` in a
            /// SINGLE critical section - all-or-nothing.
            ///
            /// Editing a rule's MAC is "remove the old, insert the new". Done
            /// as two calls (which is what the UI used to post) each half can
            /// fail on its own: the command queue refuses one of the two when
            /// full (Post returns false - only a "busy" toast), and
            /// SetRateLimitChecked refuses a new MAC at kMaxRateLimits. Either
            /// failure leaves the client with its old cap deleted and no new
            /// one stored - a silent loss of policy.
            ///
            /// `old_mac` empty means "plain insert/upsert". Returns false and
            /// changes NOTHING when `rule.mac` is new and the collection is at
            /// the cap, or when the new rule is invalid (both kbps zero).
            bool ReplaceRateLimitChecked(const std::string& old_mac,
                                         RateLimitRule rule);

            /// Immutable snapshot for lock-free rate-limit reads.
            std::shared_ptr<const std::vector<RateLimitRule>> RateLimitSnapshot() const;

        private:
            RuleStore() = default;

            /// Immutable copy of the rule vectors captured while holding
            /// mutex_. Serialization and disk I/O happen OUTSIDE mutex_ so
            /// the control plane (100 ms poll) is never blocked on a disk.
            struct PersistSnapshot final {
                uint64_t rev = 0;
                std::vector<PortMappingRule> port_maps;
                std::vector<BanEntry> bans;
                std::vector<RateLimitRule> rate_limits;
                /// P82: the tombstone set at stage time (insertion order), so
                /// the writer can emit "removed" without taking mutex_ again.
                std::vector<uint64_t> tombstones;
                /// P82: publish this snapshot as-is, WITHOUT adopting the
                /// on-disk rules. Clear() sets it: a deliberate wipe must not
                /// be undone by re-importing the document it is about to
                /// replace.
                bool direct = false;
            };

            mutable std::mutex mutex_;
            std::vector<PortMappingRule> port_maps_;
            /// batch129: immutable snapshot of port_maps_, published on every
            /// mutation under mutex_. PortMaps() used to return a COPY of the
            /// vector (strings included), so every reader - the 1 Hz rule
            /// reconciliation, each POST pre-check, each UI tick and every
            /// /api/portmap GET - paid a full deep copy. Returning a shared
            /// immutable snapshot is zero-copy, thread-safe (readers keep the
            /// buffer alive after the lock is dropped) and matches the
            /// established BanSnapshot()/RateLimitSnapshot() pattern.
            std::shared_ptr<std::vector<PortMappingRule>> port_map_snapshot_ =
                std::make_shared<std::vector<PortMappingRule>>();
            std::vector<BanEntry> bans_;
            std::shared_ptr<std::vector<BanEntry>> ban_snapshot_ =
                std::make_shared<std::vector<BanEntry>>();
            std::vector<RateLimitRule> rate_limits_;
            std::shared_ptr<std::vector<RateLimitRule>> rate_limit_snapshot_ =
                std::make_shared<std::vector<RateLimitRule>>();
            std::atomic<uint64_t> rev_{0};

            std::string persist_path_;  ///< "" = persistence disabled
            /// Serializes writers: one thread dumps/writes a snapshot at a
            /// time; later mutators publish their state through
            /// pending_snapshot_ and leave after the writer flushed it.
            std::mutex persist_mutex_;
            std::shared_ptr<const PersistSnapshot> pending_snapshot_;
            std::atomic<uint64_t> persisted_rev_{0};

            void StagePersistLocked(bool direct = false);  ///< caller holds mutex_
            void FlushPersist();        ///< caller holds NO lock
            /// batch34o D5: returns false when the file could not be written.
            /// The caller must NOT advance the persisted revision in that case.
            bool WriteSnapshot(const std::string& path,
                               const PersistSnapshot& snapshot);
            LoadOutcome LoadLockedChecked();  ///< caller holds mutex_
            /// P82: takes over a parsed document: mints ids for id-0 entries,
            /// registers every id in used_ids_, installs the vectors and the
            /// tombstone set, bumps rev_ and publishes the snapshots. Caller
            /// holds mutex_.
            void AdoptDocumentLocked(RuleDocument& doc);
            /// P82: records a deletion. Returns false (and changes nothing)
            /// when the tombstone ceiling is reached - the caller then refuses
            /// the removal instead of dropping it without a trace. Caller holds
            /// mutex_.
            bool AddTombstoneLocked(uint64_t id);
            /// P82: mints a process-unique rule id. Layout:
            ///   bit 63     = marker (new ids are >= 2^63; legacy ids are not)
            ///   bits 62..32 = salt32 (CSPRNG ^ pid, non-zero)
            ///   bits 31..0  = counter31 (shared by all three rule kinds)
            /// Caller holds mutex_.
            uint64_t MintRuleIdLocked();
            /// P82: generates the process salt once (CsprngBytes ^ pid, non-zero).
            void EnsureSaltLocked();
            /// batch85: true while persistence must not touch the file because
            /// it could not be read at attach time (guarded by mutex_).
            bool persist_blocked_ = false;
            /// batch87: while blocked, a flush first retries the load; a
            /// document that is readable again is merged with the changes the
            /// operator made while persistence was paused (deduplicated by
            /// the same identities the loaders use), the block is cleared and
            /// the flush proceeds. Returns false when the file is still not
            /// readable (the block stays). Caller holds mutex_.
            bool RecoverBlockedLocked(bool& corrupt_detected);
            /// P82: process-unique id salt (0 = not generated yet).
            uint64_t id_salt_ = 0;
            /// P82: shared monotonic counter (starts at 1).
            uint32_t id_counter_ = 1;
            /// P82: every id this process minted or loaded - the collision
            /// guard for minting.
            std::set<uint64_t> used_ids_;
            /// P82: deleted rule ids (guarded by mutex_).
            std::set<uint64_t> tombstones_;
            /// P82: the same ids in deletion order (the document's "removed").
            std::vector<uint64_t> tombstone_order_;
            /// batch34o: entries dropped by the last load (see accessor).
            size_t discarded_rules_ = 0;
            /// batch34o D5: count of failed rule-file writes.
            std::atomic<size_t> persist_failures_{0};
            /// batch91: see RecoveryCount().
            std::atomic<size_t> recovery_count_{0};
        };

        /// Registers all /api/* routes on `server`. `config_path` is the JSON
        /// file path the process loaded (used by POST /api/config to persist).
        /// batch22 B1: `console_provider` supplies the console ring text for the
        /// read-only GET /api/console. It is a callback because the ring lives
        /// in the UI layer (vgww_ui) while this API is in vgww_core - core must
        /// not depend on ui. Empty provider = the endpoint reports unavailable.
        using ConsoleTextProvider = std::function<std::string()>;

        /// batch37s: live write-auth credential. The settings save may replace
        /// the token while the server is running; the write guard reads this
        /// snapshot per request instead of capturing a stale copy at startup.
        struct AuthTokenSnapshot {
            std::string token;
            bool configured = false;
        };
        class AuthTokenState final {
        public:
            void Set(std::string token, bool configured) {
                std::lock_guard<std::mutex> lock(mutex_);
                token_ = std::move(token);
                configured_ = configured;
            }
            AuthTokenSnapshot Get() const {
                std::lock_guard<std::mutex> lock(mutex_);
                return AuthTokenSnapshot{token_, configured_};
            }
        private:
            mutable std::mutex mutex_;
            std::string token_;
            bool configured_ = false;
        };
        /// batch38: single-writer store of the most recent config-apply
        /// outcome. POST /api/config assigns a monotonic attempt id and
        /// returns it; whoever actually runs the apply (UI command worker or a
        /// headless worker) records the outcome; the Web page polls
        /// GET /api/config/apply-status until completed_id catches up with its
        /// attempt id. The store survives Web server restarts because it lives
        /// in main and its shared_ptr is handed to every listener incarnation.
        class ConfigApplyStatus {
        public:
            struct Snapshot {
                uint64_t attempt_id = 0;
                uint64_t completed_id = 0;
                bool ok = false;
                std::string error;
            };
            uint64_t MarkAttempt() {
                std::lock_guard<std::mutex> lock(mutex_);
                return ++attempt_id_;
            }
            /// batch111: the outcome must be attributed to the attempt that
            /// produced it. Two in-flight applies can finish out of order;
            /// an untagged Record made the late completion of an older
            /// attempt overwrite a newer result and look like its own.
            void Record(uint64_t attempt_id, bool ok,
                        const std::string& error) {
                std::lock_guard<std::mutex> lock(mutex_);
                if (attempt_id < completed_id_) {
                    return;  // stale completion: newer result already stored
                }
                completed_id_ = attempt_id;
                ok_ = ok;
                error_ = error;
            }
            Snapshot Get() const {
                std::lock_guard<std::mutex> lock(mutex_);
                return Snapshot{attempt_id_, completed_id_, ok_, error_};
            }

        private:
            mutable std::mutex mutex_;
            uint64_t attempt_id_ = 0;
            uint64_t completed_id_ = 0;
            bool ok_ = false;
            std::string error_;
        };

        /// batch22 B4: privileged operations reach the OS/UI layer through
        /// callbacks (core must not depend on ui). `repair_requester` returns
        /// false when a repair is already running. `autostart_setter` writes the
        /// Run key and returns the value read back. `audit_log` appends one
        /// audit line to the console ring.
        using RepairRequester = std::function<bool()>;
        using AutostartSetter = std::function<bool(bool)>;
        using AuditLog = std::function<void(const std::string&)>;
        /// batch126: cumulative console-ring lines evicted by the bound.
        using ConsoleDroppedProvider = std::function<uint64_t()>;
        /// batch37t: apply a just-saved config to the running app. The UI
        /// receives the attempt id so its completion is attributed to the
        /// save that queued it (batch111).
        /// entry point queues it to the UI/command thread and returns true;
        /// with no native UI (headless/web-only) it returns false and the
        /// response keeps the honest "applies on restart" note. The callback
        /// must NOT apply synchronously: the apply stops the HTTP server, and
        /// doing that on an HTTP worker would self-join.
        using ConfigApplier =
            std::function<bool(const core::Config&, uint64_t attempt_id)>;
        void RegisterApi(HttpServer& server, runtime::Dataplane& dataplane,
                         const core::Config& config,
                         const std::string& config_path,
                         std::string auth_token = {},
                         ConsoleTextProvider console_provider = {},
                         RepairRequester repair_requester = {},
                         AutostartSetter autostart_setter = {},
                         AuditLog audit_log = {},
                         ConfigApplier config_applier = {},
                         std::shared_ptr<ConfigApplyStatus> apply_status = {},
                         ConsoleDroppedProvider console_dropped = {});

        /// batch37s: live-token variant used by the entry point so a settings
        /// save can rotate/clear the credential and restart the listener
        /// without rebuilding the route table. Distinct name (not an overload)
        /// because `RegisterApi(..., {})` would be ambiguous.
        void RegisterApiLive(HttpServer& server, runtime::Dataplane& dataplane,
                             const core::Config& config,
                             const std::string& config_path,
                         std::shared_ptr<AuthTokenState> auth_token,
                         ConsoleTextProvider console_provider = {},
                         RepairRequester repair_requester = {},
                         AutostartSetter autostart_setter = {},
                         AuditLog audit_log = {},
                         ConfigApplier config_applier = {},
                         std::shared_ptr<ConfigApplyStatus> apply_status = {},
                         ConsoleDroppedProvider console_dropped = {});

        /// Extracts a string field from a flat JSON body. Handles the common
        /// escapes (\" \\ \n); returns false when the key is missing.
        bool JsonGetString(const std::string& body, const char* key,
                           std::string& out);

        /// Extracts an unsigned number field (no quotes in JSON).
        bool JsonGetNumber(const std::string& body, const char* key,
                           uint32_t& out);

        /// batch34r: compares two secrets in time independent of WHERE they
        /// first differ. A plain `==` returns at the first mismatching byte,
        /// so an attacker who can time the response learns the correct prefix
        /// one character at a time and recovers the token. This walks the
        /// whole length and folds the differences into one accumulator.
        /// Length is folded in as well (a shorter candidate must not be
        /// cheaper to reject than a same-length wrong one).
        bool ConstantTimeEquals(const std::string& a, const std::string& b) noexcept;

        /// batch34r: whether a write guard should be installed at all. An
        /// EMPTY token is a configuration error the caller must resolve (the
        /// launcher generates one); it must never be read as "authentication
        /// disabled", which would turn a forgotten config key into a fully
        /// open control plane.
        inline bool WriteGuardEnabledFor(const std::string& token) noexcept {
            return !token.empty();
        }

    }  // namespace web
}  // namespace vgww
