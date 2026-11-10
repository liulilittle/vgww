// ============================================================================
// controller.cpp - real data source + real command executor (S4.2 Task 5).
// ============================================================================
#include <winsock2.h>
#include <ws2ipdef.h>
#include <windows.h>

#include "ui/controller.h"

#include "ui/console_log.h"
#include "ui/i18n.h"
#include "ui/pages/page_util.h"  // batch31 P0-1: the ONE UTF-8 Widen

#include "core/limits.h"
#include "driver/installer.h"

#include <cstring>
#include <type_traits>
#include <utility>

namespace vgww {
    namespace ui {

        namespace {

            /// batch31 P0-1: command results are plain text from the core
            /// (UTF-8); page_util.h's Widen is the single decoder.
            std::wstring Widen(const std::string& text) {
                return vgww::ui::Widen(text);
            }

            /// batch38: the Web apply-outcome sink receives UTF-8 so the
            /// status endpoint never mangles non-Latin error text.
            std::string NarrowUtf8(const std::wstring& text) {
                if (text.empty()) {
                    return {};
                }
                const int need = ::WideCharToMultiByte(
                    CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()),
                    nullptr, 0, nullptr, nullptr);
                if (need <= 0) {
                    return {};
                }
                std::string out(static_cast<std::size_t>(need), '\0');
                ::WideCharToMultiByte(CP_UTF8, 0, text.c_str(),
                                      static_cast<int>(text.size()), out.data(),
                                      need, nullptr, nullptr);
                return out;
            }

            CommandResult Ok(std::wstring message) {
                CommandResult result;
                result.ok = true;
                result.message = std::move(message);
                return result;
            }

            CommandResult Fail(std::wstring message) {
                CommandResult result;
                result.ok = false;
                result.message = std::move(message);
                return result;
            }

            /// batch98: a rule-store change that could not reach disk must not
            /// be toasted as a plain success (the HTTP routes already report
            /// persisted:false; the native UI was still claiming "added").
            /// RuleStore::FlushPersist runs inside the mutation, so this
            /// verdict is current. The change is live in memory either way.
            CommandResult OkIfRulesPersisted(Str key) {
                const I18n& i18n = I18n::Instance();
                if (!web::RuleStore::Instance().PersistUpToDate()) {
                    return Fail(i18n.FormatCopy(
                        Str::SaveWriteFailedFmt,
                        {Widen("the rule file could not be written; the "
                               "change is live but will be lost after a "
                               "restart")}));
                }
                return Ok(i18n.Copy(key));
            }

            /// Full 8-group text or a compressed form; InetPtonW is the
            /// platform parser (never hand-rolled).
            bool IsValidIpv6(const std::string& text) {
                if (text.empty()) {
                    return false;
                }
                const std::wstring wide = Widen(text);
                if (wide.empty()) {
                    return false;
                }
                std::array<uint8_t, 16> addr{};
                return 1 == ::InetPtonW(AF_INET6, wide.c_str(), addr.data());
            }

            void LoadCounters(const runtime::Dataplane::Stats& stats,
                              Counters& out) {
                // Relaxed is enough for a statistics reader: per-object
                // read-read coherence keeps each counter monotonic in this
                // thread (the writer uses the default seq_cst stores).
                out.rx_frames = stats.rx_frames.load(std::memory_order_relaxed);
                out.rx_dropped =
                    stats.rx_dropped.load(std::memory_order_relaxed);
                out.tx_frames = stats.tx_frames.load(std::memory_order_relaxed);
                out.arp_replies =
                    stats.arp_replies.load(std::memory_order_relaxed);
                out.icmp_replies =
                    stats.icmp_replies.load(std::memory_order_relaxed);
                out.host_passthrough =
                    stats.host_passthrough.load(std::memory_order_relaxed);
                out.tcp_accepted =
                    stats.tcp_accepted.load(std::memory_order_relaxed);
                out.mac_misses =
                    stats.mac_misses.load(std::memory_order_relaxed);
                out.rate_limited =
                    stats.rate_limited.load(std::memory_order_relaxed);
                out.rx_vlan_frames =
                    stats.rx_vlan_frames.load(std::memory_order_relaxed);
                out.thread_errors =
                    stats.thread_errors.load(std::memory_order_relaxed);
                out.icmp_tag_exhausted =
                    stats.icmp_tag_exhausted.load(std::memory_order_relaxed);
                out.tx_vlan_frames =
                    stats.tx_vlan_frames.load(std::memory_order_relaxed);
                // batch34a: the 14th field, previously dropped on the floor.
                out.portmap_send_dropped =
                    stats.portmap_send_dropped.load(std::memory_order_relaxed);
            }

            // --- command bodies (validation first, then mutate) -----------

            CommandResult DoAddPortMap(const AddPortMapCmd& cmd) {
                if ("tcp" != cmd.proto) {
                    return Fail(I18n::Instance().Copy(Str::CmdTcpOnly));
                }
                bool ok = false;
                vgww::core::ParseIpv4(cmd.lan_ip, ok);
                if (!ok) {
                    return Fail(I18n::Instance().Copy(Str::CmdLanIpInvalid));
                }
                if (0 == cmd.wan_port || 0 == cmd.lan_port) {
                    return Fail(I18n::Instance().Copy(Str::CmdPortNotZero));
                }
                web::RuleStore& store = web::RuleStore::Instance();
                // batch128: one snapshot, reused for both the duplicate scan
                // and the cap check (the old code built PortMaps() twice per
                // request; AddPortMap still re-checks both under its lock).
                const auto existing_rules = store.PortMaps();
                for (const auto& existing : existing_rules) {
                    if (existing.proto == cmd.proto &&
                        existing.wan_port == cmd.wan_port) {
                        return Fail(I18n::Instance().Copy(Str::CmdWanPortTaken));
                    }
                }
                if (store.PortMapCount() >=
                    vgww::core::limits::kMaxPortMaps) {
                    return Fail(I18n::Instance().Copy(Str::CmdPortmapLimit));
                }
                web::PortMappingRule rule;
                rule.proto = cmd.proto;
                rule.wan_port = cmd.wan_port;
                rule.lan_ip = cmd.lan_ip;
                rule.lan_port = cmd.lan_port;
                // U8: the in-lock duplicate check is the authority under
                // concurrent web + UI writers; a race loser reports a clear
                // conflict instead of silently shadowing the earlier rule.
                if (!store.AddPortMap(std::move(rule))) {
                    return Fail(I18n::Instance().Copy(Str::CmdWanPortTaken));
                }
                console_log::AppendAuditLine(
                    "portmap add " + cmd.proto + ":" +
                    std::to_string(cmd.wan_port) + " -> " + cmd.lan_ip +
                    ":" + std::to_string(cmd.lan_port));
                return OkIfRulesPersisted(Str::CmdPortmapAdded);
            }

            CommandResult DoRemovePortMap(const RemovePortMapCmd& cmd) {
                // batch138: prefer the stable identity. A positional index is
                // only a snapshot of where the rule was when the table was
                // drawn; by the time this command reaches the worker any other
                // add/remove has shifted it, and the erase would then hit a
                // DIFFERENT rule. Checking and erasing under one lock
                // (batch34d/batch89) rules out a TOCTOU inside the store but
                // cannot fix a stale index.
                web::RuleStore& store = web::RuleStore::Instance();
                if (0 != cmd.id) {
                    // P82: a removal refused because the tombstone store is
                    // full is a persistence failure, not a missing rule - the
                    // UI must not toast "out of range" for a rule that is
                    // still in force.
                    bool refused = false;
                    if (!store.RemovePortMapById(cmd.id, refused)) {
                        if (refused) {
                            return Fail(I18n::Instance().FormatCopy(
                                Str::SaveWriteFailedFmt,
                                {Widen("the rule tombstone store is full; the "
                                       "rule was not removed")}));
                        }
                        return Fail(I18n::Instance().Copy(
                            Str::CmdIndexOutOfRange));
                    }
                    console_log::AppendAuditLine("portmap delete id=" +
                                                 std::to_string(cmd.id));
                    return OkIfRulesPersisted(Str::CmdPortmapRemoved);
                }
                // batch89: range check and erase under ONE lock. Kept for
                // callers that only have a position (tests, legacy commands).
                bool refused = false;
                if (!store.RemovePortMapChecked(cmd.index, refused)) {
                    if (refused) {
                        return Fail(I18n::Instance().FormatCopy(
                            Str::SaveWriteFailedFmt,
                            {Widen("the rule tombstone store is full; the rule "
                                   "was not removed")}));
                    }
                    return Fail(I18n::Instance().Copy(Str::CmdIndexOutOfRange));
                }
                console_log::AppendAuditLine("portmap delete index=" +
                                             std::to_string(cmd.index));
                return OkIfRulesPersisted(Str::CmdPortmapRemoved);
            }

            CommandResult DoAddBan(const AddBanCmd& cmd) {
                if ("ip" == cmd.kind) {
                    bool ok = false;
                    vgww::core::ParseIpv4(cmd.value, ok);
                    if (!ok) {
                        return Fail(I18n::Instance().Copy(Str::CmdIpInvalid));
                    }
                } else if ("mac" == cmd.kind) {
                    vgww::core::MacAddress mac{};
                    if (!vgww::core::ParseMac(cmd.value, mac)) {
                        return Fail(I18n::Instance().Copy(Str::CmdMacInvalid));
                    }
                } else {
                    return Fail(I18n::Instance().Copy(Str::CmdBanKindInvalid));
                }
                web::RuleStore& store = web::RuleStore::Instance();
                web::BanEntry ban;
                ban.kind = cmd.kind;
                ban.value = cmd.value;
                // batch89: cap + insert under ONE lock. The old code read
                // Bans().size() here and then called the void AddBan, so a
                // concurrent web writer could overrun the cap between the two.
                if (!store.AddBanChecked(std::move(ban))) {
                    return Fail(I18n::Instance().Copy(Str::CmdBanLimit));
                }
                console_log::AppendAuditLine("ban add " + cmd.kind + " " +
                                             cmd.value);
                return OkIfRulesPersisted(Str::CmdBanAdded);
            }

            CommandResult DoRemoveBan(const RemoveBanCmd& cmd) {
                // batch138: id first, positional index only as a legacy path.
                web::RuleStore& store = web::RuleStore::Instance();
                if (0 != cmd.id) {
                    // P82: tombstone-full is a persistence failure (see
                    // DoRemovePortMap).
                    bool refused = false;
                    if (!store.RemoveBanById(cmd.id, refused)) {
                        if (refused) {
                            return Fail(I18n::Instance().FormatCopy(
                                Str::SaveWriteFailedFmt,
                                {Widen("the rule tombstone store is full; the "
                                       "ban was not removed")}));
                        }
                        return Fail(I18n::Instance().Copy(
                            Str::CmdIndexOutOfRange));
                    }
                    console_log::AppendAuditLine("ban delete id=" +
                                                 std::to_string(cmd.id));
                    return OkIfRulesPersisted(Str::CmdBanRemoved);
                }
                // batch89: same one-lock shape as the port-map path above.
                bool refused = false;
                if (!store.RemoveBanChecked(cmd.index, refused)) {
                    if (refused) {
                        return Fail(I18n::Instance().FormatCopy(
                            Str::SaveWriteFailedFmt,
                            {Widen("the rule tombstone store is full; the ban "
                                   "was not removed")}));
                    }
                    return Fail(I18n::Instance().Copy(Str::CmdIndexOutOfRange));
                }
                console_log::AppendAuditLine("ban delete index=" +
                                             std::to_string(cmd.index));
                return OkIfRulesPersisted(Str::CmdBanRemoved);
            }

            CommandResult DoSetRateLimit(const SetRateLimitCmd& cmd) {
                vgww::core::MacAddress mac{};
                if (!vgww::core::ParseMac(cmd.mac, mac)) {
                    return Fail(I18n::Instance().Copy(Str::CmdMacInvalid));
                }
                if (0 == cmd.up_kbps && 0 == cmd.down_kbps) {
                    return Fail(I18n::Instance().Copy(Str::CmdRateBothZero));
                }
                web::RateLimitRule rule;
                rule.mac = cmd.mac;
                rule.uplink_kbps = cmd.up_kbps;
                rule.downlink_kbps = cmd.down_kbps;
                // batch136: a MAC edit posts ONE command that removes the old
                // rule and writes the new one under a single lock. Posting a
                // separate RemoveRateLimitCmd first let either half fail alone
                // (queue full / cap reached) and deleted the client's policy.
                if (!cmd.replace_mac.empty()) {
                    if (!web::RuleStore::Instance().ReplaceRateLimitChecked(
                            cmd.replace_mac, std::move(rule))) {
                        return Fail(I18n::Instance().Copy(Str::CmdRateLimitLimit));
                    }
                    console_log::AppendAuditLine(
                        "ratelimit set " + cmd.mac + " up=" +
                        std::to_string(cmd.up_kbps) + " down=" +
                        std::to_string(cmd.down_kbps) + " replace=" +
                        cmd.replace_mac);
                    return OkIfRulesPersisted(Str::CmdRateLimitUpdated);
                }
                // batch89: upsert + cap under ONE lock (see SetRateLimitChecked).
                // The old path scanned RateLimits() out here to guess whether
                // this MAC was new, which is the same decision the store makes
                // inside its own lock - and the two could disagree.
                if (!web::RuleStore::Instance().SetRateLimitChecked(
                        std::move(rule))) {
                    return Fail(I18n::Instance().Copy(Str::CmdRateLimitLimit));
                }
                console_log::AppendAuditLine(
                    "ratelimit set " + cmd.mac + " up=" +
                    std::to_string(cmd.up_kbps) + " down=" +
                    std::to_string(cmd.down_kbps));
                return OkIfRulesPersisted(Str::CmdRateLimitUpdated);
            }

            CommandResult DoRemoveRateLimit(const RemoveRateLimitCmd& cmd) {
                if (!web::RuleStore::Instance().RemoveRateLimit(cmd.mac)) {
                    return Fail(I18n::Instance().Copy(Str::CmdRateLimitMissing));
                }
                console_log::AppendAuditLine("ratelimit delete " + cmd.mac);
                return OkIfRulesPersisted(Str::CmdRateLimitRemoved);
            }

            /// batch97: mirror a binding command into the config document, so
            /// a restart keeps what the page shows (the HTTP routes persist
            /// through the same core helpers). An empty path means "no
            /// document configured" and is a no-op, not a failure.
            bool PersistBindV4(const std::string& config_path,
                               const std::string& mac_text,
                               const std::string& ip_text,
                               const std::string& hostname,
                               const std::string& replace_mac,
                               std::string& error) {
                if (config_path.empty()) {
                    return true;
                }
                vgww::core::MacAddress mac{};
                if (!vgww::core::ParseMac(mac_text, mac)) {
                    error = "invalid mac";
                    return false;
                }
                if (!replace_mac.empty()) {
                    vgww::core::MacAddress old{};
                    if (vgww::core::ParseMac(replace_mac, old)) {
                        std::string ignored;
                        (void)vgww::core::DeleteDhcpBinding(config_path, old,
                                                            ignored);
                    }
                }
                bool parsed = false;
                const uint32_t ip = vgww::core::ParseIpv4(ip_text, parsed);
                if (!parsed) {
                    error = "invalid ip";
                    return false;
                }
                return vgww::core::UpsertDhcpBinding(config_path, mac, ip,
                                                     hostname, error);
            }

            bool PersistBindV6(const std::string& config_path,
                               const std::string& duid_text,
                               const std::string& ip_text,
                               const std::string& hostname,
                               const std::string& replace_duid,
                               std::string& error) {
                if (config_path.empty()) {
                    return true;
                }
                std::vector<uint8_t> duid;
                if (!runtime::ParseDuidText(duid_text, duid) || duid.empty()) {
                    error = "invalid duid";
                    return false;
                }
                if (!replace_duid.empty()) {
                    std::vector<uint8_t> old;
                    if (runtime::ParseDuidText(replace_duid, old) &&
                        !old.empty()) {
                        std::string ignored;
                        (void)vgww::core::DeleteDhcp6Binding(config_path, old,
                                                             ignored);
                    }
                }
                std::array<uint8_t, 16> ip{};
                if (!vgww::core::ParseIpv6(ip_text, ip)) {
                    error = "invalid ipv6";
                    return false;
                }
                return vgww::core::UpsertDhcp6Binding(config_path, duid, ip,
                                                      hostname, error);
            }

            CommandResult DoAddDhcpBinding(runtime::Dataplane& dataplane,
                                           const std::string& config_path,
                                           const AddDhcpBindingCmd& cmd) {
                vgww::core::MacAddress mac{};
                if (!vgww::core::ParseMac(cmd.mac, mac)) {
                    return Fail(I18n::Instance().Copy(Str::CmdMacInvalid));
                }
                bool ok = false;
                const uint32_t ip = vgww::core::ParseIpv4(cmd.ip, ok);
                if (!ok || 0 == ip) {
                    return Fail(I18n::Instance().Copy(Str::CmdIpInvalid));
                }
                if (!dataplane.DhcpActive()) {
                    return Fail(I18n::Instance().Copy(Str::CmdDhcpDisabled));
                }
                // batch137: a MAC edit arrives as ONE command carrying the old
                // key (`replace_mac`); the store drops and inserts under a
                // single lock, so a refusal cannot delete the client's binding.
                const bool applied = cmd.replace_mac.empty()
                    ? dataplane.SetDhcpBinding(cmd.mac, cmd.ip, cmd.hostname)
                    : dataplane.ReplaceDhcpBinding(cmd.replace_mac, cmd.mac,
                                                   cmd.ip, cmd.hostname);
                if (!applied) {
                    return Fail(I18n::Instance().Copy(Str::CmdDhcpBindingRejected));
                }
                // batch97: the runtime change is live; also keep it across a
                // restart (P43 parity with the HTTP route).
                std::string persist_error;
                if (!PersistBindV4(config_path, cmd.mac, cmd.ip, cmd.hostname,
                                   cmd.replace_mac, persist_error)) {
                    return Fail(I18n::Instance().FormatCopy(
                        Str::SaveWriteFailedFmt, {Widen(persist_error)}));
                }
                console_log::AppendAuditLine("dhcp binding add " + cmd.mac +
                                             " -> " + cmd.ip);
                return Ok(I18n::Instance().Copy(Str::CmdDhcpBindingAdded));
            }

            CommandResult DoRemoveDhcpBinding(
                runtime::Dataplane& dataplane, const std::string& config_path,
                const RemoveDhcpBindingCmd& cmd) {
                vgww::core::MacAddress mac{};
                if (!vgww::core::ParseMac(cmd.mac, mac)) {
                    return Fail(I18n::Instance().Copy(Str::CmdMacInvalid));
                }
                if (!dataplane.DhcpActive()) {
                    return Fail(I18n::Instance().Copy(Str::CmdDhcpDisabled));
                }
                if (!dataplane.RemoveDhcpBinding(cmd.mac)) {
                    return Fail(I18n::Instance().Copy(Str::CmdDhcpBindingMissing));
                }
                // batch97: drop the persisted row too (delete of an absent row
                // still succeeds: the requested state holds).
                std::string persist_error;
                if (!config_path.empty() &&
                    !vgww::core::DeleteDhcpBinding(config_path, mac,
                                                   persist_error)) {
                    return Fail(I18n::Instance().FormatCopy(
                        Str::SaveWriteFailedFmt, {Widen(persist_error)}));
                }
                console_log::AppendAuditLine("dhcp binding delete " + cmd.mac);
                return Ok(I18n::Instance().Copy(Str::CmdDhcpBindingRemoved));
            }

            CommandResult DoAddDhcp6Binding(runtime::Dataplane& dataplane,
                                            const std::string& config_path,
                                            const AddDhcp6BindingCmd& cmd) {
                if (cmd.duid.empty()) {
                    return Fail(I18n::Instance().Copy(Str::CmdDuidEmpty));
                }
                if (!IsValidIpv6(cmd.ip)) {
                    return Fail(I18n::Instance().Copy(Str::CmdIpv6Invalid));
                }
                if (!dataplane.Dhcp6Active()) {
                    return Fail(I18n::Instance().Copy(Str::CmdDhcp6Disabled));
                }
                // batch137: same one-command re-key as the v4 sibling.
                const bool applied = cmd.replace_duid.empty()
                    ? dataplane.SetDhcp6Binding(cmd.duid, cmd.ip, cmd.hostname)
                    : dataplane.ReplaceDhcp6Binding(cmd.replace_duid, cmd.duid,
                                                    cmd.ip, cmd.hostname);
                if (!applied) {
                    return Fail(I18n::Instance().Copy(Str::CmdDhcp6BindingRejected));
                }
                // batch97: persist the v6 row as well.
                std::string persist_error;
                if (!PersistBindV6(config_path, cmd.duid, cmd.ip, cmd.hostname,
                                   cmd.replace_duid, persist_error)) {
                    return Fail(I18n::Instance().FormatCopy(
                        Str::SaveWriteFailedFmt, {Widen(persist_error)}));
                }
                console_log::AppendAuditLine("dhcp6 binding add " + cmd.duid +
                                             " -> " + cmd.ip);
                return Ok(I18n::Instance().Copy(Str::CmdDhcpBindingAdded));
            }

            CommandResult DoRemoveDhcp6Binding(
                runtime::Dataplane& dataplane, const std::string& config_path,
                const RemoveDhcp6BindingCmd& cmd) {
                if (cmd.duid.empty()) {
                    return Fail(I18n::Instance().Copy(Str::CmdDuidEmpty));
                }
                if (!dataplane.Dhcp6Active()) {
                    return Fail(I18n::Instance().Copy(Str::CmdDhcp6Disabled));
                }
                if (!dataplane.RemoveDhcp6Binding(cmd.duid)) {
                    return Fail(I18n::Instance().Copy(Str::CmdDhcp6BindingMissing));
                }
                // batch97: drop the persisted v6 row too.
                std::string persist_error;
                if (!config_path.empty()) {
                    std::vector<uint8_t> duid;
                    if (runtime::ParseDuidText(cmd.duid, duid) && !duid.empty() &&
                        !vgww::core::DeleteDhcp6Binding(config_path, duid,
                                                        persist_error)) {
                        return Fail(I18n::Instance().FormatCopy(
                            Str::SaveWriteFailedFmt, {Widen(persist_error)}));
                    }
                }
                console_log::AppendAuditLine("dhcp6 binding delete " +
                                             cmd.duid);
                return Ok(I18n::Instance().Copy(Str::CmdDhcpBindingRemoved));
            }

            CommandResult DoSaveConfig(
                const std::string& config_path, const SaveConfigCmd& cmd,
                const DataplaneCommandExecutor::ApplyLiveHook& apply_live) {
                // batch117: these strings reach the user through the settings
                // outcome toast (DrainCommandResults -> ShowText), so they must
                // follow the active language. The backend reasons come from
                // ValidateConfig / SaveToFile / the live-apply hook and are
                // English; they are injected through {0} rather than being
                // re-translated here.
                const I18n& i18n = I18n::Instance();
                std::string error;
                if (!vgww::core::ValidateConfig(cmd.config, error)) {
                    return Fail(i18n.FormatCopy(Str::SaveInvalidConfigFmt,
                                            {Widen(error)}));
                }
                if (config_path.empty()) {
                    return Fail(i18n.Copy(Str::SaveNoConfigPath));
                }
                if (!cmd.config.SaveToFilePreservingBindings(config_path,
                                                             error)) {
                    return Fail(i18n.FormatCopy(Str::SaveWriteFailedFmt,
                                            {Widen(error)}));
                }
                if (apply_live) {
                    std::wstring live_error;
                    if (!apply_live(cmd.config, live_error)) {
                        return Fail(live_error.empty()
                                        ? i18n.Copy(Str::SaveAppliedNoLive)
                                        : live_error);
                    }
                    console_log::AppendAuditLine("config saved (applied)");
                    return Ok(i18n.Copy(Str::SaveApplied));
                }
                console_log::AppendAuditLine("config saved (applies on restart)");
                return Ok(i18n.Copy(Str::SaveAppliedRestart));
            }

            CommandResult DoSetLanguage(const std::string& config_path,
                                        const SetLanguageCmd& cmd) {
                // batch117: the same user-visible path as DoSaveConfig - the
                // language-save outcome is toasted, so it must be localized.
                const I18n& i18n = I18n::Instance();
                if (config_path.empty()) {
                    return Fail(i18n.Copy(Str::SaveNoConfigPath));
                }
                std::string error;
                std::optional<vgww::core::Config> config =
                    vgww::core::Config::LoadFromFile(config_path, error);
                if (!config) {
                    return Fail(i18n.FormatCopy(Str::SaveWriteFailedFmt,
                                            {Widen(error)}));
                }
                config->ui_language = cmd.code;
                if (!config->SaveToFile(config_path, error)) {
                    return Fail(i18n.FormatCopy(Str::SaveWriteFailedFmt,
                                            {Widen(error)}));
                }
                // P85: a language switch is a privileged preference change
                // (it rewrites the config document); it must leave the same
                // audit trail as every other native command.
                console_log::AppendAuditLine(std::string("language set ") +
                                             cmd.code);
                return Ok(i18n.Copy(Str::SaveLangApplied));
            }
            CommandResult DoSetAutostart(

                const DataplaneCommandExecutor::AutostartHook& hook,
                const SetAutostartCmd& cmd) {
                if (!hook) {
                    return Fail(I18n::Instance().Copy(Str::CmdAutostartUnwired));
                }
                const CommandResult result = hook(cmd);
                if (result.ok) {
                    console_log::AppendAuditLine(
                        std::string("autostart set ") +
                        (cmd.enabled ? "1" : "0"));
                }
                return result;
            }

            // batch25a: dashboard one-click lifecycle. Stop() is a clean,
            // bounded cooperative shutdown; Start() accepts a restart only
            // after such a stop (StateIsEmpty), which the lifecycle suite
            // already exercises 3x.
            CommandResult DoStartService(runtime::Dataplane& dataplane) {
                if (dataplane.IsRunning()) {
                    return Ok(I18n::Instance().Copy(Str::CmdServiceAlreadyRunning));
                }
                std::string error;
                if (!dataplane.Start(error)) {
                    return Fail(Widen(error));
                }
                console_log::AppendAuditLine("service started");
                return Ok(I18n::Instance().Copy(Str::CmdServiceStarted));
            }

            CommandResult DoStopService(runtime::Dataplane& dataplane) {
                if (!dataplane.IsRunning()) {
                    return Ok(I18n::Instance().Copy(Str::CmdServiceStopped));
                }
                std::string error;
                if (!dataplane.Stop(error)) {
                    return Fail(Widen(error));
                }
                // batch100 semantics: a clean teardown whose lease dump failed
                // returns true with a non-empty error. Reporting a plain
                // "stopped" hides the lost lease snapshot from the operator -
                // the same verdict main.cpp checks with
                // `!stop_error.empty()` (src/main.cpp:830) and the leases page
                // shows via UiSnapshot.lease_persist_failed.
                if (!error.empty()) {
                    console_log::AppendAuditLine("service stopped (lease save failed)");
                    return Ok(I18n::Instance().FormatCopy(
                        Str::CmdServiceStoppedDirty, {Widen(error)}));
                }
                console_log::AppendAuditLine("service stopped");
                return Ok(I18n::Instance().Copy(Str::CmdServiceStopped));
            }

            CommandResult DoRecheckService(runtime::Dataplane& dataplane) {
                if (dataplane.IsRunning()) {
                    std::string error;
                    if (!dataplane.Stop(error)) {
                        return Fail(Widen(error));
                    }
                }
                std::string error;
                if (!dataplane.Start(error)) {
                    return Fail(Widen(error));
                }
                console_log::AppendAuditLine("service rechecked");
                return Ok(I18n::Instance().Copy(Str::CmdServiceRechecked));
            }

        }  // namespace

        // --- UiController ------------------------------------------------------

        UiController::UiController(UiDataSource& source,
                                   CommandExecutor& executor)
            : publisher_(source), queue_(executor, publisher_) {}

        UiController::~UiController() {
            Stop();
        }

        bool UiController::Start(std::string& error) {
            if (!publisher_.Start(error)) {
                return false;
            }
            if (!queue_.Start(error)) {
                publisher_.Stop();  // never leave a half-started controller
                return false;
            }
            return true;
        }

        void UiController::Stop() noexcept {
            queue_.Stop();      // drain pending commands first
            publisher_.Stop();
        }

        std::shared_ptr<const UiSnapshot> UiController::Load() const noexcept {
            return publisher_.Load();
        }

        bool UiController::Post(Command cmd) {
            return queue_.Post(std::move(cmd));
        }

        std::vector<CommandResult> UiController::DrainResults() {
            return queue_.DrainResults();
        }

        // --- RealDataSource ----------------------------------------------------

        RealDataSource::RealDataSource(runtime::Dataplane& dataplane,
                                       const core::Config& config,
                                       UiRuntimeFlags flags)
            : dataplane_(dataplane), config_(config), flags_(std::move(flags)),
              started_(std::chrono::steady_clock::now()) {}

        ConfigView RealDataSource::ConfigSnapshot() {
            // batch37s: the settings apply swaps the config object on the
            // command thread; the snapshot publisher may be copying it here.
            std::unique_lock<std::mutex> config_lock;
            if (flags_.config_mutex != nullptr) {
                config_lock =
                    std::unique_lock<std::mutex>(*flags_.config_mutex);
            }
            ConfigView view;
            view.adapter = config_.adapter;
            view.mode =
                (core::Mode::kMain == config_.mode) ? "main" : "bypass";
            view.gateway_ip = core::FormatIpv4(config_.gateway.ipv4);
            view.gateway_mask = core::FormatIpv4(config_.gateway.mask);
            view.gateway_mac = core::FormatMac(config_.gateway.mac);
            view.dhcp_enabled = config_.dhcp.enabled;
            view.dhcp_pool_start = core::FormatIpv4(config_.dhcp.pool_start);
            view.dhcp_pool_end = core::FormatIpv4(config_.dhcp.pool_end);
            view.dhcp_lease_s = config_.dhcp.lease_seconds;
            for (const uint32_t ip : config_.dhcp.dns) {
                view.dhcp_dns.push_back(core::FormatIpv4(ip));
            }
            view.ipv6_enabled = config_.ipv6.enabled;
            view.ula_prefix = core::FormatIpv6(config_.ipv6.ula_prefix);
            view.prefix_len = config_.ipv6.prefix_len;
            view.ra_lifetime_s = config_.ipv6.ra_lifetime_s;
            for (const auto& addr : config_.ipv6.dns) {
                view.ipv6_dns.push_back(core::FormatIpv6(addr));
            }
            view.dhcp6_enabled = config_.ipv6.dhcpv6.enabled;
            view.dhcp6_pool_start =
                core::FormatIpv6(config_.ipv6.dhcpv6.pool_start);
            view.dhcp6_pool_end =
                core::FormatIpv6(config_.ipv6.dhcpv6.pool_end);
            view.dhcp6_lease_s = config_.ipv6.dhcpv6.lease_seconds;
            view.perf_workers = config_.perf.workers;
            view.perf_max_conns = config_.perf.max_conns;
            view.perf_dial_timeout_ms = config_.perf.dial_timeout_ms;
            view.web_port = config_.web.port;
            view.web_bind = flags_.web_bind;
            view.web_enabled =
                flags_.web_enabled_live != nullptr
                    ? flags_.web_enabled_live->load()
                    : flags_.web_enabled;
            view.vlan_id = config_.vlan.id;
            view.bridge_enabled = config_.bridge.enabled;
            view.bridge_up = config_.bridge.upstream;
            view.bridge_down = config_.bridge.downstream;
            view.bridge_table_size = config_.bridge.mac_table_size;
            view.config_path = flags_.config_path;
            view.ui_scale = config_.ui_scale;
            view.theme = config_.theme;
            return view;
        }

        std::shared_ptr<UiSnapshot> RealDataSource::Collect(uint64_t seq) {
            auto snapshot = std::make_shared<UiSnapshot>();
            snapshot->seq = seq;
            snapshot->published_at = std::chrono::steady_clock::now();
            snapshot->config = ConfigSnapshot();
            // Lifecycle contract: the publisher runs only between the
            // dataplane's Start and Stop (T7 wiring), so reading the
            // unsynchronized lifecycle counters is safe here.
            snapshot->dataplane_running = dataplane_.IsRunning();
            // batch25a: a runtime Stop/Start cycle updates this live; the
            // entry-point text stays authoritative only until the plane has
            // run at least once (it may carry the driver-install note).
            if (snapshot->dataplane_running) {
                ever_running_ = true;
                snapshot->dataplane_error.clear();
            } else {
                const std::string live = dataplane_.LastError();
                snapshot->dataplane_error =
                    ever_running_ ? live
                                  : (flags_.dataplane_error.empty()
                                         ? live
                                         : flags_.dataplane_error);
            }
            snapshot->adapter_binding = dataplane_.GetAdapterBinding();
            snapshot->adapters = dataplane_.GetAdapters();
            snapshot->driver_running = vgww::driver::NdisrdServiceRunning();
            snapshot->uptime_s = static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::seconds>(
                    snapshot->published_at - started_)
                    .count());
            snapshot->dhcp_active = dataplane_.DhcpActive();
            snapshot->dhcp6_active = dataplane_.Dhcp6Active();
            // batch33z: surface the two DHCPv4 faults the counters already
            // tracked but nothing displayed.
            snapshot->dhcp_pool_exhausted =
                dataplane_.DhcpPoolExhaustedCount();
            snapshot->dhcp_persist_failures =
                dataplane_.DhcpPersistFailureCount();
            // batch103: v6 snapshot failures and a dirty LAST stop have no
            // live counter to read (the server is torn down), so carry the
            // combined verdict for the leases page.
            snapshot->lease_persist_failed =
                dataplane_.StopPersistFailed() ||
                dataplane_.Dhcp6PersistFailureCount() > 0;
            snapshot->dhcp6_pool_exhausted = dataplane_.Dhcp6PoolExhaustedCount();
            snapshot->dhcp_leases_dropped = dataplane_.DhcpDroppedLeaseCount();
            snapshot->dhcp6_leases_dropped =
                dataplane_.Dhcp6DroppedLeaseCount();
            snapshot->dhcp_leases_corrupt = dataplane_.DhcpLeaseFileCorrupt();
            snapshot->dhcp6_leases_corrupt =
                dataplane_.Dhcp6LeaseFileCorrupt();
            snapshot->dhcp_parse_rejected = dataplane_.DhcpParseRejectedCount();
            snapshot->dhcp6_parse_rejected =
                dataplane_.Dhcp6ParseRejectedCount();
            snapshot->console_dropped = console_log::DroppedLineCount();
            LoadCounters(dataplane_.GetStats(), snapshot->counters);
            snapshot->rules_rev = web::RuleStore::Instance().Rev();
            // batch115: rule write failures used to be stderr-only; carry the
            // counter so the firewall page can warn before a restart loses
            // in-memory changes.
            snapshot->rules_persist_failures =
                web::RuleStore::Instance().PersistFailureCount();
            snapshot->rules_discarded =
                web::RuleStore::Instance().DiscardedOnLastLoad();
            snapshot->throughput = dataplane_.ThroughputBps();
            snapshot->system = dataplane_.GetSystem();
            snapshot->clients = dataplane_.ClientRates();
            snapshot->leases = dataplane_.GetLeases();
            snapshot->leases6 = dataplane_.GetLeases6();
            snapshot->dhcp_bindings = dataplane_.GetDhcpBindings();
            snapshot->dhcp6_bindings = dataplane_.GetDhcp6Bindings();
            snapshot->portmaps = web::RuleStore::Instance().PortMaps();
            // batch34f: the rule list alone cannot tell whether forwarding is
            // actually live; carry the relay's counters alongside it.
            snapshot->portmap_stats = dataplane_.GetPortmapStats();
            snapshot->bans = web::RuleStore::Instance().Bans();
            snapshot->ratelimits = web::RuleStore::Instance().RateLimits();
            snapshot->bridge_state = dataplane_.GetBridgeState();
            snapshot->bridge_error = dataplane_.GetBridgeError();
            snapshot->bridge_mac_count = dataplane_.GetBridgeMacCount();
            snapshot->bridge_mac_evictions = dataplane_.GetBridgeMacEvictions();
            snapshot->neighbor_rejections = dataplane_.GetNeighborRejections();
            snapshot->dhcp_rate_limit_resets = dataplane_.DhcpRateLimitResets();
            snapshot->dhcp6_rate_limit_resets =
                dataplane_.Dhcp6RateLimitResets();
            snapshot->udp_flow_evictions = dataplane_.UdpFlowEvictions();
            return snapshot;
        }

        void RealDataSource::CollectStats(UiSnapshot& snapshot) {
            // Light tick only: counters/throughput/system (the heavy vectors
            // keep their last full-collect contents). The publisher still
            // forces a full collect after every command.
            LoadCounters(dataplane_.GetStats(), snapshot.counters);
            snapshot.throughput = dataplane_.ThroughputBps();
            snapshot.system = dataplane_.GetSystem();
        }

        // --- DataplaneCommandExecutor ------------------------------------------

        DataplaneCommandExecutor::DataplaneCommandExecutor(
            runtime::Dataplane& dataplane, std::string config_path,
            AutostartHook autostart, ApplyLiveHook apply_live)
            : dataplane_(dataplane), config_path_(std::move(config_path)),
              autostart_(std::move(autostart)),
              apply_live_(std::move(apply_live)) {}

        CommandResult DataplaneCommandExecutor::Execute(const Command& cmd) {
            return std::visit(
                [this](const auto& concrete) -> CommandResult {
                    using T = std::decay_t<decltype(concrete)>;
                    if constexpr (std::is_same_v<T, AddPortMapCmd>) {
                        return DoAddPortMap(concrete);
                    } else if constexpr (std::is_same_v<T, RemovePortMapCmd>) {
                        return DoRemovePortMap(concrete);
                    } else if constexpr (std::is_same_v<T, AddBanCmd>) {
                        return DoAddBan(concrete);
                    } else if constexpr (std::is_same_v<T, RemoveBanCmd>) {
                        return DoRemoveBan(concrete);
                    } else if constexpr (std::is_same_v<T, SetRateLimitCmd>) {
                        return DoSetRateLimit(concrete);
                    } else if constexpr (std::is_same_v<T, RemoveRateLimitCmd>) {
                        return DoRemoveRateLimit(concrete);
                    } else if constexpr (std::is_same_v<T, AddDhcpBindingCmd>) {
                        return DoAddDhcpBinding(dataplane_, config_path_,
                                                concrete);
                    } else if constexpr (std::is_same_v<T,
                                                        RemoveDhcpBindingCmd>) {
                        return DoRemoveDhcpBinding(dataplane_, config_path_,
                                                   concrete);
                    } else if constexpr (std::is_same_v<T,
                                                        AddDhcp6BindingCmd>) {
                        return DoAddDhcp6Binding(dataplane_, config_path_,
                                                 concrete);
                    } else if constexpr (std::is_same_v<
                                             T, RemoveDhcp6BindingCmd>) {
                        return DoRemoveDhcp6Binding(dataplane_, config_path_,
                                                    concrete);
                    } else if constexpr (std::is_same_v<T, SaveConfigCmd>) {
                        auto result = DoSaveConfig(config_path_, concrete,
                                                   apply_live_);
                        if (concrete.result_sink) {
                            concrete.result_sink(result.ok,
                                                 NarrowUtf8(result.message));
                        }
                        // batch42: a native settings save must be toasted by
                        // its true outcome (success or the failure reason),
                        // never by an optimistic claim made before the apply.
                        result.save_config = concrete.native_feedback;
                        return result;
                    } else if constexpr (std::is_same_v<T, SetLanguageCmd>) {
                        return DoSetLanguage(config_path_, concrete);
                    } else if constexpr (std::is_same_v<T, StartServiceCmd>) {
                        return DoStartService(dataplane_);
                    } else if constexpr (std::is_same_v<T, StopServiceCmd>) {
                        return DoStopService(dataplane_);
                    } else if constexpr (std::is_same_v<T, RecheckServiceCmd>) {
                        return DoRecheckService(dataplane_);
                    } else {
                        static_assert(std::is_same_v<T, SetAutostartCmd>,
                                      "unhandled command type");
                        return DoSetAutostart(autostart_, concrete);
                    }
                },
                cmd);
        }

    }  // namespace ui
}  // namespace vgww
