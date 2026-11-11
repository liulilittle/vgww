// ============================================================================
// i18n.h - zh-CN/en string tables for the native UI (S4.2 Task 1).
//
// `Str` is the only allowed source of user-visible text in UI code. The
// tables in i18n.cpp must stay index-aligned and equal in length (checked by
// static_assert plus TableSize/TableNonEmptyAll/PlaceholderCountParity in
// test_ui). Keys are append-only: never rename an existing enumerator, and
// keep `_Count` last.
// ============================================================================
#pragma once

#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <mutex>
#include <string>
#include <vector>

namespace vgww {
    namespace ui {

        /// Legacy 2-language enum (batch19 R4 keeps it as aliases only; the
        /// real language identity is the runtime BCP-47-ish code string).
        enum class Lang { ZhCN, En };

        /// One entry of the runtime language catalog (generated from www).
        struct LangInfo {
            std::string code;
            std::string name;
            bool rtl = false;
        };

        /// Every user-visible string in the native UI (append-only).
        enum class Str : uint16_t {
            AppTitle,
            NavDashboard,
            NavLeases,
            NavPortmap,
            NavFirewall,
            NavRatelimit,
            NavBridge,
            NavSettings,
            NavAbout,
            ClientCountFmt,
            CommonAdd,
            CommonEdit,
            CommonDelete,
            CommonCancel,
            CommonSave,
            CommonClose,
            CommonRefresh,
            CommonOk,
            CommonConfirmDeleteFmt,
            CommonEmpty,
            CommonLoading,
            CommonError,
            LangZh,
            LangEn,
            TrayShow,
            TrayHide,
            TrayAutostart,
            TrayExit,
            DataplaneDown,
            // S5-AESTH: localized driver-missing banner (was hardcoded English).
            DataplaneErrorDriver,
            // Raw engine errors (GUID lists) must never flood the banner.
            DataplaneErrorNoAdapter,
            DataplaneErrorGeneric,
            // T8 (S4.3): dashboard + leases pages.
            StatusOk,
            BridgeFailed,
            // batch34x: the bridge banner used to stop at "bridge failed";
            // these say WHICH failure (the machine reason went to stderr).
            BridgeErrorPortGone,
            BridgeErrorRead,
            BridgeErrorGeneric,
            DashRx,
            DashTx,
            DashUp,
            DashDown,
            DashClients,
            /// batch331: the dashboard's own "no clients" sentence. It used to
            /// borrow LeasesEmptyHint, which talks about DHCP addresses and the
            /// Start button - a different page's data.
            DashClientsEmpty,
            // Batch22 A2: client-table filter + sort controls.
            DashFilterAll,
            DashFilterLan,
            DashFilterWan,
            DashSortBy,
            DashSortRate,
            DashSortUp,
            DashSortDown,
            DashSortSeen,
            DashSortAsc,
            DashSortDesc,
            DashUptime,
            DashCpu,
            DashMem,
            // Batch22 A7: the second dashboard row (identity + protocol counters).
            DashGateway,
            DashIpv6Status,
            DashTcp,
            DashDrops,
            DashPass,
            DashVlanRx,
            DashVlanTx,
            DashVmem,
            // Batch22 A8: editable Web token (empty keeps the current secret;
            // clearing is an explicit, confirmed action).
            FormTokenKeepHint,
            CommonClear,
            ConfirmClearToken,
            ColIp,
            ColMac,
            ColUp,
            ColDown,
            ColLastSeen,
            ColLan,
            ColHostname,
            ColExpiry,
            ColType,
            ColDuid,
            LeasesTabV4,
            LeasesTabV6,
            LeasesTabBind4,
            LeasesTabBind6,
            LeasesRuntimeHint,
            /// batch33z: the two DHCPv4 faults that used to be stderr-only.
            LeasesPoolExhausted,
            LeasesPersistFailed,
            /// batch115: the rule document could not be written; changes are
            /// in memory only and will be lost on restart.
            RulesPersistFailed,
            /// batch118: entries in the rule document were invalid and were
            /// skipped at load; they never took effect.
            RulesDiscarded,
            /// batch119: persisted lease entries were dropped at load
            /// (malformed, expired, outside the LAN, reserved or duplicated).
            LeasesDropped,
            /// batch120: the lease document itself was corrupt and preserved
            /// aside; the persisted mappings did not survive.
            LeasesCorrupt,
            /// batch121: DHCP frames refused by strict parse validation
            /// (malformed clients on the LAN).
            LeasesParseRejected,
            /// batch126: console-ring lines were evicted by the bound.
            ConsoleDropped,
            /// batch34f: a port-map rule whose WAN port could not be bound.
            PortmapPortBusy,
            /// batch34f: forwarding is live; summary line.
            PortmapLiveSummary,
            FormMac,
            FormIp,
            FormHostname,
            FormDuid,
            LeasesErrMac,
            LeasesErrIp,
            LeasesErrDuid,
            LeaseStatic,
            LeaseDynamic,
            CommonYes,
            CommonNo,
            // T9 (S4.3): portmap + firewall + ratelimit pages.
            ColProto,
            ColWanPort,
            ColLanIp,
            ColLanPort,
            ColValue,
            ColUpKbps,
            ColDownKbps,
            FormProtoTcpOnly,
            ErrProtoTcp,
            ErrWanPort,
            ErrLanPort,
            ErrLanIp,
            ErrBanKind,
            ErrBanIp,
            ErrMacFormat,
            ErrUpDownZero,
            ErrKbps,
            // T10 (S4.3): bridge + settings + about pages.
            SettingsSaved,
            SettingsDirty,
            CommonNotSet,
            StatusRunning,
            StatusStopped,
            BridgeRestartHint,
            /// batch34h: the MAC table is at capacity and evicting entries.
            BridgeMacTableFull,
            /// batch34i: tooltip breakdown of the "dropped packets" tile.
            DashDropsBreakdown,
            AboutLicense,
            AboutVersion,
            AboutMemory,
            AboutConfigPath,
            AboutDriver,
            BridgeMacCount,
            FormMode,
            FormAdapter,
            FormGatewayIp,
            FormGatewayMask,
            FormGatewayMac,
            FormDhcpEnabled,
            FormPoolStart,
            FormPoolEnd,
            FormLeaseHours,
            FormLeaseSeconds,
            FormDns,
            FormIpv6Enabled,
            FormUla,
            FormPrefixLen,
            FormRa,
            FormDhcp6Enabled,
            FormWebPort,
            FormWebBind,
            FormVlan,
            FormBridgeEnabled,
            FormBridgeUp,
            FormBridgeDown,
            FormBridgeTable,
            FormToken,
            FormGroupBasic,
            FormGroupGateway,
            FormGroupDhcp,
            FormGroupIpv6,
            FormGroupWeb,
            FormGroupBridge,
            // Batch22 A6: the performance group (workers / max connections).
            FormGroupPerf,
            FormWorkers,
            FormMaxConns,
            ErrSettingsRange,
            ErrModeValue,
            ErrSettingsNumber,
            ErrDnsList,
            ErrUla,
            ErrDhcp6Pool,
            // T12-F3 (Round 2): degraded fix action + request toast.
            FixDriverLabel,
            FixRequested,
            // S6 U6: the command queue rejected a submission (busy).
            CommonBusy,
            // S5 GUI fix (G7): close-to-tray balloon body.
            TrayBalloonBody,
            // S5 GUI fix (G8): About-page language-switch row label.
            AboutLanguage,
            // Batch16 F1/F2: access-denied banner + async repair outcome
            // toasts (append-only tail; keep `_Count` last).
            DataplaneErrorAccessDenied,
            FixSucceeded,
            FixFailedFmt,
            // Batch19 R2: About-page Web UI entry (URL row + open button).
            AboutWebUi,
            AboutOpenWeb,
            AboutWebUnavailable,
            // Batch19 terminal: About-page Telegram user-group link (label +
            // the "cannot open browser" failure toast).
            AboutTelegram,
            AboutTelegramFailed,
            // Batch19 R3-2: the ninth navigation entry (captured output).
            NavConsole,
            // Batch20: the Settings "UI" group + its scale control label.
            SettingsUi,
            SettingsUiScale,
            // Batch22 A1: the appearance selector and its three options.
            SettingsTheme,
            ThemeDark,
            ThemeLight,
            ThemeAuto,
            // Batch20 item 1: About language-filter placeholder.
            AboutLangFilterHint,
            // Batch20 item 7: console copy button + its failure toast.
            ConsoleCopy,
            ConsoleCopyFailed,
            // Batch20 P2: the Settings Web-group enable switch.
            FormWebEnabled,
            // Batch24 P1-4: save -> restart confirm dialog (title/body/buttons).
            SettingsRestartTitle,
            SettingsRestartPrompt,
            SettingsRestartNow,
            SettingsRestartLater,
            // Batch24 P2-9: Settings adapter diagnostic success line.
            SettingsAdapterBoundFmt,
            // Batch24 P2-9b: link/IP diagnostic + adapter picker + warning
            // banner (append-only tail; keep `_Count` last).
            SettingsAdapterStatusFmt,
            SettingsAdapterLinkUp,
            SettingsAdapterLinkDown,
            SettingsAdapterIpNone,
            SettingsAdapterIpsFmt,
            FormAdapterPick,
            /// batch29: UNUSED - the adapter is a pure select now, so the
            /// "manual input (custom name or device path)" placeholder has no
            /// entry point. Kept (append-only table contract) and annotated so
            /// the dead key is explicit rather than a silent inconsistency.
            AdapterPickManual,
            DataplaneAdapterWarning,
            DataplaneAdapterDownFmt,
            DataplaneAdapterNoIpFmt,
            DataplaneAdapterSubnetFmt,
            // Batch25a: plain-language dashboard status strip, one-click
            // start/stop, help popup and the Settings tier labels.
            DashStatusRunningFmt,
            DashStatusStopped,
            DashStatusAdapterDown,
            DashStatusError,
            DashStart,
            DashStop,
            DashRecheck,
            DashDetails,
            DashHelp,
            DashHelpTitle,
            DashHelpStep1,
            DashHelpStep2Fmt,
            DashHelpStep3,
            DashHelpFootnote,
            DashHelpCopy,
            DashHelpCopied,
            DashHelpNoAddress,
            SettingsCommonGroup,
            SettingsAdvancedGroup,
            SettingsAdvancedHint,
            SettingsInternetMode,
            SettingsInternetAuto,
            SettingsInternetManual,
            // Batch25b: window-close meaning prompt and the first-run wizard
            // (append-only tail; keep `_Count` last).
            ClosePromptTitle,
            ClosePromptBody,
            ClosePromptKeep,
            ClosePromptQuit,
            WizardTitle,
            WizardIntro,
            WizardAdapterLabel,
            WizardModeLabel,
            WizardSaveStart,
            WizardSkip,
            WizardNoAdapter,
            WizardSaved,
            // Batch27: beginner-friendly feedback (short confirmations, busy
            // labels, one-line hints). Append-only tail; keep `_Count` last.
            CommonSaved,
            CommonCopied,
            DashSetup,
            DashStarting,
            DashStopping,
            SettingsSaveErrorHint,
            LeasesEmptyHint,
            AboutAutostartHint,
            SettingsLeaveTitle,
            SettingsLeaveBody,
            SettingsLeaveDiscard,
            // Batch28: short adapter diagnostic line (device path moves to the
            // hover tooltip), page-specific empty states and one plain-language
            // hint per advanced field. Append-only tail; keep `_Count` last.
            SettingsAdapterStatusShortFmt,
            FormDialTimeout,
            PortmapEmptyHint,
            FirewallEmptyHint,
            RatelimitEmptyHint,
            BridgeEmptyHint,
            SettingsHintMode,
            SettingsHintAdapter,
            SettingsHintVlan,
            SettingsHintGatewayIp,
            SettingsHintGatewayMask,
            SettingsHintGatewayMac,
            SettingsHintDhcpEnabled,
            SettingsHintPoolStart,
            SettingsHintPoolEnd,
            SettingsHintLeaseHours,
            SettingsHintDns,
            SettingsHintIpv6Enabled,
            SettingsHintUla,
            SettingsHintPrefixLen,
            SettingsHintRa,
            SettingsHintIpv6Dns,
            SettingsHintDhcp6Enabled,
            SettingsHintDhcp6PoolStart,
            SettingsHintDhcp6PoolEnd,
            SettingsHintDhcp6Lease,
            SettingsHintWebPort,
            SettingsHintWebBind,
            SettingsHintWebEnabled,
            SettingsHintToken,
            SettingsHintWorkers,
            SettingsHintMaxConns,
            SettingsHintDialTimeout,
            SettingsHintBridgeEnabled,
            SettingsHintBridgeUp,
            SettingsHintBridgeDown,
            SettingsHintBridgeTable,
            SettingsHintTheme,
            SettingsHintUiScale,
            /// batch28: instrument hover text (sparkline current/peak).
            SparkCurrentPeakFmt,
            DashSampleTimeFmt,
            /// batch29: sparkline tooltip gains the mean and the range, the
            /// leases column becomes "time left" with human units, the about
            /// page stops naming the CRT, and the tray gains a dashboard item.
            SparkCurrentPeakAvgFmt,
            SparkRangeFmt,
            ColTimeLeft,
            LeaseMinutesFmt,
            LeaseHoursFmt,
            LeaseDaysFmt,
            AboutMemoryManaged,
            AboutDevicePathFmt,
            TrayOpenDashboard,
            /// batch29 (user-reported): the adapter is a PURE select - the
            /// manual-entry placeholder and the free-text field are gone, the
            /// advanced tier shows a read-only device-path row instead.
            AdapterPathLabel,
            AdapterNotDetectedFmt,
            AdapterNotDetectedHint,
            AdapterNoneDetected,
            AdapterNoneDetectedHint,
            /// batch29 fix: the Settings diagnostic line NEVER shows the raw
            /// engine error (English, long, lists every adapter and a
            /// --adapter= hint). One localized short sentence in the body; the
            /// technical detail lives in the tooltip only.
            SettingsAdapterErrorFmt,
            /// batch30: the status word's tooltip when the live curve had to be
            /// hidden because the window is narrower than 760 px.
            DashSparkNarrowHint,
            /// batch33 B: the Win11 Task Manager performance card (title, axis,
            /// the two big send/receive numbers and the adapter line).
            DashThroughput,
            DashAxisSixty,
            DashAxisZero,
            DashSend,
            DashReceive,
            DashAdapterNotBound,
            DashAdapterNoIpv6,
            DashAdapterIpv6Disabled,
            /// batch33 B: the upper bound label suffix when the visible window
            /// is truly flat (min == max), e.g. "1.0 MiB/s, stable".
            SparkStableSuffix,
            /// batch33 B/C: connection type names (IF_TYPE mapping) and the
            /// separators the adapter line is joined with.
            ConnTypeEthernet,
            ConnTypeWifi,
            ConnTypeOther,
            DashPerfCardHint,
            DashTileClientsHint,
            DashTileUptimeHint,
            /// batch33 E: the row context menu entries + the copy confirmation.
            CtxMenuBanDevice,
            CtxMenuLimitDevice,
            CtxMenuViewLeases,
            CtxMenuCopyMac,
            CtxMenuRowHint,
            /// batch37o: standard TextInput context menu entries.
            EditUndo,
            EditRedo,
            EditCut,
            EditPaste,
            EditSelectAll,
            /// batch116: the console page's empty-log placeholder (the only
            /// data page that had none).
            ConsoleEmptyHint,
            /// batch117: command-result text shown in the settings-save toast.
            /// The backend reason (ValidateConfig / SaveToFile / live apply)
            /// is English and is passed through placeholder 0, so only the
            /// surrounding sentence is localized. NOTE: this enum body is
            /// parsed by scripts/gen-native-i18n.mjs up to the FIRST closing
            /// brace followed by a semicolon, so no comment here may contain
            /// that two-character sequence (a placeholder example followed by
            /// punctuation would truncate the parse). Keep examples bare.
            SaveInvalidConfigFmt,
            SaveNoConfigPath,
            SaveWriteFailedFmt,
            SaveAppliedNoLive,
            SaveApplied,
            SaveAppliedRestart,
            SaveLangApplied,
            /// batch118: per-command failure reasons surfaced in the toast
            /// (previously only stderr). Placeholders carry the backend
            /// detail. Enum-body note above applies: no closing brace plus
            /// semicolon inside this comment block.
            CmdTcpOnly,
            CmdLanIpInvalid,
            CmdPortNotZero,
            CmdWanPortTaken,
            CmdPortmapLimit,
            CmdIndexOutOfRange,
            CmdPortmapAdded,
            CmdPortmapRemoved,
            CmdIpInvalid,
            CmdMacInvalid,
            CmdBanKindInvalid,
            CmdBanLimit,
            CmdBanAdded,
            CmdBanRemoved,
            CmdRateBothZero,
            CmdRateLimitLimit,
            CmdRateLimitUpdated,
            CmdRateLimitMissing,
            CmdRateLimitRemoved,
            CmdDhcpDisabled,
            CmdDhcpBindingRejected,
            CmdDhcpBindingAdded,
            CmdDhcpBindingMissing,
            CmdDhcpBindingRemoved,
            CmdDuidEmpty,
            CmdIpv6Invalid,
            CmdDhcp6Disabled,
            CmdDhcp6BindingRejected,
            CmdDhcp6BindingMissing,
            CmdAutostartUnwired,
            CmdServiceAlreadyRunning,
            CmdServiceStarted,
            CmdServiceStopped,
            CmdServiceRechecked,
            /// P87: a stop that succeeded but could not persist the lease
            /// document must not report a clean stop (batch100: Stop returns
            /// true with a non-empty error in that case).
            CmdServiceStoppedDirty,
            /// batch118: driver-repair summary and tray-autostart results,
            /// both user-visible through the same toast path.
            FixRefusedSummary,
            FixStillRunningSummary,
            CommonUnknownError,
            CmdAutostartWriteFailed,
            CmdAutostartEnabled,
            CmdAutostartDisabled,
            /// batch283: a firewall row can be a MAC ban or an IP ban, so the
            /// row menu must name what the copy entry actually puts on the
            /// clipboard instead of always saying "Copy MAC".
            CtxMenuCopyValue,
            /// batch288: a paste can fail because another process holds
            /// the clipboard; it must not look like "nothing to paste".
            ClipboardPasteFailed,
            _Count
        };

        class I18n {
        public:
            static I18n& Instance() noexcept;

            void SetLang(vgww::ui::Lang lang) noexcept;
            /// Batch19 R4-P0: switch by runtime language code (e.g. "en",
            /// "zh-CN", "ar"). The catalog is authoritative for known codes;
            /// an unknown code falls back to en. Returns true when a
            /// translated table was actually installed for `code` (false means
            /// the en table is serving as the fallback).
            bool SetLangCode(const std::string& code);
            /// Active language code ("zh-CN"/"en"/... ; "en" on fallback).
            const std::string& LangCode() const noexcept { return code_; }
            /// Reading direction of the active language (catalog rtl flag).
            bool IsRtl() const noexcept { return rtl_; }
            /// True when `code` is a known catalog language.
            static bool IsKnownLanguageCode(const std::string& code) noexcept;
            /// Runtime language catalog (generated from www; www order).
            static std::size_t LanguageCount() noexcept;
            static const char* LanguageCodeAt(std::size_t index) noexcept;
            static const char* LanguageNameAt(std::size_t index) noexcept;
            static bool LanguageRtlAt(std::size_t index) noexcept;
            /// True when the embedded M1 resource (id 24002) is present in the
            /// running module (test seam for the lazy-load path).
            static bool NativeResourceAvailable() noexcept;
            /// Active language (accessor name is frozen by the S4 plan; the
            /// fully qualified types below are required because a member
            /// named `Lang` hides the enum inside this class scope).
            vgww::ui::Lang Lang() const noexcept;

            /// T()/Format() are UI-THREAD-ONLY: every writer of the
            /// language tables (SetLang / SetLangCode) runs on the UI
            /// thread, so UI-thread readers need no lock. Code that runs
            /// on another thread (the command worker, the elevated-repair
            /// worker) MUST use Copy()/FormatCopy() below, which take the
            /// table mutex: the returned pointer from T() would dangle the
            /// moment a language switch replaced loaded_.
            /// Raw table entry for the active language (L"" on a bad index).
            const wchar_t* T(Str key) const noexcept;

            /// Substitutes single-digit placeholders {0}..{9} in the entry
            /// with `args`; out-of-range placeholders are left verbatim.
            std::wstring Format(Str key,
                                std::initializer_list<std::wstring> args) const;

            /// Number of entries in each table (== static_cast<size_t>(Str::_Count)).
            static std::size_t TableSize() noexcept;

            /// Thread-safe text copy for callers that are NOT on the UI
            /// thread. Same text as T(), but the value is returned by value
            /// under the language-table mutex, so a concurrent SetLangCode
            /// cannot invalidate it.
            std::wstring Copy(Str key) const;

            /// Thread-safe counterpart of Format() for non-UI threads.
            std::wstring FormatCopy(
                Str key, std::initializer_list<std::wstring> args) const;

        private:
            vgww::ui::Lang lang_ = vgww::ui::Lang::ZhCN;
            /// Runtime code of the active language (fallback "en").
            std::string code_ = "zh-CN";
            /// Catalog rtl flag of the active language.
            bool rtl_ = false;
            /// Non-empty when the active language was decoded from the
            /// embedded M1 resource; empty means the resident compiled
            /// zh/en table (`lang_`) is serving.
            bool loaded_valid_ = false;
            std::vector<std::wstring> loaded_;
            /// Unlocked cores; callers hold table_mutex_ or are the UI thread.
            const wchar_t* TUnlocked(Str key) const noexcept;
            std::wstring FormatUnlocked(Str key,
                                     std::initializer_list<std::wstring> args) const;
            /// Serializes SetLang/SetLangCode against Copy()/FormatCopy().
            /// Deliberately NOT taken by T()/Format(): those are UI-thread
            /// only and the writers are UI-thread too, so a lock there
            /// would only add cost to the render hot path.
            mutable std::mutex table_mutex_;
        };

        /// True when no entry is empty in either table.
        bool TableNonEmptyAll() noexcept;

        /// True when zh[i] and en[i] contain the same number of '{' chars.
        bool PlaceholderCountParity() noexcept;

        /// System UI language: "zh*" -> ZhCN, anything else -> En; when the
        /// locale API fails, falls back to ZhCN (plan default).
        Lang DetectSystemLang() noexcept;

    }  // namespace ui
}  // namespace vgww
