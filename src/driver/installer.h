// ============================================================================
// installer.h - First-run driver bootstrap for the ndisrd (WinpkFilter)
// kernel filter. VGWW must be able to run on a machine that has never seen
// the driver: `--install-driver` locates the inf+sys+cat payload triple next
// to vgww.exe, publishes it through pnputil /add-driver, binds the LWF
// component via INetCfg and re-grants the normal-user device DACL.
//
// batch23: the installer no longer registers a boot task. Older releases
// registered a `VGWW-GrantAccess` onstart task; install/upgrade now actively
// removes any legacy task (idempotent), and the app re-grants device access
// in-process at every launch (main.cpp; the process always runs elevated per
// src/vgww.manifest requireAdministrator). `--uninstall-driver` removes the
// driver-store entries, the network component, the legacy SCM residue, the
// System32 copy and the self-heal artifacts (legacy task + ProgramData
// mirror).
//
// Every OS channel (pnputil subprocess, INetCfg session, SCM, schtasks,
// device DACL, filesystem removals) has an injectable seam so the test
// suite runs headless without touching the real machine (batch16 F4).
//
// Requires an elevated process for the install/uninstall/grant actions; the
// shipped manifest requests requireAdministrator, so every launch is elevated
// (the runas recovery paths stay valid and raise no UAC when already elevated).
// ============================================================================
#pragma once

#include <windows.h>

#include <filesystem>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace vgww {
    namespace driver {

        /// Replaces the pnputil subprocess boundary so headless tests can
        /// inject a fake runner (no real driver store needed). The default
        /// (nullptr) spawns %SystemRoot%\System32\pnputil.exe. Returns true
        /// when the process ran; `exit_code` holds its status.
        using PnputilRunner =
            std::function<bool(const std::vector<std::wstring>&,
                               std::string&, DWORD&)>;

        /// Runs a console tool (pnputil/sc) with args, capturing combined
        /// stdout+stderr into `output`. `timeout_ms` bounds the wait for the
        /// child; a child still running at the deadline is terminated (U2).
        /// Returns true once the process has exited; `exit_code` holds its
        /// status. A child terminated at the deadline did NOT exit on its own,
        /// so that path returns false (batch331 P2): a caller must be able to
        /// tell "ran and reported non-zero" from "never completed".
        bool RunProcessCapture(const std::wstring& exe,
                               const std::vector<std::wstring>& args,
                               std::string& output, DWORD& exit_code,
                               DWORD timeout_ms = 120000);

        /// Replaces the console-tool subprocess boundary for one call, so a
        /// test can script the result (including a timeout, reported as
        /// `false`) without spawning schtasks.exe. nullptr = RunProcessCapture.
        using ProcessCaptureRunner =
            std::function<bool(const std::wstring&,
                               const std::vector<std::wstring>&,
                               std::string&, DWORD&)>;

        /// Removes the legacy VGWW-GrantAccess boot task (batch23: the
        /// installer no longer creates it; older releases did, so install and
        /// uninstall retire it). Queries first: deleting a missing task exits
        /// non-zero, and "task absent" is the already-clean success state. A
        /// query that never completed (spawn failure or timeout) is NOT
        /// "absent": it returns false + a reason, so a hung query can never
        /// silently keep the task registered (batch331 P2). `runner` injects
        /// the subprocess boundary (tests); nullptr = the real schtasks.exe.
        bool RemoveBootTask(std::wstring& error,
                            ProcessCaptureRunner runner = nullptr);

        // -------------------------------------------------------------------
        // S5.9: INetCfg programming channel (NDIS LWF component install +
        // binding). pnputil publishes the INF to the driver store; this
        // channel instantiates the network component and binds it to the
        // physical NICs. The abstraction is injectable so headless tests can
        // script the whole sequence without touching the OS. The session type
        // must be declared before the driver install/uninstall entry points
        // below (they take an InetCfgSessionFactory).
        // -------------------------------------------------------------------

        /// One INetCfg session: COM lifetime + write lock + component
        /// install/uninstall + binding, all behind a pure interface. Every
        /// method returns "" on success and a user-presentable description on
        /// failure. `Close()` must be called after a SUCCESSFUL `Open()`
        /// (it pairs with Open and relapses in reverse order:
        /// Uninitialize -> ReleaseWriteLock -> Release -> CoUninitialize);
        /// a failed `Open()` self-cleans (ComInetCfgSession::Open releases
        /// whatever partial state it created), so Close is NOT called then.
        class InetCfgSession {
        public:
            virtual ~InetCfgSession() = default;

            /// CoInitialize + CoCreateInstance(CLSID_CNetCfg);
            /// INetCfg::Initialize runs inside AcquireWriteLock after the
            /// write lock is granted (documented lock order).
            virtual std::string Open() = 0;

            /// INetCfgLock::AcquireWriteLock (blocking up to kLockTimeoutMs).
            virtual std::string AcquireWriteLock() = 0;

            /// INetCfg::FindComponent. `found` receives whether the
            /// component exists; when it does not, returns "" (no error),
            /// `found=false`.
            virtual std::string Find(const std::wstring& inf_id,
                                     bool& found) = 0;

            /// INetCfgClassSetup::Install(pszwInfId, nullptr, 0, 0, nullptr,
            /// nullptr). `installed` receives S_OK-ness.
            virtual std::string Install(const std::wstring& inf_id,
                                        bool& installed) = 0;

            /// Enumerates physical NIC components (class GUID_DEVCLASS_NET,
            /// characteristics & NCF_PHYSICAL) into `device_ids`.
            virtual std::string EnumerateAdapters(
                std::vector<std::wstring>& device_ids) = 0;

            /// Binds the filter component (INF id) to one physical adapter
            /// device (GetBindName / devnode id). `bound` receives whether a
            /// new binding was applied.
            virtual std::string BindToAdapter(const std::wstring& filter_id,
                                              const std::wstring& adapter_id,
                                              bool& bound) = 0;

            /// Unbinds the filter component from one physical adapter.
            virtual std::string UnbindFromAdapter(
                const std::wstring& filter_id,
                const std::wstring& adapter_id,
                bool& unbound) = 0;

            /// INetCfgClassSetup::DeInstall for the component.
            virtual std::string DeInstall(const std::wstring& inf_id,
                                          bool& removed) = 0;

            /// INetCfg::Apply (commit pending changes).
            virtual std::string Apply() = 0;

            /// Uninitialize + ReleaseWriteLock + Release +
            /// CoUninitialize. Pairs exactly with `Open()`/`AcquireWriteLock`.
            virtual void Close() = 0;
        };

        using InetCfgSessionFactory =
            std::function<std::unique_ptr<InetCfgSession>()>;

        /// Checks whether the ndisrd kernel service exists and is running.
        /// (A running device \\.\Ndisrd is not required here: the caller
        /// probes the device separately.)
        bool NdisrdServiceRunning() noexcept;

        /// Probes whether THIS process can open \\.\Ndisrd. Returns true when
        /// the device opens (access sufficient). `access_denied` is set true
        /// when the device exists but the open was refused (ERROR_ACCESS_DENIED)
        /// and false when the device is absent / another error occurred.
        /// Read-only: never changes the DACL.
        bool ProbeDeviceAccess(bool& access_denied) noexcept;

        /// Extracts the `oem##.inf` published name whose original name /
        /// provider marks it as the WinpkFilter/ndisrd driver from a
        /// `pnputil /enum-drivers` transcript. Returns "" when absent.
        std::string ParsePnputilNdisrdOem(const std::string& transcript);

        /// Plural form (batch16 B-9): every published ndisrd entry in
        /// transcript order (a driver-store may hold several versions).
        /// The singular helper above stays a thin wrapper returning the
        /// first entry.
        std::vector<std::string> ParsePnputilNdisrdOems(
            const std::string& transcript);

        /// Set difference `after` minus `before`, preserving `after`
        /// order. Pure function behind the install rollback (batch16 B-9):
        /// only entries published by THIS install may be deleted.
        std::vector<std::string> DiffNewOems(
            const std::vector<std::string>& before,
            const std::vector<std::string>& after);

        /// Retries `attempt` until it succeeds or the budget is exhausted
        /// (at most `attempts` calls, `delay_ms` between failures). Pure
        /// orchestration: the caller owns the real work. A null `attempt`
        /// fails closed.
        bool GrantDeviceAccessWithRetries(const std::function<bool()>& attempt,
                                          int attempts, DWORD delay_ms);

        /// `--grant-access-only` entry (batch16 F5): re-applies the
        /// normal-user DACL to \\.\Ndisrd WITHOUT installing anything (no
        /// pnputil, no INetCfg, no scheduled task). Bounded retry
        /// (60 x 500 ms) covers the device object appearing late after a
        /// driver load. `grant_attempt` (tests) overrides the single real
        /// DACL attempt; nullptr = the real SetKernelObjectSecurity path.
        /// Returns "" on success, otherwise the diagnosis (with the next
        /// step).
        std::string GrantDeviceAccessOnly(
            std::function<bool()> grant_attempt = nullptr);

        /// argv-lines for `pnputil /add-driver <inf> /install`.
        std::vector<std::wstring> BuildAddDriverArgs(
            const std::wstring& inf_path);

        /// argv-lines for `pnputil /delete-driver <oem> /uninstall`.
        std::vector<std::wstring> BuildDeleteDriverArgs(
            const std::wstring& oem_inf);

        /// The co-located payload triple (inf + sys + cat) resolved by
        /// LocateDriverPayload. pnputil requires the .sys/.cat next to the
        /// INF (the INF's SourceDisksFiles), so the locator only accepts a
        /// complete triple inside ONE directory.
        struct DriverPayload {
            std::filesystem::path inf;
            std::filesystem::path sys;
            std::filesystem::path cat;
        };

        /// Locates the driver payload triple (batch16 F3). Candidate
        /// order: base_dir (empty = the exe directory), base_dir\drivers,
        /// base_dir\win10. Size guards: inf >= 1 KiB, sys >= 4 KiB, cat > 0
        /// (the INF declares CatalogFile=ndisrd.cat, so the cat is
        /// required). Returns false and fills `error` (missing/truncated
        /// file names + every tried directory) when no candidate directory
        /// holds a full valid triple.
        bool LocateDriverPayload(const std::filesystem::path& base_dir,
                                 DriverPayload& out, std::wstring& error);

        /// Injection seams for the install path (batch16 F4). Empty
        /// std::function members run the real implementation, so a default
        /// call behaves exactly like production. No env-var short-circuits:
        /// a stray variable must never silently skip the DACL work.
        struct InstallHooks {
            /// Re-grant normal-user access to \\.\Ndisrd (default: the real
            /// bounded DACL retry).
            std::function<bool()> ensure_device_access;
            /// Remove any legacy VGWW-GrantAccess boot task left by older
            /// releases (batch23; default: the real schtasks /query + /delete,
            /// idempotent - an absent task is the success state). A failure is
            /// a warning, not an install failure.
            std::function<bool(std::wstring&)> remove_boot_task;
            /// Retire stale SCM registrations (default: the real
            /// CleanupLegacyServiceRegistration; additive V2 seam so the
            /// full headless success test can keep zero real-SCM contact).
            /// Returns false + a reason when the registration could not be
            /// removed: a dead SERVICE_KERNEL_DRIVER cannot coexist with the
            /// NDIS-bound LWF, so the install must report that instead of
            /// letting pnputil/INetCfg fail later with an unrelated error.
            std::function<bool(std::wstring&)> cleanup_legacy_service;
        };

        /// `<windows_dir>\System32\drivers`. An EMPTY input yields an EMPTY
        /// path: the caller must skip the filesystem work instead of letting
        /// `path(L"")/"System32"/"drivers"` degrade into a RELATIVE path that
        /// resolves against the current working directory (a failed
        /// GetWindowsDirectoryW used to do exactly that, so the System32
        /// cleanup could delete an unrelated same-named file under the CWD).
        std::filesystem::path MakeSystemDriversDir(
            const std::wstring& windows_dir);

        /// Real implementation of UninstallHooks::remove_system32_copy.
        /// `windows_dir` overrides the GetWindowsDirectoryW result so the
        /// headless suite can drive the resolution-failure branch (empty
        /// string = the query failed); nullptr queries the real OS. An
        /// unresolved directory is REPORTED and skipped, never probed
        /// relatively.
        bool RemoveSystem32CopyReal(std::wstring& error,
                                    const std::wstring* windows_dir = nullptr);

        /// True only when a GetEnvironmentVariableW call captured the value
        /// into a MAX_PATH buffer: 0 means "not defined" and a value
        /// >= MAX_PATH means the buffer was too small (the API then returns
        /// the REQUIRED length and leaves the buffer contents undefined).
        /// Both cases must be treated as failure - the old code only checked
        /// for 0 and could build a path from uninitialized/partial text.
        bool EnvValueFitsBuffer(DWORD returned_length);

        /// `<program_data>\VGWW`, or an EMPTY path when `program_data` is
        /// empty (the environment query failed), so no relative path is ever
        /// used to locate or delete a file.
        std::filesystem::path MakeProgramDataPath(
            const std::wstring& program_data);

        /// Injection seams for the uninstall path (batch16 F4/F7). Empty
        /// members run the real implementation. The remover hooks return
        /// false + a reason; failures are reported as residuals.
        struct UninstallHooks {
            /// SCM legacy-service cleanup (default: real DeleteService
            /// path). Returns false + a reason when the stale registration
            /// could not be retired; the uninstall reports it as a residual.
            std::function<bool(std::wstring&)> cleanup_legacy_service;
            /// Remove the VGWW-GrantAccess boot task (default: real
            /// schtasks /query + /delete).
            std::function<bool(std::wstring&)> remove_boot_task;
            /// Remove the %ProgramData%\VGWW\vgww.exe mirror (default:
            /// real, best-effort).
            std::function<bool(std::wstring&)> remove_mirror_copy;
            /// Remove the manual System32\drivers\ndisrd.sys copy (default:
            /// real; a failure must be REPORTED - batch16 F7/B-3).
            std::function<bool(std::wstring&)> remove_system32_copy;
        };

        /// Installs the ndisrd driver via the pnputil INF channel
        /// (defect #1: LWF drivers must load through the NDIS framework, a
        /// bare CreateService start yields 0x1F). Locates the payload
        /// triple (inf+sys+cat) next to the executable, records the
        /// driver-store baseline, clears any legacy-service residue,
        /// publishes the driver and binds it; an INetCfg-stage failure
        /// rolls back only the entries published by this install.
        /// Returns an empty string on success, otherwise a user-presentable
        /// failure description. `runner` overrides the pnputil subprocess
        /// (tests); nullptr = real pnputil.exe. `inetcfg_factory` provides
        /// the INetCfg session used for the component-install + binding
        /// stage (S5.9); nullptr = the real COM session against the running
        /// OS. `hooks` injects the device/SCM/task channels (tests).
        std::string InstallNdisrdDriver(
            PnputilRunner runner = nullptr,
            InetCfgSessionFactory inetcfg_factory = nullptr,
            InstallHooks hooks = {});

        /// Uninstalls every INF-published ndisrd driver entry (plural,
        /// batch16 B-9), unbinds/deinstalls the LWF component, removes the
        /// legacy service if a stale registration exists, drops the manual
        /// System32 copy, and removes the self-heal artifacts (boot task +
        /// ProgramData mirror) so a later boot can never resurrect the
        /// driver. Cleanup failures are reported as residuals (exit
        /// non-zero at the CLI). Returns an empty string on success.
        /// `inetcfg_factory` provides the INetCfg session used for the
        /// unbind + DeInstall stage (S5.9); nullptr = the real COM session.
        /// `hooks` injects the SCM/task/mirror/System32 channels (tests).
        std::string UninstallNdisrdDriver(
            PnputilRunner runner = nullptr,
            InetCfgSessionFactory inetcfg_factory = nullptr,
            UninstallHooks hooks = {});

        // -------------------------------------------------------------------
        // S5.9: INetCfg programming channel orchestration helpers. The pure
        // session interface and factory are declared at the top of this
        // header (above the driver install/uninstall entry points that take
        // the factory as a defaulted parameter).
        // -------------------------------------------------------------------

        /// Default factory: a real COM session against the running OS.
        InetCfgSessionFactory CreateComInetCfgSessionFactory();

        /// Installs the ndisrd LWF component through INetCfg and binds it to
        /// every physical NIC. Returns "" on success, otherwise a diagnosis.
        /// The caller must already have published the INF (pnputil).
        std::string InstallNdisrdLwfComponent(InetCfgSession& session);

        /// Unbinds the ndisrd LWF component from every adapter and removes
        /// the network component (INetCfg DeInstall + Apply). Returns "" on
        /// success, otherwise a diagnosis. The caller then runs
        /// `pnputil /delete-driver`.
        std::string UninstallNdisrdLwfComponent(InetCfgSession& session);

        // -------------------------------------------------------------------
        // Install-report IO (batch16 F2): the elevated `--install-driver`
        // child publishes its outcome so the non-elevated parent can show
        // the real diagnosis instead of guessing. The child writes
        // status=running at entry (best-effort) and overwrites it with
        // ok/fail on exit; the parent only trusts a complete ok/fail
        // document (running/missing/malformed = "the child did not report
        // completion"). A write failure must never change the child's exit
        // code.
        // -------------------------------------------------------------------

        /// Parsed install report.
        struct InstallReport {
            std::string status;  ///< "running" | "ok" | "fail" | "" (none/bad)
            int exit_code = 1;   ///< child exit code (default: failure)
            std::string detail;  ///< full error text (may be empty)
        };

        /// %ProgramData%\VGWW\install-report.txt
        std::filesystem::path DefaultInstallReportPath();

        /// Best-effort write; creates the parent directory. Returns false
        /// when the file could not be written (callers ignore this).
        bool WriteInstallReport(const std::filesystem::path& path,
                                const std::string& status, int exit_code,
                                const std::string& detail);

        /// Reads the report; a missing or malformed file yields
        /// `status==""` ("did not report completion").
        InstallReport ReadInstallReport(const std::filesystem::path& path);

        /// Outcome of an elevated `--install-driver` one-shot.
        enum class ElevatedInstallOutcome {
            InstallOk,         ///< child exited and reported status=ok
            InstallFailed,     ///< child exited; fail/missing/malformed report
            StillRunning,      ///< the wait window elapsed, child still alive
            ElevationRefused,  ///< runas refused (UAC cancel) or spawn error
        };

        struct ElevatedInstallResult {
            ElevatedInstallOutcome outcome =
                ElevatedInstallOutcome::InstallFailed;
            DWORD spawn_error = 0;  ///< for ElevationRefused
            DWORD exit_code = 1;    ///< child exit code when it exited
            std::string detail;     ///< diagnosis / full report text
        };

        /// Spawns THIS executable elevated (`--install-driver`, runas,
        /// SW_HIDE, SEE_MASK_NOCLOSEPROCESS) and waits up to `wait_ms`.
        /// The child publishes the report file (WriteInstallReport); the
        /// parent only trusts status=ok with exit 0 - running, missing or
        /// malformed reports count as "did not report completion" and are
        /// failures (batch16 F2). A best-effort stale-report delete runs
        /// before the spawn; correctness does not depend on it.
        ElevatedInstallResult RunElevatedInstallAndWait(
            DWORD wait_ms = 90000);

        /// Spawns this executable elevated with `--grant-access-only`
        /// (runas, SW_HIDE, SEE_MASK_NOCLOSEPROCESS) and waits up to
        /// `wait_ms`. Returns true when the child exited 0 (the DACL was
        /// re-applied). No report file: the caller probes the device with
        /// its own retry loop. batch23: the process always runs elevated
        /// (requireAdministrator), so the runas child is already elevated and
        /// no UAC appears; the startup grant now runs in-process, this helper
        /// is retained for callers that want an isolated child.
        bool RunElevatedGrantAccessOnlyWait(DWORD wait_ms = 30000);

    }  // namespace driver
}  // namespace vgww
