// ============================================================================
// main.cpp - VGWW entry point and lifecycle owner.
//
// Boot order: parse config -> start data plane -> start HttpServer (--web /
// --web-only, default on). This build has no embedded GUI shell (removed in
// S4.1): the WebUI dashboard is served over HTTP for the operator's own
// browser while the gateway keeps running.
// ============================================================================
#include <winsock2.h>
#include <windows.h>
#include <sddl.h>

#include "main.h"

#include "runtime/dataplane.h"
#include "driver/error_class.h"
#include "driver/installer.h"
#include "driver/ndisrd_client.h"
#include "web/web_api.h"

#include "ui/app.h"
#include "ui/console_log.h"
#include "ui/controller.h"
#include "ui/debug/ui_debug_server.h"
#include "ui/restart.h"
#include "ui/single_instance.h"
#include "ui/tray.h"

namespace {
// batch22 B4: the web API needs the live UI to service privileged requests
// (driver repair) while it is registered before the UI exists.
std::atomic<vgww::ui::UiApp*> g_ui_app{nullptr};
}  // namespace

#include "core/handler_guard.h"
#include "core/memory.h"
#include "core/random.h"

#include <shellapi.h>

#include <algorithm>
#include <atomic>
#include <cstdio>
#include <filesystem>
#include <io.h>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace {

    using vgww::core::Config;
    using vgww::runtime::Dataplane;

    /// Set by the console control handler; the main loop parks until it is
    /// nonzero, then unwinds normally (Dataplane::Stop runs, restoring the
    /// adapter to its filtered mode - ExitProcess would skip that reset).
    /// Set from the console-control callback thread and read by the main
    /// loop: a plain bool would be a cross-thread data race (UB), so make
    /// it atomic.
    std::atomic<bool> g_stop{false};

    BOOL WINAPI ConsoleCtrlHandler(DWORD event) {
        if (CTRL_C_EVENT == event || CTRL_BREAK_EVENT == event ||
            CTRL_CLOSE_EVENT == event) {
            g_stop.store(true);
            return TRUE;  // handled: the main loop does the teardown
        }

        return FALSE;  // not ours (e.g. CTRL_LOGOFF_EVENT): default
    }

    bool HasFlag(const std::vector<std::string>& args,
                 const std::string& flag) noexcept {
        return args.end() != std::find(args.begin(), args.end(), flag);
    }

    void EnsureConsole() noexcept {
        if (::GetConsoleWindow() != nullptr) {
            return;
        }

        const HANDLE out_handle = ::GetStdHandle(STD_OUTPUT_HANDLE);
        const HANDLE err_handle = ::GetStdHandle(STD_ERROR_HANDLE);

        const bool out_valid = (nullptr != out_handle &&
                                INVALID_HANDLE_VALUE != out_handle);
        const bool err_valid = (nullptr != err_handle &&
                                INVALID_HANDLE_VALUE != err_handle);

        // If both handles are already valid (piped launch), keep them;
        // reopening to CONOUT$ would break pipe capture.
        if (out_valid && err_valid) {
            return;
        }

        if (::AttachConsole(ATTACH_PARENT_PROCESS)) {
            if (!out_valid) {
                FILE* out = nullptr;

                ::freopen_s(&out, "CONOUT$", "w", stdout);
                (void)out;
            }

            if (!err_valid) {
                FILE* err = nullptr;

                ::freopen_s(&err, "CONOUT$", "w", stderr);
                (void)err;
            }
        } else {
            ::AllocConsole();

            FILE* out = nullptr;
            FILE* err = nullptr;

            ::freopen_s(&out, "CONOUT$", "w", stdout);
            ::freopen_s(&err, "CONOUT$", "w", stderr);
            (void)out;
            (void)err;
        }
    }

    /// Batch19 R3-1: the exe is linked as a GUI-subsystem image, so an
    /// interactive `cmd` launch has no inherited console of its own. The
    /// one-shot CLI flags (--version/--help/--install-driver/...) print once
    /// and exit; attach to the PARENT console so those lines are visible.
    /// Deliberately attach-only: a double-click (no parent console) stays
    /// silent instead of popping an AllocConsole window, and a piped /
    /// redirected launch keeps its already-valid handles (never reopen them
    /// to CONOUT$, which would break capture).
    void AttachParentConsoleForCli() noexcept {
        const HANDLE out_handle = ::GetStdHandle(STD_OUTPUT_HANDLE);
        const HANDLE err_handle = ::GetStdHandle(STD_ERROR_HANDLE);
        const bool out_valid = (nullptr != out_handle &&
                                INVALID_HANDLE_VALUE != out_handle);
        const bool err_valid = (nullptr != err_handle &&
                                INVALID_HANDLE_VALUE != err_handle);
        if (out_valid && err_valid) {
            return;  // piped / redirected: the CRT handles are real
        }
        if (::GetConsoleWindow() == nullptr &&
            !::AttachConsole(ATTACH_PARENT_PROCESS)) {
            return;  // double-click: no console to attach; stay silent
        }
        if (!out_valid) {
            FILE* out = nullptr;
            ::freopen_s(&out, "CONOUT$", "w", stdout);
            (void)out;
        }
        if (!err_valid) {
            FILE* err = nullptr;
            ::freopen_s(&err, "CONOUT$", "w", stderr);
            (void)err;
        }
    }

    std::string WideToUtf8(const wchar_t* wide) {
        if (nullptr == wide) {
            return {};
        }

        const int needed = ::WideCharToMultiByte(
            CP_UTF8, 0, wide, -1, nullptr, 0, nullptr, nullptr);

        if (needed <= 0) {
            return {};
        }

        std::string out(static_cast<size_t>(needed), '\0');

        ::WideCharToMultiByte(
            CP_UTF8, 0, wide, -1, out.data(), needed, nullptr, nullptr);

        out.pop_back();  // drop the NUL terminator the API appended
        return out;
    }

    int RunVgww(int argc, char** argv) {
        std::vector<std::string> args(argv + (argc > 0 ? 1 : 0), argv + argc);

        vgww::StartupOptions options =
            vgww::ParseStartupOptions(args);

        // batch23: single-instance gate via a named kernel EVENT (replaces the
        // batch20 named mutex). ONLY --headless bypasses it (no window to
        // activate). --ui-debug-port / --ui-page USED TO bypass too; batch37h
        // removed them because a debug instance and a normal launch would
        // then coexist as two visible apps. See the gate comment further down.
        //
        // First launch: CREATE the event (Primary) and run a watcher thread
        // that turns a signal into a window activation. Second launch: the
        // event already exists, so signal it (the activation request) and exit
        // 0. The secondary also activates directly (best effort) because it
        // still owns the foreground right and must hand it over - measured P3:
        // without the hand-off the restored window appeared but did not take
        // the foreground.
        struct InstanceWatcher {
            HANDLE event = nullptr;
            std::thread thread;
            std::atomic<bool>* stop = nullptr;

            ~InstanceWatcher() { Reset(); }

            // Idempotent: wakes and joins the watcher, then closes the handle.
            void Reset() noexcept {
                if (thread.joinable()) {
                    if (stop != nullptr) {
                        stop->store(true);
                    }
                    if (event != nullptr) {
                        ::SetEvent(event);  // wake the waiting loop
                    }
                    thread.join();
                }
                if (event != nullptr) {
                    ::CloseHandle(event);
                    event = nullptr;
                }
            }
        };
        std::atomic<bool> instance_stop{false};
        InstanceWatcher instance_watcher;
        /// Detached-thread bodies that threw and were reported instead of
        /// terminating the process (telemetry; a std::thread body is its own
        /// entry point, so an escape is fatal).
        static std::atomic<uint64_t> instance_watcher_errors{0};
        static std::atomic<uint64_t> config_apply_errors{0};

        // batch37h (user): a GUI launch must ALWAYS participate in the
        // single-instance gate. Only a headless run (no window) may bypass it;
        // --ui-debug-port/--ui-page used to bypass too, which let a debug
        // instance and a normal launch coexist as two visible apps.
        // P87: the predicate is the testable BypassesSingleInstanceGate()
        // (options.headless), not a local literal scan, so the gate and its
        // tests cannot drift apart. --web-only is headless too, so it bypasses.
        const bool headless_run =
            vgww::BypassesSingleInstanceGate(args);
        if (!headless_run) {
            const vgww::ui::InstanceClaim claim =
                vgww::ui::ClaimSingleInstance();
            if (claim.role == vgww::ui::InstanceRole::Secondary) {
                // Another instance owns the gate. It has been signalled (when
                // possible); activate it directly too for the foreground
                // hand-off, then exit. This short exit never starts the GUI,
                // so the runas/--grant-access-only children (which are not the
                // primary launch path) are unaffected.
                (void)vgww::ui::ActivateRunningInstance();
                return 0;  // the running instance handles the activation
            }
            instance_watcher.event = claim.event;  // may be null (degraded)
            if (instance_watcher.event != nullptr) {
                instance_watcher.stop = &instance_stop;
                HANDLE ev = instance_watcher.event;
                std::atomic<bool>* stop_flag = &instance_stop;
                instance_watcher.thread = std::thread([ev, stop_flag] {
                    ::vgww::core::RunDetachedBodyGuarded(
                        instance_watcher_errors, [&] {
                            while (!stop_flag->load()) {
                                if (WAIT_OBJECT_0 !=
                                    ::WaitForSingleObject(ev, INFINITE)) {
                                    break;
                                }
                                if (stop_flag->load()) {
                                    break;
                                }
                                // The window may not exist yet (a second
                                // launch during our own startup): retry
                                // briefly.
                                for (int i = 0;
                                     i < 50 && !stop_flag->load(); ++i) {
                                    if (vgww::ui::ActivateRunningInstance()) {
                                        break;
                                    }
                                    ::Sleep(100);
                                }
                            }
                        },
                        [] {});
                });
            }
        }

        // Batch19 R3-1: the one-shot CLI flags print and exit. In the GUI
        // subsystem build an interactive cmd launch has no inherited console,
        // so attach to the parent console first (attach-only; pipes and
        // redirection keep their handles). Normal UI runs never allocate or
        // pop a console.
        if (HasFlag(args, "--version") || HasFlag(args, "--help") ||
            HasFlag(args, "--install-driver") ||
            HasFlag(args, "--uninstall-driver") ||
            HasFlag(args, "--grant-access-only")) {
            AttachParentConsoleForCli();
        }

        // S5.20: whitelist the --ui-page value at the consumption point (the
        // UI start page). An unknown/empty id degrades to the default home
        // page instead of aborting startup - the test bridge must still
        // produce a screenshot frame for the vision model.
        if (!options.ui_page.empty() && !vgww::IsKnownUiPage(options.ui_page)) {
            std::fprintf(stderr,
                         "vgww: unknown --ui-page '%s' (expected one of "
                         "dashboard|firewall|portmap|ratelimit|settings|"
                         "bridge|leases|about|console)\n",
                         options.ui_page.c_str());
            options.ui_page.clear();
        }

        // --console needs a visible console even when built as WINDOWS.
        if (options.console) {
            EnsureConsole();
        }

        // --version: report build identity including the active memory backend.
        if (HasFlag(args, "--version")) {
            std::printf(
                "VGWW - Virtual Gateway for Windows v0.1.0\n"
                "memory backend: %s (%s)\n",
                vgww::core::MemoryBackendName(),
                vgww::core::MemoryBackendVersion());
            return 0;
        }

        // --help: single source of truth via PrintUsageString().
        if (HasFlag(args, "--help")) {
            vgww::PrintUsage();
            return 0;
        }

        // --install-driver: one-shot driver install/re-grant. The process now
        // always runs elevated (manifest requireAdministrator), so this flag is
        // mainly a manual/automation entry; the first-run bootstrap and the
        // UI/web repair paths still spawn it through ShellExecuteEx "runas"
        // (an already-elevated parent raises no UAC). The child publishes its
        // outcome to the install report (status=running at entry, then ok/fail)
        // so the hidden console cannot swallow the diagnosis (batch16 F2).
        if (HasFlag(args, "--install-driver")) {
            const std::filesystem::path report =
                vgww::driver::DefaultInstallReportPath();
            (void)vgww::driver::WriteInstallReport(report, "running", 0, "");
            const std::string err = vgww::driver::InstallNdisrdDriver();
            if (err.empty()) {
                (void)vgww::driver::WriteInstallReport(report, "ok", 0, "");
                std::printf("vgww: ndisrd driver installed OK\n");
                return 0;
            }
            (void)vgww::driver::WriteInstallReport(report, "fail", 1, err);
            std::fprintf(stderr, "vgww: %s\n", err.c_str());
            return 1;
        }

        // --uninstall-driver: remove the ndisrd driver (INetCfg unbind +
        // pnputil delete). Mirrors --install-driver; same exit semantics.
        if (HasFlag(args, "--uninstall-driver")) {
            const std::string err = vgww::driver::UninstallNdisrdDriver();
            if (err.empty()) {
                std::printf("vgww: ndisrd driver uninstalled OK\n");
                return 0;
            }
            std::fprintf(stderr, "vgww: %s\n", err.c_str());
            return 1;
        }

        // --grant-access-only: re-apply the normal-user DACL on
        // \\.\Ndisrd WITHOUT installing anything (no pnputil, no INetCfg,
        // no scheduled task). Still useful as a manual recovery; the
        // access-denied recovery below invokes the same DACL logic in-process.
        if (HasFlag(args, "--grant-access-only")) {
            const std::string err = vgww::driver::GrantDeviceAccessOnly();
            if (err.empty()) {
                std::printf("vgww: device access granted OK\n");
                return 0;
            }
            std::fprintf(stderr, "vgww: %s\n", err.c_str());
            return 1;
        }

        // batch23: the process now ALWAYS runs elevated (manifest
        // requireAdministrator), so a launch can re-apply the ndisrd device
        // DACL in-process - no runas child, no UAC, no boot task. The ndisrd
        // device is recreated without the normal-user DACL on every driver
        // (re)load, so re-grant here when the driver is installed but this
        // process cannot open the device. At most once per start; TEST launches
        // (--ui-debug-port/--ui-page/--headless) and the one-shot CLI flags
        // skip it so the automation pipeline is never disturbed.
        if (!vgww::ui::IsTestLaunch(args) &&
            !HasFlag(args, "--install-driver") &&
            !HasFlag(args, "--uninstall-driver") &&
            !HasFlag(args, "--grant-access-only") &&
            vgww::driver::NdisrdServiceRunning()) {
            bool access_denied = false;
            if (!vgww::driver::ProbeDeviceAccess(access_denied) &&
                access_denied) {
                const std::string grant_error =
                    vgww::driver::GrantDeviceAccessOnly();
                if (!grant_error.empty()) {
                    std::fprintf(stderr,
                                 "vgww: device access re-grant failed: %s\n",
                                 grant_error.c_str());
                }
            }
        }

        // Batch19 R3-2: capture stdout/stderr into the bounded ring that feeds
        // the native console page. Installed after the one-shot CLI early exits
        // (so --version/--help are never routed through the pipe) and before
        // config loading, so the config warnings and the WebUI URL land in the
        // page. Only UI runs need it. The reader thread tees back to an
        // existing console, so --console keeps showing output, and the guard
        // uninstalls on every return path (a joinable std::thread at process
        // exit would call std::terminate).
        const bool console_capture =
            options.ui && vgww::ui::console_log::Install();
        struct CaptureGuard {
            bool on = false;
            ~CaptureGuard() {
                if (on) {
                    vgww::ui::console_log::Uninstall();
                }
            }
        } capture_guard{console_capture};

        const vgww::ConfigPathResult config_arg =
            vgww::ParseConfigPathArg(args);

        // An explicit --config with no usable value must NOT reach the
        // auto-discovery branch below: that branch answers "the operator said
        // nothing", and running on some other config file hides the mistake.
        if (config_arg.status == vgww::ConfigPathStatus::kInvalid) {
            std::fprintf(stderr, "vgww: %s\n", config_arg.error.c_str());
            return 1;
        }

        std::string config_path = config_arg.path;

        if (config_arg.status == vgww::ConfigPathStatus::kNotGiven) {
            // Super-large usability: double-click without --config should still
            // show the white native GUI. Try exe-dir/config.json then
            // exe-dir/config.example.json before bailing to usage.
            std::wstring exe_w;
            DWORD cap = MAX_PATH;
            while (true) {
                exe_w.resize(cap);
                DWORD got = ::GetModuleFileNameW(nullptr, exe_w.data(), cap);
                if (0 == got) break;
                if (got < cap) { exe_w.resize(got); break; }
                if (cap >= 32767) break;
                cap *= 2;
            }
            if (!exe_w.empty()) {
                std::filesystem::path exe_dir = std::filesystem::path(exe_w).parent_path();
                for (auto cand : {exe_dir / "config.json", exe_dir / "config.example.json",
                                  exe_dir / "../../config.json", exe_dir / "../../config.example.json",
                                  std::filesystem::path("config.json"), std::filesystem::path("config.example.json"),
                                  std::filesystem::path("../../config.json"), std::filesystem::path("../../config.example.json")}) {
                    if (std::filesystem::exists(cand)) { config_path = cand.string(); break; }
                }
            }
            if (config_path.empty()) {
                // Batch19 R3-1: usage is a CLI one-shot too (GUI subsystem).
                AttachParentConsoleForCli();
                vgww::PrintUsage();
                std::fprintf(stderr, "vgww: no --config given and no config.json/config.example.json found next to exe\n");
                return 2;
            }
            // G-5 F6: the fallback chain used to pick a config silently; say
            // which file was auto-selected (this branch only runs when no
            // --config was given).
            std::fprintf(stderr, "vgww: auto-selected config: %s\n",
                         config_path.c_str());
        }

        std::string error;
        std::optional<Config> config = Config::LoadFromFile(config_path, error);

        if (!config) {
            std::fprintf(stderr, "vgww: %s\n", error.c_str());
            return 1;
        }

        if (!config->ApplyCliOverrides(args, error)) {
            std::fprintf(stderr, "vgww: %s\n", error.c_str());
            return 1;
        }

        // Flag interpretation (S4.4): the HTTP management server is OPT-IN (--web /
        // --web-only; --no-web is a redundant no-op); --web-only skips the data
        // plane entirely. The native UI runs by default (unless --headless).
        const bool web_only = options.web_only;
        // batch20 P2: the Web UI is ON by default (config.web.enabled
        // defaults to true); --web forces it on, --no-web forces it off.
        const bool web = vgww::core::WebEnabledEffective(
            config->web.enabled, options.web, options.no_web);

        // Anchor DHCP lease persistence next to the config file (same
        // convention as the ".rules.json" store): a bare "leases.json" would
        // resolve against the process CWD, so a service restart from a
        // different directory would silently lose every dynamic lease.
        Dataplane dataplane(*config, config_path + ".leases.json");
        // Dataplane startup error text for the UI's degraded view (T7 wiring).
        std::string dataplane_error_text;
        // S3-Task4-F1: wire the file schema bridge section into the
        // runtime bridge loop (Task3 seam). Field names match 1:1; the
        // upstream==primary constraint stays enforced in
        // Dataplane::Start with docs D7 (no STP/RSTP anywhere).
        {
            vgww::bridge::BridgeConfig bridge_config;
            bridge_config.enabled = config->bridge.enabled;
            bridge_config.upstream = config->bridge.upstream;
            bridge_config.downstream = config->bridge.downstream;
            bridge_config.mac_table_size = config->bridge.mac_table_size;
            dataplane.SetBridgeConfig(bridge_config);
        }
        // Degraded mode: the data plane could not start, but the WebUI MUST
        // still come up (a silent exit is what made a double-click look
        // like "nothing happens").
        bool dataplane_failed = false;

        if (!web_only) {
            // First-run bootstrap: the target machine may never have had the
            // WinpkFilter kernel driver. The process already runs elevated
            // (manifest requireAdministrator), but the install still goes
            // through the one-shot --install-driver child so the report
            // handshake (batch16 F2) is preserved. The payload is pre-checked
            // FIRST, the child's outcome comes back through the install
            // report, and every outcome has a visible diagnosis.
            std::string driver_bootstrap_note;
            if (!vgww::driver::NdisrdServiceRunning()) {
                vgww::driver::DriverPayload payload;
                std::wstring payload_error;
                if (!vgww::driver::LocateDriverPayload({}, payload,
                                                       payload_error)) {
                    const std::string detail =
                        WideToUtf8(payload_error.c_str());
                    std::fprintf(stderr,
                                 "vgww: %s\n"
                                 "vgww: skipping elevation (driver payload "
                                 "incomplete). To install manually, run "
                                 "vgww.exe --install-driver as Administrator; "
                                 "see docs/zh/driver-install.md\n",
                                 detail.c_str());
                    driver_bootstrap_note =
                        detail +
                        "\nThe driver payload is incomplete, so the automatic "
                        "install was skipped. Run vgww.exe --install-driver as "
                        "Administrator; see docs/zh/driver-install.md";
                } else {
                    std::fprintf(stderr, "vgww: ndisrd driver not running - "
                                         "requesting elevation to install it...\n");
                    const vgww::driver::ElevatedInstallResult install =
                        vgww::driver::RunElevatedInstallAndWait();
                    bool wait_for_service = false;
                    switch (install.outcome) {
                        case vgww::driver::ElevatedInstallOutcome::InstallOk:
                            std::printf(
                                "vgww: ndisrd driver installed OK, continuing\n");
                            wait_for_service = true;
                            break;
                        case vgww::driver::ElevatedInstallOutcome::
                            ElevationRefused:
                            std::fprintf(stderr,
                                         "vgww: elevation refused or failed "
                                         "(%lu) - please run vgww.exe once as "
                                         "Administrator\n",
                                         static_cast<unsigned long>(
                                             install.spawn_error));
                            break;
                        case vgww::driver::ElevatedInstallOutcome::StillRunning:
                            // Do not read a half-written report: the child
                            // is still installing; carry on and let the
                            // dataplane-start result decide.
                            std::fprintf(stderr,
                                         "vgww: installer still running; "
                                         "continuing\n");
                            wait_for_service = true;
                            break;
                        case vgww::driver::ElevatedInstallOutcome::InstallFailed:
                            std::fprintf(stderr,
                                         "vgww: driver install failed: %s\n",
                                         install.detail.c_str());
                            driver_bootstrap_note = install.detail;
                            break;
                    }
                    if (wait_for_service) {
                        // Wait for the service to appear (SCM install is
                        // fast); a timeout gets an explicit line instead of
                        // silently falling through.
                        for (int i = 0;
                             i < 30 && !vgww::driver::NdisrdServiceRunning();
                             ++i) {
                            ::Sleep(500);
                        }
                        if (!vgww::driver::NdisrdServiceRunning()) {
                            std::fprintf(
                                stderr,
                                "vgww: installed but service not reported "
                                "running yet; continuing to dataplane start\n");
                        }
                    }
                }
            }

            if (!dataplane.Start(error)) {
                const std::string first_error = error;
                // Classified recovery (batch16 F1/F5): the error text is
                // never matched with ad-hoc substrings here; the classifier
                // is the single home of those literals.
                const vgww::driver::DriverFault fault =
                    vgww::driver::ClassifyDriverFault(first_error);
                bool recovered = false;
                if (vgww::driver::DriverFault::AccessDenied == fault) {
                    // The driver recreates \\.\Ndisrd on every load WITHOUT
                    // the normal-user DACL. The device exists (access was
                    // denied, not missing), so the minimal and robust fix is
                    // the grant-only path - it re-applies the DACL and cannot
                    // die on a repeat pnputil add the way a full install
                    // could. batch23: the process already runs elevated, so
                    // re-apply the DACL IN-PROCESS (no runas child, no UAC);
                    // this is the same logic the startup early-grant uses.
                    std::fprintf(stderr, "vgww: device access lost - "
                                         "re-granting normal-user access "
                                         "in-process...\n");
                    const std::string grant_error =
                        vgww::driver::GrantDeviceAccessOnly();
                    if (!grant_error.empty()) {
                        std::fprintf(stderr, "vgww: %s\n",
                                     grant_error.c_str());
                    }
                    for (int i = 0; i < 120 && !recovered; ++i) {
                        ::Sleep(500);
                        error.clear();
                        if (dataplane.Start(error)) {
                            recovered = true;
                        }
                    }
                    if (!recovered) {
                        std::fprintf(stderr,
                                     "vgww: device access still denied - run "
                                     "vgww.exe --install-driver as "
                                     "Administrator; see "
                                     "docs/zh/driver-install.md\n");
                    }
                } else if (vgww::driver::DriverFault::DriverMissing == fault) {
                    // First-install race: the service may report RUNNING
                    // while the driver is still creating \\.\Ndisrd. Bounded
                    // retry (<=10 s), never a second UAC prompt.
                    for (int i = 0; i < 20 && !recovered; ++i) {
                        ::Sleep(500);
                        error.clear();
                        if (dataplane.Start(error)) {
                            recovered = true;
                        }
                    }
                    if (!recovered) {
                        std::fprintf(stderr,
                                     "vgww: driver still unavailable - run "
                                     "vgww.exe --install-driver as "
                                     "Administrator; see "
                                     "docs/zh/driver-install.md\n");
                    }
                }
                if (!recovered) {
                    // Never exit silently: tell the operator, then continue in
                    // degraded mode so the window/UI still appears (the native
                    // UI shows the failure and offers an elevated fix). The
                    // bootstrap diagnosis survives into the banner text.
                    dataplane_failed = true;
                    dataplane_error_text = driver_bootstrap_note.empty()
                        ? first_error
                        : (driver_bootstrap_note + "\n" + first_error);
                    std::fprintf(stderr, "vgww: dataplane startup failed: %s "
                                         "- continuing in degraded mode\n",
                                 first_error.c_str());
                }
            }
        }

        // Embedded WebUI (user mandate: in-process, lightweight).
        // Security default: if no token is configured, one is generated here so
        // the 0.0.0.0 listener is never left wide open for LAN devices to
        // rewrite port maps / firewall rules. Print it once to the console.
        // Entropy comes straight from the OS CSPRNG (BCryptGenRandom): seeding a
        // PRNG would collapse the token to ~32 bits of seed, which a LAN host
        // could brute-force - the token gates the whole management API.
        std::string web_token = config->web.token;

        if (web_token.empty()) {
            web_token = vgww::core::RandomHex(16);

            if (web_token.empty()) {
                std::fprintf(stderr, "vgww: failed to generate auth token\n");
                return 1;  // fail closed: never run unauthenticated
            }
        }

        // batch37s (user: settings must apply immediately): the running WebUI
        // credential and the config object are shared with the settings apply
        // hook. The token has its own lock; the config swap is serialized
        // against the snapshot publisher (see UiRuntimeFlags::config_mutex).
        auto web_auth = std::make_shared<vgww::web::AuthTokenState>();
        web_auth->Set(web_token, !config->web.token.empty());
        auto config_mutex = std::make_shared<std::mutex>();
        auto web_enabled_live =
            std::make_shared<std::atomic<bool>>(web);
        bool web_running = false;

        vgww::web::HttpServer http;

        // Single-file distribution: the WebUI index.html is embedded into the
        // executable (RCDATA 24001, see CMakeLists vgww_webui.rc). Serve it
        // from memory so no www/ folder is required on disk; the exe-relative
        // www/ copy remains as a dev-run fallback when the resource is absent.
        {
            // 24001 = RCDATA id (CMakeLists vgww_webui.rc); RT_RCDATA would
            // expand to a narrow MAKEINTRESOURCE - use the wide form.
            HRSRC res = ::FindResourceW(nullptr, MAKEINTRESOURCEW(24001),
                                        MAKEINTRESOURCEW(10) /* RT_RCDATA */);
            if (nullptr != res) {
                const HGLOBAL hg = ::LoadResource(nullptr, res);
                const void* data = (nullptr != hg) ? ::LockResource(hg) : nullptr;
                const DWORD size =
                    (nullptr != hg) ? ::SizeofResource(nullptr, res) : 0;
                if (nullptr != data && size > 0) {
                    std::string html(static_cast<const char*>(data), size);
                    http.ServeEmbedded("/index.html", html,
                                       "text/html; charset=utf-8");
                }
            }
        }

        // Resolve the WebUI assets relative to the executable so a service
        // launch (or any working directory) does not 404 the console; fall
        // back to "www" next to the current directory for in-tree dev runs
        // where the exe lives in build/<cfg> without a copy of the UI.
        {
            std::wstring exe_path_w;
            DWORD cap = MAX_PATH;

            while (true)
            {
                exe_path_w.resize(cap);

                DWORD got = ::GetModuleFileNameW(nullptr, exe_path_w.data(), cap);

                if (0 == got)
                {
                    break;
                }

                if (got < cap)
                {
                    exe_path_w.resize(got);
                    std::string www_dir = "www";
                    const std::filesystem::path exe_dir =
                        std::filesystem::path(exe_path_w).parent_path();
                    const std::filesystem::path peer = exe_dir / "www";

                    if (std::filesystem::exists(peer / "index.html"))
                    {
                        www_dir = peer.string();
                    }

                    http.ServeStatic(www_dir);
                    goto serve_done;
                }

                if (cap >= 32767)
                {
                    break;
                }

                cap *= 2;
            }

            {
                std::string www_dir = "www";
                http.ServeStatic(www_dir);
            }

        serve_done:;
        }

        // batch37u: one shared live-apply path for both entry points. The
        // native settings command calls it from the command thread; the
        // headless WebUI config save calls it from a detached worker (never
        // from an HTTP worker, which http.Stop would self-join). The mutex
        // serializes concurrent Web saves.
        std::mutex apply_mutex;
        auto apply_config_live = [&](const Config& next,
                                     std::wstring& error) -> bool {
            std::lock_guard<std::mutex> apply_lock(apply_mutex);
            const Config previous = *config;
            const bool was_running = dataplane.IsRunning();
            const bool was_web_running = web_running;
            const bool prev_web_enabled = web_enabled_live->load();
            const vgww::web::AuthTokenSnapshot prev_auth = web_auth->Get();
            // batch37q (user: bridge settings did not apply): the bridge
            // config is a separate copy inside Dataplane, so a config swap +
            // restart alone left the old bridge running.
            const auto apply_bridge = [&dataplane](const Config& c) {
                vgww::bridge::BridgeConfig bc;
                bc.enabled = c.bridge.enabled;
                bc.upstream = c.bridge.upstream;
                bc.downstream = c.bridge.downstream;
                bc.mac_table_size = c.bridge.mac_table_size;
                dataplane.SetBridgeConfig(bc);
            };

            // batch37s: stop the HTTP workers before swapping the config
            // object they read on request threads; the listener is restarted
            // on the (possibly new) bind/port below.
            if (web_running) {
                http.Stop();
                web_running = false;
            }
            if (was_running) {
                // batch101: a live apply stops to swap the config. A stop that
                // could not persist its lease document must not vanish: log it
                // (the sticky verdict also stays visible on /api/status), then
                // let the restart below decide whether the apply succeeded.
                std::string stop_error;
                if (!dataplane.Stop(stop_error) || !stop_error.empty()) {
                    std::fprintf(stderr, "[vgww] %s\n", stop_error.c_str());
                }
            }
            {
                // The snapshot publisher reads the same config on its own
                // thread; serialize only the swap itself.
                std::lock_guard<std::mutex> lock(*config_mutex);
                *config = next;
            }
            apply_bridge(next);
            // An empty token field means "keep": the live credential
            // (possibly generated at startup) must survive an unrelated
            // settings save.
            const std::string next_token =
                next.web.token.empty() ? prev_auth.token : next.web.token;
            web_auth->Set(next_token, !next.web.token.empty());
            const bool next_web = vgww::core::WebEnabledEffective(
                next.web.enabled, options.web, options.no_web);

            const auto rollback = [&](const std::string& why) {
                if (dataplane.IsRunning()) {
                    dataplane.Stop();
                }
                {
                    std::lock_guard<std::mutex> lock(*config_mutex);
                    *config = previous;
                }
                apply_bridge(previous);
                web_auth->Set(prev_auth.token, prev_auth.configured);
                web_enabled_live->store(prev_web_enabled);
                // DoSaveConfig wrote the NEW config to disk before this hook
                // ran. A failed live apply must also restore the file,
                // otherwise the next start would come up with the rejected
                // settings.
                std::string rollback_text = why;
                std::string file_error;
                if (!previous.SaveToFile(config_path, file_error)) {
                    rollback_text +=
                        " (config rollback failed: " + file_error + ")";
                }
                std::string ignored;
                if (was_running) {
                    dataplane.Start(ignored);
                }
                if (was_web_running) {
                    std::string web_error;
                    web_running = http.Start(previous.web.bind,
                                             previous.web.port, web_error);
                }
                error.assign(rollback_text.begin(), rollback_text.end());
                return false;
            };

            if (was_running) {
                std::string start_error;
                if (!dataplane.Start(start_error)) {
                    return rollback(start_error);
                }
            }
            if (next_web) {
                std::string web_error;
                if (vgww::core::WebBindRequiresToken(next.web.bind) &&
                    next.web.token.empty()) {
                    web_error = "web.bind is not loopback and web.token is "
                                "empty; set web.token before exposing the "
                                "management UI";
                    return rollback(web_error);
                }
                if (!http.Start(next.web.bind, next.web.port, web_error)) {
                    return rollback(web_error);
                }
                web_running = true;
            }
            web_enabled_live->store(next_web);
            return true;
        };

        // batch38: the live config-apply outcome store. It lives here (not in
        // the web server) so it survives web-listener restarts on port/token
        // changes; the Web page polls it to learn the async apply's result.
        std::shared_ptr<vgww::web::ConfigApplyStatus> config_apply_status =
            std::make_shared<vgww::web::ConfigApplyStatus>();

        // batch22 B1: expose the console ring to the read-only web endpoint.
        // The ring lives in the UI layer, so it is handed over as a callback
        // (vgww_core must not depend on vgww_ui). The endpoint filters
        // token-shaped lines before serving them.
        vgww::web::RegisterApiLive(
            http, dataplane, *config, config_path, web_auth, [] {
                // The ring holds wide text; the endpoint serves UTF-8.
                const std::wstring wide =
                    vgww::ui::console_log::SnapshotText();
                std::string utf8;
                if (!wide.empty()) {
                    const int need = ::WideCharToMultiByte(
                        CP_UTF8, 0, wide.c_str(),
                        static_cast<int>(wide.size()), nullptr, 0, nullptr,
                        nullptr);
                    if (need > 0) {
                        utf8.resize(static_cast<std::size_t>(need));
                        ::WideCharToMultiByte(
                            CP_UTF8, 0, wide.c_str(),
                            static_cast<int>(wide.size()), utf8.data(), need,
                            nullptr, nullptr);
                    }
                }
                return utf8;
            },
            // batch22 B4: privileged operations. The web server may come up
            // before (or without) the native UI, so these dispatch through a
            // pointer that the UI sets once it exists; with no UI, a repair
            // request is refused (409) instead of pretending success.
            [] {
                vgww::ui::UiApp* app = g_ui_app.load();
                if (app == nullptr) {
                    return false;
                }
                app->QueueDriverRepairFromWeb();
                return true;
            },
            [](bool enabled) {
                std::string err;
                vgww::ui::tray::SetAutostart(enabled, err);
                return vgww::ui::tray::IsAutostartEnabled();
            },
            [](const std::string& line) {
                vgww::ui::console_log::AppendAuditLine(line);
            },
            // batch37t/u: Web POST /api/config applies immediately. With the
            // native UI it goes through the UI thread + command queue; in
            // headless/web-only mode a detached worker applies it after the
            // response is flushed (never on the HTTP worker itself). batch38:
            // every apply outcome (from either path) is recorded so the Web
            // page can report success/failure truthfully.
            [&apply_config_live, config_apply_status](
                const vgww::core::Config& cfg, uint64_t attempt_id) {
                auto sink = [config_apply_status, attempt_id](
                                bool ok, const std::string& err) {
                    config_apply_status->Record(attempt_id, ok, err);
                };
                vgww::ui::UiApp* app = g_ui_app.load();
                if (app != nullptr) {
                    app->QueueConfigSaveFromWeb(cfg, std::move(sink));
                    return true;
                }
                std::thread([&apply_config_live, cfg, sink] {
                    ::vgww::core::RunDetachedBodyGuarded(
                        config_apply_errors,
                        [&] {
                            ::Sleep(150);
                            std::wstring error;
                            const bool ok = apply_config_live(cfg, error);
                            std::string utf8;
                            if (!error.empty()) {
                                const int need = ::WideCharToMultiByte(
                                    CP_UTF8, 0, error.c_str(),
                                    static_cast<int>(error.size()), nullptr, 0,
                                    nullptr, nullptr);
                                if (need > 0) {
                                    utf8.resize(
                                        static_cast<std::size_t>(need));
                                    ::WideCharToMultiByte(
                                        CP_UTF8, 0, error.c_str(),
                                        static_cast<int>(error.size()),
                                        utf8.data(), need, nullptr, nullptr);
                                }
                            }
                            sink(ok, utf8);
                        },
                        [&] { sink(false, "config apply failed"); });
                }).detach();
                return true;
            },
            config_apply_status,
            // batch126: the console ring's eviction counter is visible on
            // /api/console instead of being a silent loss.
            [] { return vgww::ui::console_log::DroppedLineCount(); });

        // HttpServer is OPT-IN (--web / --web-only; S4.4 switched the default off).
        // It binds the configured web.bind (default 127.0.0.1) - never every
        // interface implicitly - and coexists with the native UI.
        if (web) {
            const uint16_t web_port = config->web.port;

            if (config->web.bind.empty() ||
                config->web.bind.size() > vgww::core::limits::kMaxAdapterBytes) {
                std::fprintf(stderr, "vgww: invalid web.bind - WebUI disabled\n");
            } else if (vgww::core::WebBindRequiresToken(config->web.bind) &&
                       config->web.token.empty()) {
                // A LAN-reachable management UI without a token accepts
                // unauthenticated config writes and privileged actions.
                std::fprintf(stderr,
                             "vgww: web.bind %s is not loopback and web.token "
                             "is empty - WebUI disabled; set web.token\n",
                             config->web.bind.c_str());
            } else if (!http.Start(config->web.bind, web_port, error)) {
                std::fprintf(stderr, "vgww: WebUI disabled (%s)\n", error.c_str());
            } else {
                web_running = true;
                // Print the ACTUAL bind address: the operator must read what
                // the server really listens on (W7 doc-sync item).
                //
                // batch19 (audit B F1): with the native UI running, stdout is
                // captured into the console page's ring, so the auth token
                // must NOT be printed there (R2's "never echo the token", and
                // the About page deliberately hides it). Headless / web-only
                // runs keep the token in their console for the operator.
                if (console_capture) {
                    std::printf("VGWW WebUI: http://%s:%u/\n",
                                config->web.bind.c_str(), web_port);
                } else {
                    std::printf(
                        "VGWW WebUI: http://%s:%u/ (auth token: %s)\n",
                        config->web.bind.c_str(), web_port,
                        web_token.c_str());
                }
                std::printf("vgww: WebUI running "
                            "(manage at http://%s:%u/)\n",
                            config->web.bind.c_str(), web_port);
            }
        }

        // S4.4: native UI mode. The window owns the process lifetime: when it
        // closes, RunVgww returns and the dataplane stops (destructor).
        if (options.ui) {
            vgww::ui::UiRuntimeFlags ui_flags;
            ui_flags.web_enabled = web;
            ui_flags.web_bind = config->web.bind;
            ui_flags.config_path = config_path;
            ui_flags.dataplane_error = dataplane_error_text;
            ui_flags.web_enabled_live = web_enabled_live;
            ui_flags.config_mutex = config_mutex;

            vgww::ui::RealDataSource ui_source(dataplane, *config, ui_flags);
            // batch37j (user): a settings save applies the new config to the
            // RUNNING app - no restart prompt. Stop the dataplane, swap the
            // live config object (the referenced one), start again; on failure
            // restore the previous config and keep the old service running.
            vgww::ui::DataplaneCommandExecutor::ApplyLiveHook apply_live =
                [&apply_config_live](const Config& next,
                                     std::wstring& error) {
                    return apply_config_live(next, error);
                };
            vgww::ui::DataplaneCommandExecutor ui_executor(
                dataplane, config_path, &vgww::ui::TrayAutostartHook,
                std::move(apply_live));
            vgww::ui::UiController ui_controller(ui_source, ui_executor);

            std::string controller_error;
            if (!ui_controller.Start(controller_error)) {
                std::fprintf(stderr, "vgww: UI controller start failed: %s\n",
                             controller_error.c_str());
            } else {
                std::shared_ptr<const vgww::ui::UiSnapshot> first =
                    ui_controller.Load();
                // Task 7: optional CDP-style UI debug channel. Declared BEFORE
                // the app so the controller outlives the window that borrows it
                // by reference in on_ui_debug (destruction runs in reverse).
                vgww::ui::UiDebugController debug_controller;
                std::unique_ptr<vgww::ui::UiDebugServer> debug_server;
            vgww::ui::UiApp app;
            g_ui_app.store(&app);
            // batch19 R4-P4: apply the persisted UI language at startup.
            app.SetInitialLanguage(config->ui_language);
            // batch20: apply the persisted UI scale ("auto" -> follow the
            // desktop DPI; a percent -> a fixed override applied before the
            // first paint).
            app.SetInitialUiScale(
                vgww::core::UiScaleValueToFactor(config->ui_scale));
            // batch24 P1-4: install the save->restart handler. Order matters:
            // release the single-instance event FIRST (closing our handle makes
            // the child's CreateEventW see "does not exist" and become Primary),
            // THEN spawn the child with our exact command line, THEN exit. The
            // release-before-spawn order closes the race where the child would
            // still see the held event, self-exit as Secondary, and leave no
            // running instance (both gone). Both processes are elevated
            // (requireAdministrator), so CreateProcess raises no UAC.
            app.SetRestartHandler([&instance_watcher, &instance_stop, &app] {
                vgww::ui::RunRestartChain(
                    [&] {
                        // 1. Drop the single-instance gate: the child's
                        // CreateEventW then sees "does not exist" and becomes
                        // Primary (see restart.h for why the order matters).
                        instance_stop.store(true);
                        instance_watcher.Reset();
                    },
                    [&] {
                        // 2. Spawn the replacement with our exact command line.
                        std::wstring cmd_line(::GetCommandLineW());
                        STARTUPINFOW si{};
                        si.cb = sizeof(si);
                        PROCESS_INFORMATION pi{};
                        if (::CreateProcessW(nullptr, cmd_line.data(), nullptr,
                                             nullptr, FALSE, 0, nullptr, nullptr,
                                             &si, &pi)) {
                            ::CloseHandle(pi.hThread);
                            ::CloseHandle(pi.hProcess);
                        }
                    },
                    [&] {
                        // 3. Leave; the child owns the process lifetime now.
                        app.window().RequestExit();
                    });
            });
            // batch22 A1: startup appearance. "auto" follows the Windows
            // apps-light preference; anything else is explicit (dark default).
            vgww::ui::SetActiveTheme(
                config->theme == "auto"
                    ? vgww::ui::SystemPrefersLightTheme()
                    : config->theme == "light");
            if (options.ui_debug_port != 0) {
                    // root()/router() are only live after Compose; compose
                    // here (Run's composed_ guard makes it idempotent) so the
                    // bind gets real objects instead of null. Run still
                    // re-applies --ui-page and the detected system language.
                    app.Compose(ui_controller, *first);
                    debug_controller.Bind(&app.root(), &app.window(),
                                          &app.router(), &app);
                    std::string server_error;
                    debug_server =
                        std::make_unique<vgww::ui::UiDebugServer>();
                    debug_server->BindController(&debug_controller);
                    if (!debug_server->Start(options.ui_debug_port,
                                             server_error)) {
                        std::fprintf(stderr,
                                     "vgww: UI debug channel disabled (%s)\n",
                                     server_error.c_str());
                        debug_server.reset();
                    } else {
                        app.window().on_ui_debug = [&debug_controller] {
                            debug_controller.DrainOnUiThread();
                        };
                    }
                }
                const int exit_code = app.Run(
                    ::GetModuleHandleW(nullptr), ui_controller, *first,
                    options.minimized, options.ui_page);
                if (debug_server) {
                    debug_server->Stop();
                }
                ui_controller.Stop();
                g_ui_app.store(nullptr);
                return exit_code;
            }
        }

        // Headless / fallback: keep the console stats loop.
        std::printf(dataplane_failed
                        ? "VGWW running in DEGRADED mode (dataplane down), "
                          "press Ctrl+C to stop.\n"
                        : "VGWW running on adapter, press Ctrl+C to stop.\n");

        // Graceful stop: the handler only flips the stop flag; the loop falls
        // through, `dataplane` is destroyed (Stop() resets the adapter filters)
        // and main returns a clean exit code.
        ::SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE);

        while (!g_stop.load()) {
            ::Sleep(1000);

            if (dataplane_failed) {
                continue;  // filters not installed; no meaningful stats
            }

            const auto& stats = dataplane.GetStats();

            std::printf(
                "rx=%llu tx=%llu arp=%llu icmp=%llu tcp=%llu pass=%llu miss=%llu\n",
                static_cast<unsigned long long>(stats.rx_frames.load()),
                static_cast<unsigned long long>(stats.tx_frames.load()),
                static_cast<unsigned long long>(stats.arp_replies.load()),
                static_cast<unsigned long long>(stats.icmp_replies.load()),
                static_cast<unsigned long long>(stats.tcp_accepted.load()),
                static_cast<unsigned long long>(stats.host_passthrough.load()),
                static_cast<unsigned long long>(stats.mac_misses.load()));
        }

        return 0;
    }

}  // namespace

int main(int argc, char** argv)
{
    return RunVgww(argc, argv);
}

#ifdef _WIN32

// WINDOWS subsystem entry (kept for source compatibility; the headless
// CONSOLE build selects main(), not this symbol). Both coexist; the
// subsystem decides which is used - not a duplication.

int WINAPI wWinMain(HINSTANCE /*hInstance*/,
                    HINSTANCE /*hPrevInstance*/,
                    PWSTR /*pCmdLine*/,
                    int /*nCmdShow*/)
{
    // Headless console build (WIN32_EXECUTABLE FALSE): the linker selects
    // main(), not wWinMain. This entry exists only so a future WINDOWS
    // subsystem build does not need a rewrite; it forwards to the same core.
    // We cannot rely on console output here if stdout is detached, so just
    // run the core and mirror its exit code.
    int argc = 0;

    LPWSTR* argv_w = ::CommandLineToArgvW(::GetCommandLineW(), &argc);

    if (nullptr == argv_w)
    {
        return 1;
    }

    // argc includes the exe name (argv_w[0]) per Win32 docs.
    // Rebuild as UTF-8 char* array for RunVgww(argc, argv) which expects
    // argv[0]=exe, argv[1..]=flags, and does args = argv[1..argc-1].

    std::vector<std::string> args_utf8;

    args_utf8.reserve(static_cast<size_t>(argc > 0 ? argc : 0));

    for (int i = 0; i < argc; ++i)
    {
        args_utf8.push_back(WideToUtf8(argv_w[i]));
    }

    ::LocalFree(argv_w);

    argv_w = nullptr;

    // Rebuild argv as non-const char* array (RunVgww takes char**).
    // Strings stay alive until RunVgww returns, so s.data() remains valid.
    // Add nullptr sentinel for C convention.

    std::vector<char*> argv_ptrs;

    argv_ptrs.reserve(args_utf8.size() + 1);

    for (std::string& s : args_utf8)
    {
        argv_ptrs.push_back(s.data());
    }

    argv_ptrs.push_back(nullptr);

    const int result = RunVgww(argc, argv_ptrs.data());

    // Batch19 R3-1: no debug line on stderr - the GUI-subsystem entry now
    // owns the CLI one-shots too, and a stray "[vgww] wWinMain returning 0"
    // polluted `--version`/`--help` pipelines (stdout parity was fine, stderr
    // was not).
    return result;
}

#endif
