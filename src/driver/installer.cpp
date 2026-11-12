// ============================================================================
// installer.cpp - ndisrd driver bootstrap (see installer.h).
// ============================================================================
#include "driver/installer.h"

#include <windows.h>
#include <shellapi.h>
#include <winsvc.h>
#include <sddl.h>
#include <netcfgx.h>
#include <objbase.h>
#include <devguid.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <sstream>
#include <string>
#include <vector>

namespace vgww {
    namespace driver {

        namespace {

            /// Full path of the running executable, resolved through a growing
            /// buffer so a vgww.exe in a directory longer than MAX_PATH still
            /// resolves (batch331 P2: the elevated install/grant spawns used a
            /// MAX_PATH stack buffer and reported "cannot locate the vgww.exe
            /// path" for long installs). Empty when GetModuleFileNameW fails or
            /// overflows the 32767-character NT limit.
            std::wstring ExecutablePath() {
                std::wstring path;
                DWORD cap = MAX_PATH;
                while (true) {
                    path.resize(cap);
                    const DWORD got =
                        ::GetModuleFileNameW(nullptr, path.data(), cap);
                    if (0 == got) {
                        return {};
                    }
                    if (got < cap) {
                        path.resize(got);
                        return path;
                    }
                    if (cap >= 32767) {
                        return {};
                    }
                    cap *= 2;
                }
            }

            /// Directory of the running executable; empty when the module
            /// path cannot be resolved.
            std::filesystem::path ExeDir() {
                const std::wstring exe = ExecutablePath();
                if (exe.empty()) {
                    return {};
                }
                return std::filesystem::path(exe).parent_path();
            }

        }  // namespace

        bool NdisrdServiceRunning() noexcept {
            SC_HANDLE scm = ::OpenSCManagerW(nullptr, nullptr,
                                              SC_MANAGER_CONNECT);
            if (nullptr == scm) {
                return false;
            }
            SC_HANDLE svc = ::OpenServiceW(scm, L"ndisrd",
                                           SERVICE_QUERY_STATUS);
            if (nullptr == svc) {
                ::CloseServiceHandle(scm);
                return false;
            }
            SERVICE_STATUS status{};
            const bool ok = ::QueryServiceStatus(svc, &status) &&
                            SERVICE_RUNNING == status.dwCurrentState;
            ::CloseServiceHandle(svc);
            ::CloseServiceHandle(scm);
            return ok;
        }

        bool ProbeDeviceAccess(bool& access_denied) noexcept {
            access_denied = false;
            HANDLE dev = ::CreateFileW(
                L"\\\\.\\Ndisrd", GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0,
                nullptr);
            if (INVALID_HANDLE_VALUE == dev) {
                access_denied = (ERROR_ACCESS_DENIED == ::GetLastError());
                return false;
            }
            ::CloseHandle(dev);
            return true;
        }

        namespace {

        // Grant authenticated users access to \\.\Ndisrd so a normal
        // double-click (filtered token) can open the data plane. The
        // registry Security value alone is not applied by every driver
        // at device load; setting the DACL on the live device object
        // (SetKernelObjectSecurity) takes effect immediately. The driver
        // recreates the device object on every load (e.g. after reboot),
        // which drops that DACL - so this must be re-applied on every
        // elevated --install-driver run, not only on first registration.
        bool GrantDeviceAccessOnce() {
            constexpr wchar_t kDeviceSddl[] =
                L"D:P(A;;0x001F01FF;;;SY)(A;;0x001F01FF;;;BA)"
                L"(A;;0x001F01FF;;;AU)(A;;0x001200A0;;;WD)"
                L"(A;;0x001200A0;;;S-1-5-12)";
            PSECURITY_DESCRIPTOR sd = nullptr;
            ULONG sd_len = 0;
            bool applied = false;
            if (::ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    kDeviceSddl, SDDL_REVISION_1, &sd, &sd_len))
            {
                HANDLE dev = ::CreateFileW(
                    L"\\\\.\\Ndisrd", GENERIC_READ | GENERIC_WRITE | WRITE_DAC,
                    FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
                    0, nullptr);
                if (INVALID_HANDLE_VALUE != dev) {
                    applied = FALSE != ::SetKernelObjectSecurity(
                                           dev, DACL_SECURITY_INFORMATION, sd);
                    ::CloseHandle(dev);
                }
                ::LocalFree(sd);
            }
            return applied;
        }

        std::wstring MbcsToWide(const std::string& mb) {
            if (mb.empty()) {
                return {};
            }
            const int needed = ::MultiByteToWideChar(
                CP_ACP, 0, mb.data(), static_cast<int>(mb.size()), nullptr, 0);
            if (needed <= 0) {
                return {};
            }
            std::wstring out(static_cast<size_t>(needed), L'\0');
            ::MultiByteToWideChar(CP_ACP, 0, mb.data(),
                                  static_cast<int>(mb.size()), out.data(), needed);
            return out;
        }

        std::string TrimAscii(std::string s) {
            const size_t first = s.find_first_not_of(" \t\r\n");
            if (std::string::npos == first) {
                return "";
            }
            const size_t last = s.find_last_not_of(" \t\r\n");
            return s.substr(first, last - first + 1);
        }

        std::string LowerAscii(std::string s) {
            for (char& c : s) {
                c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            }
            return s;
        }

        std::string WideToUtf8(const std::wstring& wide) {
            if (wide.empty()) {
                return "";
            }
            const int needed = ::WideCharToMultiByte(
                CP_UTF8, 0, wide.c_str(), static_cast<int>(wide.size()), nullptr,
                0, nullptr, nullptr);
            if (needed <= 0) {
                return "";
            }
            std::string out(static_cast<size_t>(needed), '\0');
            ::WideCharToMultiByte(CP_UTF8, 0, wide.c_str(),
                                  static_cast<int>(wide.size()), out.data(), needed,
                                  nullptr, nullptr);
            return out;
        }

        /// Retires stale SCM registrations from the retired SCM direct-start
        /// channel (defect #1: LWF drivers never start that way, leaving a
        /// dead SERVICE_KERNEL_DRIVER registration behind). A RUNNING service
        /// is left alone (already loaded); anything else is deleted.
        ///
        /// Returns false + a reason when the registration could NOT be
        /// retired. The failure must reach the caller: a dead
        /// SERVICE_KERNEL_DRIVER cannot coexist with the NDIS-bound LWF, so
        /// pnputil / INetCfg would fail afterwards with an unrelated error
        /// and the real root cause (this delete) would be lost.
        bool CleanupLegacyServiceRegistration(std::wstring& error) {
            error.clear();
            SC_HANDLE scm =
                ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
            if (nullptr == scm) {
                error = L"cannot open the service control manager (error " +
                        std::to_wstring(::GetLastError()) + L")";
                return false;
            }
            SC_HANDLE svc = ::OpenServiceW(
                scm, L"ndisrd", SERVICE_QUERY_STATUS | DELETE);
            if (nullptr == svc) {
                const DWORD open_error = ::GetLastError();
                ::CloseServiceHandle(scm);
                if (ERROR_SERVICE_DOES_NOT_EXIST == open_error) {
                    return true;  // nothing to retire
                }
                error = L"cannot open the legacy ndisrd service (error " +
                        std::to_wstring(open_error) + L")";
                return false;
            }
            SERVICE_STATUS status{};
            const bool running =
                ::QueryServiceStatus(svc, &status) &&
                SERVICE_RUNNING == status.dwCurrentState;
            if (running) {
                ::CloseServiceHandle(svc);
                ::CloseServiceHandle(scm);
                return true;  // already loaded: leave it alone
            }
            const BOOL deleted = ::DeleteService(svc);
            const DWORD delete_error = deleted ? 0 : ::GetLastError();
            ::CloseServiceHandle(svc);
            ::CloseServiceHandle(scm);
            // A service already marked for deletion disappears at the next
            // boot: that is the desired end state, not a failure.
            if (!deleted && ERROR_SERVICE_MARKED_FOR_DELETE != delete_error) {
                error = L"DeleteService(ndisrd) failed (error " +
                        std::to_wstring(delete_error) + L")";
                return false;
            }
            return true;
        }

        std::wstring PnputilExe() {
            wchar_t sysdir[MAX_PATH] = {0};
            if (0 != ::GetSystemDirectoryW(sysdir, MAX_PATH)) {
                return std::wstring(sysdir) + L"\\pnputil.exe";
            }
            return L"pnputil.exe";
        }

        /// Dispatches a pnputil call to the injected runner (tests) or the
        /// real subprocess (production).
        bool RunPnputilChannel(PnputilRunner runner,
                               const std::vector<std::wstring>& args,
                               std::string& output, DWORD& exit_code) {
            if (runner) {
                return runner(args, output, exit_code);
            }
            return RunProcessCapture(PnputilExe(), args, output, exit_code);
        }

        /// Resolves the Windows directory, keeping the API's failure signal
        /// (an empty string) visible to the caller instead of treating the
        /// untouched buffer as a directory name.
        std::wstring WindowsDirectory() {
            wchar_t windir[MAX_PATH] = {0};
            const UINT got = ::GetWindowsDirectoryW(windir, MAX_PATH);
            if (0 == got || got >= MAX_PATH) {
                return {};
            }
            return std::wstring(windir, got);
        }

        std::wstring SchtasksExe() {
            wchar_t sysdir[MAX_PATH] = {0};
            if (0 != ::GetSystemDirectoryW(sysdir, MAX_PATH)) {
                return std::wstring(sysdir) + L"\\schtasks.exe";
            }
            return L"schtasks.exe";
        }

        /// Dispatches a console-tool call to the injected runner (tests) or the
        /// real subprocess (production).
        bool RunCaptureChannel(ProcessCaptureRunner runner,
                               const std::wstring& exe,
                               const std::vector<std::wstring>& args,
                               std::string& output, DWORD& exit_code) {
            if (runner) {
                return runner(exe, args, output, exit_code);
            }
            return RunProcessCapture(exe, args, output, exit_code);
        }

        /// Removes the %ProgramData%\VGWW\vgww.exe mirror (real
        /// implementation for UninstallHooks::remove_mirror_copy). Only that
        /// one file; the (possibly shared) directory stays.
        bool RemoveMirrorCopy(std::wstring& error) {
            wchar_t pd[MAX_PATH] = {0};
            const DWORD got =
                ::GetEnvironmentVariableW(L"ProgramData", pd, MAX_PATH);
            if (!EnvValueFitsBuffer(got)) {
                return true;  // cannot name the file: no residual to claim
            }
            const std::filesystem::path vgww_dir =
                MakeProgramDataPath(std::wstring(pd, got));
            if (vgww_dir.empty()) {
                return true;  // cannot name the file: no residual to claim
            }
            const std::filesystem::path copy = vgww_dir / L"vgww.exe";
            std::error_code ec;
            if (!std::filesystem::exists(copy, ec)) {
                return true;
            }
            std::filesystem::remove(copy, ec);
            if (ec) {
                error = copy.wstring() + L": delete failed (file in use?)";
                return false;
            }
            return true;
        }

        /// Terminal audit (batch16 F7): is a stale ndisrd SCM registration
        /// still present after uninstall? Read-only.
        bool LegacyServiceStillRegistered() {
            SC_HANDLE scm =
                ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
            if (nullptr == scm) {
                return false;
            }
            SC_HANDLE svc = ::OpenServiceW(scm, L"ndisrd",
                                           SERVICE_QUERY_STATUS);
            const bool exists = (nullptr != svc);
            if (nullptr != svc) {
                ::CloseServiceHandle(svc);
            }
            ::CloseServiceHandle(scm);
            return exists;
        }

        }  // namespace

        /// See installer.h. An empty Windows directory yields an EMPTY path:
        /// joining it anyway would produce the relative "System32/drivers",
        /// which resolves against the current working directory.
        std::filesystem::path MakeSystemDriversDir(
            const std::wstring& windows_dir) {
            if (windows_dir.empty()) {
                return {};
            }
            return std::filesystem::path(windows_dir) / "System32" / "drivers";
        }

        /// See installer.h. GetEnvironmentVariableW returns the REQUIRED
        /// length when the buffer is too small, so only 1 .. MAX_PATH-1 is a
        /// value that actually landed in the buffer (the terminator needs a
        /// slot too).
        bool EnvValueFitsBuffer(DWORD returned_length) {
            return 0 != returned_length && returned_length < MAX_PATH;
        }

        /// See installer.h.
        std::filesystem::path MakeProgramDataPath(
            const std::wstring& program_data) {
            if (program_data.empty()) {
                return {};
            }
            return std::filesystem::path(program_data) / L"VGWW";
        }

        /// See installer.h.
        bool RemoveSystem32CopyReal(std::wstring& error,
                                   const std::wstring* windows_dir) {
            error.clear();
            const std::wstring windir =
                windows_dir ? *windows_dir : WindowsDirectory();
            const std::filesystem::path drivers = MakeSystemDriversDir(windir);
            if (drivers.empty()) {
                error = L"cannot resolve %SystemRoot%\\System32\\drivers "
                        L"(GetWindowsDirectoryW failed); the ndisrd.sys copy "
                        L"was NOT removed";
                return false;
            }
            std::error_code ec;
            const std::filesystem::path sys32_copy = drivers / L"ndisrd.sys";
            if (!std::filesystem::exists(sys32_copy, ec)) {
                return true;
            }
            std::filesystem::remove(sys32_copy, ec);
            if (ec) {
                error = sys32_copy.wstring() +
                        L": delete failed (driver in use or access denied)";
                return false;
            }
            return true;
        }

        /// Default body for UninstallHooks::remove_system32_copy.
        bool RemoveSystem32Copy(std::wstring& error) {
            return RemoveSystem32CopyReal(error, nullptr);
        }

        /// Removes the VGWW-GrantAccess boot task (real implementation for
        /// UninstallHooks::remove_boot_task). Queries first: deleting a
        /// missing task exits non-zero, and "task absent" is exactly the
        /// already-clean state (batch16 F5). Returns false + reason when a
        /// present task cannot be removed, and also when the QUERY could not
        /// complete at all (batch331 P2: a timed-out query is not "absent").
        bool RemoveBootTask(std::wstring& error, ProcessCaptureRunner runner) {
            std::string out;
            DWORD code = 1;
            if (!RunCaptureChannel(runner, SchtasksExe(),
                                   {L"/query", L"/tn", L"VGWW-GrantAccess"},
                                   out, code)) {
                error = L"failed to query the VGWW-GrantAccess boot task "
                        L"(schtasks.exe did not complete)";
                return false;
            }
            if (0 != code) {
                return true;  // query ran and reported: task absent
            }
            if (!RunCaptureChannel(runner, SchtasksExe(),
                                   {L"/delete", L"/f", L"/tn",
                                    L"VGWW-GrantAccess"},
                                   out, code)) {
                error = L"failed to delete the VGWW-GrantAccess boot task "
                        L"(schtasks.exe did not complete)";
                return false;
            }
            if (0 != code) {
                error = L"schtasks /delete VGWW-GrantAccess failed (exit=" +
                        std::to_wstring(code) + L")";
                return false;
            }
            return true;
        }


        bool GrantDeviceAccessWithRetries(const std::function<bool()>& attempt,
                                          int attempts, DWORD delay_ms) {
            if (!attempt || attempts <= 0) {
                return false;
            }
            for (int i = 0; i < attempts; ++i) {
                if (attempt()) {
                    return true;
                }
                if (i + 1 < attempts && delay_ms > 0) {
                    ::Sleep(delay_ms);
                }
            }
            return false;
        }

        std::string GrantDeviceAccessOnly(
            std::function<bool()> grant_attempt) {
            const std::function<bool()> attempt =
                grant_attempt ? grant_attempt : std::function<bool()>([] {
                    return GrantDeviceAccessOnce();
                });
            // Boot context: the driver may still be creating \\.\Ndisrd
            // right after an onstart task fires, so allow a 30 s window
            // (60 x 500 ms) instead of the install path's short one.
            if (!GrantDeviceAccessWithRetries(attempt, 60, 500)) {
                return "device access grant failed: could not open \\\\.\\Ndisrd and set "
                       "its DACL. Run vgww.exe --install-driver as Administrator; "
                       "see docs/zh/driver-install.md";
            }
            return "";
        }

        /// Runs a console tool (pnputil/sc) with args, capturing combined
        /// stdout+stderr into `output`. Returns true when the process spawned
        /// and exited; `exit_code` holds its status. `timeout_ms` bounds the
        /// wait for the child (U2).
        bool RunProcessCapture(const std::wstring& exe,
                               const std::vector<std::wstring>& args,
                               std::string& output, DWORD& exit_code,
                               DWORD timeout_ms) {
            std::wstring cmd = L"\"" + exe + L"\"";
            for (const std::wstring& arg : args) {
                // Quote according to the Windows argv splitting rules the
                // child will apply (CommandLineToArgvW / the MSVC runtime):
                // a run of backslashes is literal only while no quote
                // follows. 2N backslashes + `"` become N backslashes and a
                // delimiter; 2N+1 + `"` become N backslashes and a literal
                // quote; and a run at the very end of the quoted argument is
                // doubled so the closing comment-less boundary stays a
                // delimiter. Escaping only bare quotes (the old behaviour)
                // corrupted `C:\dir\` into `C:\dir"` and `a\\"b` into
                // `a\"b`.
                std::wstring escaped;
                escaped.reserve(arg.size() + 2);
                size_t backslashes = 0;
                for (const wchar_t c : arg) {
                    if (L'\\' == c) {
                        ++backslashes;
                        continue;
                    }
                    if (L'"' == c) {
                        // Double the pending run, then escape the quote.
                        escaped.append(backslashes * 2 + 1, L'\\');
                        escaped += L'"';
                        backslashes = 0;
                        continue;
                    }
                    if (backslashes > 0) {
                        escaped.append(backslashes, L'\\');
                        backslashes = 0;
                    }
                    escaped += c;
                }
                // Trailing run: double it so the closing quote we add below
                // stays a delimiter rather than escaping itself.
                escaped.append(backslashes * 2, L'\\');
                cmd += L" \"";
                cmd += escaped;
                cmd += L"\"";
            }

            HANDLE pipe_read = nullptr;
            HANDLE pipe_write = nullptr;
            SECURITY_ATTRIBUTES sa{};
            sa.nLength = sizeof(sa);
            sa.bInheritHandle = TRUE;
            if (!::CreatePipe(&pipe_read, &pipe_write, &sa, 0)) {
                return false;
            }
            ::SetHandleInformation(pipe_read, HANDLE_FLAG_INHERIT, 0);

            STARTUPINFOW si{};
            si.cb = sizeof(si);
            si.dwFlags = STARTF_USESTDHANDLES;
            si.hStdOutput = pipe_write;
            si.hStdError = pipe_write;
            si.hStdInput = ::GetStdHandle(STD_INPUT_HANDLE);
            PROCESS_INFORMATION pi{};
            const BOOL spawned = ::CreateProcessW(
                nullptr, cmd.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW,
                nullptr, nullptr, &si, &pi);
            ::CloseHandle(pipe_write);
            output.clear();
            if (!spawned) {
                ::CloseHandle(pipe_read);
                return false;
            }

            // U2: read and wait share one deadline window, so a child that
            // hangs without closing its pipe (or keeps writing) cannot block
            // the caller past `timeout_ms`. Between short process waits the
            // pipe is drained non-blockingly; a child still alive at the
            // deadline is terminated.
            char buf[4096] = {0};
            DWORD nread = 0;
            const ULONGLONG deadline = ::GetTickCount64() + timeout_ms;
            bool exited = false;
            for (;;) {
                // Drain whatever the child has buffered so far.
                for (;;) {
                    DWORD avail = 0;
                    if (!::PeekNamedPipe(pipe_read, nullptr, 0, nullptr,
                                         &avail, nullptr)) {
                        break;  // pipe broken: the child closed its write end
                    }
                    if (0 == avail) {
                        break;
                    }
                    DWORD got = 0;
                    if (!::ReadFile(pipe_read, buf,
                                    static_cast<DWORD>(std::min(
                                        sizeof(buf), static_cast<size_t>(avail))),
                                    &got, nullptr) ||
                        0 == got) {
                        break;
                    }
                    output.append(buf, got);
                }
                const DWORD wait = ::WaitForSingleObject(pi.hProcess, 50);
                if (WAIT_OBJECT_0 == wait) {
                    exited = true;
                    break;
                }
                if (WAIT_TIMEOUT != wait) {
                    break;  // handle error: bail out below
                }
                if (::GetTickCount64() >= deadline) {
                    break;  // timed out: terminate below
                }
            }
            if (exited) {
                // Final drain to EOF (the child is gone, the pipe is closed).
                for (;;) {
                    if (!::ReadFile(pipe_read, buf, sizeof(buf), &nread,
                                    nullptr) ||
                        0 == nread) {
                        break;
                    }
                    output.append(buf, nread);
                }
            }
            ::CloseHandle(pipe_read);
            if (!exited) {
                (void)::TerminateProcess(pi.hProcess, 1);
            }
            const DWORD wait = ::WaitForSingleObject(pi.hProcess, 5000);
            exit_code = 1;
            if (WAIT_OBJECT_0 == wait) {
                ::GetExitCodeProcess(pi.hProcess, &exit_code);
            }
            ::CloseHandle(pi.hThread);
            ::CloseHandle(pi.hProcess);
            // batch331 P2: "spawned and exited" is the contract. A child the
            // deadline had to terminate never exited on its own, so its
            // forced exit code must NOT be reported as a real result - the
            // caller cannot otherwise tell "tool said non-zero" from "tool
            // hung" (that conflation made RemoveBootTask read a hung query as
            // "task absent").
            return exited;
        }

        /// True when `val_lower` (already lowercased, trimmed) is THIS
        /// product's INF FILE NAME rather than some unrelated field that
        /// merely mentions the word. The uninstall deletes whole driver-store
        /// packages, so the match has to be the package identity:
        ///   * the value must be a BARE file name - no path separator and no
        ///     whitespace - ending in ".inf", and
        ///   * its stem must contain "ndisrd" (ndisrd_lwf.inf today, plus an
        ///     older or renamed WinpkFilter INF, which must never be missed).
        /// A sentence such as "interoperates with ndisrd_lwf.inf" or a
        /// provider/signer/comment string is rejected by the shape test.
        bool IsNdisrdInfValue(const std::string& val_lower) {
            constexpr const char kSuffix[] = ".inf";
            constexpr size_t kSuffixLen = sizeof(kSuffix) - 1;
            if (val_lower.size() <= kSuffixLen) {
                return false;
            }
            if (val_lower.compare(val_lower.size() - kSuffixLen, kSuffixLen,
                                  kSuffix) != 0) {
                return false;
            }
            // Reject anything that is not a single file-name token.
            for (const char c : val_lower) {
                if (' ' == c || '\t' == c || '/' == c || '\\' == c ||
                    ':' == c || '"' == c) {
                    return false;
                }
            }
            return std::string::npos != val_lower.find("ndisrd");
        }

        std::vector<std::string> ParsePnputilNdisrdOems(
            const std::string& transcript) {
            std::vector<std::string> found;
            std::string current_oem;
            std::istringstream lines(transcript);
            std::string line;
            while (std::getline(lines, line)) {
                // Trim ASCII whitespace.
                const std::string trimmed = [](
                    std::string s) {
                    const size_t b = s.find_first_not_of(" \t\r");
                    if (std::string::npos == b) {
                        return std::string();
                    }
                    const size_t e = s.find_last_not_of(" \t\r");
                    return s.substr(b, e - b + 1);
                }(line);

                const std::string lower = [](
                    const std::string& s) {
                    std::string o = s;
                    for (char& c : o) {
                        c = static_cast<char>(
                            std::tolower(static_cast<unsigned char>(c)));
                    }
                    return o;
                }(trimmed);

                const size_t colon = lower.find(':');
                if (std::string::npos != colon) {
                    const std::string key_lower = lower.substr(0, colon);
                    const std::string value =
                        trimmed.substr(colon + 1);
                    // Trim again: the field label often carries a trailing
                    // space before the colon ("Published Name :") and the
                    // value a leading run of spaces.
                    const auto strip = [](const std::string& s) {
                        const size_t b = s.find_first_not_of(" \t");
                        const size_t e = s.find_last_not_of(" \t");
                        if (std::string::npos == b) {
                            return std::string();
                        }
                        return s.substr(b, e - b + 1);
                    };
                    const std::string val = strip(value);

                    if ("published name" == strip(key_lower)) {
                        current_oem = val;
                        continue;
                    }
                    const std::string val_lower = [](
                        const std::string& s) {
                        std::string o = s;
                        for (char& c : o) {
                            c = static_cast<char>(std::tolower(
                                static_cast<unsigned char>(c)));
                        }
                        return o;
                    }(val);
                    // STRONG feature only. The old check accepted ANY labeled
                    // field containing "ndisrd" (provider, description,
                    // signer, comment), so a third-party package mentioning
                    // the substring was deleted with /delete-driver
                    // /uninstall. What identifies our package is its own INF
                    // FILE NAME, which is locale independent: accept the known
                    // product names, plus any other value that is itself an
                    // ".inf" file name containing "ndisrd" (a renamed/older
                    // WinpkFilter INF must never be missed).
                    if (!current_oem.empty() && IsNdisrdInfValue(val_lower)) {
                        // Every hit resolves to the entry the oem tracker
                        // currently points at; dedupe repeated hits within one
                        // entry.
                        if (std::find(found.begin(), found.end(),
                                      current_oem) == found.end()) {
                            found.push_back(current_oem);
                        }
                        continue;
                    }
                    // Localized systems (e.g. Chinese: published name field
                    // followed by ":oem42.inf")
                    // do not emit the English field label, so also track an
                    // "oem##.inf" value on any labeled line (key text is
                    // locale-dependent, the value shape is not). Every such
                    // value updates the tracker, mirroring the English
                    // "published name" branch, so a later ndisrd hit returns
                    // THIS entry's oem - never an unrelated one.
                    if (val_lower.size() > 4 &&
                        val_lower.rfind("oem", 0) == 0 &&
                        val_lower.size() > 6 &&
                        val_lower.substr(val_lower.size() - 4) == ".inf") {
                        const std::string mid = val_lower.substr(
                            3, val_lower.size() - 7);
                        if (!mid.empty() &&
                            std::all_of(mid.begin(), mid.end(),
                                        [](char c) {
                                            return c >= '0' && c <= '9';
                                        })) {
                            current_oem = val;
                        }
                    }
                }
            }
            return found;
        }

        std::string ParsePnputilNdisrdOem(const std::string& transcript) {
            const std::vector<std::string> all =
                ParsePnputilNdisrdOems(transcript);
            return all.empty() ? std::string() : all.front();
        }

        std::vector<std::string> DiffNewOems(
            const std::vector<std::string>& before,
            const std::vector<std::string>& after) {
            std::vector<std::string> out;
            for (const std::string& oem : after) {
                if (std::find(before.begin(), before.end(), oem) ==
                    before.end()) {
                    out.push_back(oem);
                }
            }
            return out;
        }

        std::vector<std::wstring> BuildAddDriverArgs(
            const std::wstring& inf_path) {
            return {L"/add-driver", inf_path, L"/install"};
        }

        std::vector<std::wstring> BuildDeleteDriverArgs(
            const std::wstring& oem_inf) {
            return {L"/delete-driver", oem_inf, L"/uninstall"};
        }

        bool LocateDriverPayload(const std::filesystem::path& base_dir,
                                 DriverPayload& out, std::wstring& error) {
            out = {};
            error.clear();
            const std::filesystem::path root =
                base_dir.empty() ? ExeDir() : base_dir;
            if (root.empty()) {
                error = L"cannot locate the driver payload directory (GetModuleFileNameW failed)";
                return false;
            }
            // pnputil /add-driver resolves ndisrd.sys/ndisrd.cat relative to
            // the INF (SourceDisksFiles), so only a same-directory triple is
            // usable. A split pairing used to pass the old independent
            // lookups and then fail inside pnputil.
            const std::filesystem::path candidates[] = {
                root, root / L"drivers", root / L"win10"};
            const auto size_of = [](const std::filesystem::path& p) -> long long {
                std::error_code ec;
                const auto sz = std::filesystem::file_size(p, ec);
                return ec ? -1 : static_cast<long long>(sz);
            };
            std::wstring first_report;
            for (const std::filesystem::path& dir : candidates) {
                const std::filesystem::path inf = dir / L"ndisrd_lwf.inf";
                const std::filesystem::path sys = dir / L"ndisrd.sys";
                const std::filesystem::path cat = dir / L"ndisrd.cat";
                const long long inf_sz = size_of(inf);
                const long long sys_sz = size_of(sys);
                const long long cat_sz = size_of(cat);
                // S5.4A: signing was verified against the shipped payload;
                // the size floors catch a truncated download. cat just has
                // to be present and non-empty (no invented floor).
                const bool inf_ok = inf_sz >= 1024;
                const bool sys_ok = sys_sz >= 4096;
                const bool cat_ok = cat_sz > 0;
                if (inf_ok && sys_ok && cat_ok) {
                    out.inf = inf;
                    out.sys = sys;
                    out.cat = cat;
                    return true;
                }
                if (first_report.empty() &&
                    (inf_sz >= 0 || sys_sz >= 0 || cat_sz >= 0)) {
                    // Report the first directory that has anything: the
                    // operator's fix is "put the rest next to what is there".
                    std::wstring detail;
                    const auto append = [&detail](const wchar_t* name,
                                                  long long sz, bool ok,
                                                  const wchar_t* why) {
                        if (!detail.empty()) {
                            detail += L", ";
                        }
                        detail += name;
                        if (sz < 0) {
                            detail += L" missing";
                        } else if (!ok) {
                            detail += why;
                        }
                    };
                    append(L"ndisrd_lwf.inf", inf_sz, inf_ok,
                           L" wrong size (<1 KiB)");
                    append(L"ndisrd.sys", sys_sz, sys_ok,
                           L" wrong size (<4 KiB)");
                    append(L"ndisrd.cat", cat_sz, cat_ok,
                           L" wrong size (empty file)");
                    first_report =
                        L"incomplete driver payload: " + detail + L" in " + dir.wstring();
                }
            }
            std::wstring tried;
            for (const std::filesystem::path& dir : candidates) {
                if (!tried.empty()) {
                    tried += L", ";
                }
                tried += dir.wstring();
            }
            if (first_report.empty()) {
                error = L"incomplete driver payload: missing ndisrd_lwf.inf, ndisrd.sys, "
                        L"ndisrd.cat; searched: " + tried;
            } else {
                error = first_report + L"; searched: " + tried;
            }
            return false;
        }

        std::string InstallNdisrdDriver(
            PnputilRunner runner, InetCfgSessionFactory inetcfg_factory,
            InstallHooks hooks) {
            // Defect #1 (S5.4B evidence): ndisrd 3.6.2.1 is an NDIS LWF - a
            // bare CreateServiceW(SERVICE_KERNEL_DRIVER) + StartServiceW
            // registration fails with error 31 (0x1F) + events 7000/7045.
            // The LWF must load through the NDIS framework, i.e. via an INF:
            //   pnputil /add-driver <ndisrd_lwf.inf> /install
            // publishes the payload to the driver store and binds it. The old
            // SCM channel is retired (D1: no dual path).
            // The INF + co-located .sys/.cat ship next to the executable;
            // LocateDriverPayload enforces the same-directory triple and the
            // size floors (S5.4A truncation guard; cat required because the
            // INF declares CatalogFile=ndisrd.cat).
            DriverPayload payload;
            std::wstring payload_error;
            if (!LocateDriverPayload({}, payload, payload_error)) {
                return WideToUtf8(payload_error);
            }
            const std::wstring inf = payload.inf.wstring();

            // Retire any stale SCM registration the old channel may have left
            // behind (a dead SERVICE_KERNEL_DRIVER cannot coexist with the
            // NDIS-bound LWF under the same name). A failure here MUST stop
            // the install: pnputil/INetCfg would otherwise fail later with an
            // unrelated error and the real root cause would be lost.
            std::wstring scm_note;
            const bool scm_ok = hooks.cleanup_legacy_service
                ? hooks.cleanup_legacy_service(scm_note)
                : CleanupLegacyServiceRegistration(scm_note);
            if (!scm_ok) {
                return "cannot retire the legacy ndisrd service registration "
                       "(legacy service cleanup failed): " +
                       WideToUtf8(
                           scm_note.empty()
                               ? L"the stale SCM registration is still present"
                               : scm_note);
            }

            // Baseline (batch16 F6/B-9): record the ndisrd entries in the
            // driver store BEFORE publishing, so a failed install can roll
            // back exactly what it added. An unavailable baseline disables
            // the rollback deletes entirely - mass-deleting a store we could
            // not read risks removing entries that predate this install.
            bool baseline_ok = false;
            std::vector<std::string> baseline;
            {
                std::string base_out;
                DWORD base_code = 1;
                if (RunPnputilChannel(runner, {L"/enum-drivers"}, base_out,
                                      base_code) &&
                    0 == base_code) {
                    baseline_ok = true;
                    baseline = ParsePnputilNdisrdOems(base_out);
                }
            }

            std::string output;
            DWORD code = 1;
            if (!RunPnputilChannel(runner, BuildAddDriverArgs(inf), output,
                                   code)) {
                return "failed to start pnputil.exe (system tool missing?)";
            }
            if (0 != code) {
                return "pnputil /add-driver failed (exit=" +
                       std::to_string(code) + "):\n" + output +
                       "(run vgww.exe as Administrator)";
            }

            // Shared rollback (batch16 F6): BOTH the factory-null path and
            // the component-failure path must remove only the entries this
            // install published (baseline diff). The primary diagnosis is
            // preserved and re-prepended; rollback failures carry the oem /
            // exit code / tool output instead of a bare "see pnputil above".
            const auto rollback_and_report =
                [&](const std::string& primary) -> std::string {
                if (!baseline_ok) {
                    return primary +
                           "\n(driver-store rollback skipped: baseline unavailable; "
                           "clean up later with --uninstall-driver)";
                }
                std::string rb_out;
                DWORD rb_code = 1;
                if (!RunPnputilChannel(runner, {L"/enum-drivers"}, rb_out,
                                       rb_code)) {
                    return primary +
                           "\n(driver-store rollback failed: "
                           "failed to start pnputil.exe (enum-drivers))";
                }
                if (0 != rb_code) {
                    return primary +
                           "\n(driver-store rollback failed: "
                           "enum-drivers exit=" +
                           std::to_string(rb_code) + ")";
                }
                const std::vector<std::string> now =
                    ParsePnputilNdisrdOems(rb_out);
                const std::vector<std::string> fresh =
                    DiffNewOems(baseline, now);
                if (fresh.empty()) {
                    return primary +
                           "\n(driver-store has no new entries from this run; nothing to roll back)";
                }
                for (const std::string& oem : fresh) {
                    std::wstring oem_wide(oem.begin(), oem.end());
                    std::string del_out;
                    DWORD del_code = 1;
                    if (!RunPnputilChannel(
                            runner, BuildDeleteDriverArgs(oem_wide),
                            del_out, del_code)) {
                        return primary +
                               "\n(driver-store rollback failed: "
                               "failed to start pnputil.exe (delete " + oem + "))";
                    }
                    if (0 != del_code) {
                        return primary +
                               "\n(driver-store rollback failed: delete " +
                               oem + " exit=" + std::to_string(del_code) +
                               "\n" + del_out;
                    }
                }
                return primary +
                       "\n(driver-store entry rolled back)";
            };

            // S5.9 wiring: the LWF payload is in the driver store; now
            // instantiate the network component and bind it to the NICs.
            InetCfgSessionFactory factory = inetcfg_factory
                ? inetcfg_factory : CreateComInetCfgSessionFactory();
            auto session = factory();
            if (!session) {
                return rollback_and_report(
                    "INetCfg: cannot create the configuration session");
            }
            const std::string inet_err =
                InstallNdisrdLwfComponent(*session);
            if (!inet_err.empty()) {
                return rollback_and_report("INetCfg: " + inet_err);
            }

            // The LWF driver still exposes \\.\Ndisrd to user mode (same
            // IOCTL surface as the old TDI path) - keep the DACL grant for
            // normal-user opens. StartServiceW returns BEFORE the driver
            // necessarily created the device, hence the bounded retry.
            // Best-effort: no device yet means the grant is attempted again
            // on the next --install-driver run.
            if (hooks.ensure_device_access) {
                (void)hooks.ensure_device_access();
            } else if (!GrantDeviceAccessWithRetries(
                           [] { return GrantDeviceAccessOnce(); }, 5, 100)) {
                std::fprintf(stderr,
                             "[vgww] device DACL not applied after %d attempts\n",
                             5);
            }
            // batch23: the VGWW-GrantAccess boot task is GONE. The app now
            // re-grants device access in-process at every launch (main.cpp).
            // Older releases registered that onstart task; remove any legacy
            // task here so an install/upgrade never leaves it behind.
            // Idempotent: an absent task is the success state, so a cleanup
            // failure is a warning, not an install failure.
            std::wstring legacy_note;
            const bool legacy_ok = hooks.remove_boot_task
                ? hooks.remove_boot_task(legacy_note)
                : RemoveBootTask(legacy_note);
            if (!legacy_ok) {
                std::fprintf(stderr,
                             "[vgww] legacy VGWW-GrantAccess task cleanup "
                             "failed; continuing\n");
            }
            return "";
        }

        std::string UninstallNdisrdDriver(
            PnputilRunner runner, InetCfgSessionFactory inetcfg_factory,
            UninstallHooks hooks) {
            std::string out;
            DWORD code = 1;
            // 1) Find every published INF via `pnputil /enum-drivers`.
            if (!RunPnputilChannel(runner, {L"/enum-drivers"}, out, code)) {
                return "failed to start pnputil.exe (system tool missing?)";
            }
            const std::vector<std::string> oems = ParsePnputilNdisrdOems(out);
            if (oems.empty()) {
                if (0 != code) {
                    // A failing enum is a TOOL failure, not "not installed"
                    // (batch16 F7/B-3: the code used to be ignored and the
                    // dump misread).
                    return "pnputil /enum-drivers failed (exit=" +
                           std::to_string(code) + "):\n" + out;
                }
                // oem missing early exit: an explicit uninstall still
                // removes our own self-heal artifacts (best-effort warning
                // only; the task/mirror are this product's own artifacts,
                // verdict 0.3-2). The "not published" verdict stays.
                std::string msg =
                    "no published ndisrd driver found (oem##.inf enumeration came back empty)";
                std::wstring task_note;
                const bool task_ok = hooks.remove_boot_task
                    ? hooks.remove_boot_task(task_note)
                    : RemoveBootTask(task_note);
                std::wstring mirror_note;
                const bool mirror_ok = hooks.remove_mirror_copy
                    ? hooks.remove_mirror_copy(mirror_note)
                    : RemoveMirrorCopy(mirror_note);
                std::wstring warn;
                if (!task_ok) {
                    warn += task_note.empty()
                                ? L"VGWW-GrantAccess task delete failed"
                                : task_note;
                }
                if (!mirror_ok) {
                    if (!warn.empty()) {
                        warn += L"; ";
                    }
                    warn += mirror_note.empty()
                                ? L"vgww.exe mirror delete failed"
                                : mirror_note;
                }
                if (!warn.empty()) {
                    msg += "\nself-heal artifact cleanup warning: " + WideToUtf8(warn);
                }
                return msg;
            }
            // S5.9 wiring: unbind + DeInstall the LWF component through
            // INetCfg BEFORE touching the driver store. Failure here stops
            // the uninstall (no pnp delete) - the component must be gone
            // first so the INF can be retired cleanly. The self-heal task
            // stays registered in that case too: the driver was NOT removed,
            // so the recovery device must not be dismantled.
            InetCfgSessionFactory factory = inetcfg_factory
                ? inetcfg_factory : CreateComInetCfgSessionFactory();
            auto session = factory();
            if (!session) {
                return "INetCfg: cannot create the configuration session";
            }
            const std::string inet_err =
                UninstallNdisrdLwfComponent(*session);
            if (!inet_err.empty()) {
                return "INetCfg: " + inet_err;
            }
            // 2) Delete EVERY published driver entry (plural; a store may
            // hold several ndisrd versions - batch16 B-9). Any failure names
            // the entry it stopped on.
            for (const std::string& oem : oems) {
                std::wstring oem_wide(oem.begin(), oem.end());
                std::string del_out;
                DWORD del_code = 1;
                if (!RunPnputilChannel(runner,
                                       BuildDeleteDriverArgs(oem_wide),
                                       del_out, del_code)) {
                    return "failed to start pnputil.exe (uninstall path)";
                }
                if (0 != del_code) {
                    return "pnputil /delete-driver " + oem +
                           " failed (exit=" + std::to_string(del_code) +
                           "):\n" + del_out;
                }
            }
            // 3) Cleanup phase. The driver is gone; dismantle the self-heal
            // artifacts (task + mirror) and the residues of the retired
            // channels, reporting every failure as a residual (batch16
            // F5/F7). The SCM cleanup is a residual too: a DeleteService that
            // silently failed used to leave a dead registration behind with
            // no diagnostic at all.
            std::vector<std::wstring> residual;
            std::wstring note;
            const bool scm_ok = hooks.cleanup_legacy_service
                ? hooks.cleanup_legacy_service(note)
                : CleanupLegacyServiceRegistration(note);
            if (!scm_ok) {
                residual.push_back(
                    note.empty() ? L"ndisrd SCM service delete failed" : note);
            }
            note.clear();
            const bool task_ok = hooks.remove_boot_task
                ? hooks.remove_boot_task(note)
                : RemoveBootTask(note);
            if (!task_ok) {
                residual.push_back(
                    note.empty() ? L"VGWW-GrantAccess task delete failed" : note);
            }
            note.clear();
            const bool mirror_ok = hooks.remove_mirror_copy
                ? hooks.remove_mirror_copy(note)
                : RemoveMirrorCopy(note);
            if (!mirror_ok) {
                residual.push_back(
                    note.empty() ? L"vgww.exe mirror delete failed" : note);
            }
            // 4) Drop a manual System32 copy the retired channel may have
            //    left (defect #1 residue; S5.4B copied ndisrd.sys there).
            //    A failure is reported, never swallowed (F7/B-3).
            note.clear();
            const bool sys32_ok = hooks.remove_system32_copy
                ? hooks.remove_system32_copy(note)
                : RemoveSystem32Copy(note);
            if (!sys32_ok) {
                residual.push_back(
                    note.empty()
                        ? L"System32\\drivers\\ndisrd.sys delete failed"
                        : note);
            }
            // 5) Terminal audit (read-only): a stale SCM registration that
            //    survived the cleanup. Skipped when the SCM channel was
            //    injected (the hook owns that domain; tests stay headless).
            if (!hooks.cleanup_legacy_service &&
                LegacyServiceStillRegistered()) {
                residual.push_back(
                    L"the ndisrd SCM service still exists (it may still be running)");
            }
            if (!residual.empty()) {
                std::wstring joined;
                for (const std::wstring& item : residual) {
                    if (!joined.empty()) {
                        joined += L"; ";
                    }
                    joined += item;
                }
                return "uninstalled, but leftovers remain: " + WideToUtf8(joined);
            }
            return "";
        }

        // -------------------------------------------------------------------
        // S5.9: INetCfg programming channel orchestration. The COM session is
        // a pure interface (injectable for headless tests); these functions
        // define the call order and the D9 error-pairing (Close ALWAYS runs).
        // -------------------------------------------------------------------

        namespace {

            /// INF component/model id of the WinpkFilter LWF (ndisrd_lwf.inf,
            /// [Ntkr*] ddInstall section). Same string is used by the COM
            /// Install/DeInstall and as the bind owner.
            constexpr const wchar_t kNdisrdLwfId[] = L"nt_ndisrd";

            constexpr wchar_t kClientDescription[] =
                L"VGWW ndisrd driver installer";

            /// Write-lock wait window; the network config API docs recommend
            /// a few seconds so a transient UI lock holder has time to leave.
            constexpr DWORD kLockTimeoutMs = 15000U;

            /// HRESULT -> short ASCII-ish description for user diagnostics.
            std::string HrText(HRESULT hr) {
                char buf[64] = {0};
                const int n = std::snprintf(
                    buf, sizeof(buf), "0x%08X", static_cast<unsigned>(hr));
                return std::string(buf, n);
            }

            /// Wide -> UTF-8 without losing data (avoids wchar->char
            /// truncation warnings under /W4; used only for messages).
            std::string ToNarrow(const std::wstring& w) {
                if (w.empty()) {
                    return {};
                }
                const int n = ::WideCharToMultiByte(CP_UTF8, 0, w.c_str(),
                                                    -1, nullptr, 0, nullptr,
                                                    nullptr);
                if (n <= 1) {
                    return {};
                }
                std::string out(static_cast<size_t>(n) - 1, '\0');
                ::WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, out.data(),
                                      n, nullptr, nullptr);
                return out;
            }

            /// Real INetCfg COM session (admin + active write lock needed).
            /// Mirrors the documented sequence: CoCreateInstance
            /// (CLSID_CNetCfg) -> AcquireWriteLock -> Initialize (the write
            /// lock must be granted before Initialize, see S5.18) -> class
            /// setup install/bindings -> Apply, then reverse order in Close
            /// (D9 pairing). CLSID_CNetCfg/{GUID} symbols resolve from
            /// uuid.lib, ole32 provides the COM entry points.
            class ComInetCfgSession final : public InetCfgSession {
            public:
                ~ComInetCfgSession() override { Close(); }

                std::string Open() override {
                    if (m_net_cfg != nullptr) {
                        return "";  // already open (idempotent)
                    }
                    const HRESULT co =
                        ::CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
                    if (RPC_E_CHANGED_MODE == co) {
                        // Already in MTA; we do NOT own a CoUninitialize.
                        m_com_initialized = false;
                    } else if (FAILED(co)) {
                        // Hard COM init failure: bail before touching
                        // INetCfg (D9 explicit error path, no partial).
                        return "CoInitializeEx failed: " + HrText(co);
                    } else {
                        // S_OK (first init) or S_FALSE (refcounted init):
                        // both pair with CoUninitialize in Close().
                        m_com_initialized = true;
                    }
                    HRESULT hr = ::CoCreateInstance(
                        CLSID_CNetCfg, nullptr, CLSCTX_INPROC_SERVER,
                        IID_INetCfg, reinterpret_cast<void**>(&m_net_cfg));
                    if (FAILED(hr)) {
                        m_net_cfg = nullptr;
                        if (m_com_initialized) {
                            ::CoUninitialize();
                            m_com_initialized = false;
                        }
                        return "INetCfg: CoCreateInstance(CLSID_CNetCfg) "
                               "failed: " + HrText(hr) +
                               " (run as Administrator)";
                    }
                    return "";
                }

                std::string AcquireWriteLock() override {
                    if (nullptr == m_net_cfg) {
                        return "INetCfg session is not open";
                    }
                    if (m_lock_locked) {
                        return "";  // already held (idempotent)
                    }
                    HRESULT hr = m_net_cfg->QueryInterface(
                        IID_INetCfgLock,
                        reinterpret_cast<void**>(&m_lock));
                    if (FAILED(hr)) {
                        return "INetCfgLock QueryInterface failed: " + HrText(hr);
                    }
                    LPWSTR holder = nullptr;
                    hr = m_lock->AcquireWriteLock(kLockTimeoutMs,
                                                  kClientDescription,
                                                  &holder);
                    if (hr != S_OK) {
                        // S_FALSE = the wait time elapsed before the OS
                        // granted the lock (NOT a FAILED hr); treat it as an
                        // error. Error codepath may not deliver a holder.
                        if (holder != nullptr) {
                            std::string sh;
                            const int n = ::WideCharToMultiByte(
                                CP_UTF8, 0, holder, -1, nullptr, 0, nullptr,
                                nullptr);
                            if (n > 1) {
                                sh.resize(static_cast<size_t>(n) - 1);
                                ::WideCharToMultiByte(
                                    CP_UTF8, 0, holder, -1, sh.data(),
                                    n, nullptr, nullptr);
                            }
                            const std::string detail =
                                sh.empty()
                                     ? ""
                                     : "(currently held by " + sh + ")";
                            ::CoTaskMemFree(holder);
                            holder = nullptr;
                            return "INetCfg write lock acquisition failed: " + HrText(hr) + detail;
                        }
                        return "INetCfg write lock acquisition failed: " + HrText(hr);
                    }
                    if (holder != nullptr) {
                        ::CoTaskMemFree(holder);
                    }
                    // The lock is held now; INetCfg::Initialize must run
                    // after the write lock was acquired (the documented
                    // order: AcquireWriteLock before Initialize). Use a
                    // boolean so Close can Uninitialize symmetrically and
                    // only when it actually was initialized.
                    hr = m_net_cfg->Initialize(nullptr);
                    if (FAILED(hr)) {
                        m_lock->ReleaseWriteLock();
                        m_lock_locked = false;
                        return "INetCfg::Initialize failed: " + HrText(hr);
                    }
                    m_initialized = true;
                    m_lock_locked = true;
                    return "";
                }

                std::string Find(const std::wstring& inf_id,
                                 bool& found) override {
                    found = false;
                    if (nullptr == m_net_cfg) {
                        return "INetCfg session is not open";
                    }
                    INetCfgComponent* comp = nullptr;
                    const HRESULT hr = m_net_cfg->FindComponent(
                        inf_id.c_str(), &comp);
                    if (FAILED(hr) && hr != S_FALSE && hr != E_FAIL) {
                        return "INetCfg::FindComponent failed: " + HrText(hr);
                    }
                    found = (comp != nullptr);
                    if (comp != nullptr) {
                        comp->Release();
                    }
                    return "";
                }

                std::string Install(const std::wstring& inf_id,
                                    bool& installed) override {
                    installed = false;
                    if (nullptr == m_net_cfg) {
                        return "INetCfg session is not open";
                    }
                    INetCfgClassSetup* setup = nullptr;
                    HRESULT hr = m_net_cfg->QueryNetCfgClass(
                        &GUID_DEVCLASS_NETSERVICE, IID_INetCfgClassSetup,
                        reinterpret_cast<void**>(&setup));
                    if (FAILED(hr)) {
                        return "INetCfg::QueryNetCfgClass failed: " + HrText(hr);
                    }
                    INetCfgComponent* item = nullptr;
                    // For non-GUID_DEVCLASS_NET components (here:
                    // GUID_DEVCLASS_NETSERVICE), Install requires a non-null
                    // OBO_TOKEN (MS ff547711; Bindview passes OBO_USER).
                    OBO_TOKEN obo;
                    ZeroMemory(&obo, sizeof(obo));
                    obo.Type = OBO_USER;
                    hr = setup->Install(inf_id.c_str(), &obo,
                                        /*dwSetupFlags=*/0,
                                        /*dwUpgradeFromBuildNo=*/0, nullptr,
                                        nullptr, &item);
                    if (FAILED(hr)) {
                        setup->Release();
                        // NETCFG_S_REBOOT (takes effect after a reboot) counts
                        // as a successful install.
                        return (hr == NETCFG_S_REBOOT)
                                   ? ""
                                   : "INetCfgClassSetup::Install failed: "
                                         + HrText(hr);
                    }
                    if (item != nullptr) {
                        item->Release();
                    }
                    setup->Release();
                    installed = true;
                    return "";
                }

                std::string EnumerateAdapters(
                    std::vector<std::wstring>& device_ids) override {
                    device_ids.clear();
                    if (nullptr == m_net_cfg) {
                        return "INetCfg session is not open";
                    }
                    IEnumNetCfgComponent* enumer = nullptr;
                    HRESULT hr = m_net_cfg->EnumComponents(
                        &GUID_DEVCLASS_NET,
                        reinterpret_cast<IEnumNetCfgComponent**>(&enumer));
                    if (FAILED(hr)) {
                        return "INetCfg::EnumComponents failed: " + HrText(hr);
                    }
                    for (;;) {
                        INetCfgComponent* comp = nullptr;
                        ULONG got = 0;
                        hr = enumer->Next(1, &comp, &got);
                        if (S_OK != hr || comp == nullptr) {
                            break;
                        }
                        DWORD ch = 0;
                        comp->GetCharacteristics(&ch);
                        // device_ids carries the bind name (GetBindName) for
                        // the later Bind/Unbind lookup; skip non-physical and
                        // hidden entries.
                        if (ch & NCF_PHYSICAL) {
                            LPWSTR bind_name = nullptr;
                            comp->GetBindName(&bind_name);
                            if (bind_name != nullptr) {
                                device_ids.emplace_back(bind_name);
                                ::CoTaskMemFree(bind_name);
                            }
                        }
                        comp->Release();
                    }
                    enumer->Release();
                    return "";
                }

                std::string BindToAdapter(const std::wstring& filter_id,
                                          const std::wstring& adapter_id,
                                          bool& bound) override {
                    bound = false;
                    if (nullptr == m_net_cfg) {
                        return "INetCfg session is not open";
                    }
                    INetCfgComponent* adapter_comp = nullptr;
                    if (!FindAdapterComponent(adapter_id, &adapter_comp)) {
                        return "no physical adapter bind target for " +
                               ToNarrow(adapter_id);
                    }
                    INetCfgComponent* filter_comp = nullptr;
                    HRESULT hr = m_net_cfg->FindComponent(
                        filter_id.c_str(), &filter_comp);
                    if (FAILED(hr) || filter_comp == nullptr) {
                        adapter_comp->Release();
                        return "LWF component not found: " + ToNarrow(filter_id);
                    }
                    INetCfgComponentBindings* bindings = nullptr;
                    hr = filter_comp->QueryInterface(
                        IID_INetCfgComponentBindings,
                        reinterpret_cast<void**>(&bindings));
                    filter_comp->Release();
                    if (FAILED(hr)) {
                        adapter_comp->Release();
                        return "INetCfgComponentBindings QI failed: " +
                               HrText(hr);
                    }
                    hr = bindings->BindTo(adapter_comp);
                    bindings->Release();
                    adapter_comp->Release();
                    if (FAILED(hr)) {
                        const std::string f = ToNarrow(filter_id);
                        const std::string a = ToNarrow(adapter_id);
                        return "INetCfg bind (" + f + "<-" + a + ") failed: " +
                               HrText(hr);
                    }
                    bound = true;
                    return "";
                }

                std::string UnbindFromAdapter(
                    const std::wstring& filter_id,
                    const std::wstring& adapter_id,
                    bool& unbound) override {
                    unbound = false;
                    if (nullptr == m_net_cfg) {
                        return "INetCfg session is not open";
                    }
                    INetCfgComponent* adapter_comp = nullptr;
                    if (!FindAdapterComponent(adapter_id, &adapter_comp)) {
                        return "no physical adapter unbind target: " + ToNarrow(adapter_id);
                    }
                    INetCfgComponent* filter_comp = nullptr;
                    HRESULT hr = m_net_cfg->FindComponent(
                        filter_id.c_str(), &filter_comp);
                    if (FAILED(hr) || filter_comp == nullptr) {
                        adapter_comp->Release();
                        return "LWF component not found: " + ToNarrow(filter_id);
                    }
                    INetCfgComponentBindings* bindings = nullptr;
                    hr = filter_comp->QueryInterface(
                        IID_INetCfgComponentBindings,
                        reinterpret_cast<void**>(&bindings));
                    filter_comp->Release();
                    if (FAILED(hr)) {
                        adapter_comp->Release();
                        return "INetCfgComponentBindings QI failed: " +
                               HrText(hr);
                    }
                    hr = bindings->UnbindFrom(adapter_comp);
                    bindings->Release();
                    adapter_comp->Release();
                    if (FAILED(hr)) {
                        const std::string f = ToNarrow(filter_id);
                        const std::string a = ToNarrow(adapter_id);
                        return "INetCfg unbind (" + f + "<-" + a + ") failed: " +
                               HrText(hr);
                    }
                    unbound = true;
                    return "";
                }

                std::string DeInstall(const std::wstring& inf_id,
                                      bool& removed) override {
                    removed = false;
                    if (nullptr == m_net_cfg) {
                        return "INetCfg session is not open";
                    }
                    INetCfgComponent* comp = nullptr;
                    HRESULT hr = m_net_cfg->FindComponent(inf_id.c_str(),
                                                          &comp);
                    if (comp == nullptr) {
                        // Component already gone -> no deinstall needed
                        // (same meaning as idempotent).
                        return "";
                    }
                    INetCfgClassSetup* setup = nullptr;
                    hr = m_net_cfg->QueryNetCfgClass(
                        &GUID_DEVCLASS_NETSERVICE, IID_INetCfgClassSetup,
                        reinterpret_cast<void**>(&setup));
                    if (FAILED(hr)) {
                        comp->Release();
                        return "INetCfg::QueryNetCfgClass failed: " + HrText(hr);
                    }
                    LPWSTR refs = nullptr;
                    // Same non-null OBO_TOKEN requirement as Install for
                    // non-GUID_DEVCLASS_NET classes (MS ff547710).
                    OBO_TOKEN obo;
                    ZeroMemory(&obo, sizeof(obo));
                    obo.Type = OBO_USER;
                    hr = setup->DeInstall(comp, &obo, &refs);
                    if (refs != nullptr) {
                        ::CoTaskMemFree(refs);
                    }
                    comp->Release();
                    setup->Release();
                    if (FAILED(hr)) {
                        return "INetCfgClassSetup::DeInstall failed: " +
                               HrText(hr);
                    }
                    removed = true;
                    return "";
                }

                std::string Apply() override {
                    if (nullptr == m_net_cfg) {
                        return "INetCfg session is not open";
                    }
                    const HRESULT hr = m_net_cfg->Apply();
                    if (FAILED(hr)) {
                        return "INetCfg::Apply failed: " + HrText(hr);
                    }
                    return "";
                }

                void Close() override {
                    // Documented teardown order (Bindview): Uninitialize
                    // before ReleaseWriteLock, so no other INetCfg client can
                    // grab the config while we are still initialized.
                    if (m_initialized && m_net_cfg != nullptr) {
                        m_net_cfg->Uninitialize();
                        m_initialized = false;
                    }
                    if (m_lock_locked && m_lock != nullptr) {
                        m_lock->ReleaseWriteLock();
                        m_lock_locked = false;
                    }
                    if (m_lock != nullptr) {
                        m_lock->Release();
                        m_lock = nullptr;
                    }
                    if (m_net_cfg != nullptr) {
                        m_net_cfg->Release();
                        m_net_cfg = nullptr;
                    }
                    if (m_com_initialized) {
                        ::CoUninitialize();
                        m_com_initialized = false;
                    }
                }

            private:
                /// Finds an INetCfgComponent whose getbind-name equals
                /// `adapter_id`. Returns true and sets *out.
                bool FindAdapterComponent(
                    const std::wstring& adapter_id,
                    INetCfgComponent** out) const {
                    if (out == nullptr) {
                        return false;
                    }
                    *out = nullptr;
                    IEnumNetCfgComponent* enumer = nullptr;
                    HRESULT hr = m_net_cfg->EnumComponents(
                        &GUID_DEVCLASS_NET,
                        reinterpret_cast<IEnumNetCfgComponent**>(&enumer));
                    if (FAILED(hr) || enumer == nullptr) {
                        return false;
                    }
                    bool found = false;
                    for (;;) {
                        INetCfgComponent* comp = nullptr;
                        ULONG got = 0;
                        hr = enumer->Next(1, &comp, &got);
                        if (S_OK != hr || comp == nullptr) {
                            break;
                        }
                        DWORD ch = 0;
                        comp->GetCharacteristics(&ch);
                        if (ch & NCF_PHYSICAL) {
                            LPWSTR bind_name = nullptr;
                            comp->GetBindName(&bind_name);
                            if (bind_name != nullptr &&
                                adapter_id == bind_name) {
                                *out = comp;
                                ::CoTaskMemFree(bind_name);
                                found = true;
                                break;
                            }
                            if (bind_name != nullptr) {
                                ::CoTaskMemFree(bind_name);
                            }
                        }
                        comp->Release();
                    }
                    enumer->Release();
                    return found;
                }

                INetCfg* m_net_cfg = nullptr;
                INetCfgLock* m_lock = nullptr;
                bool m_lock_locked = false;
                bool m_initialized = false;
                bool m_com_initialized = false;
            };

        }  // namespace

        InetCfgSessionFactory CreateComInetCfgSessionFactory() {
            return [] {
                return std::unique_ptr<InetCfgSession>(
                    new ComInetCfgSession());
            };
        }

        std::string InstallNdisrdLwfComponent(InetCfgSession& session) {
            // Order (lock -> find/install -> enumerate -> bind -> apply).
            std::string err = session.Open();
            if (!err.empty()) {
                return err;
            }
            err = session.AcquireWriteLock();
            if (!err.empty()) {
                session.Close();
                return err;
            }
            bool installed = false;
            err = session.Install(kNdisrdLwfId, installed);
            if (!err.empty()) {
                session.Close();
                return err;
            }
            std::vector<std::wstring> adapters;
            err = session.EnumerateAdapters(adapters);
            if (!err.empty()) {
                session.Close();
                return err;
            }
            for (const std::wstring& adapter : adapters) {
                bool bound = false;
                err = session.BindToAdapter(kNdisrdLwfId, adapter, bound);
                if (!err.empty()) {
                    session.Close();
                    return err;
                }
            }
            err = session.Apply();
            session.Close();
            return err;
        }

        std::string UninstallNdisrdLwfComponent(InetCfgSession& session) {
            std::string err = session.Open();
            if (!err.empty()) {
                return err;
            }
            err = session.AcquireWriteLock();
            if (!err.empty()) {
                session.Close();
                return err;
            }
            // Find: informational in the mock (records the call); a missing
            // component is not an error for uninstall.
            bool found = false;
            err = session.Find(kNdisrdLwfId, found);
            if (!err.empty()) {
                session.Close();
                return err;
            }
            std::vector<std::wstring> adapters;
            err = session.EnumerateAdapters(adapters);
            if (!err.empty()) {
                session.Close();
                return err;
            }
            for (const std::wstring& adapter : adapters) {
                bool unbound = false;
                err = session.UnbindFromAdapter(kNdisrdLwfId, adapter,
                                                unbound);
                if (!err.empty()) {
                    session.Close();
                    return err;
                }
            }
            bool removed = false;
            err = session.DeInstall(kNdisrdLwfId, removed);
            if (!err.empty()) {
                session.Close();
                return err;
            }
            err = session.Apply();
            session.Close();
            return err;
        }

        // -------------------------------------------------------------------
        // Install-report IO (batch16 F2): see installer.h.
        // -------------------------------------------------------------------

        std::filesystem::path DefaultInstallReportPath() {
            wchar_t pd[MAX_PATH] = {0};
            const DWORD got =
                ::GetEnvironmentVariableW(L"ProgramData", pd, MAX_PATH);
            if (!EnvValueFitsBuffer(got)) {
                return {};
            }
            const std::filesystem::path vgww_dir =
                MakeProgramDataPath(std::wstring(pd, got));
            if (vgww_dir.empty()) {
                return {};
            }
            return vgww_dir / L"install-report.txt";
        }

        bool WriteInstallReport(const std::filesystem::path& path,
                                const std::string& status, int exit_code,
                                const std::string& detail) {
            if (path.empty()) {
                return false;
            }
            std::error_code ec;
            const std::filesystem::path parent = path.parent_path();
            if (!parent.empty()) {
                std::filesystem::create_directories(parent, ec);
            }
            std::ofstream f(path, std::ios::binary | std::ios::trunc);
            if (!f.good()) {
                return false;  // best-effort: never changes the exit code
            }
            f << "status=" << status << "\n";
            f << "exit=" << exit_code << "\n";
            f << "---\n";
            f << detail;
            return f.good();
        }

        InstallReport ReadInstallReport(const std::filesystem::path& path) {
            InstallReport report;
            if (path.empty()) {
                return report;
            }
            std::ifstream f(path, std::ios::binary);
            if (!f.good()) {
                return report;  // missing: "did not report completion"
            }
            const auto strip_cr = [](std::string s) {
                if (!s.empty() && '\r' == s.back()) {
                    s.pop_back();
                }
                return s;
            };
            std::string line1;
            std::string line2;
            std::string line3;
            if (!std::getline(f, line1) || !std::getline(f, line2) ||
                !std::getline(f, line3)) {
                return report;  // malformed
            }
            line1 = strip_cr(line1);
            line2 = strip_cr(line2);
            line3 = strip_cr(line3);
            if (line1.rfind("status=", 0) != 0 ||
                line2.rfind("exit=", 0) != 0 || line3 != "---") {
                return report;  // malformed
            }
            const std::string status = line1.substr(7);
            if (status != "running" && status != "ok" && status != "fail") {
                return report;  // unknown status: do not trust the file
            }
            int exit_code = 0;
            try {
                exit_code = std::stoi(line2.substr(5));
            } catch (const std::exception&) {
                return report;
            }
            report.status = status;
            report.exit_code = exit_code;
            report.detail.assign(std::istreambuf_iterator<char>(f),
                                 std::istreambuf_iterator<char>());
            return report;
        }

        ElevatedInstallResult RunElevatedInstallAndWait(DWORD wait_ms) {
            ElevatedInstallResult result;
            // batch331 P2: MAX_PATH truncated a vgww.exe living in a long
            // directory, so "repair driver" reported "cannot locate".
            // ExecutablePath() grows past MAX_PATH (same rule as ExeDir()) and
            // returns empty only on a real resolution failure.
            const std::wstring exe_w = ExecutablePath();
            if (exe_w.empty()) {
                result.outcome = ElevatedInstallOutcome::ElevationRefused;
                result.spawn_error = ERROR_FILE_NOT_FOUND;
                result.detail = "cannot locate the vgww.exe path";
                return result;
            }
            const wchar_t* exe = exe_w.c_str();
            const std::filesystem::path report = DefaultInstallReportPath();
            // Best-effort: drop a stale report so a child that crashes
            // before writing cannot be misread. Correctness does NOT depend
            // on this (the entry sentinel + exit-code correlation do the
            // real work); a normal user may lack DELETE rights on a file an
            // elevated child created, hence "best-effort".
            if (!report.empty()) {
                std::error_code ec;
                std::filesystem::remove(report, ec);
            }
            std::wstring params = L"--install-driver";
            SHELLEXECUTEINFOW sei{};
            sei.cbSize = sizeof(sei);
            sei.fMask = SEE_MASK_NOCLOSEPROCESS;
            sei.lpVerb = L"runas";
            sei.lpFile = exe;
            sei.lpParameters = params.c_str();
            sei.nShow = SW_HIDE;
            if (!::ShellExecuteExW(&sei)) {
                result.outcome = ElevatedInstallOutcome::ElevationRefused;
                result.spawn_error = ::GetLastError();
                result.detail = "elevated launch failed";
                return result;
            }
            if (nullptr == sei.hProcess) {
                result.outcome = ElevatedInstallOutcome::StillRunning;
                result.detail = "install process handle is missing";
                return result;
            }
            const DWORD wait = ::WaitForSingleObject(sei.hProcess, wait_ms);
            if (WAIT_TIMEOUT == wait) {
                DWORD live = STILL_ACTIVE;
                ::GetExitCodeProcess(sei.hProcess, &live);
                if (STILL_ACTIVE == live) {
                    result.outcome = ElevatedInstallOutcome::StillRunning;
                    result.detail = "the install is still running";
                    ::CloseHandle(sei.hProcess);
                    return result;
                }
            }
            DWORD code = 1;
            if (!::GetExitCodeProcess(sei.hProcess, &code)) {
                code = 1;
            }
            ::CloseHandle(sei.hProcess);
            result.exit_code = code;
            const InstallReport rep = ReadInstallReport(report);
            if ("ok" == rep.status && 0 == code) {
                result.outcome = ElevatedInstallOutcome::InstallOk;
                return result;
            }
            result.outcome = ElevatedInstallOutcome::InstallFailed;
            if ("fail" == rep.status && !rep.detail.empty()) {
                result.detail = rep.detail;
            } else if ("fail" == rep.status) {
                result.detail = "the installer reported failure (exit=" +
                                std::to_string(code) + ")";
            } else {
                result.detail = "the installer never reported completion (exit=" +
                                std::to_string(code) + ", no valid report)";
            }
            return result;
        }

        bool RunElevatedGrantAccessOnlyWait(DWORD wait_ms) {
            // batch331 P2: long-path tolerant resolution (same reason and
            // pattern as RunElevatedInstallAndWait).
            std::wstring exe_w;
            DWORD cap = MAX_PATH;
            while (true) {
                exe_w.resize(cap);
                const DWORD got =
                    ::GetModuleFileNameW(nullptr, exe_w.data(), cap);
                if (0 == got) {
                    return false;
                }
                if (got < cap) {
                    exe_w.resize(got);
                    break;
                }
                if (cap >= 32767) {
                    return false;
                }
                cap *= 2;
            }
            const wchar_t* exe = exe_w.c_str();
            std::wstring params = L"--grant-access-only";
            SHELLEXECUTEINFOW sei{};
            sei.cbSize = sizeof(sei);
            sei.fMask = SEE_MASK_NOCLOSEPROCESS;
            sei.lpVerb = L"runas";
            sei.lpFile = exe;
            sei.lpParameters = params.c_str();
            sei.nShow = SW_HIDE;
            if (!::ShellExecuteExW(&sei) || nullptr == sei.hProcess) {
                return false;  // UAC refused or spawn failure
            }
            const DWORD wait = ::WaitForSingleObject(sei.hProcess, wait_ms);
            DWORD code = 1;
            ::GetExitCodeProcess(sei.hProcess, &code);
            ::CloseHandle(sei.hProcess);
            return WAIT_OBJECT_0 == wait && 0 == code;
        }

    }  // namespace driver
}  // namespace vgww
