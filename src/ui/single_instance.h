// ============================================================================
// single_instance.h - batch23: single-instance gate for the GUI.
//
// A second `vgww` launch must ACTIVATE the running instance (bring it back from
// the tray / to the foreground) instead of starting a duplicate.
//
// Mechanism (batch23, replaces the batch20 named mutex): a named KERNEL EVENT
// ("VGWW.SingleInstance.v1"). The first instance CREATES it (Primary role) and
// runs a watcher thread that turns a signal into a window activation; a second
// launch OPENS it, signals it (the activation request) and exits 0. The event
// carries an explicit DACL granting Everyone EVENT_MODIFY_STATE|SYNCHRONIZE so
// a second launch can signal it across integrity levels (the process now always
// runs elevated via requireAdministrator; the Everyone grant is harmless).
//
// GATE BYPASS (batch37h, user): ONLY --headless bypasses the gate. That run
// owns no window, so there is nothing to activate. --ui-debug-port=<n> and
// --ui-page=<id> USED TO bypass the gate as well; that was removed because a
// debug instance and a normal launch then coexisted as two visible apps.
// Automation that needs a parallel instance must pass --headless, or close
// the running instance first. IsTestLaunch() is a SEPARATE predicate used
// only for the driver device-access re-grant, not for this gate.
// ============================================================================
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

// ConvertStringSecurityDescriptorToSecurityDescriptorW / SDDL_REVISION_1
// (the event's explicit DACL).
#include <sddl.h>

namespace vgww {
    namespace ui {

        /// Named kernel event that marks "the GUI instance is running".
        inline constexpr const wchar_t* kInstanceEventName =
            L"VGWW.SingleInstance.v1";

        /// Event DACL: Everyone (WD) gets EVENT_MODIFY_STATE (0x0002) |
        /// SYNCHRONIZE (0x00100000) = 0x00100002. The explicit SD lets a
        /// second launch (a different integrity level is possible even under
        /// requireAdministrator) open and signal the event.
        inline constexpr const wchar_t* kInstanceEventSddl =
            L"D:(A;;0x00100002;;;WD)";

        /// Posted to the first instance's window to ask it to show + foreground
        /// itself (restores it from the tray).
        inline constexpr UINT kActivateMessage = WM_APP + 0x51;

        /// Which side of the gate a launch landed on.
        enum class InstanceRole {
            Primary,    ///< we created the event: keep running
            Secondary,  ///< another instance exists: signal + exit 0
        };

        /// Result of ClaimSingleInstance.
        struct InstanceClaim {
            InstanceRole role = InstanceRole::Secondary;
            /// Owned by the caller when role==Primary; null when the event
            /// could not be created (degraded single-instance: start anyway).
            HANDLE event = nullptr;
            /// role==Secondary: was the activation signal actually delivered?
            bool signalled = false;
        };

        /// Builds the SECURITY_ATTRIBUTES for the instance event from
        /// kInstanceEventSddl. On success `out_sd` holds the descriptor the
        /// caller must LocalFree; returns false (out_sd == nullptr) when the
        /// SDDL could not be converted.
        inline bool MakeInstanceEventSecurity(SECURITY_ATTRIBUTES& sa,
                                              PSECURITY_DESCRIPTOR* out_sd) {
            if (out_sd == nullptr) {
                return false;
            }
            *out_sd = nullptr;
            PSECURITY_DESCRIPTOR sd = nullptr;
            if (!::ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    kInstanceEventSddl, SDDL_REVISION_1, &sd, nullptr)) {
                return false;  // an unconvertible SDDL must not be used
            }
            sa.nLength = sizeof(sa);
            sa.lpSecurityDescriptor = sd;
            sa.bInheritHandle = FALSE;
            *out_sd = sd;
            return true;
        }

        /// Grants `existing`'s process the right to take the foreground. Returns
        /// true when the pid was resolved and AllowSetForegroundWindow accepted
        /// it (best effort).
        inline bool AllowSetForegroundForWindow(HWND existing) noexcept {
            if (existing == nullptr) {
                return false;
            }
            DWORD pid = 0;
            if (::GetWindowThreadProcessId(existing, &pid) == 0 || pid == 0) {
                return false;
            }
            return ::AllowSetForegroundWindow(pid) != FALSE;
        }

        /// Best-effort: find the running GUI window and grant it the foreground
        /// right. A secondary launch calls this BEFORE SetEvent so the primary's
        /// activation cannot race ahead of the foreground permission.
        inline bool AllowRunningInstanceForeground() noexcept {
            HWND existing = ::FindWindowW(L"VgwwWindowClass", nullptr);
            return existing != nullptr && AllowSetForegroundForWindow(existing);
        }

        /// Creates or opens the single-instance event.
        ///  - Primary: the event did not exist (we created it); `event` is the
        ///    owned handle, or null when creation failed for a non-"exists"
        ///    reason (the app still starts).
        ///  - Secondary: the event already existed; it was signalled when
        ///    possible. The caller exits 0.
        inline InstanceClaim ClaimSingleInstance(
            const wchar_t* name = kInstanceEventName) {
            InstanceClaim claim;

            SECURITY_ATTRIBUTES sa{};
            PSECURITY_DESCRIPTOR sd = nullptr;
            const bool have_sa = MakeInstanceEventSecurity(sa, &sd);

            ::SetLastError(ERROR_SUCCESS);
            HANDLE ev = ::CreateEventW(have_sa ? &sa : nullptr,
                                       FALSE /*auto-reset*/, FALSE, name);
            const DWORD create_err = ::GetLastError();
            if (sd != nullptr) {
                ::LocalFree(sd);
            }

            if (ev != nullptr && create_err != ERROR_ALREADY_EXISTS) {
                // We created the event: this launch is the first instance.
                claim.role = InstanceRole::Primary;
                claim.event = ev;
                return claim;
            }
            if (ev != nullptr) {
                // The named event already existed. CreateEventW asks for
                // EVENT_ALL_ACCESS, so this handle carries the signal right.
                // batch25b: grant the primary the foreground right BEFORE the
                // signal, otherwise its watcher can restore the window before
                // this process has handed the foreground permission over.
                AllowRunningInstanceForeground();
                ::SetEvent(ev);
                ::CloseHandle(ev);
                claim.role = InstanceRole::Secondary;
                claim.signalled = true;
                return claim;
            }

            // CreateEventW failed. When the event exists but this token lacks
            // the rights CreateEventW requests, a minimal-rights OpenEventW
            // still succeeds (this is why the event uses the explicit SDDL).
            HANDLE opened =
                ::OpenEventW(EVENT_MODIFY_STATE | SYNCHRONIZE, FALSE, name);
            if (opened != nullptr) {
                // Same ordering contract as the CreateEventW branch: the
                // foreground grant must precede the activation signal.
                AllowRunningInstanceForeground();
                ::SetEvent(opened);
                ::CloseHandle(opened);
                claim.role = InstanceRole::Secondary;
                claim.signalled = true;
                return claim;
            }
            const DWORD open_err = ::GetLastError();
            if (create_err == ERROR_ACCESS_DENIED ||
                open_err == ERROR_ACCESS_DENIED) {
                // The object exists but neither handle could be taken: treat
                // it as "already running" (best-effort activation, exit 0).
                claim.role = InstanceRole::Secondary;
                claim.signalled = false;
                return claim;
            }
            // The event truly does not exist (creation failed for another
            // reason and the open saw ERROR_FILE_NOT_FOUND): become the
            // primary without a handle; the app still starts. Single-instance
            // enforcement is degraded, never a startup failure.
            claim.role = InstanceRole::Primary;
            claim.event = nullptr;
            return claim;
        }

        /// Brings the running instance to the foreground (best effort). Returns
        /// true when a VgwwWindowClass window was found and the activation
        /// message posted.
        inline bool ActivateRunningInstance() {
            HWND existing = ::FindWindowW(L"VgwwWindowClass", nullptr);
            if (existing == nullptr) {
                return false;
            }
            (void)AllowSetForegroundForWindow(existing);
            ::SetForegroundWindow(existing);
            ::PostMessageW(existing, kActivateMessage, 0, 0);
            return true;
        }

        /// True when `flag` is one of the test-launch switches (long or short
        /// forms accepted, including --flag=value).
        inline bool IsTestLaunchFlag(const std::string& flag) noexcept {
            static const char* kFlags[] = {"--ui-debug-port", "--ui-page",
                                           "--headless"};
            for (const char* f : kFlags) {
                const std::string prefix(f);
                if (flag == prefix) {
                    return true;
                }
                if (flag.size() > prefix.size() &&
                    flag.compare(0, prefix.size(), prefix) == 0 &&
                    flag[prefix.size()] == '=') {
                    return true;
                }
            }
            return false;
        }

        /// True when any argument marks this launch as a TEST launch. P87:
        /// since batch37h this predicate is NOT used for the single-instance
        /// gate (that gate is bypassed only by a headless run, see main.cpp);
        /// it currently gates the driver device-access re-grant at startup.
        inline bool IsTestLaunch(
            const std::vector<std::string>& args) noexcept {
            for (const std::string& a : args) {
                if (IsTestLaunchFlag(a)) {
                    return true;
                }
            }
            return false;
        }

    }  // namespace ui
}  // namespace vgww
