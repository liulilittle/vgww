// ============================================================================
// tray.h - notification-area icon, context menu and autostart registry
// (S4.2 Task 6).
//
// Everything here must run on the UI thread (Shell_NotifyIcon and the popup
// menu require it). Add() registers the icon for a window; the window's
// WndProc forwards messages to HandleWindowMessage(), which owns the popup
// menu and dispatches to the registered Callbacks (VgwwWindow installs
// defaults; T7 may override).
//
// Autostart: HKCU\Software\Microsoft\Windows\CurrentVersion\Run, value name
// "VGWW", data = "<exe>" [--config <path>] --minimized (the --config part is
// preserved from the current process command line).
// ============================================================================
#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#include <windows.h>
// batch318: PNOTIFYICONDATAW (the ShellNotifyFn test seam) lives here.
#include <shellapi.h>

#include "ui/theme.h"  // Color (icon pixel helpers)

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace vgww {
    namespace ui {
        namespace tray {

            /// Menu/notification hooks (UI thread).
            struct Callbacks {
                std::function<void()> on_show;
                std::function<void()> on_hide;
                /// batch29: "Open dashboard" - show the window AND switch to
                /// the dashboard page (one activation, no second path).
                std::function<void()> on_open_dashboard;
                /// batch28: "Start service" / "Stop service" from the tray.
                /// The app routes it into the SAME command channel the window
                /// uses (Command{StartServiceCmd/StopServiceCmd}), never a
                /// second execution path.
                std::function<void(bool /*start*/)> on_toggle_service;
                std::function<void()> on_exit;
            };

            /// Installs the callbacks used by the context menu.
            void SetCallbacks(Callbacks callbacks);

            /// batch28: the service state the next popup menu shows (true ->
            /// the item reads "Stop service"). Written by the app tick and read
            /// by the UI thread when the menu opens.
            void SetServiceRunning(bool running) noexcept;
            /// batch28: menu id of the service item (test seam: a headless test
            /// can assert the dispatch posts exactly one command).
            int ServiceMenuCommand() noexcept;
            /// batch29: menu id of the "Open dashboard" item (test seam).
            int OpenDashboardMenuCommand() noexcept;
            /// batch28: runs the menu command `command` exactly like the popup
            /// did (the popup itself is modal and cannot run headless).
            void DispatchMenuCommand(UINT command) noexcept;
            /// batch28: the items the next popup would show (id, label,
            /// checked), built by the SAME code the popup uses. Lets the debug
            /// channel prove the service label follows the live state without
            /// opening a modal menu.
            struct MenuItemView {
                unsigned int id = 0;
                std::wstring label;
                bool checked = false;
            };
            std::vector<MenuItemView> MenuItems();

            /// Adds the notification icon (tip = tooltip). Returns false when
            /// Shell_NotifyIcon fails; the caller must not hide the window in
            /// that case (no way back).
            bool Add(HWND hwnd, HICON icon, std::wstring tip);
            /// Removes the icon; idempotent.
            void Remove() noexcept;

            /// batch318: the Explorer "TaskbarCreated" broadcast id (0 when
            /// RegisterWindowMessageW fails). Stable for the process lifetime.
            UINT RegisterTaskbarMessage() noexcept;
            /// True when `message` is that broadcast. HandleWindowMessage
            /// consumes it and re-registers the icon.
            bool IsTaskbarCreatedMessage(UINT message) noexcept;
            /// Re-registers the last requested icon: after an Explorer restart
            /// every Shell_NotifyIcon icon is gone, and a startup registration
            /// that failed before the shell was up can be retried here.
            /// Returns false when no window was ever registered or the shell
            /// refuses. Idempotent.
            bool ReAddAfterTaskbarCreated() noexcept;
            /// True while the shell holds our icon.
            bool IsAdded() noexcept;
            /// Test seam: replaces Shell_NotifyIconW (nullptr restores it).
            using ShellNotifyFn = BOOL(WINAPI*)(DWORD, PNOTIFYICONDATAW);
            void SetShellNotifyForTest(ShellNotifyFn fn) noexcept;

            /// Stores the autostart state used by the next popup menu (the
            /// menu itself is built on demand).
            void UpdateMenu(bool autostart);

            /// Writes/deletes the HKCU Run value. Returns false with `error`
            /// on a registry failure.
            bool SetAutostart(bool enabled, std::string& error);
            bool IsAutostartEnabled();

            /// Programmatic icon: rounded dark square + cyan "V"; falls back
            /// to IDI_APPLICATION when GDI creation fails. Parameter names
            /// avoid the legacy `small` macro from rpcndr.h (windows.h).
            void MakeAppIcon(HICON* small_icon, HICON* big_icon);

            /// Packs one sRGB color into the icon's 32-bit BGRA word (alpha
            /// 255). Exposed so the icon test can identify the accent color.
            std::uint32_t PackIconPixel(Color color) noexcept;

            /// Fills a `size` x `size` row-major BGRA buffer with the app
            /// icon (rounded square + cyan V). `bottom_up` selects the row
            /// order of the target bitmap (positive DIB height = true); the
            /// icon must look identical on screen either way (V apex at the
            /// bottom). Pure pixel work - the test seam for the orientation
            /// test (T6 review M1).
            void FillAppIconPixels(std::uint32_t* pixels, int size,
                                   bool bottom_up) noexcept;

            /// One-shot info balloon (close-to-tray hint).
            void ShowBalloon(const std::wstring& title, const std::wstring& text);

            /// Handles the tray callback message from the registered window.
            /// Returns true when the message was consumed.
            bool HandleWindowMessage(HWND hwnd, UINT message, WPARAM wparam,
                                     LPARAM lparam);

        }  // namespace tray
    }  // namespace ui
}  // namespace vgww
