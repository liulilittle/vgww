// ============================================================================
// tray.cpp - Shell_NotifyIcon icon + menu + HKCU Run autostart (S4.2 Task 6).
// ============================================================================
#include "ui/tray.h"

#include "ui/i18n.h"
#include "ui/theme.h"

#include <shellapi.h>

#include <algorithm>
#include <atomic>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <functional>
#include <vector>

namespace vgww {
    namespace ui {
        namespace tray {

            namespace {

                /// Callback message for the notification icon (window-owned).
                constexpr UINT kTrayCallbackMessage = WM_APP + 1;
                constexpr UINT kIconId = 1;

                constexpr UINT kMenuShow = 1;
                constexpr UINT kMenuHide = 2;
                constexpr UINT kMenuAutostart = 3;
                constexpr UINT kMenuExit = 4;
                /// batch28: service toggle item, placed between "Hide" and the
                /// first separator.
                constexpr UINT kMenuService = 5;
                /// batch29: "Open dashboard", directly under "Show window".
                constexpr UINT kMenuDashboard = 6;

                constexpr wchar_t kRunKey[] =
                    L"Software\\Microsoft\\Windows\\CurrentVersion\\Run";
                constexpr wchar_t kRunValue[] = L"VGWW";

                HWND g_hwnd = nullptr;
                HICON g_icon = nullptr;
                /// batch318: the tip is kept so a re-registration (Explorer
                /// restart, or a retry after a startup failure) rebuilds the
                /// exact same NOTIFYICONDATAW.
                std::wstring g_tip;
                bool g_added = false;
                /// batch318: the shell call is injectable so the re-add state
                /// machine is testable without a real taskbar.
                ShellNotifyFn g_shell_notify = &::Shell_NotifyIconW;
                /// batch164 P1-2 test seam: injectable autostart setter (nullptr
                /// restores the real registry writer).
                std::function<bool(bool, std::string&)> g_autostart_hook;
                // U4: written by the command worker (SetAutostart/UpdateMenu
                // via TrayAutostartHook) and read by the UI thread (ShowMenu);
                // a plain bool would be a data race. Atomic keeps the
                // CHECKED state consistent across the two threads.
                std::atomic<bool> g_autostart_checked{false};
                /// batch28: service state for the menu label ("Start"/"Stop").
                std::atomic<bool> g_service_running{false};
                Callbacks g_callbacks;

                /// Extracts the value of --config / --config=... from the
                /// current process command line (quoted values supported).
                std::wstring ConfigPathFromCommandLine() {
                    const std::wstring command = ::GetCommandLineW();
                    const std::wstring key = L"--config";
                    const size_t pos = command.find(key);
                    if (std::wstring::npos == pos) {
                        return std::wstring();
                    }
                    size_t at = pos + key.size();
                    if (at < command.size() && L'=' == command[at]) {
                        ++at;
                    } else {
                        while (at < command.size() && L' ' == command[at]) {
                            ++at;
                        }
                    }
                    std::wstring value;
                    if (at < command.size() && L'"' == command[at]) {
                        ++at;
                        while (at < command.size() && L'"' != command[at]) {
                            value.push_back(command[at++]);
                        }
                    } else {
                        while (at < command.size() && L' ' != command[at]) {
                            value.push_back(command[at++]);
                        }
                    }
                    return value;
                }

                std::wstring AutostartCommand() {
                    wchar_t exe[MAX_PATH * 4] = {};
                    const DWORD len =
                        ::GetModuleFileNameW(nullptr, exe, ARRAYSIZE(exe));
                    std::wstring command =
                        L"\"" + std::wstring(exe, len) + L"\"";
                    const std::wstring config = ConfigPathFromCommandLine();
                    if (!config.empty()) {
                        command += L" --config \"" + config + L"\"";
                    }
                    command += L" --minimized";
                    return command;
                }

                bool RoundedRectContains(float x, float y, float size,
                                         float radius) noexcept {
                    const float lo = radius;
                    const float hi = size - radius;
                    const float cx = std::min(std::max(x, lo), hi);
                    const float cy = std::min(std::max(y, lo), hi);
                    const float dx = x - cx;
                    const float dy = y - cy;
                    return dx * dx + dy * dy <= radius * radius + 0.0001f;
                }

                float SegmentDistance(float px, float py, float ax, float ay,
                                      float bx, float by) noexcept {
                    const float dx = bx - ax;
                    const float dy = by - ay;
                    const float len2 = dx * dx + dy * dy;
                    float t = len2 > 0.0f
                                  ? ((px - ax) * dx + (py - ay) * dy) / len2
                                  : 0.0f;
                    t = std::min(std::max(t, 0.0f), 1.0f);
                    const float qx = ax + t * dx;
                    const float qy = ay + t * dy;
                    return std::sqrt((px - qx) * (px - qx) +
                                     (py - qy) * (py - qy));
                }

                /// Packs straight (non-premultiplied) BGRA; alpha is 0/255.
                HICON CreateAppIcon(int size) {
                    BITMAPV5HEADER header{};
                    header.bV5Size = sizeof(BITMAPV5HEADER);
                    header.bV5Width = size;
                    header.bV5Height = size;
                    header.bV5Planes = 1;
                    header.bV5BitCount = 32;
                    header.bV5Compression = BI_BITFIELDS;
                    header.bV5RedMask = 0x00FF0000u;
                    header.bV5GreenMask = 0x0000FF00u;
                    header.bV5BlueMask = 0x000000FFu;
                    header.bV5AlphaMask = 0xFF000000u;

                    HDC dc = ::CreateCompatibleDC(nullptr);
                    if (nullptr == dc) {
                        return nullptr;
                    }
                    void* bits = nullptr;
                    HBITMAP color = ::CreateDIBSection(
                        dc, reinterpret_cast<BITMAPINFO*>(&header),
                        DIB_RGB_COLORS, &bits, nullptr, 0);
                    if (nullptr == color || nullptr == bits) {
                        if (color) ::DeleteObject(color);
                        ::DeleteDC(dc);
                        return nullptr;
                    }

                    FillAppIconPixels(static_cast<std::uint32_t*>(bits), size,
                                      /*bottom_up=*/true);  // positive biHeight

                    // Explicitly zeroed 1bpp mask: CreateBitmap with a null
                    // bits pointer leaves the content undefined, and every
                    // pixel must defer to the color bitmap's alpha (M1).
                    const std::size_t mask_stride =
                        ((static_cast<std::size_t>(size) + 15u) / 16u) * 2u;
                    const std::vector<std::uint8_t> mask_bits(
                        mask_stride * static_cast<std::size_t>(size), 0u);
                    HBITMAP mask =
                        ::CreateBitmap(size, size, 1, 1, mask_bits.data());
                    ICONINFO info{};
                    info.fIcon = TRUE;
                    info.hbmColor = color;
                    info.hbmMask = mask;
                    HICON icon = ::CreateIconIndirect(&info);
                    ::DeleteObject(color);
                    if (mask) ::DeleteObject(mask);
                    ::DeleteDC(dc);
                    return icon;
                }

                void ShowMenu(HWND hwnd) {
                    HMENU menu = ::CreatePopupMenu();
                    if (nullptr == menu) {
                        return;
                    }
                    // S5 GUI fix (G6): tray labels now go through the i18n
                    // tables (keys TrayShow/TrayHide/TrayAutostart/TrayExit),
                    // so a Chinese UI no longer shows hardcoded English.
                    I18n& i18n = I18n::Instance();
                    ::AppendMenuW(menu, MF_STRING, kMenuShow,
                                  i18n.T(Str::TrayShow));
                    // batch29: show the window AND land on the dashboard,
                    // directly under "Show window".
                    ::AppendMenuW(menu, MF_STRING, kMenuDashboard,
                                  i18n.T(Str::TrayOpenDashboard));
                    ::AppendMenuW(menu, MF_STRING, kMenuHide,
                                  i18n.T(Str::TrayHide));
                    // batch28: service toggle, right under the window items and
                    // above the first separator. The label follows the live
                    // service state so it always reads as the NEXT action.
                    ::AppendMenuW(menu, MF_STRING, kMenuService,
                                  i18n.T(g_service_running.load()
                                             ? Str::DashStop
                                             : Str::DashStart));
                    ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
                    ::AppendMenuW(menu, MF_STRING |
                                            (g_autostart_checked.load() ? MF_CHECKED
                                                                        : MF_UNCHECKED),
                                  kMenuAutostart, i18n.T(Str::TrayAutostart));
                    ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
                    ::AppendMenuW(menu, MF_STRING, kMenuExit,
                                  i18n.T(Str::TrayExit));

                    POINT cursor{};
                    ::GetCursorPos(&cursor);
                    ::SetForegroundWindow(hwnd);
                    const UINT command = ::TrackPopupMenu(
                        menu, TPM_RETURNCMD | TPM_NONOTIFY | TPM_RIGHTBUTTON,
                        cursor.x, cursor.y, 0, hwnd, nullptr);
                    ::PostMessageW(hwnd, WM_NULL, 0, 0);  // classic dismiss fix
                    ::DestroyMenu(menu);
                    DispatchMenuCommand(command);
                }

            }  // namespace

            std::vector<MenuItemView> MenuItems() {
                I18n& i18n = I18n::Instance();
                std::vector<MenuItemView> out;
                out.push_back(MenuItemView{kMenuShow, i18n.T(Str::TrayShow),
                                           false});
                out.push_back(MenuItemView{kMenuDashboard,
                                           i18n.T(Str::TrayOpenDashboard),
                                           false});
                out.push_back(MenuItemView{kMenuHide, i18n.T(Str::TrayHide),
                                           false});
                out.push_back(MenuItemView{
                    kMenuService,
                    i18n.T(g_service_running.load() ? Str::DashStop
                                                    : Str::DashStart),
                    false});
                out.push_back(MenuItemView{kMenuAutostart,
                                           i18n.T(Str::TrayAutostart),
                                           g_autostart_checked.load()});
                out.push_back(MenuItemView{kMenuExit, i18n.T(Str::TrayExit),
                                           false});
                return out;
            }

            std::uint32_t PackIconPixel(Color color) noexcept {
                const auto channel = [](float value) noexcept {
                    return static_cast<std::uint32_t>(
                        std::min(std::max(value, 0.0f), 1.0f) * 255.0f + 0.5f);
                };
                return (0xFFu << 24) | (channel(color.r) << 16) |
                       (channel(color.g) << 8) | channel(color.b);
            }

            void FillAppIconPixels(std::uint32_t* pixels, int size,
                                   bool bottom_up) noexcept {
                if (pixels == nullptr || size <= 0) {
                    return;
                }
                const Color panel = ColorFor(ColorToken::Panel);
                const Color border = ColorFor(ColorToken::Border);
                const Color accent = ColorFor(ColorToken::Accent);
                const float extent = static_cast<float>(size);
                const float radius = extent * 0.22f;
                const float thickness = extent * 0.11f;
                const float ax = extent * 0.28f;
                const float ay = extent * 0.30f;
                const float bx = extent * 0.50f;
                const float by = extent * 0.72f;
                const float cx = extent * 0.72f;
                const float cy = extent * 0.30f;
                for (int row = 0; row < size; ++row) {
                    // A bottom-up DIB (positive biHeight) stores its first row
                    // at the bottom, so the icon's top row lands in the last
                    // buffer row; without this the V appeared mirrored as a
                    // lambda (inverted V)
                    // (T6 review M1).
                    const int y = bottom_up ? (size - 1 - row) : row;
                    for (int x = 0; x < size; ++x) {
                        const float fx = static_cast<float>(x) + 0.5f;
                        const float fy = static_cast<float>(y) + 0.5f;
                        std::uint32_t pixel = 0;
                        if (RoundedRectContains(fx, fy, extent, radius)) {
                            const bool on_v =
                                SegmentDistance(fx, fy, ax, ay, bx, by) <=
                                    thickness * 0.5f ||
                                SegmentDistance(fx, fy, bx, by, cx, cy) <=
                                    thickness * 0.5f;
                            // The inner rounded rect is the outer one shrunk
                            // by 1px on EVERY side, so its ORIGIN must move
                            // inward too. Testing the same origin against a
                            // 2px-smaller extent made the left/top rim fall
                            // INSIDE the shrunken shape (painted as panel)
                            // while the right/bottom rim correctly became
                            // border: a 1px border on two sides only.
                            const bool on_border = !RoundedRectContains(
                                fx - 1.0f, fy - 1.0f, extent - 2.0f,
                                std::max(radius - 1.0f, 0.5f));
                            pixel = PackIconPixel(
                                on_v ? accent : (on_border ? border : panel));
                        }
                        pixels[row * size + x] = pixel;
                    }
                }
            }

            void SetCallbacks(Callbacks callbacks) {
                g_callbacks = std::move(callbacks);
            }

            void SetServiceRunning(bool running) noexcept {
                g_service_running.store(running);
            }

            int ServiceMenuCommand() noexcept {
                return static_cast<int>(kMenuService);
            }

            int OpenDashboardMenuCommand() noexcept {
                return static_cast<int>(kMenuDashboard);
            }

            void DispatchMenuCommand(UINT command) noexcept {
                switch (command) {
                    case kMenuShow:
                        if (g_callbacks.on_show) {
                            g_callbacks.on_show();
                        }
                        break;
                    case kMenuHide:
                        if (g_callbacks.on_hide) {
                            g_callbacks.on_hide();
                        }
                        break;
                    case kMenuDashboard:
                        // batch29: show the window and land on the dashboard in
                        // ONE activation (the app owns both steps).
                        if (g_callbacks.on_open_dashboard) {
                            g_callbacks.on_open_dashboard();
                        } else if (g_callbacks.on_show) {
                            g_callbacks.on_show();
                        }
                        break;
                    case kMenuService:
                        // batch28: exactly ONE command per activation - the
                        // app maps it onto Command{StartServiceCmd} or
                        // Command{StopServiceCmd} and posts it through the
                        // normal queue.
                        if (g_callbacks.on_toggle_service) {
                            g_callbacks.on_toggle_service(
                                !g_service_running.load());
                        }
                        break;
                    case kMenuAutostart: {
                        std::string error;
                        const bool enabled = !IsAutostartEnabled();
                        if (SetAutostart(enabled, error)) {
                            UpdateMenu(enabled);
                        } else {
                            std::fprintf(stderr,
                                         "[tray] SetAutostart failed: %s\n",
                                         error.c_str());
                        }
                        break;
                    }
                    case kMenuExit:
                        if (g_callbacks.on_exit) {
                            g_callbacks.on_exit();
                        } else if (g_hwnd != nullptr) {
                            ::PostMessageW(g_hwnd, WM_CLOSE, 0, 0);
                        }
                        break;
                    default:
                        break;
                }
            }

            namespace {

                /// batch318: performs the NIM_ADD for the stored request.
                /// Called by Add() and by the TaskbarCreated re-add path.
                bool RegisterIcon() noexcept {
                    if (nullptr == g_hwnd) {
                        return false;
                    }
                    NOTIFYICONDATAW data{};
                    data.cbSize = sizeof(NOTIFYICONDATAW);
                    data.hWnd = g_hwnd;
                    data.uID = kIconId;
                    data.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
                    data.uCallbackMessage = kTrayCallbackMessage;
                    data.hIcon = g_icon;
                    wcsncpy_s(data.szTip, g_tip.c_str(), _TRUNCATE);
                    g_added = FALSE != g_shell_notify(NIM_ADD, &data);
                    return g_added;
                }

            }  // namespace

            bool Add(HWND hwnd, HICON icon, std::wstring tip) {
                if (nullptr == hwnd) {
                    return false;
                }
                // batch318: remember the REQUEST even when the shell is not
                // ready yet (autostart can run before the taskbar exists).
                // The TaskbarCreated broadcast then retries this exact
                // registration instead of leaving a --minimized window with
                // no tray icon and no way back.
                g_hwnd = hwnd;
                g_icon = icon;
                g_tip = std::move(tip);
                return RegisterIcon();
            }

            void Remove() noexcept {
                if (g_added && g_hwnd) {
                    NOTIFYICONDATAW data{};
                    data.cbSize = sizeof(NOTIFYICONDATAW);
                    data.hWnd = g_hwnd;
                    data.uID = kIconId;
                    (void)g_shell_notify(NIM_DELETE, &data);
                }
                g_added = false;
                g_hwnd = nullptr;
                g_icon = nullptr;
                g_tip.clear();
            }

            UINT RegisterTaskbarMessage() noexcept {
                // The same string yields the same id for the whole session;
                // 0 means RegisterWindowMessageW failed.
                static const UINT id =
                    ::RegisterWindowMessageW(L"TaskbarCreated");
                return id;
            }

            bool IsTaskbarCreatedMessage(UINT message) noexcept {
                const UINT id = RegisterTaskbarMessage();
                return id != 0 && message == id;
            }

            bool ReAddAfterTaskbarCreated() noexcept {
                return RegisterIcon();
            }

            bool IsAdded() noexcept {
                return g_added;
            }

            void SetShellNotifyForTest(ShellNotifyFn fn) noexcept {
                g_shell_notify = fn != nullptr ? fn : &::Shell_NotifyIconW;
            }

            void SetAutostartHookForTest(
                std::function<bool(bool, std::string&)> hook) noexcept {
                g_autostart_hook = std::move(hook);
            }

            void UpdateMenu(bool autostart) {
                g_autostart_checked.store(autostart);
            }

            bool SetAutostart(bool enabled, std::string& error) {
                if (g_autostart_hook) {
                    return g_autostart_hook(enabled, error);
                }
                error.clear();
                HKEY key = nullptr;
                const LSTATUS opened = ::RegCreateKeyExW(
                    HKEY_CURRENT_USER, kRunKey, 0, nullptr, 0, KEY_SET_VALUE,
                    nullptr, &key, nullptr);
                if (ERROR_SUCCESS != opened) {
                    error = "cannot open HKCU Run key (code " +
                            std::to_string(opened) + ")";
                    return false;
                }
                LSTATUS status = ERROR_SUCCESS;
                if (enabled) {
                    const std::wstring command = AutostartCommand();
                    status = ::RegSetValueExW(
                        key, kRunValue, 0, REG_SZ,
                        reinterpret_cast<const BYTE*>(command.c_str()),
                        static_cast<DWORD>((command.size() + 1) *
                                           sizeof(wchar_t)));
                } else {
                    status = ::RegDeleteValueW(key, kRunValue);
                    if (ERROR_FILE_NOT_FOUND == status) {
                        status = ERROR_SUCCESS;  // already absent
                    }
                }
                ::RegCloseKey(key);
                if (ERROR_SUCCESS != status) {
                    error = "cannot update HKCU Run value (code " +
                            std::to_string(status) + ")";
                    return false;
                }
                g_autostart_checked.store(enabled);
                return true;
            }

            bool IsAutostartEnabled() {
                const LSTATUS status = ::RegGetValueW(
                    HKEY_CURRENT_USER, kRunKey, kRunValue, RRF_RT_REG_SZ,
                    nullptr, nullptr, nullptr);
                return ERROR_SUCCESS == status;
            }

            void MakeAppIcon(HICON* small_icon, HICON* big_icon) {
                if (small_icon) {
                    *small_icon = CreateAppIcon(16);
                    if (nullptr == *small_icon) {
                        // IDI_APPLICATION == 32512 (W-macro: the project does
                        // not define UNICODE, so the A-macro would not fit).
                        *small_icon =
                            ::LoadIconW(nullptr, MAKEINTRESOURCEW(32512));
                    }
                }
                if (big_icon) {
                    *big_icon = CreateAppIcon(32);
                    if (nullptr == *big_icon) {
                        *big_icon =
                            ::LoadIconW(nullptr, MAKEINTRESOURCEW(32512));
                    }
                }
            }

            void ShowBalloon(const std::wstring& title,
                             const std::wstring& text) {
                if (!g_added || !g_hwnd) {
                    return;
                }
                NOTIFYICONDATAW data{};
                data.cbSize = sizeof(NOTIFYICONDATAW);
                data.hWnd = g_hwnd;
                data.uID = kIconId;
                data.uFlags = NIF_INFO;
                data.dwInfoFlags = NIIF_INFO;
                wcsncpy_s(data.szInfoTitle, title.c_str(), _TRUNCATE);
                wcsncpy_s(data.szInfo, text.c_str(), _TRUNCATE);
                (void)g_shell_notify(NIM_MODIFY, &data);
            }

            bool HandleWindowMessage(HWND hwnd, UINT message, WPARAM wparam,
                                     LPARAM lparam) {
                if (nullptr == hwnd) {
                    return false;
                }
                // batch318: Explorer restarted (every Shell_NotifyIcon icon is
                // gone) or the shell came up after a startup registration
                // failed. Re-register ours; without this a hidden window has
                // no tray icon and no way back.
                if (IsTaskbarCreatedMessage(message)) {
                    (void)ReAddAfterTaskbarCreated();
                    return true;
                }
                if (kTrayCallbackMessage != message) {
                    return false;
                }
                (void)wparam;
                switch (static_cast<UINT>(lparam)) {
                    case WM_LBUTTONDBLCLK:
                        if (g_callbacks.on_show) {
                            g_callbacks.on_show();
                        }
                        break;
                    case WM_RBUTTONUP:
                    case WM_CONTEXTMENU:
                        ShowMenu(hwnd);
                        break;
                    default:
                        break;
                }
                return true;
            }

        }  // namespace tray
    }  // namespace ui
}  // namespace vgww
