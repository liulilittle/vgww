// ============================================================================
// ui_state.h - window position/size memory (batch28).
//
// The window used to open at a fixed design size on every launch. This module
// persists the last NORMAL window rect (position in physical pixels, size in
// logical/DIP units so a DPI change re-scales it) in
// %LOCALAPPDATA%\VGWW\ui_state.json.
//
// Deliberately NOT part of the config schema: ui_state.json is disposable UI
// state, so a corrupt/missing file must never affect the service or the
// config contract (it silently falls back to the defaults).
//
// Every rule that decides "is this rect usable?" lives in the pure
// RestoreWindowState() function so it is testable headless:
//   * size below the minimum design size  -> invalid (caller uses defaults);
//   * position not on any current work area (monitor unplugged) -> centred on
//     the primary work area;
//   * size larger than the work area -> clamped to it;
//   * DPI change -> the stored logical size is re-scaled before the checks.
// ============================================================================
#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#include <windows.h>

#include <string>
#include <vector>

namespace vgww {
    namespace ui {
        namespace ui_state {

            /// Integer screen rectangle (physical pixels).
            struct RectI {
                int x = 0;
                int y = 0;
                int w = 0;
                int h = 0;
            };

            /// Current ui_state.json schema version (batch30). A file that
            /// declares a DIFFERENT version is ignored entirely (defaults).
            /// A file without a version is a batch28/29 one and still loads.
            constexpr int kStateVersion = 1;

            /// Persisted window state. `w`/`h` are LOGICAL units (DIPs at 96
            /// dpi), `x`/`y` are physical screen pixels. `valid == false` means
            /// "nothing usable was stored" (missing/corrupt file).
            /// `maximized` (batch30) remembers that the window closed zoomed;
            /// x/y/w/h still hold the last NORMAL rect so un-maximizing and
            /// future restores land where the user left them.
            struct WindowState {
                int x = 0;
                int y = 0;
                float w = 0.0f;
                float h = 0.0f;
                bool valid = false;
                bool maximized = false;
            };

            /// %LOCALAPPDATA%\VGWW\ui_state.json (falls back to the exe
            /// directory when LOCALAPPDATA is unavailable).
            std::wstring StateFilePath();

            /// Test seam: overrides the file path (empty restores the default).
            void SetStatePathForTest(const std::wstring& path);

            /// Reads the persisted state. Returns false (and leaves `out`
            /// invalid) when the file is missing, unreadable or corrupt - the
            /// caller then simply keeps the defaults.
            bool Load(WindowState& out);

            /// Writes `state` (best effort; a failure never affects the app).
            bool Save(const WindowState& state);

            /// Pure restore decision (headless-testable):
            ///   * !saved.valid                 -> invalid
            ///   * scaled size below the design minimum -> invalid
            ///   * size clamped to the best-matching work area
            ///   * position outside every work area -> centred on `primary`
            /// `min_logical_w/h` are the design minimum in DIPs; `scale` is
            /// dpi/96 (<= 0 is treated as 1).
            WindowState RestoreWindowState(const WindowState& saved, float scale,
                                           float min_logical_w,
                                           float min_logical_h,
                                           const std::vector<RectI>& work_areas,
                                           const RectI& primary_work);

        }  // namespace ui_state
    }  // namespace ui
}  // namespace vgww
