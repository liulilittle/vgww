// ============================================================================
// ui_state.cpp - window position/size memory (batch28). See ui_state.h.
// ============================================================================
#include "ui/ui_state.h"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <string>

namespace vgww {
    namespace ui {
        namespace ui_state {

            namespace {

                std::wstring g_path_override;

                /// Directories are created on demand (a missing folder must not
                /// fail the save).
                void EnsureParentDirectory(const std::wstring& path) {
                    const std::size_t cut = path.find_last_of(L"\\/");
                    if (cut == std::wstring::npos || cut == 0) {
                        return;
                    }
                    const std::wstring dir = path.substr(0, cut);
                    ::CreateDirectoryW(dir.c_str(), nullptr);
                }

                bool WorkAreaContains(const RectI& area, int x, int y) noexcept {
                    return x >= area.x && x < area.x + area.w && y >= area.y &&
                           y < area.y + area.h;
                }

                /// True when at least a usable strip of `rect` overlaps an area.
                bool WorkAreaOverlaps(const RectI& area, const RectI& rect) noexcept {
                    const int left = (std::max)(area.x, rect.x);
                    const int top = (std::max)(area.y, rect.y);
                    const int right = (std::min)(area.x + area.w, rect.x + rect.w);
                    const int bottom = (std::min)(area.y + area.h, rect.y + rect.h);
                    // A visible title-bar strip (>= 64 x 24 px) counts as
                    // reachable; anything less is treated as off-screen.
                    return right - left >= 64 && bottom - top >= 24;
                }

            }  // namespace

            std::wstring StateFilePath() {
                if (!g_path_override.empty()) {
                    return g_path_override;
                }
                wchar_t buffer[MAX_PATH * 2] = L"";
                const DWORD n = ::GetEnvironmentVariableW(
                    L"LOCALAPPDATA", buffer,
                    static_cast<DWORD>(std::size(buffer)));
                if (n > 0 && n < std::size(buffer)) {
                    return std::wstring(buffer) + L"\\VGWW\\ui_state.json";
                }
                wchar_t exe[MAX_PATH * 2] = L"";
                const DWORD m = ::GetModuleFileNameW(
                    nullptr, exe, static_cast<DWORD>(std::size(exe)));
                if (m > 0) {
                    std::wstring path(exe);
                    const std::size_t cut = path.find_last_of(L"\\/");
                    if (cut != std::wstring::npos) {
                        path.resize(cut);
                    }
                    return path + L"\\ui_state.json";
                }
                return L"";
            }

            void SetStatePathForTest(const std::wstring& path) {
                g_path_override = path;
            }

            bool Load(WindowState& out) {
                out = WindowState{};
                const std::wstring path = StateFilePath();
                if (path.empty()) {
                    return false;
                }
                std::ifstream in(path.c_str(), std::ios::binary);
                if (!in.good()) {
                    return false;
                }
                std::stringstream buffer;
                buffer << in.rdbuf();
                const std::string text = buffer.str();
                if (text.empty()) {
                    return false;
                }
                // Corrupt JSON (or wrong types) must fall back silently.
                const nlohmann::json doc =
                    nlohmann::json::parse(text, nullptr, false);
                if (doc.is_discarded() || !doc.is_object()) {
                    return false;
                }
                // batch30: a file from a FUTURE schema is not guessed at -
                // the app starts with its defaults. A missing version means a
                // batch28/29 file and keeps loading (in-place upgrade).
                const auto version = doc.find("version");
                if (version != doc.end() &&
                    (!version->is_number_integer() ||
                     version->get<int>() != kStateVersion)) {
                    return false;
                }
                const auto get_int = [&doc](const char* key, int& value) {
                    const auto it = doc.find(key);
                    if (it == doc.end() || !it->is_number_integer()) {
                        return false;
                    }
                    value = it->get<int>();
                    return true;
                };
                const auto get_float = [&doc](const char* key, float& value) {
                    const auto it = doc.find(key);
                    if (it == doc.end() || !it->is_number()) {
                        return false;
                    }
                    value = it->get<float>();
                    return true;
                };
                WindowState state;
                if (!get_int("x", state.x) || !get_int("y", state.y) ||
                    !get_float("width", state.w) ||
                    !get_float("height", state.h)) {
                    return false;
                }
                if (!(state.w > 0.0f) || !(state.h > 0.0f) ||
                    !std::isfinite(state.w) || !std::isfinite(state.h)) {
                    return false;
                }
                const auto maximized = doc.find("maximized");
                state.maximized =
                    maximized != doc.end() && maximized->is_boolean() &&
                    maximized->get<bool>();
                state.valid = true;
                out = state;
                return true;
            }

            bool Save(const WindowState& state) {
                if (!state.valid) {
                    return false;
                }
                const std::wstring path = StateFilePath();
                if (path.empty()) {
                    return false;
                }
                EnsureParentDirectory(path);
                nlohmann::json doc;
                doc["version"] = kStateVersion;
                doc["x"] = state.x;
                doc["y"] = state.y;
                doc["width"] = state.w;
                doc["height"] = state.h;
                doc["maximized"] = state.maximized;
                const std::string text = doc.dump(2);
                std::ofstream out(path.c_str(),
                                  std::ios::binary | std::ios::trunc);
                if (!out.good()) {
                    return false;
                }
                out.write(text.data(),
                          static_cast<std::streamsize>(text.size()));
                out.put('\n');
                return out.good();
            }

            WindowState RestoreWindowState(const WindowState& saved, float scale,
                                           float min_logical_w,
                                           float min_logical_h,
                                           const std::vector<RectI>& work_areas,
                                           const RectI& primary_work) {
                WindowState out;
                if (!saved.valid) {
                    return out;  // caller keeps the defaults
                }
                const float s = (scale > 0.0f) ? scale : 1.0f;
                // A stored LOGICAL size is re-scaled for the CURRENT dpi, so a
                // desktop that moved from 100% to 150% gets a proportionate
                // window instead of a tiny one.
                float w = saved.w * s;
                float h = saved.h * s;
                if (!(w >= min_logical_w * s) || !(h >= min_logical_h * s)) {
                    return out;  // too small (or garbage): defaults
                }
                // Clamp to the work area the window would land on (the one
                // containing its top-left corner, else the primary).
                RectI target = primary_work;
                for (const RectI& area : work_areas) {
                    if (WorkAreaContains(area, saved.x, saved.y)) {
                        target = area;
                        break;
                    }
                }
                w = (std::min)(w, static_cast<float>(target.w));
                h = (std::min)(h, static_cast<float>(target.h));
                if (!(w >= min_logical_w * s) || !(h >= min_logical_h * s)) {
                    return out;  // the work area itself cannot hold the minimum
                }
                out.w = w / s;  // logical, re-derived from the clamped pixels
                out.h = h / s;
                const RectI rect{saved.x, saved.y, static_cast<int>(w),
                                 static_cast<int>(h)};
                bool visible = false;
                for (const RectI& area : work_areas) {
                    if (WorkAreaOverlaps(area, rect)) {
                        visible = true;
                        break;
                    }
                }
                if (visible) {
                    out.x = saved.x;
                    out.y = saved.y;
                } else {
                    // The monitor it was on is gone: centre on the primary.
                    out.x = primary_work.x +
                            static_cast<int>((primary_work.w - w) / 2.0f);
                    out.y = primary_work.y +
                            static_cast<int>((primary_work.h - h) / 2.0f);
                }
                out.maximized = saved.maximized;
                out.valid = true;
                return out;
            }

        }  // namespace ui_state
    }  // namespace ui
}  // namespace vgww
