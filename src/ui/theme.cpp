// ============================================================================
// theme.cpp - dark theme token values (frozen by the S4 plan).
// ============================================================================
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "ui/theme.h"

#include <algorithm>
#include <cstddef>
#include <utility>

namespace vgww {
    namespace ui {

        namespace {

            int HexValue(char c) noexcept {
                if (c >= '0' && c <= '9') return c - '0';
                if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                return -1;
            }

            float Channel(int value) noexcept {
                return static_cast<float>(value) / 255.0f;
            }

        }  // namespace

        Color ParseHexColor(std::string_view text) noexcept {
            Color out;  // opaque black until proven otherwise
            if (text.empty() || text.front() != '#') {
                out.valid = false;
                return out;
            }
            const std::string_view digits = text.substr(1);
            const std::size_t n = digits.size();
            if (n != 3 && n != 6 && n != 8) {
                out.valid = false;
                return out;
            }
            int values[8] = {0};
            for (std::size_t i = 0; i < n; ++i) {
                const int v = HexValue(digits[i]);
                if (v < 0) {
                    out.valid = false;
                    return out;
                }
                values[i] = v;
            }
            if (n == 3) {
                // #RGB: each nibble is doubled (0xF -> 0xFF).
                out.r = Channel(values[0] * 17);
                out.g = Channel(values[1] * 17);
                out.b = Channel(values[2] * 17);
                out.a = 1.0f;
            } else {
                out.r = Channel(values[0] * 16 + values[1]);
                out.g = Channel(values[2] * 16 + values[3]);
                out.b = Channel(values[4] * 16 + values[5]);
                out.a = (n == 8) ? Channel(values[6] * 16 + values[7]) : 1.0f;
            }
            out.valid = true;
            return out;
        }

        const Theme& DarkTheme() noexcept {
            static const Theme theme = [] {
                // Vercel/Linear-inspired neutral scale: pure neutral greys
                // (no blue cast) with an electric-blue accent, amber warning.
                Theme t;
                t.bg = ParseHexColor("#121212");
                t.panel = ParseHexColor("#1E1E1E");
                t.panel_alt = ParseHexColor("#252525");
                t.border = ParseHexColor("#2E2E2E");
                t.text = ParseHexColor("#FFFFFF");
                t.text_dim = ParseHexColor("#A0A0A0");
                // batch17 P1-c (B-2/D1): white on #007AFF was 4.02 and
                // white on hover #3D9BFF only 2.86 - both failed WCAG AA.
                // The rest/hover pair now darkens on hover (#0066CC 5.57 /
                // #0055AA 7.29 with white text; an intentional "hover =
                // darker" semantics flip).
                t.accent = ParseHexColor("#0066CC");
                t.accent_hover = ParseHexColor("#0055AA");
                t.accent_text = ParseHexColor("#66B2FF");
                // WCAG 1.4.11 (non-text 3:1) on EVERY surface a control can
                // sit on: #6E6E6E was 3.27 on Panel but only 3.01 on
                // PanelAlt - a rounding margin. #757575 is 3.62 / 3.33 /
                // 4.07 (Panel / PanelAlt / Bg), clear of the threshold.
                t.input_border = ParseHexColor("#757575");
                // batch33t: #E5484D was 4.26:1 as TEXT on Panel (#1E1E1E),
                // under WCAG AA 1.4.3's 4.5:1 - the outlined "repair as
                // administrator" banner button paints Danger as body text.
                // #F06166 is 5.24:1 on Panel and 5.89:1 on Bg, and dark
                // text on it is 5.80:1, so the same token still works as a
                // filled badge/toast background.
                t.danger = ParseHexColor("#F06166");
                t.success = ParseHexColor("#2FA84F");
                t.warning = ParseHexColor("#FFC107");
                // batch28: instrument grid - #333333 is one step BRIGHTER than
                // Border (#2E2E2E) because #2A2A2A was invisible on #121212.
                t.grid_line = ParseHexColor("#333333");
                t.range_text = ParseHexColor("#B8B8B8");
                return t;
            }();
            return theme;
        }

        // batch22 A1: light theme. Same token slots/geometry as the dark
        // palette (only colors differ) so every layout/anchor stays valid; the
        // accent pair keeps the "hover = darker" semantic of the dark theme.
        const Theme& LightTheme() noexcept {
            static const Theme theme = [] {
                Theme t;
                t.bg = ParseHexColor("#F5F5F7");
                t.panel = ParseHexColor("#FFFFFF");
                t.panel_alt = ParseHexColor("#EFEFF2");
                t.border = ParseHexColor("#D9D9DE");
                t.text = ParseHexColor("#111114");
                t.text_dim = ParseHexColor("#5A5A62");
                t.accent = ParseHexColor("#0066CC");
                t.accent_hover = ParseHexColor("#0055AA");
                // Accent-toned text must stay >=4.5:1 on panel_alt; the dark
                // theme's light blue would fail on white, so it deepens.
                t.accent_text = ParseHexColor("#0B57B8");
                // WCAG 1.4.11 on every light surface: #8A8A94 was 2.98:1 on
                // PanelAlt (#EFEFF2) - just under. #7E7E88 is 4.02 / 3.50 /
                // 3.69 (Panel / PanelAlt / Bg).
                t.input_border = ParseHexColor("#7E7E88");
                t.danger = ParseHexColor("#C42B30");
                t.success = ParseHexColor("#1E7A38");
                t.warning = ParseHexColor("#8A6100");
                t.grid_line = ParseHexColor("#D0D0D6");
                t.range_text = ParseHexColor("#4A4A52");
                return t;
            }();
            return theme;
        }

        namespace {
            /// The active theme is a stable object so the public
            /// `const Theme& g_theme` reference stays valid across switches:
            /// SetActiveTheme() assigns new values INTO it.
            Theme& ActiveThemeStorage() noexcept {
                static Theme storage = DarkTheme();
                return storage;
            }
        }  // namespace

        const Theme& g_theme = ActiveThemeStorage();

        bool SystemPrefersLightTheme() noexcept {
            // HKCU\...\Themes\Personalize\AppsUseLightTheme: 0 = dark (the
            // Windows default when the value is absent), 1 = light.
            HKEY key = nullptr;
            if (::RegOpenKeyExW(HKEY_CURRENT_USER,
                                L"Software\\Microsoft\\Windows\\CurrentVersion"
                                L"\\Themes\\Personalize",
                                0, KEY_QUERY_VALUE, &key) != ERROR_SUCCESS) {
                return false;
            }
            DWORD value = 0;
            DWORD size = sizeof(value);
            DWORD type = 0;
            const LSTATUS status =
                ::RegQueryValueExW(key, L"AppsUseLightTheme", nullptr, &type,
                                   reinterpret_cast<LPBYTE>(&value), &size);
            ::RegCloseKey(key);
            if (status != ERROR_SUCCESS || type != REG_DWORD) {
                return false;
            }
            return value != 0;
        }

        void SetActiveTheme(bool light) noexcept {
            ActiveThemeStorage() = light ? LightTheme() : DarkTheme();
        }

        bool ActiveThemeIsLight() noexcept {
            return g_theme.bg.r > 0.5f;
        }

        // --- Task 2 additions -------------------------------------------------

        namespace {

            TextMeasureFn g_text_measure;
            /// M7 (batch3): bumped on every measure-hook install/reset; see
            /// TextMeasureGeneration(). Starts at 0 (a fresh cache field's
            /// zero default never matches a bump after any install).
            uint64_t g_text_measure_gen = 0;

        }  // namespace

        Color ColorFor(ColorToken token) noexcept {
            const Theme& t = g_theme;
            switch (token) {
                case ColorToken::Bg: return t.bg;
                case ColorToken::Panel: return t.panel;
                case ColorToken::PanelAlt: return t.panel_alt;
                case ColorToken::Border: return t.border;
                case ColorToken::Text: return t.text;
                case ColorToken::TextDim: return t.text_dim;
                case ColorToken::Accent: return t.accent;
                case ColorToken::AccentHover: return t.accent_hover;
                case ColorToken::AccentText: return t.accent_text;
                case ColorToken::InputBorder: return t.input_border;
                case ColorToken::Danger: return t.danger;
                case ColorToken::Success: return t.success;
                case ColorToken::Warning: return t.warning;
                case ColorToken::GridLine: return t.grid_line;
                case ColorToken::RangeText: return t.range_text;
                case ColorToken::_Count: break;
            }
            return t.text;  // unknown token: readable default
        }

        FontSpec FontFor(FontToken token) noexcept {
            switch (token) {
                case FontToken::Small: return FontSpec{11.0f, 400};
                case FontToken::Body: return FontSpec{13.0f, 400};
                case FontToken::BodyStrong: return FontSpec{13.0f, 600};
                case FontToken::Section: return FontSpec{16.0f, 600};
                case FontToken::Title: return FontSpec{20.0f, 600};
                case FontToken::Number: return FontSpec{14.0f, 400};
                case FontToken::Stat: return FontSpec{24.0f, 600};
                case FontToken::Micro: return FontSpec{10.0f, 400};
            }
            return FontSpec{13.0f, 400};
        }

        void SetTextMeasure(TextMeasureFn fn) {
            ++g_text_measure_gen;  // M7: invalidate width caches keyed on it
            g_text_measure = std::move(fn);
        }

        uint64_t TextMeasureGeneration() noexcept {
            return g_text_measure_gen;
        }

        Size MeasureText(const std::wstring& text, FontToken font,
                         float max_width) {
            if (g_text_measure != nullptr) {
                return g_text_measure(text, font, max_width);
            }
            const FontSpec spec = FontFor(font);
            float width = 0.0f;
            for (const wchar_t ch : text) {
                width += (ch < 128 ? 0.55f : 1.0f) * spec.size;
            }
            return Size{std::min(width, max_width), spec.size * 1.35f};
        }

    }  // namespace ui
}  // namespace vgww
