// ============================================================================
// theme.h - dark theme design tokens for the native UI (S4.2 Task 1).
//
// The token values are frozen by the S4 plan (Global Constraints): dark
// high-end look, 8pt grid, 8/6 px radii, 40 px title bar, 220 px sidebar and
// a 980x640 minimum logical window. Everything here is pure data plus a hex
// color parser, so it is unit-testable headless.
// ============================================================================
#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <string_view>

namespace vgww {
    namespace ui {

        /// sRGB component triplet in 0..1 plus an alpha channel.
        struct Color {
            float r = 0.0f;
            float g = 0.0f;
            float b = 0.0f;
            float a = 1.0f;
            /// False when this value came from a malformed hex string; the
            /// components then hold opaque black so callers still get a color.
            bool valid = true;
        };

        /// Parses "#RGB", "#RRGGBB" or "#RRGGBBAA" (case-insensitive).
        /// Malformed input returns opaque black with `valid = false`.
        Color ParseHexColor(std::string_view text) noexcept;

        /// Design tokens consumed by the element tree and the renderer.
        struct Theme {
            /// Minimum logical window size (frozen: 980x640).
            struct WindowSize {
                float w = 980.0f;
                float h = 640.0f;
            };

            Color bg;
            Color panel;
            Color panel_alt;
            Color border;
            Color text;
            Color text_dim;
            Color accent;
            Color accent_hover;
            /// batch17 P1-c (B-2): accent-tinted TEXT on dark surfaces (Select
            /// popup selected item): #007AFF failed WCAG AA there (3.82);
            /// a lighter blue passes (6.84 on panel_alt).
            Color accent_text;
            /// batch17 P1-c (B-2, WCAG 1.4.11): component boundary for input
            /// controls. The decorative `border` (#2E2E2E) stays for cards /
            /// separators; input boxes need >= 3:1 against the panel.
            Color input_border;
            Color danger;
            Color success;
            Color warning;
            /// batch28: the instrument grid line (a structural line one step
            /// darker than `border`), used by the sparkline's 25/50/75 % lines.
            Color grid_line;
            /// batch28: the sparkline range label (one step brighter than
            /// `text_dim` so it reads on the curve frame).
            Color range_text;
            float radius = 8.0f;      ///< cards, dialogs, window corners
            float radius_sm = 6.0f;   ///< buttons, inputs, badges
            float titlebar_h = 40.0f;
            float sidebar_w = 220.0f;
            WindowSize min_window;
            float grid = 8.0f;        ///< layout grid step
        };

        /// The frozen dark theme (immutable singleton).
        const Theme& DarkTheme() noexcept;

        /// batch22 A1: frozen light theme (same slots/geometry, light colors).
        const Theme& LightTheme() noexcept;

        /// Convenience alias for the ACTIVE theme. The referenced object is
        /// stable, so this reference never dangles when the theme switches.
        extern const Theme& g_theme;

        /// batch22 A1: selects the active theme at runtime. Passing true/false
        /// copies the light/dark palette into the active theme storage; all
        /// subsequent ColorFor()/renderer reads observe it.
        void SetActiveTheme(bool light) noexcept;

        /// batch22 A1: true when the active theme is the light palette.
        bool ActiveThemeIsLight() noexcept;

        /// batch22 A1: reads HKCU\...\Themes\Personalize\AppsUseLightTheme
        /// (0/absent = the OS prefers dark, 1 = it prefers light).
        bool SystemPrefersLightTheme() noexcept;

        // --------------------------------------------------------------------
        // Task 2 additions: semantic tokens and the text-measure seam.
        // --------------------------------------------------------------------

        /// Semantic color slots resolved against the active theme.
        enum class ColorToken {
            Bg,
            Panel,
            PanelAlt,
            Border,
            Text,
            TextDim,
            Accent,
            AccentHover,
            /// batch17 P1-c: accent-toned text that stays readable on dark
            /// panels (Select popup selected item).
            AccentText,
            /// batch17 P1-c: input-control boundary colour (WCAG 1.4.11).
            InputBorder,
            Danger,
            Success,
            Warning,
            /// batch28: the instrument grid line (one step darker than Border)
            /// - a structural line, never decorative.
            GridLine,
            /// batch28: the instrument range label (one step brighter than
            /// TextDim so it stays legible on the curve frame).
            RangeText,
            _Count
        };

        /// Typography roles (sizes/weights frozen by the S4 plan).
        enum class FontToken {
            Small,
            Body,
            BodyStrong,
            Section,
            Title,
            Number,
            Stat,
            /// batch28: the instrument annotations (sparkline range label).
            Micro,
            _Count
        };

        struct FontSpec {
            float size = 13.0f;
            int weight = 400;
        };

        /// Resolves a color token against DarkTheme().
        Color ColorFor(ColorToken token) noexcept;

        /// Resolves a typography token: Small 11, Body 13, BodyStrong 13/600,
        /// Number 14, Section 16/600, Title 20/600.
        FontSpec FontFor(FontToken token) noexcept;

        /// Logical pixel size.
        struct Size {
            float w = 0.0f;
            float h = 0.0f;
        };

        /// Text measurement seam: T6 injects a DirectWrite-backed
        /// implementation at startup, tests inject fixed metrics, and the
        /// fallback keeps headless builds self-contained.
        using TextMeasureFn = std::function<Size(const std::wstring& text,
                                                FontToken font,
                                                float max_width)>;

        /// Installs the global measure function; nullptr restores the
        /// built-in approximation.
        void SetTextMeasure(TextMeasureFn fn);

        /// M7 (batch3): monotone generation of the measure hook, bumped on
        /// every SetTextMeasure() install/reset. Caches keyed on measured
        /// widths (TextInputElement's caret-prefix table) compare it so a
        /// swapped hook (renderer Init/Shutdown, test metrics) never leaves
        /// stale values behind.
        uint64_t TextMeasureGeneration() noexcept;

        /// Measures `text` with `font`, clamped to `max_width`. Fallback
        /// approximation: height = size * 1.35, width = sum of per-character
        /// advances (ASCII 0.55 * size, otherwise 1.0 * size).
        Size MeasureText(const std::wstring& text, FontToken font,
                         float max_width);

    }  // namespace ui
}  // namespace vgww
