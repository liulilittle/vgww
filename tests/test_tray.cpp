// ============================================================================
// test_tray.cpp - batch252: the tray ICON GEOMETRY and COLOR seams had almost
// no direct coverage. test_ui.cpp:1495-1551 only checks where the ACCENT pixels
// sit (V orientation); it never pins the channel packing, the 0..1 clamp, the
// rounding, the corner radius, the border test or the segment distance. A
// 21-mutation sweep killed only 2.
//
// Scope: pure functions only (PackIconPixel, FillAppIconPixels). The menu and
// registry paths need a real UI thread / HKCU and are covered elsewhere.
// ============================================================================
#include <cstdio>
#include <cstdint>
#include <vector>

#include "ui/tray.h"
#include "ui/theme.h"

namespace {

    int g_failures = 0;

#define CHECK(cond)                                                        \
    do {                                                                   \
        if (!(cond)) {                                                     \
            std::fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__,  \
                         __LINE__, #cond);                                 \
            ++g_failures;                                                  \
        }                                                                  \
    } while (0)

    using namespace vgww::ui;

    std::uint32_t Rgb(std::uint32_t packed) { return packed & 0x00FFFFFFu; }
    std::uint32_t Alpha(std::uint32_t packed) { return (packed >> 24) & 0xFFu; }
    std::uint32_t Red(std::uint32_t packed) { return (packed >> 16) & 0xFFu; }
    std::uint32_t Green(std::uint32_t packed) { return (packed >> 8) & 0xFFu; }
    std::uint32_t Blue(std::uint32_t packed) { return packed & 0xFFu; }

    Color MakeColor(float r, float g, float b) {
        Color c = ColorFor(ColorToken::Accent);
        c.r = r;
        c.g = g;
        c.b = b;
        return c;
    }

    // --- PackIconPixel: channel order ---------------------------------------

    void TestChannelsAreBgraNotArgb() {
        // The DIB word is 0xAARRGGBB: red must land in bits 16..23 and blue in
        // 0..7. Swapping them is invisible on a grey theme, so pin it exactly.
        const std::uint32_t p = tray::PackIconPixel(MakeColor(1.0f, 0.0f, 0.0f));
        CHECK(Red(p) == 255u);
        CHECK(Green(p) == 0u);
        CHECK(Blue(p) == 0u);

        const std::uint32_t blue = tray::PackIconPixel(MakeColor(0.0f, 0.0f, 1.0f));
        CHECK(Red(blue) == 0u);
        CHECK(Blue(blue) == 255u);

        const std::uint32_t green = tray::PackIconPixel(MakeColor(0.0f, 1.0f, 0.0f));
        CHECK(Green(green) == 255u);
        CHECK(Red(green) == 0u);
        CHECK(Blue(green) == 0u);
    }

    void TestAlphaIsAlwaysOpaque() {
        // The icon is drawn opaque; every channel value must still get FF alpha
        // (a 0 alpha would make the whole tray icon invisible).
        for (const float v : {0.0f, 0.25f, 0.5f, 1.0f}) {
            CHECK(Alpha(tray::PackIconPixel(MakeColor(v, v, v))) == 255u);
        }
    }

    // --- PackIconPixel: 0..1 clamp ------------------------------------------

    void TestClampBelowZero() {
        const std::uint32_t p = tray::PackIconPixel(MakeColor(-5.0f, -5.0f, -5.0f));
        CHECK(Red(p) == 0u);
        CHECK(Green(p) == 0u);
        CHECK(Blue(p) == 0u);
    }

    void TestClampAboveOne() {
        const std::uint32_t p = tray::PackIconPixel(MakeColor(2.5f, 2.5f, 2.5f));
        CHECK(Red(p) == 255u);
        CHECK(Green(p) == 255u);
        CHECK(Blue(p) == 255u);
    }

    // --- PackIconPixel: rounding and the 255 scale --------------------------

    void TestZeroAndOneAreExact() {
        CHECK(Red(tray::PackIconPixel(MakeColor(0.0f, 0.0f, 0.0f))) == 0u);
        CHECK(Red(tray::PackIconPixel(MakeColor(1.0f, 1.0f, 1.0f))) == 255u);
    }

    void TestMidpointRoundsUp() {
        // 0.5 * 255 = 127.5; the +0.5 bias makes it 128 (round-half-up).
        CHECK(Red(tray::PackIconPixel(MakeColor(0.5f, 0.5f, 0.5f))) == 128u);
    }

    void TestRoundingBoundary() {
        // 0.001 -> 0.255 + 0.5 = 0.755 -> 0 ; 0.002 -> 0.51 + 0.5 = 1.01 -> 1.
        // A missing +0.5 would keep both at 0, which is why the exact boundary
        // below is asserted rather than just "small values are small".
        CHECK(Red(tray::PackIconPixel(MakeColor(0.001f, 0.001f, 0.001f))) == 0u);
        CHECK(Red(tray::PackIconPixel(MakeColor(0.002f, 0.002f, 0.002f))) == 1u);
    }

    void TestFullScaleIsNotTwoFiftyFour() {
        // 1.0 must map to 255, not 254 (the scale is 255, not 254).
        CHECK(Blue(tray::PackIconPixel(MakeColor(1.0f, 1.0f, 1.0f))) == 255u);
        // And a value one step below full must be distinguishable.
        const std::uint32_t almost =
            tray::PackIconPixel(MakeColor(254.0f / 255.0f, 254.0f / 255.0f,
                                          254.0f / 255.0f));
        CHECK(Blue(almost) == 254u);
    }

    void TestEachChannelIndependent() {
        const std::uint32_t p = tray::PackIconPixel(MakeColor(0.2f, 0.6f, 0.9f));
        CHECK(Red(p) == 51u);    // 0.2*255+0.5 = 51.5 -> 51
        CHECK(Green(p) == 153u); // 0.6*255+0.5 = 153.5 -> 153
        CHECK(Blue(p) == 230u);  // 0.9*255+0.5 = 230.0 -> 230
    }

    // --- FillAppIconPixels: guards ------------------------------------------

    void TestNullBufferIsSafe() {
        tray::FillAppIconPixels(nullptr, 16, false);  // must not crash
        tray::FillAppIconPixels(nullptr, 0, true);
    }

    void TestNonPositiveSizeIsSafe() {
        std::vector<std::uint32_t> px(4, 0xDEADBEEFu);
        tray::FillAppIconPixels(px.data(), 0, false);
        CHECK(px[0] == 0xDEADBEEFu);  // untouched
        tray::FillAppIconPixels(px.data(), -3, false);
        CHECK(px[0] == 0xDEADBEEFu);
    }

    // --- FillAppIconPixels: geometry ---------------------------------------

    void TestCornersAreTransparent() {
        // Outside the rounded square the pixel stays 0, so the corner radius is
        // observable: with the radius ignored the four corners get painted.
        constexpr int kSize = 32;
        std::vector<std::uint32_t> px(static_cast<std::size_t>(kSize) * kSize, 0u);
        tray::FillAppIconPixels(px.data(), kSize, false);
        CHECK(px[0] == 0u);                                        // top-left
        CHECK(px[static_cast<std::size_t>(kSize) - 1] == 0u);      // top-right
        CHECK(px[static_cast<std::size_t>(kSize) * (kSize - 1)] == 0u);
        CHECK(px[static_cast<std::size_t>(kSize) * kSize - 1] == 0u);
    }

    void TestCenterIsPainted() {
        constexpr int kSize = 32;
        std::vector<std::uint32_t> px(static_cast<std::size_t>(kSize) * kSize, 0u);
        tray::FillAppIconPixels(px.data(), kSize, false);
        const std::uint32_t center =
            px[static_cast<std::size_t>(kSize / 2) * kSize + kSize / 2];
        CHECK(center != 0u);
        CHECK(Alpha(center) == 255u);
    }

    void TestUsesExactlyThreeThemeRoles() {
        // Panel / Border / Accent - AND NOTHING ELSE. A border-colour swap or a
        // dropped border shows up as a missing colour from this set.
        constexpr int kSize = 32;
        std::vector<std::uint32_t> px(static_cast<std::size_t>(kSize) * kSize, 0u);
        tray::FillAppIconPixels(px.data(), kSize, false);

        const std::uint32_t panel =
            tray::PackIconPixel(ColorFor(ColorToken::Panel));
        const std::uint32_t border =
            tray::PackIconPixel(ColorFor(ColorToken::Border));
        const std::uint32_t accent =
            tray::PackIconPixel(ColorFor(ColorToken::Accent));

        int n_panel = 0, n_border = 0, n_accent = 0, n_other = 0, n_empty = 0;
        for (const std::uint32_t p : px) {
            if (p == 0u) { ++n_empty; }
            else if (p == panel) { ++n_panel; }
            else if (p == border) { ++n_border; }
            else if (p == accent) { ++n_accent; }
            else { ++n_other; }
        }
        CHECK(n_other == 0);
        CHECK(n_empty > 0);   // the rounded corners
        CHECK(n_panel > 0);
        CHECK(n_border > 0);  // the 1px rim
        CHECK(n_accent > 0);  // the V
    }

    void TestBorderRimExistsOnAllSides() {
        // A row through the middle must hit border pixels on both the left and
        // the right; an inverted border test loses them.
        constexpr int kSize = 32;
        std::vector<std::uint32_t> px(static_cast<std::size_t>(kSize) * kSize, 0u);
        tray::FillAppIconPixels(px.data(), kSize, false);
        const std::uint32_t border =
            tray::PackIconPixel(ColorFor(ColorToken::Border));
        // The middle row crosses the rounded square's STRAIGHT edges, so it
        // is painted from x=0 to x=kSize-1; the rim sits just inside each end.
        const std::size_t row = static_cast<std::size_t>(kSize / 2) * kSize;
        int first_painted = -1, last_painted = -1;
        int first_border = -1, last_border = -1;
        for (int x = 0; x < kSize; ++x) {
            const std::uint32_t p = px[row + static_cast<std::size_t>(x)];
            if (p != 0u) {
                if (first_painted < 0) { first_painted = x; }
                last_painted = x;
            }
            if (p == border) {
                if (first_border < 0) { first_border = x; }
                last_border = x;
            }
        }
        CHECK(first_painted == 0);             // straight edge, fully painted
        CHECK(last_painted == kSize - 1);
        CHECK(first_border >= 0);
        CHECK(last_border >= 0);
        // SYMMETRY: the rim is 1px on EVERY side. Before the fix the inner
        // rounded rect kept the outer origin, so the left/top rim fell
        // inside it and was painted as panel while the right/bottom rim
        // became border - a border on two sides only.
        CHECK(kSize - 1 - last_painted == first_painted);
        CHECK(last_border == kSize - 1 - first_border);
        CHECK(first_border < kSize / 4);       // left rim
        CHECK(last_border > kSize * 3 / 4);    // right rim
    }

    void TestBorderHugsTheOuterEdge() {
        // The rim must be the OUTERMOST painted ring. An inverted on_border
        // test paints the interior as border and leaves the edge as panel,
        // which still yields all three colours - so count the ORDER matters:
        // walking inward from the left painted pixel, the first few must be
        // border and only then panel.
        constexpr int kSize = 32;
        std::vector<std::uint32_t> px(static_cast<std::size_t>(kSize) * kSize, 0u);
        tray::FillAppIconPixels(px.data(), kSize, false);
        const std::uint32_t panel =
            tray::PackIconPixel(ColorFor(ColorToken::Panel));
        const std::uint32_t border =
            tray::PackIconPixel(ColorFor(ColorToken::Border));
        const std::size_t row = static_cast<std::size_t>(kSize / 2) * kSize;
        CHECK(px[row + 0] == border);   // the very edge IS the rim
        CHECK(px[row + kSize - 1] == border);
        // ... and one pixel further in it is already panel, not border.
        CHECK(px[row + 1] == panel);
        CHECK(px[row + kSize - 2] == panel);
    }

    void TestBorderIsSymmetricVertically() {
        // Same defect on the Y axis: the top rim must look like the bottom.
        constexpr int kSize = 32;
        std::vector<std::uint32_t> px(static_cast<std::size_t>(kSize) * kSize, 0u);
        tray::FillAppIconPixels(px.data(), kSize, false);
        const std::uint32_t border =
            tray::PackIconPixel(ColorFor(ColorToken::Border));
        const std::size_t col = static_cast<std::size_t>(kSize / 2);
        int first_border = -1, last_border = -1;
        for (int y = 0; y < kSize; ++y) {
            if (px[static_cast<std::size_t>(y) * kSize + col] == border) {
                if (first_border < 0) { first_border = y; }
                last_border = y;
            }
        }
        CHECK(first_border >= 0);
        CHECK(last_border >= 0);
        CHECK(last_border == kSize - 1 - first_border);
    }

    void TestStrokeThicknessIsBounded() {
        // The V strokes are ~11% of the extent thick. A much thicker stroke
        // (or a missing one) changes the accent pixel count drastically, so
        // bound the accent fraction from both sides.
        constexpr int kSize = 64;
        std::vector<std::uint32_t> px(static_cast<std::size_t>(kSize) * kSize, 0u);
        tray::FillAppIconPixels(px.data(), kSize, false);
        const std::uint32_t accent =
            tray::PackIconPixel(ColorFor(ColorToken::Accent));
        int n_accent = 0;
        for (const std::uint32_t p : px) {
            if (p == accent) { ++n_accent; }
        }
        // RADIUS SENSITIVITY: the fraction OUTSIDE the rounded square is the
        // sharpest signal (measured 0.041 at radius 0.22, 0.078 at 0.30).
        // Panel/accent fractions barely move, which is why they were useless
        // as a radius tripwire.
        int n_empty = 0;
        for (const std::uint32_t p : px) {
            if (p == 0u) { ++n_empty; }
        }
        const double empty_fraction = static_cast<double>(n_empty) /
                                      (static_cast<double>(kSize) * kSize);
        CHECK(empty_fraction > 0.030);
        CHECK(empty_fraction < 0.055);
        const double fraction = static_cast<double>(n_accent) /
                                (static_cast<double>(kSize) * kSize);
        // Measured at 0.11 extent thickness on a 64px icon. A tightened band
        // (not 0.03..0.25) is what makes a thickness/radius change detectable.
        CHECK(fraction > 0.06);   // the V is present
        CHECK(fraction < 0.14);   // ... and not a filled block
    }

    void TestBottomUpMirrorsTheVVertically() {
        // MEASURED at size 64: display row 24 is the two arms (16 accent
        // pixels, NONE within +/-3 columns of centre); display row 48 is the
        // apex (6 accent pixels, ALL of them near the centre). That makes
        // the centre-hit count an asymmetric anchor: a vertical flip swaps
        // which DISPLAY row holds it, and reading a fixed BUFFER row cannot
        // follow that swap.
        constexpr int kSize = 64;
        const std::uint32_t accent =
            tray::PackIconPixel(ColorFor(ColorToken::Accent));
        const auto centre_hits = [&](const std::vector<std::uint32_t>& px,
                                     int row) {
            int n = 0;
            for (int x = kSize / 2 - 3; x <= kSize / 2 + 3; ++x) {
                if (px[static_cast<std::size_t>(row) * kSize + x] == accent) {
                    ++n;
                }
            }
            return n;
        };
        const auto total_hits = [&](const std::vector<std::uint32_t>& px,
                                    int row) {
            int n = 0;
            for (int x = 0; x < kSize; ++x) {
                if (px[static_cast<std::size_t>(row) * kSize + x] == accent) {
                    ++n;
                }
            }
            return n;
        };

        std::vector<std::uint32_t> top_down(
            static_cast<std::size_t>(kSize) * kSize, 0u);
        tray::FillAppIconPixels(top_down.data(), kSize, false);
        CHECK((total_hits(top_down, 24) > total_hits(top_down, 48)));
        CHECK((centre_hits(top_down, 48) > centre_hits(top_down, 24)));

        // bottom_up stores the VISUAL BOTTOM first, so the apex (display
        // row 48) must be the one that moved: buffer row (n-1-48)=15 now
        // carries it, and buffer row (n-1-24)=39 carries the arms. A flag
        // ignored or inverted leaves the apex at the other end.
        std::vector<std::uint32_t> bottom_up(
            static_cast<std::size_t>(kSize) * kSize, 0u);
        tray::FillAppIconPixels(bottom_up.data(), kSize, true);
        CHECK((centre_hits(bottom_up, kSize - 1 - 48) >
               centre_hits(bottom_up, kSize - 1 - 24)));
        CHECK((total_hits(bottom_up, kSize - 1 - 24) >
               total_hits(bottom_up, kSize - 1 - 48)));
        // Cross-check: the mirrored buffer rows must agree EXACTLY.
        CHECK(total_hits(bottom_up, kSize - 1 - 48) == total_hits(top_down, 48));
        CHECK(centre_hits(bottom_up, kSize - 1 - 48) == centre_hits(top_down, 48));
    }

    // --- batch318: the TaskbarCreated re-registration state machine ---------
    //
    // Explorer restarts (crash, update, "restart explorer") destroy every
    // Shell_NotifyIcon icon. The window forwards every message to
    // tray::HandleWindowMessage, so that function must consume the
    // TaskbarCreated broadcast and re-register the SAME icon - otherwise a
    // --minimized window loses its tray icon and has no way back. The shell
    // call is injected so the whole path runs without a real taskbar.

    struct FakeShell {
        static int adds;
        static int deletes;
        static int modifies;
        static HWND hwnd;
        static HICON icon;
        static UINT id;
        static std::wstring tip;
        static bool result;
    };
    int FakeShell::adds = 0;
    int FakeShell::deletes = 0;
    int FakeShell::modifies = 0;
    HWND FakeShell::hwnd = nullptr;
    HICON FakeShell::icon = nullptr;
    UINT FakeShell::id = 0;
    std::wstring FakeShell::tip;
    bool FakeShell::result = false;

    BOOL WINAPI FakeShellNotify(DWORD message, PNOTIFYICONDATAW data) {
        if (data == nullptr) {
            return FALSE;
        }
        if (NIM_ADD == message) {
            ++FakeShell::adds;
            FakeShell::hwnd = data->hWnd;
            FakeShell::icon = data->hIcon;
            FakeShell::id = data->uID;
            FakeShell::tip = data->szTip;
        } else if (NIM_DELETE == message) {
            ++FakeShell::deletes;
        } else if (NIM_MODIFY == message) {
            ++FakeShell::modifies;
        }
        return FakeShell::result ? TRUE : FALSE;
    }

    HWND FakeHwnd() {
        return reinterpret_cast<HWND>(static_cast<INT_PTR>(0x11));
    }
    HICON FakeIcon() {
        return reinterpret_cast<HICON>(static_cast<INT_PTR>(0x22));
    }

    void TestTaskbarCreatedMessageId() {
        const UINT id = tray::RegisterTaskbarMessage();
        CHECK(id != 0);  // RegisterWindowMessageW must succeed
        CHECK(tray::RegisterTaskbarMessage() == id);  // stable per session
        CHECK(tray::IsTaskbarCreatedMessage(id));
        CHECK(!tray::IsTaskbarCreatedMessage(0));
        CHECK(!tray::IsTaskbarCreatedMessage(id + 1));
        CHECK(!tray::IsTaskbarCreatedMessage(WM_APP + 1));  // the tray callback
    }

    void TestTaskbarCreatedReRegistersTheIcon() {
        tray::SetShellNotifyForTest(&FakeShellNotify);
        FakeShell::adds = 0;
        FakeShell::deletes = 0;
        FakeShell::modifies = 0;
        FakeShell::hwnd = nullptr;
        FakeShell::icon = nullptr;
        FakeShell::id = 0;
        FakeShell::tip.clear();

        // (a) The shell was not up when the window started (autostart races
        //     the taskbar): the first Add fails, but the REQUEST is kept.
        FakeShell::result = false;
        CHECK(!tray::Add(FakeHwnd(), FakeIcon(), L"VGWW"));
        CHECK(!tray::IsAdded());
        CHECK(FakeShell::adds == 1);

        // (b) The shell comes up and broadcasts TaskbarCreated. The window
        //     forwards it; the stored registration is retried and succeeds.
        FakeShell::result = true;
        CHECK(tray::HandleWindowMessage(FakeHwnd(),
                                        tray::RegisterTaskbarMessage(), 0, 0));
        CHECK(tray::IsAdded());
        CHECK(FakeShell::adds == 2);
        CHECK(FakeShell::hwnd == FakeHwnd());
        CHECK(FakeShell::icon == FakeIcon());
        CHECK(FakeShell::id == 1u);
        CHECK(FakeShell::tip == L"VGWW");

        // (c) A second Explorer restart re-registers again.
        CHECK(tray::HandleWindowMessage(FakeHwnd(),
                                        tray::RegisterTaskbarMessage(), 0, 0));
        CHECK(FakeShell::adds == 3);

        // (d) Unrelated messages are not consumed.
        CHECK(!tray::HandleWindowMessage(FakeHwnd(), WM_APP + 7, 0, 0));

        // (e) Remove forgets the request: a later broadcast must NOT
        //     resurrect an icon for a destroyed window.
        tray::Remove();
        CHECK(!tray::IsAdded());
        CHECK(FakeShell::deletes == 1);
        const int adds_before = FakeShell::adds;
        CHECK(tray::HandleWindowMessage(FakeHwnd(),
                                        tray::RegisterTaskbarMessage(), 0, 0));
        CHECK(FakeShell::adds == adds_before);

        tray::SetShellNotifyForTest(nullptr);
    }

    void TestOddSizeIsSafe() {
        // Odd extents exercise the rounding of the +0.5 pixel centre.
        for (const int size : {1, 3, 7, 15, 33}) {
            std::vector<std::uint32_t> px(
                static_cast<std::size_t>(size) * static_cast<std::size_t>(size), 0u);
            tray::FillAppIconPixels(px.data(), size, false);
            tray::FillAppIconPixels(px.data(), size, true);
        }
        CHECK(true);
    }

}  // namespace

int main() {
    TestChannelsAreBgraNotArgb();
    TestAlphaIsAlwaysOpaque();
    TestClampBelowZero();
    TestClampAboveOne();
    TestZeroAndOneAreExact();
    TestMidpointRoundsUp();
    TestRoundingBoundary();
    TestFullScaleIsNotTwoFiftyFour();
    TestEachChannelIndependent();
    TestNullBufferIsSafe();
    TestNonPositiveSizeIsSafe();
    TestCornersAreTransparent();
    TestCenterIsPainted();
    TestUsesExactlyThreeThemeRoles();
    TestBorderRimExistsOnAllSides();
    TestBorderHugsTheOuterEdge();
    TestBorderIsSymmetricVertically();
    TestStrokeThicknessIsBounded();
    TestBottomUpMirrorsTheVVertically();
    TestOddSizeIsSafe();
    TestTaskbarCreatedMessageId();
    TestTaskbarCreatedReRegistersTheIcon();

    if (0 == g_failures) {
        std::puts("test_tray: ALL PASS");
        return 0;
    }
    std::fprintf(stderr, "test_tray: %d FAILURES\n", g_failures);
    return 1;
}
