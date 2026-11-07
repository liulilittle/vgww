// ============================================================================
// test_ui_state.cpp - batch258: ui_state.cpp had large coverage holes.
//
// A 44-mutation sweep against the untouched implementation killed only 4.
// Every failure path of Load() (discarded / non-object / wrong-typed /
// non-finite / zero-size), every threshold in the two work-area predicates,
// the directory-creation and truncate flags in Save(), and the work-area
// clamping/centring branches of RestoreWindowState() were entirely free to
// change. test_ui.cpp only exercises the happy path (write -> read -> restore
// on the primary monitor).
//
// Everything here is deterministic and headless; file I/O goes through
// SetStatePathForTest under a scratch directory in the OS temp folder.
// ============================================================================
#include <windows.h>

#include "ui/ui_state.h"

#include <cmath>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

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

    namespace uis = vgww::ui::ui_state;
    using uis::RectI;
    using uis::WindowState;

    // batch326: scratch path in the OS temp folder (portable across machines).
    const std::wstring kDir =
        (std::filesystem::temp_directory_path() / L"vgww-tests" /
         L"b258-ui-state")
            .wstring();
    const std::wstring kPath = kDir + L"\\ui_state.json";

    void WriteRaw(const std::string& text) {
        std::filesystem::create_directories(kDir);
        std::ofstream out(kPath.c_str(), std::ios::binary | std::ios::trunc);
        out.write(text.data(), static_cast<std::streamsize>(text.size()));
    }

    void RemoveFile() {
        std::error_code ec;
        std::filesystem::remove(kPath, ec);
    }

    std::string ReadRaw() {
        std::ifstream in(kPath.c_str(), std::ios::binary);
        return std::string((std::istreambuf_iterator<char>(in)),
                           std::istreambuf_iterator<char>());
    }

    WindowState Saved(int x, int y, float w, float h) {
        WindowState s;
        s.x = x;
        s.y = y;
        s.w = w;
        s.h = h;
        s.valid = true;
        return s;
    }

    // ===================== RestoreWindowState: reject paths ================

    void TestRestoreRejectsInvalidSaved() {
        const RectI primary{0, 0, 1920, 1040};
        const std::vector<RectI> areas{primary};
        WindowState bogus = Saved(100, 100, 1200.0f, 800.0f);
        bogus.valid = false;
        const WindowState out =
            uis::RestoreWindowState(bogus, 1.0f, 980.0f, 640.0f, areas, primary);
        CHECK(!out.valid);  // caller keeps its defaults
    }

    void TestRestoreRejectsSizeBelowTheDesignMinimum() {
        const RectI primary{0, 0, 1920, 1040};
        const std::vector<RectI> areas{primary};
        // Width below the minimum.
        CHECK(!uis::RestoreWindowState(Saved(100, 100, 900.0f, 800.0f), 1.0f,
                                       980.0f, 640.0f, areas, primary)
                   .valid);
        // Height below the minimum.
        CHECK(!uis::RestoreWindowState(Saved(100, 100, 1200.0f, 600.0f), 1.0f,
                                       980.0f, 640.0f, areas, primary)
                   .valid);
        // Exactly the minimum is allowed (the comparison is >=).
        CHECK(uis::RestoreWindowState(Saved(100, 100, 980.0f, 640.0f), 1.0f,
                                      980.0f, 640.0f, areas, primary)
                  .valid);
    }

    void TestRestoreMinimumIsScaledTogetherWithTheSize() {
        const RectI primary{0, 0, 3840, 2160};
        const std::vector<RectI> areas{primary};
        // At 200% the same logical minimum is 1960x1280 PHYSICAL pixels, so a
        // stored logical 1500x700 (-> 3000x1400 physical) still clears it.
        CHECK(uis::RestoreWindowState(Saved(10, 10, 1500.0f, 700.0f), 2.0f,
                                      980.0f, 640.0f, areas, primary)
                  .valid);
        // ...but a stored logical 600x600 (-> 1200x1200) fails the 1280 height.
        CHECK(!uis::RestoreWindowState(Saved(10, 10, 600.0f, 600.0f), 2.0f,
                                       980.0f, 640.0f, areas, primary)
                   .valid);
    }

    void TestRestoreTreatsNonPositiveScaleAsOne() {
        const RectI primary{0, 0, 1920, 1040};
        const std::vector<RectI> areas{primary};
        const WindowState zero =
            uis::RestoreWindowState(Saved(120, 80, 1225.0f, 800.0f), 0.0f,
                                    980.0f, 640.0f, areas, primary);
        CHECK(zero.valid);
        CHECK(zero.x == 120 && zero.y == 80);
        CHECK(std::fabs(zero.w - 1225.0f) < 0.01f);

        const WindowState negative =
            uis::RestoreWindowState(Saved(120, 80, 1225.0f, 800.0f), -1.0f,
                                    980.0f, 640.0f, areas, primary);
        CHECK(negative.valid);
        CHECK(std::fabs(negative.w - 1225.0f) < 0.01f);
    }

    // ===================== RestoreWindowState: clamping ====================

    void TestRestoreClampsToTheWorkAreaItLandsOn() {
        const RectI primary{0, 0, 1920, 1040};
        // A second monitor to the RIGHT, smaller than the primary.
        const RectI secondary{1920, 0, 1280, 720};
        const std::vector<RectI> areas{primary, secondary};

        // Top-left corner on the secondary -> clamp against ITS size.
        const WindowState on_secondary = uis::RestoreWindowState(
            Saved(2000, 100, 1600.0f, 900.0f), 1.0f, 980.0f, 640.0f, areas,
            primary);
        CHECK(on_secondary.valid);
        CHECK(std::fabs(on_secondary.w - 1280.0f) < 0.01f);
        CHECK(on_secondary.h <= 720.0f + 0.01f);

        // Top-left corner on the primary -> NOT clamped (1600x900 fits).
        const WindowState on_primary = uis::RestoreWindowState(
            Saved(100, 100, 1600.0f, 900.0f), 1.0f, 980.0f, 640.0f, areas,
            primary);
        CHECK(on_primary.valid);
        CHECK(std::fabs(on_primary.w - 1600.0f) < 0.01f);
        CHECK(std::fabs(on_primary.h - 900.0f) < 0.01f);
    }

    void TestRestoreRejectsWhenTheWorkAreaCannotHoldTheMinimum() {
        // A 1x1 work area can never hold a 980x640 logical minimum.
        const RectI tiny{0, 0, 1, 1};
        const std::vector<RectI> areas{tiny};
        CHECK(!uis::RestoreWindowState(Saved(0, 0, 1200.0f, 800.0f), 1.0f,
                                       980.0f, 640.0f, areas, tiny)
                   .valid);
    }

    void TestRestoreReDerivesTheLogicalSizeFromTheClampedPixels() {
        const RectI primary{0, 0, 1920, 1040};
        const std::vector<RectI> areas{primary};
        // Logical 3000x2000 at 150% = 4500x3000 physical -> clamped to the
        // work area -> written back as LOGICAL (physical / scale).
        // (At 200% the same area could NOT hold the 1960x1280 minimum, so the
        // function would correctly return invalid -- see the contrast below.)
        const WindowState out = uis::RestoreWindowState(
            Saved(0, 0, 3000.0f, 2000.0f), 1.5f, 980.0f, 640.0f, areas,
            primary);
        CHECK(out.valid);
        CHECK(std::fabs(out.w - 1280.0f) < 0.5f);   // 1920 / 1.5
        CHECK(std::fabs(out.h - 693.33f) < 0.5f);   // 1040 / 1.5

        // Contrast: at 200% the very same work area is too small for the
        // scaled minimum, so the state is rejected rather than clamped.
        CHECK(!uis::RestoreWindowState(Saved(0, 0, 3000.0f, 2000.0f), 2.0f,
                                       980.0f, 640.0f, areas, primary)
                   .valid);
    }

    // ===================== RestoreWindowState: visibility ==================

    void TestRestoreKeepsAPositionWithAUsableTitleStrip() {
        const RectI primary{0, 0, 1920, 1040};
        const std::vector<RectI> areas{primary};
        // Mostly off the right edge, but a 100px-wide, 400px-tall strip of the
        // window still overlaps the work area -> the title bar is reachable.
        const WindowState out = uis::RestoreWindowState(
            Saved(1820, 100, 1200.0f, 800.0f), 1.0f, 980.0f, 640.0f, areas,
            primary);
        CHECK(out.valid);
        CHECK(out.x == 1820);  // NOT re-centred
        CHECK(out.y == 100);
    }

    void TestRestoreRejectsAStripNarrowerThan64px() {
        const RectI primary{0, 0, 1920, 1040};
        const std::vector<RectI> areas{primary};
        const WindowState out = uis::RestoreWindowState(
            Saved(1910, 100, 1200.0f, 800.0f), 1.0f, 980.0f, 640.0f, areas,
            primary);
        CHECK(out.valid);
        CHECK(out.x != 1910);
        CHECK(out.x ==
              primary.x +
                  static_cast<int>((primary.w - out.w * 1.0f) / 2.0f));
    }

    void TestRestoreRejectsAStripShorterThan24px() {
        const RectI primary{0, 0, 1920, 1040};
        const std::vector<RectI> areas{primary};
        const WindowState out = uis::RestoreWindowState(
            Saved(100, 1030, 1200.0f, 800.0f), 1.0f, 980.0f, 640.0f, areas,
            primary);
        CHECK(out.valid);
        CHECK(out.y != 1030);
        CHECK(out.y ==
              primary.y +
                  static_cast<int>((primary.h - out.h * 1.0f) / 2.0f));
    }

    void TestRestoreCentresOnAPrimaryWithANonZeroOrigin() {
        // Taskbar on the left/top -> the primary work area starts at (100,50).
        const RectI primary{100, 50, 1920, 1040};
        const std::vector<RectI> areas{primary};
        const WindowState out = uis::RestoreWindowState(
            Saved(9000, 9000, 1200.0f, 800.0f), 1.0f, 980.0f, 640.0f, areas,
            primary);
        CHECK(out.valid);
        CHECK(out.x == 100 + static_cast<int>((1920 - 1200) / 2.0f));
        CHECK(out.y == 50 + static_cast<int>((1040 - 800) / 2.0f));
        CHECK(out.x >= 100 && out.x < 100 + 1920);
        CHECK(out.y >= 50 && out.y < 50 + 1040);
    }

    void TestRestoreCarriesTheMaximizedFlag() {
        const RectI primary{0, 0, 1920, 1040};
        const std::vector<RectI> areas{primary};
        WindowState saved = Saved(120, 80, 1225.0f, 800.0f);
        saved.maximized = true;
        const WindowState out = uis::RestoreWindowState(
            saved, 1.0f, 980.0f, 640.0f, areas, primary);
        CHECK(out.valid);
        CHECK(out.maximized);
        // The rect is still the NORMAL one (un-maximize lands there).
        CHECK(out.x == 120 && out.y == 80);

        saved.maximized = false;
        const WindowState flat = uis::RestoreWindowState(
            saved, 1.0f, 980.0f, 640.0f, areas, primary);
        CHECK(flat.valid);
        CHECK(!flat.maximized);
    }

    // ===================== Exact boundaries ================================

    void TestRestoreContainsIsHalfOpenInBothAxes() {
        // WorkAreaContains decides which area the window is clamped against.
        // It must test BOTH axes (x AND y) and use HALF-OPEN intervals, so the
        // exact right/bottom edge belongs to the NEXT area.
        const RectI primary{0, 0, 1920, 1040};
        const RectI right_area{1920, 0, 1280, 720};
        const RectI below_area{0, 1040, 1920, 720};
        const std::vector<RectI> areas{primary, right_area, below_area};

        // x inside the secondary, y FAR outside it -> must NOT land there.
        // (A predicate that forgot the y test would pick right_area and clamp
        // against 1280 instead of 1920.)
        const WindowState ignore_y = uis::RestoreWindowState(
            Saved(2000, 5000, 1600.0f, 900.0f), 1.0f, 980.0f, 640.0f, areas,
            primary);
        CHECK(ignore_y.valid);
        CHECK(std::fabs(ignore_y.w - 1600.0f) < 0.01f);  // primary width

        // y inside the third area, x far outside it -> must NOT land there.
        const WindowState ignore_x = uis::RestoreWindowState(
            Saved(5000, 1100, 1600.0f, 900.0f), 1.0f, 980.0f, 640.0f, areas,
            primary);
        CHECK(ignore_x.valid);
        CHECK(std::fabs(ignore_x.h - 900.0f) < 0.01f);

        // EXACT right edge of the primary (1920) is NOT inside it: the window
        // lands on right_area, so a 1600-wide window is clamped to 1280.
        const WindowState on_right_edge = uis::RestoreWindowState(
            Saved(1920, 100, 1600.0f, 900.0f), 1.0f, 980.0f, 640.0f, areas,
            primary);
        CHECK(on_right_edge.valid);
        CHECK(std::fabs(on_right_edge.w - 1280.0f) < 0.01f);

        // EXACT bottom edge of the primary (1040) is NOT inside it either.
        const WindowState on_bottom_edge = uis::RestoreWindowState(
            Saved(100, 1040, 1600.0f, 900.0f), 1.0f, 980.0f, 640.0f, areas,
            primary);
        CHECK(on_bottom_edge.valid);
        CHECK(std::fabs(on_bottom_edge.h - 720.0f) < 0.01f);

        // One pixel INSIDE the primary is still the primary.
        const WindowState inside = uis::RestoreWindowState(
            Saved(1919, 1039, 1600.0f, 900.0f), 1.0f, 980.0f, 640.0f, areas,
            primary);
        CHECK(inside.valid);
        CHECK(std::fabs(inside.w - 1600.0f) < 0.01f);
        CHECK(std::fabs(inside.h - 900.0f) < 0.01f);
    }

    void TestRestoreTitleStripThresholdsAreInclusive() {
        const RectI primary{0, 0, 1920, 1040};
        const std::vector<RectI> areas{primary};

        // A strip EXACTLY 64px wide and 24px tall counts as reachable
        // (the comparison is >= on both axes).
        // Window x = 1856 => overlap = 1920 - 1856 = 64.
        // Window y = 1016 => overlap = 1040 - 1016 = 24.
        const WindowState exact = uis::RestoreWindowState(
            Saved(1856, 1016, 1200.0f, 800.0f), 1.0f, 980.0f, 640.0f, areas,
            primary);
        CHECK(exact.valid);
        CHECK(exact.x == 1856);  // NOT re-centred
        CHECK(exact.y == 1016);

        // One pixel narrower (63px) is NOT reachable -> centred.
        const WindowState narrow = uis::RestoreWindowState(
            Saved(1857, 1016, 1200.0f, 800.0f), 1.0f, 980.0f, 640.0f, areas,
            primary);
        CHECK(narrow.valid);
        CHECK(narrow.x != 1857);

        // One pixel shorter (23px) is NOT reachable -> centred.
        const WindowState short_strip = uis::RestoreWindowState(
            Saved(1856, 1017, 1200.0f, 800.0f), 1.0f, 980.0f, 640.0f, areas,
            primary);
        CHECK(short_strip.valid);
        CHECK(short_strip.y != 1017);
    }

    // ===================== Load: every rejection path ======================

    void TestLoadRejectsAnUnopenablePath() {
        uis::SetStatePathForTest(kDir + L"\\does-not-exist.json");
        WindowState out;
        out.valid = true;  // must be reset even when the load fails
        CHECK(!uis::Load(out));
        CHECK(!out.valid);
        uis::SetStatePathForTest(L"");
    }

    void TestLoadRejectsAnEmptyFile() {
        WriteRaw("");
        uis::SetStatePathForTest(kPath);
        WindowState out;
        out.valid = true;
        CHECK(!uis::Load(out));
        CHECK(!out.valid);
        uis::SetStatePathForTest(L"");
        RemoveFile();
    }

    void TestLoadRejectsNonObjectJson() {
        uis::SetStatePathForTest(kPath);
        for (const char* text : {"[]", "42", "\"hello\"", "null", "true"}) {
            WriteRaw(text);
            WindowState out;
            CHECK(!uis::Load(out));
            CHECK(!out.valid);
        }
        uis::SetStatePathForTest(L"");
        RemoveFile();
    }

    void TestLoadRejectsADiscardedDocument() {
        WriteRaw("{ this is not json");
        uis::SetStatePathForTest(kPath);
        WindowState out;
        CHECK(!uis::Load(out));
        uis::SetStatePathForTest(L"");
        RemoveFile();
    }

    void TestLoadRejectsAFutureVersion() {
        uis::SetStatePathForTest(kPath);
        WriteRaw(R"({"version":2,"x":1,"y":2,"width":1200,"height":800})");
        WindowState out;
        CHECK(!uis::Load(out));
        uis::SetStatePathForTest(L"");
        RemoveFile();
    }

    void TestLoadAcceptsAMissingVersion() {
        uis::SetStatePathForTest(kPath);
        WriteRaw(R"({"x":11,"y":22,"width":1200.0,"height":800.0})");
        WindowState out;
        CHECK(uis::Load(out));
        CHECK(out.valid);
        CHECK(out.x == 11 && out.y == 22);
        CHECK(std::fabs(out.w - 1200.0f) < 0.01f);
        uis::SetStatePathForTest(L"");
        RemoveFile();
    }

    void TestLoadRejectsANonIntegerVersion() {
        uis::SetStatePathForTest(kPath);
        WriteRaw(R"({"version":"1","x":1,"y":2,"width":1200,"height":800})");
        WindowState out;
        CHECK(!uis::Load(out));
        WriteRaw(R"({"version":1.5,"x":1,"y":2,"width":1200,"height":800})");
        CHECK(!uis::Load(out));
        uis::SetStatePathForTest(L"");
        RemoveFile();
    }

    void TestLoadRejectsNonIntegerCoordinates() {
        uis::SetStatePathForTest(kPath);
        WriteRaw(R"({"x":"1","y":2,"width":1200,"height":800})");
        WindowState out;
        CHECK(!uis::Load(out));
        WriteRaw(R"({"x":1,"y":2.5,"width":1200,"height":800})");
        CHECK(!uis::Load(out));
        uis::SetStatePathForTest(L"");
        RemoveFile();
    }

    void TestLoadRejectsNonNumericSize() {
        uis::SetStatePathForTest(kPath);
        WriteRaw(R"({"x":1,"y":2,"width":"1200","height":800})");
        WindowState out;
        CHECK(!uis::Load(out));
        WriteRaw(R"({"x":1,"y":2,"width":1200})");  // height missing
        CHECK(!uis::Load(out));
        uis::SetStatePathForTest(L"");
        RemoveFile();
    }

    void TestLoadRejectsANonPositiveSize() {
        uis::SetStatePathForTest(kPath);
        WriteRaw(R"({"x":1,"y":2,"width":0,"height":800})");
        WindowState out;
        CHECK(!uis::Load(out));
        WriteRaw(R"({"x":1,"y":2,"width":1200,"height":0})");
        CHECK(!uis::Load(out));
        WriteRaw(R"({"x":1,"y":2,"width":-5.0,"height":800})");
        CHECK(!uis::Load(out));
        uis::SetStatePathForTest(L"");
        RemoveFile();
    }

    void TestLoadRejectsNonFiniteSize() {
        // nlohmann rejects NaN/Inf literals, so a non-finite value can only
        // arrive as a numeric overflow; 1e400 makes the document discarded.
        uis::SetStatePathForTest(kPath);
        WriteRaw(R"({"x":1,"y":2,"width":1e400,"height":800})");
        WindowState out;
        CHECK(!uis::Load(out));
        uis::SetStatePathForTest(L"");
        RemoveFile();
    }

    void TestLoadMaximizedDefaultsToFalseAndIgnoresNonBoolean() {
        uis::SetStatePathForTest(kPath);
        // Missing -> false.
        WriteRaw(R"({"x":1,"y":2,"width":1200,"height":800})");
        WindowState out;
        CHECK(uis::Load(out));
        CHECK(!out.maximized);
        // Wrong type -> false, but the rest still loads.
        WriteRaw(R"({"x":1,"y":2,"width":1200,"height":800,"maximized":1})");
        CHECK(uis::Load(out));
        CHECK(!out.maximized);
        // True -> true.
        WriteRaw(R"({"x":1,"y":2,"width":1200,"height":800,"maximized":true})");
        CHECK(uis::Load(out));
        CHECK(out.maximized);
        uis::SetStatePathForTest(L"");
        RemoveFile();
    }

    // ===================== Save ============================================

    void TestSaveRejectsAnInvalidState() {
        std::error_code ec;
        std::filesystem::create_directories(kDir, ec);
        uis::SetStatePathForTest(kPath);
        RemoveFile();
        WindowState invalid;  // valid == false
        invalid.w = 1200.0f;
        invalid.h = 800.0f;
        CHECK(!uis::Save(invalid));
        CHECK(!std::filesystem::exists(kPath));  // nothing was written
        uis::SetStatePathForTest(L"");
    }

    void TestSaveCreatesTheParentDirectory() {
        // EnsureParentDirectory calls CreateDirectoryW ONCE (not recursive):
        // the only path the product produces is %LOCALAPPDATA%\VGWW\<file>,
        // i.e. exactly one directory below an existing parent.
        const std::wstring one_level =
            kDir + L"\\onelevel\\ui_state.json";
        std::error_code ec;
        std::filesystem::remove_all(
            kDir + L"\\onelevel", ec);
        CHECK(!std::filesystem::exists(
            kDir + L"\\onelevel"));
        uis::SetStatePathForTest(one_level);
        CHECK(uis::Save(Saved(1, 2, 1200.0f, 800.0f)));
        CHECK(std::filesystem::exists(one_level));
        uis::SetStatePathForTest(L"");
        std::filesystem::remove_all(
            kDir + L"\\onelevel", ec);

        // A path whose parent ALREADY exists is written without creating
        // anything (the LOCALAPPDATA\VGWW case on every run after the first).
        std::filesystem::create_directories(kDir, ec);
        uis::SetStatePathForTest(kPath);
        CHECK(uis::Save(Saved(3, 4, 1200.0f, 800.0f)));
        CHECK(std::filesystem::exists(kPath));
        uis::SetStatePathForTest(L"");
        RemoveFile();
    }

    void TestEnsureParentDirectorySkipsAPathWithNoDirectoryPart() {
        // EnsureParentDirectory returns early when there is nothing above the
        // file name. BOTH early-out cases matter:
        //   * no separator at all  ("file.json"  -> npos)
        //   * separator at index 0 ("/file.json" -> 0, the root itself)
        // Without the index-0 test the function would try to CreateDirectoryW
        // on "" (everything left of the index-0 separator), which is not a
        // directory the process must create.

        // (a) no separator: the save goes to the CWD.
        const std::wstring plain = L"b258-plain-name.json";
        uis::SetStatePathForTest(plain);
        CHECK(uis::Save(Saved(1, 2, 1200.0f, 800.0f)));
        CHECK(std::filesystem::exists(plain));
        uis::SetStatePathForTest(L"");
        std::error_code ec;
        std::filesystem::remove(plain, ec);

        // (b) separator at index 0: no directory part, so nothing is created.
        // The save may fail (the root is not writable) but it must not crash.
        uis::SetStatePathForTest(L"/b258-root-only.json");
        (void)uis::Save(Saved(1, 2, 1200.0f, 800.0f));
        uis::SetStatePathForTest(L"");
    }

    void TestSaveOverwritesRatherThanAppends() {
        WriteRaw(R"({"x":9999,"y":9999,"width":1,"height":1,"pad":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})");
        uis::SetStatePathForTest(kPath);
        CHECK(uis::Save(Saved(5, 6, 1100.0f, 700.0f)));
        uis::SetStatePathForTest(L"");

        // The old content must be gone entirely (the file was truncated).
        const std::string text = ReadRaw();
        CHECK(text.find("9999") == std::string::npos);
        CHECK(text.find("pad") == std::string::npos);

        uis::SetStatePathForTest(kPath);
        WindowState out;
        CHECK(uis::Load(out));
        CHECK(out.x == 5 && out.y == 6);
        uis::SetStatePathForTest(L"");
        RemoveFile();
    }

    void TestSaveWritesTheVersionAndTheMaximizedFlag() {
        std::error_code ec0;
        std::filesystem::create_directories(kDir, ec0);
        uis::SetStatePathForTest(kPath);
        CHECK(uis::Save(Saved(1, 2, 1200.0f, 800.0f)));
        uis::SetStatePathForTest(L"");
        const std::string text = ReadRaw();
        CHECK(text.find("\"version\"") != std::string::npos);
        CHECK(text.find("\"maximized\"") != std::string::npos);
        // The file ends with exactly one newline (a text editor must not see
        // "no newline at end of file").
        CHECK(!text.empty() && text.back() == '\n');
        RemoveFile();
    }

    void TestSaveRoundTripsMaximized() {
        uis::SetStatePathForTest(kPath);
        WindowState saved = Saved(7, 8, 1300.0f, 900.0f);
        saved.maximized = true;
        CHECK(uis::Save(saved));
        WindowState out;
        CHECK(uis::Load(out));
        CHECK(out.valid);
        CHECK(out.maximized);
        CHECK(out.x == 7 && out.y == 8);
        uis::SetStatePathForTest(L"");
        RemoveFile();
    }

    // ===================== StateFilePath ===================================

    void TestStatePathOverrideWinsAndEmptyRestoresTheDefault() {
        uis::SetStatePathForTest(L"F:\\custom\\path.json");
        CHECK(uis::StateFilePath() == L"F:\\custom\\path.json");
        uis::SetStatePathForTest(L"");
        const std::wstring fallback = uis::StateFilePath();
        // Without an override the path must still be a real path ending in the
        // state file name (LOCALAPPDATA or the exe directory).
        CHECK(fallback.empty() ||
              fallback.find(L"ui_state.json") != std::wstring::npos);
    }

}  // namespace

int main() {
    TestRestoreRejectsInvalidSaved();
    TestRestoreRejectsSizeBelowTheDesignMinimum();
    TestRestoreMinimumIsScaledTogetherWithTheSize();
    TestRestoreTreatsNonPositiveScaleAsOne();
    TestRestoreClampsToTheWorkAreaItLandsOn();
    TestRestoreRejectsWhenTheWorkAreaCannotHoldTheMinimum();
    TestRestoreReDerivesTheLogicalSizeFromTheClampedPixels();
    TestRestoreKeepsAPositionWithAUsableTitleStrip();
    TestRestoreRejectsAStripNarrowerThan64px();
    TestRestoreRejectsAStripShorterThan24px();
    TestRestoreCentresOnAPrimaryWithANonZeroOrigin();
    TestRestoreCarriesTheMaximizedFlag();
    TestRestoreContainsIsHalfOpenInBothAxes();
    TestRestoreTitleStripThresholdsAreInclusive();

    TestLoadRejectsAnUnopenablePath();
    TestLoadRejectsAnEmptyFile();
    TestLoadRejectsNonObjectJson();
    TestLoadRejectsADiscardedDocument();
    TestLoadRejectsAFutureVersion();
    TestLoadAcceptsAMissingVersion();
    TestLoadRejectsANonIntegerVersion();
    TestLoadRejectsNonIntegerCoordinates();
    TestLoadRejectsNonNumericSize();
    TestLoadRejectsANonPositiveSize();
    TestLoadRejectsNonFiniteSize();
    TestLoadMaximizedDefaultsToFalseAndIgnoresNonBoolean();

    TestSaveRejectsAnInvalidState();
    TestSaveCreatesTheParentDirectory();
    TestEnsureParentDirectorySkipsAPathWithNoDirectoryPart();
    TestSaveOverwritesRatherThanAppends();
    TestSaveWritesTheVersionAndTheMaximizedFlag();
    TestSaveRoundTripsMaximized();

    TestStatePathOverrideWinsAndEmptyRestoresTheDefault();

    if (0 == g_failures) {
        std::puts("test_ui_state: ALL PASS");
        return 0;
    }
    std::fprintf(stderr, "test_ui_state: %d FAILURES\n", g_failures);
    return 1;
}
