// ============================================================================
// main.h - VGWW entry point helpers (test seam).
// ============================================================================
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace vgww {

    /// Entry-mode flags parsed from the command line (S4.4 Task 11).
    struct StartupOptions {
        bool ui = true;         ///< native UI (default on)
        bool web = false;       ///< --web: force the HTTP server ON
        bool no_web = false;    ///< --no-web: force it OFF (beats --web/config)
        bool web_only = false;  ///< HTTP only: no data plane, no driver
        bool headless = false;  ///< no UI: console stats loop
        bool minimized = false; ///< UI starts hidden in the tray
        bool console = false;   ///< force a console window
        std::string ui_page;    ///< S5.20: --ui-page=<id> (empty = default home)
        uint16_t ui_debug_port = 0;  ///< --ui-debug-port=<n>: CDP debug channel
    };

    /// Pure flag table (testable): default (no flags) = UI only, web off.
    /// --headless / --web-only win over --minimized (the UI is off); --no-web
    /// is a redundant no-op that still force-disables the web server.
    StartupOptions ParseStartupOptions(
        const std::vector<std::string>& args) noexcept;

    /// True when this launch must bypass the single-instance gate. Only a
    /// headless run has no window to activate, so only it may coexist with
    /// another instance (--headless, and --web-only which implies headless).
    /// A GUI launch - including --ui-debug-port / --ui-page / --minimized -
    /// must always participate, so a second visible app cannot start.
    bool BypassesSingleInstanceGate(
        const std::vector<std::string>& args) noexcept;

    /// Returns true when `id` is one of the 9 pages registered by
    /// RegisterAllPages. Keep in sync with src/ui/pages/*.cpp id() literals
    /// (cross-layer double source; drift risk accepted, see audit R3).
    bool IsKnownUiPage(const std::string& id) noexcept;

    /// Returns the full --help usage text. Exposed for test_main to verify
    /// that the entry flags are documented; the string is the single source
    /// of truth for the console help output. --console stays functional but
    /// intentionally undocumented (compact help); removed --no-deelevate stays
    /// absent.
    std::string PrintUsageString();

    /// Writes PrintUsageString() to stderr.
    void PrintUsage() noexcept;

}  // namespace vgww
