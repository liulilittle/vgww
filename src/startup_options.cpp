// ============================================================================
// startup_options.cpp - out-of-line definitions for the main.h entry seam
// (ParseStartupOptions / IsKnownUiPage / PrintUsageString / PrintUsage).
//
// Moved out of main.h (S6 implementation migration): the header keeps
// declarations only, and the definitions live in vgww_core. test_main links
// vgww_core (not the exe TU that owns main.cpp), so the definitions must be
// reachable from a core translation unit.
// ============================================================================
#include "main.h"

#include <cctype>
#include <cstdio>
#include <stdexcept>

namespace vgww {

    StartupOptions ParseStartupOptions(
        const std::vector<std::string>& args) noexcept {
        const auto has = [&](const char* flag) {
            for (const std::string& arg : args) {
                if (arg == flag) {
                    return true;
                }
            }
            return false;
        };
        StartupOptions options;
        options.web_only = has("--web-only");
        // --web-only behaves headless: no UI, console-stats process.
        options.headless = has("--headless") || options.web_only;
        options.minimized = has("--minimized");
        options.console = has("--console");
        options.no_web = has("--no-web");
        options.web = (has("--web") || options.web_only) && !options.no_web;
        options.ui = !(options.headless || options.web_only);
        // S5.20: --ui-page=<id> - take the value after the prefix, trim
        // surrounding whitespace and ignore empty results (default home page).
        // Whitelist validation happens at the consumer (main.cpp), not here.
        static constexpr char kUiPageEq[] = "--ui-page=";
        for (const std::string& arg : args) {
            if (arg.rfind(kUiPageEq, 0) != 0) {
                continue;
            }
            std::string value = arg.substr(sizeof(kUiPageEq) - 1);
            std::size_t first = 0;
            while (first < value.size() &&
                   std::isspace(static_cast<unsigned char>(value[first])) != 0) {
                ++first;
            }
            std::size_t last = value.size();
            while (last > first &&
                   std::isspace(static_cast<unsigned char>(value[last - 1])) != 0) {
                --last;
            }
            value = value.substr(first, last - first);
            if (!value.empty()) {
                options.ui_page = value;
            }
        }
        // Task 7: --ui-debug-port=<n> - parse decimal port; trimmed; a
        // non-numeric or out-of-range value leaves 0 (channel off). The
        // channel binds 127.0.0.1 only, so no host argument is needed.
        static constexpr char kUiDebugPortEq[] = "--ui-debug-port=";
        for (const std::string& arg : args) {
            if (arg.rfind(kUiDebugPortEq, 0) != 0) {
                continue;
            }
            std::string value = arg.substr(sizeof(kUiDebugPortEq) - 1);
            std::size_t first = 0;
            while (first < value.size() &&
                   std::isspace(static_cast<unsigned char>(value[first])) != 0) {
                ++first;
            }
            std::size_t last = value.size();
            while (last > first &&
                   std::isspace(static_cast<unsigned char>(value[last - 1])) != 0) {
                --last;
            }
            value = value.substr(first, last - first);
            if (value.empty()) {
                continue;
            }
            try {
                // batch107: std::stol() parses a PREFIX and ignores the rest,
                // so "9123abc" returned 9123 and ENABLED the debug channel on
                // a port the operator never typed ("9123.5" -> 9123,
                // "9123 456" -> 9123). That channel exposes the whole UI tree
                // plus input injection over loopback, so "the flag was
                // rejected" and "the flag was silently truncated" must not be
                // the same outcome. This is the endptr discipline batch85
                // applied to Content-Length, expressed as a lexical check: the
                // whole (already trimmed) value must be ASCII digits, which
                // also rules out an explicit '+'/'-' sign stol would accept.
                // (A separate `consumed == value.size()` test would be pure
                // redundancy here - digits-only strings are consumed whole -
                // and mutation showed it cannot be falsified independently.)
                const bool all_digits =
                    !value.empty() &&
                    value.find_first_not_of("0123456789") ==
                        std::string::npos;
                if (!all_digits) {
                    continue;
                }
                const long port = std::stol(value);
                if (port > 0 && port <= 65535) {
                    options.ui_debug_port = static_cast<uint16_t>(port);
                }
            } catch (const std::exception&) {
                // invalid value -> leave 0 (off)
            }
        }
        return options;
    }

    bool IsKnownUiPage(const std::string& id) noexcept {
        static constexpr const char* kUiPages[] = {
            "dashboard", "firewall", "portmap", "ratelimit",
            "settings", "bridge", "leases", "about", "console",
        };
        for (const char* page : kUiPages) {
            if (id == page) {
                return true;
            }
        }
        return false;
    }

    std::string PrintUsageString() {
        return
            "VGWW - Virtual Gateway for Windows v0.1.0\n"
            "Usage:\n"
            "  vgww.exe --config=vgww.json [--adapter=<name>] [--web] [--web-only]\n"
            "                              [--headless] [--minimized] [--no-web]\n"
            "                              [--ui-page=<id>]\n"
            "                              [--ui-debug-port=<n>]\n"
            "                              [--install-driver] [--uninstall-driver]\n"
            "                              [--grant-access-only]\n"
            "                              [--version] [--help]\n"
            "Options:\n"
            "  --config=<path>   Config file (required; falls back to config.json next to the exe)\n"
            "  --adapter=<name>  Override adapter name\n"
            "  --web             Force the HTTP management UI on (overrides web.enabled)\n"
            "  --web-only        Run the HTTP management UI only (no data plane, no driver)\n"
            "  --headless        Run without the native UI (console stats loop)\n"
            "  --minimized       Start the native UI hidden to the tray\n"
            "  --no-web          Disable the HTTP management UI (overrides web.enabled and --web; the server is on by default)\n"
            "  --ui-page=<id>    Start on the given UI page (dashboard/firewall/portmap/ratelimit/settings/bridge/leases/about/console)\n"
            "  --ui-debug-port=<n>  Start the CDP-style UI debug channel on 127.0.0.1:<n> (off by default)\n"
            "  --install-driver  Install or re-grant the ndisrd driver (elevated)\n"
            "  --uninstall-driver  Uninstall the ndisrd driver (elevated)\n"
            "  --grant-access-only  Re-grant normal-user access to the ndisrd device (manual recovery; the app also does this in-process at startup)\n"
            "  --version         Show version and exit\n"
            "  --help            Show this help and exit\n";
    }

    void PrintUsage() noexcept {
        const std::string text = PrintUsageString();

        std::fputs(text.c_str(), stderr);
    }

}  // namespace vgww
