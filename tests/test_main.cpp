// ============================================================================
// test_main.cpp - StartupOptions table-driven tests (S4.4 Task 11) plus help
// text assertions: the entry flags are documented, removed flags are not.
// ============================================================================
#include <algorithm>
#include <cstdio>
#include <initializer_list>
#include <string>
#include <vector>

#include "core/config.h"
#include "main.h"

int g_failures = 0;

#define TEST(suite, name) void suite##_##name()

#define EXPECT_TRUE(cond)                                                     \
    do {                                                                      \
        if (!(cond)) {                                                        \
            std::fprintf(stderr, "EXPECT_TRUE failed at %s:%d: %s\n",         \
                         __FILE__, __LINE__, #cond);                          \
            ++g_failures;                                                     \
        }                                                                     \
    } while (0)

namespace {

    std::vector<std::string> Args(std::initializer_list<const char*> flags) {
        std::vector<std::string> out;
        for (const char* flag : flags) {
            out.push_back(flag);
        }
        return out;
    }

}  // namespace

// --- StartupOptions table (8 combinations) -------------------------------

TEST(MainStartup, DefaultIsUiOnly) {
    const vgww::StartupOptions o = vgww::ParseStartupOptions({});
    EXPECT_TRUE(o.ui);
    EXPECT_TRUE(!o.web && !o.web_only && !o.headless && !o.minimized &&
                !o.console);
}

TEST(MainStartup, WebEnablesWebKeepsUi) {
    const vgww::StartupOptions o = vgww::ParseStartupOptions(Args({"--web"}));
    EXPECT_TRUE(o.web && o.ui && !o.headless);
}

TEST(MainStartup, HeadlessDisablesUi) {
    const vgww::StartupOptions o = vgww::ParseStartupOptions(Args({"--headless"}));
    EXPECT_TRUE(o.headless && !o.ui && !o.web);
}

TEST(MainStartup, MinimizedKeepsUi) {
    const vgww::StartupOptions o = vgww::ParseStartupOptions(Args({"--minimized"}));
    EXPECT_TRUE(o.minimized && o.ui);
}

TEST(MainStartup, MinimizedAndHeadlessHeadlessWins) {
    const vgww::StartupOptions o =
        vgww::ParseStartupOptions(Args({"--minimized", "--headless"}));
    // Both flags set: headless wins, the UI is off.
    EXPECT_TRUE(o.minimized && o.headless && !o.ui);
}

TEST(MainStartup, WebOnly) {
    const vgww::StartupOptions o = vgww::ParseStartupOptions(Args({"--web-only"}));
    EXPECT_TRUE(o.web_only && o.web && !o.ui && o.headless);
}

// P87: the single-instance gate has exactly one bypass - a headless run owns
// no window to activate. The old local literal scan only matched "--headless",
// so a --web-only WebUI beside the normal launch was refused as a second
// instance and never started. The predicate must now be testable and must
// cover --web-only (implied headless) while still gating the visible-window
// flags (--ui-debug-port / --ui-page / --minimized), which batch37h removed
// from the bypass set.
TEST(MainStartup, GateBypassIsHeadlessOnly) {
    EXPECT_TRUE(vgww::BypassesSingleInstanceGate({"--headless"}));
    EXPECT_TRUE(vgww::BypassesSingleInstanceGate({"--web-only"}));
    EXPECT_TRUE(vgww::BypassesSingleInstanceGate(
        {"--config=x.json", "--web-only"}));
    // A GUI launch is gated - even with the debug/test flags.
    EXPECT_TRUE(!vgww::BypassesSingleInstanceGate({}));
    EXPECT_TRUE(!vgww::BypassesSingleInstanceGate({"--config=x.json"}));
    EXPECT_TRUE(!vgww::BypassesSingleInstanceGate({"--minimized"}));
    EXPECT_TRUE(!vgww::BypassesSingleInstanceGate({"--ui-page=dashboard"}));
    EXPECT_TRUE(!vgww::BypassesSingleInstanceGate({"--ui-debug-port=19777"}));
}

TEST(MainStartup, NoWebOverridesTheConfigDefault) {
    // web.enabled defaults to true, so --no-web is what turns the server off.
    const vgww::StartupOptions o = vgww::ParseStartupOptions(Args({"--no-web"}));
    EXPECT_TRUE(!o.web && o.ui && o.no_web && !o.web_only);
}

TEST(MainStartup, WebThenNoWebOff) {
    const vgww::StartupOptions o =
        vgww::ParseStartupOptions(Args({"--web", "--no-web"}));
    EXPECT_TRUE(!o.web && o.ui);
}

TEST(MainStartup, ConsoleFlagDocumentedBehavior) {
    const vgww::StartupOptions o = vgww::ParseStartupOptions(Args({"--console"}));
    EXPECT_TRUE(o.console && o.ui);
}

// --- S5.20 --ui-page -----------------------------------------------------

TEST(MainStartup, UiPageParsesValue) {
    const vgww::StartupOptions o =
        vgww::ParseStartupOptions(Args({"--ui-page=leases"}));
    EXPECT_TRUE(o.ui_page == "leases");
}

TEST(MainStartup, UiPageEmptyValueIgnored) {
    // "--ui-page=" with an empty value: ignored, returns an empty string
    // (the default start page is used).
    const vgww::StartupOptions o =
        vgww::ParseStartupOptions(Args({"--ui-page="}));
    EXPECT_TRUE(o.ui_page.empty());
}

TEST(MainStartup, UiPageBareFlagNoValueIgnored) {
    // "--ui-page" (no '='): does not match key=value, ignored.
    const vgww::StartupOptions o =
        vgww::ParseStartupOptions(Args({"--ui-page"}));
    EXPECT_TRUE(o.ui_page.empty());
}

TEST(MainStartup, UiPageAbsentByDefault) {
    EXPECT_TRUE(vgww::ParseStartupOptions({}).ui_page.empty());
}

TEST(MainStartup, UiPageCoexistsWithOtherFlags) {
    // Combined with --headless/--minimized: ui_page is still parsed and the
    // existing fields are unaffected.
    const vgww::StartupOptions o = vgww::ParseStartupOptions(
        Args({"--headless", "--minimized", "--ui-page=bridge"}));
    EXPECT_TRUE(o.headless && o.minimized && !o.ui);
    EXPECT_TRUE(o.ui_page == "bridge");
}

TEST(MainStartup, UiPageAfterOtherFlags) {
    // May appear at any position; flags other than ui_page do not rewrite its
    // value.
    const vgww::StartupOptions o = vgww::ParseStartupOptions(
        Args({"--web", "--ui-page=settings", "--minimized"}));
    EXPECT_TRUE(o.web && o.minimized);
    EXPECT_TRUE(o.ui_page == "settings");
}

// --- batch245: parser edges the table above never probed ------------------

TEST(MainStartup, UiPageOnlyMatchesAsAPrefix) {
    // --ui-page= must be a PREFIX of the argument. A token that merely
    // CONTAINS it is not this flag (it would otherwise be silently accepted
    // as "page=bar" after the substr offset lands mid-string).
    EXPECT_TRUE(vgww::ParseStartupOptions(Args({"--x--ui-page=bar"}))
                    .ui_page.empty());
    EXPECT_TRUE(vgww::ParseStartupOptions(Args({"--ui-pagex=bar"}))
                    .ui_page.empty());
}

TEST(MainStartup, UiPageTrimsTrailingWhitespace) {
    // Both ends are trimmed. Without the trailing pass the value keeps its
    // spaces and then fails the IsKnownUiPage whitelist in main, so the
    // start page silently degrades to home.
    EXPECT_TRUE(vgww::ParseStartupOptions(Args({"--ui-page=leases "}))
                    .ui_page == "leases");
    EXPECT_TRUE(vgww::ParseStartupOptions(Args({"--ui-page= leases"}))
                    .ui_page == "leases");
    EXPECT_TRUE(vgww::ParseStartupOptions(Args({"--ui-page=  bridge  "}))
                    .ui_page == "bridge");
    // All-whitespace degrades to empty (default home), not to a blank page.
    EXPECT_TRUE(vgww::ParseStartupOptions(Args({"--ui-page=   "}))
                    .ui_page.empty());
}

TEST(MainStartup, UiPageLastNonEmptyWins) {
    // Repeated flags: the LAST accepted value wins (the usual CLI rule), and
    // an empty later value does not erase an earlier real one.
    EXPECT_TRUE(vgww::ParseStartupOptions(
                    Args({"--ui-page=bridge", "--ui-page=settings"}))
                    .ui_page == "settings");
    EXPECT_TRUE(vgww::ParseStartupOptions(
                    Args({"--ui-page=bridge", "--ui-page=  "}))
                    .ui_page == "bridge");
}

TEST(MainStartup, UiDebugPortLastValueWins) {
    // Same last-wins rule as --ui-page; a rejected later value must not
    // clear an earlier working port.
    EXPECT_TRUE(vgww::ParseStartupOptions(Args({"--ui-debug-port=9123",
                                             "--ui-debug-port=8080"}))
                    .ui_debug_port == 8080);
    EXPECT_TRUE(vgww::ParseStartupOptions(Args({"--ui-debug-port=9123",
                                             "--ui-debug-port=abc"}))
                    .ui_debug_port == 9123);
}

TEST(MainStartup, IsKnownUiPageRejectsPrefixes) {
    // The whitelist is an exact match set: a single leading character must
    // not be enough (that would let --ui-page=d through the guard).
    EXPECT_TRUE(!vgww::IsKnownUiPage("d"));
    EXPECT_TRUE(!vgww::IsKnownUiPage("c"));
    EXPECT_TRUE(!vgww::IsKnownUiPage("s"));
    EXPECT_TRUE(!vgww::IsKnownUiPage("dashboar"));
    EXPECT_TRUE(!vgww::IsKnownUiPage("dashboards"));
}

// --- Task 7 --ui-debug-port ----------------------------------------------

TEST(MainStartup, UiDebugPortParsesValue) {
    const vgww::StartupOptions o =
        vgww::ParseStartupOptions(Args({"--ui-debug-port=9123"}));
    EXPECT_TRUE(o.ui_debug_port == 9123);
}

TEST(MainStartup, UiDebugPortAbsentByDefault) {
    EXPECT_TRUE(vgww::ParseStartupOptions({}).ui_debug_port == 0);
}

TEST(MainStartup, UiDebugPortInvalidValueOff) {
    // Non-numeric: returns 0 (disabled); does not throw and does not affect
    // the other fields.
    const vgww::StartupOptions o =
        vgww::ParseStartupOptions(Args({"--ui-debug-port=abc"}));
    EXPECT_TRUE(o.ui_debug_port == 0);
    EXPECT_TRUE(o.ui);
}

TEST(MainStartup, UiDebugPortOutOfRangeOff) {
    // 0 / 65536 / negative out of range: returns 0 (disabled).
    EXPECT_TRUE(vgww::ParseStartupOptions(Args({"--ui-debug-port=0"}))
                    .ui_debug_port == 0);
    EXPECT_TRUE(vgww::ParseStartupOptions(Args({"--ui-debug-port=65536"}))
                    .ui_debug_port == 0);
    EXPECT_TRUE(vgww::ParseStartupOptions(Args({"--ui-debug-port=-1"}))
                    .ui_debug_port == 0);
}

// batch107: --ui-debug-port used std::stol(), which parses a PREFIX and
// ignores the rest, so a malformed value silently became a working port.
//
//   try { const long port = std::stol(value);
//         if (port > 0 && port <= 65535) options.ui_debug_port = port; }
//   catch (...) { /* leave 0 */ }
//
// Measured on this toolchain: "9123abc" -> 9123 (consumed 4), "9123.5" -> 9123,
// "0x10" -> 0. The catch block only fires for a value with NO digits at all or
// for overflow, so "../9123", "9123 extra" and "9123.5" all ENABLED the debug
// channel at a port the operator never typed. That channel exposes the whole
// UI tree and input injection over loopback, so "the flag was rejected" and
// "the flag was silently truncated" must not be the same outcome.
//
// This is the same class batch85 fixed for Content-Length: a strto*/stol
// call whose endptr is not checked treats partial parsing as success.
//
// Asserted: a value with trailing garbage leaves the channel OFF, and clean
// values still work (no over-tightening).
static void TestB107DebugPortRejectsPartialNumericValue() {
    const auto port_of = [](const char* value) {
        return vgww::ParseStartupOptions(
                   Args({(std::string("--ui-debug-port=") + value).c_str()}))
            .ui_debug_port;
    };

    // Positive controls: clean decimal values still enable the channel.
    EXPECT_TRUE(port_of("9123") == 9123);
    EXPECT_TRUE(port_of("1") == 1);
    EXPECT_TRUE(port_of("65535") == 65535);
    EXPECT_TRUE(port_of(" 9123 ") == 9123);   // surrounding OWS stays tolerated

    // Trailing garbage must NOT be truncated into a port.
    EXPECT_TRUE(port_of("9123abc") == 0);
    EXPECT_TRUE(port_of("9123.5") == 0);
    EXPECT_TRUE(port_of("9123 456") == 0);
    EXPECT_TRUE(port_of("9123extra") == 0);
    // A non-decimal prefix produced 0 before, i.e. it LOOKED rejected while the
    // parse had actually stopped immediately; keep it off either way.
    EXPECT_TRUE(port_of("0x10") == 0);
    // Leading '+' was accepted by stol; a plain decimal spelling is what the
    // documentation promises, so an explicit sign is not a port.
    EXPECT_TRUE(port_of("+9123") == 0);
}

// --- S5.20 IsKnownUiPage whitelist ---------------------------------------

TEST(MainStartup, IsKnownUiPageAcceptsAllNine) {
    EXPECT_TRUE(vgww::IsKnownUiPage("dashboard"));
    EXPECT_TRUE(vgww::IsKnownUiPage("firewall"));
    EXPECT_TRUE(vgww::IsKnownUiPage("portmap"));
    EXPECT_TRUE(vgww::IsKnownUiPage("ratelimit"));
    EXPECT_TRUE(vgww::IsKnownUiPage("settings"));
    EXPECT_TRUE(vgww::IsKnownUiPage("bridge"));
    EXPECT_TRUE(vgww::IsKnownUiPage("leases"));
    EXPECT_TRUE(vgww::IsKnownUiPage("about"));
    // Batch19 R3-2: the ninth page (captured stdout/stderr).
    EXPECT_TRUE(vgww::IsKnownUiPage("console"));
}

TEST(MainStartup, IsKnownUiPageRejectsUnknownAndEmpty) {
    EXPECT_TRUE(!vgww::IsKnownUiPage("unknown"));
    EXPECT_TRUE(!vgww::IsKnownUiPage(""));
    EXPECT_TRUE(!vgww::IsKnownUiPage("dashboard "));
    EXPECT_TRUE(!vgww::IsKnownUiPage("Dashboard"));
}

// --- help text -----------------------------------------------------------

TEST(MainHelp, ListsEveryEntryFlag) {
    const std::string help = vgww::PrintUsageString();
    EXPECT_TRUE(help.find("--web") != std::string::npos);
    EXPECT_TRUE(help.find("--web-only") != std::string::npos);
    EXPECT_TRUE(help.find("--headless") != std::string::npos);
    EXPECT_TRUE(help.find("--minimized") != std::string::npos);
    EXPECT_TRUE(help.find("--no-web") != std::string::npos);
    EXPECT_TRUE(help.find("--install-driver") != std::string::npos);
    EXPECT_TRUE(help.find("--uninstall-driver") != std::string::npos);
    EXPECT_TRUE(help.find("--grant-access-only") != std::string::npos);
    EXPECT_TRUE(help.find("--ui-page") != std::string::npos);
    EXPECT_TRUE(help.find("--ui-debug-port") != std::string::npos);
    // Batch19 R3-2 / audit F6: the --ui-page value list must name all nine
    // pages, console included (the unknown-value error message in main.cpp is
    // kept in the same order; this guards the shared page set).
    EXPECT_TRUE(help.find("bridge/leases/about/console") != std::string::npos);
}

TEST(MainHelp, StatesTheWebUiDefaultAndPrecedence) {
    // The help text must not contradict WebConfig::enabled (true) or the
    // --no-web > --web precedence rule in WebEnabledEffective.
    const std::string help = vgww::PrintUsageString();
    EXPECT_TRUE(help.find("on by default") != std::string::npos);
    EXPECT_TRUE(help.find("no-op") == std::string::npos);
    EXPECT_TRUE(help.find("default: off") == std::string::npos);
}

TEST(MainHelp, OmitsRemovedFlags) {
    const std::string help = vgww::PrintUsageString();
    // Removed/deleted flags must stay absent.
    EXPECT_TRUE(std::string::npos == help.find("--no-deelevate"));
    // --console stays functional but undocumented (compact top level).
    EXPECT_TRUE(std::string::npos == help.find("--console"));
}

// --- Batch 14: CLI flag parity across usage / Parse / whitelist ----------
//
// Regression net for the two historical drift incidents (--ui-debug-port,
// 2026-10-09; --headless, 2026-10-15). Every entry flag must stay consistent
// across the usage text (PrintUsageString), ParseStartupOptions and the
// Config::ApplyCliOverrides whitelist. The early_exit column records which
// flags main handles before the config load, so their whitelist exclusions
// (--install-driver/--uninstall-driver) cannot be mistaken for drift, while
// --version/--help stay locked as the intentional defensive superset.

namespace {

    struct CliFlagRow {
        const char* flag;                              // canonical usage token
        std::vector<std::string> probe;                // args for Parse/whitelist
        bool in_usage;                                 // expected: listed by usage?
        bool (*consumed)(const vgww::StartupOptions&); // expected Parse effect (null = none)
        bool early_exit;                               // main exits before config load
        bool whitelisted;                              // expected: ApplyCliOverrides accepts?
    };

    const CliFlagRow kCliFlagRows[] = {
        {"config",           {"--config=vgww.json"},    true,  nullptr,                                     false, true},
        {"adapter",          {"--adapter=Ethernet"},    true,  nullptr,                                     false, true},
        {"web",              {"--web"},                 true,  [](const vgww::StartupOptions& o) { return o.web; },                   false, true},
        {"web-only",         {"--web-only"},            true,  [](const vgww::StartupOptions& o) { return o.web_only && o.headless && !o.ui; }, false, true},
        {"headless",         {"--headless"},            true,  [](const vgww::StartupOptions& o) { return o.headless && !o.ui; },     false, true},
        {"minimized",        {"--minimized"},           true,  [](const vgww::StartupOptions& o) { return o.minimized; },            false, true},
        // --no-web needs the two-arg probe: with the server on by default a
        // lone --no-web only restates the parser's default, so the probe pairs
        // it with --web to prove the "off wins" rule.
        {"no-web",           {"--web", "--no-web"},     true,  [](const vgww::StartupOptions& o) { return !o.web; },                 false, true},
        {"ui-page",          {"--ui-page=dashboard"},   true,  [](const vgww::StartupOptions& o) { return o.ui_page == "dashboard"; }, false, true},
        {"ui-debug-port",    {"--ui-debug-port=9123"},  true,  [](const vgww::StartupOptions& o) { return o.ui_debug_port == 9123; }, false, true},
        // --console stays functional but undocumented (see the MainHelp lock).
        {"console",          {"--console"},             false, [](const vgww::StartupOptions& o) { return o.console; },             false, true},
        {"install-driver",   {"--install-driver"},      true,  nullptr,                                     true,  false},
        {"uninstall-driver", {"--uninstall-driver"},    true,  nullptr,                                     true,  false},
        {"grant-access-only",{"--grant-access-only"},   true,  nullptr,                                     true,  false},
        {"version",          {"--version"},             true,  nullptr,                                     true,  true},
        {"help",             {"--help"},                true,  nullptr,                                     true,  true},
    };

}  // namespace

TEST(MainParity, TestCliFlagThreeLayerParity) {
    const vgww::StartupOptions defaults{};
    const auto same_as_default = [&](const vgww::StartupOptions& o) {
        return o.ui == defaults.ui && o.web == defaults.web &&
               o.web_only == defaults.web_only &&
               o.headless == defaults.headless &&
               o.minimized == defaults.minimized &&
               o.console == defaults.console &&
               o.ui_page == defaults.ui_page &&
               o.ui_debug_port == defaults.ui_debug_port;
    };

    // (1) usage bidirectional token scan over the RUNTIME string only.
    // Scanning the source file would mis-capture "--last;" (the decrement
    // operators in startup_options.cpp), so PrintUsageString() is the source.
    const std::string usage = vgww::PrintUsageString();
    std::vector<std::string> tokens;
    for (size_t i = 0; i + 2 <= usage.size(); ++i) {
        if (usage[i] != '-' || usage[i + 1] != '-') {
            continue;
        }
        size_t j = i + 2;
        while (j < usage.size() &&
               ((usage[j] >= 'a' && usage[j] <= 'z') || usage[j] == '-')) {
            ++j;
        }
        if (j > i + 2) {
            tokens.push_back(usage.substr(i, j - i));
            i = j - 1;
        }
    }
    std::string usage_mismatch;
    for (const CliFlagRow& row : kCliFlagRows) {
        const std::string token = std::string("--") + row.flag;
        const bool seen =
            std::find(tokens.begin(), tokens.end(), token) != tokens.end();
        if (row.in_usage && !seen) {
            usage_mismatch += "  usage is missing: " + token + "\n";
        }
        if (!row.in_usage && seen) {
            usage_mismatch += "  usage unexpectedly lists: " + token + "\n";
        }
    }
    for (const std::string& token : tokens) {
        bool known = false;
        for (const CliFlagRow& row : kCliFlagRows) {
            if (token == std::string("--") + row.flag) {
                known = true;
                break;
            }
        }
        if (!known) {
            usage_mismatch += "  usage token not in table: " + token + "\n";
        }
    }
    if (!usage_mismatch.empty()) {
        std::fprintf(stderr, "cli parity: usage text vs table:\n%s",
                     usage_mismatch.c_str());
    }
    EXPECT_TRUE(usage_mismatch.empty());

    // (2) Parse per-row probe: consumed rows must show their effect; the
    // rest must leave every field at the default.
    for (const CliFlagRow& row : kCliFlagRows) {
        const vgww::StartupOptions parsed =
            vgww::ParseStartupOptions(row.probe);
        if (row.consumed != nullptr) {
            EXPECT_TRUE(row.consumed(parsed));
        } else {
            EXPECT_TRUE(same_as_default(parsed));
        }
    }

    // (3) whitelist per-row probe: acceptance must match the table; a
    // rejection must come with a non-empty error (no silent swallow).
    for (const CliFlagRow& row : kCliFlagRows) {
        vgww::core::Config config;
        std::string error;
        const bool ok = config.ApplyCliOverrides(row.probe, error);
        if (ok != row.whitelisted) {
            std::fprintf(stderr,
                         "cli parity: --%s whitelist ok=%d expected=%d (%s)\n",
                         row.flag, ok ? 1 : 0, row.whitelisted ? 1 : 0,
                         error.c_str());
        }
        EXPECT_TRUE(ok == row.whitelisted);
        if (row.whitelisted) {
            EXPECT_TRUE(error.empty());
        } else {
            EXPECT_TRUE(!error.empty());
        }
        if (std::string(row.flag) == "adapter") {
            EXPECT_TRUE(config.adapter == "Ethernet");
        }
    }

    // (4) machine invariants: the mechanism nets for the two drifts.
    for (const CliFlagRow& row : kCliFlagRows) {
        // I-b: any flag Parse consumes must be whitelisted unless main exits
        // before the config path.
        if (row.consumed != nullptr && !row.early_exit) {
            EXPECT_TRUE(row.whitelisted);
        }
        // Early-exit flags must stay documented (the tooth behind the
        // usage/docs requirement).
        if (row.early_exit) {
            EXPECT_TRUE(row.in_usage);
        }
        // I-c: the only hidden + reachable + whitelisted flag is --console.
        if (!row.in_usage && row.whitelisted && !row.early_exit) {
            EXPECT_TRUE(std::string(row.flag) == "console");
        }
    }

    // (5) combination: every reachable flag together must be accepted by the
    // whitelist (full combination semantics live in the MainStartup tests
    // and test_config.cpp; this locks the all-flags-together surface).
    std::vector<std::string> combined;
    for (const CliFlagRow& row : kCliFlagRows) {
        if (!row.early_exit) {
            combined.insert(combined.end(), row.probe.begin(),
                            row.probe.end());
        }
    }
    vgww::core::Config combined_config;
    std::string combined_error;
    const bool combined_ok =
        combined_config.ApplyCliOverrides(combined, combined_error);
    if (!combined_ok) {
        std::fprintf(stderr, "cli parity: combined flags rejected: %s\n",
                     combined_error.c_str());
    }
    EXPECT_TRUE(combined_ok);
    EXPECT_TRUE(combined_error.empty());
    EXPECT_TRUE(combined_config.adapter == "Ethernet");
}

// --- --config path resolution (single authoritative parse) ---------------
//
// A "--config" carrying no value used to leave the path empty, which the boot
// code read as "not given" and answered with the auto-discovery chain: the
// explicit-but-broken flag silently ran on a DIFFERENT config file. The parse
// must therefore distinguish "absent" from "present but unusable".

TEST(MainConfigPath, EqualsFormTakesTheSuffix) {
    const vgww::ConfigPathResult r =
        vgww::ParseConfigPathArg({"--config=x.json"});
    EXPECT_TRUE(r.status == vgww::ConfigPathStatus::kOk);
    EXPECT_TRUE(r.path == "x.json");
    EXPECT_TRUE(r.error.empty());
}

TEST(MainConfigPath, SeparateArgumentFormTakesTheValue) {
    const vgww::ConfigPathResult r =
        vgww::ParseConfigPathArg({"--config", "x.json"});
    EXPECT_TRUE(r.status == vgww::ConfigPathStatus::kOk);
    EXPECT_TRUE(r.path == "x.json");
    EXPECT_TRUE(r.error.empty());
}

TEST(MainConfigPath, LoneFlagIsInvalid) {
    const vgww::ConfigPathResult r = vgww::ParseConfigPathArg({"--config"});
    EXPECT_TRUE(r.status == vgww::ConfigPathStatus::kInvalid);
    EXPECT_TRUE(!r.error.empty());
}

TEST(MainConfigPath, EmptyEqualsValueIsInvalid) {
    const vgww::ConfigPathResult r = vgww::ParseConfigPathArg({"--config="});
    EXPECT_TRUE(r.status == vgww::ConfigPathStatus::kInvalid);
    EXPECT_TRUE(!r.error.empty());
}

TEST(MainConfigPath, FlagFollowedByAnotherFlagIsInvalid) {
    const vgww::ConfigPathResult r =
        vgww::ParseConfigPathArg({"--config", "--web"});
    EXPECT_TRUE(r.status == vgww::ConfigPathStatus::kInvalid);
    EXPECT_TRUE(!r.error.empty());
}

TEST(MainConfigPath, AbsentFlagIsNotGiven) {
    const vgww::ConfigPathResult web = vgww::ParseConfigPathArg({"--web"});
    EXPECT_TRUE(web.status == vgww::ConfigPathStatus::kNotGiven);
    EXPECT_TRUE(web.path.empty());
    EXPECT_TRUE(web.error.empty());

    const vgww::ConfigPathResult none = vgww::ParseConfigPathArg({});
    EXPECT_TRUE(none.status == vgww::ConfigPathStatus::kNotGiven);
    EXPECT_TRUE(none.path.empty());
    EXPECT_TRUE(none.error.empty());
}

TEST(MainConfigPath, LastOccurrenceWins) {
    // Last-occurrence-wins is the semantics the old "=" loop already had (a
    // later assignment overwrote an earlier one), so it is kept instead of
    // inventing a "first error fails" rule the previous code never applied.
    const vgww::ConfigPathResult r =
        vgww::ParseConfigPathArg({"--config=", "--config=y.json"});
    EXPECT_TRUE(r.status == vgww::ConfigPathStatus::kOk);
    EXPECT_TRUE(r.path == "y.json");
    EXPECT_TRUE(r.error.empty());
}

TEST(MainConfigPath, ConsumedFormsAgreeWithTheWhitelist) {
    // Every --config form the authoritative parse accepts must also be
    // consumed by the post-load whitelist; otherwise the path reaches the
    // whitelist as an unknown argument (the two rules must agree). The
    // whitelist deliberately never validates the value - main has already
    // rejected the unusable forms before the config is loaded.
    const std::vector<std::vector<std::string>> accepted = {
        {"--config=x.json"},
        {"--config", "x.json"},
        {"--config=", "--config=y.json"},
    };
    for (const std::vector<std::string>& args : accepted) {
        EXPECT_TRUE(vgww::ParseConfigPathArg(args).status ==
                    vgww::ConfigPathStatus::kOk);
        vgww::core::Config config;
        std::string error;
        const bool ok = config.ApplyCliOverrides(args, error);
        if (!ok) {
            std::fprintf(stderr, "cli config: whitelist rejected a form the "
                                 "parse accepts (%s)\n", error.c_str());
        }
        EXPECT_TRUE(ok);
        EXPECT_TRUE(error.empty());
    }
}

int main() {
    MainStartup_DefaultIsUiOnly();
    MainStartup_WebEnablesWebKeepsUi();
    MainStartup_HeadlessDisablesUi();
    MainStartup_MinimizedKeepsUi();
    MainStartup_MinimizedAndHeadlessHeadlessWins();
    MainStartup_WebOnly();
    MainStartup_GateBypassIsHeadlessOnly();
    MainStartup_NoWebOverridesTheConfigDefault();
    MainStartup_WebThenNoWebOff();
    MainStartup_ConsoleFlagDocumentedBehavior();
    MainStartup_UiPageParsesValue();
    MainStartup_UiPageEmptyValueIgnored();
    MainStartup_UiPageBareFlagNoValueIgnored();
    MainStartup_UiPageAbsentByDefault();
    MainStartup_UiPageCoexistsWithOtherFlags();
    MainStartup_UiPageAfterOtherFlags();
    MainStartup_UiPageOnlyMatchesAsAPrefix();
    MainStartup_UiPageTrimsTrailingWhitespace();
    MainStartup_UiPageLastNonEmptyWins();
    MainStartup_UiDebugPortLastValueWins();
    MainStartup_IsKnownUiPageRejectsPrefixes();
    MainStartup_UiDebugPortParsesValue();
    MainStartup_UiDebugPortAbsentByDefault();
    MainStartup_UiDebugPortInvalidValueOff();
    MainStartup_UiDebugPortOutOfRangeOff();
    TestB107DebugPortRejectsPartialNumericValue();
    MainStartup_IsKnownUiPageAcceptsAllNine();
    MainStartup_IsKnownUiPageRejectsUnknownAndEmpty();
    MainHelp_ListsEveryEntryFlag();
    MainHelp_OmitsRemovedFlags();
    MainHelp_StatesTheWebUiDefaultAndPrecedence();
    MainParity_TestCliFlagThreeLayerParity();

    MainConfigPath_EqualsFormTakesTheSuffix();
    MainConfigPath_SeparateArgumentFormTakesTheValue();
    MainConfigPath_LoneFlagIsInvalid();
    MainConfigPath_EmptyEqualsValueIsInvalid();
    MainConfigPath_FlagFollowedByAnotherFlagIsInvalid();
    MainConfigPath_AbsentFlagIsNotGiven();
    MainConfigPath_LastOccurrenceWins();
    MainConfigPath_ConsumedFormsAgreeWithTheWhitelist();
    if (0 == g_failures) {
        std::puts("test_main: ALL PASS");
        return 0;
    }

    std::fprintf(stderr, "test_main: %d FAILURES\n", g_failures);
    return 1;
}
