// ============================================================================
// test_ndisrd_client.cpp - batch254: the pure adapter-matching layer of
// ndisrd_client.cpp had almost no direct coverage. test_web pins a handful of
// MatchAdapterEntry cases; everything else was free to change:
//   * WidenAdapterHint        - ZERO direct callers in tests
//   * RefreshAdapterStates    - ZERO direct callers in tests
//   * NormalizeAdapterName / SplitAdapterSuffix / AliasCanonical are in an
//     anonymous namespace, so they are pinned here indirectly through
//     FriendlyNameMatches (their only consumer).
//
// The kernel-facing half (DeviceIoControl, OID requests, ReadPackets) needs a
// live ndisrd driver and stays out of ctest; see tests/test_ndisrd_live.cpp.
// Everything below is deterministic and host-independent.
// ============================================================================
#include <winsock2.h>
#include <ws2tcpip.h>
#include <ws2ipdef.h>
#include <windows.h>

#include "driver/ndisrd_client.h"

#include <cstdio>
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

    using vgww::driver::AdapterEntry;
    using vgww::driver::FormatAdapterTable;
    using vgww::driver::FriendlyNameMatches;
    using vgww::driver::MatchAdapterEntry;
    using vgww::driver::RefreshAdapterStates;
    using vgww::driver::WidenAdapterHint;

    AdapterEntry MakeEntry(const wchar_t* name, const wchar_t* friendly,
                           void* handle) {
        AdapterEntry e;
        e.name = name;
        e.friendly_name = friendly ? friendly : L"";
        e.handle = handle;
        e.mtu = 1500;
        return e;
    }

    // --- WidenAdapterHint ---------------------------------------------------

    void TestWidenEmptyIsEmpty() {
        CHECK(WidenAdapterHint("").empty());
    }

    void TestWidenAsciiPassesThrough() {
        const std::wstring w = WidenAdapterHint("NIC 1");
        CHECK(w == L"NIC 1");
    }

    void TestWidenUtf8TriedBeforeAcp() {
        // UTF-8 bytes for U+4EE5 U+592A U+7F51. Decoding them with CP_ACP
        // (936 here) would yield different characters, so an exact match
        // proves CP_UTF8 wins the race regardless of the host code page.
        const char utf8[] = "\xE4\xBB\xA5\xE5\xA4\xAA\xE7\xBD\x91";
        const std::wstring w = WidenAdapterHint(std::string(utf8, 9));
        CHECK(w == L"\u4EE5\u592A\u7F51");
        CHECK(w.size() == 3);
    }

    void TestWidenAsciiIsByteIdenticalAcrossPaths() {
        // The UTF-8 branch must be taken for pure ASCII too (it never fails
        // there); a byte-wise fallback would produce the same value, so this
        // pins the observable result rather than the branch.
        for (const char* s : {"", "a", "Ethernet 2", "\\DEVICE\\{ABC}"}) {
            const std::string in(s);
            const std::wstring w = WidenAdapterHint(in);
            CHECK(w.size() == in.size());
            for (size_t i = 0; i < w.size(); ++i) {
                CHECK(w[i] == static_cast<wchar_t>(static_cast<unsigned char>(in[i])));
            }
        }
    }

    void TestWidenUndecodableBytesAreNeverDropped() {
        // 0x80 alone is not valid UTF-8 (lone continuation byte), so the
        // UTF-8 attempt must fail and the result must still be non-empty:
        // G-5 F1 says a hint is never dropped.
        const std::wstring w = WidenAdapterHint(std::string(1, '\x80'));
        CHECK(!w.empty());
        CHECK(w.size() <= 1);
    }

    // --- FriendlyNameMatches (pins Normalize/Split/AliasCanonical) ----------

    void TestFriendlyRejectsEmptyEitherSide() {
        CHECK(!FriendlyNameMatches(L"", L"Ethernet"));
        CHECK(!FriendlyNameMatches(L"Ethernet", L""));
        CHECK(!FriendlyNameMatches(L"", L""));
        // Whitespace-only normalizes to empty on both sides.
        CHECK(!FriendlyNameMatches(L"   ", L"Ethernet"));
        CHECK(!FriendlyNameMatches(L"Ethernet", L"\t\t"));
    }

    void TestFriendlyExactMatchNeedsNoAlias() {
        CHECK(FriendlyNameMatches(L"Wi-Fi", L"Wi-Fi"));
        CHECK(FriendlyNameMatches(L"NIC 1", L"NIC 1"));
    }

    void TestFriendlyAsciiCaseFolding() {
        CHECK(FriendlyNameMatches(L"ethernet", L"Ethernet"));
        CHECK(FriendlyNameMatches(L"ETHERNET", L"ethernet"));
        CHECK(FriendlyNameMatches(L"Wi-Fi", L"WI-FI"));
        CHECK(FriendlyNameMatches(L"NIC 1", L"nic 1"));
    }

    void TestFriendlyTrimsOuterWhitespace() {
        CHECK(FriendlyNameMatches(L"  Ethernet", L"Ethernet"));
        CHECK(FriendlyNameMatches(L"Ethernet\t", L"Ethernet"));
        CHECK(FriendlyNameMatches(L"\t Ethernet \t", L"Ethernet"));
        CHECK(FriendlyNameMatches(L"Wi-Fi", L"  Wi-Fi  "));
    }

    void TestFriendlyCollapsesInnerWhitespaceRuns() {
        CHECK(FriendlyNameMatches(L"NIC   1", L"NIC 1"));
        CHECK(FriendlyNameMatches(L"NIC\t\t1", L"NIC 1"));
        CHECK(FriendlyNameMatches(L"NIC \t 1", L"NIC 1"));
    }

    void TestFriendlyAliasAllFourLocalizedForms() {
        const wchar_t* aliases[] = {
            L"Ethernet",
            L"\u4EE5\u592A\u7F51",                        // zh-CN
            L"\u4E59\u592A\u7DB2\u8DEF",                  // zh-TW
            L"\u30A4\u30FC\u30B5\u30CD\u30C3\u30C8",      // ja-JP
            L"\uC774\uB354\uB137",                        // ko-KR
        };
        for (const wchar_t* a : aliases) {
            for (const wchar_t* b : aliases) {
                CHECK(FriendlyNameMatches(a, b));
            }
        }
    }

    void TestFriendlyAliasCarriesTheInstanceSuffix() {
        CHECK(FriendlyNameMatches(L"Ethernet 2", L"\u4EE5\u592A\u7F51 2"));
        CHECK(FriendlyNameMatches(L"ETHERNET 2", L"\u4EE5\u592A\u7F51 2"));
        CHECK(FriendlyNameMatches(L"\u4EE5\u592A\u7F51 7", L"Ethernet 7"));
    }

    void TestFriendlySuffixIsStrict() {
        // Missing on one side.
        CHECK(!FriendlyNameMatches(L"Ethernet", L"\u4EE5\u592A\u7F51 2"));
        CHECK(!FriendlyNameMatches(L"Ethernet 2", L"\u4EE5\u592A\u7F51"));
        // Different numbers.
        CHECK(!FriendlyNameMatches(L"Ethernet 2", L"\u4EE5\u592A\u7F51 3"));
        // No separating space.
        CHECK(!FriendlyNameMatches(L"\u4EE5\u592A\u7F512", L"Ethernet 2"));
        // Leading zeros are significant (D4: no leading-zero normalization).
        CHECK(!FriendlyNameMatches(L"\u4EE5\u592A\u7F51 02", L"Ethernet 2"));
        CHECK(FriendlyNameMatches(L"Ethernet 02", L"\u4EE5\u592A\u7F51 02"));
        // Full-width digits are not ASCII digits.
        CHECK(!FriendlyNameMatches(L"Ethernet \uFF12", L"Ethernet 2"));
    }

    void TestFriendlySuffixRequiresASeparatingSpace() {
        // SplitAdapterSuffix only recognises a suffix preceded by exactly one
        // space. Without that guard "Ethernet2" splits into ("Ethernet","2")
        // and would alias-match "Ethernet 2".
        CHECK(!FriendlyNameMatches(L"Ethernet2", L"Ethernet 2"));
        CHECK(!FriendlyNameMatches(L"Ethernet 2", L"Ethernet2"));
        CHECK(!FriendlyNameMatches(L"\u4EE5\u592A\u7F512", L"\u4EE5\u592A\u7F51 2"));
        CHECK(FriendlyNameMatches(L"Ethernet 2", L"Ethernet 2"));

        // Minimal distinguisher for the "must be preceded by ONE space" rule.
        // A non-space character before the digits must not be consumed as if it
        // were the separator, otherwise "EthernetA2" would split into
        // ("Ethernet","2") and alias-match "Ethernet 2".
        CHECK(!FriendlyNameMatches(L"EthernetA2", L"Ethernet 2"));
        CHECK(!FriendlyNameMatches(L"Ethernet 2", L"EthernetA2"));
        CHECK(!FriendlyNameMatches(L"\u4EE5\u592A\u7F51X3", L"Ethernet 3"));
        CHECK(FriendlyNameMatches(L"Ethernet A2", L"Ethernet a2"));
    }

    void TestFriendlySuffixAppliesToPlainNamesToo() {
        CHECK(!FriendlyNameMatches(L"NIC 1", L"NIC 2"));
        CHECK(FriendlyNameMatches(L"NIC 1", L"nic 1"));
        CHECK(!FriendlyNameMatches(L"NIC", L"NIC 1"));
    }

    void TestFriendlyNeverSubstrings() {
        // The vEthernet trap: a hyphenated switch name contains "Ethernet".
        CHECK(!FriendlyNameMatches(L"Ethernet", L"vEthernet (Default Switch)"));
        CHECK(!FriendlyNameMatches(L"vEthernet", L"vEthernet (Default Switch)"));
        CHECK(!FriendlyNameMatches(L"Wi-Fi", L"Wi-Fi 2"));
    }

    void TestFriendlyNonAliasBasesNeverMatch() {
        CHECK(!FriendlyNameMatches(L"Wi-Fi", L"\u4EE5\u592A\u7F51"));
        CHECK(!FriendlyNameMatches(L"Wi-Fi 2", L"\u4EE5\u592A\u7F51 2"));
        CHECK(!FriendlyNameMatches(L"Loopback", L"Ethernet"));
    }

    void TestFriendlyDigitOnlyBaseDoesNotAlias() {
        // " 2" splits to base "" + suffix "2": the empty base has no alias,
        // so the alias layer must reject rather than compare two nullptrs.
        CHECK(!FriendlyNameMatches(L" 2", L"Ethernet 2"));
        CHECK(!FriendlyNameMatches(L"2", L"Ethernet 2"));
    }

    // --- MatchAdapterEntry: device-path layer -------------------------------

    void TestMatchEmptyHintPicksFirstEvenWhenAmbiguous() {
        std::vector<AdapterEntry> ents;
        ents.push_back(MakeEntry(L"\\DEVICE\\{AAAA}", L"Ethernet",
                                 reinterpret_cast<void*>(1)));
        ents.push_back(MakeEntry(L"\\DEVICE\\{BBBB}", L"Ethernet",
                                 reinterpret_cast<void*>(2)));
        bool amb = true;
        CHECK(MatchAdapterEntry(ents, L"", L"", &amb) == 0);
        CHECK(!amb);
    }

    void TestMatchEmptyHintHitsEvenAnEmptyDeviceName() {
        // contains() short-circuits on an empty hint. Running std::search with
        // an empty needle over an EMPTY haystack returns last == end(), i.e.
        // "no match", which would turn an empty-hint lookup into -1.
        std::vector<AdapterEntry> ents;
        ents.push_back(MakeEntry(L"", L"n", reinterpret_cast<void*>(
                                          static_cast<intptr_t>(1))));
        bool amb = true;
        CHECK(MatchAdapterEntry(ents, L"", L"", &amb) == 0);
        CHECK(!amb);
    }

    void TestMatchEmptyHintWithNoAdapters() {
        std::vector<AdapterEntry> ents;
        bool amb = true;
        CHECK(MatchAdapterEntry(ents, L"", L"", &amb) == -1);
        CHECK(!amb);
    }

    void TestMatchDeviceLayerIsCaseInsensitiveSubstring() {
        std::vector<AdapterEntry> ents;
        ents.push_back(MakeEntry(L"\\DEVICE\\{AAAAAAAA-BBBB}", L"one",
                                 reinterpret_cast<void*>(1)));
        ents.push_back(MakeEntry(L"\\DEVICE\\{11111111-2222}", L"two",
                                 reinterpret_cast<void*>(2)));
        bool amb = false;
        CHECK(MatchAdapterEntry(ents, L"aaaaaaaA-bbbB", L"", &amb) == 0);
        CHECK(!amb);
        CHECK(MatchAdapterEntry(ents, L"11111111", L"", &amb) == 1);
        CHECK(MatchAdapterEntry(ents, L"no-such-thing", L"", &amb) == -1);
        CHECK(!amb);
    }

    void TestMatchDeviceLayerOutranksFriendlyLayer() {
        // Entry 0 matches on the device path; entry 1 matches only on the
        // friendly name. The device layer is checked first and must decide.
        std::vector<AdapterEntry> ents;
        ents.push_back(MakeEntry(L"\\DEVICE\\{TARGET-GUID}", L"unrelated",
                                 reinterpret_cast<void*>(1)));
        ents.push_back(MakeEntry(L"\\DEVICE\\{OTHER}", L"TARGET",
                                 reinterpret_cast<void*>(2)));
        bool amb = false;
        CHECK(MatchAdapterEntry(ents, L"target-guid", L"", &amb) == 0);
        CHECK(!amb);
    }

    void TestMatchAmbiguousDeviceLayerFlagsTie() {
        std::vector<AdapterEntry> ents;
        ents.push_back(MakeEntry(L"\\DEVICE\\{AAAA}", L"a",
                                 reinterpret_cast<void*>(1)));
        ents.push_back(MakeEntry(L"\\DEVICE\\{AAAB}", L"b",
                                 reinterpret_cast<void*>(2)));
        bool amb = false;
        CHECK(MatchAdapterEntry(ents, L"AAA", L"", &amb) == 0);
        CHECK(amb);
    }

    // --- MatchAdapterEntry: pick_layer connected preference ------------------

    void TestMatchSingleConnectedHitWinsWithoutAmbiguity() {
        // The USB/Ethernet trap: two NICs share a friendly name, one unplugged.
        std::vector<AdapterEntry> ents;
        AdapterEntry down =
            MakeEntry(L"\\DEVICE\\{AAAA}", L"Ethernet", reinterpret_cast<void*>(1));
        down.is_up = false;
        down.media_connected = false;
        ents.push_back(down);
        AdapterEntry up =
            MakeEntry(L"\\DEVICE\\{BBBB}", L"Ethernet", reinterpret_cast<void*>(2));
        up.is_up = true;
        up.media_connected = true;
        ents.push_back(up);

        bool amb = true;
        CHECK(MatchAdapterEntry(ents, L"Ethernet", L"", &amb) == 1);
        CHECK(!amb);
    }

    void TestMatchTwoConnectedHitsStayAmbiguous() {
        std::vector<AdapterEntry> ents;
        for (int i = 0; i < 2; ++i) {
            AdapterEntry e = MakeEntry(i == 0 ? L"\\DEVICE\\{AAAA}"
                                              : L"\\DEVICE\\{BBBB}",
                                       L"Ethernet",
                                       reinterpret_cast<void*>(
                                           static_cast<intptr_t>(i + 1)));
            e.is_up = true;
            e.media_connected = true;
            ents.push_back(e);
        }
        bool amb = false;
        CHECK(MatchAdapterEntry(ents, L"Ethernet", L"", &amb) == 0);
        CHECK(amb);
    }

    void TestMatchTieAmongDisconnectedEntriesIsAmbiguous() {
        // Both NICs share the friendly name but neither is connected, so the
        // connected-preference cannot break the tie: the caller must be told
        // the choice is ambiguous (D5) instead of silently binding one.
        std::vector<AdapterEntry> ents;
        for (int i = 0; i < 2; ++i) {
            AdapterEntry e = MakeEntry(i == 0 ? L"\\DEVICE\\{AAAA}"
                                              : L"\\DEVICE\\{BBBB}",
                                       L"Ethernet",
                                       reinterpret_cast<void*>(
                                           static_cast<intptr_t>(i + 1)));
            e.is_up = false;
            e.media_connected = false;
            ents.push_back(e);
        }
        bool amb = false;
        CHECK(MatchAdapterEntry(ents, L"Ethernet", L"", &amb) == 0);
        CHECK(amb);

        // A single disconnected match is not ambiguous.
        ents.pop_back();
        amb = true;
        CHECK(MatchAdapterEntry(ents, L"Ethernet", L"", &amb) == 0);
        CHECK(!amb);
    }

    void TestMatchRequiresBothUpAndMediaConnectedToCount() {
        // is_up alone is not "connected": the media-connect flag must also hold.
        std::vector<AdapterEntry> ents;
        AdapterEntry a =
            MakeEntry(L"\\DEVICE\\{AAAA}", L"Ethernet", reinterpret_cast<void*>(1));
        a.is_up = true;
        a.media_connected = false;
        ents.push_back(a);
        AdapterEntry b =
            MakeEntry(L"\\DEVICE\\{BBBB}", L"Ethernet", reinterpret_cast<void*>(2));
        b.is_up = true;
        b.media_connected = true;
        ents.push_back(b);
        bool amb = false;
        CHECK(MatchAdapterEntry(ents, L"Ethernet", L"", &amb) == 1);
        CHECK(!amb);

        // media_connected alone is not enough: a link-down NIC reports the
        // media state of its last association, so is_up must also hold.
        {
            std::vector<AdapterEntry> e2;
            AdapterEntry x = MakeEntry(L"\\DEVICE\\{AAAA}", L"Ethernet",
                                       reinterpret_cast<void*>(
                                           static_cast<intptr_t>(1)));
            x.is_up = false;
            x.media_connected = true;
            e2.push_back(x);
            AdapterEntry y = MakeEntry(L"\\DEVICE\\{BBBB}", L"Ethernet",
                                       reinterpret_cast<void*>(
                                           static_cast<intptr_t>(2)));
            y.is_up = true;
            y.media_connected = true;
            e2.push_back(y);
            bool a2 = true;
            CHECK(MatchAdapterEntry(e2, L"Ethernet", L"", &a2) == 1);
            CHECK(!a2);
        }

        // Symmetric control: only the second one is media-connected.
        ents[0].media_connected = true;
        ents[1].media_connected = false;
        CHECK(MatchAdapterEntry(ents, L"Ethernet", L"", &amb) == 0);
        CHECK(!amb);
    }

    // --- MatchAdapterEntry: friendly layers + precedence --------------------

    void TestMatchFriendlyLayersAreRawThenNormalizedThenAlias() {
        std::vector<AdapterEntry> ents;
        // 0: alias-only hit.
        ents.push_back(MakeEntry(L"\\DEVICE\\{A}", L"\u4EE5\u592A\u7F51",
                                 reinterpret_cast<void*>(1)));
        // 1: normalized hit (same normalized text, different raw text).
        ents.push_back(MakeEntry(L"\\DEVICE\\{B}", L"  ETHERNET  ",
                                 reinterpret_cast<void*>(2)));
        // 2: raw exact hit.
        ents.push_back(MakeEntry(L"\\DEVICE\\{C}", L"Ethernet",
                                 reinterpret_cast<void*>(3)));
        bool amb = true;
        CHECK(MatchAdapterEntry(ents, L"Ethernet", L"", &amb) == 2);
        CHECK(!amb);
    }

    void TestMatchNormalizedLayerBeatsAliasLayer() {
        std::vector<AdapterEntry> ents;
        ents.push_back(MakeEntry(L"\\DEVICE\\{A}", L"\u4EE5\u592A\u7F51",
                                 reinterpret_cast<void*>(1)));
        ents.push_back(MakeEntry(L"\\DEVICE\\{B}", L"ETHERNET ",
                                 reinterpret_cast<void*>(2)));
        bool amb = true;
        CHECK(MatchAdapterEntry(ents, L"ethernet", L"", &amb) == 1);
        CHECK(!amb);
    }

    void TestMatchAliasLayerUsedWhenNothingElseHits() {
        std::vector<AdapterEntry> ents;
        ents.push_back(MakeEntry(L"\\DEVICE\\{A}", L"\u4EE5\u592A\u7F51 2",
                                 reinterpret_cast<void*>(1)));
        bool amb = true;
        CHECK(MatchAdapterEntry(ents, L"Ethernet 2", L"", &amb) == 0);
        CHECK(!amb);
    }

    void TestMatchSkipsEntriesWithoutFriendlyName() {
        std::vector<AdapterEntry> ents;
        ents.push_back(MakeEntry(L"\\DEVICE\\{A}", L"", reinterpret_cast<void*>(1)));
        ents.push_back(MakeEntry(L"\\DEVICE\\{B}", L"Ethernet",
                                 reinterpret_cast<void*>(2)));
        bool amb = false;
        CHECK(MatchAdapterEntry(ents, L"Ethernet", L"", &amb) == 1);
        CHECK(!amb);
    }

    // --- MatchAdapterEntry: resolved GUID fallback --------------------------

    void TestMatchResolvedFallbackComparesGuidSuffixCaseInsensitively() {
        std::vector<AdapterEntry> ents;
        ents.push_back(MakeEntry(L"\\DEVICE\\{AAAAAAAA-BBBB}",
                                 L"some friendly name",
                                 reinterpret_cast<void*>(1)));
        ents.push_back(MakeEntry(L"\\DEVICE\\{CCCCCCCC-DDDD}",
                                 L"another name",
                                 reinterpret_cast<void*>(2)));
        bool amb = true;
        // \DEVICE\ prefix present on one side only.
        CHECK(MatchAdapterEntry(ents, L"not-a-device-path",
                                L"\\DEVICE\\{cccccccc-dddd}", &amb) == 1);
        CHECK(!amb);
        // No prefix on the resolved side either.
        amb = true;
        CHECK(MatchAdapterEntry(ents, L"not-a-device-path",
                                L"{CCCCCCCC-DDDD}", &amb) == 1);
        CHECK(!amb);
    }

    void TestMatchResolvedFallbackMissesReturnsMinusOne() {
        std::vector<AdapterEntry> ents;
        ents.push_back(MakeEntry(L"\\DEVICE\\{AAAA}", L"name",
                                 reinterpret_cast<void*>(1)));
        bool amb = true;
        CHECK(MatchAdapterEntry(ents, L"nope", L"\\DEVICE\\{ZZZZ}", &amb) == -1);
        CHECK(!amb);
    }

    void TestMatchNullAmbiguousPointerIsSafeOnEveryPath() {
        std::vector<AdapterEntry> ents;
        ents.push_back(MakeEntry(L"\\DEVICE\\{AAAA}", L"Ethernet",
                                 reinterpret_cast<void*>(1)));
        // device layer hit
        CHECK(MatchAdapterEntry(ents, L"AAAA", L"", nullptr) == 0);
        // empty hint
        CHECK(MatchAdapterEntry(ents, L"", L"", nullptr) == 0);
        // friendly layer hit
        CHECK(MatchAdapterEntry(ents, L"ethernet", L"", nullptr) == 0);
        // resolved fallback
        CHECK(MatchAdapterEntry(ents, L"zzz", L"\\DEVICE\\{AAAA}", nullptr) == 0);
        // total miss
        CHECK(MatchAdapterEntry(ents, L"zzz", L"", nullptr) == -1);
        // no adapters at all
        std::vector<AdapterEntry> none;
        CHECK(MatchAdapterEntry(none, L"", L"", nullptr) == -1);
        CHECK(MatchAdapterEntry(none, L"x", L"", nullptr) == -1);
    }

    // --- FormatAdapterTable -------------------------------------------------

    void TestFormatAdapterTableUsesFriendlyNamesWhenPresent() {
        std::vector<AdapterEntry> ents;
        ents.push_back(MakeEntry(L"\\DEVICE\\{AAAAAAAA-BBBB-CCCC}",
                                 L"unused", reinterpret_cast<void*>(1)));
        const std::vector<std::wstring> friendly{L"NIC 1"};
        const std::string t = FormatAdapterTable(ents, friendly);
        CHECK(t.find("NIC 1 => {AAAAAAAA-BBBB-CCCC}\n") != std::string::npos);
        // The raw \DEVICE\ prefix must not survive on the right-hand side.
        CHECK(t.find("\\DEVICE") == std::string::npos);
    }

    void TestFormatAdapterTableFallsBackToDeviceNameWhenFriendlyIsShort() {
        std::vector<AdapterEntry> ents;
        ents.push_back(MakeEntry(L"\\DEVICE\\{AAAA}", L"", reinterpret_cast<void*>(1)));
        ents.push_back(MakeEntry(L"\\DEVICE\\{BBBB}", L"", reinterpret_cast<void*>(2)));
        // Only the first adapter has a friendly name.
        const std::vector<std::wstring> friendly{L"first"};
        const std::string t = FormatAdapterTable(ents, friendly);
        CHECK(t.find("first => {AAAA}\n") != std::string::npos);
        // Adapter 1 falls back to its whole device path as the label.
        CHECK(t.find("\\DEVICE\\{BBBB} => {BBBB}\n") != std::string::npos);
    }

    void TestFormatAdapterTableKeepsLinesWithEmptyLabels() {
        std::vector<AdapterEntry> ents;
        ents.push_back(MakeEntry(L"", L"", reinterpret_cast<void*>(
                                         static_cast<intptr_t>(1))));
        const std::string t = FormatAdapterTable(ents, {});
        // One line per adapter, even when both sides are empty.
        CHECK(t == " => \n");
    }

    void TestFormatAdapterTableEmptyInputIsEmpty() {
        const std::string t = FormatAdapterTable({}, {});
        CHECK(t.empty());
    }

    void TestFormatAdapterTableOneLinePerAdapter() {
        std::vector<AdapterEntry> ents;
        for (int i = 0; i < 3; ++i) {
            ents.push_back(MakeEntry(i == 0   ? L"\\DEVICE\\{A}"
                                     : i == 1 ? L"\\DEVICE\\{B}"
                                              : L"\\DEVICE\\{C}",
                                     L"",
                                     reinterpret_cast<void*>(
                                         static_cast<intptr_t>(i + 1))));
        }
        const std::string t = FormatAdapterTable(ents, {});
        size_t lines = 0;
        for (char c : t) {
            if (c == '\n') ++lines;
        }
        CHECK(lines == 3);
    }

    // --- RefreshAdapterStates ----------------------------------------------

    void TestRefreshAdapterStatesEmptyVectorIsNoop() {
        std::vector<AdapterEntry> none;
        RefreshAdapterStates(none);
        CHECK(none.empty());
    }

    void TestRefreshAdapterStatesLeavesUnmatchedEntriesUntouched() {
        // Fail-open contract: a name GetAdaptersAddresses cannot possibly
        // report (a synthetic GUID) must keep every field exactly as set, so
        // an injected/fake adapter is never clobbered.
        std::vector<AdapterEntry> ents;
        AdapterEntry e = MakeEntry(L"\\DEVICE\\{00000000-0000-0000-0000-000000000000}",
                                   L"preset name", reinterpret_cast<void*>(7));
        e.is_up = false;
        e.media_connected = false;
        e.if_type = 12345;
        e.ipv4.push_back({0x0100007Fu, 24});
        e.ipv6.push_back("::1");
        ents.push_back(e);

        RefreshAdapterStates(ents);

        CHECK(ents.size() == 1);
        CHECK(ents[0].name == e.name);
        CHECK(ents[0].friendly_name == L"preset name");
        CHECK(ents[0].handle == e.handle);
        CHECK(ents[0].is_up == false);
        CHECK(ents[0].media_connected == false);
        CHECK(ents[0].if_type == 12345u);
        CHECK(ents[0].ipv4.size() == 1);
        CHECK(ents[0].ipv4[0].address == 0x0100007Fu);
        CHECK(ents[0].ipv4[0].prefix_len == 24);
        CHECK(ents[0].ipv6.size() == 1);
        CHECK(ents[0].ipv6[0] == "::1");
    }

    void TestRefreshAdapterStatesIsIdempotentForUnmatchedEntries() {
        std::vector<AdapterEntry> ents;
        ents.push_back(MakeEntry(
            L"\\DEVICE\\{11111111-1111-1111-1111-111111111111}", L"keep",
            reinterpret_cast<void*>(3)));
        RefreshAdapterStates(ents);
        const AdapterEntry first = ents[0];
        RefreshAdapterStates(ents);
        CHECK(ents[0].friendly_name == first.friendly_name);
        CHECK(ents[0].is_up == first.is_up);
        CHECK(ents[0].media_connected == first.media_connected);
        CHECK(ents[0].if_type == first.if_type);
        CHECK(ents[0].ipv4.size() == first.ipv4.size());
        CHECK(ents[0].ipv6.size() == first.ipv6.size());
    }

}  // namespace

int main() {
    TestWidenEmptyIsEmpty();
    TestWidenAsciiPassesThrough();
    TestWidenUtf8TriedBeforeAcp();
    TestWidenAsciiIsByteIdenticalAcrossPaths();
    TestWidenUndecodableBytesAreNeverDropped();

    TestFriendlyRejectsEmptyEitherSide();
    TestFriendlyExactMatchNeedsNoAlias();
    TestFriendlyAsciiCaseFolding();
    TestFriendlyTrimsOuterWhitespace();
    TestFriendlyCollapsesInnerWhitespaceRuns();
    TestFriendlyAliasAllFourLocalizedForms();
    TestFriendlyAliasCarriesTheInstanceSuffix();
    TestFriendlySuffixIsStrict();
    TestFriendlySuffixRequiresASeparatingSpace();
    TestFriendlySuffixAppliesToPlainNamesToo();
    TestFriendlyNeverSubstrings();
    TestFriendlyNonAliasBasesNeverMatch();
    TestFriendlyDigitOnlyBaseDoesNotAlias();

    TestMatchEmptyHintPicksFirstEvenWhenAmbiguous();
    TestMatchEmptyHintWithNoAdapters();
    TestMatchEmptyHintHitsEvenAnEmptyDeviceName();
    TestMatchDeviceLayerIsCaseInsensitiveSubstring();
    TestMatchDeviceLayerOutranksFriendlyLayer();
    TestMatchAmbiguousDeviceLayerFlagsTie();
    TestMatchSingleConnectedHitWinsWithoutAmbiguity();
    TestMatchTwoConnectedHitsStayAmbiguous();
    TestMatchRequiresBothUpAndMediaConnectedToCount();
    TestMatchTieAmongDisconnectedEntriesIsAmbiguous();
    TestMatchFriendlyLayersAreRawThenNormalizedThenAlias();
    TestMatchNormalizedLayerBeatsAliasLayer();
    TestMatchAliasLayerUsedWhenNothingElseHits();
    TestMatchSkipsEntriesWithoutFriendlyName();
    TestMatchResolvedFallbackComparesGuidSuffixCaseInsensitively();
    TestMatchResolvedFallbackMissesReturnsMinusOne();
    TestMatchNullAmbiguousPointerIsSafeOnEveryPath();

    TestFormatAdapterTableUsesFriendlyNamesWhenPresent();
    TestFormatAdapterTableFallsBackToDeviceNameWhenFriendlyIsShort();
    TestFormatAdapterTableEmptyInputIsEmpty();
    TestFormatAdapterTableKeepsLinesWithEmptyLabels();
    TestFormatAdapterTableOneLinePerAdapter();

    TestRefreshAdapterStatesEmptyVectorIsNoop();
    TestRefreshAdapterStatesLeavesUnmatchedEntriesUntouched();
    TestRefreshAdapterStatesIsIdempotentForUnmatchedEntries();

    if (0 == g_failures) {
        std::puts("test_ndisrd_client: ALL PASS");
        return 0;
    }
    std::fprintf(stderr, "test_ndisrd_client: %d FAILURES\n", g_failures);
    return 1;
}
