// ============================================================================
// test_page_util.cpp - batch247: MakeAdapterLabel / BuildAdapterChoices /
// ShortDeviceLabel / FirstIpv4 / Narrow had ZERO direct coverage. The only
// consumers in test_ui go through the Settings page and the first-run wizard,
// so none of the labelling rules (unique-name fallback, GUID shortening,
// link-state suffix, IPv4 tail, rank ordering) were pinned to a requirement.
//
// A 32-mutation sweep against the untouched implementation killed 0/32: every
// branch below was free to change. This file pins them.
// ============================================================================
#include <cstdio>
#include <string>
#include <vector>

#include "ui/pages/page_util.h"

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

    I18n& Tr() { return I18n::Instance(); }

    std::wstring Up() { return std::wstring(Tr().T(Str::SettingsAdapterLinkUp)); }
    std::wstring Down() { return std::wstring(Tr().T(Str::SettingsAdapterLinkDown)); }
    std::wstring FormAdapter() { return std::wstring(Tr().T(Str::FormAdapter)); }

    // --- Narrow: the ONLY wide->byte pair (batch31 P0-1) --------------------

    void TestNarrowEmptyIsEmpty() {
        CHECK(Narrow(std::wstring()).empty());
    }

    void TestNarrowAsciiRoundTrips() {
        CHECK(Narrow(L"NIC 1") == "NIC 1");
        CHECK(Narrow(L"") == "");
    }

    void TestNarrowUtf8IsMultiByte() {
        // A CJK adapter name must encode as UTF-8 (3 bytes per char), not as a
        // per-byte narrowing (which would give one byte per wchar_t).
        const std::wstring cjk = L"\u7F51\u5361";
        const std::string out = Narrow(cjk);
        CHECK(out.size() == 6);
        CHECK(out == "\xE7\xBD\x91\xE5\x8D\xA1");
        // Round-trip through Widen proves the pair is symmetric.
        CHECK(Widen(out) == cjk);
    }

    void TestNarrowUnpairedSurrogateFallsBack() {
        // WC_ERR_INVALID_CHARS rejects an unpaired surrogate; the documented
        // fallback is the historical per-byte widening (never drop the field).
        std::wstring bad;
        bad.push_back(static_cast<wchar_t>(0xD800));  // lone high surrogate
        const std::string out = Narrow(bad);
        CHECK(out.size() == 1);
        CHECK(static_cast<unsigned char>(out[0]) == 0x00);
    }

    // --- Widen --------------------------------------------------------------

    void TestWidenEmptyAndAscii() {
        CHECK(Widen("").empty());
        CHECK(Widen("Ethernet") == L"Ethernet");
    }

    void TestWidenUtf8() {
        CHECK(Widen("\xE7\xBD\x91\xE5\x8D\xA1") == L"\u7F51\u5361");
    }

    void TestWidenInvalidUtf8FallsBackPerByte() {
        // A lone 0xFF is not valid UTF-8: MB_ERR_INVALID_CHARS makes
        // MultiByteToWideChar fail, and the documented fallback is
        // wstring(text.begin(), text.end()) - one wchar_t per BYTE.
        //
        // MEASURED CONTRACT (not an assumption): MSVC's char is SIGNED, so
        // byte 0xFF becomes -1 and sign-extends to 0xFFFF; byte 0xFE becomes
        // -2 -> 0xFFFE. This is lossy and surprising, but it is what the
        // product has always done and it never DROPS a value.
        const std::string bad = "\xFF\xFE";
        const std::wstring out = Widen(bad);
        CHECK(out.size() == 2);
        CHECK(static_cast<unsigned>(out[0]) == 0xFFFFu);
        CHECK(static_cast<unsigned>(out[1]) == 0xFFFEu);
    }

    // --- ShortDeviceLabel (via MakeAdapterLabel) ----------------------------

    AdapterLabelSource DeviceOnly(const std::wstring& device) {
        AdapterLabelSource s;
        s.device = device;
        return s;
    }

    void TestDeviceLabelUsesGuidPrefix() {
        const AdapterLabel l = MakeAdapterLabel(
            DeviceOnly(L"\\DEVICE\\{8B645B7B-1111-2222-3333-444444444444}"), 0,
            Tr());
        // 8 chars of the GUID, then an ellipsis.
        CHECK(l.label == FormAdapter() + L" 8B645B7B\u2026 \u00B7 " + Down());
        // The VALUE keeps the full device path (saving must not change).
        CHECK(l.value == L"\\DEVICE\\{8B645B7B-1111-2222-3333-444444444444}");
    }

    void TestDeviceLabelShortGuidIsNotTruncated() {
        const AdapterLabel l =
            MakeAdapterLabel(DeviceOnly(L"\\DEVICE\\{ABC}"), 0, Tr());
        CHECK(l.label == FormAdapter() + L" ABC \u00B7 " + Down());
    }

    void TestDeviceLabelEmptyBraceFallsBackToPath() {
        // "{}" has no inner characters, so the GUID rule does not apply; the
        // last path component is used instead.
        const AdapterLabel l =
            MakeAdapterLabel(DeviceOnly(L"\\DEVICE\\{}"), 0, Tr());
        CHECK(l.label == FormAdapter() + L" {} \u00B7 " + Down());
    }

    void TestDeviceLabelPathComponentIsCapped() {
        const AdapterLabel l = MakeAdapterLabel(
            DeviceOnly(L"\\DEVICE\\VERY-LONG-COMPONENT-NAME"), 0, Tr());
        // 12 chars + ellipsis.
        CHECK(l.label == FormAdapter() + L" VERY-LONG-CO\u2026 \u00B7 " + Down());
    }

    void TestDeviceLabelShortPathComponentKept() {
        const AdapterLabel l =
            MakeAdapterLabel(DeviceOnly(L"\\DEVICE\\shortname"), 0, Tr());
        CHECK(l.label == FormAdapter() + L" shortname \u00B7 " + Down());
    }

    void TestDeviceLabelNoSeparatorUsesWholeString() {
        const AdapterLabel l = MakeAdapterLabel(DeviceOnly(L"PLAIN"), 0, Tr());
        CHECK(l.label == FormAdapter() + L" PLAIN \u00B7 " + Down());
    }

    // --- MakeAdapterLabel: unique-name rule ---------------------------------

    AdapterLabelSource Friendly(const std::wstring& name) {
        AdapterLabelSource s;
        s.friendly = name;
        s.device = L"\\DEVICE\\{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}";
        return s;
    }

    void TestUniqueFriendlyNameBecomesValueAndLabel() {
        const AdapterLabel l = MakeAdapterLabel(Friendly(L"NIC 1"), 1, Tr());
        CHECK(l.value == L"NIC 1");            // value is the friendly name
        CHECK(l.label == L"NIC 1 \u00B7 " + Down());  // NOT the device path
    }

    void TestDuplicateFriendlyNameFallsBackToDevice() {
        // friendly_count == 2 means another adapter shares the name.
        const AdapterLabel l = MakeAdapterLabel(Friendly(L"NIC 1"), 2, Tr());
        CHECK(l.value == L"\\DEVICE\\{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}");
        CHECK(l.label == FormAdapter() + L" AAAAAAAA\u2026 \u00B7 " + Down());
    }

    void TestZeroCountWithFriendlyNameIsNotUnique() {
        // friendly_count 0 is the "not seen in the inventory" case; the rule
        // is `<= 1`, so 0 still counts as unique ONLY when paired with a
        // non-empty name. Pin the actual contract: <= 1 is unique.
        const AdapterLabel l = MakeAdapterLabel(Friendly(L"NIC 1"), 0, Tr());
        CHECK(l.value == L"NIC 1");
    }

    void TestEmptyFriendlyNameAlwaysUsesDevice() {
        AdapterLabelSource s;
        s.friendly = L"";
        s.device = L"\\DEVICE\\{AB}";
        const AdapterLabel l = MakeAdapterLabel(s, 1, Tr());
        CHECK(l.value == L"\\DEVICE\\{AB}");
        CHECK(l.label == FormAdapter() + L" AB \u00B7 " + Down());
    }

    // --- MakeAdapterLabel: link state ---------------------------------------

    void TestLinkStateUpAndDown() {
        AdapterLabelSource up = Friendly(L"NIC 1");
        up.connected = true;
        CHECK(MakeAdapterLabel(up, 1, Tr()).label == L"NIC 1 \u00B7 " + Up());

        AdapterLabelSource down = Friendly(L"NIC 1");
        down.connected = false;
        CHECK(MakeAdapterLabel(down, 1, Tr()).label == L"NIC 1 \u00B7 " + Down());
    }

    // --- MakeAdapterLabel: IPv4 tail ----------------------------------------

    void TestIpv4ShownOnlyWhenConnected() {
        AdapterLabelSource up = Friendly(L"NIC 1");
        up.connected = true;
        up.ipv4 = {L"192.168.0.1/24"};
        CHECK(MakeAdapterLabel(up, 1, Tr()).label ==
              L"NIC 1 \u00B7 " + Up() + L" \u00B7 192.168.0.1/24");

        // A disconnected NIC keeps its APIPA in the inventory but the label
        // must not show it (batch29).
        AdapterLabelSource down = Friendly(L"NIC 1");
        down.connected = false;
        down.ipv4 = {L"169.254.5.5/16"};
        CHECK(MakeAdapterLabel(down, 1, Tr()).label == L"NIC 1 \u00B7 " + Down());
    }

    void TestIpv4EmptyAddsNoSeparator() {
        AdapterLabelSource up = Friendly(L"NIC 1");
        up.connected = true;
        up.ipv4.clear();
        CHECK(MakeAdapterLabel(up, 1, Tr()).label == L"NIC 1 \u00B7 " + Up());
    }

    void TestIpv4ExtraAddressesBecomePlusN() {
        AdapterLabelSource up = Friendly(L"NIC 1");
        up.connected = true;
        up.ipv4 = {L"10.0.0.1/24", L"10.0.0.2/24", L"10.0.0.3/24"};
        CHECK(MakeAdapterLabel(up, 1, Tr()).label ==
              L"NIC 1 \u00B7 " + Up() + L" \u00B7 10.0.0.1/24 +2");
    }

    void TestIpv4SingleAddressHasNoPlusSuffix() {
        AdapterLabelSource up = Friendly(L"NIC 1");
        up.connected = true;
        up.ipv4 = {L"10.0.0.1/24"};
        CHECK(MakeAdapterLabel(up, 1, Tr()).label ==
              L"NIC 1 \u00B7 " + Up() + L" \u00B7 10.0.0.1/24");
    }

    // --- BuildAdapterChoices ------------------------------------------------

    vgww::runtime::Dataplane::AdapterInfo MakeInfo(const char* friendly,
                                                   const char* device, bool up,
                                                   bool media,
                                                   const char* ip = nullptr,
                                                   uint8_t prefix = 24) {
        vgww::runtime::Dataplane::AdapterInfo info;
        info.friendly_name = friendly;
        info.device = device;
        info.is_up = up;
        info.media_connected = media;
        if (ip != nullptr) {
            // FormatIpv4 reads the address in network order (big-endian).
            const unsigned a = 192u, b = 168u, c = 0u, d = 1u;
            info.ipv4.push_back(
                {static_cast<uint32_t>(a | (b << 8) | (c << 16) | (d << 24)),
                 prefix});
        }
        return info;
    }

    void TestChoicesSkipBlankRows() {
        UiSnapshot snap;
        snap.adapters.push_back(MakeInfo("", "", true, true));
        snap.adapters.push_back(MakeInfo("NIC 1", "\\DEVICE\\{A}", true, true));
        const auto choices = BuildAdapterChoices(snap, Tr());
        CHECK(choices.size() == 1);
        if (choices.size() == 1) {
            CHECK(choices[0].value == L"NIC 1");
        }
    }

    void TestChoicesKeepDeviceOnlyRows() {
        UiSnapshot snap;
        snap.adapters.push_back(MakeInfo("", "\\DEVICE\\{A}", false, false));
        const auto choices = BuildAdapterChoices(snap, Tr());
        CHECK(choices.size() == 1);
        if (choices.size() == 1) {
            CHECK(choices[0].value == L"\\DEVICE\\{A}");
        }
    }

    void TestChoicesRankConnectedWithIpv4First() {
        UiSnapshot snap;
        snap.adapters.push_back(MakeInfo("Disconnected", "\\DEVICE\\{C}", false,
                                         false, "192.168.0.9"));
        snap.adapters.push_back(MakeInfo("NoIp", "\\DEVICE\\{B}", true, true));
        snap.adapters.push_back(
            MakeInfo("Good", "\\DEVICE\\{A}", true, true, "192.168.0.1"));
        const auto choices = BuildAdapterChoices(snap, Tr());
        CHECK(choices.size() == 3);
        if (choices.size() == 3) {
            CHECK(choices[0].value == L"Good");       // rank 0
            CHECK(choices[0].rank == 0);
            CHECK(choices[1].value == L"NoIp");       // rank 1
            CHECK(choices[1].rank == 1);
            CHECK(choices[2].value == L"Disconnected");  // rank 2
            CHECK(choices[2].rank == 2);
        }
    }

    void TestChoicesConnectedFlagMirrorsUpAndMedia() {
        UiSnapshot snap;
        snap.adapters.push_back(MakeInfo("UpMedia", "\\DEVICE\\{A}", true, true));
        snap.adapters.push_back(MakeInfo("UpNoMedia", "\\DEVICE\\{B}", true, false));
        snap.adapters.push_back(MakeInfo("DownMedia", "\\DEVICE\\{C}", false, true));
        const auto choices = BuildAdapterChoices(snap, Tr());
        CHECK(choices.size() == 3);
        if (choices.size() == 3) {
            // Both is_up and media_connected are required.
            int up_media = 0, up_nomedia = 0, down_media = 0;
            for (const auto& c : choices) {
                if (c.value == L"UpMedia") up_media = c.connected ? 1 : 0;
                if (c.value == L"UpNoMedia") up_nomedia = c.connected ? 1 : 0;
                if (c.value == L"DownMedia") down_media = c.connected ? 1 : 0;
            }
            CHECK(up_media == 1);
            CHECK(up_nomedia == 0);
            CHECK(down_media == 0);
        }
    }

    void TestChoicesAreStableWithinRank() {
        // Ranks cycle 0,2,1 so the sort must move elements ACROSS the whole
        // range. With all-equal keys an unstable sort still emits the input
        // order by accident; only real movement exposes it. 24 rows also
        // pushes MSVC past its insertion-sort cutoff.
        UiSnapshot snap;
        std::vector<std::string> input;
        std::vector<std::string> by_rank[3];
        for (int i = 0; i < 24; ++i) {
            const int phase = i % 3;  // 0 -> rank0, 1 -> rank2, 2 -> rank1
            const std::string name = "NIC " + std::to_string(i);
            input.push_back(name);
            vgww::runtime::Dataplane::AdapterInfo info;
            info.friendly_name = name;
            info.device = "\\DEVICE\\{X}";
            if (phase == 0) {
                info.is_up = true;
                info.media_connected = true;
                info.ipv4.push_back({static_cast<uint32_t>(0x0100A8C0u), 24});
            } else if (phase == 1) {
                info.is_up = true;
                info.media_connected = true;
            } else {
                info.is_up = false;
                info.media_connected = false;
            }
            // Product rank: connected+ipv4 = 0, connected = 1, down = 2.
            const int rank = (phase == 0) ? 0 : (phase == 1) ? 1 : 2;
            by_rank[rank].push_back(name);
            snap.adapters.push_back(info);
        }
        const auto choices = BuildAdapterChoices(snap, Tr());
        CHECK(choices.size() == 24);
        if (choices.size() == 24) {
            std::size_t at = 0;
            for (int rank = 0; rank < 3; ++rank) {
                for (const std::string& expect : by_rank[rank]) {
                    CHECK(choices[at].rank == rank);
                    CHECK(choices[at].value == Widen(expect));
                    ++at;
                }
            }
        }
    }

    void TestChoicesDuplicateFriendlyNamesUseDeviceLabels() {
        UiSnapshot snap;
        snap.adapters.push_back(
            MakeInfo("Ethernet", "\\DEVICE\\{AAAA1111-BBBB}", true, true));
        snap.adapters.push_back(
            MakeInfo("Ethernet", "\\DEVICE\\{CCCC2222-DDDD}", true, true));
        const auto choices = BuildAdapterChoices(snap, Tr());
        CHECK(choices.size() == 2);
        if (choices.size() == 2) {
            // Neither name is unique, so both labels come from the device path
            // and both VALUES keep the full path (they must stay distinct).
            CHECK(choices[0].value == L"\\DEVICE\\{AAAA1111-BBBB}");
            CHECK(choices[1].value == L"\\DEVICE\\{CCCC2222-DDDD}");
            CHECK(choices[0].label.find(FormAdapter()) == 0);
            CHECK(choices[1].label.find(FormAdapter()) == 0);
        }
    }

    void TestChoicesIpv4TailCarriesPrefixLength() {
        UiSnapshot snap;
        snap.adapters.push_back(
            MakeInfo("NIC 1", "\\DEVICE\\{A}", true, true, "192.168.0.1", 24));
        const auto choices = BuildAdapterChoices(snap, Tr());
        CHECK(choices.size() == 1);
        if (choices.size() == 1) {
            CHECK(choices[0].label.find(L"192.168.0.1/24") !=
                  std::wstring::npos);
        }
    }

    // --- FormValue / RelayoutHost ------------------------------------------

    void TestFormValueUnknownIdIsEmpty() {
        FormResult r;
        r.values["known"] = L"value";
        CHECK(FormValue(r, "known") == L"value");
        CHECK(FormValue(r, "unknown").empty());
    }

    void TestFormValueEmptyStringIsPreserved() {
        FormResult r;
        r.values["empty"] = L"";
        CHECK(FormValue(r, "empty").empty());
    }

}  // namespace

int main() {
    Tr().SetLang(vgww::ui::Lang::En);

    TestNarrowEmptyIsEmpty();
    TestNarrowAsciiRoundTrips();
    TestNarrowUtf8IsMultiByte();
    TestNarrowUnpairedSurrogateFallsBack();
    TestWidenEmptyAndAscii();
    TestWidenUtf8();
    TestWidenInvalidUtf8FallsBackPerByte();
    TestDeviceLabelUsesGuidPrefix();
    TestDeviceLabelShortGuidIsNotTruncated();
    TestDeviceLabelEmptyBraceFallsBackToPath();
    TestDeviceLabelPathComponentIsCapped();
    TestDeviceLabelShortPathComponentKept();
    TestDeviceLabelNoSeparatorUsesWholeString();
    TestUniqueFriendlyNameBecomesValueAndLabel();
    TestDuplicateFriendlyNameFallsBackToDevice();
    TestZeroCountWithFriendlyNameIsNotUnique();
    TestEmptyFriendlyNameAlwaysUsesDevice();
    TestLinkStateUpAndDown();
    TestIpv4ShownOnlyWhenConnected();
    TestIpv4EmptyAddsNoSeparator();
    TestIpv4ExtraAddressesBecomePlusN();
    TestIpv4SingleAddressHasNoPlusSuffix();
    TestChoicesSkipBlankRows();
    TestChoicesKeepDeviceOnlyRows();
    TestChoicesRankConnectedWithIpv4First();
    TestChoicesConnectedFlagMirrorsUpAndMedia();
    TestChoicesAreStableWithinRank();
    TestChoicesDuplicateFriendlyNamesUseDeviceLabels();
    TestChoicesIpv4TailCarriesPrefixLength();
    TestFormValueUnknownIdIsEmpty();
    TestFormValueEmptyStringIsPreserved();

    if (0 == g_failures) {
        std::puts("test_page_util: ALL PASS");
        return 0;
    }
    std::fprintf(stderr, "test_page_util: %d FAILURES\n", g_failures);
    return 1;
}
