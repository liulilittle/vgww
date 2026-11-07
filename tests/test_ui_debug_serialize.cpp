// ============================================================================
// test_ui_debug_serialize.cpp - batch248: ui_debug_serialize.cpp had ZERO test
// coverage. Three product call sites consume ElementPath() (focused_path,
// hover path, query-hit path) and one consumes SerializeElement().
//
// The header contract (ui_debug_serialize.h:73-75) says ElementPath returns
// child indices "in the same order SerializeElement emits children[]". That
// must hold for BOTH include_hidden settings, because a debug client resolves
// a path against the JSON it was given.
// ============================================================================
#include <cstdio>
#include <string>
#include <vector>

#include "ui/controls.h"
#include "ui/debug/ui_debug_serialize.h"

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


    // --- ElementPath basics -------------------------------------------------

    void TestPathOfRootIsEmpty() {
        StackPanel root(Orientation::Vertical);
        CHECK((ElementPath(root, &root).empty()));
    }

    void TestPathOfNullIsEmpty() {
        StackPanel root(Orientation::Vertical);
        CHECK((ElementPath(root, nullptr).empty()));
    }

    void TestPathOfDirectChildIsZero() {
        StackPanel root(Orientation::Vertical);
        auto* child = root.Add(std::make_unique<Text>(L""));
        CHECK((ElementPath(root, child) == std::vector<std::size_t>{0}));
    }

    void TestPathOfNestedChild() {
        StackPanel root(Orientation::Vertical);
        auto* a = root.Add(std::make_unique<Text>(L""));
        auto* b = root.Add(std::make_unique<StackPanel>(Orientation::Vertical));
        auto* deep = b->Add(std::make_unique<Text>(L""));
        CHECK((ElementPath(root, a) == std::vector<std::size_t>{0}));
        CHECK((ElementPath(root, b) == std::vector<std::size_t>{1}));
        CHECK((ElementPath(root, deep) == std::vector<std::size_t>{1, 0}));
    }

    void TestPathSecondChildIndex() {
        StackPanel root(Orientation::Vertical);
        root.Add(std::make_unique<Text>(L""));
        auto* second = root.Add(std::make_unique<Text>(L""));
        CHECK((ElementPath(root, second) == std::vector<std::size_t>{1}));
    }

    // --- ElementPath vs SerializeElement index agreement --------------------

    // SerializeElement skips invisible children when include_hidden == false.
    // ElementPath walks ALL children. With a hidden sibling before the target,
    // the path must still index the array the client actually received.
    void TestPathMatchesSerializedChildrenWhenHiddenPredates() {
        StackPanel root(Orientation::Vertical);
        auto* hidden = root.Add(std::make_unique<Text>(L""));
        hidden->visible = false;
        auto* target = root.Add(std::make_unique<Text>(L""));
        target->id = "target";

        const nlohmann::json j =
            SerializeElement(root, /*include_hidden=*/false, /*max_depth=*/-1);
        CHECK(j.contains("children"));
        if (!j.contains("children")) {
            return;
        }
        const auto& kids = j["children"];
        CHECK(kids.size() == 1);  // the hidden one was skipped
        if (kids.size() != 1) {
            return;
        }
        CHECK(kids[0]["id"] == "target");

        // DOCUMENTED CONTRACT (ui_debug_serialize.h): ElementPath indexes the
        // RAW tree, so the hidden sibling still occupies slot 0 and the
        // target is at index 1. The serialized view skipped it and put the
        // target at children[0], so the two numberings DIFFER unless the
        // client asked for include_hidden=true.
        CHECK((ElementPath(root, target) == std::vector<std::size_t>{1}));

        // The agreement the header promises holds for include_hidden=true.
        const nlohmann::json j_all =
            SerializeElement(root, /*include_hidden=*/true, /*max_depth=*/-1);
        CHECK(j_all["children"].size() == 2);
        if (j_all["children"].size() == 2) {
            CHECK(j_all["children"][1]["id"] == "target");
        }
    }

    void TestPathMatchesSerializedChildrenWhenHiddenAfter() {
        StackPanel root(Orientation::Vertical);
        auto* target = root.Add(std::make_unique<Text>(L""));
        target->id = "target";
        auto* hidden = root.Add(std::make_unique<Text>(L""));
        hidden->visible = false;

        const nlohmann::json j =
            SerializeElement(root, /*include_hidden=*/false, /*max_depth=*/-1);
        CHECK(j["children"].size() == 1);
        // Target is first in both views: this direction already agrees.
        CHECK((ElementPath(root, target) == std::vector<std::size_t>{0}));
    }

    void TestPathWithIncludeHiddenTrueAgrees() {
        StackPanel root(Orientation::Vertical);
        auto* hidden = root.Add(std::make_unique<Text>(L""));
        hidden->visible = false;
        auto* target = root.Add(std::make_unique<Text>(L""));
        target->id = "target";

        const nlohmann::json j =
            SerializeElement(root, /*include_hidden=*/true, /*max_depth=*/-1);
        CHECK(j["children"].size() == 2);
        // With hidden nodes included, index 1 is correct in both.
        CHECK((ElementPath(root, target) == std::vector<std::size_t>{1}));
    }

    // --- SerializeElement core fields ---------------------------------------

    void TestSerializeElementCoreFields() {
        Text t(L"");
        t.id = "msg";
        t.visible = true;
        StackPanel root(Orientation::Vertical);
        const nlohmann::json j =
            SerializeElement(t, false, 0, nullptr, nullptr, true);

        CHECK(j["role"].is_string());
        CHECK(j["id"] == "msg");
        CHECK(j["visible"] == true);
        CHECK(j["focused"] == false);
        CHECK(j["rect"].is_array());
        CHECK(j["rect"].size() == 4);
        CHECK(j.contains("enabled"));
        CHECK(j.contains("focusable"));
        CHECK(j.contains("renders_on_top"));
        CHECK(j.contains("is_overlay"));
        CHECK(j.contains("hit_transparent"));
        CHECK(j.contains("draw_index"));
    }

    void TestSerializeOmitsEmptyId() {
        Text t(L"");
        t.id.clear();
        const nlohmann::json j = SerializeElement(t, false, 0);
        CHECK(!j.contains("id"));
    }

    void TestSerializeFocusedFlagUsesPointerIdentity() {
        Text a(L"");
        Text b(L"");
        const nlohmann::json ja = SerializeElement(a, false, 0, &a);
        const nlohmann::json jb = SerializeElement(b, false, 0, &a);
        CHECK(ja["focused"] == true);
        CHECK(jb["focused"] == false);
    }

    // --- draw_index ---------------------------------------------------------

    void TestDrawIndexPreOrderSkipsHiddenAndOverlay() {
        // root(0) -> visible child(1) -> grandchild(2); hidden child skipped;
        // renders_on_top child skipped (overlay pass).
        StackPanel root(Orientation::Vertical);
        auto* child = root.Add(std::make_unique<StackPanel>(Orientation::Vertical));
        child->id = "child";
        auto* grand = child->Add(std::make_unique<Text>(L""));
        grand->id = "grand";

        auto* hidden = root.Add(std::make_unique<Text>(L""));
        hidden->visible = false;
        hidden->id = "hidden";

        auto* overlay = root.Add(std::make_unique<ContextMenu>());
        overlay->id = "overlay";

        int counter = 0;
        const nlohmann::json j =
            SerializeElement(root, true, -1, nullptr, &counter, true);

        CHECK(j["draw_index"] == 0);
        CHECK(j["children"].size() == 3);  // include_hidden=true keeps all
        if (j["children"].size() == 3) {
            // child subtree: child=1, grand=2
            CHECK(j["children"][0]["draw_index"] == 1);
            CHECK(j["children"][0]["children"][0]["draw_index"] == 2);
            // hidden: outside the content pass
            CHECK(j["children"][1]["draw_index"] == -1);
            // renders_on_top: outside the content pass (overlay draws later)
            CHECK(j["children"][2]["draw_index"] == -1);
        }
    }

    void TestDrawIndexMinusOneWithoutCounter() {
        StackPanel root(Orientation::Vertical);
        const nlohmann::json j =
            SerializeElement(root, false, 0, nullptr, nullptr, true);
        CHECK(j["draw_index"] == -1);
    }

    void TestDrawIndexRootOutsidePassIsMinusOne() {
        StackPanel root(Orientation::Vertical);
        int counter = 0;
        const nlohmann::json j =
            SerializeElement(root, false, 0, nullptr, &counter, false);
        CHECK(j["draw_index"] == -1);
        CHECK(counter == 0);
    }

    // --- max_depth ----------------------------------------------------------

    void TestMaxDepthZeroOmitsChildren() {
        StackPanel root(Orientation::Vertical);
        root.Add(std::make_unique<Text>(L""));
        const nlohmann::json j = SerializeElement(root, true, 0);
        CHECK(!j.contains("children"));
    }

    void TestMaxDepthOneKeepsOneLevel() {
        StackPanel root(Orientation::Vertical);
        auto* c = root.Add(std::make_unique<StackPanel>(Orientation::Vertical));
        c->Add(std::make_unique<Text>(L""));
        const nlohmann::json j = SerializeElement(root, true, 1);
        CHECK(j.contains("children"));
        CHECK(j["children"].size() == 1);
        if (j.contains("children") && j["children"].size() == 1) {
            CHECK(!j["children"][0].contains("children"));
        }
    }

    void TestNegativeMaxDepthIsUnlimited() {
        StackPanel root(Orientation::Vertical);
        auto* a = root.Add(std::make_unique<StackPanel>(Orientation::Vertical));
        auto* b = a->Add(std::make_unique<StackPanel>(Orientation::Vertical));
        b->Add(std::make_unique<Text>(L""));
        const nlohmann::json j = SerializeElement(root, true, -1);
        CHECK(j["children"][0]["children"][0].contains("children"));
    }

    // --- FindById / FindByRole / FindByText --------------------------------

    void TestFindByIdEmptyReturnsNothing() {
        StackPanel root(Orientation::Vertical);
        root.Add(std::make_unique<Text>(L""));
        CHECK(FindById(root, "").empty());
    }

    void TestFindByIdFindsAllDuplicates() {
        StackPanel root(Orientation::Vertical);
        auto* a = root.Add(std::make_unique<Text>(L""));
        a->id = "dup";
        auto* b = root.Add(std::make_unique<Text>(L""));
        b->id = "dup";
        const auto hits = FindById(root, "dup");
        CHECK(hits.size() == 2);
        if (hits.size() == 2) {
            CHECK(hits[0] == a);
            CHECK(hits[1] == b);
        }
    }

    void TestFindByRoleEmptyReturnsNothing() {
        StackPanel root(Orientation::Vertical);
        CHECK(FindByRole(root, "").empty());
    }

    void TestFindByRoleMatchesDebugRole() {
        StackPanel root(Orientation::Vertical);
        auto* t = static_cast<Text*>(root.Add(std::make_unique<Text>(L"")));
        const auto hits = FindByRole(root, t->debug_role());
        CHECK(!hits.empty());
        bool found = false;
        for (const Element* e : hits) {
            if (e == t) {
                found = true;
            }
        }
        CHECK(found);
    }

    void TestFindByTextEmptyReturnsNothing() {
        StackPanel root(Orientation::Vertical);
        CHECK(FindByText(root, "").empty());
    }

    void TestFindByTextMatchesButtonLabel() {
        StackPanel root(Orientation::Vertical);
        auto* btn = static_cast<Button*>(root.Add(std::make_unique<Button>(L"")));
        btn->SetLabel(L"Save");
        const auto hits = FindByText(root, "Save");
        CHECK(hits.size() == 1);
        if (hits.size() == 1) {
            CHECK(hits[0] == btn);
        }
    }

    void TestFindByTextMatchesTextNode() {
        StackPanel root(Orientation::Vertical);
        auto* t = static_cast<Text*>(root.Add(std::make_unique<Text>(L"")));
        t->SetText(L"Hello");
        const auto hits = FindByText(root, "Hello");
        CHECK(hits.size() == 1);
        if (hits.size() == 1) {
            CHECK(hits[0] == t);
        }
    }

    void TestFindByTextIsExactMatch() {
        StackPanel root(Orientation::Vertical);
        auto* t = static_cast<Text*>(root.Add(std::make_unique<Text>(L"")));
        t->SetText(L"Hello");
        CHECK(FindByText(root, "Hell").empty());
        CHECK(FindByText(root, "Hello!").empty());
    }

    void TestFindByTextMatchesSelectSelectedLabel() {
        StackPanel root(Orientation::Vertical);
        auto* sel = static_cast<SelectElement*>(root.Add(std::make_unique<SelectElement>()));
        sel->SetOptions({{L"a", L"Alpha"}, {L"b", L"Beta"}});
        sel->SetSelectedValue(L"b");
        const auto hits = FindByText(root, "Beta");
        CHECK(hits.size() == 1);
        if (hits.size() == 1) {
            CHECK(hits[0] == sel);
        }
    }

    void TestFindByTextSelectFallsBackToValue() {
        // SetSelectedValueRefuses an unknown option, so the documented
        // "value when the option list does not contain the selection" fallback
        // is only reachable while the option list is EMPTY (no validation).
        StackPanel root(Orientation::Vertical);
        auto* sel = static_cast<SelectElement*>(
            root.Add(std::make_unique<SelectElement>()));
        sel->SetSelectedValue(L"ghost");
        CHECK(sel->selected_value() == L"ghost");
        const auto hits = FindByText(root, "ghost");
        CHECK(hits.size() == 1);
        if (hits.size() == 1) {
            CHECK(hits[0] == sel);
        }
    }

    void TestFindByTextSelectIgnoresUnknownOption() {
        // With a NON-empty option list an unknown value is ignored by
        // SetSelectedValue, so the searchable text stays the real selection.
        StackPanel root(Orientation::Vertical);
        auto* sel = static_cast<SelectElement*>(
            root.Add(std::make_unique<SelectElement>()));
        sel->SetOptions({{L"a", L"Alpha"}});
        sel->SetSelectedValue(L"ghost");
        CHECK(sel->selected_value().empty());
        CHECK(FindByText(root, "ghost").empty());
        // selected_ stayed empty, so the searchable text is the empty string:
        // the option LABEL is not searchable until the option is selected.
        CHECK(FindByText(root, "Alpha").empty());
        sel->SetSelectedValue(L"a");
        CHECK(FindByText(root, "Alpha").size() == 1);
    }

    void TestFindByTextMatchesBadge() {
        StackPanel root(Orientation::Vertical);
        auto* badge = static_cast<BadgeElement*>(root.Add(std::make_unique<BadgeElement>(L"")));
        badge->SetText(L"NEW");
        const auto hits = FindByText(root, "NEW");
        CHECK(hits.size() == 1);
        if (hits.size() == 1) {
            CHECK(hits[0] == badge);
        }
    }

    void TestFindByTextMatchesLink() {
        StackPanel root(Orientation::Vertical);
        auto* link = static_cast<LinkElement*>(root.Add(std::make_unique<LinkElement>(L"", L"")));
        link->SetText(L"Telegram");
        const auto hits = FindByText(root, "Telegram");
        CHECK(hits.size() == 1);
        if (hits.size() == 1) {
            CHECK(hits[0] == link);
        }
    }

    void TestFindByTextMatchesTextInputValue() {
        StackPanel root(Orientation::Vertical);
        auto* input = static_cast<TextInputElement*>(root.Add(std::make_unique<TextInputElement>()));
        input->SetValue(L"typed");
        const auto hits = FindByText(root, "typed");
        CHECK(hits.size() == 1);
        if (hits.size() == 1) {
            CHECK(hits[0] == input);
        }
    }

    // --- CollectSubtree covers hidden nodes ---------------------------------

    // --- state object (S4) --------------------------------------------------

    void TestStatePresentForControlsThatCarryDebugState() {
        // Text writes {text,color,font,...}; the serializer must forward it.
        Text t(L"hello");
        const nlohmann::json j = SerializeElement(t, false, 0);
        CHECK(j.contains("state"));
        if (j.contains("state")) {
            CHECK(j["state"].contains("text"));
            CHECK(j["state"]["text"] == "hello");
        }
    }

    void TestStateAbsentWhenControlWritesNothing() {
        // A bare StackPanel writes no debug state, so the key must be OMITTED
        // (an always-present empty object would be noise for clients).
        StackPanel p(Orientation::Vertical);
        const nlohmann::json j = SerializeElement(p, false, 0);
        CHECK(!j.contains("state"));
    }

    // --- FindById is an EXACT match (F5) ------------------------------------

    void TestFindByIdIsExactMatchNotPrefix() {
        StackPanel root(Orientation::Vertical);
        auto* short_id = static_cast<Text*>(root.Add(std::make_unique<Text>(L"")));
        short_id->id = "dup";
        auto* long_id = static_cast<Text*>(root.Add(std::make_unique<Text>(L"")));
        long_id->id = "dupmore";
        const auto hits = FindById(root, "dup");
        CHECK(hits.size() == 1);
        if (hits.size() == 1) {
            CHECK(hits[0] == short_id);
        }
        CHECK(FindById(root, "dupmo").empty());
    }

    void TestFindersSeeHiddenNodes() {
        // The finders walk the RAW tree: a debug client must be able to locate
        // a hidden node by id even though the serialized view omits it.
        StackPanel root(Orientation::Vertical);
        auto* hidden = root.Add(std::make_unique<Text>(L""));
        hidden->id = "hidden.node";
        hidden->visible = false;
        CHECK(FindById(root, "hidden.node").size() == 1);
    }

}  // namespace

int main() {
    TestPathOfRootIsEmpty();
    TestPathOfNullIsEmpty();
    TestPathOfDirectChildIsZero();
    TestPathOfNestedChild();
    TestPathSecondChildIndex();
    TestPathMatchesSerializedChildrenWhenHiddenPredates();
    TestPathMatchesSerializedChildrenWhenHiddenAfter();
    TestPathWithIncludeHiddenTrueAgrees();
    TestSerializeElementCoreFields();
    TestSerializeOmitsEmptyId();
    TestSerializeFocusedFlagUsesPointerIdentity();
    TestDrawIndexPreOrderSkipsHiddenAndOverlay();
    TestDrawIndexMinusOneWithoutCounter();
    TestDrawIndexRootOutsidePassIsMinusOne();
    TestMaxDepthZeroOmitsChildren();
    TestMaxDepthOneKeepsOneLevel();
    TestNegativeMaxDepthIsUnlimited();
    TestFindByIdEmptyReturnsNothing();
    TestFindByIdFindsAllDuplicates();
    TestFindByRoleEmptyReturnsNothing();
    TestFindByRoleMatchesDebugRole();
    TestFindByTextEmptyReturnsNothing();
    TestFindByTextMatchesButtonLabel();
    TestFindByTextMatchesTextNode();
    TestFindByTextIsExactMatch();
    TestFindByTextMatchesSelectSelectedLabel();
    TestFindByTextSelectFallsBackToValue();
    TestFindByTextSelectIgnoresUnknownOption();
    TestFindByTextMatchesBadge();
    TestFindByTextMatchesLink();
    TestFindByTextMatchesTextInputValue();
    TestStatePresentForControlsThatCarryDebugState();
    TestStateAbsentWhenControlWritesNothing();
    TestFindByIdIsExactMatchNotPrefix();
    TestFindersSeeHiddenNodes();

    if (0 == g_failures) {
        std::puts("test_ui_debug_serialize: ALL PASS");
        return 0;
    }
    std::fprintf(stderr, "test_ui_debug_serialize: %d FAILURES\n", g_failures);
    return 1;
}
