#include "ui/debug/ui_debug_serialize.h"

#include "ui/controls.h"

#include <algorithm>

namespace vgww {
    namespace ui {

        nlohmann::json SerializeElement(const Element& e, bool include_hidden,
                                        int max_depth, const Element* focused,
                                        int* draw_counter,
                                        bool in_content_pass) {
            nlohmann::json j = nlohmann::json::object();
            j["role"] = e.debug_role();
            if (!e.id.empty()) {
                j["id"] = e.id;
            }
            const Rect& b = e.bounds();
            j["rect"] = {b.x, b.y, b.w, b.h};
            j["visible"] = e.visible;
            j["enabled"] = e.EffectivelyEnabled();
            j["focusable"] = e.focusable();
            j["renders_on_top"] = e.renders_on_top();
            j["is_overlay"] = e.is_overlay();
            j["hit_transparent"] = e.hit_transparent;
            // I1a: per-node focus flag by pointer identity (spec L94); always
            // present so every node carries the boolean.
            j["focused"] = (focused == &e);

            // I1b: draw_index = the node's 0-based position in the CONTENT
            // render traversal (Element::Render/RenderChildren): a pre-order
            // walk (self first, then children in order) that skips
            // `renders_on_top()` children (they draw in the second overlay
            // pass) and hidden nodes. A node outside that pass (hidden, or
            // under a renders_on_top subtree) carries -1. The serialized root
            // is treated as content (its Render is invoked directly), and
            // `content` only propagates into a child when the parent is in the
            // pass and the child is not renders_on_top().
            const bool content = in_content_pass && e.visible;
            if (content && draw_counter != nullptr) {
                j["draw_index"] = (*draw_counter)++;
            } else {
                j["draw_index"] = -1;
            }

            nlohmann::json state = nlohmann::json::object();
            JsonStateSink sink(state);
            e.debug_state(sink);
            if (!state.empty()) {
                j["state"] = std::move(state);
            }

            if (max_depth != 0) {
                nlohmann::json kids = nlohmann::json::array();
                for (const auto& child : e.children()) {
                    if (!include_hidden && !child->visible) {
                        continue;
                    }
                    kids.push_back(SerializeElement(
                        *child, include_hidden,
                        max_depth > 0 ? max_depth - 1 : max_depth, focused,
                        draw_counter, content && !child->renders_on_top()));
                }
                if (!kids.empty()) {
                    j["children"] = std::move(kids);
                }
            }
            return j;
        }

        namespace {

            /// Appends `node` and every descendant in pre-order.
            void CollectSubtree(const Element& node,
                                std::vector<const Element*>& out) {
                out.push_back(&node);
                for (const auto& child : node.children()) {
                    CollectSubtree(*child, out);
                }
            }

            /// Best-effort text of a concrete control; empty when the element
            /// carries no searchable text.
            ///
            /// batch34z: the list must cover EVERY control that paints user
            /// text - a missing family silently makes FindByText unable to
            /// locate it (the About page's Telegram link was unreachable).
            /// Elements whose label lives in a SIBLING Text (Checkbox, radio)
            /// correctly return empty: they carry no text of their own.
            std::string TextOf(const Element& e) {
                if (const auto* text = dynamic_cast<const Text*>(&e)) {
                    return Utf16ToUtf8(text->text());
                }
                if (const auto* button = dynamic_cast<const Button*>(&e)) {
                    return Utf16ToUtf8(button->label());
                }
                if (const auto* link = dynamic_cast<const LinkElement*>(&e)) {
                    return Utf16ToUtf8(link->text());
                }
                if (const auto* badge = dynamic_cast<const BadgeElement*>(&e)) {
                    return Utf16ToUtf8(badge->text());
                }
                if (const auto* input = dynamic_cast<const TextInputElement*>(&e)) {
                    return Utf16ToUtf8(input->value());
                }
                if (const auto* select = dynamic_cast<const SelectElement*>(&e)) {
                    // The selected option's label (fall back to its value when
                    // the option list does not contain the selection).
                    const std::wstring& selected = select->selected_value();
                    for (const auto& option : select->options()) {
                        if (option.first == selected) {
                            return Utf16ToUtf8(option.second);
                        }
                    }
                    return Utf16ToUtf8(selected);
                }
                return std::string();
            }

        }  // namespace

        std::vector<const Element*> FindById(const Element& root,
                                             const std::string& id) {
            std::vector<const Element*> out;
            if (id.empty()) {
                return out;
            }
            std::vector<const Element*> all;
            CollectSubtree(root, all);
            for (const Element* e : all) {
                if (e->id == id) {
                    out.push_back(e);
                }
            }
            return out;
        }

        std::vector<const Element*> FindByRole(const Element& root,
                                               const std::string& role) {
            std::vector<const Element*> out;
            if (role.empty()) {
                return out;
            }
            std::vector<const Element*> all;
            CollectSubtree(root, all);
            for (const Element* e : all) {
                if (role == e->debug_role()) {
                    out.push_back(e);
                }
            }
            return out;
        }

        std::vector<const Element*> FindByText(const Element& root,
                                               const std::string& text) {
            std::vector<const Element*> out;
            if (text.empty()) {
                return out;
            }
            std::vector<const Element*> all;
            CollectSubtree(root, all);
            for (const Element* e : all) {
                if (TextOf(*e) == text) {
                    out.push_back(e);
                }
            }
            return out;
        }

        std::vector<std::size_t> ElementPath(const Element& root,
                                             const Element* target) {
            std::vector<std::size_t> path;
            if (target == nullptr || target == &root) {
                return path;
            }
            // Walk parents up to the root, recording each child index.
            const Element* cur = target;
            while (cur != nullptr && cur->parent() != nullptr) {
                const Element* par = cur->parent();
                std::size_t idx = 0;
                for (const auto& ch : par->children()) {
                    if (ch.get() == cur) {
                        break;
                    }
                    ++idx;
                }
                path.push_back(idx);
                cur = par;
            }
            std::reverse(path.begin(), path.end());
            return path;
        }

    }  // namespace ui
}  // namespace vgww
