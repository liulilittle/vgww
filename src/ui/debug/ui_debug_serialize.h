// ============================================================================
// ui_debug_serialize.h - element-tree JSON serialization + query filters.
// Pure functions over the Element tree; no window / no message loop.
// ============================================================================
#pragma once

#include "ui/debug/debug_state.h"
#include "ui/element.h"

#include <nlohmann/json.hpp>

#include <cstddef>
#include <string>
#include <vector>

namespace vgww {
    namespace ui {

        /// DebugStateSink that writes into an nlohmann json object.
        class JsonStateSink final : public DebugStateSink {
        public:
            explicit JsonStateSink(nlohmann::json& out) : out_(out) {}
            void WriteString(const char* key, const std::string& value) override {
                out_[key] = value;
            }
            void WriteBool(const char* key, bool value) override { out_[key] = value; }
            void WriteInt(const char* key, long long value) override { out_[key] = value; }
            void WriteDouble(const char* key, double value) override { out_[key] = value; }
            void WriteDoubleArray(const char* key,
                                  const std::vector<double>& values) override {
                out_[key] = values;
            }

        private:
            nlohmann::json& out_;
        };

        /// Serializes one element (and, up to max_depth, its children).
        /// Returns a json object:
        ///   {"role","id"?,"rect":[x,y,w,h],"visible","enabled","focusable",
        ///    "renders_on_top","is_overlay","hit_transparent","focused",
        ///    "draw_index","state"?,"children"?}
        /// `max_depth < 0` means unlimited.
        ///
        /// `focused` is the window's focused element (pointer identity); each
        /// node's "focused" boolean is `focused == &e` (I1a).
        ///
        /// `draw_index` (I1b) is the node's 0-based position in the CONTENT
        /// render traversal: a pre-order walk (self, then children in order)
        /// that skips `renders_on_top()` children (the second overlay pass) and
        /// hidden nodes. Nodes outside that pass carry -1. `draw_counter` is
        /// the shared traversal counter (pass a pointer to one int per tree);
        /// `in_content_pass` is true for the serialized root and only
        /// propagates into a child when the parent is in the pass and the child
        /// is not `renders_on_top()`.
        nlohmann::json SerializeElement(const Element& e, bool include_hidden,
                                        int max_depth,
                                        const Element* focused = nullptr,
                                        int* draw_counter = nullptr,
                                        bool in_content_pass = true);

        /// Pre-order search helpers (whole subtree, root included). Return
        /// pointers valid as long as `root` is untouched.
        std::vector<const Element*> FindById(const Element& root,
                                             const std::string& id);
        std::vector<const Element*> FindByRole(const Element& root,
                                               const std::string& role);
        /// Text match on Text/Button label, TextInput value, Select selected
        /// label (and Badge text); best-effort across concrete control types.
        std::vector<const Element*> FindByText(const Element& root,
                                               const std::string& text);

        /// Root->leaf path of child indices (root excluded). Empty when
        /// `target` is nullptr or `root`.
        ///
        /// IMPORTANT: the indices address the RAW Element tree, i.e.
        /// `Element::children()` in order. They are NOT indices into the
        /// "children" array of SerializeElement(): that array omits invisible
        /// children when `include_hidden == false` (its default), so with any
        /// hidden sibling the two numberings diverge. A debug client that
        /// wants to walk its serialized JSON must request
        /// `include_hidden=true`, where both agree. (Measured: with one hidden
        /// sibling ahead of the target, the serialized index is 0 while this
        /// returns {1}.)
        std::vector<std::size_t> ElementPath(const Element& root,
                                             const Element* target);

    }  // namespace ui
}  // namespace vgww
