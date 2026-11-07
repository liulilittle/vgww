// ============================================================================
// router.cpp - page router implementation (S4.3 Task 7).
// ============================================================================
#include "ui/router.h"

#include "ui/controls.h"

#include <cassert>
#include <utility>

namespace vgww {
    namespace ui {

        namespace {
            constexpr float kPageHostGap = 12.0f;

            /// batch37h: close every open DialogHost under `e` (page switch).
            /// A dialog left open on a hidden page must not keep the keyboard.
            void CloseDialogsIn(Element& e) {
                if (auto* dialog = dynamic_cast<DialogHost*>(&e)) {
                    if (dialog->open()) {
                        dialog->Close();
                    }
                }
                for (const auto& child : e.children()) {
                    CloseDialogsIn(*child);
                }
            }
        }

        Router::Router(Element& mount_host) : mount_(mount_host) {}

        Router::~Router() = default;

        void Router::SetContext(PageContext context) {
            ctx_ = std::move(context);
        }

        Router::Entry* Router::Find(std::string_view id) noexcept {
            for (Entry& entry : entries_) {
                if (entry.page != nullptr && id == entry.page->id()) {
                    return &entry;
                }
            }
            return nullptr;
        }

        bool Router::Register(std::unique_ptr<Page> page) {
            if (!page) {
                return false;
            }
            const char* raw_id = page->id();
            const std::string id = raw_id != nullptr ? raw_id : "";
            if (id.empty() || Find(id) != nullptr) {
                assert(false && "Router::Register: duplicate or empty page id");
                return false;
            }
            auto host = std::make_unique<StackPanel>(
                Orientation::Vertical, kPageHostGap, Padding{}, Align::Stretch);
            host->id = "page." + id + ".host";
            host->visible = false;  // shown by Navigate
            StackPanel* host_raw =
                static_cast<StackPanel*>(mount_.Add(std::move(host)));
            Entry entry;
            entry.page = std::move(page);
            entry.host = host_raw;
            entries_.push_back(std::move(entry));
            ids_.push_back(id);
            return true;
        }

        void Router::Navigate(std::string_view id) {
            Entry* entry = Find(id);
            if (entry == nullptr) {
                assert(false && "Router::Navigate: unregistered page id");
                return;  // Release: ignored
            }
            // batch31 P0-2: clicking the page tab that is ALREADY current must
            // be completely side-effect free. The old body re-assigned every
            // host's visibility (a whole-tree relayout) and called
            // BeginEntrance() (reset the fade to 0) on every click - that is
            // the user-reported "why does it fully repaint when I did not even
            // switch pages" flicker. Nothing below runs for a same-page click.
            if (current_ == entry->page.get() && entry->built) {
                return;
            }
            if (!entry->built) {
                entry->host->visible = true;
                entry->page->Build(*entry->host, ctx_);
                entry->built = true;
                if (snapshot_) {
                    entry->page->Update(*snapshot_, I18n::Instance());
                }
            }
            // batch37h: a page that is being hidden must not keep an open
            // modal. It would stay in the tree, steal the keyboard focus from
            // the visible page (SyncDialogFocus) and reappear on return.
            if (current_ != nullptr) {
                for (Entry& old : entries_) {
                    if (old.page.get() == current_ && old.host != nullptr) {
                        CloseDialogsIn(*old.host);
                    }
                }
            }
            for (Entry& other : entries_) {
                other.host->visible = &other == entry;
            }
            // T9 page entrance: fade the newly shown host's content in. The
            // host is a StackPanel; BeginEntrance resets its progress and spins
            // the frame clock (render-time fade only, no layout change).
            if (entry->host != nullptr) {
                entry->host->BeginEntrance();
            }
            const bool changed = current_ != entry->page.get();
            current_ = entry->page.get();
            if (changed && on_changed) {
                on_changed();
            }
        }

        void Router::NavigateWithIntent(std::string_view id, std::string intent) {
            // batch33 D: the intent channel. Navigate first (which builds the
            // target page when needed and refreshes it with the latest
            // snapshot), then deliver the intent to whatever page is current.
            // A same-page navigation must still run the intent: the user asked
            // for an effect (open a form / scroll to a row), not for a page
            // switch - so this deliberately does NOT reuse Navigate's
            // same-tab no-op shortcut when the page is already current.
            Entry* entry = Find(id);
            if (entry == nullptr) {
                assert(false && "Router::NavigateWithIntent: unregistered page id");
                return;
            }
            if (current_ == entry->page.get() && entry->built) {
                entry->page->OnIntent(intent);
                return;
            }
            Navigate(id);
            if (current_ != nullptr) {
                current_->OnIntent(intent);
            }
        }

        void Router::Update(std::shared_ptr<const UiSnapshot> snapshot,
                            I18n& i18n) {
            snapshot_ = std::move(snapshot);
            if (current_ != nullptr && snapshot_) {
                current_->Update(*snapshot_, i18n);
            }
        }

        void Router::UpdateAll(std::shared_ptr<const UiSnapshot> snapshot,
                               I18n& i18n) {
            snapshot_ = std::move(snapshot);
            if (!snapshot_) {
                return;
            }
            for (Entry& entry : entries_) {
                if (entry.built) {
                    entry.page->Update(*snapshot_, i18n);
                }
            }
        }

        std::size_t Router::built_count() const noexcept {
            std::size_t count = 0;
            for (const Entry& entry : entries_) {
                if (entry.built) {
                    ++count;
                }
            }
            return count;
        }

        bool Router::is_built(std::string_view id) const noexcept {
            for (const Entry& entry : entries_) {
                if (entry.page != nullptr && id == entry.page->id()) {
                    return entry.built;
                }
            }
            return false;
        }

        Element* Router::host_for(std::string_view id) const noexcept {
            for (const Entry& entry : entries_) {
                if (entry.page != nullptr && id == entry.page->id()) {
                    return entry.host;
                }
            }
            return nullptr;
        }

    }  // namespace ui
}  // namespace vgww
