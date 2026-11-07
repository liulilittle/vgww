// ============================================================================
// router.h - page router (S4.3 Task 7).
//
// Owns the pages and mounts exactly one of them into the shell's content
// host. Build() runs lazily on the first navigation (with the latest
// snapshot already available); the built host stays mounted and is shown or
// hidden on later navigations, so page state survives switching.
// ============================================================================
#pragma once

#include "ui/pages/page.h"

#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace vgww {
    namespace ui {

        class Router final {
        public:
            /// `mount_host` is owned by the caller (the shell content host)
            /// and must outlive this router.
            explicit Router(Element& mount_host);
            ~Router();

            Router(const Router&) = delete;
            Router& operator=(const Router&) = delete;

            /// Installs the context passed to Page::Build().
            void SetContext(PageContext context);

            /// false when the page is null or its id is already registered
            /// (debug: assertion; Release: ignored).
            bool Register(std::unique_ptr<Page> page);

            /// Shows (and on first use builds) the page; unknown ids are
            /// ignored (debug: assertion).
            void Navigate(std::string_view id);
            /// batch33 D: navigate, then hand `intent` to the page that is
            /// current afterwards (a same-page navigation still delivers it -
            /// the side-effect-free same-tab shortcut is not taken here,
            /// because the intent itself is the requested effect).
            void NavigateWithIntent(std::string_view id, std::string intent);

            Page* current() const noexcept { return current_; }
            Element& mount() noexcept { return mount_; }

            /// Forwards a snapshot to the current page.
            void Update(std::shared_ptr<const UiSnapshot> snapshot, I18n& i18n);
            /// Forwards a snapshot to every built page (language switch).
            void UpdateAll(std::shared_ptr<const UiSnapshot> snapshot, I18n& i18n);

            /// Fired after current() changed (the shell re-reads the title).
            std::function<void()> on_changed;

            // Test anchors.
            const std::vector<std::string>& page_ids() const noexcept { return ids_; }
            std::size_t built_count() const noexcept;
            bool is_built(std::string_view id) const noexcept;
            Element* host_for(std::string_view id) const noexcept;

        private:
            struct Entry {
                std::unique_ptr<Page> page;
                StackPanel* host = nullptr;  ///< owned by mount_host
                bool built = false;
            };

            Entry* Find(std::string_view id) noexcept;

            Element& mount_;
            PageContext ctx_{};
            std::vector<Entry> entries_;
            std::vector<std::string> ids_;
            Page* current_ = nullptr;
            std::shared_ptr<const UiSnapshot> snapshot_;
        };

    }  // namespace ui
}  // namespace vgww
