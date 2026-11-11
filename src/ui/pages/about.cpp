// ============================================================================
// about.cpp - about page (S4.3 Task 10): version, memory backend, config file,
// uptime, driver state, the autostart switch and the license line. Element ids
// follow the plan anchors (`about.*`).
// ============================================================================
#include "ui/pages/page.h"
#include "ui/pages/page_util.h"

#include "ui/controller.h"
#include "ui/format.h"
#include "ui/tray.h"

#include "core/memory.h"

#include <windows.h>
#include <shellapi.h>

#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace vgww {
    namespace ui {

        namespace {

            /// "label: value" row; both texts follow the active language.
            struct InfoRow {
                Str key = Str::_Count;
                Text* label = nullptr;
                Text* value = nullptr;
            };

            InfoRow AddInfoRow(Element& host, Str label, const char* value_id) {
                // batch26: fixed label column + star value column (same as the
                // bridge page). A horizontal StackPanel let a long value grow
                // past the card and clip with no ellipsis; the GridLayout bounds
                // the value to the remaining width so Text::RenderCore can
                // ellipsize it and Text::tooltip_text exposes the full string.
                auto row = std::make_unique<GridLayout>(
                    std::vector<ColumnSpec>{ColumnSpec::Fixed(120.0f),
                                            ColumnSpec::Star()},
                    8.0f, Padding{});
                InfoRow out;
                out.key = label;
                out.label = static_cast<Text*>(row->Add(std::make_unique<Text>(
                    I18n::Instance().T(label), FontToken::BodyStrong,
                    ColorToken::Text)));
                auto value = std::make_unique<Text>(L"-", FontToken::Body,
                                                    ColorToken::TextDim);
                value->id = value_id;
                out.value = static_cast<Text*>(row->Add(std::move(value)));
                host.Add(std::move(row));
                return out;
            }

            class AboutPage final : public Page {
            public:
                const char* id() const override { return "about"; }
                Str title() const override { return Str::NavAbout; }
                void Build(Element& host, PageContext& ctx) override;
                void Update(const UiSnapshot& snapshot, I18n& i18n) override;

            private:
                void RefreshLabels(I18n& i18n);
                void RefreshWebRow(const ConfigView& config, I18n& i18n);
                /// batch164 P1-2: roll back the autostart checkbox when the
                /// OS setter refused the change.
                void OnCommandFailed() override;

                PageContext* ctx_ = nullptr;
                InfoRow version_;
                InfoRow memory_;
                InfoRow config_path_;
                InfoRow uptime_;
                InfoRow driver_;
                Text* autostart_label_ = nullptr;
                Checkbox* autostart_ = nullptr;
                /// batch164 P1-2: true while the autostart command result is
                /// pending; used to roll back the checkbox when the OS setter
                /// refuses the change.
                bool autostart_awaiting_ = false;
                /// batch27 D4-B: plain-language explanation of the checkbox.
                Text* autostart_hint_ = nullptr;
                Text* lang_label_ = nullptr;
                LanguagePicker* language_ = nullptr;
                Text* license_ = nullptr;
                std::vector<InfoRow*> rows_;
                // Batch19 R2: the Web UI row (URL text + "Open" button). The
                // token is never read here (it never enters the snapshot).
                Text* web_label_ = nullptr;
                Text* web_value_ = nullptr;
                Button* web_open_ = nullptr;
                std::wstring web_url_;
                // Batch19 terminal: the Telegram user-group hyperlink row.
                Text* telegram_label_ = nullptr;
                LinkElement* telegram_ = nullptr;
            };

            void AboutPage::Build(Element& host, PageContext& ctx) {
                ctx_ = &ctx;
                version_ = AddInfoRow(host, Str::AboutVersion, "about.version");
                version_.value->SetText(L"0.1.0");  // main.cpp's banner version

                memory_ = AddInfoRow(host, Str::AboutMemory, "about.memory");
                // batch29: the raw "memory backend: crt ucrt" line told a
                // normal user nothing.
                // The backend stays compiled in exactly as before; only the
                // label becomes the plain "system default".
                memory_.value->SetText(I18n::Instance().T(Str::AboutMemoryManaged));

                config_path_ = AddInfoRow(host, Str::AboutConfigPath, "about.config_path");
                uptime_ = AddInfoRow(host, Str::DashUptime, "about.uptime");
                driver_ = AddInfoRow(host, Str::AboutDriver, "about.driver");
                rows_ = {&version_, &memory_, &config_path_, &uptime_, &driver_};

                // Batch19 R2: the built-in Web UI had no visible entry point
                // in the GUI. Show the URL (from the snapshot's web_* fields,
                // never the auth token) plus an "Open" button that hands the
                // URL to the default browser. A disabled server or port 0
                // degrades to the localized "unavailable" text + a disabled
                // button.
                auto web_row =
                    std::make_unique<StackPanel>(Orientation::Horizontal, 8.0f);
                web_label_ = static_cast<Text*>(web_row->Add(std::make_unique<Text>(
                    I18n::Instance().T(Str::AboutWebUi), FontToken::BodyStrong,
                    ColorToken::Text)));
                auto web_value = std::make_unique<Text>(
                    I18n::Instance().T(Str::AboutWebUnavailable), FontToken::Body,
                    ColorToken::TextDim);
                web_value->id = "about.web_url";
                web_value_ = static_cast<Text*>(web_row->Add(std::move(web_value)));
                auto web_button =
                    std::make_unique<Button>(I18n::Instance().T(Str::AboutOpenWeb));
                web_button->id = "about.open_web";
                web_open_ = static_cast<Button*>(web_row->Add(std::move(web_button)));
                web_open_->enabled = false;  // until a snapshot says otherwise
                // batch199: this button discarded the ShellExecuteW result, so
                // a machine with no registered browser (or a policy blocking
                // the launch) answered a click with absolutely nothing - no
                // page, no message, not even an acknowledgement. The Telegram
                // link three lines below already reports the same failure, so
                // the two must go through the same seam and say the same thing.
                web_open_->on_click = [this] {
                    if (web_url_.empty()) {
                        return;
                    }
                    const long long result =
                        OpenExternalUrlHandler()(web_url_);
                    // ShellExecuteW (and the seam that wraps it) returns <= 32
                    // on failure.
                    if (result <= 32 && ctx_ != nullptr && ctx_->toast) {
                        ctx_->toast(Str::AboutTelegramFailed,
                                    ToastKind::Warning);
                    }
                };
                web_url_.clear();
                host.Add(std::move(web_row));

                // Batch19 terminal: the official Telegram user-group link, just
                // below the Web UI row. A clickable accent hyperlink (hand
                // cursor, hover underline, Tab + Enter/Space). A ShellExecuteW
                // failure (return <= 32) surfaces as an in-app toast instead of
                // silently doing nothing.
#if 1  // batch19 terminal: Telegram row enabled (was #if 0 for the red probe).
                auto telegram_row =
                    std::make_unique<StackPanel>(Orientation::Horizontal, 8.0f);
                telegram_label_ = static_cast<Text*>(
                    telegram_row->Add(std::make_unique<Text>(
                        I18n::Instance().T(Str::AboutTelegram),
                        FontToken::BodyStrong, ColorToken::Text)));
                telegram_label_->id = "about.telegram.label";
                auto telegram_link = std::make_unique<LinkElement>(
                    L"@supersocksr_group", L"https://t.me/supersocksr_group");
                telegram_link->id = "about.telegram";
                telegram_ = static_cast<LinkElement*>(
                    telegram_row->Add(std::move(telegram_link)));
                telegram_->on_activate =
                    [this](const std::wstring&, long long result) {
                        // ShellExecuteW returns <= 32 on failure.
                        if (result <= 32 && ctx_ != nullptr && ctx_->toast) {
                            ctx_->toast(Str::AboutTelegramFailed,
                                        ToastKind::Warning);
                        }
                    };
                host.Add(std::move(telegram_row));
#endif  // RED-PROBE

                auto row = std::make_unique<StackPanel>(Orientation::Horizontal, 8.0f);
                autostart_label_ = static_cast<Text*>(row->Add(std::make_unique<Text>(
                    I18n::Instance().T(Str::TrayAutostart), FontToken::BodyStrong,
                    ColorToken::Text)));
                auto box = std::make_unique<Checkbox>(
                    vgww::ui::tray::IsAutostartEnabled());
                box->id = "about.autostart";
                autostart_ = static_cast<Checkbox*>(row->Add(std::move(box)));
                autostart_->on_changed = [this](bool enabled) {
                    if (ctx_ != nullptr && ctx_->controller != nullptr) {
                        autostart_awaiting_ = true;
                        SubmitCommand(*ctx_, Command{SetAutostartCmd{enabled}});
                    }
                };
                host.Add(std::move(row));

                // batch27 D4-B: the bare checkbox left beginners guessing what
                // it does; one dim line explains the effect.
                autostart_hint_ = static_cast<Text*>(host.Add(std::make_unique<Text>(
                    I18n::Instance().T(Str::AboutAutostartHint),
                    FontToken::Small, ColorToken::TextDim, true)));
                autostart_hint_->id = "about.autostart.hint";

                // batch24 P2-6: the search filter is now INSIDE the picker
                // popup (its own top row) instead of a separate caption-less
                // page box (user: "what is the point, it looks hideous"). The
                // page keeps only the "interface language" label + the picker.
                auto lang_col = std::make_unique<StackPanel>(
                    Orientation::Vertical, 6.0f, Padding{}, Align::Start);
                lang_label_ = static_cast<Text*>(lang_col->Add(std::make_unique<Text>(
                    I18n::Instance().T(Str::AboutLanguage), FontToken::BodyStrong,
                    ColorToken::Text)));
                auto picker = std::make_unique<LanguagePicker>();
                picker->id = "about.language";
                // batch27 D4-A: cap the chooser at a comfortable width instead
                // of stretching a one-line control across the whole card. The
                // column uses Align::Start so the capped desired width wins
                // (a Stretch parent would override it with the card width).
                picker->SetPreferredWidth(320.0f);
                language_ = static_cast<LanguagePicker*>(
                    lang_col->Add(std::move(picker)));
                {
                    std::vector<LanguagePicker::Item> items;
                    const std::size_t n = I18n::LanguageCount();
                    items.reserve(n);
                    for (std::size_t i = 0; i < n; ++i) {
                        items.push_back(LanguagePicker::Item{
                            Widen(I18n::LanguageNameAt(i)),
                            std::string(I18n::LanguageCodeAt(i))});
                    }
                    language_->SetLanguages(std::move(items),
                                            I18n::Instance().LangCode());
                }
                if (language_->search_editor() != nullptr) {
                    language_->search_editor()->SetPlaceholder(
                        I18n::Instance().T(Str::AboutLangFilterHint));
                }
                language_->on_pick = [this](const std::string& code) {
                    I18n::Instance().SetLangCode(code);
                    if (ctx_ != nullptr && ctx_->apply_language) {
                        ctx_->apply_language();
                    } else {
                        RefreshLabels(I18n::Instance());
                    }
                    // Persist the choice (restart keeps it).
                    if (ctx_ != nullptr) {
                        SubmitCommand(*ctx_, Command{SetLanguageCmd{code}});
                    }
                };
                host.Add(std::move(lang_col));

                license_ = static_cast<Text*>(host.Add(std::make_unique<Text>(
                    I18n::Instance().T(Str::AboutLicense), FontToken::Small,
                    ColorToken::TextDim, true)));
                license_->id = "about.license";
            }

            void AboutPage::Update(const UiSnapshot& snapshot, I18n& i18n) {
                RefreshLabels(i18n);
                RefreshWebRow(snapshot.config, i18n);
                config_path_.value->SetText(snapshot.config.config_path.empty()
                                                ? i18n.T(Str::CommonNotSet)
                                                : Widen(snapshot.config.config_path));
                // batch30: the same human vocabulary as the dashboard tile.
                uptime_.value->SetText(FormatUptime(snapshot.uptime_s));
                driver_.value->SetText(i18n.T(snapshot.driver_running
                                                  ? Str::StatusRunning
                                                  : Str::StatusStopped));
                if (language_ != nullptr) {
                    language_->SetCurrentCode(I18n::Instance().LangCode());
                }
                // The autostart switch keeps the user's toggle; when the OS
                // setter refuses the change, OnCommandFailed rolls the checkbox
                // back to the registry truth so the UI never shows a state the
                // system did not accept.
            }

            void AboutPage::RefreshLabels(I18n& i18n) {
                for (InfoRow* row : rows_) {
                    row->label->SetText(i18n.T(row->key));
                }
                if (autostart_label_ != nullptr) {
                    autostart_label_->SetText(i18n.T(Str::TrayAutostart));
                }
                if (lang_label_ != nullptr) {
                    lang_label_->SetText(i18n.T(Str::AboutLanguage));
                }
                if (autostart_hint_ != nullptr) {
                    autostart_hint_->SetText(i18n.T(Str::AboutAutostartHint));
                }
                if (license_ != nullptr) {
                    license_->SetText(i18n.T(Str::AboutLicense));
                }
                if (web_label_ != nullptr) {
                    web_label_->SetText(i18n.T(Str::AboutWebUi));
                }
                if (web_open_ != nullptr) {
                    web_open_->SetLabel(i18n.T(Str::AboutOpenWeb));
                }
                if (telegram_label_ != nullptr) {
                    telegram_label_->SetText(i18n.T(Str::AboutTelegram));
                }
                if (language_ != nullptr &&
                    language_->search_editor() != nullptr) {
                    language_->search_editor()->SetPlaceholder(
                        i18n.T(Str::AboutLangFilterHint));
                }
            }

            // Batch19 R2: the Web UI row is a pure projection of the snapshot's
            // web_enabled/web_bind/web_port; the auth token is never part of the
            // snapshot and is never displayed. web.port is validated to
            // [1024, 65535] on load, so port==0 only happens when the server is
            // off - both gate the row to the disabled state.
            void AboutPage::OnCommandFailed() {
                // batch164 P1-2: roll back the autostart checkbox so it matches
                // the real autostart state when the OS setter refused the
                // change. WebUI does the same rollback (index.html:2811-2820).
                if (autostart_awaiting_ && autostart_ != nullptr) {
                    const bool real = vgww::ui::tray::IsAutostartEnabled();
                    autostart_->SetChecked(real);
                    autostart_awaiting_ = false;
                }
            }

            void AboutPage::RefreshWebRow(const ConfigView& config, I18n& i18n) {
                if (web_value_ == nullptr) {
                    return;
                }
                const bool available = config.web_enabled && config.web_port != 0;
                if (available) {
                    const std::string bind =
                        config.web_bind.empty() ? std::string("127.0.0.1")
                                                : config.web_bind;
                    web_url_ = L"http://" + Widen(bind) + L":" +
                               std::to_wstring(config.web_port) + L"/";
                    web_value_->SetText(web_url_);
                } else {
                    web_url_.clear();
                    web_value_->SetText(i18n.T(Str::AboutWebUnavailable));
                }
                if (web_open_ != nullptr) {
                    web_open_->enabled = available;
                }
            }

        }  // namespace

        std::unique_ptr<Page> MakeAboutPage() {
            return std::make_unique<AboutPage>();
        }

    }  // namespace ui
}  // namespace vgww
