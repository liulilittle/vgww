// ============================================================================
// firewall.cpp - firewall (ban) page (S4.3 Task 9): one table (kind, value)
// with an add form (mac/ip) and confirm-to-delete. Element ids follow the plan
// anchors (`firewall.*` / `page.firewall.empty`).
// ============================================================================
#include "ui/pages/page.h"

#include "ui/console_log.h"
#include "ui/controller.h"
#include "ui/pages/page_util.h"

#include <cstddef>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace vgww {
    namespace ui {

        namespace {

            /// batch138: row ids are the ban's STABLE id (BanEntry::id), not
            /// its position, so a concurrent add cannot redirect a delete.
            /// Parsing stays strict: a malformed id must never become 0.
            bool ParseIndex(const std::string& text, uint64_t& out) {
                if (text.empty()) {
                    return false;
                }
                uint64_t value = 0;
                for (const char c : text) {
                    if (c < '0' || c > '9') {
                        return false;
                    }
                    value = value * 10 + static_cast<uint64_t>(c - '0');
                }
                out = value;
                return true;
            }

            class FirewallPage final : public Page {
            public:
                const char* id() const override { return "firewall"; }
                Str title() const override { return Str::NavFirewall; }
                void Build(Element& host, PageContext& ctx) override;
                void Update(const UiSnapshot& snapshot, I18n& i18n) override;
                /// batch33 D: "mac=<MAC>" opens the add form with kind=mac and
                /// the MAC pre-filled (an invalid MAC only navigates).
                void OnIntent(const std::string& intent) override;

            private:
                void ShowAddForm();
                void ShowAddFormFor(const std::wstring& kind,
                                    const std::wstring& value);
                void SubmitForm(const FormResult& result);
                void RemoveEntry(const std::string& row_id);
                const vgww::web::BanEntry* FindBan(const std::string& row_id) const;

                /// batch138: the last rendered bans, kept so the delete
                /// confirmation can name the entry and carry its stable id.
                vgww::web::RuleList<vgww::web::BanEntry> bans_;
                void ShowError(Str message);
                void OpenRowMenu(const std::string& row_id, Point at);

                PageContext* ctx_ = nullptr;
                Element* host_ = nullptr;
                DialogHost* dialog_ = nullptr;
                Button* add_ = nullptr;
                TableElement* table_ = nullptr;
                EmptyState* empty_ = nullptr;
                ContextMenu* context_menu_ = nullptr;
                /// batch115: rule-document write failures (stderr-only before).
                Text* rules_hint_ = nullptr;
                /// batch118: invalid entries skipped at load (stderr-only).
                Text* discarded_hint_ = nullptr;
                std::string menu_row_;
                Str pending_error_ = Str::_Count;  ///< shown on the next Update
            };

            void FirewallPage::Build(Element& host, PageContext& ctx) {
                ctx_ = &ctx;
                host_ = &host;

                auto bar = std::make_unique<StackPanel>(Orientation::Horizontal, 8.0f);
                auto add = std::make_unique<Button>(
                    I18n::Instance().T(Str::CommonAdd), ButtonStyle::Primary);
                add->id = "firewall.add";
                Button* add_raw = static_cast<Button*>(bar->Add(std::move(add)));
                add_ = add_raw;
                add_raw->on_click = [this] { ShowAddForm(); };
                host.Add(std::move(bar));

                // batch115: the same "silent loss" class as the lease page -
                // a rule write failure means the in-memory rules are not on
                // disk. Warn on the page that owns the rules.
                auto hint = std::make_unique<Text>(
                    I18n::Instance().T(Str::RulesPersistFailed),
                    FontToken::Small, ColorToken::Warning, true);
                hint->id = "firewall.rules_persist_hint";
                hint->visible = false;
                rules_hint_ = static_cast<Text*>(host.Add(std::move(hint)));

                auto discarded = std::make_unique<Text>(
                    I18n::Instance().T(Str::RulesDiscarded),
                    FontToken::Small, ColorToken::Warning, true);
                discarded->id = "firewall.rules_discarded_hint";
                discarded->visible = false;
                discarded_hint_ =
                    static_cast<Text*>(host.Add(std::move(discarded)));

                // R4a: table + empty inside a FillPanel so an empty table
                // shows a centred placeholder instead of a thin band.
                auto fill = std::make_unique<FillPanel>();
                FillPanel* fill_raw =
                    static_cast<FillPanel*>(host.Add(std::move(fill)));
                // B5-2: bounded viewport - claim the host's leftover height.
                fill_raw->fill_remaining = true;
                table_ = fill_raw->SetTable(std::make_unique<TableElement>());
                table_->id = "firewall.table";
                // batch29: widths follow the measured content ("type" is 2-3
                // chars, "value" a MAC/address), then stretch to fill the
                // table.
                table_->SetColumns(std::vector<TableColumn>{
                    TableColumn{"kind", Str::ColType, 110.0f, Align::Start,
                                0.0f, true},
                    TableColumn{"value", Str::ColValue, 220.0f, Align::Start,
                                0.0f, true}});
                table_->SetRowActions(std::vector<Str>{Str::CommonDelete});
                table_->on_row_action =
                    [this](const std::string& row_id, std::size_t) { RemoveEntry(row_id); };

                empty_ = fill_raw->SetEmpty(
                    std::make_unique<EmptyState>(Str::FirewallEmptyHint));
                empty_->id = "page.firewall.empty";
                empty_->visible = false;

                // batch33 E: right-click menu on a ban row (delete + copy).
                auto menu = std::make_unique<ContextMenu>();
                menu->id = "firewall.context_menu";
                context_menu_ = static_cast<ContextMenu*>(
                    host.Add(std::move(menu)));
                table_->on_row_context =
                    [this](const std::string& row_id, Point at) {
                        OpenRowMenu(row_id, at);
                    };

                dialog_ = static_cast<DialogHost*>(
                    host.Add(std::make_unique<DialogHost>()));
                dialog_->id = "firewall.dialog";
            }

            void FirewallPage::OpenRowMenu(const std::string& row_id, Point at) {
                if (context_menu_ == nullptr) {
                    return;
                }
                menu_row_ = row_id;
                const I18n& i18n = I18n::Instance();
                std::vector<ContextMenu::Item> items;
                items.push_back(ContextMenu::Item{
                    i18n.T(Str::CommonDelete), true,
                    [this] { RemoveEntry(menu_row_); }});
                // batch283: the row is a ban, whose "value" column is a MAC or
                // an IP. Labelling this "Copy MAC" told operators on an IP ban
                // that they would get a MAC and then handed them the IP. Name
                // the VALUE - the same word the column header uses - so the
                // entry is truthful for every ban kind (and for any kind added
                // later, since no per-kind branch is involved).
                items.push_back(ContextMenu::Item{
                    i18n.T(Str::CtxMenuCopyValue), false, [this] {
                        // batch282: `menu_row_` is the ban's STABLE id, while
                        // the copy used to read a vector indexed by RENDER
                        // POSITION - so it either read out of range ("copy
                        // failed") or put a DIFFERENT ban's value on the
                        // clipboard. Look the entry up by id, exactly like the
                        // delete path already does.
                        std::wstring text;
                        if (const auto* ban = FindBan(menu_row_)) {
                            text = Widen(ban->value);
                        }
                        if (text.empty() ||
                            !console_log::CopyToClipboard(text)) {
                            if (ctx_ != nullptr && ctx_->toast) {
                                ctx_->toast(Str::ConsoleCopyFailed,
                                            ToastKind::Warning);
                            }
                            return;
                        }
                        if (ctx_ != nullptr && ctx_->toast) {
                            ctx_->toast(Str::CommonCopied, ToastKind::Success);
                        }
                    }});
                context_menu_->SetClientRect(host_ != nullptr ? host_->bounds()
                                                              : Rect{});
                context_menu_->Show(at, std::move(items));
                RelayoutHost(*host_);
            }

            void FirewallPage::OnIntent(const std::string& intent) {
                // "mac=<MAC>" - a device row / the dashboard menu asked to ban
                // this MAC: open the add form with kind=mac pre-filled. A
                // malformed MAC only navigates.
                constexpr const char* kPrefix = "mac=";
                if (intent.rfind(kPrefix, 0) != 0) {
                    return;
                }
                const std::string value = intent.substr(4);
                vgww::core::MacAddress parsed{};
                if (!vgww::core::ParseMac(value, parsed)) {
                    return;
                }
                ShowAddFormFor(L"mac", Widen(vgww::core::FormatMac(parsed)));
            }

            void FirewallPage::ShowAddForm() {
                ShowAddFormFor(L"mac", std::wstring());
            }

            void FirewallPage::ShowAddFormFor(const std::wstring& kind,
                                              const std::wstring& value) {
                if (dialog_ == nullptr) {
                    return;
                }
                std::vector<FormField> fields;
                fields.push_back(FormField{"kind", Str::ColType, FormFieldType::Select,
                                           kind.empty() ? L"mac" : kind,
                                           {{L"mac", L"mac"}, {L"ip", L"ip"}}});
                fields.push_back(FormField{"value", Str::ColValue, FormFieldType::Text,
                                           value, {}});
                dialog_->ShowForm(Str::CommonAdd, std::move(fields),
                                  [this](const FormResult& result) {
                                      SubmitForm(result);
                                  });
                RelayoutHost(*host_);
            }

            void FirewallPage::SubmitForm(const FormResult& result) {
                const std::string kind = Narrow(FormValue(result, "kind"));
                const std::string value = Narrow(FormValue(result, "value"));

                pending_error_ = Str::_Count;
                std::string canonical;
                if (kind == "mac") {
                    vgww::core::MacAddress mac{};
                    if (!vgww::core::ParseMac(value, mac)) {
                        pending_error_ = Str::ErrMacFormat;
                        return;
                    }
                    canonical = vgww::core::FormatMac(mac);
                } else if (kind == "ip") {
                    bool ok = false;
                    const uint32_t parsed = vgww::core::ParseIpv4(value, ok);
                    if (!ok) {
                        pending_error_ = Str::ErrBanIp;
                        return;
                    }
                    canonical = vgww::core::FormatIpv4(parsed);
                } else {
                    pending_error_ = Str::ErrBanKind;
                    return;
                }
                if (ctx_ == nullptr || ctx_->controller == nullptr) {
                    return;
                }
                SubmitCommand(*ctx_, Command{AddBanCmd{kind, canonical}});
            }

            const vgww::web::BanEntry* FirewallPage::FindBan(
                const std::string& row_id) const {
                uint64_t id = 0;
                if (!ParseIndex(row_id, id)) {
                    return nullptr;
                }
                for (const auto& ban : bans_) {
                    if (ban.id == id) {
                        return &ban;
                    }
                }
                return nullptr;
            }

            void FirewallPage::RemoveEntry(const std::string& row_id) {
                uint64_t id = 0;
                if (dialog_ == nullptr || !ParseIndex(row_id, id)) {
                    return;
                }
                // batch138: confirm the BAN (kind + value), not its row number,
                // and carry the stable id across the async hop.
                // batch292: an id that no longer matches any ban (the table
                // was refreshed between the click and this call) must NOT
                // open a confirmation. It used to fall back to the raw id and
                // show "Delete 5?", then queue RemoveBanCmd{id:5} - the same
                // defect batch264 fixed on the port-map page.
                const auto* ban = FindBan(row_id);
                if (ban == nullptr) {
                    return;
                }
                std::wstring summary = Widen(ban->kind);
                summary += L" ";
                summary += Widen(ban->value);
                dialog_->ShowConfirm(
                    Str::CommonDelete,
                    I18n::Instance().Format(Str::CommonConfirmDeleteFmt,
                                            {summary}),
                    [this, id] {
                        if (ctx_ != nullptr && ctx_->controller != nullptr) {
                            RemoveBanCmd cmd;
                            cmd.id = id;
                            SubmitCommand(*ctx_, Command{cmd});
                        }
                    });
                RelayoutHost(*host_);
            }

            void FirewallPage::Update(const UiSnapshot& snapshot, I18n& i18n) {
                (void)i18n;  // kind/value cells are language-neutral
                bans_ = snapshot.bans;  // batch138: keep for the confirm
                std::vector<TableRow> rows;
                rows.reserve(snapshot.bans.size());
                for (std::size_t i = 0; i < snapshot.bans.size(); ++i) {
                    const vgww::web::BanEntry& ban = snapshot.bans[i];
                    TableRow row;
                    // batch138: stable id, not the render position.
                    row.row_id = std::to_string(ban.id);
                    // batch91: build the two cells with reserve + push_back
                    // instead of a braced initializer. A braced list of
                    // std::wstring constructs temporary elements and then
                    // copies them into the vector, so every cell that does not
                    // fit the small-object buffer is allocated TWICE. Measured
                    // on a 512-ban fixture: 5.01 allocations per row with the
                    // braced form, 4.01 with this one - one avoidable heap
                    // allocation per ban per tick, on the UI thread.
                    row.cells.clear();
                    row.cells.reserve(2);
                    row.cells.push_back(Widen(ban.kind));
                    row.cells.push_back(Widen(ban.value));
                    rows.push_back(std::move(row));
                }
                table_->SetRows(std::move(rows));
                empty_->visible = snapshot.bans.empty();
                empty_->SetMessage(Str::FirewallEmptyHint);  // relabel on a language switch
                if (add_ != nullptr) {
                    add_->SetLabel(i18n.T(Str::CommonAdd));
                }
                if (rules_hint_ != nullptr) {
                    const bool failed =
                        snapshot.rules_persist_failures > 0;
                    if (rules_hint_->visible != failed) {
                        rules_hint_->visible = failed;
                        RelayoutHost(*host_);
                    }
                    if (failed) {
                        rules_hint_->SetText(
                            i18n.T(Str::RulesPersistFailed));
                    }
                }
                if (discarded_hint_ != nullptr) {
                    const bool dropped = snapshot.rules_discarded > 0;
                    if (discarded_hint_->visible != dropped) {
                        discarded_hint_->visible = dropped;
                        RelayoutHost(*host_);
                    }
                    if (dropped) {
                        discarded_hint_->SetText(
                            i18n.T(Str::RulesDiscarded));
                    }
                }
                if (pending_error_ != Str::_Count) {
                    const Str message = pending_error_;
                    pending_error_ = Str::_Count;
                    ShowError(message);
                }
            }

            void FirewallPage::ShowError(Str message) {
                if (dialog_ == nullptr) {
                    return;
                }
                // Field-specific error, shown by the next Update (T8 D3).
                dialog_->ShowMessage(Str::CommonError, I18n::Instance().T(message),
                                     Str::CommonOk);
                RelayoutHost(*host_);
            }

        }  // namespace

        std::unique_ptr<Page> MakeFirewallPage() {
            return std::make_unique<FirewallPage>();
        }

    }  // namespace ui
}  // namespace vgww
