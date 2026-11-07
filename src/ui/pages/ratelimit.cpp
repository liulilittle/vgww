// ============================================================================
// ratelimit.cpp - per-client rate limit page (S4.3 Task 9): one table (MAC,
// up kbps, down kbps) with an add/edit form (0 = unlimited, both zero is
// rejected like the backend) and confirm-to-delete. Element ids follow the
// plan anchors (`ratelimit.*` / `page.ratelimit.empty`).
// ============================================================================
#include "ui/pages/page.h"

#include "ui/console_log.h"
#include "ui/controller.h"
#include "ui/pages/page_util.h"

#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace vgww {
    namespace ui {

        namespace {

            /// kbps text: empty means 0 (no cap for that direction), otherwise
            /// decimal digits up to UINT32_MAX.
            bool ParseKbps(const std::string& text, uint32_t& out) {
                if (text.empty()) {
                    out = 0;
                    return true;
                }
                uint64_t value = 0;
                for (const char c : text) {
                    if (c < '0' || c > '9') {
                        return false;
                    }
                    value = value * 10 + static_cast<uint64_t>(c - '0');
                    if (value > 0xFFFFFFFFull) {
                        return false;
                    }
                }
                out = static_cast<uint32_t>(value);
                return true;
            }

            class RatelimitPage final : public Page {
            public:
                const char* id() const override { return "ratelimit"; }
                Str title() const override { return Str::NavRatelimit; }
                void Build(Element& host, PageContext& ctx) override;
                void Update(const UiSnapshot& snapshot, I18n& i18n) override;
                /// batch33 D: "mac=<MAC>" opens the add form with the MAC
                /// pre-filled (up/down stay empty: the operator decides).
                void OnIntent(const std::string& intent) override;

            private:
                void ShowForm(Str title, const std::wstring& mac,
                              const std::wstring& up, const std::wstring& down,
                              const std::wstring& original_mac);
                void SubmitForm(const FormResult& result,
                                const std::wstring& original_mac);
                void OnRowAction(const std::string& row_id, std::size_t action);
                void RemoveRule(const std::string& mac);
                void ShowError(Str message);
                const vgww::web::RateLimitRule* FindRule(const std::string& mac) const;
                void OpenRowMenu(const std::string& mac, Point at);

                PageContext* ctx_ = nullptr;
                Element* host_ = nullptr;
                DialogHost* dialog_ = nullptr;
                Button* add_ = nullptr;
                TableElement* table_ = nullptr;
                EmptyState* empty_ = nullptr;
                ContextMenu* context_menu_ = nullptr;
                std::string menu_mac_;
                Str pending_error_ = Str::_Count;  ///< shown on the next Update
                std::string first_client_mac_;     ///< add-form suggestion
                /// batch129: zero-copy view over the snapshot (was a full copy
                /// of every rule on each tick).
                vgww::web::RuleList<vgww::web::RateLimitRule> rules_;
            };

            void RatelimitPage::Build(Element& host, PageContext& ctx) {
                ctx_ = &ctx;
                host_ = &host;

                auto bar = std::make_unique<StackPanel>(Orientation::Horizontal, 8.0f);
                auto add = std::make_unique<Button>(
                    I18n::Instance().T(Str::CommonAdd), ButtonStyle::Primary);
                add->id = "ratelimit.add";
                Button* add_raw = static_cast<Button*>(bar->Add(std::move(add)));
                add_ = add_raw;
                add_raw->on_click = [this] {
                    ShowForm(Str::CommonAdd, Widen(first_client_mac_), L"", L"",
                             std::wstring());
                };
                host.Add(std::move(bar));

                // R4a: table + empty live inside a FillPanel so an empty
                // table shows a centred placeholder instead of a thin band.
                auto fill = std::make_unique<FillPanel>();
                FillPanel* fill_raw =
                    static_cast<FillPanel*>(host.Add(std::move(fill)));
                // B5-2: bounded viewport - claim the host's leftover height.
                fill_raw->fill_remaining = true;
                table_ = fill_raw->SetTable(std::make_unique<TableElement>());
                table_->id = "ratelimit.table";
                {
                    // batch29: the widths are the MEASURED content widths (a
                    // 17-char MAC vs a <= 10-digit kbps value) plus the inset,
                    // then the leftover is spread proportionally so the table
                    // still fills exactly. An unchanged table never re-measures
                    // (TableElement caches the natural widths per content
                    // revision), and a cell that cannot fit is ellipsized with
                    // its full text exposed via TableElement::tooltip_text.
                    table_->SetColumns(std::vector<TableColumn>{
                        TableColumn{"mac", Str::ColMac, 170.0f, Align::Start,
                                    0.0f, true},
                        TableColumn{"up_kbps", Str::ColUpKbps, 100.0f,
                                    Align::End, 0.0f, true},
                        TableColumn{"down_kbps", Str::ColDownKbps, 100.0f,
                                    Align::End, 0.0f, true}});
                }
                table_->SetRowActions(
                    std::vector<Str>{Str::CommonEdit, Str::CommonDelete});
                table_->on_row_action =
                    [this](const std::string& row_id, std::size_t action) {
                        OnRowAction(row_id, action);
                    };

                empty_ = fill_raw->SetEmpty(
                    std::make_unique<EmptyState>(Str::RatelimitEmptyHint));
                empty_->id = "page.ratelimit.empty";
                empty_->visible = false;

                // batch33 E: right-click menu on a rule row (delete + copy).
                auto menu = std::make_unique<ContextMenu>();
                menu->id = "ratelimit.context_menu";
                context_menu_ = static_cast<ContextMenu*>(
                    host.Add(std::move(menu)));
                table_->on_row_context =
                    [this](const std::string& row_id, Point at) {
                        OpenRowMenu(row_id, at);
                    };

                dialog_ = static_cast<DialogHost*>(
                    host.Add(std::make_unique<DialogHost>()));
                dialog_->id = "ratelimit.dialog";
            }

            void RatelimitPage::OpenRowMenu(const std::string& mac, Point at) {
                if (context_menu_ == nullptr) {
                    return;
                }
                menu_mac_ = mac;
                const I18n& i18n = I18n::Instance();
                std::vector<ContextMenu::Item> items;
                items.push_back(ContextMenu::Item{
                    i18n.T(Str::CommonDelete), true,
                    [this] { RemoveRule(menu_mac_); }});
                items.push_back(ContextMenu::Item{
                    i18n.T(Str::CtxMenuCopyMac), false, [this] {
                        if (!console_log::CopyToClipboard(Widen(menu_mac_))) {
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

            void RatelimitPage::OnIntent(const std::string& intent) {
                // "mac=<MAC>" - a device row (or the dashboard's context menu)
                // asked for a pre-filled rule form. A malformed MAC only
                // navigates (never opens a form with garbage).
                constexpr const char* kPrefix = "mac=";
                if (intent.rfind(kPrefix, 0) != 0) {
                    return;
                }
                const std::string value = intent.substr(4);
                vgww::core::MacAddress parsed{};
                if (!vgww::core::ParseMac(value, parsed)) {
                    return;
                }
                ShowForm(Str::CommonAdd,
                         Widen(vgww::core::FormatMac(parsed)), L"", L"",
                         std::wstring());
            }

            void RatelimitPage::ShowForm(Str title, const std::wstring& mac,
                                         const std::wstring& up,
                                         const std::wstring& down,
                                         const std::wstring& original_mac) {
                if (dialog_ == nullptr) {
                    return;
                }
                std::vector<FormField> fields;
                fields.push_back(FormField{"mac", Str::FormMac, FormFieldType::Text,
                                           mac, {}});
                fields.push_back(FormField{"up_kbps", Str::ColUpKbps,
                                           FormFieldType::Text, up, {}});
                fields.push_back(FormField{"down_kbps", Str::ColDownKbps,
                                           FormFieldType::Text, down, {}});
                dialog_->ShowForm(title, std::move(fields),
                                  [this, original_mac](const FormResult& result) {
                                      SubmitForm(result, original_mac);
                                  });
                RelayoutHost(*host_);
            }

            void RatelimitPage::SubmitForm(const FormResult& result,
                                           const std::wstring& original_mac) {
                const std::string mac = Narrow(FormValue(result, "mac"));
                const std::string up = Narrow(FormValue(result, "up_kbps"));
                const std::string down = Narrow(FormValue(result, "down_kbps"));

                pending_error_ = Str::_Count;
                vgww::core::MacAddress parsed_mac{};
                if (!vgww::core::ParseMac(mac, parsed_mac)) {
                    pending_error_ = Str::ErrMacFormat;
                    return;
                }
                uint32_t up_kbps = 0;
                uint32_t down_kbps = 0;
                if (!ParseKbps(up, up_kbps) || !ParseKbps(down, down_kbps)) {
                    pending_error_ = Str::ErrKbps;
                    return;
                }
                if (up_kbps == 0 && down_kbps == 0) {
                    pending_error_ = Str::ErrUpDownZero;
                    return;
                }
                if (ctx_ == nullptr || ctx_->controller == nullptr) {
                    return;
                }
                const std::string canonical_mac = vgww::core::FormatMac(parsed_mac);
                const bool mac_changed =
                    !original_mac.empty() &&
                    canonical_mac != Narrow(original_mac);
                // batch136: add and edit share one command. A MAC edit carries
                // the OLD mac along (replace_mac) so the remove+insert happens
                // in ONE command; posting two commands let either half be
                // refused alone, which deleted the old rule and stored nothing.
                SetRateLimitCmd cmd;
                cmd.mac = canonical_mac;
                cmd.up_kbps = up_kbps;
                cmd.down_kbps = down_kbps;
                if (mac_changed) {
                    cmd.replace_mac = Narrow(original_mac);
                }
                SubmitCommand(*ctx_, Command{std::move(cmd)});
            }

            void RatelimitPage::OnRowAction(const std::string& row_id,
                                            std::size_t action) {
                if (action == 0) {  // [edit]
                    const vgww::web::RateLimitRule* rule = FindRule(row_id);
                    ShowForm(Str::CommonEdit, Widen(row_id),
                             rule != nullptr ? std::to_wstring(rule->uplink_kbps)
                                             : std::wstring(),
                             rule != nullptr ? std::to_wstring(rule->downlink_kbps)
                                             : std::wstring(),
                             Widen(row_id));
                    return;
                }
                RemoveRule(row_id);  // [delete]
            }

            void RatelimitPage::RemoveRule(const std::string& mac) {
                if (dialog_ == nullptr) {
                    return;
                }
                dialog_->ShowConfirm(
                    Str::CommonDelete,
                    I18n::Instance().Format(Str::CommonConfirmDeleteFmt, {Widen(mac)}),
                    [this, mac] {
                        if (ctx_ != nullptr && ctx_->controller != nullptr) {
                            SubmitCommand(*ctx_, Command{RemoveRateLimitCmd{mac}});
                        }
                    });
                RelayoutHost(*host_);
            }

            void RatelimitPage::Update(const UiSnapshot& snapshot, I18n& i18n) {
                (void)i18n;  // MAC/kbps cells are language-neutral
                rules_ = snapshot.ratelimits;
                first_client_mac_.clear();
                if (!snapshot.clients.empty()) {
                    first_client_mac_ = vgww::core::FormatMac(snapshot.clients.front().mac);
                }
                std::vector<TableRow> rows;
                rows.reserve(snapshot.ratelimits.size());
                for (const vgww::web::RateLimitRule& rule : snapshot.ratelimits) {
                    TableRow row;
                    row.row_id = rule.mac;
                    // batch93: build the cells with reserve + push_back rather
                    // than a braced initializer - a braced list of wstring
                    // constructs temporary elements and then COPIES them into
                    // the vector, so the 17-char MAC cell allocates twice.
                    row.cells.clear();
                    row.cells.reserve(3);
                    row.cells.push_back(Widen(rule.mac));
                    row.cells.push_back(std::to_wstring(rule.uplink_kbps));
                    row.cells.push_back(std::to_wstring(rule.downlink_kbps));
                    rows.push_back(std::move(row));
                }
                table_->SetRows(std::move(rows));
                empty_->visible = snapshot.ratelimits.empty();
                empty_->SetMessage(Str::RatelimitEmptyHint);  // relabel on a language switch
                if (add_ != nullptr) {
                    add_->SetLabel(i18n.T(Str::CommonAdd));
                }
                if (pending_error_ != Str::_Count) {
                    const Str message = pending_error_;
                    pending_error_ = Str::_Count;
                    ShowError(message);
                }
            }

            const vgww::web::RateLimitRule* RatelimitPage::FindRule(
                const std::string& mac) const {
                for (const vgww::web::RateLimitRule& rule : rules_) {
                    if (rule.mac == mac) {
                        return &rule;
                    }
                }
                return nullptr;
            }

            void RatelimitPage::ShowError(Str message) {
                if (dialog_ == nullptr) {
                    return;
                }
                // Field-specific error, shown by the next Update (T8 D3).
                dialog_->ShowMessage(Str::CommonError, I18n::Instance().T(message),
                                     Str::CommonOk);
                RelayoutHost(*host_);
            }

        }  // namespace

        std::unique_ptr<Page> MakeRatelimitPage() {
            return std::make_unique<RatelimitPage>();
        }

    }  // namespace ui
}  // namespace vgww
