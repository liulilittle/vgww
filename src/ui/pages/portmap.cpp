// ============================================================================
// portmap.cpp - port mapping page (S4.3 Task 9): one table (protocol, WAN
// port, LAN IP, LAN port) with an add form and confirm-to-delete. Element ids
// follow the plan anchors (`portmap.*` / `page.portmap.empty`).
// ============================================================================
#include "ui/pages/page.h"

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

            /// Decimal port text: 1..65535 (the backend rejects 0/overflow).
            bool ParsePort(const std::string& text, uint16_t& out) {
                if (text.empty() || text.size() > 5) {
                    return false;
                }
                uint32_t value = 0;
                for (const char c : text) {
                    if (c < '0' || c > '9') {
                        return false;
                    }
                    value = value * 10 + static_cast<uint32_t>(c - '0');
                }
                if (value < 1 || value > 65535) {
                    return false;
                }
                out = static_cast<uint16_t>(value);
                return true;
            }

            /// batch138: row ids are the rule's STABLE id (PortMappingRule::id),
            /// not its position. Parsing stays strict so a malformed row id can
            /// never resolve to 0 and delete the first rule.
            bool ParseRuleId(const std::string& text, uint64_t& out) {
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

            /// "tcp 8080 -> 192.168.1.50:80" - the row as the user sees it.
            /// The delete confirmation used to print the raw row index, so it
            /// read "Delete 1?" and the user had to guess which rule that was.
            std::wstring RuleSummary(const vgww::web::PortMappingRule& rule) {
                std::wstring text = Widen(rule.proto);
                text += L" ";
                text += std::to_wstring(rule.wan_port);
                text += L" \u2192 ";
                text += Widen(rule.lan_ip);
                text += L":";
                text += std::to_wstring(rule.lan_port);
                return text;
            }

            class PortmapPage final : public Page {
            public:
                const char* id() const override { return "portmap"; }
                Str title() const override { return Str::NavPortmap; }
                void Build(Element& host, PageContext& ctx) override;
                void Update(const UiSnapshot& snapshot, I18n& i18n) override;

            private:
                void ShowAddForm();
                void SubmitForm(const FormResult& result);
                void RemoveRule(const std::string& row_id);
                const vgww::web::PortMappingRule* FindRule(
                    const std::string& row_id) const;

                /// batch138: the last rendered rows, kept so the delete
                /// confirmation can name the rule the user actually clicked
                /// (and so its id survives until the command is built).
                vgww::web::RuleList<vgww::web::PortMappingRule> rules_;
                void ShowError(Str message);

                PageContext* ctx_ = nullptr;
                Element* host_ = nullptr;
                DialogHost* dialog_ = nullptr;
                Button* add_ = nullptr;
                TableElement* table_ = nullptr;
                EmptyState* empty_ = nullptr;
                /// batch34f: runtime health line under the table. A rule in
                /// the list does NOT prove an acceptor exists.
                Text* status_ = nullptr;
                Str pending_error_ = Str::_Count;  ///< shown on the next Update
            };

            void PortmapPage::Build(Element& host, PageContext& ctx) {
                ctx_ = &ctx;
                host_ = &host;

                auto bar = std::make_unique<StackPanel>(Orientation::Horizontal, 8.0f);
                auto add = std::make_unique<Button>(
                    I18n::Instance().T(Str::CommonAdd), ButtonStyle::Primary);
                add->id = "portmap.add";
                Button* add_raw = static_cast<Button*>(bar->Add(std::move(add)));
                add_ = add_raw;
                add_raw->on_click = [this] { ShowAddForm(); };
                host.Add(std::move(bar));

                // R4a: table + empty inside a FillPanel so an empty table
                // shows a centred placeholder instead of a thin band.
                auto fill = std::make_unique<FillPanel>();
                FillPanel* fill_raw =
                    static_cast<FillPanel*>(host.Add(std::move(fill)));
                // B5-2: bounded viewport - claim the host's leftover height.
                fill_raw->fill_remaining = true;
                table_ = fill_raw->SetTable(std::make_unique<TableElement>());
                table_->id = "portmap.table";
                // batch29: column widths follow the MEASURED content (widest
                // cell or header + inset), then stretch proportionally to fill
                // the table. The old fixed weights made a 3-char "tcp" column
                // as wide as a full IPv4 one.
                table_->SetColumns(std::vector<TableColumn>{
                    TableColumn{"proto", Str::ColProto, 60.0f, Align::Start,
                                120.0f, true},
                    TableColumn{"wan_port", Str::ColWanPort, 100.0f,
                                Align::End, 160.0f, true},
                    TableColumn{"lan_ip", Str::ColLanIp, 200.0f, Align::Start,
                                0.0f, true},
                    TableColumn{"lan_port", Str::ColLanPort, 100.0f,
                                Align::End, 160.0f, true}});
                status_ = static_cast<Text*>(host.Add(std::make_unique<Text>(
                    L"", FontToken::Small, ColorToken::TextDim, true)));
                status_->id = "portmap.status";
                table_->SetRowActions(std::vector<Str>{Str::CommonDelete});
                table_->on_row_action =
                    [this](const std::string& row_id, std::size_t) { RemoveRule(row_id); };

                empty_ = fill_raw->SetEmpty(
                    std::make_unique<EmptyState>(Str::PortmapEmptyHint));
                empty_->id = "page.portmap.empty";
                empty_->visible = false;

                dialog_ = static_cast<DialogHost*>(
                    host.Add(std::make_unique<DialogHost>()));
                dialog_->id = "portmap.dialog";
            }

            void PortmapPage::ShowAddForm() {
                if (dialog_ == nullptr) {
                    return;
                }
                std::vector<FormField> fields;
                // SelectElement has no disabled option: the dropdown carries
                // the single supported protocol and the label states the
                // limitation (the backend rejects UDP with 400).
                fields.push_back(FormField{"proto", Str::FormProtoTcpOnly,
                                           FormFieldType::Select, L"tcp",
                                           {{L"tcp", L"tcp"}}});
                fields.push_back(FormField{"wan_port", Str::ColWanPort,
                                           FormFieldType::Text, L"", {}});
                fields.push_back(FormField{"lan_ip", Str::ColLanIp,
                                           FormFieldType::Text, L"", {}});
                fields.push_back(FormField{"lan_port", Str::ColLanPort,
                                           FormFieldType::Text, L"", {}});
                dialog_->ShowForm(Str::CommonAdd, std::move(fields),
                                  [this](const FormResult& result) {
                                      SubmitForm(result);
                                  });
                RelayoutHost(*host_);
            }

            void PortmapPage::SubmitForm(const FormResult& result) {
                const std::string proto = Narrow(FormValue(result, "proto"));
                const std::string wan = Narrow(FormValue(result, "wan_port"));
                const std::string lan_ip = Narrow(FormValue(result, "lan_ip"));
                const std::string lan = Narrow(FormValue(result, "lan_port"));

                pending_error_ = Str::_Count;
                if (proto != "tcp") {
                    pending_error_ = Str::ErrProtoTcp;
                    return;
                }
                uint16_t wan_port = 0;
                if (!ParsePort(wan, wan_port)) {
                    pending_error_ = Str::ErrWanPort;
                    return;
                }
                uint16_t lan_port = 0;
                if (!ParsePort(lan, lan_port)) {
                    pending_error_ = Str::ErrLanPort;
                    return;
                }
                bool ok = false;
                const uint32_t parsed = vgww::core::ParseIpv4(lan_ip, ok);
                if (!ok) {
                    pending_error_ = Str::ErrLanIp;
                    return;
                }
                if (ctx_ == nullptr || ctx_->controller == nullptr) {
                    return;
                }
                SubmitCommand(*ctx_, Command{AddPortMapCmd{
                    "tcp", wan_port, vgww::core::FormatIpv4(parsed), lan_port}});
            }

            const vgww::web::PortMappingRule* PortmapPage::FindRule(
                const std::string& row_id) const {
                uint64_t id = 0;
                if (!ParseRuleId(row_id, id)) {
                    return nullptr;
                }
                for (const auto& rule : rules_) {
                    if (rule.id == id) {
                        return &rule;
                    }
                }
                return nullptr;
            }

            void PortmapPage::RemoveRule(const std::string& row_id) {
                uint64_t id = 0;
                if (dialog_ == nullptr || !ParseRuleId(row_id, id)) {
                    return;
                }
                // batch138: confirm the RULE, not its row number, and carry the
                // stable id across the async confirm -> worker hop. A position
                // is only valid for the instant the table was drawn.
                // batch264: an id that no longer matches any rule (the table
                // was refreshed between the click and this call) must NOT open
                // a confirmation. It used to fall back to the raw id and show
                // Delete 0?, then queue RemovePortMapCmd{id:0}.
                const auto* rule = FindRule(row_id);
                if (rule == nullptr) {
                    return;
                }
                const std::wstring summary = RuleSummary(*rule);
                dialog_->ShowConfirm(
                    Str::CommonDelete,
                    I18n::Instance().Format(Str::CommonConfirmDeleteFmt,
                                            {summary}),
                    [this, id] {
                        if (ctx_ != nullptr && ctx_->controller != nullptr) {
                            RemovePortMapCmd cmd;
                            cmd.id = id;
                            SubmitCommand(*ctx_, Command{cmd});
                        }
                    });
                RelayoutHost(*host_);
            }

            void PortmapPage::Update(const UiSnapshot& snapshot, I18n& i18n) {
                (void)i18n;  // protocol/port/IP cells are language-neutral
                rules_ = snapshot.portmaps;  // batch138: keep for the confirm
                std::vector<TableRow> rows;
                rows.reserve(snapshot.portmaps.size());
                for (std::size_t i = 0; i < snapshot.portmaps.size(); ++i) {
                    const vgww::web::PortMappingRule& rule = snapshot.portmaps[i];
                    TableRow row;
                    // batch138: identify the row by the rule's stable id, not
                    // by its position in this render.
                    row.row_id = std::to_string(rule.id);
                    // batch93: reserve + push_back instead of a braced list.
                    // The braced form constructs temporary wstring elements and
                    // copies them in, so the lan_ip cell (a 13-char dotted quad,
                    // past the small-object buffer) allocates twice.
                    row.cells.clear();
                    row.cells.reserve(4);
                    row.cells.push_back(Widen(rule.proto));
                    row.cells.push_back(std::to_wstring(rule.wan_port));
                    row.cells.push_back(Widen(rule.lan_ip));
                    row.cells.push_back(std::to_wstring(rule.lan_port));
                    rows.push_back(std::move(row));
                }
                table_->SetRows(std::move(rows));
                empty_->visible = snapshot.portmaps.empty();
                empty_->SetMessage(Str::PortmapEmptyHint);  // relabel on a language switch
                if (add_ != nullptr) {
                    add_->SetLabel(i18n.T(Str::CommonAdd));
                }
                // batch34f: name the exact ports that failed to bind. A rule
                // can sit in the table while nothing is forwarded; without
                // this line the user has no way to tell.
                if (status_ != nullptr) {
                    const auto& st = snapshot.portmap_stats;
                    if (st.bind_failed > 0 && !st.failed_ports.empty()) {
                        std::wstring ports;
                        for (size_t k = 0; k < st.failed_ports.size(); ++k) {
                            if (k != 0) {
                                ports += L", ";
                            }
                            ports += std::to_wstring(st.failed_ports[k]);
                        }
                        std::wstring busy_line =
                            i18n.T(Str::PortmapPortBusy);
                        busy_line += L" (";
                        busy_line += ports;
                        busy_line += L")";
                        status_->SetText(busy_line);
                        status_->SetColor(ColorToken::Warning);
                    } else if (!snapshot.portmaps.empty()) {
                        // batch333: format the template through I18n::Format
                        // instead of hand-replacing two literal "%s" tokens
                        // positionally. The old loop silently dropped the
                        // dial-failure count when the template carried only
                        // one token and swapped the two numbers when a
                        // translation reordered them; the indexed template
                        // "{0}"/"{1}" is checked for order by the i18n gate
                        // across every language.
                        status_->SetText(i18n.Format(Str::PortmapLiveSummary,
                                                     {std::to_wstring(st.accepted),
                                                      std::to_wstring(st.dial_failed)}));
                        status_->SetColor(ColorToken::TextDim);
                    } else {
                        status_->SetText(std::wstring());
                    }
                }
                if (pending_error_ != Str::_Count) {
                    const Str message = pending_error_;
                    pending_error_ = Str::_Count;
                    ShowError(message);
                }
            }

            void PortmapPage::ShowError(Str message) {
                if (dialog_ == nullptr) {
                    return;
                }
                // DialogHost has no inline error slot and Confirm() always
                // closes after on_submit: the field-specific error is a
                // message dialog driven by the next Update (T8 D3).
                dialog_->ShowMessage(Str::CommonError, I18n::Instance().T(message),
                                     Str::CommonOk);
                RelayoutHost(*host_);
            }

        }  // namespace

        std::unique_ptr<Page> MakePortmapPage() {
            return std::make_unique<PortmapPage>();
        }

    }  // namespace ui
}  // namespace vgww
