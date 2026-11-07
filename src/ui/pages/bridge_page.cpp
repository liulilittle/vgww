// ============================================================================
// bridge_page.cpp - bridge page (S4.3 Task 10, read-only): state badge, the
// configured ports/table size and the live MAC table entry count. Element ids
// follow the plan anchors (`bridge.*` / `page.bridge.empty`).
// ============================================================================
#include "ui/pages/page.h"
#include "ui/pages/page_util.h"

#include "ui/format.h"

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
                // B6: fixed 120 px label column + filling value, so every row
                // aligns the same way regardless of label length.
                auto row = std::make_unique<GridLayout>(
                    std::vector<ColumnSpec>{ColumnSpec::Fixed(120.0f),
                                            ColumnSpec::Star()},
                    8.0f, Padding{});
                InfoRow out;
                out.key = label;
                auto label_text = std::make_unique<Text>(
                    I18n::Instance().T(label), FontToken::BodyStrong,
                    ColorToken::Text);
                label_text->id = std::string(value_id) + ".label";
                out.label = static_cast<Text*>(row->Add(std::move(label_text)));
                auto value = std::make_unique<Text>(L"-", FontToken::Body,
                                                    ColorToken::TextDim);
                value->id = value_id;
                out.value = static_cast<Text*>(row->Add(std::move(value)));
                host.Add(std::move(row));
                return out;
            }

            class BridgePage final : public Page {
            public:
                const char* id() const override { return "bridge"; }
                Str title() const override { return Str::NavBridge; }
                void Build(Element& host, PageContext& ctx) override;
                void Update(const UiSnapshot& snapshot, I18n& i18n) override;

            private:
                void RefreshLabels(I18n& i18n);

                BadgeElement* status_ = nullptr;
                InfoRow enabled_;
                InfoRow upstream_;
                InfoRow downstream_;
                InfoRow table_size_;
                InfoRow mac_count_;
                Text* hint_ = nullptr;
                EmptyState* empty_ = nullptr;
                std::vector<InfoRow*> rows_;
            };

            void BridgePage::Build(Element& host, PageContext& ctx) {
                (void)ctx;  // read-only page: configuration lives on settings
                // B5: keep the state badge compact - a horizontal row stops the page
                // stack from stretching it into a full-width bar.
                auto status_bar =
                    std::make_unique<StackPanel>(Orientation::Horizontal, 8.0f);
                status_ = static_cast<BadgeElement*>(status_bar->Add(
                    std::make_unique<BadgeElement>(
                        I18n::Instance().T(Str::StatusStopped),
                        BadgeKind::Neutral)));
                status_->id = "bridge.status.badge";
                host.Add(std::move(status_bar));

                enabled_ = AddInfoRow(host, Str::FormBridgeEnabled, "bridge.enabled");
                upstream_ = AddInfoRow(host, Str::FormBridgeUp, "bridge.upstream");
                downstream_ = AddInfoRow(host, Str::FormBridgeDown, "bridge.downstream");
                table_size_ = AddInfoRow(host, Str::FormBridgeTable, "bridge.table_size");
                mac_count_ = AddInfoRow(host, Str::BridgeMacCount, "bridge.mac_count");
                rows_ = {&enabled_, &upstream_, &downstream_, &table_size_, &mac_count_};

                hint_ = static_cast<Text*>(host.Add(std::make_unique<Text>(
                    I18n::Instance().T(Str::BridgeRestartHint), FontToken::Small,
                    ColorToken::TextDim, true)));
                hint_->id = "bridge.hint";

                // R4a: the empty placeholder lives in a FillPanel so it fills
                // the remaining content column and centres instead of being a
                // thin band under the hint text.
                auto fill = std::make_unique<FillPanel>();
                FillPanel* fill_raw =
                    static_cast<FillPanel*>(host.Add(std::move(fill)));
                // B5-2: bounded viewport - claim the host's leftover height.
                fill_raw->fill_remaining = true;
                empty_ = fill_raw->SetEmpty(
                    std::make_unique<EmptyState>(Str::BridgeEmptyHint));
                empty_->id = "page.bridge.empty";
                empty_->visible = false;
            }

            void BridgePage::Update(const UiSnapshot& snapshot, I18n& i18n) {
                RefreshLabels(i18n);
                if (snapshot.bridge_state == vgww::bridge::BridgeState::kFailed) {
                    status_->SetText(i18n.T(Str::BridgeFailed));
                    status_->SetKind(BadgeKind::Danger);
                } else if (snapshot.bridge_state ==
                           vgww::bridge::BridgeState::kRunning) {
                    status_->SetText(i18n.T(Str::StatusRunning));
                    status_->SetKind(BadgeKind::Success);
                } else {
                    status_->SetText(i18n.T(Str::StatusStopped));
                    status_->SetKind(BadgeKind::Neutral);
                }

                const ConfigView& config = snapshot.config;
                enabled_.value->SetText(
                    i18n.T(config.bridge_enabled ? Str::CommonYes : Str::CommonNo));
                upstream_.value->SetText(config.bridge_up.empty()
                                             ? i18n.T(Str::CommonNotSet)
                                             : Widen(config.bridge_up));
                downstream_.value->SetText(config.bridge_down.empty()
                                               ? i18n.T(Str::CommonNotSet)
                                               : Widen(config.bridge_down));
                table_size_.value->SetText(FormatCount(config.bridge_table_size));
                mac_count_.value->SetText(FormatCount(snapshot.bridge_mac_count));
                empty_->visible = (snapshot.bridge_mac_count == 0);
                empty_->SetMessage(Str::BridgeEmptyHint);  // C5: follows the language
                // batch34h: a full MAC table silently evicts the least active
                // device, whose traffic then floods. Surface it instead of
                // letting the operator wonder why one host keeps broadcasting.
                if (hint_ != nullptr) {
                    if (snapshot.bridge_mac_evictions > 0) {
                        hint_->SetText(i18n.T(Str::BridgeMacTableFull));
                        hint_->SetColor(ColorToken::Warning);
                    } else {
                        hint_->SetText(i18n.T(Str::BridgeRestartHint));
                        hint_->SetColor(ColorToken::TextDim);
                    }
                }
            }

            void BridgePage::RefreshLabels(I18n& i18n) {
                for (InfoRow* row : rows_) {
                    row->label->SetText(i18n.T(row->key));
                }
                hint_->SetText(i18n.T(Str::BridgeRestartHint));
            }

        }  // namespace

        std::unique_ptr<Page> MakeBridgePage() {
            return std::make_unique<BridgePage>();
        }

    }  // namespace ui
}  // namespace vgww
