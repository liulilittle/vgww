// ============================================================================
// leases.cpp - leases page (S4.3 Task 8): four views (v4/v6 leases and v4/v6
// static bindings) behind a tab row. Add/edit/delete drive the T3 dialog
// control and the T4 command queue; every element id follows the plan anchors
// (`leases.*`) for the headless tests.
// ============================================================================
#include <winsock2.h>
#include <ws2ipdef.h>
#include <windows.h>

#include "core/limits.h"
#include "ui/pages/page.h"

#include "ui/controller.h"
#include "ui/format.h"
#include "ui/pages/page_util.h"

#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace vgww {
    namespace ui {

        namespace {

            /// DHCPv6 DUID text: hex digits with optional ':' '-' '.' separators,
            /// 1..128 bytes (an even digit count, no empty group).
            ///
            /// batch145: the separator set mirrors the ONE parser the DHCPv6
            /// store and the Web console share (runtime::ParseDuidText strips
            /// ':', '-' and '.'), so the same DUID cannot be "valid" in the
            /// browser and "invalid" here. Empty groups stay rejected on
            /// purpose: that parser removes EVERY separator, so it would read
            /// "00::01" as a DIFFERENT, 2-byte DUID - a typo is reported
            /// instead of being silently reinterpreted.
            bool IsValidDuid(const std::string& text) {
                std::size_t digits = 0;
                bool separator = true;  // rejects a leading separator
                for (const char c : text) {
                    if (c == ':' || c == '-' || c == '.') {
                        if (separator) {
                            return false;
                        }
                        separator = true;
                        continue;
                    }
                    const bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
                                     (c >= 'A' && c <= 'F');
                    if (!hex) {
                        return false;
                    }
                    separator = false;
                    ++digits;
                }
                if (separator || digits == 0 || (digits % 2) != 0) {
                    return false;
                }
                // digits is even and non-zero here, so bytes is 1..N.
                return (digits / 2) <= ::vgww::core::limits::kMaxDuidBytes;
            }

            bool ParseIpv6Text(const std::string& text, std::array<uint8_t, 16>& out) {
                if (text.empty()) {
                    return false;
                }
                const std::wstring wide = Widen(text);
                return 1 == ::InetPtonW(AF_INET6, wide.c_str(), out.data());
            }

            enum class LeaseTab { V4 = 0, V6 = 1, Bind4 = 2, Bind6 = 3 };
            constexpr std::size_t kTabCount = 4;

            const Str kTabKeys[kTabCount] = {Str::LeasesTabV4, Str::LeasesTabV6,
                                             Str::LeasesTabBind4, Str::LeasesTabBind6};
            const char* const kTabIds[kTabCount] = {"leases.tab.v4", "leases.tab.v6",
                                                    "leases.tab.bind4", "leases.tab.bind6"};
            const char* const kTableIds[kTabCount] = {
                "leases.table.v4", "leases.table.v6", "leases.table.bindings4",
                "leases.table.bindings6"};
            const char* const kEmptyIds[kTabCount] = {
                "leases.table.v4.empty", "leases.table.v6.empty",
                "leases.table.bindings4.empty", "leases.table.bindings6.empty"};
            const char* const kViewSuffixes[kTabCount] = {"v4", "v6", "bind4", "bind6"};
            const char* const kAddIds[2] = {"leases.add.v4", "leases.add.v6"};

            std::vector<TableColumn> LeaseColumns(bool v6) {
                std::vector<TableColumn> cols;
                cols.push_back(TableColumn{v6 ? "duid" : "mac",
                                           v6 ? Str::ColDuid : Str::ColMac, 170.0f,
                                           Align::Start});
                cols.push_back(TableColumn{"ip", Str::ColIp, 170.0f, Align::Start});
                cols.push_back(TableColumn{"hostname", Str::ColHostname, 140.0f,
                                           Align::Start});
                cols.push_back(TableColumn{"expiry", Str::ColTimeLeft, 110.0f, Align::End});
                cols.push_back(TableColumn{"type", Str::ColType, 90.0f, Align::End});
                return cols;
            }

            std::vector<TableColumn> BindingColumns(bool v6) {
                std::vector<TableColumn> cols;
                cols.push_back(TableColumn{v6 ? "duid" : "mac",
                                           v6 ? Str::ColDuid : Str::ColMac, 200.0f,
                                           Align::Start});
                cols.push_back(TableColumn{"ip", Str::ColIp, 180.0f, Align::Start});
                cols.push_back(TableColumn{"hostname", Str::ColHostname, 160.0f,
                                           Align::Start});
                return cols;
            }

            // M10-1: page-side rebuild key. The expiry column renders
            // `FormatTimeLeft` -> `FixedTimeText`, i.e. HH:MM:SS with SECOND
            // resolution (format.cpp), so the displayed text changes exactly
            // when `expires_in_s` changes by one. The bucket must therefore BE
            // the second: the old /60 bucket claimed the column showed "Xh Ym"
            // and froze the countdown for up to 59 s before jumping (batch280).
            // A static lease shows a fixed label and gets its own sentinel
            // (is_static is part of the key too, so the sentinel can never
            // collide with a dynamic value).
            constexpr uint32_t kStaticExpiryBucket = 0xFFFFFFFFu;

            uint32_t ExpiryBucket(
                const vgww::runtime::Dataplane::LeaseView& lease) noexcept {
                return lease.is_static ? kStaticExpiryBucket
                                       : lease.expires_in_s;
            }
            uint32_t ExpiryBucket(
                const vgww::runtime::Dataplane::Lease6View& lease) noexcept {
                return lease.is_static ? kStaticExpiryBucket
                                       : lease.expires_in_s;
            }

            bool SameLeaseRows(
                const std::vector<vgww::runtime::Dataplane::LeaseView>& a,
                const std::vector<vgww::runtime::Dataplane::LeaseView>& b) noexcept {
                if (a.size() != b.size()) {
                    return false;
                }
                for (std::size_t i = 0; i < a.size(); ++i) {
                    const auto& x = a[i];
                    const auto& y = b[i];
                    if (x.mac != y.mac || x.ip != y.ip || x.hostname != y.hostname ||
                        x.is_static != y.is_static ||
                        ExpiryBucket(x) != ExpiryBucket(y)) {
                        return false;
                    }
                }
                return true;
            }

            bool SameLease6Rows(
                const std::vector<vgww::runtime::Dataplane::Lease6View>& a,
                const std::vector<vgww::runtime::Dataplane::Lease6View>& b) noexcept {
                if (a.size() != b.size()) {
                    return false;
                }
                for (std::size_t i = 0; i < a.size(); ++i) {
                    const auto& x = a[i];
                    const auto& y = b[i];
                    if (x.duid != y.duid || x.ip != y.ip || x.hostname != y.hostname ||
                        x.is_static != y.is_static ||
                        ExpiryBucket(x) != ExpiryBucket(y)) {
                        return false;
                    }
                }
                return true;
            }

            bool SameBindingRows(
                const std::vector<vgww::runtime::Dataplane::BindingView>& a,
                const std::vector<vgww::runtime::Dataplane::BindingView>& b) noexcept {
                if (a.size() != b.size()) {
                    return false;
                }
                for (std::size_t i = 0; i < a.size(); ++i) {
                    if (a[i].mac != b[i].mac || a[i].ip != b[i].ip ||
                        a[i].hostname != b[i].hostname) {
                        return false;
                    }
                }
                return true;
            }

            bool SameBinding6Rows(
                const std::vector<vgww::runtime::Dataplane::Binding6View>& a,
                const std::vector<vgww::runtime::Dataplane::Binding6View>& b) noexcept {
                if (a.size() != b.size()) {
                    return false;
                }
                for (std::size_t i = 0; i < a.size(); ++i) {
                    if (a[i].duid != b[i].duid || a[i].ip != b[i].ip ||
                        a[i].hostname != b[i].hostname) {
                        return false;
                    }
                }
                return true;
            }

            class LeasesPage final : public Page {
            public:
                const char* id() const override { return "leases"; }
                Str title() const override { return Str::NavLeases; }
                void Build(Element& host, PageContext& ctx) override;
                void Update(const UiSnapshot& snapshot, I18n& i18n) override;
                /// batch33 D: "mac=<MAC>" switches to the matching view, then
                /// scrolls to that row and highlights it.
                void OnIntent(const std::string& intent) override;

            private:
                struct View {
                    Element* container = nullptr;
                    TableElement* table = nullptr;
                    EmptyState* empty = nullptr;
                    Button* add = nullptr;  ///< bindings views only
                };

                /// batch33 D: applies a pending row highlight once the tables
                /// have been (re)built - SetRows resets the table offset, so the
                /// scroll must run after the data lands.
                void ApplyPendingHighlight();
                void SetTab(LeaseTab tab, bool relayout);
                void ShowForm(LeaseTab tab, Str title, const std::wstring& key,
                              const std::wstring& ip, const std::wstring& hostname);
                void SubmitForm(LeaseTab tab, const FormResult& result,
                                const std::wstring& original_key);
                void OnRowAction(LeaseTab tab, const std::string& row_id,
                                 std::size_t action);
                void RemoveBinding(LeaseTab tab, const std::string& key);
                void ShowError(Str message);
                void UpdateTables(const UiSnapshot& snapshot, I18n& i18n);
                void Relabel();
                const vgww::runtime::Dataplane::BindingView* FindBinding4(
                    const std::string& mac) const;
                const vgww::runtime::Dataplane::Binding6View* FindBinding6(
                    const std::string& duid) const;

                PageContext* ctx_ = nullptr;
                Element* host_ = nullptr;
                DialogHost* dialog_ = nullptr;
                LeaseTab tab_ = LeaseTab::V4;
                Str pending_error_ = Str::_Count;  ///< shown on the next Update
                SegmentedControl* tabs_ = nullptr;
                View views_[kTabCount] = {};
                Text* hint_ = nullptr;
                std::vector<vgww::runtime::Dataplane::BindingView> bindings4_;
                std::vector<vgww::runtime::Dataplane::Binding6View> bindings6_;
                /// M10-1: last-built row keys (the bindings vectors above are
                /// the keys for the two binding views). When the language and
                /// every key compare equal the tables are not rebuilt at all -
                /// the interior SetRows equality short-circuit (controls.cpp)
                /// stays as the second line of defence for real rebuilds.
                std::vector<vgww::runtime::Dataplane::LeaseView> leases4_seen_;
                std::vector<vgww::runtime::Dataplane::Lease6View> leases6_seen_;
                bool rows_valid_ = false;
                Lang rows_lang_ = Lang::ZhCN;
                /// batch33 D: a pending "scroll to this MAC" highlight.
                std::string pending_highlight_;
            };

            void LeasesPage::OnIntent(const std::string& intent) {
                constexpr const char* kPrefix = "mac=";
                if (intent.rfind(kPrefix, 0) != 0) {
                    return;
                }
                const std::string mac = intent.substr(4);
                if (mac.empty()) {
                    return;
                }
                pending_highlight_ = mac;
                ApplyPendingHighlight();
            }

            void LeasesPage::ApplyPendingHighlight() {
                if (pending_highlight_.empty()) {
                    return;
                }
                // Prefer the view that actually contains the row: the v4 lease
                // table first, then its bindings view. (A v6 DUID is not a MAC
                // and never matches these two.)
                for (std::size_t i = 0; i < kTabCount; ++i) {
                    TableElement* table = views_[i].table;
                    if (table == nullptr || table->RowIndex(pending_highlight_) ==
                                                std::string::npos) {
                        continue;
                    }
                    if (tab_ != static_cast<LeaseTab>(i)) {
                        SetTab(static_cast<LeaseTab>(i), false);
                    }
                    table->ScrollToRow(pending_highlight_);
                    pending_highlight_.clear();
                    if (host_ != nullptr) {
                        RelayoutHost(*host_);
                    }
                    return;
                }
                // The row is not in the model (yet): keep the request pending so
                // the next snapshot can satisfy it.
            }

            void LeasesPage::Build(Element& host, PageContext& ctx) {
                ctx_ = &ctx;
                host_ = &host;

                auto tabs = std::make_unique<SegmentedControl>(
                    std::vector<std::wstring>{I18n::Instance().T(kTabKeys[0]),
                                               I18n::Instance().T(kTabKeys[1]),
                                               I18n::Instance().T(kTabKeys[2]),
                                               I18n::Instance().T(kTabKeys[3])});
                tabs->id = "leases.tabs";
                tabs->on_changed = [this](std::size_t index) {
                    SetTab(static_cast<LeaseTab>(index), true);
                };
                tabs_ = static_cast<SegmentedControl*>(host.Add(std::move(tabs)));

                for (std::size_t i = 0; i < kTabCount; ++i) {
                    const LeaseTab tab = static_cast<LeaseTab>(i);
                    const bool bindings =
                        (tab == LeaseTab::Bind4 || tab == LeaseTab::Bind6);
                    const bool v6 = (tab == LeaseTab::V6 || tab == LeaseTab::Bind6);
                    View& view = views_[i];

                    auto container =
                        std::make_unique<StackPanel>(Orientation::Vertical, 16.0f);
                    container->id = std::string("leases.view.") + kViewSuffixes[i];
                    view.container = static_cast<StackPanel*>(host.Add(std::move(container)));
                    // B5-2: the visible view container claims the host's
                    // leftover height (tabs and hint stay fixed); the table
                    // below claims the container's leftover in turn.
                    view.container->fill_remaining = true;

                    if (bindings) {
                        auto bar =
                            std::make_unique<StackPanel>(Orientation::Horizontal,
                                                         8.0f);
                        auto add = std::make_unique<Button>(
                            I18n::Instance().T(Str::CommonAdd),
                            ButtonStyle::Primary);
                        add->id = kAddIds[v6 ? 1 : 0];
                        view.add = static_cast<Button*>(bar->Add(std::move(add)));
                        view.add->on_click = [this, tab] {
                            ShowForm(tab, Str::CommonAdd, std::wstring(),
                                     std::wstring(), std::wstring());
                        };
                        view.container->Add(std::move(bar));
                    }

                    auto table = std::make_unique<TableElement>();
                    table->id = kTableIds[i];
                    // batch27 D2: table + placeholder share one FillPanel (the
                    // same shape portmap/firewall use), so an empty view
                    // centres its message in the region below the header band
                    // instead of leaving an unequal top/bottom gap.
                    auto fill = std::make_unique<FillPanel>();
                    fill->fill_remaining = true;
                    view.table = fill->SetTable(std::move(table));
                    view.table->SetColumns(bindings ? BindingColumns(v6)
                                                    : LeaseColumns(v6));
                    if (bindings) {
                        view.table->SetRowActions(
                            std::vector<Str>{Str::CommonEdit, Str::CommonDelete});
                        view.table->on_row_action =
                            [this, tab](const std::string& row_id, std::size_t action) {
                                OnRowAction(tab, row_id, action);
                            };
                    }

                    auto empty = std::make_unique<EmptyState>(Str::LeasesEmptyHint);
                    empty->id = kEmptyIds[i];
                    view.empty = fill->SetEmpty(std::move(empty));
                    view.container->Add(std::move(fill));
                }

                dialog_ = static_cast<DialogHost*>(
                    host.Add(std::make_unique<DialogHost>()));
                dialog_->id = "leases.dialog";

                hint_ = static_cast<Text*>(host.Add(std::make_unique<Text>(
                    I18n::Instance().T(Str::LeasesRuntimeHint), FontToken::Small,
                    ColorToken::TextDim, true)));
                hint_->id = "leases.runtime_hint";

                SetTab(LeaseTab::V4, false);
            }

            void LeasesPage::SetTab(LeaseTab tab, bool relayout) {
                tab_ = tab;
                for (std::size_t i = 0; i < kTabCount; ++i) {
                    views_[i].container->visible =
                        (static_cast<std::size_t>(tab) == i);
                }
                if (tabs_ != nullptr) {
                    tabs_->SetSelected(static_cast<std::size_t>(tab));
                }
                if (relayout && host_ != nullptr) {
                    RelayoutHost(*host_);
                }
            }

            void LeasesPage::Update(const UiSnapshot& snapshot, I18n& i18n) {
                // M10-1: rebuild only when the language or a row key changed.
                // Stats ticks re-publish byte-identical vectors (CollectStats
                // only writes light fields), so the key says equal and the four
                // tables (plus the dialog-prefill copies) are skipped entirely.
                const bool same =
                    rows_valid_ && i18n.Lang() == rows_lang_ &&
                    SameLeaseRows(snapshot.leases, leases4_seen_) &&
                    SameLease6Rows(snapshot.leases6, leases6_seen_) &&
                    SameBindingRows(snapshot.dhcp_bindings, bindings4_) &&
                    SameBinding6Rows(snapshot.dhcp6_bindings, bindings6_);
                if (!same) {
                    bindings4_ = snapshot.dhcp_bindings;
                    bindings6_ = snapshot.dhcp6_bindings;
                    leases4_seen_ = snapshot.leases;
                    leases6_seen_ = snapshot.leases6;
                    UpdateTables(snapshot, i18n);
                    rows_lang_ = i18n.Lang();
                    rows_valid_ = true;
                }
                Relabel();
                // batch33z: the two DHCPv4 faults used to be stderr-only. Show
                // them on the page that owns leases, so a user whose devices
                // stop getting addresses (or whose mappings silently stop
                // surviving a restart) can see WHY.
                if (hint_ != nullptr) {
                    if (snapshot.dhcp_pool_exhausted > 0) {
                        hint_->SetText(
                            I18n::Instance().T(Str::LeasesPoolExhausted));
                        hint_->SetColor(ColorToken::Warning);
                    } else if (snapshot.dhcp_persist_failures > 0) {
                        hint_->SetText(
                            I18n::Instance().T(Str::LeasesPersistFailed));
                        hint_->SetColor(ColorToken::Warning);
                    } else {
                        hint_->SetText(
                            I18n::Instance().T(Str::LeasesRuntimeHint));
                        hint_->SetColor(ColorToken::TextDim);
                    }
                }
                if (pending_error_ != Str::_Count) {
                    const Str message = pending_error_;
                    pending_error_ = Str::_Count;
                    ShowError(message);
                }
                // batch33 D: a "mac=" intent can arrive before the data does;
                // apply it as soon as the row exists.
                ApplyPendingHighlight();
            }

            void LeasesPage::UpdateTables(const UiSnapshot& snapshot, I18n& i18n) {
                {
                    std::vector<TableRow> rows;
                    rows.reserve(snapshot.leases.size());
                    for (const auto& lease : snapshot.leases) {
                        TableRow row;
                        row.row_id = lease.mac;
                        // batch133: reserve + push_back instead of a braced
                        // list - a braced std::vector<std::wstring> builds
                        // temporaries and then COPIES them in, allocating
                        // every SSO-overflowing cell twice per tick.
                        row.cells.clear();
                        row.cells.reserve(5);
                        row.cells.push_back(Widen(lease.mac));
                        row.cells.push_back(Widen(lease.ip));
                        row.cells.push_back(Widen(lease.hostname));
                        row.cells.push_back(
                            lease.is_static
                                ? std::wstring(i18n.T(Str::LeaseStatic))
                                : FormatTimeLeft(lease.expires_in_s));
                        row.cells.push_back(i18n.T(lease.is_static
                                                      ? Str::LeaseStatic
                                                      : Str::LeaseDynamic));
                        rows.push_back(std::move(row));
                    }
                    views_[0].table->SetRows(std::move(rows));
                    views_[0].empty->visible = snapshot.leases.empty();
                    views_[0].empty->SetMessage(Str::LeasesEmptyHint);
                }
                {
                    std::vector<TableRow> rows;
                    rows.reserve(snapshot.leases6.size());
                    for (const auto& lease : snapshot.leases6) {
                        TableRow row;
                        row.row_id = lease.duid;
                        // batch133: reserve + push_back (see the v4 table).
                        row.cells.clear();
                        row.cells.reserve(5);
                        row.cells.push_back(Widen(lease.duid));
                        row.cells.push_back(Widen(lease.ip));
                        row.cells.push_back(Widen(lease.hostname));
                        row.cells.push_back(
                            lease.is_static
                                ? std::wstring(i18n.T(Str::LeaseStatic))
                                : FormatTimeLeft(lease.expires_in_s));
                        row.cells.push_back(i18n.T(lease.is_static
                                                      ? Str::LeaseStatic
                                                      : Str::LeaseDynamic));
                        rows.push_back(std::move(row));
                    }
                    views_[1].table->SetRows(std::move(rows));
                    views_[1].empty->visible = snapshot.leases6.empty();
                    views_[1].empty->SetMessage(Str::LeasesEmptyHint);
                }
                {
                    std::vector<TableRow> rows;
                    rows.reserve(snapshot.dhcp_bindings.size());
                    for (const auto& binding : snapshot.dhcp_bindings) {
                        TableRow row;
                        row.row_id = binding.mac;
                        // batch133: reserve + push_back (see the v4 table).
                        row.cells.clear();
                        row.cells.reserve(3);
                        row.cells.push_back(Widen(binding.mac));
                        row.cells.push_back(Widen(binding.ip));
                        row.cells.push_back(Widen(binding.hostname));
                        rows.push_back(std::move(row));
                    }
                    views_[2].table->SetRows(std::move(rows));
                    views_[2].empty->visible = snapshot.dhcp_bindings.empty();
                    views_[2].empty->SetMessage(Str::LeasesEmptyHint);
                }
                {
                    std::vector<TableRow> rows;
                    rows.reserve(snapshot.dhcp6_bindings.size());
                    for (const auto& binding : snapshot.dhcp6_bindings) {
                        TableRow row;
                        row.row_id = binding.duid;
                        // batch133: reserve + push_back (see the v4 table).
                        row.cells.clear();
                        row.cells.reserve(3);
                        row.cells.push_back(Widen(binding.duid));
                        row.cells.push_back(Widen(binding.ip));
                        row.cells.push_back(Widen(binding.hostname));
                        rows.push_back(std::move(row));
                    }
                    views_[3].table->SetRows(std::move(rows));
                    views_[3].empty->visible = snapshot.dhcp6_bindings.empty();
                    views_[3].empty->SetMessage(Str::LeasesEmptyHint);
                }
            }

            void LeasesPage::Relabel() {
                if (tabs_ != nullptr) {
                    std::vector<std::wstring> labels;
                    labels.reserve(kTabCount);
                    for (std::size_t i = 0; i < kTabCount; ++i) {
                        labels.push_back(I18n::Instance().T(kTabKeys[i]));
                    }
                    tabs_->SetLabels(std::move(labels));
                }
                if (hint_ != nullptr) {
                    hint_->SetText(I18n::Instance().T(Str::LeasesRuntimeHint));
                }
                for (std::size_t i = 0; i < kTabCount; ++i) {
                    if (views_[i].add != nullptr) {
                        views_[i].add->SetLabel(
                            I18n::Instance().T(Str::CommonAdd));
                    }
                }
            }

            void LeasesPage::OnRowAction(LeaseTab tab, const std::string& row_id,
                                         std::size_t action) {
                const bool v6 = (tab == LeaseTab::Bind6);
                if (action == 0) {  // [edit]: prefill from the current snapshot
                    std::string ip;
                    std::string hostname;
                    if (v6) {
                        if (const auto* binding = FindBinding6(row_id)) {
                            ip = binding->ip;
                            hostname = binding->hostname;
                        }
                    } else {
                        if (const auto* binding = FindBinding4(row_id)) {
                            ip = binding->ip;
                            hostname = binding->hostname;
                        }
                    }
                    ShowForm(tab, Str::CommonEdit, Widen(row_id), Widen(ip),
                             Widen(hostname));
                    return;
                }
                // [delete]: confirm, then post the remove command.
                if (dialog_ != nullptr) {
                    dialog_->ShowConfirm(
                        Str::CommonDelete,
                        I18n::Instance().Format(Str::CommonConfirmDeleteFmt,
                                                {Widen(row_id)}),
                        [this, tab, row_id] { RemoveBinding(tab, row_id); });
                    if (host_ != nullptr) {
                        RelayoutHost(*host_);
                    }
                }
            }

            void LeasesPage::ShowForm(LeaseTab tab, Str title,
                                      const std::wstring& key, const std::wstring& ip,
                                      const std::wstring& hostname) {
                if (dialog_ == nullptr) {
                    return;
                }
                const bool v6 = (tab == LeaseTab::Bind6);
                std::vector<FormField> fields;
                fields.push_back(FormField{v6 ? "duid" : "mac",
                                           v6 ? Str::FormDuid : Str::FormMac,
                                           FormFieldType::Text, key, {}});
                fields.push_back(FormField{"ip", Str::FormIp, FormFieldType::Text, ip,
                                           {}});
                fields.push_back(FormField{"hostname", Str::FormHostname,
                                           FormFieldType::Text, hostname, {}});
                const std::wstring original = key;
                dialog_->ShowForm(title, std::move(fields),
                                  [this, tab, original](const FormResult& result) {
                                      SubmitForm(tab, result, original);
                                  });
                if (host_ != nullptr) {
                    RelayoutHost(*host_);
                }
            }

            void LeasesPage::SubmitForm(LeaseTab tab, const FormResult& result,
                                        const std::wstring& original_key) {
                const bool v6 = (tab == LeaseTab::Bind6);
                const std::string key = Narrow(FormValue(result, v6 ? "duid" : "mac"));
                const std::string ip = Narrow(FormValue(result, "ip"));
                const std::string hostname = Narrow(FormValue(result, "hostname"));

                pending_error_ = Str::_Count;
                std::string canonical_key;
                std::string canonical_ip;
                if (v6) {
                    if (!IsValidDuid(key)) {
                        pending_error_ = Str::LeasesErrDuid;
                        return;
                    }
                    std::array<uint8_t, 16> addr{};
                    if (!ParseIpv6Text(ip, addr)) {
                        pending_error_ = Str::LeasesErrIp;
                        return;
                    }
                    canonical_key = key;
                    canonical_ip = vgww::core::FormatIpv6(addr);
                } else {
                    vgww::core::MacAddress mac{};
                    if (!vgww::core::ParseMac(key, mac)) {
                        pending_error_ = Str::LeasesErrMac;
                        return;
                    }
                    bool ok = false;
                    const uint32_t parsed = vgww::core::ParseIpv4(ip, ok);
                    if (!ok) {
                        pending_error_ = Str::LeasesErrIp;
                        return;
                    }
                    canonical_key = vgww::core::FormatMac(mac);
                    canonical_ip = vgww::core::FormatIpv4(parsed);
                }
                if (ctx_ == nullptr || ctx_->controller == nullptr) {
                    return;
                }
                // batch137: add and edit share ONE command. A key edit carries
                // the OLD key (replace_mac / replace_duid) so the engine
                // drops and inserts atomically; posting a remove followed by an
                // add let either half be refused alone, which deleted the
                // client's binding and stored nothing in its place.
                if (v6) {
                    AddDhcp6BindingCmd cmd{canonical_key, canonical_ip, hostname};
                    if (!original_key.empty()) {
                        cmd.replace_duid = Narrow(original_key);
                    }
                    SubmitCommand(*ctx_, Command{std::move(cmd)});
                } else {
                    AddDhcpBindingCmd cmd{canonical_key, canonical_ip, hostname};
                    if (!original_key.empty()) {
                        cmd.replace_mac = Narrow(original_key);
                    }
                    SubmitCommand(*ctx_, Command{std::move(cmd)});
                }
            }

            void LeasesPage::RemoveBinding(LeaseTab tab, const std::string& key) {
                if (ctx_ == nullptr || ctx_->controller == nullptr) {
                    return;
                }
                if (tab == LeaseTab::Bind6) {
                    SubmitCommand(*ctx_, Command{RemoveDhcp6BindingCmd{key}});
                } else {
                    SubmitCommand(*ctx_, Command{RemoveDhcpBindingCmd{key}});
                }
            }

            void LeasesPage::ShowError(Str message) {
                if (dialog_ == nullptr) {
                    return;
                }
                // DialogHost has no inline error slot and Confirm() always
                // closes after on_submit: the specific error is a message
                // dialog driven by the next Update.
                dialog_->ShowMessage(Str::CommonError, I18n::Instance().T(message),
                                     Str::CommonOk);
                if (host_ != nullptr) {
                    RelayoutHost(*host_);
                }
            }

            const vgww::runtime::Dataplane::BindingView* LeasesPage::FindBinding4(
                const std::string& mac) const {
                for (const auto& binding : bindings4_) {
                    if (binding.mac == mac) {
                        return &binding;
                    }
                }
                return nullptr;
            }

            const vgww::runtime::Dataplane::Binding6View* LeasesPage::FindBinding6(
                const std::string& duid) const {
                for (const auto& binding : bindings6_) {
                    if (binding.duid == duid) {
                        return &binding;
                    }
                }
                return nullptr;
            }

        }  // namespace

        std::unique_ptr<Page> MakeLeasesPage() {
            return std::make_unique<LeasesPage>();
        }

    }  // namespace ui
}  // namespace vgww
