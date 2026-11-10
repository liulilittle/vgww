// ============================================================================
// app.cpp - shell assembly + message loop implementation (S4.3 Task 7).
// ============================================================================
#include "ui/app.h"

#include "core/handler_guard.h"
#include "ui/controls.h"
#include "ui/console_log.h"
#include "ui/i18n.h"
#include "ui/pages/page_util.h"
#include "ui/tray.h"

#include "driver/error_class.h"
#include "driver/installer.h"

#include <shellapi.h>
#include <windows.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <thread>
#include <utility>

namespace vgww {
    namespace ui {

        namespace {

            /// Detached repair-worker bodies that threw and were reported
            /// instead of terminating the process (a std::thread body is its
            /// own entry point, so an escape is fatal).
            std::atomic<uint64_t> g_repair_thread_errors{0};

            /// Shell root: 220 px sidebar + filling right column.
            class ShellRoot final : public Element {
            public:
                ShellRoot() { hit_transparent = true; }

                void SetPanels(Element* sidebar, Element* right) noexcept {
                    sidebar_ = sidebar;
                    right_ = right;
                }

            protected:
                Size MeasureCore(Size available) override {
                    if (sidebar_ != nullptr) {
                        sidebar_->Measure(Size{Sidebar::kWidth, available.h});
                    }
                    if (right_ != nullptr) {
                        right_->Measure(
                            Size{std::max(available.w - Sidebar::kWidth, 0.0f),
                                 available.h});
                    }
                    return Size{available.w, available.h};
                }

                void ArrangeCore(Rect final_rect) override {
                    const float left_w =
                        std::min(Sidebar::kWidth, std::max(final_rect.w, 0.0f));
                    // batch19 R4-P2: in RTL the sidebar mirrors to the right
                    // edge; the "right column" then fills from the left.
                    const bool rtl = I18n::Instance().IsRtl();
                    if (sidebar_ != nullptr) {
                        const float sx = rtl
                                             ? final_rect.x + final_rect.w - left_w
                                             : final_rect.x;
                        sidebar_->Arrange(
                            Rect{sx, final_rect.y, left_w, final_rect.h});
                    }
                    if (right_ != nullptr) {
                        const float rx = rtl ? final_rect.x
                                             : final_rect.x + left_w;
                        right_->Arrange(
                            Rect{rx, final_rect.y,
                                 std::max(final_rect.w - left_w, 0.0f),
                                 final_rect.h});
                    }
                }

            private:
                Element* sidebar_ = nullptr;
                Element* right_ = nullptr;
            };

            /// 48 px page header + filling content area + full-size toasts.
            class RightColumn final : public Element {
            public:
                RightColumn() { hit_transparent = true; }

                void SetParts(Element* header, Element* banner, Element* content,
                              Element* toasts, Element* dialog) noexcept {
                    header_ = header;
                    banner_ = banner;
                    content_ = content;
                    toasts_ = toasts;
                    dialog_ = dialog;
                }

            protected:
                /// Batch19 R6: the failure banner sits 16 px inside the right
                /// column, matching the page title's and content area's own
                /// 16 px gutters; without it the banner's amber border ran
                /// flush into the window's right edge.
                static constexpr float kBannerInset = 16.0f;

                Size MeasureCore(Size available) override {
                    if (header_ != nullptr) {
                        header_->Measure(Size{available.w, PageHeader::kHeight});
                    }
                    const float banner_h =
                        (banner_ != nullptr && banner_->visible) ? 44.0f : 0.0f;
                    if (banner_ != nullptr) {
                        banner_->Measure(
                            Size{std::max(available.w - 2.0f * kBannerInset,
                                          0.0f),
                                 banner_ != nullptr && banner_->visible
                                     ? banner_h
                                     : 0.0f});
                    }
                    if (content_ != nullptr) {
                        content_->Measure(
                            Size{available.w,
                                 std::max(available.h -
                                              PageHeader::kHeight - banner_h,
                                          0.0f)});
                    }
                    if (toasts_ != nullptr) {
                        toasts_->Measure(available);
                    }
                    if (dialog_ != nullptr) {
                        dialog_->Measure(available);
                    }
                    return Size{available.w, available.h};
                }

                void ArrangeCore(Rect final_rect) override {
                    const float header_h =
                        std::min(PageHeader::kHeight,
                                 std::max(final_rect.h, 0.0f));
                    if (header_ != nullptr) {
                        header_->Arrange(Rect{final_rect.x, final_rect.y,
                                              final_rect.w, header_h});
                    }
                    const float banner_h =
                        (banner_ != nullptr && banner_->visible)
                            ? std::min(44.0f,
                                       std::max(final_rect.h - header_h,
                                                0.0f))
                            : 0.0f;
                    if (banner_ != nullptr && banner_->visible) {
                        banner_->Arrange(
                            Rect{final_rect.x + kBannerInset,
                                 final_rect.y + header_h,
                                 std::max(final_rect.w -
                                              2.0f * kBannerInset,
                                          0.0f),
                                 banner_h});
                    }
                    if (content_ != nullptr) {
                        content_->Arrange(
                            Rect{final_rect.x,
                                 final_rect.y + header_h + banner_h,
                                 final_rect.w,
                                 std::max(final_rect.h - header_h - banner_h,
                                          0.0f)});
                    }
                    if (toasts_ != nullptr) {
                        toasts_->Arrange(final_rect);
                    }
                    if (dialog_ != nullptr) {
                        dialog_->Arrange(final_rect);
                    }
                }

            private:
                Element* header_ = nullptr;
                Element* banner_ = nullptr;
                Element* content_ = nullptr;
                Element* toasts_ = nullptr;
                Element* dialog_ = nullptr;
            };

            /// Router mount host: 16 px content padding, fills the area.
            class ContentHost final : public Element {
            public:
                ContentHost() { hit_transparent = true; }

            protected:
                Size MeasureCore(Size available) override {
                    const Size inner{
                        std::max(available.w - kPad * 2.0f, 0.0f),
                        std::max(available.h - kPad * 2.0f, 0.0f)};
                    for (const auto& child : children()) {
                        if (child->visible) {
                            child->Measure(inner);
                        }
                    }
                    return available;
                }

                void ArrangeCore(Rect final_rect) override {
                    const Rect inner{final_rect.x + kPad, final_rect.y + kPad,
                                     std::max(final_rect.w - kPad * 2.0f, 0.0f),
                                     std::max(final_rect.h - kPad * 2.0f, 0.0f)};
                    ArrangeChildren(inner);
                }

            private:
                static constexpr float kPad = 16.0f;
            };

            /// batch25b: UTF-8 encode a wide string (form values are adapter
            /// names/device paths; non-ASCII friendly names must survive).
            /// batch31 P0-1: delegates to the ONE shared Narrow (page_util.cpp)
            /// so app.cpp cannot drift from the page layer's encoding again.
            std::string NarrowUtf8(const std::wstring& text) {
                return Narrow(text);
            }

            std::string UpperAscii(std::string text) {
                for (char& c : text) {
                    if (c >= 'a' && c <= 'z') {
                        c = static_cast<char>(c - 'a' + 'A');
                    }
                }
                return text;
            }

            /// The two raw resolution failures the dataplane emits when an
            /// adapter hint cannot be bound (dataplane.cpp Start()).
            bool MentionsAdapterResolutionError(const std::string& text) {
                std::string lower = text;
                for (char& c : lower) {
                    if (c >= 'A' && c <= 'Z') {
                        c = static_cast<char>(c - 'A' + 'a');
                    }
                }
                return lower.find("no adapter matches") != std::string::npos ||
                       lower.find("adapter matching is ambiguous") !=
                           std::string::npos;
            }

            /// S5-AESTH P1-5: the known driver errors must not be shown as
            /// hardcoded English; map them to the localized banner texts via
            /// the driver fault classifier (batch16 F1: the substring
            /// matches used to live here AND in main.cpp - editing a
            /// literal silently broke both chains). Any other error still
            /// degrades to the generic text, never a raw engine dump.
            std::wstring LocalizeDataplaneError(const std::string& text) {
                switch (vgww::driver::ClassifyDriverFault(text)) {
                    case vgww::driver::DriverFault::DriverMissing:
                        return I18n::Instance().T(Str::DataplaneErrorDriver);
                    case vgww::driver::DriverFault::AccessDenied:
                        return I18n::Instance().T(
                            Str::DataplaneErrorAccessDenied);
                    case vgww::driver::DriverFault::AdapterMissing:
                        return I18n::Instance().T(
                            Str::DataplaneErrorNoAdapter);
                    case vgww::driver::DriverFault::None:
                        return std::wstring();
                    case vgww::driver::DriverFault::Other:
                    default:
                        return I18n::Instance().T(Str::DataplaneErrorGeneric);
                }
            }

            /// batch34x: the bridge banner used to show only "bridge failed".
            /// The machine reason (port gone vs. read error) existed only on
            /// stderr, so the operator could not tell a pulled cable from a
            /// driver fault. Map the two known prefixes to localized text and
            /// keep anything else on the generic line (never a raw dump).
            std::wstring LocalizeBridgeError(const std::string& text) {
                if (text.empty()) {
                    return std::wstring();
                }
                if (text.compare(0, 23, "bridge port disappeared") == 0) {
                    return I18n::Instance().T(Str::BridgeErrorPortGone);
                }
                if (text.compare(0, 19, "bridge read error: ") == 0) {
                    return I18n::Instance().T(Str::BridgeErrorRead);
                }
                return I18n::Instance().T(Str::BridgeErrorGeneric);
            }

            /// batch24 P2-9b: actionable one-line reason for an unusable
            /// (but successfully bound) adapter.
            std::wstring AdapterWarningReason(
                const vgww::runtime::Dataplane::AdapterBinding& binding) {
                const std::wstring friendly = Widen(binding.friendly_name);
                const std::wstring name =
                    friendly.empty() ? Widen(binding.device) : friendly;
                switch (AdapterBindingIssue(binding)) {
                    case AdapterIssue::LinkDown:
                        return I18n::Instance().Format(
                            Str::DataplaneAdapterDownFmt, {name});
                    case AdapterIssue::NoIpv4:
                        return I18n::Instance().Format(
                            Str::DataplaneAdapterNoIpFmt, {name});
                    case AdapterIssue::GatewayOutsideSubnet:
                        return I18n::Instance().Format(
                            Str::DataplaneAdapterSubnetFmt, {name});
                    case AdapterIssue::None:
                    default:
                        return std::wstring();
                }
            }

            /// Short, localized repair-failure summary for the toast
            /// (batch16 F2.3); long multi-line reports are truncated.
            std::wstring RepairFailureSummary(
                const vgww::driver::ElevatedInstallResult& result) {
                const I18n& i18n = I18n::Instance();
                std::wstring summary;
                switch (result.outcome) {
                    case vgww::driver::ElevatedInstallOutcome::
                        ElevationRefused:
                        summary = i18n.Copy(Str::FixRefusedSummary);
                        break;
                    case vgww::driver::ElevatedInstallOutcome::StillRunning:
                        summary = i18n.Copy(Str::FixStillRunningSummary);
                        break;
                    default:
                        summary = result.detail.empty()
                                      ? i18n.Copy(Str::CommonUnknownError)
                                      : Widen(result.detail);
                        break;
                }
                constexpr std::size_t kMaxSummary = 120;
                if (summary.size() > kMaxSummary) {
                    summary = summary.substr(0, kMaxSummary - 3) + L"...";
                }
                return summary;
            }

        }  // namespace

        void UiApp::RequestDriverRepair() {
            // C3: re-launch this exe elevated; --install-driver installs or
            // re-grants the ndisrd driver idempotently (main.cpp path).
            // Batch16 F2.3: the child runs hidden and the 90 s wait happens
            // OFF the UI thread; the outcome is toasted when OnTick polls
            // the shared state. No dataplane hot-restart (D6): the success
            // toast tells the operator to restart VGWW.
            if (repair_in_flight_) {
                return;  // one elevated attempt at a time
            }
            repair_in_flight_ = true;
            if (toasts_ != nullptr) {
                toasts_->Show(Str::FixRequested, ToastKind::Info);
            }
            auto state = std::make_shared<RepairAsyncState>();
            repair_state_ = state;
            std::thread([state] {
                ::vgww::core::RunDetachedBodyGuarded(
                    g_repair_thread_errors,
                    [&] {
                        const vgww::driver::ElevatedInstallResult result =
                            vgww::driver::RunElevatedInstallAndWait();
                        std::lock_guard<std::mutex> lock(state->mutex);
                        state->done = true;
                        state->ok =
                            vgww::driver::ElevatedInstallOutcome::InstallOk ==
                            result.outcome;
                        if (!state->ok) {
                            state->summary = RepairFailureSummary(result);
                        }
                    },
                    [&] {
                        // The body threw, so there is no result to classify;
                        // the poller still needs a terminal failed state.
                        std::lock_guard<std::mutex> lock(state->mutex);
                        state->done = true;
                        state->ok = false;
                        state->summary = L"driver repair failed";
                    });
            }).detach();
        }

        CommandResult TrayAutostartHook(const SetAutostartCmd& cmd) {
            std::string error;
            if (!tray::SetAutostart(cmd.enabled, error)) {
                std::fprintf(stderr, "[ui] autostart update failed: %s\n",
                             error.c_str());
                return CommandResult{false, I18n::Instance().Copy(Str::CmdAutostartWriteFailed)};
            }
            tray::UpdateMenu(cmd.enabled);  // keep the tray check mark in sync
            return CommandResult{
                true, I18n::Instance().Copy(cmd.enabled ? Str::CmdAutostartEnabled
                                                        : Str::CmdAutostartDisabled)};
        }

        UiApp::UiApp() = default;
        UiApp::~UiApp() = default;

        void UiApp::Compose(UiController& controller, const UiSnapshot& first) {
            controller_ = &controller;

            auto root = std::make_unique<ShellRoot>();
            root->id = "shell.root";
            auto sidebar = std::make_unique<Sidebar>();
            sidebar->id = "shell.sidebar";
            auto right = std::make_unique<RightColumn>();
            auto header = std::make_unique<PageHeader>();
            header->id = "shell.header";
            auto content = std::make_unique<ContentHost>();
            content->id = "shell.content";
            auto toasts = std::make_unique<ToastHost>();
            toasts->id = "shell.toasts";
            // batch25b: one shell-level modal host, added LAST so it wins the
            // overlay hit order over page dialogs (reverse-children cache).
            auto dialog = std::make_unique<DialogHost>();
            dialog->id = "shell.dialog";
            dialog_ = dialog.get();
            // S5-AESTH R2: one unified failure banner under the header.
            auto banner = std::make_unique<DriverBanner>();
            banner->id = "shell.fixbar";
            DriverBanner* banner_raw = banner.get();
            banner_raw->action_button()->on_click = [this] {
                RequestDriverRepair();
            };
            banner_ = banner_raw;

            sidebar_ = sidebar.get();
            header_ = header.get();
            content_ = content.get();
            toasts_ = toasts.get();
            // batch287: a refused clipboard write must say so instead of
            // looking like a no-op. The window reports it, the shell shows
            // the same warning the pages use for their copy buttons.
            window_.on_clipboard_failed = [this](bool paste) {
                toasts_->Show(paste ? Str::ClipboardPasteFailed
                                    : Str::ConsoleCopyFailed,
                              ToastKind::Warning);
            };

            auto* right_raw = right.get();
            right_raw->SetParts(header.get(), banner_raw, content.get(),
                                toasts.get(), dialog.get());
            right->Add(std::move(header));
            right->Add(std::move(banner));
            right->Add(std::move(content));
            right->Add(std::move(toasts));
            right->Add(std::move(dialog));
            // batch37o: one shell-level edit menu for every TextInput and the
            // console (added after the modal host so it paints/hits on top).
            auto edit_menu = std::make_unique<ContextMenu>();
            edit_menu->id = "shell.edit_menu";
            window_.SetEditContextMenu(edit_menu.get());
            right->Add(std::move(edit_menu));
            auto* root_raw = root.get();
            root_raw->SetPanels(sidebar.get(), right.get());
            root->Add(std::move(sidebar));
            root->Add(std::move(right));
            root_ = std::move(root);

            router_ = std::make_unique<Router>(*content_);
            SetNavigateTarget(router_.get());
            SetNavigateIntentTarget(router_.get());
            context_ = MakePageContext(
                controller_, [this](Str text, ToastKind kind) {
                    if (toasts_ != nullptr) {
                        toasts_->Show(text, kind);
                    }
                });
            // S5 GUI fix (G8): let the About page's language switch re-read every
            // shell label immediately (see I18n / AboutPage).
            context_.apply_language = [this] { ApplyLanguage(); };
            // batch20: a page that changes the UI scale applies it immediately
            // (0 = auto). The window keeps the top-left corner and resizes to
            // 980x640 at the requested scale.
            context_.apply_ui_scale = [this](float scale) {
                window_.SetUiScale(scale);
            };
            context_.effective_ui_scale = [this] { return window_.scale(); };
            // batch22 A1: apply the appearance immediately and repaint every
            // element (colors are read at draw time, so a full invalidate is
            // enough - no relayout). Returns the mode actually in effect.
            context_.apply_theme = [this](const std::string& mode) {
                const bool auto_mode = mode == "auto";
                const bool light = auto_mode ? SystemPrefersLightTheme()
                                             : mode == "light";
                SetActiveTheme(light);
                if (window_.hwnd() != nullptr) {
                    ::InvalidateRect(window_.hwnd(), nullptr, FALSE);
                }
                // Colors are read at draw time; a fresh layout frame forces a
                // repaint of every page without changing any geometry.
                RequestLayoutFrame();
                return auto_mode ? std::string("auto")
                                 : (light ? std::string("light")
                                          : std::string("dark"));
            };
            // batch24 P1-4: the Settings page's save->restart confirm asks for
            // a process relaunch. Only arm it when the entry point installed a
            // handler; a headless/test app leaves it empty so a save keeps the
            // legacy toast path (no modal to disturb scripted interactions).
            if (restart_handler_) {
                context_.restart_app = [this] { restart_handler_(); };
            }
            // batch27 P1-5: the dashboard's "set it up for me" runs the shell's
            // own first-run wizard (the same dialog the launch path shows).
            context_.open_setup = [this] {
                if (dialog_ == nullptr) {
                    return;
                }
                first_run_decided_ = false;  // an explicit request re-arms it
                UiSnapshot current;
                if (snapshot_) {
                    current = *snapshot_;
                }
                if (!MaybeShowFirstRunWizard(current) && dialog_ != nullptr) {
                    // Nothing to configure (or no adapters): say so instead of
                    // silently doing nothing.
                    const I18n& i18n = I18n::Instance();
                    dialog_->ShowMessageText(i18n.T(Str::WizardTitle),
                                             i18n.T(Str::WizardNoAdapter),
                                             i18n.T(Str::CommonOk));
                }
                if (window_.hwnd() != nullptr) {
                    window_.RequestLayout();
                }
            };
            router_->SetContext(context_);
            // Order matters (T7 review M1): the shell callback must be
            // installed BEFORE RegisterAllPages - a page that navigates while
            // registering would otherwise leave the sidebar selection and the
            // page header stale. The sidebar hook goes in before any
            // navigation can fire as well.
            router_->on_changed = [this] {
                if (router_ == nullptr) {
                    return;
                }
                if (router_->current() != nullptr) {
                    sidebar_->SetSelected(router_->current()->id());
                }
                UpdateHeaderTitle();
                if (snapshot_) {
                    router_->Update(snapshot_, I18n::Instance());
                }
                // I1: a freshly built (or re-shown) subtree needs a real
                // layout, not just a repaint - its bounds stay zero until a
                // resize otherwise.
                window_.RequestLayout();
                // Perf (T5/M6): this callback rebuilds the page subtree AFTER
                // the last Update() sampled the content epoch. Refresh the
                // O(1) sample so a subsequent Update() with an identical
                // snapshot sees no change and does not re-request a layout
                // (equivalence with the old before/after double walk, which
                // sampled rev at Update entry and thus never saw this
                // out-of-band mutation). The tree epoch is refreshed for the
                // same reason.
                last_content_epoch_ = UiContentEpoch();
                last_tree_epoch_ = UiTreeEpoch();
            };
            sidebar_->on_navigate = [this](const std::string& id) {
                NavigateTo(id);
            };
            RegisterAllPages(*router_, context_);

            language_ = I18n::Instance().Lang();
            Update(first);
            NavigateInitialPage();  // M1: the app owns the initial screen
            composed_ = true;
        }

        bool UiApp::MaybeShowFirstRunWizard(const UiSnapshot& snapshot) {
            if (first_run_decided_ || snapshot.seq == 0) {
                // seq 0 = the publisher has not produced its first real
                // snapshot yet (controller.Start() returns before Publish):
                // do NOT decide from the empty placeholder.
                return false;
            }
            first_run_decided_ = true;
            if (dialog_ == nullptr || snapshot.dataplane_running) {
                return false;
            }
            // "Adapter empty / NONE / cannot be resolved": exactly the states
            // that leave the dashboard showing "cannot start". A clean
            // user-requested stop (no error) never triggers setup.
            const std::string hint = UpperAscii(snapshot.config.adapter);
            const bool empty_or_none = hint.empty() || hint == "NONE";
            const bool resolution_failed =
                MentionsAdapterResolutionError(snapshot.dataplane_error);
            const bool unusable =
                empty_or_none
                    ? (!snapshot.adapters.empty() || resolution_failed)
                    : (!snapshot.adapter_binding.bound && resolution_failed);
            if (!unusable) {
                return false;
            }

            I18n& i18n = I18n::Instance();
            // batch29: the SAME detached list the Settings picker builds
            // (BuildAdapterChoices lives in page_util now - one sorting rule).
            const std::vector<AdapterChoice> choices =
                BuildAdapterChoices(snapshot, i18n);
            if (choices.empty()) {
                dialog_->ShowMessageText(i18n.T(Str::WizardTitle),
                                         i18n.T(Str::WizardNoAdapter),
                                         i18n.T(Str::CommonOk));
                return true;
            }

            // Prefer an adapter that is actually connected; otherwise the
            // first detected one (the user can still change the dropdown).
            std::wstring preferred = choices.front().value;
            for (const AdapterChoice& choice : choices) {
                if (choice.connected) {
                    preferred = choice.value;
                    break;
                }
            }
            FormField adapter;
            adapter.id = "adapter";
            adapter.label = Str::WizardAdapterLabel;
            adapter.type = FormFieldType::Select;
            adapter.initial = preferred;
            for (const AdapterChoice& choice : choices) {
                adapter.options.emplace_back(choice.value, choice.label);
            }
            FormField mode;
            mode.id = "internet_mode";
            mode.label = Str::WizardModeLabel;
            mode.type = FormFieldType::Select;
            mode.initial = L"auto";
            mode.options = {{L"auto", i18n.T(Str::SettingsInternetAuto)},
                            {L"manual", i18n.T(Str::SettingsInternetManual)}};

            const ConfigView view = snapshot.config;
            const std::string config_path = snapshot.config.config_path;
            dialog_->ShowFormActionsText(
                i18n.T(Str::WizardTitle), i18n.T(Str::WizardIntro),
                {std::move(adapter), std::move(mode)},
                i18n.T(Str::WizardSaveStart), i18n.T(Str::WizardSkip),
                [this, view, config_path](const FormResult& result) {
                    std::string adapter_value;
                    std::string mode_value = "auto";
                    const auto a = result.values.find("adapter");
                    if (a != result.values.end()) {
                        adapter_value = NarrowUtf8(a->second);
                    }
                    const auto m = result.values.find("internet_mode");
                    if (m != result.values.end()) {
                        mode_value = NarrowUtf8(m->second);
                    }
                    SubmitFirstRun(view, config_path, adapter_value, mode_value);
                },
                [] {});
            if (window_.hwnd() != nullptr) {
                window_.RequestLayout();
            }
            return true;
        }

        void UiApp::SubmitFirstRun(const ConfigView& view,
                                   const std::string& config_path,
                                   const std::string& adapter,
                                   const std::string& internet_mode) {
            if (dialog_ == nullptr) {
                return;
            }
            const I18n& i18n = I18n::Instance();
            // Preserve every field the wizard does not touch: seed from the
            // on-disk config (same rule as the Settings page). A headless
            // context (empty path) falls back to the snapshot view.
            vgww::core::Config config;
            bool loaded = false;
            if (!config_path.empty()) {
                std::string load_error;
                if (auto disk =
                        vgww::core::Config::LoadFromFile(config_path, load_error)) {
                    config = *disk;
                    loaded = true;
                }
            }
            if (!loaded) {
                config.adapter = view.adapter;
                config.mode = view.mode == "main" ? vgww::core::Mode::kMain
                                                  : vgww::core::Mode::kBypass;
                bool ok = false;
                const uint32_t gateway =
                    vgww::core::ParseIpv4(view.gateway_ip, ok);
                if (ok) {
                    config.gateway.ipv4 = gateway;
                }
                const uint32_t mask =
                    vgww::core::ParseIpv4(view.gateway_mask, ok);
                if (ok) {
                    config.gateway.mask = mask;
                }
                vgww::core::ParseMac(view.gateway_mac, config.gateway.mac);
                config.dhcp.enabled = view.dhcp_enabled;
                const uint32_t pool_start =
                    vgww::core::ParseIpv4(view.dhcp_pool_start, ok);
                if (ok) {
                    config.dhcp.pool_start = pool_start;
                }
                const uint32_t pool_end =
                    vgww::core::ParseIpv4(view.dhcp_pool_end, ok);
                if (ok) {
                    config.dhcp.pool_end = pool_end;
                }
                if (view.dhcp_lease_s != 0) {
                    config.dhcp.lease_seconds = view.dhcp_lease_s;
                }
            }
            if (!adapter.empty()) {
                config.adapter = adapter;
            }
            if (internet_mode == "auto") {
                config.mode = vgww::core::Mode::kMain;
                config.dhcp.enabled = true;
            }
            if (controller_ == nullptr ||
                !controller_->Post(Command{SaveConfigCmd{std::move(config)}})) {
                dialog_->ShowMessageText(i18n.T(Str::CommonError),
                                         i18n.T(Str::CommonBusy),
                                         i18n.T(Str::CommonOk));
                return;
            }
            dialog_->Close();
            // batch37j (user): the save command applies the config to the
            // running dataplane; no relaunch. The old restart chain made the
            // first-run wizard quit and reopen the whole app.
            if (toasts_ != nullptr) {
                toasts_->Show(Str::WizardSaved, ToastKind::Success);
            }
        }

        void UiApp::OnCloseRequested() {
            if (dialog_ == nullptr || close_prompt_shown_) {
                window_.HideToTray();
                return;
            }
            close_prompt_shown_ = true;
            const I18n& i18n = I18n::Instance();
            dialog_->ShowConfirmActionsText(
                i18n.T(Str::ClosePromptTitle), i18n.T(Str::ClosePromptBody),
                i18n.T(Str::ClosePromptQuit), i18n.T(Str::ClosePromptKeep),
                [this] { window_.RequestExit(); },
                [this] { window_.HideToTray(); });
            if (window_.hwnd() != nullptr) {
                window_.RequestLayout();
            }
        }

        void UiApp::ToggleServiceFromTray(bool start) {
            if (controller_ == nullptr) {
                return;
            }
            // batch28: the SAME command channel the dashboard uses; exactly one
            // command per activation (the queue rejects while busy).
            const bool posted =
                controller_->Post(start ? Command{StartServiceCmd{}}
                                        : Command{StopServiceCmd{}});
            if (!posted && toasts_ != nullptr) {
                toasts_->Show(Str::CommonBusy, ToastKind::Warning);
            }
        }

        void UiApp::OpenDashboardFromTray() {
            // batch29: ONE route (NavigateTo) so the unsaved-edit prompt and the
            // popup dismissal behave exactly like a sidebar click. The window
            // has already shown itself (see VgwwWindow::Create's tray hook).
            if (router_ == nullptr) {
                return;
            }
            NavigateTo("dashboard");
        }

        void UiApp::NavigateInitialPage() {
            if (router_ == nullptr || router_->current() != nullptr) {
                return;
            }
            // S5.20: a requested --ui-page start page wins over the default
            // home page. Gate on registration so an unknown id falls through
            // to the first page instead of tripping Router's Debug assert.
            if (!initial_page_.empty() &&
                router_->page_ids().end() !=
                    std::find(router_->page_ids().begin(),
                              router_->page_ids().end(), initial_page_)) {
                NavigateTo(initial_page_);
                return;
            }
            if (!router_->page_ids().empty()) {
                NavigateTo(router_->page_ids().front());
            }
        }

        void UiApp::NavigateTo(const std::string& id) {
            NavigateTo(id, std::string());
        }

        void UiApp::NavigateTo(const std::string& id, const std::string& intent) {
            if (router_ == nullptr) {
                return;
            }
            // batch31 P0-2: re-clicking the CURRENT page tab is a no-op. It
            // must not reach DismissAllPopups (that would silently collapse an
            // open dropdown the user is working with) and must not reach the
            // router (whose Navigate is now also side-effect free, but the
            // shell keeps its own guarantee independent of that).
            //
            // batch33 D: a call that carries an INTENT is not a tab click - the
            // requested effect (open a pre-filled form / scroll to a row) must
            // still run, so the no-op shortcut only applies to a bare switch.
            Page* current_page = router_->current();
            if (intent.empty() && current_page != nullptr && id == current_page->id()) {
                return;
            }
            // batch27 P0-4: an expanded popup belongs to the page that owns it;
            // a sidebar switch must never carry it onto the next page.
            window_.DismissAllPopups();
            // batch27 P1-6: a page with unsaved edits gets to ask first.
            Page* leaving = router_->current();
            if (leaving != nullptr && std::string(leaving->id()) != id) {
                const bool ready = leaving->ConfirmLeave([this, id, intent] {
                    if (router_ != nullptr) {
                        window_.DismissAllPopups();
                        if (intent.empty()) {
                            router_->Navigate(id);
                        } else {
                            router_->NavigateWithIntent(id, intent);
                        }
                    }
                });
                if (!ready) {
                    return;  // the page owns the flow (it showed a prompt)
                }
            }
            if (intent.empty()) {
                router_->Navigate(id);  // on_changed refreshes the shell
            } else {
                router_->NavigateWithIntent(id, intent);
            }
        }

        void UiApp::UpdateHeaderTitle() {
            if (header_ == nullptr || router_ == nullptr) {
                return;
            }
            I18n& i18n = I18n::Instance();
            Page* page = router_->current();
            header_->SetTitle(page != nullptr ? i18n.T(page->title())
                                              : i18n.T(Str::AppTitle));
        }

        void UiApp::Update(const UiSnapshot& snapshot) {
            // W11 batch4 M10-2-lite: the const& entry point is the copy path
            // (tests, one-off callers); the shared_ptr overload below adopts
            // the caller's object without any second whole-snapshot copy.
            Update(std::make_shared<const UiSnapshot>(snapshot));
        }

        void UiApp::Update(std::shared_ptr<const UiSnapshot> snapshot) {
            if (root_ == nullptr || snapshot == nullptr) {
                return;
            }
            // P2: only a real layout change (visible text/size) needs a full
            // re-arrange; identical data (the 500 ms snapshot rebuild with an
            // unchanged seq-content) must not force Relayout every tick. Every
            // Set*/SetText path is equality-guarded and bumps content_rev only
            // on a real change, which also advances the global content epoch
            // (M6, batch3): the cached sample below is that O(1) epoch value -
            // no tree walk runs here at all.
            //
            // M10-2-lite: adopted by identity - the OnTick path already holds
            // the controller's shared_ptr, so this used to deep-copy the whole
            // snapshot on the UI thread for every new seq.
            snapshot_ = std::move(snapshot);
            const UiSnapshot& current = *snapshot_;
            // batch25b: the first real snapshot (seq > 0) decides whether the
            // launch needs the first-run wizard. A headless app has no window
            // and never auto-opens it (the explicit test seam covers it).
            if (!first_run_decided_ && window_.hwnd() != nullptr) {
                MaybeShowFirstRunWizard(current);
            }
            I18n& i18n = I18n::Instance();
            // b28-legibility P5: a service-state switch changes the instrument
            // under a stationary pointer, so the queued hover tooltip must not
            // survive it (it used to hang over the action buttons).
            if (snapshot_ != nullptr &&
                (!last_service_running_known_ ||
                 snapshot_->dataplane_running != last_service_running_)) {
                last_service_running_ = snapshot_->dataplane_running;
                last_service_running_known_ = true;
                window_.ClearHoverTooltip();
            }
            if (router_ != nullptr) {
                router_->Update(snapshot_, i18n);
            }
            if (banner_ != nullptr) {
                // S5-AESTH R2: the failure banner is the single status home
                // under the header (the page header no longer carries a
                // badge). A failed dataplane wins over a failed bridge.
                // batch25a: a clean, user-requested stop is a normal state
                // (the dashboard strip shows it); only an actual failure
                // (non-empty reason) keeps the warning banner.
                const bool dp_failed =
                    !current.dataplane_running &&
                    !current.dataplane_error.empty();
                const bool br_failed =
                    current.bridge_state == vgww::bridge::BridgeState::kFailed;
                const AdapterIssue adapter_issue =
                    AdapterBindingIssue(current.adapter_binding);
                if (dp_failed) {
                    banner_->SetFailure(
                        true, i18n.T(Str::DataplaneDown),
                        LocalizeDataplaneError(current.dataplane_error));
                } else if (br_failed) {
                    banner_->SetFailure(true, i18n.T(Str::BridgeFailed),
                                        LocalizeBridgeError(current.bridge_error));
                } else if (AdapterIssue::None != adapter_issue) {
                    // Healthy dataplane, unusable NIC (disconnected USB NIC,
                    // no IPv4, gateway outside its subnet). The action button
                    // is a driver repair and does not apply here; the reason
                    // tells the operator to pick the real NIC in Settings.
                    banner_->SetFailure(
                        true, i18n.T(Str::DataplaneAdapterWarning),
                        AdapterWarningReason(current.adapter_binding), false);
                } else {
                    banner_->SetFailure(false, std::wstring(),
                                        std::wstring());
                }
            }
            UpdateHeaderTitle();
            // P2/M6: a real change (any element's content_rev moved - observed
            // in O(1) through the global content epoch - or the banner's
            // show/hide changed its flow height) needs a full layout;
            // otherwise a repaint is enough. The old whole-tree content_rev
            // SUM walk is gone: the sum could be fooled by two different tree
            // states coincidentally matching, and a node removal can even
            // LOWER it (DialogHost::Reset retires its subtree) - the monotone
            // structural tree epoch is compared alongside, closing that
            // window. An out-of-band bump may still cause one extra
            // RequestLayout (covered by the explicit RequestLayout in
            // on_changed/ApplyLanguage).
            const bool banner_flow_changed =
                banner_ != nullptr && (banner_->visible != banner_was_visible_);
            banner_was_visible_ = banner_ != nullptr && banner_->visible;
            const uint64_t content_epoch = UiContentEpoch();
            if (content_epoch != last_content_epoch_ || banner_flow_changed ||
                UiTreeEpoch() != last_tree_epoch_) {
                if (banner_flow_changed ||
                    UiTreeEpoch() != last_tree_epoch_) {
                    // Flow/structure changed: the whole page geometry moved.
                    window_.RequestLayout();
                } else {
                    // batch29 P2/P3: content-only tick. One re-arrange for the
                    // new text widths, then repaint just the changed elements
                    // (their parents cover shifted siblings) instead of the
                    // whole window + all 62 texts.
                    window_.RepaintChangedContent();
                }
            }
            last_content_epoch_ = content_epoch;
            last_tree_epoch_ = UiTreeEpoch();
            // D2 fix: when the snapshot seq advanced but no visible content
            // changed (content_rev static, banner flow unchanged), do NOT
            // repaint. The old unconditional Invalidate() forced a full-window
            // repaint on every 500 ms stats / 1 s status publish, which kept
            // the CPU busy (~2-3 Hz full repaints) even on a static page.
        }

        void UiApp::ApplyLanguage() {
            I18n& i18n = I18n::Instance();
            language_ = i18n.Lang();
            if (root_ == nullptr) {
                return;
            }
            if (sidebar_ != nullptr) {
                sidebar_->SetLang(i18n);
            }
            if (banner_ != nullptr) {
                banner_->SetLang(i18n);
            }
            UpdateHeaderTitle();
            if (router_ != nullptr && snapshot_) {
                router_->UpdateAll(snapshot_, i18n);
            }
            // Localized labels change text widths (same class as I1).
            window_.RequestLayout();
        }

        void UiApp::OnTick() {
            // batch22 B4: a web-triggered repair request is serviced here, on the UI
            // thread (toasts/in-flight state are UI-thread bound).
            if (web_repair_requested_.exchange(false)) {
                RequestDriverRepair();
            }
            // batch37t: a Web POST /api/config is applied on the UI thread through the
            // exact native settings command (write + live apply + failure toast).
            if (web_config_pending_.exchange(false)) {
                vgww::core::Config config;
                std::function<void(bool, const std::string&)> result_sink;
                {
                    std::lock_guard<std::mutex> lock(web_config_mutex_);
                    config = web_config_;
                    result_sink = std::move(web_config_result_);
                }
                if (controller_ != nullptr) {
                    SaveConfigCmd cmd;
                    cmd.config = std::move(config);
                    cmd.result_sink = std::move(result_sink);
                    controller_->Post(Command{std::move(cmd)});
                } else if (result_sink) {
                    result_sink(false, "no UI command worker");
                }
            }
            const bool perf = ::GetEnvironmentVariableW(L"VGWW_PERF", nullptr, 0) != 0;
            const auto t0 = std::chrono::steady_clock::now();
            // T8-F1 retire+sweep cleanup point: the tick fires outside any widget
            // event frame, so retired dialog subtrees (whose button frames still run
            // during that event) are only destroyed here.
            SweepRetiredDialogChrome();
            I18n& i18n = I18n::Instance();
            if (i18n.Lang() != language_) {
                ApplyLanguage();
            }
            // Batch16 F2.3: surface the async elevated-repair outcome. The worker
            // thread only touches the shared state; the toast happens here on the
            // UI thread.
            if (repair_state_ != nullptr) {
                bool done = false;
                bool ok = false;
                std::wstring summary;
                {
                    std::lock_guard<std::mutex> lock(repair_state_->mutex);
                    done = repair_state_->done;
                    ok = repair_state_->ok;
                    summary = repair_state_->summary;
                }
                if (done) {
                    if (toasts_ != nullptr) {
                        if (ok) {
                            toasts_->Show(Str::FixSucceeded, ToastKind::Info);
                        } else {
                            toasts_->ShowText(
                                i18n.Format(Str::FixFailedFmt, {summary}),
                                ToastKind::Warning);
                        }
                    }
                    // P94: the repair outcome used to live only in a toast
                    // (transient, UI-thread) and stderr. The audit ring is the
                    // operator's durable record of privileged changes, and a
                    // failed repair is exactly what a post-mortem needs - the
                    // web route records the request, the result must be here.
                    console_log::AppendAuditLine(
                        ok ? "driver repair succeeded"
                           : "driver repair failed");
                    repair_state_.reset();
                    repair_in_flight_ = false;
                }
            }
            // Everything below is guarded by a controller; the metrics backfill at the
            // very end runs unconditionally (a controller-less tick still counts).
            if (controller_ != nullptr) {
                    // Snapshot polling: only a new seq triggers a repaint; the timer
                    // never sleeps (the message loop stays responsive).
                    std::shared_ptr<const UiSnapshot> snapshot =
                        controller_->Load();
                    if (snapshot && (!snapshot_ || snapshot->seq != snapshot_->seq)) {
                        // M10-2-lite: adopt the loaded object (no second deep copy;
                        // the seq guard above stays, pointer comparison is not an
                        // equivalent substitute here).
                        Update(std::move(snapshot));
                    }
                    // batch28: keep the tray's service item label in sync with the live
                    // service state (reads the adopted snapshot, no extra poll).
                    tray::SetServiceRunning(snapshot_ != nullptr &&
                                            snapshot_->dataplane_running);
                    bool dirty = DrainCommandResults();
                    if (toasts_ != nullptr) {
                        const std::size_t before = toasts_->active_count();
                        toasts_->Tick(std::chrono::steady_clock::now());
                        if (toasts_->active_count() != before) {
                            dirty = true;
                        }
                    }
                    if (dirty && window_.hwnd() != nullptr) {
                        window_.Invalidate();
                    }
            }
            // T8 metrics: backfill the window's tick counters every tick (the window
            // does not own the tick; the app does). Always recorded, perf verbosity
            // only affects the stderr line below.
            const auto tick_us = std::chrono::duration_cast<
                std::chrono::microseconds>(std::chrono::steady_clock::now() - t0)
                                     .count();
            window_.RecordTickForTest(static_cast<long long>(tick_us));
            if (perf) {
                std::fprintf(stderr, "[perf] tick=%lldus\n",
                             static_cast<long long>(tick_us));
            }
        }

        // batch42: drain pending command results and show their outcome toasts on
        // the UI thread. Split out of OnTick so a headless test can drive the
        // save-outcome toast without the snapshot poll/reflect part (which would
        // clobber the form back to the fixture values).
        bool UiApp::DrainCommandResults() {
            if (controller_ == nullptr) {
                return false;
            }
            bool dirty = false;
            const std::vector<CommandResult> results = controller_->DrainResults();
            const I18n& i18n = I18n::Instance();
            for (const CommandResult& result : results) {
                if (!result.ok && router_ != nullptr) {
                    // batch281: tell the page it is looking at that its command failed.
                    // The page cannot learn this from a snapshot - a refused start/stop
                    // leaves the runtime state untouched - so an in-flight "busy"
                    // indicator would stay armed forever.
                    if (Page* page = router_->current()) {
                        page->OnCommandFailed();
                    }
                }
                if (result.save_config) {
                    // A native settings save is toasted by its true outcome - success
                    // only once the async save+apply really succeeded; a rollback shows
                    // the actionable reason instead of the old optimistic "saved" plus
                    // a bare generic error with the cause hidden on stderr.
                    if (toasts_ != nullptr) {
                        if (result.ok) {
                            toasts_->Show(Str::CommonSaved, ToastKind::Success);
                        } else {
                            toasts_->ShowText(result.message, ToastKind::Danger);
                        }
                    }
                    if (!result.ok) {
                        std::fprintf(stderr, "[ui] command failed: %ls\n",
                                     result.message.c_str());
                    }
                    dirty = true;
                } else if (!result.ok) {
                    // batch118: the reason used to go to stderr only, so a GUI user
                    // saw a generic "Error" toast and had no idea which input was
                    // wrong. The executor messages are localized (controller.cpp), so
                    // they are safe to show verbatim - a long report is truncated in
                    // the toast renderer, not here.
                    if (toasts_ != nullptr) {
                        const std::wstring reason =
                            result.message.empty() ? std::wstring(i18n.T(Str::CommonError))
                                                   : result.message;
                        toasts_->ShowText(reason, ToastKind::Danger);
                    }
                    std::fprintf(stderr, "[ui] command failed: %ls\n",
                                 result.message.c_str());
                    dirty = true;
                }
            }
            return dirty;
        }

        int UiApp::Run(HINSTANCE instance, UiController& controller,
                       const UiSnapshot& first, bool start_minimized,
                       const std::string& initial_page) {
            // S5 GUI fix (G8): drive the startup language. batch19 R4-P4: the
            // persisted config language (ui_language) wins; an unknown value
            // falls back to zh-CN; empty falls back to the OS locale. Done
            // before Compose so the first paint is already localized.
            {
                I18n& i18n = I18n::Instance();
                if (initial_language_.empty()) {
                    i18n.SetLang(DetectSystemLang());
                } else if (I18n::IsKnownLanguageCode(initial_language_)) {
                    i18n.SetLangCode(initial_language_);
                } else {
                    i18n.SetLang(Lang::ZhCN);
                }
            }
            // S5.20: stash the requested page before Compose so its trailing
            // NavigateInitialPage() (the first navigation) honours it.
            initial_page_ = initial_page;
            if (!composed_) {
                Compose(controller, first);
            } else if (I18n::Instance().Lang() != language_) {
                ApplyLanguage();
            }
            // When the shell was already composed the Compose-time initial
            // navigation has already run with the default home page; re-apply
            // the requested page so --ui-page still wins. Idempotent when
            // Compose just handled it above.
            if (!initial_page_.empty() &&
                router_->page_ids().end() !=
                    std::find(router_->page_ids().begin(),
                              router_->page_ids().end(), initial_page_)) {
                NavigateTo(initial_page_);
            }
            // The tray check mark must reflect the registry from the start.
            tray::UpdateMenu(tray::IsAutostartEnabled());
            std::string error;
            if (!window_.Create(instance, start_minimized, error)) {
                std::fprintf(stderr, "[ui] window creation failed: %s\n",
                             error.c_str());
                controller.Stop();
                tray::Remove();
                return 1;
            }
            window_.SetRoot(root_.get());
            // batch20: apply the persisted UI scale before the first paint
            // (0 = auto, which is a no-op: the system DPI already applied).
            if (initial_ui_scale_ > 0.0f) {
                window_.SetUiScale(initial_ui_scale_);
            }
            window_.on_snapshot_tick = [this] { OnTick(); };
            // batch25b: X means "close the window, keep serving" - the prompt
            // explains that on the first close of this launch.
            window_.on_close_requested = [this] { OnCloseRequested(); };
            // batch28: the tray's start/stop item goes through the ONE command
            // channel (the same queue the dashboard button uses). The label's
            // state comes from the snapshot in OnTick.
            tray::SetServiceRunning(first.dataplane_running);
            window_.on_toggle_service = [this](bool start) {
                ToggleServiceFromTray(start);
            };
            // batch29: tray "Open dashboard" - the window already showed
            // itself; switch to the dashboard page through the normal route.
            window_.on_open_dashboard = [this] { OpenDashboardFromTray(); };
            // batch25b: an unusable adapter on a fresh launch opens the
            // first-run wizard (once per launch; a valid config never does).
            MaybeShowFirstRunWizard(first);
            window_.on_exit = [this] {
                if (controller_ != nullptr) {
                    controller_->Stop();
                }
            };
            window_.RunMessageLoop();
            // Exit sequence: window closed -> controller stopped -> tray gone.
            controller.Stop();
            tray::Remove();
            return 0;
        }

    }  // namespace ui
}  // namespace vgww
