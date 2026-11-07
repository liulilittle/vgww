// ============================================================================
// controller.h - UI controller: the two background workers wired to the real
// runtime (S4.2 Task 5).
//
// Composition: UiController owns the SnapshotPublisher (data -> UI) and the
// CommandQueue (UI -> data) and is the only UI-facing entry point; RealDataSource
// samples Dataplane + RuleStore into immutable UiSnapshots; the
// DataplaneCommandExecutor validates UI commands with the core parsers and
// drives Dataplane / RuleStore / the config file.
//
// Threading: the UI thread calls Start/Stop/Load/Post/DrainResults only. The
// publisher thread reads Dataplane status accessors (safe in any lifecycle
// state by contract) and RuleStore (internally locked); the command thread
// runs exactly one command at a time (strict FIFO, see snapshot.h).
// ============================================================================
#pragma once

#include "ui/snapshot.h"

#include <atomic>
#include <chrono>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace vgww {
    namespace ui {

        /// Runtime-only facts the UI needs that core::Config does not carry
        /// (decided by the entry point: web bind/enable, the loaded config
        /// path, and the dataplane's start error for the degraded view).
        struct UiRuntimeFlags {
            bool web_enabled = false;
            std::string web_bind;       ///< e.g. "127.0.0.1"
            std::string config_path;    ///< file SaveConfigCmd rewrites
            std::string dataplane_error;  ///< empty = started cleanly
            /// batch37s: live state shared with the entry point's apply hook.
            /// The publisher takes config_mutex while copying ConfigView; the
            /// hook holds it only for the object swap. web_enabled_live keeps
            /// the About row truthful after a runtime Web-UI toggle.
            std::shared_ptr<std::atomic<bool>> web_enabled_live;
            std::shared_ptr<std::mutex> config_mutex;
        };

        /// UI-thread surface over the publisher + command worker. Start is
        /// idempotent (false on the second call); Stop drains pending
        /// commands, then stops the publisher (both idempotent).
        class UiController final {
        public:
            UiController(UiDataSource& source, CommandExecutor& executor);
            ~UiController();

            UiController(const UiController&) = delete;
            UiController& operator=(const UiController&) = delete;

            bool Start(std::string& error);
            void Stop() noexcept;
            std::shared_ptr<const UiSnapshot> Load() const noexcept;
            bool Post(Command cmd);
            std::vector<CommandResult> DrainResults();  ///< <= 16 per call

        private:
            SnapshotPublisher publisher_;
            CommandQueue queue_;
        };

        /// Real data source. `config` must outlive this object (the entry
        /// point owns it for the process lifetime, same contract as
        /// runtime::Dataplane).
        class RealDataSource final : public UiDataSource {
        public:
            RealDataSource(runtime::Dataplane& dataplane,
                           const core::Config& config, UiRuntimeFlags flags);

            ConfigView ConfigSnapshot() override;
            std::shared_ptr<UiSnapshot> Collect(uint64_t seq) override;
            void CollectStats(UiSnapshot& snapshot) override;

        private:
            runtime::Dataplane& dataplane_;
            const core::Config& config_;
            UiRuntimeFlags flags_;
            std::chrono::steady_clock::time_point started_;
            /// batch25a: once the plane has actually run, the startup error
            /// from the entry point is stale; only the live lifecycle error
            /// remains authoritative.
            bool ever_running_ = false;
        };

        /// Real command executor. Inputs are validated with the core parsers
        /// (ParseMac/ParseIpv4/InetPtonW) BEFORE any state changes; every
        /// command yields exactly one CommandResult with a localized reason.
        class DataplaneCommandExecutor final : public CommandExecutor {
        public:
            /// SetAutostartCmd is wired to the tray in T7; tests inject a
            /// hook. Without a hook the command fails loudly.
            using AutostartHook =
                std::function<CommandResult(const SetAutostartCmd&)>;
            /// batch37j (user): a settings save must apply immediately instead
            /// of only asking for an app restart. The entry point supplies the
            /// live-config mutation + dataplane restart; false + `error`
            /// reports a failure (the file is already saved).
            using ApplyLiveHook =
                std::function<bool(const core::Config&, std::wstring& error)>;

            DataplaneCommandExecutor(runtime::Dataplane& dataplane,
                                     std::string config_path,
                                     AutostartHook autostart = {},
                                     ApplyLiveHook apply_live = {});

            CommandResult Execute(const Command& cmd) override;

        private:
            runtime::Dataplane& dataplane_;
            std::string config_path_;
            AutostartHook autostart_;
            ApplyLiveHook apply_live_;
        };

    }  // namespace ui
}  // namespace vgww
