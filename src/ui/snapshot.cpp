// ============================================================================
// snapshot.cpp - publisher thread + FIFO command worker (S4.2 Task 4).
// ============================================================================
#include "ui/snapshot.h"

#include "ui/console_log.h"

#include <algorithm>
#include <cstdio>
#include <exception>
#include <utility>

namespace vgww {
    namespace ui {

        namespace {

            constexpr size_t kMaxPendingCommands = 64;
            constexpr size_t kMaxDrainPerCall = 16;
            constexpr std::chrono::seconds kJoinTimeout{1};

        }  // namespace

        // --- SnapshotPublisher -------------------------------------------------

        SnapshotPublisher::SnapshotPublisher(UiDataSource& source,
                                             std::chrono::milliseconds stats_every,
                                             std::chrono::milliseconds status_every)
            : source_(source), stats_every_(stats_every), status_every_(status_every),
              empty_(std::make_shared<const UiSnapshot>()) {
            published_ = empty_;
        }

        SnapshotPublisher::~SnapshotPublisher() {
            Stop();
            if (thread_.joinable()) {
                thread_.join();
            }
        }

        bool SnapshotPublisher::Start(std::string& error) {
            if (running_.load()) {
                error = "snapshot publisher already running";
                return false;
            }
            if (thread_.joinable()) {
                error = "snapshot publisher thread not joined";
                return false;
            }
            stop_.store(false);
            refresh_requested_.store(false);
            {
                std::lock_guard<std::mutex> lock(wait_mutex_);
                refresh_at_.reset();
            }
            finished_.store(false);
            running_.store(true);
            thread_ = std::thread(&SnapshotPublisher::Run, this);
            error.clear();
            return true;
        }

        void SnapshotPublisher::Stop() noexcept {
            running_.store(false);
            stop_.store(true);
            wait_cv_.notify_all();
            if (!thread_.joinable()) {
                return;
            }
            {
                std::unique_lock<std::mutex> lock(finish_mutex_);
                finish_cv_.wait_for(lock, kJoinTimeout,
                                    [this] { return finished_.load(); });
            }
            if (finished_.load()) {
                thread_.join();
            } else {
                // Keep the thread (and this object) alive: detaching a thread
                // that touches `this` would be a use-after-free.
                std::fprintf(stderr,
                             "[ui] SnapshotPublisher::Stop join timed out; "
                             "thread kept alive\n");
            }
        }

        std::shared_ptr<const UiSnapshot> SnapshotPublisher::Load() const noexcept {
            std::lock_guard<std::mutex> lock(load_mutex_);
            return published_;
        }

        void SnapshotPublisher::RequestRefreshAfter(std::chrono::milliseconds delay) {
            if (delay.count() < 0) {
                delay = std::chrono::milliseconds(0);
            }
            {
                std::lock_guard<std::mutex> lock(wait_mutex_);
                const auto at = std::chrono::steady_clock::now() + delay;
                if (!refresh_at_.has_value() || at < *refresh_at_) {
                    refresh_at_ = at;
                }
            }
            refresh_requested_.store(true);
            wait_cv_.notify_all();
        }

        void SnapshotPublisher::Publish(bool full) {
            const uint64_t seq = seq_.fetch_add(1) + 1;
            const auto now = std::chrono::steady_clock::now();
            std::shared_ptr<const UiSnapshot> next;
            if (full) {
                // A data source must not throw (interface contract), but an
                // escaping exception must never terminate the publisher
                // thread or kill the tick loop: contain it, fall back to the
                // empty snapshot, and keep the seq monotonic.
                std::shared_ptr<UiSnapshot> collected;
                try {
                    collected = source_.Collect(seq);
                } catch (const std::exception& ex) {
                    std::fprintf(stderr,
                                 "[ui] source Collect threw: %s\n", ex.what());
                } catch (...) {
                    std::fprintf(stderr,
                                 "[ui] source Collect threw (unknown)\n");
                }
                if (collected == nullptr) {
                    collected = std::make_shared<UiSnapshot>();
                }
                // The publisher owns seq/published_at so a source cannot
                // publish out-of-order snapshots. batch52: publish the
                // collected object itself - the previous defensive deep copy
                // doubled every table allocation on each status tick.
                collected->seq = seq;
                collected->published_at = now;
                next = std::move(collected);
            } else {
                auto snapshot = std::make_shared<UiSnapshot>(*Load());
                snapshot->seq = seq;
                snapshot->published_at = now;
                // Same containment for the stats hook: the copied snapshot
                // is still published (seq advances) with the light fields
                // left stale.
                try {
                    source_.CollectStats(*snapshot);
                } catch (const std::exception& ex) {
                    std::fprintf(stderr,
                                 "[ui] source CollectStats threw: %s\n",
                                 ex.what());
                } catch (...) {
                    std::fprintf(stderr,
                                 "[ui] source CollectStats threw (unknown)\n");
                }
                next = std::move(snapshot);
            }
            {
                std::lock_guard<std::mutex> lock(load_mutex_);
                published_ = std::move(next);
            }
        }

        void SnapshotPublisher::Run() {
            Publish(true);  // initial snapshot so Load() is useful immediately

            auto next_stats = std::chrono::steady_clock::now() + stats_every_;
            auto next_status = std::chrono::steady_clock::now() + status_every_;
            std::unique_lock<std::mutex> lock(wait_mutex_);
            while (!stop_.load()) {
                auto wake = std::min(next_stats, next_status);
                if (refresh_at_.has_value()) {
                    wake = std::min(wake, *refresh_at_);
                }
                wait_cv_.wait_until(lock, wake, [this] {
                    return stop_.load() || refresh_requested_.load();
                });
                if (stop_.load()) {
                    break;
                }
                refresh_requested_.store(false);  // consumed; refresh_at_ keeps the deadline
                const auto now = std::chrono::steady_clock::now();
                bool full = false;
                if (refresh_at_.has_value() && now >= *refresh_at_) {
                    refresh_at_.reset();
                    full = true;  // command finished: refresh everything
                }
                if (now >= next_status) {
                    next_status = now + status_every_;
                    full = true;
                }
                const bool stats_due = now >= next_stats;
                if (stats_due) {
                    next_stats = now + stats_every_;
                }
                if (full || stats_due) {
                    lock.unlock();
                    Publish(full);
                    lock.lock();
                }
            }
            finished_.store(true);
            finish_cv_.notify_all();
        }

        // --- CommandQueue ------------------------------------------------------

        CommandQueue::CommandQueue(CommandExecutor& executor, SnapshotPublisher& publisher)
            : executor_(executor), publisher_(publisher) {}

        CommandQueue::~CommandQueue() {
            Stop();
            if (thread_.joinable()) {
                thread_.join();
            }
        }

        bool CommandQueue::Start(std::string& error) {
            std::lock_guard<std::mutex> lock(mutex_);
            if (running_) {
                error = "command queue already running";
                return false;
            }
            if (thread_.joinable()) {
                error = "command queue thread not joined";
                return false;
            }
            stop_ = false;
            finished_.store(false);
            running_ = true;
            thread_ = std::thread(&CommandQueue::Run, this);
            error.clear();
            return true;
        }

        void CommandQueue::Stop() noexcept {
            {
                std::lock_guard<std::mutex> lock(mutex_);
                if (!running_ && !thread_.joinable()) {
                    return;
                }
                running_ = false;
                stop_ = true;
                cv_.notify_all();
            }
            if (!thread_.joinable()) {
                return;
            }
            {
                std::unique_lock<std::mutex> lock(finish_mutex_);
                finish_cv_.wait_for(lock, kJoinTimeout,
                                    [this] { return finished_.load(); });
            }
            if (finished_.load()) {
                thread_.join();
            } else {
                std::fprintf(stderr,
                             "[ui] CommandQueue::Stop join timed out; "
                             "thread kept alive\n");
            }
        }

        bool CommandQueue::Post(Command cmd) {
            std::lock_guard<std::mutex> lock(mutex_);
            if (!running_) {
                // P108: a command posted while the worker is down was dropped
                // with only a caller-side toast; the ring is the operator's
                // durable record, so a silently refused command must land there.
                console_log::AppendAuditLine(
                    "command refused (worker not running)");
                return false;
            }
            if (queue_.size() >= kMaxPendingCommands) {
                // P108: the 65th pending command is backpressure, not a
                // success - record the refusal so the operator can see that a
                // click never became a command.
                console_log::AppendAuditLine(
                    "command refused (queue full)");
                return false;  // backpressure: the UI shows a busy toast
            }
            queue_.push_back(std::move(cmd));
            cv_.notify_one();
            return true;
        }

        std::vector<CommandResult> CommandQueue::DrainResults() {
            std::lock_guard<std::mutex> lock(mutex_);
            const size_t take = std::min(results_.size(), kMaxDrainPerCall);
            std::vector<CommandResult> out(results_.begin(), results_.begin() + take);
            results_.erase(results_.begin(), results_.begin() + take);
            return out;
        }

        size_t CommandQueue::pending() const noexcept {
            std::lock_guard<std::mutex> lock(mutex_);
            return queue_.size();
        }

        void CommandQueue::Run() {
            for (;;) {
                Command cmd;
                {
                    std::unique_lock<std::mutex> lock(mutex_);
                    cv_.wait(lock, [this] { return stop_ || !queue_.empty(); });
                    if (queue_.empty()) {
                        if (stop_) {
                            break;  // drained and stopping: no silent loss
                        }
                        continue;
                    }
                    cmd = std::move(queue_.front());
                    queue_.pop_front();
                }
                // Execute outside the lock so Post never blocks behind a
                // command. An executor must not throw (interface contract),
                // but an escaping exception must not terminate the worker
                // thread: report the command as failed and keep the 1:1
                // result contract (exactly one result per accepted command).
                CommandResult result;
                try {
                    result = executor_.Execute(cmd);
                } catch (const std::exception& ex) {
                    std::fprintf(stderr,
                                 "[ui] command executor threw: %s\n",
                                 ex.what());
                    result.ok = false;
                    result.message = L"internal error";
                } catch (...) {
                    std::fprintf(stderr,
                                 "[ui] command executor threw (unknown)\n");
                    result.ok = false;
                    result.message = L"internal error";
                }
                {
                    std::lock_guard<std::mutex> lock(mutex_);
                    results_.push_back(std::move(result));
                }
                // The UI may want to see the effect immediately.
                publisher_.RequestRefreshAfter(std::chrono::milliseconds(0));
            }
            finished_.store(true);
            finish_cv_.notify_all();
        }

    }  // namespace ui
}  // namespace vgww
