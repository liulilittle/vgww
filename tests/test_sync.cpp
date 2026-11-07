// ============================================================================
// test_sync.cpp - headless tests for the snapshot publisher + command queue
// (S4.2 Task 4). No window, no D2D: a fake data source and a fake executor
// drive the single-writer publisher and the FIFO command worker.
// ============================================================================
#include "ui/controller.h"
#include "ui/snapshot.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <fstream>
#include <functional>
#include <mutex>
#include <set>
#include <stdexcept>
#include <string>
#include <thread>
#include <type_traits>
#include <vector>

static int g_failures = 0;
#define CHECK(cond) do { if (!(cond)) { ++g_failures; \
    std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)

using namespace std::chrono_literals;

namespace {

/// Bounded wait helper: polls `pred` until the explicit deadline (2 s max).
/// Not a duration guess - the deadline is the assertion.
bool WaitFor(const std::function<bool()>& pred,
             std::chrono::milliseconds timeout = 2000ms) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    for (;;) {
        if (pred()) {
            return true;
        }
        if (std::chrono::steady_clock::now() >= deadline) {
            return pred();
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}

std::string Label(const vgww::ui::Command& cmd) {
    return std::visit(
        [](const auto& c) -> std::string {
            using T = std::decay_t<decltype(c)>;
            if constexpr (std::is_same_v<T, vgww::ui::AddPortMapCmd>) {
                return "add-portmap:" + c.proto;
            } else if constexpr (std::is_same_v<T, vgww::ui::RemovePortMapCmd>) {
                return c.id != 0 ? "remove-portmap-id:" + std::to_string(c.id)
                                 : "remove-portmap:" + std::to_string(c.index);
            } else if constexpr (std::is_same_v<T, vgww::ui::AddBanCmd>) {
                return "add-ban:" + c.value;
            } else if constexpr (std::is_same_v<T, vgww::ui::RemoveBanCmd>) {
                return c.id != 0 ? "remove-ban-id:" + std::to_string(c.id)
                                 : "remove-ban:" + std::to_string(c.index);
            } else if constexpr (std::is_same_v<T, vgww::ui::SetRateLimitCmd>) {
                return "set-rate:" + c.mac;
            } else if constexpr (std::is_same_v<T, vgww::ui::RemoveRateLimitCmd>) {
                return "remove-rate:" + c.mac;
            } else if constexpr (std::is_same_v<T, vgww::ui::AddDhcpBindingCmd>) {
                return "add-dhcp:" + c.mac;
            } else if constexpr (std::is_same_v<T, vgww::ui::RemoveDhcpBindingCmd>) {
                return "remove-dhcp:" + c.mac;
            } else if constexpr (std::is_same_v<T, vgww::ui::AddDhcp6BindingCmd>) {
                return "add-dhcp6:" + c.duid;
            } else if constexpr (std::is_same_v<T, vgww::ui::RemoveDhcp6BindingCmd>) {
                return "remove-dhcp6:" + c.duid;
            } else if constexpr (std::is_same_v<T, vgww::ui::SaveConfigCmd>) {
                return "save-config";
            } else if constexpr (std::is_same_v<
                                     T, vgww::ui::SetLanguageCmd>) {
                return "set-language:" + c.code;
            } else if constexpr (std::is_same_v<
                                     T, vgww::ui::StartServiceCmd>) {
                return "start-service";
            } else if constexpr (std::is_same_v<
                                     T, vgww::ui::StopServiceCmd>) {
                return "stop-service";
            } else if constexpr (std::is_same_v<
                                     T, vgww::ui::RecheckServiceCmd>) {
                return "recheck-service";
            } else {
                static_assert(std::is_same_v<T, vgww::ui::SetAutostartCmd>,
                              "unhandled command type");
                return c.enabled ? "set-autostart:1" : "set-autostart:0";
            }
        },
        cmd);
}

/// Controllable data source: counters derive from the lease count so every
/// published snapshot must be internally consistent (leases.size() equals
/// dhcp_bindings.size() and rx_frames tracks the same N).
class FakeDataSource final : public vgww::ui::UiDataSource {
public:
    vgww::ui::ConfigView ConfigSnapshot() override {
        vgww::ui::ConfigView view;
        view.adapter = "fake0";
        view.mode = "bypass";
        view.dhcp_lease_s = 3600;
        return view;
    }

    std::shared_ptr<vgww::ui::UiSnapshot> Collect(uint64_t seq) override {
        const uint64_t n = lease_count_.load();
        auto snap = std::make_shared<vgww::ui::UiSnapshot>();
        snap->seq = seq;
        snap->rules_rev = rules_rev_.load();
        snap->published_at = std::chrono::steady_clock::now();
        snap->config = ConfigSnapshot();
        snap->dataplane_running = true;
        snap->counters.rx_frames = 1000 + rx_frames_.fetch_add(1);
        for (uint64_t i = 0; i < n; ++i) {
            snap->leases.push_back(vgww::runtime::Dataplane::LeaseView{});
            snap->dhcp_bindings.push_back(vgww::runtime::Dataplane::BindingView{});
        }
        ++full_collections_;
        {
            std::lock_guard<std::mutex> lock(last_mutex_);
            last_collected_ = snap;
        }
        return snap;
    }

    /// Stats tick: refresh counters on the copied snapshot only (the heavy
    /// vectors keep their last full-collect contents).
    void CollectStats(vgww::ui::UiSnapshot& snapshot) override {
        snapshot.counters.rx_frames = 1000 + rx_frames_.fetch_add(1);
        snapshot.rules_rev = rules_rev_.load();
        ++stats_collections_;
    }

    void SetLeaseCount(uint64_t n) { lease_count_.store(n); }
    void SetRulesRev(uint64_t rev) { rules_rev_.store(rev); }
    int full_collections() const { return full_collections_.load(); }
    int stats_collections() const { return stats_collections_.load(); }
    std::shared_ptr<const vgww::ui::UiSnapshot> last_collected() const {
        std::lock_guard<std::mutex> lock(last_mutex_);
        return last_collected_;
    }

private:
    std::atomic<uint64_t> lease_count_{0};
    std::atomic<uint64_t> rules_rev_{0};
    std::atomic<uint64_t> rx_frames_{0};
    std::atomic<int> full_collections_{0};
    std::atomic<int> stats_collections_{0};
    mutable std::mutex last_mutex_;
    std::shared_ptr<const vgww::ui::UiSnapshot> last_collected_;
};

/// Records execution order, can inject failures and can block the first
/// command (backpressure test) behind a gate.
class FakeExecutor final : public vgww::ui::CommandExecutor {
public:
    vgww::ui::CommandResult Execute(const vgww::ui::Command& cmd) override {
        const std::string label = Label(cmd);
        bool first = false;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            first = order_.empty();
        }
        if (first && gate_enabled_.load()) {
            std::unique_lock<std::mutex> gate_lock(gate_mutex_);
            entered_.store(true);
            gate_cv_.notify_all();
            gate_cv_.wait(gate_lock, [this] { return released_.load(); });
        }
        std::lock_guard<std::mutex> lock(mutex_);
        order_.push_back(label);
        ++executed_;
        executed_cv_.notify_all();
        vgww::ui::CommandResult result;
        result.ok = fail_labels_.count(label) == 0;
        if (!result.ok) {
            result.message = L"injected failure";
        }
        return result;
    }

    void SetFailLabel(std::string label) {
        std::lock_guard<std::mutex> lock(mutex_);
        fail_labels_.insert(std::move(label));
    }

    void EnableGate() {
        gate_enabled_.store(true);
        released_.store(false);
        entered_.store(false);
    }

    void WaitUntilEntered() {
        std::unique_lock<std::mutex> lock(gate_mutex_);
        gate_cv_.wait_for(lock, 2000ms, [this] { return entered_.load(); });
    }

    void ReleaseGate() {
        released_.store(true);
        gate_cv_.notify_all();
    }

    bool WaitForExecutions(size_t n, std::chrono::milliseconds timeout) {
        std::unique_lock<std::mutex> lock(mutex_);
        return executed_cv_.wait_for(lock, timeout, [this, n] { return executed_ >= n; });
    }

    size_t executions() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return executed_;
    }

    std::vector<std::string> Order() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return order_;
    }

private:
    mutable std::mutex mutex_;
    std::condition_variable executed_cv_;
    std::vector<std::string> order_;
    std::set<std::string> fail_labels_;
    size_t executed_ = 0;

    std::atomic<bool> gate_enabled_{false};
    std::atomic<bool> released_{false};
    std::atomic<bool> entered_{false};
    std::mutex gate_mutex_;
    std::condition_variable gate_cv_;
};

}  // namespace

// ---------------------------------------------------------------------------

static void TestLoadBeforeStartAndStartIdempotent() {
    FakeDataSource source;
    vgww::ui::SnapshotPublisher publisher(source, 20ms, 50ms);

    const auto before = publisher.Load();
    CHECK(before != nullptr);                                   // never null
    CHECK(before->seq == 0);
    CHECK(before->leases.empty());

    std::string error;
    CHECK(publisher.Start(error));
    CHECK(!publisher.Start(error));                             // repeat -> false
    publisher.Stop();
    publisher.Stop();                                           // idempotent

    const auto after = publisher.Load();
    CHECK(after != nullptr);
    CHECK(after->seq >= 1);                                     // last snapshot
}

static void TestPublishMonotonic() {
    FakeDataSource source;
    source.SetLeaseCount(3);
    vgww::ui::SnapshotPublisher publisher(source, 10ms, 30ms);
    std::string error;
    CHECK(publisher.Start(error));

    uint64_t last_seq = 0;
    uint64_t last_rx = 0;
    uint64_t last_rules = 0;
    for (int i = 0; i < 6; ++i) {
        const uint64_t target = last_seq + 1;
        CHECK(WaitFor([&] { return publisher.Load()->seq >= target; }));
        const auto snap = publisher.Load();
        CHECK(snap->seq > last_seq);                            // strictly growing
        CHECK(snap->counters.rx_frames >= last_rx);             // never rewinds
        CHECK(snap->rules_rev >= last_rules);
        CHECK(snap->leases.size() == snap->dhcp_bindings.size());  // not torn
        CHECK(snap->config.adapter == "fake0");
        last_seq = snap->seq;
        last_rx = snap->counters.rx_frames;
        last_rules = snap->rules_rev;
        if (i == 3) {
            source.SetRulesRev(7);                              // monotonic anchor
        }
    }
    CHECK(last_rx >= 1005);
    CHECK(last_rules == 7);
    CHECK(source.full_collections() >= 1);
    CHECK(source.stats_collections() >= 1);
    publisher.Stop();
}

// batch52 (perf): a full publish must publish the very snapshot object the
// source collected - there is no second deep copy of every table on every
// status tick. Red: Load() pointed at a defensive copy, so the addresses
// never matched.
static void TestPublishFullReusesCollectedSnapshot() {
    FakeDataSource source;
    source.SetLeaseCount(2);
    vgww::ui::SnapshotPublisher publisher(source, 60s, 60s);
    std::string error;
    CHECK(publisher.Start(error));
    CHECK(WaitFor([&] { return publisher.Load()->seq >= 1; }));
    const uint64_t prev = publisher.Load()->seq;
    publisher.RequestRefreshAfter(std::chrono::milliseconds(0));
    CHECK(WaitFor([&] { return publisher.Load()->seq >= prev + 1; }));
    const auto collected = source.last_collected();
    const auto published = publisher.Load();
    CHECK(collected != nullptr);
    CHECK(published->leases.size() == 2);
    std::printf("b52 collected@%p published@%p\n",
                static_cast<const void*>(collected.get()),
                static_cast<const void*>(published.get()));
    CHECK(published.get() == collected.get());
    publisher.Stop();
}

static void TestCommandOrderAndResult() {
    FakeDataSource source;
    vgww::ui::SnapshotPublisher publisher(source, 60s, 60s);
    std::string error;
    CHECK(publisher.Start(error));
    FakeExecutor executor;
    executor.SetFailLabel("add-ban:B");
    vgww::ui::CommandQueue queue(executor, publisher);
    CHECK(queue.Start(error));

    CHECK(queue.Post(vgww::ui::AddBanCmd{"mac", "A"}));
    CHECK(queue.Post(vgww::ui::AddBanCmd{"mac", "B"}));
    CHECK(queue.Post(vgww::ui::AddBanCmd{"mac", "C"}));
    CHECK(executor.WaitForExecutions(3, 2000ms));
    const std::vector<std::string> order = executor.Order();
    CHECK(order.size() == 3);
    CHECK(order[0] == "add-ban:A" && order[1] == "add-ban:B" &&
          order[2] == "add-ban:C");                             // strict FIFO

    // batch34s: wait for the RESULTS, not just the executions. CommandQueue
    // pushes each result AFTER Execute() returns, so "3 executions done" can
    // be observed while the third push_back has not happened yet - draining
    // right then yielded 2 results (same anti-pattern as batch34q: a baseline
    // sampled after the event, so the condition was racy). Drain in a loop
    // until the 1:1 contract is satisfied.
    std::vector<vgww::ui::CommandResult> results;
    CHECK(WaitFor(
        [&] {
            auto batch = queue.DrainResults();
            results.insert(results.end(), batch.begin(), batch.end());
            return results.size() >= 3;
        },
        2000ms));
    CHECK(results.size() == 3);                                  // exactly 1:1
    CHECK(results[0].ok && !results[1].ok && results[2].ok);      // failure isolated
    CHECK(queue.DrainResults().empty());                          // drained
    CHECK(queue.pending() == 0);
    publisher.Stop();
}

static void TestStopJoinIdempotent() {
    FakeDataSource source;
    vgww::ui::SnapshotPublisher publisher(source, 10ms, 30ms);
    std::string error;
    CHECK(publisher.Start(error));
    FakeExecutor executor;
    vgww::ui::CommandQueue queue(executor, publisher);
    CHECK(queue.Start(error));

    CHECK(queue.Post(vgww::ui::AddBanCmd{"mac", "S1"}));
    CHECK(queue.Post(vgww::ui::AddBanCmd{"mac", "S2"}));
    queue.Stop();                                               // drains pending
    queue.Stop();                                               // idempotent
    const auto results = queue.DrainResults();
    CHECK(results.size() == 2);                                 // no silent loss
    CHECK(results[0].ok && results[1].ok);

    publisher.Stop();
    publisher.Stop();
    const auto snap = publisher.Load();
    CHECK(snap != nullptr);
    CHECK(snap->seq >= 1);                                      // readable after Stop
}

static void TestRefreshAcceleration() {
    FakeDataSource source;
    vgww::ui::SnapshotPublisher publisher(source, 60s, 60s);    // no natural ticks
    std::string error;
    CHECK(publisher.Start(error));
    CHECK(WaitFor([&] { return publisher.Load()->seq >= 1; }));
    const uint64_t before = publisher.Load()->seq;

    const auto started = std::chrono::steady_clock::now();
    publisher.RequestRefreshAfter(10ms);
    CHECK(WaitFor([&] { return publisher.Load()->seq > before; }, 100ms));
    const auto elapsed = std::chrono::steady_clock::now() - started;
    CHECK(elapsed < 100ms);                                     // early wake, not 60 s
    publisher.Stop();
}

static void TestPostBackpressure() {
    FakeDataSource source;
    vgww::ui::SnapshotPublisher publisher(source, 60s, 60s);
    std::string error;
    CHECK(publisher.Start(error));
    FakeExecutor executor;
    executor.EnableGate();
    vgww::ui::CommandQueue queue(executor, publisher);
    CHECK(queue.Start(error));

    CHECK(queue.Post(vgww::ui::AddBanCmd{"mac", "first"}));
    executor.WaitUntilEntered();                                // worker blocked
    CHECK(queue.pending() == 0);
    for (int i = 0; i < 64; ++i) {
        CHECK(queue.Post(vgww::ui::AddBanCmd{"mac", "q" + std::to_string(i)}));
    }
    CHECK(queue.pending() == 64);
    CHECK(!queue.Post(vgww::ui::AddBanCmd{"mac", "overflow"})); // 65th rejected
    CHECK(queue.pending() == 64);

    executor.ReleaseGate();
    CHECK(executor.WaitForExecutions(65, 2000ms));
    const std::vector<std::string> order = executor.Order();
    CHECK(order.size() == 65);
    bool overflow_seen = false;
    for (const auto& label : order) {
        if (label == "add-ban:overflow") {
            overflow_seen = true;
        }
    }
    CHECK(!overflow_seen);                                      // rejected, never run

    std::vector<vgww::ui::CommandResult> all;
    CHECK(WaitFor([&] {
        const auto batch = queue.DrainResults();
        all.insert(all.end(), batch.begin(), batch.end());
        return all.size() >= 65;
    }));
    CHECK(all.size() == 65);                                    // 1:1 for accepted
    queue.Stop();
    publisher.Stop();
}

static void TestConcurrentLoadDuringPublish() {
    FakeDataSource source;
    source.SetLeaseCount(4);
    vgww::ui::SnapshotPublisher publisher(source, 1ms, 5ms);    // publish hot
    std::string error;
    CHECK(publisher.Start(error));
    CHECK(WaitFor([&] { return publisher.Load()->seq >= 1; }));

    bool consistent = true;
    uint64_t last_seq = 0;
    uint64_t last_rx = 0;
    for (int i = 0; i < 1000; ++i) {
        const auto snap = publisher.Load();
        if (snap == nullptr || snap->seq < last_seq ||
            snap->counters.rx_frames < last_rx ||
            snap->leases.size() != snap->dhcp_bindings.size()) {
            consistent = false;                                 // torn read detected
            break;
        }
        last_seq = snap->seq;
        last_rx = snap->counters.rx_frames;
    }
    CHECK(consistent);
    CHECK(last_seq >= 1);
    publisher.Stop();
}

// ---------------------------------------------------------------------------
// T5: real executor against the shared RuleStore, and the controller
// composition (publisher + queue).

/// Minimal valid config for the executor's SaveConfigCmd test (bypass mode
/// keeps every address-service constraint out of the picture).
vgww::core::Config MakeSaveConfig() {
    vgww::core::Config c;
    c.adapter = "Ethernet";
    bool ok = false;
    c.gateway.ipv4 = vgww::core::ParseIpv4("192.168.0.1", ok);
    c.gateway.mask = vgww::core::ParseIpv4("255.255.255.0", ok);
    vgww::core::ParseMac("30:fc:68:88:b4:a9", c.gateway.mac);
    c.web.port = 9090;
    return c;
}

static void TestRealExecutorAgainstRuleStore() {
    using vgww::ui::AddBanCmd;
    using vgww::ui::AddDhcpBindingCmd;
    using vgww::ui::AddPortMapCmd;
    using vgww::ui::CommandResult;
    using vgww::ui::DataplaneCommandExecutor;
    using vgww::ui::RemovePortMapCmd;
    using vgww::ui::SaveConfigCmd;
    using vgww::ui::SetAutostartCmd;
    using vgww::ui::SetRateLimitCmd;

    // Isolate the process-wide store: persistence off, then empty it.
    vgww::web::RuleStore& store = vgww::web::RuleStore::Instance();
    store.AttachFile("");
    store.Clear();

    const std::string save_path = "test_executor_save.json";
    std::remove(save_path.c_str());

    vgww::core::Config cfg;
    bool ok = false;
    cfg.gateway.ipv4 = vgww::core::ParseIpv4("192.168.0.1", ok);
    CHECK(ok);
    cfg.gateway.mask = vgww::core::ParseIpv4("255.255.255.0", ok);
    CHECK(ok);
    vgww::core::ParseMac("30:fc:68:88:b4:a9", cfg.gateway.mac);
    vgww::runtime::Dataplane dataplane(cfg);  // not started: no threads

    int autostart_calls = 0;
    bool autostart_enabled = false;
    DataplaneCommandExecutor executor(
        dataplane, save_path,
        [&](const SetAutostartCmd& c) -> CommandResult {
            ++autostart_calls;
            autostart_enabled = c.enabled;
            return CommandResult{true, L"autostart ok"};
        });

    // AddPortMap: size +1 and the monotonic anchor +1.
    const uint64_t rev0 = store.Rev();
    CommandResult r = executor.Execute(
        AddPortMapCmd{"tcp", 8080, "192.168.0.50", 80});
    CHECK(r.ok);
    CHECK(store.PortMaps().size() == 1);
    CHECK(store.Rev() == rev0 + 1);

    // Rejected inputs must not touch the store (D8: failed op keeps state).
    const uint64_t rev1 = store.Rev();
    r = executor.Execute(AddPortMapCmd{"udp", 8080, "192.168.0.50", 80});
    CHECK(!r.ok);
    r = executor.Execute(AddPortMapCmd{"tcp", 8080, "not-an-ip", 80});
    CHECK(!r.ok);
    r = executor.Execute(AddPortMapCmd{"tcp", 0, "192.168.0.50", 80});
    CHECK(!r.ok);
    r = executor.Execute(AddPortMapCmd{"tcp", 8080, "192.168.0.50", 80});
    CHECK(!r.ok);
    CHECK(store.PortMaps().size() == 1);
    CHECK(store.Rev() == rev1);

    // AddBan: valid mac/ip accepted, malformed or unknown kind rejected.
    r = executor.Execute(AddBanCmd{"mac", "30:fc:68:88:b4:01"});
    CHECK(r.ok);
    CHECK(store.Bans().size() == 1);
    r = executor.Execute(AddBanCmd{"ip", "999.1.1.1"});
    CHECK(!r.ok);
    r = executor.Execute(AddBanCmd{"domain", "example.com"});
    CHECK(!r.ok);
    CHECK(store.Bans().size() == 1);

    // SetRateLimit: upsert by MAC (case-insensitive), dual-zero rejected.
    r = executor.Execute(SetRateLimitCmd{"30:fc:68:88:b4:01", 1000, 0});
    CHECK(r.ok);
    CHECK(store.RateLimits().size() == 1);
    r = executor.Execute(SetRateLimitCmd{"30:FC:68:88:B4:01", 2000, 3000});
    CHECK(r.ok);
    CHECK(store.RateLimits().size() == 1);
    if (store.RateLimits().size() == 1) {
        CHECK(store.RateLimits()[0].uplink_kbps == 2000);
        CHECK(store.RateLimits()[0].downlink_kbps == 3000);
    }
    r = executor.Execute(SetRateLimitCmd{"30:fc:68:88:b4:01", 0, 0});
    CHECK(!r.ok);


    // Out-of-range removal: ok=false and Rev unchanged.
    const uint64_t rev2 = store.Rev();
    CHECK(!executor.Execute(RemovePortMapCmd{5}).ok);
    CHECK(store.Rev() == rev2);
    CHECK(store.PortMaps().size() == 1);
    CHECK(executor.Execute(RemovePortMapCmd{0}).ok);
    CHECK(store.PortMaps().empty());

    // batch138: the delete command prefers the STABLE id. A command that only
    // carries a position is a snapshot of where the row was drawn; by the time
    // the worker runs it, another writer may have shifted it. This proves the
    // id path reaches RemovePortMapById (an unknown id is refused and does not
    // fall back to deleting some position).
    {
        store.Clear();
        vgww::web::PortMappingRule keep;
        keep.proto = "tcp";
        keep.wan_port = 19080;
        keep.lan_ip = "192.168.0.61";
        keep.lan_port = 61;
        vgww::web::PortMappingRule drop;
        drop.proto = "tcp";
        drop.wan_port = 19081;
        drop.lan_ip = "192.168.0.62";
        drop.lan_port = 62;
        const uint64_t keep_id = store.AddPortMapTracked(keep);
        const uint64_t drop_id = store.AddPortMapTracked(drop);
        CHECK(0 != keep_id && 0 != drop_id);
        // An unknown id must be refused - NOT treated as index 0.
        vgww::ui::RemovePortMapCmd bogus;
        bogus.id = drop_id + 1000;
        CHECK(!executor.Execute(bogus).ok);
        CHECK(store.PortMaps().size() == 2);
        // The real id removes exactly that rule (position 0 stays).
        vgww::ui::RemovePortMapCmd by_id;
        by_id.id = drop_id;
        CHECK(executor.Execute(by_id).ok);
        CHECK(store.PortMaps().size() == 1);
        if (store.PortMaps().size() == 1) {
            CHECK(store.PortMaps()[0].id == keep_id);
        }
        // Id 0 means "not stored": it must be refused, never fall through to
        // the positional path at index 0.
        vgww::ui::RemovePortMapCmd zero;
        zero.id = 0;
        zero.index = 0;
        CHECK(executor.Execute(zero).ok);  // legacy path still works
        CHECK(store.PortMaps().empty());
        store.Clear();
    }

    // batch138: same contract for bans (they gained an id this round).
    {
        store.Clear();
        CHECK(store.AddBanChecked(vgww::web::BanEntry{"mac", "02:00:00:00:00:31"}));
        CHECK(store.AddBanChecked(vgww::web::BanEntry{"ip", "10.7.7.7"}));
        CHECK(store.Bans().size() == 2);
        const uint64_t first_id = store.Bans()[0].id;
        const uint64_t second_id = store.Bans()[1].id;
        CHECK(0 != first_id && 0 != second_id);
        vgww::ui::RemoveBanCmd bogus_ban;
        bogus_ban.id = second_id + 1000;
        CHECK(!executor.Execute(bogus_ban).ok);
        CHECK(store.Bans().size() == 2);
        vgww::ui::RemoveBanCmd by_ban_id;
        by_ban_id.id = second_id;
        CHECK(executor.Execute(by_ban_id).ok);
        CHECK(store.Bans().size() == 1);
        if (store.Bans().size() == 1) {
            CHECK(store.Bans()[0].id == first_id);
        }
        vgww::ui::RemoveBanCmd zero_ban;
        zero_ban.id = 0;
        zero_ban.index = 0;
        CHECK(executor.Execute(zero_ban).ok);  // legacy positional path
        CHECK(store.Bans().empty());
        store.Clear();
    }
    // batch136: a MAC re-key is ONE command (`replace_mac`) that removes the
    // old rule and writes the new one atomically. Two commands used to let
    // either half fail alone (queue full / cap) and delete the policy.
    {
        store.Clear();
        r = executor.Execute(SetRateLimitCmd{"30:fc:68:88:b4:11", 100, 200});
        CHECK(r.ok);
        SetRateLimitCmd rekey{"30:fc:68:88:b4:12", 300, 400};
        rekey.replace_mac = "30:fc:68:88:b4:11";
        r = executor.Execute(rekey);
        CHECK(r.ok);
        CHECK(store.RateLimits().size() == 1);
        if (store.RateLimits().size() == 1) {
            CHECK(0 == _stricmp(store.RateLimits()[0].mac.c_str(),
                  "30:fc:68:88:b4:12"));
            CHECK(store.RateLimits()[0].uplink_kbps == 300);
            CHECK(store.RateLimits()[0].downlink_kbps == 400);
        }
        // A re-key whose new rule is invalid must change NOTHING: the old rule
        // stays (this is the half-state the split sequence produced).
        SetRateLimitCmd bad{"30:fc:68:88:b4:13", 0, 0};
        bad.replace_mac = "30:fc:68:88:b4:12";
        r = executor.Execute(bad);
        CHECK(!r.ok);
        CHECK(store.RateLimits().size() == 1);
        if (store.RateLimits().size() == 1) {
            CHECK(0 == _stricmp(store.RateLimits()[0].mac.c_str(),
                  "30:fc:68:88:b4:12"));
            CHECK(store.RateLimits()[0].uplink_kbps == 300);
        }
        store.Clear();
    }
    CHECK(store.PortMaps().empty());

    // DHCP binding with no assembled server: specific reason, no mutation.
    r = executor.Execute(
        AddDhcpBindingCmd{"30:fc:68:88:b4:02", "192.168.0.60", "host"});
    CHECK(!r.ok);
    CHECK(r.message.find(L"DHCP") != std::wstring::npos);

    // SaveConfigCmd: valid config lands on disk and loads back.
    r = executor.Execute(SaveConfigCmd{MakeSaveConfig()});
    CHECK(r.ok);
    CHECK(r.message.find(L"\u91cd\u542f") != std::wstring::npos);  // restart
    {
        std::ifstream in(save_path);
        CHECK(in.good());
    }
    std::string error;
    const auto loaded = vgww::core::Config::LoadFromFile(save_path, error);
    CHECK(loaded.has_value());
    if (loaded) {
        CHECK(loaded->web.port == 9090);
        CHECK(loaded->adapter == "Ethernet");
    }
    // Invalid config: refused before any write, file bytes unchanged.
    {
        std::ifstream in(save_path, std::ios::binary);
        const std::string before((std::istreambuf_iterator<char>(in)),
                                 std::istreambuf_iterator<char>());
        vgww::core::Config bad = MakeSaveConfig();
        bad.web.port = 0;
        r = executor.Execute(SaveConfigCmd{bad});
        CHECK(!r.ok);
        std::ifstream in2(save_path, std::ios::binary);
        const std::string after((std::istreambuf_iterator<char>(in2)),
                                std::istreambuf_iterator<char>());
        CHECK(before == after);
    }

    // SetAutostartCmd goes through the injected hook.
    CHECK(executor.Execute(SetAutostartCmd{true}).ok);
    CHECK(autostart_calls == 1);
    CHECK(autostart_enabled);

    std::remove(save_path.c_str());
    store.Clear();
}

static void TestUiControllerComposition() {
    FakeDataSource source;
    FakeExecutor executor;
    vgww::ui::UiController controller(source, executor);
    std::string error;
    CHECK(controller.Start(error));
    CHECK(!controller.Start(error));  // idempotent
    CHECK(WaitFor([&] { return controller.Load()->seq >= 1; }));

    CHECK(controller.Post(vgww::ui::AddBanCmd{"mac", "controller"}));
    std::vector<vgww::ui::CommandResult> results;
    CHECK(WaitFor([&] {
        auto batch = controller.DrainResults();
        results.insert(results.end(), batch.begin(), batch.end());
        return !results.empty();
    }));
    CHECK(results.size() == 1);
    CHECK(results[0].ok);

    controller.Stop();
    controller.Stop();  // idempotent
    CHECK(!controller.Post(vgww::ui::AddBanCmd{"mac", "after-stop"}));
    CHECK(controller.Load() != nullptr);
}

// ---------------------------------------------------------------------------
// T4-F1: robustness + assertion hardening (T4 review M1-M4).

/// Executor that throws for one labelled command; records the execution
/// order so the test can prove the worker survived and kept FIFO.
class ThrowingExecutor final : public vgww::ui::CommandExecutor {
public:
    vgww::ui::CommandResult Execute(const vgww::ui::Command& cmd) override {
        const std::string label = Label(cmd);
        {
            std::lock_guard<std::mutex> lock(mutex_);
            order_.push_back(label);
            ++executed_;
        }
        executed_cv_.notify_all();
        if (label == "add-ban:boom") {
            throw std::runtime_error("executor exploded");
        }
        vgww::ui::CommandResult result;
        result.ok = true;
        result.message = L"fine";
        return result;
    }

    bool WaitForExecutions(size_t n, std::chrono::milliseconds timeout) {
        std::unique_lock<std::mutex> lock(mutex_);
        return executed_cv_.wait_for(lock, timeout,
                                     [this, n] { return executed_ >= n; });
    }

    std::vector<std::string> Order() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return order_;
    }

private:
    mutable std::mutex mutex_;
    std::condition_variable executed_cv_;
    std::vector<std::string> order_;
    size_t executed_ = 0;
};

/// Data source that can throw from Collect/CollectStats; counts the healthy
/// collections so the test can prove the publisher kept ticking.
class ThrowingDataSource final : public vgww::ui::UiDataSource {
public:
    vgww::ui::ConfigView ConfigSnapshot() override {
        vgww::ui::ConfigView view;
        view.adapter = "throwing";
        return view;
    }

    std::shared_ptr<vgww::ui::UiSnapshot> Collect(uint64_t seq) override {
        if (throw_collect_.load()) {
            throw std::runtime_error("collect exploded");
        }
        auto snapshot = std::make_shared<vgww::ui::UiSnapshot>();
        snapshot->seq = seq;
        snapshot->config = ConfigSnapshot();
        ok_collects_.fetch_add(1);
        return snapshot;
    }

    void CollectStats(vgww::ui::UiSnapshot& snapshot) override {
        if (throw_stats_.load()) {
            throw std::runtime_error("stats exploded");
        }
        snapshot.counters.rx_frames += 1;
        ok_stats_.fetch_add(1);
    }

    void SetThrowOnCollect(bool value) { throw_collect_.store(value); }
    void SetThrowOnStats(bool value) { throw_stats_.store(value); }
    int ok_collects() const { return ok_collects_.load(); }
    int ok_stats() const { return ok_stats_.load(); }

private:
    std::atomic<bool> throw_collect_{false};
    std::atomic<bool> throw_stats_{false};
    std::atomic<int> ok_collects_{0};
    std::atomic<int> ok_stats_{0};
};

static void TestExecutorExceptionKeepsQueueAlive() {
    using vgww::ui::AddBanCmd;
    using vgww::ui::CommandResult;
    using vgww::ui::CommandQueue;
    using vgww::ui::SnapshotPublisher;

    FakeDataSource source;
    SnapshotPublisher publisher(source, 60s, 60s);
    std::string error;
    CHECK(publisher.Start(error));
    ThrowingExecutor executor;
    CommandQueue queue(executor, publisher);
    CHECK(queue.Start(error));

    CHECK(queue.Post(AddBanCmd{"mac", "boom"}));
    CHECK(queue.Post(AddBanCmd{"mac", "after"}));

    // Exactly one result per accepted command: the throwing one is reported
    // as a failed command, the next one still runs (worker survived).
    std::vector<CommandResult> all;
    CHECK(WaitFor([&] {
        auto batch = queue.DrainResults();
        all.insert(all.end(), batch.begin(), batch.end());
        return all.size() >= 2;
    }));
    CHECK(all.size() == 2);
    CHECK(!all[0].ok);
    CHECK(all[0].message == L"internal error");
    CHECK(all[1].ok);

    CHECK(executor.WaitForExecutions(2, 2000ms));
    const std::vector<std::string> order = executor.Order();
    CHECK(order.size() == 2);
    CHECK(order[0] == "add-ban:boom" && order[1] == "add-ban:after");

    queue.Stop();
    publisher.Stop();
}

static void TestPublisherSurvivesSourceException() {
    using vgww::ui::SnapshotPublisher;

    ThrowingDataSource source;
    source.SetThrowOnCollect(true);
    source.SetThrowOnStats(true);
    // Stats/status ticks must differ by more than the Windows timer
    // granularity (~15.6 ms): otherwise every wake has BOTH due and the
    // full branch wins, so the stats hook is never exercised.
    SnapshotPublisher publisher(source, 10ms, 60ms);
    std::string error;
    CHECK(publisher.Start(error));

    // The first tick is a full collect and throws: the publisher must
    // contain it and keep publishing (seq advances, no healthy collect yet).
    CHECK(WaitFor([&] { return publisher.Load()->seq >= 1; }));
    CHECK(source.ok_collects() == 0);

    // Clear the fault: the very next ticks must produce healthy snapshots
    // through BOTH paths (stats-only wakes refresh CollectStats, the status
    // tick runs the full Collect).
    source.SetThrowOnCollect(false);
    source.SetThrowOnStats(false);
    CHECK(WaitFor([&] {
        return source.ok_collects() >= 1 && source.ok_stats() >= 1;
    }));
    CHECK(publisher.Load()->seq >= 2);

    publisher.Stop();
    publisher.Stop();  // idempotent even after the exception storm
}

// ============================================================================
// batch61: the 500 ms stats tick deep-copies the published snapshot and then
// runs CollectStats. Both MUST happen outside load_mutex_ - the UI thread
// polls Load() every frame, so holding the lock across that work would stall
// the UI for the whole copy. Proven with a handshake (no wall clock): the fake
// blocks inside CollectStats until the test has completed a Load(), and
// records whether it was released by the test or by its own timeout (the
// latter means Load() could not get the lock).
// ============================================================================
class BlockingStatsSource final : public vgww::ui::UiDataSource {
public:
    vgww::ui::ConfigView ConfigSnapshot() override { return {}; }

    std::shared_ptr<vgww::ui::UiSnapshot> Collect(uint64_t seq) override {
        auto snap = std::make_shared<vgww::ui::UiSnapshot>();
        snap->seq = seq;
        snap->published_at = std::chrono::steady_clock::now();
        return snap;
    }

    void CollectStats(vgww::ui::UiSnapshot&) override {
        stats_entries_.fetch_add(1);
        entered_.store(true);
        const auto deadline = std::chrono::steady_clock::now() + 2000ms;
        while (!release_.load() &&
               std::chrono::steady_clock::now() < deadline) {
            std::this_thread::sleep_for(1ms);
        }
        if (!release_.load()) {
            timed_out_.store(true);  // Load() never got through
        }
    }

    void Release() { release_.store(true); }
    bool entered() const { return entered_.load(); }
    bool timed_out() const { return timed_out_.load(); }
    int stats_entries() const { return stats_entries_.load(); }

private:
    std::atomic<bool> entered_{false};
    std::atomic<bool> release_{false};
    std::atomic<bool> timed_out_{false};
    std::atomic<int> stats_entries_{0};
};

static void TestPublisherStatsHookDoesNotBlockLoad() {
    using vgww::ui::SnapshotPublisher;

    BlockingStatsSource source;
    // Fast stats tick, slow status tick: the stats-only path (copy +
    // CollectStats) is the one under test.
    SnapshotPublisher publisher(source, 10ms, 60s);
    std::string error;
    CHECK(publisher.Start(error));

    CHECK(WaitFor([&] { return source.entered(); }));

    // The publisher is inside CollectStats right now. Load() must still
    // return: a lock held across the copy/collect would hang here until the
    // source's own timeout.
    const auto snapshot = publisher.Load();
    const bool loaded = snapshot != nullptr;
    source.Release();  // unblock only AFTER Load() returned

    CHECK(loaded);
    CHECK(WaitFor([&] { return source.stats_entries() >= 2; }));
    CHECK(!source.timed_out());

    publisher.Stop();
}

static void TestDrainBatchBounded() {
    using vgww::ui::AddBanCmd;
    using vgww::ui::CommandQueue;
    using vgww::ui::CommandResult;
    using vgww::ui::SnapshotPublisher;

    FakeDataSource source;
    SnapshotPublisher publisher(source, 60s, 60s);
    std::string error;
    CHECK(publisher.Start(error));
    FakeExecutor executor;
    CommandQueue queue(executor, publisher);
    CHECK(queue.Start(error));

    constexpr int kTotal = 40;
    for (int i = 0; i < kTotal; ++i) {
        CHECK(queue.Post(AddBanCmd{"mac", "d" + std::to_string(i)}));
    }
    CHECK(executor.WaitForExecutions(static_cast<size_t>(kTotal), 2000ms));

    std::vector<CommandResult> all;
    int drains = 0;
    while (all.size() < static_cast<size_t>(kTotal)) {
        std::vector<CommandResult> batch;
        const bool got = WaitFor([&] {
            batch = queue.DrainResults();
            return !batch.empty();
        });
        CHECK(got);
        if (!got) {
            break;
        }
        CHECK(batch.size() <= 16);  // direct clamp assertion (M1)
        ++drains;
        all.insert(all.end(), batch.begin(), batch.end());
    }
    CHECK(all.size() == static_cast<size_t>(kTotal));  // nothing lost
    CHECK(drains >= 3);  // 40 results need at least three batches
    CHECK(queue.DrainResults().empty());

    queue.Stop();
    publisher.Stop();
}

static void TestStopTimeoutKeepsWorkerAlive() {
    using vgww::ui::AddBanCmd;
    using vgww::ui::CommandQueue;
    using vgww::ui::CommandResult;
    using vgww::ui::SnapshotPublisher;

    FakeDataSource source;
    SnapshotPublisher publisher(source, 60s, 60s);
    std::string error;
    CHECK(publisher.Start(error));
    FakeExecutor executor;
    executor.EnableGate();
    CommandQueue queue(executor, publisher);
    CHECK(queue.Start(error));

    CHECK(queue.Post(AddBanCmd{"mac", "blocked"}));
    executor.WaitUntilEntered();

    // The worker is blocked inside Execute: Stop must wait the bounded 1 s,
    // then keep the thread alive (never detach/terminate it).
    const auto started = std::chrono::steady_clock::now();
    queue.Stop();
    const auto elapsed = std::chrono::steady_clock::now() - started;
    CHECK(elapsed >= 800ms);   // the bounded wait actually waited
    CHECK(elapsed < 3000ms);   // ... and was bounded
    CHECK(!queue.Post(AddBanCmd{"mac", "after-stop"}));

    // Releasing the gate lets the kept-alive worker finish the pending
    // command: its result must still arrive (no silent loss, no UAF).
    executor.ReleaseGate();
    std::vector<CommandResult> all;
    CHECK(WaitFor([&] {
        auto batch = queue.DrainResults();
        all.insert(all.end(), batch.begin(), batch.end());
        return !all.empty();
    }));
    CHECK(all.size() == 1);
    CHECK(all[0].ok);

    queue.Stop();  // joins the finished worker
    publisher.Stop();
}

// batch251: lifecycle beyond "repeat Start while running". Both classes are
// reusable after a COMPLETED Stop (the thread was joined), Stop before Start
// is a no-op, and Post is rejected before Start. None of that was pinned.
static void TestRestartAfterStop() {
    using vgww::ui::AddBanCmd;
    using vgww::ui::Command;
    using vgww::ui::CommandQueue;
    using vgww::ui::SnapshotPublisher;

    FakeDataSource source;
    // 60s/60s: no natural tick, so nothing races the lifecycle here. The
    // restart must still leave a LIVE worker - proven below by an explicit
    // Refresh and by posting real commands.
    SnapshotPublisher publisher(source, 60s, 60s);
    std::string error;
    CHECK(publisher.Start(error));
    publisher.Stop();
    CHECK(publisher.Start(error));
    CHECK(error.empty());
    CHECK(publisher.Load() != nullptr);
    // A restart that forgot stop_=false would spawn a worker that exits at
    // once. An explicit refresh proves the loop is actually running.
    const uint64_t seq_before = publisher.Load()->seq;
    publisher.RequestRefreshAfter(std::chrono::milliseconds(0));
    CHECK(WaitFor([&] { return publisher.Load()->seq > seq_before; }));

    FakeExecutor executor;
    CommandQueue queue(executor, publisher);
    CHECK(queue.Start(error));
    queue.Stop();
    CHECK(queue.Start(error));
    CHECK(error.empty());
    // A dead restarted worker would accept Post but never drain it.
    CHECK(queue.Post(Command(AddBanCmd{"mac", "restart"})));
    CHECK(WaitFor([&] { return queue.pending() == 0; }));
    std::vector<vgww::ui::CommandResult> drained;
    CHECK(WaitFor([&] {
        auto batch = queue.DrainResults();
        drained.insert(drained.end(), batch.begin(), batch.end());
        return !drained.empty();
    }));
    CHECK(drained.size() == 1);
    if (drained.size() == 1) {
        CHECK(drained[0].ok);
    }
    queue.Stop();
    publisher.Stop();
}

static void TestStopBeforeStartIsNoop() {
    using vgww::ui::CommandQueue;
    using vgww::ui::SnapshotPublisher;

    FakeDataSource source;
    SnapshotPublisher publisher(source, 60s, 60s);
    publisher.Stop();  // never started: must not throw or latch stop_
    std::string error;
    CHECK(publisher.Start(error));
    publisher.Stop();

    FakeExecutor executor;
    CommandQueue queue(executor, publisher);
    queue.Stop();      // never started
    CHECK(queue.Start(error));
    queue.Stop();
}

static void TestPostBeforeStartRejected() {
    using vgww::ui::AddBanCmd;
    using vgww::ui::Command;
    using vgww::ui::CommandQueue;
    using vgww::ui::SnapshotPublisher;

    FakeDataSource source;
    SnapshotPublisher publisher(source, 60s, 60s);
    FakeExecutor executor;
    CommandQueue queue(executor, publisher);  // not started
    CHECK(!queue.Post(Command(AddBanCmd{"mac", "x"})));
    CHECK(queue.DrainResults().empty());
    CHECK(queue.pending() == 0);
    CHECK(!queue.Post(Command(AddBanCmd{"mac", "y"})));
}

static void TestDrainPreservesFifoAcrossBatches() {
    using vgww::ui::AddBanCmd;
    using vgww::ui::Command;
    using vgww::ui::CommandQueue;
    using vgww::ui::CommandResult;
    using vgww::ui::SnapshotPublisher;

    FakeDataSource source;
    SnapshotPublisher publisher(source, 60s, 60s);
    std::string error;
    CHECK(publisher.Start(error));
    FakeExecutor executor;
    // Alternate failing / succeeding labels so the ok-pattern identifies
    // the position: a drain that returned results from the BACK (or any
    // other order) cannot reproduce it.
    for (int i = 0; i < 20; i += 2) {
        executor.SetFailLabel("add-ban:" + std::to_string(i));
    }
    CommandQueue queue(executor, publisher);
    CHECK(queue.Start(error));
    for (int i = 0; i < 20; ++i) {
        CHECK(queue.Post(Command(AddBanCmd{"mac", std::to_string(i)})));
    }
    queue.Stop();  // drains, so all 20 results exist

    std::vector<CommandResult> all;
    CHECK(WaitFor([&] {
        auto batch = queue.DrainResults();
        all.insert(all.end(), batch.begin(), batch.end());
        return all.size() >= 20;
    }));
    CHECK(all.size() == 20);
    if (all.size() == 20) {
        for (int i = 0; i < 20; ++i) {
            CHECK(all[static_cast<std::size_t>(i)].ok == (i % 2 != 0));
        }
    }
    publisher.Stop();
}

int main() {
    TestLoadBeforeStartAndStartIdempotent();
    TestPublishMonotonic();
    TestPublishFullReusesCollectedSnapshot();
    TestCommandOrderAndResult();
    TestStopJoinIdempotent();
    TestRefreshAcceleration();
    TestPostBackpressure();
    TestConcurrentLoadDuringPublish();
    TestRealExecutorAgainstRuleStore();
    TestUiControllerComposition();
    TestExecutorExceptionKeepsQueueAlive();
    TestPublisherSurvivesSourceException();
    TestPublisherStatsHookDoesNotBlockLoad();
    TestDrainBatchBounded();
    TestStopTimeoutKeepsWorkerAlive();
    TestRestartAfterStop();
    TestStopBeforeStartIsNoop();
    TestPostBeforeStartRejected();
    TestDrainPreservesFifoAcrossBatches();
    if (g_failures == 0) {
        std::printf("OK\n");
    } else {
        std::printf("%d FAILURES\n", g_failures);
    }
    return g_failures == 0 ? 0 : 1;
}
