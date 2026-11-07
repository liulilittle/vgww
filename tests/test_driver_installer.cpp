// ============================================================================
// test_driver_installer.cpp - headless tests for the ndisrd driver installer
// (batch 16). Hosts the installer tests migrated out of test_web.cpp (S5.7 /
// S5.9 / R1 blocks) plus the batch-16 anchors:
//   RA-1 FaultClassify, RA-2 ParsePlural, RA-3 DiffNewOems, RA-5
//   InstallReportIO, RA-6 component fake matrix, RA-7 rollback
//   asserted, RA-8 rollback failure variants, RA-9 oem-missing cleanup,
//   (RA-4 the boot-task command test was REMOVED in batch23: the installer
//   no longer creates a boot task; it removes any legacy one instead),
//   RA-10 uninstall failure variants; RB-1 payload triple location, RB-2
//   install success full headless, RB-3 uninstall clean recorder, RB-4
//   grant-only entry. Everything here must run without touching the real
//   driver store / SCM / schtasks / System32 (the hooks and fake sessions
//   record calls instead).
// ============================================================================
#include "driver/error_class.h"
#include "driver/installer.h"

#include <windows.h>

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <vector>

namespace {

    int g_failures = 0;

#define CHECK(cond)                                                        \
    do {                                                                   \
        if (!(cond)) {                                                     \
            std::fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__,  \
                         __LINE__, #cond);                                 \
            ++g_failures;                                                  \
        }                                                                  \
    } while (0)

#define RUN(fn)                                                            \
    do {                                                                   \
        std::printf("[ RUN  ] %s\n", #fn);                                 \
        fn();                                                              \
        std::printf("[ DONE ] %s\n", #fn);                                 \
    } while (0)

    /// Unique scratch directory for payload fixtures; removed on exit.
    class TempDir {
    public:
        TempDir() {
            std::error_code ec;
            m_path = std::filesystem::temp_directory_path(ec) /
                     ("vgww_b16_" +
                      std::to_string(static_cast<unsigned long long>(
                          ::GetCurrentProcessId())) +
                      "_" +
                      std::to_string(reinterpret_cast<uintptr_t>(this)));
            std::filesystem::create_directories(m_path, ec);
        }
        ~TempDir() {
            std::error_code ec;
            std::filesystem::remove_all(m_path, ec);
        }
        TempDir(const TempDir&) = delete;
        TempDir& operator=(const TempDir&) = delete;
        const std::filesystem::path& path() const { return m_path; }

    private:
        std::filesystem::path m_path;
    };

    void WriteSizedFile(const std::filesystem::path& p, size_t bytes) {
        std::ofstream f(p, std::ios::binary);
        for (size_t i = 0; i < bytes; ++i) {
            f.put('x');
        }
    }

    std::filesystem::path ExeDir() {
        wchar_t buf[MAX_PATH] = {0};
        const DWORD got = ::GetModuleFileNameW(nullptr, buf, MAX_PATH);
        if (0 == got || got >= MAX_PATH) {
            return {};
        }
        return std::filesystem::path(std::wstring(buf, got)).parent_path();
    }

    /// True when the complete payload triple ships next to the test binary
    /// (Release deployments do; bare diagnostic builds may not).
    bool PayloadTripleNextToExe() {
        const std::filesystem::path dir = ExeDir();
        if (dir.empty()) {
            return false;
        }
        std::error_code ec;
        return std::filesystem::exists(dir / L"ndisrd_lwf.inf", ec) &&
               std::filesystem::exists(dir / L"ndisrd.sys", ec) &&
               std::filesystem::exists(dir / L"ndisrd.cat", ec);
    }

    /// Scriptable pnputil runner: records every call in order and returns a
    /// per-call result (transcript + exit code + spawn flag). Once the
    /// scripted calls are exhausted the fallback entry answers every
    /// remaining call.
    struct RunnerScript {
        struct Call {
            std::string out;
            DWORD code = 0;
            bool spawn_ok = true;
        };
        std::vector<Call> script;
        Call fallback;
        std::vector<std::vector<std::wstring>> all_args;
        size_t calls = 0;

        vgww::driver::PnputilRunner runner() {
            return [this](const std::vector<std::wstring>& args,
                          std::string& out, DWORD& exit_code) {
                all_args.push_back(args);
                const Call& c =
                    calls < script.size() ? script[calls] : fallback;
                ++calls;
                out = c.out;
                exit_code = c.code;
                return c.spawn_ok;
            };
        }

        std::vector<std::wstring> last_args() const {
            return all_args.empty() ? std::vector<std::wstring>{}
                                    : all_args.back();
        }
    };

    /// Fake INetCfg session (migrated from test_web.cpp): records the call
    /// order and lets each step fail on demand. `shared_log`/`shared_close`
    /// let the factory hand out fresh copies that report into one log.
    struct FakeSession : vgww::driver::InetCfgSession {
        std::vector<std::string> calls;
        bool install_fail = false;
        bool lock_fail = false;
        bool enum_fail = false;
        bool bind_fail = false;
        bool unbind_fail = false;
        bool deinstall_fail = false;
        bool apply_fail = false;
        bool close_called = false;
        // Batch16 RA-6 extensions: the remaining uncovered branches.
        bool open_fail = false;
        bool find_fail = false;
        bool no_adapters = false;
        std::shared_ptr<std::vector<std::string>> shared_log;
        std::shared_ptr<bool> shared_close;

        void Log(const std::string& e) {
            calls.push_back(e);
            if (shared_log) {
                shared_log->push_back(e);
            }
        }

        std::string Open() override {
            Log("Open");
            return open_fail ? "Open failed" : "";
        }
        std::string AcquireWriteLock() override {
            Log("AcquireWriteLock");
            return lock_fail ? "write lock busy (by OtherApp)" : "";
        }
        std::string Find(const std::wstring&, bool& found) override {
            Log("Find");
            found = false;
            return find_fail ? "Find failed" : "";
        }
        std::string Install(const std::wstring&, bool& installed) override {
            Log("Install");
            installed = !install_fail;
            return install_fail ? "Install() failed (NETCFG_E_...)" : "";
        }
        std::string EnumerateAdapters(
            std::vector<std::wstring>& device_ids) override {
            Log("EnumerateAdapters");
            if (enum_fail) {
                return "EnumerateAdapters failed";
            }
            if (no_adapters) {
                device_ids.clear();
                return "";
            }
            device_ids = {L"\\DEVICE\\{AAAA}", L"\\DEVICE\\{BBBB}"};
            return "";
        }
        std::string BindToAdapter(const std::wstring&, const std::wstring&,
                                  bool& bound) override {
            Log("BindToAdapter");
            bound = !bind_fail;
            return bind_fail ? "BindTo failed" : "";
        }
        std::string UnbindFromAdapter(const std::wstring&,
                                      const std::wstring&,
                                      bool& unbound) override {
            Log("UnbindFromAdapter");
            unbound = !unbind_fail;
            return unbind_fail ? "UnbindFrom failed" : "";
        }
        std::string DeInstall(const std::wstring&, bool& removed) override {
            Log("DeInstall");
            removed = !deinstall_fail;
            return deinstall_fail ? "DeInstall failed" : "";
        }
        std::string Apply() override {
            Log("Apply");
            return apply_fail ? "Apply failed" : "";
        }
        void Close() override {
            Log("Close");
            close_called = true;
            if (shared_close) {
                *shared_close = true;
            }
        }
    };

    /// Factory harness handing out FakeSession copies that share a call log
    /// (migrated from test_web.cpp R1 wiring tests).
    struct WiringHarness {
        FakeSession session;
        bool factory_fail = false;
        bool session_fail = false;
        std::shared_ptr<std::vector<std::string>> shared_log =
            std::make_shared<std::vector<std::string>>();
        std::shared_ptr<bool> shared_close = std::make_shared<bool>(false);
        vgww::driver::InetCfgSessionFactory factory() {
            return [this]() -> std::unique_ptr<vgww::driver::InetCfgSession> {
                if (factory_fail) {
                    return nullptr;
                }
                auto s = std::unique_ptr<FakeSession>(new FakeSession(session));
                s->shared_log = shared_log;
                s->shared_close = shared_close;
                if (session_fail) {
                    s->lock_fail = true;
                }
                return s;
            };
        }
    };

    const char* kOemTranscript =
        "Published Name :         oem25.inf\n"
        "Original Name   :        ndisrd_lwf.inf\n"
        "Provider Name   :        Ntkr\n"
        "Class Name      :        Net\n"
        "Class GUID      :        {4d36e974-e325-11ce-bfc1-08002be10318}\n";

    /// All four uninstall channels recorded (and never touching the real
    /// machine); failures can be scripted per channel.
    struct CleanupRecorder {
        int scm = 0;
        int task = 0;
        int mirror = 0;
        int sys32 = 0;
        vgww::driver::UninstallHooks hooks() {
            vgww::driver::UninstallHooks h;
            h.cleanup_legacy_service = [this] { ++scm; };
            h.remove_boot_task = [this](std::wstring&) {
                ++task;
                return true;
            };
            h.remove_mirror_copy = [this](std::wstring&) {
                ++mirror;
                return true;
            };
            h.remove_system32_copy = [this](std::wstring&) {
                ++sys32;
                return true;
            };
            return h;
        }
    };

    /// Isolation convenience for tests that do not inspect the per-channel
    /// counters: all four channels no-op via a process-lifetime recorder.
    vgww::driver::UninstallHooks SafeUninstallHooks() {
        static CleanupRecorder rec;
        return rec.hooks();
    }

    /// Isolation convenience for the install path (V-1, audit B): the
    /// install runs CleanupLegacyServiceRegistration BEFORE add-driver, so
    /// any test that lets the install proceed past the payload gate would
    /// otherwise touch the real SCM (DeleteService on a host with a stale
    /// non-running ndisrd registration). All three channels are stubbed
    /// defensively; the assertions of the calling tests are unaffected
    /// (they drive failure/rollback paths).
    vgww::driver::InstallHooks SafeInstallHooks() {
        vgww::driver::InstallHooks h;
        h.ensure_device_access = [] { return true; };
        h.remove_boot_task = [](std::wstring&) { return true; };
        h.cleanup_legacy_service = [] {};
        return h;
    }

    /// Two published ndisrd entries (version upgrade scenario): oem25 is the
    /// pre-existing baseline entry, oem99 appeared during this install.
    const char* kOemTwoTranscript =
        "Published Name :         oem25.inf\n"
        "Original Name   :        ndisrd_lwf.inf\n"
        "Provider Name   :        Ntkr\n"
        "Class Name      :        Net\n"
        "Class GUID      :        {4d36e974-e325-11ce-bfc1-08002be10318}\n"
        "\n"
        "Published Name :         oem99.inf\n"
        "Original Name   :        ndisrd_lwf.inf\n"
        "Provider Name   :        Ntkr\n"
        "Class Name      :        Net\n"
        "Class GUID      :        {4d36e974-e325-11ce-bfc1-08002be10318}\n";



    // ------------------------------------------------------------------
    // RA-1: driver fault classification (batch16 F1). The classifier is
    // the single home of the driver-error literals produced by
    // ndisrd_client.cpp and dataplane.cpp; main.cpp and ui/app.cpp must
    // consume it instead of matching substrings themselves.
    // ------------------------------------------------------------------
    void TestFaultClassify() {
        using vgww::driver::ClassifyDriverFault;
        using vgww::driver::DriverFault;

        // Boundary: an empty text has no fault to classify.
        CHECK(ClassifyDriverFault("") == DriverFault::None);

        // Driver missing: both literals the device-open path can emit.
        CHECK(ClassifyDriverFault("ndisrd driver not installed (WinpkFilter missing?)") ==
              DriverFault::DriverMissing);
        CHECK(ClassifyDriverFault("some prefix: WinpkFilter missing") ==
              DriverFault::DriverMissing);

        // Access denied: the device-open literal (tightened anchor; a bare
        // "access denied" from an unrelated path must NOT trigger the
        // elevation recovery).
        CHECK(ClassifyDriverFault(
                  "access denied opening \\\\.\\Ndisrd - run as Administrator") ==
              DriverFault::AccessDenied);
        CHECK(ClassifyDriverFault("access denied") == DriverFault::Other);

        // Adapter missing: the dataplane no-match literal.
        CHECK(ClassifyDriverFault(
                  "no adapter matches: \"Ethernet\". Available adapters: ...") ==
              DriverFault::AdapterMissing);

        // Anything else stays opaque (never guessed).
        CHECK(ClassifyDriverFault("open \\\\.\\Ndisrd failed: 1234") ==
              DriverFault::Other);
        CHECK(ClassifyDriverFault("dataplane start refused") ==
              DriverFault::Other);
    }

    // ------------------------------------------------------------------
    // RB-1: payload triple location (batch16 F3). pnputil requires the
    // .sys/.cat files next to the INF (INF SourceDisksFiles), so a full
    // triple in ONE directory is accepted; cross-directory pairings and
    // truncated files must be rejected with a diagnostic naming the
    // missing file and the tried directories.
    // ------------------------------------------------------------------
    void TestLocatePayload() {
        using vgww::driver::DriverPayload;
        using vgww::driver::LocateDriverPayload;

        // (a) nothing anywhere: all three names + all candidate dirs.
        {
            TempDir t;
            DriverPayload p;
            std::wstring err;
            CHECK(!LocateDriverPayload(t.path(), p, err));
            CHECK(err.find(L"ndisrd_lwf.inf") != std::wstring::npos);
            CHECK(err.find(L"ndisrd.sys") != std::wstring::npos);
            CHECK(err.find(L"ndisrd.cat") != std::wstring::npos);
            CHECK(err.find(t.path().wstring()) != std::wstring::npos);
            CHECK(err.find((t.path() / L"drivers").wstring()) !=
                  std::wstring::npos);
            CHECK(err.find((t.path() / L"win10").wstring()) !=
                  std::wstring::npos);
        }

        // (b) inf+sys present, cat absent: only the cat is reported.
        {
            TempDir t;
            WriteSizedFile(t.path() / L"ndisrd_lwf.inf", 2048);
            WriteSizedFile(t.path() / L"ndisrd.sys", 8192);
            DriverPayload p;
            std::wstring err;
            CHECK(!LocateDriverPayload(t.path(), p, err));
            CHECK(err.find(L"ndisrd.cat") != std::wstring::npos);
        }

        // (c) sys+cat present, inf absent.
        {
            TempDir t;
            WriteSizedFile(t.path() / L"ndisrd.sys", 8192);
            WriteSizedFile(t.path() / L"ndisrd.cat", 128);
            DriverPayload p;
            std::wstring err;
            CHECK(!LocateDriverPayload(t.path(), p, err));
            CHECK(err.find(L"ndisrd_lwf.inf") != std::wstring::npos);
        }

        // (d) complete, valid triple: accepted, all three from one dir.
        {
            TempDir t;
            WriteSizedFile(t.path() / L"ndisrd_lwf.inf", 1024);
            WriteSizedFile(t.path() / L"ndisrd.sys", 4096);
            WriteSizedFile(t.path() / L"ndisrd.cat", 1);
            DriverPayload p;
            std::wstring err;
            CHECK(LocateDriverPayload(t.path(), p, err));
            CHECK(err.empty());
            CHECK(p.inf.parent_path() == t.path());
            CHECK(p.sys.parent_path() == t.path());
            CHECK(p.cat.parent_path() == t.path());
        }

        // (e) truncated inf (< 1 KiB) is rejected by name.
        {
            TempDir t;
            WriteSizedFile(t.path() / L"ndisrd_lwf.inf", 1023);
            WriteSizedFile(t.path() / L"ndisrd.sys", 8192);
            WriteSizedFile(t.path() / L"ndisrd.cat", 128);
            DriverPayload p;
            std::wstring err;
            CHECK(!LocateDriverPayload(t.path(), p, err));
            CHECK(err.find(L"ndisrd_lwf.inf") != std::wstring::npos);
        }

        // (f) truncated sys (< 4 KiB) is rejected by name.
        {
            TempDir t;
            WriteSizedFile(t.path() / L"ndisrd_lwf.inf", 2048);
            WriteSizedFile(t.path() / L"ndisrd.sys", 4095);
            WriteSizedFile(t.path() / L"ndisrd.cat", 128);
            DriverPayload p;
            std::wstring err;
            CHECK(!LocateDriverPayload(t.path(), p, err));
            CHECK(err.find(L"ndisrd.sys") != std::wstring::npos);
        }

        // (g) zero-byte cat is rejected (cat must exist AND be non-empty).
        {
            TempDir t;
            WriteSizedFile(t.path() / L"ndisrd_lwf.inf", 2048);
            WriteSizedFile(t.path() / L"ndisrd.sys", 8192);
            WriteSizedFile(t.path() / L"ndisrd.cat", 0);
            DriverPayload p;
            std::wstring err;
            CHECK(!LocateDriverPayload(t.path(), p, err));
            CHECK(err.find(L"ndisrd.cat") != std::wstring::npos);
        }

        // (h) drivers/ subdirectory triple is accepted.
        {
            TempDir t;
            std::error_code ec;
            std::filesystem::create_directories(t.path() / L"drivers", ec);
            WriteSizedFile(t.path() / L"drivers" / L"ndisrd_lwf.inf", 2048);
            WriteSizedFile(t.path() / L"drivers" / L"ndisrd.sys", 8192);
            WriteSizedFile(t.path() / L"drivers" / L"ndisrd.cat", 128);
            DriverPayload p;
            std::wstring err;
            CHECK(LocateDriverPayload(t.path(), p, err));
            CHECK(p.inf.parent_path() == t.path() / L"drivers");
        }

        // (i) win10/ subdirectory triple is accepted (the official unpacked
        // layout used to be a false negative with the split finders).
        {
            TempDir t;
            std::error_code ec;
            std::filesystem::create_directories(t.path() / L"win10", ec);
            WriteSizedFile(t.path() / L"win10" / L"ndisrd_lwf.inf", 2048);
            WriteSizedFile(t.path() / L"win10" / L"ndisrd.sys", 8192);
            WriteSizedFile(t.path() / L"win10" / L"ndisrd.cat", 128);
            DriverPayload p;
            std::wstring err;
            CHECK(LocateDriverPayload(t.path(), p, err));
            CHECK(p.inf.parent_path() == t.path() / L"win10");
        }

        // (j) cross-directory pairing (inf+sys in root, cat under drivers/)
        // is NOT a triple: rejected, naming the first incomplete directory.
        {
            TempDir t;
            std::error_code ec;
            std::filesystem::create_directories(t.path() / L"drivers", ec);
            WriteSizedFile(t.path() / L"ndisrd_lwf.inf", 2048);
            WriteSizedFile(t.path() / L"ndisrd.sys", 8192);
            WriteSizedFile(t.path() / L"drivers" / L"ndisrd.cat", 128);
            DriverPayload p;
            std::wstring err;
            CHECK(!LocateDriverPayload(t.path(), p, err));
            CHECK(err.find(t.path().wstring()) != std::wstring::npos);
            CHECK(err.find(L"ndisrd.cat") != std::wstring::npos);
        }

        // (k) candidate order: a complete root triple wins over a complete
        // win10 triple.
        {
            TempDir t;
            std::error_code ec;
            std::filesystem::create_directories(t.path() / L"win10", ec);
            WriteSizedFile(t.path() / L"ndisrd_lwf.inf", 2048);
            WriteSizedFile(t.path() / L"ndisrd.sys", 8192);
            WriteSizedFile(t.path() / L"ndisrd.cat", 128);
            WriteSizedFile(t.path() / L"win10" / L"ndisrd_lwf.inf", 2048);
            WriteSizedFile(t.path() / L"win10" / L"ndisrd.sys", 8192);
            WriteSizedFile(t.path() / L"win10" / L"ndisrd.cat", 128);
            DriverPayload p;
            std::wstring err;
            CHECK(LocateDriverPayload(t.path(), p, err));
            CHECK(p.inf.parent_path() == t.path());
        }

        // (l) default base_dir ({}): resolves the shipped layout next to the
        // test binary. A Release deployment ships the triple; a bare build
        // (no payload) must fail with the diagnostic.
        {
            const std::filesystem::path exe_dir = ExeDir();
            bool triple_next_to_exe = false;
            if (!exe_dir.empty()) {
                std::error_code ec;
                triple_next_to_exe =
                    std::filesystem::exists(exe_dir / L"ndisrd_lwf.inf", ec) &&
                    std::filesystem::exists(exe_dir / L"ndisrd.sys", ec) &&
                    std::filesystem::exists(exe_dir / L"ndisrd.cat", ec);
            }
            DriverPayload p;
            std::wstring err;
            const bool ok = LocateDriverPayload({}, p, err);
            CHECK(ok == triple_next_to_exe);
            if (ok) {
                CHECK(p.inf.parent_path() == exe_dir);
            }
        }
    }

    // ------------------------------------------------------------------
    // Migrated from test_web.cpp (S5.7): pnputil transcript parsing and the
    // argv builders.
    // ------------------------------------------------------------------
    void TestParsePnputilOem() {
        // finds the ndisrd oem inf, none otherwise.
        const std::string transcript =
            "Published Name : oem25.inf\n"
            "Original Name   : ndisrd_lwf.inf\n"
            "Provider Name   : Ntkr\n"
            "Class Name      : Net\n"
            "Class GUID      : {4d36e974-e325-11ce-bfc1-08002be10318}\n"
            "Driver Version  : 05/17/2025 3.6.2.1\n"
            "Signer Name     : Microsoft Windows Hardware Compatibility\n"
            "Publisher\n"
            "Driver Verifier  : none\n"
            "Date/Version    : 05/17/2025 3.6.2.1\n"
            "\n"
            "Published Name : oem42.inf\n"
            "Original Name   : netother.inf\n";
        CHECK(vgww::driver::ParsePnputilNdisrdOem(transcript) == "oem25.inf");
        CHECK(vgww::driver::ParsePnputilNdisrdOem(transcript + "\n") ==
              "oem25.inf");
        CHECK(vgww::driver::ParsePnputilNdisrdOem("unrelated text") == "");
        // Provider-only variant (no "Original Name" trailer) must not crash.
        CHECK(vgww::driver::ParsePnputilNdisrdOem(
                  "Published Name : oem9.inf\nProvider Name : Other\n") == "");

        // Localized (non-English) keys with the ndisrd entry NOT in first
        // position: the oem-value tracker must follow each oem##.inf label
        // even when the English "published name" key is absent, so a later
        // ndisrd hit returns THIS entry's oem (never an unrelated one).
        {
            const std::string zh_multi =
                "发布名称 : oem11.inf\n"
                "原始名称   : amd_gpio2.sys.inf\n"
                "\n"
                "发布名称 : oem12.inf\n"
                "原始名称   : someother.inf\n"
                "\n"
                "发布名称 : oem42.inf\n"
                "原始名称   : ndisrd_lwf.inf\n";
            CHECK(vgww::driver::ParsePnputilNdisrdOem(zh_multi) == "oem42.inf");
        }
        {
            // Chinese keys, ndisrd LAST among several unpublished entries.
            const std::string zh_last =
                "发布名称 : oem1.inf\n"
                "原始名称   : a.inf\n"
                "\n"
                "发布名称 : oem2.inf\n"
                "原始名称   : b.inf\n"
                "\n"
                "发布名称 : oem3.inf\n"
                "原始名称   : ndisrd_lwf.inf\n";
            CHECK(vgww::driver::ParsePnputilNdisrdOem(zh_last) == "oem3.inf");
        }
    }

    void TestBuildDriverArgs() {
        const auto add = vgww::driver::BuildAddDriverArgs(
            L"C:\\dir with space\\ndisrd_lwf.inf");
        CHECK(add.size() == 3);
        CHECK(add[0] == L"/add-driver");
        CHECK(add[1] == L"C:\\dir with space\\ndisrd_lwf.inf");
        CHECK(add[2] == L"/install");

        const auto del = vgww::driver::BuildDeleteDriverArgs(L"oem25.inf");
        CHECK(del.size() == 3);
        CHECK(del[0] == L"/delete-driver");
        CHECK(del[1] == L"oem25.inf");
        CHECK(del[2] == L"/uninstall");
    }

    // ------------------------------------------------------------------
    // Migrated from test_web.cpp (S5.9): INetCfg LWF component
    // install/bind/unbind orchestration, exercised through FakeSession.
    // ------------------------------------------------------------------
    void TestComponentMatrix() {
        // (1) Success path: Open -> AcquireWriteLock -> Install ->
        //     EnumerateAdapters -> BindToAdapter x2 -> Apply -> Close.
        {
            FakeSession fake;
            const std::string err =
                vgww::driver::InstallNdisrdLwfComponent(fake);
            CHECK(err.empty());
            CHECK(fake.close_called);
            CHECK(fake.calls.size() == 8);
            CHECK(fake.calls[0] == "Open");
            CHECK(fake.calls[1] == "AcquireWriteLock");
            CHECK(fake.calls[2] == "Install");
            CHECK(fake.calls[3] == "EnumerateAdapters");
            CHECK(fake.calls[4] == "BindToAdapter");
            CHECK(fake.calls[5] == "BindToAdapter");
            CHECK(fake.calls[6] == "Apply");
            CHECK(fake.calls.back() == "Close");
        }

        // (2) Write-lock held elsewhere: stop before any install, surface
        //     the error, still close (every Open pairs with a Close).
        {
            FakeSession fake;
            fake.lock_fail = true;
            const std::string err =
                vgww::driver::InstallNdisrdLwfComponent(fake);
            CHECK(err.find("write lock") != std::string::npos);
            CHECK(fake.close_called);
            CHECK(fake.calls.size() == 3);  // Open, AcquireWriteLock, Close
        }

        // (3) Install failure keeps Close on the error path.
        {
            FakeSession fake;
            fake.install_fail = true;
            const std::string err =
                vgww::driver::InstallNdisrdLwfComponent(fake);
            CHECK(err.find("Install") != std::string::npos);
            CHECK(fake.close_called);
            CHECK(fake.calls[2] == "Install");
            CHECK(fake.calls.back() == "Close");
        }

        // (4) Bind failure stops before Apply but still closes.
        {
            FakeSession fake;
            fake.bind_fail = true;
            const std::string err =
                vgww::driver::InstallNdisrdLwfComponent(fake);
            CHECK(err.find("BindTo") != std::string::npos);
            CHECK(fake.close_called);
            CHECK(fake.calls.back() == "Close");
            CHECK(fake.calls.size() == 6);  // ...Install, Enum, Bind x1, Close
        }

        // (5) Apply failure surfaces and closes.
        {
            FakeSession fake;
            fake.apply_fail = true;
            const std::string err =
                vgww::driver::InstallNdisrdLwfComponent(fake);
            CHECK(err.find("Apply") != std::string::npos);
            CHECK(fake.close_called);
        }

        // (6) Uninstall order: Find -> EnumerateAdapters -> UnbindFromAdapter
        //     x2 -> DeInstall -> Apply -> Close.
        {
            FakeSession fake;
            const std::string err =
                vgww::driver::UninstallNdisrdLwfComponent(fake);
            CHECK(err.empty());
            CHECK(fake.close_called);
            CHECK(fake.calls.size() == 9);
            CHECK(fake.calls[0] == "Open");
            CHECK(fake.calls[1] == "AcquireWriteLock");
            CHECK(fake.calls[2] == "Find");
            CHECK(fake.calls[3] == "EnumerateAdapters");
            CHECK(fake.calls[4] == "UnbindFromAdapter");
            CHECK(fake.calls[5] == "UnbindFromAdapter");
            CHECK(fake.calls[6] == "DeInstall");
            CHECK(fake.calls[7] == "Apply");
            CHECK(fake.calls[8] == "Close");
        }

        // (7) DeInstall failure surfaces; Close still runs.
        {
            FakeSession fake;
            fake.deinstall_fail = true;
            const std::string err =
                vgww::driver::UninstallNdisrdLwfComponent(fake);
            CHECK(err.find("DeInstall") != std::string::npos);
            CHECK(fake.close_called);
        }
    }

    // ------------------------------------------------------------------
    // Migrated from test_web.cpp: production wiring (pnputil stage hands
    // over to the INetCfg stage in order) + the install payload gate.
    // ------------------------------------------------------------------
    void TestInstallPayloadGate() {
        // The install path must stop at the payload check with a friendly
        // diagnosis and never consult pnputil when the triple is missing.
        // Builds that ship the payload next to the test binary exercise the
        // pnputil-failure path instead (add-driver is the first runner call,
        // and the INetCfg factory is never consulted).
        RunnerScript rs;
        WiringHarness h;
        if (!PayloadTripleNextToExe()) {
            const std::string err = vgww::driver::InstallNdisrdDriver(
                rs.runner(), h.factory());
            CHECK(err.find("driver payload") != std::string::npos);
            CHECK(rs.calls == 0);
            CHECK(!*h.shared_close);
        } else {
            rs.fallback.code = 1;
            rs.fallback.out = "add failed";
            const std::string err = vgww::driver::InstallNdisrdDriver(
                rs.runner(), h.factory(), SafeInstallHooks());
            CHECK(err.find("pnputil") != std::string::npos);
            // Baseline enum runs first, then the failing add-driver.
            CHECK(rs.calls >= 2);
            CHECK(rs.all_args.size() >= 2);
            if (rs.all_args.size() >= 2) {
                CHECK(rs.all_args[0].size() == 1 &&
                      rs.all_args[0][0] == L"/enum-drivers");
                CHECK(rs.all_args[1][0] == L"/add-driver");
            }
            CHECK(!*h.shared_close);
        }
    }

    void TestUninstallWiring() {
        // (a) Uninstall wiring: INetCfg unbind runs BEFORE the pnputil
        //     delete-driver, and the session sees the full unbind order.
        {
            WiringHarness h;
            RunnerScript rs;
            rs.fallback.out = kOemTranscript;
            rs.fallback.code = 0;
            const std::string err =
                vgww::driver::UninstallNdisrdDriver(rs.runner(), h.factory(),
                                                    SafeUninstallHooks());
            CHECK(err.empty());
            CHECK(*h.shared_close);
            CHECK(h.shared_log->size() == 9);
            CHECK((*h.shared_log)[0] == "Open");
            CHECK((*h.shared_log)[1] == "AcquireWriteLock");
            CHECK((*h.shared_log)[2] == "Find");
            CHECK((*h.shared_log)[3] == "EnumerateAdapters");
            CHECK((*h.shared_log)[4] == "UnbindFromAdapter");
            CHECK((*h.shared_log)[5] == "UnbindFromAdapter");
            CHECK((*h.shared_log)[6] == "DeInstall");
            CHECK((*h.shared_log)[7] == "Apply");
            CHECK((*h.shared_log)[8] == "Close");
            // enum-drivers first, then delete-driver (INetCfg sat in between).
            CHECK(rs.calls == 2);
            CHECK(rs.all_args.size() == 2);
            if (rs.all_args.size() == 2) {
                CHECK(rs.all_args[0].size() == 1);
                CHECK(rs.all_args[0][0] == L"/enum-drivers");
                CHECK(rs.all_args[1].size() == 3);
                CHECK(rs.all_args[1][0] == L"/delete-driver");
                CHECK(rs.all_args[1][1] == L"oem25.inf");
                CHECK(rs.all_args[1][2] == L"/uninstall");
            }
        }

        // (b) Uninstall stops at the INetCfg stage when the session fails:
        //     no pnputil delete is attempted (the driver-store entry stays).
        {
            WiringHarness h;
            RunnerScript rs;
            rs.fallback.out = kOemTranscript;
            rs.fallback.code = 0;
            h.session.unbind_fail = true;
            const std::string err =
                vgww::driver::UninstallNdisrdDriver(rs.runner(), h.factory(),
                                                    SafeUninstallHooks());
            CHECK(err.find("UnbindFrom") != std::string::npos);
            CHECK(*h.shared_close);
            CHECK(rs.calls == 1);
            if (!rs.all_args.empty()) {
                CHECK(rs.all_args[0][0] == L"/enum-drivers");
            }
        }

        // (c) A factory that cannot create a session surfaces a clear
        //     error; the pnputil delete-driver must NOT run.
        {
            WiringHarness h;
            RunnerScript rs;
            rs.fallback.out = kOemTranscript;
            rs.fallback.code = 0;
            h.factory_fail = true;
            const std::string err =
                vgww::driver::UninstallNdisrdDriver(rs.runner(), h.factory(),
                                                    SafeUninstallHooks());
            CHECK(err.find("INetCfg") != std::string::npos);
            CHECK(rs.calls == 1);
            if (!rs.all_args.empty()) {
                CHECK(rs.all_args[0][0] == L"/enum-drivers");
            }
        }
    }

    void TestUninstallDeleteArgs() {
        // Uninstall with /enum-drivers reporting the ndisrd driver: the
        // delete-driver argv must be exactly built.
        WiringHarness h;
        RunnerScript rs;
        rs.fallback.out = kOemTranscript;
        rs.fallback.code = 0;
        const std::string un_out =
            vgww::driver::UninstallNdisrdDriver(rs.runner(), h.factory(),
                                                SafeUninstallHooks());
        CHECK(un_out.empty());
        const std::vector<std::wstring> del_args = rs.last_args();
        CHECK(del_args.size() == 3);
        if (del_args.size() == 3) {
            CHECK(del_args[0] == L"/delete-driver");
            CHECK(del_args[1] == L"oem25.inf");
            CHECK(del_args[2] == L"/uninstall");
        }
    }

    void TestInstallWiringPnputilFirst() {
        // Install wiring: with the payload triple present next to the test
        // binary the pnputil /add-driver must succeed BEFORE the INetCfg
        // factory is consulted; an INetCfg-stage failure then surfaces the
        // driver diagnosis and runs the best-effort driver-store rollback
        // (enum-drivers -> delete-driver). Builds without the shipped
        // payload take the missing-payload path instead (runner never
        // consulted).
        if (!PayloadTripleNextToExe()) {
            RunnerScript rs;
            WiringHarness h;
            const std::string err = vgww::driver::InstallNdisrdDriver(
                rs.runner(), h.factory());
            CHECK(err.find("driver payload") != std::string::npos);
            CHECK(rs.calls == 0);
            return;
        }

        WiringHarness h;
        RunnerScript rs;
        // Baseline sees only oem25; the rollback enum sees that oem99 was
        // published by this install, so only oem99 is deleted.
        rs.script.push_back({kOemTranscript, 0, true});     // baseline enum
        rs.script.push_back({"", 0, true});                 // add-driver ok
        rs.script.push_back({kOemTwoTranscript, 0, true});  // rollback enum
        rs.script.push_back({"", 0, true});                 // delete oem99
        h.session.install_fail = true;  // INetCfg-stage failure

        const std::string err =
            vgww::driver::InstallNdisrdDriver(rs.runner(), h.factory(),
                                              SafeInstallHooks());
        // The INetCfg diagnosis must surface (the factory WAS consulted).
        CHECK(err.find("INetCfg") != std::string::npos);
        // Every Open pairs with a Close (4 calls on this failure path).
        CHECK(*h.shared_close);
        CHECK(h.shared_log->size() == 4);
        CHECK((*h.shared_log)[0] == "Open");
        CHECK((*h.shared_log)[1] == "AcquireWriteLock");
        CHECK((*h.shared_log)[2] == "Install");
        CHECK((*h.shared_log)[3] == "Close");
        // Sequence: baseline enum, add-driver, rollback enum, delete new.
        CHECK(rs.calls == 4);
        CHECK(rs.all_args.size() == 4);
        if (rs.all_args.size() == 4) {
            CHECK(rs.all_args[0][0] == L"/enum-drivers");
            CHECK(rs.all_args[1][0] == L"/add-driver");
            CHECK(rs.all_args[2][0] == L"/enum-drivers");
            CHECK(rs.last_args()[0] == L"/delete-driver");
            CHECK(rs.last_args()[1] == L"oem99.inf");
        }
    }

    // ------------------------------------------------------------------
    // RA-6: the remaining component-level branches (batch16). Fake flags
    // added above: open_fail / find_fail / no_adapters (+ the previously
    // dead enum_fail).
    // ------------------------------------------------------------------
    void TestComponentMatrixExtended() {
        // Install: EnumerateAdapters failure -> err surfaces, Close still
        // runs (D9 pairing).
        {
            FakeSession fake;
            fake.enum_fail = true;
            const std::string err =
                vgww::driver::InstallNdisrdLwfComponent(fake);
            CHECK(err.find("EnumerateAdapters failed") != std::string::npos);
            CHECK(fake.close_called);
            CHECK(fake.calls.size() == 5);
            CHECK(fake.calls[0] == "Open");
            CHECK(fake.calls[1] == "AcquireWriteLock");
            CHECK(fake.calls[2] == "Install");
            CHECK(fake.calls[3] == "EnumerateAdapters");
            CHECK(fake.calls[4] == "Close");
        }

        // Install: zero physical adapters is NOT an install failure (nothing
        // to bind); Apply still commits and Close pairs.
        {
            FakeSession fake;
            fake.no_adapters = true;
            const std::string err =
                vgww::driver::InstallNdisrdLwfComponent(fake);
            CHECK(err.empty());
            CHECK(fake.close_called);
            CHECK(fake.calls.size() == 6);
            CHECK(fake.calls[3] == "EnumerateAdapters");
            CHECK(fake.calls[4] == "Apply");
            CHECK(fake.calls[5] == "Close");
        }

        // Uninstall: EnumerateAdapters failure -> err surfaces + Close.
        {
            FakeSession fake;
            fake.enum_fail = true;
            const std::string err =
                vgww::driver::UninstallNdisrdLwfComponent(fake);
            CHECK(err.find("EnumerateAdapters failed") != std::string::npos);
            CHECK(fake.close_called);
            CHECK(fake.calls.size() == 5);  // Open, Acq, Find, Enum, Close
        }

        // Uninstall: Apply failure surfaces + Close.
        {
            FakeSession fake;
            fake.apply_fail = true;
            const std::string err =
                vgww::driver::UninstallNdisrdLwfComponent(fake);
            CHECK(err.find("Apply failed") != std::string::npos);
            CHECK(fake.close_called);
            CHECK(fake.calls.back() == "Close");
        }

        // Open failure: the error is the session's own diagnosis and Close
        // is NOT called (the Open contract: a failed Open self-cleans; Close
        // only pairs with a successful Open).
        {
            FakeSession fake;
            fake.open_fail = true;
            const std::string err =
                vgww::driver::InstallNdisrdLwfComponent(fake);
            CHECK(err.find("Open failed") != std::string::npos);
            CHECK(!fake.close_called);
            CHECK(fake.calls.size() == 1);
            CHECK(fake.calls[0] == "Open");
        }
        {
            FakeSession fake;
            fake.open_fail = true;
            const std::string err =
                vgww::driver::UninstallNdisrdLwfComponent(fake);
            CHECK(err.find("Open failed") != std::string::npos);
            CHECK(!fake.close_called);
        }

        // Uninstall: Find failure surfaces + Close.
        {
            FakeSession fake;
            fake.find_fail = true;
            const std::string err =
                vgww::driver::UninstallNdisrdLwfComponent(fake);
            CHECK(err.find("Find failed") != std::string::npos);
            CHECK(fake.close_called);
            CHECK(fake.calls.size() == 4);  // Open, Acq, Find, Close
        }
    }

    // ------------------------------------------------------------------
    // RA-7: the INetCfg-stage failure rolls back ONLY the entry published
    // by this install (baseline diff): runner order must be
    // [enum(baseline), add-driver, enum(now), delete(new oem)] and the
    // message must state the entry was rolled back.
    // ------------------------------------------------------------------
    void TestInstallRollbackAsserted() {
        if (!PayloadTripleNextToExe()) {
            std::printf("  (payload not shipped next to the test binary; "
                        "install-level assertions skipped in this build)\n");
            return;
        }
        WiringHarness h;
        RunnerScript rs;
        rs.script.push_back({kOemTranscript, 0, true});     // baseline enum
        rs.script.push_back({"", 0, true});                 // add-driver ok
        rs.script.push_back({kOemTwoTranscript, 0, true});  // rollback enum
        rs.script.push_back({"", 0, true});                 // delete oem99
        h.session.install_fail = true;

        const std::string err =
            vgww::driver::InstallNdisrdDriver(rs.runner(), h.factory(),
                                              SafeInstallHooks());
        CHECK(err.find("INetCfg") != std::string::npos);
        CHECK(err.find("rolled back") != std::string::npos);
        CHECK(rs.calls == 4);
        CHECK(rs.all_args.size() == 4);
        if (rs.all_args.size() == 4) {
            CHECK(rs.all_args[0].size() == 1 &&
                  rs.all_args[0][0] == L"/enum-drivers");
            CHECK(rs.all_args[1][0] == L"/add-driver");
            CHECK(rs.all_args[2].size() == 1 &&
                  rs.all_args[2][0] == L"/enum-drivers");
            CHECK(rs.all_args[3][0] == L"/delete-driver");
            // ONLY the new entry may be deleted; oem25 predates this install.
            CHECK(rs.all_args[3][1] == L"oem99.inf");
        }
    }

    // ------------------------------------------------------------------
    // RA-8: rollback failure variants + factory-null symmetry (B-10) +
    // baseline-unavailable skip (data-loss guard, V2 section 0.4-1).
    // ------------------------------------------------------------------
    void TestRollbackFailVariants() {
        if (!PayloadTripleNextToExe()) {
            std::printf("  (payload not shipped next to the test binary; "
                        "install-level assertions skipped in this build)\n");
            return;
        }

        // (a) baseline unavailable (baseline enum cannot spawn): the
        // rollback must SKIP every delete (never delete pre-existing
        // entries) and say so; no further runner calls happen.
        {
            WiringHarness h;
            RunnerScript rs;
            rs.script.push_back({"", 1, false});  // baseline enum spawn fail
            rs.script.push_back({"", 0, true});   // add-driver ok
            h.session.install_fail = true;
            const std::string err =
                vgww::driver::InstallNdisrdDriver(rs.runner(), h.factory(),
                                                  SafeInstallHooks());
            CHECK(err.find("INetCfg") != std::string::npos);
            CHECK(err.find("baseline") != std::string::npos);
            CHECK(rs.calls == 2);  // no rollback enum, no delete
        }

        // (b) rollback enum fails (spawn ok, exit != 0): explicit rollback
        // failure carrying the enum exit code.
        {
            WiringHarness h;
            RunnerScript rs;
            rs.script.push_back({kOemTranscript, 0, true});  // baseline
            rs.script.push_back({"", 0, true});              // add ok
            rs.script.push_back({"garbage", 5, true});       // rollback enum fails
            h.session.install_fail = true;
            const std::string err =
                vgww::driver::InstallNdisrdDriver(rs.runner(), h.factory(),
                                                  SafeInstallHooks());
            CHECK(err.find("rollback failed") != std::string::npos);
            CHECK(err.find("5") != std::string::npos);
            CHECK(rs.calls == 3);
        }

        // (c) rollback delete fails: the message names the oem and exit
        // code (plus pnputil output), not just "see pnputil above".
        {
            WiringHarness h;
            RunnerScript rs;
            rs.script.push_back({kOemTranscript, 0, true});    // baseline
            rs.script.push_back({"", 0, true});                // add ok
            rs.script.push_back({kOemTwoTranscript, 0, true}); // enum: new found
            rs.script.push_back({"denied", 5, true});          // delete fails
            h.session.install_fail = true;
            const std::string err =
                vgww::driver::InstallNdisrdDriver(rs.runner(), h.factory(),
                                                  SafeInstallHooks());
            CHECK(err.find("rollback failed") != std::string::npos);
            CHECK(err.find("oem99.inf") != std::string::npos);
            CHECK(err.find("5") != std::string::npos);
            CHECK(err.find("denied") != std::string::npos);
            CHECK(rs.calls == 4);
        }

        // (d) B-10: a factory that cannot create the session must roll the
        // published entry back exactly like a component failure.
        {
            WiringHarness h;
            RunnerScript rs;
            rs.script.push_back({kOemTranscript, 0, true});    // baseline
            rs.script.push_back({"", 0, true});                // add ok
            rs.script.push_back({kOemTwoTranscript, 0, true}); // enum: new found
            rs.script.push_back({"", 0, true});                // delete oem99
            h.factory_fail = true;
            const std::string err =
                vgww::driver::InstallNdisrdDriver(rs.runner(), h.factory(),
                                                  SafeInstallHooks());
            CHECK(err.find("INetCfg") != std::string::npos);
            CHECK(err.find("rolled back") != std::string::npos);
            CHECK(rs.calls == 4);
            CHECK(rs.all_args.size() == 4);
            if (rs.all_args.size() == 4) {
                CHECK(rs.all_args[3][0] == L"/delete-driver");
                CHECK(rs.all_args[3][1] == L"oem99.inf");
            }
        }
    }

    // ------------------------------------------------------------------
    // RA-10: uninstall failure variants (U3 enum exit code, U6 delete
    // spawn failure, U7 delete exit code) + DeInstall E2E (A13).
    // ------------------------------------------------------------------
    void TestUninstallFailureVariants() {
        // U3: enum exit != 0 with nothing parseable -> the tool failed;
        // must NOT be misdiagnosed as "driver not published".
        {
            WiringHarness h;
            RunnerScript rs;
            rs.fallback = {"boom", 5, true};
            const std::string err =
                vgww::driver::UninstallNdisrdDriver(rs.runner(), h.factory(),
                                                    SafeUninstallHooks());
            CHECK(err.find("enum-drivers") != std::string::npos);
            CHECK(err.find("5") != std::string::npos);
            CHECK(err.find("no published ndisrd driver") == std::string::npos);
            CHECK(rs.calls == 1);
        }

        // U6: delete-driver cannot spawn -> explicit diagnosis, no cleanup
        // claims.
        {
            WiringHarness h;
            RunnerScript rs;
            rs.script.push_back({kOemTranscript, 0, true});  // enum ok
            rs.script.push_back({"", 0, false});             // delete spawn fail
            const std::string err =
                vgww::driver::UninstallNdisrdDriver(rs.runner(), h.factory(),
                                                    SafeUninstallHooks());
            CHECK(err.find("pnputil") != std::string::npos);
            CHECK(rs.calls == 2);
        }

        // U7: delete-driver exit != 0 -> names the oem and exit code.
        {
            WiringHarness h;
            RunnerScript rs;
            rs.script.push_back({kOemTranscript, 0, true});  // enum ok
            rs.script.push_back({"denied", 5, true});        // delete code 5
            const std::string err =
                vgww::driver::UninstallNdisrdDriver(rs.runner(), h.factory(),
                                                    SafeUninstallHooks());
            CHECK(err.find("delete-driver") != std::string::npos);
            CHECK(err.find("oem25.inf") != std::string::npos);
            CHECK(err.find("5") != std::string::npos);
            CHECK(err.find("denied") != std::string::npos);
            CHECK(rs.calls == 2);
        }

        // A13: DeInstall failure E2E -> the pnputil delete is never
        // attempted.
        {
            WiringHarness h;
            RunnerScript rs;
            rs.fallback = {kOemTranscript, 0, true};
            h.session.deinstall_fail = true;
            const std::string err =
                vgww::driver::UninstallNdisrdDriver(rs.runner(), h.factory(),
                                                    SafeUninstallHooks());
            CHECK(err.find("DeInstall") != std::string::npos);
            CHECK(rs.calls == 1);  // enum only
        }
    }

    // ------------------------------------------------------------------
    // RA-2: plural oem parsing (batch16 B-9). Every published ndisrd entry
    // is found, in transcript order; the singular helper stays a thin
    // wrapper returning the first one.
    // ------------------------------------------------------------------
    void TestParsePlural() {
        using vgww::driver::ParsePnputilNdisrdOem;
        using vgww::driver::ParsePnputilNdisrdOems;
        using Vec = std::vector<std::string>;

        // English multi, ndisrd NOT first.
        const std::string en_not_first =
            "Published Name : oem11.inf\n"
            "Original Name   : amd_gpio2.sys.inf\n"
            "\n"
            "Published Name : oem25.inf\n"
            "Original Name   : ndisrd_lwf.inf\n";
        CHECK(ParsePnputilNdisrdOems(en_not_first) == Vec{"oem25.inf"});
        CHECK(ParsePnputilNdisrdOem(en_not_first) == "oem25.inf");

        // Plural: two ndisrd entries, order preserved.
        const std::string en_plural =
            "Published Name : oem25.inf\n"
            "Original Name   : ndisrd_lwf.inf\n"
            "\n"
            "Published Name : oem99.inf\n"
            "Original Name   : ndisrd_lwf.inf\n";
        CHECK(ParsePnputilNdisrdOems(en_plural) ==
              (Vec{"oem25.inf", "oem99.inf"}));
        CHECK(ParsePnputilNdisrdOem(en_plural) == "oem25.inf");

        // Uppercase published name.
        CHECK(ParsePnputilNdisrdOems(
                  "Published Name : OEM25.INF\n"
                  "Original Name   : ndisrd_lwf.inf\n") == Vec{"OEM25.INF"});

        // Multi-digit oem number.
        CHECK(ParsePnputilNdisrdOems(
                  "Published Name : oem123.inf\n"
                  "Original Name   : ndisrd_lwf.inf\n") == Vec{"oem123.inf"});

        // Chinese keys with ndisrd last.
        const std::string zh_last =
            "发布名称 : oem1.inf\n"
            "原始名称   : a.inf\n"
            "\n"
            "发布名称 : oem3.inf\n"
            "原始名称   : ndisrd_lwf.inf\n";
        CHECK(ParsePnputilNdisrdOems(zh_last) == Vec{"oem3.inf"});

        // Empty transcript / no match.
        CHECK(ParsePnputilNdisrdOems("") == Vec{});
        CHECK(ParsePnputilNdisrdOems("unrelated text") == Vec{});

        // CRLF line endings parse the same.
        CHECK(ParsePnputilNdisrdOems(
                  "Published Name : oem25.inf\r\n"
                  "Original Name   : ndisrd_lwf.inf\r\n") == Vec{"oem25.inf"});

        // A bare "ndisrd" line without a preceding published-oem tracker
        // stays empty (never return an unrelated value).
        CHECK(ParsePnputilNdisrdOems("Original Name   : ndisrd_lwf.inf\n") ==
              Vec{});

        // Duplicate hits for one entry are de-duplicated.
        CHECK(ParsePnputilNdisrdOems(
                  "Published Name : oem25.inf\n"
                  "Original Name   : ndisrd_lwf.inf\n"
                  "Provider Name   : Ntkr ndisrd\n") == Vec{"oem25.inf"});
    }

    // ------------------------------------------------------------------
    // RA-3: baseline diff for the rollback (pure function).
    // ------------------------------------------------------------------
    void TestDiffNewOems() {
        using vgww::driver::DiffNewOems;
        using Vec = std::vector<std::string>;

        CHECK(DiffNewOems({}, {}) == Vec{});
        // Empty baseline: every "after" entry is technically new (the CALLER
        // must skip rollback entirely when the baseline could not be
        // captured; this function only computes the set difference).
        CHECK(DiffNewOems({}, {"oem1.inf"}) == Vec{"oem1.inf"});
        CHECK(DiffNewOems({"oem1.inf"}, {}) == Vec{});
        CHECK(DiffNewOems({"oem25.inf"}, {"oem25.inf"}) == Vec{});
        CHECK(DiffNewOems({"oem25.inf"}, {"oem25.inf", "oem99.inf"}) ==
              Vec{"oem99.inf"});
        // Order follows `after`.
        CHECK(DiffNewOems({"oem25.inf"}, {"oem99.inf", "oem25.inf"}) ==
              Vec{"oem99.inf"});
        CHECK(DiffNewOems({"a.inf", "b.inf"}, {"a.inf", "b.inf", "c.inf",
                                              "d.inf"}) ==
              (Vec{"c.inf", "d.inf"}));
    }

    // ------------------------------------------------------------------
    // RA-5: install-report IO (F2). The child publishes running/ok/fail;
    // the parent only trusts a complete status line (missing/bad -> "").
    // ------------------------------------------------------------------
    void TestInstallReportIO() {
        using vgww::driver::DefaultInstallReportPath;
        using vgww::driver::ReadInstallReport;
        using vgww::driver::WriteInstallReport;

        TempDir t;
        const std::filesystem::path p =
            t.path() / L"sub" / L"install-report.txt";

        CHECK(WriteInstallReport(p, "running", 0, ""));
        auto r = ReadInstallReport(p);
        CHECK(r.status == "running");
        CHECK(r.exit_code == 0);
        CHECK(r.detail.empty());

        CHECK(WriteInstallReport(p, "fail", 7, "boom\ndetail"));
        r = ReadInstallReport(p);
        CHECK(r.status == "fail");
        CHECK(r.exit_code == 7);
        CHECK(r.detail.find("boom") != std::string::npos);

        CHECK(WriteInstallReport(p, "ok", 0, ""));
        r = ReadInstallReport(p);
        CHECK(r.status == "ok");
        CHECK(r.exit_code == 0);

        // Missing file -> no report (status ""); the default exit code is
        // not clobbered into something misleading.
        r = ReadInstallReport(t.path() / L"nope.txt");
        CHECK(r.status.empty());

        // Malformed file -> no report.
        {
            std::ofstream bad(t.path() / L"bad.txt", std::ios::binary);
            bad << "hello\nworld\n";
        }
        r = ReadInstallReport(t.path() / L"bad.txt");
        CHECK(r.status.empty());
        {
            std::ofstream bad2(t.path() / L"bad2.txt", std::ios::binary);
            bad2 << "status=bogus\nexit=0\n---\n";
        }
        r = ReadInstallReport(t.path() / L"bad2.txt");
        CHECK(r.status.empty());

        // Default path shape: <ProgramData>\VGWW\install-report.txt.
        const std::filesystem::path dp = DefaultInstallReportPath();
        CHECK(!dp.empty());
        CHECK(dp.filename() == L"install-report.txt");
        CHECK(dp.parent_path().filename() == L"VGWW");
    }

    // ------------------------------------------------------------------
    // RA-9: the oem-missing early exit still removes our own self-heal
    // artifacts (task + mirror) best-effort and reports cleanly.
    // ------------------------------------------------------------------
    void TestUninstallOemMissingCleans() {
        const std::string no_ndisrd =
            "Published Name : oem7.inf\n"
            "Original Name   : something_else.inf\n";

        // Success variant.
        {
            WiringHarness h;
            RunnerScript rs;
            rs.fallback = {no_ndisrd, 0, true};
            int scm = 0, task = 0, mirror = 0, sys32 = 0;
            vgww::driver::UninstallHooks hooks;
            hooks.cleanup_legacy_service = [&] { ++scm; };
            hooks.remove_boot_task = [&](std::wstring&) {
                ++task;
                return true;
            };
            hooks.remove_mirror_copy = [&](std::wstring&) {
                ++mirror;
                return true;
            };
            hooks.remove_system32_copy = [&](std::wstring&) {
                ++sys32;
                return true;
            };
            const std::string err = vgww::driver::UninstallNdisrdDriver(
                rs.runner(), h.factory(), hooks);
            CHECK(!err.empty());  // explicit intent: "not installed" still reports
            CHECK(err.find("no published ndisrd driver") != std::string::npos);
            CHECK(task == 1);
            CHECK(mirror == 1);
            // The driver was never removed: no SCM/System32 audit noise.
            CHECK(scm == 0);
            CHECK(sys32 == 0);
            CHECK(rs.calls == 1);
        }

        // Task-removal failure in the early path is surfaced (warning
        // semantics) without changing the "not found" nature of the result.
        {
            WiringHarness h;
            RunnerScript rs;
            rs.fallback = {no_ndisrd, 0, true};
            vgww::driver::UninstallHooks hooks;
            hooks.remove_boot_task = [](std::wstring& e) {
                e = L"schtasks /delete failed";
                return false;
            };
            hooks.remove_mirror_copy = [](std::wstring&) { return true; };
            const std::string err = vgww::driver::UninstallNdisrdDriver(
                rs.runner(), h.factory(), hooks);
            CHECK(!err.empty());
            CHECK(err.find("schtasks /delete failed") != std::string::npos);
        }
    }

    // ------------------------------------------------------------------
    // RB-2: full install success path, headless. All real-machine channels
    // (device DACL, SCM legacy cleanup, legacy-task removal + ProgramData
    // mirror) are injected recorders; pnputil is a scripted runner.
    // ------------------------------------------------------------------
    void TestInstallSuccessFullHeadless() {
        if (!PayloadTripleNextToExe()) {
            std::printf("  (payload not shipped next to the test binary; "
                        "install-level assertions skipped in this build)\n");
            return;
        }
        WiringHarness h;
        RunnerScript rs;
        rs.script.push_back({"", 0, true});  // baseline enum: empty store
        rs.script.push_back({"", 0, true});  // add-driver ok
        int grant = 0, task = 0, scm = 0;
        vgww::driver::InstallHooks hooks;
        hooks.cleanup_legacy_service = [&] { ++scm; };
        hooks.ensure_device_access = [&] {
            ++grant;
            return true;
        };
        // batch23: the install removes any LEGACY task (idempotent) instead of
        // registering one; the hook must be consulted exactly once.
        hooks.remove_boot_task = [&](std::wstring&) {
            ++task;
            return true;
        };

        const std::string err =
            vgww::driver::InstallNdisrdDriver(rs.runner(), h.factory(), hooks);
        CHECK(err.empty());
        CHECK(grant == 1);
        CHECK(task == 1);
        CHECK(scm == 1);
        // Runner sequence: baseline enum then the one add-driver.
        CHECK(rs.calls == 2);
        if (rs.all_args.size() == 2) {
            CHECK(rs.all_args[0].size() == 1 &&
                  rs.all_args[0][0] == L"/enum-drivers");
            CHECK(rs.all_args[1][0] == L"/add-driver");
        }
        // The full INetCfg walk ran and paired Close.
        CHECK(*h.shared_close);
        CHECK(h.shared_log->size() == 8);
    }

    // ------------------------------------------------------------------
    // RB-3: full uninstall success path with the four real-machine
    // channels recorded; System32 and task failures are reported as
    // residuals (F7); plural oem entries are all deleted (B-9).
    // ------------------------------------------------------------------
    void TestUninstallFullCleanRecorder() {
        // (a) success: four hooks called once, result clean.
        {
            WiringHarness h;
            RunnerScript rs;
            rs.script.push_back({kOemTranscript, 0, true});
            rs.script.push_back({"", 0, true});
            int scm = 0, task = 0, mirror = 0, sys32 = 0;
            vgww::driver::UninstallHooks hooks;
            hooks.cleanup_legacy_service = [&] { ++scm; };
            hooks.remove_boot_task = [&](std::wstring&) {
                ++task;
                return true;
            };
            hooks.remove_mirror_copy = [&](std::wstring&) {
                ++mirror;
                return true;
            };
            hooks.remove_system32_copy = [&](std::wstring&) {
                ++sys32;
                return true;
            };
            const std::string err = vgww::driver::UninstallNdisrdDriver(
                rs.runner(), h.factory(), hooks);
            CHECK(err.empty());
            CHECK(scm == 1);
            CHECK(task == 1);
            CHECK(mirror == 1);
            CHECK(sys32 == 1);
        }

        // (b) System32 removal failure is reported with the file/reason and
        // flips the result to a residual warning.
        {
            WiringHarness h;
            RunnerScript rs;
            rs.script.push_back({kOemTranscript, 0, true});
            rs.script.push_back({"", 0, true});
            vgww::driver::UninstallHooks hooks;
            hooks.cleanup_legacy_service = [] {};
            hooks.remove_boot_task = [](std::wstring&) { return true; };
            hooks.remove_mirror_copy = [](std::wstring&) { return true; };
            hooks.remove_system32_copy = [](std::wstring& e) {
                e = L"C:\\Windows\\System32\\drivers\\ndisrd.sys 删除失败";
                return false;
            };
            const std::string err = vgww::driver::UninstallNdisrdDriver(
                rs.runner(), h.factory(), hooks);
            CHECK(err.find("leftovers") != std::string::npos);
            CHECK(err.find("ndisrd.sys") != std::string::npos);
        }

        // (c) boot-task removal failure is reported too.
        {
            WiringHarness h;
            RunnerScript rs;
            rs.script.push_back({kOemTranscript, 0, true});
            rs.script.push_back({"", 0, true});
            vgww::driver::UninstallHooks hooks;
            hooks.cleanup_legacy_service = [] {};
            hooks.remove_boot_task = [](std::wstring& e) {
                e = L"schtasks /delete failed";
                return false;
            };
            hooks.remove_mirror_copy = [](std::wstring&) { return true; };
            hooks.remove_system32_copy = [](std::wstring&) { return true; };
            const std::string err = vgww::driver::UninstallNdisrdDriver(
                rs.runner(), h.factory(), hooks);
            CHECK(err.find("leftovers") != std::string::npos);
            CHECK(err.find("schtasks /delete failed") != std::string::npos);
        }

        // (d) B-9: every published ndisrd entry is deleted, each with its
        // own delete-driver call (old+new version coexist scenario).
        {
            WiringHarness h;
            RunnerScript rs;
            rs.script.push_back({kOemTwoTranscript, 0, true});
            rs.script.push_back({"", 0, true});
            rs.script.push_back({"", 0, true});
            vgww::driver::UninstallHooks hooks;
            hooks.cleanup_legacy_service = [] {};
            hooks.remove_boot_task = [](std::wstring&) { return true; };
            hooks.remove_mirror_copy = [](std::wstring&) { return true; };
            hooks.remove_system32_copy = [](std::wstring&) { return true; };
            const std::string err = vgww::driver::UninstallNdisrdDriver(
                rs.runner(), h.factory(), hooks);
            CHECK(err.empty());
            CHECK(rs.calls == 3);
            if (rs.all_args.size() == 3) {
                CHECK(rs.all_args[1][0] == L"/delete-driver");
                CHECK(rs.all_args[1][1] == L"oem25.inf");
                CHECK(rs.all_args[2][0] == L"/delete-driver");
                CHECK(rs.all_args[2][1] == L"oem99.inf");
            }
        }
    }

    // ------------------------------------------------------------------
    // RB-4: the grant-only entry point. It must stay install-free by
    // construction (no runner, no task registration) and its retry loop is
    // separately pinned.
    // ------------------------------------------------------------------
    void TestGrantOnlyNoPnputil() {
        using vgww::driver::GrantDeviceAccessOnly;
        using vgww::driver::GrantDeviceAccessWithRetries;

        // Retry loop semantics.
        {
            int n = 0;
            CHECK(GrantDeviceAccessWithRetries(
                [&] {
                    ++n;
                    return n >= 3;
                },
                5, 0));
            CHECK(n == 3);
        }
        {
            int n = 0;
            CHECK(!GrantDeviceAccessWithRetries([&] {
                ++n;
                return false;
            }, 4, 0));
            CHECK(n == 4);
        }
        // First-try success stops immediately.
        {
            int n = 0;
            CHECK(GrantDeviceAccessWithRetries(
                [&] {
                    ++n;
                    return true;
                },
                60, 0));
            CHECK(n == 1);
        }
        // No attempt function: fail closed, no crash.
        CHECK(!GrantDeviceAccessWithRetries(nullptr, 5, 100));

        // Grant-only success: exactly one injected attempt, empty result.
        {
            int calls = 0;
            const std::string err = GrantDeviceAccessOnly([&] {
                ++calls;
                return true;
            });
            CHECK(err.empty());
            CHECK(calls == 1);
        }
    }

    // ------------------------------------------------------------------
    // batch119: enforce the project rule "code and comments are English
    // only; translations live in the UI tables". The driver layer used to
    // emit Chinese diagnostics, but those strings travel through
    // install-report.txt (read by ReadInstallReport) and end up in the
    // settings banner, so a non-Chinese operator saw text that could never
    // be translated for them. A source scan is the only assertion that
    // covers all 76 messages at once; a per-message test would rot the
    // moment someone adds the 77th.
    //
    // Scope of the scan is "text that needs translating", not "any byte
    // above 0x7F": shared typographic symbols such as U+00B7 (used as a
    // separator between two data values) are language neutral and must
    // keep their typography. The forbidden blocks are the CJK / kana /
    // hangul scripts and the full-width forms.
    // ------------------------------------------------------------------
    static bool IsCjkOrFullWidth(std::uint32_t cp) {
        return (cp >= 0x2E80 && cp <= 0x2FDF) ||   // CJK radicals
               (cp >= 0x3040 && cp <= 0x30FF) ||   // hiragana / katakana
               (cp >= 0x3400 && cp <= 0x4DBF) ||   // CJK ext A
               (cp >= 0x4E00 && cp <= 0x9FFF) ||   // CJK unified
               (cp >= 0xAC00 && cp <= 0xD7AF) ||   // hangul syllables
               (cp >= 0x3000 && cp <= 0x303F) ||   // CJK punctuation
               (cp >= 0xFF00 && cp <= 0xFFEF);     // full-width forms
    }

    /// Decodes the next UTF-8 code point. Returns false on a malformed
    /// sequence (which is itself a defect in a source file).
    static bool NextCodePoint(const std::string& s, std::size_t& i,
                              std::uint32_t& cp) {
        const unsigned char b0 = static_cast<unsigned char>(s[i]);
        std::size_t extra = 0;
        if (b0 < 0x80) {
            cp = b0;
            ++i;
            return true;
        }
        if ((b0 & 0xE0) == 0xC0) {
            cp = b0 & 0x1Fu;
            extra = 1;
        } else if ((b0 & 0xF0) == 0xE0) {
            cp = b0 & 0x0Fu;
            extra = 2;
        } else if ((b0 & 0xF8) == 0xF0) {
            cp = b0 & 0x07u;
            extra = 3;
        } else {
            return false;
        }
        if (i + extra >= s.size()) {
            return false;
        }
        for (std::size_t k = 1; k <= extra; ++k) {
            const unsigned char b = static_cast<unsigned char>(s[i + k]);
            if ((b & 0xC0) != 0x80) {
                return false;
            }
            cp = (cp << 6) | (b & 0x3Fu);
        }
        i += extra + 1;
        return true;
    }

    void TestB119SourcesAreEnglishOnly() {
        namespace fs = std::filesystem;
        // __FILE__ is the absolute path this file was compiled from, e.g.
        // <repo>\tests\test_driver_installer.cpp.
        const fs::path self = fs::path(__FILE__);
        const fs::path repo = self.parent_path().parent_path();
        const fs::path src = repo / "src";
        if (!fs::is_directory(src)) {
            // Cannot locate the tree (unusual build setup): do not pretend
            // the invariant holds, but do not fail the suite either.
            std::puts("  (skip) src tree not found next to __FILE__");
            return;
        }
        std::size_t scanned = 0;
        std::vector<fs::path> offenders;
        std::error_code ec;
        for (fs::recursive_directory_iterator it(src, ec), end; it != end;
             it.increment(ec)) {
            if (ec) {
                break;
            }
            if (!it->is_regular_file(ec)) {
                continue;
            }
            const fs::path& p = it->path();
            const std::string ext = p.extension().string();
            if (ext != ".cpp" && ext != ".h" && ext != ".inc") {
                continue;
            }
            // Two files legitimately carry localized data:
            //   ui/i18n.cpp             - the zh/en string tables
            //   ui/i18n_languages.inc   - catalog names such as native
            //                             language labels ("Nihongo")
            const std::string name = p.filename().string();
            if (name == "i18n.cpp" || name == "i18n_languages.inc") {
                continue;
            }
            std::ifstream in(p, std::ios::binary);
            if (!in.good()) {
                continue;
            }
            ++scanned;
            const std::string data((std::istreambuf_iterator<char>(in)),
                                   std::istreambuf_iterator<char>());
            bool bad = false;
            for (std::size_t i = 0; i < data.size();) {
                std::uint32_t cp = 0;
                if (!NextCodePoint(data, i, cp)) {
                    bad = true;  // malformed UTF-8 in a source file
                    break;
                }
                if (IsCjkOrFullWidth(cp)) {
                    bad = true;
                    break;
                }
            }
            if (bad) {
                offenders.push_back(p);
            }
        }
        for (const fs::path& p : offenders) {
            std::fprintf(stderr, "CJK/full-width source text: %s\n",
                         p.string().c_str());
        }
        CHECK(scanned > 50);  // the walk really ran over the tree
        CHECK(offenders.empty());
    }

    // ------------------------------------------------------------------
    // batch268: RunProcessCapture must hand every argument to the child
    // VERBATIM. The Windows argv splitter (CommandLineToArgvW and the
    // MSVC runtime) treats a run of backslashes as literal ONLY until a
    // quote follows it: 2N backslashes + a quote become N backslashes and
    // a real quote, 2N+1 become N backslashes and a literal quote, and a
    // run at the END of the argument is doubled. A naive "escape every
    // quote with one backslash" escaper therefore corrupts `C:\dir\`
    // (delivers `C:\dir"`) and `a\\"b` (delivers `a\"b`).
    //
    // The assertion is a real round trip: the test binary re-executes
    // itself with --argv-echo and compares the child's own argv.
    // ------------------------------------------------------------------
    void TestRunProcessCaptureArgvRoundTrip() {
        wchar_t self[MAX_PATH] = {0};
        const DWORD got = ::GetModuleFileNameW(nullptr, self, MAX_PATH);
        CHECK(0 != got && got < MAX_PATH);
        if (0 == got || got >= MAX_PATH) {
            return;
        }
        const std::wstring exe(self, got);

        struct Case {
            std::wstring arg;
            const char* label;
        };
        const Case cases[] = {
            {L"plain", "plain"},
            {L"C:\\dir with space\\x.inf", "path with spaces"},
            {L"C:\\dir\\", "trailing backslash"},
            {L"C:\\dir\\\\", "two trailing backslashes"},
            {L"a\"b", "embedded quote"},
            {L"a\"b\\", "quote then trailing backslash"},
            {L"a\\\\\"b", "backslashes then quote"},
            {L"a\\\\\\\"b", "three backslashes then quote"},
            {L"", "empty argument"},
            {L"\u4e2d\u6587 path\\", "unicode then trailing backslash"},
        };
        for (const Case& c : cases) {
            std::string out;
            DWORD code = 1;
            const bool ok = vgww::driver::RunProcessCapture(
                exe, {L"--argv-echo", c.arg}, out, code, 20000);
            CHECK(ok);
            CHECK(code == 0);

            const int need = ::WideCharToMultiByte(
                CP_UTF8, 0, c.arg.c_str(), static_cast<int>(c.arg.size()),
                nullptr, 0, nullptr, nullptr);
            std::string utf8(static_cast<size_t>(need > 0 ? need : 0), '\0');
            if (need > 0) {
                ::WideCharToMultiByte(CP_UTF8, 0, c.arg.c_str(),
                                      static_cast<int>(c.arg.size()),
                                      utf8.data(), need, nullptr, nullptr);
            }
            const std::string want = "[2]" + utf8 + "\r\n";
            if (out != want) {
                std::fprintf(stderr,
                             "argv round-trip (%s): want [%s] got [%s]\n",
                             c.label, want.c_str(), out.c_str());
            }
            CHECK(out == want);
        }
    }

    // ------------------------------------------------------------------
    // batch268: the remaining RunProcessCapture contract that had no test:
    // exit-code propagation, stderr capture into the same buffer, the
    // timeout terminating a silent child, and the failure path leaving
    // exit_code untouched while clearing `output`.
    // ------------------------------------------------------------------
    void TestRunProcessCaptureContract() {
        wchar_t self[MAX_PATH] = {0};
        const DWORD got = ::GetModuleFileNameW(nullptr, self, MAX_PATH);
        CHECK(0 != got && got < MAX_PATH);
        if (0 == got || got >= MAX_PATH) {
            return;
        }
        const std::wstring exe(self, got);

        // Exit code reaches the caller.
        {
            std::string out;
            DWORD code = 0;
            CHECK(vgww::driver::RunProcessCapture(
                exe, {L"--exit", L"42"}, out, code, 20000));
            CHECK(code == 42);
            CHECK(out.empty());
        }

        // A non-zero code is still a successful capture (spawned=true).
        {
            std::string out;
            DWORD code = 0;
            CHECK(vgww::driver::RunProcessCapture(
                exe, {L"--exit", L"3"}, out, code, 20000));
            CHECK(code == 3);
        }

        // stderr lands in the same capture buffer as stdout.
        {
            std::string out;
            DWORD code = 0;
            CHECK(vgww::driver::RunProcessCapture(
                exe, {L"--stderr"}, out, code, 20000));
            CHECK(code == 0);
            CHECK(out.find("STDERR-BODY") != std::string::npos);
        }

        // A child that never exits is terminated at the deadline. The
        // observable side effect is the process itself: the child reports
        // its pid on stdout first, and after the call returns that pid must
        // already be dead. (Without TerminateProcess the child keeps
        // sleeping; merely returning early is not proof it was killed.)
        {
            std::string out;
            DWORD code = 0;
            const ULONGLONG t0 = ::GetTickCount64();
            const bool ok = vgww::driver::RunProcessCapture(
                exe, {L"--sleep-pid", L"20000"}, out, code, 1200);
            const ULONGLONG elapsed = ::GetTickCount64() - t0;
            CHECK(ok);
            CHECK(code != 0);
            CHECK(elapsed < 8000);

            const size_t pid_pos = out.find("PID=");
            CHECK(pid_pos != std::string::npos);
            if (pid_pos != std::string::npos) {
                const DWORD pid = static_cast<DWORD>(
                    std::strtoul(out.c_str() + pid_pos + 4, nullptr, 10));
                CHECK(pid != 0);
                // batch309: the child is dead and RunProcessCapture already
                // closed its handle, so the kernel may have reclaimed the
                // process object by now - OpenProcess then fails with
                // ERROR_INVALID_PARAMETER. That is the STRONGEST proof the
                // child is gone, not a failure; only an unexpected error
                // means the probe itself could not conclude. (The old
                // CHECK(nullptr != child) passed only while the object was
                // still alive; the ASan build's slower parent exposed it.)
                HANDLE child = ::OpenProcess(SYNCHRONIZE, FALSE, pid);
                if (nullptr == child) {
                    CHECK(ERROR_INVALID_PARAMETER == ::GetLastError());
                } else {
                    const DWORD alive = ::WaitForSingleObject(child, 2000);
                    ::CloseHandle(child);
                    CHECK(WAIT_OBJECT_0 == alive);  // already gone
                }
            }
        }

        // Spawn failure: returns false, clears `output`, and leaves
        // `exit_code` at whatever the caller had (never fabricates a 0).
        {
            std::string out = "stale";
            DWORD code = 7;
            const bool ok = vgww::driver::RunProcessCapture(
                L"C:\\definitely\\missing\\vgww-tool.exe", {L"x"}, out, code,
                3000);
            CHECK(!ok);
            CHECK(out.empty());
            CHECK(code == 7);
        }
    }

}  // namespace

int main(int argc, char** argv) {
    // batch268 child mode: re-executed by TestRunProcessCapture* so the
    // test can observe the argv the kernel actually delivered. Kept ahead
    // of every test so a child run never recurses into the suite.
    if (argc > 1) {
        const std::string mode(argv[1]);
        if (mode == "--argv-echo") {
            // Re-split the REAL command line with CommandLineToArgvW: the
            // MSVC CRT converts argv through the ANSI code page, which
            // cannot round-trip non-ASCII paths. CommandLineToArgvW returns
            // UTF-16, so the UTF-8 comparison in the parent is exact.
            int wide_argc = 0;
            LPWSTR* wide_argv =
                ::CommandLineToArgvW(::GetCommandLineW(), &wide_argc);
            if (nullptr == wide_argv) {
                return 1;
            }
            for (int i = 2; i < wide_argc; ++i) {
                const std::wstring a(wide_argv[i]);
                const int need = ::WideCharToMultiByte(
                    CP_UTF8, 0, a.c_str(), static_cast<int>(a.size()),
                    nullptr, 0, nullptr, nullptr);
                std::string u(static_cast<size_t>(need > 0 ? need : 0), '\0');
                if (need > 0) {
                    ::WideCharToMultiByte(CP_UTF8, 0, a.c_str(),
                                          static_cast<int>(a.size()),
                                          u.data(), need, nullptr, nullptr);
                }
                std::printf("[%d]%s\n", i, u.c_str());
            }
            ::LocalFree(wide_argv);
            return 0;
        }
        if (mode == "--exit" && argc > 2) {
            return std::atoi(argv[2]);
        }
        if (mode == "--stderr") {
            std::fputs("STDERR-BODY\n", stderr);
            return 0;
        }
        if (mode == "--sleep" && argc > 2) {
            ::Sleep(static_cast<DWORD>(std::atoi(argv[2])));
            return 0;
        }
        if (mode == "--sleep-pid" && argc > 2) {
            // Report the pid BEFORE sleeping so the parent can prove the
            // process is dead after a timed-out capture returns.
            std::printf("PID=%lu\n",
                        static_cast<unsigned long>(::GetCurrentProcessId()));
            std::fflush(stdout);
            ::Sleep(static_cast<DWORD>(std::atoi(argv[2])));
            return 0;
        }
    }

    RUN(TestFaultClassify);
    RUN(TestLocatePayload);
    RUN(TestParsePnputilOem);
    RUN(TestBuildDriverArgs);
    RUN(TestComponentMatrix);
    RUN(TestInstallPayloadGate);
    RUN(TestUninstallWiring);
    RUN(TestUninstallDeleteArgs);
    RUN(TestInstallWiringPnputilFirst);
    RUN(TestComponentMatrixExtended);
    RUN(TestInstallRollbackAsserted);
    RUN(TestRollbackFailVariants);
    RUN(TestUninstallFailureVariants);
    RUN(TestParsePlural);
    RUN(TestDiffNewOems);
    RUN(TestInstallReportIO);
    RUN(TestUninstallOemMissingCleans);
    RUN(TestInstallSuccessFullHeadless);
    RUN(TestUninstallFullCleanRecorder);
    RUN(TestGrantOnlyNoPnputil);
    RUN(TestB119SourcesAreEnglishOnly);
    RUN(TestRunProcessCaptureArgvRoundTrip);
    RUN(TestRunProcessCaptureContract);

    if (0 == g_failures) {
        std::puts("test_driver_installer: ALL PASS");
        return 0;
    }
    std::fprintf(stderr, "test_driver_installer: %d FAILURES\n", g_failures);
    return 1;
}
