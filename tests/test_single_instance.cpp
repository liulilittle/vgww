// ============================================================================
// test_single_instance.cpp - batch23: the named-kernel-EVENT single-instance
// gate (was a named mutex). A first launch creates the event (Primary role);
// a second launch opens and signals it (Secondary role) and exits 0; the
// primary's watcher thread turns the signal into a window activation.
//
// These tests exercise the handle-level contract only (no window involved),
// so they run headless in the automation pipeline. A per-run unique name
// keeps them from colliding with a real running vgww or a parallel process.
// ============================================================================
#include <windows.h>

#include <cstdio>
#include <string>

#include "ui/single_instance.h"

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

    using namespace vgww::ui;

    std::wstring UniqueName(const wchar_t* tag) {
        return std::wstring(L"VGWW.SingleInstance.test.") + tag + L"." +
               std::to_wstring(::GetCurrentProcessId());
    }

    // The event's security descriptor is built from the SDDL constant. It must
    // convert and be attached to the SECURITY_ATTRIBUTES correctly.
    void TestSddlBuildsSecurityDescriptor() {
        SECURITY_ATTRIBUTES sa{};
        PSECURITY_DESCRIPTOR sd = nullptr;
        CHECK(MakeInstanceEventSecurity(sa, &sd));
        CHECK(sd != nullptr);
        CHECK(sa.nLength == sizeof(SECURITY_ATTRIBUTES));
        CHECK(sa.lpSecurityDescriptor == sd);
        CHECK(sa.bInheritHandle == FALSE);
        if (sd != nullptr) {
            ::LocalFree(sd);
        }
    }

    // First claim creates the event (Primary); a second claim from the same
    // process opens + signals it (Secondary) and never owns a handle.
    void TestPrimaryThenSecondary() {
        const std::wstring name = UniqueName(L"ab");
        InstanceClaim a = ClaimSingleInstance(name.c_str());
        CHECK(a.role == InstanceRole::Primary);
        CHECK(a.event != nullptr);

        InstanceClaim b = ClaimSingleInstance(name.c_str());
        CHECK(b.role == InstanceRole::Secondary);
        CHECK(b.signalled);
        CHECK(b.event == nullptr);  // the secondary never owns a handle

        // The secondary's signal is latched in the auto-reset event: an
        // immediate wait consumes it...
        CHECK(::WaitForSingleObject(a.event, 1000) == WAIT_OBJECT_0);
        // ...and the event is unsignalled again afterwards.
        CHECK(::WaitForSingleObject(a.event, 0) == WAIT_TIMEOUT);

        if (a.event != nullptr) {
            ::CloseHandle(a.event);
        }
    }

    // Once the last handle closes, the named object is destroyed: a fresh
    // claim becomes Primary again (the "Open fails -> become first instance"
    // branch).
    void TestLastHandleCloseResetsToPrimary() {
        const std::wstring name = UniqueName(L"reset");
        InstanceClaim a = ClaimSingleInstance(name.c_str());
        CHECK(a.role == InstanceRole::Primary);
        if (a.event != nullptr) {
            ::CloseHandle(a.event);
        }
        InstanceClaim again = ClaimSingleInstance(name.c_str());
        CHECK(again.role == InstanceRole::Primary);
        CHECK(again.event != nullptr);
        if (again.event != nullptr) {
            ::CloseHandle(again.event);
        }
    }

    // Idempotent double init: claiming repeatedly while the primary handle is
    // held always yields Secondary + a signal, never a second primary.
    void TestIdempotentDoubleInit() {
        const std::wstring name = UniqueName(L"idem");
        InstanceClaim p = ClaimSingleInstance(name.c_str());
        CHECK(p.role == InstanceRole::Primary);
        for (int i = 0; i < 3; ++i) {
            InstanceClaim s = ClaimSingleInstance(name.c_str());
            CHECK(s.role == InstanceRole::Secondary);
            CHECK(s.signalled);
        }
        if (p.event != nullptr) {
            (void)::WaitForSingleObject(p.event, 0);  // drain latched signals
            ::CloseHandle(p.event);
        }
    }


    // batch246: the out_sd==nullptr guard. A caller that forgets the out
    // parameter must get false instead of writing through a null pointer.
    // (Mutation A1 removed the guard and the test process crashed, which is
    // how this gap was found: it had zero coverage before.)
    void TestNullOutDescriptorRejected() {
        SECURITY_ATTRIBUTES sa{};
        CHECK(!MakeInstanceEventSecurity(sa, nullptr));
    }

    // batch246: the CreateEventW "already exists" branch is UNREACHABLE from
    // a single process - the event SDDL grants only EVENT_MODIFY_STATE|
    // SYNCHRONIZE, so the second CreateEventW (which asks for
    // EVENT_ALL_ACCESS) fails with ERROR_ACCESS_DENIED and the code falls
    // through to the OpenEventW path. Measured: first CreateEventW err=0,
    // second err=5. The OpenEventW path is what a test can exercise, and it
    // must CLOSE the handle it opens.
    void TestOpenEventPathClosesItsHandle() {
        DWORD before = 0;
        CHECK(::GetProcessHandleCount(::GetCurrentProcess(), &before) != 0);
        const std::wstring name = UniqueName(L"leak");
        InstanceClaim p = ClaimSingleInstance(name.c_str());
        CHECK(p.role == InstanceRole::Primary);
        for (int i = 0; i < 64; ++i) {
            InstanceClaim s = ClaimSingleInstance(name.c_str());
            CHECK(s.role == InstanceRole::Secondary);
            CHECK(s.signalled);
        }
        DWORD after = 0;
        CHECK(::GetProcessHandleCount(::GetCurrentProcess(), &after) != 0);
        CHECK(after <= before + 8);
        if (p.event != nullptr) {
            ::CloseHandle(p.event);
        }
    }
}  // namespace

int main() {
    TestSddlBuildsSecurityDescriptor();
    TestPrimaryThenSecondary();
    TestLastHandleCloseResetsToPrimary();
    TestIdempotentDoubleInit();
    TestNullOutDescriptorRejected();
    TestOpenEventPathClosesItsHandle();
    if (0 == g_failures) {
        std::puts("test_single_instance: ALL PASS");
        return 0;
    }
    std::fprintf(stderr, "test_single_instance: %d FAILURES\n", g_failures);
    return 1;
}
