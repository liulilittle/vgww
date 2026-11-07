// ============================================================================
// test_ndisrd_live.cpp - Minimal live-driver probe (manual run, not ctest).
//
// Isolates the ndisrd call sequence Open -> Enumerate -> SetMode -> Read to
// pinpoint which IOCTL returns ERROR_INVALID_PARAMETER (87) inside the full
// dataplane. Run from build output dir with a live ndisrd driver installed.
// ============================================================================
#include "driver/ndisrd_client.h"

#include <winsock2.h>
#include <windows.h>

#include <iostream>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

int main() {
    // Two full rounds: Open -> SetMode -> ArmRx -> Send -> child-thread Read.
    // Round 2 replicates vgww's pre-probe + Dataplane::StartAll sequence
    // (the first client is destroyed before the second opens).
    for (int round = 1; round <= 2; ++round) {
        std::cout << "=== round " << round << " ===\n";
        std::string error;
        auto client = vgww::driver::NdisrdClient::Open(error);
        if (!client) {
            std::cout << "Open failed: " << error << "\n";
            return 1;
        }
        const vgww::driver::AdapterEntry* adapter = client->FindAdapter(std::wstring(L"NIC 1"));
        if (nullptr == adapter) {
            std::cout << "FindAdapter failed\n";
            return 1;
        }
        if (!client->SetAdapterMode(*adapter,
                                    vgww::driver::kRecvTunnel | vgww::driver::kSentTunnel |
                                        vgww::driver::kFilterDirect,
                                    error)) {
            std::cout << "SetAdapterMode failed: " << error << "\n";
            return 1;
        }
        HANDLE evt = ::CreateEventW(nullptr, FALSE, FALSE, nullptr);
        if (!client->ArmRxEvent(*adapter, evt, error)) {
            std::cout << "ArmRxEvent failed: " << error << "\n";
            return 1;
        }
        std::vector<INTERMEDIATE_BUFFER> boot(1);
        std::memset(&boot[0], 0, sizeof(INTERMEDIATE_BUFFER));
        boot[0].m_dwDeviceFlags = PACKET_FLAG_ON_SEND;
        std::string send_err;
        client->SendPacketsToAdapter(adapter->handle, boot.data(), 1, send_err);

        std::vector<INTERMEDIATE_BUFFER> ib(32);
        std::thread reader([&]() {
            for (int r = 0; r < 2; ++r) {
                DWORD wait = ::WaitForSingleObject(evt, 1000);
                std::cout << "wait=" << wait << " ";
                uint32_t n = client->ReadPackets(adapter->handle, ib.data(), 32, error);
                if (0 == n && !error.empty()) {
                    std::cout << "ReadPackets FAILED: " << error << "\n";
                    error.clear();
                } else {
                    std::cout << "ReadPackets n=" << n << "\n";
                }
            }
        });
        reader.join();
        ::CloseHandle(evt);
        // client destroyed here (CloseHandle) exactly like vgww's pre-probe.
    }
    std::cout << "probe done\n";
    return 0;
}
