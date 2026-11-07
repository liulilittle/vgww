// ============================================================================
// ndisrd_client.h - Thin user-mode client for the WinpkFilter (ndisrd)
// kernel driver, talking to \\.\Ndisrd via DeviceIoControl directly.
//
// Why a hand-rolled client instead of ndisapi.dll:
//   * native x64 with zero DLL/import-lib dependency (no arch mismatch),
//   * explicit dependency surface for an industrial deliverable,
//   * batch read/write paths (ETH_M_REQUEST) without legacy baggage.
//
// Wire structures come from third_party/ndisapi/Common.h (MIT, NT Kernel).
//
// Threading contract (see docs/en/architecture.md):
//   * ONE thread owns ReadPackets/SendPackets calls per adapter handle
//     (the RX/TX thread). Other threads may only use Flush/CancelIoEx.
// ============================================================================
#pragma once

// Order matters: ws2ipdef defines IN6_ADDR required by Common.h.
#include <winsock2.h>
#include <ws2ipdef.h>
#include <windows.h>

#include "ndisapi/Common.h"
#include "driver/idriver_client.h"

#include <memory>
#include <string>
#include <vector>

namespace vgww {
    namespace driver {

        /// Pure adapter-name matcher used by FindAdapter (defect #2): a hint
        /// may be a friendly name, a GUID fragment, or a full \DEVICE\{GUID}
        /// path. `resolved` is the friendly-name -> \DEVICE\{GUID} path when
        /// the caller could resolve it (empty otherwise). Returns the index of
        /// the first matching entry, -1 when nothing matches; `*ambiguous` is
        /// set when the hint matched more than one entry.
        int MatchAdapterEntry(const std::vector<AdapterEntry>& adapters,
                              const std::wstring& hint,
                              const std::wstring& resolved, bool* ambiguous);

        /// Widens an adapter hint from its byte representation to UTF-16.
        /// Config files / the WebUI deliver UTF-8; console argv (main())
        /// delivers ACP bytes. Tries CP_UTF8 strictly first, then CP_ACP,
        /// then falls back to a byte-wise widening so a hint is never
        /// dropped (G-5 F1).
        std::wstring WidenAdapterHint(const std::string& hint);

        /// Pure friendly-name equivalence test (G-5 F3, D3/D4): normalized
        /// case-insensitive equality, localized Ethernet aliases (the
        /// zh-CN / zh-TW / ja-JP / ko-KR forms of "Ethernet") and a strict
        /// ASCII " N" instance suffix ("Ethernet 2" == localized "Ethernet
        /// 2", "Ethernet" != localized "Ethernet 2"). Equal-value only -
        /// never substring (vEthernet trap).
        bool FriendlyNameMatches(const std::wstring& hint,
                                 const std::wstring& friendly_name);

        /// Renders "<friendly> => <GUID-suffix>" lines (driver enumeration
        /// exposes \DEVICE\{GUID}, which users cannot map back to their NIC).
        std::string FormatAdapterTable(
            const std::vector<AdapterEntry>& adapters,
            const std::vector<std::wstring>& friendly);

        /// Re-reads friendly name, link state and IPv4 addresses from
        /// GetAdaptersAddresses for `adapters` (device-path match). Safe to
        /// call at any time; a failed GAA pass leaves the entries untouched
        /// (fail-open, so a fake/injected adapter is never clobbered).
        void RefreshAdapterStates(std::vector<AdapterEntry>& adapters);


        /// Production IDriverClient bound to the real \\.\Ndisrd device.
        class NdisrdClient final : public IDriverClient {
        public:
            /// Opens \\.\Ndisrd and enumerates bound adapters. Returns null on
            /// failure with `error` describing the reason (driver missing,
            /// access denied - admin rights required).
            static std::unique_ptr<NdisrdClient> Open(std::string& error);

            ~NdisrdClient() override;

            NdisrdClient(const NdisrdClient&) = delete;
            NdisrdClient& operator=(const NdisrdClient&) = delete;

            // ----- IDriverClient ---------------------------------------------
            const std::vector<AdapterEntry>& Adapters() const noexcept override {
                return adapters_;
            }
            const AdapterEntry* FindAdapter(
                const std::wstring& hint,
                bool* out_ambiguous = nullptr) const noexcept override;
            bool SetAdapterMode(const AdapterEntry& adapter, uint32_t flags,
                                std::string& error) override;
            bool SetHwPacketFilter(const AdapterEntry& adapter, uint32_t filter,
                                   std::string& error) override;
            bool GetHwPacketFilter(const AdapterEntry& adapter, uint32_t& filter,
                                   std::string& error) override;
            bool ArmRxEvent(const AdapterEntry& adapter, void* event_handle,
                            std::string& error) override;
            uint32_t ReadPackets(void* adapter_handle, INTERMEDIATE_BUFFER* buffers,
                                 uint32_t max_packets,
                                 std::string& error) override;
            bool SendPacketsToAdapter(void* adapter_handle,
                                      INTERMEDIATE_BUFFER* buffers, uint32_t count,
                                      std::string& error) override;
            bool SendPacketsToMstcp(void* adapter_handle,
                                    INTERMEDIATE_BUFFER* buffers, uint32_t count,
                                    std::string& error) override;
            bool FlushAdapterQueue(const AdapterEntry& adapter,
                                   std::string& error) override;
            bool ResetAdapterMode(const AdapterEntry& adapter,
                                  std::string& error) override;

        private:
            NdisrdClient() noexcept = default;

            bool EnumerateAdapters(std::string& error);

            void* device_ = nullptr;   // \\.\Ndisrd handle
            std::vector<AdapterEntry> adapters_;
        };

    }  // namespace driver
}  // namespace vgww
