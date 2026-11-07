// ============================================================================
// idriver_client.h - Driver boundary abstraction.
//
// The data plane talks to the packet source ONLY through this interface
// (backtesting principle B1: simulate boundaries, not business logic).
// Production binds NdisrdClient (WinpkFilter); tests bind an in-memory
// fake that replays scripted frames and captures everything VGWW emits -
// the entire pipeline then runs VERBATIM without any kernel driver.
// ============================================================================
#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>

struct _INTERMEDIATE_BUFFER;
typedef struct _INTERMEDIATE_BUFFER INTERMEDIATE_BUFFER;

namespace vgww {
    namespace driver {

        /// Adapter mode flags (mirror of MSTCP_FLAG_* from Common.h).
        enum AdapterModeFlags : uint32_t {
            kSentTunnel = 0x00000001,       ///< intercept frames leaving MSTCP
            kRecvTunnel = 0x00000002,       ///< consume inbound frames before MSTCP
            kSentListen = 0x00000004,       ///< observe outbound, pass through
            kRecvListen = 0x00000008,       ///< observe inbound copy, pass through
            kFilterDirect = 0x00000010,     ///< filter promiscuous-mode frames
            kLoopbackFilter = 0x00000020,   ///< pass loopback frames up
            kLoopbackBlock = 0x00000040,    ///< silently drop loopback frames
        };

        /// One IPv4 address assigned to an adapter (network byte order, the
        /// same inet_addr convention core::FormatIpv4 expects).
        struct AdapterIpv4Address {
            uint32_t address = 0;
            uint8_t prefix_len = 0;
        };

        /// One bound TCP/IP adapter as reported by the driver.
        struct AdapterEntry {
            std::wstring name;                  ///< internal device name (GUID string)
            /// Friendly name from GetAdaptersAddresses (e.g. "Ethernet", or
            /// its localized zh-CN equivalent); empty when unavailable -
            /// matching then falls back to the device path only.
            std::wstring friendly_name;
            void* handle = nullptr;             ///< driver adapter handle
            std::array<uint8_t, 6> current_address{};  ///< configured L2 address
            uint16_t mtu = 0;
            /// Link diagnostics, backfilled from GetAdaptersAddresses. They
            /// default to "usable" so an injected/fake adapter is unchanged
            /// when it does not populate them (fail-open for tests).
            bool is_up = true;             ///< IF_OPER_STATUS == IfOperStatusUp
            bool media_connected = true;   ///< MediaConnectState == Connected
            std::vector<AdapterIpv4Address> ipv4;  ///< unicast IPv4 addresses
            /// batch33 C: the real connection type (IP_ADAPTER_ADDRESSES::
            /// IfType) and the unicast IPv6 list. Both are backfilled from
            /// GetAdaptersAddresses; a failed enumeration leaves them at their
            /// defaults (0 / empty) and the UI must then say "other"/"none"
            /// rather than invent a value.
            uint32_t if_type = 0;
            std::vector<std::string> ipv6;  ///< unicast IPv6, UTF-8, no %scope
        };

        class IDriverClient {
        public:
            virtual ~IDriverClient() = default;

            virtual const std::vector<AdapterEntry>& Adapters() const noexcept = 0;

            /// Selects the adapter matching `hint`: the device path is matched
            /// as a case-insensitive substring; the adapter friendly name
            /// (when enumerated) is matched exactly, case-insensitively, with
            /// localized Ethernet aliases (the zh-CN / zh-TW / ja-JP / ko-KR
            /// localized forms of "Ethernet") and a strict ASCII " N"
            /// instance suffix. An empty
            /// hint picks the first adapter. When the hint matches more than
            /// one adapter, a single CONNECTED match wins (the USB/Ethernet
            /// trap: a stale disconnected NIC with the same friendly name);
            /// only two or more connected matches stay ambiguous and callers
            /// must reject them instead of silently binding an arbitrary NIC.
            virtual const AdapterEntry* FindAdapter(
                const std::wstring& hint,
                bool* out_ambiguous = nullptr) const noexcept = 0;

            virtual bool SetAdapterMode(const AdapterEntry& adapter, uint32_t flags,
                                        std::string& error) = 0;

            /// Sets the adapter hardware packet filter (NDIS
            /// OID_GEN_CURRENT_PACKET_FILTER, e.g. NDIS_PACKET_TYPE_PROMISCUOUS).
            /// Save/restore semantics belong to the CALLER: read the previous
            /// value with GetHwPacketFilter before changing it and restore it
            /// on shutdown.
            virtual bool SetHwPacketFilter(const AdapterEntry& adapter,
                                           uint32_t filter,
                                           std::string& error) = 0;

            /// Reads the adapter hardware packet filter into `filter`.
            virtual bool GetHwPacketFilter(const AdapterEntry& adapter,
                                           uint32_t& filter,
                                           std::string& error) = 0;

            /// Arms the kernel event signalled when packets are queued.
            virtual bool ArmRxEvent(const AdapterEntry& adapter, void* event_handle,
                                    std::string& error) = 0;

            /// Batch-reads up to `max_packets` frames from `adapter_handle` into
            /// `buffers`.
            virtual uint32_t ReadPackets(void* adapter_handle,
                                         INTERMEDIATE_BUFFER* buffers,
                                         uint32_t max_packets, std::string& error) = 0;

            virtual bool SendPacketsToAdapter(void* adapter_handle,
                                              INTERMEDIATE_BUFFER* buffers,
                                              uint32_t count, std::string& error) = 0;

            virtual bool SendPacketsToMstcp(void* adapter_handle,
                                            INTERMEDIATE_BUFFER* buffers,
                                            uint32_t count, std::string& error) = 0;

            virtual bool FlushAdapterQueue(const AdapterEntry& adapter,
                                           std::string& error) = 0;

            virtual bool ResetAdapterMode(const AdapterEntry& adapter,
                                          std::string& error) = 0;
        };

    }  // namespace driver
}  // namespace vgww
