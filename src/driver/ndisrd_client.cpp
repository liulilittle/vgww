// ============================================================================
// ndisrd_client.cpp - DeviceIoControl implementation of the ndisrd client.
// ============================================================================
#include "driver/ndisrd_client.h"

// winsock2/ws2ipdef must precede windows.h: Common.h references IN6_ADDR.
#include <winsock2.h>
#include <ws2tcpip.h>
#include <ws2ipdef.h>
#include <windows.h>
#include <iphlpapi.h>
#include <netioapi.h>

#include "ndisapi/Common.h"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstring>
#include <thread>
#include <vector>

namespace vgww {
    namespace driver {

        namespace {

            constexpr wchar_t kDeviceName[] = L"\\\\.\\Ndisrd";

            /// RAII guard for HANDLEs (1:1 open/close pairing).
            class HandleGuard final {
            public:
                explicit HandleGuard(HANDLE h) noexcept : handle_(h) {}
                ~HandleGuard() {
                    if (nullptr != handle_ && INVALID_HANDLE_VALUE != handle_) {
                        ::CloseHandle(handle_);
                    }
                }
                HandleGuard(const HandleGuard&) = delete;
                HandleGuard& operator=(const HandleGuard&) = delete;
                HANDLE Get() const noexcept { return handle_; }
                /// Relinquishes ownership without closing.
                HANDLE Release() noexcept {
                    HANDLE h = handle_;
                    handle_ = nullptr;
                    return h;
                }

            private:
                HANDLE handle_;
            };

            /// Sends a buffered IOCTL; returns true with `bytes` set on success.
            bool DoIoctl(HANDLE device, DWORD code, void* in, DWORD in_size,
                         void* out, DWORD out_size, DWORD& bytes,
                         std::string& error) {
                if (!::DeviceIoControl(device, code, in, in_size, out, out_size,
                                       &bytes, nullptr)) {
                    error = "DeviceIoControl(" + std::to_string(code) +
                            ") failed: " + std::to_string(::GetLastError());
                    return false;
                }
                return true;
            }

            std::string LastErrorText(const char* what) {
                return std::string(what) + " failed: " + std::to_string(::GetLastError());
            }

            /// NDIS OID request used by the official SetHwPacketFilter /
            /// GetHwPacketFilter API (WinpkFilter 3.6.2.1 has no dedicated
            /// IOCTL): PACKET_OID_DATA carrying OID_GEN_CURRENT_PACKET_FILTER,
            /// wrapped by IOCTL_NDISRD_NDIS_SET_REQUEST / _GET_REQUEST.
            /// See third_party/winpkfilter/sdk/sdk-notes.md.
            bool OidFilterRequest(HANDLE device, HANDLE adapter, bool set,
                                  uint32_t& filter, std::string& error) {
                alignas(PACKET_OID_DATA) uint8_t
                    buffer[sizeof(PACKET_OID_DATA) - 1 + sizeof(uint32_t)]{};
                auto* oid = reinterpret_cast<PACKET_OID_DATA*>(buffer);
                oid->hAdapterHandle = adapter;
                oid->Oid = OID_GEN_CURRENT_PACKET_FILTER;
                oid->Length = sizeof(uint32_t);
                if (set) {
                    std::memcpy(oid->Data, &filter, sizeof(uint32_t));
                }
                DWORD bytes = 0;
                const DWORD code =
                    set ? static_cast<DWORD>(IOCTL_NDISRD_NDIS_SET_REQUEST)
                        : static_cast<DWORD>(IOCTL_NDISRD_NDIS_GET_REQUEST);
                if (!DoIoctl(device, code, oid, sizeof(buffer), oid, sizeof(buffer),
                             bytes, error)) {
                    error = std::string(set ? "SetHwPacketFilter" : "GetHwPacketFilter") +
                            "(OID_GEN_CURRENT_PACKET_FILTER 0x0001010E) failed: " + error;
                    return false;
                }
                if (!set) {
                    std::memcpy(&filter, oid->Data, sizeof(uint32_t));
                }
                return true;
            }

            /// F3 normalize: trim outer [ \t], collapse inner [ \t] runs to a
            /// single ASCII space, ASCII-lowercase (never locale-sensitive).
            std::wstring NormalizeAdapterName(const std::wstring& in) {
                std::wstring out;
                out.reserve(in.size());
                bool pending_space = false;
                for (const wchar_t c : in) {
                    if (c == L' ' || c == L'\t') {
                        if (!out.empty()) {
                            pending_space = true;
                        }
                        continue;
                    }
                    if (pending_space) {
                        out.push_back(L' ');
                        pending_space = false;
                    }
                    out.push_back(c >= L'A' && c <= L'Z'
                                      ? static_cast<wchar_t>(c - L'A' + L'a')
                                      : c);
                }
                return out;  // a trailing pending_space is never flushed
            }

            /// F3 split: a trailing " <ASCII digits>" is the NIC instance
            /// suffix. D4 keeps it strict: no full-width digits, no missing
            /// space, no leading-zero normalization ("02" never equals "2").
            void SplitAdapterSuffix(const std::wstring& x, std::wstring& base,
                                    std::wstring& suffix) {
                base = x;
                suffix.clear();
                const size_t end = x.size();
                size_t beg = end;
                while (beg > 0 && x[beg - 1] >= L'0' && x[beg - 1] <= L'9') {
                    --beg;
                }
                if (beg == end || beg == 0 || x[beg - 1] != L' ') {
                    return;  // no digits, or digits not preceded by one space
                }
                base.assign(x, 0, beg - 1);
                suffix.assign(x, beg, end - beg);
            }

            /// F3 alias table: localized Windows names for the built-in
            /// Ethernet adapter template. Equal-value only (D3: never
            /// substring). Canonical value: "ethernet".
            ///   * zh-CN form    - verified on the audit host
            ///                  (Get-NetAdapter).
            ///   * zh-TW form    - candidate (Windows zh-TW template).
            ///   * ja-JP form    - candidate (Windows ja-JP template).
            ///   * ko-KR form    - candidate (Windows ko-KR template).
            const std::wstring* AliasCanonical(const std::wstring& base) {
                static const std::wstring kEthernet = L"ethernet";
                if (base == L"\u4EE5\u592A\u7F51" ||      // zh-CN form
                    base == L"\u4E59\u592A\u7DB2\u8DEF" ||  // zh-TW form
                    base == L"\u30A4\u30FC\u30B5\u30CD\u30C3\u30C8" ||  // ja-JP form
                    base == L"\uC774\uB354\uB137" ||        // ko-KR form
                    base == L"ethernet") {
                    return &kEthernet;
                }
                return nullptr;
            }

            /// Last path segment of a device name ("\DEVICE\{GUID}" -> "{GUID}").
            std::wstring AdapterNameSuffix(const std::wstring& path) {
                const size_t slash = path.find_last_of(L'\\');
                return (std::wstring::npos == slash) ? path : path.substr(slash + 1);
            }

            /// F2 + batch24 P2-9b: backfills friendly_name, link state and
            /// IPv4 addresses from GetAdaptersAddresses, matching on the GUID
            /// suffix (the driver enumerates "\DEVICE\{GUID}", GAA reports
            /// "{GUID}"). One GAA call per enumeration; on failure every entry
            /// is left untouched (fail-open: matching still works and a fake
            /// adapter is never marked down just because GAA failed).
            void BackfillFriendlyNames(std::vector<AdapterEntry>& adapters) {
                if (adapters.empty()) {
                    return;
                }
                ULONG size = 16 * 1024;
                std::vector<uint8_t> buf(size);
                auto* aa = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data());
                const ULONG flags = GAA_FLAG_SKIP_ANYCAST |
                                    GAA_FLAG_SKIP_MULTICAST |
                                    GAA_FLAG_SKIP_DNS_SERVER;
                ULONG err = ::GetAdaptersAddresses(AF_UNSPEC, flags, nullptr, aa,
                                                   &size);
                if (ERROR_BUFFER_OVERFLOW == err) {
                    buf.resize(size);
                    aa = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data());
                    err = ::GetAdaptersAddresses(AF_UNSPEC, flags, nullptr, aa,
                                                 &size);
                }
                if (NO_ERROR != err) {
                    return;
                }
                for (AdapterEntry& entry : adapters) {
                    const std::wstring want = AdapterNameSuffix(entry.name);
                    for (const IP_ADAPTER_ADDRESSES* cur = aa; nullptr != cur;
                         cur = cur->Next) {
                        if (nullptr == cur->FriendlyName ||
                            nullptr == cur->AdapterName) {
                            continue;
                        }
                        const std::wstring ansi(
                            cur->AdapterName,
                            cur->AdapterName + strlen(cur->AdapterName));
                        if (0 != _wcsicmp(AdapterNameSuffix(ansi).c_str(),
                                          want.c_str())) {
                            continue;
                        }
                        entry.friendly_name = cur->FriendlyName;
                        entry.is_up =
                            (IfOperStatusUp == cur->OperStatus);
                        // GetAdaptersAddresses has no media-connect field;
                        // GetIfEntry2 on the same interface supplies it. On a
                        // query failure fall back to OperStatus (never mark a
                        // NIC down just because the extra query failed).
                        MIB_IF_ROW2 row{};
                        row.InterfaceIndex = cur->IfIndex;
                        row.InterfaceLuid = cur->Luid;
                        entry.media_connected =
                            (NO_ERROR == ::GetIfEntry2(&row))
                                ? (MediaConnectStateConnected ==
                                   row.MediaConnectState)
                                : entry.is_up;
                        // batch33 C: the real connection type (IfType) so the
                        // UI can name Ethernet / Wi-Fi instead of guessing.
                        entry.if_type = cur->IfType;
                        entry.ipv4.clear();
                        entry.ipv6.clear();
                        for (const IP_ADAPTER_UNICAST_ADDRESS* unicast =
                                 cur->FirstUnicastAddress;
                             nullptr != unicast;
                             unicast = unicast->Next) {
                            if (nullptr == unicast->Address.lpSockaddr) {
                                continue;
                            }
                            const int family =
                                unicast->Address.lpSockaddr->sa_family;
                            if (AF_INET == family) {
                                const auto* sin =
                                    reinterpret_cast<const sockaddr_in*>(
                                        unicast->Address.lpSockaddr);
                                AdapterIpv4Address address;
                                address.address = sin->sin_addr.S_un.S_addr;
                                address.prefix_len =
                                    (unicast->OnLinkPrefixLength > 32)
                                        ? 32
                                        : static_cast<uint8_t>(
                                              unicast->OnLinkPrefixLength);
                                entry.ipv4.push_back(address);
                            } else if (AF_INET6 == family) {
                                // batch33 C: real unicast IPv6, text form.
                                // A formatting failure skips the address (it
                                // must never throw or fabricate a value).
                                const auto* sin6 =
                                    reinterpret_cast<const sockaddr_in6*>(
                                        unicast->Address.lpSockaddr);
                                wchar_t text[64] = {};
                                if (nullptr == ::InetNtopW(
                                                  AF_INET6, &sin6->sin6_addr,
                                                  text, 64)) {
                                    continue;
                                }
                                // Strip a scope suffix ("%12") if the API
                                // appended one: the UI shows a plain address.
                                std::wstring wide(text);
                                const auto pct = wide.find(L'%');
                                if (pct != std::wstring::npos) {
                                    wide.resize(pct);
                                }
                                // InetNtopW's IPv6 text is pure ASCII; encode
                                // it explicitly so the stored form is UTF-8
                                // (the same storage form as friendly_name).
                                std::string utf8(wide.size(), '\0');
                                const int written = ::WideCharToMultiByte(
                                    CP_UTF8, 0, wide.data(),
                                    static_cast<int>(wide.size()), utf8.data(),
                                    static_cast<int>(utf8.size()), nullptr,
                                    nullptr);
                                if (written <= 0) {
                                    continue;  // skip, never fabricate
                                }
                                utf8.resize(static_cast<std::size_t>(written));
                                if (!utf8.empty()) {
                                    entry.ipv6.push_back(std::move(utf8));
                                }
                            }
                        }
                        break;
                    }
                }
            }

            /// Maps a friendly adapter name ("Ethernet" or its localized
            /// zh-CN form) to its
            /// \DEVICE\{GUID} path via GetAdaptersAddresses. Config files use
            /// friendly names, but the ndisrd driver enumerates raw device
            /// paths - without this resolution "adapter": "Ethernet" never
            /// matches and the dataplane starts in degraded mode (rx=tx=0).
            /// Kept as FindAdapter's last-resort fallback (D7); returns an
            /// empty string when no interface matches.
            std::wstring ResolveFriendlyName(const std::wstring& hint) {
                ULONG size = 16 * 1024;
                std::vector<uint8_t> buf(size);
                auto* aa = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data());
                ULONG err = ::GetAdaptersAddresses(
                    AF_UNSPEC,
                    GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
                        GAA_FLAG_SKIP_DNS_SERVER,
                    nullptr, aa, &size);
                if (ERROR_BUFFER_OVERFLOW == err) {
                    buf.resize(size);
                    aa = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data());
                    err = ::GetAdaptersAddresses(
                        AF_UNSPEC,
                        GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
                            GAA_FLAG_SKIP_DNS_SERVER,
                        nullptr, aa, &size);
                }
                if (NO_ERROR != err) {
                    return L"";
                }
                for (const IP_ADAPTER_ADDRESSES* cur = aa; nullptr != cur;
                     cur = cur->Next) {
                    if (nullptr == cur->FriendlyName || nullptr == cur->AdapterName) {
                        continue;
                    }
                    if (FriendlyNameMatches(hint, cur->FriendlyName)) {
                        // AdapterName is ANSI "\DEVICE\{GUID}"; widen for match.
                        std::wstring wide(cur->AdapterName,
                                          cur->AdapterName + strlen(cur->AdapterName));
                        return wide;
                    }
                }
                return L"";
            }

        }  // namespace

        std::unique_ptr<NdisrdClient> NdisrdClient::Open(std::string& error) {
            HandleGuard device(::CreateFileW(kDeviceName, GENERIC_READ | GENERIC_WRITE,
                                             0, nullptr, OPEN_EXISTING, 0, nullptr));
            if (INVALID_HANDLE_VALUE == device.Get()) {
                const DWORD last = ::GetLastError();
                if (ERROR_FILE_NOT_FOUND == last || ERROR_PATH_NOT_FOUND == last) {
                    error = "ndisrd driver not installed (WinpkFilter missing?)";
                } else if (ERROR_ACCESS_DENIED == last) {
                    error = "access denied opening \\\\.\\Ndisrd - run as Administrator";
                } else {
                    error = "open \\\\.\\Ndisrd failed: " + std::to_string(last);
                }
                return nullptr;
            }

            // Transfer ownership into the client; keep a raw duplicate for use.
            auto client = std::unique_ptr<NdisrdClient>(new NdisrdClient());
            client->device_ = device.Release();  // client now owns the handle

            if (!client->EnumerateAdapters(error)) {
                return nullptr;
            }
            return client;
        }

        NdisrdClient::~NdisrdClient() {
            if (nullptr != device_) {
                ::CloseHandle(device_);
            }
        }

        bool NdisrdClient::EnumerateAdapters(std::string& error) {
            TCP_AdapterList list{};
            DWORD bytes = 0;
            if (!DoIoctl(device_, static_cast<DWORD>(IOCTL_NDISRD_GET_TCPIP_INTERFACES), &list,
                         sizeof(list), &list, sizeof(list), bytes, error)) {
                return false;
            }
            adapters_.clear();
            adapters_.reserve(list.m_nAdapterCount);
            for (DWORD i = 0; i < list.m_nAdapterCount && i < ADAPTER_LIST_SIZE; ++i) {
                AdapterEntry entry;
                // Names are ASCII GUID device paths; widen them for comparison.
                const char* src = reinterpret_cast<const char*>(&list.m_szAdapterNameList[i][0]);
                entry.name.assign(src, src + strnlen(src, ADAPTER_NAME_SIZE));
                entry.handle = list.m_nAdapterHandle[i];
                std::memcpy(entry.current_address.data(), &list.m_czCurrentAddress[i][0],
                            entry.current_address.size());
                entry.mtu = list.m_usMTU[i];
                adapters_.push_back(std::move(entry));
            }
            BackfillFriendlyNames(adapters_);
            return true;
        }

        const AdapterEntry* NdisrdClient::FindAdapter(const std::wstring& hint,
                                                  bool* out_ambiguous) const noexcept {
            // Fast path: device path + backfilled friendly names.
            // D7: the GetAdaptersAddresses resolution is a last resort, run
            // only when the friendly layer did not hit (net GAA drop).
            int idx = MatchAdapterEntry(adapters_, hint, std::wstring(),
                                        out_ambiguous);
            if (idx >= 0 || hint.empty()) {
                return idx < 0 ? nullptr : &adapters_[static_cast<size_t>(idx)];
            }
            const std::wstring resolved = ResolveFriendlyName(hint);
            if (resolved.empty()) {
                return nullptr;
            }
            idx = MatchAdapterEntry(adapters_, hint, resolved, out_ambiguous);
            return idx < 0 ? nullptr : &adapters_[static_cast<size_t>(idx)];
        }

        std::wstring WidenAdapterHint(const std::string& hint) {
            if (hint.empty()) {
                return std::wstring();
            }
            for (const UINT code_page : {CP_UTF8, CP_ACP}) {
                const UINT flags =
                    (CP_UTF8 == code_page) ? MB_ERR_INVALID_CHARS : 0;
                const int needed = ::MultiByteToWideChar(
                    code_page, flags, hint.c_str(),
                    static_cast<int>(hint.size()), nullptr, 0);
                if (needed <= 0) {
                    continue;
                }
                std::wstring out(static_cast<size_t>(needed), L'\0');
                ::MultiByteToWideChar(code_page, flags, hint.c_str(),
                                      static_cast<int>(hint.size()), out.data(),
                                      needed);
                return out;
            }
            return std::wstring(hint.begin(), hint.end());  // never worse
        }

        bool FriendlyNameMatches(const std::wstring& hint,
                                 const std::wstring& friendly_name) {
            const std::wstring hn = NormalizeAdapterName(hint);
            const std::wstring fn = NormalizeAdapterName(friendly_name);
            if (hn.empty() || fn.empty()) {
                return false;
            }
            if (hn == fn) {
                return true;
            }
            std::wstring hb, hs, fb, fs;
            SplitAdapterSuffix(hn, hb, hs);
            SplitAdapterSuffix(fn, fb, fs);
            if (hs != fs) {
                return false;
            }
            const std::wstring* ha = AliasCanonical(hb);
            const std::wstring* fa = AliasCanonical(fb);
            return nullptr != ha && nullptr != fa && *ha == *fa;
        }

        int MatchAdapterEntry(const std::vector<AdapterEntry>& adapters,
                              const std::wstring& hint,
                              const std::wstring& resolved, bool* ambiguous) {
            const bool empty_hint = hint.empty();
            const auto contains = [&empty_hint, &hint](const std::wstring& haystack) {
                if (empty_hint) {
                    return true;
                }
                const auto it = std::search(
                    haystack.begin(), haystack.end(), hint.begin(), hint.end(),
                    [](wchar_t a, wchar_t b) { return std::tolower(a) == std::tolower(b); });
                return it != haystack.end();
            };
            const auto norm = [](const std::wstring& path) {
                const size_t slash = path.find_last_of(L'\\');
                return (std::wstring::npos == slash) ? path : path.substr(slash + 1);
            };

            // A hit layer records both the first and the first CONNECTED
            // match: the USB/Ethernet trap is two NICs with the same friendly
            // name where the stale one is unplugged. One connected match wins
            // without an ambiguity rejection; two connected matches stay
            // ambiguous (D5 semantics preserved).
            struct LayerHits {
                int first = -1;
                int hits = 0;
                int connected_first = -1;
                int connected_hits = 0;
                void Add(int index, bool connected) {
                    if (first < 0) {
                        first = index;
                    }
                    ++hits;
                    if (connected) {
                        if (connected_first < 0) {
                            connected_first = index;
                        }
                        ++connected_hits;
                    }
                }
            };
            const auto link_connected = [](const AdapterEntry& entry) {
                return entry.is_up && entry.media_connected;
            };
            const auto pick_layer = [ambiguous](const LayerHits& layer) {
                if (layer.connected_hits == 1) {
                    if (nullptr != ambiguous) {
                        *ambiguous = false;
                    }
                    return layer.connected_first;
                }
                if (layer.connected_hits > 1) {
                    if (nullptr != ambiguous) {
                        *ambiguous = true;
                    }
                    return layer.connected_first;
                }
                if (nullptr != ambiguous) {
                    *ambiguous = layer.hits > 1;
                }
                return layer.first;
            };

            LayerHits device_hits;
            for (size_t i = 0; i < adapters.size(); ++i) {
                if (contains(adapters[i].name)) {
                    device_hits.Add(static_cast<int>(i),
                                    link_connected(adapters[i]));
                }
            }
            if (empty_hint) {
                if (nullptr != ambiguous) {
                    *ambiguous = false;
                }
                return device_hits.first;  // -1 when no adapters at all
            }
            if (device_hits.hits > 0) {
                return pick_layer(device_hits);
            }
            // Friendly-name layers (F3): raw exact (case-sensitive) >
            // normalized equality > localized alias equivalence. The highest
            // layer with any hit decides; a tie inside that layer prefers the
            // connected adapter (above).
            {
                LayerHits raw;
                LayerHits normalized;
                LayerHits alias;
                const std::wstring norm_hint = NormalizeAdapterName(hint);
                for (size_t i = 0; i < adapters.size(); ++i) {
                    const std::wstring& fn = adapters[i].friendly_name;
                    if (fn.empty()) {
                        continue;
                    }
                    const bool connected = link_connected(adapters[i]);
                    if (hint == fn) {
                        raw.Add(static_cast<int>(i), connected);
                        continue;
                    }
                    if (!norm_hint.empty() &&
                        norm_hint == NormalizeAdapterName(fn)) {
                        normalized.Add(static_cast<int>(i), connected);
                        continue;
                    }
                    if (FriendlyNameMatches(hint, fn)) {
                        alias.Add(static_cast<int>(i), connected);
                    }
                }
                for (const LayerHits* layer : {&raw, &normalized, &alias}) {
                    if (layer->hits > 0) {
                        return pick_layer(*layer);
                    }
                }
            }
            // Friendly-name fallback: the hint did not match any device path,
            // but it may be a friendly name already resolved (via
            // GetAdaptersAddresses) to a \DEVICE\{GUID} path. Compare on the
            // GUID suffix: AdaptterName there has no \DEVICE\ prefix while the
            // driver enumerates "\DEVICE\{GUID}".
            if (!resolved.empty()) {
                const std::wstring want = norm(resolved);
                for (size_t i = 0; i < adapters.size(); ++i) {
                    if (0 == _wcsicmp(norm(adapters[i].name).c_str(), want.c_str())) {
                        if (nullptr != ambiguous) {
                            *ambiguous = false;
                        }
                        return static_cast<int>(i);
                    }
                }
            }
            if (nullptr != ambiguous) {
                *ambiguous = false;
            }
            return -1;
        }

        std::string FormatAdapterTable(
            const std::vector<AdapterEntry>& adapters,
            const std::vector<std::wstring>& friendly) {
            const auto norm = [](const std::wstring& path) {
                const size_t slash = path.find_last_of(L'\\');
                return (std::wstring::npos == slash) ? path : path.substr(slash + 1);
            };
            const auto wide_to_utf8 = [](const std::wstring& in) {
                if (in.empty()) {
                    return std::string();
                }
                const int need = ::WideCharToMultiByte(
                    CP_UTF8, 0, in.data(), static_cast<int>(in.size()), nullptr, 0,
                    nullptr, nullptr);
                if (need <= 0) {
                    return std::string();
                }
                std::string out(static_cast<size_t>(need), '\0');
                ::WideCharToMultiByte(CP_UTF8, 0, in.data(),
                                      static_cast<int>(in.size()), out.data(), need,
                                      nullptr, nullptr);
                return out;
            };
            std::string out;
            for (size_t i = 0; i < adapters.size(); ++i) {
                const std::wstring guid = norm(adapters[i].name);
                const std::wstring label =
                    i < friendly.size()
                        ? friendly[i]
                        : std::wstring(adapters[i].name.begin(),
                                       adapters[i].name.end());
                out += wide_to_utf8(label) + " => " + wide_to_utf8(guid) + "\n";
            }
            return out;
        }

        void RefreshAdapterStates(std::vector<AdapterEntry>& adapters) {
            // Same pass EnumerateAdapters runs; kept public so the read-only
            // UI list reflects a NIC that was plugged/unplugged after Open().
            BackfillFriendlyNames(adapters);
        }

        bool NdisrdClient::SetAdapterMode(const AdapterEntry& adapter, uint32_t flags,
                                          std::string& error) {
            ADAPTER_MODE mode{};
            mode.hAdapterHandle = adapter.handle;
            mode.dwFlags = flags;
            DWORD bytes = 0;
            return DoIoctl(device_, static_cast<DWORD>(IOCTL_NDISRD_SET_ADAPTER_MODE), &mode,
                           sizeof(mode), &mode, sizeof(mode), bytes, error);
        }

        bool NdisrdClient::SetHwPacketFilter(const AdapterEntry& adapter, uint32_t filter,
                                             std::string& error) {
            if (nullptr == adapter.handle) {
                error = "SetHwPacketFilter: adapter handle is null";
                return false;
            }
            return OidFilterRequest(device_, static_cast<HANDLE>(adapter.handle), true,
                                    filter, error);
        }

        bool NdisrdClient::GetHwPacketFilter(const AdapterEntry& adapter, uint32_t& filter,
                                             std::string& error) {
            if (nullptr == adapter.handle) {
                error = "GetHwPacketFilter: adapter handle is null";
                return false;
            }
            return OidFilterRequest(device_, static_cast<HANDLE>(adapter.handle), false,
                                    filter, error);
        }

        bool NdisrdClient::ArmRxEvent(const AdapterEntry& adapter, void* event_handle,
                                      std::string& error) {
            struct {
                HANDLE adapter;
                HANDLE event;
            } payload{static_cast<HANDLE>(adapter.handle),
                      static_cast<HANDLE>(event_handle)};
            DWORD bytes = 0;
            return DoIoctl(device_, static_cast<DWORD>(IOCTL_NDISRD_SET_EVENT), &payload,
                           sizeof(payload), &payload, sizeof(payload), bytes, error);
        }

        uint32_t NdisrdClient::ReadPackets(void* adapter_handle,
                                   INTERMEDIATE_BUFFER* buffers,
                                   uint32_t max_packets, std::string& error) {
            if (0 == max_packets) {
                error.clear();
                return 0;
            }
            // ETH_M_REQUEST is variable-sized: header + one packet slot per
            // requested frame. Reuse a per-thread scratch instead of heap
            // allocating every call - the RX thread issues this up to 64
            // times per poll, and the worker TX drains it on every batch.
            const size_t request_size =
                sizeof(ETH_M_REQUEST) + (max_packets - 1) * sizeof(NDISRD_ETH_Packet);
            static thread_local std::vector<uint8_t> request;
            if (request.size() < request_size) {
                request.resize(request_size);
            }
            auto* req = reinterpret_cast<ETH_M_REQUEST*>(request.data());
            req->hAdapterHandle = adapter_handle;
            req->dwPacketsNumber = max_packets;
            for (uint32_t i = 0; i < max_packets; ++i) {
                req->EthPacket[i].Buffer = &buffers[i];
            }

            DWORD bytes = 0;
            if (!::DeviceIoControl(device_, static_cast<DWORD>(IOCTL_NDISRD_READ_PACKETS), req,
                                   static_cast<DWORD>(request_size), req,
                                   static_cast<DWORD>(request_size), &bytes, nullptr)) {
                const DWORD last = ::GetLastError();
                // Live-driver behavior (verified with a minimal probe): an
                // EMPTY RX queue completes READ_PACKETS with
                // ERROR_INVALID_PARAMETER instead of a zero-packet success.
                // Treat 87 as "no frames pending" - the dataplane polls in a
                // 64-round drain loop, so this path fires constantly.
                if (ERROR_INVALID_PARAMETER == last) {
                    error.clear();
                    return 0;
                }
                error = LastErrorText("READ_PACKETS");
                return 0;
            }
            // The driver reports the number of frames actually dequeued in
            // dwPacketsSuccess (verified against CNdisApi::ReadPackets).
            return req->dwPacketsSuccess;
        }

        bool NdisrdClient::SendPacketsToAdapter(void* adapter_handle,
                                                INTERMEDIATE_BUFFER* buffers,
                                                uint32_t count, std::string& error) {
            if (0 == count) {
                error.clear();
                return true;
            }
            const size_t request_size =
                sizeof(ETH_M_REQUEST) + (count - 1) * sizeof(NDISRD_ETH_Packet);
            static thread_local std::vector<uint8_t> request;
            if (request.size() < request_size) {
                request.resize(request_size);
            }
            auto* req = reinterpret_cast<ETH_M_REQUEST*>(request.data());
            req->hAdapterHandle = adapter_handle;
            req->dwPacketsNumber = count;
            for (uint32_t i = 0; i < count; ++i) {
                buffers[i].m_dwDeviceFlags = PACKET_FLAG_ON_SEND;
                req->EthPacket[i].Buffer = &buffers[i];
            }
            DWORD bytes = 0;
            return DoIoctl(device_, static_cast<DWORD>(IOCTL_NDISRD_SEND_PACKETS_TO_ADAPTER), req,
                           static_cast<DWORD>(request_size), req,
                           static_cast<DWORD>(request_size), bytes, error);
        }

        bool NdisrdClient::SendPacketsToMstcp(void* adapter_handle,
                                              INTERMEDIATE_BUFFER* buffers,
                                              uint32_t count, std::string& error) {
            if (0 == count) {
                error.clear();
                return true;
            }
            const size_t request_size =
                sizeof(ETH_M_REQUEST) + (count - 1) * sizeof(NDISRD_ETH_Packet);
            static thread_local std::vector<uint8_t> request;
            if (request.size() < request_size) {
                request.resize(request_size);
            }
            auto* req = reinterpret_cast<ETH_M_REQUEST*>(request.data());
            req->hAdapterHandle = adapter_handle;
            req->dwPacketsNumber = count;
            for (uint32_t i = 0; i < count; ++i) {
                buffers[i].m_dwDeviceFlags = PACKET_FLAG_ON_RECEIVE;
                req->EthPacket[i].Buffer = &buffers[i];
            }
            DWORD bytes = 0;
            return DoIoctl(device_, static_cast<DWORD>(IOCTL_NDISRD_SEND_PACKETS_TO_MSTCP), req,
                           static_cast<DWORD>(request_size), req,
                           static_cast<DWORD>(request_size), bytes, error);
        }

        bool NdisrdClient::FlushAdapterQueue(const AdapterEntry& adapter,
                                             std::string& error) {
            DWORD bytes = 0;
            HANDLE handle = static_cast<HANDLE>(adapter.handle);
            return DoIoctl(device_, static_cast<DWORD>(IOCTL_NDISRD_FLUSH_ADAPTER_QUEUE), &handle,
                           sizeof(handle), &handle, sizeof(handle), bytes, error);
        }

        bool NdisrdClient::ResetAdapterMode(const AdapterEntry& adapter,
                                            std::string& error) {
            return SetAdapterMode(adapter, 0, error);
        }

    }  // namespace driver
}  // namespace vgww
