# Architecture

[中文](../zh/architecture.md)

This document describes how VGWW actually works: threading, data paths,
protocol modules, and the reasoning behind each decision. Every statement
maps to code in `src/`.

## Hard constraint

**All client traffic is re-originated as userspace sockets from the host.**
This is what makes the VPN work: re-dialed connections follow the host
routing table and enter the VPN virtual adapter automatically. Writing raw
frames to the physical NIC would bypass the VPN — VGWW never does that.
This single rule shapes the entire architecture: it is why TCP is
terminated and relayed instead of L3-forwarded.

## Threading model

| Thread | Count | Responsibility |
|---|---|---|
| RX/TX | 1 | Batch-read frames (`ReadPackets`), classify, hash-dispatch; drains all worker TX rings and batch-injects |
| Worker | 8 (= xtcp shard count) | Pump its xtcp shard + own asio io_context + UDP/ICMP relay tables |
| Control | 1 | neighbor aging, tag expiry, stats |

Worker *i* pumps xtcp shard *i*. A flow's inbound frame, protocol handling,
upstream socket I/O and outbound frame construction all happen on one core:
zero cross-thread hand-offs in steady state. The only data-plane
synchronization primitive is the SPSC ring's atomic index ordering.

## The three killers (locks / copies / switches)

* **Locks**: SPSC rings are lock-free (acquire/release on padded indices).
  xtcp shard locks are touched by one thread only. Neighbor table reads are
  one atomic load of an immutable snapshot (RCU-style publish).
* **Copies**: kernel→user (driver), user→pool block, pool→socket buffer.
  Ethernet headers are written into 16-byte headroom already reserved by
  xtcp pool blocks — zero shifting. Relay buffers double as asio buffers.
* **Switches**: busy-poll loops while traffic flows; event-driven sleep when
  idle. Upstream sockets live on the worker's own io_context, so IOCP
  completions are consumed on the same thread with no cross-thread posts.

## Protocol modules

| Module | File(s) | Behavior |
|---|---|---|
| VLAN 802.1Q | `runtime/dataplane.*` | Optional single access VLAN (`vlan.id`): inbound tags for the configured VID are stripped before classification, every downlink frame is re-tagged at the single `AppendDown` choke point, frames from other VLANs are isolated (dropped); tagged replies are capped at 1510 bytes by the fixed 1514 interface buffer |
| ARP | `proto/arp.*` | Answers requests for the virtual gateway IP; passive learning covers static-IP clients |
| ICMP | `proto/icmp.*`, `relay/icmp_relay.*` | Gateway pings answered locally; client pings relayed via raw sockets with a globally unique 16-bit identifier NAT (3 s expiry) |
| NDP/RA | `proto/ndp.*` | Router Solicitations answered with Router Advertisements (SLAAC prefix + lifetime + source link-layer option); Neighbor Solicitations for the gateway's own addresses answered with Neighbor Advertisements; gateway v6 pings answered locally |
| TCP relay | `relay/tcp_relay.*` | MimtFlow ↔ upstream socket pump with end-to-end backpressure (v4 and v6) |
| UDP relay | `relay/udp_relay.*` | Per-flow connected-UDP sockets (v4/v6), LRU-capped tables, 60 s idle sweep |
| Port mapping | `relay/portmap_manager.*` | WAN-side acceptors per rule; inbound connections are reverse-dialed into the LAN client through xtcp (`Connect`) with queued relay pumps |
| Firewall | `web/web_api.*` + dispatch | MAC/IP blocklist enforced at frame dispatch via an RCU snapshot refreshed by the control thread |
| WebUI | `web/http_server.*`, `web/web_api.*`, `www/` | Embedded HTTP/1.1 server (asio), REST API, single-file vanilla SPA dashboard |

## IPv6 data path

* **TCP**: xtcp accepts v6 SYNs transparently (same mimt hook as v4); relays
  dial upstream with `make_address_v6`.
* **UDP**: flow tables key on the full 16-byte address; return frames are
  built by `BuildUdpFrameV6` with an IPv6 pseudo-header checksum.
* **Control plane**: RA/SLAAC gives clients addresses in the advertised ULA
  prefix; NDP answers keep neighbor caches pointing at the gateway.

## Backpressure

| Direction | Congestion point | Propagation |
|---|---|---|
| Client → internet (TCP) | MimtFlow rx queue full | `OnData` returns false → xtcp window 0 → client RTO |
| Internet → client (TCP) | Upstream socket stalled | stop reading the socket → host stack window shrinks |
| UDP | socket send buffer full | drop (UDP semantics); flow table capped |

There are no unbounded queues anywhere. Memory usage is computable at
startup: `max_conns × (64K rcv + 64K snd)` plus fixed ring/table sizes.

## Testing strategy

The driver boundary is an interface (`driver/idriver_client.h`). Tests bind
an in-memory fake that replays scripted frames and captures everything VGWW
emits — the entire pipeline runs verbatim without any kernel driver
(backtesting principle: simulate boundaries, not business logic). The
integration test scripts a full TCP conversation at frame level: SYN,
SYN-ACK parse, ACK, payload round-trip through a local echo server.

## Driver loading

ndisrd 3.6.2.1 is an NDIS LWF (lightweight filter) driver and must be loaded
through the vendor INF framework. The built-in `--install-driver`
(`driver/installer.cpp`) does exactly that: `pnputil /add-driver
<ndisrd_lwf.inf> /install` publishes the payload to the driver store and
binds it, then INetCfg instantiates the network component and binds it to the
physical NICs. (An earlier channel that registered the driver as a plain
kernel service — `CreateServiceW(SERVICE_KERNEL_DRIVER)` — was retired after
it failed to load with 0x1F; the LWF must go through the NDIS framework. See
`docs/{zh,en}/driver-install.md` for the install/uninstall guide and
troubleshooting.) While the LWF binding is active there **must be a resident
consumer (this product) and the configured adapter name must resolve** — after
binding, driver enumeration exposes adapters as `\DEVICE\{GUID}` paths
(`ndisrd_client.cpp` carries a friendly-name → GUID resolver). Without a
consumer the host TCP/IP data path is held up by the filter stack: both NICs
lose ICMP and TCP until the driver is uninstalled. An unresolved adapter name
under binding does not fail silently: the data plane degrades with an
actionable error that lists the available adapters (friendly name =>
\DEVICE\{GUID}) and points at `--adapter=<name>` or the config file;
friendly-name matching is case-insensitive and accepts localized Ethernet
aliases.

Verified on hardware: a one-hour soak with steady-state working set and handle
count flat, an Application Verifier run over the web, dataplane lifecycle and
UI test binaries with zero Error entries, and a full driver install/uninstall
cycle that restores the host network.

## IPv6 / NAT66

Windows has no kernel NDP proxy and upstream networks will not route our
client prefix, so egress uses NAT66 semantics. In this architecture NAT66
emerges naturally from terminate-and-relay: v6 TCP is terminated by xtcp and
re-dialed from the host address; v6 UDP is relayed per-flow. Clients see
their ULA addresses; the internet sees the host's address. The real v6 work
is control-plane only: NDP answers, RS/RA, DAD.

## Memory management

VGWW uses a replaceable memory-pool layer (\src/core/memory.h\).
\core::Malloc/Free/Realloc\ route to the compiled-in backend: **jemalloc**
when CMake detects it (\-DVGWW_JEMALLOC=ON\, the vcpkg \x64-windows\
install is the default search path; openppp2 uses the same library), else the
**CRT heap**. The choice is compile-time, so the data path keeps zero
indirection.

\core::PoolAllocator<T>\ (\src/core/allocator.h\) adapts any STL container
to that backend through the \core::PoolVector\ / \PoolString\ / \PoolMap\
aliases. The port-forward data queues already use \PoolVector\; the relay hot
path uses fixed \std::array\ buffers and never allocates per frame. All
allocations are size-aligned to 64 bytes for SIMD safety (jemalloc honours
this; CRT guarantees only \max_align_t\, 16 bytes).

The active backend is reported by \gww.exe --version\. jemalloc decay
settings are left at defaults, matching the stock vcpkg build. WebUI/API
payloads keep plain \std::string\/\std::vector\ return types (public API
contract); swapping them to pool containers is a follow-up, deliberately
outside the initial migration.
