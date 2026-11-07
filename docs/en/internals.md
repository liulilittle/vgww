# Internals

This page is the maintainer's map: how the process is wired, which thread owns
what, and which invariants a change must not break. It complements
[architecture.md](architecture.md), which describes *what* the router does.

## Module map

| Directory | Responsibility |
|---|---|
| `src/core` | Configuration (parse/validate/atomic save), logging, memory backend switch, UTF-8 sanitisation, random, limits |
| `src/dsp` | The wait-free SPSC ring and the frame classifier (the only cross-thread primitive on the data path) |
| `src/driver` | WinpkFilter client (`ndisrd`), adapter enumeration, driver install/uninstall, `error_class` (maps an NTSTATUS/errno to a user-facing class) |
| `src/proto` | Wire codecs and servers: Ethernet/ARP/ICMP/UDP/DHCP/DHCPv6/NDP |
| `src/relay` | Per-protocol relays: `TcpRelay` (pumps), `UdpFlowTable`/`UdpRelay` (per-flow NAT), `IcmpRelay` (tag NAT), `PortMapManager` (UPnP/NAT-PMP + port forwarding) |
| `src/runtime` | `Dataplane`: threads, rings, registries, DHCP/NDP wiring, lifecycle |
| `src/tables` | Neighbour table (RCU snapshot), rate limiter |
| `src/bridge` | 802.1Q bridge between a downstream and an upstream port |
| `src/ui` | Native UI: element tree, controls, window, renderer, pages, tray, i18n, debug channel |
| `src/web` | Embedded HTTP server and the JSON API behind the SPA |
| `scripts/` | The ten gates plus the native-i18n resource generator |
| `tools/` | Soak harness, UI screenshot/diff gates |

## Threads

| Thread | Owns | May not |
|---|---|---|
| RX/TX (one) | `driver::Client`, both SPSC ring sets, the wire batches, NDP timers | Touch a relay socket or an xtcp shard |
| Worker *i* (N) | xtcp shards `{i, i+N, …}`, `io_contexts[i]`, `udp_tables[i]`, `icmp_relays[i]`, registry/accept/abort state for *i* | Touch another worker's shard, table or io_context |
| Control (one) | Periodic maintenance: DHCP/NDP sweeps, port-map polls, telemetry snapshot | Anything on the packet path |
| UI / Web | Rendering, HTTP, config edits (through `Dataplane`'s public API) | Touch rings, relays or stacks directly |

Shard affinity is the load-bearing rule: **a flow's frame, its protocol handling
and every asio completion for that flow run on the same worker**. `StartMimt`
routes an accepted flow to `ShardIndexOf(conn_id) % worker_count`, and the worker
dispatches exactly the shards it owns. Breaking this (for example by sweeping a
foreign shard from `WorkerLoop`) produces concurrent asio use on one socket.

## Crossing a thread boundary

The only primitive is `dsp::SpscRing<T>`:

* one producer, one consumer, wait-free;
* free-running 64-bit indices, slots addressed by `index & mask`, capacity
  rounded up to a power of two;
* **push on a full ring returns false and the caller drops** — the RX thread is
  never blocked, and the drop is counted (`rx_dropped`).

`TxFrame` ownership moves *into* the ring, which is why the UDP reply path
allocates one `std::vector` per reply: the buffer must outlive the worker call.

## Lifecycle: teardown is the hard part

A relay can end for four reasons, and they must not be confused:

| Cause | Path | Client sees |
|---|---|---|
| Upstream EOF | `TcpRelay::Finish(true)` → `QueueTeardown(graceful=true)` | FIN |
| Upstream error / reset | `Finish(false)` | RST |
| Client reset / stack reclaimed the flow | `FinishFromFlow()` | nothing (already gone) |
| Dial timeout / connect failure | `QueueTeardown(false)` | RST |

`QueueTeardown` only appends under the worker's abort mutex; the worker's
`DrainAborts` performs the `stack->Close()`/`Abort()` on the owning thread.
`Finish` is exactly-once (`finished_` latch) and cancels the retry timer.

The registry is swept only when a relay actually finished:
`hooks_.on_finished` sets `registry_dirty[i]`, and `SweepRegistry(i)` clears it
and drops finished entries. An idle worker therefore never walks the registry —
that was the batch-306 fix (idle CPU proportional to live connections).

`NotifyPeerFin(conn_id)` (client FIN) uses the per-worker `relay_index_`
(`unordered_map<conn_id, weak_ptr<TcpRelay>>`) for a single hash lookup, then
**always posts the socket touch to the owner worker**; the FIN is delivered on
whichever worker fed the segment, which is not necessarily the owner.

## State stores

* **UDP flows** — `UdpFlowTable`, per worker: LRU list + hash map, idle timeout
  60 s, hard cap `perf.udp_flow_cap`. Evicting closes the socket so the pending
  `async_receive` cannot become a ghost. The hash folds **both ports** and
  avalanches; a hash that only mixes addresses collapses every flow of one
  client into a single MSVC bucket.
* **ICMP** — `IcmpRelay::TagAllocator`: tags `1..65535` handed out from a
  free-list, 3 s expiry, one reply consumes its tag. `0` means "pool full" and
  is never a valid tag.
* **Neighbours** — RCU style: readers load one `shared_ptr<const NeighborSnapshot>`;
  the rebuild path is the only writer.
* **DHCP / DHCPv6** — lease stores behind one mutex each, control-plane only.
  OFFER pins an address for 60 s, DECLINE parks it for 600 s, and leases are
  dumped on a clean `Stop()` so a restart keeps mappings.
* **Relay registry / index** — per worker, pre-sized at startup from
  `perf.max_conns` (`runtime::PerWorkerReserve`), so the connect path never
  reallocates under the registry mutex.

## Invariants a change must preserve

1. One thread per shard; a shard's objects are touched by exactly one worker.
2. The RX thread never blocks; full means drop-and-count.
3. Every accepted flow is eventually either torn down or swept — no ghosts
   holding sockets.
4. `Finish` runs once per relay; the retry timer is cancelled exactly once.
5. A weak `conn_id` index entry is removed only when it still points at the
   relay being swept (ids are reused).
6. Config writes are atomic (temp file + rename); a failed write leaves the old
   file intact.
7. Web token comparison is constant-time; the current token is never served
   back to the UI.
8. Frame builders never trust wire lengths: every length is validated against
   the actual buffer before it is used for an allocation or a copy.
