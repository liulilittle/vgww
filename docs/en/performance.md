# Performance

This page documents where VGWW spends time, which knobs actually matter, and how
to measure changes instead of guessing. Every number below was measured on the
development machine (Windows 11, 8-core x64, Release, MSVC 14.44); treat them as
orders of magnitude, not as a benchmark contract.

## Data path at a glance

```
driver (WinpkFilter) ──► RX thread ──classifier──► SPSC ring[worker]  (wait-free)
                                                     │
                                     worker i ───────┘
                                       ├─ UDP  → per-flow socket NAT (UdpFlowTable)
                                       ├─ ICMP → tag NAT (IcmpRelay) on a raw socket
                                       └─ TCP  → xtcp shard i, then TcpRelay pumps
                                                     │
                                     TX ring[worker] ──► RX/TX thread ──► driver
```

Two rules dominate the cost model:

1. **One thread per shard, no locks on the packet path.** A flow's inbound frame,
   protocol handling and asio completions all run on the worker that owns its
   shard. Steady-state forwarding performs no mutex acquisition.
2. **Never block the RX thread.** A full ring drops and counts; TCP recovers by
   retransmission, UDP is lossy by design. Growing queues instead of dropping
   would move the latency spike to every other flow.

## Measured baselines

| What | Result | Where |
|---|---|---|
| UDP flow hash spread, 4096 flows to one server | worst bucket **6–7** entries (was 4096 before the avalanche fix) | `tests/test_udp_relay.cpp` (`TestFlowHashSpreadsBuckets`) |
| Neighbour table tick, 4096 entries | **156.6 µs** per tick at 10 Hz ≈ 0.16 % of one core | batch 319 measurement |
| Full unit/integration suite | **49 tests in ~120 s** (`ctest -C Release`) | local + CI |
| CI job (configure + build + tests + 10 gates) | **~7 min** on `windows-latest` | GitHub Actions |
| Per-packet allocation on the UDP reply path | **1** `std::vector` (ownership hand-off to the TX ring) | `HandleUdp` reply lambda |

The hash result is the one that matters most: MSVC's `unordered_map` derives the
bucket from the **low bits** of the hash, so a hash that only mixes the
destination address degenerates to one bucket for every flow of a busy client.
That was a real 4096-entry linear scan per packet; the avalanche (Murmur3
`fmix64`) fixed it, and the test pins `max_bucket <= 64`.

## Knobs that matter

All of them live under `perf` in the configuration file.

| Key | Default | Effect |
|---|---|---|
| `perf.workers` | 8 | Worker threads; **worker *i* owns xtcp shard *i***. More workers than shards only adds idle threads. |
| `perf.ring_capacity` | 1024 | Per-worker SPSC ring depth. Larger absorbs bursts, costs memory and (slightly) cache pressure. |
| `perf.rx_batch` | 64 | Frames popped per batch. Larger amortises the index loads, increases per-iteration latency. |
| `perf.max_conns` | 4096 | Live TCP relays. Also pre-sizes the per-worker relay registry and its `conn_id` index (see below). |
| `perf.udp_flow_cap` | 65536 | Live UDP flows per worker table (LRU eviction at the cap). |
| `perf.dial_timeout_ms` | 10000 | Upstream connect deadline. A timed-out dial closes the socket, aborting the connect and RST-ing the client. |

Rules of thumb:

* Keep `workers` at the xtcp shard count (8). Extra workers steal cache lines
  without owning work.
* Raise `ring_capacity` before raising `workers` when you see `rx_dropped`
  climbing under burst traffic — dropping is cheaper than context switching.
* `max_conns` is a hard bound, not a target: every per-worker container is
  reserved up front from it (`runtime::PerWorkerReserve`), so a large value
  wastes a few hundred kilobytes at startup and nothing per packet.

## Where the remaining time goes

Per forwarded packet the worker executes, in order:

1. one acquire load to pop from the ring (batched);
2. classification (already done by the RX thread — the class rides in `RxItem`);
3. a hash lookup (`UdpFlowTable::GetOrCreate`) plus one LRU splice;
4. a `shared_ptr` snapshot load for the neighbour entry (one atomic, no copy);
5. frame build into a `TxFrame` (one allocation, moved into the TX ring);
6. one release store to push.

Steps 3–4 are O(1) and lock-free. Step 5 is the only heap allocation on the
steady-state path; removing it needs a fixed-slot TX ring (pooled frames) and is
tracked as future work rather than pretended to be free.

## Idle behaviour

An empty poll parks the worker for 200 µs (`SleepFor`), so an idle gateway
costs essentially nothing (measured: < 0.5 % of one core with the UI and WebUI
running). The trade-off is up to 200 µs of added latency for the first packet
after an idle period. Under load the rings are rarely empty and the sleep is
never reached.

## Measuring a change

```bat
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DVGWW_JEMALLOC=OFF
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

* Micro-benchmarks live inside the unit tests and print their numbers
  (`[b316] ... buckets=...`, `B229 ...`), so `ctest -V` is a usable harness.
* The soak harness (`tools/soak.cpp`, target `vgww_soak`) drives the data plane
  with synthetic load and reports throughput/latency.
* `vgww.exe --version` reports the allocator backend; jemalloc is enabled by
  default on developer builds and disabled in CI (`-DVGWW_JEMALLOC=OFF`).

## Diagnostics you can watch

| Counter | Meaning | Action |
|---|---|---|
| `rx_dropped` | Ring full or malformed frame | Raise `ring_capacity`, check `workers` |
| `portmap_send_dropped` | WAN→LAN queue at its 1024 cap | Client is not reading; the manager pauses its own reads |
| `mac_misses` | Neighbour entry aged out; an ARP probe was sent | Normal on idle clients, pathological if constant |
| `udp` evictions | `udp_flow_cap` reached, LRU evicted | Raise the cap or investigate a flow leak |
| `tcp_accepted` | Flows queued for dialling | Paired with upstream dial failures in the log |

## Known limits

* MSVC AddressSanitizer is supported (`-DVGWW_ASAN=ON`); **leak detection
  (LSan) is not available on Windows**, so leak-freedom is argued by ownership
  discipline, not by a runtime checker.
* The numbers above come from a single machine with one NIC; multi-queue RSS
  behaviour depends on the WinpkFilter driver configuration and is not measured
  here.
* `perf.workers` above 8 is accepted but has no shard to own.
