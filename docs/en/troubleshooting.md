# Troubleshooting

Symptom first, then the cause and the fix. Every entry maps to a real code path;
when a message is quoted, it is the string the program prints.

## The gateway starts but no client can reach the internet

1. **Driver not installed.** The log/UI says `driver missing` and the data plane
   stays in degraded mode. Run `vgww.exe --install-driver` from an elevated
   prompt (VGWW always runs elevated), then start it again. Removal:
   `vgww.exe --uninstall-driver`, which also clears any legacy
   `VGWW-GrantAccess` boot task.
2. **Wrong adapter.** `adapter` accepts a friendly name (`Ethernet`) or
   `\DEVICE\{GUID}`. The Settings page lists detected adapters with link state
   and IPv4 addresses and warns when the adapter is disconnected or not in the
   gateway subnet. Pick it from that list rather than typing it.
3. **Gateway MAC invalid.** The log prints `Invalid MAC address format`:
   `gateway.mac` must be `aa:bb:cc:dd:ee:ff`. This is the MAC clients will ARP
   for, so it must not collide with a real NIC.
4. **Mode is bypass.** In `bypass` mode VGWW forwards the LAN without NAT —
   the LAN needs a real router upstream. Check `mode` before debugging NAT.

## "bind failed: ... already in use"

The management port is taken (`web.port`, default 8080). Either stop the other
process or change `web.port`. `web.bind` defaults to `127.0.0.1`; bind failures
appear in the UI console and the log.

## Clients do not get a DHCP address

* `dhcp.enabled` must be true **and** the mode must not be `bypass`; in bypass
  mode the server is deliberately not assembled (a DHCP server that hands out
  addresses it cannot route is worse than silence).
* The pool must sit inside the LAN subnet and inside `gateway.ipv4/mask`. The
  pool's first and last address, the network address, the broadcast address and
  every statically bound address are refused as dynamic candidates.
* `[vgww] dhcp: pool exhausted (N total)` means exactly that: every candidate is
  leased, reserved or declined. Widen the pool or shorten `lease_hours`.
* A client that declined an address parks it for 600 s; a client that vanished
  after an OFFER pins it for 60 s.

## DHCPv6 / IPv6 clients get no address

* `ipv6.enabled` must be true. VGWW answers RA/SLAAC on the LAN and terminates
  the TCP/UDP for the client, so the client never needs a globally routed
  address of its own; `ula_prefix` supplies the LAN prefix.
* Port forwarding for UDP is not implemented. A UDP rule will not open the WAN
  port; only TCP rules are reverse-dialled.

## Leases are not restored after a restart

The lease file is written on a **clean** stop. Killing the process (Task
Manager, power loss) skips the dump: there is no live thread left to
serialise safely. A `dhcp: lease dump failed on stop: <path>` line means the
path was not writable — check the directory used by `--config`.

## Transfers stall, then recover

`portmap_send_dropped` climbing means the WAN→LAN queue hit its 1024-entry cap
because the LAN client stopped reading; the manager pauses its own WAN reads so
the queue stays finite. This is backpressure, not a leak.

## UDP replies stop arriving for one flow

If the upstream sends ICMP unreachable (port closed, network down), the receive
chain must survive it: VGWW re-arms on the whole ICMP-unreachable family and only
stops on `operation_aborted` / `bad_descriptor` / a closed socket. If a flow
still goes silent, check that it is not being LRU-evicted (`perf.udp_flow_cap`)
and that upstream datagrams fit the 8 KiB relay buffer — larger ones are
truncated by the kernel and should use TCP.

## The second launch does nothing

That is intentional: VGWW is single-instance and a second launch focuses the
running window (or the tray icon). Use the tray menu / window, not a new process.

## WebUI returns 401

The `X-Auth-Token` value does not match the configured token. The token is
never displayed back by the UI; set a new one in Settings and re-login. A
cleared field keeps the current token.

## UI/console shows a red banner after sleep or dock/undock

The window restores its geometry and DPI on resume; if the display topology
changed, the size is clamped into the current work area rather than restored
off-screen. Contribute a report with the console page contents if the clamp
picks a visibly wrong size.

## High idle CPU

* Check `rx_dropped`: sustained traffic that the ring cannot absorb means
  `ring_capacity` is too small for the burst.
* `perf.workers` above the xtcp shard count (8) adds idle threads, not
  throughput.
* The idle loop parks for 200 µs per empty poll; a few percent of one
  core with the UI, WebUI and tray running is expected.

## Logs and diagnostics

* The console page in the native UI shows the same stream that goes to the
  rotating log under `--config`'s directory (`logs/`).
* `vgww.exe --version` reports the allocator backend (jemalloc or CRT).
* `--headless` runs the data plane without the native UI; `--web-only` runs the
  WebUI without the data plane and needs no driver — useful to isolate whether a
  problem is in the UI, the API or the packet path.
