# Configuration

[中文](../zh/configuration.md)

VGWW reads a JSON configuration file (`--config=vgww.json`). Command-line
overrides: `--adapter=<name>`, `--web-only`, `--help`.

## Full reference

```json
{
  "mode": "bypass",

  "adapter": "Ethernet",

  "gateway": {
    "ipv4": "192.168.0.40",
    "mask": "255.255.255.0",
    "mac":  "30:fc:68:88:b4:a9"
  },

  "dhcp": {
    "enabled": true,
    "pool_start": "192.168.0.100",
    "pool_end": "192.168.0.200",
    "lease_hours": 12,
    "dns": ["192.168.0.1"],
    "static_bindings": [
      {"mac": "02:00:00:00:00:01", "ip": "192.168.0.50", "hostname": "printer"}
    ]
  },

  "ipv6": {
    "enabled": true,
    "ula_prefix": "fdaa:0:0::/48",
    "ra_lifetime_s": 1800,
    "dhcpv6": {
      "enabled": true,
      "pool_start": "fdaa:0:0::1000",
      "pool_end": "fdaa:0:0::1fff",
      "lease_seconds": 3600,
      "static_bindings": [
        {"duid": "00030001aabbccddeeff", "ip": "fdaa:0:0::5000", "hostname": "nas"}
      ]
    }
  },

  "perf": {
    "workers": 8,
    "rx_batch": 64,
    "max_conns": 4096,
    "udp_flow_cap": 8192,
    "ring_capacity": 4096
  },

  "web": {
    "port": 8080,
    "bind": "127.0.0.1",
    "token": ""
  },

  "bridge": {
    "enabled": false,
    "upstream": "NIC 1",
    "downstream": "NIC 2",
    "mac_table_size": 4096
  }
}
```

## Field notes

| Field | Meaning |
|---|---|
| `mode` | `bypass` (default) or `main`. Only `main` runs the address-assignment services (DHCPv4/DHCPv6/RA); under `bypass` none of them are assembled and clients keep their own configuration |
| `adapter` | Adapter friendly name or GUID substring; matched case-insensitively. Friendly names accept localized aliases (`Ethernet` ↔ `以太网`) and a strict " N" instance suffix (`Ethernet 2` ↔ `以太网 2`; `Ethernet` does not match `以太网 2`). Empty picks the first adapter; on no match the data plane degrades and the console error lists the candidates and points at `--adapter=<name>` or this file |
| `gateway.ipv4` | The virtual gateway address clients use as their default gateway. **Must NOT be bound on the host stack** (the host would answer client traffic itself). A `0.0.0.0` gateway is rejected |
| `gateway.mask` | LAN netmask. Must be non-zero and a contiguous 1-bit prefix (e.g. `255.255.255.0`); host-style masks are rejected |
| `gateway.mac` | Virtual gateway MAC; ARP requests for `gateway.ipv4` are answered with it |
| `ipv6.ula_prefix` | ULA prefix advertised via SLAAC (required when `ipv6.enabled`). Accepts a bare address (`"fdaa:0:0::"`) or one with an embedded length (`"fdaa:0:0::/48"`; default 64). Must be a ULA (`fc00::/7`) with no host bits set beyond the prefix length |
| `ipv6.prefix_len` | Advertised subnet length in `[1, 64]` (SLAAC hosts build a 64-bit interface ID). When `ula_prefix` carries a `/len`, the two must agree |
| `ipv6.ra_lifetime_s` | RA Router Lifetime in `[1, 65535]`. `0` revokes the default route and values > 65535 wrap the 16-bit RA field |
| `ipv6.dns` | v6 recursive DNS servers announced via the RA RDNSS option (RFC 8106, type 25) so SLAAC-only clients can resolve names. An array of full addresses without `/len`, at most 3. Empty (default) emits no RDNSS and preserves legacy behavior |
| `dhcp.enabled` | Run the built-in DHCPv4 server (only under `mode: main`). `false` (default) assembles nothing, persists nothing, sweeps nothing |
| `dhcp.pool_start` / `dhcp.pool_end` | Dynamic pool range (inclusive); both ends must sit inside the `gateway.ipv4`/`gateway.mask` subnet with `pool_end >= pool_start` |
| `dhcp.lease_hours` | Lease length in hours, `[1, 8760]`; default 12 |
| `dhcp.dns` | DNS servers handed to DHCPv4 clients (at most 3); defaults to the host resolver list |
| `dhcp.static_bindings` | Static bindings (`mac`/`ip`/optional `hostname`), at most 1024; MAC and IP must be unique |
| `ipv6.dhcpv6.enabled` | Run the stateful DHCPv6 server (RFC 8415 subset; requires `mode: main` and `ipv6.enabled`) |
| `ipv6.dhcpv6.pool_start` / `pool_end` | v6 dynamic pool; must sit inside `ula_prefix`. Both zero derives `prefix::1000`-`prefix::1fff` |
| `ipv6.dhcpv6.lease_seconds` | v6 lease length in seconds, `[60, 31536000]`; default 3600. T1/T2 are 0.5x/0.8x of the lease |
| `ipv6.dhcpv6.static_bindings` | v6 static bindings (`duid` hex string/`ip`/optional `hostname`), at most 1024; DUID and IP must be unique |
| `perf.workers` | Worker count in `[1, 8]` (xtcp shard count); worker *i* pumps shards *i, i+8, ...* |
| `perf.rx_batch` | Frames per `ReadPackets` call, `[1, 4096]` |
| `perf.max_conns` | Hard cap on concurrent TCP flows (`[1, 1048576]`); memory ≈ max_conns × 128 KiB |
| `perf.udp_flow_cap` | Per-worker UDP flow table cap (`[1, 65536]`, default 8192) |
| `perf.ring_capacity` | SPSC ring descriptors per worker (`[1, 1048576]`). `0` made the data plane dereference a null ring on every frame |
| `perf.dial_timeout_ms` | Upstream TCP dial timeout (`[1, 3600000]`) |
| `web.port` | Management UI listen port, `[1024, 65535]` (default 8080); privileged and ephemeral ports are rejected |
| `web.bind` | Management UI listen address (default `127.0.0.1`); rejected when empty or over 256 bytes. The server never binds every interface implicitly — configure an explicit address for LAN access |
| `web.token` | When set, every non-GET `/api/*` call must send `X-Auth-Token: <token>` (or `Authorization: Bearer <token>`); otherwise 401. **Set this on any LAN-facing deployment** — without it any device can rewrite the configuration |
| `vlan.id` | Enables a single 802.1Q access VLAN, `[1, 4094]`. Explicit `0` and `4095` are reserved 802.1Q codepoints and are **rejected**; omit the `id` field (or the whole `vlan` section) to disable. Inbound frames tagged with this VID have the tag stripped before routing; every reply is re-tagged with it (single-VLAN trunk/access gateway). Frames from any other VLAN are isolated (dropped). Q-in-Q is not supported; with 802.1Q enabled the frame-size budget shrinks by 4 bytes (the fixed 1514 interface buffer fits tagged replies only up to 1510 bytes) |
| `bridge.enabled` | Enables the built-in dual-NIC L2 bridge (default `false`, off). Independent of `mode` — the bridge works under `bypass` too |
| `bridge.upstream` / `bridge.downstream` | Adapter names for the two ends (both required and must differ when `enabled: true`). Single-path topologies only; **no STP/RSTP**, and mirror ports / looped environments are forbidden. The current implementation requires upstream to be the primary adapter (`adapter`) |
| `bridge.mac_table_size` | MAC learning table capacity, `[1, 65536]`, default 4096. `0` or over-limit values are rejected |

## Validation rules

* The gateway netmask must be non-zero, contiguous, and the gateway address
  itself must not be `0.0.0.0`.
* `perf` sizes, `ipv6.ra_lifetime_s`, `web.port` and
  `vlan.id` are range-checked; out-of-range values fail with a config error
  instead of wrapping/truncating at runtime.
* IPv6 requires a valid ULA prefix whenever `ipv6.enabled` is set.
* Under `mode: bypass` neither DHCPv4, DHCPv6 nor RA is assembled (even when
  their own `enabled` flags are true); under `mode: main` they come up only
  when enabled, and `ipv6.enabled=false` turns RA and DHCPv6 off together.
* Unknown CLI arguments are rejected.
* Missing `gateway` section is a fatal error.
* Bridge: with `enabled: true`, `upstream`/`downstream` must both be set
  and must differ; an out-of-range `mac_table_size` (`0` or > 65536) is
  rejected. The bridge is off by default; enabling it needs driver
  promiscuous-mode privileges (administrator / driver reinstall may be
  required). WLAN ports are not supported in v1; MTU ≤ 1500 on the
  standard driver build. Host-side bridging (Windows bridge / Hyper-V
  virtual switch) compatibility has not passed POC and **must not be
  claimed as supported**.

## WebUI

The embedded HTTP server is **off by default**; `--web` enables it, `--web-only` starts only the WebUI (no driver needed) and `--no-web` is a redundant compat toggle (already off). It listens on `web.port` (default 8080) bound to `web.bind` (default `127.0.0.1` loopback; configure an explicit address for LAN access - the server never binds every interface implicitly):

* **Dashboard** — live counters and client list
* **Port Mapping** — host-port → LAN-client forwarding rules
* **Firewall** — MAC/IP blocklist
* **Rate Limit** — per-client uplink/downlink caps (token bucket)
* **Settings** — running configuration view; POST `/api/config` persists a
  validated config file (applies on restart)

`/api/status` carries a top-level `bridge` object: `enabled`/`upstream`/
`downstream` (from the configuration), `mac_count` (learned MACs) and
`state` (`stopped`/`running`/`failed`). The closed state reads
`enabled=false`, `state="stopped"`, `mac_count=0`.

Write protection: set `web.token` and send the same value in the
`X-Auth-Token` header for every mutating call (POST/DELETE).

`--web-only` starts only the WebUI (no driver needed) while `--headless` runs without the native window (keeping the 1 s console stats loop); `--minimized` starts the native UI hidden to the tray.
