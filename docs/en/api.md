# HTTP API

The management UI is served by an embedded HTTP/1.1 server. Every endpoint below
is also what the bundled SPA uses; there is no separate "internal" API.

## Transport and framing

* Plain HTTP/1.1, `Connection: close` per request (no keep-alive, no pipelining).
* Request line + headers must arrive within 16 KiB; the body is bounded by
  `limits::kMaxConfigBytes` (1 MiB).
* Paths are percent-decoded once; a malformed escape is a `400`.
* A path longer than 2048 bytes or more than 64 query parameters is a `400`.
* `Content-Length` must be `1*DIGIT` and match the body exactly. A duplicate
  header, a header line without `:` , whitespace before the colon, or any
  `Transfer-Encoding` is rejected with `400` (request smuggling defences).
* Responses carry an explicit `Content-Length`; JSON responses are
  `application/json`.

## Authentication

Writes (`POST`, `DELETE`, `PUT`) require the token when one is configured:

```
X-Auth-Token: <token>
Authorization: Bearer <token>
```

* Token configured, header missing or wrong → `401`.
* No token configured → writes are accepted (loopback-only setups), except the
  two privileged routes below, which answer `403`.
* Token comparison is constant-time and length-independent.
* The token is never returned by any endpoint.
* A non-loopback `web.bind` with an empty token disables the server entirely
  (see [configuration](configuration.md#webui)).

## Endpoints

### `GET /api/status`

Dashboard poll target; keep it cheap. Returns gateway identity, packet counters,
DHCP/DHCPv6 counts and a top-level `bridge` object.

```json
{
  "gateway": { "ip": "192.168.0.40", "ipv6": true },
  "stats": {
    "rx_frames": 0, "tx_frames": 0, "tcp_accepted": 0, "arp_replies": 0,
    "icmp_replies": 0, "mac_misses": 0, "rate_limited": 0, "rx_dropped": 0,
    "host_passthrough": 0, "rx_vlan_frames": 0, "tx_vlan_frames": 0
  },
  "dhcp": { "leases": 0 },
  "dhcp6": { "leases6_count": 0, "bindings6_count": 0 },
  "bridge": { "enabled": false, "upstream": "", "downstream": "", "mac_count": 0, "state": "off" }
}
```

### `GET /api/clients`

Per-client rate state: MAC, IPv4, current up/down bits per second and the
counters behind the dashboard table.

### `GET /api/system`

Process and throughput telemetry plus identity rows: `proc` (`cpu_percent`,
`cores`, `ws_bytes`, `virt_bytes`), `throughput` (`up_bps`, `down_bps`),
`version`, `memory` (backend name and version), `config_path`, `uptime_s`,
`driver` (`running` / `stopped`).

### `GET /api/console`

The captured console ring, newest last, at most 2000 lines.
`{"text":"...","count":N,"available":true}`. Lines containing `token` or
`x-auth` (case-insensitive) are filtered out before the response, so a pasted
credential is never re-served.

### Port forwarding

| Method | Path | Body / query | Notes |
|---|---|---|---|
| `GET` | `/api/portmap` | – | Array of `{id, proto, wan_port, lan_ip, lan_port}`. |
| `POST` | `/api/portmap` | `{"proto":"tcp","wan_port":8080,"lan_ip":"192.168.0.50","lan_port":80}` | `proto` must be `tcp` (UDP forwarding is not implemented and is refused rather than silently stored). `lan_ip` must be a dotted quad; it is stored canonically. Ports are `1..65535`. A duplicate `proto:wan_port` is a `400`. |
| `DELETE` | `/api/portmap` | `?id=<id>` or `?index=<n>` | `404` when nothing matched. |

### Firewall bans

| Method | Path | Body / query | Notes |
|---|---|---|---|
| `GET` | `/api/bans` | – | Array of `{id, kind, value}`. |
| `POST` | `/api/bans` | `{"kind":"ip"\|"mac","value":"..."}` | The value is validated at the boundary; only these two kinds exist. Capped by `kMaxBans`. |
| `DELETE` | `/api/bans` | `?id=<id>` | `404` when nothing matched. |

### Rate limits

| Method | Path | Body / query | Notes |
|---|---|---|---|
| `GET` | `/api/ratelimit` | – | Array of `{mac, uplink_kbps, downlink_kbps}`. |
| `POST` | `/api/ratelimit` | `{"mac":"...","uplink_kbps":N,"downlink_kbps":N}` | Upsert by canonical MAC. Optional `replace_mac` deletes another rule in the same transaction. |
| `DELETE` | `/api/ratelimit` | `?mac=<mac>` | The MAC is canonicalised before lookup, so any legal spelling works. `404` when nothing matched. |

### DHCPv4 bindings and leases

| Method | Path | Body / query | Notes |
|---|---|---|---|
| `GET` | `/api/dhcp/leases` | – | Array of `{mac, ip, expires_in_s, is_static, hostname}`. |
| `GET` | `/api/dhcp/bindings` | – | Array of `{mac, ip, hostname}`. |
| `POST` | `/api/dhcp/bindings` | `{"mac":"...","ip":"...","hostname":"..."}` | `409 service not running` when the DHCP server is not assembled. Duplicate MAC → `400 binding exists`. Capped by `kMaxStaticBindings`. |
| `DELETE` | `/api/dhcp/bindings` | `?mac=<mac>` | `404` when nothing matched. |

### DHCPv6 bindings and leases

Same shape as v4, keyed by DUID text instead of MAC. DUIDs are compared by
parsed value, so upper case or a different separator style is the same binding.

| Method | Path |
|---|---|
| `GET` | `/api/dhcp6/leases` |
| `GET` | `/api/dhcp6/bindings` |
| `POST` | `/api/dhcp6/bindings` |
| `DELETE` | `/api/dhcp6/bindings?duid=<duid>` |

### Configuration

| Method | Path | Notes |
|---|---|---|
| `GET` | `/api/config` | The running config in the shape `POST` accepts. The auth token is **absent** by design. |
| `POST` | `/api/config` | Validates, writes atomically, then asks the running app to apply it. Because the body is a full replacement and omits the token, the running token is preserved. Keys the Web form does not own (`ui_language`, `ui_scale`, `bridge`, …) are preserved too. Returns the apply attempt id. |
| `GET` | `/api/config/apply-status` | `{attempt_id, completed_id, ok, error}`; poll until `completed_id` reaches your attempt id. |

A rejected config leaves the previous file untouched; the error names the field.

### Privileged operations

Both need a configured token even on loopback.

| Method | Path | Codes |
|---|---|---|
| `POST` | `/api/repair-driver` | `403` no token configured, `401` wrong token, `409` busy (a repair started less than 60 s ago), `503` unavailable, `200 {"requested":true}` |
| `POST` | `/api/autostart` | Same auth codes; body `{"enabled":true\|false}`; returns the value read back from the Run key |

### Static assets

`GET /` and `GET /index.html` serve the embedded SPA (RCDATA 24001), falling back
to `www/index.html` next to the executable for in-tree development.

## Status codes used

| Code | Meaning in this API |
|---|---|
| `200` | Success. |
| `400` | Malformed request, invalid or missing field, duplicate rule, limit reached. |
| `401` | A token is configured and the request did not carry it (or carried the wrong one). |
| `403` | A privileged route was called with no token configured. |
| `404` | The delete/lookup targeted something that does not exist, or no route matched. |
| `405` | The path exists but not for this method. |
| `409` | Conflict: DHCP service not running, or a privileged operation already in flight. |
| `500` | Handler exception; the response is generic and the detail goes to the local log only. |
| `503` | The callback behind a privileged route is not wired in this build. |

An over-sized body, an over-long path and a time-out are all reported as `400`
with the specific reason in the JSON `error` field; the server never relies on
`413`/`408`.

Every response carries `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`
and `Cache-Control: no-store`.

## Example

```bat
curl -H "X-Auth-Token: %VGWW_TOKEN%" http://127.0.0.1:8080/api/status
curl -X POST -H "X-Auth-Token: %VGWW_TOKEN%" -H "Content-Type: application/json" ^
     -d "{\"proto\":\"tcp\",\"wan_port\":8080,\"lan_ip\":\"192.168.0.50\",\"lan_port\":80}" ^
     http://127.0.0.1:8080/api/portmap
```
