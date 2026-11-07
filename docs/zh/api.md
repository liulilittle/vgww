# HTTP 接口

管理界面由内嵌 HTTP/1.1 服务器提供。下列端点就是随附 SPA 使用的全部接口，没有另一套"内部 API"。

## 传输与分帧

* 纯 HTTP/1.1，每个请求 `Connection: close`（不支持 keep-alive 与流水线）。
* 请求行 + 头部必须在 16 KiB 内到达；请求体上限 `limits::kMaxConfigBytes`（1 MiB）。
* 路径只做一次百分号解码；非法转义返回 `400`。
* 路径超过 2048 字节或查询参数超过 64 个返回 `400`。
* `Content-Length` 必须是 `1*DIGIT` 且与实际请求体等长。重复头部、无 `:` 的行、冒号前有空白、以及任何 `Transfer-Encoding` 一律 `400`（请求走私防护）。
* 响应带显式 `Content-Length`；JSON 响应为 `application/json`。

## 认证

配置了 token 时，写操作（`POST`/`DELETE`/`PUT`）必须携带：

```
X-Auth-Token: <token>
Authorization: Bearer <token>
```

* 已配置 token 但缺失或错误 → `401`。
* 未配置 token → 写操作放行（仅回环场景），但下面两个特权路由例外，返回 `403`。
* token 比较是恒定时间且与长度无关。
* 任何端点都不会回传 token。
* 非回环 `web.bind` 配空 token 会使服务器完全不启动（见[配置说明](configuration.md#webui)）。

## 端点

### `GET /api/status`

仪表盘 2 秒轮询目标，必须保持轻量。返回网关标识、包计数、DHCP/DHCPv6 计数与顶层 `bridge` 对象。

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

每客户端限速状态：MAC、IPv4、当前上下行 bps 以及仪表盘表格用到的计数。

### `GET /api/system`

进程与吞吐遥测加标识行：`proc`（`cpu_percent`、`cores`、`ws_bytes`、`virt_bytes`）、`throughput`（`up_bps`、`down_bps`）、`version`、`memory`（后端名与版本）、`config_path`、`uptime_s`、`driver`（`running` / `stopped`）。

### `GET /api/console`

捕获的控制台环形缓冲，最新在后，最多 2000 行。`{"text":"...","count":N,"available":true}`。含 `token` 或 `x-auth`（不区分大小写）的行在响应前被滤除，粘贴过的凭据不会被再次下发。

### 端口转发

| 方法 | 路径 | 请求体 / 查询 | 说明 |
|---|---|---|---|
| `GET` | `/api/portmap` | – | `{id, proto, wan_port, lan_ip, lan_port}` 数组。 |
| `POST` | `/api/portmap` | `{"proto":"tcp","wan_port":8080,"lan_ip":"192.168.0.50","lan_port":80}` | `proto` 只能是 `tcp`（UDP 转发未实现，直接拒绝而不是静默存下一条永不生效的规则）。`lan_ip` 必须是点分四段；以规范形式存储。端口范围 `1..65535`。重复的 `proto:wan_port` 返回 `400`。 |
| `DELETE` | `/api/portmap` | `?id=<id>` 或 `?index=<n>` | 未命中返回 `404`。 |

### 防火墙封禁

| 方法 | 路径 | 请求体 / 查询 | 说明 |
|---|---|---|---|
| `GET` | `/api/bans` | – | `{id, kind, value}` 数组。 |
| `POST` | `/api/bans` | `{"kind":"ip"\|"mac","value":"..."}` | 值在边界处校验；只有这两种 kind。受 `kMaxBans` 限制。 |
| `DELETE` | `/api/bans` | `?id=<id>` | 未命中返回 `404`。 |

### 限速

| 方法 | 路径 | 请求体 / 查询 | 说明 |
|---|---|---|---|
| `GET` | `/api/ratelimit` | – | `{mac, uplink_kbps, downlink_kbps}` 数组。 |
| `POST` | `/api/ratelimit` | `{"mac":"...","uplink_kbps":N,"downlink_kbps":N}` | 按规范 MAC upsert。可选 `replace_mac` 在同一事务内删除另一条规则。 |
| `DELETE` | `/api/ratelimit` | `?mac=<mac>` | 查询前先规范化 MAC，任何合法写法都可用。未命中返回 `404`。 |

### DHCPv4 绑定与租约

| 方法 | 路径 | 请求体 / 查询 | 说明 |
|---|---|---|---|
| `GET` | `/api/dhcp/leases` | – | `{mac, ip, expires_in_s, is_static, hostname}` 数组。 |
| `GET` | `/api/dhcp/bindings` | – | `{mac, ip, hostname}` 数组。 |
| `POST` | `/api/dhcp/bindings` | `{"mac":"...","ip":"...","hostname":"..."}` | DHCP 服务器未装配时 `409 service not running`。MAC 重复 → `400 binding exists`。受 `kMaxStaticBindings` 限制。 |
| `DELETE` | `/api/dhcp/bindings` | `?mac=<mac>` | 未命中返回 `404`。 |

### DHCPv6 绑定与租约

形状与 v4 相同，键是 DUID 文本而非 MAC。DUID 按解析后的字节比较，因此大写或不同分隔符写法视为同一绑定。

| 方法 | 路径 |
|---|---|
| `GET` | `/api/dhcp6/leases` |
| `GET` | `/api/dhcp6/bindings` |
| `POST` | `/api/dhcp6/bindings` |
| `DELETE` | `/api/dhcp6/bindings?duid=<duid>` |

### 配置

| 方法 | 路径 | 说明 |
|---|---|---|
| `GET` | `/api/config` | 与 `POST` 接受的形状一致的运行配置。认证 token **故意缺席**。 |
| `POST` | `/api/config` | 校验、原子写盘，然后请求运行中的应用应用它。由于是整体替换且缺少 token，运行中的 token 会被保留；Web 表单不拥有的键（`ui_language`、`ui_scale`、`bridge` 等）同样保留。返回本次应用尝试的 id。 |
| `GET` | `/api/config/apply-status` | `{attempt_id, completed_id, ok, error}`；轮询到 `completed_id` 追上你的 attempt id。 |

被拒绝的配置不会改动旧文件；错误信息会指出具体字段。

### 特权操作

即使在回环上，也必须先配置 token。

| 方法 | 路径 | 状态码 |
|---|---|---|
| `POST` | `/api/repair-driver` | `403` 未配置 token、`401` token 错误、`409` 忙（60 秒内已启动过修复）、`503` 不可用、`200 {"requested":true}` |
| `POST` | `/api/autostart` | 认证状态码同上；请求体 `{"enabled":true\|false}`；返回从 Run 键读回的实际值 |

### 静态资源

`GET /` 与 `GET /index.html` 提供内嵌 SPA（RCDATA 24001）；资源缺失时回退到可执行文件旁的 `www/index.html`，供源码树内开发使用。

## 使用的状态码

| 码 | 在本 API 中的含义 |
|---|---|
| `200` | 成功。 |
| `400` | 请求畸形、字段非法或缺失、规则重复、达到上限。 |
| `401` | 已配置 token 但请求未携带（或携带错误）。 |
| `403` | 未配置 token 却调用了特权路由。 |
| `404` | 删除/查找目标不存在，或没有匹配的路由。 |
| `405` | 路径存在但不支持该方法。 |
| `409` | 冲突：DHCP 服务未运行，或特权操作正在进行。 |
| `500` | 处理器异常；响应是通用文案，细节只写本地日志。 |
| `503` | 特权路由背后的回调在本构建中未接线。 |

超大请求体、超长路径与超时同样以 `400` 返回，具体原因放在 JSON 的 `error` 字段里；服务器不依赖 `413`/`408`。

所有响应都带 `X-Frame-Options: DENY`、`X-Content-Type-Options: nosniff` 与 `Cache-Control: no-store`。

## 示例

```bat
curl -H "X-Auth-Token: %VGWW_TOKEN%" http://127.0.0.1:8080/api/status
curl -X POST -H "X-Auth-Token: %VGWW_TOKEN%" -H "Content-Type: application/json" ^
     -d "{\"proto\":\"tcp\",\"wan_port\":8080,\"lan_ip\":\"192.168.0.50\",\"lan_port\":80}" ^
     http://127.0.0.1:8080/api/portmap
```
