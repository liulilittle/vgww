# 配置说明

[English](../en/configuration.md)

VGWW 从 JSON 配置文件读取配置（`--config=vgww.json`）。命令行覆盖参数：`--adapter=<网卡名>`、`--web-only`、`--help`。

## 完整参考

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

## 字段说明

| 字段 | 含义 |
|---|---|
| `mode` | `bypass`（默认）或 `main`。`main` 才启用地址分配服务（DHCPv4/DHCPv6/RA）；`bypass` 下这些服务一律不装配，客户端自行配置或使用别的 DHCP |
| `adapter` | 网卡友好名或 GUID 子串，大小写不敏感匹配；友好名支持别名等值（如 `Ethernet` ↔ `以太网`），实例序号按「名称 + ASCII 空格 + 数字」严格匹配（`Ethernet 2` ↔ `以太网 2`，`Ethernet` 不匹配 `以太网 2`）；留空表示取首个适配器；无法匹配时数据面降级，按控制台错误中的候选清单用 `--adapter=<名称>` 或修改本文件 |
| `gateway.ipv4` | 客户端使用的虚拟网关地址。**绝对不能绑定在主机协议栈上**（否则主机会自己应答客户端流量）。`0.0.0.0` 会被拒绝 |
| `gateway.mask` | 局域网掩码。必须非零且为连续的 1 前缀（如 `255.255.255.0`）；host-style 掩码会被拒绝 |
| `gateway.mac` | 虚拟网关 MAC；对 `gateway.ipv4` 的 ARP 请求用它应答 |
| `ipv6.ula_prefix` | SLAAC 通告的 ULA 前缀（`ipv6.enabled` 时必填）。接受裸地址（`"fdaa:0:0::"`）或带前缀长度的地址（`"fdaa:0:0::/48"`，默认 64）。必须是 ULA（`fc00::/7`）且前缀长度之外不得有主机位 |
| `ipv6.prefix_len` | 通告的子网长度，`[1, 64]`（SLAAC 主机需要 64 位接口标识）。若 `ula_prefix` 携带 `/len`，两者必须一致 |
| `ipv6.ra_lifetime_s` | RA 路由生存期，`[1, 65535]`。`0` 会撤销默认路由，>65535 会在 16 位 RA 字段中截断回绕 |
| `ipv6.dns` | 通过 RA 的 RDNSS 选项（RFC 8106，type 25）下发给 SLAAC 客户端的 v6 DNS 递归服务器，使纯 SLAAC 客户端也能解析域名。为不带 `/len` 的完整地址数组，最多 3 个。默认空数组不发射 RDNSS，保持旧行为 |
| `dhcp.enabled` | 启用内置 DHCPv4 服务端（仅 `mode: main` 生效）。`false`（默认）时不装配、不落盘、不扫描 |
| `dhcp.pool_start` / `dhcp.pool_end` | 动态地址池范围（含两端），必须落在 `gateway.ipv4`/`gateway.mask` 所在子网内且 `pool_end >= pool_start` |
| `dhcp.lease_hours` | 租约时长（小时），`[1, 8760]`；默认 12 |
| `dhcp.dns` | DHCPv4 下发的 DNS 服务器数组（最多 3 个），缺省时使用主机当前 DNS |
| `dhcp.static_bindings` | 静态绑定数组（`mac`/`ip`/可选 `hostname`），最多 1024 条；MAC 与 IP 均不得重复 |
| `ipv6.dhcpv6.enabled` | 启用有状态 DHCPv6 服务端（RFC 8415 子集；需 `mode: main` 且 `ipv6.enabled`） |
| `ipv6.dhcpv6.pool_start` / `pool_end` | v6 动态池，必须落在 `ula_prefix` 前缀内；两界全零时按规范派生 `prefix::1000`–`prefix::1fff` |
| `ipv6.dhcpv6.lease_seconds` | v6 租约时长（秒），`[60, 31536000]`；默认 3600。T1/T2 分别为 0.5/0.8 倍租期 |
| `ipv6.dhcpv6.static_bindings` | v6 静态绑定（`duid` 十六进制串/`ip`/可选 `hostname`），最多 1024 条；DUID 与 IP 均不得重复 |
| `perf.workers` | 工作线程数 `[1, 8]`（xtcp 分片数）；worker *i* 泵分片 *i, i+8, ...* |
| `perf.rx_batch` | 每次 `ReadPackets` 的帧数，`[1, 4096]` |
| `perf.max_conns` | 并发 TCP 流硬上限（`[1, 1048576]`）；内存 ≈ max_conns × 128 KiB |
| `perf.udp_flow_cap` | 每 worker UDP 流表上限（`[1, 65536]`，默认 8192） |
| `perf.ring_capacity` | 每 worker SPSC 环形队列描述符数（`[1, 1048576]`）。`0` 会让数据面对每一帧解引用空环而崩溃 |
| `perf.dial_timeout_ms` | 上游 TCP 拨号超时（`[1, 3600000]`） |
| `web.port` | 管理 UI 监听端口，`[1024, 65535]`（默认 8080）；特权端口与临时端口会被拒绝 |
| `web.bind` | 管理 UI 监听地址（默认 `127.0.0.1`）；为空或超过 256 字节会被校验拒绝。**不会**隐式绑定所有网卡——需要局域网访问时显式配置 |
| `web.token` | 设置后所有非 GET `/api/*` 调用必须携带 `X-Auth-Token: <token>`（或 `Authorization: Bearer <token>`），否则返回 401。**面向局域网部署务必设置**——否则任何设备都能改写配置 |
| `vlan.id` | 启用单个 802.1Q access VLAN，`[1, 4094]`。显式 `0` 与 `4095` 是 802.1Q 保留码点，**会被校验拒绝**；省略 `id` 字段（或整个 `vlan` 段）即关闭。入方向带该 VID tag 的帧在路由前剥 tag，所有回复帧重新打上该 tag（单 VLAN trunk/access 网关）。其它 VLAN 的帧默认隔离（丢弃）。不支持 Q-in-Q；启用 802.1Q 后帧长预算减少 4 字节（固定 1514 接口缓冲区只能容纳最多 1510 字节的 tagged 回复帧） |
| `bridge.enabled` | 启用内置双网卡 L2 桥（默认 `false` 关闭）。与 `mode` 独立——`bypass` 下桥仍可用 |
| `bridge.upstream` / `bridge.downstream` | 两端网卡名（`enabled: true` 时均必填且必须不同）。仅适用单路径拓扑；**无 STP/RSTP**，镜像端口/环路环境禁用。当前实现要求 upstream 为主适配器（`adapter`） |
| `bridge.mac_table_size` | MAC 学习表容量，`[1, 65536]`，默认 4096。`0` 或超上限会被校验拒绝 |

## 校验规则

* 网关掩码必须非零且连续，网关地址本身不得为 `0.0.0.0`。
* `perf` 各类容量、`ipv6.ra_lifetime_s`、`web.port`、`vlan.id` 均做范围校验；越界值直接报配置错误，不再于运行时静默回绕/截断。
* `ipv6.enabled` 时必须有合法的 ULA 前缀。
* `mode: bypass` 下 DHCPv4/DHCPv6/RA 均不装配（即使各自 `enabled: true`）；`mode: main` 且对应 `enabled: true` 时才装配，且 `ipv6.enabled=false` 会同时关闭 RA 与 DHCPv6。
* 未知的命令行参数会被拒绝。
* 缺少 `gateway` 段是致命错误。
* 桥：`enabled: true` 时 `upstream`/`downstream` 均不能为空且必须不同；`mac_table_size` 越界（`0` 或 >65536）拒绝。桥默认关闭；开启需驱动混杂模式权限（可能需要管理员/驱动重装）。WLAN 端口 v1 不支持；标准驱动版 MTU≤1500。主机侧桥接（Windows 网桥/Hyper-V 虚拟交换机）未经验证，不受支持；不要把内置桥与它组合使用。

## WebUI

内嵌 HTTP 服务器**默认开启**（`web.enabled` 默认 true）；`--no-web` 关闭它，`--web` 强制开启（最高优先级），`--web-only` 仅启动 WebUI（无需驱动）。它监听 `web.port`（默认 8080），并绑定 `web.bind`（默认 `127.0.0.1` 回环；如需局域网访问请显式配置为监听地址，**不会**隐式绑定所有网卡）：

* **Dashboard** — 实时计数器与客户端列表
* **Port Mapping** — 主机端口 → 局域网客户端转发规则
* **Firewall** — MAC/IP 黑名单
* **Rate Limit** — 按客户端上行/下行限速（令牌桶）
* **Settings** — 运行配置视图；POST `/api/config` 保存经校验的配置文件（重启后生效）

`/api/status` 顶层含 `bridge` 对象：`enabled`/`upstream`/`downstream`（取自配置）、`mac_count`（已学习 MAC 数）、`state`（`stopped`/`running`/`failed`）。关闭态为 `enabled=false`、`state="stopped"`、`mac_count=0`。

写保护：设置 `web.token` 后，所有变更调用（POST/DELETE）须在 `X-Auth-Token`
头中携带相同值。

`--web-only` 只启动 WebUI（无需驱动）而 `--headless` 关闭原生窗口（保留 1s 控制台统计循环）；`--minimized` 让原生窗口启动时隐藏到托盘。
