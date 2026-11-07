# 排障指南

先症状，后原因与修复。每条都映射到真实代码路径；引号内消息是程序打印的字符串。

## 网关启动了，但客户端无法上网

1. **驱动未安装。** 日志/UI 显示 `driver missing`，数据面保持降级态。在提升权限的命令提示符下运行 `vgww.exe --install-driver`，然后重新启动。卸载：`vgww.exe --uninstall-driver`，同时清除任何遗留的 `VGWW-GrantAccess` 开机任务。
2. **网卡选错。** `adapter` 接受友好名（`Ethernet`）或 `\DEVICE\{GUID}`。设置页列出已检测到的网卡及其链路状态、IPv4 地址，并在网卡断连或不在网关子网时发出警示。请从该列表中选取，而非手动输入。
3. **网关 MAC 无效。** 日志打印 `Invalid MAC address format`：`gateway.mac` 必须是 `aa:bb:cc:dd:ee:ff` 格式。这是客户端会 ARP 的 MAC，因此不能与真实网卡冲突。
4. **模式为 bypass。** `bypass` 模式下 VGWW 不做 NAT 而只转发 LAN —— LAN 需要上游有真实路由器。排查 NAT 前先确认 `mode`。

## "bind failed: ... already in use"

管理端口被占用（`web.port`，默认 8080）。停掉其它进程或改 `web.port`。`web.bind` 默认 `127.0.0.1`；绑定失败会出现在 UI 控制台和日志中。

## 客户端拿不到 DHCP 地址

* `dhcp.enabled` 必须为 true **且** `mode` 不能是 `bypass`；bypass 模式下服务器故意不组装（分发无法路由地址的 DHCP 服务器比沉默更糟）。
* 地址池必须落在 LAN 子网内，且在 `gateway.ipv4/mask` 内。池首尾地址、网络地址、广播地址及所有静态绑定地址都被拒绝作为动态候选。
* `[vgww] dhcp: pool exhausted (N total)` 就是字面意思：每个候选地址都被租出、保留或被拒。扩大池或缩短 `lease_hours`。
* 拒绝过地址的客户端会停放该地址 600 秒；收到 OFFER 后消失的客户端会钉住地址 60 秒。

## DHCPv6 / IPv6 客户端拿不到地址

* `ipv6.enabled` 必须为 true。VGWW 在 LAN 上回答 RA/SLAAC，并终止客户端的 TCP/UDP，所以客户端无需自己的全球可路由地址；`ula_prefix` 提供 LAN 前缀。
* UDP 端口转发尚未实现。UDP 规则不会打开 WAN 端口；只有 TCP 规则会被反向拨号。

## 重启后租约未恢复

租约文件写于**干净停止**时。杀进程（任务管理器、断电）会跳过 dump：没有活着的线程能安全序列化。日志中出现 `dhcp: lease dump failed on stop: <path>` 表示路径不可写——检查 `--config` 所用目录。

## 传输停滞，然后恢复

`portmap_send_dropped` 上升表示 WAN→LAN 队列达到 1024 条上限，因为 LAN 客户端停止读取；管理器暂停自身 WAN 读取以维持队列有限。这是背压，不是泄漏。

## 一条 UDP 流不再收到回复

若上游发送 ICMP 不可达（端口关闭、网络宕机），接收链必须存活：VGWW 对整个 ICMP 不可达族重挂，仅在 `operation_aborted` / `bad_descriptor` / socket 关闭时停止。若流仍静默，请检查是否被 LRU 淘汰（`perf.udp_flow_cap`）、上游报文是否小于 8 KiB 中继缓冲区——更大的报文会被内核截断，应改用 TCP。

## 第二次启动无反应

这是有意为之：VGWW 是单实例程序，第二次启动会聚焦正在运行的窗口（或托盘图标）。请使用托盘菜单或窗口，而非新进程。

## WebUI 返回 401

`X-Auth-Token` 值与配置的 token 不匹配。UI 永不回显 token；在设置中设新 token 并重新登录。清空字段即保持当前 token。

## 睡眠/插拔后 UI/控制台显示红色横幅

窗口在恢复时重置其几何尺寸与 DPI；若显示拓扑改变，尺寸会钳入当前工作区，而非恢复到屏幕外。如钳位明显错误，请提交报告并附上控制台页面内容。

## 空闲 CPU 高

* 查看 `rx_dropped`：环无法吸收持续流量意味着 `ring_capacity` 对突发太小。
* `perf.workers` 大于 xtcp 分片数（8）只会增加空转线程，不提升吞吐。
* 空轮询每次空 poll 睡 200 µs；UI、WebUI 和托盘都在运行时，单核几个百分点属预期范围。

## 日志与诊断

* 原生 UI 的控制台页显示与 `--config` 目录下旋转日志（`logs/`）相同的流。
* `vgww.exe --version` 报告分配器后端（jemalloc 或 CRT）。
* `--headless` 运行数据面而无原生 UI；`--web-only` 运行 WebUI 而无数据面，无需驱动——有助于隔离问题是在 UI、API 还是包通路。
