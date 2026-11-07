# 架构设计

[English](../en/architecture.md)

本文描述 VGWW 的实际工作方式：线程模型、数据通路、协议模块，以及每个决策背后的理由。文中所有陈述都对应 `src/` 中的代码。

## 硬约束

**所有客户端流量必须以用户态 socket 从主机重新发起。** 这正是 VPN 能工作的原因：重拨的连接走本机路由表、自动进入 VPN 虚拟网卡。直接向物理网卡写原始帧会绕开 VPN——VGWW 绝不这样做。这一条规则塑造了整个架构：TCP 采用终结+中继而非 L3 转发，根源在此。

## 线程模型

| 线程 | 数量 | 职责 |
|---|---|---|
| RX/TX | 1 | 批量读帧（`ReadPackets`）、分类、哈希派发；排空所有 worker TX 环并批量注入 |
| Worker | 8（= xtcp 分片数） | 泵自己的 xtcp 分片 + 自有 asio io_context + UDP/ICMP 中继表 |
| 控制面 | 1 | 邻居老化、tag 过期、统计 |

Worker *i* 泵 xtcp 分片 *i*。一条流的进包、协议处理、上游 socket 读写、回包构造全部在同一个核完成：稳态零跨线程交接。数据面唯一的同步原语是 SPSC 环的原子序。

## 三大杀手（锁/拷贝/切换）

* **锁**：SPSC 环无锁（cacheline 对齐索引上的 acquire/release）；xtcp 分片锁只被单线程触碰；邻居表读取 = 一次原子加载不可变快照（RCU 式发布）。
* **拷贝**：内核→用户（驱动）、用户→池块、池→socket 缓冲。以太头写入 xtcp 池块预留的 16 字节头空间——零搬移。中继缓冲直接作为 asio 缓冲。
* **切换**：有流量时全线程忙轮询；空闲时事件驱动休眠。上游 socket 挂在 worker 自己的 io_context 上，IOCP 完成在同一线程消费，零跨线程 post。

## 协议模块

| 模块 | 文件 | 行为 |
|---|---|---|
| VLAN 802.1Q | `runtime/dataplane.*` | 可选单 access VLAN（`vlan.id`）：入方向匹配 VID 的 tag 在分类前剥除，所有下行帧在唯一 `AppendDown` 汇点重新打 tag，其它 VLAN 的帧隔离（丢弃）；固定 1514 接口缓冲使 tagged 回复帧上限 1510 字节 |
| ARP | `proto/arp.*` | 应答虚拟网关 IP 的请求；被动学习覆盖静态 IP 客户端 |
| ICMP | `proto/icmp.*`、`relay/icmp_relay.*` | 发往网关的 ping 本地代答；客户端 ping 经 raw socket 中继，全局唯一 16 位标识符 NAT（3 秒过期） |
| NDP/RA | `proto/ndp.*` | 路由请求以路由通告应答（SLAAC 前缀+生命周期+源链路层选项）；针对网关自身地址的邻居请求以邻居通告应答；网关 v6 ping 本地代答 |
| TCP 中继 | `relay/tcp_relay.*` | MimtFlow ↔ 上游 socket 双向泵，端到端背压（v4/v6） |
| UDP 中继 | `relay/udp_relay.*` | 每流 connected-UDP socket（v4/v6），LRU 封顶表，60 秒空闲清扫 |
| 端口映射 | `relay/portmap_manager.*` | 每条规则一个 WAN 侧 acceptor；入站连接经 xtcp `Connect` 反向拨入局域网客户端，队列泵转发 |
| 防火墙 | `web/web_api.*` + 分发层 | MAC/IP 黑名单在帧分发处执行，控制线程周期刷新 RCU 快照 |
| WebUI | `web/http_server.*`、`web/web_api.*`、`www/` | 内嵌 HTTP/1.1 服务器（asio）、REST API、单文件 vanilla SPA 仪表盘 |

## IPv6 数据通路

* **TCP**：xtcp 以与 v4 相同的 mimt 钩子透明接受 v6 SYN；中继以 `make_address_v6` 拨号上游。
* **UDP**：流表键使用完整 16 字节地址；回程帧由 `BuildUdpFrameV6` 构造（IPv6 伪头校验和）。
* **控制面**：RA/SLAAC 让客户端获得宣告 ULA 前缀内的地址；NDP 应答保证邻居缓存指向网关。

## 背压

| 方向 | 拥塞点 | 传导机制 |
|---|---|---|
| 客户端 → 外网 (TCP) | MimtFlow 接收队列满 | `OnData` 返回 false → xtcp 窗口归零 → 客户端 RTO 重传 |
| 外网 → 客户端 (TCP) | 上游 socket 写不动 | 停读 socket → 主机栈窗口收缩 |
| UDP | socket 发送缓冲满 | 直接丢弃（UDP 语义）；流表封顶 |

系统任何地方都没有无界队列。内存占用启动即可算出：`max_conns × (64K 收 + 64K 发)` 加上固定的环/表尺寸。

## 测试策略

驱动边界是一个接口（`driver/idriver_client.h`）。测试绑定内存假实现：回放脚本化帧、捕获 VGWW 发出的一切——整条流水线在不装内核驱动的情况下原样运行（backtesting 原则：模拟边界，不模拟业务）。集成测试在帧级别脚本化一次完整 TCP 会话：SYN、解析 SYN-ACK、ACK、经本地 echo 服务器的载荷往返。

## 驱动装载与实机状态（S5 实测）

ndisrd 3.6.2.1 是 NDIS LWF（lightweight filter）驱动，必须经厂商 INF 框架装载：内建 `--install-driver`（`driver/installer.cpp`）即按此执行——`pnputil /add-driver <ndisrd_lwf.inf> /install` 把驱动发布到驱动库并绑定，再由 INetCfg 实例化网络组件并绑定物理网卡。（早期以普通内核服务直启——`CreateServiceW(SERVICE_KERNEL_DRIVER)`——的通道已退役：LWF 必须走 NDIS 框架，该旧方式实测装载失败 0x1F。安装/卸载与故障排查详见 `docs/{zh,en}/driver-install.md`。）驱动装载后，LWF 绑定期间**必须存在常驻消费端（本产品）且配置中的适配器名必须可解析**——适配器枚举在 LWF 绑定后呈 `\DEVICE\{GUID}` 形态（`ndisrd_client.cpp` 内含友好名→GUID 解析）。否则本机 TCP/IP 数据路径会被过滤栈挂起（S5 实测：无消费端时双网卡 ICMP/TCP 全部失效，卸载驱动后网络恢复）。绑定期适配器名匹配未命中不再静默：数据面降级并给出可操作错误（候选「友好名 => \DEVICE\{GUID}」清单 + `--adapter=<名称>` 或配置文件指引）；友好名匹配大小写不敏感并支持本地化别名（G-5）。

POC 状态：P1-P6 实机验证**未执行**（无对端注入设备、消费端缺陷未落地）。门禁：`poc-checklist` 未全 PASS 前**禁止声称"内置桥可用"**。

实机已达成：1h fake soak（无泄漏，稳态 ws/handles 零增长）；AppVerifier 实跑（web/dataplane_lifecycle/ui，XML 零 Error）；驱动装卸回环（MSI 装+卸载还原，网络恢复）。

## IPv6 / NAT66

Windows 没有内核 NDP proxy，上游网络也不会路由我们的客户端前缀，因此出口采用 NAT66 语义。在本架构中 NAT66 由"终结+中继"自然涌现：v6 TCP 被 xtcp 终结后以主机地址重拨；v6 UDP 按流中继。客户端看到 ULA 地址，互联网看到主机地址。v6 的实际工作量只在控制面：NDP 应答、RS/RA、DAD。

## 内存管理

VGWW 使用可替换内存池层（\src/core/memory.h\）。\core::Malloc/Free/Realloc\
路由到编译期内置后端：CMake 检测到 **jemalloc** 时（\-DVGWW_JEMALLOC=ON\，
默认搜索 vcpkg \x64-windows\ 安装，与 openppp2 使用同一套库），否则走
**CRT 堆**。选择在编译期完成，数据面零间接开销。

\core::PoolAllocator<T>\（\src/core/allocator.h\）通过
\core::PoolVector\ / \PoolString\ / \PoolMap\ 别名让任意 STL 容器适配
该后端。端口映射数据队列已改用 \PoolVector\；中继热路径使用固定
\std::array\ 缓冲，不按帧分配。所有分配按 64 字节对齐以确保 SIMD 安全
（jemalloc 兑现；CRT 仅保证 \max_align_t\ 即 16 字节）。

活动后端由 \gww.exe --version\ 报告。jemalloc 衰减（decay）设置保持默认，
与 vcpkg 原版构建一致。WebUI/API 载荷保持 \std::string\/\std::vector\
返回类型（公共 API 契约）；切换为池容器属于后续工作，刻意不在首轮迁移内。
