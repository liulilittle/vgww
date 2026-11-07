# 内部实现

本页是维护者的地图：进程如何连接、哪个线程拥有什么、以及一个改动必须不破坏哪些不变量。它补充了 [architecture.md](architecture.md)，后者描述路由器 *做什么*。

## 模块地图

| 目录 | 职责 |
|---|---|
| `src/core` | 配置（解析/校验/原子保存）、日志、内存后端切换、UTF-8 消毒、随机数、限制 |
| `src/dsp` | 无等待 SPSC 环与帧分类器（数据通路上唯一的跨线程原语） |
| `src/driver` | WinpkFilter 客户端（`ndisrd`）、网卡枚举、驱动安装/卸载、`error_class`（将 NTSTATUS/errno 映射为用户可见的类别） |
| `src/proto` | 帧编解码器与服务器：以太网/ARP/ICMP/UDP/DHCP/DHCPv6/NDP |
| `src/relay` | 每协议中继：`TcpRelay`（泵）、`UdpFlowTable`/`UdpRelay`（每流 NAT）、`IcmpRelay`（tag NAT）、`PortMapManager`（UPnP/NAT-PMP + 端口转发） |
| `src/runtime` | `Dataplane`：线程、环、注册表、DHCP/NDP 连接、生命周期 |
| `src/tables` | 邻居表（RCU 快照）、限速器 |
| `src/bridge` | 下游与上游端口之间的 802.1Q 桥 |
| `src/ui` | 原生 UI：元素树、控件、窗口、渲染器、页面、托盘、i18n、调试通道 |
| `src/web` | 嵌入式 HTTP 服务器与 SPA 后面的 JSON API |
| `scripts/` | 十个门禁 + 原生 i18n 资源生成器 |
| `tools/` | 浸泡工具、UI 截图/差异门禁 |

## 线程

| 线程 | 拥有 | 不得 |
|---|---|---|
| RX/TX（一个） | `driver::Client`、两组 SPSC 环、原始帧批次、NDP 计时器 | 触摸中继 socket 或 xtcp 分片 |
| Worker *i*（N 个） | xtcp 分片 `{i, i+N, …}`、`io_contexts[i]`、`udp_tables[i]`、`icmp_relays[i]`、*i* 的注册表/接受/中止状态 | 触摸另一个 worker 的分片、表或 io_context |
| 控制（一个） | 周期性维护：DHCP/NDP 清扫、端口映射轮询、遥测快照 | 数据通路任何部分 |
| UI / Web | 渲染、HTTP、配置编辑（通过 `Dataplane` 的公共 API） | 直接触摸环、中继或栈 |

分片亲和性是负载承载规则：**一条流的帧、其协议处理、以及该流的所有 asio 完成事件都在同一个 worker 上运行**。`StartMimt` 将已接受的流路由到 `ShardIndexOf(conn_id) % worker_count`，worker 则只调度自己拥有的分片。打破此规则（例如从 `WorkerLoop` 中清扫其它 worker 的分片）会导致一个 socket 上出现并发 asio 使用。

## 跨越线程边界

唯一原语是 `dsp::SpscRing<T>`：

* 一个生产者、一个消费者、无等待；
* 自由运行的 64 位索引、槽地址用 `index & mask`、容量向上取整为 2 的幂；
* **满环 push 返回 false，调用者丢弃** —— RX 线程永不阻塞，丢弃被计数（`rx_dropped`）。

`TxFrame` 所有权移入环内，因此 UDP 回复路径每回复分配一个 `std::vector`：缓冲区必须比 worker 调用存活更久。

## 生命周期：拆除是最难的部分

中继可能因四种原因结束，且它们不可混淆：

| 原因 | 路径 | 客户端看到 |
|---|---|---|
| 上游 EOF | `TcpRelay::Finish(true)` → `QueueTeardown(graceful=true)` | FIN |
| 上游错误 / 重置 | `Finish(false)` | RST |
| 客户端重置 / 栈回收流 | `FinishFromFlow()` | 无（已消失） |
| 拨号超时 / 连接失败 | `QueueTeardown(false)` | RST |

`QueueTeardown` 只在 worker 的中止互斥量下追加；worker 的 `DrainAborts` 在所属线程上执行 `stack->Close()`/`Abort()`。`Finish` 是恰好一次（`finished_` 标记），并取消重试计时器。

注册表仅在中继真正结束时清扫：`hooks_.on_finished` 设置 `registry_dirty[i]`，`SweepRegistry(i)` 清除它并删除已完成的条目。因此空闲 worker 永不遍历注册表（否则空闲 CPU 会与活跃连接数成正比）。

`NotifyPeerFin(conn_id)`（客户端 FIN）使用每个 worker 的 `relay_index_`（`unordered_map<conn_id, weak_ptr<TcpRelay>>`）进行单次哈希查找，然后**总是将 socket 触发发布到所属 worker**；FIN 是在喂给该段的 worker 上交付的，而该 worker 不一定是所属 worker。

## 状态存储

* **UDP 流** — `UdpFlowTable`，每个 worker：LRU 列表 + 哈希映射，空闲超时 60 秒，硬上限 `perf.udp_flow_cap`。淘汰会关闭 socket，这样待处理的 `async_receive` 就不会变成幽灵。哈希折叠**两个端口**并雪崩；若哈希只混合地址，则一个客户端的所有流都会坍缩进 MSVC 的一个桶里。
* **ICMP** — `IcmpRelay::TagAllocator`：标签 `1..65535` 从空闲列表中分发，3 秒过期，一次回复消耗其标签。`0` 表示“池满”，永不是有效标签。
* **邻居** — RCU 方式：读取者加载一个 `shared_ptr<const NeighborSnapshot>`；重建路径是唯一写入者。
* **DHCP / DHCPv6** — 每个背后都有一个互斥量的租约存储，仅控制平面使用。OFFER 将地址钉住 60 秒，DECLINE 将其停放 600 秒，租约在干净的 `Stop()` 时转储，以便重启保持映射。
* **中继注册表 / 索引** — 每个 worker，启动时根据 `perf.max_conns`（`runtime::PerWorkerReserve`）预分配，因此连接路径永远不会在注册表互斥量下重新分配。

## 改动必须保持的不变量

1. 每个分片一个线程；分片的对象只被一个 worker 触摸。
2. RX 线程永不阻塞；满即丢弃并计数。
3. 每个已接受的流最终要么被拆除，要么被清扫——没有幽灵持有 socket。
4. `Finish` 每个中继只运行一次；重试计时器恰好取消一次。
5. 弱 `conn_id` 索引条目只在仍指向正在清扫的中继时才被删除（id 被重用）。
6. 配置写入是原子的（临时文件 + 重命名）；失败的写入留下旧文件完整。
7. Web token 比较是恒定时间；当前 token 永不返回给 UI。
8. 帧构建器从不信任 wire 长度：每次长度都针对实际缓冲区验证，然后再用于分配或拷贝。
