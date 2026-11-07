# 性能

本页说明 VGWW 的时间花在哪里、哪些参数真正有影响、以及如何测量而不是猜。下列数字都在开发机测得（Windows 11、8 核 x64、Release、MSVC 14.44），**只当作数量级参考，不是基准承诺**。

## 数据通路

```
驱动（WinpkFilter）──► RX 线程 ──分类器──► SPSC 环[worker]（无等待）
                                                │
                                  worker i ─────┘
                                    ├─ UDP  → 每流 socket NAT（UdpFlowTable）
                                    ├─ ICMP → 原始 socket 上的 tag NAT（IcmpRelay）
                                    └─ TCP  → xtcp 分片 i，然后 TcpRelay 泵
                                                │
                                  TX 环[worker] ──► RX/TX 线程 ──► 驱动
```

两条规则决定成本模型：

1. **一个分片一个线程，包路径上无锁。** 一条流的入帧、协议处理与 asio 完成事件都跑在拥有该分片的 worker 上；稳态转发不做任何互斥量操作。
2. **绝不阻塞 RX 线程。** 环满即丢弃并计数：TCP 靠重传恢复，UDP 本来就有损。改成排队只会把延迟尖峰转嫁给其它所有流。

## 实测基线

| 项目 | 结果 | 位置 |
|---|---|---|
| UDP 流哈希分布（4096 条流打同一服务器） | 最坏桶 **6–7** 项（雪崩修复前是 4096） | `tests/test_udp_relay.cpp`（`TestFlowHashSpreadsBuckets`） |
| 邻居表 tick（4096 项） | 10 Hz 下 **156.6 µs/次** ≈ 单核 0.16% | 本项目实测 |
| 全量单测/集成测试 | **49 个用例约 120 秒**（`ctest -C Release`） | 本地 + CI |
| CI 作业（配置+构建+测试+10 门禁） | `windows-latest` 上 **约 7 分钟** | GitHub Actions |
| UDP 回包路径每包分配 | **1 次** `std::vector`（所有权移交 TX 环） | `HandleUdp` 回包 lambda |

哈希那条最关键：MSVC 的 `unordered_map` 用哈希**低位**取桶，若哈希只混合目的地址，一个活跃客户端的所有流会落进同一个桶。实测就是每包 4096 项线性扫描；加入 Murmur3 `fmix64` 雪崩后修复，测试用 `max_bucket <= 64` 钉住。

## 真正有影响的参数

都在配置文件的 `perf` 下。

| 键 | 默认 | 作用 |
|---|---|---|
| `perf.workers` | 8 | worker 线程数；**worker *i* 拥有 xtcp 分片 *i***。多于分片数只会多出空转线程。 |
| `perf.ring_capacity` | 1024 | 每 worker SPSC 环深度。更大吸收突发，代价是内存与（轻微）缓存压力。 |
| `perf.rx_batch` | 64 | 每批弹出的帧数。更大摊薄索引读取，增加单次迭代延迟。 |
| `perf.max_conns` | 4096 | 存活 TCP 中继上限；同时用于**预分配**每 worker 的中继注册表与 `conn_id` 索引。 |
| `perf.udp_flow_cap` | 65536 | 每 worker UDP 流表上限（到顶按 LRU 淘汰）。 |
| `perf.dial_timeout_ms` | 10000 | 上游连接超时。超时即关闭 socket，中止 connect 并向客户端发 RST。 |

经验规则：

* `workers` 保持等于 xtcp 分片数（8）。多出来的线程只抢缓存行，不承担工作。
* 突发下看到 `rx_dropped` 上升，先加 `ring_capacity` 而不是加 `workers`——丢弃比上下文切换便宜。
* `max_conns` 是硬上限而非目标值：每 worker 容器按它一次性预留（`runtime::PerWorkerReserve`），配大只多花启动时几百 KB，每包零成本。

## 剩余时间的去向

每个转发包，worker 依次做：

1. 一次 acquire 读取，从环批量弹出；
2. 分类（RX 线程已完成，类别随 `RxItem` 带过来）；
3. 一次哈希查找（`UdpFlowTable::GetOrCreate`）+ 一次 LRU 摘挂；
4. 邻居条目的一次 `shared_ptr` 快照加载（单次原子操作，无拷贝）；
5. 构建帧到 `TxFrame`（一次分配，随后 move 进 TX 环）；
6. 一次 release 写入。

第 3–4 步是 O(1) 且无锁。第 5 步是稳态路径上唯一的堆分配；要消掉它需要固定槽位的 TX 环（帧池化），属于后续工作，不假装它免费。

## 空闲行为

空轮询会让 worker 睡 200 µs（`SleepFor`），因此空闲网关几乎不耗 CPU（实测：UI 与 WebUI 都在运行时仍 < 单核 0.5%）。代价是空闲后第一个包最多多 200 µs 延迟；有负载时环很少为空，睡不到。

## 如何测量一次改动

```bat
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DVGWW_JEMALLOC=OFF
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

* 微基准内嵌在单测里并打印数字（`[b316] ... buckets=...`、`B229 ...`），`ctest -V` 就是现成的测试台。
* 浸泡工具 `tools/soak.cpp`（目标 `vgww_soak`）用合成负载压数据面并报告吞吐/延迟。
* `vgww.exe --version` 报告分配器后端；开发构建默认 jemalloc，CI 关闭（`-DVGWW_JEMALLOC=OFF`）。

## 可以盯的诊断计数

| 计数 | 含义 | 处理 |
|---|---|---|
| `rx_dropped` | 环满或畸形帧 | 加大 `ring_capacity`，检查 `workers` |
| `portmap_send_dropped` | WAN→LAN 队列到 1024 上限 | 客户端不读，管理器会自行暂停读取 |
| `mac_misses` | 邻居条目老化，已发 ARP 探测 | 空闲客户端正常；持续偏高则异常 |
| UDP evictions | 达到 `udp_flow_cap`，LRU 淘汰 | 提高上限或排查流泄漏 |
| `tcp_accepted` | 进入拨号队列的流 | 与上游拨号失败日志对照 |

## 已知限制

* 支持 MSVC AddressSanitizer（`-DVGWW_ASAN=ON`）；**Windows 上不提供泄漏检测（LSan）**，所以"无泄漏"靠所有权纪律论证，而不是运行期检查器。
* 上面的数字来自单机单网卡；多队列 RSS 行为取决于 WinpkFilter 驱动配置，本页未测。
* `perf.workers` 允许大于 8，但没有多余分片可拥有。
