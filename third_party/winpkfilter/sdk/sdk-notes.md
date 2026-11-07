# WinpkFilter 3.6.2.1 SDK/头文件核查笔记(S3-Task1)

- 执行者:子代理;日期:2026-09-19;主机:Windows 11 Enterprise Build 26200 (x64)
- 任务:核实 `IOCTL_NDISRD_SET_HW_PACKET_FILTER` / `IOCTL_NDISRD_GET_HW_PACKET_FILTER` 与 `NDIS_PACKET_TYPE_PROMISCUOUS` 的官方定义;获取官方 SDK 头文件。
- 边界:仅下载/落盘文档,未改任何产品代码,未 commit,未安装驱动。

## 0. 结论(先读)

1. 官方 WinpkFilter 3.6.2.1 SDK **不存在** `IOCTL_NDISRD_SET_HW_PACKET_FILTER` / `IOCTL_NDISRD_GET_HW_PACKET_FILTER` 这两个 IOCTL 宏(任何官方制品零命中,详见 §2)。禁止自行定义或臆造码值。
2. 官方等价能力是**函数**接口 `SetHwPacketFilter` / `GetHwPacketFilter`(C 与 C++),其实现 = `NdisrdRequest()` + `OID_GEN_CURRENT_PACKET_FILTER`,底层 IOCTL 为 `IOCTL_NDISRD_NDIS_SET_REQUEST` / `IOCTL_NDISRD_NDIS_GET_REQUEST`(本地 Common.h 已含,详见 §3)。
3. 过滤器位常量 `NDIS_PACKET_TYPE_PROMISCUOUS = 0x00000020` 属于 **Windows WDK/SDK 头 `ntddndis.h`**(官方文档明确如此指引,详见 §4);本机已安装该官方头(Windows Kits 10.0.26100.0)。
4. 本地 `third_party/ndisapi/Common.h`(55,319B)与官方 v3.6.2 `include/Common.h`(54,277B)**内容逐行完全一致**,差异仅为行尾(CRLF vs LF,差 1042 字节 = 1042 行 × 1 字节);两文件均含 **37** 个 `#define IOCTL_NDISRD_*`(非 39)。
5. 官方源码包 license = MIT(库/示例源码);驱动本体商用再分发需 NT KERNEL 商业许可(详见 §5)。

## 1. 官方来源与归档

- 源码包(整包,原始文件名保留在解包树中):
  - URL:`https://codeload.github.com/wiresock/ndisapi/zip/refs/tags/v3.6.2`(官方仓库 wiresock/ndisapi,tag v3.6.2;官方 releases 页 https://github.com/wiresock/ndisapi/releases/tag/v3.6.2)
  - 落盘:`sdk\wiresock-ndisapi-v3.6.2.source.zip`,503,843 B,SHA256 `3B87260255885FDB39FEC0CC7AA46D907B26F9A642869FBDEDA320B2449CBCC0`
  - 解包:`sdk\ndisapi-3.6.2\`(Expand-Archive)
- 关键文件(解包树内,路径相对 `sdk\ndisapi-3.6.2\`):

| 文件 | 大小(B) | SHA256 |
|---|---|---|
| LICENSE | 1070 | B12F4CFCCE43CEF59100CF8C4EAF67AE5246C9A047E00F6059655F6694030EFE |
| include\Common.h | 54277 | 645127BD237E28783C41054C6102D86D7C60EADB168F93C4317718D984CB3E7E |
| include\ndisapi.h | 16560 | 9669E7F7682608D6B0026E8C06E04081B259C028B5B3168AB83DCFA80FEAD630 |
| ndisapi\ndisapi.cpp | 163223 | 94894281A25E161D244CCC58ADFB3F645B042B76823FF0D1F0BFD0412C36C0B3 |
| examples\cpp\ethernet_bridge\EthernetBridge.cpp | 13649 | BCCB017F962559D2DA3735C6D638050EE643EFF5EAF56C6E907961D834764665 |
| examples\cpp\ethernet_bridge\NetworkAdapter.h | 8208 | 575A81AA0FCD2977D6D227A9E3C1BC4329103DF371CA72EFCBAC74DFB82A8340 |

- 版本:tag v3.6.2(asset 版本 3.6.2.1);`include\Common.h` 内 `#define NDISRD_VERSION 0x06013000`。
- 辅助取证文件(置于 `sdk\`,非产品代码):

| 文件 | 大小(B) | SHA256 | 用途 |
|---|---|---|---|
| Common-v3.2.24.h | 21366 | B0199F54B22F4EB198355352835B6A27DD264EE69DA9245083869F320060B98A | 旧 tag 头文件,查宏存在性 |
| Common-v3.4.0.h | 22071 | 6E06A503429D461EE0EA6B5981ACDA7686B599C36AE06D2740B40268878CF14F | 旧 tag 头文件,查宏存在性 |
| ndisapi-go-ioctl.go | 5901 | 061F9AD8F721A25D73E01253454DEA819DAE4AB3F317080397FD6881C88251D9 | 官方组织 wiresock/ndisapi-go 的 IOCTL 全表,交叉核对 |

## 2. 目标 IOCTL 宏:全渠道零命中(禁止虚构)

以下检索均为固定字符串 `HW_PACKET_FILTER` / `IOCTL_NDISRD_SET_HW_PACKET_FILTER`:

| 官方制品 | 结果 |
|---|---|
| v3.6.2 include\Common.h(37 个 `IOCTL_NDISRD_*`) | 0 命中 |
| v3.6.2 全源码树(含 ndisapi.cpp / ndisapi.net / legacy 示例) | 0 命中(仅函数名 SetHwPacketFilter/GetHwPacketFilter) |
| tag v3.2.24 include\Common.h | 0 命中 |
| tag v3.4.0 include\Common.h | 0 命中 |
| wiresock/ndisapi-go `ioctl.go`(官方 IOCTL 全表) | 0 命中 |
| 官方 API 参考文档(ntkernel.com/docs/…/ndisapi-c-2/ 与 c-api/ 索引) | 仅列出函数 SetHwPacketFilter / GetHwPacketFilter / SetHwPacketFilterEvent,无同名 IOCTL 条目 |

结论:该 IOCTL 名称并非官方 3.x 接口;S3 桥接必须走 §3 机制或 §4 常量语义,不得定义该宏。

## 3. 官方等价机制(ndisapi.cpp 逐字证据)

`ndisapi\ndisapi.cpp` L1607 起(官方 SetHwPacketFilter 实现核心行):

```cpp
1607: BOOL CNdisApi::SetHwPacketFilter(HANDLE hAdapter, const DWORD Filter) const
1615:         pPacket->Oid = OID_GEN_CURRENT_PACKET_FILTER;
1619:         bRet = NdisrdRequest(pPacket, TRUE);
1650:         pPacket->Oid = OID_GEN_CURRENT_PACKET_FILTER;      // GetHwPacketFilter
1653:         if (NdisrdRequest(pPacket, FALSE))
```

`NdisrdRequest` 实际下发 IOCTL(`ndisapi\ndisapi.cpp`):

```cpp
1483:                 (DWORD)Set ? IOCTL_NDISRD_NDIS_SET_REQUEST : IOCTL_NDISRD_NDIS_GET_REQUEST,
1517:         static_cast<DWORD>(Set) ? IOCTL_NDISRD_NDIS_SET_REQUEST : IOCTL_NDISRD_NDIS_GET_REQUEST,
```

本地 `third_party\ndisapi\Common.h` 已含这两个 IOCTL(38 处 `IOCTL_NDISRD_*` define 行中的 2 条),**无需新增任何 IOCTL**。官方文档原文(NdisrdRequest 页):"This member wraps two I/O control codes: `IOCTL_NDISRD_NDIS_SET_REQUEST` and `IOCTL_NDISRD_NDIS_GET_REQUEST`."

官方示例调用点(混杂模式启用/恢复蓝本):
- `examples\cpp\ethernet_bridge\EthernetBridge.cpp:202`: `adapters[index]->set_hw_filter(NDIS_PACKET_TYPE_PROMISCUOUS)`
- `examples\cpp\ethernet_bridge\NetworkAdapter.h:58`: `api_.SetHwPacketFilter(current_mode_.hAdapterHandle, filter)`
- `examples\cpp\ethernet_bridge\EthernetBridge.cpp:207`(随后置模式): `MSTCP_FLAG_SENT_LISTEN | MSTCP_FLAG_RECV_LISTEN | MSTCP_FLAG_FILTER_DIRECT | MSTCP_FLAG_LOOPBACK_BLOCK`

## 4. 常量来源(WDK 官方头,逐字)

- 本机官方头:`C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\shared\ntddndis.h`
  - 大小 422,655 B;SHA256 `C2D369A293E68FB895BE2C2D7AFAD55AF098CA395363F709C8C7EB6611852A40`

```c
// L475
#define OID_GEN_CURRENT_PACKET_FILTER           0x0001010E
// L2725-2739
// Ndis Packet Filter Bits (OID_GEN_CURRENT_PACKET_FILTER).
#define NDIS_PACKET_TYPE_DIRECTED               0x00000001
#define NDIS_PACKET_TYPE_MULTICAST              0x00000002
#define NDIS_PACKET_TYPE_ALL_MULTICAST          0x00000004
#define NDIS_PACKET_TYPE_BROADCAST              0x00000008
#define NDIS_PACKET_TYPE_SOURCE_ROUTING         0x00000010
#define NDIS_PACKET_TYPE_PROMISCUOUS            0x00000020
#define NDIS_PACKET_TYPE_SMT                    0x00000040
#define NDIS_PACKET_TYPE_ALL_LOCAL              0x00000080
#define NDIS_PACKET_TYPE_GROUP                  0x00001000
#define NDIS_PACKET_TYPE_ALL_FUNCTIONAL         0x00002000
#define NDIS_PACKET_TYPE_FUNCTIONAL             0x00004000
#define NDIS_PACKET_TYPE_MAC_FRAME              0x00008000
#define NDIS_PACKET_TYPE_NO_LOCAL               0x00010000
```

- 官方文档指引(SetHwPacketFilter 页原文):"The constants that define the filters are declared in the file ntddndis.h."(URL: https://www.ntkernel.com/docs/windows-packet-filter-documentation/ndisapi-c-2/sethwpacketfilter/)
- 用户态可用性链(解释官方 example 为何不显式 include):`um\iphlpapi.h:1447 #include <netioapi.h>` → `shared\netioapi.h:152 #include <ntddndis.h>` → 常量可用。VGWW 若已包含 `IPHlpApi.h`/`netioapi.h` 即可直接使用;否则显式 `#include <ntddndis.h>`。
- 旁证(官方 3.6.2 仓库内旧语言示例同样用此值):`examples\legacy\CSharp\PacketSniffer\Program.cs:57` 字面量 `0x00000020/*NDIS_PACKET_TYPE_PROMISCUOUS*/`;`examples\legacy\Delphi\PacketSniffer\PacketSniffer.dpr:23` `NDIS_PACKET_TYPE_PROMISCUOUS = $20`。

## 5. License / 再分发

- 官方源码包 `LICENSE`(MIT):
  - "MIT License / Copyright (c) 2018 Vadim Smirnov / Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files ... to deal in the Software without restriction ..." (全文见 `sdk\ndisapi-3.6.2\LICENSE`,SHA256 B12F4C…)
  - 适用范围:该 GitHub 仓库内 **ndisapi 库与示例源码**。
- 驱动本体许可(官方 licensing 页 https://www.ntkernel.com/windows-packet-filter/licensing/,2026-09-19 抓取):
  - "Windows Packet Filter is free for personal or educational use, including non-profit organizations."
  - 软件发布者(商用再分发)需商业许可:**Developer(Binary)$3000** 或 **Source Code $9000**(各含 1 年更新与 1 次定制构建)。
- 对 VGWW 的含义:个人/教育/非营利本机使用免费;若对外发布产品需按上述许可取得授权。本任务仅取库源码(默认分支仓库许可)与 WDK 常量,无再分发驱动源码行为。

## 6. 落盘清单(`E:\vgww\third_party\winpkfilter\sdk\`)

- `wiresock-ndisapi-v3.6.2.source.zip`(503,843 B)
- `ndisapi-3.6.2\`(官方源码树,原始文件名;含 LICENSE、include\Common.h、include\ndisapi.h、ndisapi\ndisapi.cpp、examples\…)
- `Common-v3.2.24.h`(21,366 B)、`Common-v3.4.0.h`(22,071 B)、`ndisapi-go-ioctl.go`(5,901 B)——取证文件
- 本笔记 `sdk-notes.md`

## 7. 本地与官方 Common.h 差异证明

- 官方 `sdk\ndisapi-3.6.2\include\Common.h`:LF 换行 1042 处,CRLF 0,BOM 无,54,277 B
- 本地 `third_party\ndisapi\Common.h`:CRLF 1042 处,LF 0,BOM 无,55,319 B(= 54,277 + 1,042)
- `Compare-Object` 行集合差集 = 0(逐行内容一致);`NDISRD_VERSION` 均 `0x06013000`;`#define IOCTL_NDISRD_*` 计数均 37。
- 结论:本地头即官方 v3.6.2 头(仅行尾风格不同),无需替换;缺失的只是"不存在的 IOCTL"与"WDK 常量",按 §3/§4 处理。
