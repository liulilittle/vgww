# 驱动安装与许可说明

VGWW 的转发数据面需要一个 NDIS 轻量过滤器(LWF)驱动程序来接入网卡。本项目内置的是
**WinpkFilter(Windows Packet Filter)** 官方驱动,仓库已随附官方发布版二进制与安装包。

本页说明:驱动文件在哪、如何安装、如何卸载、出问题了怎么排查,以及开源分发相关的许可边界。

---

## 1. 驱动文件清单

仓库 `third_party/winpkfilter/` 下:

| 文件 | 用途 |
|---|---|
| `ndisrd.sys` | 内核驱动本体(win10/11 适用,x64) |
| `ndisrd_lwf.inf` | INF 安装脚本(含组件 GUID、绑定特征) |
| `ndisrd.cat` | 目录签名文件(INF 声明 `CatalogFile=ndisrd.cat`;**必需**,缺它 pnputil 装机必失败) |
| `Windows.Packet.Filter.3.6.2.1.x64.msi` | 官方安装包原件(备选安装路径) |
| `extract/PFiles64/.../drivers/{win7,win8,win10}/` | 官方解包树(各系统版本驱动) |
| `sdk/` | 官方源码与头文件(SDK,仅供编译引用) |

> **三件套必须同目录**:`ndisrd_lwf.inf`、`ndisrd.sys`、`ndisrd.cat` 必须放在**同一个目录**
> (vgww.exe 旁、`drivers/` 或 `win10/` 均可;混合放置会被安装器拒绝并提示缺哪个文件)。

**驱动签名**:已核实 `ndisrd.sys` Authenticode 签名有效(CN=The Anti-Cloud Corporation,EV 证书有效期内)。
**版本来源**:WinpkFilter v3.6.2(asset 3.6.2.1,2025-10-23 发布),官方 GitHub Release 渠道获取。

---

## 2. 快速安装(内置 `--install-driver`)

将 `ndisrd_lwf.inf`、`ndisrd.sys`、`ndisrd.cat` **三件套放在同一目录**(`vgww.exe` 同目录或
`drivers/` 子目录;官方解包树的 `win10/` 原样目录也可),然后**以管理员身份**运行:

```bat
vgww.exe --install-driver
```

内部行为(实测核对过源码 `src/driver/installer.cpp`):

1. 校验三件套**同目录**齐备且大小正常(INF ≥ 1 KiB、SYS ≥ 4 KiB、CAT 非空;截断的文件会被拒绝,并列出缺失的文件名与已查找的目录);
2. 记录驱动库基线(baseline),清理历史遗留的旧 SCM 服务注册(若有);
3. `pnputil /add-driver ndisrd_lwf.inf /install` 把驱动发布到系统驱动库;
4. 经 INetCfg 实例化网络组件并绑定到物理网卡;若此步失败,回滚**只删除本次新发布的条目**(driver-store baseline 差集);
5. 对设备对象 `\\.\Ndisrd` 应用 DACL,使数据面能正常打开;
6. **不再注册任何开机任务**:旧版本注册的 `VGWW-GrantAccess` 任务会在安装/升级时被主动清理(幂等)。
   程序始终以管理员身份运行(清单 `requireAdministrator`),每次启动在进程内自动重授设备访问(见 `main.cpp`)。

退出码 0 = 成功。成功后驱动即可随网卡栈加载。

> 注意:VGWW 始终以管理员身份运行(manifest `requireAdministrator`);`--install-driver` 同样需要管理员 token。
> **升级/重装后**:以管理员重跑一次 `vgww.exe --install-driver`;安装器会主动清理旧版本遗留的
> `VGWW-GrantAccess` 开机任务(幂等),并重新应用设备 DACL。

---

## 3. 卸载(内置 `--uninstall-driver`)

以管理员身份运行:

```bat
vgww.exe --uninstall-driver
```

内部顺序:**先经 INetCfg 解绑**组件,再 `pnputil /delete-driver <oem##.inf> /uninstall` 删除驱动库条目
(全部 ndisrd 条目,含旧版本残留)。删除成功后**同时清理自愈/遗留产物**:遗留的开机任务 `VGWW-GrantAccess`、
`%ProgramData%\VGWW\vgww.exe` 镜像拷贝,以及旧的 System32 手动副本;任一项清理失败会以
「已卸载,但残留未清理:<原因>」报告。

即使驱动库中没有 ndisrd 条目(枚举为空),卸载也会清理上述自愈任务与镜像(带警告),**确保之后开机
不会静默重装驱动**。

退出码 0 = 成功;失败或存在未清理残留返回非 0。

---

## 4. 备选安装路径(官方 MSI)

如果内置安装器在你机器上遇到系统级问题(见第 5 节),可改用官方安装包手动安装:

```bat
:: 管理员
msiexec /i "third_party\winpkfilter\Windows.Packet.Filter.3.6.2.1.x64.msi"
```

MSI 会完成驱动签名安装与组件注册。装完后再正常启动 VGWW 即可。

---

## 5. 故障排查

| 症状 | 可能原因 | 处理 |
|---|---|---|
| `--install-driver` 提示"请以管理员身份运行" | 非管理员 token | 管理员 PowerShell 重跑 |
| 提示"驱动载荷不完整:缺少 xxx"(含已查找目录) | inf/sys/cat 三件套不齐、放错目录或文件被截断 | 把三件套放到**同一目录**(exe 旁 / `drivers/` / `win10/`);注意 INF 引用的 `.sys`/`.cat` 必须与 INF 同目录 |
| `pnputil /add-driver 失败` | 驱动库已存在同名/权限/策略 | 先 `vgww.exe --uninstall-driver` 再重装;或查 `pnputil /enum-drivers` |
| INetCfg 绑定报 `0x8004A020`(ALREADY_INITIALIZED) | 系统级 COM 会话冲突(实测出现于个别环境) | 重启后重试,或改用第 4 节官方 MSI 路径 |
| 重启后提示设备访问被拒绝 | 驱动重载后设备 DACL 被重置(旧版本靠开机任务自愈,现已取消) | 程序每次启动会自动在进程内重授 DACL;仍失败时以管理员重跑 `vgww.exe --install-driver`,或手动执行 `vgww.exe --grant-access-only`(只重授 DACL,不装驱动) |
| 安装成功但数据面不工作、网卡掉线 | 无消费进程/适配器名解析失败 | 确认配置 `adapter` 与网卡名一致;VGWW 未运行期间不要保持绑定(卸载驱动可恢复网络) |
| 驱动服务注册但从不启动(事件 0x1F/7000) | 旧版以 SCM 服务注册的残留 | 内置安装器会清理;仍存在则手动 `sc delete ndisrd` 后重装 |
| 安装了旧版 WinpkFilter 但无任何提示 | **驱动版本探测缺失**(风险条目):装载不匹配的旧驱动可能表现为神秘 IOCTL 失败 | 保持随仓库分发的官方 3.6.2.1 载荷;怀疑版本不符时先 `--uninstall-driver` 再重装 |

**关键安全注意事项**:NDIS LWF 绑定活动期间,必须有本产品作为常驻消费进程且适配器名可解析;
否则主机的 TCP/IP 数据路径会被过滤器栈挂住(实测两个网卡都丢 ICMP/TCP,卸载驱动后恢复)。
因此:数据面运行异常时,优先用 `--uninstall-driver` 还原网络,再排查配置。

---

## 6. 开源分发与许可边界

- **源码/SDK**:WinpkFilter 官方源码与头文件为 **MIT** 许可(仓库 `sdk/ndisapi-3.6.2/LICENSE`)。
- **驱动二进制**:WinpkFilter 官方许可分两层——
  - **免费层(Personal / Academic)**:个人、学术、教育、非营利使用,功能完整,但**不含商业再分发权**;
  - **商业层**:产品对外(含开源项目的公开发布物)再分发驱动二进制需商业许可(Developer Binary / Source Code,一次购买)。
- **VGWW 的立场**:本项目为**纯开源、非盈利**项目,以个人/学术/非营利形态使用与分发驱动;
  仓库随附驱动二进制与官方安装包便于用户自装。若你的部署形态超出免费层(例如商业化发行、
  或对收费用户分发),请自行向 WinpkFilter 版权方核实并取得对应授权——VGWW 不承担该等再分发授权责任。
- 第三方组件许可清单见 README「许可」一节(xtcp、nlohmann/json、Asio、WinpkFilter SDK 等)。

---

## 7. 链接

- [架构(zh)](architecture.md) · [配置说明(zh)](configuration.md)
- 英文版 [Driver installation (en)](../en/driver-install.md)
