# 命令行

`vgww.exe` 是 Windows GUI 子系统程序，但一次性命令会附着父控制台并在其中输出结果，用法与命令行工具一致。

## 用法

```bat
vgww.exe --config=<路径> [选项]
vgww.exe --install-driver | --uninstall-driver | --grant-access-only
vgww.exe --version | --help
```

`--config=<路径>` 与 `--config <路径>` 两种写法都接受。未给 `--config` 时，程序依次在可执行文件目录、其上级目录、当前工作目录（及其上级目录）中查找 `config.json`，再查 `config.example.json`；自动选中的文件会打印到 stderr。

## 选项

| 参数 | 作用 |
|---|---|
| `--config=<路径>` | 配置文件。若找不到任何回退文件则为必需。 |
| `--adapter=<名称>` | 覆盖配置中的 `adapter`。可填友好名（`Ethernet`）或 `\DEVICE\{GUID}`。上限 256 字节，超长会以指明该参数的错误拒绝。 |
| `--web` | 强制**开启**管理界面，覆盖 `web.enabled`。 |
| `--no-web` | 强制**关闭**管理界面，优先于 `--web` 与 `web.enabled`。服务默认开启。 |
| `--web-only` | 只运行管理界面：不启动数据面、不需要驱动，无原生 UI。隐含 `--web`。 |
| `--headless` | 运行数据面但不启动原生 UI，日志输出到控制台。 |
| `--minimized` | 原生 UI 启动时隐藏到托盘。 |
| `--ui-page=<id>` | 原生 UI 打开到指定页面：`dashboard`、`firewall`、`portmap`、`ratelimit`、`settings`、`bridge`、`leases`、`about`、`console`。未知 id 会在 stderr 警告并回退到默认页，不中止启动。 |
| `--ui-debug-port=<n>` | 在 `127.0.0.1:<n>` 启动 UI 调试通道（永不绑其它网卡）。`n` 必须是 `[1, 65535]` 内的纯数字，其它值使通道保持关闭。 |
| `--install-driver` | 发布并绑定随附的 NDIS LWF 驱动（需管理员）。 |
| `--uninstall-driver` | 解绑并移除驱动，恢复主机网络（需管理员）。 |
| `--grant-access-only` | 只重新应用驱动设备的普通用户 DACL，不安装任何东西（手动恢复用）。 |
| `--version` | 打印版本与当前内存后端，退出码 0。 |
| `--help` | 把用法打印到 stderr，退出码 0。 |
| `--console` | 在 GUI 子系统构建中保留控制台窗口。可用，但不在 `--help` 中列出。 |

未知参数会在数据面启动前被拒绝（`unknown argument: <arg>`）。

参数顺序无关，可出现在 `--config` 前后。重复的值参数以最后一个为准。

## 退出码

| 码 | 含义 |
|---|---|
| `0` | 正常结束，或一次性命令成功（`--version`、`--help`、`--install-driver`、`--uninstall-driver`、`--grant-access-only`）。已有实例在运行时再次启动也返回 0：它改为通知正在运行的窗口。 |
| `1` | 启动或运行失败：配置加载/校验错误、CLI 覆盖被拒、未知参数、驱动安装/卸载/授权失败、认证 token 生成失败、`--web-only` 模式下数据面或管理服务器启动失败。 |
| `2` | 没有配置文件：既未给 `--config`，也没有任何回退候选。会打印用法。 |

普通（带 UI）模式下数据面启动失败**不会**返回 1：窗口以降级态打开并显示错误，操作者可在不丢失界面的情况下修正网卡或驱动。

## 行为说明

* **提权**：清单声明 `requireAdministrator`，进程始终以管理员身份启动，不存在降权子进程。
* **单实例**：第二次启动不会启动第二个网关，而是通知正在运行的实例（聚焦窗口 / 从托盘恢复）后退出 0。
* **token 生成**：`web.token` 为空时用 `BCryptGenRandom` 取 16 字节随机值；获取失败则中止启动（退出 1），绝不以无认证状态运行管理 API。
* **非回环绑定**：`web.bind` 不在回环且 `web.token` 为空时，管理服务器不启动并给出说明。见[配置说明](configuration.md#webui)。
* **控制台捕获**：原生 UI 运行时 stdout 被捕获进控制台页面，因此 token 不会打印在其中；`--headless` 与 `--web-only` 会为操作者打印一次。
* **`--ui-page` 与 `--ui-debug-port` 的值**：都做纯数字/白名单校验，非法值只会导致该功能不生效，不会中断启动。

## 示例

用随附示例配置运行（原生 UI + 回环管理界面）：

```bat
vgww.exe --config=config.example.json
```

只跑管理界面做接口调试（无需驱动）：

```bat
vgww.exe --config=config.json --web-only --headless
```

把管理界面暴露到局域网（必须配 token）：

```bat
vgww.exe --config=config.json --web
:: config.json: "web": { "bind": "0.0.0.0", "token": "<足够长的随机串>" }
```

安装驱动、运行、再卸载：

```bat
vgww.exe --install-driver
vgww.exe --config=config.json
vgww.exe --uninstall-driver
```
