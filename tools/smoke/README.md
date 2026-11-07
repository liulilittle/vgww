# tools/smoke — VGWW 网页 UI 冒烟与自检资产(S4.6)

node-only,**不参与构建**(CMake 未注册任何入口;是否纳入 ctest 留 S4.7 决策)。脚本全部以自身位置推导仓库根(`<repo>/tools/smoke/…`),可用参数覆盖路径。

## 前置

- `node ≥ 22`(用到全局 `WebSocket`;Edge CDP 取渲染文本)。
- Microsoft Edge(`C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`;可用环境变量 `VGWW_EDGE` 覆盖,CDP 端口用 `VGWW_EDGE_CDP_PORT`,默认 9223)。
- 已构建的 `build_s4/Release/vgww.exe`(冒烟以 `--web-only` 启动它,默认端口 18080,需空闲)。
- 已知限制:本机 Edge `153.0.4234.48` 的 `--dump-dom` 对任何 URL(含 `data:`)都输出 0 字节,故渲染检查改用 DevTools 协议取 `document.title`/`body.innerText`/DOM 事实——证据等价,详见 `w7-edge-check.mjs` 头部。

## 脚本一览

| 脚本 | 用途 | 命令 | 期望输出 |
|---|---|---|---|
| `w7-smoke.mjs` | 端到端冒烟:起 `vgww.exe --web-only`(临时配置改写 `web.port`)→ `GET /`(200+SPA doctype)、`GET /api/status`(200+整包 JSON)、静态资源探测、**裸 socket HEAD `/` body=0 字节**、Edge 渲染文本 → 杀进程并验证端口释放 | `node tools/smoke/w7-smoke.mjs [--port=18080] [--exe=<path>] [--config-template=<path>] [--log=<file>]` | 每项一行 `PASS/FAIL`,末行 `RESULT: PASS - smoke green`(exit 0);日志旁附 `<log>.exe-stdout.txt` |
| `w7-edge-check.mjs` | 单独做 Edge 渲染检查;`--serve` 可只起静态服务器测 SPA(无需 exe) | `node tools/smoke/w7-edge-check.mjs http://127.0.0.1:18080/ <outDir> smoke` | `containsDashboardText=true`(exit 0);文本落盘 `<outDir>/w7-<label>-dom.txt` |
| `w6-selfcheck.mjs` | 静态断言 W6 特性集:亮/暗主题、3 断点响应式、类化(0 内联样式)、交互态/toast 队列、a11y(label[for]/th scope/aria-current/favicon)、语言筛选 + 不变量(`esc(`≥20、SET_FIELDS kind、innerHTML 数、I18N 461 语言) | `node tools/smoke/w6-selfcheck.mjs [g1\|g2\|g3\|g4\|g5\|all] [path/to/index.html]` | `OK selfcheck[all]: 42 check(s) passed (<path>)`(exit 0) |
| `rcdat-extract.ps1` | 从 exe 抽 `RCDATA 24001`(内嵌 `www/index.html`)并与磁盘文件比字节 | `powershell -NoProfile -File tools/smoke/rcdat-extract.ps1 build_s4/Release/vgww.exe out.bin www/index.html` | `RCDATA 24001: <N> bytes …` + `byte-equal=True`(不等时 exit 2) |

## 参考运行(证据)

- 冒烟:`logs/w8-smoke.20260923-155635.log`(10/10 绿)、`logs/w7-smoke-final.20260923-154308.log`(修复前 9/10,唯一 FAIL=`/api/status` 非法 JSON)。
- 自检:`logs/selfcheck-*.log`(42/42)、`logs/w6-g2-gates.*.log`(分组 12/12)。
- RCDATA:`logs/w7-rcdat2.20260923-154238.log`、`logs/w8-*` 同名步骤。

## 退出码

`0` = 全绿;`1` = 有 FAIL(冒烟/自检);`2` = RCDATA 与磁盘文件不相等;启动前端口被占 → 立即 `FAIL` 并退出(不启动 exe)。
