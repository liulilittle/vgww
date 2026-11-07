# VGWW — Windows 虚拟网关

**VGWW** 是一个高性能的 Windows 用户态软件路由器。它把一台 Windows 电脑变成局域网的默认网关：其他设备只需把网关指向这台机器，即可通过它上网——包括经由本机已连接的 VPN 虚拟网卡。

[English documentation](README.md)

## 为什么做 VGWW

1. **Windows 桌面端没有成熟的软路由软件。** ICS 不可靠；Linux 有很多选择，Windows 值得用的一个都没有。
2. **把 VPN 连接共享给整个局域网。** 所有客户端流量都会以用户态 socket 从主机重新发起，因此走本机路由表、自动进入 VPN 虚拟网卡。直接向网卡写原始帧会绕开 VPN——VGWW 绝不这样做。

## 架构一览

```
LAN 客户端 ←→ [WinpkFilter NDIS LWF] → RX 线程（分类/哈希）
                                        ├─ ARP / 发往网关的 ICMP（内联应答）
                                        ├─ TCP  → xtcp 用户态栈 → 中继泵
                                        └─ UDP  → 每流 socket NAT → 中继泵
              TX 线程 ← 每 worker SPSC 环 ← worker 池（= xtcp 分片数）
```

* **TCP**：由 xtcp（我们自研的分片用户态栈，从本地检出消费）终结后以主机 socket 重拨。
* **UDP / ICMP**：经主机 socket 中继，每流 NAT。
* **IPv6**：局域网侧 RA + SLAAC 自动配置；出口为 NAT66 语义（由"终结+中继"设计自然涌现）。
* **VLAN**：可选的单 802.1Q access VLAN（`vlan.id`，`[1, 4094]`）——入方向匹配 VID 的 tag 在路由前剥除，回复帧重新打 tag；其它 VLAN 的帧隔离。
* **WebUI**：内嵌 HTTP 服务器 + 单文件 SPA 仪表盘——实时状态、端口映射、按客户端限速、MAC/IP 防火墙、经校验的配置持久化。
* **多国语言（i18n）**：WebUI 内置 461 种语言（English、简体中文、繁體中文、日本語、한국어、العربية、Latina、Español、Français、Deutsch、Português、Русский、हिन्दी、Italiano、Türkçe、Tiếng Việt、Polski、Nederlands、Svenska、Українська、Bahasa Indonesia、ไทย、Čeština、Magyar、עברית、فارسی、বাংলা、Ελληνικά、Norsk、Dansk、Suomi、Български、Română、Slovenčina、Hrvatski、Slovenščina、Lietuvių、Latviešu、Eesti、Српски、Bahasa Melayu、اردو、ਪੰਜਾਬੀ、தமிழ்、తెలుగు、मराठी、ગુજરાતી、ಕನ್ನಡ、മലയാളം、Azərbaycanca、Қазақша、Oʻzbekcha、ქართული、Հայերեն、မြန်မာ、ខ្មែរ、සිංහල、Bosanski、Македонски、Shqip、Íslenska、Català、Euskara、Кыргызча、Монгол、Kiswahili、Hausa、isiZulu、አማርኛ、नेपाली、ລາວ、Cymraeg、Gaeilge、پښتو、Kurdî、Soomaali、Yorùbá、Igbo、Filipino、Basa Jawa、Gàidhlig、Тоҷикӣ、Türkmençe、ئۇيغۇرچە、བོད་སྐད།、অসমীয়া、ଓଡ଼ିଆ、سنڌي、Esperanto、Akan、Lingala、Runasimi、Aymar aru、Chichewa、Sesotho、Setswana、isiXhosa、Galego、Occitan、Brezhoneg、Māori、ʻŌlelo Hawaiʻi、Gagana Sāmoa、Føroyskt、Lëtzebuergesch、Malti、SiSwati、Tshivenḓa、Xitsonga、isiNdebele、ትግርኛ、Afaan Oromoo、Kinyarwanda、Kirundi、Bamanankan、Fulfulde、Wolof、Kreyòl Ayisyen、chiShona、Sepedi、कॉशुर、कोंकणी、Sardu、Corsu、Furlan、Piemontèis、Napulitano、Sicilianu、Lombard、Vèneto、Avañe'ẽ、lea faka-Tonga、Na vosa vaka-Viti、ދިވެހި、རྫོང་ཁ、Rumantsch、Asturianu、Aragonés、Eʋegbe、Sängö、Kikongo、Ichibemba、Башҡортса、Нохчийн、Чӑвашла、Татарча、Frysk、Plattdüütsch、Limburgs、Ladino、Ирон、Аҧсуа、МагIарул мацI、Лезги чIал、ייִדיש、ᐃᓄᒃᑎᑐᑦ、Walon、West-Vlams、Nouormand、Picard、Nahuatl、Mapudungun、संस्कृत、पाळि、Ἑλληνικὴ、Удмурт、Коми、Марла、Эрзянь、Мокшень、Malagasy、Tok Pisin、Bislama、Davvisámegiella、Taetae ni Kiribati、Ebon、Dorerin Naoero、tekoi er a Belau、Cabo Verdean、Papiamentu、Patwah Jumiekan、Fiji Hindi、Tetun、Hiri Motu、Reo Tahiti、Vagahau Niuē、Хальмг келн、ГIалгIай、Къарачай-Малкъар、Қарақалпақ тили、Maayatʼaan、Тыва дыл、Саха тыла、Алтай тил、粵語、客家話、閩南語、Vahcuengh、Hmoob、ꆈꌠꉙ、Dolnoserbšćina、Hornjoserbšćina、吴语、閩東語、贛語、湘語、Gaelg、Kernewek、Scots、Ligure、भोजपुरी、मैथिली、अवधी、छत्तीसगढ़ी、मगही、মৈতৈ、बड़、Santali、Diné bizaad、ᏣᎳᎩ、Lakȟólʼiya、Chahta、Nēhiyawēwin、Anishinaabemowin、Tsėhesenėstsestȯtse、Diidxazá、Basa Sunda、Kaszëbsczi、Ślōnskŏ gŏdka、مصري、الدارجة المغربية、Romani čhib、アイヌ イタク、Sranan Tongo、Binisaya、Hiligaynon、Ilokano、Winaray、Kapampangan、Bikol、Pangasinense、Bahasa Sūg、Luganda、Gĩkũyũ、Dholuo、Tiv、Kʼicheʼ、Kaqchikel、Qyool、Qʼeqchiʼ、Baso Minangkabau、Bahsa Acèh、Basa Ugi、Bali、Bhâsa Madhurâ、Thuɔ̈ŋjäŋ、Tshiluba、Kʼop Takwin、Mëranaw、Chavacano、Toraja、Runyankore、Kamba、डोगरी、ತುಳು、ကညီကျိၥ်、Seselwa、Kreol Morisien、Otjiherero、Oshikwanyama、Oshindonga、Estremeñu、Mirandés、नेपाल भाषा、Julakan、Twi、Mooré、Sasak、Gorontalo、Kabɩyɛ、Dagbanli、Gurenne、Senni、Kanuri、Ladin、ၵႂၢမ်းတႆး、Qırımtatar、Gondi、Tamasheq、Talysh、Zazaki、Kölsch、Jinghpaw、Bahasa Banjar、Gungbe、Thok Nath、Mende、بختیاری、Chamoru、Refaluwasch、سرائیکی、مازرونی、گيلکی、Gagauz、تونسي、عربي عراقي、Pidgin、Krio、Cham、Hanunoo、Kîmîîru、Baoulé、Ga、Tamaziɣt、Fɔngbè、ትግረ、ꠍꠤꠟꠐꠤ、Kui、آذربایجانجا、پنجابی、Baso Yawi、𑄌𑄋𑄴𑄟𑄳𑄦、Русинськый、Tshiluba、Runyoro、Olusoga、Ateso、Kimocho、Tyap、ChiLamba、Kurmancî、کوردیی ناوەندی、Mizo tawng、Haqniqdoq、ꪼꪕꪒꪾ、ᥖᥭᥰᥖᥨᥝᥰ、درجة、شامي、Nuurdfresk、Kahnihr、Kosrae、Chuukese、Kriol Bileez、Kreyòl Gwadloup、Bêl Kwéyòl、Pennsilfaanisch Deitsch、Дарган мез、Лакку маз、Табасаран чӀал、Vahcuengh Bouyei、ᦺᦑᦟᦹᧉ、Hmoob Dawb、Hmong Njua、Batsʼi kʼop、Runyakitara、Kirwanda、Kisukuma、Kikamba、Acholi、Mundang、Kishambaa、Kimakonde、Schwiizerdütsch、Boarisch、Pälzisch、Seeltersk、Sassaresu、Gadduresu、Mainfränkisch、Runashimi、Taqbaylit、Tashelhiyt、Tarifit、Tamaziɣt n waṭlas、Runashimi Santiago、Runasimi Qullasuyu、Māori Kūki ʻĀirani、Mandinkakaŋo、Беларуская、Interlingua、Ido、ትግረ、Soninkara、Fur、Azande、Livvi、Volapük、Lingua Franca Nova、Hñähñu、Tuꞌun Savi、Caribbean Hindustani、Silozi、Kɔniffi、Rukwangali、Umbundu、Kimbundu、Makhuwa、Chitumbuka、Kangri、Tzʼutujil、ܣܘܼܪܲܝܬ、डोटेली、Afrikaans、Garhwali、Къумукъ、Ногай тили、Адыгэбзэ、Адыгабзэ、მარგალური、Lazuri、Буряад、lo jbobau、tlhIngan Hol、Tojol-abʼal、ብሊን、Ka Ktien Khasi、A·chik、閩北語、Kpɛlɛɛwoo、Lɔɔmɔ、Ɓàsàa、Ewondo、toki pona、Ixil、Shipibo、Basa Jawa Suriname、Maa、Mvskoke、Mi'kmaq、Wayuunaiki、Muisca、Sosoxui、Vai、ግዕዝ、خليجي、شامي、حجازي、موصلاوي、شحّي、صنعاني、تعزي-عدني、عربي جوبا）。页面自动检测浏览器地区语言（精确匹配优先，其次基语言，最后前缀回退；zh-HK/zh-MO/zh-Hant 等繁体语境自动落繁体中文），手动选择记忆在 localStorage；阿拉伯语/希伯来语/波斯语自动切换 RTL 布局。新增语言只需在 `www/index.html` 的 `I18N` 映射中追加一个约 100-key 区块。
* **内存后端**：编译期开关切换到 jemalloc（`-DVGWW_JEMALLOC=ON`，vcpkg）或 CRT 堆；`vgww.exe --version` 报告当前后端。
* **WebUI 后端**：内嵌 HTTP 服务器 + 单文件 SPA 仪表盘，**默认开启**（`web.enabled` 默认 true；`--no-web` 可关闭，`--web` 强制开启；`--web-only` 仅启动它），用自己的浏览器管理。内嵌 WebView2 界面壳已于 S4.1 删除；原生 UI（S4.3/S4.4）为默认界面。

完整设计见 [docs/zh/architecture.md](docs/zh/architecture.md)，英文版 [docs/en/architecture.md](docs/en/architecture.md)。

## 构建

环境要求：Visual Studio 2022、CMake ≥ 3.20，首次配置需联网拉取依赖。

用户态 TCP 栈（xtcp）从本地检出消费，经 `VGWW_XTCP_DIR` 指定（默认 `${CMAKE_CURRENT_SOURCE_DIR}/../xtcp`，即与本仓库同级的 xtcp 检出）；检出在其它位置时在配置命令加 `-DVGWW_XTCP_DIR=<path>`。

```bat
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release --target vgww -- -m
ctest --test-dir build -C Release
```

生成资源（`src/ui/i18n_gen.bin`、`src/ui/i18n_languages.inc`）已随仓库提交；改动 `src/ui/i18n.cpp` 后用 `node scripts/gen-native-i18n.mjs .` 重新生成，并跑 `node scripts/check-native-i18n.mjs .` 校验。

## 运行

```bat
vgww.exe --config=vgww.json [--adapter=<网卡名>] [--web] [--web-only] [--headless] [--minimized]
```

默认运行启动原生 UI，并按 `web.enabled`（默认开启）启动 HTTP 管理界面（`web.port`，默认 8080），绑定 `web.bind`（默认 `127.0.0.1` 回环）——不会隐式绑定所有网卡。打开 `http://127.0.0.1:8080/` 进入管理；`--no-web` 关闭它，`--web` 强制开启（最高优先级）。`--web-only` 只启动 WebUI 不启动数据面（无需驱动），便于开发调试。

实际转发数据包需要安装 WinpkFilter 驱动：VGWW 始终以管理员身份运行（清单声明 requireAdministrator），运行一次 `vgww.exe --install-driver` 完成安装与设备授权；之后每次启动由程序在进程内自动重授设备访问（不再注册任何开机任务）。数据面无法启动时，VGWW 给出明确错误并继续运行（原生 UI 降级态展示），不再退出。需要卸载时（例如排查问题前还原网络），以管理员身份运行 `vgww.exe --uninstall-driver`（同时清理旧版本遗留的开机任务）。

## 配置

详见 [docs/zh/configuration.md](docs/zh/configuration.md)（[英文](docs/en/configuration.md)）。最小示例：

```json
{
  "adapter": "Ethernet",
  "gateway": { "ipv4": "192.168.0.40", "mask": "255.255.255.0", "mac": "30:fc:68:88:b4:a9" },
  "ipv6": {
    "enabled": true,
    "ula_prefix": "fd00::/64",
    "dns": ["fd00::53"]
  }
}
```

`adapter` 可填友好名或 `\DEVICE\{GUID}` 设备路径。建议在设置页从“检测到的网卡”列表中选择；该页诊断行会显示实际绑定的网卡、链路状态与 IPv4 地址，并在网卡断连或不在网关子网时给出警示。

## 文档索引

| 中文 | English |
|---|---|
| [架构设计](docs/zh/architecture.md) | [Architecture](docs/en/architecture.md) |
| [配置说明](docs/zh/configuration.md) | [Configuration](docs/en/configuration.md) |
| [驱动安装与许可说明](docs/zh/driver-install.md) | [Driver installation](docs/en/driver-install.md) |

## 许可

VGWW 是自由软件，采用 **GNU Affero 通用公共许可证 v3.0**（AGPL-3.0），全文见 [LICENSE](LICENSE)。若把修改版作为网络服务运行，第 13 条要求向远程用户提供对应的完整源码。

第三方组件保留各自许可：

| 组件 | 许可 |
|---|---|
| [xtcp](https://github.com/)（用户态 TCP/IP 栈，同级独立检出） | 见 xtcp 仓库 |
| nlohmann/json | MIT |
| Asio | Boost Software License 1.0 |
| WinpkFilter 用户态头文件（`third_party/ndisapi`） | MIT（NT Kernel） |
| WinpkFilter 驱动/MSI（`third_party/winpkfilter`） | 专有，© NT KERNEL —— **不受** AGPL 覆盖；此处仅为方便而随源码分发，安装或再分发驱动时请自行遵守 NT KERNEL 许可。 |
