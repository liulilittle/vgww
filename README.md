# VGWW — Virtual Gateway for Windows

[![build](https://github.com/liulilittle/vgww/actions/workflows/build.yml/badge.svg)](https://github.com/liulilittle/vgww/actions/workflows/build.yml)

**VGWW** is a high-performance userspace software router for Windows. It turns a Windows PC into the default gateway of your LAN: other devices simply point their gateway at this machine and reach the internet through it — including through whatever VPN adapter the host has active.

[简体中文文档](README.zh-CN.md)

## Why VGWW exists

1. **Windows desktops have no proper software router.** ICS is unreliable; Linux has a dozen options, Windows has none worth using.
2. **Share a VPN connection with the whole LAN.** All client traffic is re-originated as userspace sockets from the host, so it follows the host routing table and automatically enters the VPN virtual adapter. Writing raw frames to the NIC would bypass the VPN — VGWW never does that.

## Architecture at a glance

```
LAN clients --v [WinpkFilter NDIS LWF] → RX thread (classify/hash)
                                        ├─ ARP / ICMP-to-gateway  (inline answers)
                                        ├─ TCP  → xtcp userspace stack   → relay pumps
                                        └─ UDP  → per-flow socket NAT    → relay pumps
              TX thread ← per-worker SPSC rings ← worker pool (= xtcp shards)
```

* **TCP**: terminated by xtcp (our own sharded userspace stack, consumed from a local checkout) and re-dialed as host sockets.
* **UDP / ICMP**: relayed through host sockets with per-flow NAT.
* **IPv6**: RA + SLAAC on the LAN; NAT66 semantics fall out of the terminate-and-relay design.
* **VLAN**: optional single 802.1Q access VLAN (`vlan.id`, `[1, 4094]`) — inbound tags for the configured VID are stripped before routing and every reply is re-tagged; frames from other VLANs are isolated.
* **WebUI**: embedded HTTP server with a single-file SPA dashboard — live stats, port forwarding, per-client rate limits, MAC/IP firewall, and validated config persistence. TCP port forwarding is supported; **UDP port forwarding is not implemented yet** (a "udp" rule will not bind the WAN port) and is tracked separately.
* **Localization**: 461 languages built into the WebUI (English, 简体中文, 繁體中文, 日本語, 한국어, العربية, Latina, Español, Français, Deutsch, Português, Русский, हिन्दी, Italiano, Türkçe, Tiếng Việt, Polski, Nederlands, Svenska, Українська, Bahasa Indonesia, ไทย, Čeština, Magyar, עברית, فارسی, বাংলা, Ελληνικά, Norsk, Dansk, Suomi, Български, Română, Slovenčina, Hrvatski, Slovenščina, Lietuvių, Latviešu, Eesti, Српски, Bahasa Melayu, اردو, ਪੰਜਾਬੀ, தமிழ், తెలుగు, मराठी, ગુજરાતી, ಕನ್ನಡ, മലയാളം, Azərbaycanca, Қазақша, Oʻzbekcha, ქართული, Հայերեն, မြန်မာ, ខ្មែរ, සිංහල, Bosanski, Македонски, Shqip, Íslenska, Català, Euskara, Кыргызча, Монгол, Kiswahili, Hausa, isiZulu, አማርኛ, नेपाली, ລາວ, Cymraeg, Gaeilge, پښتو, Kurdî, Soomaali, Yorùbá, Igbo, Filipino, Basa Jawa, Gàidhlig, Тоҷикӣ, Türkmençe, ئۇيغۇرچە, བོད་སྐད།, অসমীয়া, ଓଡ଼ିଆ, سنڌي, Esperanto, Akan, Lingala, Runasimi, Aymar aru, Chichewa, Sesotho, Setswana, isiXhosa, Galego, Occitan, Brezhoneg, Māori, ʻŌlelo Hawaiʻi, Gagana Sāmoa, Føroyskt, Lëtzebuergesch, Malti, SiSwati, Tshivenḓa, Xitsonga, isiNdebele, ትግርኛ, Afaan Oromoo, Kinyarwanda, Kirundi, Bamanankan, Fulfulde, Wolof, Kreyòl Ayisyen, chiShona, Sepedi, कॉशुर, कोंकणी, Sardu, Corsu, Furlan, Piemontèis, Napulitano, Sicilianu, Lombard, Vèneto, Avañe'ẽ, lea faka-Tonga, Na vosa vaka-Viti, ދިވެހި, རྫོང་ཁ, Rumantsch, Asturianu, Aragonés, Eʋegbe, Sängö, Kikongo, Ichibemba, Башҡортса, Нохчийн, Чӑвашла, Татарча, Frysk, Plattdüütsch, Limburgs, Ladino, Ирон, Аҧсуа, МагIарул мацI, Лезги чIал, ייִדיש, ᐃᓄᒃᑎᑐᑦ, Walon, West-Vlams, Nouormand, Picard, Nahuatl, Mapudungun, संस्कृत, पाळि, Ἑλληνικὴ, Удмурт, Коми, Марла, Эрзянь, Мокшень, Malagasy, Tok Pisin, Bislama, Davvisámegiella, Taetae ni Kiribati, Ebon, Dorerin Naoero, tekoi er a Belau, Cabo Verdean, Papiamentu, Patwah Jumiekan, Fiji Hindi, Tetun, Hiri Motu, Reo Tahiti, Vagahau Niuē, Хальмг келн, ГIалгIай, Къарачай-Малкъар, Қарақалпақ тили, Maayatʼaan, Тыва дыл, Саха тыла, Алтай тил, 粵語, 客家話, 閩南語, Vahcuengh, Hmoob, ꆈꌠꉙ, Dolnoserbšćina, Hornjoserbšćina, 吴语, 閩東語, 贛語, 湘語, Gaelg, Kernewek, Scots, Ligure, भोजपुरी, मैथिली, अवधी, छत्तीसगढ़ी, मगही, মৈতৈ, बड़, Santali, Diné bizaad, ᏣᎳᎩ, Lakȟólʼiya, Chahta, Nēhiyawēwin, Anishinaabemowin, Tsėhesenėstsestȯtse, Diidxazá, Basa Sunda, Kaszëbsczi, Ślōnskŏ gŏdka, مصري, الدارجة المغربية, Romani čhib, アイヌ イタク, Sranan Tongo, Binisaya, Hiligaynon, Ilokano, Winaray, Kapampangan, Bikol, Pangasinense, Bahasa Sūg, Luganda, Gĩkũyũ, Dholuo, Tiv, Kʼicheʼ, Kaqchikel, Qyool, Qʼeqchiʼ, Baso Minangkabau, Bahsa Acèh, Basa Ugi, Bali, Bhâsa Madhurâ, Thuɔ̈ŋjäŋ, Tshiluba, Kʼop Takwin, Mëranaw, Chavacano, Toraja, Runyankore, Kamba, डोगरी, ತುಳು, ကညီကျိၥ်, Seselwa, Kreol Morisien, Otjiherero, Oshikwanyama, Oshindonga, Estremeñu, Mirandés, नेपाल भाषा, Julakan, Twi, Mooré, Sasak, Gorontalo, Kabɩyɛ, Dagbanli, Gurenne, Senni, Kanuri, Ladin, ၵႂၢမ်းတႆး, Qırımtatar, Gondi, Tamasheq, Talysh, Zazaki, Kölsch, Jinghpaw, Bahasa Banjar, Gungbe, Thok Nath, Mende, بختیاری, Chamoru, Refaluwasch, سرائیکی, مازرونی, گيلکی, Gagauz, تونسي, عربي عراقي, Pidgin, Krio, Cham, Hanunoo, Kîmîîru, Baoulé, Ga, Tamaziɣt, Fɔngbè, ትግረ, ꠍꠤꠟꠐꠤ, Kui, آذربایجانجا, پنجابی, Baso Yawi, 𑄌𑄋𑄴𑄟𑄳𑄦, Русинськый, Tshiluba, Runyoro, Olusoga, Ateso, Kimocho, Tyap, ChiLamba, Kurmancî, کوردیی ناوەندی, Mizo tawng, Haqniqdoq, ꪼꪕꪒꪾ, ᥖᥭᥰᥖᥨᥝᥰ, درجة, شامي, Nuurdfresk, Kahnihr, Kosrae, Chuukese, Kriol Bileez, Kreyòl Gwadloup, Bêl Kwéyòl, Pennsilfaanisch Deitsch, Дарган мез, Лакку маз, Табасаран чӀал, Vahcuengh Bouyei, ᦺᦑᦟᦹᧉ, Hmoob Dawb, Hmong Njua, Batsʼi kʼop, Runyakitara, Kirwanda, Kisukuma, Kikamba, Acholi, Mundang, Kishambaa, Kimakonde, Schwiizerdütsch, Boarisch, Pälzisch, Seeltersk, Sassaresu, Gadduresu, Mainfränkisch, Runashimi, Taqbaylit, Tashelhiyt, Tarifit, Tamaziɣt n waṭlas, Runashimi Santiago, Runasimi Qullasuyu, Māori Kūki ʻĀirani, Mandinkakaŋo, Беларуская, Interlingua, Ido, ትግረ, Soninkara, Fur, Azande, Livvi, Volapük, Lingua Franca Nova, Hñähñu, Tuꞌun Savi, Caribbean Hindustani, Silozi, Kɔniffi, Rukwangali, Umbundu, Kimbundu, Makhuwa, Chitumbuka, Kangri, Tzʼutujil, ܣܘܼܪܲܝܬ, डोटेली, Afrikaans, Garhwali, Къумукъ, Ногай тили, Адыгэбзэ, Адыгабзэ, მარგალური, Lazuri, Буряад, lo jbobau, tlhIngan Hol, Tojol-abʼal, ብሊን, Ka Ktien Khasi, A·chik, 閩北語, Kpɛlɛɛwoo, Lɔɔmɔ, Ɓàsàa, Ewondo, toki pona, Ixil, Shipibo, Basa Jawa Suriname, Maa, Mvskoke, Mi'kmaq, Wayuunaiki, Muisca, Sosoxui, Vai, ግዕዝ, خليجي, شامي, حجازي, موصلاوي, شحّي, صنعاني, تعزي-عدني, عربي جوبا). The page auto-detects the browser's locale (exact-match first, then base language, then prefix fallback; traditional-script variants like zh-HK/zh-MO/zh-Hant land on 繁體中文), remembers manual choices in localStorage, and switches layout to RTL for Arabic/Hebrew/Persian. Add a language by appending one ~100-key block to the `I18N` map in `www/index.html`.
* **Memory backend**: compiled-time switch to jemalloc (`-DVGWW_JEMALLOC=ON`, vcpkg) or the CRT heap; `vgww.exe --version` reports the active backend.
* **WebUI backend**: embedded HTTP server with a single-file SPA dashboard, **on by default** (`web.enabled` defaults to true; `--no-web` disables it, `--web` forces it on; `--web-only` runs only it); manage it from your own browser. The embedded WebView2 GUI shell was removed in S4.1; the native UI (S4.3/S4.4) is the default surface.

See [docs/en/architecture.md](docs/en/architecture.md) for the full design and [docs/zh/architecture.md](docs/zh/architecture.md) for the Chinese version.

## Config

A loadable template lives at [`config.example.json`](config.example.json) (clone it to `config.json` and edit). Required: `gateway.ipv4`/`mask`/`mac`.

## Build

Requirements: Visual Studio 2022, CMake ≥ 3.20, network access on first configure.

The userspace TCP stack ([xtcp](https://github.com/liulilittle/xtcp)) is a **git submodule** at `third_party/xtcp`:

```bat
git clone --recursive https://github.com/liulilittle/vgww.git
:: already cloned? fetch the submodule:
git submodule update --init --recursive
```

`VGWW_XTCP_DIR` defaults to `${CMAKE_CURRENT_SOURCE_DIR}/third_party/xtcp`; pass `-DVGWW_XTCP_DIR=<path>` to build against a checkout elsewhere.

```bat
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release --target vgww -- -m
ctest --test-dir build -C Release
```

Generated resources (`src/ui/i18n_gen.bin`, `src/ui/i18n_languages.inc`) are checked in; after editing `src/ui/i18n.cpp` regenerate them with `node scripts/gen-native-i18n.mjs .` and re-run `node scripts/check-native-i18n.mjs .`.

## Run

```bat
vgww.exe --config=vgww.json [--adapter=<name>] [--web] [--web-only] [--headless] [--minimized]
```

The default run starts the native UI and the HTTP management server when `web.enabled` is true (the default); the UI (`web.port`, default 8080) binds to `web.bind` (default `127.0.0.1` loopback) and never binds every interface implicitly. Open `http://127.0.0.1:8080/` to manage it; `--no-web` disables it and `--web` forces it on (highest priority). `--web-only` starts the WebUI without the data plane (no driver needed) — handy for development.

The WinpkFilter driver must be installed for actual packet forwarding. VGWW always runs elevated (its manifest requests `requireAdministrator`), so run `vgww.exe --install-driver` to install the driver and grant device access; after that, every launch re-grants device access in-process (no boot task is registered). If the data plane cannot start, VGWW reports a clear error and continues (native UI in degraded mode) instead of exiting. To remove it later (e.g. to restore the network before debugging), run `vgww.exe --uninstall-driver` as Administrator (this also removes any legacy boot task left by older releases).

## Configuration

See [docs/en/configuration.md](docs/en/configuration.md) ([中文](docs/zh/configuration.md)). Minimal example:

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

`adapter` may be a friendly name or a `\DEVICE\{GUID}` path. Prefer picking it from the Settings page's detected-adapter list; the diagnostic line there shows the actually bound NIC, its link state and its IPv4 addresses, and warns when it is disconnected or outside the gateway subnet.

## Documentation index

| English | 中文 |
|---|---|
| [Architecture](docs/en/architecture.md) | [架构设计](docs/zh/architecture.md) |
| [Configuration](docs/en/configuration.md) | [配置说明](docs/zh/configuration.md) |
| [Driver installation](docs/en/driver-install.md) | [驱动安装与许可说明](docs/zh/driver-install.md) |

## License

VGWW is free software licensed under the **GNU Affero General Public License v3.0** (AGPL-3.0). See [LICENSE](LICENSE). If you run a modified version as a network service, section 13 requires you to offer its Corresponding Source to remote users.

Third-party components keep their own licenses:

| Component | License |
|---|---|
| [xtcp](https://github.com/liulilittle/xtcp) (userspace TCP/IP stack, git submodule) | see the xtcp repository |
| nlohmann/json | MIT |
| Asio | Boost Software License 1.0 |
| WinpkFilter user-mode headers (`third_party/ndisapi`) | MIT (NT Kernel) |
| WinpkFilter driver/MSI (`third_party/winpkfilter`) | proprietary, © NT KERNEL — **not** covered by the AGPL; redistributed here in source form for convenience only. You are responsible for complying with the NT KERNEL license when installing or redistributing the driver. |
