# Driver Installation & Licensing

VGWW's forwarding data plane needs an NDIS lightweight filter (LWF) driver to attach to
the NICs. The bundled driver is **WinpkFilter (Windows Packet Filter)** from NT KERNEL;
the official release binaries and installer are shipped in this repository.

This page explains: where the driver files live, how to install/uninstall, how to debug
when something goes wrong, and the licensing boundary for open-source redistribution.

---

## 1. Driver files

Under `third_party/winpkfilter/`:

| File | Purpose |
|---|---|
| `ndisrd.sys` | Kernel driver binary (win10/11, x64) |
| `ndisrd_lwf.inf` | INF install script (component GUID, binding traits) |
| `ndisrd.cat` | Catalog signature (the INF declares `CatalogFile=ndisrd.cat`; **required** — pnputil fails without it) |
| `Windows.Packet.Filter.3.6.2.1.x64.msi` | Official installer (alternate install path) |
| `extract/PFiles64/.../drivers/{win7,win8,win10}/` | Official unpacked driver tree per OS |
| `sdk/` | Official SDK headers & sources (compile-time reference only) |

> **The triple must share one directory**: `ndisrd_lwf.inf`, `ndisrd.sys` and `ndisrd.cat`
> must sit in the SAME directory (next to vgww.exe, in `drivers/`, or in the unpacked
> `win10/`). Split placements are rejected with a message naming the missing file.

**Signing**: `ndisrd.sys` Authenticode signature verified valid (CN=The Anti-Cloud Corporation, EV certificate in validity).
**Version**: WinpkFilter v3.6.2 (asset 3.6.2.1, released 2025-10-23), fetched from the official GitHub Release channel.

---

## 2. Quick install (built-in `--install-driver`)

Place `ndisrd_lwf.inf`, `ndisrd.sys` and `ndisrd.cat` **in the same directory** (next to
`vgww.exe`, in a `drivers/` subdirectory, or as the official unpacked `win10/` folder),
then run **as Administrator**:

```bat
vgww.exe --install-driver
```

What happens internally (verified against `src/driver/installer.cpp`):

1. Validates the same-directory triple (INF >= 1 KiB, SYS >= 4 KiB, CAT non-empty;
   truncated payloads are rejected with the missing file names and the tried
   directories);
2. Records the driver-store baseline, cleans up any stale legacy SCM service
   registration (if present);
3. Runs `pnputil /add-driver ndisrd_lwf.inf /install` to publish the driver into the
   store;
4. Instantiates the network component via INetCfg and binds it to the physical NICs; on
   failure, the rollback deletes ONLY the entries published by this install (baseline
   diff);
5. Applies a DACL to the `\\.\Ndisrd` device object so the data plane can open it;
6. Registers **no boot task**: any legacy `VGWW-GrantAccess` task is actively
   removed on install/upgrade (idempotent). The app always runs elevated (manifest
   `requireAdministrator`) and re-grants device access in-process at every launch
   (see `main.cpp`).

Exit code 0 = success. The driver then loads with the NIC stack.

> VGWW always runs elevated (manifest `requireAdministrator`); `--install-driver`
> likewise needs an Administrator token.
> **After an upgrade/reinstall**: re-run `vgww.exe --install-driver` as Administrator;
> the installer actively removes any legacy `VGWW-GrantAccess` boot task (idempotent)
> and re-applies the device DACL.

---

## 3. Uninstall (built-in `--uninstall-driver`)

Run as Administrator:

```bat
vgww.exe --uninstall-driver
```

Order: **INetCfg unbind first**, then `pnputil /delete-driver <oem##.inf> /uninstall`
for EVERY published ndisrd entry (old versions included). After a successful delete the
self-heal / legacy artifacts are removed too: any legacy `VGWW-GrantAccess` boot task, the
`%ProgramData%\VGWW\vgww.exe` mirror, and the old manual System32 copy. Any cleanup
failure is reported (result text `已卸载，但残留未清理: <reason>` — "uninstalled, but
residuals were not cleaned: <reason>").

Even when the store has no ndisrd entry (empty enum), the uninstall still removes the
self-heal task and mirror (with a warning), so **a later boot cannot silently reinstall
the driver**.

Exit code 0 = success; failures or un-cleaned residuals return non-zero.

---

## 4. Alternate install (official MSI)

If the built-in installer hits a system-level issue on your machine (see §5), install
the driver manually with the official package:

```bat
:: Administrator
msiexec /i "third_party\winpkfilter\Windows.Packet.Filter.3.6.2.1.x64.msi"
```

The MSI completes signed driver installation and component registration. Start VGWW
normally afterwards.

---

## 5. Troubleshooting

| Symptom | Likely cause | Action |
|---|---|---|
| `--install-driver` says "run as administrator" | Non-elevated token | Re-run from an elevated PowerShell |
| "driver payload incomplete: missing xxx" (with tried directories) | inf/sys/cat triple incomplete, wrong folder, or truncated file | Put the triple in ONE directory (next to the exe / `drivers/` / `win10/`); the `.sys`/`.cat` the INF references must share the INF's directory |
| `pnputil /add-driver` failed | Duplicate store entry / policy / rights | Run `vgww.exe --uninstall-driver` first, then reinstall; inspect `pnputil /enum-drivers` |
| INetCfg binding `0x8004A020` (ALREADY_INITIALIZED) | System-level COM session conflict (seen on some hosts) | Reboot and retry, or use the §4 official MSI path |
| `"device access denied"` after a reboot | The driver reset the device DACL on reload (older releases relied on a boot task; that is gone) | Every launch re-grants the DACL in-process; if it still fails, re-run `vgww.exe --install-driver` as Administrator, or run `vgww.exe --grant-access-only` manually (re-applies the DACL only, never installs) |
| Installed but data plane down / NICs drop | No resident consumer / unresolved adapter name | Check `adapter` matches the NIC name; do not keep the LWF bound while VGWW is not running (uninstall to restore the network) |
| Service registered but never starts (events 0x1F/7000) | Stale SCM-service registration | The built-in installer cleans it; if it persists, `sc delete ndisrd` then reinstall |
| An old WinpkFilter version is installed with no warning | **Driver-version probing is missing** (risk note): loading an incompatible old driver can surface as obscure IOCTL failures | Keep the shipped official 3.6.2.1 payload; if you suspect a version mismatch, `--uninstall-driver` then reinstall |

**Critical safety note**: while the LWF binding is active there must be a resident
consumer (this product) and the configured adapter name must resolve; otherwise the
host TCP/IP data path is held up by the filter stack (measured: both NICs lost ICMP and
TCP; network was restored only after the driver was uninstalled). So when the data plane
misbehaves, prefer `--uninstall-driver` to restore the network before debugging config.

---

## 6. Open-source redistribution & licensing

- **Source / SDK**: WinpkFilter source and headers are **MIT**-licensed
  (`sdk/ndisapi-3.6.2/LICENSE`).
- **Driver binary**: WinpkFilter licensing is split —
  - **Free tier (Personal / Academic)**: personal, academic, educational and non-profit
    use, full functionality, but **no commercial redistribution rights**;
  - **Commercial tier**: redistributing the driver binary inside a shipped product
    (including open-source project release artifacts) requires a commercial license
    (Developer Binary / Source Code, one-time purchase).
- **VGWW's position**: this is a **pure open-source, non-profit** project using and
  distributing the driver under the personal/academic/non-profit tier; the driver binary
  and official installer are shipped in-repo so users can self-install. If your
  deployment exceeds the free tier (e.g. commercial distribution or distribution to
  paying users), verify and obtain the appropriate authorization from the WinpkFilter
  copyright holder yourself — VGWW does not assume responsibility for such redistribution
  licensing.
- Third-party license inventory is in README "License" (xtcp, nlohmann/json, Asio,
  WinpkFilter SDK, etc.).

---

## 7. Links

- [Architecture](architecture.md) · [Configuration](configuration.md)
- 中文版 [驱动安装与许可说明](../zh/driver-install.md)
