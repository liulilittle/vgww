# Command line

`vgww.exe` is a Windows GUI-subsystem binary that also behaves like a console
tool for one-shot commands: those attach to the parent console and print their
result there.

## Synopsis

```bat
vgww.exe --config=<path> [options]
vgww.exe --install-driver | --uninstall-driver | --grant-access-only
vgww.exe --version | --help
```

`--config=<path>` and `--config <path>` are both accepted. When `--config` is
absent, the program looks for `config.json`, then `config.example.json`, next to
the executable, then in the executable's grandparent directory, then in the
current working directory (and its grandparent). The file it auto-selected is
printed to stderr.

## Options

| Flag | Effect |
|---|---|
| `--config=<path>` | Configuration file. Required unless a fallback file is found. |
| `--adapter=<name>` | Overrides `adapter` from the config. Friendly name (`Ethernet`) or `\DEVICE\{GUID}`. Limited to 256 bytes; longer values are rejected with an error naming the flag. |
| `--web` | Forces the management UI **on**, overriding `web.enabled`. |
| `--no-web` | Forces it **off**. Beats `--web` and `web.enabled`. The server is on by default. |
| `--web-only` | Runs the management UI only: no data plane, no driver, headless. Implies `--web`. |
| `--headless` | Runs the data plane without the native UI; logs to the console. |
| `--minimized` | Starts the native UI hidden in the tray. |
| `--ui-page=<id>` | Opens the native UI on a page: `dashboard`, `firewall`, `portmap`, `ratelimit`, `settings`, `bridge`, `leases`, `about`, `console`. An unknown id warns on stderr and falls back to the default page instead of aborting startup. |
| `--ui-debug-port=<n>` | Starts the UI debug channel on `127.0.0.1:<n>` (never on another interface). `n` must be all digits in `[1, 65535]`; anything else leaves the channel off. |
| `--install-driver` | Publishes and binds the bundled NDIS LWF driver (elevated). |
| `--uninstall-driver` | Unbinds and removes it, restoring the host network (elevated). |
| `--grant-access-only` | Re-applies the normal-user DACL on the driver device without installing anything (manual recovery). |
| `--version` | Prints the version and the active memory backend, then exits 0. |
| `--help` | Prints usage to stderr, then exits 0. |
| `--console` | Keeps a console window in this GUI-subsystem build. Accepted but undocumented in `--help`. |

Unknown arguments are rejected (`unknown argument: <arg>`) before the data plane
starts.

Options may appear in any order and before or after `--config`. The last value
wins for repeated value flags.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Normal termination, or a successful one-shot command (`--version`, `--help`, `--install-driver`, `--uninstall-driver`, `--grant-access-only`). A second launch of an already-running instance also exits 0: it signals the running window instead. |
| `1` | Startup or runtime failure: config load/validation error, CLI override rejected, unknown argument, driver install/uninstall/grant failure, auth-token generation failure, data-plane or management-server failure in `--web-only` mode. |
| `2` | No configuration file: neither `--config` nor any fallback candidate existed. Usage is printed. |

The data plane failing to start is **not** exit code 1 in normal (UI) mode: the
window opens in degraded mode with the error shown, so the operator can fix the
adapter or the driver without losing the UI.

## Behaviour notes

* **Elevation**: the manifest requests `requireAdministrator`, so the process
  always starts elevated. There is no de-elevated child.
* **Single instance**: a second launch does not start a second gateway. It
  signals the running instance (focus the window / restore from the tray) and
  exits 0.
* **Token generation**: if `web.token` is empty, a 16-byte token is drawn from
  `BCryptGenRandom`; failure to obtain it aborts startup (exit 1) rather than
  running the management API unauthenticated.
* **Non-loopback bind**: `web.bind` outside loopback with an empty `web.token`
  disables the management server with an explanatory message. See
  [configuration](configuration.md#webui).
* **Console capture**: with the native UI running, stdout is captured into the
  console page, so the token is never printed there. Headless and `--web-only`
  runs print it once for the operator.

## Examples

Run with the shipped example config, native UI and management UI on loopback:

```bat
vgww.exe --config=config.example.json
```

Run only the management UI for API work (no driver needed):

```bat
vgww.exe --config=config.json --web-only --headless
```

Expose the management UI on the LAN (requires a token):

```bat
vgww.exe --config=config.json --web
:: config.json: "web": { "bind": "0.0.0.0", "token": "<long random string>" }
```

Install the driver, run, then remove it:

```bat
vgww.exe --install-driver
vgww.exe --config=config.json
vgww.exe --uninstall-driver
```
