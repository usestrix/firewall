# Strix's Dependency Firewall

Stops malicious packages before they install. Built by [Strix](https://strix.ai): read [the blogpost](https://www.strix.ai/blog/firewall-announcement).

Screening runs on your device: downloads go straight to the registry, never through a Strix server.
Each package's name and version are looked up [Strix's malicious-package blocklist](https://github.com/usestrix/firewall-blocklist), so installs are blocked system-wide *before* reaching your machine.

https://github.com/user-attachments/assets/835411b1-5c89-409f-b98a-cb238310429c

## Install

**Machine-wide**, from the [latest release](https://github.com/usestrix/firewall/releases/latest):

- macOS: open `Firewall.pkg`, then approve the extension when macOS asks.
- Windows: run the `.msi` as an admin.

**Prefix-mode**

cargo:
```sh
cargo install strix-firewall
```

curl: 
```sh
curl -LsSf https://github.com/usestrix/firewall/releases/latest/download/strix-firewall-installer.sh | sh
```

Powershell:
```powershell
powershell -c "irm https://github.com/usestrix/firewall/releases/latest/download/strix-firewall-installer.ps1 | iex"
```

## Platforms

| | Machine-wide | Command prefix |
|---|---|---|
| macOS 13+ | ✅ Apple silicon or T2 chip | ✅ |
| Windows 10/11, x86-64 | ✅ with a TPM 2.0 | ✅ |
| Linux (glibc 2.35+), x86-64 or arm64 | 🚧 Coming Soon | ✅ |

## Supported registries

| Registry | Package managers |
|---|---|
| npm | npm, pnpm, bun |
| PyPI | pip, uv, pdm, pipenv |
| crates.io | cargo |
| Go module proxy | go |
| RubyGems | gem |

Mirrors of these, such as Artifactory or Nexus, can be added in via a config file.

## Features

- **Up-to-the-minute data:** Strix constantly monitors updates to top packages (covering 99% of installed packages) to scan for malware, and publishes the results. We also consult [OSSF's blocklist](https://github.com/ossf/malicious-packages) and [OSV](osv.dev), as well as other public reports. Updates take effect without any user action.
- **Holds back new versions.** New packages are blocked by default, since malware is usually detected within a day. (Although this can be disabled, configured, and bypassed).
- **Alerts you.** On macOS and Windows a popup names the blocked package and links its advisory.
- **Two modes:**
  - **Machine-wide:** screens downloads from every app, across your entire machine.
  - **Command prefix:** e.g., `firewall npm install left-pad`, or create an alias with `alias npm='firewall npm`.

## Configuration

Settings are in a `config.json`:

- Machine-wide: `/Library/Application Support/Firewall/` on macOS, `%ProgramData%\Strix Firewall\`
  on Windows. Only an admin can edit it; restart from the menu bar or tray to apply.
- Command prefix: `~/.config/firewall/` on Linux, `~/Library/Application Support/com.usestrix.firewall/`
  on macOS, `%APPDATA%\usestrix\firewall\config\` on Windows.

```json
{
  "min_age_hours": 48,
  "allow": { "npm": [{ "name": "left-pad", "version": "1.3.0" }] },
  "registries": {
    "npm": ["https://npm.example.com/"],
    "pypi": ["https://pypi.example.com/"]
  },
  "telemetry": false
}
```

| Key | Default | |
|---|---|---|
| `min_age_hours` | `24` | How long new versions are held back. `0` turns this off. |
| `allow` | none | Packages exempt from the hold, by ecosystem (`npm`, `pypi`, `cargo`, `gem`, `go`). Omit `version` for every version. Known malware is still blocked. |
| `registries` | none | Mirrors, by the registry they copy (`npm`, `pypi`, `gem`, `go`, `cargo/index`). Both modes screen every mirror listed; command-prefix mode also downloads from the first one. |
| `fail_open` | `true` | Allow a package when it can't be checked. |
| `telemetry` | `true` | Log anonymized usage events to Strix. |
| `port` | `8080` | Local port for command-prefix mode. |

## License

Apache 2.0. See [LICENSE](LICENSE).
