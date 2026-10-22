# Strix Firewall

Stops malicious packages before they install. Built by [Strix](https://usestrix.com).

Screening runs on your device: downloads go straight to the registry, never through a Strix
server. Each package's name and version are looked up on OSV, and usage events go to Strix unless
`"telemetry": false` is set.

## Supported registries

| Registry | Package managers |
|---|---|
| npm | npm, pnpm, bun |
| PyPI | pip, uv, pdm, pipenv |
| crates.io | cargo |
| Go module proxy | go |
| RubyGems | gem |

Mirrors of these, such as Artifactory or Nexus, can be added in the config file.

## Features

- **Blocks malware.** Each download is checked against Strix's denylist and
  [OSV](https://osv.dev) malware advisories.
- **Holds back new versions.** Versions published in the last 24 hours are blocked until they
  age; the window is configurable.
- **Alerts you.** On macOS and Windows a popup names the blocked package and links its advisory.
- **Lets you allow a new version.** **Allow Once** lets a held-back download through; **Trust this
  version** (admin) allows it for good. Malware can never be allowed.
- **Two modes:**
  - **Command prefix:** `firewall npm install left-pad`, or `alias npm='firewall npm'`.
  - **Machine-wide:** screens downloads from every app, with no prefix.

## Platforms

| | Command prefix | Machine-wide |
|---|---|---|
| macOS 13+, Apple silicon or Intel | Yes | Yes, needs a Secure Enclave |
| Windows 10/11, x86-64 | Yes | Yes, needs a TPM 2.0 |
| Linux (glibc), x86-64 or arm64 | Yes | No |

## Install

**Command prefix**

```sh
curl -LsSf https://github.com/usestrix/firewall/releases/latest/download/strix-firewall-installer.sh | sh
```

```powershell
powershell -c "irm https://github.com/usestrix/firewall/releases/latest/download/strix-firewall-installer.ps1 | iex"
```

Or `cargo install strix-firewall`.

**Machine-wide**, from the [latest release](https://github.com/usestrix/firewall/releases/latest):

- macOS: open `Firewall.pkg`, then approve the extension when macOS asks.
- Windows: run the `.msi` as an admin.

## Configuration

Settings are in a `config.json`:

- Command prefix: `~/.config/firewall/` on Linux, `~/Library/Application Support/com.usestrix.firewall/`
  on macOS, `%APPDATA%\usestrix\firewall\config\` on Windows.
- Machine-wide: `/Library/Application Support/Firewall/` on macOS, `%ProgramData%\Strix Firewall\`
  on Windows. Only an admin can edit it; restart from the menu bar or tray to apply.

```json
{
  "min_age_hours": 48,
  "registries": {
    "npm": ["https://npm.example.com/"],
    "pypi": ["https://pypi.example.com/"]
  }
}
```

`registries` lists mirrors by the registry they copy (`npm`, `pypi`, `gem`, `go`, `cargo/index`).
Both modes screen every mirror listed; command-prefix mode also downloads from the first one.

## License

Apache 2.0. See [LICENSE](LICENSE).
