# Strix Firewall

Stops malicious packages before they install. When a package manager downloads a package, the firewall checks its name and version against Strix's denylist and [OSV](https://osv.dev) malware advisories, and fails the download if either flags it.

It covers npm, pnpm, bun, pip, uv, pipenv, pdm, cargo, gem and go.

## Install

There are no prebuilt releases yet; build from a clone of this repository.

**Command-line tool** (macOS, Linux):

```sh
cargo install --path core
```

**Whole-machine firewall** (macOS 13 or later on Apple Silicon):

1. Build `Firewall.pkg` (see [Building the macOS app](#building-the-macos-app)) and open it.
2. Open **StrixFirewall** from Applications and click **Install**.
3. Approve the system extension, the network configuration and the certificate when macOS asks, then restart.

It then lives in the menu bar. To remove it, choose **Setup** from the menu and click **Uninstall**.

## Use

Put `firewall` in front of a package manager command:

```sh
firewall npm install left-pad
```

Or alias the manager so every install is checked:

```sh
alias npm='firewall npm'
```

The whole-machine firewall needs no setup: it checks downloads from every process.

## Configure

Settings come from an optional `config.json`; a file only needs the keys it changes:

```json
{
  "min_age_hours": 24,
  "allow": { "npm": [{ "name": "left-pad", "version": "1.3.0" }] }
}
```

| Key | Default | |
| --- | --- | --- |
| `fail_open` | `true` | Allow a package when it could not be checked |
| `min_age_hours` | `0` | Hold back versions newer than this; 0 turns it off |
| `allow` | `{}` | Packages never screened, by ecosystem (`npm`, `pypi`, `cargo`, `gem`, `go`); every version when `version` is absent |
| `telemetry` | `true` | Send screening events, errors and a heartbeat to Strix |
| `port` | `8080` | Port for `firewall serve` |

The command-line tool reads `~/Library/Application Support/com.usestrix.firewall/config.json` on macOS and `~/.config/firewall/config.json` on Linux. On macOS, `/Library/Application Support/Firewall/config.json` overrides it key by key (allow lists add up), and is the only file the whole-machine firewall reads.

## Building the macOS app

It needs [XcodeGen](https://github.com/yonaskolb/XcodeGen), a Developer ID certificate, and Developer ID profiles for `com.usestrix.firewall` and `com.usestrix.firewall.extension`:

```sh
echo TEAM=<Apple team ID> > macos/.env
echo NOTARY_PROFILE=<notarytool keychain profile> >> macos/.env
macos/build.sh         # builds and notarizes macos/build/Firewall.pkg
macos/build.sh debug   # signs with Apple Development and skips notarization
```

## License

Apache 2.0. See [LICENSE](LICENSE).
