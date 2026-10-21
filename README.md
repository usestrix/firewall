# Strix Firewall

Stops malicious packages before they install. When a package manager downloads a package, the firewall checks its name and version against Strix's denylist and [OSV](https://osv.dev) malware advisories, and fails the download if either flags it.

It covers npm, pnpm, bun, pip, uv, pipenv, pdm, cargo, gem and go.

## Install

**Command-line tool** (macOS, Linux, Windows):

```sh
brew install usestrix/tap/strix-firewall
# or
cargo install strix-firewall
```

**Whole-machine firewall** (macOS on Apple Silicon, macOS 13 or later):

1. Download `Firewall.pkg` from the [latest release](https://github.com/usestrix/firewall/releases/latest) and open it.
2. Open **Firewall** from Applications and click **Install**.
3. Approve the system extension and admin prompts when macOS asks.

To remove it, open Firewall and click **Uninstall**.

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

## Build from source

```sh
cd core && cargo run --bin firewall -- npm install left-pad
```

The macOS app needs [XcodeGen](https://github.com/yonaskolb/XcodeGen), a Developer ID certificate, and Developer ID profiles for `com.usestrix.firewall` and `com.usestrix.firewall.extension`:

```sh
echo TEAM=<Apple team ID> > macos/.env
macos/build.sh   # builds macos/build/Firewall.pkg; set NOTARY_PROFILE in .env to notarize
```

## License

Apache 2.0. See [LICENSE](LICENSE).
