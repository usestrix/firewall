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

## Building the macOS app

It needs [XcodeGen](https://github.com/yonaskolb/XcodeGen), a Developer ID certificate, and Developer ID profiles for `com.usestrix.firewall` and `com.usestrix.firewall.extension`:

```sh
echo TEAM=<Apple team ID> > macos/.env
macos/build.sh   # builds macos/build/Firewall.pkg; set NOTARY_PROFILE in .env to notarize
```

## License

Apache 2.0. See [LICENSE](LICENSE).
