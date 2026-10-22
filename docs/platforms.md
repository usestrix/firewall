# Platforms

## Requirements

| | Command prefix | Machine-wide |
|---|---|---|
| macOS | 13+, Apple silicon or Intel | Apple silicon, or an Intel Mac with a T2 chip |
| Windows | 10 or 11, x86-64 | A TPM 2.0, and an admin to install |
| Linux | glibc, x86-64 or arm64 | Not supported |

There are no musl, 32-bit or Windows on Arm builds.

`cargo install strix-firewall` installs only `firewall`. Add `--features machine-wide` for the
machine-wide binaries, which otherwise come with the macOS app and the Windows MSI.

## What is screened

npm, pnpm, bun, pip, pip3, pipenv, pdm, uv, cargo, go and gem, downloading from:

| Ecosystem | Hosts |
|---|---|
| npm | registry.npmjs.org |
| PyPI | pypi.org, files.pythonhosted.org |
| crates.io | index.crates.io, static.crates.io, crates.io |
| RubyGems | rubygems.org |
| Go | proxy.golang.org |

Private registries and mirrors are not screened.

## How machine-wide screening works

Traffic to the hosts above is decrypted with a local CA that can only sign for those hosts. Its
private key never leaves the Secure Enclave (macOS) or the TPM (Windows).

- **macOS:** a system extension, which you approve in System Settings.
- **Windows:** a service, with a hosts-file entry pointing each registry host at it.
  - Without a TPM, the service can't start, so the install fails.
  - Any signed-in user can pause screening from the notification-area icon, until they resume
    it or the service restarts.
  - Clients that use an HTTP proxy or their own DNS skip the hosts file and aren't screened.
    Nor is WSL.
  - Each client has to trust the CA:

    | Client | Trusts it through |
    |---|---|
    | npm, pnpm, bun | `NODE_EXTRA_CA_CERTS`, set to `%ProgramData%\Strix Firewall\ca.pem` |
    | uv | `UV_SYSTEM_CERTS`, which uses the Windows certificate store |
    | pip, cargo | The Windows certificate store |
    | gem, go | Untested |

Tested on Windows 11 and Apple silicon only.

## Changing settings

Machine-wide screening reads an admin-only JSON file when it starts. After editing it, restart
screening. An invalid file stops screening from starting.

| OS | File | Restart from |
|---|---|---|
| macOS | `/Library/Application Support/Firewall/config.json` | The menu bar's Restart |
| Windows | `%ProgramData%\Strix Firewall\config.json` | The notification-area icon's Restart |

The `firewall` command reads `config.json` from the user's config folder instead.
