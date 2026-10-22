# Supported platforms

The `firewall` command screens what one command installs (`firewall npm install …`) or serves a
local registry (`firewall serve`). Machine-wide screening, which needs no command prefix, is
macOS and Windows only.

| Platform | Architectures | `firewall <manager>` and `serve` | Machine-wide |
|---|---|---|---|
| macOS 13+ | Apple silicon, Intel | Yes | Apple silicon only: the app's system extension |
| Windows 10/11 | x86-64 | Yes | Yes: the MSI, needs a TPM 2.0 |
| Linux (glibc) | x86-64, arm64 | Yes | No |

Release builds come from cargo-dist for exactly the targets above: `aarch64-apple-darwin`,
`x86_64-apple-darwin`, `aarch64-unknown-linux-gnu`, `x86_64-unknown-linux-gnu` and
`x86_64-pc-windows-msvc`. There are no musl, 32-bit or Windows on Arm builds.

`cargo install strix-firewall` installs only `firewall`. The machine-wide binaries come with the
macOS app and the MSI, or with `--features machine-wide`.

## Package managers

`firewall <manager>` supports npm, pnpm, bun, pip, pip3, pipenv, pdm, uv, cargo, go and gem.
They are screened against these registries:

| Ecosystem | Hosts |
|---|---|
| npm | registry.npmjs.org |
| PyPI | pypi.org, files.pythonhosted.org |
| crates.io | index.crates.io, static.crates.io, crates.io |
| RubyGems | rubygems.org |
| Go | proxy.golang.org |

Private registries and mirrors are not screened.

## Machine-wide screening

Traffic to the hosts above is intercepted with a local CA that is name-constrained to them, so
it can sign nothing else. Its private key never leaves the hardware.

**macOS**
- Needs macOS 13 or later on Apple silicon. The key is held in the Secure Enclave.
- The system extension must be approved in System Settings.

**Windows**
- Needs Windows 10 or 11 on x86-64 with a TPM 2.0. The key is held in the TPM.
- Without a TPM, the service cannot start, so the MSI fails rather than falling back to a
  software key.
- Installing and removing the MSI needs an admin.
- A notification-area icon shows whether screening is on. Any signed-in user can pause
  screening from it, until they resume it or the service restarts.
- The hosts file sends each registry host to a local service. Clients must therefore trust the
  Windows certificate store, or the CA exported to `%ProgramData%\Strix Firewall\ca.pem`.
  - npm, pnpm and bun use the exported CA via `NODE_EXTRA_CA_CERTS`.
  - uv uses the store via `UV_SYSTEM_CERTS`.
  - pip and cargo use the store directly.
  - gem and go are untested.
- Not covered:
  - Clients that resolve through an HTTP proxy or their own DNS skip the hosts file, and are
    not screened.
  - WSL is not supported.

Windows machine-wide screening has been tested on Windows 11 only.
