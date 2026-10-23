use super::{Manager, PROXY};

/// pnpm reads its own npm_config_* namespace and ignores npm's.
pub static PNPM: Manager = Manager {
    command: "pnpm",
    env: &[
        ("pnpm_config_proxy", PROXY),
        ("pnpm_config_https_proxy", PROXY),
        ("pnpm_config_registry", "http://registry.npmjs.org/"),
    ],
    args: &[],
    lockfile: None,
};
