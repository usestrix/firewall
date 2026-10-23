use super::{Lockfile, Manager, PROXY};

pub static NPM: Manager = Manager {
    command: "npm",
    env: &[
        ("npm_config_proxy", PROXY),
        ("npm_config_https_proxy", PROXY),
        ("npm_config_registry", "http://registry.npmjs.org/"),
    ],
    args: &[],
    lockfile: Some(Lockfile::Restore("package-lock.json")),
};
