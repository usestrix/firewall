use super::{Manager, PROXY};

pub static NPM: Manager = Manager {
    command: "npm",
    env: &[
        ("npm_config_proxy", PROXY),
        ("npm_config_https_proxy", PROXY),
        ("npm_config_registry", "http://{npm}/"),
    ],
    args: &[],
};
