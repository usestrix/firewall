use super::{Manager, PROXY};

/// bun ignores npm_config_proxy but honours npm_config_registry and http_proxy.
pub static BUN: Manager = Manager {
    command: "bun",
    env: &[
        ("http_proxy", PROXY),
        ("https_proxy", PROXY),
        ("npm_config_registry", "http://registry.npmjs.org/"),
    ],
    args: &[],
};
