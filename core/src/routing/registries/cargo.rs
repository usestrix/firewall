use super::{Pattern, Registry};

pub static CARGO_INDEX: Registry = Registry {
    prefix: "/cargo/index/",
    eco: "cargo",
    osv: "crates.io",
    upstream: "https://index.crates.io/",
    index: true,
    patterns: &[
        // Carries no package; it exists to steer downloads at CARGO_DL, which does see the version.
        Pattern {
            re: r"^config\.json$",
            rewrite: Some(("https://static.crates.io/crates", "/cargo-dl")),
        },
        // Sparse index paths shard by name: le/ft/left-pad, 3/s/syn, 2/cc.
        Pattern { re: r"(?<name>[^/]+)$", rewrite: None },
    ],
};

pub static CARGO_DL: Registry = Registry {
    prefix: "/cargo-dl/",
    eco: "cargo",
    osv: "crates.io",
    upstream: "https://static.crates.io/crates/",
    index: false,
    patterns: &[Pattern { re: r"^(?<name>[^/]+)/(?<version>[^/]+)", rewrite: None }],
};

/// `cargo add` resolves versions here, named by config.json's "api" field.
pub static CRATES_API: Registry = Registry {
    prefix: "/crates-api/",
    eco: "cargo",
    osv: "crates.io",
    upstream: "https://crates.io/",
    index: false,
    patterns: &[],
};
