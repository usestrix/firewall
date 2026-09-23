use super::{Pattern, Registry};

pub static GEM: Registry = Registry {
    prefix: "/gem/",
    eco: "gem",
    osv_name: "RubyGems",
    upstream: "https://rubygems.org/",
    index: true,
    normalize: None,
    patterns: &[
        // gems/<name>-<version>[-<platform>].gem: a version starts with a digit, a platform does not.
        Pattern {
            re: r"^gems/(?<name>.+)-(?<version>\d[^-/]*)(?:-[a-z][^/]*)?\.gem$",
            rewrite: None,
        },
        // The compact index, which names no version.
        Pattern { re: r"^info/(?<name>[^/]+)$", rewrite: None },
    ],
};
