use super::{Pattern, Registry};

pub static NPM: Registry = Registry {
    prefix: "/npm/",
    eco: "npm",
    osv_name: "npm",
    upstream: "https://registry.npmjs.org/",
    index: true,
    patterns: &[
        // Tarballs are <name>/-/<basename>-<version>.tgz, and the version is the last hyphen group starting with a digit.
        Pattern {
            re: r"^(?<name>@[^/]+/[^/]+|[^-/][^/]*)/-/.*-(?<version>\d[^/]*)\.tgz$",
            rewrite: None,
        },
        Pattern {
            re: r"^(?<name>@[^/]+(?:/|%2[fF])[^/]+|[^-/][^/]*)/?$",
            rewrite: Some(("https://registry.npmjs.org/", "/npm/")),
        },
    ],
};
