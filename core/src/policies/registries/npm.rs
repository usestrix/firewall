use super::{Pattern, Published, Registry};

pub static NPM: Registry = Registry {
    prefix: "/npm/",
    eco: "npm",
    osv_name: "npm",
    upstream: "https://registry.npmjs.org/",
    index: true,
    normalize: None,
    patterns: &[
        // Both halves of <basename>-<version>.tgz hold hyphens; only the version is semver.
        Pattern {
            re: r"^(?<name>@[^/]+/[^/]+|[^/]+)/-/.*-(?<version>\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)\.tgz$",
            rewrite: None,
        },
        Pattern {
            re: r"^(?<name>@[^/]+(?:/|%2[fF])[^/]+|[^/]+)/?$",
            rewrite: Some(("https://registry.npmjs.org/", "/npm/")),
        },
    ],
    published: Some(Published {
        url: "https://registry.npmjs.org/{name}",
        pointer: "/time/{version}",
        escape: None,
    }),
};
