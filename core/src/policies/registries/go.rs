use super::{Pattern, Registry};

pub static GO: Registry = Registry {
    prefix: "/go/",
    eco: "go",
    osv_name: "Go",
    upstream: "https://proxy.golang.org/",
    index: true,
    normalize: Some(unescape),
    patterns: &[
        // Go versions carry a v the advisories do not, so it stays out of the capture.
        Pattern { re: r"^(?<name>.+)/@v/v?(?<version>.+)\.(?:info|mod|zip)$", rewrite: None },
        // The version list and the latest lookup, which name no version.
        Pattern { re: r"^(?<name>.+)/@(?:v/list|latest)$", rewrite: None },
    ],
};

/// The proxy protocol writes every capital as !<lowercase>; advisories do not.
fn unescape(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    let mut chars = path.chars();
    while let Some(c) = chars.next() {
        match c {
            '!' => out.extend(chars.next().map(|c| c.to_ascii_uppercase())),
            c => out.push(c),
        }
    }
    out
}
