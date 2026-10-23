use super::{Pattern, Published, Registry};

const FILES: (&str, &str) = ("https://files.pythonhosted.org/", "/pypi-files/");

pub static PYPI: Registry = Registry {
    prefix: "/pypi/",
    eco: "pypi",
    osv_name: "PyPI",
    upstream: "https://pypi.org/",
    index: true,
    normalize: Some(pep503),
    patterns: &[
        Pattern { re: r"^simple/(?<name>[^/]+)", rewrite: Some(FILES) },
        // A mirror serves the files from its index host.
        WHEEL,
        SDIST,
        Pattern { re: "", rewrite: Some(FILES) },
    ],
    published: PUBLISHED,
};

/// The directories are hash shards, but the filename names the distribution.
pub static PYPI_FILES: Registry = Registry {
    prefix: "/pypi-files/",
    eco: "pypi",
    osv_name: "PyPI",
    upstream: "https://files.pythonhosted.org/",
    index: false,
    normalize: Some(pep503),
    patterns: &[WHEEL, SDIST],
    published: PUBLISHED,
};

// A wheel escapes - _ and . to _, so the first two fields are exactly name and version.
const WHEEL: Pattern = Pattern {
    re: r"^packages/.+/(?<name>[^-/]+)-(?<version>[^-/]+)-[^/]+\.whl(?:\.metadata)?$",
    rewrite: None,
};

// An sdist keeps the name's hyphens, so the version is the last field starting with a digit.
const SDIST: Pattern = Pattern {
    re: r"^packages/.+/(?<name>.+)-(?<version>\d[^-/]*)\.(?:tar\.gz|zip|tar\.bz2)$",
    rewrite: None,
};

const PUBLISHED: Option<Published> = Some(Published {
    url: "https://pypi.org/pypi/{name}/{version}/json",
    pointer: "/urls/0/upload_time_iso_8601",
    escape: None,
});

/// PEP 503: runs of - _ and . collapse to one -, lowercased, which also un-escapes a wheel.
fn pep503(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for c in name.chars() {
        match c {
            '-' | '_' | '.' if out.ends_with('-') => {}
            '-' | '_' | '.' => out.push('-'),
            c => out.extend(c.to_lowercase()),
        }
    }
    out
}
