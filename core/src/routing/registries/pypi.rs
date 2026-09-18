use super::{Pattern, Registry};

const FILES: (&str, &str) = ("https://files.pythonhosted.org/", "/pypi-files/");

pub static PYPI: Registry = Registry {
    prefix: "/pypi/",
    eco: "pypi",
    osv: "PyPI",
    upstream: "https://pypi.org/",
    index: true,
    patterns: &[
        Pattern { re: r"^simple/(?<name>[^/]+)", rewrite: Some(FILES) },
        Pattern { re: "", rewrite: Some(FILES) },
    ],
};

/// Downloads are hash-sharded, so no pattern here names the package yet.
pub static PYPI_FILES: Registry = Registry {
    prefix: "/pypi-files/",
    eco: "pypi",
    osv: "PyPI",
    upstream: "https://files.pythonhosted.org/",
    index: false,
    patterns: &[],
};
