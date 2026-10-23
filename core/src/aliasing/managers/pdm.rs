use super::{Manager, PROXY, PYPI_SIMPLE};

/// pdm skips an untrusted index, and turning off SSL verification is what trusts it.
pub static PDM: Manager = Manager {
    command: "pdm",
    env: &[
        ("HTTP_PROXY", PROXY),
        ("HTTPS_PROXY", PROXY),
        // urllib prefers lowercase, so a user's own http_proxy would otherwise win.
        ("http_proxy", PROXY),
        ("https_proxy", PROXY),
        ("PDM_PYPI_URL", PYPI_SIMPLE),
        ("PDM_PYPI_VERIFY_SSL", "false"),
    ],
    args: &[],
    lockfile: None,
};
