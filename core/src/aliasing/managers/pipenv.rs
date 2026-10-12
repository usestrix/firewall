use super::{Manager, PROXY, PYPI_SIMPLE};

pub static PIPENV: Manager = Manager {
    command: "pipenv",
    env: &[
        ("HTTP_PROXY", PROXY),
        ("HTTPS_PROXY", PROXY),
        // urllib prefers lowercase, so a user's own http_proxy would otherwise win.
        ("http_proxy", PROXY),
        ("https_proxy", PROXY),
        ("PIPENV_PYPI_MIRROR", PYPI_SIMPLE),
        // pipenv installs through pip, which skips a plaintext index on a host it doesn't trust.
        ("PIP_TRUSTED_HOST", "pypi.org files.pythonhosted.org"),
    ],
    args: &[],
};
