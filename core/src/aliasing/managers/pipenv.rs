use super::{Manager, PROXY, PYPI_SIMPLE};

pub static PIPENV: Manager = Manager {
    command: "pipenv",
    env: &[("HTTP_PROXY", PROXY), ("HTTPS_PROXY", PROXY), ("PIPENV_PYPI_MIRROR", PYPI_SIMPLE)],
    args: &[],
};
