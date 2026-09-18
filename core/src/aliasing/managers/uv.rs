use super::{Manager, PROXY, PYPI_SIMPLE};

pub static UV: Manager = Manager {
    command: "uv",
    env: &[("HTTP_PROXY", PROXY), ("UV_DEFAULT_INDEX", PYPI_SIMPLE)],
    args: &[],
};
