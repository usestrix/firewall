use super::{Manager, PROXY, PYPI_SIMPLE};

/// pip ignores a plaintext index unless the host, and the artefact host, are trusted.
const PIP_ENV: &[(&str, &str)] = &[
    ("PIP_PROXY", PROXY),
    ("PIP_INDEX_URL", PYPI_SIMPLE),
    ("PIP_TRUSTED_HOST", "pypi.org files.pythonhosted.org"),
    ("PIP_DISABLE_PIP_VERSION_CHECK", "1"),
];

pub static PIP: Manager = recipe("pip");
pub static PIP3: Manager = recipe("pip3");

const fn recipe(name: &'static str) -> Manager {
    Manager { command: name, env: PIP_ENV, args: &[] }
}
