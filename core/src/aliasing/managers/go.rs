use super::{Manager, PROXY};

pub static GO: Manager = Manager {
    command: "go",
    // GOSUMDB would add a second, unproxied leg to sum.golang.org.
    env: &[
        ("HTTP_PROXY", PROXY),
        ("http_proxy", PROXY),
        ("GOPROXY", "http://{go}"),
        ("GOSUMDB", "off"),
        ("GOFLAGS", "-mod=mod"),
    ],
    args: &[],
};
