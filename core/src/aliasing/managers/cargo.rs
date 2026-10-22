use super::{Args, Manager, PROXY};

pub static CARGO: Manager = Manager {
    command: "cargo",
    env: &[
        ("CARGO_HTTP_PROXY", PROXY),
        // Cargo drives sparse registries over HTTP/2 and rejects our HTTP/1.1 reply.
        ("CARGO_HTTP_MULTIPLEXING", "false"),
    ],
    // Cargo ignores CARGO_REGISTRIES_CRATES_IO_INDEX and CARGO_SOURCE_*; only --config works.
    args: &[Args {
        when: &[],
        flags: &[
            "--config",
            "source.crates-io.replace-with=\"firewall\"",
            "--config",
            "source.firewall.registry=\"sparse+http://{cargo/index}/\"",
        ],
    }],
};
