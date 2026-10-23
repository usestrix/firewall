use super::{Args, Manager, PROXY};

pub static GEM: Manager = Manager {
    command: "gem",
    env: &[("http_proxy", PROXY), ("HTTP_PROXY", PROXY)],
    // gem has no variable for the source list, and gem env and gem sources reject the flags.
    args: &[Args {
        when: &["install", "update", "fetch"],
        flags: &["--clear-sources", "--source", "http://rubygems.org/"],
    }],
    lockfile: None,
};
