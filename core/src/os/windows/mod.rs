//! The hosts file sends each registry host to its own loopback address, where a
//! LocalSystem service screens it as the macOS extension does.

mod tpm;

pub use tpm::TpmKey;

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain([0]).collect()
}
