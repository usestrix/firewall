//! The tray's task dialogs exist only in version 6 of the common controls, which takes a manifest.
fn main() {
    println!("cargo:rerun-if-changed=src/bin/firewall-tray.manifest");
    let msvc = std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc");
    if msvc && std::env::var_os("CARGO_FEATURE_MACHINE_WIDE").is_some() {
        let manifest = concat!(env!("CARGO_MANIFEST_DIR"), "/src/bin/firewall-tray.manifest");
        println!("cargo:rustc-link-arg-bin=firewall-tray=/MANIFEST:EMBED");
        println!("cargo:rustc-link-arg-bin=firewall-tray=/MANIFESTINPUT:{manifest}");
    }
}
