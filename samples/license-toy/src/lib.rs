//! The real artifact is `license_toy.dll` emitted by `build.rs` from C.
//! This rlib exists so Cargo has a package target.

pub const EXPORT: &str = "check_license";
