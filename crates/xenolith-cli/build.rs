mod source_identity;

use anyhow::{Context, Result};
use std::{env, fs, path::Path};

fn main() -> Result<()> {
    let manifest_dir = env::var_os("CARGO_MANIFEST_DIR").context("CARGO_MANIFEST_DIR")?;
    let root = Path::new(&manifest_dir).join("../..").canonicalize()?;
    let snapshot = source_identity::collect(&root)?;

    // Directory watches detect new source files as well as edits and deletions.
    // Build output belongs outside these product directories.
    for path in [
        "crates",
        "samples",
        ".cargo",
        "Cargo.toml",
        "Cargo.lock",
        ".gitignore",
        "rust-toolchain",
        "rust-toolchain.toml",
        "LICENSE",
    ] {
        println!("cargo:rerun-if-changed={}", root.join(path).display());
    }
    let out = env::var_os("OUT_DIR").context("OUT_DIR")?;
    fs::write(
        Path::new(&out).join("source-identity.json"),
        serde_json::to_vec(&snapshot.identity)?,
    )?;
    println!(
        "cargo:rustc-env=XENOLITH_BUILD_SOURCE_SHA256={}",
        snapshot.identity.sha256
    );
    Ok(())
}
