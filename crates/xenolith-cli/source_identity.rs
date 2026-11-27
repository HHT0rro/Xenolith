//! Shared by the CLI build script and release assembly. Only repository-local
//! ignore rules apply, so extraction into a different machine keeps the identity.

use anyhow::{bail, Context, Result};
use ignore::WalkBuilder;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs, path::Path};

pub const SCHEMA: &str = "xenolith-product-sources-v1";

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Identity {
    pub schema: String,
    pub sha256: String,
    /// Repo-relative POSIX paths mapped to SHA-256 of their exact file bytes.
    pub files: BTreeMap<String, String>,
}

#[derive(Serialize)]
pub struct Snapshot {
    pub identity: Identity,
    /// UTF-8 source text, with original line endings. Paths are sorted.
    pub files: BTreeMap<String, String>,
}

pub fn collect(root: &Path) -> Result<Snapshot> {
    let root = root.canonicalize().context("locate source root")?;
    for required in [
        "Cargo.toml",
        "Cargo.lock",
        "crates/xenolith-cli/Cargo.toml",
        "crates/xenolith-cli/src/main.rs",
    ] {
        if !root.join(required).is_file() {
            bail!("source identity input missing: {required}");
        }
    }
    let filter_root = root.clone();
    let walker = WalkBuilder::new(&root)
        .hidden(false)
        .ignore(false)
        .parents(false)
        .git_global(false)
        .git_exclude(false)
        .require_git(false)
        .follow_links(false)
        .filter_entry(move |entry| {
            let relative = entry
                .path()
                .strip_prefix(&filter_root)
                .expect("walk beneath source root");
            relative.as_os_str().is_empty()
                || in_scope(
                    relative,
                    entry
                        .file_type()
                        .is_some_and(|kind| kind.is_dir() || kind.is_symlink()),
                )
        })
        .build();
    let mut files = BTreeMap::new();
    let mut hashes = BTreeMap::new();
    for entry in walker {
        let entry = entry.context("enumerate product sources")?;
        if let Some(error) = entry.error() {
            bail!("invalid source ignore rules: {error}");
        }
        if entry.file_type().is_some_and(|kind| kind.is_dir()) {
            continue;
        }
        if !entry.file_type().is_some_and(|kind| kind.is_file()) {
            bail!(
                "source identity requires a regular file: {}",
                entry.path().display()
            );
        }
        let relative = entry.path().strip_prefix(&root)?;
        let path = relative
            .iter()
            .map(|part| part.to_str().context("non-UTF-8 source path"))
            .collect::<Result<Vec<_>>>()?
            .join("/");
        if path.contains('\\') {
            bail!("non-portable source path: {path}");
        }
        let text =
            fs::read_to_string(entry.path()).with_context(|| format!("read source {path}"))?;
        hashes.insert(
            path.clone(),
            format!("{:x}", Sha256::digest(text.as_bytes())),
        );
        files.insert(path, text);
    }
    let mut hash = Sha256::new();
    hash.update(SCHEMA.as_bytes());
    hash.update([0]);
    hash.update(serde_json::to_vec(&hashes)?);
    Ok(Snapshot {
        identity: Identity {
            schema: SCHEMA.into(),
            sha256: format!("{:x}", hash.finalize()),
            files: hashes,
        },
        files,
    })
}

fn in_scope(path: &Path, directory: bool) -> bool {
    let parts: Vec<_> = path.iter().filter_map(|part| part.to_str()).collect();
    if parts.iter().any(|part| {
        matches!(*part, "target" | "dist" | "out")
            || (part.starts_with('.') && !matches!(*part, ".cargo" | ".gitignore"))
    }) {
        return false;
    }
    if parts.first() == Some(&".cargo") {
        return (directory && parts.len() == 1)
            || (!directory
                && parts.len() == 2
                && matches!(parts[1], "config" | "config.toml" | ".gitignore"));
    }
    if parts.len() == 1 && !directory {
        return matches!(
            parts[0],
            "Cargo.toml"
                | "Cargo.lock"
                | ".gitignore"
                | "rust-toolchain"
                | "rust-toolchain.toml"
                | "LICENSE"
        );
    }
    if !matches!(parts.first(), Some(&"crates" | &"samples" | &".cargo")) {
        return false;
    }
    directory
        || matches!(
            path.file_name().and_then(|name| name.to_str()),
            Some(".gitignore" | "Cargo.lock")
        )
        || matches!(
            path.extension().and_then(|ext| ext.to_str()),
            Some(
                "rs" | "c"
                    | "cpp"
                    | "h"
                    | "hpp"
                    | "s"
                    | "S"
                    | "asm"
                    | "inc"
                    | "ld"
                    | "map"
                    | "def"
                    | "rc"
                    | "toml"
            )
        )
}

// Used by release assembly, while build.rs only collects the inventory.
#[allow(dead_code)]
pub fn verify(build: &Identity, current: &Identity) -> Result<()> {
    if build == current {
        return Ok(());
    }
    let added: Vec<_> = current
        .files
        .keys()
        .filter(|path| !build.files.contains_key(*path))
        .collect();
    let removed: Vec<_> = build
        .files
        .keys()
        .filter(|path| !current.files.contains_key(*path))
        .collect();
    let changed: Vec<_> = build
        .files
        .iter()
        .filter_map(|(path, hash)| {
            current
                .files
                .get(path)
                .filter(|current| *current != hash)
                .map(|_| path)
        })
        .collect();
    bail!(
        "release source drift from compiled CLI (build {}, current {}); added {:?}; removed {:?}; changed {:?}. Rebuild xenolith-cli from this source tree and retry release",
        build.sha256, current.sha256, added, removed, changed
    );
}
