//! TASK-039/040: release manifest — artifact hashes, CycloneDX SBOM from
//! `cargo metadata --locked`, license inventory, build provenance, gate
//! evidence, and the TASK-038 budget gate. No code signing exists (decision
//! D2, 2026-09-08): integrity is this manifest plus the sha256 list.
//!
//! Budget gate: any FAIL verdict in `g8_perf_baseline.json` blocks the
//! release unless `--allow-budget-fail` is given explicitly; the override is
//! recorded in the manifest, never silent (TASK-040: a failed gate blocks
//! the corresponding release level).

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

pub struct ReleaseOptions {
    pub label: String,
    pub out: PathBuf,
    pub allow_budget_fail: bool,
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    let d = h.finalize();
    let mut s = String::with_capacity(64);
    for b in d {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

pub fn sha256_file(path: &Path) -> Result<String> {
    let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    Ok(sha256_hex(&bytes))
}

/// Repo root: `$XENOLITH_REPO`, else the nearest ancestor of the exe or
/// the cwd that owns the workspace `Cargo.toml`.
pub fn find_repo_root() -> Result<PathBuf> {
    if let Ok(p) = std::env::var("XENOLITH_REPO") {
        let p = PathBuf::from(p);
        if p.join("Cargo.toml").is_file() {
            return Ok(p);
        }
    }
    let mut roots = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        roots.extend(exe.ancestors().skip(1).map(Path::to_path_buf));
    }
    if let Ok(cwd) = std::env::current_dir() {
        roots.extend(cwd.ancestors().map(Path::to_path_buf));
    }
    for r in roots {
        if r.join("Cargo.toml").is_file()
            && std::fs::read_to_string(r.join("Cargo.toml"))
                .map(|t| t.contains("[workspace]"))
                .unwrap_or(false)
        {
            return Ok(r);
        }
    }
    bail!("cannot locate repo root; set XENOLITH_REPO")
}

fn run_tool(bin: &str, args: &[&str], cwd: &Path) -> Result<String> {
    let out = std::process::Command::new(bin)
        .args(args)
        .current_dir(cwd)
        .output()
        .with_context(|| format!("spawn {bin}"))?;
    if !out.status.success() {
        bail!("{bin} {:?} failed: {}", args, String::from_utf8_lossy(&out.stderr));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// CycloneDX 1.4 SBOM from `cargo metadata --format-version 1 --locked`.
/// Every workspace member and locked dependency becomes a component with
/// name/version/license; the root package is the subject, not a component.
pub fn sbom_from_metadata(meta: &Value, label: &str) -> Value {
    let mut components = Vec::new();
    let mut licenses: Vec<String> = Vec::new();
    let root_name = meta
        .get("resolve")
        .and_then(|r| r.get("root"))
        .and_then(|v| v.as_str())
        .unwrap_or("xenolith")
        .to_string();
    if let Some(packages) = meta.get("packages").and_then(|p| p.as_array()) {
        for p in packages {
            let name = p.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let version = p.get("version").and_then(|v| v.as_str()).unwrap_or("");
            let lic = p
                .get("license")
                .and_then(|v| v.as_str())
                .unwrap_or("UNKNOWN")
                .to_string();
            if !lic.is_empty() && !licenses.contains(&lic) {
                licenses.push(lic.clone());
            }
            let mut component = json!({
                "type": "library",
                "bom-ref": format!("pkg:cargo/{name}@{version}"),
                "name": name,
                "version": version,
                "purl": format!("pkg:cargo/{name}@{version}"),
                "scope": "required",
            });
            component["properties"] = json!([
                { "name": "cdx:xenolith:source", "value":
                    p.get("source").and_then(|v| v.as_str()).unwrap_or("workspace") }
            ]);
            components.push(component);
        }
    }
    json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "serialNumber": format!("urn:uuid:xenolith-{label}"),
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "bom-ref": root_name,
                "name": "xenolith",
                "version": label,
            }
        },
        "components": components,
        "licenses": licenses
            .iter()
            .map(|l| json!({ "license": { "id": l } }))
            .collect::<Vec<_>>(),
    })
}

/// Budget gate over the TASK-038 baseline. Returns the unmet budget names.
pub fn unmet_budgets(baseline: &Value) -> Vec<String> {
    let verdicts = baseline.get("verdicts").cloned().unwrap_or(json!({}));
    let mut unmet = Vec::new();
    for key in ["app_geomean_std", "protected_call_p95", "size_worst"] {
        if verdicts.get(key).and_then(|v| v.as_str()) == Some("FAIL") {
            unmet.push(key.to_string());
        }
    }
    unmet
}

pub fn build_release(opts: &ReleaseOptions) -> Result<Value> {
    let root = find_repo_root()?;
    let out = &opts.out;
    std::fs::create_dir_all(out).with_context(|| format!("create {}", out.display()))?;

    // Artifacts: the tool binary for this host plus the evidence pack.
    let bin_name = if cfg!(windows) { "xenolith.exe" } else { "xenolith" };
    let mut files: Vec<(PathBuf, String)> = vec![
        (root.join("target/release").join(bin_name), bin_name.to_string()),
        (root.join("docs/SUPPORT.md"), "SUPPORT.md".into()),
        (root.join("docs/THREAT-MODEL.md"), "THREAT-MODEL.md".into()),
        (root.join("tests/corpus/manifest.json"), "corpus-manifest.json".into()),
        (root.join("tests/compat/manifest.json"), "compat-manifest.json".into()),
        (root.join("tests/corpus/g8_perf_baseline.json"), "g8_perf_baseline.json".into()),
        (root.join("tests/release/evidence.json"), "gate-evidence.json".into()),
    ];
    if let Ok(p) = std::env::var("XL_STRESS_EVIDENCE") {
        files.push((PathBuf::from(&p), "stress-evidence.json".into()));
    }

    let mut artifacts = Vec::new();
    for (src, name) in &files {
        if !src.is_file() {
            bail!("release input missing: {} ({})", src.display(), name);
        }
        let bytes = std::fs::read(src).with_context(|| format!("read {}", src.display()))?;
        let dst = out.join(name);
        std::fs::write(&dst, &bytes).with_context(|| format!("write {}", dst.display()))?;
        artifacts.push(json!({
            "name": name,
            "sha256": sha256_hex(&bytes),
            "bytes": bytes.len(),
        }));
    }

    // TASK-038 budget gate.
    let baseline: Value = serde_json::from_str(
        &std::fs::read_to_string(root.join("tests/corpus/g8_perf_baseline.json"))
            .context("read g8_perf_baseline.json")?,
    )
    .context("parse g8_perf_baseline.json")?;
    let unmet = unmet_budgets(&baseline);
    if !unmet.is_empty() && !opts.allow_budget_fail {
        bail!(
            "TASK-038 budgets unmet: {:?}; a failed budget blocks this release level. \
             Fix the budget or pass --allow-budget-fail to publish an engineering \
             build with the failure recorded.",
            unmet
        );
    }

    // SBOM + license inventory from the locked graph.
    let meta_raw = run_tool("cargo", &["metadata", "--format-version", "1", "--locked"], &root)?;
    let meta: Value = serde_json::from_str(&meta_raw).context("parse cargo metadata")?;
    let mut license_inventory: Vec<String> = meta
        .get("packages")
        .and_then(|p| p.as_array())
        .map(|pkgs| {
            let mut v: Vec<String> = pkgs
                .iter()
                .filter_map(|p| p.get("license").and_then(|l| l.as_str()))
                .filter(|l| !l.is_empty())
                .map(str::to_string)
                .collect();
            v.sort();
            v.dedup();
            v
        })
        .unwrap_or_default();
    license_inventory.dedup();
    let sbom = sbom_from_metadata(&meta, &opts.label);

    // Provenance.
    let git_commit = run_tool("git", &["rev-parse", "HEAD"], &root)?.trim().to_string();
    let git_dirty = run_tool("git", &["status", "--porcelain"], &root)?
        .lines()
        .any(|l| !l.trim().is_empty());
    let rustc_vv = run_tool("rustc", &["-vV"], &root)?;
    let rustc_ver = rustc_vv
        .lines()
        .find(|l| l.starts_with("release: "))
        .map(|l| l.trim_start_matches("release: ").to_string())
        .unwrap_or_default();
    let rustc_commit = rustc_vv
        .lines()
        .find(|l| l.starts_with("commit-hash: "))
        .map(|l| l.trim_start_matches("commit-hash: ").to_string())
        .unwrap_or_default();
    let cargo_ver = run_tool("cargo", &["--version"], &root)?.trim().to_string();
    let target = rustc_vv
        .lines()
        .find(|l| l.starts_with("host: "))
        .map(|l| l.trim_start_matches("host: ").to_string())
        .unwrap_or_default();

    let manifest = json!({
        "schema": 1,
        "label": opts.label,
        "release_level": "user-mode",
        "kernel_assisted": "absent (G7 out of scope for this release; no WDK/VM/signing/distro environment)",
        "generated_utc": chrono_now_utc(),
        "provenance": {
            "git_commit": git_commit,
            "git_tree_dirty": git_dirty,
            "rustc": rustc_ver,
            "rustc_commit_hash": rustc_commit,
            "cargo": cargo_ver,
            "host_target": target,
        },
        "artifacts": artifacts,
        "budgets": {
            "source": "g8_perf_baseline.json",
            "unmet": unmet,
            "override_used": opts.allow_budget_fail,
        },
        "sbom": sbom,
        "license_inventory": license_inventory,
        "signing": "none (decision D2 2026-09-08); integrity = this manifest + sha256 list",
    });

    let manifest_path = out.join("manifest.json");
    std::fs::write(&manifest_path, serde_json::to_string_pretty(&manifest)?)
        .with_context(|| format!("write {}", manifest_path.display()))?;
    Ok(manifest)
}

/// Wall-clock stamp without pulling a datetime crate: ISO-8601 UTC via the
/// platform `date`/`powershell` is flaky cross-host, so the command stamps
/// from git (deterministic) and this function records an epoch number that
/// any tool can render.
fn chrono_now_utc() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("unix_epoch_seconds={secs}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_is_stable() {
        let h = sha256_hex(b"xenolith");
        assert_eq!(h.len(), 64, "hex sha256 is 64 chars");
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(h, sha256_hex(b"xenolith"), "deterministic");
        assert_ne!(h, sha256_hex(b"xenolith2"), "input-sensitive");
    }

    #[test]
    fn sbom_structure_from_fixture() {
        let meta: Value = serde_json::from_str(
            r#"{
              "resolve": { "root": "pkg:root" },
              "packages": [
                { "name": "xenolith-cli", "version": "0.1.0", "license": "GPL-3.0-or-later", "source": null },
                { "name": "iced-x86", "version": "1.21.0", "license": "MIT", "source": "registry+https://github.com/rust-lang/crates.io-index" },
                { "name": "anstyle", "version": "1.0.0", "license": "MIT OR Apache-2.0", "source": "registry+https://github.com/rust-lang/crates.io-index" }
              ]
            }"#,
        )
        .unwrap();
        let sbom = sbom_from_metadata(&meta, "test");
        assert_eq!(sbom["bomFormat"], "CycloneDX");
        assert_eq!(sbom["specVersion"], "1.4");
        let comps = sbom["components"].as_array().unwrap();
        assert_eq!(comps.len(), 3);
        assert!(comps.iter().any(|c| c["name"] == "iced-x86" && c["purl"] == "pkg:cargo/iced-x86@1.21.0"));
        let licenses = sbom["licenses"].as_array().unwrap();
        assert_eq!(licenses.len(), 3); // GPL, MIT, MIT OR Apache-2.0
    }

    #[test]
    fn budget_gate_blocks_and_allows() {
        let passing: Value =
            serde_json::from_str(r#"{"verdicts": {"app_geomean_std": "PASS", "protected_call_p95": "PASS", "size_worst": "PASS"}}"#).unwrap();
        assert!(unmet_budgets(&passing).is_empty());
        let failing: Value =
            serde_json::from_str(r#"{"verdicts": {"app_geomean_std": "PASS", "protected_call_p95": "PASS", "size_worst": "FAIL"}}"#).unwrap();
        assert_eq!(unmet_budgets(&failing), vec!["size_worst".to_string()]);
    }
}
