//! TASK-039/040: release manifest — artifact hashes, CycloneDX SBOM from
//! `cargo metadata --locked`, license inventory, build provenance, gate
//! evidence, and the TASK-038 budget gate. No code signing exists (decision
//! D2, 2026-09-08): integrity is this manifest plus the sha256 list.
//!
//! Missing or invalid gate evidence blocks every release. An explicit
//! budget failure may be overridden for engineering builds and is recorded
//! in the manifest.

use anyhow::{bail, Context, Result};
use serde::de::{value::MapAccessDeserializer, DeserializeOwned, MapAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{ErrorKind, Read};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

#[path = "../source_identity.rs"]
mod source_identity;

const CLI_NAME: &str = if cfg!(windows) {
    "xenolith.exe"
} else {
    "xenolith"
};

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
    roots.push(Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."));
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
        bail!(
            "{bin} {:?} failed: {}",
            args,
            String::from_utf8_lossy(&out.stderr)
        );
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

#[derive(Deserialize)]
struct BudgetBaseline {
    #[serde(deserialize_with = "object")]
    verdicts: BudgetVerdicts,
}

#[derive(Deserialize)]
struct BudgetVerdicts {
    app_geomean_std: String,
    protected_call_p95: String,
    size_worst: String,
}

fn unmet_budgets(bytes: &[u8]) -> Result<Vec<&'static str>> {
    let BudgetBaseline { verdicts } =
        parse_object(bytes).context("invalid TASK-038 verdicts in g8_perf_baseline.json")?;
    let mut unmet = Vec::new();
    for (name, verdict) in [
        ("app_geomean_std", verdicts.app_geomean_std),
        ("protected_call_p95", verdicts.protected_call_p95),
        ("size_worst", verdicts.size_worst),
    ] {
        match verdict.as_str() {
            "PASS" => (),
            "FAIL" => unmet.push(name),
            _ => bail!("invalid TASK-038 verdicts in g8_perf_baseline.json: {name} = {verdict:?}"),
        }
    }
    Ok(unmet)
}

#[derive(Deserialize)]
struct GateEvidence {
    schema: u64,
    #[serde(deserialize_with = "object")]
    gates: UserModeGates,
}

#[derive(Deserialize)]
#[serde(rename_all = "UPPERCASE")]
struct UserModeGates {
    g0: GateObject,
    g1: GateObject,
    g2: GateObject,
    g3: GateObject,
    g4: GateObject,
    g5: GateObject,
    g6: GateObject,
    g7: GateObject,
    g8: GateObject,
}

#[derive(Deserialize)]
struct GateObject(#[serde(deserialize_with = "object")] Gate);

#[derive(Deserialize)]
struct Gate {
    status: String,
}

// Serde structs also accept positional sequences by default. The evidence
// format requires JSON objects with named, non-duplicate fields.
fn object<'de, D: Deserializer<'de>, T: Deserialize<'de>>(deserializer: D) -> Result<T, D::Error> {
    struct Object<T>(std::marker::PhantomData<T>);

    impl<'de, T: Deserialize<'de>> Visitor<'de> for Object<T> {
        type Value = T;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a JSON object")
        }

        fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<T, A::Error> {
            T::deserialize(MapAccessDeserializer::new(map))
        }
    }

    deserializer.deserialize_map(Object::<T>(std::marker::PhantomData))
}

fn parse_object<T: DeserializeOwned>(bytes: &[u8]) -> serde_json::Result<T> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = object(&mut deserializer)?;
    deserializer.end()?;
    Ok(value)
}

fn check_gate_evidence(bytes: &[u8]) -> Result<()> {
    let GateEvidence { schema, gates } =
        parse_object(bytes).context("invalid gate-evidence.json")?;
    if schema != 1 {
        bail!("unsupported gate-evidence.json schema: {schema}");
    }
    // G6 and G7 are recorded exclusions, not passes. G8 closes user mode only.
    for (name, GateObject(gate), expected) in [
        ("G0", gates.g0, "passed"),
        ("G1", gates.g1, "passed"),
        ("G2", gates.g2, "passed"),
        ("G3", gates.g3, "passed"),
        ("G4", gates.g4, "passed"),
        ("G5", gates.g5, "passed"),
        ("G6", gates.g6, "removed"),
        ("G7", gates.g7, "out-of-scope"),
        ("G8", gates.g8, "closed-usermode"),
    ] {
        if gate.status != expected {
            bail!(
                "gate-evidence.json: {name} status {:?}, expected {expected:?}",
                gate.status
            );
        }
    }
    Ok(())
}

struct ReleaseInput {
    name: &'static str,
    bytes: Vec<u8>,
    #[cfg(unix)]
    permissions: Option<fs::Permissions>,
}

impl ReleaseInput {
    fn read(name: &'static str, src: &Path) -> Result<Self> {
        if !src.is_file() {
            bail!(
                "release input missing or not a file: {} ({name})",
                src.display()
            );
        }
        let mut file = fs::File::open(src).with_context(|| format!("open {}", src.display()))?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)
            .with_context(|| format!("read {}", src.display()))?;
        Ok(Self {
            name,
            bytes,
            #[cfg(unix)]
            permissions: Some(
                file.metadata()
                    .with_context(|| format!("stat {}", src.display()))?
                    .permissions(),
            ),
        })
    }

    fn stage(&self, dir: &Path) -> Result<()> {
        let dst = dir.join(self.name);
        fs::write(&dst, &self.bytes).with_context(|| format!("write {}", dst.display()))?;
        #[cfg(unix)]
        if self.name == CLI_NAME {
            use std::os::unix::fs::PermissionsExt;
            // Preserve ordinary mode bits without copying setuid or setgid.
            let mode = self
                .permissions
                .as_ref()
                .context("CLI permissions missing")?
                .mode()
                & 0o777;
            fs::set_permissions(&dst, fs::Permissions::from_mode(mode))
                .with_context(|| format!("set permissions on {}", dst.display()))?;
        }
        Ok(())
    }
}

pub fn build_release(opts: &ReleaseOptions) -> Result<Value> {
    let root = find_repo_root()?;
    let cli = std::env::current_exe().context("locate the running Xenolith CLI")?;
    let stress = std::env::var_os("XL_STRESS_EVIDENCE").map(PathBuf::from);
    // include_str! binds this inventory to the compilation of this CLI. Never
    // substitute a hash computed from the release machine's current files.
    let build_identity: source_identity::Identity = serde_json::from_str(include_str!(concat!(
        env!("OUT_DIR"),
        "/source-identity.json"
    )))
    .context("invalid embedded CLI source identity")?;
    build_release_from(
        opts,
        &root,
        &cli,
        stress.as_deref(),
        &build_identity,
        run_tool,
    )
}

fn build_release_from(
    opts: &ReleaseOptions,
    root: &Path,
    cli: &Path,
    stress: Option<&Path>,
    build_identity: &source_identity::Identity,
    run: impl Fn(&str, &[&str], &Path) -> Result<String>,
) -> Result<Value> {
    let baseline = ReleaseInput::read(
        "g8_perf_baseline.json",
        &root.join("tests/corpus/g8_perf_baseline.json"),
    )?;
    let unmet = unmet_budgets(&baseline.bytes)?;
    if !unmet.is_empty() && !opts.allow_budget_fail {
        bail!(
            "TASK-038 budgets unmet: {:?}; a failed budget blocks this release level. \
             Fix the budget or pass --allow-budget-fail to publish an engineering \
             build with the failure recorded.",
            unmet
        );
    }
    let evidence = ReleaseInput::read(
        "gate-evidence.json",
        &root.join("tests/release/evidence.json"),
    )?;
    check_gate_evidence(&evidence.bytes)?;

    let snapshot = source_identity::collect(root)?;
    source_identity::verify(build_identity, &snapshot.identity)?;

    let mut inputs = vec![ReleaseInput::read(CLI_NAME, cli)?];
    inputs.push(ReleaseInput {
        name: "source-snapshot.json",
        bytes: serde_json::to_vec(&snapshot)?,
        #[cfg(unix)]
        permissions: None,
    });
    for (name, src) in [
        ("SUPPORT.md", "docs/SUPPORT.md"),
        ("THREAT-MODEL.md", "docs/THREAT-MODEL.md"),
        ("corpus-manifest.json", "tests/corpus/manifest.json"),
        ("compat-manifest.json", "tests/compat/manifest.json"),
    ] {
        let input = ReleaseInput::read(name, &root.join(src))?;
        if name.ends_with(".json") {
            // These reports are versioned JSON objects. They are bundled as evidence.
            #[derive(Deserialize)]
            struct InputManifest {
                version: u64,
            }
            let manifest: InputManifest =
                parse_object(&input.bytes).with_context(|| format!("parse {name}"))?;
            if manifest.version != 1 {
                bail!("unsupported {name} version: {}", manifest.version);
            }
        }
        inputs.push(input);
    }
    inputs.extend([baseline, evidence]);
    if let Some(src) = stress {
        inputs.push(ReleaseInput::read("stress-evidence.json", src)?);
    }

    let out = release_destination(&opts.out)?;
    check_destination(&out)?;

    // SBOM + license inventory from the locked graph.
    let meta_raw = run(
        "cargo",
        &["metadata", "--format-version", "1", "--locked"],
        root,
    )?;
    let meta: Value = serde_json::from_str(&meta_raw).context("parse cargo metadata")?;
    let packages = meta
        .get("packages")
        .and_then(Value::as_array)
        .filter(|packages| !packages.is_empty())
        .context("cargo metadata did not contain a package graph")?;
    let mut license_inventory: Vec<&str> = packages
        .iter()
        .filter_map(|p| p.get("license").and_then(Value::as_str))
        .filter(|license| !license.is_empty())
        .collect();
    license_inventory.sort_unstable();
    license_inventory.dedup();
    let sbom = sbom_from_metadata(&meta, &opts.label);

    // Provenance.
    let (git_commit, git_dirty) = if root.join(".git").exists() {
        (
            Some(run("git", &["rev-parse", "HEAD"], root)?.trim().to_string()),
            Some(
                run("git", &["status", "--porcelain"], root)?
                    .lines()
                    .any(|l| !l.trim().is_empty()),
            ),
        )
    } else {
        (None, None)
    };
    let rustc_vv = run("rustc", &["-vV"], root)?;
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
    let cargo_ver = run("cargo", &["--version"], root)?.trim().to_string();
    let target = rustc_vv
        .lines()
        .find(|l| l.starts_with("host: "))
        .map(|l| l.trim_start_matches("host: ").to_string())
        .unwrap_or_default();

    let artifacts: Vec<_> = inputs
        .iter()
        .map(|input| {
            json!({
                "name": input.name,
                "sha256": sha256_hex(&input.bytes),
                "bytes": input.bytes.len(),
            })
        })
        .collect();
    let manifest = json!({
        "schema": 1,
        "label": opts.label,
        "cli_version": env!("CARGO_PKG_VERSION"),
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
            "build_source": {
                "schema": build_identity.schema,
                "sha256": build_identity.sha256,
                "file_count": build_identity.files.len(),
                "worktree_verified": true,
                "snapshot": "source-snapshot.json",
            },
        },
        "artifacts": artifacts,
        "budgets": {
            "source": "g8_perf_baseline.json",
            "unmet": unmet,
            "override_used": !unmet.is_empty(),
        },
        "sbom": sbom,
        "license_inventory": license_inventory,
        "signing": "none (decision D2 2026-09-08); integrity = this manifest + sha256 list",
    });

    let manifest_bytes = serde_json::to_vec_pretty(&manifest)?;
    let stage = ReleaseStage::new(&out)?;
    // Filesystem aliases can make two different names refer to the same directory.
    // Catch that before writing any bundle file.
    if check_destination(&out)? && fs::canonicalize(&out)? == fs::canonicalize(&stage.path)? {
        bail!(
            "release output aliases its staging directory: {}",
            out.display()
        );
    }
    for input in &inputs {
        input.stage(&stage.path)?;
    }
    let manifest_path = stage.path.join("manifest.json");
    fs::write(&manifest_path, manifest_bytes)
        .with_context(|| format!("write {}", manifest_path.display()))?;
    stage.publish(&out)?;
    Ok(manifest)
}

fn release_destination(out: &Path) -> Result<PathBuf> {
    let name = out
        .file_name()
        .context("release output must name a directory")?;
    // Resolve relative paths exactly once. A simple --out dist has no explicit parent.
    let absolute = std::path::absolute(out)?;
    let parent = absolute
        .parent()
        .context("release output must have a parent")?;
    Ok(parent.join(name))
}

/// Return whether an empty destination already exists. Never follow a link at
/// the destination itself (including Windows directory junctions).
fn check_destination(out: &Path) -> Result<bool> {
    let metadata = match fs::symlink_metadata(out) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(false),
        Err(err) => return Err(err).with_context(|| format!("inspect {}", out.display())),
    };
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            bail!("release output is a reparse point: {}", out.display());
        }
    }
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        bail!("release output is not a plain directory: {}", out.display());
    }
    let mut entries = fs::read_dir(out).with_context(|| format!("list {}", out.display()))?;
    if entries.next().transpose()?.is_some() {
        bail!(
            "release output directory is not empty: {}; choose a new directory",
            out.display()
        );
    }
    Ok(true)
}

struct ReleaseStage {
    path: PathBuf,
}

impl ReleaseStage {
    fn new(out: &Path) -> Result<Self> {
        static NEXT_STAGE: AtomicU64 = AtomicU64::new(0);
        let parent = out.parent().context("release output must have a parent")?;
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
        let builder = fs::DirBuilder::new();
        #[cfg(unix)]
        let builder = {
            use std::os::unix::fs::DirBuilderExt;
            let mut builder = builder;
            builder.mode(0o700);
            builder
        };
        for _ in 0..128 {
            let id = NEXT_STAGE.fetch_add(1, Ordering::Relaxed);
            let name = format!(".xenolith-release-{}-{id}", std::process::id());
            if out.file_name().is_some_and(|out_name| {
                out_name
                    .as_encoded_bytes()
                    .eq_ignore_ascii_case(name.as_bytes())
            }) {
                continue;
            }
            let path = parent.join(name);
            match builder.create(&path) {
                Ok(()) => return Ok(Self { path }),
                Err(err) if err.kind() == ErrorKind::AlreadyExists => continue,
                Err(err) => {
                    return Err(err).with_context(|| format!("create stage {}", path.display()))
                }
            }
        }
        bail!("could not allocate a release stage in {}", parent.display());
    }

    fn publish(mut self, out: &Path) -> Result<()> {
        let exists = check_destination(out)?;
        // Windows cannot rename over a directory. Remove only an empty one at
        // commit time. If it gained entries, remove_dir fails without deleting any.
        if cfg!(windows) && exists {
            fs::remove_dir(out)
                .with_context(|| format!("remove empty output {}", out.display()))?;
        }
        fs::rename(&self.path, out)
            .with_context(|| format!("publish release to {}", out.display()))?;
        // Drop only cleans up the stage we still own.
        self.path.clear();
        Ok(())
    }
}

impl Drop for ReleaseStage {
    fn drop(&mut self) {
        if !self.path.as_os_str().is_empty() {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
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

    const BASELINE: &str = "tests/corpus/g8_perf_baseline.json";
    const GATE_EVIDENCE: &str = "tests/release/evidence.json";
    const PASSING_BUDGETS: &[u8] = br#"{
        "verdicts": {"app_geomean_std":"PASS", "protected_call_p95":"PASS", "size_worst":"PASS"}
    }"#;
    const PASSING_GATES: &[u8] = include_bytes!("../../../tests/release/evidence.json");

    struct Fixture {
        _temp: ReleaseStage,
        root: PathBuf,
        cli: PathBuf,
        opts: ReleaseOptions,
        build_identity: Option<source_identity::Identity>,
    }

    impl Fixture {
        fn new() -> Self {
            let temp =
                ReleaseStage::new(&std::env::temp_dir().join("xenolith-release-test")).unwrap();
            let root = temp.path.join("repo");
            let cli = temp.path.join("running-xenolith");
            let opts = ReleaseOptions {
                label: "test-release".into(),
                out: temp.path.join("output/dist"),
                allow_budget_fail: false,
            };
            let mut fixture = Self {
                _temp: temp,
                root,
                cli,
                opts,
                build_identity: None,
            };
            fixture.write("Cargo.toml", b"[workspace]\n");
            fixture.write("Cargo.lock", b"version = 4\n");
            fixture.write(
                "crates/xenolith-cli/Cargo.toml",
                b"[package]\nname = 'test'\n",
            );
            fixture.write("crates/xenolith-cli/src/main.rs", b"fn main() {}\n");
            fixture.write(BASELINE, PASSING_BUDGETS);
            fixture.write(GATE_EVIDENCE, PASSING_GATES);
            fixture.write("docs/SUPPORT.md", b"support");
            fixture.write("docs/THREAT-MODEL.md", b"threat model");
            fixture.write("tests/corpus/manifest.json", br#"{"version":1}"#);
            fixture.write("tests/compat/manifest.json", br#"{"version":1}"#);
            fixture.write(
                &format!("target/release/{CLI_NAME}"),
                b"unrelated checkout binary",
            );
            fs::write(&fixture.cli, b"running CLI bytes").unwrap();
            fixture.build_identity =
                Some(source_identity::collect(&fixture.root).unwrap().identity);
            fixture
        }

        fn write(&self, name: &str, contents: &[u8]) {
            let path = self.root.join(name);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, contents).unwrap();
        }

        fn build(&self) -> Result<Value> {
            build_release_from(
                &self.opts,
                &self.root,
                &self.cli,
                None,
                self.build_identity.as_ref().unwrap(),
                manifest_tool,
            )
        }

        fn assert_no_output_parent(&self) {
            assert!(!self.opts.out.parent().unwrap().exists());
        }
    }

    fn manifest_tool(bin: &str, args: &[&str], _: &Path) -> Result<String> {
        Ok(match (bin, args) {
            ("cargo", ["metadata", "--format-version", "1", "--locked"]) =>
                r#"{"packages":[{"name":"xenolith-cli","version":"0.1.0","license":"GPL-3.0-or-later"}]}"#,
            ("cargo", ["--version"]) => "cargo test fixture",
            ("git", ["rev-parse", "HEAD"]) => "1111111111111111111111111111111111111111",
            ("git", ["status", "--porcelain"]) => "",
            ("rustc", ["-vV"]) => "release: test\ncommit-hash: test\nhost: test-host\n",
            _ => panic!("unexpected tool call: {bin} {args:?}"),
        }
        .into())
    }

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
        assert!(comps
            .iter()
            .any(|c| c["name"] == "iced-x86" && c["purl"] == "pkg:cargo/iced-x86@1.21.0"));
        let licenses = sbom["licenses"].as_array().unwrap();
        assert_eq!(licenses.len(), 3); // GPL, MIT, MIT OR Apache-2.0
    }

    #[test]
    fn invalid_budgets_fail_before_creating_output_even_with_override() {
        let mut fixture = Fixture::new();
        fixture.opts.allow_budget_fail = true;
        for invalid in [
            "{}",
            r#"[{"app_geomean_std":"PASS","protected_call_p95":"PASS","size_worst":"PASS"}]"#,
            r#"{"verdicts":["PASS","PASS","PASS"]}"#,
            r#"{"verdicts":{"app_geomean_std":"PASS","protected_call_p95":"PASS"}}"#,
            r#"{"verdicts":{"app_geomean_std":"PASS","protected_call_p95":"PASS","size_worst":false}}"#,
            r#"{"verdicts":{"app_geomean_std":"PASS","protected_call_p95":"PASS","size_worst":"pass"}}"#,
            r#"{"verdicts":{"app_geomean_std":"PASS","protected_call_p95":"PASS","size_worst":"FAIL","size_worst":"PASS"}}"#,
        ] {
            fixture.write(BASELINE, invalid.as_bytes());
            let error = fixture.build().unwrap_err();
            assert!(
                error.to_string().contains("invalid TASK-038 verdicts"),
                "{error:#}"
            );
            fixture.assert_no_output_parent();
        }
    }

    #[test]
    fn explicit_budget_fail_blocks_or_is_recorded_as_overridden() {
        let mut fixture = Fixture::new();
        let mut baseline: Value = serde_json::from_slice(PASSING_BUDGETS).unwrap();
        baseline["verdicts"]["size_worst"] = json!("FAIL");
        let bytes = serde_json::to_vec(&baseline).unwrap();
        fixture.write(BASELINE, &bytes);

        let error = fixture.build().unwrap_err();
        assert!(error.to_string().contains("budgets unmet"), "{error:#}");
        fixture.assert_no_output_parent();

        fixture.opts.allow_budget_fail = true;
        let manifest = fixture.build().unwrap();
        assert_eq!(manifest["budgets"]["unmet"], json!(["size_worst"]));
        assert_eq!(manifest["budgets"]["override_used"], true);
        assert_eq!(
            fs::read(fixture.opts.out.join("g8_perf_baseline.json")).unwrap(),
            bytes
        );
    }

    #[test]
    fn gate_evidence_is_required_and_its_status_cannot_be_overridden() {
        let mut fixture = Fixture::new();
        fixture.opts.allow_budget_fail = true;
        let mut evidence: Value = serde_json::from_slice(PASSING_GATES).unwrap();
        for entry in [
            None,
            Some(json!(["closed-usermode"])),
            Some(json!({"status": false})),
            Some(json!({"status": "failed"})),
            Some(json!({"status": "passed"})),
        ] {
            match entry {
                Some(entry) => evidence["gates"]["G8"] = entry,
                None => {
                    evidence["gates"].as_object_mut().unwrap().remove("G8");
                }
            }
            fixture.write(GATE_EVIDENCE, &serde_json::to_vec(&evidence).unwrap());
            let error = fixture.build().unwrap_err();
            assert!(
                format!("{error:#}").contains("gate-evidence.json"),
                "{error:#}"
            );
            fixture.assert_no_output_parent();
        }
    }

    #[test]
    fn missing_sources_and_bad_manifests_do_not_put_files_in_output() {
        let fixture = Fixture::new();
        fs::create_dir_all(&fixture.opts.out).unwrap();
        let missing = fixture.root.join("missing-stress.json");
        let error = build_release_from(
            &fixture.opts,
            &fixture.root,
            &fixture.cli,
            Some(&missing),
            fixture.build_identity.as_ref().unwrap(),
            manifest_tool,
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("stress-evidence.json"),
            "{error:#}"
        );

        let name = "tests/compat/manifest.json";
        fixture.write(name, b"{");
        let error = fixture.build().unwrap_err();
        assert!(
            error.to_string().contains("compat-manifest.json"),
            "{error:#}"
        );
        fixture.write(name, br#"{"version":1}"#);

        let error = build_release_from(
            &fixture.opts,
            &fixture.root,
            &fixture.cli,
            None,
            fixture.build_identity.as_ref().unwrap(),
            |bin, args, cwd| {
                if bin == "rustc" {
                    bail!("fixture provenance unavailable");
                }
                manifest_tool(bin, args, cwd)
            },
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("fixture provenance unavailable"),
            "{error:#}"
        );

        fs::remove_file(fixture.root.join(name)).unwrap();
        let error = fixture.build().unwrap_err();
        assert!(
            error.to_string().contains("release input missing"),
            "{error:#}"
        );
        assert_eq!(fs::read_dir(&fixture.opts.out).unwrap().count(), 0);
        assert_eq!(
            fs::read_dir(fixture.opts.out.parent().unwrap())
                .unwrap()
                .count(),
            1
        );
    }

    #[test]
    fn publishes_a_complete_bundle_with_matching_manifest_and_cli_mode() {
        let mut fixture = Fixture::new();
        fixture.opts.allow_budget_fail = true;
        fs::create_dir_all(&fixture.opts.out).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&fixture.cli, fs::Permissions::from_mode(0o751)).unwrap();
        }

        let manifest = fixture.build().unwrap();
        let out = &fixture.opts.out;
        let disk: Value =
            serde_json::from_slice(&fs::read(out.join("manifest.json")).unwrap()).unwrap();
        assert_eq!(disk, manifest);
        assert_eq!(disk["budgets"]["override_used"], false);
        assert_eq!(disk["provenance"]["git_commit"], Value::Null);
        assert_eq!(disk["provenance"]["git_tree_dirty"], Value::Null);
        assert_eq!(
            disk["provenance"]["build_source"]["sha256"],
            fixture.build_identity.as_ref().unwrap().sha256
        );
        assert_eq!(fs::read(out.join(CLI_NAME)).unwrap(), b"running CLI bytes");
        let artifacts = disk["artifacts"].as_array().unwrap();
        assert_eq!(artifacts.len(), 8);
        assert_eq!(fs::read_dir(out).unwrap().count(), artifacts.len() + 1);
        for artifact in artifacts {
            let path = out.join(artifact["name"].as_str().unwrap());
            assert_eq!(artifact["sha256"], sha256_file(&path).unwrap());
            assert_eq!(artifact["bytes"], fs::metadata(path).unwrap().len());
        }
        let snapshot: Value =
            serde_json::from_slice(&fs::read(out.join("source-snapshot.json")).unwrap()).unwrap();
        let extracted = fixture._temp.path.join("extracted");
        for (path, contents) in snapshot["files"].as_object().unwrap() {
            let target = extracted.join(path);
            fs::create_dir_all(target.parent().unwrap()).unwrap();
            fs::write(target, contents.as_str().unwrap()).unwrap();
        }
        let restored = source_identity::collect(&extracted).unwrap();
        assert_eq!(&restored.identity, fixture.build_identity.as_ref().unwrap());
        assert_eq!(
            serde_json::to_vec(&restored).unwrap(),
            fs::read(out.join("source-snapshot.json")).unwrap()
        );
        assert_eq!(fs::read_dir(out.parent().unwrap()).unwrap().count(), 1);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(out.join(CLI_NAME))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o751
            );
        }
    }

    #[test]
    fn source_drift_is_reported_against_the_build_inventory_before_any_output() {
        let fixture = Fixture::new();
        let built = fixture.build_identity.as_ref().unwrap();
        fixture.write(
            "crates/xenolith-cli/src/main.rs",
            b"fn main() { println!(\"changed\"); }\n",
        );
        fixture.write(
            "crates/xenolith-cli/src/output.rs",
            b"pub fn new_output() {}\n",
        );
        fs::remove_file(fixture.root.join("Cargo.lock")).unwrap();
        // Keep a valid lockfile to test content drift alongside a new source.
        fixture.write("Cargo.lock", b"version = 4\n# changed lock\n");
        let current = source_identity::collect(&fixture.root).unwrap();
        assert_ne!(built.sha256, current.identity.sha256);
        let error = fixture.build().unwrap_err().to_string();
        assert!(error.contains("release source drift"), "{error}");
        assert!(
            error.contains("added [\"crates/xenolith-cli/src/output.rs\"]"),
            "{error}"
        );
        assert!(
            error.contains("Cargo.lock") && error.contains("crates/xenolith-cli/src/main.rs"),
            "{error}"
        );
        assert!(error.contains(&built.sha256), "{error}");
        assert!(error.contains("Rebuild xenolith-cli"), "{error}");
        fixture.assert_no_output_parent();
        // Restoring the original sources restores the original identity.
        fixture.write("crates/xenolith-cli/src/main.rs", b"fn main() {}\n");
        fixture.write("Cargo.lock", b"version = 4\n");
        fs::remove_file(fixture.root.join("crates/xenolith-cli/src/output.rs")).unwrap();
        assert_eq!(
            &source_identity::collect(&fixture.root).unwrap().identity,
            built
        );
    }

    #[test]
    fn source_inventory_ignores_local_assets_and_tracks_untracked_sources_without_git() {
        let fixture = Fixture::new();
        fixture.write(
            ".gitignore",
            b"/crates/xenolith-cli/src/local.rs\n/crates/xenolith-cli/src/scratch/\n",
        );
        fixture.write("crates/xenolith-cli/src/output.rs", b"pub fn output() {}\n");
        let before = source_identity::collect(&fixture.root).unwrap().identity;
        fixture.write(
            "crates/xenolith-cli/src/local.rs",
            b"ignored secret source\n",
        );
        fixture.write(
            "crates/xenolith-cli/src/scratch/local.rs",
            b"ignored directory\n",
        );
        fixture.write("crates/xenolith-cli/target/generated.rs", b"generated\n");
        fixture.write(".mimosa/private.rs", b"local agent state\n");
        fixture.write(".cargo/credentials.toml", b"token = 'machine-local'\n");
        fixture.write(
            ".cargo/registry/src/private.rs",
            b"machine-local registry\n",
        );
        fixture.write("out/local.rs", b"output\n");
        assert_eq!(
            source_identity::collect(&fixture.root).unwrap().identity,
            before
        );
        assert!(before
            .files
            .contains_key("crates/xenolith-cli/src/output.rs"));
        assert!(!before
            .files
            .contains_key("crates/xenolith-cli/src/local.rs"));
        // A Git checkout and its source-only extraction use identical rules.
        fs::create_dir(fixture.root.join(".git")).unwrap();
        assert_eq!(
            source_identity::collect(&fixture.root).unwrap().identity,
            before
        );
        fs::remove_file(fixture.root.join("crates/xenolith-cli/src/output.rs")).unwrap();
        let removed = source_identity::collect(&fixture.root).unwrap().identity;
        let error = source_identity::verify(&before, &removed)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("removed [\"crates/xenolith-cli/src/output.rs\"]"),
            "{error}"
        );
    }

    #[test]
    fn compiled_source_stamp_survives_drift_and_a_fresh_build_includes_new_files() {
        let fixture = Fixture::new();
        fixture.write(
            "Cargo.toml",
            b"[workspace]\nmembers = ['crates/xenolith-cli']\nresolver = '2'\n",
        );
        fixture.write(
            "crates/xenolith-cli/Cargo.toml",
            br#"
[package]
name = "xenolith-cli"
version = "0.0.0"
edition = "2021"
[[bin]]
name = "xenolith"
path = "src/main.rs"
[dependencies]
anyhow = "1"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
sha2 = "0.10"
ignore = "0.4"
[build-dependencies]
anyhow = "1"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
sha2 = "0.10"
ignore = "0.4"
"#,
        );
        fixture.write(
            "crates/xenolith-cli/build.rs",
            include_bytes!("../build.rs"),
        );
        fixture.write(
            "crates/xenolith-cli/source_identity.rs",
            include_bytes!("../source_identity.rs"),
        );
        fixture.write(
            "crates/xenolith-cli/src/release.rs",
            include_bytes!("release.rs"),
        );
        fixture.write(
            "crates/xenolith-cli/src/main.rs",
            br#"
mod release;
fn main() -> anyhow::Result<()> {
    let out = std::env::args().nth(1).unwrap();
    if out == "source-id" {
        println!("{}", env!("XENOLITH_BUILD_SOURCE_SHA256"));
    } else {
        release::build_release(&release::ReleaseOptions {
            label: "build-attribution-test".into(), out: out.into(), allow_budget_fail: false,
        })?;
    }
    Ok(())
}
"#,
        );
        let target = fixture._temp.path.join("custom-target");
        let build = || {
            let output = std::process::Command::new(
                std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()),
            )
            .args(["build", "--offline", "--quiet", "--manifest-path"])
            .arg(fixture.root.join("crates/xenolith-cli/Cargo.toml"))
            .arg("--target-dir")
            .arg(&target)
            .output()
            .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
        };
        let binary = target.join("debug").join(CLI_NAME);
        let stamp = || {
            let output = std::process::Command::new(&binary)
                .arg("source-id")
                .output()
                .unwrap();
            assert!(output.status.success());
            String::from_utf8(output.stdout).unwrap().trim().to_string()
        };
        let release = || {
            std::process::Command::new(&binary)
                .arg(&fixture.opts.out)
                .env("XENOLITH_REPO", &fixture.root)
                .env("CARGO_NET_OFFLINE", "true")
                .env_remove("XL_STRESS_EVIDENCE")
                .output()
                .unwrap()
        };
        build();
        let built = stamp();
        assert_eq!(
            built,
            source_identity::collect(&fixture.root)
                .unwrap()
                .identity
                .sha256
        );
        fixture.write(
            "crates/xenolith-cli/src/output.rs",
            b"pub fn new_source() {}\n",
        );
        assert_eq!(
            built,
            stamp(),
            "running an old CLI cannot relabel its build identity"
        );
        let blocked = release();
        assert!(!blocked.status.success());
        let error = String::from_utf8_lossy(&blocked.stderr);
        assert!(
            error.contains("release source drift")
                && error.contains("crates/xenolith-cli/src/output.rs"),
            "{error}"
        );
        fixture.assert_no_output_parent();
        build();
        let rebuilt = stamp();
        assert_ne!(
            built, rebuilt,
            "Cargo must watch additions outside the original file inventory"
        );
        assert_eq!(
            rebuilt,
            source_identity::collect(&fixture.root)
                .unwrap()
                .identity
                .sha256
        );
        let embedded =
            serde_json::to_vec(&source_identity::collect(&fixture.root).unwrap().identity).unwrap();
        assert!(fs::read(binary)
            .unwrap()
            .windows(embedded.len())
            .any(|bytes| bytes == embedded));
    }

    #[test]
    fn refuses_populated_destination_and_preserves_a_late_publisher() {
        let fixture = Fixture::new();
        let out = &fixture.opts.out;
        let stage = ReleaseStage::new(out).unwrap();
        let stage_path = stage.path.clone();
        assert_eq!(stage_path.parent(), out.parent());
        fs::write(stage_path.join(CLI_NAME), b"staged").unwrap();
        fs::create_dir(out).unwrap();
        fs::write(out.join("manifest.json"), b"previous release").unwrap();

        let error = fixture.build().unwrap_err();
        assert!(error.to_string().contains("not empty"), "{error:#}");
        let error = stage.publish(out).unwrap_err();
        assert!(error.to_string().contains("not empty"), "{error:#}");
        assert!(!stage_path.exists());
        assert_eq!(fs::read_dir(out).unwrap().count(), 1);
        assert_eq!(
            fs::read(out.join("manifest.json")).unwrap(),
            b"previous release"
        );
    }

    #[cfg(unix)]
    #[test]
    fn refuses_a_symlink_destination_without_writing_its_target() {
        use std::os::unix::fs::symlink;
        let fixture = Fixture::new();
        let target = fixture._temp.path.join("symlink-target");
        fs::create_dir(&target).unwrap();
        fs::create_dir(fixture.opts.out.parent().unwrap()).unwrap();
        symlink(&target, &fixture.opts.out).unwrap();
        let error = fixture.build().unwrap_err();
        assert!(
            error.to_string().contains("not a plain directory"),
            "{error:#}"
        );
        assert_eq!(fs::read_dir(target).unwrap().count(), 0);
        assert!(fs::symlink_metadata(&fixture.opts.out)
            .unwrap()
            .file_type()
            .is_symlink());
    }
}
