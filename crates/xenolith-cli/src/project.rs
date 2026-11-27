use crate::output::Output;
use anyhow::{bail, ensure, Context, Result};
use xenolith_loader::Profile;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

const KNOWN: &[&str] = &[
    "schema_version",
    "input",
    "output",
    "profile",
    "vm_exports",
    "trace_diverge",
    "select_rva",
    "select_functions",
    "select_all",
    "strict_coverage",
    "allow_native_fallback",
    "lazy_regions",
    "protect_imports",
    "strict_constants",
];

pub const SCHEMA_VERSION: u32 = 2;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProjectFile {
    #[serde(default = "default_schema")]
    pub schema_version: u32,
    pub input: PathBuf,
    pub output: PathBuf,
    pub profile: String,
    #[serde(default)]
    pub vm_exports: Vec<String>,
    #[serde(default)]
    pub trace_diverge: bool,
    /// `"RVA:LEN"` strings, hex or decimal.
    #[serde(default)]
    pub select_rva: Vec<String>,
    /// Function/symbol names resolved through export, COFF, DWARF, or unwind
    /// metadata. Empty means no names were requested.
    #[serde(default)]
    pub select_functions: Vec<String>,
    /// Explicit opt-in to whole-image function discovery.
    #[serde(default)]
    pub select_all: bool,
    #[serde(default)]
    pub strict_coverage: bool,
    /// Permits selected functions that fail full transformation to remain
    /// native. Such functions are reported as mixed_native and are never
    /// counted as protected.
    #[serde(default)]
    pub allow_native_fallback: bool,
    /// G5: seal non-keep regions; decrypt on execution fault.
    #[serde(default)]
    pub lazy_regions: bool,
    /// G5: seal envelope import names (writeback mode only).
    #[serde(default)]
    pub protect_imports: bool,
    /// G5: refuse to pack when read-only constants keep native references.
    #[serde(default)]
    pub strict_constants: bool,
}

fn default_schema() -> u32 {
    SCHEMA_VERSION
}

impl ProjectFile {
    /// Map the stored string onto the loader profile. `load()` validates the
    /// enum first with the file name in the message; this is the direct
    /// caller's check for hand-built structs (no file context available).
    pub fn profile(&self) -> Result<Profile> {
        match self.profile.as_str() {
            "fast" => Ok(Profile::Fast),
            "standard" => Ok(Profile::Standard),
            "max" => Ok(Profile::Max),
            other => bail!("unknown profile `{other}` (legal values: fast|standard|max)"),
        }
    }
}

pub fn load(path: &Path) -> Result<ProjectFile> {
    let text = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    parse(path, &text)
}

fn parse(path: &Path, text: &str) -> Result<ProjectFile> {
    let raw: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(text).with_context(|| format!("parse {}", path.display()))?;
    for k in raw.keys() {
        if !KNOWN.contains(&k.as_str()) {
            bail!(
                "project {}: unknown key `{k}` (not armed / not in schema)",
                path.display()
            );
        }
    }
    if let Some(value) = raw.get("schema_version") {
        match value.as_u64() {
            Some(1) => {}
            Some(version) if version == u64::from(SCHEMA_VERSION) => {}
            Some(version) if version > u64::from(SCHEMA_VERSION) => bail!(
                "project {}: schema_version {version} is newer than this tool ({SCHEMA_VERSION})",
                path.display()
            ),
            _ => bail!(
                "project {}: invalid schema_version {value}; expected 1 or {SCHEMA_VERSION}",
                path.display()
            ),
        }
    }
    // Deserialize the original text so duplicate fields are rejected too.
    let mut file: ProjectFile =
        serde_json::from_str(text).with_context(|| format!("fields in {}", path.display()))?;
    file.schema_version = SCHEMA_VERSION;
    validate(&file, path)?;
    Ok(file)
}

/// Lightweight validation applied on every `load()`. This is what makes
/// `project show` exit non-zero on a bad file before anything is printed:
/// profile must be a known enum value and every select_rva entry must parse
/// as RVA:LEN. Fail-closed — no downstream consumer sees an unvalidated file.
fn validate(file: &ProjectFile, path: &Path) -> Result<()> {
    for (key, value) in [("input", &file.input), ("output", &file.output)] {
        ensure!(
            !value.as_os_str().is_empty(),
            "empty {key} path in {}",
            path.display()
        );
        #[cfg(windows)]
        if !value.is_absolute() {
            use std::path::Component;
            ensure!(
                !value.has_root()
                    && !matches!(value.components().next(), Some(Component::Prefix(_))),
                "{key} in {} must be fully absolute or relative to the project directory",
                path.display()
            );
        }
    }
    if !matches!(file.profile.as_str(), "fast" | "standard" | "max") {
        bail!(
            "unknown profile `{}` in {} (legal values: fast|standard|max)",
            file.profile,
            path.display()
        );
    }
    if let Err(e) = parse_select_rva(&file.select_rva) {
        bail!("invalid select_rva in {}: {e}", path.display());
    }
    Ok(())
}

pub fn parse_select_rva(specs: &[String]) -> Result<Vec<(u32, u32)>> {
    let mut out = Vec::new();
    for spec in specs {
        let (rva_s, len_s) = spec.split_once(':').ok_or_else(|| {
            anyhow::anyhow!("select-rva `{spec}` must be RVA:LEN")
        })?;
        out.push((parse_u32(rva_s)?, parse_u32(len_s)?));
    }
    Ok(out)
}

fn parse_u32(s: &str) -> Result<u32> {
    let t = s.trim();
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16).map_err(|_| anyhow::anyhow!("bad number {s}"))
    } else {
        t.parse().map_err(|_| anyhow::anyhow!("bad number {s}"))
    }
}

/// Resolve fields read from a project against the directory containing the
/// project path. Explicit command-line paths keep their working-directory semantics.
pub fn load_paths(path: &Path) -> Result<ProjectFile> {
    let path = std::path::absolute(path)?;
    let mut file = load(&path)?;
    let base = path.parent().context("project path has no parent")?;
    file.input = base.join(file.input);
    file.output = base.join(file.output);
    Ok(file)
}

pub enum SaveMode {
    New,
    UpdateProject,
}

pub fn save(path: &Path, mut file: ProjectFile, mode: SaveMode) -> Result<()> {
    validate(&file, path)?;
    let actual_input = std::path::absolute(&file.input)?;
    let actual_output = std::path::absolute(&file.output)?;
    let destination = Output::new(path, &[&actual_input, &actual_output])?;
    let path = std::path::absolute(path)?;
    let base = path.parent().context("project path has no parent")?;
    // Paths passed in by the UI/CLI refer to actual files from the working
    // directory. Store paths under the project directory relative to it.
    file.input = stored_path(base, &actual_input);
    file.output = stored_path(base, &actual_output);
    let json = serde_json::to_vec_pretty(&file)?;
    match mode {
        SaveMode::New => destination.write_new(&json, None),
        SaveMode::UpdateProject => destination.write_project_update(&json, |existing| {
            let mut text = String::new();
            existing.read_to_string(&mut text)?;
            parse(&path, &text)?;
            Ok(())
        }),
    }
}

fn stored_path(base: &Path, path: &Path) -> PathBuf {
    path.strip_prefix(base)
        .ok()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(path)
        .to_path_buf()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn unknown_key_fails_closed() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("xl-proj-{}.json", std::process::id()));
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(
            br#"{"input":"a.dll","output":"b.dll","profile":"max","vm_exports":[],"c2":true}"#,
        )
        .unwrap();
        let err = load(&path).unwrap_err().to_string();
        let _ = std::fs::remove_file(&path);
        assert!(err.contains("unknown key"), "{err}");
    }

    #[test]
    fn round_trip_known_keys() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("xl-proj-ok-{}.json", std::process::id()));
        let file = ProjectFile {
            schema_version: SCHEMA_VERSION,
            input: PathBuf::from("in.dll"),
            output: PathBuf::from("out.dll"),
            profile: "max".into(),
            vm_exports: vec!["check_license".into()],
            trace_diverge: false,
            select_rva: vec![],
            select_functions: vec!["internal_fn".into()],
            select_all: false,
            strict_coverage: false,
            allow_native_fallback: false,
            lazy_regions: false,
            protect_imports: false,
            strict_constants: false,
        };
        save(&path, file, SaveMode::New).unwrap();
        let loaded = load(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        assert_eq!(loaded.vm_exports, vec!["check_license"]);
        assert!(matches!(loaded.profile().unwrap(), Profile::Max));
        assert_eq!(loaded.schema_version, SCHEMA_VERSION);
        assert_eq!(loaded.select_functions, vec!["internal_fn"]);
        assert!(!loaded.strict_coverage);
        assert!(!loaded.allow_native_fallback);
        assert!(!loaded.lazy_regions);
        assert!(!loaded.protect_imports);
        assert!(!loaded.strict_constants);
    }

    #[test]
    fn parse_select_rva_hex() {
        let v = parse_select_rva(&["0x1000:0x20".into()]).unwrap();
        assert_eq!(v, vec![(0x1000, 0x20)]);
    }

    #[test]
    fn v1_project_migrates_to_v2() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("xl-proj-v1-{}.json", std::process::id()));
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(
            br#"{"schema_version":1,"input":"in.dll","output":"out.dll","profile":"max","vm_exports":[],"trace_diverge":false,"select_rva":[],"strict_coverage":false,"lazy_regions":false,"protect_imports":false,"strict_constants":false}"#,
        )
        .unwrap();
        let loaded = load(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        assert_eq!(loaded.schema_version, SCHEMA_VERSION);
        assert!(loaded.select_functions.is_empty());
        assert!(!loaded.select_all);
        assert!(!loaded.allow_native_fallback);
    }

    #[test]
    fn explicit_invalid_schema_versions_fail_closed() {
        let path = Path::new("config/project.json");
        for version in [
            "null",
            "false",
            "0",
            "-1",
            "2.0",
            "1.5",
            "{}",
            "[]",
            "\"2\"",
            "3",
            "4294967296",
        ] {
            let text = format!(
                r#"{{"schema_version":{version},"input":"in","output":"out","profile":"fast"}}"#
            );
            let err = parse(path, &text).unwrap_err();
            assert!(
                err.to_string().contains("schema_version"),
                "{version}: {err:#}"
            );
        }
        let duplicate = r#"{"schema_version":null,"schema_version":2,"input":"in","output":"out","profile":"fast"}"#;
        assert!(parse(path, duplicate).is_err());
        let omitted = r#"{"input":"in","output":"out","profile":"fast"}"#;
        assert_eq!(parse(path, omitted).unwrap().schema_version, SCHEMA_VERSION);
    }

    #[test]
    fn saving_in_another_directory_preserves_references_and_updates_only_projects() {
        use crate::output::tests::TestDir;
        let dir = TestDir::new();
        let base = dir.0.join("configs");
        fs::create_dir(&base).unwrap();
        let path = base.join("demo.xenolith.json");
        let mut file = parse(
            &path,
            r#"{"input":"src/image.dll","output":"out/image.dll","profile":"fast"}"#,
        )
        .unwrap();
        file.input = dir.0.join(&file.input);
        file.output = base.join(&file.output);
        fs::write(&path, b"unrelated data").unwrap();
        for mode in [SaveMode::New, SaveMode::UpdateProject] {
            assert!(save(&path, file.clone(), mode).is_err());
            assert_eq!(fs::read(&path).unwrap(), b"unrelated data");
        }
        fs::remove_file(&path).unwrap();
        save(&path, file.clone(), SaveMode::New).unwrap();
        assert_eq!(load(&path).unwrap().output, Path::new("out/image.dll"));
        file.profile = "standard".into();
        save(&path, file.clone(), SaveMode::UpdateProject).unwrap();
        let loaded = load_paths(&path).unwrap();
        assert_eq!(loaded.profile, "standard");
        assert_eq!(loaded.input, file.input);
        assert_eq!(loaded.output, file.output);
    }
}
