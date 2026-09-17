use anyhow::{bail, Context, Result};
use xenolith_loader::Profile;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
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
    pub fn profile(&self) -> Result<Profile> {
        match self.profile.as_str() {
            "fast" => Ok(Profile::Fast),
            "standard" => Ok(Profile::Standard),
            "max" => Ok(Profile::Max),
            other => bail!("unknown profile {other}"),
        }
    }
}

pub fn load(path: &Path) -> Result<ProjectFile> {
    let text = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let raw: BTreeMap<String, serde_json::Value> =
        serde_json::from_str(&text).with_context(|| format!("parse {}", path.display()))?;
    for k in raw.keys() {
        if !KNOWN.contains(&k.as_str()) {
            bail!(
                "project {}: unknown key `{k}` (not armed / not in schema)",
                path.display()
            );
        }
    }
    let mut value: serde_json::Value = serde_json::from_str(&text)?;
    let version = value
        .get("schema_version")
        .and_then(|v| v.as_u64())
        .unwrap_or(1);
    if version == 0 || version == 1 {
        value["schema_version"] = serde_json::json!(SCHEMA_VERSION);
    } else if version > SCHEMA_VERSION as u64 {
        bail!(
            "project {}: schema_version {} is newer than this tool ({SCHEMA_VERSION})",
            path.display(),
            version
        );
    }
    let file: ProjectFile = serde_json::from_value(value)?;
    Ok(file)
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

pub fn save(path: &Path, file: &ProjectFile) -> Result<()> {
    let json = serde_json::to_string_pretty(file)?;
    fs::write(path, json).with_context(|| format!("write {}", path.display()))?;
    Ok(())
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
        save(&path, &file).unwrap();
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
}
