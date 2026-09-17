//! G0: frozen corpus/compat manifests must exist and name the current samples.

use serde_json::Value;
use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn load_json(rel: &str) -> Value {
    let path = repo_root().join(rel);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("missing {rel} at {}: {e}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{rel} is not JSON: {e}"))
}

#[test]
fn corpus_manifest_frozen() {
    let v = load_json("tests/corpus/manifest.json");
    assert_eq!(v["version"], 1);
    let samples = v["samples"].as_array().expect("samples");
    let ids: Vec<&str> = samples
        .iter()
        .map(|s| s["id"].as_str().unwrap())
        .collect();
    assert!(ids.contains(&"hello-dll"));
    assert!(ids.contains(&"license-toy"));
    assert!(ids.contains(&"hello-exe"));
    assert!(
        v["policy"]["no_delete_hard_cases"].as_bool() == Some(true),
        "corpus must freeze the no-delete-hard-cases rule"
    );
}

#[test]
fn compat_manifest_frozen() {
    let v = load_json("tests/compat/manifest.json");
    assert_eq!(v["version"], 1);
    assert_eq!(v["current"]["elf"], "fail-closed");
    assert_eq!(v["current"]["aslr"], "preserved-when-present-on-input");
    assert_eq!(v["current"]["injected_runtime"], "pic-stub+xl-core");
}
