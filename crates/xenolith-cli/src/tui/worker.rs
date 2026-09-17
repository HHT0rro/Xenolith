//! Background pack worker. Computes only; the UI thread decides whether to write.

use crate::args::ProfileArg;
use xenolith_pack::{pack, PackReport, PackRequest};
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

pub struct PackDone {
    pub report: PackReport,
    pub image: Vec<u8>,
    pub output: PathBuf,
    pub elapsed: Duration,
}

/// Assemble the `PackRequest` the TUI sends. Split out from `spawn_pack` so
/// the field wiring (especially `select_rva` passthrough) is testable
/// without running a pack.
pub fn build_request<'a>(
    bytes: &'a [u8],
    profile: ProfileArg,
    vm_exports: Vec<String>,
    select_rva: Vec<(u32, u32)>,
    trace_diverge: bool,
    strict_coverage: bool,
    select_functions: Vec<String>,
    select_all: bool,
    allow_native_fallback: bool,
    lazy_regions: bool,
    protect_imports: bool,
    strict_constants: bool,
) -> PackRequest<'a> {
    PackRequest {
        input: bytes,
        profile: profile.into(),
        vm_exports,
        debug_gate: 3,
        opcode_seed: None,
        trace_diverge,
        select_rva,
        select_functions,
        select_all,
        strict_coverage,
        allow_native_fallback,
        lazy_regions,
        protect_imports,
        strict_constants,
    }
}

/// Spawn `pack()` on a worker thread holding its own copy of the image bytes.
/// The thread never writes to disk. `pack()` has no interrupt hook — cancelling
/// in the UI only drops the result. `select_rva` passes through as parsed
/// `RVA:LEN` ranges (empty unless a project file supplied them).
pub fn spawn_pack(
    bytes: Vec<u8>,
    profile: ProfileArg,
    vm_exports: Vec<String>,
    select_rva: Vec<(u32, u32)>,
    trace_diverge: bool,
    strict_coverage: bool,
    select_functions: Vec<String>,
    select_all: bool,
    allow_native_fallback: bool,
    lazy_regions: bool,
    protect_imports: bool,
    strict_constants: bool,
    output: PathBuf,
) -> anyhow::Result<Receiver<Result<PackDone, String>>> {
    let (tx, rx) = mpsc::channel();
    std::thread::Builder::new()
        .name("xl-pack".into())
        .spawn(move || {
            let t0 = Instant::now();
            let msg = match pack(build_request(
                &bytes,
                profile,
                vm_exports,
                select_rva,
                trace_diverge,
                strict_coverage,
                select_functions,
                select_all,
                allow_native_fallback,
                lazy_regions,
                protect_imports,
                strict_constants,
            )) {
                Ok(packed) => Ok(PackDone {
                    report: packed.report,
                    image: packed.image,
                    output,
                    elapsed: t0.elapsed(),
                }),
                Err(e) => Err(e.to_string()),
            };
            let _ = tx.send(msg);
        })
        .map_err(|e| anyhow::anyhow!("spawn pack thread: {e}"))?;
    Ok(rx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::args::ProfileArg;
    use xenolith_formats::Pe64;
    use xenolith_pack::lift_export;
    use std::path::PathBuf;

    fn sample_dll() -> PathBuf {
        if !cfg!(windows) {
            return PathBuf::new();
        }
        let rel = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/release/license_toy.dll");
        if rel.is_file() {
            return rel;
        }
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/debug/license_toy.dll")
    }

    #[test]
    fn worker_computes_without_writing() {
        let dll = sample_dll();
        if !dll.is_file() {
            return;
        }
        let out = std::env::temp_dir().join(format!(
            "xl-tui-nowrite-{}-{}.xl.dll",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&out);
        let bytes = std::fs::read(&dll).expect("read sample dll");
        let rx = spawn_pack(
            bytes,
            ProfileArg::Max,
            vec!["check_license".into()],
            vec![],
            false,
            false,
            vec![],
            false,
            false,
            false,
            false,
            false,
            out.clone(),
        )
        .expect("spawn");
        let done = rx.recv().expect("recv").expect("pack ok");
        assert!(!out.exists(), "worker must not write {}", out.display());
        assert!(!done.image.is_empty());
        assert_eq!(done.report.vm_functions, 1);
        assert_eq!(done.report.seed_len, 16);
    }

    #[test]
    fn request_carries_select_rva_and_switches() {
        let bytes = vec![0u8; 16];
        let req = build_request(
            &bytes,
            ProfileArg::Standard,
            vec!["f".into()],
            vec![(0x1000, 0x20), (0x7fff, 16)],
            true,
            true,
            vec!["internal".into()],
            true,
            false,
            true,
            true,
            true,
        );
        assert_eq!(req.select_rva, vec![(0x1000, 0x20), (0x7fff, 16)]);
        assert_eq!(req.vm_exports, vec!["f"]);
        assert!(req.trace_diverge && req.strict_coverage);
        assert_eq!(req.select_functions, vec!["internal"]);
        assert!(req.select_all && !req.allow_native_fallback);
        assert!(req.lazy_regions && req.protect_imports && req.strict_constants);
        assert_eq!(req.debug_gate, 3);
        assert!(req.opcode_seed.is_none());
    }

    /// End-to-end passthrough: parsed ranges reach `pack()` and internal
    /// range entries are rewritten through their original entry.
    #[test]
    fn select_rva_reaches_pack() {
        let dll = sample_dll();
        if !dll.is_file() {
            return;
        }
        let bytes = std::fs::read(&dll).expect("read sample dll");
        let pe = Pe64::parse(&bytes).expect("parse sample dll");
        let exp = pe
            .exports(&bytes)
            .expect("exports")
            .into_iter()
            .find(|e| e.name == "check_license")
            .expect("check_license export");
        let lifted = lift_export(&pe, &bytes, "check_license", exp.rva).expect("pre-lift");
        assert!(lifted.native_len > 0, "native_len must bound the range");
        let out = std::env::temp_dir().join(format!(
            "xl-tui-rva-{}-{}.xl.dll",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let rx = spawn_pack(
            bytes,
            ProfileArg::Max,
            vec![],
            vec![(exp.rva, lifted.native_len as u32)],
            false,
            false,
            vec![],
            false,
            false,
            false,
            false,
            false,
            out.clone(),
        )
        .expect("spawn");
        let res = rx.recv().expect("recv");
        assert!(!out.exists(), "worker must not write {}", out.display());
        let done = res.expect("range-only pack should now rewrite the range");
        assert!(
            done.report
                .selected_functions
                .iter()
                .any(|name| name.starts_with("rva_")),
            "range selection did not reach pack(): {:?}",
            done.report.selected_functions
        );
        assert_eq!(done.report.vm_functions, 1);
    }
}
