//! TASK-038: G8 performance baseline vs the release budgets. Runs only when
//! explicitly asked (`cargo bench` passes `--bench`, or XL_PERF_RUN=1) so the
//! normal `cargo test --workspace` cycle never pays for it.
//!
//! Budgets (release targets, not current claims):
//!   * Standard app geometric-mean wall time  <= 2.0x plain
//!   * protected (virtualized) call P95       <= 10.0x native call
//!   * packed file size                       <= 4.0x input
//!
//! Everything measured here lands in tests/corpus/g8_perf_baseline.json via
//! XL_PERF_OUT; numbers are reported honestly, including failures.

#[cfg(windows)]
mod perf {
    use std::path::PathBuf;
    use std::time::Instant;

    const BATCH_CALLS: usize = 20_000;
    const BATCHES: usize = 40;
    const SPAWN_RUNS: usize = 30;

    #[link(name = "kernel32")]
    extern "system" {
        fn LoadLibraryW(p: *const u16) -> *mut core::ffi::c_void;
        fn FreeLibrary(h: *mut core::ffi::c_void) -> i32;
        fn GetProcAddress(h: *mut core::ffi::c_void, n: *const u8) -> *mut core::ffi::c_void;
    }

    fn wide(path: &std::path::Path) -> Vec<u16> {
        use std::os::windows::ffi::OsStrExt;
        let mut w: Vec<u16> = path.as_os_str().encode_wide().collect();
        w.push(0);
        w
    }

    pub fn sample(name: &str) -> Vec<u8> {
        let mut candidates = Vec::new();
        if let Ok(manifest) = std::env::var("CARGO_MANIFEST_DIR") {
            candidates.push(PathBuf::from(manifest).join("../../target/release").join(name));
        }
        if let Ok(td) = std::env::var("CARGO_TARGET_DIR") {
            candidates.push(PathBuf::from(td).join("release").join(name));
        }
        candidates.push(PathBuf::from("target/release").join(name));
        for c in &candidates {
            if let Ok(b) = std::fs::read(c) {
                if !b.is_empty() {
                    return b;
                }
            }
        }
        panic!(
            "missing required sample {name} (looked in {candidates:?}); \
             build samples first: cargo build -p hello-dll -p hello-exe \
             -p license-toy -p eh-dll --release"
        );
    }

    fn pack_to(input: &[u8], profile: xenolith_loader::Profile, vm: &[&str], tag: &str) -> PathBuf {
        use xenolith_pack::{pack, PackRequest};
        let out = pack(PackRequest {
            input,
            profile,
            vm_exports: vm.iter().map(|s| s.to_string()).collect(),
            debug_gate: 3,
            opcode_seed: Some([0x24u8; 16]),
            trace_diverge: false,
            select_rva: vec![],
            select_functions: Vec::new(),
            select_all: false,
            allow_native_fallback: false,
            strict_coverage: false,
            lazy_regions: false,
            protect_imports: false,
            strict_constants: false,
        })
        .unwrap_or_else(|e| panic!("pack {tag}: {e}"));
        let path = std::env::temp_dir().join(format!("xl-perf-{tag}-{}.bin", std::process::id()));
        std::fs::write(&path, &out.image).expect("write packed");
        path
    }

    fn call_batches(dll: &std::path::Path, export: &str) -> Vec<f64> {
        let h = unsafe { LoadLibraryW(wide(dll).as_ptr()) };
        assert!(!h.is_null(), "LoadLibrary {} failed", dll.display());
        let proc = unsafe { GetProcAddress(h, export.as_ptr()) };
        assert!(!proc.is_null(), "missing {export} in {}", dll.display());
        let f: extern "C" fn(i32, i32) -> i32 = unsafe { core::mem::transmute(proc) };
        let mut rates = Vec::new();
        for b in 0..BATCHES {
            let t = Instant::now();
            for i in 0..BATCH_CALLS {
                let v = f(i as i32, b as i32);
                std::hint::black_box(v);
            }
            let ns = t.elapsed().as_nanos() as f64;
            rates.push(ns / BATCH_CALLS as f64);
        }
        assert!(unsafe { FreeLibrary(h) } != 0);
        rates
    }

    fn percentile(sorted: &[f64], p: f64) -> f64 {
        let idx = ((sorted.len() as f64 - 1.0) * p).round() as usize;
        sorted[idx.min(sorted.len() - 1)]
    }

    fn spawn_runs(exe: &std::path::Path) -> Vec<f64> {
        let mut times = Vec::new();
        for _ in 0..SPAWN_RUNS {
            let t = Instant::now();
            let st = std::process::Command::new(exe).output().expect("spawn exe");
            let ms = t.elapsed().as_secs_f64() * 1000.0;
            assert!(st.status.success(), "exe {} failed", exe.display());
            times.push(ms);
        }
        times.sort_by(|a, b| a.partial_cmp(b).unwrap());
        times
    }

    fn geomean(v: &[f64]) -> f64 {
        (v.iter().map(|x| x.ln()).sum::<f64>() / v.len() as f64).exp()
    }

    pub fn run() -> String {
        use xenolith_loader::Profile;
        let native_dll = {
            let bytes = sample("hello_dll.dll");
            let p = std::env::temp_dir().join(format!("xl-perf-native-{}.dll", std::process::id()));
            std::fs::write(&p, &bytes).expect("write native");
            p
        };
        let hello_exe = sample("hello-exe.exe");
        let plain_exe = {
            let p = std::env::temp_dir().join(format!("xl-perf-plain-exe-{}.exe", std::process::id()));
            std::fs::write(&p, &hello_exe).expect("write plain exe");
            p
        };
        let packed_exe = pack_to(&hello_exe, Profile::Standard, &[], "std-exe");
        let packed_vm_dll = pack_to(&sample("hello_dll.dll"), Profile::Standard, &["hello_add"], "vm-dll");

        // 1) protected call P95: virtualized hello_add vs native hello_add.
        let mut native = call_batches(&native_dll, "hello_add\0");
        let mut vm = call_batches(&packed_vm_dll, "hello_add\0");
        native.sort_by(|a, b| a.partial_cmp(b).unwrap());
        vm.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let native_p50 = percentile(&native, 0.50);
        let vm_p95 = percentile(&vm, 0.95);
        let vm_p50 = percentile(&vm, 0.50);
        let call_ratio = vm_p95 / native_p50;

        // 2) app geomean: packed exe spawn vs plain exe spawn (Standard).
        let plain = spawn_runs(&plain_exe);
        let packed = spawn_runs(&packed_exe);
        let spawn_ratio = geomean(&packed) / geomean(&plain);

        // 3) size ratios across the frozen corpus samples (Standard).
        let mut size_rows: Vec<(String, f64, f64)> = Vec::new();
        for (name, sample_bytes) in [
            ("hello_dll.dll", sample("hello_dll.dll")),
            ("license_toy.dll", sample("license_toy.dll")),
            ("hello-exe.exe", hello_exe.clone()),
            ("eh_dll.dll", sample("eh_dll.dll")),
        ] {
            let out = pack_to(&sample_bytes, Profile::Standard, &[], "size-probe");
            let packed_len = std::fs::metadata(&out).expect("stat").len() as f64;
            let _ = std::fs::remove_file(&out);
            size_rows.push((name.to_string(), sample_bytes.len() as f64, packed_len));
        }
        let size_ratio = size_rows
            .iter()
            .map(|(_, i, o)| o / i)
            .fold(f64::MIN, f64::max);

        let verdict = |ok: bool, what: &str, value: f64, budget: f64| {
            format!(
                "  {:<28} {:>8.3}x  budget {:>5.1}x  {}\n",
                what,
                value,
                budget,
                if ok { "PASS" } else { "FAIL" }
            )
        };
        let mut report = String::from("G8 perf baseline (Standard profile, Windows host)\n");
        report.push_str(&format!(
            "  native hello_add p50 {:.1} ns | vm p50 {:.1} ns | vm p95 {:.1} ns\n",
            native_p50, vm_p50, vm_p95
        ));
        report.push_str(&format!(
            "  plain exe geomean {:.1} ms | packed exe geomean {:.1} ms\n",
            geomean(&plain),
            geomean(&packed)
        ));
        for (name, i, o) in &size_rows {
            report.push_str(&format!("  size {name}: {i:.0}B -> {o:.0}B ({:.3}x)\n", o / i));
        }
        report.push_str("budgets:\n");
        report.push_str(&verdict(spawn_ratio <= 2.0, "app geomean (std)", spawn_ratio, 2.0));
        report.push_str(&verdict(call_ratio <= 10.0, "protected call p95", call_ratio, 10.0));
        report.push_str(&verdict(size_ratio <= 4.0, "size (worst sample)", size_ratio, 4.0));

        // Machine-readable copy of the same numbers.
        report.push_str(&format!(
            "{{\n  \"app_geomean_ratio_std\": {spawn_ratio:.6},\n  \"protected_call_p95_ratio\": {call_ratio:.6},\n  \"native_call_p50_ns\": {native_p50:.3},\n  \"vm_call_p50_ns\": {vm_p50:.3},\n  \"vm_call_p95_ns\": {vm_p95:.3},\n  \"size_worst_ratio\": {size_ratio:.6},\n  \"sizes\": [\n{}  ],\n  \"budgets\": {{\"app_geomean\": 2.0, \"call_p95\": 10.0, \"size\": 4.0}},\n  \"spawn_runs\": {SPAWN_RUNS},\n  \"call_batches\": {BATCHES},\n  \"batch_calls\": {BATCH_CALLS}\n}}\n",
            size_rows
                .iter()
                .map(|(n, i, o)| format!("    {{\"sample\": \"{n}\", \"in\": {i:.0}, \"out\": {o:.0}}}"))
                .collect::<Vec<_>>()
                .join(",\n")
        ));

        for p in [&native_dll, &plain_exe, &packed_exe, &packed_vm_dll] {
            let _ = std::fs::remove_file(p);
        }
        report
    }
}

fn main() {
    let invoked = std::env::args().any(|a| a == "--bench")
        || std::env::var("XL_PERF_RUN").as_deref() == Ok("1");
    if !invoked {
        println!("g8_perf: passive (set XL_PERF_RUN=1 or run via `cargo bench`)");
        return;
    }
    #[cfg(windows)]
    {
        let report = perf::run();
        print!("{report}");
        if let Ok(p) = std::env::var("XL_PERF_OUT") {
            let path = std::path::PathBuf::from(&p);
            if let Some(parent) = path.parent() {
                if !parent.as_os_str().is_empty() {
                    let _ = std::fs::create_dir_all(parent);
                }
            }
            std::fs::write(&path, &report).unwrap_or_else(|e| panic!("write {p}: {e}"));
        }
    }
    #[cfg(not(windows))]
    eprintln!("BLOCKED: g8_perf measures the Windows PE runtime; not run here");
}
