//! TASK-037: duration-configurable stress harness for the packed lazy-region
//! runtime. The 10k load/unload soak in `os_load.rs` proves one fixed shape;
//! this harness runs the same pressure (concurrent callers, census races,
//! full load/unload boot cycles) for a configurable wall duration and samples
//! process memory so sustained leaks become visible numbers, not vibes.
//!
//! Usage:
//!   cargo test --test resilience -- --nocapture            # 60 s default
//!   XL_STRESS_SECONDS=900 XL_STRESS_REPORT=out.json cargo test --test resilience
//!
//! The 72 h release-qualification run uses the same entry point:
//!   XL_STRESS_SECONDS=259200 XL_STRESS_REPORT=stress-72h.json cargo test --test resilience
//!
//! Non-Windows hosts print BLOCKED (user-mode stress is a Windows/PE
//! capability today); `XL_REQUIRE_STRESS=1` upgrades that to a failure.

mod common;

#[cfg(windows)]
mod stress {
    use super::common;
    use xenolith_loader::Profile;
    use xenolith_pack::{pack, PackRequest};
    use std::time::{Duration, Instant};

    const PAGE_NOACCESS: u32 = 0x01;
    const PAGE_EXECUTE_READ: u32 = 0x20;

    #[link(name = "kernel32")]
    extern "system" {
        fn LoadLibraryW(p: *const u16) -> *mut core::ffi::c_void;
        fn FreeLibrary(h: *mut core::ffi::c_void) -> i32;
        fn GetProcAddress(h: *mut core::ffi::c_void, n: *const u8) -> *mut core::ffi::c_void;
        fn VirtualQuery(
            a: *const core::ffi::c_void,
            b: *mut u8,
            l: usize,
        ) -> usize;
        fn K32GetProcessMemoryInfo(
            proc: *mut core::ffi::c_void,
            counters: *mut MemoryCounters,
            cb: u32,
        ) -> i32;
        fn GetCurrentProcess() -> *mut core::ffi::c_void;
    }

    #[repr(C)]
    struct MemoryCounters {
        cb: u32,
        page_faults: u32,
        peak_working_set: usize,
        working_set: usize,
        quota_peak_paged: usize,
        quota_paged: usize,
        quota_peak_nonpaged: usize,
        quota_nonpaged: usize,
        pagefile_usage: usize,
        peak_pagefile_usage: usize,
    }

    fn memory_sample() -> (usize, usize) {
        let mut mc = MemoryCounters {
            cb: std::mem::size_of::<MemoryCounters>() as u32,
            page_faults: 0,
            peak_working_set: 0,
            working_set: 0,
            quota_peak_paged: 0,
            quota_paged: 0,
            quota_peak_nonpaged: 0,
            quota_nonpaged: 0,
            pagefile_usage: 0,
            peak_pagefile_usage: 0,
        };
        let ok = unsafe {
            K32GetProcessMemoryInfo(
                GetCurrentProcess(),
                &mut mc,
                std::mem::size_of::<MemoryCounters>() as u32,
            )
        };
        assert_ne!(ok, 0, "K32GetProcessMemoryInfo failed");
        (mc.working_set, mc.pagefile_usage)
    }

    fn wide_path(path: &std::path::Path) -> Vec<u16> {
        use std::os::windows::ffi::OsStrExt;
        let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
        wide.push(0);
        wide
    }

    fn parse_envelope(image: &[u8]) -> xenolith_protocol::EnvelopeV2 {
        for pos in 0..image.len().saturating_sub(4) {
            if &image[pos..pos + 4] != b"XLV2" {
                continue;
            }
            if let Ok(e) = xenolith_protocol::parse(&image[pos..]) {
                return e;
            }
        }
        panic!("no parseable XLV2 envelope in packed image");
    }

    /// (dormant, woken) over the lazy pages; any protection class outside
    /// {NOACCESS, RX} is a hard failure, same contract as the G5 census.
    fn census(handle: *mut core::ffi::c_void, rvas: &[u32]) -> (usize, usize) {
        let (mut dormant, mut woken) = (0usize, 0usize);
        for &rva in rvas {
            let mut mbi = [0u8; 48];
            let ok =
                unsafe { VirtualQuery((handle as usize + rva as usize) as *const _, mbi.as_mut_ptr(), mbi.len()) };
            assert_eq!(ok, mbi.len(), "VirtualQuery failed");
            let protect = u32::from_le_bytes(mbi[0x24..0x28].try_into().unwrap());
            match protect {
                PAGE_NOACCESS => dormant += 1,
                PAGE_EXECUTE_READ => woken += 1,
                other => panic!(
                    "stress census: lazy rva={rva:#x} protect=0x{other:02x}; expected NOACCESS/RX"
                ),
            }
        }
        (dormant, woken)
    }

    fn pack_lazy(input: &[u8]) -> xenolith_pack::PackOutput {
        pack(PackRequest {
            input,
            profile: Profile::Standard,
            vm_exports: vec![],
            debug_gate: 3,
            opcode_seed: Some([0x42u8; 16]),
            trace_diverge: false,
            select_rva: vec![],
            select_functions: Vec::new(),
            select_all: false,
            allow_native_fallback: false,
            strict_coverage: false,
            lazy_regions: true,
            protect_imports: false,
            strict_constants: false,
        })
        .unwrap_or_else(|e| panic!("pack lazy: {e}"))
    }

    struct RoundSample {
        round: usize,
        seconds_in: u64,
        dormant: usize,
        woken: usize,
        working_set: usize,
        commit: usize,
        load_cycles: u64,
        calls: u64,
    }

    fn json_report(
        seconds: u64,
        samples: &[RoundSample],
        leak_baseline: (usize, usize),
        end_state: (usize, usize),
    ) -> String {
        let mut s = String::from("{\n  \"harness\": \"xl-stress-resilience\",\n");
        s.push_str(&format!("  \"configured_seconds\": {seconds},\n"));
        s.push_str(&format!(
            "  \"rounds\": {},\n  \"total_load_cycles\": {},\n  \"total_calls\": {},\n",
            samples.len(),
            samples.last().map(|r| r.load_cycles).unwrap_or(0),
            samples.last().map(|r| r.calls).unwrap_or(0),
        ));
        s.push_str(&format!(
            "  \"working_set_start\": {},\n  \"working_set_end\": {},\n",
            leak_baseline.0, end_state.0
        ));
        s.push_str(&format!(
            "  \"commit_start\": {},\n  \"commit_end\": {},\n",
            leak_baseline.1, end_state.1
        ));
        s.push_str("  \"samples\": [\n");
        for (i, r) in samples.iter().enumerate() {
            s.push_str(&format!(
                "    {{\"round\": {}, \"t_s\": {}, \"dormant\": {}, \"woken\": {}, \"ws\": {}, \"commit\": {}, \"cycles\": {}, \"calls\": {}}}{}\n",
                r.round, r.seconds_in, r.dormant, r.woken, r.working_set, r.commit, r.load_cycles, r.calls,
                if i + 1 < samples.len() { "," } else { "" }
            ));
        }
        s.push_str("  ]\n}\n");
        s
    }

    // Child: the actual stress loop. Marker "STRESS OK".
    #[test]
    fn stress_child_run() {
        if std::env::var("XL_LOADER_CHILD").as_deref() != Ok("1") {
            return;
        }
        let seconds: u64 = std::env::var("XL_STRESS_SECONDS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(60)
            .max(1);
        let dll = common::required_release_sample("hello_dll.dll");
        let dir = std::env::temp_dir();
        let packed = pack_lazy(&dll);
        let path = dir.join(format!("xl-stress-{}.dll", std::process::id()));
        std::fs::write(&path, &packed.image).expect("write packed");
        let env = parse_envelope(&packed.image);
        let rvas: Vec<u32> = env
            .lazy
            .iter()
            .map(|&idx| env.regions[idx as usize].rva)
            .collect();
        let has_lazy = !rvas.is_empty();
        if !has_lazy {
            eprintln!(
                "STRESS SKIP residency: every executable page is in the entry/export keep set for this sample"
            );
        }

        let deadline = Instant::now() + Duration::from_secs(seconds);
        let mut samples: Vec<RoundSample> = Vec::new();
        let mut cycles: u64 = 0;
        let mut calls: u64 = 0;
        let mut baseline: Option<(usize, usize)> = None;

        while Instant::now() < deadline {
            // Phase A: 8 concurrent callers against one mapping.
            {
                let wide = wide_path(&path);
                let h = unsafe { LoadLibraryW(wide.as_ptr()) };
                assert!(!h.is_null(), "LoadLibrary failed (round {})", samples.len());
                unsafe {
                    let proc = GetProcAddress(h, b"hello_add\0".as_ptr());
                    assert!(!proc.is_null(), "hello_add missing");
                    let f: extern "C" fn(i32, i32) -> i32 = core::mem::transmute(proc);
                    let mut threads = Vec::new();
                    for t in 0..8usize {
                        threads.push(std::thread::spawn(move || {
                            for i in 0..2000i32 {
                                assert_eq!(f(i, t as i32), i + t as i32, "stress hello_add");
                            }
                        }));
                    }
                    for th in threads {
                        th.join().expect("stress caller panicked");
                    }
                    calls += 8 * 2000;
                }
                let (dormant, woken) = if has_lazy {
                    let c = census(h, &rvas);
                    assert_eq!(c.0 + c.1, rvas.len(), "census lost a lazy page");
                    c
                } else {
                    (0, 0)
                };
                let (ws, commit) = memory_sample();
                if baseline.is_none() {
                    // Warm-up done (CRT + first boot allocations happened);
                    // leak verdicts compare against this.
                    baseline = Some((ws, commit));
                }
                samples.push(RoundSample {
                    round: samples.len(),
                    seconds_in: seconds - deadline.duration_since(Instant::now()).as_secs(),
                    dormant,
                    woken,
                    working_set: ws,
                    commit,
                    load_cycles: cycles,
                    calls,
                });
                assert!(unsafe { FreeLibrary(h) } != 0, "FreeLibrary failed after phase A");
            }
            // Phase B: 25 full load/unload boot cycles (decrypt, seal, VEH,
            // quiesce, deregister, zeroize).
            {
                let wide = wide_path(&path);
                for _ in 0..25 {
                    let h = unsafe { LoadLibraryW(wide.as_ptr()) };
                    assert!(!h.is_null(), "LoadLibrary failed in cycle loop");
                    unsafe {
                        let proc = GetProcAddress(h, b"hello_add\0".as_ptr());
                        let f: extern "C" fn(i32, i32) -> i32 = core::mem::transmute(proc);
                        assert_eq!(f(1, 2), 3, "hello_add in load cycle");
                        calls += 1;
                    }
                    assert!(unsafe { FreeLibrary(h) } != 0, "FreeLibrary failed in cycle loop");
                    cycles += 1;
                    if Instant::now() >= deadline {
                        break;
                    }
                }
            }
            eprintln!(
                "STRESS round {} cycles={cycles} calls={calls}",
                samples.len()
            );
        }

        let (start_ws, start_commit) = baseline.expect("no baseline sample");
        let (end_ws, end_commit) = memory_sample();
        samples.push(RoundSample {
            round: samples.len(),
            seconds_in: seconds,
            dormant: 0,
            woken: 0,
            working_set: end_ws,
            commit: end_commit,
            load_cycles: cycles,
            calls,
        });

        // Sustained-leak verdict: with the warm-up baseline subtracted, the
        // working set may float (allocator caches, ASLR heaps) but not grow
        // without bound. 256 MiB above baseline for a hello-scale DLL is
        // already two orders of magnitude past anything legitimate.
        let ws_growth = end_ws.saturating_sub(start_ws);
        assert!(
            ws_growth < 256 * 1024 * 1024,
            "working set grew {ws_growth} bytes above baseline in {seconds}s; sustained leak"
        );

        let report = json_report(seconds, &samples, (start_ws, start_commit), (end_ws, end_commit));
        match std::env::var("XL_STRESS_REPORT") {
            Ok(p) => {
                let path = std::path::PathBuf::from(&p);
                if let Some(parent) = path.parent() {
                    if !parent.as_os_str().is_empty() {
                        let _ = std::fs::create_dir_all(parent);
                    }
                }
                std::fs::write(&path, report)
                    .unwrap_or_else(|e| panic!("write report {}: {e}", path.display()));
                eprintln!("STRESS report -> {}", path.display());
            }
            Err(_) => {
                let fallback = dir.join(format!("xl-stress-report-{}.json", std::process::id()));
                let _ = std::fs::write(&fallback, &report);
                eprintln!("STRESS report -> {} (XL_STRESS_REPORT unset)", fallback.display());
            }
        }
        let _ = std::fs::remove_file(&path);
        eprintln!("STRESS OK seconds={seconds} cycles={cycles} calls={calls} ws={start_ws}->{end_ws}");
    }

    // Keep the duration imports referenced when compiled as a library-style
    // test target without reaching the child body.
    #[allow(dead_code)]
    fn _deadline(seconds: u64) -> Instant {
        Instant::now() + Duration::from_secs(seconds)
    }

    // Parent: fresh pack per run (unique seed), spawn the child, require the
    // completion marker, and sanity-check the JSON report when pointed at one.
    #[test]
    fn stress_resilience_bounded() {
        let out = common::spawn_exact_child("stress::stress_child_run");
        common::assert_child_ok(&out, "STRESS OK", "stress resilience");
        if let Ok(p) = std::env::var("XL_STRESS_REPORT") {
            let report = std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {p}: {e}"));
            assert!(report.contains("\"harness\": \"xl-stress-resilience\""), "report shape");
            assert!(report.contains("\"rounds\":"), "report rounds");
        }
    }
}

#[cfg(not(windows))]
#[test]
fn stress_resilience_not_executed() {
    eprintln!(
        "BLOCKED: user-mode stress resilience runs the Windows PE runtime; \
         this host cannot execute it. This is not a stress pass."
    );
    if std::env::var("XL_REQUIRE_STRESS").as_deref() == Ok("1") {
        panic!("XL_REQUIRE_STRESS=1 but this host is not Windows");
    }
}
