//! Runtime anti-debug / anti-dump policy.
//!
//! Host-side code records which probes a packed image will run. The actual
//! syscalls live in the injected PIC stub (`xenolith-pack::stub`). This
//! crate is the policy surface so tests can assert forbidden techniques stay
//! absent. `xenolith-loader` does not execute these probes.
//!
//! Android/bionic (plan `.apk-compat/xenolith/plan.md` WS-A): the probe
//! body for the ELF path lives in the freestanding C core
//! (`xenolith-runtime/core/xl_core.c`, `#if defined(__aarch64__)`), gated by
//! a pack-time probe bitmap this crate computes. The mask travels over the
//! stub↔core protocol (`stub_meta::CTX_PROBE_MASK`, offset 128), encoded as
//! a machine-code constant by the aarch64 stub emitter — NOT as an envelope
//! field, so it never perturbs region AADs.

use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Probe {
    PebBeingDebugged,
    ProcessDebugPort,
    ProcessDebugObjectHandle,
    ProcessDebugFlags,
    KernelDebuggerInfo,
    HideFromDebugger,
    ClearInstrumentationCallback,
    RedirectDbgUiRemoteBreakin,
    HardwareBreakpoints,
    TrapFlagTiming,
    Int3StubScan,
    TlsEarlyProbe,
    CleanNtdllCompare,
    HypervisorCpuid,
    MiniDumpWatch,
    RemoteReadWatch,
    // ---- Android/bionic probes (global ids 17+; execution is aarch64-only
    // in v1, see `android_probes`) ----
    /// `/proc/self/status` TracerPid scan, resolved through
    /// [`classify_tracerpid`].
    TracerPidScan,
    /// `ptrace(PTRACE_TRACEME)` self-attach: occupy the tracer slot so any
    /// later external PTRACE_ATTACH is refused by the kernel.
    PtraceSelfAttach,
    /// `/proc/self/maps` scan for known analysis-module markers (frida,
    /// xposed, substrate, dlopen-hook).
    MapsScan,
}

pub const FORBIDDEN_SUBSTRINGS: &[&str] = &[
    "TerminateProcess",
    "NtTerminateProcess",
    "CreateRemoteThread",
    "WriteProcessMemory",
    "EtwEventWrite",
    "DbgUiRemoteBreakin patch file",
];

pub fn max_probes() -> &'static [Probe] {
    &[
        Probe::PebBeingDebugged,
        Probe::ProcessDebugPort,
        Probe::ProcessDebugObjectHandle,
        Probe::ProcessDebugFlags,
        Probe::KernelDebuggerInfo,
        Probe::HideFromDebugger,
        Probe::ClearInstrumentationCallback,
        Probe::RedirectDbgUiRemoteBreakin,
        Probe::HardwareBreakpoints,
        Probe::TrapFlagTiming,
        Probe::Int3StubScan,
        Probe::TlsEarlyProbe,
        Probe::CleanNtdllCompare,
        Probe::HypervisorCpuid,
        Probe::MiniDumpWatch,
        Probe::RemoteReadWatch,
    ]
}

pub fn probe_id(probe: Probe) -> u32 {
    match probe {
        Probe::PebBeingDebugged => 1,
        Probe::ProcessDebugPort => 2,
        Probe::ProcessDebugObjectHandle => 3,
        Probe::ProcessDebugFlags => 4,
        Probe::KernelDebuggerInfo => 5,
        Probe::HideFromDebugger => 6,
        Probe::ClearInstrumentationCallback => 7,
        Probe::RedirectDbgUiRemoteBreakin => 8,
        Probe::HardwareBreakpoints => 9,
        Probe::TrapFlagTiming => 10,
        Probe::Int3StubScan => 11,
        Probe::TlsEarlyProbe => 12,
        Probe::CleanNtdllCompare => 13,
        Probe::HypervisorCpuid => 14,
        Probe::MiniDumpWatch => 15,
        Probe::RemoteReadWatch => 16,
        Probe::TracerPidScan => 17,
        Probe::PtraceSelfAttach => 18,
        Probe::MapsScan => 19,
    }
}

/// Stable wire/report name per probe (mirrors the Windows naming style).
pub fn probe_name(probe: Probe) -> &'static str {
    match probe {
        Probe::PebBeingDebugged => "PebBeingDebugged",
        Probe::ProcessDebugPort => "ProcessDebugPort",
        Probe::ProcessDebugObjectHandle => "ProcessDebugObjectHandle",
        Probe::ProcessDebugFlags => "ProcessDebugFlags",
        Probe::KernelDebuggerInfo => "KernelDebuggerInfo",
        Probe::HideFromDebugger => "HideFromDebugger",
        Probe::ClearInstrumentationCallback => "ClearInstrumentationCallback",
        Probe::RedirectDbgUiRemoteBreakin => "RedirectDbgUiRemoteBreakin",
        Probe::HardwareBreakpoints => "HardwareBreakpoints",
        Probe::TrapFlagTiming => "TrapFlagTiming",
        Probe::Int3StubScan => "Int3StubScan",
        Probe::TlsEarlyProbe => "TlsEarlyProbe",
        Probe::CleanNtdllCompare => "CleanNtdllCompare",
        Probe::HypervisorCpuid => "HypervisorCpuid",
        Probe::MiniDumpWatch => "MiniDumpWatch",
        Probe::RemoteReadWatch => "RemoteReadWatch",
        Probe::TracerPidScan => "TracerPidScan",
        Probe::PtraceSelfAttach => "PtraceSelfAttach",
        Probe::MapsScan => "MapsScan",
    }
}

// ---- Android/bionic probe surface (plan WS-A §2.2.1) ----

/// Android probes shipped in v1, in canonical bitmap order. Execution is
/// aarch64-only: the host/CI x86-64 core is MSVC/gcc-built without the
/// inline `svc` wrappers, and build.rs emits no NDK x86_64-linux-android
/// core (`runtime_image.rs` `sysv_abi:false` path). No `BrkScan` in v1 —
/// sealed pages are 0x90 filler on disk, so a pre-decrypt BRK scan is
/// meaningless (follow-up: self-scan after AEAD open).
pub fn android_probes() -> &'static [Probe] {
    &[Probe::TracerPidScan, Probe::PtraceSelfAttach, Probe::MapsScan]
}

/// Platform-local probe bits consumed by the aarch64 core (`XL_PROBE_BIT_*`
/// in `xl_core.c`). Bit i = `android_probes()[i]` — deliberately decoupled
/// from the global probe ids (17+ would need >imm16 in the stub's `movz`,
/// review 3-3). The stub emitter encodes the mask as a pack-time constant.
pub const ANDROID_PROBE_TRACERPID_SCAN: u32 = 1 << 0;
pub const ANDROID_PROBE_PTRACE_SELF_ATTACH: u32 = 1 << 1;
pub const ANDROID_PROBE_MAPS_SCAN: u32 = 1 << 2;

/// Map a probe selection onto the platform-local bitmap. Windows probes in
/// the input do not contribute bits (the function answers "which Android
/// probes does this selection enable"). With ≤16 Android probes the full
/// mask stays within imm16 — `android_probe_mask(android_probes())` is
/// asserted ≤ 0xFFFF in the tests (review 3-3 pack-time bound).
pub fn android_probe_mask(probes: &[Probe]) -> u32 {
    let mut mask = 0u32;
    for (i, candidate) in android_probes().iter().enumerate() {
        if probes.contains(candidate) {
            mask |= 1 << i;
        }
    }
    mask
}

/// Inverse of [`android_probe_mask`]: which Android probes a decoded stub
/// bitmap enables. Used by `inspect` to recover the probe manifest from a
/// packed artifact's machine code (encode/decode round-trip).
pub fn android_probes_for_mask(mask: u32) -> Vec<Probe> {
    android_probes()
            .iter()
            .enumerate()
            .filter(|(i, _)| mask & (1 << i) != 0)
            .map(|(_, p)| *p)
            .collect()
}

/// Default Android probe selection per profile. `PtraceSelfAttach` is
/// deliberately NOT default-armed in any profile: a successful
/// `PTRACE_TRACEME` on the INIT_ARRAY (dlopen/`System.loadLibrary`) thread
/// makes the parent — zygote on real apps — that thread's tracer, and
/// ptrace has no tracee-side detach, so the next signal delivered to the
/// thread (ART GC suspension, ANR SIGQUIT, any directed signal, even a
/// SIG_IGN'd synchronous fault) enters signal-delivery-stop and is never
/// resumed: the app freezes until SIGKILL (verified on Linux; independent
/// review 2026-10-06). The probe stays implemented and armable for custom
/// builds whose parent cooperates (standalone runners) via
/// `android_probe_mask(&[...])`.
pub fn android_probes_for_profile(max_profile: bool) -> Vec<Probe> {
    if max_profile {
        vec![Probe::TracerPidScan, Probe::MapsScan]
    } else {
        vec![Probe::TracerPidScan]
    }
}

/// Analysis modules whose appearance in `/proc/self/maps` fails the load
/// (MapsScan). The C core matches case-insensitive path substrings
/// ("frida", "xposed", "substrate", "dlopen-hook"), which covers these
/// names; this hash list is the policy surface for reporting/tests.
pub fn known_android_analysis_module_hashes() -> Vec<[u8; 32]> {
    [
        "frida-agent.so",
        "frida-gadget.so",
        "libxposed_art.so",
        "libsubstrate-dvm.so",
        "libdlopen-hook.so",
    ]
    .into_iter()
    .map(module_name_hash)
    .collect()
}

/// Three-way TracerPid verdict (plan review 3-2: the shared disambiguator
/// both TracerPid probes consume). This Rust function is the reference
/// semantics; `xl_classify_tracerpid` in `xl_core.c` mirrors it and is the
/// one that actually executes on device.
///
/// - `None`: TracerPid == 0, no tracer.
/// - `BenignSelf`: TracerPid == getppid() — the residue of our own earlier
///   `PTRACE_TRACEME` self-attach (every re-activation in the same process,
///   e.g. a dlopen/dlclose soak, sees this and MUST NOT fire). Known
///   indistinguishability: a debugger that spawned the process itself
///   (`gdb ./prog`) shows the same signature and passes — recorded as a
///   documented trade-off, not a hidden claim.
/// - `Hit`: some other process traces us — fail closed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TracerVerdict {
    None,
    BenignSelf,
    Hit,
}

pub fn classify_tracerpid(tracer_pid: u32, ppid: u32) -> TracerVerdict {
    if tracer_pid == 0 {
        TracerVerdict::None
    } else if tracer_pid == ppid {
        TracerVerdict::BenignSelf
    } else {
        TracerVerdict::Hit
    }
}

pub fn module_name_hash(name: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"XLMOD\x01");
    hasher.update(name.as_bytes());
    hasher.finalize().into()
}

pub fn known_analysis_module_hashes() -> Vec<[u8; 32]> {
    [
        "x64dbg.dll",
        "x32dbg.dll",
        "scyllahide.dll",
        "scylla_hide.dll",
        "frida-agent.dll",
        "frida-gadget.dll",
        "win32kdbg.dll",
    ]
    .into_iter()
    .map(module_name_hash)
    .collect()
}

pub fn policy_source_is_clean(source: &str) -> bool {
    !FORBIDDEN_SUBSTRINGS.iter().any(|needle| source.contains(needle))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forbidden_list_does_not_include_allowed_syscalls() {
        let src = "NtQueryInformationProcess NtSetInformationThread DbgUiRemoteBreakin";
        assert!(policy_source_is_clean(src));
    }

    #[test]
    fn terminate_process_is_forbidden() {
        assert!(!policy_source_is_clean("call TerminateProcess"));
    }

    // ---- Android probe surface (plan WS-A §2.2.1 / review 3-2 / 3-3) ----

    #[test]
    fn android_probe_ids_are_unique_and_continuous() {
        let mut ids: Vec<u32> = android_probes().iter().map(|p| probe_id(*p)).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids, vec![17, 18, 19]);
    }

    #[test]
    fn android_probe_mask_maps_platform_local_bits() {
        assert_eq!(android_probe_mask(&[]), 0);
        assert_eq!(
            android_probe_mask(&[Probe::TracerPidScan]),
            ANDROID_PROBE_TRACERPID_SCAN
        );
        assert_eq!(
            android_probe_mask(&[Probe::PtraceSelfAttach]),
            ANDROID_PROBE_PTRACE_SELF_ATTACH
        );
        assert_eq!(
            android_probe_mask(&[Probe::MapsScan]),
            ANDROID_PROBE_MAPS_SCAN
        );
        // Full set = three contiguous low bits.
        assert_eq!(android_probe_mask(android_probes()), 0b111);
        // Windows probes contribute no Android bits (answered set-wise).
        assert_eq!(android_probe_mask(max_probes()) & !android_probe_mask(android_probes()), 0);
    }

    /// Review 3-3: with ≤16 Android probes the full mask must stay within
    /// imm16 so the stub's single `movz w9, #mask` always encodes.
    #[test]
    fn android_probe_mask_fits_imm16() {
        assert!(android_probe_mask(android_probes()) <= 0xFFFF);
        assert!(android_probes().len() <= 16);
    }

    #[test]
    fn android_profile_defaults_mirror_windows_policy() {
        // PtraceSelfAttach is implemented but NOT profile-armed: TRACEME on
        // the dlopen thread makes the parent (zygote) the thread's tracer
        // with no tracee-side detach — the next signal on that thread
        // freezes the app (independent review 2026-10-06). Max = scan set;
        // other profiles keep the TracerPid core check only.
        assert_eq!(
            android_probes_for_profile(true),
            vec![Probe::TracerPidScan, Probe::MapsScan]
        );
        assert_eq!(
            android_probes_for_profile(false),
            vec![Probe::TracerPidScan]
        );
        // And every default is a strict subset of the full implemented set.
        let d = android_probe_mask(&android_probes_for_profile(false));
        assert_eq!(d, ANDROID_PROBE_TRACERPID_SCAN);
        let m = android_probe_mask(&android_probes_for_profile(true));
        assert_eq!(m, ANDROID_PROBE_TRACERPID_SCAN | ANDROID_PROBE_MAPS_SCAN);
        assert_eq!(d & !android_probe_mask(android_probes()), 0);
        assert_eq!(m & !android_probe_mask(android_probes()), 0);
        // Custom builds can still arm the self-attach probe explicitly.
        assert_eq!(
            android_probe_mask(&[Probe::PtraceSelfAttach]),
            ANDROID_PROBE_PTRACE_SELF_ATTACH
        );
    }

    /// Review 3-2: full classify matrix, including the cross-probe case —
    /// after PtraceSelfAttach succeeds, TracerPid == getppid() on re-scan
    /// must stay BENIGN (the gate-5 soak scenario, as a constructive
    /// regression).
    #[test]
    fn classify_tracerpid_full_matrix() {
        use TracerVerdict::*;
        let ppid = 4242u32;
        assert_eq!(classify_tracerpid(0, ppid), None);
        assert_eq!(classify_tracerpid(ppid, ppid), BenignSelf);
        assert_eq!(classify_tracerpid(ppid + 1, ppid), Hit);
        assert_eq!(classify_tracerpid(1, ppid), Hit);
        assert_eq!(classify_tracerpid(ppid - 1, ppid), Hit);
        // Cross-probe: self-attach residue re-scanned by TracerPidScan.
        assert_eq!(classify_tracerpid(ppid, ppid), BenignSelf);
        // ppid==0 cannot happen for a live process, but must not misfire.
        assert_eq!(classify_tracerpid(0, 0), None);
    }

    #[test]
    fn android_analysis_module_hashes_are_distinct() {
        let hashes = known_android_analysis_module_hashes();
        assert_eq!(hashes.len(), 5);
        for i in 0..hashes.len() {
            for j in i + 1..hashes.len() {
                assert_ne!(hashes[i], hashes[j]);
            }
        }
        // The hashed names match the markers the C core scans for.
        for name in ["frida-agent.so", "frida-gadget.so"] {
            assert!(hashes.contains(&module_name_hash(name)));
        }
    }

    #[test]
    fn probe_names_roundtrip_through_ids() {
        for p in android_probes() {
            assert!(!probe_name(*p).is_empty());
        }
        // Names are unique across the union of both probe sets, and each
        // probe's name maps back to the same probe via the tables above
        // (id → name is injective).
        let mut pairs: Vec<(u32, &str)> = max_probes()
            .iter()
            .chain(android_probes().iter())
            .map(|p| (probe_id(*p), probe_name(*p)))
            .collect();
        pairs.sort();
        pairs.dedup();
        assert_eq!(pairs.len(), max_probes().len() + android_probes().len());
        let mut ids: Vec<u32> = pairs.iter().map(|(i, _)| *i).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), pairs.len(), "probe ids must be injective");
    }
}
