//! Runtime anti-debug / anti-dump policy.
//!
//! Host-side code records which probes a packed image will run. The actual
//! syscalls live in the injected PIC stub (`xenolith-pack::stub`). This
//! crate is the policy surface so tests can assert forbidden techniques stay
//! absent. `xenolith-loader` does not execute these probes.

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
}
