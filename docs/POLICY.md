# Xenolith policy

## Allowed in this repository (injected PIC stub / `xenolith-guard` policy)

The syscalls listed here are emitted by `crates/xenolith-pack/src/stub.rs`.
`xenolith-guard` only records which probes a profile selected.
`xenolith-loader` does not run them. `xenolith-runtime` is not in the image.

- Direct syscalls for debug-port / debug-object / PEB `BeingDebugged`
- `NtSetInformationThread(ThreadHideFromDebugger)` on the current thread
- Clearing `ProcessInstrumentationCallback` for the current process
- Redirecting `DbgUiRemoteBreakin` **inside the packed image only**
- Hardware-breakpoint / trap-flag checks are **policy-listed only**; the PIC stub does not `mov drN` (privileged in user mode)
- INT3 / `0xCC` scans of critical ntdll text
- TLS-callback early probes
- Read-only mapping of on-disk ntdll for integrity compare
- Timing checks around decryption
- In-place XOR decrypt, keyed FNV page digest, in-memory section-table scramble, `SizeOfImage` lie. Executable-page C2 is **not** armed (sample `.text` is live end-to-end)
- Fail-closed load (`DllMain` FALSE / process exit) after a hit

Host HMAC page MACs are computed at pack time. The PIC stub does not compute SHA-256 HMAC.

G-DBG / G-FRIDA / G-RPM probes exist on profile `max`. CI does not attach a debugger, spawn Frida, or exercise RPM.

## Forbidden

- Killing other processes
- Injecting into other processes
- Patching on-disk `ntdll.dll`
- Unloading or attacking EDR products
- Destructive payloads unrelated to refusing to run
- Shipping a contiguous 32-byte master key or a `SHA-256(id || public ASCII label)` wrap

## JavaShroud

JavaShroud-public product code keeps its own bans. If JavaShroud calls Xenolith, it must spawn the CLI, not link these crates. The `.jsms` / `.jsmk` / `.jsmd` section names are the host's measurement data — they are preserved as inputs and must never be reused as injected stub/payload names.

## IAT (C1)

On `standard`/`max` without TLS and without `JNI_OnLoad` / `qp_r1_*` exports, the on-disk import directory RVA is 0. At unpack the PIC stub still writes resolved VAs into the original IAT slots so CRT `DllMain` can run. That is a Scylla write-breakpoint residual, not "never write FirstThunk". JNI / Qp bridge hosts keep the disk import directory so the system loader fills the IAT before those exports run.
