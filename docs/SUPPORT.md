# Support matrix (product contract)

This file is the support contract for Xenolith. It records **what the
current tree actually packs** and **what a later production release must
cover**. It is not a marketing page. Claims that are not in this file or in
a CI gate that inspects a packed artifact are not claims.

## Current product (G0 baseline, 2026-09-07)

Xenolith is a **standalone binary packer**. It does not require source or
recompilation of the input. The object that actually runs on the target OS is the **PIC boot stub** plus
the freestanding `xl_core` object (`xenolith-runtime/core/xl_core.c`)
embedded in the stub section. The stub walks the PEB and resolves kernel32;
`xl_core_activate` authenticates EnvelopeV2 (ChaCha20-Poly1305) and copies
pages RW→RX. It writes VAs back into original IAT slots, restores stolen
entry bytes, and returns so the stub can jump to the original entry.

The following are **not** the product runtime:

| Crate / tool | What it is | What it is not |
| --- | --- | --- |
| `xenolith-pack` PIC stub + `xl_core.c` | Injected into the packed image. Product truth. | A full PE/ELF loader. |
| `xenolith-loader` | Host-side EnvelopeV2 parser and a test emulator. | Injected code. Not behavioral truth for a packed file. |
| `xenolith-runtime` rustc cdylib | A separate HKDF/XChaCha experiment with CRT imports. | Rejected by `runtime_image`; not injected. |
| `xenolith-runtime/core/xl_core.c` | Freestanding EnvelopeV2 + AEAD core, no CRT. | Linux platform split is G3. |
| `xenolith-vm` key-mix VM | Tiny opcode map used by the stub to rebuild MBA limbs. | The user-code VM. |
| `eval_ir` / superoperators | Pack-time compiler for **selected named exports**. | A shared bytecode ISA or a whole-`.text` virtualizer. |

### Platforms (current)

| Input | Pack | Load on target OS |
| --- | --- | --- |
| Windows AMD64 PE64 DLL | Yes | Yes, via system `LoadLibrary` (`GATE 3 OK result=Some(7)`) |
| Windows AMD64 PE64 EXE | Yes | Yes on this Windows host (`hello-exe` prints `xenolith-hello`); selected-export VM still needs a named export or `--select-rva` |
| Linux AMD64 ELF64 ET_DYN / ET_EXEC / .so | Yes — appends an R+X PT_LOAD (relocated PHDR table + PIC stub + `xl_core` + EnvelopeV2) and redirects INIT_ARRAY[0] to the stub; ld.so stays the loader (PIE/RELRO/GOT-PLT untouched) | Verified in WSL Ubuntu 24.04: packed `hello-elf` prints `xenolith-hello-elf`; packed `libhello-elf.so` dlopen/dlclose OK (`packed_elf_prints_hello`). PT_TLS, IFUNC, TLSDESC, copy reloc, static, RELATIVE-into-RX fail closed |
| ARM64, x86-32, macOS, Android | Rejected or unparsed | Out of scope for this version |
| .NET mixed-mode images (COM descriptor / CLR header, datadir 14 present) | **Rejected** with a named diagnostic | Out of scope for this version |
| CFG-instrumented images (`DllCharacteristics GUARD_CF` or load-config `GuardFlags` instrumented) | **Rejected** with a named diagnostic | The loader GuardCF-checks a CFG image's entry against GFIDS; the packed stub entry is not registered there and the process fast-fails (0xC0000409) at load. Rebuild without `/guard:cf`, or wait for GFIDS-aware packing |

Current `pack()` also:

- keeps `IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE` / `HIGH_ENTROPY_VA` and the relocation directory; the system loader applies ASLR. DIR64 that land in EnvelopeV2-protected pages are re-applied by `xl_core` after AEAD open
- keeps the TLS directory; the first TLS callback is wrapped so unpack runs before CRT TLS. Images with TLS callbacks also keep the disk import directory (`LoadLibraryA` is unsafe under the loader lock). Images without TLS still wipe the import directory on `standard`/`max`
- emits the stub section as **RX** (no long-term RWX); `xl_core` uses temporary RW then RX for payload pages
- does **not** re-encrypt executable pages after unpack (C2 keep-list is serialized, `l_reenc` is not jumped to)
- output suffix follows kind: `.xl.dll` / `.xl.exe` / `.xl.so` / `.xl.elf`

C++ exceptions, setjmp/longjmp, varargs, 8-byte struct returns and tail calls are verified through **packed** images on both OSes (`packed_eh_matrix`, `packed_elf_eh_matrix`); the injected stub carries synthesized unwind records (PE: XDATA + relocated .pdata with the stub RUNTIME_FUNCTION; ELF: appended .eh_frame + PT_GNU_EH_FRAME). Rust panic-unwind through a packed image is not separately frozen; On Linux, IFUNC (resolver pages stay native), symbol versions (DT_VERNEED/VERDEF preserved, dlvsym-verified) and initial-exec/local-dynamic TLS are supported packed; imported IFUNC, TLS descriptors, local-exec TPOFF32 and static linkage still fail closed.
TLS callback images keep the directory with the first callback wrapped by the stub; delay-load and ordinal-only imports are packed (see "Imports: delay-load and ordinal"). On ELF, executable PT_LOAD file bytes are 0x90-filled and sealed in EnvelopeV2, except the first 64 bytes at `e_entry` which stay original — glibc (2.39 verified) decodes an ~40-byte instruction window at the entry point and suppresses the whole init phase when it cannot; that window is the `_start` prologue, not protected logic. Linux IFUNC/TLS descriptor/copy reloc/PT_TLS still fail closed until stage 5. Those remaining gaps are defects relative to G3/G4, not features.

### ASLR / DIR64 pairing (current)

Packed images keep ASLR (`DYNAMIC_BASE` + reloc directory). The system loader
applies every DIR64 fixup at map time; `xl_core` then decrypts the protected
pages back to their **unrelocated** plaintext and re-applies the loader's
fixups for the slots that live inside protected pages. Two invariants make
that pairing hold (both sides are frozen by tests that pack and run a
delta≠0 ASLR image):

- **AAD pairing:** the packer authenticates the reloc-table byte length
  (`record count * 8`) in the region AAD tail (`aad[28..32]`,
  `xenolith_protocol::region_aad`); `xl_core` derives the same value from the
  envelope. A mismatch made every AEAD open fail for any image whose envelope
  carried at least one reloc record — the historical "ASLR EXE exits 0
  silently" defect.
- **Delta recovery:** the loader rewrites the in-memory
  `OptionalHeader.ImageBase` to the actual base while relocating, so the
  preferred base cannot be read back at runtime. `xl_core` instead recovers
  delta from the packer's disk invariant (protected page bodies are `0xCC`):
  before decrypting, each recorded slot holds `0xCCCC…CC + delta`; all
  recorded slots must agree, otherwise boot fails closed. After decrypt +
  re-apply, a recorded slot equals `original + delta` (verified: packed
  `xz` under ASLR, slot `base+0xce38 == base+0xcdb0`).

### Packed-image boot failure codes (PE EXE)

When the boot fails closed, a packed EXE exits with the failing stage so a
dead `rc=0, no output` names its cause. A packed DLL always returns 0
(`FALSE`) — a nonzero `DllMain` return would present a failed boot to the
loader as init success. The ELF stub keeps its existing fail-closed contract
(return success + `0xCC` trap pages at lowered gates); stages do not apply.

| Exit code | Stage | Meaning |
| --- | --- | --- |
| 0 | `STAGE_UNKNOWN` | Pre-core failure without a recorded stage (packer bug; report) |
| 1 | `STAGE_MAGIC` | Envelope signature mismatch |
| 2 | `STAGE_KERNEL32` | PEB walk found no kernel32 |
| 3 | `STAGE_EXPORT_DIR` | kernel32 export directory unusable |
| 4 | `STAGE_APIS` | `GetProcAddress` / `LoadLibraryA` / `VirtualProtect` unresolved |
| 5 | `STAGE_DEBUGGER` | An anti-debug probe fired (`max` profile) |
| 6 | `STAGE_CORE` | `xl_core_activate` failed (AEAD open, import resolution, reloc apply) |
| 7 | `STAGE_NO_CORE` | Stub emitted without a core image |
| 8 | `STAGE_OPCODE` | Unknown VM opcode (legacy no-core path) |
| 9 | `STAGE_DIGEST` | Page digest mismatch (tamper; legacy path) |
| 10 | `STAGE_PROTECT` | `VirtualProtect` failed |
| 11 | `STAGE_RESOLVE` | `LoadLibraryA` / `GetProcAddress` failed on an import |
| 12 | `STAGE_PE` | No PE signature at the image base |
| 13 | `STAGE_DLL_STATE` | DLL attach state not process-attach |

### Imports: delay-load and ordinal (current)

- **Delay-load imports (datadir 13) are packed as-is.** The PE64 loader
  ignores the delay directory; the application's own `__delayLoadHelper2`
  resolves lazily through the app's IAT (`LoadLibraryA` / `GetProcAddress`
  slots), which the packer fills exactly like every other import. The delay
  descriptors are plain data the packer never touches. Verified with a real
  12.7 MB `cargo.exe` (2249 protected pages, two delay descriptors, zero
  ordinals, no GUARD_CF): the packed image runs and `cargo --version` prints
  `cargo 1.95.0` with exit 0. If runtime evidence ever contradicts this, the
  fallback is per-mode rejection (writeback refuses, TLS-keep/fast allow) —
  never silent packing.
- **Ordinal-only imports are packed** and recorded under the reserved display
  name `#<decimal ordinal>` (e.g. `#116`). `#` at the start of an import
  name is a Xenolith-reserved prefix — a DLL can technically export a literal
  `#116` name, and such a collision would mis-bind, so the prefix is
  reserved and documented here. The writeback runtime detects the reserved
  prefix and resolves through `GetProcAddress`'s ordinal channel
  (`MAKEINTRESOURCE` semantics). Resolution failure fails the boot closed
  (`STAGE_CORE`). TLS-keep/fast images never reach this path (the system
  loader resolves their disk IAT natively).

### Functions (current)

`--vm-export` virtualizes **named exports you list**. Constraints, all fail-closed:

- export must exist; unknown names fail
- CRT / `DllMain` / leading-underscore names stay native
- `fast` profile rejects `--vm-export`
- lift window is `MAX_LIFT_BYTES` (256)
- memory, calls, RIP-relative, SEH, unfused flags, and spill fail the pack
- `eval_ir` is a Win64 32-bit wrapper around `MachineState` (RCX/RDX → EAX). 64-bit/`MachineState` exists; superop emission is still 32-bit GPR
- `--select-rva RVA:LEN`, `--select-function`, `--select-all`, `--strict-coverage` and `--allow-native-fallback` are wired; PDB/DWARF discovery is not
- PE function discovery covers named exports, COFF function symbols, and `.pdata` unwind boundaries (`fn_0x...`); `--select-all` is explicit opt-in
- memory / call / RIP-relative / indirect jmp still fail closed at lift time

Truth sample: `samples/license-toy` `check_license` (C, `/O1` or `-O1`, handwritten `DllMain`). `hello_add` only proves a straight-line block reaches the backend. If rustc and C disagree, **C wins**.

### JNI hosts (current)

JNI-shaped host images are a supported input form (JavaShroud adaptation): `samples/jni-host` packs and `LoadLibrary`es with `JNI_OnLoad` resolving and a pure arithmetic leaf executing through the packed image; the real JSIM-patched `qp_ffi.dll` verified the same shape end to end. `samples/jni-rust` is a rustc cdylib whose `JNI_OnLoad` requires a fake `JavaVM*` (`GetEnv` → `JNI_OK` + non-null env → `JNI_VERSION_1_8`, else `JNI_ERR`); tests call it after `LoadLibrary` and never pass `NULL,NULL`.

- `.jsms` / `.jsmk` / `.jsmd` are **input data sections**: preserved byte-identical on disk under every profile (never sealed, never `0xCC` — the packer only seals `IMAGE_SCN_MEM_EXECUTE` pages). They stay forbidden as names for the injected stub/payload sections. C3 may scramble the **in-memory** section table after unpack; disk `PointerToRawData` lookup must still find the original names and bytes.
- Exports named `JNI_OnLoad` or `qp_r1_*` force `keep_import_directory` (`disk-import-directory`) even without TLS and even on `standard`/`max`.
- JVM/CRT ABI names refuse `--vm-export` **before** existence is checked: `DllMain`, `*crt*`, leading `_`, plus `JNI_OnLoad`, `JNI_OnUnload`, `Java_*`, `qp_r1_*`. The whole-image pack still runs (export pages stay in the keep set; JNI exports are never thunks).
- `inspect` does not reject images that merely carry JS measurement sections; foreign packer section names (UPX*/.packed/...) still refuse.
- ELF: the dynsym extent now comes from `DT_HASH` nchain / `DT_GNU_HASH` (the old "dynsym runs to dynstr" bound decoded `.gnu.version` padding as symbols and false-positived an imported-IFUNC rejection on real cdylibs).
- ELF: a dynamic table with `DT_INIT_ARRAY` but a mis-tagged `DT_INIT_ARRAYSZ` (emitted as `DT_FINI_ARRAY` by some linker emulations) fails closed with a named diagnostic: that image's `INIT_ARRAY[0]` never ran, so packing must not synthesize the size and activate it.

Internal PE functions are discoverable through `--select-all` / `.pdata` and can be rewritten when their semantics fit the current lift matrix. 64-bit data, more than two arguments, indirect calls, function pointers, recursion, jump tables, and unsupported float/vector forms remain **fail-closed**; with `--allow-native-fallback` they are reported as `mixed_native` and are never counted as protected. ELF symbol selection is report-only in this release and requires the same fallback flag.

### Imports, dump, kernel (current)

- **IAT (current):** on `standard`/`max`, the on-disk import directory RVA is 0 **unless** TLS bootstrap or a `JNI_OnLoad` / `qp_r1_*` export forces `keep_import_directory`. The PIC stub still writes resolved VAs into the original IAT slots so CRT `DllMain` can run when the directory was wiped. That is `hashed-resolve-writeback-iat`, not "hashed-runtime" and not "never write FirstThunk". `fast` always keeps the disk import directory (`disk-import-directory`).
- **Linux GOT/PLT:** not implemented.
- **Anti-dump (current):** EnvelopeV2 AEAD on disk; on-disk executable pages are `0xCC` traps. After unpack, executable pages stay plaintext. A paused process with process access can read the current page. This is **not** a decryption window and **not** "cannot dump". Section-table scramble is no longer a production default.
- **Kernel:** no driver, no LSM policy, no `KernelAssistMode`. Off by absence.

### Profiles (current)

| Profile | What it actually does |
| --- | --- |
| `fast` | Mutation + XOR page encryption; keeps disk import directory; rejects `--vm-export` |
| `standard` | + hashed import names in the envelope, stolen entry bytes, keyed FNV |
| `max` | + extra stub probes (PEB/NtQuery/HideFromDebugger). Does not arm C2. |

Wired CLI / project / TUI surface: `input`, `output`, `profile`, `vm_exports`, `trace_diverge`, `select_rva`, `strict_coverage`, `lazy_regions`, `protect_imports`, `strict_constants`, plus optional `--seed-hex` (never printed). The TUI exposes the same six switches (profile, trace-diverge, lazy-regions, protect-imports, strict-constants, strict-coverage), accepts PE/ELF inputs and project files, and keeps `select_rva` read-only passthrough from projects. Unknown project keys fail closed. `--keep-export` is hidden and fails closed (C2 unarmed).

## Production target (`user-mode-full`, 2026-09-15)

This is the binding release target for the current work branch. Until every
row below has real packed-artifact evidence, builds remain RC/engineering;
the "current" sections above are not silently promoted.

The first production version, if and only if G0–G8 in the architecture plan pass, must cover:

| Axis | Required |
| --- | --- |
| Platform | AMD64 Windows PE64 EXE/DLL **and** Linux ELF64 PIE / non-PIE executables and shared libraries. Default matrix: Windows 11, Windows Server 2022/2025, Ubuntu 22.04/24.04, Debian 12. |
| Functions | Internal functions, integer/memory/stack, direct and indirect calls, function pointers, recursion, jump tables, plus the stage-5 exception/thread/float/vector set. Not "named exports only" and not "two u32 leaf functions only". |
| Selection | Export, symbol, PDB/DWARF, unwind metadata, or explicit address range. Uncertain boundaries are reported, never guessed. |
| Honesty | Report `transformed` / `mixed_native` / `unsupported` / `boundary_uncertain`. Strict mode fails the pack if the requested level is not met. Compatibility fallback must not count native leftovers as obfuscated. |
| Production load | System loader, ASLR/PIE, W^X, TLS, imports/dynamic linking, unwind info usable. Unimplemented semantics fail closed. Do not disable ASLR, DEP/NX, W^X, CFG/CET, or RELRO to gain compatibility. Current status: ASLR/PIE packed images re-apply DIR64 fixups on decrypted pages (see the ASLR/DIR64 pairing section). CFG/CET-instrumented images are refused at pack time (the packed entry is not in GFIDS); disabling the guard bit is explicitly out of scope. |
| Imports | Windows IAT and Linux GOT/PLT are separate models. Do not mix them. Do not promise that every loader-required name is deleted, or that the target of an API call is unobservable at the call instant. |
| Residency | Protected code does not remain as complete original plaintext long-term; dormant regions do not leak plaintext. The currently executing region remains observable. |
| Kernel | Optional signed / supported access control: `off` / `optional` / `required`. Not "move the user program into the kernel". Not resistance to a malicious kernel or hypervisor. |
| Architecture | Default remains per-function / per-region unique superoperator native code. A shared bytecode table plus central dispatcher is forbidden as the default product. |

ARM64, 32-bit x86, Android, and macOS are **not** completion criteria for this version.

## Fail-closed rules

- Unknown input, unsupported semantics, uncertain boundaries: default **strict failure**. No silent downgrade.
- Unwired switches do not appear in `--help`, TUI, or the project schema.
- Missing samples, un-run subprocesses, or missing required tools in tests are **failure or blocked**, never a pass.
- `cargo test --workspace --exclude xenolith-runtime` does not verify the runtime crate. Exclusion exists because unifying `std` into that `no_std` `#[panic_handler]` crate is E0152.
- Host emulator success is not OS-load success.
- Linux hosts must not treat skipped `cfg(windows)` load tests as a pass.
