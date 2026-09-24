//! PE mutation and envelope writer.

pub mod analysis;
pub mod protect;
pub mod stats;
pub mod unwind;
pub mod lift;
pub mod platform;
pub mod runtime_image;
pub mod selection;
pub mod stub;

pub use stub::{emit_pic_stub, emit_pic_stub_with_guest, GuestEmit, PicStub, STUB_META_LEN};
pub use lift::{forbidden_vm_name, lift_export, lift_function, LiftError, LiftedExport};
pub use selection::{FunctionSelector, SelectError};

use analysis::function_map::BoundarySource;
use xenolith_crypto::{
    api_hash, image_measurement, random_nonce12, random_seed16, MbaKeyShare, Secret32, PAGE_SIZE,
};
use xenolith_protocol::{
    encode as encode_v2, seal_region, EnvelopeV2, FLAG_IMPORTS_SEALED, PLATFORM_PE64,
    POLICY_STRICT,
};
use xenolith_formats::{
    align_up, classify, write_u64, FormatError, ImageKind, LoadConfigCfg, Pe64, Section,
    IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR,
    IMAGE_DIRECTORY_ENTRY_DEBUG, IMAGE_DIRECTORY_ENTRY_EXCEPTION,
    IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_DIRECTORY_ENTRY_SECURITY,
    IMAGE_DIRECTORY_ENTRY_TLS, IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE,
    IMAGE_DLLCHARACTERISTICS_GUARD_CF, IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA,
    IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT, IMAGE_GUARD_XFG_ENABLED,
    IMAGE_REL_BASED_DIR64, IMAGE_SCN_CNT_CODE,
    IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE,
};
use xenolith_guard::{max_probes, Probe};
use xenolith_loader::{
    section_name_from_seed, steal_entry_bytes, HashedImport, PackedImage, PageRecord, Profile,
    STOLEN_BYTES,
};
use xenolith_vm::{emit_superop_ex, OpcodeMap, Program, SuperopOptions};
use rand::{rngs::OsRng, RngCore};
use serde::Serialize;
use thiserror::Error;
use stub::{
    META_ENVELOPE_LEN, META_MEASUREMENT, META_ORIGINAL_ENTRY, META_PAYLOAD_RVA, META_TLS_CALLBACK,
    META_UNPACKED,
};

#[derive(Debug, Error)]
pub enum PackError {
    #[error(transparent)]
    Format(#[from] FormatError),
    #[error("{0}")]
    Invalid(&'static str),
    #[error("{0}")]
    Stub(String),
    #[error("{0}")]
    Lift(String),
    #[error("ELF cannot be packed: {0}")]
    Elf(&'static str),
    #[error("{0}")]
    Runtime(String),
    #[error("{0}")]
    Protocol(String),
    #[error("{0}")]
    DataProtection(String),
}

impl From<xenolith_protocol::ProtocolError> for PackError {
    fn from(e: xenolith_protocol::ProtocolError) -> Self {
        PackError::Protocol(e.to_string())
    }
}

/// Version of the capability report. Bump when fields change meaning.
pub const PACK_REPORT_VERSION: u32 = 1;

/// Injected product runtime: PIC boot bridge + freestanding xl_core.
/// `xenolith-loader` and the rustc `xenolith-runtime` cdylib are never this.
pub const BACKEND_PIC_STUB: &str = "pic-stub+xl-core";

#[derive(Clone, Debug, Serialize)]
pub struct FunctionCoverageRecord {
    pub name: String,
    pub rva: u32,
    pub len: Option<u32>,
    pub source: BoundarySource,
    pub bucket: String,
    pub reason: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct PackReport {
    pub report_version: u32,
    pub profile: String,
    pub format: String,
    /// TASK-038: on-disk sizes feeding the G8 size budget (output/input).
    pub input_bytes: usize,
    pub output_bytes: usize,
    /// What `pack()` actually injected. Not the host emulator and not the
    /// unused `xenolith-runtime` crate.
    pub backend: String,
    pub export_surface: Vec<String>,
    /// `disk-import-directory` (fast) or `hashed-resolve-writeback-iat`
    /// (standard/max). Never the aspirational `hashed-runtime`.
    pub iat_mode: String,
    /// True only when dormant executable pages are re-encrypted after unpack.
    /// Current PIC stub leaves pages plaintext; this is false.
    pub runtime_decryption_window: bool,
    pub c2_reencrypt: bool,
    pub aslr: bool,
    pub high_entropy_va: bool,
    pub reloc_directory: bool,
    pub tls_directory: bool,
    pub long_term_rwx: bool,
    pub seed_len: usize,
    pub pages: usize,
    pub stolen_bytes: usize,
    pub vm_functions: usize,
    pub selected_functions: Vec<String>,
    /// Per-function disposition. `mixed_native` is never counted as
    /// protected and is only legal when `allow_native_fallback` was set.
    pub coverage: Vec<FunctionCoverageRecord>,
    pub strict_coverage: bool,
    pub allow_native_fallback: bool,
    /// TASK-024: envelope import names are sealed (writeback mode only).
    pub import_names_sealed: bool,
    /// TASK-024: per-import disposition. Counts only — never the names: a
    /// report sitting next to the artifact must not undo the sealing.
    pub imports_protected: usize,
    pub imports_kept: usize,
    /// Why imports stayed on disk (e.g. "tls-bootstrap-needs-loader-iat"
    /// or "jni-abi-needs-loader-iat").
    pub imports_kept_reason: String,
    /// TASK-025: read-only constant census. `constants_encrypted` is always
    /// 0 until the lift matrix covers data references (reads would need
    /// decrypt-on-access interposition).
    pub constants_candidates: usize,
    pub constants_protectable: usize,
    pub constants_encrypted: usize,
    pub constants_native_referenced: usize,
    pub notes: Vec<String>,
}

fn iat_mode_for_profile(profile: Profile, keep_import_directory: bool) -> &'static str {
    if keep_import_directory || profile == Profile::Fast {
        "disk-import-directory"
    } else {
        "hashed-resolve-writeback-iat"
    }
}

/// JVM / Qp bridge exports that need the system loader to fill the disk IAT
/// before `JNI_OnLoad` / `qp_r1_*` run. Without TLS this still forces
/// `keep_import_directory` so hashed writeback is not the only path.
fn needs_disk_iat_export(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n == "jni_onload" || n.starts_with("qp_r1_")
}

fn disk_iat_keep_reason(tls: bool, jni_abi: bool) -> String {
    if tls {
        "tls-bootstrap-needs-loader-iat".into()
    } else if jni_abi {
        "jni-abi-needs-loader-iat".into()
    } else {
        String::new()
    }
}

pub struct PackRequest<'a> {
    pub input: &'a [u8],
    pub profile: Profile,
    pub vm_exports: Vec<String>,
    /// Stub phase gate for loader debugging: 0 map-only, 1 +PEB/APIs,
    /// 2 +pages, 3 full unpack. Production packs always use 3.
    pub debug_gate: u8,
    /// Optional 16-byte opcode/PIC seed (G-POLY reproduction). `None` = OsRng.
    /// Never printed in reports.
    pub opcode_seed: Option<[u8; 16]>,
    /// W3: two semantically equal paths per block. Default false (W2).
    pub trace_diverge: bool,
    /// Explicit RVA+length selections (G2). Empty = export-only.
    pub select_rva: Vec<(u32, u32)>,
    /// Function/symbol names from export/COFF/DWARF/unwind discovery.
    pub select_functions: Vec<String>,
    /// Explicit whole-image discovery. Without this flag, discovery is never
    /// implicitly applied to every function.
    pub select_all: bool,
    /// Strict coverage: empty selection fails the pack.
    pub strict_coverage: bool,
    /// Permit selected functions that cannot be fully transformed to remain
    /// native. Such functions are reported as mixed_native.
    pub allow_native_fallback: bool,
    /// G5/TASK-026: seal non-keep regions at bootstrap and decrypt on
    /// execution fault (VEH wake). Residency matrix, tamper rejection,
    /// 10k load/unload, and EH suites are green; stays opt-in.
    pub lazy_regions: bool,
    /// G5/TASK-024: seal import name records in the envelope with the boot
    /// runtime key. Only applies in writeback mode (no on-disk import
    /// directory): a retained loader directory keeps plaintext names, and
    /// the report says so instead of pretending.
    pub protect_imports: bool,
    /// G5/TASK-025: refuse to pack when read-only constants still have
    /// unresolved native references (strict data protection). Nothing is
    /// scan-replaced without a complete reference proof.
    pub strict_constants: bool,
}

pub struct PackOutput {
    pub image: Vec<u8>,
    pub report: PackReport,
    pub packed: PackedImage,
}

pub fn pack(request: PackRequest<'_>) -> Result<PackOutput, PackError> {
    if request.strict_coverage && request.allow_native_fallback {
        return Err(PackError::Invalid(
            "strict-coverage and allow-native-fallback are mutually exclusive",
        ));
    }
    let kind = match classify(request.input) {
        Ok(ImageKind::Elf64Exec | ImageKind::Elf64Dyn) => {
            return platform::pack_elf(&request);
        }
        Ok(k) => k,
        Err(FormatError::ElfNotImplemented) => return Err(PackError::Elf("unsupported ELF kind")),
        Err(e) => return Err(PackError::Format(e)),
    };
    // Header-slack injection: pack() appends TWO section headers (stub +
    // payload). Tight MSVC layouts end the section table exactly at
    // SizeOfHeaders, leaving no room; instead of rejecting the image, grow
    // the header block by inserting a FileAlignment-sized hole before the
    // first raw data and re-enter pack() on the shifted image so every
    // downstream offset (entry steal, imports, relocs, pdata, envelope) is
    // computed on the shifted bytes consistently. See inject_header_slack.
    if matches!(kind, ImageKind::Pe64Dll | ImageKind::Pe64Exe) {
        if let Some(shifted) = inject_header_slack(request.input)? {
            let PackRequest {
                input: _,
                profile,
                vm_exports,
                debug_gate,
                opcode_seed,
                trace_diverge,
                select_rva,
                select_functions,
                select_all,
                strict_coverage,
                allow_native_fallback,
                lazy_regions,
                protect_imports,
                strict_constants,
            } = request;
            return pack(PackRequest {
                input: &shifted,
                profile,
                vm_exports,
                debug_gate,
                opcode_seed,
                trace_diverge,
                select_rva,
                select_functions,
                select_all,
                strict_coverage,
                allow_native_fallback,
                lazy_regions,
                protect_imports,
                strict_constants,
            });
        }
    }
    let pe = Pe64::parse(request.input)?;
    if is_already_packed(&pe, request.input) {
        return Err(PackError::Invalid(
            "input is already packed (xenolith pic-stub+xl-core envelope detected); \
             re-packing a packed image is not supported — pack the original \
             unpacked build instead",
        ));
    }
    // Delay-load imports: the PE64 loader ignores the delay directory
    // (datadir 13) — the application's own __delayLoadHelper2 resolves it at
    // first call through the app's IAT (LoadLibraryA/GetProcAddress slots).
    // Those slots are filled exactly like every other import (the system
    // loader keeps the disk IAT in TLS/Fast mode; xl_core writeback fills
    // them otherwise), and the delay descriptors themselves are plain data
    // the packer never touches, relocated like any other pointer. Rejecting
    // here only blocked whole images on a mechanism that works. If runtime
    // evidence contradicts this, the fallback is per-mode rejection
    // (writeback refuses, TLS-keep/fast allow) — never silent packing.
    // .NET mixed-mode images (COM descriptor / CLR runtime header present)
    // rely on the runtime host for entry, unwinding, and metadata tokens —
    // none of which survive repacking. Fail closed with the specific check
    // and construction named.
    if pe
        .directory(IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR)
        .map(|d| d.rva != 0 && d.size != 0)
        .unwrap_or(false)
    {
        return Err(PackError::Invalid(
            ".NET mixed-mode image (COM descriptor present) is not packed in this release; \
             pack a native build of the same code instead",
        ));
    }

    // Entry-less images (AddressOfEntryPoint == 0). Two shapes exist:
    //
    // 1. Resource-only DLLs (e.g. MSORES-class): no entry, no executable
    //    section, no exports. The loader never calls anything, so there is
    //    nothing to seal and nothing that could ever run the stub. These
    //    pack structurally (envelope with 0 regions, entry stays 0) and a
    //    vacuous GUARD_CF DllCharacteristics bit — set by blanket build
    //    flags while the image ships no load-config/GFIDS and contains no
    //    code — is cleared: nothing CFG-shaped can be enforced for code
    //    that does not exist, and the OS itself loads this exact shape.
    // 2. Entry-less images that DO carry executable code or exports: the
    //    stub would never be invoked (nothing calls an entry that does not
    //    exist), sealed pages could never decrypt, and repointed exports
    //    would never initialize. Fail closed with the construction named.
    let no_exec_sections = pe
        .sections
        .iter()
        .all(|s| s.characteristics & IMAGE_SCN_MEM_EXECUTE == 0);
    if pe.entry_rva == 0 && !no_exec_sections {
        return Err(PackError::Invalid(
            "entry-less image (AddressOfEntryPoint == 0) still carries executable sections: \
             nothing would ever invoke the packed stub, so sealed pages could never decrypt — \
             this shape is refused instead of silently broken",
        ));
    }
    let entryless_exports = if pe.entry_rva == 0 {
        let exports = pe.exports(request.input)?;
        if !exports.is_empty() {
            return Err(PackError::Invalid(
                "entry-less image (AddressOfEntryPoint == 0) has exports: the stub cannot \
                 initialize without an entry, so repointed exports would never resolve — \
                 this shape is refused instead of silently broken",
            ));
        }
        true
    } else {
        false
    };
    let entryless = pe.entry_rva == 0 && entryless_exports;

    // CFG: the loader invokes a GUARD_CF image's entry (and later any
    // export-repointed stub thunk) through the GuardCF indirect-call check.
    // Those RVAs must be in the on-disk GFIDS table or the process fast-fails
    // (0xC0000409) at load — before a single unpacked byte executes. Parse the
    // load-config now so every fail-closed case names the construction; the
    // table itself is rewritten after the stub/payload RVAs are known.
    // Entry-less images skip CFG work entirely: their entry is never invoked,
    // so no GuardCF check can fire, and the vacuous GUARD_CF bit is cleared
    // below (an entry-less image with a real GFIDS-carrying load config is
    // still cleared: the table protects code that does not exist).
    let cfg_plan = if entryless {
        None
    } else {
        plan_cfg_rewrite(&pe, request.input)?
    };
    let mut working = request.input.to_vec();
    pe.zero_directory(&mut working, IMAGE_DIRECTORY_ENTRY_DEBUG)?;
    // Stale Authenticode, uniformly on every PE repack path. Any repack
    // invalidates the signature (sealed pages, rewritten headers, appended
    // stub/payload all change the digest it covers), and unlike every other
    // directory the SECURITY VA is an absolute FILE OFFSET — after the
    // header-slack shift it points at moved bytes. A nonzero entry would
    // make loaders/verifiers treat the packed output as signed-and-invalid.
    // This covers fast/standard/max, entryless, and the header-slack
    // re-entry (which zeroes it again after shifting raw data), so no
    // packed image ever claims to be signed.
    pe.zero_directory(&mut working, IMAGE_DIRECTORY_ENTRY_SECURITY)?;
    if entryless && pe.dll_characteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF != 0 {
        pe.set_dll_characteristics(
            &mut working,
            pe.dll_characteristics & !IMAGE_DLLCHARACTERISTICS_GUARD_CF,
        )?;
    }
    let tls_first = pe.tls_first_callback(request.input)?;
    // Entry-less + TLS CALLBACKS: fail closed (review: the combination was
    // previously undefined — the generic TLS-wrap path below would have
    // repointed the first callback slot at the stub trampoline).
    //
    // Why refuse instead of support: the loader invokes TLS callbacks before
    // any entry, but an entry-less pack seals 0 pages and keeps
    // AddressOfEntryPoint == 0 — there is no boot path that could ever run
    // the packed stub, so the trampoline would bootstrap outside every
    // invariant it was built for and then chain into the ORIGINAL callback,
    // which by the no-executable-sections check above lives in non-executable
    // memory: a guaranteed fault under the loader lock. Leaving the callback
    // untouched is no better — unanalyzed code would run from an image whose
    // packer assumed nothing ever executes. Real resource-only DLLs never
    // carry this shape: a genuine TLS callback body needs an executable
    // section, which the check above already refuses. What remains is
    // hand-built or corrupt input — refuse it by name.
    if entryless && tls_first.is_some() {
        return Err(PackError::Invalid(
            "entry-less image (AddressOfEntryPoint == 0) carries TLS callbacks: the loader \
             invokes TLS callbacks before any entry, and with no entry the packed stub can \
             never bootstrap, so the callback would either fault in non-executable memory \
             or run unvirtualized — this shape is refused instead of silently broken; \
             give the image an entry point or drop the TLS callbacks",
        ));
    }
    // Entry-less + TLS directory WITHOUT callbacks: fully defined and
    // supported. The directory is pure data — the loader allocates the TLS
    // block from StartAddressOfRawData/SizeOfZeroFill and never calls
    // anything — and entry-less packs seal no pages, so the directory and
    // its callback list survive byte-identical in the output.
    // TLS callbacks run before the packed entry. Keep the directory and wrap
    // the first callback so CRT TLS sees decrypted pages. LoadLibraryA is
    // unsafe under the loader lock, so those images also keep the disk IAT.
    if !request.vm_exports.is_empty() && request.profile == Profile::Fast {
        return Err(PackError::Invalid("vm-export requires standard or max"));
    }

    let secret = Secret32::random();
    let opcode_seed = request.opcode_seed.unwrap_or_else(random_seed16);
    let api_salt = random_seed16();
    let mba = MbaKeyShare::split(&secret, &opcode_seed);
    let map = OpcodeMap::from_seed(&opcode_seed);
    let program = Program::encode_key_mix(map, &mba);

    let exports = pe.exports(request.input)?;
    let export_names: Vec<String> = exports.iter().map(|e| e.name.clone()).collect();
    let jni_abi_disk_iat = exports.iter().any(|e| needs_disk_iat_export(&e.name));
    // Keep IAT slots in memory for the runtime to fill. Wipe the import
    // *directory* so the disk image has no DLL/name window (A3/C1), except
    // when TLS callbacks need the system loader to fill the IAT first, or when
    // JNI / qp_r1_* exports require a disk import directory even without TLS.
    let keep_import_directory =
        request.profile == Profile::Fast || tls_first.is_some() || jni_abi_disk_iat;
    if !keep_import_directory {
        pe.zero_directory(&mut working, IMAGE_DIRECTORY_ENTRY_IMPORT)?;
    }
    // G3: keep DYNAMIC_BASE / HIGH_ENTROPY_VA and the reloc directory so the
    // system loader applies ASLR. Relocs that land in protected pages are
    // re-applied by xl_core after AEAD open.

    // Entry-less images have no entry bytes to steal and no entry site to
    // trap; RVA 0 maps onto the DOS header and must never be touched.
    let (stolen, entry_off) = if entryless {
        (Vec::new(), 0usize)
    } else {
        let stolen = steal_entry_bytes(&working, &pe)
            .map_err(|e| PackError::Stub(format!("entry stolen-bytes read failed: {e}")))?;
        let entry_off = pe.file_offset_of(pe.entry_rva).map_err(|_| {
            PackError::Stub(format!(
                "entry rva {:#x} does not map to file data; cannot plant stolen-byte traps",
                pe.entry_rva
            ))
        })?;
        (stolen, entry_off as usize)
    };
    for i in 0..stolen.len().min(STOLEN_BYTES) {
        if entry_off + i < working.len() {
            working[entry_off + i] = 0xCC; // trap if executed without stub
        }
    }

    let imports = pe.imports(request.input)?;
    // Ordinal imports carry no name string. They are recorded under the
    // reserved display name "#<decimal ordinal>" so the writeback runtime can
    // resolve them through GetProcAddress's ordinal channel ('#' is the
    // reserved prefix, documented in docs/SUPPORT.md). The envelope record,
    // the hash, and the TASK-024 sealed name||dll payload all use the same
    // display name — no protocol change.
    let hashed: Vec<HashedImport> = imports
        .iter()
        .map(|imp| {
            let display_name = match imp.ordinal {
                Some(ord) => format!("#{ord}"),
                None => imp.name.clone(),
            };
            HashedImport {
                hash: api_hash(&imp.dll, &display_name, &api_salt),
                original_iat_rva: imp.iat_rva,
                dll: imp.dll.clone(),
                name: display_name,
            }
        })
        .collect();

    // The JVM/CRT ABI contract precedes existence: a forbidden name must
    // answer "stays native" whether or not the export exists. Missing names
    // are NOT pre-checked against the export table alone — COFF symbols and
    // fn_{rva:#x} unwind names are valid selections, and selection::resolve
    // reports them by name.
    for name in &request.vm_exports {
        if let Some(rule) = lift::forbidden_vm_rule(name) {
            return Err(PackError::Lift(format!(
                "vm-export {name}: stays native ({rule}); CRT/DllMain/JNI ABI exports must \
                 stay native — pick another export"
            )));
        }
    }

    let selector = FunctionSelector {
        exports: request.vm_exports.clone(),
        ranges: request.select_rva.clone(),
        functions: request.select_functions.clone(),
        select_all: request.select_all,
        strict: request.strict_coverage,
    };
    if selector.strict && selector.is_empty() {
        return Err(PackError::Invalid("strict coverage: no functions selected"));
    }
    let fn_map = selector
        .resolve(&pe, request.input)
        .map_err(|e| PackError::Lift(e.to_string()))?;
    let mut lifted: Vec<LiftedExport> = Vec::new();
    let mut coverage: Vec<FunctionCoverageRecord> = Vec::new();
    for func in &fn_map.functions {
        match lift_function(
            &pe,
            request.input,
            &func.name,
            func.rva,
            func.len,
            // Explicit --select-rva windows are the user's exact boundary;
            // everything else (named exports etc.) may sit on an
            // incremental-link thunk that needs resolving first.
            !matches!(func.source, BoundarySource::ExplicitRange),
        ) {
            Ok(function) => {
                coverage.push(FunctionCoverageRecord {
                    name: func.name.clone(),
                    rva: func.rva,
                    len: func.len,
                    source: func.source,
                    bucket: "transformed".into(),
                    reason: String::new(),
                });
                lifted.push(function);
            }
            Err(e) if request.allow_native_fallback && !request.strict_coverage => {
                coverage.push(FunctionCoverageRecord {
                    name: func.name.clone(),
                    rva: func.rva,
                    len: func.len,
                    source: func.source,
                    bucket: if e.0.contains("boundary")
                        || e.0.contains("out of lift window")
                        || e.0.contains("lift cap")
                        || e.0.contains("branch out of lift window")
                    {
                        "boundary_uncertain".into()
                    } else {
                        "mixed_native".into()
                    },
                    // Full reason, not just the first line: the reason text
                    // carries the function/RVA/remediation context.
                    reason: e.0.clone(),
                });
            }
            Err(e) => return Err(PackError::Lift(e.0)),
        }
    }
    if request.strict_coverage {
        let failed: Vec<&FunctionCoverageRecord> = coverage
            .iter()
            .filter(|record| record.bucket != "transformed")
            .collect();
        if !failed.is_empty() {
            let detail = failed
                .iter()
                .map(|r| {
                    format!(
                        "  {} (rva {:#x}, {}): {}",
                        r.name,
                        r.rva,
                        r.bucket,
                        r.reason.lines().next().unwrap_or("unknown reason")
                    )
                })
                .collect::<Vec<_>>()
                .join("\n");
            return Err(PackError::Lift(format!(
                "strict coverage: {} selected function(s) did not fully transform \
                 (drop --strict-coverage, use --allow-native-fallback, or pick functions \
                 the lifter supports):\n{detail}",
                failed.len()
            )));
        }
    }
    let mut functions = Vec::new();
    for (i, func) in lifted.iter().enumerate() {
        let mut block_seed = opcode_seed;
        block_seed[0] ^= (i as u8).wrapping_add(1);
        functions.push(
            emit_superop_ex(
                &func.ir,
                &block_seed,
                SuperopOptions {
                    trace_diverge: request.trace_diverge,
                },
            )
            .map_err(|e| {
                PackError::Stub(format!(
                    "vm {name} (rva {rva:#x}): {e}",
                    name = func.name,
                    rva = func.rva
                ))
            })?,
        );
    }
    let guest_emit = GuestEmit { functions };
    let core_img = runtime_image::load_builtin()
        .map_err(|e| PackError::Runtime(e.to_string()))?;
    let is_dll = matches!(kind, ImageKind::Pe64Dll);
    let pic = stub::emit_pic_stub_with_core_g5(
        &opcode_seed,
        &guest_emit,
        &core_img.text,
        core_img.entry_off,
        stub::CoreEntryPoints {
            fault_off: core_img.fault_off,
            quiesce_off: core_img.quiesce_off,
            state: if request.lazy_regions {
                core_img.state.clone()
            } else {
                Vec::new()
            },
            enabled: request.lazy_regions,
        },
        is_dll,
        !keep_import_directory,
    )
    .map_err(PackError::Stub)?;
    if lifted.len() != pic.guest_thunk_offs.len() {
        return Err(PackError::Stub(format!(
            "guest thunk count mismatch: {} lifted functions but the stub emitted {} \
             thunks (packer bug; report with the input image)",
            lifted.len(),
            pic.guest_thunk_offs.len()
        )));
    }
    let last_for_va = pe.sections.last().ok_or_else(|| {
        PackError::Stub(format!(
            "image has no sections ({} bytes, {} headers); cannot place the stub",
            request.input.len(),
            pe.number_of_sections
        ))
    })?;
    let stub_va = align_up(
        last_for_va.virtual_address + last_for_va.virtual_size.max(last_for_va.raw_size),
        pe.section_align,
    );
    for (func, thunk_off) in lifted.iter().zip(&pic.guest_thunk_offs) {
        rewrite_function(&pe, &mut working, func, stub_va.wrapping_add(*thunk_off))?;
    }

    // Pages the system loader may execute before xl_core opens AEAD:
    // original AddressOfEntryPoint (stolen-byte restore still needs it in
    // keep), CFG check/dispatch gadgets (`ret 0` / `jmp rax` in .text), and
    // the `fothk` forwarder section. Sealing any of these plants INT3s on
    // the pre-entry GuardCF path.
    let mut cfg_live_pages: std::collections::BTreeSet<u32> = std::collections::BTreeSet::new();
    if let Some(plan) = &cfg_plan {
        for (slot, what) in [
            (
                plan.cfg.check_function_slot_va,
                "GuardCFCheckFunctionPointer",
            ),
            (
                plan.cfg.dispatch_function_slot_va,
                "GuardCFDispatchFunctionPointer",
            ),
        ] {
            if let Some(rva) = pe.load_config_guard_target_rva(request.input, slot, what)? {
                cfg_live_pages.insert(rva & !0xfff);
            }
        }
    }
    for section in &pe.sections {
        if is_cfg_forwarder_section(&section.name_str()) {
            cfg_live_pages.insert(section.virtual_address & !0xfff);
        }
    }

    let mut pages = Vec::new();
    let mut page_files: Vec<(usize, usize)> = Vec::new(); // (file offset, len)
    let mut page_index = 0u32;
    for section in &pe.sections {
        if section.characteristics & IMAGE_SCN_MEM_EXECUTE == 0 {
            continue;
        }
        // MSVC /guard:cf emits a tiny RX `fothk` section: a 5-byte jmp back
        // into .text that the loader's CFG dispatch uses as an IAT/FID
        // forwarder. That jmp runs at process-init, before xl_core can open
        // AEAD pages. Sealing it plants INT3s on the dispatch path and the
        // image "starts" (GFIDS covers the stub entry) then silently does
        // nothing (ping/Robocopy). Keep the section plaintext.
        if is_cfg_forwarder_section(&section.name_str()) {
            continue;
        }
        let start = section.raw_ptr as usize;
        let len = section.raw_size.min(section.virtual_size) as usize;
        if start.saturating_add(len) > working.len() {
            continue;
        }
        let mut offset = 0usize;
        while offset < len {
            let page_rva = section.virtual_address + offset as u32;
            if cfg_live_pages.contains(&(page_rva & !0xfff)) {
                offset += PAGE_SIZE;
                continue;
            }
            let chunk = (len - offset).min(PAGE_SIZE);
            let slice = working[start + offset..start + offset + chunk].to_vec();
            let nonce = random_nonce12();
            page_files.push((start + offset, chunk));
            pages.push((page_index, page_rva, slice, nonce));
            // The stub decrypts IN PLACE (mapped file bytes XOR keystream), so
            // the file must hold plaintext XOR keystream: no plaintext .text on
            // disk (C2/C3) and an exact one-pass unpack. The keystream here is
            // derived from the same runtime key the stub rebuilds.
            // NOTE: computed after `runtime` below; placeholder replaced there.
            page_index += 1;
            offset += chunk;
        }
    }
    if pages.len() > xenolith_loader::MAX_PAGES {
        return Err(PackError::Stub(format!(
            "too many pages: {} > {} (executable bytes ≈ {} KiB); the loader envelope \
             caps a packed image at {} 4-KiB page records — split the binary or exclude \
             sections from packing",
            pages.len(),
            xenolith_loader::MAX_PAGES,
            pages.len() * 4,
            xenolith_loader::MAX_PAGES
        )));
    }
    // G5 lazy regions: the injected core's fault-wake/quiesce table is a
    // fixed 64-entry array (XlRegionTable.st[] in xl_core.c). A lazy pack
    // beyond it would boot but never wake a sealed page, so refuse here
    // instead of shipping a silently-broken image. All-live packs are
    // unaffected (the boot decrypt walk is streaming).
    if request.lazy_regions && pages.len() > xenolith_loader::LAZY_REGION_STATE_MAX {
        return Err(PackError::Stub(format!(
            "lazy regions: {} sealed pages exceed the injected runtime's region-state \
             table ({} entries); dormant-region packs must stay within it — pack without \
             --lazy-regions (all-live decrypt) or exclude sections from packing",
            pages.len(),
            xenolith_loader::LAZY_REGION_STATE_MAX
        )));
    }

    let mut seed = [0u8; 16];
    OsRng.fill_bytes(&mut seed);
    let payload_name = section_name_from_seed(&seed, 0);
    let stub_name = section_name_from_seed(&seed, 1);

    let file_align = pe.file_align;
    let section_align = pe.section_align;
    let mut image = working;
    pad_file(&mut image, file_align);

    // Bind the runtime key to MBA material rather than the whole mapped image
    // so ASLR does not invalidate the AEAD.
    let mut measure_src = mba.as_bytes();
    measure_src.extend_from_slice(&opcode_seed);
    measure_src.extend_from_slice(&(pages.len() as u32).to_le_bytes());
    let measurement = image_measurement(&measure_src);
    let runtime = xenolith_crypto::mix_runtime_key(&mba, &measurement).map_err(|e| {
        PackError::Stub(format!(
            "runtime key derivation failed (mba {} B, measurement {} B): {e}",
            mba.as_bytes().len(),
            measurement.len()
        ))
    })?;

    // Disk original pages are traps, not XOR keystream. Plaintext lives only
    // in EnvelopeV2 AEAD records (xl_core copies them to RX pages).
    for (foff, clen) in &page_files {
        for b in &mut image[*foff..*foff + *clen] {
            *b = 0xCC;
        }
    }

    // Entry-less images seal zero pages, so the keep set starts empty (an
    // entry RVA of 0 would otherwise record page 0 for nothing).
    let mut keep: Vec<u32> = if entryless {
        Vec::new()
    } else {
        vec![pe.entry_rva & !0xfff]
    };
    for exp in &exports {
        let page = exp.rva & !0xfff;
        if !keep.contains(&page) {
            keep.push(page);
        }
    }
    for page in &cfg_live_pages {
        if !keep.contains(page) {
            keep.push(*page);
        }
    }
    let mba_bytes = mba.as_bytes();
    let mut mba_arr = [0u8; 96];
    mba_arr.copy_from_slice(&mba_bytes);
    let mut env_v2 = EnvelopeV2 {
        platform: PLATFORM_PE64,
        profile: request.profile as u8,
        flags: 0,
        policy: POLICY_STRICT,
        mba: mba_arr,
        opcode_seed,
        api_salt,
        opcode_map: [
            map.load_imm, map.add, map.xor, map.mul, map.jz, map.jmp, map.halt, map.mix_key,
        ],
        stolen: stolen.clone(),
        program: program.code.clone(),
        regions: Vec::new(),
        imports: hashed
            .iter()
            .map(|imp| xenolith_protocol::ImportRec {
                hash: imp.hash,
                iat_rva: imp.original_iat_rva,
                name: imp.name.as_bytes().to_vec(),
                dll: imp.dll.as_bytes().to_vec(),
                sealed: None,
            })
            .collect(),
        keep: keep.clone(),
        // G5/TASK-026: dormant regions. Everything not in the keep set
        // (entry page + export pages + resolver pages) stays sealed after
        // bootstrap and decrypts on the first execution fault. Fast keeps
        // the all-live behavior.
        lazy: if !request.lazy_regions || request.profile == Profile::Fast {
            Vec::new()
        } else {
            // Pages carrying DIR64 slots must stay live: the loader applies
            // those fixups once; a later fault-decrypt would restore the
            // UNRELOCATED plaintext and revert the pointers.
            let reloc_pages: std::collections::BTreeSet<u32> = pe
                .relocs(request.input)
                .unwrap_or_default()
                .into_iter()
                .filter(|e| e.kind == IMAGE_REL_BASED_DIR64)
                .map(|e| e.rva & !0xfff)
                .collect();
            (0..pages.len() as u32)
                .filter(|i| {
                    let (idx, rva, _, _) = &pages[*i as usize];
                    let _ = idx;
                    let page = rva & !0xfff;
                    !keep.contains(&page) && !reloc_pages.contains(&page)
                })
                .collect()
        },
        relocs: {
            // Sealed-page interval table. Page chunks step 4 KiB inside each
            // executable section, but nothing in the PE format forces
            // sections to own disjoint RVA ranges — merge_ranges unions the
            // (possibly overlapping or nested) page ranges first, so the one
            // binary search per relocation below is correct for every input.
            // Real monoliths carry 5×10^5-8×10^5 DIR64 entries against
            // 2×10^4-5×10^4 pages and the former per-relocation linear scan
            // measured minutes (R×P ≈ 4×10^10 on libcef-class inputs).
            let protected = merge_ranges(
                pages
                    .iter()
                    .map(|(_i, rva, plain, _n)| (*rva, *rva + plain.len() as u32))
                    .collect(),
            );
            let mut r = Vec::new();
            for e in pe.relocs(request.input).unwrap_or_default() {
                if e.kind != 0 && e.kind != IMAGE_REL_BASED_DIR64 {
                    return Err(PackError::Stub(format!(
                        "unsupported PE relocation at rva {:#x}: type {} (IMAGE_REL_BASED_{}) \
                         — only DIR64/ABSOLUTE relocs are preserved through packing; \
                         rebuild the image or strip the non-DIR64 fixups",
                        e.rva,
                        e.kind,
                        reloc_kind_name(e.kind)
                    )));
                }
                if e.kind == IMAGE_REL_BASED_DIR64 && range_contains(&protected, e.rva) {
                    r.push((e.rva, e.kind));
                }
            }
            r
        },
    };
    // TASK-024: seal the envelope import-name records with the boot runtime
    // key. The flag must be set BEFORE any region is sealed — region AAD
    // binds the header flags, so the injected runtime and the packer have to
    // see the same value. Sealing only makes sense when the on-disk import
    // directory is gone (writeback mode); a directory kept for TLS/Fast
    // bootstrap already exposes every name and the report says "kept".
    let seal_import_names =
        request.protect_imports && !keep_import_directory && !env_v2.imports.is_empty();
    let (imports_protected, imports_kept, imports_kept_reason) = if seal_import_names {
        // Scrub the raw .idata name bytes: the wiped directory entry hides
        // them from the loader, but the strings themselves stay in the file
        // otherwise. IAT slots survive — they are the writeback targets.
        for (rva, len) in pe.import_name_locations(request.input)? {
            if let Ok(off) = pe.file_offset_of(rva) {
                let end = (off as usize).saturating_add(len as usize).min(image.len());
                let start = off as usize;
                if start < end {
                    image[start..end].fill(0);
                }
            }
        }
        env_v2.flags |= FLAG_IMPORTS_SEALED;
        for i in 0..env_v2.imports.len() {
            let sealed = xenolith_protocol::seal_import(&runtime, &env_v2, i)?;
            env_v2.imports[i].sealed = Some(sealed);
        }
        (env_v2.imports.len(), 0, String::new())
    } else if request.protect_imports && keep_import_directory {
        (
            0,
            env_v2.imports.len(),
            disk_iat_keep_reason(tls_first.is_some(), jni_abi_disk_iat),
        )
    } else {
        (
            0,
            env_v2.imports.len(),
            // The keep reason is a product fact (TLS/JNI contract), not tied
            // to whether the operator asked for import sealing.
            if keep_import_directory {
                disk_iat_keep_reason(tls_first.is_some(), jni_abi_disk_iat)
            } else {
                String::new()
            },
        )
    };
    // TASK-025: plan read-only constant protection. The transform matrix
    // rejects data-referencing code today, so nothing is encrypted; the
    // strict knob still refuses targets whose constants keep native refs.
    let transformed_ranges: Vec<(u32, u32)> = lifted
        .iter()
        .map(|f| (f.rva, f.native_len as u32))
        .collect();
    let const_plan = protect::constants::plan_constants(
        &pe,
        request.input,
        &transformed_ranges,
        request.strict_constants,
    )
    .map_err(|e| PackError::DataProtection(e.to_string()))?;
    let mut records = Vec::new();
    for (index, rva, plain, _old_nonce) in &pages {
        let nonce = random_nonce12();
        let sealed = seal_region(&runtime, &env_v2, *index, *rva, plain, nonce)?;
        let mut mac = [0u8; 32];
        mac[..16].copy_from_slice(&sealed.tag);
        records.push(PageRecord {
            index: *index,
            original_rva: *rva,
            original_len: plain.len() as u32,
            nonce,
            ciphertext: sealed.ciphertext.clone(),
            mac,
            stub_digest: 0,
        });
        env_v2.regions.push(sealed);
    }
    let envelope = encode_v2(&env_v2)?;

    let mut stub = pic.bytes;
    let meta_off = pic.meta_off;
    let probes: Vec<Probe> = if request.profile == Profile::Max {
        max_probes().to_vec()
    } else {
        vec![Probe::TlsEarlyProbe, Probe::PebBeingDebugged]
    };

    // TASK-021: unwind metadata for the injected stub lives in the payload
    // section — a UNWIND_INFO blob (XDATA) plus a relocated .pdata array
    // (original entries + one RUNTIME_FUNCTION for the stub, appended so the
    // array stays sorted by begin RVA). The exception directory is repointed
    // at the new array; the original .pdata bytes stay untouched on disk.
    let stub_pushes: Vec<(u8, u32)> = vec![
        (3, unwind::windows::PUSH1),   // rbx
        (5, unwind::windows::PUSH1),   // rbp
        (6, unwind::windows::PUSH1),   // rsi
        (7, unwind::windows::PUSH1),   // rdi
        (12, unwind::windows::PUSH2),  // r12
        (13, unwind::windows::PUSH2),  // r13
        (14, unwind::windows::PUSH2),  // r14
        (15, unwind::windows::PUSH2),  // r15
    ];
    let mut xdata = unwind::windows::unwind_info(&stub_pushes, 0x3F8);
    // sub rsp,0x3F8 is 7 bytes; prologue size was accumulated from push sizes.
    debug_assert_eq!(xdata[1], 19);
    xdata[1] = 19;
    let pdata = pe
        .directory(IMAGE_DIRECTORY_ENTRY_EXCEPTION)
        .map(|d| d.rva)
        .filter(|rva| *rva != 0)
        .and_then(|rva| pe.file_offset_of(rva).ok())
        .map(|off| {
            let dir = pe.directory(IMAGE_DIRECTORY_ENTRY_EXCEPTION).unwrap();
            let dir_size = dir.size as usize;
            if dir_size % 12 != 0 {
                return Err(PackError::Stub(format!(
                    "exception directory size {dir_size} is not a multiple of 12 \
                     (RUNTIME_FUNCTION); the .pdata declaration is inconsistent with the \
                     image — refusing to copy a corrupt unwind table"
                )));
            }
            // The directory size can exceed the actual raw data (virtual_size
            // > raw_size sections, linker padding, third-party edits). Slice
            // through `get` so a lying declaration is a clean error, not a
            // panic.
            let raw = image
                .get(off..off.saturating_add(dir_size))
                .ok_or_else(|| {
                    PackError::Stub(format!(
                        "exception directory declares {} bytes of .pdata at file offset \
                         {off} but the image ends at {} bytes — refusing to copy a \
                         truncated unwind table",
                        dir_size,
                        image.len()
                    ))
                })?;
            Ok(raw.to_vec())
        })
        .transpose()?
        .unwrap_or_default();

    // Layout inside the payload raw area:
    //   [envelope][pad to 4][xdata][pdata][pad to 4][gfids]
    // GFIDS lives here — the payload section is IMAGE_SCN_MEM_READ, never
    // AEAD-sealed, and is mapped before the loader's GuardCF check runs.
    let xdata_off = (envelope.len() + 3) & !3usize;
    let pdata_off = (xdata_off + xdata.len() + 3) & !3usize;
    let gfids_off = (pdata_off + pdata.len() + 12 + 3) & !3usize;
    // Upper bound: original entries + stub entry + optional TLS trampoline +
    // one thunk per lifted function (only export-repointed thunks are written).
    let gfids_extra_cap = 1
        + usize::from(tls_first.is_some())
        + lifted.len();
    let gfids_reserve = cfg_plan
        .as_ref()
        .map(|p| {
            p.entries
                .len()
                .saturating_add(gfids_extra_cap)
                .saturating_mul(p.stride)
        })
        .unwrap_or(0);
    let payload_total = gfids_off + gfids_reserve;

    let payload_raw = align_up(payload_total as u32, file_align);
    let stub_raw = align_up(stub.len() as u32, file_align);
    let payload_virt = align_up(payload_total as u32, section_align);
    let stub_virt = align_up(stub.len() as u32, section_align);

    let last = pe
        .sections
        .last()
        .ok_or_else(|| PackError::Stub("image has no sections; cannot place the stub".into()))?;
    let next_va = align_up(
        last.virtual_address + last.virtual_size.max(last.raw_size),
        section_align,
    );
    if next_va != stub_va {
        return Err(PackError::Stub(format!(
            "stub va drifted: layout pass computed {:#x} but the section table pass \
             computed {:#x} (packer bug; report with the input image)",
            stub_va, next_va
        )));
    }
    let next_raw = align_up(image.len() as u32, file_align);
    if next_raw as usize > image.len() {
        image.resize(next_raw as usize, 0);
    }

    // Stub first so trampoline RVAs are known before XOR. Payload follows.
    let stub_section = Section {
        name: stub_name,
        virtual_size: stub.len() as u32,
        virtual_address: next_va,
        raw_size: stub_raw,
        raw_ptr: next_raw,
        characteristics: IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ,
        header_offset: 0,
    };
    let payload_section = Section {
        name: payload_name,
        // Covers the envelope AND the TASK-021 unwind metadata that follows
        // it in the same raw area; the exception directory points in here.
        virtual_size: payload_total as u32,
        virtual_address: next_va + stub_virt,
        raw_size: payload_raw,
        raw_ptr: next_raw + stub_raw,
        characteristics: IMAGE_SCN_MEM_READ,
        header_offset: 0,
    };

    let new_count = pe.number_of_sections + 2;
    let needed_headers_end = pe.section_table_offset + (new_count as usize) * 40;
    if needed_headers_end > pe.size_of_headers as usize {
        return Err(PackError::Stub(format!(
            "no room for 2 extra section headers: section table would end at \
             {needed_headers_end}, SizeOfHeaders is {} — rebuild the input with \
             header slack (e.g. /FILEALIGN or linker padding)",
            pe.size_of_headers
        )));
    }
    pe.set_number_of_sections(&mut image, new_count)?;
    pe.write_section_header(&mut image, pe.number_of_sections as usize, &stub_section)?;
    pe.write_section_header(&mut image, pe.number_of_sections as usize + 1, &payload_section)?;
    let entry_rva = stub_section.virtual_address + pic.entry_off;
    // Entry-less images keep AddressOfEntryPoint == 0: the loader never
    // calls it, and pointing it at the stub would make it run and then
    // transfer to the nonexistent original entry.
    if !entryless {
        pe.set_entry_rva(&mut image, entry_rva)?;
    }
    pe.set_size_of_image(&mut image, payload_section.virtual_address + payload_virt)?;

    image.resize((payload_section.raw_ptr + payload_section.raw_size) as usize, 0);
    image[payload_section.raw_ptr as usize..payload_section.raw_ptr as usize + envelope.len()]
        .copy_from_slice(&envelope);

    // TASK-021: write XDATA + relocated PDATA into the payload section and
    // repoint the exception directory. The stub RUNTIME_FUNCTION is appended
    // after the original entries (sorted: the stub RVA is past them all).
    let xdata_rva = payload_section.virtual_address + xdata_off as u32;
    let pdata_rva = payload_section.virtual_address + pdata_off as u32;
    image[payload_section.raw_ptr as usize + xdata_off
        ..payload_section.raw_ptr as usize + xdata_off + xdata.len()]
        .copy_from_slice(&xdata);
    image[payload_section.raw_ptr as usize + pdata_off
        ..payload_section.raw_ptr as usize + pdata_off + pdata.len()]
        .copy_from_slice(&pdata);
    let stub_end = stub_section
        .virtual_address
        .wrapping_add(stub_section.virtual_size.max(stub_section.raw_size));
    let stub_rf =
        unwind::windows::runtime_function(stub_section.virtual_address, stub_end, xdata_rva);
    image[payload_section.raw_ptr as usize + pdata_off + pdata.len()
        ..payload_section.raw_ptr as usize + pdata_off + pdata.len() + 12]
        .copy_from_slice(&stub_rf);
    pe.set_directory(
        &mut image,
        IMAGE_DIRECTORY_ENTRY_EXCEPTION,
        pdata_rva,
        (pdata.len() + 12) as u32,
    )?;

    if let Some(plan) = &cfg_plan {
        // Register every RVA the loader will invoke through GuardCF that we
        // actually changed: the new AddressOfEntryPoint, the TLS trampoline
        // (if the first callback slot was wrapped), and named-export thunks
        // whose export-directory RVA was retargeted. Internal vm-hooks keep
        // their original RVA (a direct jmp), which is already in GFIDS.
        let mut extra_rvas = vec![entry_rva];
        if tls_first.is_some() {
            extra_rvas.push(stub_section.virtual_address.wrapping_add(pic.tls_entry_off));
        }
        let packed_exports = pe.exports(&image).map_err(|e| {
            PackError::Stub(format!(
                "CFG GFIDS: re-reading export directory after rewrite failed: {e}"
            ))
        })?;
        for old in &exports {
            if let Some(new) = packed_exports.iter().find(|e| e.name == old.name) {
                if new.rva != old.rva {
                    extra_rvas.push(new.rva);
                }
            }
        }
        apply_cfg_gfids(
            &pe,
            &mut image,
            plan,
            payload_section.virtual_address + gfids_off as u32,
            payload_section.raw_ptr as usize + gfids_off,
            gfids_reserve,
            &extra_rvas,
        )?;
    }

    let mut meta = vec![0u8; STUB_META_LEN];
    meta[META_PAYLOAD_RVA..META_PAYLOAD_RVA + 4]
        .copy_from_slice(&payload_section.virtual_address.to_le_bytes());
    meta[META_ENVELOPE_LEN..META_ENVELOPE_LEN + 4]
        .copy_from_slice(&(envelope.len() as u32).to_le_bytes());
    meta[META_ORIGINAL_ENTRY..META_ORIGINAL_ENTRY + 4]
        .copy_from_slice(&pe.entry_rva.to_le_bytes());
    meta[META_UNPACKED..META_UNPACKED + 4].copy_from_slice(&0u32.to_le_bytes());
    meta[META_MEASUREMENT..META_MEASUREMENT + 32].copy_from_slice(&measurement);
    for i in 0..16 {
        meta[48 + i] = opcode_seed[i];
    }
    meta[63] = request.debug_gate;
    let orig_tls_rva = tls_first.map(|(rva, _)| rva).unwrap_or(0);
    meta[META_TLS_CALLBACK..META_TLS_CALLBACK + 4].copy_from_slice(&orig_tls_rva.to_le_bytes());
    stub[meta_off..meta_off + STUB_META_LEN].copy_from_slice(&meta);
    image[stub_section.raw_ptr as usize..stub_section.raw_ptr as usize + stub.len()]
        .copy_from_slice(&stub);
    if let Some((_rva, slot_off)) = tls_first {
        let tls_va = pe
            .image_base
            .wrapping_add(u64::from(stub_section.virtual_address + pic.tls_entry_off));
        write_u64(&mut image, slot_off, tls_va)?;
    }

    let packed = PackedImage {
        profile: request.profile,
        kind_dll: matches!(kind, ImageKind::Pe64Dll),
        original_entry_rva: pe.entry_rva,
        stolen,
        mba,
        opcode_seed,
        api_salt,
        imports: hashed,
        exports: exports
            .into_iter()
            .map(|e| (e.name, e.rva))
            .collect(),
        pages: records,
        probes,
        program,
        original_bytes: request.input.to_vec(),
    };

    let out_pe = Pe64::parse(&image)?;
    let report = PackReport {
        report_version: PACK_REPORT_VERSION,
        profile: request.profile.as_str().to_string(),
        format: match kind {
            ImageKind::Pe64Dll => "pe64-dll".into(),
            ImageKind::Pe64Exe => "pe64-exe".into(),
            ImageKind::Elf64Exec => "elf64-exec".into(),
            ImageKind::Elf64Dyn => "elf64-dyn".into(),
        },
        input_bytes: request.input.len(),
        output_bytes: image.len(),
        backend: BACKEND_PIC_STUB.into(),
        export_surface: export_names,
        iat_mode: iat_mode_for_profile(request.profile, keep_import_directory).into(),
        runtime_decryption_window: false,
        c2_reencrypt: false,
        aslr: out_pe.dll_characteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE != 0,
        high_entropy_va: out_pe.dll_characteristics & IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA != 0,
        reloc_directory: out_pe
            .directory(IMAGE_DIRECTORY_ENTRY_BASERELOC)
            .map(|d| d.rva != 0 && d.size != 0)
            .unwrap_or(false),
        tls_directory: out_pe
            .directory(IMAGE_DIRECTORY_ENTRY_TLS)
            .map(|d| d.rva != 0 && d.size != 0)
            .unwrap_or(false),
        long_term_rwx: out_pe.sections.iter().any(|s| {
            s.characteristics & IMAGE_SCN_MEM_EXECUTE != 0
                && s.characteristics & IMAGE_SCN_MEM_WRITE != 0
        }),
        seed_len: 16,
        pages: packed.pages.len(),
        stolen_bytes: packed.stolen.len(),
        vm_functions: lifted.len(),
        selected_functions: coverage.iter().map(|f| f.name.clone()).collect(),
        coverage,
        strict_coverage: request.strict_coverage,
        allow_native_fallback: request.allow_native_fallback,
        import_names_sealed: seal_import_names,
        imports_protected,
        imports_kept,
        imports_kept_reason,
        constants_candidates: const_plan.candidates,
        constants_protectable: const_plan.protectable,
        constants_encrypted: const_plan.encrypted,
        constants_native_referenced: const_plan.native_referenced,
        notes: {
            let mut notes = vec![
                "backend=pic-stub+xl-core (PIC boot + freestanding EnvelopeV2 core)".into(),
                "xenolith-loader is a host emulator, not injected".into(),
                "rustc xenolith-runtime cdylib is not injected (imports/CRT)".into(),
                "EnvelopeV2 ChaCha20-Poly1305; legacy NSEN/XOR is not decoded".into(),
                "ASLR/relocs preserved; TLS directory kept and first callback wrapped; delay-load imports fail closed".into(),
                "Sealed pages decrypt through a transient RW window, then return to the \
                 section's original loader protection (RX stays RX; an input section that \
                 is legitimately RWX keeps RWX — such images are reported as \
                 long_term_rwx, matching what the unpacked process actually runs)"
                    .into(),
                "C2 page re-encrypt is not jumped to; executing pages stay plaintext after unpack".into(),
            ];
            if entryless {
                notes.push(
                    "entry-less image (AddressOfEntryPoint=0, no executable sections, no \
                     exports): structural pack — 0 pages sealed, entry stays 0, and a \
                     vacuous GUARD_CF DllCharacteristics bit was cleared (the image ships \
                     no load-config/GFIDS and no code to enforce it on)"
                        .into(),
                );
            }
            notes
        },
    };

    Ok(PackOutput {
        image,
        report,
        packed,
    })
}

/// MSVC CFG forwarder section (`fothk`). The loader's GuardCF dispatch
/// jumps through it before any packed stub byte runs, so it must stay
/// plaintext on disk. Name match is exact (8-byte section name, no padding
/// variants observed on the System32 corpus).
fn is_cfg_forwarder_section(name: &str) -> bool {
    name == "fothk"
}

/// Grow a PE's header block so two more section headers fit.
///
/// Tight linker layouts end the section table exactly at `SizeOfHeaders`
/// (e.g. 16 sections, `FileAlignment` 0x200, raw data starting at 0x400),
/// and pack() appends two section headers (stub + payload) — the historical
/// behavior was to reject the whole image ("no room for 2 extra section
/// headers"). Instead of refusing, insert a `FileAlignment`-multiple hole
/// immediately before the first section's raw data and shift every raw
/// pointer past it:
///
/// * the section TABLE stays at its spec-fixed offset (it always follows the
///   optional header); only its end must fit inside the grown header block;
/// * `SizeOfHeaders += delta`, still ≤ the (shifted) first raw pointer — the
///   loader maps the enlarged header region and finds the two new headers;
/// * raw pointers of sections with raw data each shift by the same `delta`,
///   so no bytes are reordered, only relocated as a block — RVAs, imports,
///   relocs, and unwind tables are untouched;
/// * the SECURITY directory is zeroed: unlike every other directory its VA
///   is an absolute FILE OFFSET, and an Authenticode signature over the
///   original bytes is invalid after any repack anyway;
/// * `None` means "no injection needed" (the table already fits) or "this
///   image cannot be shifted safely" (raw data starting inside the header
///   block, or no raw data at all) — the caller's existing fail-closed
///   error then reports it.
fn inject_header_slack(input: &[u8]) -> Result<Option<Vec<u8>>, PackError> {
    let pe = Pe64::parse(input)?;
    let headers = pe.size_of_headers as usize;
    let needed =
        pe.section_table_offset + (pe.number_of_sections as usize + 2) * 40; // + stub + payload
    if needed <= headers {
        return Ok(None);
    }
    let mut raw_ptrs: Vec<u32> = pe
        .sections
        .iter()
        .filter(|s| s.raw_size > 0 && s.raw_ptr > 0)
        .map(|s| s.raw_ptr)
        .collect();
    raw_ptrs.sort_unstable();
    let Some(&first_raw) = raw_ptrs.first() else {
        return Ok(None); // no raw data: nothing to shift around
    };
    let first_raw = first_raw as usize;
    if first_raw < headers {
        // Raw data starts inside the header block — not a layout the loader
        // honors for grown headers; leave it to the fail-closed check.
        return Ok(None);
    }
    let align = pe.file_align as usize;
    if align < 512 || !align.is_power_of_two() {
        return Err(PackError::Stub(format!(
            "FileAlignment {align:#x} outside the PE range [512, 65536] or not a power of \
             two — cannot grow the header block safely",
        )));
    }
    let delta = (needed - headers).div_ceil(align) * align;
    let mut out = Vec::with_capacity(input.len() + delta);
    out.extend_from_slice(&input[..first_raw]);
    out.resize(first_raw + delta, 0);
    out.extend_from_slice(&input[first_raw..]);
    for (i, sec) in pe.sections.iter().enumerate() {
        let mut shifted = sec.clone();
        if sec.raw_size > 0 && sec.raw_ptr > 0 {
            shifted.raw_ptr = sec.raw_ptr.checked_add(delta as u32).ok_or_else(|| {
                PackError::Stub(format!(
                    "raw pointer {:#x} + {delta:#x} overflows u32 while growing the header \
                     block — the input is larger than a 32-bit file layout allows",
                    sec.raw_ptr
                ))
            })?;
        }
        pe.write_section_header(&mut out, i, &shifted)?;
    }
    pe.set_size_of_headers(&mut out, (headers + delta) as u32)?;
    pe.zero_directory(&mut out, IMAGE_DIRECTORY_ENTRY_SECURITY)?;
    // Fail closed on our own arithmetic: the shifted image must parse and
    // actually satisfy the bound pack() is about to rely on.
    let reparsed = Pe64::parse(&out)?;
    let new_needed =
        reparsed.section_table_offset + (reparsed.number_of_sections as usize + 2) * 40;
    if new_needed > reparsed.size_of_headers as usize || reparsed.file_align as usize != align {
        return Err(PackError::Stub(
            "header-slack injection produced an inconsistent image (packer bug; report with \
             the input image)"
                .into(),
        ));
    }
    Ok(Some(out))
}

/// Parsed CFG rewrite plan. `None` from `plan_cfg_rewrite` means the image is
/// not GuardCF-enforced (including INSTRUMENTED-without-table rustc images).
struct CfgPlan {
    cfg: LoadConfigCfg,
    entries: Vec<xenolith_formats::GfidsEntry>,
    stride: usize,
    flag_len: usize,
}

/// Decide whether this image needs a GFIDS rewrite, and fail closed on every
/// construction we cannot faithfully reproduce.
fn plan_cfg_rewrite(pe: &Pe64, bytes: &[u8]) -> Result<Option<CfgPlan>, PackError> {
    let dll_cf = pe.dll_characteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF != 0;
    let cfg = pe.load_config_cfg(bytes)?;
    let flags = cfg.as_ref().map(|c| c.guard_flags).unwrap_or(0);
    let table_present = flags & IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT != 0;

    // rustc/MSVC images often set INSTRUMENTED in load-config without
    // DllCharacteristics GUARD_CF and without a function table (hello-exe:
    // flags 0x100, table VA 0). The loader does not CFG-check those entries.
    if !dll_cf && !table_present {
        return Ok(None);
    }

    let Some(cfg) = cfg else {
        return Err(PackError::Lift(format!(
            "CFG image (DllCharacteristics GUARD_CF={dll_cf}) has no parseable \
             IMAGE_LOAD_CONFIG_DIRECTORY64: the directory is absent or its declared \
             Size is below 0x94 (GuardFlags). Cannot register the packed stub in GFIDS"
        )));
    };

    if cfg.guard_flags & IMAGE_GUARD_XFG_ENABLED != 0 {
        return Err(PackError::Lift(format!(
            "CFG image load-config GuardFlags {:#x} has IMAGE_GUARD_XFG_ENABLED \
             (0x800000): GFIDS entries carry an XFG hash this packer does not rewrite",
            cfg.guard_flags
        )));
    }
    if !table_present {
        return Err(PackError::Lift(format!(
            "CFG image (DllCharacteristics GUARD_CF, GuardFlags {:#x}) is missing \
             IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT (0x400); no GFIDS table to extend",
            cfg.guard_flags
        )));
    }

    let entries = pe.gfids_table(bytes, &cfg).map_err(|e| {
        PackError::Lift(format!(
            "CFG GFIDS table unreadable (GuardCFFunctionTable VA {:#x}, count {}, \
             GuardFlags {:#x}, stride {}): {e}",
            cfg.table_va,
            cfg.function_count,
            cfg.guard_flags,
            Pe64::gfids_stride(cfg.guard_flags)
        ))
    })?;
    let stride = Pe64::gfids_stride(cfg.guard_flags);
    Ok(Some(CfgPlan {
        cfg,
        entries,
        stride,
        flag_len: stride - 4,
    }))
}

/// Write a merged GFIDS table into the plaintext payload section and retarget
/// load-config GuardCFFunctionTable / GuardCFFunctionCount in place.
///
/// GuardCFFunctionTable is a preferred-base VA. The field offset is unchanged,
/// so the original DIR64 reloc covering load-config+0x80 still fixes it up
/// when the image is relocated. The new table itself stores RVAs, not VAs,
/// and does not need its own reloc entries.
fn apply_cfg_gfids(
    pe: &Pe64,
    image: &mut [u8],
    plan: &CfgPlan,
    table_rva: u32,
    table_file_off: usize,
    reserved: usize,
    extra_rvas: &[u32],
) -> Result<(), PackError> {
    // Load-config lives in a non-executable section on well-formed images; if
    // it sat inside a sealed RX page the 0xCC trap fill would already have
    // clobbered it and this write would not reach the mapped directory.
    let cfg_end = plan
        .cfg
        .flags_file_offset
        .checked_add(4)
        .ok_or_else(|| PackError::Stub("CFG load-config offset overflow".into()))?;
    if cfg_end > image.len()
        || plan.cfg.table_va_file_offset + 8 > image.len()
        || plan.cfg.count_file_offset + 8 > image.len()
    {
        return Err(PackError::Stub(format!(
            "CFG load-config at file offset {:#x} overruns the {}-byte packed image",
            plan.cfg.config_file_offset,
            image.len()
        )));
    }

    let merged = Pe64::merge_gfids_entries(
        &plan.entries,
        extra_rvas,
        pe.entry_rva,
        plan.flag_len,
    )
    .map_err(|e| PackError::Stub(format!("CFG GFIDS merge failed: {e}")))?;
    let encoded = Pe64::encode_gfids_table(&merged, plan.flag_len)
        .map_err(|e| PackError::Stub(format!("CFG GFIDS encode failed: {e}")))?;
    if encoded.len() > reserved {
        return Err(PackError::Stub(format!(
            "CFG GFIDS encoded {} bytes but the payload reserved only {reserved} \
             ({} original entries + extras); packer bound is wrong",
            encoded.len(),
            plan.entries.len()
        )));
    }
    let table_end = table_file_off
        .checked_add(encoded.len())
        .ok_or_else(|| PackError::Stub("CFG GFIDS payload offset overflow".into()))?;
    if table_end > image.len() {
        return Err(PackError::Stub(format!(
            "CFG GFIDS table at file offset {table_file_off:#x} ({} bytes) overruns \
             the {}-byte packed image",
            encoded.len(),
            image.len()
        )));
    }
    image[table_file_off..table_end].copy_from_slice(&encoded);

    let new_va = pe.image_base.wrapping_add(u64::from(table_rva));
    write_u64(image, plan.cfg.table_va_file_offset, new_va).map_err(|e| {
        PackError::Stub(format!(
            "CFG GFIDS: writing GuardCFFunctionTable VA {new_va:#x} at file offset \
             {:#x} failed: {e}",
            plan.cfg.table_va_file_offset
        ))
    })?;
    write_u64(image, plan.cfg.count_file_offset, merged.len() as u64).map_err(|e| {
        PackError::Stub(format!(
            "CFG GFIDS: writing GuardCFFunctionCount {} at file offset {:#x} failed: {e}",
            merged.len(),
            plan.cfg.count_file_offset
        ))
    })?;
    Ok(())
}

fn pad_file(image: &mut Vec<u8>, align: u32) {
    let aligned = align_up(image.len() as u32, align) as usize;
    if aligned > image.len() {
        image.resize(aligned, 0);
    }
}

/// IMAGE_REL_BASED_* name for the relocation types that can appear in an
/// x64 image; unknown types render numerically.
fn reloc_kind_name(kind: u16) -> String {
    match kind {
        0 => "ABSOLUTE".into(),
        1 => "HIGH".into(),
        2 => "LOW".into(),
        3 => "HIGHLOW".into(),
        4 => "HIGHADJ".into(),
        10 => "DIR64".into(),
        other => format!("TYPE{other}"),
    }
}

/// Merge a set of half-open RVA intervals `[lo, hi)` into a sorted, disjoint
/// table whose union equals the union of the inputs.
///
/// Executable sections normally own distinct RVA ranges, but nothing in the
/// PE format enforces that: hand-linked and post-processed images can carry
/// sections whose RVA ranges overlap or nest. On such input a merely
/// *sorted* table breaks the containment binary search — a later-starting
/// interval shadows an earlier, longer one, and relocations inside the
/// shadowed tail would look unprotected and be silently dropped from the
/// envelope (wild pointers at runtime once the loader applies the surviving
/// fixups). Unioning the ranges before searching makes the answer correct
/// for every input, overlapping or not, without rejecting images the OS
/// loader itself accepts.
fn merge_ranges(ranges: Vec<(u32, u32)>) -> Vec<(u32, u32)> {
    let mut ranges = ranges;
    ranges.sort_unstable_by_key(|&(lo, _)| lo);
    let mut merged: Vec<(u32, u32)> = Vec::with_capacity(ranges.len());
    for (lo, hi) in ranges {
        if hi <= lo {
            continue; // empty interval: covers nothing, cannot merge
        }
        match merged.last_mut() {
            // Overlapping or touching: extend the running hull. Adjacent
            // intervals merge too; containment semantics are unchanged.
            Some(last) if lo <= last.1 => last.1 = last.1.max(hi),
            _ => merged.push((lo, hi)),
        }
    }
    merged
}

/// Half-open containment against a table produced by [`merge_ranges`]
/// (sorted, disjoint): one binary search, no linear scan.
fn range_contains(table: &[(u32, u32)], rva: u32) -> bool {
    let idx = table.partition_point(|&(lo, _)| lo <= rva);
    idx > 0 && {
        let (lo, hi) = table[idx - 1];
        rva >= lo && rva < hi
    }
}

/// Guard against double packing. Both signals must agree so ordinary images
/// whose entry happens to sit in the second-to-last section are never
/// rejected: the entry must land inside the stub section AND the payload
/// section must open with the EnvelopeV2 magic + version.
fn is_already_packed(pe: &Pe64, image: &[u8]) -> bool {
    if pe.sections.len() < 2 {
        return false;
    }
    let stub = &pe.sections[pe.sections.len() - 2];
    let stub_end = stub
        .virtual_address
        .saturating_add(stub.virtual_size.max(stub.raw_size));
    let entry_in_stub =
        pe.entry_rva >= stub.virtual_address && pe.entry_rva < stub_end;
    if !entry_in_stub {
        return false;
    }
    let payload = pe.sections.last().expect("checked len");
    let off = payload.raw_ptr as usize;
    image.len() >= off + 6
        && &image[off..off + 4] == b"XLV2"
        && u16::from_le_bytes(image[off + 4..off + 6].try_into().unwrap_or([0, 0])) == 2
}

fn rewrite_function(
    pe: &Pe64,
    working: &mut [u8],
    func: &LiftedExport,
    thunk_rva: u32,
) -> Result<(), PackError> {
    apply_vm_hook(pe, working, func, thunk_rva)
}

fn apply_vm_hook(
    pe: &Pe64,
    working: &mut [u8],
    func: &LiftedExport,
    thunk_rva: u32,
) -> Result<(), PackError> {
    let off = pe.file_offset_of(func.rva).map_err(|_| {
        PackError::Stub(format!(
            "vm hook: {name} rva {rva:#x} does not map to file data",
            name = func.name,
            rva = func.rva
        ))
    })?;
    let end = off.checked_add(func.native_len).ok_or_else(|| {
        PackError::Stub(format!(
            "vm hook: {name} native_len {} overflows at rva {rva:#x}",
            func.native_len,
            name = func.name,
            rva = func.rva
        ))
    })?;
    if end > working.len() {
        return Err(PackError::Stub(format!(
            "vm hook: {name} rewrite of {} bytes at rva {rva:#x} (file offset {off}) \
             overruns the {}-byte image",
            func.native_len,
            working.len(),
            name = func.name,
            rva = func.rva
        )));
    }
    // Named exports keep their export-directory entry pointed at the thunk.
    // Internal functions selected through COFF/.pdata are reached through
    // their original entry, which receives the same jmp rewrite below.
    let is_export = pe
        .exports(working)
        .map_err(|e| {
            PackError::Stub(format!(
                "vm hook: export table re-read failed while hooking {name}: {e}",
                name = func.name
            ))
        })?
        .iter()
        .any(|e| e.name == func.name);
    if is_export {
        pe.set_export_rva(working, &func.name, thunk_rva).map_err(|e| {
            PackError::Stub(format!(
                "vm hook: repointing export {name} (rva {rva:#x}) to thunk {thunk_rva:#x} \
                 failed: {e}",
                name = func.name,
                rva = func.rva
            ))
        })?;
    }
    if func.native_len >= 5 {
        let next = func.rva.wrapping_add(5);
        let rel = thunk_rva.wrapping_sub(next) as i32;
        working[off] = 0xE9;
        working[off + 1..off + 5].copy_from_slice(&rel.to_le_bytes());
        for b in &mut working[off + 5..end] {
            *b = 0xCC;
        }
    } else {
        for b in &mut working[off..end] {
            *b = 0xCC;
        }
    }
    Ok(())
}

pub fn inspect_bytes(image: &[u8]) -> Result<serde_json::Value, PackError> {
    match classify(image) {
        Ok(ImageKind::Elf64Exec | ImageKind::Elf64Dyn) => {
            let elf = xenolith_formats::elf::parse(image).map_err(PackError::Format)?;
            // Packed artifact: INIT_ARRAY[0]'s R_X86_64_RELATIVE addend (what
            // ld.so actually calls first) lands inside the appended R+X
            // PT_LOAD — that addend is the bootstrap stub. Anything else is
            // an unpacked (or foreign) ELF.
            let boot = xenolith_formats::elf::packed_bootstrap_target(image, &elf)
                .map_err(PackError::Format)?;
            let packed = boot.is_some();
            let resolvers = xenolith_formats::elf::ifunc_resolvers(image, &elf)
                .map_err(PackError::Format)?
                .len();
            let (verneed, verdef) = xenolith_formats::elf::symbol_versions(image, &elf)
                .map_err(PackError::Format)?;
            let (tls_ie, tls_ld) = xenolith_formats::elf::tls_reloc_census(image, &elf)
                .map_err(PackError::Format)?;
            let mut info = serde_json::json!({
                "report_version": PACK_REPORT_VERSION,
                "backend": if packed { BACKEND_PIC_STUB } else { "none" },
                "format": match elf.kind {
                    ImageKind::Elf64Exec => "elf64-exec",
                    ImageKind::Elf64Dyn => "elf64-dyn",
                    _ => "elf64",
                },
                "image_bytes": image.len(),
                "pie": elf.pie,
                "relro": elf.relro,
                "tls": elf.has_tls,
                "dynamic": elf.dynamic,
                "entry": elf.entry,
                "packed": packed,
                "aslr": elf.pie,
                "long_term_rwx": false,
                "runtime_decryption_window": false,
                "c2_reencrypt": false,
                "host_emulator_injected": false,
                "xenolith_runtime_injected": false,
                "iat_mode": if packed { "loader-resolved-got-plt" } else { "ld.so" },
                "ifunc_resolvers": resolvers,
                "symbol_versions": { "verneed": verneed, "verdef": verdef },
                "tls_models": { "initial_exec": tls_ie, "dynamic": tls_ld },
            });
            if !packed {
                info["note"] = serde_json::json!(
                    "unpacked ELF: parsed only; packing fail-closes on static linkage, \
                     TPOFF32-in-text, RELATIVE into sealed page"
                );
            } else {
                info["note"] = serde_json::json!(
                    "packed ELF: INIT_ARRAY[0] bootstraps pic-stub+xl-core; ld.so keeps \
                     PIE/RELRO/GOT-PLT; executable PT_LOAD bytes sealed on disk"
                );
            }
            return Ok(info);
        }
        Err(e) if image.starts_with(b"\x7fELF") => return Err(PackError::Format(e)),
        _ => {}
    }
    let pe = Pe64::parse(image)?;
    let names: Vec<String> = pe.sections.iter().map(|s| s.name_str()).collect();
    // JavaShroud JSIM measurement/key sections are plain data in an unpacked
    // host image, not a packer fingerprint. Foreign packer section names
    // (UPX*/.packed/...) still refuse inspection.
    let foreign_packed = names.iter().any(|n| {
        !Pe64::is_host_measurement_section(n) && Pe64::forbidden_section_name(n)
    });
    if foreign_packed {
        return Err(PackError::Invalid("forbidden section name present"));
    }
    let exports = pe.exports(image).unwrap_or_default();
    let export_rows: Vec<serde_json::Value> = exports
        .iter()
        .map(|e| {
            serde_json::json!({
                "name": e.name,
                "ordinal": e.ordinal,
                "rva": e.rva,
            })
        })
        .collect();
    let import_rva = pe
        .directory(IMAGE_DIRECTORY_ENTRY_IMPORT)
        .map(|d| d.rva)
        .unwrap_or(0);
    let reloc_rva = pe
        .directory(IMAGE_DIRECTORY_ENTRY_BASERELOC)
        .map(|d| d.rva)
        .unwrap_or(0);
    let tls_rva = pe
        .directory(IMAGE_DIRECTORY_ENTRY_TLS)
        .map(|d| d.rva)
        .unwrap_or(0);
    let aslr = pe.dll_characteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE != 0;
    let high_entropy_va =
        pe.dll_characteristics & IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA != 0;
    let long_term_rwx = pe.sections.iter().any(|s| {
        s.characteristics & IMAGE_SCN_MEM_EXECUTE != 0
            && s.characteristics & IMAGE_SCN_MEM_WRITE != 0
    });
    let backend = if pe.sections.len() >= 2 {
        let stub = &pe.sections[pe.sections.len() - 2];
        let stub_end = stub
            .virtual_address
            .saturating_add(stub.virtual_size.max(stub.raw_size));
        if pe.entry_rva >= stub.virtual_address && pe.entry_rva < stub_end {
            BACKEND_PIC_STUB
        } else {
            "native-or-unknown"
        }
    } else {
        "native-or-unknown"
    };
    let iat_mode = if import_rva == 0 {
        "hashed-resolve-writeback-iat"
    } else {
        "disk-import-directory"
    };
    let note = if matches!(pe.kind, xenolith_formats::PeKind::Dll) {
        ""
    } else if export_rows.is_empty() {
        "W1 cannot virtualize EXE entry; use a DLL export or wait for RVA selection"
    } else {
        ""
    };
    let mut envelope_magic = String::new();
    let mut envelope_version = 0u16;
    if let Some(payload) = pe.sections.last() {
        let off = payload.raw_ptr as usize;
        if off + 6 <= image.len() {
            envelope_magic = String::from_utf8_lossy(&image[off..off + 4]).into_owned();
            envelope_version = u16::from_le_bytes(image[off + 4..off + 6].try_into().unwrap_or([0, 0]));
        }
    }
    Ok(serde_json::json!({
        "report_version": PACK_REPORT_VERSION,
        "backend": backend,
        "envelope_magic": envelope_magic,
        "envelope_version": envelope_version,
        "format": match pe.kind {
            xenolith_formats::PeKind::Dll => "pe64-dll",
            xenolith_formats::PeKind::Exe => "pe64-exe",
        },
        "image_bytes": image.len(),
        "sections": names,
        "entry_rva": pe.entry_rva,
        "dll": matches!(pe.kind, xenolith_formats::PeKind::Dll),
        "import_rva": import_rva,
        "reloc_directory_rva": reloc_rva,
        "tls_directory_rva": tls_rva,
        "aslr": aslr,
        "high_entropy_va": high_entropy_va,
        "long_term_rwx": long_term_rwx,
        "iat_mode": iat_mode,
        "runtime_decryption_window": false,
        "c2_reencrypt": false,
        "injected_runtime": backend,
        "host_emulator_injected": false,
        "xenolith_runtime_injected": false,
        "exports": export_rows,
        "note": note,
    }))
}

pub fn strength_scan(image: &[u8], original_secret: Option<&[u8; 32]>) -> StrengthScan {
    let mut scan = StrengthScan::default();
    if let Ok(pe) = Pe64::parse(image) {
        scan.forbidden_section = pe.sections.iter().any(|s| {
            let n = s.name_str();
            !Pe64::is_host_measurement_section(&n) && Pe64::forbidden_section_name(&n)
        });
        scan.import_directory_present = pe
            .directory(IMAGE_DIRECTORY_ENTRY_IMPORT)
            .map(|d| d.rva != 0)
            .unwrap_or(false);
        scan.entry_is_original = false;
    } else {
        scan.parse_ok = false;
        return scan;
    }
    scan.parse_ok = true;
    if let Some(secret) = original_secret {
        scan.contiguous_secret = find_subslice(image, secret);
    }
    scan.upx_magic = image.windows(4).any(|w| w == b"UPX0" || w == b"UPX!")
        || image.windows(5).any(|w| w == b"UPX1\0");
    scan
}

fn find_subslice(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct StrengthScan {
    pub parse_ok: bool,
    pub forbidden_section: bool,
    pub import_directory_present: bool,
    pub entry_is_original: bool,
    pub contiguous_secret: bool,
    pub upx_magic: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn required_sample(name: &str) -> Vec<u8> {
        std::fs::read(format!("target/release/{name}"))
            .or_else(|_| std::fs::read(format!("../../target/release/{name}")))
            .unwrap_or_else(|e| {
                panic!(
                    "missing required sample {name} ({e}). Build first: \
                     cargo build -p hello-dll --release && cargo build -p license-toy --release. \
                     Missing sample is a FAIL, not a skip."
                )
            })
    }

    fn thunk_pic<'a>(pe: &Pe64, image: &'a [u8], name: &str) -> &'a [u8] {
        let exp = pe
            .exports(image)
            .unwrap()
            .into_iter()
            .find(|e| e.name == name)
            .expect("export");
        let stub = pe.sections.iter().rev().nth(1).expect("stub");
        let off = (exp.rva - stub.virtual_address) as usize;
        let raw = stub.raw_ptr as usize;
        let len = stub.raw_size.min(stub.virtual_size) as usize;
        let bytes = &image[raw..raw + len];
        let end = len.saturating_sub(STUB_META_LEN);
        &bytes[off.min(end)..end]
    }

    #[test]
    fn stub_is_seed_divergent() {
        let a = emit_pic_stub(&[1; 16]).expect("stub a");
        let b = emit_pic_stub(&[2; 16]).expect("stub b");
        assert_ne!(a.bytes, b.bytes, "G-POLY");
        assert_eq!(a.meta_off + STUB_META_LEN, a.bytes.len());
        assert_eq!(a.tls_entry_off, 0);
        assert_ne!(a.entry_off, 0, "DllMain/EXE entry follows the TLS trampoline");
        assert!(!a.bytes.starts_with(&[0x60, 0xE8])); // not pushad; call
    }

    #[test]
    #[cfg(windows)]
    fn packs_hello_dll_without_upx_or_contiguous_secret() {
        let dll = required_sample("hello_dll.dll");
        let original = Pe64::parse(&dll).expect("sample dll");
        let a = pack(PackRequest {
            input: &dll,
            profile: Profile::Standard,
            vm_exports: vec![],
            debug_gate: 3,
            opcode_seed: None,
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
        .unwrap_or_else(|e| panic!("{e}"));
        let b = pack(PackRequest {
            input: &dll,
            profile: Profile::Standard,
            vm_exports: vec![],
            debug_gate: 3,
            opcode_seed: None,
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
        .unwrap_or_else(|e| panic!("{e}"));
        assert_ne!(a.image, b.image, "G-POLY");
        let pe = Pe64::parse(&a.image).expect("packed pe");
        assert_ne!(pe.entry_rva, original.entry_rva, "G-OEP");
        let import_rva = pe
            .directory(IMAGE_DIRECTORY_ENTRY_IMPORT)
            .map(|d| d.rva)
            .unwrap_or(0);
        let orig_tls = original
            .tls_first_callback(&dll)
            .expect("tls")
            .is_some();
        if orig_tls {
            assert_ne!(import_rva, 0, "TLS images keep the disk import directory");
        } else {
            assert_eq!(import_rva, 0, "G-IAT");
        }
        assert!(!a.image.windows(4).any(|w| w == b"UPX0" || w == b"UPX!"));
        let secret = a.packed.mba.reconstruct().expect("mba");
        let scan = strength_scan(&a.image, Some(&secret.0));
        assert!(scan.parse_ok);
        assert!(!scan.forbidden_section);
        assert!(!scan.contiguous_secret, "G-KEY");
        assert!(!scan.upx_magic, "G-UPX");
        assert!(!a.packed.pages.is_empty());
        assert_eq!(a.report.backend, BACKEND_PIC_STUB);
        if orig_tls {
            assert_eq!(a.report.iat_mode, "disk-import-directory");
            assert!(a.report.tls_directory);
        } else {
            assert_eq!(a.report.iat_mode, "hashed-resolve-writeback-iat");
        }
        assert!(!a.report.runtime_decryption_window);
        assert!(!a.report.c2_reencrypt);
        assert_eq!(
            a.report.aslr,
            original.dll_characteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE != 0
        );
        assert!(!a.report.long_term_rwx);
        let info = inspect_bytes(&a.image).expect("inspect packed");
        assert_eq!(info["backend"], BACKEND_PIC_STUB);
        assert_eq!(info["iat_mode"], a.report.iat_mode);
        assert_eq!(info["runtime_decryption_window"], false);
        assert_eq!(info["host_emulator_injected"], false);
        assert_eq!(info["xenolith_runtime_injected"], false);
        assert_eq!(info["aslr"], a.report.aslr);
        assert_eq!(info["long_term_rwx"], false);
        assert_eq!(info["envelope_magic"], "XLV2");
        assert_eq!(info["envelope_version"], 2);
        // TASK-038: size fields feed the G8 size budget; they must describe
        // exactly the bytes that hit the disk.
        assert_eq!(a.report.input_bytes, dll.len());
        assert_eq!(a.report.output_bytes, a.image.len());
        assert_eq!(info["image_bytes"], a.image.len());
        let fast = pack(PackRequest {
            input: &dll,
            profile: Profile::Fast,
            vm_exports: vec![],
            debug_gate: 3,
            opcode_seed: None,
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
        .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(fast.report.iat_mode, "disk-import-directory");
        assert!(!fast.report.runtime_decryption_window);
    }

    #[test]
    #[cfg(windows)]
    fn packed_vm_export_stub_has_no_guest_dispatcher() {
        let dll = required_sample("hello_dll.dll");
        let a = pack(PackRequest {
            input: &dll,
            profile: Profile::Standard,
            vm_exports: vec!["hello_add".into()],
            debug_gate: 3,
            opcode_seed: Some([1; 16]),
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
        .unwrap_or_else(|e| panic!("{e}"));
        let b = pack(PackRequest {
            input: &dll,
            profile: Profile::Standard,
            vm_exports: vec!["hello_add".into()],
            debug_gate: 3,
            opcode_seed: Some([2; 16]),
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
        .unwrap_or_else(|e| panic!("{e}"));
        let pe_a = Pe64::parse(&a.image).unwrap();
        let pe_b = Pe64::parse(&b.image).unwrap();
        let stub_a = pe_a.sections.iter().rev().nth(1).expect("stub a");
        let stub_b = pe_b.sections.iter().rev().nth(1).expect("stub b");
        let bytes_a = &a.image[stub_a.raw_ptr as usize
            ..stub_a.raw_ptr as usize + stub_a.raw_size.min(stub_a.virtual_size) as usize];
        let bytes_b = &b.image[stub_b.raw_ptr as usize
            ..stub_b.raw_ptr as usize + stub_b.raw_size.min(stub_b.virtual_size) as usize];
        assert!(
            !xenolith_vm::has_guest_dispatch_tetrad(bytes_a),
            "G-VM: packed stub still has GuestMap l_gloop tetrad"
        );
        assert!(!xenolith_vm::has_guest_dispatch_tetrad(bytes_b));
        assert_ne!(bytes_a, bytes_b, "two packs must not share one opcode table");

        let pic_a = thunk_pic(&pe_a, &a.image, "hello_add");
        let pic_b = thunk_pic(&pe_b, &b.image, "hello_add");
        assert!(
            !xenolith_vm::has_guest_dispatch_tetrad(pic_a),
            "G-WB-NOLIFT: thunk still has l_gloop tetrad"
        );
        let map = xenolith_vm::GuestMap::from_seed(&[1; 16]);
        let guest = xenolith_vm::GuestProgram {
            map,
            code: pic_a.to_vec(),
        };
        assert!(
            xenolith_vm::run_guest(&guest, 3, 4).is_err(),
            "G-WB-NOLIFT: GuestMap must not decode packed PIC"
        );
        let sa = xenolith_vm::native_shape(pic_a);
        let sb = xenolith_vm::native_shape(pic_b);
        assert!(
            !xenolith_vm::shapes_alignable(&sa, &sb),
            "G-WB-DIVERSE: two seeds collapsed to one opcode table"
        );
    }

    #[test]
    #[cfg(windows)]
    fn g_wb_meta_two_packs_not_one_opcode_table() {
        let dll = required_sample("license_toy.dll");
        let a = pack(PackRequest {
            input: &dll,
            profile: Profile::Standard,
            vm_exports: vec!["check_license".into()],
            debug_gate: 3,
            opcode_seed: Some([1; 16]),
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
        .unwrap_or_else(|e| panic!("{e}"));
        let b = pack(PackRequest {
            input: &dll,
            profile: Profile::Standard,
            vm_exports: vec!["check_license".into()],
            debug_gate: 3,
            opcode_seed: Some([2; 16]),
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
        .unwrap_or_else(|e| panic!("{e}"));
        let pe_a = Pe64::parse(&a.image).unwrap();
        let pe_b = Pe64::parse(&b.image).unwrap();
        let pic_a = thunk_pic(&pe_a, &a.image, "check_license");
        let pic_b = thunk_pic(&pe_b, &b.image, "check_license");
        let sa = xenolith_vm::native_shape(pic_a);
        let sb = xenolith_vm::native_shape(pic_b);
        assert!(
            !xenolith_vm::shapes_alignable(&sa, &sb),
            "G-WB-META: two packs collapsed to one opcode→semantics table"
        );
    }

    #[test]
    #[cfg(windows)]
    fn strict_coverage_empty_fails() {
        let dll = required_sample("hello_dll.dll");
        let err = match pack(PackRequest {
            input: &dll,
            profile: Profile::Standard,
            vm_exports: vec![],
            debug_gate: 3,
            opcode_seed: None,
            trace_diverge: false,
            select_rva: vec![],
            select_functions: Vec::new(),
            select_all: false,
            allow_native_fallback: false,
            strict_coverage: true,
            lazy_regions: false,
            protect_imports: false,
            strict_constants: false,
        }) {
            Ok(_) => panic!("strict empty selection must fail"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("strict coverage"), "{err}");
    }

    #[test]
    #[cfg(windows)]
    fn packed_report_matches_output_directories() {
        let dll = required_sample("hello_dll.dll");
        let out = pack(PackRequest {
            input: &dll,
            profile: Profile::Max,
            vm_exports: vec![],
            debug_gate: 3,
            opcode_seed: None,
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
        .unwrap_or_else(|e| panic!("{e}"));
        let pe = Pe64::parse(&out.image).unwrap();
        let tls = pe
            .directory(IMAGE_DIRECTORY_ENTRY_TLS)
            .map(|d| d.rva != 0 && d.size != 0)
            .unwrap_or(false);
        let reloc = pe
            .directory(IMAGE_DIRECTORY_ENTRY_BASERELOC)
            .map(|d| d.rva != 0 && d.size != 0)
            .unwrap_or(false);
        let orig_pe = Pe64::parse(&dll).unwrap();
        let orig_tls_dir = orig_pe
            .directory(IMAGE_DIRECTORY_ENTRY_TLS)
            .map(|d| d.rva != 0 && d.size != 0)
            .unwrap_or(false);
        let orig_tls_cb = orig_pe.tls_first_callback(&dll).unwrap().is_some();
        assert_eq!(out.report.tls_directory, tls);
        assert_eq!(out.report.tls_directory, orig_tls_dir);
        assert_eq!(out.report.reloc_directory, reloc);
        assert!(out.report.aslr);
        assert!(out.report.reloc_directory);
        assert_eq!(out.report.backend, BACKEND_PIC_STUB);
        let rwx = pe.sections.iter().any(|s| {
            s.characteristics & IMAGE_SCN_MEM_EXECUTE != 0
                && s.characteristics & IMAGE_SCN_MEM_WRITE != 0
        });
        assert_eq!(out.report.long_term_rwx, rwx);
        assert!(!out.report.long_term_rwx);
        let stub = pe.sections.iter().rev().nth(1).expect("stub");
        if orig_tls_cb {
            let (cb_rva, _) = pe.tls_first_callback(&out.image).unwrap().expect("wrapped tls");
            assert!(
                cb_rva >= stub.virtual_address
                    && cb_rva < stub.virtual_address + stub.virtual_size.max(stub.raw_size),
                "first TLS callback must land in the stub"
            );
        } else {
            assert!(
                pe.tls_first_callback(&out.image).unwrap().is_none(),
                "packer must not invent a TLS callback"
            );
        }
    }

    fn minimal_elf64_dyn() -> Vec<u8> {
        let mut elf = vec![0u8; 256];
        elf[0..4].copy_from_slice(b"\x7fELF");
        elf[4] = 2;
        elf[5] = 1;
        elf[6] = 1;
        elf[16..18].copy_from_slice(&3u16.to_le_bytes());
        elf[18..20].copy_from_slice(&62u16.to_le_bytes());
        elf[20..24].copy_from_slice(&1u32.to_le_bytes());
        elf[24..32].copy_from_slice(&0x1000u64.to_le_bytes());
        elf[32..40].copy_from_slice(&64u64.to_le_bytes());
        elf[52..54].copy_from_slice(&64u16.to_le_bytes());
        elf[54..56].copy_from_slice(&56u16.to_le_bytes());
        elf[56..58].copy_from_slice(&2u16.to_le_bytes());
        // PT_LOAD
        elf[64..68].copy_from_slice(&1u32.to_le_bytes());
        elf[68..72].copy_from_slice(&5u32.to_le_bytes());
        elf[88..96].copy_from_slice(&256u64.to_le_bytes());
        elf[96..104].copy_from_slice(&256u64.to_le_bytes());
        elf[104..112].copy_from_slice(&0x1000u64.to_le_bytes());
        // PT_DYNAMIC at file offset 176
        elf[120..124].copy_from_slice(&2u32.to_le_bytes());
        elf[128..136].copy_from_slice(&176u64.to_le_bytes());
        elf[136..144].copy_from_slice(&176u64.to_le_bytes());
        elf[152..160].copy_from_slice(&16u64.to_le_bytes());
        elf[160..168].copy_from_slice(&16u64.to_le_bytes());
        elf
    }

    #[test]
    fn elf_pack_fails_closed() {
        let elf = minimal_elf64_dyn();
        let err = match pack(PackRequest {
            input: &elf,
            profile: Profile::Max,
            vm_exports: vec![],
            debug_gate: 3,
            opcode_seed: None,
            trace_diverge: false,
            select_rva: vec![],
            select_functions: Vec::new(),
            select_all: false,
            allow_native_fallback: false,
            strict_coverage: false,
            lazy_regions: false,
            protect_imports: false,
            strict_constants: false,
        }) {
            Ok(_) => panic!("elf pack must fail closed"),
            Err(err) => err,
        };
        assert!(
            matches!(err, PackError::Elf(_)),
            "well-formed ELF must fail after feature detect, got {err}"
        );
    }

    #[test]
    fn inspect_elf_reports_unpacked() {
        let elf = minimal_elf64_dyn();
        let info = inspect_bytes(&elf).expect("inspect parsed ELF");
        assert_eq!(info["format"], "elf64-dyn");
        assert_eq!(info["packed"], false);
        assert_eq!(info["backend"], "none");
        assert!(info["note"].as_str().unwrap().contains("fail-closes"));
    }

    fn cfg_pack_request(input: &[u8]) -> PackRequest<'_> {
        PackRequest {
            input,
            profile: Profile::Max,
            vm_exports: vec![],
            debug_gate: 3,
            opcode_seed: Some([7; 16]),
            trace_diverge: false,
            select_rva: vec![],
            select_functions: Vec::new(),
            select_all: false,
            allow_native_fallback: false,
            strict_coverage: false,
            lazy_regions: false,
            protect_imports: false,
            strict_constants: false,
        }
    }

    /// Pack a real CFG image and assert the new GFIDS table contains the stub
    /// entry, is sorted, preserves original RVAs, and that load-config still
    /// points at a preferred-base VA (DIR64 will fix it at load).
    #[test]
    #[cfg(windows)]
    fn packed_cfg_image_registers_stub_entry_in_gfids() {
        // A tiny committed /guard:cf build: the test must not depend on
        // scratch files that only exist on a developer machine.
        let bytes = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/cfg_smoke.exe"
        ))
        .expect("tests/fixtures/cfg_smoke.exe");
        let orig = Pe64::parse(&bytes).unwrap();
        let orig_cfg = orig.load_config_cfg(&bytes).unwrap().unwrap();
        let orig_table = orig.gfids_table(&bytes, &orig_cfg).unwrap();
        let orig_count = orig_table.len();

        let packed = pack(cfg_pack_request(&bytes)).unwrap_or_else(|e| panic!("{e}"));
        let pe = Pe64::parse(&packed.image).unwrap();
        assert_ne!(pe.entry_rva, orig.entry_rva, "packed entry must be the stub");
        let cfg = pe
            .load_config_cfg(&packed.image)
            .unwrap()
            .expect("packed load-config");
        assert_eq!(
            cfg.guard_flags & IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT,
            IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT
        );
        assert_eq!(
            cfg.table_va_file_offset, orig_cfg.table_va_file_offset,
            "GuardCFFunctionTable field offset must stay put so DIR64 still covers it"
        );
        let table = pe.gfids_table(&packed.image, &cfg).unwrap();
        assert!(
            table.len() > orig_count,
            "packed GFIDS must grow (orig {orig_count}, now {})",
            table.len()
        );
        assert_eq!(cfg.function_count, table.len() as u64);
        assert!(
            table.windows(2).all(|w| w[0].rva <= w[1].rva),
            "packed GFIDS must stay sorted"
        );
        assert!(
            table.iter().any(|e| e.rva == pe.entry_rva),
            "stub entry {:#x} missing from packed GFIDS",
            pe.entry_rva
        );
        for old in &orig_table {
            assert!(
                table.iter().any(|e| e.rva == old.rva),
                "original GFIDS rva {:#x} dropped",
                old.rva
            );
        }
        // New table VA is preferred-base + payload RVA, not an RVA stuffed into
        // a VA-typed field.
        let payload = pe.sections.last().expect("payload");
        let table_rva = u32::try_from(cfg.table_va.wrapping_sub(pe.image_base))
            .expect("GuardCFFunctionTable VA must be image_base + RVA");
        assert_eq!(
            cfg.table_va,
            pe.image_base.wrapping_add(u64::from(table_rva)),
            "GuardCFFunctionTable must stay a preferred-base VA"
        );
        assert!(
            table_rva >= payload.virtual_address
                && table_rva < payload.virtual_address + payload.virtual_size.max(payload.raw_size),
            "new GFIDS must live in the plaintext payload section"
        );
        // CFG forwarder section stays on disk: sealing it plants INT3s on the
        // loader's pre-entry dispatch path.
        if let Some(orig_fothk) = orig.sections.iter().find(|s| s.name_str() == "fothk") {
            let packed_fothk = pe
                .sections
                .iter()
                .find(|s| s.name_str() == "fothk")
                .expect("fothk survives packing");
            let o_off = orig_fothk.raw_ptr as usize;
            let p_off = packed_fothk.raw_ptr as usize;
            let n = orig_fothk.raw_size.min(orig_fothk.virtual_size) as usize;
            assert_eq!(
                &bytes[o_off..o_off + n],
                &packed.image[p_off..p_off + n],
                "fothk must remain plaintext"
            );
        }
        // Check/dispatch gadgets (`ret 0` / `jmp rax`) stay on disk too.
        for (slot, what) in [
            (orig_cfg.check_function_slot_va, "check"),
            (orig_cfg.dispatch_function_slot_va, "dispatch"),
        ] {
            let Some(rva) = orig
                .load_config_guard_target_rva(&bytes, slot, what)
                .unwrap()
            else {
                continue;
            };
            let o_off = orig.file_offset_of(rva).unwrap();
            let p_off = pe.file_offset_of(rva).unwrap();
            assert_eq!(
                packed.image[p_off], bytes[o_off],
                "{what} gadget at rva {rva:#x} must remain plaintext"
            );
            assert_ne!(
                packed.image[p_off], 0xCC,
                "{what} gadget at rva {rva:#x} was sealed to INT3"
            );
        }
    }

    #[test]
    #[cfg(windows)]
    fn non_cfg_hello_exe_still_packs() {
        let bytes = required_sample("hello-exe.exe");
        let orig = Pe64::parse(&bytes).unwrap();
        assert_eq!(orig.dll_characteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF, 0);
        let packed = pack(cfg_pack_request(&bytes)).unwrap_or_else(|e| panic!("{e}"));
        let pe = Pe64::parse(&packed.image).unwrap();
        assert_ne!(pe.entry_rva, orig.entry_rva);
        // INSTRUMENTED-without-table images must not grow a fake GFIDS.
        if let Some(cfg) = pe.load_config_cfg(&packed.image).unwrap() {
            assert_eq!(cfg.function_count, 0);
            assert_eq!(cfg.table_va, 0);
        }
    }

    #[test]
    #[cfg(windows)]
    fn cfg_xfg_plan_fails_closed_on_real_layout() {
        let mut bytes = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/cfg_smoke.exe"
        ))
        .expect("tests/fixtures/cfg_smoke.exe");
        let pe = Pe64::parse(&bytes).unwrap();
        let cfg = pe.load_config_cfg(&bytes).unwrap().unwrap();
        let xfg = cfg.guard_flags | IMAGE_GUARD_XFG_ENABLED;
        bytes[cfg.flags_file_offset..cfg.flags_file_offset + 4]
            .copy_from_slice(&xfg.to_le_bytes());
        let pe = Pe64::parse(&bytes).unwrap();
        let err = match plan_cfg_rewrite(&pe, &bytes) {
            Err(e) => e,
            Ok(_) => panic!("XFG image must fail closed"),
        };
        assert!(
            err.to_string().contains("IMAGE_GUARD_XFG_ENABLED"),
            "{err}"
        );
        let err = match pack(cfg_pack_request(&bytes)) {
            Err(e) => e,
            Ok(_) => panic!("XFG pack must fail closed"),
        };
        assert!(
            err.to_string().contains("IMAGE_GUARD_XFG_ENABLED"),
            "{err}"
        );
    }
}

#[cfg(test)]
mod envelope_probe {
    use super::*;

    #[test]
    #[cfg(windows)]
    fn select_all_records_unwind_coverage() {
        let dll = std::fs::read("target/release/hello_dll.dll")
            .or_else(|_| std::fs::read("../../target/release/hello_dll.dll"))
            .expect("hello_dll");
        let out = pack(PackRequest {
            input: &dll,
            profile: Profile::Standard,
            vm_exports: vec![],
            debug_gate: 3,
            opcode_seed: None,
            trace_diverge: false,
            select_rva: vec![],
            select_functions: Vec::new(),
            select_all: true,
            allow_native_fallback: true,
            strict_coverage: false,
            lazy_regions: false,
            protect_imports: false,
            strict_constants: false,
        })
        .expect("select-all fallback pack");
        assert!(!out.report.coverage.is_empty());
        assert!(out.report.coverage.iter().any(|c| c.bucket == "transformed"));
        assert!(
            out.report
                .coverage
                .iter()
                .any(|c| matches!(c.source, BoundarySource::Unwind)),
            "select-all must report .pdata-discovered functions"
        );
        let transformed = out
            .report
            .coverage
            .iter()
            .filter(|c| c.bucket == "transformed")
            .count();
        assert_eq!(out.report.vm_functions, transformed);
    }

    #[test]
    fn elf_select_all_fallback_reports_mixed_native() {
        let Some(elf) = [
            "target/hello-elf",
            "../../target/hello-elf",
            "samples/hello-elf/hello-elf",
        ]
        .iter()
        .find_map(|p| std::fs::read(p).ok())
        else {
            eprintln!("SKIP: hello-elf sample was not built in this checkout");
            return;
        };
        let out = pack(PackRequest {
            input: &elf,
            profile: Profile::Standard,
            vm_exports: vec![],
            debug_gate: 3,
            opcode_seed: None,
            trace_diverge: false,
            select_rva: vec![],
            select_functions: Vec::new(),
            select_all: true,
            allow_native_fallback: true,
            strict_coverage: false,
            lazy_regions: false,
            protect_imports: false,
            strict_constants: false,
        })
        .expect("ELF select-all fallback pack");
        assert_eq!(out.report.vm_functions, 0);
        assert!(
            out.report
                .coverage
                .iter()
                .all(|c| c.bucket == "mixed_native" && !c.reason.is_empty()),
            "ELF selection must report mixed_native, got {:?}",
            out.report
                .coverage
                .iter()
                .map(|c| (&c.name, &c.bucket))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    #[cfg(windows)]
    fn walk_envelope_like_stub() {
        let dll = std::fs::read("target/release/hello_dll.dll")
            .or_else(|_| std::fs::read("../../target/release/hello_dll.dll"))
            .unwrap_or_else(|e| {
                panic!(
                    "missing required sample hello_dll.dll ({e}). \
                     cargo build -p hello-dll --release first. Missing sample is a FAIL."
                )
            });
        let out = pack(PackRequest {
            input: &dll,
            profile: Profile::Standard,
            vm_exports: vec![],
            debug_gate: 3,
            opcode_seed: None,
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
        .unwrap();
        let pe = Pe64::parse(&out.image).unwrap();
        // Envelope lives at the last section (payload; stub is second to last).
        let payload = pe.sections.last().expect("payload section");
        let off = payload.raw_ptr as usize;
        let env = &out.image[off..];
        assert_eq!(&env[0..4], b"XLV2");
        let parsed = xenolith_protocol::parse(env).expect("EnvelopeV2");
        println!(
            "v2 regions={} imports={} keep={}",
            parsed.regions.len(),
            parsed.imports.len(),
            parsed.keep.len()
        );
        assert!(!parsed.regions.is_empty());
        let mut src = out.packed.mba.as_bytes();
        src.extend_from_slice(&out.packed.opcode_seed);
        src.extend_from_slice(&(out.packed.pages.len() as u32).to_le_bytes());
        let measurement = xenolith_crypto::image_measurement(&src);
        let key = xenolith_crypto::mix_runtime_key(&out.packed.mba, &measurement).unwrap();
        let pt = xenolith_protocol::open_region(&key, &parsed, &parsed.regions[0]).unwrap();
        assert_eq!(pt.len(), parsed.regions[0].len as usize);
    }

    #[test]
    #[cfg(windows)]
    fn v2_host_open_matches_original_page() {
        let dll = std::fs::read("target/release/hello_dll.dll")
            .or_else(|_| std::fs::read("../../target/release/hello_dll.dll"))
            .expect("hello_dll");
        let out = pack(PackRequest {
            input: &dll,
            profile: Profile::Standard,
            vm_exports: vec![],
            debug_gate: 3,
            opcode_seed: Some([9; 16]),
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
        .unwrap();
        let pe = Pe64::parse(&out.image).unwrap();
        let payload = pe.sections.last().unwrap();
        let env = &out.image[payload.raw_ptr as usize..];
        let parsed = xenolith_protocol::parse(env).unwrap();
        let mut src = out.packed.mba.as_bytes();
        src.extend_from_slice(&out.packed.opcode_seed);
        src.extend_from_slice(&(out.packed.pages.len() as u32).to_le_bytes());
        let measurement = xenolith_crypto::image_measurement(&src);
        let key = xenolith_crypto::mix_runtime_key(&out.packed.mba, &measurement).unwrap();
        assert!(!parsed.regions.is_empty());
        for r in &parsed.regions {
            let pt = xenolith_protocol::open_region(&key, &parsed, r).expect("host open");
            assert_eq!(pt.len(), r.len as usize);
        }
        let mut tampered = parsed.regions[0].clone();
        tampered.tag[0] ^= 1;
        assert!(xenolith_protocol::open_region(&key, &parsed, &tampered).is_err());
        assert!(xenolith_protocol::parse(b"NSEN\x01\x00").is_err());
        let mut bad = env.to_vec();
        bad[0] = b'Y';
        assert!(xenolith_protocol::parse(&bad).is_err());
    }
}
