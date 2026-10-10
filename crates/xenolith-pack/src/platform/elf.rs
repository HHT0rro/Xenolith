//! ELF64 AMD64/AArch64 pack backend: INIT_ARRAY[0] bootstrap.
//!
//! ld.so (glibc on Linux, bionic on Android) stays the loader of record:
//! PIE/RELRO/GOT-PLT are untouched. Packing appends one R+X PT_LOAD
//! (bootstrap PHDR table + PIC stub + xl_core + EnvelopeV2), redirects
//! INIT_ARRAY[0]'s RELATIVE addend into the stub, and seals every executable
//! PT_LOAD's file bytes in AEAD records (disk holds 0x90). The stub unpacks
//! during init — before the original INIT_ARRAY[0] target, before the ELF
//! entry — then forwards.
//!
//! Android (design .apk-compat/xenolith/design.md):
//! - aarch64 (EM_AARCH64) uses the `stub_aarch64` emitter and the
//!   NDK-compiled arm64 core; x86_64 reuses the existing x86-64 ELF path
//!   (stub/machine code/__NR_mprotect are identical on Linux and bionic).
//! - Page size is derived from the input (`clamp(max PT_LOAD.p_align, 4K,
//!   16K)`) and threads through chunking, sealing, the appended PT_LOAD's
//!   congruence, the resolver carve-outs, the protocol gates and the stub's
//!   vprotect alignment (META_PAGE_SIZE) — 16-KiB-page devices load packed
//!   images without a single hardcoded 4096.
//!
//! Fail-closed (named): static linkage (no PT_DYNAMIC), TPOFF32/TLSLE-in-text
//! entries that target executable text, RELATIVE entries that target
//! encrypted pages (ld.so applies them before init), RELR/packed-relocation
//! inputs (formats layer), aarch64 PIE executables (PT_INTERP), p_align
//! above 16 KiB, `--lazy-regions`, DT_INIT+DT_INIT_ARRAY coexistence (the
//! rewrite drops DT_INIT — silently discarding a real DT_INIT function is a
//! semantic change, so the input shape is refused instead).

use crate::lift::forbidden_vm_rule;
use crate::lift_aarch64::{lift_function_aarch64, LiftedExport64};
use crate::runtime_image::{self, CoreArch};
use crate::stub::{emit_elf_stub, META_ENVELOPE_LEN, META_MEASUREMENT, META_ORIGINAL_ENTRY,
    META_PAGE_SIZE, META_PAYLOAD_RVA, META_SELF_RVA, META_TABLE_RVA, META_UNPACKED,
    STUB_META_LEN};
use crate::stub_aarch64::emit_elf_stub_aarch64;
use crate::{PackError, PackOutput, PackRequest, BACKEND_PIC_STUB, PACK_REPORT_VERSION};
use xenolith_crypto::{
    image_measurement, random_nonce12, random_seed16, MbaKeyShare, Secret32,
};
use xenolith_formats::{
    align_up, elf, elf::ElfMachine, write_u64, classify, ImageKind,
};
use xenolith_loader::{section_name_from_seed, PackedImage, PageRecord, Profile};
use xenolith_protocol::{
    encode as encode_v2, seal_region, EnvelopeV2, PLATFORM_ELF64, PLATFORM_ELF64_AARCH64,
    POLICY_STRICT,
};
use xenolith_guard::{android_probe_mask, android_probes_for_profile, probe_name, Probe};
use xenolith_vm::superop_aarch64::{emit_superop_aarch64, SuperopAarch64Options};
use xenolith_vm::{OpcodeMap, Program};

pub fn pack_elf(request: &PackRequest<'_>) -> Result<PackOutput, PackError> {
    let kind = match classify(request.input) {
        Ok(k @ (ImageKind::Elf64Exec | ImageKind::Elf64Dyn)) => k,
        Ok(_) => return Err(PackError::Elf("not an ELF64 AMD64/AArch64 image")),
        Err(e) => return Err(PackError::Format(e)),
    };
    let parsed = elf::parse(request.input).map_err(PackError::Format)?;
    let machine = parsed.machine;

    // ---- Android fail-closed gates (design §0 non-goals, A-7) ----
    if machine == ElfMachine::Aarch64 && parsed.interp {
        return Err(PackError::Elf(
            "aarch64 input carries PT_INTERP (PIE executable): only ET_DYN \
             shared objects (.so, no PT_INTERP) are packed in this release — \
             dlopen objects depend solely on e_phoff, which the appended \
             PT_LOAD strategy preserves",
        ));
    }
    if request.lazy_regions {
        return Err(PackError::Invalid(
            "lazy regions require the G5 fault-wake runtime (not available on \
             ELF in this release): dormant pages would SIGSEGV with no wake \
             handler — pack without --lazy-regions",
        ));
    }

    // ---- page-size derivation (A-3) ----
    let phdrs = elf::program_headers(request.input, &parsed).map_err(PackError::Format)?;
    let mut max_align: u64 = 0;
    for ph in &phdrs {
        if ph.p_type == elf::PT_LOAD {
            max_align = max_align.max(ph.p_align);
        }
    }
    if max_align > 0x4000 {
        return Err(PackError::Elf(
            "ELF PT_LOAD alignment exceeds 16 KiB: only 4-KiB/16-KiB page \
             granularities exist on supported targets (Linux x86-64, Android)",
        ));
    }
    let page_size = (max_align.clamp(0x1000, 0x4000)) as u32;
    let page_mask = !(page_size - 1);

    // TASK-022: PT_TLS is allowed. ld.so finishes TLS setup (DTPMOD/DTPREL/
    // GOTTPOFF into the RW GOT) before INIT_ARRAY, and we only seal RX
    // pages, so initial-exec and local/general-dynamic models survive.
    // TPOFF32-in-text and TLS descriptors stay rejected in formats::scan_rela.
    let tls_census = elf::tls_reloc_census(request.input, &parsed).map_err(PackError::Format)?;
    // IFUNC resolvers run during ld.so relocation — before our INIT_ARRAY
    // bootstrap — so pages containing them must stay native plaintext.
    let mut resolvers = elf::ifunc_resolvers(request.input, &parsed).map_err(PackError::Format)?;
    // GLOB_DAT against a defined IFUNC also forces resolution at load time.
    resolvers.extend(
        elf::ifunc_symbol_values(request.input, &parsed).map_err(PackError::Format)?,
    );
    // Carve-outs are chunk-granular (A-3 resolver-mask covariant): a 16-KiB
    // seal unit cannot leave a 4-KiB plaintext window inside it; the
    // pack-time mask below uses `page_mask`.
    let (verneed, verdef) = elf::symbol_versions(request.input, &parsed).map_err(PackError::Format)?;
    // Bootstrap rides INIT_ARRAY[0]: ld.so applies its R_<ARCH>_RELATIVE
    // before running any init code, so redirecting the addend to the stub is
    // ASLR-proof and avoids the DT_INIT path entirely (the loader gates the
    // DT_INIT call on the un-corrupted entry-region bytes, which a packed
    // image cannot guarantee; verified empirically on glibc 2.39).
    let boot = init_array_bootstrap(request.input, &parsed)?;
    let rx = elf::rx_load_ranges(request.input, &parsed).map_err(PackError::Format)?;
    if rx.is_empty() {
        return Err(PackError::Elf("ELF has no executable PT_LOAD to protect"));
    }
    // Loader-metadata carve-outs (merged-segment layouts): ld.so parses the
    // ELF header/phdrs, PT_DYNAMIC and every dynamic-pointed table BEFORE
    // any INIT_ARRAY code runs. NDK `--no-rosegment`-style links place that
    // metadata inside the executable PT_LOAD — sealing those bytes on disk
    // garbles NEEDED/symbol parsing and dlopen fails before the stub can
    // restore anything. Page-granular exclusion, same mechanism as the
    // resolver carve-outs; split layouts (metadata in an R LOAD) no-op.
    let metadata_pages: Vec<u32> = {
        let ranges =
            elf::loader_metadata_file_ranges(request.input, &parsed).map_err(PackError::Format)?;
        let mut v: Vec<u32> = Vec::new();
        for (foff, flen) in &ranges {
            let mut o = *foff;
            let end = foff + flen;
            while o < end {
                if let Some(va) = file_off_to_vaddr(&rx, o) {
                    let pg = (va as u32) & page_mask;
                    if !v.contains(&pg) {
                        v.push(pg);
                    }
                }
                o = ((o / page_size as usize) + 1) * page_size as usize;
            }
        }
        v
    };
    let selection_requested = !request.select_functions.is_empty() || request.select_all
        || !request.vm_exports.is_empty()
        || !request.select_rva.is_empty();

    // ---- function selection gate (vm-aarch64 design §8.2) ----
    // aarch64 runs the new whitelist lift pipeline; x86-64 ELF keeps the
    // named SysV-lift rejection. PE behavior is untouched (different path).
    let mut vm64: Vec<LiftedExport64> = Vec::new();
    // Derived ONCE per request (see the sizing-pass comment below for why).
    let opcode_seed_once = opcode_seed_for(request);
    let mut vm_coverage: Vec<crate::FunctionCoverageRecord> = Vec::new();
    let mut vm_selected: Vec<String> = Vec::new();
    let mut vm_thunk_words: Vec<Vec<u32>> = Vec::new();
    // The hooked working buffer: every later stage (page sealing, 0x90 fill,
    // output assembly) reads this so hook bytes travel inside the sealed
    // pages (design §5.4 — seal reads the patched buffer).
    let mut working = request.input.to_vec();
    if machine == ElfMachine::Aarch64 {
        if !request.vm_exports.is_empty() && request.profile == Profile::Fast {
            return Err(PackError::Invalid("vm-export requires standard or max"));
        }
        if selection_requested {
            let selected =
                resolve_elf_selection(request, request.input, &parsed, &resolvers)?;
            for func in selected {
                vm_selected.push(func.name.clone());
                match lift_function_aarch64(
                    &parsed,
                    request.input,
                    &func.name,
                    func.rva,
                    func.len,
                    &resolvers,
                ) {
                    Ok(f) => {
                        vm_coverage.push(crate::FunctionCoverageRecord {
                            name: func.name.clone(),
                            rva: func.rva,
                            len: func.len,
                            source: func.source,
                            bucket: "transformed".into(),
                            reason: String::new(),
                        });
                        vm64.push(f);
                    }
                    Err(e) if request.allow_native_fallback && !request.strict_coverage => {
                        vm_coverage.push(crate::FunctionCoverageRecord {
                            name: func.name.clone(),
                            rva: func.rva,
                            len: func.len,
                            source: func.source,
                            bucket: if e.0.contains("boundary")
                                || e.0.contains("out of lift window")
                                || e.0.contains("lift cap")
                            {
                                "boundary_uncertain".into()
                            } else {
                                "mixed_native".into()
                            },
                            reason: e.0.clone(),
                        });
                    }
                    Err(e) => return Err(PackError::Lift(e.0)),
                }
            }
            if request.strict_coverage {
                let failed: Vec<&crate::FunctionCoverageRecord> = vm_coverage
                    .iter()
                    .filter(|r| r.bucket != "transformed")
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
                         (drop --strict-coverage, use --allow-native-fallback, or pick \
                         functions the lifter supports):\n{detail}",
                        failed.len()
                    )));
                }
            }
            // Inner-label reference scans (design §5.2) run before hooking.
            let windows: Vec<(u32, usize)> =
                vm64.iter().map(|f| (f.rva, f.native_len)).collect();
            scan_inner_label_refs(request.input, &parsed, &rx, &windows)?;
            // Sizing pass: thunk word counts are rva-independent (the bias
            // constant materialization is fixed-width), so rva=0 output
            // sizes the layout deterministically. The seed is derived ONCE
            // per request: opcode_seed_for() draws from the crypto RNG when
            // --seed-hex is absent, so per-call derivation gave the sizing
            // and real passes different register allocations (and word
            // counts) -- the "changed size" packer error.
            for (i, f) in vm64.iter().enumerate() {
                let mut seed = opcode_seed_once;
                seed[0] ^= (i as u8).wrapping_add(1);
                let words = emit_superop_aarch64(
                    &f.ir,
                    &seed,
                    &SuperopAarch64Options { thunk_rva: 0 },
                )
                .map_err(|e| {
                    PackError::Stub(format!(
                        "vm {} (rva {:#x}): {e}",
                        f.name, f.rva
                    ))
                })?;
                vm_thunk_words.push(words);
            }
        }
    } else if !request.vm_exports.is_empty() || !request.select_rva.is_empty() {
        return Err(PackError::Invalid(
            "ELF x86-64 function selection requires the SysV x86-64 lift (stage 5); \
             fail-closed here",
        ));
    } else if request.strict_coverage {
        return Err(PackError::Invalid(
            "strict coverage has no selected functions on x86-64 ELF in this release",
        ));
    } else if selection_requested && !request.allow_native_fallback {
        return Err(PackError::Invalid(
            "ELF x86-64 symbol selection requires --allow-native-fallback until the SysV \
             x86-64 lift lands",
        ));
    }
    fail_closed_on_relative_into_rx(request.input, &parsed, &rx)?;

    let secret = Secret32::random();
    let opcode_seed = request.opcode_seed.unwrap_or_else(random_seed16);
    let api_salt = random_seed16();
    let mba = MbaKeyShare::split(&secret, &opcode_seed);
    let map = OpcodeMap::from_seed(&opcode_seed);
    let program = Program::encode_key_mix(map, &mba);

    // ---- Android anti-debug probe policy (plan WS-A 2.2.3) ----
    // aarch64: profile-defaulted Android set (Max = TracerPid + Maps;
    // otherwise TracerPid only). PtraceSelfAttach is implemented but never
    // profile-armed: TRACEME on this dlopen/INIT_ARRAY thread makes the
    // parent (zygote on real apps) the thread's tracer with no tracee-side
    // detach, and the next signal on the thread freezes the app (see
    // `android_probes_for_profile`). x86-64-ELF: none -- probes are
    // aarch64-only in this release and the report says so explicitly (no
    // fake pass-through of the Windows claim).
    let android_probes: Vec<Probe> = match machine {
        ElfMachine::Aarch64 => android_probes_for_profile(request.profile == Profile::Max),
        ElfMachine::Amd64 => Vec::new(),
    };
    let probe_mask = android_probe_mask(&android_probes);

    // ---- core object + stub emitter dispatch (A-1/A-4) ----
    let stub = match machine {
        ElfMachine::Amd64 => {
            let core_img = runtime_image::load_builtin(CoreArch::X8664)
                .map_err(|e| PackError::Runtime(e.to_string()))?;
            emit_elf_stub(&core_img.text, core_img.entry_off, core_img.sysv_abi)
                .map_err(PackError::Stub)?
        }
        ElfMachine::Aarch64 => {
            let core_img = runtime_image::load_builtin(CoreArch::Aarch64)
                .map_err(|e| PackError::Runtime(e.to_string()))?;
            if vm_thunk_words.is_empty() {
                emit_elf_stub_aarch64(&core_img.text, core_img.entry_off, probe_mask, &[])
                    .map_err(PackError::Stub)?
            } else {
                // Layout arithmetic mirrored from below (input-only inputs):
                // the appended LOAD starts at load_vaddr; the stub's code
                // starts after the relocated PHDR table.
                let max_va_end = elf::max_load_vaddr_end(request.input, &parsed)
                    .map_err(PackError::Format)?;
                let load_vaddr = align_up(max_va_end as u32, page_size) as u64;
                let table_len =
                    (parsed.phnum as usize + 2) * parsed.phentsize as usize;
                let stub_vaddr = load_vaddr + table_len as u64;
                // Sizing emission gives the in-stub guest offsets.
                let sized = emit_elf_stub_aarch64(
                    &core_img.text,
                    core_img.entry_off,
                    probe_mask,
                    &vm_thunk_words,
                )
                .map_err(PackError::Stub)?;
                // Real pass: re-emit every thunk at its true RVA (word counts
                // are rva-independent by construction).
                for (i, f) in vm64.iter().enumerate() {
                    let thunk_rva =
                        stub_vaddr + sized.guest_thunk_offs[i] as u64;
                    let mut seed = opcode_seed_once;
                    seed[0] ^= (i as u8).wrapping_add(1);
                    let words = emit_superop_aarch64(
                        &f.ir,
                        &seed,
                        &SuperopAarch64Options {
                            thunk_rva: thunk_rva as u32,
                        },
                    )
                    .map_err(|e| {
                        PackError::Stub(format!(
                            "vm {} (rva {:#x}): {e}",
                            f.name, f.rva
                        ))
                    })?;
                    if words.len() != vm_thunk_words[i].len() {
                        return Err(PackError::Stub(format!(
                            "guest thunk {} changed size between the sizing and real \
                             emission passes ({} vs {} words) — packer bug; report with \
                             the input image",
                            f.name,
                            vm_thunk_words[i].len(),
                            words.len()
                        )));
                    }
                    vm_thunk_words[i] = words;
                }
                let stub = emit_elf_stub_aarch64(
                    &core_img.text,
                    core_img.entry_off,
                    probe_mask,
                    &vm_thunk_words,
                )
                .map_err(PackError::Stub)?;
                // Hook the selected entries into the working buffer (§5.3):
                // 4-byte `b rel26` + brk fill, before page extraction below.
                for (i, f) in vm64.iter().enumerate() {
                    let target = stub_vaddr + stub.guest_thunk_offs[i] as u64;
                    apply_vm_hook_elf(
                        &mut working,
                        &parsed,
                        request.input,
                        &f.name,
                        f.rva,
                        f.native_len,
                        target,
                    )?;
                }
                if vm64.len() != stub.guest_thunk_offs.len() {
                    return Err(PackError::Stub(format!(
                        "guest thunk count mismatch: {} lifted functions but the stub \
                         emitted {} thunks (packer bug; report with the input image)",
                        vm64.len(),
                        stub.guest_thunk_offs.len()
                    )));
                }
                stub
            }
        }
    };

    // Pages: every executable PT_LOAD's file bytes, chunked at page_size.
    // ld.so has applied relocations before init, so RELATIVE targets inside
    // these ranges were rejected above; everything else here is link-time
    // stable. 16-KiB chunks are within the protocol's XL_MAX_REGION gate.
    let mut pages = Vec::new();
    let mut page_files: Vec<(usize, usize)> = Vec::new();
    let mut page_index = 0u32;
    for (va, va_end, off, len) in &rx {
        let mut o = 0usize;
        while o < *len {
            let chunk = (*len - o).min(page_size as usize);
            let pg = ((va + o as u64) as u32) & page_mask;
            if metadata_pages.contains(&pg) {
                // Loader metadata stays native plaintext (not sealed, not
                // wiped) — ld.so must parse it before init runs.
                o += chunk;
                continue;
            }
            pages.push((
                page_index,
                (va + o as u64) as u32,
                working[off + o..off + o + chunk].to_vec(),
                random_nonce12(),
            ));
            page_files.push((off + o, chunk));
            page_index += 1;
            o += chunk;
        }
        let _ = va_end;
    }
    if pages.len() > xenolith_loader::MAX_PAGES {
        return Err(PackError::Stub(format!(
            "too many pages: {} > {} (executable bytes ≈ {} KiB); the loader envelope \
             caps a packed image at {} page records — split the binary or exclude \
             PT_LOAD segments from packing",
            pages.len(),
            xenolith_loader::MAX_PAGES,
            pages.len() * (page_size as usize / 1024),
            xenolith_loader::MAX_PAGES
        )));
    }

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

    let mut mba_arr = [0u8; 96];
    mba_arr.copy_from_slice(&mba.as_bytes());
    let mut env_v2 = EnvelopeV2 {
        // Platform byte is authenticated in every region AAD: arm64
        // envelopes (2) fail closed in every older core/CLI (A-2).
        platform: match machine {
            ElfMachine::Amd64 => PLATFORM_ELF64,
            ElfMachine::Aarch64 => PLATFORM_ELF64_AARCH64,
        },
        profile: request.profile as u8,
        flags: 0,
        policy: POLICY_STRICT,
        mba: mba_arr,
        opcode_seed,
        api_salt,
        opcode_map: [
            map.load_imm, map.add, map.xor, map.mul, map.jz, map.jmp, map.halt, map.mix_key,
        ],
        stolen: Vec::new(),
        program: program.code.clone(),
        regions: Vec::new(),
        imports: Vec::new(),
        keep: Vec::new(),
        // ELF never carries dormant regions (A-7: --lazy-regions is refused
        // above); the G5 table stays empty.
        lazy: Vec::new(),
        // ELF: ld.so applied all relocations before init; the core must
        // not re-apply anything (PE DIR64 replay runs for platform==0 only).
        relocs: Vec::new(),
    };
    let mut records = Vec::new();
    for (index, rva, plain, _seed_nonce) in &pages {
        let nonce = random_nonce12();
        let sealed = seal_region(&runtime, &env_v2, *index, *rva, plain, nonce)?;
        let mut mac = [0u8; 32];
        mac[..16].copy_from_slice(&sealed.tag);
        records.push(PageRecord {
            index: *index,
            original_rva: *rva,
            original_len: plain.len() as u32,
            nonce,
            mac,
            stub_digest: 0,
        });
        env_v2.regions.push(sealed);
    }
    let envelope = encode_v2(&env_v2)?;
    let imports_kept_count = env_v2.imports.len();
    // The regions' ciphertext now lives in `envelope`; free the envelope-side
    // copy before the output image is assembled (same bytes would otherwise
    // be held twice through the whole tail of the pack).
    drop(env_v2);

    // ---- append the new R+X PT_LOAD ----
    // Layout: [original file, section headers included] pad → new PHDR table
    // (original entries + one new LOAD) → PIC stub → EnvelopeV2. The kernel
    // maps via e_phoff (updated); the in-image PT_PHDR copy keeps the
    // original 13 entries for ld.so, so glibc/bionic's view of segments is
    // unchanged — it simply never needs to know about the stub LOAD.
    let phentsize = parsed.phentsize as usize;
    let phnum = parsed.phnum as usize;
    // +1 for the appended R+X PT_LOAD, +1 for the appended PT_GNU_EH_FRAME
    // carrying the stub's unwind records (TASK-021).
    let table_len = (phnum + 2) * phentsize;
    let new_phoff = align_up(request.input.len() as u32, page_size) as usize;
    let stub_off = new_phoff + table_len;
    let env_off = align_up((stub_off + stub.bytes.len()) as u32, 16) as usize;
    // TASK-021: self-contained .eh_frame (CIE+FDE for the stub) and an
    // .eh_frame_hdr binary-search table, both offset-embedded so the
    // unwinder needs zero ld.so relocations. The CIE return register is
    // per-arch (RAX vs x30).
    let eh = match machine {
        ElfMachine::Amd64 => crate::unwind::dwarf::eh_frame_stub(stub.bytes.len() as u32),
        ElfMachine::Aarch64 => {
            crate::unwind::dwarf::eh_frame_stub_aarch64(stub.bytes.len() as u32)
        }
    };
    let eh_off = align_up((env_off + envelope.len()) as u32, 8) as usize;
    let hdr = crate::unwind::dwarf::eh_frame_hdr(&[]);
    let hdr_off = eh_off + eh.bytes.len();
    // seg_filesz is finalized AFTER the content is placed: it must satisfy
    // bionic's hard `p_offset + p_filesz <= file size` check exactly (the
    // historical value was the page-aligned ABSOLUTE end of the file, added
    // on top of p_offset — double-counting the prefix and overshooting EOF
    // by up to a page; glibc silently zero-fills that, bionic refuses).

    let max_va_end =
        elf::max_load_vaddr_end(request.input, &parsed).map_err(PackError::Format)?;
    let load_vaddr = align_up(max_va_end as u32, page_size) as u64;

    let mut image = working;
    image.resize(new_phoff, 0);
    image.resize(new_phoff + table_len, 0);
    let phdrs =
        elf::program_headers(request.input, &parsed).map_err(PackError::Format)?;
    // The relocated table lives at new_phoff; only e_phoff/e_phnum point at it.
    let parsed_new = elf::Elf64 {
        phoff: new_phoff as u64,
        phnum: (phnum + 2) as u16,
        ..parsed.clone()
    };
    for (i, ph) in phdrs.iter().enumerate() {
        elf::write_program_header(&mut image, &parsed_new, i, ph).map_err(PackError::Format)?;
    }
    // Kernel auxv: AT_PHDR = bias + PT_PHDR.p_vaddr, AT_PHNUM = e_phnum. The
    // table must be self-consistent or ld.so reads one entry past the old
    // table (INTERP bytes) as a header. Point PT_PHDR at the relocated copy.
    // Executables only: dlopen'd objects have no PT_PHDR (ld.so reads their
    // phdrs straight from the file at e_phoff, which we already updated).
    let phdr_idx = phdrs
        .iter()
        .position(|ph| ph.p_type == elf::PT_PHDR);
    if parsed.interp {
        let phdr_idx = phdr_idx.ok_or(PackError::Elf(
            "PIE executable has no PT_PHDR; auxv phdr walk cannot be kept consistent",
        ))?;
        let phdr_ph = elf::ProgramHeader {
            p_type: elf::PT_PHDR,
            p_flags: elf::PF_R,
            p_offset: new_phoff as u64,
            p_vaddr: load_vaddr,
            p_paddr: load_vaddr,
            p_filesz: table_len as u64,
            p_memsz: table_len as u64,
            p_align: 8,
        };
        elf::write_program_header(&mut image, &parsed_new, phdr_idx, &phdr_ph)
            .map_err(PackError::Format)?;
    }
    // `hdr` here is the zero-entry placeholder sizing the segment; the real
    // one-entry header is written later once stub_vaddr is known.
    let hdr_placeholder_len = hdr.len();
    image.resize(hdr_off + hdr_placeholder_len.max(4 + 4 + 4 + 8), 0);
    image[stub_off..stub_off + stub.bytes.len()].copy_from_slice(&stub.bytes);
    image[env_off..env_off + envelope.len()].copy_from_slice(&envelope);
    let envelope_len = envelope.len();
    drop(envelope);

    // In the new segment, va = base + p_vaddr + (file_off - p_offset); the
    // bootstrap table precedes the stub, so add table_len to every stub-file
    // offset when converting to a load-relative VA.
    let stub_vaddr = load_vaddr + table_len as u64 + stub.entry_off as u64;
    let self_rva = (load_vaddr + table_len as u64 + stub.meta_off as u64) as u32;

    // TASK-021: emit the .eh_frame + .eh_frame_hdr and the PT_GNU_EH_FRAME
    // exposing them. All encodings are pack-time constants: pc_begin is
    // pcrel within the appended segment; the search table is datarel
    // (object-base = load-relative RVA).
    let eh_frame_rva = (load_vaddr + (eh_off - new_phoff) as u64) as u32;
    let hdr_rva = (load_vaddr + (hdr_off - new_phoff) as u64) as u32;
    let mut eh_bytes = eh.bytes;
    let pc = (stub_vaddr as i64 - (eh_frame_rva as i64 + eh.pc_begin_off as i64)) as i32;
    eh_bytes[eh.pc_begin_off..eh.pc_begin_off + 4].copy_from_slice(&pc.to_le_bytes());
    let entries = [(
        stub_vaddr as i32,
        (eh_frame_rva as i64 + eh.fde_off as i64) as i32,
    )];
    let mut hdr_bytes = crate::unwind::dwarf::eh_frame_hdr(&entries);
    let efp = (eh_frame_rva as i64 - (hdr_rva as i64 + 4)) as i32;
    hdr_bytes[4..8].copy_from_slice(&efp.to_le_bytes());
    image[eh_off..eh_off + eh_bytes.len()].copy_from_slice(&eh_bytes);
    image[hdr_off..hdr_off + hdr_bytes.len()].copy_from_slice(&hdr_bytes);
    let eh_ph = elf::ProgramHeader {
        p_type: elf::PT_GNU_EH_FRAME,
        p_flags: elf::PF_R,
        p_offset: hdr_off as u64,
        p_vaddr: hdr_rva as u64,
        p_paddr: hdr_rva as u64,
        p_filesz: hdr_bytes.len() as u64,
        p_memsz: hdr_bytes.len() as u64,
        p_align: 4,
    };
    elf::write_program_header(&mut image, &parsed_new, phnum + 1, &eh_ph)
        .map_err(PackError::Format)?;
    let mut meta = vec![0u8; STUB_META_LEN];
    // The stub computes `base + payload_rva`, so this is the load-relative
    // VA of the envelope (not the stub-relative file offset).
    meta[META_PAYLOAD_RVA..META_PAYLOAD_RVA + 4]
        .copy_from_slice(&((load_vaddr + (env_off - new_phoff) as u64) as u32).to_le_bytes());
    meta[META_ENVELOPE_LEN..META_ENVELOPE_LEN + 4]
        .copy_from_slice(&(envelope_len as u32).to_le_bytes());
    meta[META_ORIGINAL_ENTRY..META_ORIGINAL_ENTRY + 4]
        .copy_from_slice(&(boot.orig_target as u32).to_le_bytes());
    meta[META_UNPACKED..META_UNPACKED + 4].copy_from_slice(&0u32.to_le_bytes());
    meta[META_MEASUREMENT..META_MEASUREMENT + 32].copy_from_slice(&measurement);
    for i in 0..16 {
        meta[48 + i] = opcode_seed[i];
    }
    meta[63] = request.debug_gate;
    meta[META_SELF_RVA..META_SELF_RVA + 4].copy_from_slice(&self_rva.to_le_bytes());
    // Seal-chunk granularity: both stubs' vprotect shims align to this
    // instead of a hardcoded 4096 (A-3 stub covariant).
    meta[META_PAGE_SIZE..META_PAGE_SIZE + 4].copy_from_slice(&page_size.to_le_bytes());
    // Relocated phdr table VA (the appended segment starts with it): the
    // core's final-protect walk needs the MAPPED address — the image header
    // still carries the file-offset e_phoff for the OS loader.
    meta[META_TABLE_RVA..META_TABLE_RVA + 4].copy_from_slice(&(load_vaddr as u32).to_le_bytes());
    image[stub_off + stub.meta_off..stub_off + stub.meta_off + STUB_META_LEN]
        .copy_from_slice(&meta);

    // ---- finalize the appended PT_LOAD (exact, bionic-safe arithmetic) ----
    // The image now ends at the last content byte; the LOAD covers exactly
    // [new_phoff, image.len()) so p_offset + p_filesz == file length — no
    // overshoot for loaders that check (bionic), no reliance on zero-fill
    // tolerance (glibc). new_phoff and load_vaddr are both page_size-aligned,
    // so the congruence (p_vaddr - p_offset) % p_align == 0 still holds
    // (A-3) on 4-KiB and 16-KiB devices alike.
    let seg_filesz = image.len() - new_phoff;
    if load_vaddr + seg_filesz as u64 > u32::MAX as u64 {
        return Err(PackError::Elf("ELF too large for 32-bit load vaddrs"));
    }
    let new_load = elf::ProgramHeader {
        p_type: elf::PT_LOAD,
        p_flags: elf::PF_R | elf::PF_X,
        p_offset: new_phoff as u64,
        p_vaddr: load_vaddr,
        p_paddr: load_vaddr,
        p_filesz: seg_filesz as u64,
        p_memsz: seg_filesz as u64,
        p_align: page_size as u64,
    };
    elf::write_program_header(&mut image, &parsed_new, phnum, &new_load)
        .map_err(PackError::Format)?;
    // Kernel-facing program header table.
    write_u64(&mut image, 32, new_phoff as u64)?;
    elf::set_phnum(&mut image, (phnum + 2) as u16).map_err(PackError::Format)?;

    // Bootstrap: drop DT_INIT (an in-place tag-zero would truncate the array
    // at DT_NULL, so the remaining entries shift left), then point the
    // INIT_ARRAY[0] R_<ARCH>_RELATIVE addend at the stub. ld.so computes
    // *(init_array) = load_bias + addend before running it: the stub
    // unpacks, forwards to the original target, and everything else runs in
    // order. (A-14 refused inputs where DT_INIT coexists with a non-empty
    // INIT_ARRAY — the rewrite would drop that DT_INIT silently.)
    rebuild_dynamic_without_init(&mut image, boot.dyn_off, boot.dyn_len)?;
    write_u64(&mut image, boot.rela_addend_off, stub_vaddr)?;
    // Disk copy of protected code must not leak plaintext — except the
    // first ENTRY_KEEP bytes at e_entry, which MUST stay intact: the loader
    // decodes an ~40-byte instruction window at the entry point and skips
    // the whole init phase (DT_INIT *and* INIT_ARRAY execution) when it
    // cannot parse it (verified empirically on glibc 2.39; 36 restored
    // bytes fail, 40 pass, 64 adds margin for other toolchain _start
    // shapes — bionic has no known equivalent check, O-2 keeps 64 until
    // device evidence narrows it). That window is the _start prologue — no
    // protected logic. Everything else is 0x90 filler; the stub restores the
    // real bytes from the AEAD envelope before any of it executes.
    const ENTRY_KEEP: usize = 64;
    let entry_keep_lo = parsed.entry as usize;
    let entry_keep_hi = entry_keep_lo + ENTRY_KEEP;
    // Resolver pages: ld.so executes IRELATIVE addends before INIT_ARRAY;
    // keep every chunk holding a resolver out of the seal set (native
    // plaintext on disk, restored pages never touch them). Chunk-granular
    // on 16-KiB images (A-3).
    let mut resolver_pages: Vec<u32> = Vec::new();
    for &r in &resolvers {
        let pg = (r as u32) & page_mask;
        if !resolver_pages.contains(&pg) {
            resolver_pages.push(pg);
        }
    }
    for (foff, clen) in &page_files {
        for k in 0..*clen {
            let file_off = foff + k;
            if let Some(va) = file_off_to_vaddr(&rx, file_off) {
                if (va as usize) >= entry_keep_lo && (va as usize) < entry_keep_hi {
                    continue;
                }
                if resolver_pages.iter().any(|pg| (va as u32 & page_mask) == *pg) {
                    continue;
                }
            }
            image[file_off] = 0x90;
        }
    }

    let packed = PackedImage {
        profile: request.profile,
        kind_dll: false,
        original_entry_rva: boot.orig_target as u32,
        stolen: Vec::new(),
        mba,
        opcode_seed,
        api_salt,
        imports: Vec::new(),
        exports: Vec::new(),
        pages: records,
        probes: android_probes.clone(),
        program,
    };

    let coverage = if machine == ElfMachine::Aarch64 && selection_requested {
        vm_coverage
    } else if selection_requested {
        let wanted: std::collections::BTreeSet<&str> =
            request.select_functions.iter().map(String::as_str).collect();
        elf::symtab_functions(request.input, &parsed)
            .map_err(PackError::Format)?
            .into_iter()
            .filter(|f| request.select_all || wanted.contains(f.name.as_str()))
            .filter(|f| f.size > 0)
            .map(|f| crate::FunctionCoverageRecord {
                name: f.name,
                rva: f.value as u32,
                len: Some(f.size as u32),
                source: crate::analysis::function_map::BoundarySource::Symbol,
                bucket: "mixed_native".into(),
                reason: "sysv-lift-not-implemented".into(),
            })
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    let selected_functions = if machine == ElfMachine::Aarch64 && selection_requested {
        vm_selected
    } else {
        coverage.iter().map(|c| c.name.clone()).collect()
    };
    let report = crate::PackReport {
        report_version: PACK_REPORT_VERSION,
        profile: request.profile.as_str().to_string(),
        format: match (kind, parsed.interp) {
            // ET_DYN + PT_INTERP = PIE executable; ET_DYN alone = shared object.
            (ImageKind::Elf64Exec, _) | (ImageKind::Elf64Dyn, true) => "elf64-exec".into(),
            (ImageKind::Elf64Dyn, false) => "elf64-dyn".into(),
            _ => unreachable!("classified above"),
        },
        machine: match machine {
            ElfMachine::Amd64 => "x86_64".into(),
            ElfMachine::Aarch64 => "aarch64".into(),
        },
        debug_gate: request.debug_gate,
        input_bytes: request.input.len(),
        output_bytes: image.len(),
        backend: BACKEND_PIC_STUB.into(),
        export_surface: Vec::new(),
        // Anti-debug probe manifest actually injected into the stub
        // (aarch64 only; the list is what the artifact runs -- never a
        // pass-through of the Windows claim).
        probes: android_probes.iter().map(|p| probe_name(*p).to_string()).collect(),
        // GOT/PLT are filled by ld.so before init; the runtime never
        // resolves imports on ELF.
        iat_mode: "loader-resolved-got-plt".into(),
        runtime_decryption_window: false,
        c2_reencrypt: false,
        aslr: parsed.pie,
        high_entropy_va: false,
        reloc_directory: false,
        tls_directory: false,
        long_term_rwx: false,
        seed_len: 16,
        pages: packed.pages.len(),
        stolen_bytes: 0,
        vm_functions: vm64.len(),
        selected_functions,
        coverage,
        strict_coverage: request.strict_coverage,
        allow_native_fallback: request.allow_native_fallback,
        import_names_sealed: false,
        imports_protected: 0,
        imports_kept: imports_kept_count,
        imports_kept_reason: String::new(),
        constants_candidates: 0,
        constants_protectable: 0,
        constants_encrypted: 0,
        constants_native_referenced: 0,
        notes: vec![
            format!(
                "backend=pic-stub+xl-core (ELF INIT_ARRAY[0] bootstrap, appended R+X \
                 PT_LOAD, page_size={page_size}, machine={})",
                match machine {
                    ElfMachine::Amd64 => "x86_64",
                    ElfMachine::Aarch64 => "aarch64",
                }
            ),
            "ld.so stays the loader: PIE/RELRO/GOT-PLT untouched; imports loader-resolved".into(),
            format!(
                "anti-debug probes: {}",
                if machine == ElfMachine::Aarch64 {
                    format!(
                        "{} (aarch64 core: TracerPid scan, PTRACE_TRACEME self-attach,                          /proc/self/maps marker scan; fail-closed, run before any AEAD open)",
                        android_probes.iter().map(|p| probe_name(*p)).collect::<Vec<_>>().join("+")
                    )
                } else {
                    "anti-debug probes are aarch64-only in this release".to_string()
                }
            ),
            "executable PT_LOAD file bytes sealed as EnvelopeV2 AEAD; disk holds 0x90              (carve-outs: entry window, IFUNC resolver pages, loader metadata pages)".into(),
            format!(
                "loader metadata: {} page(s) kept native (ld.so parses them before init)",
                metadata_pages.len()
            ),
            format!(
                "decrypt window: {}",
                if machine == ElfMachine::Aarch64 {
                    // The arm64 shim maps XL_PAGE_RW to RWX for the write
                    // window: binary translators (ndk_translation) crash
                    // when a translated code page drops exec. Final state
                    // still returns to the segment-declared protection.
                    "transient RWX on aarch64 (ndk_translation cannot drop X;                      final protection restored to the PT_LOAD-declared bits)"
                } else {
                    "transient RW on x86-64 (final protection restored)"
                }
            ),
            format!(
                "tls: PT_TLS kept; models IE(GOTTPOFF)={} LD(DTPMOD/DTPREL)={}; ifunc resolvers={} on {} native pages; symbol versions verneed={} verdef={}",
                tls_census.0, tls_census.1, resolvers.len(), resolver_pages.len(), verneed, verdef
            ),
            format!(
                "dt_init: {}",
                if boot.dropped_dt_init {
                    // x86-64/glibc only; aarch64 refuses this input shape.
                    "dropped (glibc crti _init convention; empty on modern toolchains)"
                } else {
                    "absent in input"
                }
            ),
                "fail-closed: TPOFF32/TLSLE-in-text, static linkage, RELATIVE into sealed page, RELR/packed relocs, ELF --lazy-regions, DT_INIT+INIT_ARRAY coexistence".into(),
            "pages decrypt through a transient RW window, then return to the protection \n             their PT_LOAD declares (R+X normally; a W+X segment stays W+X via \n             raw mprotect)"
                .into(),
            format!("payload section name: {:02x?}", section_name_from_seed(&opcode_seed, 0)),
        ],
    };

    Ok(PackOutput {
        image,
        report,
        packed,
    })
}

/// The per-build superop seed (mirrors the PE path's block_seed derivation;
/// None falls back to the same derivation the envelope uses later).
fn opcode_seed_for(request: &PackRequest<'_>) -> [u8; 16] {
    request.opcode_seed.unwrap_or_else(|| {
        // Deterministic per-request is impossible without OsRng here; the
        // PE path derives it from the same random source the envelope
        // uses. The lift only needs *a* seed, so reuse the request's when
        // present and otherwise derive from the crypto RNG.
        xenolith_crypto::random_seed16()
    })
}

/// A resolved selection entry (vm-aarch64 design §8.4): dynsym/symtab give
/// name/rva/st_size; explicit windows come verbatim; ifunc resolvers are
/// rejected by name with the pre-init-window reason.
struct ElfFnSel {
    name: String,
    rva: u32,
    len: Option<u32>,
    source: crate::analysis::function_map::BoundarySource,
}

fn resolve_elf_selection(
    request: &PackRequest<'_>,
    input: &[u8],
    parsed: &elf::Elf64,
    ifunc_resolvers: &[u64],
) -> Result<Vec<ElfFnSel>, PackError> {
    let mut out: Vec<ElfFnSel> = Vec::new();
    // Explicit windows first (highest priority, always retained).
    for (rva, len) in &request.select_rva {
        if *len == 0 {
            return Err(PackError::Lift(format!(
                "select-rva {rva:#x}: length must be > 0"
            )));
        }
        if elf::vaddr_file_offset(input, parsed, *rva as u64).is_err() {
            return Err(PackError::Lift(format!(
                "select-rva {rva:#x}: not in image"
            )));
        }
        out.push(ElfFnSel {
            name: format!("rva_{rva:#x}"),
            rva: *rva,
            len: Some(*len),
            source: crate::analysis::function_map::BoundarySource::ExplicitRange,
        });
    }
    let dynsym = elf::dynsym_functions(input, parsed).map_err(PackError::Format)?;
    let symtab = elf::symtab_functions(input, parsed).map_err(PackError::Format)?;
    let mut explicit: Vec<String> = request.vm_exports.clone();
    explicit.extend(request.select_functions.iter().cloned());
    explicit.sort();
    explicit.dedup();
    for name in &explicit {
        if let Some(rule) = forbidden_vm_rule(name) {
            return Err(PackError::Lift(format!(
                "vm-export {name}: stays native ({rule}); CRT/JNI ABI exports must stay \
                 native — pick another function"
            )));
        }
        let hit = dynsym
            .iter()
            .find(|f| f.name == *name)
            .map(|f| (f.value, f.size))
            .or_else(|| {
                symtab
                    .iter()
                    .find(|f| f.name == *name)
                    .map(|f| (f.value, f.size))
            });
        let Some((value, size)) = hit else {
            const MAX_LISTED: usize = 8;
            let mut named: Vec<&str> =
                dynsym.iter().chain(symtab.iter()).map(|f| f.name.as_str()).collect();
            named.sort();
            named.dedup();
            let listed: Vec<&str> = named.iter().take(MAX_LISTED).copied().collect();
            let more = if named.len() > MAX_LISTED {
                format!(" … (+{} more)", named.len() - MAX_LISTED)
            } else {
                String::new()
            };
            let available = if named.is_empty() {
                "This image exports no named functions (stripped, no dynsym/symtab \
                 entries with sizes)."
                    .to_string()
            } else {
                format!(
                    "Available functions ({} of {}): {}{}. Full list: run `xenolith \
                     inspect <input>`.",
                    listed.len(),
                    named.len(),
                    listed.join(", "),
                    more
                )
            };
            return Err(PackError::Lift(format!(
                "vm-export {name} is missing: it is neither a dynsym nor a symtab \
                 function symbol. {available}"
            )));
        };
        if size == 0 {
            return Err(PackError::Lift(format!(
                "vm-export {name}: symbol has st_size 0 — no lift window; select an \
                 explicit --select-rva <rva>:<len> window instead"
            )));
        }
        out.push(ElfFnSel {
            name: name.clone(),
            rva: value as u32,
            len: Some(size as u32),
            source: crate::analysis::function_map::BoundarySource::Symbol,
        });
    }
    if request.select_all {
        let mut discovered: Vec<(String, u64, u64)> = Vec::new();
        for f in dynsym.iter().chain(symtab.iter()) {
            if forbidden_vm_rule(&f.name).is_some() || f.size == 0 {
                continue;
            }
            discovered.push((f.name.clone(), f.value, f.size));
        }
        discovered.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0)));
        discovered.dedup_by(|a, b| a.1 == b.1 && a.0 == b.0);
        for (name, value, size) in discovered {
            if out.iter().any(|f| f.rva as u64 == value) {
                continue;
            }
            out.push(ElfFnSel {
                name,
                rva: value as u32,
                len: Some(size as u32),
                source: crate::analysis::function_map::BoundarySource::Symbol,
            });
        }
    }
    // §8.4 ifunc exclusion: resolvers execute during ld.so relocation,
    // before the INIT_ARRAY unpack stub — hooking them in that window is
    // unproven, so they stay native.
    for f in &out {
        if ifunc_resolvers.contains(&(f.rva as u64)) {
            return Err(PackError::Lift(format!(
                "vm-export {} (rva {:#x}): IFUNC resolvers run during ld.so relocation, \
                 before the INIT_ARRAY unpack stub; hooking the entry in that pre-init \
                 window is unproven, so resolver functions stay native — pick a \
                 non-ifunc export",
                f.name, f.rva
            )));
        }
    }
    Ok(out)
}

/// `b rel26` + `brk #0` fill at the selected entry (design §5.3): a direct
/// branch into the guest thunk, with the rest of the lifted window trapped.
fn apply_vm_hook_elf(
    working: &mut [u8],
    parsed: &elf::Elf64,
    input: &[u8],
    name: &str,
    rva: u32,
    native_len: usize,
    target_va: u64,
) -> Result<(), PackError> {
    if rva % 4 != 0 {
        return Err(PackError::Stub(format!(
            "vm hook: {name} rva {rva:#x} is not 4-byte aligned"
        )));
    }
    let off = elf::vaddr_file_offset(input, parsed, rva as u64)
        .map_err(|_| PackError::Stub(format!("vm hook: {name} bad rva {rva:#x}")))?;
    let end = off + native_len;
    if end > working.len() || native_len < 4 {
        return Err(PackError::Stub(format!(
            "vm hook: {name} rewrite of {native_len} bytes at rva {rva:#x} overruns the \
             {}-byte image",
            working.len()
        )));
    }
    let rel = target_va as i64 - rva as i64;
    if rel % 4 != 0 || rel / 4 < -(1 << 25) || rel / 4 >= (1 << 25) {
        return Err(PackError::Stub(format!(
            "vm hook: {name} branch distance {rel:#x} is out of the ±128MiB rel26 range"
        )));
    }
    let word: u32 = 0x1400_0000 | (((rel / 4) as u32) & 0x03FF_FFFF);
    working[off..off + 4].copy_from_slice(&word.to_le_bytes());
    for w in working[off + 4..end].chunks_exact_mut(4) {
        w.copy_from_slice(&0xD420_0000u32.to_le_bytes());
    }
    Ok(())
}

/// Design §5.2 gate 2: references into the middle of a virtualized window
/// (switch-table inner labels and in-window b/bl targets) would execute
/// brk filler after the hook — conservative named rejection.
fn scan_inner_label_refs(
    input: &[u8],
    parsed: &elf::Elf64,
    rx: &[(u64, u64, usize, usize)],
    windows: &[(u32, usize)],
) -> Result<(), PackError> {
    if windows.is_empty() {
        return Ok(());
    }
    let inside = |rva: u64| -> Option<usize> {
        windows
            .iter()
            .position(|(w_rva, w_len)| rva > *w_rva as u64 && rva < (*w_rva as u64 + *w_len as u64))
    };
    // (a) RELATIVE addends pointing inside a window.
    let phdrs = elf::program_headers(input, parsed).map_err(PackError::Format)?;
    let (mut rela_off, mut rela_sz, mut dyn_off, mut dyn_len) = (0u64, 0u64, 0usize, 0usize);
    for ph in &phdrs {
        if ph.p_type == elf::PT_DYNAMIC {
            dyn_off = ph.p_offset as usize;
            dyn_len = ph.p_filesz as usize;
        }
    }
    if dyn_len > 0 {
        let mut i = 0usize;
        while i + 16 <= dyn_len {
            let tag = u64::from_le_bytes(input[dyn_off + i..dyn_off + i + 8].try_into().unwrap());
            let val =
                u64::from_le_bytes(input[dyn_off + i + 8..dyn_off + i + 16].try_into().unwrap());
            if tag == 0 {
                break;
            }
            if tag == DT_RELA {
                rela_off = val;
            } else if tag == DT_RELASZ {
                rela_sz = val;
            }
            i += 16;
        }
    }
    if rela_off != 0 && rela_sz > 0 {
        let off = elf::vaddr_file_offset(input, parsed, rela_off).map_err(PackError::Format)?;
        for k in 0..(rela_sz as usize / 24) {
            let o = off + k * 24;
            let addend =
                u64::from_le_bytes(input[o + 16..o + 24].try_into().unwrap());
            if let Some(wi) = inside(addend) {
                return Err(PackError::Lift(format!(
                    "vm-export rva_{:#x}: a relocation addend ({addend:#x}) points inside \
                     the virtualized window (rva {:#x}, {} bytes) - an inner label (switch \
                     table) would execute trap filler; keep the function native with \
                     --allow-native-fallback",
                    windows[wi].0, windows[wi].0, windows[wi].1
                )));
            }
        }
    }
    // (a2) Defined FUNC symbol st_values (dynsym + symtab) pointing inside
    // a window. An alias symbol whose st_value lands mid-window keeps
    // resolving there in the packed image while the hook wrote trap filler
    // over it — a GOT/PLT or dlsym indirect call would SIGTRAP (independent
    // review 2026-10-06: the addend-only check below let exactly this
    // through). Size-0 aliases (no st_size) stay outside these parsers'
    // surface and are an accepted residual, same as before.
    for (face, syms) in [
        ("dynsym", elf::dynsym_functions(input, parsed).map_err(PackError::Format)?),
        ("symtab", elf::symtab_functions(input, parsed).map_err(PackError::Format)?),
    ] {
        for sym in syms {
            if let Some(wi) = inside(sym.value) {
                return Err(PackError::Lift(format!(
                    "vm-export rva_{:#x}: {face} symbol `{}` (st_value {:#x}) points inside \
                     the virtualized window (rva {:#x}, {} bytes) - an indirect call through \
                     its GOT/PLT slot or dlsym would execute trap filler; keep the function \
                     native with --allow-native-fallback",
                    windows[wi].0, sym.name, sym.value, windows[wi].0, windows[wi].1
                )));
            }
        }
    }
    // (b) 4-aligned b/bl scan over the input RX ranges.
    for (va, _va_end, off, len) in rx {
        let mut o = *off;
        let end = off + len;
        while o + 4 <= end {
            let word = u32::from_le_bytes(input[o..o + 4].try_into().unwrap());
            if word & 0xFC00_0000 == 0x1400_0000 || word & 0xFC00_0000 == 0x9400_0000 {
                let imm26 = (word & 0x03FF_FFFF) as i64;
                let imm26 = if imm26 & (1 << 25) != 0 {
                    imm26 - (1 << 26)
                } else {
                    imm26
                };
                let src_va = va + (o - off) as u64;
                // A branch that ORIGINATES inside a virtualized window never
                // executes natively (the lift turns it into an in-VM Jmp/Jcc
                // and validates the target itself); only native branches
                // entering a window from outside would hit trap filler.
                if inside(src_va).is_some() {
                    o += 4;
                    continue;
                }
                let target = src_va.wrapping_add((imm26 * 4) as u64);
                if let Some(wi) = inside(target) {
                    return Err(PackError::Lift(format!(
                        "vm-export rva_{:#x}: a b/bl at {:#x} targets {target:#x} inside the \
                         virtualized window (rva {:#x}, {} bytes) — the inner label would \
                         execute trap filler; keep the function native with \
                         --allow-native-fallback",
                        windows[wi].0,
                        va + (o - off) as u64,
                        windows[wi].0,
                        windows[wi].1
                    )));
                }
            }
            o += 4;
        }
    }
    Ok(())
}

/// R_<ARCH>_RELATIVE applied by ld.so *before* init would be overwritten
/// when the stub restores link-time plaintext. Any such entry inside an
/// encrypted range is refused instead of silently corrupting the pointer.
fn fail_closed_on_relative_into_rx(
    input: &[u8],
    parsed: &elf::Elf64,
    rx: &[(u64, u64, usize, usize)],
) -> Result<(), PackError> {
    let phdrs = elf::program_headers(input, parsed).map_err(PackError::Format)?;
    let (mut rela_off, mut rela_sz) = (0u64, 0u64);
    let mut dyn_off = None;
    let mut dyn_sz = 0usize;
    for ph in &phdrs {
        match ph.p_type {
            elf::PT_DYNAMIC => {
                dyn_off = Some(ph.p_offset as usize);
                dyn_sz = ph.p_filesz as usize;
            }
            _ => {}
        }
    }
    let Some(dyn_off) = dyn_off else {
        return Ok(());
    };
    let mut i = 0usize;
    while i + 16 <= dyn_sz {
        let tag = u64::from_le_bytes(
            input[dyn_off + i..dyn_off + i + 8].try_into().unwrap(),
        );
        if tag == 0 {
            break;
        }
        let val = u64::from_le_bytes(
            input[dyn_off + i + 8..dyn_off + i + 16].try_into().unwrap(),
        );
        match tag {
            7 => rela_off = val, // DT_RELA
            8 => rela_sz = val,  // DT_RELASZ
            _ => {}
        }
        i += 16;
    }
    if rela_off == 0 || rela_sz == 0 {
        return Ok(());
    }
    let off = elf::vaddr_file_offset(input, parsed, rela_off).map_err(PackError::Format)?;
    let n = (rela_sz as usize) / 24;
    for k in 0..n {
        let o = off + k * 24;
        let r_offset = u64::from_le_bytes(input[o..o + 8].try_into().unwrap());
        let info = u64::from_le_bytes(input[o + 8..o + 16].try_into().unwrap());
        if (info & 0xffff_ffff) as u32 == parsed.machine.relative_type()
            && rx.iter().any(|(lo, hi, _, _)| r_offset >= *lo && r_offset < *hi)
        {
            return Err(PackError::Invalid(
                "ELF RELATIVE relocation targets an encrypted page (ld.so applies it before init)",
            ));
        }
    }
    Ok(())
}

/// Everything needed to redirect INIT_ARRAY[0] into the bootstrap stub.
struct InitArrayBoot {
    /// File offset of PT_DYNAMIC.
    dyn_off: usize,
    /// PT_DYNAMIC p_filesz.
    dyn_len: usize,
    /// File offset of the INIT_ARRAY[0] R_<ARCH>_RELATIVE *addend* field.
    rela_addend_off: usize,
    /// Original addend: the function the stub must forward to after unpack.
    orig_target: u64,
    /// Input carried a live DT_INIT (its removal is reported honestly).
    dropped_dt_init: bool,
}

const DT_INIT: u64 = 12;
const DT_INIT_ARRAY: u64 = 25;
const DT_INIT_ARRAYSZ: u64 = 27;
const DT_RELA: u64 = 7;
const DT_RELASZ: u64 = 8;

fn init_array_bootstrap(input: &[u8], parsed: &elf::Elf64) -> Result<InitArrayBoot, PackError> {
    let phdrs = elf::program_headers(input, parsed).map_err(PackError::Format)?;
    let (mut dyn_off, mut dyn_len) = (0usize, 0usize);
    let (mut rela_va, mut rela_sz) = (0u64, 0u64);
    let (mut init_array_va, mut init_array_sz) = (0u64, 0u64);
    let mut saw_init = false;
    let mut saw_init_arraysz = false;
    let mut saw_misfini_slot = false;
    for ph in &phdrs {
        if ph.p_type != elf::PT_DYNAMIC {
            continue;
        }
        dyn_off = ph.p_offset as usize;
        dyn_len = ph.p_filesz as usize;
    }
    if dyn_len == 0 {
        return Err(PackError::Elf("ELF has no PT_DYNAMIC"));
    }
    let mut i = 0usize;
    while i + 16 <= dyn_len {
        let tag = u64::from_le_bytes(input[dyn_off + i..dyn_off + i + 8].try_into().unwrap());
        if tag == 0 {
            break;
        }
        let val = u64::from_le_bytes(
            input[dyn_off + i + 8..dyn_off + i + 16].try_into().unwrap(),
        );
        match tag {
            DT_RELA => rela_va = val,
            DT_RELASZ => rela_sz = val,
            DT_INIT_ARRAY => init_array_va = val,
            DT_INIT_ARRAYSZ => {
                init_array_sz = val;
                saw_init_arraysz = true;
            }
            DT_INIT if val != 0 => saw_init = true,
            // Known broken-linker shape: DT_INIT_ARRAYSZ mis-emitted as
            // DT_FINI_ARRAY (tag 26) with a tiny non-vaddr value. Recognized
            // only for the diagnostic; the pack still refuses (below).
            26 if val < 0x1000 => saw_misfini_slot = true,
            _ => {}
        }
        i += 16;
    }
    // A-14: rebuild_dynamic_without_init drops DT_INIT while the bootstrap
    // only replays INIT_ARRAY[0]'s original addend — an input with BOTH a
    // live DT_INIT and a non-empty INIT_ARRAY would silently lose the
    // DT_INIT function (ELF order: DT_INIT runs first). Android is a new
    // toolchain surface, so aarch64 refuses that shape outright. glibc
    // toolchains always emit a (functionally empty) crti `_init` alongside
    // INIT_ARRAY; dropping it is the long-validated x86-64 behavior (the
    // WSL OS-load suite packs exactly that shape), so the x86-64 path keeps
    // it and reports the drop instead of pretending nothing happened.
    if saw_init && init_array_sz >= 8 && parsed.machine == ElfMachine::Aarch64 {
        return Err(PackError::Elf(
            "aarch64 input has both DT_INIT and DT_INIT_ARRAY: packing would \
             drop the original DT_INIT function (rebuild keeps only \
             INIT_ARRAY[0]); relink with constructors in init_array only",
        ));
    }
    if init_array_va == 0 || (!saw_init_arraysz && init_array_sz < 8) {
        if init_array_va != 0 && saw_misfini_slot {
            // The size tag exists but carries the wrong tag id, so ld.so has
            // NEVER run INIT_ARRAY[0] in this image. Synthesizing the size
            // would activate an entry the input never executed — not
            // semantics-preserving. Fail closed; fix the target's linker
            // script to emit DT_INIT_ARRAYSZ.
            return Err(PackError::Elf(
                "DT_INIT_ARRAYSZ is mis-tagged as DT_FINI_ARRAY (broken linker \
                 emulation): INIT_ARRAY[0] never ran in this image, so packing \
                 must not synthesize the size; fix the target link spec",
            ));
        }
        return Err(PackError::Elf(
            "ELF has no DT_INIT_ARRAY slot to bootstrap (required in this release)",
        ));
    }
    if rela_va == 0 || rela_sz == 0 {
        return Err(PackError::Elf("ELF has no DT_RELA (DT_REL-only images fail closed)"));
    }
    let rela_file = elf::vaddr_file_offset(input, parsed, rela_va).map_err(PackError::Format)?;
    let n = (rela_sz as usize) / 24;
    for k in 0..n {
        let o = rela_file + k * 24;
        let r_offset = u64::from_le_bytes(input[o..o + 8].try_into().unwrap());
        let r_info = u64::from_le_bytes(input[o + 8..o + 16].try_into().unwrap());
        let r_addend = u64::from_le_bytes(input[o + 16..o + 24].try_into().unwrap());
        if r_offset == init_array_va
            && (r_info & 0xffff_ffff) as u32 == parsed.machine.relative_type()
        {
            return Ok(InitArrayBoot {
                dyn_off,
                dyn_len,
                rela_addend_off: o + 16,
                orig_target: r_addend,
                dropped_dt_init: saw_init,
            });
        }
    }
    Err(PackError::Elf(
        "INIT_ARRAY[0] has no R_<ARCH>_RELATIVE relocation (non-PIE-style init slot)",
    ))
}

/// Rewrite PT_DYNAMIC in place without the DT_INIT entry. Entries shift left;
/// the first DT_NULL (and any tail padding) terminates the walk for ld.so.
/// PT_DYNAMIC p_filesz stays valid: the array only shrinks.
fn rebuild_dynamic_without_init(
    image: &mut [u8],
    dyn_off: usize,
    dyn_len: usize,
) -> Result<(), PackError> {
    let mut entries = Vec::new();
    let mut i = 0usize;
    while i + 16 <= dyn_len {
        let tag = u64::from_le_bytes(image[dyn_off + i..dyn_off + i + 8].try_into().unwrap());
        let val =
            u64::from_le_bytes(image[dyn_off + i + 8..dyn_off + i + 16].try_into().unwrap());
        if tag == 0 {
            break;
        }
        if tag != DT_INIT {
            entries.push((tag, val));
        }
        i += 16;
    }
    let mut cur = dyn_off;
    for (tag, val) in &entries {
        if cur + 16 > dyn_off + dyn_len {
            return Err(PackError::Elf("dynamic rewrite overflows PT_DYNAMIC"));
        }
        image[cur..cur + 8].copy_from_slice(&tag.to_le_bytes());
        image[cur + 8..cur + 16].copy_from_slice(&val.to_le_bytes());
        cur += 16;
    }
    if cur + 16 <= dyn_off + dyn_len {
        image[cur..cur + 16].fill(0); // DT_NULL terminator
    }
    Ok(())
}

/// Map a file offset inside a protected RX range back to its vaddr.
fn file_off_to_vaddr(rx: &[(u64, u64, usize, usize)], file_off: usize) -> Option<u64> {
    rx.iter().find_map(|(va, _va_end, off, len)| {
        if file_off >= *off && file_off < *off + *len {
            Some(va + (file_off - *off) as u64)
        } else {
            None
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal packable ET_DYN (one R+X PT_LOAD covering the whole file,
    /// vaddr == file offset; PT_DYNAMIC with DT_RELA/DT_RELASZ/
    /// DT_INIT_ARRAY/DT_INIT_ARRAYSZ plus extras; one RELATIVE entry at
    /// INIT_ARRAY[0]). `machine` picks x86-64 (8) or aarch64 (1027)
    /// RELATIVE numbering; `with_dt_init` adds a live DT_INIT.
    fn elf_dyn_fixture(machine: ElfMachine, extra_dyn: &[(u64, u64)], with_dt_init: bool) -> Vec<u8> {
        // Layout: [ehdr | phdrs(3)][rela] -- R+X LOAD boundary -- [dynamic |
        // init_array] in an RW LOAD. INIT_ARRAY lives in the RW segment so
        // its RELATIVE entry never targets the sealed RX range (the same
        // shape every real toolchain emits).
        const PHOFF: usize = 64;
        const PHNUM: usize = 4; // slot 3 stays PT_NULL (spare for tests)
        const RX_END: usize = 0x300; // page-ish boundary, file == vaddr
        let rel_type = machine.relative_type();
        let em: u16 = match machine {
            ElfMachine::Amd64 => 62,
            ElfMachine::Aarch64 => 183,
        };
        let n_base = if with_dt_init { 6 } else { 5 };
        let dyn_off = RX_END;
        let rela_off = PHOFF + PHNUM * 56;
        let ia_off = dyn_off + (n_base + extra_dyn.len()) * 16;
        let total = ia_off + 8;

        let mut dyns: Vec<u8> = Vec::new();
        for (tag, val) in [
            (7u64, rela_off as u64), // DT_RELA
            (8u64, 24u64),           // DT_RELASZ (one entry)
            (25u64, ia_off as u64),  // DT_INIT_ARRAY
            (27u64, 8u64),           // DT_INIT_ARRAYSZ
        ] {
            dyns.extend_from_slice(&tag.to_le_bytes());
            dyns.extend_from_slice(&val.to_le_bytes());
        }
        if with_dt_init {
            dyns.extend_from_slice(&12u64.to_le_bytes()); // DT_INIT
            dyns.extend_from_slice(&0x1234u64.to_le_bytes());
        }
        for (tag, val) in extra_dyn {
            dyns.extend_from_slice(&tag.to_le_bytes());
            dyns.extend_from_slice(&val.to_le_bytes());
        }
        dyns.extend_from_slice(&[0u8; 16]);

        let mut img = vec![0u8; total];
        img[0..4].copy_from_slice(b"ELF");
        img[4] = 2;
        img[5] = 1;
        img[16..18].copy_from_slice(&3u16.to_le_bytes()); // ET_DYN
        img[18..20].copy_from_slice(&em.to_le_bytes());
        img[32..40].copy_from_slice(&(PHOFF as u64).to_le_bytes());
        img[54..56].copy_from_slice(&56u16.to_le_bytes());
        img[56..58].copy_from_slice(&(PHNUM as u16).to_le_bytes());
        // LOAD 0: headers + rela, R+X.
        img[PHOFF..PHOFF + 4].copy_from_slice(&1u32.to_le_bytes());
        img[PHOFF + 4..PHOFF + 8].copy_from_slice(&5u32.to_le_bytes());
        img[PHOFF + 8..PHOFF + 16].copy_from_slice(&0u64.to_le_bytes());
        img[PHOFF + 32..PHOFF + 40].copy_from_slice(&(RX_END as u64).to_le_bytes());
        img[PHOFF + 40..PHOFF + 48].copy_from_slice(&(RX_END as u64).to_le_bytes());
        img[PHOFF + 48..PHOFF + 56].copy_from_slice(&0x1000u64.to_le_bytes());
        // LOAD 1: dynamic + init_array, RW.
        let l1 = PHOFF + 56;
        img[l1..l1 + 4].copy_from_slice(&1u32.to_le_bytes());
        img[l1 + 4..l1 + 8].copy_from_slice(&6u32.to_le_bytes());
        img[l1 + 8..l1 + 16].copy_from_slice(&(dyn_off as u64).to_le_bytes());
        img[l1 + 16..l1 + 24].copy_from_slice(&(dyn_off as u64).to_le_bytes());
        img[l1 + 32..l1 + 40].copy_from_slice(&((total - dyn_off) as u64).to_le_bytes());
        img[l1 + 40..l1 + 48].copy_from_slice(&((total - dyn_off) as u64).to_le_bytes());
        img[l1 + 48..l1 + 56].copy_from_slice(&0x1000u64.to_le_bytes());
        // PT_DYNAMIC.
        let d = PHOFF + 2 * 56;
        img[d..d + 4].copy_from_slice(&2u32.to_le_bytes());
        img[d + 8..d + 16].copy_from_slice(&(dyn_off as u64).to_le_bytes());
        img[d + 16..d + 24].copy_from_slice(&(dyn_off as u64).to_le_bytes());
        img[d + 32..d + 40].copy_from_slice(&(dyns.len() as u64).to_le_bytes());
        img[dyn_off..dyn_off + dyns.len()].copy_from_slice(&dyns);
        // INIT_ARRAY[0]'s RELATIVE: r_offset = init_array va, addend in the
        // RX LOAD.
        img[rela_off..rela_off + 8].copy_from_slice(&(ia_off as u64).to_le_bytes());
        img[rela_off + 8..rela_off + 16].copy_from_slice(&(rel_type as u64).to_le_bytes());
        img[rela_off + 16..rela_off + 24].copy_from_slice(&0x40u64.to_le_bytes());
        img
    }

    fn req<'a>(input: &'a [u8], lazy: bool) -> PackRequest<'a> {
        PackRequest {
            input,
            profile: Profile::Max,
            vm_exports: vec![],
            debug_gate: 3,
            opcode_seed: Some([9; 16]),
            trace_diverge: false,
            select_rva: vec![],
            select_functions: Vec::new(),
            select_all: false,
            strict_coverage: false,
            allow_native_fallback: false,
            lazy_regions: lazy,
            protect_imports: false,
            strict_constants: false,
        }
    }

    #[test]
    fn elf_lazy_regions_fail_closed_named() {
        let img = elf_dyn_fixture(ElfMachine::Amd64, &[], false);
        let msg = match pack_elf(&req(&img, true)) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("lazy regions must fail closed"),
        };
        assert!(msg.contains("lazy regions require the G5 fault-wake runtime"), "{msg}");
        assert!(msg.contains("--lazy-regions"), "{msg}");
    }

    #[test]
    fn aarch64_dt_init_coexistence_fail_closed_named() {
        let img = elf_dyn_fixture(ElfMachine::Aarch64, &[], true);
        let msg = match pack_elf(&req(&img, false)) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("DT_INIT coexistence must fail closed on aarch64"),
        };
        assert!(
            msg.contains("aarch64 input has both DT_INIT and DT_INIT_ARRAY"),
            "{msg}"
        );
        // x86-64 (glibc crti _init convention) accepts the same shape and
        // reports the drop honestly.
        let img = elf_dyn_fixture(ElfMachine::Amd64, &[], true);
        match pack_elf(&req(&img, false)) {
            Ok(out) => assert!(
                out.report.notes.iter().any(|n| n.contains("dt_init: dropped")),
                "x86-64 must note the DT_INIT drop"
            ),
            // A machine without the host x86-64 core cannot pack at all;
            // the named-error path is acceptable there too.
            Err(e) => assert!(!e.to_string().contains("DT_INIT"), "{e}"),
        }
    }

    #[test]
    fn aarch64_pt_interp_fail_closed_named() {
        let mut img = elf_dyn_fixture(ElfMachine::Aarch64, &[], false);
        // The fixture reserves phdr slot 3 as PT_NULL: fill it with
        // PT_INTERP and place the path string past the RW LOAD (extended).
        let img_len = img.len();
        img.resize(img_len + 16, 0);
        img[img_len..img_len + 8].copy_from_slice(b"/system\x00");
        let p = 64 + 3 * 56;
        img[p..p + 4].copy_from_slice(&3u32.to_le_bytes()); // PT_INTERP
        img[p + 8..p + 16].copy_from_slice(&(img_len as u64).to_le_bytes());
        let fsz_o = 64 + 56 + 32;
        let msz_o = 64 + 56 + 40;
        let fsz = u64::from_le_bytes(img[fsz_o..fsz_o + 8].try_into().unwrap());
        img[fsz_o..fsz_o + 8].copy_from_slice(&(fsz + 16).to_le_bytes());
        let msz = u64::from_le_bytes(img[msz_o..msz_o + 8].try_into().unwrap());
        img[msz_o..msz_o + 8].copy_from_slice(&(msz + 16).to_le_bytes());
        let msg = match pack_elf(&req(&img, false)) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("aarch64 PT_INTERP must fail closed"),
        };
        assert!(msg.contains("PT_INTERP"), "{msg}");
        assert!(msg.contains(".so"), "{msg}");
    }

    #[test]
    fn oversized_pt_align_fail_closed_named() {
        let mut img = elf_dyn_fixture(ElfMachine::Amd64, &[], false);
        // 64 KiB alignment exceeds the 16 KiB ceiling.
        img[64 + 48..64 + 56].copy_from_slice(&0x10000u64.to_le_bytes());
        let msg = match pack_elf(&req(&img, false)) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("oversized p_align must fail closed"),
        };
        assert!(msg.contains("exceeds 16 KiB"), "{msg}");
    }

    #[test]
    fn appended_load_ends_exactly_at_the_file() {
        // bionic rejects p_offset + p_filesz > file size (glibc only
        // zero-fills). The appended LOAD must end exactly at EOF.
        let img = elf_dyn_fixture(ElfMachine::Amd64, &[], false);
        match pack_elf(&req(&img, false)) {
            Ok(out) => {
                let phoff = u64::from_le_bytes(out.image[32..40].try_into().unwrap()) as usize;
                let phnum = u16::from_le_bytes(out.image[56..58].try_into().unwrap()) as usize;
                let o = phoff + (phnum - 2) * 56;
                let p_off = u64::from_le_bytes(out.image[o + 8..o + 16].try_into().unwrap());
                let p_fsz = u64::from_le_bytes(out.image[o + 32..o + 40].try_into().unwrap());
                assert!(
                    p_off + p_fsz == out.image.len() as u64,
                    "p_offset({p_off:#x}) + p_filesz({p_fsz:#x}) != file len ({:#x})",
                    out.image.len()
                );
            }
            Err(PackError::Runtime(_)) => {} // no host core on this machine
            Err(e) => panic!("{e}"),
        }
    }

    #[test]
    fn merged_layout_metadata_survives_on_disk() {
        // STRTAB living inside the executable PT_LOAD (NDK --no-rosegment
        // shape): its bytes must stay plaintext in the packed image —
        // sealing them garbles NEEDED parsing before init ever runs.
        const STRTAB_OFF: usize = 0x2c0; // free bytes inside the RX LOAD
        let mut img = elf_dyn_fixture(
            ElfMachine::Amd64,
            &[(5u64, STRTAB_OFF as u64), (10u64, 8u64)], // DT_STRTAB, DT_STRSZ
            false,
        );
        img[STRTAB_OFF..STRTAB_OFF + 8].copy_from_slice(b"libc.so\x00");
        match pack_elf(&req(&img, false)) {
            Ok(out) => {
                assert!(
                    &out.image[STRTAB_OFF..STRTAB_OFF + 8] == b"libc.so\x00",
                    "strtab inside the RX LOAD must survive as plaintext"
                );
            }
            Err(PackError::Runtime(_)) => {}
            Err(e) => panic!("{e}"),
        }
    }

    #[test]
    fn aarch64_without_core_is_a_named_runtime_error() {
        let img = elf_dyn_fixture(ElfMachine::Aarch64, &[], false);
        match pack_elf(&req(&img, false)) {
            Ok(out) => {
                // NDK core present: the machine field and a real image.
                assert_eq!(out.report.machine, "aarch64");
                assert!(!out.image.is_empty());
            }
            Err(PackError::Runtime(msg)) => {
                assert!(
                    msg.contains("aarch64 runtime core not built")
                        && msg.contains("NDK"),
                    "named NDK-missing error, got {msg}"
                );
            }
            Err(e) => panic!("unexpected error: {e}"),
        }
    }

    // ---- plan WS-A 2.2.3: probe assembly + report + inspect round-trip ----

    /// Pack an aarch64 fixture with the NDK core present and assert the
    /// probe manifest travels the whole path: guard mask -> stub machine
    /// code (movz+str at ctx+128) -> PackReport.probes -> PackedImage.probes
    /// -> inspect_bytes decode. Skips (without asserting) when no NDK core
    /// exists on this host -- CI installs the pinned NDK so the assert
    /// always runs there.
    fn pack_aarch64_or_skip(img: &[u8], profile: Profile) -> Option<PackOutput> {
        let r = PackRequest {
            input: img,
            profile,
            vm_exports: vec![],
            debug_gate: 3,
            opcode_seed: Some([9; 16]),
            trace_diverge: false,
            select_rva: vec![],
            select_functions: Vec::new(),
            select_all: false,
            strict_coverage: false,
            allow_native_fallback: false,
            lazy_regions: false,
            protect_imports: false,
            strict_constants: false,
        };
        match pack_elf(&r) {
            Ok(out) => Some(out),
            Err(PackError::Runtime(msg)) => {
                if msg.contains("aarch64 runtime core not built") {
                    eprintln!("skipped: no NDK aarch64 core on this host");
                    return None;
                }
                panic!("unexpected runtime error: {msg}");
            }
            Err(e) => panic!("{e}"),
        }
    }

    #[test]
    fn aarch64_probe_assembly_report_and_inspect_roundtrip() {
        use xenolith_guard::Probe;
        let img = elf_dyn_fixture(ElfMachine::Aarch64, &[], false);
        let Some(out) = pack_aarch64_or_skip(&img, Profile::Max) else {
            return;
        };
        // Max profile: the default armed set, in canonical bitmap order
        // (PtraceSelfAttach implemented but not profile-armed — freeze
        // hazard, see android_probes_for_profile).
        assert_eq!(
            out.report.probes,
            vec!["TracerPidScan", "MapsScan"],
            "report must list exactly the injected probes"
        );
        assert_eq!(
            out.packed.probes,
            vec![Probe::TracerPidScan, Probe::MapsScan]
        );
        // The report note names them and states the fail-closed contract.
        assert!(
            out.report
                .notes
                .iter()
                .any(|n| n.contains("anti-debug probes") && n.contains("TracerPidScan")),
            "notes must describe the probe set: {:?}",
            out.report.notes
        );
        // inspect decodes the same manifest back out of the machine code.
        let info = crate::inspect_bytes(&out.image).expect("packed artifact inspects");
        assert_eq!(info["packed"], serde_json::json!(true));
        assert_eq!(
            info["probes"],
            serde_json::json!(["TracerPidScan", "MapsScan"]),
            "inspect must round-trip the probe manifest from the stub bytes"
        );
        let note = info["note"].as_str().unwrap_or_default();
        assert!(!note.contains("not decodable"), "decode note: {note}");
    }

    #[test]
    fn aarch64_probe_default_profile_is_the_two_core_checks() {
        let img = elf_dyn_fixture(ElfMachine::Aarch64, &[], false);
        let Some(out) = pack_aarch64_or_skip(&img, Profile::Standard) else {
            return;
        };
        // PtraceSelfAttach is not profile-armed (freeze hazard, see
        // android_probes_for_profile) — non-Max keeps TracerPid only.
        assert_eq!(
            out.report.probes,
            vec!["TracerPidScan"],
            "non-Max profiles arm the TracerPid core check only"
        );
        let info = crate::inspect_bytes(&out.image).expect("packed artifact inspects");
        assert_eq!(info["probes"], serde_json::json!(["TracerPidScan"]));
    }

    /// x86-64 ELF: zero probes AND the explicit aarch64-only note -- the
    /// report may never pass the Windows claim through.
    #[test]
    fn x86_64_elf_reports_empty_probes_with_aarch64_only_note() {
        let img = elf_dyn_fixture(ElfMachine::Amd64, &[], false);
        let Some(out) = pack_aarch64_or_skip(&img, Profile::Max) else {
            return; // host x86-64 core also missing on this machine
        };
        assert_eq!(out.report.machine, "x86_64");
        assert!(
            out.report.probes.is_empty(),
            "x86-64 ELF must not claim any probe"
        );
        assert!(
            out.report
                .notes
                .iter()
                .any(|n| n.contains("anti-debug probes are aarch64-only")),
            "notes must carry the aarch64-only statement: {:?}",
            out.report.notes
        );
        let info = crate::inspect_bytes(&out.image).expect("packed artifact inspects");
        assert_eq!(info["probes"], serde_json::json!([]));
        assert!(
            info["note"]
                .as_str()
                .unwrap_or_default()
                .contains("anti-debug probes are aarch64-only"),
            "inspect note must state the aarch64-only scope"
        );
    }

    // ------------------------------------------------------------------
    // vm-export pipeline (vm-aarch64 design §2/§8): end-to-end gate tests.
    // ------------------------------------------------------------------

    /// `elf_dyn_fixture` plus a section-header table carrying SHT_SYMTAB /
    /// SHT_STRTAB with one named STT_FUNC whose body (liftable whitelist
    /// words) sits at FN_RVA inside the RX LOAD (file offset == vaddr).
    fn elf_dyn_fixture_with_fn(machine: ElfMachine, fn_rva: u32, body: &[u32]) -> Vec<u8> {
        let mut img = elf_dyn_fixture(machine, &[], false);
        let fn_off = fn_rva as usize;
        assert!(fn_off + body.len() * 4 <= 0x2F0, "body must fit the RX LOAD");
        for (i, w) in body.iter().enumerate() {
            img[fn_off + i * 4..fn_off + i * 4 + 4].copy_from_slice(&w.to_le_bytes());
        }
        // Sections past every LOAD: [0] NULL, [1] SYMTAB, [2] STRTAB.
        let sym_off = img.len();
        let str_off = sym_off + 24 * 2;
        let sh_off = align_up((str_off + 16) as u32, 8) as usize;
        img.resize(sh_off + 3 * 64, 0);
        // Elf64_Sym: name, info, other, shndx, value, size, size_hi
        let mut sym: Vec<u8> = Vec::new();
        sym.extend_from_slice(&1u32.to_le_bytes()); // st_name: "leaf_add"
        sym.push(0x12); // STB_GLOBAL << 4 | STT_FUNC
        sym.push(0);
        sym.extend_from_slice(&1u16.to_le_bytes()); // shndx
        sym.extend_from_slice(&(fn_rva as u64).to_le_bytes());
        sym.extend_from_slice(&((body.len() * 4) as u64).to_le_bytes());
        img[sym_off..sym_off + sym.len()].copy_from_slice(&sym);
        img[str_off..str_off + 16].copy_from_slice(b"\0leaf_add\0\0\0\0\0\0\0");
        // e_shoff / e_shentsize / e_shnum / e_shstrndx
        img[40..48].copy_from_slice(&(sh_off as u64).to_le_bytes());
        img[58..60].copy_from_slice(&64u16.to_le_bytes());
        img[60..62].copy_from_slice(&3u16.to_le_bytes());
        img[62..64].copy_from_slice(&0u16.to_le_bytes());
        let mut sh = |i: usize, ty: u32, off: u64, size: u64, link: u32| {
            let b = sh_off + i * 64;
            img[b + 4..b + 8].copy_from_slice(&ty.to_le_bytes()); // sh_type
            img[b + 24..b + 32].copy_from_slice(&off.to_le_bytes());
            img[b + 32..b + 40].copy_from_slice(&size.to_le_bytes());
            img[b + 40..b + 44].copy_from_slice(&link.to_le_bytes());
            img[b + 56..b + 64].copy_from_slice(&24u64.to_le_bytes());
        };
        sh(1, 2, sym_off as u64, 48, 2);
        sh(2, 3, str_off as u64, 16, 0);
        img
    }

    const LEAF_ADD: [u32; 2] = [0x8B01_0000, 0xD65F_03C0]; // add x0,x0,x1; ret

    /// `elf_dyn_fixture_with_fn` plus a second GLOBAL FUNC symbol
    /// `inner_alias` at `alias_va` — the alias-inside-window probe shape
    /// from independent review 2026-10-06.
    fn elf_dyn_fixture_with_alias(alias_va: u64) -> Vec<u8> {
        let mut img = elf_dyn_fixture(ElfMachine::Aarch64, &[], false);
        let fn_rva = 0x200usize;
        for (i, w) in LEAF_ADD.iter().enumerate() {
            img[fn_rva + i * 4..fn_rva + i * 4 + 4].copy_from_slice(&w.to_le_bytes());
        }
        let sym_off = img.len();
        let str_off = sym_off + 24 * 3;
        let sh_off = align_up((str_off + 24) as u32, 8) as usize;
        img.resize(sh_off + 3 * 64, 0);
        let mut sym: Vec<u8> = Vec::new();
        sym.extend_from_slice(&1u32.to_le_bytes()); // st_name "leaf_add"
        sym.push(0x12);
        sym.push(0);
        sym.extend_from_slice(&1u16.to_le_bytes());
        sym.extend_from_slice(&(fn_rva as u64).to_le_bytes());
        sym.extend_from_slice(&8u64.to_le_bytes());
        sym.extend_from_slice(&10u32.to_le_bytes()); // st_name "inner_alias"
        sym.push(0x12);
        sym.push(0);
        sym.extend_from_slice(&1u16.to_le_bytes());
        sym.extend_from_slice(&alias_va.to_le_bytes());
        sym.extend_from_slice(&4u64.to_le_bytes());
        img[sym_off..sym_off + sym.len()].copy_from_slice(&sym);
        img[str_off..str_off + 24].copy_from_slice(b"\0leaf_add\0inner_alias\0\0\0");
        img[40..48].copy_from_slice(&(sh_off as u64).to_le_bytes());
        img[58..60].copy_from_slice(&64u16.to_le_bytes());
        img[60..62].copy_from_slice(&3u16.to_le_bytes());
        let mut sh = |i: usize, ty: u32, off: u64, size: u64, link: u32| {
            let b = sh_off + i * 64;
            img[b + 4..b + 8].copy_from_slice(&ty.to_le_bytes());
            img[b + 24..b + 32].copy_from_slice(&off.to_le_bytes());
            img[b + 32..b + 40].copy_from_slice(&size.to_le_bytes());
            img[b + 40..b + 44].copy_from_slice(&link.to_le_bytes());
            img[b + 56..b + 64].copy_from_slice(&24u64.to_le_bytes());
        };
        sh(1, 2, sym_off as u64, 72, 2);
        sh(2, 3, str_off as u64, 24, 0);
        img
    }

    #[test]
    fn vm_export_rejects_symbol_alias_inside_window() {
        // Independent review 2026-10-06: an alias symbol whose st_value
        // lands strictly inside a virtualized window survived the
        // addend-only gate, packed, and its GOT/PLT slot resolved to trap
        // filler -> SIGTRAP. A/B at the scan layer: 0x204 inside
        // [0x200,0x208) is a named rejection; 0x100 outside passes.
        let rx = [(0u64, 0x300u64, 0usize, 0x300usize)];
        let windows = [(0x200u32, 8usize)];

        let inside_img = elf_dyn_fixture_with_alias(0x204);
        let parsed = elf::parse(&inside_img).unwrap();
        let err = scan_inner_label_refs(&inside_img, &parsed, &rx, &windows)
            .err()
            .expect("alias inside window must be rejected");
        let msg = format!("{err}");
        assert!(msg.contains("symtab symbol `inner_alias`"), "{msg}");
        assert!(msg.contains("0x204"), "{msg}");

        let outside_img = elf_dyn_fixture_with_alias(0x100);
        let parsed = elf::parse(&outside_img).unwrap();
        scan_inner_label_refs(&outside_img, &parsed, &rx, &windows)
            .expect("alias outside every window must pass");
    }

    #[test]
    fn aarch64_vm_export_packs_and_reports() {
        let img = elf_dyn_fixture_with_fn(ElfMachine::Aarch64, 0x200, &LEAF_ADD);
        let r = PackRequest {
            input: &img,
            profile: Profile::Max,
            vm_exports: vec!["leaf_add".into()],
            debug_gate: 3,
            opcode_seed: Some([9; 16]),
            trace_diverge: false,
            select_rva: vec![],
            select_functions: Vec::new(),
            select_all: false,
            strict_coverage: false,
            allow_native_fallback: false,
            lazy_regions: false,
            protect_imports: false,
            strict_constants: false,
        };
        let out = match pack_elf(&r) {
            Ok(out) => out,
            Err(PackError::Runtime(msg)) if msg.contains("aarch64 runtime core not built") => {
                eprintln!("skipped: no NDK aarch64 core on this host");
                return;
            }
            Err(e) => panic!("{e}"),
        };
        assert_eq!(out.report.vm_functions, 1, "one function virtualized");
        assert_eq!(out.report.selected_functions, vec!["leaf_add".to_string()]);
        let rec = &out.report.coverage[0];
        assert_eq!(rec.bucket, "transformed", "bucket: {rec:?}");
        assert_eq!(rec.rva, 0x200);
        // The appended PT_LOAD is plaintext: the guest thunk's prologue
        // (paired sub sp + stp x19,x20 saves) must be visible in it.
        let phoff = u64::from_le_bytes(out.image[32..40].try_into().unwrap()) as usize;
        let phnum = u16::from_le_bytes(out.image[56..58].try_into().unwrap()) as usize;
        let mut stub_off = None;
        for i in 0..phnum {
            let b = phoff + i * 56;
            let ty = u32::from_le_bytes(out.image[b..b + 4].try_into().unwrap());
            if ty == 1 {
                let flags =
                    u32::from_le_bytes(out.image[b + 4..b + 8].try_into().unwrap());
                let o = u64::from_le_bytes(out.image[b + 8..b + 16].try_into().unwrap());
                if flags & 1 != 0 && o > img.len() as u64 {
                    stub_off = Some(o as usize);
                }
            }
        }
        let stub_off = stub_off.expect("appended RX LOAD present");
        let words: Vec<u32> = out.image[stub_off..]
            .chunks_exact(4)
            .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
            .collect();
        // The thunk opens with  — the stub's
        // own ctx frame uses , so the PAIR identifies a thunk.
        let sub_sp = words
            .windows(2)
            .position(|w| {
                w[0] & 0xFF00_0000 == 0xD100_0000
                    && (w[0] >> 5) & 0x1F == 31
                    && w[0] & 0x1F == 31
                    && (w[0] >> 10) & 0xFFF >= 96
                    && (w[0] >> 10) & 0xFFF % 16 == 0
                    && w[1] == 0xA900_53F3
            })
            .expect("thunk frame prologue in the appended LOAD");
        assert_eq!(
            words[sub_sp + 1],
            0xA900_53F3,
            "stp x19,x20,[sp] right after the frame sub"
        );
        // inspect still decodes the packed artifact.
        let info = crate::inspect_bytes(&out.image).expect("packed artifact inspects");
        assert_eq!(info["packed"], serde_json::json!(true));
    }

    #[test]
    fn aarch64_vm_export_unsupported_instruction_fails_closed_named() {
        // bl inside the body: whole-function fail-closed with the word,
        // function name and remediation.
        let body = [0x8B01_0000u32, 0x9400_0000 | 4, 0xD65F_03C0];
        let img = elf_dyn_fixture_with_fn(ElfMachine::Aarch64, 0x200, &body);
        let r = PackRequest {
            input: &img,
            profile: Profile::Max,
            vm_exports: vec!["leaf_add".into()],
            debug_gate: 3,
            opcode_seed: Some([9; 16]),
            trace_diverge: false,
            select_rva: vec![],
            select_functions: Vec::new(),
            select_all: false,
            strict_coverage: false,
            allow_native_fallback: false,
            lazy_regions: false,
            protect_imports: false,
            strict_constants: false,
        };
        let msg = match pack_elf(&r) {
            Err(PackError::Lift(m)) => m,
            Err(PackError::Runtime(m)) if m.contains("aarch64 runtime core not built") => {
                eprintln!("skipped: no NDK aarch64 core on this host");
                return;
            }
            other => panic!("expected a named lift error, got Ok(..)"),
        };
        assert!(msg.contains("leaf_add"), "{msg}");
        assert!(msg.contains("0x94000004"), "{msg}");
        assert!(msg.contains("--allow-native-fallback"), "{msg}");
    }

    #[test]
    fn aarch64_vm_export_fallback_reports_mixed_native() {
        let body = [0x8B01_0000u32, 0x9400_0000 | 4, 0xD65F_03C0];
        let img = elf_dyn_fixture_with_fn(ElfMachine::Aarch64, 0x200, &body);
        let r = PackRequest {
            input: &img,
            profile: Profile::Max,
            vm_exports: vec!["leaf_add".into()],
            debug_gate: 3,
            opcode_seed: Some([9; 16]),
            trace_diverge: false,
            select_rva: vec![],
            select_functions: Vec::new(),
            select_all: false,
            strict_coverage: false,
            allow_native_fallback: true,
            lazy_regions: false,
            protect_imports: false,
            strict_constants: false,
        };
        let out = match pack_elf(&r) {
            Ok(out) => out,
            Err(PackError::Runtime(m)) if m.contains("aarch64 runtime core not built") => {
                eprintln!("skipped: no NDK aarch64 core on this host");
                return;
            }
            Err(e) => panic!("{e}"),
        };
        assert_eq!(out.report.vm_functions, 0);
        assert_eq!(out.report.coverage[0].bucket, "mixed_native");
        assert!(out.report.coverage[0].reason.contains("0x94000004"));
    }

    #[test]
    fn aarch64_select_rva_window_packs() {
        let img = elf_dyn_fixture_with_fn(ElfMachine::Aarch64, 0x200, &LEAF_ADD);
        let r = PackRequest {
            input: &img,
            profile: Profile::Standard,
            vm_exports: vec![],
            debug_gate: 3,
            opcode_seed: Some([9; 16]),
            trace_diverge: false,
            select_rva: vec![(0x200, 8)],
            select_functions: Vec::new(),
            select_all: false,
            strict_coverage: true,
            allow_native_fallback: false,
            lazy_regions: false,
            protect_imports: false,
            strict_constants: false,
        };
        let out = match pack_elf(&r) {
            Ok(out) => out,
            Err(PackError::Runtime(m)) if m.contains("aarch64 runtime core not built") => {
                eprintln!("skipped: no NDK aarch64 core on this host");
                return;
            }
            Err(e) => panic!("{e}"),
        };
        assert_eq!(out.report.vm_functions, 1);
        assert_eq!(out.report.selected_functions, vec!["rva_0x200".to_string()]);
    }

    #[test]
    fn x86_64_elf_selection_stays_named_rejected() {
        let img = elf_dyn_fixture(ElfMachine::Amd64, &[], false);
        let r = PackRequest {
            input: &img,
            profile: Profile::Max,
            vm_exports: vec!["whatever".into()],
            debug_gate: 3,
            opcode_seed: Some([9; 16]),
            trace_diverge: false,
            select_rva: vec![],
            select_functions: Vec::new(),
            select_all: false,
            strict_coverage: false,
            allow_native_fallback: false,
            lazy_regions: false,
            protect_imports: false,
            strict_constants: false,
        };
        let msg = match pack_elf(&r) {
            Err(PackError::Invalid(m)) => m,
            other => panic!("expected named rejection, got Ok(..)"),
        };
        assert!(msg.contains("SysV x86-64 lift"), "{msg}");
        // select-rva also stays rejected on x86-64
        let r = PackRequest {
            select_rva: vec![(0x40, 8)],
            vm_exports: vec![],
            ..r_self(&img)
        };
        let msg = match pack_elf(&r) {
            Err(PackError::Invalid(m)) => m,
            other => panic!("expected named rejection, got Ok(..)"),
        };
        assert!(msg.contains("SysV x86-64 lift"), "{msg}");
    }

    fn r_self<'a>(input: &'a [u8]) -> PackRequest<'a> {
        PackRequest {
            input,
            profile: Profile::Max,
            vm_exports: vec![],
            debug_gate: 3,
            opcode_seed: Some([9; 16]),
            trace_diverge: false,
            select_rva: vec![],
            select_functions: Vec::new(),
            select_all: false,
            strict_coverage: false,
            allow_native_fallback: false,
            lazy_regions: false,
            protect_imports: false,
            strict_constants: false,
        }
    }

    #[test]
    fn aarch64_vm_export_missing_symbol_names_alternatives() {
        let img = elf_dyn_fixture_with_fn(ElfMachine::Aarch64, 0x200, &LEAF_ADD);
        let r = PackRequest {
            vm_exports: vec!["no_such".into()],
            ..r_self(&img)
        };
        let msg = match pack_elf(&r) {
            Err(PackError::Lift(m)) => m,
            Err(PackError::Runtime(m)) if m.contains("aarch64 runtime core not built") => {
                eprintln!("skipped: no NDK aarch64 core on this host");
                return;
            }
            other => panic!("expected named error, got Ok(..)"),
        };
        assert!(msg.contains("no_such"), "{msg}");
        assert!(msg.contains("leaf_add"), "{msg}");
    }

    #[test]
    fn aarch64_vm_export_fast_profile_rejected() {
        let img = elf_dyn_fixture_with_fn(ElfMachine::Aarch64, 0x200, &LEAF_ADD);
        let r = PackRequest {
            profile: Profile::Fast,
            vm_exports: vec!["leaf_add".into()],
            ..r_self(&img)
        };
        let msg = match pack_elf(&r) {
            Err(PackError::Invalid(m)) => m,
            other => panic!("expected named rejection, got Ok(..)"),
        };
        assert!(msg.contains("standard or max"), "{msg}");
    }
}
