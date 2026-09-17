//! ELF64 AMD64 pack backend: DT_INIT bootstrap.
//!
//! ld.so stays the loader of record: PIE/RELRO/GOT-PLT are untouched. Packing
//! appends one R+X PT_LOAD (bootstrap PHDR table + PIC stub + xl_core +
//! EnvelopeV2), redirects DT_INIT into the stub, and seals every executable
//! PT_LOAD's file bytes in AEAD records (disk holds 0xCC). The stub unpacks
//! during DT_INIT — before INIT_ARRAY, before the ELF entry — then forwards
//! to the original DT_INIT.
//!
//! Fail-closed (stage 5 will revisit): PT_TLS, IFUNC symbols, IRELATIVE and
//! TLSDESC relocations, copy relocations, static linkage, missing DT_INIT,
//! and R_X86_64_RELATIVE entries that target encrypted pages (ld.so applies
//! them before DT_INIT; restoring plaintext would silently undo them).

use crate::runtime_image;
use crate::stub::{emit_elf_stub, META_ENVELOPE_LEN, META_MEASUREMENT, META_ORIGINAL_ENTRY,
    META_PAYLOAD_RVA, META_SELF_RVA, META_UNPACKED, STUB_META_LEN};
use crate::{PackError, PackOutput, PackRequest, BACKEND_PIC_STUB, PACK_REPORT_VERSION};
use xenolith_crypto::{
    image_measurement, random_nonce12, random_seed16, MbaKeyShare, Secret32,
};
use xenolith_formats::{
    align_up, elf, write_u64, classify, ImageKind,
};
use xenolith_loader::{section_name_from_seed, PackedImage, PageRecord};
use xenolith_protocol::{
    encode as encode_v2, seal_region, EnvelopeV2, PLATFORM_ELF64, POLICY_STRICT,
};
use xenolith_vm::{OpcodeMap, Program};

const R_X86_64_RELATIVE: u32 = 8;

pub fn pack_elf(request: &PackRequest<'_>) -> Result<PackOutput, PackError> {
    let kind = match classify(request.input) {
        Ok(k @ (ImageKind::Elf64Exec | ImageKind::Elf64Dyn)) => k,
        Ok(_) => return Err(PackError::Elf("not an ELF64 AMD64 image")),
        Err(e) => return Err(PackError::Format(e)),
    };
    let parsed = elf::parse(request.input).map_err(PackError::Format)?;
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
    let resolver_pages_wip: Vec<u32> = {
        let mut v: Vec<u32> = Vec::new();
        for &r in &resolvers {
            let pg = (r as u32) & !0xfff;
            if !v.contains(&pg) {
                v.push(pg);
            }
        }
        v
    };
    let (verneed, verdef) = elf::symbol_versions(request.input, &parsed).map_err(PackError::Format)?;
    // Bootstrap rides INIT_ARRAY[0]: ld.so applies its R_X86_64_RELATIVE
    // before running any init code, so redirecting the addend to the stub is
    // ASLR-proof and avoids the DT_INIT path entirely (the loader gates the
    // DT_INIT call on the un-corrupted entry-region bytes, which a packed
    // image cannot guarantee; verified empirically on glibc 2.39).
    let boot = init_array_bootstrap(request.input, &parsed)?;
    let rx = elf::rx_load_ranges(request.input, &parsed).map_err(PackError::Format)?;
    if rx.is_empty() {
        return Err(PackError::Elf("ELF has no executable PT_LOAD to protect"));
    }
    if !request.vm_exports.is_empty() || !request.select_rva.is_empty() {
        return Err(PackError::Invalid(
            "ELF function selection requires the SysV lift (stage 5); fail-closed here",
        ));
    }
    if request.strict_coverage {
        return Err(PackError::Invalid(
            "strict coverage has no selected functions on ELF in this release",
        ));
    }
    let selection_requested = !request.select_functions.is_empty() || request.select_all;
    if selection_requested && !request.allow_native_fallback {
        return Err(PackError::Invalid(
            "ELF symbol selection requires --allow-native-fallback until the SysV lift lands",
        ));
    }
    fail_closed_on_relative_into_rx(request.input, &parsed, &rx)?;

    let secret = Secret32::random();
    let opcode_seed = request.opcode_seed.unwrap_or_else(random_seed16);
    let api_salt = random_seed16();
    let mba = MbaKeyShare::split(&secret, &opcode_seed);
    let map = OpcodeMap::from_seed(&opcode_seed);
    let program = Program::encode_key_mix(map, &mba);

    let core_img = runtime_image::load_builtin()
        .map_err(|e| PackError::Runtime(e.to_string()))?;
    let stub =
        emit_elf_stub(&core_img.text, core_img.entry_off, core_img.sysv_abi)
            .map_err(PackError::Stub)?;

    // Pages: every executable PT_LOAD's file bytes, chunked at 4K. ld.so has
    // applied relocations before DT_INIT, so RELATIVE targets inside these
    // ranges were rejected above; everything else here is link-time stable.
    let mut pages = Vec::new();
    let mut page_files: Vec<(usize, usize)> = Vec::new();
    let mut page_index = 0u32;
    for (va, va_end, off, len) in &rx {
        let mut o = 0usize;
        while o < *len {
            let chunk = (*len - o).min(xenolith_crypto::PAGE_SIZE as usize);
            pages.push((
                page_index,
                (va + o as u64) as u32,
                request.input[off + o..off + o + chunk].to_vec(),
                random_nonce12(),
            ));
            page_files.push((off + o, chunk));
            page_index += 1;
            o += chunk;
        }
        let _ = va_end;
    }
    if pages.len() > xenolith_loader::MAX_PAGES {
        return Err(PackError::Invalid("too many pages"));
    }

    let mut measure_src = mba.as_bytes();
    measure_src.extend_from_slice(&opcode_seed);
    measure_src.extend_from_slice(&(pages.len() as u32).to_le_bytes());
    let measurement = image_measurement(&measure_src);
    let runtime = xenolith_crypto::mix_runtime_key(&mba, &measurement)
        .map_err(|_| PackError::Invalid("runtime key"))?;

    let mut mba_arr = [0u8; 96];
    mba_arr.copy_from_slice(&mba.as_bytes());
    let mut env_v2 = EnvelopeV2 {
        platform: PLATFORM_ELF64,
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
        // G5/TASK-026: dormant regions except the entry-keep page and the
        // IFUNC resolver pages (carved native at fill time).
        lazy: if request.lazy_regions { (0..pages.len() as u32)
            .filter(|i| {
                let (_, rva, _, _) = &pages[*i as usize];
                let page = rva & !0xfff;
                (parsed.entry as u32 & !0xfff) != page
                    && !resolver_pages_wip.contains(&(rva & !0xfff))
            })
            .collect()
        } else {
            Vec::new()
        },
        // ELF: ld.so applied all relocations before DT_INIT; the core must
        // not re-apply anything (and its PE DIR64 path is skipped for
        // platform==1).
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
            ciphertext: sealed.ciphertext.clone(),
            mac,
            stub_digest: 0,
        });
        env_v2.regions.push(sealed);
    }
    let envelope = encode_v2(&env_v2)?;

    // ---- append the new R+X PT_LOAD ----
    // Layout: [original file, section headers included] pad → new PHDR table
    // (original entries + one new LOAD) → PIC stub → EnvelopeV2. The kernel
    // maps via e_phoff (updated); the in-image PT_PHDR copy keeps the
    // original 13 entries for ld.so, so glibc's view of segments is
    // unchanged — it simply never needs to know about the stub LOAD.
    let phentsize = parsed.phentsize as usize;
    let phnum = parsed.phnum as usize;
    // +1 for the appended R+X PT_LOAD, +1 for the appended PT_GNU_EH_FRAME
    // carrying the stub's unwind records (TASK-021).
    let table_len = (phnum + 2) * phentsize;
    let new_phoff = align_up(request.input.len() as u32, 0x1000) as usize;
    let stub_off = new_phoff + table_len;
    let env_off = align_up((stub_off + stub.bytes.len()) as u32, 16) as usize;
    // TASK-021: self-contained .eh_frame (CIE+FDE for the stub) and an
    // .eh_frame_hdr binary-search table, both offset-embedded so the
    // unwinder needs zero ld.so relocations.
    let eh = crate::unwind::dwarf::eh_frame_stub(stub.bytes.len() as u32);
    let eh_off = align_up((env_off + envelope.len()) as u32, 8) as usize;
    let hdr = crate::unwind::dwarf::eh_frame_hdr(&[]);
    let hdr_off = eh_off + eh.bytes.len();
    let content_len = hdr_off + hdr.len();
    let seg_filesz = align_up(content_len as u32, 0x1000) as usize;

    let max_va_end =
        elf::max_load_vaddr_end(request.input, &parsed).map_err(PackError::Format)?;
    let load_vaddr = align_up(max_va_end as u32, 0x1000) as u64;
    if load_vaddr + seg_filesz as u64 > u32::MAX as u64 {
        return Err(PackError::Elf("ELF too large for 32-bit load vaddrs"));
    }

    let mut image = request.input.to_vec();
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
    let new_load = elf::ProgramHeader {
        p_type: elf::PT_LOAD,
        p_flags: elf::PF_R | elf::PF_X,
        p_offset: new_phoff as u64,
        p_vaddr: load_vaddr,
        p_paddr: load_vaddr,
        p_filesz: seg_filesz as u64,
        p_memsz: seg_filesz as u64,
        p_align: 0x1000,
    };
    elf::write_program_header(&mut image, &parsed_new, phnum, &new_load)
        .map_err(PackError::Format)?;
    // Kernel-facing program header table.
    write_u64(&mut image, 32, new_phoff as u64)?;
    elf::set_phnum(&mut image, (phnum + 2) as u16).map_err(PackError::Format)?;

    // `hdr` here is the zero-entry placeholder sizing the segment; the real
    // one-entry header is written later once stub_vaddr is known.
    let hdr_placeholder_len = hdr.len();
    image.resize(hdr_off + hdr_placeholder_len.max(4 + 4 + 4 + 8), 0);
    image[stub_off..stub_off + stub.bytes.len()].copy_from_slice(&stub.bytes);
    image[env_off..env_off + envelope.len()].copy_from_slice(&envelope);

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
        .copy_from_slice(&(envelope.len() as u32).to_le_bytes());
    meta[META_ORIGINAL_ENTRY..META_ORIGINAL_ENTRY + 4]
        .copy_from_slice(&(boot.orig_target as u32).to_le_bytes());
    meta[META_UNPACKED..META_UNPACKED + 4].copy_from_slice(&0u32.to_le_bytes());
    meta[META_MEASUREMENT..META_MEASUREMENT + 32].copy_from_slice(&measurement);
    for i in 0..16 {
        meta[48 + i] = opcode_seed[i];
    }
    meta[63] = request.debug_gate;
    meta[META_SELF_RVA..META_SELF_RVA + 4].copy_from_slice(&self_rva.to_le_bytes());
    image[stub_off + stub.meta_off..stub_off + stub.meta_off + STUB_META_LEN]
        .copy_from_slice(&meta);

    // Bootstrap: drop DT_INIT (an in-place tag-zero would truncate the array
    // at DT_NULL, so the remaining entries shift left), then point the
    // INIT_ARRAY[0] R_X86_64_RELATIVE addend at the stub. ld.so computes
    // *(init_array) = load_bias + addend before running it: the stub
    // unpacks, forwards to the original target, and everything else runs in
    // order.
    rebuild_dynamic_without_init(&mut image, boot.dyn_off, boot.dyn_len)?;
    write_u64(&mut image, boot.rela_addend_off, stub_vaddr)?;
    // Disk copy of protected code must not leak plaintext — except the
    // first ENTRY_KEEP bytes at e_entry, which MUST stay intact: the loader
    // decodes an ~40-byte instruction window at the entry point and skips
    // the whole init phase (DT_INIT *and* INIT_ARRAY execution) when it
    // cannot parse it (verified empirically on glibc 2.39; 36 restored
    // bytes fail, 40 pass, 64 adds margin for other toolchain _start
    // shapes). That window is the _start prologue — no protected logic.
    // Everything else is 0x90 filler; the stub restores the real bytes from
    // the AEAD envelope before any of it executes.
    const ENTRY_KEEP: usize = 64;
    let entry_keep_lo = parsed.entry as usize;
    let entry_keep_hi = entry_keep_lo + ENTRY_KEEP;
    // Resolver pages: ld.so executes IRELATIVE addends before INIT_ARRAY;
    // keep every 4K page holding a resolver out of the seal set (native
    // plaintext on disk, restored pages never touch them).
    let mut resolver_pages: Vec<u32> = Vec::new();
    for &r in &resolvers {
        let pg = (r as u32) & !0xfff;
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
                if resolver_pages.iter().any(|pg| (va as u32 & !0xfff) == *pg) {
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
        probes: Vec::new(),
        program,
        original_bytes: request.input.to_vec(),
    };

    let imports_kept_count = env_v2.imports.len();
    let coverage = if selection_requested {
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
    let selected_functions = coverage.iter().map(|c| c.name.clone()).collect();
    let report = crate::PackReport {
        report_version: PACK_REPORT_VERSION,
        profile: request.profile.as_str().to_string(),
        format: match (kind, parsed.interp) {
            // ET_DYN + PT_INTERP = PIE executable; ET_DYN alone = shared object.
            (ImageKind::Elf64Exec, _) | (ImageKind::Elf64Dyn, true) => "elf64-exec".into(),
            (ImageKind::Elf64Dyn, false) => "elf64-dyn".into(),
            _ => unreachable!("classified above"),
        },
        input_bytes: request.input.len(),
        output_bytes: image.len(),
        backend: BACKEND_PIC_STUB.into(),
        export_surface: Vec::new(),
        // GOT/PLT are filled by ld.so before DT_INIT; the runtime never
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
        vm_functions: 0,
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
            "backend=pic-stub+xl-core (ELF DT_INIT bootstrap, appended R+X PT_LOAD)".into(),
            "ld.so stays the loader: PIE/RELRO/GOT-PLT untouched; imports loader-resolved".into(),
            "executable PT_LOAD file bytes sealed as EnvelopeV2 AEAD; disk holds 0xCC".into(),
            format!(
                "tls: PT_TLS kept; models IE(GOTTPOFF)={} LD(DTPMOD/DTPREL)={}; ifunc resolvers={} on {} native pages; symbol versions verneed={} verdef={}",
                tls_census.0, tls_census.1, resolvers.len(), resolver_pages.len(), verneed, verdef
            ),
            "fail-closed: TLSDESC, TPOFF32-in-text, copy reloc, static linkage, RELATIVE into RX".into(),
            "pages copied RW then RX via raw mprotect; no long-term RWX".into(),
            format!("payload section name: {:02x?}", section_name_from_seed(&opcode_seed, 0)),
        ],
    };

    Ok(PackOutput {
        image,
        report,
        packed,
    })
}

/// R_X86_64_RELATIVE applied by ld.so *before* DT_INIT would be overwritten
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
        if (info & 0xffff_ffff) as u32 == R_X86_64_RELATIVE
            && rx.iter().any(|(lo, hi, _, _)| r_offset >= *lo && r_offset < *hi)
        {
            return Err(PackError::Invalid(
                "ELF R_X86_64_RELATIVE targets an encrypted page (ld.so applies it before DT_INIT)",
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
    /// File offset of the INIT_ARRAY[0] R_X86_64_RELATIVE *addend* field.
    rela_addend_off: usize,
    /// Original addend: the function the stub must forward to after unpack.
    orig_target: u64,
}

const DT_INIT: u64 = 12;
const DT_INIT_ARRAY: u64 = 25;
const DT_INIT_ARRAYSZ: u64 = 26;
const DT_RELA: u64 = 7;
const DT_RELASZ: u64 = 8;

fn init_array_bootstrap(input: &[u8], parsed: &elf::Elf64) -> Result<InitArrayBoot, PackError> {
    let phdrs = elf::program_headers(input, parsed).map_err(PackError::Format)?;
    let (mut dyn_off, mut dyn_len) = (0usize, 0usize);
    let (mut rela_va, mut rela_sz) = (0u64, 0u64);
    let (mut init_array_va, mut init_array_sz) = (0u64, 0u64);
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
    let mut saw_init_arraysz = false;
    let mut saw_misfini_slot = false;
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
            // Known broken-linker shape: DT_INIT_ARRAYSZ mis-emitted as
            // DT_FINI_ARRAY with a tiny non-vaddr value. Recognized only for
            // the diagnostic; the pack still refuses (below).
            0x1b if val < 0x1000 => saw_misfini_slot = true,
            _ => {}
        }
        i += 16;
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
        if r_offset == init_array_va && (r_info & 0xffff_ffff) as u32 == R_X86_64_RELATIVE {
            return Ok(InitArrayBoot {
                dyn_off,
                dyn_len,
                rela_addend_off: o + 16,
                orig_target: r_addend,
            });
        }
    }
    Err(PackError::Elf(
        "INIT_ARRAY[0] has no R_X86_64_RELATIVE relocation (non-PIE-style init slot)",
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
