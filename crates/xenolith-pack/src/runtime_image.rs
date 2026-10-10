//! Validate a compiled runtime object before it is copied into a packed image.
//!
//! The rustc `xenolith-runtime` cdylib is **not** injectable: it has a
//! KERNEL32/VCRUNTIME import table. Production injection is the freestanding
//! `xenolith-runtime/core/xl_core.c` object, checked here — one host-compiled
//! x86-64 object (COFF on Windows, ET_REL on Linux) and one NDK-compiled
//! aarch64 ET_REL object for Android packing.

use thiserror::Error;
use xenolith_formats::elf_aarch64;

#[derive(Debug, Error)]
pub enum RuntimeImageError {
    #[error("runtime object missing: {0}")]
    Missing(String),
    #[error("runtime object is not a supported COFF/ELF object")]
    Format,
    #[error("runtime object has imports or CRT dependencies")]
    Imports,
    #[error("runtime object has unsupported relocations")]
    Relocs,
    #[error("xl_core_activate not found")]
    Symbol,
    #[error("{0}")]
    Invalid(&'static str),
}

/// Which injected core to load: the host-built x86-64 object or the
/// NDK-built aarch64 object (Android).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoreArch {
    X8664,
    Aarch64,
}

#[derive(Clone, Debug)]
pub struct RuntimeImage {
    pub text: Vec<u8>,
    pub entry_off: u32,
    /// G5/TASK-026 entry points inside the embedded core object.
    pub fault_off: u32,
    pub quiesce_off: u32,
    /// Initialized state (.xlg) — MUST land on its own page in the image:
    /// it is flipped RW at runtime, which would strip X from any code
    /// sharing the page.
    pub state: Vec<u8>,
    /// Calling convention of the HOST compiler that produced the object:
    /// false = Win64 (MSVC COFF), true = SysV (gcc/clang ELF). The stub
    /// passes XlHostCtx in RCX vs RDI and hands the core a matching
    /// vprotect trampoline.
    pub sysv_abi: bool,
}

struct CoffSec {
    index: usize,
    raw_ptr: usize,
    raw_size: u32,
    nreloc: u16,
    reloc_ptr: u32,
    chars: u32,
    name: [u8; 8],
}

pub fn validate_and_extract(obj: &[u8], arch: CoreArch) -> Result<RuntimeImage, RuntimeImageError> {
    if obj.len() >= 4 && obj.starts_with(b"\x7fELF") {
        // Linux-hosted builds: cc emits an ELF64 ET_REL object (x86-64 host)
        // and the NDK emits an ELF64 ET_REL aarch64 object. Same flat layout
        // contract as the COFF path below ([core text][.xlg state], .xlg
        // relocations shifted by the emit-time page pad).
        return match arch {
            CoreArch::X8664 => extract_elf_rel(obj),
            CoreArch::Aarch64 => extract_elf_rel_aarch64(obj),
        };
    }
    if arch != CoreArch::X8664 {
        // The aarch64 core is only ever an NDK ELF ET_REL; a COFF blob means
        // the probe picked up the wrong object.
        return Err(RuntimeImageError::Format);
    }
    if obj.len() < 20 {
        return Err(RuntimeImageError::Format);
    }
    let machine = u16::from_le_bytes(obj[0..2].try_into().unwrap());
    if machine != 0x8664 {
        return Err(RuntimeImageError::Format);
    }
    let nsec = u16::from_le_bytes(obj[2..4].try_into().unwrap()) as usize;
    let ptrsym = u32::from_le_bytes(obj[8..12].try_into().unwrap()) as usize;
    let nsyms = u32::from_le_bytes(obj[12..16].try_into().unwrap()) as usize;
    let opt = u16::from_le_bytes(obj[16..18].try_into().unwrap()) as usize;
    let sec_off = 20 + opt;
    let mut secs = Vec::new();
    for i in 0..nsec {
        let o = sec_off + i * 40;
        if o + 40 > obj.len() {
            return Err(RuntimeImageError::Format);
        }
        let mut name = [0u8; 8];
        name.copy_from_slice(&obj[o..o + 8]);
        let raw_size = u32::from_le_bytes(obj[o + 16..o + 20].try_into().unwrap());
        let raw_ptr = u32::from_le_bytes(obj[o + 20..o + 24].try_into().unwrap());
        let reloc_ptr = u32::from_le_bytes(obj[o + 24..o + 28].try_into().unwrap());
        let nreloc = u16::from_le_bytes(obj[o + 32..o + 34].try_into().unwrap());
        let chars_s = u32::from_le_bytes(obj[o + 36..o + 40].try_into().unwrap());
        if name.starts_with(b".idata") {
            return Err(RuntimeImageError::Imports);
        }
        secs.push(CoffSec {
            index: i,
            raw_ptr: raw_ptr as usize,
            raw_size,
            nreloc,
            reloc_ptr,
            chars: chars_s,
            name,
        });
    }

    let mut text_idx: Vec<usize> = secs
        .iter()
        .filter(|s| {
            s.raw_size > 0
                && (s.name.starts_with(b".text")
                    || s.chars & 0x20 != 0
                    || s.name.starts_with(b".xlg"))
                && (s.chars & 0x40 == 0 || s.name.starts_with(b".xlg"))
        })
        .map(|s| s.index)
        .collect();
    if text_idx.is_empty() {
        return Err(RuntimeImageError::Invalid("no .text"));
    }
    // .xlg must land AFTER every .text part: text_len (where the state
    // splits off) is measured at the last .text section, and the emitted
    // layout is [core text][pad][guard][state]. Section-index order in the
    // object has .xlg BEFORE .text$mn, so order explicitly.
    text_idx.sort_by_key(|&i| (secs[i].name.starts_with(b".xlg"), i));

    let mut bytes = Vec::new();
    let mut sec_base = vec![None; nsec];
    let mut text_len = 0usize;
    for &i in &text_idx {
        let s = &secs[i];
        if s.raw_ptr.saturating_add(s.raw_size as usize) > obj.len() {
            return Err(RuntimeImageError::Format);
        }
        sec_base[i] = Some(bytes.len() as u32);
        bytes.extend_from_slice(&obj[s.raw_ptr..s.raw_ptr + s.raw_size as usize]);
        if s.name.starts_with(b".text") {
            text_len = bytes.len();
        }
    }

    let mut entry = None;
    let mut fault = None;
    let mut quiesce = None;
    let strtab_off = if nsyms > 0 {
        let off = ptrsym + nsyms * 18;
        if ptrsym == 0 || off + 4 > obj.len() {
            return Err(RuntimeImageError::Format);
        }
        Some(off)
    } else {
        None
    };
    let sym_name = |idx: usize| -> String {
        let o = ptrsym.saturating_add(idx.saturating_mul(18));
        if o + 18 > obj.len() {
            return String::new();
        }
        if obj[o..o + 4] == [0, 0, 0, 0] {
            let Some(strtab_off) = strtab_off else {
                return String::new();
            };
            let off = u32::from_le_bytes(obj[o + 4..o + 8].try_into().unwrap()) as usize;
            cstr_at(obj, strtab_off + off)
        } else {
            let end = obj[o..o + 8].iter().position(|&b| b == 0).unwrap_or(8);
            String::from_utf8_lossy(&obj[o..o + end]).into_owned()
        }
    };
    if nsyms > 0 {
        let mut i = 0;
        while i < nsyms {
            let o = ptrsym + i * 18;
            if o + 18 > obj.len() {
                break;
            }
            let value = u32::from_le_bytes(obj[o + 8..o + 12].try_into().unwrap());
            let sec_num = i16::from_le_bytes(obj[o + 12..o + 14].try_into().unwrap());
            let sclass = obj[o + 16];
            let naux = obj[o + 17] as usize;
            let name = sym_name(i);
            let pick = |slot: &mut Option<u32>, want: &str, slot_name: &str| {
                if sclass == 2 && (name == want || name == format!("_{want}")) && slot.is_none() {
                    if sec_num <= 0 {
                        return Err(RuntimeImageError::Symbol);
                    }
                    let si = (sec_num as usize).saturating_sub(1);
                    let base =
                        sec_base.get(si).and_then(|b| *b).ok_or(RuntimeImageError::Symbol)?;
                    let off = base + value;
                    if off as usize >= bytes.len() {
                        return Err(RuntimeImageError::Symbol);
                    }
                    let _ = slot_name;
                    *slot = Some(off);
                }
                Ok(())
            };
            pick(&mut entry, "xl_core_activate", "entry")?;
            pick(&mut fault, "xl_core_fault", "fault")?;
            pick(&mut quiesce, "xl_core_quiesce", "quiesce")?;
            i += 1 + naux;
        }
    }

    // The stub emits [core text][page pad][guard page][state][meta]. The
    // extra 0x1000 guard keeps VirtualProtect(&g_xl) off every code page
    // even though core text is not section-page-aligned. Patch .xlg
    // relocations with that same pad so injected references resolve here.
    let pad = (0x1000 - (text_len % 0x1000)) % 0x1000 + 0x1000;
    for &i in &text_idx {
        let s = &secs[i];
        if s.nreloc == 0 {
            continue;
        }
        let this_base = sec_base[i].unwrap();
        let rel_off = s.reloc_ptr as usize;
        for r in 0..s.nreloc as usize {
            let o = rel_off + r * 10;
            if o + 10 > obj.len() {
                return Err(RuntimeImageError::Relocs);
            }
            let va = u32::from_le_bytes(obj[o..o + 4].try_into().unwrap());
            let mut sym_idx =
                u32::from_le_bytes(obj[o + 4..o + 8].try_into().unwrap()) as usize;
            let typ = u16::from_le_bytes(obj[o + 8..o + 10].try_into().unwrap());
            let mut so = ptrsym + sym_idx * 18;
            if so + 18 > obj.len() {
                return Err(RuntimeImageError::Relocs);
            }
            let mut sec_num = i16::from_le_bytes(obj[so + 12..so + 14].try_into().unwrap());
            if sec_num <= 0 {
                // MSVC can leave a relocation against the external spelling
                // of a symbol that is also defined in this same object (for
                // example the freestanding memcpy/memset implementations).
                // Resolve that alias locally; unresolved names remain a hard
                // import failure.
                let want = sym_name(sym_idx);
                let mut found = None;
                let mut j = 0usize;
                while j < nsyms {
                    let jo = ptrsym + j * 18;
                    if jo + 18 > obj.len() {
                        break;
                    }
                    let jsec =
                        i16::from_le_bytes(obj[jo + 12..jo + 14].try_into().unwrap());
                    if jsec > 0 && sym_name(j) == want {
                        found = Some(j);
                        break;
                    }
                    j += 1 + obj[jo + 17] as usize;
                }
                sym_idx = found.ok_or(RuntimeImageError::Imports)?;
                so = ptrsym + sym_idx * 18;
                sec_num = i16::from_le_bytes(obj[so + 12..so + 14].try_into().unwrap());
            }
            let si = (sec_num as usize).saturating_sub(1);
            let mut dest_base =
                sec_base.get(si).and_then(|b| *b).ok_or(RuntimeImageError::Relocs)?;
            if secs[si].name.starts_with(b".xlg") {
                dest_base += pad as u32;
            }
            let sym_val = u32::from_le_bytes(obj[so + 8..so + 12].try_into().unwrap());
            let at = (this_base + va) as usize;
            match typ {
                // 4 = REL32 (calls/jmps); 5 and 8 are the RIP-relative
                // disp32 data forms MSVC emits for cmp/mov [rip+disp32].
                // All three resolve identically for an intra-object symbol.
                0x0004 | 0x0005 | 0x0008 => {
                    if at + 4 > bytes.len() {
                        return Err(RuntimeImageError::Relocs);
                    }
                    let addend = i32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
                    let next = this_base.wrapping_add(va).wrapping_add(4);
                    let rel =
                        (dest_base as i64 + sym_val as i64 + addend as i64 - next as i64) as i32;
                    bytes[at..at + 4].copy_from_slice(&rel.to_le_bytes());
                }
                _ => return Err(RuntimeImageError::Relocs),
            }
        }
    }

    let entry_off = entry.ok_or(RuntimeImageError::Symbol)?;
    if entry_off as usize >= bytes.len() {
        return Err(RuntimeImageError::Symbol);
    }
    let state = bytes.split_off(text_len);
    Ok(RuntimeImage {
        text: bytes,
        entry_off,
        fault_off: fault.ok_or(RuntimeImageError::Symbol)?,
        quiesce_off: quiesce.ok_or(RuntimeImageError::Symbol)?,
        state,
        sysv_abi: false,
    })
}

/// ELF64 ET_REL extraction (gcc/clang `cc -c` output on Linux hosts).
/// Mirrors the COFF contract: collect `.text*` then `.xlg` into one flat
/// blob, resolve xl_core_* symbols, apply intra-object PC32/PLT32 RELAs
/// with the `.xlg` pad, and split state at the end of the last .text.
fn extract_elf_rel(obj: &[u8]) -> Result<RuntimeImage, RuntimeImageError> {
    extract_elf_rel_machine(obj, 62, false)
}

/// aarch64 twin of `extract_elf_rel`: same flat-blob contract, AArch64
/// instruction-field relocation application. Anything outside the clang
/// `-fpie -mbranch-protection=none` whitelist fails closed (Relocs) exactly
/// like the x86-64 PC32/PLT32-only rule.
fn extract_elf_rel_aarch64(obj: &[u8]) -> Result<RuntimeImage, RuntimeImageError> {
    extract_elf_rel_machine(obj, 183, true)
}

fn extract_elf_rel_machine(
    obj: &[u8],
    machine: u16,
    aarch64: bool,
) -> Result<RuntimeImage, RuntimeImageError> {
    const SHT_SYMTAB: u32 = 2;
    const SHT_RELA: u32 = 4;
    const SHT_NOBITS: u32 = 8;
    const R_X86_64_PC32: u32 = 2;
    const R_X86_64_PLT32: u32 = 4;

    if obj.len() < 64 {
        return Err(RuntimeImageError::Format);
    }
    let rd_u16 = |o: usize| u16::from_le_bytes(obj[o..o + 2].try_into().unwrap());
    let rd_u32 = |o: usize| u32::from_le_bytes(obj[o..o + 4].try_into().unwrap());
    let rd_u64 = |o: usize| u64::from_le_bytes(obj[o..o + 8].try_into().unwrap());
    if rd_u16(16) != 1 || rd_u16(18) != machine {
        return Err(RuntimeImageError::Format); // ET_REL, expected machine only
    }
    let shoff = rd_u64(40) as usize;
    let shentsize = rd_u16(58) as usize;
    let shnum = rd_u16(60) as usize;
    let shstrndx = rd_u16(62) as usize;
    if shentsize != 64 || shnum == 0 || shoff.saturating_add(shnum * 64) > obj.len() {
        return Err(RuntimeImageError::Format);
    }
    let sh = |i: usize| (shoff + i * 64, rd_u32(shoff + i * 64 + 4), rd_u64(shoff + i * 64 + 24) as usize, rd_u64(shoff + i * 64 + 32) as usize, rd_u32(shoff + i * 64 + 40) as usize);
    let (_, _, str_off, str_size, _) = sh(shstrndx);
    if str_off.saturating_add(str_size) > obj.len() {
        return Err(RuntimeImageError::Format);
    }
    let name_of = |i: usize| -> String {
        let no = rd_u32(shoff + i * 64) as usize;
        if str_off + no >= obj.len() {
            return String::new();
        }
        cstr_at(obj, str_off + no)
    };

    // Layout: every .text* section first, .xlg last (state split point).
    let mut text_idx: Vec<usize> = Vec::new();
    let mut xlg_idx: Option<usize> = None;
    for i in 0..shnum {
        let (_, ty, _, size, _) = sh(i);
        let name = name_of(i);
        if name == ".xlg" {
            if ty == SHT_NOBITS || size == 0 {
                // The injected image must carry the state bytes inline.
                return Err(RuntimeImageError::Invalid(
                    ".xlg must be initialized PROGBITS (zero initializer would land in .bss)",
                ));
            }
            xlg_idx = Some(i);
        } else if name.starts_with(".text") && size > 0 {
            text_idx.push(i);
        }
    }
    if text_idx.is_empty() {
        return Err(RuntimeImageError::Invalid("no .text"));
    }
    if let Some(n) = xlg_idx {
        text_idx.push(n);
    }
    text_idx.sort_by_key(|&i| (name_of(i) == ".xlg", i));

    let mut bytes: Vec<u8> = Vec::new();
    let mut sec_base = vec![None; shnum];
    let mut text_len = 0usize;
    for &i in &text_idx {
        let (_, ty, off, size, _) = sh(i);
        sec_base[i] = Some(bytes.len() as u32);
        if ty == SHT_NOBITS {
            bytes.resize(bytes.len() + size, 0);
        } else {
            if off.saturating_add(size) > obj.len() {
                return Err(RuntimeImageError::Format);
            }
            bytes.extend_from_slice(&obj[off..off + size]);
        }
        if name_of(i).starts_with(".text") {
            text_len = bytes.len();
        }
    }

    // Symtab: pick the xl_core_* entry points.
    let mut entry = None;
    let mut fault = None;
    let mut quiesce = None;
    let mut symtab: Option<(usize, usize, usize)> = None; // (offset, bytes, strtab section)
    for i in 0..shnum {
        let (o, ty, off, size, link) = sh(i);
        let _ = o;
        if ty == SHT_SYMTAB {
            symtab = Some((off, size, link));
            break;
        }
    }
    let Some((sym_off, sym_sz, sym_link)) = symtab else {
        return Err(RuntimeImageError::Symbol);
    };
    let (_, _, sym_str_off, sym_str_size, _) = sh(sym_link);
    if sym_off.saturating_add(sym_sz) > obj.len()
        || sym_str_off.saturating_add(sym_str_size) > obj.len()
    {
        return Err(RuntimeImageError::Format);
    }
    let nsym = sym_sz / 24;
    let sym_shndx = |i: usize| rd_u16(sym_off + i * 24 + 6);
    let sym_value = |i: usize| rd_u64(sym_off + i * 24 + 8);
    let sym_name = |i: usize| -> String {
        let no = rd_u32(sym_off + i * 24) as usize;
        if sym_str_off + no >= obj.len() {
            return String::new();
        }
        cstr_at(obj, sym_str_off + no)
    };
    for i in 0..nsym {
        let name = sym_name(i);
        let shndx = sym_shndx(i) as usize;
        let pick = |slot: &mut Option<u32>, want: &str| -> Result<(), RuntimeImageError> {
            if name == want && slot.is_none() && shndx != 0 {
                let base = sec_base
                    .get(shndx)
                    .and_then(|b| *b)
                    .ok_or(RuntimeImageError::Symbol)?;
                let off = base + sym_value(i) as u32;
                if off as usize >= bytes.len() {
                    return Err(RuntimeImageError::Symbol);
                }
                *slot = Some(off);
            }
            Ok(())
        };
        pick(&mut entry, "xl_core_activate")?;
        pick(&mut fault, "xl_core_fault")?;
        pick(&mut quiesce, "xl_core_quiesce")?;
    }

    // RELA application with the same .xlg pad the emitter inserts.
    let pad = (0x1000 - (text_len % 0x1000)) % 0x1000 + 0x1000;
    for &sec in &text_idx {
        for i in 0..shnum {
            // sh_info (not sh_link — that is the symtab index) selects the
            // section this RELA table applies to.
            let info = rd_u32(shoff + i * 64 + 44) as usize;
            let (_, ty, off, size, _) = sh(i);
            if ty != SHT_RELA || info != sec {
                continue;
            }
            let n = size / 24;
            for r in 0..n {
                let o = off + r * 24;
                if o + 24 > obj.len() {
                    return Err(RuntimeImageError::Relocs);
                }
                let r_offset = rd_u64(o) as u32;
                let r_info = rd_u64(o + 8);
                let addend = i64::from_le_bytes(obj[o + 16..o + 24].try_into().unwrap());
                let sym = (r_info >> 32) as usize;
                let typ = (r_info & 0xffff_ffff) as u32;
                if sym >= nsym {
                    return Err(RuntimeImageError::Relocs);
                }
                let shndx = sym_shndx(sym) as usize;
                if shndx == 0 {
                    return Err(RuntimeImageError::Imports); // undefined external
                }
                let mut dest_base = sec_base
                    .get(shndx)
                    .and_then(|b| *b)
                    .ok_or(RuntimeImageError::Relocs)?;
                if name_of(shndx) == ".xlg" {
                    dest_base += pad as u32;
                }
                let this_base = sec_base[sec].ok_or(RuntimeImageError::Relocs)?;
                let at = (this_base + r_offset) as usize;
                if aarch64 {
                    if at % 4 != 0 || at + 4 > bytes.len() {
                        return Err(RuntimeImageError::Relocs);
                    }
                    let s = dest_base as i64 + sym_value(sym) as i64;
                    let p = (this_base + r_offset) as i64;
                    let word = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
                    let fixed = apply_aarch64_reloc(word, typ, s, addend, p)?;
                    bytes[at..at + 4].copy_from_slice(&fixed.to_le_bytes());
                } else {
                    match typ {
                        R_X86_64_PC32 | R_X86_64_PLT32 => {
                            if at + 4 > bytes.len() {
                                return Err(RuntimeImageError::Relocs);
                            }
                            // ELF PC32/PLT32: S + A - P with P at the field
                            // itself; the rip-relative "-4" already lives in
                            // the assembler-provided addend (unlike COFF REL32).
                            let s = dest_base as i64 + sym_value(sym) as i64;
                            let p = (this_base + r_offset) as i64;
                            let rel = (s + addend - p) as i32;
                            bytes[at..at + 4].copy_from_slice(&rel.to_le_bytes());
                        }
                        _ => return Err(RuntimeImageError::Relocs),
                    }
                }
            }
        }
    }

    let state = bytes.split_off(text_len);
    Ok(RuntimeImage {
        text: bytes,
        entry_off: entry.ok_or(RuntimeImageError::Symbol)?,
        fault_off: fault.ok_or(RuntimeImageError::Symbol)?,
        quiesce_off: quiesce.ok_or(RuntimeImageError::Symbol)?,
        state,
        sysv_abi: true,
    })
}

fn cstr_at(buf: &[u8], off: usize) -> String {
    if off >= buf.len() {
        return String::new();
    }
    let end = buf[off..]
        .iter()
        .position(|&b| b == 0)
        .map(|p| off + p)
        .unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[off..end]).into_owned()
}

/// Apply one whitelisted AArch64 ET_REL relocation in place. `s`/`a`/`p` are
/// the ELF S+A-P triple in flat-blob coordinates. Every field insertion
/// follows the ARM ARM immediate layouts; anything outside the whitelist or
/// any range violation is a hard `Relocs` failure (fail-closed, mirroring
/// the x86-64 PC32/PLT32-only rule).
fn apply_aarch64_reloc(
    word: u32,
    typ: u32,
    s: i64,
    a: i64,
    p: i64,
) -> Result<u32, RuntimeImageError> {
    use elf_aarch64::*;
    let in_range = |v: i64, bits: u32| -> bool { v >= -(1i64 << (bits - 1)) && v < (1i64 << (bits - 1)) };
    match typ {
        R_AARCH64_JUMP26 | R_AARCH64_CALL26 => {
            let rel = s + a - p;
            let imm = rel >> 2;
            if rel & 3 != 0 || !in_range(imm, 26) {
                return Err(RuntimeImageError::Relocs);
            }
            Ok((word & 0xFC00_0000) | ((imm as u32) & 0x03FF_FFFF))
        }
        R_AARCH64_CONDBR19 => {
            let rel = s + a - p;
            let imm = rel >> 2;
            if rel & 3 != 0 || !in_range(imm, 19) {
                return Err(RuntimeImageError::Relocs);
            }
            Ok((word & 0xFF00_001F) | (((imm as u32) & 0x7FFFF) << 5))
        }
        R_AARCH64_TSTBR14 => {
            let rel = s + a - p;
            let imm = rel >> 2;
            if rel & 3 != 0 || !in_range(imm, 14) {
                return Err(RuntimeImageError::Relocs);
            }
            Ok((word & 0xFFF8_001F) | (((imm as u32) & 0x3FFF) << 5))
        }
        R_AARCH64_ADR_PREL_LO21 => {
            let rel = s + a - p;
            if !in_range(rel, 21) {
                return Err(RuntimeImageError::Relocs);
            }
            let imm = rel as u32 & 0x1F_FFFF; // 21 bits, two's complement
            let immlo = imm & 0x3;
            let immhi = (imm >> 2) & 0x7_FFFF;
            Ok((word & 0x9F00_001F) | (immlo << 29) | (immhi << 5))
        }
        R_AARCH64_ADR_PREL_PG_HI21 => {
            let prel = ((s + a) & !0xFFF) - (p & !0xFFF);
            let imm = prel >> 12;
            if !in_range(imm, 21) {
                return Err(RuntimeImageError::Relocs);
            }
            let imm = imm as u32 & 0x1F_FFFF;
            let immlo = imm & 0x3;
            let immhi = (imm >> 2) & 0x7_FFFF;
            Ok((word & 0x9F00_001F) | (immlo << 29) | (immhi << 5))
        }
        R_AARCH64_ADD_ABS_LO12_NC => {
            let imm12 = ((s + a) & 0xFFF) as u32;
            Ok((word & 0xFFC0_03FF) | (imm12 << 10))
        }
        R_AARCH64_LDST8_ABS_LO12_NC
        | R_AARCH64_LDST16_ABS_LO12_NC
        | R_AARCH64_LDST32_ABS_LO12_NC
        | R_AARCH64_LDST64_ABS_LO12_NC => {
            // The unsigned-offset immediate is scaled by the access size,
            // encoded in the instruction's own size bits [31:30].
            let scale = (word >> 30) & 0x3;
            let imm12 = (((s + a) & 0xFFF) >> scale) as u32;
            Ok((word & 0xFFC0_03FF) | (imm12 << 10))
        }
        R_AARCH64_LDST128_ABS_LO12_NC => {
            // 128-bit SIMD&FP accesses always scale by 16.
            let imm12 = (((s + a) & 0xFFF) >> 4) as u32;
            Ok((word & 0xFFC0_03FF) | (imm12 << 10))
        }
        _ => Err(RuntimeImageError::Relocs),
    }
}

pub fn load_builtin(arch: CoreArch) -> Result<RuntimeImage, RuntimeImageError> {
    let bytes = builtin_object_bytes(arch)?;
    validate_and_extract(&bytes, arch)
}

fn builtin_object_bytes(arch: CoreArch) -> Result<Vec<u8>, RuntimeImageError> {
    // The core objects are EMBEDDED via include_bytes!, never read off the
    // build machine's disk at runtime. v1.1.0 shipped a CLI whose "builtin"
    // loader fs::read() the build-time OUT_DIR path — the downloaded exe
    // could not pack anything (PE included) off the CI runner. The env-var
    // overrides remain for local dev/test cycles against a fresh object.
    match arch {
        CoreArch::X8664 => {
            let path = option_env!("XL_CORE_OBJ").unwrap_or("");
            if !path.is_empty() {
                return std::fs::read(path).map_err(|e| RuntimeImageError::Missing(e.to_string()));
            }
            Ok(include_bytes!(concat!(env!("OUT_DIR"), "/xl_core.obj")).to_vec())
        }
        CoreArch::Aarch64 => {
            if env!("XL_AARCH64_CORE") != "1" {
                return Err(RuntimeImageError::Missing(
                    "aarch64 runtime core not built (NDK not found): set \
                     ANDROID_NDK_HOME/ANDROID_NDK_ROOT/ANDROID_HOME and rebuild; \
                     x86-64/PE packing is unaffected".to_string(),
                ));
            }
            Ok(include_bytes!(concat!(env!("OUT_DIR"), "/xl_core_aarch64.o")).to_vec())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rustc_runtime_dll_is_rejected() {
        let dll = std::fs::read("target/release/xenolith_runtime.dll")
            .or_else(|_| std::fs::read("../../target/release/xenolith_runtime.dll"));
        if let Ok(bytes) = dll {
            assert!(validate_and_extract(&bytes, CoreArch::X8664).is_err());
        }
    }

    #[test]
    fn builtin_core_has_entry() {
        match load_builtin(CoreArch::X8664) {
            Ok(img) => {
                assert!(!img.text.is_empty());
                assert!((img.entry_off as usize) < img.text.len());
                assert!(
                    (img.fault_off as usize) < img.text.len(),
                    "fault_off {:#x} outside text {}",
                    img.fault_off,
                    img.text.len()
                );
                eprintln!(
                    "CORE text={} fault={:#x} quiesce={:#x} state={}",
                    img.text.len(),
                    img.fault_off,
                    img.quiesce_off,
                    img.state.len()
                );
            }
            Err(e) => panic!("xl_core object missing or invalid: {e}"),
        }
    }

    #[test]
    fn aarch64_builtin_named_error_or_valid() {
        // Without an NDK at build time the marker is NONE and the error must
        // carry the named reason; with an NDK the object must extract cleanly.
        // Both outcomes are honest — anything else is a defect.
        match load_builtin(CoreArch::Aarch64) {
            Ok(img) => {
                assert!(!img.text.is_empty());
                assert!((img.entry_off as usize) < img.text.len());
                assert_eq!(img.entry_off % 4, 0, "AAPCS64 entry must stay word-aligned");
            }
            Err(RuntimeImageError::Missing(msg)) => {
                assert!(
                    msg.contains("aarch64 runtime core not built") && msg.contains("NDK"),
                    "named NDK-missing error, got {msg}"
                );
            }
            Err(e) => panic!("unexpected aarch64 core error: {e}"),
        }
    }

    /// Synthetic aarch64 ET_REL exercising the whole relocation whitelist.
    /// Twelve-word .text (activate@0, fault@40, quiesce@44 = bare `ret`s),
    /// 16-byte .xlg `g_state`, one RELA per whitelisted type. Returns the
    /// image plus the flat-blob address the extractor must assign to
    /// `g_state` (text_len 48 → pad 0x1FD0 → state at 0x2000).
    fn aarch64_et_rel(relas: &[(u32, u32, i64)], machine: u16) -> Vec<u8> {
        const TEXT_WORDS: usize = 12;
        let text_len = TEXT_WORDS * 4; // 48
        // Placeholder instruction words: LDST64/TSTBR14 bases must already
        // carry their size/bit fields (the extractor only inserts immediates).
        let words = [
            0x9400_0000u32, // 0:  bl   xl_core_fault          (CALL26)
            0x9000_0000u32, // 4:  adrp x0, g_state            (PG_HI21)
            0x9100_0000u32, // 8:  add  x0, x0, :lo12: g_state (ADD_LO12_NC)
            0x1000_0001u32, // 12: adr  x1, xl_core_activate   (ADR_PREL_LO21)
            0xF940_0002u32, // 16: ldr  x2, [x0, :lo12: g_state] (LDST64)
            0x5400_0001u32, // 20: b.ne xl_core_activate       (CONDBR19)
            0x3718_0000u32, // 24: tbnz x0, #3, activate       (TSTBR14)
            0x1400_0000u32, // 28: b    xl_core_activate       (JUMP26)
            0xD65F_03C0u32, // 32: ret
            0xD65F_03C0u32, // 36: ret
            0xD65F_03C0u32, // 40: ret  (xl_core_fault)
            0xD65F_03C0u32, // 44: ret  (xl_core_quiesce)
        ];

        const TEXT_OFF: usize = 64;
        let XLG_OFF: usize = TEXT_OFF + text_len;
        const XLG_LEN: usize = 16;
        let SYM_OFF: usize = XLG_OFF + XLG_LEN;
        const NSYM: usize = 5;
        let RELA_OFF: usize = SYM_OFF + NSYM * 24;
        let strtab: &[u8] = b"\0xl_core_activate\0xl_core_fault\0xl_core_quiesce\0g_state\0";
        let str_off = RELA_OFF + relas.len() * 24;
        let shstr: &[u8] = b"\0.text\0.xlg\0.symtab\0.rela.text\0.strtab\0.shstrtab\0";
        let shstr_off = str_off + strtab.len();
        let shoff = shstr_off + shstr.len();
        const SHNUM: usize = 7;
        let total = shoff + SHNUM * 64;

        let mut img = vec![0u8; total];
        img[0..4].copy_from_slice(b"\x7fELF");
        img[4] = 2;
        img[5] = 1;
        img[16..18].copy_from_slice(&1u16.to_le_bytes()); // ET_REL
        img[18..20].copy_from_slice(&machine.to_le_bytes());
        img[20..24].copy_from_slice(&1u32.to_le_bytes());
        img[40..48].copy_from_slice(&(shoff as u64).to_le_bytes());
        img[52..54].copy_from_slice(&64u16.to_le_bytes());
        img[58..60].copy_from_slice(&64u16.to_le_bytes());
        img[60..62].copy_from_slice(&(SHNUM as u16).to_le_bytes());
        img[62..64].copy_from_slice(&6u16.to_le_bytes()); // shstrndx

        for (i, w) in words.iter().enumerate() {
            img[TEXT_OFF + i * 4..TEXT_OFF + i * 4 + 4].copy_from_slice(&w.to_le_bytes());
        }
        for (i, b) in [0x5Au8, 0x5A, 0x5A, 0x5A, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
            .iter()
            .enumerate()
        {
            img[XLG_OFF + i] = *b;
        }

        // Symbols: 0 null; 1 activate(.text+0); 2 fault(.text+40);
        // 3 quiesce(.text+44); 4 g_state(.xlg+0).
        let names = [
            ("xl_core_activate", 1u16, 0u64, 0x12u8),
            ("xl_core_fault", 1, 40, 0x12),
            ("xl_core_quiesce", 1, 44, 0x12),
            ("g_state", 2, 0, 0x11),
        ];
        for (k, (name, shndx, value, info)) in names.iter().enumerate() {
            let o = SYM_OFF + (k + 1) * 24;
            let name_off = strtab
                .windows(name.len())
                .position(|w| w == name.as_bytes())
                .unwrap_or(0);
            img[o..o + 4].copy_from_slice(&(name_off as u32).to_le_bytes());
            img[o + 4] = *info;
            img[o + 6..o + 8].copy_from_slice(&shndx.to_le_bytes());
            img[o + 8..o + 16].copy_from_slice(&value.to_le_bytes());
        }

        for (k, (r_offset, typ, addend)) in relas.iter().enumerate() {
            let o = RELA_OFF + k * 24;
            img[o..o + 4].copy_from_slice(&r_offset.to_le_bytes());
            // r_info: sym index in the high 32 bits. sym 4 = g_state,
            // 1 = activate, 2 = fault.
            let sym = match *r_offset {
                0 => 2u32, // bl fault
                12 | 20 | 24 | 28 => 1u32, // branches to activate
                _ => 4u32, // g_state references
            };
            img[o + 8..o + 16]
                .copy_from_slice(&((((sym as u64) << 32) | *typ as u64)).to_le_bytes());
            img[o + 16..o + 24].copy_from_slice(&(*addend as i64).to_le_bytes());
        }
        img[str_off..str_off + strtab.len()].copy_from_slice(strtab);
        img[shstr_off..shstr_off + shstr.len()].copy_from_slice(shstr);

        // Section headers.
        let mut sh = |i: usize, name: u32, ty: u32, off: u64, size: u64, link: u32, info: u32,
                      entsize: u64| {
            let o = shoff + i * 64;
            img[o..o + 4].copy_from_slice(&name.to_le_bytes());
            img[o + 4..o + 8].copy_from_slice(&ty.to_le_bytes());
            img[o + 24..o + 32].copy_from_slice(&off.to_le_bytes());
            img[o + 32..o + 40].copy_from_slice(&size.to_le_bytes());
            img[o + 40..o + 44].copy_from_slice(&link.to_le_bytes());
            img[o + 44..o + 48].copy_from_slice(&info.to_le_bytes());
            img[o + 56..o + 64].copy_from_slice(&entsize.to_le_bytes());
        };
        let name_off = |n: &str| {
            shstr
                .windows(n.len())
                .position(|w| w == n.as_bytes())
                .unwrap_or(0) as u32
        };
        sh(1, name_off(".text"), 1, TEXT_OFF as u64, text_len as u64, 0, 0, 0);
        sh(2, name_off(".xlg"), 1, XLG_OFF as u64, XLG_LEN as u64, 0, 0, 0);
        sh(
            3,
            name_off(".symtab"),
            2,
            SYM_OFF as u64,
            (NSYM * 24) as u64,
            5,
            4,
            24,
        );
        sh(
            4,
            name_off(".rela.text"),
            4,
            RELA_OFF as u64,
            (relas.len() * 24) as u64,
            3,
            1,
            24,
        );
        sh(5, name_off(".strtab"), 3, str_off as u64, strtab.len() as u64, 0, 0, 0);
        sh(
            6,
            name_off(".shstrtab"),
            3,
            shstr_off as u64,
            shstr.len() as u64,
            0,
            0,
            0,
        );
        img
    }


    #[test]
    fn aarch64_et_rel_whitelist_applies_golden_words() {
        use elf_aarch64::*;
        let relas: Vec<(u32, u32, i64)> = vec![
            (0, R_AARCH64_CALL26, 0),
            (4, R_AARCH64_ADR_PREL_PG_HI21, 0),
            (8, R_AARCH64_ADD_ABS_LO12_NC, 0),
            (12, R_AARCH64_ADR_PREL_LO21, 0),
            (16, R_AARCH64_LDST64_ABS_LO12_NC, 0),
            (20, R_AARCH64_CONDBR19, 0),
            (24, R_AARCH64_TSTBR14, 0),
            (28, R_AARCH64_JUMP26, 0),
        ];
        let obj = aarch64_et_rel(&relas, 183);
        let img = extract_elf_rel_aarch64(&obj).expect("whitelisted ET_REL extracts");
        assert_eq!(img.entry_off, 0, "xl_core_activate sits at .text+0");
        assert_eq!(img.fault_off, 40);
        assert_eq!(img.quiesce_off, 44);
        assert_eq!(img.state.len(), 16);
        // Flat-blob g_state: text 48 B + pad (0x1000-48)%0x1000 + 0x1000.
        let state: i64 = 0x2000;
        let words: Vec<u32> = img
            .text
            .chunks(4)
            .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
            .collect();
        // Hand-computed per ARM ARM field layouts (P = word file offset):
        let rel = |s: i64, p: i64| s - p;
        let exp0 = 0x9400_0000u32 | (((rel(40, 0) >> 2) as u32) & 0x03FF_FFFF); // bl fault
        let imm = ((state & !0xFFF) - (4 & !0xFFF)) >> 12; // adrp page delta = 2
        let exp1 = 0x9000_0000u32 | ((((imm as u32) & 3) << 29) | (((imm as u32) >> 2) << 5));
        let exp2 = 0x9100_0000u32 | (((state & 0xFFF) as u32) << 10); // add :lo12: = 0
        let a = rel(0, 12) as u32; // adr x1, activate → imm21 of -12
        let exp3 = 0x1000_0000u32 | ((a & 3) << 29) | (((a >> 2) & 0x7_FFFF) << 5) | 1;
        // ldr x2: size bits 11 → scale 3, :lo12: 0
        let exp4 = 0xF940_0002u32 | ((((state & 0xFFF) >> 3) as u32) << 10);
        let c = rel(0, 20) >> 2; // b.ne → imm19 of -5
        let exp5 = 0x5400_0001u32 | (((c as u32) & 0x7FFFF) << 5);
        let t = rel(0, 24) >> 2; // tbnz → imm14 of -6
        let exp6 = 0x3718_0000u32 | (((t as u32) & 0x3FFF) << 5);
        let j = rel(0, 28) >> 2; // b → imm26 of -7
        let exp7 = 0x1400_0000u32 | (((j as u32) & 0x03FF_FFFF));
        let expected = [exp0, exp1, exp2, exp3, exp4, exp5, exp6, exp7];
        for (i, want) in expected.iter().enumerate() {
            assert_eq!(words[i], *want, "word {i} mismatch");
        }
        assert_eq!(words[10], 0xD65F_03C0);
    }

    #[test]
    fn aarch64_et_rel_rejects_out_of_whitelist_and_machine() {
        use elf_aarch64::*;
        // R_AARCH64_ABS64 (data absolute) is outside the -fpie text whitelist.
        let relas = vec![(0u32, R_AARCH64_ABS64, 0i64)];
        let obj = aarch64_et_rel(&relas, 183);
        assert!(
            matches!(extract_elf_rel_aarch64(&obj), Err(RuntimeImageError::Relocs)),
            "absolute data relocation must fail closed"
        );
        // An x86-64 ET_REL fed to the aarch64 extractor is a format error.
        let obj = aarch64_et_rel(&[], 62);
        assert!(matches!(extract_elf_rel_aarch64(&obj), Err(RuntimeImageError::Format)));
    }
}
