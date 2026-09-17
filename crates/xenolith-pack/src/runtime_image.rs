//! Validate a compiled runtime object before it is copied into a packed image.
//!
//! The rustc `xenolith-runtime` cdylib is **not** injectable: it has a
//! KERNEL32/VCRUNTIME import table. Production injection is the freestanding
//! `xenolith-runtime/core/xl_core.c` object, checked here.

use thiserror::Error;

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

pub fn validate_and_extract(obj: &[u8]) -> Result<RuntimeImage, RuntimeImageError> {
    if obj.len() >= 4 && obj.starts_with(b"\x7fELF") {
        // Linux-hosted builds: cc emits an ELF64 ET_REL object. Same flat
        // layout contract as the COFF path below ([core text][.xlg state],
        // .xlg relocations shifted by the emit-time page pad).
        return extract_elf_rel(obj);
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
    if rd_u16(16) != 1 || rd_u16(18) != 62 {
        return Err(RuntimeImageError::Format); // ET_REL, EM_X86_64 only
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

pub fn load_builtin() -> Result<RuntimeImage, RuntimeImageError> {
    let bytes = builtin_object_bytes()?;
    validate_and_extract(&bytes)
}

fn builtin_object_bytes() -> Result<Vec<u8>, RuntimeImageError> {
    let path = option_env!("XL_CORE_OBJ").unwrap_or("");
    if !path.is_empty() {
        return std::fs::read(path).map_err(|e| RuntimeImageError::Missing(e.to_string()));
    }
    let out = env!("XL_CORE_OBJ_PATH");
    std::fs::read(out).map_err(|e| RuntimeImageError::Missing(format!("{out}: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rustc_runtime_dll_is_rejected() {
        let dll = std::fs::read("target/release/xenolith_runtime.dll")
            .or_else(|_| std::fs::read("../../target/release/xenolith_runtime.dll"));
        if let Ok(bytes) = dll {
            assert!(validate_and_extract(&bytes).is_err());
        }
    }

    #[test]
    fn builtin_core_has_entry() {
        match load_builtin() {
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

}
