//! ELF64 AMD64/AArch64 parser. Unsupported features fail closed.

use crate::elf_aarch64;
use crate::{read_u16, read_u32, read_u64, FormatError, ImageKind};

const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;
const EM_X86_64: u16 = 62;
const EM_AARCH64: u16 = 183;
pub const PT_LOAD: u32 = 1;
pub const PT_DYNAMIC: u32 = 2;
pub const PT_INTERP: u32 = 3;
pub const PT_PHDR: u32 = 6;
pub const PT_TLS: u32 = 7;
pub const PT_GNU_RELRO: u32 = 0x6474e552;
pub const PT_GNU_EH_FRAME: u32 = 0x6474e550;
pub const PF_X: u32 = 1;
pub const PF_W: u32 = 2;
pub const PF_R: u32 = 4;
pub const DT_NULL: u64 = 0;
const DT_NEEDED: u64 = 1;
const DT_RELA: u64 = 7;
const DT_RELASZ: u64 = 8;
const DT_SYMTAB: u64 = 6;
const DT_STRTAB: u64 = 5;
pub const DT_INIT: u64 = 12;
const DT_FLAGS: u64 = 30;
const DT_FLAGS_1: u64 = 0x6ffffffb;
const DT_VERSYM: u64 = 0x6ffffff0;
const DT_HASH: u64 = 4;
const DT_GNU_HASH: u64 = 0x6FFF_FEF5;
const DF_1_PIE: u64 = 0x0800_0000;
const R_X86_64_TPOFF32: u32 = 23;
const R_X86_64_IRELATIVE: u32 = 37;
const STT_GNU_IFUNC: u8 = 10;
const PN_XNUM: usize = 0xFFFF;
/// Sane phdr-table bound: real images stay below ~30 entries.
const MAX_PHNUM: usize = 4096;

/// AArch64 packed-relocation/RELR dynamic tags (DT_LOOS = 0x6000000D). Any
/// input carrying them fails closed: scan_rela only walks DT_RELA, so a
/// packed table would let ld.so apply relative fixups into sealed RX pages
/// that the stub later restores to link-time plaintext.
const DT_ANDROID_REL: u64 = 0x6000_000F; // DT_LOOS + 2
const DT_ANDROID_RELSZ: u64 = 0x6000_0010; // DT_LOOS + 3
const DT_ANDROID_RELA: u64 = 0x6000_0011; // DT_LOOS + 4
const DT_ANDROID_RELASZ: u64 = 0x6000_0012; // DT_LOOS + 5
const DT_RELRSZ: u64 = 35;
const DT_RELR: u64 = 36;
const DT_RELRENT: u64 = 37;

/// Input ELF machine. Drives per-architecture constants and stub dispatch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ElfMachine {
    Amd64,
    Aarch64,
}

impl ElfMachine {
    /// e_machine discriminator.
    pub fn from_em(em: u16) -> Option<Self> {
        match em {
            EM_X86_64 => Some(ElfMachine::Amd64),
            EM_AARCH64 => Some(ElfMachine::Aarch64),
            _ => None,
        }
    }

    /// The RELATIVE relocation type ld.so applies before INIT_ARRAY — the
    /// relocation the INIT_ARRAY[0] bootstrap redirects.
    pub fn relative_type(self) -> u32 {
        match self {
            ElfMachine::Amd64 => 8, // R_X86_64_RELATIVE
            ElfMachine::Aarch64 => elf_aarch64::R_AARCH64_RELATIVE,
        }
    }

    /// The IRELATIVE type whose addends are IFUNC resolver addresses.
    pub fn ifunc_type(self) -> u32 {
        match self {
            ElfMachine::Amd64 => R_X86_64_IRELATIVE,
            ElfMachine::Aarch64 => elf_aarch64::R_AARCH64_IRELATIVE,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ProgramHeader {
    pub p_type: u32,
    pub p_flags: u32,
    pub p_offset: u64,
    pub p_vaddr: u64,
    pub p_paddr: u64,
    pub p_filesz: u64,
    pub p_memsz: u64,
    pub p_align: u64,
}

#[derive(Clone, Debug)]
pub struct Elf64 {
    pub kind: ImageKind,
    pub machine: ElfMachine,
    pub pie: bool,
    pub relro: bool,
    pub has_tls: bool,
    pub dynamic: bool,
    pub interp: bool,
    pub entry: u64,
    pub phoff: u64,
    pub phentsize: u16,
    pub phnum: u16,
}

pub fn parse(bytes: &[u8]) -> Result<Elf64, FormatError> {
    if bytes.len() < 64 || &bytes[0..4] != b"\x7fELF" {
        return Err(FormatError::Unsupported);
    }
    if bytes[4] == 1 {
        return Err(FormatError::Invalid(
            "ELF32 images (armeabi-v7a and every other 32-bit target) are not \
             packed in this release: only ELF64 AMD64/AArch64 is accepted",
        ));
    }
    if bytes[5] != 1 {
        return Err(FormatError::Invalid("only ELF64 little-endian is accepted"));
    }
    let etype = read_u16(bytes, 16)?;
    let machine = read_u16(bytes, 18)?;
    let Some(machine) = ElfMachine::from_em(machine) else {
        return Err(FormatError::Invalid(
            "ELF machine is not AMD64 (62) or AArch64 (183)",
        ));
    };
    let kind = match etype {
        ET_EXEC => ImageKind::Elf64Exec,
        ET_DYN => ImageKind::Elf64Dyn,
        _ => return Err(FormatError::Invalid("ELF type is not ET_EXEC/ET_DYN")),
    };
    let entry = read_u64(bytes, 24)?;
    let phoff = read_u64(bytes, 32)? as usize;
    let phentsize = read_u16(bytes, 54)? as usize;
    let phnum_raw = read_u16(bytes, 56)? as usize;
    // PN_XNUM (extended numbering): the real count lives in shdr[0].sh_info.
    let phnum = if phnum_raw == PN_XNUM {
        let shoff = read_u64(bytes, 40)? as usize;
        let shentsize = read_u16(bytes, 58)? as usize;
        if shoff == 0
            || shentsize < 64
            || shoff.saturating_add(shentsize) > bytes.len()
        {
            return Err(FormatError::Invalid("ELF program headers"));
        }
        read_u32(bytes, shoff + 44)? as usize // shdr[0].sh_info
    } else {
        phnum_raw
    };
    if phentsize < 56 || phnum == 0 || phnum > MAX_PHNUM {
        return Err(FormatError::Invalid("ELF program headers"));
    }
    let mut relro = false;
    let mut has_tls = false;
    let mut interp = false;
    let mut dynamic_off = None;
    let mut dynamic_sz = 0usize;
    let mut loads = 0u32;
    for i in 0..phnum {
        let o = phoff.saturating_add(i * phentsize);
        let ptype = read_u32(bytes, o)?;
        let filesz = read_u64(bytes, o + 32)? as usize;
        let offset = read_u64(bytes, o + 8)? as usize;
        match ptype {
            PT_LOAD => loads += 1,
            PT_DYNAMIC => {
                dynamic_off = Some(offset);
                dynamic_sz = filesz;
            }
            PT_TLS => has_tls = true,
            PT_GNU_RELRO => relro = true,
            PT_INTERP => interp = true,
            _ => {}
        }
    }
    if loads == 0 {
        return Err(FormatError::Invalid("ELF has no PT_LOAD"));
    }
    let dynamic = dynamic_off.is_some();
    if !dynamic {
        return Err(FormatError::Invalid(
            "static ELF (no PT_DYNAMIC) is not packed in this release: the injected \
             bootstrap requires ld.so, so statically linked images (Go w/o cgo, \
             musl targets, busybox) are out of scope",
        ));
    }
    let dyn_off = dynamic_off.unwrap();
    let mut pie = kind == ImageKind::Elf64Dyn;
    let mut rela_off = 0u64;
    let mut rela_sz = 0u64;
    let mut i = 0usize;
    while i + 16 <= dynamic_sz {
        let tag = read_u64(bytes, dyn_off + i)?;
        let val = read_u64(bytes, dyn_off + i + 8)?;
        if tag == DT_NULL {
            break;
        }
        match tag {
            DT_RELA => rela_off = val,
            DT_RELASZ => rela_sz = val,
            DT_FLAGS_1 => {
                pie = pie || (val & DF_1_PIE) != 0;
            }
            DT_VERSYM => {}
            // A-8: RELR and Android packed relocations fail closed with the
            // relink workaround in the message — scan_rela only walks DT_RELA,
            // so silently accepting a packed table would leak relative fixups
            // into pages the stub restores to link-time plaintext.
            DT_RELR | DT_RELRSZ | DT_RELRENT | DT_ANDROID_REL | DT_ANDROID_RELSZ
            | DT_ANDROID_RELA | DT_ANDROID_RELASZ => {
                return Err(FormatError::Invalid(
                    "ELF input uses RELR or Android packed relocations \
                     (DT_RELR/DT_ANDROID_*): relink with -Wl,--pack-dyn-relocs=none \
                     (CMake: ANDROID_PACK_DYN_RELOCS_OFF) — packed tables apply \
                     relative fixups into pages the packer seals",
                ));
            }
            _ => {}
        }
        let _ = (DT_NEEDED, DT_SYMTAB, DT_FLAGS);
        i += 16;
    }
    scan_rela(bytes, machine, phoff, phentsize, phnum, rela_off, rela_sz)?;
    Ok(Elf64 {
        kind,
        machine,
        pie,
        relro,
        has_tls,
        dynamic,
        interp,
        entry,
        phoff: phoff as u64,
        phentsize: phentsize as u16,
        phnum: phnum as u16,
    })
}

pub fn program_headers(bytes: &[u8], elf: &Elf64) -> Result<Vec<ProgramHeader>, FormatError> {
    let mut out = Vec::with_capacity(elf.phnum as usize);
    for i in 0..elf.phnum as usize {
        let o = (elf.phoff as usize).saturating_add(i * elf.phentsize as usize);
        out.push(ProgramHeader {
            p_type: read_u32(bytes, o)?,
            p_flags: read_u32(bytes, o + 4)?,
            p_offset: read_u64(bytes, o + 8)?,
            p_vaddr: read_u64(bytes, o + 16)?,
            p_paddr: read_u64(bytes, o + 24)?,
            p_filesz: read_u64(bytes, o + 32)?,
            p_memsz: read_u64(bytes, o + 40)?,
            p_align: read_u64(bytes, o + 48)?,
        });
    }
    Ok(out)
}

pub fn write_program_header(
    bytes: &mut [u8],
    elf: &Elf64,
    index: usize,
    ph: &ProgramHeader,
) -> Result<(), FormatError> {
    let o = (elf.phoff as usize)
        .checked_add(index * elf.phentsize as usize)
        .ok_or(FormatError::Invalid("ELF program header index"))?;
    if o + elf.phentsize as usize > bytes.len() {
        return Err(FormatError::Invalid("ELF program header index"));
    }
    crate::write_u32(bytes, o, ph.p_type)?;
    crate::write_u32(bytes, o + 4, ph.p_flags)?;
    crate::write_u64(bytes, o + 8, ph.p_offset)?;
    crate::write_u64(bytes, o + 16, ph.p_vaddr)?;
    crate::write_u64(bytes, o + 24, ph.p_paddr)?;
    crate::write_u64(bytes, o + 32, ph.p_filesz)?;
    crate::write_u64(bytes, o + 40, ph.p_memsz)?;
    crate::write_u64(bytes, o + 48, ph.p_align)?;
    Ok(())
}

pub fn set_phnum(bytes: &mut [u8], phnum: u16) -> Result<(), FormatError> {
    crate::write_u16(bytes, 56, phnum)
}

/// File offset of a virtual address inside a PT_LOAD with filesz coverage.
pub fn vaddr_file_offset(bytes: &[u8], elf: &Elf64, vaddr: u64) -> Result<usize, FormatError> {
    vaddr_to_off(
        bytes,
        elf.phoff as usize,
        elf.phentsize as usize,
        elf.phnum as usize,
        vaddr,
    )
}

/// File ranges the ELF loader parses BEFORE any DT_INIT/INIT_ARRAY code
/// runs: the ELF header + program-header table (pread straight from the
/// file), the PT_DYNAMIC array itself, and every dynamic-table-pointed
/// structure it walks from the mapped image (dynsym/dynstr, hash tables,
/// relocation tables, init/fini arrays, symbol versioning). On toolchain
/// layouts that merge read-only metadata into the executable PT_LOAD
/// (NDK `--no-rosegment`, old defaults), these bytes MUST stay plaintext
/// on disk — sealing them breaks ld.so's dependency/relocation phase with
/// garbled NEEDED strings long before the unpack stub could run.
///
/// Returns file-offset ranges (start, len). Anything unparseable is a named
/// failure (fail-closed), never a silently short carve-out.
pub fn loader_metadata_file_ranges(
    bytes: &[u8],
    elf: &Elf64,
) -> Result<Vec<(usize, usize)>, FormatError> {
    const DT_PLTRELSZ: u64 = 2;
    const DT_STRSZ: u64 = 10;
    const DT_JMPREL: u64 = 23;
    const DT_PREINIT_ARRAY: u64 = 32;
    const DT_PREINIT_ARRAYSZ: u64 = 33;
    const DT_FINI_ARRAYSZ: u64 = 28;
    const DT_VERNEED: u64 = 0x6fff_fffe;
    const DT_VERNEEDNUM: u64 = 0x6fff_ffff;
    const DT_VERDEF: u64 = 0x6fff_fffc;
    const DT_VERDEFNUM: u64 = 0x6fff_fffd;
    const DT_VERSYM: u64 = 0x6fff_fff0;
    const MAX_WALK: usize = 1 << 16;

    let mut out = Vec::new();
    // 1. ELF header + phdr table: dlopen preads these from the file.
    let hdr_end = elf.phoff as usize + elf.phnum as usize * elf.phentsize as usize;
    out.push((0usize, hdr_end));

    let phdrs = program_headers(bytes, elf)?;
    let mut dyn_off = None;
    let mut dyn_len = 0usize;
    for ph in &phdrs {
        if ph.p_type == PT_DYNAMIC {
            dyn_off = Some(ph.p_offset as usize);
            dyn_len = ph.p_filesz as usize;
        }
    }
    let mut tags: Vec<(u64, u64)> = Vec::new();
    if let Some(off) = dyn_off {
        out.push((off, dyn_len));
        let mut i = 0usize;
        while i + 16 <= dyn_len {
            let tag = read_u64(bytes, off + i)?;
            if tag == DT_NULL {
                break;
            }
            tags.push((tag, read_u64(bytes, off + i + 8)?));
            i += 16;
        }
    }
    let tag_val = |want: u64| -> Option<u64> {
        tags.iter().find(|(t, _)| *t == want).map(|(_, v)| *v)
    };
    let to_file = |va: u64| -> Result<usize, FormatError> {
        vaddr_to_off(
            bytes,
            elf.phoff as usize,
            elf.phentsize as usize,
            elf.phnum as usize,
            va,
        )
    };
    let mut push_va = |va: u64, len: u64| -> Result<(), FormatError> {
        if va == 0 || len == 0 {
            return Ok(());
        }
        let off = to_file(va)?;
        if off.checked_add(len as usize).map(|e| e > bytes.len()).unwrap_or(true) {
            return Err(FormatError::Invalid(
                "dynamic metadata range runs past the file (corrupt dynamic table)",
            ));
        }
        out.push((off, len as usize));
        Ok(())
    };

    // 2. Exact-size tables.
    if let (Some(st), Some(sz)) = (tag_val(DT_STRTAB), tag_val(DT_STRSZ)) {
        push_va(st, sz)?;
    }
    if let (Some(r), Some(sz)) = (tag_val(DT_RELA), tag_val(DT_RELASZ)) {
        push_va(r, sz)?;
    }
    if let (Some(r), Some(sz)) = (tag_val(DT_JMPREL), tag_val(DT_PLTRELSZ)) {
        push_va(r, sz)?;
    }
    if let (Some(r), Some(sz)) = (tag_val(25), tag_val(27)) { // DT_INIT_ARRAY + SZ
        push_va(r, sz)?;
    }
    if let (Some(r), Some(sz)) = (tag_val(26), tag_val(DT_FINI_ARRAYSZ)) {
        push_va(r, sz)?;
    }
    if let (Some(r), Some(sz)) = (tag_val(DT_PREINIT_ARRAY), tag_val(DT_PREINIT_ARRAYSZ)) {
        push_va(r, sz)?;
    }

    // 3. dynsym extent (hash-table-derived count — the same bound
    // ifunc_symbol_values relies on).
    if let Some(symtab) = tag_val(DT_SYMTAB) {
        let dyn_off_v = dyn_off.unwrap_or(0);
        let dyn_sz_v = dyn_len;
        let extent = dynsym_extent(
            bytes,
            elf.phoff as usize,
            elf.phentsize as usize,
            elf.phnum as usize,
            dyn_off_v,
            dyn_sz_v,
        )?;
        if let Some((off, end)) = extent {
            let len = end.saturating_sub(off);
            let _ = off;
            push_va(symtab, len as u64)?;
            if let Some(versym) = tag_val(DT_VERSYM) {
                push_va(versym, 2 * len as u64)?;
            }
        } else {
            // No hash table states the count: carve conservatively to the
            // strtab (dynsym always precedes dynstr in practice; if strtab
            // is missing too, the input is not a loadable shared object).
            let end = tag_val(DT_STRTAB).ok_or(FormatError::Invalid(
                "dynsym extent unknown (no DT_HASH/DT_GNU_HASH/DT_STRTAB bound)",
            ))?;
            if end > symtab {
                push_va(symtab, end - symtab)?;
            }
        }
    }

    // 4. DT_HASH: nbucket+nchain header states the exact table size.
    if let Some(h) = tag_val(DT_HASH) {
        let off = to_file(h)?;
        let nb = read_u32(bytes, off)? as usize;
        let nc = read_u32(bytes, off + 4)? as usize;
        if nb == 0 || nb > MAX_WALK || nc == 0 || nc > MAX_WALK {
            return Err(FormatError::Invalid("DT_HASH table size out of bounds"));
        }
        out.push((off, 8 + 4 * (nb + nc)));
    }
    // 5. DT_GNU_HASH: walk buckets/chains once (bounded by the file).
    if let Some(g) = tag_val(DT_GNU_HASH) {
        let off = to_file(g)?;
        let nbuckets = read_u32(bytes, off)? as usize;
        let symoffset = read_u32(bytes, off + 4)? as usize;
        let bloom = read_u32(bytes, off + 8)? as usize;
        if nbuckets == 0 || nbuckets > MAX_WALK || bloom > MAX_WALK {
            return Err(FormatError::Invalid("DT_GNU_HASH header out of bounds"));
        }
        let chains_off = off + 16 + bloom * 8 + nbuckets * 4;
        let mut maxsym = 0usize;
        for b in 0..nbuckets {
            let v = read_u32(bytes, off + 16 + bloom * 8 + b * 4)? as usize;
            maxsym = maxsym.max(v);
        }
        if maxsym < symoffset {
            maxsym = symoffset;
        } else {
            let limit = (bytes.len().saturating_sub(chains_off)) / 4;
            let mut idx = maxsym;
            while idx - symoffset < limit {
                let word = read_u32(bytes, chains_off + (idx - symoffset) * 4)? as usize;
                idx += 1;
                if word & 1 == 1 {
                    break;
                }
            }
            maxsym = idx;
        }
        out.push((off, chains_off - off + (maxsym - symoffset) * 4));
    }
    // 6. Verneed/Verdef chains: vn_next/vd_next walks, bounded.
    if let (Some(vn), Some(num)) = (tag_val(DT_VERNEED), tag_val(DT_VERNEEDNUM)) {
        let start = to_file(vn)?;
        let mut cur = start;
        let mut end = start;
        for _ in 0..num.min(MAX_WALK as u64) as usize {
            let cnt = read_u32(bytes, cur + 4)? as usize;
            let mut aux = read_u32(bytes, cur + 8)? as usize;
            for _ in 0..cnt.min(MAX_WALK) {
                if aux == 0 {
                    break;
                }
                if cur.checked_add(aux + 16).map(|e| e > bytes.len()).unwrap_or(true) {
                    return Err(FormatError::Invalid("verneed aux chain out of bounds"));
                }
                let vna_next = read_u32(bytes, cur + aux + 12)? as usize;
                end = end.max(cur + aux + 16);
                aux = if vna_next == 0 { 0 } else { aux + vna_next };
            }
            end = end.max(cur + 16); // Elf64_Verneed header
            let vn_next = read_u32(bytes, cur + 12)? as usize;
            if vn_next == 0 {
                break;
            }
            let next = cur + vn_next;
            if next <= cur || next > bytes.len() {
                return Err(FormatError::Invalid("verneed chain out of bounds"));
            }
            cur = next;
        }
        out.push((start, end - start));
    }
    if let (Some(vd), Some(num)) = (tag_val(DT_VERDEF), tag_val(DT_VERDEFNUM)) {
        // Elf64_Verdef: vd_version(2) vd_flags(2) vd_ndx(2) vd_cnt(2)
        // vd_hash(4) vd_aux(4) vd_next(4) — vd_next is at +16.
        let start = to_file(vd)?;
        let mut cur = start;
        let mut end = start;
        for _ in 0..num.min(MAX_WALK as u64) as usize {
            let vd_aux = read_u32(bytes, cur + 12)? as usize;
            let vd_next = read_u32(bytes, cur + 16)? as usize;
            end = end.max(cur + 20);
            // Verdaux chain: vda_name(4) vda_next(4) — 8 bytes per entry.
            let mut a = vd_aux;
            for _ in 0..MAX_WALK {
                if a == 0 {
                    break;
                }
                if cur.checked_add(a + 8).map(|e| e > bytes.len()).unwrap_or(true) {
                    return Err(FormatError::Invalid("verdef aux chain out of bounds"));
                }
                let vda_next = read_u32(bytes, cur + a + 4)? as usize;
                end = end.max(cur + a + 8);
                a = if vda_next == 0 { 0 } else { a + vda_next };
            }
            if vd_next == 0 {
                break;
            }
            let next = cur + vd_next;
            if next <= cur || next > bytes.len() {
                return Err(FormatError::Invalid("verdef chain out of bounds"));
            }
            cur = next;
        }
        out.push((start, end - start));
    }
    Ok(out)
}

/// File offset of the DT_INIT value slot, plus the original init VA (0 if absent).
pub fn dt_init_slot(bytes: &[u8], elf: &Elf64) -> Result<Option<(usize, u64)>, FormatError> {
    let mut dyn_off = None;
    let mut dyn_sz = 0usize;
    for ph in program_headers(bytes, elf)? {
        if ph.p_type == PT_DYNAMIC {
            dyn_off = Some(ph.p_offset as usize);
            dyn_sz = ph.p_filesz as usize;
            break;
        }
    }
    let Some(off) = dyn_off else {
        return Ok(None);
    };
    let mut i = 0usize;
    while i + 16 <= dyn_sz {
        let tag = read_u64(bytes, off + i)?;
        if tag == DT_NULL {
            break;
        }
        if tag == DT_INIT {
            return Ok(Some((off + i + 8, read_u64(bytes, off + i + 8)?)));
        }
        i += 16;
    }
    Ok(None)
}

pub fn rx_load_ranges(bytes: &[u8], elf: &Elf64) -> Result<Vec<(u64, u64, usize, usize)>, FormatError> {
    let mut out = Vec::new();
    for ph in program_headers(bytes, elf)? {
        if ph.p_type != PT_LOAD || (ph.p_flags & PF_X) == 0 {
            continue;
        }
        let filesz = ph.p_filesz.min(ph.p_memsz) as usize;
        if filesz == 0 {
            continue;
        }
        out.push((
            ph.p_vaddr,
            ph.p_vaddr.saturating_add(filesz as u64),
            ph.p_offset as usize,
            filesz,
        ));
    }
    Ok(out)
}

/// Highest exclusive virtual address of any PT_LOAD (memsz).
pub fn max_load_vaddr_end(bytes: &[u8], elf: &Elf64) -> Result<u64, FormatError> {
    let mut end = 0u64;
    for ph in program_headers(bytes, elf)? {
        if ph.p_type == PT_LOAD {
            end = end.max(ph.p_vaddr.saturating_add(ph.p_memsz));
        }
    }
    if end == 0 {
        return Err(FormatError::Invalid("ELF has no PT_LOAD"));
    }
    Ok(end)
}

fn vaddr_to_off(
    bytes: &[u8],
    phoff: usize,
    phentsize: usize,
    phnum: usize,
    vaddr: u64,
) -> Result<usize, FormatError> {
    for i in 0..phnum {
        let o = phoff.saturating_add(i * phentsize);
        if read_u32(bytes, o)? != PT_LOAD {
            continue;
        }
        let off = read_u64(bytes, o + 8)?;
        let va = read_u64(bytes, o + 16)?;
        let filesz = read_u64(bytes, o + 32)?;
        let Some(seg_end) = va.checked_add(filesz) else {
            continue;
        };
        if vaddr >= va && vaddr < seg_end {
            let off = off
                .checked_add(vaddr - va)
                .ok_or(FormatError::Invalid("ELF PT_LOAD file offset overflow"))?;
            return Ok(off as usize);
        }
    }
    Err(FormatError::Invalid("ELF vaddr not in PT_LOAD"))
}

fn scan_rela(
    bytes: &[u8],
    machine: ElfMachine,
    phoff: usize,
    phentsize: usize,
    phnum: usize,
    rela_vaddr: u64,
    rela_sz: u64,
) -> Result<(), FormatError> {
    if rela_vaddr == 0 || rela_sz == 0 {
        return Ok(());
    }
    let off = vaddr_to_off(bytes, phoff, phentsize, phnum, rela_vaddr)?;
    let n = (rela_sz as usize) / 24;
    if n > 1 << 23 {
        return Err(FormatError::Invalid("ELF rela count"));
    }
    for i in 0..n {
        let info = read_u64(bytes, off + i * 24 + 8)?;
        let kind = (info & 0xffff_ffff) as u32;
        match (machine, kind) {
            // R_X86_64_IRELATIVE: allowed since TASK-022 — resolvers run
            // during ld.so relocation (before INIT_ARRAY), so the packer
            // keeps their pages native; see `ifunc_resolvers`.
            // R_X86_64_COPY: writes the shared-library data into this
            // image's RW .bss at relocation time — a page class the packer
            // never seals (only executable PT_LOAD file bytes are sealed).
            // R_X86_64_TLSDESC: resolved by ld.so into the RW GOT before
            // INIT_ARRAY — likewise outside the seal set.
            // R_X86_64_TPOFF64 (18): targets an RW GOT slot (initial-exec).
            (_, R_X86_64_TPOFF32) => {
                // Local-exec: the offset is embedded in the text itself, and
                // the ld.so write happens before the stub restores plaintext —
                // the page restore would wipe the applied value. Still
                // rejected because its target IS a sealed RX page.
                return Err(FormatError::Invalid(
                    "ELF R_X86_64_TPOFF32 (text TLS offset) is not packed",
                ));
            }
            // AArch64 local-exec TLS offsets (TLSLE_ADD_TPREL_*): the arm64
            // counterpart of TPOFF32 — the TP offset is baked into the
            // instruction immediate on sealed RX text.
            (
                ElfMachine::Aarch64,
                elf_aarch64::R_AARCH64_TLSLE_ADD_TPREL_LO12
                | elf_aarch64::R_AARCH64_TLSLE_ADD_TPREL_HI12
                | elf_aarch64::R_AARCH64_TLSLE_ADD_TPREL_LO12_NC,
            ) => {
                return Err(FormatError::Invalid(
                    "ELF R_AARCH64_TLSLE_ADD_TPREL_* (text TLS offset) is not packed",
                ));
            }
            _ => {}
        }
    }
    Ok(())
}

/// True extent of the dynamic symbol table. The classic "dynsym ends where
/// dynstr begins" layout assumption breaks whenever .gnu.version / .gnu.hash
/// sit between the two tables (every modern GNU-ld/lld shared object): the
/// gap then decodes as garbage symbols and false-positived an
/// imported-IFUNC rejection on real Rust cdylibs. DT_HASH's nchain is the
/// exact count; DT_GNU_HASH yields it by walking the last bucket chain.
fn dynsym_extent(
    bytes: &[u8],
    phoff: usize,
    phentsize: usize,
    phnum: usize,
    dyn_off: usize,
    dynamic_sz: usize,
) -> Result<Option<(usize, usize)>, FormatError> {
    let (mut symtab, mut strtab, mut hash, mut gnu_hash) = (0u64, 0u64, 0u64, 0u64);
    let mut i = 0usize;
    while i + 16 <= dynamic_sz {
        let tag = read_u64(bytes, dyn_off + i)?;
        let val = read_u64(bytes, dyn_off + i + 8)?;
        if tag == DT_NULL {
            break;
        }
        match tag {
            DT_SYMTAB => symtab = val,
            DT_STRTAB => strtab = val,
            DT_HASH => hash = val,
            DT_GNU_HASH => gnu_hash = val,
            _ => {}
        }
        i += 16;
    }
    if symtab == 0 {
        return Ok(None);
    }
    let off = match vaddr_to_off(bytes, phoff, phentsize, phnum, symtab) {
        Ok(o) => o,
        Err(_) => return Ok(None),
    };
    const MAX_SYMS: usize = 1 << 20;
    // DT_HASH: nbucket(u32), nchain(u32) — nchain IS the symbol count.
    if hash != 0 {
        if let Ok(hoff) = vaddr_to_off(bytes, phoff, phentsize, phnum, hash) {
            if let Ok(nchain) = read_u32(bytes, hoff + 4).map(|v| v as usize) {
                if nchain > 0 && nchain <= MAX_SYMS {
                    return Ok(Some((off, off.saturating_add(nchain * 24))));
                }
            }
        }
    }
    // DT_GNU_HASH: nbuckets(u32), symoffset(u32), bloom_size(u32),
    // bloom_shift(u32), bloom[bloom_size](u64), buckets[nbuckets](u32),
    // chains[](u32). The count is max(bucket)+1 plus the terminal chain.
    if gnu_hash != 0 {
        if let Some(end) = gnu_hash_sym_count(bytes, phoff, phentsize, phnum, gnu_hash) {
            return Ok(Some((off, off.saturating_add(end * 24))));
        }
    }
    // Fallback: the classic layout (.dynstr directly after .dynsym) when no
    // hash table states the count. Without a table-derived or layout bound
    // the rest of the file decodes as garbage symbols — refuse to guess and
    // let callers skip the scan instead (prefer missing over wrong).
    if strtab <= symtab {
        return Ok(None);
    }
    let end = match vaddr_to_off(bytes, phoff, phentsize, phnum, strtab) {
        Ok(o) => o,
        Err(_) => return Ok(None),
    };
    Ok(Some((off, end)))
}

/// Symbol count from DT_GNU_HASH, or None when the table is absent, out of
/// bounds, or malformed — the caller then falls back to the layout bound.
fn gnu_hash_sym_count(
    bytes: &[u8],
    phoff: usize,
    phentsize: usize,
    phnum: usize,
    gnu_hash: u64,
) -> Option<usize> {
    const MAX_TABLE: usize = 1 << 20;
    let goff = vaddr_to_off(bytes, phoff, phentsize, phnum, gnu_hash).ok()?;
    let nbuckets = read_u32(bytes, goff).ok()? as usize;
    let symoffset = read_u32(bytes, goff + 4).ok()? as usize;
    let bloom_words = read_u32(bytes, goff + 8).ok()? as usize;
    if nbuckets == 0 || nbuckets > MAX_TABLE || bloom_words > MAX_TABLE {
        return None;
    }
    let buckets_off = goff.checked_add(16 + bloom_words * 8)?;
    let mut maxsym = 0usize;
    for b in 0..nbuckets {
        let v = read_u32(bytes, buckets_off.checked_add(b * 4)?).ok()? as usize;
        if v > maxsym {
            maxsym = v;
        }
    }
    if maxsym < symoffset {
        return Some(symoffset);
    }
    let chains_off = buckets_off.checked_add(nbuckets * 4)?;
    let limit = (bytes.len().saturating_sub(chains_off)) / 4;
    let mut idx = maxsym;
    while idx - symoffset < limit {
        let word = read_u32(bytes, chains_off.checked_add((idx - symoffset) * 4)?).ok()? as usize;
        idx += 1;
        if word & 1 == 1 {
            break;
        }
    }
    Some(idx)
}

/// Load-relative addresses of every STT_GNU_IFUNC symbol DEFINED in this
/// object (the resolvers ld.so may call at relocation time). IMPORTED IFUNC
/// symbols (st_shndx == 0) are deliberately absent: their GLOB_DAT/PLT
/// slots live in RW GOT pages and ld.so resolves them before INIT_ARRAY,
/// the same window that handles defined resolvers — no page of ours is
/// executed before the stub restored it, so neither flavor needs to be
/// rejected (the packer keeps defined-resolver pages native via this
/// function and `ifunc_resolvers`).
/// Defined STT_FUNC symbols from the dynamic symbol table (the selection
/// surface for stripped .so files, where SHT_SYMTAB is gone). Names come
/// from DT_STRTAB; the extent comes from the hash tables (`dynsym_extent`).
pub fn dynsym_functions(bytes: &[u8], elf: &Elf64) -> Result<Vec<SymtabFunc>, FormatError> {
    let phdrs = program_headers(bytes, elf)?;
    let (mut dyn_off, mut dyn_sz) = (None, 0usize);
    for ph in &phdrs {
        if ph.p_type == PT_DYNAMIC {
            dyn_off = Some(ph.p_offset as usize);
            dyn_sz = ph.p_filesz as usize;
        }
    }
    let Some(doff) = dyn_off else {
        return Ok(Vec::new());
    };
    let (mut symtab_va, mut strtab_va) = (0u64, 0u64);
    let mut i = 0usize;
    while i + 16 <= dyn_sz {
        let tag = read_u64(bytes, doff + i)?;
        let val = read_u64(bytes, doff + i + 8)?;
        if tag == 0 {
            break;
        }
        match tag {
            DT_SYMTAB => symtab_va = val,
            DT_STRTAB => strtab_va = val,
            _ => {}
        }
        i += 16;
    }
    if symtab_va == 0 || strtab_va == 0 {
        return Ok(Vec::new());
    }
    let Some((off, end)) = dynsym_extent(
        bytes,
        elf.phoff as usize,
        elf.phentsize as usize,
        elf.phnum as usize,
        doff,
        dyn_sz,
    )? else {
        return Ok(Vec::new());
    };
    let str_off = vaddr_file_offset(bytes, elf, strtab_va)?;
    let mut out = Vec::new();
    let mut o = off;
    while o + 24 <= end && o + 24 <= bytes.len() {
        let info = bytes[o + 4];
        let value = read_u64(bytes, o + 8)?;
        let size = read_u64(bytes, o + 16)?;
        if info & 0xf == 2 && info >> 4 == 1 && size > 0 {
            // STB_GLOBAL/STB_WEAK defined functions only: STB_LOCAL dynsym
            // entries exist but are not the exported selection surface.
            let name_off = read_u32(bytes, o)? as usize;
            let name = cstr_at_off(bytes, str_off, usize::MAX, name_off);
            if !name.is_empty() {
                out.push(SymtabFunc { name, value, size });
            }
        }
        o += 24;
    }
    Ok(out)
}

pub fn ifunc_symbol_values(bytes: &[u8], elf: &Elf64) -> Result<Vec<u64>, FormatError> {
    let phdrs = program_headers(bytes, elf)?;
    let (mut dyn_off, mut dyn_sz) = (None, 0usize);
    for ph in &phdrs {
        if ph.p_type == PT_DYNAMIC {
            dyn_off = Some(ph.p_offset as usize);
            dyn_sz = ph.p_filesz as usize;
        }
    }
    let Some(doff) = dyn_off else {
        return Ok(Vec::new());
    };
    let Some((off, end)) = dynsym_extent(
        bytes,
        elf.phoff as usize,
        elf.phentsize as usize,
        elf.phnum as usize,
        doff,
        dyn_sz,
    )?
    else {
        return Ok(Vec::new());
    };
    let n = (end.saturating_sub(off)) / 24;
    let mut out = Vec::new();
    for k in 0..n.min(65_536) {
        let so = off + k * 24;
        if so + 24 > bytes.len() {
            break;
        }
        let ty = bytes[so + 4] & 0xf;
        let shndx = u16::from_le_bytes([bytes[so + 6], bytes[so + 7]]);
        if ty == STT_GNU_IFUNC && shndx != 0 {
            out.push(read_u64(bytes, so + 8)?);
        }
    }
    Ok(out)
}


/// Addresses (load-relative) of IFUNC resolver functions: the addends of
/// R_X86_64_IRELATIVE relocations. ld.so calls these during relocation
/// processing, BEFORE any INIT_ARRAY code — a packed image must keep their
/// pages native plaintext.
pub fn ifunc_resolvers(bytes: &[u8], elf: &Elf64) -> Result<Vec<u64>, FormatError> {
    let phdrs = program_headers(bytes, elf)?;
    let (mut rela_off, mut rela_sz, mut dyn_off, mut dyn_sz) = (0u64, 0u64, None, 0usize);
    for ph in &phdrs {
        if ph.p_type == PT_DYNAMIC {
            dyn_off = Some(ph.p_offset as usize);
            dyn_sz = ph.p_filesz as usize;
        }
    }
    if let Some(off) = dyn_off {
        let mut i = 0usize;
        while i + 16 <= dyn_sz {
            let tag = read_u64(bytes, off + i)?;
            if tag == 0 {
                break;
            }
            let val = read_u64(bytes, off + i + 8)?;
            if tag == 7 {
                rela_off = val;
            } else if tag == 8 {
                rela_sz = val;
            }
            i += 16;
        }
    }
    let mut out = Vec::new();
    if rela_off == 0 || rela_sz == 0 {
        return Ok(out);
    }
    let file = vaddr_file_offset(bytes, elf, rela_off)?;
    for k in 0..(rela_sz as usize / 24) {
        let o = file + k * 24;
        let info = read_u64(bytes, o + 8)?;
        if (info & 0xffff_ffff) as u32 == elf.machine.ifunc_type() {
            out.push(read_u64(bytes, o + 16)?);
        }
    }
    Ok(out)
}

/// Symbol-versioning summary: (verneed_entries, verdef_entries). Preserved by
/// the packer (only DT_INIT is removed from the dynamic array).
pub fn symbol_versions(bytes: &[u8], elf: &Elf64) -> Result<(u32, u32), FormatError> {
    let phdrs = program_headers(bytes, elf)?;
    let (mut dyn_off, mut dyn_sz) = (None, 0usize);
    for ph in &phdrs {
        if ph.p_type == PT_DYNAMIC {
            dyn_off = Some(ph.p_offset as usize);
            dyn_sz = ph.p_filesz as usize;
        }
    }
    let (mut verneed, mut verdef) = (0u32, 0u32);
    let Some(off) = dyn_off else {
        return Ok((0, 0));
    };
    let mut i = 0usize;
    while i + 16 <= dyn_sz {
        let tag = read_u64(bytes, off + i)?;
        if tag == 0 {
            break;
        }
        let val = read_u64(bytes, off + i + 8)?;
        match tag {
            0x6ffffffe => verneed = val as u32, // DT_VERNEEDNUM
            0x6ffffffc => verdef = val as u32,  // DT_VERDEFNUM
            _ => {}
        }
        i += 16;
    }
    Ok((verneed, verdef))
}

/// TLS relocation census: how many GOTTPOFF (initial-exec), DTPMOD64/DTPREL64
/// (general/local dynamic) relocations exist, and whether any targets an
/// executable page (TPOFF32-in-text is rejected elsewhere).
pub fn tls_reloc_census(bytes: &[u8], elf: &Elf64) -> Result<(u32, u32), FormatError> {
    let phdrs = program_headers(bytes, elf)?;
    let (mut rela_off, mut rela_sz, mut dyn_off, mut dyn_sz) = (0u64, 0u64, None, 0usize);
    for ph in &phdrs {
        if ph.p_type == PT_DYNAMIC {
            dyn_off = Some(ph.p_offset as usize);
            dyn_sz = ph.p_filesz as usize;
        }
    }
    if let Some(off) = dyn_off {
        let mut i = 0usize;
        while i + 16 <= dyn_sz {
            let tag = read_u64(bytes, off + i)?;
            if tag == 0 {
                break;
            }
            let val = read_u64(bytes, off + i + 8)?;
            if tag == 7 {
                rela_off = val;
            } else if tag == 8 {
                rela_sz = val;
            }
            i += 16;
        }
    }
    let (mut ie, mut ld) = (0u32, 0u32);
    if rela_off == 0 || rela_sz == 0 {
        return Ok((ie, ld));
    }
    let file = vaddr_file_offset(bytes, elf, rela_off)?;
    // Per-arch census so the report's TLS note is truthful on arm64 inputs
    // (x86 numbers would silently count nothing and report 0/0).
    let (ie_types, ld_types): (&[u32], &[u32]) = match elf.machine {
        ElfMachine::Amd64 => (
            &[18, 22], // TPOFF64 GOT slots + GOTTPOFF offsets (initial-exec)
            &[16, 17], // DTPMOD64/DTPREL64 (general/local dynamic)
        ),
        ElfMachine::Aarch64 => (
            &[elf_aarch64::R_AARCH64_TLS_TPREL64],
            &[
                elf_aarch64::R_AARCH64_TLS_DTPMOD64,
                elf_aarch64::R_AARCH64_TLS_DTPREL64,
            ],
        ),
    };
    for k in 0..(rela_sz as usize / 24) {
        let o = file + k * 24;
        let info = read_u64(bytes, o + 8)?;
        let kind = (info & 0xffff_ffff) as u32;
        // TLSDESC stays uncounted on both arches (RW GOT, resolved before
        // INIT_ARRAY — mirrors the x86 handling).
        if ie_types.contains(&kind) {
            ie += 1;
        } else if ld_types.contains(&kind) {
            ld += 1;
        }
    }
    Ok((ie, ld))
}


/// A function symbol from the (non-dynamic) symbol table.
pub struct SymtabFunc {
    pub name: String,
    pub value: u64,
    pub size: u64,
}

/// Enumerate STT_FUNC symbols with sizes from SHT_SYMTAB (stripped objects
/// return an empty list — stats then fall back to nothing, not garbage).
pub fn symtab_functions(bytes: &[u8], _elf: &Elf64) -> Result<Vec<SymtabFunc>, FormatError> {
    let e_shoff = read_u64(bytes, 40)? as usize;
    let e_shentsize = read_u16(bytes, 58)? as usize;
    let e_shnum = read_u16(bytes, 60)? as usize;
    let mut out = Vec::new();
    if e_shoff == 0 || e_shentsize < 64 || e_shnum == 0 || e_shnum > 4096 {
        return Ok(out);
    }
    let sh_base = |i: usize| e_shoff.saturating_add(i.saturating_mul(e_shentsize));
    let sh_type = |i: usize| -> u32 { read_u32(bytes, sh_base(i).saturating_add(4)).unwrap_or(0) };
    let sh_off = |i: usize| -> u64 { read_u64(bytes, sh_base(i).saturating_add(24)).unwrap_or(0) };
    let sh_size = |i: usize| -> u64 { read_u64(bytes, sh_base(i).saturating_add(32)).unwrap_or(0) };
    let sh_link = |i: usize| -> usize {
        read_u32(bytes, sh_base(i).saturating_add(40)).unwrap_or(0) as usize
    };
    for i in 0..e_shnum {
        if sh_type(i) != 2 {
            continue; // SHT_SYMTAB
        }
        let sym_off = sh_off(i) as usize;
        let sym_sz = sh_size(i) as usize;
        let str_idx = sh_link(i);
        if str_idx >= e_shnum {
            continue;
        }
        let str_off = sh_off(str_idx) as usize;
        let str_sz = sh_size(str_idx) as usize;
        let n = sym_sz / 24;
        for k in 0..n.min(200_000) {
            let o = sym_off.saturating_add(k.saturating_mul(24));
            if o.saturating_add(24) > bytes.len() {
                break;
            }
            let info = bytes[o + 4];
            if info & 0xf != 2 {
                continue; // STT_FUNC
            }
            let size = read_u64(bytes, o + 16).unwrap_or(0); // Elf64_Sym.st_size
            if size == 0 {
                continue;
            }
            let name_off = read_u32(bytes, o).unwrap_or(0) as usize;
            let name = cstr_at_off(bytes, str_off, str_sz, name_off);
            out.push(SymtabFunc {
                name,
                value: read_u64(bytes, o + 8)?,
                size,
            });
        }
    }
    Ok(out)
}

fn cstr_at_off(bytes: &[u8], base: usize, len: usize, off: usize) -> String {
    let Some(start) = base.checked_add(off) else {
        return String::new();
    };
    if off >= len || start >= bytes.len() {
        return String::new();
    }
    let limit = base.saturating_add(len).min(bytes.len());
    if limit <= start {
        return String::new();
    }
    let end = bytes[start..limit]
        .iter()
        .position(|&b| b == 0)
        .map(|p| start + p)
        .unwrap_or(limit);
    String::from_utf8_lossy(&bytes[start..end]).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_elf() {
        assert!(parse(b"MZ").is_err());
    }

    #[test]
    fn parses_minimal_header_as_invalid_without_phdrs() {
        let mut elf = vec![0x7f, b'E', b'L', b'F', 2, 1, 1];
        elf.resize(64, 0);
        elf[16] = ET_DYN as u8;
        elf[18] = EM_X86_64 as u8;
        assert!(parse(&elf).is_err());
    }

    /// Minimal ET_DYN with one RX PT_LOAD (vaddr == file offset) and one
    /// PT_DYNAMIC. `sym1_info` is sym1's st_info; `gap` bytes follow the
    /// real dynsym before .dynstr, imitating .gnu.version padding that a
    /// "dynsym runs to dynstr" scanner decodes as garbage symbols.
    fn elf_with_dynsym(sym1_info: u8, gap: &[u8]) -> Vec<u8> {
        const PHOFF: usize = 64;
        const DYN_OFF: usize = PHOFF + 2 * 56; // 176
        let hash_off = DYN_OFF + 4 * 16; // 3 tags + DT_NULL
        let sym_off = hash_off + 8 + 8 + 4 + 8; // nbucket+nchain+bucket+2*4 chain
        let str_off = sym_off + 2 * 24 + gap.len();

        let mut dyns: Vec<u8> = Vec::new();
        for (tag, val) in [
            (DT_HASH, hash_off as u64),
            (DT_SYMTAB, sym_off as u64),
            (DT_STRTAB, str_off as u64),
        ] {
            dyns.extend_from_slice(&tag.to_le_bytes());
            dyns.extend_from_slice(&val.to_le_bytes());
        }
        dyns.extend_from_slice(&[0u8; 16]); // DT_NULL

        let mut img = vec![0u8; DYN_OFF];
        img[0..4].copy_from_slice(b"\x7fELF");
        img[4] = 2; // ELFCLASS64
        img[5] = 1; // little-endian
        img[16..18].copy_from_slice(&ET_DYN.to_le_bytes());
        img[18..20].copy_from_slice(&EM_X86_64.to_le_bytes());
        img[32..40].copy_from_slice(&(PHOFF as u64).to_le_bytes());
        img[54..56].copy_from_slice(&56u16.to_le_bytes());
        img[56..58].copy_from_slice(&2u16.to_le_bytes());
        img.resize(PHOFF + 2 * 56, 0);
        let total = (str_off + 2) as u64; // + "c\0"
        // PT_LOAD: whole file, R+X.
        img[PHOFF..PHOFF + 4].copy_from_slice(&PT_LOAD.to_le_bytes());
        img[PHOFF + 4..PHOFF + 8].copy_from_slice(&5u32.to_le_bytes());
        img[PHOFF + 32..PHOFF + 40].copy_from_slice(&total.to_le_bytes());
        img[PHOFF + 40..PHOFF + 48].copy_from_slice(&total.to_le_bytes());
        // PT_DYNAMIC.
        let d = PHOFF + 56;
        img[d..d + 4].copy_from_slice(&PT_DYNAMIC.to_le_bytes());
        img[d + 8..d + 16].copy_from_slice(&(DYN_OFF as u64).to_le_bytes());
        img[d + 16..d + 24].copy_from_slice(&(DYN_OFF as u64).to_le_bytes());
        img[d + 32..d + 40].copy_from_slice(&(dyns.len() as u64).to_le_bytes());
        img.extend_from_slice(&dyns);

        // DT_HASH: nbucket=1, nchain=2 (the EXACT symbol count), one bucket.
        img.extend_from_slice(&1u64.to_le_bytes());
        img.extend_from_slice(&2u64.to_le_bytes());
        img.extend_from_slice(&1u32.to_le_bytes()); // bucket[0]
        img.extend_from_slice(&[0u8; 8]); // chain[0..2]
        debug_assert_eq!(img.len(), sym_off);

        // sym0: null. sym1: undefined import with caller-chosen st_info.
        img.extend_from_slice(&[0u8; 24]);
        img.extend_from_slice(&1u32.to_le_bytes()); // st_name
        img.push(sym1_info);
        img.push(0x00); // st_other
        img.extend_from_slice(&0u16.to_le_bytes()); // st_shndx = 0
        img.extend_from_slice(&0u64.to_le_bytes()); // st_value
        img.extend_from_slice(&0u64.to_le_bytes()); // st_size

        // The gap: a forged STT_GNU_IFUNC import (type nibble 10, shndx 0).
        img.extend_from_slice(gap);
        img.extend_from_slice(b"c\0");
        img
    }

    #[test]
    fn gap_between_dynsym_and_dynstr_is_not_an_imported_ifunc() {
        // DT_HASH states nchain=2; the IFUNC-looking bytes live PAST the real
        // table (as .gnu.version does in every modern .so). The classic
        // "dynsym runs to dynstr" bound decodes a 3rd "symbol" there and
        // false-positives on this image.
        let mut gap = vec![0u8; 40];
        gap[28] = 0x1a; // st_info: (bind 1 << 4) | type 10 (STT_GNU_IFUNC)
        let img = elf_with_dynsym(0x00, &gap);
        assert!(
            parse(&img).is_ok(),
            "garbage between dynsym and dynstr must not decode as an imported IFUNC",
        );
    }

    #[test]
    fn real_imported_ifunc_inside_dynsym_is_accepted() {
        // An UNDEFINED STT_GNU_IFUNC in .dynsym (as glibc's memcpy/strlen
        // appear in every dynamically linked binary's dynsym) is resolved by
        // ld.so into the RW GOT before INIT_ARRAY — same window as defined
        // resolvers — so it is no longer a rejection.
        let mut gap = vec![0u8; 40];
        gap[28] = 0x1a;
        let img = elf_with_dynsym(0x0a, &gap); // sym1 st_info type 10, shndx 0
        parse(&img).expect("imported IFUNC must be accepted");
    }

    #[test]
    fn dynsym_without_hash_or_layout_bound_skips_scan() {
        // strtab <= symtab and no DT_HASH/DT_GNU_HASH: the extent is
        // unknowable, so the scan is skipped instead of decoding the whole
        // file as symbols.
        let img = elf_with_dynsym_no_hash(0x0a);
        parse(&img).expect("unbounded dynsym must not fail the parse");
    }

    /// Minimal ET_DYN with one R+X PT_LOAD (vaddr == file offset) and a
    /// PT_DYNAMIC carrying DT_RELA/DT_INIT_ARRAY plus caller-supplied extra
    /// tags and relocation entries. Enough shape for the per-arch rejection
    /// matrix and the census/bootstrap scans. Returns the image and the
    /// INIT_ARRAY virtual address (a RELATIVE r_offset that must match).
    fn elf_dyn_with_rela(
        machine: ElfMachine,
        relas: &[(u64, u32, u64)],
        extra_dyn: &[(u64, u64)],
    ) -> (Vec<u8>, u64) {
        const PHOFF: usize = 64;
        const PHNUM: usize = 2;
        const DYN_OFF: usize = PHOFF + PHNUM * 56; // 176
        let n_dyn = 4 + extra_dyn.len() + 1; // RELA/RELASZ/INIT_ARRAY/INIT_ARRAYSZ + extra + NULL
        let rela_off = DYN_OFF + n_dyn * 16;
        let ia_off = rela_off + relas.len() * 24;

        let mut dyns: Vec<u8> = Vec::new();
        for (tag, val) in [
            (7u64, rela_off as u64),   // DT_RELA
            (8u64, (relas.len() * 24) as u64), // DT_RELASZ
            (25u64, ia_off as u64),    // DT_INIT_ARRAY
            (27u64, 8u64),             // DT_INIT_ARRAYSZ
        ] {
            dyns.extend_from_slice(&tag.to_le_bytes());
            dyns.extend_from_slice(&val.to_le_bytes());
        }
        for (tag, val) in extra_dyn {
            dyns.extend_from_slice(&tag.to_le_bytes());
            dyns.extend_from_slice(&val.to_le_bytes());
        }
        dyns.extend_from_slice(&[0u8; 16]); // DT_NULL

        let total = ia_off + 8;
        let mut img = vec![0u8; total];
        img[0..4].copy_from_slice(b"\x7fELF");
        img[4] = 2;
        img[5] = 1;
        img[16..18].copy_from_slice(&ET_DYN.to_le_bytes());
        img[18..20].copy_from_slice(
            &(match machine {
                ElfMachine::Amd64 => EM_X86_64,
                ElfMachine::Aarch64 => EM_AARCH64,
            })
            .to_le_bytes(),
        );
        img[32..40].copy_from_slice(&(PHOFF as u64).to_le_bytes());
        img[54..56].copy_from_slice(&56u16.to_le_bytes());
        img[56..58].copy_from_slice(&(PHNUM as u16).to_le_bytes());
        // PT_LOAD: whole file, R+X, vaddr 0.
        img[PHOFF..PHOFF + 4].copy_from_slice(&PT_LOAD.to_le_bytes());
        img[PHOFF + 4..PHOFF + 8].copy_from_slice(&5u32.to_le_bytes());
        img[PHOFF + 8..PHOFF + 16].copy_from_slice(&0u64.to_le_bytes());
        img[PHOFF + 32..PHOFF + 40].copy_from_slice(&(total as u64).to_le_bytes());
        img[PHOFF + 40..PHOFF + 48].copy_from_slice(&(total as u64).to_le_bytes());
        img[PHOFF + 48..PHOFF + 56].copy_from_slice(&0x1000u64.to_le_bytes());
        // PT_DYNAMIC.
        let d = PHOFF + 56;
        img[d..d + 4].copy_from_slice(&PT_DYNAMIC.to_le_bytes());
        img[d + 8..d + 16].copy_from_slice(&(DYN_OFF as u64).to_le_bytes());
        img[d + 16..d + 24].copy_from_slice(&(DYN_OFF as u64).to_le_bytes());
        img[d + 32..d + 40].copy_from_slice(&(dyns.len() as u64).to_le_bytes());
        img[DYN_OFF..DYN_OFF + dyns.len()].copy_from_slice(&dyns);
        for (k, (r_offset, kind, addend)) in relas.iter().enumerate() {
            let o = rela_off + k * 24;
            let r_offset = if *r_offset == u64::MAX { ia_off as u64 } else { *r_offset };
            img[o..o + 8].copy_from_slice(&r_offset.to_le_bytes());
            img[o + 8..o + 16].copy_from_slice(&(*kind as u64).to_le_bytes());
            img[o + 16..o + 24].copy_from_slice(&addend.to_le_bytes());
        }
        (img, ia_off as u64)
    }

    #[test]
    fn aarch64_et_dyn_parses_and_rejects_by_name() {
        let (img, _) = elf_dyn_with_rela(ElfMachine::Aarch64, &[], &[]);
        let parsed = parse(&img).expect("aarch64 ET_DYN parses");
        assert_eq!(parsed.machine, ElfMachine::Aarch64);
        assert_eq!(parsed.kind, ImageKind::Elf64Dyn);

        // ELF32 (EI_CLASS=1): named rejection, not a generic parse failure.
        let (mut elf32, _) = elf_dyn_with_rela(ElfMachine::Amd64, &[], &[]);
        elf32[4] = 1;
        let err = format!("{}", parse(&elf32).unwrap_err());
        assert!(err.contains("ELF32"), "named ELF32 rejection, got {err}");

        // Unknown e_machine (EM_ARM with ELFCLASS64): named rejection.
        let (mut arm, _) = elf_dyn_with_rela(ElfMachine::Amd64, &[], &[]);
        arm[18..20].copy_from_slice(&40u16.to_le_bytes());
        let err = format!("{}", parse(&arm).unwrap_err());
        assert!(err.contains("not AMD64"), "named machine rejection, got {err}");
    }

    #[test]
    fn relr_and_android_packed_relocs_fail_closed() {
        for tag in [36u64, 35, 37, 0x6000_000F, 0x6000_0010, 0x6000_0011, 0x6000_0012] {
            let (img, _) = elf_dyn_with_rela(ElfMachine::Aarch64, &[], &[(tag, 0x2000)]);
            let err = format!("{}", parse(&img).unwrap_err());
            assert!(
                err.contains("packed relocations") && err.contains("--pack-dyn-relocs=none"),
                "tag {tag:#x} must name the packed-reloc refusal with a relink workaround, got {err}"
            );
            let (img, _) = elf_dyn_with_rela(ElfMachine::Amd64, &[], &[(tag, 0x2000)]);
            assert!(parse(&img).is_err(), "x86 inputs refuse tag {tag:#x} too");
        }
    }

    #[test]
    fn aarch64_tlsle_text_reloc_rejected() {
        for kind in [549u32, 550, 551] {
            let (img, _) = elf_dyn_with_rela(ElfMachine::Aarch64, &[(0x300, kind, 0x10)], &[]);
            let err = format!("{}", parse(&img).unwrap_err());
            assert!(
                err.contains("TLSLE"),
                "TLSLE kind {kind} must be named, got {err}"
            );
        }
        // x86 keeps its own TPOFF32 rejection and ignores arm64 numbers.
        let (img, _) = elf_dyn_with_rela(ElfMachine::Amd64, &[(0x300, 23, 0x10)], &[]);
        assert!(parse(&img).is_err());
        let (img, _) = elf_dyn_with_rela(ElfMachine::Amd64, &[(0x300, 550, 0x10)], &[]);
        assert!(parse(&img).is_ok(), "x86 census ignores arm64 TLSLE kinds");
    }

    #[test]
    fn aarch64_census_ifunc_and_bootstrap_marker() {
        // One of each: RELATIVE(1027), IRELATIVE(1032), TLS_TPREL64(1030),
        // TLS_DTPMOD64(1028), TLS_DTPREL64(1029), GLOB_DAT(1025) —
        // ie=1, ld=2, one resolver at 0x280.
        let relas: Vec<(u64, u32, u64)> = vec![
            (u64::MAX, 1027, 0x180),
            (0x180, 1032, 0x280),
            (0x188, 1030, 0),
            (0x190, 1028, 0),
            (0x198, 1029, 8),
            (0x1a0, 1025, 0),
        ];
        let (img, _ia) = elf_dyn_with_rela(ElfMachine::Aarch64, &relas, &[]);
        let parsed = parse(&img).unwrap();
        assert_eq!(tls_reloc_census(&img, &parsed).unwrap(), (1, 2));
        assert_eq!(ifunc_resolvers(&img, &parsed).unwrap(), vec![0x280]);
        // packed marker: INIT_ARRAY[0] rides a 1027 whose addend sits inside
        // the last R+X PT_LOAD (the whole file here).
        assert_eq!(packed_bootstrap_target(&img, &parsed).unwrap(), Some(0x180));
    }

    #[test]
    fn loader_metadata_ranges_cover_headers_rela_and_init_array() {
        let (img, _ia) = elf_dyn_with_rela(ElfMachine::Amd64, &[(u64::MAX, 8, 0x300)], &[]);
        let parsed = parse(&img).unwrap();
        let ranges = loader_metadata_file_ranges(&img, &parsed).unwrap();
        // ELF header + phdr table always carved.
        assert!(ranges.contains(&(0usize, 64 + 2 * 56)), "header range: {ranges:?}");
        // PT_DYNAMIC's own file range and the RELA table (va==off here)
        // are carved with their exact sizes.
        assert!(ranges.contains(&(176usize, 80usize)), "dynamic range: {ranges:?}");
        assert!(ranges.contains(&(256usize, 24usize)), "rela range: {ranges:?}");
    }

    #[test]
    fn x86_machine_field_flows() {
        let (img, _) = elf_dyn_with_rela(ElfMachine::Amd64, &[(u64::MAX, 8, 0x100)], &[]);
        let parsed = parse(&img).unwrap();
        assert_eq!(parsed.machine, ElfMachine::Amd64);
        assert_eq!(
            packed_bootstrap_target(&img, &parsed).unwrap(),
            Some(0x100),
            "x86 keeps its R_X86_64_RELATIVE(8) bootstrap marker"
        );
    }

    /// Same shape as `elf_with_dynsym` but with no DT_HASH: forces the
    /// dynsym-extent fallback path with strtab > symtab removed by pointing
    /// DT_STRTAB *below* DT_SYMTAB.
    fn elf_with_dynsym_no_hash(sym1_info: u8) -> Vec<u8> {
        const PHOFF: usize = 64;
        const DYN_OFF: usize = PHOFF + 2 * 56;
        let sym_off = DYN_OFF + 3 * 16; // 2 tags + DT_NULL
        let str_off = sym_off - 8; // below symtab

        let mut dyns: Vec<u8> = Vec::new();
        for (tag, val) in [
            (DT_SYMTAB, sym_off as u64),
            (DT_STRTAB, str_off as u64),
        ] {
            dyns.extend_from_slice(&tag.to_le_bytes());
            dyns.extend_from_slice(&val.to_le_bytes());
        }
        dyns.extend_from_slice(&[0u8; 16]); // DT_NULL

        let mut img = vec![0u8; DYN_OFF];
        img[0..4].copy_from_slice(b"\x7fELF");
        img[4] = 2;
        img[5] = 1;
        img[16..18].copy_from_slice(&ET_DYN.to_le_bytes());
        img[18..20].copy_from_slice(&EM_X86_64.to_le_bytes());
        img[32..40].copy_from_slice(&(PHOFF as u64).to_le_bytes());
        img[54..56].copy_from_slice(&56u16.to_le_bytes());
        img[56..58].copy_from_slice(&2u16.to_le_bytes());
        img.resize(DYN_OFF, 0);
        let total = (sym_off + 24) as u64;
        img[PHOFF..PHOFF + 4].copy_from_slice(&PT_LOAD.to_le_bytes());
        img[PHOFF + 4..PHOFF + 8].copy_from_slice(&5u32.to_le_bytes());
        img[PHOFF + 32..PHOFF + 40].copy_from_slice(&total.to_le_bytes());
        img[PHOFF + 40..PHOFF + 48].copy_from_slice(&total.to_le_bytes());
        let d = PHOFF + 56;
        img[d..d + 4].copy_from_slice(&PT_DYNAMIC.to_le_bytes());
        img[d + 8..d + 16].copy_from_slice(&(DYN_OFF as u64).to_le_bytes());
        img[d + 16..d + 24].copy_from_slice(&(DYN_OFF as u64).to_le_bytes());
        img[d + 32..d + 40].copy_from_slice(&(dyns.len() as u64).to_le_bytes());
        img.extend_from_slice(&dyns);
        img.extend_from_slice(&[0u8; 24]); // sym0
        img.extend_from_slice(&1u32.to_le_bytes());
        img.push(sym1_info);
        img.push(0x00);
        img.extend_from_slice(&0u16.to_le_bytes());
        img.extend_from_slice(&0u64.to_le_bytes());
        img.extend_from_slice(&0u64.to_le_bytes());
        img
    }
}

/// If INIT_ARRAY[0] rides an R_<ARCH>_RELATIVE whose addend lands inside the
/// last R+X PT_LOAD, that addend is the injected bootstrap stub — the packed
/// marker for Xenolith ELF images.
pub fn packed_bootstrap_target(bytes: &[u8], elf: &Elf64) -> Result<Option<u64>, FormatError> {
    let phdrs = program_headers(bytes, elf)?;
    let last_rx = phdrs.iter().filter(|p| p.p_type == PT_LOAD && p.p_flags & PF_X != 0).last()
        .ok_or(FormatError::Invalid("no executable PT_LOAD"))?;
    let (mut rela_off, mut rela_sz, mut init_array_va, mut init_array_sz) = (0u64, 0u64, 0u64, 0u64);
    let mut dyn_off = None;
    let mut dyn_sz = 0usize;
    for ph in &phdrs {
        if ph.p_type == PT_DYNAMIC {
            dyn_off = Some(ph.p_offset as usize);
            dyn_sz = ph.p_filesz as usize;
        }
    }
    let Some(off) = dyn_off else { return Ok(None) };
    let mut i = 0usize;
    while i + 16 <= dyn_sz {
        let tag = read_u64(bytes, off + i)?;
        if tag == 0 { break; }
        let val = read_u64(bytes, off + i + 8)?;
        match tag {
            7 => rela_off = val,
            8 => rela_sz = val,
            25 => init_array_va = val,
            27 => init_array_sz = val, // DT_INIT_ARRAYSZ (26 is DT_FINI_ARRAY)
            _ => {}
        }
        i += 16;
    }
    if init_array_va == 0 || init_array_sz < 8 || rela_off == 0 || rela_sz == 0 {
        return Ok(None);
    }
    let rela_file = vaddr_file_offset(bytes, elf, rela_off)?;
    for k in 0..(rela_sz as usize / 24) {
        let o = rela_file + k * 24;
        let r_offset = read_u64(bytes, o)?;
        let info = read_u64(bytes, o + 8)?;
        if r_offset == init_array_va
            && (info & 0xffff_ffff) as u32 == elf.machine.relative_type()
        {
            let addend = read_u64(bytes, o + 16)?;
            if addend >= last_rx.p_vaddr && addend < last_rx.p_vaddr + last_rx.p_memsz {
                return Ok(Some(addend));
            }
            return Ok(None);
        }
    }
    Ok(None)
}