//! ELF64 AMD64 parser. Unsupported features fail closed.

use crate::{read_u16, read_u32, read_u64, FormatError, ImageKind};

const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;
const EM_X86_64: u16 = 62;
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
const R_X86_64_COPY: u32 = 5;
const R_X86_64_TPOFF32: u32 = 23;
const R_X86_64_IRELATIVE: u32 = 37;
const R_X86_64_TLSDESC: u32 = 36;
const STT_GNU_IFUNC: u8 = 10;

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
    if bytes[4] != 2 || bytes[5] != 1 {
        return Err(FormatError::Invalid("only ELF64 little-endian AMD64"));
    }
    let etype = read_u16(bytes, 16)?;
    let machine = read_u16(bytes, 18)?;
    if machine != EM_X86_64 {
        return Err(FormatError::Invalid("ELF machine is not AMD64"));
    }
    let kind = match etype {
        ET_EXEC => ImageKind::Elf64Exec,
        ET_DYN => ImageKind::Elf64Dyn,
        _ => return Err(FormatError::Invalid("ELF type is not ET_EXEC/ET_DYN")),
    };
    let entry = read_u64(bytes, 24)?;
    let phoff = read_u64(bytes, 32)? as usize;
    let phentsize = read_u16(bytes, 54)? as usize;
    let phnum = read_u16(bytes, 56)? as usize;
    if phentsize < 56 || phnum == 0 || phnum > 128 {
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
        return Err(FormatError::Invalid("static ELF is not packed in this release"));
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
            _ => {}
        }
        let _ = (DT_NEEDED, DT_SYMTAB, DT_FLAGS);
        i += 16;
    }
    scan_rela(bytes, phoff, phentsize, phnum, rela_off, rela_sz)?;
    scan_ifunc(bytes, phoff, phentsize, phnum, dyn_off, dynamic_sz)?;
    Ok(Elf64 {
        kind,
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
    if n > 1_000_000 {
        return Err(FormatError::Invalid("ELF rela count"));
    }
    for i in 0..n {
        let info = read_u64(bytes, off + i * 24 + 8)?;
        let kind = (info & 0xffff_ffff) as u32;
        match kind {
            R_X86_64_COPY => {
                return Err(FormatError::Invalid("ELF copy relocation is not packed"));
            }
            R_X86_64_TLSDESC => {
                return Err(FormatError::Invalid(
                    "ELF TLS descriptor reloc is not packed",
                ));
            }
            // R_X86_64_IRELATIVE: allowed since TASK-022 — resolvers run
            // during ld.so relocation (before INIT_ARRAY), so the packer
            // keeps their pages native; see `ifunc_resolvers`.
            // R_X86_64_TPOFF64 (18) targets an RW GOT slot: initial-exec,
            // unaffected by sealing RX pages.
            R_X86_64_TPOFF32 => {
                // Local-exec: offset embedded in the text itself — the page
                // restore would wipe the ld.so-applied value.
                return Err(FormatError::Invalid(
                    "ELF R_X86_64_TPOFF32 (text TLS offset) is not packed",
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
    // Fallback: the classic layout, when no hash table states the count.
    // Without this bound, bytes past .dynsym read as garbage symbols.
    let end = if strtab > symtab {
        match vaddr_to_off(bytes, phoff, phentsize, phnum, strtab) {
            Ok(o) => o,
            Err(_) => bytes.len(),
        }
    } else {
        bytes.len()
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

fn scan_ifunc(
    bytes: &[u8],
    phoff: usize,
    phentsize: usize,
    phnum: usize,
    dyn_off: usize,
    dynamic_sz: usize,
) -> Result<(), FormatError> {
    let Some((off, end)) = dynsym_extent(bytes, phoff, phentsize, phnum, dyn_off, dynamic_sz)?
    else {
        return Ok(());
    };
    let n_syms = (end.saturating_sub(off)) / 24;
    for n in 0..n_syms.min(65_536) {
        let so = off + n * 24;
        if so + 24 > bytes.len() {
            break;
        }
        let info = bytes[so + 4];
        let ty = info & 0xf;
        let shndx = u16::from_le_bytes([bytes[so + 6], bytes[so + 7]]);
        if ty == STT_GNU_IFUNC {
            if shndx == 0 {
                // An IMPORTED ifunc: ld.so must run someone else's resolver
                // during our load — outside our control, keep failing closed.
                return Err(FormatError::Invalid(
                    "ELF imported IFUNC symbol is not packed",
                ));
            }
            // Defined here: the resolver runs pre-init, but its address is
            // known — the packer keeps that page native (see
            // ifunc_symbol_values / ifunc_resolvers).
        }
    }
    Ok(())
}

/// Load-relative addresses of every STT_GNU_IFUNC symbol DEFINED in this
/// object (the resolvers ld.so may call at relocation time).
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
        if (info & 0xffff_ffff) as u32 == R_X86_64_IRELATIVE {
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
    for k in 0..(rela_sz as usize / 24) {
        let o = file + k * 24;
        let info = read_u64(bytes, o + 8)?;
        match (info & 0xffff_ffff) as u32 {
            // initial-exec: GOTTPOFF (22) offsets + TPOFF64 (18) GOT slots.
            18 | 22 => ie += 1,
            // general/local-dynamic module+offset pairs.
            16 | 17 => ld += 1,
            _ => {}
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
    fn real_imported_ifunc_inside_dynsym_still_fails_closed() {
        let mut gap = vec![0u8; 40];
        gap[28] = 0x1a;
        let img = elf_with_dynsym(0x0a, &gap); // sym1 st_info type 10, shndx 0
        match parse(&img) {
            Err(FormatError::Invalid(m)) => assert!(m.contains("imported IFUNC"), "{m}"),
            other => panic!("real imported IFUNC must fail closed, got {other:?}"),
        }
    }
}

/// If INIT_ARRAY[0] rides an R_X86_64_RELATIVE whose addend lands inside the
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
            26 => init_array_sz = val,
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
        if r_offset == init_array_va && (info & 0xffff_ffff) as u32 == R_X86_64_RELATIVE_TYPE {
            let addend = read_u64(bytes, o + 16)?;
            if addend >= last_rx.p_vaddr && addend < last_rx.p_vaddr + last_rx.p_memsz {
                return Ok(Some(addend));
            }
            return Ok(None);
        }
    }
    Ok(None)
}

const R_X86_64_RELATIVE_TYPE: u32 = 8;