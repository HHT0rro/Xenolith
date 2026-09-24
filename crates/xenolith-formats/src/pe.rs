use crate::{
    read_u16, read_u32, read_u64, write_u16, write_u32, FormatError, MAX_IMAGE,
};
use serde::Serialize;

pub const IMAGE_FILE_DLL: u16 = 0x2000;
pub const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
pub const IMAGE_NT_OPTIONAL_HDR64_MAGIC: u16 = 0x20b;
pub const IMAGE_DIRECTORY_ENTRY_EXPORT: usize = 0;
pub const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;
pub const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;
/// The security (Authenticode certificate) directory. Unlike every other
/// directory its VA field is an absolute FILE OFFSET, so it does not survive
/// any byte-level repack (the signature covered the original bytes).
pub const IMAGE_DIRECTORY_ENTRY_SECURITY: usize = 4;
pub const IMAGE_DIRECTORY_ENTRY_DEBUG: usize = 6;
pub const IMAGE_DIRECTORY_ENTRY_TLS: usize = 9;
pub const IMAGE_DIRECTORY_ENTRY_EXCEPTION: usize = 3;
pub const IMAGE_DIRECTORY_ENTRY_IAT: usize = 12;
pub const IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT: usize = 13;
pub const IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG: usize = 10;
pub const IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR: usize = 14;
pub const IMAGE_REL_BASED_DIR64: u16 = 10;
pub const IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE: u16 = 0x0040;
pub const IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA: u16 = 0x0020;
pub const IMAGE_DLLCHARACTERISTICS_GUARD_CF: u16 = 0x4000;
/// IMAGE_GUARD_CF_INSTRUMENTED inside the load-config GuardFlags dword.
pub const IMAGE_GUARD_CF_INSTRUMENTED: u32 = 0x0000_0100;
/// IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT — GFIDS table VA/count are valid.
pub const IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT: u32 = 0x0000_0400;
/// IMAGE_GUARD_XFG_ENABLED — GFIDS entries carry an extra XFG hash; format
/// change relative to a plain RVA(+flag-bytes) table. Fail closed.
pub const IMAGE_GUARD_XFG_ENABLED: u32 = 0x0080_0000;
/// High nibble of GuardFlags: extra flag-bytes after each GFIDS RVA dword.
/// stride = 4 + ((GuardFlags >> 28) & 0xF).
pub const IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT: u32 = 28;
pub const IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK: u32 = 0xF;
/// DoS bound on a GFIDS table we are willing to copy. Real system EXEs sit
/// well below this (where.exe: 8, Robocopy.exe: 116, curl.exe: 0x187).
pub const MAX_GFIDS_ENTRIES: u64 = 1 << 20;
/// Modern PE64 load-config Size that reaches GuardFlags (winnt.h 0x94).
pub const LOAD_CONFIG64_GUARD_FLAGS_SIZE: u32 = 0x94;
/// Offset of GuardCFCheckFunctionPointer (ULONGLONG VA) in IMAGE_LOAD_CONFIG_DIRECTORY64.
pub const LOAD_CONFIG64_GUARD_CF_CHECK_FUNCTION_POINTER: usize = 0x70;
/// Offset of GuardCFDispatchFunctionPointer (ULONGLONG VA) in IMAGE_LOAD_CONFIG_DIRECTORY64.
pub const LOAD_CONFIG64_GUARD_CF_DISPATCH_FUNCTION_POINTER: usize = 0x78;
/// Offset of GuardCFFunctionTable (ULONGLONG VA) in IMAGE_LOAD_CONFIG_DIRECTORY64.
pub const LOAD_CONFIG64_GUARD_CF_FUNCTION_TABLE: usize = 0x80;
/// Offset of GuardCFFunctionCount (ULONGLONG) in IMAGE_LOAD_CONFIG_DIRECTORY64.
pub const LOAD_CONFIG64_GUARD_CF_FUNCTION_COUNT: usize = 0x88;
/// Offset of GuardFlags (DWORD) in IMAGE_LOAD_CONFIG_DIRECTORY64.
pub const LOAD_CONFIG64_GUARD_FLAGS: usize = 0x90;
pub const IMAGE_FILE_RELOCS_STRIPPED: u16 = 0x0001;
pub const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
pub const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
pub const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
pub const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;
const SECTION_HEADER_SIZE: usize = 40;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum PeKind {
    Dll,
    Exe,
}

#[derive(Clone, Debug, Serialize)]
pub struct DataDirectory {
    pub rva: u32,
    pub size: u32,
}

#[derive(Clone, Debug, Serialize)]
pub struct Section {
    pub name: [u8; 8],
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub raw_size: u32,
    pub raw_ptr: u32,
    pub characteristics: u32,
    pub header_offset: usize,
}

impl Section {
    pub fn name_str(&self) -> String {
        let end = self
            .name
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.name.len());
        String::from_utf8_lossy(&self.name[..end]).into_owned()
    }

    pub fn contains_rva(&self, rva: u32) -> bool {
        let size = self.virtual_size.max(self.raw_size);
        rva >= self.virtual_address && rva < self.virtual_address.saturating_add(size)
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct ExportSymbol {
    pub name: String,
    pub ordinal: u16,
    pub rva: u32,
}

#[derive(Clone, Debug, Serialize)]
pub struct ImportSymbol {
    pub dll: String,
    pub name: String,
    pub iat_rva: u32,
    pub ordinal: Option<u16>,
}

#[derive(Clone, Debug, Serialize)]
pub struct CoffFunction {
    pub name: String,
    pub rva: u32,
}

#[derive(Clone, Copy, Debug, Serialize)]
pub struct RuntimeFunction {
    pub begin_rva: u32,
    pub end_rva: u32,
}

#[derive(Clone, Copy, Debug)]
pub struct RelocEntry {
    pub rva: u32,
    pub kind: u16,
}

/// One GFIDS entry: a 4-byte function RVA plus 0..=15 flag bytes whose
/// length is `((GuardFlags >> 28) & 0xF)`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GfidsEntry {
    pub rva: u32,
    pub flags: Vec<u8>,
}

/// Parsed PE64 load-config CFG fields. `table_va` is the on-disk preferred
/// VA (ImageBase + table RVA); the system DIR64 reloc covering this field
/// still applies at load because the field stays at the same file offset.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoadConfigCfg {
    /// File offset of the load-config directory (Size field).
    pub config_file_offset: usize,
    /// Declared Size dword at the start of the directory.
    pub declared_size: u32,
    /// Preferred-base VA of the GuardCFCheckFunctionPointer slot (pointer to
    /// a function pointer, typically in .rdata). Zero if undeclared.
    pub check_function_slot_va: u64,
    /// Preferred-base VA of the GuardCFDispatchFunctionPointer slot.
    pub dispatch_function_slot_va: u64,
    /// Preferred-base VA stored in GuardCFFunctionTable.
    pub table_va: u64,
    pub function_count: u64,
    pub guard_flags: u32,
    /// File offset of the GuardCFFunctionTable ULONGLONG (always config+0x80
    /// on a Size>=0x94 PE64 config).
    pub table_va_file_offset: usize,
    /// File offset of the GuardCFFunctionCount ULONGLONG.
    pub count_file_offset: usize,
    /// File offset of the GuardFlags DWORD.
    pub flags_file_offset: usize,
}

#[derive(Clone, Debug)]
pub struct Pe64 {
    pub kind: PeKind,
    pub dos_lfanew: u32,
    pub file_header_offset: usize,
    pub optional_offset: usize,
    pub size_of_optional: u16,
    pub section_table_offset: usize,
    pub number_of_sections: u16,
    pub characteristics: u16,
    pub entry_rva: u32,
    pub image_base: u64,
    pub section_align: u32,
    pub file_align: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub dll_characteristics: u16,
    pub directories: Vec<DataDirectory>,
    pub sections: Vec<Section>,
}

impl Pe64 {
    pub fn parse(bytes: &[u8]) -> Result<Self, FormatError> {
        if bytes.len() < 0x40 {
            return Err(FormatError::Truncated);
        }
        if bytes.len() > MAX_IMAGE {
            return Err(FormatError::TooLarge);
        }
        if &bytes[0..2] != b"MZ" {
            return Err(FormatError::Unsupported);
        }
        let lfanew = read_u32(bytes, 0x3c)?;
        let nt = lfanew as usize;
        if nt
            .checked_add(24 + 112)
            .filter(|end| *end <= bytes.len())
            .is_none()
        {
            return Err(FormatError::Truncated);
        }
        if &bytes[nt..nt + 4] != b"PE\0\0" {
            return Err(FormatError::Invalid("PE signature"));
        }
        let file_header = nt + 4;
        let machine = read_u16(bytes, file_header)?;
        if machine != IMAGE_FILE_MACHINE_AMD64 {
            return Err(FormatError::Unsupported);
        }
        let number_of_sections = read_u16(bytes, file_header + 2)?;
        if number_of_sections == 0 {
            return Err(FormatError::Invalid("section count"));
        }
        let size_of_optional = read_u16(bytes, file_header + 16)?;
        let characteristics = read_u16(bytes, file_header + 18)?;
        let optional = file_header + 20;
        let magic = read_u16(bytes, optional)?;
        if magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC {
            return Err(FormatError::Unsupported);
        }
        if size_of_optional < 112 {
            return Err(FormatError::Invalid("optional header"));
        }
        let entry_rva = read_u32(bytes, optional + 16)?;
        let image_base = read_u64(bytes, optional + 24)?;
        let section_align = read_u32(bytes, optional + 32)?;
        let file_align = read_u32(bytes, optional + 36)?;
        if section_align == 0 || file_align == 0 {
            return Err(FormatError::Invalid("alignment"));
        }
        let size_of_image = read_u32(bytes, optional + 56)?;
        let size_of_headers = read_u32(bytes, optional + 60)?;
        let dll_characteristics = read_u16(bytes, optional + 70)?;
        // Loader-consistent clamp instead of a hard reject: only directories
        // that fit both the spec maximum (16) and the declared optional
        // header are read; entries beyond either are never queried.
        let declared_dirs = read_u32(bytes, optional + 108)? as usize;
        let dir_capacity = (size_of_optional as usize).saturating_sub(112) / 8;
        let dir_count = declared_dirs.min(16).min(dir_capacity);
        let dir_off = optional + 112;
        let mut directories = Vec::with_capacity(dir_count);
        for i in 0..dir_count {
            let o = dir_off + i * 8;
            directories.push(DataDirectory {
                rva: read_u32(bytes, o)?,
                size: read_u32(bytes, o + 4)?,
            });
        }
        let section_table = optional + size_of_optional as usize;
        // Structural bound instead of an arbitrary section-count cap: the
        // whole table must sit inside the file (well-formed images keep it
        // within SizeOfHeaders). Per-header fields remain bounds-checked.
        section_table
            .checked_add(number_of_sections as usize * SECTION_HEADER_SIZE)
            .filter(|end| *end <= bytes.len())
            .ok_or(FormatError::Truncated)?;
        let mut sections = Vec::with_capacity(number_of_sections as usize);
        for i in 0..number_of_sections as usize {
            let o = section_table + i * SECTION_HEADER_SIZE;
            let mut name = [0u8; 8];
            let raw = bytes.get(o..o + 8).ok_or(FormatError::Truncated)?;
            name.copy_from_slice(raw);
            let virtual_size = read_u32(bytes, o + 8)?;
            let virtual_address = read_u32(bytes, o + 12)?;
            let raw_size = read_u32(bytes, o + 16)?;
            let raw_ptr = read_u32(bytes, o + 20)?;
            let characteristics = read_u32(bytes, o + 36)?;
            // Loader semantics: raw bytes running past EOF are legal — the
            // loader zero-fills the tail (truncated overlays, repacked and
            // exotic-linker images). Reject only a PointerToRawData wholly
            // beyond the file; otherwise clamp raw_size so later reads fail
            // with the specific "rva outside raw data" bound.
            let raw_size = if raw_size != 0 {
                let ptr = raw_ptr as usize;
                if ptr > bytes.len() {
                    return Err(FormatError::Truncated);
                }
                (raw_size as usize).min(bytes.len() - ptr) as u32
            } else {
                raw_size
            };
            sections.push(Section {
                name,
                virtual_size,
                virtual_address,
                raw_size,
                raw_ptr,
                characteristics,
                header_offset: o,
            });
        }
        let kind = if characteristics & IMAGE_FILE_DLL != 0 {
            PeKind::Dll
        } else {
            PeKind::Exe
        };
        Ok(Self {
            kind,
            dos_lfanew: lfanew,
            file_header_offset: file_header,
            optional_offset: optional,
            size_of_optional,
            section_table_offset: section_table,
            number_of_sections,
            characteristics,
            entry_rva,
            image_base,
            section_align,
            file_align,
            size_of_image,
            size_of_headers,
            dll_characteristics,
            directories,
            sections,
        })
    }

    /// External function symbols from the COFF symbol table. Release images
    /// often strip this table; callers must fall back to exports, unwind
    /// metadata, or an explicit range instead of guessing.
    pub fn coff_functions(&self, bytes: &[u8]) -> Result<Vec<CoffFunction>, FormatError> {
        let sym_ptr = read_u32(bytes, self.file_header_offset + 8)? as usize;
        let sym_count = read_u32(bytes, self.file_header_offset + 12)? as usize;
        if sym_ptr == 0 || sym_count == 0 {
            return Ok(Vec::new());
        }
        let sym_bytes = sym_count
            .checked_mul(18)
            .ok_or(FormatError::Invalid("COFF symbol extent"))?;
        let sym_end = sym_ptr
            .checked_add(sym_bytes)
            .filter(|end| *end <= bytes.len())
            .ok_or(FormatError::Truncated)?;
        let str_len = read_u32(bytes, sym_end)? as usize;
        if str_len < 4 {
            return Err(FormatError::Invalid("COFF string table"));
        }
        let str_off = sym_end
            .checked_add(4)
            .filter(|off| *off <= bytes.len())
            .ok_or(FormatError::Truncated)?;
        let strings = bytes
            .get(str_off..str_off.saturating_add(str_len - 4))
            .ok_or(FormatError::Truncated)?;

        let mut out = Vec::new();
        let mut i = 0usize;
        while i < sym_count {
            let off = sym_ptr + i * 18;
            let raw_name = &bytes[off..off + 8];
            let value = read_u32(bytes, off + 8)?;
            let section = i16::from_le_bytes([bytes[off + 12], bytes[off + 13]]);
            let typ = read_u16(bytes, off + 14)?;
            let storage = bytes[off + 16];
            let aux = bytes[off + 17] as usize;
            i = i
                .checked_add(1 + aux)
                .ok_or(FormatError::Invalid("COFF aux count"))?;

            let is_function = typ & 0x20 != 0;
            let is_external = storage == 2;
            if !is_function || !is_external || section <= 0 {
                continue;
            }
            let section = match self.sections.get(section as usize - 1) {
                Some(section) => section,
                None => continue,
            };
            let name = if raw_name[..4] == [0, 0, 0, 0] {
                let name_off = u32::from_le_bytes(raw_name[4..8].try_into().unwrap()) as usize;
                let Some(tail) = strings.get(name_off..) else {
                    continue;
                };
                let Some(end) = tail.iter().position(|&b| b == 0) else {
                    continue;
                };
                String::from_utf8_lossy(&tail[..end]).into_owned()
            } else {
                let end = raw_name.iter().position(|&b| b == 0).unwrap_or(8);
                String::from_utf8_lossy(&raw_name[..end]).into_owned()
            };
            if name.is_empty() {
                continue;
            }
            let section_end = section
                .virtual_address
                .saturating_add(section.virtual_size.max(section.raw_size));
            let rva = if value >= section.virtual_address && value < section_end {
                value
            } else if value < section.virtual_size.max(section.raw_size) {
                section.virtual_address.saturating_add(value)
            } else {
                continue;
            };
            if self.file_offset_of(rva).is_ok() {
                out.push(CoffFunction { name, rva });
            }
        }
        out.sort_by_key(|f| f.rva);
        out.dedup_by(|a, b| a.name == b.name && a.rva == b.rva);
        Ok(out)
    }

    /// Function boundaries from the PE x64 exception directory (`.pdata`).
    /// This is available on stripped release images and is the authoritative
    /// unwind boundary source when COFF/PDB symbols are absent.
    pub fn runtime_functions(&self, bytes: &[u8]) -> Result<Vec<RuntimeFunction>, FormatError> {
        const MAX_RUNTIME_FUNCTIONS: usize = 262_144;
        let Some(dir) = self.directory(IMAGE_DIRECTORY_ENTRY_EXCEPTION) else {
            return Ok(Vec::new());
        };
        if dir.rva == 0 || dir.size < 12 {
            return Ok(Vec::new());
        }
        let off = self.file_offset_of(dir.rva)?;
        let count = (dir.size as usize / 12).min(MAX_RUNTIME_FUNCTIONS);
        let end = off
            .checked_add(count * 12)
            .filter(|end| *end <= bytes.len())
            .ok_or(FormatError::Truncated)?;
        let mut out = Vec::with_capacity(count);
        for entry in bytes[off..end].chunks_exact(12) {
            let begin_rva = u32::from_le_bytes(entry[0..4].try_into().unwrap());
            let end_rva = u32::from_le_bytes(entry[4..8].try_into().unwrap());
            if begin_rva == 0 || end_rva <= begin_rva {
                continue;
            }
            if self.file_offset_of(begin_rva).is_err() {
                continue;
            }
            out.push(RuntimeFunction {
                begin_rva,
                end_rva,
            });
        }
        out.sort_by_key(|f| (f.begin_rva, f.end_rva));
        out.dedup_by(|a, b| a.begin_rva == b.begin_rva && a.end_rva == b.end_rva);
        Ok(out)
    }

    pub fn directory(&self, index: usize) -> Option<&DataDirectory> {
        self.directories.get(index)
    }

    pub fn section_for_rva(&self, rva: u32) -> Option<&Section> {
        self.sections.iter().find(|s| s.contains_rva(rva))
    }

    pub fn file_offset_of(&self, rva: u32) -> Result<usize, FormatError> {
        let section = self
            .section_for_rva(rva)
            .ok_or(FormatError::Invalid("rva outside sections"))?;
        let delta = rva - section.virtual_address;
        if delta >= section.raw_size && section.raw_size != 0 {
            return Err(FormatError::Invalid("rva outside raw data"));
        }
        Ok(section.raw_ptr as usize + delta as usize)
    }

    /// ANSI byte-string bound for import/export names. MSVC decorated names
    /// from deeply nested templates exceed 512 bytes, so the anti-DoS bound
    /// is 4096.
    const MAX_NAME_BYTES: usize = 4096;

    /// Import/export name strings are ANSI bytes in PE, not UTF-8: localized
    /// builds (GBK/Shift-JIS/cp1252) carry raw code-page bytes. Names feed
    /// display and hashing only, so decode lossily — the same treatment the
    /// COFF path already applies.
    pub fn read_cstr(&self, bytes: &[u8], rva: u32) -> Result<String, FormatError> {
        let mut offset = self.file_offset_of(rva)?;
        let mut out = Vec::new();
        while offset < bytes.len() {
            let b = bytes[offset];
            if b == 0 {
                break;
            }
            out.push(b);
            offset += 1;
            if out.len() > Self::MAX_NAME_BYTES {
                return Err(FormatError::Invalid("string too long"));
            }
        }
        Ok(String::from_utf8_lossy(&out).into_owned())
    }

    /// Export-directory slot bound. Modern template-heavy C++ DLLs export
    /// far more than 16k symbols; 2^20 keeps a DoS bound while real images
    /// stay orders of magnitude below it.
    const MAX_EXPORT_SLOTS: usize = 1 << 20;

    pub fn exports(&self, bytes: &[u8]) -> Result<Vec<ExportSymbol>, FormatError> {
        let dir = match self.directory(IMAGE_DIRECTORY_ENTRY_EXPORT) {
            Some(d) if d.rva != 0 && d.size >= 40 => d,
            _ => return Ok(Vec::new()),
        };
        let base = self.file_offset_of(dir.rva)?;
        let ordinal_base = read_u32(bytes, base + 16)?;
        let n_functions = read_u32(bytes, base + 20)? as usize;
        let n_names = read_u32(bytes, base + 24)? as usize;
        if n_functions > Self::MAX_EXPORT_SLOTS || n_names > Self::MAX_EXPORT_SLOTS {
            return Err(FormatError::Invalid("export count"));
        }
        let addr_rva = read_u32(bytes, base + 28)?;
        let names_rva = read_u32(bytes, base + 32)?;
        let ords_rva = read_u32(bytes, base + 36)?;
        let mut exports = Vec::with_capacity(n_names);
        for i in 0..n_names {
            let name_rva_arr = names_rva
                .checked_add((i as u32) * 4)
                .ok_or(FormatError::Invalid("export name table rva overflow"))?;
            let name_ptr_off = self.file_offset_of(name_rva_arr)?;
            let name_rva = read_u32(bytes, name_ptr_off)?;
            let name = self.read_cstr(bytes, name_rva)?;
            let ord_rva_arr = ords_rva
                .checked_add((i as u32) * 2)
                .ok_or(FormatError::Invalid("export ordinal table rva overflow"))?;
            let ord_off = self.file_offset_of(ord_rva_arr)?;
            let ordinal_index = read_u16(bytes, ord_off)? as u32;
            if ordinal_index as usize >= n_functions {
                return Err(FormatError::Invalid("export ordinal"));
            }
            let func_tbl_rva = addr_rva
                .checked_add(ordinal_index * 4)
                .ok_or(FormatError::Invalid("export function table rva overflow"))?;
            let func_off = self.file_offset_of(func_tbl_rva)?;
            let rva = read_u32(bytes, func_off)?;
            exports.push(ExportSymbol {
                name,
                // Display-only field; wrapping keeps hostile headers from
                // panicking the parser.
                ordinal: ordinal_base.wrapping_add(ordinal_index) as u16,
                rva,
            });
        }
        Ok(exports)
    }

    pub fn set_export_rva(
        &self,
        bytes: &mut [u8],
        name: &str,
        new_rva: u32,
    ) -> Result<(), FormatError> {
        let dir = match self.directory(IMAGE_DIRECTORY_ENTRY_EXPORT) {
            Some(d) if d.rva != 0 && d.size >= 40 => d,
            _ => return Err(FormatError::Invalid("export directory")),
        };
        let base = self.file_offset_of(dir.rva)?;
        let n_functions = read_u32(bytes, base + 20)? as usize;
        let n_names = read_u32(bytes, base + 24)? as usize;
        if n_functions > Self::MAX_EXPORT_SLOTS || n_names > Self::MAX_EXPORT_SLOTS {
            return Err(FormatError::Invalid("export count"));
        }
        let addr_rva = read_u32(bytes, base + 28)?;
        let names_rva = read_u32(bytes, base + 32)?;
        let ords_rva = read_u32(bytes, base + 36)?;
        for i in 0..n_names {
            let name_ptr_off = self.file_offset_of(names_rva + (i as u32) * 4)?;
            let name_rva = read_u32(bytes, name_ptr_off)?;
            let found = self.read_cstr(bytes, name_rva)?;
            if found != name {
                continue;
            }
            let ord_off = self.file_offset_of(ords_rva + (i as u32) * 2)?;
            let ordinal_index = read_u16(bytes, ord_off)? as u32;
            if ordinal_index as usize >= n_functions {
                return Err(FormatError::Invalid("export ordinal"));
            }
            let func_off = self.file_offset_of(addr_rva + ordinal_index * 4)?;
            write_u32(bytes, func_off, new_rva)?;
            return Ok(());
        }
        Err(FormatError::Invalid("export name"))
    }

    /// Import-table walk bounds. The previous silent caps (256 descriptors,
    /// 4096 thunks) truncated large real import tables without any signal;
    /// exceeding the bound is now an explicit error so a truncated IAT can
    /// never be packed (unresolved slots would fault at load).
    const MAX_IMPORT_DESCRIPTORS: usize = 65_536;
    const MAX_IMPORT_THUNKS: usize = 65_536;

    /// TASK-024: (rva, len) of every plaintext import name string — DLL
    /// names and hint/name entries (hint u16 + name + NUL). Zeroing only the
    /// import *directory* hides it from the loader but leaves these bytes
    /// readable in the file; the packer scrubs the ranges themselves.
    /// Ordinal imports have no name string, so their slots contribute
    /// nothing here.
    pub fn import_name_locations(&self, bytes: &[u8]) -> Result<Vec<(u32, u32)>, FormatError> {
        let dir = match self.directory(IMAGE_DIRECTORY_ENTRY_IMPORT) {
            Some(d) if d.rva != 0 && d.size >= 20 => d,
            _ => return Ok(Vec::new()),
        };
        let mut desc_rva = dir.rva;
        let mut out = Vec::new();
        let mut descriptors = 0usize;
        loop {
            if descriptors >= Self::MAX_IMPORT_DESCRIPTORS {
                return Err(FormatError::Invalid("import descriptor count"));
            }
            descriptors += 1;
            let desc_off = self.file_offset_of(desc_rva)?;
            let lookup_rva = read_u32(bytes, desc_off)?;
            let name_rva = read_u32(bytes, desc_off + 12)?;
            let iat_rva = read_u32(bytes, desc_off + 16)?;
            if lookup_rva == 0 && name_rva == 0 && iat_rva == 0 {
                break;
            }
            let dll_len = self.read_cstr(bytes, name_rva)?.len() as u32;
            out.push((name_rva, dll_len + 1));
            let mut thunk_rva = if lookup_rva != 0 { lookup_rva } else { iat_rva };
            let mut terminated = false;
            for _ in 0..Self::MAX_IMPORT_THUNKS {
                let thunk_off = self.file_offset_of(thunk_rva)?;
                let thunk = read_u64(bytes, thunk_off)?;
                if thunk == 0 {
                    terminated = true;
                    break;
                }
                if thunk & (1u64 << 63) == 0 {
                    let hint_name = thunk as u32;
                    let hint_off = hint_name
                        .checked_add(2)
                        .ok_or(FormatError::Invalid("hint/name rva overflow"))?;
                    let n = self.read_cstr(bytes, hint_off)?.len() as u32;
                    out.push((hint_name, n + 3)); // hint(2) + name + NUL
                }
                thunk_rva = thunk_rva.saturating_add(8);
            }
            if !terminated {
                // No NUL terminator within the bound: refusing beats leaving
                // name bytes unscrubbed.
                return Err(FormatError::Invalid("import thunk count"));
            }
            desc_rva = desc_rva.saturating_add(20);
        }
        Ok(out)
    }

    /// Every IAT slot as (dll, name-or-empty, iat_rva, ordinal). Ordinal
    /// imports — thunk high bit set, ordinal in the low 16 bits — are parsed
    /// per the PE spec instead of rejecting the image: Delphi/C++Builder
    /// RTLs, ws2_32 callers, and ordinal-only vendor DLLs are routine. The
    /// runtime entry carrying them is `ordinal: Some(_)` with an empty
    /// `name` (there is no hint/name string).
    pub fn imports(&self, bytes: &[u8]) -> Result<Vec<ImportSymbol>, FormatError> {
        let dir = match self.directory(IMAGE_DIRECTORY_ENTRY_IMPORT) {
            Some(d) if d.rva != 0 && d.size >= 20 => d,
            _ => return Ok(Vec::new()),
        };
        let mut desc_rva = dir.rva;
        let mut out = Vec::new();
        let mut descriptors = 0usize;
        loop {
            if descriptors >= Self::MAX_IMPORT_DESCRIPTORS {
                return Err(FormatError::Invalid("import descriptor count"));
            }
            descriptors += 1;
            let desc_off = self.file_offset_of(desc_rva)?;
            let lookup_rva = read_u32(bytes, desc_off)?;
            let name_rva = read_u32(bytes, desc_off + 12)?;
            let iat_rva = read_u32(bytes, desc_off + 16)?;
            if lookup_rva == 0 && name_rva == 0 && iat_rva == 0 {
                break;
            }
            let dll = self.read_cstr(bytes, name_rva)?;
            let mut thunk_rva = if lookup_rva != 0 { lookup_rva } else { iat_rva };
            let mut iat_slot = iat_rva;
            let mut terminated = false;
            for _ in 0..Self::MAX_IMPORT_THUNKS {
                let thunk_off = self.file_offset_of(thunk_rva)?;
                let thunk = read_u64(bytes, thunk_off)?;
                if thunk == 0 {
                    terminated = true;
                    break;
                }
                let (name, ordinal) = if thunk & (1u64 << 63) != 0 {
                    // Import by ordinal: no hint/name RVA exists.
                    (String::new(), Some((thunk & 0xFFFF) as u16))
                } else {
                    let hint_name = thunk as u32;
                    let hint_off = hint_name
                        .checked_add(2)
                        .ok_or(FormatError::Invalid("hint/name rva overflow"))?;
                    (self.read_cstr(bytes, hint_off)?, None)
                };
                out.push(ImportSymbol {
                    dll: dll.clone(),
                    name,
                    iat_rva: iat_slot,
                    ordinal,
                });
                thunk_rva = thunk_rva.saturating_add(8);
                iat_slot = iat_slot.saturating_add(8);
            }
            if !terminated {
                // Loop exhausted without a NUL terminator: fail closed
                // instead of silently packing a truncated IAT (unresolved
                // slots would fault at load).
                return Err(FormatError::Invalid("import thunk count"));
            }
            desc_rva = desc_rva.saturating_add(20);
        }
        Ok(out)
    }

    pub fn delay_import_present(&self) -> bool {
        self.directory(IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT)
            .map(|d| d.rva != 0 && d.size != 0)
            .unwrap_or(false)
    }

    pub fn load_config_present(&self) -> bool {
        self.directory(IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG)
            .map(|d| d.rva != 0 && d.size != 0)
            .unwrap_or(false)
    }

    /// GuardFlags from the PE64 load-config directory.
    ///
    /// IMAGE_LOAD_CONFIG_DIRECTORY64 (winnt.h): GuardCFFunctionTable at +0x80
    /// (ULONGLONG VA), GuardCFFunctionCount at +0x88 (ULONGLONG), GuardFlags
    /// at +0x90 (DWORD). A config whose declared Size does not reach 0x94
    /// cannot carry those fields and yields None — nothing is inferred from
    /// bytes the image itself does not declare. A previous layout that read
    /// +0x88 as a DWORD was actually reading the low half of FunctionCount
    /// (where.exe 8, tasklist.exe 0x10, curl.exe 0x187).
    pub fn load_config_guard_flags(&self, bytes: &[u8]) -> Result<Option<u32>, FormatError> {
        Ok(self.load_config_cfg(bytes)?.map(|c| c.guard_flags))
    }

    /// Parse the CFG-bearing fields of IMAGE_LOAD_CONFIG_DIRECTORY64.
    /// Returns None when the directory is absent or too small to declare
    /// GuardFlags. Truncation of a declared modern config is an error.
    pub fn load_config_cfg(&self, bytes: &[u8]) -> Result<Option<LoadConfigCfg>, FormatError> {
        let Some(dir) = self.directory(IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG) else {
            return Ok(None);
        };
        if dir.rva == 0 || dir.size < 4 {
            return Ok(None);
        }
        let off = self.file_offset_of(dir.rva)?;
        let dir_end = off
            .checked_add(dir.size as usize)
            .filter(|e| *e <= bytes.len())
            .ok_or(FormatError::Truncated)?;
        let declared = read_u32(bytes, off)?;
        if declared < LOAD_CONFIG64_GUARD_FLAGS_SIZE {
            return Ok(None);
        }
        let flags_off = off
            .checked_add(LOAD_CONFIG64_GUARD_FLAGS)
            .ok_or(FormatError::Truncated)?;
        let table_off = off
            .checked_add(LOAD_CONFIG64_GUARD_CF_FUNCTION_TABLE)
            .ok_or(FormatError::Truncated)?;
        let count_off = off
            .checked_add(LOAD_CONFIG64_GUARD_CF_FUNCTION_COUNT)
            .ok_or(FormatError::Truncated)?;
        let check_off = off
            .checked_add(LOAD_CONFIG64_GUARD_CF_CHECK_FUNCTION_POINTER)
            .ok_or(FormatError::Truncated)?;
        let dispatch_off = off
            .checked_add(LOAD_CONFIG64_GUARD_CF_DISPATCH_FUNCTION_POINTER)
            .ok_or(FormatError::Truncated)?;
        // Declared Size is authoritative for field presence; the data-directory
        // Size is a second bound so a lying Size dword cannot read past the
        // mapped directory window.
        if flags_off + 4 > dir_end || flags_off + 4 > off + declared as usize {
            return Ok(None);
        }
        if table_off + 8 > dir_end
            || count_off + 8 > dir_end
            || check_off + 8 > dir_end
            || dispatch_off + 8 > dir_end
        {
            return Err(FormatError::Truncated);
        }
        Ok(Some(LoadConfigCfg {
            config_file_offset: off,
            declared_size: declared,
            check_function_slot_va: read_u64(bytes, check_off)?,
            dispatch_function_slot_va: read_u64(bytes, dispatch_off)?,
            table_va: read_u64(bytes, table_off)?,
            function_count: read_u64(bytes, count_off)?,
            guard_flags: read_u32(bytes, flags_off)?,
            table_va_file_offset: table_off,
            count_file_offset: count_off,
            flags_file_offset: flags_off,
        }))
    }

    /// Resolve a load-config function-pointer *slot* (preferred VA of a
    /// pointer-to-function in .rdata) to the pointed-to function RVA.
    /// The loader calls that gadget (MSVC: `ret 0` / `jmp rax`) before any
    /// packed stub byte runs.
    pub fn load_config_guard_target_rva(
        &self,
        bytes: &[u8],
        slot_va: u64,
        what: &'static str,
    ) -> Result<Option<u32>, FormatError> {
        if slot_va == 0 {
            return Ok(None);
        }
        let slot_rva = self.va_to_rva(slot_va, what)?;
        let off = self.file_offset_of(slot_rva)?;
        let target_va = read_u64(bytes, off)?;
        if target_va == 0 {
            return Ok(None);
        }
        Ok(Some(self.va_to_rva(target_va, what)?))
    }

    /// GFIDS entry stride: 4-byte RVA + `((GuardFlags >> 28) & 0xF)` flag bytes.
    pub fn gfids_stride(guard_flags: u32) -> usize {
        4 + ((guard_flags >> IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT)
            & IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK) as usize
    }

    /// Read the on-disk GFIDS table referenced by a parsed load-config.
    /// Fail-closed on XFG (entry format change), missing FUNCTION_TABLE_PRESENT,
    /// count overflow, or a table that runs past mapped raw data.
    pub fn gfids_table(
        &self,
        bytes: &[u8],
        cfg: &LoadConfigCfg,
    ) -> Result<Vec<GfidsEntry>, FormatError> {
        if cfg.guard_flags & IMAGE_GUARD_XFG_ENABLED != 0 {
            return Err(FormatError::Invalid(
                "load-config GuardFlags IMAGE_GUARD_XFG_ENABLED (0x800000): GFIDS entries carry an XFG hash this packer does not rewrite",
            ));
        }
        if cfg.guard_flags & IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT == 0 {
            return Err(FormatError::Invalid(
                "load-config GuardFlags missing IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT (0x400)",
            ));
        }
        if cfg.table_va == 0 {
            return Err(FormatError::Invalid(
                "load-config GuardCFFunctionTable VA is zero while FUNCTION_TABLE_PRESENT is set",
            ));
        }
        if cfg.function_count > MAX_GFIDS_ENTRIES {
            return Err(FormatError::Invalid(
                "load-config GuardCFFunctionCount exceeds MAX_GFIDS_ENTRIES",
            ));
        }
        let stride = Self::gfids_stride(cfg.guard_flags);
        let table_rva = self.va_to_rva(cfg.table_va, "GuardCFFunctionTable VA")?;
        let table_off = self.file_offset_of(table_rva)?;
        let count = cfg.function_count as usize;
        let bytes_len = count
            .checked_mul(stride)
            .ok_or(FormatError::Invalid("GFIDS table size overflow"))?;
        let table_end = table_off
            .checked_add(bytes_len)
            .filter(|e| *e <= bytes.len())
            .ok_or(FormatError::Truncated)?;
        // The table must sit inside one section's raw data, not merely the
        // file: a count that walks into the next section is a corrupt GFIDS.
        let section = self
            .section_for_rva(table_rva)
            .ok_or(FormatError::Invalid("GFIDS table RVA outside sections"))?;
        let raw_end = (section.raw_ptr as usize)
            .checked_add(section.raw_size as usize)
            .ok_or(FormatError::Truncated)?;
        if table_end > raw_end {
            return Err(FormatError::Invalid(
                "GFIDS table overruns the containing section's raw data",
            ));
        }
        let mut out = Vec::with_capacity(count);
        let mut cur = table_off;
        for _ in 0..count {
            let rva = read_u32(bytes, cur)?;
            let flags = bytes[cur + 4..cur + stride].to_vec();
            out.push(GfidsEntry { rva, flags });
            cur += stride;
        }
        Ok(out)
    }

    /// Encode a GFIDS table (already sorted by RVA) into the on-disk layout.
    /// `flag_len` is the extra-byte count from GuardFlags bits 28..31.
    pub fn encode_gfids_table(
        entries: &[GfidsEntry],
        flag_len: usize,
    ) -> Result<Vec<u8>, FormatError> {
        if flag_len > IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK as usize {
            return Err(FormatError::Invalid("GFIDS flag-byte count exceeds 15"));
        }
        let stride = 4 + flag_len;
        let mut out = Vec::with_capacity(
            entries
                .len()
                .checked_mul(stride)
                .ok_or(FormatError::Invalid("GFIDS encode size overflow"))?,
        );
        for e in entries {
            if e.flags.len() != flag_len {
                return Err(FormatError::Invalid(
                    "GFIDS entry flag-byte length does not match GuardFlags stride",
                ));
            }
            out.extend_from_slice(&e.rva.to_le_bytes());
            out.extend_from_slice(&e.flags);
        }
        Ok(out)
    }

    /// Insert `new_rvas` into a GFIDS table, sorted by RVA, skipping duplicates.
    /// New entries copy `oep_rva`'s flag bytes when that RVA is already in the
    /// table; otherwise the flags are zeros of `flag_len`.
    pub fn merge_gfids_entries(
        existing: &[GfidsEntry],
        new_rvas: &[u32],
        oep_rva: u32,
        flag_len: usize,
    ) -> Result<Vec<GfidsEntry>, FormatError> {
        if flag_len > IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK as usize {
            return Err(FormatError::Invalid("GFIDS flag-byte count exceeds 15"));
        }
        let template = existing
            .iter()
            .find(|e| e.rva == oep_rva)
            .map(|e| {
                if e.flags.len() == flag_len {
                    e.flags.clone()
                } else {
                    vec![0u8; flag_len]
                }
            })
            .unwrap_or_else(|| vec![0u8; flag_len]);
        let mut out = existing.to_vec();
        let mut seen: std::collections::BTreeSet<u32> = out.iter().map(|e| e.rva).collect();
        for &rva in new_rvas {
            if seen.insert(rva) {
                out.push(GfidsEntry {
                    rva,
                    flags: template.clone(),
                });
            }
        }
        out.sort_by_key(|e| e.rva);
        Ok(out)
    }

    pub fn tls_callbacks_present(&self, bytes: &[u8]) -> Result<bool, FormatError> {
        Ok(self.tls_first_callback(bytes)?.is_some())
    }

    /// Preferred-base VA → RVA. Non-standard producers store an RVA (or a
    /// zero-ImageBase VA) in the VA-typed TLS fields; instead of asserting
    /// `va >= image_base`, fall back to reading the field itself as an RVA
    /// and let `file_offset_of` decide whether the target is a mapped,
    /// file-backed location.
    fn va_to_rva(&self, va: u64, what: &'static str) -> Result<u32, FormatError> {
        if let Some(delta) = va.checked_sub(self.image_base) {
            if delta <= u32::MAX as u64 {
                return Ok(delta as u32);
            }
        }
        if va <= u32::MAX as u64 {
            return Ok(va as u32);
        }
        Err(FormatError::Invalid(what))
    }

    /// First `PIMAGE_TLS_CALLBACK` RVA and the file offset of that slot.
    /// The slot is a preferred-base VA that the system DIR64 reloc will fix up.
    pub fn tls_first_callback(&self, bytes: &[u8]) -> Result<Option<(u32, usize)>, FormatError> {
        let dir = match self.directory(IMAGE_DIRECTORY_ENTRY_TLS) {
            Some(d) if d.rva != 0 && d.size >= 40 => d,
            _ => return Ok(None),
        };
        let off = self.file_offset_of(dir.rva)?;
        let callbacks_va = read_u64(bytes, off + 24)?;
        if callbacks_va == 0 {
            return Ok(None);
        }
        let array_rva = self.va_to_rva(callbacks_va, "TLS callback array VA")?;
        let slot_off = self.file_offset_of(array_rva)?;
        let first = read_u64(bytes, slot_off)?;
        if first == 0 {
            return Ok(None);
        }
        let first_rva = self.va_to_rva(first, "TLS callback VA")?;
        // Bounds check folded into the existing file-offset logic: garbage
        // targets fail closed, real ones (VA or RVA-shaped) pass.
        self.file_offset_of(first_rva)?;
        Ok(Some((first_rva, slot_off)))
    }

    pub fn relocs(&self, bytes: &[u8]) -> Result<Vec<RelocEntry>, FormatError> {
        let dir = match self.directory(IMAGE_DIRECTORY_ENTRY_BASERELOC) {
            Some(d) if d.rva != 0 && d.size >= 8 => d,
            _ => return Ok(Vec::new()),
        };
        let mut out = Vec::new();
        let mut consumed = 0u32;
        while consumed + 8 <= dir.size {
            let block_off = self.file_offset_of(dir.rva + consumed)?;
            let page_rva = read_u32(bytes, block_off)?;
            let block_size = read_u32(bytes, block_off + 4)?;
            if block_size < 8 {
                break;
            }
            let count = ((block_size - 8) / 2) as usize;
            for i in 0..count {
                let entry = read_u16(bytes, block_off + 8 + i * 2)?;
                let kind = entry >> 12;
                let ofs = entry & 0x0fff;
                if kind != 0 {
                    out.push(RelocEntry {
                        rva: page_rva.saturating_add(ofs as u32),
                        kind,
                    });
                }
            }
            consumed = consumed.saturating_add(block_size);
            if block_size == 0 {
                break;
            }
        }
        Ok(out)
    }

    pub fn set_entry_rva(&self, bytes: &mut [u8], rva: u32) -> Result<(), FormatError> {
        write_u32(bytes, self.optional_offset + 16, rva)
    }

    pub fn set_size_of_image(&self, bytes: &mut [u8], size: u32) -> Result<(), FormatError> {
        write_u32(bytes, self.optional_offset + 56, size)
    }

    pub fn set_number_of_sections(&self, bytes: &mut [u8], count: u16) -> Result<(), FormatError> {
        write_u16(bytes, self.file_header_offset + 2, count)
    }

    pub fn set_size_of_headers(&self, bytes: &mut [u8], size: u32) -> Result<(), FormatError> {
        write_u32(bytes, self.optional_offset + 60, size)
    }

    pub fn set_directory(
        &self,
        bytes: &mut [u8],
        index: usize,
        rva: u32,
        size: u32,
    ) -> Result<(), FormatError> {
        let dir_off = self.optional_offset + 112 + index * 8;
        write_u32(bytes, dir_off, rva)?;
        write_u32(bytes, dir_off + 4, size)?;
        Ok(())
    }

    pub fn set_dll_characteristics(&self, bytes: &mut [u8], value: u16) -> Result<(), FormatError> {
        write_u16(bytes, self.optional_offset + 70, value)
    }

    pub fn set_characteristics(&self, bytes: &mut [u8], value: u16) -> Result<(), FormatError> {
        write_u16(bytes, self.file_header_offset + 18, value)
    }

    pub fn zero_directory(&self, bytes: &mut [u8], index: usize) -> Result<(), FormatError> {
        let dir_off = self.optional_offset + 112 + index * 8;
        write_u32(bytes, dir_off, 0)?;
        write_u32(bytes, dir_off + 4, 0)?;
        Ok(())
    }

    pub fn write_section_header(&self, bytes: &mut [u8], index: usize, section: &Section) -> Result<(), FormatError> {
        let o = self.section_table_offset + index * 40;
        let name = bytes.get_mut(o..o + 8).ok_or(FormatError::Truncated)?;
        name.copy_from_slice(&section.name);
        write_u32(bytes, o + 8, section.virtual_size)?;
        write_u32(bytes, o + 12, section.virtual_address)?;
        write_u32(bytes, o + 16, section.raw_size)?;
        write_u32(bytes, o + 20, section.raw_ptr)?;
        write_u32(bytes, o + 24, 0)?;
        write_u32(bytes, o + 28, 0)?;
        write_u16(bytes, o + 32, 0)?;
        write_u16(bytes, o + 34, 0)?;
        write_u32(bytes, o + 36, section.characteristics)?;
        Ok(())
    }

    /// JavaShroud host measurement / key / dialect data sections. Plain input
    /// data: never sealed, never reused as injected stub/payload names.
    pub fn is_host_measurement_section(name: &str) -> bool {
        matches!(name, ".jsms" | ".jsmk" | ".jsmd")
    }

    pub fn forbidden_section_name(name: &str) -> bool {
        matches!(
            name,
            "UPX0" | "UPX1" | "UPX2" | ".packed" | ".chmrt" | ".chmvm" | ".jsms"
                | ".jsmk" | ".jsmd" | ".nsp0"
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OPTIONAL_OFF: usize = 0x58;
    const SECTION_TABLE_OFF: usize = OPTIONAL_OFF + 240; // 0x148
    const RVA_BASE: u32 = 0x1000;
    const RAW_BASE: usize = 0x400;

    /// Minimal x64 PE EXE with `num_sections` zero-filled section headers
    /// (raw_size 0) and a content area at file offset RAW_BASE ↔ RVA_BASE.
    fn pe64_image(num_sections: u16) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(b"MZ");
        b.resize(0x40, 0);
        b[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        b.extend_from_slice(b"PE\0\0");
        // File header.
        b.extend_from_slice(&IMAGE_FILE_MACHINE_AMD64.to_le_bytes());
        b.extend_from_slice(&num_sections.to_le_bytes());
        b.extend_from_slice(&[0u8; 12]); // timestamp, symtab ptr, sym count
        b.extend_from_slice(&240u16.to_le_bytes()); // size_of_optional
        b.extend_from_slice(&0x0022u16.to_le_bytes()); // EXE characteristics
        // Optional header.
        let opt = b.len();
        assert_eq!(opt, OPTIONAL_OFF);
        b.extend_from_slice(&IMAGE_NT_OPTIONAL_HDR64_MAGIC.to_le_bytes());
        b.resize(opt + 16, 0);
        b.extend_from_slice(&0u32.to_le_bytes()); // entry rva (+16)
        b.resize(opt + 24, 0); // +20 BaseOfCode (obsolete in PE32+)
        b.extend_from_slice(&0x140000000u64.to_le_bytes()); // image base (+24)
        b.resize(opt + 32, 0);
        b.extend_from_slice(&0x1000u32.to_le_bytes()); // section align (+32)
        b.extend_from_slice(&0x200u32.to_le_bytes()); // file align (+36)
        b.resize(opt + 56, 0);
        b.extend_from_slice(&0x10000u32.to_le_bytes()); // size_of_image (+56)
        b.extend_from_slice(&0x1200u32.to_le_bytes()); // size_of_headers (+60)
        b.resize(opt + 70, 0);
        b.extend_from_slice(&0u16.to_le_bytes()); // dll characteristics (+70)
        b.resize(opt + 108, 0);
        b.extend_from_slice(&16u32.to_le_bytes()); // NumberOfRvaAndSizes (+108)
        for _ in 0..16 {
            b.extend_from_slice(&[0u8; 8]); // data directories
        }
        // Section table.
        for _ in 0..num_sections {
            b.extend_from_slice(&[0u8; 8]); // name
            b.extend_from_slice(&0x1000u32.to_le_bytes()); // virtual size
            b.extend_from_slice(&RVA_BASE.to_le_bytes()); // virtual address
            b.extend_from_slice(&0u32.to_le_bytes()); // raw size
            b.extend_from_slice(&0u32.to_le_bytes()); // raw ptr
            b.extend_from_slice(&[0u8; 12]);
            b.extend_from_slice(&0x6000_0020u32.to_le_bytes()); // characteristics
        }
        while b.len() < RAW_BASE {
            b.push(0);
        }
        b
    }

    fn set_section(img: &mut [u8], idx: usize, vsize: u32, va: u32, rawsize: u32, rawptr: u32) {
        let o = SECTION_TABLE_OFF + idx * SECTION_HEADER_SIZE;
        img[o + 8..o + 12].copy_from_slice(&vsize.to_le_bytes());
        img[o + 12..o + 16].copy_from_slice(&va.to_le_bytes());
        img[o + 16..o + 20].copy_from_slice(&rawsize.to_le_bytes());
        img[o + 20..o + 24].copy_from_slice(&rawptr.to_le_bytes());
    }

    fn set_dir(img: &mut [u8], idx: usize, rva: u32, size: u32) {
        let o = OPTIONAL_OFF + 112 + idx * 8;
        img[o..o + 4].copy_from_slice(&rva.to_le_bytes());
        img[o + 4..o + 8].copy_from_slice(&size.to_le_bytes());
    }

    fn wr32(img: &mut [u8], off: usize, v: u32) {
        img[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }

    fn wr64(img: &mut [u8], off: usize, v: u64) {
        img[off..off + 8].copy_from_slice(&v.to_le_bytes());
    }

    /// rva → file offset inside the fixture's single section.
    fn fo(rva: u32) -> usize {
        RAW_BASE + (rva - RVA_BASE) as usize
    }

    #[test]
    fn rejects_non_pe() {
        assert!(Pe64::parse(b"not a pe").is_err());
    }

    #[test]
    fn accepts_ordinal_imports() {
        let mut img = pe64_image(1);
        set_section(&mut img, 0, 0x200, RVA_BASE, 0x200, RAW_BASE as u32);
        img.resize(RAW_BASE + 0x200, 0);
        // One descriptor + terminator at RVA 0x1000.
        let d = fo(0x1000);
        wr32(&mut img, d, 0x1080); // OriginalFirstThunk
        wr32(&mut img, d + 12, 0x1100); // DLL name
        wr32(&mut img, d + 16, 0x10a0); // FirstThunk (IAT)
        wr32(&mut img, d + 20, 0); // terminator
        // Thunk: one ordinal import (0x42), then NUL. IAT mirrors it.
        wr64(&mut img, fo(0x1080), 0x8000_0000_0000_0042);
        wr64(&mut img, fo(0x1088), 0);
        wr64(&mut img, fo(0x10a0), 0x8000_0000_0000_0042);
        wr64(&mut img, fo(0x10a8), 0);
        img[fo(0x1100)..fo(0x1100) + 8].copy_from_slice(b"FOO.DLL\0");
        set_dir(&mut img, IMAGE_DIRECTORY_ENTRY_IMPORT, 0x1000, 40);

        let pe = Pe64::parse(&img).unwrap();
        let imports = pe.imports(&img).unwrap();
        assert_eq!(imports.len(), 1, "ordinal import must be listed, not rejected");
        assert_eq!(imports[0].dll, "FOO.DLL");
        assert_eq!(imports[0].name, "", "ordinal imports carry no name string");
        assert_eq!(imports[0].ordinal, Some(0x42));
        assert_eq!(imports[0].iat_rva, 0x10a0);
        // Only the DLL name is a scrub target; an ordinal slot has no
        // hint/name bytes.
        let locs = pe.import_name_locations(&img).unwrap();
        assert_eq!(locs, vec![(0x1100, 8)]);
    }

    #[test]
    fn accepts_mixed_name_and_ordinal_thunks() {
        let mut img = pe64_image(1);
        set_section(&mut img, 0, 0x400, RVA_BASE, 0x400, RAW_BASE as u32);
        img.resize(RAW_BASE + 0x400, 0);
        let d = fo(0x1000);
        wr32(&mut img, d, 0x1080);
        wr32(&mut img, d + 12, 0x1100);
        wr32(&mut img, d + 16, 0x10a0);
        wr32(&mut img, d + 20, 0);
        // thunk[0]: by name ("Bar"), thunk[1]: ordinal 0x7, thunk[2]: NUL.
        wr64(&mut img, fo(0x1080), 0x1200);
        wr64(&mut img, fo(0x1088), 0x8000_0000_0000_0007);
        wr64(&mut img, fo(0x1090), 0);
        wr64(&mut img, fo(0x10a0), 0x1200);
        wr64(&mut img, fo(0x10a8), 0x8000_0000_0000_0007);
        wr64(&mut img, fo(0x10b0), 0);
        img[fo(0x1100)..fo(0x1100) + 8].copy_from_slice(b"FOO.DLL\0");
        // hint(2) + "Bar" + NUL at RVA 0x1200.
        img[fo(0x1200)..fo(0x1200) + 6].copy_from_slice(&[0, 0, b'B', b'a', b'r', 0]);
        set_dir(&mut img, IMAGE_DIRECTORY_ENTRY_IMPORT, 0x1000, 40);

        let pe = Pe64::parse(&img).unwrap();
        let imports = pe.imports(&img).unwrap();
        assert_eq!(imports.len(), 2);
        assert_eq!(imports[0].name, "Bar");
        assert_eq!(imports[0].ordinal, None);
        assert_eq!(imports[0].iat_rva, 0x10a0);
        assert_eq!(imports[1].name, "");
        assert_eq!(imports[1].ordinal, Some(7));
        assert_eq!(imports[1].iat_rva, 0x10a8);
    }

    #[test]
    fn read_cstr_is_lossy_over_ansi_bytes() {
        let mut img = pe64_image(1);
        set_section(&mut img, 0, 0x400, RVA_BASE, 0x400, RAW_BASE as u32);
        img.resize(RAW_BASE + 0x400, 0);
        // 0xFF/0xFE/0x81 are never valid UTF-8 — real localized exports
        // (GBK/Shift-JIS/cp1252) carry such ANSI byte strings.
        img[fo(0x1200)..fo(0x1200) + 4].copy_from_slice(&[0xff, 0xfe, 0x81, 0]);
        let pe = Pe64::parse(&img).unwrap();
        let name = pe.read_cstr(&img, 0x1200).unwrap();
        assert_eq!(
            name.chars().filter(|&c| c == '\u{fffd}').count(),
            3,
            "lossy decode keeps the bytes, no error"
        );
    }

    #[test]
    fn read_cstr_bounded_beyond_4096() {
        let mut img = pe64_image(1);
        set_section(&mut img, 0, 0x2000, RVA_BASE, 0x2000, RAW_BASE as u32);
        img.resize(RAW_BASE + 0x2000, 0);
        for off in fo(0x1200)..fo(0x1200) + Pe64::MAX_NAME_BYTES + 8 {
            img[off] = b'a';
        }
        let pe = Pe64::parse(&img).unwrap();
        let err = pe.read_cstr(&img, 0x1200).unwrap_err();
        assert!(err.to_string().contains("string too long"), "{err}");
    }

    #[test]
    fn accepts_more_than_96_sections_when_table_fits() {
        let img = pe64_image(100);
        let pe = Pe64::parse(&img).unwrap();
        assert_eq!(pe.number_of_sections, 100);
        // A table running past EOF is still truncated.
        let short = img[..SECTION_TABLE_OFF + 99 * SECTION_HEADER_SIZE].to_vec();
        assert!(Pe64::parse(&short).is_err());
    }

    #[test]
    fn data_directory_count_is_clamped_not_rejected() {
        let mut img = pe64_image(1);
        let o = OPTIONAL_OFF + 108;
        wr32(&mut img, o, 0xffff_ffff);
        let pe = Pe64::parse(&img).unwrap();
        assert_eq!(pe.directories.len(), 16);
    }

    #[test]
    fn raw_tail_past_eof_is_clamped_like_the_loader() {
        let mut img = pe64_image(1);
        // Section claims 64 KiB of raw data; the file ends at 0x600 (the
        // loader maps the 0x200 backed bytes and zero-fills the rest).
        set_section(&mut img, 0, 0x1000, RVA_BASE, 0x10000, RAW_BASE as u32);
        img.resize(RAW_BASE + 0x200, 0);
        let pe = Pe64::parse(&img).unwrap();
        assert_eq!(pe.sections[0].raw_size, 0x200, "raw_size clamped to EOF");
        // Reads inside the zero-fill tail fail with the specific bound.
        match pe.file_offset_of(RVA_BASE + 0x300) {
            Err(FormatError::Invalid(m)) => assert_eq!(m, "rva outside raw data"),
            other => panic!("expected bounded read failure, got {other:?}"),
        }
    }

    #[test]
    fn raw_pointer_wholly_past_eof_is_truncated() {
        let mut img = pe64_image(1);
        set_section(&mut img, 0, 0x1000, RVA_BASE, 0x100, 0x10000);
        match Pe64::parse(&img) {
            Err(FormatError::Truncated) => {}
            other => panic!("expected Truncated, got {other:?}"),
        }
    }

    #[test]
    fn tls_rva_fallback_when_va_below_image_base() {
        let mut img = pe64_image(1);
        set_section(&mut img, 0, 0x200, RVA_BASE, 0x200, RAW_BASE as u32);
        img.resize(RAW_BASE + 0x200, 0);
        // AddressOfCallBacks holding a plain RVA (non-standard producer)
        // while ImageBase is 0x140000000: the regular VA→RVA conversion
        // underflows, so the field is re-read as an RVA.
        wr64(&mut img, fo(0x1000) + 24, 0x1080);
        // First callback slot: a proper preferred-base VA inside the section.
        wr64(&mut img, fo(0x1080), 0x140001080);
        set_dir(&mut img, IMAGE_DIRECTORY_ENTRY_TLS, 0x1000, 64);

        let pe = Pe64::parse(&img).unwrap();
        assert_eq!(
            pe.tls_first_callback(&img).unwrap(),
            Some((0x1080, fo(0x1080)))
        );
        // A callback target outside any section still fails closed.
        wr64(&mut img, fo(0x1080), 0x1400dead);
        assert!(pe.tls_first_callback(&img).is_err());
    }

    /// GuardFlags live at IMAGE_LOAD_CONFIG_DIRECTORY64 +0x90 on a modern
    /// Size>=0x94 config. The previous +0x88 DWORD read was GuardCFFunctionCount
    /// (where.exe 8, tasklist.exe 0x10, curl.exe 0x187). Samples are session
    /// artifacts in out/real-samples; absent samples skip rather than fail
    /// gates on machines that never collected them.
    #[test]
    #[cfg(windows)]
    fn load_config_guard_flags_match_measured_layouts() {
        let anchors = [
            ("where.exe", 0x0041_7500u32, 8u64, 4usize),
            ("tasklist.exe", 0x0041_7500u32, 0x10u64, 4usize),
            ("curl.exe", 0x1001_7500u32, 0x187u64, 5usize),
        ];
        for (name, expected_flags, expected_count, expected_stride) in anchors {
            let bytes = ["out/real-samples", "../../out/real-samples"]
                .iter()
                .find_map(|d| std::fs::read(format!("{d}/{name}")).ok());
            let Some(bytes) = bytes else {
                eprintln!("SKIP: {name} not present in out/real-samples");
                continue;
            };
            let pe = Pe64::parse(&bytes).unwrap();
            assert!(pe.load_config_present(), "{name} has a load config");
            let flags = pe
                .load_config_guard_flags(&bytes)
                .expect("load config parse")
                .unwrap_or_else(|| panic!("{name} GuardFlags must be readable"));
            assert_eq!(flags, expected_flags, "{name} layout-parsed GuardFlags");
            let cfg = pe
                .load_config_cfg(&bytes)
                .expect("cfg parse")
                .expect("cfg present");
            assert_eq!(cfg.function_count, expected_count, "{name} GFIDS count");
            assert_eq!(Pe64::gfids_stride(cfg.guard_flags), expected_stride);
            assert_eq!(
                cfg.guard_flags & IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT,
                IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT
            );
            let table = pe.gfids_table(&bytes, &cfg).expect("gfids");
            assert_eq!(table.len() as u64, expected_count);
            assert!(
                table.windows(2).all(|w| w[0].rva <= w[1].rva),
                "{name} GFIDS must be sorted by RVA"
            );
            assert!(
                table.iter().any(|e| e.rva == pe.entry_rva),
                "{name} OEP {:#x} must be in GFIDS",
                pe.entry_rva
            );
        }
    }

    #[test]
    fn load_config_guard_flags_absent_or_undeclared_is_none() {
        // No load config directory at all.
        let img = pe64_image(1);
        let pe = Pe64::parse(&img).unwrap();
        assert_eq!(pe.load_config_guard_flags(&img).unwrap(), None);
        // Directory present but the declared config does not reach GuardFlags
        // at +0x90: None, not a guessed 0.
        let mut img = pe64_image(1);
        set_section(&mut img, 0, 0x200, RVA_BASE, 0x200, RAW_BASE as u32);
        img.resize(RAW_BASE + 0x200, 0);
        wr32(&mut img, fo(0x1000), 0x10); // declared Size smaller than any layout
        set_dir(&mut img, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, 0x1000, 0x40);
        let pe = Pe64::parse(&img).unwrap();
        assert_eq!(pe.load_config_guard_flags(&img).unwrap(), None);
    }

    fn plant_load_config_cfg(
        img: &mut Vec<u8>,
        cfg_rva: u32,
        table_rva: u32,
        count: u64,
        flags: u32,
        entries: &[(u32, &[u8])],
    ) {
        set_section(img, 0, 0x400, RVA_BASE, 0x400, RAW_BASE as u32);
        img.resize(RAW_BASE + 0x400, 0);
        let cfg_off = fo(cfg_rva);
        wr32(img, cfg_off, 0x140); // modern Size, reaches +0x90
        wr64(img, cfg_off + LOAD_CONFIG64_GUARD_CF_FUNCTION_TABLE, 0x140000000 + table_rva as u64);
        wr64(img, cfg_off + LOAD_CONFIG64_GUARD_CF_FUNCTION_COUNT, count);
        wr32(img, cfg_off + LOAD_CONFIG64_GUARD_FLAGS, flags);
        set_dir(img, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, cfg_rva, 0x140);
        let stride = Pe64::gfids_stride(flags);
        let mut cur = fo(table_rva);
        for (rva, extra) in entries {
            wr32(img, cur, *rva);
            img[cur + 4..cur + stride].copy_from_slice(extra);
            cur += stride;
        }
    }

    #[test]
    fn gfids_table_round_trip_stride4_and_stride5() {
        // stride 4: extra nibble 0 (where.exe / tasklist.exe layout).
        let mut img = pe64_image(1);
        plant_load_config_cfg(
            &mut img,
            0x1000,
            0x1200,
            3,
            IMAGE_GUARD_CF_INSTRUMENTED | IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT,
            &[(0x1010, &[]), (0x1300, &[]), (0x1850, &[])],
        );
        let pe = Pe64::parse(&img).unwrap();
        let cfg = pe.load_config_cfg(&img).unwrap().unwrap();
        assert_eq!(Pe64::gfids_stride(cfg.guard_flags), 4);
        let table = pe.gfids_table(&img, &cfg).unwrap();
        assert_eq!(
            table.iter().map(|e| e.rva).collect::<Vec<_>>(),
            vec![0x1010, 0x1300, 0x1850]
        );
        let merged = Pe64::merge_gfids_entries(&table, &[0x2000, 0x1300], 0x1300, 0).unwrap();
        assert_eq!(
            merged.iter().map(|e| e.rva).collect::<Vec<_>>(),
            vec![0x1010, 0x1300, 0x1850, 0x2000]
        );
        let encoded = Pe64::encode_gfids_table(&merged, 0).unwrap();
        assert_eq!(encoded.len(), 16);
        assert_eq!(&encoded[12..16], &0x2000u32.to_le_bytes());

        // stride 5: extra nibble 1 (curl.exe layout). New entries inherit OEP flags.
        let mut img = pe64_image(1);
        plant_load_config_cfg(
            &mut img,
            0x1000,
            0x1200,
            2,
            IMAGE_GUARD_CF_INSTRUMENTED
                | IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT
                | (1 << IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT),
            &[(0x1010, &[0x00]), (0x1300, &[0xAB])],
        );
        let pe = Pe64::parse(&img).unwrap();
        let cfg = pe.load_config_cfg(&img).unwrap().unwrap();
        assert_eq!(Pe64::gfids_stride(cfg.guard_flags), 5);
        let table = pe.gfids_table(&img, &cfg).unwrap();
        assert_eq!(table[1].flags, vec![0xAB]);
        let merged = Pe64::merge_gfids_entries(&table, &[0x1400], 0x1300, 1).unwrap();
        assert_eq!(merged[2].rva, 0x1400);
        assert_eq!(merged[2].flags, vec![0xAB], "new entry copies OEP flags");
        let encoded = Pe64::encode_gfids_table(&merged, 1).unwrap();
        assert_eq!(encoded.len(), 15);
        assert_eq!(encoded[14], 0xAB);
    }

    #[test]
    fn gfids_xfg_and_missing_table_present_fail_closed() {
        let mut img = pe64_image(1);
        plant_load_config_cfg(
            &mut img,
            0x1000,
            0x1200,
            1,
            IMAGE_GUARD_CF_INSTRUMENTED
                | IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT
                | IMAGE_GUARD_XFG_ENABLED,
            &[(0x1010, &[])],
        );
        let pe = Pe64::parse(&img).unwrap();
        let cfg = pe.load_config_cfg(&img).unwrap().unwrap();
        let err = pe.gfids_table(&img, &cfg).unwrap_err();
        assert!(
            err.to_string().contains("IMAGE_GUARD_XFG_ENABLED"),
            "{err}"
        );

        let mut img = pe64_image(1);
        plant_load_config_cfg(
            &mut img,
            0x1000,
            0x1200,
            1,
            IMAGE_GUARD_CF_INSTRUMENTED, // no FUNCTION_TABLE_PRESENT
            &[(0x1010, &[])],
        );
        let pe = Pe64::parse(&img).unwrap();
        let cfg = pe.load_config_cfg(&img).unwrap().unwrap();
        let err = pe.gfids_table(&img, &cfg).unwrap_err();
        assert!(
            err.to_string()
                .contains("IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT"),
            "{err}"
        );
    }

    #[test]
    fn gfids_table_overrun_and_count_cap_fail_closed() {
        let mut img = pe64_image(1);
        // Count that would walk past the 0x400 raw section.
        plant_load_config_cfg(
            &mut img,
            0x1000,
            0x13f0,
            16,
            IMAGE_GUARD_CF_INSTRUMENTED | IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT,
            &[(0x1010, &[])],
        );
        let pe = Pe64::parse(&img).unwrap();
        let cfg = pe.load_config_cfg(&img).unwrap().unwrap();
        assert!(pe.gfids_table(&img, &cfg).is_err());

        let mut img = pe64_image(1);
        plant_load_config_cfg(
            &mut img,
            0x1000,
            0x1200,
            MAX_GFIDS_ENTRIES + 1,
            IMAGE_GUARD_CF_INSTRUMENTED | IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT,
            &[(0x1010, &[])],
        );
        let pe = Pe64::parse(&img).unwrap();
        let cfg = pe.load_config_cfg(&img).unwrap().unwrap();
        let err = pe.gfids_table(&img, &cfg).unwrap_err();
        assert!(err.to_string().contains("MAX_GFIDS_ENTRIES"), "{err}");
    }
}
