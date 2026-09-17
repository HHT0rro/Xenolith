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
pub const IMAGE_DIRECTORY_ENTRY_DEBUG: usize = 6;
pub const IMAGE_DIRECTORY_ENTRY_TLS: usize = 9;
pub const IMAGE_DIRECTORY_ENTRY_EXCEPTION: usize = 3;
pub const IMAGE_DIRECTORY_ENTRY_IAT: usize = 12;
pub const IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT: usize = 13;
pub const IMAGE_REL_BASED_DIR64: u16 = 10;
pub const IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE: u16 = 0x0040;
pub const IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA: u16 = 0x0020;
pub const IMAGE_FILE_RELOCS_STRIPPED: u16 = 0x0001;
pub const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
pub const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
pub const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
pub const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;
const MAX_SECTIONS: usize = 96;

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
        if number_of_sections == 0 || number_of_sections as usize > MAX_SECTIONS {
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
        let dir_count = read_u32(bytes, optional + 108)? as usize;
        if dir_count > 16 {
            return Err(FormatError::Invalid("data directory count"));
        }
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
        let mut sections = Vec::with_capacity(number_of_sections as usize);
        for i in 0..number_of_sections as usize {
            let o = section_table + i * 40;
            let mut name = [0u8; 8];
            let raw = bytes.get(o..o + 8).ok_or(FormatError::Truncated)?;
            name.copy_from_slice(raw);
            let virtual_size = read_u32(bytes, o + 8)?;
            let virtual_address = read_u32(bytes, o + 12)?;
            let raw_size = read_u32(bytes, o + 16)?;
            let raw_ptr = read_u32(bytes, o + 20)?;
            let characteristics = read_u32(bytes, o + 36)?;
            if raw_ptr as usize + raw_size as usize > bytes.len() && raw_size != 0 {
                return Err(FormatError::Truncated);
            }
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
            if out.len() > 512 {
                return Err(FormatError::Invalid("string too long"));
            }
        }
        String::from_utf8(out).map_err(|_| FormatError::Invalid("string encoding"))
    }

    pub fn exports(&self, bytes: &[u8]) -> Result<Vec<ExportSymbol>, FormatError> {
        let dir = match self.directory(IMAGE_DIRECTORY_ENTRY_EXPORT) {
            Some(d) if d.rva != 0 && d.size >= 40 => d,
            _ => return Ok(Vec::new()),
        };
        let base = self.file_offset_of(dir.rva)?;
        let ordinal_base = read_u32(bytes, base + 16)?;
        let n_functions = read_u32(bytes, base + 20)? as usize;
        let n_names = read_u32(bytes, base + 24)? as usize;
        if n_functions > 16_384 || n_names > 16_384 {
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
        if n_functions > 16_384 || n_names > 16_384 {
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

    /// TASK-024: (rva, len) of every plaintext import name string — DLL
    /// names and hint/name entries (hint u16 + name + NUL). Zeroing only the
    /// import *directory* hides it from the loader but leaves these bytes
    /// readable in the file; the packer scrubs the ranges themselves.
    pub fn import_name_locations(&self, bytes: &[u8]) -> Result<Vec<(u32, u32)>, FormatError> {
        let dir = match self.directory(IMAGE_DIRECTORY_ENTRY_IMPORT) {
            Some(d) if d.rva != 0 && d.size >= 20 => d,
            _ => return Ok(Vec::new()),
        };
        let mut desc_rva = dir.rva;
        let mut out = Vec::new();
        for _ in 0..256 {
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
            for _ in 0..4096 {
                let thunk_off = self.file_offset_of(thunk_rva)?;
                let thunk = read_u64(bytes, thunk_off)?;
                if thunk == 0 {
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
            desc_rva = desc_rva.saturating_add(20);
        }
        Ok(out)
    }

    pub fn imports(&self, bytes: &[u8]) -> Result<Vec<ImportSymbol>, FormatError> {
        let dir = match self.directory(IMAGE_DIRECTORY_ENTRY_IMPORT) {
            Some(d) if d.rva != 0 && d.size >= 20 => d,
            _ => return Ok(Vec::new()),
        };
        let mut desc_rva = dir.rva;
        let mut out = Vec::new();
        for _ in 0..256 {
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
            for _ in 0..4096 {
                let thunk_off = self.file_offset_of(thunk_rva)?;
                let thunk = read_u64(bytes, thunk_off)?;
                if thunk == 0 {
                    break;
                }
                if thunk & (1u64 << 63) == 0 {
                    let hint_name = thunk as u32;
                    let hint_off = hint_name
                        .checked_add(2)
                        .ok_or(FormatError::Invalid("hint/name rva overflow"))?;
                    let name = self.read_cstr(bytes, hint_off)?;
                    out.push(ImportSymbol {
                        dll: dll.clone(),
                        name,
                        iat_rva: iat_slot,
                        ordinal: None,
                    });
                } else {
                    return Err(FormatError::Invalid(
                        "ordinal-only import is not packed in this release",
                    ));
                }
                thunk_rva = thunk_rva.saturating_add(8);
                iat_slot = iat_slot.saturating_add(8);
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

    pub fn tls_callbacks_present(&self, bytes: &[u8]) -> Result<bool, FormatError> {
        Ok(self.tls_first_callback(bytes)?.is_some())
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
        if callbacks_va < self.image_base {
            return Err(FormatError::Invalid("TLS callback array VA"));
        }
        let array_rva = (callbacks_va - self.image_base) as u32;
        let slot_off = self.file_offset_of(array_rva)?;
        let first = read_u64(bytes, slot_off)?;
        if first == 0 {
            return Ok(None);
        }
        if first < self.image_base {
            return Err(FormatError::Invalid("TLS callback VA"));
        }
        Ok(Some(((first - self.image_base) as u32, slot_off)))
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

    #[test]
    fn rejects_non_pe() {
        assert!(Pe64::parse(b"not a pe").is_err());
    }
}
