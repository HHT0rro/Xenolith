//! Fail-closed parsers for Xenolith inputs.
//!
//! PE64 AMD64 and ELF64 AMD64 parsers. ELF is parsed for real; packing an ELF
//! still fails closed until the G3 injected bootstrap exists.

pub mod elf;
mod pe;

pub use pe::{
    DataDirectory, ExportSymbol, GfidsEntry, ImportSymbol, LoadConfigCfg, Pe64, PeKind, Section,
    IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR,
    IMAGE_DIRECTORY_ENTRY_DEBUG, IMAGE_DIRECTORY_ENTRY_EXPORT,
    IMAGE_DIRECTORY_ENTRY_SECURITY,
    IMAGE_DLLCHARACTERISTICS_GUARD_CF, IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA,
    IMAGE_FILE_RELOCS_STRIPPED, IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT,
    IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK, IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT,
    IMAGE_GUARD_CF_INSTRUMENTED, IMAGE_GUARD_XFG_ENABLED, MAX_GFIDS_ENTRIES,
    IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT, IMAGE_DIRECTORY_ENTRY_EXCEPTION,
    IMAGE_DIRECTORY_ENTRY_IAT, IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG,
    IMAGE_DIRECTORY_ENTRY_TLS,
    IMAGE_REL_BASED_DIR64, RelocEntry,
    IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE, IMAGE_FILE_DLL, IMAGE_SCN_CNT_CODE,
    IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE,
    LOAD_CONFIG64_GUARD_CF_CHECK_FUNCTION_POINTER,
    LOAD_CONFIG64_GUARD_CF_DISPATCH_FUNCTION_POINTER,
    LOAD_CONFIG64_GUARD_CF_FUNCTION_COUNT, LOAD_CONFIG64_GUARD_CF_FUNCTION_TABLE,
    LOAD_CONFIG64_GUARD_FLAGS, LOAD_CONFIG64_GUARD_FLAGS_SIZE,
};

use thiserror::Error;

/// Upper bound on any input image. Large runtimes, unstripped game and
/// Electron-class binaries comfortably exceed 64 MiB; 512 MiB keeps a DoS
/// bound without rejecting legitimate real-world images.
pub const MAX_IMAGE: usize = 512 * 1024 * 1024;
pub const PAGE: u32 = 0x1000;

#[derive(Debug, Error)]
pub enum FormatError {
    #[error("image is empty or truncated")]
    Truncated,
    #[error("image exceeds the {MAX_IMAGE} byte bound")]
    TooLarge,
    #[error("{0}")]
    Invalid(&'static str),
    #[error("ELF shared objects are not packed in this release")]
    ElfNotImplemented,
    #[error("{0}")]
    ElfUnsupported(&'static str),
    #[error("only Windows x86_64 PE DLL/EXE is accepted")]
    Unsupported,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImageKind {
    Pe64Dll,
    Pe64Exe,
    Elf64Exec,
    Elf64Dyn,
}

pub fn classify(bytes: &[u8]) -> Result<ImageKind, FormatError> {
    if bytes.len() > MAX_IMAGE {
        return Err(FormatError::TooLarge);
    }
    if bytes.len() >= 4 && bytes.starts_with(b"\x7fELF") {
        return Ok(elf::parse(bytes)?.kind);
    }
    let pe = Pe64::parse(bytes)?;
    match pe.kind {
        PeKind::Dll => Ok(ImageKind::Pe64Dll),
        PeKind::Exe => Ok(ImageKind::Pe64Exe),
    }
}

pub fn packed_output_name(input: &std::path::Path, kind: ImageKind) -> std::path::PathBuf {
    let mut out = input.to_path_buf();
    let ext = match kind {
        ImageKind::Pe64Dll => "xl.dll",
        ImageKind::Pe64Exe => "xl.exe",
        ImageKind::Elf64Dyn => "xl.so",
        ImageKind::Elf64Exec => "xl.elf",
    };
    out.set_extension(ext);
    out
}

pub use elf::Elf64;

pub fn align_up(value: u32, align: u32) -> u32 {
    if align == 0 {
        return value;
    }
    value.saturating_add(align - 1) / align * align
}

pub fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, FormatError> {
    let slice = bytes
        .get(offset..offset.saturating_add(2))
        .ok_or(FormatError::Truncated)?;
    Ok(u16::from_le_bytes([slice[0], slice[1]]))
}

pub fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, FormatError> {
    let slice = bytes
        .get(offset..offset.saturating_add(4))
        .ok_or(FormatError::Truncated)?;
    Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

pub fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, FormatError> {
    let slice = bytes
        .get(offset..offset.saturating_add(8))
        .ok_or(FormatError::Truncated)?;
    Ok(u64::from_le_bytes([
        slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
    ]))
}

pub fn write_u16(bytes: &mut [u8], offset: usize, value: u16) -> Result<(), FormatError> {
    let slice = bytes
        .get_mut(offset..offset.saturating_add(2))
        .ok_or(FormatError::Truncated)?;
    slice.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

pub fn write_u32(bytes: &mut [u8], offset: usize, value: u32) -> Result<(), FormatError> {
    let slice = bytes
        .get_mut(offset..offset.saturating_add(4))
        .ok_or(FormatError::Truncated)?;
    slice.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

pub fn write_u64(bytes: &mut [u8], offset: usize, value: u64) -> Result<(), FormatError> {
    let slice = bytes
        .get_mut(offset..offset.saturating_add(8))
        .ok_or(FormatError::Truncated)?;
    slice.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn elf_is_recognized_and_rejected() {
        let mut elf = vec![0x7f, b'E', b'L', b'F', 2, 1, 1];
        elf.resize(64, 0);
        match classify(&elf) {
            Err(FormatError::Invalid(_)) | Err(FormatError::Unsupported) => {}
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn packed_output_suffix_follows_kind() {
        use std::path::Path;
        assert_eq!(
            packed_output_name(Path::new("a.dll"), ImageKind::Pe64Dll)
                .extension()
                .unwrap(),
            "dll"
        );
        assert!(packed_output_name(Path::new("a.exe"), ImageKind::Pe64Exe)
            .file_name()
            .unwrap()
            .to_string_lossy()
            .ends_with(".xl.exe"));
        assert!(packed_output_name(Path::new("libx.so"), ImageKind::Elf64Dyn)
            .file_name()
            .unwrap()
            .to_string_lossy()
            .ends_with(".xl.so"));
        assert!(packed_output_name(Path::new("app"), ImageKind::Elf64Exec)
            .file_name()
            .unwrap()
            .to_string_lossy()
            .ends_with(".xl.elf"));
    }
}
