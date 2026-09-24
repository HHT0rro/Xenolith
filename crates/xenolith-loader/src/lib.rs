//! Host-side envelope types and a test emulator.
//!
//! This crate is **not** injected into packed images. The product runtime is
//! the handwritten PIC stub in `xenolith-pack::stub`. Host comments below
//! describe the *emulator* model (C1 never-write FirstThunk, C2 four-page
//! window, C3 dump poison). Those emulator rules are **not** what `pack()`
//! currently emits: the PIC stub writes resolved VAs into original IAT slots,
//! C2 re-encrypt is unarmed, and executable pages stay plaintext after unpack.

use xenolith_crypto::{
    mix_runtime_key, random_nonce, MbaKeyShare, Secret32, NONCE_LEN,
};
use xenolith_protocol::{open_region, parse as parse_v2, EnvelopeV2, ProtocolError};
use xenolith_formats::Pe64;
use xenolith_guard::Probe;
use xenolith_vm::{run_key_mix, Program};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const ENVELOPE_VERSION: u16 = 2;
pub const MAX_PLAINTEXT_PAGES: usize = 4;
pub const STOLEN_BYTES: usize = 16;

/// Upper bound on sealed 4-KiB page records in one envelope.
///
/// The wire format counts regions in a u32 and the host emulator is fully
/// dynamic; the binding constraint is the injected core's envelope pre-scan
/// (`xl_reloc_scan` in crates/xenolith-runtime/core/xl_core.c), which walks
/// the region records with per-step bounds checks and rejects
/// `region_count > 0xffff`. Real-world monolithic binaries (libcef/Electron
/// class, 150-250 MB) carry 3-5×10⁴ executable pages, so the historical
/// 16_384 cap rejected them all; the limit now sits exactly at what the
/// core accepts.
pub const MAX_PAGES: usize = 65_535;

/// Region states the injected core can track for the G5 lazy-region
/// lifecycle (fault-wake / quiesce re-seal): `XlRegionTable.st[]` in
/// crates/xenolith-runtime/core/xl_core.c is a fixed 64-entry array. A lazy
/// pack with more sealed regions than this would boot but never wake a
/// sealed page (the fault path rebuilds the table and fails closed), so the
/// packer refuses it up front. All-live packs are unaffected — the boot
/// decrypt walk is streaming and unbounded by this table.
pub const LAZY_REGION_STATE_MAX: usize = 64;

#[derive(Debug, Error)]
pub enum LoaderError {
    #[error("{0}")]
    Invalid(&'static str),
    #[error("integrity check failed")]
    Integrity,
    #[error("too many pages")]
    TooManyPages,
    #[error("legacy NSEN is not a v2 product")]
    LegacyV1,
    #[error("{0}")]
    Protocol(String),
}

impl From<ProtocolError> for LoaderError {
    fn from(e: ProtocolError) -> Self {
        match e {
            ProtocolError::LegacyV1 => LoaderError::LegacyV1,
            ProtocolError::Auth => LoaderError::Integrity,
            other => LoaderError::Protocol(other.to_string()),
        }
    }
}

pub fn parse_envelope(bytes: &[u8]) -> Result<EnvelopeV2, LoaderError> {
    Ok(parse_v2(bytes)?)
}

#[derive(Clone, Debug)]
pub struct PageRecord {
    pub index: u32,
    pub original_rva: u32,
    pub original_len: u32,
    pub nonce: [u8; NONCE_LEN],
    pub mac: [u8; 32],
    /// Keyed FNV-1a of the mapped bytes; the stub re-verifies (G-TAMPER).
    pub stub_digest: u32,
}

#[derive(Clone, Debug)]
pub struct HashedImport {
    pub hash: [u8; 32],
    pub original_iat_rva: u32,
    pub dll: String,
    pub name: String,
}

#[derive(Clone, Debug)]
pub struct PackedImage {
    pub profile: Profile,
    pub kind_dll: bool,
    pub original_entry_rva: u32,
    pub stolen: Vec<u8>,
    pub mba: MbaKeyShare,
    pub opcode_seed: [u8; 16],
    pub api_salt: [u8; 16],
    pub imports: Vec<HashedImport>,
    pub exports: Vec<(String, u32)>,
    pub pages: Vec<PageRecord>,
    pub probes: Vec<Probe>,
    pub program: Program,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Profile {
    Fast = 1,
    Standard = 2,
    Max = 3,
}

impl Profile {
    pub fn parse(value: &str) -> Result<Self, LoaderError> {
        match value {
            "fast" => Ok(Self::Fast),
            "standard" => Ok(Self::Standard),
            "max" => Ok(Self::Max),
            _ => Err(LoaderError::Invalid("unknown profile")),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fast => "fast",
            Self::Standard => "standard",
            Self::Max => "max",
        }
    }
}

#[derive(Clone)]
pub struct RuntimeState {
    pub runtime_key: Secret32,
    pub live_pages: Vec<u32>,
    pub import_slots: Vec<u64>,
    pub poisoned_header: bool,
}

impl PackedImage {
    pub fn activate(&self, measurement: &[u8; 32]) -> Result<RuntimeState, LoaderError> {
        let runtime_key = mix_runtime_key(&self.mba, measurement).map_err(|_| LoaderError::Integrity)?;
        let _ = run_key_mix(&self.program, measurement);
        Ok(RuntimeState {
            runtime_key,
            live_pages: Vec::new(),
            import_slots: vec![0; self.imports.len()],
            poisoned_header: false,
        })
    }

    pub fn open_envelope_region(
        &self,
        state: &RuntimeState,
        env: &EnvelopeV2,
        page_index: u32,
    ) -> Result<Vec<u8>, LoaderError> {
        let region = env
            .regions
            .iter()
            .find(|r| r.index == page_index)
            .ok_or(LoaderError::Invalid("missing page"))?;
        Ok(open_region(&state.runtime_key, env, region)?)
    }

    pub fn open_page(
        &self,
        state: &mut RuntimeState,
        page_index: u32,
        _measurement: &[u8; 32],
    ) -> Result<Vec<u8>, LoaderError> {
        let page = self
            .pages
            .iter()
            .find(|p| p.index == page_index)
            .ok_or(LoaderError::Invalid("missing page"))?;
        if page.mac[..16].iter().all(|b| *b == 0) {
            return Err(LoaderError::Integrity);
        }
        if !state.live_pages.contains(&page_index) {
            if state.live_pages.len() >= MAX_PLAINTEXT_PAGES {
                state.live_pages.remove(0);
            }
            state.live_pages.push(page_index);
        }
        Err(LoaderError::Invalid(
            "host emulator must open EnvelopeV2 via open_envelope_region",
        ))
    }
}

pub fn steal_entry_bytes(image: &[u8], pe: &Pe64) -> Result<Vec<u8>, LoaderError> {
    let off = pe
        .file_offset_of(pe.entry_rva)
        .map_err(|_| LoaderError::Invalid("entry rva"))?;
    let end = (off + STOLEN_BYTES).min(image.len());
    Ok(image[off..end].to_vec())
}

pub fn fresh_nonce() -> [u8; NONCE_LEN] {
    random_nonce()
}

pub fn section_name_from_seed(seed: &[u8], index: u8) -> [u8; 8] {
    let mut hasher = Sha256::new();
    hasher.update(b"XLSECT");
    hasher.update(seed);
    hasher.update([index]);
    let d = hasher.finalize();
    let mut name = [0u8; 8];
    name[0] = b'.';
    for i in 0..6 {
        name[i + 1] = b'a' + (d[i] % 26);
    }
    let s = std::str::from_utf8(&name).unwrap_or(".xxxxxx");
    let trimmed = s.trim_end_matches('\0');
    // Never collide with host measurement sections or foreign packer names.
    if Pe64::forbidden_section_name(trimmed) || Pe64::is_host_measurement_section(trimmed) {
        name[1] = b'z';
    }
    name
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn max_plaintext_pages_is_small() {
        assert!(MAX_PLAINTEXT_PAGES <= 4);
    }

    #[test]
    fn forbidden_section_names_are_rejected() {
        assert!(Pe64::forbidden_section_name("UPX0"));
        assert!(Pe64::forbidden_section_name(".packed"));
        assert!(Pe64::forbidden_section_name(".jsms"));
        assert!(Pe64::forbidden_section_name(".jsmk"));
        assert!(Pe64::forbidden_section_name(".jsmd"));
        assert!(Pe64::is_host_measurement_section(".jsms"));
        assert!(Pe64::is_host_measurement_section(".jsmk"));
        assert!(Pe64::is_host_measurement_section(".jsmd"));
    }

    #[test]
    fn host_parser_rejects_legacy_nsen() {
        let mut old = b"NSEN".to_vec();
        old.resize(64, 0);
        assert!(matches!(parse_envelope(&old), Err(LoaderError::LegacyV1)));
    }
}
