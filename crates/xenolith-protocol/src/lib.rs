//! EnvelopeV2: the production on-disk contract.
//!
//! v1 `NSEN` + XOR + FNV is a fixture only. `parse()` rejects it. There is no
//! silent compatibility decode.

use xenolith_crypto::{
    aead_open, aead_seal, random_nonce12, AeadError, Secret32, AEAD_NONCE_LEN, AEAD_TAG_LEN,
    PAGE_SIZE,
};
use thiserror::Error;

pub const MAGIC: &[u8; 4] = b"XLV2";
pub const VERSION: u16 = 2;
pub const LEGACY_MAGIC: &[u8; 4] = b"NSEN";

pub const PLATFORM_PE64: u8 = 0;
pub const PLATFORM_ELF64: u8 = 1;

pub const FLAG_LONG_TERM_RWX: u32 = 1 << 0;
pub const FLAG_ASLR: u32 = 1 << 1;
pub const FLAG_DECRYPT_WINDOW: u32 = 1 << 2;

pub const POLICY_STRICT: u32 = 1;

/// Fixed prefix before MBA.
pub const PREFIX_LEN: usize = 16;
pub const MBA_LEN: usize = 96;
pub const SEED_LEN: usize = 16;
pub const SALT_LEN: usize = 16;
pub const OPCODE_MAP_LEN: usize = 8;

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("truncated envelope")]
    Truncated,
    #[error("legacy NSEN/XOR+FNV is not a v2 product")]
    LegacyV1,
    #[error("unsupported envelope version")]
    Version,
    #[error("envelope field is invalid")]
    Invalid,
    #[error("authenticated data failed")]
    Auth,
    #[error(transparent)]
    Aead(#[from] AeadError),
}

#[derive(Clone, Debug)]
pub struct Region {
    pub index: u32,
    pub rva: u32,
    pub len: u32,
    pub nonce: [u8; AEAD_NONCE_LEN],
    pub ciphertext: Vec<u8>,
    pub tag: [u8; AEAD_TAG_LEN],
}

#[derive(Clone, Debug)]
pub struct ImportRec {
    pub hash: [u8; 32],
    pub iat_rva: u32,
    pub name: Vec<u8>,
    pub dll: Vec<u8>,
    /// G5/TASK-024: sealed name||dll record (nonce+tag+ct). When present the
    /// wire payload carries the sealed form; `name`/`dll` keep the plaintext
    /// (and its lengths) for pack-side bookkeeping only. Parsers that read a
    /// sealed envelope get the opaque ciphertext back in `name`.
    pub sealed: Option<ImportSealed>,
}

#[derive(Clone, Debug)]
pub struct ImportSealed {
    pub nonce: [u8; AEAD_NONCE_LEN],
    pub tag: [u8; AEAD_TAG_LEN],
    pub ciphertext: Vec<u8>,
}

/// Envelope flag: import name records are sealed (TASK-024). Only set when
/// the on-disk import directory is gone too (writeback mode); a retained
/// loader directory makes sealing the envelope copy pointless.
pub const FLAG_IMPORTS_SEALED: u32 = 0x2;

/// AAD for a sealed import record. Binds the ciphertext to its slot and the
/// exact plaintext lengths so records cannot be swapped or respliced. The
/// injected runtime mirrors this layout byte-for-byte. Lengths are passed
/// explicitly: a re-parsed sealed record carries empty plaintext fields.
pub fn import_aad(
    env: &EnvelopeV2,
    index: u32,
    iat_rva: u32,
    name_len: u16,
    dll_len: u16,
) -> [u8; 32] {
    let mut aad = [0u8; 32];
    aad[0..4].copy_from_slice(MAGIC);
    aad[4..6].copy_from_slice(&VERSION.to_le_bytes());
    aad[6] = b'I'; // domain: import record (region AAD uses platform here)
    aad[7] = env.platform;
    aad[8..12].copy_from_slice(&env.flags.to_le_bytes());
    aad[12..16].copy_from_slice(&iat_rva.to_le_bytes());
    aad[16..18].copy_from_slice(&name_len.to_le_bytes());
    aad[18..20].copy_from_slice(&dll_len.to_le_bytes());
    aad[20..24].copy_from_slice(&index.to_le_bytes());
    aad
}

/// Seal one import record's name||dll with the boot runtime key. The stub
/// decrypts during import resolution; a failed open fails the load closed.
pub fn seal_import(
    key: &Secret32,
    env: &EnvelopeV2,
    index: usize,
) -> Result<ImportSealed, ProtocolError> {
    let imp = env.imports.get(index).ok_or(ProtocolError::Invalid)?;
    let mut pt = imp.name.clone();
    pt.extend_from_slice(&imp.dll);
    if pt.len() > 0xffff {
        return Err(ProtocolError::Invalid);
    }
    let nonce = random_nonce12();
    let aad = import_aad(
        env,
        index as u32,
        imp.iat_rva,
        imp.name.len() as u16,
        imp.dll.len() as u16,
    );
    let (ciphertext, tag) = aead_seal(key, &nonce, &aad, &pt)?;
    Ok(ImportSealed {
        nonce,
        tag,
        ciphertext,
    })
}

#[derive(Clone, Debug)]
pub struct EnvelopeV2 {
    pub platform: u8,
    pub profile: u8,
    pub flags: u32,
    pub policy: u32,
    pub mba: [u8; MBA_LEN],
    pub opcode_seed: [u8; SEED_LEN],
    pub api_salt: [u8; SALT_LEN],
    pub opcode_map: [u8; OPCODE_MAP_LEN],
    pub stolen: Vec<u8>,
    pub program: Vec<u8>,
    pub regions: Vec<Region>,
    pub imports: Vec<ImportRec>,
    pub keep: Vec<u32>,
    pub relocs: Vec<(u32, u16)>,
    /// G5/TASK-026: region indexes that stay SEALED after bootstrap and
    /// decrypt on first execution fault (appended table; empty = all live,
    /// which keeps older parsers three-way compatible).
    pub lazy: Vec<u32>,
}

pub fn region_aad(env: &EnvelopeV2, region: &Region) -> [u8; 32] {
    let mut aad = [0u8; 32];
    aad[0..4].copy_from_slice(MAGIC);
    aad[4..6].copy_from_slice(&VERSION.to_le_bytes());
    aad[6] = env.platform;
    aad[7] = env.profile;
    aad[8..12].copy_from_slice(&env.flags.to_le_bytes());
    aad[12..16].copy_from_slice(&region.index.to_le_bytes());
    aad[16..20].copy_from_slice(&region.rva.to_le_bytes());
    aad[20..24].copy_from_slice(&region.len.to_le_bytes());
    aad[24..28].copy_from_slice(&env.policy.to_le_bytes());
    aad[28..32].copy_from_slice(&((env.relocs.len() as u32).wrapping_mul(8)).to_le_bytes());
    aad
}

pub fn encode(env: &EnvelopeV2) -> Result<Vec<u8>, ProtocolError> {
    if env.stolen.len() > 0xffff {
        return Err(ProtocolError::Invalid);
    }
    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&VERSION.to_le_bytes());
    out.push(env.platform);
    out.push(env.profile);
    out.extend_from_slice(&env.flags.to_le_bytes());
    out.extend_from_slice(&(env.regions.len() as u32).to_le_bytes());
    out.extend_from_slice(&env.mba);
    out.extend_from_slice(&env.opcode_seed);
    out.extend_from_slice(&env.api_salt);
    out.extend_from_slice(&env.opcode_map);
    out.extend_from_slice(&(env.stolen.len() as u16).to_le_bytes());
    out.extend_from_slice(&env.stolen);
    out.extend_from_slice(&(env.program.len() as u32).to_le_bytes());
    out.extend_from_slice(&env.program);
    out.extend_from_slice(&env.policy.to_le_bytes());
    for r in &env.regions {
        if r.ciphertext.len() > PAGE_SIZE {
            return Err(ProtocolError::Invalid);
        }
        out.extend_from_slice(&r.index.to_le_bytes());
        out.extend_from_slice(&r.rva.to_le_bytes());
        out.extend_from_slice(&r.len.to_le_bytes());
        out.extend_from_slice(&r.nonce);
        out.extend_from_slice(&(r.ciphertext.len() as u32).to_le_bytes());
        out.extend_from_slice(&r.ciphertext);
        out.extend_from_slice(&r.tag);
    }
    out.extend_from_slice(&(env.imports.len() as u32).to_le_bytes());
    for imp in &env.imports {
        if imp.name.len() > 0xffff || imp.dll.len() > 0xffff {
            return Err(ProtocolError::Invalid);
        }
        out.extend_from_slice(&imp.hash);
        out.extend_from_slice(&imp.iat_rva.to_le_bytes());
        out.extend_from_slice(&(imp.name.len() as u16).to_le_bytes());
        out.extend_from_slice(&(imp.dll.len() as u16).to_le_bytes());
        match &imp.sealed {
            Some(s) => {
                if s.ciphertext.len() != imp.name.len() + imp.dll.len() {
                    return Err(ProtocolError::Invalid);
                }
                out.extend_from_slice(&s.nonce);
                out.extend_from_slice(&s.tag);
                out.extend_from_slice(&s.ciphertext);
            }
            None => {
                out.extend_from_slice(&imp.name);
                out.extend_from_slice(&imp.dll);
            }
        }
    }
    out.extend_from_slice(&(env.keep.len() as u32).to_le_bytes());
    for rva in &env.keep {
        out.extend_from_slice(&rva.to_le_bytes());
    }
    out.extend_from_slice(&(env.relocs.len() as u32).to_le_bytes());
    for (rva, kind) in &env.relocs {
        out.extend_from_slice(&rva.to_le_bytes());
        out.extend_from_slice(&kind.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
    }
    out.extend_from_slice(&(env.lazy.len() as u32).to_le_bytes());
    for idx in &env.lazy {
        out.extend_from_slice(&idx.to_le_bytes());
    }
    Ok(out)
}

pub fn parse(bytes: &[u8]) -> Result<EnvelopeV2, ProtocolError> {
    if bytes.len() >= 4 && bytes.starts_with(LEGACY_MAGIC) {
        return Err(ProtocolError::LegacyV1);
    }
    if bytes.len() < PREFIX_LEN + MBA_LEN + SEED_LEN + SALT_LEN + OPCODE_MAP_LEN + 2 {
        return Err(ProtocolError::Truncated);
    }
    if &bytes[0..4] != MAGIC {
        return Err(ProtocolError::Invalid);
    }
    let version = u16::from_le_bytes(bytes[4..6].try_into().unwrap());
    if version != VERSION {
        return Err(ProtocolError::Version);
    }
    let platform = bytes[6];
    let profile = bytes[7];
    let flags = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
    let region_count = u32::from_le_bytes(bytes[12..16].try_into().unwrap()) as usize;
    let mut cur = PREFIX_LEN;
    let mut mba = [0u8; MBA_LEN];
    mba.copy_from_slice(take(bytes, &mut cur, MBA_LEN)?);
    let mut opcode_seed = [0u8; SEED_LEN];
    opcode_seed.copy_from_slice(take(bytes, &mut cur, SEED_LEN)?);
    let mut api_salt = [0u8; SALT_LEN];
    api_salt.copy_from_slice(take(bytes, &mut cur, SALT_LEN)?);
    let mut opcode_map = [0u8; OPCODE_MAP_LEN];
    opcode_map.copy_from_slice(take(bytes, &mut cur, OPCODE_MAP_LEN)?);
    let stolen_len = u16::from_le_bytes(take(bytes, &mut cur, 2)?.try_into().unwrap()) as usize;
    let stolen = take(bytes, &mut cur, stolen_len)?.to_vec();
    let prog_len = u32::from_le_bytes(take(bytes, &mut cur, 4)?.try_into().unwrap()) as usize;
    let program = take(bytes, &mut cur, prog_len)?.to_vec();
    let policy = u32::from_le_bytes(take(bytes, &mut cur, 4)?.try_into().unwrap());
    // Unbounded attacker-controlled counts must not drive huge upfront
    // allocations (TASK-037 input safety): every region record needs at
    // least 44 fixed bytes, so a count that cannot fit the remaining input
    // is rejected before any allocation.
    const MIN_REGION_REC: usize = 4 + 4 + 4 + AEAD_NONCE_LEN + 4 + AEAD_TAG_LEN;
    if region_count > (bytes.len() - cur) / MIN_REGION_REC {
        return Err(ProtocolError::Invalid);
    }
    let mut regions = Vec::with_capacity(region_count);
    for _ in 0..region_count {
        let index = u32::from_le_bytes(take(bytes, &mut cur, 4)?.try_into().unwrap());
        let rva = u32::from_le_bytes(take(bytes, &mut cur, 4)?.try_into().unwrap());
        let len = u32::from_le_bytes(take(bytes, &mut cur, 4)?.try_into().unwrap());
        let mut nonce = [0u8; AEAD_NONCE_LEN];
        nonce.copy_from_slice(take(bytes, &mut cur, AEAD_NONCE_LEN)?);
        let ct_len = u32::from_le_bytes(take(bytes, &mut cur, 4)?.try_into().unwrap()) as usize;
        if ct_len > PAGE_SIZE {
            return Err(ProtocolError::Invalid);
        }
        let ciphertext = take(bytes, &mut cur, ct_len)?.to_vec();
        let mut tag = [0u8; AEAD_TAG_LEN];
        tag.copy_from_slice(take(bytes, &mut cur, AEAD_TAG_LEN)?);
        regions.push(Region {
            index,
            rva,
            len,
            nonce,
            ciphertext,
            tag,
        });
    }
    let import_count = u32::from_le_bytes(take(bytes, &mut cur, 4)?.try_into().unwrap()) as usize;
    // Same allocation guard as regions: an import record needs at least
    // 40 fixed bytes (hash 32 + iat 4 + two u16 lengths).
    const MIN_IMPORT_REC: usize = 32 + 4 + 2 + 2;
    if import_count > (bytes.len() - cur) / MIN_IMPORT_REC {
        return Err(ProtocolError::Invalid);
    }
    let mut imports = Vec::with_capacity(import_count);
    for _ in 0..import_count {
        let mut hash = [0u8; 32];
        hash.copy_from_slice(take(bytes, &mut cur, 32)?);
        let iat_rva = u32::from_le_bytes(take(bytes, &mut cur, 4)?.try_into().unwrap());
        let name_len = u16::from_le_bytes(take(bytes, &mut cur, 2)?.try_into().unwrap()) as usize;
        let dll_len = u16::from_le_bytes(take(bytes, &mut cur, 2)?.try_into().unwrap()) as usize;
        let (name, dll, sealed) = if flags & FLAG_IMPORTS_SEALED != 0 {
            // Opaque sealed payload: nonce(12) + tag(16) + ct(name||dll).
            // Plaintext lengths stay in the header so trusted consumers can
            // split the decrypted blob; an unkeyed parser gets the sealed
            // form and empty plaintext fields.
            let mut nonce = [0u8; AEAD_NONCE_LEN];
            nonce.copy_from_slice(take(bytes, &mut cur, AEAD_NONCE_LEN)?);
            let mut tag = [0u8; AEAD_TAG_LEN];
            tag.copy_from_slice(take(bytes, &mut cur, AEAD_TAG_LEN)?);
            let ct = take(bytes, &mut cur, name_len + dll_len)?.to_vec();
            (
                Vec::new(),
                Vec::new(),
                Some(ImportSealed {
                    nonce,
                    tag,
                    ciphertext: ct,
                }),
            )
        } else {
            (
                take(bytes, &mut cur, name_len)?.to_vec(),
                take(bytes, &mut cur, dll_len)?.to_vec(),
                None,
            )
        };
        imports.push(ImportRec {
            hash,
            iat_rva,
            name,
            dll,
            sealed,
        });
    }
    let keep_count = u32::from_le_bytes(take(bytes, &mut cur, 4)?.try_into().unwrap()) as usize;
    if keep_count > (bytes.len() - cur) / 4 {
        return Err(ProtocolError::Invalid);
    }
    let mut keep = Vec::with_capacity(keep_count);
    for _ in 0..keep_count {
        keep.push(u32::from_le_bytes(take(bytes, &mut cur, 4)?.try_into().unwrap()));
    }
    let reloc_count = if cur + 4 <= bytes.len() {
        u32::from_le_bytes(take(bytes, &mut cur, 4)?.try_into().unwrap()) as usize
    } else {
        0
    };
    if reloc_count > (bytes.len() - cur) / 8 {
        return Err(ProtocolError::Invalid);
    }
    let mut relocs = Vec::with_capacity(reloc_count);
    for _ in 0..reloc_count {
        let rva = u32::from_le_bytes(take(bytes, &mut cur, 4)?.try_into().unwrap());
        let kind = u16::from_le_bytes(take(bytes, &mut cur, 2)?.try_into().unwrap());
        let _pad = take(bytes, &mut cur, 2)?;
        relocs.push((rva, kind));
    }
    let lazy_count = if cur + 4 <= bytes.len() {
        u32::from_le_bytes(take(bytes, &mut cur, 4)?.try_into().unwrap()) as usize
    } else {
        0
    };
    let mut lazy = Vec::with_capacity(lazy_count.min(65_536));
    for _ in 0..lazy_count {
        lazy.push(u32::from_le_bytes(take(bytes, &mut cur, 4)?.try_into().unwrap()));
    }
    if cur > bytes.len() {
        return Err(ProtocolError::Truncated);
    }
    Ok(EnvelopeV2 {
        platform,
        profile,
        flags,
        policy,
        mba,
        opcode_seed,
        api_salt,
        opcode_map,
        stolen,
        program,
        regions,
        imports,
        keep,
        relocs,
        lazy,
    })
}

fn take<'a>(bytes: &'a [u8], cur: &mut usize, n: usize) -> Result<&'a [u8], ProtocolError> {
    let start = *cur;
    let end = start.checked_add(n).ok_or(ProtocolError::Truncated)?;
    if end > bytes.len() {
        return Err(ProtocolError::Truncated);
    }
    *cur = end;
    Ok(&bytes[start..end])
}

pub fn seal_region(
    key: &Secret32,
    env: &EnvelopeV2,
    index: u32,
    rva: u32,
    plaintext: &[u8],
    nonce: [u8; AEAD_NONCE_LEN],
) -> Result<Region, ProtocolError> {
    if plaintext.len() > PAGE_SIZE {
        return Err(ProtocolError::Invalid);
    }
    let region = Region {
        index,
        rva,
        len: plaintext.len() as u32,
        nonce,
        ciphertext: Vec::new(),
        tag: [0u8; AEAD_TAG_LEN],
    };
    let aad = region_aad(env, &region);
    let (ct, tag) = aead_seal(key, &nonce, &aad, plaintext)?;
    Ok(Region {
        ciphertext: ct,
        tag,
        ..region
    })
}

pub fn open_region(key: &Secret32, env: &EnvelopeV2, region: &Region) -> Result<Vec<u8>, ProtocolError> {
    let aad = region_aad(env, region);
    aead_open(key, &region.nonce, &aad, &region.ciphertext, &region.tag)
        .map_err(|_| ProtocolError::Auth)
}

#[cfg(test)]
mod tests {
    use super::*;
    use xenolith_crypto::{random_nonce12, Secret32};

    fn sample_env() -> EnvelopeV2 {
        EnvelopeV2 {
            platform: PLATFORM_PE64,
            profile: 2,
            flags: 0,
            policy: POLICY_STRICT,
            mba: [3; MBA_LEN],
            opcode_seed: [4; SEED_LEN],
            api_salt: [5; SALT_LEN],
            opcode_map: [1, 2, 3, 4, 5, 6, 7, 8],
            stolen: vec![0x90; 16],
            program: vec![9, 10, 11],
        regions: vec![],
        imports: vec![],
        keep: vec![0x1000],
        relocs: vec![],
        lazy: vec![],
    }
}

    #[test]
    fn roundtrip_and_open() {
        let key = Secret32::from_bytes([0x11; 32]);
        let mut env = sample_env();
        let nonce = random_nonce12();
        let pt = b"hello-region-plain".to_vec();
        env.regions
            .push(seal_region(&key, &env, 0, 0x1000, &pt, nonce).unwrap());
        let bytes = encode(&env).unwrap();
        let parsed = parse(&bytes).unwrap();
        assert_eq!(parsed.regions.len(), 1);
        let out = open_region(&key, &parsed, &parsed.regions[0]).unwrap();
        assert_eq!(out, pt);
    }

    #[test]
    fn legacy_v1_rejected() {
        let mut old = b"NSEN".to_vec();
        old.resize(64, 0);
        assert!(matches!(parse(&old), Err(ProtocolError::LegacyV1)));
    }

    #[test]
    fn previous_v2_magic_rejected() {
        let mut old = b"NSV2".to_vec();
        old.resize(256, 0);
        assert!(parse(&old).is_err());
    }

    #[test]
    fn truncated_rejected() {
        assert!(matches!(parse(b"XLV2"), Err(ProtocolError::Truncated)));
    }

    #[test]
    fn bad_tag_rejected() {
        let key = Secret32::from_bytes([0x11; 32]);
        let mut env = sample_env();
        let nonce = random_nonce12();
        env.regions
            .push(seal_region(&key, &env, 0, 0x1000, b"abc", nonce).unwrap());
        env.regions[0].tag[0] ^= 1;
        let bytes = encode(&env).unwrap();
        let parsed = parse(&bytes).unwrap();
        assert!(open_region(&key, &parsed, &parsed.regions[0]).is_err());
    }
}
