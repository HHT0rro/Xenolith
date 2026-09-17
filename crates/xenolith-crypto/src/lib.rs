//! Sharded AEAD, MBA key mix, and page MAC.
//!
//! The master secret is never stored as 32 contiguous bytes in an image.
//! Pack-time material is split into MBA immediates; runtime reconstruction
//! mixes those immediates with an image measurement. There is no
//! `SHA-256(identity || public ASCII label)` wrap.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;
pub const AEAD_NONCE_LEN: usize = 12;
pub const AEAD_TAG_LEN: usize = 16;
pub const PAGE_SIZE: usize = 0x1000;
pub const MBA_LIMBS: usize = 8;
/// Domain is binary on purpose: it must not appear as searchable ASCII in images.
pub const WRAP_DOMAIN: [u8; 16] = [
    0x4e, 0x53, 0x70, 0x6b, 0x76, 0x32, 0x00, 0x7f, 0xa1, 0x3c, 0x91, 0x08, 0x55, 0xd2, 0xee, 0x11,
];
pub const PAGE_MAC_DOMAIN: [u8; 8] = [0x4e, 0x53, 0x4d, 0x41, 0x43, 0x70, 0x31, 0x00];

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("AEAD failed")]
    Aead,
    #[error("page length is invalid")]
    Page,
    #[error("mba limb count is invalid")]
    Mba,
}

#[derive(Debug, Error)]
pub enum AeadError {
    #[error("ChaCha20-Poly1305 failed")]
    Auth,
    #[error("nonce or length is invalid")]
    Length,
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Secret32(pub [u8; KEY_LEN]);

impl std::fmt::Debug for Secret32 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret32(..)")
    }
}

impl Secret32 {
    pub fn random() -> Self {
        let mut bytes = [0u8; KEY_LEN];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }
}

/// Eight (mul, add, xor_mask) limbs that reconstruct 32 key bytes.
#[derive(Clone, Debug)]
pub struct MbaKeyShare {
    pub mul: [u32; MBA_LIMBS],
    pub add: [u32; MBA_LIMBS],
    pub xor_mask: [u32; MBA_LIMBS],
}

impl MbaKeyShare {
    pub fn split(secret: &Secret32, seed: &[u8; 16]) -> Self {
        let mut mul = [0u32; MBA_LIMBS];
        let mut add = [0u32; MBA_LIMBS];
        let mut xor_mask = [0u32; MBA_LIMBS];
        for i in 0..MBA_LIMBS {
            let word = u32::from_le_bytes(secret.0[i * 4..i * 4 + 4].try_into().unwrap());
            let m =
                u32::from_le_bytes(seed[(i % 4) * 4..(i % 4) * 4 + 4].try_into().unwrap()) | 1;
            let a = (seed[i] as u32)
                .wrapping_add(i as u32)
                .wrapping_mul(0x9E37_79B9);
            mul[i] = m;
            add[i] = a;
            xor_mask[i] = word.wrapping_mul(m).wrapping_add(a);
        }
        Self { mul, add, xor_mask }
    }

    pub fn reconstruct(&self) -> Result<Secret32, CryptoError> {
        let mut out = [0u8; KEY_LEN];
        for i in 0..MBA_LIMBS {
            if self.mul[i] % 2 == 0 {
                return Err(CryptoError::Mba);
            }
            let inv = mul_inverse_odd(self.mul[i]);
            let word = self.xor_mask[i].wrapping_sub(self.add[i]).wrapping_mul(inv);
            out[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        Ok(Secret32(out))
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(MBA_LIMBS * 12);
        for i in 0..MBA_LIMBS {
            out.extend_from_slice(&self.mul[i].to_le_bytes());
            out.extend_from_slice(&self.add[i].to_le_bytes());
            out.extend_from_slice(&self.xor_mask[i].to_le_bytes());
        }
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != MBA_LIMBS * 12 {
            return Err(CryptoError::Mba);
        }
        let mut mul = [0u32; MBA_LIMBS];
        let mut add = [0u32; MBA_LIMBS];
        let mut xor_mask = [0u32; MBA_LIMBS];
        for i in 0..MBA_LIMBS {
            let o = i * 12;
            mul[i] = u32::from_le_bytes(bytes[o..o + 4].try_into().unwrap());
            add[i] = u32::from_le_bytes(bytes[o + 4..o + 8].try_into().unwrap());
            xor_mask[i] = u32::from_le_bytes(bytes[o + 8..o + 12].try_into().unwrap());
        }
        Ok(Self { mul, add, xor_mask })
    }
}

fn mul_inverse_odd(value: u32) -> u32 {
    let mut x = value;
    x = x.wrapping_mul(2u32.wrapping_sub(value.wrapping_mul(x)));
    x = x.wrapping_mul(2u32.wrapping_sub(value.wrapping_mul(x)));
    x = x.wrapping_mul(2u32.wrapping_sub(value.wrapping_mul(x)));
    x = x.wrapping_mul(2u32.wrapping_sub(value.wrapping_mul(x)));
    x
}

pub fn image_measurement(image: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"XLIM\x01v1");
    hasher.update(&(image.len() as u64).to_le_bytes());
    hasher.update(image);
    hasher.finalize().into()
}

pub fn mix_runtime_key(mba: &MbaKeyShare, measurement: &[u8; 32]) -> Result<Secret32, CryptoError> {
    let mut reconstructed = mba.reconstruct()?;
    let out = mix_runtime_key_bytes(&reconstructed.0, measurement)?;
    reconstructed.zeroize();
    Ok(out)
}

pub fn mix_runtime_key_bytes(secret: &[u8; KEY_LEN], measurement: &[u8; 32]) -> Result<Secret32, CryptoError> {
    let mut out = [0u8; KEY_LEN];
    for i in 0..KEY_LEN {
        out[i] = secret[i] ^ measurement[i] ^ WRAP_DOMAIN[i % WRAP_DOMAIN.len()];
    }
    Ok(Secret32(out))
}

pub fn page_key(runtime: &Secret32, page_index: u32, nonce: &[u8; NONCE_LEN]) -> Secret32 {
    let idx = page_index.to_le_bytes();
    let mut out = [0u8; KEY_LEN];
    for i in 0..KEY_LEN {
        out[i] = runtime.0[i]
            ^ nonce[i % NONCE_LEN]
            ^ idx[i % 4]
            ^ PAGE_MAC_DOMAIN[i % PAGE_MAC_DOMAIN.len()];
    }
    Secret32(out)
}

pub fn encrypt_page(
    runtime: &Secret32,
    page_index: u32,
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if plaintext.len() > PAGE_SIZE {
        return Err(CryptoError::Page);
    }
    let mut padded = vec![0u8; PAGE_SIZE];
    padded[..plaintext.len()].copy_from_slice(plaintext);
    let key = page_key(runtime, page_index, nonce);
    xor_page(&key.0, nonce, &mut padded);
    Ok(padded)
}

pub fn decrypt_page(
    runtime: &Secret32,
    page_index: u32,
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if ciphertext.len() != PAGE_SIZE {
        return Err(CryptoError::Page);
    }
    let key = page_key(runtime, page_index, nonce);
    let mut body = ciphertext.to_vec();
    xor_page(&key.0, nonce, &mut body);
    Ok(body)
}

/// Stream XOR that a tiny PIC stub can reproduce without ChaCha.
///
/// The keystream reads the nonce through a 16-byte view (nonce ++ nonce[0..4])
/// so the stub indexes with a single `AND 15` instead of a modulo.
pub fn xor_page(key: &[u8; KEY_LEN], nonce12: &[u8; NONCE_LEN], data: &mut [u8]) {
    for (i, b) in data.iter_mut().enumerate() {
        let slot = i & 15;
        let n = if slot < NONCE_LEN { nonce12[slot] } else { nonce12[slot & 3] };
        let k = key[i % KEY_LEN]
            ^ n
            ^ ((i as u8).wrapping_mul(0x9d))
            ^ ((i >> 8) as u8);
        *b ^= k;
    }
}

pub fn page_mac(
    runtime: &Secret32,
    measurement: &[u8; 32],
    page_index: u32,
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&runtime.0).expect("hmac key");
    mac.update(&PAGE_MAC_DOMAIN);
    mac.update(measurement);
    mac.update(&page_index.to_le_bytes());
    mac.update(nonce);
    mac.update(ciphertext);
    mac.finalize().into_bytes().into()
}

/// Production AEAD. v1 XOR+FNV must not call this.
pub fn aead_seal(
    key: &Secret32,
    nonce: &[u8; AEAD_NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, [u8; AEAD_TAG_LEN]), AeadError> {
    let cipher = ChaCha20Poly1305::new_from_slice(&key.0).map_err(|_| AeadError::Length)?;
    let n = Nonce::from_slice(nonce);
    let sealed = cipher
        .encrypt(
            n,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| AeadError::Auth)?;
    if sealed.len() < AEAD_TAG_LEN {
        return Err(AeadError::Length);
    }
    let split = sealed.len() - AEAD_TAG_LEN;
    let mut tag = [0u8; AEAD_TAG_LEN];
    tag.copy_from_slice(&sealed[split..]);
    Ok((sealed[..split].to_vec(), tag))
}

pub fn aead_open(
    key: &Secret32,
    nonce: &[u8; AEAD_NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; AEAD_TAG_LEN],
) -> Result<Vec<u8>, AeadError> {
    let cipher = ChaCha20Poly1305::new_from_slice(&key.0).map_err(|_| AeadError::Length)?;
    let n = Nonce::from_slice(nonce);
    let mut sealed = Vec::with_capacity(ciphertext.len() + AEAD_TAG_LEN);
    sealed.extend_from_slice(ciphertext);
    sealed.extend_from_slice(tag);
    cipher
        .decrypt(
            n,
            Payload {
                msg: &sealed,
                aad,
            },
        )
        .map_err(|_| AeadError::Auth)
}

pub fn random_nonce12() -> [u8; AEAD_NONCE_LEN] {
    random_nonce()
}

pub fn random_nonce() -> [u8; NONCE_LEN] {
    let mut n = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut n);
    n
}

pub fn random_seed16() -> [u8; 16] {
    let mut n = [0u8; 16];
    OsRng.fill_bytes(&mut n);
    n
}

pub fn api_hash(dll: &str, name: &str, salt: &[u8; 16]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"XLAPI\x01");
    hasher.update(salt);
    hasher.update(dll.as_bytes());
    hasher.update([0]);
    hasher.update(name.as_bytes());
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mba_roundtrip() {
        let secret = Secret32::random();
        let seed = random_seed16();
        let share = MbaKeyShare::split(&secret, &seed);
        let back = share.reconstruct().unwrap();
        assert_eq!(secret.0, back.0);
        assert!(share.mul.iter().all(|m| m % 2 == 1));
    }

    #[test]
    fn mba_is_not_contiguous_secret() {
        let secret = Secret32::from_bytes([0x11; 32]);
        let seed = [0x22; 16];
        let share = MbaKeyShare::split(&secret, &seed);
        let blob = share
            .xor_mask
            .iter()
            .flat_map(|w| w.to_le_bytes())
            .collect::<Vec<_>>();
        assert_ne!(&blob[..], &secret.0);
    }

    #[test]
    fn page_roundtrip_and_mac() {
        let secret = Secret32::random();
        let seed = random_seed16();
        let share = MbaKeyShare::split(&secret, &seed);
        let measurement = [0xAB; 32];
        let runtime = mix_runtime_key(&share, &measurement).unwrap();
        let nonce = random_nonce();
        let pt = vec![1u8, 2, 3, 4];
        let ct = encrypt_page(&runtime, 7, &nonce, &pt).unwrap();
        let mac = page_mac(&runtime, &measurement, 7, &nonce, &ct);
        let back = decrypt_page(&runtime, 7, &nonce, &ct).unwrap();
        assert_eq!(&back[..4], &pt[..]);
        assert_eq!(mac, page_mac(&runtime, &measurement, 7, &nonce, &ct));
        let wrong = decrypt_page(&runtime, 8, &nonce, &ct).unwrap();
        assert_ne!(&wrong[..4], &pt[..]);
    }

    #[test]
    fn wrap_domain_is_not_ascii() {
        assert!(!WRAP_DOMAIN.iter().all(|b| b.is_ascii_graphic()));
    }

    #[test]
    fn chacha20_poly1305_roundtrip_and_aad() {
        let key = Secret32::from_bytes([7; 32]);
        let nonce = [3u8; 12];
        let aad = b"XLV2-aad-platform-region";
        let pt = b"protected-bytes";
        let (ct, tag) = aead_seal(&key, &nonce, aad, pt).unwrap();
        let back = aead_open(&key, &nonce, aad, &ct, &tag).unwrap();
        assert_eq!(back, pt);
        let mut bad = tag;
        bad[0] ^= 1;
        assert!(aead_open(&key, &nonce, aad, &ct, &bad).is_err());
        assert!(aead_open(&key, &nonce, b"other-aad", &ct, &tag).is_err());
    }
}
