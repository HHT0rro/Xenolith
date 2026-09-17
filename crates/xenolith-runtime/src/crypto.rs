//! no_std copies of the packer KDF / AEAD used by the mapped stub.

use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::XChaCha20;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use poly1305::universal_hash::{KeyInit, UniversalHash};
use poly1305::{Block as PolyBlock, Poly1305};
use sha2::{Digest, Sha256};

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;
pub const MBA_LIMBS: usize = 8;
pub const WRAP_DOMAIN: [u8; 16] = [
    0x4e, 0x53, 0x70, 0x6b, 0x76, 0x32, 0x00, 0x7f, 0xa1, 0x3c, 0x91, 0x08, 0x55, 0xd2, 0xee, 0x11,
];
pub const PAGE_MAC_DOMAIN: [u8; 8] = [0x4e, 0x53, 0x4d, 0x41, 0x43, 0x70, 0x31, 0x00];

pub fn mul_inverse_odd(value: u32) -> u32 {
    let mut x = value;
    x = x.wrapping_mul(2u32.wrapping_sub(value.wrapping_mul(x)));
    x = x.wrapping_mul(2u32.wrapping_sub(value.wrapping_mul(x)));
    x = x.wrapping_mul(2u32.wrapping_sub(value.wrapping_mul(x)));
    x = x.wrapping_mul(2u32.wrapping_sub(value.wrapping_mul(x)));
    x
}

pub fn reconstruct_mba(bytes: &[u8]) -> Option<[u8; KEY_LEN]> {
    if bytes.len() != MBA_LIMBS * 12 {
        return None;
    }
    let mut out = [0u8; KEY_LEN];
    for i in 0..MBA_LIMBS {
        let o = i * 12;
        let mul = u32::from_le_bytes(bytes[o..o + 4].try_into().ok()?);
        let add = u32::from_le_bytes(bytes[o + 4..o + 8].try_into().ok()?);
        let xor_mask = u32::from_le_bytes(bytes[o + 8..o + 12].try_into().ok()?);
        if mul % 2 == 0 {
            return None;
        }
        let word = xor_mask.wrapping_sub(add).wrapping_mul(mul_inverse_odd(mul));
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    Some(out)
}

pub fn mix_runtime_key(secret: &[u8; KEY_LEN], measurement: &[u8; 32]) -> Option<[u8; KEY_LEN]> {
    let hk = Hkdf::<Sha256>::new(Some(&WRAP_DOMAIN), secret);
    let mut out = [0u8; KEY_LEN];
    hk.expand(measurement, &mut out).ok()?;
    Some(out)
}

pub fn page_key(runtime: &[u8; KEY_LEN], page_index: u32, nonce: &[u8; NONCE_LEN]) -> [u8; KEY_LEN] {
    let hk = Hkdf::<Sha256>::new(Some(&PAGE_MAC_DOMAIN), runtime);
    let mut info = [0u8; 4 + NONCE_LEN];
    info[..4].copy_from_slice(&page_index.to_le_bytes());
    info[4..].copy_from_slice(nonce);
    let mut out = [0u8; KEY_LEN];
    hk.expand(&info, &mut out).expect("hkdf");
    out
}

pub fn page_mac(
    runtime: &[u8; KEY_LEN],
    measurement: &[u8; 32],
    page_index: u32,
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(runtime).expect("hmac");
    mac.update(&PAGE_MAC_DOMAIN);
    mac.update(measurement);
    mac.update(&page_index.to_le_bytes());
    mac.update(nonce);
    mac.update(ciphertext);
    mac.finalize().into_bytes().into()
}

fn poly1305_update(poly: &mut Poly1305, data: &[u8]) {
    let mut offset = 0;
    while offset + 16 <= data.len() {
        poly.update(&[PolyBlock::clone_from_slice(&data[offset..offset + 16])]);
        offset += 16;
    }
    if offset < data.len() {
        let mut last = [0u8; 16];
        last[..data.len() - offset].copy_from_slice(&data[offset..]);
        poly.update(&[PolyBlock::clone_from_slice(&last)]);
    }
}

pub fn xchacha20_poly1305_open(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    sealed: &[u8],
    out: &mut [u8],
) -> bool {
    if sealed.len() < 16 || out.len() + 16 != sealed.len() {
        return false;
    }
    let (ct, tag) = sealed.split_at(sealed.len() - 16);
    let mut cipher = XChaCha20::new(key.into(), nonce.into());
    let mut otk = [0u8; 32];
    cipher.apply_keystream(&mut otk);
    let mut poly = Poly1305::new((&otk).into());
    poly1305_update(&mut poly, ct);
    let mut lens = [0u8; 16];
    lens[..8].copy_from_slice(&(ct.len() as u64).to_le_bytes());
    poly1305_update(&mut poly, &lens);
    let expected = poly.finalize();
    if expected.as_slice() != tag {
        return false;
    }
    for (d, s) in out.iter_mut().zip(ct.iter()) {
        *d = *s;
    }
    cipher.apply_keystream(out);
    true
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub fn image_measurement(image: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"XLIM\x01v1");
    hasher.update(&(image.len() as u64).to_le_bytes());
    hasher.update(image);
    hasher.finalize().into()
}
