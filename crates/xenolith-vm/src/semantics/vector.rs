//! Packed lane semantics for the G4 frozen corpus.
//!
//! V128/V256 are lane-typed byte arrays; every op mirrors the hardware
//! lane-wise definition (including float NaN rules per lane). Integer ops
//! are wrapping per lane, exactly like the SSE2/SSE4/AVX2 definitions.

use super::float::{sse_f32, sse_f64, Mxcsr, ScalarOp};

pub type V128 = [u8; 16];
pub type V256 = [u8; 32];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Lane {
    B8,
    B16,
    B32,
    B64,
}

impl Lane {
    pub fn bytes(self) -> usize {
        match self {
            Lane::B8 => 1,
            Lane::B16 => 2,
            Lane::B32 => 4,
            Lane::B64 => 8,
        }
    }
}

fn lane_u64(v: &[u8], i: usize, w: usize) -> u64 {
    let mut b = [0u8; 8];
    b[..w].copy_from_slice(&v[i * w..i * w + w]);
    u64::from_le_bytes(b)
}

fn set_lane_u64(v: &mut [u8], i: usize, w: usize, x: u64) {
    v[i * w..i * w + w].copy_from_slice(&x.to_le_bytes()[..w]);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IntVecOp {
    Add,
    Sub,
    /// pmullw: 16-bit lanes, low half of the product.
    MullW,
    /// pmulhw: 16-bit lanes, high half of the signed product.
    MulHW,
    /// SSE4_1 pmulld: full 32-bit product per lane.
    MulLd,
    And,
    Or,
    Xor,
    /// pcmpeq on the lane width (all-ones on equal).
    CmpEq,
    /// SSE4_1 pminsd/pmaxsd: signed 32-bit.
    MinSd,
    MaxSd,
}

fn lane_int_op(op: IntVecOp, lane: Lane, a: u64, b: u64, _w: usize) -> u64 {
    match (op, lane) {
        (IntVecOp::Add, _) => a.wrapping_add(b),
        (IntVecOp::Sub, _) => a.wrapping_sub(b),
        (IntVecOp::And, _) => a & b,
        (IntVecOp::Or, _) => a | b,
        (IntVecOp::Xor, _) => a ^ b,
        (IntVecOp::CmpEq, _) => {
            if a == b {
                u64::MAX
            } else {
                0
            }
        }
        (IntVecOp::MullW, Lane::B16) => {
            let p = (a as u16 as u32).wrapping_mul(b as u16 as u32);
            (p & 0xFFFF) as u64
        }
        (IntVecOp::MulHW, Lane::B16) => {
            let p = ((a as u16 as i16) as i32).wrapping_mul((b as u16 as i16) as i32);
            ((p >> 16) as u16) as u64
        }
        (IntVecOp::MulLd, Lane::B32) => (a as u32).wrapping_mul(b as u32) as u64,
        (IntVecOp::MinSd, Lane::B32) => {
            if (a as u32 as i32) < (b as u32 as i32) {
                a
            } else {
                b
            }
        }
        (IntVecOp::MaxSd, Lane::B32) => {
            if (a as u32 as i32) > (b as u32 as i32) {
                a
            } else {
                b
            }
        }
        _ => 0, // callers must only pair op with supported lane widths
    }
}

/// Lane-wise packed integer op. `w` is the lane width in bytes (1/2/4/8);
/// the vector length is implied by the slice.
pub fn int_vec(op: IntVecOp, lane: Lane, a: &[u8], b: &[u8], out: &mut [u8]) -> bool {
    let w = lane.bytes();
    if a.len() != b.len() || out.len() != a.len() || a.len() % w != 0 {
        return false;
    }
    // op/lane pairing check (fail closed instead of guessing)
    let ok = match (op, lane) {
        (IntVecOp::MullW | IntVecOp::MulHW, Lane::B16) => true,
        (IntVecOp::MulLd | IntVecOp::MinSd | IntVecOp::MaxSd, Lane::B32) => true,
        (IntVecOp::Add | IntVecOp::Sub | IntVecOp::And | IntVecOp::Or | IntVecOp::Xor
        | IntVecOp::CmpEq, _) => true,
        _ => false,
    };
    if !ok {
        return false;
    }
    for i in 0..(a.len() / w) {
        let r = lane_int_op(op, lane, lane_u64(a, i, w), lane_u64(b, i, w), w);
        set_lane_u64(out, i, w, r);
    }
    true
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FloatVecOp {
    Add,
    Sub,
    Mul,
    Div,
}

/// Packed single-precision (addps/…): 4 lanes of f32 with SSE NaN rules.
pub fn f32_vec(op: FloatVecOp, a: &V128, b: &V128, mxcsr: &mut Mxcsr) -> V128 {
    let sop = match op {
        FloatVecOp::Add => ScalarOp::Add,
        FloatVecOp::Sub => ScalarOp::Sub,
        FloatVecOp::Mul => ScalarOp::Mul,
        FloatVecOp::Div => ScalarOp::Div,
    };
    let mut out = [0u8; 16];
    for i in 0..4 {
        let x = u32::from_le_bytes(a[i * 4..i * 4 + 4].try_into().unwrap());
        let y = u32::from_le_bytes(b[i * 4..i * 4 + 4].try_into().unwrap());
        out[i * 4..i * 4 + 4].copy_from_slice(&sse_f32(sop, x, y, mxcsr).to_le_bytes());
    }
    out
}

/// Packed double-precision (addpd/…): 2 lanes of f64.
pub fn f64_vec(op: FloatVecOp, a: &V128, b: &V128, mxcsr: &mut Mxcsr) -> V128 {
    let sop = match op {
        FloatVecOp::Add => ScalarOp::Add,
        FloatVecOp::Sub => ScalarOp::Sub,
        FloatVecOp::Mul => ScalarOp::Mul,
        FloatVecOp::Div => ScalarOp::Div,
    };
    let mut out = [0u8; 16];
    for i in 0..2 {
        let x = u64::from_le_bytes(a[i * 8..i * 8 + 8].try_into().unwrap());
        let y = u64::from_le_bytes(b[i * 8..i * 8 + 8].try_into().unwrap());
        out[i * 8..i * 8 + 8].copy_from_slice(&sse_f64(sop, x, y, mxcsr).to_le_bytes());
    }
    out
}

/// pshufd: lane order by 2-bit selectors (imm packed as d2 d1 d0 in bits 0..7
/// — the classic imm8: bits [1:0] dst0, [3:2] dst1, [5:4] dst2, [7:6] dst3).
pub fn pshufd(a: &V128, imm: u8) -> V128 {
    let mut out = [0u8; 16];
    for i in 0..4 {
        let sel = ((imm >> (i * 2)) & 3) as usize;
        out[i * 4..i * 4 + 4].copy_from_slice(&a[sel * 4..sel * 4 + 4]);
    }
    out
}

/// punpcklqdq: dst = [a.low64, b.low64].
pub fn punpcklqdq(a: &V128, b: &V128) -> V128 {
    let mut out = [0u8; 16];
    out[..8].copy_from_slice(&a[..8]);
    out[8..].copy_from_slice(&b[..8]);
    out
}

/// Concatenate the low 128 bits of two YMM values (vinserti128 semantics
/// for the frozen corpus: dst = [a.lo128, b.lo128]).
pub fn vinserti128_lo(a: &V256, b: &V128) -> V256 {
    let mut out = *a;
    out[16..].copy_from_slice(b);
    out
}

/// Extract a YMM half into a V128.
pub fn vextracti128(v: &V256, half: usize) -> V128 {
    let mut out = [0u8; 16];
    let s = half * 16;
    out.copy_from_slice(&v[s..s + 16]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v128_from_lanes32(l: [u32; 4]) -> V128 {
        let mut v = [0u8; 16];
        for (i, x) in l.iter().enumerate() {
            v[i * 4..i * 4 + 4].copy_from_slice(&x.to_le_bytes());
        }
        v
    }

    #[test]
    fn paddd_wraps_per_lane() {
        let a = v128_from_lanes32([u32::MAX, 1, 2, 3]);
        let b = v128_from_lanes32([1, 1, 0, 0]);
        let mut out = [0u8; 16];
        assert!(int_vec(IntVecOp::Add, Lane::B32, &a, &b, &mut out));
        assert_eq!(out, v128_from_lanes32([0, 2, 2, 3]));
    }

    #[test]
    fn pmullw_and_pmulhw() {
        let mut a = [0u8; 16];
        let mut b = [0u8; 16];
        for i in 0..8 {
            a[i * 2..i * 2 + 2].copy_from_slice(&0xFFFFu16.to_le_bytes());
            b[i * 2..i * 2 + 2].copy_from_slice(&0xFFFFu16.to_le_bytes());
        }
        let mut out = [0u8; 16];
        assert!(int_vec(IntVecOp::MullW, Lane::B16, &a, &b, &mut out));
        assert_eq!(out[0], 1); // (-1)*(-1) = 1 low half
        assert!(int_vec(IntVecOp::MulHW, Lane::B16, &a, &b, &mut out));
        assert_eq!(out[0], 0); // high half of 1
    }

    #[test]
    fn pmulld_frozen() {
        let a = v128_from_lanes32([0x10000, 0x10000, 0, 0]);
        let b = v128_from_lanes32([0x10000, 3, 0, 0]);
        let mut out = [0u8; 16];
        assert!(int_vec(IntVecOp::MulLd, Lane::B32, &a, &b, &mut out));
        assert_eq!(out, v128_from_lanes32([0, 0x30000, 0, 0]));
    }

    #[test]
    fn unsupported_pairing_fails_closed() {
        let a = [0u8; 16];
        let b = [0u8; 16];
        let mut out = [0u8; 16];
        assert!(!int_vec(IntVecOp::MullW, Lane::B32, &a, &b, &mut out));
        assert!(!int_vec(IntVecOp::MinSd, Lane::B16, &a, &b, &mut out));
    }

    #[test]
    fn addps_lane_nan_rules() {
        let mut a = v128_from_lanes32([1, 0x7F800001, 3, 4]); // lane1 sNaN
        let _ = &mut a;
        let b = v128_from_lanes32([1, 1, 3, 0x7FC00000]);
        let mut mx = Mxcsr::new();
        let out = f32_vec(FloatVecOp::Add, &a, &b, &mut mx);
        let lanes: Vec<u32> = (0..4)
            .map(|i| u32::from_le_bytes(out[i * 4..i * 4 + 4].try_into().unwrap()))
            .collect();
        assert_eq!(lanes[0], 2);
        assert_eq!(lanes[1], 0x7FC00001, "src1 sNaN quieted");
        assert_eq!(lanes[3], 0x7FC00000, "src2 QNaN propagates");
    }

    #[test]
    fn pshufd_classic() {
        let a = v128_from_lanes32([0, 1, 2, 3]);
        assert_eq!(pshufd(&a, 0b00_01_10_11), v128_from_lanes32([3, 2, 1, 0]));
        assert_eq!(pshufd(&a, 0), v128_from_lanes32([0, 0, 0, 0]));
    }

    #[test]
    fn avx2_lane_ops_over_256() {
        let mut a = [0xAAu8; 32];
        let mut b = [0x55u8; 32];
        for (i, x) in a.chunks_mut(4).enumerate() {
            let v = (i as u32) * 0x0101_0101;
            x.copy_from_slice(&v.to_le_bytes());
        }
        for (i, x) in b.chunks_mut(4).enumerate() {
            let v = (i as u32) + 1;
            x.copy_from_slice(&v.to_le_bytes());
        }
        let mut out = [0u8; 32];
        assert!(int_vec(IntVecOp::Add, Lane::B32, &a, &b, &mut out));
        let l0 = u32::from_le_bytes(out[..4].try_into().unwrap());
        let l7 = u32::from_le_bytes(out[28..].try_into().unwrap());
        assert_eq!(l0, 1u32); // lane0 = 0 + 1
        assert_eq!(l7, 0x0707_0707u32.wrapping_add(8));
    }
}
