//! MBA identities used by superoperator codegen.
//! Applied at PIC emit time, not stored as a guest opcode.

use crate::ir::{apply_bin, BinOp};

/// `a + b == (a ^ b) + 2*(a & b)` (wrapping 32-bit).
pub fn add_xor_and(lhs: u32, rhs: u32) -> u32 {
    let x = lhs ^ rhs;
    let y = (lhs & rhs).wrapping_shl(1);
    x.wrapping_add(y)
}

/// `a - b == a + (~b + 1)`.
pub fn sub_via_add_not(lhs: u32, rhs: u32) -> u32 {
    lhs.wrapping_add((!rhs).wrapping_add(1))
}

/// `a ^ b == (a | b) - (a & b)`.
pub fn xor_via_or_and(lhs: u32, rhs: u32) -> u32 {
    (lhs | rhs).wrapping_sub(lhs & rhs)
}

/// `a & b == (a + b) - (a | b)`.
pub fn and_via_add_or(lhs: u32, rhs: u32) -> u32 {
    lhs.wrapping_add(rhs).wrapping_sub(lhs | rhs)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MbaFamily {
    Identity,
    AddXorAnd,
    AddLea,
    SubAddNot,
    XorOrAnd,
    AndAddOr,
}

pub fn pick_family(op: BinOp, seed: u8) -> MbaFamily {
    match op {
        BinOp::Add => match seed % 3 {
            0 => MbaFamily::Identity,
            1 => MbaFamily::AddXorAnd,
            _ => MbaFamily::AddLea,
        },
        BinOp::Sub => {
            if seed & 1 == 1 {
                MbaFamily::SubAddNot
            } else {
                MbaFamily::Identity
            }
        }
        BinOp::Xor => {
            if seed & 1 == 1 {
                MbaFamily::XorOrAnd
            } else {
                MbaFamily::Identity
            }
        }
        BinOp::And => {
            if seed & 1 == 1 {
                MbaFamily::AndAddOr
            } else {
                MbaFamily::Identity
            }
        }
        BinOp::Or => MbaFamily::Identity,
        // No MBA rewrite yet for multiply/shifts: emit them verbatim.
        BinOp::Mul | BinOp::Shl | BinOp::Shr | BinOp::Sar => MbaFamily::Identity,
    }
}

pub fn eval_family(family: MbaFamily, op: BinOp, lhs: u32, rhs: u32) -> u32 {
    match family {
        MbaFamily::Identity => apply_bin(op, lhs, rhs),
        MbaFamily::AddXorAnd | MbaFamily::AddLea => add_xor_and(lhs, rhs),
        MbaFamily::SubAddNot => sub_via_add_not(lhs, rhs),
        MbaFamily::XorOrAnd => xor_via_or_and(lhs, rhs),
        MbaFamily::AndAddOr => and_via_add_or(lhs, rhs),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identities_hold() {
        for a in [0u32, 1, 3, 0x1234_5678, 0xFFFF_FFFF, 0x8000_0000] {
            for b in [0u32, 1, 4, 0x9E37_79B9, 0xFFFF_FFFF] {
                assert_eq!(add_xor_and(a, b), a.wrapping_add(b));
                assert_eq!(sub_via_add_not(a, b), a.wrapping_sub(b));
                assert_eq!(xor_via_or_and(a, b), a ^ b);
                assert_eq!(and_via_add_or(a, b), a & b);
            }
        }
    }

    #[test]
    fn add_has_two_non_identity_families() {
        let fams: Vec<_> = (0u8..9).map(|s| pick_family(BinOp::Add, s)).collect();
        assert!(fams.contains(&MbaFamily::AddXorAnd));
        assert!(fams.contains(&MbaFamily::AddLea));
        assert!(fams.contains(&MbaFamily::Identity));
    }
}
