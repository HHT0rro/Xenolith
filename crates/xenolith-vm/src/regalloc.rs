//! Callee-saved / parallel-move notes for superop emission.
//!
//! Allocation still lives in `superop`. This module records ABI constraints
//! the emitter must not violate.

use crate::abi::Abi;
use crate::ir::{VREG_RAX, VREG_RCX, VREG_RDX, VREG_RSP};

pub fn callee_saved(abi: Abi) -> &'static [u8] {
    match abi {
        Abi::Win64 => &[3, 5, 6, 7, 12, 13, 14, 15], // rbx, rbp, rsi, rdi, r12-r15
        Abi::SysV64 => &[3, 5, 12, 13, 14, 15],      // rbx, rbp, r12-r15
    }
}

pub fn caller_saved(abi: Abi) -> &'static [u8] {
    match abi {
        Abi::Win64 => &[VREG_RAX, VREG_RCX, VREG_RDX, 8, 9, 10, 11],
        Abi::SysV64 => &[VREG_RAX, VREG_RCX, VREG_RDX, 6, 7, 8, 9, 10, 11],
    }
}

pub fn forbidden() -> &'static [u8] {
    &[VREG_RSP]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rsp_never_allocatable() {
        assert!(forbidden().contains(&VREG_RSP));
        assert!(!callee_saved(Abi::Win64).contains(&VREG_RSP));
        assert!(!caller_saved(Abi::SysV64).contains(&VREG_RSP));
    }
}
