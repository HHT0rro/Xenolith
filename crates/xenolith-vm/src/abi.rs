//! Win64 and SysV64 argument / return / stack layout.

use crate::ir::{VREG_RCX, VREG_RDX};

pub const VREG_R8: u8 = 8;
pub const VREG_R9: u8 = 9;
pub const VREG_RDI: u8 = 7;
pub const VREG_RSI: u8 = 6;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Abi {
    Win64,
    SysV64,
}

impl Abi {
    pub fn arg_reg(self, index: usize) -> Option<u8> {
        match self {
            Abi::Win64 => match index {
                0 => Some(VREG_RCX),
                1 => Some(VREG_RDX),
                2 => Some(VREG_R8),
                3 => Some(VREG_R9),
                _ => None,
            },
            Abi::SysV64 => match index {
                0 => Some(VREG_RDI),
                1 => Some(VREG_RSI),
                2 => Some(VREG_RDX),
                3 => Some(VREG_RCX),
                4 => Some(VREG_R8),
                5 => Some(VREG_R9),
                _ => None,
            },
        }
    }

    pub fn register_args(self) -> usize {
        match self {
            Abi::Win64 => 4,
            Abi::SysV64 => 6,
        }
    }

    pub fn shadow_space(self) -> u64 {
        match self {
            Abi::Win64 => 32,
            Abi::SysV64 => 0,
        }
    }

    pub fn red_zone(self) -> u64 {
        match self {
            Abi::SysV64 => 128,
            Abi::Win64 => 0,
        }
    }

    /// Address of stack argument `index` (0-based, including register args).
    pub fn stack_arg_addr(self, rsp: u64, index: usize) -> u64 {
        let nreg = self.register_args();
        assert!(index >= nreg);
        let slot = (index - nreg) as u64;
        rsp + self.shadow_space() + 8 + slot * 8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn win64_four_regs_then_stack() {
        assert_eq!(Abi::Win64.arg_reg(0), Some(VREG_RCX));
        assert_eq!(Abi::Win64.arg_reg(3), Some(VREG_R9));
        assert_eq!(Abi::Win64.arg_reg(4), None);
        assert_eq!(Abi::Win64.shadow_space(), 32);
        assert_eq!(Abi::Win64.stack_arg_addr(0x1000, 4), 0x1000 + 32 + 8);
    }

    #[test]
    fn sysv_six_regs_red_zone() {
        assert_eq!(Abi::SysV64.arg_reg(0), Some(VREG_RDI));
        assert_eq!(Abi::SysV64.arg_reg(5), Some(VREG_R9));
        assert_eq!(Abi::SysV64.arg_reg(6), None);
        assert_eq!(Abi::SysV64.red_zone(), 128);
        assert_eq!(Abi::SysV64.stack_arg_addr(0x2000, 6), 0x2000 + 8);
    }
}
