//! Guest VM for selected exported functions.
//! Retired GuestMap ISA (host fixture only). The packed stub no longer
//! emits `l_gloop`. Kept so leftover bytecode fails `run_guest` instead of
//! silently decoding. Must not share `OpcodeMap` (`XLVMOP\x01` / `ENV_OPCODES`).

use sha2::{Digest, Sha256};

use crate::{VmError, MAX_CODE, MAX_STEPS};

pub const MAX_GUEST_CODE: usize = MAX_CODE;
pub const GPR_COUNT: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GuestMap {
    pub mov32: u8,
    pub add32: u8,
    pub lea_sum32: u8,
    pub halt: u8,
}

impl GuestMap {
    pub fn from_seed(seed: &[u8; 16]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"XLGVM\x01");
        hasher.update(seed);
        let digest = hasher.finalize();
        let mut used = [false; 256];
        let mut pick = |i: usize| -> u8 {
            let mut v = digest[i];
            while used[v as usize] {
                v = v.wrapping_add(17);
            }
            used[v as usize] = true;
            v
        };
        Self {
            mov32: pick(0),
            add32: pick(1),
            lea_sum32: pick(2),
            halt: pick(3),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GuestOp {
    Mov32 { dst: u8, src: u8 },
    Add32 { dst: u8, src: u8 },
    LeaSum32 { dst: u8, a: u8, b: u8 },
    Halt,
}

#[derive(Clone, Debug)]
pub struct GuestProgram {
    pub map: GuestMap,
    pub code: Vec<u8>,
}

impl GuestProgram {
    pub fn encode(map: GuestMap, ops: &[GuestOp]) -> Result<Self, VmError> {
        let mut code = Vec::new();
        for op in ops {
            match *op {
                GuestOp::Mov32 { dst, src } => {
                    check_reg(dst)?;
                    check_reg(src)?;
                    code.push(map.mov32);
                    code.push(dst);
                    code.push(src);
                }
                GuestOp::Add32 { dst, src } => {
                    check_reg(dst)?;
                    check_reg(src)?;
                    code.push(map.add32);
                    code.push(dst);
                    code.push(src);
                }
                GuestOp::LeaSum32 { dst, a, b } => {
                    check_reg(dst)?;
                    check_reg(a)?;
                    check_reg(b)?;
                    code.push(map.lea_sum32);
                    code.push(dst);
                    code.push(a);
                    code.push(b);
                }
                GuestOp::Halt => code.push(map.halt),
            }
        }
        if code.is_empty() {
            return Err(VmError::Truncated);
        }
        if code.len() > MAX_GUEST_CODE {
            return Err(VmError::TooLarge);
        }
        Ok(Self { map, code })
    }
}

fn check_reg(r: u8) -> Result<(), VmError> {
    if (r as usize) < GPR_COUNT {
        Ok(())
    } else {
        Err(VmError::Opcode)
    }
}

fn write32(regs: &mut [u64; GPR_COUNT], idx: u8, value: u32) -> Result<(), VmError> {
    let i = idx as usize;
    if i >= GPR_COUNT {
        return Err(VmError::Opcode);
    }
    regs[i] = value as u64;
    Ok(())
}

fn read32(regs: &[u64; GPR_COUNT], idx: u8) -> Result<u32, VmError> {
    let i = idx as usize;
    if i >= GPR_COUNT {
        return Err(VmError::Opcode);
    }
    Ok(regs[i] as u32)
}

/// Interpret `program` with Win64 args in virtual RCX/RDX. Result is EAX.
pub fn run_guest(program: &GuestProgram, rcx: u64, rdx: u64) -> Result<u32, VmError> {
    if program.code.is_empty() {
        return Err(VmError::Truncated);
    }
    if program.code.len() > MAX_GUEST_CODE {
        return Err(VmError::TooLarge);
    }
    let mut regs = [0u64; GPR_COUNT];
    regs[1] = rcx;
    regs[2] = rdx;
    let mut pc = 0usize;
    let mut steps = 0u32;
    while steps < MAX_STEPS {
        steps += 1;
        let op = *program.code.get(pc).ok_or(VmError::Truncated)?;
        pc += 1;
        if op == program.map.halt {
            return Ok(regs[0] as u32);
        } else if op == program.map.mov32 {
            let dst = *program.code.get(pc).ok_or(VmError::Truncated)?;
            pc += 1;
            let src = *program.code.get(pc).ok_or(VmError::Truncated)?;
            pc += 1;
            let v = read32(&regs, src)?;
            write32(&mut regs, dst, v)?;
        } else if op == program.map.add32 {
            let dst = *program.code.get(pc).ok_or(VmError::Truncated)?;
            pc += 1;
            let src = *program.code.get(pc).ok_or(VmError::Truncated)?;
            pc += 1;
            let v = read32(&regs, dst)?.wrapping_add(read32(&regs, src)?);
            write32(&mut regs, dst, v)?;
        } else if op == program.map.lea_sum32 {
            let dst = *program.code.get(pc).ok_or(VmError::Truncated)?;
            pc += 1;
            let a = *program.code.get(pc).ok_or(VmError::Truncated)?;
            pc += 1;
            let b = *program.code.get(pc).ok_or(VmError::Truncated)?;
            pc += 1;
            let v = read32(&regs, a)?.wrapping_add(read32(&regs, b)?);
            write32(&mut regs, dst, v)?;
        } else {
            return Err(VmError::Opcode);
        }
    }
    Err(VmError::StepLimit)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guest_map_is_seed_divergent() {
        let a = GuestMap::from_seed(&[1; 16]);
        let b = GuestMap::from_seed(&[2; 16]);
        assert_ne!(a.halt, b.halt);
        assert_ne!(a.mov32, a.halt);
        assert_ne!(a.add32, a.lea_sum32);
    }

    #[test]
    fn lea_sum_hello_add() {
        let map = GuestMap::from_seed(&[9; 16]);
        let program = GuestProgram::encode(
            map,
            &[
                GuestOp::LeaSum32 {
                    dst: 0,
                    a: 1,
                    b: 2,
                },
                GuestOp::Halt,
            ],
        )
        .unwrap();
        assert_eq!(run_guest(&program, 3, 4).unwrap(), 7);
        assert_eq!(run_guest(&program, u32::MAX as u64, 1).unwrap(), 0);
    }

    #[test]
    fn mov_add_hello_add() {
        let map = GuestMap::from_seed(&[3; 16]);
        let program = GuestProgram::encode(
            map,
            &[
                GuestOp::Mov32 { dst: 0, src: 1 },
                GuestOp::Add32 { dst: 0, src: 2 },
                GuestOp::Halt,
            ],
        )
        .unwrap();
        assert_eq!(run_guest(&program, 3, 4).unwrap(), 7);
    }

    #[test]
    fn superop_pic_is_not_guest_bytecode() {
        let pic = crate::emit_superop(&crate::hello_add_ir(), &[1; 16]).unwrap();
        let program = GuestProgram {
            map: GuestMap::from_seed(&[1; 16]),
            code: pic,
        };
        assert!(run_guest(&program, 3, 4).is_err());
    }
}
