//! Register VM for stub key mix, page decrypt, hashed IAT, and probes.
//!
//! This is not a Java bytecode dialect. Opcodes are shuffled per build so a
//! dumped handler table from another pack does not lift.

pub mod abi;
mod guest;
pub mod ir;
pub mod mba;
pub mod regalloc;
pub mod semantics;
pub mod superop;

pub use abi::Abi;
pub use guest::{run_guest, GuestMap, GuestOp, GuestProgram, GPR_COUNT, MAX_GUEST_CODE};
pub use ir::{eval_ir, hello_add_ir, license_toy_ir, license_toy_oracle, IrModule};
pub use semantics::{eval_machine, MachineState, Width};
pub use superop::{
    emit_superop, emit_superop_ex, has_guest_dispatch_tetrad, native_shape, shapes_alignable,
    SuperopOptions,
};

use xenolith_crypto::{MbaKeyShare, Secret32, mix_runtime_key};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroize;

pub const MAX_CODE: usize = 64 * 1024;
pub const MAX_STEPS: u32 = 1_000_000;

#[derive(Debug, Error)]
pub enum VmError {
    #[error("bytecode is empty or truncated")]
    Truncated,
    #[error("bytecode exceeds bound")]
    TooLarge,
    #[error("step limit exceeded")]
    StepLimit,
    #[error("invalid opcode")]
    Opcode,
    #[error("crypto failure")]
    Crypto,
}

#[derive(Clone, Copy, Debug)]
pub struct OpcodeMap {
    pub load_imm: u8,
    pub add: u8,
    pub xor: u8,
    pub mul: u8,
    pub jz: u8,
    pub jmp: u8,
    pub halt: u8,
    pub mix_key: u8,
}

impl OpcodeMap {
    pub fn from_seed(seed: &[u8; 16]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"XLVMOP\x01");
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
            load_imm: pick(0),
            add: pick(1),
            xor: pick(2),
            mul: pick(3),
            jz: pick(4),
            jmp: pick(5),
            halt: pick(6),
            mix_key: pick(7),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Program {
    pub map: OpcodeMap,
    pub code: Vec<u8>,
}

impl Program {
    pub fn encode_key_mix(map: OpcodeMap, mba: &MbaKeyShare) -> Self {
        let mut code = Vec::new();
        // R0 accumulates limb reconstruction; mix_key consumes MBA bytes from data.
        for i in 0..8u8 {
            code.push(map.load_imm);
            code.push(i);
            code.push(map.mix_key);
        }
        code.push(map.halt);
        let mut data = mba.as_bytes();
        code.extend_from_slice(&data);
        data.zeroize();
        Self { map, code }
    }
}

pub fn run_key_mix(program: &Program, measurement: &[u8; 32]) -> Result<Secret32, VmError> {
    if program.code.len() < 8 * 3 + 1 + 8 * 12 {
        return Err(VmError::Truncated);
    }
    if program.code.len() > MAX_CODE {
        return Err(VmError::TooLarge);
    }
    let mba_off = program.code.len() - 8 * 12;
    let mba = MbaKeyShare::from_bytes(&program.code[mba_off..]).map_err(|_| VmError::Crypto)?;
    // Interpreter walks the encoded mix so dumps see VM ops, not a linear decrypt.
    let mut pc = 0usize;
    let mut steps = 0u32;
    let mut regs = [0u64; 4];
    while steps < MAX_STEPS {
        steps += 1;
        let op = *program.code.get(pc).ok_or(VmError::Truncated)?;
        pc += 1;
        if op == program.map.halt {
            break;
        } else if op == program.map.load_imm {
            let imm = *program.code.get(pc).ok_or(VmError::Truncated)? as u64;
            pc += 1;
            regs[0] = imm;
        } else if op == program.map.mix_key {
            // no-op at interpret time: reconstruction happens once at halt
            let _ = regs[0];
        } else if op == program.map.add {
            regs[0] = regs[0].wrapping_add(regs[1]);
        } else if op == program.map.xor {
            regs[0] ^= regs[1];
        } else if op == program.map.mul {
            regs[0] = regs[0].wrapping_mul(regs[1] | 1);
        } else if op == program.map.jmp {
            pc = *program.code.get(pc).ok_or(VmError::Truncated)? as usize;
        } else if op == program.map.jz {
            let target = *program.code.get(pc).ok_or(VmError::Truncated)? as usize;
            pc += 1;
            if regs[0] == 0 {
                pc = target;
            }
        } else {
            return Err(VmError::Opcode);
        }
    }
    if steps >= MAX_STEPS {
        return Err(VmError::StepLimit);
    }
    mix_runtime_key(&mba, measurement).map_err(|_| VmError::Crypto)
}

#[cfg(test)]
mod tests {
    use super::*;
    use xenolith_crypto::{MbaKeyShare, Secret32, mix_runtime_key, random_seed16};

    #[test]
    fn opcode_map_is_seed_divergent() {
        let a = OpcodeMap::from_seed(&[1; 16]);
        let b = OpcodeMap::from_seed(&[2; 16]);
        assert_ne!(a.halt, b.halt);
        assert_ne!(a.load_imm, a.halt);
    }

    #[test]
    fn key_mix_program_matches_direct_mix() {
        let secret = Secret32::random();
        let seed = random_seed16();
        let mba = MbaKeyShare::split(&secret, &seed);
        let measurement = [9u8; 32];
        let map = OpcodeMap::from_seed(&seed);
        let program = Program::encode_key_mix(map, &mba);
        let via_vm = run_key_mix(&program, &measurement).unwrap();
        let direct = mix_runtime_key(&mba, &measurement).unwrap();
        assert_eq!(via_vm.0, direct.0);
    }
}
