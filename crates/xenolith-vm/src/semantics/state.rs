//! 64-bit AMD64 machine state. `eval_ir` is a Win64 two-u32 wrapper around this.

use super::flags::Flags;
use super::memory::{MemError, Memory};
use crate::ir::{cmp, Addr, AtomicOpIr, BinOp, CvtKind, FOp, FWidth, IrError, IrModule, Src, Stmt, Term, VecOp, VREG_COUNT, VREG_RAX, VREG_RCX, VREG_RDX, VREG_RSP};
use crate::abi::Abi;
use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Width {
    B8,
    B16,
    B32,
    B64,
}

impl Width {
    pub fn from_bytes(n: u8) -> Self {
        match n {
            1 => Width::B8,
            2 => Width::B16,
            4 => Width::B32,
            _ => Width::B64,
        }
    }

    pub fn bits(self) -> u32 {
        match self {
            Width::B8 => 8,
            Width::B16 => 16,
            Width::B32 => 32,
            Width::B64 => 64,
        }
    }

    pub fn bytes(self) -> u8 {
        (self.bits() / 8) as u8
    }

    pub fn mask(self) -> u64 {
        match self {
            Width::B8 => 0xff,
            Width::B16 => 0xffff,
            Width::B32 => 0xffff_ffff,
            Width::B64 => u64::MAX,
        }
    }
}

#[derive(Debug, Error, Clone, Eq, PartialEq)]
pub enum MachineError {
    #[error(transparent)]
    Ir(#[from] IrError),
    #[error(transparent)]
    Mem(#[from] MemError),
    #[error("unsupported semantic")]
    Unsupported,
    #[error("call stack overflow")]
    Call,
}

#[derive(Clone, Debug)]
pub struct MachineState {
    pub gpr: [u64; VREG_COUNT],
    pub flags: Flags,
    pub rip: u64,
    pub mem: Memory,
    pub abi: Abi,
    pub width: Width,
    /// G4: MXCSR for float/vector stmts (defaults match the OS).
    pub mxcsr: super::float::Mxcsr,
}

impl MachineState {
    pub fn new(abi: Abi) -> Self {
        let mut s = Self {
            gpr: [0; VREG_COUNT],
            flags: Flags::default(),
            rip: 0,
            mem: Memory::new(),
            abi,
            width: Width::B64,
            mxcsr: super::float::Mxcsr::new(),
        };
        s.gpr[VREG_RSP as usize] = 0x0000_7fff_ffff_f000;
        s
    }

    pub fn from_win64_u32(rcx: u32, rdx: u32) -> Self {
        let mut s = Self::new(Abi::Win64);
        s.width = Width::B32;
        s.gpr[VREG_RCX as usize] = rcx as u64;
        s.gpr[VREG_RDX as usize] = rdx as u64;
        s
    }

    pub fn write_arg(&mut self, index: usize, value: u64) -> Result<(), MachineError> {
        if let Some(reg) = self.abi.arg_reg(index) {
            self.gpr[reg as usize] = value;
            return Ok(());
        }
        let slot = self.abi.stack_arg_addr(self.gpr[VREG_RSP as usize], index);
        self.mem
            .write_u64(slot, 8, value)
            .map_err(MachineError::from)
    }

    pub fn ret_value(&self) -> u64 {
        self.gpr[VREG_RAX as usize]
    }
}

pub fn eval_machine(module: &IrModule, state: &mut MachineState) -> Result<u64, MachineError> {
    if module.blocks.is_empty() || module.entry >= module.blocks.len() {
        return Err(MachineError::Ir(IrError::BadBlock));
    }
    let mask = state.width.mask();
    let mut bb = module.entry;
    let mut steps = 0u32;
    const MAX_STEPS: u32 = 64_000;
    loop {
        steps += 1;
        if steps > MAX_STEPS {
            return Err(MachineError::Ir(IrError::StepLimit));
        }
        let block = module.blocks.get(bb).ok_or(IrError::BadBlock)?;
        for stmt in &block.stmts {
            match *stmt {
                Stmt::Mov { dst, src } => {
                    check_reg(dst, state.width)?;
                    let v = read_src(src, state, mask)?;
                    write_reg(state, dst, v, mask);
                }
                Stmt::Bin { op, dst, lhs, rhs } => {
                    check_reg(dst, state.width)?;
                    let a = read_src(lhs, state, mask)?;
                    let b = read_src(rhs, state, mask)?;
                    let v = apply_bin64(op, a, b, state.width.bits()) & mask;
                    write_reg(state, dst, v, mask);
                    if matches!(op, BinOp::Sub) {
                        state.flags = Flags::from_sub(a, b, state.width.bits());
                    }
                }
                Stmt::Load { dst, addr, width } => {
                    check_reg(dst, state.width)?;
                    let ea = effective_addr(state, addr, mask)?;
                    let v = state.mem.read_u64(ea, width)?;
                    write_reg(state, dst, v, Width::from_bytes(width).mask());
                }
                Stmt::Store { addr, src, width } => {
                    let ea = effective_addr(state, addr, mask)?;
                    let v = read_src(src, state, Width::from_bytes(width).mask())?;
                    state.mem.write_u64(ea, width, v)?;
                }
                Stmt::CallDirect { target_rva: _ } => {
                    return Err(MachineError::Unsupported);
                }
                Stmt::FScalar { op, width, dst, lhs, rhs } => {
                    check_reg(dst, Width::B64)?;
                    let a = read_src64(lhs, state)?;
                    let b = read_src64(rhs, state)?;
                    let v = eval_fscalar(op, width, a, b, &mut state.mxcsr)?;
                    state.gpr[dst as usize] = v;
                }
                Stmt::FCvt { kind, dst, src } => {
                    check_reg(dst, Width::B64)?;
                    let v = read_src64(src, state)?;
                    state.gpr[dst as usize] = eval_fcvt(kind, v)?;
                }
                Stmt::FCmp { width, dst, lhs, rhs } => {
                    check_reg(dst, Width::B64)?;
                    let a = read_src64(lhs, state)?;
                    let b = read_src64(rhs, state)?;
                    state.gpr[dst as usize] = match width {
                        FWidth::F32 => {
                            let (zf, _pf, cf) = super::float::comis_f32(a as u32, b as u32);
                            code_of(zf, cf)
                        }
                        FWidth::F64 => {
                            let (zf, _pf, cf) = super::float::comis_f64(a, b);
                            code_of(zf, cf)
                        }
                        FWidth::X87 => return Err(MachineError::Unsupported),
                    };
                }
                Stmt::VecBin { op, dst, dst_hi, lhs_lo, lhs_hi, rhs_lo, rhs_hi } => {
                    check_reg(dst, Width::B64)?;
                    check_reg(dst_hi, Width::B64)?;
                    let mut x = [0u8; 16];
                    let mut y = [0u8; 16];
                    x[..8].copy_from_slice(&read_src64(lhs_lo, state)?.to_le_bytes());
                    x[8..].copy_from_slice(&read_src64(lhs_hi, state)?.to_le_bytes());
                    y[..8].copy_from_slice(&read_src64(rhs_lo, state)?.to_le_bytes());
                    y[8..].copy_from_slice(&read_src64(rhs_hi, state)?.to_le_bytes());
                    let r = eval_vec(op, x, y, &mut state.mxcsr)?;
                    state.gpr[dst as usize] = u64::from_le_bytes(r[..8].try_into().unwrap());
                    state.gpr[dst_hi as usize] = u64::from_le_bytes(r[8..].try_into().unwrap());
                }
                Stmt::Atomic { op, addr, width, expect, incoming, dst, zf_dst } => {
                    check_reg(dst, Width::B64)?;
                    check_reg(zf_dst, Width::B64)?;
                    check_reg(expect, Width::B64)?;
                    let ea = effective_addr(state, addr, u64::MAX)?;
                    let inc = read_src64(incoming, state)?;
                    let exp = state.gpr[expect as usize];
                    let (old, zf) = super::atomic::atomic_rmw(
                        match op {
                            AtomicOpIr::CmpXchg => super::atomic::AtomicOp::CmpXchg,
                            AtomicOpIr::XAdd => super::atomic::AtomicOp::XAdd,
                            AtomicOpIr::Xchg => super::atomic::AtomicOp::Xchg,
                        },
                        &mut state.mem,
                        ea,
                        width,
                        exp,
                        inc,
                        super::atomic::MemOrder::SeqCst,
                    )
                    .map_err(|_| MachineError::Unsupported)?;
                    state.gpr[dst as usize] = old;
                    state.gpr[zf_dst as usize] = zf.unwrap_or(false) as u64;
                }
            }
        }
        match block.term {
            Term::Ret => return Ok(state.gpr[VREG_RAX as usize] & mask),
            Term::Jmp { target } => {
                if target >= module.blocks.len() {
                    return Err(MachineError::Ir(IrError::BadBlock));
                }
                bb = target;
            }
            Term::BrCmp {
                pred,
                lhs,
                rhs,
                then_bb,
                else_bb,
            } => {
                if then_bb >= module.blocks.len() || else_bb >= module.blocks.len() {
                    return Err(MachineError::Ir(IrError::BadBlock));
                }
                let a = read_src(lhs, state, mask)?;
                let b = read_src(rhs, state, mask)?;
                let take = if state.width == Width::B32 {
                    cmp(pred, a as u32, b as u32)
                } else {
                    cmp64(pred, a, b)
                };
                bb = if take { then_bb } else { else_bb };
            }
        }
    }
}


fn read_src64(src: Src, state: &MachineState) -> Result<u64, MachineError> {
    read_src(src, state, u64::MAX)
}

/// comiss result encoding shared with codegen: 0 eq, 1 above, 2 below, 3 unordered.
fn code_of(zf: bool, cf: bool) -> u64 {
    if zf && cf {
        3
    } else if cf {
        2
    } else if zf {
        0
    } else {
        1
    }
}

fn eval_fscalar(
    op: FOp,
    width: FWidth,
    a: u64,
    b: u64,
    mxcsr: &mut super::float::Mxcsr,
) -> Result<u64, MachineError> {
    use super::float::{sse_f32, sse_f64, sse_sqrt_f32, sse_sqrt_f64, x87_bin, F80, ScalarOp};
    let sop = |op: FOp| match op {
        FOp::Add => ScalarOp::Add,
        FOp::Sub => ScalarOp::Sub,
        FOp::Mul => ScalarOp::Mul,
        FOp::Div => ScalarOp::Div,
        FOp::Min => ScalarOp::Min,
        FOp::Max => ScalarOp::Max,
        FOp::Sqrt => ScalarOp::Add,
    };
    match (op, width) {
        (FOp::Sqrt, FWidth::F32) => Ok(sse_sqrt_f32(a as u32, mxcsr) as u64),
        (FOp::Sqrt, FWidth::F64) => Ok(sse_sqrt_f64(a, mxcsr)),
        (_, FWidth::X87) => {
            if matches!(op, FOp::Sqrt) {
                // f64-representable sqrt via the 80-bit model (exact for the
                // frozen corpus: f64 in, f64 out).
                let x = F80::from_f64(f64::from_bits(a));
                if x.is_nan() {
                    // fsqrt quiets SNaN inputs.
                    return Ok(x.quiet().to_f64().to_bits());
                }
                if x.sign && !x.is_zero() {
                    return Ok(super::float::F80_INDEFINITE.to_f64().to_bits());
                }
                return Ok(f64::from_bits(a).sqrt().to_bits());
            }
            let r = x87_bin(sop(op), F80::from_f64(f64::from_bits(a)), F80::from_f64(f64::from_bits(b)));
            Ok(r.to_f64().to_bits())
        }
        (_, FWidth::F32) => Ok(sse_f32(sop(op), a as u32, b as u32, mxcsr) as u64),
        (_, FWidth::F64) => Ok(sse_f64(sop(op), a, b, mxcsr)),
    }
}

fn eval_fcvt(kind: CvtKind, v: u64) -> Result<u64, MachineError> {
    use super::float::*;
    Ok(match kind {
        CvtKind::I32F32 => (v as u32 as i32 as f32).to_bits() as u64,
        CvtKind::I32F64 => (v as u32 as i32 as f64).to_bits(),
        CvtKind::I64F32 => (v as i64 as f32).to_bits() as u64,
        CvtKind::I64F64 => (v as i64 as f64).to_bits(),
        CvtKind::F32I32T => cvtt_f32_i32(v as u32) as u32 as u64,
        CvtKind::F64I32T => cvtt_f64_i32(v) as u32 as u64,
        CvtKind::F32I64T => cvtt_f32_i64(v as u32) as u64,
        CvtKind::F64I64T => cvtt_f64_i64(v) as u64,
        CvtKind::F32I32R => cvt_rne_f32_i32(v as u32) as u32 as u64,
        CvtKind::F64I64R => cvt_rne_f64_i64(v) as u64,
        CvtKind::F32F64 => cvt_f32_f64(v as u32),
        CvtKind::F64F32 => cvt_f64_f32(v) as u64,
    })
}

fn eval_vec(
    op: VecOp,
    x: [u8; 16],
    y: [u8; 16],
    mxcsr: &mut super::float::Mxcsr,
) -> Result<[u8; 16], MachineError> {
    use super::vector::*;
    let mut out = [0u8; 16];
    let ok = match op {
        VecOp::PAddD => int_vec(IntVecOp::Add, Lane::B32, &x, &y, &mut out),
        VecOp::PSubD => int_vec(IntVecOp::Sub, Lane::B32, &x, &y, &mut out),
        VecOp::PMulLW => int_vec(IntVecOp::MullW, Lane::B16, &x, &y, &mut out),
        VecOp::PMulHW => int_vec(IntVecOp::MulHW, Lane::B16, &x, &y, &mut out),
        VecOp::PMulLD => int_vec(IntVecOp::MulLd, Lane::B32, &x, &y, &mut out),
        VecOp::PMinSD => int_vec(IntVecOp::MinSd, Lane::B32, &x, &y, &mut out),
        VecOp::PMaxSD => int_vec(IntVecOp::MaxSd, Lane::B32, &x, &y, &mut out),
        VecOp::PAnd => int_vec(IntVecOp::And, Lane::B64, &x, &y, &mut out),
        VecOp::POr => int_vec(IntVecOp::Or, Lane::B64, &x, &y, &mut out),
        VecOp::PXor => int_vec(IntVecOp::Xor, Lane::B64, &x, &y, &mut out),
        VecOp::PCmpEqD => int_vec(IntVecOp::CmpEq, Lane::B32, &x, &y, &mut out),
        VecOp::PAddPS => {
            out = f32_vec(FloatVecOp::Add, &x, &y, mxcsr);
            true
        }
        VecOp::PMulPS => {
            out = f32_vec(FloatVecOp::Mul, &x, &y, mxcsr);
            true
        }
        VecOp::PAddPD => {
            out = f64_vec(FloatVecOp::Add, &x, &y, mxcsr);
            true
        }
        VecOp::PShufD(imm) => {
            // pshufd dst, src: the shuffle reads the SECOND operand (rhs),
            // matching the codegen (`pshufd xmm0, xmm1, imm`).
            out = pshufd(&y, imm);
            true
        }
        VecOp::Punpcklqdq => {
            out = punpcklqdq(&x, &y);
            true
        }
    };
    if !ok {
        return Err(MachineError::Unsupported);
    }
    Ok(out)
}

fn check_reg(r: u8, width: Width) -> Result<(), MachineError> {
    if (r as usize) < VREG_COUNT && (width == Width::B64 || r != VREG_RSP) {
        Ok(())
    } else if r == VREG_RSP && width != Width::B64 {
        Err(MachineError::Ir(IrError::BadReg))
    } else if (r as usize) >= VREG_COUNT {
        Err(MachineError::Ir(IrError::BadReg))
    } else {
        Ok(())
    }
}

fn read_src(src: Src, state: &MachineState, mask: u64) -> Result<u64, MachineError> {
    match src {
        Src::Imm(v) => Ok(v as u64 & mask),
        Src::Reg(r) => {
            check_reg(r, state.width)?;
            Ok(state.gpr[r as usize] & mask)
        }
    }
}

fn write_reg(state: &mut MachineState, dst: u8, value: u64, mask: u64) {
    match state.width {
        Width::B64 => state.gpr[dst as usize] = value,
        Width::B32 => state.gpr[dst as usize] = value & 0xffff_ffff,
        Width::B16 => {
            let old = state.gpr[dst as usize];
            state.gpr[dst as usize] = (old & !0xffff) | (value & 0xffff);
        }
        Width::B8 => {
            let old = state.gpr[dst as usize];
            state.gpr[dst as usize] = (old & !0xff) | (value & 0xff);
        }
    }
    let _ = mask;
}

fn effective_addr(state: &MachineState, addr: Addr, mask: u64) -> Result<u64, MachineError> {
    match addr {
        Addr::BaseDisp { base, disp } => {
            check_reg(base, state.width)?;
            Ok((state.gpr[base as usize] & mask).wrapping_add(disp as i64 as u64))
        }
    }
}

fn apply_bin64(op: BinOp, lhs: u64, rhs: u64, width_bits: u32) -> u64 {
    match op {
        BinOp::Add => lhs.wrapping_add(rhs),
        BinOp::Sub => lhs.wrapping_sub(rhs),
        BinOp::Xor => lhs ^ rhs,
        BinOp::And => lhs & rhs,
        BinOp::Or => lhs | rhs,
        BinOp::Mul => lhs.wrapping_mul(rhs),
        // x86 masks the shift count to the operand width (`& (bits-1)`); the
        // caller masks the result back to `width` so only the low bits matter.
        BinOp::Shl => {
            let cnt = (rhs as u32) & (width_bits - 1);
            lhs.wrapping_shl(cnt)
        }
        BinOp::Shr => {
            let cnt = (rhs as u32) & (width_bits - 1);
            lhs.wrapping_shr(cnt)
        }
        BinOp::Sar => {
            let cnt = (rhs as u32) & (width_bits - 1);
            // Sign-extend the width-sized value into i64, then arithmetic-shift.
            let s = 64 - width_bits;
            (((lhs << s) as i64) >> (s + cnt)) as u64
        }
    }
}

fn cmp64(pred: crate::ir::CmpOp, lhs: u64, rhs: u64) -> bool {
    use crate::ir::CmpOp::*;
    match pred {
        Eq => lhs == rhs,
        Ne => lhs != rhs,
        ULt => lhs < rhs,
        ULe => lhs <= rhs,
        UGt => lhs > rhs,
        UGe => lhs >= rhs,
        SLt => (lhs as i64) < (rhs as i64),
        SLe => (lhs as i64) <= (rhs as i64),
        SGt => (lhs as i64) > (rhs as i64),
        SGe => (lhs as i64) >= (rhs as i64),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{hello_add_ir, license_toy_ir};

    #[test]
    fn machine_matches_eval_ir_hello_add() {
        let ir = hello_add_ir();
        let mut st = MachineState::from_win64_u32(3, 4);
        let v = eval_machine(&ir, &mut st).unwrap();
        assert_eq!(v, 7);
    }

    #[test]
    fn machine_matches_license_toy() {
        let ir = license_toy_ir();
        for x in 0..64u32 {
            for y in 0..64u32 {
                let mut st = MachineState::from_win64_u32(x, y);
                let v = eval_machine(&ir, &mut st).unwrap() as u32;
                assert_eq!(v, crate::ir::license_toy_oracle(x, y));
            }
        }
    }

    #[test]
    fn memory_roundtrip_and_partial_reg() {
        let mut st = MachineState::new(Abi::Win64);
        st.width = Width::B64;
        st.mem.write_u64(0x2000, 8, 0x0102_0304_0506_0708).unwrap();
        assert_eq!(st.mem.read_u64(0x2000, 8).unwrap(), 0x0102_0304_0506_0708);
        st.gpr[1] = 0xaaaa_aaaa_aaaa_aaaa;
        st.width = Width::B8;
        write_reg(&mut st, 1, 0x11, 0xff);
        assert_eq!(st.gpr[1], 0xaaaa_aaaa_aaaa_aa11);
        st.width = Width::B32;
        write_reg(&mut st, 1, 0x1234_5678, 0xffff_ffff);
        assert_eq!(st.gpr[1], 0x1234_5678);
        assert!(st.mem.read_u64(0x3000, 4).is_err());
    }

    #[test]
    fn win64_fifth_arg_is_stack_slot() {
        let mut st = MachineState::new(Abi::Win64);
        st.gpr[VREG_RSP as usize] = 0x1000;
        st.write_arg(0, 1).unwrap();
        st.write_arg(4, 0xdead_beef).unwrap();
        let addr = Abi::Win64.stack_arg_addr(0x1000, 4);
        assert_eq!(st.mem.read_u64(addr, 8).unwrap(), 0xdead_beef);
        assert_eq!(st.gpr[VREG_RCX as usize], 1);
    }

    #[test]
    fn load_store_ir() {
        use crate::ir::{Addr, IrBlock, IrModule, Stmt, Term};
        let ir = IrModule {
            entry: 0,
            blocks: vec![IrBlock {
                stmts: vec![
                    Stmt::Load {
                        dst: VREG_RAX,
                        addr: Addr::BaseDisp {
                            base: VREG_RCX,
                            disp: 0,
                        },
                        width: 4,
                    },
                    Stmt::Store {
                        addr: Addr::BaseDisp {
                            base: VREG_RDX,
                            disp: 0,
                        },
                        src: Src::Reg(VREG_RAX),
                        width: 4,
                    },
                ],
                term: Term::Ret,
            }],
        };
        let mut st = MachineState::from_win64_u32(0x2000, 0x3000);
        st.mem.write_u64(0x2000, 4, 7).unwrap();
        st.mem.write_u64(0x3000, 4, 0).unwrap();
        assert_eq!(eval_machine(&ir, &mut st).unwrap(), 7);
        assert_eq!(st.mem.read_u64(0x3000, 4).unwrap(), 7);
        let pic = crate::emit_superop(&ir, &[3; 16]).unwrap();
        assert!(!pic.is_empty());
    }
}
