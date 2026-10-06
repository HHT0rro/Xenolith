//! 64-bit IR + software oracle for the aarch64 virtualization pipeline
//! (vm-aarch64 design §6).
//!
//! The aarch64 engine is fixed on the 64-bit machine model: vregs 0..=30 are
//! x0..x30 and vreg 31 is SP (allowed only in whitelisted positions — the
//! lifter enforces that; the oracle treats 31 as an ordinary register so
//! SP-writes stay first-class statements). `xzr` reads are materialized as
//! `Imm(0)` at lift time; `xzr` writes are dropped. Statement-level width
//! `W` mirrors a 32-bit aarch64 datapath op: operands read low 32 bits,
//! results are zero-extended into the full vreg.

use crate::ir::{BinOp, CmpOp};
use crate::semantics::{MemError, Memory};
use thiserror::Error;

pub const VREG64_COUNT: usize = 32;
pub const VREG64_SP: u8 = 31;
pub const VREG64_X0: u8 = 0;
pub const VREG64_X1: u8 = 1;

/// Oracle sentinel for the guest SP at function entry (§7.5: the word-level
/// interpreter starts its architectural sp at exactly this value).
pub const SP_SENTINEL: u64 = 0x0000_7000_0000_F000;
/// Oracle sentinel standing in for the runtime load bias in `Bias` stmts.
pub const BIAS_SENTINEL: u64 = 0x0000_5100_0000_0000;

/// Steps are bounded so a malformed module cannot spin forever.
pub const MAX_STEPS64: u32 = 64_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Src64 {
    Reg(u8),
    Imm(u64),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Width64 {
    /// 64-bit datapath (X registers).
    X,
    /// 32-bit datapath (W registers): zero-extends on write.
    W,
}

impl Width64 {
    pub fn bits(self) -> u32 {
        match self {
            Width64::X => 64,
            Width64::W => 32,
        }
    }
    pub fn mask(self) -> u64 {
        match self {
            Width64::X => u64::MAX,
            Width64::W => 0xFFFF_FFFF,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Addr64 {
    /// `[base + disp]`, byte disp.
    BaseDisp { base: u8, disp: i32 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stmt64 {
    Mov { dst: u8, src: Src64 },
    Bin { op: BinOp, w: Width64, dst: u8, lhs: Src64, rhs: Src64 },
    Load { dst: u8, addr: Addr64, width: u8 },
    Store { addr: Addr64, src: Src64, width: u8 },
    /// adr/adrp result: `dst = load_bias + rva` (adr: exact rva; adrp: page
    /// base with lo12=0). rva is a pack-time constant — no pairing, no
    /// folding (§4).
    Bias { dst: u8, rva: u32 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Term64 {
    Ret,
    Jmp { target: usize },
    BrCmp {
        pred: CmpOp,
        w: Width64,
        lhs: Src64,
        rhs: Src64,
        then_bb: usize,
        else_bb: usize,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ir64Block {
    pub stmts: Vec<Stmt64>,
    pub term: Term64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ir64Module {
    pub blocks: Vec<Ir64Block>,
    pub entry: usize,
}

#[derive(Debug, Error, Clone, Eq, PartialEq)]
pub enum Ir64Error {
    #[error("ir64: register out of range")]
    BadReg,
    #[error("ir64: block index out of range")]
    BadBlock,
    #[error("ir64: step limit")]
    StepLimit,
    #[error("ir64: memory error: {0:?}")]
    Mem(#[from] MemError),
    #[error("ir64: unsupported statement ({0})")]
    Unsupported(&'static str),
}

/// Full machine state: the oracle's equivalence truth (§6.2).
#[derive(Clone, Debug)]
pub struct Machine64 {
    pub gpr: [u64; VREG64_COUNT],
    pub mem: Memory,
}

impl Machine64 {
    pub fn new() -> Self {
        Machine64 {
            gpr: [0; VREG64_COUNT],
            mem: Memory::new(),
        }
    }

    /// Entry state for `eval_ir64`: args in x0/x1, SP at the sentinel.
    pub fn entry(x0: u64, x1: u64) -> Self {
        let mut m = Machine64::new();
        m.gpr[VREG64_X0 as usize] = x0;
        m.gpr[VREG64_X1 as usize] = x1;
        m.gpr[VREG64_SP as usize] = SP_SENTINEL;
        m
    }
}

/// Interpret the module; returns the guest x0 at Ret.
pub fn eval_machine64(module: &Ir64Module, state: &mut Machine64) -> Result<u64, Ir64Error> {
    if module.blocks.is_empty() || module.entry >= module.blocks.len() {
        return Err(Ir64Error::BadBlock);
    }
    let mut bb = module.entry;
    let mut steps = 0u32;
    loop {
        steps += 1;
        if steps > MAX_STEPS64 {
            return Err(Ir64Error::StepLimit);
        }
        let block = module.blocks.get(bb).ok_or(Ir64Error::BadBlock)?;
        for stmt in &block.stmts {
            match *stmt {
                Stmt64::Mov { dst, src } => {
                    check_reg(dst)?;
                    let v = read_src(src, state)?;
                    write_reg(state, dst, v, Width64::X);
                }
                Stmt64::Bin { op, w, dst, lhs, rhs } => {
                    check_reg(dst)?;
                    let a = read_src(lhs, state)? & w.mask();
                    let b = read_src(rhs, state)? & w.mask();
                    let v = apply_bin64(op, a, b, w) & w.mask();
                    write_reg(state, dst, v, w);
                }
                Stmt64::Load { dst, addr, width } => {
                    check_reg(dst)?;
                    let ea = effective_addr(state, addr)?;
                    let v = state.mem.read_u64(ea, width)?;
                    // Narrow loads zero-extend into the full vreg; the
                    // Memory API already returns the zero-extended value.
                    write_reg(state, dst, v, Width64::X);
                }
                Stmt64::Store { addr, src, width } => {
                    let ea = effective_addr(state, addr)?;
                    let v = read_src(src, state)?;
                    state.mem.write_u64(ea, width, v & width_mask(width))?;
                }
                Stmt64::Bias { dst, rva } => {
                    check_reg(dst)?;
                    state.gpr[dst as usize] = BIAS_SENTINEL.wrapping_add(rva as u64);
                }
            }
        }
        match block.term {
            Term64::Ret => return Ok(state.gpr[VREG64_X0 as usize]),
            Term64::Jmp { target } => {
                if target >= module.blocks.len() {
                    return Err(Ir64Error::BadBlock);
                }
                bb = target;
            }
            Term64::BrCmp {
                pred,
                w,
                lhs,
                rhs,
                then_bb,
                else_bb,
            } => {
                if then_bb >= module.blocks.len() || else_bb >= module.blocks.len() {
                    return Err(Ir64Error::BadBlock);
                }
                let a = read_src(lhs, state)? & w.mask();
                let b = read_src(rhs, state)? & w.mask();
                let take = match w {
                    Width64::X => cmp64(pred, a, b),
                    Width64::W => crate::ir::cmp(pred, a as u32, b as u32),
                };
                bb = if take { then_bb } else { else_bb };
            }
        }
    }
}

/// Convenience entry: args in x0/x1, SP at the sentinel; result is x0.
pub fn eval_ir64(module: &Ir64Module, x0: u64, x1: u64) -> Result<u64, Ir64Error> {
    let mut st = Machine64::entry(x0, x1);
    eval_machine64(module, &mut st)
}

fn width_mask(width: u8) -> u64 {
    match width {
        1 => 0xFF,
        2 => 0xFFFF,
        4 => 0xFFFF_FFFF,
        _ => u64::MAX,
    }
}

fn check_reg(r: u8) -> Result<(), Ir64Error> {
    if (r as usize) < VREG64_COUNT {
        Ok(())
    } else {
        Err(Ir64Error::BadReg)
    }
}

fn read_src(src: Src64, state: &Machine64) -> Result<u64, Ir64Error> {
    match src {
        Src64::Imm(v) => Ok(v),
        Src64::Reg(r) => {
            check_reg(r)?;
            Ok(state.gpr[r as usize])
        }
    }
}

fn write_reg(state: &mut Machine64, dst: u8, value: u64, w: Width64) {
    state.gpr[dst as usize] = value & w.mask();
}

fn effective_addr(state: &Machine64, addr: Addr64) -> Result<u64, Ir64Error> {
    let Addr64::BaseDisp { base, disp } = addr;
    check_reg(base)?;
    Ok(state.gpr[base as usize].wrapping_add(disp as i64 as u64))
}

/// Shift counts mask to the operand width (aarch64 semantics); Sar
/// sign-extends from the operand width first.
pub fn apply_bin64(op: BinOp, lhs: u64, rhs: u64, w: Width64) -> u64 {
    let bits = w.bits();
    match op {
        BinOp::Add => lhs.wrapping_add(rhs),
        BinOp::Sub => lhs.wrapping_sub(rhs),
        BinOp::Xor => lhs ^ rhs,
        BinOp::And => lhs & rhs,
        BinOp::Or => lhs | rhs,
        BinOp::Mul => lhs.wrapping_mul(rhs),
        BinOp::Shl => {
            let cnt = (rhs as u32) & (bits - 1);
            lhs.wrapping_shl(cnt)
        }
        BinOp::Shr => {
            let cnt = (rhs as u32) & (bits - 1);
            lhs.wrapping_shr(cnt)
        }
        BinOp::Sar => {
            let cnt = (rhs as u32) & (bits - 1);
            let s = 64 - bits;
            (((lhs << s) as i64) >> (s + cnt)) as u64
        }
    }
}

fn cmp64(pred: CmpOp, lhs: u64, rhs: u64) -> bool {
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
    use crate::ir::BinOp;

    /// A2 oracle vectors: width mixing, shift-count masking at 0/31/32/63,
    /// Bias, memory, and the cmn corner views (the views the lifter's §6.3
    /// matrix builds on — verified here so the matrix itself rests on truth).
    #[test]
    fn w_writes_zero_extend() {
        let m = Ir64Module {
            entry: 0,
            blocks: vec![Ir64Block {
                stmts: vec![
                    Stmt64::Mov { dst: 2, src: Src64::Imm(u64::MAX) },
                    Stmt64::Bin {
                        op: BinOp::Add,
                        w: Width64::W,
                        dst: 2,
                        lhs: Src64::Reg(2),
                        rhs: Src64::Imm(1),
                    },
                ],
                term: Term64::Ret,
            }],
        };
        let mut st = Machine64::entry(0, 0);
        st.gpr[2] = u64::MAX;
        eval_machine64(&m, &mut st).unwrap();
        assert_eq!(st.gpr[2], 0); // 0xFFFFFFFF + 1 at W width zero-extends
    }

    #[test]
    fn x_add_keeps_high_bits() {
        let m = Ir64Module {
            entry: 0,
            blocks: vec![Ir64Block {
                stmts: vec![Stmt64::Bin {
                    op: BinOp::Add,
                    w: Width64::X,
                    dst: 2,
                    lhs: Src64::Reg(2),
                    rhs: Src64::Imm(1),
                }],
                term: Term64::Ret,
            }],
        };
        let mut st = Machine64::entry(0, 0);
        st.gpr[2] = u64::MAX;
        eval_machine64(&m, &mut st).unwrap();
        assert_eq!(st.gpr[2], 0);
        let mut st = Machine64::entry(0, 0);
        st.gpr[2] = 0x1_0000_0001;
        eval_machine64(&m, &mut st).unwrap();
        assert_eq!(st.gpr[2], 0x1_0000_0002);
    }

    #[test]
    fn shift_counts_mask_by_width() {
        // X width: counts 0/31/32/63
        for (cnt, want) in [
            (0u64, 1u64 << 0),
            (31, 1 << 31),
            (32, 1 << 32),
            (63, 1 << 63),
            (64, 1), // masked to 0
        ] {
            let m = Ir64Module {
                entry: 0,
                blocks: vec![Ir64Block {
                    stmts: vec![Stmt64::Bin {
                        op: BinOp::Shl,
                        w: Width64::X,
                        dst: 0,
                        lhs: Src64::Imm(1),
                        rhs: Src64::Imm(cnt),
                    }],
                    term: Term64::Ret,
                }],
            };
            assert_eq!(eval_ir64(&m, 0, 0).unwrap(), want, "shl #{cnt}");
        }
        // W width: 32 masks to 0
        let m = Ir64Module {
            entry: 0,
            blocks: vec![Ir64Block {
                stmts: vec![Stmt64::Bin {
                    op: BinOp::Shl,
                    w: Width64::W,
                    dst: 0,
                    lhs: Src64::Imm(1),
                    rhs: Src64::Imm(32),
                }],
                term: Term64::Ret,
            }],
        };
        assert_eq!(eval_ir64(&m, 0, 0).unwrap(), 1, "w-shl #32 masks to 0");
        // Sar at W sign-extends from bit 31
        let m = Ir64Module {
            entry: 0,
            blocks: vec![Ir64Block {
                stmts: vec![Stmt64::Bin {
                    op: BinOp::Sar,
                    w: Width64::W,
                    dst: 0,
                    lhs: Src64::Reg(2),
                    rhs: Src64::Imm(4),
                }],
                term: Term64::Ret,
            }],
        };
        let mut st = Machine64::entry(0, 0);
        st.gpr[2] = 0x8000_0000;
        eval_machine64(&m, &mut st).unwrap();
        assert_eq!(st.gpr[0], 0xF800_0000, "sar w keeps sign in low 32");
    }

    #[test]
    fn bias_adds_sentinel_plus_rva() {
        let m = Ir64Module {
            entry: 0,
            blocks: vec![Ir64Block {
                stmts: vec![Stmt64::Bias { dst: 3, rva: 0x1234 }],
                term: Term64::Ret,
            }],
        };
        let mut st = Machine64::entry(0, 0);
        eval_machine64(&m, &mut st).unwrap();
        assert_eq!(st.gpr[3], BIAS_SENTINEL + 0x1234);
    }

    #[test]
    fn load_store_roundtrip_widths() {
        let m = Ir64Module {
            entry: 0,
            blocks: vec![Ir64Block {
                stmts: vec![
                    Stmt64::Store {
                        addr: Addr64::BaseDisp { base: 31, disp: 16 },
                        src: Src64::Imm(0xAABB_CCDD_EEFF_0011),
                        width: 8,
                    },
                    Stmt64::Load {
                        dst: 4,
                        addr: Addr64::BaseDisp { base: 31, disp: 16 },
                        width: 2,
                    },
                    Stmt64::Load {
                        dst: 5,
                        addr: Addr64::BaseDisp { base: 31, disp: 16 },
                        width: 8,
                    },
                ],
                term: Term64::Ret,
            }],
        };
        let mut st = Machine64::entry(0, 0);
        eval_machine64(&m, &mut st).unwrap();
        assert_eq!(st.gpr[4], 0x0011, "narrow load zero-extends");
        assert_eq!(st.gpr[5], 0xAABB_CCDD_EEFF_0011);
    }

    #[test]
    fn branch_compare_widths() {
        // W compare: 0xFFFFFFFF > 1 unsigned? At W: 0xFFFFFFFF > 1 → true
        // unsigned; X: same. Use a signed predicate to see the width split:
        // SLt(-1, 0) is true at both; ULt(0xFFFFFFFF, 1) false at W because
        // both are W-masked... 0xFFFFFFFF < 1 is false. The width split
        // shows with high bits set: lhs = 0x1_0000_0000 at W == 0.
        let m = Ir64Module {
            entry: 0,
            blocks: vec![
                Ir64Block {
                    stmts: vec![],
                    term: Term64::BrCmp {
                        pred: CmpOp::Eq,
                        w: Width64::W,
                        lhs: Src64::Imm(0x1_0000_0000),
                        rhs: Src64::Imm(0),
                        then_bb: 1,
                        else_bb: 2,
                    },
                },
                Ir64Block {
                    stmts: vec![Stmt64::Mov { dst: 0, src: Src64::Imm(7) }],
                    term: Term64::Ret,
                },
                Ir64Block {
                    stmts: vec![Stmt64::Mov { dst: 0, src: Src64::Imm(9) }],
                    term: Term64::Ret,
                },
            ],
        };
        assert_eq!(eval_ir64(&m, 0, 0).unwrap(), 7, "W masks lhs to 0 == 0");
    }

    /// A2 cmn corner vectors: the compare views the fusion matrix relies on.
    #[test]
    fn cmn_corner_views() {
        // compare(a, -b) vs adds(a, b) — where they agree and diverge.
        let a = 1u64;
        let b = i64::MIN as u64; // rhs = INT_MIN: -rhs == rhs
        // adds view: Z = (a+b == 0)?
        let sum = a.wrapping_add(b);
        // compare view: a == -b = INT_MIN?
        let neg_b = b.wrapping_neg();
        // eq predicate: hardware Z ⟺ a+b==0; compare ⟺ a == -b. For
        // a=1, b=INT_MIN: a+b != 0 and a != INT_MIN → both false → eq is
        // EXACT for the register-form cmn (as §6.3 claims).
        assert_eq!(sum == 0, a == neg_b);
        // ge predicate divergence: hardware N==V; compare view SGe(a,-b).
        // a=1, b=INT_MIN → sum = INT_MIN+1 (N=1, V=0) → ge false.
        let n = (sum as i64) < 0;
        let v = (a as i64).checked_add(b as i64).is_none();
        let hw_ge = n == v;
        let cmp_ge = (a as i64) >= (neg_b as i64);
        assert_ne!(hw_ge, cmp_ge, "the V-corner divergence §6.3 rejects");
        // C corner: cmn a, #0 → hardware C=0, compare(a,0) says UGe true.
        let b0 = 0u64;
        let carry = (a as u128) + (b0 as u128) >= 1 << 64;
        let cmp_uge = a >= b0;
        assert!(!carry && cmp_uge, "the C-corner divergence §6.3 rejects");
    }

    #[test]
    fn sp_sentinel_flows_through_statements() {
        let m = Ir64Module {
            entry: 0,
            blocks: vec![Ir64Block {
                stmts: vec![
                    Stmt64::Mov { dst: 2, src: Src64::Reg(VREG64_SP) },
                    Stmt64::Bin {
                        op: BinOp::Sub,
                        w: Width64::X,
                        dst: VREG64_SP,
                        lhs: Src64::Reg(VREG64_SP),
                        rhs: Src64::Imm(32),
                    },
                    Stmt64::Load {
                        dst: 3,
                        addr: Addr64::BaseDisp { base: VREG64_SP, disp: 0 },
                        width: 8,
                    },
                ],
                term: Term64::Ret,
            }],
        };
        let mut st = Machine64::entry(0, 0);
        // Seed a value below the sentinel so the load can read it.
        st.mem
            .write_u64(SP_SENTINEL - 32, 8, 0x1234)
            .unwrap();
        eval_machine64(&m, &mut st).unwrap();
        assert_eq!(st.gpr[2], SP_SENTINEL);
        assert_eq!(st.gpr[3], 0x1234);
        assert_eq!(st.gpr[31], SP_SENTINEL - 32);
    }
}
