//! A4/A4b/A5/A7 gates for the aarch64 superop emitter.
//!
//! The word-level interpreter (A4b) executes the emitted stream through the
//! production decoder — initial architectural sp = `SP_SENTINEL` (§7.5
//! contract), bias = `BIAS_SENTINEL` — and is compared against the
//! `eval_machine64` oracle on x0, the restored SP, the restored callee-saved
//! set and the union of touched memory. A prologue/cap/mapping error shows
//! up here directly.

use super::*;
use crate::aarch64_decode::{
    decode_bitmask, decode_word, ExtendKind, Gpr, Inst64, LogicOp, PairMode, ShiftType, UbfmKind,
    VarShiftKind,
};
use crate::ir::{BinOp, CmpOp};
use crate::ir64::{
    eval_machine64, Addr64, Ir64Block, Machine64, Src64, Width64, BIAS_SENTINEL, SP_SENTINEL,
    VREG64_SP,
};
use crate::semantics::Memory;

// ---------------------------------------------------------------------
// A4b: word-level interpreter over the whitelist classes
// ---------------------------------------------------------------------

struct InterpState {
    gpr: [u64; 32], // 0..=30 GPR, 31 = architectural sp
    flags: (bool, bool, bool, bool), // N Z C V
    mem: Memory,
    bias: u64,
    steps: u32,
    touched: Vec<u64>,
}

/// Execute a thunk word stream. Initial sp = SP_SENTINEL; bias as given.
fn run_words(
    words: &[u32],
    x0: u64,
    x1: u64,
    mem_seeds: &[(u64, u8, u64)],
    bias: u64,
) -> Result<(u64, u64, [u64; 32], Memory, Vec<u64>), String> {
    let mut st = InterpState {
        gpr: [0; 32],
        flags: (false, false, false, false),
        mem: Memory::new(),
        bias,
        steps: 0,
        touched: Vec::new(),
    };
    st.gpr[0] = x0;
    st.gpr[1] = x1;
    st.gpr[31] = SP_SENTINEL;
    for &(a, w, v) in mem_seeds {
        st.mem.write_u64(a, w, v).map_err(|e| format!("seed: {e:?}"))?;
    }
    let mut pc: usize = 0; // word index
    loop {
        st.steps += 1;
        if st.steps > 64_000 {
            return Err("interp step limit".into());
        }
        let w = *words.get(pc).ok_or("fell off the thunk stream")?;
        let inst = decode_word(w).map_err(|e| format!("at word {pc} ({w:#010x}): {e}"))?;
        let bits = |sf: bool| if sf { 64u32 } else { 32u32 };
        let mask = |sf: bool| if sf { u64::MAX } else { 0xFFFF_FFFF };
        match inst {
            Inst64::AddSubImm { sf, setflags: _, sub, rd, rn, imm } => {
                let a = reg_read(&st, rn);
                let b = imm & mask(sf);
                let r = set_addsub_flags(&mut st, a, b, sub, bits(sf));
                reg_write(&mut st, rd, r, bits(sf));
            }
            Inst64::AddSubShiftReg { sf, setflags: _, sub, rd, rn, rm, shift, imm6 } => {
                let a = reg_read(&st, rn);
                let b = alu_shift(reg_read(&st, rm), shift, imm6 as u32, bits(sf));
                let r = set_addsub_flags(&mut st, a, b, sub, bits(sf));
                reg_write(&mut st, rd, r, bits(sf));
            }
            Inst64::AddSubExtReg { sf, setflags: _, sub, rd, rn, rm, ext, imm3 } => {
                let a = reg_read(&st, rn);
                let b = extend_val(reg_read(&st, rm), ext).wrapping_shl(imm3 as u32);
                let r = set_addsub_flags(&mut st, a, b, sub, bits(sf));
                reg_write(&mut st, rd, r, bits(sf));
            }
            Inst64::LogicReg { sf, op, setflags: _, rd, rn, rm, shift, imm6 } => {
                let a = reg_read(&st, rn) & mask(sf);
                let b = alu_shift(reg_read(&st, rm), shift, imm6 as u32, bits(sf));
                let r = match op {
                    LogicOp::And => a & b,
                    LogicOp::Orr => a | b,
                    LogicOp::Eor => a ^ b,
                } & mask(sf);
                set_logic_flags(&mut st, r, mask(sf));
                reg_write(&mut st, rd, r, bits(sf));
            }
            Inst64::LogicImm { sf, op, setflags: _, rd, rn, n, immr, imms } => {
                let k = decode_bitmask(n, immr, imms, sf)
                    .ok_or("logic-imm UNDEF in emitted code")?;
                let a = reg_read(&st, rn) & mask(sf);
                let r = match op {
                    LogicOp::And => a & k,
                    LogicOp::Orr => a | k,
                    LogicOp::Eor => a ^ k,
                } & mask(sf);
                set_logic_flags(&mut st, r, mask(sf));
                reg_write(&mut st, rd, r, bits(sf));
            }
            Inst64::UbfmAlias { sf, kind, signed_: _, rd, rn, amount } => {
                let v = reg_read(&st, rn);
                let b = bits(sf);
                let m = mask(sf);
                let r = match kind {
                    UbfmKind::Mov => v & m,
                    UbfmKind::Lsl => (v & m).wrapping_shl(amount as u32) & m,
                    UbfmKind::Lsr => v.wrapping_shr(amount as u32),
                    UbfmKind::Asr => (sign_ext(v & m, b) >> amount) as u64 & m,
                };
                reg_write(&mut st, rd, r, b);
            }
            Inst64::VarShift { sf, kind, rd, rn, rm } => {
                let v = reg_read(&st, rn);
                let cnt = reg_read(&st, rm) as u32;
                let b = bits(sf);
                let m = mask(sf);
                let r = match kind {
                    VarShiftKind::Lslv => (v & m).wrapping_shl(cnt & (b - 1)) & m,
                    VarShiftKind::Lsrv => (v & m).wrapping_shr(cnt & (b - 1)),
                    VarShiftKind::Asrv => {
                        (sign_ext(v & m, b) >> (cnt & (b - 1))) as u64 & m
                    }
                };
                reg_write(&mut st, rd, r, b);
            }
            Inst64::Movz { sf, rd, imm16, hw } => {
                let v = (imm16 as u64) << (hw as u32 * 16);
                reg_write(&mut st, rd, v, bits(sf));
            }
            Inst64::Movk { sf, rd, imm16, hw } => {
                let old = reg_read(&st, rd) & mask(sf);
                let sh = hw as u32 * 16;
                let v = (old & !(0xFFFFu64 << sh)) | ((imm16 as u64) << sh);
                reg_write(&mut st, rd, v, bits(sf));
            }
            Inst64::B { off } => {
                pc = ((pc as i64 * 4 + off) / 4) as usize;
                continue;
            }
            Inst64::BCond { cond, off } => {
                if eval_cond(st.flags, cond) {
                    pc = ((pc as i64 * 4 + off) / 4) as usize;
                    continue;
                }
            }
            Inst64::Cbz { sf, nz, rt, off } => {
                let v = reg_read(&st, rt) & mask(sf);
                let taken = if nz { v != 0 } else { v == 0 };
                if taken {
                    pc = ((pc as i64 * 4 + off) / 4) as usize;
                    continue;
                }
            }
            Inst64::Tbz { nz, rt, bit, off } => {
                let bit_set = (reg_read(&st, rt) >> bit) & 1 == 1;
                let taken = if nz { bit_set } else { !bit_set };
                if taken {
                    pc = ((pc as i64 * 4 + off) / 4) as usize;
                    continue;
                }
            }
            Inst64::Ret => {
                let mem = st.mem.clone();
                let touched = st.touched.clone();
                return Ok((st.gpr[0], st.gpr[31], st.gpr, mem, touched));
            }
            Inst64::LdrStr { size, load, rt, rn, off } => {
                let addr = reg_read(&st, rn).wrapping_add(off as u64);
                let width = 1u8 << size;
                st.touched.push(addr);
                if load {
                    let v = st
                        .mem
                        .read_u64(addr, width)
                        .map_err(|e| format!("interp load {addr:#x}: {e:?}"))?;
                    reg_write(&mut st, rt, v, 64);
                } else {
                    let v = reg_read(&st, rt) & wmask(width);
                    st.mem
                        .write_u64(addr, width, v)
                        .map_err(|e| format!("interp store {addr:#x}: {e:?}"))?;
                }
            }
            Inst64::LdpStp { sf, load, mode, rt, rt2, rn, off } => {
                let width: u8 = if sf { 8 } else { 4 };
                let (base, writeback) = match mode {
                    PairMode::SignedOffset => {
                        (reg_read(&st, rn).wrapping_add(off as i64 as u64), false)
                    }
                    PairMode::PreIndex => {
                        (reg_read(&st, rn).wrapping_add(off as i64 as u64), true)
                    }
                    PairMode::PostIndex => (reg_read(&st, rn), true),
                };
                // NOTE: the emitter only produces ldp/stp for the thunk
                // prologue/epilogue (guest pairs are decomposed at lift) —
                // these addresses are frame-internal, excluded from the
                // guest-memory comparison.
                if load {
                    let v1 = st
                        .mem
                        .read_u64(base, width)
                        .map_err(|e| format!("ldp {base:#x}: {e:?}"))?;
                    let v2 = st
                        .mem
                        .read_u64(base + width as u64, width)
                        .map_err(|e| format!("ldp+8 {:#x}: {e:?}", base + width as u64))?;
                    reg_write(&mut st, rt, v1, 64);
                    reg_write(&mut st, rt2, v2, 64);
                } else {
                    let v1 = reg_read(&st, rt) & wmask(width);
                    let v2 = reg_read(&st, rt2) & wmask(width);
                    st.mem
                        .write_u64(base, width, v1)
                        .map_err(|e| format!("stp {base:#x}: {e:?}"))?;
                    st.mem
                        .write_u64(base + width as u64, width, v2)
                        .map_err(|e| format!("stp+8: {e:?}"))?;
                }
                if writeback {
                    let new_base = match mode {
                        PairMode::PostIndex => base.wrapping_add(off as i64 as u64),
                        _ => base, // pre-index already applied
                    };
                    reg_write(&mut st, rn, new_base, 64);
                }
            }
            Inst64::Adr { rd, off } => {
                let addr = st
                    .bias
                    .wrapping_add((pc as u64) * 4)
                    .wrapping_add(off as u64);
                reg_write(&mut st, rd, addr, 64);
            }
            Inst64::Adrp { rd, off } => {
                let pc_b = st.bias.wrapping_add((pc as u64) * 4);
                let addr = (pc_b & !0xFFFu64).wrapping_add(off as u64);
                reg_write(&mut st, rd, addr, 64);
            }
            Inst64::Nop => {}
        }
        pc += 1;
    }
}

fn wmask(width: u8) -> u64 {
    match width {
        1 => 0xFF,
        2 => 0xFFFF,
        4 => 0xFFFF_FFFF,
        _ => u64::MAX,
    }
}

fn reg_read(st: &InterpState, g: Gpr) -> u64 {
    match g {
        Gpr::R(n) => st.gpr[n as usize],
        Gpr::Sp => st.gpr[31],
        Gpr::Zr => 0,
    }
}

fn reg_write(st: &mut InterpState, g: Gpr, v: u64, bits: u32) {
    let masked = if bits == 64 { v } else { v & ((1u64 << bits) - 1) };
    match g {
        Gpr::R(n) => st.gpr[n as usize] = masked,
        Gpr::Sp => st.gpr[31] = masked,
        Gpr::Zr => {} // write discarded
    }
}

fn sign_ext(v: u64, bits: u32) -> i64 {
    if bits == 64 {
        v as i64
    } else {
        let s = 64 - bits;
        (((v << s) as i64) >> s) as i64
    }
}

fn overflow_add(a: i64, b: i64, r: i64) -> bool {
    (a >= 0 && b >= 0 && r < 0) || (a < 0 && b < 0 && r >= 0)
}

fn overflow_sub(a: i64, b: i64, r: i64) -> bool {
    (a >= 0 && b < 0 && r < 0) || (a < 0 && b >= 0 && r >= 0)
}

fn set_addsub_flags(st: &mut InterpState, a: u64, b: u64, sub: bool, bits: u32) -> u64 {
    let m = if bits == 64 { u64::MAX } else { (1u64 << bits) - 1 };
    let (a, b) = (a & m, b & m);
    let (r, c) = if sub {
        (a.wrapping_sub(b), a >= b) // C = NOT borrow
    } else {
        let c = (a as u128) + (b as u128) >= 1u128 << bits;
        (a.wrapping_add(b), c)
    };
    let v = if sub {
        overflow_sub(sign_ext(a, bits), sign_ext(b, bits), sign_ext(r & m, bits))
    } else {
        overflow_add(sign_ext(a, bits), sign_ext(b, bits), sign_ext(r & m, bits))
    };
    st.flags = ((r >> (bits - 1)) & 1 == 1, r & m == 0, c, v);
    r & m
}

fn set_logic_flags(st: &mut InterpState, r: u64, m: u64) {
    st.flags = ((r >> 63) & 1 == 1, r & m == 0, false, false);
}

fn eval_cond(f: (bool, bool, bool, bool), cond: u8) -> bool {
    let (n, z, c, v) = f;
    match cond {
        0 => z,
        1 => !z,
        2 => c,
        3 => !c,
        8 => c && !z,
        9 => !c || z,
        10 => n == v,
        11 => n != v,
        12 => !z && n == v,
        13 => z || n != v,
        _ => unreachable!("unsupported cond in emitted code"),
    }
}

fn alu_shift(v: u64, kind: ShiftType, amt: u32, bits: u32) -> u64 {
    let m = if bits == 64 { u64::MAX } else { (1u64 << bits) - 1 };
    let v = v & m;
    match kind {
        ShiftType::Lsl => v.wrapping_shl(amt) & m,
        ShiftType::Lsr => v.wrapping_shr(amt),
        ShiftType::Asr => (sign_ext(v, bits) >> amt) as u64 & m,
        ShiftType::Ror => v.rotate_right(amt % bits) & m,
    }
}

fn extend_val(v: u64, ext: ExtendKind) -> u64 {
    match ext {
        ExtendKind::Uxtb => v & 0xFF,
        ExtendKind::Uxth => v & 0xFFFF,
        ExtendKind::Uxtx => v,
        ExtendKind::Sxtb => sign_ext(v & 0xFF, 8) as u64,
        ExtendKind::Sxth => sign_ext(v & 0xFFFF, 16) as u64,
        ExtendKind::Sxtw => sign_ext(v & 0xFFFF_FFFF, 32) as u64,
    }
}

// ---------------------------------------------------------------------
// Equivalence harness
// ---------------------------------------------------------------------

fn check_equiv(
    name: &str,
    module: &Ir64Module,
    seeds: &[(u64, u64)],
    mem_seeds: &[(u64, u8, u64)],
) {
    const THUNK_RVA: u32 = 0x30000;
    let words = emit_superop_aarch64(
        module,
        &[0xA5; 16],
        &SuperopAarch64Options { thunk_rva: THUNK_RVA },
    )
    .unwrap_or_else(|e| panic!("{name}: emit: {e}"));
    for &(x0, x1) in seeds {
        let mut o = Machine64::entry(x0, x1);
        for &(a, w, v) in mem_seeds {
            o.mem.write_u64(a, w, v).unwrap();
        }
        let want =
            eval_machine64(module, &mut o).unwrap_or_else(|e| panic!("{name}: oracle: {e:?}"));
        // The interpreter models runtime addresses as base+offset; the
        // thunk's own adr lands at base+0, so the base must be
        // BIAS_SENTINEL + thunk_rva for the recovered bias to match the
        // oracle sentinel.
        let (got_x0, got_sp, got_gpr, got_mem, touched) = run_words(
            &words,
            x0,
            x1,
            mem_seeds,
            BIAS_SENTINEL.wrapping_add(THUNK_RVA as u64),
        )
        .unwrap_or_else(|e| panic!("{name} ({x0:#x},{x1:#x}): {e}"));
        assert_eq!(got_x0, want, "{name} ({x0:#x},{x1:#x}) x0");
        assert_eq!(
            got_sp, SP_SENTINEL,
            "{name}: sp restored to the entry sentinel"
        );
        for r in 19..=29 {
            assert_eq!(
                got_gpr[r], 0,
                "{name}: callee-saved x{r} must be restored (entry value 0)"
            );
        }
        for &a in &touched {
            let m = o.mem.read_u64(a, 8).ok();
            let g = got_mem.read_u64(a, 8).ok();
            assert_eq!(m, g, "{name}: memory at {a:#x}");
        }
    }
}

fn mod_ret(stmts: Vec<Stmt64>) -> Ir64Module {
    Ir64Module {
        entry: 0,
        blocks: vec![Ir64Block {
            stmts,
            term: Term64::Ret,
        }],
    }
}

const SEEDS64: [(u64, u64); 32] = [
    (0, 0),
    (1, 1),
    (3, 4),
    (7, 7),
    (0xFF, 0x100),
    (0xFFFF, 0x1),
    (0xFFFF_FFFF, 2),
    (0x8000_0000, 1),
    (0x8000_0000_0000_0000, 3),
    (0xFFFF_FFFF_FFFF_FFFF, 0xFFFF_FFFF_FFFF_FFFF),
    (0x1234_5678_9ABC_DEF0, 0x0F0F_0F0F_0F0F_0F0F),
    (0xDEAD_BEEF, 0xCAFE_BABE),
    (0x1, 0xFFFF_FFFF),
    (0x42, 0x42),
    (0x7FFF_FFFF, 1),
    (0x7FFF_FFFF_FFFF_FFFF, 1),
    (2, 63),
    (1, 31),
    (0x5555_5555_5555_5555, 0x2),
    (0xAAAA_AAAA_AAAA_AAAA, 0x4),
    (0x100, 8),
    (0x1000, 0x1000),
    (0x9E37_79B9_7F4A_7C15, 0x1),
    (0x1122_3344_5566_7788, 0x8877_6655_4433_2211),
    (0, 1),
    (1, 0),
    (0xFFFF_FFFF, 0x8000_0000),
    (0x8000_0000, 0x8000_0000),
    (0x3FFF_FFFF, 0x4000_0000),
    (0xC000_0000_0000_0000, 0x4000_0000_0000_0000),
    (0x10, 0xFFFF_FFFF_FFFF_FFFF),
    (0x0F0F, 0x7070),
];

// ---------------------------------------------------------------------
// A4: per-instruction-class re-emit → word-interp → oracle equivalence
// ---------------------------------------------------------------------

#[test]
fn a4_add_sub_x() {
    for op in [BinOp::Add, BinOp::Sub] {
        check_equiv(
            "add/sub x",
            &mod_ret(vec![
                Stmt64::Mov { dst: 2, src: Src64::Reg(0) },
                Stmt64::Bin {
                    op,
                    w: Width64::X,
                    dst: 0,
                    lhs: Src64::Reg(0),
                    rhs: Src64::Reg(1),
                },
                Stmt64::Bin {
                    op,
                    w: Width64::X,
                    dst: 0,
                    lhs: Src64::Reg(0),
                    rhs: Src64::Imm(0x123),
                },
                Stmt64::Bin {
                    op,
                    w: Width64::X,
                    dst: 3,
                    lhs: Src64::Reg(2),
                    rhs: Src64::Imm(0x1_0000),
                },
                Stmt64::Bin {
                    op,
                    w: Width64::X,
                    dst: 0,
                    lhs: Src64::Reg(0),
                    rhs: Src64::Reg(3),
                },
            ]),
            &SEEDS64,
            &[],
        );
    }
}

#[test]
fn a4_add_sub_w() {
    for op in [BinOp::Add, BinOp::Sub] {
        check_equiv(
            "add/sub w",
            &mod_ret(vec![
                Stmt64::Bin {
                    op,
                    w: Width64::W,
                    dst: 0,
                    lhs: Src64::Reg(0),
                    rhs: Src64::Reg(1),
                },
                Stmt64::Bin {
                    op,
                    w: Width64::W,
                    dst: 0,
                    lhs: Src64::Reg(0),
                    rhs: Src64::Imm(0x1234),
                },
                Stmt64::Bin {
                    op,
                    w: Width64::W,
                    dst: 0,
                    lhs: Src64::Reg(0),
                    rhs: Src64::Imm(0xFFFF_0000),
                },
            ]),
            &SEEDS64,
            &[],
        );
    }
}

#[test]
fn a4_logic_and_shifts() {
    for op in [BinOp::And, BinOp::Or, BinOp::Xor] {
        check_equiv(
            "logic x/w",
            &mod_ret(vec![
                Stmt64::Bin {
                    op,
                    w: Width64::X,
                    dst: 0,
                    lhs: Src64::Reg(0),
                    rhs: Src64::Reg(1),
                },
                Stmt64::Bin {
                    op,
                    w: Width64::W,
                    dst: 4,
                    lhs: Src64::Reg(0),
                    rhs: Src64::Reg(1),
                },
                Stmt64::Bin {
                    op,
                    w: Width64::X,
                    dst: 0,
                    lhs: Src64::Reg(0),
                    rhs: Src64::Reg(4),
                },
                Stmt64::Bin {
                    op,
                    w: Width64::X,
                    dst: 0,
                    lhs: Src64::Reg(0),
                    rhs: Src64::Imm(0x5A5A_5A5A_5A5A_5A5A),
                },
            ]),
            &SEEDS64,
            &[],
        );
    }
    check_equiv(
        "shifts imm",
        &mod_ret(vec![
            Stmt64::Mov { dst: 2, src: Src64::Reg(0) },
            Stmt64::Bin {
                op: BinOp::Shl,
                w: Width64::X,
                dst: 3,
                lhs: Src64::Reg(2),
                rhs: Src64::Imm(5),
            },
            Stmt64::Bin {
                op: BinOp::Shr,
                w: Width64::X,
                dst: 4,
                lhs: Src64::Reg(2),
                rhs: Src64::Imm(3),
            },
            Stmt64::Bin {
                op: BinOp::Sar,
                w: Width64::X,
                dst: 5,
                lhs: Src64::Reg(2),
                rhs: Src64::Imm(2),
            },
            Stmt64::Bin {
                op: BinOp::Xor,
                w: Width64::X,
                dst: 0,
                lhs: Src64::Reg(3),
                rhs: Src64::Reg(4),
            },
            Stmt64::Bin {
                op: BinOp::Add,
                w: Width64::X,
                dst: 0,
                lhs: Src64::Reg(0),
                rhs: Src64::Reg(5),
            },
        ]),
        &SEEDS64,
        &[],
    );
    check_equiv(
        "shifts imm w (count 32 masks to 0)",
        &mod_ret(vec![
            Stmt64::Mov { dst: 2, src: Src64::Reg(0) },
            Stmt64::Bin {
                op: BinOp::Shl,
                w: Width64::W,
                dst: 3,
                lhs: Src64::Reg(2),
                rhs: Src64::Imm(31),
            },
            Stmt64::Bin {
                op: BinOp::Shl,
                w: Width64::W,
                dst: 4,
                lhs: Src64::Reg(2),
                rhs: Src64::Imm(32),
            },
            Stmt64::Bin {
                op: BinOp::Sar,
                w: Width64::W,
                dst: 5,
                lhs: Src64::Reg(3),
                rhs: Src64::Imm(4),
            },
            Stmt64::Bin {
                op: BinOp::Xor,
                w: Width64::X,
                dst: 0,
                lhs: Src64::Reg(3),
                rhs: Src64::Reg(4),
            },
            Stmt64::Bin {
                op: BinOp::Add,
                w: Width64::X,
                dst: 0,
                lhs: Src64::Reg(0),
                rhs: Src64::Reg(5),
            },
        ]),
        &SEEDS64,
        &[],
    );
    check_equiv(
        "variable shifts",
        &mod_ret(vec![
            Stmt64::Mov { dst: 2, src: Src64::Reg(0) },
            Stmt64::Bin {
                op: BinOp::Shl,
                w: Width64::X,
                dst: 3,
                lhs: Src64::Reg(2),
                rhs: Src64::Reg(1),
            },
            Stmt64::Bin {
                op: BinOp::Shr,
                w: Width64::X,
                dst: 4,
                lhs: Src64::Reg(2),
                rhs: Src64::Reg(1),
            },
            Stmt64::Bin {
                op: BinOp::Sar,
                w: Width64::X,
                dst: 5,
                lhs: Src64::Reg(2),
                rhs: Src64::Reg(1),
            },
            Stmt64::Bin {
                op: BinOp::Xor,
                w: Width64::X,
                dst: 0,
                lhs: Src64::Reg(3),
                rhs: Src64::Reg(4),
            },
            Stmt64::Bin {
                op: BinOp::Add,
                w: Width64::X,
                dst: 0,
                lhs: Src64::Reg(0),
                rhs: Src64::Reg(5),
            },
        ]),
        &SEEDS64,
        &[],
    );
}

#[test]
fn a4_constant_materialization_and_bias() {
    check_equiv(
        "mov imm",
        &mod_ret(vec![
            Stmt64::Mov { dst: 2, src: Src64::Imm(0x1234_5678_9ABC_DEF0) },
            Stmt64::Mov { dst: 3, src: Src64::Imm(0xFFFF) },
            Stmt64::Mov { dst: 4, src: Src64::Imm(0) },
            Stmt64::Bin {
                op: BinOp::Xor,
                w: Width64::X,
                dst: 0,
                lhs: Src64::Reg(2),
                rhs: Src64::Reg(0),
            },
            Stmt64::Bin {
                op: BinOp::Add,
                w: Width64::X,
                dst: 0,
                lhs: Src64::Reg(0),
                rhs: Src64::Reg(3),
            },
            Stmt64::Bin {
                op: BinOp::Add,
                w: Width64::X,
                dst: 0,
                lhs: Src64::Reg(0),
                rhs: Src64::Reg(4),
            },
        ]),
        &SEEDS64,
        &[],
    );
    check_equiv(
        "bias",
        &mod_ret(vec![
            Stmt64::Bias { dst: 2, rva: 0x1234 },
            Stmt64::Bias { dst: 3, rva: 0x8000 },
            Stmt64::Bin {
                op: BinOp::Add,
                w: Width64::X,
                dst: 0,
                lhs: Src64::Reg(0),
                rhs: Src64::Reg(2),
            },
            Stmt64::Bin {
                op: BinOp::Xor,
                w: Width64::X,
                dst: 0,
                lhs: Src64::Reg(0),
                rhs: Src64::Reg(3),
            },
        ]),
        &SEEDS64,
        &[],
    );
}

#[test]
fn a4_memory_and_sp() {
    // [sp] traffic with SP updates (the stack-shaped §7.5 form).
    check_equiv(
        "sp memory",
        &mod_ret(vec![
            Stmt64::Bin {
                op: BinOp::Sub,
                w: Width64::X,
                dst: VREG64_SP,
                lhs: Src64::Reg(VREG64_SP),
                rhs: Src64::Imm(32),
            },
            Stmt64::Mov { dst: 2, src: Src64::Reg(0) },
            Stmt64::Mov { dst: 3, src: Src64::Reg(1) },
            Stmt64::Store {
                addr: Addr64::BaseDisp { base: VREG64_SP, disp: 0 },
                src: Src64::Reg(2),
                width: 8,
            },
            Stmt64::Store {
                addr: Addr64::BaseDisp { base: VREG64_SP, disp: 8 },
                src: Src64::Reg(3),
                width: 8,
            },
            Stmt64::Store {
                addr: Addr64::BaseDisp { base: VREG64_SP, disp: 16 },
                src: Src64::Imm(0xAB),
                width: 1,
            },
            Stmt64::Load {
                dst: 4,
                addr: Addr64::BaseDisp { base: VREG64_SP, disp: 0 },
                width: 8,
            },
            Stmt64::Load {
                dst: 5,
                addr: Addr64::BaseDisp { base: VREG64_SP, disp: 16 },
                width: 1,
            },
            Stmt64::Bin {
                op: BinOp::Add,
                w: Width64::X,
                dst: 4,
                lhs: Src64::Reg(4),
                rhs: Src64::Reg(5),
            },
            Stmt64::Bin {
                op: BinOp::Add,
                w: Width64::X,
                dst: VREG64_SP,
                lhs: Src64::Reg(VREG64_SP),
                rhs: Src64::Imm(32),
            },
            Stmt64::Mov { dst: 0, src: Src64::Reg(4) },
        ]),
        &SEEDS64,
        &[],
    );
    // pointer-arg memory at 4 widths
    check_equiv(
        "widths",
        &mod_ret(vec![
            Stmt64::Store {
                addr: Addr64::BaseDisp { base: 0, disp: 0 },
                src: Src64::Reg(1),
                width: 8,
            },
            Stmt64::Load {
                dst: 2,
                addr: Addr64::BaseDisp { base: 0, disp: 0 },
                width: 1,
            },
            Stmt64::Load {
                dst: 3,
                addr: Addr64::BaseDisp { base: 0, disp: 0 },
                width: 2,
            },
            Stmt64::Load {
                dst: 4,
                addr: Addr64::BaseDisp { base: 0, disp: 4 },
                width: 4,
            },
            Stmt64::Bin {
                op: BinOp::Xor,
                w: Width64::X,
                dst: 2,
                lhs: Src64::Reg(2),
                rhs: Src64::Reg(3),
            },
            Stmt64::Bin {
                op: BinOp::Add,
                w: Width64::X,
                dst: 2,
                lhs: Src64::Reg(2),
                rhs: Src64::Reg(4),
            },
            Stmt64::Mov { dst: 0, src: Src64::Reg(2) },
        ]),
        &SEEDS64,
        &[(0x2000, 8, 0x1122_3344_5566_7788)],
    );
}

#[test]
fn a4_branches_all_predicates() {
    for pred in [
        CmpOp::Eq,
        CmpOp::Ne,
        CmpOp::ULt,
        CmpOp::ULe,
        CmpOp::UGt,
        CmpOp::UGe,
        CmpOp::SLt,
        CmpOp::SLe,
        CmpOp::SGt,
        CmpOp::SGe,
    ] {
        for w in [Width64::X, Width64::W] {
            let m = Ir64Module {
                entry: 0,
                blocks: vec![
                    Ir64Block {
                        stmts: vec![],
                        term: Term64::BrCmp {
                            pred,
                            w,
                            lhs: Src64::Reg(0),
                            rhs: Src64::Reg(1),
                            then_bb: 1,
                            else_bb: 2,
                        },
                    },
                    Ir64Block {
                        stmts: vec![Stmt64::Mov { dst: 0, src: Src64::Imm(7) }],
                        term: Term64::Jmp { target: 3 },
                    },
                    Ir64Block {
                        stmts: vec![Stmt64::Mov { dst: 0, src: Src64::Imm(9) }],
                        term: Term64::Jmp { target: 3 },
                    },
                    Ir64Block {
                        stmts: vec![Stmt64::Bin {
                            op: BinOp::Add,
                            w: Width64::X,
                            dst: 0,
                            lhs: Src64::Reg(0),
                            rhs: Src64::Imm(1),
                        }],
                        term: Term64::Ret,
                    },
                ],
            };
            check_equiv("br-cmp", &m, &SEEDS64, &[]);
        }
    }
    // Immediate compare beyond imm12.
    let m = Ir64Module {
        entry: 0,
        blocks: vec![
            Ir64Block {
                stmts: vec![],
                term: Term64::BrCmp {
                    pred: CmpOp::UGt,
                    w: Width64::X,
                    lhs: Src64::Reg(0),
                    rhs: Src64::Imm(0x12345),
                    then_bb: 1,
                    else_bb: 2,
                },
            },
            Ir64Block {
                stmts: vec![Stmt64::Mov { dst: 0, src: Src64::Imm(1) }],
                term: Term64::Ret,
            },
            Ir64Block {
                stmts: vec![Stmt64::Mov { dst: 0, src: Src64::Imm(2) }],
                term: Term64::Ret,
            },
        ],
    };
    check_equiv("br-cmp imm", &m, &SEEDS64, &[]);
}

#[test]
fn a4_stress_many_regs() {
    // 15 live vregs force real allocation + shuffles across blocks.
    let mut stmts: Vec<Stmt64> = Vec::new();
    for r in 2u8..16 {
        stmts.push(Stmt64::Mov { dst: r, src: Src64::Reg(0) });
        stmts.push(Stmt64::Bin {
            op: BinOp::Add,
            w: Width64::X,
            dst: r,
            lhs: Src64::Reg(r),
            rhs: Src64::Imm(r as u64 * 3),
        });
    }
    stmts.push(Stmt64::Bin {
        op: BinOp::Add,
        w: Width64::X,
        dst: 0,
        lhs: Src64::Reg(1),
        rhs: Src64::Reg(2),
    });
    for r in 3u8..16 {
        stmts.push(Stmt64::Bin {
            op: BinOp::Add,
            w: Width64::X,
            dst: 0,
            lhs: Src64::Reg(0),
            rhs: Src64::Reg(r),
        });
    }
    let split = stmts.len() / 2;
    let m = Ir64Module {
        entry: 0,
        blocks: vec![
            Ir64Block {
                stmts: stmts[..split].to_vec(),
                term: Term64::Jmp { target: 1 },
            },
            Ir64Block {
                stmts: stmts[split..].to_vec(),
                term: Term64::Ret,
            },
        ],
    };
    check_equiv("many regs", &m, &SEEDS64, &[]);
}

// ---------------------------------------------------------------------
// A5: structural gates
// ---------------------------------------------------------------------

fn words_of(m: &Ir64Module) -> Vec<u32> {
    emit_superop_aarch64(m, &[7; 16], &SuperopAarch64Options { thunk_rva: 0x1000 }).unwrap()
}

fn is_sub_sp_sp(w: u32) -> bool {
    w & 0xFF00_0000 == 0xD100_0000 && (w >> 5) & 0x1F == 31 && w & 0x1F == 31
}

fn is_add_sp_sp(w: u32) -> bool {
    w & 0xFF00_0000 == 0x9100_0000 && (w >> 5) & 0x1F == 31 && w & 0x1F == 31
}

#[test]
fn a5_frame_is_paired_and_capped() {
    let m = mod_ret(vec![Stmt64::Bin {
        op: BinOp::Add,
        w: Width64::X,
        dst: 0,
        lhs: Src64::Reg(0),
        rhs: Src64::Reg(1),
    }]);
    let ws = words_of(&m);
    assert!(is_sub_sp_sp(ws[0]), "thunk must open with sub sp,sp,#K");
    let k = (ws[0] >> 10) & 0xFFF;
    assert!(
        k % 16 == 0 && k >= SAVES as u32 && k <= FRAME_CAP as u32,
        "K={k}"
    );
    // exactly one `add sp,sp,#K` (epilogue restore) + one `add x15,sp,#K`.
    let adds: Vec<u32> = ws.iter().copied().filter(|w| is_add_sp_sp(*w)).collect();
    assert_eq!(adds.len(), 1, "epilogue restore");
    assert_eq!((adds[0] >> 10) & 0xFFF, k);
    let gsp: Vec<u32> = ws
        .iter()
        .copied()
        .filter(|w| *w & 0xFF00_0000 == 0x9100_0000 && (*w >> 5) & 0x1F == 31 && *w & 0x1F == 15)
        .collect();
    assert_eq!(gsp.len(), 1, "GSP init add x15,sp,#K");
    assert_eq!((gsp[0] >> 10) & 0xFFF, k);
    assert_eq!((ws[ws.len() - 2] >> 10) & 0xFFF, k);
    assert_eq!(ws[ws.len() - 1], RET);
    // save pairs sit at fixed offsets below SAVES
    let saves: Vec<u32> = ws
        .iter()
        .copied()
        .filter(|w| w & 0xFFC0_0000 == 0xA900_0000)
        .collect();
    assert_eq!(saves.len(), 6, "six stp saves");
}

#[test]
fn a5_deep_descent_hits_named_cap() {
    let mut stmts = Vec::new();
    for _ in 0..64 {
        stmts.push(Stmt64::Bin {
            op: BinOp::Sub,
            w: Width64::X,
            dst: VREG64_SP,
            lhs: Src64::Reg(VREG64_SP),
            rhs: Src64::Imm(0x1000), // imm12<<12 shape: 4096 each
        });
    }
    let m = mod_ret(stmts);
    let e = emit_superop_aarch64(&m, &[1; 16], &SuperopAarch64Options { thunk_rva: 0 })
        .unwrap_err();
    assert!(e.contains("exceeds the emitter cap"), "{e}");
    assert!(e.contains("4080"), "{e}");
}

#[test]
fn a5_thunk_size_is_rva_independent() {
    let m = mod_ret(vec![
        Stmt64::Bias { dst: 2, rva: 0x7777 },
        Stmt64::Bin {
            op: BinOp::Add,
            w: Width64::X,
            dst: 0,
            lhs: Src64::Reg(0),
            rhs: Src64::Reg(2),
        },
    ]);
    let a = emit_superop_aarch64(&m, &[3; 16], &SuperopAarch64Options { thunk_rva: 0 }).unwrap();
    let b = emit_superop_aarch64(
        &m,
        &[3; 16],
        &SuperopAarch64Options { thunk_rva: 0x1234_5678 },
    )
    .unwrap();
    assert_eq!(a.len(), b.len(), "sizing pass / real pass sizes must match");
    assert_ne!(a, b, "the bias constant must actually change");
}

#[test]
fn a5_seed_divergent() {
    let m = mod_ret(vec![Stmt64::Bin {
        op: BinOp::Add,
        w: Width64::X,
        dst: 0,
        lhs: Src64::Reg(0),
        rhs: Src64::Reg(1),
    }]);
    let a = emit_superop_aarch64(&m, &[1; 16], &SuperopAarch64Options { thunk_rva: 0x1000 })
        .unwrap();
    let b = emit_superop_aarch64(&m, &[2; 16], &SuperopAarch64Options { thunk_rva: 0x1000 })
        .unwrap();
    assert_ne!(a, b, "per-build seeds must diverge");
}

// ---------------------------------------------------------------------
// A7: MBA u64 identities + emitted-form equivalence
// ---------------------------------------------------------------------

#[test]
fn a7_mba_identities_u64() {
    let vals = [
        0u64,
        1,
        3,
        0x1234_5678_9ABC_DEF0,
        u64::MAX,
        0x8000_0000_0000_0000,
        0x7FFF_FFFF_FFFF_FFFF,
        0xDEAD_BEEF_CAFE_F00D,
    ];
    for a in vals {
        for b in vals {
            assert_eq!(
                (a ^ b).wrapping_add((a & b) << 1),
                a.wrapping_add(b),
                "AddXorAnd {a:#x},{b:#x}"
            );
            assert_eq!(
                (a | b).wrapping_add(a & b),
                a.wrapping_add(b),
                "AddOrAnd {a:#x},{b:#x}"
            );
            assert_eq!(
                a.wrapping_add(b.wrapping_neg()),
                a.wrapping_sub(b),
                "SubAddNot {a:#x},{b:#x}"
            );
            assert_eq!((a | b).wrapping_sub(a & b), a ^ b, "XorOrAnd {a:#x},{b:#x}");
            assert_eq!(
                a.wrapping_add(b).wrapping_sub(a | b),
                a & b,
                "AndAddOr {a:#x},{b:#x}"
            );
        }
    }
}

#[test]
fn a7_mba_emitted_forms_match_oracle() {
    // Sweep seeds so every family is picked; both operand orders exercise
    // every source/destination aliasing shape.
    for op in [BinOp::Add, BinOp::Sub, BinOp::Xor, BinOp::And] {
        let m = mod_ret(vec![
            Stmt64::Mov { dst: 3, src: Src64::Reg(0) },
            Stmt64::Bin {
                op,
                w: Width64::X,
                dst: 0,
                lhs: Src64::Reg(3),
                rhs: Src64::Reg(1),
            },
            Stmt64::Bin {
                op,
                w: Width64::X,
                dst: 2,
                lhs: Src64::Reg(1),
                rhs: Src64::Reg(3),
            },
            Stmt64::Bin {
                op,
                w: Width64::X,
                dst: 1,
                lhs: Src64::Reg(1),
                rhs: Src64::Reg(1),
            },
            Stmt64::Bin {
                op: BinOp::Xor,
                w: Width64::X,
                dst: 0,
                lhs: Src64::Reg(0),
                rhs: Src64::Reg(2),
            },
        ]);
        for seed in [[0u8; 16], [1; 16], [2; 16], [3; 16], [4; 16], [5; 16]] {
            let words =
                emit_superop_aarch64(&m, &seed, &SuperopAarch64Options { thunk_rva: 0x2000 })
                    .unwrap();
            for &(x0, x1) in &SEEDS64[..8] {
                let mut o = Machine64::entry(x0, x1);
                let want = eval_machine64(&m, &mut o).unwrap();
                let (got, sp, _, mem, _) =
                    run_words(&words, x0, x1, &[], BIAS_SENTINEL).unwrap();
                assert_eq!(got, want, "{op:?} seed {seed:?} ({x0:#x},{x1:#x})");
                assert_eq!(sp, SP_SENTINEL);
                let _ = mem;
            }
        }
    }
}

#[test]
fn register_pool_exhaustion_is_named() {
    // 27 live vregs contend for the 26-entry pool.
    let mut stmts: Vec<Stmt64> = Vec::new();
    for r in 0u8..27 {
        stmts.push(Stmt64::Mov { dst: r, src: Src64::Imm(r as u64 + 1) });
    }
    for r in 1u8..27 {
        stmts.push(Stmt64::Bin {
            op: BinOp::Or,
            w: Width64::X,
            dst: 0,
            lhs: Src64::Reg(0),
            rhs: Src64::Reg(r),
        });
    }
    let m = mod_ret(stmts);
    let e = emit_superop_aarch64(&m, &[9; 16], &SuperopAarch64Options { thunk_rva: 0 })
        .unwrap_err();
    assert!(e.contains("not enough physical registers"), "{e}");
}
