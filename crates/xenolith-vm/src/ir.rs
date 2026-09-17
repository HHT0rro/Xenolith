//! Pack-internal SSA-ish IR for selected-export virtualization.
//!
//! This is **not** a guest ISA and is never written into a packed image.
//! `eval_ir` is the semantic oracle: PIC codegen must match it on EAX.

pub const VREG_COUNT: usize = 16;
pub const VREG_RAX: u8 = 0;
pub const VREG_RCX: u8 = 1;
pub const VREG_RDX: u8 = 2;
pub const VREG_RSP: u8 = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Src {
    Reg(u8),
    Imm(u32),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BinOp {
    Add,
    Sub,
    Xor,
    And,
    Or,
    Mul,
    Shl,
    Shr,
    Sar,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CmpOp {
    Eq,
    Ne,
    ULt,
    ULe,
    UGt,
    UGe,
    SLt,
    SLe,
    SGt,
    SGe,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Addr {
    /// `[base + disp]`
    BaseDisp { base: u8, disp: i32 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stmt {
    Mov { dst: u8, src: Src },
    Bin { op: BinOp, dst: u8, lhs: Src, rhs: Src },
    Load { dst: u8, addr: Addr, width: u8 },
    Store { addr: Addr, src: Src, width: u8 },
    /// Direct relative call to an RVA in the same image. Superop patches rel32.
    CallDirect { target_rva: u32 },
    /// G4: SSE/SSE2 scalar float on raw bits held in GPRs. `Sqrt` ignores
    /// `rhs`. `X87` runs the software 80-bit model on f64-bit operands.
    FScalar { op: FOp, width: FWidth, dst: u8, lhs: Src, rhs: Src },
    /// G4: scalar conversions (frozen set; truncating kinds carry T).
    FCvt { kind: CvtKind, dst: u8, src: Src },
    /// G4: (u)comis → dst code: 0 eq, 1 above, 2 below, 3 unordered.
    FCmp { width: FWidth, dst: u8, lhs: Src, rhs: Src },
    /// G4: 128-bit packed op; operands/results are GPR lane pairs
    /// (lo, hi). YMM/AVX2-256 stays outside the IR this release.
    VecBin { op: VecOp, dst: u8, dst_hi: u8, lhs_lo: Src, lhs_hi: Src, rhs_lo: Src, rhs_hi: Src },
    /// G4: RMW atomics. `expect`/`incoming` are GPRs; `dst` receives the
    /// old memory value; `zf_dst` receives cmpxchg's ZF (0 for xadd/xchg).
    Atomic { op: AtomicOpIr, addr: Addr, width: u8, expect: u8, incoming: Src, dst: u8, zf_dst: u8 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FOp {
    Add,
    Sub,
    Mul,
    Div,
    Min,
    Max,
    Sqrt,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FWidth {
    F32,
    F64,
    /// Software 80-bit x87 model (oracle) + fld/fop/fstp codegen.
    X87,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CvtKind {
    I32F32,
    I32F64,
    I64F32,
    I64F64,
    F32I32T,
    F64I32T,
    F32I64T,
    F64I64T,
    /// cvtss2si/cvtsd2si: RNE per MXCSR (frozen RC=nearest).
    F32I32R,
    F64I64R,
    F32F64,
    F64F32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VecOp {
    PAddD,
    PSubD,
    PMulLW,
    PMulHW,
    PMulLD,
    PMinSD,
    PMaxSD,
    PAnd,
    POr,
    PXor,
    PCmpEqD,
    PAddPS,
    PMulPS,
    PAddPD,
    PShufD(u8),
    Punpcklqdq,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AtomicOpIr {
    CmpXchg,
    XAdd,
    Xchg,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Term {
    Ret,
    Jmp { target: usize },
    BrCmp {
        pred: CmpOp,
        lhs: Src,
        rhs: Src,
        then_bb: usize,
        else_bb: usize,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IrBlock {
    pub stmts: Vec<Stmt>,
    pub term: Term,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IrModule {
    pub blocks: Vec<IrBlock>,
    pub entry: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IrError {
    BadReg,
    BadBlock,
    StepLimit,
    Spill, // W1: register file only; never introduce stack
}

impl std::fmt::Display for IrError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IrError::BadReg => f.write_str("ir: register out of range or rsp"),
            IrError::BadBlock => f.write_str("ir: block index out of range"),
            IrError::StepLimit => f.write_str("ir: step limit"),
            IrError::Spill => f.write_str("ir: spill/mem is forbidden in W1"),
        }
    }
}

impl std::error::Error for IrError {}

pub fn cmp(pred: CmpOp, lhs: u32, rhs: u32) -> bool {
    match pred {
        CmpOp::Eq => lhs == rhs,
        CmpOp::Ne => lhs != rhs,
        CmpOp::ULt => lhs < rhs,
        CmpOp::ULe => lhs <= rhs,
        CmpOp::UGt => lhs > rhs,
        CmpOp::UGe => lhs >= rhs,
        CmpOp::SLt => (lhs as i32) < (rhs as i32),
        CmpOp::SLe => (lhs as i32) <= (rhs as i32),
        CmpOp::SGt => (lhs as i32) > (rhs as i32),
        CmpOp::SGe => (lhs as i32) >= (rhs as i32),
    }
}

pub fn apply_bin(op: BinOp, lhs: u32, rhs: u32) -> u32 {
    match op {
        BinOp::Add => lhs.wrapping_add(rhs),
        BinOp::Sub => lhs.wrapping_sub(rhs),
        BinOp::Xor => lhs ^ rhs,
        BinOp::And => lhs & rhs,
        BinOp::Or => lhs | rhs,
        BinOp::Mul => lhs.wrapping_mul(rhs),
        // u32 shifts mask the count to 0..=31 (matching x86 32-bit semantics).
        BinOp::Shl => lhs.wrapping_shl(rhs),
        BinOp::Shr => lhs.wrapping_shr(rhs),
        BinOp::Sar => (lhs as i32).wrapping_shr(rhs) as u32,
    }
}

/// Interpret `module` with Win64 args in virtual RCX/RDX. Result is EAX.
/// Implemented on `MachineState` (32-bit width); two u32s are not the full ABI.
pub fn eval_ir(module: &IrModule, rcx: u32, rdx: u32) -> Result<u32, IrError> {
    let mut state = crate::semantics::MachineState::from_win64_u32(rcx, rdx);
    match crate::semantics::eval_machine(module, &mut state) {
        Ok(v) => Ok(v as u32),
        Err(crate::semantics::MachineError::Ir(e)) => Err(e),
        Err(_) => Err(IrError::BadBlock),
    }
}

/// Oracle matching `samples/license_toy` `check_license`.
pub fn license_toy_oracle(x: u32, y: u32) -> u32 {
    let mut t = x ^ y;
    t = t.wrapping_add(0x9E37_79B9);
    if t > 0x0001_0000 {
        t.wrapping_sub(y)
    } else {
        t.wrapping_add(y)
    }
}

pub fn license_toy_ir() -> IrModule {
    // t = x ^ y; t += K; if t > IMM { t - y } else { t + y }; eax = t
    IrModule {
        entry: 0,
        blocks: vec![
            IrBlock {
                stmts: vec![
                    Stmt::Mov {
                        dst: VREG_RAX,
                        src: Src::Reg(VREG_RCX),
                    },
                    Stmt::Bin {
                        op: BinOp::Xor,
                        dst: VREG_RAX,
                        lhs: Src::Reg(VREG_RAX),
                        rhs: Src::Reg(VREG_RDX),
                    },
                    Stmt::Bin {
                        op: BinOp::Add,
                        dst: VREG_RAX,
                        lhs: Src::Reg(VREG_RAX),
                        rhs: Src::Imm(0x9E37_79B9),
                    },
                ],
                term: Term::BrCmp {
                    pred: CmpOp::UGt,
                    lhs: Src::Reg(VREG_RAX),
                    rhs: Src::Imm(0x0001_0000),
                    then_bb: 1,
                    else_bb: 2,
                },
            },
            IrBlock {
                stmts: vec![Stmt::Bin {
                    op: BinOp::Sub,
                    dst: VREG_RAX,
                    lhs: Src::Reg(VREG_RAX),
                    rhs: Src::Reg(VREG_RDX),
                }],
                term: Term::Ret,
            },
            IrBlock {
                stmts: vec![Stmt::Bin {
                    op: BinOp::Add,
                    dst: VREG_RAX,
                    lhs: Src::Reg(VREG_RAX),
                    rhs: Src::Reg(VREG_RDX),
                }],
                term: Term::Ret,
            },
        ],
    }
}

pub fn hello_add_ir() -> IrModule {
    IrModule {
        entry: 0,
        blocks: vec![IrBlock {
            stmts: vec![Stmt::Bin {
                op: BinOp::Add,
                dst: VREG_RAX,
                lhs: Src::Reg(VREG_RCX),
                rhs: Src::Reg(VREG_RDX),
            }],
            term: Term::Ret,
        }],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VECTORS: [(u32, u32); 10] = [
        (0, 0),
        (1, 1),
        (3, 4),
        (0x0001_0000, 1),
        (0x0001_0001, 0),
        (0xFFFF_FFFF, 0),
        (0x1234, 0x5678),
        (0x8000_0000, 1),
        (0xFFFF, 0xFFFF),
        (0x0002_0000, 0x10),
    ];

    #[test]
    fn eval_ir_license_toy_truth_table() {
        let m = license_toy_ir();
        for (x, y) in VECTORS {
            let got = eval_ir(&m, x, y).unwrap();
            let expect = license_toy_oracle(x, y);
            assert_eq!(got, expect, "check_license({x:#x},{y:#x})");
        }
    }

    #[test]
    fn eval_ir_hello_add() {
        let m = hello_add_ir();
        assert_eq!(eval_ir(&m, 3, 4).unwrap(), 7);
        assert_eq!(eval_ir(&m, u32::MAX, 1).unwrap(), 0);
    }

    #[test]
    fn eval_ir_rejects_rsp() {
        let m = IrModule {
            entry: 0,
            blocks: vec![IrBlock {
                stmts: vec![Stmt::Mov {
                    dst: VREG_RSP,
                    src: Src::Imm(1),
                }],
                term: Term::Ret,
            }],
        };
        assert!(matches!(eval_ir(&m, 0, 0), Err(IrError::BadReg)));
    }

    #[test]
    fn eval_ir_million_license_toy_no_drift() {
        let m = license_toy_ir();
        let mut n = 0u32;
        for x in 0..1000u32 {
            for y in 0..1000u32 {
                assert_eq!(eval_ir(&m, x, y).unwrap(), license_toy_oracle(x, y));
                n += 1;
            }
        }
        assert_eq!(n, 1_000_000);
    }
}
