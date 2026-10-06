//! Whitelist AArch64 decoder (vm-aarch64 design §2.1, §3).
//!
//! Fixed 4-byte instructions, no external disassembler dependency.
//! Fail-closed by construction:
//! - full-opcode-mask comparison happens before any immediate-field
//!   extraction (the adr/b collision class, §0.3);
//! - UNDEFINED encodings and illegal width combinations (sf=0 with imm6>31,
//!   reserved bitmask immediates, cond 4..7/14/15, b5-set W-form test
//!   branches) are named rejects with the same weight as unknown words;
//! - never panics: every path returns `Err(String)` (A6).
//!
//! All bit layouts are cross-checked against NDK clang/llvm-objdump golden
//! words in the tests below.

/// A register operand with its encoding-position interpretation resolved:
/// register 0..=30, the zero register (reads 0, writes dropped), or SP.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Gpr {
    R(u8),
    Zr,
    Sp,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShiftType {
    Lsl,
    Lsr,
    Asr,
    Ror,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExtendKind {
    Uxtb,
    Uxth,
    Uxtx,
    Sxtb,
    Sxth,
    Sxtw,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LogicOp {
    And,
    Orr,
    Eor,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UbfmKind {
    Lsl,
    Lsr,
    Asr,
    /// immr=0, imms=sz-1: the MOV alias of LSL/LSR #0.
    Mov,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VarShiftKind {
    Lslv,
    Lsrv,
    Asrv,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairMode {
    SignedOffset,
    PreIndex,
    PostIndex,
}

/// A decoded whitelist instruction. Branch targets are byte offsets
/// relative to the instruction (the lifter resolves `ip + off`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Inst64 {
    /// add/sub (immediate), including the `imm12 << 12` variant and the
    /// S=1 forms (adds/subs/cmp/cmn immediate). `cmn imm 0` is rejected at
    /// decode (C-flag corner, §6.3).
    AddSubImm {
        sf: bool,
        setflags: bool,
        sub: bool,
        rd: Gpr,
        rn: Gpr,
        imm: u64,
    },
    /// add/sub (shifted register), bit21=0. Shift-immediate cap: sf=0
    /// allows imm6 in 0..=31 (UNDEFINED above — named reject in decode).
    AddSubShiftReg {
        sf: bool,
        setflags: bool,
        sub: bool,
        rd: Gpr,
        rn: Gpr,
        rm: Gpr,
        shift: ShiftType,
        imm6: u8,
    },
    /// add/sub (extended register), bit21=1, imm3 in 0..=3.
    AddSubExtReg {
        sf: bool,
        setflags: bool,
        sub: bool,
        rd: Gpr,
        rn: Gpr,
        rm: Gpr,
        ext: ExtendKind,
        imm3: u8,
    },
    /// and/orr/eor/ands (shifted register), N=0, LSL/LSR/ASR only.
    LogicReg {
        sf: bool,
        op: LogicOp,
        setflags: bool,
        rd: Gpr,
        rn: Gpr,
        rm: Gpr,
        shift: ShiftType,
        imm6: u8,
    },
    /// and/orr/eor/ands (bitmask immediate). UNDEF patterns rejected here.
    LogicImm {
        sf: bool,
        op: LogicOp,
        setflags: bool,
        rd: Gpr,
        rn: Gpr,
        n: bool,
        immr: u8,
        imms: u8,
    },
    /// Exact UBFM/SBFM alias forms (lsl/lsr/asr imm; lsl/lsr #0 = Mov).
    UbfmAlias {
        sf: bool,
        kind: UbfmKind,
        signed_: bool,
        rd: Gpr,
        rn: Gpr,
        amount: u8,
    },
    /// lslv/lsrv/asrv.
    VarShift {
        sf: bool,
        kind: VarShiftKind,
        rd: Gpr,
        rn: Gpr,
        rm: Gpr,
    },
    Movz {
        sf: bool,
        rd: Gpr,
        imm16: u16,
        hw: u8,
    },
    Movk {
        sf: bool,
        rd: Gpr,
        imm16: u16,
        hw: u8,
    },
    /// Unconditional `b imm26` (bl is rejected: it is a call).
    B { off: i64 },
    /// b.cond with cond in the supported set; unsupported conds named-reject.
    BCond { cond: u8, off: i64 },
    Cbz {
        sf: bool,
        nz: bool,
        rt: Gpr,
        off: i64,
    },
    /// tbz/tbnz: the tested bit (0..=63; bit31 of the word is its bit-5
    /// selector). Bits below 32 test the same physical bit in W and X view.
    Tbz {
        nz: bool,
        rt: Gpr,
        bit: u8,
        off: i64,
    },
    Ret,
    /// ldr/str unsigned-offset family (size,opc), width = 1<<size.
    LdrStr {
        size: u8,
        load: bool,
        rt: Gpr,
        rn: Gpr,
        off: u32,
    },
    /// ldp/stp (GPR pairs; X pairs only for the W/X opc 00/10 forms).
    LdpStp {
        sf: bool,
        load: bool,
        mode: PairMode,
        rt: Gpr,
        rt2: Gpr,
        rn: Gpr,
        off: i32,
    },
    Adr { rd: Gpr, off: i64 },
    Adrp { rd: Gpr, off: i64 },
    Nop,
}

/// b.cond condition codes the first batch supports (§3.1#10):
/// eq/ne/cs-hs/cc-lo/hi/ls/ge/lt/gt/le. mi/pl/vs/vc/al/nv fail closed.
pub const SUPPORTED_CONDS: [u8; 10] = [0, 1, 2, 3, 8, 9, 10, 11, 12, 13];

pub fn cond_name(cond: u8) -> &'static str {
    match cond {
        0 => "eq",
        1 => "ne",
        2 => "hs/cs",
        3 => "lo/cc",
        4 => "mi",
        5 => "pl",
        6 => "vs",
        7 => "vc",
        8 => "hi",
        9 => "ls",
        10 => "ge",
        11 => "lt",
        12 => "gt",
        13 => "le",
        14 => "al",
        _ => "nv",
    }
}

fn gpr_sp(n: u32) -> Gpr {
    if n == 31 {
        Gpr::Sp
    } else {
        Gpr::R(n as u8)
    }
}

fn gpr_zr(n: u32) -> Gpr {
    if n == 31 {
        Gpr::Zr
    } else {
        Gpr::R(n as u8)
    }
}

fn sext26(w: u32) -> i64 {
    let v = (w & 0x03FF_FFFF) as i64;
    if v & (1 << 25) != 0 {
        v - (1 << 26)
    } else {
        v
    }
    .wrapping_mul(4)
}

fn sext19(w: u32) -> i64 {
    let v = ((w >> 5) & 0x7_FFFF) as i64;
    if v & (1 << 18) != 0 {
        v - (1 << 19)
    } else {
        v
    }
    .wrapping_mul(4)
}

fn sext14(w: u32) -> i64 {
    let v = ((w >> 5) & 0x3FFF) as i64;
    if v & (1 << 13) != 0 {
        v - (1 << 14)
    } else {
        v
    }
    .wrapping_mul(4)
}

fn sext7(v: u32) -> i32 {
    let v = (v & 0x7F) as i32;
    if v & (1 << 6) != 0 {
        v - (1 << 7)
    } else {
        v
    }
}

/// Decode the bitmask immediate (N:immr:imms) per ARM ARM `DecodeBitMasks`.
/// Returns `None` for reserved (UNDEFINED) patterns.
pub fn decode_bitmask(n: bool, immr: u8, imms: u8, sf64: bool) -> Option<u64> {
    // len = HighestSetBit(N:NOT(imms)), 7-bit field. nni==0 is the only
    // reserved shape; N=1 forces len=6 (esize 64).
    let nni = ((n as u32) << 6) | (!(imms as u32) & 0x3F);
    if nni == 0 {
        return None;
    }
    let len = 6 - (nni.leading_zeros() - 25); // position of the MSB in 7 bits
    // A 32-bit destination cannot carry a 64-bit-sized pattern.
    if !sf64 && len > 5 {
        return None;
    }
    // Element = p consecutive ones rotated right by immr%esize, replicated
    // every esize bits. Semantics cross-checked against NDK clang 18 golden
    // words (class_bitmask_ndk_golden_sweep below): N=1 -> p = imms+1;
    // N=0 -> p = imms + 2^(len+1) - 63 (imms lives in the high bits above
    // len). 1 <= p <= esize holds by construction for encodable patterns.
    let esize: u32 = 1 << len;
    let emask: u64 = if esize == 64 { u64::MAX } else { (1u64 << esize) - 1 };
    let p: u32 = if n {
        (imms as u32) + 1
    } else {
        (imms as u32).wrapping_add(2u32 << len).wrapping_sub(63)
    };
    if p == 0 || p > esize {
        return None; // defensive: unreachable for encodable patterns
    }
    let welem: u64 = ((1u64 << (p - 1)) << 1).wrapping_sub(1) & emask; // p ones
    let r = (immr as u32) % esize;
    let telem = if r == 0 {
        welem
    } else {
        ((welem >> r) | (welem << (esize - r))) & emask
    };
    let size = if sf64 { 64u32 } else { 32u32 };
    let mut imm: u64 = 0;
    let mut pos = 0u32;
    while pos < size {
        imm |= telem << pos;
        pos += esize;
    }
    if !sf64 {
        imm &= 0xFFFF_FFFF;
    }
    Some(imm)
}

/// Decode one instruction word. Unknown words, UNDEFINED encodings and
/// out-of-first-batch shapes return a named error (never panics).
pub fn decode_word(w: u32) -> Result<Inst64, String> {
    // ---- exact-word whitelist shapes first ----
    if w == 0xD65F_03C0 {
        return Ok(Inst64::Ret);
    }
    if w == 0xD503_201F {
        return Ok(Inst64::Nop);
    }

    // Family predicates use FIXED bit fields (sf/opc/S excluded), never
    // whole top bytes — movz shares its top byte with eor-immediate, and
    // shift-type bits leak into bit 23 of the register families. Every
    // predicate is measured against NDK clang/llvm-objdump goldens (tests).

    // ---- add/sub immediate: bits[28:23] = 100010 ----
    if (w >> 23) & 0x3F == 0b100010 {
        let sf = w & 0x8000_0000 != 0;
        let op = w & 0x4000_0000 != 0;
        let s = w & 0x2000_0000 != 0;
        let sh = w & 0x0040_0000 != 0;
        let imm12 = (w >> 10) & 0xFFF;
        let imm = if sh { (imm12 as u64) << 12 } else { imm12 as u64 };
        let rn = gpr_sp((w >> 5) & 0x1F);
        // Rd=31 is SP for ADD/SUB and XZR for ADDS/SUBS (cmp/cmn live here).
        let rd = if s { gpr_zr(w & 0x1F) } else { gpr_sp(w & 0x1F) };
        // `cmn rd,rn,#0` is the C-bit corner (§6.3): hardware adds C=0 but
        // the compare view compare(a,0) says C=1 — rejected before lift.
        if s && !op && imm == 0 {
            return Err(format!(
                "unsupported instruction word {w:#010x}: adds/cmn with immediate 0 (C-flag \
                 corner: hardware C=0 but the compare view says C=1; stage-2 may model exact \
                 carry) — keep the function native with --allow-native-fallback"
            ));
        }
        return Ok(Inst64::AddSubImm {
            sf,
            setflags: s,
            sub: op,
            rd,
            rn,
            imm,
        });
    }

    // ---- add/sub register: bits[28:24] = 01011 (shift occupies 23:22) ----
    if (w >> 24) & 0x1F == 0b01011 {
        let sf = w & 0x8000_0000 != 0;
        let op = w & 0x4000_0000 != 0;
        let s = w & 0x2000_0000 != 0;
        let shift = match (w >> 22) & 3 {
            0 => ShiftType::Lsl,
            1 => ShiftType::Lsr,
            2 => ShiftType::Asr,
            _ => {
                return Err(format!(
                    "unsupported instruction word {w:#010x}: ROR operand shift is outside \
                     the first batch — keep the function native with --allow-native-fallback"
                ))
            }
        };
        let imm6 = ((w >> 10) & 0x3F) as u8;
        let imm_cap = if sf { 63 } else { 31 };
        if imm6 as u32 > imm_cap {
            return Err(format!(
                "unsupported instruction word {w:#010x}: UNDEFINED shift immediate {imm6} for \
                 a {bits}-bit operand (cap {imm_cap})",
                bits = if sf { 64 } else { 32 }
            ));
        }
        let rm = gpr_zr((w >> 16) & 0x1F);
        // In the shifted form both Rn=31 and Rd=31 are the zero register
        // (the `neg xd,xm` alias proves Rn; `add xzr,xn,xm` proves Rd) — SP
        // reaches this family only through the extended form below or the
        // immediate family above.
        let rn = gpr_zr((w >> 5) & 0x1F);
        let rd = gpr_zr(w & 0x1F);
        if w & 0x0020_0000 == 0 {
            return Ok(Inst64::AddSubShiftReg {
                sf,
                setflags: s,
                sub: op,
                rd,
                rn,
                rm,
                shift,
                imm6,
            });
        }
        // Extended register form: option[15:13], imm3[12:10]; Rn/Rd are
        // SP-capable (`add sp,x1,x2` / `add x0,sp,x2` encode here).
        let option = (w >> 13) & 7;
        let imm3 = ((w >> 10) & 7) as u8;
        let ext = match (sf, option) {
            (false, 0) => ExtendKind::Uxtb,
            (false, 1) => ExtendKind::Uxth,
            (true, 3) => ExtendKind::Uxtx,
            (true, 4) => ExtendKind::Sxtb,
            (true, 5) => ExtendKind::Sxth,
            (true, 6) => ExtendKind::Sxtw,
            _ => {
                return Err(format!(
                    "unsupported instruction word {w:#010x}: extend option {option} with \
                     sf={} is outside the whitelist — keep the function native with \
                     --allow-native-fallback",
                    sf
                ))
            }
        };
        if shift != ShiftType::Lsl {
            return Err(format!(
                "unsupported instruction word {w:#010x}: extended-register form requires a \
                 LSL-class option encoding"
            ));
        }
        let rn_sp = gpr_sp((w >> 5) & 0x1F);
        let rd_sp = if s { gpr_zr(w & 0x1F) } else { gpr_sp(w & 0x1F) };
        return Ok(Inst64::AddSubExtReg {
            sf,
            setflags: s,
            sub: op,
            rd: rd_sp,
            rn: rn_sp,
            rm,
            ext,
            imm3,
        });
    }

    // ---- logic register: bits[28:24] = 01010, N (bit21) = 0 ----
    if (w >> 24) & 0x1F == 0b01010 {
        let sf = w & 0x8000_0000 != 0;
        let op = match (w >> 29) & 3 {
            0 => LogicOp::And,
            1 => LogicOp::Orr,
            2 => LogicOp::Eor,
            _ => LogicOp::And, // 3 = ANDS
        };
        let setflags = (w >> 29) & 3 == 3;
        if w & 0x0020_0000 != 0 {
            return Err(format!(
                "unsupported instruction word {w:#010x}: N=1 logic (BIC/ORN/EON/BICS) is \
                 outside the first batch — keep the function native with \
                 --allow-native-fallback"
            ));
        }
        let shift = match (w >> 22) & 3 {
            0 => ShiftType::Lsl,
            1 => ShiftType::Lsr,
            2 => ShiftType::Asr,
            _ => {
                return Err(format!(
                    "unsupported instruction word {w:#010x}: ROR operand shift is outside \
                     the first batch — keep the function native with --allow-native-fallback"
                ))
            }
        };
        let imm6 = ((w >> 10) & 0x3F) as u8;
        let imm_cap = if sf { 63 } else { 31 };
        if imm6 as u32 > imm_cap {
            return Err(format!(
                "unsupported instruction word {w:#010x}: UNDEFINED shift immediate {imm6} for \
                 a {bits}-bit operand (cap {imm_cap})",
                bits = if sf { 64 } else { 32 }
            ));
        }
        let rm = gpr_zr((w >> 16) & 0x1F);
        let rn = gpr_zr((w >> 5) & 0x1F);
        let rd = gpr_zr(w & 0x1F);
        return Ok(Inst64::LogicReg {
            sf,
            op,
            setflags,
            rd,
            rn,
            rm,
            shift,
            imm6,
        });
    }

    // ---- logic immediate: bits[28:23] = 100100 ----
    if (w >> 23) & 0x3F == 0b100100 {
        let sf = w & 0x8000_0000 != 0;
        let op = match (w >> 29) & 3 {
            0 => LogicOp::And,
            1 => LogicOp::Orr,
            2 => LogicOp::Eor,
            _ => LogicOp::And,
        };
        let setflags = (w >> 29) & 3 == 3;
        let n = w & 0x0040_0000 != 0;
        let immr = ((w >> 16) & 0x3F) as u8;
        let imms = ((w >> 10) & 0x3F) as u8;
        if decode_bitmask(n, immr, imms, sf).is_none() {
            return Err(format!(
                "unsupported instruction word {w:#010x}: reserved bitmask immediate \
                 (N={n}, immr={immr}, imms={imms}) — UNDEFINED encoding, not liftable"
            ));
        }
        let rn = gpr_zr((w >> 5) & 0x1F);
        let rd = gpr_zr(w & 0x1F);
        return Ok(Inst64::LogicImm {
            sf,
            op,
            setflags,
            rd,
            rn,
            n,
            immr,
            imms,
        });
    }

    // ---- UBFM/SBFM: bits[28:23] = 100110 (opc 00=SBFM, 10=UBFM) ----
    if (w >> 23) & 0x3F == 0b100110 {
        let sf = w & 0x8000_0000 != 0;
        let opc = (w >> 29) & 3;
        if opc != 0b00 && opc != 0b10 {
            return Err(format!(
                "unsupported instruction word {w:#010x}: BFM (opc={opc}) is outside the \
                 first batch — keep the function native with --allow-native-fallback"
            ));
        }
        let signed_ = opc == 0b00;
        let immr = ((w >> 16) & 0x3F) as u8;
        let imms = ((w >> 10) & 0x3F) as u8;
        let sz = if sf { 63u32 } else { 31u32 };
        let rd = gpr_sp(w & 0x1F);
        let rn = gpr_sp((w >> 5) & 0x1F);
        // LSL #0 / LSR #0 / ASR #0 all alias MOV: immr=0, imms=sz.
        if immr as u32 == 0 && imms as u32 == sz {
            return Ok(Inst64::UbfmAlias {
                sf,
                kind: UbfmKind::Mov,
                signed_,
                rd,
                rn,
                amount: 0,
            });
        }
        // immr/imms beyond the operand width are UNDEFINED bitfield forms.
        if immr as u32 > sz {
            return Err(format!(
                "unsupported instruction word {w:#010x}: UNDEFINED bitfield immr={immr} for a                  {bits}-bit operand",
                bits = if sf { 64 } else { 32 }
            ));
        }
        // LSL #m (m>0): immr = (sz+1-m) mod (sz+1), imms = sz-m.
        let m_from_immr = (sz + 1 - immr as u32) % (sz + 1);
        if (imms as u32) < sz && sz - (imms as u32) == m_from_immr {
            return Ok(Inst64::UbfmAlias {
                sf,
                kind: UbfmKind::Lsl,
                signed_,
                rd,
                rn,
                amount: (sz - imms as u32) as u8,
            });
        }
        // LSR/ASR #m: immr=m, imms=sz.
        if imms as u32 == sz {
            return Ok(Inst64::UbfmAlias {
                sf,
                kind: if signed_ { UbfmKind::Asr } else { UbfmKind::Lsr },
                signed_,
                rd,
                rn,
                amount: immr,
            });
        }
        return Err(format!(
            "unsupported instruction word {w:#010x}: non-alias bitfield form (immr={immr}, \
             imms={imms}); only the exact lsl/lsr/asr aliases are liftable — keep the \
             function native with --allow-native-fallback"
        ));
    }

    // ---- variable shifts (lslv/lsrv/asrv); the mask covers bits 23:21 so
    // CSEL (same bits[31:24], e.g. cond=hs) can never leak in ----
    if w & 0xFFE0_0000 == 0x9AC0_0000 || w & 0xFFE0_0000 == 0x1AC0_0000 {
        let sf = w & 0x8000_0000 != 0;
        let kind = match (w >> 10) & 0x3F {
            8 => VarShiftKind::Lslv,
            9 => VarShiftKind::Lsrv,
            10 => VarShiftKind::Asrv,
            _ => {
                return Err(format!(
                    "unsupported instruction word {w:#010x}: data-processing (register) \
                     opc {:x} is outside the shift whitelist",
                    (w >> 10) & 0x3F
                ))
            }
        };
        let rm = gpr_zr((w >> 16) & 0x1F);
        let rn = gpr_sp((w >> 5) & 0x1F);
        let rd = gpr_sp(w & 0x1F);
        return Ok(Inst64::VarShift {
            sf,
            kind,
            rd,
            rn,
            rm,
        });
    }

    // ---- movz/movk: bits[28:23] = 100101 (movn opc=00 stays out) ----
    if (w >> 23) & 0x3F == 0b100101 {
        let sf = w & 0x8000_0000 != 0;
        let opc = (w >> 29) & 3;
        let hw = ((w >> 21) & 3) as u8;
        let imm16 = ((w >> 5) & 0xFFFF) as u16;
        let rd = gpr_sp(w & 0x1F);
        match opc {
            0b10 => return Ok(Inst64::Movz { sf, rd, imm16, hw }),
            0b11 => {
                if !sf && hw > 1 {
                    return Err(format!(
                        "unsupported instruction word {w:#010x}: UNDEFINED movk hw={hw} for a \
                         32-bit operand"
                    ));
                }
                return Ok(Inst64::Movk { sf, rd, imm16, hw });
            }
            _ => {
                return Err(format!(
                    "unsupported instruction word {w:#010x}: movn is outside the first \
                     batch (only non-negative 16/32/64-bit constants lift) — keep the \
                     function native with --allow-native-fallback"
                ))
            }
        }
    }

    // ---- b (unconditional, imm26; bl is a call) ----
    if w & 0xFC00_0000 == 0x1400_0000 {
        return Ok(Inst64::B { off: sext26(w) });
    }
    // ---- b.cond: full mask incl. the fixed-zero cond slot ----
    if w & 0xFF00_0010 == 0x5400_0000 {
        let cond = (w & 0xF) as u8;
        if !SUPPORTED_CONDS.contains(&cond) {
            return Err(format!(
                "unsupported instruction word {w:#010x}: b.{name} condition is outside the \
                 first batch (only eq/ne/hs/lo/hi/ls/ge/lt/gt/le lift) — keep the function \
                 native with --allow-native-fallback",
                name = cond_name(cond)
            ));
        }
        return Ok(Inst64::BCond {
            cond,
            off: sext19(w),
        });
    }
    // ---- cbz/cbnz: bits[30:25] = 011010 (bit24 = nz) ----
    if w & 0x7E00_0000 == 0x3400_0000 {
        let sf = w & 0x8000_0000 != 0;
        let nz = w & 0x0100_0000 != 0;
        return Ok(Inst64::Cbz {
            sf,
            nz,
            rt: gpr_zr(w & 0x1F),
            off: sext19(w),
        });
    }
    // ---- tbz/tbnz: bits[30:25] = 011011; word bit31 selects bit32 ----
    if w & 0x7E00_0000 == 0x3600_0000 {
        let nz = w & 0x0100_0000 != 0;
        let b5 = ((w >> 31) & 1) as u8;
        let b40 = ((w >> 19) & 0x1F) as u8;
        let bit = b5 * 32 + b40;
        return Ok(Inst64::Tbz {
            nz,
            rt: gpr_zr(w & 0x1F),
            bit,
            off: sext14(w),
        });
    }

    // ---- loads/stores: unsigned-offset immediate ----
    if w & 0x3B20_0000 == 0x3900_0000 {
        let size = ((w >> 30) & 3) as u8;
        let opc = (w >> 22) & 3;
        let load = match opc {
            0 => false,
            1 => true,
            2 => {
                return Err(format!(
                    "unsupported instruction word {w:#010x}: LDRSW/atomic opc=10 is outside \
                     the whitelist — sign-extending loads stay native"
                ))
            }
            _ => {
                return Err(format!(
                    "unsupported instruction word {w:#010x}: prefetch opc=11 is outside the \
                     whitelist"
                ))
            }
        };
        let imm12 = (w >> 10) & 0xFFF;
        let off = imm12 << size;
        return Ok(Inst64::LdrStr {
            size,
            load,
            rt: gpr_zr(w & 0x1F),
            rn: gpr_sp((w >> 5) & 0x1F),
            off,
        });
    }

    // ---- loads/stores: pairs (bits[29:25] = 10100, V=0) ----
    if w & 0x7E00_0000 == 0x2800_0000 {
        let sf = (w >> 30) & 3 == 2;
        let opc = (w >> 30) & 3;
        if opc == 1 || opc == 3 {
            return Err(format!(
                "unsupported instruction word {w:#010x}: SIMD ldp/stp (opc={opc}) is outside \
                 the whitelist"
            ));
        }
        let load = w & 0x0040_0000 != 0;
        // b24 b23 addressing mode: 10 = signed offset, 11 = pre-index,
        // 01 = post-index.
        let mode = match ((w >> 24) & 1, (w >> 23) & 1) {
            (1, 0) => PairMode::SignedOffset,
            (1, 1) => PairMode::PreIndex,
            (0, 1) => PairMode::PostIndex,
            _ => {
                return Err(format!(
                    "unsupported instruction word {w:#010x}: ldp/stp addressing mode is \
                     outside the whitelist"
                ))
            }
        };
        let scale = if sf { 8 } else { 4 };
        let off = sext7((w >> 15) & 0x7F) * scale;
        return Ok(Inst64::LdpStp {
            sf,
            load,
            mode,
            rt: gpr_zr(w & 0x1F),
            rt2: gpr_zr((w >> 10) & 0x1F),
            rn: gpr_sp((w >> 5) & 0x1F),
            off,
        });
    }

    // ---- adr / adrp ----
    if w & 0x9F00_0000 == 0x1000_0000 {
        let immlo = (w >> 29) & 3;
        let immhi = (w >> 5) & 0x7_FFFF;
        let imm = ((immhi << 2) | immlo) as i64;
        let off = if imm & (1 << 20) != 0 {
            imm - (1 << 21)
        } else {
            imm
        };
        return Ok(Inst64::Adr {
            rd: gpr_sp(w & 0x1F),
            off,
        });
    }
    if w & 0x9F00_0000 == 0x9000_0000 {
        let immlo = (w >> 29) & 3;
        let immhi = (w >> 5) & 0x7_FFFF;
        let imm = ((immhi << 2) | immlo) as i64;
        let off = if imm & (1 << 20) != 0 {
            (imm - (1 << 21)) << 12
        } else {
            imm << 12
        };
        return Ok(Inst64::Adrp {
            rd: gpr_sp(w & 0x1F),
            off,
        });
    }

    Err(format!(
        "unsupported instruction word {w:#010x}: not in the first-batch aarch64 whitelist \
         (calls, system, SIMD/FP, atomics, PAC, multiply, bitfields and more stay native) — \
         keep the function native with --allow-native-fallback or pick another export"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(w: u32) -> Inst64 {
        decode_word(w).unwrap_or_else(|e| panic!("{w:#010x}: {e}"))
    }

    // ---- A1 golden decodes (every word measured on NDK clang+objdump) ----

    #[test]
    fn class1_add_sub_imm() {
        assert_eq!(
            d(0x1104_8C20),
            Inst64::AddSubImm {
                sf: false,
                setflags: false,
                sub: false,
                rd: Gpr::R(0),
                rn: Gpr::R(1),
                imm: 0x123
            }
        );
        // sub x2,x3,#1,lsl#12 → imm 0x1000
        assert_eq!(
            d(0xD140_0462),
            Inst64::AddSubImm {
                sf: true,
                setflags: false,
                sub: true,
                rd: Gpr::R(2),
                rn: Gpr::R(3),
                imm: 0x1000
            }
        );
        // add sp,sp,#32 = 0x910083ff
        assert_eq!(
            d(0x9100_83FF),
            Inst64::AddSubImm {
                sf: true,
                setflags: false,
                sub: false,
                rd: Gpr::Sp,
                rn: Gpr::Sp,
                imm: 32
            }
        );
    }

    #[test]
    fn class2_add_sub_reg_two_forms() {
        assert_eq!(
            d(0x8B02_0020),
            Inst64::AddSubShiftReg {
                sf: true,
                setflags: false,
                sub: false,
                rd: Gpr::R(0),
                rn: Gpr::R(1),
                rm: Gpr::R(2),
                shift: ShiftType::Lsl,
                imm6: 0
            }
        );
        // add w0,w1,w2,lsl #31 — W-form imm6 cap boundary is legal
        assert_eq!(
            d(0x0B02_7C20),
            Inst64::AddSubShiftReg {
                sf: false,
                setflags: false,
                sub: false,
                rd: Gpr::R(0),
                rn: Gpr::R(1),
                rm: Gpr::R(2),
                shift: ShiftType::Lsl,
                imm6: 31
            }
        );
        assert_eq!(
            d(0x8B02_0C20),
            Inst64::AddSubShiftReg {
                sf: true,
                setflags: false,
                sub: false,
                rd: Gpr::R(0),
                rn: Gpr::R(1),
                rm: Gpr::R(2),
                shift: ShiftType::Lsl,
                imm6: 3
            }
        );
        assert_eq!(
            d(0x8B22_6020),
            Inst64::AddSubExtReg {
                sf: true,
                setflags: false,
                sub: false,
                rd: Gpr::R(0),
                rn: Gpr::R(1),
                rm: Gpr::R(2),
                ext: ExtendKind::Uxtx,
                imm3: 0
            }
        );
        assert_eq!(
            d(0x8B22_C820),
            Inst64::AddSubExtReg {
                sf: true,
                setflags: false,
                sub: false,
                rd: Gpr::R(0),
                rn: Gpr::R(1),
                rm: Gpr::R(2),
                ext: ExtendKind::Sxtw,
                imm3: 2
            }
        );
    }

    #[test]
    fn class5_adds_subs_cmp_cmn() {
        // register forms (S=1)
        for (w, sub, sf) in [
            (0xAB06_00A4u32, false, true), // adds x4,x5,x6
            (0x6B09_0107u32, true, false), // subs w7,w8,w9
            (0xEB02_003Fu32, true, true),  // cmp x1,x2
            (0x6B02_003Fu32, true, false), // cmp w1,w2
        ] {
            match d(w) {
                Inst64::AddSubShiftReg {
                    setflags: true,
                    sub: got_sub,
                    sf: got_sf,
                    ..
                }
                | Inst64::AddSubExtReg {
                    setflags: true,
                    sub: got_sub,
                    sf: got_sf,
                    ..
                } => {
                    assert_eq!(got_sub, sub, "{w:#010x}");
                    assert_eq!(got_sf, sf, "{w:#010x}");
                }
                other => panic!("{w:#010x} decoded as {other:?}"),
            }
        }
        // immediate forms (S=1)
        for (w, sub, sf) in [
            (0xB100_1441u32, false, true), // adds x1,x2,#5
            (0x7100_1441u32, true, false), // subs w1,w2,#5
            (0xF100_401Fu32, true, true),  // cmp x0,#0x10
            (0x7100_401Fu32, true, false), // cmp w0,#0x10
        ] {
            match d(w) {
                Inst64::AddSubImm {
                    setflags: true,
                    sub: got_sub,
                    sf: got_sf,
                    ..
                } => {
                    assert_eq!(got_sub, sub, "{w:#010x}");
                    assert_eq!(got_sf, sf, "{w:#010x}");
                }
                other => panic!("{w:#010x} decoded as {other:?}"),
            }
        }
        // cmn x0,x1 / cmn x0,#1
        assert!(matches!(
            d(0xAB01_001F),
            Inst64::AddSubShiftReg { setflags: true, sub: false, rd: Gpr::Zr, .. }
        ));
        assert!(matches!(
            d(0xB100_041F),
            Inst64::AddSubImm { setflags: true, sub: false, rd: Gpr::Zr, imm: 1, .. }
        ));
    }

    #[test]
    fn class3_4_logic() {
        assert_eq!(
            d(0x8A06_00A4),
            Inst64::LogicReg {
                sf: true,
                op: LogicOp::And,
                setflags: false,
                rd: Gpr::R(4),
                rn: Gpr::R(5),
                rm: Gpr::R(6),
                shift: ShiftType::Lsl,
                imm6: 0
            }
        );
        // and w0,w1,w2,lsl #4 (imm6 cap applies to W forms too)
        assert_eq!(
            d(0x0A02_1020),
            Inst64::LogicReg {
                sf: false,
                op: LogicOp::And,
                setflags: false,
                rd: Gpr::R(0),
                rn: Gpr::R(1),
                rm: Gpr::R(2),
                shift: ShiftType::Lsl,
                imm6: 4
            }
        );
        // orr x0,x1,x2,lsr #7
        assert!(matches!(
            d(0xAA42_1C20),
            Inst64::LogicReg { shift: ShiftType::Lsr, imm6: 7, .. }
        ));
        // eor x0,x1,x2,asr #9
        assert!(matches!(
            d(0xCA82_2420),
            Inst64::LogicReg { op: LogicOp::Eor, shift: ShiftType::Asr, imm6: 9, .. }
        ));
        // bitmask immediates
        assert!(matches!(
            d(0x9240_1CA4),
            Inst64::LogicImm { op: LogicOp::And, n: true, immr: 0, imms: 7, .. }
        ));
        assert!(matches!(
            d(0xD240_2E10),
            Inst64::LogicImm { op: LogicOp::Eor, n: true, immr: 0, imms: 11, .. }
        ));
        // tst x2,x3 / tst x3,#0xff / ands
        assert!(matches!(
            d(0xEA03_005F),
            Inst64::LogicReg { op: LogicOp::And, setflags: true, rd: Gpr::Zr, .. }
        ));
        assert!(matches!(
            d(0xF240_1C7F),
            Inst64::LogicImm { setflags: true, rd: Gpr::Zr, .. }
        ));
    }

    #[test]
    fn class6_lsl_lsr_asr_aliases() {
        assert!(matches!(
            d(0xD37F_F820),
            Inst64::UbfmAlias { kind: UbfmKind::Lsl, amount: 1, .. }
        ));
        assert!(matches!(
            d(0x531F_7820),
            Inst64::UbfmAlias { sf: false, kind: UbfmKind::Lsl, amount: 1, .. }
        ));
        assert!(matches!(
            d(0xD341_0020),
            Inst64::UbfmAlias { kind: UbfmKind::Lsl, amount: 63, .. }
        ));
        assert!(matches!(
            d(0x5301_0020),
            Inst64::UbfmAlias { sf: false, kind: UbfmKind::Lsl, amount: 31, .. }
        ));
        assert!(matches!(
            d(0xD345_FC20),
            Inst64::UbfmAlias { kind: UbfmKind::Lsr, amount: 5, .. }
        ));
        assert!(matches!(
            d(0x9347_FC62),
            Inst64::UbfmAlias { kind: UbfmKind::Asr, amount: 7, .. }
        ));
        // lsl/lsr #0 = MOV alias word
        assert!(matches!(
            d(0xD340_FC20),
            Inst64::UbfmAlias { kind: UbfmKind::Mov, .. }
        ));
        assert!(matches!(
            d(0x9340_FC20),
            Inst64::UbfmAlias { kind: UbfmKind::Mov, signed_: true, .. }
        ));
    }

    #[test]
    fn class7_variable_shifts() {
        assert!(matches!(
            d(0x9AC6_20A4),
            Inst64::VarShift { kind: VarShiftKind::Lslv, .. }
        ));
        assert!(matches!(
            d(0x9AC6_24A4),
            Inst64::VarShift { kind: VarShiftKind::Lsrv, .. }
        ));
        assert!(matches!(
            d(0x9AC6_28A4),
            Inst64::VarShift { kind: VarShiftKind::Asrv, .. }
        ));
        assert!(matches!(
            d(0x1AC6_28A4),
            Inst64::VarShift { sf: false, kind: VarShiftKind::Asrv, .. }
        ));
        // rorv (opc=19) fails closed
        assert!(decode_word(0x9AC6_4CA4).is_err());
    }

    #[test]
    fn class8_movz_movk_mov() {
        assert!(matches!(
            d(0xD280_0200),
            Inst64::Movz { sf: true, imm16: 0x10, hw: 0, .. }
        ));
        assert!(matches!(
            d(0x5280_0200),
            Inst64::Movz { sf: false, imm16: 0x10, hw: 0, .. }
        ));
        assert!(matches!(
            d(0xD2A2_4680),
            Inst64::Movz { imm16: 0x1234, hw: 1, .. }
        ));
        assert!(matches!(
            d(0xF282_4680),
            Inst64::Movk { sf: true, imm16: 0x1234, hw: 0, .. }
        ));
        assert!(matches!(
            d(0x7282_4680),
            Inst64::Movk { sf: false, imm16: 0x1234, hw: 0, .. }
        ));
        assert!(matches!(
            d(0xF2EA_CF00),
            Inst64::Movk { imm16: 0x5678, hw: 3, .. }
        ));
        // mov x0,x1 = orr x0,xzr,x1 (rn is the zero register)
        assert!(matches!(
            d(0xAA01_03E0),
            Inst64::LogicReg { op: LogicOp::Orr, rn: Gpr::Zr, rm: Gpr::R(1), rd: Gpr::R(0), .. }
        ));
        // mov x0,sp = add x0,sp,#0
        assert!(matches!(
            d(0x9100_03E0),
            Inst64::AddSubImm { rd: Gpr::R(0), rn: Gpr::Sp, imm: 0, .. }
        ));
    }

    #[test]
    fn class9_12_branches() {
        assert_eq!(d(0x1400_0002), Inst64::B { off: 8 });
        assert_eq!(d(0x5400_0043), Inst64::BCond { cond: 3, off: 8 });
        assert_eq!(d(0x5400_0040), Inst64::BCond { cond: 0, off: 8 });
        assert_eq!(d(0x5400_0042), Inst64::BCond { cond: 2, off: 8 });
        assert_eq!(d(0x5400_004A), Inst64::BCond { cond: 10, off: 8 });
        assert_eq!(d(0xB400_0040), Inst64::Cbz { sf: true, nz: false, rt: Gpr::R(0), off: 8 });
        assert_eq!(d(0x3500_0041), Inst64::Cbz { sf: false, nz: true, rt: Gpr::R(1), off: 8 });
        assert_eq!(
            d(0x3618_0040),
            Inst64::Tbz { nz: false, rt: Gpr::R(0), bit: 3, off: 8 }
        );
        assert_eq!(
            d(0xB7F8_0040),
            Inst64::Tbz { nz: true, rt: Gpr::R(0), bit: 63, off: 8 }
        );
        assert_eq!(
            d(0x36F8_0040),
            Inst64::Tbz { nz: false, rt: Gpr::R(0), bit: 31, off: 8 }
        );
        // unsupported conds fail closed by name
        for w in [0x5400_0044u32, 0x5400_0045, 0x5400_0046, 0x5400_0047, 0x5400_004E, 0x5400_004F]
        {
            let e = decode_word(w).unwrap_err();
            assert!(e.contains("b."), "{w:#010x}: {e}");
        }
        // negative branch offsets sign-extend
        match d(0x17FF_FFFE) {
            Inst64::B { off } => assert_eq!(off, -8),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn class13_15_mem_and_ret() {
        assert_eq!(d(0xD65F_03C0), Inst64::Ret);
        assert!(matches!(
            d(0xF940_0420),
            Inst64::LdrStr { size: 3, load: true, rt: Gpr::R(0), rn: Gpr::R(1), off: 8 }
        ));
        assert!(matches!(
            d(0xB940_0820),
            Inst64::LdrStr { size: 2, load: true, off: 8, .. }
        ));
        assert!(matches!(
            d(0x7940_0862),
            Inst64::LdrStr { size: 1, load: true, rt: Gpr::R(2), rn: Gpr::R(3), off: 4 }
        ));
        assert!(matches!(
            d(0x3940_18A4),
            Inst64::LdrStr { size: 0, load: true, rt: Gpr::R(4), rn: Gpr::R(5), off: 6 }
        ));
        assert!(matches!(
            d(0xF900_13E0),
            Inst64::LdrStr { size: 3, load: false, rt: Gpr::R(0), rn: Gpr::Sp, off: 32 }
        ));
        assert!(matches!(
            d(0xA941_07E0),
            Inst64::LdpStp {
                sf: true,
                load: true,
                mode: PairMode::SignedOffset,
                rt: Gpr::R(0),
                rt2: Gpr::R(1),
                rn: Gpr::Sp,
                off: 16
            }
        ));
        assert!(matches!(
            d(0xA9BF_7BFD),
            Inst64::LdpStp {
                mode: PairMode::PreIndex,
                load: false,
                rt: Gpr::R(29),
                rt2: Gpr::R(30),
                rn: Gpr::Sp,
                off: -16,
                ..
            }
        ));
        assert!(matches!(
            d(0xA8C1_0FE2),
            Inst64::LdpStp { mode: PairMode::PostIndex, load: true, off: 16, .. }
        ));
        assert!(matches!(
            d(0x2941_07E0),
            Inst64::LdpStp { sf: false, load: true, off: 8, .. }
        ));
    }

    #[test]
    fn class16_17_adr_adrp_nop() {
        assert_eq!(d(0x1000_0000), Inst64::Adr { rd: Gpr::R(0), off: 0 });
        assert_eq!(d(0x1000_0805), Inst64::Adr { rd: Gpr::R(5), off: 0x100 });
        assert_eq!(d(0x9000_0000), Inst64::Adrp { rd: Gpr::R(0), off: 0 });
        assert_eq!(d(0xD503_201F), Inst64::Nop);
        // negative adr offsets sign-extend: imm21 = 0x1FFFD (= -3)
        let w = 0x1000_0000u32 | (1u32 << 29) | (0x7_FFFFu32 << 5);
        match d(w) {
            Inst64::Adr { off, .. } => assert_eq!(off, -3),
            other => panic!("{other:?}"),
        }
    }

    // ---- A1 negatives: the design's named collision + UNDEFINED forms ----

    #[test]
    fn adr_word_is_not_decoded_as_b() {
        // 0x10000000 is `adr x0, .`; a naive b decode on [31:26]=000100
        // would misread it. Full-mask b must reject it.
        assert!(!matches!(decode_word(0x1000_0000), Ok(Inst64::B { .. })));
        assert_eq!(d(0x1000_0000), Inst64::Adr { rd: Gpr::R(0), off: 0 });
        // bl is a call, never a b
        assert!(decode_word(0x9400_0002).is_err());
    }

    #[test]
    fn w_form_imm6_above_31_is_named_undefined() {
        // add w0,w1,w2,lsl #32 = 0x0B028020 — assembler rejects; decoder must too
        let e = decode_word(0x0B02_8020).unwrap_err();
        assert!(e.contains("UNDEFINED"), "{e}");
        assert!(e.contains("32"), "{e}");
        // and w5,w6,w7,lsl #47 = 0x0A07BC25 — same class
        let e = decode_word(0x0A07_BC25).unwrap_err();
        assert!(e.contains("UNDEFINED"), "{e}");
    }

    #[test]
    fn cmn_imm_zero_is_named_rejected() {
        // cmn x0,#0 = 0xb100001f — assembler accepts; the C-bit corner
        // (§6.3) makes hs/lo diverge, so the first batch rejects it.
        let e = decode_word(0xB100_001F).unwrap_err();
        assert!(e.contains("immediate 0"), "{e}");
        assert!(e.contains("C-flag"), "{e}");
    }

    #[test]
    fn reserved_bitmasks_fail_closed() {
        // N=1, imms=0b111111 with immr=0 → imm = ~0 (valid: mvn). imms=63,N=1:
        // all-ones welem — valid (mov x0,#-1 style). Reserved: N=0, imms>=32
        // region, e.g. N=0, immr=0, imms=0b111111 (63) → len path invalid.
        assert!(decode_bitmask(false, 0, 63, true).is_none());
        assert!(decode_bitmask(false, 0, 63, false).is_none());
        // and x0,x1,#(reserved) word: N=0 immr=0 imms=63 sf=1
        let w = 0x9200_0000u32 | (0 << 16) | (63 << 10) | (1 << 5) | 0;
        let e = decode_word(w).unwrap_err();
        assert!(e.contains("reserved bitmask"), "{e}");
    }

    #[test]
    fn bitmask_decode_known_constants() {
        assert_eq!(decode_bitmask(true, 0, 7, true), Some(0xFF));
        assert_eq!(decode_bitmask(true, 0, 11, true), Some(0xFFF));
        assert_eq!(
            decode_bitmask(true, 32, 15, true),
            Some(0x0000_FFFF_0000_0000)
        );
        assert_eq!(decode_bitmask(false, 0, 7, false), Some(0xFF));
        assert_eq!(decode_bitmask(true, 0, 63, true), Some(u64::MAX));
        assert_eq!(decode_bitmask(true, 0, 0, true), Some(1)); // esize 64, single bit
        // all-ones 32-bit element: N=0, imms=31
        assert_eq!(decode_bitmask(false, 0, 31, false), Some(0xFFFF_FFFF));
        // single bit at 31 = ror(1, 1) within a 32-bit element
        assert_eq!(decode_bitmask(false, 1, 0, false), Some(0x8000_0000));
    }

    #[test]
    fn system_pac_simd_call_shapes_fail_closed() {
        for w in [
            0xD503_233Fu32, // paciasp
            0xD503_248Eu32, // bti jc
            0xD63F_0220u32, // blr x17
            0xD400_0001u32, // svc #0
            0x9B02_7C20u32, // mul x0,x1,x2
            0x9AC0_4CA4u32, // rorv
            0x9BA0_0000u32, // madd region
            0x4E20_0000u32, // SIMD
            0x9370_0000u32, // BFM region
            0x9AC0_0000u32, // rorv base (opc=11 region)
        ] {
            assert!(decode_word(w).is_err(), "{w:#010x} must fail closed");
        }
    }

    #[test]
    fn movn_fails_closed() {
        // movn x0,#0 = 0x12800000 — outside the first batch (§3.2)
        assert!(decode_word(0x1280_0000).is_err());
    }

    #[test]
    fn csel_family_never_decodes_as_variable_shift() {
        // csel/csinc share bits[31:24] with lslv; only bits[23:21]+opc
        // separate them. The collision case: csel cond=hs has opc==lslv's.
        assert!(decode_word(0x9A82_2020).is_err(), "csel x0,x1,x2,hs");
        assert!(decode_word(0x9A82_3020).is_err(), "csel x0,x1,x2,lo");
        assert!(decode_word(0x9A82_1420).is_err(), "csinc x0,x1,x2,ne");
        assert!(decode_word(0x9A9F_17E0).is_err(), "cset x0,eq");
        assert!(decode_word(0x9B02_0C20).is_err(), "madd");
        assert!(decode_word(0xFA41_0000).is_err(), "ccmp");
    }

    // ---- A6: fuzz the decoder with SHA-derived words; no panics, every
    // rejection is a named error (checked by unwrap_err returning String).
    #[test]
    fn sha_word_stream_never_panics_and_names_errors() {
        use sha2::{Digest, Sha256};
        let mut words_decoded = 0usize;
        let mut errors = 0usize;
        let mut h = Sha256::new();
        h.update(b"aarch64-decode-fuzz");
        let mut buf = h.finalize().to_vec();
        let total = 1_000_000u32;
        let mut done = 0u32;
        while done < total {
            let mut h2 = Sha256::new();
            h2.update(&buf);
            h2.update(done.to_le_bytes());
            let digest = h2.finalize();
            for chunk in digest.chunks_exact(4) {
                let w = u32::from_le_bytes(chunk.try_into().unwrap());
                match decode_word(w) {
                    Ok(_) => words_decoded += 1,
                    Err(msg) => {
                        errors += 1;
                        // named error: non-empty, mentions the word
                        assert!(!msg.is_empty());
                        assert!(msg.contains(&format!("{w:#010x}")), "{msg}");
                    }
                }
                done += 1;
                if done >= total {
                    break;
                }
            }
            buf = digest.to_vec();
        }
        // The whitelist must actually accept some words (sanity: not
        // rejecting everything) and reject the vast majority.
        assert!(words_decoded > 100, "decoded {words_decoded}");
        assert!(errors > total as usize / 2);
    }

    // Regression sweep: 21 logical immediates assembled by NDK clang 18
    // (aarch64-linux-android34, `and x1,x0,#imm`) — the words are the
    // assembler's own encodings, so this pins decode_bitmask to real
    // toolchain output. The pre-fix decoder rejected 0x0f0f../0x5555../
    // 0x33.. (canonical N=0, imms-in-high-bits shapes) as "reserved".
    #[test]
    fn class_bitmask_ndk_golden_sweep() {
        let goldens: &[(u32, u64)] = &[
            (0x9240_1C01, 0x0000_0000_0000_00FF),
            (0x9240_0C01, 0x0000_0000_0000_000F),
            (0x927C_0C01, 0x0000_0000_0000_00F0),
            (0x9200_CC01, 0x0F0F_0F0F_0F0F_0F0F),
            (0x9204_CC01, 0xF0F0_F0F0_F0F0_F0F0),
            (0x9200_F001, 0x5555_5555_5555_5555),
            (0x9201_F001, 0xAAAA_AAAA_AAAA_AAAA),
            (0x9200_E401, 0x3333_3333_3333_3333),
            (0x9202_E401, 0xCCCC_CCCC_CCCC_CCCC),
            (0x9240_3C01, 0x0000_0000_0000_FFFF),
            (0x9270_3C01, 0x0000_0000_FFFF_0000),
            (0x9200_3C01, 0x0000_FFFF_0000_FFFF),
            (0x9218_3C01, 0x00FF_FF00_00FF_FF00),
            (0x9241_0001, 0x8000_0000_0000_0000),
            (0x9240_BC01, 0x0000_FFFF_FFFF_FFFF),
            (0x9208_9C01, 0xFF00_FF00_FF00_FF00),
            (0x9200_9C01, 0x00FF_00FF_00FF_00FF),
            (0x9240_3801, 0x0000_0000_0000_7FFF),
            (0x9240_0001, 0x0000_0000_0000_0001),
            (0x9240_0401, 0x0000_0000_0000_0003),
            (0x927E_7401, 0x0000_0000_FFFF_FFFC),
        ];
        for &(w, want) in goldens {
            let n = (w >> 22) & 1 != 0;
            let immr = ((w >> 16) & 0x3F) as u8;
            let imms = ((w >> 10) & 0x3F) as u8;
            let got = decode_bitmask(n, immr, imms, true)
                .unwrap_or_else(|| panic!("{w:#010x}: rejected as reserved"));
            assert_eq!(got, want, "{w:#010x}: n={n} immr={immr} imms={imms}");
        }
    }
}
