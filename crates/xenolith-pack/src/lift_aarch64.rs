//! CFG lift of a selected ELF aarch64 function into the 64-bit IR
//! (vm-aarch64 design §2, §3, §6).
//!
//! Fail-closed discipline mirrors `lift.rs` (the x86-64 lifter): every
//! rejection names the function, the faulting instruction word and its RVA,
//! and tells the user what to do next. The whitelist is the first-batch
//! matrix of design §3.1; everything else — including the flags-fusion
//! matrix rejections of §6.3 — is a named pack error, never a silent
//! approximation.

use xenolith_formats::elf::{self, Elf64};
use xenolith_vm::aarch64_decode::{
    cond_name, decode_bitmask, decode_word, ExtendKind, Gpr, Inst64, LogicOp, PairMode,
    ShiftType, UbfmKind, VarShiftKind,
};
use xenolith_vm::ir::{BinOp, CmpOp};
use xenolith_vm::ir64::{
    Addr64, Ir64Block, Ir64Module, Src64, Stmt64, Term64, Width64, VREG64_SP,
};

pub const MAX_LIFT_BYTES: usize = 256;

#[derive(Debug)]
pub struct LiftError(pub String);

impl std::fmt::Display for LiftError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Clone, Debug)]
pub struct LiftedExport64 {
    pub name: String,
    pub rva: u32,
    pub native_len: usize,
    pub ir: Ir64Module,
}

/// §6.3 flags-producer state: what the next b.cond may consume.
#[derive(Clone, Copy, Debug)]
enum FlagSrc {
    /// subs/cmp (register or immediate): the compare(lhs,rhs) view is exact
    /// for all ten predicates. `pure` = no value write (rd was ZR).
    Subs { lhs: Src64, rhs: Src64, w: Width64, pure: bool },
    /// cmn/adds with imm != 0: compare(lhs, −imm) exact for all ten.
    CmnImm { lhs: Src64, neg_imm: u64, w: Width64, pure: bool },
    /// cmn/adds register form: only eq/ne are exact (C corner at rhs=0, V
    /// corner at rhs=INT_MIN). eq/ne ⟺ lhs + rhs == 0.
    CmnReg { lhs: Src64, rhs: Src64, w: Width64, scratch: u8, pure: bool },
    /// ands/tst: value a&b materialized in `mat`; eq/ne/ge/lt/gt/le exact
    /// (N/V view), hs/lo/hi/ls are not (C=0 vs compare(·,0) C=1).
    Ands { mat: u8, w: Width64, pure: bool },

}

pub fn lift_function_aarch64(
    parsed: &Elf64,
    image: &[u8],
    name: &str,
    rva: u32,
    len: Option<u32>,
    ifunc_resolvers: &[u64],
) -> Result<LiftedExport64, LiftError> {
    if let Some(rule) = crate::lift::forbidden_vm_rule(name) {
        return Err(LiftError(format!(
            "vm-export {name}: stays native ({rule}); CRT/JNI ABI exports must stay native — \
             pick another export"
        )));
    }
    // §8.4 ifunc exclusion: a resolver runs during ld.so relocation, before
    // the INIT_ARRAY unpack stub — hooking it is unproven in that window.
    if ifunc_resolvers.contains(&(rva as u64)) {
        return Err(LiftError(format!(
            "vm-export {name} (rva {rva:#x}): IFUNC resolvers run during ld.so relocation, \
             before the INIT_ARRAY unpack stub; hooking the entry in that pre-init window is \
             unproven, so resolver functions stay native — pick a non-ifunc export"
        )));
    }
    let off = elf::vaddr_file_offset(image, parsed, rva as u64)
        .map_err(|_| LiftError(format!("vm-export {name}: bad rva {rva:#x}")))?;
    let cap = len
        .map(|n| n as usize)
        .unwrap_or(MAX_LIFT_BYTES)
        .min(MAX_LIFT_BYTES)
        .min(image.len().saturating_sub(off));
    if cap == 0 {
        return Err(LiftError(format!("vm-export {name}: empty at {rva:#x}")));
    }
    let (ir, native_len) = lift_code64(&image[off..off + cap], rva as u64, name)?;
    if let Some(want) = len {
        if native_len as u32 > want {
            return Err(LiftError(format!(
                "lift {name}: decoded {native_len} bytes past selected length {want}"
            )));
        }
    }
    Ok(LiftedExport64 {
        name: name.to_string(),
        rva,
        native_len,
        ir,
    })
}

/// Decode the reachable window (worklist, leaders) then lift block by block.
pub fn lift_code64(bytes: &[u8], start_ip: u64, name: &str) -> Result<(Ir64Module, usize), LiftError> {
    let decoded = decode_reachable64(bytes, start_ip, name)?;
    if decoded.is_empty() {
        return Err(LiftError(format!("vm-export {name}: no instructions")));
    }
    let native_len = decoded
        .keys()
        .map(|ip| (*ip - start_ip) as usize + 4)
        .max()
        .unwrap_or(0);
    let mut leaders = std::collections::BTreeSet::new();
    leaders.insert(start_ip);
    for (ip, inst) in &decoded {
        match inst {
            Inst64::B { off } => {
                leaders.insert(ip.wrapping_add(*off as u64));
            }
            Inst64::BCond { off, .. } => {
                leaders.insert(ip.wrapping_add(*off as u64));
                leaders.insert(ip + 4);
            }
            Inst64::Cbz { off, .. } | Inst64::Tbz { off, .. } => {
                leaders.insert(ip.wrapping_add(*off as u64));
                leaders.insert(ip + 4);
            }
            _ => {}
        }
    }
    // Branch targets must be 4-aligned and inside the window; anything else
    // was already rejected in decode_reachable64.
    let scratch = scratch_vreg64(&decoded);
    let leader_list: Vec<u64> = leaders.into_iter().collect();
    let index_of = |ip: u64| -> Result<usize, LiftError> {
        leader_list
            .iter()
            .position(|l| *l == ip)
            .ok_or_else(|| LiftError(format!("vm-export {name}: no block at {ip:#x}")))
    };
    let mut blocks = Vec::with_capacity(leader_list.len());
    for (bi, &leader) in leader_list.iter().enumerate() {
        let next_leader = leader_list.get(bi + 1).copied();
        blocks.push(lift_block64(
            &decoded,
            leader,
            next_leader,
            name,
            &index_of,
            scratch,
        )?);
    }
    let entry = index_of(start_ip)?;
    Ok((Ir64Module { blocks, entry }, native_len))
}

/// A vreg the window never touches, for materializations (bitmask constants,
/// shifted operands, tbz masks). Over-approximated like the x86 lifter.
fn scratch_vreg64(decoded: &std::collections::BTreeMap<u64, Inst64>) -> Option<u8> {
    let mut used = [false; 31];
    let mut mark = |g: Gpr, used: &mut [bool; 31]| {
        if let Gpr::R(n) = g {
            if (n as usize) < 31 {
                used[n as usize] = true;
            }
        }
    };
    for inst in decoded.values() {
        mark_regs(inst, &mut mark, &mut used);
    }
    // x30 (LR) carries the thunk's return; x18 is the platform register.
    // Neither may serve as the materialization scratch.
    used[30] = true;
    used[18] = true;
    (0..31u8).find(|&v| !used[v as usize])
}

fn mark_regs(
    inst: &Inst64,
    mark: &mut impl FnMut(Gpr, &mut [bool; 31]),
    used: &mut [bool; 31],
) {
    match *inst {
        Inst64::AddSubImm { rd, rn, .. } => {
            mark(rd, used);
            mark(rn, used);
        }
        Inst64::AddSubShiftReg { rd, rn, rm, .. } | Inst64::AddSubExtReg { rd, rn, rm, .. } => {
            mark(rd, used);
            mark(rn, used);
            mark(rm, used);
        }
        Inst64::LogicReg { rd, rn, .. } | Inst64::LogicImm { rd, rn, .. } => {
            mark(rd, used);
            mark(rn, used);
            if let Inst64::LogicReg { rm, .. } = *inst {
                mark(rm, used);
            }
        }
        Inst64::UbfmAlias { rd, rn, .. } | Inst64::VarShift { rd, rn, .. } => {
            mark(rd, used);
            mark(rn, used);
            if let Inst64::VarShift { rm, .. } = *inst {
                mark(rm, used);
            }
        }
        Inst64::Movz { rd, .. } | Inst64::Movk { rd, .. } | Inst64::Adr { rd, .. }
        | Inst64::Adrp { rd, .. } => mark(rd, used),
        Inst64::LdrStr { rt, rn, .. } => {
            mark(rt, used);
            mark(rn, used);
        }
        Inst64::LdpStp { rt, rt2, rn, .. } => {
            mark(rt, used);
            mark(rt2, used);
            mark(rn, used);
        }
        Inst64::Cbz { rt, .. } | Inst64::Tbz { rt, .. } => mark(rt, used),
        Inst64::B { .. } | Inst64::BCond { .. } | Inst64::Ret | Inst64::Nop => {}
    }
}

fn decode_reachable64(
    bytes: &[u8],
    start_ip: u64,
    name: &str,
) -> Result<std::collections::BTreeMap<u64, Inst64>, LiftError> {
    let mut decoded = std::collections::BTreeMap::new();
    let mut work = vec![start_ip];
    let end_ip = start_ip + bytes.len() as u64;
    while let Some(ip) = work.pop() {
        if decoded.contains_key(&ip) {
            continue;
        }
        if ip < start_ip || ip + 4 > end_ip {
            return Err(LiftError(format!(
                "vm-export {name}: branch out of lift window to {ip:#x} (window \
                 {start_ip:#x}..{end_ip:#x}, cap {MAX_LIFT_BYTES} bytes); the function is left \
                 native with --allow-native-fallback, or select an explicit fn_{:#x}/rva \
                 window that fits the cap",
                ip as u32
            )));
        }
        if ip % 4 != 0 {
            return Err(LiftError(format!(
                "vm-export {name}: branch target {ip:#x} is not 4-byte aligned"
            )));
        }
        let off = (ip - start_ip) as usize;
        let word = u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap());
        let inst = decode_word(word).map_err(|why| {
            LiftError(format!("vm-export {name}: {why} (at rva {ip:#x})"))
        })?;
        match inst {
            Inst64::B { off: rel } => work.push(ip.wrapping_add(rel as u64)),
            Inst64::BCond { off: rel, .. } => {
                work.push(ip.wrapping_add(rel as u64));
                work.push(ip + 4);
            }
            Inst64::Cbz { off: rel, .. } | Inst64::Tbz { off: rel, .. } => {
                work.push(ip.wrapping_add(rel as u64));
                work.push(ip + 4);
            }
            Inst64::Ret => {}
            _ => work.push(ip + 4),
        }
        decoded.insert(ip, inst);
    }
    Ok(decoded)
}

// ---- register helpers ----

fn src_of(g: Gpr) -> Src64 {
    match g {
        Gpr::R(n) => Src64::Reg(n),
        Gpr::Zr => Src64::Imm(0),
        Gpr::Sp => Src64::Reg(VREG64_SP),
    }
}

fn unsupported_sp(name: &str, ip: u64, what: &str) -> LiftError {
    LiftError(format!(
        "vm-export {name}: unsupported SP reference at {ip:#x} ({what}); the SP whitelist \
         covers add/sub sp,sp,#imm, [sp,#off] memory, ldp/stp pre/post-index on sp and \
         mov xD,sp only — rewrite the frame code or keep the function native with \
         --allow-native-fallback"
    ))
}

fn x18_rejected(name: &str, ip: u64) -> LiftError {
    LiftError(format!(
        "vm-export {name}: x18 reference at {ip:#x}; x18 is the platform register (shadow-call \
         stack / custom ABIs) and is never virtualized — keep the function native with \
         --allow-native-fallback"
    ))
}

fn check_reg(g: Gpr, name: &str, ip: u64) -> Result<u8, LiftError> {
    match g {
        Gpr::R(n) if n == 18 => Err(x18_rejected(name, ip)),
        Gpr::R(n) => Ok(n),
        Gpr::Zr => Ok(31), // callers map Zr via src_of; dst sites drop writes
        Gpr::Sp => Ok(VREG64_SP),
    }
}

// ---- per-instruction classification (LiftStep64) ----

enum Step64 {
    /// Ordered statement sequence (multi-instruction expansions keep order).
    Seq(Vec<Stmt64>),
    /// A flags producer whose value stmts ride first.
    Producer { stmts: Vec<Stmt64>, src: FlagSrc },
    Ret,
    Jmp(u64),
    Jcc {
        cond: u8,
        target: u64,
        fallthrough: u64,
        ip: u64,
    },
    Skip,
}

fn classify64(
    inst: &Inst64,
    ip: u64,
    name: &str,
    scratch: Option<u8>,
) -> Result<Step64, LiftError> {
    match inst {
        Inst64::Ret => Ok(Step64::Ret),
        Inst64::Nop => Ok(Step64::Skip),
        Inst64::B { off } => Ok(Step64::Jmp(ip.wrapping_add(*off as u64))),
        Inst64::BCond { cond, off } => Ok(Step64::Jcc {
            cond: *cond,
            target: ip.wrapping_add(*off as u64),
            fallthrough: ip + 4,
            ip,
        }),
        Inst64::AddSubImm { sf, setflags, sub, rd, rn, imm } => {
            let w = if *sf { Width64::X } else { Width64::W };
            let op = if *sub { BinOp::Sub } else { BinOp::Add };
            // SP whitelist (§3.1): add/sub sp,sp,#imm (the real write),
            // mov xD,sp (imm 0 read), and nothing else in this family.
            if matches!(rd, Gpr::Sp) {
                if *setflags {
                    return Err(unsupported_sp(name, ip, "adds/subs writing SP"));
                }
                if !matches!(rn, Gpr::Sp) {
                    return Err(unsupported_sp(name, ip, "SP write from a non-SP base"));
                }
                let imm_v = *imm;
                return Ok(Step64::Seq(vec![Stmt64::Bin {
                    op,
                    w: Width64::X,
                    dst: VREG64_SP,
                    lhs: Src64::Reg(VREG64_SP),
                    rhs: Src64::Imm(imm_v),
                }]));
            }
            if matches!(rn, Gpr::Sp) {
                if *imm == 0 && !setflags {
                    // mov xD, sp
                    let d = check_reg(*rd, name, ip)?;
                    return Ok(Step64::Seq(vec![Stmt64::Mov {
                        dst: d,
                        src: Src64::Reg(VREG64_SP),
                    }]));
                }
                return Err(unsupported_sp(name, ip, "SP as add/sub-immediate source"));
            }
            let r = src_of(*rn);
            let imm_v = if *sf { *imm } else { *imm & 0xFFFF_FFFF };
            let mut stmts = Vec::new();
            if !matches!(rd, Gpr::Zr) {
                let d = check_reg(*rd, name, ip)?;
                stmts.push(Stmt64::Bin {
                    op,
                    w,
                    dst: d,
                    lhs: r,
                    rhs: Src64::Imm(imm_v),
                });
            } else if !setflags {
                return Ok(Step64::Skip);
            }
            if !setflags {
                return Ok(Step64::Seq(stmts));
            }
            // flags producer
            if *sub {
                // subs/cmp: compare(lhs, imm) — exact for all predicates.
                Ok(Step64::Producer {
                    stmts,
                    src: FlagSrc::Subs {
                        lhs: r,
                        rhs: Src64::Imm(imm_v),
                        w,
                        pure: matches!(rd, Gpr::Zr),
                    },
                })
            } else {
                // adds/cmn imm (imm != 0, decode-rejected otherwise):
                // compare(lhs, −imm) exact for all predicates.
                let neg = imm_v.wrapping_neg();
                let neg = if *sf { neg } else { neg & 0xFFFF_FFFF };
                Ok(Step64::Producer {
                    stmts,
                    src: FlagSrc::CmnImm {
                        lhs: r,
                        neg_imm: neg,
                        w,
                        pure: matches!(rd, Gpr::Zr),
                    },
                })
            }
        }
        Inst64::AddSubShiftReg { sf, setflags, sub, rd, rn, rm, shift, imm6 } => {
            let w = if *sf { Width64::X } else { Width64::W };
            let op = if *sub { BinOp::Sub } else { BinOp::Add };
            for g in [*rd, *rn, *rm] {
                if let Gpr::R(18) = g {
                    return Err(x18_rejected(name, ip));
                }
                if matches!(g, Gpr::Sp) {
                    // The shifted form decodes 31 as XZR (never SP) — fail
                    // closed anyway against decoder drift.
                    return Err(unsupported_sp(name, ip, "SP in shifted-register add/sub"));
                }
            }
            let lhs = src_of(*rn);
            // Pure register operand is used directly; a shifted operand
            // materializes into the scratch first (§3.1#2a): the shift rides
            // a temp, the main op stays a plain Bin.
            let (rhs, shift_stmt) = operand_with_shift(*rm, *shift, *imm6, w, scratch, name, ip)?;
            let mut stmts = Vec::new();
            if let Some(st) = shift_stmt {
                stmts.push(st);
            }
            let rd_is_zr = matches!(rd, Gpr::Zr);
            if !rd_is_zr {
                let d = check_reg(*rd, name, ip)?;
                stmts.push(Stmt64::Bin {
                    op,
                    w,
                    dst: d,
                    lhs,
                    rhs,
                });
            } else if !setflags {
                // discarded destination, no flags: side-effect-free
                return Ok(Step64::Skip);
            }
            if !setflags {
                return Ok(Step64::Seq(stmts));
            }
            if *sub {
                Ok(Step64::Producer {
                    stmts,
                    src: FlagSrc::Subs { lhs, rhs, w, pure: rd_is_zr },
                })
            } else {
                // cmn register form: eq/ne only (§6.3), materialize -rhs.
                let t = scratch.ok_or_else(|| no_scratch(name, ip, "cmn register form"))?;
                stmts.push(Stmt64::Bin {
                    op: BinOp::Sub,
                    w,
                    dst: t,
                    lhs: Src64::Imm(0),
                    rhs,
                });
                Ok(Step64::Producer {
                    stmts,
                    src: FlagSrc::CmnReg { lhs, rhs, w, scratch: t, pure: rd_is_zr },
                })
            }
        }
        Inst64::AddSubExtReg { sf, setflags, sub, rd, rn, rm, ext, imm3 } => {
            let w = if *sf { Width64::X } else { Width64::W };
            let op = if *sub { BinOp::Sub } else { BinOp::Add };
            if let Gpr::R(18) = *rm {
                return Err(x18_rejected(name, ip));
            }
            // Rn=SP: `add x0,sp,x2,uxtx` etc. — read of SP outside the
            // whitelisted mov shape; keep SP reads to the imm form.
            if matches!(rn, Gpr::Sp) {
                return Err(unsupported_sp(name, ip, "SP as extended-register source"));
            }
            if matches!(rd, Gpr::Sp) {
                return Err(unsupported_sp(name, ip, "SP as extended-register destination"));
            }
            let t = scratch
                .ok_or_else(|| no_scratch(name, ip, "extended register operand"))?;
            let mut stmts = Vec::new();
            // Materialize the extended+shifted operand into t.
            match ext {
                ExtendKind::Uxtx => stmts.push(Stmt64::Mov {
                    dst: t,
                    src: src_of(*rm),
                }),
                ExtendKind::Uxtb => {
                    stmts.push(Stmt64::Bin {
                        op: BinOp::And,
                        w: Width64::X,
                        dst: t,
                        lhs: src_of(*rm),
                        rhs: Src64::Imm(0xFF),
                    });
                }
                ExtendKind::Uxth => stmts.push(Stmt64::Bin {
                    op: BinOp::And,
                    w: Width64::X,
                    dst: t,
                    lhs: src_of(*rm),
                    rhs: Src64::Imm(0xFFFF),
                }),
                ExtendKind::Sxtb | ExtendKind::Sxth | ExtendKind::Sxtw => {
                    let (mask, sign): (u64, u64) = match ext {
                        ExtendKind::Sxtb => (0xFF, 0x80),
                        ExtendKind::Sxth => (0xFFFF, 0x8000),
                        _ => (0xFFFF_FFFF, 0x8000_0000),
                    };
                    stmts.push(Stmt64::Bin {
                        op: BinOp::And,
                        w: Width64::X,
                        dst: t,
                        lhs: src_of(*rm),
                        rhs: Src64::Imm(mask),
                    });
                    stmts.push(Stmt64::Bin {
                        op: BinOp::Xor,
                        w: Width64::X,
                        dst: t,
                        lhs: Src64::Reg(t),
                        rhs: Src64::Imm(sign),
                    });
                    stmts.push(Stmt64::Bin {
                        op: BinOp::Sub,
                        w: Width64::X,
                        dst: t,
                        lhs: Src64::Reg(t),
                        rhs: Src64::Imm(sign),
                    });
                }
            }
            if *imm3 > 0 {
                stmts.push(Stmt64::Bin {
                    op: BinOp::Shl,
                    w: Width64::X,
                    dst: t,
                    lhs: Src64::Reg(t),
                    rhs: Src64::Imm(*imm3 as u64),
                });
            }
            let d = check_reg(*rd, name, ip)?;
            let lhs = src_of(*rn);
            stmts.push(Stmt64::Bin {
                op,
                w,
                dst: d,
                lhs,
                rhs: Src64::Reg(t),
            });
            if !setflags {
                return Ok(Step64::Seq(stmts));
            }
            if *sub {
                Ok(Step64::Producer {
                    stmts,
                    src: FlagSrc::Subs {
                        lhs,
                        rhs: Src64::Reg(t),
                        w,
                        pure: matches!(rd, Gpr::Zr),
                    },
                })
            } else {
                let _ = setflags;
                Err(LiftError(format!(
                    "vm-export {name}: adds/cmn extended-register form at {ip:#x} is outside \
                     the flags whitelist (only the eq/ne-exact register form lifts) — keep \
                     the function native with --allow-native-fallback",
                )))
            }
        }
        Inst64::LogicReg { sf, op, setflags, rd, rn, rm, shift, imm6 } => {
            let w = if *sf { Width64::X } else { Width64::W };
            for g in [*rd, *rn, *rm] {
                if let Gpr::R(18) = g {
                    return Err(x18_rejected(name, ip));
                }
                if matches!(g, Gpr::Sp) {
                    return Err(unsupported_sp(name, ip, "SP in a logic instruction"));
                }
            }
            // mov reg = orr rd, xzr, rm, lsl #0
            if *op == LogicOp::Orr && matches!(rn, Gpr::Zr) && *shift == ShiftType::Lsl && *imm6 == 0
            {
                if matches!(rd, Gpr::Zr) {
                    return Ok(Step64::Skip);
                }
                let d = check_reg(*rd, name, ip)?;
                return Ok(Step64::Seq(vec![Stmt64::Mov {
                    dst: d,
                    src: src_of(*rm),
                }]));
            }
            let lhs = src_of(*rn);
            let (rhs, shift_stmt) = operand_with_shift(*rm, *shift, *imm6, w, scratch, name, ip)?;
            let bin_op = match op {
                LogicOp::And => BinOp::And,
                LogicOp::Orr => BinOp::Or,
                LogicOp::Eor => BinOp::Xor,
            };
            if matches!(rd, Gpr::Zr) && !setflags {
                // and/orr/eor with a discarded destination: no side effects.
                return Ok(Step64::Skip);
            }
            let mut stmts = Vec::new();
            if let Some(st) = shift_stmt {
                stmts.push(st);
            }
            if !matches!(rd, Gpr::Zr) {
                let d = check_reg(*rd, name, ip)?;
                stmts.push(Stmt64::Bin {
                    op: bin_op,
                    w,
                    dst: d,
                    lhs,
                    rhs,
                });
            }
            if !setflags {
                return Ok(Step64::Seq(stmts));
            }
            // ands: value write (already pushed) + Ands producer.
            if *op != LogicOp::And {
                return Err(LiftError(format!(
                    "vm-export {name}: {op:?} with S=1 at {ip:#x} does not exist (decoder \
                     drift); fail closed",
                )));
            }
            let t = scratch.ok_or_else(|| no_scratch(name, ip, "ands/tst"))?;
            stmts.push(Stmt64::Bin {
                op: BinOp::And,
                w,
                dst: t,
                lhs,
                rhs,
            });
            Ok(Step64::Producer {
                stmts,
                src: FlagSrc::Ands {
                    mat: t,
                    w,
                    pure: matches!(rd, Gpr::Zr),
                },
            })
        }
        Inst64::LogicImm { sf, op, setflags, rd, rn, n, immr, imms } => {
            let w = if *sf { Width64::X } else { Width64::W };
            for g in [*rd, *rn] {
                if let Gpr::R(18) = g {
                    return Err(x18_rejected(name, ip));
                }
            }
            let k = decode_bitmask(*n, *immr, *imms, *sf).ok_or_else(|| {
                LiftError(format!(
                    "vm-export {name}: reserved bitmask at {ip:#x} (decoder should have \
                     rejected this)"
                ))
            })?;
            let t = scratch
                .ok_or_else(|| no_scratch(name, ip, "bitmask immediate materialization"))?;
            let bin_op = match op {
                LogicOp::And => BinOp::And,
                LogicOp::Orr => BinOp::Or,
                LogicOp::Eor => BinOp::Xor,
            };
            let lhs = src_of(*rn);
            let mut stmts = vec![Stmt64::Mov {
                dst: t,
                src: Src64::Imm(k),
            }];
            if matches!(rd, Gpr::Zr) && !setflags {
                // no value write, no flags: still no side effect at all
                return Ok(Step64::Skip);
            }
            if !matches!(rd, Gpr::Zr) {
                let d = check_reg(*rd, name, ip)?;
                stmts.push(Stmt64::Bin {
                    op: bin_op,
                    w,
                    dst: d,
                    lhs,
                    rhs: Src64::Reg(t),
                });
            } else if !setflags {
                return Ok(Step64::Skip);
            }
            if !setflags {
                return Ok(Step64::Seq(stmts));
            }
            // ands/tst immediate
            let t2 = scratch.ok_or_else(|| no_scratch(name, ip, "tst immediate"))?;
            let mut s = vec![Stmt64::Mov {
                dst: t,
                src: Src64::Imm(k),
            }];
            s.push(Stmt64::Bin {
                op: BinOp::And,
                w,
                dst: t2,
                lhs,
                rhs: Src64::Reg(t),
            });
            if !matches!(rd, Gpr::Zr) {
                let d = check_reg(*rd, name, ip)?;
                s.push(Stmt64::Bin {
                    op: BinOp::And,
                    w,
                    dst: d,
                    lhs,
                    rhs: Src64::Reg(t),
                });
            }
            Ok(Step64::Producer {
                stmts: s,
                src: FlagSrc::Ands {
                    mat: t2,
                    w,
                    pure: matches!(rd, Gpr::Zr),
                },
            })
        }
        Inst64::UbfmAlias { sf, kind, rd, rn, amount, .. } => {
            let w = if *sf { Width64::X } else { Width64::W };
            if let Gpr::R(18) = *rd {
                return Err(x18_rejected(name, ip));
            }
            if matches!(rn, Gpr::Sp) || matches!(rd, Gpr::Sp) {
                return Err(unsupported_sp(name, ip, "SP in a bitfield shift"));
            }
            if matches!(rd, Gpr::Zr) {
                return Ok(Step64::Skip);
            }
            let d = check_reg(*rd, name, ip)?;
            let lhs = src_of(*rn);
            let stmt = match kind {
                // W-form MOV alias zero-extends the low 32 bits; the IR Mov
                // is a full-width copy, so fold the extension in.
                UbfmKind::Mov => {
                    if *sf {
                        Stmt64::Mov { dst: d, src: lhs }
                    } else {
                        return Ok(Step64::Seq(vec![
                            Stmt64::Mov { dst: d, src: lhs },
                            Stmt64::Bin {
                                op: BinOp::And,
                                w: Width64::W,
                                dst: d,
                                lhs: Src64::Reg(d),
                                rhs: Src64::Imm(0xFFFF_FFFF),
                            },
                        ]));
                    }
                }
                UbfmKind::Lsl => Stmt64::Bin {
                    op: BinOp::Shl,
                    w,
                    dst: d,
                    lhs,
                    rhs: Src64::Imm(*amount as u64),
                },
                UbfmKind::Lsr => Stmt64::Bin {
                    op: BinOp::Shr,
                    w,
                    dst: d,
                    lhs,
                    rhs: Src64::Imm(*amount as u64),
                },
                UbfmKind::Asr => Stmt64::Bin {
                    op: BinOp::Sar,
                    w,
                    dst: d,
                    lhs,
                    rhs: Src64::Imm(*amount as u64),
                },
            };
            Ok(Step64::Seq(vec![stmt]))
        }
        Inst64::VarShift { sf, kind, rd, rn, rm, .. } => {
            let w = if *sf { Width64::X } else { Width64::W };
            if let Gpr::R(18) = *rm {
                return Err(x18_rejected(name, ip));
            }
            if matches!(rn, Gpr::Sp) || matches!(rd, Gpr::Sp) {
                return Err(unsupported_sp(name, ip, "SP in a variable shift"));
            }
            if matches!(rd, Gpr::Zr) {
                return Ok(Step64::Skip);
            }
            let d = check_reg(*rd, name, ip)?;
            let op = match kind {
                VarShiftKind::Lslv => BinOp::Shl,
                VarShiftKind::Lsrv => BinOp::Shr,
                VarShiftKind::Asrv => BinOp::Sar,
            };
            Ok(Step64::Seq(vec![Stmt64::Bin {
                op,
                w,
                dst: d,
                lhs: src_of(*rn),
                rhs: src_of(*rm),
            }]))
        }
        Inst64::Movz { rd, imm16, hw, .. } => {
            if let Gpr::R(18) = *rd {
                return Err(x18_rejected(name, ip));
            }
            if matches!(rd, Gpr::Sp) {
                return Err(unsupported_sp(name, ip, "SP as movz destination"));
            }
            if matches!(rd, Gpr::Zr) {
                return Ok(Step64::Skip);
            }
            let d = check_reg(*rd, name, ip)?;
            let v = (*imm16 as u64) << (*hw as u32 * 16);
            Ok(Step64::Seq(vec![Stmt64::Mov {
                dst: d,
                src: Src64::Imm(v),
            }]))
        }
        Inst64::Movk { sf, rd, imm16, hw } => {
            if let Gpr::R(18) = *rd {
                return Err(x18_rejected(name, ip));
            }
            if matches!(rd, Gpr::Sp) || matches!(rd, Gpr::Zr) {
                return Ok(Step64::Skip);
            }
            let d = check_reg(*rd, name, ip)?;
            let sh = *hw as u32 * 16;
            let mask = 0xFFFFu64 << sh;
            let v = (*imm16 as u64) << sh;
            let mut stmts = Vec::new();
            if !*sf {
                // W movk discards the upper half before merging.
                stmts.push(Stmt64::Bin {
                    op: BinOp::And,
                    w: Width64::W,
                    dst: d,
                    lhs: Src64::Reg(d),
                    rhs: Src64::Imm(0xFFFF_FFFF),
                });
            }
            let t = scratch.ok_or_else(|| no_scratch(name, ip, "movk"))?;
            stmts.push(Stmt64::Mov {
                dst: t,
                src: Src64::Imm(mask),
            });
            stmts.push(Stmt64::Bin {
                op: BinOp::And,
                w: Width64::X,
                dst: t,
                lhs: Src64::Reg(d),
                rhs: Src64::Reg(t),
            }); // t = dst & M
            stmts.push(Stmt64::Bin {
                op: BinOp::Xor,
                w: Width64::X,
                dst: d,
                lhs: Src64::Reg(d),
                rhs: Src64::Reg(t),
            }); // dst &= ~M
            stmts.push(Stmt64::Bin {
                op: BinOp::Or,
                w: Width64::X,
                dst: d,
                lhs: Src64::Reg(d),
                rhs: Src64::Imm(v),
            });
            Ok(Step64::Seq(stmts))
        }
        Inst64::LdrStr { size, load, rt, rn, off } => {
            let width = 1u8 << size;
            if let Gpr::R(18) = *rt {
                return Err(x18_rejected(name, ip));
            }
            let base = match rn {
                Gpr::Sp => VREG64_SP,
                Gpr::R(n) => {
                    if *n == 18 {
                        return Err(x18_rejected(name, ip));
                    }
                    *n
                }
                Gpr::Zr => 31, // [xzr,#off] is an absolute address — outside
                // the flat model; reject below via base check.
            };
            if matches!(rn, Gpr::Zr) {
                return Err(LiftError(format!(
                    "vm-export {name}: [xzr] absolute addressing at {ip:#x} is outside the \
                     flat-memory model — keep the function native with \
                     --allow-native-fallback",
                )));
            }
            let addr = Addr64::BaseDisp {
                base,
                disp: *off as i32,
            };
            if *load {
                if matches!(rt, Gpr::Zr) {
                    return Ok(Step64::Skip); // prefetch-like discard load
                }
                let d = check_reg(*rt, name, ip)?;
                Ok(Step64::Seq(vec![Stmt64::Load {
                    dst: d,
                    addr,
                    width,
                }]))
            } else {
                Ok(Step64::Seq(vec![Stmt64::Store {
                    addr,
                    src: src_of(*rt),
                    width,
                }]))
            }
        }
        Inst64::LdpStp { sf, load, mode, rt, rt2, rn, off } => {
            for g in [*rt, *rt2] {
                if let Gpr::R(18) = g {
                    return Err(x18_rejected(name, ip));
                }
            }
            let width: u8 = if *sf { 8 } else { 4 };
            if matches!(rn, Gpr::Zr) {
                return Err(LiftError(format!(
                    "vm-export {name}: [xzr] absolute addressing at {ip:#x} is outside the \
                     flat-memory model — keep the function native with \
                     --allow-native-fallback",
                )));
            }
            let is_sp = matches!(rn, Gpr::Sp);
            if !is_sp && matches!(mode, PairMode::PreIndex | PairMode::PostIndex) {
                return Err(LiftError(format!(
                    "vm-export {name}: writeback ldp/stp on a non-SP base at {ip:#x} is \
                     outside the whitelist (register writeback + memory in one instruction) — \
                     keep the function native with --allow-native-fallback",
                )));
            }
            let base = if is_sp { VREG64_SP } else { check_reg(*rn, name, ip)? };
            let addr0 = Addr64::BaseDisp { base, disp: 0 };
            let addr1 = Addr64::BaseDisp {
                base,
                disp: width as i32,
            };
            let mut stmts = Vec::new();
            match mode {
                PairMode::PreIndex => {
                    // sp += off; then store pair from the updated sp.
                    stmts.push(Stmt64::Bin {
                        op: BinOp::Add,
                        w: Width64::X,
                        dst: VREG64_SP,
                        lhs: Src64::Reg(VREG64_SP),
                        rhs: Src64::Imm((*off as i64) as u64),
                    });
                }
                _ => {}
            }
            if *load {
                if !matches!(rt, Gpr::Zr) {
                    let d = check_reg(*rt, name, ip)?;
                    stmts.push(Stmt64::Load {
                        dst: d,
                        addr: addr0,
                        width,
                    });
                }
                if !matches!(rt2, Gpr::Zr) {
                    let d2 = check_reg(*rt2, name, ip)?;
                    stmts.push(Stmt64::Load {
                        dst: d2,
                        addr: addr1,
                        width,
                    });
                }
            } else {
                stmts.push(Stmt64::Store {
                    addr: addr0,
                    src: src_of(*rt),
                    width,
                });
                stmts.push(Stmt64::Store {
                    addr: addr1,
                    src: src_of(*rt2),
                    width,
                });
            }
            match mode {
                PairMode::PostIndex => {
                    stmts.push(Stmt64::Bin {
                        op: BinOp::Add,
                        w: Width64::X,
                        dst: VREG64_SP,
                        lhs: Src64::Reg(VREG64_SP),
                        rhs: Src64::Imm((*off as i64) as u64),
                    });
                }
                PairMode::PreIndex => {}
                PairMode::SignedOffset => {}
            }
            Ok(Step64::Seq(stmts))
        }
        Inst64::Adr { rd, off } => {
            if let Gpr::R(18) = *rd {
                return Err(x18_rejected(name, ip));
            }
            if matches!(rd, Gpr::Sp) || matches!(rd, Gpr::Zr) {
                return Ok(Step64::Skip);
            }
            let d = check_reg(*rd, name, ip)?;
            let rva = ip.wrapping_add(*off as u64) as u32;
            Ok(Step64::Seq(vec![Stmt64::Bias { dst: d, rva }]))
        }
        Inst64::Adrp { rd, off } => {
            if let Gpr::R(18) = *rd {
                return Err(x18_rejected(name, ip));
            }
            if matches!(rd, Gpr::Sp) || matches!(rd, Gpr::Zr) {
                return Ok(Step64::Skip);
            }
            let d = check_reg(*rd, name, ip)?;
            let page = (ip & !0xFFFu64).wrapping_add(*off as u64);
            Ok(Step64::Seq(vec![Stmt64::Bias {
                dst: d,
                rva: page as u32,
            }]))
        }
        // decode_word never returns these without a prior error, but the
        // match must stay exhaustive for future whitelist growth.
        Inst64::Cbz { .. } | Inst64::Tbz { .. } => unreachable!("handled at block level"),
    }
}

fn no_scratch(name: &str, ip: u64, what: &str) -> LiftError {
    LiftError(format!(
        "vm-export {name}: {what} at {ip:#x} needs a spare vreg and every guest GPR of this \
         function is in use — keep the function native with --allow-native-fallback",
    ))
}

/// A register operand, optionally shifted: the pure form is used directly,
/// a shifted form materializes into the scratch (returning its statement).
fn operand_with_shift(
    rm: Gpr,
    shift: ShiftType,
    imm6: u8,
    w: Width64,
    scratch: Option<u8>,
    name: &str,
    ip: u64,
) -> Result<(Src64, Option<Stmt64>), LiftError> {
    if shift == ShiftType::Lsl && imm6 == 0 {
        return Ok((src_of(rm), None));
    }
    if matches!(rm, Gpr::Sp) {
        return Err(unsupported_sp(name, ip, "SP as a shifted operand"));
    }
    let t = scratch.ok_or_else(|| no_scratch(name, ip, "shifted operand"))?;
    let op = match shift {
        ShiftType::Lsl => BinOp::Shl,
        ShiftType::Lsr => BinOp::Shr,
        ShiftType::Asr => BinOp::Sar,
        ShiftType::Ror => {
            return Err(LiftError(format!(
                "vm-export {name}: ROR operand at {ip:#x} (decoder drift); fail closed"
            )))
        }
    };
    Ok((
        Src64::Reg(t),
        Some(Stmt64::Bin {
            op,
            w,
            dst: t,
            lhs: src_of(rm),
            rhs: Src64::Imm(imm6 as u64),
        }),
    ))
}

// ---- block assembly with the §6.3 fusion matrix ----

fn lift_block64(
    decoded: &std::collections::BTreeMap<u64, Inst64>,
    leader: u64,
    next_leader: Option<u64>,
    name: &str,
    index_of: &dyn Fn(u64) -> Result<usize, LiftError>,
    scratch: Option<u8>,
) -> Result<Ir64Block, LiftError> {
    let mut stmts: Vec<Stmt64> = Vec::new();
    let mut pending: Option<FlagSrc> = None;
    let mut ip = leader;
    loop {
        let inst = decoded.get(&ip).ok_or_else(|| {
            LiftError(format!("vm-export {name}: missing instr at {ip:#x}"))
        })?;
        if next_leader == Some(ip) && ip != leader {
            if let Some(src) = pending.take() {
                if is_pure(src) {
                    return Err(LiftError(format!(
                        "vm-export {name}: unfused flags producer at block end {ip:#x} — the \
                         producer must be immediately followed by the b.cond that reads it",
                    )));
                }
            }
            return Ok(Ir64Block {
                stmts,
                term: Term64::Jmp { target: index_of(ip)? },
            });
        }
        match inst {
            Inst64::Cbz { sf, nz, rt, off } => {
                if pending.is_some() {
                    return Err(LiftError(format!(
                        "vm-export {name}: cbz consumes no flags but a producer is pending at \
                         {ip:#x} — fusion requires strict adjacency",
                    )));
                }
                if let Gpr::R(18) = rt {
                    return Err(x18_rejected(name, ip));
                }
                let w = if *sf { Width64::X } else { Width64::W };
                let pred = if *nz { CmpOp::Ne } else { CmpOp::Eq };
                let target = ip.wrapping_add(*off as u64);
                return Ok(Ir64Block {
                    stmts,
                    term: Term64::BrCmp {
                        pred,
                        w,
                        lhs: src_of(*rt),
                        rhs: Src64::Imm(0),
                        then_bb: index_of(target)?,
                        else_bb: index_of(ip + 4)?,
                    },
                });
            }
            Inst64::Tbz { nz, rt, bit, off } => {
                if pending.is_some() {
                    return Err(LiftError(format!(
                        "vm-export {name}: tbz consumes no flags but a producer is pending at \
                         {ip:#x} — fusion requires strict adjacency",
                    )));
                }
                if let Gpr::R(18) = rt {
                    return Err(x18_rejected(name, ip));
                }
                let t = scratch
                    .ok_or_else(|| no_scratch(name, ip, "tbz/tbnz bit test"))?;
                stmts.push(Stmt64::Bin {
                    op: BinOp::And,
                    w: Width64::X,
                    dst: t,
                    lhs: src_of(*rt),
                    rhs: Src64::Imm(1u64 << *bit),
                });
                let pred = if *nz { CmpOp::Ne } else { CmpOp::Eq };
                let target = ip.wrapping_add(*off as u64);
                return Ok(Ir64Block {
                    stmts,
                    term: Term64::BrCmp {
                        pred,
                        w: Width64::X,
                        lhs: Src64::Reg(t),
                        rhs: Src64::Imm(0),
                        then_bb: index_of(target)?,
                        else_bb: index_of(ip + 4)?,
                    },
                });
            }
            _ => {}
        }
        match classify64(inst, ip, name, scratch)? {
            Step64::Skip => pending = None,
            Step64::Seq(s) => {
                if let Some(src) = pending.take() {
                    if is_pure(src) {
                        return Err(LiftError(format!(
                            "vm-export {name}: unfused flags at {ip:#x} — a cmp/test/cm \
                             producer must be immediately followed by the conditional branch \
                             that reads it",
                        )));
                    }
                    // adds/subs/ands with a value destination: the dead flags
                    // simply die (x86-lifter parity: value stmts may fuse but
                    // never require it).
                }
                stmts.extend(s);
            }
            Step64::Producer { stmts: s, src } => {
                if let Some(old) = pending.take() {
                    if is_pure(old) {
                        return Err(LiftError(format!(
                            "vm-export {name}: stacked flags producers at {ip:#x}",
                        )));
                    }
                }
                stmts.extend(s);
                pending = Some(src);
            }
            Step64::Ret => {
                if let Some(src) = pending.take() {
                    if is_pure(src) {
                        return Err(LiftError(format!(
                            "vm-export {name}: unfused flags producer before ret at {ip:#x}",
                        )));
                    }
                }
                return Ok(Ir64Block {
                    stmts,
                    term: Term64::Ret,
                });
            }
            Step64::Jmp(t) => {
                if let Some(src) = pending.take() {
                    if is_pure(src) {
                        return Err(LiftError(format!(
                            "vm-export {name}: unfused flags producer before jmp at {ip:#x}",
                        )));
                    }
                }
                return Ok(Ir64Block {
                    stmts,
                    term: Term64::Jmp { target: index_of(t)? },
                });
            }
            Step64::Jcc { cond, target, fallthrough, ip } => {
                let (pred, w, lhs, rhs, extra) = fuse_bcond(pending.take(), cond, scratch)
                    .map_err(|why| {
                        LiftError(format!(
                            "vm-export {name}: {why} (b.{cname} at {ip:#x})",
                            cname = cond_name(cond)
                        ))
                    })?;
                if let Some(e) = extra {
                    stmts.push(e);
                }
                let _ = fallthrough;
                return Ok(Ir64Block {
                    stmts,
                    term: Term64::BrCmp {
                        pred,
                        w,
                        lhs,
                        rhs,
                        then_bb: index_of(target)?,
                        else_bb: index_of(ip + 4)?,
                    },
                });
            }
        }
        ip += 4;
    }
}

/// The §6.3 producer×predicate matrix. Returns (pred, width, lhs, rhs,
/// optional pre-branch statement for the register-form cmn materialization).
fn fuse_bcond(
    pending: Option<FlagSrc>,
    cond: u8,
    scratch: Option<u8>,
) -> Result<(CmpOp, Width64, Src64, Src64, Option<Stmt64>), String> {
    let pred = cond_pred(cond).ok_or_else(|| {
        format!(
            "b.{} has no comparison predicate in the first batch",
            cond_name(cond)
        )
    })?;
    let Some(src) = pending else {
        return Err(
            "conditional branch without an adjacent flags producer; only cmp/tst/cmn (and \
             nothing in between) can pair with b.cond"
                .into(),
        );
    };
    match src {
        FlagSrc::Subs { lhs, rhs, w, .. } => Ok((pred, w, lhs, rhs, None)),
        FlagSrc::CmnImm { lhs, neg_imm, w, .. } => Ok((pred, w, lhs, Src64::Imm(neg_imm), None)),
        FlagSrc::CmnReg { lhs, rhs, w, scratch, .. } => match pred {
            CmpOp::Eq | CmpOp::Ne => {
                let extra = Stmt64::Bin {
                    op: BinOp::Sub,
                    w,
                    dst: scratch,
                    lhs: Src64::Imm(0),
                    rhs,
                };
                Ok((pred, w, lhs, Src64::Reg(scratch), Some(extra)))
            }
            _ => Err(format!(
                "{p:?} after a register-form cmn/adds is not provably exact (C corner at \
                 rhs=0, V corner at rhs=INT_MIN) — only eq/ne lift; stage-2 may model exact \
                 carry/overflow",
                p = pred
            )),
        },
        FlagSrc::Ands { mat, w, .. } => match pred {
            CmpOp::Eq | CmpOp::Ne | CmpOp::SGe | CmpOp::SLt | CmpOp::SGt | CmpOp::SLe => {
                Ok((pred, w, Src64::Reg(mat), Src64::Imm(0), None))
            }
            _ => Err(format!(
                "{p:?} after tst/ands is not exact (hardware C=0 while compare(·,0) says \
                 C=1) — hs/lo/hi/ls stay native",
                p = pred
            )),
        },
    }
    .map(|(p, w, l, r, e)| {
        let _ = scratch;
        (p, w, l, r, e)
    })
}

fn is_pure(src: FlagSrc) -> bool {
    match src {
        FlagSrc::Subs { pure, .. }
        | FlagSrc::CmnImm { pure, .. }
        | FlagSrc::CmnReg { pure, .. }
        | FlagSrc::Ands { pure, .. } => pure,
    }
}

fn cond_pred(cond: u8) -> Option<CmpOp> {
    Some(match cond {
        0 => CmpOp::Eq,
        1 => CmpOp::Ne,
        2 => CmpOp::UGe, // hs
        3 => CmpOp::ULt, // lo
        8 => CmpOp::UGt, // hi
        9 => CmpOp::ULe, // ls
        10 => CmpOp::SGe, // ge
        11 => CmpOp::SLt, // lt
        12 => CmpOp::SGt, // gt
        13 => CmpOp::SLe, // le
        _ => return None,
    })
}

#[cfg(test)]
mod tests;
