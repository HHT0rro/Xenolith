//! CFG lift of a selected export into pack-internal IR.
//!
//! Fail-closed: mem / call / rip-rel / SEH / unfused flags / spill are pack
//! errors with the iced-x86 mnemonic. IR is never written to the image.

use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Instruction, Mnemonic, OpKind, Register,
};
use xenolith_formats::Pe64;
use xenolith_vm::ir::{
    Addr, BinOp, CmpOp, IrBlock, IrModule, Src, Stmt, Term, VREG_RCX, VREG_RSP,
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
pub struct LiftedExport {
    pub name: String,
    pub rva: u32,
    pub native_len: usize,
    pub ir: IrModule,
}

pub fn lift_function(
    pe: &Pe64,
    image: &[u8],
    name: &str,
    rva: u32,
    len: Option<u32>,
) -> Result<LiftedExport, LiftError> {
    if forbidden_vm_name(name) {
        return Err(LiftError(format!(
            "vm-export {name}: CRT/DllMain/JNI stay native"
        )));
    }
    let off = pe
        .file_offset_of(rva)
        .map_err(|_| LiftError(format!("vm-export {name}: bad rva {rva:#x}")))?;
    let cap = len
        .map(|n| n as usize)
        .unwrap_or(MAX_LIFT_BYTES)
        .min(image.len().saturating_sub(off));
    if cap == 0 {
        return Err(LiftError(format!("vm-export {name}: empty at {rva:#x}")));
    }
    let (ir, native_len) = lift_code(&image[off..off + cap], rva as u64, name)?;
    if let Some(want) = len {
        if native_len as u32 > want {
            return Err(LiftError(format!(
                "lift {name}: decoded {native_len} bytes past selected length {want}"
            )));
        }
    }
    Ok(LiftedExport {
        name: name.to_string(),
        rva,
        native_len,
        ir,
    })
}

pub fn lift_export(
    pe: &Pe64,
    image: &[u8],
    name: &str,
    rva: u32,
) -> Result<LiftedExport, LiftError> {
    if forbidden_vm_name(name) {
        return Err(LiftError(format!(
            "vm-export {name}: CRT/DllMain/JNI stay native"
        )));
    }
    lift_function(pe, image, name, rva, None)
}

pub fn forbidden_vm_name(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n == "dllmain"
        || n.starts_with("dllmain@")
        || n.contains("crt")
        || n.starts_with('_')
        // JVM ABI and the Qp bridge surface must stay native: the JVM calls
        // these by exact name at load time, never through a thunk.
        || n == "jni_onload"
        || n == "jni_onunload"
        || n.starts_with("java_")
        || n.starts_with("qp_r1_")
}

pub fn lift_code(bytes: &[u8], start_ip: u64, name: &str) -> Result<(IrModule, usize), LiftError> {
    let decoded = decode_reachable(bytes, start_ip, name)?;
    if decoded.is_empty() {
        return Err(LiftError(format!("vm-export {name}: no instructions")));
    }
    let native_len = decoded
        .iter()
        .map(|(ip, ins)| (*ip - start_ip) as usize + ins.len())
        .max()
        .unwrap_or(0);
    let mut leaders = std::collections::BTreeSet::new();
    leaders.insert(start_ip);
    for (ip, ins) in &decoded {
        match ins.flow_control() {
            FlowControl::UnconditionalBranch => {
                leaders.insert(ins.near_branch_target());
            }
            FlowControl::ConditionalBranch => {
                leaders.insert(ins.near_branch_target());
                leaders.insert(*ip + ins.len() as u64);
            }
            FlowControl::Return => {}
            FlowControl::Next => {}
            other => {
                return Err(LiftError(format!(
                    "vm-export {name}: unsupported flow {other:?} at {ip:#x}"
                )));
            }
        }
    }
    let leader_list: Vec<u64> = leaders.into_iter().collect();
    let index_of = |ip: u64| -> Result<usize, LiftError> {
        leader_list
            .iter()
            .position(|l| *l == ip)
            .ok_or_else(|| LiftError(format!("vm-export {name}: no block at {ip:#x}")))
    };

    let mut protos = Vec::with_capacity(leader_list.len());
    for (bi, &leader) in leader_list.iter().enumerate() {
        let next_leader = leader_list.get(bi + 1).copied();
        protos.push(lift_block(&decoded, leader, next_leader, name, &index_of)?);
    }
    let entry = index_of(start_ip)?;
    let blocks = expand_cmovs(protos);
    Ok((IrModule { blocks, entry }, native_len))
}

fn decode_reachable(
    bytes: &[u8],
    start_ip: u64,
    name: &str,
) -> Result<std::collections::BTreeMap<u64, Instruction>, LiftError> {
    let mut decoded = std::collections::BTreeMap::new();
    let mut work = vec![start_ip];
    let end_ip = start_ip + bytes.len() as u64;
    while let Some(ip) = work.pop() {
        if decoded.contains_key(&ip) {
            continue;
        }
        if ip < start_ip || ip >= end_ip {
            return Err(LiftError(format!(
                "vm-export {name}: branch out of lift window to {ip:#x}"
            )));
        }
        let off = (ip - start_ip) as usize;
        let mut decoder = Decoder::with_ip(64, &bytes[off..], ip, DecoderOptions::NONE);
        let mut instr = Instruction::default();
        decoder.decode_out(&mut instr);
        if instr.is_invalid() {
            return Err(LiftError(format!(
                "vm-export {name}: invalid instruction at {ip:#x}"
            )));
        }
        if (ip - start_ip) as usize + instr.len() > MAX_LIFT_BYTES {
            return Err(LiftError(format!(
                "vm-export {name}: exceeds {MAX_LIFT_BYTES} byte lift cap"
            )));
        }
        match instr.flow_control() {
            FlowControl::Next => work.push(ip + instr.len() as u64),
            FlowControl::UnconditionalBranch => {
                if !matches!(instr.op0_kind(), OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64) {
                    return Err(unsupported(&instr));
                }
                work.push(instr.near_branch_target());
            }
            FlowControl::ConditionalBranch => {
                if !matches!(instr.op0_kind(), OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64) {
                    return Err(unsupported(&instr));
                }
                work.push(instr.near_branch_target());
                work.push(ip + instr.len() as u64);
            }
            FlowControl::Return => {}
            _ => return Err(unsupported(&instr)),
        }
        decoded.insert(ip, instr);
    }
    Ok(decoded)
}

fn lift_block(
    decoded: &std::collections::BTreeMap<u64, Instruction>,
    leader: u64,
    next_leader: Option<u64>,
    name: &str,
    index_of: &dyn Fn(u64) -> Result<usize, LiftError>,
) -> Result<ProtoBlock, LiftError> {
    let mut stmts = Vec::new();
    let mut pending_cmp: Option<(Src, Src)> = None;
    let mut ip = leader;
    loop {
        let instr = decoded.get(&ip).ok_or_else(|| {
            LiftError(format!("vm-export {name}: missing instr at {ip:#x}"))
        })?;
        if next_leader == Some(ip) && ip != leader {
            if pending_cmp.is_some() {
                return Err(LiftError(format!(
                    "vm-export {name}: unfused cmp at {ip:#x}"
                )));
            }
            return Ok(ProtoBlock {
                stmts,
                term: Term::Jmp { target: index_of(ip)? },
            });
        }
        match classify_instr(instr)? {
            LiftStep::Skip => {}
            LiftStep::Stmt(s) => {
                if pending_cmp.is_some() {
                    return Err(LiftError(format!(
                        "vm-export {name}: unfused flags at {:#x}",
                        instr.ip()
                    )));
                }
                stmts.push(CodeStmt::N(s));
            }
            LiftStep::Cmp(lhs, rhs) => {
                if pending_cmp.is_some() {
                    return Err(LiftError(format!(
                        "vm-export {name}: stacked cmp at {:#x}",
                        instr.ip()
                    )));
                }
                pending_cmp = Some((lhs, rhs));
            }
            LiftStep::Cmov { pred, dst, src } => {
                let (lhs, rhs) = pending_cmp.take().ok_or_else(|| {
                    LiftError(format!(
                        "vm-export {name}: cmov without fused cmp at {:#x}",
                        instr.ip()
                    ))
                })?;
                stmts.push(CodeStmt::Cmov {
                    pred,
                    dst,
                    src,
                    lhs,
                    rhs,
                });
            }
            LiftStep::Ret => {
                if pending_cmp.is_some() {
                    return Err(LiftError(format!(
                        "vm-export {name}: unfused cmp before ret"
                    )));
                }
                return Ok(ProtoBlock {
                    stmts,
                    term: Term::Ret,
                });
            }
            LiftStep::Jmp(t) => {
                if pending_cmp.is_some() {
                    return Err(LiftError(format!(
                        "vm-export {name}: unfused cmp before jmp"
                    )));
                }
                return Ok(ProtoBlock {
                    stmts,
                    term: Term::Jmp { target: index_of(t)? },
                });
            }
            LiftStep::Jcc { pred, target, fallthrough } => {
                let (lhs, rhs) = pending_cmp.take().ok_or_else(|| {
                    LiftError(format!(
                        "vm-export {name}: jcc without fused cmp at {:#x}",
                        instr.ip()
                    ))
                })?;
                return Ok(ProtoBlock {
                    stmts,
                    term: Term::BrCmp {
                        pred,
                        lhs,
                        rhs,
                        then_bb: index_of(target)?,
                        else_bb: index_of(fallthrough)?,
                    },
                });
            }
        }
        match instr.flow_control() {
            FlowControl::Next => ip += instr.len() as u64,
            _ => {
                return Err(LiftError(format!(
                    "vm-export {name}: block did not terminate at {:#x}",
                    instr.ip()
                )));
            }
        }
        if next_leader == Some(ip) {
            if pending_cmp.is_some() {
                return Err(LiftError(format!(
                    "vm-export {name}: unfused cmp at block end {ip:#x}"
                )));
            }
            return Ok(ProtoBlock {
                stmts,
                term: Term::Jmp { target: index_of(ip)? },
            });
        }
    }
}

fn expand_cmovs(mut protos: Vec<ProtoBlock>) -> Vec<IrBlock> {
    loop {
        let hit = protos.iter().enumerate().find_map(|(bi, b)| {
            b.stmts.iter().position(|s| matches!(s, CodeStmt::Cmov { .. })).map(|si| (bi, si))
        });
        let Some((bi, si)) = hit else { break };
        let mut block = std::mem::replace(
            &mut protos[bi],
            ProtoBlock {
                stmts: Vec::new(),
                term: Term::Ret,
            },
        );
        let CodeStmt::Cmov {
            pred,
            dst,
            src,
            lhs,
            rhs,
        } = block.stmts[si].clone()
        else {
            unreachable!()
        };
        let prefix: Vec<CodeStmt> = block.stmts.drain(..si).collect();
        block.stmts.remove(0); // the cmov
        let suffix = block.stmts;
        let term = block.term;
        let then_i = protos.len();
        let else_i = then_i + 1;
        let join_i = then_i + 2;
        protos[bi] = ProtoBlock {
            stmts: prefix,
            term: Term::BrCmp {
                pred,
                lhs,
                rhs,
                then_bb: then_i,
                else_bb: else_i,
            },
        };
        protos.push(ProtoBlock {
            stmts: vec![CodeStmt::N(Stmt::Mov { dst, src })],
            term: Term::Jmp { target: join_i },
        });
        protos.push(ProtoBlock {
            stmts: vec![],
            term: Term::Jmp { target: join_i },
        });
        protos.push(ProtoBlock {
            stmts: suffix,
            term,
        });
    }
    protos
        .into_iter()
        .map(|b| IrBlock {
            stmts: b
                .stmts
                .into_iter()
                .map(|s| match s {
                    CodeStmt::N(st) => st,
                    CodeStmt::Cmov { .. } => unreachable!(),
                })
                .collect(),
            term: b.term,
        })
        .collect()
}

enum LiftStep {
    Skip,
    Stmt(Stmt),
    Cmp(Src, Src),
    Ret,
    Jmp(u64),
    Jcc {
        pred: CmpOp,
        target: u64,
        fallthrough: u64,
    },
    Cmov {
        pred: CmpOp,
        dst: u8,
        src: Src,
    },
}

#[derive(Clone)]
enum CodeStmt {
    N(Stmt),
    Cmov {
        pred: CmpOp,
        dst: u8,
        src: Src,
        lhs: Src,
        rhs: Src,
    },
}

struct ProtoBlock {
    stmts: Vec<CodeStmt>,
    term: Term,
}

fn classify_instr(instr: &Instruction) -> Result<LiftStep, LiftError> {
    match instr.mnemonic() {
        Mnemonic::Ret => {
            if instr.op_count() != 0 {
                return Err(unsupported(instr));
            }
            Ok(LiftStep::Ret)
        }
        Mnemonic::Nop | Mnemonic::Endbr64 => Ok(LiftStep::Skip),
        Mnemonic::Push | Mnemonic::Pop => {
            if instr.op0_kind() == OpKind::Register && instr.op0_register().is_gpr() {
                Ok(LiftStep::Skip)
            } else {
                Err(unsupported(instr))
            }
        }
        Mnemonic::Sub | Mnemonic::Add if is_rsp_imm(instr) => Ok(LiftStep::Skip),
        Mnemonic::Lea => lift_lea(instr),
        Mnemonic::Mov => {
            if is_frame_mov(instr) {
                Ok(LiftStep::Skip)
            } else {
                lift_mov(instr)
            }
        }
        Mnemonic::Add => lift_bin(instr, BinOp::Add),
        Mnemonic::Sub => lift_bin(instr, BinOp::Sub),
        Mnemonic::Xor => lift_bin(instr, BinOp::Xor),
        Mnemonic::And => lift_bin(instr, BinOp::And),
        Mnemonic::Or => lift_bin(instr, BinOp::Or),
        Mnemonic::Imul => lift_imul(instr),
        // sal shares Shl's opcode/mnemonic in iced.
        Mnemonic::Shl => lift_shift(instr, BinOp::Shl),
        Mnemonic::Shr => lift_shift(instr, BinOp::Shr),
        Mnemonic::Sar => lift_shift(instr, BinOp::Sar),
        Mnemonic::Inc => lift_incdec(instr, BinOp::Add),
        Mnemonic::Dec => lift_incdec(instr, BinOp::Sub),
        Mnemonic::Neg => lift_neg(instr),
        Mnemonic::Not => lift_not(instr),
        Mnemonic::Cmp => lift_cmp(instr),
        Mnemonic::Test => lift_test(instr),
        Mnemonic::Jmp => {
            if matches!(instr.op0_kind(), OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64) {
                Ok(LiftStep::Jmp(instr.near_branch_target()))
            } else {
                Err(unsupported(instr))
            }
        }
        m if jcc_pred(m).is_some() => {
            if !matches!(instr.op0_kind(), OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64) {
                return Err(unsupported(instr));
            }
            Ok(LiftStep::Jcc {
                pred: jcc_pred(m).unwrap(),
                target: instr.near_branch_target(),
                fallthrough: instr.ip() + instr.len() as u64,
            })
        }
        m if cmov_pred(m).is_some() => {
            if instr.op_count() != 2 || instr.op0_kind() != OpKind::Register {
                return Err(unsupported(instr));
            }
            let dst = gpr_index(instr.op0_register(), instr)?;
            let src = match instr.op1_kind() {
                OpKind::Register => Src::Reg(gpr_index(instr.op1_register(), instr)?),
                _ => return Err(unsupported(instr)),
            };
            Ok(LiftStep::Cmov {
                pred: cmov_pred(m).unwrap(),
                dst,
                src,
            })
        }
        _ => Err(unsupported(instr)),
    }
}

fn cmov_pred(m: Mnemonic) -> Option<CmpOp> {
    Some(match m {
        Mnemonic::Cmove => CmpOp::Eq,
        Mnemonic::Cmovne => CmpOp::Ne,
        Mnemonic::Cmovb => CmpOp::ULt,
        Mnemonic::Cmovbe => CmpOp::ULe,
        Mnemonic::Cmova => CmpOp::UGt,
        Mnemonic::Cmovae => CmpOp::UGe,
        Mnemonic::Cmovl => CmpOp::SLt,
        Mnemonic::Cmovle => CmpOp::SLe,
        Mnemonic::Cmovg => CmpOp::SGt,
        Mnemonic::Cmovge => CmpOp::SGe,
        _ => return None,
    })
}

fn jcc_pred(m: Mnemonic) -> Option<CmpOp> {
    Some(match m {
        Mnemonic::Je => CmpOp::Eq,
        Mnemonic::Jne => CmpOp::Ne,
        Mnemonic::Jb => CmpOp::ULt,
        Mnemonic::Jbe => CmpOp::ULe,
        Mnemonic::Ja => CmpOp::UGt,
        Mnemonic::Jae => CmpOp::UGe,
        Mnemonic::Jl => CmpOp::SLt,
        Mnemonic::Jle => CmpOp::SLe,
        Mnemonic::Jg => CmpOp::SGt,
        Mnemonic::Jge => CmpOp::SGe,
        _ => return None,
    })
}

fn is_rsp_imm(instr: &Instruction) -> bool {
    instr.op_count() == 2
        && instr.op0_kind() == OpKind::Register
        && instr.op0_register() == Register::RSP
        && is_imm(instr.op1_kind())
}

fn is_imm(kind: OpKind) -> bool {
    matches!(
        kind,
        OpKind::Immediate8
            | OpKind::Immediate8to32
            | OpKind::Immediate8to64
            | OpKind::Immediate32
            | OpKind::Immediate32to64
            | OpKind::Immediate64
    )
}

fn is_frame_mov(instr: &Instruction) -> bool {
    if instr.op_count() != 2
        || instr.op0_kind() != OpKind::Register
        || instr.op1_kind() != OpKind::Register
    {
        return false;
    }
    let a = instr.op0_register();
    let b = instr.op1_register();
    a.is_gpr64()
        && b.is_gpr64()
        && (a == Register::RBP || a == Register::RSP || b == Register::RBP || b == Register::RSP)
}

fn lift_lea(instr: &Instruction) -> Result<LiftStep, LiftError> {
    if instr.op_count() != 2
        || instr.op0_kind() != OpKind::Register
        || instr.op1_kind() != OpKind::Memory
    {
        return Err(unsupported(instr));
    }
    if instr.is_ip_rel_memory_operand() || instr.segment_prefix() != Register::None {
        return Err(unsupported(instr));
    }
    let dst = gpr_index(instr.op0_register(), instr)?;
    let a = gpr_index(instr.memory_base(), instr)?;
    let idx = instr.memory_index();
    let disp = instr.memory_displacement64() as u32;
    if idx == Register::None {
        if disp == 0 {
            return Ok(LiftStep::Stmt(Stmt::Mov {
                dst,
                src: Src::Reg(a),
            }));
        }
        return Ok(LiftStep::Stmt(Stmt::Bin {
            op: BinOp::Add,
            dst,
            lhs: Src::Reg(a),
            rhs: Src::Imm(disp),
        }));
    }
    if instr.memory_index_scale() != 1 || disp != 0 {
        return Err(unsupported(instr));
    }
    let b = gpr_index(idx, instr)?;
    Ok(LiftStep::Stmt(Stmt::Bin {
        op: BinOp::Add,
        dst,
        lhs: Src::Reg(a),
        rhs: Src::Reg(b),
    }))
}

fn mem_addr(instr: &Instruction) -> Result<Addr, LiftError> {
    if instr.is_ip_rel_memory_operand() || instr.segment_prefix() != Register::None {
        return Err(unsupported(instr));
    }
    if instr.memory_index() != Register::None {
        return Err(unsupported(instr));
    }
    let base = instr.memory_base();
    if !base.is_gpr() {
        return Err(unsupported(instr));
    }
    let base_i = gpr_index_allow_rsp(base, instr, true)?;
    Ok(Addr::BaseDisp {
        base: base_i,
        disp: instr.memory_displacement64() as i32,
    })
}

fn op_width(instr: &Instruction) -> Result<u8, LiftError> {
    match instr.memory_size().size() {
        1 | 2 | 4 | 8 => Ok(instr.memory_size().size() as u8),
        _ => {
            if instr.op0_kind() == OpKind::Register {
                match instr.op0_register().size() {
                    1 | 2 | 4 | 8 => Ok(instr.op0_register().size() as u8),
                    _ => Err(unsupported(instr)),
                }
            } else {
                Err(unsupported(instr))
            }
        }
    }
}

fn lift_mov(instr: &Instruction) -> Result<LiftStep, LiftError> {
    if instr.op_count() != 2 {
        return Err(unsupported(instr));
    }
    match (instr.op0_kind(), instr.op1_kind()) {
        (OpKind::Register, OpKind::Register) => {
            let dst = gpr_index(instr.op0_register(), instr)?;
            let src = gpr_index(instr.op1_register(), instr)?;
            Ok(LiftStep::Stmt(Stmt::Mov {
                dst,
                src: Src::Reg(src),
            }))
        }
        (OpKind::Register, k) if is_imm(k) => {
            let dst = gpr_index(instr.op0_register(), instr)?;
            Ok(LiftStep::Stmt(Stmt::Mov {
                dst,
                src: Src::Imm(instr.immediate(1) as u32),
            }))
        }
        (OpKind::Register, OpKind::Memory) => {
            let dst = gpr_index(instr.op0_register(), instr)?;
            let addr = mem_addr(instr)?;
            let width = op_width(instr)?;
            Ok(LiftStep::Stmt(Stmt::Load { dst, addr, width }))
        }
        (OpKind::Memory, OpKind::Register) => {
            let addr = mem_addr(instr)?;
            let src = Src::Reg(gpr_index(instr.op1_register(), instr)?);
            let width = op_width(instr)?;
            Ok(LiftStep::Stmt(Stmt::Store { addr, src, width }))
        }
        (OpKind::Memory, k) if is_imm(k) => {
            let addr = mem_addr(instr)?;
            let width = op_width(instr)?;
            Ok(LiftStep::Stmt(Stmt::Store {
                addr,
                src: Src::Imm(instr.immediate(1) as u32),
                width,
            }))
        }
        _ => Err(unsupported(instr)),
    }
}

fn lift_bin(instr: &Instruction, op: BinOp) -> Result<LiftStep, LiftError> {
    if instr.op_count() != 2 || instr.op0_kind() != OpKind::Register {
        return Err(unsupported(instr));
    }
    let dst = gpr_index(instr.op0_register(), instr)?;
    let lhs = Src::Reg(dst);
    let rhs = match instr.op1_kind() {
        OpKind::Register => Src::Reg(gpr_index(instr.op1_register(), instr)?),
        k if is_imm(k) => Src::Imm(instr.immediate(1) as u32),
        _ => return Err(unsupported(instr)),
    };
    Ok(LiftStep::Stmt(Stmt::Bin { op, dst, lhs, rhs }))
}

/// `imul` register forms with a 32-bit destination. The 1-operand widening
/// form (edx:eax) and any 64-bit operand stay fail-closed — there is no
/// pack-time equivalence check, so a silent width mismatch is unacceptable.
fn lift_imul(instr: &Instruction) -> Result<LiftStep, LiftError> {
    if instr.op0_kind() != OpKind::Register {
        return Err(unsupported(instr));
    }
    let dst = reg32_index(instr.op0_register(), instr)?;
    match instr.op_count() {
        2 => {
            // imul r32, r/m32  →  dst = dst * src
            let rhs = match instr.op1_kind() {
                OpKind::Register => Src::Reg(reg32_index(instr.op1_register(), instr)?),
                _ => return Err(unsupported(instr)),
            };
            Ok(LiftStep::Stmt(Stmt::Bin { op: BinOp::Mul, dst, lhs: Src::Reg(dst), rhs }))
        }
        3 => {
            // imul r32, r/m32, imm  →  dst = src * imm
            let src = match instr.op1_kind() {
                OpKind::Register => Src::Reg(reg32_index(instr.op1_register(), instr)?),
                _ => return Err(unsupported(instr)),
            };
            if !is_imm(instr.op2_kind()) {
                return Err(unsupported(instr));
            }
            let rhs = Src::Imm(instr.immediate(2) as u32);
            Ok(LiftStep::Stmt(Stmt::Bin { op: BinOp::Mul, dst, lhs: src, rhs }))
        }
        _ => Err(unsupported(instr)),
    }
}

/// `shl`/`shr`/`sar` with a 32-bit destination. Only immediate counts and the
/// shift-by-CL form are representable; the count register maps to guest RCX.
fn lift_shift(instr: &Instruction, op: BinOp) -> Result<LiftStep, LiftError> {
    if instr.op0_kind() != OpKind::Register {
        return Err(unsupported(instr));
    }
    let dst = reg32_index(instr.op0_register(), instr)?;
    let rhs = match instr.op_count() {
        // `shl r/m, 1` encodes the count implicitly in the opcode.
        1 => Src::Imm(1),
        2 => match instr.op1_kind() {
            k if is_imm(k) => Src::Imm(instr.immediate(1) as u32),
            OpKind::Register => {
                if instr.op1_register() != Register::CL {
                    return Err(unsupported(instr));
                }
                // The count is CL, i.e. the low byte of guest (E)CX.
                Src::Reg(VREG_RCX as u8)
            }
            _ => return Err(unsupported(instr)),
        },
        _ => return Err(unsupported(instr)),
    };
    Ok(LiftStep::Stmt(Stmt::Bin { op, dst, lhs: Src::Reg(dst), rhs }))
}

/// `inc`/`dec` lower to `+1` / `-1` on a 32-bit register.
fn lift_incdec(instr: &Instruction, op: BinOp) -> Result<LiftStep, LiftError> {
    if instr.op_count() != 1 || instr.op0_kind() != OpKind::Register {
        return Err(unsupported(instr));
    }
    let dst = reg32_index(instr.op0_register(), instr)?;
    Ok(LiftStep::Stmt(Stmt::Bin { op, dst, lhs: Src::Reg(dst), rhs: Src::Imm(1) }))
}

/// `neg dst` == `0 - dst` on a 32-bit register.
fn lift_neg(instr: &Instruction) -> Result<LiftStep, LiftError> {
    if instr.op_count() != 1 || instr.op0_kind() != OpKind::Register {
        return Err(unsupported(instr));
    }
    let dst = reg32_index(instr.op0_register(), instr)?;
    Ok(LiftStep::Stmt(Stmt::Bin {
        op: BinOp::Sub,
        dst,
        lhs: Src::Imm(0),
        rhs: Src::Reg(dst),
    }))
}

/// `not dst` == `dst ^ 0xFFFF_FFFF` on a 32-bit register.
fn lift_not(instr: &Instruction) -> Result<LiftStep, LiftError> {
    if instr.op_count() != 1 || instr.op0_kind() != OpKind::Register {
        return Err(unsupported(instr));
    }
    let dst = reg32_index(instr.op0_register(), instr)?;
    Ok(LiftStep::Stmt(Stmt::Bin {
        op: BinOp::Xor,
        dst,
        lhs: Src::Reg(dst),
        rhs: Src::Imm(0xFFFF_FFFF),
    }))
}

fn lift_cmp(instr: &Instruction) -> Result<LiftStep, LiftError> {
    if instr.op_count() != 2 || instr.op0_kind() != OpKind::Register {
        return Err(unsupported(instr));
    }
    let lhs = Src::Reg(gpr_index(instr.op0_register(), instr)?);
    let rhs = match instr.op1_kind() {
        OpKind::Register => Src::Reg(gpr_index(instr.op1_register(), instr)?),
        k if is_imm(k) => Src::Imm(instr.immediate(1) as u32),
        _ => return Err(unsupported(instr)),
    };
    Ok(LiftStep::Cmp(lhs, rhs))
}

fn lift_test(instr: &Instruction) -> Result<LiftStep, LiftError> {
    if instr.op_count() != 2
        || instr.op0_kind() != OpKind::Register
        || instr.op1_kind() != OpKind::Register
    {
        return Err(unsupported(instr));
    }
    let a = gpr_index(instr.op0_register(), instr)?;
    let b = gpr_index(instr.op1_register(), instr)?;
    if a != b {
        return Err(unsupported(instr));
    }
    Ok(LiftStep::Cmp(Src::Reg(a), Src::Imm(0)))
}

fn gpr_index(reg: Register, instr: &Instruction) -> Result<u8, LiftError> {
    gpr_index_allow_rsp(reg, instr, false)
}

/// Like `gpr_index`, but only accepts 32-bit GPRs (eax..r15d). Used by the
/// newer lifters (imul/shifts/neg/not/inc/dec) whose superop codegen is fixed
/// to 32-bit width; any other operand size stays fail-closed.
fn reg32_index(reg: Register, instr: &Instruction) -> Result<u8, LiftError> {
    if reg.size() != 4 {
        return Err(unsupported(instr));
    }
    gpr_index(reg, instr)
}

fn gpr_index_allow_rsp(reg: Register, instr: &Instruction, allow_rsp: bool) -> Result<u8, LiftError> {
    if !reg.is_gpr() {
        return Err(unsupported(instr));
    }
    let n = reg.number();
    if n >= 16 || (!allow_rsp && n == VREG_RSP as usize) {
        return Err(unsupported(instr));
    }
    Ok(n as u8)
}

fn unsupported(instr: &Instruction) -> LiftError {
    LiftError(format!(
        "vm-export unsupported {:?} at {:#x}",
        instr.mnemonic(),
        instr.ip()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use xenolith_vm::ir::{eval_ir, license_toy_oracle, Stmt};

    #[test]
    fn lifts_lea_eax_rcx_rdx_ret() {
        let bytes = [0x8D, 0x04, 0x11, 0xC3];
        let (ir, len) = lift_code(&bytes, 0x1000, "hello_add").unwrap();
        assert_eq!(len, 4);
        assert_eq!(eval_ir(&ir, 3, 4).unwrap(), 7);
    }

    #[test]
    fn lifts_license_toy_hand_bytes() {
        // mov eax,ecx; xor eax,edx; add eax,K; cmp eax,IMM; jbe +3; sub eax,edx; ret; add eax,edx; ret
        let bytes = [
            0x89, 0xC8, 0x31, 0xD0, 0x05, 0xB9, 0x79, 0x37, 0x9E, 0x3D, 0x00, 0x00, 0x01, 0x00,
            0x76, 0x03, 0x29, 0xD0, 0xC3, 0x01, 0xD0, 0xC3,
        ];
        let (ir, _) = lift_code(&bytes, 0x1000, "check_license").unwrap();
        assert!(ir.blocks.len() >= 2);
        for (x, y) in [
            (0u32, 0u32),
            (3, 4),
            (0x0001_0001, 0),
            (0x0002_0000, 0x10),
            (1, 1),
            (0xFFFF_FFFF, 0),
            (0x1234, 0x5678),
            (0x8000_0000, 1),
        ] {
            assert_eq!(
                eval_ir(&ir, x, y).unwrap(),
                license_toy_oracle(x, y),
                "{x:#x},{y:#x}"
            );
        }
    }

    #[test]
    fn call_fails_closed() {
        let bytes = [0xFF, 0xD0];
        let err = lift_code(&bytes, 0x1000, "x").unwrap_err();
        assert!(err.0.contains("unsupported"), "{}", err.0);
    }

    #[test]
    fn rip_rel_fails_closed() {
        let bytes = [0x48, 0x8D, 0x05, 0x00, 0x00, 0x00, 0x00, 0xC3];
        let err = lift_code(&bytes, 0x1000, "x").unwrap_err();
        assert!(err.0.contains("unsupported"), "{}", err.0);
    }

    #[test]
    fn lifts_load_store_base_disp() {
        // mov eax, [rcx]; mov [rdx], eax; ret
        let bytes = [0x8B, 0x01, 0x89, 0x02, 0xC3];
        let (ir, len) = lift_code(&bytes, 0x1000, "ldst").unwrap();
        assert_eq!(len, 5);
        assert!(ir.blocks[0].stmts.iter().any(|s| matches!(s, Stmt::Load { .. })));
        assert!(ir.blocks[0].stmts.iter().any(|s| matches!(s, Stmt::Store { .. })));
        let mut st = xenolith_vm::MachineState::from_win64_u32(0x2000, 0x3000);
        st.mem.write_u64(0x2000, 4, 0x11).unwrap();
        st.mem.write_u64(0x3000, 4, 0).unwrap();
        let v = xenolith_vm::eval_machine(&ir, &mut st).unwrap();
        assert_eq!(v, 0x11);
        assert_eq!(st.mem.read_u64(0x3000, 4).unwrap(), 0x11);
    }

    #[test]
    fn unfused_jcc_fails_closed() {
        // je +0; ret  without cmp
        let bytes = [0x74, 0x00, 0xC3];
        let err = lift_code(&bytes, 0x1000, "x").unwrap_err();
        assert!(err.0.contains("fused") || err.0.contains("unsupported"), "{}", err.0);
    }

    #[test]
    #[cfg(windows)]
    fn lifts_real_license_toy_export() {
        let dll = std::fs::read("target/release/license_toy.dll")
            .or_else(|_| std::fs::read("../../target/release/license_toy.dll"));
        let Ok(dll) = dll else { return };
        let pe = Pe64::parse(&dll).expect("license_toy pe");
        let exp = pe
            .exports(&dll)
            .unwrap()
            .into_iter()
            .find(|e| e.name == "check_license")
            .expect("check_license");
        let (ir, _) = {
            let lifted = lift_export(&pe, &dll, &exp.name, exp.rva).unwrap_or_else(|e| panic!("{e}"));
            (lifted.ir, lifted.native_len)
        };
        for (x, y) in [
            (0u32, 0u32),
            (3, 4),
            (0x0001_0001, 0),
            (0x0002_0000, 0x10),
            (1, 1),
            (0xFFFF_FFFF, 0),
            (0x1234, 0x5678),
            (0x8000_0000, 1),
        ] {
            assert_eq!(
                eval_ir(&ir, x, y).unwrap(),
                license_toy_oracle(x, y),
                "{x:#x},{y:#x}"
            );
        }
    }

    // ------------------------------------------------------------------
    // Instruction-breadth lifters (imul / shifts / neg / not / inc / dec).
    // Assemble a tiny straight-line body, lift, and check the software
    // oracle (eval_ir, B32) against a Rust reference. Host-independent.
    // ------------------------------------------------------------------
    fn asm_bytes(
        f: impl FnOnce(&mut iced_x86::code_asm::CodeAssembler) -> Result<(), iced_x86::IcedError>,
    ) -> Vec<u8> {
        let mut a = iced_x86::code_asm::CodeAssembler::new(64).unwrap();
        f(&mut a).unwrap();
        a.assemble(0x1000).unwrap()
    }

    const INT_INPUTS: [(u32, u32); 10] = [
        (0, 0),
        (3, 4),
        (7, 7),
        (1, 31),
        (0xFFFF_FFFF, 2),
        (0x8000_0000, 2),
        (0x8000_0001, 33),
        (0x1234_5678, 5),
        (0x9E37_79B9, 0),
        (0xDEAD_BEEF, 17),
    ];

    fn check_lift(bytes: &[u8], reference: impl Fn(u32, u32) -> u32) {
        let (ir, _) = lift_code(bytes, 0x1000, "probe").unwrap();
        for &(x, y) in &INT_INPUTS {
            assert_eq!(eval_ir(&ir, x, y).unwrap(), reference(x, y), "{x:#x},{y:#x}");
        }
    }

    #[test]
    fn lifts_imul_2op() {
        use iced_x86::code_asm::*;
        let bytes = asm_bytes(|a| {
            a.mov(eax, ecx)?;
            a.imul_2(eax, edx)?;
            a.ret()
        });
        check_lift(&bytes, |x, y| x.wrapping_mul(y));
    }

    #[test]
    fn lifts_imul_3op_imm() {
        use iced_x86::code_asm::*;
        let bytes = asm_bytes(|a| {
            a.imul_3(eax, ecx, 5i32)?;
            a.ret()
        });
        check_lift(&bytes, |x, _| x.wrapping_mul(5));
    }

    #[test]
    fn lifts_shifts_imm() {
        use iced_x86::code_asm::*;
        let shl = asm_bytes(|a| {
            a.mov(eax, ecx)?;
            a.shl(eax, 4u32)?;
            a.ret()
        });
        check_lift(&shl, |x, _| x.wrapping_shl(4));
        let shr = asm_bytes(|a| {
            a.mov(eax, ecx)?;
            a.shr(eax, 4u32)?;
            a.ret()
        });
        check_lift(&shr, |x, _| x.wrapping_shr(4));
        let sar = asm_bytes(|a| {
            a.mov(eax, ecx)?;
            a.sar(eax, 4u32)?;
            a.ret()
        });
        check_lift(&sar, |x, _| ((x as i32).wrapping_shr(4)) as u32);
    }

    #[test]
    fn lifts_shift_by_cl() {
        use iced_x86::code_asm::*;
        // eax = edx << (cl & 31), cl being the low byte of guest ECX.
        let bytes = asm_bytes(|a| {
            a.mov(eax, edx)?;
            a.shl(eax, cl)?;
            a.ret()
        });
        check_lift(&bytes, |x, y| y.wrapping_shl(x & 31));
    }

    #[test]
    fn lifts_inc_dec() {
        use iced_x86::code_asm::*;
        let inc = asm_bytes(|a| {
            a.mov(eax, ecx)?;
            a.inc(eax)?;
            a.ret()
        });
        check_lift(&inc, |x, _| x.wrapping_add(1));
        let dec = asm_bytes(|a| {
            a.mov(eax, ecx)?;
            a.dec(eax)?;
            a.ret()
        });
        check_lift(&dec, |x, _| x.wrapping_sub(1));
    }

    #[test]
    fn lifts_neg_not() {
        use iced_x86::code_asm::*;
        let neg = asm_bytes(|a| {
            a.mov(eax, ecx)?;
            a.neg(eax)?;
            a.ret()
        });
        check_lift(&neg, |x, _| 0u32.wrapping_sub(x));
        let not = asm_bytes(|a| {
            a.mov(eax, ecx)?;
            a.not(eax)?;
            a.ret()
        });
        check_lift(&not, |x, _| !x);
    }

    #[test]
    fn imul_64bit_fails_closed() {
        use iced_x86::code_asm::*;
        // 64-bit multiply must not lift as a 32-bit op.
        let bytes = asm_bytes(|a| {
            a.imul_2(rax, rdx)?;
            a.ret()
        });
        assert!(lift_code(&bytes, 0x1000, "probe").is_err());
    }
}

/// (liftable_instructions, total_decoded) over a byte window — the probe
/// behind `mixed_native` classification: functions whose lift fails but that
/// contain liftable work are mixed-native candidates, not pure unsupported.
pub fn liftable_work_ratio(bytes: &[u8], start_ip: u64) -> (usize, usize) {
    let mut decoder = Decoder::with_ip(64, bytes, start_ip, DecoderOptions::NONE);
    let (mut liftable, mut total) = (0usize, 0usize);
    for ins in decoder.iter() {
        if ins.is_invalid() {
            break;
        }
        total += 1;
        match classify_instr(&ins) {
            Ok(_) => liftable += 1,
            Err(_) => {}
        }
    }
    (liftable, total)
}
