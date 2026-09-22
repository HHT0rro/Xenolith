//! CFG lift of a selected export into pack-internal IR.
//!
//! Fail-closed: mem / call / rip-rel / SEH / unfused flags / spill are pack
//! errors that name the function, the faulting instruction and its RVA, and
//! tell the user what to do next. IR is never written to the image. The IR
//! oracle and superop codegen are fixed at 32-bit operand width, so every
//! register write goes through `reg32_index` — 64/16/8-bit register operands
//! fail closed instead of silently computing wrong results.

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
    follow_thunks: bool,
) -> Result<LiftedExport, LiftError> {
    if let Some(rule) = forbidden_vm_rule(name) {
        return Err(LiftError(format!(
            "vm-export {name}: stays native ({rule}); CRT/DllMain/JNI ABI exports must \
             stay native — pick another export"
        )));
    }
    pe.file_offset_of(rva)
        .map_err(|_| LiftError(format!("vm-export {name}: bad rva {rva:#x}")))?;
    // Named-export selection may land on an incremental-link thunk (`jmp
    // rel32` at the entry, real body at the target). Lift the resolved body,
    // but keep the hook bookkeeping on the thunk itself: apply_vm_hook
    // rewrites exactly `native_len` bytes at the selected RVA — the 5-byte
    // jmp covers internal callers — while the export-table repoint routes
    // external callers into the VM. Explicit `RVA:LEN` selections skip
    // resolution: the user asked for that exact window.
    let mut lift_rva = rva as u64;
    let mut thunk_len = 0usize;
    if follow_thunks {
        if let Some(resolved) =
            follow_entry_thunk(image, name, rva as u64, |r| pe.file_offset_of(r as u32).ok())?
        {
            thunk_len = 5;
            lift_rva = resolved;
        }
    }
    let lift_u32 = u32::try_from(lift_rva).map_err(|_| {
        LiftError(format!(
            "vm-export {name}: thunk target {lift_rva:#x} exceeds a 32-bit RVA"
        ))
    })?;
    let off = pe
        .file_offset_of(lift_u32)
        .map_err(|_| LiftError(format!("vm-export {name}: bad rva {lift_u32:#x}")))?;
    // A thunk-resolved body lives outside the selected window, so the window
    // length (the thunk's own runtime range) no longer bounds the lift.
    let cap = if thunk_len > 0 { None } else { len }
        .map(|n| n as usize)
        .unwrap_or(MAX_LIFT_BYTES)
        .min(image.len().saturating_sub(off));
    if cap == 0 {
        return Err(LiftError(format!(
            "vm-export {name}: empty at {lift_u32:#x}"
        )));
    }
    let (ir, body_len) = lift_code(&image[off..off + cap], lift_rva, name)?;
    if thunk_len == 0 {
        if let Some(want) = len {
            if body_len as u32 > want {
                return Err(LiftError(format!(
                    "lift {name}: decoded {body_len} bytes past selected length {want}"
                )));
            }
        }
    }
    let native_len = if thunk_len > 0 { thunk_len } else { body_len };
    Ok(LiftedExport {
        name: name.to_string(),
        rva,
        native_len,
        ir,
    })
}

/// Max hops when resolving an incremental-link thunk chain at a selected
/// entry. Real linkers emit exactly one `jmp rel32`; the bound turns a
/// manufactured jump cycle into an error instead of a hang.
const MAX_THUNK_HOPS: usize = 4;

/// Follow `jmp rel32` entry thunks to the real function body. Returns
/// `None` when the entry is not a thunk so the normal lift (and its
/// actionable errors) applies unchanged. Only the linker's exact 5-byte
/// form qualifies: `jmp rel8` cannot be patched with a rel32 rewrite, and
/// indirect jmps point through memory the packer cannot resolve here.
fn follow_entry_thunk(
    image: &[u8],
    name: &str,
    rva: u64,
    resolve: impl Fn(u64) -> Option<usize>,
) -> Result<Option<u64>, LiftError> {
    let mut cur = rva;
    let mut followed = false;
    for _ in 0..MAX_THUNK_HOPS {
        let Some(off) = resolve(cur) else {
            return if !followed {
                Ok(None)
            } else {
                Err(LiftError(format!(
                    "vm-export {name}: entry thunk jumps to unmapped {cur:#x}"
                )))
            };
        };
        let mut dec = Decoder::with_ip(64, &image[off..], cur, DecoderOptions::NONE);
        let ins = dec.decode();
        if ins.is_invalid()
            || ins.len() != 5
            || ins.mnemonic() != Mnemonic::Jmp
            || ins.flow_control() != FlowControl::UnconditionalBranch
        {
            // Not a jmp: with no hops this entry simply is not a thunk, so
            // the normal lift (and its actionable errors) applies unchanged;
            // after a hop this instruction is the resolved body.
            return if !followed { Ok(None) } else { Ok(Some(cur)) };
        }
        let target = ins.near_branch_target();
        if target == cur {
            return Err(LiftError(format!(
                "vm-export {name}: entry thunk self-jump at {cur:#x}"
            )));
        }
        if resolve(target).is_none() {
            return if !followed {
                Ok(None)
            } else {
                Err(LiftError(format!(
                    "vm-export {name}: entry thunk chain leaves the mapped \
                     image at {cur:#x}"
                )))
            };
        }
        cur = target;
        followed = true;
    }
    Err(LiftError(format!(
        "vm-export {name}: entry thunk chain exceeds {MAX_THUNK_HOPS} jumps at {cur:#x}"
    )))
}

pub fn lift_export(
    pe: &Pe64,
    image: &[u8],
    name: &str,
    rva: u32,
) -> Result<LiftedExport, LiftError> {
    if let Some(rule) = forbidden_vm_rule(name) {
        return Err(LiftError(format!(
            "vm-export {name}: stays native ({rule}); CRT/DllMain/JNI ABI exports must \
             stay native — pick another export"
        )));
    }
    lift_function(pe, image, name, rva, None, true)
}

pub fn forbidden_vm_name(name: &str) -> bool {
    forbidden_vm_rule(name).is_some()
}

/// Which keep-native rule a name hits, for actionable errors. `forbidden_vm_name`
/// is this predicate's boolean view.
pub fn forbidden_vm_rule(name: &str) -> Option<&'static str> {
    let n = name.to_ascii_lowercase();
    // JVM ABI and the Qp bridge surface must stay native: the JVM calls
    // these by exact name at load time, never through a thunk.
    if n == "dllmain" || n.starts_with("dllmain@") {
        Some("DllMain runs under the loader lock")
    } else if n.contains("crt") {
        Some("name contains 'crt' (CRT ABI contract)")
    } else if n.starts_with('_') {
        Some("name starts with '_' (CRT-internal convention)")
    } else if n == "jni_onload" || n == "jni_onunload" {
        Some("JNI_OnLoad/JNI_OnUnload are called by exact name at load time")
    } else if n.starts_with("java_") {
        Some("name starts with 'java_' (JNI ABI contract)")
    } else if n.starts_with("qp_r1_") {
        Some("name starts with 'qp_r1_' (Qp bridge ABI contract)")
    } else {
        None
    }
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
    // Scratch vreg for constructs that need a temp (test a≠b, movsx widening).
    // The scan is a superset of every vreg the lifted IR will touch, so a
    // scratch picked here can never alias guest state.
    let scratch = scratch_vreg(&decoded);
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
        protos.push(lift_block(
            &decoded,
            leader,
            next_leader,
            name,
            &index_of,
            scratch,
        )?);
    }
    let entry = index_of(start_ip)?;
    let blocks = expand_cmovs(protos);
    Ok((IrModule { blocks, entry }, native_len))
}

/// Every GPR the decoded window touches — register operands plus memory
/// base/index. Deliberately over-approximate: instructions that would fail to
/// lift still pin their registers.
fn scratch_vreg(decoded: &std::collections::BTreeMap<u64, Instruction>) -> Option<u8> {
    let mut used = [false; 16];
    for ins in decoded.values() {
        for op in 0..ins.op_count() {
            if ins.op_kind(op) == OpKind::Register {
                let r = ins.op_register(op);
                if r.is_gpr() && r.number() < 16 {
                    used[r.number()] = true;
                }
            }
        }
        for r in [ins.memory_base(), ins.memory_index()] {
            if r.is_gpr() && r.number() < 16 {
                used[r.number()] = true;
            }
        }
    }
    used[VREG_RSP as usize] = true;
    (0..16u8).find(|&v| !used[v as usize])
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
                "vm-export {name}: branch out of lift window to {ip:#x} (window \
                 {start_ip:#x}..{end_ip:#x}, cap {MAX_LIFT_BYTES} bytes); the function is \
                 left native with --allow-native-fallback, or select an explicit \
                 fn_{:#x}/RVA window that fits the cap",
                ip as u32
            )));
        }
        let off = (ip - start_ip) as usize;
        let mut decoder = Decoder::with_ip(64, &bytes[off..], ip, DecoderOptions::NONE);
        let mut instr = Instruction::default();
        decoder.decode_out(&mut instr);
        if instr.is_invalid() {
            return Err(LiftError(format!(
                "vm-export {name}: invalid instruction at {ip:#x}; the selected boundary \
                 may cut mid-instruction or the body may be obfuscated — check the \
                 function length or pick another export"
            )));
        }
        if (ip - start_ip) as usize + instr.len() > MAX_LIFT_BYTES {
            return Err(LiftError(format!(
                "vm-export {name}: exceeds the {MAX_LIFT_BYTES} byte lift cap at {ip:#x}; \
                 only small leaf functions can be proven equivalent, so raise nothing — \
                 keep this function native with --allow-native-fallback or select a \
                 smaller one"
            )));
        }
        match instr.flow_control() {
            FlowControl::Next => work.push(ip + instr.len() as u64),
            FlowControl::UnconditionalBranch => {
                if !matches!(instr.op0_kind(), OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64) {
                    return Err(unsupported(&instr, name));
                }
                work.push(instr.near_branch_target());
            }
            FlowControl::ConditionalBranch => {
                if !matches!(instr.op0_kind(), OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64) {
                    return Err(unsupported(&instr, name));
                }
                work.push(instr.near_branch_target());
                work.push(ip + instr.len() as u64);
            }
            FlowControl::Return => {}
            FlowControl::Call | FlowControl::IndirectCall => {
                return Err(LiftError(format!(
                    "vm-export {name}: unsupported call at {ip:#x} ({:?}); a callee's side \
                     effects cannot be modeled statically, so functions that call anything \
                     (subroutines, IAT thunks, CRT) fail closed — pick a leaf function or \
                     pack with --allow-native-fallback to keep {name} native",
                    instr.mnemonic()
                )));
            }
            _ => return Err(unsupported(&instr, name)),
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
    scratch: Option<u8>,
) -> Result<ProtoBlock, LiftError> {
    let mut stmts = Vec::new();
    let mut pending_cmp: Option<(Src, Src)> = None;
    // vreg whose zero test equals the live ZF (add/sub/xor/and/or/inc/dec/neg
    // results). Cleared by any other statement — mov does not write flags and
    // a later write to the same vreg invalidates the equivalence.
    let mut last_zero_dst: Option<u8> = None;
    let mut ip = leader;
    loop {
        let instr = decoded.get(&ip).ok_or_else(|| {
            LiftError(format!("vm-export {name}: missing instr at {ip:#x}"))
        })?;
        if next_leader == Some(ip) && ip != leader {
            if pending_cmp.is_some() {
                return Err(LiftError(format!(
                    "vm-export {name}: unfused cmp at {ip:#x} — cmp/test must be \
                     immediately followed by the conditional branch or cmov that reads it"
                )));
            }
            return Ok(ProtoBlock {
                stmts,
                term: Term::Jmp { target: index_of(ip)? },
            });
        }
        match classify_instr(instr, name, scratch)? {
            LiftStep::Skip => {
                // Some skipped instructions still write guest flags (the
                // skipped `add/sub rsp,imm` prologue adjustments), and fusion
                // requires strict adjacency regardless — so neither fusion
                // source may survive a Skip; the next jcc/cmov fails closed.
                pending_cmp = None;
                last_zero_dst = None;
            }
            LiftStep::Seq { first, rest } => {
                if pending_cmp.is_some() {
                    return Err(LiftError(format!(
                        "vm-export {name}: unfused flags at {:#x} — a cmp/test must be \
                         immediately followed by the branch or cmov that reads it",
                        instr.ip()
                    )));
                }
                // lea/movsx sequences do not write guest flags.
                last_zero_dst = None;
                stmts.push(CodeStmt::N(first));
                stmts.extend(rest.into_iter().map(CodeStmt::N));
            }
            LiftStep::Stmt(s) => {
                if pending_cmp.is_some() {
                    return Err(LiftError(format!(
                        "vm-export {name}: unfused flags at {:#x} — a cmp/test must be \
                         immediately followed by the branch or cmov that reads it",
                        instr.ip()
                    )));
                }
                last_zero_dst = zero_dst_of(&s);
                stmts.push(CodeStmt::N(s));
            }
            LiftStep::AndCmp { dst, a, b } => {
                if pending_cmp.is_some() {
                    return Err(LiftError(format!(
                        "vm-export {name}: stacked cmp at {:#x}",
                        instr.ip()
                    )));
                }
                last_zero_dst = None;
                stmts.push(CodeStmt::N(Stmt::Bin {
                    op: BinOp::And,
                    dst,
                    lhs: a,
                    rhs: b,
                }));
                pending_cmp = Some((Src::Reg(dst), Src::Imm(0)));
            }
            LiftStep::Cmp(lhs, rhs) => {
                if pending_cmp.is_some() {
                    return Err(LiftError(format!(
                        "vm-export {name}: stacked cmp at {:#x}",
                        instr.ip()
                    )));
                }
                last_zero_dst = None;
                pending_cmp = Some((lhs, rhs));
            }
            LiftStep::Cmov { pred, dst, src } => {
                let (lhs, rhs) = fused_operands(
                    &mut pending_cmp,
                    last_zero_dst.take(),
                    pred,
                    instr,
                    name,
                )?;
                stmts.push(CodeStmt::Cmov {
                    pred,
                    dst,
                    src,
                    lhs,
                    rhs,
                });
                last_zero_dst = None;
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
                let (lhs, rhs) = fused_operands(
                    &mut pending_cmp,
                    last_zero_dst.take(),
                    pred,
                    instr,
                    name,
                )?;
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

/// Operands for a jcc/cmov: the fused cmp/test when present, otherwise the
/// result of a just-executed flag-setting arithmetic whose ZF is `result==0`
/// (add/sub/xor/and/or/inc/dec/neg). Everything else stays fail-closed.
fn fused_operands(
    pending_cmp: &mut Option<(Src, Src)>,
    zero_dst: Option<u8>,
    pred: CmpOp,
    instr: &Instruction,
    name: &str,
) -> Result<(Src, Src), LiftError> {
    if let Some(pair) = pending_cmp.take() {
        return Ok(pair);
    }
    match (zero_dst, pred) {
        (Some(dst), CmpOp::Eq | CmpOp::Ne) => Ok((Src::Reg(dst), Src::Imm(0))),
        _ => Err(LiftError(format!(
            "vm-export {name}: jcc without fused cmp at {:#x} ({:?}); only cmp/test — or a \
             zero-testing add/sub/xor/and/or/inc/dec result — can pair with a conditional \
             branch, and nothing may run between them",
            instr.ip(),
            instr.mnemonic()
        ))),
    }
}

/// The dst of a statement whose ZF equals `dst == 0`. imul's ZF is undefined
/// and shifts leave flags untouched when the count is 0, so neither fuses.
fn zero_dst_of(s: &Stmt) -> Option<u8> {
    match *s {
        Stmt::Bin {
            op: BinOp::Add | BinOp::Sub | BinOp::Xor | BinOp::And | BinOp::Or,
            dst,
            ..
        } => Some(dst),
        _ => None,
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
    /// One guest instruction lowering to an ordered statement sequence
    /// (scaled lea, movsx). None of these writes flags.
    Seq { first: Stmt, rest: Vec<Stmt> },
    Cmp(Src, Src),
    /// `test a, b` with an AND result: materialize `a & b` into `dst`, then
    /// the fused compare reads it against 0.
    AndCmp { dst: u8, a: Src, b: Src },
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

fn classify_instr(instr: &Instruction, name: &str, scratch: Option<u8>) -> Result<LiftStep, LiftError> {
    match instr.mnemonic() {
        Mnemonic::Ret => {
            if instr.op_count() != 0 {
                return Err(unsupported(instr, name));
            }
            Ok(LiftStep::Ret)
        }
        Mnemonic::Nop | Mnemonic::Endbr64 => Ok(LiftStep::Skip),
        Mnemonic::Push | Mnemonic::Pop => {
            if instr.op0_kind() == OpKind::Register && instr.op0_register().is_gpr() {
                Ok(LiftStep::Skip)
            } else {
                Err(unsupported(instr, name))
            }
        }
        Mnemonic::Sub | Mnemonic::Add if is_rsp_imm(instr) => Ok(LiftStep::Skip),
        Mnemonic::Lea => lift_lea(instr, name, scratch),
        Mnemonic::Mov => {
            if is_frame_mov(instr) {
                Ok(LiftStep::Skip)
            } else {
                lift_mov(instr, name)
            }
        }
        Mnemonic::Movzx => lift_movzx(instr, name),
        Mnemonic::Movsx | Mnemonic::Movsxd => lift_movsx(instr, name),
        Mnemonic::Add => lift_bin(instr, BinOp::Add, name),
        Mnemonic::Sub => lift_bin(instr, BinOp::Sub, name),
        Mnemonic::Xor => lift_bin(instr, BinOp::Xor, name),
        Mnemonic::And => lift_bin(instr, BinOp::And, name),
        Mnemonic::Or => lift_bin(instr, BinOp::Or, name),
        Mnemonic::Imul => lift_imul(instr, name),
        // sal shares Shl's opcode/mnemonic in iced.
        Mnemonic::Shl => lift_shift(instr, BinOp::Shl, name),
        Mnemonic::Shr => lift_shift(instr, BinOp::Shr, name),
        Mnemonic::Sar => lift_shift(instr, BinOp::Sar, name),
        Mnemonic::Inc => lift_incdec(instr, BinOp::Add, name),
        Mnemonic::Dec => lift_incdec(instr, BinOp::Sub, name),
        Mnemonic::Neg => lift_neg(instr, name),
        Mnemonic::Not => lift_not(instr, name),
        Mnemonic::Cmp => lift_cmp(instr, name),
        Mnemonic::Test => lift_test(instr, name, scratch),
        Mnemonic::Jmp => {
            if matches!(instr.op0_kind(), OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64) {
                Ok(LiftStep::Jmp(instr.near_branch_target()))
            } else {
                Err(unsupported(instr, name))
            }
        }
        m if jcc_pred(m).is_some() => {
            if !matches!(instr.op0_kind(), OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64) {
                return Err(unsupported(instr, name));
            }
            Ok(LiftStep::Jcc {
                pred: jcc_pred(m).unwrap(),
                target: instr.near_branch_target(),
                fallthrough: instr.ip() + instr.len() as u64,
            })
        }
        m if cmov_pred(m).is_some() => {
            if instr.op_count() != 2 || instr.op0_kind() != OpKind::Register {
                return Err(unsupported(instr, name));
            }
            let dst = reg32_index(instr.op0_register(), instr, name)?;
            let src = match instr.op1_kind() {
                OpKind::Register => Src::Reg(reg32_index(instr.op1_register(), instr, name)?),
                _ => return Err(unsupported(instr, name)),
            };
            Ok(LiftStep::Cmov {
                pred: cmov_pred(m).unwrap(),
                dst,
                src,
            })
        }
        _ => Err(unsupported(instr, name)),
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

fn lift_lea(instr: &Instruction, name: &str, scratch: Option<u8>) -> Result<LiftStep, LiftError> {
    if instr.op_count() != 2
        || instr.op0_kind() != OpKind::Register
        || instr.op1_kind() != OpKind::Memory
    {
        return Err(unsupported(instr, name));
    }
    if instr.is_ip_rel_memory_operand() {
        return Err(LiftError(format!(
            "vm-export {name}: unsupported rip-relative operand at {:#x} (Lea); addressing \
             a global through RIP needs the runtime image base, which the 32-bit IR model \
             does not carry — pass the address as an argument instead",
            instr.ip()
        )));
    }
    if instr.segment_prefix() != Register::None {
        return Err(LiftError(format!(
            "vm-export {name}: unsupported segment prefix at {:#x} (Lea); fs/gs-based \
             addressing (TEB/PEB) is outside the flat-memory IR model",
            instr.ip()
        )));
    }
    let dst = reg32_index(instr.op0_register(), instr, name)?;
    let a = gpr_index(instr.memory_base(), instr, name)?;
    let idx = instr.memory_index();
    let disp = instr.memory_displacement64() as u32;
    let scale_log: Option<u32> = match instr.memory_index_scale() {
        1 => Some(0),
        2 => Some(1),
        4 => Some(2),
        8 => Some(3),
        _ => None,
    };
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
    // scale==1 with a displacement folds into two adds with no scratch; the
    // single-statement add reads base and index before writing dst, so every
    // dst aliasing is safe.
    if scale_log == Some(0) {
        let b = gpr_index(idx, instr, name)?;
        let mut steps = vec![Stmt::Bin {
            op: BinOp::Add,
            dst,
            lhs: Src::Reg(a),
            rhs: Src::Reg(b),
        }];
        if disp != 0 {
            steps.push(Stmt::Bin {
                op: BinOp::Add,
                dst,
                lhs: Src::Reg(dst),
                rhs: Src::Imm(disp),
            });
        }
        return Ok(multi_step(steps));
    }
    let Some(shift) = scale_log else {
        return Err(unsupported(instr, name));
    };
    let b = gpr_index(idx, instr, name)?;
    // dst = base + (idx << shift) + disp. Aliasing decides the shape:
    // - base == idx: computing idx<<shift into dst would destroy base, so a
    //   function-wide scratch vreg is required.
    // - dst == idx: shift dst in place (dst is idx), then add base.
    // - dst == base: scale idx into a scratch first.
    // - otherwise: scale into dst (base and idx are untouched), then add.
    if a == b {
        let Some(t) = scratch else {
            return Err(LiftError(format!(
                "vm-export {name}: unsupported lea scale at {:#x}; scaling an index that \
                 aliases its base needs a spare vreg and every guest GPR of this function \
                 is in use",
                instr.ip()
            )));
        };
        let mut steps = vec![
            Stmt::Bin {
                op: BinOp::Shl,
                dst: t,
                lhs: Src::Reg(b),
                rhs: Src::Imm(shift),
            },
            Stmt::Bin {
                op: BinOp::Add,
                dst,
                lhs: Src::Reg(a),
                rhs: Src::Reg(t),
            },
        ];
        if disp != 0 {
            steps.push(Stmt::Bin {
                op: BinOp::Add,
                dst,
                lhs: Src::Reg(dst),
                rhs: Src::Imm(disp),
            });
        }
        return Ok(multi_step(steps));
    }
    if dst == b as u8 {
        let mut steps = vec![Stmt::Bin {
            op: BinOp::Shl,
            dst,
            lhs: Src::Reg(dst),
            rhs: Src::Imm(shift),
        }];
        steps.push(Stmt::Bin {
            op: BinOp::Add,
            dst,
            lhs: Src::Reg(a),
            rhs: Src::Reg(dst),
        });
        if disp != 0 {
            steps.push(Stmt::Bin {
                op: BinOp::Add,
                dst,
                lhs: Src::Reg(dst),
                rhs: Src::Imm(disp),
            });
        }
        return Ok(multi_step(steps));
    }
    if dst == a as u8 {
        let Some(t) = scratch else {
            return Err(LiftError(format!(
                "vm-export {name}: unsupported lea scale at {:#x}; scaling an index into a \
                 dst that aliases its base needs a spare vreg and every guest GPR of this \
                 function is in use",
                instr.ip()
            )));
        };
        let mut steps = vec![Stmt::Bin {
            op: BinOp::Shl,
            dst: t,
            lhs: Src::Reg(b),
            rhs: Src::Imm(shift),
        }];
        steps.push(Stmt::Bin {
            op: BinOp::Add,
            dst,
            lhs: Src::Reg(a),
            rhs: Src::Reg(t),
        });
        if disp != 0 {
            steps.push(Stmt::Bin {
                op: BinOp::Add,
                dst,
                lhs: Src::Reg(dst),
                rhs: Src::Imm(disp),
            });
        }
        return Ok(multi_step(steps));
    }
    let mut steps = vec![Stmt::Bin {
        op: BinOp::Shl,
        dst,
        lhs: Src::Reg(b),
        rhs: Src::Imm(shift),
    }];
    steps.push(Stmt::Bin {
        op: BinOp::Add,
        dst,
        lhs: Src::Reg(a),
        rhs: Src::Reg(dst),
    });
    if disp != 0 {
        steps.push(Stmt::Bin {
            op: BinOp::Add,
            dst,
            lhs: Src::Reg(dst),
            rhs: Src::Imm(disp),
        });
    }
    Ok(multi_step(steps))
}

/// Some lifters expand one guest instruction into a statement sequence; the
/// first lands as the step's statement, the rest ride along as immediate
/// followers. Kept order-preserving: none of the sequences here is
/// schedulable junk.
fn multi_step(steps: Vec<Stmt>) -> LiftStep {
    let mut it = steps.into_iter();
    let first = it.next().expect("multi_step needs at least one stmt");
    LiftStep::Seq {
        first,
        rest: it.collect(),
    }
}

fn mem_addr(instr: &Instruction, name: &str) -> Result<Addr, LiftError> {
    if instr.is_ip_rel_memory_operand() {
        return Err(LiftError(format!(
            "vm-export {name}: unsupported rip-relative operand at {:#x} ({:?}); reading a \
             global through RIP needs the runtime image base, which the IR model does not \
             carry — pass the pointer as an argument instead",
            instr.ip(),
            instr.mnemonic()
        )));
    }
    if instr.segment_prefix() != Register::None {
        return Err(LiftError(format!(
            "vm-export {name}: unsupported segment prefix at {:#x} ({:?}); fs/gs-based \
             addressing (TEB/PEB) is outside the flat-memory IR model",
            instr.ip(),
            instr.mnemonic()
        )));
    }
    if instr.memory_index() != Register::None {
        return Err(LiftError(format!(
            "vm-export {name}: unsupported indexed memory operand at {:#x} ({:?}); only \
             [base + disp] addressing is modeled — precompute the address with a lea",
            instr.ip(),
            instr.mnemonic()
        )));
    }
    let base = instr.memory_base();
    if !base.is_gpr() {
        return Err(unsupported(instr, name));
    }
    let base_i = gpr_index_allow_rsp(base, instr, true, name)?;
    Ok(Addr::BaseDisp {
        base: base_i,
        disp: instr.memory_displacement64() as i32,
    })
}

fn op_width(instr: &Instruction, name: &str) -> Result<u8, LiftError> {
    match instr.memory_size().size() {
        1 | 2 | 4 | 8 => Ok(instr.memory_size().size() as u8),
        _ => {
            if instr.op0_kind() == OpKind::Register {
                match instr.op0_register().size() {
                    1 | 2 | 4 | 8 => Ok(instr.op0_register().size() as u8),
                    _ => Err(unsupported(instr, name)),
                }
            } else {
                Err(unsupported(instr, name))
            }
        }
    }
}

/// Width gate: the IR oracle and superop codegen are fixed at 32-bit, so a
/// wider operand would compute wrong high bits at runtime — fail closed with
/// the actual width instead of lifting it.
fn width_error(instr: &Instruction, name: &str) -> LiftError {
    let bits = if instr.op0_kind() == OpKind::Register {
        instr.op0_register().size() * 8
    } else {
        instr.memory_size().size() * 8
    };
    LiftError(format!(
        "vm-export {name}: unsupported {:?} operand width at {:#x} ({bits}-bit); the IR \
         oracle and codegen are fixed at 32-bit, so wider operands fail closed instead of \
         silently computing wrong high bits — rewrite the hot path at 32-bit width or keep \
         the function native with --allow-native-fallback",
        instr.mnemonic(),
        instr.ip()
    ))
}

fn lift_mov(instr: &Instruction, name: &str) -> Result<LiftStep, LiftError> {
    if instr.op_count() != 2 {
        return Err(unsupported(instr, name));
    }
    match (instr.op0_kind(), instr.op1_kind()) {
        (OpKind::Register, OpKind::Register) => {
            let dst = reg32_index(instr.op0_register(), instr, name)?;
            let src = reg32_index(instr.op1_register(), instr, name)?;
            Ok(LiftStep::Stmt(Stmt::Mov {
                dst,
                src: Src::Reg(src),
            }))
        }
        (OpKind::Register, k) if is_imm(k) => {
            let dst = reg32_index(instr.op0_register(), instr, name)?;
            Ok(LiftStep::Stmt(Stmt::Mov {
                dst,
                src: Src::Imm(instr.immediate(1) as u32),
            }))
        }
        (OpKind::Register, OpKind::Memory) => {
            // A plain mov writes the destination register in its own width;
            // partial-register (8/16-bit) and 64-bit loads are not modeled.
            // Narrow zero-extending loads go through `movzx`.
            let width = op_width(instr, name)?;
            if width != 4 {
                return Err(width_error(instr, name));
            }
            let dst = reg32_index(instr.op0_register(), instr, name)?;
            let addr = mem_addr(instr, name)?;
            Ok(LiftStep::Stmt(Stmt::Load { dst, addr, width }))
        }
        (OpKind::Memory, OpKind::Register) => {
            let width = op_width(instr, name)?;
            if width > 4 {
                return Err(width_error(instr, name));
            }
            let addr = mem_addr(instr, name)?;
            let src = reg32_index(instr.op1_register(), instr, name)?;
            // Only the low `width` bytes of the vreg are stored, which is
            // exactly what an 8/16/32-bit register store does.
            Ok(LiftStep::Stmt(Stmt::Store { addr, src: Src::Reg(src), width }))
        }
        (OpKind::Memory, k) if is_imm(k) => {
            let width = op_width(instr, name)?;
            if width > 4 {
                // mov qword [x], imm is a sign-extended imm32; the u32 Imm
                // source cannot carry the sign extension.
                return Err(width_error(instr, name));
            }
            let addr = mem_addr(instr, name)?;
            Ok(LiftStep::Stmt(Stmt::Store {
                addr,
                src: Src::Imm(instr.immediate(1) as u32),
                width,
            }))
        }
        _ => Err(unsupported(instr, name)),
    }
}

/// `movzx r32, m8/m16` — a zero-extending narrow load, which the IR Load
/// already models exactly (the vreg is fully replaced with the zero-extended
/// value). Register sources need a low-byte/low-word read of a vreg, which
/// the model cannot express.
fn lift_movzx(instr: &Instruction, name: &str) -> Result<LiftStep, LiftError> {
    if instr.op_count() != 2 {
        return Err(unsupported(instr, name));
    }
    let dst = reg32_index(instr.op0_register(), instr, name)?;
    match instr.op1_kind() {
        OpKind::Memory => {
            let width = op_width(instr, name)?;
            if width != 1 && width != 2 {
                return Err(unsupported(instr, name));
            }
            let addr = mem_addr(instr, name)?;
            Ok(LiftStep::Stmt(Stmt::Load { dst, addr, width }))
        }
        _ => Err(LiftError(format!(
            "vm-export {name}: unsupported movzx register source at {:#x}; reading the \
             low byte/word of a vreg is not modeled — reload the value from memory with \
             an explicit narrow load instead",
            instr.ip()
        ))),
    }
}

/// `movsx r32, m8/m16` — sign-extending narrow load, built from the modeled
/// zero-extending Load plus the exact identity sext(v) = (v ^ 0x8000…) −
/// 0x8000… on the 32-bit result. Register sources stay fail-closed.
fn lift_movsx(instr: &Instruction, name: &str) -> Result<LiftStep, LiftError> {
    if instr.mnemonic() == Mnemonic::Movsxd || instr.op_count() != 2 {
        return Err(unsupported(instr, name));
    }
    let dst = reg32_index(instr.op0_register(), instr, name)?;
    match instr.op1_kind() {
        OpKind::Memory => {
            let width = op_width(instr, name)?;
            let sign = match width {
                1 => 0x80u32,
                2 => 0x8000u32,
                _ => return Err(unsupported(instr, name)),
            };
            let addr = mem_addr(instr, name)?;
            let steps = vec![
                Stmt::Load { dst, addr, width },
                Stmt::Bin {
                    op: BinOp::Xor,
                    dst,
                    lhs: Src::Reg(dst),
                    rhs: Src::Imm(sign),
                },
                Stmt::Bin {
                    op: BinOp::Sub,
                    dst,
                    lhs: Src::Reg(dst),
                    rhs: Src::Imm(sign),
                },
            ];
            Ok(multi_step(steps))
        }
        _ => Err(LiftError(format!(
            "vm-export {name}: unsupported movsx register source at {:#x}; reading the \
             low byte/word of a vreg is not modeled — reload the value from memory with \
             an explicit narrow load instead",
            instr.ip()
        ))),
    }
}

fn lift_bin(instr: &Instruction, op: BinOp, name: &str) -> Result<LiftStep, LiftError> {
    if instr.op_count() != 2 || instr.op0_kind() != OpKind::Register {
        return Err(unsupported(instr, name));
    }
    if instr.op0_register().size() != 4 {
        return Err(width_error(instr, name));
    }
    let dst = reg32_index(instr.op0_register(), instr, name)?;
    let lhs = Src::Reg(dst);
    let rhs = match instr.op1_kind() {
        OpKind::Register => {
            if instr.op1_register().size() != 4 {
                return Err(width_error(instr, name));
            }
            Src::Reg(reg32_index(instr.op1_register(), instr, name)?)
        }
        k if is_imm(k) => Src::Imm(instr.immediate(1) as u32),
        OpKind::Memory => {
            return Err(LiftError(format!(
                "vm-export {name}: unsupported memory operand at {:#x} ({:?}); only \
                 [base + disp] loads into a register are modeled — load the value with a \
                 mov first",
                instr.ip(),
                instr.mnemonic()
            )));
        }
        _ => return Err(unsupported(instr, name)),
    };
    Ok(LiftStep::Stmt(Stmt::Bin { op, dst, lhs, rhs }))
}

/// `imul` register forms with a 32-bit destination. The 1-operand widening
/// form (edx:eax) and any 64-bit operand stay fail-closed — there is no
/// pack-time equivalence check, so a silent width mismatch is unacceptable.
fn lift_imul(instr: &Instruction, name: &str) -> Result<LiftStep, LiftError> {
    if instr.op0_kind() != OpKind::Register {
        return Err(unsupported(instr, name));
    }
    let dst = reg32_index(instr.op0_register(), instr, name)?;
    match instr.op_count() {
        2 => {
            // imul r32, r/m32  →  dst = dst * src
            let rhs = match instr.op1_kind() {
                OpKind::Register => Src::Reg(reg32_index(instr.op1_register(), instr, name)?),
                _ => return Err(unsupported(instr, name)),
            };
            Ok(LiftStep::Stmt(Stmt::Bin { op: BinOp::Mul, dst, lhs: Src::Reg(dst), rhs }))
        }
        3 => {
            // imul r32, r/m32, imm  →  dst = src * imm
            let src = match instr.op1_kind() {
                OpKind::Register => Src::Reg(reg32_index(instr.op1_register(), instr, name)?),
                _ => return Err(unsupported(instr, name)),
            };
            if !is_imm(instr.op2_kind()) {
                return Err(unsupported(instr, name));
            }
            let rhs = Src::Imm(instr.immediate(2) as u32);
            Ok(LiftStep::Stmt(Stmt::Bin { op: BinOp::Mul, dst, lhs: src, rhs }))
        }
        _ => Err(unsupported(instr, name)),
    }
}

/// `shl`/`shr`/`sar` with a 32-bit destination. Only immediate counts and the
/// shift-by-CL form are representable; the count register maps to guest RCX.
fn lift_shift(instr: &Instruction, op: BinOp, name: &str) -> Result<LiftStep, LiftError> {
    if instr.op0_kind() != OpKind::Register {
        return Err(unsupported(instr, name));
    }
    let dst = reg32_index(instr.op0_register(), instr, name)?;
    let rhs = match instr.op_count() {
        // `shl r/m, 1` encodes the count implicitly in the opcode.
        1 => Src::Imm(1),
        2 => match instr.op1_kind() {
            k if is_imm(k) => Src::Imm(instr.immediate(1) as u32),
            OpKind::Register => {
                if instr.op1_register() != Register::CL {
                    return Err(unsupported(instr, name));
                }
                // The count is CL, i.e. the low byte of guest (E)CX.
                Src::Reg(VREG_RCX as u8)
            }
            _ => return Err(unsupported(instr, name)),
        },
        _ => return Err(unsupported(instr, name)),
    };
    Ok(LiftStep::Stmt(Stmt::Bin { op, dst, lhs: Src::Reg(dst), rhs }))
}

/// `inc`/`dec` lower to `+1` / `-1` on a 32-bit register.
fn lift_incdec(instr: &Instruction, op: BinOp, name: &str) -> Result<LiftStep, LiftError> {
    if instr.op_count() != 1 || instr.op0_kind() != OpKind::Register {
        return Err(unsupported(instr, name));
    }
    let dst = reg32_index(instr.op0_register(), instr, name)?;
    Ok(LiftStep::Stmt(Stmt::Bin { op, dst, lhs: Src::Reg(dst), rhs: Src::Imm(1) }))
}

/// `neg dst` == `0 - dst` on a 32-bit register.
fn lift_neg(instr: &Instruction, name: &str) -> Result<LiftStep, LiftError> {
    if instr.op_count() != 1 || instr.op0_kind() != OpKind::Register {
        return Err(unsupported(instr, name));
    }
    let dst = reg32_index(instr.op0_register(), instr, name)?;
    Ok(LiftStep::Stmt(Stmt::Bin {
        op: BinOp::Sub,
        dst,
        lhs: Src::Imm(0),
        rhs: Src::Reg(dst),
    }))
}

/// `not dst` == `dst ^ 0xFFFF_FFFF` on a 32-bit register.
fn lift_not(instr: &Instruction, name: &str) -> Result<LiftStep, LiftError> {
    if instr.op_count() != 1 || instr.op0_kind() != OpKind::Register {
        return Err(unsupported(instr, name));
    }
    let dst = reg32_index(instr.op0_register(), instr, name)?;
    Ok(LiftStep::Stmt(Stmt::Bin {
        op: BinOp::Xor,
        dst,
        lhs: Src::Reg(dst),
        rhs: Src::Imm(0xFFFF_FFFF),
    }))
}

fn lift_cmp(instr: &Instruction, name: &str) -> Result<LiftStep, LiftError> {
    if instr.op_count() != 2 || instr.op0_kind() != OpKind::Register {
        return Err(unsupported(instr, name));
    }
    if instr.op0_register().size() != 4 {
        return Err(width_error(instr, name));
    }
    let lhs = Src::Reg(reg32_index(instr.op0_register(), instr, name)?);
    let rhs = match instr.op1_kind() {
        OpKind::Register => {
            if instr.op1_register().size() != 4 {
                return Err(width_error(instr, name));
            }
            Src::Reg(reg32_index(instr.op1_register(), instr, name)?)
        }
        k if is_imm(k) => Src::Imm(instr.immediate(1) as u32),
        _ => return Err(unsupported(instr, name)),
    };
    Ok(LiftStep::Cmp(lhs, rhs))
}

/// `test` sets flags from `a & b` without writing back.
/// - `test r, r` folds to `cmp r, 0` (every flag derives from the value).
/// - other forms materialize `a & b` into a function-wide scratch vreg, then
///   compare it against 0 — exact for every condition code.
fn lift_test(instr: &Instruction, name: &str, scratch: Option<u8>) -> Result<LiftStep, LiftError> {
    if instr.op_count() != 2 || instr.op0_kind() != OpKind::Register {
        return Err(unsupported(instr, name));
    }
    if instr.op0_register().size() != 4 {
        return Err(width_error(instr, name));
    }
    let a = reg32_index(instr.op0_register(), instr, name)?;
    let b = match instr.op1_kind() {
        OpKind::Register => {
            if instr.op1_register().size() != 4 {
                return Err(width_error(instr, name));
            }
            Src::Reg(reg32_index(instr.op1_register(), instr, name)?)
        }
        k if is_imm(k) => Src::Imm(instr.immediate(1) as u32),
        _ => return Err(unsupported(instr, name)),
    };
    if let Src::Reg(r) = b {
        if r == a {
            return Ok(LiftStep::Cmp(Src::Reg(a), Src::Imm(0)));
        }
    }
    let Some(t) = scratch else {
        return Err(LiftError(format!(
            "vm-export {name}: unsupported test of two different registers at {:#x}; \
             materializing a & b needs a spare vreg and every guest GPR of this function \
             is in use",
            instr.ip()
        )));
    };
    Ok(LiftStep::AndCmp { dst: t, a: Src::Reg(a), b })
}

fn gpr_index(reg: Register, instr: &Instruction, name: &str) -> Result<u8, LiftError> {
    gpr_index_allow_rsp(reg, instr, false, name)
}

/// Only accepts 32-bit GPRs (eax..r15d). Codegen for register writes and
/// arithmetic is fixed to 32-bit width; any other operand size stays
/// fail-closed with the actual width in the error.
fn reg32_index(reg: Register, instr: &Instruction, name: &str) -> Result<u8, LiftError> {
    if reg.size() != 4 {
        return Err(width_error(instr, name));
    }
    gpr_index(reg, instr, name)
}

fn gpr_index_allow_rsp(
    reg: Register,
    instr: &Instruction,
    allow_rsp: bool,
    name: &str,
) -> Result<u8, LiftError> {
    if !reg.is_gpr() {
        return Err(unsupported(instr, name));
    }
    let n = reg.number();
    if n >= 16 || (!allow_rsp && n == VREG_RSP as usize) {
        return Err(unsupported(instr, name));
    }
    Ok(n as u8)
}

fn unsupported(instr: &Instruction, name: &str) -> LiftError {
    let fallback = if !name.is_empty() {
        format!(
            " — {name} is left native with --allow-native-fallback, or pick a different \
             export"
        )
    } else {
        String::new()
    };
    LiftError(format!(
        "vm-export {name}: unsupported {:?} at {:#x}{}",
        instr.mnemonic(),
        instr.ip(),
        fallback
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

    // ------------------------------------------------------------------
    // Width gating (audit: silent wrong-code for 64-bit operands).
    // ------------------------------------------------------------------

    #[test]
    fn mov_rax_imm64_fails_closed() {
        use iced_x86::code_asm::*;
        // The highest-volume 64-bit constant load must not truncate to u32.
        let bytes = asm_bytes(|a| {
            a.mov(rax, 0x1234_5678_1234_5678u64)?;
            a.ret()
        });
        let err = lift_code(&bytes, 0x1000, "probe").unwrap_err();
        assert!(err.0.contains("width"), "{}", err.0);
    }

    #[test]
    fn add64_fails_closed() {
        use iced_x86::code_asm::*;
        let bytes = asm_bytes(|a| {
            a.add(rax, rbx)?;
            a.ret()
        });
        let err = lift_code(&bytes, 0x1000, "probe").unwrap_err();
        assert!(err.0.contains("width"), "{}", err.0);
    }

    #[test]
    fn add8_fails_closed() {
        use iced_x86::code_asm::*;
        let bytes = asm_bytes(|a| {
            a.add(al, 1u32)?;
            a.ret()
        });
        assert!(lift_code(&bytes, 0x1000, "probe").is_err());
    }

    #[test]
    fn mov_r64_r64_fails_closed() {
        use iced_x86::code_asm::*;
        let bytes = asm_bytes(|a| {
            a.mov(rax, rbx)?;
            a.ret()
        });
        assert!(lift_code(&bytes, 0x1000, "probe").is_err());
    }

    #[test]
    fn partial_register_load_fails_closed() {
        use iced_x86::code_asm::*;
        // mov al, [rcx] keeps rax's upper bytes in x86; the IR Load replaces
        // the whole vreg — must fail closed, not silently zero-extend.
        let bytes = asm_bytes(|a| {
            a.mov(al, byte_ptr(rcx))?;
            a.ret()
        });
        assert!(lift_code(&bytes, 0x1000, "probe").is_err());
    }

    #[test]
    fn load64_fails_closed() {
        use iced_x86::code_asm::*;
        // The oracle masks reads to 32 bits; codegen moves 64 — mismatch.
        let bytes = asm_bytes(|a| {
            a.mov(rax, qword_ptr(rcx))?;
            a.ret()
        });
        assert!(lift_code(&bytes, 0x1000, "probe").is_err());
    }

    #[test]
    fn call_direct_error_names_remediation() {
        use iced_x86::code_asm::*;
        let mut a = iced_x86::code_asm::CodeAssembler::new(64).unwrap();
        a.call(rbx).unwrap();
        a.ret().unwrap();
        let bytes = a.assemble(0x1000).unwrap();
        let err = lift_code(&bytes, 0x1000, "my_fn").unwrap_err();
        assert!(err.0.contains("my_fn"), "{}", err.0);
        assert!(err.0.contains("leaf"), "{}", err.0);
        assert!(err.0.contains("--allow-native-fallback"), "{}", err.0);
    }

    #[test]
    fn forbidden_rule_reports_which_rule() {
        assert!(forbidden_vm_rule("my_crt_helper").unwrap().contains("crt"));
        assert!(forbidden_vm_rule("_inner").unwrap().contains("'_'"));
        assert!(forbidden_vm_rule("hello_add").is_none());
    }

    // Identity-mapped fake image: RVA equals file offset, which is all the
    // thunk resolver asks of its `resolve` closure.
    fn thunk_image(body_at: usize, body: &[u8]) -> Vec<u8> {
        let mut image = vec![0u8; 0x100];
        image[body_at..body_at + body.len()].copy_from_slice(body);
        image
    }

    #[test]
    fn follows_incremental_link_thunk() {
        let mut image = thunk_image(0x25, &[0xB8, 1, 0, 0, 0, 0xC3]); // mov eax,1; ret
        image[0] = 0xE9; // jmp rel32 at rva 0
        image[1..5].copy_from_slice(&0x20i32.to_le_bytes()); // 5 + 0x20 = 0x25
        let resolved = follow_entry_thunk(&image, "exp", 0, |r| {
            if (r as usize) < image.len() { Some(r as usize) } else { None }
        })
        .unwrap();
        assert_eq!(resolved, Some(0x25));
    }

    #[test]
    fn non_thunk_entry_resolves_to_none() {
        let image = thunk_image(0, &[0xB8, 1, 0, 0, 0, 0xC3]); // mov eax,1; ret
        let resolved = follow_entry_thunk(&image, "exp", 0, |r| Some(r as usize)).unwrap();
        assert_eq!(resolved, None);
    }

    #[test]
    fn rel8_jmp_is_not_a_thunk() {
        // `jmp rel8` (EB 20) cannot be patched with a rel32 rewrite — must
        // stay untouched so apply_vm_hook never under-fills the window.
        let mut image = vec![0u8; 0x100];
        image[0] = 0xEB;
        image[1] = 0x20; // -> 2 + 0x20 = 0x22
        image[0x22..0x28].copy_from_slice(&[0xB8, 1, 0, 0, 0, 0xC3]);
        let resolved = follow_entry_thunk(&image, "exp", 0, |r| {
            if (r as usize) < image.len() { Some(r as usize) } else { None }
        })
        .unwrap();
        assert_eq!(resolved, None);
    }

    #[test]
    fn thunk_self_jump_fails_closed() {
        let mut image = vec![0u8; 0x20];
        image[0] = 0xE9;
        image[1..5].copy_from_slice(&(-5i32).to_le_bytes()); // target = 0
        let err = follow_entry_thunk(&image, "exp", 0, |r| Some(r as usize)).unwrap_err();
        assert!(err.0.contains("self-jump"), "{}", err.0);
    }

    #[test]
    fn thunk_chain_over_hop_bound_fails_closed() {
        // Four chained jmps at 0x00 -> 0x10 -> 0x20 -> 0x30 -> 0x40, where
        // 0x40 is still a jmp: exceeds MAX_THUNK_HOPS and must error.
        let mut image = vec![0u8; 0x100];
        for (i, at) in [0x00usize, 0x10, 0x20, 0x30, 0x40].into_iter().enumerate() {
            image[at] = 0xE9;
            let next = 0x10i32 * (i as i32 + 1) - (at as i32 + 5);
            image[at + 1..at + 5].copy_from_slice(&next.to_le_bytes());
        }
        let err = follow_entry_thunk(&image, "exp", 0, |r| Some(r as usize)).unwrap_err();
        assert!(err.0.contains("exceeds 4 jumps"), "{}", err.0);
    }

    #[test]
    fn unmapped_thunk_target_is_not_a_thunk() {
        let mut image = vec![0u8; 0x20];
        image[0] = 0xE9;
        image[1..5].copy_from_slice(&0x1000i32.to_le_bytes()); // far outside
        let resolved = follow_entry_thunk(&image, "exp", 0, |r| {
            if (r as usize) < image.len() { Some(r as usize) } else { None }
        })
        .unwrap();
        assert_eq!(resolved, None);
    }

    // ------------------------------------------------------------------
    // Expanded coverage: movzx/movsx, test forms, scaled lea, ZF fusion.
    // ------------------------------------------------------------------

    #[test]
    fn lifts_movzx_mem() {
        use iced_x86::code_asm::*;
        let bytes = asm_bytes(|a| {
            a.movzx(eax, byte_ptr(rcx))?;
            a.ret()
        });
        let (ir, _) = lift_code(&bytes, 0x1000, "probe").unwrap();
        let mut st = xenolith_vm::MachineState::from_win64_u32(0x2000, 0);
        st.mem.write_u64(0x2000, 1, 0xFF).unwrap();
        assert_eq!(xenolith_vm::eval_machine(&ir, &mut st).unwrap(), 0xFF);
    }

    #[test]
    fn lifts_movsx_mem() {
        use iced_x86::code_asm::*;
        let b8 = asm_bytes(|a| {
            a.movsx(eax, byte_ptr(rcx))?;
            a.ret()
        });
        let (ir, _) = lift_code(&b8, 0x1000, "probe").unwrap();
        let mut st = xenolith_vm::MachineState::from_win64_u32(0x2000, 0);
        st.mem.write_u64(0x2000, 1, 0xFF).unwrap();
        assert_eq!(xenolith_vm::eval_machine(&ir, &mut st).unwrap(), 0xFFFF_FFFF);

        let b16 = asm_bytes(|a| {
            a.movsx(eax, word_ptr(rcx))?;
            a.ret()
        });
        let (ir, _) = lift_code(&b16, 0x1000, "probe").unwrap();
        let mut st = xenolith_vm::MachineState::from_win64_u32(0x2000, 0);
        st.mem.write_u64(0x2000, 2, 0x8000).unwrap();
        assert_eq!(xenolith_vm::eval_machine(&ir, &mut st).unwrap(), 0xFFFF_8000);
    }

    #[test]
    fn lifts_test_diff_regs_and_imm() {
        use iced_x86::code_asm::*;
        // test ecx, edx; jz → zero iff x & y == 0
        let bytes = asm_bytes(|a| {
            let mut z = a.create_label();
            a.test(ecx, edx)?;
            a.jz(z)?;
            a.mov(eax, 1i32)?;
            a.ret()?;
            a.set_label(&mut z)?;
            a.xor(eax, eax)?;
            a.ret()
        });
        check_lift(&bytes, |x, y| u32::from((x & y) != 0));
        // test eax, 0x10; jz → zero iff x & 0x10 == 0
        let bytes = asm_bytes(|a| {
            let mut z = a.create_label();
            a.mov(eax, ecx)?;
            a.test(eax, 0x10u32)?;
            a.jz(z)?;
            a.mov(eax, 1i32)?;
            a.ret()?;
            a.set_label(&mut z)?;
            a.xor(eax, eax)?;
            a.ret()
        });
        check_lift(&bytes, |x, _| u32::from((x & 0x10) != 0));
    }

    #[test]
    fn lifts_lea_scale() {
        use iced_x86::code_asm::*;
        let scaled = asm_bytes(|a| {
            a.lea(eax, dword_ptr(rcx + rdx * 4))?;
            a.ret()
        });
        check_lift(&scaled, |x, y| x.wrapping_add(y.wrapping_mul(4)));
        // aliased index+base through the scratch path
        let alias = asm_bytes(|a| {
            a.lea(ecx, dword_ptr(rcx + rcx * 2))?;
            a.mov(eax, ecx)?;
            a.ret()
        });
        check_lift(&alias, |x, _| x.wrapping_mul(3));
        // scale + displacement, dst aliasing the index
        let disped = asm_bytes(|a| {
            a.mov(ecx, edx)?;
            a.lea(edx, dword_ptr(rcx + rcx * 8 + 7))?;
            a.mov(eax, edx)?;
            a.ret()
        });
        check_lift(&disped, |_, y| y.wrapping_mul(9).wrapping_add(7));
    }

    #[test]
    fn lifts_arith_zf_fusion() {
        use iced_x86::code_asm::*;
        // add eax, edx; jz — the audit's "loop counter" pattern.
        let bytes = asm_bytes(|a| {
            let mut z = a.create_label();
            a.mov(eax, ecx)?;
            a.add(eax, edx)?;
            a.jz(z)?;
            a.mov(eax, 1i32)?;
            a.ret()?;
            a.set_label(&mut z)?;
            a.xor(eax, eax)?;
            a.ret()
        });
        check_lift(&bytes, |x, y| u32::from(x.wrapping_add(y) != 0));
        // sub ecx, ecx; je
        let bytes = asm_bytes(|a| {
            let mut z = a.create_label();
            a.sub(ecx, ecx)?;
            a.je(z)?;
            a.mov(eax, 1i32)?;
            a.ret()?;
            a.set_label(&mut z)?;
            a.xor(eax, eax)?;
            a.ret()
        });
        check_lift(&bytes, |_, _| 0);
        // fusion must not survive an intervening write to the flag source
        let bytes = asm_bytes(|a| {
            let mut z = a.create_label();
            a.add(ecx, 1i32)?;
            a.mov(ecx, edx)?;
            a.je(z)?;
            a.mov(eax, 1i32)?;
            a.ret()?;
            a.set_label(&mut z)?;
            a.xor(eax, eax)?;
            a.ret()
        });
        assert!(lift_code(&bytes, 0x1000, "probe").is_err());
    }

    #[test]
    fn skipped_rsp_adjustment_breaks_flag_fusion() {
        use iced_x86::code_asm::*;
        // add eax, edx; sub rsp, 0x28; jz — the skipped stack adjustment
        // writes ZF on real hardware, so the stale eax==0 fusion must not
        // survive it: the block fails closed instead of misfusing.
        let bytes = asm_bytes(|a| {
            let mut z = a.create_label();
            a.mov(eax, ecx)?;
            a.add(eax, edx)?;
            a.sub(rsp, 0x28i32)?;
            a.jz(z)?;
            a.mov(eax, 1i32)?;
            a.ret()?;
            a.set_label(&mut z)?;
            a.xor(eax, eax)?;
            a.ret()
        });
        let err = lift_code(&bytes, 0x1000, "probe").unwrap_err();
        assert!(err.0.contains("fused"), "{}", err.0);
        // Same hole for the fused-cmp path: cmp; sub rsp; jcc.
        let bytes = asm_bytes(|a| {
            let mut z = a.create_label();
            a.cmp(eax, edx)?;
            a.sub(rsp, 8i32)?;
            a.je(z)?;
            a.mov(eax, 1i32)?;
            a.ret()?;
            a.set_label(&mut z)?;
            a.xor(eax, eax)?;
            a.ret()
        });
        let err = lift_code(&bytes, 0x1000, "probe").unwrap_err();
        assert!(err.0.contains("fused"), "{}", err.0);
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
        match classify_instr(&ins, "", None) {
            Ok(_) => liftable += 1,
            Err(_) => {}
        }
    }
    (liftable, total)
}
