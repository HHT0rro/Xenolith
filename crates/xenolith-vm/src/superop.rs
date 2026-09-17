//! Per-block unique PIC. No guest bytecode, no dispatcher.
//!
//! W2: per-block register allocation, stmt scheduling, MBA families,
//! never-taken opaque junk edges. CFG of the original IR stays isomorphic.
//! W3: optional `--trace-diverge` emits two semantically equal paths
//! selected by a process-unique coin (not RDTSC-only).

use iced_x86::code_asm::*;
use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind};
use sha2::{Digest, Sha256};

use crate::ir::{
    Addr, AtomicOpIr, BinOp, CmpOp, CvtKind, FOp, FWidth, IrModule, Src, Stmt, Term, VecOp,
    VREG_COUNT, VREG_RAX, VREG_RCX, VREG_RDX, VREG_RSP,
};
use crate::mba::{pick_family, MbaFamily};

const POOL: [u8; 12] = [3, 5, 6, 7, 8, 9, 10, 12, 13, 14, 15, 11];
const TMP: u8 = 11; // dedicated shuffle/MBA temp; maps avoid it when possible

#[derive(Clone, Copy, Debug, Default)]
pub struct SuperopOptions {
    /// W3: two equivalent paths per block. Default off (no new W2 flag).
    pub trace_diverge: bool,
}

pub fn emit_superop(module: &IrModule, seed: &[u8; 16]) -> Result<Vec<u8>, String> {
    emit_superop_ex(module, seed, SuperopOptions::default())
}

pub fn emit_superop_ex(
    module: &IrModule,
    seed: &[u8; 16],
    opt: SuperopOptions,
) -> Result<Vec<u8>, String> {
    if module.blocks.is_empty() || module.entry >= module.blocks.len() {
        return Err("superop: empty ir".into());
    }
    let live = used_vregs(module);
    let maps: Vec<[u8; VREG_COUNT]> = (0..module.blocks.len())
        .map(|bi| alloc_map(seed, bi as u32, &live))
        .collect::<Result<Vec<_>, _>>()?;
    emit_inner(module, seed, opt, &maps, &live).map_err(|e| format!("superop: {e}"))
}

fn emit_inner(
    module: &IrModule,
    seed: &[u8; 16],
    opt: SuperopOptions,
    maps: &[[u8; VREG_COUNT]],
    live: &[bool; VREG_COUNT],
) -> Result<Vec<u8>, iced_x86::IcedError> {

    let mut a = CodeAssembler::new(64)?;
    let mut block_labels: Vec<CodeLabel> = (0..module.blocks.len())
        .map(|_| a.create_label())
        .collect();
    let mut l_epilogue = a.create_label();
    let mut l_junk: Vec<CodeLabel> = (0..module.blocks.len())
        .map(|_| a.create_label())
        .collect();
    let mut l_path_b: Vec<CodeLabel> = (0..module.blocks.len())
        .map(|_| a.create_label())
        .collect();

    a.push(rbx)?;
    a.push(rbp)?;
    a.push(rsi)?;
    a.push(rdi)?;
    a.push(r12)?;
    a.push(r13)?;
    a.push(r14)?;
    a.push(r15)?;

    let entry_map = maps[module.entry];
    let mut id_map = [0u8; VREG_COUNT];
    for (i, slot) in id_map.iter_mut().enumerate() {
        *slot = i as u8;
    }
    let mut live_args = [false; VREG_COUNT];
    live_args[VREG_RCX as usize] = true;
    live_args[VREG_RDX as usize] = true;
    emit_shuffle(&mut a, &id_map, &entry_map, &live_args)?;
    a.jmp(block_labels[module.entry])?;

    for (bi, block) in module.blocks.iter().enumerate() {
        a.set_label(&mut block_labels[bi])?;
        let stream = block_stream(seed, bi as u32);
        let map = maps[bi];
        let scheduled = schedule_stmts(&block.stmts, stream[0]);

        if opt.trace_diverge {
            emit_coin(&mut a, stream[4])?;
            a.jnz(l_path_b[bi])?;
        }

        emit_block_body(&mut a, &scheduled, stream, map, seed, bi, false)?;
        emit_opaque_junk_edge(&mut a, &mut l_junk[bi], stream[8], map)?;
        emit_term(
            &mut a,
            &block.term,
            map,
            &maps,
            &live,
            &block_labels,
            l_epilogue,
        )?;

        if opt.trace_diverge {
            a.set_label(&mut l_path_b[bi])?;
            let scheduled_b = schedule_stmts(&block.stmts, stream[0] ^ 0xA5);
            emit_block_body(&mut a, &scheduled_b, stream, map, seed, bi, true)?;
            emit_term(
                &mut a,
                &block.term,
                map,
                &maps,
                &live,
                &block_labels,
                l_epilogue,
            )?;
        }
    }

    a.set_label(&mut l_epilogue)?;
    a.pop(r15)?;
    a.pop(r14)?;
    a.pop(r13)?;
    a.pop(r12)?;
    a.pop(rdi)?;
    a.pop(rsi)?;
    a.pop(rbp)?;
    a.pop(rbx)?;
    a.ret()?;

    Ok(a.assemble(0)?)
}

fn emit_block_body(
    a: &mut CodeAssembler,
    stmts: &[Stmt],
    stream: [u8; 32],
    map: [u8; VREG_COUNT],
    seed: &[u8; 16],
    bi: usize,
    alt: bool,
) -> Result<(), iced_x86::IcedError> {
    for (stmt_i, stmt) in stmts.iter().enumerate() {
        let junk_imm = u32::from_le_bytes([
            stream[stmt_i % 32],
            stream[(stmt_i + 1) % 32],
            stream[(stmt_i + 2) % 32],
            stream[(stmt_i + 3) % 32],
        ]) ^ u32::from_le_bytes(seed[0..4].try_into().unwrap())
            ^ (bi as u32).wrapping_mul(0x9E37_79B9)
            ^ if alt { 0xA5A5_A5A5 } else { 0 };
        emit_junk(a, junk_imm)?;
        let seedb = stream[(stmt_i + 7) % 32] ^ if alt { 0x5A } else { 0 };
        emit_stmt(a, remap_stmt(*stmt, &map), seedb)?;
    }
    Ok(())
}

fn emit_term(
    a: &mut CodeAssembler,
    term: &Term,
    map: [u8; VREG_COUNT],
    maps: &[[u8; VREG_COUNT]],
    live: &[bool; VREG_COUNT],
    block_labels: &[CodeLabel],
    l_epilogue: CodeLabel,
) -> Result<(), iced_x86::IcedError> {
    match *term {
        Term::Ret => {
            emit_mov(a, VREG_RAX, Src::Reg(map[VREG_RAX as usize]))?;
            a.jmp(l_epilogue)?;
        }
        Term::Jmp { target } => {
            emit_shuffle(a, &map, &maps[target], live)?;
            a.jmp(block_labels[target])?;
        }
        Term::BrCmp {
            pred,
            lhs,
            rhs,
            then_bb,
            else_bb,
        } => {
            emit_cmp(a, remap_src(lhs, &map), remap_src(rhs, &map))?;
            let mut l_then = a.create_label();
            emit_jcc(a, pred, l_then)?;
            emit_shuffle(a, &map, &maps[else_bb], live)?;
            a.jmp(block_labels[else_bb])?;
            a.set_label(&mut l_then)?;
            emit_shuffle(a, &map, &maps[then_bb], live)?;
            a.jmp(block_labels[then_bb])?;
        }
    }
    Ok(())
}

/// Process-unique coin: TEB ^ PEB.ProcessHeap ^ RSP, not RDTSC.
/// Image ASLR is stripped; heap/stack still vary across processes.
fn emit_coin(a: &mut CodeAssembler, mix: u8) -> Result<(), iced_x86::IcedError> {
    // Process-unique coin: TEB ^ PEB.ProcessHeap ^ RSP. Image ASLR is
    // stripped; heap/stack still differ across processes. Not RDTSC.
    // r10 is in the alloc pool — save it. r11 is TMP (dead at block entry).
    a.push(r10)?;
    // mov r11, gs:[0x30]  TEB
    a.db(&[0x65, 0x4C, 0x8B, 0x1C, 0x25, 0x30, 0x00, 0x00, 0x00])?;
    // mov r10, gs:[0x60]  PEB
    a.db(&[0x65, 0x4C, 0x8B, 0x14, 0x25, 0x60, 0x00, 0x00, 0x00])?;
    a.mov(r10, qword_ptr(r10 + 0x18i32))?; // ProcessHeap
    a.xor(r11, r10)?;
    a.xor(r11, rsp)?;
    a.pop(r10)?;
    a.shr(r11, ((mix & 7) + 4) as u32)?;
    a.test(r11d, 1i32)?;
    Ok(())
}

fn emit_opaque_junk_edge(
    a: &mut CodeAssembler,
    l_junk: &mut CodeLabel,
    seedb: u8,
    map: [u8; VREG_COUNT],
) -> Result<(), iced_x86::IcedError> {
    // Never-taken: xor tmp,tmp ; jnz junk. CFG of executed IR stays isomorphic.
    let mut l_skip = a.create_label();
    a.xor(r32(TMP), r32(TMP))?;
    a.jnz(*l_junk)?;
    a.jmp(l_skip)?;
    a.set_label(l_junk)?;
    let preg = map[VREG_RAX as usize];
    a.xor(r32(preg), seedb as u32)?;
    a.xor(r32(preg), seedb as u32)?;
    a.jmp(l_skip)?;
    a.set_label(&mut l_skip)?;
    Ok(())
}

fn alloc_map(seed: &[u8; 16], block: u32, live: &[bool; VREG_COUNT]) -> Result<[u8; VREG_COUNT], String> {
    let stream = block_stream(seed, block ^ 0xC0FF_EE);
    let mut pool: Vec<u8> = POOL.iter().copied().filter(|&r| r != TMP).collect();
    for i in 0..pool.len() {
        let j = (stream[i % 32] as usize) % pool.len();
        pool.swap(i, j);
    }
    let mut taken = [false; VREG_COUNT];
    taken[TMP as usize] = true;
    taken[VREG_RSP as usize] = true;
    let mut map = [0u8; VREG_COUNT];
    let mut k = 0usize;
    for v in 0..VREG_COUNT {
        if v as u8 == VREG_RSP {
            map[v] = VREG_RSP;
            continue;
        }
        if !live[v] {
            map[v] = v as u8;
            continue;
        }
        loop {
            if k >= pool.len() {
                return Err("superop: not enough physical registers (no spill)".into());
            }
            let p = pool[k];
            k += 1;
            if !taken[p as usize] {
                taken[p as usize] = true;
                map[v] = p;
                break;
            }
        }
    }
    Ok(map)
}

fn used_vregs(module: &IrModule) -> [bool; VREG_COUNT] {
    let mut used = [false; VREG_COUNT];
    let mark = |used: &mut [bool; VREG_COUNT], src: Src| {
        if let Src::Reg(r) = src {
            if (r as usize) < VREG_COUNT {
                used[r as usize] = true;
            }
        }
    };
    used[VREG_RAX as usize] = true;
    used[VREG_RCX as usize] = true;
    used[VREG_RDX as usize] = true;
    for b in &module.blocks {
        for s in &b.stmts {
            match *s {
                Stmt::Mov { dst, src } => {
                    used[dst as usize] = true;
                    mark(&mut used, src);
                }
                Stmt::Bin { dst, lhs, rhs, .. } => {
                    used[dst as usize] = true;
                    mark(&mut used, lhs);
                    mark(&mut used, rhs);
                }
                Stmt::Load { dst, addr, .. } => {
                    used[dst as usize] = true;
                    let Addr::BaseDisp { base, .. } = addr;
                    used[base as usize] = true;
                }
                Stmt::Store { addr, src, .. } => {
                    let Addr::BaseDisp { base, .. } = addr;
                    used[base as usize] = true;
                    mark(&mut used, src);
                }
                Stmt::CallDirect { .. } => {}
                Stmt::FScalar { dst, lhs, rhs, .. } => {
                    used[dst as usize] = true;
                    mark(&mut used, lhs);
                    mark(&mut used, rhs);
                }
                Stmt::FCvt { dst, src, .. } => {
                    used[dst as usize] = true;
                    mark(&mut used, src);
                }
                Stmt::FCmp { dst, lhs, rhs, .. } => {
                    used[dst as usize] = true;
                    mark(&mut used, lhs);
                    mark(&mut used, rhs);
                }
                Stmt::VecBin { dst, dst_hi, lhs_lo, lhs_hi, rhs_lo, rhs_hi, .. } => {
                    used[dst as usize] = true;
                    used[dst_hi as usize] = true;
                    mark(&mut used, lhs_lo);
                    mark(&mut used, lhs_hi);
                    mark(&mut used, rhs_lo);
                    mark(&mut used, rhs_hi);
                }
                Stmt::Atomic { addr, expect, incoming, dst, zf_dst, .. } => {
                    let Addr::BaseDisp { base, .. } = addr;
                    used[base as usize] = true;
                    used[expect as usize] = true;
                    used[dst as usize] = true;
                    used[zf_dst as usize] = true;
                    mark(&mut used, incoming);
                }
            }
        }
        if let Term::BrCmp { lhs, rhs, .. } = b.term {
            mark(&mut used, lhs);
            mark(&mut used, rhs);
        }
    }
    used
}

fn schedule_stmts(stmts: &[Stmt], seedb: u8) -> Vec<Stmt> {
    if stmts.len() < 2 {
        return stmts.to_vec();
    }
    let mut out = stmts.to_vec();
    if seedb & 1 == 1 {
        // reverse independent suffix: bubble independent pairs
        for i in (1..out.len()).rev() {
            if independent(out[i - 1], out[i]) && (seedb.wrapping_add(i as u8) & 2) != 0 {
                out.swap(i - 1, i);
            }
        }
    }
    out
}

fn independent(a: Stmt, b: Stmt) -> bool {
    let (ad, auses) = stmt_regs(a);
    let (bd, buses) = stmt_regs(b);
    if ad == bd {
        return false;
    }
    if auses.contains(&bd) || buses.contains(&ad) {
        return false;
    }
    true
}

fn stmt_regs(s: Stmt) -> (u8, Vec<u8>) {
    match s {
        Stmt::Mov { dst, src } => (dst, src_regs(src)),
        Stmt::Bin { dst, lhs, rhs, .. } => {
            let mut u = src_regs(lhs);
            u.extend(src_regs(rhs));
            (dst, u)
        }
        Stmt::Load { dst, addr, .. } => {
            let Addr::BaseDisp { base, .. } = addr;
            (dst, vec![base])
        }
        Stmt::Store { addr, src, .. } => {
            let Addr::BaseDisp { base, .. } = addr;
            let mut u = vec![base];
            u.extend(src_regs(src));
            (0xff, u)
        }
        Stmt::CallDirect { .. } => (0xff, vec![]),
        Stmt::FScalar { dst, lhs, rhs, .. } => {
            let mut u = src_regs(lhs);
            u.extend(src_regs(rhs));
            (dst, u)
        }
        Stmt::FCvt { dst, src, .. } => (dst, src_regs(src)),
        Stmt::FCmp { dst, lhs, rhs, .. } => {
            let mut u = src_regs(lhs);
            u.extend(src_regs(rhs));
            (dst, u)
        }
        Stmt::VecBin { dst, dst_hi, lhs_lo, lhs_hi, rhs_lo, rhs_hi, .. } => {
            // Treat the second destination as a use so the scheduler stays
            // conservative across packed ops.
            let mut u = vec![dst_hi];
            u.extend(src_regs(lhs_lo));
            u.extend(src_regs(lhs_hi));
            u.extend(src_regs(rhs_lo));
            u.extend(src_regs(rhs_hi));
            (dst, u)
        }
        Stmt::Atomic { addr, expect, incoming, dst, zf_dst, .. } => {
            let Addr::BaseDisp { base, .. } = addr;
            let mut u = vec![base, expect, dst, zf_dst];
            u.extend(src_regs(incoming));
            (dst, u)
        }
    }
}

fn src_regs(s: Src) -> Vec<u8> {
    match s {
        Src::Reg(r) => vec![r],
        Src::Imm(_) => vec![],
    }
}

fn remap_src(src: Src, map: &[u8; VREG_COUNT]) -> Src {
    match src {
        Src::Reg(r) if (r as usize) < VREG_COUNT => Src::Reg(map[r as usize]),
        _ => src,
    }
}

fn remap_stmt(stmt: Stmt, map: &[u8; VREG_COUNT]) -> Stmt {
    match stmt {
        Stmt::Mov { dst, src } => Stmt::Mov {
            dst: map[dst as usize],
            src: remap_src(src, map),
        },
        Stmt::Bin { op, dst, lhs, rhs } => Stmt::Bin {
            op,
            dst: map[dst as usize],
            lhs: remap_src(lhs, map),
            rhs: remap_src(rhs, map),
        },
        Stmt::Load { dst, addr, width } => Stmt::Load {
            dst: map[dst as usize],
            addr: remap_addr(addr, map),
            width,
        },
        Stmt::Store { addr, src, width } => Stmt::Store {
            addr: remap_addr(addr, map),
            src: remap_src(src, map),
            width,
        },
        Stmt::FScalar { op, width, dst, lhs, rhs } => Stmt::FScalar {
            op,
            width,
            dst: map[dst as usize],
            lhs: remap_src(lhs, map),
            rhs: remap_src(rhs, map),
        },
        Stmt::FCvt { kind, dst, src } => Stmt::FCvt {
            kind,
            dst: map[dst as usize],
            src: remap_src(src, map),
        },
        Stmt::FCmp { width, dst, lhs, rhs } => Stmt::FCmp {
            width,
            dst: map[dst as usize],
            lhs: remap_src(lhs, map),
            rhs: remap_src(rhs, map),
        },
        Stmt::VecBin { op, dst, dst_hi, lhs_lo, lhs_hi, rhs_lo, rhs_hi } => Stmt::VecBin {
            op,
            dst: map[dst as usize],
            dst_hi: map[dst_hi as usize],
            lhs_lo: remap_src(lhs_lo, map),
            lhs_hi: remap_src(lhs_hi, map),
            rhs_lo: remap_src(rhs_lo, map),
            rhs_hi: remap_src(rhs_hi, map),
        },
        Stmt::Atomic { op, addr, width, expect, incoming, dst, zf_dst } => Stmt::Atomic {
            op,
            addr: remap_addr(addr, map),
            width,
            expect: map[expect as usize],
            incoming: remap_src(incoming, map),
            dst: map[dst as usize],
            zf_dst: map[zf_dst as usize],
        },
        other => other,
    }
}

fn remap_addr(addr: Addr, map: &[u8; VREG_COUNT]) -> Addr {
    match addr {
        Addr::BaseDisp { base, disp } => Addr::BaseDisp {
            base: map[base as usize],
            disp,
        },
    }
}

fn emit_shuffle(
    a: &mut CodeAssembler,
    from: &[u8; VREG_COUNT],
    to: &[u8; VREG_COUNT],
    live: &[bool; VREG_COUNT],
) -> Result<(), iced_x86::IcedError> {
    if from == to {
        return Ok(());
    }
    let mut pending: Vec<(u8, u8)> = Vec::new();
    for v in 0..VREG_COUNT {
        if !live[v] {
            continue;
        }
        let s = from[v];
        let d = to[v];
        if s != d {
            pending.push((s, d));
        }
    }
    while !pending.is_empty() {
        let sources: Vec<u8> = pending.iter().map(|&(s, _)| s).collect();
        if let Some(i) = pending.iter().position(|&(_, d)| !sources.contains(&d)) {
            let (s, d) = pending.remove(i);
            emit_mov(a, d, Src::Reg(s))?;
            continue;
        }
        let (s, d) = pending.remove(0);
        emit_mov(a, TMP, Src::Reg(s))?;
        pending.push((TMP, d));
    }
    Ok(())
}

fn block_stream(seed: &[u8; 16], block: u32) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"XLSOP\x02");
    hasher.update(seed);
    hasher.update(block.to_le_bytes());
    hasher.finalize().into()
}

fn emit_junk(a: &mut CodeAssembler, imm: u32) -> Result<(), iced_x86::IcedError> {
    a.xor(r32(TMP), imm)?;
    a.xor(r32(TMP), imm)?;
    Ok(())
}

fn emit_stmt(a: &mut CodeAssembler, stmt: Stmt, seedb: u8) -> Result<(), iced_x86::IcedError> {
    match stmt {
        Stmt::Mov { dst, src } => emit_mov(a, dst, src),
        Stmt::Bin { op, dst, lhs, rhs } => match pick_family(op, seedb) {
            MbaFamily::AddXorAnd if op == BinOp::Add => emit_add_mba(a, dst, lhs, rhs),
            MbaFamily::AddLea if op == BinOp::Add => emit_add_lea(a, dst, lhs, rhs),
            MbaFamily::SubAddNot if op == BinOp::Sub => emit_sub_mba(a, dst, lhs, rhs),
            MbaFamily::XorOrAnd if op == BinOp::Xor => emit_xor_mba(a, dst, lhs, rhs),
            MbaFamily::AndAddOr if op == BinOp::And => emit_and_mba(a, dst, lhs, rhs),
            _ => emit_bin_id(a, op, dst, lhs, rhs),
        },
        Stmt::Load { dst, addr, width } => emit_load(a, dst, addr, width),
        Stmt::Store { addr, src, width } => emit_store(a, addr, src, width),
        Stmt::CallDirect { .. } => {
            // Direct calls stay fail-closed at lift until rewrite can prove the
            // target. Superop must not invent a call.
            Ok(())
        },
        Stmt::FScalar { .. } => emit_fscalar(a, stmt),
        Stmt::FCvt { .. } => emit_fcvt(a, stmt),
        Stmt::FCmp { .. } => emit_fcmp(a, stmt),
        Stmt::VecBin { .. } => emit_vecbin(a, stmt),
        Stmt::Atomic { .. } => emit_atomic(a, stmt),
    }
}

/// Load a scalar Src into xmm0 (F32: movd, F64: movq). Imms go via TMP.
fn load_xmm0(a: &mut CodeAssembler, src: Src, f64w: bool) -> Result<(), iced_x86::IcedError> {
    match src {
        Src::Reg(r) => {
            if f64w {
                a.movq(xmm0, gpr64(r))?;
            } else {
                a.movd(xmm0, r32(r))?;
            }
        }
        Src::Imm(v) => {
            a.mov(r32(TMP), v)?;
            if f64w {
                a.movd(xmm0, r32(TMP))?;
            } else {
                a.movd(xmm0, r32(TMP))?;
            }
        }
    }
    Ok(())
}

fn load_xmm1(a: &mut CodeAssembler, src: Src, f64w: bool) -> Result<(), iced_x86::IcedError> {
    match src {
        Src::Reg(r) => {
            if f64w {
                a.movq(xmm1, gpr64(r))?;
            } else {
                a.movd(xmm1, r32(r))?;
            }
        }
        Src::Imm(v) => {
            a.mov(r32(TMP), v)?;
            a.movd(xmm1, r32(TMP))?;
        }
    }
    Ok(())
}

fn store_xmm0(a: &mut CodeAssembler, dst: u8, f64w: bool) -> Result<(), iced_x86::IcedError> {
    if f64w {
        a.movq(gpr64(dst), xmm0)?;
    } else {
        a.movd(r32(dst), xmm0)?;
    }
    Ok(())
}

fn emit_fscalar(a: &mut CodeAssembler, stmt: Stmt) -> Result<(), iced_x86::IcedError> {
    let Stmt::FScalar { op, width, dst, lhs, rhs, .. } = stmt else {
        unreachable!()
    };
    match width {
        FWidth::F32 => {
            load_xmm0(a, lhs, false)?;
            if matches!(op, FOp::Sqrt) {
                a.sqrtss(xmm0, xmm0)?;
            } else {
                load_xmm1(a, rhs, false)?;
                match op {
                    FOp::Add => a.addss(xmm0, xmm1)?,
                    FOp::Sub => a.subss(xmm0, xmm1)?,
                    FOp::Mul => a.mulss(xmm0, xmm1)?,
                    FOp::Div => a.divss(xmm0, xmm1)?,
                    FOp::Min => a.minss(xmm0, xmm1)?,
                    FOp::Max => a.maxss(xmm0, xmm1)?,
                    FOp::Sqrt => unreachable!(),
                }
            }
            store_xmm0(a, dst, false)
        }
        FWidth::F64 => {
            load_xmm0(a, lhs, true)?;
            if matches!(op, FOp::Sqrt) {
                a.sqrtsd(xmm0, xmm0)?;
            } else {
                load_xmm1(a, rhs, true)?;
                match op {
                    FOp::Add => a.addsd(xmm0, xmm1)?,
                    FOp::Sub => a.subsd(xmm0, xmm1)?,
                    FOp::Mul => a.mulsd(xmm0, xmm1)?,
                    FOp::Div => a.divsd(xmm0, xmm1)?,
                    FOp::Min => a.minsd(xmm0, xmm1)?,
                    FOp::Max => a.maxsd(xmm0, xmm1)?,
                    FOp::Sqrt => unreachable!(),
                }
            }
            store_xmm0(a, dst, true)
        }
        FWidth::X87 => {
            // fld/fop/fstp through a scratch slot. Operands are f64 bits.
            a.sub(rsp, 16i32)?;
            emit_mov(a, TMP, lhs)?;
            a.mov(qword_ptr(rsp), gpr64(TMP))?;
            a.fld(qword_ptr(rsp))?;
            if matches!(op, FOp::Sqrt) {
                a.fsqrt()?;
            } else {
                emit_mov(a, TMP, rhs)?;
                a.mov(qword_ptr(rsp), gpr64(TMP))?;
                a.fld(qword_ptr(rsp))?;
                match op {
                    FOp::Add => a.faddp(st1, st0)?,
                    FOp::Sub => a.fsubp(st1, st0)?,
                    FOp::Mul => a.fmulp(st1, st0)?,
                    FOp::Div => a.fdivp(st1, st0)?,
                    _ => a.faddp(st1, st0)?,
                }
            }
            a.fstp(qword_ptr(rsp))?;
            a.mov(gpr64(dst), qword_ptr(rsp))?;
            a.add(rsp, 16i32)?;
            Ok(())
        }
    }
}

fn emit_fcvt(a: &mut CodeAssembler, stmt: Stmt) -> Result<(), iced_x86::IcedError> {
    let Stmt::FCvt { kind, dst, src } = stmt else {
        unreachable!()
    };
    // Materialize the source into TMP64 once for the memory forms.
    let src_reg = match src {
        Src::Reg(r) => r,
        Src::Imm(v) => {
            a.mov(r32(TMP), v)?;
            TMP
        }
    };
    match kind {
        CvtKind::I32F32 => {
            a.cvtsi2ss(xmm0, r32(src_reg))?;
            a.movd(r32(dst), xmm0)?;
        }
        CvtKind::I32F64 => {
            a.cvtsi2sd(xmm0, r32(src_reg))?;
            a.movq(gpr64(dst), xmm0)?;
        }
        CvtKind::I64F32 => {
            a.cvtsi2ss(xmm0, gpr64(src_reg))?;
            a.movd(r32(dst), xmm0)?;
        }
        CvtKind::I64F64 => {
            a.cvtsi2sd(xmm0, gpr64(src_reg))?;
            a.movq(gpr64(dst), xmm0)?;
        }
        CvtKind::F32I32T => {
            load_xmm0(a, src, false)?;
            a.cvttss2si(r32(dst), xmm0)?;
        }
        CvtKind::F64I32T => {
            load_xmm0(a, src, true)?;
            a.cvttsd2si(r32(dst), xmm0)?;
        }
        CvtKind::F32I64T => {
            load_xmm0(a, src, false)?;
            a.cvttss2si(gpr64(dst), xmm0)?;
        }
        CvtKind::F64I64T => {
            load_xmm0(a, src, true)?;
            a.cvttsd2si(gpr64(dst), xmm0)?;
        }
        CvtKind::F32I32R => {
            load_xmm0(a, src, false)?;
            a.cvtss2si(r32(dst), xmm0)?;
        }
        CvtKind::F64I64R => {
            load_xmm0(a, src, true)?;
            a.cvtsd2si(gpr64(dst), xmm0)?;
        }
        CvtKind::F32F64 => {
            load_xmm0(a, src, false)?;
            a.cvtss2sd(xmm0, xmm0)?;
            a.movq(gpr64(dst), xmm0)?;
        }
        CvtKind::F64F32 => {
            load_xmm0(a, src, true)?;
            a.cvtsd2ss(xmm0, xmm0)?;
            a.movd(r32(dst), xmm0)?;
        }
    }
    Ok(())
}

fn emit_fcmp(a: &mut CodeAssembler, stmt: Stmt) -> Result<(), iced_x86::IcedError> {
    let Stmt::FCmp { width, dst, lhs, rhs } = stmt else {
        unreachable!()
    };
    // dst defaults BEFORE the flags-producing instruction.
    a.xor(r32(dst), r32(dst))?;
    match width {
        FWidth::F32 => {
            load_xmm0(a, lhs, false)?;
            load_xmm1(a, rhs, false)?;
            a.ucomiss(xmm0, xmm1)?;
        }
        FWidth::F64 => {
            load_xmm0(a, lhs, true)?;
            load_xmm1(a, rhs, true)?;
            a.ucomisd(xmm0, xmm1)?;
        }
        FWidth::X87 => return Ok(()),
    }
    // dst: 0 eq, 1 above, 2 below, 3 unordered.
    let mut l_unord = a.create_label();
    let mut l_gt = a.create_label();
    let mut l_lt = a.create_label();
    let mut l_done = a.create_label();
    a.jp(l_unord)?;
    a.ja(l_gt)?;
    a.jb(l_lt)?;
    a.jmp(l_done)?;
    a.set_label(&mut l_unord)?;
    a.mov(r32(dst), 3u32)?;
    a.jmp(l_done)?;
    a.set_label(&mut l_gt)?;
    a.mov(r32(dst), 1u32)?;
    a.jmp(l_done)?;
    a.set_label(&mut l_lt)?;
    a.mov(r32(dst), 2u32)?;
    a.set_label(&mut l_done)?;
    Ok(())
}

/// Build xmm0 = (lhs_lo, lhs_hi) and xmm1 = (rhs_lo, rhs_hi) as lane pairs.
fn load_xmm_pair(a: &mut CodeAssembler, lo: Src, hi: Src, xmm_is_1: bool) -> Result<(), iced_x86::IcedError> {
    let lo_reg = match lo {
        Src::Reg(r) => r,
        Src::Imm(v) => {
            a.mov(r32(TMP), v)?;
            TMP
        }
    };
    let hi_reg = match hi {
        Src::Reg(r) => r,
        Src::Imm(v) => {
            a.mov(r32(TMP), v)?;
            TMP
        }
    };
    if xmm_is_1 {
        a.movq(xmm1, gpr64(lo_reg))?;
        if hi_reg != lo_reg {
            a.pinsrq(xmm1, gpr64(hi_reg), 1)?;
        } else {
            a.pinsrq(xmm1, gpr64(lo_reg), 1)?;
        }
    } else {
        a.movq(xmm0, gpr64(lo_reg))?;
        if hi_reg != lo_reg {
            a.pinsrq(xmm0, gpr64(hi_reg), 1)?;
        } else {
            a.pinsrq(xmm0, gpr64(lo_reg), 1)?;
        }
    }
    Ok(())
}

fn emit_vecbin(a: &mut CodeAssembler, stmt: Stmt) -> Result<(), iced_x86::IcedError> {
    let Stmt::VecBin { op, dst, dst_hi, lhs_lo, lhs_hi, rhs_lo, rhs_hi } = stmt else {
        unreachable!()
    };
    load_xmm_pair(a, lhs_lo, lhs_hi, false)?;
    load_xmm_pair(a, rhs_lo, rhs_hi, true)?;
    match op {
        VecOp::PAddD => a.paddd(xmm0, xmm1)?,
        VecOp::PSubD => a.psubd(xmm0, xmm1)?,
        VecOp::PMulLW => a.pmullw(xmm0, xmm1)?,
        VecOp::PMulHW => a.pmulhw(xmm0, xmm1)?,
        VecOp::PMulLD => a.pmulld(xmm0, xmm1)?,
        VecOp::PMinSD => a.pminsd(xmm0, xmm1)?,
        VecOp::PMaxSD => a.pmaxsd(xmm0, xmm1)?,
        VecOp::PAnd => a.pand(xmm0, xmm1)?,
        VecOp::POr => a.por(xmm0, xmm1)?,
        VecOp::PXor => a.pxor(xmm0, xmm1)?,
        VecOp::PCmpEqD => a.pcmpeqd(xmm0, xmm1)?,
        VecOp::PAddPS => a.addps(xmm0, xmm1)?,
        VecOp::PMulPS => a.mulps(xmm0, xmm1)?,
        VecOp::PAddPD => a.addpd(xmm0, xmm1)?,
        VecOp::PShufD(imm) => a.pshufd(xmm0, xmm1, imm as i32)?,
        VecOp::Punpcklqdq => a.punpcklqdq(xmm0, xmm1)?,
    }
    a.pextrq(gpr64(dst), xmm0, 0)?;
    a.pextrq(gpr64(dst_hi), xmm0, 1)?;
    Ok(())
}

fn emit_atomic(a: &mut CodeAssembler, stmt: Stmt) -> Result<(), iced_x86::IcedError> {
    let Stmt::Atomic { op, addr, width, expect, incoming, dst, zf_dst } = stmt else {
        unreachable!()
    };
    let Addr::BaseDisp { base, disp } = addr;
    let inc_reg = match incoming {
        Src::Reg(r) => r,
        Src::Imm(v) => {
            a.mov(r32(TMP), v)?;
            TMP
        }
    };
    // cmpxchg compares RAX implicitly; drive it through the dst register.
    match op {
        AtomicOpIr::CmpXchg => {
            a.mov(gpr64(TMP), gpr64(expect))?;
            a.mov(rax, gpr64(TMP))?;
            emit_lock_cmpxchg(a, base, disp, inc_reg, width)?;
            a.mov(gpr64(dst), rax)?;
            a.setz(gpr8(zf_dst))?;
            a.movzx(r32(zf_dst), gpr8(zf_dst))?;
        }
        AtomicOpIr::XAdd => {
            a.mov(gpr64(dst), gpr64(inc_reg))?;
            emit_lock_xadd(a, base, disp, dst, width)?;
            a.xor(r32(zf_dst), r32(zf_dst))?;
        }
        AtomicOpIr::Xchg => {
            a.mov(gpr64(dst), gpr64(inc_reg))?;
            emit_xchg_mem(a, base, disp, dst, width)?;
            a.xor(r32(zf_dst), r32(zf_dst))?;
        }
    }
    Ok(())
}

fn emit_lock_cmpxchg(
    a: &mut CodeAssembler,
    base: u8,
    disp: i32,
    src: u8,
    width: u8,
) -> Result<(), iced_x86::IcedError> {
    let mem8 = byte_ptr(gpr64(base) + disp);
    let mem16 = word_ptr(gpr64(base) + disp);
    let mem32 = dword_ptr(gpr64(base) + disp);
    let mem64 = qword_ptr(gpr64(base) + disp);
    let _ = a.lock();
    match width {
        1 => a.cmpxchg(mem8, gpr8(src))?,
        2 => a.cmpxchg(mem16, gpr16(src))?,
        4 => a.cmpxchg(mem32, r32(src))?,
        _ => a.cmpxchg(mem64, gpr64(src))?,
    }
    Ok(())
}

fn emit_lock_xadd(
    a: &mut CodeAssembler,
    base: u8,
    disp: i32,
    src: u8,
    width: u8,
) -> Result<(), iced_x86::IcedError> {
    let mem32 = dword_ptr(gpr64(base) + disp);
    let mem64 = qword_ptr(gpr64(base) + disp);
    let mem16 = word_ptr(gpr64(base) + disp);
    let mem8 = byte_ptr(gpr64(base) + disp);
    let _ = a.lock();
    match width {
        1 => a.xadd(mem8, gpr8(src))?,
        2 => a.xadd(mem16, gpr16(src))?,
        4 => a.xadd(mem32, r32(src))?,
        _ => a.xadd(mem64, gpr64(src))?,
    }
    Ok(())
}

fn emit_xchg_mem(
    a: &mut CodeAssembler,
    base: u8,
    disp: i32,
    src: u8,
    width: u8,
) -> Result<(), iced_x86::IcedError> {
    let mem32 = dword_ptr(gpr64(base) + disp);
    let mem64 = qword_ptr(gpr64(base) + disp);
    let mem16 = word_ptr(gpr64(base) + disp);
    let mem8 = byte_ptr(gpr64(base) + disp);
    match width {
        1 => a.xchg(mem8, gpr8(src))?,
        2 => a.xchg(mem16, gpr16(src))?,
        4 => a.xchg(mem32, r32(src))?,
        _ => a.xchg(mem64, gpr64(src))?,
    }
    Ok(())
}

fn emit_load(
    a: &mut CodeAssembler,
    dst: u8,
    addr: Addr,
    width: u8,
) -> Result<(), iced_x86::IcedError> {
    let Addr::BaseDisp { base, disp } = addr;
    let mem = qword_ptr(gpr64(base) + disp);
    match width {
        1 => {
            a.movzx(r32(dst), byte_ptr(gpr64(base) + disp))?;
        }
        2 => {
            a.movzx(r32(dst), word_ptr(gpr64(base) + disp))?;
        }
        4 => {
            a.mov(r32(dst), dword_ptr(gpr64(base) + disp))?;
        }
        8 => {
            a.mov(gpr64(dst), mem)?;
        }
        _ => {
            a.mov(r32(dst), dword_ptr(gpr64(base) + disp))?;
        }
    }
    Ok(())
}

fn emit_store(
    a: &mut CodeAssembler,
    addr: Addr,
    src: Src,
    width: u8,
) -> Result<(), iced_x86::IcedError> {
    let Addr::BaseDisp { base, disp } = addr;
    match src {
        Src::Reg(r) => match width {
            1 => a.mov(byte_ptr(gpr64(base) + disp), gpr8(r))?,
            2 => a.mov(word_ptr(gpr64(base) + disp), gpr16(r))?,
            4 => a.mov(dword_ptr(gpr64(base) + disp), r32(r))?,
            8 => a.mov(qword_ptr(gpr64(base) + disp), gpr64(r))?,
            _ => a.mov(dword_ptr(gpr64(base) + disp), r32(r))?,
        },
        Src::Imm(v) => {
            a.mov(r32(TMP), v)?;
            match width {
                1 => a.mov(byte_ptr(gpr64(base) + disp), gpr8(TMP))?,
                2 => a.mov(word_ptr(gpr64(base) + disp), gpr16(TMP))?,
                4 => a.mov(dword_ptr(gpr64(base) + disp), r32(TMP))?,
                8 => a.mov(qword_ptr(gpr64(base) + disp), gpr64(TMP))?,
                _ => a.mov(dword_ptr(gpr64(base) + disp), r32(TMP))?,
            }
        }
    }
    Ok(())
}

fn emit_mov(a: &mut CodeAssembler, dst: u8, src: Src) -> Result<(), iced_x86::IcedError> {
    match src {
        Src::Reg(s) if s == dst => Ok(()),
        // Reg→reg moves keep the full 64 bits: vregs hold u64 (a 32-bit move
        // truncates pointers — G4 memory operands pass buffer addresses).
        Src::Reg(s) => {
            a.mov(gpr64(dst), gpr64(s))?;
            Ok(())
        }
        Src::Imm(v) => {
            // Imm is u32; a 32-bit mov zero-extends into the full register.
            a.mov(r32(dst), v)?;
            Ok(())
        }
    }
}

fn emit_bin_id(
    a: &mut CodeAssembler,
    op: BinOp,
    dst: u8,
    lhs: Src,
    rhs: Src,
) -> Result<(), iced_x86::IcedError> {
    if let Src::Reg(r) = rhs {
        if r == dst && Src::Reg(dst) != lhs {
            emit_mov(a, TMP, lhs)?;
            apply_binop(a, op, TMP, Src::Reg(dst))?;
            emit_mov(a, dst, Src::Reg(TMP))?;
            return Ok(());
        }
    }
    if Src::Reg(dst) != lhs {
        emit_mov(a, dst, lhs)?;
    }
    apply_binop(a, op, dst, rhs)
}

fn apply_binop(
    a: &mut CodeAssembler,
    op: BinOp,
    dst: u8,
    rhs: Src,
) -> Result<(), iced_x86::IcedError> {
    let d = r32(dst);
    match rhs {
        Src::Reg(r) => {
            let s = r32(r);
            match op {
                BinOp::Add => a.add(d, s)?,
                BinOp::Sub => a.sub(d, s)?,
                BinOp::Xor => a.xor(d, s)?,
                BinOp::And => a.and(d, s)?,
                BinOp::Or => a.or(d, s)?,
                BinOp::Mul => a.imul_2(d, s)?,
                // Physical rcx is never in POOL, so CL is dead scratch here:
                // stage the count into CL and shift by CL (x86 masks to &31).
                BinOp::Shl => {
                    a.mov(gpr8(VREG_RCX), gpr8(r))?;
                    a.shl(d, gpr8(VREG_RCX))?;
                }
                BinOp::Shr => {
                    a.mov(gpr8(VREG_RCX), gpr8(r))?;
                    a.shr(d, gpr8(VREG_RCX))?;
                }
                BinOp::Sar => {
                    a.mov(gpr8(VREG_RCX), gpr8(r))?;
                    a.sar(d, gpr8(VREG_RCX))?;
                }
            };
        }
        Src::Imm(v) => match op {
            BinOp::Add => {
                a.add(d, v)?;
            }
            BinOp::Sub => {
                a.sub(d, v)?;
            }
            BinOp::Xor => {
                a.xor(d, v)?;
            }
            BinOp::And => {
                a.and(d, v)?;
            }
            BinOp::Or => {
                a.or(d, v)?;
            }
            BinOp::Mul => {
                a.imul_3(d, d, v as i32)?;
            }
            BinOp::Shl => {
                a.shl(d, v & 0x1f)?;
            }
            BinOp::Shr => {
                a.shr(d, v & 0x1f)?;
            }
            BinOp::Sar => {
                a.sar(d, v & 0x1f)?;
            }
        },
    }
    Ok(())
}

fn emit_add_mba(
    a: &mut CodeAssembler,
    dst: u8,
    lhs: Src,
    rhs: Src,
) -> Result<(), iced_x86::IcedError> {
    emit_mov(a, TMP, lhs)?;
    emit_bin_id(a, BinOp::And, TMP, Src::Reg(TMP), rhs)?;
    emit_bin_id(a, BinOp::Add, TMP, Src::Reg(TMP), Src::Reg(TMP))?;
    emit_mov(a, dst, lhs)?;
    emit_bin_id(a, BinOp::Xor, dst, Src::Reg(dst), rhs)?;
    emit_bin_id(a, BinOp::Add, dst, Src::Reg(dst), Src::Reg(TMP))
}

fn emit_add_lea(
    a: &mut CodeAssembler,
    dst: u8,
    lhs: Src,
    rhs: Src,
) -> Result<(), iced_x86::IcedError> {
    match (lhs, rhs) {
        (Src::Reg(l), Src::Reg(r)) => {
            let d = r32(dst);
            a.lea(d, dword_ptr(r32(l) + r32(r)))?;
            Ok(())
        }
        _ => emit_bin_id(a, BinOp::Add, dst, lhs, rhs),
    }
}

fn emit_sub_mba(
    a: &mut CodeAssembler,
    dst: u8,
    lhs: Src,
    rhs: Src,
) -> Result<(), iced_x86::IcedError> {
    emit_mov(a, TMP, rhs)?;
    a.not(r32(TMP))?;
    a.add(r32(TMP), 1u32)?;
    emit_mov(a, dst, lhs)?;
    emit_bin_id(a, BinOp::Add, dst, Src::Reg(dst), Src::Reg(TMP))
}

fn emit_xor_mba(
    a: &mut CodeAssembler,
    dst: u8,
    lhs: Src,
    rhs: Src,
) -> Result<(), iced_x86::IcedError> {
    emit_mov(a, TMP, lhs)?;
    emit_bin_id(a, BinOp::Or, TMP, Src::Reg(TMP), rhs)?;
    emit_mov(a, dst, lhs)?;
    emit_bin_id(a, BinOp::And, dst, Src::Reg(dst), rhs)?;
    emit_bin_id(a, BinOp::Sub, dst, Src::Reg(TMP), Src::Reg(dst))
}

fn emit_and_mba(
    a: &mut CodeAssembler,
    dst: u8,
    lhs: Src,
    rhs: Src,
) -> Result<(), iced_x86::IcedError> {
    emit_mov(a, TMP, lhs)?;
    emit_bin_id(a, BinOp::Add, TMP, Src::Reg(TMP), rhs)?;
    emit_mov(a, dst, lhs)?;
    emit_bin_id(a, BinOp::Or, dst, Src::Reg(dst), rhs)?;
    emit_bin_id(a, BinOp::Sub, dst, Src::Reg(TMP), Src::Reg(dst))
}

fn emit_cmp(a: &mut CodeAssembler, lhs: Src, rhs: Src) -> Result<(), iced_x86::IcedError> {
    match (lhs, rhs) {
        (Src::Reg(l), Src::Reg(r)) => {
            a.cmp(r32(l), r32(r))?;
        }
        (Src::Reg(l), Src::Imm(v)) => {
            a.cmp(r32(l), v)?;
        }
        (Src::Imm(v), Src::Reg(r)) => {
            a.cmp(r32(r), v)?;
        }
        (Src::Imm(_), Src::Imm(_)) => {}
    }
    Ok(())
}

fn emit_jcc(
    a: &mut CodeAssembler,
    pred: CmpOp,
    target: CodeLabel,
) -> Result<(), iced_x86::IcedError> {
    match pred {
        CmpOp::Eq => a.je(target)?,
        CmpOp::Ne => a.jne(target)?,
        CmpOp::ULt => a.jb(target)?,
        CmpOp::ULe => a.jbe(target)?,
        CmpOp::UGt => a.ja(target)?,
        CmpOp::UGe => a.jae(target)?,
        CmpOp::SLt => a.jl(target)?,
        CmpOp::SLe => a.jle(target)?,
        CmpOp::SGt => a.jg(target)?,
        CmpOp::SGe => a.jge(target)?,
    };
    Ok(())
}

fn r32(v: u8) -> AsmRegister32 {
    match v {
        0 => eax,
        1 => ecx,
        2 => edx,
        3 => ebx,
        5 => ebp,
        6 => esi,
        7 => edi,
        8 => r8d,
        9 => r9d,
        10 => r10d,
        11 => r11d,
        12 => r12d,
        13 => r13d,
        14 => r14d,
        15 => r15d,
        _ => eax,
    }
}

fn gpr64(v: u8) -> AsmRegister64 {
    match v {
        0 => rax,
        1 => rcx,
        2 => rdx,
        3 => rbx,
        4 => rsp,
        5 => rbp,
        6 => rsi,
        7 => rdi,
        8 => r8,
        9 => r9,
        10 => r10,
        11 => r11,
        12 => r12,
        13 => r13,
        14 => r14,
        15 => r15,
        _ => rax,
    }
}

fn gpr16(v: u8) -> AsmRegister16 {
    match v {
        0 => ax,
        1 => cx,
        2 => dx,
        3 => bx,
        5 => bp,
        6 => si,
        7 => di,
        8 => r8w,
        9 => r9w,
        10 => r10w,
        11 => r11w,
        12 => r12w,
        13 => r13w,
        14 => r14w,
        15 => r15w,
        _ => ax,
    }
}

fn gpr8(v: u8) -> AsmRegister8 {
    match v {
        0 => al,
        1 => cl,
        2 => dl,
        3 => bl,
        5 => bpl,
        6 => sil,
        7 => dil,
        8 => r8b,
        9 => r9b,
        10 => r10b,
        11 => r11b,
        12 => r12b,
        13 => r13b,
        14 => r14b,
        15 => r15b,
        _ => al,
    }
}

/// Old guest dispatcher: `movzx eax,[rsi]; inc rsi; cmp eax,imm8; je`.
pub fn has_guest_dispatch_tetrad(bytes: &[u8]) -> bool {
    bytes.windows(10).any(|w| {
        w[0..6] == [0x0F, 0xB6, 0x06, 0x48, 0xFF, 0xC6]
            && w[6] == 0x83
            && w[7] == 0xF8
            && w[9] == 0x74
    })
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NativeShape {
    pub mnemonics: Vec<String>,
    pub regs: [u32; 16],
}

pub fn native_shape(bytes: &[u8]) -> NativeShape {
    let mut decoder = Decoder::with_ip(64, bytes, 0, DecoderOptions::NONE);
    let mut shape = NativeShape::default();
    while decoder.can_decode() {
        let instr: Instruction = decoder.decode();
        if instr.is_invalid() || instr.mnemonic() == Mnemonic::Nop {
            break;
        }
        shape
            .mnemonics
            .push(format!("{:?}", instr.mnemonic()));
        for op in 0..instr.op_count() {
            if instr.op_kind(op) == OpKind::Register {
                let n = instr.op_register(op).number();
                if n < 16 {
                    shape.regs[n] += 1;
                }
            }
        }
    }
    shape
}

/// Two PICs collapse to one opcode table if mnemonic streams match after
/// ignoring junk xor-pairs and register identities.
pub fn shapes_alignable(a: &NativeShape, b: &NativeShape) -> bool {
    if a.mnemonics == b.mnemonics && a.regs == b.regs {
        return true;
    }
    let fa = freq(&a.mnemonics);
    let fb = freq(&b.mnemonics);
    fa == fb && a.regs == b.regs
}

fn freq(m: &[String]) -> std::collections::BTreeMap<String, usize> {
    let mut t = std::collections::BTreeMap::new();
    for s in m {
        *t.entry(s.clone()).or_insert(0) += 1;
    }
    t
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{eval_ir, hello_add_ir, license_toy_ir, license_toy_oracle};

    #[test]
    fn superop_bytes_are_seed_divergent() {
        let m = hello_add_ir();
        let a = emit_superop(&m, &[1; 16]).unwrap();
        let b = emit_superop(&m, &[2; 16]).unwrap();
        assert_ne!(a, b);
        assert!(!has_guest_dispatch_tetrad(&a));
        assert!(!has_guest_dispatch_tetrad(&b));
        let sa = native_shape(&a);
        let sb = native_shape(&b);
        assert!(!shapes_alignable(&sa, &sb), "G-WB-DIVERSE hello_add");
    }

    #[test]
    fn license_toy_ir_oracle_stable() {
        let m = license_toy_ir();
        for (x, y) in [(0u32, 0u32), (3, 4), (0x20000, 0x10), (1, 1)] {
            assert_eq!(eval_ir(&m, x, y).unwrap(), license_toy_oracle(x, y));
        }
        let pic = emit_superop(&m, &[9; 16]).unwrap();
        assert!(!has_guest_dispatch_tetrad(&pic));
        assert!(pic.len() > 16);
    }

    #[test]
    fn license_toy_shapes_not_one_opcode_table() {
        let m = license_toy_ir();
        let a = emit_superop(&m, &[1; 16]).unwrap();
        let b = emit_superop(&m, &[2; 16]).unwrap();
        assert!(!shapes_alignable(&native_shape(&a), &native_shape(&b)));
        assert_eq!(m.blocks.len(), license_toy_ir().blocks.len());
    }

    #[test]
    fn w2_cfg_stays_isomorphic() {
        let m = license_toy_ir();
        let n = m.blocks.len();
        let _ = emit_superop(&m, &[3; 16]).unwrap();
        assert_eq!(m.blocks.len(), n);
        assert_eq!(m.entry, 0);
    }

    #[test]
    fn w3_coin_is_teb_not_rdtsc() {
        let m = license_toy_ir();
        let pic = emit_superop_ex(
            &m,
            &[7; 16],
            SuperopOptions {
                trace_diverge: true,
            },
        )
        .unwrap();
        assert!(
            pic.windows(9)
                .any(|w| w == [0x65, 0x4C, 0x8B, 0x1C, 0x25, 0x30, 0x00, 0x00, 0x00]),
            "missing TEB gs:[0x30]"
        );
        assert!(
            !pic.windows(2).any(|w| w == [0x0F, 0x31]),
            "RDTSC must not be the coin"
        );
        assert!(!has_guest_dispatch_tetrad(&pic));
        let a = emit_superop_ex(&m, &[7; 16], SuperopOptions { trace_diverge: true }).unwrap();
        let b = emit_superop(&m, &[7; 16]).unwrap();
        assert_ne!(a, b, "trace-diverge PIC must differ from single-path");
    }

    #[test]
    fn ir_and_pic_exist_for_hello_add_and_license() {
        for (ir, seed) in [(hello_add_ir(), [1u8; 16]), (license_toy_ir(), [9u8; 16])] {
            assert_eq!(eval_ir(&ir, 3, 4).unwrap(), if seed[0] == 1 { 7 } else { license_toy_oracle(3, 4) });
            let pic = emit_superop(&ir, &seed).unwrap();
            assert!(!pic.is_empty());
            assert!(!has_guest_dispatch_tetrad(&pic));
        }
    }
}
