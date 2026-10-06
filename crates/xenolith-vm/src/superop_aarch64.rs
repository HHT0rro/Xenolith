//! Per-block unique PIC for AArch64 guest thunks (vm-aarch64 design §7).
//!
//! Mirrors the x86-64 superop (`superop.rs`) on the shared AArch64 word
//! emitter (`aarch64_asm`): per-block register allocation, entry/exit block
//! shuffles, net-zero junk pairs, never-taken opaque edges, MBA families
//! (with `AddLea` replaced by `AddOrAnd`). The emitted thunk is
//! position-independent and self-contained; the load bias is recovered from
//! `adr x16, .` minus the thunk's own pack-time RVA (§7.4: no adrp re-issue).
//!
//! Frame contract (§7.2/§7.5, v3):
//! ```text
//!   sub  sp, sp, #(SAVES+F)     ; SAVES = 96 (6 saved pairs), F = guest
//!   stp  x19..x30, [sp, #0..80] ; saved pairs at the BOTTOM of the reserve
//!   add  x15, sp, #(SAVES+F)    ; x15 = GSP ≡ C ≡ guest entry SP
//!   <bias recovery into x17>    ; adr x16,. ; const ; sub
//!   <entry shuffle x0..x7> ; b L_entry
//!   <blocks: junk + stmts + MBA + terminators>
//! L_epilogue:
//!   <per-Ret: mov x0, map[0]>   ; emitted at each Ret terminator
//!   ldp  x19..x30, [sp, #0..80]
//!   add  sp, sp, #(SAVES+F)     ; sp = C again — paired same imm12
//!   ret                         ; LR untouched (the hook is a direct b)
//! ```

use crate::aarch64_asm::*;
use crate::ir::{BinOp, CmpOp};
use crate::ir64::{
    Addr64, Ir64Module, Src64, Stmt64, Term64, Width64, VREG64_COUNT, VREG64_SP, VREG64_X0,
};
use crate::mba::{pick_family, MbaFamily};
use sha2::{Digest, Sha256};

/// Physical allocation pool: x0..x14 + x19..x29 (26 registers). Reserved:
/// x15=GSP, x16=TMP, x17=BIAS, x18 (platform), x30=LR, x31=SP.
pub const POOL: [u8; 26] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28,
    29,
];
const TMP: u8 = 16;
const GSP: u8 = 15;
const BIAS: u8 = 17;
const SAVES: u64 = 96; // 6 pairs: x19/x20 .. x29/x30
/// `SAVES+F ≤ 4080`: the largest 16-multiple that still encodes in imm12.
pub const FRAME_CAP: u64 = 4080;

pub struct SuperopAarch64Options {
    /// Load-relative RVA of the thunk's first word (the bias-recovery
    /// constant). Pass 0 for a sizing pass — the word count is rva-
    /// independent because the constant materialization is fixed-width.
    pub thunk_rva: u32,
}

/// Emit one guest thunk as fully-resolved words.
pub fn emit_superop_aarch64(
    module: &Ir64Module,
    seed: &[u8; 16],
    opt: &SuperopAarch64Options,
) -> Result<Vec<u32>, String> {
    if module.blocks.is_empty() || module.entry >= module.blocks.len() {
        return Err("superop-aarch64: empty ir64".into());
    }
    let frame = guest_frame(module)?;
    let live = used_vregs64(module);
    let maps: Vec<[u8; VREG64_COUNT]> = (0..module.blocks.len())
        .map(|bi| alloc_map(seed, bi as u32, &live))
        .collect::<Result<Vec<_>, _>>()?;
    emit_inner(module, seed, &maps, &live, opt, frame).map_err(|e| format!("superop-aarch64: {e}"))
}

// ---- frame planning (§7.5) ----

/// Static SP trajectory over the whole window: SP writes are immediate-only
/// (the lift whitelist guarantees it), so a linear scan over the blocks is
/// exact for balanced control flow and conservative otherwise.
fn guest_frame(module: &Ir64Module) -> Result<u64, String> {
    let mut sp: i64 = 0;
    let mut min: i64 = 0;
    for (bi, block) in module.blocks.iter().enumerate() {
        for stmt in &block.stmts {
            let Stmt64::Bin { op, w, dst, lhs: _, rhs, .. } = stmt else {
                continue;
            };
            if *dst != VREG64_SP {
                continue;
            }
            if *w != Width64::X {
                return Err(format!(
                    "guest stack frame: 32-bit SP write in block {bi} is outside the \
                     whitelist (SP arithmetic is 64-bit on aarch64)"
                )
                .into());
            }
            let Src64::Imm(imm) = *rhs else {
                return Err(
                    "guest stack frame: dynamic (register) SP update — the whitelist only \
                     admits immediate SP adjustments; keep the function native with \
                     --allow-native-fallback"
                        .into(),
                );
            };
            match op {
                BinOp::Add => sp = sp.wrapping_add(imm as i64),
                BinOp::Sub => sp = sp.wrapping_sub(imm as i64),
                _ => {
                    return Err(
                        "guest stack frame: non add/sub SP statement is outside the whitelist"
                            .into(),
                    )
                }
            }
            min = min.min(sp);
        }
    }
    let depth = ((-min).max(0)) as u64;
    let f = ((depth + 8 + 15) / 16) * 16;
    let total = SAVES + f;    if total > FRAME_CAP {
        return Err(format!(
            "guest stack frame {total} exceeds the emitter cap (SAVES+F ≤ {FRAME_CAP}; \
             immediate-shifted `add/sub sp,#imm<<12` descents hit this cap by design) — \
             keep the function native with --allow-native-fallback"
        ));
    }
    Ok(total as u64)
}

// ---- register allocation (mirror of superop.rs) ----

fn alloc_map(
    seed: &[u8; 16],
    block: u32,
    live: &[bool; VREG64_COUNT],
) -> Result<[u8; VREG64_COUNT], String> {
    let stream = block_stream(seed, block ^ 0xC0FF_EE);
    let mut pool: Vec<u8> = POOL.to_vec();
    for i in 0..pool.len() {
        let j = (stream[i % 32] as usize) % pool.len();
        pool.swap(i, j);
    }
    let mut taken = [false; 32];
    taken[TMP as usize] = true;
    taken[GSP as usize] = true;
    taken[BIAS as usize] = true;
    taken[18] = true; // x18 is platform-reserved, never allocated
    taken[30] = true; // LR
    taken[31] = true; // SP
    let mut map = [0u8; VREG64_COUNT];
    let mut k = 0usize;
    let live_count = live.iter().filter(|&&l| l).count();
    for v in 0..VREG64_COUNT {
        if v as u8 == VREG64_SP {
            map[v] = GSP;
            continue;
        }
        if !live[v] {
            map[v] = v as u8;
            continue;
        }
        loop {
            if k >= pool.len() {
                return Err(format!(
                    "not enough physical registers in block {block} (no spill allowed): \
                     {live_count} live vregs but the pool holds {} registers — this happens \
                     when a function touches many guest GPRs at once; keep the function \
                     native or split it",
                    pool.len()
                ));
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

fn used_vregs64(module: &Ir64Module) -> [bool; VREG64_COUNT] {
    let mut used = [false; VREG64_COUNT];
    let mark = |used: &mut [bool; VREG64_COUNT], src: Src64| {
        if let Src64::Reg(r) = src {
            if (r as usize) < VREG64_COUNT {
                used[r as usize] = true;
            }
        }
    };
    used[VREG64_X0 as usize] = true;
    for b in &module.blocks {
        for s in &b.stmts {
            match *s {
                Stmt64::Mov { dst, src } => {
                    used[dst as usize] = true;
                    mark(&mut used, src);
                }
                Stmt64::Bin { dst, lhs, rhs, .. } => {
                    used[dst as usize] = true;
                    mark(&mut used, lhs);
                    mark(&mut used, rhs);
                }
                Stmt64::Load { dst, addr, .. } => {
                    used[dst as usize] = true;
                    let Addr64::BaseDisp { base, .. } = addr;
                    used[base as usize] = true;
                }
                Stmt64::Store { addr, src, .. } => {
                    let Addr64::BaseDisp { base, .. } = addr;
                    used[base as usize] = true;
                    mark(&mut used, src);
                }
                Stmt64::Bias { dst, .. } => {
                    used[dst as usize] = true;
                }
            }
        }
        if let Term64::BrCmp { lhs, rhs, .. } = b.term {
            mark(&mut used, lhs);
            mark(&mut used, rhs);
        }
    }
    used
}

// ---- remap ----

fn remap_src64(src: Src64, map: &[u8; VREG64_COUNT]) -> Src64 {
    match src {
        Src64::Reg(r) if (r as usize) < VREG64_COUNT => Src64::Reg(map[r as usize]),
        other => other,
    }
}

fn remap_addr64(addr: Addr64, map: &[u8; VREG64_COUNT]) -> Addr64 {
    let Addr64::BaseDisp { base, disp } = addr;
    Addr64::BaseDisp {
        base: map[base as usize],
        disp,
    }
}

fn remap_stmt64(stmt: &Stmt64, map: &[u8; VREG64_COUNT]) -> Stmt64 {
    match *stmt {
        Stmt64::Mov { dst, src } => Stmt64::Mov {
            dst: map[dst as usize],
            src: remap_src64(src, map),
        },
        Stmt64::Bin { op, w, dst, lhs, rhs } => Stmt64::Bin {
            op,
            w,
            dst: map[dst as usize],
            lhs: remap_src64(lhs, map),
            rhs: remap_src64(rhs, map),
        },
        Stmt64::Load { dst, addr, width } => Stmt64::Load {
            dst: map[dst as usize],
            addr: remap_addr64(addr, map),
            width,
        },
        Stmt64::Store { addr, src, width } => Stmt64::Store {
            addr: remap_addr64(addr, map),
            src: remap_src64(src, map),
            width,
        },
        Stmt64::Bias { dst, rva } => Stmt64::Bias {
            dst: map[dst as usize],
            rva,
        },
    }
}

// ---- emission ----

fn emit_inner(
    module: &Ir64Module,
    seed: &[u8; 16],
    maps: &[[u8; VREG64_COUNT]],
    live: &[bool; VREG64_COUNT],
    opt: &SuperopAarch64Options,
    frame: u64,
) -> Result<Vec<u32>, String> {
    let needs_bias = module.blocks.iter().any(|b| {
        b.stmts.iter().any(|s| matches!(s, Stmt64::Bias { .. }))
    });
    let mut a = Asm::new();
    let block_labels: Vec<usize> = (0..module.blocks.len()).map(|_| a.label()).collect();
    let l_epilogue = a.label();
    let l_junk: Vec<usize> = (0..module.blocks.len()).map(|_| a.label()).collect();

    // ---- prologue ----
    a.emit(sub_x_imm(31, 31, frame as u32));
    for i in 0..6u32 {
        let r1 = 19 + i * 2;
        let r2 = 20 + i * 2;
        a.emit(stp_x_off(r1, r2, 31, i * 2)); // imm7 = bytes/8 = i*2
    }
    a.emit(add_x_imm(GSP as u32, 31, frame as u32));
    if needs_bias {
        // x17 = load_bias: `adr x16, .` yields bias + rva_of_this_word; the
        // pack-time constant subtracts exactly that (thunk_rva + anchor
        // offset), so the anchor position is immaterial. Fixed 4-word
        // materialization keeps the thunk size rva-independent (sizing pass
        // / real pass emit alike).
        let anchor = a.here() as u64 * 4;
        a.emit(ADR_SELF | TMP as u32);
        let rva = opt.thunk_rva as u64 + anchor;
        emit_const_x(&mut a, BIAS as u32, rva, true);
        a.emit(sub_x_reg(BIAS as u32, TMP as u32, BIAS as u32));
    }
    // Entry shuffle: only x0..x7 are live arguments (§7.2); everything else
    // at entry is scratch. GSP (vreg 31) is already in place.
    let mut entry_live = [false; VREG64_COUNT];
    for v in 0..8 {
        entry_live[v] = live[v];
    }
    let id_map: [u8; VREG64_COUNT] = core::array::from_fn(|i| if i == 31 { GSP } else { i as u8 });
    emit_shuffle(&mut a, &id_map, &maps[module.entry], &entry_live)?;
    a.fixup(
        FixupKind::Branch { base: 0x1400_0000 },
        Target::Label(block_labels[module.entry]),
    );
    a.emit(0);

    // ---- blocks ----
    for (bi, block) in module.blocks.iter().enumerate() {
        a.bind(block_labels[bi]);
        let stream = block_stream(seed, bi as u32);
        let map = maps[bi];
        for (stmt_i, stmt) in block.stmts.iter().enumerate() {
            let junk_k = u32::from_le_bytes([
                stream[stmt_i % 32],
                stream[(stmt_i + 1) % 32],
                stream[(stmt_i + 2) % 32],
                stream[(stmt_i + 3) % 32],
            ]) % 4096;
            emit_junk(&mut a, junk_k);
            let seedb = stream[(stmt_i + 7) % 32];
            emit_stmt64(&mut a, &remap_stmt64(stmt, &map), seedb)?;
        }
        emit_opaque_junk_edge(&mut a, l_junk[bi], stream[8])?;
        emit_term64(
            &mut a,
            &block.term,
            map,
            maps,
            live,
            &block_labels,
            l_epilogue,
        )?;
    }

    // ---- epilogue ----
    a.bind(l_epilogue);
    for i in 0..6u32 {
        let r1 = 19 + i * 2;
        let r2 = 20 + i * 2;
        a.emit(ldp_x_off(r1, r2, 31, i * 2));
    }
    a.emit(add_x_imm(31, 31, frame as u32));
    a.emit(RET);
    a.finish_standalone()
}

fn emit_shuffle(
    a: &mut Asm,
    from: &[u8; VREG64_COUNT],
    to: &[u8; VREG64_COUNT],
    live: &[bool; VREG64_COUNT],
) -> Result<(), String> {
    if from == to {
        return Ok(());
    }
    let mut pending: Vec<(u8, u8)> = Vec::new();
    for v in 0..VREG64_COUNT {
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
            a.emit(mov_x(d as u32, s as u32));
            continue;
        }
        let (s, d) = pending.remove(0);
        a.emit(mov_x(TMP as u32, s as u32));
        pending.push((TMP, d));
    }
    Ok(())
}

/// Net-zero junk: paired add/sub on the TMP register (always encodable,
/// §7.3 — no logical-immediate encodability gamble).
fn emit_junk(a: &mut Asm, k: u32) {
    a.emit(add_x_imm(TMP as u32, TMP as u32, k));
    a.emit(sub_x_imm(TMP as u32, TMP as u32, k));
}

/// Never-taken opaque edge: `eor x16,x16,x16` forces Z=1, so `b.ne` never
/// fires; the junk body is unreachable but present in the stream.
fn emit_opaque_junk_edge(a: &mut Asm, l_junk: usize, seedb: u8) -> Result<(), String> {
    let l_skip = a.label();
    a.emit(eor_self_x(TMP as u32));
    a.fixup(
        FixupKind::BranchCond { cond: 1 }, // b.ne
        Target::Label(l_junk),
    );
    a.emit(0);
    a.fixup(
        FixupKind::Branch { base: 0x1400_0000 },
        Target::Label(l_skip),
    );
    a.emit(0);
    a.bind(l_junk);
    a.emit(add_x_imm(TMP as u32, TMP as u32, (seedb as u32) % 4096));
    a.emit(sub_x_imm(TMP as u32, TMP as u32, (seedb as u32) % 4096));
    a.fixup(
        FixupKind::Branch { base: 0x1400_0000 },
        Target::Label(l_skip),
    );
    a.emit(0);
    a.bind(l_skip);
    Ok(())
}

/// Fixed-or-variable width constant materialization. `fixed4` forces the
/// full movz+movk×3 shape (sizing-pass determinism).
fn emit_const_x(a: &mut Asm, rd: u32, v: u64, fixed4: bool) {
    if !fixed4 && v <= 0xFFFF {
        a.emit(movz_x(rd, v as u32));
        return;
    }
    a.emit(movz_x(rd, (v & 0xFFFF) as u32));
    for hw in 1..4u32 {
        let lane = (v >> (hw * 16)) & 0xFFFF;
        if !fixed4 && lane == 0 && v < (1u64 << (hw * 16)) {
            break;
        }
        a.emit(movk_x(rd, lane as u32, hw));
    }
}

fn emit_const_w(a: &mut Asm, rd: u32, v: u32) {
    if v <= 0xFFFF {
        a.emit(movz_w(rd, v));
        return;
    }
    a.emit(movz_w(rd, v & 0xFFFF));
    a.emit(movk_w(rd, v >> 16, 1));
}

fn emit_stmt64(a: &mut Asm, stmt: &Stmt64, seedb: u8) -> Result<(), String> {
    match stmt {
        Stmt64::Mov { dst, src } => {
            let Src64::Reg(s) = *src else {
                let Src64::Imm(v) = *src else { unreachable!() };
                emit_const_x(a, *dst as u32, v, false);
                return Ok(());
            };
            if s != *dst {
                a.emit(mov_x(*dst as u32, s as u32));
            }
            Ok(())
        }
        Stmt64::Bin { op, w, dst, lhs, rhs } => emit_bin64(a, *op, *w, *dst, *lhs, *rhs, seedb),
        Stmt64::Load { dst, addr, width } => {
            let Addr64::BaseDisp { base, disp } = *addr;
            if disp < 0 || (disp as u64) / *width as u64 > 0xFFF {
                return Err(format!(
                    "load offset {disp:#x} (width {width}) is outside the unsigned imm12 \
                     family — the whitelist lifter cannot produce this; packer bug",
                ));
            }
            let word = match width {
                1 => ldrb_w(*dst as u32, base as u32, disp as u32),
                2 => ldrh_w(*dst as u32, base as u32, disp as u32),
                4 => ldr_w(*dst as u32, base as u32, disp as u32),
                8 => ldr_x(*dst as u32, base as u32, disp as u32),
                _ => return Err(format!("unsupported load width {width}").into()),
            };
            a.emit(word);
            Ok(())
        }
        Stmt64::Store { addr, src, width } => {
            let Addr64::BaseDisp { base, disp } = *addr;
            if disp < 0 || (disp as u64) / *width as u64 > 0xFFF {
                return Err(format!(
                    "store offset {disp:#x} (width {width}) is outside the unsigned imm12 \
                     family — the whitelist lifter cannot produce this; packer bug",
                ));
            }
            let rt = match *src {
                Src64::Reg(r) => r as u32,
                Src64::Imm(v) => {
                    match width {
                        1 => emit_const_w(a, TMP as u32, v as u32 & 0xFF),
                        2 => emit_const_w(a, TMP as u32, v as u32 & 0xFFFF),
                        4 => emit_const_w(a, TMP as u32, v as u32),
                        _ => emit_const_x(a, TMP as u32, v, false),
                    }
                    TMP as u32
                }
            };
            let word = match width {
                1 => strb_w(rt, base as u32, disp as u32),
                2 => strh_w(rt, base as u32, disp as u32),
                4 => str_w(rt, base as u32, disp as u32),
                8 => str_x(rt, base as u32, disp as u32),
                _ => return Err(format!("unsupported store width {width}").into()),
            };
            a.emit(word);
            Ok(())
        }
        Stmt64::Bias { dst, rva } => {
            emit_const_x(a, TMP as u32, *rva as u64, false);
            a.emit(add_x_reg(*dst as u32, BIAS as u32, TMP as u32));
            Ok(())
        }
    }
}

fn stage_lhs(a: &mut Asm, w: Width64, dst: u8, lhs: Src64) -> Result<(), String> {
    match lhs {
        Src64::Reg(l) => {
            if l != dst {
                if w == Width64::X {
                    a.emit(mov_x(dst as u32, l as u32));
                } else {
                    a.emit(mov_w(dst as u32, l as u32));
                }
            }
            Ok(())
        }
        Src64::Imm(v) => {
            match w {
                Width64::X => emit_const_x(a, TMP as u32, v, false),
                Width64::W => emit_const_w(a, TMP as u32, v as u32),
            }
            Ok(())
        }
    }
}

fn emit_bin64(
    a: &mut Asm,
    op: BinOp,
    w: Width64,
    dst: u8,
    lhs: Src64,
    rhs: Src64,
    seedb: u8,
) -> Result<(), String> {
    let x = w == Width64::X;
    // Shifts first: immediate forms have dedicated alias encodings.
    match op {
        BinOp::Shl | BinOp::Shr | BinOp::Sar => {
            let cnt = match rhs {
                Src64::Imm(c) => {
                    let bits = w.bits();
                    (c as u32) & (bits - 1)
                }
                Src64::Reg(r) => {
                    // variable shift
                    stage_lhs(a, w, dst, lhs)?;
                    let (rd, rn, rm) = (dst as u32, dst as u32, r as u32);
                    let word = match (op, x) {
                        (BinOp::Shl, true) => lslv_x(rd, rn, rm),
                        (BinOp::Shl, false) => lslv_w(rd, rn, rm),
                        (BinOp::Shr, true) => lsrv_x(rd, rn, rm),
                        (BinOp::Shr, false) => lsrv_w(rd, rn, rm),
                        (BinOp::Sar, true) => asrv_x(rd, rn, rm),
                        _ => asrv_w(rd, rn, rm),
                    };
                    a.emit(word);
                    return Ok(());
                }
            };
            stage_lhs(a, w, dst, lhs)?;
            let (rd, rn) = (dst as u32, dst as u32);
            let word = match (op, x) {
                (BinOp::Shl, true) => lsl_x_imm(rd, rn, cnt),
                (BinOp::Shl, false) => lsl_w_imm(rd, rn, cnt),
                (BinOp::Shr, true) => lsr_x_imm(rd, rn, cnt),
                (BinOp::Shr, false) => lsr_w_imm(rd, rn, cnt),
                (BinOp::Sar, true) => asr_x_imm(rd, rn, cnt),
                _ => asr_w_imm(rd, rn, cnt),
            };
            a.emit(word);
            return Ok(());
        }
        BinOp::Mul => {
            return Err(
                "multiply is outside the aarch64 first batch (the lifter rejects it; a \
                 Mul statement reaching the emitter is a packer bug)"
                    .into(),
            )
        }
        _ => {}
    }
    // MBA families: 64-bit datapath only, register/register only — one
    // scratch temp plus dst must suffice for every aliasing shape.
    if x {
        if let (Src64::Reg(_), Src64::Reg(_)) = (lhs, rhs) {
            match pick_family(op, seedb) {
                MbaFamily::AddXorAnd if op == BinOp::Add => {
                    return emit_mba_add_xor_and(a, dst, lhs, rhs)
                }
                MbaFamily::AddLea if op == BinOp::Add => {
                    // AddLea has no aarch64 counterpart; AddOrAnd replaces it.
                    return emit_mba_add_or_and(a, dst, lhs, rhs);
                }
                MbaFamily::SubAddNot if op == BinOp::Sub => {
                    return emit_mba_sub_add_not(a, dst, lhs, rhs)
                }
                MbaFamily::XorOrAnd if op == BinOp::Xor => {
                    return emit_mba_xor_or_and(a, dst, lhs, rhs)
                }
                MbaFamily::AndAddOr if op == BinOp::And => {
                    return emit_mba_and_add_or(a, dst, lhs, rhs)
                }
                _ => {}
            }
        }
    }
    // Identity form. aarch64 3-operand ALU reads both sources before the
    // destination write, so `op dst, lhs, rhs` is alias-safe with no staging
    // whenever lhs is a register; immediate add/sub take (negated) imm12
    // shortcuts, everything else materializes through TMP.
    if let Src64::Imm(v) = rhs {
        if let Src64::Imm(_) = lhs {
            return Err(
                "double-immediate binary op is not encodable (the lifter folds constant \
                 arithmetic; reaching this is a packer bug)"
                    .into(),
            );
        }
        if op == BinOp::Add || op == BinOp::Sub {
            let v_enc = if x { v } else { v & 0xFFFF_FFFF };
            let neg = v_enc.wrapping_neg();
            if v_enc <= 0xFFF {
                // imm forms stage lhs into dst (mov w/x dst, lhs)
                stage_lhs(a, w, dst, lhs)?;
                a.emit(imm_form(op, x, dst as u32, dst as u32, v_enc as u32));
                return Ok(());
            }
            if neg <= 0xFFF {
                let flipped = match op {
                    BinOp::Add => BinOp::Sub,
                    _ => BinOp::Add,
                };
                stage_lhs(a, w, dst, lhs)?;
                a.emit(imm_form(flipped, x, dst as u32, dst as u32, neg as u32));
                return Ok(());
            }
        }
        let Src64::Reg(l) = lhs else { unreachable!() };
        match w {
            Width64::X => emit_const_x(a, TMP as u32, v, false),
            Width64::W => emit_const_w(a, TMP as u32, v as u32),
        }
        a.emit(reg_form(op, x, dst as u32, l as u32, TMP as u32)?);
        return Ok(());
    }
    // rhs is Reg: direct 3-operand form covers every aliasing.
    let Src64::Reg(r) = rhs else { unreachable!() };
    match lhs {
        Src64::Reg(l) => {
            a.emit(reg_form(op, x, dst as u32, l as u32, r as u32)?);
            Ok(())
        }
        Src64::Imm(v) => {
            match w {
                Width64::X => emit_const_x(a, TMP as u32, v, false),
                Width64::W => emit_const_w(a, TMP as u32, v as u32),
            }
            a.emit(reg_form(op, x, dst as u32, TMP as u32, r as u32)?);
            Ok(())
        }
    }
}

fn imm_form(op: BinOp, x: bool, rd: u32, rn: u32, imm12: u32) -> u32 {
    match (op, x) {
        (BinOp::Add, true) => add_x_imm(rd, rn, imm12),
        (BinOp::Add, false) => add_w_imm(rd, rn, imm12),
        (_, true) => sub_x_imm(rd, rn, imm12),
        _ => sub_w_imm(rd, rn, imm12),
    }
}

fn reg_form(op: BinOp, x: bool, rd: u32, rn: u32, rm: u32) -> Result<u32, String> {
    Ok(match (op, x) {
        (BinOp::Add, true) => add_x_reg(rd, rn, rm),
        (BinOp::Add, false) => add_w_reg(rd, rn, rm),
        (BinOp::Sub, true) => sub_x_reg(rd, rn, rm),
        (BinOp::Sub, false) => sub_w_reg(rd, rn, rm),
        (BinOp::And, true) => and_x_reg(rd, rn, rm),
        (BinOp::And, false) => and_w_reg(rd, rn, rm),
        (BinOp::Or, true) => orr_x_reg(rd, rn, rm),
        (BinOp::Or, false) => orr_w_reg(rd, rn, rm),
        (BinOp::Xor, true) => eor_x_reg(rd, rn, rm),
        (BinOp::Xor, false) => eor_w_reg(rd, rn, rm),
        _ => return Err("op has no register form in the aarch64 whitelist".into()),
    })
}

// ---- MBA identities (A7-checked in tests) ----
// Every shape consumes its sources through 3-operand reads (sources are
// read before Rd is written), so any dst==lhs / dst==rhs aliasing is safe;
// t (=TMP) is never a mapped vreg.

/// dst = a + b via (a^b) + 2*(a&b).
fn emit_mba_add_xor_and(a: &mut Asm, dst: u8, lhs: Src64, rhs: Src64) -> Result<(), String> {
    let (Src64::Reg(lr), Src64::Reg(rr)) = (lhs, rhs) else { unreachable!() };
    let (l, r, d, t) = (lr as u32, rr as u32, dst as u32, TMP as u32);
    a.emit(mov_x(t, l));
    a.emit(and_x_reg(t, t, r)); // t = a & b
    a.emit(add_x_reg(t, t, t)); // t = 2*(a&b)
    emit_eor_into(a, d, l, r); // dst = a ^ b
    a.emit(add_x_reg(d, d, t));
    Ok(())
}

/// dst = a + b via (a|b) + (a&b) — the aarch64 replacement for AddLea.
fn emit_mba_add_or_and(a: &mut Asm, dst: u8, lhs: Src64, rhs: Src64) -> Result<(), String> {
    let (Src64::Reg(lr), Src64::Reg(rr)) = (lhs, rhs) else { unreachable!() };
    let (l, r, d, t) = (lr as u32, rr as u32, dst as u32, TMP as u32);
    a.emit(mov_x(t, l));
    a.emit(and_x_reg(t, t, r)); // t = a & b
    emit_orr_into(a, d, l, r); // dst = a | b
    a.emit(add_x_reg(d, d, t));
    Ok(())
}

/// dst = a - b via a + (-b); the negation rides on `sub t, xzr, b` (the
/// shifted-register form reads Rn=31 as XZR — golden `neg x0,x1` = cb0103e0).
fn emit_mba_sub_add_not(a: &mut Asm, dst: u8, lhs: Src64, rhs: Src64) -> Result<(), String> {
    let (Src64::Reg(lr), Src64::Reg(rr)) = (lhs, rhs) else { unreachable!() };
    let (l, r, d, t) = (lr as u32, rr as u32, dst as u32, TMP as u32);
    a.emit(sub_x_reg(t, 31, r)); // t = 0 - b  (neg t, r)
    a.emit(add_x_reg(d, l, t)); // dst = a + t (3-operand, alias-safe)
    Ok(())
}

/// dst = a ^ b via (a|b) - (a&b).
fn emit_mba_xor_or_and(a: &mut Asm, dst: u8, lhs: Src64, rhs: Src64) -> Result<(), String> {
    let (Src64::Reg(lr), Src64::Reg(rr)) = (lhs, rhs) else { unreachable!() };
    let (l, r, d, t) = (lr as u32, rr as u32, dst as u32, TMP as u32);
    a.emit(mov_x(t, l));
    a.emit(and_x_reg(t, t, r)); // t = a & b
    emit_orr_into(a, d, l, r); // dst = a | b
    a.emit(sub_x_reg(d, d, t)); // dst = (a|b) - (a&b)
    Ok(())
}

/// dst = a & b via (a+b) - (a|b).
fn emit_mba_and_add_or(a: &mut Asm, dst: u8, lhs: Src64, rhs: Src64) -> Result<(), String> {
    let (Src64::Reg(lr), Src64::Reg(rr)) = (lhs, rhs) else { unreachable!() };
    let (l, r, d, t) = (lr as u32, rr as u32, dst as u32, TMP as u32);
    a.emit(mov_x(t, l));
    a.emit(add_x_reg(t, t, r)); // t = a + b
    emit_orr_into(a, d, l, r); // dst = a | b
    a.emit(sub_x_reg(d, t, d)); // dst = (a+b) - (a|b)
    Ok(())
}

/// dst = a OP b (commutative ORR/EOR) with every aliasing safe.
fn emit_orr_into(a: &mut Asm, d: u32, l: u32, r: u32) {
    if d == r {
        // dst holds b: read it as Rm before the write.
        a.emit(orr_x_reg(d, l, d));
    } else {
        if d != l {
            a.emit(mov_x(d, l));
        }
        a.emit(orr_x_reg(d, d, r));
    }
}

fn emit_eor_into(a: &mut Asm, d: u32, l: u32, r: u32) {
    if d == r {
        a.emit(eor_x_reg(d, l, d));
    } else {
        if d != l {
            a.emit(mov_x(d, l));
        }
        a.emit(eor_x_reg(d, d, r));
    }
}

fn emit_term64(
    a: &mut Asm,
    term: &Term64,
    map: [u8; VREG64_COUNT],
    maps: &[[u8; VREG64_COUNT]],
    live: &[bool; VREG64_COUNT],
    block_labels: &[usize],
    l_epilogue: usize,
) -> Result<(), String> {
    match *term {
        Term64::Ret => {
            a.emit(mov_x(0, map[VREG64_X0 as usize] as u32));
            a.fixup(
                FixupKind::Branch { base: 0x1400_0000 },
                Target::Label(l_epilogue),
            );
            a.emit(0);
            Ok(())
        }
        Term64::Jmp { target } => {
            emit_shuffle(a, &map, &maps[target], live)?;
            a.fixup(
                FixupKind::Branch { base: 0x1400_0000 },
                Target::Label(block_labels[target]),
            );
            a.emit(0);
            Ok(())
        }
        Term64::BrCmp {
            pred,
            w,
            lhs,
            rhs,
            then_bb,
            else_bb,
        } => {
            let x = w == Width64::X;
            let enc_imm = |v: u64| if x { v } else { v & 0xFFFF_FFFF };
            // Materialize lhs if Imm; rhs via imm12 when it fits.
            let lhs_reg = match lhs {
                Src64::Reg(r) => map[r as usize] as u32,
                Src64::Imm(v) => {
                    if x {
                        emit_const_x(a, TMP as u32, v, false);
                    } else {
                        emit_const_w(a, TMP as u32, v as u32);
                    }
                    TMP as u32
                }
            };
            let cond = cond_of(pred);
            match rhs {
                Src64::Imm(v) if enc_imm(v) <= 0xFFF => {
                    let word = if x {
                        cmp_x_imm(lhs_reg, enc_imm(v) as u32)
                    } else {
                        cmp_w_imm(lhs_reg, enc_imm(v) as u32)
                    };
                    a.emit(word);
                }
                Src64::Imm(_) if matches!(lhs, Src64::Reg(_)) => {
                    // big immediate: materialize rhs in TMP (lhs is a reg)
                    let v = match rhs {
                        Src64::Imm(v) => v,
                        _ => unreachable!(),
                    };
                    if x {
                        emit_const_x(a, TMP as u32, v, false);
                        a.emit(cmp_x_reg(lhs_reg, TMP as u32));
                    } else {
                        emit_const_w(a, TMP as u32, v as u32);
                        a.emit(cmp_w_reg(lhs_reg, TMP as u32));
                    }
                }
                Src64::Imm(_) => {
                    return Err(
                        "double-immediate compare is not encodable (the lifter never \
                         produces one) — packer bug"
                            .into(),
                    )
                }
                Src64::Reg(r) => {
                    let word = if x {
                        cmp_x_reg(lhs_reg, map[r as usize] as u32)
                    } else {
                        cmp_w_reg(lhs_reg, map[r as usize] as u32)
                    };
                    a.emit(word);
                }
            }
            let l_then = a.label();
            a.fixup(FixupKind::BranchCond { cond }, Target::Label(l_then));
            a.emit(0);
            emit_shuffle(a, &map, &maps[else_bb], live)?;
            a.fixup(
                FixupKind::Branch { base: 0x1400_0000 },
                Target::Label(block_labels[else_bb]),
            );
            a.emit(0);
            a.bind(l_then);
            emit_shuffle(a, &map, &maps[then_bb], live)?;
            a.fixup(
                FixupKind::Branch { base: 0x1400_0000 },
                Target::Label(block_labels[then_bb]),
            );
            a.emit(0);
            Ok(())
        }
    }
}

fn cond_of(pred: CmpOp) -> u32 {
    match pred {
        CmpOp::Eq => 0,
        CmpOp::Ne => 1,
        CmpOp::UGe => 2,  // hs
        CmpOp::ULt => 3,  // lo
        CmpOp::UGt => 8,  // hi
        CmpOp::ULe => 9,  // ls
        CmpOp::SGe => 10, // ge
        CmpOp::SLt => 11, // lt
        CmpOp::SGt => 12, // gt
        CmpOp::SLe => 13, // le
    }
}

fn block_stream(seed: &[u8; 16], block: u32) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"XLSP64\x02");
    hasher.update(seed);
    hasher.update(block.to_le_bytes());
    hasher.finalize().into()
}

#[cfg(test)]
mod tests;
