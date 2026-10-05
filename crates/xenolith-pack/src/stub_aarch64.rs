//! Handwritten AArch64 (Android arm64) PIC unpack stub.
//!
//! Mirrors the x86-64 ELF stub contract byte-for-byte in structure:
//! `[code][core bytes][meta 80B]`, entry at offset 0 (INIT_ARRAY[0] is
//! redirected here), meta layout shared via `stub_meta.rs`. The stub
//! recovers the load bias from `meta.self_rva`, builds a Win64-layout
//! `XlHostCtx` on the stack, calls the embedded freestanding
//! `xl_core_activate` (AAPCS64: ctx in x0), marks `META_UNPACKED` through
//! the raw-mprotect shim, then forwards to the original INIT_ARRAY[0]
//! target. No GOT/PLT use — works under bionic with RELRO intact.
//!
//! AArch64 instructions are fixed 4 bytes: this emitter is a plain
//! `Vec<u32>` with post-hoc label fixups — no assembler dependency
//! (iced-x86 does not cover AArch64).
//!
//! BTI (design §3.5): bionic applies PROT_BTI to executable segments on
//! BTI-marked images; both indirect entry points (`bti jc` for the
//! INIT_ARRAY call, `bti c` for the core's vprotect calls) must land on a
//! BTI instruction or BTI devices SIGILL. The core itself is only reached
//! by direct `bl` (no BTI needed) and is compiled with
//! `-mbranch-protection=none` to pin that.

use crate::stub::ElfStub;
use crate::stub_meta::{
    CTX_ENVELOPE, CTX_ENVELOPE_LEN, CTX_GATE, CTX_IMAGE_BASE, CTX_LOAD_LIBRARY, CTX_MEASUREMENT,
    CTX_GET_PROC, CTX_PHDR_VA, CTX_VPROTECT, META_ENVELOPE_LEN, META_MEASUREMENT, META_ORIGINAL_ENTRY,
    META_PAGE_SIZE, META_PAYLOAD_RVA, META_SELF_RVA, META_TABLE_RVA, META_UNPACKED, STUB_META_LEN,
};

// ---- fixed instruction words (ARM ARM encodings, verified by unit test) ----
/// `bti jc` — indirect-call-tail entry guard.
pub const BTI_JC: u32 = 0xD503_248E;
/// `bti c` — callable function entry guard (vprotect shim).
pub const BTI_C: u32 = 0xD503_248A;
/// `stp x29, x30, [sp, #-16]!`
const STP_X29_X30_PRE: u32 = 0xA9BF_7BFD;
/// `stp x19, x20, [sp, #-16]!`
const STP_X19_X20_PRE: u32 = 0xA9BF_53F3;
/// `ldp x19, x20, [sp], #16` (post-index imm7 = 16/8 = 2).
const LDP_X19_X20_POST: u32 = 0xA8C1_53F3;
/// `ldp x29, x30, [sp], #16`
const LDP_X29_X30_POST: u32 = 0xA8C1_7BFD;
/// `ret` (return to LR).
const RET: u32 = 0xD65F_03C0;
/// `blr x17` — tail-call the original INIT_ARRAY[0] target.
const BLR_X17: u32 = 0xD63F_0220;
/// `svc #0` — Linux syscall (aarch64 generic table).
const SVC0: u32 = 0xD400_0001;
/// `mov x0, sp` (add x0, sp, #0) — ctx pointer for the core.
const MOV_X0_SP: u32 = 0x9100_03E0;
/// `mov x3, xzr` (orr x3, xzr, xzr) — NULL *old for the shim calls.
const MOV_X3_XZR: u32 = 0xAA1F_03E3;
/// `neg x17, x17` (sub x17, xzr, x17).
const NEG_X17: u32 = 0xCB11_03F1;
/// `mvn x6, x17` (orn x6, xzr, x17) → x6 = page - 1.
const MVN_X6_X17: u32 = 0xAA31_03E6;

// ---- parameterized encoders (field masks per ARM ARM) ----
const fn movz_x(rd: u32, imm16: u32) -> u32 {
    0xD280_0000 | (imm16 << 5) | rd
}
const fn movz_w(rd: u32, imm16: u32) -> u32 {
    0x5280_0000 | (imm16 << 5) | rd
}
const fn mov_x(rd: u32, rm: u32) -> u32 {
    0xAA00_0000 | (rm << 16) | (31 << 5) | rd // orr rd, xzr, rm
}
const fn mov_w(rd: u32, rm: u32) -> u32 {
    0x2A00_0000 | (rm << 16) | (31 << 5) | rd // orr rd, wzr, rm
}
const fn add_x_imm(rd: u32, rn: u32, imm12: u32) -> u32 {
    0x9100_0000 | (imm12 << 10) | (rn << 5) | rd
}
const fn sub_x_imm(rd: u32, rn: u32, imm12: u32) -> u32 {
    0xD100_0000 | (imm12 << 10) | (rn << 5) | rd
}
const fn add_x_reg(rd: u32, rn: u32, rm: u32) -> u32 {
    0x8B00_0000 | (rm << 16) | (rn << 5) | rd
}
const fn sub_x_reg(rd: u32, rn: u32, rm: u32) -> u32 {
    0xCB00_0000 | (rm << 16) | (rn << 5) | rd
}
const fn and_x_reg(rd: u32, rn: u32, rm: u32) -> u32 {
    0x8A00_0000 | (rm << 16) | (rn << 5) | rd
}
const fn cmp_w_imm(rn: u32, imm12: u32) -> u32 {
    0x7100_0000 | (imm12 << 10) | (rn << 5) | 31 // subs wzr, rn, #imm
}
const fn ldr_w(rt: u32, rn: u32, byte_off: u32) -> u32 {
    0xB940_0000 | ((byte_off / 4) << 10) | (rn << 5) | rt
}
const fn ldrb_w(rt: u32, rn: u32, byte_off: u32) -> u32 {
    0x3940_0000 | (byte_off << 10) | (rn << 5) | rt
}
const fn str_w(rt: u32, rn: u32, byte_off: u32) -> u32 {
    0xB900_0000 | ((byte_off / 4) << 10) | (rn << 5) | rt
}
const fn str_x(rt: u32, rn: u32, byte_off: u32) -> u32 {
    0xF900_0000 | ((byte_off / 8) << 10) | (rn << 5) | rt
}
const fn strb_w(rt: u32, rn: u32, byte_off: u32) -> u32 {
    0x3900_0000 | (byte_off << 10) | (rn << 5) | rt
}
/// `stp x9, x10, [sp, #byte_off]` (signed-offset form; imm7 = bytes/8).
const fn stp_x9_x10_off(byte_off: u32) -> u32 {
    0xA900_0000 | (((byte_off / 8) & 0x7F) << 15) | (10 << 10) | (31 << 5) | 9
}
/// `ldp x9, x10, [x16, #byte_off]`.
const fn ldp_x9_x10_off(byte_off: u32) -> u32 {
    0xA940_0000 | (((byte_off / 8) & 0x7F) << 15) | (10 << 10) | (16 << 5) | 9
}

// ---- label fixups ----
#[derive(Clone, Copy)]
enum Target {
    Label(usize),
    /// First word after the code (core bytes start), offset by core_entry.
    CoreEntry,
    /// Meta word (first word of the 80-byte meta tail).
    Meta,
}

#[derive(Clone, Copy)]
enum FixupKind {
    /// B / BL: imm26 at [25:0], value (target-pc)>>2.
    Branch { base: u32 },
    /// B.cond: imm19 at [23:5].
    BranchCond { cond: u32 },
    /// CBZ/CBNZ (sf picks 32/64-bit Rt): imm19 at [23:5].
    CompBranch { base: u32, rt: u32 },
    /// ADR: imm21 split immlo[30:29] / immhi[23:5], byte granularity.
    Adr { rd: u32 },
    /// TBNZ/TBZ: imm14 at [18:5], (target-pc)>>2.
    TestBranch { base: u32, bit: u32, rt: u32 },
}

struct Fixup {
    kind: FixupKind,
    at_word: usize,
    target: Target,
}

/// Two-pass word emitter with post-hoc label patching.
struct Asm {
    words: Vec<u32>,
    fixups: Vec<Fixup>,
    labels: Vec<usize>,
}

impl Asm {
    fn new() -> Self {
        Asm {
            words: Vec::new(),
            fixups: Vec::new(),
            labels: Vec::new(),
        }
    }

    fn label(&mut self) -> usize {
        self.labels.push(usize::MAX);
        self.labels.len() - 1
    }

    fn bind(&mut self, l: usize) {
        self.labels[l] = self.words.len();
    }

    fn emit(&mut self, word: u32) {
        self.words.push(word);
    }

    fn fixup(&mut self, kind: FixupKind, target: Target) {
        self.fixups.push(Fixup {
            kind,
            at_word: self.words.len(),
            target,
        });
    }

    /// Resolve every fixup once `core_entry` (byte offset into the core
    /// blob) is known; the core follows the code words directly and the
    /// meta block follows the (padded) core.
    fn finish(mut self, core_len_padded: usize, core_entry: u32) -> Result<Vec<u32>, String> {
        let code_words = self.words.len();
        let core_words = core_len_padded / 4;
        let meta_word = code_words + core_words;
        for f in &self.fixups {
            let pc = f.at_word as i64 * 4;
            let target_word = match f.target {
                Target::Label(l) => {
                    let w = self.labels[l];
                    if w == usize::MAX {
                        return Err("unbound stub label".into());
                    }
                    w as i64
                }
                Target::CoreEntry => code_words as i64 + (core_entry / 4) as i64,
                Target::Meta => meta_word as i64,
            };
            let patched = match f.kind {
                FixupKind::Branch { base } => {
                    let rel = target_word * 4 - pc;
                    if rel & 3 != 0 || rel / 4 < -(1 << 25) || rel / 4 >= (1 << 25) {
                        return Err(format!("branch out of ±128MiB range ({rel})"));
                    }
                    base | (((rel / 4) as u32) & 0x03FF_FFFF)
                }
                FixupKind::BranchCond { cond } => {
                    let rel = target_word * 4 - pc;
                    if rel & 3 != 0 || rel / 4 < -(1 << 18) || rel / 4 >= (1 << 18) {
                        return Err(format!("b.cond out of ±1MiB range ({rel})"));
                    }
                    0x5400_0000 | ((((rel / 4) as u32) & 0x7FFFF) << 5) | cond
                }
                FixupKind::CompBranch { base, rt } => {
                    let rel = target_word * 4 - pc;
                    if rel & 3 != 0 || rel / 4 < -(1 << 18) || rel / 4 >= (1 << 18) {
                        return Err(format!("cbz/cbnz out of ±1MiB range ({rel})"));
                    }
                    base | ((((rel / 4) as u32) & 0x7FFFF) << 5) | rt
                }
                FixupKind::Adr { rd } => {
                    let rel = target_word * 4 - pc;
                    if rel < -(1 << 20) || rel >= (1 << 20) {
                        return Err(format!("adr out of ±1MiB range ({rel})"));
                    }
                    let imm = rel as u32 & 0x1F_FFFF;
                    0x1000_0000 | ((imm & 3) << 29) | (((imm >> 2) & 0x7_FFFF) << 5) | rd
                }
                FixupKind::TestBranch { base, bit, rt } => {
                    let rel = target_word * 4 - pc;
                    if rel & 3 != 0 || rel / 4 < -(1 << 13) || rel / 4 >= (1 << 13) {
                        return Err(format!("tbz/tbnz out of ±32KiB range ({rel})"));
                    }
                    let b5 = (bit >> 5) & 1;
                    let b40 = bit & 0x1F;
                    base | (b5 << 31) | (b40 << 19) | ((((rel / 4) as u32) & 0x3FFF) << 5) | rt
                }
            };
            self.words[f.at_word] = patched;
        }
        Ok(self.words)
    }
}

// Registers used by the stub (AAPCS64):
//   x16/x17: IP0/IP1 scratch (meta pointer / values)
//   x19:     load bias (callee-saved across the core call)
//   x29/x30: frame + link
const X0: u32 = 0;
const X1: u32 = 1;
const X2: u32 = 2;
const X3: u32 = 3;
const X4: u32 = 4;
const X5: u32 = 5;
const X6: u32 = 6;
const X9: u32 = 9;
const X16: u32 = 16;
const X17: u32 = 17;
const X19: u32 = 19;
const SP: u32 = 31;
const GATE_META_BYTE: u32 = 63; // debug_gate byte inside meta
/// CTX reservation: 0xC0 covers the 128-byte ctx with alignment slack.
const CTX_FRAME: u32 = 0xC0;

// XL_PAGE_* protection constants (stub_meta contract with xl_core).
const XL_PAGE_RW: u32 = 0x04;
const XL_PAGE_RX: u32 = 0x20;
const XL_PAGE_RWX: u32 = 0x40;
/// arm64 generic syscall table: __NR_mprotect.
const __NR_MPROTECT: u32 = 226;

/// Emit the aarch64 ELF stub: `[code][core][meta 80B]`, entry at offset 0.
pub fn emit_elf_stub_aarch64(core: &[u8], core_entry: u32) -> Result<ElfStub, String> {
    if core.is_empty() {
        return Err("empty xl_core object".into());
    }
    if core_entry as usize % 4 != 0 || core_entry as usize >= core.len() {
        return Err(format!(
            "aarch64 core entry {core_entry:#x} is unaligned or outside the core object"
        ));
    }
    let core_padded = (core.len() + 3) & !3;

    let mut a = Asm::new();
    let l_forward = a.label();
    let l_ret = a.label();
    let l_fail = a.label();
    let l_vp = a.label();
    let l_vp_rw = a.label();
    let l_vp_rx = a.label();
    let l_vp_rwx = a.label();
    let l_vp_go = a.label();
    let l_vp_old = a.label();
    let l_vp_err = a.label();

    // ---- entry (INIT_ARRAY[0] lands here via ld.so's RELATIVE addend) ----
    a.emit(BTI_JC);
    a.emit(STP_X29_X30_PRE);
    a.emit(STP_X19_X20_PRE);
    a.fixup(FixupKind::Adr { rd: X16 }, Target::Meta);
    a.emit(0); // adr x16, meta
    a.emit(ldr_w(X17, X16, META_SELF_RVA as u32));
    a.emit(sub_x_reg(X19, X16, X17)); // x19 = load bias
    a.emit(ldr_w(X17, X16, META_UNPACKED as u32));
    a.emit(cmp_w_imm(X17, 1));
    a.fixup(
        FixupKind::BranchCond { cond: 0 }, // EQ
        Target::Label(l_forward),
    );
    a.emit(0); // b.eq forward

    // ---- build XlHostCtx at [sp, sp+120) ----
    a.emit(sub_x_imm(SP, SP, CTX_FRAME));
    a.emit(str_x(X19, SP, CTX_IMAGE_BASE as u32));
    a.emit(ldr_w(X9, X16, META_PAYLOAD_RVA as u32));
    a.emit(add_x_reg(X9, X19, X9));
    a.emit(str_x(X9, SP, CTX_ENVELOPE as u32));
    a.emit(ldr_w(X9, X16, META_ENVELOPE_LEN as u32));
    a.emit(str_w(X9, SP, CTX_ENVELOPE_LEN as u32));
    a.emit(ldr_w(X9, X16, META_ORIGINAL_ENTRY as u32));
    a.emit(str_w(X9, SP, 20));
    a.emit(ldrb_w(X9, X16, GATE_META_BYTE));
    a.emit(strb_w(X9, SP, CTX_GATE as u32));
    // measurement: 32 bytes in two ldp/stp pairs.
    a.emit(ldp_x9_x10_off(META_MEASUREMENT as u32));
    a.emit(stp_x9_x10_off(CTX_MEASUREMENT as u32));
    a.emit(ldp_x9_x10_off(META_MEASUREMENT as u32 + 16));
    a.emit(stp_x9_x10_off(CTX_MEASUREMENT as u32 + 16));
    // load_library/get_proc stay NULL (ld.so resolved GOT/PLT already) and
    // the module-dir channel slots are zeroed so the core never chases a
    // stale stack value as a function pointer.
    a.emit(str_x(SP, SP, CTX_LOAD_LIBRARY as u32)); // xzr
    a.emit(str_x(SP, SP, CTX_GET_PROC as u32)); // xzr
    a.fixup(FixupKind::Adr { rd: X9 }, Target::Label(l_vp));
    a.emit(0); // adr x9, vp_shim
    a.emit(str_x(X9, SP, CTX_VPROTECT as u32));
    a.emit(str_x(SP, SP, 88)); // xzr
    a.emit(str_x(SP, SP, 96)); // xzr
    a.emit(str_x(SP, SP, 104)); // xzr
    a.emit(str_x(SP, SP, 112)); // xzr
    // phdr_va: the packed image's e_phoff is a file offset into the
    // appended PT_LOAD — the core must walk the table at its mapped VA.
    a.emit(ldr_w(X9, X16, META_TABLE_RVA as u32));
    a.emit(str_x(X9, SP, CTX_PHDR_VA as u32));
    a.emit(MOV_X0_SP);
    a.fixup(FixupKind::Branch { base: 0x9400_0000 }, Target::CoreEntry);
    a.emit(0); // bl xl_core_activate
    a.fixup(
        FixupKind::CompBranch {
            base: 0x3400_0000, // cbz (32-bit Rt)
            rt: X0,
        },
        Target::Label(l_fail),
    );
    a.emit(0); // cbz w0, fail

    // ---- mark META_UNPACKED via the shim (RW → write → RX) ----
    a.fixup(FixupKind::Adr { rd: X16 }, Target::Meta);
    a.emit(0); // adr x16, meta (reload: x16 is caller-saved)
    a.emit(mov_x(X0, X16));
    a.emit(movz_x(X1, 4));
    a.emit(movz_w(X2, XL_PAGE_RW));
    a.emit(MOV_X3_XZR);
    a.fixup(
        FixupKind::Branch { base: 0x9400_0000 },
        Target::Label(l_vp),
    );
    a.emit(0); // bl vp
    a.fixup(
        FixupKind::CompBranch {
            base: 0x3400_0000,
            rt: X0,
        },
        Target::Label(l_fail),
    );
    a.emit(0); // cbz w0, fail
    a.emit(movz_w(X9, 1));
    a.emit(str_w(X9, X16, META_UNPACKED as u32));
    a.emit(mov_x(X0, X16));
    a.emit(movz_x(X1, 4));
    a.emit(movz_w(X2, XL_PAGE_RX));
    a.emit(MOV_X3_XZR);
    a.fixup(
        FixupKind::Branch { base: 0x9400_0000 },
        Target::Label(l_vp),
    );
    a.emit(0); // bl vp
    a.fixup(
        FixupKind::CompBranch {
            base: 0x3400_0000,
            rt: X0,
        },
        Target::Label(l_fail),
    );
    a.emit(0); // cbz w0, fail
    a.emit(add_x_imm(SP, SP, CTX_FRAME));

    // ---- forward to the original INIT_ARRAY[0] target ----
    a.bind(l_forward);
    a.fixup(FixupKind::Adr { rd: X16 }, Target::Meta);
    a.emit(0); // adr x16, meta (the shim leaves x16 = meta, but stay explicit)
    a.emit(ldr_w(X17, X16, META_ORIGINAL_ENTRY as u32));
    a.fixup(
        FixupKind::CompBranch {
            base: 0x3400_0000,
            rt: X17,
        },
        Target::Label(l_ret),
    );
    a.emit(0); // cbz w17, ret
    a.emit(add_x_reg(X17, X19, X17)); // zero-extended by ldr w17
    a.emit(BLR_X17);

    a.bind(l_ret);
    a.emit(LDP_X19_X20_POST);
    a.emit(LDP_X29_X30_POST);
    a.emit(RET);

    // Fail closed: unwind the ctx frame and return as if init succeeded —
    // every protected page is 0x90 filler, so the next call traps loudly.
    a.bind(l_fail);
    a.emit(add_x_imm(SP, SP, CTX_FRAME));
    a.fixup(
        FixupKind::Branch { base: 0x1400_0000 },
        Target::Label(l_ret),
    );
    a.emit(0); // b ret

    // ---- vprotect shim (xl_core calls it as vp(addr, len, prot, *old)) ----
    a.bind(l_vp);
    a.emit(BTI_C);
    a.fixup(FixupKind::Adr { rd: X16 }, Target::Meta);
    a.emit(0); // adr x16, meta
    a.emit(ldr_w(X17, X16, META_PAGE_SIZE as u32));
    a.fixup(
        FixupKind::CompBranch {
            base: 0x3400_0000, // cbz w17 (32-bit: page size is a u32)
            rt: X17,
        },
        Target::Label(l_vp_err),
    );
    a.emit(0); // cbz w17, err (corrupt/zero page size: fail closed)
    a.emit(mov_w(X4, X2)); // w4 = requested XL_PAGE_* (echoed to *old)
    a.emit(cmp_w_imm(X2, XL_PAGE_RW));
    a.fixup(FixupKind::BranchCond { cond: 0 }, Target::Label(l_vp_rw));
    a.emit(0); // b.eq vp_rw
    a.emit(cmp_w_imm(X2, XL_PAGE_RX));
    a.fixup(FixupKind::BranchCond { cond: 0 }, Target::Label(l_vp_rx));
    a.emit(0); // b.eq vp_rx
    a.emit(cmp_w_imm(X2, XL_PAGE_RWX));
    a.fixup(FixupKind::BranchCond { cond: 0 }, Target::Label(l_vp_rwx));
    a.emit(0); // b.eq vp_rwx
    a.emit(movz_w(X0, 0)); // unknown protection constant: fail closed
    a.emit(RET);

    a.bind(l_vp_rw);
    // Decrypt window keeps the EXEC bit (RWX, not RW): binary translators
    // (ndk_translation on x86_64 hosts) fatally crash when a translated
    // code page drops X — mprotect(RW) on guest text kills the translator
    // before any write happens (measured: mprotect(RW) alone SIGSEGVs
    // inside ndk_translation_HandleNoExec). The final protect below still
    // restores the segment-declared (RX) permission, so the RWX window is
    // transient — reported as such by the packer.
    a.emit(movz_w(X2, 7)); // PROT_READ|PROT_WRITE|PROT_EXEC
    a.fixup(FixupKind::Branch { base: 0x1400_0000 }, Target::Label(l_vp_go));
    a.emit(0);
    a.bind(l_vp_rx);
    a.emit(movz_w(X2, 5)); // PROT_READ|PROT_EXEC
    a.fixup(FixupKind::Branch { base: 0x1400_0000 }, Target::Label(l_vp_go));
    a.emit(0);
    a.bind(l_vp_rwx);
    a.emit(movz_w(X2, 7)); // PROT_READ|PROT_WRITE|PROT_EXEC
    a.bind(l_vp_go);
    a.fixup(
        FixupKind::CompBranch {
            base: 0xB400_0000, // cbz (64-bit Rt)
            rt: X3,
        },
        Target::Label(l_vp_old),
    );
    a.emit(0); // cbz x3, vp_old
    a.emit(str_w(X4, X3, 0)); // *old = requested constant
    a.bind(l_vp_old);
    // Align to meta[META_PAGE_SIZE]: addr down, len covers head, round up.
    a.emit(NEG_X17); // x17 = -page
    a.emit(mov_x(X5, X0));
    a.emit(and_x_reg(X0, X0, X17));
    a.emit(sub_x_reg(X5, X5, X0)); // head
    a.emit(add_x_reg(X1, X1, X5));
    a.emit(MVN_X6_X17); // x6 = page - 1
    a.emit(add_x_reg(X1, X1, X6));
    a.emit(and_x_reg(X1, X1, X17));
    a.emit(movz_x(8, __NR_MPROTECT));
    a.emit(SVC0);
    // mprotect returns -errno on failure (negative → bit 63 set).
    a.fixup(
        FixupKind::TestBranch {
            base: 0x3700_0000, // tbnz
            bit: 63,
            rt: X0,
        },
        Target::Label(l_vp_err),
    );
    a.emit(0); // tbnz x0, #63, err
    a.emit(movz_w(X0, 1));
    a.emit(RET);
    a.bind(l_vp_err);
    a.emit(movz_w(X0, 0));
    a.emit(RET);

    let code = a.finish(core_padded, core_entry)?;
    let mut bytes = Vec::with_capacity(code.len() * 4 + core_padded + STUB_META_LEN);
    for w in &code {
        bytes.extend_from_slice(&w.to_le_bytes());
    }
    let code_len = bytes.len();
    bytes.extend_from_slice(core);
    bytes.resize(code_len + core_padded, 0);
    let meta_off = bytes.len();
    bytes.resize(meta_off + STUB_META_LEN, 0);
    Ok(ElfStub {
        bytes,
        meta_off,
        entry_off: 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn word_at(stub: &[u8], i: usize) -> u32 {
        u32::from_le_bytes(stub[i * 4..i * 4 + 4].try_into().unwrap())
    }

    /// `adr x16, meta` expected word for a stub whose meta starts at byte
    /// `meta_off`, instruction at byte `at`.
    fn exp_adr_x16(meta_off: usize, at: usize) -> u32 {
        let rel = (meta_off - at) as u32;
        0x1000_0000 | ((rel & 3) << 29) | (((rel >> 2) & 0x7_FFFF) << 5) | 16
    }

    #[test]
    fn structure_and_golden_prologue() {
        // 24-byte fake core, entry at +4 (word-aligned).
        let core = [0xAAu8; 24];
        let stub = emit_elf_stub_aarch64(&core, 4).unwrap();
        assert_eq!(stub.entry_off, 0, "INIT_ARRAY[0] redirects to byte 0");
        assert_eq!(stub.bytes.len() % 4, 0);
        assert_eq!(
            stub.meta_off,
            stub.bytes.len() - STUB_META_LEN,
            "meta is the 80-byte tail"
        );
        assert_eq!(stub.bytes.len(), stub.meta_off + STUB_META_LEN);
        // Golden prologue.
        assert_eq!(word_at(&stub.bytes, 0), BTI_JC);
        assert_eq!(word_at(&stub.bytes, 1), 0xA9BF_7BFD); // stp x29,x30
        assert_eq!(word_at(&stub.bytes, 2), 0xA9BF_53F3); // stp x19,x20
        // adr x16, meta at word 3 patched to the real distance.
        assert_eq!(
            word_at(&stub.bytes, 3),
            exp_adr_x16(stub.meta_off, 12),
            "adr fixup must reach the meta tail"
        );
        // ldr w17, [x16, #68] — META_SELF_RVA at u32-granular offset 17.
        assert_eq!(word_at(&stub.bytes, 4), 0xB940_0000 | (17 << 10) | (16 << 5) | 17);
        // Core bytes land verbatim after the code, zero-padded to 4.
        assert_eq!(&stub.bytes[stub.meta_off - 24..stub.meta_off], &core);
        // Epilogue must POP: post-index LDP immediates are 16 (regression
        // guard — an imm7 of 0 left sp 0x20 low and wild-jumped the caller).
        let words: Vec<u32> = stub
            .bytes
            .chunks(4)
            .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
            .collect();
        assert!(
            words.contains(&LDP_X19_X20_POST),
            "ldp x19,x20,[sp],#16 missing (got {:#x?})",
            words.iter().find(|w| *w & 0xFFC0_0000 == 0xA8C0_0000)
        );
        assert!(words.contains(&LDP_X29_X30_POST), "ldp x29,x30,[sp],#16 missing");
        // Meta tail is zeroed (packer fills it).
        assert!(stub.bytes[stub.meta_off..].iter().all(|&b| b == 0));
    }

    #[test]
    fn bl_targets_core_entry() {
        let core = [0x11u8; 40];
        let entry = 8u32;
        let stub = emit_elf_stub_aarch64(&core, entry).unwrap();
        // Find the `bl` to the core: scan for a word whose imm26 resolves
        // into [meta_off - core_len, meta_off).
        let mut found = 0;
        for i in 0..stub.meta_off / 4 {
            let w = word_at(&stub.bytes, i);
            if w & 0xFC00_0000 == 0x9400_0000 {
                let imm26 = (w & 0x03FF_FFFF) as i64;
                let imm26 = if imm26 & (1 << 25) != 0 {
                    imm26 - (1 << 26)
                } else {
                    imm26
                };
                let target = (i as i64 * 4 + imm26 * 4) as usize;
                let core_start = stub.meta_off - 40;
                if target >= core_start && target < stub.meta_off {
                    assert_eq!(target, core_start + entry as usize);
                    found += 1;
                }
            }
        }
        assert_eq!(found, 1, "exactly one bl into the core (xl_core_activate)");
    }

    #[test]
    fn vprotect_shim_encodings() {
        let core = [0u8; 8];
        let stub = emit_elf_stub_aarch64(&core, 0).unwrap();
        let b = &stub.bytes;
        // The shim opens with `bti c` after the fail-path `b ret`.
        let vp = b
            .chunks(4)
            .position(|c| u32::from_le_bytes(c.try_into().unwrap()) == BTI_C)
            .expect("bti c present");
        // Shim opens: bti c; adr; ldr w17,[x16,#72]; cbz w17; mov w4, w2
        assert_eq!(
            word_at(b, vp + 2),
            0xB940_0000 | (18 << 10) | (16 << 5) | 17, // ldr w17, [x16, #72]
            "META_PAGE_SIZE=72 → imm12 = 72/4 = 18"
        );
        assert_eq!(word_at(b, vp + 4), 0x2A02_03E4); // mov w4, w2
        assert_eq!(word_at(b, vp + 5), 0x7100_105F, "cmp w2, #4 = subs wzr,w2,#4");
        // mprotect constants: mov x8, #226 then svc #0.
        let pos = b
            .chunks(4)
            .position(|c| u32::from_le_bytes(c.try_into().unwrap()) == movz_x(8, 226))
            .expect("mov x8, #226");
        assert_eq!(word_at(b, pos + 1), SVC0);
        // Alignment block constants.
        for want in [NEG_X17, MVN_X6_X17, BLR_X17, RET] {
            assert!(
                b.chunks(4)
                    .any(|c| u32::from_le_bytes(c.try_into().unwrap()) == want),
                "missing {want:#010x}"
            );
        }
    }


    #[test]
    fn rejects_bad_core_entry() {
        assert!(emit_elf_stub_aarch64(&[1u8; 16], 2).is_err(), "unaligned entry");
        assert!(emit_elf_stub_aarch64(&[], 0).is_err(), "empty core");
        assert!(emit_elf_stub_aarch64(&[1u8; 16], 16).is_err(), "entry at core end");
    }
}
