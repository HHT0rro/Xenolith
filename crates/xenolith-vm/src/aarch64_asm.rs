//! Shared AArch64 word emitter: two-pass label fixups + parameterized
//! encoder primitives.
//!
//! Generalized from `xenolith-pack/src/stub_aarch64.rs` (vm-aarch64 design
//! §7.1): the stub and the superop emitter share one fixup engine and one
//! set of encoding constants, so decode-side and emit-side bit patterns can
//! never drift apart. Every constant here is cross-checked against NDK
//! llvm-objdump golden words (see `aarch64_decode` tests and the stub's
//! golden tests).

// ---- label fixups ----
#[derive(Clone, Copy)]
pub enum Target {
    Label(usize),
    /// First word after the code (core bytes start), offset by core_entry.
    CoreEntry,
    /// Meta word (first word of the meta tail).
    Meta,
}

#[derive(Clone, Copy)]
pub enum FixupKind {
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
pub struct Asm {
    pub words: Vec<u32>,
    fixups: Vec<Fixup>,
    labels: Vec<usize>,
}

impl Asm {
    pub fn new() -> Self {
        Asm {
            words: Vec::new(),
            fixups: Vec::new(),
            labels: Vec::new(),
        }
    }

    pub fn label(&mut self) -> usize {
        self.labels.push(usize::MAX);
        self.labels.len() - 1
    }

    pub fn bind(&mut self, l: usize) {
        self.labels[l] = self.words.len();
    }

    pub fn emit(&mut self, word: u32) {
        self.words.push(word);
    }

    /// Append a fully-resolved word stream (e.g. a guest thunk emitted by
    /// `superop_aarch64`); every internal branch is already relative.
    pub fn emit_words(&mut self, words: &[u32]) {
        self.words.extend_from_slice(words);
    }

    /// Word index the next `emit` will land on.
    pub fn here(&self) -> usize {
        self.words.len()
    }

    pub fn fixup(&mut self, kind: FixupKind, target: Target) {
        self.fixups.push(Fixup {
            kind,
            at_word: self.words.len(),
            target,
        });
    }

    /// Resolve every fixup once `core_len_padded` (bytes) and `core_entry`
    /// are known: the core follows the code words directly and the meta
    /// block follows the (padded) core.
    pub fn finish(mut self, core_len_padded: usize, core_entry: u32) -> Result<Vec<u32>, String> {
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

    /// Standalone finish for word streams whose fixups are all label-local
    /// (guest thunks): no core/meta tail follows the code.
    pub fn finish_standalone(mut self) -> Result<Vec<u32>, String> {
        let code_words = self.words.len();
        for f in &self.fixups {
            let pc = f.at_word as i64 * 4;
            let target_word = match f.target {
                Target::Label(l) => {
                    let w = self.labels[l];
                    if w == usize::MAX {
                        return Err("unbound label".into());
                    }
                    w as i64
                }
                Target::CoreEntry | Target::Meta => {
                    return Err("standalone stream cannot target core/meta".into())
                }
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
        let _ = code_words;
        Ok(self.words)
    }
}

// ---- parameterized encoders (field layout per ARM ARM; every base is
// verified against an NDK-assembled golden word — see tests) ----

pub const RET: u32 = 0xD65F_03C0;
pub const NOP: u32 = 0xD503_201F;
pub const BRK0: u32 = 0xD420_0000;
/// `adr x Rd, .` (imm21 = 0) — self-address, the bias anchor.
pub const ADR_SELF: u32 = 0x1000_0000;

pub const fn movz_x(rd: u32, imm16: u32) -> u32 {
    0xD280_0000 | (imm16 << 5) | rd
}
pub const fn movz_w(rd: u32, imm16: u32) -> u32 {
    0x5280_0000 | (imm16 << 5) | rd
}
pub const fn movk_x(rd: u32, imm16: u32, hw: u32) -> u32 {
    0xF280_0000 | (hw << 21) | (imm16 << 5) | rd
}
pub const fn movk_w(rd: u32, imm16: u32, hw: u32) -> u32 {
    0x7280_0000 | (hw << 21) | (imm16 << 5) | rd
}
pub const fn mov_x(rd: u32, rm: u32) -> u32 {
    0xAA00_0000 | (rm << 16) | (31 << 5) | rd // orr rd, xzr, rm
}
pub const fn mov_w(rd: u32, rm: u32) -> u32 {
    0x2A00_0000 | (rm << 16) | (31 << 5) | rd // orr wd, wzr, wm
}
pub const fn add_x_imm(rd: u32, rn: u32, imm12: u32) -> u32 {
    0x9100_0000 | (imm12 << 10) | (rn << 5) | rd
}
pub const fn sub_x_imm(rd: u32, rn: u32, imm12: u32) -> u32 {
    0xD100_0000 | (imm12 << 10) | (rn << 5) | rd
}
pub const fn add_w_imm(rd: u32, rn: u32, imm12: u32) -> u32 {
    0x1100_0000 | (imm12 << 10) | (rn << 5) | rd
}
pub const fn sub_w_imm(rd: u32, rn: u32, imm12: u32) -> u32 {
    0x5100_0000 | (imm12 << 10) | (rn << 5) | rd
}
/// `subs xzr, rn, #imm12` (cmp).
pub const fn cmp_x_imm(rn: u32, imm12: u32) -> u32 {
    0xF100_0000 | (imm12 << 10) | (rn << 5) | 31
}
/// `subs wzr, wn, #imm12`.
pub const fn cmp_w_imm(rn: u32, imm12: u32) -> u32 {
    0x7100_0000 | (imm12 << 10) | (rn << 5) | 31
}
pub const fn add_x_reg(rd: u32, rn: u32, rm: u32) -> u32 {
    0x8B00_0000 | (rm << 16) | (rn << 5) | rd
}
pub const fn sub_x_reg(rd: u32, rn: u32, rm: u32) -> u32 {
    0xCB00_0000 | (rm << 16) | (rn << 5) | rd
}
pub const fn add_w_reg(rd: u32, rn: u32, rm: u32) -> u32 {
    0x0B00_0000 | (rm << 16) | (rn << 5) | rd
}
pub const fn sub_w_reg(rd: u32, rn: u32, rm: u32) -> u32 {
    0x4B00_0000 | (rm << 16) | (rn << 5) | rd
}
pub const fn and_x_reg(rd: u32, rn: u32, rm: u32) -> u32 {
    0x8A00_0000 | (rm << 16) | (rn << 5) | rd
}
pub const fn orr_x_reg(rd: u32, rn: u32, rm: u32) -> u32 {
    0xAA00_0000 | (rm << 16) | (rn << 5) | rd
}
pub const fn eor_x_reg(rd: u32, rn: u32, rm: u32) -> u32 {
    0xCA00_0000 | (rm << 16) | (rn << 5) | rd
}
pub const fn and_w_reg(rd: u32, rn: u32, rm: u32) -> u32 {
    0x0A00_0000 | (rm << 16) | (rn << 5) | rd
}
pub const fn orr_w_reg(rd: u32, rn: u32, rm: u32) -> u32 {
    0x2A00_0000 | (rm << 16) | (rn << 5) | rd
}
pub const fn eor_w_reg(rd: u32, rn: u32, rm: u32) -> u32 {
    0x4A00_0000 | (rm << 16) | (rn << 5) | rd
}
/// `subs xzr, rn, rm` (cmp register form).
pub const fn cmp_x_reg(rn: u32, rm: u32) -> u32 {
    0xEB00_0000 | (rm << 16) | (rn << 5) | 31
}
pub const fn cmp_w_reg(rn: u32, rm: u32) -> u32 {
    0x6B00_0000 | (rm << 16) | (rn << 5) | 31
}

// ---- UBFM/SBFM shift aliases (vm-aarch64 design §3.1#6 exact forms) ----
/// `lsl xd, xn, #m` (m>0): immr = (64-m) mod 64, imms = 63-m.
pub const fn lsl_x_imm(rd: u32, rn: u32, m: u32) -> u32 {
    0xD340_0000 | ((((64 - m) % 64) & 0x3F) << 16) | (((63 - m) & 0x3F) << 10) | (rn << 5) | rd
}
/// `lsl wd, wn, #m` (0<m<32): immr = (32-m) mod 32, imms = 31-m.
pub const fn lsl_w_imm(rd: u32, rn: u32, m: u32) -> u32 {
    0x5300_0000 | ((((32 - m) % 32) & 0x3F) << 16) | (((31 - m) & 0x3F) << 10) | (rn << 5) | rd
}
/// `lsr xd, xn, #m`: immr = m, imms = 63.
pub const fn lsr_x_imm(rd: u32, rn: u32, m: u32) -> u32 {
    0xD340_0000 | ((m & 0x3F) << 16) | (63 << 10) | (rn << 5) | rd
}
pub const fn lsr_w_imm(rd: u32, rn: u32, m: u32) -> u32 {
    0x5300_0000 | ((m & 0x3F) << 16) | (31 << 10) | (rn << 5) | rd
}
/// `asr xd, xn, #m`: immr = m, imms = 63, N=1 (SBFM 64-bit).
pub const fn asr_x_imm(rd: u32, rn: u32, m: u32) -> u32 {
    0x9340_0000 | ((m & 0x3F) << 16) | (63 << 10) | (rn << 5) | rd
}
pub const fn asr_w_imm(rd: u32, rn: u32, m: u32) -> u32 {
    0x1300_0000 | ((m & 0x3F) << 16) | (31 << 10) | (rn << 5) | rd
}
/// `mov xd, xn` via UBFM full-width (`lsl #0` alias word).
pub const fn ubfm_mov_x(rd: u32, rn: u32) -> u32 {
    lsr_x_imm(rd, rn, 0)
}
pub const fn ubfm_mov_w(rd: u32, rn: u32) -> u32 {
    lsr_w_imm(rd, rn, 0)
}

// ---- variable shifts (lslv/lsrv/asrv) ----
pub const fn lslv_x(rd: u32, rn: u32, rm: u32) -> u32 {
    0x9AC0_2000 | (rm << 16) | (rn << 5) | rd
}
pub const fn lsrv_x(rd: u32, rn: u32, rm: u32) -> u32 {
    0x9AC0_2400 | (rm << 16) | (rn << 5) | rd
}
pub const fn asrv_x(rd: u32, rn: u32, rm: u32) -> u32 {
    0x9AC0_2800 | (rm << 16) | (rn << 5) | rd
}
pub const fn lslv_w(rd: u32, rn: u32, rm: u32) -> u32 {
    0x1AC0_2000 | (rm << 16) | (rn << 5) | rd
}
pub const fn lsrv_w(rd: u32, rn: u32, rm: u32) -> u32 {
    0x1AC0_2400 | (rm << 16) | (rn << 5) | rd
}
pub const fn asrv_w(rd: u32, rn: u32, rm: u32) -> u32 {
    0x1AC0_2800 | (rm << 16) | (rn << 5) | rd
}

// ---- loads/stores, unsigned-offset immediate family ----
pub const fn ldr_x(rt: u32, rn: u32, byte_off: u32) -> u32 {
    0xF940_0000 | ((byte_off / 8) << 10) | (rn << 5) | rt
}
pub const fn ldr_w(rt: u32, rn: u32, byte_off: u32) -> u32 {
    0xB940_0000 | ((byte_off / 4) << 10) | (rn << 5) | rt
}
pub const fn ldrh_w(rt: u32, rn: u32, byte_off: u32) -> u32 {
    0x7940_0000 | ((byte_off / 2) << 10) | (rn << 5) | rt
}
pub const fn ldrb_w(rt: u32, rn: u32, byte_off: u32) -> u32 {
    0x3940_0000 | (byte_off << 10) | (rn << 5) | rt
}
pub const fn str_x(rt: u32, rn: u32, byte_off: u32) -> u32 {
    0xF900_0000 | ((byte_off / 8) << 10) | (rn << 5) | rt
}
pub const fn str_w(rt: u32, rn: u32, byte_off: u32) -> u32 {
    0xB900_0000 | ((byte_off / 4) << 10) | (rn << 5) | rt
}
pub const fn strh_w(rt: u32, rn: u32, byte_off: u32) -> u32 {
    0x7900_0000 | ((byte_off / 2) << 10) | (rn << 5) | rt
}
pub const fn strb_w(rt: u32, rn: u32, byte_off: u32) -> u32 {
    0x3900_0000 | (byte_off << 10) | (rn << 5) | rt
}
/// `stp rt, rt2, [rn, #off]` (X pair, signed-offset form; off = imm7*8).
pub const fn stp_x_off(rt: u32, rt2: u32, rn: u32, imm7: u32) -> u32 {
    0xA900_0000 | ((imm7 & 0x7F) << 15) | (rt2 << 10) | (rn << 5) | rt
}
/// `ldp rt, rt2, [rn, #off]` (X pair, signed-offset form).
pub const fn ldp_x_off(rt: u32, rt2: u32, rn: u32, imm7: u32) -> u32 {
    0xA940_0000 | ((imm7 & 0x7F) << 15) | (rt2 << 10) | (rn << 5) | rt
}

/// `eor xd, xd, xd` — canonical zero (also sets Z for never-taken edges).
pub const fn eor_self_x(rd: u32) -> u32 {
    0xCA00_0000 | (rd << 16) | (rd << 5) | rd
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encoder constants must equal NDK-assembled golden words (corpus in
    /// the vm-aarch64 design; re-verified with clang --target=
    /// aarch64-linux-android35 + llvm-objdump for this module).
    #[test]
    fn encoders_match_ndk_goldens() {
        assert_eq!(movz_x(0, 0x10), 0xD280_0200);
        assert_eq!(movz_w(0, 0x10), 0x5280_0200);
        assert_eq!(movk_x(0, 0x1234, 0), 0xF282_4680);
        assert_eq!(movk_w(0, 0x1234, 0), 0x7282_4680);
        assert_eq!(movk_x(0, 0x1234, 1), 0xF2A2_4680);
        assert_eq!(movk_x(0, 0x5678, 3), 0xF2EA_CF00);
        assert_eq!(mov_x(0, 1), 0xAA01_03E0);
        assert_eq!(mov_w(0, 1), 0x2A01_03E0);
        assert_eq!(add_x_reg(0, 1, 2), 0x8B02_0020);
        assert_eq!(add_w_reg(0, 1, 2), 0x0B02_0020);
        assert_eq!(sub_x_reg(4, 5, 6), 0xCB06_00A4);
        assert_eq!(sub_w_reg(4, 5, 6), 0x4B06_00A4);
        assert_eq!(and_x_reg(4, 5, 6), 0x8A06_00A4);
        assert_eq!(orr_w_reg(7, 8, 9), 0x2A09_0107);
        assert_eq!(eor_x_reg(10, 11, 12), 0xCA0C_016A);
        assert_eq!(cmp_x_reg(1, 2), 0xEB02_003F);
        assert_eq!(cmp_w_reg(1, 2), 0x6B02_003F);
        assert_eq!(cmp_x_imm(0, 0x10), 0xF100_401F);
        assert_eq!(cmp_w_imm(0, 0x10), 0x7100_401F);
        // imm12 forms (golden: add w0,w1,#0x123 = 0x1104_8C20)
        assert_eq!(add_w_imm(0, 1, 0x123), 0x1104_8C20);
        assert_eq!(add_x_imm(0, 1, 0x123), 0x9104_8C20);
        assert_eq!(sub_x_imm(2, 3, 1), 0xD100_0462);
        assert_eq!(sub_w_imm(0, 1, 0x123), 0x5104_8C20);
        // lsl/lsr/asr aliases
        assert_eq!(lsl_x_imm(0, 1, 1), 0xD37F_F820);
        assert_eq!(lsl_w_imm(0, 1, 1), 0x531F_7820);
        assert_eq!(lsl_x_imm(0, 1, 63), 0xD341_0020);
        assert_eq!(lsl_w_imm(0, 1, 31), 0x5301_0020);
        assert_eq!(lsr_x_imm(0, 1, 5), 0xD345_FC20);
        assert_eq!(lsr_w_imm(0, 1, 5), 0x5305_7C20);
        assert_eq!(asr_x_imm(2, 3, 7), 0x9347_FC62);
        assert_eq!(asr_w_imm(2, 3, 7), 0x1307_7C62);
        assert_eq!(ubfm_mov_x(0, 1), 0xD340_FC20); // lsl x0,x1,#0 golden
        assert_eq!(ubfm_mov_w(0, 1), 0x5300_7C20); // ubfm w0,w1,#0,#31 (NDK)
        // variable shifts
        assert_eq!(lslv_x(4, 5, 6), 0x9AC6_20A4);
        assert_eq!(lsrv_x(4, 5, 6), 0x9AC6_24A4);
        assert_eq!(asrv_x(4, 5, 6), 0x9AC6_28A4);
        assert_eq!(lslv_w(4, 5, 6), 0x1AC6_20A4);
        assert_eq!(lsrv_w(4, 5, 6), 0x1AC6_24A4);
        assert_eq!(asrv_w(4, 5, 6), 0x1AC6_28A4);
        // loads/stores
        assert_eq!(ldr_x(0, 1, 8), 0xF940_0420);
        assert_eq!(ldr_w(0, 1, 8), 0xB940_0820);
        assert_eq!(ldrh_w(2, 3, 4), 0x7940_0862);
        assert_eq!(ldrb_w(4, 5, 6), 0x3940_18A4);
        assert_eq!(str_x(6, 7, 16), 0xF900_08E6);
        assert_eq!(str_w(8, 9, 12), 0xB900_0D28);
        assert_eq!(strh_w(10, 11, 6), 0x7900_0D6A);
        assert_eq!(strb_w(12, 13, 6), 0x3900_19AC);
        // pairs
        assert_eq!(ldp_x_off(0, 1, 31, 2), 0xA941_07E0);
        assert_eq!(stp_x_off(19, 20, 31, 0), 0xA900_53F3);
        assert_eq!(ldp_x_off(19, 20, 31, 0), 0xA940_53F3);
        // misc
        assert_eq!(eor_self_x(16), 0xCA10_0210);
        assert_eq!(ADR_SELF, 0x1000_0000);
        assert_eq!(RET, 0xD65F_03C0);
        assert_eq!(NOP, 0xD503_201F);
        assert_eq!(BRK0, 0xD420_0000);
    }

    #[test]
    fn label_fixup_resolves_forward_branch() {
        let mut a = Asm::new();
        let l = a.label();
        a.fixup(FixupKind::Branch { base: 0x1400_0000 }, Target::Label(l));
        a.emit(0); // b l
        a.emit(NOP);
        a.bind(l);
        let words = a.finish_standalone().unwrap();
        assert_eq!(words[0], 0x1400_0002); // b .+8
    }

    #[test]
    fn unbound_label_is_a_named_error() {
        let mut a = Asm::new();
        let l = a.label();
        a.fixup(FixupKind::Branch { base: 0x1400_0000 }, Target::Label(l));
        a.emit(0);
        assert!(a.finish_standalone().is_err());
    }
}
