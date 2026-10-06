//! Per-instruction-class lift tests (task item 3): every §3.1 class is
//! hand-assembled from the shared encoder primitives (encoding round-trip
//! through the production decoder), lifted, and checked against a Rust
//! reference on the IR oracle. Fail-closed cases (§6.3 matrix cells and
//! whitelist rejections) assert the named errors.

use super::*;
use xenolith_vm::aarch64_asm::*;
use xenolith_vm::ir64::{eval_ir64, BIAS_SENTINEL, SP_SENTINEL};

const SEEDS: [(u64, u64); 32] = [
    (0, 0),
    (1, 1),
    (3, 4),
    (7, 7),
    (0xFF, 0x100),
    (0xFFFF, 1),
    (0xFFFF_FFFF, 2),
    (0x8000_0000, 1),
    (0x8000_0000_0000_0000, 3),
    (u64::MAX, u64::MAX),
    (0x1234_5678_9ABC_DEF0, 0x0F0F_0F0F_0F0F_0F0F),
    (0xDEAD_BEEF, 0xCAFE_BABE),
    (1, 0xFFFF_FFFF),
    (0x42, 0x42),
    (0x7FFF_FFFF, 1),
    (0x7FFF_FFFF_FFFF_FFFF, 1),
    (2, 63),
    (1, 31),
    (0x5555_5555_5555_5555, 2),
    (0xAAAA_AAAA_AAAA_AAAA, 4),
    (0x100, 8),
    (0x1000, 0x1000),
    (0x9E37_79B9_7F4A_7C15, 1),
    (0x1122_3344_5566_7788, 0x8877_6655_4433_2211),
    (0, 1),
    (1, 0),
    (0xFFFF_FFFF, 0x8000_0000),
    (0x8000_0000, 0x8000_0000),
    (0x3FFF_FFFF, 0x4000_0000),
    (0xC000_0000_0000_0000, 0x4000_0000_0000_0000),
    (0x10, u64::MAX),
    (0x0F0F, 0x7070),
];

fn lift_words(words: &[u32], name: &str) -> Ir64Module {
    let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    let (m, _) = lift_code64(&bytes, 0x1000, name).unwrap_or_else(|e| panic!("{name}: {e}"));
    m
}

fn check(words: &[u32], name: &str, reference: impl Fn(u64, u64) -> u64) {
    let m = lift_words(words, name);
    for &(x0, x1) in &SEEDS {
        let got = eval_ir64(&m, x0, x1).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        let want = reference(x0, x1);
        assert_eq!(got, want, "{name} ({x0:#x},{x1:#x})");
    }
}

fn must_fail(words: &[u32], name: &str, want_substr: &str) {
    let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    let err = lift_code64(&bytes, 0x1000, name).unwrap_err().0;
    assert!(err.contains(want_substr), "{name}: {err}");
}

fn b_cond(cond: u32, byte_off: i32) -> u32 {
    let o = ((byte_off / 4) as u32) & 0x7_FFFF;
    0x5400_0000 | (o << 5) | cond
}

fn b_to(byte_off: i32) -> u32 {
    let o = ((byte_off / 4) as u32) & 0x03FF_FFFF;
    0x1400_0000 | o
}

// ---- class 1: add/sub immediate (incl. <<12) ----

#[test]
fn class1_add_sub_imm() {
    check(
        &[
            add_x_imm(0, 0, 0x123),  // add x0,x0,#0x123
            sub_x_imm(0, 0, 0x45),   // sub x0,x0,#0x45
            add_w_imm(0, 0, 0x100),  // add w0,w0,#0x100 (W zero-extends)
            sub_w_imm(0, 0, 0x40),   // sub w0,w0,#0x40
            RET,
        ],
        "addsub-imm",
        |x, _| {
            let v = x.wrapping_add(0x123).wrapping_sub(0x45);
            let w = (v as u32).wrapping_add(0x100).wrapping_sub(0x40);
            w as u64
        },
    );
    // imm12 << 12 variant: add x0,x0,#1,lsl#12 (0xD1400462 shape with rd/rn 0)
    check(
        &[0x9140_0400, RET],
        "add-imm-sh12",
        |x, _| x.wrapping_add(0x1000),
    );
}

// ---- class 2: add/sub register (pure, shifted, extended) ----

#[test]
fn class2_add_sub_reg() {
    check(
        &[
            add_x_reg(0, 0, 1), // add x0,x0,x1
            RET,
        ],
        "add-reg",
        |x, y| x.wrapping_add(y),
    );
    check(
        &[sub_x_reg(0, 0, 1), RET],
        "sub-reg",
        |x, y| x.wrapping_sub(y),
    );
    // shifted: add x0,x0,x1,lsl #3 (imm6=3)
    check(
        &[0x8B01_0C00, RET], // add x0,x0,x1,lsl#3
        "add-reg-lsl",
        |x, y| x.wrapping_add(y << 3),
    );
    // W-form imm6=31 boundary (0x0B027C20 with rd/rn adapted)
    check(
        &[0x0B01_7C00, RET], // add w0,w0,w1,lsl#31
        "add-w-lsl31",
        |x, y| ((x as u32).wrapping_add((y as u32) << 31)) as u64,
    );
    // extended: add x0,x0,x1,uxtx (8b216000 shape)
    check(
        &[0x8B21_6000, RET], // add x0,x0,x1,uxtx
        "add-ext-uxtx",
        |x, y| x.wrapping_add(y),
    );
    // extended: add x0,x0,w1,sxtw#2 (8b21c800 shape)
    check(
        &[0x8B21_C800 | 0, RET],
        "add-ext-sxtw2",
        |x, y| {
            let sext = ((y as u32) as i32) as i64;
            x.wrapping_add((sext.wrapping_shl(2)) as u64)
        },
    );
    // W-form imm6=32 is UNDEFINED: named reject
    must_fail(&[0x0B01_8000, RET], "w-imm6-32", "UNDEFINED");
}

// ---- class 3/4: logic register + bitmask immediates ----

#[test]
fn class3_4_logic() {
    for (word, name, f) in [
        (and_x_reg(0, 0, 1), "and", (|x: u64, y: u64| x & y) as fn(u64, u64) -> u64),
        (orr_x_reg(0, 0, 1), "orr", (|x: u64, y: u64| x | y) as fn(u64, u64) -> u64),
        (eor_x_reg(0, 0, 1), "eor", (|x: u64, y: u64| x ^ y) as fn(u64, u64) -> u64),
    ] {
        check(&[word, RET], name, f);
    }
    // shifted logic: and x0,x0,x1,lsr #7
    check(
        &[0x8A41_1C00, RET],
        "and-lsr7",
        |x, y| x & (y >> 7),
    );
    // bitmask immediates: and x0,x0,#0xff / eor x0,x0,#0xfff / orr x0,x0,#..
    check(
        &[0x9240_0000 | (0 << 16) | (7 << 10), RET], // and x0,x0,#0xff
        "and-imm-ff",
        |x, _| x & 0xFF,
    );
    check(
        &[0xD240_0000 | (0 << 16) | (11 << 10), RET], // eor x0,x0,#0xfff
        "eor-imm-fff",
        |x, _| x ^ 0xFFF,
    );
    // W bitmask: and w0,w0,#0xff
    check(
        &[0x1200_1C00, RET],
        "and-w-imm",
        |x, _| (x as u32 & 0xFF) as u64,
    );
}

// ---- class 5: adds/subs/cmp/cmn/tst + b.cond (§6.3 matrix) ----

#[test]
fn class5_subs_cmp_all_predicates() {
    // cmp x0,x1; b.<cond> then1 else2 — exercises the full-precision row.
    for (cond, name, f) in [
        (0u32, "eq", (|a: u64, b: u64| a == b) as fn(u64, u64) -> bool),
        (1, "ne", (|a: u64, b: u64| a != b) as fn(u64, u64) -> bool),
        (2, "hs", (|a: u64, b: u64| a >= b) as fn(u64, u64) -> bool),
        (3, "lo", (|a: u64, b: u64| a < b) as fn(u64, u64) -> bool),
        (8, "hi", (|a: u64, b: u64| a > b) as fn(u64, u64) -> bool),
        (9, "ls", (|a: u64, b: u64| a <= b) as fn(u64, u64) -> bool),
        (10, "ge", (|a: u64, b: u64| (a as i64) >= (b as i64)) as fn(u64, u64) -> bool),
        (11, "lt", (|a: u64, b: u64| (a as i64) < (b as i64)) as fn(u64, u64) -> bool),
        (12, "gt", (|a: u64, b: u64| (a as i64) > (b as i64)) as fn(u64, u64) -> bool),
        (13, "le", (|a: u64, b: u64| (a as i64) <= (b as i64)) as fn(u64, u64) -> bool),
    ] {
        // cmp x0,x1 ; b.cond +2 ; movz x0,#1 ; ret ; movz x0,#2 ; ret
        let words = [
            cmp_x_reg(0, 1),
            b_cond(cond, 12),
            movz_x(0, 1),
            RET,
            movz_x(0, 2),
            RET,
        ];
        check(&words, name, move |x, y| if f(x, y) { 2 } else { 1 });
    }
}

#[test]
fn class5_cmp_imm() {
    // cmp x0,#0x10; b.hs +2; 1; ret; 2; ret
    let words = [
        cmp_x_imm(0, 0x10),
        b_cond(2, 12),
        movz_x(0, 1),
        RET,
        movz_x(0, 2),
        RET,
    ];
    check(&words, "cmp-imm-hs", |x, _| if x >= 0x10 { 2 } else { 1 });
}

#[test]
fn class5_cmn_imm_full_precision() {
    // cmn x0,x1-imm (#1): hardware adds x0+1; compare view x0 == -1.
    // All ten predicates are exact per §6.3.
    for (cond, f) in [
        (0u32, (|a: u64| a == 0xFFFF_FFFF_FFFF_FFFF) as fn(u64) -> bool),
        (1, (|a: u64| a != 0xFFFF_FFFF_FFFF_FFFF) as fn(u64) -> bool),
        (2, (|a: u64| a >= (-1i64) as u64) as fn(u64) -> bool),
        (3, (|a: u64| a < (-1i64) as u64) as fn(u64) -> bool),
        (8, (|a: u64| a > (-1i64) as u64) as fn(u64) -> bool),
        (9, (|a: u64| a <= (-1i64) as u64) as fn(u64) -> bool),
        (10, (|a: u64| (a as i64) >= -1) as fn(u64) -> bool),
        (11, (|a: u64| (a as i64) < -1) as fn(u64) -> bool),
        (12, (|a: u64| (a as i64) > -1) as fn(u64) -> bool),
        (13, (|a: u64| (a as i64) <= -1) as fn(u64) -> bool),
    ] {
        // cmn x0,#1 ; b.cond +2 ; movz 1 ; ret ; movz 2 ; ret
        let words = [
            0xB100_041F, // cmn x0,#1 (Rd=31)
            b_cond(cond, 12),
            movz_x(0, 1),
            RET,
            movz_x(0, 2),
            RET,
        ];
        check(&words, "cmn-imm", move |x, _| if f(x) { 2 } else { 1 });
    }
}

#[test]
fn class5_cmn_reg_eq_ne_only() {
    // cmn x0,x1; b.eq +2; 1; ret; 2; ret — Z ⟺ x0+x1 == 0
    let words = [
        0xAB01_001F, // cmn x0,x1
        b_cond(0, 12),
        movz_x(0, 1),
        RET,
        movz_x(0, 2),
        RET,
    ];
    check(&words, "cmn-reg-eq", |x, y| {
        if x.wrapping_add(y) == 0 { 2 } else { 1 }
    });
    let words = [
        0xAB01_001F,
        b_cond(1, 12),
        movz_x(0, 1),
        RET,
        movz_x(0, 2),
        RET,
    ];
    check(&words, "cmn-reg-ne", |x, y| {
        if x.wrapping_add(y) != 0 { 2 } else { 1 }
    });
    // §6.3 rejection cells: cmn reg + ordered predicate
    must_fail(
        &[0xAB01_001F, b_cond(2, 12), movz_x(0, 1), RET, RET, RET],
        "cmn-reg-hs",
        "not provably exact",
    );
    // adds reg + ge (V corner)
    must_fail(
        &[0xAB00_0000, b_cond(10, 8), movz_x(0, 1), RET],
        "adds-reg-ge",
        "not provably exact",
    );
    // cmn imm = 0 is decoder-rejected (C corner)
    must_fail(&[0xB100_001F, RET], "cmn-imm0", "immediate 0");
}

#[test]
fn class5_tst_ands_predicates() {
    // tst x0,x1; b.eq — Z ⟺ x0&x1 == 0
    for (cond, f) in [
        (0u32, (|v: u64| v == 0) as fn(u64) -> bool),
        (1, (|v: u64| v != 0) as fn(u64) -> bool),
        (10, (|v: u64| (v as i64) >= 0) as fn(u64) -> bool),
        (11, (|v: u64| (v as i64) < 0) as fn(u64) -> bool),
        (12, (|v: u64| (v as i64) > 0) as fn(u64) -> bool),
        (13, (|v: u64| (v as i64) <= 0) as fn(u64) -> bool),
    ] {
        let words = [
            0xEA01_001F, // tst x0,x1
            b_cond(cond, 12),
            movz_x(0, 1),
            RET,
            movz_x(0, 2),
            RET,
        ];
        check(&words, "tst", move |x, y| if f(x & y) { 2 } else { 1 });
    }
    // hs after tst is the C-corner rejection (§6.3)
    must_fail(
        &[0xEA01_003F, b_cond(2, 12), movz_x(0, 1), RET, RET, RET],
        "tst-hs",
        "not exact",
    );
    // tst x0,#0xff (immediate form) + eq
    let words = [
        0xF240_0000 | (0 << 16) | (7 << 10) | 0x1F, // tst x0,#0xff
        b_cond(0, 12),
        movz_x(0, 1),
        RET,
        movz_x(0, 2),
        RET,
    ];
    check(&words, "tst-imm-eq", |x, _| if x & 0xFF == 0 { 2 } else { 1 });
    // ands value write: ands x2,x0,x1; b.eq; 1;ret;2;ret with x2 discarded?
    // ands x2 keeps its value: ands x2,x0,x1; mov x0,x2; ret
    check(
        &[0xEA01_0002, mov_x(0, 2), RET], // ands x2,x0,x1
        "ands-value",
        |x, y| x & y,
    );
}

#[test]
fn class5_unfused_producer_fails() {
    // cmp x0,x1; nop; b.eq — nop clears the fusion
    must_fail(
        &[cmp_x_reg(0, 1), NOP, b_cond(0, 12), movz_x(0, 1), RET, RET],
        "unfused",
        "adjacent flags producer",
    );
    // b.cond with no producer at all
    must_fail(&[b_cond(0, 4), RET], "no-producer", "adjacent flags producer");
    // stacked producers
    must_fail(
        &[cmp_x_reg(0, 1), cmp_x_reg(0, 1), b_cond(0, 12), RET, RET, RET],
        "stacked",
        "stacked",
    );
}

// ---- class 6/7: shifts ----

#[test]
fn class6_shift_aliases() {
    check(&[lsl_x_imm(0, 0, 5), RET], "lsl5", |x, _| x << 5);
    check(&[lsr_x_imm(0, 0, 5), RET], "lsr5", |x, _| x >> 5);
    check(&[asr_x_imm(0, 0, 7), RET], "asr7", |x, _| ((x as i64) >> 7) as u64);
    check(&[lsl_w_imm(0, 0, 31), RET], "lslw31", |x, _| ((x as u32) << 31) as u64);
    check(&[lsr_w_imm(0, 0, 1), RET], "lsrw1", |x, _| ((x as u32) >> 1) as u64);
    check(&[asr_w_imm(0, 0, 3), RET], "asrw3", |x, _| {
        (((x as u32) as i32) >> 3) as u32 as u64
    });
    // LSL #0 / LSR #0 / ASR #0 = MOV alias words
    check(&[ubfm_mov_x(0, 1), RET], "mov-alias-x", |_, y| y);
    check(&[ubfm_mov_w(0, 1), RET], "mov-alias-w", |_, y| (y as u32) as u64);
    // non-alias bitfield: named reject
    must_fail(&[0xD340_0000 | (5 << 16) | (5 << 10), RET], "bfm", "non-alias");
}

#[test]
fn class7_variable_shifts() {
    check(&[lslv_x(0, 0, 1), RET], "lslv", |x, y| x.wrapping_shl(y as u32 & 63));
    check(&[lsrv_x(0, 0, 1), RET], "lsrv", |x, y| x.wrapping_shr(y as u32 & 63));
    check(&[asrv_x(0, 0, 1), RET], "asrv", |x, y| {
        ((x as i64).wrapping_shr(y as u32 & 63)) as u64
    });
    check(&[lslv_w(0, 0, 1), RET], "lslv-w", |x, y| {
        ((x as u32).wrapping_shl(y as u32 & 31)) as u64
    });
}

// ---- class 8: movz/movk/mov ----

#[test]
fn class8_movz_movk_mov() {
    check(&[movz_x(0, 0x1234), RET], "movz", |_, _| 0x1234);
    check(&[movz_w(0, 0x1234), RET], "movz-w", |_, _| 0x1234);
    // movz + movk lane merge
    check(
        &[
            movz_x(2, 0x1234),         // x2 = 0x1234
            movk_x(2, 0x5678, 1),      // x2 = 0x5678_1234
            movk_x(2, 0x9ABC, 2),      // x2 = 0x9ABC_5678_1234
            mov_x(0, 2),
            RET,
        ],
        "movk-merge",
        |_, _| 0x9ABC_5678_1234,
    );
    // W movk discards the upper half
    check(
        &[
            movz_x(2, 0xFFFF) | (3 << 21), // movz x2,#0xFFFF,lsl#48
            movk_w(2, 0x1234, 1), // w2 = (w2 & ~0x0FFF0000)|0x1234_0000, zero-extended
            mov_x(0, 2),
            RET,
        ],
        "movk-w",
        |_, _| 0x1234_0000, // W movk zero-extends: the upper half is discarded
    );
}

// ---- class 9/10: b / b.cond CFG ----

#[test]
fn class9_b_cfg() {
    // b +2; ret(1); movz 7; ret — unconditional b skips
    check(
        &[b_to(8), RET, movz_x(0, 7), RET],
        "b",
        |_, _| 7,
    );
}

// ---- class 11/12: cbz/cbnz/tbz/tbnz ----

#[test]
fn class11_cbz_cbnz() {
    let words = [
        0xB400_0060, // cbz x0, +12
        movz_x(0, 1),
        RET,
        movz_x(0, 2),
        RET,
    ];
    check(&words, "cbz-x", |x, _| if x == 0 { 2 } else { 1 });
    // cbnz w1 (35000041 with our offsets)
    let words = [
        0x3500_0061, // cbnz w1,+12
        movz_x(0, 1),
        RET,
        movz_x(0, 2),
        RET,
    ];
    check(&words, "cbnz-w", |_, y| if (y as u32) != 0 { 2 } else { 1 });
}

#[test]
fn class12_tbz_tbnz() {
    // tbz x0,#3,+8 → taken iff bit3 clear
    let words = [
        0x3600_0000 | (3 << 19) | (3 << 5), // tbz x0,#3,+12
        movz_x(0, 1),
        RET,
        movz_x(0, 2),
        RET,
    ];
    check(&words, "tbz3", |x, _| if x & 8 == 0 { 2 } else { 1 });
    // tbnz x0,#63,+8 → taken iff sign bit set
    let words = [
        0xB700_0000 | (31 << 19) | (3 << 5), // tbnz x0,#63,+12
        movz_x(0, 1),
        RET,
        movz_x(0, 2),
        RET,
    ];
    check(&words, "tbnz63", |x, _| if x >> 63 == 1 { 2 } else { 1 });
    // tbz w0,#31 (b5=0 form)
    let words = [
        0x3600_0000 | (31 << 19) | (3 << 5),
        movz_x(0, 1),
        RET,
        movz_x(0, 2),
        RET,
    ];
    check(&words, "tbz-w31", |x, _| if (x as u32) >> 31 == 0 { 2 } else { 1 });
}

// ---- class 14: ldr/str ----

#[test]
fn class14_ldr_str() {
    // str x1,[x0]; ldrb w2,[x0]; ldrh w3,[x0,#2]... via pointer arg
    let m = lift_words(
        &[
            str_x(1, 0, 0),   // str x1,[x0]
            ldrb_w(2, 0, 0),  // ldrb w2,[x0]
            ldrh_w(3, 0, 2),  // ldrh w3,[x0,#2]
            ldr_w(4, 0, 4),   // ldr w4,[x0,#4]
            ldr_x(5, 0, 0),   // ldr x5,[x0]
            eor_x_reg(2, 2, 3),
            add_x_reg(2, 2, 4),
            add_x_reg(0, 2, 5),
            RET,
        ],
        "ldst",
    );
    for &(x0, x1) in &SEEDS[..8] {
        let mut st = xenolith_vm::ir64::Machine64::entry(x0, x1);
        let v = xenolith_vm::ir64::eval_machine64(&m, &mut st).unwrap();
        let want = ((x1 & 0xFF) ^ ((x1 >> 16) & 0xFFFF))
            .wrapping_add((x1 >> 32) & 0xFFFF_FFFF)
            .wrapping_add(x1);
        assert_eq!(v, want, "ldst ({x0:#x},{x1:#x})");
    }
}

// ---- class 15: ldp/stp with sp ----

#[test]
fn class15_stp_ldp_sp() {
    // sub sp,sp,#32; str x0,[sp]; str x1,[sp,#8]; ldr x2,[sp];
    // ldr x3,[sp,#8]; add sp,sp,#32; add x0,x2,x3; ret
    let m = lift_words(
        &[
            sub_x_imm(31, 31, 32),
            str_x(0, 31, 0),
            str_x(1, 31, 8),
            ldr_x(2, 31, 0),
            ldr_x(3, 31, 8),
            add_x_imm(31, 31, 32),
            add_x_reg(0, 2, 3),
            RET,
        ],
        "sp-ldst",
    );
    for &(x0, x1) in &SEEDS[..8] {
        let v = eval_ir64(&m, x0, x1).unwrap();
        assert_eq!(v, x0.wrapping_add(x1));
    }
    // pre-index stp + post-index ldp (design §3.1#15 decomposition)
    // stp x0,x1,[sp,#-16]! ; ldp x2,x3,[sp],#16 ; add x0,x2,x3 ; ret
    let m = lift_words(
        &[
            0xA980_0000 | (0x7E << 15) | (1 << 10) | (31 << 5), // stp x0,x1,[sp,#-16]!
            0xA8C0_0000 | (2 << 15) | (3 << 10) | (31 << 5) | 2, // ldp x2,x3,[sp],#16
            add_x_reg(0, 2, 3),
            RET,
        ],
        "stp-pre-ldp-post",
    );
    for &(x0, x1) in &SEEDS[..8] {
        let mut st = xenolith_vm::ir64::Machine64::entry(x0, x1);
        let v = xenolith_vm::ir64::eval_machine64(&m, &mut st).unwrap();
        assert_eq!(v, x0.wrapping_add(x1), "pre/post");
        assert_eq!(st.gpr[31], SP_SENTINEL, "SP restored");
    }
    // writeback pair on a non-SP base: named reject
    must_fail(
        &[0xA980_0000 | (0x7E << 15) | (1 << 10) | (2 << 5), RET],
        "wb-nonsp",
        "writeback ldp/stp on a non-SP base",
    );
}

// ---- class 16: adr/adrp ----

#[test]
fn class16_adr_adrp() {
    // adr x2, .+8 ; add x0,x0,x2 ; ret — Bias = BIAS_SENTINEL + (0x1000+8)
    // adr off=+8: immlo=0, immhi=8>>2=2
    let adr = 0x1000_0000u32 | (0u32 << 29) | (2u32 << 5) | 2;
    let m = lift_words(&[adr, add_x_reg(0, 0, 2), RET], "adr");
    let v = eval_ir64(&m, 5, 0).unwrap();
    assert_eq!(v, 5u64.wrapping_add(BIAS_SENTINEL).wrapping_add(0x1008));
    // adrp x2, .+0x1000: imm21=1 → immlo=1, immhi=0; pc page of 0x1000 is 0.
    let adrp = 0x9000_0000u32 | (1u32 << 29) | (0u32 << 5) | 2;
    let m = lift_words(&[adrp, add_x_reg(0, 0, 2), RET], "adrp");
    let v = eval_ir64(&m, 5, 0).unwrap();
    assert_eq!(v, 5u64.wrapping_add(BIAS_SENTINEL).wrapping_add(0x2000));
}

// ---- class 17 + SP/x18/call fail-closed ----

#[test]
fn class17_nop_and_sp_mov() {
    check(&[NOP, add_x_reg(0, 0, 1), NOP, RET], "nop", |x, y| x.wrapping_add(y));
    // mov x0,sp reads the SP sentinel
    let m = lift_words(&[add_x_imm(0, 31, 0), RET], "mov-sp");
    let v = eval_ir64(&m, 0, 0).unwrap();
    assert_eq!(v, SP_SENTINEL);
}

#[test]
fn sp_whitelist_rejections() {
    // orr x0,xzr,sp — logic with SP (decoder maps SP only in specific
    // fields, this word uses the extended add family instead) — craft:
    // add x0,sp,x1 via extended form (SP as ext source)
    must_fail(
        &[0x8B21_63E0, RET], // add x0,sp,x1,uxtx — SP as extended source
        "sp-ext",
        "SP as extended-register source",
    );
    // `add sp,x1,x2` (extended form, golden 0x8b22603f): SP destination
    // outside the imm whitelist
    must_fail(&[0x8B22_603F, RET], "sp-dst", "SP as extended-register destination");
}

#[test]
fn x18_and_calls_fail_closed() {
    must_fail(&[add_x_reg(18, 18, 0), RET], "x18", "x18");
    must_fail(&[0x9400_0002, RET], "bl", "not in the first-batch");
    // ldr x18,[x0]
    must_fail(&[ldr_x(18, 0, 0), RET], "x18-ldr", "x18");
}

#[test]
fn out_of_window_branch_fails_named() {
    // b far out of the 256-byte window
    must_fail(&[b_to(200), RET], "oob", "out of lift window");
}

#[test]
fn unsupported_cond_fails_named() {
    must_fail(
        &[cmp_x_reg(0, 1), b_cond(4, 12), movz_x(0, 1), RET],
        "b.mi",
        "b.mi",
    );
}

#[test]
fn selects_over_scratch_shortage() {
    // Using every vreg but one starves the scratch for a shifted operand.
    let mut words = Vec::new();
    // Pin every reg except x18 (the lifter excludes 18/30 from scratch duty
    // — 30 by the LR reserve, 18 by the platform rule).
    for r in 0u32..31 {
        if r != 18 {
            words.push(movz_x(r, 1));
        }
    }
    // and x0,x1,x2,lsl #4 needs a scratch; vreg 30 is reserved → none left
    words.push(0x8A02_1020);
    words.push(RET);
    must_fail(&words, "no-scratch", "spare vreg");
}
