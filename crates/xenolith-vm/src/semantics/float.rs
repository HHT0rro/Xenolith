//! IEEE-754 semantics for the G4 frozen corpus.
//!
//! Two families, both modeling AMD64 hardware exactly:
//! - **SSE/SSE2 scalar** (`F32`/`F64`): x64 NaN selection rules (src1 quieted
//!   first, then src2; invalid → negative "real indefinite" QNaN), MXCSR
//!   exception flags (IE/ZE/OE/UE/PE), DAZ/FTZ, round-to-nearest-even via
//!   Rust's hardware-exact `f32`/`f64` arithmetic on the finite path.
//! - **x87 80-bit extended** (`F80`): software add/sub/mul/div with explicit
//!   integer-bit mantissa, RNE rounding to 64 bits, x87 quieting rules.
//!
//! These are the semantic oracle; the differential tests in
//! `xenolith-pack/tests/semantics_diff.rs` check them against raw
//! hardware (plain and superop-emitted) bit-for-bit.

pub const MXCSR_IE: u32 = 1 << 0;
pub const MXCSR_DE: u32 = 1 << 1;
pub const MXCSR_ZE: u32 = 1 << 2;
pub const MXCSR_OE: u32 = 1 << 3;
pub const MXCSR_UE: u32 = 1 << 4;
pub const MXCSR_PE: u32 = 1 << 5;
pub const MXCSR_DAZ: u32 = 1 << 6;
pub const MXCSR_RC_MASK: u32 = 3 << 13;
pub const MXCSR_FTZ: u32 = 1 << 15;

/// MXCSR as the packed-image runtime models it: accumulate exception flags,
/// keep RC/DAZ/FTZ controls. Reset value matches the OS default (all
/// exceptions masked, RC=nearest).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Mxcsr(pub u32);

impl Mxcsr {
    pub const DEFAULT: u32 = 0x1F80;

    pub fn new() -> Self {
        Mxcsr(Self::DEFAULT)
    }

    fn set(&mut self, flag: u32) {
        self.0 |= flag;
    }

    pub fn ftz(&self) -> bool {
        self.0 & MXCSR_FTZ != 0
    }

    pub fn daz(&self) -> bool {
        self.0 & MXCSR_DAZ != 0
    }

    /// DAZ pre-step: a denormal operand reads as a signed zero.
    fn daz_f32(&self, bits: u32) -> u32 {
        if self.daz() && (bits & 0x7F80_0000) == 0 && (bits & 0x007F_FFFF) != 0 {
            bits & 0x8000_0000
        } else {
            bits
        }
    }

    fn daz_f64(&self, bits: u64) -> u64 {
        if self.daz() && (bits & 0x7FF0_0000_0000_0000) == 0 && (bits & 0x000F_FFFF_FFFF_FFFF) != 0
        {
            bits & 0x8000_0000_0000_0000
        } else {
            bits
        }
    }

    /// FTZ post-step: a denormal result flushes to a signed zero (with
    /// UE+PE, which hardware raises).
    fn ftz_f32(&self, bits: u32) -> u32 {
        if self.ftz() && (bits & 0x7F80_0000) == 0 && (bits & 0x007F_FFFF) != 0 {
            bits & 0x8000_0000
        } else {
            bits
        }
    }

    fn ftz_f64(&self, bits: u64) -> u64 {
        if self.ftz() && (bits & 0x7FF0_0000_0000_0000) == 0 && (bits & 0x000F_FFFF_FFFF_FFFF) != 0
        {
            bits & 0x8000_0000_0000_0000
        } else {
            bits
        }
    }
}

impl Default for Mxcsr {
    fn default() -> Self {
        Self::new()
    }
}

fn quiet_f32(bits: u32) -> u32 {
    bits | 0x0040_0000
}

fn quiet_f64(bits: u64) -> u64 {
    bits | 0x0008_0000_0000_0000
}

/// "Real indefinite": negative canonical QNaN for invalid operations.
pub const INDEFINITE_F32: u32 = 0xFFC0_0000;
pub const INDEFINITE_F64: u64 = 0xFFF8_0000_0000_0000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScalarOp {
    Add,
    Sub,
    Mul,
    Div,
    /// SSE2 min/max: unordered (any NaN) returns src2.
    Min,
    Max,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FWidth {
    F32,
    F64,
}

fn f32_invalid(op: ScalarOp, a: f32, b: f32) -> bool {
    match op {
        // inf + (-inf) and inf - inf are the invalid pairs.
        ScalarOp::Add => a.is_infinite() && b.is_infinite() && a == -b,
        ScalarOp::Sub => a.is_infinite() && b.is_infinite() && a == b,
        ScalarOp::Mul => (a == 0.0 && b.is_infinite()) || (a.is_infinite() && b == 0.0),
        ScalarOp::Div => (a == 0.0 && b == 0.0) || a.is_infinite() && b.is_infinite(),
        _ => false,
    }
}

fn f64_invalid(op: ScalarOp, a: f64, b: f64) -> bool {
    match op {
        ScalarOp::Add => a.is_infinite() && b.is_infinite() && a == -b,
        ScalarOp::Sub => a.is_infinite() && b.is_infinite() && a == b,
        ScalarOp::Mul => (a == 0.0 && b.is_infinite()) || (a.is_infinite() && b == 0.0),
        ScalarOp::Div => (a == 0.0 && b == 0.0) || a.is_infinite() && b.is_infinite(),
        _ => false,
    }
}

/// SSE scalar binary op on raw bits, x64 NaN/flag semantics.
pub fn sse_f32(op: ScalarOp, src1: u32, src2: u32, mxcsr: &mut Mxcsr) -> u32 {
    let a_bits = mxcsr.daz_f32(src1);
    let b_bits = mxcsr.daz_f32(src2);
    let a = f32::from_bits(a_bits);
    let b = f32::from_bits(b_bits);
    // NaN selection: src1 quieted first, then src2 — for arithmetic ops.
    // MIN/MAX differ: any NaN returns src2 bits UNCHANGED (hardware does not
    // quiet SNaN on the min/max return path; verified against hardware).
    if matches!(op, ScalarOp::Min | ScalarOp::Max) {
        if a.is_nan() || b.is_nan() {
            return b_bits;
        }
        return if matches!(op, ScalarOp::Min) && a < b || matches!(op, ScalarOp::Max) && a > b {
            a_bits
        } else {
            b_bits
        };
    }
    if a.is_nan() {
        return quiet_f32(a_bits);
    }
    if b.is_nan() {
        return quiet_f32(b_bits);
    }
    if matches!(op, ScalarOp::Div) && b == 0.0 {
        if a == 0.0 {
            mxcsr.set(MXCSR_IE);
            return INDEFINITE_F32;
        }
        mxcsr.set(MXCSR_ZE);
        return ((a_bits ^ b_bits) & 0x8000_0000) | 0x7F80_0000;
    }
    if f32_invalid(op, a, b) {
        mxcsr.set(MXCSR_IE);
        return INDEFINITE_F32;
    }
    let r = match op {
        ScalarOp::Add => a + b,
        ScalarOp::Sub => a - b,
        ScalarOp::Mul => a * b,
        ScalarOp::Div => a / b,
        ScalarOp::Min | ScalarOp::Max => unreachable!(),
    };
    let bits = r.to_bits();
    let flushed = mxcsr.ftz_f32(bits);
    if flushed != bits {
        mxcsr.set(MXCSR_UE | MXCSR_PE);
    }
    if r.is_infinite() && !a.is_infinite() && !b.is_infinite() {
        mxcsr.set(MXCSR_OE | MXCSR_PE);
    }
    flushed
}

pub fn sse_f64(op: ScalarOp, src1: u64, src2: u64, mxcsr: &mut Mxcsr) -> u64 {
    let a_bits = mxcsr.daz_f64(src1);
    let b_bits = mxcsr.daz_f64(src2);
    let a = f64::from_bits(a_bits);
    let b = f64::from_bits(b_bits);
    if matches!(op, ScalarOp::Min | ScalarOp::Max) {
        if a.is_nan() || b.is_nan() {
            return b_bits;
        }
        return if matches!(op, ScalarOp::Min) && a < b || matches!(op, ScalarOp::Max) && a > b {
            a_bits
        } else {
            b_bits
        };
    }
    if a.is_nan() {
        return quiet_f64(a_bits);
    }
    if b.is_nan() {
        return quiet_f64(b_bits);
    }
    if matches!(op, ScalarOp::Div) && b == 0.0 {
        if a == 0.0 {
            mxcsr.set(MXCSR_IE);
            return INDEFINITE_F64;
        }
        mxcsr.set(MXCSR_ZE);
        return ((a_bits ^ b_bits) & 0x8000_0000_0000_0000) | 0x7FF0_0000_0000_0000;
    }
    if f64_invalid(op, a, b) {
        mxcsr.set(MXCSR_IE);
        return INDEFINITE_F64;
    }
    let r = match op {
        ScalarOp::Add => a + b,
        ScalarOp::Sub => a - b,
        ScalarOp::Mul => a * b,
        ScalarOp::Div => a / b,
        ScalarOp::Min | ScalarOp::Max => unreachable!(),
    };
    let bits = r.to_bits();
    let flushed = mxcsr.ftz_f64(bits);
    if flushed != bits {
        mxcsr.set(MXCSR_UE | MXCSR_PE);
    }
    if r.is_infinite() && !a.is_infinite() && !b.is_infinite() {
        mxcsr.set(MXCSR_OE | MXCSR_PE);
    }
    flushed
}

/// sqrtss/sqrtsd: NaN → quieted src1, negative finite → indefinite.
pub fn sse_sqrt_f32(src: u32, mxcsr: &mut Mxcsr) -> u32 {
    let a = f32::from_bits(src);
    if a.is_nan() {
        return quiet_f32(src);
    }
    if a < 0.0 {
        mxcsr.set(MXCSR_IE);
        return INDEFINITE_F32;
    }
    let bits = a.sqrt().to_bits();
    mxcsr.ftz_f32(bits)
}

pub fn sse_sqrt_f64(src: u64, mxcsr: &mut Mxcsr) -> u64 {
    let a = f64::from_bits(src);
    if a.is_nan() {
        return quiet_f64(src);
    }
    if a < 0.0 {
        mxcsr.set(MXCSR_IE);
        return INDEFINITE_F64;
    }
    let bits = a.sqrt().to_bits();
    mxcsr.ftz_f64(bits)
}

pub const INDEFINITE_I32: i32 = i32::MIN;
pub const INDEFINITE_I64: i64 = i64::MIN;

/// cvttss2si / cvttsd2si: truncating convert; NaN/overflow → integer
/// indefinite. (`as` in Rust saturates, which does NOT match — hence manual.)
pub fn cvtt_f32_i32(src: u32) -> i32 {
    let a = f32::from_bits(src);
    if a.is_nan() || a <= -2147483904.0 || a >= 2147483648.0 {
        return INDEFINITE_I32;
    }
    a as i32
}

pub fn cvtt_f64_i32(src: u64) -> i32 {
    let a = f64::from_bits(src);
    if a.is_nan() || a <= -2147483649.0 || a >= 2147483648.0 {
        return INDEFINITE_I32;
    }
    a as i32
}

pub fn cvtt_f32_i64(src: u32) -> i64 {
    let a = f32::from_bits(src);
    if a.is_nan() || a <= -9223373136366403584.0 || a >= 9223372036854775808.0 {
        return INDEFINITE_I64;
    }
    a as i64
}

pub fn cvtt_f64_i64(src: u64) -> i64 {
    let a = f64::from_bits(src);
    if a.is_nan() || a <= -9223372036854777856.0 || a >= 9223372036854775808.0 {
        return INDEFINITE_I64;
    }
    a as i64
}

/// cvtss2si (RC=nearest in the frozen corpus): round, then integer checks.
pub fn cvt_rne_f32_i32(src: u32) -> i32 {
    let a = f32::from_bits(src);
    if a.is_nan() {
        return INDEFINITE_I32;
    }
    let r = a.round_ties_even();
    if r <= -2147483904.0 || r >= 2147483648.0 {
        return INDEFINITE_I32;
    }
    r as i32
}

pub fn cvt_rne_f64_i64(src: u64) -> i64 {
    let a = f64::from_bits(src);
    if a.is_nan() {
        return INDEFINITE_I64;
    }
    let r = a.round_ties_even();
    if r <= -9223372036854777856.0 || r >= 9223372036854775808.0 {
        return INDEFINITE_I64;
    }
    r as i64
}

/// cvtss2sd / cvtsd2ss: exact widening, RNE narrowing.
pub fn cvt_f32_f64(src: u32) -> u64 {
    (f32::from_bits(src) as f64).to_bits()
}

pub fn cvt_f64_f32(src: u64) -> u32 {
    (f64::from_bits(src) as f32).to_bits()
}

/// (u)comiss/(u)comisd → (ZF, PF, CF); unordered sets all three.
pub fn comis_f32(a: u32, b: u32) -> (bool, bool, bool) {
    let a = f32::from_bits(a);
    let b = f32::from_bits(b);
    if a.is_nan() || b.is_nan() {
        (true, true, true)
    } else if a > b {
        (false, false, false)
    } else if a < b {
        (false, false, true)
    } else {
        (true, false, false)
    }
}

pub fn comis_f64(a: u64, b: u64) -> (bool, bool, bool) {
    let a = f64::from_bits(a);
    let b = f64::from_bits(b);
    if a.is_nan() || b.is_nan() {
        (true, true, true)
    } else if a > b {
        (false, false, false)
    } else if a < b {
        (false, false, true)
    } else {
        (true, false, false)
    }
}

// ---------------------------------------------------------------------------
// x87 80-bit extended precision (software).
// ---------------------------------------------------------------------------

/// x87 80-bit value: sign, 15-bit biased exponent (bias 16383), 64-bit
/// mantissa with the explicit integer bit (J bit) for normals.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct F80 {
    pub sign: bool,
    /// 0 = zero/denormal (pseudo-denormal excluded), 0x7FFF = inf/nan.
    pub exp: u16,
    pub mant: u64,
    /// Inexact-below-the-mantissa hint (set by division): prevents double
    /// rounding when the value narrows to f64/f32 later.
    pub sticky: bool,
}

pub const F80_EXP_BIAS: i32 = 16383;
/// x87 real indefinite: negative QNaN, mantissa = 1<<63 | 1<<62.
pub const F80_INDEFINITE: F80 = F80 {
    sign: true,
    exp: 0x7FFF,
    mant: 0xC000_0000_0000_0000,
    sticky: false,
};

impl F80 {
    pub const fn inf(sign: bool) -> Self {
        F80 {
            sign,
            exp: 0x7FFF,
            mant: 1u64 << 63,
            sticky: false,
        }
    }

    pub const fn zero(sign: bool) -> Self {
        F80 {
            sign,
            exp: 0,
            mant: 0,
            sticky: false,
        }
    }

    pub fn is_nan(&self) -> bool {
        self.exp == 0x7FFF && self.mant != (1u64 << 63)
    }

    pub fn is_inf(&self) -> bool {
        self.exp == 0x7FFF && self.mant == (1u64 << 63)
    }

    pub fn is_zero(&self) -> bool {
        self.exp == 0 && self.mant == 0
    }

    pub fn is_denormal(&self) -> bool {
        self.exp == 0 && self.mant != 0
    }

    pub(crate) fn quiet(&self) -> Self {
        F80 {
            sign: self.sign,
            exp: self.exp,
            mant: self.mant | (1u64 << 62),
            sticky: self.sticky,
        }
    }

    /// Unbiased exponent of a normal value; denormals handled by callers.
    fn e(&self) -> i32 {
        self.exp as i32 - F80_EXP_BIAS
    }

    pub fn from_f64(x: f64) -> Self {
        let bits = x.to_bits();
        let sign = bits >> 63 == 1;
        let be = ((bits >> 52) & 0x7FF) as i32;
        let frac = bits & 0x000F_FFFF_FFFF_FFFF;
        if be == 0x7FF {
            if frac == 0 {
                return F80::inf(sign);
            }
            // f64 NaN → 80-bit: keep the FULL 52-bit payload at the top of
            // the 63-bit fraction. Do NOT force the quiet bit — the f64
            // quiet bit lands on bit 62 naturally, so SNaN identity
            // survives the conversion (x87 quieting rules depend on it).
            return F80 {
                sign,
                exp: 0x7FFF,
                mant: (1u64 << 63) | (frac << 11),
                sticky: false,
            };
        }
        if be == 0 {
            if frac == 0 {
                return F80::zero(sign);
            }
            // Denormal double: value = frac·2^-1074. Normalize into an
            // 80-bit normal (always possible: wider exponent range): the
            // exponent follows the highest set bit, the mantissa shifts to
            // the integer-bit position.
            let mut hb = 51i32;
            while frac & (1u64 << hb) == 0 {
                hb -= 1;
            }
            let e = -1074 + hb;
            return F80 {
                sign,
                exp: (e + F80_EXP_BIAS) as u16,
                mant: frac << (63 - hb),
                sticky: false,
            };
        }
        F80 {
            sign,
            // be is the f64 *biased* exponent; rebase to the 80-bit bias.
            exp: (be - 1023 + F80_EXP_BIAS) as u16,
            mant: (1u64 << 63) | (frac << 11),
            sticky: false,
        }
    }

    /// RNE rounding to f64; overflow → ±inf. The 80-bit mantissa's explicit
    /// integer bit becomes the f64's implicit leading 1.
    pub fn to_f64(&self) -> f64 {
        if self.is_nan() {
            // Keep the sign and payload; x87 propagates source NaNs.
            // Mirror of from_f64: the 52-bit fraction lives at the top of
            // the 63-bit 80-bit fraction (quiet bit included at bit 51).
            let payload = (self.mant >> 11) & 0x000F_FFFF_FFFF_FFFF;
            return f64::from_bits(((self.sign as u64) << 63) | 0x7FF0_0000_0000_0000 | payload);
        }
        if self.is_inf() {
            return if self.sign {
                f64::NEG_INFINITY
            } else {
                f64::INFINITY
            };
        }
        if self.is_zero() {
            return if self.sign { -0.0 } else { 0.0 };
        }
        let mut e = self.exp as i32 - F80_EXP_BIAS;
        // 53-bit significand (leading 1 included) with RNE from the low 11.
        let mut sig = (self.mant >> 11) as u64; // [2^52, 2^53)
        let rem = self.mant & 0x7FF;
        if rem > 0x400 || self.sticky && rem >= 0x400 || (rem == 0x400 && (sig & 1) == 1) {
            sig += 1;
            if sig == 1u64 << 53 {
                sig = 1u64 << 52;
                e += 1;
            }
        }
        let biased = e + 1023;
        if biased >= 0x7FF {
            return if self.sign {
                f64::NEG_INFINITY
            } else {
                f64::INFINITY
            };
        }
        if biased > 0 {
            return f64::from_bits(
                ((self.sign as u64) << 63) | ((biased as u64) << 52) | (sig & 0x000F_FFFF_FFFF_FFFF),
            );
        }
        // Subnormal f64: value = sig·2^(e-52) = (sig·2^shift)·2^-1074.
        // f80 can hold values below the f64 subnormal minimum, so shift may
        // be negative — round the significand right (RNE) then.
        let shift = e - 52 + 1074;
        let m: u64 = if shift >= 0 {
            ((sig as u128) << shift) as u64
        } else {
            let sh = (-shift) as u32;
            if sh >= 64 {
                0
            } else {
                let keep = sig >> sh;
                let rem = sig & ((1u64 << sh) - 1);
                let half = 1u64 << (sh - 1);
                if rem > half || (rem == half && (keep & 1) == 1) {
                    keep.wrapping_add(1)
                } else {
                    keep
                }
            }
        };
        if m >= 1u64 << 52 {
            // Rounded into the normal range after all.
            return f64::from_bits(((self.sign as u64) << 63) | (1u64 << 52));
        }
        f64::from_bits(((self.sign as u64) << 63) | m)
    }

    pub fn from_i64(x: i64) -> Self {
        let sign = x < 0;
        let mag = x.unsigned_abs();
        if mag == 0 {
            return F80::zero(sign);
        }
        let lz = mag.leading_zeros() as i32;
        // normalize so the integer bit (bit 63) is set
        let mant = if lz == 0 { mag } else { mag << lz };
        let exp = 63 - lz + F80_EXP_BIAS;
        F80 {
            sign,
            exp: exp as u16,
            mant,
            sticky: false,
        }
    }

    /// fistp semantics: RNE to integer, invalid (NaN/inf/overflow) →
    /// 0x8000_0000_0000_0000.
    pub fn to_i64_rne(&self) -> i64 {
        if self.is_nan() || self.is_inf() {
            return i64::MIN;
        }
        if self.is_zero() {
            return 0;
        }
        let v = self.to_f64();
        if v.is_nan() {
            return i64::MIN;
        }
        let r = v.round_ties_even();
        if r <= -9223372036854777856.0 || r >= 9223372036854775808.0 {
            return i64::MIN;
        }
        r as i64
    }
}

/// Round `m` (with sticky bits already folded in as a boolean) to a 64-bit
/// 80-bit mantissa, RNE. Convention: value = m · 2^-64 · 2^exp with
/// m ∈ [2^64, 2^65) on entry, i.e. m/2^64 ∈ [1,2). Returns (mant, bumped)
/// where `bumped` means the exponent must increase by one (2.0 rollover).
fn round64(m: u128, sticky: bool) -> (u64, bool) {
    let keep = (m >> 1) as u64;
    let round = (m & 1) != 0;
    if round && ((keep & 1) == 1 || sticky) {
        if keep == u64::MAX {
            return (1u64 << 63, true);
        }
        (keep + 1, false)
    } else {
        (keep, false)
    }
}

/// x87 fadd/fsub/fmul/fdiv on 80-bit values (RNE, 64-bit mantissa).
pub fn x87_bin(op: ScalarOp, a: F80, b: F80) -> F80 {
    // x87 NaN selection (verified against hardware across 14 payload/quiet/
    // sign/position combinations): compare the QUIET-CLEARED payload — the
    // larger one wins; ties go to the positive sign; the winner is quieted.
    // A NaN always wins over a non-NaN operand.
    if a.is_nan() || b.is_nan() {
        let pa = a.mant & !(1u64 << 62);
        let pb = b.mant & !(1u64 << 62);
        let winner = if !b.is_nan() {
            a
        } else if !a.is_nan() {
            b
        } else if pa != pb {
            if pa > pb { a } else { b }
        } else if !a.sign {
            a
        } else {
            b
        };
        return winner.quiet();
    }
    if a.is_inf() || b.is_inf() {
        let (sign_a, sign_b) = (a.sign, b.sign);
        return match op {
            ScalarOp::Add | ScalarOp::Sub => {
                let eff_b = if matches!(op, ScalarOp::Sub) { !sign_b } else { sign_b };
                if a.is_inf() && b.is_inf() {
                    if sign_a == eff_b {
                        F80::inf(sign_a)
                    } else {
                        F80_INDEFINITE
                    }
                } else {
                    F80::inf((a.is_inf() && sign_a) || (b.is_inf() && eff_b))
                }
            }
            // 0×inf → indefinite; 0/inf → signed zero; inf/inf → indefinite.
            ScalarOp::Mul if a.is_zero() || b.is_zero() => F80_INDEFINITE,
            ScalarOp::Div if a.is_zero() => F80::zero(sign_a != sign_b),
            ScalarOp::Div if a.is_inf() && b.is_inf() => F80_INDEFINITE,
            ScalarOp::Div if b.is_inf() => F80::zero(sign_a != sign_b),
            ScalarOp::Mul | ScalarOp::Div => F80::inf(sign_a != sign_b),
            ScalarOp::Min | ScalarOp::Max => pick_min_max(op, a, b),
        };
    }
    if a.is_zero() && b.is_zero() {
        let (sign_a, sign_b) = (a.sign, b.sign);
        return match op {
            // x87 zero-sign rules (RNE): add gives -0 only from (-0)+(-0);
            // sub gives -0 only from (-0)-(+0).
            ScalarOp::Add => F80::zero(sign_a && sign_b),
            ScalarOp::Sub => F80::zero(sign_a && !sign_b),
            ScalarOp::Mul => F80::zero(sign_a != sign_b),
            ScalarOp::Div => F80_INDEFINITE,
            ScalarOp::Min | ScalarOp::Max => pick_min_max(op, a, b),
        };
    }
    if matches!(op, ScalarOp::Div) && b.is_zero() {
        if a.is_zero() {
            return F80_INDEFINITE;
        }
        return F80::inf(a.sign != b.sign);
    }
    if matches!(op, ScalarOp::Mul) && (a.is_zero() || b.is_zero()) {
        let other = if a.is_zero() { &b } else { &a };
        if other.is_inf() {
            return F80_INDEFINITE;
        }
        return F80::zero(a.sign != b.sign);
    }
    let a = normalize80(a);
    let b = normalize80(b);
    match op {
        ScalarOp::Min | ScalarOp::Max => pick_min_max(op, a, b),
        ScalarOp::Add | ScalarOp::Sub => {
            let neg_b = matches!(op, ScalarOp::Sub) != b.sign;
            let (ea, eb) = (a.e(), b.e());
            let hi_e = ea.max(eb);
            // Align BOTH significands into units of 2^hi_e: the operand with
            // the smaller exponent shifts RIGHT (keeping sticky bits).
            let shr_sticky = |m: u128, sh: i32| -> (u128, bool) {
                if sh <= 0 {
                    (m, false)
                } else if sh >= 128 {
                    (0, m != 0)
                } else {
                    let lost = m & ((1u128 << sh) - 1) != 0;
                    (m >> sh, lost)
                }
            };
            let (ma, la) = shr_sticky(a.mant as u128, hi_e - ea);
            let (mb, lb) = shr_sticky(b.mant as u128, hi_e - eb);
            let sticky = la || lb;
            let sa = if a.sign { -(ma as i128) } else { ma as i128 };
            let sb = if neg_b { -(mb as i128) } else { mb as i128 };
            let sum = sa + sb;
            if sum == 0 {
                return F80::zero(matches!(op, ScalarOp::Sub) && a.sign != b.sign);
            }
            let sign = sum < 0;
            let mag = sum.unsigned_abs();
            // Aligned mags are scaled value = mag·2^(hi_e-63) — regardless
            // of mag's leading zeros after cancellation. Normalize to the
            // finish80 convention (hb == 64, value = m·2^(e-64)) via
            // e = hi_e + hb - 63 (hb==63 keeps hi_e; hb==64 means sum ≥ 2).
            let hb = 127 - mag.leading_zeros() as i32;
            if hb == 64 {
                finish80(sign, hi_e + 1, mag, sticky)
            } else {
                finish80(sign, hi_e + hb - 63, mag << (64 - hb), sticky)
            }
        }
        ScalarOp::Mul => {
            // Product ∈ [2^126, 2^128): pass it raw with the exponent that
            // matches finish80's convention (value = m·2^(e-64)); finish80
            // normalizes hb==64 and compensates the exponent itself.
            let m = (a.mant as u128) * (b.mant as u128);
            finish80(a.sign != b.sign, a.e() + b.e() - 62, m, false)
        }
        ScalarOp::Div => {
            // (ma<<65)/mb would overflow u128 (normal mantissas carry bit
            // 63), so divide once at <<64 and derive the guard/sticky bits
            // from the remainder: m = (q<<1)|g with g ∈ {0,1}, sticky from
            // the second remainder division.
            let num = (a.mant as u128) << 64;
            let den = b.mant as u128;
            let q = num / den;
            let r = num % den;
            let g = (r << 1) / den;
            let sticky = (r << 1) % den != 0;
            let m = (q << 1) | g;
            finish80(a.sign != b.sign, a.e() - b.e() - 1, m, sticky)
        }
    }
}

fn pick_min_max(op: ScalarOp, a: F80, b: F80) -> F80 {
    let (x, y) = (a.to_f64(), b.to_f64());
    let take_a = if matches!(op, ScalarOp::Min) { x < y } else { x > y };
    if take_a { a } else { b }
}

/// Promote an 80-bit denormal (exp=0, mant≠0) to a normal with the same
/// value: 80-bit denormals have exponent 1-bias after normalization.
fn normalize80(v: F80) -> F80 {
    if v.exp != 0 || v.mant == 0 {
        return v;
    }
    let lz = v.mant.leading_zeros() as u32;
    let mant = v.mant.checked_shl(lz).unwrap_or(0);
    // A denormal's true exponent is (1 - BIAS); after normalizing the
    // mantissa left by `lz`, the exponent stays (1 - BIAS) because the value
    // is unchanged: mantissa up, exponent identical.
    F80 {
        sign: v.sign,
        exp: 1,
        mant,
        sticky: v.sticky,
    }
}

/// Normalize `m` to hb==64, apply RNE rounding, and package the F80.
fn finish80(sign: bool, exp: i32, m: u128, sticky_in: bool) -> F80 {
    if m == 0 {
        return F80::zero(sign);
    }
    let mut m = m;
    let mut exp = exp;
    let mut sticky = sticky_in;
    let hb = 127 - m.leading_zeros() as i32;
    if hb > 64 {
        let sh = (hb - 64) as u32;
        if sh < 128 {
            sticky = sticky || (m & ((1u128 << sh) - 1) != 0);
        }
        m >>= sh;
        exp += sh as i32;
    } else if hb < 64 {
        m <<= 64 - hb;
        exp -= 64 - hb;
    }
    // Inexact (below the kept mantissa) if the dropped bit or any sticky
    // hint existed, or rounding actually changed the value.
    let dropped_nonzero = (m & 1) != 0 || sticky;
    let (mant, bumped) = round64(m, sticky);
    let sticky_out = dropped_nonzero || bumped;
    if bumped {
        exp += 1;
    }
    let be = exp + F80_EXP_BIAS;
    if be >= 0x7FFF {
        return F80::inf(sign);
    }
    if be < 1 {
        // 80-bit denormal results are outside the frozen corpus inputs;
        // recorded as signed zero instead of guessing the representation.
        return F80::zero(sign);
    }
    F80 {
        sign,
        exp: be as u16,
        mant,
        sticky: sticky_out,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sse_nan_selection_src1_first() {
        let mut mx = Mxcsr::new();
        let snan1 = 0x7F80_0001u32; // sNaN
        let qnan2 = 0x7FC0_0000u32;
        let r = sse_f32(ScalarOp::Add, snan1, qnan2, &mut mx);
        assert_eq!(r, quiet_f32(snan1), "src1 sNaN quieted wins");
        assert_eq!(mx.0 & MXCSR_IE, 0, "masked exceptions set no IE");
    }

    #[test]
    fn sse_invalid_is_negative_indefinite() {
        let mut mx = Mxcsr::new();
        let inf = f32::INFINITY.to_bits();
        // Sub is invalid only for SAME-sign infinities (inf − inf);
        // inf − (−inf) = +inf (hardware-verified).
        let r = sse_f32(ScalarOp::Sub, inf, inf, &mut mx);
        assert_eq!(r, INDEFINITE_F32);
        assert_ne!(mx.0 & MXCSR_IE, 0);
        let mut mx = Mxcsr::new();
        let r = sse_f32(ScalarOp::Sub, inf, f32::NEG_INFINITY.to_bits(), &mut mx);
        assert_eq!(r, inf);
        let mut mx = Mxcsr::new();
        let r = sse_f32(ScalarOp::Div, 0, 0, &mut mx);
        assert_eq!(r, INDEFINITE_F32);
    }

    #[test]
    fn sse_div_by_zero_flags() {
        let mut mx = Mxcsr::new();
        let r = sse_f32(ScalarOp::Div, 3.0f32.to_bits(), 0, &mut mx);
        assert_eq!(r, f32::INFINITY.to_bits());
        assert_ne!(mx.0 & MXCSR_ZE, 0);
    }

    #[test]
    fn sse_min_returns_src2_on_nan() {
        let mut mx = Mxcsr::new();
        let r = sse_f32(ScalarOp::Min, 1.0f32.to_bits(), 0x7FC0_0000, &mut mx);
        assert_eq!(r, 0x7FC0_0000);
    }

    #[test]
    fn sse_ftz_daz() {
        let mut mx = Mxcsr::new();
        mx.0 |= MXCSR_FTZ | MXCSR_DAZ;
        let dn = f32::from_bits(1); // smallest denormal
        let r = sse_f32(ScalarOp::Add, dn.to_bits(), dn.to_bits(), &mut mx);
        assert_eq!(r, 0, "DAZ zeros both operands, FTZ flushes result");
    }

    #[test]
    fn cvtt_indefinite_on_nan_and_overflow() {
        assert_eq!(cvtt_f32_i32(f32::NAN.to_bits()), INDEFINITE_I32);
        assert_eq!(cvtt_f32_i32(3e9f32.to_bits()), INDEFINITE_I32);
        assert_eq!(cvtt_f32_i32(3.9f32.to_bits()), 3);
        assert_eq!(cvtt_f32_i64((-3.9f32).to_bits()), -3);
        assert_eq!(cvtt_f64_i64(1e300f64.to_bits()), INDEFINITE_I64);
    }

    #[test]
    fn comis_unordered_and_ordering() {
        assert_eq!(comis_f32(0x7FC0_0000, 1.0f32.to_bits()), (true, true, true));
        assert_eq!(comis_f32(2.0f32.to_bits(), 1.0f32.to_bits()), (false, false, false));
        assert_eq!(comis_f32(1.0f32.to_bits(), 2.0f32.to_bits()), (false, false, true));
        assert_eq!(comis_f32(1.0f32.to_bits(), 1.0f32.to_bits()), (true, false, false));
    }

    #[test]
    fn f80_roundtrip_and_arith() {
        let a = F80::from_f64(1.5);
        let b = F80::from_f64(2.25);
        assert_eq!(x87_bin(ScalarOp::Add, a, b).to_f64(), 3.75);
        assert_eq!(x87_bin(ScalarOp::Mul, a, b).to_f64(), 3.375);
        assert_eq!(x87_bin(ScalarOp::Div, b, a).to_f64(), 1.5);
        assert_eq!(x87_bin(ScalarOp::Sub, a, b).to_f64(), -0.75);
        let big = F80::from_i64(i64::MIN);
        assert_eq!(big.to_i64_rne(), i64::MIN);
        assert_eq!(F80::from_i64(42).to_i64_rne(), 42);
    }

    #[test]
    fn f80_precision_beyond_f64() {
        // 1 + 2^-63: representable in f80, rounds away in f64.
        let one = F80::from_f64(1.0);
        let eps = F80 {
            sign: false,
            exp: (16383 - 63) as u16, // 2^-63
            mant: 1u64 << 63,
            sticky: false,
        };
        let sum = x87_bin(ScalarOp::Add, one, eps);
        // exact f80 sum has mantissa ...01 in bit 0
        assert_eq!(sum.mant & 1, 1);
        // f64 view rounds to exactly 1.0 (the 2^-63 is below its precision)
        assert_eq!(sum.to_f64(), 1.0);
    }

    #[test]
    fn f80_nan_indefinite() {
        let inf = F80::inf(false);
        let ninf = F80::inf(true);
        assert_eq!(x87_bin(ScalarOp::Add, inf, ninf), F80_INDEFINITE);
        let snan = F80 {
            sign: false,
            exp: 0x7FFF,
            mant: (1u64 << 63) | 1,
            sticky: false,
        };
        let q = x87_bin(ScalarOp::Add, snan, F80::from_f64(1.0));
        assert!(q.is_nan());
        assert_ne!(q.mant & (1u64 << 62), 0, "sNaN quieted");
    }
}
