//! RFLAGS subset used by integer/compare IR.

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Flags {
    pub cf: bool,
    pub zf: bool,
    pub sf: bool,
    pub of: bool,
    pub pf: bool,
}

impl Flags {
    pub fn from_sub(lhs: u64, rhs: u64, width_bits: u32) -> Self {
        let mask = if width_bits >= 64 {
            u64::MAX
        } else {
            (1u64 << width_bits) - 1
        };
        let a = lhs & mask;
        let b = rhs & mask;
        let res = a.wrapping_sub(b) & mask;
        let sign = 1u64 << (width_bits - 1);
        Self {
            cf: a < b,
            zf: res == 0,
            sf: res & sign != 0,
            of: ((a ^ b) & (a ^ res) & sign) != 0,
            pf: (res as u8).count_ones() % 2 == 0,
        }
    }
}
