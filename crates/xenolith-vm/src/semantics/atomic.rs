//! Atomic memory-op semantics for the G4 frozen corpus.
//!
//! The oracle is single-threaded: a statement stream linearizes into one
//! total order, which is exactly seq_cst for lock-prefixed RMW on x86 —
//! the model the differential test validates against `lock cmpxchg` /
//! `lock xadd` / `xchg` on hardware. Multi-threaded schedules are stage 6
//! (G5 region lifetimes); anything needing them fails closed here.

use super::memory::Memory;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AtomicOp {
    /// `lock cmpxchg [mem], src`: compare memory with RAX; equal → store
    /// src, ZF=1; unequal → load old into RAX, ZF=0.
    CmpXchg,
    /// `lock xadd [mem], src`: tmp = mem; mem = tmp + src; src = tmp.
    XAdd,
    /// `xchg [mem], src` (implicitly locked on x86).
    Xchg,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemOrder {
    /// x86 lock-prefixed RMW: full fence. The oracle's total order.
    SeqCst,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AtomicError {
    UnsupportedWidth,
    BadOrder,
}

/// Apply an RMW on `mem` at `addr`. Returns the value loaded from memory
/// (the "old" that hardware writes into the source register), plus the ZF
/// for cmpxchg (None for xadd/xchg).
pub fn atomic_rmw(
    op: AtomicOp,
    mem: &mut Memory,
    addr: u64,
    width: u8,
    expected: u64,
    incoming: u64,
    order: MemOrder,
) -> Result<(u64, Option<bool>), AtomicError> {
    if !matches!(width, 1 | 2 | 4 | 8) {
        return Err(AtomicError::UnsupportedWidth);
    }
    if order != MemOrder::SeqCst {
        return Err(AtomicError::BadOrder);
    }
    // The single-threaded total order IS seq_cst; no fences needed in the
    // oracle. Width masks follow the hardware register semantics.
    let mask = match width {
        1 => 0xffu64,
        2 => 0xffff,
        4 => 0xffff_ffff,
        _ => u64::MAX,
    };
    let old = mem.read_u64(addr, width).map_err(|_| AtomicError::UnsupportedWidth)? & mask;
    // Destination-register semantics, matching the hardware RMW exactly:
    // - 8/16-bit ops update only the low bits (upper bits of the register
    //   keep their pre-op value, which is `incoming` in the IR model);
    // - 32-bit ops zero-extend; 64-bit ops replace.
    let reg_out = |pre: u64| -> u64 {
        match width {
            1 | 2 => (pre & !mask) | old,
            _ => old,
        }
    };
    match op {
        AtomicOp::CmpXchg => {
            let eq = (expected & mask) == old;
            if eq {
                mem.write_u64(addr, width, incoming & mask)
                    .map_err(|_| AtomicError::UnsupportedWidth)?;
                // Success leaves RAX untouched (full width, not masked).
                Ok((expected, Some(true)))
            } else {
                // Failure loads the old value into RAX: 32-bit loads zero
                // the upper half, 64-bit replaces, 8/16-bit touch only the
                // low bits (upper bits keep the pre-compare RAX = expected).
                let rax = match width {
                    1 | 2 => (expected & !mask) | old,
                    _ => old,
                };
                Ok((rax, Some(false)))
            }
        }
        AtomicOp::XAdd => {
            let sum = old.wrapping_add(incoming) & mask;
            mem.write_u64(addr, width, sum)
                .map_err(|_| AtomicError::UnsupportedWidth)?;
            Ok((reg_out(incoming), None))
        }
        AtomicOp::Xchg => {
            mem.write_u64(addr, width, incoming & mask)
                .map_err(|_| AtomicError::UnsupportedWidth)?;
            Ok((reg_out(incoming), None))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cmpxchg_success_and_failure() {
        let mut m = Memory::new();
        m.write_u64(0x1000, 4, 7).unwrap();
        let (old, zf) = atomic_rmw(
            AtomicOp::CmpXchg,
            &mut m,
            0x1000,
            4,
            7,
            9,
            MemOrder::SeqCst,
        )
        .unwrap();
        assert_eq!(old, 7, "success keeps the full expected value");
        assert_eq!(zf, Some(true));
        assert_eq!(m.read_u64(0x1000, 4).unwrap(), 9);

        let (old, zf) = atomic_rmw(
            AtomicOp::CmpXchg,
            &mut m,
            0x1000,
            4,
            8, // wrong expected
            11,
            MemOrder::SeqCst,
        )
        .unwrap();
        assert_eq!(old, 9);
        assert_eq!(zf, Some(false));
        assert_eq!(m.read_u64(0x1000, 4).unwrap(), 9, "failure does not store");
    }

    #[test]
    fn xadd_returns_old_and_wraps() {
        let mut m = Memory::new();
        m.write_u64(0x2000, 4, u32::MAX as u64).unwrap();
        let (old, zf) = atomic_rmw(AtomicOp::XAdd, &mut m, 0x2000, 4, 2, 1, MemOrder::SeqCst).unwrap();
        assert_eq!(old, u32::MAX as u64);
        assert_eq!(zf, None);
        assert_eq!(m.read_u64(0x2000, 4).unwrap(), 0, "wraps to 0");
    }

    #[test]
    fn xchg_swaps() {
        let mut m = Memory::new();
        m.write_u64(0x3000, 8, 1).unwrap();
        let (old, _) =
            atomic_rmw(AtomicOp::Xchg, &mut m, 0x3000, 8, 0, 0xDEAD, MemOrder::SeqCst).unwrap();
        assert_eq!(old, 1);
        assert_eq!(m.read_u64(0x3000, 8).unwrap(), 0xDEAD);
    }

    #[test]
    fn widths_and_orders_fail_closed() {
        let mut m = Memory::new();
        assert!(atomic_rmw(AtomicOp::XAdd, &mut m, 0, 3, 0, 0, MemOrder::SeqCst).is_err());
    }
}
