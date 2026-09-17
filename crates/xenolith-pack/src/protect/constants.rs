//! TASK-025: read-only constant protection planning.
//!
//! A constant may only be encrypted when EVERY reference to it is provably
//! under our control (a transformed call site we could decrypt on access).
//! Today the lift matrix rejects data-referencing code (Lea/mov rip-relative
//! are outside the transform matrix per TASK-023), so the protectable set is
//! expected to be empty for real inputs — this module reports that honestly
//! and never pretends. Scanning hit-and-replace without proof is forbidden
//! by policy; targets that REQUIRE strict data protection are refused when
//! unresolved native references exist.

use xenolith_formats::{Pe64, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConstantsError {
    #[error("strict data protection: {0} read-only constants still have native references")]
    UnresolvedRefs(usize),
}

#[derive(Clone, Debug, Default)]
pub struct ConstantPlan {
    /// Read-only string-like runs found in the image.
    pub candidates: usize,
    /// Candidates whose every reference is inside transformed ranges.
    /// Reported for visibility; NOT encrypted — reads cannot be rewritten
    /// until the lift matrix covers data references.
    pub protectable: usize,
    /// Constants actually encrypted by this pack. Always 0 today.
    pub encrypted: usize,
    /// Candidates with at least one reference outside transformed code.
    pub native_referenced: usize,
}

fn printable_run(buf: &[u8]) -> Option<usize> {
    // A string-like run: >=6 printable bytes followed by NUL.
    let mut run = 0usize;
    for (i, &b) in buf.iter().enumerate() {
        if (0x20..0x7f).contains(&b) {
            run += 1;
        } else {
            if b == 0 && run >= 6 {
                return Some(i + 1); // include the NUL
            }
            run = 0;
        }
    }
    None
}

/// Plan constant protection for a PE image.
///
/// `transformed` is the (rva, len) set of function bodies this pack rewrote
/// (the only code whose data reads we could interpose on). Reference proof
/// is deliberately over-approximated: any u32 inside an executable section
/// that resolves into the candidate range — either as an absolute value or
/// as a rip-relative displacement from its own position — counts as a
/// reference, and only references inside `transformed` are "resolved".
pub fn plan_constants(
    pe: &Pe64,
    input: &[u8],
    transformed: &[(u32, u32)],
    strict: bool,
) -> Result<ConstantPlan, ConstantsError> {
    let mut plan = ConstantPlan::default();
    let mut candidates: Vec<(u32, u32)> = Vec::new(); // (rva, len)
    for sec in &pe.sections {
        if sec.characteristics & IMAGE_SCN_MEM_READ == 0
            || sec.characteristics & IMAGE_SCN_MEM_WRITE != 0
            || sec.characteristics & IMAGE_SCN_MEM_EXECUTE != 0
        {
            continue;
        }
        let Ok(start) = pe.file_offset_of(sec.virtual_address) else {
            continue;
        };
        let raw = input
            .get(start as usize..)
            .and_then(|s| s.get(..sec.raw_size as usize))
            .unwrap_or(&[][..]);
        let mut off = 0usize;
        while off < raw.len() {
            if let Some(run) = printable_run(&raw[off..]) {
                candidates.push((sec.virtual_address + off as u32, run as u32));
                off += run;
            } else {
                off += 1;
            }
        }
    }
    plan.candidates = candidates.len();

    // Executable bytes, for reference proof.
    let mut exec: Vec<(u32, Vec<u8>)> = Vec::new(); // (rva, bytes)
    for sec in &pe.sections {
        if sec.characteristics & IMAGE_SCN_MEM_EXECUTE == 0 {
            continue;
        }
        let Ok(start) = pe.file_offset_of(sec.virtual_address) else {
            continue;
        };
        if let Some(bytes) = input
            .get(start as usize..)
            .and_then(|s| s.get(..sec.raw_size as usize))
        {
            exec.push((sec.virtual_address, bytes.to_vec()));
        }
    }

    let in_transformed = |rva: u32| {
        transformed
            .iter()
            .any(|&(lo, len)| rva >= lo && rva < lo.wrapping_add(len))
    };

    for &(rva, len) in &candidates {
        let hi = rva + len;
        let mut resolved_only = true;
        let mut referenced = false;
        for (sec_rva, bytes) in &exec {
            for (i, w) in bytes.windows(4).enumerate() {
                let v = u32::from_le_bytes([w[0], w[1], w[2], w[3]]);
                let site = sec_rva + i as u32;
                // Absolute reference or rip-relative disp32 (next-insn
                // approximation: the true base is within a few bytes).
                let rip_target = site.wrapping_add(4).wrapping_add(v);
                let hits = (v >= rva && v < hi)
                    || (rip_target >= rva && rip_target < hi && rip_target.wrapping_sub(site) < 0x1000);
                if hits {
                    referenced = true;
                    if !in_transformed(site) {
                        resolved_only = false;
                    }
                }
            }
        }
        if referenced {
            if resolved_only {
                plan.protectable += 1;
            } else {
                plan.native_referenced += 1;
            }
        }
    }

    if strict && plan.native_referenced > 0 {
        return Err(ConstantsError::UnresolvedRefs(plan.native_referenced));
    }
    Ok(plan)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Minimal PE harness: plan_constants only touches the section table and
    // raw bytes, so a synthetic image with two sections suffices.
    fn synth_image() -> Vec<u8> {
        // headers omitted: tests call the helpers directly instead.
        Vec::new()
    }

    #[test]
    fn printable_run_bounds() {
        assert_eq!(printable_run(b"abcdef\0rest"), Some(7));
        assert_eq!(printable_run(b"abc\0"), None);
        assert_eq!(printable_run(b"no terminator"), None);
        let _ = synth_image();
    }
}
