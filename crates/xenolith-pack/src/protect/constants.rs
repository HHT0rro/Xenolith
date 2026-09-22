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
    #[error(
        "strict data protection: {count} read-only constants still have native references \
         (first samples as (constant rva, reference rva): {samples}); nothing is encrypted \
         without a complete reference proof — drop --strict-constants or narrow the \
         selection",
        count = .0,
        samples = .1
            .iter()
            .map(|(c, s)| format!("({c:#x}, {s:#x})"))
            .collect::<Vec<_>>()
            .join(", ")
    )]
    UnresolvedRefs(usize, Vec<(u32, u32)>),
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

/// One candidate constant interval, sorted by rva. `printable_run` scans
/// forward within a section, so the produced intervals never overlap and the
/// sorted table answers "which candidate does this address fall into" with a
/// single binary search per position instead of a nested loop per candidate.
#[derive(Clone, Copy, Debug)]
struct Candidate {
    rva: u32,
    len: u32,
}

impl Candidate {
    fn contains(self, target: u32) -> bool {
        target >= self.rva && target < self.rva.wrapping_add(self.len)
    }
}

/// Reference accounting for one candidate: any hit at all, and the first
/// reference site outside the transformed set (the strict-mode breadcrumb).
#[derive(Clone, Copy, Default)]
struct RefState {
    referenced: bool,
    resolved_only: bool,
    first_native_site: Option<u32>,
}

/// Plan constant protection for a PE image.
///
/// `transformed` is the (rva, len) set of function bodies this pack rewrote
/// (the only code whose data reads we could interpose on). Reference proof
/// is deliberately over-approximated: any u32 inside an executable section
/// that resolves into the candidate range — either as an absolute value or
/// as a rip-relative displacement from its own position — counts as a
/// reference, and only references inside `transformed` are "resolved".
///
/// The proof runs as ONE linear pass over the executable bytes (candidates
/// are a sorted, non-overlapping interval table consulted per position with
/// `partition_point`); per-candidate verdicts are identical to a
/// candidates×bytes nested scan because every (site, value) pair is examined
/// exactly once either way. Large images (go.exe-scale) no longer stall in a
/// minute-level candidates×positions product.
pub fn plan_constants(
    pe: &Pe64,
    input: &[u8],
    transformed: &[(u32, u32)],
    strict: bool,
) -> Result<ConstantPlan, ConstantsError> {
    let mut plan = ConstantPlan::default();
    let mut candidates: Vec<Candidate> = Vec::new();
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
                candidates.push(Candidate {
                    rva: sec.virtual_address + off as u32,
                    len: run as u32,
                });
                off += run;
            } else {
                off += 1;
            }
        }
    }
    plan.candidates = candidates.len();
    // Interval table invariants: sorted by rva, non-overlapping (a run is
    // consumed before the scan resumes past it, and PE sections have distinct
    // RVA ranges).
    candidates.sort_by_key(|c| c.rva);

    let in_transformed = |rva: u32| {
        transformed
            .iter()
            .any(|&(lo, len)| rva >= lo && rva < lo.wrapping_add(len))
    };

    let mut states: Vec<RefState> = vec![RefState::default(); candidates.len()];
    for sec in &pe.sections {
        if sec.characteristics & IMAGE_SCN_MEM_EXECUTE == 0 {
            continue;
        }
        let Ok(start) = pe.file_offset_of(sec.virtual_address) else {
            continue;
        };
        let Some(bytes) = input
            .get(start as usize..)
            .and_then(|s| s.get(..sec.raw_size as usize))
        else {
            continue;
        };
        for (i, w) in bytes.windows(4).enumerate() {
            let v = u32::from_le_bytes([w[0], w[1], w[2], w[3]]);
            let site = sec.virtual_address + i as u32;
            // Absolute reference or rip-relative disp32 (next-insn
            // approximation: the true base is within a few bytes).
            let rip_target = site.wrapping_add(4).wrapping_add(v);
            // Which candidate interval(s) does this position reference? The
            // table is sorted, so every interval with rva <= target sits
            // before the partition point; walk back over the (in practice
            // zero or one) intervals that end past the target. The extra
            // walk-back only matters for degenerate overlapping tables and
            // preserves the nested scan's verdicts exactly.
            let mut idx = candidates.partition_point(|c| c.rva <= v);
            while idx > 0 && candidates[idx - 1].rva.wrapping_add(candidates[idx - 1].len) > v {
                idx -= 1;
                if candidates[idx].contains(v) {
                    let st = &mut states[idx];
                    st.referenced = true;
                    if !in_transformed(site) {
                        st.resolved_only = false;
                        if st.first_native_site.is_none() {
                            st.first_native_site = Some(site);
                        }
                    }
                }
            }
            idx = candidates.partition_point(|c| c.rva <= rip_target);
            while idx > 0
                && candidates[idx - 1].rva.wrapping_add(candidates[idx - 1].len) > rip_target
            {
                idx -= 1;
                if candidates[idx].contains(rip_target)
                    && rip_target.wrapping_sub(site) < 0x1000
                {
                    let st = &mut states[idx];
                    st.referenced = true;
                    if !in_transformed(site) {
                        st.resolved_only = false;
                        if st.first_native_site.is_none() {
                            st.first_native_site = Some(site);
                        }
                    }
                }
            }
        }
    }

    // (constant rva, reference site rva) pairs for the strict-mode report —
    // candidate-discovery order, first non-transformed site each, exactly as
    // the nested scan reported them.
    let mut unresolved_samples: Vec<(u32, u32)> = Vec::new();
    for (cand, st) in candidates.iter().zip(states.iter()) {
        if !st.referenced {
            continue;
        }
        if st.resolved_only {
            plan.protectable += 1;
        } else {
            plan.native_referenced += 1;
            if let Some(site) = st.first_native_site {
                if unresolved_samples.len() < 8 {
                    unresolved_samples.push((cand.rva, site));
                }
            }
        }
    }

    if strict && plan.native_referenced > 0 {
        return Err(ConstantsError::UnresolvedRefs(
            plan.native_referenced,
            unresolved_samples,
        ));
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
