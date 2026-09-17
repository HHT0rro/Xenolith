//! TASK-023: real-function coverage statistics.
//!
//! For every STT_FUNC symbol (with size) in an ELF's `.symtab`, classify the
//! function against the CURRENT transform capability:
//! - `transformed`: full CFG lift to IR + superoperator emission succeeds.
//! - `mixed_native`: whole-function lift fails, but the body contains
//!   liftable work — a mixed design (protected blocks + native blocks) is
//!   the honest label.
//! - `unsupported`: nothing liftable (every meaningful instruction is
//!   outside the current semantics).
//! - `boundary_uncertain`: lift window/cap limits or out-of-window branches
//!   prevented proving the function's boundaries.
//!
//! Buckets are mutually exclusive and sum to the function total. This module
//! never writes into images; it is reporting only.

use xenolith_formats::elf::{self, Elf64};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Bucket {
    Transformed,
    MixedNative,
    Unsupported,
    BoundaryUncertain,
}

impl Bucket {
    pub fn as_str(self) -> &'static str {
        match self {
            Bucket::Transformed => "transformed",
            Bucket::MixedNative => "mixed_native",
            Bucket::Unsupported => "unsupported",
            Bucket::BoundaryUncertain => "boundary_uncertain",
        }
    }
}

#[derive(Clone, Debug)]
pub struct FunctionVerdict {
    pub name: String,
    pub size: u64,
    pub bucket: Bucket,
    /// Rejection reason for non-transformed functions (top line).
    pub reason: String,
}

#[derive(Clone, Debug, Default)]
pub struct CoverageStats {
    pub functions: usize,
    pub bytes: u64,
    pub transformed: usize,
    pub transformed_bytes: u64,
    pub mixed_native: usize,
    pub unsupported: usize,
    pub boundary_uncertain: usize,
    /// reason → count (top-N reported).
    pub reasons: std::collections::BTreeMap<String, usize>,
}

pub fn classify_elf(image: &[u8], parsed: &Elf64) -> Result<CoverageStats, String> {
    let funcs = elf::symtab_functions(image, parsed).map_err(|e| e.to_string())?;
    let mut stats = CoverageStats::default();
    let phdrs = elf::program_headers(image, parsed).map_err(|e| e.to_string())?;
    for f in funcs {
        // Function bytes: value → file offset via the containing PT_LOAD.
        let Some(ph) = phdrs.iter().find(|p| {
            p.p_type == elf::PT_LOAD
                && f.value >= p.p_vaddr
                && f.value < p.p_vaddr.saturating_add(p.p_filesz)
        }) else {
            continue;
        };
        let Some(off_u64) = ph.p_offset.checked_add(f.value - ph.p_vaddr) else {
            continue;
        };
        let off = off_u64 as usize;
        let len = f.size as usize;
        if len == 0 || off.saturating_add(len) > image.len() {
            continue;
        }
        let bytes = &image[off..off + len];
        stats.functions += 1;
        stats.bytes += f.size;
        let (bucket, reason) = classify_one(bytes, f.value);
        match bucket {
            Bucket::Transformed => {
                stats.transformed += 1;
                stats.transformed_bytes += f.size;
            }
            Bucket::MixedNative => stats.mixed_native += 1,
            Bucket::Unsupported => stats.unsupported += 1,
            Bucket::BoundaryUncertain => stats.boundary_uncertain += 1,
        }
        if !reason.is_empty() {
            *stats.reasons.entry(reason).or_insert(0) += 1;
        }
    }
    Ok(stats)
}

fn classify_one(bytes: &[u8], ip: u64) -> (Bucket, String) {
    match crate::lift::lift_code(bytes, ip, "") {
        Ok((ir, _)) => match xenolith_vm::emit_superop(&ir, &[7u8; 16]) {
            Ok(_) => (Bucket::Transformed, String::new()),
            Err(e) => (Bucket::MixedNative, first_line(&e)),
        },
        Err(e) => {
            let msg = e.0;
            if msg.contains("lift cap") || msg.contains("out of lift window") {
                return (Bucket::BoundaryUncertain, first_line(&msg));
            }
            // Mixed-native probe: does the body contain ANY liftable work?
            let (liftable, total) = crate::lift::liftable_work_ratio(bytes, ip);
            if liftable > 1 && total > 0 {
                (Bucket::MixedNative, first_line(&msg))
            } else {
                (Bucket::Unsupported, first_line(&msg))
            }
        }
    }
}

fn first_line(s: &str) -> String {
    let l = s.lines().next().unwrap_or("");
    // Normalize the trailing "at 0x..." so reasons aggregate by cause, not
    // by address — the artifact holds measured counts, one per cause.
    match l.find(" at 0x") {
        Some(i) => l[..i].to_string(),
        None => l.to_string(),
    }
}
