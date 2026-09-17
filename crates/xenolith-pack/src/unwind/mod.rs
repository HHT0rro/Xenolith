//! Unwind metadata for injected/transformed code (TASK-021).
//!
//! "The original exception table is still there" is NOT the same as "the new
//! code can unwind". The injected stub (and future transformed functions)
//! live in appended sections the OS has no unwind records for — this module
//! synthesizes them:
//! - `windows`: RUNTIME_FUNCTION (PDATA entry) + UNWIND_INFO (XDATA blob)
//!   for the PE stub prologue.
//! - `dwarf`: a self-contained .eh_frame (CIE+FDE) + .eh_frame_hdr that an
//!   appended PT_GNU_EH_FRAME exposes to the libgcc unwinder — all offsets
//!   are self-relative sdata4, so no ld.so relocation is required.

pub mod dwarf;
pub mod windows;
