//! Windows x64 UNWIND_INFO synthesis for the injected PIC stub.
//!
//! The stub's entry sequence is a fixed, known prologue: a run of nonvolatile
//! pushes followed by a stack allocation. One RUNTIME_FUNCTION covering the
//! whole stub section is correct because every entry path performs the same
//! pushes before touching anything else.
//!
//! Layout reference (PE x64 exception handling): each UNWIND_CODE u16 packs
//! `CodeOffset | (UnwindOp << 8) | (OpInfo << 12)` in prologue execution
//! order; CodeOffset is the byte offset of the END of that instruction.

const UNW_VERSION: u8 = 1;

const UWOP_PUSH_NONVOL: u8 = 0;
const UWOP_ALLOC_LARGE: u8 = 1;
const UWOP_ALLOC_SMALL: u8 = 2;

/// Instruction byte lengths the frozen prologues use (1-byte push, 2-byte
/// REX push, 4-byte REX sub imm8, 7-byte REX sub imm32).
pub const PUSH1: u32 = 1;
pub const PUSH2: u32 = 2;

/// Build a complete UNWIND_INFO blob for `pushes` of (reg, instruction size)
/// in push order, followed by a `sub rsp, stack_alloc`.
/// No frame pointer, no handlers — the stub never installs handlers.
pub fn unwind_info(pushes: &[(u8, u32)], stack_alloc: u32) -> Vec<u8> {
    assert!(stack_alloc % 8 == 0, "stack allocation must be 8-byte aligned");
    let mut codes: Vec<u16> = Vec::new();
    let mut off = 0u32;
    for &(reg, size) in pushes {
        off += size;
        codes.push((off as u16) | ((UWOP_PUSH_NONVOL as u16) << 8) | ((reg as u16) << 12));
    }
    if stack_alloc == 0 {
        // leaf-style: nothing more
    } else if stack_alloc <= 128 {
        // ALLOC_SMALL encodes (size/8 - 1) in OpInfo; the sub itself is 4 or
        // 7 bytes — use 7 (imm32 form) as the canonical frozen prologue.
        off += 7;
        codes.push(
            (off as u16)
                | ((UWOP_ALLOC_SMALL as u16) << 8)
                | (((stack_alloc / 8 - 1) as u16) << 12),
        );
    } else {
        // ALLOC_LARGE with OpInfo 0: exactly ONE operand slot (size/8 in
        // slots) — the frozen prologues stay far below the 512 KiB u16 max.
        off += 7;
        codes.push((off as u16) | ((UWOP_ALLOC_LARGE as u16) << 8));
        codes.push((stack_alloc / 8) as u16);
    }
    // UNWIND_CODE array stores the operations in REVERSE prologue order, but
    // each operation's operand slots stay AFTER its code slot (reverse by
    // operation groups, never flat — a flat reverse puts operands first and
    // the unwinder misparses the whole array).
    let has_alloc_large = stack_alloc > 128 && stack_alloc > 0;
    let mut grouped: Vec<Vec<u16>> = Vec::new();
    let it = codes.iter();
    if has_alloc_large {
        // codes = [pushes..., alloc_code, alloc_operand]
        let n = codes.len();
        for &c in &codes[..n - 2] {
            grouped.push(vec![c]);
        }
        grouped.push(vec![codes[n - 2], codes[n - 1]]);
    } else {
        for &c in it {
            grouped.push(vec![c]);
        }
    }
    grouped.reverse();
    let mut flat: Vec<u16> = Vec::new();
    for g in &grouped {
        flat.extend_from_slice(g);
    }
    let count_of_slots = flat.len();
    let mut out = Vec::with_capacity(4 + count_of_slots * 2 + 4);
    out.push(UNW_VERSION); // no E/U/CHAIN handler
    out.push(off as u8); // prologue size (offsets < 256 in frozen prologues)
    out.push(count_of_slots as u8);
    out.push(0); // no frame pointer register
    for half in &flat {
        out.extend_from_slice(&half.to_le_bytes());
    }
    if count_of_slots % 2 == 1 {
        out.extend_from_slice(&0u16.to_le_bytes()); // pad to even slots
    }
    out.extend_from_slice(&0u32.to_le_bytes()); // handler RVA count (none)
    out
}

/// A RUNTIME_FUNCTION entry (BeginAddress, EndAddress, UnwindData).
pub fn runtime_function(begin_rva: u32, end_rva: u32, unwind_rva: u32) -> [u8; 12] {
    let mut out = [0u8; 12];
    out[0..4].copy_from_slice(&begin_rva.to_le_bytes());
    out[4..8].copy_from_slice(&end_rva.to_le_bytes());
    out[8..12].copy_from_slice(&unwind_rva.to_le_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pe_stub_prologue_shape() {
        // The PE stub pushes rbx,rbp,rsi,rdi (1 byte each), r12..r15
        // (2 bytes each), then subs 0x3F8 (7 bytes).
        let pushes: Vec<(u8, u32)> = [
            (3u8, PUSH1),
            (5, PUSH1),
            (6, PUSH1),
            (7, PUSH1),
            (12, PUSH2),
            (13, PUSH2),
            (14, PUSH2),
            (15, PUSH2),
        ]
        .to_vec();
        let blob = unwind_info(&pushes, 0x3F8);
        assert_eq!(blob[0], UNW_VERSION);
        assert_eq!(blob[1], 12 + 7, "prologue size");
        // 8 pushes + ALLOC_LARGE(2 slots: code + one operand) = 10 slots
        assert_eq!(blob[2], 10);
        assert_eq!(blob[3], 0);
        let slot = |i: usize| u16::from_le_bytes([blob[4 + i * 2], blob[5 + i * 2]]);
        // operations reversed: alloc first (code+operand), then r15..rbx
        assert_eq!(slot(0), 0x0113, "ALLOC_LARGE code first");
        assert_eq!(slot(1), 0x3F8 / 8, "alloc operand follows its code");
        assert_eq!(slot(2), 0xF00C, "r15 push (offset 12) next");
        assert_eq!(slot(9), 0x3001, "rbx push (offset 1) last");
    }

    #[test]
    fn small_alloc_uses_alloc_small() {
        let blob = unwind_info(&[(3, PUSH1), (15, PUSH2)], 8);
        assert_eq!(blob[2], 3, "2 pushes + 1 ALLOC_SMALL");
        let slot = |i: usize| u16::from_le_bytes([blob[4 + i * 2], blob[5 + i * 2]]);
        // operations reversed: alloc first, then r15, then rbx
        assert_eq!(slot(0) & 0x0F00, (UWOP_ALLOC_SMALL as u16) << 8);
        assert_eq!(slot(0) & 0xF000, 0 << 12, "8 bytes = (0+1)*8");
        assert_eq!(slot(0) & 0x00FF, 10, "pushes 3 bytes + sub imm32 7 bytes");
        assert_eq!(slot(1) & 0xF000, 15 << 12, "r15");
        assert_eq!(slot(2) & 0xF000, 3 << 12, "rbx last");
    }

    #[test]
    fn runtime_function_layout() {
        let rf = runtime_function(0x1000, 0x2000, 0x3000);
        assert_eq!(&rf, &[0x00, 0x10, 0, 0, 0x00, 0x20, 0, 0, 0x00, 0x30, 0, 0]);
    }
}
