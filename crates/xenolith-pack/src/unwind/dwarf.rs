//! Self-contained .eh_frame + .eh_frame_hdr synthesis for the injected ELF
//! stub (TASK-021).
//!
//! The appended segment carries its own eh_frame (CIE with `zR` augmentation,
//! pcrel-sdata4 FDE for the stub range) and a binary-search eh_frame_hdr; a
//! PT_GNU_EH_FRAME program header exposes it so the libgcc unwinder's
//! dl_iterate_phdr path finds FDEs for the stub with **zero** ld.so
//! relocation — pc_begin is self-relative (pcrel) and the search table is
//! datarel (object-base relative); both are pack-time constants for an
//! appended segment.
//!
//! The FDE describes the ELF stub's fixed prologue:
//! `push rbx; push r15; sub rsp, 8` (1+2+4 bytes).

const DW_CFA_NOP: u8 = 0x00;
const DW_CFA_ADVANCE_LOC1: u8 = 0x02;
const DW_CFA_DEF_CFA: u8 = 0x0c;
const DW_CFA_OFFSET: u8 = 0x80; // | (reg << 6) | factored_offset

const REG_RSP: u8 = 7;
const REG_RBX: u8 = 3;
const REG_R15: u8 = 15;
const REG_RA: u8 = 16;

/// Built .eh_frame plus patch/bookkeeping offsets.
pub struct EhFrame {
    pub bytes: Vec<u8>,
    /// Byte offset of the FDE pc_begin field: patch it with
    /// `stub_rva − (eh_frame_rva + pc_begin_off)` (pcrel sdata4).
    pub pc_begin_off: usize,
    /// Byte offset just past the FDE header (length+CIE pointer), i.e. the
    /// datarel search-table value for the FDE.
    pub fde_off: usize,
}

/// CIE + FDE covering `[stub_rva, stub_rva + stub_len)`.
pub fn eh_frame_stub(stub_len: u32) -> EhFrame {
    let mut out = Vec::new();
    // ---- CIE: version 1, "zR", pcrel|sdata4 ----
    let mut cie = Vec::new();
    cie.push(1);
    cie.extend_from_slice(b"zR");
    cie.push(0);
    cie.push(1); // code alignment factor
    cie.push(0x78); // data alignment factor = -8
    cie.push(REG_RA);
    cie.push(1); // augmentation data length
    cie.push(0x1B); // R = DW_EH_PE_pcrel | sdata4
    cie.push(DW_CFA_DEF_CFA); // initial CFA = RSP + 8
    cie.push(REG_RSP);
    cie.push(8);
    while (4 + 4 + cie.len()) % 8 != 0 {
        cie.push(DW_CFA_NOP);
    }
    out.extend_from_slice(&((cie.len() + 4) as u32).to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&cie);

    // ---- FDE for push rbx (1B); push r15 (2B); sub rsp,8 (4B) ----
    let mut fde = Vec::new();
    fde.extend_from_slice(&0i32.to_le_bytes()); // pc_begin (patched)
    fde.extend_from_slice(&stub_len.to_le_bytes());
    // The CIE carries the `z` augmentation, so the FDE MUST lead its body
    // with a ULEB128 augmentation-data length (zero here) — libgcc rejects
    // the FDE outright without it.
    fde.push(0);
    fde.push(DW_CFA_ADVANCE_LOC1);
    fde.push(1);
    fde.push(DW_CFA_DEF_CFA); // CFA = rsp+16
    fde.push(REG_RSP);
    fde.push(16);
    fde.push(DW_CFA_OFFSET | REG_RBX);
    fde.push(1); // saved at CFA-16 → factored (16-8)/8 = 1
    fde.push(DW_CFA_ADVANCE_LOC1);
    fde.push(2);
    fde.push(DW_CFA_DEF_CFA); // CFA = rsp+24
    fde.push(REG_RSP);
    fde.push(24);
    fde.push(DW_CFA_OFFSET | REG_R15);
    fde.push(1);
    fde.push(DW_CFA_ADVANCE_LOC1);
    fde.push(4);
    fde.push(DW_CFA_DEF_CFA); // CFA = rsp+32
    fde.push(REG_RSP);
    fde.push(32);
    while (4 + 4 + fde.len()) % 8 != 0 {
        fde.push(DW_CFA_NOP);
    }
    out.extend_from_slice(&(fde.len() as u32).to_le_bytes());
    let fde_len_field = out.len();
    out.extend_from_slice(&((fde_len_field - 4) as i32).to_le_bytes()); // cie_ptr = FDE length-field offset
    let pc_begin_off = out.len();
    out.extend_from_slice(&fde);
    // The search table points at the FDE START (its length field), which is
    // 8 bytes before pc_begin (length + CIE pointer).
    let fde_off = pc_begin_off - 8;
    EhFrame {
        bytes: out,
        pc_begin_off,
        fde_off,
    }
}

/// .eh_frame_hdr with search entries in datarel|sdata4 (object-base
/// relative). Patch the eh_frame_ptr field (offset 4) with
/// `eh_frame_rva − (hdr_rva + 4)` (pcrel sdata4).
pub fn eh_frame_hdr(entries: &[(i32, i32)]) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(1); // version
    out.push(0x1B); // eh_frame_ptr_enc = pcrel|sdata4
    out.push(0x03); // fde_count_enc = udata4
    out.push(0x3B); // table_enc = datarel|sdata4
    out.extend_from_slice(&0i32.to_le_bytes()); // eh_frame_ptr (patched)
    out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for &(loc, fde) in entries {
        out.extend_from_slice(&loc.to_le_bytes());
        out.extend_from_slice(&fde.to_le_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cie_and_fde_structure() {
        let eh = eh_frame_stub(0x100);
        let b = &eh.bytes;
        let cie_len = u32::from_le_bytes(b[0..4].try_into().unwrap()) as usize;
        assert_eq!(&b[4..8], &0u32.to_le_bytes());
        assert_eq!(b[8], 1);
        assert_eq!(&b[9..11], b"zR");
        assert_eq!(b[12], 1);
        assert_eq!(b[13], 0x78);
        assert_eq!(b[14], REG_RA);
        assert_eq!(b[15], 1);
        assert_eq!(b[16], 0x1B);
        let fde_field = 4 + cie_len;
        let cie_ptr = i32::from_le_bytes(b[fde_field + 4..fde_field + 8].try_into().unwrap());
        assert_eq!(cie_ptr, fde_field as i32, "fde_start - cie_start");
        assert_eq!(eh.pc_begin_off, fde_field + 8);
        assert_eq!(b.len() % 8, 0);
        // pc_range + augmentation-length byte follow pc_begin
        let range = u32::from_le_bytes(
            b[eh.pc_begin_off + 4..eh.pc_begin_off + 8].try_into().unwrap(),
        );
        assert_eq!(range, 0x100);
        assert_eq!(b[eh.pc_begin_off + 8], 0, "FDE augmentation length = 0");
    }

    #[test]
    fn hdr_shape() {
        let hdr = eh_frame_hdr(&[(0x5310i32, 0x5140i32)]);
        assert_eq!(&hdr[0..4], &[1, 0x1B, 0x03, 0x3B]);
        assert_eq!(u32::from_le_bytes(hdr[8..12].try_into().unwrap()), 1);
        assert_eq!(hdr.len(), 4 + 4 + 4 + 8);
    }
}
