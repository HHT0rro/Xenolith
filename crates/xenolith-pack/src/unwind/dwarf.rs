//! Self-contained .eh_frame + .eh_frame_hdr synthesis for the injected ELF
//! stub (TASK-021).
//!
//! The appended segment carries a self-contained eh_frame (CIE with `zR`
//! augmentation and a pcrel-sdata4 FDE for the stub range). The original
//! binary-search eh_frame_hdr entries and the stub entry are merged into one
//! relocated header so libgcc's dl_iterate_phdr path can find both original
//! and injected frames with **zero** ld.so relocation.
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
const REG_X30: u8 = 30; // aarch64 link register
const REG_X29: u8 = 29;
const REG_X19: u8 = 19;
const REG_X20: u8 = 20;

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

/// Move an ELF object's unwind lookup table and add the injected stub's FDE.
/// The data-relative table entries are decoded to object-relative addresses
/// before they are re-encoded against the new header location.
pub fn merge_eh_frame_hdr(
    existing: Option<(&[u8], u64)>,
    header_addr: u64,
    eh_frame_addr: u64,
    stub_addr: u64,
    stub_fde_addr: u64,
) -> Result<Vec<u8>, &'static str> {
    const HEADER_PREFIX_LEN: usize = 12;
    const ENTRY_LEN: usize = 8;
    const ENCODINGS: [u8; 4] = [1, 0x1b, 0x03, 0x3b];

    let mut eh_frame_addr = eh_frame_addr;
    let mut entries = Vec::new();
    if let Some((bytes, old_header_addr)) = existing {
        if bytes.len() < HEADER_PREFIX_LEN || bytes[..4] != ENCODINGS {
            return Err("unsupported or truncated PT_GNU_EH_FRAME header");
        }
        let count = u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize;
        let expected_len = HEADER_PREFIX_LEN
            .checked_add(count.checked_mul(ENTRY_LEN).ok_or("unwind header is too large")?)
            .ok_or("unwind header is too large")?;
        if bytes.len() != expected_len {
            return Err("PT_GNU_EH_FRAME size does not match its entry count");
        }

        let frame_pointer = i32::from_le_bytes(bytes[4..8].try_into().unwrap());
        let frame_pointer_addr = old_header_addr
            .checked_add(4)
            .ok_or("unwind header address is out of range")?;
        eh_frame_addr = add_signed(frame_pointer_addr, frame_pointer)?;
        for entry in bytes[HEADER_PREFIX_LEN..].chunks_exact(ENTRY_LEN) {
            let pc_offset = i32::from_le_bytes(entry[0..4].try_into().unwrap());
            let fde_offset = i32::from_le_bytes(entry[4..8].try_into().unwrap());
            entries.push((
                add_signed(old_header_addr, pc_offset)?,
                add_signed(old_header_addr, fde_offset)?,
            ));
        }
    }

    entries.push((stub_addr, stub_fde_addr));
    entries.sort_unstable_by_key(|(pc, _)| *pc);
    if entries.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err("duplicate PC in merged PT_GNU_EH_FRAME table");
    }

    let frame_pointer_addr = header_addr
        .checked_add(4)
        .ok_or("merged unwind header address is out of range")?;
    let frame_pointer = i32::try_from(eh_frame_addr as i128 - frame_pointer_addr as i128)
        .map_err(|_| "merged eh_frame pointer is out of range")?;
    let count = u32::try_from(entries.len()).map_err(|_| "too many unwind table entries")?;
    let mut merged = eh_frame_hdr(&[]);
    merged[4..8].copy_from_slice(&frame_pointer.to_le_bytes());
    merged[8..12].copy_from_slice(&count.to_le_bytes());
    for (pc, fde) in entries {
        let pc_offset = i32::try_from(pc as i128 - header_addr as i128)
            .map_err(|_| "merged unwind PC is out of range")?;
        let fde_offset = i32::try_from(fde as i128 - header_addr as i128)
            .map_err(|_| "merged unwind FDE is out of range")?;
        merged.extend_from_slice(&pc_offset.to_le_bytes());
        merged.extend_from_slice(&fde_offset.to_le_bytes());
    }
    Ok(merged)
}

fn add_signed(base: u64, offset: i32) -> Result<u64, &'static str> {
    let address = base as i128 + i128::from(offset);
    u64::try_from(address).map_err(|_| "unwind table address is out of range")
}

/// AArch64 twin of `eh_frame_stub`: the CIE's return-address column is x30
/// (not RAX) and the FDE describes the aarch64 stub's fixed prologue
/// `stp x29,x30,[sp,#-16]!; stp x19,x20,[sp,#-16]!` (4+4 bytes).
pub fn eh_frame_stub_aarch64(stub_len: u32) -> EhFrame {
    let mut out = Vec::new();
    // ---- CIE: version 1, "zR", pcrel|sdata4 ----
    let mut cie = Vec::new();
    cie.push(1);
    cie.extend_from_slice(b"zR");
    cie.push(0);
    cie.push(1); // code alignment factor
    cie.push(0x78); // data alignment factor = -8
    cie.push(REG_X30);
    cie.push(1); // augmentation data length
    cie.push(0x1B); // R = DW_EH_PE_pcrel | sdata4
    cie.push(DW_CFA_DEF_CFA); // initial CFA = SP + 0
    cie.push(31); // SP
    cie.push(0);
    while (4 + 4 + cie.len()) % 8 != 0 {
        cie.push(DW_CFA_NOP);
    }
    out.extend_from_slice(&((cie.len() + 4) as u32).to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&cie);

    // ---- FDE for the two 4-byte STP steps ----
    let mut fde = Vec::new();
    fde.extend_from_slice(&0i32.to_le_bytes()); // pc_begin (patched)
    fde.extend_from_slice(&stub_len.to_le_bytes());
    fde.push(0); // augmentation-data length (z CIE)
    // stp x29, x30, [sp,#-16]!: CFA stays at the entry SP, i.e. sp'+16;
    // x30 at [sp'] = CFA-16, x29 at [sp'+8] = CFA-8. Factored offsets are
    // against data_align -8: location = CFA + f*(-8).
    fde.push(DW_CFA_ADVANCE_LOC1);
    fde.push(4);
    fde.push(DW_CFA_DEF_CFA);
    fde.push(31); // SP
    fde.push(16);
    fde.push(DW_CFA_OFFSET | REG_X30);
    fde.push(2); // CFA-16
    fde.push(DW_CFA_OFFSET | REG_X29);
    fde.push(1); // CFA-8
    // stp x19, x20, [sp,#-16]!: CFA = sp''+32; x20 at [sp''] = CFA-32,
    // x19 at [sp''+8] = CFA-24.
    fde.push(DW_CFA_ADVANCE_LOC1);
    fde.push(4);
    fde.push(DW_CFA_DEF_CFA);
    fde.push(31);
    fde.push(32);
    fde.push(DW_CFA_OFFSET | REG_X20);
    fde.push(4); // CFA-32
    fde.push(DW_CFA_OFFSET | REG_X19);
    fde.push(3); // CFA-24
    while (4 + 4 + fde.len()) % 8 != 0 {
        fde.push(DW_CFA_NOP);
    }
    out.extend_from_slice(&(fde.len() as u32).to_le_bytes());
    let fde_len_field = out.len();
    out.extend_from_slice(&((fde_len_field - 4) as i32).to_le_bytes()); // cie_ptr
    let pc_begin_off = out.len();
    out.extend_from_slice(&fde);
    let fde_off = pc_begin_off - 8;
    EhFrame {
        bytes: out,
        pc_begin_off,
        fde_off,
    }
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
    fn aarch64_cie_and_fde_structure() {
        let eh = eh_frame_stub_aarch64(0x100);
        let b = &eh.bytes;
        let cie_len = u32::from_le_bytes(b[0..4].try_into().unwrap()) as usize;
        assert_eq!(b[8], 1, "CIE version");
        assert_eq!(&b[9..11], b"zR");
        assert_eq!(b[13], 0x78, "data alignment -8");
        assert_eq!(b[14], REG_X30, "return register is x30");
        let fde_field = 4 + cie_len;
        let range = u32::from_le_bytes(
            b[eh.pc_begin_off + 4..eh.pc_begin_off + 8].try_into().unwrap(),
        );
        assert_eq!(range, 0x100);
        assert_eq!(b[eh.pc_begin_off + 8], 0, "FDE augmentation length = 0");
        assert_eq!(b.len() % 8, 0);
        // Body walk: advance(4) def_cfa(sp,16) offset(x30,2) offset(x29,1)
        // advance(4) def_cfa(sp,32) offset(x20,4) offset(x19,3).
        let body = &b[eh.pc_begin_off + 9..];
        let want = [
            DW_CFA_ADVANCE_LOC1, 4,
            DW_CFA_DEF_CFA, 31, 16,
            DW_CFA_OFFSET | REG_X30, 2,
            DW_CFA_OFFSET | REG_X29, 1,
            DW_CFA_ADVANCE_LOC1, 4,
            DW_CFA_DEF_CFA, 31, 32,
            DW_CFA_OFFSET | REG_X20, 4,
            DW_CFA_OFFSET | REG_X19, 3,
        ];
        for (i, w) in want.iter().enumerate() {
            assert_eq!(body[i], *w, "FDE op {i}");
        }
    }

    #[test]
    fn hdr_shape() {
        let hdr = eh_frame_hdr(&[(0x5310i32, 0x5140i32)]);
        assert_eq!(&hdr[0..4], &[1, 0x1B, 0x03, 0x3B]);
        assert_eq!(u32::from_le_bytes(hdr[8..12].try_into().unwrap()), 1);
        assert_eq!(hdr.len(), 4 + 4 + 4 + 8);
    }

    #[test]
    fn merged_header_rebases_existing_entries_and_sorts_stub() {
        let old_header_addr = 0x2000;
        let old_eh_frame_addr = 0x2070;
        let old_entries = [(0x1010, 0x2080), (0x3040, 0x2110)];
        let mut old_header = eh_frame_hdr(
            &old_entries
                .map(|(pc, fde)| {
                    (
                        (pc as i64 - old_header_addr as i64) as i32,
                        (fde as i64 - old_header_addr as i64) as i32,
                    )
                }),
        );
        old_header[4..8]
            .copy_from_slice(&((old_eh_frame_addr - (old_header_addr + 4)) as i32).to_le_bytes());

        let new_header_addr = 0x9000;
        let new_eh_frame_addr = 0x9100;
        let stub_addr = 0x1020;
        let stub_fde_addr = 0x9120;
        let merged = merge_eh_frame_hdr(
            Some((&old_header, old_header_addr)),
            new_header_addr,
            new_eh_frame_addr,
            stub_addr,
            stub_fde_addr,
        )
        .unwrap();

        assert_eq!(merged.len(), 12 + 3 * 8);
        assert_eq!(u32::from_le_bytes(merged[8..12].try_into().unwrap()), 3);
        assert_eq!(
            i32::from_le_bytes(merged[4..8].try_into().unwrap()),
            (old_eh_frame_addr as i64 - (new_header_addr + 4) as i64) as i32
        );
        let decoded: Vec<_> = merged[12..]
            .chunks_exact(8)
            .map(|entry| {
                let pc = i32::from_le_bytes(entry[0..4].try_into().unwrap());
                let fde = i32::from_le_bytes(entry[4..8].try_into().unwrap());
                (
                    add_signed(new_header_addr, pc).unwrap(),
                    add_signed(new_header_addr, fde).unwrap(),
                )
            })
            .collect();
        assert_eq!(decoded, [(0x1010, 0x2080), (0x1020, 0x9120), (0x3040, 0x2110)]);
    }

    #[test]
    fn merged_header_without_existing_header_points_to_new_frame() {
        let merged = merge_eh_frame_hdr(None, 0x9000, 0x9100, 0x9200, 0x9120).unwrap();
        assert_eq!(merged.len(), 20);
        assert_eq!(
            i32::from_le_bytes(merged[4..8].try_into().unwrap()),
            0xfc
        );
        assert_eq!(
            i32::from_le_bytes(merged[12..16].try_into().unwrap()),
            0x200
        );
        assert_eq!(
            i32::from_le_bytes(merged[16..20].try_into().unwrap()),
            0x120
        );
    }

    #[test]
    fn merged_header_rejects_unknown_encoding_and_duplicate_pc() {
        let mut unsupported = eh_frame_hdr(&[]);
        unsupported[3] = 0x00;
        assert_eq!(
            merge_eh_frame_hdr(Some((&unsupported, 0x2000)), 0x9000, 0x9100, 0x9200, 0x9120)
                .unwrap_err(),
            "unsupported or truncated PT_GNU_EH_FRAME header"
        );

        let old = eh_frame_hdr(&[(0x200, 0x240)]);
        assert_eq!(
            merge_eh_frame_hdr(Some((&old, 0x9000)), 0x9000, 0x9100, 0x9200, 0x9240)
                .unwrap_err(),
            "duplicate PC in merged PT_GNU_EH_FRAME table"
        );
    }
}
