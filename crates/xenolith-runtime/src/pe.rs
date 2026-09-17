use crate::windows::rva_to_ptr;

pub unsafe fn nt_headers(base: *mut u8) -> *mut u8 {
    let lfanew = *(base.add(0x3c) as *const u32) as usize;
    base.add(lfanew)
}

pub unsafe fn optional_header(base: *mut u8) -> *mut u8 {
    nt_headers(base).add(4 + 20)
}

pub unsafe fn size_of_image(base: *mut u8) -> u32 {
    *(optional_header(base).add(56) as *const u32)
}

pub unsafe fn entry_rva(base: *mut u8) -> u32 {
    *(optional_header(base).add(16) as *const u32)
}

pub unsafe fn section_count(base: *mut u8) -> u16 {
    *(nt_headers(base).add(4 + 2) as *const u16)
}

pub unsafe fn size_of_optional(base: *mut u8) -> u16 {
    *(nt_headers(base).add(4 + 16) as *const u16)
}

pub unsafe fn section_table(base: *mut u8) -> *mut u8 {
    optional_header(base).add(size_of_optional(base) as usize)
}

pub unsafe fn directory(base: *mut u8, index: usize) -> (u32, u32) {
    let dir = optional_header(base).add(112 + index * 8);
    (*(dir as *const u32), *(dir.add(4) as *const u32))
}

pub unsafe fn apply_relocs(base: *mut u8, preferred: u64) {
    let (rva, size) = directory(base, 5);
    if rva == 0 || size < 8 {
        return;
    }
    let delta = base as u64 as i64 - preferred as i64;
    if delta == 0 {
        return;
    }
    let mut offset = 0u32;
    while offset + 8 <= size {
        let block = rva_to_ptr(base, rva + offset);
        let page_rva = *(block as *const u32);
        let block_size = *(block.add(4) as *const u32);
        if block_size < 8 {
            break;
        }
        let count = ((block_size - 8) / 2) as usize;
        for i in 0..count {
            let entry = *(block.add(8 + i * 2) as *const u16);
            let kind = entry >> 12;
            let off = (entry & 0x0fff) as usize;
            if kind == 10 {
                let ptr = rva_to_ptr(base, page_rva).add(off) as *mut u64;
                *ptr = (*ptr as i64 + delta) as u64;
            }
        }
        offset = offset.saturating_add(block_size);
        if block_size == 0 {
            break;
        }
    }
}

pub unsafe fn poison_headers(base: *mut u8) {
    *base = 0;
    *base.add(1) = 0;
}
