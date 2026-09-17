//! Minimal PEB / export walking. No imports.

use core::ffi::c_void;

pub type HANDLE = *mut c_void;
pub type HMODULE = *mut c_void;
pub type BOOL = i32;
pub type DWORD = u32;
pub type NTSTATUS = i32;
pub type ULONG = u32;
pub type SIZE_T = usize;
pub type ULONG_PTR = usize;

pub const DLL_PROCESS_ATTACH: DWORD = 1;
pub const MEM_COMMIT: DWORD = 0x1000;
pub const MEM_RESERVE: DWORD = 0x2000;
pub const PAGE_READWRITE: DWORD = 0x04;
pub const PAGE_EXECUTE_READ: DWORD = 0x20;
pub const PAGE_EXECUTE_READWRITE: DWORD = 0x40;
pub const PAGE_READONLY: DWORD = 0x02;
pub const ThreadHideFromDebugger: ULONG = 0x11;
pub const ProcessDebugPort: ULONG = 7;
pub const ProcessDebugObjectHandle: ULONG = 0x1e;
pub const ProcessDebugFlags: ULONG = 0x1f;
pub const ProcessInstrumentationCallback: ULONG = 0x28;

#[repr(C)]
pub struct ListEntry {
    pub flink: *mut ListEntry,
    pub blink: *mut ListEntry,
}

#[repr(C)]
pub struct UnicodeString {
    pub length: u16,
    pub maximum_length: u16,
    pub buffer: *mut u16,
}

#[repr(C)]
pub struct PebLdrData {
    pub length: ULONG,
    pub initialized: BOOL,
    pub ss_handle: HANDLE,
    pub in_load_order: ListEntry,
    pub in_memory_order: ListEntry,
    pub in_init_order: ListEntry,
}

#[repr(C)]
pub struct LdrDataTableEntry {
    pub in_load_order: ListEntry,
    pub in_memory_order: ListEntry,
    pub in_init_order: ListEntry,
    pub dll_base: *mut u8,
    pub entry_point: *mut c_void,
    pub size_of_image: ULONG,
    pub full_dll_name: UnicodeString,
    pub base_dll_name: UnicodeString,
}

#[inline(always)]
pub unsafe fn peb() -> *mut u8 {
    let peb: *mut u8;
    core::arch::asm!("mov {}, gs:[0x60]", out(reg) peb, options(nostack, nomem, preserves_flags));
    peb
}

#[inline(always)]
pub unsafe fn peb_ldr(peb: *mut u8) -> *mut PebLdrData {
    *(peb.add(0x18) as *const *mut PebLdrData)
}

pub fn ascii_eq_ci(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .all(|(x, y)| x.to_ascii_lowercase() == y.to_ascii_lowercase())
}

pub unsafe fn unicode_to_ascii_lower(us: &UnicodeString, out: &mut [u8]) -> Option<usize> {
    if us.buffer.is_null() {
        return None;
    }
    let chars = (us.length as usize) / 2;
    if chars > out.len() {
        return None;
    }
    for i in 0..chars {
        let ch = *us.buffer.add(i);
        out[i] = if ch < 128 { (ch as u8).to_ascii_lowercase() } else { b'?' };
    }
    Some(chars)
}

pub unsafe fn module_by_name(want: &[u8]) -> Option<*mut u8> {
    let ldr = peb_ldr(peb());
    if ldr.is_null() {
        return None;
    }
    let head = &mut (*ldr).in_load_order as *mut ListEntry;
    let mut cur = (*head).flink;
    let mut buf = [0u8; 64];
    while !cur.is_null() && cur != head {
        let entry = cur as *mut LdrDataTableEntry;
        if let Some(n) = unicode_to_ascii_lower(&(*entry).base_dll_name, &mut buf) {
            if ascii_eq_ci(&buf[..n], want) {
                return Some((*entry).dll_base);
            }
        }
        cur = (*cur).flink;
    }
    None
}

pub unsafe fn rva_to_ptr(base: *mut u8, rva: u32) -> *mut u8 {
    base.add(rva as usize)
}

pub unsafe fn export_by_hash(base: *mut u8, hash: u32) -> Option<*mut c_void> {
    if base.is_null() {
        return None;
    }
    let lfanew = *(base.add(0x3c) as *const u32) as usize;
    let export_rva = *(base.add(lfanew + 4 + 20 + 112) as *const u32);
    if export_rva == 0 {
        return None;
    }
    let dir = rva_to_ptr(base, export_rva);
    let n_names = *(dir.add(24) as *const u32) as usize;
    let funcs = *(dir.add(28) as *const u32);
    let names = *(dir.add(32) as *const u32);
    let ords = *(dir.add(36) as *const u32);
    for i in 0..n_names {
        let name_rva = *(rva_to_ptr(base, names).add(i * 4) as *const u32);
        let name = rva_to_ptr(base, name_rva);
        if djb2(name) == hash {
            let ord = *(rva_to_ptr(base, ords).add(i * 2) as *const u16) as usize;
            let fn_rva = *(rva_to_ptr(base, funcs).add(ord * 4) as *const u32);
            return Some(rva_to_ptr(base, fn_rva) as *mut c_void);
        }
    }
    None
}

pub fn djb2(ptr: *mut u8) -> u32 {
    let mut h: u32 = 5381;
    let mut i = 0usize;
    unsafe {
        loop {
            let b = *ptr.add(i);
            if b == 0 {
                break;
            }
            h = h.wrapping_mul(33).wrapping_add(b.to_ascii_lowercase() as u32);
            i += 1;
            if i > 256 {
                break;
            }
        }
    }
    h
}

pub fn djb2_bytes(bytes: &[u8]) -> u32 {
    let mut h: u32 = 5381;
    for b in bytes {
        if *b == 0 {
            break;
        }
        h = h.wrapping_mul(33).wrapping_add(b.to_ascii_lowercase() as u32);
    }
    h
}

pub type FnVirtualProtect = unsafe extern "system" fn(*mut c_void, SIZE_T, DWORD, *mut DWORD) -> BOOL;
pub type FnVirtualAlloc = unsafe extern "system" fn(*mut c_void, SIZE_T, DWORD, DWORD) -> *mut c_void;
pub type FnGetProcAddress = unsafe extern "system" fn(HMODULE, *const u8) -> *mut c_void;
pub type FnLoadLibraryA = unsafe extern "system" fn(*const u8) -> HMODULE;
pub type FnNtSetInformationThread =
    unsafe extern "system" fn(HANDLE, ULONG, *mut c_void, ULONG) -> NTSTATUS;
pub type FnNtQueryInformationProcess =
    unsafe extern "system" fn(HANDLE, ULONG, *mut c_void, ULONG, *mut ULONG) -> NTSTATUS;
pub type FnGetCurrentThread = unsafe extern "system" fn() -> HANDLE;
pub type FnGetCurrentProcess = unsafe extern "system" fn() -> HANDLE;

pub struct Apis {
    pub virtual_protect: FnVirtualProtect,
    pub virtual_alloc: FnVirtualAlloc,
    pub get_proc_address: FnGetProcAddress,
    pub load_library_a: FnLoadLibraryA,
    pub get_current_thread: FnGetCurrentThread,
    pub get_current_process: FnGetCurrentProcess,
    pub nt_set_information_thread: Option<FnNtSetInformationThread>,
    pub nt_query_information_process: Option<FnNtQueryInformationProcess>,
}

pub unsafe fn resolve_apis() -> Option<Apis> {
    let k32 = module_by_name(b"kernel32.dll")?;
    let ntdll = module_by_name(b"ntdll.dll");
    let virtual_protect = core::mem::transmute(export_by_hash(k32, djb2_bytes(b"VirtualProtect"))?);
    let virtual_alloc = core::mem::transmute(export_by_hash(k32, djb2_bytes(b"VirtualAlloc"))?);
    let get_proc_address = core::mem::transmute(export_by_hash(k32, djb2_bytes(b"GetProcAddress"))?);
    let load_library_a = core::mem::transmute(export_by_hash(k32, djb2_bytes(b"LoadLibraryA"))?);
    let get_current_thread = core::mem::transmute(export_by_hash(k32, djb2_bytes(b"GetCurrentThread"))?);
    let get_current_process = core::mem::transmute(export_by_hash(k32, djb2_bytes(b"GetCurrentProcess"))?);
    let nt_set = ntdll.and_then(|b| export_by_hash(b, djb2_bytes(b"NtSetInformationThread")));
    let nt_query = ntdll.and_then(|b| export_by_hash(b, djb2_bytes(b"NtQueryInformationProcess")));
    Some(Apis {
        virtual_protect,
        virtual_alloc,
        get_proc_address,
        load_library_a,
        get_current_thread,
        get_current_process,
        nt_set_information_thread: nt_set.map(|p| core::mem::transmute(p)),
        nt_query_information_process: nt_query.map(|p| core::mem::transmute(p)),
    })
}
