use crate::crypto::{
    mix_runtime_key, page_key, page_mac, reconstruct_mba, xchacha20_poly1305_open, NONCE_LEN,
};
use crate::guard;
use crate::pe::{apply_relocs, poison_headers};
use crate::windows::{
    resolve_apis, rva_to_ptr, Apis, BOOL, DLL_PROCESS_ATTACH, DWORD, PAGE_EXECUTE_READWRITE,
    PAGE_READONLY,
};
use core::ffi::c_void;
use core::sync::atomic::{AtomicBool, Ordering};

const MAGIC: &[u8; 4] = b"NSEN";
static ACTIVATED: AtomicBool = AtomicBool::new(false);

#[repr(C)]
pub struct StubMeta {
    pub envelope_rva: u32,
    pub envelope_len: u32,
    pub original_entry_rva: u32,
    pub preferred_base: u64,
    pub measurement: [u8; 32],
}

#[no_mangle]
#[inline(never)]
pub unsafe extern "system" fn xl_unpack_entry(
    module: *mut u8,
    reason: DWORD,
    reserved: *mut c_void,
) -> BOOL {
    if module.is_null() {
        return 0;
    }
    if reason != DLL_PROCESS_ATTACH && reason != 0 {
        let meta = stub_meta(module);
        if meta.is_null() {
            return 1;
        }
        let original: unsafe extern "system" fn(*mut u8, DWORD, *mut c_void) -> BOOL =
            core::mem::transmute(rva_to_ptr(module, (*meta).original_entry_rva));
        return original(module, reason, reserved);
    }
    if ACTIVATED.swap(true, Ordering::SeqCst) {
        return 1;
    }
    if !activate(module) {
        return 0;
    }
    let meta = stub_meta(module);
    if meta.is_null() {
        return 0;
    }
    let original: unsafe extern "system" fn(*mut u8, DWORD, *mut c_void) -> BOOL =
        core::mem::transmute(rva_to_ptr(module, (*meta).original_entry_rva));
    original(module, reason, reserved)
}

#[no_mangle]
#[inline(never)]
pub unsafe extern "system" fn xl_tls_callback(
    module: *mut c_void,
    reason: DWORD,
    _reserved: *mut c_void,
) {
    if reason == DLL_PROCESS_ATTACH {
        let _ = xl_unpack_entry(module as *mut u8, reason, _reserved);
    }
}

unsafe fn stub_meta(module: *mut u8) -> *const StubMeta {
    // The packer places StubMeta immediately before the code entry via a
    // RIP-relative lea in the tiny thunk. Here we recover it from the first
    // section named by walking backwards is not reliable; instead the thunk
    // stores the meta pointer in GS unused is avoided. The packer patches
    // `lea rcx, [rip+disp]` so this function is only reached after RCX is set
    // in the thunk. For the exported C ABI we locate meta by envelope magic
    // scan of extra sections.
    locate_meta(module).unwrap_or(core::ptr::null())
}

unsafe fn locate_meta(module: *mut u8) -> Option<*const StubMeta> {
    let lfanew = *(module.add(0x3c) as *const u32) as usize;
    let file_header = module.add(lfanew + 4);
    let nsec = *(file_header.add(2) as *const u16) as usize;
    let opt_size = *(file_header.add(16) as *const u16) as usize;
    let sections = file_header.add(20 + opt_size);
    for i in 0..nsec {
        let sec = sections.add(i * 40);
        let va = *(sec.add(12) as *const u32);
        let vs = *(sec.add(8) as *const u32) as usize;
        if vs < core::mem::size_of::<StubMeta>() + 4 {
            continue;
        }
        let ptr = rva_to_ptr(module, va);
        for extra in [0usize, 16usize] {
            if vs > extra + core::mem::size_of::<StubMeta>() {
                let maybe = ptr.add(extra) as *const StubMeta;
                if (*maybe).envelope_len > 32 && (*maybe).original_entry_rva != 0 {
                    let env = rva_to_ptr(module, (*maybe).envelope_rva);
                    if core::slice::from_raw_parts(env, 4) == MAGIC {
                        return Some(maybe);
                    }
                }
            }
        }
        if vs >= core::mem::size_of::<StubMeta>() {
            let maybe = ptr.add(vs - core::mem::size_of::<StubMeta>()) as *const StubMeta;
            if (*maybe).envelope_len > 32 && (*maybe).original_entry_rva != 0 {
                let env = rva_to_ptr(module, (*maybe).envelope_rva);
                if core::slice::from_raw_parts(env, 4) == MAGIC {
                    return Some(maybe);
                }
            }
        }
        if core::slice::from_raw_parts(ptr, 4) == MAGIC {
            continue;
        }
        let maybe = ptr as *const StubMeta;
        if (*maybe).envelope_len > 32 && (*maybe).original_entry_rva != 0 {
            let env = rva_to_ptr(module, (*maybe).envelope_rva);
            if core::slice::from_raw_parts(env, 4) == MAGIC {
                return Some(maybe);
            }
        }
    }
    None
}

#[inline(never)]
#[allow(unused_assignments)]
unsafe fn activate(module: *mut u8) -> bool {
    let Some(meta) = locate_meta(module) else {
        return false;
    };
    let meta = &*meta;
    let Some(apis) = resolve_apis() else {
        return false;
    };
    let env = core::slice::from_raw_parts(
        rva_to_ptr(module, meta.envelope_rva),
        meta.envelope_len as usize,
    );
    if env.len() < 11 || &env[..4] != MAGIC {
        return false;
    }
    let mut cur = 4usize;
    let _version = u16::from_le_bytes(env[cur..cur + 2].try_into().unwrap());
    cur += 2;
    let profile = env[cur];
    cur += 1;
    if !guard::run(&apis, false) {
        return false;
    }
    let _ = profile;
    let page_count = u32::from_le_bytes(env[cur..cur + 4].try_into().unwrap()) as usize;
    cur += 4;
    if cur + 96 > env.len() {
        return false;
    }
    let mba = &env[cur..cur + 96];
    cur += 96;
    let _opcode_seed = &env[cur..cur + 16];
    cur += 16;
    let mut api_salt = [0u8; 16];
    api_salt.copy_from_slice(&env[cur..cur + 16]);
    cur += 16;
    let stolen_len = u16::from_le_bytes(env[cur..cur + 2].try_into().unwrap()) as usize;
    cur += 2;
    if cur + stolen_len + 4 > env.len() {
        return false;
    }
    let stolen = &env[cur..cur + stolen_len];
    cur += stolen_len;
    let prog_len = u32::from_le_bytes(env[cur..cur + 4].try_into().unwrap()) as usize;
    cur += 4;
    if cur + prog_len > env.len() {
        return false;
    }
    cur += prog_len;

    let Some(secret) = reconstruct_mba(mba) else {
        return false;
    };
    let mut measure_src = [0u8; 96 + 16 + 4];
    measure_src[..96].copy_from_slice(mba);
    measure_src[96..112].copy_from_slice(_opcode_seed);
    measure_src[112..116].copy_from_slice(&(page_count as u32).to_le_bytes());
    let measurement = crate::crypto::image_measurement(&measure_src);
    if measurement != meta.measurement {
        return false;
    }
    let Some(runtime) = mix_runtime_key(&secret, &measurement) else {
        return false;
    };

    apply_relocs(module, meta.preferred_base);

    for _ in 0..page_count {
        if cur + 4 + 4 + 4 + NONCE_LEN + 4 > env.len() {
            return false;
        }
        let index = u32::from_le_bytes(env[cur..cur + 4].try_into().unwrap());
        cur += 4;
        let rva = u32::from_le_bytes(env[cur..cur + 4].try_into().unwrap());
        cur += 4;
        let plain_len = u32::from_le_bytes(env[cur..cur + 4].try_into().unwrap()) as usize;
        cur += 4;
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&env[cur..cur + NONCE_LEN]);
        cur += NONCE_LEN;
        let ct_len = u32::from_le_bytes(env[cur..cur + 4].try_into().unwrap()) as usize;
        cur += 4;
        if cur + ct_len + 32 > env.len() {
            return false;
        }
        let ct = &env[cur..cur + ct_len];
        cur += ct_len;
        let mut mac = [0u8; 32];
        mac.copy_from_slice(&env[cur..cur + 32]);
        cur += 32;
        if page_mac(&runtime, &meta.measurement, index, &nonce, ct) != mac {
            return false;
        }
        let key = page_key(&runtime, index, &nonce);
        if ct_len < 16 {
            return false;
        }
        let dest = rva_to_ptr(module, rva);
        let mut old = 0u32;
        if (apis.virtual_protect)(dest as *mut c_void, 0x1000, PAGE_EXECUTE_READWRITE, &mut old) == 0
        {
            return false;
        }
        if !xchacha20_poly1305_open(&key, &nonce, ct, core::slice::from_raw_parts_mut(dest, ct_len - 16))
        {
            let _ = (apis.virtual_protect)(dest as *mut c_void, 0x1000, old, &mut old);
            return false;
        }
        let _ = (apis.virtual_protect)(dest as *mut c_void, 0x1000, old, &mut old);
        let _ = plain_len;
    }

    if cur + 4 > env.len() {
        return false;
    }
    let nimp = u32::from_le_bytes(env[cur..cur + 4].try_into().unwrap()) as usize;
    cur += 4;
    for _ in 0..nimp {
        if cur + 32 + 4 + 2 > env.len() {
            return false;
        }
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&env[cur..cur + 32]);
        cur += 32;
        let iat_rva = u32::from_le_bytes(env[cur..cur + 4].try_into().unwrap());
        cur += 4;
        let name_len = u16::from_le_bytes(env[cur..cur + 2].try_into().unwrap()) as usize;
        cur += 2;
        if cur + name_len + 2 > env.len() {
            return false;
        }
        let dll_len = u16::from_le_bytes(env[cur..cur + 2].try_into().unwrap()) as usize;
        cur += 2;
        if cur + name_len + dll_len > env.len() {
            return false;
        }
        let name = &env[cur..cur + name_len];
        cur += name_len;
        let dll = &env[cur..cur + dll_len];
        cur += dll_len;
        let _ = (hash, api_salt);
        if !bind_import(&apis, module, iat_rva, dll, name) {
            return false;
        }
    }

    if !stolen.is_empty() {
        let dest = rva_to_ptr(module, meta.original_entry_rva);
        let mut old = 0u32;
        if (apis.virtual_protect)(dest as *mut c_void, stolen.len(), PAGE_EXECUTE_READWRITE, &mut old)
            == 0
        {
            return false;
        }
        core::ptr::copy_nonoverlapping(stolen.as_ptr(), dest, stolen.len());
        let _ = (apis.virtual_protect)(dest as *mut c_void, stolen.len(), old, &mut old);
    }

    if profile == 3 {
        let mut old = 0u32;
        let _ = (apis.virtual_protect)(module as *mut c_void, 0x1000, PAGE_READONLY, &mut old);
        poison_headers(module);
        let _ = (apis.virtual_protect)(module as *mut c_void, 0x1000, old, &mut old);
    }
    true
}

unsafe fn bind_import(apis: &Apis, module: *mut u8, iat_rva: u32, dll: &[u8], name: &[u8]) -> bool {
    let mut dllz = [0u8; 96];
    if dll.len() >= dllz.len() {
        return false;
    }
    dllz[..dll.len()].copy_from_slice(dll);
    let mut namez = [0u8; 96];
    if name.len() >= namez.len() {
        return false;
    }
    namez[..name.len()].copy_from_slice(name);
    let handle = (apis.load_library_a)(dllz.as_ptr());
    if handle.is_null() {
        return false;
    }
    let proc = (apis.get_proc_address)(handle, namez.as_ptr());
    if proc.is_null() {
        return false;
    }
    let slot = rva_to_ptr(module, iat_rva) as *mut u64;
    let mut old = 0u32;
    if (apis.virtual_protect)(slot as *mut c_void, 8, PAGE_EXECUTE_READWRITE, &mut old) == 0 {
        return false;
    }
    *slot = proc as u64;
    let _ = (apis.virtual_protect)(slot as *mut c_void, 8, old, &mut old);
    true
}
