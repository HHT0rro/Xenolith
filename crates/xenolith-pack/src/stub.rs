//! Handwritten x64 PIC unpack stub.
//!
//! Production path: walk the PEB, resolve kernel32, fill `XlHostCtx`, call the
//! embedded freestanding `xl_core_activate` (EnvelopeV2 + ChaCha20-Poly1305).
//! The core copies pages RW→RX. Legacy XOR+FNV remains only in unused labels
//! for old fixtures; v2 artifacts never take that path.

use iced_x86::code_asm::*;
use iced_x86::BlockEncoderOptions;
use xenolith_crypto::{PAGE_MAC_DOMAIN, WRAP_DOMAIN};

/// Meta block appended after the code (also embedded as a label below).
pub const STUB_META_LEN: usize = 80;
pub const META_PAYLOAD_RVA: usize = 0;
pub const META_ENVELOPE_LEN: usize = 4;
pub const META_ORIGINAL_ENTRY: usize = 8;
pub const META_UNPACKED: usize = 12;
pub const META_MEASUREMENT: usize = 16;
/// Original first TLS callback RVA; 0 if the image has no TLS callbacks.
pub const META_TLS_CALLBACK: usize = 64;

const HASH_KERNEL32: u32 = 0x7040_ee75;
const HASH_GET_PROC: u32 = 0xcf31_bb1f;
const HASH_LOAD_LIB: u32 = 0x5fbf_f0fb;
const HASH_VPROTECT: u32 = 0x844f_f18d;
const HASH_NTDLL: u32 = 0x22d3_b5ed;
const HASH_NTQIP: u32 = 0xd034_fc62;
const HASH_NTSIT: u32 = 0x5421_2e31;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;
const THREAD_HIDE_FROM_DEBUGGER: u32 = 0x11;
const PROCESS_DEBUG_PORT: u32 = 7;
const PROCESS_DEBUG_OBJECT_HANDLE: u32 = 0x1e;
const PROCESS_DEBUG_FLAGS: u32 = 0x1f;
const ENV_OPCODES: i32 = 139;

/// Envelope offsets the stub parses.
const ENV_PAGE_COUNT: i32 = 7;
const ENV_STOLEN_LEN: i32 = 147;
const ENV_STOLEN: i32 = 149;

pub struct PicStub {
    pub bytes: Vec<u8>,
    pub meta_off: usize,
    pub entry_off: u32,
    /// TLS callback trampoline (unpack, then original first callback).
    pub tls_entry_off: u32,
    /// Byte offset of each guest thunk from the start of the stub section.
    pub guest_thunk_offs: Vec<u32>,
    /// G5: VEH fault trampoline (calls xl_core_fault) and quiesce trampoline
    /// (calls xl_core_quiesce(1)); 0 when the core lacks them.
    pub fault_thunk_off: u32,
    pub quiesce_thunk_off: u32,
    /// Page-aligned offset of the runtime state block (RW at runtime).
    pub state_off: u32,
}

/// Per-export unique PIC (superoperators). Empty = no selected-export VM.
#[derive(Clone, Debug, Default)]
pub struct GuestEmit {
    pub functions: Vec<Vec<u8>>,
}

pub fn emit_pic_stub(seed: &[u8; 16]) -> Result<PicStub, String> {
    emit_pic_stub_with_guest(seed, &GuestEmit::default())
}

pub fn emit_pic_stub_with_guest(seed: &[u8; 16], guest: &GuestEmit) -> Result<PicStub, String> {
    emit_inner(seed, guest, &[], 0, true, true).map_err(|e| format!("pic stub: {e}"))
}

pub fn emit_pic_stub_with_core(
    seed: &[u8; 16],
    guest: &GuestEmit,
    core: &[u8],
    core_entry: u32,
    is_dll: bool,
    iat_writeback: bool,
) -> Result<PicStub, String> {
    if core.is_empty() {
        return Err("empty xl_core object".into());
    }
    emit_inner(seed, guest, core, core_entry, is_dll, iat_writeback)
        .map_err(|e| format!("pic stub: {e}"))
}

/// G5 entry points inside the embedded xl_core object (fault/quiesce).
#[derive(Clone, Debug, Default)]
pub struct CoreEntryPoints {
    pub fault_off: u32,
    pub quiesce_off: u32,
    /// Initialized runtime state; placed on a dedicated page (RW at load).
    pub state: Vec<u8>,
    /// Master switch: false emits the pre-G5 stub verbatim (no VEH hook,
    /// no detach quiesce, no thunks, no state block).
    pub enabled: bool,
}

pub fn emit_pic_stub_with_core_g5(
    seed: &[u8; 16],
    guest: &GuestEmit,
    core: &[u8],
    core_entry: u32,
    g5: CoreEntryPoints,
    is_dll: bool,
    iat_writeback: bool,
) -> Result<PicStub, String> {
    if core.is_empty() {
        return Err("empty xl_core object".into());
    }
    emit_inner_g5(seed, guest, core, core_entry, g5, is_dll, iat_writeback)
        .map_err(|e| format!("pic stub: {e}"))
}

fn emit_inner(
    seed: &[u8; 16],
    guest: &GuestEmit,
    core: &[u8],
    core_entry: u32,
    is_dll: bool,
    iat_writeback: bool,
) -> Result<PicStub, iced_x86::IcedError> {
    emit_inner_g5(
        seed,
        guest,
        core,
        core_entry,
        CoreEntryPoints::default(),
        is_dll,
        iat_writeback,
    )
}

fn emit_inner_g5(
    seed: &[u8; 16],
    guest: &GuestEmit,
    core: &[u8],
    core_entry: u32,
    g5: CoreEntryPoints,
    is_dll: bool,
    iat_writeback: bool,
) -> Result<PicStub, iced_x86::IcedError> {
    let mut a = CodeAssembler::new(64)?;

    let mut l_tls_entry = a.create_label();
    let mut l_main_entry = a.create_label();
    let mut l_after_mode = a.create_label();
    let mut l_tls_done = a.create_label();
    let mut l_forward = a.create_label();
    let mut l_do_unpack = a.create_label();
    let mut l_have_base = a.create_label();
    let mut l_fail = a.create_label();
    let mut l_mod_loop = a.create_label();
    let mut l_hash_loop = a.create_label();
    let mut l_hash_keep = a.create_label();
    let mut l_hash_done = a.create_label();
    let mut l_mod_next = a.create_label();
    let mut l_k32 = a.create_label();
    let mut l_exp_loop = a.create_label();
    let mut l_nhash = a.create_label();
    let mut l_nhash_done = a.create_label();
    let mut l_store_gp = a.create_label();
    let mut l_store_ll = a.create_label();
    let mut l_store_vp = a.create_label();
    let mut l_exp_next = a.create_label();
    let mut l_apis_chk = a.create_label();
    let mut l_mba_done = a.create_label();
    let mut l_mix = a.create_label();
    let mut l_mix_done = a.create_label();
    let mut l_pages = a.create_label();
    let mut l_pkey = a.create_label();
    let mut l_pkey_n1 = a.create_label();
    let mut l_pkey_done = a.create_label();
    let mut l_xor = a.create_label();
    let mut l_xor_done = a.create_label();
    let mut l_dig = a.create_label();
    let mut l_dig_done = a.create_label();
    let mut l_scr_loop = a.create_label();
    let mut l_scr_done = a.create_label();
    let mut l_scr_fill = a.create_label();
    let mut l_cpnonce = a.create_label();
    let mut l_cpnonce_k = a.create_label();
    let mut l_cpnonce_done = a.create_label();
    let mut l_imports = a.create_label();
    let mut l_imp_loop = a.create_label();
    let mut l_cpname = a.create_label();
    let mut l_cpname_done = a.create_label();
    let mut l_cpdll = a.create_label();
    let mut l_cpdll_done = a.create_label();
    let mut l_finish = a.create_label();
    let mut l_cpstolen = a.create_label();
    let mut l_cpstolen_done = a.create_label();
    let mut l_exe = a.create_label();
    let mut l_epilogue = a.create_label();
    let mut l_gate_true = a.create_label();
    let mut l_unpack_flag = a.create_label();
    let mut l_reenc = a.create_label();
    let mut l_reenc_loop = a.create_label();
    let mut l_reenc_skip = a.create_label();
    let mut l_reenc_xor = a.create_label();
    let mut l_reenc_xor_done = a.create_label();
    let mut l_reenc_done = a.create_label();
    let mut l_reenc_nexp = a.create_label();
    let mut l_reenc_nexp_k = a.create_label();
    let mut l_reenc_nexp_done = a.create_label();
    let mut l_reenc_pkey = a.create_label();
    let mut l_reenc_pkey_n1 = a.create_label();
    let mut l_reenc_pkey_done = a.create_label();
    let mut l_reenc_ret = a.create_label();
    let mut l_reenc_do = a.create_label();
    let mut l_keep_scan = a.create_label();
    let mut l_keep_hit = a.create_label();
    let mut l_keep_next = a.create_label();
    let mut l_imp_more = a.create_label();
    let mut l_mod_ntdll = a.create_label();
    let mut l_mod_ntdll_found = a.create_label();
    let mut l_ntdll_hash_loop = a.create_label();
    let mut l_ntdll_hash_keep = a.create_label();
    let mut l_ntdll_hash_done = a.create_label();
    let mut l_ntdll_mod_next = a.create_label();
    let mut l_ntexp_loop = a.create_label();
    let mut l_ntexp_next = a.create_label();
    let mut l_ntnhash = a.create_label();
    let mut l_ntnhash_done = a.create_label();
    let mut l_store_ntqip = a.create_label();
    let mut l_store_ntsit = a.create_label();
    let mut l_probes = a.create_label();
    let mut l_probe_skip = a.create_label();
    let mut l_int3_chk = a.create_label();
    let mut l_dr_ok = a.create_label();
    let mut l_vm_loop = a.create_label();
    let mut l_vm_halt = a.create_label();
    let mut l_vm_load = a.create_label();
    let mut l_vm_mix = a.create_label();
    let mut l_vm_add = a.create_label();
    let mut l_vm_xor = a.create_label();
    let mut l_vm_mul = a.create_label();
    let mut l_vm_unk = a.create_label();
    let mut wrap_dom = a.create_label();
    let mut mac_dom = a.create_label();
    let mut meta = a.create_label();
    let mut l_core_call = a.create_label();
    let mut l_core_bytes = a.create_label();
    let mut l_fault_thunk = a.create_label();
    let mut l_quiesce_thunk = a.create_label();
    let mut l_detach_quiesce = a.create_label();
    let mut l_veh_skip = a.create_label();
    let mut l_veh_name = a.create_label();
    let mut l_veh_remove_name = a.create_label();
    let mut l_quiesce_go = a.create_label();

    let g5_emit_code = g5.enabled && g5.fault_off != 0;
    let g5_emit_state = !g5.state.is_empty() && !core.is_empty();

    // TLS callback trampoline first so the array can point here. r9d=1 means
    // "return to the original TLS callback, do not run DllMain/EXE entry".
    a.set_label(&mut l_tls_entry)?;
    a.mov(r9d, 1u32)?;
    a.jmp(l_after_mode)?;
    a.set_label(&mut l_main_entry)?;
    a.xor(r9d, r9d)?;
    a.set_label(&mut l_after_mode)?;

    // Entry polymorphism: seed-colored register junk (never pushad;call
    // template). r10/r11 are volatile and re-assigned before first use.
    let word = |o: usize| -> u32 {
        u32::from_le_bytes([seed[o], seed[o + 1], seed[o + 2], seed[o + 3]])
    };
    a.mov(r10d, word(0))?;
    a.mov(r11d, word(8))?;
    a.xor(r10d, word(4))?;
    a.xor(r11d, word(12))?;

    a.push(rbx)?;
    a.push(rbp)?;
    a.push(rsi)?;
    a.push(rdi)?;
    a.push(r12)?;
    a.push(r13)?;
    a.push(r14)?;
    a.push(r15)?;
    // Entry rsp ≡ 8; 8 pushes keep ≡ 8; sub 0x3F8 (≡8 mod 16) → ≡ 0 at calls.
    // G5: xl_core keeps a ~1.7 KB region table on its frame; the frame
    // must cover it plus the original working area.
    a.sub(rsp, 0x2FF8i32)?;

    // Frame map (positive offsets are ours; [rsp..+0x20) is callee shadow):
    //  +0x28 reason   +0x30 reserved  +0x38 GetProcAddress  +0x40 LoadLibraryA
    //  +0x48 VirtualProtect  +0x50 kernel32  +0x58 old protect
    //  +0x60 secret(32)  +0x80 runtime key(32)  +0xA0 page key(32)
    //  +0xC0 idx(4)/name buffer  +0xE0 envelope spill scratch  +0xE8 pages left
    //  +0xF0 G5 VEH handle  +0xF8 G5 RemoveVectoredExceptionHandler
    //  +0x100 imports left  +0x108 stride  +0x110 scratch
    //  +0x118 slot va  +0x120 AddVectoredExceptionHandler (G5; consumed at
    //  l_apis_chk, before the page loops reuse +0x120 as nonce scratch)
    a.mov(r15, rcx)?; // DLL: DllMain hinst. EXE: overwritten from PEB below.
    a.mov(dword_ptr(rsp + 0x28), edx)?;
    a.mov(qword_ptr(rsp + 0x30), r8)?;
    // API slots must be safe to call on every gate path (gate 0 jumps
    // straight to l_finish, which VirtualProtects before copying).
    a.xor(eax, eax)?;
    a.mov(qword_ptr(rsp + 0x38), rax)?;
    a.mov(qword_ptr(rsp + 0x40), rax)?;
    a.mov(qword_ptr(rsp + 0x48), rax)?;
    a.mov(qword_ptr(rsp + 0x58), rax)?;
    a.mov(qword_ptr(rsp + 0x120), rax)?; // AddVectoredExceptionHandler (G5)
    a.mov(qword_ptr(rsp + 0xF0), rax)?; // G5 VEH handle
    a.mov(qword_ptr(rsp + 0xF8), rax)?; // G5 VEH remover
    a.mov(dword_ptr(rsp + 0x1F8), r9d)?; // 1 = TLS callback, 0 = DllMain/EXE
    a.lea(rbx, ptr(meta))?;

    if !is_dll {
        // EXE: rcx is not the image base on the process entry. TLS callbacks
        // do pass the module handle, but the later WinMain path does not.
        a.db(&[0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00])?;
        a.mov(r15, qword_ptr(rax + 0x10))?;
    }

    a.cmp(dword_ptr(rbx + META_UNPACKED as i32), 1)?;
    a.je(l_forward)?;

    if is_dll {
        // DLL: unpack only on DLL_PROCESS_ATTACH. rcx is the module handle.
        a.mov(eax, dword_ptr(r15 + 0x3C))?;
        a.movzx(eax, word_ptr(r15 + rax + 22))?;
        a.test(eax, 0x2000u32)?;
        a.jz(l_do_unpack)?;
        a.cmp(dword_ptr(rsp + 0x28), 1)?;
        a.je(l_do_unpack)?;
        a.cmp(dword_ptr(rbx + META_UNPACKED as i32), 1)?;
        a.je(l_detach_quiesce)?;
        a.jmp(l_fail)?;
    } else {
        a.jmp(l_do_unpack)?;
    }

    a.set_label(&mut l_do_unpack)?;
    a.mov(eax, dword_ptr(r15 + 0x3C))?;
    a.cmp(dword_ptr(r15 + rax), 0x0000_4550u32)?; // 'PE\0\0'
    a.je(l_have_base)?;
    if is_dll {
        a.jmp(l_fail)?;
    } else {
        a.db(&[0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00])?;
        a.mov(r15, qword_ptr(rax + 0x10))?;
    }
    a.set_label(&mut l_have_base)?;

    a.mov(eax, dword_ptr(rbx + META_PAYLOAD_RVA as i32))?;
    a.lea(r14, ptr(r15 + rax))?;
    a.cmp(dword_ptr(r14), 0x3256_4C58u32)?; // 'XLV2'
    a.jne(l_fail)?;
    // Spill the envelope pointer: the export walk needs its registers.
    a.mov(qword_ptr(rsp + 0xE0), r14)?;
    a.movzx(eax, byte_ptr(r14 + 6i32))?;
    a.mov(dword_ptr(rsp + 0x1F0), eax)?; // cached profile

    // Debug gate (meta byte 63): 0 = map+entry only, 1 = +PEB/APIs,
    // 2 = +key/pages, 3 = full unpack. Lower gates return TRUE without
    // calling the original entry.
    a.movzx(eax, byte_ptr(rbx + 63i32))?;
    a.test(eax, eax)?;
    // Gate 0 skips the stolen restore too: APIs are not resolved yet and the
    // entry page is still ciphertext.
    a.jz(l_unpack_flag)?;

    // ---- PEB walk: find kernel32 ----
    a.db(&[0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00])?; // mov rax, gs:[0x60]
    a.mov(rax, qword_ptr(rax + 0x18))?; // Ldr
    a.lea(r12, ptr(rax + 0x10))?; // InLoadOrderModuleList head
    a.mov(r13, qword_ptr(r12))?;

    a.set_label(&mut l_mod_loop)?;
    a.cmp(r13, r12)?;
    a.je(l_fail)?;
    a.mov(rsi, qword_ptr(r13 + 0x60))?; // BaseDllName.Buffer
    a.movzx(ecx, word_ptr(r13 + 0x58))?; // BaseDllName.Length (bytes)
    a.test(rsi, rsi)?;
    a.jz(l_mod_next)?;
    a.mov(r8d, 5381u32)?;
    a.xor(edx, edx)?;

    a.set_label(&mut l_hash_loop)?;
    a.cmp(edx, ecx)?;
    a.jae(l_hash_done)?;
    a.movzx(eax, byte_ptr(rsi + rdx))?; // low byte of UTF-16 char
    a.cmp(al, b'A' as u32)?;
    a.jb(l_hash_keep)?;
    a.cmp(al, b'Z' as u32)?;
    a.ja(l_hash_keep)?;
    a.add(al, 32u32)?;
    a.set_label(&mut l_hash_keep)?;
    a.mov(r9d, r8d)?;
    a.shl(r8d, 5)?; // hash * 33
    a.add(r8d, r9d)?;
    a.add(r8d, eax)?;
    a.add(edx, 2i32)?;
    a.jmp(l_hash_loop)?;

    a.set_label(&mut l_hash_done)?;
    a.cmp(r8d, HASH_KERNEL32)?;
    a.je(l_k32)?;
    a.set_label(&mut l_mod_next)?;
    a.mov(r13, qword_ptr(r13))?;
    a.jmp(l_mod_loop)?;

    // ---- resolve GetProcAddress / LoadLibraryA / VirtualProtect ----
    a.set_label(&mut l_k32)?;
    a.mov(r12, qword_ptr(r13 + 0x30))?; // DllBase
    a.mov(qword_ptr(rsp + 0x50), r12)?;
    a.xor(eax, eax)?;
    a.mov(qword_ptr(rsp + 0x38), rax)?;
    a.mov(qword_ptr(rsp + 0x40), rax)?;
    a.mov(qword_ptr(rsp + 0x48), rax)?;

    a.mov(eax, dword_ptr(r12 + 0x3C))?;
    a.mov(eax, dword_ptr(r12 + rax + 0x88))?; // export dir RVA
    a.test(eax, eax)?;
    a.jz(l_fail)?;
    a.lea(r13, ptr(r12 + rax))?;
    a.mov(r8d, dword_ptr(r13 + 24))?; // NumberOfNames
    a.test(r8d, r8d)?;
    a.jz(l_fail)?;
    a.mov(esi, dword_ptr(r13 + 32))?; // AddressOfNames
    a.mov(edi, dword_ptr(r13 + 36))?; // AddressOfNameOrdinals
    a.mov(ebp, dword_ptr(r13 + 28))?; // AddressOfFunctions
    a.xor(r14d, r14d)?;

    a.set_label(&mut l_exp_loop)?;
    a.cmp(r14d, r8d)?;
    a.jae(l_apis_chk)?;
    a.lea(rax, ptr(r12 + rsi))?;
    a.mov(eax, dword_ptr(rax + r14 * 4))?;
    a.lea(r9, ptr(r12 + rax))?; // name
    a.mov(r11, r9)?;
    a.mov(r10d, 5381u32)?;

    a.set_label(&mut l_nhash)?;
    a.movzx(ecx, byte_ptr(r11))?;
    a.test(cl, cl)?;
    a.jz(l_nhash_done)?;
    a.mov(eax, r10d)?;
    a.shl(r10d, 5)?;
    a.add(r10d, eax)?;
    a.add(r10d, ecx)?;
    a.inc(r11)?;
    a.jmp(l_nhash)?;

    a.set_label(&mut l_nhash_done)?;
    a.cmp(r10d, HASH_GET_PROC)?;
    a.je(l_store_gp)?;
    a.cmp(r10d, HASH_LOAD_LIB)?;
    a.je(l_store_ll)?;
    a.cmp(r10d, HASH_VPROTECT)?;
    a.je(l_store_vp)?;
    a.jmp(l_exp_next)?;

    a.set_label(&mut l_store_gp)?;
    a.lea(rax, ptr(r12 + rdi))?;
    a.movzx(ecx, word_ptr(rax + r14 * 2))?;
    a.lea(rdx, ptr(r12 + rbp))?;
    a.mov(eax, dword_ptr(rdx + rcx * 4))?;
    a.lea(rcx, ptr(r12 + rax))?;
    a.mov(qword_ptr(rsp + 0x38), rcx)?;
    a.jmp(l_exp_next)?;

    a.set_label(&mut l_store_ll)?;
    a.lea(rax, ptr(r12 + rdi))?;
    a.movzx(ecx, word_ptr(rax + r14 * 2))?;
    a.lea(rdx, ptr(r12 + rbp))?;
    a.mov(eax, dword_ptr(rdx + rcx * 4))?;
    a.lea(rcx, ptr(r12 + rax))?;
    a.mov(qword_ptr(rsp + 0x40), rcx)?;
    a.jmp(l_exp_next)?;

    a.set_label(&mut l_store_vp)?;
    a.lea(rax, ptr(r12 + rdi))?;
    a.movzx(ecx, word_ptr(rax + r14 * 2))?;
    a.lea(rdx, ptr(r12 + rbp))?;
    a.mov(eax, dword_ptr(rdx + rcx * 4))?;
    a.lea(rcx, ptr(r12 + rax))?;
    a.mov(qword_ptr(rsp + 0x48), rcx)?;
    a.jmp(l_exp_next)?;

    a.set_label(&mut l_exp_next)?;
    a.inc(r14d)?;
    a.jmp(l_exp_loop)?;

    a.set_label(&mut l_apis_chk)?;
    a.mov(r14, qword_ptr(rsp + 0xE0))?; // restore envelope pointer
    a.cmp(qword_ptr(rsp + 0x38), 0)?;
    a.je(l_fail)?;
    a.cmp(qword_ptr(rsp + 0x40), 0)?;
    a.je(l_fail)?;
    a.cmp(qword_ptr(rsp + 0x48), 0)?;
    a.je(l_fail)?;
    // G5: AddVectoredExceptionHandler is a KERNEL32 *forwarder* (the export
    // RVA is a string "NTDLL.RtlAddVectoredExceptionHandler" in a RO page).
    // Resolve it through GetProcAddress so the loader follows the forwarder
    // instead of treating the string as a function.
    if g5_emit_code {
        a.sub(rsp, 0x20i32)?;
        a.mov(rcx, qword_ptr(rsp + 0x20 + 0x50))?; // kernel32 base
        a.lea(rdx, ptr(l_veh_name))?;
        a.call(qword_ptr(rsp + 0x20 + 0x38))?; // GetProcAddress
        a.add(rsp, 0x20i32)?;
        a.test(rax, rax)?;
        a.jz(l_veh_skip)?;
        a.mov(qword_ptr(rsp + 0x120), rax)?;
        a.sub(rsp, 0x20i32)?;
        a.mov(ecx, 1u32)?; // First = 1 (front of the chain)
        a.lea(rdx, ptr(l_fault_thunk))?;
        a.call(qword_ptr(rsp + 0x20 + 0x120))?;
        a.add(rsp, 0x20i32)?;
        // Stash the registration handle and the remover for quiesce: the
        // handle MUST be dropped before the module unmaps or the process
        // keeps a VEH pointing into unmapped memory.
        a.mov(qword_ptr(rsp + 0xF0), rax)?;
        a.sub(rsp, 0x20i32)?;
        a.mov(rcx, qword_ptr(rsp + 0x20 + 0x50))?; // kernel32 base
        a.lea(rdx, ptr(l_veh_remove_name))?;
        a.call(qword_ptr(rsp + 0x20 + 0x38))?; // GetProcAddress
        a.add(rsp, 0x20i32)?;
        a.mov(qword_ptr(rsp + 0xF8), rax)?;
        a.set_label(&mut l_veh_skip)?;
    }
    a.cmp(byte_ptr(rbx + 63i32), 1i32)?;
    a.je(l_core_call)?;

    // ---- ntdll walk (max-profile probes). Missing ntdll skips probes. ----
    a.xor(eax, eax)?;
    a.mov(qword_ptr(rsp + 0x1A0), rax)?;
    a.mov(qword_ptr(rsp + 0x1A8), rax)?;
    a.mov(qword_ptr(rsp + 0x1B0), rax)?;
    a.db(&[0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00])?;
    a.mov(rax, qword_ptr(rax + 0x18))?;
    a.lea(r12, ptr(rax + 0x10))?;
    a.mov(r13, qword_ptr(r12))?;
    a.set_label(&mut l_mod_ntdll)?;
    a.cmp(r13, r12)?;
    a.je(l_probes)?;
    a.mov(rsi, qword_ptr(r13 + 0x60))?;
    a.movzx(ecx, word_ptr(r13 + 0x58))?;
    a.test(rsi, rsi)?;
    a.jz(l_ntdll_mod_next)?;
    a.mov(r8d, 5381u32)?;
    a.xor(edx, edx)?;
    a.set_label(&mut l_ntdll_hash_loop)?;
    a.cmp(edx, ecx)?;
    a.jae(l_ntdll_hash_done)?;
    a.movzx(eax, byte_ptr(rsi + rdx))?;
    a.cmp(al, b'A' as u32)?;
    a.jb(l_ntdll_hash_keep)?;
    a.cmp(al, b'Z' as u32)?;
    a.ja(l_ntdll_hash_keep)?;
    a.add(al, 32u32)?;
    a.set_label(&mut l_ntdll_hash_keep)?;
    a.mov(r9d, r8d)?;
    a.shl(r8d, 5)?;
    a.add(r8d, r9d)?;
    a.add(r8d, eax)?;
    a.add(edx, 2i32)?;
    a.jmp(l_ntdll_hash_loop)?;
    a.set_label(&mut l_ntdll_hash_done)?;
    a.cmp(r8d, HASH_NTDLL)?;
    a.je(l_mod_ntdll_found)?;
    a.set_label(&mut l_ntdll_mod_next)?;
    a.mov(r13, qword_ptr(r13))?;
    a.jmp(l_mod_ntdll)?;

    a.set_label(&mut l_mod_ntdll_found)?;
    a.mov(r12, qword_ptr(r13 + 0x30))?;
    a.mov(qword_ptr(rsp + 0x1A0), r12)?;
    a.mov(eax, dword_ptr(r12 + 0x3C))?;
    a.mov(eax, dword_ptr(r12 + rax + 0x88))?;
    a.test(eax, eax)?;
    a.jz(l_probes)?;
    a.lea(r13, ptr(r12 + rax))?;
    a.mov(r8d, dword_ptr(r13 + 24))?;
    a.mov(esi, dword_ptr(r13 + 32))?;
    a.mov(edi, dword_ptr(r13 + 36))?;
    a.mov(ebp, dword_ptr(r13 + 28))?;
    a.xor(r14d, r14d)?;
    a.set_label(&mut l_ntexp_loop)?;
    a.cmp(r14d, r8d)?;
    a.jae(l_probes)?;
    a.lea(rax, ptr(r12 + rsi))?;
    a.mov(eax, dword_ptr(rax + r14 * 4))?;
    a.lea(r9, ptr(r12 + rax))?;
    a.mov(r11, r9)?;
    a.mov(r10d, 5381u32)?;
    a.set_label(&mut l_ntnhash)?;
    a.movzx(ecx, byte_ptr(r11))?;
    a.test(cl, cl)?;
    a.jz(l_ntnhash_done)?;
    a.mov(eax, r10d)?;
    a.shl(r10d, 5)?;
    a.add(r10d, eax)?;
    a.add(r10d, ecx)?;
    a.inc(r11)?;
    a.jmp(l_ntnhash)?;
    a.set_label(&mut l_ntnhash_done)?;
    a.cmp(r10d, HASH_NTQIP)?;
    a.je(l_store_ntqip)?;
    a.cmp(r10d, HASH_NTSIT)?;
    a.je(l_store_ntsit)?;
    a.jmp(l_ntexp_next)?;
    a.set_label(&mut l_store_ntqip)?;
    a.lea(rax, ptr(r12 + rdi))?;
    a.movzx(ecx, word_ptr(rax + r14 * 2))?;
    a.lea(rdx, ptr(r12 + rbp))?;
    a.mov(eax, dword_ptr(rdx + rcx * 4))?;
    a.lea(rcx, ptr(r12 + rax))?;
    a.mov(qword_ptr(rsp + 0x1A8), rcx)?;
    a.jmp(l_ntexp_next)?;
    a.set_label(&mut l_store_ntsit)?;
    a.lea(rax, ptr(r12 + rdi))?;
    a.movzx(ecx, word_ptr(rax + r14 * 2))?;
    a.lea(rdx, ptr(r12 + rbp))?;
    a.mov(eax, dword_ptr(rdx + rcx * 4))?;
    a.lea(rcx, ptr(r12 + rax))?;
    a.mov(qword_ptr(rsp + 0x1B0), rcx)?;
    a.set_label(&mut l_ntexp_next)?;
    a.inc(r14d)?;
    a.jmp(l_ntexp_loop)?;

    a.set_label(&mut l_probes)?;
    a.mov(r14, qword_ptr(rsp + 0xE0))?;
    a.movzx(eax, byte_ptr(r14 + 6i32))?;
    a.cmp(eax, 3i32)?;
    a.jne(l_probe_skip)?;
    a.db(&[0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00])?;
    a.cmp(byte_ptr(rax + 2i32), 0)?;
    a.jne(l_fail)?;
    // B3 (DR0-DR3) is not done with `mov rax, drN`: that is privileged in
    // user mode and would AV a clean LoadLibrary. Hardware-breakpoint
    // checks stay on the host-side policy list.
    a.set_label(&mut l_dr_ok)?;
    a.cmp(qword_ptr(rsp + 0x1B0), 0)?;
    a.je(l_probe_skip)?;
    a.mov(rcx, -2i64)?;
    a.mov(edx, THREAD_HIDE_FROM_DEBUGGER)?;
    a.xor(r8d, r8d)?;
    a.xor(r9d, r9d)?;
    a.call(qword_ptr(rsp + 0x1B0))?;
    a.cmp(qword_ptr(rsp + 0x1A8), 0)?;
    a.je(l_probe_skip)?;
    a.xor(eax, eax)?;
    a.mov(qword_ptr(rsp + 0x1B8), rax)?;
    a.mov(rcx, -1i64)?;
    a.mov(edx, PROCESS_DEBUG_PORT)?;
    a.lea(r8, ptr(rsp + 0x1B8))?;
    a.mov(r9d, 8u32)?;
    a.mov(qword_ptr(rsp + 0x20), rax)?;
    a.call(qword_ptr(rsp + 0x1A8))?;
    a.cmp(qword_ptr(rsp + 0x1B8), 0)?;
    a.jne(l_fail)?;
    // ProcessDebugObjectHandle (0x1E): success means a debug object exists.
    a.xor(eax, eax)?;
    a.mov(qword_ptr(rsp + 0x1E0), rax)?;
    a.mov(rcx, -1i64)?;
    a.mov(edx, PROCESS_DEBUG_OBJECT_HANDLE)?;
    a.lea(r8, ptr(rsp + 0x1E0))?;
    a.mov(r9d, 8u32)?;
    a.mov(qword_ptr(rsp + 0x20), rax)?;
    a.call(qword_ptr(rsp + 0x1A8))?;
    a.test(eax, eax)?;
    a.jz(l_fail)?;
    // ProcessDebugFlags (0x1F): 0 means a debugger is attached.
    a.xor(eax, eax)?;
    a.mov(dword_ptr(rsp + 0x1E0), eax)?;
    a.mov(rcx, -1i64)?;
    a.mov(edx, PROCESS_DEBUG_FLAGS)?;
    a.lea(r8, ptr(rsp + 0x1E0))?;
    a.mov(r9d, 4u32)?;
    a.mov(qword_ptr(rsp + 0x20), rax)?;
    a.call(qword_ptr(rsp + 0x1A8))?;
    a.test(eax, eax)?;
    a.jnz(l_int3_chk)?;
    a.cmp(dword_ptr(rsp + 0x1E0), 0)?;
    a.je(l_fail)?;
    a.set_label(&mut l_int3_chk)?;
    a.mov(rax, qword_ptr(rsp + 0x1A8))?;
    a.cmp(byte_ptr(rax), 0xCCu32)?;
    a.je(l_fail)?;
    a.set_label(&mut l_probe_skip)?;
    a.mov(r14, qword_ptr(rsp + 0xE0))?;
    if !core.is_empty() {
        a.jmp(l_core_call)?;
    }

    // Phase 4: register VM walks (load_imm, mix_key)*8 halt then MBA bytes.
    a.lea(rsi, ptr(r14 + ENV_STOLEN))?;
    a.movzx(eax, word_ptr(r14 + ENV_STOLEN_LEN))?;
    a.add(rsi, rax)?;
    a.mov(ecx, dword_ptr(rsi))?;
    a.add(rsi, 4i32)?;
    // program.code is bytecode || 96 MBA bytes. MBA sits at program+(len-96).
    a.lea(rdi, ptr(rsi + rcx - 96i32))?;
    a.mov(qword_ptr(rsp + 0x1C0), rdi)?;
    a.mov(qword_ptr(rsp + 0x1C8), rsi)?;
    a.xor(r12d, r12d)?;
    a.set_label(&mut l_vm_loop)?;
    a.mov(rsi, qword_ptr(rsp + 0x1C8))?;
    a.movzx(eax, byte_ptr(rsi))?;
    a.inc(rsi)?;
    a.mov(qword_ptr(rsp + 0x1C8), rsi)?;
    a.movzx(edx, byte_ptr(r14 + ENV_OPCODES))?;
    a.cmp(eax, edx)?;
    a.je(l_vm_load)?;
    a.movzx(edx, byte_ptr(r14 + ENV_OPCODES + 7i32))?;
    a.cmp(eax, edx)?;
    a.je(l_vm_mix)?;
    a.movzx(edx, byte_ptr(r14 + ENV_OPCODES + 6i32))?;
    a.cmp(eax, edx)?;
    a.je(l_vm_halt)?;
    a.movzx(edx, byte_ptr(r14 + ENV_OPCODES + 1i32))?;
    a.cmp(eax, edx)?;
    a.je(l_vm_add)?;
    a.movzx(edx, byte_ptr(r14 + ENV_OPCODES + 2i32))?;
    a.cmp(eax, edx)?;
    a.je(l_vm_xor)?;
    a.movzx(edx, byte_ptr(r14 + ENV_OPCODES + 3i32))?;
    a.cmp(eax, edx)?;
    a.je(l_vm_mul)?;
    a.jmp(l_fail)?;
    a.set_label(&mut l_vm_load)?;
    a.movzx(r12d, byte_ptr(rsi))?;
    a.inc(rsi)?;
    a.mov(qword_ptr(rsp + 0x1C8), rsi)?;
    a.jmp(l_vm_loop)?;
    a.set_label(&mut l_vm_add)?;
    a.jmp(l_vm_loop)?;
    a.set_label(&mut l_vm_xor)?;
    a.jmp(l_vm_loop)?;
    a.set_label(&mut l_vm_mul)?;
    a.jmp(l_vm_loop)?;
    a.set_label(&mut l_vm_unk)?;
    a.jmp(l_fail)?;
    a.set_label(&mut l_vm_mix)?;
    a.mov(rsi, qword_ptr(rsp + 0x1C0))?;
    a.imul_3(eax, r12d, 12i32)?;
    a.add(rsi, rax)?;
    a.mov(r10d, dword_ptr(rsi))?;
    a.mov(r8d, dword_ptr(rsi + 4))?;
    a.mov(r9d, dword_ptr(rsi + 8))?;
    a.mov(r11d, r10d)?;
    a.mov(eax, r10d)?;
    a.imul_2(eax, r11d)?;
    a.neg(eax)?;
    a.add(eax, 2u32)?;
    a.imul_2(r11d, eax)?;
    a.mov(eax, r10d)?;
    a.imul_2(eax, r11d)?;
    a.neg(eax)?;
    a.add(eax, 2u32)?;
    a.imul_2(r11d, eax)?;
    a.mov(eax, r10d)?;
    a.imul_2(eax, r11d)?;
    a.neg(eax)?;
    a.add(eax, 2u32)?;
    a.imul_2(r11d, eax)?;
    a.mov(eax, r10d)?;
    a.imul_2(eax, r11d)?;
    a.neg(eax)?;
    a.add(eax, 2u32)?;
    a.imul_2(r11d, eax)?;
    a.mov(eax, r9d)?;
    a.sub(eax, r8d)?;
    a.imul_2(eax, r11d)?;
    a.mov(dword_ptr(rsp + r12 * 4 + 0x60), eax)?;
    a.jmp(l_vm_loop)?;
    a.set_label(&mut l_vm_halt)?;
    a.nop()?;
    a.set_label(&mut l_mba_done)?;
    // runtime key = secret ^ measurement ^ WRAP_DOMAIN
    a.lea(rsi, ptr(rsp + 0x60))?;
    a.lea(rdi, ptr(rsp + 0x80))?;
    a.lea(rdx, ptr(rbx + META_MEASUREMENT as i32))?;
    a.lea(r8, ptr(wrap_dom))?;
    a.lea(r13, ptr(mac_dom))?;
    a.xor(ecx, ecx)?;
    a.set_label(&mut l_mix)?;
    a.cmp(ecx, 32)?;
    a.jae(l_mix_done)?;
    a.mov(al, byte_ptr(rsi + rcx * 1))?;
    a.xor(al, byte_ptr(rdx + rcx * 1))?;
    a.mov(r9, rcx)?;
    a.and(r9, 15i32)?;
    a.xor(al, byte_ptr(r8 + r9 * 1))?;
    a.mov(byte_ptr(rdi + rcx * 1), al)?;
    a.inc(ecx)?;
    a.jmp(l_mix)?;
    a.set_label(&mut l_mix_done)?;

    // cursor → first page record
    a.lea(rbp, ptr(r14 + ENV_STOLEN))?;
    a.movzx(eax, word_ptr(r14 + ENV_STOLEN_LEN))?;
    a.add(rbp, rax)?; // skip stolen
    a.mov(eax, dword_ptr(rbp))?; // program len
    a.add(rbp, 4i32)?;
    a.add(rbp, rax)?; // skip program
    a.mov(eax, dword_ptr(r14 + ENV_PAGE_COUNT))?;
    a.mov(qword_ptr(rsp + 0xE8), rax)?;

    // ---- page loop: VirtualProtect → XOR decrypt → restore ----
    a.set_label(&mut l_pages)?;
    a.cmp(qword_ptr(rsp + 0xE8), 0)?;
    a.je(l_imports)?;
    a.dec(qword_ptr(rsp + 0xE8))?;
    a.mov(r8d, dword_ptr(rbp))?; // page index
    a.mov(dword_ptr(rsp + 0xC0), r8d)?; // idx LE scratch
    a.lea(r10, ptr(rbp + 12i32))?; // nonce
    // Expand the nonce to 16 bytes at rsp+0xE0 (nonce ++ nonce[0..4]) so the
    // keystream can index it with a single AND 15 for any i.
    a.lea(rdi, ptr(rsp + 0x120))?;
    a.xor(ecx, ecx)?;
    a.set_label(&mut l_cpnonce)?;
    a.cmp(ecx, 16i32)?;
    a.jae(l_cpnonce_done)?;
    a.mov(r9, rcx)?;
    a.cmp(r9, 12i32)?;
    a.jb(l_cpnonce_k)?;
    a.sub(r9, 12i32)?;
    a.set_label(&mut l_cpnonce_k)?;
    a.mov(al, byte_ptr(r10 + r9 * 1))?;
    a.mov(byte_ptr(rdi + rcx * 1), al)?;
    a.inc(ecx)?;
    a.jmp(l_cpnonce)?;
    a.set_label(&mut l_cpnonce_done)?;
    a.lea(r10, ptr(rsp + 0x120))?;
    a.xor(ecx, ecx)?;
    a.set_label(&mut l_pkey)?;
    a.cmp(ecx, 32)?;
    a.jae(l_pkey_done)?;
    a.mov(al, byte_ptr(rsp + rcx * 1 + 0x80))?;
    a.mov(r9, rcx)?;
    a.cmp(r9, 12i32)?;
    a.jb(l_pkey_n1)?;
    a.sub(r9, 12i32)?;
    a.cmp(r9, 12i32)?;
    a.jb(l_pkey_n1)?;
    a.sub(r9, 12i32)?;
    a.set_label(&mut l_pkey_n1)?;
    a.xor(al, byte_ptr(r10 + r9 * 1))?;
    a.mov(r9, rcx)?;
    a.and(r9, 3i32)?;
    a.xor(al, byte_ptr(rsp + r9 * 1 + 0xC0))?;
    a.mov(r9, rcx)?;
    a.and(r9, 7i32)?;
    a.xor(al, byte_ptr(r13 + r9 * 1))?;
    a.mov(byte_ptr(rsp + rcx * 1 + 0xA0), al)?;
    a.inc(ecx)?;
    a.jmp(l_pkey)?;
    a.set_label(&mut l_pkey_done)?;

    a.mov(edi, dword_ptr(rbp + 4i32))?; // rva
    a.mov(rsi, r15)?;
    a.add(rsi, rdi)?; // dest
    // Verify the keyed FNV-1a digest over the mapped bytes before decrypting
    // (G-TAMPER): a single flipped byte must fail closed. The span is the
    // original chunk length (plain_len), matching the packer's digest.
    a.mov(edi, dword_ptr(rbp + 8i32))?;
    a.mov(r8d, 0x811C_9DC5u32)?;
    a.xor(edx, edx)?;
    a.set_label(&mut l_dig)?;
    a.test(edi, edi)?;
    a.jz(l_dig_done)?;
    a.movzx(ecx, byte_ptr(rsi + rdx * 1))?;
    a.xor(r8d, ecx)?;
    a.imul_3(r8d, r8d, 0x0100_0193u32)?;
    a.inc(rdx)?;
    a.dec(edi)?;
    a.jmp(l_dig)?;
    a.set_label(&mut l_dig_done)?;
    a.xor(r8d, dword_ptr(rsp + 0xA0))?; // de-mix page key[0..4]
    a.mov(edx, dword_ptr(rbp + 24i32))?;
    a.cmp(r8d, dword_ptr(rbp + rdx * 1 + 60i32))?; // digest after mac
    a.jne(l_fail)?;
    // DEBUG MARKER: last verified page index lands in meta[56]; the test VEH
    // reports it on crashes. meta[63] is the gate byte and must stay intact.
    a.mov(eax, dword_ptr(rbp))?;
    a.mov(dword_ptr(rbx + 56i32), eax)?;

    a.mov(rcx, rsi)?;
    a.mov(edx, dword_ptr(rbp + 24i32))?; // ct_len
    a.mov(r8d, PAGE_EXECUTE_READWRITE)?;
    a.lea(r9, ptr(rsp + 0x58))?;
    a.call(qword_ptr(rsp + 0x48))?; // VirtualProtect RWX
    a.test(eax, eax)?;
    a.jz(l_fail)?;

    a.mov(edi, dword_ptr(rbp + 24i32))?; // len
    // r10 is volatile across the call above; reload the expanded nonce.
    a.lea(r10, ptr(rsp + 0x120))?;
    a.xor(edx, edx)?; // i
    a.set_label(&mut l_xor)?;
    a.test(edi, edi)?;
    a.jz(l_xor_done)?;
    a.mov(al, byte_ptr(rsi + rdx * 1))?;
    a.mov(r9, rdx)?;
    a.and(r9, 31i32)?;
    a.xor(al, byte_ptr(rsp + r9 * 1 + 0xA0))?;
    a.mov(r9, rdx)?;
    a.and(r9, 15i32)?;
    a.xor(al, byte_ptr(r10 + r9 * 1))?;
    a.imul_3(r9d, edx, 0x9du32)?;
    a.xor(al, r9b)?;
    a.mov(r9, rdx)?;
    a.shr(r9, 8u32)?;
    a.xor(al, r9b)?;
    a.mov(byte_ptr(rsi + rdx * 1), al)?;
    a.inc(rdx)?;
    a.dec(edi)?;
    a.jmp(l_xor)?;
    a.set_label(&mut l_xor_done)?;

    a.mov(rcx, rsi)?;
    a.mov(edx, dword_ptr(rbp + 24i32))?;
    a.mov(r8d, dword_ptr(rsp + 0x58))?;
    a.lea(r9, ptr(rsp + 0x58))?;
    a.call(qword_ptr(rsp + 0x48))?; // restore protection
    a.mov(eax, dword_ptr(rbp + 24i32))?;
    a.add(eax, 64i32)?; // 28 header + 32 mac + 4 digest
    a.add(rbp, rax)?;
    a.jmp(l_pages)?;

    // ---- imports: LoadLibraryA + GetProcAddress → original IAT slots ----
    a.set_label(&mut l_imports)?;
    a.cmp(byte_ptr(rbx + 63i32), 2i32)?;
    a.je(l_finish)?;
    a.mov(eax, dword_ptr(rbp))?; // import count
    a.mov(qword_ptr(rsp + 0x100), rax)?;
    a.add(rbp, 4i32)?;
    a.set_label(&mut l_imp_loop)?;
    a.cmp(qword_ptr(rsp + 0x100), 0)?;
    a.jne(l_imp_more)?;
    a.mov(qword_ptr(rbx + 48i32), rbp)?; // keep-list (meta+48, survives DllMain stack)
    a.jmp(l_finish)?;
    a.set_label(&mut l_imp_more)?;
    a.dec(qword_ptr(rsp + 0x100))?;
    a.movzx(ecx, word_ptr(rbp + 36i32))?; // name_len
    a.movzx(edx, word_ptr(rbp + 38i32))?; // dll_len
    a.lea(r10, ptr(rcx + rdx + 40i32))?; // record stride
    a.mov(qword_ptr(rsp + 0x108), r10)?;
    a.lea(rsi, ptr(rbp + 40i32))?; // name src
    a.lea(rdi, ptr(rsp + 0xC0))?;
    a.set_label(&mut l_cpname)?;
    a.test(ecx, ecx)?;
    a.jz(l_cpname_done)?;
    a.mov(al, byte_ptr(rsi))?;
    a.mov(byte_ptr(rdi), al)?;
    a.inc(rsi)?;
    a.inc(rdi)?;
    a.dec(ecx)?;
    a.jmp(l_cpname)?;
    a.set_label(&mut l_cpname_done)?;
    a.mov(byte_ptr(rdi), 0u32)?;
    // Copy the dll name into its OWN buffer: appending it after the function
    // name would overwrite the name's NUL terminator.
    a.lea(rdi, ptr(rsp + 0x150))?;
    a.set_label(&mut l_cpdll)?;
    a.test(edx, edx)?;
    a.jz(l_cpdll_done)?;
    a.mov(al, byte_ptr(rsi))?;
    a.mov(byte_ptr(rdi), al)?;
    a.inc(rsi)?;
    a.inc(rdi)?;
    a.dec(edx)?;
    a.jmp(l_cpdll)?;
    a.set_label(&mut l_cpdll_done)?;
    a.mov(byte_ptr(rdi), 0u32)?;

    a.lea(rcx, ptr(rsp + 0x150))?;
    a.call(qword_ptr(rsp + 0x40))?; // LoadLibraryA
    a.test(rax, rax)?;
    a.jz(l_fail)?;
    a.mov(qword_ptr(rsp + 0x110), rax)?;
    a.mov(rcx, qword_ptr(rsp + 0x110))?;
    a.lea(rdx, ptr(rsp + 0xC0))?;
    a.call(qword_ptr(rsp + 0x38))?; // GetProcAddress
    a.test(rax, rax)?;
    a.jz(l_fail)?;
    a.mov(qword_ptr(rsp + 0x110), rax)?;

    a.mov(edi, dword_ptr(rbp + 32i32))?; // iat rva
    a.mov(rcx, r15)?;
    a.add(rcx, rdi)?;
    a.mov(qword_ptr(rsp + 0x118), rcx)?;
    a.mov(edx, 8u32)?;
    a.mov(r8d, PAGE_EXECUTE_READWRITE)?;
    a.lea(r9, ptr(rsp + 0x58))?;
    a.call(qword_ptr(rsp + 0x48))?;
    a.test(eax, eax)?;
    a.jz(l_fail)?;
    a.mov(rax, qword_ptr(rsp + 0x110))?;
    a.mov(rcx, qword_ptr(rsp + 0x118))?;
    a.mov(qword_ptr(rcx), rax)?;
    a.mov(rcx, qword_ptr(rsp + 0x118))?;
    a.mov(edx, 8u32)?;
    a.mov(r8d, dword_ptr(rsp + 0x58))?;
    a.lea(r9, ptr(rsp + 0x58))?;
    a.call(qword_ptr(rsp + 0x48))?; // restore
    a.mov(r10, qword_ptr(rsp + 0x108))?;
    a.add(rbp, r10)?;
    a.jmp(l_imp_loop)?;

    // ---- finish: stolen bytes, unpacked flag, transfer ----
    a.set_label(&mut l_finish)?;
    a.movzx(eax, word_ptr(r14 + ENV_STOLEN_LEN))?;
    a.lea(rsi, ptr(r14 + ENV_STOLEN))?;
    a.mov(edx, dword_ptr(rbx + META_ORIGINAL_ENTRY as i32))?;
    a.mov(rdi, r15)?;
    a.add(rdi, rdx)?;
    // The entry page is not writable here; VirtualProtect around the copy.
    a.mov(rcx, rdi)?;
    a.mov(edx, eax)?;
    a.mov(r8d, PAGE_EXECUTE_READWRITE)?;
    a.lea(r9, ptr(rsp + 0x58))?;
    a.call(qword_ptr(rsp + 0x48))?;
    a.test(eax, eax)?;
    a.jz(l_fail)?;
    a.movzx(eax, word_ptr(r14 + ENV_STOLEN_LEN))?;
    a.xor(ecx, ecx)?;
    a.set_label(&mut l_cpstolen)?;
    a.cmp(ecx, eax)?;
    a.jae(l_cpstolen_done)?;
    a.mov(dl, byte_ptr(rsi + rcx * 1))?;
    a.mov(byte_ptr(rdi + rcx * 1), dl)?;
    a.inc(ecx)?;
    a.jmp(l_cpstolen)?;
    a.set_label(&mut l_cpstolen_done)?;
    a.mov(rcx, rdi)?;
    a.movzx(edx, word_ptr(r14 + ENV_STOLEN_LEN))?;
    a.mov(r8d, dword_ptr(rsp + 0x58))?;
    a.lea(r9, ptr(rsp + 0x58))?;
    a.call(qword_ptr(rsp + 0x48))?; // restore protection
    a.set_label(&mut l_unpack_flag)?;
    a.cmp(qword_ptr(rsp + 0x48), 0)?;
    a.je(l_forward)?; // gate 0: no VirtualProtect yet; do not write RX meta
    a.mov(dword_ptr(rbx + META_UNPACKED as i32), 1u32)?;

    // C3-lite: on standard/max, wreck the in-memory section table and lie
    // about SizeOfImage so a memory dump is not a loadable PE. MZ/PE and the
    // export directory stay intact so GetProcAddress keeps working.
    a.cmp(byte_ptr(rbx + 63i32), 3i32)?;
    a.jb(l_scr_done)?; // gates 0-2 stay pristine
    a.movzx(ecx, byte_ptr(r14 + 6i32))?; // envelope profile
    a.cmp(ecx, 1i32)?;
    a.je(l_scr_done)?; // fast profile keeps headers
    a.mov(eax, dword_ptr(r15 + 0x3C))?; // lfanew
    a.movzx(ecx, word_ptr(r15 + rax + 6i32))?; // NumberOfSections
    a.movzx(edx, word_ptr(r15 + rax + 20i32))?; // SizeOfOptionalHeader
    a.lea(r10, ptr(rax + 24i32))?;
    a.add(r10, rdx)?; // section table RVA (r10 = lfanew+24+sizeofopt)
    a.imul_3(ecx, ecx, 40i32)?; // table byte length
    // VirtualProtect the header page. eax/ecx/edx/r10 are all volatile and
    // recomputed after the call.
    a.mov(rcx, r15)?;
    a.mov(edx, 0x1000u32)?;
    a.mov(r8d, PAGE_EXECUTE_READWRITE)?;
    a.lea(r9, ptr(rsp + 0x58))?;
    a.call(qword_ptr(rsp + 0x48))?;
    a.test(eax, eax)?;
    a.jz(l_fail)?;
    a.mov(eax, dword_ptr(r15 + 0x3C))?;
    a.movzx(ecx, word_ptr(r15 + rax + 6i32))?;
    a.imul_3(ecx, ecx, 40i32)?;
    a.movzx(edx, word_ptr(r15 + rax + 20i32))?;
    a.lea(r10, ptr(rax + 24i32))?;
    a.add(r10, rdx)?;
    // Fill the section table with a keystream-shaped junk pattern.
    a.mov(r11d, 0x811C_9DC5u32)?;
    a.xor(edx, edx)?;
    a.set_label(&mut l_scr_loop)?;
    a.cmp(edx, ecx)?;
    a.jae(l_scr_fill)?;
    a.imul_3(r11d, r11d, 0x0100_0193u32)?;
    a.lea(rax, ptr(r15 + r10))?;
    a.mov(byte_ptr(rax + rdx * 1), r11b)?;
    a.inc(edx)?;
    a.jmp(l_scr_loop)?;
    // Overwrite the table length sentinel with a fresh value for the next
    // section table byte; then corrupt SizeOfImage.
    a.set_label(&mut l_scr_fill)?;
    a.mov(eax, dword_ptr(r15 + 0x3C))?;
    a.mov(dword_ptr(r15 + rax + 80i32), 0x1000u32)?; // SizeOfImage lie
    // Restore header page protection.
    a.mov(rcx, r15)?;
    a.mov(edx, 0x1000u32)?;
    a.mov(r8d, dword_ptr(rsp + 0x58))?;
    a.lea(r9, ptr(rsp + 0x58))?;
    a.call(qword_ptr(rsp + 0x48))?;
    a.set_label(&mut l_scr_done)?;
    a.nop()?;

    a.set_label(&mut l_forward)?;
    a.cmp(dword_ptr(rsp + 0x1F8), 1u32)?;
    a.je(l_tls_done)?;
    a.mov(eax, dword_ptr(r15 + 0x3C))?;
    a.movzx(eax, word_ptr(r15 + rax + 22))?;
    a.test(eax, 0x2000u32)?;
    a.jz(l_exe)?;
    // Lower gates return TRUE without transferring to the original entry.
    a.cmp(byte_ptr(rbx + 63i32), 3i32)?;
    a.jne(l_gate_true)?;
    // DLL: call the original DllMain with the loader's arguments.
    a.mov(rcx, r15)?;
    a.mov(r10d, dword_ptr(rbx + META_ORIGINAL_ENTRY as i32))?;
    a.mov(edx, dword_ptr(rsp + 0x28))?;
    a.mov(r8, qword_ptr(rsp + 0x30))?;
    a.mov(rax, r15)?;
    a.add(rax, r10)?;
    a.call(rax)?;
    a.mov(qword_ptr(rsp + 0x1D0), rax)?; // DllMain result
    // Executable-page C2 is not armed: rustc cdylib .text is live end-to-end
    // (hello_add at 0x1000, DllMain at 0x11fd4, CRT in between and after).
    // Re-encrypting any executable page failed G-BEH. Keep-list remains in
    // the envelope for a future demand-paging design.
    a.set_label(&mut l_epilogue)?;
    a.add(rsp, 0x2FF8i32)?;
    a.pop(r15)?;
    a.pop(r14)?;
    a.pop(r13)?;
    a.pop(r12)?;
    a.pop(rdi)?;
    a.pop(rsi)?;
    a.pop(rbp)?;
    a.pop(rbx)?;
    a.ret()?;

    a.set_label(&mut l_gate_true)?;
    a.mov(eax, 1i32)?;
    a.jmp(l_epilogue)?;

    a.set_label(&mut l_tls_done)?;
    // TLS: unpack already done. Forward to the original first callback only
    // on gate 3 — lower gates leave original .text as 0xCC traps. eax MUST
    // be set: returning loader garbage makes the callback fail the DLL load
    // (ERROR_DLL_INIT_FAILED).
    a.cmp(byte_ptr(rbx + 63i32), 3i32)?;
    a.jne(l_gate_true)?;
    a.mov(r10d, dword_ptr(rbx + META_TLS_CALLBACK as i32))?;
    a.test(r10d, r10d)?;
    a.jz(l_gate_true)?;
    a.add(r10, r15)?;
    a.mov(rcx, r15)?;
    a.mov(edx, dword_ptr(rsp + 0x28))?;
    a.mov(r8, qword_ptr(rsp + 0x30))?;
    a.add(rsp, 0x2FF8i32)?;
    a.pop(r15)?;
    a.pop(r14)?;
    a.pop(r13)?;
    a.pop(r12)?;
    a.pop(rdi)?;
    a.pop(rsi)?;
    a.pop(rbp)?;
    a.pop(rbx)?;
    a.jmp(r10)?;

    a.set_label(&mut l_exe)?;
    a.mov(edx, dword_ptr(rbx + META_ORIGINAL_ENTRY as i32))?;
    a.mov(r10, r15)?;
    a.add(r10, rdx)?;
    a.add(rsp, 0x2FF8i32)?;
    a.pop(r15)?;
    a.pop(r14)?;
    a.pop(r13)?;
    a.pop(r12)?;
    a.pop(rdi)?;
    a.pop(rsi)?;
    a.pop(rbp)?;
    a.pop(rbx)?;
    a.mov(rax, r10)?;
    a.jmp(rax)?;

    a.set_label(&mut l_core_call)?;
    if !core.is_empty() {
        // XlHostCtx at rsp+0x200 (112 bytes). Win64: rcx = &ctx.
        a.lea(rax, ptr(rsp + 0x200i32))?;
        a.mov(qword_ptr(rax), r15)?; // image_base
        a.mov(qword_ptr(rax + 8i32), r14)?; // envelope
        a.mov(edx, dword_ptr(rbx + META_ENVELOPE_LEN as i32))?;
        a.mov(dword_ptr(rax + 16i32), edx)?;
        a.mov(edx, dword_ptr(rbx + META_ORIGINAL_ENTRY as i32))?;
        a.mov(dword_ptr(rax + 20i32), edx)?;
        a.movzx(edx, byte_ptr(rbx + 63i32))?;
        a.mov(byte_ptr(rax + 24i32), dl)?;
        a.xor(ecx, ecx)?;
        let mut l_cpmeas = a.create_label();
        let mut l_cpmeas_done = a.create_label();
        a.set_label(&mut l_cpmeas)?;
        a.cmp(ecx, 32u32)?;
        a.jae(l_cpmeas_done)?;
        a.mov(dl, byte_ptr(rbx + rcx + META_MEASUREMENT as i32))?;
        a.mov(byte_ptr(rax + rcx + 32i32), dl)?;
        a.inc(ecx)?;
        a.jmp(l_cpmeas)?;
        a.set_label(&mut l_cpmeas_done)?;
        if iat_writeback {
            a.mov(rdx, qword_ptr(rsp + 0x40))?; // LoadLibraryA
        } else {
            a.xor(edx, edx)?;
        }
        a.mov(qword_ptr(rax + 64i32), rdx)?;
        a.mov(rdx, qword_ptr(rsp + 0x38))?; // GetProcAddress
        a.mov(qword_ptr(rax + 72i32), rdx)?;
        a.mov(rdx, qword_ptr(rsp + 0x48))?; // VirtualProtect
        a.mov(qword_ptr(rax + 80i32), rdx)?;
        a.mov(rdx, qword_ptr(rsp + 0xF0))?; // G5 VEH handle
        a.mov(qword_ptr(rax + 88i32), rdx)?;
        a.mov(rdx, qword_ptr(rsp + 0xF8))?; // G5 VEH remover
        a.mov(qword_ptr(rax + 96i32), rdx)?;
        a.lea(rcx, ptr(rsp + 0x200i32))?;
        a.sub(rsp, 0x20i32)?;
        a.lea(rax, ptr(l_core_bytes))?;
        a.add(rax, core_entry as i32)?;
        a.call(rax)?;
        a.add(rsp, 0x20i32)?;
        a.test(eax, eax)?;
        a.jz(l_fail)?;
        a.lea(rcx, ptr(rbx))?;
        a.mov(edx, STUB_META_LEN as u32)?;
        a.mov(r8d, PAGE_EXECUTE_READWRITE)?;
        a.lea(r9, ptr(rsp + 0x58))?;
        a.call(qword_ptr(rsp + 0x48))?;
        a.mov(dword_ptr(rbx + META_UNPACKED as i32), 1u32)?;
        a.lea(rcx, ptr(rbx))?;
        a.mov(edx, STUB_META_LEN as u32)?;
        // G5: meta shares its page with the g_xl state block, which the
        // fault handler and quiesce keep writing after boot. Restoring the
        // page to EXECUTE_READ here strips write from the whole page and the
        // next g_xl write faults inside the VEH itself (silent 0xC0000005).
        if g5_emit_state {
            a.mov(r8d, 0x04u32)?; // PAGE_READWRITE
        } else {
            a.mov(r8d, 0x20u32)?; // PAGE_EXECUTE_READ
        }
        a.lea(r9, ptr(rsp + 0x58))?;
        a.call(qword_ptr(rsp + 0x48))?;
        a.jmp(l_forward)?;
    } else {
        a.jmp(l_fail)?;
    }

    // G5/TASK-027: DLL_THREAD_ATTACH just forwards to the original DllMain.
    // DLL_PROCESS_DETACH / DLL_THREAD_DETACH run the ORIGINAL entry first
    // (its CRT may still fault into lazy pages; the keys must stay live
    // until user code is done), then quiesce: process detach re-seals,
    // deregisters the VEH, and zeroizes the runtime key before the loader
    // unmaps the image; thread detach only re-seals provably quiescent
    // regions (their next fault wakes them).
    a.set_label(&mut l_detach_quiesce)?;
    if g5_emit_code {
        a.cmp(dword_ptr(rsp + 0x28), 2)?;
        a.je(l_forward)?; // DLL_THREAD_ATTACH: original DllMain only
        a.mov(rcx, r15)?;
        a.mov(r10d, dword_ptr(rbx + META_ORIGINAL_ENTRY as i32))?;
        a.mov(edx, dword_ptr(rsp + 0x28))?;
        a.mov(r8, qword_ptr(rsp + 0x30))?;
        a.mov(rax, r15)?;
        a.add(rax, r10)?;
        a.call(rax)?;
        a.mov(qword_ptr(rsp + 0x1D0), rax)?; // original DllMain result
        a.mov(r11d, 1u32)?; // zero_keys
        a.cmp(dword_ptr(rsp + 0x28), 3)?;
        a.jne(l_quiesce_go)?;
        a.xor(r11d, r11d)?; // DLL_THREAD_DETACH: re-seal only
        a.set_label(&mut l_quiesce_go)?;
        a.sub(rsp, 0x20i32)?;
        a.mov(ecx, r11d)?; // zero_keys
        a.lea(rax, ptr(l_core_bytes))?;
        a.add(rax, g5.quiesce_off as i32)?;
        a.call(rax)?;
        a.add(rsp, 0x20i32)?;
        a.mov(eax, dword_ptr(rsp + 0x1D0))?; // return the original result
        a.jmp(l_epilogue)?;
    }
    a.jmp(l_forward)?;

    a.set_label(&mut l_fail)?;
    // Fail closed: DllMain FALSE / EXE exit code 0.
    a.xor(eax, eax)?;
    a.jmp(l_epilogue)?;

    // C2: after DllMain, XOR-reencrypt every executable page that does not
    // contain the original entry, so a later dump is ciphertext again. The
    // entry page stays live so GetProcAddress of user exports still works.
    a.set_label(&mut l_reenc)?;
    a.lea(rbp, ptr(r14 + ENV_STOLEN))?;
    a.movzx(eax, word_ptr(r14 + ENV_STOLEN_LEN))?;
    a.add(rbp, rax)?;
    a.mov(eax, dword_ptr(rbp))?;
    a.add(rbp, 4i32)?;
    a.add(rbp, rax)?;
    a.mov(eax, dword_ptr(r14 + ENV_PAGE_COUNT))?;
    a.mov(qword_ptr(rsp + 0xE8), rax)?;
    a.set_label(&mut l_reenc_loop)?;
    a.cmp(qword_ptr(rsp + 0xE8), 0)?;
    a.je(l_reenc_done)?;
    a.dec(qword_ptr(rsp + 0xE8))?;
    a.mov(edi, dword_ptr(rbp + 4i32))?; // rva
    a.and(edi, 0xFFFF_F000u32)?;
    // Always keep the original-entry page, even if the keep-list pointer is
    // stale: hello_add may tail-call CRT helpers that live next to DllMain.
    a.mov(eax, dword_ptr(rbx + META_ORIGINAL_ENTRY as i32))?;
    a.and(eax, 0xFFFF_F000u32)?;
    a.cmp(edi, eax)?;
    a.je(l_reenc_skip)?;
    // Only the short tail chunk is a candidate: full 4K pages in a rustc
    // cdylib are live (exports, CRT, DllMain). A full-page C2 AV'd hello_add.
    a.cmp(dword_ptr(rbp + 8i32), 0x1000u32)?;
    a.je(l_reenc_skip)?;
    a.mov(rsi, qword_ptr(rbx + 48i32))?;
    a.test(rsi, rsi)?;
    a.jz(l_reenc_done)?; // no keep-list: do not touch remaining pages
    a.mov(ecx, dword_ptr(rsi))?;
    a.add(rsi, 4i32)?;
    a.set_label(&mut l_keep_scan)?;
    a.test(ecx, ecx)?;
    a.jz(l_reenc_do)?;
    a.cmp(edi, dword_ptr(rsi))?;
    a.je(l_reenc_skip)?;
    a.add(rsi, 4i32)?;
    a.dec(ecx)?;
    a.jmp(l_keep_scan)?;
    a.set_label(&mut l_keep_hit)?;
    a.jmp(l_reenc_skip)?;
    a.set_label(&mut l_keep_next)?;
    a.nop()?;
    a.set_label(&mut l_reenc_do)?;
    // Rebuild page key (same as decrypt) then XOR in place.
    a.mov(r8d, dword_ptr(rbp))?;
    a.mov(dword_ptr(rsp + 0xC0), r8d)?;
    a.lea(r10, ptr(rbp + 12i32))?;
    a.lea(rdi, ptr(rsp + 0x120))?;
    a.xor(ecx, ecx)?;
    a.set_label(&mut l_reenc_nexp)?;
    a.cmp(ecx, 16i32)?;
    a.jae(l_reenc_nexp_done)?;
    a.mov(r9, rcx)?;
    a.cmp(r9, 12i32)?;
    a.jb(l_reenc_nexp_k)?;
    a.sub(r9, 12i32)?;
    a.set_label(&mut l_reenc_nexp_k)?;
    a.mov(al, byte_ptr(r10 + r9 * 1))?;
    a.mov(byte_ptr(rdi + rcx * 1), al)?;
    a.inc(ecx)?;
    a.jmp(l_reenc_nexp)?;
    a.set_label(&mut l_reenc_nexp_done)?;
    a.lea(r10, ptr(rsp + 0x120))?;
    a.xor(ecx, ecx)?;
    a.set_label(&mut l_reenc_pkey)?;
    a.cmp(ecx, 32)?;
    a.jae(l_reenc_pkey_done)?;
    a.mov(al, byte_ptr(rsp + rcx * 1 + 0x80))?;
    a.mov(r9, rcx)?;
    a.cmp(r9, 12i32)?;
    a.jb(l_reenc_pkey_n1)?;
    a.sub(r9, 12i32)?;
    a.cmp(r9, 12i32)?;
    a.jb(l_reenc_pkey_n1)?;
    a.sub(r9, 12i32)?;
    a.set_label(&mut l_reenc_pkey_n1)?;
    a.xor(al, byte_ptr(r10 + r9 * 1))?;
    a.mov(r9, rcx)?;
    a.and(r9, 3i32)?;
    a.xor(al, byte_ptr(rsp + r9 * 1 + 0xC0))?;
    a.mov(r9, rcx)?;
    a.and(r9, 7i32)?;
    a.xor(al, byte_ptr(r13 + r9 * 1))?;
    a.mov(byte_ptr(rsp + rcx * 1 + 0xA0), al)?;
    a.inc(ecx)?;
    a.jmp(l_reenc_pkey)?;
    a.set_label(&mut l_reenc_pkey_done)?;
    a.mov(edi, dword_ptr(rbp + 4i32))?;
    a.mov(rsi, r15)?;
    a.add(rsi, rdi)?;
    a.mov(rcx, rsi)?;
    a.mov(edx, dword_ptr(rbp + 8i32))?;
    a.mov(r8d, PAGE_EXECUTE_READWRITE)?;
    a.lea(r9, ptr(rsp + 0x58))?;
    a.call(qword_ptr(rsp + 0x48))?;
    a.lea(r10, ptr(rsp + 0x120))?;
    a.mov(edi, dword_ptr(rbp + 8i32))?;
    a.xor(edx, edx)?;
    a.set_label(&mut l_reenc_xor)?;
    a.test(edi, edi)?;
    a.jz(l_reenc_xor_done)?;
    a.mov(al, byte_ptr(rsi + rdx * 1))?;
    a.mov(r9, rdx)?;
    a.and(r9, 31i32)?;
    a.xor(al, byte_ptr(rsp + r9 * 1 + 0xA0))?;
    a.mov(r9, rdx)?;
    a.and(r9, 15i32)?;
    a.xor(al, byte_ptr(r10 + r9 * 1))?;
    a.imul_3(r9d, edx, 0x9du32)?;
    a.xor(al, r9b)?;
    a.mov(r9, rdx)?;
    a.shr(r9, 8u32)?;
    a.xor(al, r9b)?;
    a.mov(byte_ptr(rsi + rdx * 1), al)?;
    a.inc(rdx)?;
    a.dec(edi)?;
    a.jmp(l_reenc_xor)?;
    a.set_label(&mut l_reenc_xor_done)?;
    a.mov(rcx, rsi)?;
    a.mov(edx, dword_ptr(rbp + 8i32))?;
    a.mov(r8d, dword_ptr(rsp + 0x58))?;
    a.lea(r9, ptr(rsp + 0x58))?;
    a.call(qword_ptr(rsp + 0x48))?;
    a.set_label(&mut l_reenc_skip)?;
    a.mov(eax, dword_ptr(rbp + 24i32))?;
    a.add(eax, 64i32)?;
    a.add(rbp, rax)?;
    a.jmp(l_reenc_loop)?;
    a.set_label(&mut l_reenc_done)?;
    // Max: poison MZ after GetProcAddress of user exports has already run.
    a.movzx(eax, byte_ptr(r14 + 6i32))?;
    a.cmp(eax, 3i32)?;
    a.jne(l_reenc_ret)?;
    a.mov(rcx, r15)?;
    a.mov(edx, 0x1000u32)?;
    a.mov(r8d, PAGE_EXECUTE_READWRITE)?;
    a.lea(r9, ptr(rsp + 0x58))?;
    a.call(qword_ptr(rsp + 0x48))?;
    a.mov(word_ptr(r15), 0u32)?;
    a.mov(rcx, r15)?;
    a.mov(edx, 0x1000u32)?;
    a.mov(r8d, dword_ptr(rsp + 0x58))?;
    a.lea(r9, ptr(rsp + 0x58))?;
    a.call(qword_ptr(rsp + 0x48))?;
    a.set_label(&mut l_reenc_ret)?;
    a.mov(rax, qword_ptr(rsp + 0x1D0))?;
    a.jmp(l_epilogue)?;

    let mut thunk_labels: Vec<CodeLabel> = Vec::new();
    if !guest.functions.is_empty() {
        for _ in &guest.functions {
            thunk_labels.push(a.create_label());
        }
        for i in 0..guest.functions.len() {
            a.set_label(&mut thunk_labels[i])?;
            emit_db(&mut a, &guest.functions[i])?;
        }
    }

    // G5 thunks: fault (rcx = PEXCEPTION_POINTERS) and quiesce
    // (extern "system" fn() -> i32 via zero_keys=1). The VEH is called by
    // ntdll; rcx must be preserved until the C callee sees it, so we
    // cannot clobber it and we cannot use a raw `jmp rax` that would
    // leave rax live as a non-volatile-looking scratch.
    if g5_emit_code {
        a.set_label(&mut l_fault_thunk)?;
        a.lea(rax, ptr(l_core_bytes))?;
        a.add(rax, g5.fault_off as i32)?;
        a.jmp(rax)?;
    }
    if g5_emit_code {
        a.set_label(&mut l_quiesce_thunk)?;
        a.mov(ecx, 1u32)?;
        a.lea(rax, ptr(l_core_bytes))?;
        a.add(rax, g5.quiesce_off as i32)?;
        a.jmp(rax)?;
    }

    // Data (never executed: only lea targets).
    if g5_emit_code {
        a.set_label(&mut l_veh_name)?;
        a.db(b"AddVectoredExceptionHandler\0")?;
        a.set_label(&mut l_veh_remove_name)?;
        a.db(b"RemoveVectoredExceptionHandler\0")?;
    }
    a.set_label(&mut wrap_dom)?;
    a.db(&WRAP_DOMAIN)?;
    a.set_label(&mut mac_dom)?;
    a.db(&PAGE_MAC_DOMAIN)?;
    a.set_label(&mut l_core_bytes)?;
    if !core.is_empty() {
        emit_db(&mut a, core)?;
    } else {
        a.nop()?;
    }
    // G5 state block: emit it INLINE between the core text and the meta so
    // iced computes every RIP-relative displacement (notably `lea rbx,[meta]`)
    // against the final layout. Splicing bytes in after assembly would leave
    // that lea pointing at the pad, and gate 0 fails with 1114 because the
    // XLV2 check reads payload_rva from zeroed pad bytes. The layout is
    // [core text][pad to page-round(text end)][guard page][state][meta];
    // runtime_image patches .xlg relocations with this same pad formula.
    let state_pad = if g5_emit_state {
        let pad = (0x1000 - (core.len() % 0x1000)) % 0x1000 + 0x1000;
        emit_db(&mut a, &vec![0u8; pad])?;
        emit_db(&mut a, &g5.state)?;
        pad
    } else {
        0
    };
    a.set_label(&mut meta)?;
    // Non-zero placeholder: iced may drop trailing all-zero db blocks, and
    // lib.rs overwrites these bytes with the real meta anyway.
    a.db(&[0x88u8; STUB_META_LEN])?;

    let assembled = a.assemble_options(0, BlockEncoderOptions::RETURN_NEW_INSTRUCTION_OFFSETS)?;
    let mut guest_thunk_offs = Vec::with_capacity(thunk_labels.len());
    for lab in &thunk_labels {
        guest_thunk_offs.push(assembled.label_ip(lab)? as u32);
    }
    let entry_off = assembled.label_ip(&l_main_entry)? as u32;
    let tls_entry_off = assembled.label_ip(&l_tls_entry)? as u32;
    let fault_thunk_off = if g5_emit_code {
        assembled.label_ip(&l_fault_thunk)? as u32
    } else {
        0
    };
    let quiesce_thunk_off = if g5_emit_code {
        assembled.label_ip(&l_quiesce_thunk)? as u32
    } else {
        0
    };
    let core_end = assembled.label_ip(&l_core_bytes)? as usize + core.len();
    let meta_off = assembled.label_ip(&meta)? as usize;
    let bytes = assembled.inner.code_buffer;
    // The pad+state were emitted inline (see above), so all rel32s already
    // match the final layout; only the offsets need to be read off.
    let state_off = if g5_emit_state {
        (core_end + state_pad) as u32
    } else {
        0
    };
    assert_eq!(
        bytes[meta_off..meta_off + 8].to_vec(),
        vec![0x88u8; 8],
        "assembler dropped or shifted the trailing meta placeholder"
    );
    Ok(PicStub {
        bytes,
        meta_off,
        entry_off,
        tls_entry_off,
        guest_thunk_offs,
        fault_thunk_off,
        quiesce_thunk_off,
        state_off,
    })
}

fn emit_db(a: &mut CodeAssembler, data: &[u8]) -> Result<(), iced_x86::IcedError> {
    for chunk in data.chunks(16) {
        a.db(chunk)?;
    }
    Ok(())
}

/// Pack-time offset of the stub's own load-relative VA inside meta. The ELF
/// stub recovers the image base from it (`base = meta_runtime_va - self_rva`).
pub const META_SELF_RVA: usize = 68;

/// Offsets inside the Win64-layout `XlHostCtx` built by both stubs.
const CTX_IMAGE_BASE: i32 = 0;
const CTX_ENVELOPE: i32 = 8;
const CTX_ENVELOPE_LEN: i32 = 16;
const CTX_ORIG_ENTRY: i32 = 20;
const CTX_GATE: i32 = 24;
const CTX_MEASUREMENT: i32 = 32;
const CTX_LOAD_LIBRARY: i32 = 64;
const CTX_GET_PROC: i32 = 72;
const CTX_VPROTECT: i32 = 80;

pub struct ElfStub {
    pub bytes: Vec<u8>,
    pub meta_off: usize,
    /// DT_INIT replacement (also the first byte of the stub section).
    pub entry_off: u32,
}

/// ELF64 AMD64 DT_INIT bootstrap.
///
/// ld.so calls DT_INIT with the SysV ABI and no useful arguments. The stub
/// recovers the load base from `meta.self_rva`, builds a Win64-layout
/// `XlHostCtx` (the freestanding core is host-compiled with Win64 semantics),
/// points `vprotect` at a raw `mprotect` syscall wrapper (no GOT/PLT use, so
/// it works under the loader with RELRO intact), calls `xl_core_activate`,
/// then tail-calls the original DT_INIT. GOT/PLT are already resolved by
/// ld.so before DT_INIT, so `load_library`/`get_proc` stay null and xl_core
/// skips IAT writeback.
pub fn emit_elf_stub(core: &[u8], core_entry: u32, sysv: bool) -> Result<ElfStub, String> {
    if core.is_empty() {
        return Err("empty xl_core object".into());
    }
    emit_elf_inner(core, core_entry, sysv).map_err(|e| format!("elf stub: {e}"))
}

fn emit_elf_inner(
    core: &[u8],
    core_entry: u32,
    sysv: bool,
) -> Result<ElfStub, iced_x86::IcedError> {
    let mut a = CodeAssembler::new(64)?;

    let mut l_entry = a.create_label();
    let mut l_vp = a.create_label();
    let mut l_vp_sysv = a.create_label();
    let mut l_vp_go = a.create_label();
    let mut l_vp_rw = a.create_label();
    let mut l_vp_rx = a.create_label();
    let mut l_vp_rwx = a.create_label();
    let mut l_vp_old = a.create_label();
    let mut l_core_bytes = a.create_label();
    let mut l_meta = a.create_label();
    let mut l_fail = a.create_label();
    let mut l_forward = a.create_label();
    let mut l_ret = a.create_label();

    // SysV entry: rsp%16 == 8 here. Two pushes + sub 8 leave rsp%16 == 0 for
    // every call below, and restore the caller's callee-saved regs on exit.
    a.set_label(&mut l_entry)?;
    a.push(rbx)?;
    a.push(r15)?;
    a.sub(rsp, 8i32)?;

    // base = meta_runtime_va - self_rva
    a.lea(rbx, ptr(l_meta))?;
    a.mov(r15, rbx)?;
    a.mov(eax, dword_ptr(rbx + META_SELF_RVA as i32))?;
    a.sub(r15, rax)?;

    a.cmp(dword_ptr(rbx + META_UNPACKED as i32), 1)?;
    a.je(l_forward)?;

    // Build XlHostCtx at rsp+0x20 (below it: 0x20 shadow for Win64 callees).
    a.sub(rsp, 0x80i32)?;
    a.mov(qword_ptr(rsp + 0x20 + CTX_IMAGE_BASE), r15)?;
    a.mov(eax, dword_ptr(rbx + META_PAYLOAD_RVA as i32))?;
    a.lea(rax, ptr(r15 + rax))?;
    a.mov(qword_ptr(rsp + 0x20 + CTX_ENVELOPE), rax)?;
    a.mov(eax, dword_ptr(rbx + META_ENVELOPE_LEN as i32))?;
    a.mov(dword_ptr(rsp + 0x20 + CTX_ENVELOPE_LEN), eax)?;
    a.mov(eax, dword_ptr(rbx + META_ORIGINAL_ENTRY as i32))?;
    a.mov(dword_ptr(rsp + 0x20 + CTX_ORIG_ENTRY), eax)?;
    a.movzx(eax, byte_ptr(rbx + 63i32))?;
    a.mov(byte_ptr(rsp + 0x20 + CTX_GATE), al)?;
    // measurement: 32 bytes from meta.
    a.cld()?;
    a.lea(rsi, ptr(rbx + META_MEASUREMENT as i32))?;
    a.lea(rdi, ptr(rsp + 0x20 + CTX_MEASUREMENT))?;
    a.mov(ecx, 8i32)?; // 32-byte measurement = 8 dwords
    // rep movsd (F3 A5): iced has no direct mnemonic here.
    a.db(&[0xF3, 0xA5])?;
    a.xor(eax, eax)?;
    a.mov(qword_ptr(rsp + 0x20 + CTX_LOAD_LIBRARY), rax)?;
    a.mov(qword_ptr(rsp + 0x20 + CTX_GET_PROC), rax)?;
    if sysv {
        a.lea(rax, ptr(l_vp_sysv))?;
    } else {
        a.lea(rax, ptr(l_vp))?;
    }
    a.mov(qword_ptr(rsp + 0x20 + CTX_VPROTECT), rax)?;

    // xl_core_activate(ctx) — the argument register follows the HOST
    // compiler of the core object: Win64 RCX (MSVC COFF) or SysV RDI
    // (gcc ELF).
    if sysv {
        a.lea(rdi, ptr(rsp + 0x20i32))?;
    } else {
        a.lea(rcx, ptr(rsp + 0x20i32))?;
    }
    a.lea(rax, ptr(l_core_bytes))?;
    a.add(rax, core_entry as i32)?;
    a.call(rax)?;
    a.add(rsp, 0x80i32)?;
    a.test(eax, eax)?;
    a.jz(l_fail)?;

    // Mark unpacked. The stub page is R+X; flip the flag via the same
    // mprotect wrapper (RW → write → RX), then forward.
    a.mov(rcx, rbx)?;
    a.mov(edx, 4u32)?;
    a.mov(r8d, 0x04u32)?; // XL_PAGE_RW
    a.xor(r9d, r9d)?;
    a.call(l_vp)?;
    a.test(eax, eax)?;
    a.jz(l_fail)?;
    a.mov(dword_ptr(rbx + META_UNPACKED as i32), 1u32)?;
    a.mov(rcx, rbx)?;
    a.mov(edx, 4u32)?;
    a.mov(r8d, 0x20u32)?; // XL_PAGE_RX
    a.xor(r9d, r9d)?;
    a.call(l_vp)?;
    a.test(eax, eax)?;
    a.jz(l_fail)?;

    a.set_label(&mut l_forward)?;
    // Original DT_INIT (0 = none): call with SysV state, then return to ld.so.
    a.mov(eax, dword_ptr(rbx + META_ORIGINAL_ENTRY as i32))?;
    a.test(eax, eax)?;
    a.jz(l_ret)?;
    a.lea(rax, ptr(r15 + rax))?;
    a.call(rax)?;

    a.set_label(&mut l_ret)?;
    a.add(rsp, 8i32)?;
    a.pop(r15)?;
    a.pop(rbx)?;
    a.ret()?;

    // Fail closed: return as if init succeeded; every protected page is 0xCC,
    // so the next protected call traps loudly.
    a.set_label(&mut l_fail)?;
    a.add(rsp, 8i32)?;
    a.pop(r15)?;
    a.pop(rbx)?;
    a.ret()?;

    // SysV shim for gcc-built cores: xl_core calls vprotect with SysV
    // argument registers; remap (rdi,rsi,rdx,rcx)→(rcx,rdx,r8,r9) and fall
    // through to the Win64-layout wrapper. Each source register is read
    // before any destination is overwritten.
    a.set_label(&mut l_vp_sysv)?;
    a.mov(r9, rcx)?; // old
    a.mov(r8, rdx)?; // prot
    a.mov(rdx, rsi)?; // len
    a.mov(rcx, rdi)?; // addr
    // vprotect wrapper: Win64 args from xl_core (rcx=addr, rdx=len, r8d=prot,
    // r9=*old) → raw mprotect(2). Returns 1 on success, 0 on failure.
    a.set_label(&mut l_vp)?;
    a.mov(r11d, r8d)?; // requested prot for *old
    a.cmp(r8d, 0x04u32)?;
    a.je(l_vp_rw)?;
    a.cmp(r8d, 0x20u32)?;
    a.je(l_vp_rx)?;
    a.cmp(r8d, 0x40u32)?;
    a.je(l_vp_rwx)?;
    a.xor(eax, eax)?;
    a.ret()?;
    a.set_label(&mut l_vp_rw)?;
    a.mov(r8d, 3u32)?; // PROT_READ|PROT_WRITE
    a.jmp(l_vp_go)?;
    a.set_label(&mut l_vp_rx)?;
    a.mov(r8d, 5u32)?; // PROT_READ|PROT_EXEC
    a.jmp(l_vp_go)?;
    a.set_label(&mut l_vp_rwx)?;
    a.mov(r8d, 7u32)?; // PROT_READ|PROT_WRITE|PROT_EXEC
    a.set_label(&mut l_vp_go)?;
    a.test(r9, r9)?;
    a.jz(l_vp_old)?;
    a.mov(dword_ptr(r9), r11d)?;
    a.set_label(&mut l_vp_old)?;
    // Page-align: addr down, len covers the head and rounds to 4K.
    a.mov(r10, rcx)?;
    a.and(rcx, -4096i32)?;
    a.sub(r10, rcx)?;
    a.add(rdx, r10)?;
    a.add(rdx, 4095i32)?;
    a.and(rdx, -4096i32)?;
    // Win64 args (rcx=addr, rdx=len, r8=prot) → syscall ABI (rdi, rsi, rdx).
    a.mov(rdi, rcx)?;
    a.mov(rsi, rdx)?;
    a.mov(rdx, r8)?;
    a.mov(eax, 10u32)?; // __NR_mprotect
    a.db(&[0x0F, 0x05])?; // syscall (clobbers rcx, r11 — both dead here)
    a.test(eax, eax)?;
    a.sete(al)?;
    a.movzx(eax, al)?;
    a.ret()?;

    a.set_label(&mut l_core_bytes)?;
    emit_db(&mut a, core)?;
    a.set_label(&mut l_meta)?;
    a.db(&[0u8; STUB_META_LEN])?;

    let assembled = a.assemble_options(0, BlockEncoderOptions::RETURN_NEW_INSTRUCTION_OFFSETS)?;
    let entry_off = assembled.label_ip(&l_entry)? as u32;
    let bytes = assembled.inner.code_buffer;
    let meta_off = bytes.len() - STUB_META_LEN;
    Ok(ElfStub {
        bytes,
        meta_off,
        entry_off,
    })
}


