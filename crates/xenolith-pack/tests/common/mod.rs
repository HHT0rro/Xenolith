//! Shared helpers for pack integration tests.
//!
//! Missing samples are a hard failure, not a skip.

#![allow(dead_code)]

use xenolith_formats::Pe64;
use std::path::{Path, PathBuf};

pub fn required_release_sample(file_name: &str) -> Vec<u8> {
    let mut paths = Vec::new();
    if let Ok(manifest) = std::env::var("CARGO_MANIFEST_DIR") {
        let p = PathBuf::from(manifest);
        paths.push(p.join("../../target/release").join(file_name));
        paths.push(p.join("../../../target/release").join(file_name));
    }
    if let Ok(td) = std::env::var("CARGO_TARGET_DIR") {
        paths.push(PathBuf::from(td).join("release").join(file_name));
    }
    paths.push(PathBuf::from("target/release").join(file_name));
    paths.push(PathBuf::from("../../target/release").join(file_name));
    for p in &paths {
        if let Ok(bytes) = std::fs::read(p) {
            if !bytes.is_empty() {
                return bytes;
            }
        }
    }
    panic!(
        "missing required sample {file_name}; looked in {paths:?}. \
         Build first: cargo build -p hello-dll --release && \
         cargo build -p license-toy --release && \
         cargo build -p hello-exe --release && \
         cargo build -p jni-host --release && \
         cargo build -p jni-rust --release. \
         Missing sample is a FAIL, not a skip."
    );
}

pub fn thunk_pic<'a>(pe: &Pe64, image: &'a [u8], name: &str) -> &'a [u8] {
    let exp = pe
        .exports(image)
        .unwrap()
        .into_iter()
        .find(|e| e.name == name)
        .expect("export");
    let stub = pe.sections.iter().rev().nth(1).expect("stub");
    let off = (exp.rva - stub.virtual_address) as usize;
    let raw = stub.raw_ptr as usize;
    let len = stub.raw_size.min(stub.virtual_size) as usize;
    let bytes = &image[raw..raw + len];
    let end = len.saturating_sub(xenolith_pack::STUB_META_LEN);
    &bytes[off.min(end)..end]
}

pub fn spawn_exact_child(test_name: &str) -> std::process::Output {
    let exe = std::env::current_exe().expect("current_exe");
    std::process::Command::new(&exe)
        .arg(test_name)
        .arg("--exact")
        .arg("--nocapture")
        .env("XL_LOADER_CHILD", "1")
        .output()
        .unwrap_or_else(|e| {
            panic!("failed to spawn child {test_name} from {}: {e}", exe.display())
        })
}

pub fn assert_child_ok(out: &std::process::Output, marker: &str, what: &str) {
    eprint!("{}", String::from_utf8_lossy(&out.stderr));
    assert!(
        out.status.success(),
        "{what} child crashed (status={:?}); missing tool/sample is a fail",
        out.status
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains(marker),
        "{what} child did not complete (`{marker}` missing). subprocess did not run to verdict."
    );
}

#[cfg(windows)]
pub fn entry_bytes(dll: &[u8]) -> Option<[u8; 16]> {
    let pe = Pe64::parse(dll).ok()?;
    let off = pe.file_offset_of(pe.entry_rva).ok()?;
    let mut out = [0u8; 16];
    out.copy_from_slice(&dll[off..off + 16]);
    Some(out)
}

#[cfg(windows)]
pub unsafe fn load_and_call(
    path: &Path,
    call_export: bool,
    entry_rva: u32,
    expected: Option<[u8; 16]>,
    sectbl: Option<(u32, Vec<u8>, bool)>,
    dump_rva: Option<u32>,
    dump_expect: Option<[u8; 16]>,
) -> Option<i32> {
    use std::os::windows::ffi::OsStrExt;
    #[link(name = "kernel32")]
    extern "system" {
        fn LoadLibraryW(p: *const u16) -> *mut core::ffi::c_void;
        fn GetProcAddress(h: *mut core::ffi::c_void, n: *const u8) -> *mut core::ffi::c_void;
        fn FreeLibrary(h: *mut core::ffi::c_void) -> i32;
        fn AddVectoredExceptionHandler(
            first: u32,
            handler: Option<extern "system" fn(*mut core::ffi::c_void) -> i32>,
        ) -> *mut core::ffi::c_void;
        fn GetModuleHandleExW(
            flags: u32,
            name: *const u16,
            module: *mut *mut core::ffi::c_void,
        ) -> i32;
    }

    extern "system" fn veh(info: *mut core::ffi::c_void) -> i32 {
        unsafe {
            let ptr = info as *const u8;
            let record = *(ptr as *const *const u8);
            let ctx = *(ptr.add(8) as *const *const u8);
            let code = (record as *const u32).read_unaligned();
            let addr = ((record as *const u8).add(0x10) as *const usize).read_unaligned();
            let nparams = ((record as *const u8).add(0x18) as *const u32).read_unaligned();
            let info0 = if nparams > 0 {
                ((record as *const u8).add(0x20) as *const usize).read_unaligned()
            } else {
                0
            };
            let info1 = if nparams > 1 {
                ((record as *const u8).add(0x28) as *const usize).read_unaligned()
            } else {
                0
            };
            let rip = ((ctx as *const u8).add(0xF8) as *const usize).read_unaligned();
            let r = |o: usize| ((ctx as *const u8).add(o) as *const usize).read_unaligned();
            let mut code_at_rip = [0u8; 16];
            std::ptr::copy_nonoverlapping(rip as *const u8, code_at_rip.as_mut_ptr(), 16);
            eprintln!(
                "VEH code=0x{code:08x} op={info0} target={info1:#x} rip={rip:#x} bytes={:02x?} rax={:#x} rcx={:#x} rdx={:#x} rbx={:#x} rsp={:#x} rbp={:#x} rsi={:#x} rdi={:#x} r10={:#x}",
                code_at_rip,
                r(0x78), r(0x80), r(0x88), r(0x90), r(0x98), r(0xA0), r(0xA8), r(0xB0), r(0xC8)
            );
            let rbx_v = r(0x90);
            if rbx_v > 0x10000 && (rbx_v & 0xfff) > 0x100 {
                let page = ((rbx_v as *const u8).add(56) as *const u32).read_unaligned();
                let callmark = ((rbx_v as *const u8).add(59) as *const u8).read_unaligned();
                eprintln!("VEH last_verified_page={page:#x} callmark={callmark:#x}");
            }
            let rbp_v = r(0xA0);
            if rbp_v > 0x10000 {
                let mut rec = [0u8; 48];
                std::ptr::copy_nonoverlapping(rbp_v as *const u8, rec.as_mut_ptr(), 48);
                eprintln!("VEH rec@{rbp_v:#x} = {:02x?}", rec);
            }
            let mut module: *mut core::ffi::c_void = std::ptr::null_mut();
            if GetModuleHandleExW(6, addr as *const u16, &mut module) != 0 && !module.is_null() {
                eprintln!(
                    "VEH module={:p} off=+{:x}",
                    module,
                    addr - module as usize
                );
            } else {
                eprintln!("VEH rip not in any module");
            }
            use std::io::Write;
            let _ = std::io::stderr().flush();
        }
        0
    }
    AddVectoredExceptionHandler(1, Some(veh));

    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    wide.push(0);
    let handle = LoadLibraryW(wide.as_ptr());
    if handle.is_null() {
        #[link(name = "kernel32")]
        extern "system" {
            fn GetLastError() -> u32;
        }
        eprintln!("LoadLibraryW failed gle={}", GetLastError());
        return None;
    }
    if let Some(exp) = expected {
        if !handle.is_null() {
            let mut got = [0u8; 16];
            std::ptr::copy_nonoverlapping(
                (handle as *const u8).add(entry_rva as usize),
                got.as_mut_ptr(),
                16,
            );
            eprintln!("LOAD entry={entry_rva:#x} got={got:02x?} expect={exp:02x?}");
        }
    }
    if !handle.is_null() {
        if let Some(off) = dump_rva {
            let mut got = [0u8; 16];
            std::ptr::copy_nonoverlapping(
                (handle as *const u8).add(off as usize),
                got.as_mut_ptr(),
                16,
            );
            eprintln!("DUMP rva={off:#x} bytes={got:02x?}");
            if let Some(plain) = dump_expect {
                if got.as_slice() == plain.as_slice() {
                    eprintln!("C2 STILL PLAIN at {off:#x} (expected: exec pages stay live)");
                } else {
                    eprintln!("C2 DIVERGED at {off:#x}");
                }
            }
        }
        if let Some((rva, disk, expect_scramble)) = &sectbl {
            if !disk.is_empty() {
                let mut got = vec![0u8; disk.len()];
                std::ptr::copy_nonoverlapping(
                    (handle as *const u8).add(*rva as usize),
                    got.as_mut_ptr(),
                    got.len(),
                );
                let same = got == *disk;
                eprintln!("SCRAMBLE rva={rva:#x} same={same} expect_scramble={expect_scramble}");
                assert_eq!(same, !expect_scramble, "section table scramble mismatch");
            }
        }
    }
    let out = if call_export {
        let proc = GetProcAddress(handle, b"hello_add\0".as_ptr());
        if proc.is_null() {
            None
        } else {
            let f: extern "C" fn(i32, i32) -> i32 = core::mem::transmute(proc);
            Some(f(3, 4))
        }
    } else {
        Some(-1)
    };
    FreeLibrary(handle);
    out
}

#[cfg(windows)]
pub unsafe fn load_and_call_named(
    path: &Path,
    name: &[u8],
    a: i32,
    b: i32,
    expected: Option<[u8; 16]>,
) -> Option<i32> {
    let _ = expected;
    use std::os::windows::ffi::OsStrExt;
    #[link(name = "kernel32")]
    extern "system" {
        fn LoadLibraryW(p: *const u16) -> *mut core::ffi::c_void;
        fn GetProcAddress(h: *mut core::ffi::c_void, n: *const u8) -> *mut core::ffi::c_void;
        fn FreeLibrary(h: *mut core::ffi::c_void) -> i32;
    }
    let mut w: Vec<u16> = path.as_os_str().encode_wide().collect();
    w.push(0);
    let handle = LoadLibraryW(w.as_ptr());
    if handle.is_null() {
        return None;
    }
    let proc = GetProcAddress(handle, name.as_ptr());
    let out = if proc.is_null() {
        None
    } else {
        let f: extern "C" fn(i32, i32) -> i32 = core::mem::transmute(proc);
        Some(f(a, b))
    };
    FreeLibrary(handle);
    out
}

#[cfg(windows)]
pub unsafe fn load_and_call_named_traced(
    path: &Path,
    name: &[u8],
    a: i32,
    b: i32,
    image_size: usize,
) -> (Option<i32>, u64, u32) {
    use std::os::windows::ffi::OsStrExt;
    const PAGE_EXECUTE_READWRITE: u32 = 0x40;
    const PAGE_GUARD: u32 = 0x100;
    const STATUS_GUARD_PAGE: u32 = 0x8000_0001;
    const STATUS_SINGLE_STEP: u32 = 0x8000_0004;
    #[link(name = "kernel32")]
    extern "system" {
        fn LoadLibraryW(p: *const u16) -> *mut core::ffi::c_void;
        fn GetProcAddress(h: *mut core::ffi::c_void, n: *const u8) -> *mut core::ffi::c_void;
        fn FreeLibrary(h: *mut core::ffi::c_void) -> i32;
        fn VirtualProtect(
            addr: *mut core::ffi::c_void,
            size: usize,
            new: u32,
            old: *mut u32,
        ) -> i32;
        fn AddVectoredExceptionHandler(
            first: u32,
            handler: Option<extern "system" fn(*mut core::ffi::c_void) -> i32>,
        ) -> *mut core::ffi::c_void;
        fn RemoveVectoredExceptionHandler(h: *mut core::ffi::c_void) -> u32;
    }

    struct Trace {
        lo: usize,
        hi: usize,
        hash: u64,
        steps: u32,
        on: bool,
    }
    static mut TRACE: Trace = Trace {
        lo: 0,
        hi: 0,
        hash: 0xcbf2_9ce4_8422_2325,
        steps: 0,
        on: false,
    };

    extern "system" fn veh(info: *mut core::ffi::c_void) -> i32 {
        unsafe {
            let rec = *(info as *const *const u8);
            let ctx = *((info as *const u8).add(8) as *const *mut u8);
            let code = (rec as *const u32).read_unaligned();
            let eflags_p = ctx.add(0x44) as *mut u32;
            if code == STATUS_GUARD_PAGE {
                if TRACE.on {
                    let eflags = eflags_p.read_unaligned();
                    eflags_p.write_unaligned(eflags | 0x100);
                }
                return -1;
            }
            if code != STATUS_SINGLE_STEP {
                return 0;
            }
            if !TRACE.on || TRACE.steps >= 64_000 {
                let eflags = eflags_p.read_unaligned();
                eflags_p.write_unaligned(eflags & !0x100);
                return -1;
            }
            let rip = (ctx.add(0xF8) as *const usize).read_unaligned();
            if rip >= TRACE.lo && rip < TRACE.hi {
                let off = (rip - TRACE.lo) as u64;
                TRACE.hash ^= off;
                TRACE.hash = TRACE.hash.wrapping_mul(0x1000_0000_01B3);
                TRACE.steps += 1;
                let eflags = eflags_p.read_unaligned();
                eflags_p.write_unaligned(eflags | 0x100);
            } else {
                let eflags = eflags_p.read_unaligned();
                eflags_p.write_unaligned(eflags & !0x100);
            }
            -1
        }
    }

    let mut w: Vec<u16> = path.as_os_str().encode_wide().collect();
    w.push(0);
    let handle = LoadLibraryW(w.as_ptr());
    if handle.is_null() {
        return (None, 0, 0);
    }
    let proc = GetProcAddress(handle, name.as_ptr());
    if proc.is_null() {
        FreeLibrary(handle);
        return (None, 0, 0);
    }
    let veh_h = AddVectoredExceptionHandler(1, Some(veh));
    TRACE.lo = handle as usize;
    TRACE.hi = TRACE.lo + image_size.max(0x1000);
    TRACE.hash = 0xcbf2_9ce4_8422_2325;
    TRACE.steps = 0;
    TRACE.on = true;
    let mut old = 0u32;
    let page = (proc as usize) & !0xfff;
    VirtualProtect(
        page as *mut core::ffi::c_void,
        0x1000,
        PAGE_EXECUTE_READWRITE | PAGE_GUARD,
        &mut old,
    );
    let f: extern "C" fn(i32, i32) -> i32 = core::mem::transmute(proc);
    let eax = f(a, b);
    TRACE.on = false;
    let mut restore = 0u32;
    VirtualProtect(
        page as *mut core::ffi::c_void,
        0x1000,
        PAGE_EXECUTE_READWRITE,
        &mut restore,
    );
    if !veh_h.is_null() {
        RemoveVectoredExceptionHandler(veh_h);
    }
    let hash = TRACE.hash;
    let steps = TRACE.steps;
    FreeLibrary(handle);
    (Some(eax), hash, steps)
}

/// Call `JNI_OnLoad` after LoadLibrary with a real (possibly fake) JavaVM*.
/// Never passes NULL/NULL — that would false-pass a constant-return C stub.
#[cfg(windows)]
pub unsafe fn load_and_call_jni_onload(
    path: &Path,
    vm: *mut core::ffi::c_void,
) -> Option<i32> {
    use std::os::windows::ffi::OsStrExt;
    #[link(name = "kernel32")]
    extern "system" {
        fn LoadLibraryW(p: *const u16) -> *mut core::ffi::c_void;
        fn GetProcAddress(h: *mut core::ffi::c_void, n: *const u8) -> *mut core::ffi::c_void;
        fn FreeLibrary(h: *mut core::ffi::c_void) -> i32;
    }
    let mut w: Vec<u16> = path.as_os_str().encode_wide().collect();
    w.push(0);
    let handle = LoadLibraryW(w.as_ptr());
    if handle.is_null() {
        return None;
    }
    let proc = GetProcAddress(handle, b"JNI_OnLoad\0".as_ptr());
    let out = if proc.is_null() {
        None
    } else {
        let f: unsafe extern "system" fn(*mut core::ffi::c_void, *mut core::ffi::c_void) -> i32 =
            core::mem::transmute(proc);
        Some(f(vm, core::ptr::null_mut()))
    };
    FreeLibrary(handle);
    out
}

/// On-disk raw bytes of a named PE section (PointerToRawData..SizeOfRawData).
pub fn section_raw_bytes<'a>(pe: &Pe64, image: &'a [u8], name: &str) -> &'a [u8] {
    let sec = pe
        .sections
        .iter()
        .find(|s| s.name_str() == name)
        .unwrap_or_else(|| panic!("missing section {name}"));
    let start = sec.raw_ptr as usize;
    let len = (sec.raw_size.min(sec.virtual_size)) as usize;
    &image[start..start + len]
}

/// Assert host measurement sections survive packing with the same name and
/// byte-identical raw content (C3 may scramble the *in-memory* section table
/// after unpack; disk lookup must still work).
pub fn assert_measurement_sections_preserved(
    input: &[u8],
    packed: &[u8],
    names: &[&str],
) {
    let in_pe = Pe64::parse(input).expect("input pe");
    let out_pe = Pe64::parse(packed).expect("packed pe");
    for name in names {
        let before = section_raw_bytes(&in_pe, input, name);
        let after = section_raw_bytes(&out_pe, packed, name);
        assert_eq!(
            before, after,
            "{name} must survive packing byte-identical (name + raw content)"
        );
        assert!(
            out_pe.sections.iter().any(|s| s.name_str() == *name),
            "{name} section name must remain findable on disk"
        );
    }
}
