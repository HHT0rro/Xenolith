//! JNI-shaped host pack gate (JavaShroud adaptation). The host contract:
//! pack a DLL that carries `JNI_OnLoad`, `.jsms` / `.jsmk` / `.jsmd`
//! measurement slots and one pure arithmetic leaf; the packed image must
//! LoadLibrary, the JVM ABI export must resolve and run, the leaf must
//! compute through, and the measurement sections must survive byte-identical.

mod common;

use xenolith_formats::{Pe64, IMAGE_DIRECTORY_ENTRY_IMPORT};
use xenolith_loader::Profile;

const MEASUREMENT_SECTIONS: &[&str] = &[".jsms", ".jsmk", ".jsmd"];

/// W1-shape leaf oracle, must match jni_host.c `jh_leaf_mix`.
fn jh_leaf_mix_oracle(a: u32, b: u32) -> u32 {
    let mut t = a ^ b;
    t = t.wrapping_add(0x9E37_79B9);
    if t > 0x0001_0000 {
        t.wrapping_sub(b)
    } else {
        t.wrapping_add(b)
    }
}

#[test]
#[cfg(windows)]
fn jni_host_sample_inspects_clean_despite_jsms() {
    // Measurement sections are data in an unpacked host image, not a packer
    // fingerprint; inspect must not reject the JavaShroud input.
    let dll = common::required_release_sample("jni_host.dll");
    let info = xenolith_pack::inspect_bytes(&dll)
        .unwrap_or_else(|e| panic!("inspect unpacked jni_host: {e}"));
    assert_eq!(info["backend"], "native-or-unknown");
    let sections: Vec<String> = info["sections"]
        .as_array()
        .expect("sections")
        .iter()
        .map(|s| s.as_str().unwrap_or_default().to_string())
        .collect();
    for name in MEASUREMENT_SECTIONS {
        assert!(
            sections.iter().any(|s| s == name),
            "sections {sections:?} must keep {name}"
        );
    }
}

#[test]
#[cfg(windows)]
fn jni_abi_names_fail_closed_at_selection() {
    let dll = common::required_release_sample("jni_host.dll");
    for name in ["JNI_OnLoad", "JNI_OnUnload", "Java_probe_x", "qp_r1_open_frame"] {
        let err = match xenolith_pack::pack(xenolith_pack::PackRequest {
            input: &dll,
            profile: xenolith_loader::Profile::Max,
            vm_exports: vec![name.to_string()],
            debug_gate: 0,
            opcode_seed: None,
            trace_diverge: false,
            select_rva: vec![],
            select_functions: Vec::new(),
            select_all: false,
            allow_native_fallback: false,
            strict_coverage: false,
            lazy_regions: false,
            protect_imports: false,
            strict_constants: false,
        }) {
            Ok(_) => panic!("{name} must refuse virtualization"),
            Err(err) => err,
        };
        let text = err.to_string();
        assert!(
            text.contains("stay native"),
            "{name}: wrong error: {text}"
        );
    }
}

/// Hard gate: every profile keeps `.jsms` / `.jsmk` / `.jsmd` names and raw
/// bytes on disk (PointerToRawData still locatable). C3 may scramble the
/// in-memory section table after unpack — that must not alter the file.
#[test]
#[cfg(windows)]
fn measurement_sections_survive_all_profiles_byte_identical() {
    let dll = common::required_release_sample("jni_host.dll");
    let orig_pe = Pe64::parse(&dll).unwrap();
    assert_eq!(
        &common::section_raw_bytes(&orig_pe, &dll, ".jsms")[..8],
        b"JSIM\x01v6\0",
        "sample JSIM magic"
    );
    assert_eq!(
        &common::section_raw_bytes(&orig_pe, &dll, ".jsmk")[..8],
        b"JSMK\x01k1\0",
        "sample JSMK magic"
    );
    assert_eq!(
        &common::section_raw_bytes(&orig_pe, &dll, ".jsmd")[..8],
        b"JSMD\x01d1\0",
        "sample JSMD magic"
    );

    for profile in [Profile::Fast, Profile::Standard, Profile::Max] {
        let packed = xenolith_pack::pack(xenolith_pack::PackRequest {
            input: &dll,
            profile,
            vm_exports: vec![],
            debug_gate: 3,
            opcode_seed: None,
            trace_diverge: false,
            select_rva: vec![],
            select_functions: Vec::new(),
            select_all: false,
            allow_native_fallback: false,
            strict_coverage: false,
            lazy_regions: false,
            protect_imports: false,
            strict_constants: false,
        })
        .unwrap_or_else(|e| panic!("pack {profile:?}: {e}"));
        common::assert_measurement_sections_preserved(&dll, &packed.image, MEASUREMENT_SECTIONS);
        // JNI export forces disk IAT even on standard/max (no TLS required).
        let pe = Pe64::parse(&packed.image).unwrap();
        let import_rva = pe
            .directory(IMAGE_DIRECTORY_ENTRY_IMPORT)
            .map(|d| d.rva)
            .unwrap_or(0);
        assert_ne!(
            import_rva, 0,
            "{profile:?}: JNI_OnLoad export must force keep_import_directory"
        );
        assert_eq!(
            packed.report.iat_mode, "disk-import-directory",
            "{profile:?}: iat_mode"
        );
    }
}

#[cfg(windows)]
#[test]
fn packed_jni_host_loadlibrary_gate() {
    let out = common::spawn_exact_child("loader_child_jni_host");
    common::assert_child_ok(&out, "JNIHOST OK", "jni_host packed load");
}

#[cfg(windows)]
#[test]
fn packed_jni_host_leaf_vm_gate() {
    let out = common::spawn_exact_child("loader_child_jni_host_leaf");
    common::assert_child_ok(&out, "JNILEAF OK", "jni_host leaf vm-export");
}

#[cfg(windows)]
#[test]
fn packed_jni_rust_getenv_gate() {
    let out = common::spawn_exact_child("loader_child_jni_rust");
    common::assert_child_ok(&out, "JNIRUST OK", "jni_rust GetEnv JNI_OnLoad");
}

/// C1 gate: the arithmetic leaf virtualizes through `--vm-export` while the
/// JNI ABI stays native, and the packed image still loads.
#[cfg(windows)]
#[test]
fn loader_child_jni_host_leaf() {
    if std::env::var("XL_LOADER_CHILD").as_deref() != Ok("1") {
        return;
    }
    use xenolith_formats::Pe64;
    use xenolith_loader::Profile;
    use xenolith_pack::{pack, PackRequest};

    let dll = common::required_release_sample("jni_host.dll");
    let packed = pack(PackRequest {
        input: &dll,
        profile: Profile::Max,
        vm_exports: vec!["jh_leaf_mix".into()],
        debug_gate: 3,
        opcode_seed: None,
        trace_diverge: false,
        select_rva: vec![],
        select_functions: Vec::new(),
        select_all: false,
        allow_native_fallback: false,
        strict_coverage: false,
        lazy_regions: false,
        protect_imports: false,
        strict_constants: false,
    })
    .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(packed.report.vm_functions, 1, "leaf must be virtualized");
    assert_eq!(
        packed.report.selected_functions,
        vec!["jh_leaf_mix".to_string()],
        "selected_functions must name the leaf"
    );
    common::assert_measurement_sections_preserved(&dll, &packed.image, MEASUREMENT_SECTIONS);
    // The JNI ABI export must NOT be in the VM set and must stay at its
    // original .text page (not the stub).
    let pe = Pe64::parse(&packed.image).unwrap();
    let jni = pe
        .exports(&packed.image)
        .unwrap()
        .into_iter()
        .find(|e| e.name == "JNI_OnLoad")
        .expect("JNI_OnLoad export survives");
    let text = pe.sections.first().expect(".text first");
    assert!(
        jni.rva >= text.virtual_address && jni.rva < text.virtual_address + text.virtual_size,
        "JNI_OnLoad must stay native in .text"
    );
    assert_eq!(packed.report.iat_mode, "disk-import-directory");

    let dir = std::env::temp_dir();
    let path = dir.join(format!("xl-jnileaf-{}.dll", std::process::id()));
    std::fs::write(&path, &packed.image).expect("write");
    let want = jh_leaf_mix_oracle(9, 4) as i32;
    let got = unsafe { common::load_and_call_named(&path, b"jh_leaf_mix\0", 9, 4, None) };
    // C sample ignores the VM pointer; still pass a non-null fake so the
    // calling convention matches the rustc GetEnv gate.
    let mut fake_env: u8 = 1;
    let mut invoke = FakeInvoke {
        reserved0: std::ptr::null_mut(),
        reserved1: std::ptr::null_mut(),
        reserved2: std::ptr::null_mut(),
        destroy: None,
        attach: None,
        detach: None,
        get_env: Some(fake_get_env_ok),
    };
    let mut vm = FakeJavaVm {
        functions: &invoke as *const FakeInvoke,
    };
    let jni_onload = unsafe {
        common::load_and_call_jni_onload(&path, &mut vm as *mut _ as *mut _)
    };
    let _ = std::fs::remove_file(&path);
    let _ = &mut fake_env;
    let _ = &mut invoke;
    assert_eq!(got, Some(want), "virtualized leaf must compute through PIC");
    assert_eq!(
        jni_onload,
        Some(0x0001_0008),
        "JNI_OnLoad must stay loadable beside the virtualized leaf"
    );
    eprintln!("JNILEAF OK leaf={want} jni_onload={:#x}", 0x0001_0008);
}

#[cfg(windows)]
#[test]
fn loader_child_jni_host() {
    if std::env::var("XL_LOADER_CHILD").as_deref() != Ok("1") {
        return;
    }
    use xenolith_formats::Pe64;
    use xenolith_loader::Profile;
    use xenolith_pack::{pack, PackRequest};

    let dll = common::required_release_sample("jni_host.dll");
    let orig_pe = Pe64::parse(&dll).unwrap();
    let leaf_rva = orig_pe
        .exports(&dll)
        .unwrap()
        .into_iter()
        .find(|e| e.name == "jh_leaf_mix")
        .expect("jh_leaf_mix export")
        .rva;

    assert_eq!(
        &common::section_raw_bytes(&orig_pe, &dll, ".jsms")[..8],
        b"JSIM\x01v6\0",
        "sample JSIM magic"
    );

    let packed = pack(PackRequest {
        input: &dll,
        profile: Profile::Max,
        vm_exports: vec![],
        debug_gate: 3,
        opcode_seed: None,
        trace_diverge: false,
        select_rva: vec![],
        select_functions: Vec::new(),
        select_all: false,
        allow_native_fallback: false,
        strict_coverage: false,
        lazy_regions: false,
        protect_imports: false,
        strict_constants: false,
    })
    .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(packed.report.vm_functions, 0, "default pack VMs nothing");
    assert_eq!(packed.report.format, "pe64-dll");
    assert_eq!(packed.report.iat_mode, "disk-import-directory");
    common::assert_measurement_sections_preserved(&dll, &packed.image, MEASUREMENT_SECTIONS);

    let packed_pe = Pe64::parse(&packed.image).unwrap();

    // The leaf's on-disk bytes are traps after packing (A3 residency shape).
    let leaf_off = packed_pe.file_offset_of(leaf_rva).unwrap();
    assert_ne!(
        &packed.image[leaf_off..leaf_off + 8],
        &dll[orig_pe.file_offset_of(leaf_rva).unwrap()..orig_pe.file_offset_of(leaf_rva).unwrap() + 8],
        "packed .text at the leaf must not stay original plaintext"
    );

    // inspect on the PACKED image must work and report the stub backend.
    let info = xenolith_pack::inspect_bytes(&packed.image)
        .unwrap_or_else(|e| panic!("inspect packed jni_host: {e}"));
    assert_eq!(info["backend"], xenolith_pack::BACKEND_PIC_STUB);
    assert_eq!(info["iat_mode"], "disk-import-directory");

    // OS-load gate: DllMain runs the stub, CRT init succeeds, JVM ABI and
    // the leaf both resolve and execute.
    let dir = std::env::temp_dir();
    let path = dir.join(format!("xl-jnihost-{}.dll", std::process::id()));
    std::fs::write(&path, &packed.image).expect("write");
    let mut invoke = FakeInvoke {
        reserved0: std::ptr::null_mut(),
        reserved1: std::ptr::null_mut(),
        reserved2: std::ptr::null_mut(),
        destroy: None,
        attach: None,
        detach: None,
        get_env: Some(fake_get_env_ok),
    };
    let mut vm = FakeJavaVm {
        functions: &invoke as *const FakeInvoke,
    };
    let jni_onload = unsafe {
        common::load_and_call_jni_onload(&path, &mut vm as *mut _ as *mut _)
    };
    assert_eq!(
        jni_onload,
        Some(0x0001_0008),
        "JNI_OnLoad must return JNI_VERSION_1_8 through the packed image"
    );
    let want = jh_leaf_mix_oracle(7, 5) as i32;
    let leaf = unsafe { common::load_and_call_named(&path, b"jh_leaf_mix\0", 7, 5, None) };
    let _ = std::fs::remove_file(&path);
    let _ = &mut invoke;
    assert_eq!(leaf, Some(want), "jh_leaf_mix must compute through");
    eprintln!("JNIHOST OK jni_onload={:#x} leaf={want}", 0x0001_0008);
}

/// rustc cdylib: packed image LoadLibrary, then JNI_OnLoad with a fake
/// JavaVM* whose GetEnv returns JNI_OK + non-null env. NULL/NULL must not be
/// used (would return JNI_ERR here and would false-pass constant C stubs).
#[cfg(windows)]
#[test]
fn loader_child_jni_rust() {
    if std::env::var("XL_LOADER_CHILD").as_deref() != Ok("1") {
        return;
    }
    use xenolith_loader::Profile;
    use xenolith_pack::{pack, PackRequest};

    let dll = common::required_release_sample("jni_rust.dll");
    let packed = pack(PackRequest {
        input: &dll,
        profile: Profile::Fast,
        vm_exports: vec![],
        debug_gate: 3,
        opcode_seed: None,
        trace_diverge: false,
        select_rva: vec![],
        select_functions: Vec::new(),
        select_all: false,
        allow_native_fallback: false,
        strict_coverage: false,
        lazy_regions: false,
        protect_imports: false,
        strict_constants: false,
    })
    .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(packed.report.format, "pe64-dll");
    assert_eq!(
        packed.report.iat_mode, "disk-import-directory",
        "JNI_OnLoad must force disk IAT"
    );

    let dir = std::env::temp_dir();
    let path = dir.join(format!("xl-jnirust-{}.dll", std::process::id()));
    std::fs::write(&path, &packed.image).expect("write");

    // Positive: GetEnv OK + non-null env → JNI_VERSION_1_8
    let mut fake_env: u8 = 0x5a;
    let mut invoke_ok = FakeInvoke {
        reserved0: std::ptr::null_mut(),
        reserved1: std::ptr::null_mut(),
        reserved2: std::ptr::null_mut(),
        destroy: None,
        attach: None,
        detach: None,
        get_env: Some(fake_get_env_ok),
    };
    let mut vm_ok = FakeJavaVm {
        functions: &invoke_ok as *const FakeInvoke,
    };
    let ok = unsafe { common::load_and_call_jni_onload(&path, &mut vm_ok as *mut _ as *mut _) };
    assert_eq!(ok, Some(0x0001_0008), "GetEnv OK must yield JNI_VERSION_1_8");

    // Negative: GetEnv returns null env → JNI_ERR
    let mut invoke_null = FakeInvoke {
        reserved0: std::ptr::null_mut(),
        reserved1: std::ptr::null_mut(),
        reserved2: std::ptr::null_mut(),
        destroy: None,
        attach: None,
        detach: None,
        get_env: Some(fake_get_env_null_env),
    };
    let mut vm_null = FakeJavaVm {
        functions: &invoke_null as *const FakeInvoke,
    };
    let err_null =
        unsafe { common::load_and_call_jni_onload(&path, &mut vm_null as *mut _ as *mut _) };
    assert_eq!(err_null, Some(-1), "null env must yield JNI_ERR");

    // Negative: never call with NULL vm (JNI_OnLoad(NULL,NULL) is forbidden)
    let err_vm =
        unsafe { common::load_and_call_jni_onload(&path, std::ptr::null_mut()) };
    assert_eq!(err_vm, Some(-1), "NULL JavaVM* must yield JNI_ERR");

    let _ = std::fs::remove_file(&path);
    let _ = &mut fake_env;
    let _ = &mut invoke_ok;
    let _ = &mut invoke_null;
    eprintln!("JNIRUST OK jni_onload={:#x}", 0x0001_0008);
}

#[cfg(windows)]
#[repr(C)]
struct FakeJavaVm {
    functions: *const FakeInvoke,
}

#[cfg(windows)]
#[repr(C)]
struct FakeInvoke {
    reserved0: *mut core::ffi::c_void,
    reserved1: *mut core::ffi::c_void,
    reserved2: *mut core::ffi::c_void,
    destroy: Option<unsafe extern "system" fn(*mut FakeJavaVm) -> i32>,
    attach: Option<
        unsafe extern "system" fn(*mut FakeJavaVm, *mut *mut core::ffi::c_void, *mut core::ffi::c_void) -> i32,
    >,
    detach: Option<unsafe extern "system" fn(*mut FakeJavaVm) -> i32>,
    get_env: Option<
        unsafe extern "system" fn(*mut FakeJavaVm, *mut *mut core::ffi::c_void, i32) -> i32,
    >,
}

#[cfg(windows)]
unsafe extern "system" fn fake_get_env_ok(
    _vm: *mut FakeJavaVm,
    penv: *mut *mut core::ffi::c_void,
    _version: i32,
) -> i32 {
    // Non-null opaque env token; JNI_OnLoad only checks non-null + JNI_OK.
    *penv = 0x1 as *mut core::ffi::c_void;
    0
}

#[cfg(windows)]
unsafe extern "system" fn fake_get_env_null_env(
    _vm: *mut FakeJavaVm,
    penv: *mut *mut core::ffi::c_void,
    _version: i32,
) -> i32 {
    *penv = std::ptr::null_mut();
    0
}
