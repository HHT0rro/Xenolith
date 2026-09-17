mod common;

#[cfg(windows)]
#[test]
fn packed_dll_vm_export_hello_add() {
    let out = common::spawn_exact_child("loader_child_vm_export_hello");
    common::assert_child_ok(&out, "VMEXPORT OK", "vm-export hello");
}

#[cfg(windows)]
#[test]
fn loader_child_vm_export_hello() {
    if std::env::var("XL_LOADER_CHILD").as_deref() != Ok("1") {
        return;
    }
    use xenolith_formats::Pe64;
    use xenolith_loader::Profile;
    use xenolith_pack::{pack, PackRequest};

    let dll = common::required_release_sample("hello_dll.dll");
    let orig_pe = Pe64::parse(&dll).unwrap();
    let hello_rva = orig_pe
        .exports(&dll)
        .unwrap()
        .into_iter()
        .find(|e| e.name == "hello_add")
        .expect("hello_add")
        .rva;
    let packed = pack(PackRequest {
        input: &dll,
        profile: Profile::Standard,
        vm_exports: vec!["hello_add".into()],
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
    assert_eq!(packed.report.vm_functions, 1);
    let packed_pe = Pe64::parse(&packed.image).unwrap();
    let live_export = packed_pe
        .exports(&packed.image)
        .unwrap()
        .into_iter()
        .find(|e| e.name == "hello_add")
        .expect("packed hello_add");
    let stub_sec = packed_pe
        .sections
        .iter()
        .rev()
        .nth(1)
        .expect("stub section");
    assert!(
        live_export.rva >= stub_sec.virtual_address
            && live_export.rva
                < stub_sec.virtual_address + stub_sec.virtual_size.max(stub_sec.raw_size),
        "G-VM: hello_add export must retarget stub thunk (got {:#x}, stub {:#x})",
        live_export.rva,
        stub_sec.virtual_address
    );
    let orig_off = orig_pe.file_offset_of(hello_rva).unwrap();
    let orig0 = dll[orig_off];
    eprintln!(
        "VMEXPORT orig_rva={hello_rva:#x} orig0={orig0:#x} packed_export={:#x} stub={:#x}",
        live_export.rva, stub_sec.virtual_address
    );
    let dir = std::env::temp_dir();
    let path = dir.join(format!("xl-vmexport-{}.dll", std::process::id()));
    std::fs::write(&path, &packed.image).expect("write");
    let expect = common::entry_bytes(&dll);
    let result = unsafe {
        common::load_and_call(
            &path,
            true,
            packed.packed.original_entry_rva,
            expect,
            None,
            Some(hello_rva),
            None,
        )
    };
    let _ = std::fs::remove_file(&path);
    assert_eq!(result, Some(7), "vm-export hello_add");
    eprintln!("VMEXPORT OK orig0={orig0:#x}");
}

#[cfg(windows)]
#[test]
fn packed_dll_vm_export_license_toy() {
    let out = common::spawn_exact_child("loader_child_vm_export_license");
    common::assert_child_ok(&out, "LICENSEVM OK", "license_toy vm-export");
}

#[cfg(windows)]
#[test]
fn loader_child_vm_export_license() {
    if std::env::var("XL_LOADER_CHILD").as_deref() != Ok("1") {
        return;
    }
    use xenolith_formats::Pe64;
    use xenolith_loader::Profile;
    use xenolith_pack::{pack, PackRequest};

    let dll = common::required_release_sample("license_toy.dll");
    let orig_pe = Pe64::parse(&dll).unwrap();
    let rva = orig_pe
        .exports(&dll)
        .unwrap()
        .into_iter()
        .find(|e| e.name == "check_license")
        .expect("check_license")
        .rva;
    let packed = pack(PackRequest {
        input: &dll,
        profile: Profile::Standard,
        vm_exports: vec!["check_license".into()],
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
    assert_eq!(packed.report.vm_functions, 1);
    let packed_pe = Pe64::parse(&packed.image).unwrap();
    let live = packed_pe
        .exports(&packed.image)
        .unwrap()
        .into_iter()
        .find(|e| e.name == "check_license")
        .expect("packed check_license");
    let stub_sec = packed_pe.sections.iter().rev().nth(1).expect("stub");
    assert!(
        live.rva >= stub_sec.virtual_address
            && live.rva < stub_sec.virtual_address + stub_sec.virtual_size.max(stub_sec.raw_size),
        "G-VM: check_license must retarget stub thunk"
    );
    let dir = std::env::temp_dir();
    let path = dir.join(format!("xl-license-{}.dll", std::process::id()));
    std::fs::write(&path, &packed.image).expect("write");
    let expect = common::entry_bytes(&dll);
    let result = unsafe { common::load_and_call_named(&path, b"check_license\0", 3, 4, expect) };
    let _ = std::fs::remove_file(&path);
    let want = xenolith_vm::license_toy_oracle(3, 4) as i32;
    assert_eq!(result, Some(want), "vm-export check_license");
    eprintln!("LICENSEVM OK rva={rva:#x} eax={want}");
}

#[cfg(windows)]
#[test]
fn packed_dll_vm_export_license_toy_trace_diverge() {
    let mut eax = None;
    let mut hashes = Vec::new();
    for i in 0..2 {
        let out = common::spawn_exact_child("loader_child_vm_export_license_diverge");
        eprint!("{}", String::from_utf8_lossy(&out.stderr));
        assert!(
            out.status.success(),
            "license_toy trace-diverge child {i} crashed"
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("LICENSEDIV OK"),
            "license_toy diverge child {i} did not finish"
        );
        let got = stderr
            .split("eax=")
            .nth(1)
            .and_then(|s| s.split_whitespace().next())
            .and_then(|s| s.parse::<i32>().ok());
        let hash = stderr
            .split("stream_hash=")
            .nth(1)
            .and_then(|s| s.split_whitespace().next())
            .and_then(|s| {
                let t = s.strip_prefix("0x").unwrap_or(s);
                u64::from_str_radix(t, 16).ok()
            });
        assert!(
            hash.is_some() && hash != Some(0),
            "G-WB-TRACE: missing stream_hash child {i}"
        );
        hashes.push(hash.unwrap());
        match eax {
            None => eax = got,
            Some(a) => assert_eq!(got, Some(a), "G-WB-TRACE: two processes, same eax"),
        }
    }
    assert_eq!(hashes.len(), 2);
    if hashes[0] != hashes[1] {
        eprintln!(
            "G-WB-TRACE stream hashes differ {:#x} vs {:#x} (allowed)",
            hashes[0], hashes[1]
        );
    } else {
        eprintln!(
            "G-WB-TRACE stream hashes matched {:#x} this run (allowed; PIC still has two paths)",
            hashes[0]
        );
    }
}

#[cfg(windows)]
#[test]
fn loader_child_vm_export_license_diverge() {
    if std::env::var("XL_LOADER_CHILD").as_deref() != Ok("1") {
        return;
    }
    use xenolith_formats::Pe64;
    use xenolith_loader::Profile;
    use xenolith_pack::{pack, PackRequest};

    let dll = common::required_release_sample("license_toy.dll");
    let packed = pack(PackRequest {
        input: &dll,
        profile: Profile::Standard,
        vm_exports: vec!["check_license".into()],
        debug_gate: 3,
        opcode_seed: Some([7; 16]),
        trace_diverge: true,
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
    let pe = Pe64::parse(&packed.image).unwrap();
    let pic = common::thunk_pic(&pe, &packed.image, "check_license");
    assert!(
        pic.windows(9)
            .any(|w| w == [0x65, 0x4C, 0x8B, 0x1C, 0x25, 0x30, 0x00, 0x00, 0x00]),
        "G-WB-TRACE: missing TEB coin gs:[0x30]"
    );
    assert!(
        !pic.windows(2).any(|w| w == [0x0F, 0x31]),
        "G-WB-TRACE: RDTSC is forbidden as the coin"
    );
    assert!(
        !xenolith_vm::has_guest_dispatch_tetrad(pic),
        "G-WB-TRACE: no l_gloop"
    );
    let dir = std::env::temp_dir();
    let path = dir.join(format!("xl-licensediv-{}.dll", std::process::id()));
    std::fs::write(&path, &packed.image).expect("write");
    let want = xenolith_vm::license_toy_oracle(3, 4) as i32;
    let (eax, hash, steps) = unsafe {
        common::load_and_call_named_traced(
            &path,
            b"check_license\0",
            3,
            4,
            pe.size_of_image as usize,
        )
    };
    let _ = std::fs::remove_file(&path);
    assert_eq!(eax, Some(want), "G-WB-TRACE eax");
    assert!(
        steps > 8,
        "G-WB-TRACE: trap-flag captured too few RIPs ({steps})"
    );
    assert_ne!(hash, 0, "G-WB-TRACE: empty stream hash");
    eprintln!("LICENSEDIV OK eax={want} stream_hash={hash:#x} steps={steps}");
}
