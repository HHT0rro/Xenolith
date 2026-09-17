mod common;

#[cfg(windows)]
#[test]
fn packed_dll_tamper_flip_fails_closed() {
    let out = common::spawn_exact_child("loader_child_tamper_flip");
    common::assert_child_ok(&out, "TAMPER OK", "tamper");
}

#[cfg(windows)]
#[test]
fn loader_child_tamper_flip() {
    if std::env::var("XL_LOADER_CHILD").as_deref() != Ok("1") {
        return;
    }
    use xenolith_formats::Pe64;
    use xenolith_loader::Profile;
    use xenolith_pack::{pack, PackRequest};

    let dll = common::required_release_sample("hello_dll.dll");
    let packed = pack(PackRequest {
        input: &dll,
        profile: Profile::Standard,
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
    let dir = std::env::temp_dir();
    let pe = Pe64::parse(&packed.image).unwrap();
    let payload = pe.sections.last().expect("payload section");
    let env_off = payload.raw_ptr as usize;
    let env = &packed.image[env_off..];
    assert_eq!(&env[0..4], b"XLV2");
    let parsed = xenolith_protocol::parse(env).expect("v2");
    let first = parsed.regions.first().expect("region");
    let mut cur = 16 + 96 + 16 + 16 + 8;
    let stolen_len = u16::from_le_bytes(env[cur..cur + 2].try_into().unwrap()) as usize;
    cur += 2 + stolen_len;
    let prog_len = u32::from_le_bytes(env[cur..cur + 4].try_into().unwrap()) as usize;
    cur += 4 + prog_len + 4; // program + policy
    cur += 4 + 4 + 4 + 12; // index rva len nonce
    let ct_len = u32::from_le_bytes(env[cur..cur + 4].try_into().unwrap()) as usize;
    cur += 4;
    let ct_off = env_off + cur;
    let tag_off = env_off + cur + ct_len;
    let mba_off = env_off + 16;
    let _ = first;
    let cases = [
        ("ciphertext", ct_off),
        ("mba", mba_off + 8),
        ("tag", tag_off),
    ];
    for (label, off) in cases {
        let mut image = packed.image.clone();
        image[off] ^= 0x40;
        let path = dir.join(format!("xl-tamper-{label}-{}.dll", std::process::id()));
        std::fs::write(&path, &image).expect("write tampered");
        let result = unsafe {
            common::load_and_call(
                &path,
                false,
                packed.packed.original_entry_rva,
                None,
                None,
                None,
                None,
            )
        };
        let _ = std::fs::remove_file(&path);
        eprintln!("TAMPER {label} result={result:?}");
        assert_eq!(result, None, "tampered {label} image must not load");
    }
    eprintln!("TAMPER OK");
}
