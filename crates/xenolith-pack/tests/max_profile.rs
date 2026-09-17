mod common;

#[cfg(windows)]
#[test]
fn packed_dll_max_profile_hello_add() {
    let out = common::spawn_exact_child("loader_child_max_profile");
    common::assert_child_ok(&out, "MAX OK", "max-profile");
}

#[cfg(windows)]
#[test]
fn loader_child_max_profile() {
    if std::env::var("XL_LOADER_CHILD").as_deref() != Ok("1") {
        return;
    }
    use xenolith_formats::Pe64;
    use xenolith_loader::Profile;
    use xenolith_pack::{pack, PackRequest};

    let dll = common::required_release_sample("hello_dll.dll");
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
    let dir = std::env::temp_dir();
    let path = dir.join(format!("xl-max-{}.dll", std::process::id()));
    std::fs::write(&path, &packed.image).expect("write");
    let expect = common::entry_bytes(&dll);
    let orig_pe = Pe64::parse(&dll).unwrap();
    let keep: std::collections::HashSet<u32> = {
        let mut k = std::collections::HashSet::new();
        k.insert(packed.packed.original_entry_rva & !0xfff);
        for (_name, rva) in &packed.packed.exports {
            k.insert(*rva & !0xfff);
        }
        k
    };
    let victim = packed
        .packed
        .pages
        .iter()
        .rev()
        .find(|p| {
            !keep.contains(&(p.original_rva & !0xfff))
                && p.original_len >= 16
        });
    // Small toolchain-dependent samples can have every executable page in
    // the entry/export keep set. The C2 dump probe then has no legal victim;
    // record that explicitly and still exercise the max-profile load + call.
    let (dump_rva, dump16) = match victim {
        Some(victim) => {
            let orig_off = orig_pe.file_offset_of(victim.original_rva).unwrap();
            let orig16 = dll[orig_off..orig_off + 16].to_vec();
            (Some(victim.original_rva), Some(orig16))
        }
        None => {
            eprintln!("C2 VICTIM SKIP: no non-keep executable page in sample");
            (None, None)
        }
    };
    let result = unsafe {
        common::load_and_call(
            &path,
            true,
            packed.packed.original_entry_rva,
            expect,
            None,
            dump_rva,
            dump16.as_deref().and_then(|b| b.try_into().ok()),
        )
    };
    let _ = std::fs::remove_file(&path);
    assert_eq!(result, Some(7), "max-profile hello_add");
    if let Some(orig16) = dump16 {
        eprintln!("C2_EXPECT {orig16:02x?}");
    }
    eprintln!("MAX OK");
}
