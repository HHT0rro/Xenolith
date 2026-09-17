fn main() {
    println!("cargo:rerun-if-changed=src/eh.cpp");
    let mut b = cc::Build::new();
    b.file("src/eh.cpp")
        .cpp(true)
        .opt_level(1)
        .warnings(false);
    if b.get_compiler().is_like_msvc() {
        b.flag("/EHsc").flag("/std:c++14");
    } else {
        b.flag("-fexceptions");
    }
    b.compile("eh_matrix");
    // Without whole-archive the linker drops the unreferenced C++ TU and
    // the __declspec(dllexport) functions never materialize.
    if b.get_compiler().is_like_msvc() {
        // lib.rs references the C++ symbols (xl_eh_keepalive), so the plain
        // static link keeps the TU and its dllexports.
    }
}
