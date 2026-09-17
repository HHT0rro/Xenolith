use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=../xenolith-runtime/core/xl_core.c");
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let src = manifest.join("../xenolith-runtime/core/xl_core.c");
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    let obj = out.join("xl_core.obj");

    let mut build = cc::Build::new();
    build.file(&src);
    // The runtime is injected verbatim into every artifact. Compile for
    // speed/size rather than debugability; -O0 doubled the fixed footprint
    // and pushed small binaries over the release size budget.
    build.opt_level(1);
    build.warnings(false);
    build.cargo_metadata(false);
    if build.get_compiler().is_like_msvc() {
        build.flag("/GS-");
        build.flag("/Zl");
        build.flag("/Gy-");
        build.flag("/Gw-");
        build.flag("/Oi-");
        build.flag("/Gs999999");
        build.flag("/c");
        let compiler = build.get_compiler();
        let mut cmd = compiler.to_command();
        cmd.arg(src.as_os_str());
        cmd.arg(format!("/Fo{}", obj.display()));
        use std::process::Stdio;
        let out = cmd.stdout(Stdio::piped()).stderr(Stdio::piped()).output().expect("spawn cl for xl_core");
        eprintln!("cl stdout: {} stderr: {}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
        let status = out.status;
        if !status.success() || !obj.exists() {
            panic!("G1: cl failed to compile xl_core.c: {status}");
        }
    } else {
        build.flag("-ffreestanding");
        build.flag("-fno-stack-protector");
        build.flag("-fno-asynchronous-unwind-tables");
        /* PIE codegen keeps every intra-object reference RIP-relative
         * (R_X86_64_PC32/PLT32); non-PIE would emit absolute R_X86_64_32/
         * 32S, which cannot resolve in a flat blob copied to an ASLR
         * address. Statics don't go through the GOT, so no extra reloc
         * forms appear. */
        build.flag("-fpie");
        build.flag("-c");
        let compiler = build.get_compiler();
        let mut cmd = compiler.to_command();
        cmd.arg("-o");
        cmd.arg(&obj);
        cmd.arg(&src);
        let status = cmd.status().expect("spawn cc for xl_core");
        if !status.success() || !obj.exists() {
            panic!("G1: cc failed to compile xl_core.c: {status}");
        }
    }
    println!("cargo:rustc-env=XL_CORE_OBJ_PATH={}", obj.display());
}
