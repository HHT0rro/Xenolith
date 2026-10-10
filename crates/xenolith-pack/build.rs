use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=../xenolith-runtime/core/xl_core.c");
    println!("cargo:rerun-if-env-changed=ANDROID_NDK_HOME");
    println!("cargo:rerun-if-env-changed=ANDROID_NDK_ROOT");
    println!("cargo:rerun-if-env-changed=ANDROID_HOME");
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

    // AArch64 core for Android packing: cross-compiled with the NDK clang.
    // A missing NDK must NOT fail the build (PE/x86-64 packing is unaffected);
    // the placeholder plus the XL_AARCH64_CORE flag make arm64 packing fail
    // closed with a named error instead, while include_bytes! always has a
    // file to embed (the object is baked into the binary — never read off
    // the build machine's disk at runtime, which is how v1.1.0 shipped a
    // CLI that could not pack anything off the CI runner).
    let aarch64_obj = out.join("xl_core_aarch64.o");
    match compile_aarch64_core(&src, &out) {
        Ok(path) => {
            assert_eq!(path, aarch64_obj, "aarch64 core must land at the staged path");
            println!("cargo:rustc-env=XL_AARCH64_CORE=1");
        }
        Err(reason) => {
            std::fs::write(&aarch64_obj, [0u8; 8]).expect("write aarch64 placeholder");
            println!("cargo:rustc-env=XL_AARCH64_CORE=0");
            eprintln!("xenolith-pack: aarch64 core not built: {reason}");
        }
    }
}

/// Locate an NDK (ANDROID_NDK_HOME / ANDROID_NDK_ROOT / ANDROID_HOME/ndk/*)
/// and cross-compile xl_core.c for aarch64-linux-android.
fn compile_aarch64_core(src: &PathBuf, out: &PathBuf) -> Result<PathBuf, String> {
    let ndk = find_ndk()?;
    let bin = ndk.join("toolchains/llvm/prebuilt");
    let prebuilt = std::fs::read_dir(&bin)
        .map_err(|e| format!("NDK at {} has no prebuilt toolchain: {e}", ndk.display()))?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .find(|p| p.is_dir())
        .ok_or_else(|| format!("NDK at {} has no prebuilt/<tag> directory", ndk.display()))?;
    let obj = out.join("xl_core_aarch64.o");

    // Prefer the API-level wrapper (sets target + sysroot); fall back to the
    // bare clang with an explicit --target for NDK layouts without wrappers.
    let wrapper = prebuilt.join("bin/aarch64-linux-android24-clang");
    let wrapper_cmd = prebuilt.join("bin/aarch64-linux-android24-clang.cmd");
    let mut cmd;
    if wrapper_cmd.exists() {
        cmd = std::process::Command::new(&wrapper_cmd);
    } else if wrapper.exists() {
        cmd = std::process::Command::new(&wrapper);
    } else {
        let clang = prebuilt.join("bin/clang.exe");
        let clang = if clang.exists() {
            clang
        } else {
            prebuilt.join("bin/clang")
        };
        cmd = std::process::Command::new(&clang);
        cmd.arg("--target=aarch64-linux-android24");
    }
    cmd.arg("-O1")
        .arg("-ffreestanding")
        .arg("-fno-stack-protector")
        .arg("-fno-asynchronous-unwind-tables")
        // Same flat-blob PIC contract as the x86-64 core: every intra-object
        // reference must be PC-relative, never absolute.
        .arg("-fpie")
        // Pin branch protection OFF: the stub BLs the core directly (no BTI
        // needed at its entry) and NDK clang versions drift on defaults.
        .arg("-mbranch-protection=none")
        // NDK r21+ defaults to outline atomics, which emit calls into
        // compiler-rt (`__aarch64_cas*_acq` etc.) — external references the
        // injected flat blob cannot resolve. Keep the ldaxr/stlxr inline
        // forms (the C already has a same-behavior inline path).
        .arg("-mno-outline-atomics")
        .arg("-c")
        .arg("-o")
        .arg(&obj)
        .arg(src);
    let status = cmd
        .status()
        .map_err(|e| format!("spawn NDK clang {:?}: {e}", cmd.get_program()))?;
    if !status.success() || !obj.exists() {
        return Err(format!("NDK clang exited {status}"));
    }
    Ok(obj)
}

fn find_ndk() -> Result<PathBuf, String> {
    for var in ["ANDROID_NDK_HOME", "ANDROID_NDK_ROOT"] {
        if let Ok(v) = env::var(var) {
            if !v.is_empty() {
                let p = PathBuf::from(&v);
                if p.join("toolchains").is_dir() {
                    return Ok(p);
                }
                return Err(format!("{var}={v} has no toolchains/ directory"));
            }
        }
    }
    if let Ok(home) = env::var("ANDROID_HOME") {
        if !home.is_empty() {
            let ndkroot = PathBuf::from(&home).join("ndk");
            if let Some(v) = newest_dir(&ndkroot) {
                return Ok(v);
            }
            return Err(format!("ANDROID_HOME={home} has no ndk/<version>"));
        }
    }
    Err("NDK not found (set ANDROID_NDK_HOME/ANDROID_NDK_ROOT or ANDROID_HOME)".into())
}

/// Highest-versioned `ndk/<dir>` entry (rNN sort falls back to name sort).
fn newest_dir(root: &PathBuf) -> Option<PathBuf> {
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(root)
        .ok()?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.is_dir() && p.join("toolchains").is_dir())
        .collect();
    dirs.sort();
    dirs.pop()
}
