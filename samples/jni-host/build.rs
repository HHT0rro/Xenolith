//! Compile `jni_host.c` as a real Windows DLL (not a rustc cdylib).
//! The JNI host contract under test is a C-ABI DLL: `JNI_OnLoad` resolves by
//! exact name, `.jsms` / `.jsmk` / `.jsmd` measurement slots survive packing
//! untouched, and one pure 2xu32 leaf is the virtualization target. rustc
//! wrapping would add a second prologue in front of the C bodies; C is the
//! truth. See `samples/jni-rust` for the GetEnv-aware rustc gate.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=src/jni_host.c");
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let src = manifest.join("src/jni_host.c");
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let profile = env::var("PROFILE").unwrap_or_else(|_| "debug".into());
    let target_dir = workspace_target_dir(&out_dir).join(&profile);
    let _ = fs::create_dir_all(&target_dir);
    let dll = target_dir.join("jni_host.dll");

    let build = cc::Build::new();
    let compiler = build.get_compiler();
    let mut cmd = compiler.to_command();
    if compiler.is_like_msvc() {
        cmd.arg("/nologo");
        cmd.arg("/LD");
        cmd.arg("/O1");
        cmd.arg("/TC");
        cmd.arg(src.as_os_str());
        cmd.arg(format!("/Fe:{}", dll.display()));
        cmd.arg(format!("/Fo:{}", out_dir.join("jni_host.obj").display()));
    } else {
        cmd.arg("-shared");
        cmd.arg("-O1");
        cmd.arg("-o");
        cmd.arg(&dll);
        cmd.arg(&src);
    }
    let status = cmd.status().expect("spawn C compiler for jni_host");
    if !status.success() {
        panic!("jni_host C compile failed: {status}");
    }
    println!("cargo:warning=jni_host.dll -> {}", dll.display());
}

fn workspace_target_dir(out_dir: &Path) -> PathBuf {
    // OUT_DIR = .../target/<triple?>/<profile>/build/<pkg>/out
    let mut p = out_dir.to_path_buf();
    for _ in 0..5 {
        if p.file_name().and_then(|s| s.to_str()) == Some("build") {
            if let Some(parent) = p.parent() {
                if parent.file_name().and_then(|s| s.to_str()) == Some("debug")
                    || parent.file_name().and_then(|s| s.to_str()) == Some("release")
                {
                    return parent.parent().unwrap().to_path_buf();
                }
                return parent.to_path_buf();
            }
        }
        if !p.pop() {
            break;
        }
    }
    PathBuf::from("target")
}
