//! Test-only load host for the Xenolith compatibility harness (scripts/compat2).
//!
//! Usage: xl-loadhost <dll-path> [export-name ...]
//!
//! Loads the DLL with LoadLibraryW(LOAD_WITH_ALTERED_SEARCH_PATH), resolves
//! each named export with GetProcAddress, prints one JSON line, frees the
//! library, exits. NEVER calls any export. See Cargo.toml for the contract.

#[cfg(windows)]
mod host {
    use std::ffi::OsStr;
    use std::io::Write;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr;

    type HModule = *mut core::ffi::c_void;

    #[repr(C)]
    #[allow(non_snake_case)]
    struct MODULEENTRY32W {
        dwSize: u32,
        th32ModuleID: u32,
        th32ProcessID: u32,
        GlblcntUsage: u32,
        ProccntUsage: u32,
        modBaseAddr: *mut core::ffi::c_void,
        modBaseSize: u32,
        hModule: HModule,
        szModule: [u16; 256],
        szExePath: [u16; 260],
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn LoadLibraryW(lpFileName: *const u16, dwFlags: u32) -> HModule;
        fn GetProcAddress(hModule: HModule, lpProcName: *const u8) -> *mut core::ffi::c_void;
        fn FreeLibrary(hLibModule: HModule) -> i32;
        fn GetLastError() -> u32;
        fn CreateToolhelp32Snapshot(dwFlags: u32, th32ProcessID: u32) -> *mut core::ffi::c_void;
        fn Module32FirstW(hSnapshot: *mut core::ffi::c_void, lpme: *mut MODULEENTRY32W) -> i32;
        fn Module32NextW(hSnapshot: *mut core::ffi::c_void, lpme: *mut MODULEENTRY32W) -> i32;
        fn CloseHandle(hObject: *mut core::ffi::c_void) -> i32;
    }

    const LOAD_WITH_ALTERED_SEARCH_PATH: u32 = 0x0000_0008;
    const TH32CS_SNAPMODULE: u32 = 0x0000_0008;

    fn json_escape(s: &str) -> String {
        let mut out = String::with_capacity(s.len() + 2);
        for c in s.chars() {
            match c {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
                c => out.push(c),
            }
        }
        out
    }

    fn emit(line: &str) {
        // LineWriter flushes on '\n'; explicit flush so std::process::exit
        // (which skips destructors) can never swallow the JSON.
        println!("{line}");
        let _ = std::io::stdout().flush();
    }

    // Count modules loaded in THIS process right now (toolhelp snapshot).
    fn count_modules() -> i64 {
        unsafe {
            let snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0);
            if snap.is_null() {
                return -1;
            }
            let mut me = MODULEENTRY32W {
                dwSize: std::mem::size_of::<MODULEENTRY32W>() as u32,
                th32ModuleID: 0,
                th32ProcessID: 0,
                GlblcntUsage: 0,
                ProccntUsage: 0,
                modBaseAddr: ptr::null_mut(),
                modBaseSize: 0,
                hModule: ptr::null_mut(),
                szModule: [0; 256],
                szExePath: [0; 260],
            };
            let mut n: i64 = 0;
            if Module32FirstW(snap, &mut me) != 0 {
                loop {
                    n += 1;
                    if Module32NextW(snap, &mut me) == 0 {
                        break;
                    }
                }
            }
            CloseHandle(snap);
            n
        }
    }

    pub fn run() -> i32 {
        let args: Vec<String> = std::env::args().skip(1).collect();
        if args.is_empty() {
            eprintln!("usage: xl-loadhost <dll-path> [export-name ...]");
            return 2;
        }
        let dll: Vec<u16> = OsStr::new(&args[0]).encode_wide().chain(Some(0)).collect();

        let handle = unsafe { LoadLibraryW(dll.as_ptr(), LOAD_WITH_ALTERED_SEARCH_PATH) };
        if handle.is_null() {
            // capture immediately: formatting/allocation may clear last error
            let err = unsafe { GetLastError() };
            emit(&format!("{{\"loaded\":false,\"lastWinError\":{err}}}"));
            return 3;
        }

        let mut exports = String::from("{");
        for (i, name) in args.iter().skip(1).enumerate() {
            if i > 0 {
                exports.push(',');
            }
            let cname: Vec<u8> = name.as_bytes().iter().copied().chain(Some(0)).collect();
            let proc = unsafe { GetProcAddress(handle, cname.as_ptr()) };
            if proc.is_null() {
                exports.push_str(&format!("\"{}\":null", json_escape(name)));
            } else {
                exports.push_str(&format!("\"{}\":{}", json_escape(name), proc as usize));
            }
        }
        exports.push('}');

        let modules = count_modules();
        emit(&format!(
            "{{\"loaded\":true,\"exports\":{},\"modules\":{}}}",
            exports, modules
        ));

        unsafe { FreeLibrary(handle) };
        0
    }
}

#[cfg(windows)]
fn main() {
    std::process::exit(host::run());
}

#[cfg(not(windows))]
fn main() {
    eprintln!("xl-loadhost is Windows-only (LoadLibraryW host for the compat harness)");
    std::process::exit(2);
}
