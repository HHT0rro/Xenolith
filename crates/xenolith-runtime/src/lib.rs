//! Unused-by-pack HKDF/XChaCha Windows x64 experiment.
//!
//! `xenolith-pack::pack()` does **not** compile, inject, or jump to this
//! crate. The product runtime is the handwritten PIC stub. Keep this crate
//! excluded from workspace tests (`--exclude xenolith-runtime`) because
//! unifying `std` into its `no_std` `#[panic_handler]` build is E0152.
//!
//! Historical intent (not current product behavior):
//! - resolve kernel32/ntdll through the PEB
//! - reconstruct a page key via HKDF
//! - decrypt with XChaCha
//! - fill IAT slots from hashed names
//! - restore stolen entry bytes
//!
//! Do not report those capabilities on a `pack()` artifact.

// Win32 FFI keeps its canonical spelling (SIZE_T, ProcessDebugPort, ...) and
// the experiment surface stays complete even where the packer does not call
// it yet; this crate is excluded from every gate (see the module doc above).
#![allow(nonstandard_style)]
#![allow(dead_code)]
#![allow(clippy::missing_safety_doc)]
#![cfg(windows)]
#![cfg_attr(not(test), no_std)]

mod bootstrap;
mod crypto;
mod guard;
mod pe;
mod windows;

pub use bootstrap::{xl_tls_callback, xl_unpack_entry};

#[cfg(not(test))]
#[no_mangle]
pub unsafe extern "system" fn DllMain(
    module: *mut u8,
    reason: u32,
    reserved: *mut core::ffi::c_void,
) -> i32 {
    xl_unpack_entry(module, reason, reserved)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[cfg(not(test))]
#[no_mangle]
pub unsafe extern "C" fn __chkstk() {}

#[cfg(test)]
mod tests {
    #[test]
    fn crate_links() {}
}

#[no_mangle]
pub unsafe extern "C" fn memcpy(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    core::ptr::copy_nonoverlapping(src, dst, n);
    dst
}

#[no_mangle]
pub unsafe extern "C" fn memset(dst: *mut u8, val: i32, n: usize) -> *mut u8 {
    core::ptr::write_bytes(dst, val as u8, n);
    dst
}

#[no_mangle]
pub unsafe extern "C" fn memcmp(a: *const u8, b: *const u8, n: usize) -> i32 {
    for i in 0..n {
        let d = *a.add(i) as i32 - *b.add(i) as i32;
        if d != 0 {
            return d;
        }
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn memmove(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    core::ptr::copy(src, dst, n);
    dst
}

#[no_mangle]
pub unsafe extern "C" fn strlen(s: *const u8) -> usize {
    let mut n = 0usize;
    while *s.add(n) != 0 {
        n += 1;
    }
    n
}
