//! Tiny cdylib used as a packer sample.

#[no_mangle]
pub extern "C" fn hello_add(a: i32, b: i32) -> i32 {
    a.wrapping_add(b)
}
