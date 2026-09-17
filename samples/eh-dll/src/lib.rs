//! C++ exception / setjmp / varargs / struct-return matrix sample.
//! The C++ TU in src/eh.cpp provides the exports; these declarations keep
//! the linker from discarding it (no whole-archive tricks needed).

#[allow(improper_ctypes)]
extern "C" {
    fn eh_throw_catch(x: i32) -> i32;
    fn eh_unwind_across(depth: i32) -> i32;
    fn sj_probe(x: i32) -> i32;
    fn vararg_sum(n: i32, ...) -> i32;
    fn struct_ret(x: i32) -> (i32, i32);
    fn tail_call(x: i32) -> i32;
}

/// Referenced export that forces the C++ TU into the link.
#[no_mangle]
pub extern "C" fn xl_eh_keepalive(x: i32) -> i32 {
    unsafe {
        let (a, b) = struct_ret(x);
        eh_throw_catch(x) + eh_unwind_across(1) + sj_probe(x) + vararg_sum(1, a) + tail_call(b)
    }
}
