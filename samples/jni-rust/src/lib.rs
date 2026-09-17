//! rustc cdylib JNI_OnLoad gate (JavaShroud adaptation).
//!
//! Unlike the C `jni-host` sample (constant return), this entry point exercises
//! a real `JavaVM::GetEnv` path: `JNI_OK` + non-null env → `JNI_VERSION_1_8`,
//! otherwise `JNI_ERR`. Callers must pass a fake `JavaVM*` after `LoadLibrary`
//! — never `JNI_OnLoad(NULL, NULL)`.

use std::os::raw::c_void;

pub const JNI_OK: i32 = 0;
pub const JNI_ERR: i32 = -1;
pub const JNI_VERSION_1_8: i32 = 0x0001_0008;

#[repr(C)]
pub struct JavaVM {
    pub functions: *const JNIInvokeInterface,
}

#[repr(C)]
pub struct JNIInvokeInterface {
    pub reserved0: *mut c_void,
    pub reserved1: *mut c_void,
    pub reserved2: *mut c_void,
    pub destroy_java_vm: Option<unsafe extern "system" fn(*mut JavaVM) -> i32>,
    pub attach_current_thread:
        Option<unsafe extern "system" fn(*mut JavaVM, *mut *mut c_void, *mut c_void) -> i32>,
    pub detach_current_thread: Option<unsafe extern "system" fn(*mut JavaVM) -> i32>,
    pub get_env: Option<unsafe extern "system" fn(*mut JavaVM, *mut *mut c_void, i32) -> i32>,
}

/// JVM ABI entry: stay native under the packer; resolve by exact export name.
#[no_mangle]
pub unsafe extern "system" fn JNI_OnLoad(vm: *mut JavaVM, _reserved: *mut c_void) -> i32 {
    if vm.is_null() {
        return JNI_ERR;
    }
    let funcs = (*vm).functions;
    if funcs.is_null() {
        return JNI_ERR;
    }
    let Some(get_env) = (*funcs).get_env else {
        return JNI_ERR;
    };
    let mut env: *mut c_void = std::ptr::null_mut();
    let rc = get_env(vm, &mut env, JNI_VERSION_1_8);
    if rc == JNI_OK && !env.is_null() {
        JNI_VERSION_1_8
    } else {
        JNI_ERR
    }
}
