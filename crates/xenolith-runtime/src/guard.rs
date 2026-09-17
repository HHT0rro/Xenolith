use crate::windows::{
    Apis, ProcessDebugObjectHandle, ProcessDebugPort, ProcessInstrumentationCallback,
    ThreadHideFromDebugger,
};
use core::ffi::c_void;

pub unsafe fn run(apis: &Apis, max_profile: bool) -> bool {
    let peb = crate::windows::peb();
    if peb.is_null() {
        return false;
    }
    if *peb.add(2) != 0 {
        return false;
    }
    if !max_profile {
        return true;
    }
    let process = (apis.get_current_process)();
    let thread = (apis.get_current_thread)();
    if let Some(set) = apis.nt_set_information_thread {
        let _ = set(thread, ThreadHideFromDebugger, core::ptr::null_mut(), 0);
    }
    if let Some(query) = apis.nt_query_information_process {
        let mut port: usize = 0;
        let mut ret = 0u32;
        if query(
            process,
            ProcessDebugPort,
            &mut port as *mut usize as *mut c_void,
            core::mem::size_of::<usize>() as u32,
            &mut ret,
        ) >= 0
            && port != 0
        {
            return false;
        }
        let mut obj: usize = 0;
        if query(
            process,
            ProcessDebugObjectHandle,
            &mut obj as *mut usize as *mut c_void,
            core::mem::size_of::<usize>() as u32,
            &mut ret,
        ) >= 0
            && obj != 0
        {
            return false;
        }
        let mut cb: usize = 0;
        let _ = query(
            process,
            ProcessInstrumentationCallback,
            &mut cb as *mut usize as *mut c_void,
            core::mem::size_of::<usize>() as u32,
            &mut ret,
        );
    }
    true
}
