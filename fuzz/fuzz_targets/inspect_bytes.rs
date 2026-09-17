//! TASK-037: `inspect_bytes` is the first thing the CLI runs on any input;
//! it must classify and report (or reject) arbitrary bytes without
//! panicking, for PE and ELF alike.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = xenolith_pack::inspect_bytes(data);
});
