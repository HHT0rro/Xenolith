//! TASK-037: the EnvelopeV2 wire format must fail closed on arbitrary
//! bytes — field truncation, length overflow, and version mismatch are
//! rejected before any protected code runs. Both decoders (protocol core
//! and loader wrapper) share this contract.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = xenolith_protocol::parse(data);
    let _ = xenolith_loader::parse_envelope(data);
});
