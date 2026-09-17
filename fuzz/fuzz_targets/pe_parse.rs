//! TASK-037: arbitrary input must be rejected, never panic, across every
//! PE parsing surface the packer touches (headers, exports, imports,
//! relocs, TLS callbacks, import-name scrub locations).

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(pe) = xenolith_formats::Pe64::parse(data) {
        let _ = pe.exports(data);
        let _ = pe.imports(data);
        let _ = pe.relocs(data);
        let _ = pe.tls_first_callback(data);
        let _ = pe.import_name_locations(data);
        let _ = pe.delay_import_present();
        for s in &pe.sections {
            let _ = pe.file_offset_of(s.virtual_address);
        }
    }
});
