//! TASK-037: arbitrary input must be rejected, never panic, across every
//! ELF parsing surface the packer touches (program headers, dynamic tags,
//! relocations, IFUNC/TLS/symbol-version census, symtab stats, packed
//! bootstrap detection).

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(elf) = xenolith_formats::elf::parse(data) {
        if let Ok(phdrs) = xenolith_formats::elf::program_headers(data, &elf) {
            for ph in &phdrs {
                if let Ok(off) = xenolith_formats::elf::vaddr_file_offset(data, &elf, ph.p_vaddr)
                {
                    let _ = off;
                }
            }
        }
        let _ = xenolith_formats::elf::rx_load_ranges(data, &elf);
        let _ = xenolith_formats::elf::max_load_vaddr_end(data, &elf);
        let _ = xenolith_formats::elf::dt_init_slot(data, &elf);
        let _ = xenolith_formats::elf::ifunc_resolvers(data, &elf);
        let _ = xenolith_formats::elf::ifunc_symbol_values(data, &elf);
        let _ = xenolith_formats::elf::symbol_versions(data, &elf);
        let _ = xenolith_formats::elf::tls_reloc_census(data, &elf);
        let _ = xenolith_formats::elf::symtab_functions(data, &elf);
        let _ = xenolith_formats::elf::packed_bootstrap_target(data, &elf);
        let _ = xenolith_pack::stats::classify_elf(data, &elf);
    }
});
