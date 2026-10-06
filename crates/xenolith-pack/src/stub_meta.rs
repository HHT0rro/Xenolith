//! Shared stub meta-block and host-context layout (x86-64 and aarch64).
//!
//! The 80-byte meta block closes every emitted stub (`[code][core][meta]`).
//! Both architecture emitters and the pack layer agree on these offsets —
//! field drift between stubs is a silent-corruption bug class, hence one
//! table for all of them.
//!
//! ```text
//! meta[ 0.. 4]  META_PAYLOAD_RVA     envelope VA (load-relative, u32)
//! meta[ 4.. 8]  META_ENVELOPE_LEN    envelope byte length (u32)
//! meta[ 8..12]  META_ORIGINAL_ENTRY  forwarded init target RVA (u32)
//! meta[12..16]  META_UNPACKED        idempotence gate (u32, 0→1)
//! meta[16..48]  META_MEASUREMENT     32-byte image measurement
//! meta[48..64]  opcode seed copy     16 bytes
//! meta[63]      debug gate byte
//! meta[64..68]  META_TLS_CALLBACK    PE only (first TLS callback RVA)
//! meta[68..72]  META_SELF_RVA        this meta's load-relative VA (u32)
//! meta[72..76]  META_PAGE_SIZE       seal chunk/page granularity (u32)
//! meta[76..80]  reserved (zero)
//! ```

/// Meta block appended after the code (also embedded as a label below).
pub const STUB_META_LEN: usize = 80;
pub const META_PAYLOAD_RVA: usize = 0;
pub const META_ENVELOPE_LEN: usize = 4;
pub const META_ORIGINAL_ENTRY: usize = 8;
pub const META_UNPACKED: usize = 12;
pub const META_MEASUREMENT: usize = 16;
/// Original first TLS callback RVA (PE path); 0 if the image has none.
pub const META_TLS_CALLBACK: usize = 64;
/// Pack-time offset of the stub's own load-relative VA inside meta. Stubs
/// recover the image base from it (`base = meta_runtime_va - self_rva`).
pub const META_SELF_RVA: usize = 68;
/// Seal-chunk granularity the vprotect shim aligns to. 4096 on 4-KiB-page
/// x86-64 images, up to 16384 on 16-KiB-page Android devices. Written by
/// the packer; every shim reads it instead of hardcoding 4096.
pub const META_PAGE_SIZE: usize = 72;
/// Load-relative VA of the relocated program-header table (start of the
/// appended PT_LOAD). The stubs copy it into CTX_PHDR_VA so the core walks
/// phdrs at a mapped address instead of the file-offset e_phoff.
pub const META_TABLE_RVA: usize = 76;

/// Offsets inside the Win64-layout `XlHostCtx` built by both stubs (the
/// freestanding core is host-compiled with Win64 field semantics; on aarch64
/// the same byte layout is produced in AAPCS64 registers).
pub const CTX_IMAGE_BASE: usize = 0;
pub const CTX_ENVELOPE: usize = 8;
pub const CTX_ENVELOPE_LEN: usize = 16;
pub const CTX_ORIG_ENTRY: usize = 20;
pub const CTX_GATE: usize = 24;
pub const CTX_MEASUREMENT: usize = 32;
pub const CTX_LOAD_LIBRARY: usize = 64;
pub const CTX_GET_PROC: usize = 72;
pub const CTX_VPROTECT: usize = 80;
/// ELF only: load-relative phdr-table VA for `xl_final_protect` (see
/// META_TABLE_RVA). PE stubs leave it zero.
pub const CTX_PHDR_VA: usize = 120;
/// Android/bionic anti-debug probe bitmap (plan WS-A §2.2.3). Pack-time
/// constant produced by `xenolith_guard::android_probe_mask`; the aarch64
/// stub encodes it as a `movz w9, #mask` machine-code constant and the
/// freestanding core consumes it as `XL_PROBE_BIT_*` (platform-local bits,
/// decoupled from the global probe ids). The x86-64 ELF and PE stubs write
/// an explicit ZERO (no probes on those paths — the core must never read
/// stack garbage here). The ctx grows to 136 bytes.
pub const CTX_PROBE_MASK: usize = 128;
/// Byte size of `XlHostCtx` as the stubs build it (grew from 128 to 136
/// with CTX_PROBE_MASK). Stubs reserve at least this much frame below the
/// saved-register slots — golden frame-size assertions lock this.
pub const CTX_LEN: usize = 136;
