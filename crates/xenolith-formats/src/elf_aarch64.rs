//! AArch64 (EM_AARCH64 / ELF64 LE) relocation constants.
//!
//! Every value below was MEASURED against the pinned Android NDK r27c
//! toolchain (design R-9: constants are fixed against the toolchain, not
//! recalled): `aarch64-linux-android24-clang -c` on probe assemblies and
//! linked `.so`s, read back with `llvm-readelf -rW`:
//!
//! ```text
//! ET_REL:   ADR_PREL_LO21=274(0x112)  ADR_PREL_PG_HI21=275(0x113)
//!           ADD_ABS_LO12_NC=277(0x115) LDST8=278(0x116)  TSTBR14=279(0x117)
//!           CONDBR19=280(0x118)        JUMP26=282(0x11a) CALL26=283(0x11b)
//!           LDST16=284 LDST32=285 LDST64=286  LDST128=299(0x12b)
//! dynamic:  JUMP_SLOT=1026(0x402)      RELATIVE=1027(0x403)
//!           TLS_TPREL64=1030(0x406)    TLSDESC=1031(0x407)
//! TLSLE:    ADD_TPREL_HI12=549(0x225)  ADD_TPREL_LO12_NC=551(0x227)
//! ```
//! GLOB_DAT(1025), TLS_DTPMOD64(1028), TLS_DTPREL64(1029), IRELATIVE(1032)
//! complete the standard AAELF64 dynamic block (1025..1032 contiguous;
//! neighbors measured as above).

// ---- dynamic relocations (inputs and packed images) ----
pub const R_AARCH64_ABS64: u32 = 257;
pub const R_AARCH64_GLOB_DAT: u32 = 1025;
pub const R_AARCH64_JUMP_SLOT: u32 = 1026;
pub const R_AARCH64_RELATIVE: u32 = 1027;
pub const R_AARCH64_TLS_DTPMOD64: u32 = 1028;
pub const R_AARCH64_TLS_DTPREL64: u32 = 1029;
pub const R_AARCH64_TLS_TPREL64: u32 = 1030;
pub const R_AARCH64_TLSDESC: u32 = 1031;
pub const R_AARCH64_IRELATIVE: u32 = 1032;

/// Local-exec TLS offsets embedded in sealed RX text (the TPOFF32
/// counterpart on arm64): the linker patches the instruction immediate at
/// link time and the packer must not restore over it.
pub const R_AARCH64_TLSLE_ADD_TPREL_HI12: u32 = 549;
pub const R_AARCH64_TLSLE_ADD_TPREL_LO12: u32 = 550;
pub const R_AARCH64_TLSLE_ADD_TPREL_LO12_NC: u32 = 551;

// ---- ET_REL relocations (whitelist of the aarch64 core extraction) ----
pub const R_AARCH64_ADR_PREL_LO21: u32 = 274;
pub const R_AARCH64_ADR_PREL_PG_HI21: u32 = 275;
pub const R_AARCH64_ADD_ABS_LO12_NC: u32 = 277;
pub const R_AARCH64_LDST8_ABS_LO12_NC: u32 = 278;
pub const R_AARCH64_TSTBR14: u32 = 279;
pub const R_AARCH64_CONDBR19: u32 = 280;
pub const R_AARCH64_JUMP26: u32 = 282;
pub const R_AARCH64_CALL26: u32 = 283;
pub const R_AARCH64_LDST16_ABS_LO12_NC: u32 = 284;
pub const R_AARCH64_LDST32_ABS_LO12_NC: u32 = 285;
pub const R_AARCH64_LDST64_ABS_LO12_NC: u32 = 286;
pub const R_AARCH64_LDST128_ABS_LO12_NC: u32 = 299;
