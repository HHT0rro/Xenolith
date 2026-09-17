use clap::{Parser, Subcommand, ValueEnum};
use xenolith_loader::Profile;
use std::path::PathBuf;

pub const LONG_ABOUT: &str = "\
Xenolith is a standalone PE packer. --vm-export virtualizes selected named \
exports into per-block unique PIC (superoperators). --trace-diverge emits two \
equal paths per block (W3). That is not whole-.text virtualization and not a \
VMProtect-style shared ISA. CRT / DllMain stay native. Only wired options appear here.";

#[derive(Parser)]
#[command(
    name = "xenolith",
    version,
    about = "Standalone native PE packer",
    long_about = LONG_ABOUT
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Subcommand)]
pub enum Command {
    Pack {
        input: Option<PathBuf>,
        #[arg(short, long)]
        output: Option<PathBuf>,
        #[arg(long, value_enum, default_value_t = ProfileArg::Max)]
        profile: ProfileArg,
        #[arg(long, value_delimiter = ',')]
        vm_export: Vec<String>,
        #[arg(long)]
        json: bool,
        #[arg(long, value_name = "FILE")]
        project: Option<PathBuf>,
        /// 32 hex chars. G-POLY reproduction only. Never printed in reports.
        #[arg(long, value_name = "HEX")]
        seed_hex: Option<String>,
        /// W3: two semantically equal paths per block. Selector is TEB^heap^RSP, not RDTSC.
        #[arg(long)]
        trace_diverge: bool,
        /// Explicit function range `RVA:LEN` (hex or decimal). Repeatable. Fail-closed if unliftable.
        #[arg(long, value_name = "RVA:LEN")]
        select_rva: Vec<String>,
        /// Select a function by symbol/export name after metadata discovery.
        #[arg(long, value_delimiter = ',')]
        select_function: Vec<String>,
        /// Select every discoverable function. Without this flag discovery is
        /// never implicitly applied to the whole image.
        #[arg(long)]
        select_all: bool,
        /// Fail the pack when no function is selected, or a selected function cannot be fully transformed.
        #[arg(long)]
        strict_coverage: bool,
        /// Allow selected functions that cannot be fully transformed to stay
        /// native. Explicitly reported as mixed_native and never counted as
        /// protected. Rejected together with --strict-coverage.
        #[arg(long)]
        allow_native_fallback: bool,
        /// G5: seal non-keep code regions at bootstrap; pages decrypt on first execution fault (VEH wake).
        #[arg(long)]
        lazy_regions: bool,
        /// G5: seal import name records in the envelope (writeback mode only; TLS/Fast targets keep the loader directory and are reported as kept).
        #[arg(long)]
        protect_imports: bool,
        /// G5: refuse to pack when read-only constants keep native references (strict data protection).
        #[arg(long)]
        strict_constants: bool,
        /// Not armed (C2 off). Presence fails closed; hidden from --help.
        #[arg(long, hide = true)]
        keep_export: Vec<String>,
    },
    Inspect {
        input: PathBuf,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        exports: bool,
    },
    /// TASK-023: classify every .symtab function of an ELF against the
    /// current transform capability (transformed / mixed_native /
    /// unsupported / boundary_uncertain). Read-only reporting.
    Stats {
        input: PathBuf,
        #[arg(long)]
        json: bool,
    },
    Project {
        #[command(subcommand)]
        cmd: ProjectCmd,
    },
    Tui {
        input: Option<PathBuf>,
    },
    /// TASK-039/040: assemble a release bundle — artifact sha256 list,
    /// CycloneDX SBOM (cargo metadata --locked), license inventory, build
    /// provenance, gate evidence, and the TASK-038 budget gate.
    Release {
        #[arg(long, value_name = "DIR")]
        out: PathBuf,
        #[arg(long, value_name = "LABEL")]
        label: String,
        /// Publish an engineering build despite unmet TASK-038 budgets;
        /// the override is recorded in the manifest, never silent.
        #[arg(long)]
        allow_budget_fail: bool,
    },
}

#[derive(Subcommand)]
pub enum ProjectCmd {
    Init {
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
        #[arg(long, value_enum, default_value_t = ProfileArg::Max)]
        profile: ProfileArg,
        #[arg(long, value_delimiter = ',')]
        vm_export: Vec<String>,
        #[arg(long)]
        trace_diverge: bool,
        #[arg(long, value_name = "RVA:LEN")]
        select_rva: Vec<String>,
        #[arg(long, value_delimiter = ',')]
        select_function: Vec<String>,
        #[arg(long)]
        select_all: bool,
        #[arg(long)]
        strict_coverage: bool,
        #[arg(long)]
        allow_native_fallback: bool,
        /// G5: seal non-keep regions; decrypt on execution fault.
        #[arg(long)]
        lazy_regions: bool,
        /// G5: seal envelope import names (writeback mode only).
        #[arg(long)]
        protect_imports: bool,
        /// G5: refuse to pack when read-only constants keep native references (strict data protection).
        #[arg(long)]
        strict_constants: bool,
    },
    Show {
        file: PathBuf,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum ProfileArg {
    Fast,
    Standard,
    Max,
}

impl From<ProfileArg> for Profile {
    fn from(value: ProfileArg) -> Self {
        match value {
            ProfileArg::Fast => Profile::Fast,
            ProfileArg::Standard => Profile::Standard,
            ProfileArg::Max => Profile::Max,
        }
    }
}

impl ProfileArg {
    pub fn parse_str(s: &str) -> anyhow::Result<Self> {
        match s {
            "fast" => Ok(Self::Fast),
            "standard" => Ok(Self::Standard),
            "max" => Ok(Self::Max),
            other => anyhow::bail!("unknown profile {other}"),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fast => "fast",
            Self::Standard => "standard",
            Self::Max => "max",
        }
    }
}

pub fn parse_seed_hex(s: &str) -> anyhow::Result<[u8; 16]> {
    let t = s.trim();
    if t.len() != 32 {
        anyhow::bail!("--seed-hex must be 32 hex chars");
    }
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = u8::from_str_radix(&t[i * 2..i * 2 + 2], 16)
            .map_err(|_| anyhow::anyhow!("--seed-hex is not hex"))?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn help_hides_keep_export() {
        let mut cmd = Cli::command();
        let mut buf = Vec::new();
        cmd.write_long_help(&mut buf).unwrap();
        let top = String::from_utf8(buf).unwrap();
        assert!(top.contains("superoperators") || top.contains("selected named"), "{top}");
        let pack = cmd.find_subcommand_mut("pack").expect("pack");
        let mut buf = Vec::new();
        pack.write_long_help(&mut buf).unwrap();
        let help = String::from_utf8(buf).unwrap();
        assert!(!help.contains("keep-export"), "{help}");
        assert!(help.contains("vm-export"), "{help}");
        assert!(help.contains("select-function"), "{help}");
        assert!(help.contains("select-all"), "{help}");
        assert!(help.contains("allow-native-fallback"), "{help}");
        assert!(help.contains("seed-hex"), "{help}");
        assert!(help.contains("trace-diverge"), "{help}");
        assert!(!help.contains("c2"), "{help}");
    }

    #[test]
    fn seed_hex_round_trip() {
        let s = parse_seed_hex("0123456789abcdef0123456789abcdef").unwrap();
        assert_eq!(s[0], 0x01);
        assert_eq!(s[15], 0xef);
        assert!(parse_seed_hex("zz").is_err());
    }
}
