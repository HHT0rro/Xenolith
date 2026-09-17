mod args;
mod project;
mod release;
mod tui;

use anyhow::{bail, Context, Result};
use args::{parse_seed_hex, Cli, Command, ProfileArg, ProjectCmd};
use clap::Parser;
use xenolith_pack::{inspect_bytes, pack, PackRequest};
use project::ProjectFile;
use std::fs;
use std::path::PathBuf;

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        None => tui::run(None),
        Some(Command::Tui { input }) => tui::run(input),
        Some(Command::Release {
            out,
            label,
            allow_budget_fail,
        }) => {
            let manifest = release::build_release(&release::ReleaseOptions {
                label,
                out: out.clone(),
                allow_budget_fail,
            })?;
            let manifest_path = out.join("manifest.json");
            let digest = release::sha256_file(&manifest_path)?;
            println!(
                "release -> {} (level={}, budget_override={})\nmanifest sha256: {digest}",
                manifest_path.display(),
                manifest["release_level"].as_str().unwrap_or("?"),
                manifest["budgets"]["override_used"].as_bool().unwrap_or(false),
            );
            Ok(())
        }
        Some(Command::Pack {
            input,
            output,
            profile,
            vm_export,
            json,
            project,
            seed_hex,
            keep_export,
            trace_diverge,
            select_rva,
            select_function,
            select_all,
            strict_coverage,
            allow_native_fallback,
            lazy_regions,
            protect_imports,
            strict_constants,
        }) => {
            if !keep_export.is_empty() {
                bail!("--keep-export is not armed (C2 is off)");
            }
            let resolved = resolve_pack(
                input,
                output,
                profile,
                vm_export,
                project,
                seed_hex,
                trace_diverge,
                select_rva,
                select_function,
                select_all,
                strict_coverage,
                allow_native_fallback,
                lazy_regions,
                protect_imports,
                strict_constants,
            )?;
            let packed = pack(PackRequest {
                debug_gate: 3,
                input: &resolved.bytes,
                profile: resolved.profile,
                vm_exports: resolved.vm_exports,
                opcode_seed: resolved.seed,
                trace_diverge: resolved.trace_diverge,
                select_rva: resolved.ranges,
                select_functions: resolved.select_functions,
                select_all: resolved.select_all,
                strict_coverage: resolved.strict_coverage,
                allow_native_fallback: resolved.allow_native_fallback,
                lazy_regions: resolved.lazy_regions,
                protect_imports: resolved.protect_imports,
                strict_constants: resolved.strict_constants,
            })?;
            fs::write(&resolved.output, &packed.image)
                .with_context(|| format!("write {}", resolved.output.display()))?;
            if json {
                println!("{}", serde_json::to_string_pretty(&packed.report)?);
            } else {
                println!(
                    "packed -> {} ({} pages, backend={}, iat={}, decrypt_window={}, vm={}, size={}B->{}B)",
                    resolved.output.display(),
                    packed.report.pages,
                    packed.report.backend,
                    packed.report.iat_mode,
                    packed.report.runtime_decryption_window,
                    packed.report.vm_functions,
                    packed.report.input_bytes,
                    packed.report.output_bytes
                );
            }
            Ok(())
        }
        Some(Command::Inspect {
            input,
            json,
            exports,
        }) => {
            let bytes = fs::read(&input).with_context(|| format!("read {}", input.display()))?;
            let info = inspect_bytes(&bytes)?;
            if exports {
                if let Some(list) = info.get("exports") {
                    if json {
                        println!("{}", serde_json::to_string_pretty(list)?);
                    } else {
                        println!("{:<32} {:>6} {:>10}", "name", "ord", "rva");
                        if let Some(arr) = list.as_array() {
                            if arr.is_empty() {
                                if let Some(note) = info.get("note").and_then(|v| v.as_str()) {
                                    if !note.is_empty() {
                                        println!("{note}");
                                    }
                                }
                            }
                            for e in arr {
                                println!(
                                    "{:<32} {:>6} {:>10}",
                                    e.get("name").and_then(|v| v.as_str()).unwrap_or(""),
                                    e.get("ordinal").and_then(|v| v.as_u64()).unwrap_or(0),
                                    format!(
                                        "{:#x}",
                                        e.get("rva").and_then(|v| v.as_u64()).unwrap_or(0)
                                    )
                                );
                            }
                        }
                    }
                    return Ok(());
                }
            }
            if json {
                println!("{}", serde_json::to_string_pretty(&info)?);
            } else {
                println!("{info}");
            }
            Ok(())
        }
        Some(Command::Stats { input, json }) => {
            let image = std::fs::read(&input)?;
            let parsed = xenolith_formats::elf::parse(&image)
                .map_err(|e| anyhow::anyhow!("parse: {e}"))?;
            let s = xenolith_pack::stats::classify_elf(&image, &parsed)
                .map_err(|e| anyhow::anyhow!("stats: {e}"))?;
            let mut reasons: Vec<_> = s.reasons.iter().collect();
            reasons.sort_by_key(|(_, c)| std::cmp::Reverse(**c));
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "functions": s.functions,
                        "bytes": s.bytes,
                        "transformed": s.transformed,
                        "transformed_bytes": s.transformed_bytes,
                        "mixed_native": s.mixed_native,
                        "unsupported": s.unsupported,
                        "boundary_uncertain": s.boundary_uncertain,
                        "top_reasons": reasons.into_iter().take(10)
                            .map(|(r, c)| serde_json::json!({"reason": r, "count": c}))
                            .collect::<Vec<_>>(),
                    })
                );
            } else {
                println!(
                    "functions={} bytes={} transformed={}({}B) mixed_native={} unsupported={} boundary_uncertain={}",
                    s.functions, s.bytes, s.transformed, s.transformed_bytes,
                    s.mixed_native, s.unsupported, s.boundary_uncertain
                );
                for (r, c) in reasons.into_iter().take(8) {
                    println!("  x{c:<4} {r}");
                }
            }
            Ok(())
        }
        Some(Command::Project { cmd }) => match cmd {
            ProjectCmd::Init {
                input,
                output,
                profile,
                vm_export,
                trace_diverge,
                select_rva,
                select_function,
                select_all,
                strict_coverage,
                allow_native_fallback,
                lazy_regions,
                protect_imports,
                strict_constants,
            } => {
                let packed_out = {
                    let bytes = fs::read(&input)
                        .with_context(|| format!("read {}", input.display()))?;
                    match xenolith_formats::classify(&bytes) {
                        Ok(kind) => xenolith_formats::packed_output_name(&input, kind),
                        Err(_) => {
                            let mut o = input.clone();
                            o.set_extension("xl.dll");
                            o
                        }
                    }
                };
                let file = ProjectFile {
                    schema_version: project::SCHEMA_VERSION,
                    input,
                    output: packed_out,
                    profile: profile.as_str().to_string(),
                    vm_exports: vm_export,
                    trace_diverge,
                    select_rva,
                    select_functions: select_function,
                    select_all,
                    strict_coverage,
                    allow_native_fallback,
                    lazy_regions,
                    protect_imports,
                    strict_constants,
                };
                project::save(&output, &file)?;
                println!("wrote {}", output.display());
                Ok(())
            }
            ProjectCmd::Show { file } => {
                let p = project::load(&file)?;
                println!("{}", serde_json::to_string_pretty(&p)?);
                Ok(())
            }
        },
    }
}

struct ResolvedPack {
    bytes: Vec<u8>,
    output: PathBuf,
    profile: xenolith_loader::Profile,
    vm_exports: Vec<String>,
    seed: Option<[u8; 16]>,
    trace_diverge: bool,
    ranges: Vec<(u32, u32)>,
    select_functions: Vec<String>,
    select_all: bool,
    strict_coverage: bool,
    allow_native_fallback: bool,
    lazy_regions: bool,
    protect_imports: bool,
    strict_constants: bool,
}

fn resolve_pack(
    input: Option<PathBuf>,
    output: Option<PathBuf>,
    profile: ProfileArg,
    vm_export: Vec<String>,
    project: Option<PathBuf>,
    seed_hex: Option<String>,
    trace_diverge: bool,
    select_rva: Vec<String>,
    select_function: Vec<String>,
    select_all: bool,
    strict_coverage: bool,
    allow_native_fallback: bool,
    lazy_regions: bool,
    protect_imports: bool,
    strict_constants: bool,
) -> Result<ResolvedPack> {
    let seed = match seed_hex {
        Some(s) => Some(parse_seed_hex(&s)?),
        None => None,
    };
    if let Some(pj) = project {
        let file = project::load(&pj)?;
        let bytes =
            fs::read(&file.input).with_context(|| format!("read {}", file.input.display()))?;
        let out = output.unwrap_or_else(|| file.output.clone());
        let mut vm = file.vm_exports.clone();
        vm.extend(vm_export);
        vm.sort();
        vm.dedup();
        let mut ranges = project::parse_select_rva(&file.select_rva)?;
        ranges.extend(project::parse_select_rva(&select_rva)?);
        let mut functions = file.select_functions.clone();
        functions.extend(select_function);
        functions.sort();
        functions.dedup();
        let strict = strict_coverage || file.strict_coverage;
        let fallback = allow_native_fallback || file.allow_native_fallback;
        if strict && fallback {
            bail!("strict-coverage and allow-native-fallback are mutually exclusive");
        }
        return Ok(ResolvedPack {
            bytes,
            output: out,
            profile: file.profile()?,
            vm_exports: vm,
            seed,
            trace_diverge: trace_diverge || file.trace_diverge,
            ranges,
            select_functions: functions,
            select_all: select_all || file.select_all,
            strict_coverage: strict,
            allow_native_fallback: fallback,
            lazy_regions: lazy_regions || file.lazy_regions,
            protect_imports: protect_imports || file.protect_imports,
            strict_constants: strict_constants || file.strict_constants,
        });
    }
    let input = input.ok_or_else(|| anyhow::anyhow!("pack requires INPUT or --project"))?;
    let output = output.ok_or_else(|| anyhow::anyhow!("pack requires -o/--output or --project"))?;
    let bytes = fs::read(&input).with_context(|| format!("read {}", input.display()))?;
    if strict_coverage && allow_native_fallback {
        bail!("strict-coverage and allow-native-fallback are mutually exclusive");
    }
    Ok(ResolvedPack {
        bytes,
        output,
        profile: profile.into(),
        vm_exports: vm_export,
        seed,
        trace_diverge,
        ranges: project::parse_select_rva(&select_rva)?,
        select_functions: select_function,
        select_all,
        strict_coverage,
        allow_native_fallback,
        lazy_regions,
        protect_imports,
        strict_constants,
    })
}
