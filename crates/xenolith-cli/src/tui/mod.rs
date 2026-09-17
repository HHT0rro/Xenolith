//! Four-screen pack wizard. Wired switches only; mouse hits recorded rects.

mod browse;
mod render;
mod worker;

use anyhow::{bail, Context, Result};
use browse::{read_dir_sorted, DirRow, parent_of};
use crossterm::event::{
    self, Event, KeyCode, KeyEventKind, MouseButton, MouseEvent, MouseEventKind,
};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use xenolith_formats::{ImageKind, Pe64};
use xenolith_pack::{forbidden_vm_name, inspect_bytes, lift_export};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::Rect;
use ratatui::widgets::ListState;
use ratatui::Terminal;
use std::collections::HashMap;
use std::io::{self, stdout, IsTerminal};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, TryRecvError};
use std::time::{Duration, Instant};
use worker::{spawn_pack, PackDone};

use crate::args::ProfileArg;
use crate::project::{self, ProjectFile};

const SPINNER: &[char] = &['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Screen {
    Pick,
    Configure,
    Packing,
    Result,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Focus {
    List,
    Options,
    Buttons,
}

/// The wired switches, in focus order. Everything else on the right
/// side (hashed IAT, stolen OEP, probes, select-rva, C2) is read-only.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OptionRow {
    Profile,
    TraceDiverge,
    LazyRegions,
    ProtectImports,
    StrictConstants,
    StrictCoverage,
    SelectAll,
    AllowNativeFallback,
}

const OPTION_ROWS: [OptionRow; 8] = [
    OptionRow::Profile,
    OptionRow::TraceDiverge,
    OptionRow::LazyRegions,
    OptionRow::ProtectImports,
    OptionRow::StrictConstants,
    OptionRow::StrictCoverage,
    OptionRow::SelectAll,
    OptionRow::AllowNativeFallback,
];

impl OptionRow {
    fn label(self) -> &'static str {
        match self {
            OptionRow::Profile => "profile",
            OptionRow::TraceDiverge => "trace-diverge",
            OptionRow::LazyRegions => "lazy-regions",
            OptionRow::ProtectImports => "protect-imports",
            OptionRow::StrictConstants => "strict-constants",
            OptionRow::StrictCoverage => "strict-coverage",
            OptionRow::SelectAll => "select-all",
            OptionRow::AllowNativeFallback => "allow-native-fallback",
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum Action {
    PickEntry(usize),
    ExportRow(usize),
    OptionClick(usize),
    ProfilePick(ProfileArg),
    BulkAll,
    BulkInvert,
    BulkNone,
    Pack,
    SaveProject,
    Back,
    Quit,
    Cancel,
    PackAnother,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Bulk {
    All,
    Invert,
    None,
}

impl Bulk {
    fn as_str(self) -> &'static str {
        match self {
            Bulk::All => "all",
            Bulk::Invert => "invert",
            Bulk::None => "none",
        }
    }
}

struct HotRect {
    rect: Rect,
    action: Action,
}

#[derive(Clone, Copy)]
enum Zone {
    Pick,
    Exports,
    Log,
}

#[derive(Clone)]
struct ExportRow {
    name: String,
    ordinal: u16,
    rva: u32,
    vm: bool,
    native_locked: bool,
}

enum DetailResult {
    Ok { native_len: usize, blocks: usize },
    Locked { reason: String },
    Err(String),
}

enum PackOutcome {
    Success(PackDone),
    Failure(String),
}

struct App {
    screen: Screen,
    input: PathBuf,
    output: PathBuf,
    profile: ProfileArg,
    exports: Vec<ExportRow>,
    selected: usize,
    focus: Focus,
    option_sel: usize,
    button: usize,
    log: Vec<String>,
    log_scroll: u16,
    log_follow: bool,
    trace_diverge: bool,
    strict_coverage: bool,
    select_all: bool,
    allow_native_fallback: bool,
    lazy_regions: bool,
    protect_imports: bool,
    strict_constants: bool,
    /// `RVA:LEN` strings passed through from a project file. Read-only in the
    /// TUI; empty unless a project supplied them.
    select_rva: Vec<String>,
    /// Function/symbol names passed through from a project file.
    select_functions: Vec<String>,
    image_kind: Option<ImageKind>,
    hot: Vec<HotRect>,
    scroll_zones: Vec<(Rect, Zone)>,
    cwd: PathBuf,
    pick_rows: Vec<DirRow>,
    pick_selected: usize,
    pick_state: ListState,
    export_state: ListState,
    details: HashMap<usize, DetailResult>,
    pe_bytes: Option<Vec<u8>>,
    pack_rx: Option<Receiver<Result<PackDone, String>>>,
    pack_started: Option<Instant>,
    spinner_frame: usize,
    cancelled: bool,
    packing_exports: Vec<String>,
    outcome: Option<PackOutcome>,
}

pub fn run(input: Option<PathBuf>) -> Result<()> {
    if !io::stdin().is_terminal() {
        bail!("no TTY; use `xenolith pack IN -o OUT` flags");
    }
    let mut app = App::new(input)?;
    enable_raw_mode().context("enable raw mode; use flags if this console cannot")?;
    let mut stdout = stdout();
    crossterm::execute!(
        stdout,
        crossterm::terminal::EnterAlternateScreen,
        crossterm::event::EnableMouseCapture
    )?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    let result = event_loop(&mut terminal, &mut app);
    disable_raw_mode()?;
    crossterm::execute!(
        io::stdout(),
        crossterm::event::DisableMouseCapture,
        crossterm::terminal::LeaveAlternateScreen
    )?;
    result
}

impl App {
    fn new(input: Option<PathBuf>) -> Result<Self> {
        let cwd = init_cwd(input.as_ref());
        let mut app = Self {
            screen: Screen::Pick,
            input: PathBuf::new(),
            output: PathBuf::from("packed.dll"),
            profile: ProfileArg::Max,
            exports: Vec::new(),
            selected: 0,
            focus: Focus::List,
            option_sel: 0,
            button: 0,
            log: vec!["Xenolith TUI. Exports: space VM · a/v/u all/invert/none. Options: space toggle · ←/→ profile. Tab cycles list→options→buttons.".into()],
            log_scroll: 0,
            log_follow: true,
            trace_diverge: false,
            strict_coverage: false,
            select_all: false,
            allow_native_fallback: false,
            lazy_regions: false,
            protect_imports: false,
            strict_constants: false,
            select_rva: Vec::new(),
            select_functions: Vec::new(),
            image_kind: None,
            hot: Vec::new(),
            scroll_zones: Vec::new(),
            cwd,
            pick_rows: Vec::new(),
            pick_selected: 0,
            pick_state: ListState::default(),
            export_state: ListState::default(),
            details: HashMap::new(),
            pe_bytes: None,
            pack_rx: None,
            pack_started: None,
            spinner_frame: 0,
            cancelled: false,
            packing_exports: Vec::new(),
            outcome: None,
        };
        app.reload_pick();
        if let Some(path) = input {
            if path.as_os_str().is_empty() {
                return Ok(app);
            }
            match app.open_file(path) {
                Ok(()) => {}
                Err(e) => app.push_log(format!("open failed: {e}")),
            }
        }
        Ok(app)
    }

    fn push_log(&mut self, msg: impl Into<String>) {
        self.log.push(msg.into());
        if self.log_follow {
            self.log_scroll = u16::MAX;
        }
    }

    fn reload_pick(&mut self) {
        match read_dir_sorted(&self.cwd) {
            Ok(rows) => {
                self.pick_rows = rows;
                self.pick_selected = 0;
                self.sync_pick_state();
            }
            Err(e) => self.push_log(format!("read_dir {}: {e}", self.cwd.display())),
        }
    }

    fn enter_dir(&mut self, path: PathBuf) {
        match read_dir_sorted(&path) {
            Ok(rows) => {
                self.cwd = path;
                self.pick_rows = rows;
                self.pick_selected = 0;
                self.sync_pick_state();
            }
            Err(e) => self.push_log(format!("read_dir {}: {e}", path.display())),
        }
    }

    fn sync_pick_state(&mut self) {
        if self.pick_rows.is_empty() {
            self.pick_selected = 0;
            self.pick_state.select(None);
        } else {
            self.pick_selected = self.pick_selected.min(self.pick_rows.len() - 1);
            self.pick_state.select(Some(self.pick_selected));
        }
    }

    fn sync_export_state(&mut self) {
        if self.exports.is_empty() {
            self.selected = 0;
            self.export_state.select(None);
        } else {
            self.selected = self.selected.min(self.exports.len() - 1);
            self.export_state.select(Some(self.selected));
        }
    }

    fn enter_configure(&mut self) {
        self.screen = Screen::Configure;
        self.focus = Focus::List;
        self.option_sel = 0;
        self.button = 0;
    }

    fn open_file(&mut self, path: PathBuf) -> Result<()> {
        let name = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        if name.ends_with(".xenolith.json") {
            return self.open_project(path);
        }
        let bytes =
            std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
        match xenolith_formats::classify(&bytes)? {
            kind @ (ImageKind::Elf64Exec | ImageKind::Elf64Dyn) => self.open_elf(path, kind),
            kind => {
                self.input = path;
                self.output = xenolith_formats::packed_output_name(&self.input, kind);
                self.image_kind = Some(kind);
                self.load_pe_exports(bytes)?;
                self.enter_configure();
            }
        }
        Ok(())
    }

    fn open_elf(&mut self, path: PathBuf, kind: ImageKind) {
        self.input = path;
        self.output = xenolith_formats::packed_output_name(&self.input, kind);
        self.image_kind = Some(kind);
        self.exports.clear();
        self.details.clear();
        self.selected = 0;
        self.pe_bytes = None;
        self.sync_export_state();
        self.push_log(format!(
            "ELF {}: whole-image sealing; --vm-export needs the SysV lift (not in this release); Pack with an empty list is allowed",
            self.input.display()
        ));
        self.enter_configure();
    }

    /// Restore a saved project. Relative `input`/`output` resolve against the
    /// project file's directory; profile, switches, VM checks and `select_rva`
    /// come back exactly as saved. A missing input stays on Pick (caller logs).
    fn open_project(&mut self, path: PathBuf) -> Result<()> {
        let file = project::load(&path).with_context(|| format!("load {}", path.display()))?;
        let base = match path.parent() {
            Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
            _ => std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
        };
        let input = resolve_relative(&base, &file.input);
        let output = resolve_relative(&base, &file.output);
        let profile = ProfileArg::parse_str(&file.profile)?;
        if !input.is_file() {
            bail!("project input {} not found", input.display());
        }
        let bytes =
            std::fs::read(&input).with_context(|| format!("read {}", input.display()))?;
        let kind = xenolith_formats::classify(&bytes)?;

        self.profile = profile;
        self.trace_diverge = file.trace_diverge;
        self.lazy_regions = file.lazy_regions;
        self.protect_imports = file.protect_imports;
        self.strict_constants = file.strict_constants;
        self.strict_coverage = file.strict_coverage;
        self.select_rva = file.select_rva.clone();
        self.select_functions = file.select_functions.clone();
        self.select_all = file.select_all;
        self.allow_native_fallback = file.allow_native_fallback;
        self.input = input;
        self.output = output;
        self.image_kind = Some(kind);
        match kind {
            ImageKind::Elf64Exec | ImageKind::Elf64Dyn => {
                self.exports.clear();
                self.details.clear();
                self.selected = 0;
                self.pe_bytes = None;
                self.sync_export_state();
                if !file.vm_exports.is_empty() {
                    self.push_log(format!(
                        "project vm_exports {:?} ignored: ELF selection needs the SysV lift",
                        file.vm_exports
                    ));
                }
            }
            _ => {
                self.load_pe_exports(bytes)?;
                for row in &mut self.exports {
                    if !row.native_locked && file.vm_exports.iter().any(|n| n == &row.name) {
                        row.vm = true;
                    }
                }
                let missing: Vec<String> = file
                    .vm_exports
                    .iter()
                    .filter(|n| !self.exports.iter().any(|e| &e.name == *n))
                    .cloned()
                    .collect();
                if !missing.is_empty() {
                    self.push_log(format!(
                        "project vm_exports not in image: {}",
                        missing.join(", ")
                    ));
                }
            }
        }
        self.push_log(format!(
            "project {}: profile={} trace={} lazy={} imports={} consts={} strictcov={} fallback={} select_all={} select_rva={} select_functions={}",
            path.file_name().and_then(|s| s.to_str()).unwrap_or("?"),
            self.profile.as_str(),
            on_off(self.trace_diverge),
            on_off(self.lazy_regions),
            on_off(self.protect_imports),
            on_off(self.strict_constants),
            on_off(self.strict_coverage),
            on_off(self.allow_native_fallback),
            on_off(self.select_all),
            self.select_rva.len(),
            self.select_functions.len(),
        ));
        self.enter_configure();
        Ok(())
    }

    fn load_pe_exports(&mut self, bytes: Vec<u8>) -> Result<()> {
        let pe = Pe64::parse(&bytes).context("parse PE")?;
        let exports = pe.exports(&bytes).unwrap_or_default();
        if !matches!(pe.kind, xenolith_formats::PeKind::Dll) && exports.is_empty() {
            self.push_log(
                "W1 cannot virtualize EXE entry; use a DLL export or wait for RVA selection",
            );
        }
        self.exports = exports
            .into_iter()
            .map(|e| {
                let native_locked = forbidden_vm_name(&e.name);
                ExportRow {
                    name: e.name,
                    ordinal: e.ordinal,
                    rva: e.rva,
                    vm: false,
                    native_locked,
                }
            })
            .collect();
        let info = inspect_bytes(&bytes)?;
        self.push_log(format!(
            "loaded {} exports; import_rva={}",
            self.exports.len(),
            info.get("import_rva").unwrap_or(&serde_json::Value::Null)
        ));
        self.pe_bytes = Some(bytes);
        self.details.clear();
        self.selected = 0;
        self.sync_export_state();
        Ok(())
    }

    fn selected_count(&self) -> usize {
        self.exports.iter().filter(|e| e.vm).count()
    }

    fn toggle_selected(&mut self) {
        if self.exports.is_empty() {
            return;
        }
        let i = self.selected.min(self.exports.len() - 1);
        if self.exports[i].native_locked {
            self.push_log(format!(
                "{} stays native (CRT/DllMain)",
                self.exports[i].name
            ));
            return;
        }
        self.exports[i].vm = !self.exports[i].vm;
        if !self.exports[i].vm {
            return;
        }
        self.ensure_detail(i);
        match self.details.get(&i) {
            Some(DetailResult::Ok { blocks, .. }) => {
                let name = self.exports[i].name.clone();
                let blocks = *blocks;
                self.push_log(format!("lift ok {name} · {blocks} blocks"));
            }
            Some(DetailResult::Err(e)) => {
                let err = e.clone();
                self.exports[i].vm = false;
                self.push_log(format!("lift failed: {err}"));
            }
            Some(DetailResult::Locked { reason }) => {
                let reason = reason.clone();
                self.exports[i].vm = false;
                self.push_log(reason);
            }
            None => {
                self.exports[i].vm = false;
                self.push_log("lift failed: no detail");
            }
        }
    }

    /// Pre-lift export `i` and check the box only on success. Bulk operations
    /// count failures instead of logging each one.
    fn try_mark_vm(&mut self, i: usize) -> bool {
        self.ensure_detail(i);
        matches!(self.details.get(&i), Some(DetailResult::Ok { .. }))
    }

    /// Bulk All/Invert/None over the export list. Locked exports are skipped
    /// entirely; rows whose pre-lift fails stay unchecked. One summary log.
    fn bulk_set(&mut self, mode: Bulk) {
        if self.exports.is_empty() {
            self.push_log(format!(
                "bulk {}: no exports (ELF packs the whole image)",
                mode.as_str()
            ));
            return;
        }
        let mut checked = 0usize;
        let mut cleared = 0usize;
        let mut failed = 0usize;
        for i in 0..self.exports.len() {
            if self.exports[i].native_locked {
                continue;
            }
            match mode {
                Bulk::None => {
                    if self.exports[i].vm {
                        self.exports[i].vm = false;
                        cleared += 1;
                    }
                }
                Bulk::All => {
                    if self.exports[i].vm {
                        checked += 1;
                    } else if self.try_mark_vm(i) {
                        self.exports[i].vm = true;
                        checked += 1;
                    } else {
                        failed += 1;
                    }
                }
                Bulk::Invert => {
                    if self.exports[i].vm {
                        self.exports[i].vm = false;
                        cleared += 1;
                    } else if self.try_mark_vm(i) {
                        self.exports[i].vm = true;
                        checked += 1;
                    } else {
                        failed += 1;
                    }
                }
            }
        }
        let locked = self.exports.iter().filter(|e| e.native_locked).count();
        self.push_log(format!(
            "bulk {}: {checked} checked, {cleared} cleared, {failed} failed pre-lift, {locked} locked skipped",
            mode.as_str()
        ));
    }

    fn ensure_detail(&mut self, i: usize) {
        if self.details.contains_key(&i) || i >= self.exports.len() {
            return;
        }
        let name = self.exports[i].name.clone();
        let rva = self.exports[i].rva;
        if self.exports[i].native_locked {
            self.details.insert(
                i,
                DetailResult::Locked {
                    reason: lock_reason(&name),
                },
            );
            return;
        }
        let Some(bytes) = self.pe_bytes.as_ref() else {
            self.details
                .insert(i, DetailResult::Err("no image bytes".into()));
            return;
        };
        let pe = match Pe64::parse(bytes) {
            Ok(p) => p,
            Err(e) => {
                self.details.insert(i, DetailResult::Err(e.to_string()));
                return;
            }
        };
        match lift_export(&pe, bytes, &name, rva) {
            Ok(lifted) => {
                self.details.insert(
                    i,
                    DetailResult::Ok {
                        native_len: lifted.native_len,
                        blocks: lifted.ir.blocks.len(),
                    },
                );
            }
            Err(e) => {
                self.details.insert(i, DetailResult::Err(e.to_string()));
            }
        }
    }

    fn vm_exports(&self) -> Vec<String> {
        self.exports
            .iter()
            .filter(|e| e.vm)
            .map(|e| e.name.clone())
            .collect()
    }

    fn save_project(&mut self) -> Result<()> {
        if self.input.as_os_str().is_empty() {
            bail!("no input");
        }
        let path = {
            let mut p = self.output.clone();
            p.set_extension("xenolith.json");
            p
        };
        project::save(
            &path,
            &ProjectFile {
                schema_version: crate::project::SCHEMA_VERSION,
                input: self.input.clone(),
                output: self.output.clone(),
                profile: self.profile.as_str().to_string(),
                vm_exports: self.vm_exports(),
                trace_diverge: self.trace_diverge,
                select_rva: self.select_rva.clone(),
                select_functions: self.select_functions.clone(),
                select_all: self.select_all,
                strict_coverage: self.strict_coverage,
                allow_native_fallback: self.allow_native_fallback,
                lazy_regions: self.lazy_regions,
                protect_imports: self.protect_imports,
                strict_constants: self.strict_constants,
            },
        )?;
        self.push_log(format!("saved {}", path.display()));
        Ok(())
    }

    fn cycle_profile(&mut self) {
        self.step_profile(1);
    }

    fn step_profile(&mut self, delta: isize) {
        let order = [ProfileArg::Fast, ProfileArg::Standard, ProfileArg::Max];
        let i = match self.profile {
            ProfileArg::Fast => 0,
            ProfileArg::Standard => 1,
            ProfileArg::Max => 2,
        };
        let next = order[(i as isize + delta).rem_euclid(order.len() as isize) as usize];
        self.profile = next;
        self.push_log(format!("profile = {}", next.as_str()));
    }

    fn set_profile(&mut self, p: ProfileArg) {
        self.profile = p;
        self.push_log(format!("profile = {}", p.as_str()));
    }

    fn toggle_trace(&mut self) {
        self.trace_diverge = !self.trace_diverge;
        self.push_log(format!(
            "trace-diverge = {}",
            on_off(self.trace_diverge)
        ));
    }

    fn toggle_lazy(&mut self) {
        self.lazy_regions = !self.lazy_regions;
        self.push_log(format!("lazy-regions = {}", on_off(self.lazy_regions)));
    }

    fn toggle_imports(&mut self) {
        self.protect_imports = !self.protect_imports;
        self.push_log(format!(
            "protect-imports = {}",
            on_off(self.protect_imports)
        ));
    }

    fn toggle_strict_constants(&mut self) {
        self.strict_constants = !self.strict_constants;
        self.push_log(format!(
            "strict-constants = {}",
            on_off(self.strict_constants)
        ));
    }

    fn toggle_strict_coverage(&mut self) {
        self.strict_coverage = !self.strict_coverage;
        if self.strict_coverage {
            self.allow_native_fallback = false;
        }
        self.push_log(format!(
            "strict-coverage = {}",
            on_off(self.strict_coverage)
        ));
    }

    fn toggle_select_all(&mut self) {
        self.select_all = !self.select_all;
        self.push_log(format!("select-all = {}", on_off(self.select_all)));
    }

    fn toggle_native_fallback(&mut self) {
        self.allow_native_fallback = !self.allow_native_fallback;
        if self.allow_native_fallback {
            self.strict_coverage = false;
        }
        self.push_log(format!(
            "allow-native-fallback = {}",
            on_off(self.allow_native_fallback)
        ));
    }

    fn apply_option_row(&mut self, row: OptionRow) {
        match row {
            OptionRow::Profile => self.cycle_profile(),
            OptionRow::TraceDiverge => self.toggle_trace(),
            OptionRow::LazyRegions => self.toggle_lazy(),
            OptionRow::ProtectImports => self.toggle_imports(),
            OptionRow::StrictConstants => self.toggle_strict_constants(),
            OptionRow::StrictCoverage => self.toggle_strict_coverage(),
            OptionRow::SelectAll => self.toggle_select_all(),
            OptionRow::AllowNativeFallback => self.toggle_native_fallback(),
        }
    }

    fn apply_option_sel(&mut self) {
        let i = self.option_sel.min(OPTION_ROWS.len() - 1);
        self.apply_option_row(OPTION_ROWS[i]);
    }

    fn move_option(&mut self, delta: isize) {
        let n = OPTION_ROWS.len() as isize;
        let next = (self.option_sel as isize + delta).clamp(0, n - 1) as usize;
        self.option_sel = next;
    }

    fn focus_next(&mut self) {
        self.focus = match self.focus {
            Focus::List => Focus::Options,
            Focus::Options => Focus::Buttons,
            Focus::Buttons => Focus::List,
        };
        self.clamp_button();
    }

    fn focus_prev(&mut self) {
        self.focus = match self.focus {
            Focus::List => Focus::Buttons,
            Focus::Options => Focus::List,
            Focus::Buttons => Focus::Options,
        };
        self.clamp_button();
    }

    fn clamp_button(&mut self) {
        if self.focus == Focus::Buttons {
            self.button = self.button.min(self.button_count().saturating_sub(1));
        }
    }

    /// `fast` plus any checked VM export: pack() rejects this combination.
    fn fast_vm_conflict(&self) -> bool {
        matches!(self.profile, ProfileArg::Fast) && self.exports.iter().any(|e| e.vm)
    }

    /// `protect-imports` only seals under writeback IAT; `fast` keeps the disk
    /// IAT, so the switch stays on but has nothing to do.
    fn fast_imports_note(&self) -> bool {
        matches!(self.profile, ProfileArg::Fast) && self.protect_imports
    }

    fn start_pack(&mut self) {
        if self.input.as_os_str().is_empty() {
            self.push_log("no input");
            return;
        }
        let vm = self.vm_exports();
        if matches!(self.profile, ProfileArg::Fast) && !vm.is_empty() {
            self.push_log(
                "fast rejects --vm-export; switch to standard/max or uncheck VM exports",
            );
            return;
        }
        let ranges = match project::parse_select_rva(&self.select_rva) {
            Ok(r) => r,
            Err(e) => {
                self.push_log(format!("select-rva: {e}"));
                return;
            }
        };
        let bytes = match std::fs::read(&self.input) {
            Ok(b) => b,
            Err(e) => {
                self.push_log(format!("read {}: {e}", self.input.display()));
                return;
            }
        };
        match spawn_pack(
            bytes,
            self.profile,
            vm.clone(),
            ranges,
            self.trace_diverge,
            self.strict_coverage,
            self.select_functions.clone(),
            self.select_all,
            self.allow_native_fallback,
            self.lazy_regions,
            self.protect_imports,
            self.strict_constants,
            self.output.clone(),
        ) {
            Ok(rx) => {
                self.pack_rx = Some(rx);
                self.pack_started = Some(Instant::now());
                self.spinner_frame = 0;
                self.cancelled = false;
                self.packing_exports = vm;
                self.screen = Screen::Packing;
                self.focus = Focus::Buttons;
                self.button = 0;
            }
            Err(e) => self.push_log(format!("spawn pack: {e}")),
        }
    }

    fn cancel_pack(&mut self) {
        self.cancelled = true;
        self.pack_rx = None;
        self.screen = Screen::Configure;
        self.focus = Focus::List;
        self.push_log("pack cancelled; image discarded (worker may still finish)");
    }

    fn poll_pack(&mut self) {
        let Some(rx) = self.pack_rx.as_ref() else {
            return;
        };
        match rx.try_recv() {
            Ok(Ok(done)) => {
                self.pack_rx = None;
                if self.cancelled {
                    return;
                }
                match std::fs::write(&done.output, &done.image) {
                    Ok(()) => {
                        self.push_log(format!(
                            "pack {} · {} vm · {} pages · {:.1}s",
                            done.output.display(),
                            done.report.vm_functions,
                            done.report.pages,
                            done.elapsed.as_secs_f32()
                        ));
                        self.finish_result(PackOutcome::Success(done));
                    }
                    Err(e) => self.finish_result(PackOutcome::Failure(format!(
                        "write {}: {e}",
                        done.output.display()
                    ))),
                }
            }
            Ok(Err(e)) => {
                self.pack_rx = None;
                if !self.cancelled {
                    self.finish_result(PackOutcome::Failure(e));
                }
            }
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => {
                self.pack_rx = None;
                if !self.cancelled {
                    self.finish_result(PackOutcome::Failure("pack thread died".into()));
                }
            }
        }
    }

    fn finish_result(&mut self, outcome: PackOutcome) {
        self.outcome = Some(outcome);
        self.screen = Screen::Result;
        self.focus = Focus::Buttons;
        self.button = 0;
    }

    fn back_to_configure(&mut self) {
        self.screen = Screen::Configure;
        self.focus = Focus::List;
        self.button = 0;
    }

    fn back_to_pick(&mut self) {
        self.screen = Screen::Pick;
        self.focus = Focus::List;
        self.button = 0;
        if let Some(parent) = self.input.parent() {
            if !parent.as_os_str().is_empty() {
                self.enter_dir(parent.to_path_buf());
                return;
            }
        }
        self.reload_pick();
    }

    fn activate_pick(&mut self) {
        if self.pick_rows.is_empty() {
            return;
        }
        let i = self.pick_selected.min(self.pick_rows.len() - 1);
        let row = self.pick_rows[i].clone();
        if row.is_dir {
            self.enter_dir(row.path);
        } else if let Err(e) = self.open_file(row.path) {
            self.push_log(format!("open failed: {e}"));
        }
    }

    fn pick_parent(&mut self) {
        if let Some(parent) = parent_of(&self.cwd) {
            self.enter_dir(parent);
        }
    }

    fn move_pick(&mut self, delta: isize) {
        if self.pick_rows.is_empty() {
            return;
        }
        let n = self.pick_rows.len() as isize;
        let next = (self.pick_selected as isize + delta).clamp(0, n - 1) as usize;
        self.pick_selected = next;
        self.pick_state.select(Some(next));
    }

    fn move_export(&mut self, delta: isize) {
        if self.exports.is_empty() {
            return;
        }
        let n = self.exports.len() as isize;
        let next = (self.selected as isize + delta).clamp(0, n - 1) as usize;
        self.selected = next;
        self.export_state.select(Some(next));
    }

    fn button_count(&self) -> usize {
        match self.screen {
            Screen::Pick => 0,
            Screen::Configure => 4,
            Screen::Packing => 1,
            Screen::Result => match self.outcome {
                Some(PackOutcome::Success(_)) => 3,
                _ => 2,
            },
        }
    }

    fn move_button(&mut self, delta: isize) {
        let n = self.button_count() as isize;
        if n == 0 {
            return;
        }
        let next = (self.button as isize + delta).rem_euclid(n) as usize;
        self.button = next;
    }

    fn activate_button(&mut self) -> bool {
        match self.screen {
            Screen::Configure => match self.button {
                0 => {
                    self.start_pack();
                    false
                }
                1 => {
                    if let Err(e) = self.save_project() {
                        self.push_log(format!("save error: {e}"));
                    }
                    false
                }
                2 => {
                    self.back_to_pick();
                    false
                }
                _ => true,
            },
            Screen::Packing => {
                self.cancel_pack();
                false
            }
            Screen::Result => {
                let success = matches!(self.outcome, Some(PackOutcome::Success(_)));
                match (success, self.button) {
                    (true, 0) | (false, 0) => {
                        self.back_to_configure();
                        false
                    }
                    (true, 1) => {
                        if let Err(e) = self.save_project() {
                            self.push_log(format!("save error: {e}"));
                        }
                        false
                    }
                    _ => true,
                }
            }
            Screen::Pick => false,
        }
    }

    fn dispatch(&mut self, action: Action) -> bool {
        match action {
            Action::PickEntry(i) => {
                if i < self.pick_rows.len() {
                    self.pick_selected = i;
                    self.pick_state.select(Some(i));
                    self.activate_pick();
                }
                false
            }
            Action::ExportRow(i) => {
                if i < self.exports.len() {
                    self.selected = i;
                    self.export_state.select(Some(i));
                    self.focus = Focus::List;
                    self.toggle_selected();
                }
                false
            }
            Action::OptionClick(i) => {
                if i < OPTION_ROWS.len() {
                    self.option_sel = i;
                    self.apply_option_row(OPTION_ROWS[i]);
                }
                false
            }
            Action::ProfilePick(p) => {
                self.set_profile(p);
                false
            }
            Action::BulkAll => {
                self.bulk_set(Bulk::All);
                false
            }
            Action::BulkInvert => {
                self.bulk_set(Bulk::Invert);
                false
            }
            Action::BulkNone => {
                self.bulk_set(Bulk::None);
                false
            }
            Action::Pack => {
                self.focus = Focus::Buttons;
                self.button = 0;
                self.start_pack();
                false
            }
            Action::SaveProject => {
                self.focus = Focus::Buttons;
                if self.screen == Screen::Configure {
                    self.button = 1;
                } else if self.screen == Screen::Result {
                    self.button = 1;
                }
                if let Err(e) = self.save_project() {
                    self.push_log(format!("save error: {e}"));
                }
                false
            }
            Action::Back => {
                match self.screen {
                    Screen::Configure => self.back_to_pick(),
                    Screen::Result => self.back_to_configure(),
                    Screen::Packing => self.cancel_pack(),
                    Screen::Pick => {}
                }
                false
            }
            Action::Quit => true,
            Action::Cancel => {
                if self.screen == Screen::Packing {
                    self.cancel_pack();
                }
                false
            }
            Action::PackAnother => {
                self.back_to_configure();
                false
            }
        }
    }

    fn handle_scroll(&mut self, col: u16, row: u16, up: bool) {
        let zone = self
            .scroll_zones
            .iter()
            .rev()
            .find(|(r, _)| contains(*r, col, row))
            .map(|(_, z)| *z);
        let Some(zone) = zone else {
            return;
        };
        let delta = if up { -1 } else { 1 };
        match zone {
            Zone::Pick => self.move_pick(delta),
            Zone::Exports => self.move_export(delta),
            Zone::Log => {
                self.log_follow = false;
                if up {
                    self.log_scroll = self.log_scroll.saturating_sub(1);
                } else {
                    self.log_scroll = self.log_scroll.saturating_add(1);
                }
            }
        }
    }

    fn handle_click(&mut self, col: u16, row: u16) -> bool {
        let action = self
            .hot
            .iter()
            .rev()
            .find(|h| contains(h.rect, col, row))
            .map(|h| h.action);
        if let Some(action) = action {
            return self.dispatch(action);
        }
        false
    }

    fn spinner(&self) -> char {
        SPINNER[self.spinner_frame % SPINNER.len()]
    }
}

fn on_off(v: bool) -> &'static str {
    if v {
        "on"
    } else {
        "off"
    }
}

fn resolve_relative(base: &Path, p: &Path) -> PathBuf {
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        base.join(p)
    }
}

fn init_cwd(input: Option<&PathBuf>) -> PathBuf {
    if let Some(p) = input {
        if let Some(parent) = p.parent() {
            if !parent.as_os_str().is_empty() {
                return parent.to_path_buf();
            }
        }
    }
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

fn lock_reason(name: &str) -> String {
    let n = name.to_ascii_lowercase();
    if n == "dllmain" || n.starts_with("dllmain@") {
        format!("{name}: DllMain stays native")
    } else if n.contains("crt") {
        format!("{name}: CRT stays native")
    } else if n.starts_with('_') {
        format!("{name}: leading underscore stays native")
    } else {
        format!("{name}: stays native")
    }
}

fn contains(rect: Rect, col: u16, row: u16) -> bool {
    col >= rect.x
        && col < rect.x.saturating_add(rect.width)
        && row >= rect.y
        && row < rect.y.saturating_add(rect.height)
}

fn event_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
) -> Result<()> {
    loop {
        terminal.draw(|f| render::ui(f, app))?;
        let timeout = if app.screen == Screen::Packing {
            Duration::from_millis(120)
        } else {
            Duration::from_millis(250)
        };
        if event::poll(timeout)? {
            match event::read()? {
                Event::Key(k) if k.kind == KeyEventKind::Press => {
                    if handle_key(app, k.code) {
                        return Ok(());
                    }
                }
                Event::Mouse(m) => {
                    if handle_mouse(app, m) {
                        return Ok(());
                    }
                }
                _ => {}
            }
        } else if app.screen == Screen::Packing {
            app.spinner_frame = app.spinner_frame.wrapping_add(1);
        }
        if app.screen == Screen::Packing {
            app.poll_pack();
        }
    }
}

fn handle_mouse(app: &mut App, m: MouseEvent) -> bool {
    match m.kind {
        MouseEventKind::Down(MouseButton::Left) => app.handle_click(m.column, m.row),
        MouseEventKind::ScrollUp => {
            app.handle_scroll(m.column, m.row, true);
            false
        }
        MouseEventKind::ScrollDown => {
            app.handle_scroll(m.column, m.row, false);
            false
        }
        _ => false,
    }
}

fn handle_key(app: &mut App, code: KeyCode) -> bool {
    match app.screen {
        Screen::Pick => match code {
            KeyCode::Esc | KeyCode::Char('q') => true,
            KeyCode::Up => {
                app.move_pick(-1);
                false
            }
            KeyCode::Down => {
                app.move_pick(1);
                false
            }
            KeyCode::Enter => {
                app.activate_pick();
                false
            }
            KeyCode::Backspace => {
                app.pick_parent();
                false
            }
            _ => false,
        },
        Screen::Configure => match code {
            KeyCode::Esc => {
                app.back_to_pick();
                false
            }
            KeyCode::Char('q') => true,
            KeyCode::Tab => {
                app.focus_next();
                false
            }
            KeyCode::BackTab => {
                app.focus_prev();
                false
            }
            KeyCode::Up => {
                match app.focus {
                    Focus::List => app.move_export(-1),
                    Focus::Options => app.move_option(-1),
                    Focus::Buttons => {}
                }
                false
            }
            KeyCode::Down => {
                match app.focus {
                    Focus::List => app.move_export(1),
                    Focus::Options => app.move_option(1),
                    Focus::Buttons => {}
                }
                false
            }
            KeyCode::Left => {
                match app.focus {
                    // Profile row is a radio: left steps backwards.
                    Focus::Options if app.option_sel == 0 => app.step_profile(-1),
                    Focus::Buttons => app.move_button(-1),
                    _ => {}
                }
                false
            }
            KeyCode::Right => {
                match app.focus {
                    Focus::Options if app.option_sel == 0 => app.step_profile(1),
                    Focus::Buttons => app.move_button(1),
                    _ => {}
                }
                false
            }
            KeyCode::Char(' ') => {
                match app.focus {
                    Focus::List => app.toggle_selected(),
                    Focus::Options => app.apply_option_sel(),
                    Focus::Buttons => {}
                }
                false
            }
            KeyCode::Char('a') => {
                app.bulk_set(Bulk::All);
                false
            }
            KeyCode::Char('v') => {
                app.bulk_set(Bulk::Invert);
                false
            }
            KeyCode::Char('u') => {
                app.bulk_set(Bulk::None);
                false
            }
            KeyCode::Char('p') => {
                app.cycle_profile();
                false
            }
            KeyCode::Char('d') => {
                app.toggle_trace();
                false
            }
            KeyCode::Char('l') => {
                app.toggle_lazy();
                false
            }
            KeyCode::Char('i') => {
                app.toggle_imports();
                false
            }
            KeyCode::Char('c') => {
                app.toggle_strict_constants();
                false
            }
            KeyCode::Char('s') => {
                app.toggle_strict_coverage();
                false
            }
            KeyCode::Char('x') => {
                app.toggle_select_all();
                false
            }
            KeyCode::Char('f') => {
                app.toggle_native_fallback();
                false
            }
            KeyCode::Enter => match app.focus {
                Focus::List => {
                    app.toggle_selected();
                    false
                }
                Focus::Options => {
                    app.apply_option_sel();
                    false
                }
                Focus::Buttons => app.activate_button(),
            },
            _ => false,
        },
        Screen::Packing => match code {
            KeyCode::Esc | KeyCode::Char('q') | KeyCode::Enter => {
                app.cancel_pack();
                false
            }
            _ => false,
        },
        Screen::Result => match code {
            KeyCode::Esc => {
                app.back_to_configure();
                false
            }
            KeyCode::Char('q') => true,
            KeyCode::Left => {
                app.move_button(-1);
                false
            }
            KeyCode::Right | KeyCode::Tab => {
                app.move_button(1);
                false
            }
            KeyCode::Enter => app.activate_button(),
            KeyCode::Char('p') if matches!(app.outcome, Some(PackOutcome::Success(_))) => {
                app.back_to_configure();
                false
            }
            _ => false,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn test_app() -> App {
        App::new(None).expect("app")
    }

    fn configure_app() -> App {
        let mut app = test_app();
        app.enter_configure();
        app
    }

    fn row(name: &str, locked: bool) -> ExportRow {
        ExportRow {
            name: name.to_string(),
            ordinal: 1,
            rva: 0x1000,
            vm: false,
            native_locked: locked,
        }
    }

    fn sample_dll() -> Option<PathBuf> {
        if !cfg!(windows) {
            return None;
        }
        let rel = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/release/license_toy.dll");
        if rel.is_file() {
            return Some(rel);
        }
        let dbg = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/debug/license_toy.dll");
        dbg.is_file().then_some(dbg)
    }

    fn unique_dir(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "xl-tui-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn focus_cycles_list_options_buttons() {
        let mut app = configure_app();
        assert_eq!(app.focus, Focus::List);
        handle_key(&mut app, KeyCode::Tab);
        assert_eq!(app.focus, Focus::Options);
        handle_key(&mut app, KeyCode::Tab);
        assert_eq!(app.focus, Focus::Buttons);
        handle_key(&mut app, KeyCode::Tab);
        assert_eq!(app.focus, Focus::List);
        handle_key(&mut app, KeyCode::BackTab);
        assert_eq!(app.focus, Focus::Buttons);
        handle_key(&mut app, KeyCode::BackTab);
        assert_eq!(app.focus, Focus::Options);
        handle_key(&mut app, KeyCode::BackTab);
        assert_eq!(app.focus, Focus::List);
    }

    #[test]
    fn arrows_never_cross_columns() {
        let mut app = configure_app();
        app.exports = vec![row("a", false), row("b", false)];
        app.sync_export_state();
        // In Options: Up/Down move the option cursor, Left/Right do not move
        // focus or buttons...
        app.focus = Focus::Options;
        app.option_sel = 0;
        handle_key(&mut app, KeyCode::Down);
        assert_eq!(app.option_sel, 1);
        handle_key(&mut app, KeyCode::Down);
        assert_eq!(app.option_sel, 2);
        handle_key(&mut app, KeyCode::Up);
        assert_eq!(app.option_sel, 1);
        assert_eq!(app.focus, Focus::Options);
        assert_eq!(app.button, 0);
        // ...and in Buttons: Left/Right move buttons, Up/Down do not leave.
        app.focus = Focus::Buttons;
        handle_key(&mut app, KeyCode::Right);
        assert_eq!(app.button, 1);
        handle_key(&mut app, KeyCode::Down);
        assert_eq!(app.focus, Focus::Buttons);
        assert_eq!(app.button, 1);
        // In List: Left/Right are inert.
        app.focus = Focus::List;
        handle_key(&mut app, KeyCode::Right);
        assert_eq!(app.focus, Focus::List);
        assert_eq!(app.button, 1);
    }

    #[test]
    fn option_rows_map_to_wired_switches() {
        let mut app = configure_app();
        // Profile row: cycle Max -> Fast, then set back via ProfilePick.
        app.dispatch(Action::OptionClick(0));
        assert!(matches!(app.profile, ProfileArg::Fast));
        app.dispatch(Action::ProfilePick(ProfileArg::Max));
        assert!(matches!(app.profile, ProfileArg::Max));
        // Each toggle row flips exactly its own field.
        app.dispatch(Action::OptionClick(1));
        assert!(app.trace_diverge);
        app.dispatch(Action::OptionClick(2));
        assert!(app.lazy_regions);
        app.dispatch(Action::OptionClick(3));
        assert!(app.protect_imports);
        app.dispatch(Action::OptionClick(4));
        assert!(app.strict_constants);
        app.dispatch(Action::OptionClick(5));
        assert!(app.strict_coverage);
        assert!(app.trace_diverge && app.lazy_regions);
        assert!(app.protect_imports && app.strict_constants);
        // OPTION_ROWS order is the surface contract.
        assert_eq!(OPTION_ROWS[0].label(), "profile");
        assert_eq!(OPTION_ROWS[5].label(), "strict-coverage");
    }

    #[test]
    fn option_hotkeys_toggle_directly() {
        let mut app = configure_app();
        let checks: Vec<(KeyCode, fn(&App) -> bool)> = vec![
            (KeyCode::Char('s'), |a: &App| a.strict_coverage),
            (KeyCode::Char('c'), |a: &App| a.strict_constants),
            (KeyCode::Char('i'), |a: &App| a.protect_imports),
            (KeyCode::Char('l'), |a: &App| a.lazy_regions),
            (KeyCode::Char('d'), |a: &App| a.trace_diverge),
        ];
        for (key, get) in checks {
            handle_key(&mut app, key);
            assert!(get(&app), "{key:?} must toggle on");
            handle_key(&mut app, key);
            assert!(!get(&app), "{key:?} must toggle off");
        }
    }

    #[test]
    fn fast_plus_vm_export_is_warned_and_rejected() {
        let mut app = configure_app();
        app.input = PathBuf::from("whatever.dll");
        app.profile = ProfileArg::Fast;
        app.exports = vec![row("f", false)];
        app.sync_export_state();
        app.exports[0].vm = true;
        app.details.insert(
            0,
            DetailResult::Ok {
                native_len: 16,
                blocks: 2,
            },
        );
        assert!(app.fast_vm_conflict());
        let before = app.log.len();
        app.start_pack();
        assert!(app.pack_rx.is_none());
        assert!(app.log.len() > before);
        assert!(app.log.last().unwrap().contains("fast rejects"));
        // The options area carries the same warning for rendering.
        assert!(app.fast_vm_conflict());
    }

    #[test]
    fn bad_select_rva_is_reported_not_packed() {
        let mut app = configure_app();
        app.input = PathBuf::from("whatever.dll");
        app.select_rva = vec!["nope".into()];
        app.start_pack();
        assert!(app.pack_rx.is_none());
        assert!(app.log.last().unwrap().contains("select-rva"));
    }

    #[test]
    fn bulk_skips_locked_rows_and_failed_pre_lifts() {
        let mut app = configure_app();
        app.exports = vec![
            row("a", false),
            row("b", false),
            row("_crt", true),
        ];
        app.sync_export_state();
        // Only `a` has a successful pre-lift on record; `b` will fail because
        // no image bytes are loaded.
        app.details.insert(
            0,
            DetailResult::Ok {
                native_len: 8,
                blocks: 1,
            },
        );
        app.bulk_set(Bulk::All);
        assert!(app.exports[0].vm);
        assert!(!app.exports[1].vm, "failed pre-lift must stay unchecked");
        assert!(!app.exports[2].vm, "locked row must never be checked");
        assert!(app.log.last().unwrap().contains("bulk all: 1 checked"));

        app.bulk_set(Bulk::Invert);
        assert!(!app.exports[0].vm);
        assert!(!app.exports[1].vm);
        assert!(app.log.last().unwrap().contains("bulk invert:"));

        app.exports[0].vm = true;
        app.bulk_set(Bulk::None);
        assert!(!app.exports[0].vm);
        assert!(!app.exports[1].vm);
        assert!(!app.exports[2].vm);
        assert!(app.log.last().unwrap().contains("bulk none:"));
    }

    #[test]
    fn bulk_on_empty_export_list_is_a_logged_noop() {
        let mut app = configure_app();
        app.image_kind = Some(ImageKind::Elf64Dyn);
        app.bulk_set(Bulk::All);
        assert!(app.exports.is_empty());
        assert!(app.log.last().unwrap().contains("no exports"));
    }

    #[test]
    fn junk_file_stays_on_pick() {
        let dir = unique_dir("junk");
        let p = dir.join("junk.dll");
        fs::write(&p, b"not an image").unwrap();
        let mut app = test_app();
        assert!(app.open_file(p).is_err());
        assert_eq!(app.screen, Screen::Pick);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn project_load_restores_switches_select_rva_and_vm_checks() {
        let Some(dll) = sample_dll() else {
            return;
        };
        let dir = unique_dir("proj");
        let json = dir.join("app.xenolith.json");
        fs::write(
            &json,
            format!(
                r#"{{"schema_version":1,"input":{inp:?},"output":{out:?},"profile":"standard","vm_exports":["check_license"],"trace_diverge":true,"select_rva":["0x1000:0x20"],"strict_coverage":true,"lazy_regions":true,"protect_imports":true,"strict_constants":true}}"#,
                inp = dll.display().to_string(),
                out = dir.join("out.xl.dll").display().to_string(),
            ),
        )
        .unwrap();
        let mut app = test_app();
        app.open_file(json).unwrap();
        assert_eq!(app.screen, Screen::Configure);
        assert!(matches!(app.profile, ProfileArg::Standard));
        assert!(app.trace_diverge);
        assert!(app.lazy_regions);
        assert!(app.protect_imports);
        assert!(app.strict_constants);
        assert!(app.strict_coverage);
        assert_eq!(app.select_rva, vec!["0x1000:0x20".to_string()]);
        let check = app
            .exports
            .iter()
            .find(|e| e.name == "check_license")
            .expect("check_license export row");
        assert!(check.vm, "project vm_exports must restore the checkbox");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn project_with_missing_input_stays_on_pick() {
        let dir = unique_dir("gone");
        let json = dir.join("app.xenolith.json");
        fs::write(
            &json,
            r#"{"input":"missing.dll","output":"out.xl.dll","profile":"max"}"#,
        )
        .unwrap();
        let mut app = test_app();
        assert!(app.open_file(json).is_err());
        assert_eq!(app.screen, Screen::Pick);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn elf_project_restores_select_rva_without_vm_checks() {
        let so = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../samples/hello-elf/libhello-elf.so");
        if !so.is_file() {
            return;
        }
        let dir = unique_dir("elfproj");
        let json = dir.join("elf.xenolith.json");
        fs::write(
            &json,
            format!(
                r#"{{"input":{inp:?},"output":"out.xl.so","profile":"max","vm_exports":["some_fn"],"select_rva":["0x1000:0x10"],"lazy_regions":true}}"#,
                inp = so.display().to_string(),
            ),
        )
        .unwrap();
        let mut app = test_app();
        app.open_file(json).unwrap();
        assert_eq!(app.screen, Screen::Configure);
        assert!(matches!(app.image_kind, Some(ImageKind::Elf64Dyn)));
        assert!(app.exports.is_empty());
        assert_eq!(app.select_rva, vec!["0x1000:0x10".to_string()]);
        assert!(app.lazy_regions);
        assert!(app.log.iter().any(|l| l.contains("ignored")));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn elf_open_never_runs_pe_parse() {
        let so = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../samples/hello-elf/libhello-elf.so");
        if !so.is_file() {
            return;
        }
        let mut app = test_app();
        app.open_file(so).unwrap();
        assert_eq!(app.screen, Screen::Configure);
        assert!(matches!(app.image_kind, Some(ImageKind::Elf64Dyn)));
        assert!(app.exports.is_empty(), "ELF export selection is not wired");
        assert!(app.pe_bytes.is_none());
        assert!(app
            .output
            .to_string_lossy()
            .ends_with(".xl.so"));
    }

    #[test]
    fn select_rva_survives_save() {
        let mut app = configure_app();
        app.input = PathBuf::from("in.dll");
        app.output = PathBuf::from("out.xl.dll");
        app.select_rva = vec!["0x2000:0x40".into()];
        app.save_project().unwrap();
        let loaded = project::load(Path::new("out.xl.xenolith.json"))
            .expect("saved project loads");
        assert_eq!(loaded.select_rva, vec!["0x2000:0x40".to_string()]);
        let _ = fs::remove_file("out.xl.xenolith.json");
    }
}
