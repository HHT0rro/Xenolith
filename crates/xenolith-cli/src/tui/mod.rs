//! Four-screen pack wizard. Wired switches only; mouse hits recorded rects.

mod browse;
mod render;
mod worker;

use anyhow::{bail, Context, Result};
use browse::{read_dir_sorted, DirRow, parent_of};
use crossterm::event::{
    self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers, MouseButton, MouseEvent,
    MouseEventKind,
};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use xenolith_formats::{ImageKind, Pe64};
use xenolith_pack::{forbidden_vm_name, inspect_bytes, lift_export};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::Rect;
use ratatui::widgets::ListState;
use ratatui::Terminal;
use std::collections::{HashMap, HashSet};
use std::io::{self, stdout, IsTerminal};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, Sender, TryRecvError, channel};
use std::sync::Arc;
use std::time::{Duration, Instant};
use worker::{spawn_pack, PackDone};

use crate::args::{ProfileArg, parse_seed_hex};
use crate::project::{self, ProjectFile};

const SPINNER: &[char] = &['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];

/// How far PgUp/PgDn moves in a list whose height we have not measured yet.
const DEFAULT_PAGE: u16 = 10;

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
    Result,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LogLevel {
    Info,
    Ok,
    Warn,
    Error,
}

#[derive(Clone, Debug)]
struct LogLine {
    level: LogLevel,
    text: String,
}

impl LogLine {
    fn new(level: LogLevel, text: impl Into<String>) -> Self {
        Self {
            level,
            text: text.into(),
        }
    }
}

#[derive(Clone)]
struct ExportRow {
    name: String,
    ordinal: u16,
    rva: u32,
    vm: bool,
    native_locked: bool,
}

#[derive(Clone, Debug)]
enum DetailResult {
    Ok { native_len: usize, blocks: usize },
    Locked { reason: String },
    Err(String),
}

/// Bottom-bar editor target. `o` edits the output path, `e` edits the opcode
/// seed. While any editor is open it swallows all keys.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EditTarget {
    Output,
    Seed,
}

#[derive(Clone, Debug)]
struct Editor {
    target: EditTarget,
    buf: String,
}

/// Messages from the background pre-lift threads (single detail lift or bulk).
enum LiftMsg {
    /// One row's lift finished.
    Detail {
        idx: usize,
        result: DetailResult,
    },
    /// Bulk progress tick (done rows out of total).
    BulkStep { done: usize, total: usize },
    /// Bulk finished; rows carry whether they were checked before the bulk.
    BulkDone {
        mode: Bulk,
        results: Vec<(usize, bool, DetailResult)>,
    },
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
    log: Vec<LogLine>,
    log_scroll: u16,
    log_follow: bool,
    /// Any user-visible configuration change since the last save/pack.
    dirty: bool,
    /// Bottom-bar "unsaved changes" quit confirmation is showing.
    confirm_quit: bool,
    /// `?` keys overlay is showing.
    help: bool,
    /// Bottom-bar editor (`o` output path, `e` opcode seed).
    edit: Option<Editor>,
    /// Opcode seed as typed on Configure: 32 hex chars, or empty for the
    /// runtime's random draw (OsRng). Validated by `parse_seed_hex` — the
    /// same gate as the CLI's `--seed-hex` — before a pack may start.
    seed_hex: String,
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
    /// Case-insensitive substring filter typed on the Pick screen.
    pick_filter: String,
    /// Indices into `pick_rows` that survive `pick_filter`.
    pick_view: Vec<usize>,
    /// Viewport height of the pick/export lists, measured at render time for
    /// PgUp/PgDn page steps.
    pick_viewport: u16,
    export_viewport: u16,
    pick_selected: usize,
    pick_state: ListState,
    export_state: ListState,
    details: HashMap<usize, DetailResult>,
    /// Rows whose lift is running on a background thread.
    pending_lift: HashSet<usize>,
    lift_tx: Sender<LiftMsg>,
    lift_rx: Receiver<LiftMsg>,
    /// `Some((mode, done, total))` while a bulk pre-lift runs in the background.
    bulk_busy: Option<(Bulk, usize, usize)>,
    /// Results already known when a bulk started (pre-computed details).
    bulk_staged: Option<(Bulk, Vec<(usize, bool, DetailResult)>)>,
    pe_bytes: Option<Arc<Vec<u8>>>,
    pack_rx: Option<Receiver<Result<PackDone, String>>>,
    pack_started: Option<Instant>,
    spinner_frame: usize,
    cancelled: bool,
    packing_exports: Vec<String>,
    outcome: Option<PackOutcome>,
    result_scroll: u16,
    /// Where the full failure chain was dumped (`last-error.txt`), set by
    /// `dump_last_error` when a pack fails. The Result screen shows it.
    failure_path: Option<PathBuf>,
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
        let (lift_tx, lift_rx) = channel();
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
            log: vec![
                LogLine::new(LogLevel::Info, "Xenolith TUI — press ? any time for the key map."),
                LogLine::new(
                    LogLevel::Info,
                    "Exports: space check · a/v/u all/invert/none. Options: space toggle · ←/→ profile. Tab cycles list→options→buttons.",
                ),
                LogLine::new(
                    LogLevel::Info,
                    "Type on the file picker to filter; Backspace goes up; drive roots list all drives.",
                ),
            ],
            log_scroll: 0,
            log_follow: true,
            dirty: false,
            confirm_quit: false,
            help: false,
            edit: None,
            seed_hex: String::new(),
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
            pick_filter: String::new(),
            pick_view: Vec::new(),
            pick_viewport: DEFAULT_PAGE,
            export_viewport: DEFAULT_PAGE,
            pick_selected: 0,
            pick_state: ListState::default(),
            export_state: ListState::default(),
            details: HashMap::new(),
            pending_lift: HashSet::new(),
            lift_tx,
            lift_rx,
            bulk_busy: None,
            bulk_staged: None,
            pe_bytes: None,
            pack_rx: None,
            pack_started: None,
            spinner_frame: 0,
            cancelled: false,
            packing_exports: Vec::new(),
            outcome: None,
            result_scroll: 0,
            failure_path: None,
        };
        app.reload_pick();
        if let Some(path) = input {
            if path.as_os_str().is_empty() {
                return Ok(app);
            }
            if let Err(e) = app.open_file(path) {
                app.log_error(format!("open failed: {e}"));
                app.log_warn("pick another file, or press ? for keys");
            }
        }
        Ok(app)
    }

    fn push_log(&mut self, msg: impl Into<String>) {
        self.log.push(LogLine::new(LogLevel::Info, msg));
        if self.log_follow {
            self.log_scroll = u16::MAX;
        }
    }

    fn log_line(&mut self, level: LogLevel, msg: impl Into<String>) {
        self.log.push(LogLine::new(level, msg));
        if self.log_follow {
            self.log_scroll = u16::MAX;
        }
    }

    fn log_ok(&mut self, msg: impl Into<String>) {
        self.log_line(LogLevel::Ok, msg);
    }

    fn log_warn(&mut self, msg: impl Into<String>) {
        self.log_line(LogLevel::Warn, msg);
    }

    fn log_error(&mut self, msg: impl Into<String>) {
        self.log_line(LogLevel::Error, msg);
    }

    fn mark_dirty(&mut self) {
        self.dirty = true;
    }

    fn reload_pick(&mut self) {
        match read_dir_sorted(&self.cwd) {
            Ok(rows) => {
                self.pick_rows = rows;
                self.rebuild_pick_view();
            }
            Err(e) => self.log_error(format!("read_dir {}: {e}", self.cwd.display())),
        }
    }

    fn enter_dir(&mut self, path: PathBuf) {
        match read_dir_sorted(&path) {
            Ok(rows) => {
                self.cwd = path;
                self.pick_rows = rows;
                // A new directory starts unfiltered: predictable over filters.
                self.pick_filter.clear();
                self.rebuild_pick_view();
            }
            Err(e) => self.log_error(format!("read_dir {}: {e}", path.display())),
        }
    }

    /// Recompute the visible pick rows from `pick_filter` (case-insensitive
    /// substring on the name). Reset the cursor to the top.
    fn rebuild_pick_view(&mut self) {
        let needle = self.pick_filter.to_lowercase();
        self.pick_view = self
            .pick_rows
            .iter()
            .enumerate()
            .filter(|(_, r)| {
                needle.is_empty() || r.name.to_lowercase().contains(&needle.as_str())
            })
            .map(|(i, _)| i)
            .collect();
        self.pick_selected = 0;
        self.sync_pick_state();
    }

    /// Append a character to the Pick filter.
    fn pick_filter_push(&mut self, c: char) {
        self.pick_filter.push(c);
        self.rebuild_pick_view();
    }

    /// Backspace on Pick: pop a filter char first, otherwise go up a directory.
    fn pick_backspace(&mut self) {
        if self.pick_filter.pop().is_some() {
            self.rebuild_pick_view();
            return;
        }
        self.pick_parent();
    }

    /// Enter with no visible rows: try the filter text as a path (directory
    /// jump or direct file open). Handles `C:` → `C:\` on Windows.
    fn pick_open_path_from_filter(&mut self) {
        let text = self.pick_filter.trim().to_string();
        if text.is_empty() {
            return;
        }
        let mut p = PathBuf::from(&text);
        let bytes = p.as_os_str().to_string_lossy().into_owned();
        if bytes.len() == 2 && bytes.as_bytes()[1] == b':' && bytes.as_bytes()[0].is_ascii_alphabetic()
        {
            p = PathBuf::from(format!("{}:\\", (bytes.as_bytes()[0] as char).to_ascii_uppercase()));
        }
        if p.is_dir() {
            self.enter_dir(p);
            return;
        }
        if p.is_file() {
            self.pick_filter.clear();
            self.rebuild_pick_view();
            if let Err(e) = self.open_file(p) {
                self.log_error(format!("open failed: {e}"));
            }
            return;
        }
        self.log_warn(format!(
            "'{text}' matches no entry here and is not a path"
        ));
    }

    fn sync_pick_state(&mut self) {
        if self.pick_view.is_empty() {
            self.pick_selected = 0;
            self.pick_state.select(None);
        } else {
            self.pick_selected = self.pick_selected.min(self.pick_view.len() - 1);
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
            self.log_warn("W1 cannot virtualize EXE entry; use a DLL export or wait for RVA selection");
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
        self.log_ok(format!(
            "loaded {} exports; import_rva={}",
            self.exports.len(),
            info.get("import_rva").unwrap_or(&serde_json::Value::Null)
        ));
        self.pe_bytes = Some(Arc::new(bytes));
        self.details.clear();
        self.pending_lift.clear();
        self.selected = 0;
        self.sync_export_state();
        self.ensure_detail(self.selected);
        Ok(())
    }

    fn selected_count(&self) -> usize {
        self.exports.iter().filter(|e| e.vm).count()
    }

    fn toggle_selected(&mut self) {
        if self.exports.is_empty() {
            return;
        }
        if self.bulk_busy.is_some() {
            self.log_warn("bulk pre-lift running; wait for it to finish (see Log)");
            return;
        }
        let i = self.selected.min(self.exports.len() - 1);
        if self.exports[i].native_locked {
            self.log_warn(format!("{} stays native (CRT/DllMain)", self.exports[i].name));
            return;
        }
        if self.exports[i].vm {
            self.exports[i].vm = false;
            self.mark_dirty();
            return;
        }
        if self.pending_lift.contains(&i) {
            return; // a check is already being verified for this row
        }
        // Optimistic check; the background lift un-checks and logs on failure.
        self.exports[i].vm = true;
        self.mark_dirty();
        self.ensure_detail(i);
        // Locked/no-bytes paths resolve inline; thread results land later in
        // poll_lifts, which also announces them.
        match self.details.get(&i) {
            Some(DetailResult::Err(e)) => {
                let err = e.clone();
                self.exports[i].vm = false;
                self.log_error(format!("lift failed: {err}"));
                self.log_warn(
                    "hint: allow-native-fallback (f) skips failing rows; strict-coverage (s) tightens instead",
                );
            }
            Some(DetailResult::Locked { reason }) => {
                let reason = reason.clone();
                self.exports[i].vm = false;
                self.log_warn(reason);
            }
            _ => {}
        }
    }

    /// Bulk All/Invert/None over the export list. Locked exports are skipped
    /// entirely; rows whose pre-lift fails stay unchecked. All/Invert lift
    /// unknown rows on a background thread with N/M progress in the Log title.
    fn bulk_set(&mut self, mode: Bulk) {
        if self.bulk_busy.is_some() {
            self.log_warn("bulk pre-lift already running; wait for it to finish");
            return;
        }
        if self.exports.is_empty() {
            self.push_log(format!(
                "bulk {}: no exports (ELF packs the whole image)",
                mode.as_str()
            ));
            return;
        }
        if mode == Bulk::None {
            let mut cleared = 0usize;
            for row in &mut self.exports {
                if row.vm {
                    row.vm = false;
                    cleared += 1;
                }
            }
            if cleared > 0 {
                self.mark_dirty();
            }
            let locked = self.exports.iter().filter(|e| e.native_locked).count();
            self.push_log(format!(
                "bulk none: 0 checked, {cleared} cleared, 0 failed pre-lift, {locked} locked skipped"
            ));
            return;
        }

        // Stage rows whose lift result we already know; send the rest to a
        // background thread.
        let mut staged: Vec<(usize, bool, DetailResult)> = Vec::new();
        let mut need: Vec<(usize, bool, String, u32)> = Vec::new();
        for (i, row) in self.exports.iter().enumerate() {
            if row.native_locked {
                continue;
            }
            let relevant = match mode {
                Bulk::All => !row.vm,
                Bulk::Invert => true,
                Bulk::None => false,
            };
            if !relevant {
                continue;
            }
            let was_vm = row.vm;
            match self.details.get(&i) {
                Some(d) => staged.push((i, was_vm, d.clone())),
                None => need.push((i, was_vm, row.name.clone(), row.rva)),
            }
        }
        if staged.is_empty() && need.is_empty() {
            self.push_log(format!("bulk {}: nothing to do", mode.as_str()));
            return;
        }
        if need.is_empty() {
            self.apply_bulk_results(mode, staged);
            return;
        }
        let Some(bytes) = self.pe_bytes.clone() else {
            for (i, was_vm, _, _) in need {
                staged.push((i, was_vm, DetailResult::Err("no image bytes".into())));
            }
            self.apply_bulk_results(mode, staged);
            return;
        };
        let total = need.len();
        self.bulk_busy = Some((mode, 0, total));
        self.bulk_staged = Some((mode, staged));
        let tx = self.lift_tx.clone();
        let _ = std::thread::Builder::new()
            .name("xl-bulk".into())
            .spawn(move || {
                let mut results = Vec::with_capacity(total);
                for (done, (idx, was_vm, name, rva)) in need.iter().enumerate() {
                    let result = lift_one(&bytes, name, *rva);
                    let _ = tx.send(LiftMsg::BulkStep {
                        done: done + 1,
                        total,
                    });
                    results.push((*idx, *was_vm, result));
                }
                let _ = tx.send(LiftMsg::BulkDone { mode, results });
            });
        self.log_line(
            LogLevel::Info,
            format!("bulk {}: pre-lifting 0/{total} in background…", mode.as_str()),
        );
    }

    /// Apply finished bulk results: checks survive only rows whose lift
    /// succeeded. `was_vm` rows on Invert are cleared exactly once.
    fn apply_bulk_results(&mut self, mode: Bulk, mut results: Vec<(usize, bool, DetailResult)>) {
        self.bulk_busy = None;
        if let Some((_, staged)) = self.bulk_staged.take() {
            results.extend(staged);
        }
        let mut checked = 0usize;
        let mut cleared = 0usize;
        let mut failed = 0usize;
        for (idx, was_vm, result) in results {
            let ok = matches!(result, DetailResult::Ok { .. });
            self.details.insert(idx, result);
            if mode == Bulk::Invert && was_vm {
                if self.exports[idx].vm {
                    self.exports[idx].vm = false;
                    cleared += 1;
                }
                continue;
            }
            match ok {
                true => {
                    self.exports[idx].vm = true;
                    checked += 1;
                }
                false => {
                    failed += 1;
                }
            }
        }
        let locked = self.exports.iter().filter(|e| e.native_locked).count();
        if checked + cleared > 0 {
            self.mark_dirty();
        }
        self.push_log(format!(
            "bulk {}: {checked} checked, {cleared} cleared, {failed} failed pre-lift, {locked} locked skipped",
            mode.as_str()
        ));
    }

    /// Ensure a lift detail exists for row `i`, computing it on a background
    /// thread when needed. Rows already locked or computed return instantly.
    fn ensure_detail(&mut self, i: usize) {
        if self.details.contains_key(&i)
            || self.pending_lift.contains(&i)
            || i >= self.exports.len()
        {
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
        let Some(bytes) = self.pe_bytes.clone() else {
            self.details
                .insert(i, DetailResult::Err("no image bytes".into()));
            return;
        };
        self.pending_lift.insert(i);
        let tx = self.lift_tx.clone();
        let _ = std::thread::Builder::new()
            .name("xl-lift".into())
            .spawn(move || {
                let result = lift_one(&bytes, &name, rva);
                let _ = tx.send(LiftMsg::Detail { idx: i, result });
            });
    }

    /// Drain finished background lifts. Checked rows announce their lift
    /// outcome in the Log (and un-check on failure); browse-only rows just
    /// fill the detail panel.
    fn poll_lifts(&mut self) {
        loop {
            match self.lift_rx.try_recv() {
                Ok(LiftMsg::Detail { idx, result }) => {
                    self.pending_lift.remove(&idx);
                    let announce = self.exports.get(idx).is_some_and(|e| e.vm);
                    let name = self.exports.get(idx).map(|e| e.name.clone());
                    let (ok, err_text, lock_text) = match &result {
                        DetailResult::Ok { blocks, .. } => (Some(*blocks), None, None),
                        DetailResult::Err(e) => (None, Some(e.clone()), None),
                        DetailResult::Locked { reason } => (None, None, Some(reason.clone())),
                    };
                    self.details.insert(idx, result);
                    match (ok, err_text, lock_text) {
                        (Some(blocks), _, _) => {
                            if announce {
                                self.log_ok(format!(
                                    "lift ok {} · {blocks} blocks",
                                    name.unwrap_or_default()
                                ));
                            }
                        }
                        (_, Some(e), _) => {
                            if announce {
                                if let Some(row) = self.exports.get_mut(idx) {
                                    row.vm = false;
                                }
                                self.log_error(format!("lift failed: {e}"));
                                self.log_warn(
                                    "hint: allow-native-fallback (f) skips failing rows; strict-coverage (s) tightens instead",
                                );
                            }
                        }
                        (_, _, Some(reason)) => {
                            if announce {
                                if let Some(row) = self.exports.get_mut(idx) {
                                    row.vm = false;
                                }
                                self.log_warn(reason);
                            }
                        }
                        _ => {}
                    }
                }
                Ok(LiftMsg::BulkStep { done, total }) => {
                    if let Some((_, d, t)) = self.bulk_busy.as_mut() {
                        *d = done;
                        *t = total;
                    }
                }
                Ok(LiftMsg::BulkDone { mode, results }) => {
                    self.apply_bulk_results(mode, results);
                }
                Err(TryRecvError::Empty) | Err(TryRecvError::Disconnected) => break,
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

    /// Where [Save project] will write, derived from the output path.
    fn project_path(&self) -> PathBuf {
        let mut p = self.output.clone();
        p.set_extension("xenolith.json");
        p
    }

    fn save_project(&mut self) -> Result<()> {
        if self.input.as_os_str().is_empty() {
            bail!("no input");
        }
        let path = self.project_path();
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
        self.dirty = false;
        self.log_ok(format!("saved {}", path.display()));
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
        self.mark_dirty();
        self.push_log(format!("profile = {}", next.as_str()));
    }

    fn set_profile(&mut self, p: ProfileArg) {
        self.profile = p;
        self.mark_dirty();
        self.push_log(format!("profile = {}", p.as_str()));
    }

    fn toggle_trace(&mut self) {
        self.trace_diverge = !self.trace_diverge;
        self.mark_dirty();
        self.push_log(format!(
            "trace-diverge = {}",
            on_off(self.trace_diverge)
        ));
    }

    fn toggle_lazy(&mut self) {
        self.lazy_regions = !self.lazy_regions;
        self.mark_dirty();
        self.push_log(format!("lazy-regions = {}", on_off(self.lazy_regions)));
    }

    fn toggle_imports(&mut self) {
        self.protect_imports = !self.protect_imports;
        self.mark_dirty();
        self.push_log(format!(
            "protect-imports = {}",
            on_off(self.protect_imports)
        ));
    }

    fn toggle_strict_constants(&mut self) {
        self.strict_constants = !self.strict_constants;
        self.mark_dirty();
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
        self.mark_dirty();
        self.push_log(format!(
            "strict-coverage = {}",
            on_off(self.strict_coverage)
        ));
    }

    fn toggle_select_all(&mut self) {
        self.select_all = !self.select_all;
        self.mark_dirty();
        self.push_log(format!("select-all = {}", on_off(self.select_all)));
    }

    fn toggle_native_fallback(&mut self) {
        self.allow_native_fallback = !self.allow_native_fallback;
        if self.allow_native_fallback {
            self.strict_coverage = false;
        }
        self.mark_dirty();
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
            self.log_warn("no input loaded — pick an image first");
            return;
        }
        if self.bulk_busy.is_some() {
            self.log_warn("bulk pre-lift running; wait for it to finish (see Log)");
            return;
        }
        let vm = self.vm_exports();
        if matches!(self.profile, ProfileArg::Fast) && !vm.is_empty() {
            self.log_warn("fast rejects --vm-export; switch to standard/max or uncheck VM exports");
            return;
        }
        let ranges = match project::parse_select_rva(&self.select_rva) {
            Ok(r) => r,
            Err(e) => {
                self.log_error(format!("select-rva: {e}"));
                return;
            }
        };
        // Fail-closed seed gate, identical to the CLI's `--seed-hex`: an
        // invalid seed must block the pack, not fall back to a random one.
        let seed = if self.seed_hex.trim().is_empty() {
            None
        } else {
            match parse_seed_hex(self.seed_hex.trim()) {
                Ok(s) => Some(s),
                Err(e) => {
                    self.log_error(format!("opcode-seed: {e}"));
                    return;
                }
            }
        };
        let bytes = match std::fs::read(&self.input) {
            Ok(b) => b,
            Err(e) => {
                self.log_error(format!("read {}: {e}", self.input.display()));
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
            seed,
            self.output.clone(),
        ) {
            Ok(rx) => {
                self.pack_rx = Some(rx);
                self.pack_started = Some(Instant::now());
                self.spinner_frame = 0;
                self.cancelled = false;
                self.packing_exports = vm;
                self.failure_path = None;
                self.screen = Screen::Packing;
                self.focus = Focus::Buttons;
                self.button = 0;
            }
            Err(e) => self.log_error(format!("spawn pack: {e}")),
        }
    }

    fn cancel_pack(&mut self) {
        self.cancelled = true;
        self.pack_rx = None;
        self.screen = Screen::Configure;
        self.focus = Focus::List;
        self.log_warn("pack cancelled; image discarded (worker may still finish)");
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
                        self.log_ok(format!(
                            "pack {} · {} vm · {} pages · {:.1}s",
                            done.output.display(),
                            done.report.vm_functions,
                            done.report.pages,
                            done.elapsed.as_secs_f32()
                        ));
                        self.dirty = false;
                        self.result_scroll = 0;
                        self.finish_result(PackOutcome::Success(done));
                    }
                    Err(e) => {
                        self.log_error(format!("write {}: {e}", done.output.display()));
                        self.finish_result(PackOutcome::Failure(format!(
                            "write {}: {e}",
                            done.output.display()
                        )));
                    }
                }
            }
            Ok(Err(e)) => {
                self.pack_rx = None;
                if !self.cancelled {
                    self.log_error(format!("pack failed: {e}"));
                    self.finish_result(PackOutcome::Failure(e));
                }
            }
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => {
                self.pack_rx = None;
                if !self.cancelled {
                    self.log_error("pack thread died");
                    self.finish_result(PackOutcome::Failure("pack thread died".into()));
                }
            }
        }
    }

    fn finish_result(&mut self, outcome: PackOutcome) {
        if let PackOutcome::Failure(msg) = &outcome {
            self.dump_last_error(msg);
        }
        self.outcome = Some(outcome);
        self.screen = Screen::Result;
        self.focus = Focus::Buttons;
        self.button = 0;
    }

    /// Persist the whole error chain to the fixed file so the scrollable
    /// Result screen is not the only copy. Prefers a `last-error.txt` next to
    /// the output (the directory the pack was headed for), falls back to the
    /// cwd when the output has no usable parent directory or the write there
    /// fails. Records the chosen path for the Result screen; a failed dump is
    /// logged, never fatal.
    fn dump_last_error(&mut self, msg: &str) {
        self.failure_path = None;
        let mut candidates: Vec<PathBuf> = Vec::new();
        if let Some(dir) = self.output.parent() {
            if !dir.as_os_str().is_empty() && dir.is_dir() {
                candidates.push(dir.join("last-error.txt"));
            }
        }
        candidates.push(
            std::env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .join("last-error.txt"),
        );
        for path in candidates {
            match std::fs::write(&path, format!("{msg}\n")) {
                Ok(()) => {
                    self.failure_path = Some(path);
                    return;
                }
                Err(e) => self.log_warn(format!("cannot write {}: {e}", path.display())),
            }
        }
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
        if self.pick_view.is_empty() {
            // Nothing matches the filter: treat Enter as "open typed path".
            self.pick_open_path_from_filter();
            return;
        }
        let view_i = self.pick_selected.min(self.pick_view.len() - 1);
        let row_i = self.pick_view[view_i];
        let row = self.pick_rows[row_i].clone();
        if row.is_dir {
            self.enter_dir(row.path);
        } else if let Err(e) = self.open_file(row.path) {
            self.log_error(format!("open failed: {e}"));
        }
    }

    fn pick_parent(&mut self) {
        if let Some(parent) = parent_of(&self.cwd) {
            self.enter_dir(parent);
        }
    }

    fn move_pick(&mut self, delta: isize) {
        if self.pick_view.is_empty() {
            return;
        }
        let n = self.pick_view.len() as isize;
        let next = (self.pick_selected as isize + delta).clamp(0, n - 1) as usize;
        self.pick_selected = next;
        self.pick_state.select(Some(next));
    }

    fn move_pick_page(&mut self, up: bool) {
        let page = self.pick_viewport.max(1) as isize;
        self.move_pick(if up { -page } else { page });
    }

    fn move_pick_edge(&mut self, end: bool) {
        if self.pick_view.is_empty() {
            return;
        }
        let next = if end { self.pick_view.len() - 1 } else { 0 };
        self.pick_selected = next;
        self.pick_state.select(Some(next));
    }

    fn move_export(&mut self, delta: isize) {
        if self.exports.is_empty() {
            return;
        }
        let n = self.exports.len() as isize;
        let next = (self.selected as isize + delta).clamp(0, n - 1) as usize;
        if next != self.selected {
            self.selected = next;
            self.export_state.select(Some(next));
            self.ensure_detail(next);
        }
    }

    fn move_export_page(&mut self, up: bool) {
        let page = self.export_viewport.max(1) as isize;
        self.move_export(if up { -page } else { page });
    }

    fn move_export_edge(&mut self, end: bool) {
        if self.exports.is_empty() {
            return;
        }
        let next = if end { self.exports.len() - 1 } else { 0 };
        self.selected = next;
        self.export_state.select(Some(next));
        self.ensure_detail(next);
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
                        self.log_error(format!("save error: {e}"));
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
            Action::PickEntry(view_i) => {
                if view_i < self.pick_view.len() {
                    self.pick_selected = view_i;
                    self.pick_state.select(Some(view_i));
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
                    self.log_error(format!("save error: {e}"));
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
            Action::Quit => self.quit_request(),
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

    /// Quit immediately unless there are unsaved changes, in which case the
    /// bottom confirmation bar appears first (Q quits, any other key stays).
    fn quit_request(&mut self) -> bool {
        if self.dirty && !self.confirm_quit {
            self.confirm_quit = true;
            return false;
        }
        true
    }

    fn scroll_log(&mut self, delta: isize) {
        self.log_follow = false;
        self.log_scroll = if delta < 0 {
            self.log_scroll.saturating_sub(delta.unsigned_abs() as u16)
        } else {
            self.log_scroll.saturating_add(delta as u16)
        };
    }

    fn scroll_result(&mut self, delta: isize) {
        self.result_scroll = if delta < 0 {
            self.result_scroll.saturating_sub(delta.unsigned_abs() as u16)
        } else {
            self.result_scroll.saturating_add(delta as u16)
        };
    }

    fn begin_edit(&mut self, target: EditTarget) {
        if self.bulk_busy.is_some() {
            self.log_warn("bulk pre-lift running; wait for it to finish");
            return;
        }
        let buf = match target {
            EditTarget::Output => self.output.to_string_lossy().into_owned(),
            // Seed always starts empty: the value is not shown elsewhere, and
            // an immediate Enter means "back to OsRng".
            EditTarget::Seed => String::new(),
        };
        self.edit = Some(Editor { target, buf });
    }

    /// Enter in the bottom-bar editor. Output commits any non-empty path;
    /// seed accepts 32 hex chars (the CLI `--seed-hex` gate) or clears back
    /// to OsRng when empty. Invalid seed input logs an inline error and keeps
    /// the editor open — nothing is committed, so nothing can be packed.
    fn accept_edit(&mut self) {
        let Some(editor) = self.edit.as_ref() else {
            return;
        };
        match editor.target {
            EditTarget::Output => {
                let text = editor.buf.trim().to_string();
                if text.is_empty() {
                    self.log_warn("output path empty; kept previous value");
                    return;
                }
                self.output = PathBuf::from(&text);
                self.mark_dirty();
                self.log_ok(format!("output = {}", self.output.display()));
                self.edit = None;
            }
            EditTarget::Seed => {
                let text = editor.buf.trim().to_string();
                if text.is_empty() {
                    self.seed_hex.clear();
                    self.mark_dirty();
                    self.log_ok("opcode-seed = OsRng (random per pack)".to_string());
                    self.edit = None;
                    return;
                }
                // Reuse the CLI validator so TUI and `--seed-hex` accept
                // exactly the same input.
                match parse_seed_hex(&text) {
                    Ok(_) => {
                        self.seed_hex = text.to_ascii_lowercase();
                        self.mark_dirty();
                        self.log_ok("opcode-seed set (32 hex, value hidden elsewhere)".to_string());
                        self.edit = None;
                    }
                    Err(e) => {
                        self.log_error(format!("opcode-seed rejected: {e}"));
                        // Editor stays open for correction; Esc cancels.
                    }
                }
            }
        }
    }

    /// Feed one key to the bottom-bar editor. Returns true when the key was
    /// consumed (edit mode swallows everything except quit-level controls).
    fn edit_key(&mut self, k: KeyEvent) -> bool {
        match k.code {
            KeyCode::Enter => {
                self.accept_edit();
                true
            }
            KeyCode::Esc => {
                self.edit = None;
                true
            }
            KeyCode::Backspace => {
                if let Some(editor) = self.edit.as_mut() {
                    editor.buf.pop();
                }
                true
            }
            KeyCode::Char(c)
                if !k
                    .modifiers
                    .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
            {
                if let Some(editor) = self.edit.as_mut() {
                    editor.buf.push(c);
                }
                true
            }
            _ => true, // arrows/Tab while editing: swallowed, no side effects
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
            Zone::Log => self.scroll_log(delta),
            Zone::Result => self.scroll_result(delta),
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

/// One pre-lift, runnable on any thread. Parses the PE once per call and maps
/// every failure into a renderable `DetailResult`.
fn lift_one(bytes: &[u8], name: &str, rva: u32) -> DetailResult {
    match Pe64::parse(bytes) {
        Ok(pe) => match lift_export(&pe, bytes, name, rva) {
            Ok(lifted) => DetailResult::Ok {
                native_len: lifted.native_len,
                blocks: lifted.ir.blocks.len(),
            },
            Err(e) => DetailResult::Err(e.to_string()),
        },
        Err(e) => DetailResult::Err(e.to_string()),
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
        app.poll_lifts();
        terminal.draw(|f| render::ui(f, app))?;
        let busy = app.screen == Screen::Packing
            || app.bulk_busy.is_some()
            || !app.pending_lift.is_empty();
        let timeout = if busy {
            Duration::from_millis(120)
        } else {
            Duration::from_millis(250)
        };
        if event::poll(timeout)? {
            match event::read()? {
                Event::Key(k) if k.kind == KeyEventKind::Press => {
                    if handle_key(app, k) {
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
        }
        if app.screen == Screen::Packing {
            // Advance the progress animation once per loop, not only on
            // poll timeouts, so it keeps moving while events stream in.
            app.spinner_frame = app.spinner_frame.wrapping_add(1);
            app.poll_pack();
        }
    }
}

fn handle_mouse(app: &mut App, m: MouseEvent) -> bool {
    // Overlays swallow clicks: close them instead of clicking through.
    if app.help {
        app.help = false;
        return false;
    }
    if app.confirm_quit {
        app.confirm_quit = false;
        return false;
    }
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

fn handle_key(app: &mut App, k: KeyEvent) -> bool {
    // Ctrl+C / Ctrl+Q always quit — raw mode turns the terminal's SIGINT off,
    // so these must be handled explicitly and must never fall through to a
    // letter binding (`c` toggles strict-constants!). An in-flight pack is
    // cancelled first.
    if k.modifiers.contains(KeyModifiers::CONTROL)
        && matches!(k.code, KeyCode::Char('c') | KeyCode::Char('q'))
    {
        if app.screen == Screen::Packing {
            app.cancel_pack();
        }
        return true;
    }
    // `?` overlay: any key closes it and is otherwise swallowed.
    if app.help {
        app.help = false;
        return false;
    }
    if k.code == KeyCode::Char('?') {
        app.help = true;
        return false;
    }
    // Quit confirmation bar: Q/Enter quits, anything else stays.
    if app.confirm_quit {
        if matches!(k.code, KeyCode::Char('Q') | KeyCode::Char('q') | KeyCode::Enter) {
            return true;
        }
        app.confirm_quit = false;
        return false;
    }
    // Output-path editor swallows all keys while open.
    if app.edit.is_some() {
        app.edit_key(k);
        return false;
    }

    match app.screen {
        Screen::Pick => match k.code {
            KeyCode::Esc => {
                if !app.pick_filter.is_empty() {
                    app.pick_filter.clear();
                    app.rebuild_pick_view();
                    false
                } else {
                    app.quit_request()
                }
            }
            // 'q' quits only from an empty filter; with filter text it must
            // reach the type-to-filter arm like any other character.
            KeyCode::Char('q') if app.pick_filter.is_empty() => app.quit_request(),
            KeyCode::Up => {
                app.move_pick(-1);
                false
            }
            KeyCode::Down => {
                app.move_pick(1);
                false
            }
            KeyCode::PageUp => {
                app.move_pick_page(true);
                false
            }
            KeyCode::PageDown => {
                app.move_pick_page(false);
                false
            }
            KeyCode::Home => {
                app.move_pick_edge(false);
                false
            }
            KeyCode::End => {
                app.move_pick_edge(true);
                false
            }
            KeyCode::Enter => {
                app.activate_pick();
                false
            }
            KeyCode::Backspace => {
                app.pick_backspace();
                false
            }
            KeyCode::Char(c)
                if !k
                    .modifiers
                    .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
            {
                // Type-to-filter (like fzf); Esc clears, Backspace pops.
                app.pick_filter_push(c);
                false
            }
            _ => false,
        },
        Screen::Configure => match k.code {
            KeyCode::Esc => {
                app.back_to_pick();
                false
            }
            KeyCode::Char('q') => app.quit_request(),
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
                    // Space activates a focused button too, matching form
                    // conventions (Enter keeps working).
                    Focus::Buttons => return app.activate_button(),
                }
                false
            }
            KeyCode::PageUp => {
                if app.focus == Focus::List {
                    app.move_export_page(true);
                } else {
                    app.scroll_log(-10);
                }
                false
            }
            KeyCode::PageDown => {
                if app.focus == Focus::List {
                    app.move_export_page(false);
                } else {
                    app.scroll_log(10);
                }
                false
            }
            KeyCode::Home => {
                if app.focus == Focus::List {
                    app.move_export_edge(false);
                } else {
                    app.log_follow = false;
                    app.log_scroll = 0;
                }
                false
            }
            KeyCode::End => {
                if app.focus == Focus::List {
                    app.move_export_edge(true);
                } else {
                    app.log_follow = true;
                    app.log_scroll = u16::MAX;
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
            KeyCode::Char('o') => {
                app.begin_edit(EditTarget::Output);
                false
            }
            KeyCode::Char('e') => {
                app.begin_edit(EditTarget::Seed);
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
        Screen::Packing => match k.code {
            KeyCode::Esc | KeyCode::Char('q') | KeyCode::Enter => {
                app.cancel_pack();
                false
            }
            _ => false,
        },
        Screen::Result => match k.code {
            KeyCode::Esc => {
                app.back_to_configure();
                false
            }
            KeyCode::Char('q') => app.quit_request(),
            KeyCode::Left => {
                app.move_button(-1);
                false
            }
            KeyCode::Right | KeyCode::Tab => {
                app.move_button(1);
                false
            }
            KeyCode::PageUp => {
                app.scroll_result(-10);
                false
            }
            KeyCode::PageDown => {
                app.scroll_result(10);
                false
            }
            KeyCode::Home => {
                app.result_scroll = 0;
                false
            }
            KeyCode::Char(' ') | KeyCode::Enter => app.activate_button(),
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
        handle_key(&mut app, KeyCode::Tab.into());
        assert_eq!(app.focus, Focus::Options);
        handle_key(&mut app, KeyCode::Tab.into());
        assert_eq!(app.focus, Focus::Buttons);
        handle_key(&mut app, KeyCode::Tab.into());
        assert_eq!(app.focus, Focus::List);
        handle_key(&mut app, KeyCode::BackTab.into());
        assert_eq!(app.focus, Focus::Buttons);
        handle_key(&mut app, KeyCode::BackTab.into());
        assert_eq!(app.focus, Focus::Options);
        handle_key(&mut app, KeyCode::BackTab.into());
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
        handle_key(&mut app, KeyCode::Down.into());
        assert_eq!(app.option_sel, 1);
        handle_key(&mut app, KeyCode::Down.into());
        assert_eq!(app.option_sel, 2);
        handle_key(&mut app, KeyCode::Up.into());
        assert_eq!(app.option_sel, 1);
        assert_eq!(app.focus, Focus::Options);
        assert_eq!(app.button, 0);
        // ...and in Buttons: Left/Right move buttons, Up/Down do not leave.
        app.focus = Focus::Buttons;
        handle_key(&mut app, KeyCode::Right.into());
        assert_eq!(app.button, 1);
        handle_key(&mut app, KeyCode::Down.into());
        assert_eq!(app.focus, Focus::Buttons);
        assert_eq!(app.button, 1);
        // In List: Left/Right are inert.
        app.focus = Focus::List;
        handle_key(&mut app, KeyCode::Right.into());
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
            handle_key(&mut app, key.into());
            assert!(get(&app), "{key:?} must toggle on");
            handle_key(&mut app, key.into());
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
        assert!(app.log.last().unwrap().text.contains("fast rejects"));
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
        assert!(app.log.last().unwrap().text.contains("select-rva"));
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
        assert!(app.log.last().unwrap().text.contains("bulk all: 1 checked"));

        app.bulk_set(Bulk::Invert);
        assert!(!app.exports[0].vm);
        assert!(!app.exports[1].vm);
        assert!(app.log.last().unwrap().text.contains("bulk invert:"));

        app.exports[0].vm = true;
        app.bulk_set(Bulk::None);
        assert!(!app.exports[0].vm);
        assert!(!app.exports[1].vm);
        assert!(!app.exports[2].vm);
        assert!(app.log.last().unwrap().text.contains("bulk none:"));
    }

    #[test]
    fn bulk_on_empty_export_list_is_a_logged_noop() {
        let mut app = configure_app();
        app.image_kind = Some(ImageKind::Elf64Dyn);
        app.bulk_set(Bulk::All);
        assert!(app.exports.is_empty());
        assert!(app.log.last().unwrap().text.contains("no exports"));
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
        assert!(app.log.iter().any(|l| l.text.contains("ignored")));
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
    fn ctrl_c_quits_without_toggling_strict_constants() {
        let mut app = configure_app();
        let k = KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL);
        assert!(handle_key(&mut app, k), "Ctrl+C quits");
        assert!(!app.strict_constants, "Ctrl+C must not toggle strict-constants");
    }

    #[test]
    fn ctrl_c_cancels_pack_then_quits() {
        let mut app = configure_app();
        app.screen = Screen::Packing;
        let k = KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL);
        assert!(handle_key(&mut app, k));
        assert!(app.cancelled, "in-flight pack must be cancelled");
        assert_eq!(app.screen, Screen::Configure, "cancel_pack ran before quit");
    }

    #[test]
    fn plain_c_still_toggles_strict_constants() {
        let mut app = configure_app();
        assert!(!handle_key(&mut app, KeyCode::Char('c').into()));
        assert!(app.strict_constants);
        assert!(!handle_key(&mut app, KeyCode::Char('c').into()));
        assert!(!app.strict_constants);
    }

    #[test]
    fn q_with_unsaved_changes_confirms_before_quitting() {
        let mut app = configure_app();
        app.toggle_trace();
        assert!(app.dirty);
        assert!(!handle_key(&mut app, KeyCode::Char('q').into()), "first q asks");
        assert!(app.confirm_quit);
        assert!(!handle_key(&mut app, KeyCode::Esc.into()), "Esc stays");
        assert!(!app.confirm_quit);
        assert!(!handle_key(&mut app, KeyCode::Char('q').into()));
        assert!(handle_key(&mut app, KeyCode::Char('Q').into()), "Q confirms quit");
    }

    #[test]
    fn clean_app_quits_without_confirm() {
        let mut app = configure_app();
        assert!(handle_key(&mut app, KeyCode::Char('q').into()));
        assert!(!app.confirm_quit);
    }

    #[test]
    fn dirty_clears_after_successful_save() {
        let mut app = configure_app();
        app.input = PathBuf::from("in.dll");
        app.output = std::env::temp_dir().join("xl-tui-dirty.dll");
        app.toggle_trace();
        assert!(app.dirty);
        app.save_project().unwrap();
        assert!(!app.dirty, "save must clear the dirty flag");
        let _ = fs::remove_file(app.project_path());
    }

    #[test]
    fn output_edit_accept_and_swallow() {
        let mut app = configure_app();
        app.begin_edit(EditTarget::Output);
        assert!(app.edit.is_some());
        // While editing, letters feed the buffer and never leak to toggles.
        assert!(!handle_key(&mut app, KeyCode::Char('x').into()));
        assert!(app.edit.is_some(), "editor must stay open");
        assert!(!app.strict_constants, "letter must not toggle anything");
        assert!(!handle_key(&mut app, KeyCode::Enter.into()));
        assert!(app.edit.is_none());
        assert!(app.dirty, "changing output marks dirty");
    }

    #[test]
    fn seed_edit_validates_inline_and_pack_gate_rejects_bad_seed() {
        let mut app = configure_app();
        app.input = PathBuf::from("whatever.dll");
        app.begin_edit(EditTarget::Seed);
        // Garbage seed: Enter is rejected inline, the editor stays open, and
        // nothing is committed.
        for c in "zz".chars() {
            handle_key(&mut app, KeyCode::Char(c).into());
        }
        assert!(!handle_key(&mut app, KeyCode::Enter.into()), "Enter consumed");
        assert!(app.edit.is_some(), "invalid seed keeps the editor open");
        assert!(app.seed_hex.is_empty(), "invalid seed must not commit");
        assert!(app.log.last().unwrap().text.contains("opcode-seed rejected"));
        // Even if state were reached some other way, start_pack refuses.
        app.edit = None;
        app.seed_hex = "nothex".into();
        app.start_pack();
        assert!(app.pack_rx.is_none(), "bad seed must not start a pack");
        assert!(app.log.last().unwrap().text.contains("opcode-seed"));

        // A valid 32-hex seed commits (normalized) and the editor closes.
        app.begin_edit(EditTarget::Seed);
        for c in "ABCDEF0123456789abcdef0123456789".chars() {
            handle_key(&mut app, KeyCode::Char(c).into());
        }
        assert!(!handle_key(&mut app, KeyCode::Enter.into()));
        assert!(app.edit.is_none());
        assert_eq!(app.seed_hex, "abcdef0123456789abcdef0123456789");

        // Emptying the buffer and accepting means OsRng again (the editor
        // prefills the current seed, so clear it first).
        app.begin_edit(EditTarget::Seed);
        if let Some(ed) = app.edit.as_mut() {
            ed.buf.clear();
        }
        assert!(!handle_key(&mut app, KeyCode::Enter.into()));
        assert!(app.seed_hex.is_empty(), "empty seed = OsRng");
        assert!(app.log.last().unwrap().text.contains("OsRng"));
    }

    #[test]
    fn failure_dump_prefers_output_dir_and_sets_path() {
        let mut app = configure_app();
        let dir = unique_dir("lasterr");
        app.output = dir.join("out.xl.dll");
        app.finish_result(PackOutcome::Failure("boom: root cause: deeper cause".into()));
        assert_eq!(app.screen, Screen::Result);
        let saved = app
            .failure_path
            .clone()
            .expect("dump path recorded on failure");
        assert_eq!(saved, dir.join("last-error.txt"));
        let text = fs::read_to_string(&saved).unwrap();
        assert!(text.contains("boom: root cause: deeper cause"), "{text}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn pick_filter_narrows_and_esc_clears_before_quitting() {
        let mut app = test_app();
        app.pick_rows = vec![
            DirRow {
                name: "alpha.dll".into(),
                path: PathBuf::from("alpha.dll"),
                is_dir: false,
                openable: true,
            },
            DirRow {
                name: "beta.dll".into(),
                path: PathBuf::from("beta.dll"),
                is_dir: false,
                openable: true,
            },
        ];
        app.rebuild_pick_view();
        assert_eq!(app.pick_view, vec![0, 1]);
        handle_key(&mut app, KeyCode::Char('a').into());
        handle_key(&mut app, KeyCode::Char('l').into());
        assert_eq!(app.pick_view, vec![0], "filter 'al' keeps only alpha");
        assert!(!handle_key(&mut app, KeyCode::Esc.into()), "Esc clears filter");
        assert!(app.pick_filter.is_empty());
        assert_eq!(app.pick_view, vec![0, 1]);
    }

    #[test]
    fn help_overlay_swallows_one_key_then_closes() {
        let mut app = configure_app();
        assert!(!handle_key(&mut app, KeyCode::Char('?').into()));
        assert!(app.help);
        assert!(!handle_key(&mut app, KeyCode::Char('x').into()));
        assert!(!app.help);
        assert!(!app.select_all, "key that closed help must not act");
    }

    #[test]
    fn space_activates_focused_button() {
        let mut app = configure_app();
        app.focus = Focus::Buttons;
        app.button = 3; // [Quit]
        assert!(handle_key(&mut app, KeyCode::Char(' ').into()));
    }

    #[test]
    fn lift_failure_unchecks_row_and_logs_hint() {
        let mut app = configure_app();
        app.exports = vec![row("broken", false)];
        app.sync_export_state();
        // Garbage bytes: the background lift thread fails and un-checks.
        app.pe_bytes = Some(std::sync::Arc::new(vec![0u8; 0]));
        handle_key(&mut app, KeyCode::Char(' ').into());
        assert!(app.exports[0].vm, "row is checked optimistically");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while app.bulk_busy.is_some() || !app.pending_lift.is_empty() {
            assert!(std::time::Instant::now() < deadline, "lift never finished");
            std::thread::sleep(std::time::Duration::from_millis(2));
            app.poll_lifts();
        }
        assert!(!app.exports[0].vm, "failed lift must un-check the row");
        assert!(app
            .log
            .iter()
            .any(|l| l.text.contains("lift failed") && l.level == LogLevel::Error));
        assert!(app.log.iter().any(|l| l.text.contains("hint:")));
    }

    #[test]
    fn bulk_all_reports_progress_and_finishes() {
        let mut app = configure_app();
        app.exports = vec![row("a", false), row("b", false), row("_crt", true)];
        app.sync_export_state();
        app.pe_bytes = Some(std::sync::Arc::new(vec![0u8; 0]));
        app.bulk_set(Bulk::All);
        assert!(app.bulk_busy.is_some(), "unknown rows lift in background");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while app.bulk_busy.is_some() {
            assert!(std::time::Instant::now() < deadline, "bulk never finished");
            std::thread::sleep(std::time::Duration::from_millis(2));
            app.poll_lifts();
        }
        assert!(!app.exports[0].vm && !app.exports[1].vm, "empty bytes fail all lifts");
        assert!(!app.exports[2].vm, "locked stays unchecked");
        assert!(app
            .log
            .iter()
            .any(|l| l.text.contains("bulk all:") && l.text.contains("2 failed pre-lift")));
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
