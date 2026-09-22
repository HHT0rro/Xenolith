//! Screen drawing plus hot-rect / scroll-zone capture.

use super::{
    Action, App, DetailResult, EditTarget, Focus, HotRect, LogLevel, LogLine, OptionRow,
    OPTION_ROWS, PackOutcome, Screen, Zone,
};
use crate::args::ProfileArg;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Wrap};
use ratatui::Frame;
use xenolith_formats::ImageKind;

const PROFILE_ORDER: [ProfileArg; 3] = [ProfileArg::Fast, ProfileArg::Standard, ProfileArg::Max];

/// Below this the layouts crush panels to zero height; show a hint instead.
const MIN_WIDTH: u16 = 80;
const MIN_HEIGHT: u16 = 24;

fn cyan() -> Style {
    Style::default().fg(Color::Cyan)
}

fn dim() -> Style {
    Style::default().fg(Color::DarkGray)
}

fn warn() -> Style {
    Style::default().fg(Color::Yellow)
}

fn bold(style: Style) -> Style {
    style.add_modifier(Modifier::BOLD)
}

/// Focused panels get a cyan border and a `◆` title marker; unfocused ones
/// stay plain so the cursor position is obvious at a glance.
fn panel(title: impl Into<String>, focused: bool) -> Block<'static> {
    let title = title.into();
    if focused {
        Block::default()
            .borders(Borders::ALL)
            .border_style(cyan())
            .title(Span::styled(
                format!("{title} ◆"),
                bold(cyan()),
            ))
    } else {
        Block::default().borders(Borders::ALL).title(title)
    }
}

pub fn ui(f: &mut Frame, app: &mut App) {
    app.hot.clear();
    app.scroll_zones.clear();
    let area = f.area();
    if area.width < MIN_WIDTH || area.height < MIN_HEIGHT {
        too_small(f, area);
        return;
    }
    match app.screen {
        Screen::Pick => pick(f, app),
        Screen::Configure => configure(f, app),
        Screen::Packing => packing(f, app),
        Screen::Result => result(f, app),
    }
    if app.edit.is_some() {
        edit_bar(f, app, area);
    }
    if app.help {
        help_overlay(f, app);
    }
    if app.confirm_quit {
        confirm_bar(f, area);
    }
}

fn too_small(f: &mut Frame, area: Rect) {
    let text = vec![
        Line::from(Span::styled("Terminal too small", bold(warn()))),
        Line::from(format!(
            "need ≥ {MIN_WIDTH}×{MIN_HEIGHT}, current {}×{}",
            area.width, area.height
        )),
        Line::from(Span::styled(
            "resize the window to continue",
            dim(),
        )),
    ];
    f.render_widget(
        Paragraph::new(text).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(warn())
                .title("Xenolith"),
        ),
        area,
    );
}

fn pick(f: &mut Frame, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(8),
            Constraint::Length(1),
            Constraint::Length(3),
        ])
        .split(f.area());

    let shown = app.pick_view.len();
    let total = app.pick_rows.len();
    let filter_note = if app.pick_filter.is_empty() {
        String::new()
    } else {
        format!("  filter: \"{}\" (Esc clears)", app.pick_filter)
    };
    let header = Paragraph::new(Line::from(vec![
        Span::raw(" "),
        Span::styled(app.cwd.display().to_string(), bold(cyan())),
        Span::styled(
            format!("  ·  {shown}/{total} shown{filter_note}"),
            dim(),
        ),
    ]))
    .block(panel("Directory — type to filter · PgUp/PgDn pages · drives listed at roots", false));
    f.render_widget(header, chunks[0]);

    let items: Vec<ListItem> = app
        .pick_view
        .iter()
        .filter_map(|&i| app.pick_rows.get(i))
        .map(|r| {
            let line = if r.is_dir {
                Line::from(Span::styled(format!("/ {}", r.name), cyan()))
            } else if r.openable {
                Line::from(format!("  {}", r.name))
            } else {
                Line::from(Span::styled(format!("  {}", r.name), dim()))
            };
            ListItem::new(line)
        })
        .collect();
    let list = List::new(items)
        .block(panel(
            "Files — dimmed = not an image (dll/exe/sys/ocx/cpl/scr/so/elf/project)",
            false,
        ))
        .highlight_style(bold(Style::default().bg(Color::Blue).fg(Color::White)))
        .highlight_symbol("▶ ");
    f.render_stateful_widget(list, chunks[1], &mut app.pick_state);
    push_list_hot(
        &mut app.hot,
        chunks[1],
        app.pick_state.offset(),
        app.pick_view.len(),
        Action::PickEntry,
    );
    app.scroll_zones.push((chunks[1], Zone::Pick));
    app.pick_viewport = inner_rect(chunks[1]).map(|r| r.height).unwrap_or(1);

    // Last message on its own line: errors get a full-width red banner so a
    // failed open can't hide behind the hint text.
    if let Some(last) = app.log.last() {
        let line = last_line(last);
        f.render_widget(Paragraph::new(line), chunks[2]);
    }

    let hints = Paragraph::new(Line::from(vec![
        Span::raw(" ↑/↓ move  Enter open  Backspace up/filter  "),
        Span::styled("? help", warn()),
        Span::raw("  Esc/q quit  "),
        Span::styled("Ctrl+C quit", dim()),
    ]))
    .block(Block::default().borders(Borders::ALL));
    f.render_widget(hints, chunks[3]);
}

/// One full-width line for the latest log entry (Pick bottom bar).
fn last_line(l: &LogLine) -> Line<'static> {
    let text = l.text.clone();
    match l.level {
        LogLevel::Error => Line::from(Span::styled(
            format!(" ✗ {text} "),
            Style::default().bg(Color::Red).fg(Color::White),
        )),
        LogLevel::Warn => Line::from(Span::styled(format!(" ⚠ {text} "), warn())),
        LogLevel::Ok => Line::from(Span::styled(format!(" ✓ {text} "), Style::default().fg(Color::Green))),
        LogLevel::Info => Line::from(Span::styled(format!(" {text} "), dim())),
    }
}

/// `C:\dir\name.dll` → `name.dll` (for header badges); falls back to the full
/// path when there is no file name.
fn bold_path(p: &std::path::Path) -> String {
    p.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| p.display().to_string())
}

fn kind_badge(kind: ImageKind) -> (&'static str, Style) {
    match kind {
        ImageKind::Pe64Dll => ("PE64 DLL", bold(cyan())),
        ImageKind::Pe64Exe => ("PE64 EXE", bold(cyan())),
        ImageKind::Elf64Exec => ("ELF64 EXEC", bold(cyan())),
        ImageKind::Elf64Dyn => ("ELF64 SO", bold(cyan())),
    }
}

fn configure(f: &mut Frame, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(17),
            Constraint::Min(3),
            Constraint::Length(3),
        ])
        .split(f.area());

    header(f, app, chunks[0]);

    let mid = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(chunks[1]);

    let left = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Min(3)])
        .split(mid[0]);
    export_toolbar(f, app, left[0]);

    let title = format!(
        "Exports — {} selected (space/click = VM)",
        app.selected_count()
    );
    let list_focused = app.focus == Focus::List;
    let items: Vec<ListItem> = app
        .exports
        .iter()
        .enumerate()
        .map(|(i, e)| ListItem::new(export_line(i, e, app)))
        .collect();
    let list = List::new(items)
        .block(panel(title, list_focused))
        .highlight_style(bold(Style::default().bg(Color::Blue).fg(Color::White)))
        .highlight_symbol("▶ ");
    f.render_stateful_widget(list, left[1], &mut app.export_state);
    push_list_hot(
        &mut app.hot,
        left[1],
        app.export_state.offset(),
        app.exports.len(),
        Action::ExportRow,
    );
    app.scroll_zones.push((left[1], Zone::Exports));
    app.export_viewport = inner_rect(left[1]).map(|r| r.height).unwrap_or(1);

    let right = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(6), Constraint::Min(13)])
        .split(mid[1]);
    detail(f, app, right[0]);
    options(f, app, right[1]);

    log_panel(f, app, chunks[2]);

    // Dynamic hint: the save target and pack-blocking reasons live right next
    // to the buttons that act on them.
    let mut hint = String::from("Tab/BackTab sections · Space · ←/→ · a/v/u · p/d/l/i/c/s/x/f · o output · e seed · PgUp/PgDn log · ? help");
    if app.bulk_busy.is_some() {
        hint = format!("⚠ bulk pre-lift running — pack waits · {hint}");
    } else if app.fast_vm_conflict() {
        hint = format!("⚠ Pack disabled: fast + VM exports — switch profile (p) or uncheck · {hint}");
    }
    let save_exists = app.project_path().exists();
    let save_label = if save_exists {
        "[Overwrite project]"
    } else {
        "[Save project]"
    };
    let mut disabled: Vec<usize> = Vec::new();
    if app.fast_vm_conflict() || app.bulk_busy.is_some() {
        disabled.push(0);
    }
    paint_buttons(
        f,
        app,
        chunks[3],
        &[
            ("[Pack]".to_string(), Action::Pack),
            (save_label.to_string(), Action::SaveProject),
            ("[Back]".to_string(), Action::Back),
            ("[Quit]".to_string(), Action::Quit),
        ],
        &format!(
            "save → {} · {hint}",
            app.project_path().display()
        ),
        &disabled,
    );
}

/// One export row: green bold `[x]` when VM'd, whole line dimmed when locked,
/// plus a lift-status glyph from the details cache (✓ / ✗ / …).
fn export_line(i: usize, e: &super::ExportRow, app: &App) -> Line<'static> {
    let base = if e.native_locked { dim() } else { Style::default() };
    let mark = if e.vm {
        Span::styled("[x] ", bold(Style::default().fg(Color::Green)))
    } else {
        Span::styled("[ ] ", base)
    };
    let name = Span::styled(e.name.clone(), if e.vm { bold(Style::default()) } else { base });
    let mut spans = vec![
        mark,
        name,
        Span::styled(format!("  ord={} rva={:#x}", e.ordinal, e.rva), dim()),
    ];
    if e.native_locked {
        spans.push(Span::styled(" (native)", dim()));
    }
    match app.details.get(&i) {
        Some(DetailResult::Ok { blocks, .. }) => spans.push(Span::styled(
            format!(" ✓ {blocks} blk"),
            Style::default().fg(Color::Green),
        )),
        Some(DetailResult::Err(err)) => spans.push(Span::styled(
            format!(" ✗ {err}"),
            Style::default().fg(Color::Red),
        )),
        Some(DetailResult::Locked { .. }) => {}
        None if app.pending_lift.contains(&i) => {
            spans.push(Span::styled(" … lifting", cyan()))
        }
        None => {}
    }
    Line::from(spans)
}

fn export_toolbar(f: &mut Frame, app: &mut App, area: Rect) {
    let style = Style::default().fg(Color::Cyan);
    let mut spans = Vec::new();
    let mut x = area.x;
    for (label, action) in [
        ("[All]", Action::BulkAll),
        ("[Invert]", Action::BulkInvert),
        ("[None]", Action::BulkNone),
    ] {
        spans.push(Span::styled(label, style));
        spans.push(Span::raw(" "));
        app.hot.push(HotRect {
            rect: Rect {
                x,
                y: area.y,
                width: label.len() as u16,
                height: 1,
            },
            action,
        });
        x = x.saturating_add(label.len() as u16 + 1);
    }
    spans.push(Span::styled(" a/v/u", dim()));
    if let Some((_, done, total)) = app.bulk_busy {
        spans.push(Span::styled(
            format!("  {} lifting {done}/{total} {}", app.spinner(), total),
            bold(warn()),
        ));
    }
    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn header(f: &mut Frame, app: &App, area: Rect) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Min(20), Constraint::Length(24)])
        .split(area);

    // Left: file name bold cyan in the body, full path in the title so long
    // paths stay reachable; kind badge + counts as a one-line summary.
    let name = bold_path(&app.input);
    let mut left_spans = vec![Span::raw(" "), Span::styled(name.clone(), bold(cyan()))];
    if let Some(kind) = app.image_kind {
        let (badge, style) = kind_badge(kind);
        left_spans.push(Span::styled(format!(" · {badge}"), style));
        if matches!(kind, ImageKind::Elf64Exec | ImageKind::Elf64Dyn) {
            left_spans.push(Span::styled(" · whole-image", dim()));
        } else {
            left_spans.push(Span::styled(
                format!(
                    " · {} exports · {} VM",
                    app.exports.len(),
                    app.selected_count()
                ),
                dim(),
            ));
        }
    }
    left_spans.push(Span::styled(
        format!("  →  {}", app.output.display()),
        dim(),
    ));
    if app.dirty {
        left_spans.push(Span::styled("  ● unsaved", warn()));
    }
    let left_title = if app.input.as_os_str().is_empty() {
        "Xenolith — no file".to_string()
    } else {
        format!("Xenolith — {}", app.input.display())
    };
    f.render_widget(
        Paragraph::new(Line::from(left_spans)).block(Block::default().borders(Borders::ALL).title(left_title)),
        cols[0],
    );

    let profile = Paragraph::new(Line::from(vec![
        Span::raw(" Profile: "),
        Span::styled(app.profile.as_str(), bold(warn())),
    ]))
    .block(Block::default().borders(Borders::ALL).title("profile → Options"));
    f.render_widget(profile, cols[1]);
}

fn detail(f: &mut Frame, app: &App, area: Rect) {
    let lines = if matches!(
        app.image_kind,
        Some(ImageKind::Elf64Exec) | Some(ImageKind::Elf64Dyn)
    ) {
        vec![
            Line::from("ELF image — whole-image sealing"),
            Line::from("--vm-export needs the SysV lift"),
            Line::from("(stage 5; not in this release)"),
            Line::from("selection stays empty; Pack is allowed"),
        ]
    } else if app.exports.is_empty() {
        vec![Line::from("no exports")]
    } else {
        let i = app.selected.min(app.exports.len() - 1);
        let e = &app.exports[i];
        let mut lines = vec![
            Line::from(Span::styled(e.name.clone(), bold(cyan()))),
            Line::from(format!("ordinal     {}", e.ordinal)),
            Line::from(format!("rva         {:#x}", e.rva)),
        ];
        match app.details.get(&i) {
            Some(DetailResult::Ok {
                native_len,
                blocks,
            }) => {
                lines.push(Line::from(format!("native_len  {native_len}")));
                lines.push(Line::from(Span::styled(
                    format!("pre-lift    {blocks} blocks"),
                    Style::default().fg(Color::Green),
                )));
                lines.push(Line::from("lock        —"));
            }
            Some(DetailResult::Locked { reason }) => {
                lines.push(Line::from("native_len  —"));
                lines.push(Line::from("pre-lift    —"));
                lines.push(Line::from(Span::styled(format!("lock        {reason}"), warn())));
            }
            Some(DetailResult::Err(err)) => {
                lines.push(Line::from("native_len  —"));
                lines.push(Line::from(Span::styled("pre-lift    lift failed", Style::default().fg(Color::Red))));
                lines.push(Line::from(Span::styled(err.as_str(), Style::default().fg(Color::Red))));
            }
            None if app.pending_lift.contains(&i) => {
                lines.push(Line::from(Span::styled(
                    format!("pre-lift    {} lifting…", app.spinner()),
                    cyan(),
                )));
            }
            None => lines.push(Line::from("detail pending")),
        }
        lines
    };
    f.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: true })
            .block(panel("Export detail", false)),
        area,
    );
}

fn options(f: &mut Frame, app: &mut App, area: Rect) {
    let Some(inner) = inner_rect(area) else {
        return;
    };
    let focus_here = app.focus == Focus::Options;
    let dim = dim();

    // Line index -> hot rect, plus profile token rects. Rows come first in a
    // fixed order so the rect lookup in the click handler stays trivial.
    let mut lines: Vec<Line> = Vec::with_capacity(16);

    for (i, row) in OPTION_ROWS.iter().enumerate() {
        let selected = focus_here && i == app.option_sel;
        let hl = if selected {
            Style::default().bg(Color::DarkGray)
        } else {
            Style::default()
        };
        let mut spans: Vec<Span> = Vec::new();
        if i == 0 {
            spans.push(Span::styled("profile      ", hl));
            let mut tx = inner.x + 13;
            for p in PROFILE_ORDER {
                let active = profile_is(app.profile, p);
                let text = if active {
                    format!("[{}]", p.as_str())
                } else {
                    format!(" {} ", p.as_str())
                };
                let w = text.len() as u16;
                let style = if active {
                    bold(warn())
                } else {
                    hl
                };
                spans.push(Span::styled(text, style));
                // Token rects win over the row rect (clicks are searched in
                // reverse insertion order).
                app.hot.push(HotRect {
                    rect: Rect {
                        x: tx,
                        y: inner.y,
                        width: w,
                        height: 1,
                    },
                    action: Action::ProfilePick(p),
                });
                tx = tx.saturating_add(w);
            }
            spans.push(Span::styled("  ←/→", dim));
        } else {
            let on = match row {
                OptionRow::TraceDiverge => app.trace_diverge,
                OptionRow::LazyRegions => app.lazy_regions,
                OptionRow::ProtectImports => app.protect_imports,
                OptionRow::StrictConstants => app.strict_constants,
                OptionRow::StrictCoverage => app.strict_coverage,
                OptionRow::SelectAll => app.select_all,
                OptionRow::AllowNativeFallback => app.allow_native_fallback,
                OptionRow::Profile => false,
            };
            let key = match row {
                OptionRow::TraceDiverge => 'd',
                OptionRow::LazyRegions => 'l',
                OptionRow::ProtectImports => 'i',
                OptionRow::StrictConstants => 'c',
                OptionRow::StrictCoverage => 's',
                OptionRow::SelectAll => 'x',
                OptionRow::AllowNativeFallback => 'f',
                OptionRow::Profile => 'p',
            };
            let mark = if on { "[x]" } else { "[ ]" };
            let mark_style = if on {
                bold(hl.fg(Color::Green))
            } else {
                hl
            };
            spans.push(Span::styled(format!("{mark} "), mark_style));
            spans.push(Span::styled(format!("{:<12}", row.label()), hl));
            spans.push(Span::styled(format!("({key})"), dim));
        }
        lines.push(Line::from(spans));
        app.hot.push(HotRect {
            rect: Rect {
                x: inner.x,
                y: inner.y + i as u16,
                width: inner.width,
                height: 1,
            },
            action: Action::OptionClick(i),
        });
    }

    if app.fast_vm_conflict() {
        lines.push(Line::from(Span::styled(
            "⚠ fast + VM exports: Pack rejects this",
            bold(warn()),
        )));
    }
    if app.fast_imports_note() {
        lines.push(Line::from(Span::styled(
            "⚠ protect-imports idle on fast:",
            warn(),
        )));
        lines.push(Line::from(Span::styled(
            "  disk IAT stays plaintext",
            warn(),
        )));
    }

    // Read-only capability summary, visually separated from the clickable
    // switches above: divider line, darker style, ⓘ prefix.
    let hashed = matches!(app.profile, ProfileArg::Standard | ProfileArg::Max);
    let probes = matches!(app.profile, ProfileArg::Max);
    lines.push(Line::from(Span::styled(
        "─ capabilities ──────────────",
        dim,
    )));
    lines.push(Line::from(Span::styled(
        if hashed {
            "ⓘ hashed IAT (std/max)"
        } else {
            "ⓘ IAT kept (fast)"
        },
        dim,
    )));
    lines.push(Line::from(Span::styled("ⓘ stolen OEP · integrity FNV", dim)));
    lines.push(Line::from(Span::styled(
        if probes {
            "ⓘ probes (max only)"
        } else {
            "ⓘ probes off"
        },
        dim,
    )));
    if app.select_rva.is_empty() {
        lines.push(Line::from(Span::styled(
            "ⓘ select-rva — (project only)",
            dim,
        )));
    } else {
        lines.push(Line::from(Span::styled(
            format!("ⓘ select-rva {} range(s):", app.select_rva.len()),
            dim,
        )));
        for r in app.select_rva.iter().take(4) {
            lines.push(Line::from(Span::styled(format!("ⓘ   {r}"), dim)));
        }
        if app.select_rva.len() > 4 {
            lines.push(Line::from(Span::styled(
                format!("ⓘ   +{} more", app.select_rva.len() - 4),
                dim,
            )));
        }
    }
    if !app.select_functions.is_empty() {
        lines.push(Line::from(Span::styled(
            format!("ⓘ select-functions {} (project)", app.select_functions.len()),
            dim,
        )));
    }
    // Seed status without echoing the value: empty means the runtime draws a
    // random seed (OsRng) per pack, exactly like omitting `--seed-hex`.
    lines.push(Line::from(Span::styled(
        if app.seed_hex.is_empty() {
            "ⓘ opcode-seed OsRng (e to set)"
        } else {
            "ⓘ opcode-seed set (32 hex, hidden)"
        },
        dim,
    )));
    lines.push(Line::from(Span::styled("ⓘ C2 not armed", dim)));

    f.render_widget(
        Paragraph::new(lines).block(panel(
            "Options (space/enter · ←/→ profile)",
            focus_here,
        )),
        area,
    );
}

fn profile_is(actual: ProfileArg, candidate: ProfileArg) -> bool {
    matches!(
        (actual, candidate),
        (ProfileArg::Fast, ProfileArg::Fast)
            | (ProfileArg::Standard, ProfileArg::Standard)
            | (ProfileArg::Max, ProfileArg::Max)
    )
}

/// Braille-wave indeterminate bar: `pack()` exposes no progress callback, so
/// this shows motion plus elapsed time instead of a fake percentage.
fn indeterminate_bar(width: usize, frame: usize) -> String {
    if width == 0 {
        return String::new();
    }
    let mut bar: Vec<char> = vec!['·'; width];
    let window = (width / 4).clamp(3, 12);
    let pos = frame % (width + window);
    for k in 0..window {
        let p = pos as isize - k as isize;
        if p >= 0 && (p as usize) < width {
            bar[p as usize] = if k == 0 { '█' } else { '▓' };
        }
    }
    bar.into_iter().collect()
}

fn packing(f: &mut Frame, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(8), Constraint::Length(3)])
        .split(f.area());
    let inner_w = inner_rect(chunks[0])
        .map(|r| r.width as usize)
        .unwrap_or(40)
        .saturating_sub(2);

    let elapsed = app
        .pack_started
        .map(|t| t.elapsed().as_secs_f32())
        .unwrap_or(0.0);
    let mut lines = vec![
        Line::from(Span::styled(
            format!("{} packing  {:.1}s", app.spinner(), elapsed),
            bold(Style::default().fg(Color::Cyan)),
        )),
        Line::from(Span::styled(
            indeterminate_bar(inner_w, app.spinner_frame),
            Style::default().fg(Color::Cyan),
        )),
        Line::from(""),
        Line::from(format!(
            "profile={}  trace={}  lazy={}  imports={}  consts={}  strictcov={}  fallback={}  select-all={}  rva={} rng  fns={}",
            app.profile.as_str(),
            on_off(app.trace_diverge),
            on_off(app.lazy_regions),
            on_off(app.protect_imports),
            on_off(app.strict_constants),
            on_off(app.strict_coverage),
            on_off(app.allow_native_fallback),
            on_off(app.select_all),
            app.select_rva.len(),
            app.select_functions.len(),
        )),
        Line::from(format!("output  {}", app.output.display())),
        Line::from(format!(
            "VM exports: {}",
            if app.packing_exports.is_empty() {
                "(none)".to_string()
            } else {
                app.packing_exports.len().to_string()
            }
        )),
    ];
    for name in app.packing_exports.iter().take(8) {
        lines.push(Line::from(Span::styled(format!("  {name}"), dim())));
    }
    if app.packing_exports.len() > 8 {
        lines.push(Line::from(Span::styled(
            format!("  +{} more", app.packing_exports.len() - 8),
            dim(),
        )));
    }
    lines.push(Line::from(""));
    if elapsed > 10.0 {
        lines.push(Line::from(Span::styled(
            format!(
                "still working… {:.0}s — large images can take minutes; pack runs lift → seal → encrypt",
                elapsed
            ),
            bold(warn()),
        )));
    }
    lines.push(Line::from(Span::styled(
        "Cancel discards the image and does not write. pack() has no interrupt hook; the worker may still finish.",
        dim(),
    )));
    f.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: true })
            .block(panel("Packing", false)),
        chunks[0],
    );
    paint_buttons(
        f,
        app,
        chunks[1],
        &[("[Cancel]".to_string(), Action::Cancel)],
        "Esc cancel · Ctrl+C cancel + quit",
        &[],
    );
}

fn result(f: &mut Frame, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(8), Constraint::Length(3)])
        .split(f.area());

    let dim = dim();
    let success_body: Option<Vec<Line>> = match &app.outcome {
        Some(PackOutcome::Success(done)) => {
            let r = &done.report;
            let mut lines = vec![
                Line::from(Span::styled(
                    "pack ok",
                    bold(Style::default().fg(Color::Green)),
                )),
                Line::from(format!("profile      {}", r.profile)),
                Line::from(format!("format       {}", r.format)),
                Line::from(format!("backend      {}", r.backend)),
                Line::from(Span::styled(
                    format!(
                        "size         {} -> {} B ({:.2}x)",
                        r.input_bytes,
                        r.output_bytes,
                        r.output_bytes as f64 / r.input_bytes.max(1) as f64
                    ),
                    cyan(),
                )),
                Line::from(format!("pages        {}", r.pages)),
                Line::from(Span::styled(
                    format!("vm_functions {}", r.vm_functions),
                    cyan(),
                )),
                Line::from(format!("selected     {}", join_names(&r.selected_functions))),
                Line::from(format!("stolen_bytes {}", r.stolen_bytes)),
                Line::from(format!("iat_mode     {}", r.iat_mode)),
                Line::from(Span::styled(
                    format!(
                        "imports      sealed={} protected={} kept={}",
                        r.import_names_sealed, r.imports_protected, r.imports_kept
                    ),
                    Style::default().fg(Color::Green),
                )),
            ];
            if !r.imports_kept_reason.is_empty() {
                lines.push(Line::from(Span::styled(
                    format!("  kept because: {}", r.imports_kept_reason),
                    dim,
                )));
            }
            lines.push(Line::from(format!(
                "constants    cand={} protectable={} encrypted={} native_ref={}",
                r.constants_candidates,
                r.constants_protectable,
                r.constants_encrypted,
                r.constants_native_referenced
            )));
            lines.push(Line::from(format!(
                "strict_coverage={} aslr={} long_term_rwx={}",
                r.strict_coverage, r.aslr, r.long_term_rwx
            )));
            lines.push(Line::from(format!(
                "decrypt_win  {}  seed_len {}",
                r.runtime_decryption_window, r.seed_len
            )));
            // Keep the tail visible: output path + elapsed are the two facts
            // users actually need, so they come before the notes.
            lines.push(Line::from(Span::styled(
                format!("output       {}", done.output.display()),
                bold(Style::default().fg(Color::Green)),
            )));
            lines.push(Line::from(format!(
                "elapsed      {:.1}s",
                done.elapsed.as_secs_f32()
            )));
            for note in &r.notes {
                lines.push(Line::from(Span::styled(format!("note {}", note), dim)));
            }
            Some(lines)
        }
        _ => None,
    };
    let failure_body = match &app.outcome {
        Some(PackOutcome::Failure(err)) => Some(err.clone()),
        _ => None,
    };

    if let Some(mut body) = success_body {
        let area0 = chunks[0];
        let inner_h = area0.height.saturating_sub(2) as usize;
        let max_scroll = body.len().saturating_sub(inner_h) as u16;
        app.result_scroll = app.result_scroll.min(max_scroll);
        if app.result_scroll < max_scroll {
            body.push(Line::from(Span::styled(
                format!(
                    "… PgDn scrolls ({}/{} lines hidden)",
                    body.len() - inner_h,
                    body.len()
                ),
                dim,
            )));
        }
        f.render_widget(
            Paragraph::new(body)
                .scroll((app.result_scroll, 0))
                .wrap(Wrap { trim: true })
                .block(panel("Result — PgUp/PgDn or wheel scrolls", false)),
            area0,
        );
        app.scroll_zones.push((area0, Zone::Result));
        paint_buttons(
            f,
            app,
            chunks[1],
            &[
                ("[Pack again]".to_string(), Action::PackAnother),
                ("[Save project]".to_string(), Action::SaveProject),
                ("[Quit]".to_string(), Action::Quit),
            ],
            "Enter/Space confirm · ←/→ move · Esc back to configure",
            &[],
        );
    } else if let Some(err) = failure_body {
        let mut body = vec![
            Line::from(Span::styled(
                "pack failed",
                bold(Style::default().fg(Color::Red)),
            )),
            Line::from(""),
            Line::from(Span::styled(err.as_str(), Style::default().fg(Color::Red))),
        ];
        // The full chain is also on disk; point at the file so a long chain
        // can be read in a pager even if this window is small.
        if let Some(p) = &app.failure_path {
            body.push(Line::from(Span::styled(
                format!("full error saved to {}", p.display()),
                bold(warn()),
            )));
        }
        body.push(Line::from(""));
        body.push(Line::from(Span::styled("next steps:", bold(warn()))));
        for hint in failure_hints(&err) {
            body.push(Line::from(Span::styled(hint, warn())));
        }
        body.push(Line::from(Span::styled(
            "PgUp/PgDn (or mouse wheel) scrolls the full chain",
            dim,
        )));
        body.push(Line::from(Span::styled(
            "Esc returns to Configure — switches, selection and output path all survive.",
            dim,
        )));
        let area0 = chunks[0];
        let inner_h = area0.height.saturating_sub(2) as usize;
        let max_scroll = body.len().saturating_sub(inner_h) as u16;
        app.result_scroll = app.result_scroll.min(max_scroll);
        if app.result_scroll < max_scroll {
            body.push(Line::from(Span::styled(
                format!(
                    "… PgDn scrolls ({}/{} lines hidden)",
                    body.len() - inner_h,
                    body.len()
                ),
                dim,
            )));
        }
        f.render_widget(
            Paragraph::new(body)
                .scroll((app.result_scroll, 0))
                .wrap(Wrap { trim: false })
                .block(panel("Result — full error chain · PgUp/PgDn scrolls", false)),
            area0,
        );
        app.scroll_zones.push((area0, Zone::Result));
        paint_buttons(
            f,
            app,
            chunks[1],
            &[
                ("[Back]".to_string(), Action::Back),
                ("[Quit]".to_string(), Action::Quit),
            ],
            "Enter/Space confirm · Esc back to configure",
            &[],
        );
    } else {
        f.render_widget(
            Paragraph::new("no result").block(Block::default().borders(Borders::ALL)),
            chunks[0],
        );
    }
}

/// Map a pack error chain onto concrete next actions in the TUI.
fn failure_hints(err: &str) -> Vec<&'static str> {
    let e = err.to_lowercase();
    let mut hints = Vec::new();
    if e.contains("fast") {
        hints.push("· fast profile rejects VM exports — press p to switch profile");
    }
    if e.contains("native") || e.contains("lift") || e.contains("vm-export") {
        hints.push("· enable allow-native-fallback (f) to keep failing exports native");
    }
    if e.contains("coverage") {
        hints.push("· strict-coverage (s) is on — relax it, or drop the failing selection");
    }
    if e.contains("os error") || e.contains("denied") || e.contains("write") || e.contains("read")
    {
        hints.push("· check the path exists and is writable — press o on Configure to change it");
    }
    if e.contains("select-rva") {
        hints.push("· select-rva comes from the project file — fix the RVA:LEN ranges there");
    }
    if hints.is_empty() {
        hints.push("· Esc back, adjust options, and check the Log for the earlier steps");
    }
    hints
}

/// Keep the selected list to five visible names; the rest collapse so the
/// result summary never pushes `output`/`elapsed` off screen.
fn join_names(names: &[String]) -> String {
    if names.is_empty() {
        return "—".into();
    }
    if names.len() <= 5 {
        return names.join(", ");
    }
    format!(
        "{}, +{} more ({} total)",
        names[..5].join(", "),
        names.len() - 5,
        names.len()
    )
}

fn on_off(v: bool) -> &'static str {
    if v {
        "on"
    } else {
        "off"
    }
}

fn log_panel(f: &mut Frame, app: &mut App, area: Rect) {
    let inner_h = area.height.saturating_sub(2);
    let max_scroll = (app.log.len() as u16).saturating_sub(inner_h);
    if app.log_follow {
        app.log_scroll = max_scroll;
    } else {
        app.log_scroll = app.log_scroll.min(max_scroll);
        if app.log_scroll >= max_scroll {
            app.log_follow = true;
        }
    }
    let title = if app.log_follow {
        "Log — PgUp/PgDn scrolls back".to_string()
    } else {
        format!(
            "Log — line {}/{} (End/PgDn to follow)",
            (app.log_scroll + inner_h).min(app.log.len() as u16),
            app.log.len()
        )
    };
    let lines: Vec<Line> = app
        .log
        .iter()
        .map(|l| match l.level {
            LogLevel::Error => Line::from(Span::styled(l.text.as_str(), Style::default().fg(Color::Red))),
            LogLevel::Warn => Line::from(Span::styled(l.text.as_str(), warn())),
            LogLevel::Ok => {
                Line::from(Span::styled(l.text.as_str(), Style::default().fg(Color::Green)))
            }
            LogLevel::Info => Line::from(l.text.as_str()),
        })
        .collect();
    f.render_widget(
        Paragraph::new(lines)
            .scroll((app.log_scroll, 0))
            .block(panel(title, false)),
        area,
    );
    app.scroll_zones.push((area, Zone::Log));
}

/// Bottom strip for the editors (`o` output path, `e` opcode seed).
fn edit_bar(f: &mut Frame, app: &mut App, area: Rect) {
    let Some(editor) = app.edit.as_ref() else {
        return;
    };
    let (title, header) = match editor.target {
        EditTarget::Output => (
            "edit output",
            " Output path — Enter accept · Esc cancel",
        ),
        EditTarget::Seed => (
            "edit opcode seed",
            " Opcode seed — 32 hex chars · empty = OsRng · Enter accept · Esc cancel",
        ),
    };
    let rect = Rect {
        x: 0,
        y: area.height.saturating_sub(3),
        width: area.width,
        height: 3,
    };
    let lines = vec![
        Line::from(Span::styled(header, bold(warn()))),
        Line::from(Span::styled(
            format!(" > {}", editor.buf),
            Style::default().fg(Color::White),
        )),
    ];
    f.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(warn())
                .title(title),
        ),
        rect,
    );
}

fn confirm_bar(f: &mut Frame, area: Rect) {
    let rect = Rect {
        x: 0,
        y: area.height.saturating_sub(1),
        width: area.width,
        height: 1,
    };
    f.render_widget(
        Paragraph::new(Span::styled(
            " Unsaved changes — Q quit · any other key stays",
            bold(Style::default().bg(Color::Yellow).fg(Color::Black)),
        )),
        rect,
    );
}

fn help_overlay(f: &mut Frame, app: &App) {
    let lines: Vec<Line> = match app.screen {
        Screen::Pick => vec![
            keys("↑/↓ · PgUp/PgDn · Home/End", "move in the file list"),
            keys("Enter", "open file / enter dir"),
            keys("a-z, 0-9 …", "type to filter by name"),
            keys("Backspace", "pop filter char, else parent dir"),
            keys("Esc", "clear filter first, then quit"),
            keys("Enter (empty list)", "open the filter text as a path"),
            keys("q / Ctrl+C", "quit (q asks when unsaved)"),
        ],
        Screen::Configure => vec![
            keys("Tab / BackTab", "cycle focus: list → options → buttons"),
            keys("↑/↓", "move in the focused section"),
            keys("←/→", "step profile (options) or buttons"),
            keys("Space / Enter", "check row · toggle option · press button"),
            keys("a / v / u", "select all / invert / none (background pre-lift)"),
            keys("p", "cycle profile fast/standard/max"),
            keys("d l i c s x f", "trace · lazy · imports · consts · strictcov · select-all · fallback"),
            keys("o", "edit output path (Enter accept, Esc cancel)"),
            keys("e", "edit opcode seed (32 hex, empty = OsRng)"),
            keys("PgUp/PgDn · Home/End", "scroll the Log"),
            keys("Esc", "back to the file picker"),
            keys("q", "quit — asks when there are unsaved changes"),
            keys("Ctrl+C / Ctrl+Q", "quit immediately (cancels a running pack)"),
        ],
        Screen::Packing => vec![
            keys("Esc / q / Enter", "cancel — image discarded, worker may finish"),
            keys("Ctrl+C / Ctrl+Q", "cancel and quit immediately"),
            keys("", "pack() has no interrupt hook; progress is indeterminate"),
        ],
        Screen::Result => vec![
            keys("←/→ · Tab", "move between buttons"),
            keys("Enter / Space", "activate button"),
            keys("PgUp/PgDn · wheel", "scroll the report"),
            keys("p", "pack again (after success)"),
            keys("Esc", "back to configure — settings survive"),
            keys("q / Ctrl+C", "quit"),
        ],
    };
    let height = (lines.len() as u16 + 2).min(20);
    let area = centered(f.area(), 72, height);
    f.render_widget(Clear, area);
    f.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(cyan())
                .title("? Keys — press any key to close"),
        ),
        area,
    );
}

fn keys(key: &str, desc: &str) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!(" {key:<22}"), bold(cyan())),
        Span::raw(desc.to_string()),
    ])
}

fn centered(area: Rect, w: u16, h: u16) -> Rect {
    let w = w.min(area.width.saturating_sub(2));
    let h = h.min(area.height.saturating_sub(2));
    Rect {
        x: area.x + (area.width.saturating_sub(w)) / 2,
        y: area.y + (area.height.saturating_sub(h)) / 2,
        width: w,
        height: h,
    }
}

fn paint_buttons(
    f: &mut Frame,
    app: &mut App,
    area: Rect,
    items: &[(String, Action)],
    hint: &str,
    disabled: &[usize],
) {
    let focus_buttons = app.focus == Focus::Buttons || app.screen != Screen::Configure;
    let mut spans = Vec::new();
    let inner = inner_rect(area);
    let mut x = inner.map(|r| r.x).unwrap_or(area.x);
    let y = inner.map(|r| r.y).unwrap_or(area.y);
    for (i, (label, action)) in items.iter().enumerate() {
        let on = focus_buttons && i == app.button;
        let off = disabled.contains(&i);
        spans.push(btn(label, on, off));
        spans.push(Span::raw("  "));
        let w = label.len() as u16;
        if inner.is_some() && !off {
            app.hot.push(HotRect {
                rect: Rect {
                    x,
                    y,
                    width: w,
                    height: 1,
                },
                action: *action,
            });
        }
        x = x.saturating_add(w + 2);
    }
    spans.push(Span::raw("  "));
    spans.push(Span::styled(hint.to_string(), dim()));
    f.render_widget(
        Paragraph::new(Line::from(spans)).block(Block::default().borders(Borders::ALL)),
        area,
    );
}

fn btn(label: &str, on: bool, disabled: bool) -> Span<'static> {
    let label = label.to_string();
    if disabled {
        return Span::styled(label, dim());
    }
    if on {
        Span::styled(label, bold(Style::default().bg(Color::Blue).fg(Color::White)))
    }
    // Unfocused buttons stay visible (yellow) instead of looking like hint text.
    else {
        Span::styled(label, warn())
    }
}

fn inner_rect(area: Rect) -> Option<Rect> {
    if area.width < 2 || area.height < 2 {
        None
    } else {
        Some(Rect {
            x: area.x + 1,
            y: area.y + 1,
            width: area.width - 2,
            height: area.height - 2,
        })
    }
}

fn push_list_hot(
    hot: &mut Vec<HotRect>,
    area: Rect,
    offset: usize,
    len: usize,
    map: fn(usize) -> Action,
) {
    let Some(inner) = inner_rect(area) else {
        return;
    };
    for row in 0..inner.height {
        let idx = offset + row as usize;
        if idx >= len {
            break;
        }
        hot.push(HotRect {
            rect: Rect {
                x: inner.x,
                y: inner.y + row,
                width: inner.width,
                height: 1,
            },
            action: map(idx),
        });
    }
}
