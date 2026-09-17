//! Screen drawing plus hot-rect / scroll-zone capture.

use super::{
    Action, App, DetailResult, Focus, HotRect, OptionRow, OPTION_ROWS, PackOutcome, Screen, Zone,
};
use crate::args::ProfileArg;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Wrap};
use ratatui::Frame;

const PROFILE_ORDER: [ProfileArg; 3] = [ProfileArg::Fast, ProfileArg::Standard, ProfileArg::Max];

pub fn ui(f: &mut Frame, app: &mut App) {
    app.hot.clear();
    app.scroll_zones.clear();
    match app.screen {
        Screen::Pick => pick(f, app),
        Screen::Configure => configure(f, app),
        Screen::Packing => packing(f, app),
        Screen::Result => result(f, app),
    }
}

fn pick(f: &mut Frame, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(8),
            Constraint::Length(3),
        ])
        .split(f.area());

    let header = Paragraph::new(Line::from(vec![
        Span::raw(" "),
        Span::styled(
            app.cwd.display().to_string(),
            Style::default().fg(Color::Cyan),
        ),
    ]))
    .block(Block::default().borders(Borders::ALL).title("Directory"));
    f.render_widget(header, chunks[0]);

    let items: Vec<ListItem> = app
        .pick_rows
        .iter()
        .map(|r| {
            let label = if r.is_dir {
                format!("/ {}", r.name)
            } else {
                format!("  {}", r.name)
            };
            ListItem::new(label)
        })
        .collect();
    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Files (*.dll / *.exe / *.so / *.elf / *.xenolith.json)"),
        )
        .highlight_style(Style::default().bg(Color::DarkGray))
        .highlight_symbol(" ");
    f.render_stateful_widget(list, chunks[1], &mut app.pick_state);
    push_list_hot(
        &mut app.hot,
        chunks[1],
        app.pick_state.offset(),
        app.pick_rows.len(),
        Action::PickEntry,
    );
    app.scroll_zones.push((chunks[1], Zone::Pick));

    let last = app.log.last().map(|s| s.as_str()).unwrap_or("");
    let hints = Paragraph::new(Line::from(vec![
        Span::raw(" ↑/↓ move  Enter open  Backspace up  Esc/q quit  "),
        Span::styled(last, Style::default().fg(Color::Yellow)),
    ]))
    .block(Block::default().borders(Borders::ALL));
    f.render_widget(hints, chunks[2]);
}

fn configure(f: &mut Frame, app: &mut App) {
    if !app.exports.is_empty() {
        let i = app.selected.min(app.exports.len() - 1);
        app.ensure_detail(i);
    }

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
    let items: Vec<ListItem> = app
        .exports
        .iter()
        .map(|e| {
            let mark = if e.vm { "[x]" } else { "[ ]" };
            let extra = if e.native_locked { " (native)" } else { "" };
            ListItem::new(format!(
                "{mark} {}  ord={} rva={:#x}{extra}",
                e.name, e.ordinal, e.rva
            ))
        })
        .collect();
    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(title))
        .highlight_style(Style::default().bg(Color::DarkGray))
        .highlight_symbol(" ");
    f.render_stateful_widget(list, left[1], &mut app.export_state);
    push_list_hot(
        &mut app.hot,
        left[1],
        app.export_state.offset(),
        app.exports.len(),
        Action::ExportRow,
    );
    app.scroll_zones.push((left[1], Zone::Exports));

    let right = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(6), Constraint::Min(13)])
        .split(mid[1]);
    detail(f, app, right[0]);
    options(f, app, right[1]);

    log_panel(f, app, chunks[2]);

    paint_buttons(
        f,
        app,
        chunks[3],
        &[
            ("[Pack]", Action::Pack),
            ("[Save project]", Action::SaveProject),
            ("[Back]", Action::Back),
            ("[Quit]", Action::Quit),
        ],
        "Tab/BackTab sections · Space · ←/→ · a/v/u · p/d/l/i/c/s · Esc back",
    );
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
    spans.push(Span::raw(" a/v/u"));
    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn header(f: &mut Frame, app: &App, area: Rect) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Min(20), Constraint::Length(22)])
        .split(area);

    let left = Paragraph::new(Line::from(vec![
        Span::raw(" File: "),
        Span::styled(
            app.input.display().to_string(),
            Style::default().fg(Color::Cyan),
        ),
        Span::raw("  Out: "),
        Span::raw(app.output.display().to_string()),
    ]))
    .block(Block::default().borders(Borders::ALL).title("Xenolith"));
    f.render_widget(left, cols[0]);

    let profile = Paragraph::new(Line::from(vec![
        Span::raw(" Profile: "),
        Span::styled(
            app.profile.as_str(),
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
    ]))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title("profile → Options"),
    );
    f.render_widget(profile, cols[1]);
}

fn detail(f: &mut Frame, app: &App, area: Rect) {
    let lines = if matches!(
        app.image_kind,
        Some(xenolith_formats::ImageKind::Elf64Exec)
            | Some(xenolith_formats::ImageKind::Elf64Dyn)
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
            Line::from(e.name.as_str()),
            Line::from(format!("ordinal     {}", e.ordinal)),
            Line::from(format!("rva         {:#x}", e.rva)),
        ];
        match app.details.get(&i) {
            Some(DetailResult::Ok {
                native_len,
                blocks,
            }) => {
                lines.push(Line::from(format!("native_len  {native_len}")));
                lines.push(Line::from(format!("pre-lift    {blocks} blocks")));
                lines.push(Line::from("lock        —"));
            }
            Some(DetailResult::Locked { reason }) => {
                lines.push(Line::from("native_len  —"));
                lines.push(Line::from("pre-lift    —"));
                lines.push(Line::from(format!("lock        {reason}")));
            }
            Some(DetailResult::Err(err)) => {
                lines.push(Line::from("native_len  —"));
                lines.push(Line::from("pre-lift    lift failed"));
                lines.push(Line::from(Span::styled(
                    err.as_str(),
                    Style::default().fg(Color::Red),
                )));
            }
            None => lines.push(Line::from("detail pending")),
        }
        lines
    };
    f.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: true })
            .block(Block::default().borders(Borders::ALL).title("Export detail")),
        area,
    );
}

fn options(f: &mut Frame, app: &mut App, area: Rect) {
    let Some(inner) = inner_rect(area) else {
        return;
    };
    let focus_here = app.focus == Focus::Options;
    let warn = Style::default().fg(Color::Yellow);
    let dim = Style::default().fg(Color::DarkGray);

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
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD)
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
                hl.add_modifier(Modifier::BOLD)
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
            warn,
        )));
    }
    if app.fast_imports_note() {
        lines.push(Line::from(Span::styled(
            "⚠ protect-imports idle on fast:",
            warn,
        )));
        lines.push(Line::from(Span::styled(
            "  disk IAT stays plaintext",
            warn,
        )));
    }

    // Read-only capability summary; never clickable.
    let hashed = matches!(app.profile, ProfileArg::Standard | ProfileArg::Max);
    let probes = matches!(app.profile, ProfileArg::Max);
    lines.push(Line::from(Span::styled(
        if hashed {
            "hashed IAT (std/max)"
        } else {
            "IAT kept (fast)"
        },
        dim,
    )));
    lines.push(Line::from(Span::styled("stolen OEP · integrity FNV", dim)));
    lines.push(Line::from(Span::styled(
        if probes {
            "probes (max only)"
        } else {
            "probes off"
        },
        dim,
    )));
    lines.push(Line::from(Span::styled(
        if app.select_rva.is_empty() {
            "select-rva — (project only)".to_string()
        } else {
            format!("select-rva {} range(s) (project)", app.select_rva.len())
        },
        dim,
    )));
    lines.push(Line::from(Span::styled("(C2 not armed)", dim)));

    f.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .title("Options (space/enter · ←/→ profile)"),
        ),
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

fn packing(f: &mut Frame, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(8), Constraint::Length(3)])
        .split(f.area());

    let elapsed = app
        .pack_started
        .map(|t| t.elapsed().as_secs_f32())
        .unwrap_or(0.0);
    let mut lines = vec![
        Line::from(format!("{} packing  {:.1}s", app.spinner(), elapsed)),
        Line::from(format!(
            "profile={}  trace-diverge={}  lazy-regions={}  protect-imports={}",
            app.profile.as_str(),
            on_off(app.trace_diverge),
            on_off(app.lazy_regions),
            on_off(app.protect_imports),
        )),
        Line::from(format!(
            "strict-constants={}  strict-coverage={}  fallback={}  select-all={}  select-rva={} range(s)  select-functions={}",
            on_off(app.strict_constants),
            on_off(app.strict_coverage),
            on_off(app.allow_native_fallback),
            on_off(app.select_all),
            app.select_rva.len(),
            app.select_functions.len(),
        )),
        Line::from(format!("out {}", app.output.display())),
        Line::from(""),
        Line::from("VM exports:"),
    ];
    if app.packing_exports.is_empty() {
        lines.push(Line::from("  (none)"));
    } else {
        for name in &app.packing_exports {
            lines.push(Line::from(format!("  {name}")));
        }
    }
    lines.push(Line::from(""));
    lines.push(Line::from(
        "Cancel discards the image and does not write. pack() has no interrupt hook; the worker may still finish.",
    ));
    f.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: true })
            .block(Block::default().borders(Borders::ALL).title("Packing")),
        chunks[0],
    );
    paint_buttons(f, app, chunks[1], &[("[Cancel]", Action::Cancel)], "Esc cancel");
}

fn result(f: &mut Frame, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(8), Constraint::Length(3)])
        .split(f.area());

    let dim = Style::default().fg(Color::DarkGray);
    let success_body = match &app.outcome {
        Some(PackOutcome::Success(done)) => {
            let r = &done.report;
            let mut lines = vec![
                Line::from(Span::styled(
                    "pack ok",
                    Style::default()
                        .fg(Color::Green)
                        .add_modifier(Modifier::BOLD),
                )),
                Line::from(format!("profile      {}", r.profile)),
                Line::from(format!("format       {}", r.format)),
                Line::from(format!("backend      {}", r.backend)),
                Line::from(format!(
                    "size         {} -> {} B ({:.2}x)",
                    r.input_bytes,
                    r.output_bytes,
                    r.output_bytes as f64 / r.input_bytes.max(1) as f64
                )),
                Line::from(format!("pages        {}", r.pages)),
                Line::from(format!("vm_functions {}", r.vm_functions)),
                Line::from(format!("selected     {}", join_names(&r.selected_functions))),
                Line::from(format!("stolen_bytes {}", r.stolen_bytes)),
                Line::from(format!("iat_mode     {}", r.iat_mode)),
                Line::from(format!(
                    "imports      sealed={} protected={} kept={}",
                    r.import_names_sealed, r.imports_protected, r.imports_kept
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
            lines.push(Line::from(format!("output       {}", done.output.display())));
            lines.push(Line::from(format!("elapsed      {:.1}s", done.elapsed.as_secs_f32())));
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

    if let Some(body) = success_body {
        f.render_widget(
            Paragraph::new(body)
                .wrap(Wrap { trim: true })
                .block(Block::default().borders(Borders::ALL).title("Result")),
            chunks[0],
        );
        paint_buttons(
            f,
            app,
            chunks[1],
            &[
                ("[Pack again]", Action::PackAnother),
                ("[Save project]", Action::SaveProject),
                ("[Quit]", Action::Quit),
            ],
            "Enter confirm · ←/→ move · Esc back to configure",
        );
    } else if let Some(err) = failure_body {
        let body = vec![
            Line::from(Span::styled(
                "pack failed",
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            )),
            Line::from(err),
        ];
        f.render_widget(
            Paragraph::new(body)
                .wrap(Wrap { trim: true })
                .block(Block::default().borders(Borders::ALL).title("Result")),
            chunks[0],
        );
        paint_buttons(
            f,
            app,
            chunks[1],
            &[("[Back]", Action::Back), ("[Quit]", Action::Quit)],
            "Enter confirm · Esc back to configure",
        );
    } else {
        f.render_widget(
            Paragraph::new("no result").block(Block::default().borders(Borders::ALL)),
            chunks[0],
        );
    }
}

fn join_names(names: &[String]) -> String {
    if names.is_empty() {
        "—".into()
    } else {
        names.join(", ")
    }
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
        if app.log_scroll == max_scroll {
            app.log_follow = true;
        }
    }
    let lines: Vec<Line> = app.log.iter().map(|s| Line::from(s.as_str())).collect();
    f.render_widget(
        Paragraph::new(lines)
            .scroll((app.log_scroll, 0))
            .block(Block::default().borders(Borders::ALL).title("Log")),
        area,
    );
    app.scroll_zones.push((area, Zone::Log));
}

fn paint_buttons(
    f: &mut Frame,
    app: &mut App,
    area: Rect,
    items: &[(&'static str, Action)],
    hint: &'static str,
) {
    let focus_buttons = app.focus == Focus::Buttons || app.screen != Screen::Configure;
    let mut spans = Vec::new();
    let inner = inner_rect(area);
    let mut x = inner.map(|r| r.x).unwrap_or(area.x);
    let y = inner.map(|r| r.y).unwrap_or(area.y);
    for (i, (label, action)) in items.iter().enumerate() {
        let on = focus_buttons && i == app.button;
        spans.push(btn(label, on));
        spans.push(Span::raw("  "));
        let w = label.len() as u16;
        if inner.is_some() {
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
    spans.push(Span::raw(hint));
    f.render_widget(
        Paragraph::new(Line::from(spans)).block(Block::default().borders(Borders::ALL)),
        area,
    );
}

fn btn(label: &'static str, on: bool) -> Span<'static> {
    if on {
        Span::styled(label, Style::default().bg(Color::Blue).fg(Color::White))
    } else {
        Span::raw(label)
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
