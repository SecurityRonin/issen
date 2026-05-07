//! Terminal UI rendering with ratatui.

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState};
use ratatui::Frame;

use issen_signatures::matching::results::Severity;

use crate::app::App;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

#[allow(clippy::cast_precision_loss)]
fn format_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * 1024;
    const GB: u64 = 1024 * 1024 * 1024;

    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{bytes} B")
    }
}

/// Map a file's modification time to a heat-map color.
///
/// Uses the most recent timestamp in the tree as reference (not wall clock),
/// so forensic images from any era get useful color gradients.
/// Buckets are exponentially spaced: changes are most visible for recent files.
fn age_color(
    modified: chrono::DateTime<chrono::Utc>,
    reference: chrono::DateTime<chrono::Utc>,
) -> Color {
    let age = reference.signed_duration_since(modified);
    let hours = age.num_hours();

    if hours < 1 {
        Color::Rgb(255, 60, 60) // bright red — just modified
    } else if hours < 6 {
        Color::Rgb(255, 120, 50) // red-orange
    } else if hours < 24 {
        Color::Rgb(255, 170, 50) // orange
    } else if hours < 24 * 3 {
        Color::Rgb(255, 220, 60) // yellow
    } else if hours < 24 * 7 {
        Color::Rgb(200, 230, 80) // yellow-green
    } else if hours < 24 * 14 {
        Color::Rgb(130, 210, 100) // green
    } else if hours < 24 * 30 {
        Color::Rgb(80, 200, 180) // teal
    } else if hours < 24 * 90 {
        Color::Rgb(80, 170, 210) // cyan-blue
    } else if hours < 24 * 180 {
        Color::Rgb(100, 140, 200) // blue
    } else if hours < 24 * 365 {
        Color::Rgb(130, 130, 180) // muted blue-gray
    } else {
        Color::Rgb(140, 140, 140) // gray — ancient
    }
}

// ---------------------------------------------------------------------------
// Main draw
// ---------------------------------------------------------------------------

pub fn draw(frame: &mut Frame, app: &mut App) {
    let footer_height =
        if app.searching || !app.search_query.is_empty() || !app.search_results.is_empty() {
            4
        } else {
            3
        };
    let chunks = Layout::vertical([
        Constraint::Length(3),             // header (title + selected path)
        Constraint::Min(1),                // file list
        Constraint::Length(footer_height), // footer (+ search bar)
    ])
    .split(frame.area());

    draw_header(frame, chunks[0], app);

    // Split main area if detail panel is active
    if app.show_detail_panel && !app.entries.is_empty() {
        let main_chunks = Layout::horizontal([
            Constraint::Min(30),    // file list (takes remaining space)
            Constraint::Length(40), // detail panel (fixed width)
        ])
        .split(chunks[1]);

        draw_file_list(frame, main_chunks[0], app);
        draw_detail_panel(frame, main_chunks[1], app);
    } else {
        draw_file_list(frame, chunks[1], app);
    }

    draw_footer(frame, chunks[2], app);

    if app.show_help {
        draw_help_modal(frame);
    }
}

// ---------------------------------------------------------------------------
// Header
// ---------------------------------------------------------------------------

fn draw_header(frame: &mut Frame, area: Rect, app: &App) {
    let path = app.current_path();
    let depth = app.entries.len();

    // Selected entry's full path (shrunk to fit terminal width).
    let selected_path = if !app.entries.is_empty() {
        let full = app.tree.cached_path(app.entries[app.selected]);
        let max_w = area.width.saturating_sub(2) as usize; // leave margin
        if full.len() > max_w {
            shrinkpath::shrink_to(full, max_w)
        } else {
            full.to_string()
        }
    } else {
        String::new()
    };

    let lines = vec![
        Line::from(vec![
            Span::styled(
                " rt-nav ",
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" "),
            Span::styled(
                path,
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("  "),
            Span::styled(
                format!("[{depth} items]"),
                Style::default().fg(Color::DarkGray),
            ),
            Span::raw("  "),
            Span::styled(
                format!("[Sort: {}]", app.soissen_mode.label()),
                Style::default().fg(Color::DarkGray),
            ),
        ]),
        Line::from(Span::styled(
            format!(" {selected_path}"),
            Style::default().fg(Color::White),
        )),
    ];

    frame.render_widget(Paragraph::new(lines), area);
}

// ---------------------------------------------------------------------------
// File list (the main panel)
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_lines)]
fn draw_file_list(frame: &mut Frame, area: Rect, app: &mut App) {
    if app.entries.is_empty() {
        let empty = Paragraph::new("  (empty directory)")
            .style(Style::default().fg(Color::DarkGray))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::DarkGray))
                    .title(" Files "),
            );
        frame.render_widget(empty, area);
        return;
    }

    // -- Virtual scrolling: only build Row widgets for visible entries --------
    // area.height minus 3 = border top (1) + header row (1) + border bottom (1)
    let visible_height = area.height.saturating_sub(3) as usize;
    app.visible_height = visible_height;
    app.file_list_area = area;
    let total = app.entries.len();

    // Adjust scroll_offset so `selected` stays visible.
    if app.selected < app.scroll_offset {
        app.scroll_offset = app.selected;
    } else if visible_height > 0 && app.selected >= app.scroll_offset + visible_height {
        app.scroll_offset = app
            .selected
            .saturating_sub(visible_height.saturating_sub(1));
    }
    // Clamp so we don't scroll past the end.
    if visible_height > 0 && total > visible_height {
        app.scroll_offset = app.scroll_offset.min(total - visible_height);
    } else {
        app.scroll_offset = 0;
    }

    let end = (app.scroll_offset + visible_height).min(total);

    let header = Row::new(vec![
        Cell::from(" Name"),
        Cell::from("Size"),
        Cell::from("Attr"),
        Cell::from("Modified"),
        Cell::from("Created"),
    ])
    .style(
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    )
    .height(1);

    let rows: Vec<Row> = (app.scroll_offset..end)
        .map(|i| {
            let idx = app.entries[i];
            let node = app.tree.node(idx);
            let depth = app.depths[i];

            let indent = "  ".repeat(depth);
            let tree_icon = if node.is_dir {
                if app.collapsed.contains(&idx) {
                    "\u{25b6} " // ▶ collapsed
                } else {
                    "\u{25bc} " // ▼ expanded
                }
            } else {
                "  "
            };

            let marker = match app.anomaly_index.max_severity(idx) {
                Some(Severity::Critical | Severity::High) => "\u{1f6a8} ", // 🚨
                Some(Severity::Medium) => "\u{1f7e1} ",                    // 🟡
                Some(Severity::Low | Severity::Informational) => "\u{1f535} ", // 🔵
                None => "",
            };

            let name_cell: Cell = if node.is_dir {
                Cell::from(format!("{indent}{tree_icon}{marker}{}/", node.name)).style(
                    Style::default()
                        .fg(Color::Blue)
                        .add_modifier(Modifier::BOLD),
                )
            } else {
                let file_color = age_color(node.si_timestamps.modified, app.reference_time);
                if node.is_downloaded() {
                    Cell::from(Line::from(vec![
                        Span::styled(
                            format!("{indent}{tree_icon}{marker}"),
                            Style::default().fg(file_color),
                        ),
                        Span::styled(
                            "\u{1f4e5} ", // 📥
                            Style::default(),
                        ),
                        Span::styled(node.name.clone(), Style::default().fg(file_color)),
                    ]))
                } else {
                    Cell::from(format!("{indent}{tree_icon}{marker}{}", node.name))
                        .style(Style::default().fg(file_color))
                }
            };

            let size_text = if node.is_dir {
                "<DIR>".to_string()
            } else {
                format_size(node.size)
            };

            let modified = node
                .si_timestamps
                .modified
                .format("%Y-%m-%d %H:%M:%S")
                .to_string();
            let created = node
                .si_timestamps
                .created
                .format("%Y-%m-%d %H:%M:%S")
                .to_string();
            let attrs = node.format_attributes();
            let attr_style = if node.is_hidden() || node.is_system() {
                Style::default().fg(Color::Yellow)
            } else {
                Style::default().fg(Color::DarkGray)
            };

            Row::new(vec![
                name_cell,
                Cell::from(size_text).style(Style::default().fg(Color::Green)),
                Cell::from(attrs).style(attr_style),
                Cell::from(modified).style(Style::default().fg(Color::DarkGray)),
                Cell::from(created).style(Style::default().fg(Color::DarkGray)),
            ])
        })
        .collect();

    let widths = [
        Constraint::Min(30),
        Constraint::Length(10),
        Constraint::Length(6),
        Constraint::Length(19),
        Constraint::Length(19),
    ];

    // Selected index is relative to the visible window.
    let relative_selected = app.selected.saturating_sub(app.scroll_offset);

    let table = Table::new(rows, widths)
        .header(header)
        .row_highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol(" ")
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray))
                .title(" Files "),
        );

    let mut state = TableState::default().with_selected(Some(relative_selected));
    frame.render_stateful_widget(table, area, &mut state);
}

// ---------------------------------------------------------------------------
// Anomaly detail panel
// ---------------------------------------------------------------------------

fn draw_detail_panel(frame: &mut Frame, area: Rect, app: &mut App) {
    if app.entries.is_empty() {
        return;
    }
    let idx = app.entries[app.selected];
    let node = app.tree.node(idx);
    let anomalies = app.anomaly_index.for_node(idx);

    let mut lines = vec![
        Line::from(Span::styled(
            format!(" {}", node.name),
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
    ];

    // -- Full path -----------------------------------------------------------
    let full_path = app.tree.cached_path(idx);
    lines.push(Line::from(Span::styled(
        format!(" {full_path}"),
        Style::default().fg(Color::DarkGray),
    )));
    lines.push(Line::from(""));

    // -- File info section ---------------------------------------------------
    let fmt = "%Y-%m-%d %H:%M:%S";
    let dim = Style::default().fg(Color::DarkGray);
    let label = Style::default().fg(Color::Cyan);
    let val = Style::default().fg(Color::White);

    lines.push(Line::from(vec![
        Span::styled(" MFT# ", label),
        Span::styled(node.mft_entry.to_string(), val),
        Span::styled("  Seq ", label),
        Span::styled(node.sequence_number.to_string(), val),
    ]));
    lines.push(Line::from(vec![
        Span::styled(" Attr ", label),
        Span::styled(node.format_attributes(), val),
        Span::styled("  Links ", label),
        Span::styled(node.hard_link_count.to_string(), val),
    ]));

    if !node.is_dir {
        let resident_label = if node.is_resident {
            "resident"
        } else {
            "non-resident"
        };
        lines.push(Line::from(vec![
            Span::styled(" Size ", label),
            Span::styled(format_size(node.size), val),
            Span::styled(format!(" ({resident_label})"), dim),
        ]));
    }

    if node.owner_id != 0 || node.security_id != 0 {
        lines.push(Line::from(vec![
            Span::styled(" SID ", label),
            Span::styled(node.security_id.to_string(), val),
            Span::styled("  Owner ", label),
            Span::styled(node.owner_id.to_string(), val),
        ]));
    }
    if node.usn != 0 {
        lines.push(Line::from(vec![
            Span::styled(" USN ", label),
            Span::styled(format!("0x{:X}", node.usn), val),
        ]));
    }
    if node.usn_change_count > 0 {
        lines.push(Line::from(vec![
            Span::styled(" Changes ", label),
            Span::styled(node.usn_change_count.to_string(), val),
        ]));
    }

    // -- Alternate Data Streams ----------------------------------------------
    if node.has_ads() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            " Alternate Data Streams",
            Style::default()
                .fg(Color::LightRed)
                .add_modifier(Modifier::BOLD),
        )));
        for name in &node.ads_names {
            lines.push(Line::from(vec![
                Span::styled("  :", dim),
                Span::styled(name.clone(), Style::default().fg(Color::LightRed)),
            ]));
        }
    }

    // $SI timestamps
    lines.push(Line::from(Span::styled(" $SI Timestamps", label)));
    lines.push(Line::from(vec![
        Span::styled("  Created  ", dim),
        Span::styled(node.si_timestamps.created.format(fmt).to_string(), val),
    ]));
    lines.push(Line::from(vec![
        Span::styled("  Modified ", dim),
        Span::styled(node.si_timestamps.modified.format(fmt).to_string(), val),
    ]));
    lines.push(Line::from(vec![
        Span::styled("  Accessed ", dim),
        Span::styled(node.si_timestamps.accessed.format(fmt).to_string(), val),
    ]));
    lines.push(Line::from(vec![
        Span::styled("  MFT Mod  ", dim),
        Span::styled(
            node.si_timestamps.entry_modified.format(fmt).to_string(),
            val,
        ),
    ]));

    // $FN timestamps (only shown when they differ from $SI — forensic indicator)
    if let Some(fn_ts) = &node.fn_timestamps {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            " $FN Timestamps (kernel-managed)",
            Style::default()
                .fg(Color::LightRed)
                .add_modifier(Modifier::BOLD),
        )));

        let warn = Style::default().fg(Color::LightRed);
        let ok = val;

        let c_style = if fn_ts.created != node.si_timestamps.created {
            warn
        } else {
            ok
        };
        let m_style = if fn_ts.modified != node.si_timestamps.modified {
            warn
        } else {
            ok
        };
        let a_style = if fn_ts.accessed != node.si_timestamps.accessed {
            warn
        } else {
            ok
        };
        let e_style = if fn_ts.entry_modified != node.si_timestamps.entry_modified {
            warn
        } else {
            ok
        };

        lines.push(Line::from(vec![
            Span::styled("  Created  ", dim),
            Span::styled(fn_ts.created.format(fmt).to_string(), c_style),
        ]));
        lines.push(Line::from(vec![
            Span::styled("  Modified ", dim),
            Span::styled(fn_ts.modified.format(fmt).to_string(), m_style),
        ]));
        lines.push(Line::from(vec![
            Span::styled("  Accessed ", dim),
            Span::styled(fn_ts.accessed.format(fmt).to_string(), a_style),
        ]));
        lines.push(Line::from(vec![
            Span::styled("  MFT Mod  ", dim),
            Span::styled(fn_ts.entry_modified.format(fmt).to_string(), e_style),
        ]));
    }

    // -- Anomalies section ---------------------------------------------------
    if !anomalies.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            " Anomalies",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        )));

        for anomaly in anomalies {
            let severity_color = match anomaly.severity {
                Severity::Critical => Color::Red,
                Severity::High => Color::LightRed,
                Severity::Medium => Color::Yellow,
                Severity::Low => Color::Blue,
                Severity::Informational => Color::DarkGray,
            };

            lines.push(Line::from(vec![
                Span::styled(
                    format!(" [{}] ", anomaly.rule_id),
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("{}", anomaly.severity),
                    Style::default()
                        .fg(severity_color)
                        .add_modifier(Modifier::BOLD),
                ),
            ]));
            lines.push(Line::from(Span::styled(
                format!("  {}", anomaly.description),
                val,
            )));
            lines.push(Line::from(Span::styled(
                format!("  Evidence: {}", anomaly.evidence),
                dim,
            )));
        }
    }

    let title = if anomalies.is_empty() {
        " Info "
    } else {
        " Info + Anomalies "
    };
    let border_color = if anomalies.is_empty() {
        Color::Cyan
    } else {
        Color::Yellow
    };

    let detail = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(border_color))
                .title(title),
        )
        .wrap(ratatui::widgets::Wrap { trim: false });

    frame.render_widget(detail, area);
}

// ---------------------------------------------------------------------------
// Footer
// ---------------------------------------------------------------------------

fn draw_footer(frame: &mut Frame, area: Rect, app: &App) {
    let (dirs, files, total_size) = app.tree.dir_stats(app.current_dir);

    let flagged = app.anomaly_index.flagged_count();
    let stats = if flagged > 0 {
        format!(
            " {dirs} dirs, {files} files ({})  |  MFT: {} records ({} allocated)  |  {} flagged",
            format_size(total_size),
            app.tree.total_mft_entries,
            app.tree.allocated_entries,
            flagged,
        )
    } else {
        format!(
            " {dirs} dirs, {files} files ({})  |  MFT: {} records ({} allocated)",
            format_size(total_size),
            app.tree.total_mft_entries,
            app.tree.allocated_entries,
        )
    };

    let help =
        " \u{2191}\u{2193}/jk: Nav  h/\u{2190}: Up  l/\u{2192}: Expand  Space: Fold  ^B/^F: Page  Bksp: Back  s: Sort  /: Search  n/N: Cycle  i: Info  f: Flagged  q: Quit";

    let mut lines = vec![
        Line::from(Span::styled(stats, Style::default().fg(Color::Green))),
        Line::from(Span::styled(help, Style::default().fg(Color::DarkGray))),
    ];

    if app.searching {
        let match_info = if app.pending_search {
            " ...".to_string()
        } else if app.search_results.is_empty() && !app.search_query.is_empty() {
            " (no matches)".to_string()
        } else if !app.search_results.is_empty() {
            format!("  {}/{}", app.search_cursor + 1, app.search_results.len())
        } else {
            String::new()
        };

        lines.push(Line::from(vec![
            Span::styled(
                " /",
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!(" {}\u{2588}", app.search_query),
                Style::default().fg(Color::Yellow),
            ),
            Span::styled(match_info, Style::default().fg(Color::DarkGray)),
            Span::styled(
                "  (Enter: accept  Esc: cancel  n/N: cycle)",
                Style::default().fg(Color::DarkGray),
            ),
        ]));
    } else if !app.search_query.is_empty() && !app.search_results.is_empty() {
        lines.push(Line::from(vec![
            Span::styled(
                format!(
                    " {}/{} \"{}\"",
                    app.search_cursor + 1,
                    app.search_results.len(),
                    app.search_query
                ),
                Style::default().fg(Color::Yellow),
            ),
            Span::styled(
                "  (n/N: cycle  /: new search)",
                Style::default().fg(Color::DarkGray),
            ),
        ]));
    } else if !app.search_query.is_empty() {
        lines.push(Line::from(vec![Span::styled(
            format!(" No matches for \"{}\"", app.search_query),
            Style::default().fg(Color::Red),
        )]));
    }

    let footer = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::TOP)
            .border_style(Style::default().fg(Color::DarkGray)),
    );

    frame.render_widget(footer, area);
}

fn draw_help_modal(frame: &mut Frame) {
    let area = frame.area();

    // Center the modal — 64 wide, 18 tall (or smaller if terminal is small).
    let modal_w = 64.min(area.width.saturating_sub(4));
    let modal_h = 18.min(area.height.saturating_sub(4));
    let x = (area.width.saturating_sub(modal_w)) / 2;
    let y = (area.height.saturating_sub(modal_h)) / 2;
    let modal_area = Rect::new(x, y, modal_w, modal_h);

    frame.render_widget(ratatui::widgets::Clear, modal_area);

    // Outer border block — render first, then work inside `inner`.
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Yellow))
        .title(" Help (?) ");
    let inner = block.inner(modal_area);
    frame.render_widget(block, modal_area);

    let bold = Style::default().add_modifier(Modifier::BOLD);
    let dim = Style::default().fg(Color::DarkGray);
    let cyan = Style::default().fg(Color::Cyan);

    // Vertical split: title row, two-column content, footer.
    let rows = Layout::vertical([
        Constraint::Length(2), // title + blank
        Constraint::Min(12),   // two-column content
        Constraint::Length(1), // footer
    ])
    .split(inner);

    // ── Title ────────────────────────────────────────────────────
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            " rt-nav Help",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ))),
        rows[0],
    );

    // ── Two columns: heat map (left) │ badges + nav (right) ─────
    let cols = Layout::horizontal([
        Constraint::Length(12), // heat map strip
        Constraint::Min(20),    // badges + navigation
    ])
    .split(rows[1]);

    // Left column — vertical heat map (hot → cold, top → bottom).
    let heat_entries: [(Color, &str); 11] = [
        (Color::Rgb(255, 60, 60), "<1h"),
        (Color::Rgb(255, 120, 50), "<6h"),
        (Color::Rgb(255, 170, 50), "<1d"),
        (Color::Rgb(255, 220, 60), "<3d"),
        (Color::Rgb(200, 230, 80), "<1w"),
        (Color::Rgb(130, 210, 100), "<2w"),
        (Color::Rgb(80, 200, 180), "<1m"),
        (Color::Rgb(80, 170, 210), "<3m"),
        (Color::Rgb(100, 140, 200), "<6m"),
        (Color::Rgb(130, 130, 180), "<1y"),
        (Color::Rgb(140, 140, 140), ">1y"),
    ];

    let mut heat_lines = vec![Line::from(Span::styled(" Recency", bold))];
    for &(color, label) in &heat_entries {
        heat_lines.push(Line::from(vec![
            Span::styled(" \u{2588}\u{2588}", Style::default().fg(color)),
            Span::styled(format!(" {label}"), dim),
        ]));
    }
    frame.render_widget(Paragraph::new(heat_lines), cols[0]);

    // Right column — badges + navigation.
    let right_lines = vec![
        Line::from(Span::styled(" Badges", bold)),
        Line::from(vec![
            Span::styled("  \u{1f6a8} ", Style::default()),
            Span::styled("Critical/High anomaly", Style::default().fg(Color::Red)),
        ]),
        Line::from(vec![
            Span::styled("  \u{1f7e1} ", Style::default()),
            Span::styled("Medium anomaly", Style::default().fg(Color::Yellow)),
        ]),
        Line::from(vec![
            Span::styled("  \u{1f535} ", Style::default()),
            Span::styled("Low/Info anomaly", Style::default().fg(Color::Blue)),
        ]),
        Line::from(vec![
            Span::styled("  \u{1f4e5} ", Style::default()),
            Span::styled(
                "Downloaded (Zone.Identifier)",
                Style::default().fg(Color::Magenta),
            ),
        ]),
        Line::from(""),
        Line::from(Span::styled(" Navigation", bold)),
        Line::from(vec![
            Span::styled("  \u{2191}\u{2193}/j/k ", cyan),
            Span::styled("Navigate  ", dim),
            Span::styled("h/\u{2190} ", cyan),
            Span::styled("Collapse", dim),
        ]),
        Line::from(vec![
            Span::styled("  Space ", cyan),
            Span::styled("Toggle fold  ", dim),
            Span::styled("l/\u{2192} ", cyan),
            Span::styled("Expand", dim),
        ]),
        Line::from(vec![
            Span::styled("  / ", cyan),
            Span::styled("Search  ", dim),
            Span::styled("n/N ", cyan),
            Span::styled("Next/prev  ", dim),
            Span::styled("s ", cyan),
            Span::styled("Sort", dim),
        ]),
        Line::from(vec![
            Span::styled("  ^B/^F ", cyan),
            Span::styled("Page up/dn  ", dim),
            Span::styled("Bksp ", cyan),
            Span::styled("Back", dim),
        ]),
        Line::from(vec![
            Span::styled("  i ", cyan),
            Span::styled("Info panel  ", dim),
            Span::styled("f ", cyan),
            Span::styled("Flagged  ", dim),
            Span::styled("q ", cyan),
            Span::styled("Quit", dim),
        ]),
    ];
    frame.render_widget(Paragraph::new(right_lines), cols[1]);

    // ── Footer ───────────────────────────────────────────────────
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            " Recency = P95 of timestamps \u{2502} Press any key to close",
            dim,
        ))),
        rows[2],
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};

    fn ref_time() -> chrono::DateTime<Utc> {
        Utc.with_ymd_and_hms(2024, 6, 15, 12, 0, 0).unwrap()
    }

    #[test]
    fn age_color_just_modified() {
        let modified = ref_time(); // 0 hours ago
        let color = age_color(modified, ref_time());
        asseissen_eq!(color, Color::Rgb(255, 60, 60));
    }

    #[test]
    fn age_color_few_hours_ago() {
        let modified = ref_time() - chrono::Duration::hours(3);
        let color = age_color(modified, ref_time());
        asseissen_eq!(color, Color::Rgb(255, 120, 50));
    }

    #[test]
    fn age_color_one_day_ago() {
        let modified = ref_time() - chrono::Duration::hours(12);
        let color = age_color(modified, ref_time());
        asseissen_eq!(color, Color::Rgb(255, 170, 50));
    }

    #[test]
    fn age_color_few_days_ago() {
        let modified = ref_time() - chrono::Duration::days(2);
        let color = age_color(modified, ref_time());
        asseissen_eq!(color, Color::Rgb(255, 220, 60));
    }

    #[test]
    fn age_color_one_week_ago() {
        let modified = ref_time() - chrono::Duration::days(5);
        let color = age_color(modified, ref_time());
        asseissen_eq!(color, Color::Rgb(200, 230, 80));
    }

    #[test]
    fn age_color_two_weeks_ago() {
        let modified = ref_time() - chrono::Duration::days(10);
        let color = age_color(modified, ref_time());
        asseissen_eq!(color, Color::Rgb(130, 210, 100));
    }

    #[test]
    fn age_color_one_month_ago() {
        let modified = ref_time() - chrono::Duration::days(20);
        let color = age_color(modified, ref_time());
        asseissen_eq!(color, Color::Rgb(80, 200, 180));
    }

    #[test]
    fn age_color_three_months_ago() {
        let modified = ref_time() - chrono::Duration::days(60);
        let color = age_color(modified, ref_time());
        asseissen_eq!(color, Color::Rgb(80, 170, 210));
    }

    #[test]
    fn age_color_six_months_ago() {
        let modified = ref_time() - chrono::Duration::days(120);
        let color = age_color(modified, ref_time());
        asseissen_eq!(color, Color::Rgb(100, 140, 200));
    }

    #[test]
    fn age_color_one_year_ago() {
        let modified = ref_time() - chrono::Duration::days(300);
        let color = age_color(modified, ref_time());
        asseissen_eq!(color, Color::Rgb(130, 130, 180));
    }

    #[test]
    fn age_color_ancient() {
        let modified = ref_time() - chrono::Duration::days(500);
        let color = age_color(modified, ref_time());
        asseissen_eq!(color, Color::Rgb(140, 140, 140));
    }

    #[test]
    fn age_color_future_timestamp() {
        // Modified in the future (clock skew) — treat as hottest
        let modified = ref_time() + chrono::Duration::hours(5);
        let color = age_color(modified, ref_time());
        asseissen_eq!(color, Color::Rgb(255, 60, 60));
    }
}
