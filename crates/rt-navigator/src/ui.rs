//! Terminal UI rendering with ratatui.

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState};
use ratatui::Frame;

use rt_signatures::matching::results::Severity;

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
            Constraint::Percentage(60), // file list
            Constraint::Percentage(40), // detail panel
        ])
        .split(chunks[1]);

        draw_file_list(frame, main_chunks[0], app);
        draw_detail_panel(frame, main_chunks[1], app);
    } else {
        draw_file_list(frame, chunks[1], app);
    }

    draw_footer(frame, chunks[2], app);
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
                format!("[Sort: {}]", app.sort_mode.label()),
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
        Cell::from("MFT#"),
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
                "  " // align with folder icon
            };

            let marker = match app.anomaly_index.max_severity(idx) {
                Some(Severity::Critical | Severity::High) => "!! ",
                Some(Severity::Medium) => "!  ",
                Some(Severity::Low | Severity::Informational) => "\u{00b7}  ",
                None => "",
            };

            let (name_text, name_style) = if node.is_dir {
                (
                    format!("{indent}{tree_icon}{marker}{}/", node.name),
                    Style::default()
                        .fg(Color::Blue)
                        .add_modifier(Modifier::BOLD),
                )
            } else {
                (
                    format!("{indent}{tree_icon}{marker}{}", node.name),
                    Style::default().fg(Color::White),
                )
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
            let mft_num = node.mft_entry.to_string();

            let attrs = node.format_attributes();
            let attr_style = if node.is_hidden() || node.is_system() {
                Style::default().fg(Color::Yellow)
            } else {
                Style::default().fg(Color::DarkGray)
            };

            Row::new(vec![
                Cell::from(name_text).style(name_style),
                Cell::from(size_text).style(Style::default().fg(Color::Green)),
                Cell::from(attrs).style(attr_style),
                Cell::from(modified).style(Style::default().fg(Color::DarkGray)),
                Cell::from(created).style(Style::default().fg(Color::DarkGray)),
                Cell::from(mft_num).style(Style::default().fg(Color::DarkGray)),
            ])
        })
        .collect();

    let widths = [
        Constraint::Min(30),
        Constraint::Length(10),
        Constraint::Length(6),
        Constraint::Length(19),
        Constraint::Length(19),
        Constraint::Length(8),
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
        .highlight_symbol("\u{25b6}")
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

    // -- File info section ---------------------------------------------------
    let fmt = "%Y-%m-%d %H:%M:%S";
    let dim = Style::default().fg(Color::DarkGray);
    let label = Style::default().fg(Color::Cyan);
    let val = Style::default().fg(Color::White);

    lines.push(Line::from(vec![
        Span::styled(" MFT# ", label),
        Span::styled(node.mft_entry.to_string(), val),
        Span::styled("  Attr ", label),
        Span::styled(node.format_attributes(), val),
    ]));

    if !node.is_dir {
        lines.push(Line::from(vec![
            Span::styled(" Size ", label),
            Span::styled(format_size(node.size), val),
        ]));
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
        " Details "
    } else {
        " Details + Anomalies "
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
        " \u{2191}\u{2193}/jk: Nav  h/\u{2190}: Up  l/\u{2192}: Expand  Space: Fold  ^B/^F: Page  Bksp: Back  s: Sort  /: Search  n/N: Cycle  f: Flagged  q: Quit";

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
