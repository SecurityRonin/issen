//! Terminal UI rendering with ratatui.

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState};
use ratatui::Frame;

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

pub fn draw(frame: &mut Frame, app: &App) {
    let footer_height = if app.searching || !app.search_query.is_empty() {
        4
    } else {
        3
    };
    let chunks = Layout::vertical([
        Constraint::Length(2),             // header
        Constraint::Min(1),                // file list
        Constraint::Length(footer_height), // footer (+ search bar)
    ])
    .split(frame.area());

    draw_header(frame, chunks[0], app);
    draw_file_list(frame, chunks[1], app);
    draw_footer(frame, chunks[2], app);
}

// ---------------------------------------------------------------------------
// Header
// ---------------------------------------------------------------------------

fn draw_header(frame: &mut Frame, area: Rect, app: &App) {
    let path = app.current_path();
    let depth = app.entries.len();

    let line = Line::from(vec![
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
    ]);

    frame.render_widget(Paragraph::new(line), area);
}

// ---------------------------------------------------------------------------
// File list (the main panel)
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_lines)]
fn draw_file_list(frame: &mut Frame, area: Rect, app: &App) {
    if app.entries.is_empty() {
        let msg = if app.search_query.is_empty() {
            "  (empty directory)"
        } else {
            "  (no matches)"
        };
        let empty = Paragraph::new(msg)
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

    let name_header = if app.search_query.is_empty() {
        " Name"
    } else {
        " Path"
    };
    let header = Row::new(vec![
        Cell::from(name_header),
        Cell::from("Size"),
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

    let in_search = !app.search_query.is_empty();

    let rows: Vec<Row> = app
        .entries
        .iter()
        .map(|&idx| {
            let node = app.tree.node(idx);

            let (name_text, name_style) = if node.is_dir {
                let label = if in_search {
                    format!(" {}/", app.tree.cached_path(idx))
                } else {
                    format!(" {}/", node.name)
                };
                (
                    label,
                    Style::default()
                        .fg(Color::Blue)
                        .add_modifier(Modifier::BOLD),
                )
            } else {
                let label = if in_search {
                    format!(" {}", app.tree.cached_path(idx))
                } else {
                    format!(" {}", node.name)
                };
                (label, Style::default().fg(Color::White))
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

            Row::new(vec![
                Cell::from(name_text).style(name_style),
                Cell::from(size_text).style(Style::default().fg(Color::Green)),
                Cell::from(modified).style(Style::default().fg(Color::DarkGray)),
                Cell::from(created).style(Style::default().fg(Color::DarkGray)),
                Cell::from(mft_num).style(Style::default().fg(Color::DarkGray)),
            ])
        })
        .collect();

    let widths = [
        Constraint::Min(30),
        Constraint::Length(10),
        Constraint::Length(19),
        Constraint::Length(19),
        Constraint::Length(8),
    ];

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

    let mut state = TableState::default().with_selected(Some(app.selected));
    frame.render_stateful_widget(table, area, &mut state);
}

// ---------------------------------------------------------------------------
// Footer
// ---------------------------------------------------------------------------

fn draw_footer(frame: &mut Frame, area: Rect, app: &App) {
    let (dirs, files, total_size) = app.tree.dir_stats(app.current_dir);

    let stats = format!(
        " {dirs} dirs, {files} files ({})  |  MFT: {} records ({} allocated)",
        format_size(total_size),
        app.tree.total_mft_entries,
        app.tree.allocated_entries,
    );

    let help =
        " \u{2191}\u{2193}/jk: Nav  Enter/l: Open  Bksp/h: Back  s: Sort  /: Search  ^N/^P: Pg  g/G: Top/End  q: Quit";

    let mut lines = vec![
        Line::from(Span::styled(stats, Style::default().fg(Color::Green))),
        Line::from(Span::styled(help, Style::default().fg(Color::DarkGray))),
    ];

    if app.searching {
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
            Span::styled(
                "  (Enter: accept  Esc: cancel)",
                Style::default().fg(Color::DarkGray),
            ),
        ]));
    } else if !app.search_query.is_empty() {
        lines.push(Line::from(vec![
            Span::styled(" Filter: ", Style::default().fg(Color::DarkGray)),
            Span::styled(&app.search_query, Style::default().fg(Color::Yellow)),
            Span::styled(
                format!("  ({} matches)", app.entries.len()),
                Style::default().fg(Color::DarkGray),
            ),
        ]));
    }

    let footer = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::TOP)
            .border_style(Style::default().fg(Color::DarkGray)),
    );

    frame.render_widget(footer, area);
}
