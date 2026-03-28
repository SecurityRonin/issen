use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::widgets::{Block, Borders, Row, Table};
use ratatui::Frame;

use crate::investigation::WorkbenchApp;

pub fn draw(frame: &mut Frame, app: &WorkbenchApp, area: Rect) {
    let data = &app.data.network;
    let title = format!(" Network Connections ({}) ", data.len());

    let header = Row::new(vec![
        "Proto",
        "Local Addr",
        "Remote Addr",
        "State",
        "PID",
        "Program",
    ])
    .style(Style::default().add_modifier(Modifier::BOLD));

    let visible_height = area.height.saturating_sub(3) as usize;
    let start = app.scroll_offset;
    let end = (start + visible_height).min(data.len());

    let rows: Vec<Row<'_>> = data[start..end]
        .iter()
        .enumerate()
        .map(|(i, conn)| {
            let style = if start + i == app.selected {
                Style::default().add_modifier(Modifier::REVERSED)
            } else {
                Style::default()
            };
            Row::new(vec![
                conn.protocol.clone(),
                conn.local_addr.clone(),
                conn.remote_addr.clone(),
                conn.state.clone(),
                conn.pid
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "-".into()),
                conn.program.as_deref().unwrap_or("-").to_string(),
            ])
            .style(style)
        })
        .collect();

    let widths = [
        Constraint::Length(6),  // Proto
        Constraint::Length(22), // Local Addr
        Constraint::Length(22), // Remote Addr
        Constraint::Length(12), // State
        Constraint::Length(7),  // PID
        Constraint::Min(15),    // Program
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default().borders(Borders::ALL).title(title));

    frame.render_widget(table, area);
}
