use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::widgets::{Block, Borders, Row, Table};
use ratatui::Frame;

use crate::investigation::WorkbenchApp;

pub fn draw(frame: &mut Frame, app: &WorkbenchApp, area: Rect) {
    let data = &app.data.logins;
    let title = format!(" Login Records ({}) ", data.len());

    let header = Row::new(vec![
        "User", "Terminal", "Source", "Login", "Logout", "Duration",
    ])
    .style(Style::default().add_modifier(Modifier::BOLD));

    let visible_height = area.height.saturating_sub(3) as usize;
    let start = app.scroll_offset;
    let end = (start + visible_height).min(data.len());

    let rows: Vec<Row<'_>> = data[start..end]
        .iter()
        .enumerate()
        .map(|(i, record)| {
            let style = if start + i == app.selected {
                Style::default().add_modifier(Modifier::REVERSED)
            } else {
                Style::default()
            };
            Row::new(vec![
                record.user.clone(),
                record.terminal.clone(),
                record.source.clone(),
                record.login_time.as_deref().unwrap_or("-").to_string(),
                record.logout_time.as_deref().unwrap_or("-").to_string(),
                record.duration.as_deref().unwrap_or("-").to_string(),
            ])
            .style(style)
        })
        .collect();

    let widths = [
        Constraint::Length(12), // User
        Constraint::Length(10), // Terminal
        Constraint::Length(16), // Source
        Constraint::Length(20), // Login
        Constraint::Length(20), // Logout
        Constraint::Min(10),    // Duration
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default().borders(Borders::ALL).title(title));

    frame.render_widget(table, area);
}
