use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::widgets::{Block, Borders, Row, Table};
use ratatui::Frame;

use crate::investigation::WorkbenchApp;

pub fn draw(frame: &mut Frame, app: &WorkbenchApp, area: Rect) {
    let data = &app.data.processes;
    let title = format!(" Processes ({}) ", data.len());

    let header = Row::new(vec![
        "PID", "PPID", "User", "CPU%", "MEM%", "Start", "Command",
    ])
    .style(Style::default().add_modifier(Modifier::BOLD));

    let visible_height = area.height.saturating_sub(3) as usize;
    let start = app.scroll_offset;
    let end = (start + visible_height).min(data.len());

    let rows: Vec<Row<'_>> = data[start..end]
        .iter()
        .enumerate()
        .map(|(i, proc_info)| {
            let style = if start + i == app.selected {
                Style::default().add_modifier(Modifier::REVERSED)
            } else {
                Style::default()
            };
            Row::new(vec![
                proc_info.pid.to_string(),
                proc_info.ppid.to_string(),
                proc_info.user.clone(),
                proc_info.cpu_pct.as_deref().unwrap_or("-").to_string(),
                proc_info.mem_pct.as_deref().unwrap_or("-").to_string(),
                proc_info.start_time.as_deref().unwrap_or("-").to_string(),
                proc_info.command.clone(),
            ])
            .style(style)
        })
        .collect();

    let widths = [
        Constraint::Length(7),  // PID
        Constraint::Length(7),  // PPID
        Constraint::Length(12), // User
        Constraint::Length(6),  // CPU%
        Constraint::Length(6),  // MEM%
        Constraint::Length(12), // Start
        Constraint::Min(20),    // Command
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default().borders(Borders::ALL).title(title));

    frame.render_widget(table, area);
}
