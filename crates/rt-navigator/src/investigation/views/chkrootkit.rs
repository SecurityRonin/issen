use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::{Block, Borders, Row, Table};
use ratatui::Frame;

use crate::investigation::WorkbenchApp;

pub fn draw(frame: &mut Frame, app: &WorkbenchApp, area: Rect) {
    let data = &app.data.chkrootkit;
    let title = format!(" Chkrootkit Findings ({}) ", data.len());

    let header = Row::new(vec!["Check", "Result", "Infected"])
        .style(Style::default().add_modifier(Modifier::BOLD));

    let visible_height = area.height.saturating_sub(3) as usize;
    let start = app.scroll_offset;
    let end = (start + visible_height).min(data.len());

    let rows: Vec<Row<'_>> = data[start..end]
        .iter()
        .enumerate()
        .map(|(i, finding)| {
            let base_fg = if finding.is_infected {
                Color::Red
            } else {
                Color::default()
            };
            let style = if start + i == app.selected {
                Style::default()
                    .fg(base_fg)
                    .add_modifier(Modifier::REVERSED)
            } else {
                Style::default().fg(base_fg)
            };
            Row::new(vec![
                finding.check_name.clone(),
                finding.result.clone(),
                if finding.is_infected {
                    "YES".to_string()
                } else {
                    "no".to_string()
                },
            ])
            .style(style)
        })
        .collect();

    let widths = [
        Constraint::Length(24), // Check
        Constraint::Min(30),    // Result
        Constraint::Length(10), // Infected
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default().borders(Borders::ALL).title(title));

    frame.render_widget(table, area);
}
