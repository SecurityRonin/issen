use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::widgets::{Block, Borders, Row, Table};
use ratatui::Frame;

use crate::investigation::WorkbenchApp;

pub fn draw(frame: &mut Frame, app: &WorkbenchApp, area: Rect) {
    let data = &app.data.packages;
    let title = format!(" Installed Packages ({}) ", data.len());

    let header = Row::new(vec!["Name", "Version", "Manager"])
        .style(Style::default().add_modifier(Modifier::BOLD));

    let visible_height = area.height.saturating_sub(3) as usize;
    let start = app.scroll_offset;
    let end = (start + visible_height).min(data.len());

    let rows: Vec<Row<'_>> = data[start..end]
        .iter()
        .enumerate()
        .map(|(i, pkg)| {
            let style = if start + i == app.selected {
                Style::default().add_modifier(Modifier::REVERSED)
            } else {
                Style::default()
            };
            Row::new(vec![
                pkg.name.clone(),
                pkg.version.clone(),
                format!("{:?}", pkg.manager),
            ])
            .style(style)
        })
        .collect();

    let widths = [
        Constraint::Min(20),    // Name
        Constraint::Length(15), // Version
        Constraint::Length(8),  // Manager
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default().borders(Borders::ALL).title(title));

    frame.render_widget(table, area);
}
