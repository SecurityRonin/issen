//! Dashboard rendering for the Investigation Workbench.
//!
//! The dashboard is the landing page of the workbench, showing a summary
//! panel (left) with category counts, and a right panel with a sparkline
//! visualization of timeline activity plus an alerts list.

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Sparkline};
use ratatui::Frame;

use super::alerts::AlertSeverity;
use super::timeline::build_sparkline;
use super::WorkbenchApp;

/// Draw the full dashboard view into the given area.
pub fn draw_dashboard(frame: &mut Frame, app: &WorkbenchApp, area: Rect) {
    let chunks =
        Layout::horizontal([Constraint::Percentage(40), Constraint::Percentage(60)]).split(area);

    draw_summary(frame, app, chunks[0]);
    draw_right_panel(frame, app, chunks[1]);
}

/// Left panel: category counts summary.
fn draw_summary(frame: &mut Frame, app: &WorkbenchApp, area: Rect) {
    let mut items: Vec<ListItem<'_>> = Vec::new();

    // Collection metadata header
    let meta = &app.data.metadata;
    if !meta.hostname.is_empty() {
        let mut lines = Vec::new();
        lines.push(Line::from(vec![
            Span::styled(
                "  Host: ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(&meta.hostname),
        ]));
        if !meta.os.is_empty() {
            lines.push(Line::from(format!("  OS: {}", meta.os)));
        }
        if !meta.collection_tool.is_empty() {
            lines.push(Line::from(format!("  Tool: {}", meta.collection_tool)));
        }
        if meta.acquisition_time > 0 {
            let dt = chrono::DateTime::from_timestamp(meta.acquisition_time, 0);
            if let Some(dt) = dt {
                lines.push(Line::from(format!(
                    "  Date: {}",
                    dt.format("%Y-%m-%d %H:%M UTC")
                )));
            }
        }
        lines.push(Line::from(""));
        items.push(ListItem::new(lines));
    }

    // Supertimeline entry
    if !app.data.timeline.is_empty() {
        let count = app.data.timeline.len();
        let mut lines = vec![Line::from(vec![
            Span::styled("  Supertimeline: ", Style::default().fg(Color::Cyan)),
            Span::raw(format_count(count)),
        ])];
        // Sub-counts by source
        for (label, src_count) in app.data.timeline_source_counts() {
            lines.push(Line::from(format!(
                "    {label}: {}",
                format_count(src_count)
            )));
        }
        items.push(ListItem::new(lines));
    }

    // Snapshot categories
    let categories: Vec<(&str, usize)> = vec![
        ("Network", app.data.network.len()),
        ("Processes", app.data.processes.len()),
        ("Logins", app.data.logins.len()),
        ("Packages", app.data.packages.len()),
        ("Configs", app.data.configs.len()),
        ("Hashes", app.data.hashes.len()),
        ("Chkrootkit", app.data.chkrootkit.len()),
    ];

    for (name, count) in categories {
        if count > 0 {
            items.push(ListItem::new(Line::from(vec![
                Span::raw(format!("  {name}: ")),
                Span::raw(format_count(count)),
            ])));
        }
    }

    // Artifact inventory (from collection manifest)
    if !app.data.artifact_counts.is_empty() {
        let mut counts: Vec<_> = app.data.artifact_counts.iter().collect();
        counts.sort_by(|a, b| b.1.cmp(a.1));
        let mut lines = vec![Line::from(Span::styled(
            "  Collection Artifacts:",
            Style::default().fg(Color::Green),
        ))];
        for (label, count) in counts {
            lines.push(Line::from(format!("    {label}: {}", format_count(*count))));
        }
        items.push(ListItem::new(lines));
    }

    let block = Block::default().borders(Borders::ALL).title(" Summary ");

    let list = List::new(items)
        .block(block)
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED));

    frame.render_widget(list, area);
}

/// Right panel: sparkline + alerts list.
fn draw_right_panel(frame: &mut Frame, app: &WorkbenchApp, area: Rect) {
    let chunks = Layout::vertical([
        Constraint::Length(5), // sparkline
        Constraint::Min(4),    // alerts
    ])
    .split(area);

    // Sparkline
    let sparkline_data = build_sparkline(&app.data.timeline, chunks[0].width as usize);
    let sparkline = Sparkline::default()
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Supertimeline Activity "),
        )
        .data(&sparkline_data)
        .style(Style::default().fg(Color::Cyan));
    frame.render_widget(sparkline, chunks[0]);

    // Alerts
    let critical_count = app
        .data
        .alerts
        .iter()
        .filter(|a| a.severity == AlertSeverity::Critical)
        .count();
    let warning_count = app
        .data
        .alerts
        .iter()
        .filter(|a| a.severity == AlertSeverity::Warning)
        .count();

    let title = format!(" Alerts ({critical_count} critical, {warning_count} warning) ");

    let alert_items: Vec<ListItem<'_>> = app
        .data
        .alerts
        .iter()
        .map(|alert| {
            let color = match alert.severity {
                AlertSeverity::Critical => Color::Red,
                AlertSeverity::Warning => Color::Yellow,
                AlertSeverity::Info => Color::Blue,
            };
            ListItem::new(Line::from(vec![
                Span::styled(
                    format!("{} ", alert.severity.label()),
                    Style::default().fg(color).add_modifier(Modifier::BOLD),
                ),
                Span::raw(&alert.message),
            ]))
        })
        .collect();

    let alerts_list =
        List::new(alert_items).block(Block::default().borders(Borders::ALL).title(title));

    frame.render_widget(alerts_list, chunks[1]);
}

/// Format a count with K/M suffixes for readability.
fn format_count(n: usize) -> String {
    if n >= 1_000_000 {
        format!("{:.1}M", n as f64 / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{:.1}K", n as f64 / 1_000.0)
    } else {
        n.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_count() {
        assert_eq!(format_count(0), "0");
        assert_eq!(format_count(999), "999");
        assert_eq!(format_count(1_000), "1.0K");
        assert_eq!(format_count(47_832), "47.8K");
        assert_eq!(format_count(1_000_000), "1.0M");
    }
}
