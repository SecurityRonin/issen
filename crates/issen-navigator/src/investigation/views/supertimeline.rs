use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Row, Table, Wrap};
use ratatui::Frame;

use crate::investigation::timeline::TimelineSource;
use crate::investigation::WorkbenchApp;

pub fn draw(frame: &mut Frame, app: &WorkbenchApp, area: Rect) {
    let chunks = Layout::horizontal([
        Constraint::Percentage(if app.show_detail { 65 } else { 100 }),
        Constraint::Percentage(if app.show_detail { 35 } else { 0 }),
    ])
    .split(area);

    draw_table(frame, app, chunks[0]);

    if app.show_detail && chunks.len() > 1 {
        draw_detail(frame, app, chunks[1]);
    }
}

fn draw_table(frame: &mut Frame, app: &WorkbenchApp, area: Rect) {
    let filter_label = app.timeline_filter_label();
    let count = app.filtered_timeline.len();
    let title = format!(" Timeline [{filter_label}] ({count} events) [f] filter ");

    let header = Row::new(vec!["Time", "Src", "Type", "Path"])
        .style(Style::default().add_modifier(Modifier::BOLD))
        .bottom_margin(0);

    // Virtual scrolling: only render visible rows
    let visible_height = area.height.saturating_sub(3) as usize; // borders + header
    let start = app.scroll_offset;
    let end = (start + visible_height).min(app.filtered_timeline.len());

    let rows: Vec<Row<'_>> = app.filtered_timeline[start..end]
        .iter()
        .enumerate()
        .map(|(i, &idx)| {
            let event = &app.data.timeline[idx];
            let is_selected = start + i == app.selected;

            let src_color = source_color(event.source);
            let style = if is_selected {
                Style::default()
                    .fg(src_color)
                    .add_modifier(Modifier::REVERSED)
            } else {
                Style::default().fg(src_color)
            };

            Row::new(vec![
                format_timestamp(event.timestamp),
                event.source.label().to_string(),
                event.timestamp_type.label().to_string(),
                truncate_path(&event.path, 40),
            ])
            .style(style)
        })
        .collect();

    let widths = [
        Constraint::Length(19), // "2026-03-24T19:01:05"
        Constraint::Length(8),  // "bodyfile" (longest source label)
        Constraint::Length(6),  // "FN-M" etc
        Constraint::Min(20),    // path
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default().borders(Borders::ALL).title(title));

    frame.render_widget(table, area);
}

fn draw_detail(frame: &mut Frame, app: &WorkbenchApp, area: Rect) {
    if app.filtered_timeline.is_empty() {
        let empty = Paragraph::new("No events")
            .block(Block::default().borders(Borders::ALL).title(" Detail "));
        frame.render_widget(empty, area);
        return;
    }

    let idx = app
        .filtered_timeline
        .get(app.selected)
        .copied()
        .unwrap_or(0);
    let event = &app.data.timeline[idx];

    let lines = vec![
        Line::from(vec![
            Span::styled("Source: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(event.source.label()),
        ]),
        Line::from(vec![
            Span::styled("Type: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(event.timestamp_type.label()),
        ]),
        Line::from(vec![
            Span::styled("Time: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(format_timestamp(event.timestamp)),
        ]),
        Line::from(vec![
            Span::styled("Path: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(&event.path),
        ]),
        Line::from(""),
        Line::from(vec![Span::styled(
            "Description: ",
            Style::default().add_modifier(Modifier::BOLD),
        )]),
        Line::from(event.description.as_str()),
        Line::from(""),
        Line::from(vec![Span::styled(
            "Extra: ",
            Style::default().add_modifier(Modifier::BOLD),
        )]),
        Line::from(event.extra.as_str()),
    ];

    let detail = Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).title(" Detail "))
        .wrap(Wrap { trim: false });

    frame.render_widget(detail, area);
}

fn source_color(source: TimelineSource) -> Color {
    match source {
        TimelineSource::Bodyfile => Color::Green,
        TimelineSource::MftSi => Color::Cyan,
        TimelineSource::MftFn => Color::Blue,
        TimelineSource::UsnJournal => Color::Magenta,
        TimelineSource::LoginHistory => Color::Yellow,
        TimelineSource::ProcessList => Color::LightRed,
        TimelineSource::Registry => Color::LightCyan,
        TimelineSource::EventLog => Color::White,
    }
}

fn format_timestamp(ts: i64) -> String {
    use chrono::{DateTime, Utc};
    DateTime::from_timestamp(ts, 0).map_or_else(
        || format!("{ts}"),
        |dt: DateTime<Utc>| dt.format("%Y-%m-%dT%H:%M:%S").to_string(),
    )
}

fn truncate_path(path: &str, max_len: usize) -> String {
    if path.len() <= max_len {
        path.to_string()
    } else {
        format!("...{}", &path[path.len() - max_len + 3..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_timestamp_valid() {
        // 2024-01-01T00:00:00 UTC = 1704067200
        assert_eq!(format_timestamp(1704067200), "2024-01-01T00:00:00");
    }

    #[test]
    fn format_timestamp_zero() {
        assert_eq!(format_timestamp(0), "1970-01-01T00:00:00");
    }

    #[test]
    fn format_timestamp_negative_falls_back() {
        // Very old timestamps should still produce something
        let result = format_timestamp(-1);
        assert!(!result.is_empty());
    }

    #[test]
    fn truncate_path_short() {
        assert_eq!(truncate_path("/short/path", 40), "/short/path");
    }

    #[test]
    fn truncate_path_exact_length() {
        let path = "x".repeat(40);
        assert_eq!(truncate_path(&path, 40), path);
    }

    #[test]
    fn truncate_path_long() {
        let path = "/very/long/path/that/exceeds/the/maximum/allowed/length/for/display";
        let result = truncate_path(path, 30);
        assert!(result.starts_with("..."));
        assert_eq!(result.len(), 30);
    }

    #[test]
    fn source_color_all_variants() {
        // Just verify no panics and each source gets a color
        use crate::investigation::timeline::TimelineSource;
        let sources = [
            TimelineSource::Bodyfile,
            TimelineSource::MftSi,
            TimelineSource::MftFn,
            TimelineSource::UsnJournal,
            TimelineSource::LoginHistory,
            TimelineSource::ProcessList,
            TimelineSource::Registry,
            TimelineSource::EventLog,
        ];
        for src in sources {
            let _color = source_color(src);
        }
    }
}
