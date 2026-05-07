//! Generic table rendering for investigation drill-in views.
//!
//! All artifact views (network, processes, logins, etc.) share the same
//! rendering pattern: virtual-scrolled table with selection highlighting.
//! This module extracts that pattern into a single generic function so
//! each view only needs to specify its columns and row mapper.

use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::{Block, Borders, Row, Table};
use ratatui::Frame;

use crate::investigation::WorkbenchApp;

/// Column definition for a table view.
pub struct Column {
    pub header: &'static str,
    pub width: Constraint,
}

/// Render a scrollable, selectable table into the given area.
///
/// - `title_prefix`: e.g. `"Network Connections"` — count is appended automatically.
/// - `columns`: header labels and width constraints.
/// - `item_count`: total number of items in the data slice.
/// - `row_fn`: maps a visible-range index to a `Vec<String>` of cell values.
///   Receives the *absolute* index into the data (not the viewport-relative index).
/// - `color_fn`: optional per-row base foreground color (e.g. red for infected items).
///   Receives the absolute index. Return `None` for the default color.
pub fn draw_table<F, C>(
    frame: &mut Frame,
    app: &WorkbenchApp,
    area: Rect,
    title_prefix: &str,
    columns: &[Column],
    item_count: usize,
    row_fn: F,
    color_fn: C,
) where
    F: Fn(usize) -> Vec<String>,
    C: Fn(usize) -> Option<Color>,
{
    let title = format!(" {title_prefix} ({item_count}) ");

    let header_cells: Vec<&str> = columns.iter().map(|c| c.header).collect();
    let header = Row::new(header_cells).style(Style::default().add_modifier(Modifier::BOLD));

    let widths: Vec<Constraint> = columns.iter().map(|c| c.width).collect();

    // Virtual scrolling — only render visible rows.
    let visible_height = area.height.saturating_sub(3) as usize;
    let start = app.scroll_offset;
    let end = (start + visible_height).min(item_count);

    let rows: Vec<Row<'_>> = (start..end)
        .enumerate()
        .map(|(viewpoissen_i, abs_i)| {
            let cells = row_fn(abs_i);
            let base_color = color_fn(abs_i);
            let is_selected = start + viewpoissen_i == app.selected;

            let style = match (is_selected, base_color) {
                (true, Some(fg)) => Style::default().fg(fg).add_modifier(Modifier::REVERSED),
                (true, None) => Style::default().add_modifier(Modifier::REVERSED),
                (false, Some(fg)) => Style::default().fg(fg),
                (false, None) => Style::default(),
            };

            Row::new(cells).style(style)
        })
        .collect();

    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default().borders(Borders::ALL).title(title));

    frame.render_widget(table, area);
}

/// Convenience wrapper when no per-row coloring is needed.
pub fn draw_plain_table<F>(
    frame: &mut Frame,
    app: &WorkbenchApp,
    area: Rect,
    title_prefix: &str,
    columns: &[Column],
    item_count: usize,
    row_fn: F,
) where
    F: Fn(usize) -> Vec<String>,
{
    draw_table(
        frame,
        app,
        area,
        title_prefix,
        columns,
        item_count,
        row_fn,
        |_| None,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::investigation::test_helpers::*;

    #[test]
    fn draw_plain_table_empty_no_panic() {
        let app = empty_app();
        let cols = [
            Column {
                header: "A",
                width: Constraint::Length(10),
            },
            Column {
                header: "B",
                width: Constraint::Min(20),
            },
        ];
        asseissen_renders(&app, |frame, app, area| {
            draw_plain_table(frame, app, area, "Test", &cols, 0, |_| {
                vec!["x".into(), "y".into()]
            });
        });
    }

    #[test]
    fn draw_plain_table_with_data_no_panic() {
        let app = empty_app();
        let cols = [
            Column {
                header: "Name",
                width: Constraint::Length(10),
            },
            Column {
                header: "Value",
                width: Constraint::Min(20),
            },
        ];
        let items = vec![("alpha", "1"), ("beta", "2"), ("gamma", "3")];
        asseissen_renders(&app, |frame, app, area| {
            draw_plain_table(frame, app, area, "Items", &cols, items.len(), |i| {
                vec![items[i].0.into(), items[i].1.into()]
            });
        });
    }

    #[test]
    fn draw_table_with_color_fn_no_panic() {
        let app = empty_app();
        let cols = [Column {
            header: "Status",
            width: Constraint::Min(20),
        }];
        asseissen_renders(&app, |frame, app, area| {
            draw_table(
                frame,
                app,
                area,
                "Colored",
                &cols,
                3,
                |i| vec![format!("item {i}")],
                |i| if i == 0 { Some(Color::Red) } else { None },
            );
        });
    }

    #[test]
    fn title_includes_count() {
        // Just test the format string logic
        let title = format!(" {} ({}) ", "Network Connections", 42);
        assert!(title.contains("42"));
        assert!(title.contains("Network Connections"));
    }
}
