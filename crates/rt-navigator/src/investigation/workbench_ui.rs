use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use super::dashboard::draw_dashboard;
use super::detail::draw_detail;
use super::views::draw_view;
use super::{WorkbenchApp, WorkbenchView};

/// Main rendering entry point for the investigation workbench.
pub fn draw_workbench(frame: &mut Frame, app: &mut WorkbenchApp) {
    let area = frame.area();

    // If in MFT tree view, delegate to existing ui::draw
    if app.current_view() == WorkbenchView::MftTree {
        if let Some(ref mut mft_app) = app.mft_app {
            crate::ui::draw(frame, mft_app);
        }
        return;
    }

    let chunks = Layout::vertical([
        Constraint::Length(3), // header + tab bar
        Constraint::Min(5),    // main content
        Constraint::Length(1), // footer
    ])
    .split(area);

    draw_header(frame, app, chunks[0]);
    draw_body(frame, app, chunks[1]);
    draw_footer(frame, app, chunks[2]);
}

fn draw_header(frame: &mut Frame, app: &WorkbenchApp, area: Rect) {
    let meta = &app.data.metadata;

    let title_line = Line::from(vec![
        Span::styled(
            " RT Investigation: ",
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Span::raw(meta.hostname.clone()),
        Span::raw("   OS: "),
        Span::raw(meta.os.clone()),
        Span::raw(format!("   {} ", &meta.collection_tool)),
    ]);

    // Tab bar
    let tab_titles: Vec<String> = app
        .available_views
        .iter()
        .enumerate()
        .map(|(i, v)| {
            if i == app.current_view_idx {
                format!("[{}]", v.label())
            } else {
                v.label().to_string()
            }
        })
        .collect();

    let tabs_line = Line::from(
        tab_titles
            .iter()
            .enumerate()
            .flat_map(|(i, title)| {
                let style = if i == app.current_view_idx {
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::DarkGray)
                };
                vec![Span::styled(title.clone(), style), Span::raw("  ")]
            })
            .collect::<Vec<Span>>(),
    );

    let header = Paragraph::new(vec![title_line, tabs_line])
        .block(Block::default().borders(Borders::BOTTOM));

    frame.render_widget(header, area);
}

fn draw_body(frame: &mut Frame, app: &WorkbenchApp, area: Rect) {
    match app.current_view() {
        WorkbenchView::Dashboard => draw_dashboard(frame, app, area),
        WorkbenchView::Timeline => draw_view(frame, app, area),
        _ => {
            // Artifact views with optional detail panel
            if app.show_detail {
                let chunks =
                    Layout::horizontal([Constraint::Percentage(65), Constraint::Percentage(35)])
                        .split(area);
                draw_view(frame, app, chunks[0]);
                draw_detail(frame, app, chunks[1]);
            } else {
                draw_view(frame, app, area);
            }
        }
    }
}

fn draw_footer(frame: &mut Frame, app: &WorkbenchApp, area: Rect) {
    let view = app.current_view();
    let count = app.current_item_count();

    let mut spans = vec![
        Span::raw(" [Tab] switch view"),
        Span::raw("  [Esc] dashboard"),
    ];

    if view == WorkbenchView::Timeline {
        spans.push(Span::raw("  [f] filter"));
    }

    spans.extend([
        Span::raw("  [s] sort"),
        Span::raw("  [/] search"),
        Span::raw("  [q] quit"),
    ]);

    if app.search_mode {
        spans.push(Span::styled(
            format!("  /{}", app.search_query),
            Style::default().fg(Color::Yellow),
        ));
    }

    spans.push(Span::styled(
        format!("  {count} items"),
        Style::default().fg(Color::DarkGray),
    ));

    let footer = Paragraph::new(Line::from(spans));
    frame.render_widget(footer, area);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::investigation::data::{CollectionMetadata, InvestigationData};
    use crate::investigation::test_helpers::*;
    use crate::investigation::timeline::{TimelineEvent, TimelineSource, TimestampType};
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    fn make_test_app() -> WorkbenchApp {
        let timeline: Vec<TimelineEvent> = (0..5)
            .map(|i| TimelineEvent {
                timestamp: i * 100 + 1704067200,
                timestamp_type: TimestampType::Modified,
                source: TimelineSource::Bodyfile,
                path: format!("/test/file{i}.txt"),
                description: format!("Test event {i}"),
                extra: String::new(),
            })
            .collect();

        let network = vec![rt_parser_uac::parsers::network::NetworkConnection {
            protocol: "tcp".to_string(),
            local_addr: "0.0.0.0:80".to_string(),
            remote_addr: "1.2.3.4:443".to_string(),
            state: "ESTABLISHED".to_string(),
            pid: Some(1234),
            program: Some("nginx".to_string()),
        }];

        app_with(InvestigationData {
            metadata: CollectionMetadata {
                hostname: "testhost".to_string(),
                os: "Linux".to_string(),
                collection_tool: "UAC".to_string(),
                acquisition_time: 1704067200,
            },
            timeline,
            network,
            ..Default::default()
        })
    }

    #[test]
    fn render_dashboard_no_panic() {
        let mut app = make_test_app();
        let backend = TestBackend::new(120, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| draw_workbench(frame, &mut app))
            .unwrap();
    }

    #[test]
    fn render_timeline_view_no_panic() {
        let mut app = make_test_app();
        app.next_view(); // Switch to Timeline
        let backend = TestBackend::new(120, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| draw_workbench(frame, &mut app))
            .unwrap();
    }

    #[test]
    fn render_network_view_no_panic() {
        let mut app = make_test_app();
        // Find and switch to Network view
        for (i, v) in app.available_views.iter().enumerate() {
            if *v == WorkbenchView::Network {
                app.current_view_idx = i;
                break;
            }
        }
        let backend = TestBackend::new(120, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| draw_workbench(frame, &mut app))
            .unwrap();
    }

    #[test]
    fn render_with_search_mode_no_panic() {
        let mut app = make_test_app();
        app.search_mode = true;
        app.search_query = "test".to_string();
        let backend = TestBackend::new(120, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| draw_workbench(frame, &mut app))
            .unwrap();
    }

    #[test]
    fn render_small_terminal_no_panic() {
        let mut app = make_test_app();
        let backend = TestBackend::new(40, 10); // very small
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| draw_workbench(frame, &mut app))
            .unwrap();
    }

    #[test]
    fn render_empty_data_no_panic() {
        let mut app = empty_app();
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| draw_workbench(frame, &mut app))
            .unwrap();
    }
}
