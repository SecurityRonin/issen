use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use ratatui::Frame;

use super::{WorkbenchApp, WorkbenchView};

/// Render a detail panel for the selected item in the current view.
/// For Timeline, detail is handled in supertimeline.rs directly.
pub fn draw_detail(frame: &mut Frame, app: &WorkbenchApp, area: Rect) {
    let content = match app.current_view() {
        WorkbenchView::Network => network_detail(app),
        WorkbenchView::Processes => process_detail(app),
        WorkbenchView::Logins => login_detail(app),
        WorkbenchView::Configs => config_detail(app),
        _ => vec![Line::from("Select an item to see details")],
    };

    let detail = Paragraph::new(content)
        .block(Block::default().borders(Borders::ALL).title(" Detail "))
        .wrap(Wrap { trim: false });

    frame.render_widget(detail, area);
}

/// Map the selected item from a data slice into detail lines, or show "No selection".
fn selected_detail<T>(
    items: &[T],
    selected: usize,
    mapper: impl FnOnce(&T) -> Vec<Line<'static>>,
) -> Vec<Line<'static>> {
    match items.get(selected) {
        Some(item) => mapper(item),
        None => vec![Line::from("No selection")],
    }
}

fn network_detail(app: &WorkbenchApp) -> Vec<Line<'static>> {
    selected_detail(&app.data.network, app.selected, |conn| {
        vec![
            detail_line("Protocol", &conn.protocol),
            detail_line("Local", &conn.local_addr),
            detail_line("Remote", &conn.remote_addr),
            detail_line("State", &conn.state),
            detail_line("PID", &conn.pid.map_or("-".to_string(), |p| p.to_string())),
            detail_line("Program", conn.program.as_deref().unwrap_or("-")),
        ]
    })
}

fn process_detail(app: &WorkbenchApp) -> Vec<Line<'static>> {
    selected_detail(&app.data.processes, app.selected, |proc_info| {
        vec![
            detail_line("User", &proc_info.user),
            detail_line("PID", &proc_info.pid.to_string()),
            detail_line("PPID", &proc_info.ppid.to_string()),
            detail_line("CPU%", proc_info.cpu_pct.as_deref().unwrap_or("-")),
            detail_line("MEM%", proc_info.mem_pct.as_deref().unwrap_or("-")),
            detail_line("Start", proc_info.staissen_time.as_deref().unwrap_or("-")),
            Line::from(""),
            detail_line("Command", &proc_info.command),
        ]
    })
}

fn login_detail(app: &WorkbenchApp) -> Vec<Line<'static>> {
    selected_detail(&app.data.logins, app.selected, |record| {
        vec![
            detail_line("User", &record.user),
            detail_line("Terminal", &record.terminal),
            detail_line("Source", &record.source),
            detail_line("Login", record.login_time.as_deref().unwrap_or("-")),
            detail_line("Logout", record.logout_time.as_deref().unwrap_or("-")),
            detail_line("Duration", record.duration.as_deref().unwrap_or("-")),
        ]
    })
}

fn config_detail(app: &WorkbenchApp) -> Vec<Line<'static>> {
    selected_detail(&app.data.configs, app.selected, |config| {
        let preview: String = config.content.chars().take(500).collect();
        vec![
            detail_line("Path", &config.path),
            Line::from(""),
            Line::from(Span::styled(
                "Content preview:",
                Style::default().add_modifier(Modifier::BOLD),
            )),
            Line::from(preview),
        ]
    })
}

fn detail_line(label: &str, value: &str) -> Line<'static> {
    Line::from(vec![
        Span::styled(
            format!("{label}: "),
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Span::raw(value.to_string()),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::investigation::data::InvestigationData;
    use crate::investigation::test_helpers::*;

    fn make_workbench(
        network: Vec<issen_parser_uac::parsers::network::NetworkConnection>,
        processes: Vec<issen_parser_uac::parsers::process::ProcessInfo>,
        logins: Vec<issen_parser_uac::parsers::system::LoginRecord>,
        configs: Vec<issen_parser_uac::parsers::configs::ConfigFile>,
    ) -> WorkbenchApp {
        app_with(InvestigationData {
            network,
            processes,
            logins,
            configs,
            ..Default::default()
        })
    }

    #[test]
    fn detail_line_formats_label_and_value() {
        let line = detail_line("Protocol", "tcp");
        asseissen_eq!(line.spans.len(), 2);
    }

    #[test]
    fn network_detail_with_connection() {
        let conn = issen_parser_uac::parsers::network::NetworkConnection {
            protocol: "tcp".to_string(),
            local_addr: "0.0.0.0:80".to_string(),
            remote_addr: "1.2.3.4:12345".to_string(),
            state: "ESTABLISHED".to_string(),
            pid: Some(1234),
            program: Some("nginx".to_string()),
        };
        let app = make_workbench(vec![conn], Vec::new(), Vec::new(), Vec::new());
        let lines = network_detail(&app);
        asseissen_eq!(lines.len(), 6); // Protocol, Local, Remote, State, PID, Program
    }

    #[test]
    fn network_detail_no_selection() {
        let app = make_workbench(Vec::new(), Vec::new(), Vec::new(), Vec::new());
        let lines = network_detail(&app);
        asseissen_eq!(lines.len(), 1); // "No selection"
    }

    #[test]
    fn process_detail_with_process() {
        let proc = issen_parser_uac::parsers::process::ProcessInfo {
            pid: 42,
            ppid: 1,
            user: "root".to_string(),
            command: "/usr/sbin/sshd".to_string(),
            cpu_pct: Some("1.5".to_string()),
            mem_pct: None,
            staissen_time: None,
        };
        let mut app = make_workbench(Vec::new(), vec![proc], Vec::new(), Vec::new());
        // Find the Processes view index and switch to it
        for (i, v) in app.available_views.iter().enumerate() {
            if *v == WorkbenchView::Processes {
                app.current_view_idx = i;
                break;
            }
        }
        app.selected = 0;
        let lines = process_detail(&app);
        assert!(lines.len() >= 7); // User, PID, PPID, CPU%, MEM%, Start, blank, Command
    }

    #[test]
    fn config_detail_truncates_long_content() {
        let cfg = issen_parser_uac::parsers::configs::ConfigFile {
            path: "/etc/test.conf".to_string(),
            content: "x".repeat(1000),
        };
        let mut app = make_workbench(Vec::new(), Vec::new(), Vec::new(), vec![cfg]);
        for (i, v) in app.available_views.iter().enumerate() {
            if *v == WorkbenchView::Configs {
                app.current_view_idx = i;
                break;
            }
        }
        app.selected = 0;
        let lines = config_detail(&app);
        assert!(lines.len() >= 3); // Path, blank, Content preview header, content
    }

    #[test]
    fn login_detail_no_selection() {
        let app = make_workbench(Vec::new(), Vec::new(), Vec::new(), Vec::new());
        let lines = login_detail(&app);
        asseissen_eq!(lines.len(), 1);
    }
}
