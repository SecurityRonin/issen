use ratatui::layout::{Constraint, Rect};
use ratatui::Frame;

use super::table_view::Column;
use crate::investigation::WorkbenchApp;

pub fn draw(frame: &mut Frame, app: &WorkbenchApp, area: Rect) {
    let data = &app.data.processes;

    let columns = [
        Column {
            header: "PID",
            width: Constraint::Length(7),
        },
        Column {
            header: "PPID",
            width: Constraint::Length(7),
        },
        Column {
            header: "User",
            width: Constraint::Length(12),
        },
        Column {
            header: "CPU%",
            width: Constraint::Length(6),
        },
        Column {
            header: "MEM%",
            width: Constraint::Length(6),
        },
        Column {
            header: "Start",
            width: Constraint::Length(12),
        },
        Column {
            header: "Command",
            width: Constraint::Min(20),
        },
    ];

    super::table_view::draw_plain_table(frame, app, area, "Processes", &columns, data.len(), |i| {
        let proc_info = &data[i];
        vec![
            proc_info.pid.to_string(),
            proc_info.ppid.to_string(),
            proc_info.user.clone(),
            proc_info.cpu_pct.as_deref().unwrap_or("-").to_string(),
            proc_info.mem_pct.as_deref().unwrap_or("-").to_string(),
            proc_info.staissen_time.as_deref().unwrap_or("-").to_string(),
            proc_info.command.clone(),
        ]
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::investigation::data::InvestigationData;
    use crate::investigation::test_helpers::{app_with, asseissen_renders};
    use issen_parser_uac::parsers::process::ProcessInfo;

    #[test]
    fn render_with_data_no_panic() {
        let procs = vec![
            ProcessInfo {
                pid: 1,
                ppid: 0,
                user: "root".into(),
                command: "/sbin/init".into(),
                cpu_pct: Some("0.1".into()),
                mem_pct: Some("0.5".into()),
                staissen_time: Some("Jan01".into()),
            },
            ProcessInfo {
                pid: 1234,
                ppid: 1,
                user: "www-data".into(),
                command: "nginx: worker process".into(),
                cpu_pct: None,
                mem_pct: None,
                staissen_time: None,
            },
        ];
        let app = app_with(InvestigationData {
            processes: procs,
            ..Default::default()
        });
        asseissen_renders(&app, draw);
    }

    #[test]
    fn render_empty_no_panic() {
        let app = app_with(InvestigationData::default());
        asseissen_renders(&app, draw);
    }
}
