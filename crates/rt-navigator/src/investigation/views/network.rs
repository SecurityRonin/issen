use ratatui::layout::{Constraint, Rect};
use ratatui::Frame;

use super::table_view::Column;
use crate::investigation::WorkbenchApp;

pub fn draw(frame: &mut Frame, app: &WorkbenchApp, area: Rect) {
    let data = &app.data.network;

    let columns = [
        Column {
            header: "Proto",
            width: Constraint::Length(6),
        },
        Column {
            header: "Local Addr",
            width: Constraint::Length(22),
        },
        Column {
            header: "Remote Addr",
            width: Constraint::Length(22),
        },
        Column {
            header: "State",
            width: Constraint::Length(12),
        },
        Column {
            header: "PID",
            width: Constraint::Length(7),
        },
        Column {
            header: "Program",
            width: Constraint::Min(15),
        },
    ];

    super::table_view::draw_plain_table(
        frame,
        app,
        area,
        "Network Connections",
        &columns,
        data.len(),
        |i| {
            let conn = &data[i];
            vec![
                conn.protocol.clone(),
                conn.local_addr.clone(),
                conn.remote_addr.clone(),
                conn.state.clone(),
                conn.pid
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "-".into()),
                conn.program.as_deref().unwrap_or("-").to_string(),
            ]
        },
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::investigation::data::InvestigationData;
    use crate::investigation::test_helpers::{app_with, assert_renders};
    use rt_parser_uac::parsers::network::NetworkConnection;

    #[test]
    fn render_with_data_no_panic() {
        let conns = vec![
            NetworkConnection {
                protocol: "tcp".into(),
                local_addr: "127.0.0.1:8080".into(),
                remote_addr: "10.0.0.1:443".into(),
                state: "ESTABLISHED".into(),
                pid: Some(1234),
                program: Some("nginx".into()),
            },
            NetworkConnection {
                protocol: "udp".into(),
                local_addr: "0.0.0.0:53".into(),
                remote_addr: "*:*".into(),
                state: "LISTEN".into(),
                pid: None,
                program: None,
            },
        ];
        let app = app_with(InvestigationData {
            network: conns,
            ..Default::default()
        });
        assert_renders(&app, draw);
    }

    #[test]
    fn render_empty_no_panic() {
        let app = app_with(InvestigationData::default());
        assert_renders(&app, draw);
    }
}
