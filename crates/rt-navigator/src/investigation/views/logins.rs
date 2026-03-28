use ratatui::layout::{Constraint, Rect};
use ratatui::Frame;

use super::table_view::Column;
use crate::investigation::WorkbenchApp;

pub fn draw(frame: &mut Frame, app: &WorkbenchApp, area: Rect) {
    let data = &app.data.logins;

    let columns = [
        Column {
            header: "User",
            width: Constraint::Length(12),
        },
        Column {
            header: "Terminal",
            width: Constraint::Length(10),
        },
        Column {
            header: "Source",
            width: Constraint::Length(16),
        },
        Column {
            header: "Login",
            width: Constraint::Length(20),
        },
        Column {
            header: "Logout",
            width: Constraint::Length(20),
        },
        Column {
            header: "Duration",
            width: Constraint::Min(10),
        },
    ];

    super::table_view::draw_plain_table(
        frame,
        app,
        area,
        "Login Records",
        &columns,
        data.len(),
        |i| {
            let record = &data[i];
            vec![
                record.user.clone(),
                record.terminal.clone(),
                record.source.clone(),
                record.login_time.as_deref().unwrap_or("-").to_string(),
                record.logout_time.as_deref().unwrap_or("-").to_string(),
                record.duration.as_deref().unwrap_or("-").to_string(),
            ]
        },
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::investigation::data::InvestigationData;
    use crate::investigation::test_helpers::{app_with, assert_renders};
    use rt_parser_uac::parsers::system::LoginRecord;

    #[test]
    fn render_with_data_no_panic() {
        let logins = vec![
            LoginRecord {
                user: "root".into(),
                terminal: "pts/0".into(),
                source: "192.168.1.10".into(),
                login_time: Some("Mon Jan  1 00:00".into()),
                logout_time: Some("Mon Jan  1 01:00".into()),
                duration: Some("01:00".into()),
            },
            LoginRecord {
                user: "admin".into(),
                terminal: "tty1".into(),
                source: "".into(),
                login_time: None,
                logout_time: None,
                duration: None,
            },
        ];
        let app = app_with(InvestigationData {
            logins,
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
