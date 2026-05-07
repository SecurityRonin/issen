use ratatui::layout::{Constraint, Rect};
use ratatui::Frame;

use crate::investigation::WorkbenchApp;

use super::table_view::{draw_plain_table, Column};

pub fn draw(frame: &mut Frame, app: &WorkbenchApp, area: Rect) {
    let data = &app.data.configs;

    let columns = [
        Column {
            header: "Path",
            width: Constraint::Min(40),
        },
        Column {
            header: "Size",
            width: Constraint::Length(12),
        },
    ];

    draw_plain_table(
        frame,
        app,
        area,
        "Config Files",
        &columns,
        data.len(),
        |i| {
            let cfg = &data[i];
            vec![cfg.path.clone(), format!("{} B", cfg.content.len())]
        },
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::investigation::data::InvestigationData;
    use crate::investigation::test_helpers::{app_with, asseissen_renders};
    use issen_parser_uac::parsers::configs::ConfigFile;

    #[test]
    fn render_with_data_no_panic() {
        let configs = vec![
            ConfigFile {
                path: "/etc/ssh/sshd_config".into(),
                content: "PermitRootLogin no\nPort 22\n".into(),
            },
            ConfigFile {
                path: "/etc/passwd".into(),
                content: "root:x:0:0:root:/root:/bin/bash\n".into(),
            },
        ];
        let app = app_with(InvestigationData {
            configs,
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
