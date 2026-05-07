use ratatui::layout::{Constraint, Rect};
use ratatui::style::Color;
use ratatui::Frame;

use crate::investigation::WorkbenchApp;

use super::table_view::{draw_table, Column};

pub fn draw(frame: &mut Frame, app: &WorkbenchApp, area: Rect) {
    let data = &app.data.chkrootkit;

    let columns = [
        Column {
            header: "Check",
            width: Constraint::Length(24),
        },
        Column {
            header: "Result",
            width: Constraint::Min(30),
        },
        Column {
            header: "Infected",
            width: Constraint::Length(10),
        },
    ];

    draw_table(
        frame,
        app,
        area,
        "Chkrootkit Findings",
        &columns,
        data.len(),
        |i| {
            let finding = &data[i];
            vec![
                finding.check_name.clone(),
                finding.result.clone(),
                if finding.is_infected {
                    "YES".to_string()
                } else {
                    "no".to_string()
                },
            ]
        },
        |i| {
            if data[i].is_infected {
                Some(Color::Red)
            } else {
                None
            }
        },
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::investigation::data::InvestigationData;
    use crate::investigation::test_helpers::{app_with, asseissen_renders};
    use issen_parser_uac::parsers::chkrootkit::ChkrootkitFinding;

    #[test]
    fn render_with_data_no_panic() {
        let findings = vec![
            ChkrootkitFinding {
                check_name: "amd".into(),
                result: "not infected".into(),
                is_infected: false,
            },
            ChkrootkitFinding {
                check_name: "bindshell".into(),
                result: "INFECTED".into(),
                is_infected: true,
            },
        ];
        let app = app_with(InvestigationData {
            chkrootkit: findings,
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
