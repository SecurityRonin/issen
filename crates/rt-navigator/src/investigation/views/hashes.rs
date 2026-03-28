use ratatui::layout::{Constraint, Rect};
use ratatui::Frame;

use crate::investigation::WorkbenchApp;

use super::table_view::{draw_plain_table, Column};

pub fn draw(frame: &mut Frame, app: &WorkbenchApp, area: Rect) {
    let data = &app.data.hashes;

    let columns = [
        Column {
            header: "Algorithm",
            width: Constraint::Length(8),
        },
        Column {
            header: "Hash",
            width: Constraint::Length(64),
        },
        Column {
            header: "Path",
            width: Constraint::Min(20),
        },
    ];

    draw_plain_table(
        frame,
        app,
        area,
        "Hashed Executables",
        &columns,
        data.len(),
        |i| {
            let h = &data[i];
            vec![h.algorithm.clone(), h.hash.clone(), h.path.clone()]
        },
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::investigation::data::InvestigationData;
    use crate::investigation::test_helpers::{app_with, assert_renders};
    use rt_parser_uac::parsers::hash_execs::HashedExecutable;

    #[test]
    fn render_with_data_no_panic() {
        let hashes = vec![
            HashedExecutable {
                algorithm: "sha256".into(),
                hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".into(),
                path: "/usr/bin/ls".into(),
            },
            HashedExecutable {
                algorithm: "md5".into(),
                hash: "d41d8cd98f00b204e9800998ecf8427e".into(),
                path: "/usr/bin/cat".into(),
            },
        ];
        let app = app_with(InvestigationData {
            hashes,
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
