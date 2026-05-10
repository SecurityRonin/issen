use ratatui::layout::{Constraint, Rect};
use ratatui::Frame;

use super::table_view::Column;
use crate::investigation::WorkbenchApp;

pub fn draw(frame: &mut Frame, app: &WorkbenchApp, area: Rect) {
    let data = &app.data.packages;

    let columns = [
        Column {
            header: "Name",
            width: Constraint::Min(20),
        },
        Column {
            header: "Version",
            width: Constraint::Length(15),
        },
        Column {
            header: "Manager",
            width: Constraint::Length(8),
        },
    ];

    super::table_view::draw_plain_table(
        frame,
        app,
        area,
        "Installed Packages",
        &columns,
        data.len(),
        |i| {
            let pkg = &data[i];
            vec![
                pkg.name.clone(),
                pkg.version.clone(),
                format!("{:?}", pkg.manager),
            ]
        },
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::investigation::data::InvestigationData;
    use crate::investigation::test_helpers::{app_with, assert_renders};
    use issen_parser_uac::parsers::packages::{InstalledPackage, PackageManager};

    #[test]
    fn render_with_data_no_panic() {
        let packages = vec![
            InstalledPackage {
                name: "openssl".into(),
                version: "3.0.2-0ubuntu1".into(),
                manager: PackageManager::Dpkg,
            },
            InstalledPackage {
                name: "curl".into(),
                version: "7.81.0-1".into(),
                manager: PackageManager::Rpm,
            },
        ];
        let app = app_with(InvestigationData {
            packages,
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
