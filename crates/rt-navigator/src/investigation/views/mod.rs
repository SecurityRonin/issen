pub mod chkrootkit;
pub mod configs;
pub mod hashes;
pub mod logins;
pub mod network;
pub mod packages;
pub mod process;
pub mod supertimeline;
pub mod table_view;

use ratatui::layout::Rect;
use ratatui::Frame;

use super::{WorkbenchApp, WorkbenchView};

/// Render the current view's list content in the given area.
pub fn draw_view(frame: &mut Frame, app: &WorkbenchApp, area: Rect) {
    match app.current_view() {
        // Dashboard is handled separately by dashboard.rs;
        // MftTree is handled by delegation to existing App.
        WorkbenchView::Dashboard | WorkbenchView::MftTree => {}
        WorkbenchView::Timeline => supertimeline::draw(frame, app, area),
        WorkbenchView::Network => network::draw(frame, app, area),
        WorkbenchView::Processes => process::draw(frame, app, area),
        WorkbenchView::Logins => logins::draw(frame, app, area),
        WorkbenchView::Packages => packages::draw(frame, app, area),
        WorkbenchView::Configs => configs::draw(frame, app, area),
        WorkbenchView::Hashes => hashes::draw(frame, app, area),
        WorkbenchView::Chkrootkit => chkrootkit::draw(frame, app, area),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::investigation::test_helpers::*;

    /// Build a `WorkbenchApp` with empty `InvestigationData` and all views
    /// forced into `available_views` so we can exercise every branch of
    /// `draw_view` without needing real data.
    fn make_all_views_app() -> WorkbenchApp {
        let mut app = empty_app();
        // Force all views into available_views so we can switch to any of them.
        app.available_views = vec![
            WorkbenchView::Dashboard,
            WorkbenchView::MftTree,
            WorkbenchView::Timeline,
            WorkbenchView::Network,
            WorkbenchView::Processes,
            WorkbenchView::Logins,
            WorkbenchView::Packages,
            WorkbenchView::Configs,
            WorkbenchView::Hashes,
            WorkbenchView::Chkrootkit,
        ];
        app
    }

    /// Helper: set the app to a specific view by index into `available_views`.
    fn set_view(app: &mut WorkbenchApp, view: WorkbenchView) {
        let idx = app
            .available_views
            .iter()
            .position(|v| *v == view)
            .expect("view must be in available_views");
        app.current_view_idx = idx;
    }

    // -----------------------------------------------------------------------
    // No-op views (Dashboard, MftTree)
    // -----------------------------------------------------------------------

    #[test]
    fn draw_view_dashboard_is_noop() {
        let app = make_all_views_app();
        // Default view is Dashboard (index 0).
        assert_eq!(app.current_view(), WorkbenchView::Dashboard);
        assert_renders(&app, |frame, app, area| draw_view(frame, app, area));
        // No panic = success.
    }

    #[test]
    fn draw_view_mft_tree_is_noop() {
        let mut app = make_all_views_app();
        set_view(&mut app, WorkbenchView::MftTree);
        assert_eq!(app.current_view(), WorkbenchView::MftTree);
        assert_renders(&app, |frame, app, area| draw_view(frame, app, area));
    }

    // -----------------------------------------------------------------------
    // Content views (each delegates to its sub-module draw function)
    // -----------------------------------------------------------------------

    #[test]
    fn draw_view_timeline_no_panic() {
        let mut app = make_all_views_app();
        set_view(&mut app, WorkbenchView::Timeline);
        assert_renders(&app, |frame, app, area| draw_view(frame, app, area));
    }

    #[test]
    fn draw_view_network_no_panic() {
        let mut app = make_all_views_app();
        set_view(&mut app, WorkbenchView::Network);
        assert_renders(&app, |frame, app, area| draw_view(frame, app, area));
    }

    #[test]
    fn draw_view_processes_no_panic() {
        let mut app = make_all_views_app();
        set_view(&mut app, WorkbenchView::Processes);
        assert_renders(&app, |frame, app, area| draw_view(frame, app, area));
    }

    #[test]
    fn draw_view_logins_no_panic() {
        let mut app = make_all_views_app();
        set_view(&mut app, WorkbenchView::Logins);
        assert_renders(&app, |frame, app, area| draw_view(frame, app, area));
    }

    #[test]
    fn draw_view_packages_no_panic() {
        let mut app = make_all_views_app();
        set_view(&mut app, WorkbenchView::Packages);
        assert_renders(&app, |frame, app, area| draw_view(frame, app, area));
    }

    #[test]
    fn draw_view_configs_no_panic() {
        let mut app = make_all_views_app();
        set_view(&mut app, WorkbenchView::Configs);
        assert_renders(&app, |frame, app, area| draw_view(frame, app, area));
    }

    #[test]
    fn draw_view_hashes_no_panic() {
        let mut app = make_all_views_app();
        set_view(&mut app, WorkbenchView::Hashes);
        assert_renders(&app, |frame, app, area| draw_view(frame, app, area));
    }

    #[test]
    fn draw_view_chkrootkit_no_panic() {
        let mut app = make_all_views_app();
        set_view(&mut app, WorkbenchView::Chkrootkit);
        assert_renders(&app, |frame, app, area| draw_view(frame, app, area));
    }
}
