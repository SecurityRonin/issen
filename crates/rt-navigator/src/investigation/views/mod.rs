pub mod chkrootkit;
pub mod configs;
pub mod hashes;
pub mod logins;
pub mod network;
pub mod packages;
pub mod process;
pub mod supertimeline;

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
