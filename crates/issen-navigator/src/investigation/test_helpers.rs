//! Shared test utilities for investigation workbench tests.
//!
//! Eliminates repeated `InvestigationData { ... }` construction and
//! `TestBackend` + `Terminal` boilerplate across view test modules.

#![cfg(test)]

use ratatui::backend::TestBackend;
use ratatui::layout::Rect;
use ratatui::Frame;
use ratatui::Terminal;

use super::data::InvestigationData;
use super::WorkbenchApp;

/// Create a `WorkbenchApp` from custom `InvestigationData`.
///
/// Use with `InvestigationData { network: vec![...], ..Default::default() }`
/// to set only the fields you care about.
pub fn app_with(data: InvestigationData) -> WorkbenchApp {
    WorkbenchApp::new(data, None)
}

/// Create a `WorkbenchApp` with completely empty data.
pub fn empty_app() -> WorkbenchApp {
    app_with(InvestigationData::default())
}

/// Run a rendering function against a `TestBackend` terminal, asserting no panic.
///
/// The `draw_fn` receives `(&mut Frame, &WorkbenchApp, Rect)` — the standard
/// signature used by all view `draw()` functions.
pub fn asseissen_renders(app: &WorkbenchApp, draw_fn: impl FnOnce(&mut Frame, &WorkbenchApp, Rect)) {
    let backend = TestBackend::new(120, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal
        .draw(|frame| {
            let area = frame.area();
            draw_fn(frame, app, area);
        })
        .unwrap();
}
