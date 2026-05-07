//! Library re-exports for integration tests.
//!
//! The `rt-navigator` crate is primarily a binary (`rt-nav`). This library
//! target exposes the investigation data-loading functions so that integration
//! tests can exercise the full collection-loading pipeline without going
//! through the TUI.

/// Investigation data model and collection loaders.
///
/// Re-exports only the data-oriented submodules (no TUI dependencies).
/// Uses `#[path]` to bypass `investigation/mod.rs` which depends on binary-only
/// modules (`app`, `ui`, etc.).
pub mod investigation {
    #[path = "../investigation/alerts/mod.rs"]
    pub mod alerts;

    #[path = "../investigation/timeline.rs"]
    pub mod timeline;

    #[path = "../investigation/data.rs"]
    pub mod data;
}
