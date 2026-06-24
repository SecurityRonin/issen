#![allow(clippy::doc_markdown, clippy::missing_errors_doc)]

pub mod artifacts;
pub mod classify;
pub mod config;
pub mod container;
pub mod coverage;
pub mod error;
pub mod plugin;
pub mod timeline;

/// CADET forensic-semantic category, re-exported from `forensicnomicon` for
/// convenience: parsers tag their `TimelineEvent`s with `issen_core::ActivityCategory`
/// without each taking a direct `forensicnomicon` dependency.
pub use forensicnomicon::cadet::ActivityCategory;
