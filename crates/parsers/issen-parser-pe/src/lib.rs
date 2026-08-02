//! PE (Portable Executable) parser and forensic detector for Issen.
//!
//! Accepts raw `&[u8]` bytes. Medium-agnostic: works equally from a disk file,
//! an extracted memory region, or a carved AFF4 stream.

#![allow(
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::trivially_copy_pass_by_ref,
    clippy::unnecessary_literal_bound
)]
// Tests opt out of the panic lints (fleet standard) — unwrap/expect in test code.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
pub mod detections;
pub mod parser;
pub mod wiring;

pub use detections::{detect_all, PeDetection, PeDetectionKind};
pub use parser::{parse_pe, PeError, PeInfo, PeSection};
pub use wiring::{pe_events_from_info, pe_findings, PeParser};
