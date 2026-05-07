//! Built-in parser implementations (MFT and USN Journal).
//!
//! These register themselves via `inventory::submit!` at link time,
//! replacing the removed `rt-parser-mft` and `rt-parser-usnjrnl` crates.

pub mod mft;
pub mod usnjrnl;
