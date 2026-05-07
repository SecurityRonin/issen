#![allow(
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::cast_lossless,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss,
    clippy::format_push_string,
    clippy::manual_let_else,
    clippy::map_unwrap_or,
    clippy::needless_borrow,
    clippy::redundant_closure_for_method_calls,
    clippy::too_many_lines,
    clippy::trivially_copy_pass_by_ref,
    clippy::uninlined_format_args,
    clippy::elidable_lifetime_names,
    clippy::match_same_arms,
    clippy::return_self_not_must_use,
    clippy::single_match_else,
    clippy::unnested_or_patterns,
    clippy::field_reassign_with_default,
    clippy::inefficient_to_string,
    clippy::manual_strip,
    clippy::redundant_else,
    clippy::trim_split_whitespace,
    clippy::case_sensitive_file_extension_comparisons,
    clippy::unused_self,
    clippy::assigning_clones,
    clippy::collapsible_if,
    clippy::missing_fields_in_debug,
    clippy::result_unit_err,
    clippy::unreadable_literal,
    clippy::manual_contains,
    clippy::unnecessary_literal_bound
)]
#![allow(
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate
)]
//! E01/EWF forensic image reader.
//!
//! Wraps the [`ewf`] crate to provide a [`DataSource`] implementation for the
//! Issen pipeline, enabling random-access reads over Expert Witness Format
//! forensic disk images.

use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::Mutex;

use issen_core::error::RtError;
use issen_core::plugin::traits::DataSource;

// ── Error type ───────────────────────────────────────────────────────

/// Errors specific to EWF image operations.
#[derive(Debug, thiserror::Error)]
pub enum EwfError {
    /// An I/O error occurred while reading the EWF image.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// An error from the underlying EWF parser.
    #[error("EWF error: {0}")]
    Ewf(String),
}

impl From<ewf::EwfError> for EwfError {
    fn from(e: ewf::EwfError) -> Self {
        // ewf::EwfError has an Io variant; everything else we format as a string.
        match e {
            ewf::EwfError::Io(io) => Self::Io(io),
            other => Self::Ewf(other.to_string()),
        }
    }
}

impl From<EwfError> for RtError {
    fn from(e: EwfError) -> Self {
        match e {
            EwfError::Io(io) => Self::Io(io),
            EwfError::Ewf(msg) => Self::Parse {
                offset: 0,
                message: msg,
            },
        }
    }
}

// ── Data source ──────────────────────────────────────────────────────

/// A [`DataSource`] backed by an EWF/E01 forensic disk image.
///
/// Thread-safe random-access reads are achieved by wrapping the inner
/// [`ewf::EwfReader`] in a [`Mutex`]. Each `read_at` call locks, seeks,
/// reads, and unlocks.
pub struct EwfDataSource {
    reader: Mutex<ewf::EwfReader>,
    total_size: u64,
}

impl std::fmt::Debug for EwfDataSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EwfDataSource")
            .field("total_size", &self.total_size)
            .finish_non_exhaustive()
    }
}

impl EwfDataSource {
    /// Open an EWF/E01 forensic image.
    ///
    /// Multi-segment images (`.E01`, `.E02`, ...) are discovered automatically.
    ///
    /// # Errors
    ///
    /// Returns [`EwfError`] if the file cannot be opened or is not a valid EWF
    /// image.
    pub fn open(path: &Path) -> Result<Self, EwfError> {
        let reader = ewf::EwfReader::open(path)?;
        let total_size = reader.total_size();
        Ok(Self {
            reader: Mutex::new(reader),
            total_size,
        })
    }

    /// Get the logical size of the forensic image in bytes.
    #[must_use]
    pub fn total_size(&self) -> u64 {
        self.total_size
    }
}

impl DataSource for EwfDataSource {
    fn len(&self) -> u64 {
        self.total_size
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, RtError> {
        if buf.is_empty() || offset >= self.total_size {
            return Ok(0);
        }

        let mut reader = self.reader.lock().map_err(|e| RtError::Parse {
            offset,
            message: format!("EWF mutex poisoned: {e}"),
        })?;

        reader
            .seek(SeekFrom::Start(offset))
            .map_err(|e| RtError::Parse {
                offset,
                message: format!("EWF seek error: {e}"),
            })?;

        let available = (self.total_size - offset) as usize;
        let to_read = buf.len().min(available);

        reader
            .read(&mut buf[..to_read])
            .map_err(|e| RtError::Parse {
                offset,
                message: format!("EWF read error: {e}"),
            })
    }
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ewf_error_display_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file gone");
        let ewf_err = EwfError::Io(io_err);
        let display = format!("{ewf_err}");
        assert!(
            display.contains("I/O error"),
            "Expected 'I/O error' in: {display}"
        );
        assert!(
            display.contains("file gone"),
            "Expected 'file gone' in: {display}"
        );
    }

    #[test]
    fn test_ewf_error_display_ewf() {
        let ewf_err = EwfError::Ewf("bad signature".to_string());
        let display = format!("{ewf_err}");
        assert!(
            display.contains("EWF error"),
            "Expected 'EWF error' in: {display}"
        );
        assert!(
            display.contains("bad signature"),
            "Expected 'bad signature' in: {display}"
        );
    }

    #[test]
    fn test_ewf_error_to_issen_error_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
        let ewf_err = EwfError::Io(io_err);
        let issen_err: RtError = ewf_err.into();
        assert!(
            matches!(issen_err, RtError::Io(_)),
            "Expected RtError::Io, got: {issen_err:?}"
        );
    }

    #[test]
    fn test_ewf_error_to_issen_error_ewf() {
        let ewf_err = EwfError::Ewf("corrupt chunk".to_string());
        let issen_err: RtError = ewf_err.into();
        match issen_err {
            RtError::Parse { offset, message } => {
                asseissen_eq!(offset, 0);
                assert!(
                    message.contains("corrupt chunk"),
                    "Expected 'corrupt chunk' in: {message}"
                );
            }
            other => panic!("Expected RtError::Parse, got: {other:?}"),
        }
    }

    #[test]
    fn test_open_nonexistent_file() {
        let result = EwfDataSource::open(Path::new("/tmp/nonexistent_image_12345.E01"));
        assert!(result.is_err(), "Expected error for nonexistent file");
        let err = result.expect_err("should be an error");
        let display = format!("{err}");
        // Should be either an I/O error or an EWF error about missing file
        assert!(
            display.contains("error") || display.contains("Error"),
            "Expected error message, got: {display}"
        );
    }

    #[test]
    fn test_module_compiles() {
        // Verify that EwfDataSource satisfies Send + Sync (required by DataSource).
        fn asseissen_send_sync<T: Send + Sync>() {}
        asseissen_send_sync::<EwfDataSource>();
    }

    #[test]
    fn test_ewf_error_from_io() {
        // Verify From<std::io::Error> for EwfError works.
        let io_err = std::io::Error::new(std::io::ErrorKind::Other, "test");
        let ewf_err: EwfError = io_err.into();
        assert!(
            matches!(ewf_err, EwfError::Io(_)),
            "Expected EwfError::Io, got: {ewf_err:?}"
        );
    }
}
