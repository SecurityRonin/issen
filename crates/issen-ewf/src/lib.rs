#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
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
//! E01/EWF forensic image reader.
//!
//! Wraps the [`ewf`] crate to provide a [`DataSource`] implementation for the
//! Issen pipeline, enabling random-access reads over Expert Witness Format
//! forensic disk images.

use std::fs::File;
use std::path::Path;
use std::sync::Arc;

use ewf::SegmentSource;

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
/// Reads go straight through [`ewf::EwfReader::read_at`], a lock-free
/// positioned read on a shared `&self`, so concurrent reads of one image
/// decompress in parallel instead of serializing on a mutex.
pub struct EwfDataSource {
    reader: ewf::EwfReader,
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
        Ok(Self::from_reader(reader))
    }

    /// Open an EWF image whose `.E01`/`.E02`/… segments live INSIDE a `.zip` —
    /// directly, without extracting them to a temp directory first.
    ///
    /// `Stored` zip entries are read **in place** (a positioned sub-range of the
    /// zip file); `Deflated` entries (the common case — E01 is already compressed,
    /// so zipping it gains nothing) are **inflated once into RAM**. Either backing
    /// feeds the lazy chunk table, so the in-memory chunk index stays bounded
    /// regardless of image size.
    ///
    /// # Errors
    /// [`EwfError`] if the zip cannot be read, or holds no `.E01`/`.E02`/… segment.
    pub fn open_zip(zip_path: &Path) -> Result<Self, EwfError> {
        use std::io::Read as _;

        // One handle backs the in-place `Sub` reads; a second drives the zip's
        // own central-directory walk + on-demand inflation.
        let backing = Arc::new(File::open(zip_path)?);
        let mut archive = zip::ZipArchive::new(File::open(zip_path)?)
            .map_err(|e| EwfError::Ewf(format!("zip open: {e}")))?;

        // Collect (name, source) per EWF segment entry; sort by name so the
        // segment order is deterministic (the reader also re-sorts by the EWF
        // segment number embedded in each header).
        let mut segs: Vec<(String, SegmentSource)> = Vec::new();
        for i in 0..archive.len() {
            let mut entry = archive
                .by_index(i)
                .map_err(|e| EwfError::Ewf(format!("zip entry {i}: {e}")))?;
            let name = entry.name().to_string();
            if !is_ewf_segment(&name) {
                continue;
            }
            let src = if entry.compression() == zip::CompressionMethod::Stored {
                // Contiguous, uncompressed -> read straight from the zip at its
                // data offset. Zero extraction, zero inflate, true random access.
                SegmentSource::sub(Arc::clone(&backing), entry.data_start(), entry.size())
            } else {
                // Deflated -> inflate the whole segment once into RAM (sequential,
                // which deflate supports), then random-access it there.
                let mut buf = Vec::with_capacity(usize::try_from(entry.size()).unwrap_or(0));
                entry
                    .read_to_end(&mut buf)
                    .map_err(|e| EwfError::Ewf(format!("inflate {name}: {e}")))?;
                SegmentSource::from_bytes(buf)
            };
            segs.push((name, src));
        }
        if segs.is_empty() {
            return Err(EwfError::Ewf(format!(
                "no EWF segment (.E01/.E02/…) found in {}",
                zip_path.display()
            )));
        }
        segs.sort_by(|a, b| a.0.cmp(&b.0));
        let sources: Vec<SegmentSource> = segs.into_iter().map(|(_, s)| s).collect();
        let reader = ewf::EwfReader::open_lazy_from_sources(sources)?;
        Ok(Self::from_reader(reader))
    }

    /// Wrap an already-opened reader (shared by `open`/`open_zip`).
    fn from_reader(reader: ewf::EwfReader) -> Self {
        let total_size = reader.total_size();
        Self { reader, total_size }
    }

    /// Get the logical size of the forensic image in bytes.
    #[must_use]
    pub fn total_size(&self) -> u64 {
        self.total_size
    }
}

/// True when a zip entry names an EWF v1 segment file — basename ends in `.E`
/// plus two alphanumerics (`.E01`–`.EZZ`). Excludes the `.E01.txt` acquisition
/// sidecars, directory entries, and EWF2 (`.Ex01`, 4-char ext — the lazy
/// reader is v1-only).
fn is_ewf_segment(name: &str) -> bool {
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
    let Some((_, ext)) = base.rsplit_once('.') else {
        return false;
    };
    let b = ext.as_bytes();
    b.len() == 3
        && (b[0] == b'E' || b[0] == b'e')
        && b[1].is_ascii_alphanumeric()
        && b[2].is_ascii_alphanumeric()
}

impl DataSource for EwfDataSource {
    fn len(&self) -> u64 {
        self.total_size
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, RtError> {
        if buf.is_empty() || offset >= self.total_size {
            return Ok(0);
        }

        let available = (self.total_size - offset) as usize;
        let to_read = buf.len().min(available);

        // Lock-free positioned read on a shared `&self`; concurrent callers
        // decompress their own chunks in parallel.
        self.reader
            .read_at(&mut buf[..to_read], offset)
            .map_err(|e| RtError::Parse {
                offset,
                message: format!("EWF read error: {e}"),
            })
    }
}

// ── CollectionProvider ────────────────────────────────────────────────

use issen_unpack::{CollectionManifest, CollectionProvider, Confidence};

/// Format-recognition and manifest provider for EWF/E01 forensic images.
#[derive(Debug, Default)]
pub struct EwfProvider;

impl CollectionProvider for EwfProvider {
    fn name(&self) -> &str {
        "EWF"
    }

    fn probe(&self, path: &Path) -> Result<Confidence, RtError> {
        use std::io::Read;
        // EWF v1 signature: EVF\x09\x0d\x0a\xff\x00
        const EVF_SIG: [u8; 8] = [0x45, 0x56, 0x46, 0x09, 0x0d, 0x0a, 0xff, 0x00];
        let mut f = std::fs::File::open(path).map_err(RtError::Io)?;
        let mut magic = [0u8; 8];
        match f.read_exact(&mut magic) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(Confidence::None),
            Err(e) => return Err(RtError::Io(e)),
        }
        if magic == EVF_SIG {
            Ok(Confidence::High)
        } else {
            Ok(Confidence::None)
        }
    }

    fn open(&self, path: &Path) -> Result<CollectionManifest, RtError> {
        // Decode the E01, then run the NTFS disk-triage extractor (same path as
        // the VMDK provider): pull $MFT, $UsnJrnl:$J, every .evtx, and the
        // registry hives off the volume into a manifest.
        let source = EwfDataSource::open(path)?;
        Ok(issen_disk::triage_manifest(&source, self.name())?)
    }
}

inventory::submit!(issen_unpack::registry::ProviderRegistration {
    create: || Box::new(EwfProvider),
});

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_ewf_segment_matches_e01_family_only() {
        assert!(is_ewf_segment("disk.E01"));
        assert!(is_ewf_segment("E01-DC01/CDrive.E02"));
        assert!(is_ewf_segment("x.EAA"));
        assert!(is_ewf_segment("x.EZZ"));
        assert!(!is_ewf_segment("disk.E01.txt")); // acquisition sidecar
        assert!(!is_ewf_segment("notes.txt"));
        assert!(!is_ewf_segment("E01-DC01/")); // directory entry
        assert!(!is_ewf_segment("disk.Ex01")); // EWF2, 4-char ext (lazy is v1-only)
        assert!(!is_ewf_segment("disk.vmdk"));
    }

    /// Env-gated (fleet real-data pattern): point `ISSEN_EWF_TEST_E01` at a small
    /// single-segment `.E01`; the test zips it BOTH stored and deflated and asserts
    /// `open_zip` == `open(loose)` byte-identical over the whole image — proving the
    /// Sub (in-place) and Mem (inflate) glue. Skips cleanly when unset.
    #[test]
    fn open_zip_matches_open_loose_stored_and_deflated() {
        use std::io::Write as _;
        let Ok(e01) = std::env::var("ISSEN_EWF_TEST_E01") else {
            eprintln!("skip open_zip test: set ISSEN_EWF_TEST_E01 to a .E01 path");
            return;
        };
        let e01 = std::path::PathBuf::from(e01);
        let oracle = EwfDataSource::open(&e01).expect("open loose E01");
        let total = oracle.total_size() as usize;
        let mut want = vec![0u8; total];
        oracle.read_at(0, &mut want).expect("read loose");
        let bytes = std::fs::read(&e01).expect("read E01 bytes");

        for method in [
            zip::CompressionMethod::Stored,
            zip::CompressionMethod::Deflated,
        ] {
            let zip_path = std::env::temp_dir().join(format!("issen_ewf_bridge_{method:?}.zip"));
            {
                let f = File::create(&zip_path).unwrap();
                let mut zw = zip::ZipWriter::new(f);
                let opts = zip::write::SimpleFileOptions::default().compression_method(method);
                zw.start_file("image.E01", opts).unwrap();
                zw.write_all(&bytes).unwrap();
                zw.finish().unwrap();
            }
            let via_zip = EwfDataSource::open_zip(&zip_path).expect("open_zip");
            assert_eq!(
                via_zip.total_size() as usize,
                total,
                "{method:?} total_size"
            );
            let mut got = vec![0u8; total];
            via_zip.read_at(0, &mut got).expect("read via zip");
            assert_eq!(got, want, "{method:?}: bytes via zip differ from loose");
            let _ = std::fs::remove_file(&zip_path);
        }
    }

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
                assert_eq!(offset, 0);
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
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<EwfDataSource>();
    }

    #[test]
    fn test_ewf_error_from_io() {
        // Verify From<std::io::Error> for EwfError works.
        let io_err = std::io::Error::other("test");
        let ewf_err: EwfError = io_err.into();
        assert!(
            matches!(ewf_err, EwfError::Io(_)),
            "Expected EwfError::Io, got: {ewf_err:?}"
        );
    }

    // ── EwfProvider tests ─────────────────────────────────────────────

    #[test]
    fn ewf_provider_name() {
        assert_eq!(EwfProvider.name(), "EWF");
    }

    #[test]
    fn ewf_provider_probe_valid_magic_returns_high() {
        use std::io::Write;
        // EWF v1 magic: EVF\x09\x0d\x0a\xff\x00
        let magic = [0x45u8, 0x56, 0x46, 0x09, 0x0d, 0x0a, 0xff, 0x00];
        let mut f = tempfile::NamedTempFile::new().expect("tmpfile");
        f.write_all(&magic).expect("write");
        // RED: stub returns None — FAILS
        assert_eq!(
            EwfProvider.probe(f.path()).expect("probe"),
            Confidence::High
        );
    }

    #[test]
    fn ewf_provider_probe_wrong_magic_returns_none() {
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::new().expect("tmpfile");
        f.write_all(b"not-ewf-\x00\x00").expect("write");
        assert_eq!(
            EwfProvider.probe(f.path()).expect("probe"),
            Confidence::None
        );
    }

    #[test]
    fn ewf_provider_probe_nonexistent_returns_err() {
        // RED: stub returns Ok(None) — FAILS
        assert!(EwfProvider
            .probe(Path::new("/tmp/nonexistent_99999.E01"))
            .is_err());
    }

    fn zip_named(entry: &str) -> tempfile::NamedTempFile {
        use std::io::Write;
        use zip::write::SimpleFileOptions;
        let mut cursor = std::io::Cursor::new(Vec::<u8>::new());
        {
            let mut zw = zip::ZipWriter::new(&mut cursor);
            zw.start_file(entry, SimpleFileOptions::default()).unwrap();
            zw.write_all(b"content").unwrap();
            zw.finish().unwrap();
        }
        let mut f = tempfile::Builder::new().suffix(".zip").tempfile().unwrap();
        f.write_all(cursor.get_ref()).unwrap();
        f.flush().unwrap();
        f
    }

    #[test]
    fn ewf_provider_probe_zip_wrapping_e01_returns_high() {
        // A zip whose entry is a .E01 segment: claim it for zip-direct ingest
        // (High beats the generic archive provider's Medium) — no extraction.
        let f = zip_named("E01-DC01/20200918_CDrive.E01");
        assert_eq!(
            EwfProvider.probe(f.path()).expect("probe"),
            Confidence::High
        );
    }

    #[test]
    fn ewf_provider_probe_zip_without_e01_returns_none() {
        // No .E01 inside → defer to the archive provider (loose-artifact extract).
        let f = zip_named("notes.txt");
        assert_eq!(
            EwfProvider.probe(f.path()).expect("probe"),
            Confidence::None
        );
    }

    #[test]
    fn ewf_provider_open_invalid_returns_err() {
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::new().expect("tmpfile");
        f.write_all(b"not an ewf file").expect("write");
        assert!(EwfProvider.open(f.path()).is_err());
    }

    #[test]
    fn ewf_provider_open_nonexistent_returns_err() {
        assert!(EwfProvider
            .open(Path::new("/tmp/nonexistent_99999.E01"))
            .is_err());
    }

    #[test]
    fn ewf_provider_registered_in_inventory() {
        use issen_unpack::registry::ProviderRegistration;
        let names: Vec<String> = inventory::iter::<ProviderRegistration>
            .into_iter()
            .map(|r| (r.create)().name().to_string())
            .collect();
        assert!(
            names.contains(&"EWF".to_string()),
            "EwfProvider must be in inventory; got: {names:?}"
        );
    }
}
