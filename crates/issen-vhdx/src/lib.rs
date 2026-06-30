//! VHDX container reader for the Issen forensic pipeline.
//!
//! Wraps the [`vhdx`] crate to provide a [`DataSource`] implementation for the
//! Issen pipeline, enabling random-access reads over Microsoft VHDX virtual
//! disk images.

use std::fs::File;
use std::io::{Seek, SeekFrom};
use std::path::Path;
use std::sync::{Arc, Mutex};

use vhdx::Backing;

use issen_core::error::RtError;
use issen_core::plugin::traits::DataSource;

// ── Error type ───────────────────────────────────────────────────────

/// Errors specific to VHDX image operations.
#[derive(Debug, thiserror::Error)]
pub enum VhdxError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("VHDX parse error: {0}")]
    Vhdx(String),
}

impl From<vhdx::VhdxError> for VhdxError {
    fn from(e: vhdx::VhdxError) -> Self {
        match e {
            vhdx::VhdxError::Io(io) => Self::Io(io),
            other => Self::Vhdx(other.to_string()),
        }
    }
}

impl From<VhdxError> for RtError {
    fn from(e: VhdxError) -> Self {
        match e {
            VhdxError::Io(io) => Self::Io(io),
            VhdxError::Vhdx(msg) => Self::Parse {
                offset: 0,
                message: format!("vhdx: {msg}"),
            },
        }
    }
}

// ── DataSource implementation ────────────────────────────────────────

/// A [`DataSource`] backed by a VHDX virtual disk image.
///
/// Opens the image at construction time (reads the full file into memory) and
/// wraps the [`vhdx::VhdxReader`] in a [`Mutex`]. Each `read_at` call locks,
/// seeks, and reads the requested bytes.
pub struct VhdxDataSource {
    reader: Mutex<vhdx::VhdxReader>,
    size: u64,
}

impl std::fmt::Debug for VhdxDataSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VhdxDataSource")
            .field("size", &self.size)
            .finish_non_exhaustive()
    }
}

impl VhdxDataSource {
    /// Open a VHDX virtual disk image.
    ///
    /// Returns [`VhdxError`] if the file cannot be opened or is not a valid
    /// VHDX image. Differencing (parent-linked) disks are not supported.
    pub fn open(path: &Path) -> Result<Self, VhdxError> {
        let reader = vhdx::VhdxReader::open(path)?;
        Ok(Self::from_reader(reader))
    }

    /// Open a VHDX image that lives INSIDE a `.zip` — directly, without
    /// extracting it to a temp directory first.
    ///
    /// A `Stored` (uncompressed) entry is read **in place** as a positioned
    /// sub-range of the zip file ([`Backing::Sub`]); a `Deflated` entry is
    /// **inflated once into RAM** ([`Backing::Mem`]). Either backing feeds the
    /// bounded reader, so a stored entry never loads the whole image and an
    /// inflated entry pays the inflate exactly once.
    ///
    /// # Errors
    /// [`VhdxError`] if the zip cannot be read, holds no `.vhdx` entry, or the
    /// entry is not a valid VHDX image.
    pub fn open_zip(zip_path: &Path) -> Result<Self, VhdxError> {
        use std::io::Read as _;

        // One handle backs the in-place `Sub` reads; a second drives the zip's
        // central-directory walk + on-demand inflation.
        let backing_file = Arc::new(File::open(zip_path)?);
        let mut archive = zip_core::ZipArchive::new(File::open(zip_path)?)
            .map_err(|e| VhdxError::Vhdx(format!("zip open: {e}")))?;

        let mut chosen: Option<Backing> = None;
        for i in 0..archive.len() {
            let mut entry = archive
                .by_index(i)
                .map_err(|e| VhdxError::Vhdx(format!("zip entry {i}: {e}")))?;
            if !is_vhdx_entry(entry.name()) {
                continue;
            }
            let backing = if entry.compression() == zip_core::CompressionMethod::Stored {
                // Contiguous, uncompressed → read straight from the zip at its
                // data offset. Zero extraction, zero inflate, bounded reads.
                Backing::sub(Arc::clone(&backing_file), entry.data_start(), entry.size())
            } else {
                // Deflated → inflate the whole entry once into RAM (deflate is
                // sequential), then read it via Backing::Mem.
                let mut buf = Vec::with_capacity(usize::try_from(entry.size()).unwrap_or(0));
                entry
                    .read_to_end(&mut buf)
                    .map_err(|e| VhdxError::Vhdx(format!("inflate {}: {e}", entry.name())))?;
                Backing::from_bytes(buf)
            };
            chosen = Some(backing);
            break;
        }

        let backing = chosen.ok_or_else(|| {
            VhdxError::Vhdx(format!("no .vhdx entry found in {}", zip_path.display()))
        })?;
        let reader = vhdx::VhdxReader::from_backing(backing, None)?;
        Ok(Self::from_reader(reader))
    }

    /// Wrap an already-opened reader (shared by `open`/`open_zip`).
    fn from_reader(reader: vhdx::VhdxReader) -> Self {
        let size = reader.virtual_disk_size();
        Self {
            reader: Mutex::new(reader),
            size,
        }
    }
}

/// True when a zip entry names a VHDX container — a basename ending in `.vhdx`
/// (case-insensitive). Excludes directory entries and other artifacts.
fn is_vhdx_entry(name: &str) -> bool {
    if name.ends_with('/') {
        return false;
    }
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
    base.len() > 5
        && base
            .rsplit('.')
            .next()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("vhdx"))
}

impl DataSource for VhdxDataSource {
    fn len(&self) -> u64 {
        self.size
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, RtError> {
        let mut guard = self.reader.lock().expect("VhdxDataSource mutex poisoned");
        guard.seek(SeekFrom::Start(offset)).map_err(RtError::Io)?;
        let mut total = 0;
        while total < buf.len() {
            match std::io::Read::read(&mut *guard, &mut buf[total..]) {
                Ok(0) => break,
                Ok(n) => total += n,
                Err(e) => return Err(RtError::Io(e)),
            }
        }
        Ok(total)
    }
}

// ── CollectionProvider ────────────────────────────────────────────────

use issen_unpack::{CollectionManifest, CollectionProvider, Confidence};

/// Format-recognition and manifest provider for VHDX disk images.
#[derive(Debug, Default)]
pub struct VhdxProvider;

impl CollectionProvider for VhdxProvider {
    fn name(&self) -> &'static str {
        "VHDX"
    }

    fn probe(&self, path: &Path) -> Result<Confidence, RtError> {
        use std::io::Read;
        let mut f = std::fs::File::open(path).map_err(RtError::Io)?;
        let mut magic = [0u8; 8];
        match f.read_exact(&mut magic) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(Confidence::None),
            Err(e) => return Err(RtError::Io(e)),
        }
        if &magic == b"vhdxfile" {
            Ok(Confidence::High)
        } else {
            Ok(Confidence::None)
        }
    }

    fn open(&self, path: &Path) -> Result<CollectionManifest, RtError> {
        // The container opens (format decodes), but no triage extractor is
        // wired for it yet. Returning an empty manifest would emit a silent,
        // clean-looking timeline (indistinguishable from a genuinely clean
        // image) — fail loud instead of fabricating "no findings".
        VhdxDataSource::open(path)?;
        Err(RtError::UnsupportedFormat(format!(
            "{}: image opens, but artifact extraction is not yet wired for \
             this container (refusing to emit a silent empty timeline)",
            self.name()
        )))
    }
}

inventory::submit!(issen_unpack::registry::ProviderRegistration {
    create: || Box::new(VhdxProvider),
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_nonexistent_path_returns_err() {
        let result = VhdxDataSource::open(Path::new("/tmp/nonexistent_image_99999.vhdx"));
        assert!(result.is_err(), "opening a nonexistent path must fail");
    }

    #[test]
    fn open_non_vhdx_file_returns_err() {
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::new().expect("tmpfile");
        f.write_all(b"this is not a vhdx file").expect("write");
        let result = VhdxDataSource::open(f.path());
        assert!(result.is_err(), "opening a non-VHDX file must fail");
    }

    #[test]
    fn vhdx_data_source_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<VhdxDataSource>();
    }

    #[test]
    fn vhdx_error_io_displays_message() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let err = VhdxError::Io(io_err);
        let display = format!("{err}");
        assert!(display.contains("file not found"));
    }

    #[test]
    fn vhdx_error_parse_displays_message() {
        let err = VhdxError::Vhdx("bad magic".to_string());
        let display = format!("{err}");
        assert!(display.contains("bad magic"));
    }

    #[test]
    fn from_vhdx_error_io_converts_to_issen_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
        let vhdx_err = VhdxError::Io(io_err);
        let rt_err: RtError = vhdx_err.into();
        assert!(matches!(rt_err, RtError::Io(_)));
    }

    #[test]
    fn from_vhdx_error_parse_converts_to_rt_parse_error() {
        let vhdx_err = VhdxError::Vhdx("corrupt region table".to_string());
        let rt_err: RtError = vhdx_err.into();
        assert!(matches!(rt_err, RtError::Parse { ref message, .. } if message.contains("vhdx")));
    }

    // ── VhdxProvider tests ────────────────────────────────────────────

    #[test]
    fn vhdx_provider_name() {
        assert_eq!(VhdxProvider.name(), "VHDX");
    }

    #[test]
    fn vhdx_provider_probe_valid_magic_returns_high() {
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::new().expect("tmpfile");
        f.write_all(b"vhdxfile\x00\x00\x00\x00").expect("write");
        // RED: stub returns None — this test FAILS
        assert_eq!(
            VhdxProvider.probe(f.path()).expect("probe"),
            Confidence::High
        );
    }

    #[test]
    fn vhdx_provider_probe_wrong_magic_returns_none() {
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::new().expect("tmpfile");
        f.write_all(b"not-vhdx\x00\x00\x00\x00").expect("write");
        assert_eq!(
            VhdxProvider.probe(f.path()).expect("probe"),
            Confidence::None
        );
    }

    #[test]
    fn vhdx_provider_probe_nonexistent_returns_err() {
        // RED: stub returns Ok(None) — this test FAILS
        assert!(VhdxProvider
            .probe(Path::new("/tmp/nonexistent_99999.vhdx"))
            .is_err());
    }

    #[test]
    fn vhdx_provider_open_invalid_returns_err() {
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::new().expect("tmpfile");
        f.write_all(b"not a vhdx file").expect("write");
        assert!(VhdxProvider.open(f.path()).is_err());
    }

    #[test]
    fn vhdx_provider_open_nonexistent_returns_err() {
        assert!(VhdxProvider
            .open(Path::new("/tmp/nonexistent_99999.vhdx"))
            .is_err());
    }

    #[test]
    fn vhdx_provider_registered_in_inventory() {
        use issen_unpack::registry::ProviderRegistration;
        let names: Vec<String> = inventory::iter::<ProviderRegistration>
            .into_iter()
            .map(|r| (r.create)().name().to_string())
            .collect();
        assert!(
            names.contains(&"VHDX".to_string()),
            "VhdxProvider must be in inventory; got: {names:?}"
        );
    }

    // ── open_zip tests ────────────────────────────────────────────────────

    #[test]
    fn is_vhdx_entry_recognizes_only_vhdx_basenames() {
        assert!(is_vhdx_entry("disk.vhdx"));
        assert!(is_vhdx_entry("case/DC01.VHDX")); // case-insensitive ext
        assert!(is_vhdx_entry("nested/dir/image.vhdx"));
        assert!(!is_vhdx_entry("disk.vhd")); // VHD, not VHDX
        assert!(!is_vhdx_entry("disk.vhdx.txt")); // sidecar
        assert!(!is_vhdx_entry("notes.txt"));
        assert!(!is_vhdx_entry("case/")); // directory entry
        assert!(!is_vhdx_entry(".vhdx")); // no stem
    }

    /// `open_zip` over a zip with no `.vhdx` entry must fail loud (never a
    /// silent empty source).
    #[test]
    fn open_zip_without_vhdx_entry_returns_err() {
        use std::io::Write as _;
        let zip_path = std::env::temp_dir().join("issen_vhdx_no_entry.zip");
        {
            let f = std::fs::File::create(&zip_path).expect("create zip");
            let mut zw = zip::ZipWriter::new(f);
            zw.start_file("notes.txt", zip::write::SimpleFileOptions::default())
                .expect("start");
            zw.write_all(b"nothing here").expect("write");
            zw.finish().expect("finish");
        }
        let res = VhdxDataSource::open_zip(&zip_path);
        let _ = std::fs::remove_file(&zip_path);
        assert!(res.is_err(), "zip without a .vhdx entry must fail");
    }

    /// Zip a real loose `.vhdx` BOTH stored and deflated and assert that
    /// `open_zip` reads byte-identical to `open(loose)` over the whole virtual
    /// disk — proving the `Sub` (in-place) and `Mem` (inflate) backings.
    ///
    /// Env-gated (fleet real-data pattern): point `ISSEN_VHDX_TEST` at a small
    /// `.vhdx`. Skips cleanly when unset.
    #[test]
    fn open_zip_matches_open_loose_stored_and_deflated() {
        use std::io::Write as _;

        let Ok(vhdx_path) = std::env::var("ISSEN_VHDX_TEST") else {
            eprintln!("skip open_zip test: set ISSEN_VHDX_TEST to a .vhdx path");
            return;
        };
        let vhdx_path = std::path::PathBuf::from(vhdx_path);

        let oracle = VhdxDataSource::open(&vhdx_path).expect("open loose vhdx");
        let total = oracle.len() as usize;
        let mut want = vec![0u8; total];
        oracle.read_at(0, &mut want).expect("read loose full");

        let bytes = std::fs::read(&vhdx_path).expect("read vhdx bytes");
        for method in [
            zip::CompressionMethod::Stored,
            zip::CompressionMethod::Deflated,
        ] {
            let zip_path = std::env::temp_dir().join(format!("issen_vhdx_bridge_{method:?}.zip"));
            {
                let f = std::fs::File::create(&zip_path).expect("create zip");
                let mut zw = zip::ZipWriter::new(f);
                let opts = zip::write::SimpleFileOptions::default().compression_method(method);
                zw.start_file("image.vhdx", opts).expect("start_file");
                zw.write_all(&bytes).expect("write entry");
                zw.finish().expect("finish");
            }
            let via_zip = VhdxDataSource::open_zip(&zip_path).expect("open_zip");
            assert_eq!(via_zip.len() as usize, total, "{method:?} len");
            let mut got = vec![0u8; total];
            via_zip.read_at(0, &mut got).expect("read via zip");
            let _ = std::fs::remove_file(&zip_path);
            assert!(want == got, "{method:?}: open_zip must match open(loose)");
        }
    }
}
