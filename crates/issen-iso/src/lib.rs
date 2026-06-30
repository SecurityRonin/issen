#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
//! ISO 9660 optical disc image reader for the Issen forensic pipeline.
//!
//! Uses [`iso9660_forensic`] for format validation and exposes the raw sector
//! stream as a [`DataSource`] for downstream forensic parsers.

use std::fs::File;
use std::io::{Cursor, Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::{Arc, Mutex};

use issen_core::error::RtError;
use issen_core::plugin::traits::DataSource;

/// A seekable, thread-safe byte source the raw reader can sit on: a `File`, an
/// in-RAM `Cursor`, or a positioned sub-range of a `.zip`.
pub trait ReadSeekSend: Read + Seek + Send + Sync {}
impl<T: Read + Seek + Send + Sync> ReadSeekSend for T {}

/// Errors specific to ISO image operations.
#[derive(Debug, thiserror::Error)]
pub enum IsoError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("not a valid ISO 9660 image: {0}")]
    InvalidIso(String),
}

impl From<IsoError> for RtError {
    fn from(e: IsoError) -> Self {
        match e {
            IsoError::Io(io) => Self::Io(io),
            IsoError::InvalidIso(msg) => Self::Parse {
                offset: 0,
                message: format!("iso: {msg}"),
            },
        }
    }
}

/// A [`DataSource`] backed by an ISO 9660 optical disc image.
pub struct IsoDataSource {
    reader: Mutex<Box<dyn ReadSeekSend>>,
    size: u64,
}

impl std::fmt::Debug for IsoDataSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IsoDataSource")
            .field("size", &self.size)
            .finish_non_exhaustive()
    }
}

impl IsoDataSource {
    /// Open an ISO 9660 image, validating the format with our `iso9660-forensic` reader.
    ///
    /// Opens the file twice: once for `iso9660-forensic` validation, once to keep
    /// as a raw sector stream for [`DataSource::read_at`].
    pub fn open(path: &Path) -> Result<Self, IsoError> {
        // Validate the ISO 9660 structure with our own iso9660-forensic reader.
        let validate_file = File::open(path)?;
        iso9660_forensic::IsoReader::open(validate_file)
            .map_err(|e| IsoError::InvalidIso(e.to_string()))?;

        // Raw read handle for DataSource I/O.
        let raw = File::open(path)?;
        let size = raw.metadata()?.len();
        Ok(Self {
            reader: Mutex::new(Box::new(raw)),
            size,
        })
    }

    /// Open an ISO 9660 image that lives INSIDE a `.zip` — directly, without
    /// extracting it to a temp directory first. A `Stored` entry is read in
    /// place (a positioned sub-range of the zip); a `Deflated` entry is inflated
    /// once into RAM. The image is validated with `iso9660-forensic`, then the
    /// same backing serves [`DataSource::read_at`].
    ///
    /// # Errors
    /// [`IsoError`] if the zip cannot be read, holds no `.iso` entry, or the
    /// entry is not a valid ISO 9660 image.
    pub fn open_zip(zip_path: &Path) -> Result<Self, IsoError> {
        let backing = Arc::new(File::open(zip_path)?);
        let mut archive = zip_core::ZipArchive::new(File::open(zip_path)?)
            .map_err(|e| IsoError::InvalidIso(format!("zip open: {e}")))?;

        let idx = find_iso_entry(&mut archive).ok_or_else(|| {
            IsoError::InvalidIso(format!("no .iso entry found in {}", zip_path.display()))
        })?;
        let mut entry = archive
            .by_index(idx)
            .map_err(|e| IsoError::InvalidIso(format!("zip entry {idx}: {e}")))?;

        let stored = entry.compression() == zip_core::CompressionMethod::Stored;
        let data_start = entry.data_start();
        let entry_size = entry.size();

        let (reader, size): (Box<dyn ReadSeekSend>, u64) = if stored {
            // Validate on one positioned window, keep a second for read_at — both
            // read the zip in place (no extraction).
            let validate = SubRangeReader::new(Arc::clone(&backing), data_start, entry_size);
            iso9660_forensic::IsoReader::open(validate)
                .map_err(|e| IsoError::InvalidIso(e.to_string()))?;
            let reader = SubRangeReader::new(Arc::clone(&backing), data_start, entry_size);
            (Box::new(reader), entry_size)
        } else {
            let mut buf = Vec::with_capacity(usize::try_from(entry_size).unwrap_or(0));
            entry.read_to_end(&mut buf).map_err(IsoError::Io)?;
            let size = buf.len() as u64;
            // Validate against a borrowed view, then move the bytes into the
            // read-at Cursor (no second copy of the image).
            iso9660_forensic::IsoReader::open(Cursor::new(buf.as_slice()))
                .map_err(|e| IsoError::InvalidIso(e.to_string()))?;
            (Box::new(Cursor::new(buf)), size)
        };

        Ok(Self {
            reader: Mutex::new(reader),
            size,
        })
    }
}

/// Find the first `.iso` file entry in the archive, by extension.
fn find_iso_entry(archive: &mut zip_core::ZipArchive<File>) -> Option<usize> {
    for i in 0..archive.len() {
        let Ok(entry) = archive.by_index(i) else {
            continue;
        };
        if entry.is_dir() {
            continue;
        }
        let is_iso = Path::new(entry.name())
            .extension()
            .and_then(|x| x.to_str())
            .is_some_and(|x| x.eq_ignore_ascii_case("iso"));
        if is_iso {
            return Some(i);
        }
    }
    None
}

/// A positioned, read-only window `[base, base + len)` over a shared file — lets
/// the ISO reader sit directly on a `Stored` zip entry without extraction. Uses
/// positioned reads (no `&mut` on the file), so it is `Send + Sync`.
struct SubRangeReader {
    file: Arc<File>,
    base: u64,
    len: u64,
    pos: u64,
}

impl SubRangeReader {
    fn new(file: Arc<File>, base: u64, len: u64) -> Self {
        Self {
            file,
            base,
            len,
            pos: 0,
        }
    }
}

impl Read for SubRangeReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let remaining = self.len.saturating_sub(self.pos);
        if remaining == 0 || buf.is_empty() {
            return Ok(0);
        }
        let to_read = (buf.len() as u64).min(remaining) as usize;
        #[cfg(unix)]
        let n = {
            use std::os::unix::fs::FileExt;
            self.file
                .read_at(&mut buf[..to_read], self.base + self.pos)?
        };
        #[cfg(windows)]
        let n = {
            use std::os::windows::fs::FileExt;
            self.file
                .seek_read(&mut buf[..to_read], self.base + self.pos)?
        };
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for SubRangeReader {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        let new_pos = match pos {
            SeekFrom::Start(n) => n as i64,
            SeekFrom::Current(n) => self.pos as i64 + n,
            SeekFrom::End(n) => self.len as i64 + n,
        };
        if new_pos < 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "seek before start",
            ));
        }
        self.pos = new_pos as u64;
        Ok(self.pos)
    }
}

impl DataSource for IsoDataSource {
    fn len(&self) -> u64 {
        self.size
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, RtError> {
        let mut guard = self.reader.lock().expect("mutex poisoned");
        guard.seek(SeekFrom::Start(offset)).map_err(RtError::Io)?;
        let mut total = 0;
        while total < buf.len() {
            match guard.read(&mut buf[total..]).map_err(RtError::Io)? {
                0 => break,
                n => total += n,
            }
        }
        Ok(total)
    }
}

// ── CollectionProvider ────────────────────────────────────────────────

use issen_unpack::{CollectionManifest, CollectionProvider, Confidence};

/// Format-recognition and manifest provider for ISO 9660 disc images.
#[derive(Debug, Default)]
pub struct IsoProvider;

impl CollectionProvider for IsoProvider {
    #[allow(clippy::unnecessary_literal_bound)] // trait fixes the `-> &str` signature
    fn name(&self) -> &str {
        "ISO"
    }

    fn probe(&self, path: &Path) -> Result<Confidence, RtError> {
        use std::io::{Read, Seek, SeekFrom};
        // ISO 9660 Primary Volume Descriptor starts at sector 16 (byte 0x8000).
        // Byte 1 of the PVD is the standard identifier "CD001" (5 bytes at 0x8001).
        let mut f = std::fs::File::open(path).map_err(RtError::Io)?;
        if f.seek(SeekFrom::Start(0x8001)).map_err(RtError::Io)? < 0x8001 {
            return Ok(Confidence::None);
        }
        let mut id = [0u8; 5];
        match f.read_exact(&mut id) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(Confidence::None),
            Err(e) => return Err(RtError::Io(e)),
        }
        if &id == b"CD001" {
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
        IsoDataSource::open(path)?;
        Err(RtError::UnsupportedFormat(format!(
            "{}: image opens, but artifact extraction is not yet wired for \
             this container (refusing to emit a silent empty timeline)",
            self.name()
        )))
    }
}

inventory::submit!(issen_unpack::registry::ProviderRegistration {
    create: || Box::new(IsoProvider),
});

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    const SECTOR: usize = 2048;

    /// Minimal ISO 9660 image: system area + PVD + terminator + one data sector.
    fn make_iso(sector18_data: &[u8]) -> Vec<u8> {
        let mut iso = vec![0u8; 19 * SECTOR];
        let pvd = 16 * SECTOR;
        iso[pvd] = 1;
        iso[pvd + 1..pvd + 6].copy_from_slice(b"CD001");
        iso[pvd + 6] = 1;
        let vdt = 17 * SECTOR;
        iso[vdt] = 0xFF;
        iso[vdt + 1..vdt + 6].copy_from_slice(b"CD001");
        iso[vdt + 6] = 1;
        let n = sector18_data.len().min(SECTOR);
        iso[18 * SECTOR..18 * SECTOR + n].copy_from_slice(&sector18_data[..n]);
        iso
    }

    fn write_tmp(data: &[u8]) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(data).unwrap();
        f
    }

    #[test]
    fn open_nonexistent_returns_err() {
        assert!(IsoDataSource::open(Path::new("/tmp/nope.iso")).is_err());
    }

    #[test]
    fn open_non_iso_file_returns_err() {
        let f = write_tmp(&vec![0u8; 40_000]);
        assert!(IsoDataSource::open(f.path()).is_err());
    }

    #[test]
    fn len_matches_file_size() {
        let img = make_iso(&[0u8; 512]);
        let f = write_tmp(&img);
        let src = IsoDataSource::open(f.path()).expect("open");
        assert_eq!(src.len(), img.len() as u64);
    }

    #[test]
    fn read_at_returns_correct_bytes() {
        let mut data = vec![0u8; SECTOR];
        data[10] = 0xCA;
        data[11] = 0xFE;
        let img = make_iso(&data);
        let f = write_tmp(&img);
        let src = IsoDataSource::open(f.path()).expect("open");
        let mut buf = [0u8; 2];
        src.read_at((18 * SECTOR + 10) as u64, &mut buf)
            .expect("read_at");
        assert_eq!(buf, [0xCA, 0xFE]);
    }

    #[test]
    fn iso_data_source_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<IsoDataSource>();
    }

    /// Write `data` into a single-entry zip with the given compression method.
    fn make_zip(
        name: &str,
        data: &[u8],
        method: zip::CompressionMethod,
    ) -> tempfile::NamedTempFile {
        use zip::write::SimpleFileOptions;
        let mut cursor = std::io::Cursor::new(Vec::<u8>::new());
        {
            let mut zw = zip::ZipWriter::new(&mut cursor);
            let opts = SimpleFileOptions::default().compression_method(method);
            zw.start_file(name, opts).expect("start_file");
            zw.write_all(data).expect("write entry");
            zw.finish().expect("finish zip");
        }
        let mut f = tempfile::Builder::new()
            .suffix(".zip")
            .tempfile()
            .expect("tempfile");
        f.write_all(cursor.get_ref()).expect("write zip");
        f.flush().expect("flush");
        f
    }

    /// The oracle: open_zip over a zipped ISO (BOTH Stored and Deflated) reads
    /// byte-identically to opening the loose `.iso` directly.
    #[test]
    fn open_zip_matches_open_loose_stored_and_deflated() {
        let mut data = vec![0u8; SECTOR];
        data[10] = 0xCA;
        data[11] = 0xFE;
        let img = make_iso(&data);

        let loose = write_tmp(&img);
        let oracle = IsoDataSource::open(loose.path()).expect("open loose");
        let size = oracle.len();
        let mut want = vec![0u8; size as usize];
        oracle.read_at(0, &mut want).expect("read loose");

        for method in [
            zip::CompressionMethod::Stored,
            zip::CompressionMethod::Deflated,
        ] {
            let zip = make_zip("disc.iso", &img, method);
            let via_zip = IsoDataSource::open_zip(zip.path()).expect("open_zip");
            assert_eq!(via_zip.len(), size, "size mismatch for {method:?}");
            let mut got = vec![0u8; size as usize];
            via_zip.read_at(0, &mut got).expect("read via zip");
            assert_eq!(got, want, "byte mismatch for {method:?}");
        }
    }

    #[test]
    fn iso_error_converts_to_rt_error() {
        let e = IsoError::InvalidIso("bad signature".into());
        assert!(matches!(RtError::from(e), RtError::Parse { .. }));
    }

    // ── IsoProvider tests ─────────────────────────────────────────────

    #[test]
    fn iso_provider_name() {
        assert_eq!(IsoProvider.name(), "ISO");
    }

    #[test]
    fn iso_provider_probe_valid_iso_returns_high() {
        let img = make_iso(&[0u8; SECTOR]);
        let f = write_tmp(&img);
        // RED: stub returns None — FAILS
        assert_eq!(
            IsoProvider.probe(f.path()).expect("probe"),
            Confidence::High
        );
    }

    #[test]
    fn iso_provider_probe_wrong_bytes_returns_none() {
        let f = write_tmp(&vec![0u8; 40_000]);
        assert_eq!(
            IsoProvider.probe(f.path()).expect("probe"),
            Confidence::None
        );
    }

    #[test]
    fn iso_provider_probe_nonexistent_returns_err() {
        // RED: stub returns Ok(None) — FAILS
        assert!(IsoProvider
            .probe(Path::new("/tmp/nonexistent_99999.iso"))
            .is_err());
    }

    #[test]
    fn iso_provider_open_invalid_returns_err() {
        let f = write_tmp(&vec![0u8; 40_000]);
        assert!(IsoProvider.open(f.path()).is_err());
    }

    #[test]
    fn iso_provider_open_nonexistent_returns_err() {
        assert!(IsoProvider
            .open(Path::new("/tmp/nonexistent_99999.iso"))
            .is_err());
    }

    #[test]
    fn iso_provider_registered_in_inventory() {
        use issen_unpack::registry::ProviderRegistration;
        let names: Vec<String> = inventory::iter::<ProviderRegistration>
            .into_iter()
            .map(|r| (r.create)().name().to_string())
            .collect();
        assert!(
            names.contains(&"ISO".to_string()),
            "IsoProvider must be in inventory; got: {names:?}"
        );
    }
}
