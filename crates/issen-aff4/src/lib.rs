//! AFF4 disk image reader for the Issen forensic pipeline.
//!
//! Wraps [`aff4::Aff4Reader`] and exposes the virtual disk as a [`DataSource`]
//! for downstream forensic parsers.

// Tests opt out of the panic lints (fleet standard) — unwrap/expect in test code.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::Mutex;

use issen_core::error::RtError;
use issen_core::plugin::traits::DataSource;

/// Errors specific to AFF4 image operations.
#[derive(Debug, thiserror::Error)]
pub enum Aff4Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("AFF4 error: {0}")]
    Aff4(String),
}

impl From<aff4::Aff4Error> for Aff4Error {
    fn from(e: aff4::Aff4Error) -> Self {
        match e {
            aff4::Aff4Error::Io(io) => Self::Io(io),
            other => Self::Aff4(other.to_string()),
        }
    }
}

impl From<Aff4Error> for RtError {
    fn from(e: Aff4Error) -> Self {
        match e {
            Aff4Error::Io(io) => Self::Io(io),
            Aff4Error::Aff4(msg) => Self::Parse {
                offset: 0,
                message: format!("aff4: {msg}"),
            },
        }
    }
}

/// A [`DataSource`] backed by an AFF4 disk image.
pub struct Aff4DataSource {
    reader: Mutex<aff4::Aff4Reader>,
    size: u64,
}

impl std::fmt::Debug for Aff4DataSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Aff4DataSource")
            .field("size", &self.size)
            .finish_non_exhaustive()
    }
}

impl Aff4DataSource {
    /// Open an AFF4 image, parsing metadata from `information.turtle`.
    pub fn open(path: &Path) -> Result<Self, Aff4Error> {
        let reader = aff4::Aff4Reader::open(path)?;
        let size = reader.virtual_disk_size();
        Ok(Self {
            reader: Mutex::new(reader),
            size,
        })
    }

    /// Open an AFF4 container whose `.aff4` file lives INSIDE an outer `.zip` —
    /// directly, without extracting it to a temp directory first. A `Stored`
    /// entry is read in place (a positioned sub-range of the outer zip); a
    /// `Deflated` entry is inflated once into RAM. Either backing feeds
    /// `Aff4Reader::open_reader`.
    ///
    /// # Errors
    /// [`Aff4Error`] if the zip cannot be read or holds no `.aff4` entry.
    pub fn open_zip(zip_path: &Path) -> Result<Self, Aff4Error> {
        // Delegate to the centralized archive backing (DRY): zip-Stored is read
        // in place, otherwise decompressed per the adaptive RAM/temp spill
        // policy; the determination is logged under `--verbose`.
        let plan = issen_unpack::backing::probe_spill_plan(1);
        let backing = issen_unpack::backing::archive_backing(zip_path, &plan, &["aff4"])
            .map_err(|e| Aff4Error::Aff4(format!("open_zip: {e}")))?;
        let reader = aff4::Aff4Reader::open_reader(Box::new(backing))?;
        let size = reader.virtual_disk_size();
        Ok(Self {
            reader: Mutex::new(reader),
            size,
        })
    }
}

// ── CollectionProvider ────────────────────────────────────────────────

use issen_unpack::{CollectionManifest, CollectionProvider, Confidence};

/// Format-recognition and manifest provider for AFF4 disk images.
#[derive(Debug, Default)]
pub struct Aff4Provider;

impl CollectionProvider for Aff4Provider {
    #[allow(clippy::unnecessary_literal_bound)] // trait fixes the `-> &str` signature
    fn name(&self) -> &str {
        "AFF4"
    }

    fn probe(&self, path: &Path) -> Result<Confidence, RtError> {
        // An AFF4 container is a ZIP holding `information.turtle` (the metadata
        // graph the reader parses). A cheap central-directory lookup confirms it
        // without a full decode; a non-zip / non-AFF4 file yields None.
        let Ok(file) = File::open(path) else {
            return Ok(Confidence::None);
        };
        let Ok(mut archive) = zip_core::ZipArchive::new(file) else {
            return Ok(Confidence::None); // not a zip → not AFF4
        };
        if archive.by_name("information.turtle").is_ok() {
            Ok(Confidence::High)
        } else {
            Ok(Confidence::None)
        }
    }

    fn open(&self, path: &Path) -> Result<CollectionManifest, RtError> {
        // Decode the AFF4 image, then run the NTFS disk-triage extractor — pull
        // $MFT, $UsnJrnl:$J, the .evtx logs and the registry hives off the volume
        // into a manifest (mirrors EwfProvider). The disk layer emits a loud
        // diagnostic when the volume is an unsupported filesystem (ADR-0008), so
        // no container-level stopgap is needed here.
        let source = Aff4DataSource::open(path)?;
        Ok(issen_disk::triage_manifest(&source, self.name())?)
    }
}

inventory::submit!(issen_unpack::registry::ProviderRegistration {
    create: || Box::new(Aff4Provider),
});

impl DataSource for Aff4DataSource {
    fn len(&self) -> u64 {
        self.size
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, RtError> {
        // A poisoned lock means an earlier read panicked while holding it, so
        // the reader's position is unknown. `read_at` has an error channel —
        // use it, rather than cascading the panic into every later read.
        let mut guard = self.reader.lock().map_err(|_| {
            RtError::Io(std::io::Error::other(
                "Aff4DataSource: reader mutex poisoned",
            ))
        })?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    fn write_tmp(data: &[u8]) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().expect("tempfile");
        f.write_all(data).expect("write");
        f
    }

    #[test]
    fn open_nonexistent_returns_err() {
        assert!(Aff4DataSource::open(Path::new("/tmp/nope.aff4")).is_err());
    }

    #[test]
    fn open_non_aff4_returns_err() {
        let f = write_tmp(&[0u8; 1024]);
        assert!(Aff4DataSource::open(f.path()).is_err());
    }

    #[test]
    fn len_matches_virtual_disk_size() {
        let img = aff4::testutil::test_aff4(&[0u8; 512]);
        let f = write_tmp(&img);
        let src = Aff4DataSource::open(f.path()).expect("open");
        assert_eq!(src.len(), aff4::testutil::CHUNK_SIZE as u64);
    }

    #[test]
    fn read_at_returns_correct_bytes() {
        let mut data = vec![0u8; 512];
        data[10] = 0xCA;
        data[11] = 0xFE;
        let img = aff4::testutil::test_aff4(&data);
        let f = write_tmp(&img);
        let src = Aff4DataSource::open(f.path()).expect("open");
        let mut buf = [0u8; 2];
        src.read_at(10, &mut buf).expect("read_at");
        assert_eq!(buf, [0xCA, 0xFE]);
    }

    #[test]
    fn aff4_data_source_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Aff4DataSource>();
    }

    #[test]
    fn aff4_error_converts_to_rt_error() {
        let e = Aff4Error::Aff4("bad turtle".into());
        assert!(matches!(RtError::from(e), RtError::Parse { .. }));
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

    /// The oracle: open_zip over a zipped AFF4 (BOTH Stored and Deflated) reads
    /// byte-identically to opening the loose `.aff4` directly.
    #[test]
    fn open_zip_matches_open_loose_stored_and_deflated() {
        let mut sector = vec![0u8; 512];
        sector[10] = 0xCA;
        sector[11] = 0xFE;
        let img = aff4::testutil::test_aff4(&sector);

        let loose = write_tmp(&img);
        let oracle = Aff4DataSource::open(loose.path()).expect("open loose");
        let size = oracle.len();
        let mut want = vec![0u8; size as usize];
        oracle.read_at(0, &mut want).expect("read loose");

        for method in [
            zip::CompressionMethod::Stored,
            zip::CompressionMethod::Deflated,
        ] {
            let zip = make_zip("disk.aff4", &img, method);
            let via_zip = Aff4DataSource::open_zip(zip.path()).expect("open_zip");
            assert_eq!(via_zip.len(), size, "size mismatch for {method:?}");
            let mut got = vec![0u8; size as usize];
            via_zip.read_at(0, &mut got).expect("read via zip");
            assert_eq!(got, want, "byte mismatch for {method:?}");
        }
    }

    #[test]
    fn aff4_provider_name() {
        assert_eq!(Aff4Provider.name(), "AFF4");
    }

    #[test]
    fn aff4_provider_probe_valid_aff4_returns_high() {
        let img = aff4::testutil::test_aff4(&[0u8; 512]);
        let f = write_tmp(&img);
        assert_eq!(
            Aff4Provider.probe(f.path()).expect("probe"),
            Confidence::High
        );
    }

    #[test]
    fn aff4_provider_probe_non_aff4_returns_none() {
        let f = write_tmp(&[0u8; 1024]);
        assert_eq!(
            Aff4Provider.probe(f.path()).expect("probe"),
            Confidence::None
        );
    }

    #[test]
    fn aff4_provider_open_runs_disk_triage() {
        // open() must run the NTFS disk triage over the AFF4 image (like EWF),
        // returning a CollectionManifest — not the old container-level fail-loud
        // stopgap. This fixture has no partition table, so the manifest is empty;
        // the point is that triage RAN (the disk layer now owns fail-loud on an
        // unsupported filesystem, per ADR-0008), not that artifacts were found.
        let img = aff4::testutil::test_aff4(&[0u8; 512]);
        let f = write_tmp(&img);
        let manifest = Aff4Provider
            .open(f.path())
            .expect("disk triage should run, not fail loud");
        assert_eq!(manifest.format_name, "AFF4");
    }

    #[test]
    fn aff4_provider_registered_in_inventory() {
        use issen_unpack::registry::ProviderRegistration;
        let names: Vec<String> = inventory::iter::<ProviderRegistration>
            .into_iter()
            .map(|r| (r.create)().name().to_string())
            .collect();
        assert!(
            names.contains(&"AFF4".to_string()),
            "Aff4Provider must be in inventory; got: {names:?}"
        );
    }
}
