#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
//! QCOW2 disk image reader for the Issen forensic pipeline.
//!
//! Wraps the [`qcow2`] crate to provide a [`DataSource`] implementation for
//! QCOW2 v2/v3 images (QEMU/KVM / libvirt).

use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::Mutex;

use issen_core::error::RtError;
use issen_core::plugin::traits::DataSource;

/// Errors specific to QCOW2 image operations.
#[derive(Debug, thiserror::Error)]
pub enum Qcow2Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("QCOW2 parse error: {0}")]
    Qcow2(String),
}

impl From<qcow2::Qcow2Error> for Qcow2Error {
    fn from(e: qcow2::Qcow2Error) -> Self {
        match e {
            qcow2::Qcow2Error::Io(io) => Self::Io(io),
            other => Self::Qcow2(other.to_string()),
        }
    }
}

impl From<Qcow2Error> for RtError {
    fn from(e: Qcow2Error) -> Self {
        match e {
            Qcow2Error::Io(io) => Self::Io(io),
            Qcow2Error::Qcow2(msg) => Self::Parse {
                offset: 0,
                message: format!("qcow2: {msg}"),
            },
        }
    }
}

/// A [`DataSource`] backed by a QCOW2 disk image.
pub struct Qcow2DataSource {
    reader: Mutex<qcow2::Qcow2Reader>,
    size: u64,
}

impl std::fmt::Debug for Qcow2DataSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Qcow2DataSource")
            .field("size", &self.size)
            .finish_non_exhaustive()
    }
}

impl Qcow2DataSource {
    /// Open a QCOW2 disk image (v2 or v3, no encryption, no backing file).
    pub fn open(path: &Path) -> Result<Self, Qcow2Error> {
        let reader = qcow2::Qcow2Reader::open(path)?;
        let size = reader.virtual_disk_size();
        Ok(Self {
            reader: Mutex::new(reader),
            size,
        })
    }

    /// Open a QCOW2 image whose `.qcow2` file lives INSIDE a `.zip` — directly,
    /// without extracting it to a temp directory first. A `Stored` entry is read
    /// in place (a positioned sub-range of the zip); a `Deflated` entry is
    /// inflated once into RAM and read from a `Cursor`. Either backing feeds
    /// `Qcow2Reader::open_reader`, whose lazy L1/L2 tables stay bounded.
    ///
    /// # Errors
    /// [`Qcow2Error`] if the zip cannot be read or holds no `.qcow2` entry.
    pub fn open_zip(zip_path: &Path) -> Result<Self, Qcow2Error> {
        let _ = zip_path;
        Err(Qcow2Error::Qcow2("open_zip not implemented".into())) // RED stub
    }
}

impl DataSource for Qcow2DataSource {
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

/// Format-recognition and manifest provider for QCOW2 disk images.
#[derive(Debug, Default)]
pub struct Qcow2Provider;

impl CollectionProvider for Qcow2Provider {
    #[allow(clippy::unnecessary_literal_bound)] // trait fixes the `-> &str` signature
    fn name(&self) -> &str {
        "QCOW2"
    }

    fn probe(&self, path: &Path) -> Result<Confidence, RtError> {
        use std::io::Read;
        // QCOW2 magic: 0x5146_49fb stored BE = bytes [0x51, 0x46, 0x49, 0xFB]
        const QCOW2_MAGIC: [u8; 4] = [0x51, 0x46, 0x49, 0xFB];
        let mut f = std::fs::File::open(path).map_err(RtError::Io)?;
        let mut magic = [0u8; 4];
        match f.read_exact(&mut magic) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(Confidence::None),
            Err(e) => return Err(RtError::Io(e)),
        }
        if magic == QCOW2_MAGIC {
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
        Qcow2DataSource::open(path)?;
        Err(RtError::UnsupportedFormat(format!(
            "{}: image opens, but artifact extraction is not yet wired for \
             this container (refusing to emit a silent empty timeline)",
            self.name()
        )))
    }
}

inventory::submit!(issen_unpack::registry::ProviderRegistration {
    create: || Box::new(Qcow2Provider),
});

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_tmp(data: &[u8]) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(data).unwrap();
        f
    }

    #[test]
    fn open_nonexistent_returns_err() {
        assert!(Qcow2DataSource::open(Path::new("/tmp/nope.qcow2")).is_err());
    }

    #[test]
    fn len_matches_virtual_disk_size() {
        let img = qcow2::testutil::test_qcow2(&vec![0u8; 512]);
        let f = write_tmp(&img);
        let src = Qcow2DataSource::open(f.path()).expect("open");
        assert_eq!(src.len(), qcow2::testutil::CLUSTER_SIZE as u64);
    }

    #[test]
    fn read_at_returns_correct_bytes() {
        let mut data = vec![0u8; 512];
        data[10] = 0xCA;
        data[11] = 0xFE;
        let img = qcow2::testutil::test_qcow2(&data);
        let f = write_tmp(&img);
        let src = Qcow2DataSource::open(f.path()).expect("open");
        let mut buf = [0u8; 2];
        src.read_at(10, &mut buf).expect("read_at");
        assert_eq!(buf, [0xCA, 0xFE]);
    }

    #[test]
    fn qcow2_data_source_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Qcow2DataSource>();
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

    /// The oracle: open_zip over a zipped image (BOTH Stored and Deflated)
    /// reads byte-identically to opening the loose `.qcow2` directly.
    #[test]
    fn open_zip_matches_open_loose_stored_and_deflated() {
        let mut data = vec![0u8; 1024];
        data[10] = 0xCA;
        data[11] = 0xFE;
        data[600] = 0x42;
        let img = qcow2::testutil::test_qcow2(&data);

        let loose = write_tmp(&img);
        let oracle = Qcow2DataSource::open(loose.path()).expect("open loose");
        let size = oracle.len();
        let mut want = vec![0u8; size as usize];
        oracle.read_at(0, &mut want).expect("read loose");

        for method in [
            zip::CompressionMethod::Stored,
            zip::CompressionMethod::Deflated,
        ] {
            let zip = make_zip("disk.qcow2", &img, method);
            let via_zip = Qcow2DataSource::open_zip(zip.path()).expect("open_zip");
            assert_eq!(via_zip.len(), size, "size mismatch for {method:?}");
            let mut got = vec![0u8; size as usize];
            via_zip.read_at(0, &mut got).expect("read via zip");
            assert_eq!(got, want, "byte mismatch for {method:?}");
        }
    }

    #[test]
    fn qcow2_error_converts_to_rt_error() {
        let e = Qcow2Error::Qcow2("bad magic".into());
        assert!(matches!(RtError::from(e), RtError::Parse { .. }));
    }

    // ── Qcow2Provider tests ───────────────────────────────────────────

    #[test]
    fn qcow2_provider_name() {
        assert_eq!(Qcow2Provider.name(), "QCOW2");
    }

    #[test]
    fn qcow2_provider_probe_valid_magic_returns_high() {
        // QCOW2 magic: 0x5146_49fb BE = bytes [0x51, 0x46, 0x49, 0xFB]
        let img = qcow2::testutil::test_qcow2(&vec![0u8; 512]);
        let f = write_tmp(&img);
        // RED: stub returns None — FAILS
        assert_eq!(
            Qcow2Provider.probe(f.path()).expect("probe"),
            Confidence::High
        );
    }

    #[test]
    fn qcow2_provider_probe_wrong_magic_returns_none() {
        let f = write_tmp(b"not-qcow2\x00\x00\x00");
        assert_eq!(
            Qcow2Provider.probe(f.path()).expect("probe"),
            Confidence::None
        );
    }

    #[test]
    fn qcow2_provider_probe_nonexistent_returns_err() {
        // RED: stub returns Ok(None) — FAILS
        assert!(Qcow2Provider
            .probe(Path::new("/tmp/nonexistent_99999.qcow2"))
            .is_err());
    }

    #[test]
    fn qcow2_provider_open_invalid_returns_err() {
        let f = write_tmp(b"not a qcow2");
        assert!(Qcow2Provider.open(f.path()).is_err());
    }

    #[test]
    fn qcow2_provider_open_nonexistent_returns_err() {
        assert!(Qcow2Provider
            .open(Path::new("/tmp/nonexistent_99999.qcow2"))
            .is_err());
    }

    #[test]
    fn qcow2_provider_registered_in_inventory() {
        use issen_unpack::registry::ProviderRegistration;
        let names: Vec<String> = inventory::iter::<ProviderRegistration>
            .into_iter()
            .map(|r| (r.create)().name().to_string())
            .collect();
        assert!(
            names.contains(&"QCOW2".to_string()),
            "Qcow2Provider must be in inventory; got: {names:?}"
        );
    }
}
