#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
//! Legacy VHD disk image reader for the Issen forensic pipeline.
//!
//! Wraps the [`vhd`] crate to provide a [`DataSource`] implementation for
//! Fixed and Dynamic VHD images (Microsoft Virtual PC / Hyper-V Gen-1).

use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::Mutex;

use issen_core::error::RtError;
use issen_core::plugin::traits::DataSource;

/// Errors specific to VHD image operations.
#[derive(Debug, thiserror::Error)]
pub enum VhdError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("VHD parse error: {0}")]
    Vhd(String),
}

impl From<vhd::VhdError> for VhdError {
    fn from(e: vhd::VhdError) -> Self {
        match e {
            vhd::VhdError::Io(io) => Self::Io(io),
            other => Self::Vhd(other.to_string()),
        }
    }
}

impl From<VhdError> for RtError {
    fn from(e: VhdError) -> Self {
        match e {
            VhdError::Io(io) => Self::Io(io),
            VhdError::Vhd(msg) => Self::Parse {
                offset: 0,
                message: format!("vhd: {msg}"),
            },
        }
    }
}

/// A [`DataSource`] backed by a legacy VHD disk image.
pub struct VhdDataSource {
    reader: Mutex<vhd::VhdReader>,
    size: u64,
}

impl std::fmt::Debug for VhdDataSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VhdDataSource")
            .field("size", &self.size)
            .finish_non_exhaustive()
    }
}

impl VhdDataSource {
    /// Open a VHD disk image (Fixed or Dynamic).
    pub fn open(path: &Path) -> Result<Self, VhdError> {
        let reader = vhd::VhdReader::open(path)?;
        let size = reader.virtual_disk_size();
        Ok(Self {
            reader: Mutex::new(reader),
            size,
        })
    }

    /// Open a VHD whose `.vhd` file lives INSIDE a `.zip` — directly, without
    /// extracting it to a temp directory first. A `Stored` entry is read in
    /// place (a positioned sub-range of the zip); a `Deflated` entry is inflated
    /// once into RAM and read from a `Cursor`. Either backing feeds
    /// `VhdReader::open_reader`.
    ///
    /// # Errors
    /// [`VhdError`] if the zip cannot be read or holds no `.vhd` entry.
    pub fn open_zip(zip_path: &Path) -> Result<Self, VhdError> {
        // Delegate to the centralized archive backing (DRY): zip-Stored is read
        // in place, otherwise decompressed per the adaptive RAM/temp spill
        // policy; the determination is logged under `--verbose`.
        let plan = issen_unpack::backing::probe_spill_plan(1);
        let backing = issen_unpack::backing::archive_backing(zip_path, &plan, &["vhd"])
            .map_err(|e| VhdError::Vhd(format!("open_zip: {e}")))?;
        let reader = vhd::VhdReader::open_reader(Box::new(backing))?;
        let size = reader.virtual_disk_size();
        Ok(Self {
            reader: Mutex::new(reader),
            size,
        })
    }
}

impl DataSource for VhdDataSource {
    fn len(&self) -> u64 {
        self.size
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, RtError> {
        // A poisoned lock means an earlier read panicked while holding it, so
        // the reader's position is unknown. `read_at` has an error channel —
        // use it, rather than cascading the panic into every later read.
        let mut guard = self.reader.lock().map_err(|_| {
            RtError::Io(std::io::Error::other(
                "VhdDataSource: reader mutex poisoned",
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

// ── CollectionProvider ────────────────────────────────────────────────

use issen_unpack::{CollectionManifest, CollectionProvider, Confidence};

/// Format-recognition and manifest provider for legacy VHD disk images.
#[derive(Debug, Default)]
pub struct VhdProvider;

impl CollectionProvider for VhdProvider {
    #[allow(clippy::unnecessary_literal_bound)] // trait fixes the `-> &str` signature
    fn name(&self) -> &str {
        "VHD"
    }

    fn probe(&self, path: &Path) -> Result<Confidence, RtError> {
        use std::io::{Read, Seek, SeekFrom};
        // VHD footer cookie "conectix" sits in the last 512 bytes of the file.
        let mut f = std::fs::File::open(path).map_err(RtError::Io)?;
        let len = f.metadata().map_err(RtError::Io)?.len();
        if len < 512 {
            return Ok(Confidence::None);
        }
        f.seek(SeekFrom::Start(len - 512)).map_err(RtError::Io)?;
        let mut cookie = [0u8; 8];
        match f.read_exact(&mut cookie) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(Confidence::None),
            Err(e) => return Err(RtError::Io(e)),
        }
        if &cookie == b"conectix" {
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
        VhdDataSource::open(path)?;
        Err(RtError::UnsupportedFormat(format!(
            "{}: image opens, but artifact extraction is not yet wired for \
             this container (refusing to emit a silent empty timeline)",
            self.name()
        )))
    }
}

inventory::submit!(issen_unpack::registry::ProviderRegistration {
    create: || Box::new(VhdProvider),
});

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn fixed_vhd(sector_data: &[u8]) -> Vec<u8> {
        let mut v = sector_data.to_vec();
        v.extend_from_slice(&vhd::footer::test_fixed_footer(sector_data.len() as u64));
        v
    }

    fn write_tmp(data: &[u8]) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(data).unwrap();
        f
    }

    #[test]
    fn open_nonexistent_returns_err() {
        assert!(VhdDataSource::open(Path::new("/tmp/nope.vhd")).is_err());
    }

    #[test]
    fn len_matches_virtual_disk_size() {
        let vhd = fixed_vhd(&vec![0u8; 512]);
        let f = write_tmp(&vhd);
        let src = VhdDataSource::open(f.path()).expect("open");
        assert_eq!(src.len(), 512);
    }

    #[test]
    fn read_at_returns_correct_bytes() {
        let mut sector = vec![0u8; 512];
        sector[10] = 0xCA;
        sector[11] = 0xFE;
        let vhd = fixed_vhd(&sector);
        let f = write_tmp(&vhd);
        let src = VhdDataSource::open(f.path()).expect("open");
        let mut buf = [0u8; 2];
        src.read_at(10, &mut buf).expect("read_at");
        assert_eq!(buf, [0xCA, 0xFE]);
    }

    #[test]
    fn vhd_data_source_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<VhdDataSource>();
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

    /// The oracle: open_zip over a zipped VHD (BOTH Stored and Deflated) reads
    /// byte-identically to opening the loose `.vhd` directly.
    #[test]
    fn open_zip_matches_open_loose_stored_and_deflated() {
        let mut sector = vec![0u8; 1024];
        sector[10] = 0xCA;
        sector[11] = 0xFE;
        sector[600] = 0x42;
        let img = fixed_vhd(&sector);

        let loose = write_tmp(&img);
        let oracle = VhdDataSource::open(loose.path()).expect("open loose");
        let size = oracle.len();
        let mut want = vec![0u8; size as usize];
        oracle.read_at(0, &mut want).expect("read loose");

        for method in [
            zip::CompressionMethod::Stored,
            zip::CompressionMethod::Deflated,
        ] {
            let zip = make_zip("disk.vhd", &img, method);
            let via_zip = VhdDataSource::open_zip(zip.path()).expect("open_zip");
            assert_eq!(via_zip.len(), size, "size mismatch for {method:?}");
            let mut got = vec![0u8; size as usize];
            via_zip.read_at(0, &mut got).expect("read via zip");
            assert_eq!(got, want, "byte mismatch for {method:?}");
        }
    }

    #[test]
    fn vhd_error_converts_to_rt_error() {
        let e = VhdError::Vhd("bad cookie".into());
        assert!(matches!(RtError::from(e), RtError::Parse { .. }));
    }

    // ── VhdProvider tests ─────────────────────────────────────────────

    #[test]
    fn vhd_provider_name() {
        assert_eq!(VhdProvider.name(), "VHD");
    }

    #[test]
    fn vhd_provider_probe_valid_footer_returns_high() {
        // Valid VHD = data + 512-byte footer with "conectix" cookie
        let sector = vec![0u8; 512];
        let vhd_bytes = fixed_vhd(&sector);
        let f = write_tmp(&vhd_bytes);
        // RED: stub returns None — FAILS
        assert_eq!(
            VhdProvider.probe(f.path()).expect("probe"),
            Confidence::High
        );
    }

    #[test]
    fn vhd_provider_probe_wrong_footer_returns_none() {
        let f = write_tmp(&vec![0u8; 1024]);
        assert_eq!(
            VhdProvider.probe(f.path()).expect("probe"),
            Confidence::None
        );
    }

    #[test]
    fn vhd_provider_probe_nonexistent_returns_err() {
        // RED: stub returns Ok(None) — FAILS
        assert!(VhdProvider
            .probe(Path::new("/tmp/nonexistent_99999.vhd"))
            .is_err());
    }

    #[test]
    fn vhd_provider_open_invalid_returns_err() {
        let f = write_tmp(b"not a vhd");
        assert!(VhdProvider.open(f.path()).is_err());
    }

    #[test]
    fn vhd_provider_open_nonexistent_returns_err() {
        assert!(VhdProvider
            .open(Path::new("/tmp/nonexistent_99999.vhd"))
            .is_err());
    }

    #[test]
    fn vhd_provider_registered_in_inventory() {
        use issen_unpack::registry::ProviderRegistration;
        let names: Vec<String> = inventory::iter::<ProviderRegistration>
            .into_iter()
            .map(|r| (r.create)().name().to_string())
            .collect();
        assert!(
            names.contains(&"VHD".to_string()),
            "VhdProvider must be in inventory; got: {names:?}"
        );
    }
}
