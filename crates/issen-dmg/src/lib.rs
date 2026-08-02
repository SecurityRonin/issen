#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
//! Apple Disk Image (DMG/UDIF) container reader for the Issen forensic pipeline.
//!
//! Wraps the [`dmg`] crate (`dmg-core`) to decode a UDIF container into its raw
//! virtual sector stream and expose it as a [`DataSource`] for downstream
//! forensic parsers. A Mac evidence image is often a DMG wrapping HFS+/APFS.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::Mutex;

use issen_core::error::RtError;
use issen_core::plugin::traits::DataSource;

/// A seekable, thread-safe byte source the raw reader can sit on: a `File`, an
/// in-RAM `Cursor`, or a positioned sub-range of a `.zip`.
pub trait ReadSeekSend: Read + Seek + Send + Sync {}
impl<T: Read + Seek + Send + Sync> ReadSeekSend for T {}

/// Errors specific to DMG image operations.
#[derive(Debug, thiserror::Error)]
pub enum DmgError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("not a valid DMG/UDIF image: {0}")]
    InvalidDmg(String),
}

impl From<dmg::DmgError> for DmgError {
    fn from(e: dmg::DmgError) -> Self {
        match e {
            dmg::DmgError::Io(io) => Self::Io(io),
            other => Self::InvalidDmg(other.to_string()),
        }
    }
}

impl From<DmgError> for RtError {
    fn from(e: DmgError) -> Self {
        match e {
            DmgError::Io(io) => Self::Io(io),
            DmgError::InvalidDmg(msg) => Self::Parse {
                offset: 0,
                message: format!("dmg: {msg}"),
            },
        }
    }
}

/// A [`DataSource`] backed by an Apple DMG (UDIF) disk image.
pub struct DmgDataSource {
    reader: Mutex<dmg::DmgReader<Box<dyn ReadSeekSend>>>,
    size: u64,
}

impl std::fmt::Debug for DmgDataSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DmgDataSource")
            .field("size", &self.size)
            .finish_non_exhaustive()
    }
}

impl DmgDataSource {
    /// Open a DMG/UDIF disk image, decoding the koly trailer and block tables.
    pub fn open(path: &Path) -> Result<Self, DmgError> {
        let raw: Box<dyn ReadSeekSend> = Box::new(File::open(path)?);
        Self::open_reader(raw)
    }

    /// Open a DMG/UDIF image from any seekable byte source (a `File`, an in-RAM
    /// `Cursor`, or a positioned sub-range of a `.zip`). This is the uniform
    /// entry the container dispatch can call after selecting a backing.
    ///
    /// # Errors
    /// [`DmgError`] if the source is not a valid UDIF container.
    pub fn open_reader(reader: Box<dyn ReadSeekSend>) -> Result<Self, DmgError> {
        let reader = dmg::DmgReader::open(reader)?;
        let size = reader.virtual_disk_size();
        Ok(Self {
            reader: Mutex::new(reader),
            size,
        })
    }
}

impl DataSource for DmgDataSource {
    fn len(&self) -> u64 {
        self.size
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, RtError> {
        // A poisoned lock means an earlier read panicked while holding it, so
        // the reader's position is unknown. `read_at` has an error channel —
        // use it, rather than cascading the panic into every later read.
        let mut guard = self.reader.lock().map_err(|_| {
            RtError::Io(std::io::Error::other(
                "DmgDataSource: reader mutex poisoned",
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

/// Format-recognition and manifest provider for Apple DMG/UDIF disk images.
#[derive(Debug, Default)]
pub struct DmgProvider;

impl CollectionProvider for DmgProvider {
    #[allow(clippy::unnecessary_literal_bound)] // trait fixes the `-> &str` signature
    fn name(&self) -> &str {
        "DMG"
    }

    fn probe(&self, path: &Path) -> Result<Confidence, RtError> {
        // UDIF images carry a 512-byte "koly" trailer at the very end of the
        // file; its first 4 bytes are the magic b"koly".
        let mut f = std::fs::File::open(path).map_err(RtError::Io)?;
        let len = f.metadata().map_err(RtError::Io)?.len();
        if len < 512 {
            return Ok(Confidence::None);
        }
        f.seek(SeekFrom::Start(len - 512)).map_err(RtError::Io)?;
        let mut magic = [0u8; 4];
        match f.read_exact(&mut magic) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(Confidence::None),
            Err(e) => return Err(RtError::Io(e)),
        }
        if &magic == b"koly" {
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
        DmgDataSource::open(path)?;
        Err(RtError::UnsupportedFormat(format!(
            "{}: image opens, but artifact extraction is not yet wired for \
             this container (refusing to emit a silent empty timeline)",
            self.name()
        )))
    }
}

inventory::submit!(issen_unpack::registry::ProviderRegistration {
    create: || Box::new(DmgProvider),
});

#[cfg(test)]
mod tests {
    use super::*;

    /// A real macOS `hdiutil` UDZO (zlib) DMG virtualising a 4 MiB HFS+ disk.
    /// Ground truth (independently confirmed via `dmg-core`'s reader):
    ///   - `virtual_disk_size` = 4194304 (8192 × 512 sectors)
    ///   - bytes @ 510   = 55 AA (protective MBR signature)
    ///   - bytes @ 21504 = 48 2B 00 04 (HFS+ volume-header magic "H+")
    const DMG_FIXTURE: &[u8] = include_bytes!("../tests/data/hfsplus_compressed.dmg");

    fn write_fixture() -> tempfile::NamedTempFile {
        use std::io::Write;
        let mut f = tempfile::Builder::new()
            .suffix(".dmg")
            .tempfile()
            .expect("tempfile");
        f.write_all(DMG_FIXTURE).expect("write dmg");
        f.flush().expect("flush");
        f
    }

    #[test]
    fn open_nonexistent_returns_err() {
        assert!(DmgDataSource::open(Path::new("/tmp/nope_99999.dmg")).is_err());
    }

    #[test]
    fn open_non_dmg_bytes_returns_err_not_panic() {
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(&vec![0u8; 4096]).unwrap();
        f.flush().unwrap();
        assert!(DmgDataSource::open(f.path()).is_err());
    }

    #[test]
    fn len_matches_virtual_disk_size() {
        let f = write_fixture();
        let src = DmgDataSource::open(f.path()).expect("open");
        assert_eq!(src.len(), 4_194_304);
    }

    #[test]
    fn read_at_hfsplus_magic() {
        let f = write_fixture();
        let src = DmgDataSource::open(f.path()).expect("open");
        let mut buf = [0u8; 4];
        let n = src.read_at(21504, &mut buf).expect("read_at");
        assert_eq!(n, 4);
        assert_eq!(buf, [0x48, 0x2B, 0x00, 0x04], "HFS+ volume-header magic");
    }

    #[test]
    fn read_at_protective_mbr_signature() {
        let f = write_fixture();
        let src = DmgDataSource::open(f.path()).expect("open");
        let mut buf = [0u8; 2];
        src.read_at(510, &mut buf).expect("read_at");
        assert_eq!(buf, [0x55, 0xAA], "protective MBR signature");
    }

    #[test]
    fn open_reader_matches_open_path() {
        // The uniform `open_reader(Box<dyn ...>)` entry the container dispatch
        // uses reads byte-identically to opening the loose file.
        let f = write_fixture();
        let via_path = DmgDataSource::open(f.path()).expect("open path");
        let backing: Box<dyn ReadSeekSend> = Box::new(std::io::Cursor::new(DMG_FIXTURE.to_vec()));
        let via_reader = DmgDataSource::open_reader(backing).expect("open reader");
        assert_eq!(via_reader.len(), via_path.len());
        let mut a = [0u8; 4];
        let mut b = [0u8; 4];
        via_path.read_at(21504, &mut a).expect("read path");
        via_reader.read_at(21504, &mut b).expect("read reader");
        assert_eq!(a, b);
    }

    #[test]
    fn dmg_data_source_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<DmgDataSource>();
    }

    #[test]
    fn dmg_error_converts_to_rt_error() {
        let e = DmgError::InvalidDmg("bad koly".into());
        assert!(matches!(RtError::from(e), RtError::Parse { .. }));
    }

    // ── DmgProvider tests ─────────────────────────────────────────────

    #[test]
    fn dmg_provider_name() {
        assert_eq!(DmgProvider.name(), "DMG");
    }

    #[test]
    fn dmg_provider_probe_valid_dmg_returns_high() {
        let f = write_fixture();
        assert_eq!(
            DmgProvider.probe(f.path()).expect("probe"),
            Confidence::High
        );
    }

    #[test]
    fn dmg_provider_probe_wrong_bytes_returns_none() {
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(&vec![0u8; 4096]).unwrap();
        f.flush().unwrap();
        assert_eq!(
            DmgProvider.probe(f.path()).expect("probe"),
            Confidence::None
        );
    }

    #[test]
    fn dmg_provider_probe_nonexistent_returns_err() {
        assert!(DmgProvider
            .probe(Path::new("/tmp/nonexistent_99999.dmg"))
            .is_err());
    }

    #[test]
    fn dmg_provider_open_invalid_returns_err() {
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(b"not a dmg").unwrap();
        f.flush().unwrap();
        assert!(DmgProvider.open(f.path()).is_err());
    }

    #[test]
    fn dmg_provider_open_nonexistent_returns_err() {
        assert!(DmgProvider
            .open(Path::new("/tmp/nonexistent_99999.dmg"))
            .is_err());
    }

    #[test]
    fn dmg_provider_registered_in_inventory() {
        use issen_unpack::registry::ProviderRegistration;
        let names: Vec<String> = inventory::iter::<ProviderRegistration>
            .into_iter()
            .map(|r| (r.create)().name().to_string())
            .collect();
        assert!(
            names.contains(&"DMG".to_string()),
            "DmgProvider must be in inventory; got: {names:?}"
        );
    }
}
