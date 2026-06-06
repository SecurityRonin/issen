//! VMware VMDK disk image reader for the Issen forensic pipeline.
//!
//! Wraps the [`vmdk`] crate to provide a [`DataSource`] implementation for
//! monolithic sparse VMDK images (VMware Workstation / Fusion).

use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::Mutex;

use issen_core::error::RtError;
use issen_core::plugin::traits::DataSource;

/// Errors specific to VMDK image operations.
#[derive(Debug, thiserror::Error)]
pub enum VmdkError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("VMDK parse error: {0}")]
    Vmdk(String),
}

impl From<vmdk::VmdkError> for VmdkError {
    fn from(e: vmdk::VmdkError) -> Self {
        match e {
            vmdk::VmdkError::Io(io) => Self::Io(io),
            other => Self::Vmdk(other.to_string()),
        }
    }
}

impl From<VmdkError> for RtError {
    fn from(e: VmdkError) -> Self {
        match e {
            VmdkError::Io(io) => Self::Io(io),
            VmdkError::Vmdk(msg) => Self::Parse {
                offset: 0,
                message: format!("vmdk: {msg}"),
            },
        }
    }
}

/// A [`DataSource`] backed by a VMware VMDK disk image.
pub struct VmdkDataSource {
    reader: Mutex<vmdk::VmdkReader<std::fs::File>>,
    size: u64,
}

impl std::fmt::Debug for VmdkDataSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VmdkDataSource")
            .field("size", &self.size)
            .finish()
    }
}

impl VmdkDataSource {
    /// Open a VMDK disk image (monolithic sparse).
    pub fn open(path: &Path) -> Result<Self, VmdkError> {
        let file = std::fs::File::open(path)?;
        let reader = vmdk::VmdkReader::open(file)?;
        let size = reader.virtual_disk_size();
        Ok(Self {
            reader: Mutex::new(reader),
            size,
        })
    }
}

impl DataSource for VmdkDataSource {
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

/// Format-recognition and manifest provider for VMware VMDK disk images.
#[derive(Debug, Default)]
pub struct VmdkProvider;

impl CollectionProvider for VmdkProvider {
    fn name(&self) -> &str {
        "VMDK"
    }

    fn probe(&self, path: &Path) -> Result<Confidence, RtError> {
        use std::io::Read;
        // VMDK sparse extent magic: 0x564D444B stored LE = bytes [0x4B, 0x44, 0x4D, 0x56]
        const VMDK_MAGIC: [u8; 4] = [0x4B, 0x44, 0x4D, 0x56];
        let mut f = std::fs::File::open(path).map_err(RtError::Io)?;
        let mut magic = [0u8; 4];
        match f.read_exact(&mut magic) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(Confidence::None),
            Err(e) => return Err(RtError::Io(e)),
        }
        if magic == VMDK_MAGIC {
            Ok(Confidence::High)
        } else {
            Ok(Confidence::None)
        }
    }

    fn open(&self, path: &Path) -> Result<CollectionManifest, RtError> {
        // Decode the VMDK, then run the NTFS disk-triage pipeline: detect the
        // partition table, open each NTFS volume, and extract the standard
        // Windows triage artifacts into a manifest the ingest pipeline parses.
        let source = VmdkDataSource::open(path)?;
        Ok(issen_disk::triage_manifest(&source, self.name())?)
    }
}

inventory::submit!(issen_unpack::registry::ProviderRegistration {
    create: || Box::new(VmdkProvider),
});

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn sparse_vmdk(sector_data: &[u8]) -> Vec<u8> {
        vmdk::testutil::test_sparse_vmdk(sector_data)
    }

    fn write_tmp(data: &[u8]) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(data).unwrap();
        f
    }

    #[test]
    fn open_nonexistent_returns_err() {
        assert!(VmdkDataSource::open(Path::new("/tmp/nope.vmdk")).is_err());
    }

    #[test]
    fn len_matches_virtual_disk_size() {
        let vmdk = sparse_vmdk(&vec![0u8; 512]);
        let f = write_tmp(&vmdk);
        let src = VmdkDataSource::open(f.path()).expect("open");
        assert_eq!(src.len(), vmdk::testutil::GRAIN_SIZE_BYTES as u64);
    }

    #[test]
    fn read_at_returns_correct_bytes() {
        let mut data = vec![0u8; 512];
        data[10] = 0xCA;
        data[11] = 0xFE;
        let vmdk = sparse_vmdk(&data);
        let f = write_tmp(&vmdk);
        let src = VmdkDataSource::open(f.path()).expect("open");
        let mut buf = [0u8; 2];
        src.read_at(10, &mut buf).expect("read_at");
        assert_eq!(buf, [0xCA, 0xFE]);
    }

    #[test]
    fn vmdk_data_source_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<VmdkDataSource>();
    }

    #[test]
    fn vmdk_error_converts_to_rt_error() {
        let e = VmdkError::Vmdk("bad magic".into());
        assert!(matches!(RtError::from(e), RtError::Parse { .. }));
    }

    // ── VmdkProvider tests ────────────────────────────────────────────

    #[test]
    fn vmdk_provider_name() {
        assert_eq!(VmdkProvider.name(), "VMDK");
    }

    #[test]
    fn vmdk_provider_probe_valid_magic_returns_high() {
        // VMDK sparse magic: 0x564D444B LE = bytes [0x4B, 0x44, 0x4D, 0x56]
        let magic_bytes = 0x564D_444Bu32.to_le_bytes();
        let vmdk_data = vmdk::testutil::test_sparse_vmdk(&[0u8; 512]);
        let f = write_tmp(&vmdk_data);
        assert_eq!(
            magic_bytes[..],
            vmdk_data[..4],
            "test VMDK must start with sparse magic"
        );
        // RED: stub returns None — FAILS
        assert_eq!(
            VmdkProvider.probe(f.path()).expect("probe"),
            Confidence::High
        );
    }

    #[test]
    fn vmdk_provider_probe_wrong_magic_returns_none() {
        let f = write_tmp(b"not-vmdk\x00\x00\x00\x00");
        assert_eq!(
            VmdkProvider.probe(f.path()).expect("probe"),
            Confidence::None
        );
    }

    #[test]
    fn vmdk_provider_probe_nonexistent_returns_err() {
        // RED: stub returns Ok(None) — FAILS
        assert!(VmdkProvider
            .probe(Path::new("/tmp/nonexistent_99999.vmdk"))
            .is_err());
    }

    #[test]
    fn vmdk_provider_open_invalid_returns_err() {
        let f = write_tmp(b"not a vmdk");
        assert!(VmdkProvider.open(f.path()).is_err());
    }

    #[test]
    fn vmdk_provider_open_nonexistent_returns_err() {
        assert!(VmdkProvider
            .open(Path::new("/tmp/nonexistent_99999.vmdk"))
            .is_err());
    }

    #[test]
    fn vmdk_provider_open_runs_disk_triage() {
        // A VMDK wrapping a disk with no partition table: open() now runs the
        // NTFS disk-triage pipeline (issen_disk::triage_manifest), which tags
        // the collection os_type = Windows. The old stub left it Unknown.
        // (Full artifact extraction is covered by issen-disk's own tests.)
        let disk = vec![0u8; 64 * 512];
        let vmdk_data = vmdk::testutil::test_sparse_vmdk(&disk);
        let f = write_tmp(&vmdk_data);
        let manifest = VmdkProvider.open(f.path()).expect("open runs triage");
        assert_eq!(manifest.format_name, "VMDK");
        assert!(matches!(
            manifest.metadata.os_type,
            issen_unpack::OsType::Windows
        ));
    }

    #[test]
    fn vmdk_provider_registered_in_inventory() {
        use issen_unpack::registry::ProviderRegistration;
        let names: Vec<String> = inventory::iter::<ProviderRegistration>
            .into_iter()
            .map(|r| (r.create)().name().to_string())
            .collect();
        assert!(
            names.contains(&"VMDK".to_string()),
            "VmdkProvider must be in inventory; got: {names:?}"
        );
    }
}
