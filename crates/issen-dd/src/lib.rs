//! Raw (dd) disk image reader for the Issen forensic pipeline.
//!
//! A raw/dd image is a flat byte stream with no container format, so this reads
//! it directly through [`std::fs::File`] (which is `Read + Seek`) to provide a
//! [`DataSource`] for random-access reads over `.dd`, `.img`, `.raw`, `.bin`.

use std::fs::File;
use std::io::Read;
use std::io::{Seek, SeekFrom};
use std::path::Path;
use std::sync::Mutex;

use issen_core::error::RtError;
use issen_core::plugin::traits::DataSource;

/// A seekable, thread-safe byte source the raw reader can sit on: a `File`, an
/// in-RAM `Cursor`, or a positioned sub-range of a `.zip`.
pub trait ReadSeekSend: Read + Seek + Send + Sync {}
impl<T: Read + Seek + Send + Sync> ReadSeekSend for T {}

/// Errors specific to raw image operations.
#[derive(Debug, thiserror::Error)]
pub enum DdError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

impl From<DdError> for RtError {
    fn from(e: DdError) -> Self {
        match e {
            DdError::Io(io) => Self::Io(io),
        }
    }
}

/// A [`DataSource`] backed by a raw (dd) disk image.
pub struct DdDataSource {
    reader: Mutex<Box<dyn ReadSeekSend>>,
    size: u64,
}

impl std::fmt::Debug for DdDataSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DdDataSource")
            .field("size", &self.size)
            .finish_non_exhaustive()
    }
}

impl DdDataSource {
    /// Open a raw disk image file. The on-disk file length is the image size.
    pub fn open(path: &Path) -> Result<Self, DdError> {
        let reader = File::open(path).map_err(DdError::Io)?;
        let size = reader.metadata().map_err(DdError::Io)?.len();
        Ok(Self {
            reader: Mutex::new(Box::new(reader)),
            size,
        })
    }

    /// Open a raw (dd) image that lives INSIDE a `.zip` — directly, without
    /// extracting it to a temp directory first. A `Stored` entry is read in
    /// place (a positioned sub-range of the zip); a `Deflated` entry is inflated
    /// once into RAM. The image entry is chosen by raw-image extension, else the
    /// largest file entry.
    ///
    /// # Errors
    /// [`DdError`] if the zip cannot be read or holds no file entry.
    pub fn open_zip(zip_path: &Path) -> Result<Self, DdError> {
        // Delegate to the centralized archive backing (DRY): zip-Stored read in
        // place, else decompressed per the adaptive RAM/temp spill policy; the
        // determination is logged under `--verbose`.
        let plan = issen_unpack::backing::probe_spill_plan(1);
        let mut backing = issen_unpack::backing::archive_backing(zip_path, &plan, DD_EXTS)
            .map_err(DdError::Io)?;
        // A raw image carries no header — its size is the backing's length.
        let size = backing.seek(SeekFrom::End(0)).map_err(DdError::Io)?;
        backing.seek(SeekFrom::Start(0)).map_err(DdError::Io)?;
        Ok(Self {
            reader: Mutex::new(Box::new(backing)),
            size,
        })
    }
}

/// Raw-image entry extensions recognized inside a zip (lowercase, no dot).
const DD_EXTS: &[&str] = &["dd", "img", "raw", "bin", "001"];

impl DataSource for DdDataSource {
    fn len(&self) -> u64 {
        self.size
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, RtError> {
        let mut guard = self.reader.lock().expect("DdDataSource mutex poisoned");
        guard.seek(SeekFrom::Start(offset)).map_err(RtError::Io)?;
        let mut total = 0;
        while total < buf.len() {
            match guard.read(&mut buf[total..]) {
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

/// Format-recognition and manifest provider for raw (dd) disk images.
///
/// Raw images have no magic bytes. This provider returns [`Confidence::Low`]
/// for any readable file, making it the last-resort fallback in the registry.
#[derive(Debug, Default)]
pub struct DdProvider;

impl CollectionProvider for DdProvider {
    fn name(&self) -> &'static str {
        "DD"
    }

    fn probe(&self, path: &Path) -> Result<Confidence, RtError> {
        // Any readable file is a potential raw image — lowest confidence so
        // format-specific providers always win.
        std::fs::metadata(path).map_err(RtError::Io)?;
        Ok(Confidence::Low)
    }

    fn open(&self, path: &Path) -> Result<CollectionManifest, RtError> {
        // The container opens (format decodes), but no triage extractor is
        // wired for it yet. Returning an empty manifest would emit a silent,
        // clean-looking timeline (indistinguishable from a genuinely clean
        // image) — fail loud instead of fabricating "no findings".
        //
        // "Show the unrecognized value": surface the leading magic bytes at
        // offset 0 so the investigator can identify the format themselves, and
        // name a known-but-unsupported one (a network capture) when we see it.
        let src = DdDataSource::open(path)?;
        let mut head = [0u8; LEADING_BYTES];
        let read = src.read_at(0, &mut head)?;
        let head = &head[..read];
        let hex = hex_dump(head);
        Err(RtError::UnsupportedFormat(format!(
            "{}: image opens, but artifact extraction is not yet wired for \
             this container (refusing to emit a silent empty timeline). \
             First bytes at offset 0: {hex}{}",
            self.name(),
            describe_known_format(head),
        )))
    }
}

/// Number of leading bytes shown in the diagnostic hex dump.
const LEADING_BYTES: usize = 16;

/// Space-separated lowercase hex of `bytes` (e.g. `a1 b2 c3 d4`).
fn hex_dump(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Name a known-but-unsupported format from the leading bytes, or empty string.
///
/// `issen ingest` analyzes disk/memory images, not these, so naming them turns a
/// dead-end "unsupported" into an actionable redirect. Magic per the pcap and
/// pcapng (`[pcapng]`) specs — both byte orders for classic pcap.
fn describe_known_format(head: &[u8]) -> &'static str {
    if head.len() < 4 {
        return "";
    }
    match head[..4] {
        // Classic libpcap: magic 0xA1B2C3D4 written in the capturer's byte order,
        // so it lands on disk as a1 b2 c3 d4 (big-endian) or d4 c3 b2 a1 (little).
        // The ns-resolution variant 0xA1B23C4D / 0x4D3CB2A1 reads the same way.
        [0xA1, 0xB2, 0xC3, 0xD4]
        | [0xD4, 0xC3, 0xB2, 0xA1]
        | [0xA1, 0xB2, 0x3C, 0x4D]
        | [0x4D, 0x3C, 0xB2, 0xA1]
        // pcapng Section Header Block type 0x0A0D0D0A.
        | [0x0A, 0x0D, 0x0D, 0x0A] => {
            " (looks like a pcap capture — issen ingest analyzes disk/memory \
             images, not network captures)"
        }
        _ => "",
    }
}

inventory::submit!(issen_unpack::registry::ProviderRegistration {
    create: || Box::new(DdProvider),
});

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn make_image(bytes: &[u8]) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().expect("tmpfile");
        f.write_all(bytes).expect("write");
        f
    }

    #[test]
    fn open_nonexistent_returns_err() {
        assert!(DdDataSource::open(Path::new("/tmp/nope_dd_99999.dd")).is_err());
    }

    #[test]
    fn len_matches_file_size() {
        let img = make_image(&[0u8; 512]);
        let src = DdDataSource::open(img.path()).expect("open");
        assert_eq!(src.len(), 512);
    }

    #[test]
    fn read_at_returns_correct_bytes() {
        let mut data = vec![0u8; 512];
        data[256] = 0xBE;
        data[257] = 0xEF;
        let img = make_image(&data);
        let src = DdDataSource::open(img.path()).expect("open");
        let mut buf = [0u8; 2];
        let n = src.read_at(256, &mut buf).expect("read_at");
        assert_eq!(n, 2);
        assert_eq!(buf, [0xBE, 0xEF]);
    }

    #[test]
    fn dd_data_source_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<DdDataSource>();
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

    /// The oracle: open_zip over a zipped raw image (BOTH Stored and Deflated)
    /// reads byte-identically to opening the loose `.dd` directly.
    #[test]
    fn open_zip_matches_open_loose_stored_and_deflated() {
        let mut img = vec![0u8; 2048];
        img[256] = 0xBE;
        img[257] = 0xEF;
        img[1000] = 0x42;

        let loose = make_image(&img);
        let oracle = DdDataSource::open(loose.path()).expect("open loose");
        let size = oracle.len();
        let mut want = vec![0u8; size as usize];
        oracle.read_at(0, &mut want).expect("read loose");

        for method in [
            zip::CompressionMethod::Stored,
            zip::CompressionMethod::Deflated,
        ] {
            let zip = make_zip("disk.dd", &img, method);
            let via_zip = DdDataSource::open_zip(zip.path()).expect("open_zip");
            assert_eq!(via_zip.len(), size, "size mismatch for {method:?}");
            let mut got = vec![0u8; size as usize];
            via_zip.read_at(0, &mut got).expect("read via zip");
            assert_eq!(got, want, "byte mismatch for {method:?}");
        }
    }

    #[test]
    fn dd_error_converts_to_rt_error() {
        let io = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
        let e = DdError::Io(io);
        assert!(matches!(RtError::from(e), RtError::Io(_)));
    }

    // ── DdProvider tests ──────────────────────────────────────────────

    #[test]
    fn dd_provider_name() {
        assert_eq!(DdProvider.name(), "DD");
    }

    #[test]
    fn dd_provider_probe_readable_file_returns_low() {
        let img = make_image(&[0u8; 512]);
        // RED: stub returns None — FAILS (expects Low)
        assert_eq!(
            DdProvider.probe(img.path()).expect("probe"),
            Confidence::Low
        );
    }

    #[test]
    fn dd_provider_probe_nonexistent_returns_err() {
        // RED: stub returns Ok(None) — FAILS
        assert!(DdProvider
            .probe(Path::new("/tmp/nonexistent_99999.dd"))
            .is_err());
    }

    #[test]
    fn dd_provider_open_refuses_to_emit_silent_empty_manifest() {
        let img = make_image(&[0u8; 512]);
        // The DD container opens, but no triage extractor is wired for raw disk
        // images yet. Returning an empty manifest would emit a silent,
        // clean-looking timeline (indistinguishable from a genuinely empty
        // image) — fail loud instead.
        let err = DdProvider
            .open(img.path())
            .expect_err("must fail loud, not return an empty manifest");
        assert!(
            matches!(err, RtError::UnsupportedFormat(_)),
            "expected UnsupportedFormat; got: {err:?}"
        );
    }

    #[test]
    fn dd_provider_open_pcap_names_pcap_and_shows_hex() {
        // Classic little-endian pcap magic 0xA1B2C3D4 (on-disk: d4 c3 b2 a1).
        let mut bytes = vec![0xD4, 0xC3, 0xB2, 0xA1];
        bytes.extend_from_slice(&[0x02, 0x00, 0x04, 0x00, 0, 0, 0, 0, 0, 0, 0, 0]);
        let img = make_image(&bytes);
        let err = DdProvider.open(img.path()).expect_err("must fail loud");
        let msg = err.to_string();
        assert!(
            msg.contains("d4 c3 b2 a1"),
            "must show the leading magic bytes as hex; got: {msg}"
        );
        assert!(
            msg.to_lowercase().contains("pcap"),
            "must name the detected pcap format; got: {msg}"
        );
    }

    #[test]
    fn dd_provider_open_arbitrary_bytes_shows_hex_dump() {
        let bytes: Vec<u8> = (0u8..16).collect();
        let img = make_image(&bytes);
        let err = DdProvider.open(img.path()).expect_err("must fail loud");
        let msg = err.to_string();
        // The first 16 bytes (00..0f) must appear as a hex dump in the message.
        assert!(
            msg.contains("00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f"),
            "must include the first 16 bytes as a hex dump; got: {msg}"
        );
    }

    #[test]
    fn dd_provider_open_nonexistent_returns_err() {
        assert!(DdProvider
            .open(Path::new("/tmp/nonexistent_99999.dd"))
            .is_err());
    }

    #[test]
    fn dd_provider_registered_in_inventory() {
        use issen_unpack::registry::ProviderRegistration;
        let names: Vec<String> = inventory::iter::<ProviderRegistration>
            .into_iter()
            .map(|r| (r.create)().name().to_string())
            .collect();
        assert!(
            names.contains(&"DD".to_string()),
            "DdProvider must be in inventory; got: {names:?}"
        );
    }
}
