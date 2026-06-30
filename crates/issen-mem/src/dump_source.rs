//! Open a memory dump from a regular file OR straight out of a `.zip` entry,
//! without extracting it to a temporary file first.
//!
//! DFIR corpora (e.g. DFIR Madness "Szechuan Sauce", Total Recall) ship memory
//! dumps inside `.zip` archives. `issen memory dump.zip` reads the dump entry
//! directly into RAM and builds the same [`PhysicalMemoryProvider`] memf-format
//! would build from a loose file — so no temp file is written to disk.
//!
//! memf-format already holds the whole dump in RAM (`*Provider::from_bytes`
//! copies into a `Vec<u8>`), so routing the zip path through bytes costs no
//! extra memory over the loose-file path.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use anyhow::{anyhow, Context};
use memf_format::PhysicalMemoryProvider;

use crate::open::{detect_format_bytes, DumpFormat};

/// ZIP local-file-header magic (`PK\x03\x04`).
const ZIP_MAGIC: [u8; 4] = [0x50, 0x4B, 0x03, 0x04];

/// Bytes peeked from a dump entry to detect its format (covers every header).
const PEEK_LEN: usize = 4096;

/// Memory-dump entry extensions recognized inside a zip (lowercase, no dot).
/// Used only to PREFER an entry; the actual format is decided by magic bytes.
const DUMP_EXTS: &[&str] = &[
    "mem", "vmem", "lime", "raw", "dmp", "dump", "core", "vmss", "vmsn",
];

/// True if `path` is a zip archive — by magic bytes, never by extension.
#[must_use]
pub fn is_zip(path: &Path) -> bool {
    let mut magic = [0u8; 4];
    File::open(path)
        .and_then(|mut f| f.read_exact(&mut magic).map(|()| magic))
        .map(|m| m == ZIP_MAGIC)
        .unwrap_or(false)
}

/// Choose the zip entry that holds the memory dump: an entry whose extension is
/// a known dump extension, else the largest file entry (a memory dump dominates
/// the archive). Fails loud when the archive has no file entry.
fn find_dump_entry(archive: &mut zip_core::ZipArchive<File>) -> anyhow::Result<usize> {
    let mut by_ext: Option<usize> = None;
    let mut largest: Option<(usize, u64)> = None;
    for i in 0..archive.len() {
        let entry = archive
            .by_index(i)
            .map_err(|e| anyhow!("zip entry {i}: {e}"))?;
        if entry.is_dir() {
            continue;
        }
        let size = entry.size();
        if by_ext.is_none() {
            let is_dump_ext = Path::new(entry.name())
                .extension()
                .and_then(|e| e.to_str())
                .map(str::to_ascii_lowercase)
                .is_some_and(|e| DUMP_EXTS.contains(&e.as_str()));
            if is_dump_ext {
                by_ext = Some(i);
            }
        }
        if largest.is_none_or(|(_, s)| size > s) {
            largest = Some((i, size));
        }
    }
    by_ext
        .or(largest.map(|(i, _)| i))
        .ok_or_else(|| anyhow!("zip contains no file entry to read a memory dump from"))
}

/// Read up to `buf.len()` bytes, tolerating short reads (the zip reader inflates
/// in chunks). Returns the number of bytes filled.
fn read_up_to(r: &mut impl Read, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut total = 0;
    while total < buf.len() {
        match r.read(&mut buf[total..])? {
            0 => break,
            k => total += k,
        }
    }
    Ok(total)
}

/// Read the memory-dump bytes out of a zip and detect the format from them.
///
/// The dump entry is chosen by extension when one matches, else the largest
/// entry (a memory dump dominates the archive). Both `Stored` and `Deflated`
/// entries are read transparently into RAM — no temp file is written.
pub fn read_dump_from_zip(zip_path: &Path) -> anyhow::Result<(DumpFormat, Vec<u8>)> {
    let file =
        File::open(zip_path).with_context(|| format!("opening zip {}", zip_path.display()))?;
    let mut archive = zip_core::ZipArchive::new(file)
        .with_context(|| format!("reading zip central directory of {}", zip_path.display()))?;
    let idx = find_dump_entry(&mut archive)?;
    let mut entry = archive
        .by_index(idx)
        .map_err(|e| anyhow!("zip entry {idx}: {e}"))?;
    let name = entry.name().to_string();
    let mut buf = Vec::with_capacity(usize::try_from(entry.size()).unwrap_or(0));
    entry
        .read_to_end(&mut buf)
        .with_context(|| format!("reading dump entry '{name}' from zip"))?;
    let fmt = detect_format_bytes(&buf);
    Ok((fmt, buf))
}

/// Build a [`PhysicalMemoryProvider`] from already-read dump bytes, dispatched
/// on the detected format.
pub fn provider_from_bytes(
    fmt: DumpFormat,
    bytes: &[u8],
) -> anyhow::Result<Box<dyn PhysicalMemoryProvider>> {
    let provider: Box<dyn PhysicalMemoryProvider> = match fmt {
        DumpFormat::Lime => Box::new(
            memf_format::lime::LimeProvider::from_bytes(bytes)
                .map_err(|e| anyhow!("LiME decode: {e}"))?,
        ),
        DumpFormat::Avml => Box::new(
            memf_format::avml::AvmlProvider::from_bytes(bytes)
                .map_err(|e| anyhow!("AVML decode: {e}"))?,
        ),
        DumpFormat::WindowsCrashDump => Box::new(
            memf_format::win_crashdump::CrashDumpProvider::from_bytes(bytes)
                .map_err(|e| anyhow!("crash dump decode: {e}"))?,
        ),
        DumpFormat::Raw => Box::new(memf_format::raw::RawProvider::from_bytes(bytes)),
    };
    Ok(provider)
}

/// Open a memory dump from `path`, transparently handling a `.zip` that wraps a
/// dump. Returns the detected format and a provider over the dump bytes.
pub fn open_dump_source(
    path: &Path,
) -> anyhow::Result<(DumpFormat, Box<dyn PhysicalMemoryProvider>)> {
    if is_zip(path) {
        let (fmt, bytes) = read_dump_from_zip(path)?;
        let provider = provider_from_bytes(fmt, &bytes)?;
        Ok((fmt, provider))
    } else {
        let provider = memf_format::open_dump_with_raw_fallback(path)
            .map_err(|e| anyhow!("failed to open dump {}: {e}", path.display()))?;
        let fmt = crate::open::detect_format(path).unwrap_or(DumpFormat::Raw);
        Ok((fmt, provider))
    }
}

/// Detect the dump format of `path`, transparently handling a `.zip` wrapper by
/// peeking the dump entry's header (reads only the first bytes, not the whole
/// dump).
pub fn detect_format_any(path: &Path) -> std::io::Result<DumpFormat> {
    if !is_zip(path) {
        return crate::open::detect_format(path);
    }
    let file = File::open(path)?;
    let mut archive = zip_core::ZipArchive::new(file)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let idx = find_dump_entry(&mut archive)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
    let mut entry = archive
        .by_index(idx)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let mut head = vec![0u8; PEEK_LEN];
    let n = read_up_to(&mut entry, &mut head)?;
    Ok(detect_format_bytes(&head[..n]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    use memf_format::test_builders::LimeBuilder;

    /// A valid LiME dump with one physical range at address 0.
    fn lime_dump() -> (Vec<u8>, Vec<u8>) {
        let payload: Vec<u8> = (0u8..=255).cycle().take(8192).collect();
        let dump = LimeBuilder::new().add_range(0, &payload).build();
        (dump, payload)
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
        f.write_all(cursor.get_ref()).expect("write zip bytes");
        f.flush().expect("flush");
        f
    }

    fn loose_file(data: &[u8]) -> tempfile::NamedTempFile {
        let mut f = tempfile::Builder::new()
            .suffix(".lime")
            .tempfile()
            .expect("tempfile");
        f.write_all(data).expect("write");
        f.flush().expect("flush");
        f
    }

    #[test]
    fn is_zip_true_for_zip_magic() {
        let (dump, _) = lime_dump();
        let zip = make_zip("dump.lime", &dump, zip::CompressionMethod::Stored);
        assert!(
            is_zip(zip.path()),
            "PK\\x03\\x04 magic must be detected as zip"
        );
    }

    #[test]
    fn is_zip_false_for_loose_dump() {
        let (dump, _) = lime_dump();
        let f = loose_file(&dump);
        assert!(!is_zip(f.path()), "a raw LiME dump is not a zip");
    }

    #[test]
    fn read_dump_from_zip_returns_lime_format_and_bytes() {
        let (dump, _) = lime_dump();
        let zip = make_zip("DC01.mem", &dump, zip::CompressionMethod::Stored);
        let (fmt, bytes) = read_dump_from_zip(zip.path()).expect("read from zip");
        assert_eq!(fmt, DumpFormat::Lime);
        assert_eq!(bytes, dump, "extracted bytes must equal the original dump");
    }

    #[test]
    fn provider_from_bytes_raw_total_size_matches() {
        let bytes: Vec<u8> = (0u8..=255).collect();
        let provider = provider_from_bytes(DumpFormat::Raw, &bytes).expect("provider");
        assert_eq!(provider.total_size(), bytes.len() as u64);
    }

    #[test]
    fn open_dump_source_plain_file_matches_loose_open() {
        let (dump, payload) = lime_dump();
        let f = loose_file(&dump);
        let (fmt, provider) = open_dump_source(f.path()).expect("open loose");
        assert_eq!(fmt, DumpFormat::Lime);
        let mut buf = vec![0u8; payload.len()];
        let n = provider.read_phys(0, &mut buf).expect("read_phys");
        assert_eq!(&buf[..n], &payload[..n]);
    }

    /// The oracle: open_dump_source over a zipped dump (BOTH Stored and Deflated)
    /// returns a provider byte-identical to opening the loose dump directly —
    /// the memory analog of ewf's `open_zip_matches_open_loose`.
    #[test]
    fn open_dump_source_zip_matches_loose_stored_and_deflated() {
        let (dump, payload) = lime_dump();

        let loose = loose_file(&dump);
        let oracle = memf_format::open_dump_with_raw_fallback(loose.path()).expect("loose open");

        for method in [
            zip::CompressionMethod::Stored,
            zip::CompressionMethod::Deflated,
        ] {
            let zip = make_zip("DESKTOP.mem", &dump, method);
            let (fmt, provider) = open_dump_source(zip.path()).expect("open via zip");
            assert_eq!(fmt, DumpFormat::Lime, "method {method:?}");
            assert_eq!(
                provider.total_size(),
                oracle.total_size(),
                "total_size mismatch for {method:?}"
            );
            let mut got = vec![0u8; payload.len()];
            let mut want = vec![0u8; payload.len()];
            let gn = provider.read_phys(0, &mut got).expect("read via zip");
            let wn = oracle.read_phys(0, &mut want).expect("read loose");
            assert_eq!(gn, wn, "bytes-read mismatch for {method:?}");
            assert_eq!(got, want, "phys bytes mismatch for {method:?}");
        }
    }

    #[test]
    fn detect_format_any_peeks_zip_entry_header() {
        let (dump, _) = lime_dump();
        let zip = make_zip("dump.lime", &dump, zip::CompressionMethod::Deflated);
        assert_eq!(
            detect_format_any(zip.path()).expect("detect"),
            DumpFormat::Lime,
            "must peek the entry header, not see the zip's PK magic as Raw"
        );
    }

    #[test]
    fn read_dump_from_zip_empty_archive_fails_loud() {
        // A zip with only a directory entry — no dump to read.
        use zip::write::SimpleFileOptions;
        let mut cursor = std::io::Cursor::new(Vec::<u8>::new());
        {
            let mut zw = zip::ZipWriter::new(&mut cursor);
            zw.add_directory("empty/", SimpleFileOptions::default())
                .expect("add_directory");
            zw.finish().expect("finish");
        }
        let mut f = tempfile::Builder::new()
            .suffix(".zip")
            .tempfile()
            .expect("tempfile");
        f.write_all(cursor.get_ref()).expect("write");
        f.flush().expect("flush");
        assert!(
            read_dump_from_zip(f.path()).is_err(),
            "an archive with no file entry must fail loud"
        );
    }
}
