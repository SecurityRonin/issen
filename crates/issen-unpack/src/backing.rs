//! Centralized bounded backing for a disk-image container that may live loose on
//! disk OR inside an archive (zip / 7z / tar.gz / tar.bz2 / dar).
//!
//! The RAM-vs-temp spill decision for a *compressed* image entry is governed by
//! an adaptive budget (this module's pure core, [`ram_threshold`]) plus a
//! streaming spooled buffer that rolls over on the *actual* decompressed bytes
//! (bomb-safe, independent of the entry's declared size). A `zip` `Stored` entry
//! never reaches the spill path — it is read in place (zero copy).

use std::fmt;
use std::fs::File;
use std::io::{self, Cursor, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tempfile::SpooledTempFile;

/// A seekable, thread-safe byte source a container reader can sit on: an in-place
/// window over an archive file, an in-RAM buffer, or a disk-backed temp spill.
/// One canonical definition for the whole fleet (each container's `open_reader`
/// accepts `Box<dyn ReadSeekSend>`).
pub trait ReadSeekSend: Read + Seek + Send + Sync {}
impl<T: Read + Seek + Send + Sync> ReadSeekSend for T {}

/// One mebibyte, in bytes.
const MIB: u64 = 1024 * 1024;
/// One gibibyte, in bytes.
const GIB: u64 = 1024 * 1024 * 1024;

/// Floor on the per-image RAM-residency threshold: below this, spilling a tiny
/// entry costs more in filesystem overhead than the RAM it would save.
const THRESHOLD_FLOOR: u64 = 64 * MIB;
/// Ceiling: above the parser's typical working set, holding more of an image
/// resident buys nothing (a multi-GB image is read in scattered fragments), so
/// spill instead of committing more RAM.
const THRESHOLD_CEILING: u64 = GIB;
/// Denominator of the fraction of *available* RAM we commit to resident images;
/// the remaining 3/4 is left for issen's own growth (DuckDB / correlate) + OS.
const RAM_COMMIT_DENOMINATOR: u64 = 4;

/// Resource snapshot gathered once per ingest, used to size the per-image
/// RAM-residency threshold. All byte counts are bytes. The platform probing that
/// fills this in is a thin shell ([`probe_spill_plan`]); this struct keeps the
/// budget math pure and testable.
#[derive(Debug, Clone, Copy)]
pub struct SpillPlan {
    /// Currently available (free + reclaimable) RAM, in bytes.
    pub available_ram: u64,
    /// Planned concurrent decompressions (sources × worker cap). Treated as 1 if
    /// zero.
    pub concurrency: usize,
    /// Explicit operator override (`ISSEN_ARCHIVE_SPILL_THRESHOLD`), in bytes;
    /// when set it wins outright, unclamped, for deterministic environments.
    pub env_override: Option<u64>,
}

/// Per-image RAM-residency threshold in bytes: a decompressed image strictly
/// smaller than this stays in a RAM buffer; at or above it, it spills to a
/// disk-backed temp file.
///
/// The budget is `1/4 of available RAM`, split across the planned concurrency,
/// clamped to `[64 MiB, 1 GiB]`. An `env_override` bypasses the formula entirely.
#[must_use]
pub fn ram_threshold(plan: &SpillPlan) -> u64 {
    // An explicit operator override wins outright (deterministic environments).
    if let Some(n) = plan.env_override {
        return n;
    }
    let concurrency = plan.concurrency.max(1) as u64;
    // 1/4 of available RAM, split across the planned concurrent decompressions.
    // Divide before multiplying is unnecessary here (denominator only), and the
    // budget can't overflow u64 for any real RAM size.
    let budget = plan.available_ram / RAM_COMMIT_DENOMINATOR;
    let per_image = budget / concurrency;
    per_image.clamp(THRESHOLD_FLOOR, THRESHOLD_CEILING)
}

/// Parse a human byte size for `ISSEN_ARCHIVE_SPILL_THRESHOLD`: a bare count
/// (`1073741824`), a binary suffix (`256MiB`, `1GiB`, `2G`, `512K`), or a decimal
/// suffix (`512MB`, `1GB`). Case-insensitive; a fractional value is allowed
/// (`1.5GiB`). Returns `None` on anything unparseable.
#[must_use]
pub fn parse_size(s: &str) -> Option<u64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    // Split the leading numeric part (digits + one optional '.') from the unit.
    let (num, unit) = match s.find(|c: char| !(c.is_ascii_digit() || c == '.')) {
        Some(i) => (&s[..i], s[i..].trim()),
        None => (s, ""),
    };
    let value: f64 = num.parse().ok()?;
    if !value.is_finite() || value < 0.0 {
        return None;
    }
    let mult: f64 = match unit.to_ascii_lowercase().as_str() {
        "" | "b" => 1.0,
        "k" | "kib" => 1024.0,
        "kb" => 1000.0,
        "m" | "mib" => 1024.0 * 1024.0,
        "mb" => 1_000_000.0,
        "g" | "gib" => 1024.0_f64.powi(3),
        "gb" => 1_000_000_000.0,
        "t" | "tib" => 1024.0_f64.powi(4),
        "tb" => 1_000_000_000_000.0,
        _ => return None,
    };
    let bytes = value * mult;
    if bytes.is_finite() && bytes >= 0.0 {
        Some(bytes as u64)
    } else {
        None
    }
}

/// Best-effort available system RAM in bytes (platform shell, via `sysinfo`).
#[must_use]
pub fn available_ram_bytes() -> u64 {
    let mut sys = sysinfo::System::new();
    sys.refresh_memory_specifics(sysinfo::MemoryRefreshKind::everything().with_ram());
    match sys.available_memory() {
        0 => {
            // Some platforms (notably macOS) report `available_memory() == 0`
            // while `total_memory()` is correct; fall back to a conservative half
            // of total, then a fixed default if even total is unknown.
            let total = sys.total_memory();
            if total > 0 {
                total / 2
            } else {
                4 * GIB
            }
        }
        avail => avail,
    }
}

/// Free bytes on the filesystem containing `dir` (statvfs: `f_bavail × f_frsize`);
/// 0 if it can't be probed (callers treat 0 as "do not spill here").
#[must_use]
pub fn temp_free_bytes(dir: &Path) -> u64 {
    rustix::fs::statvfs(dir)
        .map(|s| s.f_bavail.saturating_mul(s.f_frsize))
        .unwrap_or(0)
}

/// Gather the live resource snapshot for `concurrency` planned sources, reading
/// the `ISSEN_ARCHIVE_SPILL_THRESHOLD` override if set. The thin platform shell
/// over the pure budget/decision core.
#[must_use]
pub fn probe_spill_plan(concurrency: usize) -> SpillPlan {
    SpillPlan {
        available_ram: available_ram_bytes(),
        concurrency,
        env_override: std::env::var("ISSEN_ARCHIVE_SPILL_THRESHOLD")
            .ok()
            .and_then(|s| parse_size(&s)),
    }
}

/// Reserve kept free on the spill volume so an ingest never fills it to zero.
const TEMP_RESERVE: u64 = 2 * GIB;

/// How a container's bytes are being backed for reading, and why — the
/// per-source determination surfaced under `issen ingest --verbose`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackingDecision {
    /// Uncompressed-contiguous source (zip `Stored`, loose file): read in place,
    /// zero copy — no RAM buffer, no temp.
    InPlace,
    /// Decompress into a RAM buffer of `bytes`. `forced_by_low_temp` is true when
    /// it would have spilled but the temp volume was too small and RAM had room.
    Ram {
        bytes: u64,
        forced_by_low_temp: bool,
    },
    /// Decompress to a disk-backed temp spill in `dir` (`bytes` decompressed).
    Spill { dir: PathBuf, bytes: u64 },
    /// Won't fit the temp volume or a safe share of RAM — refuse before reading.
    Refused {
        needed: u64,
        temp_free: u64,
        ram_avail: u64,
        dir: PathBuf,
    },
}

/// Decide how to back a container given its declared decompressed size, whether
/// it can be read in place (uncompressed-contiguous), the resource [`SpillPlan`],
/// and the chosen spill `temp_dir` + its `temp_free` bytes. Pure — the probing is
/// a thin shell, and the decision is logged verbatim under `--verbose`.
#[must_use]
pub fn decide_backing(
    declared_size: u64,
    in_place: bool,
    plan: &SpillPlan,
    temp_dir: &Path,
    temp_free: u64,
) -> BackingDecision {
    // Uncompressed-contiguous: read straight from the archive, no copy at all.
    if in_place {
        return BackingDecision::InPlace;
    }
    // Small enough to keep resident: a RAM buffer, no temp.
    if declared_size < ram_threshold(plan) {
        return BackingDecision::Ram {
            bytes: declared_size,
            forced_by_low_temp: false,
        };
    }
    // Want to spill: the decompressed image plus a reserve must fit the volume.
    if temp_free >= declared_size.saturating_add(TEMP_RESERVE) {
        return BackingDecision::Spill {
            dir: temp_dir.to_path_buf(),
            bytes: declared_size,
        };
    }
    // Temp can't hold it — fall back to RAM only if it clearly fits (≤ half of
    // available), trading the spill for completing the analysis.
    if declared_size <= plan.available_ram / 2 {
        return BackingDecision::Ram {
            bytes: declared_size,
            forced_by_low_temp: true,
        };
    }
    // Fits neither temp nor a safe share of RAM — refuse before reading a byte.
    BackingDecision::Refused {
        needed: declared_size,
        temp_free,
        ram_avail: plan.available_ram,
        dir: temp_dir.to_path_buf(),
    }
}

impl fmt::Display for BackingDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InPlace => write!(f, "read in place (no decompression, no temp)"),
            Self::Ram {
                bytes,
                forced_by_low_temp: false,
            } => write!(f, "decompress into RAM ({})", human(*bytes)),
            Self::Ram {
                bytes,
                forced_by_low_temp: true,
            } => write!(
                f,
                "decompress into RAM ({}) — temp volume too small, RAM has room",
                human(*bytes)
            ),
            Self::Spill { dir, bytes } => {
                write!(f, "spill {} to {}", human(*bytes), dir.display())
            }
            Self::Refused {
                needed,
                temp_free,
                ram_avail,
                dir,
            } => write!(
                f,
                "REFUSED: needs {} decompressed; {} has {} free, RAM {} available — \
                 set ISSEN_SPILL_DIR to a volume with enough space",
                human(*needed),
                dir.display(),
                human(*temp_free),
                human(*ram_avail),
            ),
        }
    }
}

/// Human-readable byte size, e.g. `42.0 GiB`, `100 B`.
fn human(bytes: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} {}", UNITS[0])
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

/// Outer archive format wrapping a disk image, recognized by leading magic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveFormat {
    /// PKZIP (`.zip`).
    Zip,
    /// 7-Zip (`.7z`).
    SevenZ,
    /// gzip stream (`.gz` / `.tar.gz`).
    Gzip,
    /// bzip2 stream (`.bz2` / `.tar.bz2`).
    Bzip2,
    /// DAR backup archive (`.dar`).
    Dar,
}

/// Recognize the outer archive format from leading bytes. `None` for a loose
/// (non-archive) file — the caller then opens it directly.
#[must_use]
pub fn detect_archive_format(magic: &[u8]) -> Option<ArchiveFormat> {
    match magic {
        // PKZIP local-file / central-dir / end-of-cd headers.
        [0x50, 0x4B, 0x03, 0x04, ..]
        | [0x50, 0x4B, 0x05, 0x06, ..]
        | [0x50, 0x4B, 0x07, 0x08, ..] => Some(ArchiveFormat::Zip),
        // 7-Zip signature "7z\xBC\xAF\x27\x1C".
        [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C, ..] => Some(ArchiveFormat::SevenZ),
        // gzip member header.
        [0x1F, 0x8B, ..] => Some(ArchiveFormat::Gzip),
        // bzip2 "BZh".
        [0x42, 0x5A, 0x68, ..] => Some(ArchiveFormat::Bzip2),
        // DAR slice magic SAUV_MAGIC_NUMBER = 123, big-endian u32.
        [0x00, 0x00, 0x00, 0x7B, ..] => Some(ArchiveFormat::Dar),
        _ => None,
    }
}

/// Open a disk-image container that lives inside an archive (`zip` today;
/// 7z/tar.gz/tar.bz2/dar next), returning a bounded backing per the adaptive
/// [`decide_backing`] policy. `exts` names the image entry to extract (an entry
/// with a matching extension, else the largest file entry). The chosen
/// determination is logged at `debug` (surfaced under `--verbose`).
///
/// # Errors
/// Not a recognized archive, no matching entry, an unsupported format, a decode
/// failure, or a [`BackingDecision::Refused`] (won't fit temp or RAM).
pub fn archive_backing(
    path: &Path,
    plan: &SpillPlan,
    exts: &[&str],
) -> io::Result<Box<dyn ReadSeekSend>> {
    let mut head = [0u8; 8];
    let n = File::open(path)?.read(&mut head)?;
    match detect_archive_format(&head[..n]) {
        Some(ArchiveFormat::Zip) => zip_backing(path, plan, exts),
        Some(other) => Err(io::Error::other(format!(
            "{}: archive format {other:?} not yet supported",
            path.display()
        ))),
        None => Err(io::Error::other(format!(
            "{}: not a recognized archive",
            path.display()
        ))),
    }
}

/// Back a disk-image entry inside a `.zip`: `Stored` → in-place window, otherwise
/// decompress per [`decide_backing`] into RAM or a temp spill.
fn zip_backing(path: &Path, plan: &SpillPlan, exts: &[&str]) -> io::Result<Box<dyn ReadSeekSend>> {
    let shared = Arc::new(File::open(path)?);
    let mut archive = zip::ZipArchive::new(File::open(path)?).map_err(io::Error::other)?;
    let idx = find_image_entry(&mut archive, exts).ok_or_else(|| {
        io::Error::other(format!(
            "{}: no disk-image entry in archive",
            path.display()
        ))
    })?;
    let mut entry = archive.by_index(idx).map_err(io::Error::other)?;

    let name = entry.name().to_string();
    let in_place = entry.compression() == zip::CompressionMethod::Stored;
    let declared = entry.size();
    let data_start = entry.data_start();

    let temp_dir = storage_backed_temp_dir();
    let temp_free = temp_free_bytes(&temp_dir);
    let decision = decide_backing(declared, in_place, plan, &temp_dir, temp_free);
    tracing::debug!(target: "issen::backing", entry = %name, format = "zip", "{decision}");

    match decision {
        BackingDecision::InPlace => Ok(Box::new(SubRangeReader::new(
            Arc::clone(&shared),
            data_start,
            declared,
        ))),
        BackingDecision::Ram { .. } => {
            // Bounded read: stop one byte past the declared size so a lying
            // header is an error, not an unbounded allocation.
            let mut buf = Vec::with_capacity(usize::try_from(declared).unwrap_or(0));
            entry
                .by_ref()
                .take(declared.saturating_add(1))
                .read_to_end(&mut buf)?;
            if buf.len() as u64 > declared {
                return Err(io::Error::other(format!(
                    "{name}: entry larger than its declared {declared} bytes (possible bomb)"
                )));
            }
            Ok(Box::new(Cursor::new(buf)))
        }
        BackingDecision::Spill { dir, .. } => {
            let spool = spill_from(&mut entry, ram_threshold(plan), declared, &dir)?;
            Ok(Box::new(spool))
        }
        BackingDecision::Refused { .. } => Err(io::Error::other(decision.to_string())),
    }
}

/// Pick the disk-image entry: a file entry whose extension is in `exts`, else the
/// largest file entry (the image dominates the archive).
fn find_image_entry<R: Read + Seek>(
    archive: &mut zip::ZipArchive<R>,
    exts: &[&str],
) -> Option<usize> {
    let mut by_ext: Option<usize> = None;
    let mut largest: Option<(usize, u64)> = None;
    for i in 0..archive.len() {
        let Ok(entry) = archive.by_index(i) else {
            continue;
        };
        if entry.is_dir() {
            continue;
        }
        let size = entry.size();
        if by_ext.is_none() {
            let is_image = Path::new(entry.name())
                .extension()
                .and_then(|e| e.to_str())
                .map(str::to_ascii_lowercase)
                .is_some_and(|e| exts.iter().any(|x| x.eq_ignore_ascii_case(&e)));
            if is_image {
                by_ext = Some(i);
            }
        }
        if largest.is_none_or(|(_, s)| size > s) {
            largest = Some((i, size));
        }
    }
    by_ext.or(largest.map(|(i, _)| i))
}

/// A positioned, read-only window `[base, base + len)` over a shared archive
/// file — lets a container reader sit directly on a `Stored` (uncompressed) zip
/// entry with zero copy. Positioned reads (no `&mut` on the file), so `Send +
/// Sync`. This is the one canonical copy (the per-container duplicates fold into
/// it).
#[derive(Debug)]
pub struct SubRangeReader {
    file: Arc<File>,
    base: u64,
    len: u64,
    pos: u64,
}

impl SubRangeReader {
    /// Window `[base, base + len)` over `file`.
    #[must_use]
    pub fn new(file: Arc<File>, base: u64, len: u64) -> Self {
        Self {
            file,
            base,
            len,
            pos: 0,
        }
    }
}

impl Read for SubRangeReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
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
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new_pos = match pos {
            SeekFrom::Start(n) => n as i64,
            SeekFrom::Current(n) => self.pos as i64 + n,
            SeekFrom::End(n) => self.len as i64 + n,
        };
        if new_pos < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek before start",
            ));
        }
        self.pos = new_pos as u64;
        Ok(self.pos)
    }
}

/// Stream every byte of `src` into a spooled buffer that stays in RAM until it
/// exceeds `ram_threshold` bytes, then rolls over to a disk-backed temp file in
/// `dir`. Returns the buffer seeked to the start. Bounded: `io::copy` streams
/// through a fixed buffer, so RAM never holds the whole decompressed image once
/// it has rolled over. `max_bytes` caps the output (decompression-bomb guard) —
/// exceeding it is an error, not a silent truncation.
///
/// # Errors
/// I/O failure, or `src` produces more than `max_bytes` (possible bomb).
pub fn spill_from<R: Read>(
    src: R,
    ram_threshold: u64,
    max_bytes: u64,
    dir: &Path,
) -> io::Result<SpooledTempFile> {
    let threshold = usize::try_from(ram_threshold).unwrap_or(usize::MAX);
    let mut spool = tempfile::spooled_tempfile_in(threshold, dir);
    // Read at most max_bytes + 1 so an overrun is detectable without consuming
    // the whole (possibly bomb-sized) stream.
    let mut limited = src.take(max_bytes.saturating_add(1));
    let written = io::copy(&mut limited, &mut spool)?;
    if written > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("decompressed output exceeds cap of {max_bytes} bytes (possible bomb)"),
        ));
    }
    spool.seek(SeekFrom::Start(0))?;
    Ok(spool)
}

/// Choose the first writable, **non-tmpfs** directory from `candidates` in order
/// (storage-backed before in-memory), falling back to any writable candidate.
/// Pure: filesystem facts are injected via the predicates, so the
/// prefer-storage-over-RAM logic is testable without real mounts.
fn select_storage_dir(
    candidates: &[PathBuf],
    writable: &dyn Fn(&Path) -> bool,
    is_tmpfs: &dyn Fn(&Path) -> bool,
) -> Option<PathBuf> {
    // Prefer a writable, storage-backed directory in priority order.
    if let Some(d) = candidates
        .iter()
        .find(|c| writable(c) && !is_tmpfs(c))
        .cloned()
    {
        return Some(d);
    }
    // Nothing storage-backed: a writable tmpfs beats failing outright.
    candidates.iter().find(|c| writable(c)).cloned()
}

/// Resolve a disk-backed temp directory for spilling decompressed images,
/// preferring storage-backed mounts over RAM-backed tmpfs — the OS default temp
/// dir is often tmpfs (tempfile's own docs warn of this), and spilling there
/// would silently defeat the bounded-RAM goal. Honors `ISSEN_SPILL_DIR`.
#[must_use]
pub fn storage_backed_temp_dir() -> PathBuf {
    if let Some(d) = std::env::var_os("ISSEN_SPILL_DIR") {
        return PathBuf::from(d);
    }
    let candidates = [
        PathBuf::from("/var/tmp"), // Linux: persistent, disk-backed
        std::env::temp_dir(),      // macOS: disk-backed ($TMPDIR); Linux: often tmpfs
        PathBuf::from("/tmp"),
    ];
    select_storage_dir(&candidates, &dir_is_writable, &dir_is_tmpfs)
        .unwrap_or_else(std::env::temp_dir)
}

/// True if a temp file can actually be created in `dir` right now.
fn dir_is_writable(dir: &Path) -> bool {
    dir.is_dir() && tempfile::Builder::new().tempfile_in(dir).is_ok()
}

/// True if `dir` lives on a RAM-backed filesystem (tmpfs/ramfs). Reads
/// `/proc/mounts` (absent off Linux → `false`, which is correct: macOS/Windows
/// default temp dirs are disk-backed).
fn dir_is_tmpfs(dir: &Path) -> bool {
    // statfs(2) at the moment the spill dir is chosen — the kernel's own answer,
    // authoritative across bind mounts / overlays (unlike parsing /proc/mounts).
    // Off Linux the magics don't match, which is the correct conservative default
    // (macOS/Windows default temp dirs are disk-backed).
    rustix::fs::statfs(dir)
        .map(|s| is_ram_backed_fstype(s.f_type as i64))
        .unwrap_or(false)
}

/// True for a RAM-backed filesystem magic, per the Linux `statfs(2)` man page
/// (`TMPFS_MAGIC` / `RAMFS_MAGIC`). Pure, so the classification is testable
/// without a real mount.
fn is_ram_backed_fstype(f_type: i64) -> bool {
    const TMPFS_MAGIC: i64 = 0x0102_1994;
    const RAMFS_MAGIC: i64 = 0x8584_58f6;
    matches!(f_type, TMPFS_MAGIC | RAMFS_MAGIC)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan(available_ram: u64, concurrency: usize) -> SpillPlan {
        SpillPlan {
            available_ram,
            concurrency,
            env_override: None,
        }
    }

    #[test]
    fn env_override_wins_unclamped() {
        // Override is an explicit operator choice — honored literally, even
        // outside the [floor, ceiling] band, regardless of RAM/concurrency.
        let p = SpillPlan {
            available_ram: 64 * GIB,
            concurrency: 100,
            env_override: Some(5 * GIB),
        };
        assert_eq!(ram_threshold(&p), 5 * GIB);
        let p2 = SpillPlan {
            available_ram: 1 * GIB,
            concurrency: 1,
            env_override: Some(16 * MIB),
        };
        assert_eq!(ram_threshold(&p2), 16 * MIB);
    }

    #[test]
    fn shrinks_as_concurrency_grows() {
        // 8 GiB available: /4 = 2 GiB budget; ÷concurrency lands in-band.
        let four = ram_threshold(&plan(8 * GIB, 4)); // 512 MiB
        let eight = ram_threshold(&plan(8 * GIB, 8)); // 256 MiB
        assert_eq!(four, 512 * MIB);
        assert_eq!(eight, 256 * MIB);
        assert!(eight < four, "more sources → smaller per-image budget");
    }

    #[test]
    fn grows_with_available_ram() {
        let lo = ram_threshold(&plan(2 * GIB, 2)); // 0.25*2G/2 = 256 MiB
        let hi = ram_threshold(&plan(8 * GIB, 2)); // 0.25*8G/2 = 1 GiB (ceiling)
        assert_eq!(lo, 256 * MIB);
        assert_eq!(hi, GIB);
        assert!(hi > lo, "more available RAM → larger per-image budget");
    }

    #[test]
    fn clamps_to_floor_on_scarce_ram() {
        // 1 GiB available, 4 sources: 0.25*1G/4 = 64 MiB exactly; 512 MiB box
        // would compute 32 MiB → clamped up to the 64 MiB floor.
        assert_eq!(ram_threshold(&plan(1 * GIB, 4)), 64 * MIB);
        assert_eq!(ram_threshold(&plan(512 * MIB, 4)), 64 * MIB);
    }

    #[test]
    fn clamps_to_ceiling_on_abundant_ram() {
        // 64 GiB available, single source: 16 GiB budget → capped at 1 GiB.
        assert_eq!(ram_threshold(&plan(64 * GIB, 1)), GIB);
    }

    #[test]
    fn zero_concurrency_treated_as_one() {
        assert_eq!(
            ram_threshold(&plan(8 * GIB, 0)),
            ram_threshold(&plan(8 * GIB, 1))
        );
    }

    fn tmp_file_with(bytes: &[u8]) -> (tempfile::NamedTempFile, Arc<File>) {
        use std::io::Write as _;
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(bytes).unwrap();
        f.flush().unwrap();
        let reopened = Arc::new(f.reopen().unwrap());
        (f, reopened)
    }

    #[test]
    fn sub_range_reads_only_its_window() {
        let data: Vec<u8> = (0u8..=255).collect();
        let (_keep, file) = tmp_file_with(&data);
        let mut sr = SubRangeReader::new(file, 20, 10); // bytes 20..30
        let mut buf = vec![0u8; 16];
        let n = sr.read(&mut buf).unwrap();
        assert_eq!(n, 10, "clamped to window length");
        assert_eq!(&buf[..10], &data[20..30]);
        assert_eq!(sr.read(&mut buf).unwrap(), 0, "EOF at window end");
    }

    #[test]
    fn sub_range_seek_is_window_relative() {
        let data: Vec<u8> = (0u8..=255).collect();
        let (_keep, file) = tmp_file_with(&data);
        let mut sr = SubRangeReader::new(file, 100, 50);
        sr.seek(SeekFrom::Start(5)).unwrap();
        let mut buf = [0u8; 1];
        sr.read(&mut buf).unwrap();
        assert_eq!(buf[0], data[105], "offset 5 in window = byte base+5");
        assert_eq!(sr.seek(SeekFrom::End(0)).unwrap(), 50, "End = window len");
    }

    #[test]
    fn sub_range_is_read_seek_send_sync() {
        fn assert_rss<T: ReadSeekSend>() {}
        assert_rss::<SubRangeReader>();
    }

    #[test]
    fn spill_below_threshold_stays_in_ram() {
        let dir = tempfile::tempdir().unwrap();
        let payload = vec![0xABu8; 100];
        let mut spool = spill_from(&payload[..], 1000, 1 << 20, dir.path()).unwrap();
        assert!(!spool.is_rolled(), "100 B under 1000 B threshold → in RAM");
        let mut got = Vec::new();
        spool.read_to_end(&mut got).unwrap();
        assert_eq!(got, payload);
    }

    #[test]
    fn spill_above_threshold_rolls_to_temp() {
        let dir = tempfile::tempdir().unwrap();
        let payload = vec![0xCDu8; 10_000];
        let mut spool = spill_from(&payload[..], 100, 1 << 20, dir.path()).unwrap();
        assert!(
            spool.is_rolled(),
            "10 kB over 100 B threshold → spilled to disk"
        );
        let mut got = Vec::new();
        spool.read_to_end(&mut got).unwrap();
        assert_eq!(got, payload, "spilled bytes round-trip identically");
    }

    #[test]
    fn spill_rejects_output_over_cap() {
        let dir = tempfile::tempdir().unwrap();
        let payload = vec![0u8; 10_000];
        let result = spill_from(&payload[..], 1 << 20, 100, dir.path());
        assert!(
            result.is_err(),
            "output exceeding max_bytes must error (bomb guard)"
        );
    }

    #[test]
    fn select_storage_dir_prefers_non_tmpfs() {
        let cands = vec![PathBuf::from("/tmp"), PathBuf::from("/var/tmp")];
        let writable = |_: &Path| true;
        let is_tmpfs = |p: &Path| p == Path::new("/tmp");
        assert_eq!(
            select_storage_dir(&cands, &writable, &is_tmpfs),
            Some(PathBuf::from("/var/tmp")),
            "skip the writable-but-tmpfs /tmp for storage-backed /var/tmp"
        );
    }

    #[test]
    fn select_storage_dir_falls_back_to_tmpfs_when_only_option() {
        let cands = vec![PathBuf::from("/tmp")];
        assert_eq!(
            select_storage_dir(&cands, &|_| true, &|_| true),
            Some(PathBuf::from("/tmp")),
            "tmpfs beats failing entirely"
        );
    }

    #[test]
    fn select_storage_dir_none_when_nothing_writable() {
        assert_eq!(
            select_storage_dir(&[PathBuf::from("/nope")], &|_| false, &|_| false),
            None
        );
    }

    #[test]
    fn ram_backed_fstype_matches_tmpfs_and_ramfs_only() {
        assert!(is_ram_backed_fstype(0x0102_1994), "TMPFS_MAGIC");
        assert!(is_ram_backed_fstype(0x8584_58f6), "RAMFS_MAGIC");
        assert!(
            !is_ram_backed_fstype(0xEF53),
            "ext4 (EXT4_SUPER_MAGIC) is disk"
        );
        assert!(!is_ram_backed_fstype(0x5846_5342), "xfs is disk");
        assert!(!is_ram_backed_fstype(0), "unknown/zero is not RAM-backed");
    }

    #[test]
    fn dir_is_tmpfs_does_not_crash_on_a_real_dir() {
        // Exercise the statfs shell against a real temp dir; the value is
        // platform-dependent, but it must not panic.
        let dir = tempfile::tempdir().unwrap();
        let _ = dir_is_tmpfs(dir.path());
    }

    fn rplan(available_ram: u64) -> SpillPlan {
        SpillPlan {
            available_ram,
            concurrency: 1,
            env_override: None,
        }
    }

    #[test]
    fn decide_in_place_ignores_sizes() {
        let d = decide_backing(99 * GIB, true, &rplan(GIB), Path::new("/var/tmp"), 0);
        assert_eq!(d, BackingDecision::InPlace);
    }

    #[test]
    fn decide_small_image_stays_in_ram() {
        // 8 GiB avail → 2 GiB budget → threshold 1 GiB (ceiling). 10 MiB < that.
        let d = decide_backing(10 * MIB, false, &rplan(8 * GIB), Path::new("/var/tmp"), 0);
        assert_eq!(
            d,
            BackingDecision::Ram {
                bytes: 10 * MIB,
                forced_by_low_temp: false
            }
        );
    }

    #[test]
    fn decide_large_image_spills_when_temp_fits() {
        let d = decide_backing(
            40 * GIB,
            false,
            &rplan(8 * GIB),
            Path::new("/scratch"),
            1024 * GIB,
        );
        assert_eq!(
            d,
            BackingDecision::Spill {
                dir: PathBuf::from("/scratch"),
                bytes: 40 * GIB
            }
        );
    }

    #[test]
    fn decide_falls_back_to_ram_when_temp_short_but_ram_fits() {
        // 8 GiB image, temp nearly full, 32 GiB RAM available (image ≤ half).
        let d = decide_backing(8 * GIB, false, &rplan(32 * GIB), Path::new("/var/tmp"), GIB);
        assert_eq!(
            d,
            BackingDecision::Ram {
                bytes: 8 * GIB,
                forced_by_low_temp: true
            }
        );
    }

    #[test]
    fn decide_refuses_when_neither_temp_nor_ram_fits() {
        // 4 TiB image; temp 480 GiB free, 32 GiB RAM — neither suffices.
        let d = decide_backing(
            4096 * GIB,
            false,
            &rplan(32 * GIB),
            Path::new("/var/tmp"),
            480 * GIB,
        );
        assert_eq!(
            d,
            BackingDecision::Refused {
                needed: 4096 * GIB,
                temp_free: 480 * GIB,
                ram_avail: 32 * GIB,
                dir: PathBuf::from("/var/tmp"),
            }
        );
    }

    #[test]
    fn human_formats_binary_units() {
        assert_eq!(human(100), "100 B");
        assert_eq!(human(2048), "2.0 KiB");
        assert_eq!(human(40 * GIB), "40.0 GiB");
    }

    #[test]
    fn parse_size_bare_and_binary_suffixes() {
        assert_eq!(parse_size("1073741824"), Some(GIB));
        assert_eq!(parse_size("512"), Some(512));
        assert_eq!(parse_size("256MiB"), Some(256 * MIB));
        assert_eq!(parse_size("1GiB"), Some(GIB));
        assert_eq!(parse_size("2G"), Some(2 * GIB));
        assert_eq!(parse_size("512K"), Some(512 * 1024));
    }

    #[test]
    fn parse_size_decimal_suffixes_and_fraction() {
        assert_eq!(parse_size("1GB"), Some(1_000_000_000));
        assert_eq!(parse_size("512MB"), Some(512_000_000));
        assert_eq!(parse_size("1.5GiB"), Some(GIB + GIB / 2));
    }

    #[test]
    fn parse_size_is_case_insensitive_and_trims() {
        assert_eq!(parse_size("  1gib "), Some(GIB));
        assert_eq!(parse_size("256mib"), Some(256 * MIB));
    }

    #[test]
    fn parse_size_rejects_garbage() {
        assert_eq!(parse_size(""), None);
        assert_eq!(parse_size("abc"), None);
        assert_eq!(parse_size("10XB"), None);
        assert_eq!(parse_size("-5GiB"), None);
    }

    #[test]
    fn probe_spill_plan_reports_live_resources() {
        // Smoke-test the platform shell on this host: available RAM is positive
        // and a temp dir reports positive free space.
        let plan = probe_spill_plan(2);
        assert!(
            plan.available_ram > 0,
            "available RAM probe must be positive"
        );
        assert_eq!(plan.concurrency, 2);
        let dir = tempfile::tempdir().unwrap();
        assert!(
            temp_free_bytes(dir.path()) > 0,
            "temp free-space probe must be positive on a real dir"
        );
    }

    #[test]
    fn decision_display_is_actionable() {
        assert!(BackingDecision::InPlace.to_string().contains("in place"));
        let spill = BackingDecision::Spill {
            dir: PathBuf::from("/scratch"),
            bytes: 40 * GIB,
        }
        .to_string();
        assert!(spill.contains("/scratch") && spill.contains("40.0 GiB"));
        let refused = BackingDecision::Refused {
            needed: 4096 * GIB,
            temp_free: 480 * GIB,
            ram_avail: 32 * GIB,
            dir: PathBuf::from("/var/tmp"),
        }
        .to_string();
        assert!(refused.contains("ISSEN_SPILL_DIR") && refused.contains("/var/tmp"));
    }

    use std::io::Write as _;

    /// Build a single-entry zip with the given compression method.
    fn make_zip(
        name: &str,
        data: &[u8],
        method: zip::CompressionMethod,
    ) -> tempfile::NamedTempFile {
        make_zip_entries(&[(name, data, method)])
    }

    /// Build a zip from several `(name, data, method)` entries.
    fn make_zip_entries(
        entries: &[(&str, &[u8], zip::CompressionMethod)],
    ) -> tempfile::NamedTempFile {
        use zip::write::SimpleFileOptions;
        let mut cursor = Cursor::new(Vec::<u8>::new());
        {
            let mut zw = zip::ZipWriter::new(&mut cursor);
            for (name, data, method) in entries {
                zw.start_file(
                    *name,
                    SimpleFileOptions::default().compression_method(*method),
                )
                .unwrap();
                zw.write_all(data).unwrap();
            }
            zw.finish().unwrap();
        }
        let mut f = tempfile::Builder::new().suffix(".zip").tempfile().unwrap();
        f.write_all(cursor.get_ref()).unwrap();
        f.flush().unwrap();
        f
    }

    fn read_all(mut r: Box<dyn ReadSeekSend>) -> Vec<u8> {
        let mut v = Vec::new();
        r.read_to_end(&mut v).unwrap();
        v
    }

    fn big_plan(env_override: Option<u64>) -> SpillPlan {
        SpillPlan {
            available_ram: 8 * GIB,
            concurrency: 1,
            env_override,
        }
    }

    #[test]
    fn detect_format_by_magic() {
        assert_eq!(
            detect_archive_format(&[0x50, 0x4B, 0x03, 0x04]),
            Some(ArchiveFormat::Zip)
        );
        assert_eq!(
            detect_archive_format(&[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]),
            Some(ArchiveFormat::SevenZ)
        );
        assert_eq!(
            detect_archive_format(&[0x1F, 0x8B, 0x08]),
            Some(ArchiveFormat::Gzip)
        );
        assert_eq!(detect_archive_format(b"BZh9"), Some(ArchiveFormat::Bzip2));
        assert_eq!(
            detect_archive_format(&[0x00, 0x00, 0x00, 0x7B]),
            Some(ArchiveFormat::Dar)
        );
        assert_eq!(detect_archive_format(b"not an archive"), None);
        assert_eq!(detect_archive_format(&[]), None);
    }

    /// Oracle: regardless of the path chosen (in-place / RAM / spill), the bytes
    /// read back equal the original — proving probe→decide→build is lossless.
    #[test]
    fn archive_backing_zip_stored_reads_in_place() {
        let payload: Vec<u8> = (0u8..=255).cycle().take(4096).collect();
        let zip = make_zip("disk.img", &payload, zip::CompressionMethod::Stored);
        let backing = archive_backing(zip.path(), &big_plan(None), &["img"]).unwrap();
        assert_eq!(read_all(backing), payload);
    }

    #[test]
    fn archive_backing_zip_deflated_small_uses_ram() {
        let payload = vec![0xABu8; 4096];
        let zip = make_zip("disk.img", &payload, zip::CompressionMethod::Deflated);
        let backing = archive_backing(zip.path(), &big_plan(None), &["img"]).unwrap();
        assert_eq!(read_all(backing), payload);
    }

    #[test]
    fn archive_backing_zip_deflated_spills_over_threshold() {
        let payload = vec![0xCDu8; 8192];
        let zip = make_zip("disk.img", &payload, zip::CompressionMethod::Deflated);
        // Force the spill path: a 1 KiB override threshold < the 8 KiB entry.
        let backing = archive_backing(zip.path(), &big_plan(Some(1024)), &["img"]).unwrap();
        assert_eq!(read_all(backing), payload);
    }

    #[test]
    fn archive_backing_picks_entry_by_extension() {
        let img = vec![0x42u8; 2048];
        let zip = make_zip_entries(&[
            ("readme.txt", b"ignore me", zip::CompressionMethod::Stored),
            ("disk.img", &img, zip::CompressionMethod::Stored),
        ]);
        let backing = archive_backing(zip.path(), &big_plan(None), &["img"]).unwrap();
        assert_eq!(read_all(backing), img);
    }

    #[test]
    fn archive_backing_rejects_non_archive() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(&[0u8; 100]).unwrap();
        f.flush().unwrap();
        assert!(archive_backing(f.path(), &big_plan(None), &["img"]).is_err());
    }
}
