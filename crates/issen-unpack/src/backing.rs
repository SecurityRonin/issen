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

/// How many materializing sources may run concurrently within `budget` bytes,
/// capped at `requested` — the admission governor that degrades a multi-source
/// ingest from full parallel toward serial when the temp volume (or RAM) can't
/// hold every concurrent spill at once.
///
/// `sizes` are the declared materialization sizes (0 = read in place, no budget
/// draw). The worst case for `k` concurrent is the `k` largest running together,
/// so the result is the largest `k` whose top-`k` sum fits `budget`. A source
/// larger than the whole budget can't materialize at all (handled per-item by
/// [`decide_backing`]) and is excluded here. Returns `requested` when nothing
/// materializes, and at least 1 once any single source fits.
#[must_use]
pub fn admit_concurrency(sizes: &[u64], budget: u64, requested: usize) -> usize {
    // Only sources that materialize (size > 0) AND fit the budget individually
    // participate; an item larger than the whole budget can't spill at all and is
    // left to the per-item Refused / RAM-fallback path.
    let mut materializing: Vec<u64> = sizes
        .iter()
        .copied()
        .filter(|&s| s > 0 && s <= budget)
        .collect();
    if materializing.is_empty() {
        // Nothing materializes (or nothing fits the budget) → no spill pressure;
        // the in-place / per-item-handled sources run at the requested width.
        return requested;
    }
    materializing.sort_unstable_by(|a, b| b.cmp(a)); // largest first
    let mut sum = 0u64;
    let mut k = 0;
    for &size in materializing.iter().take(requested) {
        let next = sum.saturating_add(size);
        if next > budget {
            break;
        }
        sum = next;
        k += 1;
    }
    k.max(1)
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
        Some(ArchiveFormat::SevenZ) => first_entry(sevenz_entries(path, plan, exts)?, path, exts),
        Some(ArchiveFormat::Gzip) => first_entry(targz_entries(path, plan, exts)?, path, exts),
        Some(ArchiveFormat::Bzip2) => first_entry(bzip2_entries(plan, path, exts)?, path, exts),
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
    let mut archive = zip_core::ZipArchive::new(File::open(path)?).map_err(io::Error::other)?;
    let idx = find_image_entry(&mut archive, exts).ok_or_else(|| {
        io::Error::other(format!(
            "{}: no disk-image entry in archive",
            path.display()
        ))
    })?;
    let mut entry = archive.by_index(idx).map_err(io::Error::other)?;

    let name = entry.name().to_string();
    let in_place = entry.compression() == zip_core::CompressionMethod::Stored;
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
    archive: &mut zip_core::ZipArchive<R>,
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

// ── Multi-entry collection + the compressed formats (7z / tar.gz / tar.bz2) ──

/// Collect EVERY archive entry whose extension is in `exts` as an independent
/// bounded backing — the shared "N backings from a zip" step for multi-file
/// images (ewf `.E01`/`.E02`… segments, split-vmdk extents). Returns
/// `(name, backing)` pairs in archive order; the caller assembles them
/// (ewf concatenates ordered segments; vmdk resolves the descriptor's extents).
///
/// Each entry is decided independently: zip-`Stored` is an in-place window, while
/// the codec-wrapped formats (7z solid LZMA, tar.gz, tar.bz2) always materialize
/// through the adaptive RAM/temp spill.
///
/// # Errors
/// Not a recognized archive, an unsupported format, or a decode/spill failure.
pub fn archive_entries(
    path: &Path,
    plan: &SpillPlan,
    exts: &[&str],
) -> io::Result<Vec<(String, Box<dyn ReadSeekSend>)>> {
    let mut head = [0u8; 8];
    let n = File::open(path)?.read(&mut head)?;
    match detect_archive_format(&head[..n]) {
        Some(ArchiveFormat::Zip) => zip_entries(path, plan, exts),
        Some(ArchiveFormat::SevenZ) => sevenz_entries(path, plan, exts),
        Some(ArchiveFormat::Gzip) => targz_entries(path, plan, exts),
        Some(ArchiveFormat::Bzip2) => bzip2_entries(plan, path, exts),
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

/// Single-image pick from a collected set: the first matching entry, else a loud
/// "no entry" error (never a silent empty backing).
fn first_entry(
    entries: Vec<(String, Box<dyn ReadSeekSend>)>,
    path: &Path,
    exts: &[&str],
) -> io::Result<Box<dyn ReadSeekSend>> {
    entries.into_iter().next().map(|(_, b)| b).ok_or_else(|| {
        io::Error::other(format!("{}: no {exts:?} entry in archive", path.display()))
    })
}

/// True if `name`'s extension is in `exts` (case-insensitive).
fn ext_matches(name: &str, exts: &[&str]) -> bool {
    Path::new(name)
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase)
        .is_some_and(|e| exts.iter().any(|x| x.eq_ignore_ascii_case(&e)))
}

/// Build a backing for one entry given its decision. `reader` supplies the
/// positioned/decompressed bytes for the RAM and Spill paths; `InPlace` ignores
/// it and windows directly over the shared archive file.
fn build_decided_backing(
    decision: BackingDecision,
    shared: &Arc<File>,
    data_start: u64,
    declared: u64,
    plan: &SpillPlan,
    name: &str,
    reader: &mut dyn Read,
) -> io::Result<Box<dyn ReadSeekSend>> {
    match decision {
        BackingDecision::InPlace => Ok(Box::new(SubRangeReader::new(
            Arc::clone(shared),
            data_start,
            declared,
        ))),
        BackingDecision::Ram { .. } => {
            let mut buf = Vec::with_capacity(usize::try_from(declared).unwrap_or(0));
            reader
                .take(declared.saturating_add(1))
                .read_to_end(&mut buf)?;
            if buf.len() as u64 > declared {
                return Err(io::Error::other(format!(
                    "{name}: entry larger than its declared {declared} bytes (possible bomb)"
                )));
            }
            Ok(Box::new(Cursor::new(buf)))
        }
        BackingDecision::Spill { dir, .. } => Ok(Box::new(spill_from(
            reader,
            ram_threshold(plan),
            declared,
            &dir,
        )?)),
        BackingDecision::Refused { .. } => Err(io::Error::other(decision.to_string())),
    }
}

/// Materialize one seek-blind decompressed entry into a spooled backing: RAM
/// under the threshold, rolling to a temp file past it; bomb-capped. Used by the
/// codec-wrapped formats (7z solid, tar.gz, tar.bz2) that cannot window in place.
/// `declared == 0` means the codec did not expose the size (whole-stream gz/bz2).
fn spill_entry(
    reader: &mut dyn Read,
    plan: &SpillPlan,
    declared: u64,
    temp_dir: &Path,
    temp_free: u64,
    name: &str,
    fmt: &str,
) -> io::Result<Box<dyn ReadSeekSend>> {
    let threshold = ram_threshold(plan);
    // A known-size entry that fits neither a safe share of RAM nor the temp
    // volume is refused loudly — never a silent truncation.
    if declared > threshold && declared > temp_free {
        return Err(io::Error::other(format!(
            "{name}: {declared} bytes fit neither the {threshold}-byte RAM threshold \
             nor {temp_free} bytes of temp at {}",
            temp_dir.display()
        )));
    }
    // Cap: the known size, or — when the codec hides it — the most we can hold
    // (RAM threshold for a small stream, else the temp free space).
    let cap = if declared > 0 {
        declared
    } else {
        threshold.max(temp_free)
    };
    tracing::debug!(target: "issen::backing", entry = %name, format = fmt, declared, "spill (compressed)");
    Ok(Box::new(spill_from(reader, threshold, cap, temp_dir)?))
}

/// Read up to `buf.len()` bytes, returning how many were filled (short only at EOF).
fn read_up_to(r: &mut impl Read, buf: &mut [u8]) -> io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..])? {
            0 => break,
            k => n += k,
        }
    }
    Ok(n)
}

/// Decode a tar stream — or a single bare-compressed image — into bounded
/// backings. Peeks for the tar `ustar` magic at offset 257; absent it, the
/// decompressed stream is itself a single image (e.g. `disk.raw.gz`) and is
/// returned as one entry. Tar members are materialized per [`spill_entry`].
fn tar_entries_from<R: Read>(
    mut decoded: R,
    plan: &SpillPlan,
    exts: &[&str],
    temp_dir: &Path,
    temp_free: u64,
    fmt: &str,
) -> io::Result<Vec<(String, Box<dyn ReadSeekSend>)>> {
    let mut head = vec![0u8; 512];
    let got = read_up_to(&mut decoded, &mut head)?;
    head.truncate(got);
    let is_tar = head.get(257..262) == Some(b"ustar".as_slice());
    let mut chained = Cursor::new(head).chain(decoded);
    if !is_tar {
        let name = format!("<{fmt}-stream>");
        let b = spill_entry(&mut chained, plan, 0, temp_dir, temp_free, &name, fmt)?;
        return Ok(vec![(name, b)]);
    }
    let mut archive = tar::Archive::new(chained);
    let mut out: Vec<(String, Box<dyn ReadSeekSend>)> = Vec::new();
    for entry in archive.entries()? {
        let mut entry = entry?;
        let name = entry.path()?.to_string_lossy().into_owned();
        if entry.header().entry_type().is_dir() || !ext_matches(&name, exts) {
            continue;
        }
        let size = entry.size();
        let b = spill_entry(&mut entry, plan, size, temp_dir, temp_free, &name, fmt)?;
        out.push((name, b));
    }
    Ok(out)
}

fn zip_entries(
    path: &Path,
    plan: &SpillPlan,
    exts: &[&str],
) -> io::Result<Vec<(String, Box<dyn ReadSeekSend>)>> {
    let shared = Arc::new(File::open(path)?);
    let mut archive = zip_core::ZipArchive::new(File::open(path)?).map_err(io::Error::other)?;
    let temp_dir = storage_backed_temp_dir();
    let temp_free = temp_free_bytes(&temp_dir);
    let mut out: Vec<(String, Box<dyn ReadSeekSend>)> = Vec::new();
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i).map_err(io::Error::other)?;
        if entry.is_dir() || !ext_matches(entry.name(), exts) {
            continue;
        }
        let name = entry.name().to_string();
        let in_place = entry.compression() == zip_core::CompressionMethod::Stored;
        let declared = entry.size();
        let data_start = entry.data_start();
        let decision = decide_backing(declared, in_place, plan, &temp_dir, temp_free);
        tracing::debug!(target: "issen::backing", entry = %name, format = "zip", "{decision}");
        let backing = build_decided_backing(
            decision, &shared, data_start, declared, plan, &name, &mut entry,
        )?;
        out.push((name, backing));
    }
    Ok(out)
}

/// Eligible for the non-solid selective path: every file is its own LZMA stream
/// (so `read_file` decodes just that file, skipping the rest) AND each matching
/// file fits a RAM buffer (`read_file` returns a `Vec`, no spill). A solid
/// archive or an oversized member falls back to stream-once + spill.
fn sevenz_selective_eligible(is_solid: bool, sizes: &[u64], threshold: u64) -> bool {
    !is_solid && sizes.iter().all(|&s| s <= threshold)
}

fn sevenz_entries(
    path: &Path,
    plan: &SpillPlan,
    exts: &[&str],
) -> io::Result<Vec<(String, Box<dyn ReadSeekSend>)>> {
    let temp_dir = storage_backed_temp_dir();
    let temp_free = temp_free_bytes(&temp_dir);
    let mut reader =
        sevenz_rust2::ArchiveReader::new(File::open(path)?, sevenz_rust2::Password::empty())
            .map_err(|e| io::Error::other(format!("{}: 7z: {e}", path.display())))?;

    // Decide the path from metadata alone (no decode yet): a non-solid archive
    // whose matching members each fit RAM can decode just those files.
    let is_solid = reader.archive().is_solid;
    let matching: Vec<(String, u64)> = reader
        .archive()
        .files
        .iter()
        .filter(|f| f.has_stream() && !f.is_directory() && ext_matches(f.name(), exts))
        .map(|f| (f.name().to_string(), f.size()))
        .collect();
    let sizes: Vec<u64> = matching.iter().map(|&(_, s)| s).collect();

    if sevenz_selective_eligible(is_solid, &sizes, ram_threshold(plan)) {
        let mut out: Vec<(String, Box<dyn ReadSeekSend>)> = Vec::new();
        for (name, _) in matching {
            // read_file on a non-solid archive seeks straight to this file's
            // block and decodes only it — the other files are never inflated.
            let bytes = reader
                .read_file(&name)
                .map_err(|e| io::Error::other(format!("{}: 7z: {e}", path.display())))?;
            tracing::debug!(target: "issen::backing", entry = %name, format = "7z", solid = false, "selective file");
            out.push((name, Box::new(Cursor::new(bytes))));
        }
        return Ok(out);
    }

    // Solid, or an oversized member: stream every entry once, spilling matches.
    sevenz_entries_streaming(&mut reader, plan, exts, &temp_dir, temp_free, path)
}

/// Stream a 7z once: every entry's reader is drained (a solid block is one
/// continuous stream), and matching entries are spilled to a bounded backing.
fn sevenz_entries_streaming(
    reader: &mut sevenz_rust2::ArchiveReader<File>,
    plan: &SpillPlan,
    exts: &[&str],
    temp_dir: &Path,
    temp_free: u64,
    path: &Path,
) -> io::Result<Vec<(String, Box<dyn ReadSeekSend>)>> {
    let mut out: Vec<(String, Box<dyn ReadSeekSend>)> = Vec::new();
    let mut captured: Option<io::Error> = None;
    reader
        .for_each_entries(|entry, rdr| {
            if entry.is_directory() || !ext_matches(entry.name(), exts) {
                io::copy(rdr, &mut io::sink())?;
                return Ok(true);
            }
            let name = entry.name().to_string();
            match spill_entry(rdr, plan, entry.size(), temp_dir, temp_free, &name, "7z") {
                Ok(b) => {
                    out.push((name, b));
                    Ok(true)
                }
                Err(e) => {
                    captured = Some(e);
                    Ok(false)
                }
            }
        })
        .map_err(|e| io::Error::other(format!("{}: 7z: {e}", path.display())))?;
    if let Some(e) = captured {
        return Err(e);
    }
    Ok(out)
}

fn targz_entries(
    path: &Path,
    plan: &SpillPlan,
    exts: &[&str],
) -> io::Result<Vec<(String, Box<dyn ReadSeekSend>)>> {
    let temp_dir = storage_backed_temp_dir();
    let temp_free = temp_free_bytes(&temp_dir);
    let decoded = flate2::read::GzDecoder::new(File::open(path)?);
    tar_entries_from(decoded, plan, exts, &temp_dir, temp_free, "tar.gz")
}

/// bzip2 is the one stream codec with a random-access unit (its independent
/// ~900 KB blocks), so it gets the *selective* path instead of a full spill: a
/// `.tar.bz2` member is a `RangeView` over a shared seekable reader (only the
/// covering blocks inflate), and a bare `.bz2` image is one such view over the
/// whole stream. See `docs/selective-decompression-triage.md`.
fn bzip2_entries(
    _plan: &SpillPlan,
    path: &Path,
    exts: &[&str],
) -> io::Result<Vec<(String, Box<dyn ReadSeekSend>)>> {
    let reader = Arc::new(crate::bzseek::Bzip2SeekReader::open(Box::new(File::open(
        path,
    )?))?);
    // A tar.bz2 carries the ustar magic at offset 257 of the decompressed stream;
    // a bare compressed image does not.
    let mut magic = [0u8; 5];
    let is_tar = reader.read_at(257, &mut magic)? == 5 && &magic == b"ustar";
    if !is_tar {
        // The whole decompressed stream is the image; one selective view over it.
        let total = reader.len();
        return Ok(vec![(
            "<bz2-stream>".to_string(),
            Box::new(crate::bzseek::RangeView::new(reader, 0, total)),
        )]);
    }
    let mut out: Vec<(String, Box<dyn ReadSeekSend>)> = Vec::new();
    for (name, off, size) in crate::bzseek::tar_members(&reader)? {
        if !ext_matches(&name, exts) {
            continue;
        }
        tracing::debug!(target: "issen::backing", entry = %name, format = "tar.bz2", off, size, "selective member");
        out.push((
            name,
            Box::new(crate::bzseek::RangeView::new(
                Arc::clone(&reader),
                off,
                size,
            )),
        ));
    }
    Ok(out)
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
            available_ram: GIB,
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
        assert_eq!(ram_threshold(&plan(GIB, 4)), 64 * MIB);
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
        sr.read_exact(&mut buf).unwrap();
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

    #[test]
    fn admit_full_parallel_when_nothing_materializes() {
        // All sources read in place (size 0) → no budget pressure → full parallel.
        assert_eq!(admit_concurrency(&[0, 0, 0], 8 * GIB, 4), 4);
        assert_eq!(admit_concurrency(&[], 8 * GIB, 4), 4);
    }

    #[test]
    fn admit_full_parallel_when_all_fit() {
        // Two 2 GiB spills into 8 GiB → both fit; capped at the 2 sources.
        assert_eq!(admit_concurrency(&[2 * GIB, 2 * GIB], 8 * GIB, 4), 2);
    }

    #[test]
    fn admit_serializes_when_sum_exceeds() {
        // Three 5 GiB spills, 8 GiB budget: one fits, two together don't → serial.
        assert_eq!(
            admit_concurrency(&[5 * GIB, 5 * GIB, 5 * GIB], 8 * GIB, 3),
            1
        );
    }

    #[test]
    fn admit_partial_parallel() {
        // Three 3 GiB spills, 8 GiB: top-2 = 6 GiB fits, top-3 = 9 GiB doesn't → 2.
        assert_eq!(
            admit_concurrency(&[3 * GIB, 3 * GIB, 3 * GIB], 8 * GIB, 3),
            2
        );
    }

    #[test]
    fn admit_excludes_oversize_source() {
        // A 10 GiB spill can't fit 8 GiB at all (per-item Refused); the 2 GiB one
        // still runs serially.
        assert_eq!(admit_concurrency(&[10 * GIB, 2 * GIB], 8 * GIB, 4), 1);
    }

    #[test]
    fn admit_respects_requested_cap() {
        // Plenty of budget, but only one worker allowed.
        assert_eq!(admit_concurrency(&[GIB, GIB, GIB], 64 * GIB, 1), 1);
    }

    // ── Multi-entry + compressed-format fixtures (all pure-Rust) ──────────

    /// A recognizable byte pattern of `len` bytes.
    fn pattern(len: usize) -> Vec<u8> {
        (0u8..=255).cycle().take(len).collect()
    }

    fn write_named(suffix: &str, bytes: &[u8]) -> tempfile::NamedTempFile {
        let mut f = tempfile::Builder::new().suffix(suffix).tempfile().unwrap();
        f.write_all(bytes).unwrap();
        f.flush().unwrap();
        f
    }

    /// Build an uncompressed tar from `(name, data)` entries.
    fn tar_bytes(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut buf = Vec::new();
        {
            let mut tb = tar::Builder::new(&mut buf);
            for (name, data) in entries {
                let mut h = tar::Header::new_gnu();
                h.set_size(data.len() as u64);
                h.set_mode(0o644);
                tb.append_data(&mut h, name, *data).unwrap();
            }
            tb.finish().unwrap();
        }
        buf
    }

    fn make_7z(entries: &[(&str, &[u8])]) -> tempfile::NamedTempFile {
        let mut buf = Vec::new();
        {
            let mut w = sevenz_rust2::ArchiveWriter::new(Cursor::new(&mut buf)).unwrap();
            for (name, data) in entries {
                w.push_archive_entry(sevenz_rust2::ArchiveEntry::new_file(name), Some(*data))
                    .unwrap();
            }
            w.finish().unwrap();
        }
        write_named(".7z", &buf)
    }

    fn make_targz(entries: &[(&str, &[u8])]) -> tempfile::NamedTempFile {
        let tar = tar_bytes(entries);
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(&tar).unwrap();
        write_named(".tar.gz", &gz.finish().unwrap())
    }

    fn make_bare_gz(suffix: &str, data: &[u8]) -> tempfile::NamedTempFile {
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(data).unwrap();
        write_named(suffix, &gz.finish().unwrap())
    }

    fn make_tarbz2(entries: &[(&str, &[u8])]) -> tempfile::NamedTempFile {
        let tar = tar_bytes(entries);
        let mut bz = Vec::new();
        banzai::encode(Cursor::new(&tar), std::io::BufWriter::new(&mut bz), 9).unwrap();
        write_named(".tar.bz2", &bz)
    }

    fn make_bare_bz2(suffix: &str, data: &[u8]) -> tempfile::NamedTempFile {
        let mut bz = Vec::new();
        banzai::encode(Cursor::new(data), std::io::BufWriter::new(&mut bz), 9).unwrap();
        write_named(suffix, &bz)
    }

    /// Read every `(name, backing)` pair to bytes, sorted by name for stability.
    fn collect_named(got: Vec<(String, Box<dyn ReadSeekSend>)>) -> Vec<(String, Vec<u8>)> {
        let mut v: Vec<(String, Vec<u8>)> =
            got.into_iter().map(|(n, b)| (n, read_all(b))).collect();
        v.sort_by(|x, y| x.0.cmp(&y.0));
        v
    }

    // ── archive_entries: the shared "N backings from a zip" step ──────────

    #[test]
    fn archive_entries_zip_collects_matching_in_order() {
        let a = pattern(100);
        let b = pattern(200);
        let zip = make_zip_entries(&[
            ("img.E01", &a, zip::CompressionMethod::Stored),
            ("notes.txt", b"ignore me", zip::CompressionMethod::Stored),
            ("img.E02", &b, zip::CompressionMethod::Deflated),
        ]);
        let got =
            collect_named(archive_entries(zip.path(), &big_plan(None), &["e01", "e02"]).unwrap());
        assert_eq!(got.len(), 2, "two segments collected, the .txt skipped");
        assert!(got[0].0.ends_with(".E01"));
        assert_eq!(got[0].1, a);
        assert!(got[1].0.ends_with(".E02"));
        assert_eq!(got[1].1, b);
    }

    // ── 7z (solid LZMA) ───────────────────────────────────────────────────

    #[test]
    fn archive_backing_sevenz_roundtrip() {
        let p = pattern(4096);
        let z = make_7z(&[("disk.img", &p)]);
        assert_eq!(
            read_all(archive_backing(z.path(), &big_plan(None), &["img"]).unwrap()),
            p
        );
    }

    #[test]
    fn archive_entries_sevenz_multi() {
        let a = pattern(300);
        let b = pattern(700);
        let z = make_7z(&[("img.E01", &a), ("readme", b"x"), ("img.E02", &b)]);
        let got =
            collect_named(archive_entries(z.path(), &big_plan(None), &["e01", "e02"]).unwrap());
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].1, a);
        assert_eq!(got[1].1, b);
    }

    // ── tar.gz / bare .gz ─────────────────────────────────────────────────

    #[test]
    fn archive_backing_targz_roundtrip() {
        let p = pattern(5000);
        let t = make_targz(&[("disk.dd", &p)]);
        assert_eq!(
            read_all(archive_backing(t.path(), &big_plan(None), &["dd"]).unwrap()),
            p
        );
    }

    #[test]
    fn archive_backing_bare_gz_roundtrip() {
        // A single gzipped image (no tar wrapper): the decoded stream IS the image.
        let p = pattern(5000);
        let g = make_bare_gz(".dd.gz", &p);
        assert_eq!(
            read_all(archive_backing(g.path(), &big_plan(None), &["dd"]).unwrap()),
            p
        );
    }

    // ── tar.bz2 / bare .bz2 (pure-Rust bzip2-rs decode) ───────────────────

    #[test]
    fn archive_backing_tarbz2_roundtrip() {
        let p = pattern(5000);
        let t = make_tarbz2(&[("disk.dd", &p)]);
        assert_eq!(
            read_all(archive_backing(t.path(), &big_plan(None), &["dd"]).unwrap()),
            p
        );
    }

    #[test]
    fn sevenz_selective_eligible_rules() {
        let t = 64 * MIB;
        assert!(
            sevenz_selective_eligible(false, &[1000, 2000], t),
            "non-solid + small members → selective read_file"
        );
        assert!(
            !sevenz_selective_eligible(true, &[1000], t),
            "solid → must stream the whole block"
        );
        assert!(
            !sevenz_selective_eligible(false, &[t + 1], t),
            "oversized member → stream + spill, not a RAM read_file"
        );
        assert!(
            sevenz_selective_eligible(false, &[], t),
            "no matching members → vacuously eligible (empty result)"
        );
    }

    #[test]
    fn sevenz_nonsolid_selective_reads_matching() {
        // make_7z uses push_archive_entry per file → non-solid.
        let a = pattern(4096);
        let b = pattern(8192);
        let z = make_7z(&[("img.E01", &a), ("readme.txt", b"skip"), ("img.E02", &b)]);
        let got =
            collect_named(archive_entries(z.path(), &big_plan(None), &["e01", "e02"]).unwrap());
        assert_eq!(got.len(), 2, "two segments, the .txt skipped");
        assert_eq!(got[0].1, a);
        assert_eq!(got[1].1, b);
    }

    #[test]
    fn sevenz_streaming_fallback_when_member_oversized() {
        // A 1-byte RAM threshold makes every member oversized → the streaming +
        // spill path, which must still return identical bytes.
        let a = pattern(4096);
        let z = make_7z(&[("disk.img", &a)]);
        let tiny = big_plan(Some(1));
        let got = collect_named(archive_entries(z.path(), &tiny, &["img"]).unwrap());
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].1, a);
    }

    #[test]
    fn archive_entries_tarbz2_selective_members() {
        // Multi-member .tar.bz2 → each matching member is a selective RangeView
        // over a shared seekable reader; the .txt is skipped.
        let a = pattern(120_000);
        let b = pattern(90_000);
        let t = make_tarbz2(&[("disk.E01", &a), ("notes.txt", b"skip"), ("disk.E02", &b)]);
        let got =
            collect_named(archive_entries(t.path(), &big_plan(None), &["e01", "e02"]).unwrap());
        assert_eq!(got.len(), 2, "two image segments, the .txt skipped");
        assert_eq!(got[0].1, a);
        assert_eq!(got[1].1, b);
    }

    #[test]
    fn archive_backing_bare_bz2_roundtrip() {
        let p = pattern(5000);
        let z = make_bare_bz2(".dd.bz2", &p);
        assert_eq!(
            read_all(archive_backing(z.path(), &big_plan(None), &["dd"]).unwrap()),
            p
        );
    }

    #[test]
    fn archive_entries_unrecognized_errors() {
        let f = write_named(".bin", b"not an archive at all");
        assert!(archive_entries(f.path(), &big_plan(None), &["dd"]).is_err());
    }
}
