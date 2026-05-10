# usnjrnl-forensic Architecture Patterns for winreg-forensic

Analysis of `/Users/4n6h4x0r/src/usnjrnl-forensic/` (v0.6.0) to extract replicable patterns.

## 1. Crate Structure

**Single crate** (not a workspace). One `lib.rs` + one `main.rs` binary.

```
src/
  lib.rs                    # Public API surface (13 pub mod declarations)
  main.rs                   # CLI binary (~800 lines, orchestrates everything)
  usn/
    mod.rs                  # Re-exports: UsnRecord, UsnReason, FileAttributes, etc.
    record.rs               # Binary parsing: parse_usn_record_v2(), parse_usn_record_v3()
    reader.rs               # UsnJournalReader<R: Read + Seek> — streaming iterator
    reason.rs               # bitflags! UsnReason (24 flags)
    attributes.rs           # bitflags! FileAttributes (17 flags)
    carver.rs               # carve_usn_records() — unallocated space recovery
    parallel.rs             # parse_usn_journal_parallel() — rayon chunked parsing
  mft/
    mod.rs                  # MftData, MftEntry structs, parse_mft(), detect_timestomping()
    carver.rs               # MFT entry carving from unallocated space
  rewind/
    mod.rs                  # RewindEngine, ResolvedRecord, EntryKey, RecordSource enum
  output/
    mod.rs                  # Re-exports all output submodules
    csv_output.rs           # export_csv<W: Write>()
    json_output.rs          # export_jsonl<W: Write>()
    body_output.rs          # export_body<W: Write>() — Sleuthkit bodyfile
    tln_output.rs           # export_tln<W: Write>() — 5-field TLN format
    xml_output.rs           # export_xml<W: Write>()
    sqlite_output.rs        # export_sqlite() — rusqlite with WAL + batch transactions
    stats.rs                # format_reason_stats(), write_reason_stats()
    report.rs               # HTML triage report generation
  analysis/
    mod.rs                  # detect_secure_deletion(), detect_ransomware(), detect_timestomping()
  rules/
    mod.rs                  # Rule, RuleSet, RuleMatch, Severity, FilenameMatch (Glob/Regex/Extension)
  triage/
    mod.rs                  # TriageQuestion, TriageQuery, TriageResult, run_triage()
    queries.rs              # builtin_questions() — 12 IR triage questions
  correlation/
    mod.rs                  # GhostRecord, QuadLink correlation engine
  logfile/
    mod.rs                  # parse_logfile(), RestartArea, LogFileSummary
    usn_extractor.rs        # Extract USN records embedded in $LogFile RCRD pages
  mftmirr/
    mod.rs                  # MFTMirr integrity check (byte-level comparison)
  image/
    mod.rs                  # E01/raw disk image opening, NTFS partition discovery
    unallocated.rs          # Unallocated space scanning
  monitor/
    mod.rs                  # JournalSource trait, JournalMonitor, MonitorEvent
    windows.rs              # Windows-specific live journal monitoring
  refs/
    mod.rs                  # ReFS journal support (separate filesystem)
```

**Key pattern**: Each domain concept gets its own module directory with a `mod.rs` that contains the primary types and logic plus submodules for specialized functionality. The `mod.rs` files re-export everything needed by consumers.

## 2. Public API Design

### lib.rs (v0.6.0)

```rust
pub mod analysis;
pub mod correlation;
pub mod image;
pub mod logfile;
pub mod mft;
pub mod mftmirr;
pub mod monitor;
pub mod output;
pub mod refs;
pub mod rewind;
pub mod rules;
pub mod triage;
pub mod usn;
```

**Every module is `pub`** — the library exposes everything. No `prelude` module. Consumers navigate the module tree directly:

```rust
use usnjrnl_forensic::usn::{UsnRecord, UsnReason, FileAttributes};
use usnjrnl_forensic::rewind::{RewindEngine, ResolvedRecord, RecordSource};
use usnjrnl_forensic::mft::{MftData, MftEntry};
use usnjrnl_forensic::output::csv_output::export_csv;
use usnjrnl_forensic::triage::{queries::builtin_questions, run_triage};
```

### Core types

**Raw record** (parsing layer):

```rust
pub struct UsnRecord {
    pub mft_entry: u64,
    pub mft_sequence: u16,
    pub parent_mft_entry: u64,
    pub parent_mft_sequence: u16,
    pub usn: i64,
    pub timestamp: DateTime<Utc>,
    pub reason: UsnReason,         // bitflags
    pub filename: String,
    pub file_attributes: FileAttributes,  // bitflags
    pub source_info: u32,
    pub security_id: u32,
    pub major_version: u16,
}
```

**Resolved record** (enrichment layer):

```rust
pub struct ResolvedRecord {
    pub record: UsnRecord,        // Wraps the raw record
    pub full_path: String,        // e.g. ".\Users\admin\temp\malware.exe"
    pub parent_path: String,      // e.g. ".\Users\admin\temp"
    pub source: RecordSource,     // Allocated | Carved | Ghost
}
```

**Pattern**: Raw parsing produces `UsnRecord`. Resolution/enrichment wraps it in `ResolvedRecord` which adds derived fields. Output formatters consume `&[ResolvedRecord]`.

## 3. Parsing Approach

### Binary parsing — manual, no nom/binrw

All binary parsing is done with manual `from_le_bytes` helper functions:

```rust
fn read_u16_le(data: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([data[offset], data[offset + 1]])
}

fn read_u32_le(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([data[offset], data[offset+1], data[offset+2], data[offset+3]])
}

fn read_i64_le(data: &[u8], offset: usize) -> i64 { /* ... */ }
```

**Parsing functions** take `&[u8]` slices and return `Result<UsnRecord>`:

```rust
pub fn parse_usn_record_v2(data: &[u8]) -> Result<UsnRecord> { /* ... */ }
pub fn parse_usn_record_v3(data: &[u8]) -> Result<UsnRecord> { /* ... */ }
pub fn parse_usn_journal(data: &[u8]) -> Result<Vec<UsnRecord>> { /* ... */ }
```

**Constants** define minimum record sizes and sanity bounds:

```rust
const USN_V2_MIN_SIZE: usize = 0x3C;  // 60 bytes
const USN_V3_MIN_SIZE: usize = 0x4C;  // 76 bytes
const USN_V4_MIN_SIZE: usize = 0x38;  // 56 bytes
const USN_MAX_RECORD_SIZE: usize = 65536;
```

### Streaming (64KB buffered reader)

`UsnJournalReader<R: Read + Seek>` implements `Iterator<Item = Result<UsnRecord>>`:

```rust
pub struct UsnJournalReader<R: Read + Seek> {
    reader: R,
    buf: Vec<u8>,       // 64KB read buffer
    buf_len: usize,
    buf_offset: usize,
    stream_pos: u64,
    total_size: u64,
    done: bool,
}
```

- Reads in 64KB chunks
- Moves unconsumed data to front of buffer on refill
- Skips zero-filled regions (sparse journal pages) in 8-byte increments
- Dispatches to V2/V3 parsers based on version field at offset+4
- On parse error, calls `self.next()` to skip and continue

### UTF-16LE filename decoding

```rust
let u16_chars: Vec<u16> = name_bytes
    .chunks_exact(2)
    .map(|c| u16::from_le_bytes([c[0], c[1]]))
    .collect();
String::from_utf16_lossy(&u16_chars)
```

### Windows FILETIME to DateTime conversion

```rust
fn filetime_to_datetime(filetime: i64) -> Option<DateTime<Utc>> {
    const EPOCH_DIFF: i64 = 116_444_736_000_000_000;
    let unix_100ns = filetime - EPOCH_DIFF;
    if unix_100ns < 0 { return None; }
    let secs = unix_100ns / 10_000_000;
    let nanos = ((unix_100ns % 10_000_000) * 100) as u32;
    DateTime::from_timestamp(secs, nanos)
}
```

## 4. Error Handling

**`anyhow` only** — no `thiserror`, no custom error enum. All functions return `anyhow::Result<T>`. The `bail!` macro is used for early returns. Parser functions use `bail!` for invalid data.

```rust
use anyhow::{bail, Result};

pub fn parse_usn_record_v2(data: &[u8]) -> Result<UsnRecord> {
    if data.len() < USN_V2_MIN_SIZE {
        bail!("V2 record too short: {} bytes", data.len());
    }
    // ...
}
```

**`log::debug!`** is used extensively for skipped/invalid records — never panics on bad data, just logs and continues.

## 5. Output Formatting

### Pattern: `export_*<W: Write>(records: &[ResolvedRecord], writer: &mut W) -> Result<()>`

All output formatters share the same signature pattern — generic over `Write` for testability:

**CSV** (`csv_output.rs`):
```rust
pub fn export_csv<W: Write>(records: &[ResolvedRecord], writer: &mut W) -> Result<()> {
    let mut wtr = csv::Writer::from_writer(writer);
    wtr.write_record(["UpdateTimestamp", "UpdateSequenceNumber", /* ... 14 columns */])?;
    for resolved in records {
        wtr.write_record([/* field conversions */])?;
    }
    wtr.flush()?;
    Ok(())
}
```

**JSONL** (`json_output.rs`):
```rust
#[derive(Serialize)]
struct JsonRecord { /* all fields as strings/primitives */ }

pub fn export_jsonl<W: Write>(records: &[ResolvedRecord], writer: &mut W) -> Result<()> {
    for resolved in records {
        let json_rec = JsonRecord { /* map fields */ };
        serde_json::to_writer(&mut *writer, &json_rec)?;
        writeln!(writer)?;
    }
    Ok(())
}
```

**Bodyfile** (`body_output.rs`):
```rust
pub fn export_body<W: Write>(records: &[ResolvedRecord], writer: &mut W) -> Result<()> {
    for resolved in records {
        writeln!(writer, "0|{}|{}|0|0|0|0|{}|{}|{}|{}", /* ... */)?;
    }
    Ok(())
}
```

**SQLite** (`sqlite_output.rs`) — different pattern, takes a path:
```rust
pub fn export_sqlite(
    path: &std::path::Path,
    usn_records: &[ResolvedRecord],
    mft_entries: Option<&[MftEntry]>,
) -> Result<()> {
    let conn = Connection::open(path)?;
    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")?;
    conn.execute_batch("BEGIN TRANSACTION")?;
    // ... batch inserts ...
    conn.execute_batch("COMMIT")?;
    // Create indexes after bulk insert
}
```

**Key patterns**:
- All output functions consume `&[ResolvedRecord]` (the enriched type, not raw)
- CSV headers are MFTECmd-compatible for interoperability
- Extension is derived at output time: `filename.rsplit('.').next().filter(|ext| ext.len() < filename.len())`
- Timestamps formatted as RFC 3339 with nanosecond precision
- SQLite uses WAL mode, batch transactions, and post-insert indexing

## 6. CLI Interface

**clap v4 with derive macros** — flat struct, no subcommands:

```rust
#[derive(Parser)]
#[command(
    name = "usnjrnl-forensic",
    about = "NTFS USN Journal parser with full path reconstruction via journal rewind",
    long_about = "...",
    version
)]
struct Cli {
    // Input sources
    #[arg(short = 'j', long)]
    journal: PathBuf,                    // Required: path to $UsnJrnl:$J

    #[arg(short = 'm', long)]
    mft: Option<PathBuf>,                // Optional: $MFT for path resolution

    #[arg(long)]
    mftmirr: Option<PathBuf>,           // Optional: $MFTMirr for integrity

    #[arg(long)]
    logfile: Option<PathBuf>,           // Optional: $LogFile for correlation

    #[arg(short = 'i', long)]
    image: Option<PathBuf>,             // Optional: E01/raw disk image

    // Output destinations (all optional, multiple allowed)
    #[arg(long)]
    csv: Option<PathBuf>,
    #[arg(long)]
    jsonl: Option<PathBuf>,
    #[arg(long)]
    sqlite: Option<PathBuf>,
    #[arg(long)]
    body: Option<PathBuf>,
    #[arg(long)]
    tln: Option<PathBuf>,
    #[arg(long)]
    xml: Option<PathBuf>,
    #[arg(long)]
    report: Option<PathBuf>,            // HTML triage report

    // Analysis flags
    #[arg(long)]
    detect_timestomping: bool,
    #[arg(long, default_value_t = true)]
    stats: bool,
}
```

**main() pipeline** (pseudocode):
1. Parse CLI args
2. If `--image`: extract artifacts from disk image to temp dir
3. Parse USN journal (streaming or parallel)
4. Optionally parse $MFT -> `MftData`
5. Seed `RewindEngine` from MFT
6. Run Rewind algorithm -> `Vec<ResolvedRecord>`
7. Optionally perform carving -> merge carved records
8. Optionally run correlation (LogFile, MFTMirr)
9. Run analysis detectors (SDelete, ransomware, timestomping)
10. Run triage questions
11. Export to each requested output format
12. Print stats

## 7. Testing Strategy

**483 tests total**. Test structure:

### Unit tests (inline `#[cfg(test)] mod tests`)

Every module has inline tests. Pattern:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn make_record(filename: &str, reason: UsnReason) -> UsnRecord {
        UsnRecord {
            mft_entry: 1,
            mft_sequence: 1,
            parent_mft_entry: 5,
            parent_mft_sequence: 1,
            usn: 0,
            timestamp: DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
            reason,
            filename: filename.to_string(),
            file_attributes: FileAttributes::from_bits_retain(0x20),
            source_info: 0,
            security_id: 0,
            major_version: 2,
        }
    }
}
```

**Every module has a `make_record()` helper** that constructs test data with sensible defaults.

### Integration tests (`tests/` directory)

```
tests/
  image_integration.rs      # E01 parsing end-to-end (requires `image` feature)
  precision_recall.rs        # Triage accuracy against ground truth (CTF image)
  report_integration.rs      # Full pipeline: resolved records -> triage -> HTML report
```

**Key testing patterns**:
- Binary parsers tested with hand-crafted byte arrays (`to_le_bytes`)
- Output formatters tested with `Vec<u8>` as the `Write` sink, then `String::from_utf8`
- Bodyfile tests verify exact pipe-delimited field counts and positions
- CSV tests verify header presence and field values
- Carver tests verify validation (timestamp sanity, structure checks, dedup)
- Reader tests use `std::io::Cursor` to simulate streaming
- Integration tests build synthetic `ResolvedRecord` vectors (no disk images needed)
- Ground-truth integration test (`precision_recall.rs`) runs against real CTF forensic image

### Test data construction for binary parsers

```rust
fn build_v2_record_bytes(entry: u64, seq: u16, parent: u64, parent_seq: u16, reason: u32, name: &str) -> Vec<u8> {
    let name_utf16: Vec<u16> = name.encode_utf16().collect();
    let name_bytes_len = name_utf16.len() * 2;
    // ... manually construct byte array matching USN_RECORD_V2 layout
}
```

## 8. Performance

- **rayon** for parallel journal parsing: `parse_usn_journal_parallel()` splits data into chunks, parses each on a worker, merges results sorted by USN offset
- **64KB buffered I/O** in `UsnJournalReader` (manual ring-buffer style, not `BufReader`)
- **No memory-mapped files** — uses standard `Read + Seek`
- **8-byte aligned scanning** for carving (USN records are always 8-byte aligned)
- **HashMap lookups** for the Rewind engine (O(1) path resolution)
- **Batch SQLite transactions** with `BEGIN TRANSACTION` / `COMMIT` and post-insert indexing
- **SQLite WAL mode** for write performance
- **4MB overlapping chunks** for unallocated space scanning

## 9. Feature Gates

```toml
[features]
default = []
image = ["ewf", "ntfs"]
```

Only one feature: `image` — gates disk image support (E01 via `ewf` crate, NTFS traversal via `ntfs` crate). Without it, the tool only works with pre-extracted artifact files.

The `image` module uses `#[cfg(feature = "image")]` guards. When disabled, `extract_artifacts_from_image()` returns an error message telling users to rebuild with `--features image`.

## 10. Dependency Choices

| Crate | Version | Purpose |
|-------|---------|---------|
| `anyhow` | 1 | Error handling (no custom error types) |
| `bitflags` | 2 | `UsnReason`, `FileAttributes` flag types |
| `chrono` | 0.4 | Timestamps with serde support (`features = ["serde"]`) |
| `clap` | 4 | CLI argument parsing (`features = ["derive"]`) |
| `csv` | 1 | CSV output writing |
| `env_logger` | 0.11 | Logging initialization |
| `log` | 0.4 | Logging facade |
| `mft` | 0.6 | MFT entry parsing (third-party crate) |
| `rayon` | 1.10 | Parallel processing |
| `regex` | 1 | Rule engine pattern matching, triage queries |
| `rusqlite` | 0.32 | SQLite output (`features = ["bundled"]`) |
| `serde` | 1 | Serialization (`features = ["derive"]`) |
| `serde_json` | 1 | JSONL output |
| `tempfile` | 3 | Temp directories for image extraction |
| `ewf` | 0.1 | E01 disk image reading (optional) |
| `ntfs` | 0.4 | NTFS filesystem traversal (optional) |

## 11. Raw vs. Resolved Data Pattern

This is the most important architectural pattern for `winreg-forensic`:

### Layer 1: Raw parsing

- `usn::UsnRecord` — direct binary parse, no enrichment
- `mft::MftEntry` — direct MFT parse with SI/FN timestamps
- Functions: `parse_usn_record_v2()`, `parse_usn_journal()`, `UsnJournalReader`

### Layer 2: Resolution/Enrichment

- `rewind::ResolvedRecord` wraps `UsnRecord` + adds `full_path`, `parent_path`, `source`
- `RewindEngine` performs the enrichment (path resolution via lookup table)
- `MftData.seed_rewind()` creates the engine from MFT state

### Layer 3: Analysis (layered on resolved data)

- `analysis` module: `detect_secure_deletion()`, `detect_ransomware()`, `detect_timestomping()`
- `rules` module: `RuleSet::evaluate()` matches patterns against records
- `triage` module: `run_triage()` evaluates forensic questions against resolved records
- `correlation` module: cross-references LogFile ghost records with resolved records

### Layer 4: Output

- All output formatters consume `&[ResolvedRecord]` (never raw records)
- Stats module consumes `&[UsnRecord]` (raw, for aggregate counting)

**Mapping to winreg-forensic**:
- Layer 1: Raw hive parsing (cells, keys, values, data types)
- Layer 2: Resolved/enriched registry entries (full key paths, decoded values, timestamps)
- Layer 3: Analysis (persistence detection, malware indicators, anomalies)
- Layer 4: Output (CSV, JSONL, SQLite, bodyfile, etc.)

## 12. Conventions Summary

1. **Module naming**: `mod.rs` for primary types + logic, submodules for specializations
2. **Re-exports**: `mod.rs` uses `pub use` to flatten commonly-needed types
3. **Private helpers**: Internal parsing helpers (`read_u16_le`, etc.) are module-private
4. **Validation**: Constants for min/max sizes, timestamp sanity ranges (2000-2030)
5. **Graceful degradation**: `log::debug!` on bad data, skip and continue (never panic)
6. **Display impls**: `bitflags` types have `Display` via `iter_names().join("|")`
7. **Test helpers**: `make_record()` in every test module with sensible defaults
8. **Output generics**: `<W: Write>` for testability (real file or `Vec<u8>`)
9. **CLI**: Flat clap struct, all outputs optional, multiple simultaneous outputs
10. **No serde on core types**: `UsnRecord` is not `Serialize` — only output-specific structs derive it
11. **Documentation**: Module-level `//!` doc comments explaining purpose and approach
12. **Section separators**: Unicode box-drawing comments (`// ═══`, `// ───`) to divide code sections
