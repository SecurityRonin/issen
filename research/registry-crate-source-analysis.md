# Windows Registry Forensic Parser: Deep Source Code Analysis

Comprehensive analysis of all major Windows registry parsing implementations to inform the architecture of `winreg-forensic` — a best-in-class Rust forensic registry parser.

---

## Table of Contents

1. [Notatin (Stroz Friedberg / LevelBlue)](#1-notatin)
2. [nt-hive2 (dfir-dd / Jan Starke)](#2-nt-hive2)
3. [regf (peitaosu)](#3-regf-crate)
4. [dfir-toolkit Registry Tools](#4-dfir-toolkit)
5. [yarp (Maxim Suhanov)](#5-yarp)
6. [python-registry (Willi Ballenthin)](#6-python-registry)
7. [libregf (libyal / Joachim Metz)](#7-libregf)
8. [RegRipper (Harlan Carvey)](#8-regripper)
9. [Eric Zimmerman's Registry Explorer / RECmd](#9-eric-zimmerman)
10. [Cross-Crate Comparison Matrix](#10-comparison-matrix)
11. [What to Steal / Improve / Replace](#11-design-recommendations)

---

## 1. Notatin

**Repository:** https://github.com/strozfriedberg/notatin
**Version:** 1.0.1 | **License:** Apache-2.0 | **Stars:** 41 | **Commits:** 513
**Authors:** Kimberly Stone, Joel Uckelman (Stroz Friedberg / LevelBlue)

### Architecture & Module Structure

Notatin uses a flat module structure with clear separation of concerns. The crate is organized into:

```
src/
├── lib.rs                    # Public API exports (~40 modules)
├── parser.rs                 # Core Parser struct (42KB) - main traversal engine
├── parser_builder.rs         # Builder pattern for Parser construction
├── parser_recover_deleted.rs # Deleted key/value recovery
├── base_block.rs             # REGF file header parsing
├── cell.rs                   # Cell state/type enums (CellState, CellType)
├── cell_key_node.rs          # NK cell parsing (51KB - largest file)
├── cell_key_value.rs         # VK cell parsing (35KB)
├── cell_key_security.rs      # SK cell parsing
├── cell_big_data.rs          # DB cell parsing (>16KB values)
├── cell_value.rs             # Value decode logic (CellValue enum)
├── hive_bin_header.rs        # Hive bin header parsing
├── sub_key_list_lf.rs        # Fast leaf subkey list
├── sub_key_list_lh.rs        # Hash leaf subkey list
├── sub_key_list_li.rs        # Index leaf subkey list
├── sub_key_list_ri.rs        # Index root subkey list
├── filter.rs                 # Regex/literal path filtering
├── transaction_log.rs        # Transaction log replay (26KB)
├── state.rs                  # Mutable parser state (deleted/modified maps)
├── field_offset_len.rs       # Field tracking with file offsets
├── field_serializers.rs      # Serde serialization helpers
├── file_info.rs              # File I/O abstraction (ReadSeek trait)
├── log.rs                    # Warning/log message system
├── marvin32.rs               # Marvin32 hash for log validation
├── err.rs                    # Error types (thiserror)
├── reg_item_map.rs           # Registry item mapping
├── progress.rs               # Console progress updates
├── util.rs                   # Utility functions
├── cli_util.rs               # CLI helper functions
└── macros.rs                 # Internal macros
```

**Key Architectural Decisions:**
- Entire hive loaded into memory as `Vec<u8>` buffer (`FileInfo.buffer`)
- All parsing uses `nom` combinators operating on byte slices
- Cell offsets are absolute file offsets, not relative to hive bins data
- State is mutable and tracks deleted/modified items via HashMaps
- Uses extensive macro system (`make_file_offset_structs!`, `make_field_struct!`) for DRY struct definitions with optional offset tracking

### API Design Patterns

**Builder Pattern (ParserBuilder):**
```rust
// Two builder variants: path-based and reader-based
ParserBuilder::from_path("system")
    .with_transaction_log("system.log1")
    .with_transaction_log("system.log2")
    .recover_deleted(true)
    .get_full_field_info(true)   // track byte offsets per field
    .build()?;
```

The builder has two concrete types:
- `ParserBuilderFromPath` — opens files by path
- `ParserBuilderFromFile` — accepts `ReadSeek` trait objects
- Both share `ParserBuilderBase` for common options

**Iterator Pattern:**
```rust
for key in parser.iter() {           // prefix order (default)
    for value in key.value_iter() {  // lazy value iteration
        value.get_content();         // decode on demand
    }
}
parser.iter_postorder();             // children before parents
```

- `ParserIterator` implements `Iterator<Item = CellKeyNode>`
- Traversal is lazy — nodes parsed on demand during iteration
- Filter evaluation short-circuits to skip non-matching subtrees

**Filter System:**
```rust
FilterBuilder::new()
    .add_literal_segment("Control Panel")
    .add_regex_segment("access.*")
    .return_child_keys(false)
    .build();
```

- Filters are per-path-segment (not whole-path regex)
- Supports mixed literal + regex segments
- `FilterFlags` bitflags control iteration: `FILTER_ITERATE_KEYS`, `FILTER_RETURN_KEY`
- `FilterMatchState`: `None`, `Descendent`, `Exact`

### Cell Parsing Approach

All cells are parsed with `nom` combinators from raw byte slices:

**Cell State Model:**
```rust
enum CellState {
    DeletedTransactionLog = -3,     // Deleted, found in transaction log
    DeletedPrimaryFile = -2,        // Deleted, found in primary file free space
    DeletedPrimaryFileSlack = -1,   // Deleted, found in cell slack
    Allocated = 0,                   // Normal allocated cell
    ModifiedTransactionLog = 1,      // Modified version from transaction log
}
```

**Cell Type Detection:**
```rust
enum CellType {
    CellOther, CellKey, CellValue, CellSecurity, CellBigData,
    CellIndexRoot, CellHashLeaf, CellFastLeaf, CellIndexLeaf,
}
// Detected by reading 2-byte signature: "nk", "vk", "sk", "db", "lf", "lh", "li", "ri"
```

**Key Node (NK) Parsing (cell_key_node.rs):**
- Full field-by-field parsing with `nom` (`le_u32`, `le_u16`, `tag`, `take`)
- 18+ fields parsed: flags, timestamp, parent offset, subkey count, value count, etc.
- Optional field offset tracking via `FieldFull` vs `FieldLight` (controlled by `get_full_field_info`)
- Macro-generated struct with conditional compilation for offset tracking
- Subkey lists parsed lazily when accessed via offset chasing

**Key Value (VK) Parsing (cell_key_value.rs):**
- Supports all standard types: `REG_NONE` through `REG_QWORD`
- Also supports `REG_FILETIME` (0x0010)
- Full support for **UWP/AppContainer composite types** (0x0101-0x011F): `REG_COMPOSITE_UINT8` through `REG_COMPOSITE_UNICODE_STRING_ARRAY`
- Inline data detection: MSB of data_size indicates data stored in offset field directly (<=4 bytes)
- Big data support for values >16344 bytes via `CellBigData`

**Value Decode Formats:**
```rust
enum DecodeFormat {
    Lznt1,           // LZNT1 compression (used in some values)
    Rot13,           // ROT13 encoding (e.g., UserAssist)
    Utf16,           // UTF-16LE string decode
    Utf16Multiple,   // Multiple UTF-16LE strings (REG_MULTI_SZ)
}
```

### Error Handling

Uses `thiserror` with a flat enum:
```rust
enum Error {
    Nom { detail: String },        // nom parsing errors (detail lost!)
    Winstructs { detail: String },  // Security descriptor parsing
    Conversion { detail: String },  // Type conversion
    StripPrefix { detail: String },
    Io { detail: String },          // I/O errors (detail stringified!)
    XlsxWriter { detail: String },  // Optional xlsx feature
    TryFromInt { detail: String },
    Buffer { detail: String },      // Out-of-bounds buffer access
    Any { detail: String },         // Catch-all
}
```

**Weakness:** All errors are converted to string representations, losing the original error types. The `From<io::Error>` impl calls `format!("{:#?}", error.to_string())` which is redundant and loses structured error info. The `From<nom::Err>` impl discards all nom error context.

### Transaction Log Handling

**Comprehensive implementation** supporting both old and new formats:
- Old format: Dirty vector bitmap (512-byte pages)
- New format: `HvLE` log entries with dirty page references and Marvin32 hash validation
- Transaction log entries stored as `Vec<LogEntry>` with sequence numbers
- Log replay applies dirty pages to an in-memory copy of the hive buffer
- Validates hashes (Hash-1 and Hash-2) using Marvin32 seeded with `0x82EF4D887A4E55C5`
- Multiple log files supported (`.LOG1`, `.LOG2`) with sequence number ordering
- Tracks modified keys/values from log replay in `State.modified_*` maps
- Modified items are tagged with `CellState::ModifiedTransactionLog`

### Deleted Key Recovery

**`ParserRecoverDeleted` (parser_recover_deleted.rs):**
1. Scans all hive bins looking for free (unallocated) cells
2. For each free cell, checks the 2-byte signature after the cell size
3. If signature is "nk" or "vk", attempts to parse as key/value
4. Parsed items stored in `State.deleted_keys_map` and `State.deleted_values_map`
5. During iteration, deleted items are interleaved with allocated items
6. Recovery states: `DeletedPrimaryFile` (free cell), `DeletedPrimaryFileSlack` (slack space after allocated cell data)

**Recovery from transaction logs:**
- Compares current hive state to prior states found in log entries
- Keys that exist in log but not in current hive tagged as `DeletedTransactionLog`
- Modified values tracked by comparing blake3 hashes

**Content hashing:**
- Uses `blake3` to hash key/value content for deduplication
- Prevents duplicate items when same content appears in both primary and log files

### Performance Characteristics

- **Memory model:** Entire hive loaded into memory (fast random access, high memory usage)
- **Benchmarks included** (criterion): Tests `read_small_reg` and `read_small_reg_with_deleted`
- **Parsing approach:** `nom` zero-copy combinators on byte slices (fast)
- **No mmap support:** Uses `read_to_end()` into `Vec<u8>`
- **Allocation heavy:** Many `String` and `Vec` allocations during parsing
- **Filter optimization:** Filters skip parsing non-matching subtrees entirely

### Forensic Features: Supported vs Missing

**Supported:**
- Transaction log replay (old + new format) with hash validation
- Deleted key/value recovery from free cells and slack space
- Modified key/value tracking from transaction logs
- Cell state tracking (allocated, deleted, modified)
- Full field offset information for hex editor correlation
- Security descriptor parsing (via `winstructs` crate)
- Big data (>16KB values)
- All standard + UWP composite data types
- JSONL, XLSX, TSV, Common export formats
- Registry comparison (regshot-like diff)
- Regex-based key path filtering
- Blake3 content hashing
- Python bindings (pynotatin)

**Missing:**
- No hive carving from disk/memory images
- No timeline (bodyfile) output
- No artifact interpretation (ShellBags, UserAssist decode, etc.)
- No partial/truncated hive support
- No streaming/zero-copy parsing (requires full hive in memory)
- No parallel processing
- No hive writing/modification
- Pre-release warning: "should not be used for active investigations"
- No FUSE/virtual filesystem mount support

### Code Quality & Tests

- 100% safe Rust (no `unsafe`)
- 513 commits, CI/CD pipeline
- Test data included in repo
- Criterion benchmarks
- Extensive use of `serde` for serialization
- Macro-heavy code reduces boilerplate but increases learning curve
- Some very large files (cell_key_node.rs: 51KB, parser.rs: 42KB)

### Dependencies

```
nom 8.0          # Parser combinators
thiserror 2.0    # Error derive
serde 1.0        # Serialization
serde_json 1.0   # JSON output
chrono >=0.4.27  # Timestamps
bitflags 2.3     # Flag bitfields
blake3 1.8       # Content hashing
md5 0.8          # Legacy hash
winstructs 0.3   # Security descriptor parsing
regex 1.5        # Filter regex
enum-primitive-derive 0.3  # Enum from integer
num / num-traits
paste 1.0        # Macro helpers
strum_macros     # Enum to string
crossterm 0.29   # Terminal output
```

---

## 2. nt-hive2

**Repository:** https://github.com/dfir-dd/nt-hive2
**Version:** 4.2.3 | **License:** GPL-3.0 | **Stars:** 7 | **Commits:** 157
**Author:** Jan Starke (dfir-dd)
**Status:** Archived (July 2025) — moved off GitHub

### Architecture & Module Structure

```
src/
├── lib.rs              # Public API exports
├── hive/               # Hive module (directory-based)
│   ├── mod.rs          # Hive struct, Read/Seek impls, transaction log application
│   ├── base_block.rs   # HiveBaseBlock parsing
│   ├── file_type.rs    # FileType enum
│   ├── hive_bin_iterator.rs  # Iterator over hive bins
│   ├── hive_parse_mode.rs    # Raw, Normal, NormalWithBaseBlock
│   ├── hive_status.rs  # CleanHive / DirtyHive type states
│   ├── hive_with_logs.rs     # HiveWithLogs wrapper
│   └── offset.rs       # Offset newtype (u32 wrapper)
├── hivebin.rs          # HiveBin parsing
├── cell.rs             # Generic Cell<T, A> with CellHeader
├── nk.rs               # KeyNode parsing (BinRead derive)
├── vk.rs               # KeyValue parsing (BinRead derive)
├── db.rs               # BigData parsing
├── subkeys_list.rs     # All subkey list types (lf, lh, li, ri)
├── cell_with_u8_list.rs  # Raw byte list cells
├── transactionlog/     # Transaction log module
│   ├── mod.rs          # TransactionLog struct
│   ├── transactionlogsentry.rs
│   ├── dirty_pages.rs
│   └── application_result.rs
└── util.rs             # Timestamp and string parsing
```

### Key Architectural Decisions

**BinRead-based parsing:** The most distinctive feature. Uses the `binread` crate's derive macros to declaratively define binary struct layouts:

```rust
#[derive_binread]
#[derive(Debug)]
pub struct KeyNode {
    #[br(parse_with=parse_node_flags)]
    pub(crate) flags: KeyNodeFlags,

    #[br(parse_with=parse_timestamp)]
    timestamp: DateTime<Utc>,

    access_bits: u32,
    pub parent: Offset,
    subkey_count: u32,

    #[br(temp)]
    volatile_subkey_count: u32,  // parsed then discarded

    subkeys_list_offset: Offset,

    #[br(if(key_values_count > 0),
          deref_now,
          restore_position,
          args(key_values_count as usize))]
    key_values_list: Option<FilePtr32<KeyValueList>>,
    // ... eagerly loads values using FilePtr32 seeking
}
```

**Advantages of BinRead approach:**
- Declarative parsing — struct layout IS the parser
- `#[br(temp)]` discards fields after parsing (saves memory)
- `FilePtr32` follows offset pointers automatically
- `#[br(magic = b"nk")]` validates signatures
- `#[br(assert(...))]` adds validation inline
- Less code than manual nom parsing

**Disadvantages:**
- Less control over error recovery
- Can't easily implement custom backtracking
- `binread 2.2` is older (newer `binrw` is the maintained fork)
- Eager value loading via `FilePtr32` — may load more than needed

**MemOverlay for transaction logs:**
- Uses custom `memoverlay` crate to overlay dirty pages on the hive data
- Clean separation: `Hive<B, CleanHive>` vs `Hive<B, DirtyHive>` type states
- Transaction log application creates a new hive with overlaid pages
- Type-state pattern ensures you can't accidentally use a dirty hive without applying logs

**Offset newtype:**
```rust
pub struct Offset(pub u32);
```
Prevents mixing up raw integers and hive offsets.

### API Design

```rust
let hive_file = File::open("tests/data/testhive")?;
let mut hive = Hive::new(hive_file, HiveParseMode::NormalWithBaseBlock)?;
let root_key = hive.root_key_node()?;

for sk in root_key.subkeys(&mut hive)?.iter() {
    println!("{}: {}", sk.borrow().name(), sk.borrow().timestamp());
    for value in sk.borrow().values() {
        println!("  {} = {}", value.name(), value.value());
    }
}
```

**Key differences from notatin:**
- `Hive` implements `Read + Seek` — acts as a reader with offset translation
- Subkeys accessed by passing `&mut hive` (hive is the reader context)
- Values stored in `Rc<RefCell<>>` for shared ownership
- No iterator-over-all-keys pattern — manual traversal required
- `HiveParseMode::Raw` allows parsing without base block (for carving)

### Cell Parsing

**Generic Cell:**
```rust
struct Cell<T: BinRead<Args = A>, A> {
    header: CellHeader,
    data: T,
}
```
CellHeader reads the i32 size, determines allocation status (positive = deleted), and validates 8-byte alignment.

**Tombstone detection** in key values:
```rust
const IS_TOMBSTONE = 0x0002;  // Windows 10 RS1+ feature
```

**Inline data handling** with discriminated union:
```rust
enum OffsetOrData {
    U32Data(u32),    // MSB set, 3-4 bytes
    U16Data(u16, u16),  // MSB set, 2 bytes
    U8Data(u8, u8, u8, u8),  // MSB set, 1 byte
    None(u32),       // MSB set, 0 bytes
    Offset(Offset),  // MSB clear, follow pointer
}
```

### Error Handling

Uses `anyhow` for ad-hoc errors and `thiserror` for typed errors:
- `anyhow::Result` in many places (loses error type info)
- `BinResult` from binread for parsing errors
- Less granular than notatin's error types

### Transaction Log Handling

- `TransactionLog` struct parsed via BinRead
- `TransactionLogsEntry` contains sequence number and dirty pages
- Application creates a `MemOverlay` from dirty page data
- Type-state transition: `Hive<_, DirtyHive>` → `Hive<_, CleanHive>`
- Reads log entries in a loop until EOF or parse error

### Forensic Features

**Supported:**
- Transaction log replay (new format)
- Deleted cell detection (via CellHeader.is_deleted())
- Tombstone value detection (Windows 10 RS1+)
- Timestamps on all keys
- Security descriptors (via winstructs)
- Big data support

**Missing:**
- No deleted key/value recovery scanning (only detects existing deleted cells)
- No old-format transaction log support
- No export formats (JSONL, etc.)
- No filter system
- No modified value tracking from logs
- No content hashing
- No Python bindings
- No hive carving
- Archived project (no further development)

### Dependencies

```
binread 2.2       # Declarative binary parsing (outdated; binrw is successor)
binwrite 0.2      # Binary writing
memoverlay >=0.1.3  # Memory overlay for log application
bitflags 1.3      # Flag bitfields
encoding_rs 0.8   # Character encoding
chrono 0.4        # Timestamps
winstructs 0.3    # Security descriptors
anyhow 1.0        # Error handling
thiserror 1.0     # Error derive
log 0.4           # Logging
marvin32 0.1.0    # Hash validation
derive-getters, getset, num-traits, num-derive, byteorder
```

---

## 3. regf Crate

**Repository:** https://github.com/peitaosu/regf
**Version:** 0.1.0 | **License:** MIT | **Stars:** 0 | **Downloads:** ~416
**Author:** Tony Su

### Architecture

```
src/
├── lib.rs              # Public API re-exports
├── parser.rs           # HiveParser with cell reading
├── hive.rs             # RegistryHive high-level API
├── structures.rs       # All binary structures (not found as single file — likely directory)
├── error.rs            # Error types
├── reg_export.rs       # .reg text export
├── reg_import.rs       # .reg text import
├── writer.rs           # Hive writing (HiveBuilder)
├── transaction_log.rs  # Transaction log support
└── (structures/)       # KeyNode, KeyValue, BaseBlock, etc.
```

### Key Features

This is the only Rust crate that supports **both reading AND writing** registry hives:

```rust
// Read
let hive = RegistryHive::from_file("NTUSER.DAT")?;
let key = hive.open_key("Software\\Microsoft\\Windows")?;

// Write
let mut builder = HiveBuilder::new();
let root = builder.root_offset();
let software = builder.add_key(root, "Software")?;
builder.add_value(app, "Version", DataType::Dword, &1u32.to_le_bytes())?;
builder.write_to_file("output.dat")?;

// Import/Export
reg_file_to_hive_file("input.reg", "output.dat")?;
```

### Parsing Approach

- Uses `byteorder` for manual byte-level parsing (no nom, no binread)
- `HiveParser` reads full hive into memory, parses all bins upfront
- Cell offsets resolved by binary searching the bin list
- Supports versions 1.3-1.6 (Windows NT 4.0 through Windows 11)
- Does NOT support versions 1.1-1.2 (NT 3.1/3.5)

### Error Handling

Well-structured `thiserror` enum with specific variants:
```rust
enum Error {
    Io(io::Error),
    InvalidSignature { expected, found },
    ChecksumMismatch { expected, calculated },
    SequenceMismatch { primary, secondary },  // dirty hive detection
    InvalidCellOffset(u32),
    InvalidCellSize(i32),
    UnallocatedCell(u32),
    UnknownCellType([u8; 2]),
    InvalidHiveBin { offset, message },
    KeyNotFound(String),
    ValueNotFound(String),
    InvalidUtf16String,
    InvalidDataType(u32),
    DataTooLarge { size, max },
    BufferTooSmall { needed, available },
    UnsupportedVersion { major, minor },
    CorruptHive(String),
    InvalidPath(String),
}
```

**Best error design of all Rust crates** — specific, structured, and informative.

### Forensic Features

**Supported:**
- Basic read/navigate registry keys and values
- Standard data types (REG_SZ through REG_QWORD, REG_MULTI_SZ)
- .reg format import/export
- Hive creation from scratch
- Transaction log support (declared in lib.rs)

**Missing:**
- No deleted key recovery
- No transaction log replay (structure exists but unclear if functional)
- No filter system
- No composite/UWP data types
- No big data support (unclear)
- No security descriptor parsing
- No hive carving
- No Python bindings
- Very early (0.1.0), only 6 commits, 0 stars

### Assessment

The `regf` crate is notable for its **writing capability** and **clean error handling**, but it's extremely immature. It's essentially a proof-of-concept. The reg import/export is genuinely useful and could be borrowed. The error design is the best among all Rust crates and should be the template for `winreg-forensic`.

### Dependencies

```
byteorder 1.5     # Manual byte parsing
thiserror 1.0     # Error derive
chrono 0.4        # Timestamps
bitflags 2.4      # Flags
encoding_rs 0.8   # Character encoding
serde 1.0         # Optional serialization
```

---

## 4. dfir-toolkit Registry Tools

**Repository:** https://github.com/dfir-dd/dfir-toolkit
**Stars:** 349 | **License:** GPL-3.0
**Author:** Jan Starke (same as nt-hive2)
**Status:** Archived (July 2025)

### Tools Overview

The dfir-toolkit wraps nt-hive2 into CLI tools:

| Tool | Purpose |
|------|---------|
| `cleanhive` | Apply transaction logs to produce a clean hive file |
| `hivescan` | Scan for registry hive fragments in disk images |
| `regdump` | Dump registry contents |
| `reg2bodyfile` | Convert registry timestamps to bodyfile format for timeline analysis |

### Key Forensic Patterns

**reg2bodyfile** — Timeline output:
- Converts registry key last-write timestamps to bodyfile format
- Bodyfile format: `MD5|name|inode|mode_as_string|UID|GID|size|atime|mtime|ctime|crtime`
- Feeds into `mactime2` (also in toolkit) for super-timeline generation
- Integrates with Sleuth Kit ecosystem

**hivescan** — Hive carving:
- Scans raw disk images for hive bin signatures (`hbin`)
- Can detect and extract hive fragments from unallocated space
- Uses nt-hive2's `HiveParseMode::Raw` for fragment parsing

**cleanhive** — Transaction log application:
- Reads dirty hive + transaction logs
- Applies dirty pages via MemOverlay
- Writes clean hive to output file
- Useful for preprocessing before analysis with other tools

### Assessment

The dfir-toolkit demonstrates how to build a complete forensic workflow around a registry library. The `reg2bodyfile` pattern (timestamp extraction for super-timelines) and `hivescan` pattern (fragment carving) are important capabilities to replicate.

---

## 5. yarp (Yet Another Registry Parser)

**Repository:** https://github.com/msuhanov/yarp
**Version:** 1.0.33 | **License:** GPL-3.0 | **Stars:** 136 | **Commits:** 91
**Author:** Maxim Suhanov (also authored the [regf format specification](https://github.com/msuhanov/regf))

### Architecture

```
yarp/
├── RegistryFile.py     # Core hive parser (20KB+) — low-level binary parsing
├── RegistryRecover.py  # Deleted key/value recovery
├── RegistryCarve.py    # Hive carving from disk/memory images (32KB!)
├── RegistryRecords.py  # Record structures
├── RegistryHelpers.py  # Helper functions
├── Registry.py         # High-level API
└── RegistryFuse.py     # FUSE filesystem mount!
```

### Parsing Approach

Pure Python with `struct.unpack()` for all binary parsing. Despite Python, the code is highly performant due to careful buffer management.

**Supported hive versions:** 1.1-1.6 (NT 3.1 through Windows 11) — **broadest version support of any parser**.

### Deleted Key Recovery (RegistryRecover.py)

The most sophisticated recovery algorithm among all parsers:

**Plausibility validation:**
```python
MAX_PLAUSIBLE_SUBKEYS_COUNT = 10000
MAX_PLAUSIBLE_VALUES_COUNT  = 1000
MAX_PLAUSIBLE_NAME_LENGTH   = 1024
MAX_PLAUSIBLE_NULL_COUNT    = 5

def ValidateKey(Key):
    # Check name length, null count, unicode replacement chars
    # Validate subkey/value counts against thresholds
    # Validate timestamp year (1970-2100)
```

**Cell-level scanning:**
- Iterates through unallocated (free) cells
- For each free cell, scans for "nk" and "vk" signatures at 2-byte boundaries
- Validates each candidate against plausibility heuristics
- Yields both recovered items AND unknown remnant data between items
- Tracks "unknown data" between recovered structures for gap analysis

### Hive Carving (RegistryCarve.py)

**This is the crown jewel of yarp and the most advanced carving implementation anywhere:**

```python
CarveResult = namedtuple('CarveResult', [
    'offset', 'size', 'hbins_data_size', 'truncated',
    'truncation_point', 'truncation_scenario', 'filename'
])
CarveResultFragment = namedtuple('CarveResultFragment', [
    'offset', 'size', 'hbin_start', 'suggested_margin_rounded', 'suggested_margin'
])
CarveResultMemory = namedtuple('CarveResultMemory', [
    'offset', 'buffer', 'hbin_start', 'compressed', 'partial_decompression'
])
```

**Capabilities:**
- Carve complete hives from disk images (base block + hive bins)
- Carve hive fragments (just hive bins without base block)
- Carve compressed hives from memory dumps
- Carve individual cells from deep memory analysis
- Validate base blocks, hive bins, and cell structures
- Handle truncated hives with truncation scenario reporting
- Log entry carving from transaction log files
- `mmap` support for efficient large image scanning
- Configurable size limits: `FILE_SIZE_MAX_MIB = 500`, `CELL_SIZE_MAX = 2MB`, `HBIN_SIZE_MAX = 64MB`

### Transaction Log Support

- Supports both old format (dirty vector bitmap) and new format (HvLE log entries)
- Marvin32 hash validation for new-format entries
- Complete reimplementation of the log replay algorithm

### FUSE Support

`RegistryFuse.py` mounts a registry hive as a virtual filesystem — keys become directories, values become files. This is unique among all parsers.

### Forensic Features: Assessment

**yarp is the most forensically complete parser**, with features no other tool has:
- Broadest version support (1.1-1.6)
- Most sophisticated deleted key recovery with plausibility heuristics
- Only tool with hive carving from disk/memory images
- Only tool with compressed hive support in memory carving
- Only tool with FUSE mount capability
- Only tool that yields "unknown remnant data" between recovered items
- Transaction log support for both old and new formats

**Weaknesses:**
- Python (slow for large-scale processing)
- No structured error handling (uses exceptions)
- Limited export format support
- No parallelism

---

## 6. python-registry

**Repository:** https://github.com/williballenthin/python-registry
**Stars:** 441 | **License:** Apache-2.0 | **Commits:** 344
**Author:** Willi Ballenthin (Mandiant / Google)

### Architecture

```
Registry/
├── Registry.py         # High-level API (Registry, RegistryKey, RegistryValue)
├── RegistryParse.py    # Low-level binary parser (35KB)
├── SettingsParse.py    # UWP settings.dat parser
├── creg.py             # CREG format support
└── (additional modules)
```

### Key Contributions

**1. Academic-quality documentation:** Every structure is documented with references to specifications. The code serves as a readable specification implementation.

**2. UWP/AppContainer composite types (SettingsParse.py):** First implementation of the settings.dat registry format used by UWP apps. Notatin later adopted this.

```python
# Types 0x101-0x11F: Composite types for settings.dat
RegUint8 = 0x101
RegInt16 = 0x102
# ... through ...
RegUnicodeStringArray = 0x11F
```

**3. Comprehensive data type handling (RegistryParse.py):**
- All 12 standard types + FILETIME
- 30+ composite UWP types
- Proper encoding handling (ASCII compressed names vs UTF-16LE)
- DevProp mask support for device property types

**4. Transaction log support:** Full old-format and new-format log replay.

**5. ShellBag-adjacent parsing:** While not full ShellBag parsing, provides the raw value parsing infrastructure that ShellBag tools build upon.

### API Design

```python
reg = Registry.Registry(sys.argv[1])
key = reg.open("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run")
for value in key.values():
    print(f"{value.name()}: {value.value()}")
```

Three-class hierarchy: `Registry` → `RegistryKey` → `RegistryValue`

### Assessment

python-registry is the best-documented and most educational implementation. Its composite type handling and clear code structure make it the ideal reference for understanding the format. However, it lacks advanced forensic features (carving, deleted recovery) that yarp provides.

---

## 7. libregf

**Repository:** https://github.com/libyal/libregf
**Stars:** 133 | **License:** LGPL-3.0+ | **Commits:** 211
**Author:** Joachim Metz (also authored the [REGF format specification](https://github.com/libyal/libregf/blob/main/documentation/Windows%20NT%20Registry%20File%20(REGF)%20format.asciidoc))

### Architecture

Classic C library with extensive separation of concerns:

```
libregf/
├── libregf_file.c/.h       # Top-level file API
├── libregf_key.c/.h        # Key navigation (82KB!)
├── libregf_value.c/.h      # Value access (42KB)
├── libregf_key_item.c/.h   # Key item internal parsing
├── libregf_value_item.c/.h # Value item internal parsing
├── libregf_key_tree.c/.h   # Key tree traversal
├── libregf_hive_bin.c/.h           # Hive bin parsing
├── libregf_hive_bin_cell.c/.h      # Cell parsing
├── libregf_hive_bin_header.c/.h    # Bin header parsing
├── libregf_hive_bins_list.c/.h     # Bin list management (18KB)
├── libregf_io_handle.c/.h  # I/O abstraction
├── libregf_multi_string.c/.h       # REG_MULTI_SZ handling
├── libregf_sub_key_list.c/.h       # Subkey list parsing
├── libregf_named_key.c/.h  # Named key parsing
├── libregf_data_type.c/.h  # Data type handling
└── regftools/               # CLI tools (regfinfo, regfexport, regfmount)
```

### Key Design Patterns

**1. Handle-based API (C opaque pointers):**
```c
libregf_file_t *file = NULL;
libregf_file_initialize(&file, &error);
libregf_file_open(file, "hive.dat", LIBREGF_OPEN_READ, &error);
libregf_file_get_root_key(file, &root_key, &error);
```

**2. Lazy loading with caching:**
- Uses `libfdata` for on-demand data loading
- `libfcache` for cell caching
- Cells loaded from disk only when accessed
- This allows processing very large hives without loading everything into memory

**3. Thread safety:**
```c
#include "libregf_libcthreads.h"
// Read-write lock on internal key structure
```

**4. ossfuzz integration:**
- Fuzz testing directory with OSS-Fuzz harnesses
- Critical for security-sensitive parsing code

### Forensic Features

**Supported:**
- All standard data types
- Multi-string value handling
- Security descriptor parsing
- Key tree traversal with parent navigation
- UTF-8, UTF-16LE, ASCII name handling
- Class name reading
- regfmount: FUSE filesystem mount
- regfinfo: Hive metadata display
- regfexport: Registry export

**Missing:**
- No transaction log replay (primary files only!)
- No deleted key recovery
- No hive carving
- No composite/UWP types
- No content hashing
- Still in "alpha" development status (since 2009!)

### Assessment

libregf is the **reference implementation** for understanding the REGF format, written by the author of one of the two major format specifications. Its strengths are:
- Battle-tested C code with ossfuzz integration
- Efficient lazy-loading architecture
- Thread-safe design
- Comprehensive name encoding handling
- FUSE mount support

However, it's **surprisingly incomplete** for forensics — no transaction logs, no deleted recovery. The format specification is more useful than the library itself for forensic purposes.

---

## 8. RegRipper

**Repository:** https://github.com/keydet89/RegRipper3.0
**Stars:** 687 | **Commits:** 109
**Author:** Harlan Carvey
**Language:** Perl

### Architecture

```
RegRipper3.0/
├── rip.pl / rip.exe    # Main CLI tool
├── File.pm             # Low-level file parsing
├── Key.pm              # Registry key abstraction
├── Base.pm             # Plugin base class
└── plugins/            # 200+ forensic artifact plugins!
```

### Plugin Architecture

Each plugin is a Perl module that:
1. Declares which hive type(s) it operates on (NTUSER, SYSTEM, SOFTWARE, SAM, etc.)
2. Defines a specific registry path to examine
3. Implements artifact-specific parsing/interpretation logic
4. Outputs human-readable forensic findings

### Key Plugin Categories (Selection of ~200+ Plugins)

**Execution Artifacts:**
- `userassist` — Program execution with timestamps and run counts (ROT13-encoded)
- `shimcache` / `appcompatcache` — Application compatibility cache entries
- `muicache` — MUI cache (program execution evidence)
- `prefetch` — Prefetch configuration settings

**Persistence/Autostart:**
- `run` / `runonce` — Autostart entries (Run, RunOnce keys)
- `services` — Windows services enumeration
- `bho` — Browser Helper Objects
- `winlogon` — Winlogon shell/userinit entries
- `tasks` — Scheduled tasks

**User Activity:**
- `recentdocs` — Recently accessed documents (with timestamps)
- `typedurls` — Browser typed URLs
- `wordwheelquery` — Windows Search terms
- `runmru` — Explorer Run dialog MRU
- `comdlg32` — Common dialog MRU (Open/Save dialogs)
- `recentapps` — Windows 10 recent apps
- `shellfolders` — Shell folder paths

**Device/Network:**
- `mountdev` / `mounteddevices` — Connected devices
- `usbstor` — USB storage device history
- `usb` — USB device connections
- `networkadapter` — Network adapter history
- `networkconnections` — Network connections
- `rdpnla` — RDP NLA connections

**System Configuration:**
- `timezone` — System timezone
- `compname` — Computer name
- `profilelist` — User profiles and SIDs
- `samparse` — SAM database (users, groups, login timestamps)
- `shutdown` — System shutdown timestamps
- `lastloggedon` — Last logged-on user
- `networklist` — Network profiles history

**Security/Malware:**
- `defender` — Windows Defender configuration
- `policies` — Security policies
- `svc` — Service manipulation (persistence indicator)
- `bam` — Background Activity Moderator (execution evidence)
- `amcache` — Amcache (program execution/installation)

**Application-Specific:**
- `unreadmail` — Outlook unread email counts
- `putty` — PuTTY session configuration
- `winscp` — WinSCP session history
- `teamviewerconnections` — TeamViewer connections
- `officemru` — Microsoft Office MRU
- `adobereader` — Adobe Reader recent files

### Key Limitation

RegRipper does **NOT** process transaction logs. The tool checks if a hive is dirty but does not automatically apply transaction log data. Users must preprocess with yarp's `registryFlush.py` or EZ's `rla.exe`.

### Assessment

RegRipper's value is entirely in its **artifact knowledge** — 200+ plugins encode decades of forensic research into machine-parseable form. The parsing engine itself (File.pm, Key.pm) is basic Perl binary parsing. The plugin catalog represents the most comprehensive artifact coverage of any tool and defines the forensic feature requirements for any registry parser.

---

## 9. Eric Zimmerman's Registry Explorer / RECmd

**Repository:** https://github.com/EricZimmerman/RECmd (CLI) + https://github.com/EricZimmerman/RegistryPlugins (Plugins)
**Stars:** 167 (RECmd), 77 (Plugins) | **License:** MIT
**Language:** C# (.NET)

### Architecture (Documented, Not Source-Analyzed)

Closed-source parsing engine, open-source plugins:

```
RegistryPlugins/
├── RegistryExplorer.MountedDevices/
├── RegistryPlugin.7-ZipHistory/
├── RegistryPlugin.Adobe/
├── RegistryPlugin.Amcache-*/        # Multiple Amcache plugins
├── RegistryPlugin.AppCompatFlags/
├── RegistryPlugin.BamDam/
├── RegistryPlugin.CIDSizeMRU/
├── RegistryPlugin.DHCPNetworkHint/
├── RegistryPlugin.FirstFolder/
├── RegistryPlugin.KnownNetworks/
├── RegistryPlugin.OpenSaveMRU/
├── RegistryPlugin.RecentDocs/
├── RegistryPlugin.SAM-*/            # Multiple SAM plugins
├── RegistryPlugin.Services/
├── RegistryPlugin.ShellBags/
├── RegistryPlugin.Syscache/
├── RegistryPlugin.TaskCache/
├── RegistryPlugin.Terminal*/         # Terminal services
├── RegistryPlugin.TypedURLs/
├── RegistryPlugin.Uninstall/
├── RegistryPlugin.UserAssist/
├── RegistryPlugin.WordWheelQuery/
└── ... (50+ plugin projects)
```

### Key Features

**1. Deleted Key/Value Recovery:** Enabled by default. Both Registry Explorer and RECmd perform full recovery of deleted keys and values. Also exposes **value slack** data.

**2. Batch Processing (RECmd):**
- Batch files define sets of registry paths to extract
- DFIR Batch File: 100+ keys across all hive types
- Output to normalized CSV with ValueData, ValueData2, ValueData3 columns
- Plugin-parsed data marked with "(plugin)" in ValueType column

**3. Plugin System:**
- .NET interface: `IRegistryPluginGrid`
- Plugins transform raw binary data into human-readable columns
- ValueData2/ValueData3 provide additional parsed fields
- 50+ plugins covering major forensic artifacts

**4. Volume Shadow Copy Processing:**
- `--vss` flag processes Volume Shadow Copies
- Unique capability among registry tools

**5. Search Capabilities:**
- Search keys (`--sk`), values (`--sv`), data (`--sd`), slack (`--ss`)
- Base64-encoded value detection (`--base64`)
- Regex support in searches
- Minimum size filtering

**6. Integration:**
- Works with KAPE for automated collection/processing
- Supports Eric Zimmerman's "common" registry export format
- JSON export available

### Assessment

Registry Explorer/RECmd is the **industry standard** for forensic registry analysis. Its strengths:
- Most polished UI and workflow
- Deleted recovery + value slack exposure
- Volume Shadow Copy support
- Extensive plugin ecosystem
- KAPE integration
- Batch processing for large-scale analysis

For `winreg-forensic`, the goal is to match RECmd's forensic capabilities in a Rust library with open-source parsing.

---

## 10. Comparison Matrix

| Feature | notatin | nt-hive2 | regf | dfir-toolkit | yarp | python-registry | libregf | RegRipper | EZ RECmd |
|---------|---------|----------|------|--------------|------|-----------------|---------|-----------|----------|
| **Language** | Rust | Rust | Rust | Rust | Python | Python | C | Perl | C# |
| **License** | Apache-2.0 | GPL-3.0 | MIT | GPL-3.0 | GPL-3.0 | Apache-2.0 | LGPL-3.0 | MIT | MIT |
| **Active** | Yes | Archived | Nascent | Archived | Yes | Maintained | Alpha | Yes | Yes |
| **Transaction logs (old)** | Yes | No | No | No | Yes | Yes | No | No | Yes |
| **Transaction logs (new)** | Yes | Yes | Partial | Yes | Yes | Yes | No | No | Yes |
| **Deleted recovery** | Yes | Detect-only | No | No | Yes (best) | No | No | No | Yes |
| **Hive carving** | No | No | No | Scan-only | Yes (best) | No | No | No | No |
| **Memory carving** | No | No | No | No | Yes | No | No | No | No |
| **Big data (>16KB)** | Yes | Yes | Unclear | Yes | Yes | Yes | Yes | N/A | Yes |
| **Composite/UWP types** | Yes | No | No | No | No | Yes (first) | No | No | Partial |
| **FUSE mount** | No | No | No | No | Yes | No | Yes | No | No |
| **Python bindings** | Yes | No | No | No | Native | Native | Yes | No | No |
| **Hive writing** | No | No | Yes | No | No | No | No | No | No |
| **Timeline output** | No | No | No | Yes | No | No | No | TLN | CSV |
| **Value slack** | No | No | No | No | Yes | No | No | No | Yes |
| **Artifact plugins** | No | No | No | No | No | No | No | 200+ | 50+ |
| **Security descriptors** | Yes | Yes | No | Yes | Yes | Limited | Yes | Limited | Yes |
| **Content hashing** | Blake3 | No | No | No | No | No | No | No | No |
| **Export formats** | JSONL,XLSX,TSV | None | .reg | bodyfile | None | None | Custom | Text/TLN | CSV,JSON |
| **Regex filtering** | Yes | No | No | No | No | No | No | No | Yes |
| **Benchmarks** | Criterion | No | No | No | No | No | No | No | .NET |
| **Fuzz testing** | No | No | No | No | No | No | OSS-Fuzz | No | No |
| **Thread safety** | No | No | No | No | No | No | Yes | No | Yes |
| **Version support** | 1.3-1.6 | 1.3-1.6 | 1.3-1.6 | 1.3-1.6 | **1.1-1.6** | 1.3-1.6 | 1.3-1.6 | N/A | 1.3-1.6 |
| **Cell slack recovery** | Yes | No | No | No | Yes | No | No | No | Yes |

---

## 11. Design Recommendations for winreg-forensic

### What to Steal

| From | What | Why |
|------|------|-----|
| **notatin** | Transaction log replay algorithm | Most complete Rust implementation with both old/new format, Marvin32 validation |
| **notatin** | Composite/UWP type definitions | `CellKeyValueDataTypes` enum covering 0x0000-0x011F |
| **notatin** | Filter system architecture | Segment-based regex/literal path matching with short-circuit |
| **notatin** | Builder pattern for parser construction | Ergonomic, well-tested API |
| **notatin** | Cell state model (5 states) | Most granular tracking of cell provenance |
| **notatin** | Blake3 content hashing | Deduplication of recovered items |
| **nt-hive2** | `Offset` newtype pattern | Type safety for hive offsets vs raw u32 |
| **nt-hive2** | Type-state pattern (CleanHive/DirtyHive) | Compile-time enforcement of transaction log processing |
| **nt-hive2** | MemOverlay for transaction logs | Clean in-memory page overlay |
| **nt-hive2** | Tombstone detection flag | Windows 10 RS1+ deleted value marker |
| **regf** | Error type design | Best-structured errors of any Rust crate |
| **regf** | Hive writing + .reg import/export | Unique capability, useful for testing |
| **regf** | HiveBuilder for creating test hives | Enables property-based testing |
| **yarp** | Deleted key recovery heuristics | Plausibility validation (name length, null count, timestamp range, subkey/value count) |
| **yarp** | Hive carving algorithm | Complete disk/memory image carving with truncation detection |
| **yarp** | Memory dump carving | Compressed hive and deep cell carving |
| **yarp** | Unknown remnant data tracking | Gap analysis between recovered items |
| **yarp** | FUSE mount concept | Virtual filesystem exposure of registry |
| **python-registry** | Data type documentation | Most readable reference for all value types |
| **python-registry** | UWP settings.dat parsing | Pioneer implementation of composite types |
| **libregf** | Lazy-loading architecture | Only load cells when accessed (for large hives) |
| **libregf** | Thread-safe design | Read-write locks on internal structures |
| **libregf** | OSS-Fuzz integration | Security-critical parsing needs fuzzing |
| **libregf** | REGF format specification | Most detailed format documentation |
| **RegRipper** | Artifact plugin catalog | 200+ plugins define the forensic feature requirements |
| **RegRipper** | UserAssist ROT13 decode | Classic forensic decode pattern |
| **EZ RECmd** | Value slack exposure | Access to slack data after value content |
| **EZ RECmd** | Batch processing model | Declarative artifact extraction |
| **EZ RECmd** | Volume Shadow Copy integration | Multi-timepoint analysis |
| **dfir-toolkit** | bodyfile output | Timeline integration |

### What to Improve

| Area | Current State | Improvement |
|------|---------------|-------------|
| **Parsing approach** | notatin uses nom (verbose), nt-hive2 uses binread (outdated) | Use `binrw` (modern fork of binread) with zero-copy parsing where possible |
| **Memory model** | All crates load entire hive into memory | Support both memory-mapped and streaming modes; lazy cell loading (libregf pattern) |
| **Error handling** | notatin stringifies all errors, nt-hive2 uses anyhow, regf has good errors | Structured errors with byte offset context, source chain preservation, and recoverable vs fatal classification |
| **Deleted recovery** | notatin scans free cells, yarp adds heuristics | Combine: scan + plausibility heuristics + cross-reference with transaction logs + confidence scoring |
| **Thread safety** | Only libregf has it (C mutexes) | Use `Send + Sync` bounds, `RwLock` for shared hive access, rayon for parallel cell scanning |
| **Hive carving** | Only yarp has it (Python) | Port yarp's algorithms to Rust with SIMD-accelerated signature scanning |
| **Value types** | Fragmented support across crates | Comprehensive enum covering all known types + extensible for future types |
| **Testing** | Limited test data, no fuzzing in Rust crates | Property-based testing (proptest), fuzz testing (cargo-fuzz/afl), golden file tests |
| **Python bindings** | Only notatin has them (via PyO3) | First-class PyO3 bindings with async support |
| **Documentation** | Varies widely | Inline doc-tests, format specification cross-references on every struct/field |

### What to Replace

| What | Replace With |
|------|-------------|
| `nom` + `binread` | `binrw` (modern, maintained, ergonomic) for fixed-layout structures; hand-coded for complex/conditional parsing |
| `Vec<u8>` buffer model | `mmap` (via `memmap2`) + `Cursor` fallback for non-seekable sources |
| `winstructs` for security descriptors | Purpose-built security descriptor parser with ACL interpretation and SID resolution |
| Flat module structure | Workspace with sub-crates: `winreg-core` (parsing), `winreg-recover` (recovery), `winreg-carve` (carving), `winreg-forensic` (artifact interpretation), `winreg-cli` (tools) |
| String-based errors | `miette`/`thiserror` with span information pointing to byte offsets in the hive |
| `HashMap` for state tracking | Arena allocator + index-based access for better cache locality |
| Single-threaded scanning | `rayon` parallel iterator over hive bins for deleted key scanning |

### Architecture for winreg-forensic

```
winreg-forensic/              # Workspace root
├── crates/
│   ├── winreg-format/        # Pure format definitions (no I/O)
│   │   └── Cell types, offsets, flags, data types
│   ├── winreg-core/          # Core parser (Read+Seek based)
│   │   └── HiveParser, CellReader, transaction logs
│   ├── winreg-recover/       # Deleted key/value recovery
│   │   └── Free cell scanning, heuristic validation, confidence scoring
│   ├── winreg-carve/         # Hive carving from images
│   │   └── Disk carving, memory carving, fragment extraction
│   ├── winreg-artifacts/     # Forensic artifact interpretation
│   │   └── Plugin system, UserAssist, ShellBags, services, etc.
│   ├── winreg-timeline/      # Timeline output
│   │   └── bodyfile, CSV, JSON timeline formats
│   ├── winreg-fuse/          # FUSE mount (optional feature)
│   └── winreg-py/            # Python bindings (PyO3)
├── fuzz/                     # Cargo-fuzz targets
├── benches/                  # Criterion benchmarks
└── tests/                    # Integration tests with real hive files
```

---

## References

### Format Specifications
- [Maxim Suhanov's regf specification](https://github.com/msuhanov/regf/blob/master/Windows%20registry%20file%20format%20specification.md) — Most detailed unofficial spec
- [libyal REGF format docs](https://github.com/libyal/libregf/blob/main/documentation/Windows%20NT%20Registry%20File%20(REGF)%20format.asciidoc) — Complementary specification
- [Google Project Zero: The Windows Registry Adventure](https://projectzero.google/2024/04/the-windows-registry-adventure-1.html) — 7-part series on registry internals

### Source Repositories
- [notatin](https://github.com/strozfriedberg/notatin) — Rust, Apache-2.0
- [nt-hive2](https://github.com/dfir-dd/nt-hive2) — Rust, GPL-3.0 (archived)
- [regf](https://github.com/peitaosu/regf) — Rust, MIT
- [dfir-toolkit](https://github.com/dfir-dd/dfir-toolkit) — Rust, GPL-3.0 (archived)
- [yarp](https://github.com/msuhanov/yarp) — Python, GPL-3.0
- [python-registry](https://github.com/williballenthin/python-registry) — Python, Apache-2.0
- [libregf](https://github.com/libyal/libregf) — C, LGPL-3.0
- [RegRipper 3.0](https://github.com/keydet89/RegRipper3.0) — Perl, MIT
- [RECmd](https://github.com/EricZimmerman/RECmd) — C#, MIT
- [Registry Plugins](https://github.com/EricZimmerman/RegistryPlugins) — C#, MIT

### Community Resources
- [SANS Registry Explorer page](https://www.sans.org/tools/registry-explorer/)
- [Eric Zimmerman's Tools](https://ericzimmerman.github.io/)
- [AboutDFIR Registry Tools](https://aboutdfir.com/toolsandartifacts/windows/registry-explorer-recmd/)
- [regf crate on crates.io](https://crates.io/crates/regf)
- [nt_hive2 crate on crates.io](https://crates.io/crates/nt_hive2)
- [notatin crate on crates.io](https://crates.io/crates/notatin)
