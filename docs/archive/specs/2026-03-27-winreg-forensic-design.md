# winreg-forensic Design Specification

> The world's most comprehensive Windows registry forensic parser — a standalone
> open-source Rust workspace covering REGF binary parsing, transaction log replay,
> deleted key recovery, hive carving, 200+ artifact decoders, timeline generation,
> FUSE mount, and Python bindings.

**Repository:** `~/src/winreg-forensic` (standalone, NOT inside Issen monorepo)
**License:** Apache-2.0
**CLI binary:** `rt-reg`
**Rust edition:** 2021
**MSRV:** 1.75+

---

## 1. Strategic Context

### 1.1 Why Build This

No existing tool covers the full registry forensic surface in a single, fast, correct
implementation:

- **notatin** (Rust) — best Rust crate but weak errors, memory-hungry, no carving, pre-release
- **nt-hive2** (Rust) — cleanest type design but archived, no recovery, no artifact decoders
- **yarp** (Python) — most forensically advanced (carving, recovery) but Python-speed
- **RegRipper** (Perl) — 200+ plugins but Perl, no structured output, no recovery
- **RECmd** (C#) — 50+ batch plugins, Windows-only
- **libregf** (C) — reference lazy-loading but no txlog, no recovery, C API ergonomics

winreg-forensic combines the best of all: yarp's forensic algorithms + notatin's Rust
foundation + nt-hive2's type safety + RegRipper/RECmd's artifact coverage + original
contributions (fuzz testing, structured errors, parallel recovery, anti-forensics detection).

### 1.2 Design Principles

1. **Forensic purity** — strictly read-only, never modify evidence
2. **Correctness over speed** — every decoder validated against RegRipper/RECmd output
3. **All features enabled by default** — `cargo build` compiles everything
4. **Errors carry byte offsets** — every error pinpoints the exact location in the hive
5. **Parallel where embarrassingly so** — deleted recovery, hbin scanning via rayon
6. **Python-first bindings** — forensic community lives in Python, we meet them there

### 1.3 Integration with Issen

winreg-forensic is open-source and standalone. Issen consumes it via a thin
`rt-parser-registry` crate that bridges `Finding` → `ParsedArtifact`. The proprietary
value in Issen is the correlation engine (cross-referencing registry with MFT,
USN, evtx, prefetch) and attorney-focused reporting — not the parsing itself.

---

## 2. Workspace Structure

```
winreg-forensic/                        # Workspace root
├── crates/
│   ├── winreg-format/                  # Zero-dependency format definitions
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── header.rs               # BaseBlock (regf header, 4096 bytes)
│   │   │   ├── hbin.rs                 # Hive bin headers (32 bytes each)
│   │   │   ├── cells.rs                # NK, VK, SK, LF, LH, LI, RI, DB cell types
│   │   │   ├── flags.rs                # bitflags: key flags, value types, ACB flags
│   │   │   ├── security.rs             # SECURITY_DESCRIPTOR, ACL, ACE, SID layouts
│   │   │   └── version.rs              # RegfVersion enum (1.0–1.6) + feature gates
│   │   └── Cargo.toml                  # deps: binrw, bitflags only
│   │
│   ├── winreg-core/                    # Core parser — the heart of the project
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── hive.rs                 # Hive<R> struct — mmap'd or buffered
│   │   │   ├── cell_reader.rs          # Read cells by offset, validate signatures
│   │   │   ├── key.rs                  # Key navigation (subkeys, values, class name)
│   │   │   ├── value.rs                # Value data decoding (all REG_* types)
│   │   │   ├── security.rs             # SK chain traversal, ACL/SID interpretation
│   │   │   ├── path.rs                 # Key path navigation + parent reconstruction
│   │   │   ├── txlog.rs                # Transaction log replay (DIRT + HvLE)
│   │   │   ├── txr.rs                  # TxR/CLFS transactional registry parsing
│   │   │   └── iter.rs                 # BFS/DFS key iterators
│   │   └── Cargo.toml                  # deps: winreg-format, memmap2, miette, thiserror
│   │
│   ├── winreg-recover/                 # Deleted key/value recovery
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── scanner.rs              # Free cell scanning (rayon-parallel)
│   │   │   ├── validator.rs            # Plausibility heuristics (yarp port)
│   │   │   ├── orphan.rs               # Orphan key detection (allocated but unreachable)
│   │   │   ├── remnant.rs              # Remnant data beyond last hbin
│   │   │   ├── slack.rs                # Cell slack space analysis
│   │   │   ├── confidence.rs           # Confidence scoring (High/Medium/Low/Speculative)
│   │   │   └── anomalies.rs            # Anti-forensics detection
│   │   └── Cargo.toml                  # deps: winreg-core, rayon
│   │
│   ├── winreg-carve/                   # Hive carving from raw images
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── disk.rs                 # Disk image carving (regf + hbin scan)
│   │   │   ├── memory.rs               # Memory dump carving (kernel struct walking)
│   │   │   ├── pagefile.rs             # Pagefile fragment extraction
│   │   │   ├── hibernation.rs          # Hibernation file decompression + carving
│   │   │   └── fragment.rs             # Fragment reassembly from scattered hbins
│   │   └── Cargo.toml                  # deps: winreg-core, memmap2
│   │
│   ├── winreg-artifacts/               # Forensic artifact decoders (200+ decoders)
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── decoder.rs              # RegistryDecoder trait + registry + Finding type
│   │   │   ├── system/                 # SYSTEM hive decoders
│   │   │   │   ├── mod.rs
│   │   │   │   ├── services.rs         # Services (ImagePath, ServiceDLL, FailureActions)
│   │   │   │   ├── shimcache.rs        # AppCompatCache (XP/Vista/7/8/10/11 formats)
│   │   │   │   ├── bam.rs              # BAM/DAM background activity monitor
│   │   │   │   ├── usb.rs              # USBSTOR, USB, WpdBusEnumRoot, DeviceClasses
│   │   │   │   ├── mounted.rs          # MountedDevices (internal vs USB binary format)
│   │   │   │   ├── network.rs          # TCP/IP interfaces, adapter configs
│   │   │   │   ├── computer.rs         # ComputerName, timezone, last shutdown
│   │   │   │   ├── prefetch.rs         # Prefetch configuration
│   │   │   │   ├── firewall.rs         # Windows Firewall rules
│   │   │   │   ├── lsa_packages.rs     # LSA authentication/notification packages
│   │   │   │   ├── defender.rs         # Windows Defender exclusions
│   │   │   │   ├── terminal.rs         # Terminal Server / RDP settings
│   │   │   │   ├── svchost.rs          # SvcHost group membership
│   │   │   │   └── boot.rs             # Boot configuration, safe mode, last known good
│   │   │   ├── software/               # SOFTWARE hive decoders
│   │   │   │   ├── mod.rs
│   │   │   │   ├── installed.rs        # Uninstall keys + WOW6432Node
│   │   │   │   ├── network_list.rs     # NetworkList profiles + signatures (SYSTEMTIME)
│   │   │   │   ├── os_info.rs          # Windows version, installation date, product key
│   │   │   │   ├── persistence.rs      # Run/RunOnce, AppInit_DLLs, IFEO, Winlogon
│   │   │   │   ├── tracing.rs          # Tracing keys (application diagnostics)
│   │   │   │   ├── profiles.rs         # ProfileList SID→path mapping
│   │   │   │   ├── compat.rs           # AppCompatFlags
│   │   │   │   ├── print.rs            # Print spooler settings
│   │   │   │   └── com.rs              # COM object registrations (hijacking detection)
│   │   │   ├── ntuser/                 # NTUSER.DAT hive decoders
│   │   │   │   ├── mod.rs
│   │   │   │   ├── userassist.rs       # UserAssist v3 (16-byte) + v5 (72-byte) + ROT13
│   │   │   │   ├── shellbags.rs        # ShellBags (full shell item binary parsing)
│   │   │   │   ├── mru.rs              # RecentDocs, TypedPaths, TypedURLs, RunMRU
│   │   │   │   ├── wordwheel.rs        # WordWheelQuery (search terms)
│   │   │   │   ├── comdlg.rs           # OpenSavePidlMRU, LastVisitedPidlMRU, CIDSizeMRU
│   │   │   │   ├── office.rs           # Office MRU, TrustRecords, Reading Locations
│   │   │   │   ├── rdp.rs              # Terminal Server Client MRU + Servers
│   │   │   │   ├── muicache.rs         # MUICache (program execution with display names)
│   │   │   │   ├── featureusage.rs     # FeatureUsage (Win10+ app usage counters)
│   │   │   │   ├── notify.rs           # Notification area icon cache
│   │   │   │   ├── mountpoints.rs      # MountPoints2 (drive/share access)
│   │   │   │   ├── network_drives.rs   # Map Network Drive MRU + persistent connections
│   │   │   │   ├── putty.rs            # PuTTY sessions + WinSCP
│   │   │   │   ├── sysinternals.rs     # Sysinternals EULA acceptance (tool usage)
│   │   │   │   ├── cmd.rs              # Command Processor AutoRun
│   │   │   │   ├── ie.rs               # IE download history, typed URLs
│   │   │   │   ├── taskband.rs         # Taskbar pinned items
│   │   │   │   ├── cap_access.rs       # CapabilityAccessManager (webcam/mic/location)
│   │   │   │   └── persistence.rs      # HKCU Run/RunOnce, UserInitMprLogonScript, shell
│   │   │   ├── sam/                    # SAM hive decoders
│   │   │   │   ├── mod.rs
│   │   │   │   ├── accounts.rs         # F/V value binary parsing, account enumeration
│   │   │   │   └── groups.rs           # Group membership, SID resolution
│   │   │   ├── security/               # SECURITY hive decoders
│   │   │   │   ├── mod.rs
│   │   │   │   ├── lsa.rs              # LSA Secrets (3-step decryption: BootKey→LSAKey→Secret)
│   │   │   │   └── cached.rs           # Cached domain credentials (DCC2 / NL$)
│   │   │   ├── amcache/                # Amcache.hve decoders
│   │   │   │   ├── mod.rs
│   │   │   │   └── inventory.rs        # InventoryApplicationFile, drivers, shortcuts, legacy
│   │   │   └── usrclass/              # USRCLASS.DAT decoders
│   │   │       ├── mod.rs
│   │   │       └── shellbags.rs        # BagMRU hierarchy + shell item binary parsing
│   │   └── Cargo.toml                  # deps: winreg-core, chrono, serde, serde_json
│   │
│   ├── winreg-timeline/                # Timeline output generation
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── event.rs                # TimelineEvent struct
│   │   │   ├── bodyfile.rs             # Sleuth Kit bodyfile format
│   │   │   ├── csv.rs                  # CSV with configurable columns
│   │   │   └── jsonl.rs                # JSON Lines (one event per line)
│   │   └── Cargo.toml                  # deps: winreg-artifacts, chrono, serde, csv
│   │
│   ├── winreg-fuse/                    # FUSE virtual filesystem mount
│   │   ├── src/
│   │   │   └── lib.rs                  # Key→dir, Value→file mapping
│   │   └── Cargo.toml                  # deps: winreg-core, fuser
│   │
│   └── winreg-py/                      # Python bindings (PyO3)
│       ├── src/
│       │   └── lib.rs                  # #[pymodule] winreg_forensic
│       └── Cargo.toml                  # deps: winreg-core, winreg-artifacts, pyo3
│
├── rt-reg/                             # CLI binary
│   ├── src/
│   │   ├── main.rs                     # clap v4 subcommand dispatch
│   │   ├── discover.rs                 # Auto-discover hives + txlogs in a directory
│   │   └── output.rs                   # --format table|json|jsonl|csv|bodyfile
│   └── Cargo.toml
│
├── fuzz/                               # cargo-fuzz targets
│   └── fuzz_targets/
│       ├── parse_hive.rs
│       ├── parse_cell.rs
│       ├── replay_txlog.rs
│       ├── recover_deleted.rs
│       └── decode_value.rs
│
├── benches/                            # criterion benchmarks
│   └── parse_benchmark.rs
│
├── tests/                              # Integration tests
│   ├── common/
│   │   └── hive_builder.rs             # TestHiveBuilder for synthesizing test hives
│   ├── fixtures/                       # Real sanitized hive files
│   ├── golden/                         # Expected output from RegRipper/RECmd
│   └── golden_tests.rs
│
├── Cargo.toml                          # Workspace manifest
├── LICENSE                             # Apache-2.0
└── README.md
```

---

## 3. Core Parsing Architecture

### 3.1 I/O Layer

`Hive<R>` is generic over `R: Read + Seek`, supporting three construction paths:

```rust
/// Memory-mapped file (primary path for on-disk hives).
impl Hive<Mmap> {
    pub fn from_path(path: &Path) -> Result<Self>;
}

/// In-memory buffer (carved fragments, piped input, tests).
impl Hive<Cursor<Vec<u8>>> {
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self>;
}

/// Transaction-log-overlaid hive (forensic replay without modifying original).
impl Hive<Cursor<OverlayBuffer>> {
    pub fn from_path_with_logs(path: &Path, logs: &[&Path]) -> Result<Self>;
}
```

On construction, `Hive` validates the base block signature and checksum, catalogs all
hbin descriptors (offset + size), and determines the REGF version (1.0–1.6).

### 3.2 Cell Reading

```rust
/// Newtype preventing file offset / cell offset confusion.
pub struct CellOffset(pub u32);

impl CellOffset {
    pub const NULL: Self = Self(0xFFFF_FFFF);
    pub fn file_offset(self) -> u64 { 0x1000 + u64::from(self.0) }
    pub fn is_null(self) -> bool { self.0 == 0xFFFF_FFFF }
}

/// All 8 REGF cell types.
pub enum Cell {
    KeyNode(KeyNode),           // nk — registry key
    KeyValue(KeyValue),         // vk — registry value
    SecurityKey(SecurityKey),   // sk — security descriptor
    FastLeaf(FastLeaf),         // lf — subkey index with 4-byte name hints
    HashLeaf(HashLeaf),         // lh — subkey index with hash (H = 37*H + C[i])
    IndexLeaf(IndexLeaf),       // li — simple subkey index
    RootIndex(RootIndex),       // ri — index of subkey indices
    BigData(BigData),           // db — large value data (>16,344 bytes)
}
```

Cell allocation convention: negative size = allocated, positive = free. 8-byte alignment.

### 3.3 Key Navigation

```rust
pub struct Key<'h, R: ReadSeek> { ... }

impl<'h, R: ReadSeek> Key<'h, R> {
    pub fn name(&self) -> &str;
    pub fn path(&self) -> Result<String>;              // Walk parents to root
    pub fn subkeys(&self) -> Result<Vec<Key<'h, R>>>;
    pub fn subkey(&self, name: &str) -> Result<Option<Key<'h, R>>>;
    pub fn values(&self) -> Result<Vec<Value<'h, R>>>;
    pub fn value(&self, name: &str) -> Result<Option<Value<'h, R>>>;
    pub fn class_name(&self) -> Result<Option<String>>;
    pub fn security(&self) -> Result<SecurityDescriptor>;
    pub fn timestamps(&self) -> KeyTimestamp;
    pub fn flags(&self) -> KeyFlags;
}
```

Subkey lookup is case-insensitive (matching Windows registry semantics). For LH leaves,
we use the hash (H = 37*H + C[i]) for fast rejection before string comparison.

### 3.4 Value Decoding

```rust
pub struct Value<'h, R: ReadSeek> { ... }

impl<'h, R: ReadSeek> Value<'h, R> {
    pub fn name(&self) -> &str;
    pub fn data_type(&self) -> ValueType;
    pub fn raw_data(&self) -> Result<Vec<u8>>;
    pub fn as_string(&self) -> Result<String>;           // REG_SZ, REG_EXPAND_SZ
    pub fn as_u32(&self) -> Result<u32>;                 // REG_DWORD
    pub fn as_u64(&self) -> Result<u64>;                 // REG_QWORD
    pub fn as_multi_string(&self) -> Result<Vec<String>>; // REG_MULTI_SZ
    pub fn is_resident(&self) -> bool;
    pub fn data_size(&self) -> u32;
}
```

Resident data (MSB of data size set = data stored in VK header offset field) and big
data (db cell indirection for values >16,344 bytes) are handled transparently.

### 3.5 Transaction Log Replay

```rust
/// Overlay buffer: original hive bytes + dirty page patches.
/// Implements Read + Seek, plugs directly into Hive<Cursor<OverlayBuffer>>.
pub struct OverlayBuffer {
    base: Vec<u8>,
    dirty_pages: BTreeMap<u32, Vec<u8>>,
}

/// Replay transaction logs onto a hive.
/// Supports old format (DIRT bitmap + dirty pages) and new format (HvLE entries
/// with Marvin32 checksums).
pub fn replay_transaction_logs(
    hive_path: &Path,
    log_paths: &[&Path],
) -> Result<OverlayBuffer>;
```

Forensic purity: the original hive bytes are never modified. The overlay intercepts
reads at dirty page offsets and returns the patched data.

### 3.6 TxR / CLFS Parsing

Windows Vista+ uses transactional registry operations via CLFS (Common Log File System).
The `.regtrans-ms` files contain uncommitted registry operations that may hold forensically
significant evidence (including evidence of attacker activity that was rolled back).

```rust
/// winreg-core/src/txr.rs
pub struct TxrRecord {
    pub operation: TxrOperation,       // KeyCreate, KeyDelete, ValueWrite, ValueDelete
    pub key_path: String,
    pub value_name: Option<String>,
    pub data: Option<Vec<u8>>,
    pub timestamp: DateTime<Utc>,
}

pub enum TxrOperation {
    KeyCreate,
    KeyDelete,
    ValueWrite,
    ValueDelete,
}

pub fn parse_txr_files(paths: &[&Path]) -> Result<Vec<TxrRecord>>;
```

---

## 4. Artifact Decoder System

### 4.1 Core Types

```rust
/// Forensic finding — the universal output type for all decoders.
pub struct Finding {
    pub timestamp: Option<DateTime<Utc>>,
    pub source: &'static str,           // "UserAssist", "ShimCache", etc.
    pub category: Category,
    pub key_path: String,
    pub detail: serde_json::Value,       // Flexible structured data per decoder
    pub mitre: Option<&'static str>,     // MITRE ATT&CK technique ID
    pub confidence: Confidence,
}

pub enum Category {
    Execution,       // Program was run
    Persistence,     // Survives reboot
    FileAccess,      // User accessed file/folder
    Network,         // Network configuration/activity
    UserAccount,     // Account enumeration/info
    DeviceUsage,     // USB, printer, etc.
    SystemConfig,    // OS/machine configuration
    Credential,      // Passwords, tokens, secrets
    Lateral,         // RDP, PsExec, WMI lateral movement
    AntiForensic,    // Timestomping, clearing, hiding
}

pub enum Confidence { High, Medium, Low, Speculative }
```

### 4.2 Decoder Trait

```rust
pub trait RegistryDecoder: Send + Sync {
    fn name(&self) -> &'static str;
    fn hive_types(&self) -> &[HiveType];
    fn key_paths(&self) -> &[&'static str];
    fn mitre_ids(&self) -> &[&'static str] { &[] }
    fn decode<R: ReadSeek>(&self, hive: &Hive<R>) -> Result<Vec<Finding>>;
}
```

### 4.3 Compiled-In Registry

All decoders are compiled-in, registered in a static slice. No dynamic loading.

```rust
pub fn all_decoders() -> &'static [&'static dyn RegistryDecoder] { ... }

pub fn decoders_for_hive(hive_type: HiveType) -> Vec<&'static dyn RegistryDecoder> {
    all_decoders().iter()
        .filter(|d| d.hive_types().contains(&hive_type))
        .copied().collect()
}

pub fn decode_hive<R: ReadSeek>(
    hive: &Hive<R>,
    hive_type: HiveType,
) -> Result<Vec<Finding>> {
    decoders_for_hive(hive_type).iter()
        .flat_map(|d| d.decode(hive).unwrap_or_default())
        .collect()
}
```

### 4.4 Hive Type Auto-Detection

```rust
pub fn detect_hive_type<R: ReadSeek>(hive: &Hive<R>) -> Option<HiveType>;
```

Detection by root key structure: SYSTEM has `Select` + `ControlSet001`, SOFTWARE has
`Microsoft\Windows\CurrentVersion`, SAM has `SAM\Domains`, etc.

### 4.5 Decoder Catalog

Full list of decoders organized by hive, ported from RegRipper + RECmd:

**SYSTEM hive (15 decoders):**
- `services` — Services: ImagePath, ServiceDLL, FailureActions binary structure, Start type
- `shimcache` — AppCompatCache: XP 32-bit, XP 64-bit/2003, Vista/7, 8.x, 10/11 binary formats
- `bam` — BAM/DAM: background activity monitor with execution timestamps
- `usb` — USB devices: USBSTOR, USB, WpdBusEnumRoot, DeviceClasses with property GUIDs
- `mounted` — MountedDevices: drive letter mapping, internal vs USB binary format
- `network` — Network interfaces: TCP/IP configuration, adapter settings
- `computer` — ComputerName, timezone (bias/standard/daylight), last shutdown time
- `prefetch` — Prefetch configuration (EnablePrefetcher, EnableSuperfetch)
- `firewall` — Windows Firewall authorized applications and rules
- `lsa_packages` — LSA authentication packages, notification packages, security packages
- `defender` — Windows Defender exclusions (paths, extensions, processes)
- `terminal` — Terminal Server / RDP settings, fDenyTSConnections, port
- `svchost` — SvcHost group membership (DLL loading vectors)
- `boot` — Boot configuration, safe mode, last known good, BCD references
- `currentcontrolset` — CurrentControlSet determination via Select key

**SOFTWARE hive (10 decoders):**
- `installed` — Installed programs: Uninstall keys + WOW6432Node, install dates, publishers
- `network_list` — NetworkList profiles: SSIDs, MACs, first/last connected (SYSTEMTIME format)
- `os_info` — Windows version, build, installation date, product key, registered owner
- `persistence` — Run/RunOnce, AppInit_DLLs, IFEO debuggers, Winlogon notify/shell/userinit
- `tracing` — Tracing keys (application diagnostic configuration)
- `profiles` — ProfileList: SID→profile path mapping
- `compat` — AppCompatFlags: compatibility shims, layers
- `print` — Print spooler settings, installed printers
- `com` — COM object registrations: InprocServer32, LocalServer32 (hijacking detection)
- `srum` — SRUM database configuration and extension CLSIDs

**NTUSER.DAT hive (21 decoders):**
- `userassist` — UserAssist: v3 (16-byte) + v5 (72-byte), ROT13 program names, run counts
- `shellbags` — ShellBags: full shell item binary parsing (0x1F/0x2F/0x3x/0x4x/0x61/0x71)
- `mru` — MRU lists: RecentDocs, TypedPaths, TypedURLs, RunMRU, LastVisitedMRU
- `wordwheel` — WordWheelQuery: Explorer search terms
- `comdlg` — ComDlg32: OpenSavePidlMRU, LastVisitedPidlMRU, CIDSizeMRU
- `office` — Microsoft Office: MRU per version/app, TrustRecords, Reading Locations
- `rdp` — Terminal Server Client: MRU servers, UsernameHint, connection history
- `muicache` — MUICache: program execution with display names
- `featureusage` — FeatureUsage: Win10+ app usage counters (AppLaunch, AppSwitched, etc.)
- `notify` — Notification area icon cache
- `mountpoints` — MountPoints2: volume/share access timestamps
- `network_drives` — Map Network Drive MRU + persistent network connections
- `putty` — PuTTY sessions, hostkeys + WinSCP stored sessions
- `sysinternals` — Sysinternals EULA acceptance (tool execution evidence)
- `cmd` — Command Processor AutoRun (persistence)
- `ie` — IE/Edge download history, TypedURLs, TypedURLsTime
- `taskband` — Taskbar pinned items
- `cap_access` — CapabilityAccessManager: webcam, microphone, location access timestamps
- `persistence` — HKCU Run/RunOnce, UserInitMprLogonScript, Winlogon shell
- `env` — Environment variables, VolatileEnvironment, user PATH
- `applets` — Built-in app MRUs: Paint, Notepad, WordPad, Calculator, Regedit

**SAM hive (2 decoders):**
- `accounts` — F/V value binary parsing: last logon, password last set, account expires, last failed login, RID, ACB flags, login counts, password hint, account creation derivation
- `groups` — Group membership, SID resolution, group descriptions

**SECURITY hive (2 decoders):**
- `lsa` — LSA Secrets: 3-step decryption (Boot Key from SAM → LSA Key → per-secret decrypt)
- `cached` — Cached domain credentials: DCC2/NL$ format, entry binary structure, decryption

**Amcache.hve (1 decoder):**
- `inventory` — InventoryApplicationFile (SHA-1 from FileId), InventoryApplication, InventoryDriverBinary, InventoryDriverPackage, InventoryDeviceContainer, InventoryApplicationShortcut, legacy Win8 File/Programs format

**USRCLASS.DAT (1 decoder):**
- `shellbags` — BagMRU hierarchy: full shell item parsing, CLSID registrations, file extension associations, FAT date/time encoding

**BCD (1 decoder):**
- `bcd` — Boot configuration store: element type codes, boot entries, integrity validation

**Total: 53 decoders** covering all artifact categories documented in the research catalog.
Additional decoders will be added over time following the same trait pattern.

---

## 5. Recovery & Anti-Forensics

### 5.1 Deleted Key/Value Recovery

Five recovery techniques, each with confidence scoring:

```rust
pub struct RecoveredCell {
    pub cell: Cell,
    pub offset: CellOffset,
    pub technique: RecoveryTechnique,
    pub confidence: Confidence,
    pub parent_path: Option<String>,
}

pub enum RecoveryTechnique {
    FreeCell,        // Deallocated cell with valid NK/VK payload
    Orphan,          // Allocated but unreachable from root
    Remnant,         // Data beyond declared hive size
    SlackSpace,      // Trailing bytes within allocated cell
    TransactionLog,  // Recovered from txlog dirty pages
}
```

**Free cell scanning** — primary technique. Iterates all hbins, finds cells with positive
size (free), checks for valid NK/VK signatures. Parallelized over hbins with rayon.

**Plausibility validation** — ported from yarp's heuristics:
- Timestamp within reasonable range (1990–2035)
- Key name printable, reasonable length (<256 chars)
- Parent entry offset points to valid cell or is null
- Null byte ratio in name below threshold
- Value data size plausible (<16 MB)

**Confidence scoring** — based on corroborating evidence:

| Signal | High | Medium | Low | Speculative |
|--------|------|--------|-----|-------------|
| Valid parent chain | Yes | Partial | No | No |
| Timestamp plausible | Yes | Yes | Marginal | No |
| Name valid | Yes | Yes | Yes | Garbage |
| Corroborated by txlog | Yes | — | — | — |
| Found in slack space | — | — | Yes | Yes |

### 5.2 Hive Carving

```rust
/// Carve hives from raw disk/partition images.
pub fn carve_from_disk<R: Read + Seek>(
    image: R, callback: impl FnMut(CarvedHive),
) -> Result<()>;

/// Carve from memory dumps (handles non-contiguous hbins).
pub fn carve_from_memory<R: Read + Seek>(
    dump: R, callback: impl FnMut(CarvedHive),
) -> Result<()>;

pub struct CarvedHive {
    pub offset: u64,
    pub header: BaseBlock,
    pub completeness: Completeness,
    pub hive_type: Option<HiveType>,
    pub data: Vec<u8>,
}

pub enum Completeness {
    Complete,
    Partial { bins_found: u32, bins_expected: u32 },
    FragmentOnly,
}
```

Disk carving: scan for "regf" at 4096-byte boundaries, validate checksum, follow hbin chain.
Memory carving: scan for both "regf" and isolated "hbin", reassemble using hbin offset fields.
Pagefile: 4KB page fragments, limited reassembly.
Hibernation: requires decompression (Xpress/LZ) before scanning.

### 5.3 Anti-Forensics Detection

```rust
pub enum RegistryAnomaly {
    TimestampAnomaly { key_path: String, timestamp: DateTime<Utc>, os_install: DateTime<Utc> },
    SuspiciousClassName { key_path: String, data_size: usize },
    TxLogSequenceGap { expected: u32, actual: u32 },
    OrphanAllocatedKey { offset: CellOffset, key_name: String },
    RemnantDataPresent { declared_size: u64, actual_size: u64 },
    MissingTransactionLogs { hive_path: String },
    LayeredKeyDetected { key_path: String, flags: KeyFlags },
}
```

Anomalies emit as `Finding`s with `Category::AntiForensic`, integrating naturally into
the decoder output stream.

---

## 6. CLI Design (`rt-reg`)

### 6.1 Subcommands

```
rt-reg info <HIVE>                        Show hive metadata
rt-reg dump <HIVE> [--path KEY] [--format] Dump registry tree
rt-reg search <PATH> [--key|--value|--data PATTERN] Search by regex
rt-reg decode <PATH> [--decoder LIST] [--format] Run artifact decoders
rt-reg timeline <PATH> [--format bodyfile|csv|jsonl] Generate timeline
rt-reg recover <HIVE> [--min-confidence LEVEL] Recover deleted keys
rt-reg carve <IMAGE> [--output DIR] Carve hives from images
rt-reg diff <HIVE> [--txlog LOG1 LOG2] Compare base vs replayed
rt-reg mount <HIVE> <MOUNTPOINT> FUSE mount
rt-reg verify <HIVE> [--txlog LOG1 LOG2] Integrity + anomaly check
```

### 6.2 Directory Mode

When `<PATH>` is a directory, `rt-reg` auto-discovers all hives:
- Known filenames (SYSTEM, SOFTWARE, NTUSER.DAT, SAM, SECURITY, Amcache.hve, etc.)
- "regf" magic scan for unknown filenames
- Companion txlog discovery (.LOG1/.LOG2 alongside each hive)
- Companion .regtrans-ms discovery

### 6.3 Output Formats

All commands support `--format`:

| Format | Description | Default when |
|--------|-------------|--------------|
| `table` | Aligned columns, colors | TTY output |
| `json` | Pretty-printed JSON | — |
| `jsonl` | One JSON object per line | Piped output |
| `csv` | Comma-separated values | — |
| `bodyfile` | Sleuth Kit bodyfile | Timeline only |

### 6.4 Global Flags

```
--txlog <LOG1> [LOG2]     Replay transaction logs before processing
--no-color                Disable colored output
--quiet                   Suppress progress indicators
--verbose                 Show debug information
--threads <N>             Number of parallel threads (default: num_cpus)
```

---

## 7. Python Bindings

### 7.1 API Surface

```python
import winreg_forensic as wrf

# Open hive (mmap'd)
hive = wrf.Hive("SYSTEM")
hive = wrf.Hive("SYSTEM", txlogs=["SYSTEM.LOG1", "SYSTEM.LOG2"])

# Properties
hive.hive_type        # HiveType.System
hive.version          # "1.5"
hive.root_key()       # Key object

# Key navigation
key = hive.open_key("ControlSet001\\Services\\BITS")
key.name              # "BITS"
key.path              # "ControlSet001\\Services\\BITS"
key.timestamp         # datetime
key.subkeys()         # list[Key]
key.values()          # list[Value]
key.value("Start")    # Value object

# Value access
val.name              # "Start"
val.data_type         # "REG_DWORD"
val.data              # 3 (auto-decoded based on type)
val.raw_data          # bytes

# Artifact decoders (returns list of dicts for pandas compatibility)
findings = wrf.decode(hive)
findings = wrf.decode(hive, decoders=["shimcache", "services"])

# Directory mode
findings = wrf.decode_directory("./case/registry/")

# Timeline
events = wrf.timeline([hive1, hive2])
wrf.write_csv(events, "timeline.csv")
wrf.write_bodyfile(events, "timeline.body")

# Deleted recovery
recovered = wrf.recover(hive, min_confidence="medium")

# Carving
for carved in wrf.carve("disk.raw"):
    print(f"{carved.hive_type} at offset {carved.offset}")
```

### 7.2 Implementation

PyO3 with `#[pymodule]`. Findings return as Python dicts (not custom PyO3 classes) for
native compatibility with `pandas.DataFrame()`, `json.dumps()`, and existing Python
forensic scripts.

---

## 8. Feature Flags

```toml
[features]
default = ["full"]
full = ["recover", "carve", "artifacts-all", "timeline", "fuse", "python"]

# Core capabilities (always compiled)
# winreg-format and winreg-core have no feature flags

# Optional capabilities
recover = []
carve = []
timeline = []
fuse = ["dep:fuser"]
python = ["dep:pyo3"]

# Per-hive artifact modules
artifacts-all = [
    "artifacts-system", "artifacts-software", "artifacts-ntuser",
    "artifacts-sam", "artifacts-security", "artifacts-amcache",
    "artifacts-usrclass", "artifacts-bcd"
]
artifacts-system = []
artifacts-software = []
artifacts-ntuser = []
artifacts-sam = []
artifacts-security = []
artifacts-amcache = []
artifacts-usrclass = []
artifacts-bcd = []
```

All features enabled by default. Feature flags exist for downstream crates that need
only a subset (e.g., `rt-parser-registry` may only need specific hive modules).

---

## 9. Testing Strategy

### 9.1 Test Hive Builder

Shared test infrastructure for constructing valid in-memory REGF hives:

```rust
pub struct TestHiveBuilder { ... }

impl TestHiveBuilder {
    pub fn new() -> Self;
    pub fn add_key(self, path: &str) -> Self;
    pub fn add_value(self, key_path: &str, vtype: ValueType, data: &[u8]) -> Self;
    pub fn with_deleted_key(self, path: &str) -> Self;   // Creates then frees
    pub fn build(self) -> Hive<Cursor<Vec<u8>>>;
}
```

### 9.2 Testing Levels

**Unit tests:** Every module has `#[cfg(test)]` tests. Every decoder tests at least:
- Happy path with known-good synthetic data
- Missing key path (returns empty vec, not error)
- Malformed binary data (returns error or skips gracefully)

**Golden tests:** Decode fixture hives, compare output against RegRipper/RECmd baseline.
Tests run `rt-reg decode --format jsonl` on each fixture and diff against `.expected.jsonl`.

**Property-based tests (proptest):** Core parser roundtrip properties — any valid structure
that parses must re-serialize to identical bytes.

**Fuzz targets (cargo-fuzz):**
- `parse_hive` — `Hive::from_bytes(arbitrary)`
- `parse_cell` — `CellReader::read_cell(arbitrary offset)`
- `replay_txlog` — `replay_transaction_logs(corrupt log)`
- `recover_deleted` — `scan_free_cells(corrupt hive)`
- `decode_value` — `Value::as_string()` / `as_u32()` / etc. on garbage

**Benchmarks (criterion):**
- Full hive parse (<500ms for 50MB SYSTEM)
- Artifact decode (<2s for all decoders on a hive)
- Deleted recovery scan (<1s parallel for 50MB hive)

### 9.3 CI Pipeline

- `cargo fmt --check`
- `cargo clippy -- -D warnings`
- `cargo test --all-features`
- `cargo fuzz run` (nightly, time-bounded)
- `cargo bench` (performance regression detection)
- Python: `maturin develop && pytest`

---

## 10. Dependency Summary

| Crate | Purpose | Used in |
|-------|---------|---------|
| `binrw` | Declarative binary struct parsing | winreg-format |
| `bitflags` | Flag type definitions | winreg-format |
| `memmap2` | Memory-mapped file I/O | winreg-core, winreg-carve |
| `miette` | Rich diagnostic errors with byte spans | winreg-core |
| `thiserror` | Ergonomic error type derivation | all crates |
| `chrono` | Timestamp handling (FILETIME → DateTime) | winreg-core, winreg-artifacts |
| `serde` + `serde_json` | Serialization for Finding detail field | winreg-artifacts, winreg-timeline |
| `rayon` | Parallel iteration for recovery scanning | winreg-recover |
| `clap` | CLI argument parsing | rt-reg |
| `csv` | CSV output | winreg-timeline |
| `fuser` | FUSE filesystem (optional) | winreg-fuse |
| `pyo3` | Python bindings (optional) | winreg-py |
| `proptest` | Property-based testing | dev-dependency |
| `criterion` | Benchmarks | dev-dependency |
| `tempfile` | Temporary files for tests | dev-dependency |

---

## 11. Issen Integration

### 11.1 Integration Crate

```
Issen/crates/rt-parser-registry/
├── src/
│   ├── lib.rs          # ForensicParser trait implementation
│   ├── source.rs       # Hive discovery from ArtifactSources
│   └── bridge.rs       # Finding → ParsedArtifact conversion
└── Cargo.toml          # deps: winreg-core, winreg-artifacts, rt-core
```

### 11.2 Dependency Direction

```
winreg-forensic (standalone)          Issen (monorepo)
─────────────────────────            ──────────────────────
winreg-format                         rt-core
    ↑                                    ↑
winreg-core ─────────────────────→ rt-parser-registry
    ↑                                    ↑
winreg-artifacts ────────────────→ rt-parser-registry
    ↑
winreg-recover
    ↑
winreg-carve
```

winreg-forensic has zero dependency on Issen. Issen depends on
winreg-forensic via git dependency or path dependency during development.

---

## 12. Research Inputs

This design synthesizes findings from the following research documents:

- `research/regf-binary-format-specification.md` (1,269 lines) — Complete REGF format
- `research/registry-forensic-artifacts-complete-catalog.md` (1,537 lines) — All hive artifacts
- `research/registry-crate-source-analysis.md` (1,218 lines) — 9 existing tools analyzed
- `research/registry-recovery-carving-antiforensics.md` (824 lines) — Recovery techniques
- `research/usnjrnl-forensic-architecture-patterns.md` (511 lines) — Architecture reference
- `research/registry-forensic-tools-matrix.md` (869 lines) — Tool comparison
- `research/registry-file-access-artifacts.md` (1,057 lines) — File access artifacts
- `research/third-party-app-registry-forensics.md` (1,383 lines) — Third-party app artifacts
- `research/encryption-and-antifore-registry-artifacts.md` (1,217 lines) — Encryption/anti-forensics
- `research/lolrmm-registry-paths-complete.md` (274 lines) — RMM tool registry paths
- `research/pyrsistencesniper-persistence-detection.md` — 117 persistence checks
- `research/ntfs-8dot3-name-forensics.md` — 8.3 name anomaly techniques
