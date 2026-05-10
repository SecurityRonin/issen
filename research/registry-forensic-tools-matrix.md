# Windows Registry Forensic Tools -- Comprehensive Feature Matrix

**Research Date:** 2026-03-24
**Purpose:** Inform development of a best-in-class registry parser

---

## Table of Contents

1. [Tool Feature Matrix](#1-tool-feature-matrix)
2. [Detailed Tool Profiles](#2-detailed-tool-profiles)
3. [REGF Format Essentials](#3-regf-format-essentials)
4. [Transaction Log Handling](#4-transaction-log-handling)
5. [Deleted Key/Value Recovery](#5-deleted-keyvalue-recovery)
6. [Registry Carving](#6-registry-carving)
7. [Timeline Analysis](#7-timeline-analysis)
8. [Registry Redirection, Virtualization & Virtual Hives](#8-registry-redirection-virtualization--virtual-hives)
9. [Registry Diff/Comparison](#9-registry-diffcomparison)
10. [Gap Analysis -- What No Tool Does Well](#10-gap-analysis----what-no-tool-does-well)

---

## 1. Tool Feature Matrix

| Capability | notatin | RegRipper 3.0 | nt-hive | nt_hive2 | regf (crate) | Registry Explorer / RECmd | libregf | yarp | python-registry |
|---|---|---|---|---|---|---|---|---|---|
| **Language** | Rust | Perl | Rust | Rust | Rust | C# (.NET) | C | Python | Python |
| **License** | Apache-2.0 | MIT | GPL-2.0+ | GPL-3.0 | MIT | Free (closed) | LGPLv3+ | GPL-3.0 | Apache-2.0 |
| **Cross-platform** | Yes | Yes (Perl) | Yes | Yes | Yes | Windows only | Yes | Yes | Yes |
| **Library / API** | Yes | No (scripts) | Yes | Yes | Yes | No (GUI+CLI) | Yes | Yes | Yes |
| **Python bindings** | Yes (pynotatin) | N/A (is Perl) | No | No | No | No | Yes (pyregf) | N/A (is Python) | N/A (is Python) |
| **no_std support** | No | No | Yes | No | No | No | No | No | No |
| **Read keys/values** | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes |
| **Write support** | No | No | Basic in-memory | No | **Yes (full)** | No | No | No | No |
| **Transaction log replay** | Yes | **No** | No | Yes (via dfir-toolkit) | Yes | Yes (rla.exe) | No | Yes | No |
| **Deleted key recovery** | Yes | No | No | Yes | No | Yes | No | Yes | Partial |
| **Deleted value recovery** | Yes | No | No | Yes | No | Yes | No | Yes | Partial |
| **Modified/versioned recovery** | Yes | No | No | No | No | Yes | No | Yes (via logs) | No |
| **Value slack exposure** | Yes (JSONL) | No | No | No | No | Yes | No | Yes | No |
| **Hive carving (disk)** | No | No | No | No | No | No | No | **Yes** | No |
| **Hive carving (memory)** | No | No | No | No | No | No | No | **Yes** | No |
| **Truncated hive support** | No | No | No | No | No | No | No | **Yes** | No |
| **Fragment reconstruction** | No | No | No | No | No | No | No | **Yes** | No |
| **Registry diff/compare** | **Yes (reg_compare)** | No | No | No | No | No | No | No | No |
| **Export: JSONL** | Yes | No | No | No | No | No | No | No | No |
| **Export: XLSX** | Yes | No | No | No | No | No | No | No | No |
| **Export: TSV** | Yes | No | No | No | No | No | No | No | No |
| **Export: EZ Common** | Yes | No | No | No | No | Yes | No | No | No |
| **Export: .reg text** | No | No | No | No | **Yes** | Yes | No | No | No |
| **Export: CSV** | No | No | No | No | No | Yes (RECmd) | No | No | No |
| **Export: bodyfile** | No | No | No | Yes (dfir-toolkit) | No | No | No | No | No |
| **Import: .reg text** | No | No | No | No | **Yes** | No | No | No | No |
| **FUSE mount** | No | No | No | No | No | No | **Yes** (regfmount) | **Yes** (yarp-mount) | No |
| **Offset/field info** | Yes (--full-field-info) | No | Yes (error bytes) | No | No | No | No | Yes | Yes (low-level) |
| **Plugin/artifact system** | No | **Yes (300+)** | No | No | No | **Yes (plugins)** | No | No | No |
| **Batch processing** | Yes (--recurse) | Yes (-a, profiles) | No | No | No | Yes (--bn) | No | No | No |
| **Recursive hive scanning** | Yes | No | No | No | No | Yes (-d flag) | No | No | No |
| **Timeline extraction** | No | Yes (TLN plugins) | No | Yes (hivescan bodyfile) | No | No | No | **Yes** (yarp-timeline) | No |
| **SQLite interface** | No | No | No | No | No | No | No | **Yes** | No |
| **Zero-copy parsing** | No | No | **Yes** | No | No | No | No | No | No |
| **Binary search (key lookup)** | No | No | **Yes** | No | No | Unknown | No | No | No |
| **Big data support** | Yes | No | Unknown | Unknown | Unknown | Yes | Unknown | Yes | Unknown |
| **Hive version support** | Modern | Modern | NT 4.0 -- Win 10 | Modern | Modern | Modern | Modern | 1.1--1.6 (NT 3.1+) | Modern |
| **Active development** | Yes | Occasional | Yes | Yes | New (v0.1) | Yes | Slow | Yes | Slow |
| **GitHub stars** | 41 | 687 | 53 | (in dfir-toolkit) | New | N/A (closed) | 133 | 137 | 441 |

---

## 2. Detailed Tool Profiles

### 2.1 notatin (Stroz Friedberg / LevelBlue)

**Repository:** https://github.com/strozfriedberg/notatin
**Crate:** https://crates.io/crates/notatin (v1.0.1)

**What makes it special:**
- The most complete Rust-based forensic registry parser available today
- First-class transaction log support with automatic detection and replay
- Comprehensive deleted/modified key and value recovery
- Built-in registry diff tool (reg_compare) -- unique among all tools
- Python bindings (pynotatin) bridge the Rust/Python ecosystem gap
- Export to Eric Zimmerman's Common format for interop with the EZ ecosystem
- Full field offset/length info in JSONL output for low-level analysis
- `--recovered-only` mode for focusing on forensic artifacts
- 100% safe Rust, no `unsafe` blocks

**Components:**
1. `notatin` -- core library crate
2. `reg_dump` -- export utility (JSONL, XLSX, TSV, Common format)
3. `reg_compare` -- diff/comparison tool (Regshot-like or unified diff output)
4. `pynotatin` -- Python bindings via PyO3/maturin

**API design:**
- `ParserBuilder` pattern for configuring parser options
- `.with_transaction_log(path)` to attach log files
- `.recover_deleted(true)` to enable recovery
- Prefix-order iteration by default; postorder available
- Filter support (regex and literal paths) applied at iteration time for performance

**Key limitations:**
- No hive carving capability
- No truncated/fragment hive support
- No hive writing
- No bodyfile/timeline output natively
- No FUSE mount
- No plugin/artifact interpretation system

---

### 2.2 RegRipper 3.0 (Harlan Carvey)

**Repository:** https://github.com/keydet89/RegRipper3.0

**What makes it special:**
- The gold standard for artifact extraction -- 300+ plugins covering virtually every forensic artifact
- Automated hive-type detection and plugin selection (`-a` switch)
- TLN (timeline) output mode via `-aT` for timeline plugins
- Deepest artifact knowledge base of any registry tool
- Used by SANS in official training and SIFT workstation

**Plugin categories by hive:**
| Hive | Key Plugins | Artifacts |
|------|-----------|-----------|
| SAM | `samparse` | User/group info, login counts, RIDs, password hints, account creation |
| SYSTEM | `compname`, `mountdev`, `services`, `bam`, `timezone`, `usbstor` | Computer name, mounted devices, services, Background Activity Monitor, timezone, USB history |
| SOFTWARE | `profilelist`, `appcompatcache`, `appinit`, `networklist`, `uninstall` | User profiles, shimcache, AppInit DLLs, network history, installed software |
| SECURITY | `secrets`, `auditpol` | LSA secrets, audit policy |
| NTUSER | `userassist`, `recentdocs`, `run`, `typedurls`, `shellbags`, `compdesc`, `mstsc` | Program execution, recent files, autorun, typed URLs, folder access, RDP connections |
| UsrClass | `shellbags` | Folder access history with timestamps |

**Key limitations:**
- Does NOT process transaction logs (must use yarp or rla.exe externally)
- Perl-based -- increasingly difficult to maintain and extend
- No deleted key recovery
- Output is text-only (no structured formats like JSON/CSV)
- Plugin quality varies (community-contributed, no formal testing)
- No library API -- script-only interface

**Alternative: RegRippy** (Airbus CERT) -- Python 3 rewrite using python-registry as backend.

---

### 2.3 nt-hive (Colin Finck)

**Repository:** https://github.com/ColinFinck/nt-hive
**Crate:** https://crates.io/crates/nt-hive (v0.3.0)

**What makes it special:**
- Designed for bootloader use (ReactOS) -- extreme performance focus
- `no_std` compatible (works in bare-metal and OS kernel environments)
- Zero-copy parsing via zerocopy crate -- minimal allocations
- Binary search for key lookups -- optimal for sorted subkey lists
- Static borrow checking -- no runtime overhead
- Basic in-memory write support (key/value modification)
- Platform and endian independent
- Hive format support: NT 4.0 through Windows 10

**API design:**
- `Hive::new(byte_slice)` -- works with any `SplitByteSlice`
- `root_key_node()` -> subpath navigation -> value access
- Iterators for idiomatic Rust usage
- Precise error reporting with faulty byte offsets
- No `unsafe` code anywhere

**Key limitations:**
- Read-focused (write is basic, not full REGF write)
- No transaction log support
- No deleted key/value recovery
- No forensic features (no carving, no timeline, no recovery)
- GPL-2.0 license limits commercial use
- Non-goal: full write support

---

### 2.4 nt_hive2 (Jan Starke / dfir-dd)

**Repository:** https://github.com/dfir-dd/nt-hive2 (moving to Codeberg)
**Crate:** https://crates.io/crates/nt_hive2 (v4.2.4)

**What makes it special:**
- Fork/replacement of nt-hive with forensic focus
- Uses BinRead for parsing (different approach from nt-hive's zerocopy)
- Adds last-written timestamp display
- Adds deleted cell recovery
- Integrated with dfir-toolkit (cleanhive, hivescan, regdump tools)

**dfir-toolkit registry tools:**
1. `cleanhive` -- merge transaction log files into a hive (creates clean hive)
2. `hivescan` -- scan hive with optional bodyfile output for timelining
3. `regdump` -- dump registry hive contents; supports --ignore-base-block for damaged hives

**Key limitations:**
- GPL-3.0 license
- Less mature than notatin for forensic completeness
- No carving
- No fragment/truncated hive support
- dfir-toolkit project is archived on GitHub (moved to Codeberg)

---

### 2.5 regf (Rust crate by peitaosu)

**Repository:** https://github.com/peitaosu/regf
**Crate:** https://crates.io/crates/regf (v0.1.0)

**What makes it special:**
- **Only Rust crate that supports full read AND write** of REGF files
- .reg text format import AND export
- Transaction log file support module
- Complete module architecture: hive, parser, writer, reg_export, reg_import, transaction_log, structures

**Modules:**
- `hive` -- High-level registry hive API
- `parser` -- Low-level parser for registry hive files
- `writer` -- Registry hive writer
- `reg_export` -- Export to .reg text format
- `reg_import` -- Import from .reg text files to binary hives
- `transaction_log` -- Transaction log file support
- `structures` -- Binary structures for REGF format
- `error` -- Error types

**Key limitations:**
- Very new (v0.1.0) -- likely immature
- MIT license (good for commercial use)
- No forensic-specific features (no deleted recovery, no carving)
- Small user base, unproven in production
- ~5.2K SLoC

---

### 2.6 Eric Zimmerman's Registry Explorer / RECmd

**Website:** https://ericzimmerman.github.io/
**RECmd GitHub:** https://github.com/EricZimmerman/RECmd
**Plugins:** https://github.com/EricZimmerman/RegistryPlugins

**What makes it special:**
- De facto industry standard for Windows registry forensics
- GUI (Registry Explorer) + CLI (RECmd) sharing the same backend
- Full deleted key/value recovery (enabled by default in RECmd)
- Value slack exposure
- Transaction log replay via rla.exe (included in package)
- Plugin system with rich artifact interpretation (ValueData2, ValueData3 columns)
- Batch mode with RECmd batch files (e.g., Kroll_Batch with 100+ artifact keys)
- Integration with KAPE for automated collection and processing
- Volume Shadow Copy support (`--vss` flag)
- JSON and CSV export
- Regex search across all loaded hives

**RECmd key flags:**
- `-f` / `-d` -- single file or directory (recursive hive discovery)
- `--bn` -- batch file for structured artifact extraction
- `--csv` -- CSV output directory
- `--json` -- JSON export
- `--recover` -- deleted key/value recovery (default: TRUE)
- `--vss` -- process Volume Shadow Copies
- `--nl` -- control transaction log replay behavior
- `--kn` / `--vn` / `--sk` / `--sv` -- key/value name and search options
- `--regex` -- treat searches as regular expressions

**Plugin architecture:**
- Plugins parse specific registry keys into structured columnar data
- ValueData, ValueData2, ValueData3 columns provide multi-field output
- Plugin-parsed rows marked with "(plugin)" in ValueType column
- Open-source plugin repository on GitHub

**Key limitations:**
- Windows-only (.NET/C#)
- Closed-source core (plugins are open)
- No library API for embedding
- No cross-platform support
- No hive writing
- No carving

---

### 2.7 libregf (libyal by Joachim Metz)

**Repository:** https://github.com/libyal/libregf

**What makes it special:**
- Part of the comprehensive libyal forensic library ecosystem
- C library with Python bindings (pyregf) via PyPI
- FUSE mount support (regfmount) -- mount hive as filesystem
- Included tools: regfinfo, regfexport, regfmount, regfreport
- Well-documented REGF format specification (in-repo ASCIIDoc)
- OSS Fuzz integration for robustness
- Packaged in major Linux distributions (Debian, Ubuntu, openSUSE)
- Used as a backend by many other forensic tools

**Tools:**
| Tool | Purpose |
|------|---------|
| `regfinfo` | Display hive file metadata (version, type) |
| `regfexport` | Export hive contents |
| `regfmount` | FUSE mount hive as filesystem |
| `regfreport` | Generate analysis reports |

**Key limitations:**
- Status: alpha (self-declared by author)
- No transaction log support
- No deleted key recovery
- Slow development pace
- Documentation quality is mixed (wiki exists but sparse)
- C codebase is harder to extend than Rust/Python

---

### 2.8 yarp -- Yet Another Registry Parser (Maxim Suhanov)

**Repository:** https://github.com/msuhanov/yarp

**What makes it special:**
- **Most complete forensic feature set of any registry parser**
- Written by the author of the definitive REGF format specification
- Only tool that does BOTH disk AND memory carving of registry hives
- Handles truncated/carved/fragmented hive files
- Fragment reconstruction via brute-force and NTFS-aware approaches
- Transaction log support with intermediate state exploration (callback API)
- Deleted key/value recovery
- Timeline extraction from all hive states observed in transaction logs
- Remnant data from transaction log slack space
- SQLite interface for advanced querying
- FUSE mount support (yarp-mount)
- Cython acceleration available

**Tools:**
| Tool | Purpose |
|------|---------|
| `yarp-print` | Print keys/values with deleted recovery, transaction log replay, truncated hive support |
| `yarp-timeline` | Extract timestamps from all hive states, including TX log intermediate states |
| `yarp-carver` | Carve registry files and fragments from disk images (NTFS-aware) |
| `yarp-memcarver` | Carve registry fragments from memory images |
| `yarp-mount` | FUSE mount a registry hive |

**Carving capabilities:**
- Locates and rebuilds fragmented registry files
- Brute-force reconstruction + NTFS-aware carving (scans for MFT data runs)
- ~10-25% of fragmented registry files successfully reconstructed
- Identifies standalone (freestanding) hive bins

**Key limitations:**
- Python-only (performance ceiling for large datasets)
- GPL-3.0 license
- No structured export formats (JSONL, CSV, XLSX)
- No plugin/artifact interpretation system
- No registry diff/compare
- No write support

---

### 2.9 python-registry (Will Ballenthin)

**Repository:** https://github.com/williballenthin/python-registry

**What makes it special:**
- Pioneer library for cross-platform Python registry access
- Dual API: high-level (RegistryKey/RegistryValue) + low-level (HBIN blocks, cells)
- Foundation for RegRippy and many other Python forensic tools
- Pure Python -- no compiled dependencies
- Well-designed API modeled after Windows Registry API (familiar to analysts)
- Sample forensic scripts included (forensicating.py)
- Used by Mandiant for incident response

**API design:**
```python
from Registry import Registry
reg = Registry.Registry("NTUSER.DAT")
key = reg.open("Software\\Microsoft\\Windows\\CurrentVersion\\Run")
for value in key.values():
    print(f"{value.name()}: {value.value()}")
```

- `Registry.RegistryHive(path)` -- load a hive
- `reg.open(path)` -- navigate to key
- `key.subkeys()` / `key.values()` -- iterate children
- `key.timestamp()` -- LastWrite time
- Low-level: `RegistryParse` module exposes HBIN, Cell, Record objects

**Key limitations:**
- Read-only
- No transaction log support
- Basic/partial deleted key recovery (unallocated cell parsing exists but limited)
- No carving
- No structured export
- Slow for large hives (pure Python)
- Maintenance is slow (last significant updates years ago)
- No timeline output

---

## 3. REGF Format Essentials

**Definitive specification:** https://github.com/msuhanov/regf

### 3.1 File Structure

```
[Base Block - 4096 bytes]
[Hive Bin 0 (hbin) - n*4096 bytes]
  [Cell] [Cell] [Cell] ...
[Hive Bin 1 (hbin) - n*4096 bytes]
  [Cell] [Cell] [Cell] ...
...
[Optional padding / remnant data]
```

### 3.2 Base Block (Header)

| Field | Size | Description |
|-------|------|-------------|
| Signature | 4 | "regf" ASCII |
| Primary sequence number | 4 | Incremented at end of write |
| Secondary sequence number | 4 | Must match primary after successful write |
| Last written timestamp | 8 | FILETIME (UTC) |
| Major version | 4 | Always 1 |
| Minor version | 4 | 1-6 (3=NT3.5, 5=WinXP/2003, 6=Vista+) |
| Type | 4 | 0=primary file, 1=transaction log |
| Format | 4 | 1=direct memory load |
| Root cell offset | 4 | Offset from start of hive bins data |
| Hive bins data size | 4 | Total size of all hive bins |
| Clustering factor | 4 | Typically 1 (sector size / 512) |
| File name | 64 | UTF-16LE original hive path |
| Checksum | 4 | XOR-32 of first 508 bytes |

**Dirty hive detection:** A hive is dirty when checksum is wrong OR primary sequence != secondary sequence.

### 3.3 Cell Types

| Record | Signature | Description |
|--------|-----------|-------------|
| Key Node | `nk` | Registry key with timestamps, parent ref, subkey/value counts |
| Key Value | `vk` | Value name, data type, data offset/inline data |
| Key Security | `sk` | Security descriptor, doubly-linked list |
| Index Leaf | `li` | Simple subkey list |
| Fast Leaf | `lf` | Subkey list with 4-byte name hints |
| Hash Leaf | `lh` | Subkey list with 32-bit name hashes |
| Index Root | `ri` | List of subkey lists (for large key counts) |
| Big Data | `db` | Data segment list for values > 16344 bytes |

**Cell allocation:** Negative size = allocated; Positive size = unallocated (free). Size aligned to 8 bytes.

### 3.4 Data Types

| Value | Name | Description |
|-------|------|-------------|
| 0x00 | REG_NONE | No type |
| 0x01 | REG_SZ | Unicode null-terminated string |
| 0x02 | REG_EXPAND_SZ | String with environment variable references |
| 0x03 | REG_BINARY | Binary data |
| 0x04 | REG_DWORD | 32-bit little-endian integer |
| 0x05 | REG_DWORD_BIG_ENDIAN | 32-bit big-endian integer |
| 0x06 | REG_LINK | Unicode symbolic link |
| 0x07 | REG_MULTI_SZ | Array of null-terminated strings |
| 0x08 | REG_RESOURCE_LIST | Resource list |
| 0x09 | REG_FULL_RESOURCE_DESCRIPTOR | Full resource descriptor |
| 0x0A | REG_RESOURCE_REQUIREMENTS_LIST | Resource requirements list |
| 0x0B | REG_QWORD | 64-bit little-endian integer |

**Inline data optimization:** When data <= 4 bytes, the most significant bit of data size is set to 1, and data is stored directly in the data offset field (no separate cell needed).

### 3.5 Key Node Flags

| Bit | Name | Description |
|-----|------|-------------|
| 0x0001 | KEY_VOLATILE | Volatile key (not written to disk) |
| 0x0002 | KEY_HIVE_EXIT | Mount point |
| 0x0004 | KEY_HIVE_ENTRY | Root key of a hive |
| 0x0008 | KEY_NO_DELETE | Cannot be deleted |
| 0x0010 | KEY_SYM_LINK | Symbolic link |
| 0x0020 | KEY_COMP_NAME | Key name is ASCII (not UTF-16LE) |
| 0x0040 | KEY_PREDEF_HANDLE | Predefined handle |
| 0x0080 | KEY_VIRT_MIRRORED | Virtualization mirrored |
| 0x0100 | KEY_VIRT_TARGET | Virtualization target |
| 0x0200 | KEY_VIRTUAL_STORE | Virtual store key |

---

## 4. Transaction Log Handling

### 4.1 Log Schemes

| Scheme | Files | Windows Version | Description |
|--------|-------|----------------|-------------|
| None | -- | -- | No fault tolerance |
| Single log | *.LOG | Pre-Vista | One log file, overwritten on each transaction |
| Dual log | *.LOG1, *.LOG2 | Vista+ | Circular dual-logging for crash resilience |

### 4.2 Old Format (Pre-Vista)

Structure: Base block backup + dirty vector (bitmap) + dirty pages
- Bitmap indicates which 4KB pages are present in the log
- Pages follow in order after the bitmap
- Start of file is frequently overwritten -- difficult to recover old data

### 4.3 New (Incremental) Format (Vista+)

Structure: Base block + log entries (each with sequence number + dirty pages)
- Log entries are appended, not overwritten
- Each entry has a sequence number for ordering
- Kernel may delay writing to primary file up to 1 hour
- Primary hive on disk can be significantly stale ("dirty")
- Multiple intermediate states recoverable from log entries

### 4.4 Recovery Process

1. Check if primary file is dirty (checksum mismatch or sequence mismatch)
2. If primary has valid base block: apply entries from BOTH log files (earlier first)
3. If primary has invalid base block: use only the log with latest entries
4. Sort writes by sequence number descending for deleted entry discovery

### 4.5 Tool Support for Transaction Logs

| Tool | Replay | Intermediate States | Log Parsing | Auto-detect Format |
|------|--------|--------------------|-----------|--------------------|
| notatin | Yes | No | Yes | Yes |
| yarp | Yes | **Yes** (callback API) | Yes | Yes (auto mode) |
| RECmd / rla.exe | Yes | No | Yes | Yes |
| dfir-toolkit (cleanhive) | Yes | No | Yes | Unknown |
| regf crate | Module exists | Unknown | Yes | Unknown |
| RegRipper | **No** | No | No | No |
| nt-hive | No | No | No | No |
| python-registry | No | No | No | No |
| libregf | No | No | No | No |

### 4.6 Transactional Registry (TxR)

- Separate from .LOG transaction logs
- Uses CLFS (Common Log File System) format
- Stored in `%SystemRoot%\System32\config\TxR\`
- Files: `<hive><GUID>.TxR.<number>.regtrans-ms`
- Used by applications for atomic compound registry operations
- Logs NOT automatically cleared -- forensic goldmine for historical data
- Common use: application installers (rollback on failure)

---

## 5. Deleted Key/Value Recovery

### 5.1 How Deletion Works

When a registry key or value is deleted:
1. The cell's size field sign flips (negative -> positive), marking it as unallocated
2. Adjacent unallocated cells may be coalesced into a single larger free cell
3. The cell data (nk/vk records) is NOT zeroed -- it remains as remnant data
4. References from parent keys are removed
5. In Windows 2000: a free-list pointer was written to cell data; from XP onward, this is not done

### 5.2 Recovery Techniques

**Basic approach:**
1. Scan all cells in hive (allocated and unallocated)
2. In unallocated cells, look for nk/vk signatures
3. Parse record structures from remnant data
4. Validate references (may point to overwritten cells -- false positive risk)

**Advanced approach (Mandiant):**
1. Parse ALL cells and determine type and data size
2. Enumerate allocated cells to find referenced value lists, class names, security records
3. Find referenced deleted values from deleted keys
4. Search remaining unallocated cells for unreferenced deleted value cells
5. Find referenced data cells from all deleted values
6. Compare against original hive to identify truly deleted entries
7. Process cell slack space for additional remnants

**Transaction log recovery:**
- Overwritten values may survive in transaction logs even when unrecoverable from the primary hive
- Sort log writes by sequence number (descending) and parse allocated/unallocated cells

### 5.3 Tool Support for Deleted Recovery

| Tool | Deleted Keys | Deleted Values | Prior Versions | Slack Space | Validation Quality |
|------|-------------|---------------|----------------|------------|-------------------|
| notatin | Yes | Yes | Yes | Yes (JSONL) | Good |
| yarp | Yes | Yes | Yes (via logs) | Yes | Good |
| Registry Explorer / RECmd | Yes | Yes | Yes | Yes | Excellent |
| nt_hive2 | Yes | Unknown | No | No | Basic |
| python-registry | Partial | Partial | No | No | Basic |
| RegRipper | No | No | No | No | N/A |
| nt-hive | No | No | No | No | N/A |
| libregf | No | No | No | No | N/A |
| regf crate | No | No | No | No | N/A |

### 5.4 Challenges

- **Cell coalescing:** Adjacent deleted cells merge, obscuring boundaries
- **Overwritten data:** Freed cells may be reused before recovery attempt
- **False positives:** References from deleted cells may point to overwritten data
- **No signature for data cells:** Value data and value lists lack magic numbers -- type must be inferred
- **SSD TRIM:** On SSDs, deleted data may be physically erased

---

## 6. Registry Carving

### 6.1 Disk Carving

**Only tool with dedicated support: yarp (yarp-carver)**

Approach:
1. Scan raw disk image for `regf` signature (base block) and `hbin` signatures
2. Validate structural integrity of found artifacts
3. For fragmented hives:
   - Extract first fragment (truncated registry file)
   - Identify truncation/fragmentation point
   - Attempt reconstruction via brute-force matching of hive bins
   - NTFS-aware carving: scan for MFT mapping pairs/data runs to find non-contiguous fragments
4. Extract standalone (freestanding) hive bins that don't have a base block

**Success rate:** ~10-25% of fragmented registry files can be reconstructed

### 6.2 Memory Carving

**Tools:**
- **yarp (yarp-memcarver):** Carves registry fragments from memory images (standalone hive bins or keys/values)
- **Volatility Framework:** `windows.hivelist` plugin lists registry hives in memory; `printkey`, `hivedump` extract content

**Technique:**
1. Scan memory dump for `hbin` signatures
2. Validate hive bin headers (size, offset consistency)
3. Parse cells within found bins
4. Reconstruct hive structure from found bins

### 6.3 Additional Sources

- **hiberfil.sys:** Contains RAM snapshot from hibernation -- registry hives may be carved
- **pagefile.sys:** May contain paged-out registry data
- **Volume Shadow Copies:** Historical snapshots of registry hive files

---

## 7. Timeline Analysis

### 7.1 Data Sources

Registry keys have a single timestamp: **LastWrite time** (analogous to file modification time). Values do NOT have individual timestamps.

### 7.2 Approaches

**Bodyfile method:**
1. Extract LastWrite timestamps from all keys into bodyfile format
2. Merge with filesystem bodyfile (from fls/TSK)
3. Process with mactime to generate chronological timeline
4. Tool: `regtime.pl` (Harlan Carvey) or dfir-toolkit's `hivescan`

**TLN (Timeline) format:**
- RegRipper TLN plugins output in 5-field pipe-delimited format
- Fields: Time|Source|Host|User|Description

**Super Timeline (log2timeline/plaso):**
- Incorporates registry timestamps alongside event logs, file timestamps, browser history, etc.
- Processes registry hives via built-in parsers

**yarp-timeline approach:**
- Extracts timestamps from ALL hive states observed in transaction log files
- Can show "before" (dirty) and "after" (recovered) states
- Includes remnant data from transaction log slack space
- Handles truncated/carved files

### 7.3 Tool Support

| Tool | Timeline Output | Format | TX Log States | Super Timeline |
|------|----------------|--------|---------------|----------------|
| yarp-timeline | Yes | Custom | **Yes** (all intermediate) | No |
| dfir-toolkit (hivescan) | Yes | bodyfile | Via cleanhive | Via mactime2 |
| RegRipper | Yes | TLN | No | Via log2timeline |
| RECmd | Indirect | CSV timestamps | Via rla.exe | Via plaso |
| notatin | No (JSONL has timestamps) | -- | -- | -- |

---

## 8. Registry Redirection, Virtualization & Virtual Hives

### 8.1 WOW6432Node (Registry Redirection)

**What:** On 64-bit Windows, 32-bit application registry access is transparently redirected.

**Mechanism:**
- 32-bit app accesses `HKLM\Software\<key>` -> redirected to `HKLM\Software\WOW6432Node\<key>`
- Applies to specific keys under HKLM\Software (not all)
- Some keys are shared (not redirected), some are reflected

**Forensic impact:**
- **Must check BOTH locations** for persistence mechanisms (e.g., Run keys)
- `Software\Microsoft\Windows\CurrentVersion\Run` AND `Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run`
- Missing either location means potentially missing malware persistence
- Registry tools should surface both views or flag redirection

### 8.2 UAC Registry Virtualization

**What:** Legacy 32-bit apps without a UAC manifest that try to write to protected areas get transparently redirected.

**Mechanism:**
- Write to `HKLM\Software\<key>` -> redirected to `HKCU\Software\Classes\VirtualStore\Machine\Software\<key>`
- Stored in user's UsrClass.dat hive (`%LocalAppData%\Microsoft\Windows\UsrClass.dat`)
- On reads: merged view (virtual values take precedence over global values)
- Only applies to: non-elevated, 32-bit, non-manifest legacy apps

**Forensic impact:**
- VirtualStore may contain evidence of application activity invisible in HKLM
- UsrClass.dat must be collected and analyzed
- VirtualStore data does NOT roam with roaming profiles

**Flags on keys:**
- `REG_KEY_DONT_VIRTUALIZE` -- disables virtualization for a key
- `REG_KEY_DONT_SILENT_FAIL` -- fail instead of redirect
- `REG_KEY_RECURSE_FLAG` -- inherit flag to subkeys

### 8.3 Application Hives (RegLoadAppKey)

**What:** API allowing any process (no admin required) to load a private registry hive.

**Key facts:**
- Loaded under `\Registry\A\` (not under MACHINE or USER)
- Cannot be enumerated -- private to loading process
- No privilege escalation required to load
- Auto-unloaded when all handles closed
- Windows 8+: multiple app hives per process; Windows 7: one at a time
- Security is file-based, not per-key

**Forensic impact:**
- App hives invisible to normal registry enumeration
- Used by UWP/Immersive apps for activation data and settings
- Past vulnerabilities (MS16-111) allowed cross-app hive access
- Offline Registry Library (Offreg.dll) can manipulate hives without registry API -- **invisible to ProcMon and ETW**
- Potential persistence mechanism that evades common monitoring

### 8.4 Layered Keys (Windows 10+)

Modern Windows uses layered key composition for:
- Differencing hives in containers (Docker/Windows Sandbox)
- Composed registry views from multiple hive layers
- Relevant key node flags: layered key flags in nk record

---

## 9. Registry Diff/Comparison

### 9.1 Dedicated Tools

| Tool | Type | Features |
|------|------|----------|
| **notatin reg_compare** | Offline diff | Compare two hive files or trees; Regshot-like or unified diff output |
| **Regshot** | Live snapshot diff | Before/after snapshots; text/HTML reports; also tracks filesystem changes |
| **NirSoft RegistryChangesView** | Live snapshot diff | Compare snapshots; export to .reg file |
| **InstallWatch Pro** | Install monitor | Registry + file + folder change tracking during installs |
| **WhatChanged** | Live diff | Lightweight portable snapshot comparison |
| **Process Monitor** | Real-time | Continuous logging of all registry operations (not diff-based) |

### 9.2 Forensic Diff Approaches

1. **Hive-to-hive comparison:** Compare current hive to Volume Shadow Copy version (notatin reg_compare ideal for this)
2. **Timeline-based:** Extract timestamps and identify clusters of changes
3. **Log replay:** Compare hive states before and after transaction log application

---

## 10. Gap Analysis -- What No Tool Does Well

These are capabilities that are either missing entirely or poorly served across ALL existing tools:

### 10.1 Unmet Needs

| Gap | Description | Opportunity |
|-----|-------------|-------------|
| **Unified carving + recovery + timeline** | No single tool does carving, deleted recovery, TX log replay, AND timeline in one pass | Build integrated pipeline |
| **Structured export from carved hives** | yarp carves but outputs text; notatin exports structured but doesn't carve | Add carving to notatin-like architecture |
| **Cross-platform GUI** | Registry Explorer is Windows-only; no cross-platform GUI exists | Web UI or Tauri/egui desktop app |
| **Memory-resident hive analysis** | Only Volatility + yarp-memcarver; no Rust-based solution | Rust memory carver module |
| **App hive discovery** | No forensic tool specifically targets RegLoadAppKey artifacts | Scan for orphan hive files, correlate with process data |
| **Transactional Registry (TxR/CLFS) parsing** | No tool fully parses TxR regtrans-ms files in a forensic context | Add CLFS parser |
| **Full write support in forensic parser** | regf crate is too new; no mature Rust lib does read+write+forensics | Combine notatin forensics + regf write capability |
| **Registry anomaly detection** | No tool flags structural anomalies (corrupted cells, inconsistent references, anti-forensic manipulation) | Integrity checker module |
| **Streaming/incremental parsing** | All tools load-then-parse; no streaming parser for very large hives or disk streams | Iterator-based streaming architecture |
| **WOW6432Node correlation** | No tool automatically correlates 32/64-bit key pairs or flags redirection | Auto-detect and present merged/split views |
| **VirtualStore correlation** | No tool automatically resolves UAC virtualization merging | Auto-merge VirtualStore with base key view |
| **Layered key composition** | Container/sandbox layered hives not handled by any forensic tool | Differencing hive support |

### 10.2 Best-of-Breed Synthesis

A world-class registry parser should combine:

1. **notatin's** architecture: safe Rust, cross-platform, Python bindings, diff tool, multiple export formats, field offset info
2. **yarp's** forensic completeness: carving, fragment reconstruction, truncated hive support, intermediate TX log state exploration, memory carving
3. **nt-hive's** performance: zero-copy, no_std, binary search for key lookups
4. **regf crate's** write support: full read/write/import/export capability
5. **RegRipper/RECmd's** artifact knowledge: plugin system for forensic artifact interpretation
6. **Registry Explorer's** UX: deleted recovery with visual indicators, batch processing, VSS support

### 10.3 Recommended Architecture for "World's Best Parser"

```
Core Library (Rust, no_std optional):
  +-- REGF Parser (zero-copy, streaming)
  +-- REGF Writer (full write support)
  +-- Transaction Log Parser (old + new format, intermediate states)
  +-- Deleted Cell Recovery Engine
  +-- Hive Carver (disk + memory, NTFS-aware)
  +-- Fragment Reconstructor
  +-- Diff Engine (key-level + value-level)
  +-- Timeline Generator (bodyfile, JSONL)
  +-- Anomaly Detector (structural integrity checks)
  +-- WOW6432Node Resolver
  +-- VirtualStore Merger

Bindings:
  +-- Python (PyO3)
  +-- C FFI
  +-- WASM (for web UI)

Export Formats:
  +-- JSONL (with field offsets)
  +-- XLSX / CSV / TSV
  +-- .reg text
  +-- bodyfile (mactime compatible)
  +-- EZ Common format
  +-- SQLite

CLI Tools:
  +-- reg_dump (export/recovery)
  +-- reg_compare (diff)
  +-- reg_carve (disk/memory carving)
  +-- reg_timeline (timeline generation)
  +-- reg_check (integrity/anomaly scanning)

Plugin System:
  +-- Artifact interpreters (Lua or WASM plugins)
  +-- Built-in: UserAssist, ShimCache, BAM, Services, USB, ShellBags, etc.
```

---

## Sources

### Primary Tool Repositories
- notatin: https://github.com/strozfriedberg/notatin
- RegRipper 3.0: https://github.com/keydet89/RegRipper3.0
- nt-hive: https://github.com/ColinFinck/nt-hive
- nt_hive2: https://github.com/dfir-dd/nt-hive2
- regf crate: https://crates.io/crates/regf
- RECmd: https://github.com/EricZimmerman/RECmd
- Registry Plugins: https://github.com/EricZimmerman/RegistryPlugins
- libregf: https://github.com/libyal/libregf
- yarp: https://github.com/msuhanov/yarp
- python-registry: https://github.com/williballenthin/python-registry
- dfir-toolkit: https://github.com/dfir-dd/dfir-toolkit
- RegRippy: https://github.com/airbus-cert/regrippy

### Format Specifications
- REGF format (msuhanov): https://github.com/msuhanov/regf/blob/master/Windows%20registry%20file%20format%20specification.md
- REGF format (libyal): https://github.com/libyal/libregf/blob/main/documentation/Windows%20NT%20Registry%20File%20(REGF)%20format.asciidoc
- REGF format (Project Zero): https://projectzero.google/2024/12/the-windows-registry-adventure-5-regf.html
- NIST Registry Forensic Tool Specification: https://www.nist.gov/document/windows-registry-forensic-tool-specification-draft-2-version-10

### Research & Articles
- Mandiant "Digging Up the Past": https://cloud.google.com/blog/topics/threat-intelligence/digging-up-the-past-windows-registry-forensics-revisited/
- Registry TX Logs (Suhanov blog): https://dfir.ru/2018/11/19/exploring-intermediate-states-of-a-registry-hive-using-transaction-log-files/
- Registry TX Logs (Carvey blog): http://windowsir.blogspot.com/2019/04/registry-transaction-logs-pt-ii.html
- Parsing Registry Hives with Python (Mandiant): https://cloud.google.com/blog/topics/threat-intelligence/parsing-registry-hives-python
- SANS Registry Timeline: https://www.sans.org/blog/digital-forensic-sifting-registry-and-filesystem-timeline-creation
- Registry Explorer SANS page: https://www.sans.org/tools/registry-explorer
- UAC Virtualization deep dive: https://trainsec.net/library/windows-internals/understanding-uac-virtualization/
- Microsoft Registry Virtualization: https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-virtualization
- Microsoft WOW64 Registry: https://learn.microsoft.com/en-us/windows/win32/winprog64/shared-registry-keys
- Microsoft RegLoadAppKey: https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regloadappkeya
- Praetorian persistence via registry internals: https://www.praetorian.com/blog/corrupting-the-hive-mind-persistence-through-forgotten-windows-internals/
- Cyber Triage 2025 Registry Forensics Guide: https://www.cybertriage.com/blog/windows-registry-forensics-2025/
- Recovering Deleted Registry Data (Morgan): https://www.sciencedirect.com/science/article/pii/S1742287608000303
- Registry in Memory (Dolan-Gavitt): https://www.sciencedirect.com/science/article/pii/S1742287608000297
