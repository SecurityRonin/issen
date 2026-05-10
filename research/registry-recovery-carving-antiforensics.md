# Windows Registry Recovery, Carving, and Anti-Forensic Detection

## Deep Research for winreg-forensic: A World-Class Rust Registry Forensic Parser

**Date:** 2026-03-27
**Purpose:** Technical reference for implementing recovery and forensic analysis capabilities in `~/src/winreg-forensic`

---

## Table of Contents

1. [Deleted Key/Value Recovery](#1-deleted-keyvalue-recovery)
2. [Transaction Log Replay](#2-transaction-log-replay)
3. [Transactional Registry (TxR)](#3-transactional-registry-txr)
4. [Registry Carving from Non-Hive Sources](#4-registry-carving-from-non-hive-sources)
5. [Anti-Forensic Detection](#5-anti-forensic-detection)
6. [Registry Virtualization and Layered Keys](#6-registry-virtualization-and-layered-keys)

---

## 1. Deleted Key/Value Recovery

### 1.1 How Windows Deletes Registry Keys

When a registry key or value is deleted, the Windows kernel does **not** zero out or overwrite the cell data. Instead, the following happens:

1. **Cell size sign flip**: The 4-byte size field at the start of each cell is flipped from negative (allocated) to positive (unallocated/free). A negative size indicates an allocated cell; a positive size indicates an unallocated (free) cell. ([msuhanov/regf specification](https://github.com/msuhanov/regf/blob/master/Windows%20registry%20file%20format%20specification.md))

2. **Cell coalescence**: If an adjacent cell is also unallocated, the kernel **merges** the two free cells into a single larger free cell. This changes the effective cell boundary and size, but the *data within* remains intact until overwritten by a future allocation. This coalescence behavior is the primary challenge for deleted key recovery, because the original cell boundaries are destroyed and must be inferred from the cell contents. ([Mandiant, "Digging Up the Past"](https://cloud.google.com/blog/topics/threat-intelligence/digging-up-the-past-windows-registry-forensics-revisited/))

3. **No data zeroing**: The actual NK (key node), VK (value node), and associated data bytes remain in the freed space. Only when a new allocation reuses that space is the old data overwritten, and even then only the portions actually written to.

4. **Deallocation is simultaneous for all related cells**: When a key is deleted, all of its associated cells (key node, value list, individual value cells, data cells, security descriptor references) are freed simultaneously. However, certain failure conditions can result in incomplete deallocation, leaving orphaned allocated cells. ([Mandiant, "Digging Up the Past"](https://cloud.google.com/blog/topics/threat-intelligence/digging-up-the-past-windows-registry-forensics-revisited/))

### 1.2 Distribution of Recoverable Deleted Data

According to Maxim Suhanov's research, the distribution of recoverable deleted data across different sources in primary hive files is:

| Source | Percentage |
|--------|-----------|
| Unallocated cells | 97.9% |
| Remnant data at end of file | 0.6% |
| Slack space in allocated/referenced cells | 1.5% |
| Allocated but unreferenced (orphan) cells | ~0% (extremely rare) |

([Suhanov, ZeroNights 2017](https://2017.zeronights.org/wp-content/uploads/materials/ZN17-Suhanov-Registry.pdf))

### 1.3 The Msuhanov/yarp Recovery Algorithm

The `RegistryRecover.py` module in [yarp](https://github.com/msuhanov/yarp) implements the following approach:

1. **Walk all hbins**: Iterate over every hive bin in the file
2. **Identify unallocated cells**: Cells with a positive size field are free
3. **Scan for NK/VK signatures**: Within each unallocated cell, search for the magic bytes `nk` (0x6E6B) and `vk` (0x766B) at expected offsets within the cell
4. **Apply plausibility constraints**: yarp defines upper bounds to filter false positives:
   - `MAX_PLAUSIBLE_SUBKEYS_COUNT = 10000`
   - `MAX_PLAUSIBLE_VALUES_COUNT = 1000`
   - `MAX_PLAUSIBLE_NAME_LENGTH = 1024`
5. **Validate structural fields**: Check that timestamps, parent key offsets, name lengths, and other fields are within reasonable ranges
6. **Reconstruct references**: For deleted keys, attempt to find their associated deleted values by following value list offsets (if they still point to unallocated cells with valid VK signatures)

([yarp/RegistryRecover.py](https://github.com/msuhanov/yarp/blob/master/yarp/RegistryRecover.py))

### 1.4 The Mandiant/FireEye Improved Algorithm (2024)

Mandiant's research produced a more sophisticated algorithm that significantly reduces false positives. Their approach:

**Phase 1: Full Cell Inventory**
1. Perform basic parsing for **all** allocated and unallocated cells
2. Determine cell type (NK, VK, SK, subkey list, value list, data) and data size where possible
3. Build a complete map of every cell in the hive and its status

**Phase 2: Allocated Cell Enumeration**
1. For allocated keys: find referenced value lists, class names, and security records
2. Populate data size of referenced cells
3. **Validate key ancestors** to determine if the key has been orphaned (allocated but unreachable from root)
4. For allocated values: find referenced data and populate data size
5. **Define all allocated cell slack space as additional unallocated cells** (this is key -- slack space within allocated cells is treated as a recovery source)

**Phase 3: Deleted Element Recovery**
1. Enumerate allocated keys and attempt to find deleted values in the values list
2. Attempt to find old deleted value references in **value list slack space**
3. Enumerate unallocated cells and find deleted key cells (NK signature scan)
4. Enumerate unallocated keys and attempt to define their referenced class names, security records, and values
5. Enumerate remaining unallocated cells for unreferenced deleted value cells
6. Enumerate unallocated values and find referenced data cells

**Key innovations over the simple algorithm:**
- Tracking ALL cells enables cross-validation (a deleted key's value list offset can be checked against known cell boundaries)
- Processing **slack space** within allocated cells recovers data that simpler algorithms miss entirely
- Orphan detection identifies allocated cells with valid data that are no longer reachable from the root key
- Reference validation prevents false positive associations when cells have been reused multiple times

([Mandiant, "Digging Up the Past: Windows Registry Forensics Revisited"](https://cloud.google.com/blog/topics/threat-intelligence/digging-up-the-past-windows-registry-forensics-revisited/))

### 1.5 Orphan Cell Detection

Orphaned cells are allocated cells that are not reachable from the root key through any chain of parent references. They can occur due to:

- **Incomplete deletion**: Certain failure conditions can leave cells allocated but unlinked
- **Key renaming**: In recent Windows 10 builds, renaming a key leaves the old key node in an allocated cell until the hive is defragmented. This is a particularly valuable forensic artifact as it preserves the previous name of renamed keys.
- **Hive corruption**: Partial writes or crashes can orphan subtrees

Detection algorithm:
1. Start from the root cell and recursively walk all subkey lists
2. Mark every reachable cell as "referenced"
3. Any allocated cell NOT in the referenced set is an orphan
4. Validate orphan cells by checking their internal structure (NK signature, timestamp validity, etc.)

Academic research by Kahvedžić and Kechadi (2009) in the *Journal of Digital Forensics, Security and Law* defined formal methods for correlating orphaned registry data structures and reconstructing their original context using data mining approaches that match values to their parents. ([Kahvedžić & Kechadi, 2009](https://commons.erau.edu/jdfsl/vol4/iss2/3/))

### 1.6 Slack Space Recovery

Slack space exists within allocated cells when the cell is larger than the data it contains. This happens because:

- Cells must be aligned to 8-byte boundaries
- When a cell is reused, the new data may be smaller than the previous occupant
- Subkey lists and value lists have fixed-size entries, and deletions can leave gaps

Slack space recovery targets:
1. **Value list slack**: When values are deleted from a list, old VK cell offsets may remain in the slack area after the active list entries
2. **Data cell slack**: Large data cells reused for smaller values leave old data bytes after the new data
3. **Key node slack**: If a key node cell is reused for a key with a shorter name, the old name bytes remain in the slack

### 1.7 Remnant Data Beyond Last Hbin

When hive bins are deleted (the hive shrinks), the data beyond the last active hbin remains in the file. This area can contain entire deleted subtrees. Detection:

1. Read the "Hive bins data size" from the base block
2. Compare with actual file size
3. Everything beyond `0x1000 + hive_bins_data_size` is remnant data
4. Scan for NK/VK signatures in the remnant area

### 1.8 Path Reconstruction for Deleted Keys

Reconstructing the full registry path for a deleted key is challenging because:

- The parent key offset in an NK cell may point to a cell that has been reallocated
- The parent chain may be broken at any level

Approaches:
1. **Direct parent traversal**: Follow the parent key offset; if the parent cell is still a valid NK with a recognizable name, continue up the tree
2. **Known path matching**: Compare the key name and structure against known registry paths (e.g., if the key is named "Run" and has value entries typical of autostart items, it likely came from `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`)
3. **Timestamp correlation**: Use the key's last-write timestamp to correlate with transaction log entries that may preserve the full path
4. **Cross-reference with transaction logs**: Transaction log entries contain full page data that preserves the linkage between parent and child keys at a specific point in time

### 1.9 Timestamp-Based Ordering

Every NK cell contains a FILETIME (64-bit, 100-nanosecond intervals since 1601-01-01) representing the key's last-write time. Recovered deleted keys can be:

1. Sorted chronologically to reconstruct a timeline of registry activity
2. Grouped by similar timestamps to identify bulk operations (e.g., software installation/uninstallation)
3. Cross-referenced with other forensic artifacts (MFT timestamps, Event Logs, USN Journal) to validate authenticity

### 1.10 Jolanta Thomassen's regslack Algorithm

Thomassen's 2008 research at Cranfield University produced `regslack.pl`, one of the first tools for deleted registry recovery. Key insight: the four bytes immediately preceding the key signature (`nk`), when read as an unsigned long value, will for most valid registry keys be a negative number (because this is the cell size field, and allocated cells have negative sizes). This pattern persists even in unallocated space where the size has been changed by coalescence, because the NK signature itself is at a fixed offset within the original cell structure.

([Thomassen, "Forensic Analysis of Unallocated Space in Windows Registry Hive Files"](https://sentinelchicken.com/data/JolantaThomassenDISSERTATION.pdf))

---

## 2. Transaction Log Replay

### 2.1 Transaction Log Overview

Windows maintains transaction logs alongside each primary hive file to ensure atomicity of registry writes:

| File | Purpose |
|------|---------|
| `*.LOG` | Original single-log format (Windows 2000-XP), or dummy placeholder in dual-log systems |
| `*.LOG1` | Primary transaction log (dual-logging, Vista+) |
| `*.LOG2` | Secondary/failover transaction log (dual-logging, Vista+) |

Under normal circumstances, only LOG1 is used. LOG2 is activated only when a write to the primary file fails. If errors persist, the system alternates between LOG1 and LOG2, keeping a cumulative log of dirty data.

### 2.2 Old Log Format (Pre-Windows 8.1)

Structure:
```
[Base block (backup copy)]
[Dirty vector (bitmap)]
[Dirty sectors (pages)]
[Remnant data]
```

- Every bit in the bitmap corresponds to a single **512-byte sector** of the hive bins data in the primary file
- If a bit is set, that sector is dirty and its modified contents are present in the log file
- Pages follow in order after the bitmap
- Because the start of the file is frequently overwritten (on each use), old data recovery from these logs is very limited
- However, since different amounts of data are written on each use, old pages can sometimes remain at the end of the file across multiple uses

### 2.3 New Log Format (Windows 8.1+)

Structure:
```
[Base block (backup copy, 512 bytes)]
[Log entry 1]
[Log entry 2]
...
[Log entry N]
[Remnant data]
```

Each **log entry** is stored at an offset divisible by 512 bytes with no gaps between entries.

#### Log Entry Structure

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0x00 | 4 | Signature | "HvLE" |
| 0x04 | 4 | Size | Size of this log entry |
| 0x08 | 4 | Flags | Copy of base block Flags field at entry creation time |
| 0x0C | 4 | Sequence number | Constitutes the value of Primary/Secondary seq num after this entry is applied |
| 0x10 | 4 | Hive bins data size | Copy from base block at entry creation time |
| 0x14 | 4 | Dirty pages count | Number of dirty page references |
| 0x18 | 8 | Hash-1 | Marvin32 hash of data from first page reference to end (Size - 40 bytes) |
| 0x20 | 8 | Hash-2 | Marvin32 hash of first 32 bytes of this entry (including calculated Hash-1) |

Followed by an array of **dirty page references**, each describing a single page to be written to the primary file (offset and size). The actual dirty page data follows the references array in the same order.

#### Marvin32 Hash

Both Hash-1 and Hash-2 use the Marvin32 algorithm with seed: `82 EF 4D 88 7A 4E 55 C5` (hexadecimal bytes).

- Hash-1 validates the integrity of the dirty page data
- Hash-2 validates the integrity of the log entry header itself (including Hash-1)

This double-hash scheme ensures both the metadata and the data are tamper-proof.

([msuhanov/regf specification](https://github.com/msuhanov/regf/blob/master/Windows%20registry%20file%20format%20specification.md))

### 2.4 Sequence Number Coordination

Two 32-bit sequence numbers are stored in the hive base block:

- **Primary sequence number** (offset 0x04): Updated when a flush begins
- **Secondary sequence number** (offset 0x08): Updated when a flush completes

**Clean state**: Primary == Secondary (hive is consistent)
**Dirty state**: Primary != Secondary (pending changes need to be applied from logs)

The flush process:
1. Dirty data is written to a transaction log file
2. Primary sequence number is incremented by 1
3. Secondary sequence number retains its previous value
4. When dirty data is successfully written to the primary file, Secondary is updated to match Primary

([Google Project Zero, "The Windows Registry Adventure #5"](https://projectzero.google/2024/12/the-windows-registry-adventure-5-regf.html))

### 2.5 Recovery Algorithm

#### Case 1: Valid Base Block in Primary File

Both transaction log files are used:

1. Start with the log file containing **earlier** log entries (lower sequence numbers)
2. Apply log entries in sequence number order
3. If applying from this log file fails/exhausts entries, switch to the other log file
4. The first entry of the next log file must have sequence number = N+1 (where N is the last applied sequence number)
5. Continue until all applicable entries are applied

#### Case 2: Invalid Base Block in Primary File

Only the transaction log file with the **latest** log entries is used:

1. The base block is restored from the backup copy in the log file
2. Log entries are applied starting from the first valid entry

#### Sequence Number Validation

A log entry is applicable if its sequence number >= the secondary sequence number of the primary file's base block. Entries are applied in ascending sequence number order.

### 2.6 New Flush Strategy (Windows 8.1+)

Windows 8.1 introduced a more aggressive log-based strategy:

1. First flush after log reset: dirty data written to LOG file, primary file header **invalidated** (checksum set to invalid)
2. Subsequent flushes: new log entries **appended** to the log file; primary file remains untouched
3. **Reconciliation** occurs when: all users become inactive, the hive starts unloading, or 1 hour has elapsed since the last primary file write
4. During reconciliation: all dirty data written to primary, header validated, log status reset

This means the primary file can remain "stale" for extended periods, with all recent data only in the logs. **Forensic tools that only read the primary file will miss recent changes.**

([msuhanov/regf-samples, "Flush strategies"](https://github.com/msuhanov/regf-samples/blob/master/8.1-unreconciled/Flush%20strategies%20in%20the%20Windows%20registry.md))

### 2.7 Forensic Timeline from Transaction Logs

Transaction logs contain forensically valuable data:

1. **Old (already applied) log entries** may remain in the file after new entries are written, because the file is not truncated
2. **Remnant data** at the end of log files can contain fragments of previous log entries
3. Each log entry's sequence number and dirty pages provide a diff of what changed between two points in time
4. By replaying log entries one at a time, an analyst can reconstruct the state of the hive at each logged flush point

The Mandiant algorithm for processing transaction files:
1. Sort all writes by sequence number descending (most recent first)
2. Perform allocated and unallocated cell parsing to find entries
3. Compare entries against the original hive
4. Any entries not present in the current hive are marked as deleted and logged

**Critical forensic implication**: If a threat actor deletes a persistence key and the system is seized, the creation of that key may only be recoverable from the LOG files.

### 2.8 Missing Log Entries

Suhanov documented cases where log entries can be missing from transaction log files. This occurs when:

- The system crashes between writing dirty data to the primary file and resetting the log
- Race conditions during rapid successive flushes
- Disk write failures that corrupt specific log entries

Parsers should handle gaps in sequence numbers gracefully.

([msuhanov/regf-samples, "Missing log entries"](https://github.com/msuhanov/regf-samples/blob/master/10-missing_log_entries/Missing%20log%20entries.md))

---

## 3. Transactional Registry (TxR)

### 3.1 Overview

The Transactional Registry (TxR) uses the Common Log File System (CLFS) to implement atomic registry operations. Introduced in Windows Vista, TxR provides ACID guarantees for registry modifications through the Kernel Transaction Manager (KTM).

Files involved:
- `*.TxR.<number>.regtrans-ms` -- CLFS container files containing transaction data
- `*.TxR.blf` -- CLFS Base Log File containing metadata
- Stored in `%SystemRoot%\System32\config\TxR` for system hives
- Stored in user profile directories for per-user hives

### 3.2 CLFS Format

CLFS (Common Log File System) is a general-purpose logging subsystem. Key technical details:

- Maximum of 1023 containers per log
- Container files have equal sizes (multiples of 512 KiB, max 4 GiB)
- Each record identified by a **Log Sequence Number (LSN)** -- an increasing 32-bit number
- LSN encodes: container identifier, offset to record, record identifier
- Binary format -- no built-in Windows viewer

Documentation sources:
- [ionescu007/clfs-docs](https://github.com/ionescu007/clfs-docs) -- Unofficial CLFS documentation
- [libyal/libfsclfs](https://github.com/libyal/libfsclfs/blob/main/documenation/Common%20Log%20File%20System%20(CLFS).asciidoc) -- CLFS format working document

### 3.3 Forensic Value of TxR Logs

**System hive TxR logs are NOT automatically cleared.** This means historical transaction data accumulates over time, potentially providing:

1. **Registry key creation and deletion records** with full key paths
2. **Value writes and deletes** with key path, value name, data type, and data
3. **Uncommitted transactions** that were never applied to the hive
4. Evidence of **what** changed, not just which pages were dirty (unlike LOG1/LOG2 which only contain page-level data)

For user hives, TxR logs are stored in the user profile directory and **cleared on user logout**, limiting their forensic window.

### 3.4 What Uses TxR

Common Windows components that use transacted registry operations:
- **Scheduled Tasks**: Task creation/modification uses TxR, meaning task registry data persists in TxR logs even after task deletion
- **Windows Update**: Update operations use transactions for rollback capability
- **MSI Installer**: Application installations use transacted operations
- **Group Policy**: Policy application uses transactions

### 3.5 Malware Abuse of CLFS: PRIVATELOG/STASHLOG

Mandiant discovered the PRIVATELOG malware family and its installer STASHLOG, which abuse CLFS for data hiding:

- Payload data is written to CLFS log files using `clfsw32.dll!ReserveAndAppendLog()`
- Data stored in the first container file: `C:\Users\Default\NTUSER.DAT<GUID>.TMContainer00000000000000000001.regtrans-ms`
- Detection: while `svchost.exe` commonly loads `ktmw32.dll`, loading of `clfsw32.dll` is rare and suspicious
- File writes to `.regtrans-ms` files for the **default user** profile are highly anomalous

([Mandiant, "Too Log; Didn't Read"](https://cloud.google.com/blog/topics/threat-intelligence/unknown-actor-using-clfs-log-files-for-stealth/))

### 3.6 Parsing TxR Records

With experimentation, Mandiant researchers determined the basic record format within TxR CLFS containers:

- Records for **key creation** and **deletion** can be identified
- Records for **value writes** and **deletes** are present
- Each record contains the relevant key path, value name, data type, and data
- The format is not officially documented by Microsoft

**Implementation recommendation**: Build a CLFS container parser that can enumerate records by LSN, then implement TxR-specific record type identification to extract registry operations.

---

## 4. Registry Carving from Non-Hive Sources

### 4.1 Memory Dump Analysis

#### In-Memory vs. On-Disk Format

The registry in memory is NOT a simple memory-mapped copy of the on-disk file. Key differences:

- **Cell index translation**: On disk, cell indexes are 32-bit offsets from the start of hive data. In memory, they are translated through a 3-level structure called a **cell map** (similar to a CPU page table), accessible through `_CMHIVE.Hive.Storage`. The structures are `_DUAL` -> `_HMAP_DIRECTORY` -> `_HMAP_TABLE` -> `_HMAP_ENTRY`. ([Google Project Zero, "The Windows Registry Adventure #5"](https://projectzero.google/2024/12/the-windows-registry-adventure-5-regf.html))

- **Non-contiguous mapping**: Unlike on disk, hive bins in memory need not be contiguous. The cell map handles arbitrary virtual address mapping.

- **Volatile storage**: Active hives have up to 2 GiB of additional **volatile storage** for temporary keys/values that exist only in memory. Each NK cell has TWO subkey counts and TWO subkey list pointers: one for stable (on-disk) data and one for volatile (memory-only) data.

- **Volatile hives**: The `\Registry\Machine\HARDWARE` hive and the `\Registry` root hive exist **only in memory** -- they have no on-disk representation. The HARDWARE hive contains information about all currently detected Plug-and-Play devices.

#### CMHive Structure

Each loaded hive is represented by a `_CMHIVE` kernel structure containing:
- `Hive` (`_HHIVE`): Contains the cell map for address translation
- `HiveList`: Doubly-linked list linking all loaded hives
- `FileHandles`: Handles to the backing files
- `FlushDirtyVector`: Tracks which pages have been modified

Volatility's `hivelist` plugin traverses `_CMHIVE.HiveList` to enumerate all loaded hives.

#### What Volatile Hives Reveal

Brendan Dolan-Gavitt's 2008 research found that analyzing the registry in memory recovers on average **631 keys and 1,231 values** per image that exist only in volatile storage and are undetectable on disk. These include:
- Hardware configuration data
- Active session information
- Temporary configuration states

([Dolan-Gavitt, "Forensic analysis of the Windows registry in memory"](https://www.sciencedirect.com/science/article/pii/S1742287608000297))

#### Memory-Only Attack Detection

An attacker with kernel access can modify cached registry data in memory without those changes being visible on disk. For example, replacing password hashes in the in-memory SAM hive. Such attacks are **undetectable** by on-disk analysis alone but are revealed by comparing memory dumps against the on-disk hive files.

([Dolan-Gavitt, "Challenges in Carving Registry Hives from Memory"](https://moyix.blogspot.com/2007/09/challenges-in-carving-registry-hives.html))

### 4.2 Carving from Page Files

**pagefile.sys** and **swapfile.sys** present significant challenges:

- Memory pages are stored **unstructured/unordered** -- there is no page table context
- Pages are typically 4 KiB, so only data smaller than 4 KiB can be fully carved from a single page
- Standard memory forensics tools (Volatility, MemProcFS) **cannot** analyze page files directly because they lack the necessary context
- Analysis is limited to:
  - **Signature-based carving**: Search for `hbin` headers, `nk` signatures, `vk` signatures
  - **String extraction**: Search for known registry key names and value data
  - **YARA rule scanning**: Apply rules targeting known malware registry indicators

**Caveat**: False positives are common because registry-like byte patterns can appear in swapped pages from security tools or other applications.

### 4.3 Hibernation Files

**hiberfil.sys** is a much richer source of registry data than page files because it contains a **complete snapshot** of physical memory at hibernation time.

#### Compression Formats

Windows uses two proprietary compression algorithms:
- **Xpress**: Microsoft Xpress LZ77 (older Windows versions)
- **HuffmanXpress**: Microsoft Xpress LZ77+Huffman (modern Windows)

The format was reverse-engineered by Matthieu Suiche and Nicolas Ruff (Sandman project). The file consists of:
1. `PO_MEMORY_IMAGE` header (signature: `hibr` or `wake`)
2. Kernel context and registers (`_KPROCESSOR_STATE`, including CR3)
3. Arrays of compressed Xpress data blocks with `_IMAGE_XPRESS_HEADER` and `_PO_MEMORY_RANGE_ARRAY`

#### Tools for Decompression

- **Volatility 3**: `windows.hibernation.Dump` plugin converts to raw memory dump
- **Hibr2Bin**: Standalone decompression tool
- **Hibernation Recon** (Arsenal Recon): Commercial tool with advanced analysis capabilities
- After decompression, the resulting raw memory image can be analyzed with standard memory forensics tools (Volatility, etc.) to extract registry hives

#### Forensic Significance

- Contains the complete state of all loaded registry hives at hibernation time, including volatile data
- Persists across power cycles (unlike a RAM dump)
- **Slack space** within hiberfil.sys may contain data from previous hibernation cycles
- If BitLocker or other FDE is enabled, hiberfil.sys is encrypted on disk

([Forensicxlab, "Volatility3: Modern Windows Hibernation file analysis"](https://www.forensicxlab.com/blog/hibernation))

### 4.4 Volume Shadow Copies (VSS)

VSS provides point-in-time snapshots of disk volumes, enabling powerful registry forensic techniques:

#### Registry Hive Diffing

1. Mount VSS snapshots using Arsenal Image Mounter or similar tool
2. Extract registry hives from each snapshot
3. Compare hives across snapshots to detect:
   - Newly created keys (persistence mechanisms added)
   - Deleted keys (evidence destruction)
   - Modified values (configuration changes)
   - Timestamp changes (timestomping)

**Example**: If the live NTUSER.DAT has cleared UserAssist keys, but a VSS snapshot from hours earlier shows them populated, this proves deliberate registry clearing.

#### Timeline Building

`log2timeline.py` has built-in VSS support and can process multiple snapshots, with `psort` providing deduplication to remove identical entries across snapshots.

#### Caveats

- **Windows 8+ ScopeSnapshots**: Limits VSS capture scope on client OS editions by default
- **RegBack disabled**: `C:\Windows\System32\config\RegBack` is disabled by default since Windows 10 version 1803
- **Ransomware targets VSS**: Families like WannaCry, LockBit, and Conti routinely delete shadow copies before encryption
- **Key locations**: `HKLM\System\CurrentControlSet\Services\VSS` and `HKLM\System\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot` control VSS behavior

([Andrea Fortuna, "Volume Shadow Copies in forensic analysis"](https://andreafortuna.org/2017/10/02/volume-shadow-copies-in-forensic-analysis/))

### 4.5 Carving from Unallocated Disk Space

#### Signature-Based Carving Algorithm

1. **Scan for `regf` headers**: Search at the start of each sector (512-byte boundaries) for the `regf` magic (0x72656766)
2. **Validate base block**: Check version numbers, timestamps, checksum (XOR of first 127 DWORDs)
3. **Follow hbin chain**: Starting at offset 0x1000, look for `hbin` signatures every 4096 bytes
4. **Validate each hbin**: Check offset and size fields in the 32-byte `_HBIN` header
5. **Handle fragmentation**: If hbin chain breaks (expected offset doesn't match), mark as truncation point
6. **Detect interleaving**: If cells within an hbin contain `regf` or `hbin` signatures from another registry file, use that as a truncation point (adjusted to 512-byte sector boundary)
7. **Reconstruct fragments**: Attempt to chain non-contiguous hbin runs based on their offset fields

#### Tools

- **yarp**: Supports truncated registry files and fragmented hive carving
- **HbinRecon / HiveRecon** (Arsenal Recon): Specialized carving tool with multiple modes:
  - Mode 0: Intact hive parsing with full NK path resolution
  - Mode 2: Stacked hbin parsing (no regf header required)
  - Mode 4: Carving mode for extracting hbins from any input
- **reorder_hbins.py**: Reorders displaced hbins based on their internal offset fields

#### Partial Reconstruction

When only fragments are available:
1. Scan on block boundaries for `hbin` headers
2. Read each hbin's internal offset field to determine its correct position in the hive
3. Write hbins out at their correct positions in a new file
4. Individual NK cells can be found and subtrees partially reconstructed even when the hive is incomplete

([Cyber Forensicator, "Carving Fragmented Registry Files"](http://cyberforensicator.com/2018/01/13/carving-fragmented-registry-files/))

---

## 5. Anti-Forensic Detection

### 5.1 Timestamp Manipulation Detection

#### Registry Key Last-Write Timestamps

Every NK cell contains a 64-bit FILETIME representing the key's last write time. Manipulation can be detected through:

1. **Cross-reference with NTFS timestamps**:
   - Compare hive file's MFT modification time with the most recent key last-write timestamp inside the hive
   - If key timestamps are newer than the file's MFT timestamp, anomalous
   - If key timestamps are much older than expected given the file's modification history, suspicious

2. **USN Journal analysis**:
   - The USN Journal tracks "BasicInfoChange" events on files
   - "BasicInfoChange" followed by "BasicInfoChange | Close" in the USN Journal is a signature of timestomping
   - The USN Journal typically has 30-40 hours of data, compared to only 2-3 hours for $LogFile

3. **$STANDARD_INFORMATION vs $FILE_NAME comparison**:
   - $SI timestamps can be manipulated via Win32 API (`SetFileTime`)
   - $FN timestamps can only be modified by the kernel -- no known anti-forensic tools can manipulate them
   - Discrepancies between $SI and $FN are strong evidence of manipulation

4. **Statistical analysis within the hive**:
   - Clusters of keys with identical timestamps suggest bulk modification
   - Keys with timestamps predating the OS installation are suspicious
   - Keys with zeroed timestamps indicate deliberate clearing
   - Large gaps in timestamp sequences within a subtree suggest selective manipulation

5. **Registry transaction log correlation**:
   - Log entries have sequence numbers that can be correlated with key timestamps
   - If a key's timestamp doesn't match any log entry's time window, it may have been manipulated

([SANS DFIR Blog, "Digital Forensics: Detecting time stamp manipulation"](https://www.sans.org/blog/digital-forensics-detecting-time-stamp-manipulation/))

([DFRWS, "Artifacts for Detecting Timestamp Manipulation in NTFS"](https://dfrws.org/wp-content/uploads/2020/05/Artifacts-for-Detecting-Timestamp-Manipulati_2020_Forensic-Science-Internati.pdf))

### 5.2 Registry Wiping Tool Detection

#### CCleaner Artifacts

- **"Z" filename pattern**: CCleaner overwrites filenames with the letter "Z" (e.g., `TEST.TXT` -> `ZZZZ.ZZZ`). This pattern is detectable in unallocated disk space, the hibernation file, and the page file.
- **Registry configuration keys**: `HKCU\Software\Piriform\CCleaner` contains settings showing which cleaning items were selected (data value "True")
- **LTR value**: After multiple runs, a `LTR` (Last Time Run) value appears with a timestamp that approximates execution time (adjusted to local timezone)
- **USN Journal evidence**: When CCleaner "clears" Windows Event Logs, the USN Journal reveals the logs were overwritten to minimum size (evtx header size), not truly deleted
- **MFT orphan entries**: Comparing MFT entries with deletion timestamps reveals mass file deletion events that can be correlated with CCleaner execution

([Synacktiv, "CCleaner forensics"](https://www.synacktiv.com/en/publications/ccleaner-forensics))
([KoreLogic, "What Did CCleaner Wipe?"](https://blog.korelogic.com/blog/2015/05/18/what_did_ccleaner_wipe))

#### General Wiping Detection Patterns

1. **Bulk deletion indicators**: Large numbers of keys deleted within a very short time window (visible in transaction logs and as clusters of freed cells with similar timestamps)
2. **Selective artifact clearing**: Specific forensic-relevant keys cleared (UserAssist, RecentDocs, MUICache) while unrelated keys remain -- this pattern is characteristic of privacy tools
3. **Empty forensic containers**: Key paths that are expected to have subkeys/values (e.g., `Explorer\UserAssist\{GUID}\Count`) exist but are empty -- suggesting targeted cleaning
4. **The absence of evidence IS evidence**: When combined with other artifacts showing system activity, the complete absence of expected registry entries becomes a forensic finding

### 5.3 Hidden Data Detection

#### Null-Character Embedded Key/Value Names

**The core technique**: Windows kernel uses counted Unicode strings (`UNICODE_STRING` with explicit length), while the Win32 API uses null-terminated strings. Keys/values created via Native API (`NtCreateKey`, `NtSetValueKey`) with embedded null characters (e.g., `Key\0HiddenSuffix`) are:

- **Invisible to Regedit**: The null character terminates the displayed name
- **Invisible to reg.exe and PowerShell**: They also use the Win32 API
- **Visible in raw hive parsing**: The full name including the null character and suffix is present in the NK/VK cell data

**Real-world malware**: Kovter and Poweliks use Run key values with names starting with `\0` to persist while being invisible to standard tools.

**Detection**: Parse key and value names as counted byte strings (using the name length field from the NK/VK cell header), not as null-terminated strings. Flag any name containing embedded null bytes.

([Tripwire, "How to Evade Detection: Hiding in the Registry"](https://www.tripwire.com/state-of-security/evade-detection-hiding-registry))
([SpecterOps, "Hiding Registry Keys with PSReflect"](https://posts.specterops.io/hiding-registry-keys-with-psreflect-b18ec5ac8353))

#### Data Hidden in Key Class Names

Registry keys have an often-overlooked "class name" attribute. The `NtCreateKey` API accepts a `Class` parameter allowing arbitrary Unicode data to be stored:

- **Most tools ignore it**: Regedit, reg.exe, and many forensic tools don't display key class names
- **No errors raised**: Unlike null-byte key names, class name data doesn't cause tool errors
- **Arbitrary size**: Class names can be up to 65,535 bytes
- **Detection**: Parse the class name offset and length from every NK cell; flag keys with non-empty class names in unexpected locations (most registry keys have empty class names, with the notable exception of performance counter keys)

([Suhanov, "Hiding data in the registry"](https://dfir.ru/2018/10/07/hiding-data-in-the-registry/))

#### Value Slack Space as Data Storage

Attackers can potentially hide data in:
- **Value data slack**: Allocate a large data cell, then overwrite the value with smaller data, leaving hidden bytes in the slack
- **REG_BINARY opacity**: Applications define their own interpretation of REG_BINARY data; the same bytes can be decoded differently as 8-bit ASCII vs 16-bit Unicode
- **Type mismatch**: A value declared as REG_SZ but containing non-string binary data

#### Security Descriptor Manipulation

The "Tarrask" malware (discovered by Microsoft, April 2022) deletes the `SD` (Security Descriptor) value from scheduled task registry entries, making tasks invisible to `schtasks.exe`, Autoruns, and Task Scheduler while the task continues to execute.

Detection: Scan for task entries under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` that are missing the `SD` value.

([Binary Defense, "Diving into Hidden Scheduled Tasks"](https://binarydefense.com/resources/blog/diving-into-hidden-scheduled-tasks))

#### Exploiting Parser Differences

Suhanov documented that some offline parsers handle encoding incorrectly:
- Registry names are stored using UTF-16LE and Latin-1
- Some parsers incorrectly use Windows-1252 instead of Latin-1
- This allows creation of keys with different actual names that appear identical under the wrong encoding
- Such "duplicate" names can disrupt tree traversal in vulnerable parsers

**Implementation note**: The Rust parser must correctly handle Latin-1 (ISO 8859-1) for key names, not Windows-1252.

### 5.4 Rootkit Artifacts and Detection

#### CmRegisterCallback / Registry Filter Drivers

The `CmRegisterCallbackEx` function allows kernel drivers to intercept ALL registry operations. Both legitimate EDR products and rootkits use this:

- **Legitimate use**: EDR drivers register callbacks to monitor and block malicious registry modifications
- **Malicious use**: Rootkits register callbacks to hide specific keys/values from API queries (e.g., the Mingloa rootkit)
- **Detection**: Registry callbacks are stored in a kernel callback table that can be enumerated from a memory dump. Volatility can identify registered callbacks and their owning drivers.

#### DKOM Effects on Registry

Direct Kernel Object Manipulation can affect registry access in several ways:
- **Process hiding**: A hidden process's registry access patterns may still be visible in transaction logs
- **Token manipulation**: Elevated tokens can bypass registry ACLs
- **Callback list manipulation**: A rootkit can unregister EDR callbacks from the callback list

**Forensic detection**: Compare the registry view from the Win32 API (potentially manipulated by a rootkit) against a raw parse of the on-disk hive file. Discrepancies indicate active manipulation. This is the approach used by Sysinternals RootkitRevealer.

([RootkitRevealer - Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/rootkit-revealer))

#### Memory Forensic Detection

From memory dumps, the following can reveal rootkit activity:
- **Pool tag scanning**: Find `_EPROCESS` objects via pool-tag scanning (works even when DKOM has unlinked the process)
- **Callback enumeration**: List all registered CmRegisterCallback entries
- **SSDT hooks**: Examine the System Service Descriptor Table for hooked registry functions
- **Orphan threads**: Threads without a parent process can indicate rootkit code

### 5.5 Transaction Log Evasion Detection

Suhanov documented a technique where malware forces the OS not to write data to primary hive files, leaving all modified data only in transaction log files. Many offline parsing tools do not process transaction logs, making this an effective evasion technique.

**Detection**: A parser that properly applies transaction logs will see the full picture. The parser should ALWAYS check and apply transaction logs, not just parse the primary file.

---

## 6. Registry Virtualization and Layered Keys

### 6.1 UAC Virtualization

Since Windows Vista, registry writes from non-elevated 32-bit applications to `HKLM\SOFTWARE` are silently redirected:

- **Source**: `HKEY_LOCAL_MACHINE\Software\<AppKey>`
- **Redirected to**: `HKEY_USERS\<User SID>_Classes\VirtualStore\Machine\Software\<AppKey>`
- **Merged view**: When reading, the system presents a merged view -- virtual values override global values
- **Scope**: Only affects `HKLM\Software`; only applies to 32-bit processes without a UAC manifest; disabled for services and non-interactive processes

**Forensic impact**:
- Investigators MUST check BOTH the global hive and the per-user VirtualStore
- Malware running as a standard user writes to VirtualStore, which can be missed if only HKLM is examined
- The merged view at runtime differs from what either location stores individually

([Microsoft Learn, "Registry Virtualization"](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-virtualization))
([TrainSec, "A Deep Dive into UAC Virtualization"](https://trainsec.net/library/windows-internals/understanding-uac-virtualization/))

### 6.2 Layered Keys (Windows 10 1607+)

Introduced in Windows 10 Anniversary Update (1607) for container support:

- **Patent**: US20170279678A1 "Containerized Configuration"
- **Implementation**: A kernel driver `VRegDriver` (built into ntoskrnl.exe) consisting of:
  - An IOCTL interface at `\Device\VRegDriver` for container management
  - A registry callback (`VrpRegistryCallback`) implementing namespace redirection
- **Concept**: Load a base hive, then stack up to 127 overlay hives on top. Values in higher layers override values in lower layers.
- **Format details**: NK cells in layered hives have special bit flags:
  - `IsSupersedeTree` (0x3): Key and its subkeys supersede the base hive
  - `InheritClass` (0x80): Key inherits class name from the base layer

#### Differencing Hives

- A "writethrough" differencing hive redirects all write operations to lower layers
- Differencing hives are unloaded when the corresponding silo is destroyed
- On export from inside a container, the kernel creates a temporary hive with a merged view -- **no deleted registry data is preserved**. Forensic examiners must export both base and delta hives separately.

([Suhanov, "Containerized registry hives in Windows"](https://dfir.ru/2020/08/15/containerized-registry-hives-in-windows/))
([Google Project Zero, "The Windows Registry Adventure #4"](https://projectzero.google/2024/10/the-windows-registry-adventure-4-hives.html))

### 6.3 Windows Container Silo Registry

Windows Containers use server silos with private registry namespaces:

- **WC key**: `\Registry\WC` is the mount point for container-private registry keys
- **Silo types**: Application Silos (Desktop Bridge) and Server Silos (true containers)
- **Container forensic locations**:
  - Docker: `C:\ProgramData\docker\windowsfilter\<hash>\`
  - Base hives in the `Hives` directory
  - Overlay hives in `sandbox.vhdx` at `/WcSandboxState/Hives/`

**Security concern**: In the `CmpOKToFollowLink` function, if the current thread is in a server silo, all registry symbolic links are allowed between any hives, bypassing the trusted-hive check. This can grant non-administrator users access to host registry keys.

([Google Project Zero, "Who Contains the Containers?"](https://projectzero.google/2021/04/who-contains-containers.html))
([OSDFIR Blog, "Windows Container Forensics"](https://osdfir.blogspot.com/2021/07/windows-container-forensics.html))

### 6.4 WSL2 Forensic Considerations

WSL2 creates forensic challenges by bridging Windows and Linux ecosystems:

- WSL2 installations leave registry artifacts that can be detected with RegRipper plugins
- The Linux filesystem lives inside a virtual disk (ext4.vhdx) requiring separate analysis
- Investigators must consider both Windows registry artifacts and Linux filesystem artifacts

([ACM/DFRWS, "WSL2 Forensics: Detection, Analysis & Revirtualization"](https://dl.acm.org/doi/fullHtml/10.1145/3538969.3544439))

### 6.5 MSIX App Registry

MSIX-packaged applications can have their own private registry hives that are only visible to that application. Changes made in MSIX hives are NOT visible in the standard registry hives. Forensic examiners should look for app-specific hives in app package directories.

---

## Implementation Priority for winreg-forensic

Based on forensic impact and differentiation potential, recommended implementation priority:

### Tier 1 (Must-Have for a World-Class Parser)

1. **Transaction log replay** (LOG1/LOG2) -- both old bitmap format and new log entry format with Marvin32 validation
2. **Deleted key/value recovery** from unallocated cells with the Mandiant improved algorithm
3. **Slack space recovery** within allocated cells
4. **Orphan cell detection** (allocated but unreachable from root)
5. **Null-character detection** in key/value names
6. **Proper Latin-1 encoding** (not Windows-1252)

### Tier 2 (Major Differentiators)

7. **TxR/CLFS parsing** for transactional registry logs
8. **Key class name extraction and anomaly detection**
9. **Timeline generation** from key last-write timestamps + log entry sequence numbers
10. **Hive diffing** (compare two hives, e.g., from VSS snapshots)
11. **Remnant data scanning** beyond last hbin
12. **Security descriptor anomaly detection** (missing SD values, unusual ACLs)

### Tier 3 (Advanced Capabilities)

13. **Registry carving** from raw disk/memory with fragmented hive reconstruction
14. **Layered key parsing** (differencing hives, VRegDriver support)
15. **Hibernation file hive extraction** (requires Xpress decompression)
16. **Anti-forensic scoring** (statistical analysis of timestamps, bulk deletion detection)
17. **Memory dump hive extraction** (CMHive structure parsing, volatile storage)
18. **CCleaner/wiping tool artifact detection**

---

## Key References

### Specifications and Documentation
- [msuhanov/regf -- Windows registry file format specification](https://github.com/msuhanov/regf/blob/master/Windows%20registry%20file%20format%20specification.md)
- [ionescu007/clfs-docs -- Unofficial CLFS documentation](https://github.com/ionescu007/clfs-docs)
- [libyal/libregf -- REGF format documentation](https://github.com/libyal/libregf/blob/main/documentation/Windows%20NT%20Registry%20File%20(REGF)%20format.asciidoc)
- [libyal/libfsclfs -- CLFS format documentation](https://github.com/libyal/libfsclfs/blob/main/documenation/Common%20Log%20File%20System%20(CLFS).asciidoc)

### Research Papers and Blog Posts
- [Mandiant -- "Digging Up the Past: Windows Registry Forensics Revisited" (2024)](https://cloud.google.com/blog/topics/threat-intelligence/digging-up-the-past-windows-registry-forensics-revisited/)
- [Google Project Zero -- "The Windows Registry Adventure" series (2024-2025)](https://projectzero.google/2024/12/the-windows-registry-adventure-5-regf.html)
- [Suhanov -- ZeroNights 2017 presentation on registry forensics](https://2017.zeronights.org/wp-content/uploads/materials/ZN17-Suhanov-Registry.pdf)
- [Suhanov -- "Hiding data in the registry" (2018)](https://dfir.ru/2018/10/07/hiding-data-in-the-registry/)
- [Suhanov -- "Containerized registry hives in Windows" (2020)](https://dfir.ru/2020/08/15/containerized-registry-hives-in-windows/)
- [Dolan-Gavitt -- "Forensic analysis of the Windows registry in memory" (2008)](https://www.sciencedirect.com/science/article/pii/S1742287608000297)
- [Dolan-Gavitt -- "Challenges in Carving Registry Hives from Memory" (2007)](https://moyix.blogspot.com/2007/09/challenges-in-carving-registry-hives.html)
- [Thomassen -- "Forensic Analysis of Unallocated Space in Windows Registry Hive Files" (2008)](https://sentinelchicken.com/data/JolantaThomassenDISSERTATION.pdf)
- [Kahvedžić & Kechadi -- "Correlating Orphaned Windows Registry Data Structures" (2009)](https://commons.erau.edu/jdfsl/vol4/iss2/3/)
- [Mandiant -- "Too Log; Didn't Read" (CLFS abuse by PRIVATELOG)](https://cloud.google.com/blog/topics/threat-intelligence/unknown-actor-using-clfs-log-files-for-stealth/)
- [ElcomSoft -- "Investigating Windows Registry" (2026)](https://blog.elcomsoft.com/2026/02/investigating-windows-registry/)
- [Synacktiv -- "CCleaner forensics"](https://www.synacktiv.com/en/publications/ccleaner-forensics)
- [Binary Defense -- "Diving into Hidden Scheduled Tasks" (Tarrask)](https://binarydefense.com/resources/blog/diving-into-hidden-scheduled-tasks)

### Tools and Implementations
- [msuhanov/yarp -- Yet Another Registry Parser (Python)](https://github.com/msuhanov/yarp)
- [msuhanov/regf-samples -- Registry format test samples](https://github.com/msuhanov/regf-samples)
- [Arsenal Recon -- HbinRecon / HiveRecon](https://arsenalrecon.com/2018/10/new-versions-of-hiverecon-and-hbinrecon-launched/)
- [Outflanknl/SharpHide -- Tool to create hidden registry keys](https://github.com/outflanknl/SharpHide)
- [Volatility Framework -- Memory forensics with registry plugins](https://github.com/volatilityfoundation/volatility)
- [RegRipper4 -- Harlan Carvey's registry parsing tool](https://github.com/keydet89/RegRipper4.0)

### Books
- Harlan Carvey, *Windows Registry Forensics: Advanced Digital Forensic Analysis of the Windows Registry*, 2nd Edition (2016)
- Peter Norris, *The Internal Structure of the Windows Registry* (PhD thesis)

### Patents
- US20170279678A1 -- "Containerized Configuration" (Microsoft, 2016) -- Layered keys / differencing hives
