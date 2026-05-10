# Snapshot/Backup Forensic Parsing Research

## Comprehensive findings for the vsc-forensic Rust crate

---

# Part 1: Volume Shadow Copy (VSS) — Windows

## 1.1 VSS Architecture

VSS (Volume Snapshot Service) is a Windows framework since Vista for creating point-in-time snapshots of NTFS volumes. Three components cooperate:

- **Requester**: Application requesting the snapshot (Windows Backup, System Restore, third-party tools like Veeam)
- **Writer**: Data-specific modules ensuring data consistency (SQL Writer, Registry Writer, etc.)
- **Provider**: Engine that creates/manages shadow copies. Default is "Microsoft Software Shadow Copy provider 1.0" (GUID: `b5946137-7b9f-4925-af80-51abd60b20d5`)

The kernel driver `volsnap.sys` manages the differential copies at block level.

## 1.2 VSS On-Disk Format (from libvshadow specification)

### Identification
- VSS GUID: `3808876b-c176-4e48-b7ae-04046e6cc752` (little-endian)
- Byte order: little-endian throughout
- Date/time values: FILETIME in UTC
- Character strings: UTF-16LE without BOM
- Block size: 16,384 bytes (16 KiB / 0x4000)

### File Naming Convention
Files in `System Volume Information`:
- **VSS Catalog**: `{3808876b-c176-4e48-b7ae-04046e6cc752}` (the VSS GUID alone)
- **VSS Store**: `{<time/MAC-based-GUID>}{3808876b-c176-4e48-b7ae-04046e6cc752}` (store GUID + VSS GUID)

### Volume Header (offset 0x1E00 on volume)

The VSS volume header is stored at byte offset **7680 (0x1E00)** within the NTFS volume (inside the $Boot metadata file area). Size: at least 100 bytes (likely 512, sector-aligned).

| Offset | Size | Description |
|--------|------|-------------|
| 0 | 16 | VSS identifier GUID |
| 16 | 4 | Version |
| 20 | 4 | Record type (0x01 = Volume header) |
| 24 | 8 | Current offset (0x1E00, relative to volume start) |
| 32 | 8 | Unknown (Next offset?) |
| 40 | 8 | Unknown (empty) |
| 48 | 8 | **Catalog offset** (relative to volume start; 0 if no catalog) |
| 56 | 8 | Maximum size (0 if unbounded) |
| 64 | 16 | Volume identifier GUID |
| 80 | 16 | Shadow copy storage volume identifier GUID |
| 96 | 4 | Unknown |
| 100 | 412 | Unknown (empty) |

### Catalog Structure

The catalog stores metadata about individual stores (snapshots). Consists of one or more **catalog blocks**, each **16,384 bytes**.

**Catalog Block Header** (128 bytes):

| Offset | Size | Description |
|--------|------|-------------|
| 0 | 16 | VSS identifier GUID |
| 16 | 4 | Version (0x01) |
| 20 | 4 | Record type (0x02 = Catalog block header) |
| 24 | 8 | Relative offset (from first catalog block) |
| 32 | 8 | Current offset (from volume start) |
| 40 | 8 | Next block offset (from volume start; 0 = last) |
| 48 | 80 | Unknown (empty) |

**Catalog Entry Type 0x02** (128 bytes) -- the main snapshot descriptor:

| Offset | Size | Description |
|--------|------|-------------|
| 0 | 8 | Catalog entry type (0x02) |
| 8 | 8 | Volume size |
| 16 | 16 | **Store identifier** GUID (used in store filename) |
| 32 | 8 | Sequence number |
| 40 | 8 | Flags (0x40 = Vista/7; 0x440 = Win8 file backup?) |
| 48 | 8 | **Shadow copy creation time** (FILETIME) |
| 56 | 72 | Unknown (empty) |

### Store Structure

Each store contains the actual shadow copy data (COW blocks). Applied in reverse chronological order to reconstruct any snapshot point.

**Store Block Record Types**:

| Value | Description |
|-------|-------------|
| 0x0001 | Volume header |
| 0x0002 | Catalog block header |
| 0x0003 | Block descriptor list (diff area table) |
| 0x0004 | Store header |
| 0x0005 | Store block ranges list |
| 0x0006 | Store bitmap |

**Store Block Header** (128 bytes):

| Offset | Size | Description |
|--------|------|-------------|
| 0 | 16 | VSS identifier GUID |
| 16 | 4 | Version (0x01) |
| 20 | 4 | Record type |
| 24 | 8 | Relative offset (from store start) |
| 32 | 8 | Current offset (from volume start) |
| 40 | 8 | Next block offset (from volume start; 0 = last) |
| 48 | 8 | Size of store information (first block only) |
| 56 | 72 | Unknown (empty) |

**Store Information** (variable size, after first store header):

| Offset | Size | Description |
|--------|------|-------------|
| 0 | 16 | Unknown identifier GUID |
| 16 | 16 | **Shadow copy identifier** GUID |
| 32 | 16 | **Shadow copy set identifier** GUID |
| 48 | 4 | Snapshot context |
| 52 | 4 | Unknown (Provider?) |
| 56 | 4 | **Attribute flags** |
| 60 | 4 | Empty |
| 64 | 2 | Operating machine string size (bytes) |
| 66 | var | Operating machine string (UTF-16, no null terminator) |
| ... | 2 | Service machine string size |
| ... | var | Service machine string |

**Store Attribute Flags** (VSS_VOLUME_SNAPSHOT_ATTRIBUTES):

| Value | Description |
|-------|-------------|
| 0x00000001 | Persistent (survives reboot) |
| 0x00000002 | No auto-recovery |
| 0x00000004 | Client-accessible |
| 0x00000008 | No auto release |
| 0x00000010 | No writers |
| 0x00000020 | Transportable |
| 0x00000040 | Not surfaced |
| 0x00000080 | Not transacted |
| 0x00020000 | Differential (COW mechanism) |
| 0x00040000 | Plex (complete copy) |

### Block Descriptor (Diff Area Table)

Each block descriptor is **32 bytes**:

| Offset | Size | Description |
|--------|------|-------------|
| 0 | 8 | **Original data block offset** (relative to volume start) |
| 8 | 8 | **Relative store data block offset** (relative to store start) |
| 16 | 8 | **Store data block offset** (relative to volume start) |
| 24 | 4 | **Flags** |
| 28 | 4 | **Allocation bitmap** (used if flag 0x02 set) |

**Block Descriptor Flags**:

| Value | Description |
|-------|-------------|
| 0x01 | Is forwarder -- maps to next block's original offset |
| 0x02 | Overlay -- allocation bitmap defines block fill |
| 0x04 | Not used -- block ignored |

### Store Block Range Entry (24 bytes):

| Offset | Size | Description |
|--------|------|-------------|
| 0 | 8 | Store block range start offset (volume-relative) |
| 8 | 8 | Relative block range start offset (store-relative) |
| 16 | 8 | Block range size |

### Store Bitmap

Each bit represents a 16,384-byte block. LSB = first bit in byte.
- **Previous bitmap**: bit set = block NOT in use by previous store
- **Current bitmap**: bit set = block NOT in use by current store

### Snapshot Reconstruction Algorithm

To reconstruct the volume at snapshot N (where N=1 is oldest):
1. Start with the **current volume data**
2. Apply store changes from **most recent store** (newest) first
3. Then apply next-most-recent store, working backwards
4. Continue until you reach store N

For each store, the block descriptor list maps: `original_offset -> store_data_offset`, meaning "the original data at `original_offset` was replaced; the old data is saved at `store_data_offset` in the store."

### Successive Block Descriptor Algorithm (Forward/Reverse Lists)

The block list is scanned front-to-back. For each new descriptor:
- If `not_used` flag (0x04): skip
- If `overlay` flag (0x02) NOT set and there's a matching forwarder in the reverse list: replace original offset
- If `forwarder` flag (0x01) set and original == relative: skip
- Otherwise: add to block list or merge with overlay bitmap

## 1.3 VSS Metadata per Snapshot

Each snapshot stores:
- **Shadow copy identifier** (GUID)
- **Shadow copy set identifier** (GUID)
- **Creation timestamp** (FILETIME)
- **Originating machine** (Unicode string)
- **Service machine** (Unicode string)
- **Snapshot context** (backup type)
- **Attribute flags** (persistent, client-accessible, etc.)
- **Provider ID** (typically Microsoft Software Shadow Copy provider 1.0)
- **Volume size** at time of snapshot

## 1.4 Copy-on-Write (COW) Mechanism

VSS uses COW at 16KB block granularity:
1. When a write targets a block that hasn't been saved yet for the current snapshot period, the **original 16KB block** is first copied to the VSS store file
2. Then the new data is written to the original location
3. Block descriptors in the store maintain the mapping: original_offset <-> saved_copy_offset
4. Each block is only saved once per snapshot period (first-write tracking via bitmap)

**Redirect-on-Write** variant (used by some hardware providers):
- New data is written to a new location instead
- Original location retains old data
- Metadata updated to point to new location
- More efficient for write-heavy workloads

## 1.5 Registry Keys for VSS Detection

| Registry Path | Purpose |
|---------------|---------|
| `HKLM\SYSTEM\CurrentControlSet\Services\VSS` | VSS service configuration |
| `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToBackup` | Files excluded from backup |
| `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot` | Files deleted from new shadow copies (Vista+) |
| `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\KeysNotToRestore` | Registry keys not to restore |
| `Settings\MaxShadowCopies` | Max snapshots (default 64, range 1-512) |
| `Settings\MinDiffAreaFileSize` | Initial shadow storage size in MB |

## 1.6 Snapshot Scheduling

- **Windows Vista**: Every 24 hours (on idle or shutdown)
- **Windows 7+**: Every 7 days
- Also created: before Windows Updates, software installation, manual creation
- Always one "live" shadow copy collecting 16KB block changes
- When new snapshot created, live changes committed and archived

---

# Part 2: VSS Forensic Tools

## 2.1 libvshadow (Joachim Metz / libyal)

- **Repository**: https://github.com/libyal/libvshadow
- **Status**: Alpha, LGPL v3+
- **Latest release**: 20240504
- **Language**: C with Python bindings (pyvshadow)
- **Format spec**: 1184 lines of asciidoc documentation

**API Design** (C):
```c
libvshadow_volume_initialize(&volume, &error);
libvshadow_volume_open(volume, filename, LIBVSHADOW_OPEN_READ, &error);
libvshadow_volume_get_number_of_stores(volume, &count, &error);
libvshadow_volume_get_store(volume, index, &store, &error);
libvshadow_store_read_buffer(store, buffer, size, &error);
libvshadow_store_seek_offset(store, offset, whence, &error);
libvshadow_store_get_identifier(store, guid, 16, &error);
libvshadow_store_get_creation_time(store, &filetime, &error);
libvshadow_store_get_copy_identifier(store, guid, 16, &error);
libvshadow_store_get_copy_set_identifier(store, guid, 16, &error);
libvshadow_volume_close(volume, &error);
libvshadow_volume_free(&volume, &error);
```

**Key capabilities**: snapshot enumeration, reconstructed volume read at any snapshot point, metadata access, corruption handling, zero-fill unused blocks, FUSE mounting

**Tools**: vshadowinfo, vshadowmount (FUSE)

## 2.2 vss_carver (Minoru Kobayashi)

- **Repository**: https://github.com/mnrkbys/vss_carver
- **Released at**: JSAC 2018
- **Language**: Python 3.7+
- **Dependencies**: Patched libvshadow fork, pyewf, pyvmdk

**How it works**:
1. Scans the raw disk image for VSS store block headers (signature: VSS GUID)
2. Reconstructs the VSS catalog from found store blocks
3. Creates carved catalog and store files usable with vshadowmount
4. Can recover snapshots deleted by ransomware

**Tools**: vss_carver.py, vss_catalog_sorter.py, vss_catalog_manipulator.py

## 2.3 Other VSS Forensic Tools

| Tool | Capabilities |
|------|-------------|
| vshadowmount | FUSE mount individual VSS snapshots |
| Arsenal Image Mounter | Mount forensic images with VSS access |
| X-Ways Forensics | Parse volume shadow copies; can recover from deleted VSS |
| EnCase | VSS Examiner module (requires Windows API) |
| FTK / FTK Imager | Image file evidence for recovered VSS |
| Magnet AXIOM | Auto-identifies VSS, merges into timeline |
| ShadowExplorer | GUI VSS browser (live system only) |
| Velociraptor | VSS artifacts for live collection |
| KAPE | VSS collection targets |
| Plaso/log2timeline | Built-in VSS support with --vss_stores option |

## 2.4 Deleted VSS Recovery

**Key insight**: wmic/vssadmin deletion operates at file system layer only:
- VSS catalog entries zeroed out
- Store data files marked as deleted in NTFS
- **Actual 16KB data blocks remain until overwritten**

**Recovery approach** (vss_carver method):
1. Scan disk for VSS store block headers (VSS GUID signature)
2. Parse store block headers to find linked blocks
3. Reconstruct catalog from discovered stores
4. Use modified libvshadow to mount reconstructed snapshots

## 2.5 Anti-Forensic VSS Deletion (MITRE ATT&CK T1490)

### Common Deletion Methods

| Method | Command | Used By |
|--------|---------|---------|
| vssadmin | `vssadmin delete shadows /all /quiet` | REvil, WannaCry, RobbinHood |
| WMIC | `wmic shadowcopy delete` | CRYPVAULT, Nefilim |
| PowerShell | `Get-WmiObject Win32_ShadowCopy \| ForEach-Object { $_.Delete() }` | NetWalker |
| bcdedit | `bcdedit /set {default} recoveryenabled no` | Olympic Destroyer |
| wbadmin | `wbadmin delete catalog -quiet` | Multiple families |
| diskshadow | `diskshadow delete shadows all` | Advanced adversaries |
| DeviceIoControl | Resize shadow storage via IOCTL | Evasion technique |

### Ransomware Families Known to Delete VSS
WannaCry, LockBit, Conti, REvil/Sodinokibi, BlackCat/ALPHV, Black Basta, Babuk, Maze, Akira, Hakbit, BitPaymer, MegaCortex, Olympic Destroyer, CryptoWall 3.0, CRYPVAULT

### Detection
- Process monitoring: vssadmin.exe, wmic.exe, bcdedit.exe, powershell.exe with shadow-related args
- Event logs: WMI-Activity Operational 5857/5858 events
- Sysmon: Process creation EventID 1, Security EventID 4688
- CAR-2021-01-009 detection analytics

---

# Part 3: macOS -- APFS Snapshots

## 3.1 APFS Internals

### Container Structure
- **NX Superblock** (`nx_superblock_t`): Block 0 of partition. Magic: `NXSB`
- Checksum: Fletcher 64 (`o_cksum`)
- Contains: block size, block count, pointers to space manager, checkpoint areas
- `nx_fs_oid` field: list of volume OIDs

### Object Header (all APFS objects)
| Field | Description |
|-------|-------------|
| `o_cksum` | Fletcher 64 checksum |
| `o_oid` | Object identifier |
| `o_xid` | Most recent transaction ID |
| `o_type` | Low 16 bits = type, high 16 bits = flags |
| `o_subtype` | Data structure content type |

### Volume Superblock
- Magic: `APSB`
- Contains pointer to catalog B-tree
- `apfs_snap_meta_tree_oid`: Snapshot Metadata Tree OID
- `apfs_omap_oid`: Volume Object Map OID

### Checkpoints
- Checkpoint Descriptor Area: stores ephemeral objects for crash protection
- At end of each transaction, new state saved as checkpoint
- Chain of superblocks allows walking back through container states
- Located via `nx_xp_desc_base` field of block-zero superblock

## 3.2 APFS Snapshot Structure

### Copy-on-Write Mechanism
- When data changes, APFS writes new blocks and updates metadata pointers
- Old blocks NOT freed if a snapshot references them
- Snapshots share data blocks -- very space efficient
- Only changed blocks diverge between snapshots

### Snapshot Metadata Tree
A B-Tree located via `apfs_snap_meta_tree_oid` in the Volume Superblock.

**Snapshot Metadata Record** (`j_snap_metadata_val_t`):
```c
typedef struct j_snap_metadata_val {
  oid_t extentref_tree_oid;       // 0x00 - Extent reference B-Tree
  oid_t sblock_oid;               // 0x08 - Backup Volume Superblock
  uint64_t create_time;           // 0x10 - Creation timestamp
  uint64_t change_time;           // 0x18 - Last modification time
  uint64_t inum;                  // 0x20 - Reserved
  uint32_t extentref_tree_type;   // 0x28 - Extent ref tree type
  uint32_t flags;                 // 0x2C - Flags
  uint16_t name_len;              // 0x30 - Name length in bytes
  uint8_t name[0];                // 0x32 - UTF-8 snapshot name
} j_snap_metadata_val_t;
```

Key: `j_snap_metadata_key_t` with type `APFS_TYPE_SNAP_METADATA`. Object ID = snapshot's transaction ID.

**Snapshot Name Record** (`j_snap_name_key_t`):
```c
typedef struct j_snap_name_key {
  j_key_t hdr;
  uint16_t name_len;
  uint8_t name[0];    // UTF-8 name
} j_snap_name_key_t;

typedef struct j_snap_name_val {
  xid_t snap_xid;    // Transaction ID of snapshot
} j_snap_name_val_t;
```

### Object Map Snapshots
OMAP preserves File System Tree Nodes from earlier transactions. OMAP Snapshot Tree enumerates transaction IDs of each volume snapshot.

### Snapshot Reconstruction
1. Look up snapshot's transaction ID
2. Find snapshot's Volume Superblock backup (sblock_oid)
3. Use extent reference tree (extentref_tree_oid) for that snapshot
4. Resolve object references using OMAP, constrained to xid <= snapshot's xid

## 3.3 Time Machine Local Snapshots

- Created approximately every hour when Time Machine enabled
- Named: `com.apple.TimeMachine.YYYY-MM-DD-HHMMSS.local`
- Stored at filesystem metadata level, NOT as logical files
- Auto-purged: ~24 hours retention, or when disk space low
- On SSDs with TRIM, snapshots may be the ONLY way to recover deleted files

## 3.4 APFS Forensic Tools

| Tool | Capabilities |
|------|-------------|
| apfs-fuse (sgan81) | FUSE driver; snapshot mounting via `snap=<xid>` option |
| linux-apfs-rw | Kernel module; read-only snapshot mounting |
| libfsapfs (libyal) | C library; snapshot type defined but parsing NOT implemented |
| BlackLight/Cellebrite Inspector | Parse APFS snapshots from disk images |
| SUMURI RECON IMAGER | Acquires data including local Time Machine snapshots |

## 3.5 T2/Apple Silicon Challenges

- T2 chipset encrypts data at rest
- Must access through chipset for forensic imaging
- Sealed System Volumes (SSV) on Big Sur+ add cryptographic verification

---

# Part 4: Linux Snapshots

## 4.1 Btrfs Snapshots

### Internals
- COW filesystem using B-Trees for all internal structures
- **Subvolumes**: Independently mountable POSIX filetrees
- **Snapshots**: Subvolume sharing data/metadata with original via COW
- Creating a snapshot is nearly instantaneous

### Forensic Recovery
- Generation numbers allow access to previous filesystem states
- TSK extended with Btrfs support (DFRWS research by Hilgert et al.)
- Can recover data from degraded multi-device configurations
- Differential analysis between snapshots reveals file changes

## 4.2 ZFS Snapshots

- 128-bit addressing, COW design, transaction groups
- Uberblock array for crash recovery
- TSK extension: specify older txg to recover deleted files
- `zfs diff` for differences between snapshots

## 4.3 LVM Snapshots

- Block-level COW, filesystem-agnostic
- If COW area exhausted, snapshot becomes invalid
- Useful for live system imaging

---

# Part 5: Windows System Restore Points (Legacy, Pre-Vista)

## 5.1 Directory Structure

Location: `C:\System Volume Information\_restore{<machine-GUID>}\`

Each RPn directory contains: rp.log, change.log*, snapshot/ (with registry hives, NTUser.dat, Usrclass.dat, COM+ DB, WMI repository)

## 5.2 rp.log Format (RESTOREPOINTINFOW)

| Offset | Size | Description |
|--------|------|-------------|
| 0 | 4 | Event type (0x64=BEGIN_SYSTEM_CHANGE, etc.) |
| 4 | 4 | Restore point type (0=APP_INSTALL, 12=DRIVER, 16=CHECKPOINT) |
| 8 | 8 | Sequence number |
| 16 | 520 | Description (UTF-16 null-terminated) |
| Footer | 8 | Creation time (FILETIME) |

## 5.3 change.log Record Types

| Value | Type | Description |
|-------|------|-------------|
| 0 | RecordTypeLogHeader | Header for change log |
| 1 | RecordTypeLogEntry | Change log entry header |
| 2 | RecordTypeVolumePath | Volume path |
| 3 | RecordTypeFirstPath | File path |
| 4 | RecordTypeSecondPath | Renamed file path |
| 5 | RecordTypeTempPath | Backup file name |
| 6 | RecordTypeAclInline | Inline ACL (max 8192 bytes) |
| 7 | RecordTypeAclFile | ACL file reference |
| 8 | RecordTypeDebugInfo | Debug info |
| 9 | RecordTypeShortName | Short name |

## 5.4 fifo.log

Plain text entries like: `11/14/12-13:54:45 : Fifoed RP1 on drive C:\`
Records auto-deletion at 90 days or when space (12% of drive) is 90% full.

## 5.5 Registry: `HKLM\Software\Microsoft\Windows NT\CurrentVersion\SystemRestore`

---

# Part 6: Windows File History

## 6.1 Catalog1.edb (ESE Database)

Location: `%LocalAppData%\Microsoft\Windows\FileHistory\Configuration\`

### Tables
- **backupset**: Timestamps referenced by other tables
- **file**: File processing details, size, state/status
- **namespace**: Main table -- file/folder refs, attributes, fileCreated, fileModified, usnJournalEntry
- **global**: Key-value pairs (FirstBackupTime, LastBackupTime, etc.)
- **library**: Limited forensic value

### Default Configuration
- Schedule: hourly snapshots
- Retention: never purge
- Patent US9824091B2 documents internal state values

## 6.2 Tools
ESEDatabaseView (NirSoft), esedbinfo/libesedb, eseutil, PowerShell scripts

---

# Part 7: Windows Backup (wbadmin)

## 7.1 Structure
```
<drive>\WindowsImageBackup\<computer>\
  Backup YYYY-MM-DD HHMMSS\
    <volume>.vhd(x)
    *.xml
  Catalog\
    GlobalCatalog
    BackupGlobalCatalog
```

VHD (<=Win7, max 2TB) or VHDX (Win8+, max 64TB)
Block-level via VSS -- contains deleted files, slack space, unallocated

---

# Part 8: Temporal Filesystem Reconstruction

## 8.1 Data Sources (by granularity)

| Source | Granularity | Coverage |
|--------|-------------|----------|
| $LogFile | Sub-second transactions | Hours/days |
| $UsnJrnl | Per-operation timestamps | Days-weeks |
| $MFT | MACB timestamps | Full volume lifetime |
| VSS Snapshots | Full volume state | Days-months |
| File History | Per-file hourly | Months-years |

## 8.2 Reconstruction Algorithm

1. Find bracketing VSS snapshots around target time T
2. Start with earlier snapshot's complete state
3. Apply $UsnJrnl changes from snapshot time to T
4. Use $LogFile for sub-second precision
5. Cross-reference with $MFT timestamps for validation

## 8.3 Key Academic Research

- **NTFS Data Tracker** (2021): Tracks complete file data modification history through $LogFile
- **DFRWS EU 2019**: Deleted file fragment dating by neighbor cluster analysis
- **DFRWS APAC 2021**: ReFS journaling forensics (different from NTFS)
- **Btrfs Filesystem Forensics** (TU Wien 2014): First comprehensive Btrfs forensic analysis
- **ERNW Whitepaper**: APFS Internals for Forensic Analysis

## 8.4 Tools

- **Plaso/log2timeline**: Super timeline with VSS support (--vss_stores)
- **MFTECmd**: Parses MFT, $UsnJrnl, $LogFile including from VSS
- **TZWorks JP**: Journal parser with VSS cluster scanning
- **Velociraptor**: Real-time USN Journal parsing with path resolution

---

# Part 9: Cross-Platform Detection Checklist

### Windows
- Check `System Volume Information` for VSS catalog/store files
- Read VSS volume header at offset 0x1E00
- Parse registry for VSS configuration
- Check for File History ESE databases
- Check for WindowsImageBackup folders
- Check for legacy restore points (_restore{GUID})

### macOS
- Check APFS container for snapshot metadata tree
- Look for com.apple.TimeMachine.* snapshot names
- Examine Volume Superblock apfs_snap_meta_tree_oid

### Linux
- Detect Btrfs superblock, check for .snapshots subvolume
- Detect ZFS labels in first/last 256KB of disks
- Check for LVM headers

---

# Part 10: Rust Ecosystem Gap Analysis

## Available Crates

| Crate | Description |
|-------|-------------|
| ntfs (Colin Finck) | Low-level NTFS filesystem library |
| ntfs-reader | MFT and USN journal reading |
| usn-parser | USN Change Journal parser |
| forensic-rs | Forensic artifact analysis framework |
| nt_hive2 | Windows registry hive parser |
| rawcopy-rs-next | File copying via Windows VSS API (live only) |

## Critical Gap

**No Rust crate exists for offline forensic parsing of VSS on-disk format.** The only implementation is libvshadow (C). This is the primary opportunity for vsc-forensic.

## Proposed Architecture

```
vsc-forensic/
  src/
    lib.rs
    vss/                    # Windows VSS parsing
      volume_header.rs      # Parse 0x1E00 header
      catalog.rs            # Catalog blocks and entries
      store.rs              # Store blocks, headers, info
      block_descriptor.rs   # Diff area table parsing
      block_range.rs        # Store block range list
      bitmap.rs             # Store bitmap
      reconstruct.rs        # Volume reconstruction
      carver.rs             # Deleted VSS recovery
    apfs/                   # macOS APFS snapshot parsing
      container.rs          # NX Superblock
      volume.rs             # Volume Superblock
      snapshot.rs           # Snapshot Metadata Tree
      omap.rs               # Object Map
      checkpoint.rs         # Checkpoint navigation
    btrfs/                  # Linux Btrfs
      superblock.rs
      subvolume.rs
      snapshot.rs
    zfs/                    # ZFS
      uberblock.rs
      snapshot.rs
    restore_point/          # Legacy Windows XP
      rp_log.rs
      change_log.rs
      fifo_log.rs
    file_history/           # Windows File History
      ese_catalog.rs
      config.rs
    wbadmin/                # Windows Backup
      catalog.rs
      vhd.rs
    temporal/               # Temporal reconstruction
      timeline.rs
      anchor.rs
      interpolate.rs
      validate.rs
    common/
      guid.rs
      filetime.rs
      io.rs
```

---

# References

## VSS Format & Tools
- [libvshadow VSS format spec](https://github.com/libyal/libvshadow/blob/main/documentation/Volume%20Shadow%20Snapshot%20(VSS)%20format.asciidoc)
- [libvshadow repository](https://github.com/libyal/libvshadow)
- [vss_carver](https://github.com/mnrkbys/vss_carver)
- [Into The Shadows](https://forensic4cast.com/2010/04/into-the-shadows/)
- [deaddisk VSS](https://www.deaddisk.com/posts/vss/)
- [forensics.wiki Windows Shadow Volumes](https://forensics.wiki/windows_shadow_volumes/)
- [Deleted Shadow Copies analysis](https://www.kazamiya.net/en/DeletedSC)
- [BlackHat 2018 -- VSS Recovery](https://i.blackhat.com/us-18/Thu-August-9/us-18-Kobayashi-Reconstruct-The-World-From-Vanished-Shadow-Recovering-Deleted-VSS-Snapshots.pdf)

## APFS
- [Apple APFS Reference](https://developer.apple.com/support/downloads/Apple-File-System-Reference.pdf)
- [APFS Snapshot Metadata (Sylve)](https://jtsylve.blog/post/2022/12/28/APFS-Snapshot-Metadata)
- [ERNW APFS Forensics](https://static.ernw.de/whitepaper/ERNW_Whitepaper65_APFS-forensics_signed.pdf)
- [libfsapfs](https://github.com/libyal/libfsapfs)
- [apfs-fuse](https://github.com/sgan81/apfs-fuse)

## Linux
- [DFRWS Btrfs](https://dfrws.org/wp-content/uploads/2019/06/paper_forensic_analysis_of_multiple_device_btrfs_configurations_using_the_sleuth_kit.pdf)
- [TU Wien Btrfs Forensics](https://repositum.tuwien.at/bitstream/20.500.12708/7491/2/Juch%20Andreas%20-%202014%20-%20Btrfs%20filesystem%20forensics.pdf)

## Temporal Reconstruction
- [NTFS Data Tracker](https://www.sciencedirect.com/science/article/abs/pii/S2666281721002341)
- [DFRWS EU 2019](https://dfrws.org/wp-content/uploads/2019/06/2019_EU_paper-deleted_file_fragment_dating_by_analysis_of_allocated_neighbors.pdf)
- [DFRWS APAC 2021](https://dfrws.org/wp-content/uploads/2021/01/2021_APAC_paper-forensic_analysis_of_refs_journaling.pdf)
- [Plaso/log2timeline](https://github.com/log2timeline/plaso)

## Windows Restore Points & File History
- [Restore Point Formats (Metz)](https://github.com/libyal/dtformats/blob/main/documentation/Restore%20point%20formats.asciidoc)
- [PSBits File History](https://github.com/gtworek/PSBits/blob/master/docs/filehistory.md)
- [Microsoft Patent US9824091B2](https://patents.google.com/patent/US9824091B2)

## Anti-Forensics
- [MITRE ATT&CK T1490](https://attack.mitre.org/techniques/T1490/)
- [Atomic Red Team T1490](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1490/T1490.md)
- [MITRE CAR-2021-01-009](https://car.mitre.org/analytics/CAR-2021-01-009/)

## Rust Ecosystem
- [ntfs crate](https://crates.io/crates/ntfs)
- [forensic-rs](https://lib.rs/crates/forensic-rs)
- [usn-parser](https://crates.io/crates/usn-parser)
- [nt_hive2](https://crates.io/crates/nt_hive2)
