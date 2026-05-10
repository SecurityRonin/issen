# Snapshot & Backup Format Reference

Comprehensive technical reference for all snapshot, backup, and disk image formats
encountered in digital forensics. This document informs the design of `snapshot-forensic`,
a unified Rust crate for temporal filesystem reconstruction.

---

## Table of Contents

1. [Enterprise Backup Formats](#1-enterprise-backup-formats)
2. [Virtualization Snapshots](#2-virtualization-snapshots)
3. [Mobile Device Backups](#3-mobile-device-backups)
4. [Cloud Backup Formats](#4-cloud-backup-formats)
5. [Forensic Image Formats](#5-forensic-image-formats)
6. [Tape Backup Formats](#6-tape-backup-formats)
7. [Database / Application Backups](#7-database--application-backups)
8. [Container / Orchestration Snapshots](#8-container--orchestration-snapshots)
9. [NAS / Storage Snapshots](#9-nas--storage-snapshots)
10. [Rust Ecosystem Survey](#10-rust-ecosystem-survey)
11. [Unified Crate Design Considerations](#11-unified-crate-design-considerations)

---

## 1. Enterprise Backup Formats

### 1.1 Acronis TrueImage / Cyber Protect

#### TIB Format (Legacy)

| Property | Details |
|----------|---------|
| **Extension** | `.tib`, `.tib.metadata` |
| **Magic bytes** | Not publicly documented (proprietary) |
| **Compression** | Proprietary; LZ-based (variant unknown) |
| **Encryption** | AES-128, AES-192, AES-256 (optional) |
| **Backup types** | Full, incremental, differential |
| **Supported FS** | NTFS, FAT32, HFS+, APFS, ext2/3/4, ReiserFS, Linux Swap |

**Internal Structure:**
- Proprietary binary format with no official public documentation
- Mac and Windows versions produce different file format variants
- Format has evolved across versions (pre-2012, 2012-2019 distinct variants)
- Incremental backups: only changes from previous backup are stored
- Each `.tib` file is a self-contained backup point in older versions

**Key metadata:** Backup date/time, machine name, disk geometry/partition table, file system type

**TIBX Format (2020+):**
- Introduced in Acronis True Image 2020
- Consolidates all incremental backups into a single `.tibx` file
- Improved password hashing (replaced MD5 with stronger KDF)
- Not backward compatible with pre-2020 software
- Cloud-destination backups always use TIBX; local file/folder backups still use TIB

**Open-source parsers:**
- [dennisss/acronis-tib](https://github.com/dennisss/acronis-tib) (TypeScript/Node.js) - partial reverse engineering, integrity verification, FUSE planned, encryption TODO

**Forensic challenges:** Completely proprietary, multiple format variants, encryption blocks parsing, no Rust crate

---

### 1.2 Veeam Backup & Replication

| Property | Details |
|----------|---------|
| **Extensions** | `.vbk` (full), `.vib` (incremental), `.vrb` (reverse incremental), `.vbm` (metadata) |
| **Magic bytes** | Not publicly documented |
| **Compression** | LZ4, zstd (configurable per job) |
| **Encryption** | AES-256 (optional, header-indicated) |
| **Format basis** | Proprietary (not VHD/VHDX based) |

**Internal Structure (from Synacktiv 2024 reverse engineering):**
- Header with optional encryption details
- Metadata bank pairs followed by backup data blocks
- Size/offset varies due to compression
- Point structure: number (increments per restore point), type (0=Full, 1=Increment), creation time

**Backup Chain Methods:**
1. **Forever Forward Incremental:** VBK + VIBs; oldest VIB merged into VBK at retention
2. **Reverse Incremental:** VBK always current; old data pushed to VRBs
3. **Active Full / Synthetic Full:** New VBK created from chain summary

**Additional extensions:** `.vsb`, `.vlb`, `.vsm`, `.vlm`, `.vom`, `.vindex`, `.vslice`, `.vblob`, `.vbasket`, `.vlist`, `.vcache`, `.vacm`, `.vasm`

**Open-source tools:**
- [Synacktiv Velociraptor artifacts](https://www.synacktiv.com/en/publications/using-veeam-metadata-for-efficient-extraction-of-backup-artefacts-13) - `Windows.Veeam.RestorePoints.BackupFiles` and `.MetadataFiles`
- No Rust crate or C library exists

---

### 1.3 Veritas Backup Exec / NetBackup

| Property | Details |
|----------|---------|
| **Format** | Microsoft Tape Format (MTF) based |
| **Extensions** | `.bkf` (Backup Exec), various (NetBackup) |
| **Media types** | BKF, OST, IMG, tape |

**Catalog Structure:**
- **NetBackup:** Flat-file catalog under `/usr/openv/netbackup/db/images`, relational database
- **Backup Exec:** Disk-based catalog (XML + FH files) and media-based catalog on tape
- Inventory: read headers; Catalog: read metadata from media

---

### 1.4 Commvault

Proprietary format. Uses hierarchical indexing: Agent > Backup Set > Subclient. No public specification or open-source parser.

### 1.5 Cohesity / Rubrik

Both use proprietary internal formats accessible only via REST API:
- **Cohesity:** SpanFS distributed FS, DataLock immutability, [REST API](https://developer.cohesity.com/apidocs/versions/)
- **Rubrik:** Atlas/Cerebro, API-first/RBAC, immutable by default

Forensic approach: API-based extraction to standard VM formats only.

### 1.6 Datto / Kaseya SIRIS

| Property | Details |
|----------|---------|
| **Extensions** | `.datto` (unencrypted raw), `.detto` (AES-XTS encrypted) |
| **Storage** | ZFS filesystem on appliance |
| **Encryption** | AES-XTS via `cryptsetup` (plain, aes-xts-plain64) |
| **Export** | VMDK-linked, VHD, VHDX, RAW |

Inverse Chain Technology: each recovery point is fully constructed/bootable. Reverse engineering by [Slide Docs](https://docs.slide.tech/guides/manually-accessing-datto-reverse-roundtrip-backups/).

### 1.7 Nakivo / MSP360 (CloudBerry)

Both proprietary with no public format documentation or open-source parsers.

---

## 2. Virtualization Snapshots

### 2.1 VMware VMDK

| Property | Details |
|----------|---------|
| **Extension** | `.vmdk` (descriptor), `-flat.vmdk` (data), `-delta.vmdk` (snapshot), `-sesparse.vmdk` |
| **Magic bytes** | `KDMV` (0x564D444B LE, "VMDK" reversed) for sparse |
| **Official spec** | VMware Virtual Disk Format 5.0 Technical Note |

**Disk Types:**
1. **Flat (Fixed/Static):** Raw disk image, no special structure. Provisioning: thin, zeroedthick, eagerzeroedthick.
2. **Sparse (Dynamic):** Proprietary COW structure with two-level indirection.
3. **SEsparse:** Space-efficient sparse (ESXi 6.5+)

**Sparse Extent Structure:**
```
[Header - 512 bytes]
  Magic: KDMV (4 bytes)
  Version, flags, capacity, grain size
  Descriptor offset/size, GD offset, overhead
  Single/double end-of-line check bytes

[Grain Directory]
  Array of sector offsets pointing to Grain Tables
  Primary + secondary (redundant) directories

[Grain Table]
  512 entries per table
  Each entry: sector offset to grain data (0 = unallocated/sparse)
  Zeroed-grain: sector number 1 = grain is all zeros

[Grain Data]
  Default: 128 sectors = 64 KB per grain
```

**Delta VMDK (Snapshots):**
- `*-delta.vmdk` contains changes since snapshot point
- Chain: base.vmdk -> delta1 -> delta2 -> ...
- `.vmsd`: snapshot metadata (XML); `.vmsn`: VM memory state
- COW mechanism: writes to latest delta, reads fall through chain

**Stream-Optimized Compressed:** Markers between sections, footer has corrected GD offset (header has `GD_AT_END` = 0xFFFFFFFFFFFFFFFF)

**Reconstruction:** Walk chain from latest delta to base; for each grain, use first allocated version found.

**Open-source parsers:**
- [libvmdk](https://github.com/libyal/libvmdk) (C, libyal) - comprehensive
- `libvmdk-sys` Rust crate (v0.1.0, FFI bindings, 2018)
- QEMU `block/vmdk.c`

**References:** [libvmdk docs](https://github.com/libyal/libvmdk/blob/main/documentation/VMWare%20Virtual%20Disk%20Format%20(VMDK).asciidoc), [Forensicxlab walkthrough](https://www.forensicxlab.com/blog/vmdk)

---

### 2.2 Hyper-V VHD

| Property | Details |
|----------|---------|
| **Extension** | `.vhd` |
| **Magic bytes** | `conectix` (8 bytes, footer/header cookie) |
| **Max size** | ~2 TB (32-bit BAT) |
| **Official spec** | Microsoft Open Specification (MS-VHD) |

**Disk Types:** Fixed, Dynamic, Differencing

**Structure (Dynamic):**
```
[Footer Copy - 512 bytes at offset 0]
  Cookie: "conectix" (8 bytes)
  Features, format version, data offset, timestamp
  Creator app/version/host OS, original/current size
  Disk geometry, disk type (2=Fixed, 3=Dynamic, 4=Differencing)
  Checksum, unique ID, saved state

[Dynamic Disk Header]
  Cookie: "cxsparse" (8 bytes)
  Data offset: 0xFFFFFFFF, Table offset -> BAT
  Header version, max table entries, block size (default 2 MB)

[Block Allocation Table (BAT)]
  Array of 32-bit sector offsets
  0xFFFFFFFF = unallocated
  Offset = (BAT_entry * 512) + sector_bitmap_size

[Data Blocks]
  Sector bitmap + data per block
  Dynamic: 1=has data, 0=sparse
  Differencing: 1=in this file, 0=in parent
  Bitmap: MSB = first bit

[Footer - 512 bytes at end]
  Identical to footer copy at offset 0
```

**Parser:** [libvhdi](https://github.com/libyal/libvhdi) (C, libyal) - no Rust bindings

---

### 2.3 Hyper-V VHDX

| Property | Details |
|----------|---------|
| **Extension** | `.vhdx`, `.avhdx` (checkpoint) |
| **Magic bytes** | `vhdxfile` (file type identifier) |
| **Max size** | 64 TB |
| **Official spec** | [MS-VHDX](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-vhdx/) |

**Structure:**
```
[File Type Identifier - 1 MB]
  Signature: "vhdxfile"

[Header Section]
  Header 1 + Header 2 (dual, only one active, sequence numbers)
  Signature, checksum, sequence number, file/data write GUIDs, log GUID

[Region Table]
  Lists: BAT region + Metadata region (MB-aligned, non-overlapping)

[Log Section]
  Crash-consistency replay log
  BAT/metadata updates MUST go through log; payload data NOT logged

[BAT Region]
  Entries grouped in chunks: (2^23 * logical_sector_size) / block_size
  States: PAYLOAD_BLOCK_NOT_PRESENT, _UNMAPPED, _FULLY_PRESENT, _PARTIALLY_PRESENT
  Sector bitmap blocks interleaved (for differencing)

[Metadata Region]
  File parameters, virtual disk size, logical/physical sector size
  Parent locator (differencing disks)

[Payload Blocks] - actual disk data, 1 MB aligned
[Sector Bitmap Blocks] - 1 MiB each, LSB = first bit (opposite of VHD!)
```

**AVHDX (Checkpoints):** Differencing disk chain. `.vmcx` (binary VM config), `.vmrs` (runtime state)

**Rust crate:** `vhdx` on crates.io; also [libvhdi](https://github.com/libyal/libvhdi) (C)

---

### 2.4 VirtualBox VDI

| Property | Details |
|----------|---------|
| **Extension** | `.vdi` |
| **Magic bytes** | `0x7F10DABE` (signature at offset 0x40) |
| **Pre-header** | `"<<< Sun xVM VirtualBox Disk Image >>>"` |

**Types:** Dynamic (1), Static (2), Undo (3), Diff (4)

**Structure:**
```
[Pre-Header - 0x40 bytes]
  Description text string

[Signature + Version]
  0x7F10DABE (4 bytes), Version major.minor

[Header Main]
  Image type, flags, description
  Blocks map offset, data offset
  Geometry (C/H/S), disk size
  Block data size (1 MB default), block metadata size
  Total blocks, allocated blocks
  UUIDs: image, last snapshot, link, parent

[Block Map]
  Array of uint32, one entry per 1 MB of virtual disk
  0xFFFFFFFF = unallocated, 0xFFFFFFFE = discarded

[Padding] - alignment (512, 4096, or 1 MB)
[Image Blocks] - 1 MB each
```

**Address translation:** `blocks_map[offset/block_size] * block_size + metadata_size + (offset % block_size)`

**Snapshot:** Diff type images with parent UUID linking. `.sav` state files in snapshot folder.

**Parsers:** QEMU `block/vdi.c`, VirtualBox `Storage/VDI.cpp`, [Kaitai Struct](https://formats.kaitai.io/vdi/)

---

### 2.5 QEMU/KVM QCOW2

| Property | Details |
|----------|---------|
| **Extension** | `.qcow2` |
| **Magic bytes** | `QFI\xfb` (0x514649FB, 4 bytes) |
| **Versions** | 2, 3 (with feature flags) |
| **Official spec** | [QEMU docs](https://www.qemu.org/docs/master/interop/qcow2.html) |

**Header (version 3):**
```
Offset  Size  Field
0       4     magic: 0x514649FB
4       4     version: 2 or 3
8       8     backing_file_offset
16      4     backing_file_size
20      4     cluster_bits (default 16 = 64KB clusters)
24      8     size (virtual disk size in bytes)
32      4     crypt_method (0=none, 1=AES, 2=LUKS)
36      4     l1_size (entries in active L1 table)
40      8     l1_table_offset
48      8     refcount_table_offset
56      4     refcount_table_clusters
60      4     nb_snapshots
64      8     snapshots_offset
--- Version 3 only ---
72      8     incompatible_features (bit0=dirty, bit1=corrupt)
80      8     compatible_features (bit0=lazy_refcounts)
88      8     autoclear_features
96      4     refcount_order (default 4 = 16-bit refcounts)
100     4     header_length
```

**Two-Level Address Translation (L1/L2):**
```
Guest address decomposition:
  L1 index = (guest_offset / cluster_size) / l2_entries
  L2 index = (guest_offset / cluster_size) % l2_entries
  In-cluster offset = guest_offset % cluster_size

L1 Entry (8 bytes):
  Bits 9-55: L2 table offset (cluster-aligned), 0=unallocated
  Bit 63: copied flag (refcount == 1)

L2 Entry (8 bytes):
  Standard cluster:
    Bits 0-61: host cluster offset, 0=unallocated
    Bit 62: 0 (standard)
    Bit 63: copied flag
  Compressed cluster:
    Bits 0-61: compressed offset + size
    Bit 62: 1 (compressed)
```

**Reference Counting:**
- Two-level: refcount table -> refcount blocks (each 1 cluster)
- Configurable width: 1/2/4/8/16/32/64 bits per entry
- refcount >= 2: cluster shared by snapshots, COW required on write
- refcount == 1: "copied" flag set in L1/L2 (fast path, no COW needed)

**Internal Snapshots:**
- Stored in same file at `snapshots_offset`
- Creation: copy L1 table, increment refcounts for all reachable L2 tables and data clusters
- Loading: reconstruct bit 63 of all entries from refcount table
- Snapshot table entry: L1 offset, L1 size, ID string, name string, timestamps, extra data

**External Snapshots:** Backing file chain (`backing_file_offset` in header)

**Compression:** zlib per cluster (bit 62 of L2 entry set)
**Encryption:** AES-128-CBC (crypt_method=1, legacy) or LUKS (crypt_method=2, v3+)

**Rust crates:**
- `qcow2` - parse and read QCOW2 images
- `imago` - async-first, QCOW2 + raw

**References:** [QEMU spec](https://qemu.readthedocs.io/en/master/interop/qcow2.html), [libqcow docs](https://github.com/libyal/libqcow/blob/main/documentation/QEMU%20Copy-On-Write%20file%20format.asciidoc)

---

### 2.6 Proxmox VMA (Virtual Machine Archive)

| Property | Details |
|----------|---------|
| **Extension** | `.vma` (+ `.gz`, `.lzo`, `.zstd` wrappers) |
| **Magic/ID** | Random UUID per archive |
| **Spec** | `vma_spec.txt` in [pve-qemu](https://git.proxmox.com/?p=pve-qemu.git;a=blob_plain;f=vma_spec.txt;hb=refs/heads/master) |

**Structure:**
```
[VMA Header]
  UUID (random, unique per archive)
  VM configuration (binary blobs)
  Device list: (dev_id, device_name) pairs
  MD5 checksum of header

[Extents] (sequence)
  [Extent Header - 512 bytes]
    UUID reference, MD5 checksum
    Up to 64 cluster descriptors (8 bytes each):
      dev_id (1B), reserved (1B), zero_indicator (2B, 16x4096B flags), cluster_number (4B)
  [Data Blocks]
    Only non-zero 4096-byte blocks stored
    Up to 3776 KiB per extent
```

Cluster size: 64 KiB. Blocks stored out-of-order between runs.

**Tools:** [vma-extractor](https://github.com/jancc/vma-extractor) (Python), [vma-tool](https://github.com/gustaebel/vma-tool) (Python)

---

### 2.7 Citrix XenServer / XCP-ng (XVA)

| Property | Details |
|----------|---------|
| **Extension** | `.xva` |
| **Container** | tar archive |
| **Metadata** | `ova.xml` (XML, 300+ VM parameters) |

Disk blocks: separate 1 MB raw files in named directory, with per-block checksums (`.checksum` pre-8.1, `.xxhash` 8.1+). Hypervisor-neutral packaging format.

---

## 3. Mobile Device Backups

### 3.1 Apple iTunes / Finder Backups

| Property | Details |
|----------|---------|
| **Location** | `~/Library/Application Support/MobileSync/Backup/{UDID}/` |
| **Key files** | `Manifest.db`, `Manifest.plist`, `Info.plist`, `Status.plist` |
| **File naming** | SHA-1(domain + "-" + relativePath) |
| **Encryption** | PBKDF2-SHA256 (10M iter) + PBKDF2-SHA1 (10K iter) -> KEK -> AES-256-CBC |

**Backup Structure:**
```
{UDID}/
  Info.plist              # Device info (name, UDID, iOS version, serial)
  Manifest.plist          # Backup metadata, encrypted keybag, ManifestKey
  Manifest.db             # SQLite: file mapping (encrypted if backup encrypted)
  Status.plist            # Backup completion status
  00/ - ff/               # Subdirectories by first 2 hex chars of SHA-1 hash
    {sha1_hash}           # Actual backup file data
```

**Manifest.db Schema:**
```sql
CREATE TABLE Files (
  fileID TEXT,        -- SHA-1(domain + "-" + relativePath)
  domain TEXT,        -- e.g., "HomeDomain", "AppDomain-com.example.app"
  relativePath TEXT,  -- Original path within domain
  flags INTEGER,      -- File type flags
  file BLOB           -- Binary plist (MBFile): ProtectionClass, EncryptionKey, metadata
);
```

**Keybag Structure (TLV in Manifest.plist > BackupKeyBag):**
- Big-endian: 4-byte tag + 4-byte length + value
- Global tags: VERS, TYPE, UUID, HMCK, WRAP, SALT, ITER, DPSL, DPIC
- Per-class tags: CLAS, KTYP, WPKY (wrapped key)
- Protection classes: Complete, CompleteUnlessOpen, UntilFirstAuth, None

**Decryption Process:**
```
1. password -> PBKDF2-SHA256(password, DPSL, DPIC=10000000, 32) -> intermediate_key
2. intermediate_key -> PBKDF2-SHA1(intermediate_key, SALT, ITER=10000, 32) -> KEK
3. For each class: RFC 3394 AES Key Unwrap(KEK, WPKY) -> class_key
4. ManifestKey (from Manifest.plist): first 4 bytes LE = protection class, rest = wrapped key
5. Unwrap ManifestKey with class 3 key -> manifest_decryption_key
6. AES-256-CBC(manifest_decryption_key, IV=0x00*16) -> decrypted Manifest.db
7. Per file: unwrap EncryptionKey (from file blob) with appropriate class key
8. AES-256-CBC(file_key, IV=0x00*16) -> decrypted file
```

**Legacy (pre-iOS 10):** `Manifest.mbdb` binary format instead of SQLite

**Tools:**
- [iphone_backup_decrypt](https://github.com/jsharkey13/iphone_backup_decrypt) (Python)
- [libimobiledevice](https://libimobiledevice.org/) (C)
- [dunhamsteve/ios](https://github.com/dunhamsteve/ios) (Go)
- Hashcat: mode 14700 (iOS <10), mode 14800 (iOS >=10)

---

### 3.2 Android ADB Backup

| Property | Details |
|----------|---------|
| **Extension** | `.ab` |
| **Magic** | `ANDROID BACKUP\n` (first line) |
| **Format** | 4-line text header + DEFLATE-compressed TAR |
| **Encryption** | Optional AES-256 (password-based) |
| **Requires root** | No |
| **Android version** | 4.0+ (Ice Cream Sandwich) |

**Header (4 lines of text):**
```
ANDROID BACKUP         # Line 1: Magic
5                      # Line 2: Version number
1                      # Line 3: Compression (1=yes, 0=no)
none                   # Line 4: Encryption ("none" or "AES-256")
[binary DEFLATE data]
```

**Manual decompression (unencrypted):**
```bash
dd if=backup.ab bs=24 skip=1 | \
  (printf '\x1f\x8b\x08\x00\x00\x00\x00\x00' ; cat) | gzip -d > backup.tar
```

**Contents:** App data, settings, shared preferences, databases (not root-level)
**Limitation:** Developers can opt out via `android:allowBackup="false"`

**Tools:** Android Backup Extractor (`abe.jar`), Cellebrite, Oxygen, Magnet AXIOM, MOBILedit

---

### 3.3 Samsung Smart Switch

| Property | Details |
|----------|---------|
| **Extensions** | `.sbu` (pre-Kies 2.5.2), folder with `.bk` (Smart Switch) |
| **Encryption** | AES-256 + GZIP + Base64 |

**History:**
- Kies <= 2.5.1: Single `.sbu` file (header + metadata + data)
- Kies 2.5.2+/Smart Switch: Separate encrypted files per item, folder structure with `.bk` index
- iOS transfer: `DATA_0` folder with ZIP files containing SHA1-named files (iOS backup style)

**PIN recovery:** Up to 9-digit PIN recoverable via precomputed table (~30 GB, ~11 min)

**Research:** "How to decrypt PIN-Based encrypted backup data of Samsung smartphones" (Digital Investigation, 2018)

---

### 3.4 Huawei HiSuite / KoBackup

| Property | Details |
|----------|---------|
| **Entry point** | `info.xml` |
| **Location** | `C:/Users/%User%/Documents/HiSuite/backup/` |
| **Encryption** | Password-based (reversible with analysis) |

**Tool:** [kobackupdec](https://github.com/RealityNet/kobackupdec) (Python3) - supports v9/v10 structures
**Decrypted output:** `data/app/`, `data/data/`, `db/`, `storage/` (mimics Android structure)

**Research:** "Decrypting password-based encrypted backup data for Huawei smartphones" (Digital Investigation, 2019); "A study on data acquisition based on the Huawei smartphone backup protocol" (2022)

### 3.5 Xiaomi MIUI Backup

**Location:** `MIUI/backup/AllBackup/[YYYYMMDD_random]/`
**Contents:** System settings, contacts, call logs, messages, Wi-Fi passwords
**Tool support:** Belkasoft Evidence Center v9.7+, MOBILedit

---

## 4. Cloud Backup Formats

### 4.1 Google Takeout

ZIP archive with service-organized folders. Each content file has companion `.json` metadata (timestamps, titles, descriptions, GPS coordinates for photos).

### 4.2 Apple iCloud Backup

| Property | Details |
|----------|---------|
| **Protocol** | Protobuf-based |
| **Storage** | Chunked, per-chunk encryption |
| **Providers** | Apple, Amazon S3, Microsoft Azure |
| **Snapshots** | Up to 2 most recent per device |

Files split into chunks of varying sizes, each encrypted with key derived from chunk data. Apple provides file-to-chunk mapping and encryption keys. iOS 15+: temporary backups (21-day retention, no storage quota impact).

**Tools:**
- [InflatableDonkey](https://github.com/horrorho/InflatableDonkey) (Java, iOS 9+ PoC)
- ElcomSoft Phone Breaker (commercial)
- [protobuf-inspector](https://github.com/mildsunrise/protobuf-inspector) for raw protobuf analysis

### 4.3 Microsoft 365

No standardized export format. Access via Graph API, eDiscovery PST export, or third-party tools.

---

## 5. Forensic Image Formats

### 5.1 E01 (EnCase / Expert Witness Format)

| Property | Details |
|----------|---------|
| **Extensions** | `.E01`, `.E02`, ..., `.E99`, `.EAA`, ... |
| **File header** | 13 bytes per segment file |
| **Section types** | header, volume, table, next, done |
| **Chunk size** | 32 KB (64 x 512-byte sectors) |
| **Segment size** | ~640 MB per file |
| **Compression** | zlib ('b'=best, 'f'=fastest, 'n'=none) |
| **Hashing** | MD5 (v3+), SHA-1 (v6+), CRC per chunk |

**Structure per segment:**
```
[13-byte file header]
  File signature identifying EWF format

[Sections] (back-to-back, each starting with 76-byte descriptor)
  header section:  case info, examiner, description, timestamps
  volume section:  media info, sector count, chunk count
  table section:   chunk offset table
  data section:    compressed chunk data with interlaced CRCs
  ...

[Last section]
  "next" (more segments follow) or "done" (final segment)
```

**Metadata (header section):**
- Case number, evidence number, unique description
- Examiner name, notes
- Media description, acquisition date/time
- MD5/SHA-1 hash in dedicated "hash" section (last segment)

**EWF-X (Extended):** XML-based headers/hash sections for richer metadata (libewf project)

**Parser:** [libewf](https://github.com/libyal/libewf) (C, libyal) - tools: ewfexport, ewfinfo, ewfverify. Python: pyewf. No published Rust `-sys` crate.

---

### 5.2 Ex01 (EnCase v2 / EWF2)

| Property | Details |
|----------|---------|
| **Extension** | `.Ex01` |
| **Introduced** | EnCase 7 (Guidance Software) |
| **Compression** | Lzxpress / bzip2 (single level) |
| **Encryption** | AES-256 (data + metadata) |
| **Hashing** | MD5, SHA-1 |

Significantly different internal structure from EWF v1. Reference: [libewf EWF2 docs](https://github.com/libyal/libewf/blob/main/documentation/Expert%20Witness%20Compression%20Format%202%20(EWF2).asciidoc)

---

### 5.3 AFF4 (Advanced Forensic Format 4)

| Property | Details |
|----------|---------|
| **Extension** | `.aff4` |
| **Container** | ZIP64 archive |
| **Metadata** | RDF / Turtle (`information.turtle`) |
| **URN scheme** | `urn:aff4:{UUID}` (RFC 4122) |
| **Namespace** | `http://aff4.org/Schema#` |
| **Spec** | [aff4/Standard v1.0a](https://github.com/aff4/Standard/blob/master/inprogress/AFF4StandardSpecification-v1.0a.md) |

**Structure:**
```
[ZIP64 Archive]
  version.txt                    # Format version
  information.turtle             # RDF metadata (Turtle serialization)
  {urn}/
    00000000                     # Bevy 0 (chunk data)
    00000000.index               # Bevy 0 index
    00000001                     # Bevy 1
    00000001.index
    ...
```

**ImageStream:** Chunks (default 32,768 bytes) stored in Bevies. Index entry: `{ bevy_offset: u64, chunk_size: u32 }`

**MapStream (AFF4-L logical images):**
- Target dictionary: ID -> stream name
- Intervals list: (virtual_offset, length, target_offset, target_index)

**Hashing:** Block hashing (primary, validated on read) + full stream hashing. RDF datatype URIs for algorithms.

**Volume types:** ZipFile (single archive) or Directory (flat files, good for FAT filesystem)

**Implementations:** [pyaff4](https://github.com/aff4/pyaff4) (Python), [c-aff4](https://github.com/aff4/c-aff4) (C++). No Rust crate.

---

### 5.4 AD1 (FTK / AccessData)

| Property | Details |
|----------|---------|
| **Extension** | `.ad1` |
| **Type** | Logical evidence container |
| **Creator** | AccessData / Exterro |
| **Spec** | Proprietary, not published |

Proprietary container for file-level acquisitions. Encrypted variant: ADCRYPT. Preserves filenames, timestamps, sizes, hashes, permissions, paths.

**Tools:** [AD1-tools](https://github.com/al3ks1s/AD1-tools) (C, Linux) - extraction, verification, FUSE mounting; [reverse engineering blog](https://al3ks1s.fr/posts/adventures-part-1/)

---

### 5.5 L01 / Lx01 (EnCase Logical Evidence)

| Property | Details |
|----------|---------|
| **Extensions** | `.L01` (legacy), `.Lx01` (EnCase 7+) |
| **Basis** | EWF sections (similar to E01) |
| **Type** | Logical evidence file |

Stores files with full metadata (name, timestamps, sizes, hashes, permissions, original paths). Lx01 adds AES-256 encryption and LZ compression. Reverse-engineered by Joachim Metz (libewf, EWF_L01 subtype). Academic analysis: "Revisiting logical image formats" (2024).

---

### 5.6 DMG (Apple Disk Image / UDIF)

| Property | Details |
|----------|---------|
| **Extension** | `.dmg` |
| **Format** | UDIF (Universal Disk Image Format) |
| **Spec** | Not published by Apple (reverse-engineered) |

**Variants:** UDRW (read/write), UDZO (zlib-compressed), UDBZ (bzip2, deprecated), ULFO (LZFSE), UDSP (sparse), UDSB (sparse bundle)

**Structure:** Block data (partition table + filesystem) + mish structure (block/chunk table). Internal FS: APFS, HFS+, FAT, ExFAT.

**Encryption:** v1 (pre-10.5): `cdsaencr` trailer; v2 (10.5+): `encrcdsa` header. AES-128 or AES-256.

**Parser:** [libmodi](https://github.com/libyal/libmodi) (C, libyal), darling-dmg (FUSE, Linux), hdiutil (macOS)

### 5.7 Raw / dd Images

No container format. Extensions: `.dd`, `.raw`, `.img`, `.bin`, `.001`/`.002`/... (split). Simple contiguous byte stream.

---

## 6. Tape Backup Formats

### 6.1 tar (Tape Archive)

| Property | Details |
|----------|---------|
| **Block size** | 512 bytes |
| **Variants** | v7, POSIX (ustar), GNU, pax |

**Header (512 bytes per entry):**
```
0-99:    filename (100B)
100-107: mode (8B octal)
108-115: uid (8B), 116-123: gid (8B)
124-135: size (12B octal)
136-147: mtime (12B octal)
148-155: checksum (8B)
156:     typeflag (1B)
157-256: linkname (100B)
257-262: magic "ustar" (6B, POSIX)
263-264: version (2B)
265-296: uname (32B), 297-328: gname (32B)
329-336: devmajor (8B), 337-344: devminor (8B)
345-499: prefix (155B)
500-511: padding (12B)
```

**Rust crate:** `tar` (well-maintained, widely used)

### 6.2 cpio

**Variants:** Binary (old), ASCII odc (`070707`), New ASCII newc (`070701`), CRC (`070702`)

### 6.3 Microsoft Tape Format (MTF)

| Property | Details |
|----------|---------|
| **Extensions** | `.bkf` (NTBackup) |
| **Magic** | `TAPE` (0x45504154) as first DBLK type |
| **Used by** | NTBackup, Backup Exec, SQL Server, Veeam (partial) |

**Elements:** Descriptor Blocks (DBLKs), Data Streams, Filemarks

**DBLK Types:**

| Magic | ASCII | Purpose |
|-------|-------|---------|
| 0x45504154 | TAPE | Tape header |
| 0x54455353 | SSET | Start of Set |
| 0x424C4F56 | VOLB | Volume block |
| 0x42524944 | DIRB | Directory block |
| 0x454C4946 | FILE | File block |
| 0x4C494643 | CFIL | Corrupt file |
| 0x42505345 | ESPB | End of Set Pad |
| 0x54455345 | ESET | End of Set |
| 0x4D544F45 | EOTM | End of Tape Media |
| 0x424D4653 | SFMB | Soft Filemark |

**Common Block Header (94 bytes):**
```
type:     u32    DBLK type
attr:     u32    Block attributes
off:      u16    Offset to first event
osId:     u8     OS ID
osVer:    u8     OS version
size:     u64    Displayable size
fla:      u64    Format logical address
mbc:      u16    Reserved for MBC
cbId:     u32    Control block ID
osData:   MTF_TAPE_ADDRESS
strType:  u8     String type
check:    u16    Header checksum
```

**Tools:** [mtf](https://github.com/KyleBruene/mtf) (C), mtftar, [CodeProject reader](https://www.codeproject.com/articles/Reading-MTF-Backup-Files), Java MTF Reader

### 6.4 LTFS (Linear Tape File System)

| Property | Details |
|----------|---------|
| **Standard** | ISO/IEC 20919:2021, SNIA v2.5 |
| **Partitions** | Index Partition + Data Partition |
| **Index** | XML document |

Dual partition: Index Partition stores XML index + optional small files; Data Partition stores file data as sequential blocks. Constructs: Label (VOL1 + LTFS label), Index (file mark + XML + file mark), Data Extent.

Index includes generation number, back pointers, data placement policy. Incremental indexes (v2.5+): sparse, changes-only.

**Reference implementation:** [LinearTapeFileSystem/ltfs](https://github.com/LinearTapeFileSystem/ltfs)

---

## 7. Database / Application Backups

### 7.1 SQL Server .bak

| Property | Details |
|----------|---------|
| **Extension** | `.bak` |
| **Basis** | Modified MTF (non-standard) |
| **Magic** | `TAPE` header, vendor ID 0x1200 (Microsoft) |

SQL Server BAK is "apparently based on MTF but many blocks aren't defined in the documentation, some link to invalid places." It is NOT standard MTF. T-SQL: `RESTORE HEADERONLY/FILELISTONLY/LABELONLY`.

**Tool:** [unraveling_sql_server_bak](https://github.com/klandermans/unraveling_sql_server_bak) (converts to SQLite)

### 7.2 MySQL/MariaDB

Text `.sql` dumps (SQL statements) or binary via Percona xtrabackup (raw InnoDB data files + metadata).

### 7.3 PostgreSQL

`pg_dump` custom format (compressed, selective restore) or WAL-based PITR (Write-Ahead Log segments).

---

## 8. Container / Orchestration Snapshots

### 8.1 Docker / OCI Images

| Property | Details |
|----------|---------|
| **Spec** | [OCI Image Specification](https://github.com/opencontainers/image-spec) |
| **Layers** | tar + gzip or zstd |
| **Manifest** | JSON (`application/vnd.oci.image.manifest.v1+json`) |

**OCI Image Layout:**
```
blobs/sha256/
  {manifest_digest}     # Image manifest (JSON)
  {config_digest}       # Image config (JSON): created, architecture, os, rootfs, history
  {layer1_digest}       # Layer 1 (tar+gzip)
  {layer2_digest}       # Layer 2 (tar+gzip)
index.json              # Entry point (image index)
oci-layout              # Layout version
```

**Layer format:** tar archive, applied bottom-up (layers[0] = base). Whiteout: `.wh.{filename}` = deletion, `.wh..wh..opq` = opaque (replace directory).

### 8.2 Kubernetes

etcd snapshots: Bolt DB files. PV snapshots: CSI driver-specific (vendor dependent).

---

## 9. NAS / Storage Snapshots

### 9.1 Synology Hyper Backup (.hbk)

| Property | Details |
|----------|---------|
| **Extension** | `.hbk` (actually a folder) |
| **Encryption** | AES-256, ECC Curve25519 |
| **Max versions** | 65,535 |

```
.hbk/
  Config/                      # Version configs
  Control/                     # Control data
  Guard/                       # Integrity
  Pool/                        # Deduplicated data (idx + bucket files)
  storage_statistics.db.XXXX   # SQLite
  synobkpinfo.db               # SQLite (backup info)
  SynologyHyperBackup.bkpi     # Marker (0 bytes)
  _Syno_TaskConfig             # Task config
```

File-level and block-level deduplication. No open-source parser (SOS Ransomware has commercial recovery tool).

### 9.2 QNAP Hybrid Backup Sync

Proprietary. May use ZFS snapshots on ZFS-capable models.

### 9.3 NetApp WAFL / SnapMirror

Proprietary WAFL snapshots, SnapMirror/SnapVault replication. API access only.

### 9.4 TrueNAS / FreeNAS (ZFS)

ZFS snapshots: filesystem-level, no separate file format. `zfs send/receive` streams documented in OpenZFS.

---

## 10. Rust Ecosystem Survey

### Published Crates

| Crate | Formats | Status | License |
|-------|---------|--------|---------|
| **qcow2** | QCOW2 | Published | - |
| **imago** | QCOW2, Raw | Published, async-first | - |
| **vhdx** | VHDX | Published, MS-VHDX based | - |
| **guestkit** | QCOW2, VMDK, VDI, VHD/VHDX, RAW | Published | LGPL-3.0 |
| **libvmdk-sys** | VMDK (FFI to libvmdk) | v0.1.0 (2018) | LGPL-3.0 |
| **rdisk** | VHD, VHDX, VMDK + FS | v0.1.0, unmaintained | - |
| **file-format** | Detection only (VHD, VHDX, VMDK, QCOW, VDI, DMG) | Active | - |
| **tar** | tar archives | Active, well-maintained | MIT/Apache-2.0 |
| **forensic-rs** | Forensic analysis framework | Active, pure Rust | - |

### C Libraries Needing Rust Bindings

| Library | Formats | Rust Bindings |
|---------|---------|---------------|
| **libewf** | E01, Ex01, L01, Lx01 | None published |
| **libvmdk** | VMDK | `libvmdk-sys` v0.1.0 |
| **libvhdi** | VHD, VHDX | None published |
| **libqcow** | QCOW, QCOW2 | None published |
| **libmodi** | DMG/UDIF | None published |

### Key Ecosystem Notes

- **ForensicRS** ([github.com/ForensicRS](https://github.com/ForensicRS)): Pure Rust, no C deps, modular
- DFRWS 2024: "Transitioning from Python to Rust for Forensic Tool Creation"
- Matthew Seyer: Rust DFIR community interest but "hard until forensics libs are accessible"

---

## 11. Unified Crate Design Considerations

### Format Priority Matrix

**Tier 1 (High priority, well-documented):**
E01/Ex01, VMDK, VHD/VHDX, QCOW2, Raw/dd, iOS backup

**Tier 2 (Medium priority):**
VDI, AFF4, VMA, Android ADB, tar/cpio, OCI layers, DMG

**Tier 3 (Lower priority, proprietary/undocumented):**
Acronis TIB/TIBX, Veeam VBK, AD1, L01/Lx01, MTF/BKF, mobile backups, Synology HBK, Datto

**Tier 4 (API-only, no direct parsing):**
Cohesity, Rubrik, NetApp, Commvault, iCloud

### Unified Trait Design

```rust
/// Core trait for any snapshot/backup format reader
pub trait SnapshotReader {
    /// List all available snapshots/restore points in chronological order
    fn list_snapshots(&self) -> Result<Vec<SnapshotInfo>>;

    /// Get filesystem tree at a specific snapshot point
    fn filesystem_at(&self, snapshot: &SnapshotId) -> Result<Box<dyn FileSystem>>;

    /// Read raw bytes at disk offset for a specific snapshot (disk-level formats)
    fn read_at(&self, snapshot: &SnapshotId, offset: u64, buf: &mut [u8]) -> Result<usize>;

    /// Format metadata (machine name, backup date, disk geometry, etc.)
    fn metadata(&self) -> Result<FormatMetadata>;
}

/// Metadata common across all formats
pub struct FormatMetadata {
    pub format_type: FormatType,
    pub format_version: Option<String>,
    pub created: Option<DateTime<Utc>>,
    pub machine_name: Option<String>,
    pub disk_geometry: Option<DiskGeometry>,
    pub partition_table: Option<PartitionTable>,
    pub encryption: EncryptionInfo,
    pub compression: CompressionInfo,
    pub hashes: Vec<HashInfo>,
}

/// Snapshot/restore point information
pub struct SnapshotInfo {
    pub id: SnapshotId,
    pub name: Option<String>,
    pub timestamp: Option<DateTime<Utc>>,
    pub parent: Option<SnapshotId>,
    pub snapshot_type: SnapshotType, // Full, Incremental, Differential, Reverse
    pub size: Option<u64>,
}
```

### Architecture

1. **Pure Rust preferred** over FFI for safety, portability, and `no_std` potential
2. **Async-first** design (tokio) for I/O-heavy forensic workloads
3. **Zero-copy** via memory-mapped files (`memmap2`) for large images
4. **Layered sub-crates:**
   - `snapshot-forensic-detect`: Format detection via magic bytes
   - `snapshot-forensic-vm`: VMDK, VHD/VHDX, VDI, QCOW2
   - `snapshot-forensic-ewf`: E01, Ex01, L01, AFF4
   - `snapshot-forensic-mobile`: iOS backup, Android ADB
   - `snapshot-forensic-enterprise`: Veeam, Acronis, Datto, VMA
   - `snapshot-forensic`: Unified re-export + auto-detection
5. **Snapshot chain resolution** as first-class feature
6. **Temporal reconstruction:** Given backup chain, reconstruct state at any point

---

## References & Sources

### Official Specifications
- [VMware VMDK Format 5.0](https://www.vmware.com/app/vmdk/?src=vmdk)
- [MS-VHDX](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-vhdx/)
- [QEMU QCOW2](https://www.qemu.org/docs/master/interop/qcow2.html)
- [AFF4 Standard v1.0a](https://github.com/aff4/Standard/blob/master/inprogress/AFF4StandardSpecification-v1.0a.md)
- [OCI Image Spec](https://github.com/opencontainers/image-spec)
- [SNIA LTFS v2.5](https://www.snia.org/sites/default/files/technical-work/ltfs/release/SNIA-LTFS-Format-v2.5-Technical-Position.pdf)
- [Proxmox VMA spec](https://git.proxmox.com/?p=pve-qemu.git;a=blob_plain;f=vma_spec.txt)

### Reverse Engineering & Community
- [libvmdk docs](https://github.com/libyal/libvmdk/blob/main/documentation/VMWare%20Virtual%20Disk%20Format%20(VMDK).asciidoc)
- [libvhdi VHD docs](https://github.com/libyal/libvhdi/blob/main/documentation/Virtual%20Hard%20Disk%20(VHD)%20image%20format.asciidoc)
- [libvhdi VHDX docs](https://github.com/libyal/libvhdi/blob/main/documentation/Virtual%20Hard%20Disk%20version%202%20(VHDX)%20image%20format.asciidoc)
- [libqcow docs](https://github.com/libyal/libqcow/blob/main/documentation/QEMU%20Copy-On-Write%20file%20format.asciidoc)
- [libewf EWF docs](https://github.com/libyal/libewf/blob/main/documentation/Expert%20Witness%20Compression%20Format%20(EWF).asciidoc)
- [libewf EWF2 docs](https://github.com/libyal/libewf/blob/main/documentation/Expert%20Witness%20Compression%20Format%202%20(EWF2).asciidoc)
- [libmodi DMG docs](https://github.com/libyal/libmodi/blob/main/documentation/Mac%20OS%20disk%20image%20types.asciidoc)
- [Kaitai Struct VDI](https://formats.kaitai.io/vdi/)
- [Forensicxlab VMDK](https://www.forensicxlab.com/blog/vmdk)
- [Synacktiv Veeam research](https://www.synacktiv.com/en/publications/using-veeam-metadata-for-efficient-extraction-of-backup-artefacts-13)
- [Slide Docs Datto RE](https://docs.slide.tech/guides/manually-accessing-datto-reverse-roundtrip-backups/)
- [Rich Infante iOS Backup RE](https://www.richinfante.com/2017/3/16/reverse-engineering-the-ios-backup)
- [mac4n6 Protobuf forensics](http://www.mac4n6.com/blog/2019/9/27/just-call-me-buffy-the-proto-slayer)

### Research Papers
- Cohen, Garfinkel, Schatz: "Extending the advanced forensic format" (2009)
- Schatz: "AFF4-L: A Scalable Open Logical Evidence Container" (DFRWS 2019)
- Han et al.: "A practical approach to analyze smartphone backup data" (DFRWS 2016)
- Kim et al.: "How to decrypt PIN-Based encrypted Samsung backup data" (2018)
- Park et al.: "Encrypted smartphone backup data decryption methodology" (2020)
- Kim et al.: "Decrypting password-based Huawei backup data" (2019)
- "Revisiting logical image formats: L01 and AFF4-L analysis" (2024)

### Open-Source Tools
- [acronis-tib](https://github.com/dennisss/acronis-tib) (TypeScript)
- [AD1-tools](https://github.com/al3ks1s/AD1-tools) (C)
- [iphone_backup_decrypt](https://github.com/jsharkey13/iphone_backup_decrypt) (Python)
- [kobackupdec](https://github.com/RealityNet/kobackupdec) (Python)
- [InflatableDonkey](https://github.com/horrorho/InflatableDonkey) (Java)
- [vma-extractor](https://github.com/jancc/vma-extractor) (Python)
- [ForensicRS](https://github.com/ForensicRS) (Rust)
- [libimobiledevice](https://libimobiledevice.org/) (C)
- [unraveling_sql_server_bak](https://github.com/klandermans/unraveling_sql_server_bak)
- [LinearTapeFileSystem/ltfs](https://github.com/LinearTapeFileSystem/ltfs)
