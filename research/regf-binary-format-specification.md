# Windows Registry REGF Binary Format Specification

**Research Date:** 2026-03-27
**Purpose:** Exhaustive binary format reference for building a forensic registry parser from scratch
**Companion Document:** [Registry Forensic Tools Matrix](registry-forensic-tools-matrix.md)

---

## Table of Contents

1. [Base Block (regf Header)](#1-base-block-regf-header)
2. [Hive Bins (hbin)](#2-hive-bins-hbin)
3. [Cell Types](#3-cell-types)
   - 3.1 [NK (Named Key / Key Node)](#31-nk-named-key--key-node)
   - 3.2 [VK (Value Key)](#32-vk-value-key)
   - 3.3 [LF (Fast Leaf)](#33-lf-fast-leaf)
   - 3.4 [LH (Hash Leaf)](#34-lh-hash-leaf)
   - 3.5 [LI (Index Leaf)](#35-li-index-leaf)
   - 3.6 [RI (Root Index / Index Root)](#36-ri-root-index--index-root)
   - 3.7 [SK (Security Key)](#37-sk-security-key)
   - 3.8 [DB (Big Data)](#38-db-big-data)
   - 3.9 [Key Values List](#39-key-values-list)
4. [Cell Allocation](#4-cell-allocation)
5. [Key Path Navigation](#5-key-path-navigation)
6. [Version Differences](#6-version-differences)
7. [Transaction Log Format](#7-transaction-log-format)
8. [Transactional Registry (TxR)](#8-transactional-registry-txr)
9. [Deleted Key/Value Recovery](#9-deleted-keyvalue-recovery)
10. [Registry Carving](#10-registry-carving)
11. [Undocumented and Obscure Features](#11-undocumented-and-obscure-features)
12. [References](#12-references)

---

## 1. Base Block (regf Header)

The base block is the first 4096 bytes of a registry hive file. Only the first 512 bytes contain meaningful header data; the remainder (offsets 512-4095) is reserved/zero-filled, with a few exceptions at the end of the 4096-byte block. Transaction log files may have a header block of only 1024 bytes.

The base block is represented internally by the `_HBASE_BLOCK` structure in `ntoskrnl.exe`.

### 1.1 Header Structure (First 512 Bytes)

| Offset | Length | Field | Value/Description |
|--------|--------|-------|-------------------|
| 0x000 | 4 | **Signature** | `regf` (ASCII: `0x72 0x65 0x67 0x66`) |
| 0x004 | 4 | **Primary sequence number** | Incremented on each write; must match Secondary sequence number if hive was properly synchronized |
| 0x008 | 4 | **Secondary sequence number** | Updated after successful write; mismatch with Primary indicates dirty/crashed hive |
| 0x00C | 8 | **Last written timestamp** | FILETIME (UTC), 100-nanosecond intervals since 1601-01-01. **Not updated as of Windows 8.1/Server 2012 R2** (but may be set at hive creation) |
| 0x014 | 4 | **Major version** | Always `1` for all known Windows versions |
| 0x018 | 4 | **Minor version** | `0`-`2` (NT 3.x), `3` (NT 4.0), `4` (XP betas only), `5` (XP release+), `6` (Win10+ differencing hives) |
| 0x01C | 4 | **Type** | File type: `0` = primary file, `1` = transaction log, `2` = alternate file (Win2000 SYSTEM.ALT only), `6` = transaction log (Win2000) |
| 0x020 | 4 | **Format** | `1` = direct memory load (the only valid value) |
| 0x024 | 4 | **Root cell offset** | Offset in bytes to the root key node cell, **relative to the start of the hive bins data** (not file start). File offset = 4096 + Root cell offset |
| 0x028 | 4 | **Hive bins data size (Length)** | Total size of all hive bins in bytes |
| 0x02C | 4 | **Clustering factor** | Logical sector size of the underlying disk in bytes divided by 512. Typically `1` (512-byte sectors) or `8` (4096-byte sectors). Controls how much of the base block is written to transaction logs |
| 0x030 | 64 | **FileName** | Internal hive path in UTF-16LE (e.g., `\SystemRoot\System32\Config\SYSTEM`). Often only the last portion of the path. May or may not be null-terminated. Unused bytes are zero. Not always reliable -- may contain remnant data |
| 0x070 | 16 | **RmId** | GUID -- Resource Manager identifier. Introduced in Windows Vista as part of CLFS integration. Null if CLFS not used |
| 0x080 | 16 | **LogId** | GUID -- Log identifier. Usually same value as RmId. May contain garbage if RmId is null |
| 0x090 | 4 | **Flags** | Bit mask: `0x1` = pending transactions exist, `0x2` = hive is differencing and contains layered keys (typically set when minor version is 6) |
| 0x094 | 16 | **TmId** | GUID -- Transaction Manager identifier. May contain garbage if RmId is null |
| 0x0A4 | 4 | **GuidSignature** | `rmtm` (ASCII: `0x72 0x6D 0x74 0x6D`) -- validates that the GUID fields above are present and meaningful |
| 0x0A8 | 8 | **LastReorganizeTime** | FILETIME (UTC) -- timestamp of the latest hive reorganization. Introduced in Windows 8/Server 2012. Special values: `1` = next reorg will defragment, `2` = next reorg will clear access history |
| 0x0B0 | 332 | **Reserved1** | Zero-filled (83 DWORDs) |
| 0x1FC | 4 | **Checksum** | XOR-32 checksum of the preceding 508 bytes |

### 1.2 Remainder of the 4096-Byte Header Block

| Offset | Length | Field | Description |
|--------|--------|-------|-------------|
| 0x200 | 3528 | **Reserved2** | Zero-filled (882 DWORDs) |
| 0xFC8 | 16 | **ThawTmId** | GUID -- used to restore TmId when thawing a hive after a Volume Shadow Copy snapshot |
| 0xFD8 | 16 | **ThawRmId** | GUID -- used to restore RmId when thawing |
| 0xFE8 | 16 | **ThawLogId** | GUID -- used to restore LogId when thawing |
| 0xFF8 | 4 | **BootType** | In-memory boot recovery management field. Not meaningful on disk (unless Clustering factor is 8, in which case it may be written but still meaningless) |
| 0xFFC | 4 | **BootRecover** | In-memory boot recovery management field. Same caveat as BootType |

### 1.3 Checksum Algorithm (XOR-32)

The checksum is computed over the first 508 bytes (offsets 0x000 through 0x1FB) of the base block:

```
Algorithm:
1. Let C = 0 (32-bit unsigned)
2. Let D = the first 508 bytes of the base block
3. Split D into 127 non-overlapping 32-bit little-endian DWORDs: G[0]..G[126]
4. For each G[i]: C = C XOR G[i]
5. If C == 0xFFFFFFFF (-1 as signed): set C = 0xFFFFFFFE (-2)
6. If C == 0x00000000: set C = 0x00000001
7. C is the checksum
```

**Implementation note:** The special-casing of 0 and -1 means those two values are never valid checksums. The kernel implementation is in the internal `HvpHeaderCheckSum` function.

**Critical for fuzzing/testing:** Any modification to bytes 0-507 requires recalculating the checksum at offset 0x1FC, or the hive will be rejected with `STATUS_REGISTRY_CORRUPT`.

### 1.4 Sequence Number Semantics

The Primary and Secondary sequence numbers coordinate with transaction logs to detect incomplete writes:

- **Before a write operation:** Primary sequence number is incremented. Last written timestamp is updated (pre-Win 8.1). Changes are written.
- **After successful write:** Secondary sequence number is set to match Primary.
- **If Primary != Secondary:** The hive is "dirty" -- an incomplete write occurred. Transaction log replay is needed.

Starting with Windows Vista, both sequence numbers are written simultaneously before log data is written, changing the coordination protocol. See Section 7 for full details.

---

## 2. Hive Bins (hbin)

Hive bins are the organizational containers that hold cells. They immediately follow the 4096-byte base block. Each hive bin is a variable-length structure that is always a multiple of 4096 bytes (4 KiB).

### 2.1 Hive Bin Header (32 Bytes)

| Offset | Length | Field | Value/Description |
|--------|--------|-------|-------------------|
| 0x000 | 4 | **Signature** | `hbin` (ASCII: `0x68 0x62 0x69 0x6E`) |
| 0x004 | 4 | **Offset** | Offset of this hive bin in bytes, **relative to the start of the hive bins data** (i.e., the first hbin has offset 0, not 4096). This is the same coordinate space used by all cell offsets throughout the hive |
| 0x008 | 4 | **Size** | Size of this hive bin in bytes (including the 32-byte header). Always a multiple of 4096 |
| 0x00C | 8 | **Reserved** | Typically zero. May contain remnant data |
| 0x014 | 8 | **Timestamp** | FILETIME (UTC). **Only meaningful for the first hive bin** -- acts as a backup copy of the Last written timestamp from the base block. All other hive bins typically have this as zero or remnant data |
| 0x01C | 4 | **Spare (MemAlloc)** | Used at runtime for memory management. No meaning on disk. In Windows 2000 called MemAlloc (tracks memory allocations). In later versions called Spare (used when shifting hive bins in memory). Starting with Windows 8/Server 2012, this field was repurposed as a bit mask for hive defragmentation hints (Windows 8/Server 2012 only; not in later versions) |

### 2.2 Offset Coordinate System

**This is critical for parser implementation:** All offsets stored in cells (parent pointers, subkey list pointers, value data pointers, security key pointers, etc.) are **relative to the start of the hive bins data**, NOT relative to the file start.

To convert a cell offset to a file offset:

```
file_offset = 4096 + cell_offset
```

The sentinel value `0xFFFFFFFF` means "no reference" (null pointer equivalent).

### 2.3 Size and Alignment Constraints

- Hive bin size is always a multiple of 4096 bytes.
- At runtime, bins are allocated as the smallest 4096-aligned region that can fit the requested cell. Typical bins are 4-16 KiB.
- Bins can organically grow up to 1 MiB through normal kernel operations.
- There is no technical maximum enforced beyond the 32-bit size field, so a crafted hive could theoretically have a single bin of ~2 GiB.
- The sum of all bin offsets and sizes must be consistent: each bin's offset + size should equal the next bin's offset.
- The total of all bin sizes must equal the Hive bins data size field in the base block.

### 2.4 Bin/Cell Integrity

After the 32-byte header, the remainder of a hive bin is filled entirely with cells (with no gaps). The bin header + all cells must exactly fill the declared bin size. If the hive loader detects a mismatch, it forcefully creates a single free cell spanning from the failing point to the end of the bin.

---

## 3. Cell Types

Cells are the fundamental data units within hive bins. Every cell begins with a 4-byte signed size field, followed by cell data. The format recognizes eight cell types identified by 2-byte ASCII signatures, plus raw data cells (value data, class name data) that have no signature.

### 3.0 Cell Structure (Common Prefix)

| Offset | Length | Field | Description |
|--------|--------|-------|-------------|
| 0x000 | 4 | **Size** | Signed 32-bit integer. **Negative = allocated, Positive = free/unallocated.** Use absolute value for actual size. Includes the 4-byte size field itself. Must be a multiple of 8 |
| 0x004 | ... | **Cell data** | Contents depend on cell type |

### 3.1 NK (Named Key / Key Node)

The NK cell represents a single registry key. It is the most complex cell type. Signature: `nk` (0x6E 0x6B).

#### 3.1.1 NK Structure

| Offset | Length | Field | Description |
|--------|--------|-------|-------------|
| 0x00 | 2 | **Signature** | `nk` |
| 0x02 | 2 | **Flags** | Bit mask (see Section 3.1.2) |
| 0x04 | 8 | **Last written timestamp** | FILETIME (UTC) -- updated when this key or its values are modified |
| 0x0C | 4 | **Access bits** | Bit mask (see Section 3.1.3). Used as of Windows 8/Server 2012; in earlier versions this field is reserved (called "Spare") and set to 0 |
| 0x10 | 4 | **Parent** | Offset of parent key node, relative to hive bins data start. For the root key node of a hive, this field has no meaning on disk |
| 0x14 | 4 | **Number of subkeys** | Count of stable (non-volatile) subkeys |
| 0x18 | 4 | **Number of volatile subkeys** | Count of volatile subkeys. No meaning on disk (volatile keys exist only in memory) |
| 0x1C | 4 | **Subkeys list offset** | Offset to the subkeys list (LF, LH, LI, or RI cell), relative to hive bins data start. `0xFFFFFFFF` if no subkeys |
| 0x20 | 4 | **Volatile subkeys list offset** | No meaning on disk |
| 0x24 | 4 | **Number of key values** | Count of values under this key |
| 0x28 | 4 | **Key values list offset** | Offset to the values list cell (array of VK offsets), relative to hive bins data start. `0xFFFFFFFF` if no values |
| 0x2C | 4 | **Key security offset** | Offset to the SK (Security Key) cell, relative to hive bins data start. `0xFFFFFFFF` if none |
| 0x30 | 4 | **Class name offset** | Offset to the cell containing class name data, relative to hive bins data start. `0xFFFFFFFF` if none |
| 0x34 | 4 | **Largest subkey name length / UserFlags / VirtControlFlags / Debug** | Compound field (see Section 3.1.4) |
| 0x38 | 4 | **Largest subkey class name length** | In bytes |
| 0x3C | 4 | **Largest value name length** | In bytes. Value name treated as UTF-16LE for size purposes |
| 0x40 | 4 | **Largest value data size** | In bytes |
| 0x44 | 4 | **WorkVar** | Cached index -- used at runtime for performance optimization. On disk, typically contains residual data from last runtime use |
| 0x48 | 2 | **Key name length** | In bytes |
| 0x4A | 2 | **Class name length** | In bytes. `0` if no class name |
| 0x4C | ... | **Key name string** | ASCII (compressed) or UTF-16LE depending on KEY_COMP_NAME flag |

**Total fixed header size: 76 bytes (0x4C) + variable key name**

#### 3.1.2 NK Flags

| Bit | Value | Name | Description |
|-----|-------|------|-------------|
| 0 | 0x0001 | **KEY_IS_VOLATILE** | Key exists only in memory; not persisted to disk |
| 1 | 0x0002 | **KEY_HIVE_EXIT** | Mount point -- this key is a link to the root of another hive (e.g., HKLM\SYSTEM mounting the SYSTEM hive) |
| 2 | 0x0004 | **KEY_HIVE_ENTRY** | Root key of the current hive |
| 3 | 0x0008 | **KEY_NO_DELETE** | Key cannot be deleted |
| 4 | 0x0010 | **KEY_SYM_LINK** | Symbolic link key -- the key's target is specified by a REG_LINK value named "SymbolicLinkValue" |
| 5 | 0x0020 | **KEY_COMP_NAME** | Key name is stored as compressed ASCII (extended ASCII, one byte per character) rather than UTF-16LE. This is an optimization since most key names are ASCII-representable |
| 6 | 0x0040 | **KEY_PREDEF_HANDLE** | Predefined handle -- the key maps to a predefined handle rather than an actual key node |
| 7 | 0x0080 | **KEY_VIRT_MIRRORED** | VirtualizationInfo: key is a mirror of a virtualized key |
| 8 | 0x0100 | **KEY_VIRT_TARGET** | VirtualizationInfo: key is the target of virtualization |
| 9 | 0x0200 | **KEY_VIRTUAL_STORE** | VirtualizationInfo: key is part of the virtual store |
| 12 | 0x1000 | **(Unknown)** | Observed in some hives; purpose undocumented |
| 14 | 0x4000 | **(Unknown)** | Observed in some hives; purpose undocumented |

#### 3.1.3 Access Bits (Offset 0x0C)

Starting with Windows 8/Server 2012, this 4-byte field at offset 0x0C is used as a bit mask for tracking key access patterns. This data feeds into the hive reorganization/defragmentation engine: keys that are accessed frequently are placed closer together on disk during reorganization.

The `AccessBits` field occupies only the first byte (offset 0x0C). The remaining bytes at offsets 0x0D-0x0F have been repurposed in modern Windows:

From the `_CM_KEY_NODE` kernel structure:
```
+0x00C AccessBits       : UChar        (1 byte)
+0x00D LayerSemantics   : Pos 0, 2 Bits
+0x00D Spare1           : Pos 2, 5 Bits
+0x00D InheritClass     : Pos 7, 1 Bit
+0x00E Spare2           : Uint2B       (2 bytes)
```

**LayerSemantics** (2 bits at offset 0x0D): Controls behavior for layered/differencing keys:
- `0` = normal key
- `1` = Supersede -- this key entirely replaces the lower layer
- `2` = Tombstone -- this key marks deletion in the differencing layer
- `3` = Decommissioned (undocumented; observed in some contexts)

**InheritClass** (1 bit at offset 0x0D, bit 7): When set, the class name is inherited from the corresponding key in the lower layer of a differencing hive.

#### 3.1.4 Compound Field at Offset 0x34

Starting from Windows Vista (and Windows Server 2003 SP2, Windows XP SP3), the "Largest subkey name length" field at offset 0x34 was split into four sub-fields:

From the `_CM_KEY_NODE` kernel structure:
```
+0x034 MaxNameLen       : Pos 0, 16 Bits   (lower 16 bits)
+0x034 UserFlags        : Pos 16, 4 Bits   (bits 16-19)
+0x034 VirtControlFlags : Pos 20, 4 Bits   (bits 20-23)
+0x034 Debug            : Pos 24, 8 Bits   (bits 24-31)
```

- **MaxNameLen** (16 bits): Largest subkey name length in bytes (the name is treated as a UTF-16LE string for size calculation purposes, regardless of whether it is stored compressed)
- **UserFlags** (4 bits): Also called Wow64 flags. Prior to Windows Vista, user flags occupied bits 0-3 of the Flags field; they were moved here. These flags are returned by `NtQueryKey` with `KeyFlagsInformation` and set by `NtSetInformationKey`
- **VirtControlFlags** (4 bits): Registry virtualization control flags
- **Debug** (8 bits): Debug/diagnostic flags

#### 3.1.5 Key Name Encoding

If `KEY_COMP_NAME` (0x0020) is set in the Flags field, the key name is stored as **compressed ASCII** (extended ASCII): each UTF-16LE character with a code point < 256 is stored as a single byte by dropping the high zero byte. This is a size optimization that applies to the vast majority of key names.

If `KEY_COMP_NAME` is NOT set, the key name is stored as **UTF-16LE** (2 bytes per character).

The Key name length field always stores the byte length of the name as stored on disk (i.e., after compression if applicable).

#### 3.1.6 Class Name

The class name is an optional UTF-16LE string associated with a key. It is stored in a separate cell pointed to by the Class name offset field. The Class name length field at offset 0x4A stores the byte length.

**Forensic note:** The class name field is rarely used by legitimate Windows applications. It can be abused as a covert data hiding mechanism -- up to 64 KiB of arbitrary data can be stored in a key's class name via `NtCreateKey`. Standard tools like `RegEdit` and `RegQueryInfoKey` may not properly display or return class data. Detection requires parsing the raw hive binary (see Section 11.1).

#### 3.1.7 WorkVar (Offset 0x44)

The WorkVar field is used at runtime as a cached index hint to speed up subkey lookups. On disk, it may contain stale data from the last time the hive was in use. It has no reliability guarantee for forensic analysis but may contain forensically interesting residual data.

### 3.2 VK (Value Key)

The VK cell represents a single registry value. Signature: `vk` (0x76 0x6B).

#### 3.2.1 VK Structure

| Offset | Length | Field | Description |
|--------|--------|-------|-------------|
| 0x00 | 2 | **Signature** | `vk` |
| 0x02 | 2 | **Name length** | In bytes. `0` if the value is unnamed (the "Default" value) |
| 0x04 | 4 | **Data size** | In bytes. The most significant bit (bit 31) is a **resident flag** (see Section 3.2.2). `0` means value is not set |
| 0x08 | 4 | **Data offset** | Offset to value data cell, relative to hive bins data start. **OR** the data itself if resident (see Section 3.2.2) |
| 0x0C | 4 | **Data type** | Registry value type (see Section 3.2.3) |
| 0x10 | 2 | **Flags** | Bit mask: `0x0001` = `VALUE_COMP_NAME` (name is compressed ASCII, same encoding as NK KEY_COMP_NAME) |
| 0x12 | 2 | **Spare** | Reserved, not used |
| 0x14 | ... | **Value name string** | ASCII (compressed) or UTF-16LE depending on VALUE_COMP_NAME flag |

**Total fixed header size: 20 bytes (0x14) + variable value name**

#### 3.2.2 Data Size and Resident Data

The Data size field at offset 0x04 uses its most significant bit (bit 31) as a flag:

- **Bit 31 = 1 (MSB set):** Data is **resident** (inline). The actual data (4 bytes or fewer) is stored directly in the Data offset field at offset 0x08. The true data size is the lower 31 bits. If the data is smaller than 4 bytes, it occupies the beginning (lowest address bytes) of the Data offset field.
- **Bit 31 = 0 (MSB clear):** Data is stored in a separate cell pointed to by the Data offset field. For data > 16,344 bytes, a Big Data (DB) structure is used (see Section 3.8).

**Parser implementation:** Always mask off bit 31 before interpreting the data size: `real_size = data_size & 0x7FFFFFFF`.

#### 3.2.3 Data Types

| Value | Name | Description |
|-------|------|-------------|
| 0x00000000 | **REG_NONE** | No defined value type |
| 0x00000001 | **REG_SZ** | Null-terminated Unicode (UTF-16LE) string |
| 0x00000002 | **REG_EXPAND_SZ** | Unicode string with unexpanded environment variable references (e.g., `%SystemRoot%`) |
| 0x00000003 | **REG_BINARY** | Arbitrary binary data |
| 0x00000004 | **REG_DWORD** / **REG_DWORD_LITTLE_ENDIAN** | 32-bit unsigned integer, little-endian |
| 0x00000005 | **REG_DWORD_BIG_ENDIAN** | 32-bit unsigned integer, big-endian (rarely used) |
| 0x00000006 | **REG_LINK** | Unicode symbolic link string |
| 0x00000007 | **REG_MULTI_SZ** | Sequence of null-terminated UTF-16LE strings, terminated by an empty string (double null) |
| 0x00000008 | **REG_RESOURCE_LIST** | Device-driver resource list (CM_RESOURCE_LIST) |
| 0x00000009 | **REG_FULL_RESOURCE_DESCRIPTOR** | Device-driver resource descriptor (CM_FULL_RESOURCE_DESCRIPTOR) |
| 0x0000000A | **REG_RESOURCE_REQUIREMENTS_LIST** | Device-driver resource requirements (IO_RESOURCE_REQUIREMENTS_LIST) |
| 0x0000000B | **REG_QWORD** / **REG_QWORD_LITTLE_ENDIAN** | 64-bit unsigned integer, little-endian |

**Forensic notes on string types:**
- REG_SZ and REG_EXPAND_SZ should be UTF-16LE and null-terminated, but real-world hives frequently contain malformed data: missing null terminators, odd byte counts (truncated final character), or ASCII data stored as REG_SZ.
- REG_MULTI_SZ is a sequence of null-terminated UTF-16LE strings followed by a final empty string (4 zero bytes total at the end). Real-world data may lack the double null terminator.

### 3.3 LF (Fast Leaf)

The Fast Leaf is a subkey index that includes a 4-byte "name hint" for each subkey to speed up lookups. Introduced in regf version 1.3 (Windows NT 4.0). Signature: `lf` (0x6C 0x66).

#### 3.3.1 LF Structure

| Offset | Length | Field | Description |
|--------|--------|-------|-------------|
| 0x00 | 2 | **Signature** | `lf` |
| 0x02 | 2 | **Number of elements** | Count of list elements |
| 0x04 | 8 * N | **List elements** | Array of N elements, each 8 bytes |

Each list element:

| Offset | Length | Field | Description |
|--------|--------|-------|-------------|
| 0x00 | 4 | **Key node offset** | Offset of the NK cell, relative to hive bins data start |
| 0x04 | 4 | **Name hint** | First 4 ASCII characters of the key name (used for fast comparison). If name < 4 chars, remaining bytes are null. UTF-16LE names are converted to extended ASCII for the hint; if conversion is impossible, the first byte is null |

**List elements must be sorted** ascending by the uppercase version of the key name (character code comparison).

### 3.4 LH (Hash Leaf)

The Hash Leaf is an improved subkey index that uses a full 32-bit hash instead of a 4-character hint. Used when minor version > 4 (i.e., version 1.5+, Windows XP release and later). Signature: `lh` (0x6C 0x68).

#### 3.4.1 LH Structure

| Offset | Length | Field | Description |
|--------|--------|-------|-------------|
| 0x00 | 2 | **Signature** | `lh` |
| 0x02 | 2 | **Number of elements** | Count of list elements |
| 0x04 | 8 * N | **List elements** | Array of N elements, each 8 bytes |

Each list element:

| Offset | Length | Field | Description |
|--------|--------|-------|-------------|
| 0x00 | 4 | **Key node offset** | Offset of the NK cell, relative to hive bins data start |
| 0x04 | 4 | **Name hash** | 32-bit hash of the key name (see algorithm below) |

#### 3.4.2 LH Hash Algorithm

```
Algorithm (name hash):
1. Let H = 0 (32-bit unsigned)
2. Let N = uppercase key name
3. For each character C[i] in N (treated as its numeric code):
   - For compressed ASCII names: C[i] is the 1-byte character code
   - For UTF-16LE names: C[i] is the 2-byte character code (wide character)
   H = 37 * H + C[i]
4. H (truncated to 32 bits) is the hash value
```

**List elements must be sorted** ascending by the uppercase version of the key name.

**Implementation note:** The hash does NOT use the full name; it uses the uppercased name. For ASCII-representable names, the uppercasing follows standard ASCII rules. The multiplication by 37 is performed as 32-bit unsigned arithmetic (overflow wraps).

### 3.5 LI (Index Leaf)

The Index Leaf is the simplest subkey index -- a plain list of key node offsets with no hint or hash. This is the original format used in regf versions 1.0-1.2 (Windows NT 3.x). Signature: `li` (0x6C 0x69).

#### 3.5.1 LI Structure

| Offset | Length | Field | Description |
|--------|--------|-------|-------------|
| 0x00 | 2 | **Signature** | `li` |
| 0x02 | 2 | **Number of elements** | Count of list elements |
| 0x04 | 4 * N | **List elements** | Array of N elements, each 4 bytes |

Each list element:

| Offset | Length | Field | Description |
|--------|--------|-------|-------------|
| 0x00 | 4 | **Key node offset** | Offset of the NK cell, relative to hive bins data start |

**List elements must be sorted** ascending by the uppercase key name.

### 3.6 RI (Root Index / Index Root)

The Root Index is an index-of-indices used when the number of subkeys exceeds what a single LF/LH/LI list can hold. It points to multiple subkey lists. Signature: `ri` (0x72 0x69).

#### 3.6.1 RI Structure

| Offset | Length | Field | Description |
|--------|--------|-------|-------------|
| 0x00 | 2 | **Signature** | `ri` |
| 0x02 | 2 | **Number of elements** | Count of subkey list references |
| 0x04 | 4 * N | **List elements** | Array of N elements, each 4 bytes |

Each list element:

| Offset | Length | Field | Description |
|--------|--------|-------|-------------|
| 0x00 | 4 | **Subkeys list offset** | Offset to an LF, LH, or LI cell, relative to hive bins data start |

**Constraints:**
- An RI **cannot** point to another RI (no nesting of index roots).
- A subkeys list (LF/LH/LI) cannot point to an RI.
- List elements within all referenced subkeys lists must be **globally sorted** -- the first element of the second subkeys list must be greater than the last element of the first subkeys list.

**Practical occurrence:** RI is used for keys with hundreds or thousands of subkeys (e.g., `HKLM\SOFTWARE\Classes\CLSID` which may have 10,000+ subkeys).

### 3.7 SK (Security Key)

The SK cell contains a Windows NT security descriptor that defines access control for one or more registry keys. Signature: `sk` (0x73 0x6B).

#### 3.7.1 SK Structure

| Offset | Length | Field | Description |
|--------|--------|-------|-------------|
| 0x00 | 2 | **Signature** | `sk` |
| 0x02 | 2 | **Reserved** | Unused |
| 0x04 | 4 | **Flink** | Forward link -- offset to next SK cell in the doubly linked list, relative to hive bins data start |
| 0x08 | 4 | **Blink** | Backward link -- offset to previous SK cell in the doubly linked list, relative to hive bins data start |
| 0x0C | 4 | **Reference count** | Number of NK cells pointing to this SK cell |
| 0x10 | 4 | **Security descriptor size** | Size of the security descriptor in bytes |
| 0x14 | ... | **Security descriptor** | Windows NT SECURITY_DESCRIPTOR in **self-relative** format |

#### 3.7.2 SK Linked List

SK cells form a **doubly linked circular list** within the hive:

- The first SK cell acts as a **list header**. Its flink points to the first entry; its blink points to the last entry.
- Each subsequent SK cell is a **list entry**. Its flink points to the next entry (or back to the header if last); its blink points to the previous entry (or back to the header if first).
- If the list contains only the header, both flink and blink point to itself.

#### 3.7.3 Reference Counting

SK cells are **reference counted**. Multiple NK cells with identical security descriptors share a single SK cell. When a key is deleted, the reference count is decremented. When it reaches zero, the SK cell is freed. This is the only cell type in the registry that uses reference counting.

#### 3.7.4 Security Descriptor Format

The security descriptor is in **self-relative** format (all offsets within the descriptor are relative to the start of the descriptor itself). It contains:

| Component | Description |
|-----------|-------------|
| **Header** | SECURITY_DESCRIPTOR_RELATIVE structure: Revision (1 byte, must be 1), Sbz1 (1 byte), Control flags (2 bytes, including SE_SELF_RELATIVE=0x8000), Owner offset (4 bytes), Group offset (4 bytes), SACL offset (4 bytes, 0 if absent), DACL offset (4 bytes, 0 if absent) |
| **Owner SID** | Security Identifier of the key owner (typically S-1-5-32-544 Administrators or S-1-5-18 SYSTEM) |
| **Group SID** | Primary group Security Identifier |
| **DACL** | Discretionary Access Control List -- defines who can access the key and what operations are permitted. Contains ACL header (Revision, Size, AceCount) followed by ACCESS_ALLOWED_ACE / ACCESS_DENIED_ACE entries |
| **SACL** | System Access Control List -- defines audit logging rules. Same structure as DACL but with SYSTEM_AUDIT_ACE entries. Often absent (offset = 0) |

**SID format:** Revision (1 byte) + SubAuthorityCount (1 byte) + IdentifierAuthority (6 bytes) + SubAuthority array (4 bytes each).

**Forensic note:** Malware sometimes modifies DACL entries to deny access to forensic tools, or creates keys with restrictive ACLs to prevent deletion. Parsing the full security descriptor is essential for complete forensic analysis.

### 3.8 DB (Big Data)

The DB structure handles storage of value data exceeding 16,344 bytes (~16 KiB). Available in hive versions 1.4+ (Windows XP and later). Signature: `db` (0x64 0x62).

#### 3.8.1 Why 16,344 Bytes?

The threshold is 16,344 bytes, not 16,384 (16 KiB). This accounts for cell overhead: a cell with 16,344 bytes of data plus the 4-byte size field and any alignment padding fits within a single hive bin page.

#### 3.8.2 DB Structure

| Offset | Length | Field | Description |
|--------|--------|-------|-------------|
| 0x00 | 2 | **Signature** | `db` |
| 0x02 | 2 | **Number of segments** | Count of data segments |
| 0x04 | 4 | **Segment list offset** | Offset to the list of segment references, relative to hive bins data start |

#### 3.8.3 Segment List

The segment list is stored in a separate cell:

| Offset | Length | Field | Description |
|--------|--------|-------|-------------|
| 0x00 | 4 * N | **Segment offsets** | Array of N offsets, each pointing to a cell containing one data segment |

Each data segment is stored in its own cell. All segments except the last have a maximum size of 16,344 bytes. The last segment may be smaller.

To reconstruct the complete value data, read segments in order and concatenate them.

**Maximum value size:** In the standard format (version 1.3), value data is limited to 1 MiB. In the latest format (version 1.5+), the limit is theoretically the available memory, though practical limits apply.

### 3.9 Key Values List

The key values list is a simple array of offsets to VK cells. It is not a typed cell -- it has no signature. The cell is referenced from the NK cell's "Key values list offset" field.

#### 3.9.1 Structure

| Offset | Length | Field | Description |
|--------|--------|-------|-------------|
| 0x00 | 4 * N | **VK offsets** | Array of N key value offsets, each relative to hive bins data start |

**List elements are NOT required to be sorted** (unlike subkey lists).

---

## 4. Cell Allocation

The cell allocation system within hive bins functions like a simple heap allocator.

### 4.1 Allocation State

- **Allocated cell:** Size field is **negative** (bit 31 set as a signed integer). Example: a 128-byte allocated cell has size `0xFFFFFF80` (-128).
- **Free/unallocated cell:** Size field is **positive**. Example: a 32-byte free cell has size `0x00000020` (+32).

### 4.2 Alignment

All cell sizes are aligned to **8 bytes** (3 lowest bits are zero). When the kernel allocates a cell, if the requested size is not a multiple of 8, it is rounded up to the next multiple. This can create **padding bytes** (slack space) at the end of the cell.

Minimum cell size: 8 bytes (4-byte size field + at least 4 bytes of slack or data, to maintain 8-byte alignment).

### 4.3 Free Cell Coalescence

When a cell is freed (deallocated), the system checks if **adjacent cells** (immediately before and after) are also free. If so, they are **merged** into a single larger free cell by updating the size field of the first free cell to encompass all contiguous free cells. This is analogous to heap coalescing in `malloc`/`free` implementations.

**Forensic implication:** When deleted data is in a coalesced free cell, the original cell boundaries are lost. The forensic examiner must infer where individual cells began and ended by scanning for cell signatures (`nk`, `vk`, etc.) within the free space.

### 4.4 Bin Packing Invariant

All cells within a hive bin must be **tightly packed** with no gaps:

```
hbin_header (32 bytes) + cell[0] + cell[1] + ... + cell[N-1] = hbin_size
```

The sum of the bin header and all consecutive cell sizes (absolute values) must exactly equal the bin's declared size. If the hive loader detects a violation, it creates a single free cell from the failing point to the end of the bin.

### 4.5 Forensic Implications of Cell Allocation

| Scenario | Size Field Sign | Accessible via Tree Walk | Contains Valid Data |
|----------|----------------|--------------------------|---------------------|
| Active cell | Negative | Yes | Yes |
| Deleted cell (not yet overwritten) | Positive | No | Possibly (remnant data) |
| Orphaned cell (allocated but unreferenced) | Negative | No | Yes (see Section 9) |
| Free cell (never used or overwritten) | Positive | No | No (garbage/zeros) |

---

## 5. Key Path Navigation

### 5.1 Walking from Root to Any Key

To navigate from the root key to an arbitrary subkey path like `SOFTWARE\Microsoft\Windows`:

```
1. Read the Root cell offset from the base block (offset 0x24)
2. Navigate to file offset: 4096 + Root cell offset
3. Read the cell size field, verify it is negative (allocated)
4. Read the NK cell data; verify signature is "nk" and KEY_HIVE_ENTRY flag is set
5. For each path component ("SOFTWARE", "Microsoft", "Windows"):
   a. Read the Subkeys list offset from the current NK cell
   b. Navigate to the subkeys list cell (LF/LH/LI/RI)
   c. If RI: iterate through each referenced subkeys list
   d. Search the subkeys list for the target name:
      - LH: compute hash of uppercase target name, compare to stored hashes
      - LF: compare first 4 chars of uppercase target name to stored hints
      - LI: must read each referenced NK cell to compare names
   e. When a matching hash/hint is found, follow the key node offset
      to the candidate NK cell and verify the full name matches
   f. The matched NK cell becomes the current key for the next iteration
```

### 5.2 Parent Path Reconstruction

Every NK cell contains a **Parent** offset (offset 0x10) pointing to its parent NK cell. To reconstruct the full path of any key:

```
1. Start at the target NK cell
2. Read its key name
3. Follow its Parent offset to the parent NK cell
4. Prepend the parent's name to the path
5. Repeat until KEY_HIVE_ENTRY flag is found (root key reached)
```

**Forensic note for deleted key recovery:** The Parent field in a deleted (unallocated) NK cell may still be valid if the parent key still exists. This is a primary technique for reconstructing paths of recovered deleted keys (see Section 9).

### 5.3 Volatile vs Stable Storage

Every NK cell has two pairs of subkey-related fields:
- **Stable:** Number of subkeys (offset 0x14) and Subkeys list offset (0x1C) -- persisted to disk
- **Volatile:** Number of volatile subkeys (0x18) and Volatile subkeys list offset (0x20) -- exist only in memory, not on disk

Volatile keys (those with `KEY_IS_VOLATILE` flag) are used for runtime-only data like `HKLM\HARDWARE` and `HKLM\SYSTEM\CurrentControlSet\Hardware Profiles\Current`. They are never written to a primary hive file.

When parsing a hive file from disk, all volatile fields should be ignored.

---

## 6. Version Differences

The only valid major version is `1`. The minor version indicates feature support:

### 6.1 Version History

| Minor Version | First Appeared | Windows Version | Key Changes |
|---------------|---------------|-----------------|-------------|
| 0 | 1993 | NT 3.1 | Original format |
| 1 | 1994 | NT 3.5 | Minor refinements |
| 2 | 1995 | NT 3.51 | No Fast Leaf support |
| **3** | 1996 | **NT 4.0** | **Fast Leaf (LF) introduced.** Baseline for modern parsers |
| **4** | 2001 | **XP betas (Whistler)** | **Big Data (DB) introduced** for values > 16,344 bytes. Only in beta builds; never shipped as default |
| **5** | 2001 | **XP release** | **Hash Leaf (LH) introduced** for faster subkey lookups. The "latest" format per Microsoft documentation |
| **6** | 2016 | **Windows 10 "Redstone 1"** | **Differencing hives and layered keys.** Used for containerized/silo registries |

### 6.2 Cross-Version Compatibility

Versions >= 1.3 are all **cross-compatible** in practice. While the version number is supposed to indicate which features are used inside the hive (e.g., only hives >= 1.4 should use Big Data, only >= 1.5 should use Hash Leafs), this is **not enforced** when loading a hive. Newer features used in older-versioned hives work fine.

### 6.3 Per-Hive Version Assignments (Windows 7 Example)

| Hive | Version | Reason |
|------|---------|--------|
| NTUSER.DAT | 1.3 | Legacy user hive format |
| BCD-Template | 1.3 | Boot Configuration Data template |
| COMPONENTS | 1.3 | Component-Based Servicing |
| SAM | 1.3 | Security Account Manager |
| SECURITY | 1.3 | Security policy |
| DEFAULT | 1.5 | Default user profile |
| SOFTWARE | 1.5 | System-wide software configuration |
| SYSTEM | 1.5 | System configuration |

### 6.4 Per-Hive Version Assignments (Windows 10/11)

| Hive | Version | Notes |
|------|---------|-------|
| Most system hives (SYSTEM, SOFTWARE, etc.) | 1.5 | Standard latest format |
| NTUSER.DAT | 1.5 | Upgraded from 1.3 in newer Windows |
| BCD hive | 1.3 | Boot hive, conservative format |
| Differencing hives (under `\Registry\WC`) | 1.6 | Container/silo registry hives |
| Volatile hives (e.g., HARDWARE) | 1.3 | Root hive, never persisted |

### 6.5 Windows Version Feature Changes (Not Tied to Minor Version)

| Feature | Windows Version | Details |
|---------|----------------|---------|
| User flags moved from Flags to UserFlags sub-field | Vista, Server 2003 SP2, XP SP3 | Bits 0-3 of Flags freed; UserFlags at offset 0x34 bits 16-19 |
| CLFS GUID fields in base block (RmId, LogId, TmId) | Vista | GuidSignature `rmtm` validates their presence |
| Access bits field in NK cells | Windows 8, Server 2012 | Replaces reserved "Spare" field; tracks key access for reorganization |
| Last reorganized timestamp in base block | Windows 8, Server 2012 | Hive defragmentation tracking |
| Spare field in hbin header repurposed | Windows 8, Server 2012 | Bit mask for defragmentation (this version only) |
| Last written timestamp no longer updated | Windows 8.1, Server 2012 R2 | Base block timestamp becomes stale |
| New transaction log format (HvLE entries) | Windows 8.1, Server 2012 R2 | Ring-buffer style logs with Marvin32 checksums |
| LayerSemantics, InheritClass in NK cells | Windows 10 Redstone 1 | Support for differencing hives |

---

## 7. Transaction Log Format

Windows uses transaction log files to ensure registry hive integrity during writes. Log files have the same filename as the hive with `.LOG`, `.LOG1`, or `.LOG2` extensions.

### 7.1 Logging Schemes

| Scheme | Log Files | Windows Versions |
|--------|-----------|-----------------|
| Single log | `*.LOG` | Windows 2000 |
| Dual logging | `*.LOG1`, `*.LOG2` | Windows Vista and later |
| Legacy dummy | `*.LOG` (empty/stale) | May exist alongside LOG1/LOG2 as installation artifact |

### 7.2 Old Format (Windows 2000 through Windows 8)

#### 7.2.1 Overall Structure

```
[Base block (partial backup)] [Dirty vector] [Dirty pages]
```

1. **Base block backup:** A partial copy of the primary file's base block, occupying the first `Clustering factor * 512` bytes. Modified: File type set to 1 (log), sequence numbers adjusted, checksum recalculated.
2. **Dirty vector:** Starting at the second sector (offset 512).
3. **Dirty pages:** Starting at the sector following the last sector of the dirty vector.

#### 7.2.2 Dirty Vector

| Offset | Length | Field | Description |
|--------|--------|-------|-------------|
| 0x00 | 4 | **Signature** | `DIRT` (ASCII) |
| 0x04 | ... | **Bitmap** | Bit array; each bit represents a 512-byte page within hive bins data |

Bitmap semantics:
- Bit = 0: corresponding 512-byte page is clean (not in this log)
- Bit = 1: corresponding 512-byte page is dirty (present in log)
- Bitmap length (bits) = Hive bins data size / 512
- Bits are packed into bytes, LSB first within each byte (checked via `bt` instruction equivalent)

**Important:** The bitmap does NOT track the base block itself -- only hive bins data pages.

#### 7.2.3 Dirty Pages

Dirty pages follow the dirty vector. Each is 512 bytes, stored at 512-byte aligned offsets with no gaps. The first dirty page corresponds to the first set bit in the bitmap, the second to the second set bit, etc.

To apply a dirty page to a primary file:
```
primary_file_offset = 4096 + (512 * bit_position)
```
where `bit_position` is the zero-based index of the corresponding bit in the bitmap.

During recovery, contiguous dirty pages belonging to the same hive bin are processed together, and the resulting dirty hive bin is validated (Signature must be `hbin`, Size >= 4096, Offset must match). Recovery stops if a dirty hive bin is invalid.

#### 7.2.4 Sequence Number Coordination (Old Format)

**Windows 2000 / XP / Server 2003:**
1. Primary sequence number incremented by 1 BEFORE writing dirty data to log
2. Secondary sequence number incremented by 1 AFTER dirty data is written

**Windows Vista and later:**
1. Both Primary and Secondary sequence numbers (identical, incremented by 1) written simultaneously BEFORE writing dirty data

#### 7.2.5 Limitations of Old Format

- Data is always written at the start of the log file, overwriting previous content
- Very difficult to recover historical data since the beginning is frequently overwritten
- However, remnant data from previous writes may persist beyond the current dirty pages

### 7.3 New Format (Windows 8.1 and Later)

The new format uses discrete **log entries** that function as a ring buffer. Multiple log entries can coexist in a single log file, enabling recovery of historical transaction data.

#### 7.3.1 Overall Structure

```
[Base block (backup copy)] [Log entry 1] [Log entry 2] ... [Log entry N] [Remnant data]
```

#### 7.3.2 Log Entry (HvLE) Structure

Each log entry starts at a 512-byte aligned offset:

| Offset | Length | Field | Description |
|--------|--------|-------|-------------|
| 0x00 | 4 | **Signature** | `HvLE` (ASCII) |
| 0x04 | 4 | **Size** | Total size of this log entry in bytes (multiple of 512) |
| 0x08 | 4 | **Flags** | Partial copy of base block Flags field at time of creation |
| 0x0C | 4 | **Sequence number** | The sequence number that the primary/secondary fields of the base block will have after this entry is applied |
| 0x10 | 4 | **Hive bins data size** | Copy of the Hive bins data size field from the base block at creation time |
| 0x14 | 4 | **Dirty pages count** | Number of dirty page references in this entry |
| 0x18 | 8 | **Hash-1** | Marvin32 hash of data from first page reference to end of entry (Size - 40 bytes) |
| 0x20 | 8 | **Hash-2** | Marvin32 hash of the first 32 bytes of this log entry (computed after Hash-1) |
| 0x28 | 8 * N | **Dirty page references** | Array of N references |
| ... | ... | **Dirty pages** | Actual page data, in same order as references |

Each dirty page reference:

| Offset | Length | Field | Description |
|--------|--------|-------|-------------|
| 0x00 | 4 | **Offset** | Offset into primary file's hive bins data (bytes) |
| 0x04 | 4 | **Size** | Size of this dirty page in bytes |

#### 7.3.3 Marvin32 Hash Algorithm

Marvin32 is a keyed 32-bit hash (producing a 64-bit output) used for integrity verification of log entries. The seed used for both Hash-1 and Hash-2 is:

```
Seed (hex bytes): 82 EF 4D 88 7A 4E 55 C5
(64-bit little-endian: 0xC5554E7A884DEF82)
```

**Hash-1** is computed over: bytes from offset 0x28 (first dirty page reference) through the end of the log entry, length = Size - 40 bytes.

**Hash-2** is computed over: the first 32 bytes of the log entry (offsets 0x00 through 0x1F, which includes the already-computed Hash-1 at offset 0x18).

**Validation:** A log entry is valid only if both hashes match recomputed values.

#### 7.3.4 Log Entry Application

A transaction log file may contain multiple log entries, including old (already applied) entries. The application rules are:

1. If the primary file is dirty (Primary seq != Secondary seq) and has a valid checksum:
   - Apply only **subsequent** log entries: those with sequence number >= the primary sequence number from the log file's base block backup
   - Apply entries in order of ascending sequence number

2. If the primary file has an invalid base block checksum:
   - **Before Windows 8:** Only the first transaction log file (*.LOG1) is used
   - **Windows 8 and later:** Both log files may be used; only the one with latest log entries is used

3. After applying all valid log entries:
   - Update the primary file's base block: set both sequence numbers to the last applied entry's sequence number
   - Copy the Hive bins data size and Flags from the last applied log entry
   - Recalculate the base block checksum

### 7.4 Dual-Log Coordination

Under normal circumstances, only `*.LOG1` is used. The `*.LOG2` file comes into play on write errors:

1. **Normal operation:** All dirty data goes to `*.LOG1`
2. **Write error to primary file:** Switch to `*.LOG2`, which accumulates a **cumulative** log (dirty pages that failed to write + all subsequent dirty pages)
3. **Persistent write errors:** The system alternates between `*.LOG1` and `*.LOG2` on each attempt, keeping a cumulative copy in the alternate file
4. **Successful write to primary:** Revert to `*.LOG1`

**Recovery logic:**
- If primary has valid base block: use **both** log files. Apply the one with **earlier** log entries first, then the one with later entries
- If primary has invalid base block: use only the log file with the **latest** log entries

### 7.5 Dirty Hive Flushing Triggers

Transaction log data is flushed (written to the primary hive file) under these conditions:
- All interactive users have logged off
- System is performing a full shutdown
- 3600 seconds (1 hour) have elapsed since the last write to the primary file

**Forensic implication:** A live system's primary hive file may be significantly out of date. The most current data often exists only in the LOG1/LOG2 files. Forensic tools MUST replay transaction logs to reconstruct the true current state.

---

## 8. Transactional Registry (TxR)

The Transactional Registry (TxR) is a separate mechanism from the standard transaction logs described in Section 7. TxR uses the **Common Log File System (CLFS)** format and supports atomic, multi-key registry operations via the `KTM` (Kernel Transaction Manager).

### 8.1 Overview

TxR is activated when applications use transactional registry APIs:
- `RegCreateKeyTransacted()`
- `RegOpenKeyTransacted()`
- `RegDeleteKeyTransacted()`
- Other `*Transacted()` API variants

These operations participate in KTM transactions that can be committed or rolled back atomically.

### 8.2 File Format and Locations

TxR logs are stored as CLFS containers:

| Component | Naming Pattern | Description |
|-----------|---------------|-------------|
| BLF file | `<hive>{GUID}.TxR.blf` | CLFS Base Log File -- metadata only, references containers |
| Container 0 | `<hive>{GUID}.TxR.0.regtrans-ms` | First CLFS container -- holds actual log records |
| Container 1 | `<hive>{GUID}.TxR.1.regtrans-ms` | Second CLFS container (if needed) |
| TM containers | `<hive>.TMContainer*.regtrans-ms` | Transaction Manager containers |

**Storage locations:**
- **System hives:** `%SystemRoot%\System32\config\TxR\` -- logs are **NOT** automatically cleared
- **User hives:** Same directory as the hive file (e.g., next to NTUSER.DAT) -- **cleared on user logout**

### 8.3 Record Format

The CLFS container format is largely undocumented by Microsoft. Through reverse engineering (notably by Mandiant/FireEye researchers), the basic record format has been determined:

- Records can represent **key creation**, **key deletion**, **value write**, and **value delete** operations
- Each record contains: the relevant **key path**, **value name** (if applicable), **data type**, and **data**
- Records are written via `clfsw32.dll` API function `ReserveAndAppendLog()`

### 8.4 Forensic Significance

1. **Persistence of evidence:** Because system hive TxR logs are not automatically cleared, they can contain historical data long after the corresponding registry keys have been deleted. For example, a scheduled task created via transactional APIs may have its full configuration recoverable from TxR logs even weeks after deletion.

2. **Undocumented format:** The CLFS container format has been researched by Mandiant and others but remains partially documented. A forensic parser must be prepared for format variations across Windows versions.

3. **Threat actor abuse:** CLFS container files have been abused by threat actors for stealth (storing payloads in CLFS logs where security tools don't typically scan). The payload is written using `ReserveAndAppendLog()` and stored in the first container file.

4. **User hive limitations:** Because user hive TxR logs are cleared on logout, they are only useful for forensic analysis of active sessions or if the system was not cleanly shut down.

---

## 9. Deleted Key/Value Recovery

### 9.1 How Deletion Works

When a registry key is deleted:
1. The NK cell's size field is changed from negative to positive (marked as free/unallocated)
2. Associated VK cells, subkey lists, security key references, and value data cells are also freed
3. Adjacent free cells may be **coalesced** into a single larger free cell
4. The cell data itself is **NOT zeroed or overwritten** immediately -- it persists as remnant data

### 9.2 Recovery Techniques

#### 9.2.1 Scanning Unallocated Cells (Primary Technique)

The most common approach:

```
Algorithm:
1. Walk all hive bins sequentially
2. For each bin, walk all cells by following the absolute size field
3. For each cell with a POSITIVE size (free/unallocated):
   a. Scan the cell data for NK signatures ("nk" at expected offsets)
   b. Scan for VK signatures ("vk" at expected offsets)
   c. Validate found structures:
      - Check flags for plausibility
      - Check timestamp for plausibility (year 1990-2100)
      - Check name length < 1024 bytes
      - Check subkey count < 10,000
      - Check value count < 1,000
   d. If valid, record as a recovered deleted key/value
```

**Challenge:** After cell coalescence, multiple deleted cells may be merged into one free cell. The scanner must search **within** the free cell at multiple offsets, not just at the beginning.

#### 9.2.2 Allocated but Unreferenced Cells (Orphan Detection)

Some cells remain **allocated** (negative size) but are not reachable by walking the registry tree from the root key. These "orphaned" cells can arise from:
- Incomplete deletion operations (bugs)
- A Windows 10 bug where renaming a key leaves the old NK cell allocated but unlinked from its parent's subkey list
- System crashes during multi-cell operations

Detection algorithm:
```
1. Walk the entire registry tree from root, recording all cell offsets visited
2. Walk all hive bins, examining every allocated cell
3. Any allocated cell NOT in the visited set is an orphan
4. Validate orphaned NK/VK cells as potentially deleted data
```

#### 9.2.3 Remnant Data Beyond Last Hbin

If the hive file is larger than `4096 + Hive bins data size`, data exists beyond the declared hive boundary. This can contain:
- Old hive bin data from before the hive was truncated/compacted
- Partial or complete deleted key structures

#### 9.2.4 Slack Space Within Allocated Cells

Due to 8-byte alignment, allocated cells may have unused bytes at the end (between the actual structure end and the next 8-byte boundary). This slack space can contain remnant data from previous, smaller cell contents that occupied the same space.

#### 9.2.5 Path Reconstruction for Recovered Keys

For each recovered NK cell:
1. Read its **Parent** offset field
2. If the parent cell is still allocated and contains a valid NK structure, follow it upward to reconstruct the path
3. If the parent is also deleted/free, attempt to recover the parent recursively
4. If the parent cannot be found, report the key as "unassociated" (orphaned without a path)

### 9.3 The Msuhanov/YARP Algorithm

Maxim Suhanov's YARP (Yet Another Registry Parser) library implements a refined recovery algorithm. Key aspects:

1. **Plausibility validation:** Recovered keys/values are checked against thresholds:
   - Name length <= 1024 bytes
   - Null character count in name <= 5
   - No Unicode replacement characters in name
   - Subkey count <= 10,000
   - Value count <= 1,000
   - Timestamp year between plausible bounds (not before 1990, not after 2100)

2. **Deep unallocated cell scanning:** Within each unallocated cell, scan at every 2-byte offset for NK/VK signatures (not just at the cell start or aligned offsets)

3. **Remnant data extraction:** After scanning for complete NK/VK structures within a free cell, collect any remaining bytes as "unknown remnant data" for further analysis

4. **Value data recovery:** For recovered VK cells, attempt to follow the data offset to retrieve value data, validating that the referenced cell exists and contains plausible data

### 9.4 Mandiant/Google Improved Algorithm

Mandiant developed an improved recovery algorithm with better accuracy and fewer false positives:

1. **Phase 1 -- Full cell enumeration:** Parse ALL cells in the hive (both allocated and free), determining cell type and data size
2. **Phase 2 -- Allocated cell analysis:** For allocated NK cells, enumerate referenced value lists, class names, security records. Validate key ancestors to detect orphaned allocated keys
3. **Phase 3 -- Deleted entry detection:** Compare discovered entries against the active registry tree. Any entries not reachable from root are marked as deleted
4. **Phase 4 -- Slack space processing:** Examine padding bytes within allocated cells for residual data

This approach reduces false positives by cross-referencing all discovered cells before reporting recovered data.

### 9.5 Common Pitfalls in Deleted Key Recovery

| Pitfall | Description |
|---------|-------------|
| **Stale parent references** | Deleted NK cell's Parent offset may point to a cell that has been reused for a different key |
| **Coalesced cell boundaries** | Free cell may contain multiple overlapping deleted structures; tools that only check the cell start will miss data |
| **Reused cells** | A cell location may have been reused multiple times; current data may not match referenced offsets in deleted cells |
| **Invalid value associations** | A deleted NK cell's value list offset may point to value cells that now belong to a different key |
| **Inconsistent tools** | Different forensic tools use different recovery algorithms and produce different results for the same hive |

---

## 10. Registry Carving

Registry carving recovers hive data from non-hive sources (unallocated disk space, memory, page files, etc.) where no file system structure points to the data.

### 10.1 Signature-Based Carving from Disk

#### 10.1.1 Complete Hive Carving

Scan for the `regf` signature (0x72656766) at 4096-byte aligned offsets:
1. Validate the base block: check checksum, verify sequence numbers, check minor version
2. Read Hive bins data size to determine expected hive length
3. Verify the first hbin at offset 4096 has a valid `hbin` signature
4. Attempt to read the full hive; mark as truncated if data ends before expected size
5. Parse the recovered hive normally

#### 10.1.2 Fragment Carving (Partial Hives)

When a complete hive is not available, scan for individual `hbin` signatures:
1. Search for `hbin` (0x6862696E) at 4096-byte aligned offsets
2. Validate each candidate: check Size field (must be multiple of 4096), check Offset field consistency
3. If adjacent hbins are found, merge them into a larger fragment
4. Parse cells within recovered hbins independently (without the base block)

**Carving fragmented hives:** When hbin blocks are scattered across the disk due to NTFS fragmentation:
1. Identify all valid hbin blocks by signature
2. Sort by their internal Offset field
3. Reconstruct the hive by placing blocks at their declared offsets
4. Handle missing blocks gracefully (report gaps)

### 10.2 Carving from Memory Dumps

Registry hives are mapped into kernel virtual memory when loaded. Memory forensics tools (e.g., Volatility) can locate hives by:

1. **Scanning for `regf` signatures** in the memory dump
2. **Walking kernel data structures:** Locate the `CmpHiveListHead` linked list, which chains all loaded `_CMHIVE` structures. Each `_CMHIVE` contains a pointer to the hive's in-memory base block
3. **Extracting individual bins:** Walk the `_HHIVE.Storage[Stable].Map` which contains a hierarchical table mapping bin indexes to virtual addresses

**Considerations:**
- In-memory hives may contain volatile keys that don't exist on disk
- Memory-resident hive pages may reflect pending (unflushed) changes
- Hive data may be split across multiple virtual-to-physical page mappings

### 10.3 Carving from Page Files (pagefile.sys)

The page file contains memory pages that have been swapped to disk. Registry hive pages may be present if they were paged out:

1. Since pagefile.sys contains unstructured/unordered 4 KB memory pages, full hive reconstruction is generally not possible
2. Scan for `hbin` and `regf` signatures at 4096-byte boundaries
3. Individual cells (NK/VK) within recovered pages can be parsed independently
4. Only data structures smaller than 4 KB can be fully recovered from a single page

**Limitation:** Pages are typically 4 KB, so only structures that fit within a single page can be completely carved. Larger structures spanning multiple pages may be irrecoverable unless the pages happen to be adjacent.

### 10.4 Carving from Hibernation Files (hiberfil.sys)

The hibernation file contains a compressed snapshot of physical memory:

1. Decompress the hibernation file (tools: Volatility's `imagecopy`, `hibr2bin`)
2. The decompressed data represents the system's physical memory at the time of hibernation
3. Apply the same memory dump carving techniques as Section 10.2

**Caveat:** The hiberfil.sys is explicitly listed in `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToBackup`, meaning Volume Shadow Copy Service does NOT capture previous versions of this file.

### 10.5 Carving from Volume Shadow Copies

Volume Shadow Copies (VSS) provide point-in-time snapshots of NTFS volumes, potentially containing previous versions of registry hive files:

1. Mount the shadow copy volume (e.g., via `vssadmin`, `ShadowExplorer`, `ShadowCopyView`)
2. Navigate to the hive file locations (`%SystemRoot%\System32\Config\*`, `%USERPROFILE%\NTUSER.DAT`)
3. Extract and parse the hive files normally

**Important notes:**
- The VSS **Registry Writer** only captures system hives, not user hives (on modern Windows)
- System Restore Points (which use VSS) may contain registry hives from days or weeks earlier
- VSS snapshots may contain hives in a dirty state; always check for and apply corresponding LOG files from the same snapshot
- Maximum 64 shadow copies by default (configurable via `MaxShadowCopies` registry value)

### 10.6 Deep Carving (Cell-Level)

For severely fragmented or corrupted sources, scan for individual cell signatures at any offset:

1. Search for `nk` and `vk` signatures at 2-byte aligned offsets throughout the data source
2. Validate each candidate cell structure (check flags, timestamps, name lengths)
3. Extract individual key/value information even without surrounding hive structure
4. Report recovered items with reduced confidence (no path context, no value data cross-references)

---

## 11. Undocumented and Obscure Features

### 11.1 Class Name Field Abuse

The class name field of NK cells (offset 0x30 for the offset, 0x4A for the length) is rarely used by legitimate Windows applications. It can be abused as a covert data storage mechanism:

- Up to 64 KiB of arbitrary data can be stored via `NtCreateKey` with a class name parameter
- The data is NOT displayed by `RegEdit` or returned by `RegQueryInfoKey` on many systems
- Recovery requires `NtQueryKey` with `KeyNodeInformation` information class, or raw hive parsing
- Unlike null-character-based hiding techniques (used by Poweliks/Kovter malware), class name abuse does not cause any visible errors in RegEdit
- **Detection:** Parse the NK cell directly and check for non-empty Class name offset and Class name length fields. Read the class name data cell and inspect its contents

### 11.2 Layered Keys (Windows 10+)

Layered keys enable the containerized registry used by Application Silos (Windows Containers) and Centennial/UWP applications.

**How it works:**
- A **differencing hive** (version 1.6) is loaded on top of a base hive
- Keys in the differencing hive **override** keys in the base hive
- The `LayerSemantics` field in NK cells (2 bits at offset 0x0D) controls the override behavior:
  - `0` = Normal key (merged with base layer)
  - `1` = **Supersede** -- completely replaces the base layer key and all its subkeys
  - `2` = **Tombstone** -- marks this key as deleted in the differencing layer, even if it exists in the base layer
- The `InheritClass` bit (offset 0x0D, bit 7): when set, the class name is inherited from the base layer
- The base block Flags field bit 0x2 indicates the hive contains layered keys

**Forensic implications:**
- Differencing hives are loaded under `\Registry\WC` via the VRegDriver IOCTL interface (0x220008)
- They are unloaded when the corresponding silo/container is destroyed
- Forensic tools must understand the layering to reconstruct the effective registry state for containerized applications
- The `DIFF_HIVE_WRITETHROUGH` flag (0x2 in `DiffHiveFlags`) indicates all writes are redirected to lower layers

### 11.3 Container/Silo Registries

Windows Server Containers and Application Silos use a virtualized registry implemented via the `VRegDriver`:

- **VRegDriver** is built into `ntoskrnl.exe` and consists of:
  - An IOCTL interface at `\Device\VRegDriver` with 9+ operations
  - A registry callback (`VrpRegistryCallback`) implementing namespace redirection
- IOCTL operations include:
  - `0x220008`: `VrpHandleIoctlLoadDifferencingHive` -- loads a differencing hive
  - `0x220018`: `VrpHandleIoctlUnloadDynamicallyLoadedHives` -- tears down container hives
- Legal load flags for differencing hives: `REG_HIVE_NO_RM` (0x100), `REG_OPEN_READ_ONLY` (0x2000), `REG_IMMUTABLE` (0x4000)
- Differencing hive-specific flags: `DIFF_HIVE_ADD_TO_TRUST_CLASS` (0x1), `DIFF_HIVE_WRITETHROUGH` (0x2), `DIFF_HIVE_TRUSTED` (0x4)

### 11.4 Differencing Hives

Differencing hives (version 1.6) are a specific application of layered keys used by:
- **Centennial (Desktop Bridge) applications:** UWP-packaged desktop apps that need their own registry namespace
- **Windows Server Containers:** Lightweight containers with isolated registry views
- **Application Silos:** Isolation mechanism for packaged applications

The differencing hive contains only the **delta** from the base hive. Keys not present in the differencing hive are transparently read from the base layer.

### 11.5 Registry Virtualization (User Account Control)

Starting with Windows Vista, UAC introduced **registry virtualization** for legacy 32-bit applications that write to protected locations (e.g., `HKLM\SOFTWARE`). Writes are silently redirected to per-user virtual stores.

The `VirtControlFlags` (4 bits at NK offset 0x34, bits 20-23) and the NK flags `KEY_VIRT_MIRRORED` (0x0080), `KEY_VIRT_TARGET` (0x0100), `KEY_VIRTUAL_STORE` (0x0200) control this behavior:

| Flag | Purpose |
|------|---------|
| `KEY_VIRT_TARGET` | This key is a target for virtualization (writes will be redirected) |
| `KEY_VIRT_MIRRORED` | This key is mirrored (exists in both locations) |
| `KEY_VIRTUAL_STORE` | This key is part of the virtual store (the redirect destination) |

### 11.6 Registry Flight Recorder

Windows internally maintains diagnostic information about registry operations. While not formally documented, the kernel tracks performance metrics and error conditions during hive operations. This data may be available in crash dumps and diagnostic telemetry.

### 11.7 NotificationInfo

Registry key change notifications (via `RegNotifyChangeKeyValue`/`NtNotifyChangeKey`) create internal tracking structures. While these are purely in-memory constructs and do not appear in hive files, forensic analysis of memory dumps may reveal which keys were being monitored, potentially indicating surveillance or trigger-based malware.

### 11.8 Hive Reorganization/Defragmentation

Starting with Windows 8, the kernel periodically reorganizes hive files:
- **Defragmentation:** Compacts allocated cells, eliminating free cell gaps
- **Access history clearing:** Resets the AccessBits field in NK cells
- Occurs once per week when the hive is not locked
- The `LastReorganizeTime` field in the base block tracks when this last happened
- After defragmentation, **deleted key recovery becomes much harder** because free cells have been eliminated and data may have been shifted

### 11.9 Compressed Hives in Memory

Starting with certain Windows versions, the kernel can compress hive pages in memory. This affects memory dump analysis:
- Compressed hive bins have different in-memory layouts
- The YARP carving module (`RegistryCarve`) handles both compressed and uncompressed fragments
- Compressed fragments require decompression before cell parsing

---

## 12. References

### Primary Specifications

1. **Maxim Suhanov** -- [Windows Registry File Format Specification](https://github.com/msuhanov/regf/blob/master/Windows%20registry%20file%20format%20specification.md) (v1.0.75, 2018). The most comprehensive community specification. GitHub: [msuhanov/regf](https://github.com/msuhanov/regf)

2. **Joachim Metz (libyal)** -- [Windows NT Registry File (REGF) Format](https://github.com/libyal/libregf/blob/main/documentation/Windows%20NT%20Registry%20File%20(REGF)%20format.asciidoc). Detailed format specification with corruption scenarios. GitHub: [libyal/libregf](https://github.com/libyal/libregf)

3. **Kaitai Struct** -- [REGF Format Specification](https://formats.kaitai.io/regf/). Machine-readable format specification.

### Google Project Zero Research

4. **Mateusz Jurczyk** -- [The Windows Registry Adventure #4: Hives and the Registry Layout](https://projectzero.google/2024/10/the-windows-registry-adventure-4-hives.html) (October 2024). Deep dive into hive loading, differencing hives, VRegDriver, silos, and container registries.

5. **Mateusz Jurczyk** -- [The Windows Registry Adventure #5: The regf File Format](https://projectzero.google/2024/12/the-windows-registry-adventure-5-regf.html) (December 2024). Comprehensive analysis of the binary format, cell types, version history, base block, bins, and cells from a security research perspective.

### Forensic Research

6. **Mandiant/Google Cloud** -- [Digging Up the Past: Windows Registry Forensics Revisited](https://cloud.google.com/blog/topics/threat-intelligence/digging-up-the-past-windows-registry-forensics-revisited/) (March 2024). Improved deleted key/value recovery algorithm, transaction log replay, TxR analysis.

7. **Mandiant** -- [Too Log; Didn't Read -- Unknown Actor Using CLFS Log Files for Stealth](https://cloud.google.com/blog/topics/threat-intelligence/unknown-actor-using-clfs-log-files-for-stealth/). Research on CLFS container abuse by threat actors.

8. **Maxim Suhanov** -- [In-depth Forensic Analysis of Windows Registry Files](https://www.slideshare.net/MaximSuhanov/indepth-forensic-analysis-of-windows-registry-files) (2017 presentation). Practical forensic analysis techniques.

9. **Maxim Suhanov (dfir.ru)** -- [Tools That Recover Deleted Registry Data Don't Do the Same Job](https://dfir.ru/2018/11/18/tools-that-recover-deleted-registry-data-dont-do-the-same-job/) (November 2018). Comparative analysis of recovery tool accuracy.

10. **Timothy D. Morgan** -- [Recovering Deleted Data from the Windows Registry](https://www.sciencedirect.com/science/article/pii/S1742287608000303) (Digital Investigation, 2008). Foundational research on deleted registry data recovery.

11. **Jolanta Thomassen** -- [Forensic Analysis of Unallocated Space in Windows Registry Hive Files](http://sentinelchicken.com/research/thomassen_registry_unallocated_space/). Analysis of remnant data persistence in unallocated space.

12. **Andrea Fortuna** -- [Windows Registry Transaction Logs in Forensic Analysis](https://andreafortuna.org/2021/02/06/windows-registry-transaction-logs-in-forensic-analysis/) (February 2021). Practical guide to transaction log analysis.

### Anti-Forensics and Data Hiding

13. **Jackson T.** -- [Covert Data Persistence with Registry Keys](https://jackson-t.com/covert-data-persistence-with-registry-keys/). Class name field abuse for covert data storage.

14. **Apriorit** -- [Hiding of Registry Keys](https://www.apriorit.com/white-papers/53-hiding-of-registry-keys). Techniques for hiding registry keys from enumeration.

### Standards and Tool Specifications

15. **NIST** -- [Windows Registry Forensic Tool Specification](https://www.nist.gov/document/windows-registry-forensic-tool-specification-draft-2-version-10) (Draft 2, v1.0, June 2018). Requirements specification for registry forensic tools.

16. **Microsoft** -- [Registry Hives (Win32 API Documentation)](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives). Official (limited) documentation on hive structure and APIs.

### Forensic Tool Source Code

17. **notatin** -- Rust registry parser with transaction log support. GitHub: [strozfriedberg/notatin](https://github.com/strozfriedberg/notatin)

18. **YARP** -- Python library for parsing and recovering registry data. GitHub: [msuhanov/yarp](https://github.com/msuhanov/yarp)

19. **python-registry** -- Python parser for registry hive files. GitHub: [williballenthin/python-registry](https://github.com/williballenthin/python-registry)

### Microsoft Symbol Information

20. **Microsoft Symbol Server** -- PDB symbols for `ntoskrnl.exe` provide the definitive kernel structure definitions (`_HBASE_BLOCK`, `_HBIN`, `_CM_KEY_NODE`, `_CM_KEY_VALUE`, `_CM_KEY_INDEX`, `_CM_KEY_SECURITY`). Access via WinDbg or `symchk`.

---

## Appendix A: Quick Reference -- File Layout

```
Offset 0x0000: +-----------------------+
               | Base Block (regf)     |  4096 bytes (header)
               | Signature: "regf"     |
               | Checksum at 0x1FC     |
Offset 0x1000: +-----------------------+
               | Hive Bin 0 (hbin)     |  4096+ bytes (multiple of 4096)
               | Signature: "hbin"     |
               | Offset: 0x00000000    |
               | Cells: [nk][vk]...    |
               +-----------------------+
               | Hive Bin 1 (hbin)     |
               | Offset: size of bin 0 |
               | Cells: [nk][vk]...    |
               +-----------------------+
               | ...                   |
               +-----------------------+
               | Hive Bin N (hbin)     |
               | Last bin              |
               +-----------------------+
               | (Remnant data)        |  Optional: data beyond declared size
               +-----------------------+
```

## Appendix B: Quick Reference -- Cell Offset Calculation

```
All cell offsets in the hive are relative to the start of the hive bins data area.

file_offset = 0x1000 + cell_offset

Where:
  0x1000 = 4096 bytes = size of the base block
  cell_offset = the offset value stored in NK/VK/SK/LF/LH/LI/RI/DB fields

Null/empty offset sentinel: 0xFFFFFFFF
```

## Appendix C: Quick Reference -- Cell Signatures

| Signature | Hex | Cell Type | Description |
|-----------|-----|-----------|-------------|
| `nk` | 0x6E6B | Key Node | Registry key |
| `vk` | 0x766B | Value Key | Registry value |
| `sk` | 0x736B | Security Key | Security descriptor |
| `lf` | 0x6C66 | Fast Leaf | Subkey index with name hints (v1.3+) |
| `lh` | 0x6C68 | Hash Leaf | Subkey index with name hashes (v1.5+) |
| `li` | 0x6C69 | Index Leaf | Simple subkey index (v1.0-1.2, still valid) |
| `ri` | 0x7269 | Root Index | Index of subkey indices |
| `db` | 0x6462 | Big Data | Large value data reference (v1.4+) |

## Appendix D: Quick Reference -- Base Block Signatures

| Signature | Hex | Location | Description |
|-----------|-----|----------|-------------|
| `regf` | 0x72656766 | Base block offset 0x00 | Primary hive file identifier |
| `rmtm` | 0x726D746D | Base block offset 0xA4 | GUID fields are valid (Vista+) |
| `hbin` | 0x6862696E | Each hive bin offset 0x00 | Hive bin identifier |
| `DIRT` | 0x44495254 | Transaction log (old format) | Dirty vector identifier |
| `HvLE` | 0x48764C45 | Transaction log (new format) | Log entry identifier |
