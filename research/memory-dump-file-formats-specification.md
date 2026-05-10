# Memory Dump File Formats Specification

Comprehensive reference for memory dump formats used in digital forensics, covering Linux, Windows, and virtualization platforms. Each format includes magic bytes, header structures, physical address range encoding, and compression schemes.

---

## 1. LiME Format (.lime) -- Linux Memory Extractor

**Source**: [504ensicsLabs/LiME](https://github.com/504ensicsLabs/LiME) | [lime.h](https://github.com/504ensicsLabs/LiME/blob/master/src/lime.h)
**Author**: Joe T. Sylve, Ph.D. (presented at ShmooCon 2012)

### 1.1 Output Modes

LiME supports three output modes selected via the `format=` parameter when loading the kernel module:

| Mode | Constant | Description |
|------|----------|-------------|
| `raw` | `LIME_MODE_RAW (0)` | Concatenates all System RAM ranges; loses positional info |
| `lime` | `LIME_MODE_LIME (1)` | Prepends each range with a 32-byte header |
| `padded` | `LIME_MODE_PADDED (2)` | Zero-pads non-RAM gaps from physical address 0 |

Transfer methods: `LIME_METHOD_TCP (1)` for network, `LIME_METHOD_DISK (2)` for file.

### 1.2 Magic Bytes

```
#define LIME_MAGIC 0x4C694D45   // "LiME" in big-endian
```

On-disk (little-endian): `45 4D 69 4C` (reads as "EMiL" in ASCII)

### 1.3 Header Structure (`lime_mem_range_header`)

Total size: **32 bytes**, packed `__attribute__((packed))`

```c
typedef struct {
    unsigned int magic;            // 0x00: Always 0x4C694D45
    unsigned int version;          // 0x04: Header version (currently 1)
    unsigned long long s_addr;     // 0x08: Starting physical address
    unsigned long long e_addr;     // 0x10: Ending physical address (inclusive)
    unsigned char reserved[8];     // 0x18: Reserved, zeroed
} __attribute__((packed)) lime_mem_range_header;
```

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| `0x00` | 4 | `magic` | `0x4C694D45` ("EMiL" on disk, little-endian) |
| `0x04` | 4 | `version` | Header version; currently `1` |
| `0x08` | 8 | `s_addr` | Starting physical RAM address |
| `0x10` | 8 | `e_addr` | Ending physical RAM address (inclusive) |
| `0x18` | 8 | `reserved` | All zeros |

### 1.4 File Layout

```
[32-byte header][raw memory data: s_addr..e_addr]
[32-byte header][raw memory data: s_addr..e_addr]
...
```

Each contiguous physical memory range from `/proc/iomem` (lines marked "System RAM") gets one header + data segment. Non-RAM regions (MMIO, reserved) are omitted entirely in `lime` mode.

### 1.5 Writing Logic

From `main.c`, the `write_lime_header()` function:
1. Zero-initializes the header
2. Sets `header.magic = LIME_MAGIC`
3. Sets `header.version = 1`
4. Sets `header.s_addr = res->start`, `header.e_addr = res->end`
5. Writes the 32-byte header to output

### 1.6 Compression

LiME itself does **not** implement compression. The `digest=` parameter supports `sha1` and `sha256` hash generation as sidecar files, but the memory data is always uncompressed. For compressed LiME output, see AVML below.

### 1.7 Padding Mode Details

In `padded` mode, the dump starts at physical address 0. Non-RAM regions are filled with zero bytes, producing a file where `file_offset == physical_address`. This is convenient for tools that expect raw linear dumps but wastes space for the MMIO hole (typically 0.5-1.5 GB gap below 4GB on x86_64).

---

## 2. AVML Format -- Microsoft Acquire Volatile Memory for Linux

**Source**: [microsoft/avml](https://github.com/microsoft/avml) | [Volatility3 avml.py](https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/layers/avml.py)
**Author**: Brian Caswell (Microsoft), written in Rust

### 2.1 Overview

AVML is a userland volatile memory acquisition tool deployed as a static binary. It reads from `/dev/crash`, `/proc/kcore`, or `/dev/mem` (auto-selected). It fails if `kernel_lockdown` is active.

### 2.2 Output Format Versions

| Version | Compression | Magic | Format |
|---------|-------------|-------|--------|
| 1 | None | `0x4C694D45` (LiME) | Standard LiME format |
| 2 | Snappy (page-level) | `0x4C4D5641` (AVML) | AVML compressed format |

Version selection from source: `let version = if compress { 2 } else { 1 };`

### 2.3 Version 1 (Uncompressed): Standard LiME

When no `--compress` flag is used, AVML outputs standard LiME format (see Section 1). Identical header structure, identical magic `0x4C694D45`.

### 2.4 Version 2 (Compressed): AVML Native Format

**Magic**: `0x4C4D5641` -- "AVML" in big-endian, on disk as `41 56 4D 4C`

#### Per-Range Header Structure

From Volatility3's `avml.py` (`_load_segments`):

```python
avml_header_structure = "<IIQQQ"   # little-endian: 2x uint32, 3x uint64
```

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| `0x00` | 4 | `magic` | `0x4C4D5641` |
| `0x04` | 4 | `version` | Always `2` |
| `0x08` | 8 | `start` | Starting physical address |
| `0x10` | 8 | `end` | Ending physical address |
| `0x18` | 8 | `padding` | Reserved/padding |

Total header size: **32 bytes** (same as LiME, different magic+version)

#### Compression: Snappy Framing

After each 32-byte header, the memory data for that range is stored in **Snappy framed format** (not raw Snappy). The Volatility3 parser uses `libsnappy.so.1` (Linux) or `libsnappy.1.dylib` (macOS) via ctypes to decompress.

The parser processes chunks of Snappy-compressed data and maps them to segments with proper offset adjustments. After consuming each range's data, 8 trailing bytes are skipped.

#### File Layout

```
[32-byte AVML header][Snappy-framed compressed data][8 trailing bytes]
[32-byte AVML header][Snappy-framed compressed data][8 trailing bytes]
...
```

### 2.5 Conversion

`avml-convert` handles bidirectional conversion:
- AVML compressed -> LiME uncompressed
- LiME uncompressed -> AVML compressed
- Either -> raw format

Supported format enum: `Raw`, `Lime`, `LimeCompressed`

### 2.6 Key Difference from LiME

| Feature | LiME | AVML v2 |
|---------|------|---------|
| Magic | `0x4C694D45` | `0x4C4D5641` |
| Compression | None | Snappy (page-level) |
| Acquisition | Kernel module (LKM) | Userland static binary |
| Android support | Yes | No |
| Upload | No | Azure Blob, HTTP PUT |
| Memory sources | Kernel-direct | `/dev/crash`, `/proc/kcore`, `/dev/mem` |

---

## 3. Raw/Padded Memory Dumps (dd-style)

### 3.1 Format Description

Raw memory dumps are the simplest format: a linear byte stream where `file_offset == physical_address`. No headers, no metadata, no magic bytes.

### 3.2 The Non-Contiguous Memory Problem

Physical memory on modern systems is **not contiguous**. The physical address space contains:
- **System RAM** regions (actual DRAM)
- **MMIO holes** (memory-mapped I/O for devices, PCI, APIC)
- **Reserved regions** (BIOS, ACPI, firmware)
- **PCI hole** (typically `0xA0000`-`0xFFFFF` and a large gap below 4GB)

On x86_64, `/proc/iomem` shows the actual layout:
```
00000000-00000fff : Reserved
00001000-0009fbff : System RAM
000a0000-000fffff : Reserved (video, ROM)
00100000-bfffffff : System RAM
c0000000-febfffff : PCI MMIO hole (~1GB gap)
100000000-47fffffff : System RAM (above 4GB)
```

### 3.3 Handling Non-Contiguous Ranges

| Approach | Description | Pros | Cons |
|----------|-------------|------|------|
| **Padded (zero-fill)** | Fill gaps with `\x00` | `offset == phys_addr`; works in most tools | Wastes disk space; cannot distinguish real zero pages from padding |
| **Concatenated** | Skip gaps entirely | Smaller file | Offsets wrong; most tools fail to parse |
| **LiME format** | Header per range | Compact; metadata preserved | Requires LiME-aware parser |
| **ELF core** | PT_LOAD per range | Standard format; rich metadata | Larger overhead for many ranges |
| **Crash dump** | `PHYSICAL_MEMORY_DESCRIPTOR` | Native Windows debug tool support | Windows-specific |

### 3.4 Linux Acquisition with dd

**`/dev/mem`**: Limited to first 1MB on modern kernels (unless `CONFIG_STRICT_DEVMEM=n`). Not suitable for full acquisition.

**`/dev/fmem`** (fmem module): Creates unrestricted memory access device. Must consult `/proc/iomem` to avoid reading non-RAM addresses (causes hangs/crashes).

**`/proc/kcore`**: ELF core format (see Section 4). Not directly `dd`-able as raw.

**`/dev/crash`**: Available when crash driver is loaded. Same caution about non-RAM addresses.

### 3.5 Tools That Produce Padded Raw Dumps

- **LiME** with `format=padded`
- **WinPmem** (raw output mode)
- **DumpIt** (Windows, creates padded raw by default)
- **FTK Imager** (can capture raw memory)
- **VirtualBox** `.pgmphystofile` command

---

## 4. ELF Core Dumps -- Linux Crash Dumps and /proc/kcore

**References**: [ELF specification](https://refspecs.linuxfoundation.org/elf/elf.pdf) | [Dumping /proc/kcore](https://schlafwandler.github.io/posts/dumping-/proc/kcore/)

### 4.1 Overview

ELF core dumps (ET_CORE, ELF type 4) are the standard format for:
- `/proc/kcore` (live kernel memory view)
- `/proc/vmcore` (crash kernel memory, captured via kdump)
- VirtualBox core dumps (with VBCORE extension)
- QEMU `dump-guest-memory` default output

### 4.2 Magic Bytes

Standard ELF header:
```
7F 45 4C 46   -- ELF magic ("\x7fELF")
02            -- EI_CLASS: 64-bit (ELFCLASS64)
01            -- EI_DATA: little-endian (ELFDATA2LSB)
01            -- EI_VERSION: current
```

ELF header `e_type = ET_CORE (4)`

### 4.3 ELF Header (`Elf64_Ehdr`)

Key fields for memory dump parsing:

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| `0x00` | 16 | `e_ident` | Magic + class + endianness |
| `0x10` | 2 | `e_type` | `ET_CORE (4)` |
| `0x12` | 2 | `e_machine` | `EM_X86_64 (62)`, `EM_AARCH64 (183)`, etc. |
| `0x20` | 8 | `e_phoff` | Program header table offset |
| `0x38` | 2 | `e_phentsize` | Size of program header entry (56 bytes for ELF64) |
| `0x3A` | 2 | `e_phnum` | Number of program header entries |

### 4.4 Program Headers (`Elf64_Phdr`)

Each program header describes a segment:

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| `0x00` | 4 | `p_type` | `PT_LOAD (1)` or `PT_NOTE (4)` |
| `0x04` | 4 | `p_flags` | Permission flags (R/W/X) |
| `0x08` | 8 | `p_offset` | Offset in file where segment data begins |
| `0x10` | 8 | `p_vaddr` | Virtual address |
| `0x18` | 8 | `p_paddr` | **Physical address** (critical for forensics) |
| `0x20` | 8 | `p_filesz` | Size of segment in file |
| `0x28` | 8 | `p_memsz` | Size of segment in memory |
| `0x30` | 8 | `p_align` | Alignment |

### 4.5 Physical Memory Mapping via PT_LOAD

Each `PT_LOAD` segment maps a contiguous range of physical memory:
- `p_paddr`: Starting physical address
- `p_offset`: Where in the ELF file the data is located
- `p_memsz`: Size of the physical memory range

To read physical address `X` from the dump:
1. Find the `PT_LOAD` segment where `p_paddr <= X < p_paddr + p_memsz`
2. File offset = `p_offset + (X - p_paddr)`

### 4.6 `/proc/kcore` Specifics

- Appears as a multi-terabyte file (virtual address space size); no actual disk usage
- Generated on-the-fly by `fs/proc/kcore.c`
- Contains `PT_NOTE` with `VMCOREINFO` ELF note (metadata about kernel layout)
- **KASLR (kernel 4.8+)**: The `p_paddr` field in each `PT_LOAD` header contains the correct physical address despite KASLR randomization, making it reliable for physical memory dumping
- Only readable by root; blocked by `lockdown=confidentiality`

### 4.7 PT_NOTE: VMCOREINFO

The `VMCOREINFO` note contains key-value pairs describing kernel data structure offsets, symbol addresses, and configuration. Critical for forensic tools to locate kernel structures:

```
OSRELEASE=5.15.0-generic
PAGESIZE=4096
SYMBOL(init_uts_ns)=ffffffffb2c1b580
OFFSET(task_struct.pid)=1312
...
```

### 4.8 `/proc/vmcore` (Post-Crash)

- Created by the kdump mechanism after a kernel panic
- Second kernel boots via kexec, reads first kernel's memory
- Same ELF core format but represents the crashed kernel's memory
- Typically converted to kdump-compressed format by makedumpfile

---

## 5. Kdump-Compressed Format

**Source**: [makedumpfile/IMPLEMENTATION](https://github.com/makedumpfile/makedumpfile/blob/master/IMPLEMENTATION) | [diskdump_mod.h](https://github.com/makedumpfile/makedumpfile/blob/master/diskdump_mod.h)

### 5.1 Overview

The kdump-compressed format (also called "diskdump format") is the most common format for Linux kernel core dumps in production. Produced by `makedumpfile` and readable by the `crash` utility.

### 5.2 Magic Bytes

```c
#define KDUMP_SIGNATURE "KDUMP   "    // "KDUMP" + 3 spaces (8 bytes total)
#define SIG_LEN 8
```

On disk: `4B 44 55 4D 50 20 20 20`

### 5.3 File Layout

```
Block 0:           struct disk_dump_header (main header)
Block 1:           struct kdump_sub_header
Block 2:           1st-bitmap
Block 2+X:         2nd-bitmap (aligned by block)
Block 2+2*X:       page data (compressed pages)
```

Block size is defined in the header (typically 4096).

### 5.4 `disk_dump_header` Structure

```c
struct disk_dump_header {
    char    signature[SIG_LEN];    // "KDUMP   "
    int     header_version;        // Format version (currently up to 6)
    struct  new_utsname utsname;   // System identification
    struct  timeval timestamp;     // Dump creation time
    unsigned int status;           // Status flags (legacy, unused)
    int     block_size;            // Block size in bytes
    int     sub_hdr_size;          // Size of arch-dependent sub-header
    unsigned int bitmap_blocks;    // Number of bitmap blocks
    unsigned int max_mapnr;        // Max page frame number
    int     total_ram_blocks;      // Total number of RAM pages
    int     device_blocks;         // Unused
    int     written_blocks;        // Unused
    int     current_cpu;           // CPU that generated the dump
    int     nr_cpus;               // Number of CPUs
};
```

### 5.5 `kdump_sub_header` Structure

```c
struct kdump_sub_header {
    unsigned long phys_base;       // For x86_64 relocatable kernels
    int           dump_level;      // makedumpfile -d option value (v1+)
    int           split;           // Whether split dump (v2+)
    unsigned long start_pfn;       // Start page frame number (v2+, obsolete)
    unsigned long end_pfn;         // End page frame number (v2+, obsolete)
    off_t         offset_vmcoreinfo;  // Offset to vmcoreinfo (v3+)
    unsigned long size_vmcoreinfo;    // Size of vmcoreinfo (v3+)
    off_t         offset_note;     // Offset to ELF note (v4+)
    unsigned long size_note;       // Size of ELF note (v4+)
    off_t         offset_eraseinfo;   // Offset to erase info (v5+)
    unsigned long size_eraseinfo;     // Size of erase info (v5+)
    unsigned long long start_pfn_64;  // 64-bit start PFN (v6+)
    unsigned long long end_pfn_64;    // 64-bit end PFN (v6+)
    unsigned long long max_mapnr_64;  // 64-bit max map number (v6+)
};
```

### 5.6 Compression Schemes

| Variant | Compression | Tool Flag |
|---------|-------------|-----------|
| `kdump-zlib` | zlib | `makedumpfile -c` |
| `kdump-lzo` | LZO | `makedumpfile -l` |
| `kdump-snappy` | Snappy | `makedumpfile -p` |
| `kdump-zstd` | Zstandard | `makedumpfile --zstd` (newer) |
| `kdump-raw` | None (uncompressed pages) | QEMU 8.2+ |

Each individual page can be independently compressed/uncompressed. The 2nd bitmap indicates which pages are present in the dump.

### 5.7 Bitmaps

- **1st bitmap**: Marks which page frame numbers exist in the system
- **2nd bitmap**: Marks which page frame numbers are actually dumped (after filtering by dump level)

The dump level (`-d`) controls filtering: e.g., exclude zero pages, cache, user data, free pages.

---

## 6. Windows Crash Dump (.dmp)

**References**: [Volatility Crash Address Space](https://github.com/volatilityfoundation/volatility/wiki/Crash-Address-Space) | [DMP binary template](https://github.com/nforest/dumplib/blob/master/DMPTemplate.bt) | [WASM DMP format](https://wasm.in/blogs/description-of-dmp-format.505/)

### 6.1 Magic Bytes

| Architecture | Signature (ASCII) | Hex | Header Size |
|-------------|-------------------|-----|-------------|
| 32-bit | `PAGEDUMP` | `50 41 47 45 44 55 4D 50` | 4096 bytes (1 page) |
| 64-bit | `PAGEDU64` | `50 41 47 45 44 55 36 34` | 8192 bytes (2 pages) |

The signature occupies the first 8 bytes of the file.

### 6.2 32-bit Header (`_DMP_HEADER`, 4096 bytes)

```c
struct _DMP_HEADER {
    char     Signature[4];          // 0x000: "PAGE"
    char     ValidDump[4];          // 0x004: "DUMP"
    uint32   MajorVersion;          // 0x008
    uint32   MinorVersion;          // 0x00C
    uint32   DirectoryTableBase;    // 0x010: CR3 value
    uint32   PfnDataBase;           // 0x014
    uint32   PsLoadedModuleList;    // 0x018
    uint32   PsActiveProcessHead;   // 0x01C
    uint32   MachineImageType;      // 0x020: IMAGE_FILE_MACHINE_I386 (0x14C)
    uint32   NumberProcessors;      // 0x024
    uint32   BugCheckCode;          // 0x028
    uint32   BugCheckParameter[4];  // 0x02C
    char     VersionUser[32];       // 0x03C
    // ...
    _PHYSICAL_MEMORY_DESCRIPTOR PhysicalMemoryBlock; // 0x064
    // ...
    _CONTEXT ContextRecord;         // 0x320
    _EXCEPTION_RECORD ExceptionRecord; // 0x7D0
    // ...
    e_DumpType DumpType;            // 0xF88
};
```

### 6.3 64-bit Header (`_DMP_HEADER64`, 8192 bytes)

```c
struct _DMP_HEADER64 {
    char     Signature[4];          // 0x000: "PAGE"
    char     ValidDump[4];          // 0x004: "DU64"
    uint32   MajorVersion;          // 0x008
    uint32   MinorVersion;          // 0x00C
    uint32   DirectoryTableBase;    // 0x010
    uint32   PfnDataBase;           // 0x018
    uint64   PsLoadedModuleList;    // 0x020
    uint64   PsActiveProcessHead;   // 0x028
    uint32   MachineImageType;      // 0x030: IMAGE_FILE_MACHINE_AMD64 (0x8664)
    uint32   NumberProcessors;      // 0x034
    uint32   BugCheckCode;          // 0x038
    uint32   BugCheckParameter[4];  // 0x040
    uint64   KdDebuggerDataBlock;   // 0x080
    _PHYSICAL_MEMORY_DESCRIPTOR PhysicalMemoryBlock; // 0x088
    // ...
    _CONTEXT64 ContextRecord;       // 0x348
    _EXCEPTION_RECORD64 Exception;  // 0xF00
    e_DumpType DumpType;            // 0xF98
    uint64   RequiredDumpSpace;     // 0xFA0
    FILETIME SystemTime;            // 0xFA8
};
```

### 6.4 Physical Memory Descriptor

```c
typedef struct _PHYSICAL_MEMORY_RUN32 {
    uint32 BasePage;      // PFN of first page in this run
    uint32 PageCount;     // Number of pages in this run
};

typedef struct _PHYSICAL_MEMORY_DESCRIPTOR32 {
    uint32 NumberOfRuns;
    uint32 NumberOfPages;  // Total pages across all runs
    _PHYSICAL_MEMORY_RUN32 Run[];
};

// 64-bit variant uses uint64 for BasePage and PageCount
typedef struct _PHYSICAL_MEMORY_RUN64 {
    uint64 BasePage;
    uint64 PageCount;
};

typedef struct _PHYSICAL_MEMORY_DESCRIPTOR64 {
    uint32 NumberOfRuns;
    uint32 Padding;
    uint64 NumberOfPages;
    _PHYSICAL_MEMORY_RUN64 Run[];
};
```

**Sentinel check**: If `NumberOfRuns == 0x45474150` (`"PAGE"` in little-endian), the descriptor is invalid (seen in non-full dumps).

### 6.5 Data Layout

In a full dump, physical memory pages follow the header in order of the memory runs:
- Run 0 pages, then Run 1 pages, ..., Run N-1 pages
- To find physical address `X`:
  1. Calculate PFN = `X / PAGE_SIZE`
  2. Find which run contains this PFN
  3. Calculate page offset within the dump
  4. `file_offset = header_size + cumulative_pages_before * PAGE_SIZE + (PFN - run.BasePage) * PAGE_SIZE`

### 6.6 Dump Types

| DumpType Value | Name | Contents |
|---------------|------|----------|
| 1 | `FULL` | All physical memory pages |
| 2 | `KERNEL` | Only kernel-mode pages |
| 3 | `SMALL` | Mini-dump (64KB/128KB) |
| 5 | `TRIAGE` | Triage dump (limited) |
| 5 | `SPARSE_FULL` | Sparse full dump (Win 8.1+) |
| 6 | `SPARSE_KERNEL` | Sparse kernel dump |

### 6.7 KdDebuggerDataBlock

Signature: `GBDK` (0x4742444B). Contains kernel global variable addresses needed by forensic tools (PsActiveProcessHead, PsLoadedModuleList, etc.).

### 6.8 Triage Dump Headers

| Architecture | Offset |
|-------------|--------|
| 32-bit | `0x1000` (`TRIAGE_DUMP_HEADER32`) |
| 64-bit | `0x2000` (`TRIAGE_DUMP_HEADER64`) |

Contains offsets to context, exception record, call stack, driver list, and unloaded drivers.

---

## 7. Windows Hibernation File (hiberfil.sys)

**References**: [libhibr format specification](https://github.com/libyal/libhibr/blob/main/documentation/Windows%20Hibernation%20File%20(hiberfil.sys)%20format.asciidoc) | [forensics.wiki](https://forensics.wiki/hiberfil.sys/) | [Forensicxlab](https://www.forensicxlab.com/blog/hibernation)

### 7.1 Magic Bytes / Signature

| Value | Hex | Meaning |
|-------|-----|---------|
| `hibr` | `68 69 62 72` | Valid hibernation file (XP and below) |
| `HIBR` | `48 49 42 52` | Valid hibernation file (Vista and above) |
| `wake` | `77 61 6B 65` | Invalid/consumed file (XP and below) |
| `WAKE` | `57 41 4B 45` | Invalid/consumed file (Vista and above) |
| `RSTR` | `52 53 54 52` | Resuming state (transient; rarely seen in forensic images) |

After successful resume, the signature is changed from `HIBR` to `WAKE` to prevent re-processing.

### 7.2 Header Structure (PO_MEMORY_IMAGE)

The header varies by Windows version and architecture:

| Windows Version | Arch | Header Size |
|----------------|------|-------------|
| XP/2003 | 32-bit | 168 bytes |
| XP/2003 | 64-bit | 192 bytes |
| Vista SP0 | 32-bit | 224 bytes |
| Vista SP0 | 64-bit | 296 bytes |
| Vista SP2 | 32-bit | 240 bytes |
| 7 SP0 | 32-bit | 224 bytes |
| 7 SP0 | 64-bit | 280 bytes |
| 8/8.1/10/11 | 64-bit | Variable, larger |

#### Windows Vista+ 64-bit Key Fields

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 4 | Signature | `HIBR` / `WAKE` / `RSTR` |
| 4 | 4 | Image type | See section 7.3 |
| 8 | 4 | Checksum | Type unknown |
| 12 | 4 | Size | Header size |
| 16 | 8 | Page number | |
| 24 | 4 | Page size | Usually 4096 |
| 32 | 8 | System time | FILETIME |
| 40 | 8 | Interrupt time | |
| 48 | 4 | Feature flags | |
| 52 | 1 | Hibernation flags | |
| 96 | 8 | Total number of pages | |
| 104 | 8 | FirstTablePage | First page of memory range table |
| 112 | 8 | LastFilePage | |

### 7.3 Image Types

| Value | Meaning |
|-------|---------|
| 0 | None |
| 1 | Hibernation |
| 2 | Wake |

### 7.4 Page Layout

The file is divided into 4096-byte pages:

| Page | Content |
|------|---------|
| 0 | PO_MEMORY_IMAGE header (or zeroed) |
| 1 | Processor State (_KPROCESSOR_STATE) |
| 2 | Unknown |
| 3-5 | Unknown |
| 6 | Compressed page map (first block) |
| 7+ | Compressed page data (first block) |

Windows divides memory storage into two sections:
- **Boot section**: Starting at `FirstBootRestorePage * PAGE_SIZE`
- **Kernel section**: Starting at `FirstKernelRestorePage * PAGE_SIZE`

### 7.5 Compressed Page Data (Xpress)

Each compressed chunk has a header:

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 8 | Signature | `\x81\x81xpress` |
| 8 | 1 | Page count | Number of pages minus 1 |
| 9 | 4 | Compressed size | `(value / 4) + 1` = actual size |
| 13 | 19 | Reserved | Zeros |
| 32 | variable | Data | LZ XPRESS compressed data |
| ... | variable | Padding | 8-byte alignment |

### 7.6 Compression Evolution

| Windows Version | Compression |
|----------------|-------------|
| ME and earlier | None |
| 2000 | LZNT1 (LZ77 variant) |
| Vista, 7 | Xpress LZ77 |
| 8, 8.1 | Xpress LZ77+Huffman |
| 10, 11 | Both Xpress LZ77 and LZ77+Huffman |

The Xpress compression was reverse engineered by Matthieu Suiche. Microsoft later released [documentation in MS-DRSR](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/f977faaa-673e-4f66-b9bf-48c640241d47) (section 4.1.10.6.15), though with errors documented by Suiche.

### 7.7 Encryption

hiberfil.sys is not independently encrypted. If BitLocker/FDE is enabled, it resides on the encrypted volume and requires FDE keys for offline access.

### 7.8 Forensic Tools

| Tool | Capability |
|------|-----------|
| **Volatility/Volatility3** | Full parsing; brute-force fallback for zeroed headers |
| **Hibr2Bin** | Decompression to raw binary |
| **Sandman** (Suiche/Ruff) | Read/write Vista and 7 hibernation files |
| **Hibernation Recon** (Arsenal) | Commercial; XP through Windows 11 |
| **libhibr** (Joachim Metz) | Open-source parsing library |

---

## 8. Windows Pagefile (pagefile.sys)

### 8.1 Format

pagefile.sys has **no standardized header or magic bytes**. It is a flat file containing 4KB pages that have been paged out from physical memory. The pages are not stored sequentially -- their original virtual addresses are tracked only by the kernel's page tables and page table entries (PTEs), not within the pagefile itself.

### 8.2 Physical Address Mapping

There is no physical address mapping within the pagefile. The mapping is:
1. Virtual address -> PTE -> pagefile offset (if page is not present in RAM)
2. The PTE for a paged-out page contains: pagefile number + offset within pagefile

Without the corresponding page tables (from a memory dump or hibernation file), the pagefile cannot be reconstructed into a coherent address space.

### 8.3 Forensic Approach

Since there is no structural format, forensic analysis relies on:
- **String searching**: `strings`, `grep` for URLs, passwords, file paths
- **Data carving**: Extract file fragments (images, documents) using file signature detection
- **YARA scanning**: Apply malware rules to find indicators
- **PTE reconstruction**: If a full memory dump is available alongside the pagefile, Volatility can reconstruct paged-out virtual pages using the page table entries

### 8.4 Configuration

- Location: `%SystemDrive%\pagefile.sys` (default)
- Size: Typically 1.5-3x physical RAM
- Up to 16 pagefiles can exist across volumes
- OS holds file handle open -- cannot be read live without raw filesystem access
- Can be configured to clear at shutdown via local policy

---

## 9. VMware Formats (.vmem, .vmss, .vmsn)

**References**: [Volatility VMware Snapshot](https://github.com/volatilityfoundation/volatility/wiki/VMware-Snapshot-File) | [Volatility Labs MoVP II](https://volatility-labs.blogspot.com/2013/05/movp-ii-13-vmware-snapshot-and-saved.html)

### 9.1 .vmem Files

**Format**: Raw physical memory dump. No header, no magic bytes. `file_offset == guest_physical_address`.

Created by VMware Workstation, Fusion, and some ESX configurations when suspending or snapshotting a VM. Directly parseable by any tool that supports raw memory dumps.

### 9.2 .vmss / .vmsn Files

**`.vmss`**: Suspended state file
**`.vmsn`**: Snapshot state file

These files contain both VM metadata and physical memory in a proprietary format.

#### Header (`_VMWARE_HEADER`)

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| `0x00` | 4 | `Magic` | See below |
| `0x04` | 4 | Unknown | |
| `0x08` | 4 | `GroupCount` | Number of data groups |
| `0x0C` | varies | `Groups` | Array of `_VMWARE_GROUP` |

#### Magic Values

| Value | Hex |
|-------|-----|
| `0xbed2bed0` | Valid |
| `0xbad1bad1` | Valid |
| `0xbed2bed2` | Valid |
| `0xbed3bed3` | Valid |

#### Tag Structure (`_VMWARE_TAG`)

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| `0x00` | 1 | `Flags` | Contains data length encoding |
| `0x01` | 1 | `NameLength` | Length of tag name |
| `0x02` | varies | `Name` | Tag name string |

Tags have indices to distinguish multiple tags with the same name within a group. Data groups include: `Memory`, `CPU`, `DMA`, `CMOS`, `FlashRam`, `Keyboard`, `serial`, `MemoryHotplug`, `vmDebugControl`.

The `Memory` group contains the physical memory data. CPU state groups contain register values (EAX-EDI, EIP, EFLAGS, CR0-CR4, DR0-DR7, GDTR, IDTR).

### 9.3 Lazy Snapshotting

VMware implements lazy snapshotting: a trace flag is added to each page, and pages are saved to disk only when modified after the snapshot is triggered. This means the guest continues execution during the save process.

### 9.4 Forensic Conversion

- **vmss2core**: VMware utility that converts `.vmss`/`.vmsn` + `.vmem` to crash dump or ELF core format
- **Volatility `vmwareinfo`**: Dumps metadata from `.vmss`/`.vmsn` files
- **Volatility `imagecopy`**: Converts to raw dd-style dump

### 9.5 ESX vs Workstation

| Product | Suspend/Snapshot Memory Storage |
|---------|-------------------------------|
| Workstation/Fusion | Separate `.vmem` file (raw) |
| ESX/ESXi | Memory embedded in `.vmss`/`.vmsn` (proprietary format) |

---

## 10. VirtualBox Formats (.sav, ELF64 Core Dump)

**References**: [Volatility VirtualBox Core Dump](https://github.com/volatilityfoundation/volatility/wiki/Virtual-Box-Core-Dump) | [Volatility Labs MoVP II](https://volatility-labs.blogspot.com/2013/05/movp-ii-12-virtualbox-elf64-core-dumps.html) | [VBox Core Format](http://www.virtualbox.org/manual/ch12.html#guestcoreformat)

### 10.1 Overview

VirtualBox does not automatically save a separate raw memory file. The `.sav` file stores the complete VM state (including memory) in an ELF64 core dump format with custom extensions.

### 10.2 Acquisition Methods

1. **`vboxmanage debugvm <vm> dumpvmcore --filename=<file>`**: Creates ELF64 with VBCORE extensions
2. **`--dbg` + `.pgmphystofile <file>`**: Creates raw dd-style physical memory dump

### 10.3 ELF64 Core Dump with VBCORE

Standard ELF64 header with `e_type = ET_CORE (4)`.

#### PT_NOTE: VBCORE Descriptor

The ELF64 file contains a `PT_NOTE` segment whose name is `"VBCORE"`. This note contains a `DBGFCOREDESCRIPTOR` structure:

| Field | Size | Description |
|-------|------|-------------|
| `u32Magic` | 4 | `0xc01ac0de` |
| `u32FmtVersion` | 4 | Format version |
| `cbSelf` | 4 | Size of this structure |
| `u32VBoxVersion` | 4 | VirtualBox version number |
| `u32VBoxRevision` | 4 | VirtualBox SVN revision |
| `cCpus` | 4 | Number of virtual CPUs |

#### PT_LOAD: Physical Memory Segments

Each `PT_LOAD` segment maps guest physical memory:
- `p_paddr`: Guest physical address start
- `p_offset`: File offset of data
- `p_memsz`: Size of this physical memory range

The dump also includes VGA memory and other MMIO device memory as separate PT_LOAD segments.

### 10.4 Source Code References

- Header: `include/VBox/vmm/dbgfcorefmt.h`
- Implementation: `src/VBox/VMM/VMMR3/DBGFCoreWrite.cpp`

---

## 11. Hyper-V Formats (.bin, .vsv, .vmrs)

**References**: [Analyzing Hyper-V Saved State](https://www.wyattroersma.com/?p=77) | [DFRWS 2014 presentation](https://dfrws.org/sites/default/files/session-files/2014_USA_pres-memory_forensics_with_hyper-v_virtual_machines.pdf) | [LeechCore Hyper-V](https://github.com/ufrisk/LeechCore/wiki/Device_HyperV_SavedState)

### 11.1 Legacy Format (Server 2008-2012 R2)

| File | Contents |
|------|----------|
| `.BIN` | Physical memory chunks |
| `.VSV` | Device/hardware state (registers, device memory) |
| `.XML` | VM configuration |

The `.BIN` file is **pre-allocated** to the VM's configured RAM size for performance. Created when the VM is running; absent when powered off.

**Format**: Proprietary, **not publicly documented**. Microsoft considers format documentation a security risk (host-VM trust boundary).

### 11.2 Modern Format (Server 2016+)

| File | Contents |
|------|----------|
| `.VMRS` | Runtime state (memory + device state, combined) |
| `.VMCX` | VM configuration (binary, replaces XML) |

The `.VMRS` format replaced both `.BIN` and `.VSV`. Also proprietary and undocumented. Designed for better read/write efficiency and corruption resistance.

### 11.3 Forensic Conversion

#### Legacy (2008-2012 R2)

```
vm2dmp.exe -bin <path>.bin -vsv <path>.vsv -dmp <output>.dmp
```

Creates a Windows crash dump that Volatility/WinDbg can parse.

**Limitations**:
- Only Hyper-V 2.0 (Server 2008/2008R2)
- VMs with 4GB+ RAM fail
- No Linux guest support

#### Modern (2016+)

Requires `vmsavedstatedumpprovider.dll` from Windows SDK:
```
C:\Program Files (x86)\Windows Kits\10\bin\10.0.<build>.0\x64\vmsavedstatedumpprovider.dll
```

Used by:
- **MemProcFS / LeechCore**: Reads `.VMRS` directly via the DLL
- **Microsoft Project Freta**: Cloud-based analysis of Hyper-V memory snapshots

### 11.4 Checkpoint-Based Acquisition

```powershell
Checkpoint-VM -Name "VMName" -SnapshotName "ForensicCapture"
```

Creates a `.VMRS` file containing the VM's memory state without guest awareness -- ideal for forensic acquisition where the guest (and any malware) cannot detect the operation.

---

## 12. QEMU Memory Dump Formats

**References**: [QEMU dump.c](https://github.com/qemu/qemu/blob/master/dump/dump.c) | [Daynix QEMU debugging](https://daynix.github.io/2023/02/19/Guest-Windows-debugging-and-crashdumping-under-QEMU-KVM-dump-guest-memory-vmcoreinfo-and-virtio-win.html)

### 12.1 dump-guest-memory Command

The `dump-guest-memory` QMP/HMP command supports multiple output formats:

| Format Flag | Format | Compression |
|-------------|--------|-------------|
| (default) | ELF core | None |
| `-z` | kdump-compressed | zlib |
| `-l` | kdump-compressed | LZO |
| `-s` | kdump-compressed | Snappy |
| `-w` | Windows crash dump | None (DMP format) |
| kdump-raw | kdump standard | None (QEMU 8.2+) |

### 12.2 ELF Format Output

Identified as: `ELF 64-bit LSB core file, x86-64, version 1 (SYSV), SVR4-style`

Same ELF structure as described in Section 4, with PT_LOAD segments for physical memory ranges. However:
- QEMU may use a fake virtual address (same as physical address) since it doesn't have guest virtual address info
- Without `-device vmcoreinfo`, the dump will lack VMCOREINFO ELF note data

### 12.3 Windows Dump Output (-w flag)

The `-w` flag produces a WinDbg-readable `.DMP` format file, compatible with Windows Server 2012 through Server 2022, both 32-bit and 64-bit.

### 12.4 VMCOREINFO Device

```
-device vmcoreinfo
```

When present, the guest Linux kernel writes its VMCOREINFO data into this virtual device at boot. QEMU stores it alongside the VM state and includes it in core dumps, enabling `crash` and `drgn` to parse the dump without the corresponding `vmlinux` symbol file.

---

## 13. Summary: Magic Bytes Quick Reference

| Format | Magic (Hex) | Magic (ASCII) | Offset | Notes |
|--------|-------------|---------------|--------|-------|
| LiME | `45 4D 69 4C` | "EMiL" (LE) | 0 | Per-range header |
| AVML v2 | `41 56 4D 4C` | "AVML" (LE) | 0 | Per-range header, Snappy compressed |
| Raw/padded | None | N/A | N/A | No header |
| ELF core | `7F 45 4C 46` | "\x7fELF" | 0 | Standard ELF; e_type=4 |
| kdump | `4B 44 55 4D 50 20 20 20` | "KDUMP   " | 0 | 8-byte signature |
| Windows crash (32) | `50 41 47 45 44 55 4D 50` | "PAGEDUMP" | 0 | 4096-byte header |
| Windows crash (64) | `50 41 47 45 44 55 36 34` | "PAGEDU64" | 0 | 8192-byte header |
| hiberfil.sys | `48 49 42 52` | "HIBR" | 0 | Vista+ valid; also "wake"/"WAKE" |
| VMware .vmss/.vmsn | `D0 BE D2 BE` | N/A | 0 | `0xbed2bed0` (LE); multiple valid values |
| VirtualBox core | `7F 45 4C 46` | "\x7fELF" | 0 | ELF + PT_NOTE name "VBCORE" |
| VirtualBox desc | `DE C0 1A C0` | N/A | in note | `0xc01ac0de` (LE) in DBGFCOREDESCRIPTOR |
| Hyper-V .bin/.vmrs | Unknown | N/A | N/A | Proprietary, undocumented |
| pagefile.sys | None | N/A | N/A | No header; flat page store |

---

## 14. Compression Schemes Summary

| Format | Compression | Library |
|--------|-------------|---------|
| LiME | None | N/A |
| AVML v2 | Snappy (framed) | libsnappy |
| kdump | zlib, LZO, Snappy, Zstandard | Per-page selectable |
| hiberfil.sys (Win 2000) | LZNT1 | N/A |
| hiberfil.sys (Vista/7) | Xpress LZ77 | N/A |
| hiberfil.sys (8/10/11) | Xpress LZ77+Huffman | N/A |
| Windows crash dump | None (full), sparse (8.1+) | N/A |
| VMware .vmss/.vmsn | None | N/A |
| VirtualBox core | None | N/A |
| Hyper-V | Unknown (proprietary) | N/A |

---

## 15. Physical Address Encoding Comparison

| Format | How Physical Addresses Are Stored |
|--------|----------------------------------|
| LiME | Per-range 32-byte header: `s_addr` + `e_addr` |
| AVML v2 | Per-range 32-byte header: `start` + `end` (same layout, different magic) |
| Raw padded | Implicit: `file_offset == physical_address` |
| Raw concatenated | Lost (unless external map provided) |
| ELF core | PT_LOAD headers: `p_paddr` + `p_memsz` + `p_offset` |
| kdump | Bitmap + disk_dump_header: page frame numbers indexed |
| Windows crash | `_PHYSICAL_MEMORY_DESCRIPTOR`: `Run[].BasePage` + `Run[].PageCount` |
| hiberfil.sys | PO_MEMORY_RANGE_ARRAY: page numbers in compressed page map |
| VMware .vmss | Tags in Memory group (proprietary encoding) |
| VMware .vmem | Implicit: `file_offset == guest_physical_address` |
| VirtualBox | PT_LOAD headers: `p_paddr` + `p_memsz` (standard ELF) |
| Hyper-V | Proprietary (decoded by vmsavedstatedumpprovider.dll) |

---

## References

### Primary Sources (Format Specifications)
- [LiME source code (lime.h)](https://github.com/504ensicsLabs/LiME/blob/master/src/lime.h)
- [Microsoft AVML repository](https://github.com/microsoft/avml)
- [Volatility3 AVML layer parser](https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/layers/avml.py)
- [libhibr hiberfil.sys format specification](https://github.com/libyal/libhibr/blob/main/documentation/Windows%20Hibernation%20File%20(hiberfil.sys)%20format.asciidoc)
- [makedumpfile diskdump_mod.h](https://github.com/makedumpfile/makedumpfile/blob/master/diskdump_mod.h)
- [makedumpfile IMPLEMENTATION](https://github.com/makedumpfile/makedumpfile/blob/master/IMPLEMENTATION)
- [DMP binary template (nforest/dumplib)](https://github.com/nforest/dumplib/blob/master/DMPTemplate.bt)
- [QEMU dump.c source](https://github.com/qemu/qemu/blob/master/dump/dump.c)
- [VirtualBox dbgfcorefmt.h](http://www.virtualbox.org/svn/vbox/trunk/include/VBox/vmm/dbgfcorefmt.h)

### Forensic Tool Documentation
- [Volatility Crash Address Space](https://github.com/volatilityfoundation/volatility/wiki/Crash-Address-Space)
- [Volatility Lime Address Space](https://github.com/volatilityfoundation/volatility/wiki/Lime-Address-Space)
- [Volatility VMware Snapshot File](https://github.com/volatilityfoundation/volatility/wiki/VMware-Snapshot-File)
- [Volatility VirtualBox Core Dump](https://github.com/volatilityfoundation/volatility/wiki/Virtual-Box-Core-Dump)
- [forensics.wiki: hiberfil.sys](https://forensics.wiki/hiberfil.sys/)

### Research Papers and Articles
- [LiME whitepaper (BlackHat 2012)](https://media.blackhat.com/bh-us-12/Arsenal/Sylve/BH_US_12_Sylve_LiME_WP.pdf)
- [Volatility Labs: VirtualBox ELF64 Core Dumps](https://volatility-labs.blogspot.com/2013/05/movp-ii-12-virtualbox-elf64-core-dumps.html)
- [Volatility Labs: VMware Snapshot and Saved State](https://volatility-labs.blogspot.com/2013/05/movp-ii-13-vmware-snapshot-and-saved.html)
- [Oracle: What's Inside a Linux Kernel Core Dump](https://blogs.oracle.com/linux/whats-inside-a-linux-kernel-core-dump)
- [Dumping /proc/kcore in 2019](https://schlafwandler.github.io/posts/dumping-/proc/kcore/)
- [Memory Dump Formats (Forensic Focus)](https://www.forensicfocus.com/articles/memory-dump-formats/)
- [DFRWS 2014: Memory Forensics with Hyper-V](https://dfrws.org/sites/default/files/session-files/2014_USA_pres-memory_forensics_with_hyper-v_virtual_machines.pdf)
- [Magnet Forensics: Inside hiberfil.sys](https://www.magnetforensics.com/blog/when-windows-takes-a-nap-and-leaves-you-evidence-inside-hiberfil-sys/)
- [Daynix: Guest Windows Debugging under QEMU/KVM](https://daynix.github.io/2023/02/19/Guest-Windows-debugging-and-crashdumping-under-QEMU-KVM-dump-guest-memory-vmcoreinfo-and-virtio-win.html)
- [Volatility Foundation: 64-bit Windows 8 Raw Memory Dump Forensics](https://volatilityfoundation.org/the-secret-to-64-bit-windows-8-and-2012-raw-memory-dump-forensics/)
- [LeechCore: Hyper-V Saved State](https://github.com/ufrisk/LeechCore/wiki/Device_HyperV_SavedState)
- [VMware KB: vmss2core](https://knowledge.broadcom.com/external/article/323788/converting-a-snapshot-file-to-memory-dum.html)
- [MS-DRSR: Xpress Compression Algorithm](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/f977faaa-673e-4f66-b9bf-48c640241d47)
- [Forensicxlab: Volatility3 Windows Hibernation Analysis](https://www.forensicxlab.com/blog/hibernation)
