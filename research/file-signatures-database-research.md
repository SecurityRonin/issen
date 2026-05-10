# Comprehensive File Signature Database Research
## For the `forensic-signatures` Crate — Issen Forensic Toolkit

**Date:** 2026-03-25
**Purpose:** Inform the design of a shared `forensic-signatures` crate for file identification and carving across winreg-forensic, onedrive-forensic, and outlook-forensic parser crates.

---

## Part 1: Major File Signature Databases

### 1. Linux `file` Command / libmagic

**Source:** https://github.com/file/file — `magic/Magdir/` directory

**Overview:**
- The `file` command (Release 5.46+) uses libmagic to identify file types via "magic number" patterns
- The Magdir directory contains **100+ individual magic pattern files** organized by category (archive, audio, images, windows, compress, linux, etc.)
- Contains **thousands of individual magic test rules** covering several thousand distinct file formats
- No single official count is published; estimates range from 1,000–3,000+ distinct file types

**Magic File Format (DSL):**
Each line consists of four tab-separated fields:
```
[level>] offset  type  test  message
```

- **Offset:** Absolute byte offset, relative (`&`), indirect (`(20.s)`), or from-end-of-file
- **Type:** `byte`, `short`, `long`, `quad`, `float`, `double`, `string`, `search`, `regex`, `default`, `indirect`, `guid`, `der`; endian-specific variants (`leshort`, `beshort`, `lelong`, `belong`) and unsigned variants (`uleshort`, etc.)
- **Test:** Value to match with optional operator (`=`, `<`, `>`, `&`, `^`, `~`, `x` for any)
- **Message:** String to print (supports printf format specifiers)

**Continuation Lines (Multi-Level Matching):**
- Lines prefixed with `>` indicate child tests (continuation)
- `>>` = level 2, `>>>` = level 3, etc.
- Tree-like hierarchy: if level N test passes, all level N+1 children are tested
- Named subroutines via `name` and `use` directives
- `default` and `clear` for fallback matching

**Strengths for Forensic Use:**
- Most comprehensive general-purpose signature database
- Battle-tested for decades on Unix/Linux
- Handles complex multi-rule matching with continuation lines
- Supports indirect offsets (read a value from file, use as offset)
- Active maintenance

**Weaknesses for Forensic Use:**
- Designed for identification, NOT carving (no footer detection, no max-size)
- No file validation/structure checking
- No fragmentation handling
- Performance: sequential rule evaluation (no tree optimization)
- Complex DSL with undocumented features

**Key Documentation:**
- `magic(5)` man page: https://man7.org/linux/man-pages/man4/magic.4.html
- Trail of Bits deep-dive: https://blog.trailofbits.com/2022/07/01/libmagic-the-blathering/

---

### 2. PhotoRec (CGSecurity / Christophe Grenier)

**Source:** https://github.com/cgsecurity/testdisk

**File Type Coverage:**
- **480+ file extensions** across **~300 file families**
- Full list: https://www.cgsecurity.org/wiki/File_Formats_Recovered_By_PhotoRec
- Current stable: PhotoRec 7.2 (2024-02-22); beta 7.3-WIP has newer signatures

**Signature Definition Format:**
PhotoRec uses C source code for signature definitions. Each file type has a dedicated `file_*.c` source file in `src/` implementing:
- `header_check()` — validates header bytes
- `data_check()` — validates ongoing data stream
- `file_check()` — post-recovery validation
- `register_header_check()` — registers signature at offset with callback

**Custom Signature Format** (`photorec.sig`):
```
extension  offset  hex_signature
```
Example: `bar 0 4261722100`

**Beyond Simple Header Matching:**
1. **Structure validation:** JPEG uses libjpeg for validation; OLE uses internal FAT analysis for file size
2. **Footer detection:** JPEG footer (`FF D9`), ZIP end-of-central-directory
3. **File size estimation:** OLE files parsed for internal FAT to determine size
4. **Statistical methods:** Text detection via UTF-8 to ASCII translation + index of coincidence
5. **Block/cluster alignment:** Detects cluster size from first 10 files found
6. **Fragmentation handling:** Limited JPEG bifragment recovery using libjpeg validation

**Strengths:** Structure-aware carving, format-specific validators, large signature database, active development
**Weaknesses:** Written in C (not library-friendly), limited fragmentation handling beyond JPEG

---

### 3. Foremost (Jesse Kornblum)

**Source:** https://github.com/korczis/foremost — Originally USAF OSI / CISSRL

**Supported File Types:** jpg, gif, png, bmp, avi, exe, mpg, wav, riff, wmv, mov, pdf, ole, doc, zip, rar, htm, cpp (built-in); extensible via config

**Configuration File Format** (`/etc/foremost.conf`):
```
# Extension  CaseSensitive(y/n)  MaxSize(bytes)  Header(hex)  Footer(hex, optional)
jpg          y                   20000000        \xff\xd8      \xff\xd9
pdf          y                   5000000         \x25\x50\x44\x46  \x25\x25\x45\x4f\x46
```

Tab-delimited, five fields:
1. **Extension** — output file extension
2. **Case sensitivity** — y/n
3. **Max file size** — in bytes
4. **Header** — hex escape sequences
5. **Footer** — hex escape sequences (optional)

**How It Differs from PhotoRec:**
- Simpler approach: header + optional footer + max size
- No structure validation (PhotoRec validates JPEG with libjpeg, OLE via FAT)
- Configuration-file driven (easy to customize, no code changes needed)
- Does not detect cluster/block sizes
- PhotoRec generally recovers more files in head-to-head comparisons

---

### 4. 010 Editor Binary Templates

**Source:** https://www.sweetscape.com/010editor/repository/templates/

**Template Count:** **80+ officially verified templates** in the SweetScape repository; community GitHub repos add many more

**Categories:** Archive, Audio, CAD, Crypto, Database, Disk, Document, Email, Executable, Font, Game, Image, Misc, Network, Programming, Science, System, Video

**Template Structure:**
Templates use a **C-like struct definition language** (.bt files):
```c
typedef struct {
    char signature[4];   // "PK\x03\x04"
    ushort version;
    ushort flags;
    ushort compression;
    // ...
} ZIPFILERECORD;
```

**Relevance to `forensic-signatures`:**
- 010 templates define **exact binary structure layouts** for hundreds of formats
- Can inform our Rust struct definitions for structure-aware validation
- Provide field-by-field format documentation
- Cover forensically important formats: EXE, ZIP, PDF, JPEG, PNG, BMP, GIF, DOC, XLSX, SQLite, EVTX, Registry, LNK, Prefetch, MFT, FAT, NTFS, etc.

---

### 5. Scalpel (Golden G. Richard III)

**Source:** https://github.com/sleuthkit/scalpel — Rewrite of Foremost 0.69

**Status:** Not actively maintained but widely used in forensic training

**Configuration Format:** (`scalpel.conf`) — Same format as Foremost:
```
# Extension  CaseSensitive  MaxSize  Header            Footer
gif          y              5000000  \x47\x49\x46\x38  \x00\x3b
```
All patterns are **commented out by default** — must be selectively enabled.

**Two-Pass Approach:**
1. **First pass:** Identifies potential file boundaries from signature matches
2. **Second pass:** Reads identified blocks in detail, extracts complete files

**Fragmented File Handling:**
- Performance-optimized for large disk images over Foremost
- GPU acceleration via NVIDIA CUDA (Linux only, compute capability >= 1.2)
- Limited native fragment reassembly

**Key Features:**
- Preview mode (`-p`): audit log without actual carving
- Cluster-aligned carving (`-q`): only match headers at cluster boundaries
- Header/footer database generation (`-d`)

---

### 6. bulk_extractor (Simson Garfinkel)

**Source:** https://github.com/simsong/bulk_extractor

**Approach:** Stream-based forensic feature extraction (not traditional file carving)

**What It Extracts:**
- Email addresses, URLs, credit card numbers, phone numbers
- JPEG images, EXIF data
- ZIP file components
- Windows PE executables
- JSON objects, HTTP headers
- GPS coordinates, domain names

**Compressed Data Handling:**
- **Optimistic decompression:** probes every byte to see if it starts a decompressible sequence
- Automatically detects and decompresses: gzip, zlib, bzip2, LZMA
- Recursively re-processes decompressed data
- Finds BASE64-encoded JPEGs, compressed JSON that traditional carvers miss

**Scanner Architecture:**
- **Basic scanners:** Search for specific patterns (email, URL, etc.)
- **Recursive scanners:** Decode data and pass back for re-analysis (e.g., zip-scanner)
- 16 MiB page-based parallel processing (24 cores = ~24x speedup)
- Context-based stop-lists for false positive reduction
- "Forensic path" documents physical location + transformations

**Key Reference:** Garfinkel, "Digital media triage with bulk data analysis and bulk_extractor," Computers and Security 32: 56-72 (2013)

---

### 7. Binwalk

**Source:** https://github.com/ReFirmLabs/binwalk — 13.8k stars

**Primary Focus:** Firmware/embedded file extraction

**Signature Database:**
- Extended libmagic-compatible magic signature database at `/etc/binwalk/magic`
- Custom signatures for firmware-specific formats: bootloaders, kernel images, filesystems (SquashFS, JFFS2, UBI, CRAMFS, YAFFS2)
- Compression: gzip, bzip2, LZMA, LZO, Zstandard, LZ4
- Common formats: ZIP, TAR, CPIO, AR, RAR
- Signatures <3 bytes excluded by default (use `--all` to include)

**Nested/Embedded File Handling:**
- **Matryoshka mode** (`-M`): Recursive extraction up to 8 levels deep
- Scans entire binary blob byte-by-byte (unlike `file` which only checks start)
- **Entropy analysis** (`-E`): Detect encrypted/compressed regions by measuring randomness

**Custom Signatures:**
- Add to `$HOME/.config/binwalk/magic` or via `--magic` flag
- Uses standard libmagic DSL syntax

---

### 8. DROID / PRONOM (The National Archives UK)

**Source:** https://www.nationalarchives.gov.uk/PRONOM/ | https://github.com/digital-preservation/droid

**PRONOM Database:**
- **1,400+ file format identifications** (growing)
- Current signature file: **DROID_SignatureFile_V120.xml** (2025-02-25)
- Current DROID version: 6.9.10 (November 2025)

**Two Types of Signatures:**
1. **Binary (XML) Signatures:** Compiled from PRONOM into XML; regex-like byte patterns with offsets (BOF = beginning of file, EOF = end of file, variable positions)
2. **Container Signatures:** For ZIP/OLE-based formats; inspects internal file structure (e.g., DOCX = ZIP containing specific XML files)

**Signature Syntax (XML-based):**
```xml
<InternalSignature ID="100" Specificity="Specific">
  <ByteSequence Reference="BOFoffset" Offset="0">
    <SubSequence Position="1" SubSeqMinOffset="0" SubSeqMaxOffset="0">
      <Sequence>255044462D</Sequence> <!-- %PDF- -->
    </SubSequence>
  </ByteSequence>
</InternalSignature>
```

**How PRONOM Differs from Magic-Based:**
- Formal PUID (PRONOM Unique Identifier) system for each format version
- Container signatures solve the DOCX-is-just-a-ZIP problem
- No structure validation or carving capabilities
- Monthly auto-generated updates

**Related Tool:** [Siegfried](https://github.com/richardlehane/siegfried) — Fast Go-based PRONOM identifier

---

### 9. Apache Tika

**Source:** https://github.com/apache/tika | Database: `tika-mimetypes.xml`

**Coverage:** **1,400+ MIME types** detected

**Detection Strategies (layered):**
1. **Magic bytes:** MIME magic info (Freedesktop MIME-info format + extensions)
2. **File extension:** Name-based heuristics
3. **XML root element:** Namespace/root tag analysis
4. **Container format detection:** OLE2, ZIP internal inspection
5. **Content-type metadata:** HTTP header hints
6. **Machine learning (experimental):** Byte-frequency histograms + neural network

**Database Format:** XML (`tika-mimetypes.xml`)
```xml
<mime-type type="application/pdf">
  <magic priority="50">
    <match value="%PDF-" type="string" offset="0"/>
  </magic>
  <glob pattern="*.pdf"/>
</mime-type>
```

**Notable:** `tika-magic` Rust crate exists (Apache 2.0 licensed MIME detection using Tika's rules)

---

### 10. Gary Kessler's File Signatures Table

**Source:** https://www.garykessler.net/library/file_sigs.html (now transferred to SEARCH: https://filesig.search.org/)

**History:**
- Started February 2002
- Listed in Wikipedia's List of File Signatures and many DFIR textbooks
- Referenced in forensic courses worldwide for 20+ years
- Transferred to SEARCH in early 2025 after Kessler's retirement

**Format:** HTML table with columns: Hex Signature, File Extension, Description
**Coverage:** Several hundred file signatures with header and sometimes trailer bytes

---

### 11. Other Signature Databases

#### YARA Rules for File Type ID
- YARA rules can match binary/hex/regex patterns
- Used for malware classification AND file type identification
- Can be integrated with ClamAV for leveraging file decomposition
- Pure Rust YARA implementation available: `yara-x` crate

#### ClamAV Signatures
- Signature database formats: NDB, HDB, HSB, MDB, MSB
- `main.cld` / `daily.cld` — primary + incremental databases
- Supports YARA rules since ClamAV 0.99
- Leverages file decomposition for deep inspection

#### VirusTotal
- Uses multiple AV engines, each with own signature databases
- YARA rules can be run against VirusTotal corpus
- Community YARA rulesets available (e.g., Florian Roth's rules)

---

## Part 2: Forensically Critical File Signatures

### Registry / Windows System Files

| Artifact | Signature (Hex) | Signature (ASCII) | Offset | Notes |
|----------|-----------------|-------------------|--------|-------|
| REGF (Registry Hive) | `72 65 67 66` | `regf` | 0 | Internal `hbin` at every 4096 bytes |
| Registry Bin (internal) | `68 62 69 6E` | `hbin` | 4096, 8192, ... | Internal structure marker |
| LNK (Windows Shortcut) | `4C 00 00 00 01 14 02 00 00 00 00 00 C0 00 00 00 00 00 00 46` | `L...............F` | 0 | Full CLSID header; first 4 bytes = `4C 00 00 00` |
| Prefetch (XP/Win7) | `(ver) 00 00 00 53 43 43 41` | `....SCCA` | 0 | Version byte at offset 0: `0x11`=XP, `0x17`=Win7 |
| Prefetch (Win8/8.1) | `(ver) 00 00 00 53 43 43 41` | `....SCCA` | 0 | Version: `0x1A`=Win8, `0x1E`=Win8v2, `0x1F`=Win8.1 |
| Prefetch (Win10/11 compressed) | `4D 41 4D 04` | `MAM.` | 0 | XPRESS Huffman compressed; `SCCA` after decompression |
| EVTX File Header | `45 6C 66 46 69 6C 65 00` | `ElfFile\0` | 0 | |
| EVTX Chunk Header | `45 6C 66 43 68 6E 6B 00` | `ElfChnk\0` | Chunk boundaries | 64KB chunks |
| EVTX Event Record | `2A 2A 00 00` | `**..` | Record start | |
| Jump Lists (Auto) | `D0 CF 11 E0 A1 B1 1A E1` | OLE/CFB | 0 | OLE Compound File with DestList stream |
| Thumbcache | `43 4D 4D 4D` | `CMMM` | 0 | Version field: `0x14`=Vista, `0x15`=Win7, `0x20`=Win10 |
| Thumbcache Index | `49 4D 4D 4D` | `IMMM` | 0 | Index file (`thumbcache_idx.db`) |
| ESE Database (JET Blue) | `EF CD AB 89` | N/A | 4 | Bytes 0-3 are XOR checksum; signature at offset 4 |
| Amcache.hve | `72 65 67 66` | `regf` | 0 | Same as Registry hive format |

### Email / Messaging

| Artifact | Signature (Hex) | Signature (ASCII) | Offset | Notes |
|----------|-----------------|-------------------|--------|-------|
| PST (Outlook) | `21 42 44 4E` | `!BDN` | 0 | `SM` (`53 4D`) at offset 8; Unicode vs ANSI at offset 10 |
| OST (Outlook Offline) | `21 42 44 4E` | `!BDN` | 0 | Same header as PST |
| PAB (Personal Address Book) | `21 42 44 4E` | `!BDN` | 0 | Same header as PST/OST |
| MSG (Outlook Message) | `D0 CF 11 E0 A1 B1 1A E1` | OLE/CFB | 0 | OLE compound document |
| EML | `46 72 6F 6D 3A 20` or RFC822 headers | `From: ` | 0 | Text-based; variable headers |
| MBOX | `46 72 6F 6D 20` | `From ` | 0 | Each message starts with `From ` at line beginning |
| DBX (Outlook Express) | `CF AD 12 FE` | N/A | 0 | Followed by CLSID for subtype |

### Cloud Storage / Browsers

| Artifact | Signature (Hex) | Signature (ASCII) | Offset | Notes |
|----------|-----------------|-------------------|--------|-------|
| SQLite | `53 51 4C 69 74 65 20 66 6F 72 6D 61 74 20 33 00` | `SQLite format 3\0` | 0 | Chrome, Firefox, OneDrive databases |
| LevelDB Table | `57 FB 80 8B 24 75 47 DB` | N/A | **End of file** (last 8 bytes) | Chrome, Electron apps |

### Disk Images / Forensic Formats

| Format | Signature (Hex) | Signature (ASCII) | Offset | Notes |
|--------|-----------------|-------------------|--------|-------|
| E01 (EnCase v1) | `45 56 46 09 0D 0A FF 00` | `EVF.....` | 0 | Expert Witness Format |
| Ex01 (EnCase v2) | `45 56 46 32 0D 0A 81` | `EVF2...` | 0 | EWF2 format, not backward-compatible |
| AFF4 | `50 4B 03 04` | `PK..` | 0 | ZIP-based; identify by internal `container.description` |
| VMDK (sparse) | `4B 44 4D 56` | `KDMV` | 0 | "VMDK" in little-endian; flat VMDKs have no magic |
| VHD | `63 6F 6E 65 63 74 69 78` | `conectix` | 0 | 512-byte footer; same signature at start AND end |
| VHDX | `76 68 64 78 66 69 6C 65` | `vhdxfile` | 0 | Hyper-V (Windows 8+) |
| QCOW2 | `51 46 49 FB` | `QFI\xfb` | 0 | Version at bytes 4-7 (2 or 3) |
| Raw/DD | (none) | N/A | N/A | No signature; identified by context |

### Archives / Containers

| Format | Signature (Hex) | Offset | Footer | Notes |
|--------|-----------------|--------|--------|-------|
| ZIP | `50 4B 03 04` | 0 | `50 4B 05 06` (EOCD) | Variants: `50 4B 05 06` (empty), `50 4B 07 08` (spanned) |
| RAR 4 | `52 61 72 21 1A 07 00` | 0 | N/A | |
| RAR 5 | `52 61 72 21 1A 07 01 00` | 0 | N/A | |
| 7z | `37 7A BC AF 27 1C` | 0 | N/A | |
| GZIP | `1F 8B` | 0 | N/A | Byte 2 = compression method (usually `08` for deflate) |
| BZIP2 | `42 5A 68` | 0 | N/A | Followed by block size digit ('1'-'9') |
| XZ | `FD 37 7A 58 5A 00` | 0 | `59 5A` | YZ footer |
| Zstandard | `28 B5 2F FD` | 0 | N/A | |
| TAR (ustar) | `75 73 74 61 72` | 257 | N/A | Two 512-byte zero blocks at end |
| CAB | `4D 53 43 46` | 0 | N/A | `MSCF` |
| LZ4 (frame) | `04 22 4D 18` | 0 | N/A | |

### Documents

| Format | Signature (Hex) | Offset | Notes |
|--------|-----------------|--------|-------|
| PDF | `25 50 44 46 2D` | 0 | `%PDF-`; footer `%%EOF` |
| OLE/CFB (DOC/XLS/PPT) | `D0 CF 11 E0 A1 B1 1A E1` | 0 | 8-byte signature; distinguish by internal streams |
| DOCX/XLSX/PPTX | `50 4B 03 04` | 0 | ZIP; identify by `[Content_Types].xml` and `word/`, `xl/`, `ppt/` dirs |
| RTF | `7B 5C 72 74 66` | 0 | `{\rtf` |

### Databases

| Format | Signature (Hex) | Offset | Notes |
|--------|-----------------|--------|-------|
| SQLite | `53 51 4C 69 74 65 20 66 6F 72 6D 61 74 20 33 00` | 0 | 16 bytes |
| ESE (JET Blue) | `EF CD AB 89` | **4** | Bytes 0-3 = XOR checksum |
| MDB (Access <=2000) | `00 01 00 00 53 74 61 6E 64 61 72 64 20 4A 65 74 20 44 42` | 0 | `Standard Jet DB` at byte 4 |
| ACCDB (Access 2007+) | `00 01 00 00 53 74 61 6E 64 61 72 64 20 41 43 45 20 44 42` | 0 | `Standard ACE DB` at byte 4 |
| LevelDB Table (.ldb) | `57 FB 80 8B 24 75 47 DB` | EOF-8 | Footer signature (last 8 bytes) |

### Encryption

| Format | Signature (Hex) | Offset | Notes |
|--------|-----------------|--------|-------|
| BitLocker | `2D 46 56 45 2D 46 53 2D` | Volume start | `-FVE-FS-` (8 bytes) |
| LUKS v1 | `4C 55 4B 53 BA BE` | 0 | `LUKS\xBA\xBE` — 6 bytes; followed by version `00 01` |
| LUKS v2 | `4C 55 4B 53 BA BE 00 02` | 0 | Version `00 02` |
| VeraCrypt/TrueCrypt | **(NONE)** | N/A | By design; use heuristics: entropy >7.9, size % 512 == 0, no known header |
| PGP Encrypted | `A6 00` (old-format, Tag 9) | 0 | Symmetrically Encrypted Data Packet |
| PGP Public Key | `99 xx yy` (old-format) | 0 | Public-Key Packet, two-octet length |
| PGP Signed | `A8 03` (old-format, Tag 10) | 0 | Marker Packet |
| PGP ASCII-Armored | `2D 2D 2D 2D 2D 42 45 47 49 4E 20 50 47 50` | 0 | `-----BEGIN PGP` |

### Executables

| Format | Signature (Hex) | Offset | Notes |
|--------|-----------------|--------|-------|
| PE (EXE/DLL) | `4D 5A` | 0 | `MZ`; PE header at offset in DWORD at `0x3C` |
| ELF | `7F 45 4C 46` | 0 | `.ELF`; byte 4 = class (32/64), byte 5 = endianness |
| Mach-O (32-bit) | `FE ED FA CE` | 0 | Big-endian |
| Mach-O (64-bit) | `FE ED FA CF` | 0 | Big-endian |
| Mach-O (32-bit LE) | `CE FA ED FE` | 0 | Little-endian (most common on x86/ARM) |
| Mach-O (64-bit LE) | `CF FA ED FE` | 0 | Little-endian (most common) |
| Mach-O Universal | `CA FE BA BE` | 0 | Fat binary (conflicts with Java class!) |
| Java class | `CA FE BA BE` | 0 | Differentiate from Mach-O by bytes 4-7 (version numbers) |
| .NET Assembly | `4D 5A` | 0 | PE format with CLI header; check for `PE\0\0` + optional header |
| DEX (Android) | `64 65 78 0A 30 33` | 0 | `dex\n03` |
| WebAssembly | `00 61 73 6D` | 0 | `\0asm` |

### Media

| Format | Signature (Hex) | Offset | Footer | Notes |
|--------|-----------------|--------|--------|-------|
| JPEG | `FF D8 FF` | 0 | `FF D9` | Byte 3: `E0`=JFIF, `E1`=Exif, `E2`=ICC, `DB`=raw |
| PNG | `89 50 4E 47 0D 0A 1A 0A` | 0 | `49 45 4E 44 AE 42 60 82` | 8-byte header; IEND chunk as footer |
| GIF87a | `47 49 46 38 37 61` | 0 | `3B` | `GIF87a` |
| GIF89a | `47 49 46 38 39 61` | 0 | `3B` | `GIF89a` |
| BMP | `42 4D` | 0 | N/A | `BM`; file size at bytes 2-5 (LE) |
| TIFF (LE) | `49 49 2A 00` | 0 | N/A | `II*\0` |
| TIFF (BE) | `4D 4D 00 2A` | 0 | N/A | `MM\0*` |
| HEIF/HEIC | `66 74 79 70` | 4 | N/A | `ftyp` at offset 4; subtypes: `heic`, `heix`, `mif1` |
| WebP | `52 49 46 46 ?? ?? ?? ?? 57 45 42 50` | 0 | N/A | RIFF container with `WEBP` |
| AVIF | `66 74 79 70` | 4 | N/A | `ftyp` with subtype `avif` |
| MP4/MOV | `66 74 79 70` | 4 | N/A | `ftyp` at offset 4; subtypes: `isom`, `mp41`, `mp42`, `qt  ` |
| AVI | `52 49 46 46 ?? ?? ?? ?? 41 56 49 20` | 0 | N/A | RIFF with `AVI ` |
| MKV/WebM | `1A 45 DF A3` | 0 | N/A | EBML header |
| FLV | `46 4C 56 01` | 0 | N/A | `FLV\x01` |
| MP3 (ID3v2) | `49 44 33` | 0 | N/A | `ID3` |
| MP3 (MPEG frame) | `FF FB` or `FF FA` or `FF F3` | 0 | N/A | Frame sync bits |
| WAV | `52 49 46 46 ?? ?? ?? ?? 57 41 56 45` | 0 | N/A | RIFF with `WAVE` |
| FLAC | `66 4C 61 43` | 0 | N/A | `fLaC` |
| OGG | `4F 67 67 53` | 0 | N/A | `OggS` |
| PCAP | `D4 C3 B2 A1` (LE) / `A1 B2 C3 D4` (BE) | 0 | N/A | Network capture |
| PCAPNG | `0A 0D 0D 0A` | 0 | N/A | Section Header Block |

---

## Part 3: Carving Techniques

### 1. Header-Footer Carving
- Match known header signature, scan forward for known footer
- Extract everything between header and footer
- **Pro:** Accurate file boundaries when footer exists
- **Con:** Many formats lack footers; false positives from embedded headers
- **Examples:** JPEG (`FF D8 FF` → `FF D9`), PNG (header → IEND), GIF (header → `3B`), PDF (`%PDF-` → `%%EOF`)

### 2. Header-Max-Size Carving
- Match known header, extract up to configured maximum file size
- **Pro:** Works when no footer exists
- **Con:** Often captures trailing garbage; may truncate large files
- **Examples:** Foremost default mode, EXE/DLL files, BMP (can use embedded size field)

### 3. Structure-Aware Carving
- Parse internal file structure during carving to determine boundaries
- Validate structural integrity of carved data
- **Examples:**
  - JPEG: Decode MCU blocks, validate Huffman tables
  - ZIP: Parse local file headers + central directory
  - OLE/CFB: Parse FAT/directory entries for actual file size
  - PE: Parse section table for total image size
  - PDF: Parse cross-reference table for file structure
- **Pro:** Accurate file boundaries, validates carved output
- **Con:** Requires per-format parser; computationally expensive

### 4. Fragment Recovery (General)
- **Problem:** Garfinkel showed forensically important files have high fragmentation rates:
  - JPEG: 16% fragmented
  - Word documents: 17%
  - AVI: 22%
  - PST (Outlook): 58%
- Contiguous carving misses or corrupts fragmented files
- No general solution exists; all approaches are heuristic

### 5. Bifragment Gap Carving (Garfinkel & Metz, 2007)
- **Assumption:** File split into exactly two non-contiguous parts with a gap between them
- **Algorithm:**
  1. Identify header at cluster H
  2. Identify footer at cluster F
  3. For each possible gap start G (H < G < F):
     - For each possible gap size S:
       - Concatenate clusters [H..G-1] + [G+S..F]
       - Validate concatenated data using fast object validator
       - If valid → recovered file
- **Fast Object Validation:** Format-specific validators (JPEG decoding, ZIP CRC, OLE FAT parsing) quickly accept/reject candidate reconstructions
- **Limitation:** Only handles bifragmented files; exponential search space for n-fragment files

### 6. Smart Carving (Pal et al.)
- Not limited to bifragmented files
- Three phases:
  1. **Preprocessing:** Decompress/decrypt blocks if necessary
  2. **Collation:** Sort blocks by file type (using byte-frequency analysis)
  3. **Reassembly:** Place blocks in sequence using filesystem heuristics
- Uses heuristics about filesystem fragmentation behavior (NTFS, FAT allocation patterns)
- Basis for Adroit Photo Forensics commercial tool

### 7. RAM Carving
- Specific considerations for volatile memory dumps:
  - High noise from kernel pools, page tables, shared libraries → many false positives
  - Memory smearing during acquisition creates inconsistencies across pages
  - Integration with memory analysis frameworks (Volatility) essential
  - Plugins: `filescan`, `dumpfiles` contextualize carvings within process/cache mappings
  - Process memory regions more useful than full physical memory
- **Applicable artifacts:** Recently viewed images/documents, chat messages, URLs, passwords, cryptographic keys

### 8. Compressed Stream Carving
- bulk_extractor approach: probe every byte as potential compressed stream start
- Detect: gzip (`1F 8B`), zlib (`78 01/9C/DA`), bzip2 (`42 5A 68`), LZMA, deflate
- Decompress optimistically, recursively re-process decompressed data
- Finds embedded compressed data in unallocated space missed by standard carvers

### 9. Embedded File Carving
- Files within files:
  - **ZIP-based:** DOCX, XLSX, PPTX, ODP, ODT, EPUB, APK, JAR, AFF4
  - **OLE/CFB-based:** DOC, XLS, PPT, MSG, MSI, Thumbs.db, Jump Lists
  - **RIFF containers:** AVI, WAV, WebP
  - **ISO base media file format:** MP4, MOV, HEIF, AVIF
  - **EBML containers:** MKV, WebM
- Must recursively enter containers to identify inner content
- Container format identification → extraction → inner file identification

### 10. Validation After Carving
- **Format-specific validation:**
  - JPEG: Decode with libjpeg; check for complete scan
  - PNG: Verify CRC32 of each chunk
  - ZIP: Verify CRC32 of each file entry
  - PDF: Parse cross-reference table
  - PE: Validate section checksums
  - SQLite: Check page integrity, freelist consistency
- **Generic validation:**
  - File size sanity (not zero, not impossibly large)
  - Entropy analysis (detect all-zero or random-noise false positives)
  - Duplicate detection (hash-based deduplication)
  - Header/trailer consistency
- **Best practice:** Run carved files through format-specific parser; reject parse failures

---

## Part 4: Rust Ecosystem

### File Type Detection Crates

| Crate | Latest | Approach | `no_std` | Custom Matchers | Notes |
|-------|--------|----------|----------|----------------|-------|
| **`infer`** | 0.19.0 (2025-02) | Magic number signatures | Yes | Yes | Lightweight; port of Go `filetype`; most actively maintained |
| **`file-format`** | Active | Signatures + intelligent readers | No | No | Wide format coverage; rich metadata (name, media type, kind) |
| **`tree_magic_mini`** | Active | MIME tree traversal (FreeDesktop) | No | Via checkers | Fast (~150ns per check); maintained fork of `tree_magic` |
| **`tree_magic`** | Stale | MIME tree traversal | No | Via checkers | Original; GPL-licensed magic DB if embedded |
| **`filetypes`** | — | Magic numbers | — | — | Simpler/smaller |
| **`file_type`** | — | Signatures + extensions | — | — | Combines multiple data sources |
| **`tika-magic`** | — | Apache Tika rules | — | — | Apache 2.0 licensed |

### Forensic Crates

| Crate | Description |
|-------|-------------|
| **`forensic-rs`** | Framework to build forensic artifact analysis tools |
| **`zff`** | Z Forensic File Format — alternative to EWF/AFF for disk images |
| **`memprocfs`** | Physical memory analysis (live + dump files) |
| **`fat`** | FAT filesystem image analysis |
| **`yara-x`** | Pure Rust YARA implementation for pattern matching |
| **`evtx`** | Windows EVTX event log parser |
| **`notatin`** | Windows Registry hive parser |
| **`nt-hive`** | Another Windows Registry parser |
| **`lnk`** | Windows LNK shortcut parser |
| **`prefetch`** | Windows Prefetch file parser |

### Recommended Architecture for `forensic-signatures`

Based on this research, the `forensic-signatures` crate should:

1. **Signature Database Layer:**
   - Define all signatures as const byte slices with offset, header, optional footer, and max size
   - Use enum-based file type taxonomy (Category → Format → Version)
   - Support both BOF (beginning of file) and EOF (end of file) signatures
   - Support offset-based matching (e.g., TAR at offset 257, HEIF at offset 4)
   - Support wildcard bytes in signatures (e.g., RIFF `?? ?? ?? ??` WebP pattern)

2. **Identification Engine:**
   - Fast multi-pattern matching (Aho-Corasick for parallel header scan)
   - Container-aware detection (ZIP → check internal files for DOCX/XLSX/etc.)
   - Layered detection: magic bytes → structure validation → content analysis
   - `no_std` support for embedded/memory-constrained environments

3. **Carving Engine:**
   - Header-footer carving with configurable strategies per format
   - Header-max-size carving as fallback
   - Structure-aware carving for high-value formats (JPEG, PDF, ZIP, OLE, SQLite, REGF, EVTX)
   - Bifragment gap carving with pluggable validators
   - Compressed stream detection and decompression

4. **Validation Engine:**
   - Per-format validators (fast-reject invalid carved files)
   - Generic validators (size, entropy, duplicate detection)
   - Confidence scoring (high/medium/low based on validation depth)

---

## Appendix A: Source References

### Major Databases
1. libmagic / file(1): https://github.com/file/file
2. PhotoRec / TestDisk: https://github.com/cgsecurity/testdisk
3. Foremost: https://github.com/korczis/foremost
4. 010 Editor Templates: https://www.sweetscape.com/010editor/repository/templates/
5. Scalpel: https://github.com/sleuthkit/scalpel
6. bulk_extractor: https://github.com/simsong/bulk_extractor
7. Binwalk: https://github.com/ReFirmLabs/binwalk
8. DROID / PRONOM: https://github.com/digital-preservation/droid
9. Apache Tika: https://github.com/apache/tika
10. Gary Kessler: https://filesig.search.org/
11. Wikipedia: https://en.wikipedia.org/wiki/List_of_file_signatures

### Key Academic Papers
- Garfinkel, S. "Carving contiguous and fragmented files with fast object validation" (DFRWS 2007)
- Garfinkel, S. "Digital media triage with bulk data analysis and bulk_extractor" (Computers and Security 32, 2013)
- Pal, A. & Memon, N. "The evolution of file carving" (IEEE Signal Processing 26(2), 2009)
- Richard, G. & Roussev, V. "Scalpel: A Frugal, High Performance File Carver" (DFRWS 2005)

### Format Specifications
- REGF: https://github.com/libyal/libregf (documentation directory)
- EVTX: https://github.com/libyal/libevtx
- Prefetch: https://github.com/libyal/libscca
- ESE/EDB: https://github.com/libyal/libesedb
- EWF (E01): https://github.com/libyal/libewf
- VHD/VHDX: https://github.com/libyal/libvhdi
- PST/OST: https://github.com/libyal/libpff
- LNK: https://github.com/libyal/liblnk
- OLE/CFB: https://github.com/libyal/libolecf
- QCOW2: https://www.qemu.org/docs/master/interop/qcow2.html
- SQLite: https://www.sqlite.org/fileformat.html
- OpenPGP: RFC 4880, RFC 9580
- BitLocker: https://forensics.wiki/bitlocker_disk_encryption/
- LUKS: https://gitlab.com/cryptsetup/cryptsetup/-/wikis/LUKS-standard/on-disk-format.pdf
