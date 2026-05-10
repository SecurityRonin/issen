# Windows Forensic Artifact Parser Libraries — Deep Research

**Date**: 2026-03-23
**Purpose**: Evaluate available libraries for parsing Windows forensic artifacts in Issen

---

## Table of Contents

1. [Registry Hives](#1-windows-registry-hives)
2. [Prefetch Files](#2-prefetch-files)
3. [Amcache](#3-amcache)
4. [ShimCache / AppCompatCache](#4-shimcache--appcompatcache)
5. [SRUM (ESE Database)](#5-srum-ese-database)
6. [BAM/DAM](#6-bamdam)
7. [UserAssist](#7-userassist)
8. [Scheduled Tasks](#8-scheduled-tasks)
9. [Windows Services](#9-windows-services)
10. [LNK Files](#10-lnk-files)
11. [Jumplist Files](#11-jumplist-files)
12. [Major Rust DFIR Tools](#major-rust-dfir-tools)
13. [LOLRMM.io](#lolrmmio)
14. [Format Documentation Master List](#format-documentation-master-list)
15. [License Compatibility](#license-compatibility-summary)
16. [Strategic Recommendations](#strategic-recommendations-for-issen)

---

## 1. Windows Registry Hives

**Artifacts**: SAM, SYSTEM, SOFTWARE, NTUSER.DAT, UsrClass.dat
**Use**: Parse keys, values, timestamps; foundation for ShimCache, BAM/DAM, UserAssist, Services

### Rust Crates

| Crate | Version | License | Downloads | Last Updated | Repo Stars | Notes |
|-------|---------|---------|-----------|--------------|------------|-------|
| `notatin` | 1.0.1 | **Apache-2.0** | 34,860 | 2023-08-18 | 41 | Stroz Friedberg/LevelBlue. Stable v1.0. Forensics-focused. |
| `nt_hive2` | 4.2.4 | GPL-3.0 | 33,341 | 2025-07-27 | — | Part of dfir-toolkit. Most actively developed. GPL is restrictive. |
| `nt-hive` | 0.3.0 | GPL-2.0+ | 15,626 | 2025-01-21 | 53 | ColinFinck. Originally for bootloader. Supports basic mods. |
| `frnsc-hive` | 0.13.4 | **MIT** | 7,918 | 2025-02-18 | — | ForensicRS ecosystem. Implements `RegistryReader` trait. |
| `forensic-rs` | 0.13.1 | **MIT** | 36,846 | 2025-02-18 | 31 | Core framework. Pushed 2026-03-19. Active. |

### C/C++ Libraries

| Library | License | Status | Notes |
|---------|---------|--------|-------|
| `libregf` (libyal) | LGPLv3+ | Alpha | C library for REGF format. No Rust FFI bindings exist. |
| DFIR-ORC (ANSSI) | LGPL-2.1 | Active | C++ collection framework, 434 stars. Collection only, not parsing. |

### Python Reference Implementations

| Tool | Notes |
|------|-------|
| `python-registry` (williballenthin) | Pure Python, most widely used reference. Used by Mandiant. |
| `regipy` (mkorman90) | Python 3, plugin system, transaction log support, header validation. |
| `RegRippy` (Airbus CERT) | Python 3, alternative to RegRipper, built on python-registry. |

### Format Documentation

| Resource | URL |
|----------|-----|
| msuhanov/regf spec (best community spec, versions 1.1-1.6) | https://github.com/msuhanov/regf |
| libyal/libregf asciidoc | https://github.com/libyal/libregf/blob/main/documentation/ |
| Google Project Zero "Windows Registry Adventure" (2024) | https://googleprojectzero.blogspot.com/2024/12/the-windows-registry-adventure-5-regf.html |
| NIST Registry Forensic Tool Specification | https://www.nist.gov/document/windows-registry-forensic-tool-specification-draft-2-version-10 |
| forensics.wiki | https://forensics.wiki/windows_nt_registry_file_(regf)/ |

### Recommendation

- **Primary**: `notatin` — Apache-2.0, v1.0 stable, forensics-focused, by Stroz Friedberg
- **Alternative**: `forensic-rs` + `frnsc-hive` — MIT, modular framework, actively maintained
- **Avoid**: `nt-hive` / `nt_hive2` due to GPL licensing

---

## 2. Prefetch Files

**Artifact**: `.pf` files in `C:\Windows\Prefetch\`
**Use**: Execution evidence with timestamps, run count, file references

### Rust Crates

| Crate | Version | License | Downloads | Last Updated | Notes |
|-------|---------|---------|-----------|--------------|-------|
| `frnsc-prefetch` | 0.13.3 | **MIT** | 9,810 | 2025-02-19 | Pure Rust, all platforms, ForensicRS ecosystem. |
| `libprefetch` | 0.1.1 | MIT | 4,464 | ~2018 | **Abandoned** (7+ years old). |

### C Libraries

| Library | License | Notes |
|---------|---------|-------|
| `libscca` (libyal) | LGPLv3+ | Best format documentation. By Joachim Metz. |

### Python Reference

| Tool | Notes |
|------|-------|
| `windowsprefetch` (PoorBillionaire) | Supports versions 17/23/26/30. |
| Crow-Eye Prefetch Analyzer | Supports through Windows 11 (version 31). |

### Format Documentation

| Resource | URL |
|----------|-----|
| libyal/libscca format spec (most detailed) | https://github.com/libyal/libscca/blob/main/documentation/ |
| forensics.wiki | https://forensics.wiki/windows_prefetch_file_format/ |

**Format versions**: 17 (XP), 23 (Vista/7), 26 (8.1), 30 (Win10), 31 (Win11)
**Note**: Windows 10+ uses XPRESS Huffman compression (MAM signature before SCCA header)

### Recommendation

- **Primary**: `frnsc-prefetch` (MIT, pure Rust, actively maintained)

---

## 3. Amcache

**Artifact**: `C:\Windows\AppCompat\Programs\Amcache.hve` (REGF hive)
**Use**: Program installation/execution history, device tracking

### Rust Crates

| Crate | Version | License | Downloads | Last Updated | Notes |
|-------|---------|---------|-----------|--------------|-------|
| `frnsc-amcache` | 0.13.0 | **MIT** | 788 | 2025-02-18 | Dedicated Amcache parser. InventoryApplication*, InventoryDevice*, InventoryDriver*. |

### Other Rust Tools

- **Artemis** — MIT, full Amcache parser, pushed 2026-03-23
- **Chainsaw** — GPL-3.0, enriches Shimcache timelines with Amcache data

### Reference Implementations

| Tool | Language | Notes |
|------|----------|-------|
| AmcacheParser (Eric Zimmerman) | C# | Reference implementation |
| Velociraptor `Windows.System.Amcache` | VQL | Raw hive parsing |

### Format Notes

- Standard REGF hive file, not mounted by Windows API — must parse raw file
- Key paths: `Root\InventoryApplicationFile`, `Root\InventoryApplication`, etc.
- Tracks: first execution, installation paths, SHA1 hashes, file sizes, link dates

### Recommendation

- **Primary**: `frnsc-amcache` (MIT, dedicated parser)
- **Alternative**: Registry parser + custom key-path extraction logic

---

## 4. ShimCache / AppCompatCache

**Artifact**: Binary value in SYSTEM registry hive
**Path**: `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache\AppCompatCache`
**Use**: Application execution/browsing evidence

### Rust Crates

No standalone crate exists. Covered by:
- **Artemis** — MIT, includes ShimCache parser
- **Chainsaw** — GPL-3.0, ShimCache timeline creation

### Reference Implementations

| Tool | Language | Notes |
|------|----------|-------|
| ShimCacheParser (Mandiant) | Python 2 | Proof-of-concept. **Python 2 only (EOL)**. https://github.com/mandiant/ShimCacheParser |
| AppCompatCacheParser (Eric Zimmerman) | C# | Supports XP through Windows 11. |
| appcompatprocessor | Python | Fork with additional processing. |

### Format Notes

- Binary data format varies significantly by Windows version:
  - XP: Different structure entirely
  - Vista/2003/2008: Contains file size, last modified time
  - Win7: Adds insertion flags
  - Win8+: Changed header format
  - Win10/11: Further modifications
- InsertFlag bit indicates execution (but unreliable for definitive conclusions)
- Files browsed in Explorer (not executed) may also appear (Vista+)
- Survives file deletion from disk

### Recommendation

- **Approach**: Use registry parser (`notatin`) to extract raw binary value, implement custom binary format parser
- **Reference**: Mandiant `ShimCacheParser.py` for format logic, **Artemis source** for Rust reference

---

## 5. SRUM (ESE Database)

**Artifact**: `C:\Windows\System32\sru\SRUDB.dat`
**Format**: Extensible Storage Engine (ESE) database
**Use**: Network usage per app, CPU/memory usage, energy consumption

### Rust Crates / Tools

| Crate/Tool | License | Status | Notes |
|------------|---------|--------|-------|
| ForensicRS ESEDB reader | MIT | **Under development** | Pure Rust, cross-platform, not yet stable |
| `esedb-rs` (wfraser) | Unlicensed | **Abandoned** | Proof-of-concept, last pushed 2020, 6 stars |
| Artemis | MIT | Active | Full SRUM + ESE parser, pushed 2026-03-23 |

### C Libraries

| Library | License | Status | Notes |
|---------|---------|--------|-------|
| `libesedb` (libyal) | LGPLv3+ | Active | Most mature ESE parser. Release 20240420. Could FFI via bindgen. |

### Python / C# Reference

| Tool | Language | Notes |
|------|----------|-------|
| srum-dump (MarkBaggett) | Python | Converts SRUM to Excel. https://github.com/MarkBaggett/srum-dump |
| ese-analyst (MarkBaggett) | Python | General ESE forensics tools. |
| dissect.esedb (Fox-IT) | Python | Part of dissect framework. |
| SrumECmd (Eric Zimmerman) | C# | Command-line SRUM parser. |

### Format Notes

- ESE database used by: Active Directory, Exchange, Windows Search, SRUM, UAL
- Typically contains 60+ days of evidence
- Records persist even after application uninstall/deletion
- Tables: NetworkUsage, NetworkConnections, EnergyUsage, AppTimeline, etc.
- File is usually locked while system is running (need raw NTFS or offline access)

### Recommendation

- **Short-term**: FFI bindings to `libesedb` via `bindgen` (most mature option)
- **Medium-term**: ForensicRS ESEDB reader when stable, or extract from Artemis source
- **Reference**: Artemis source for pure Rust ESE parsing approach

---

## 6. BAM/DAM

**Artifact**: Values in SYSTEM registry hive
**Paths**:
- BAM: `HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\{SID}`
- DAM: `HKLM\SYSTEM\CurrentControlSet\Services\dam\State\UserSettings\{SID}`

**Use**: Execution timestamps with user attribution

### Rust Crates

No standalone crate. **Artemis** includes BAM parsing (MIT).

### Format Notes

- Windows 10 Fall Creators Update (1709) and later only
- Binary value format: 8-byte Windows FILETIME per executable path
- Entries clear on reboot or after 7 days
- Executables on removable media are NOT recorded
- **Provides user attribution** (SID-specific) — unlike Prefetch
- Each value name = full executable path, value data = FILETIME timestamp

### Velociraptor Reference

- `Windows.Forensics.Bam` artifact — VQL reference implementation

### Recommendation

- **Approach**: Registry parser + FILETIME parsing (trivial implementation)
- Total implementation effort: ~50-100 lines of Rust

---

## 7. UserAssist

**Artifact**: Values in NTUSER.DAT hive
**Path**: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`
**Use**: GUI application execution tracking

### Rust Crates

No standalone crate. **Artemis** includes UserAssist parsing (MIT).

### Format Notes

- Value names are **ROT13 encoded** (trivial to decode)
- GUIDs:
  - `{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}` = executable file execution
  - `{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}` = shortcut file execution
- Binary value structure (Win7+, 72 bytes):
  - Offset 0: Session (4 bytes)
  - Offset 4: Run count (4 bytes)
  - Offset 8: Focus count (4 bytes)
  - Offset 12: Focus time (4 bytes, milliseconds)
  - Offset 60: Last execution time (8 bytes, FILETIME)
- Earlier Windows versions use 16-byte structure

### Reference

- 4n6k blog: https://www.4n6k.com/2013/05/userassist-forensics-timelines.html
- Velociraptor has built-in UserAssist artifact

### Recommendation

- **Approach**: Registry parser + ROT13 decode + binary struct parsing
- Total implementation effort: ~100-150 lines of Rust

---

## 8. Scheduled Tasks

**Artifacts**:
- Modern (Vista+): XML files in `C:\Windows\System32\Tasks\`
- Legacy (XP): Binary `.job` files in `C:\Windows\Tasks\`

**Use**: Persistence mechanism detection

### Rust Crates

No standalone crate. **Artemis** includes Windows Tasks parsing (MIT).

### Format Notes

- Modern XML tasks use standard XML format — parseable with any XML library
- Key XML elements: `<Exec>/<Command>`, `<Triggers>`, `<Principal>`, `<Actions>`
- Legacy `.job` binary format documented by Harlan Carvey / SANS blog
- Hidden tasks possible via Security Descriptor manipulation

### Velociraptor Reference

- `Windows.System.TaskScheduler` artifact

### Recommendation

- **Approach**: `quick-xml` or `roxmltree` for modern XML tasks, custom binary parser for `.job`
- Focus on XML tasks first (vast majority of modern Windows systems)

---

## 9. Windows Services

**Artifact**: Keys in SYSTEM registry hive
**Path**: `HKLM\SYSTEM\CurrentControlSet\Services\{ServiceName}`
**Use**: Service configurations, RAT/persistence detection

### Format Notes

- Standard registry keys with well-known value names:
  - `Start` (DWORD): 0=Boot, 1=System, 2=Automatic, 3=Manual, 4=Disabled
  - `Type` (DWORD): Service type flags
  - `ImagePath` (REG_EXPAND_SZ): Executable path
  - `DisplayName`, `Description` (REG_SZ)
  - `ObjectName` (REG_SZ): Account the service runs as
- No special binary format — pure registry enumeration

### Recommendation

- **Approach**: Registry parser to enumerate `Services` subkeys and extract values
- No special crate needed — direct registry access

---

## 10. LNK Files

**Artifact**: `.lnk` files (Windows shortcuts)
**Use**: Target paths, timestamps, machine IDs, volume serial numbers

### Rust Crates

| Crate | Version | License | Downloads | Last Updated | Notes |
|-------|---------|---------|-----------|--------------|-------|
| `lnk` | 0.6.3 | **MIT** | 46,572 | 2025-09-02 | Read/write. Most downloaded LNK crate. |
| `lnk_parser` | 0.4.3 | **MIT** | 11,614 | 2026-02-17 | By AbdulRhman Alfaifi. JSON/CSV output. Forensics-focused. Most recently updated. |
| `parselnk` | — | — | — | — | Pure safe Rust. Less documented. |

### C Libraries

| Library | License | Notes |
|---------|---------|-------|
| `liblnk` (libyal) | LGPLv3+ | Alpha status. No Rust bindings. |

### Format Documentation

| Resource | URL |
|----------|-----|
| MS-SHLLINK (official Microsoft spec) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/ |
| Kaitai Struct machine-readable spec | https://formats.kaitai.io/windows_lnk_file/ |
| libyal/liblnk documentation | https://github.com/libyal/liblnk/blob/main/documentation/ |

### Recommendation

- **Primary**: `lnk_parser` (MIT, forensics-focused, actively updated, same author as `jumplist_parser`)
- **Alternative**: `lnk` crate (MIT, more downloads, also supports writing)

---

## 11. Jumplist Files

**Artifacts**:
- `%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations\*.automaticDestinations-ms`
- `%APPDATA%\Microsoft\Windows\Recent\CustomDestinations\*.customDestinations-ms`

**Use**: Recent/frequent file access evidence per application

### Rust Crates

| Crate | Version | License | Downloads | Last Updated | Notes |
|-------|---------|---------|-----------|--------------|-------|
| `jumplist_parser` | 0.1.0 | **MIT** | ~1,000 | Recent | By AbdulRhman Alfaifi. Both auto and custom destinations. |

### Format Notes

- AutomaticDestinations: OLE Compound Files containing LNK streams + DestList stream
- CustomDestinations: Raw LNK entries grouped by category
- AppID (hash in filename) maps to application name
- DestList contains: access count, timestamps, entry numbers, path data

### Recommendation

- **Primary**: `jumplist_parser` (MIT, dedicated parser, same author as `lnk_parser`)

---

## Major Rust DFIR Tools

### Artemis — puffyCid/artemis

| Attribute | Value |
|-----------|-------|
| Stars | 102 |
| License | **MIT** |
| Language | Rust |
| Last pushed | **2026-03-23** (today) |
| Forks | 13 |

**Windows artifact coverage** (all relevant to Issen):
Prefetch, EventLogs, Registry, UserAssist, ShimCache, ShellBags, Amcache, Shortcuts (LNK), UsnJrnl, BITS, SRUM, Windows Search, Tasks, Services, Jumplists, RecycleBin, WMI Persist, Outlook, MFT

**Key features**:
- Embedded JavaScript runtime (Boa) for custom artifact scripts
- Timeline output compatible with Timesketch
- Cross-platform (Windows, macOS, Linux, FreeBSD)
- Architecture: `artifacts/` directory grouped by OS, each artifact in own module

**Value for Issen**: MIT licensed, comprehensive coverage, actively maintained. Individual parser modules could be extracted or used as reference implementations, especially for artifacts lacking standalone crates (ShimCache, BAM/DAM, UserAssist, SRUM, Tasks, Services).

### Chainsaw — WithSecureLabs/chainsaw

| Attribute | Value |
|-----------|-------|
| Stars | 3,483 |
| License | GPL-3.0 |
| Language | Rust |
| Last pushed | 2026-03-02 |

**Capabilities**: Sigma rule hunting, Shimcache/Amcache timelines, SRUM analysis, MFT/registry dumping
**Uses**: `evtx` crate by @OBenamram for event log parsing
**License warning**: GPL-3.0 prevents library reuse in non-GPL projects

### Hayabusa — Yamato-Security/hayabusa

| Attribute | Value |
|-----------|-------|
| Stars | 3,070 |
| License | AGPL-3.0 |
| Language | Rust |
| Last pushed | 2026-03-21 |

**Focus**: Windows event log analysis with Sigma v2.0 support (4,000+ rules)
**License warning**: AGPL-3.0 is very restrictive — not usable as library
**Value**: Detection rules reference, not parser extraction

### evtx crate (OBenamram)

Pure Rust Windows Event Log parser. Used by both Chainsaw and Hayabusa. High download count on crates.io.

---

## LOLRMM.io

| Attribute | Value |
|-----------|-------|
| GitHub | https://github.com/magicsword-io/LOLRMM |
| Stars | 320 |
| License | **Apache-2.0** |
| Last pushed | 2026-03-13 |
| YAML files | **294** (one per RMM tool) |

### YAML Schema

```yaml
Name: <tool name>           # e.g., "AnyDesk"
Category: RMM
Description: |
    <multi-line description>
Author: <contributors>
Created: '<date>'
LastModified: '<date>'
Details:
    Website: <url>
    PEMetadata:
        - Filename: <exe name>
          OriginalFileName: <original name>
          Description: <PE description>
          Product: <product name>
    Privileges: <User|Admin>
    Free: <true|false>
    Verification: <true|false>
    SupportedOS:
        - <OS list>
    Capabilities:
        - <capability list: File Transfer, Remote Control, GUI Support, etc.>
    Vulnerabilities:
        - <CVE URLs>
    InstallationPaths:
        - <glob paths, e.g., C:\Program Files\AnyDesk\*>
Artifacts:
    Disk:
        - File: '<path with %env% vars>'
          Description: '<what the file contains>'
          OS: <Windows|Linux|Mac>
    EventLog:
        - EventID: <number>
          ProviderName: '<provider>'
          LogFile: '<log file name>'
    Registry:
        - Path: '<registry path>'
          Description: '<description>'
    Network:
        - Description: '<description>'
          Domains:
              - <domain list>
          Ports:
              - <port list>
Detections:
    - Sigma: <URL to sigma rule>
      Description: '<rule description>'
References:
    - <reference URLs>
```

---

## Format Documentation Master List

| Artifact | Primary Specification | URL |
|----------|----------------------|-----|
| Registry (REGF) | msuhanov/regf | https://github.com/msuhanov/regf |
| Prefetch (SCCA) | libyal/libscca docs | https://github.com/libyal/libscca/blob/main/documentation/ |
| LNK (Shell Link) | MS-SHLLINK | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/ |
| ESE Database | libyal/libesedb docs | https://github.com/libyal/libesedb/blob/main/documentation/ |
| Amcache | REGF + key paths | AmcacheParser source |
| ShimCache | Mandiant ShimCacheParser | https://github.com/mandiant/ShimCacheParser |
| BAM/DAM | FILETIME in registry value | Velociraptor `Windows.Forensics.Bam` |
| UserAssist | ROT13 + binary struct | https://www.4n6k.com/2013/05/userassist-forensics-timelines.html |
| Scheduled Tasks | XML / .job binary | MS XML schema / SANS blog |
| Jumplist | OLE CF + LNK + DestList | MS-CFB + LNK spec |

---

## License Compatibility Summary

Target: **Apache-2.0 or MIT** for Issen

| Crate/Tool | License | Compatible? |
|------------|---------|-------------|
| `forensic-rs` + all `frnsc-*` crates | **MIT** | YES |
| `notatin` | **Apache-2.0** | YES |
| `lnk` | **MIT** | YES |
| `lnk_parser` | **MIT** | YES |
| `jumplist_parser` | **MIT** | YES |
| Artemis | **MIT** | YES (reference/extraction) |
| LOLRMM data | **Apache-2.0** | YES |
| `nt-hive` | GPL-2.0+ | NO — copyleft |
| `nt_hive2` | GPL-3.0 | NO — strong copyleft |
| Chainsaw | GPL-3.0 | NO — strong copyleft |
| Hayabusa | AGPL-3.0 | NO — very restrictive |
| `libesedb` (C, FFI) | LGPLv3+ | MAYBE — dynamic linking OK, static NO |

---

## Strategic Recommendations for Issen

### Tier 1 — Direct Crate Dependencies (MIT/Apache-2.0, ready to use)

| Artifact | Crate | License | Maturity |
|----------|-------|---------|----------|
| Registry Hives | `notatin` | Apache-2.0 | Stable (v1.0) |
| Prefetch | `frnsc-prefetch` | MIT | Pre-1.0 but functional |
| Amcache | `frnsc-amcache` | MIT | Pre-1.0 but functional |
| LNK Files | `lnk_parser` | MIT | Active development |
| Jumplists | `jumplist_parser` | MIT | Early (v0.1) |

### Tier 2 — Implement Using Registry Parser + Format Knowledge

| Artifact | Approach | Effort | Reference |
|----------|----------|--------|-----------|
| ShimCache | `notatin` + custom binary parser | Medium | Mandiant ShimCacheParser, Artemis source |
| BAM/DAM | `notatin` + FILETIME parse | Low (~50-100 LOC) | Velociraptor BAM artifact |
| UserAssist | `notatin` + ROT13 + binary struct | Low (~100-150 LOC) | 4n6k blog, Artemis source |
| Services | `notatin` + key enumeration | Low (~50 LOC) | Standard registry values |
| Scheduled Tasks | `quick-xml` for XML tasks | Low-Medium | Velociraptor TaskScheduler |

### Tier 3 — Requires Significant Work

| Artifact | Approach | Effort | Notes |
|----------|----------|--------|-------|
| SRUM (ESE DB) | FFI to `libesedb` OR extract from Artemis | High | No stable pure-Rust ESE parser yet |

### Key Reference Repository

**Artemis** (`puffyCid/artemis`) — MIT licensed, pushed today, covers ALL 11 artifact types listed above. Can extract individual parser modules as starting points, especially for Tier 2 and Tier 3 artifacts. This is the single most valuable reference codebase for Issen's parser development.
