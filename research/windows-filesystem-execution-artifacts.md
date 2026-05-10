# Windows Filesystem-Based Execution Evidence Artifacts

Comprehensive catalog of file-based execution artifacts on Windows systems. Registry artifacts are excluded; see the companion registry artifact catalog. All paths use `%` environment variable notation where applicable.

**Last updated:** 2026-04-13  
**Scope:** Windows Vista through Windows 11 (noted per artifact)

---

## Table of Contents

1. [Prefetch Files (.pf)](#1-prefetch-files-pf)
2. [LNK / Shell Link Files](#2-lnk--shell-link-files)
3. [Jump Lists — AutomaticDestinations](#3-jump-lists--automaticdestinations)
4. [Jump Lists — CustomDestinations](#4-jump-lists--customdestinations)
5. [Amcache.hve](#5-amcachehve)
6. [RecentFileCache.bcf (Windows 7 only)](#6-recentfilecachebcf-windows-7-only)
7. [ShimCache / AppCompatCache (file-persisted portion)](#7-shimcache--appcompatcache-file-persisted-portion)
8. [SRUM Database (SRUDB.dat)](#8-srum-database-srudbdat)
9. [Windows Timeline — ActivitiesCache.db](#9-windows-timeline--activitiescachedb)
10. [Windows Search Database (Windows.edb / Windows.db)](#10-windows-search-database-windowsedb--windowsdb)
11. [Thumbnail Cache (thumbcache_*.db)](#11-thumbnail-cache-thumbcache_db)
12. [Recycle Bin ($I / $R Files)](#12-recycle-bin-i--r-files)
13. [USN Journal ($UsnJrnl:$J)](#13-usn-journal-usnjrnlj)
14. [NTFS Master File Table ($MFT)](#14-ntfs-master-file-table-mft)
15. [Volume Shadow Copies (VSS)](#15-volume-shadow-copies-vss)
16. [Windows Notification Database (wpndatabase.db)](#16-windows-notification-database-wpndatabasedb)
17. [PowerShell History File (ConsoleHost_history.txt)](#17-powershell-history-file-consolehost_historytxt)
18. [Startup Folder Files](#18-startup-folder-files)
19. [Windows Event Log Channels (EVTX)](#19-windows-event-log-channels-evtx)
20. [BAM / DAM Registry-Backed Execution Records](#20-bam--dam-registry-backed-execution-records)
21. [UserAssist (NTUSER.DAT-backed, file-resident)](#21-userassist-ntuserdat-backed-file-resident)

---

## 1. Prefetch Files (.pf)

| Field | Value |
|-------|-------|
| **Location** | `C:\Windows\Prefetch\<EXECNAME>-<HASH>.pf` |
| **Format** | Proprietary binary. File header 84 bytes. 4-byte version at offset 0, 4-byte magic `SCCA` (0x53 0x43 0x43 0x41) at offset 4. Windows 10+ files are MAM-compressed (magic `0x4D 0x4D 0x41`) using Microsoft XPRESS Huffman (LZXPRESS). |
| **Version Numbers** | v17 = Win XP/2003; v23 = Win Vista/7/2008/2012; v26 = Win 8.1; v30 = Win 10; v31 = Win 11 (2024) |
| **Key Fields** | Executable name (max 29 UTF-16 chars), run count, last 8 run timestamps (Win 8+), volume device path, volume serial number, referenced file/directory list (Section C: UTF-16 filename strings; Section D: volume info subsections), file metrics array, trace chain array |
| **Forensic Value** | Proves execution of named binary; up to 8 last-run timestamps with millisecond precision; hash encodes launch path (different launch paths → different .pf files); DLL/file reference list shows what resources the process loaded; max 128 entries on Win 7/XP, 1024 on Win 8+ |
| **OS Scope** | Windows XP – Windows 11 (enabled by default on desktop; disabled by default on Server SKUs) |
| **Data Scope** | System (per-executable, not per-user) |
| **Decoder Approach** | Eric Zimmerman's **PECmd** (`PECmd.exe -f <file.pf> --csv`); libscca library; Velociraptor artifact `Windows.Forensics.Prefetch`; manually: decompress MAM header on Win 10+, then parse 84-byte file header, sections A–D |
| **MITRE ATT&CK** | T1059 (Command and Scripting Interpreter), T1036 (Masquerading) — absence after execution indicates possible anti-forensic deletion |
| **References** | [forensics.wiki/prefetch](https://forensics.wiki/prefetch/); [libscca format spec](https://github.com/libyal/libscca/blob/main/documentation/Windows%20Prefetch%20File%20(PF)%20format.asciidoc); [Magnet Forensics](https://www.magnetforensics.com/blog/forensic-analysis-of-prefetch-files-in-windows/); [SANS ISC Diary 29168](https://isc.sans.edu/diary/29168) |

---

## 2. LNK / Shell Link Files

| Field | Value |
|-------|-------|
| **Location** | Per-user Recent: `%APPDATA%\Microsoft\Windows\Recent\*.lnk`; Desktop: `%USERPROFILE%\Desktop\*.lnk`; Startup: `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\*.lnk`; Common Startup: `%ProgramData%\Microsoft\Windows\Start Menu\Programs\StartUp\*.lnk`; arbitrary paths where shortcuts are created |
| **Format** | MS-SHLLINK binary format (MS-SHLLINK spec). Mandatory 76-byte `SHELL_LINK_HEADER`. Magic `0x4C 00 00 00` at offset 0; CLSID `00021401-0000-0000-C000-000000000046` at offset 4. Optional structures: Shell Item ID List, Link Info block, String Data block, Extra Data blocks. |
| **Key Fields** | Target path (local and/or network UNC), target file size at time of last access, target creation/access/modification timestamps (3 × 8-byte FILETIME — snapshot of target before last open), LNK file own creation/modification timestamps, drive type (fixed/removable/network), drive serial number, volume label, NetBIOS machine name, Distributed Link Tracker Object ID (contains MAC address of originating host as GUID droid), relative path string, working directory, command-line arguments, icon location |
| **Forensic Value** | LNK creation time = first access of target on this system; LNK modification time = most recent access; 6 timestamps total (3 for LNK file itself + 3 target MAC snapshots); volume serial and drive type identify removable or network media; MAC address in Object ID Extra Data block identifies originating host; target path persists even if target file is deleted; max ~149 LNK files in Recent folder (pre-Win 10) or 20 per file type (Win 10+) |
| **OS Scope** | Windows 95 – Windows 11 |
| **Data Scope** | User (NTUSER.DAT-adjacent; files live in user profile) |
| **Decoder Approach** | Eric Zimmerman's **LECmd** (`LECmd.exe -f <file.lnk>`); liblnk library; Autopsy; FTK |
| **MITRE ATT&CK** | T1547.001 (Boot/Logon Autostart via Startup folder LNKs), T1070.004 (File Deletion — deleted targets still leave LNK), T1091 (Replication Through Removable Media) |
| **References** | [liblnk format spec](https://github.com/libyal/liblnk/blob/main/documentation/Windows%20Shell%20Link%20(.lnk)%20format.asciidoc); [forensics.wiki/lnk](https://forensics.wiki/lnk/); [Magnet LNK profile](https://www.magnetforensics.com/blog/forensic-analysis-of-lnk-files/); [ThedfirSpot](https://www.thedfirspot.com/post/a-lnk-to-the-past-utilizing-lnk-files-for-your-investigations) |

---

## 3. Jump Lists — AutomaticDestinations

| Field | Value |
|-------|-------|
| **Location** | `%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations\<AppID>.automaticDestinations-ms` |
| **Format** | Microsoft Compound File Binary (CFB / OLE2) format. Contains numbered SHLLINK streams (one per accessed file) plus a `DestList` stream acting as an MRU list. AppID is a 16-character hex string derived from the application's full path hash. |
| **Key Fields** | AppID (application identifier), DestList stream entries (MRU order, access count, pin status, NetBIOS hostname, volume GUID, file ID / MFT reference, target timestamps, target path), embedded LNK entries (all LNK fields per entry) |
| **Forensic Value** | Documents which files a specific application opened, in MRU order; survives file deletion of targets; AppID is universal across Windows installs, enabling attribution to specific applications; entry timestamps are preserved even after application uninstall |
| **OS Scope** | Windows 7 – Windows 11 |
| **Data Scope** | User |
| **Decoder Approach** | Eric Zimmerman's **JLECmd** (`JLECmd.exe -f <file>`); JumpList Explorer GUI; Autopsy; Cyber Triage |
| **MITRE ATT&CK** | T1059 (execution evidence), T1552.001 (Credentials in Files — can show what document files were opened) |
| **References** | [Jump Lists forensics wiki](https://forensics.wiki/jump_lists/); [Cyber Triage 2025 guide](https://www.cybertriage.com/blog/jump-list-forensics-2025/); [JLECmd GitHub](https://github.com/EricZimmerman/JLECmd); [artifacts-kb](https://artifacts-kb.readthedocs.io/en/latest/sources/windows/JumpLists.html) |

---

## 4. Jump Lists — CustomDestinations

| Field | Value |
|-------|-------|
| **Location** | `%APPDATA%\Microsoft\Windows\Recent\CustomDestinations\<AppID>.customDestinations-ms` |
| **Format** | Sequential packed MS-SHLLINK binary structures (not CFB). LNK entries are laid out sequentially. May include application-specific custom metadata blocks. |
| **Key Fields** | AppID, sequentially packed LNK entries (each with full LNK metadata), application-defined custom data blocks |
| **Forensic Value** | Records files pinned by users to taskbar or Start Menu; may contain application-specific metadata not present in AutomaticDestinations; entries are user-intentional (pinned) rather than just access-based |
| **OS Scope** | Windows 7 – Windows 11 |
| **Data Scope** | User |
| **Decoder Approach** | Eric Zimmerman's **JLECmd**; liblnk-based parsers; manual parsing requires sequentially reading SHLLINK structures |
| **MITRE ATT&CK** | T1547.001 (persistence via pinned items), T1059 |
| **References** | [forensics.wiki/jump_lists](https://forensics.wiki/jump_lists/); [Nasbench Medium article](https://nasbench.medium.com/windows-forensics-analysis-windows-artifacts-part-ii-71b8fa68d8a1) |

---

## 5. Amcache.hve

| Field | Value |
|-------|-------|
| **Location** | `C:\Windows\AppCompat\Programs\Amcache.hve` (registry hive file, not the active registry) |
| **Format** | Windows NT Registry File (REGF hive). Key structure under `Root\InventoryApplicationFile\` (Win 10+) or `Root\File\` (Win 8/8.1). Each subkey represents one scanned executable. |
| **Key Fields** | Full file path (`LowerCaseLongPath`), SHA-1 hash of first ~31 MB of file (`FileId` field, with leading four zeroes stripped), file size, PE link date (compile timestamp), publisher, product name, product version, first execution timestamp (via key last-write time), OS install flag |
| **Forensic Value** | SHA-1 hash enables VirusTotal lookup even for deleted files; records presence (not always confirmed execution) of executables including those run from USB or network shares that no longer exist; persists after application uninstall; `ProgramDataUpdater` scheduled task runs at 00:30 daily and can trigger scans without user execution |
| **OS Scope** | Windows 8 – Windows 11 (replaces RecentFileCache.bcf from Win 7) |
| **Data Scope** | System |
| **Decoder Approach** | Eric Zimmerman's **AmcacheParser** (`AmcacheParser.exe -f Amcache.hve --csv`); Registry Explorer with Amcache plugin; Velociraptor `Windows.Forensics.Amcache`; KAPE |
| **MITRE ATT&CK** | T1059, T1553.002 (Code Signing — publisher field), T1036 (Masquerading — file name vs hash mismatch) |
| **References** | [Magnet ShimCache vs Amcache](https://www.magnetforensics.com/blog/shimcache-vs-amcache-key-windows-forensic-artifacts/); [Securelist Amcache deep dive](https://securelist.com/amcache-forensic-artifact/117622/); [SANS mass triage part 5](https://www.sans.org/blog/mass-triage-part-5-processing-returned-files-amcache); [ERAU JDFSL paper](https://commons.erau.edu/jdfsl/vol11/iss4/7/) |

---

## 6. RecentFileCache.bcf (Windows 7 only)

| Field | Value |
|-------|-------|
| **Location** | `C:\Windows\AppCompat\Programs\RecentFileCache.bcf` |
| **Format** | Proprietary binary (BCF = Binary Cache File). UTF-16 null-terminated strings containing executable paths, preceded by fixed-size header. |
| **Key Fields** | Full executable path (drive letter + path + binary name) for each entry |
| **Forensic Value** | Predecessor to Amcache.hve; triggered primarily when executables are recently copied or downloaded to the system and then executed; proves executable was present and run; `ProgramDataUpdater` task at 00:30 can update entries |
| **OS Scope** | Windows Vista, Windows 7 (superseded by Amcache.hve in Windows 8) |
| **Data Scope** | System |
| **Decoder Approach** | **RecentFileCacheParse** tool; libyal dtformats specification; Velociraptor `Windows.Forensics.RecentFileCache` |
| **MITRE ATT&CK** | T1059 |
| **References** | [artifacts-kb RecentFileCache](https://artifacts-kb.readthedocs.io/en/latest/sources/windows/RecentFileCache.html); [Journey Into IR blog](http://journeyintoir.blogspot.com/2013/12/revealing-recentfilecachebcf-file.html); [dtformats BCF spec](https://github.com/libyal/dtformats/blob/main/documentation/RecentFileCache.bcf%20format.asciidoc) |

---

## 7. ShimCache / AppCompatCache (file-persisted portion)

| Field | Value |
|-------|-------|
| **Location** | Data is stored in registry key `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache` (value `AppCompatCache`, binary blob). The SYSTEM hive file is at `C:\Windows\System32\config\SYSTEM`. Only written to disk at **shutdown or reboot**; current session entries reside in RAM only. |
| **Format** | Binary blob within SYSTEM registry hive. Structure varies by Windows version. Starts with a 4-byte header/signature and entry count, followed by variable-length records. Each record contains file path (Unicode string), file size (XP–Win 7), last-modified `$STANDARD_INFORMATION` timestamp, and an execution/insert flag (Win XP–Win 8.1; removed in Win 10). |
| **Key Fields** | Full executable path, file last-modified time (SI), file size (Win XP/2003 only), execute flag (Win XP: proves execution; Win 7–8.1: insert flag indicates possible execution; Win 10/11: removed — presence alone is ambiguous) |
| **Forensic Value** | Can contain executables that existed on the system but were deleted before acquisition; last-modified timestamp is the **file's modification time, NOT execution time** — do not confuse these; entries not yet flushed to registry on a live system require memory acquisition; on Win 10/11, any file viewed via Explorer may appear, so presence alone is insufficient for proof of execution |
| **OS Scope** | Windows XP – Windows 11 |
| **Data Scope** | System |
| **Decoder Approach** | Eric Zimmerman's **AppCompatCacheParser** (`AppCompatCacheParser.exe -f SYSTEM --csv`); RegRipper `appcompatcache` plugin; Volatility `shimcache` plugin (from memory) |
| **MITRE ATT&CK** | T1059, T1036 |
| **References** | [Magnet ShimCache vs Amcache](https://www.magnetforensics.com/blog/shimcache-vs-amcache-key-windows-forensic-artifacts/); [SANS mass triage part 4](https://www.sans.org/blog/mass-triage-part-4-processing-returned-files-appcache-shimcache); [AppCompatCache deep dive nullsec.us](https://nullsec.us/windows-10-11-appcompatcache-deep-dive/) |

---

## 8. SRUM Database (SRUDB.dat)

| Field | Value |
|-------|-------|
| **Location** | `C:\Windows\System32\sru\SRUDB.dat` |
| **Format** | Extensible Storage Engine (ESE / JET Blue) database. Same format as Active Directory, Exchange, and Windows Search databases. Interim data held in registry under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SRUM` until flushed hourly or at shutdown. |
| **Key Tables** | `{D10CA2FE-6FCF-4F6D-848E-B2E99266FA86}` — Application Resource Usage (CPU time, disk reads/writes, network bytes sent/received, per SID per app); `{973F5D5C-1D90-4944-BE8E-24B94231A174}` — Network Data Usage Monitor (bytes sent/received per app per interface); `{DD6636C4-8929-4683-974E-22C046A43763}` — Network Connectivity Usage (connection start time, duration, interface type); `{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}` — Energy Estimator; `{D10CA2FE-6FCF-4F6D-848E-B2E99266FA85}` — Push Notifications |
| **Key Fields** | Application full path, SID of executing user, timestamps (start/end), CPU time (foreground + background), disk read/write bytes, network bytes sent/received, interface type (Ethernet/Wi-Fi), SSID, connection duration, charge level (portable devices) |
| **Forensic Value** | 30-day rolling history of application execution, network usage, and energy consumption; persists even after application uninstall; ties execution to specific user SID; can identify data exfiltration by correlating bytes-sent with application and time; shows execution even from removed USB/network paths; records network SSIDs the device was connected to |
| **OS Scope** | Windows 8 – Windows 11 |
| **Data Scope** | System (multi-user, records include SID for attribution) |
| **Decoder Approach** | Eric Zimmerman's **SrumECmd** (`SrumECmd.exe -f SRUDB.dat -r SOFTWARE --csv`); Mark Baggett's **srum-dump** (outputs to Excel); KAPE; `esentutl /mh SRUDB.dat` to repair dirty database |
| **MITRE ATT&CK** | T1059 (execution evidence), T1048 (Exfiltration — network bytes sent), T1071 (Application Layer Protocol) |
| **References** | [Magnet SRUM analysis](https://www.magnetforensics.com/blog/srum-forensic-analysis-of-windows-system-resource-utilization-monitor/); [srum-dump GitHub](https://github.com/MarkBaggett/srum-dump); [artifacts-kb SRUM](https://artifacts-kb.readthedocs.io/en/latest/sources/windows/SystemResourceUsageMonitor.html); [ScienceDirect paper](https://www.sciencedirect.com/article/abs/pii/S1742287615000031) |

---

## 9. Windows Timeline — ActivitiesCache.db

| Field | Value |
|-------|-------|
| **Location** | `%LOCALAPPDATA%\ConnectedDevicesPlatform\L.<username>\ActivitiesCache.db` (local MSA); `%LOCALAPPDATA%\ConnectedDevicesPlatform\AAD.<GUID>\ActivitiesCache.db` (Azure AD-joined). Auxiliary files: `ActivitiesCache.db-shm`, `ActivitiesCache.db-wal`. |
| **Format** | SQLite 3 database. Requires SQLite JSON1 extension for payload parsing. |
| **Key Tables** | `Activity` (primary execution/browse records), `Activity_PackageId` (application paths and expiry), `ActivityAssetCache`, `ActivityOperation`, `AppSettings`, `Metadata` |
| **Key Fields** | `AppId` (application identifier), `ActivityType` (5 = app/URL open), `StartTime` / `EndTime` (Unix epoch), `CreationTime`, `LastModifiedTime`, `ExpirationTime`, `DisplayText` (filename or URL), `Description` (full path), `FileShellLink` (encoded re-open link), `Payload` (JSON blob with rich metadata), `ClipboardPayload`, unique GUID per activity |
| **Forensic Value** | Documents application launches, file opens, and URLs browsed with start/end times (duration of use); 30-day retention; WAL file can recover recently deleted records; synced activity from other devices if MSA sync was enabled (pre-July 2021); not all actions are recorded — treat as corroborating evidence, not sole source |
| **OS Scope** | Windows 10 version 1803+ through Windows 11 (cloud sync discontinued July 2021 for MSA) |
| **Data Scope** | User |
| **Decoder Approach** | Eric Zimmerman's **WxTCmd** (`WxTCmd.exe -f ActivitiesCache.db --csv`); DB Browser for SQLite; kacos2000 WindowsTimeline PowerShell scripts |
| **MITRE ATT&CK** | T1059, T1217 (Browser Bookmark Discovery — URLs recorded) |
| **References** | [kacos2000 WindowsTimeline](https://kacos2000.github.io/WindowsTimeline/); [Andrea Fortuna Timeline forensics](https://andreafortuna.org/2019/10/03/some-forensic-thoughts-about-windows-10-timeline/); [artifacts-kb ActivitiesCache](https://artifacts-kb.readthedocs.io/en/latest/sources/windows/ActivitiesCacheDatabase.html); [Group-IB Timeline forensics](https://www.group-ib.com/blog/windows10-timeline-for-forensics/) |

---

## 10. Windows Search Database (Windows.edb / Windows.db)

| Field | Value |
|-------|-------|
| **Location** | Windows 10 and earlier: `C:\ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb` (ESE format). Windows 11: three SQLite databases: `Windows.db`, `Windows-usn.db`, `Windows-gather.db` (same directory). Transaction logs in same folder. |
| **Format** | Windows 10-: ESE (Extensible Storage Engine / JET Blue) database. Windows 11+: SQLite 3 databases. Hidden file; Windows Search service must be stopped (or image acquired) to access without shadow copy. |
| **Key Tables / Columns** | `SystemIndex_PropertyStore` (Win 10-): file path, timestamps, content summary; `SystemIndex_Gthr`: gathering metadata; URL access records for IE/Edge (except InPrivate) |
| **Key Fields** | Indexed file path, file creation/modification/access times, file size, content type, partial/full text content of indexed documents (including emails via Outlook integration), visited URLs (IE/Edge), application-specific metadata (image resolution, email sender/recipient, document author) |
| **Forensic Value** | Reveals files that existed (including those later deleted or on removed external drives); partial content recovery of deleted indexed documents; URL history (IE/Edge non-private); operates transparently to users; persists content even after original file deletion; does not respect per-user boundaries — single database covers all users on system; can link thumbnail cache entries to original file paths |
| **OS Scope** | Windows XP (with Windows Search installed) – Windows 11 |
| **Data Scope** | System (all users' indexed files in one database) |
| **Decoder Approach** | **WinSearchDBAnalyzer** (supports Win 10 ESE format); **SIDR** (Search Index Database Reporter, supports both ESE and SQLite Win 11 format); `esentutl` for ESE repair; EseDbViewer; specialized modules in EnCase/X-Ways |
| **MITRE ATT&CK** | T1005 (Data from Local System — shows what data existed), T1083 (File and Directory Discovery) |
| **References** | [AON Cyber Labs article](https://www.aon.com/cyber-solutions/aon_cyber_labs/windows-search-index-the-forensic-artifact-youve-been-searching-for/); [ScienceDirect forensic data recovery paper](https://www.sciencedirect.com/article/abs/pii/S1742287611000028); [forensics.wiki/windows_desktop_search](https://forensics.wiki/windows_desktop_search/) |

---

## 11. Thumbnail Cache (thumbcache_*.db)

| Field | Value |
|-------|-------|
| **Location** | `%LOCALAPPDATA%\Microsoft\Windows\Explorer\thumbcache_32.db`, `thumbcache_96.db`, `thumbcache_256.db`, `thumbcache_1280.db`, `thumbcache_idx.db` (index). Legacy per-directory `Thumbs.db` (OLE Compound File) on XP and network share writes. |
| **Format** | Proprietary binary (Vista+). Each `thumbcache_NN.db` file contains a header and sub-records. Each sub-record has: 4-byte magic, record size, cache entry ID (64-bit Unique ID / File ID linking to `thumbcache_idx.db`), Thumbnail Cache ID (Unicode hex string linking to original file), data type, data offset, data size, data checksum, header checksum, and raw thumbnail image data (JPEG or other). `thumbcache_idx.db` provides pointer lookup from Cache Entry ID to file offset in each sized DB. |
| **Key Fields** | Cache Record ID, Thumbnail Cache ID (correlates to `Windows.edb` for filename recovery), data type, thumbnail pixel data, data/header checksums |
| **Forensic Value** | Thumbnail images persist after original file deletion — proves the image file was present and displayed to the user; used in court by law enforcement including FBI (2008 child exploitation case); correlates with shellbags (folder access) and Windows.edb (filename); covers JPEG, BMP, GIF, PNG, TIFF, AVI, PDF, PPTX, DOCX, HTML, MP4 and more |
| **OS Scope** | Windows Vista – Windows 11 (legacy Thumbs.db: Windows 95 – XP, still created on network shares in Vista/7) |
| **Data Scope** | User |
| **Decoder Approach** | OSForensics Thumbnail Cache Viewer; EnCase / FTK Imager; X-Ways; Thumbcache Viewer (open-source); correlate Thumbnail Cache ID with `SystemIndex_PropertyStore` in Windows.edb for filename |
| **MITRE ATT&CK** | T1005, T1070.004 (File Deletion — thumbnails survive deletion) |
| **References** | [forensics.wiki/windows_thumbcache](https://forensics.wiki/windows_thumbcache/); [Pen Test Partners DFIR thumbcache](https://www.pentestpartners.com/security-blog/thumbnail-forensics-dfir-techniques-for-analysing-windows-thumbcache/); [Villanova University paper](http://www.csc.villanova.edu/~dprice/extra_handouts/Forensic_Analysis_of_Windows_Thumbcache_files.pdf) |

---

## 12. Recycle Bin ($I / $R Files)

| Field | Value |
|-------|-------|
| **Location** | `C:\$Recycle.Bin\<SID>\$I<6-char-random>.<original-ext>` (metadata) and `C:\$Recycle.Bin\<SID>\$R<6-char-random>.<original-ext>` (content). One `$Recycle.Bin` per NTFS volume. SID subdirectory identifies the deleting user. |
| **Format** | `$I` file binary format: 8-byte version header (0x01 or 0x02); 8-byte original file size; 8-byte FILETIME deletion timestamp (offset 0x10); UTF-16 null-terminated original path string. Win 10+ adds a 4-byte filename-length field before the path string; pre-Win 10 files were a static 544 bytes; Win 10+ files are variable-length. `$R` file contains the verbatim deleted file content. |
| **Key Fields** | Original full path (including filename), original file size, deletion timestamp (FILETIME, UTC), deleting user's SID (from containing subdirectory), `$R` file contains original file content |
| **Forensic Value** | Proves a specific file was on the system and was deleted by a specific user; deletion timestamp accurate to 100-nanosecond precision; if `$I` is present but `$R` is absent, file was restored (restore leaves `$I` behind); items deleted via CMD/PowerShell/Terminal do NOT create `$I`/`$R` pairs; older Windows used `INFO2` in `C:\RECYCLER\<SID>\` (XP/2000) |
| **OS Scope** | Windows Vista – Windows 11 ($I/$R scheme); Windows XP/2000 used INFO2 in RECYCLER folder |
| **Data Scope** | User (SID-attributed) |
| **Decoder Approach** | Velociraptor `Windows.Forensics.RecycleBin`; `$I Parse` tool; EnCase / Autopsy / FTK; manual: parse binary $I file at fixed offsets |
| **MITRE ATT&CK** | T1070.004 (Indicator Removal — File Deletion), T1074 (Data Staged) |
| **References** | [Magnet Recycle Bin profile](https://www.magnetforensics.com/blog/artifact-profile-recycle-bin/); [forensic focus Vista Recycle Bin analysis](https://www.forensicfocus.com/articles/forensic-analysis-of-the-microsoft-windows-vista-recycle-bin/); [Seth Enoka Win 10/11 Recycle Bin](https://sethenoka.com/windows-recycle-bin-forensics-on-windows-10-and-11/); [Velociraptor RecycleBin artifact](https://docs.velociraptor.app/artifact_references/pages/windows.forensics.recyclebin/) |

---

## 13. USN Journal ($UsnJrnl:$J)

| Field | Value |
|-------|-------|
| **Location** | `<Volume>\$Extend\$UsnJrnl:$J` (alternate data stream). Second ADS: `$UsnJrnl:$Max` (32 bytes: max journal size, allocation delta). Sparse file — beginning is zeroed/sparse as records are cycled out. |
| **Format** | NTFS native. Each record is a variable-length structure: 4-byte record length, 2-byte major version (2 or 3), 2-byte minor version, 8-byte file reference number (MFT entry + sequence), 8-byte parent file reference number, 8-byte USN (Update Sequence Number — monotonically increasing 64-bit integer), 8-byte FILETIME timestamp, 4-byte reason flags bitmask, 4-byte source info, 4-byte security ID, 4-byte file attributes, 2-byte filename length, 2-byte filename offset, UTF-16 filename. |
| **Key Fields** | USN (sequence number), timestamp (millisecond precision FILETIME), filename, MFT reference (entry + sequence numbers for path reconstruction), parent MFT reference, reason flags (`USN_REASON_FILE_CREATE`, `USN_REASON_FILE_DELETE`, `USN_REASON_DATA_OVERWRITE`, `USN_REASON_RENAME_NEW_NAME`, `USN_REASON_RENAME_OLD_NAME`, `USN_REASON_BASIC_INFO_CHANGE`, etc.) |
| **Forensic Value** | Chronicle of every file system change with millisecond-precision timestamps; detects timestomping by cross-referencing `USN_REASON_BASIC_INFO_CHANGE` against file SI timestamps; reveals file creation and deletion sequences for malware staging; journal is typically 32 MB capped, retaining days to weeks of history; deleted records may remain in unallocated sparse space; shadow copies can extend recoverable history by weeks |
| **OS Scope** | NTFS: Windows 2000+ (XP/2000 usually disabled; Vista+ enabled by default) |
| **Data Scope** | System (per NTFS volume) |
| **Decoder Approach** | Eric Zimmerman's **MFTECmd** (`MFTECmd.exe -f '$J' --csv`); UsnJrnl2Csv; Velociraptor `parse_usn()` plugin; X-Ways; `fsutil usn readJournal` on live system |
| **MITRE ATT&CK** | T1070.004 (File Deletion detection), T1036 (Masquerading — rename chains visible), T1565 (Data Manipulation — timestomping detection) |
| **References** | [Wikipedia USN Journal](https://en.wikipedia.org/wiki/USN_Journal); [Velociraptor USN Journal blog](https://docs.velociraptor.app/blog/2020/2020-11-13-the-windows-usn-journal-f0c55c9010e/); [CyberEngage NTFS journaling](https://www.cyberengage.org/post/power-of-ntfs-journaling-in-digital-forensics-logfile-usnjrnl); [Andrea Fortuna USN Journal](https://andreafortuna.org/2025/09/06/usn-journal) |

---

## 14. NTFS Master File Table ($MFT)

| Field | Value |
|-------|-------|
| **Location** | `<Volume>\$MFT` (NTFS system file, record 0). Mirror backup at `<Volume>\$MFTMirr` (first 4 records). |
| **Format** | Each MFT record is exactly 1,024 bytes. Records 0–15 reserved for NTFS metadata files. Each record contains attribute headers followed by variable-length attributes. Key attributes: `$STANDARD_INFORMATION` (0x10) — SI timestamps + file flags; `$FILE_NAME` (0x30) — FN timestamps + filename + parent MFT reference; `$DATA` (0x80) — file data (inline if <~700 bytes) or data runs; `$INDEX_ROOT` / `$INDEX_ALLOCATION` (0x90/0xA0) — directory index entries containing child filenames and FN timestamps. |
| **Key Fields (MACB timestamps — two sets per file)** | `$STANDARD_INFORMATION` (0x10): M (last data modification), A (last access), C (MFT record changed), B (file born/created); `$FILE_NAME` (0x30): same four timestamps but harder to tamper — updated by NTFS kernel, rarely by user-land tools. Eight total timestamps per file. Also: file size, parent directory MFT reference, allocated vs. actual size, file attributes (hidden/system/readonly), flags (in-use vs. deleted) |
| **Forensic Value** | Central directory of all NTFS volume files and directories; deleted MFT entries are marked free but not immediately zeroed — full metadata recoverable until slot is reused; SI vs FN timestamp mismatch is primary timestomping indicator (timestomping tools update SI via `SetFileTime()` but typically cannot update FN timestamps without kernel access); Prefetch file creation timestamp in MFT = binary execution time; MFT slack space (bytes beyond real data in 1024-byte records) can contain residual filename data from previous occupants |
| **OS Scope** | All NTFS volumes: Windows NT 3.51 – Windows 11 |
| **Data Scope** | System (per volume) |
| **Decoder Approach** | Eric Zimmerman's **MFTECmd** (`MFTECmd.exe -f '$MFT' --csv`); Autopsy / Sleuth Kit `istat` / `fls`; FTK Imager (raw MFT extraction); dfir_ntfs (Maxim Suhanov, recovers MFT slack); Timeline Explorer for correlation |
| **MITRE ATT&CK** | T1565.001 (Stored Data Manipulation — timestomping visible via SI/FN mismatch), T1070.004, T1083 |
| **References** | [Sygnia MFT slack space](https://www.sygnia.co/blog/the-forensic-value-of-mft-slack-space/); [deaddisk MFT deep dive](https://www.deaddisk.com/posts/mastering-mft-forensic-analysis-mftecmd/); [MCSI MFT overview](https://library.mosse-institute.com/articles/2022/05/windows-master-file-table-mft-in-digital-forensics/windows-master-file-table-mft-in-digital-forensics.html) |

---

## 15. Volume Shadow Copies (VSS)

| Field | Value |
|-------|-------|
| **Location** | `<Volume>\System Volume Information\{<GUID>}` (hidden, protected, NTFS/ReFS only). Snapshots are block-level differential copies managed by the VSS driver. Not directly browsable as a file tree without mounting. |
| **Format** | VSS is a block-level copy-on-write mechanism, not a file format per se. Snapshots are addressed via GUIDs. The `System Volume Information` folder contains VSS catalog files (`{3808876b...}`) and diff area files. Each snapshot is accessible as a device path: `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN`. |
| **Key Fields** | Shadow copy GUID, creation timestamp, originating volume, associated VSS writer (system, backup, etc.) |
| **Forensic Value** | Each snapshot is a point-in-time copy of the entire volume — any file-based artifact (Prefetch, Amcache, registry hives, browser databases, SRUDB.dat) can be extracted from older snapshots to reconstruct historical state; snapshots created automatically ~daily (idle detection), on Windows Update, or by backup software; ransomware commonly deletes VSS (`vssadmin delete shadows /all /quiet`, WMI, PowerShell) — deletion attempt is itself an IOC; SI timestamps in MFT snapshots cannot be timestomped retroactively, enabling anti-forensics detection |
| **OS Scope** | Windows Vista – Windows 11 (requires NTFS or ReFS; not available on FAT volumes) |
| **Data Scope** | System (per volume) |
| **Decoder Approach** | `vssadmin list shadows` (enumerate); ShadowExplorer GUI (browse contents); **libvshadow** / `vshadowmount` (Joachim Metz — mount for forensic images, included in SIFT Workstation); Magnet AXIOM / EnCase / X-Ways (automated VSS integration); Eric Zimmerman tools accept `--vss` flag |
| **MITRE ATT&CK** | T1490 (Inhibit System Recovery — deletion of shadow copies is T1490), T1006 (Direct Volume Access) |
| **References** | [deaddisk VSS forensics](https://www.deaddisk.com/posts/vss/); [Andrea Fortuna VSS analysis](https://andreafortuna.org/2017/10/02/volume-shadow-copies-in-forensic-analysis/); [Microsoft Learn VSS](https://learn.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service); [Wikipedia Shadow Copy](https://en.wikipedia.org/wiki/Shadow_Copy) |

---

## 16. Windows Notification Database (wpndatabase.db)

| Field | Value |
|-------|-------|
| **Location** | Per-user: `%LOCALAPPDATA%\Microsoft\Windows\Notifications\wpndatabase.db`; System-wide: `C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\Notifications\wpndatabase.db`. Auxiliary files: `wpndatabase.db-shm`, `wpndatabase.db-wal`. |
| **Format** | SQLite 3 database (WAL mode). Replaced `appdb.dat` starting with Windows 10 Anniversary Edition (1607). |
| **Key Tables** | `Notification` (notification records with XML payloads containing content, app source path, notification type — badge/tile/toast), `NotificationHandler` (application registration), `HandlerAsset` |
| **Key Fields** | Notification XML payload (application name, notification text/content, source application path, image URLs, browser type for push notifications), notification type, creation and expiry timestamps, per-user attribution via profile path |
| **Forensic Value** | XML payloads can identify application execution via toast notifications (email received, message from IM client, security alert); browser push notifications reveal visited domains; linked to specific user accounts; WAL file contains notifications aged out of main DB (retention ~3 days in main DB, older entries in WAL); system-wide DB covers OS-level notifications |
| **OS Scope** | Windows 10 Anniversary Edition (1607) – Windows 11 |
| **Data Scope** | User (per-user DB) + System (system-wide DB) |
| **Decoder Approach** | DB Browser for SQLite; Velociraptor `Windows.Forensics.NotificationsDatabase`; Autopsy with WNA Python/Jython module; ArtiFast |
| **MITRE ATT&CK** | T1059 (execution evidence via notifications), T1204 (User Execution — toast for downloaded file execution) |
| **References** | [MDPI Digital Forensics paper](https://www.mdpi.com/2673-6756/2/1/7); [HECF Blog #440](https://www.hecfblog.com/2018/08/daily-blog-440-windows-10-notifications.html); [Swiftforensics parsing WPN DB](http://www.swiftforensics.com/2016/06/prasing-windows-10-notification-database.html); [Velociraptor NotificationsDatabase](https://docs.velociraptor.app/exchange/artifacts/pages/windows.forensics.notificationsdatabase/) |

---

## 17. PowerShell History File (ConsoleHost_history.txt)

| Field | Value |
|-------|-------|
| **Location** | `%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt` (i.e., `C:\Users\<username>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`). One file per user profile. |
| **Format** | Plain UTF-8 text file. One command per line, appended in execution order. No per-command timestamps embedded in the file. |
| **Key Fields** | Command text (one line per command, in execution order), up to 4,096 most recent commands by default |
| **Forensic Value** | Contains last 4,096 PowerShell console commands executed by the user; enabled by default in PowerShell 5+ (Windows 10); often the best or only record of PowerShell activity when Script Block logging is disabled; `$STANDARD_INFORMATION` last-modified timestamp of the file = time last command was appended; absence of the file (when it should exist) is itself an IOC — indicates deliberate deletion; `Clear-History` cmdlet clears session history but does NOT clear this file; `Set-PSReadlineOption -HistorySaveStyle SaveNothing` disables logging |
| **OS Scope** | Windows 10 – Windows 11 (PowerShell 5+ with PSReadLine module) |
| **Data Scope** | User |
| **Decoder Approach** | Plain text — read directly; correlate $MFT SI timestamps of the file with command content; check VSS snapshots for historical versions |
| **MITRE ATT&CK** | T1059.001 (PowerShell execution), T1070 (Indicator Removal — file deletion is T1070), T1562.006 (Disable/Modify OS Logging — `SaveNothing` setting) |
| **References** | [Sophos PowerShell history forensics](https://community.sophos.com/sophos-labs/b/blog/posts/powershell-command-history-forensics); [Eric Capuano Substack](https://blog.ecapuano.com/p/powershell-artifact-consolehost_historytxt); [kacos2000 ConsoleHost_history PDF](https://kacos2000.github.io/Win10/ConsoleHost_history.pdf); [Insider Threat Matrix detection](https://insiderthreatmatrix.org/detections/DT002) |

---

## 18. Startup Folder Files

| Field | Value |
|-------|-------|
| **Location** | Per-user: `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\` (i.e., `C:\Users\<username>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\`); All-users: `%ProgramData%\Microsoft\Windows\Start Menu\Programs\StartUp\` (i.e., `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\`) |
| **Format** | Any executable file type: `.exe`, `.bat`, `.vbs`, `.js`, `.hta`, `.ps1`, `.lnk` (shortcut to executable), `.cmd`. The presence of any file in these directories causes Windows Shell to execute it at user logon. |
| **Key Fields** | Filename and extension (type of payload), creation timestamp ($MFT / SI), last-modified timestamp, file hash, LNK target path if shortcut |
| **Forensic Value** | Per-user startup requires no admin privileges — commonly abused by malware and APTs (APT3, APT33, APT39 documented); all-users startup requires administrator privilege; parent process of resulting execution is `explorer.exe` (not always user-interactive); LNK files here link to payload location which may already be deleted; Sysmon EID 12 (FileCreate) detects new files added to these paths |
| **OS Scope** | Windows 95 – Windows 11 |
| **Data Scope** | User (per-user) / System (all-users) |
| **Decoder Approach** | Directory listing; Sysinternals Autoruns (enumerates all startup locations); Sysmon Event ID 12 for creation events; correlate with Prefetch for execution confirmation |
| **MITRE ATT&CK** | T1547.001 (Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder) |
| **References** | [MITRE ATT&CK T1547.001](https://attack.mitre.org/techniques/T1547/001/); [stmxcsr startup persistence analysis](https://stmxcsr.com/persistence/looking-at-the-startup-directory.html); [Azeria Labs Persistence](https://azeria-labs.com/persistence/) |

---

## 19. Windows Event Log Channels (EVTX)

| Field | Value |
|-------|-------|
| **Location** | `C:\Windows\System32\winevt\Logs\*.evtx` |
| **Format** | Binary XML wrapped in proprietary EVTX container format. Replaced legacy EVT format (XP/2003). Circular log with configurable max size (default 20 MB for most channels). |

### Top 15 Forensically Valuable Event IDs for Execution Evidence

| Event ID | Log File | Description | Forensic Value |
|----------|----------|-------------|----------------|
| **4688** | `Security.evtx` | New process created | Process name, PID, parent PID, creator process name, command line (if "Include command line" GPO enabled), token elevation type (UAC indicator), user SID. Requires "Audit Process Creation" policy. |
| **4689** | `Security.evtx` | Process terminated | Correlate with 4688 for process duration; process exit code |
| **4698** | `Security.evtx` | Scheduled task created | Task name, full XML task definition including trigger, action (executable path), author |
| **4702** | `Security.evtx` | Scheduled task updated | Changed task definition — persistence modification detection |
| **7045** | `System.evtx` | New service installed | Service name, full path to service executable, service type, start type, service account. PsExec and many RATs create services with random names. |
| **4697** | `Security.evtx` | Service installed (Security log) | Duplicates 7045 but in Security log; service name, path, account |
| **4103** | `Microsoft-Windows-PowerShell/Operational.evtx` | PowerShell module logging | Full pipeline output including obfuscated command expansion; requires Module Logging GPO |
| **4104** | `Microsoft-Windows-PowerShell/Operational.evtx` | PowerShell script block logging | Full script text as executed (decoded from Base64 if applicable); large scripts split across multiple events; enabled by default in PS5+; captures runtime-decoded obfuscated scripts |
| **400** | `Windows PowerShell.evtx` | PowerShell engine started | EngineState = "Available" indicates PS session started; correlate Host ID with 4103 events |
| **800** | `Windows PowerShell.evtx` | PowerShell pipeline execution | Command pipeline details for older PS versions |
| **1102** | `Security.evtx` | Security audit log cleared | Username of account that cleared the log; primary anti-forensics indicator |
| **104** | `System.evtx` | System event log cleared | Equivalent of 1102 for System log |
| **4663** | `Security.evtx` | Object (file/folder) access attempt | File path, access type requested, user SID; requires Object Access auditing; high volume — filter on sensitive paths |
| **4657** | `Security.evtx` | Registry value modified | Registry key path, value name, old/new data; requires Registry auditing |
| **4719** | `Security.evtx` | System audit policy changed | Detects attacker disabling logging policies |

| **Additional High-Value IDs** | |
|------|-------|
| 4624/4625 | Logon success / failure |
| 4634/4647 | Logoff |
| 4776 | NTLM credential validation |
| 5140 | Network share access |
| 4660 | Object deleted |

| Field | Value |
|-------|-------|
| **Forensic Value** | Structured, timestamped record of system and security events; Event IDs 4688 + 4104 together provide the most complete execution picture; logs are volatile (circular overwrite) — acquire early; attacker clearing logs (EID 1102/104) is itself an artifact; centralized log forwarding (WEF/SIEM) may preserve logs deleted on endpoint |
| **OS Scope** | Windows Vista – Windows 11 (EVTX format); Windows XP/2003 used legacy EVT format |
| **Data Scope** | System (Security, System); per-user entries within system logs include user SID |
| **Decoder Approach** | Eric Zimmerman's **EvtxECmd** + EvtxECmd Map Repository; Timeline Explorer; Event Viewer (`eventvwr.msc`); `wevtutil` CLI; PowerShell `Get-WinEvent`; Velociraptor `Windows.EventLogs.*` artifacts |
| **MITRE ATT&CK** | T1059 (all execution EIDs), T1053 (Scheduled Task — 4698/4702), T1543 (Service — 7045/4697), T1070.001 (Clear Windows Event Logs — 1102/104) |
| **References** | [Ultimate Windows Security EID 4688](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4688); [Psmths EID 4688](https://github.com/Psmths/windows-forensic-artifacts/blob/main/execution/evtx-4688-process-created.md); [stuhli awesome-event-ids](https://github.com/stuhli/awesome-event-ids); [Forward Defense EVTX reference](https://forwarddefense.com/media/attachments/2021/05/15/windows-event-log-analyst-reference.pdf); [ElcomSoft EVTX forensics](https://blog.elcomsoft.com/2026/02/forensic-analysis-of-windows-10-and-11-event-logs/) |

---

## 20. BAM / DAM Registry-Backed Execution Records

| Field | Value |
|-------|-------|
| **Location** | BAM: `HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\<SID>\` (Win 10 1803+; prior to 1803 it was `\bam\UserSettings\`). DAM: `HKLM\SYSTEM\CurrentControlSet\Services\dam\UserSettings\<SID>\`. These registry keys live in the SYSTEM hive at `C:\Windows\System32\config\SYSTEM`. |
| **Format** | Each executed binary is a REG_BINARY value whose **name** is the full executable path (Unicode) and whose **data** is an 8-byte FILETIME timestamp (little-endian 64-bit) recording last execution time, followed by additional padding bytes. |
| **Key Fields** | Full executable path (value name), last execution FILETIME timestamp (value data, 64-bit little-endian), executing user SID (from containing subkey) |
| **Forensic Value** | Records last execution time per binary per user with high fidelity; user attribution is explicit via SID (unlike Prefetch which is system-wide); survives application deletion for up to ~7 days post-execution; written on process creation AND termination; entries purged on boot approximately one week after last execution; console applications launched via CLI do not appear; executables on file shares or removable media do not appear; only available on Windows 10 1709+ |
| **OS Scope** | Windows 10 version 1709 (Fall Creators Update) – Windows 11 |
| **Data Scope** | System registry (per-user SID attribution) |
| **Decoder Approach** | Eric Zimmerman's Registry Explorer; Velociraptor `Windows.Forensics.Bam`; RegRipper `bam` plugin; 0xSCHfL BamParser enhanced; manual: read SYSTEM hive offline, enumerate BAM UserSettings subkeys |
| **MITRE ATT&CK** | T1059 (execution evidence), T1078 (Valid Accounts — per-SID attribution) |
| **References** | [CyberEngage BAM/DAM guide](https://www.cyberengage.org/post/bam-and-dam-in-windows-forensics-tracking-executed-applications); [Psmths BAM/DAM artifact](https://github.com/Psmths/windows-forensic-artifacts/blob/main/execution/bam-dam.md); [Velociraptor BAM artifact](https://docs.velociraptor.app/artifact_references/pages/windows.forensics.bam/); [forensafe BAM](https://forensafe.com/blogs/bam.html) |

---

## 21. UserAssist (NTUSER.DAT-backed, file-resident)

| Field | Value |
|-------|-------|
| **Location** | `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count\` within the NTUSER.DAT hive file at `C:\Users\<username>\NTUSER.DAT`. Primary GUIDs: `{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}` (direct executable launches); `{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}` (shortcut launches). |
| **Format** | Each value under the `Count` subkey has: name = ROT13-encoded executable path or shortcut path (using KNOWNFOLDERID GUIDs instead of real folder paths); data = binary blob containing run count (4 bytes at offset 4), focus count (4 bytes at offset 8), focus time in seconds (4 bytes at offset 12), last run FILETIME timestamp (8 bytes at offset 60 on Win 7+). Structure varies slightly by Windows version. |
| **Key Fields** | ROT13-decoded executable path, run count, focus count, focus time (seconds of active foreground use), last execution timestamp |
| **Forensic Value** | Records GUI-launched application execution specifically — proves a human clicked on an icon or launched an application via the shell (command-line executions are NOT recorded); run count documents frequency; focus time distinguishes brief launch-crash from sustained interactive use; persists after application uninstall; ROT13 encoding is trivial to reverse; zero focus time with positive run count suggests execution without user interaction |
| **OS Scope** | Windows 2000 – Windows 11 (field structure and captured metrics vary by version) |
| **Data Scope** | User (NTUSER.DAT hive) |
| **Decoder Approach** | Eric Zimmerman's **Registry Explorer** (UserAssist plugin handles ROT13 + KNOWNFOLDERID mapping + binary blob parsing automatically); Magnet AXIOM; Belkasoft X; RegRipper `userassist` plugin; CyberChef ROT13 for manual decoding |
| **MITRE ATT&CK** | T1059 (GUI-based execution), T1204.002 (User Execution: Malicious File — proves user clicked) |
| **References** | [Magnet UserAssist profile](https://www.magnetforensics.com/blog/artifact-profile-userassist/); [Cyber Triage UserAssist 2025](https://www.cybertriage.com/blog/userassist-forensics-2025/); [CyberEngage UserAssist guide](https://www.cyberengage.org/post/userassist-a-powerful-yet-complex-forensic-artifact-for-tracking-application-execution); [Velociraptor Windows.Registry.UserAssist](https://docs.velociraptor.app/artifact_references/pages/windows.registry.userassist/) |

---

## Cross-Artifact Correlation Matrix

| Artifact | Proves Execution | Proves Presence | User Attribution | Survives Deletion | Timestamps |
|----------|:-:|:-:|:-:|:-:|--------|
| Prefetch (.pf) | Strong | Yes | No (system-wide) | Until overwrite | Up to 8 last-run timestamps |
| LNK files | Access (not exec) | Yes | Yes (user profile) | Yes (target deleted) | 6 timestamps (3 LNK + 3 target MAC) |
| AutomaticDestinations | Access (not exec) | Yes | Yes | Yes | Per-entry LNK timestamps |
| Amcache.hve | Presence (not definitive exec) | Yes | No | Yes (30+ days) | First seen via key last-write |
| SRUDB.dat | Strong | Yes | Yes (SID) | 30 days | Start/end per execution |
| ActivitiesCache.db | Strong | Yes | Yes | 30 days | Start + end (duration) |
| EVTX 4688 | Definitive (if enabled) | Yes | Yes (SID) | Until log overwrite | Event timestamp |
| EVTX 4104 | Definitive (PowerShell) | Yes | Yes (SID) | Until log overwrite | Event timestamp |
| BAM/DAM | Strong | Yes | Yes (SID) | ~7 days post-exec | Last execution FILETIME |
| UserAssist | Strong (GUI only) | Yes | Yes (NTUSER.DAT) | Yes (after uninstall) | Last run + focus time |
| $UsnJrnl | Change journal only | Via reason flags | No | Days to weeks | FILETIME per change |
| $MFT | Via Prefetch entry | Yes | No | Until MFT reuse | 8 MACB timestamps |
| ShimCache | Ambiguous (OS-dependent) | Yes | No | Yes | File last-modified (not exec) |
| RecentFileCache.bcf | Presence only | Yes | No | Yes | Via key write time |
| thumbcache | File was displayed | Yes | Yes (user profile) | Yes | Thumbnail generation time |
| Recycle Bin $I | File was deleted | Yes (path+size) | Yes (SID) | Until emptied | Deletion FILETIME |
| wpndatabase.db | Indirect (app notified) | Via notification | Yes | ~3 days (WAL longer) | Notification timestamp |
| ConsoleHost_history.txt | Strong (PS commands) | Yes | Yes (user profile) | Until deleted | File SI last-modified |
| Startup folder | Persistence (not exec) | Yes | Yes (user/system) | Yes | Creation timestamp |
| Windows.edb | Was indexed | Yes | No (system-wide) | Yes | Indexing timestamps |
| VSS snapshots | Historical copies | Yes | Per-artifact | Volume lifetime | Snapshot creation time |

---

## Tooling Reference

| Tool | Author | Artifacts Covered |
|------|--------|------------------|
| PECmd | Eric Zimmerman | Prefetch |
| LECmd | Eric Zimmerman | LNK files |
| JLECmd | Eric Zimmerman | Jump Lists |
| AmcacheParser | Eric Zimmerman | Amcache.hve |
| AppCompatCacheParser | Eric Zimmerman | ShimCache |
| SrumECmd | Eric Zimmerman | SRUDB.dat |
| WxTCmd | Eric Zimmerman | ActivitiesCache.db |
| MFTECmd | Eric Zimmerman | $MFT, $UsnJrnl:$J |
| EvtxECmd | Eric Zimmerman | EVTX event logs |
| Registry Explorer | Eric Zimmerman | NTUSER.DAT, SYSTEM, SOFTWARE hives |
| Timeline Explorer | Eric Zimmerman | CSV timeline correlation |
| KAPE | Eric Zimmerman | Automated triage collection + parsing |
| Velociraptor | Rapid7/community | All artifacts via VQL artifacts |
| srum-dump | Mark Baggett | SRUDB.dat |
| libvshadow / vshadowmount | Joachim Metz | Volume Shadow Copies |
| WinSearchDBAnalyzer | community | Windows.edb (Win 10) |
| SIDR | community | Windows.db (Win 11) + Windows.edb |
| Magnet AXIOM | Magnet Forensics | All artifacts (commercial) |
| X-Ways Forensics | X-Ways | All artifacts (commercial) |
| Autopsy / Sleuth Kit | Basis Technology | All artifacts (open-source) |

---

## Sources

- [forensics.wiki/prefetch](https://forensics.wiki/prefetch/)
- [forensics.wiki/lnk](https://forensics.wiki/lnk/)
- [forensics.wiki/jump_lists](https://forensics.wiki/jump_lists/)
- [forensics.wiki/windows_thumbcache](https://forensics.wiki/windows_thumbcache/)
- [libscca Prefetch format spec (libyal)](https://github.com/libyal/libscca/blob/main/documentation/Windows%20Prefetch%20File%20(PF)%20format.asciidoc)
- [liblnk LNK format spec (libyal)](https://github.com/libyal/liblnk/blob/main/documentation/Windows%20Shell%20Link%20(.lnk)%20format.asciidoc)
- [Psmths windows-forensic-artifacts (GitHub)](https://github.com/Psmths/windows-forensic-artifacts)
- [Magnet Forensics — Prefetch profile](https://www.magnetforensics.com/blog/forensic-analysis-of-prefetch-files-in-windows/)
- [Magnet Forensics — LNK files](https://www.magnetforensics.com/blog/forensic-analysis-of-lnk-files/)
- [Magnet Forensics — SRUM analysis](https://www.magnetforensics.com/blog/srum-forensic-analysis-of-windows-system-resource-utilization-monitor/)
- [Magnet Forensics — UserAssist profile](https://www.magnetforensics.com/blog/artifact-profile-userassist/)
- [Magnet Forensics — Recycle Bin profile](https://www.magnetforensics.com/blog/artifact-profile-recycle-bin/)
- [Magnet Forensics — ShimCache vs Amcache](https://www.magnetforensics.com/blog/shimcache-vs-amcache-key-windows-forensic-artifacts/)
- [Securelist — Amcache forensic artifact](https://securelist.com/amcache-forensic-artifact/117622/)
- [SANS — Mass Triage Part 4: ShimCache](https://www.sans.org/blog/mass-triage-part-4-processing-returned-files-appcache-shimcache)
- [SANS — Mass Triage Part 5: Amcache](https://www.sans.org/blog/mass-triage-part-5-processing-returned-files-amcache)
- [SANS ISC — Forensic Value of Prefetch](https://isc.sans.edu/diary/29168)
- [artifacts-kb (ForensicArtifacts)](https://artifacts-kb.readthedocs.io/en/latest/)
- [kacos2000 WindowsTimeline](https://kacos2000.github.io/WindowsTimeline/)
- [Andrea Fortuna — Windows 10 Timeline forensics](https://andreafortuna.org/2019/10/03/some-forensic-thoughts-about-windows-10-timeline/)
- [AON Cyber Labs — Windows Search Index](https://www.aon.com/cyber-solutions/aon_cyber_labs/windows-search-index-the-forensic-artifact-youve-been-searching-for/)
- [Pen Test Partners — thumbcache DFIR](https://www.pentestpartners.com/security-blog/thumbnail-forensics-dfir-techniques-for-analysing-windows-thumbcache/)
- [Cyber Triage — Jump Lists 2025](https://www.cybertriage.com/blog/jump-list-forensics-2025/)
- [Cyber Triage — UserAssist 2025](https://www.cybertriage.com/blog/userassist-forensics-2025/)
- [CyberEngage — BAM/DAM forensics](https://www.cyberengage.org/post/bam-and-dam-in-windows-forensics-tracking-executed-applications)
- [Velociraptor — Evidence of Execution](https://docs.velociraptor.app/docs/forensic/evidence_of_execution/)
- [deaddisk — VSS forensics](https://www.deaddisk.com/posts/vss/)
- [deaddisk — MFT forensics](https://www.deaddisk.com/posts/mastering-mft-forensic-analysis-mftecmd/)
- [Sygnia — MFT slack space](https://www.sygnia.co/blog/the-forensic-value-of-mft-slack-space/)
- [Velociraptor — USN Journal blog](https://docs.velociraptor.app/blog/2020/2020-11-13-the-windows-usn-journal-f0c55c9010e/)
- [MDPI — Windows 10 Notifications forensics paper](https://www.mdpi.com/2673-6756/2/1/7)
- [Sophos Labs — PowerShell history forensics](https://community.sophos.com/sophos-labs/b/blog/posts/powershell-command-history-forensics)
- [Eric Capuano — ConsoleHost_history.txt](https://blog.ecapuano.com/p/powershell-artifact-consolehost_historytxt)
- [Ultimate Windows Security — Event ID 4688](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4688)
- [stuhli awesome-event-ids (GitHub)](https://github.com/stuhli/awesome-event-ids)
- [MITRE ATT&CK T1547.001](https://attack.mitre.org/techniques/T1547/001/)
- [ElcomSoft — EVTX forensics 2026](https://blog.elcomsoft.com/2026/02/forensic-analysis-of-windows-10-and-11-event-logs/)
- [Forward Defense Windows Event Log Analyst Reference](https://forwarddefense.com/media/attachments/2021/05/15/windows-event-log-analyst-reference.pdf)
