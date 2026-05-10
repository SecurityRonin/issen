# Windows Registry Artifacts: Evidence of File & Folder Access

## Comprehensive Reference for Digital Forensic Investigations

**Last Updated:** 2026-03-24
**Scope:** Every known registry path that records file access, folder browsing, search history, or document usage

---

## Key Timestamp Principle

Registry keys have last-write timestamps but individual values do NOT. This means:
- **Parent key timestamp** = when any value under it was last modified
- **Subkey timestamps** = individual timing for each entry (when subkeys are used as MRU entries)
- **MRU order + key timestamps** = chronological reconstruction
- A key's LastWrite time is updated whenever any value OR subkey under it changes

---

## Table of Contents

1. [Explorer Shell MRU Artifacts](#1-explorer-shell-mru-artifacts)
2. [ComDlg32 Common Dialog Artifacts](#2-comdlg32-common-dialog-artifacts)
3. [ShellBags (Folder Access)](#3-shellbags-folder-access)
4. [Search History Artifacts](#4-search-history-artifacts)
5. [Microsoft Office Artifacts](#5-microsoft-office-artifacts)
6. [Browser & Internet Artifacts](#6-browser--internet-artifacts)
7. [Remote Access Artifacts](#7-remote-access-artifacts)
8. [Network & Share Access Artifacts](#8-network--share-access-artifacts)
9. [Application Execution (File Access Evidence)](#9-application-execution-file-access-evidence)
10. [Built-in Application MRUs](#10-built-in-application-mrus)
11. [Third-Party Application MRUs](#11-third-party-application-mrus)
12. [Media Player Artifacts](#12-media-player-artifacts)
13. [Encryption & Security Artifacts](#13-encryption--security-artifacts)
14. [Capability Access Manager](#14-capability-access-manager)
15. [Printer Artifacts](#15-printer-artifacts)
16. [Windows 11 New Artifacts](#16-windows-11-new-artifacts)
17. [Miscellaneous File Access Artifacts](#17-miscellaneous-file-access-artifacts)

---

## 1. Explorer Shell MRU Artifacts

### 1.1 RecentDocs

| Field | Details |
|---|---|
| **Registry Path** | `Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs` |
| **Hive** | NTUSER.DAT |
| **Forensic Value** | Recent files and folders accessed by the user. Subkeys exist for each file extension (e.g., `.docx`, `.pdf`, `.jpg`). The root key tracks ALL recent items regardless of type. |
| **Timestamp Behavior** | Each extension subkey has its own LastWrite timestamp = when the last file of that type was opened. MRUListEx value provides temporal ordering. |
| **Data Format** | Binary values containing filename in Unicode + LNK target data. MRUListEx = array of 4-byte little-endian integers indicating access order (0 = most recent). |
| **Windows Versions** | XP through 11 |
| **Caveats** | Persists even after source file is deleted. Tracks up to ~150 entries per extension. Populated by Windows Explorer shell — programmatic file access may not trigger it. |

### 1.2 RunMRU

| Field | Details |
|---|---|
| **Registry Path** | `Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` |
| **Hive** | NTUSER.DAT |
| **Forensic Value** | Last 26 commands typed into the Win+R Run dialog. Can reveal file paths, UNC paths, URLs, and application launches. |
| **Timestamp Behavior** | Key LastWrite = time of most recently executed command. MRUList value provides ordering. |
| **Data Format** | REG_SZ string values named `a` through `z`. Each contains the typed command + `\1` suffix. MRUList = string of letters in access order. |
| **Windows Versions** | XP through 11 |
| **Caveats** | Only 26 slots (a-z). Only captures Run dialog input, not cmd.exe or PowerShell commands. |

### 1.3 TypedPaths

| Field | Details |
|---|---|
| **Registry Path** | `Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths` |
| **Hive** | NTUSER.DAT |
| **Forensic Value** | Paths typed directly into the Windows Explorer address bar (e.g., `C:\Users\secret`, `\\server\share`). |
| **Timestamp Behavior** | Key LastWrite = most recent path entry. No MRU ordering value — `url1` is always the most recent. |
| **Data Format** | REG_SZ values named `url1`, `url2`, etc. `url1` = most recent. When new path is typed, previous values shift down. |
| **Windows Versions** | Vista through 11 (XP used TypedURLs for this purpose) |
| **Caveats** | Tracks last ~25 entries. Only populated when user types a path and presses Enter — clicking through folders does NOT populate this key. |

### 1.4 Explorer\FeatureUsage (All Subkeys)

| Field | Details |
|---|---|
| **Registry Path** | `Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage` |
| **Hive** | NTUSER.DAT |
| **Forensic Value** | Tracks taskbar interactions. Subkeys: **AppBadgeUpdated** (badge notifications), **AppLaunch** (pinned app launches), **AppSwitched** (app focus changes via taskbar click), **ShowJumpView** (right-click on taskbar = Jump List access), **TrayButtonClicked** (system tray clicks). |
| **Timestamp Behavior** | Each subkey has its own LastWrite. Values are DWORD counters (run counts). **KeyCreationTime** QWORD on root key = first interactive logon timestamp (FILETIME). |
| **Data Format** | Value names = executable paths or app IDs. Value data = DWORD count of interactions. |
| **Windows Versions** | Windows 10 v1903+ through 11 |
| **Caveats** | Persists after application uninstall. No per-value timestamps — use subkey LastWrite for last interaction time. AppSwitched tracks ALL GUI apps (not just pinned). ShowJumpView = evidence user right-clicked app to see recent files. |

### 1.5 RecentApps

| Field | Details |
|---|---|
| **Registry Path** | `Software\Microsoft\Windows\CurrentVersion\Search\RecentApps` |
| **Hive** | NTUSER.DAT |
| **Forensic Value** | Recently launched applications with launch count, last accessed time, and paths to files used with each application. Each GUID subkey = one application. |
| **Timestamp Behavior** | Contains explicit `LastAccessedTime` value (FILETIME) per app + `LaunchCount`. |
| **Data Format** | GUID subkeys. Values: `AppId` (string), `LastAccessedTime` (QWORD FILETIME), `LaunchCount` (DWORD). Sub-subkeys may contain individual file access entries with their own timestamps. |
| **Windows Versions** | Windows 10 v1607 to v1709 ONLY |
| **Caveats** | DEPRECATED after Windows 10 v1709. Key stops being populated but existing data remains. Replaced functionally by FeatureUsage. |

### 1.6 StartPage2 ProgramsCache

| Field | Details |
|---|---|
| **Registry Path** | `Software\Microsoft\Windows\CurrentVersion\Explorer\StartPage2` |
| **Hive** | NTUSER.DAT |
| **Forensic Value** | Start Menu program cache / Jump List data. Values `ProgramsCacheSMP` and `ProgramsCacheTBP` contain binary data about programs shown in Start Menu. |
| **Timestamp Behavior** | Key LastWrite = last Start Menu interaction. |
| **Data Format** | Binary blobs containing serialized program list data. |
| **Windows Versions** | Windows 7, 8 |
| **Caveats** | Largely superseded by Jump Lists files on Windows 10+. Requires specialized parsing. |

---

## 2. ComDlg32 Common Dialog Artifacts

All under: `Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\`

### 2.1 OpenSavePidlMRU (OpenSaveMRU on XP)

| Field | Details |
|---|---|
| **Registry Path** | `...\ComDlg32\OpenSavePidlMRU` (Vista+) or `...\ComDlg32\OpenSaveMRU` (XP) |
| **Hive** | NTUSER.DAT |
| **Forensic Value** | Full paths of files opened or saved via ANY application's Open/Save As dialog box. Organized by file extension subkeys. The `*` subkey tracks last 20 files of any type (10 on XP). |
| **Timestamp Behavior** | Each extension subkey LastWrite = when last file of that type was opened/saved via dialog. MRUListEx provides ordering. |
| **Data Format** | XP: REG_SZ strings with paths. Vista+: Binary PIDL (ItemID List) structures. MRUListEx = 4-byte LE integer array. |
| **Windows Versions** | XP (OpenSaveMRU), Vista through 11 (OpenSavePidlMRU) |
| **Caveats** | Does NOT include files opened via Microsoft Office (Office uses its own MRU). Includes browser Save As dialogs. Extension subkeys reveal installed applications. Anti-forensics detection: compare MRUListEx numbers against existing value names — missing values indicate deletion attempts. |

### 2.2 OpenSavePidlMRULegacy

| Field | Details |
|---|---|
| **Registry Path** | `...\ComDlg32\OpenSavePidlMRULegacy` |
| **Hive** | NTUSER.DAT |
| **Forensic Value** | Same as OpenSavePidlMRU but for legacy-style dialog boxes (older applications using the classic dialog interface). |
| **Timestamp Behavior** | Same as OpenSavePidlMRU. |
| **Data Format** | Same as OpenSavePidlMRU. |
| **Windows Versions** | Vista through 11 |
| **Caveats** | Only populated by applications using the older Common Dialog interface. |

### 2.3 LastVisitedPidlMRU (LastVisitedMRU on XP)

| Field | Details |
|---|---|
| **Registry Path** | `...\ComDlg32\LastVisitedPidlMRU` (Vista+) or `...\ComDlg32\LastVisitedMRU` (XP) |
| **Hive** | NTUSER.DAT |
| **Forensic Value** | Tracks which EXECUTABLE opened files via Open/Save dialog AND the last DIRECTORY that executable accessed. Pairs with OpenSavePidlMRU. |
| **Timestamp Behavior** | Key LastWrite = last time any application used Open/Save dialog. MRUListEx ordering. |
| **Data Format** | Binary values containing: executable name (Unicode null-terminated) followed by Shell Item ID List (PIDL) of the directory path. |
| **Windows Versions** | XP (LastVisitedMRU), Vista through 11 (LastVisitedPidlMRU) |
| **Caveats** | The directory stored is the LAST directory used by that specific executable, not a history of all directories. Useful for identifying deleted file locations. |

### 2.4 LastVisitedPidlMRULegacy

| Field | Details |
|---|---|
| **Registry Path** | `...\ComDlg32\LastVisitedPidlMRULegacy` |
| **Hive** | NTUSER.DAT |
| **Forensic Value** | Same as LastVisitedPidlMRU but for legacy-style dialog boxes. Records last folder location used by each application in old-style Open/Save dialogs. |
| **Timestamp Behavior** | Same as LastVisitedPidlMRU. |
| **Data Format** | Same as LastVisitedPidlMRU. |
| **Windows Versions** | Vista through 11 |
| **Caveats** | Same as 2.3 Legacy variant. |

### 2.5 CIDSizeMRU

| Field | Details |
|---|---|
| **Registry Path** | `...\ComDlg32\CIDSizeMRU` |
| **Hive** | NTUSER.DAT |
| **Forensic Value** | Tracks recently launched applications that opened a Common Dialog box (Open, Save As, Print). Evidence of program execution AND dialog usage. |
| **Timestamp Behavior** | Key LastWrite = last time an application used a common dialog. MRUListEx ordering. |
| **Data Format** | Binary values containing executable path information. MRUListEx = 4-byte LE integer array. |
| **Windows Versions** | Vista through 11 |
| **Caveats** | Only records apps that actually used a common dialog — not all launched applications. Eric Zimmerman has a dedicated RegistryPlugin for parsing this key. |

### 2.6 FirstFolder

| Field | Details |
|---|---|
| **Registry Path** | `...\ComDlg32\FirstFolder` |
| **Hive** | NTUSER.DAT |
| **Forensic Value** | Tracks the first folder opened when using a common dialog box. Less documented than other ComDlg32 subkeys. |
| **Timestamp Behavior** | Key LastWrite = last update. |
| **Data Format** | Binary. Parsed by RegRipper `comdlg32.pl` plugin. |
| **Windows Versions** | Vista through 11 |
| **Caveats** | Limited documentation. Best parsed with RegRipper or RECmd. |

---

## 3. ShellBags (Folder Access)

### 3.1 ShellBags — USRCLASS.DAT (Primary)

| Field | Details |
|---|---|
| **Registry Path** | `Local Settings\Software\Microsoft\Windows\Shell\BagMRU` and `...\Shell\Bags` |
| **Hive** | USRCLASS.DAT (`C:\Users\{user}\AppData\Local\Microsoft\Windows\UsrClass.dat`) |
| **Forensic Value** | Records EVERY folder browsed via Windows Explorer: local folders, zip files, Windows special folders, virtual folders, Control Panel applets. The BagMRU hierarchy mirrors the folder tree structure. Bags stores view preferences (icon size, sort order, window position). |
| **Timestamp Behavior** | Each BagMRU subkey LastWrite = when that folder was last accessed or a child folder was navigated. Embedded timestamps within shell item data may include folder creation/modification times. |
| **Data Format** | BagMRU: Binary Shell Item ID List values per folder. **MRUListEx** value = access order of child folders. **NodeSlot** value = pointer to corresponding Bags entry. Bags: DWORD/binary values for view settings (Mode, Rev, FFlags, etc.). |
| **Windows Versions** | Vista through 11 (XP stored in NTUSER.DAT under ShellNoRoam) |
| **Caveats** | Only records FOLDER-level interactions, not individual file access. Persists after folder deletion — evidence of folders that no longer exist. Cannot be natively disabled. Anti-forensics: using PowerShell/cmd to navigate bypasses ShellBag creation. Does NOT record programmatic folder access. |

### 3.2 ShellBags — NTUSER.DAT (Secondary)

| Field | Details |
|---|---|
| **Registry Path** | `Software\Microsoft\Windows\Shell\BagMRU` and `...\Shell\Bags` |
| **Hive** | NTUSER.DAT |
| **Forensic Value** | Records folder access for **network folders**, **remote machines**, and **remote folder paths**. Complements USRCLASS.DAT which stores local folder access. |
| **Timestamp Behavior** | Same as USRCLASS.DAT ShellBags. |
| **Data Format** | Same structure as USRCLASS.DAT ShellBags. |
| **Windows Versions** | Vista through 11 |
| **Caveats** | Same limitations. The split between NTUSER.DAT (network) and USRCLASS.DAT (local) is important — analyze BOTH hives. |

### 3.3 ShellBags — Windows XP

| Field | Details |
|---|---|
| **Registry Path** | `Software\Microsoft\Windows\ShellNoRoam\BagMRU` and `...\ShellNoRoam\Bags` |
| **Hive** | NTUSER.DAT |
| **Forensic Value** | Same as above but XP stored all ShellBags in NTUSER.DAT. |
| **Windows Versions** | Windows XP only |

---

## 4. Search History Artifacts

### 4.1 WordWheelQuery

| Field | Details |
|---|---|
| **Registry Path** | `Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery` |
| **Hive** | NTUSER.DAT |
| **Forensic Value** | Keywords searched from the Windows Explorer search bar / Start Menu search bar. |
| **Timestamp Behavior** | Key LastWrite = most recent search. MRUListEx provides temporal ordering. |
| **Data Format** | Binary values containing Unicode search terms. MRUListEx = 4-byte LE integer array. |
| **Windows Versions** | Windows 7 through 11 |
| **Caveats** | Only captures searches via the Explorer/Start Menu search interface. |

### 4.2 ACMru (Windows XP Search Assistant)

| Field | Details |
|---|---|
| **Registry Path** | `Software\Microsoft\Search Assistant\ACMru` |
| **Hive** | NTUSER.DAT |
| **Forensic Value** | Windows XP search terms. Subkeys: **5001** = Internet search, **5603** = Files and folders search (filename), **5604** = word/phrase in a file, **5647** = computers or people search. |
| **Timestamp Behavior** | Each subkey LastWrite = time of most recent search of that type. Value `000` = most recent term. |
| **Data Format** | REG_SZ string values. Numbered ascending (000 = most recent). |
| **Windows Versions** | Windows XP only |
| **Caveats** | Replaced by WordWheelQuery on Vista+. Legacy data may persist on upgraded systems. |

### 4.3 Explorer Bars FilesNamedMRU / ContainingTextMRU (Windows 2000/XP Legacy)

| Field | Details |
|---|---|
| **Registry Path** | `Software\Microsoft\Internet Explorer\Explorer Bars\{C4EE31F3-4768-11D2-BE5C-00A0C9A83DA1}\FilesNamedMRU` and `...\ContainingTextMRU` |
| **Hive** | NTUSER.DAT |
| **Forensic Value** | Windows 2000 era search MRU. FilesNamedMRU = filenames searched for. ContainingTextMRU = text content searched within files. |
| **Windows Versions** | Windows 2000, may persist on upgraded XP systems |
| **Caveats** | Very legacy. Only relevant for aged or upgraded systems. |

---

## 5. Microsoft Office Artifacts

### 5.1 Office File MRU

| Field | Details |
|---|---|
| **Registry Path** | `Software\Microsoft\Office\{version}\{app}\File MRU` |
| **Hive** | NTUSER.DAT |
| **Forensic Value** | Recently opened files per Office application (Word, Excel, PowerPoint, Access, Publisher). |
| **Timestamp Behavior** | Starting Office 2010+, each `Item N` value contains an embedded timestamp in `[T<hex_datetime>]` format (Win32 FILETIME, big-endian hex). Key LastWrite = last file opened. |
| **Data Format** | REG_SZ values named "Item 1", "Item 2", etc. Format: `[F00000000][T<datetime>][O00000000]*<filepath>`. `Max Display` DWORD controls UI display count but actual list may exceed it. |
| **Windows Versions** | Office 2007+ (Office 2003 used different format) |
| **Caveats** | Files opened via common dialog do NOT appear here (they go to OpenSavePidlMRU instead). Office uses its own file opening mechanism. Version numbers: 12.0 (2007), 14.0 (2010), 15.0 (2013), 16.0 (2016/2019/365). |

### 5.2 Office Place MRU

| Field | Details |
|---|---|
| **Registry Path** | `Software\Microsoft\Office\{version}\{app}\Place MRU` |
| **Hive** | NTUSER.DAT |
| **Forensic Value** | Recently accessed DIRECTORIES/locations from each Office application. Shows folders the user navigated to when opening/saving documents. |
| **Timestamp Behavior** | Same embedded timestamp format as File MRU. |
| **Data Format** | Same REG_SZ format as File MRU but with directory paths instead of file paths. |
| **Windows Versions** | Office 2010+ |
| **Caveats** | Only populated when user is NOT signed into a Live/Microsoft account. See User MRU for signed-in users. |

### 5.3 Office User MRU (Live Account / Microsoft 365)

| Field | Details |
|---|---|
| **Registry Path** | `Software\Microsoft\Office\{version}\{app}\User MRU\{LiveId_xxx}\File MRU` and `...\Place MRU` |
| **Hive** | NTUSER.DAT |
| **Forensic Value** | Same as File MRU and Place MRU but stored under a user-specific subkey when signed into a Microsoft account. The `LiveId_xxx` identifier ties MRU data to a specific Microsoft account. |
| **Timestamp Behavior** | Same as File MRU. |
| **Data Format** | Same as File MRU. |
| **Windows Versions** | Office 2013+ with Live account sign-in |
| **Caveats** | MRU data disappears from view when user signs out but reappears on sign-in. Multiple LiveId subkeys may exist for different accounts. |

### 5.4 Office TrustRecords

| Field | Details |
|---|---|
| **Registry Path** | `Software\Microsoft\Office\{version}\{app}\Security\Trusted Documents\TrustRecords` |
| **Hive** | NTUSER.DAT |
| **Forensic Value** | Records of documents where the user clicked "Enable Content" (enabling macros). Full file path + trust timestamp. Critical for malware investigations. |
| **Timestamp Behavior** | Each value contains a binary blob with a FILETIME timestamp of when trust was granted. Key LastWrite = most recent trust grant. |
| **Data Format** | Value names = full file paths (URL-encoded for network paths). Value data = binary blob containing FILETIME + trust flags. |
| **Windows Versions** | Office 2010+ |
| **Caveats** | Extremely valuable for macro malware investigations. Proves user explicitly enabled macros on a specific document at a specific time. |

### 5.5 Office Reading Locations (Word)

| Field | Details |
|---|---|
| **Registry Path** | `Software\Microsoft\Office\{version}\Word\Reading Locations` |
| **Hive** | NTUSER.DAT |
| **Forensic Value** | Records the cursor position and reading location when a Word document is closed. Subkeys are created per document. Proves the user had the document open and how far they read. |
| **Timestamp Behavior** | Each document subkey LastWrite = when document was last closed. Contains `Datetime` value with explicit timestamp. |
| **Data Format** | Subkeys per document. Values include `Position 1`, `Position 2` (cursor positioning), `Datetime` (string timestamp). |
| **Windows Versions** | Office 2013+ (version 15.0+) |
| **Caveats** | Created when document is closed, not when opened. Position data can prove how much of a document was actually viewed. |

### 5.6 Office BackstageInAppNavCache

| Field | Details |
|---|---|
| **Registry Path** | File system artifact, not registry. Located under Office app data directories. |
| **Forensic Value** | Records directory listings from the Office Backstage file browser. Contains full path, filename, and modification date (FILETIME) for all files/directories in each location navigated via Backstage. Includes SharePoint locations. |
| **Windows Versions** | Office 2016+ |
| **Caveats** | File system artifact, not a registry key. Included here because it complements Office MRU data and records directory paths no longer on disk. |

---

## 6. Browser & Internet Artifacts

### 6.1 Internet Explorer TypedURLs

| Field | Details |
|---|---|
| **Registry Path** | `Software\Microsoft\Internet Explorer\TypedURLs` |
| **Hive** | NTUSER.DAT |
| **Forensic Value** | Last ~50 URLs typed into the IE address bar. On Windows XP, also records paths typed into Windows Explorer address bar. |
| **Timestamp Behavior** | `url1` = most recent. Key LastWrite = time of most recent URL entry. See also TypedURLsTime for explicit timestamps. |
| **Data Format** | REG_SZ values named `url1`, `url2`, ... `url50`. New entries always become `url1`; older entries shift down. |
| **Windows Versions** | IE 4+ through IE 11 (all Windows versions XP through 10) |
| **Caveats** | Clearing IE browsing history DELETES this entire key. On XP, this key records Explorer address bar paths too; on Windows 7+ it does NOT (use TypedPaths instead). Auto-completed URLs are NOT recorded unless previously visited. |

### 6.2 Internet Explorer TypedURLsTime

| Field | Details |
|---|---|
| **Registry Path** | `Software\Microsoft\Internet Explorer\TypedURLsTime` |
| **Hive** | NTUSER.DAT |
| **Forensic Value** | Timestamps for each TypedURL entry. Values correspond 1:1 with TypedURLs (url1Time, url2Time, etc.). |
| **Timestamp Behavior** | Each value = FILETIME (8-byte binary) of when URL was typed. |
| **Data Format** | Binary (FILETIME). |
| **Windows Versions** | IE 10+ |
| **Caveats** | Only available on IE 10 and later. Deleted when browsing history is cleared. |

### 6.3 Internet Explorer Download Directory

| Field | Details |
|---|---|
| **Registry Path** | `Software\Microsoft\Internet Explorer\Download Directory` or `...\Main\Default Download Directory` |
| **Hive** | NTUSER.DAT |
| **Forensic Value** | Last directory used to save a downloaded file from IE. Reveals where user stores downloads. |
| **Timestamp Behavior** | Key LastWrite = last download location change. |
| **Data Format** | REG_SZ string with directory path. |
| **Windows Versions** | IE on all Windows versions |
| **Caveats** | Only stores the most recent download directory, not a history. |

---

## 7. Remote Access Artifacts

### 7.1 Terminal Server Client — Default (RDP MRU)

| Field | Details |
|---|---|
| **Registry Path** | `Software\Microsoft\Terminal Server Client\Default` |
| **Hive** | NTUSER.DAT |
| **Forensic Value** | Last 10 RDP connections (hostnames/IPs) made via mstsc.exe. MRU0 = most recent connection. |
| **Timestamp Behavior** | Key LastWrite = most recent RDP connection. MRU ordering (MRU0 = latest). |
| **Data Format** | REG_SZ values named `MRU0` through `MRU9`. Data = IP address or hostname of remote system. |
| **Windows Versions** | XP through 11 |
| **Caveats** | Only records successful connections. Critical for lateral movement investigation. |

### 7.2 Terminal Server Client — Servers

| Field | Details |
|---|---|
| **Registry Path** | `Software\Microsoft\Terminal Server Client\Servers` |
| **Hive** | NTUSER.DAT |
| **Forensic Value** | Complete history of ALL RDP connections ever made (not limited to 10 like Default). Each server has its own subkey. Contains `UsernameHint` (auto-fill username) and `CertHash` (server certificate thumbprint). |
| **Timestamp Behavior** | Each server subkey LastWrite = last connection to that server. |
| **Data Format** | Subkeys named by IP/hostname. Values: `UsernameHint` (REG_SZ), `CertHash` (binary = certificate thumbprint). |
| **Windows Versions** | XP through 11 |
| **Caveats** | More complete than Default key — no entry limit. UsernameHint reveals which account was used. CertHash can correlate to specific servers. |

### 7.3 PuTTY SSH Host Keys

| Field | Details |
|---|---|
| **Registry Path** | `Software\SimonTatham\PuTTY\SshHostKeys` |
| **Hive** | NTUSER.DAT |
| **Forensic Value** | SSH server fingerprints for all hosts connected to via PuTTY. Format: `algorithm@port:hostname` = fingerprint. |
| **Timestamp Behavior** | Key LastWrite = most recent SSH connection. |
| **Data Format** | REG_SZ values. Name format: `rsa2@22:192.168.1.1`. Data = host key fingerprint. |
| **Windows Versions** | Any (PuTTY is third-party) |
| **Caveats** | Only present if PuTTY was installed/used. SessionGopher tool can extract this data. |

### 7.4 PuTTY Sessions

| Field | Details |
|---|---|
| **Registry Path** | `Software\SimonTatham\PuTTY\Sessions` |
| **Hive** | NTUSER.DAT |
| **Forensic Value** | Saved PuTTY session configurations. Each subkey = one saved session with hostname, port, protocol, username, and connection settings. |
| **Timestamp Behavior** | Each session subkey LastWrite = last modification of that session config. |
| **Data Format** | Subkeys with multiple values (HostName, PortNumber, Protocol, UserName, etc.). |
| **Windows Versions** | Any (third-party) |

### 7.5 WinSCP Sessions

| Field | Details |
|---|---|
| **Registry Path** | `Software\Martin Prikryl\WinSCP 2\Sessions` |
| **Hive** | NTUSER.DAT |
| **Forensic Value** | Saved WinSCP sessions with hostname, username, protocol, and potentially obfuscated password. Reveals SFTP/SCP server connections. |
| **Timestamp Behavior** | Each session subkey LastWrite = last session modification. |
| **Data Format** | Subkeys per session. Values include HostName, UserName, Password (obfuscated unless master password set), FSProtocol. |
| **Windows Versions** | Any (third-party) |
| **Caveats** | Passwords can be deobfuscated if no master password is set (SessionGopher does this automatically). |

---

## 8. Network & Share Access Artifacts

### 8.1 MountPoints2

| Field | Details |
|---|---|
| **Registry Path** | `Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2` |
| **Hive** | NTUSER.DAT |
| **Forensic Value** | All mounted drives and network shares accessed by the user. Network shares appear as `##servername#sharename`. Volume GUIDs link to SYSTEM\MountedDevices. |
| **Timestamp Behavior** | Each subkey LastWrite = last time that mount point was accessed. |
| **Data Format** | Subkeys named as: volume GUIDs (e.g., `{xxxxxxxx-xxxx-...}`), drive letters, or network share paths (e.g., `##192.168.1.80#SharedFolder`). |
| **Windows Versions** | XP through 11 |
| **Caveats** | Critical for lateral movement detection (look for `C$`, `ADMIN$`, `IPC$` shares). Entries persist after shares are disconnected. Fast User Switching: USB insertion creates entries for ALL logged-on users, even background sessions. Absence of an entry does NOT prove the user didn't access the share. |

### 8.2 Map Network Drive MRU

| Field | Details |
|---|---|
| **Registry Path** | `Software\Microsoft\Windows\CurrentVersion\Explorer\Map Network Drive MRU` |
| **Hive** | NTUSER.DAT |
| **Forensic Value** | UNC paths of recently mapped network drives via the "Map Network Drive" dialog. |
| **Timestamp Behavior** | Key LastWrite = most recent drive mapping. MRUList provides ordering. |
| **Data Format** | REG_SZ values with UNC paths (e.g., `\\server\share`). MRUList = letter-based ordering. |
| **Windows Versions** | XP through 11 |
| **Caveats** | Only captures drives mapped via the GUI dialog, not `net use` commands. |

### 8.3 Network Persistent Connections

| Field | Details |
|---|---|
| **Registry Path** | `Network` (under HKCU root) |
| **Hive** | NTUSER.DAT |
| **Forensic Value** | Currently and previously mapped network drives with persistence. Each subkey = drive letter. Contains `RemotePath`, `UserName`, `ProviderName`. |
| **Timestamp Behavior** | Each drive letter subkey LastWrite = last connection/reconnection. |
| **Data Format** | Subkeys named by drive letter (E, F, Z, etc.). Values: `RemotePath` (REG_SZ = UNC path), `UserName` (REG_SZ), `ProviderName` (REG_SZ), `ConnectionType` (DWORD). |
| **Windows Versions** | XP through 11 |

### 8.4 NetworkList\Profiles

| Field | Details |
|---|---|
| **Registry Path** | `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles` |
| **Hive** | SOFTWARE (HKLM) |
| **Forensic Value** | History of all network connections (wired and wireless). Each profile subkey contains: `ProfileName` (SSID for wireless), `Description`, `NameType` (wired vs wireless), `DateCreated` and `DateLastConnected` (128-bit SYSTEMTIME). |
| **Timestamp Behavior** | `DateCreated` = first connection. `DateLastConnected` = last connection. Both are explicit SYSTEMTIME values (not key timestamps). |
| **Data Format** | GUID subkeys. Values: `ProfileName` (REG_SZ), `DateCreated` (REG_BINARY, 16 bytes = SYSTEMTIME), `DateLastConnected` (REG_BINARY, 16 bytes = SYSTEMTIME), `NameType` (DWORD: 6=wired, 71=wireless). |
| **Windows Versions** | Vista through 11 |
| **Caveats** | System-wide, not per-user. SYSTEMTIME values require decoding (year, month, day, hour, minute, second, millisecond). Not 100% reliable — Windows may not create/update entries for every connection. |

### 8.5 NetworkList\Signatures\Unmanaged

| Field | Details |
|---|---|
| **Registry Path** | `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged` |
| **Hive** | SOFTWARE (HKLM) |
| **Forensic Value** | Physical network identification data. `DefaultGatewayMac` correlates to specific routers/access points. Links to Profiles via ProfileGuid. |
| **Timestamp Behavior** | Subkey LastWrite = last connection event. |
| **Data Format** | Subkeys with values: `DefaultGatewayMac` (REG_BINARY = 6-byte MAC address), `DnsSuffix`, `FirstNetwork`, `ProfileGuid`. |
| **Windows Versions** | Vista through 11 |
| **Caveats** | Gateway MAC address can identify the specific physical network/router the system connected to — useful for geolocation. |

### 8.6 Tcpip Parameters Interfaces

| Field | Details |
|---|---|
| **Registry Path** | `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces` |
| **Hive** | SYSTEM |
| **Forensic Value** | IP configuration per network interface. Includes DHCP server address, assigned IP, subnet mask, lease obtained/expires times, DNS servers. |
| **Timestamp Behavior** | `LeaseObtainedTime` and `LeaseTerminatesTime` = explicit UNIX timestamps. |
| **Data Format** | GUID subkeys per interface. Values include `DhcpIPAddress`, `DhcpServer`, `DhcpSubnetMask`, `DhcpDefaultGateway`, `DhcpDhcpServerMacAddress`, `LeaseObtainedTime` (DWORD = Unix epoch), etc. |
| **Windows Versions** | XP through 11 |

---

## 9. Application Execution (File Access Evidence)

These artifacts primarily prove execution but contain file path/access data.

### 9.1 UserAssist

| Field | Details |
|---|---|
| **Registry Path** | `Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count` |
| **Hive** | NTUSER.DAT |
| **Forensic Value** | ROT13-encoded records of GUI programs and shortcuts launched. Contains: program path, run count, focus time, and last execution timestamp. |
| **Timestamp Behavior** | Each value contains an embedded FILETIME timestamp of last execution. Focus time in milliseconds shows how long the application was the active window. |
| **Data Format** | Value names: ROT13-encoded paths (e.g., `ehaqyy32.rkr` = `rundll32.exe`). Value data: 72-byte binary structure (Win7+) containing: session ID, run count, focus count, focus time (ms), last run time (FILETIME). GUID subkeys differentiate artifact types (e.g., `{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}` for executable runs). |
| **Windows Versions** | 2000 through 11 (XP = 16-byte structure, Vista+ = 72-byte) |
| **Caveats** | Only tracks GUI applications launched through Explorer shell. Command-line programs run via cmd.exe are NOT recorded. Zero Focus Time + non-zero Run Count = ambiguous (may be automated/preload, not user action). Automated processes like shell preloading generate entries. |

### 9.2 MuiCache

| Field | Details |
|---|---|
| **Registry Path** | `Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache` |
| **Hive** | USRCLASS.DAT (Vista+) or NTUSER.DAT (XP) |
| **Forensic Value** | Maps executable paths to their display names (from PE resource section). Two entries per executable: `<path>.FriendlyAppName` and `<path>.ApplicationCompany`. |
| **Timestamp Behavior** | Key LastWrite = last time any new executable was cached. Individual entries have NO timestamps (values stored directly in key, not as subkeys). |
| **Data Format** | REG_SZ values. Name = full executable path + `.FriendlyAppName` or `.ApplicationCompany`. Data = display name string. |
| **Windows Versions** | 2000 through 11 |
| **Caveats** | No per-entry timestamp. Persists after application uninstall. Only populated for GUI executables launched through Explorer. |

### 9.3 AppCompatCache (ShimCache)

| Field | Details |
|---|---|
| **Registry Path** | `SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache` |
| **Hive** | SYSTEM |
| **Forensic Value** | Tracks executables that exist on the system (and may have been run). Contains file path, file size, and last modification timestamp of the executable. |
| **Timestamp Behavior** | Timestamp in entries = last modification time of the FILE, not execution time. Key LastWrite = last system shutdown (data is flushed from RAM on shutdown). |
| **Data Format** | Single `AppCompatCache` REG_BINARY value containing a serialized list of entries. Format varies by Windows version. Requires specialized parsers (AppCompatCacheParser by Eric Zimmerman). |
| **Windows Versions** | XP through 11 (format changes per version) |
| **Caveats** | Data is maintained in RAM and only written to registry on shutdown/restart. Live system registry data is STALE. An execution flag exists on some versions but its reliability is debated. Best used as corroborating evidence, not sole proof of execution. |

### 9.4 BAM / DAM (Background/Desktop Activity Moderator)

| Field | Details |
|---|---|
| **Registry Path** | `SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\{SID}` (Win10 1809+) or `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}` (Win10 1709-1803) |
| **Hive** | SYSTEM |
| **Forensic Value** | Tracks background application execution with explicit timestamps. Full executable path + last execution FILETIME. |
| **Timestamp Behavior** | Each value data = FILETIME of last execution. |
| **Data Format** | Values named by full executable path (e.g., `\Device\HarddiskVolume3\Windows\System32\cmd.exe`). Data = binary with embedded FILETIME. |
| **Windows Versions** | Windows 10 v1709+ through 11 |
| **Caveats** | Data may be cleared on reboot on some builds. Limited retention period. DAM (Desktop Activity Moderator) is the desktop counterpart to BAM. |

---

## 10. Built-in Application MRUs

### 10.1 MS Paint Recent File List

| Field | Details |
|---|---|
| **Registry Path** | `Software\Microsoft\Windows\CurrentVersion\Applets\Paint\Recent File List` |
| **Hive** | NTUSER.DAT |
| **Forensic Value** | Files recently opened/saved with MS Paint. Full file paths. |
| **Timestamp Behavior** | Key LastWrite = most recent Paint file access. NO MRUList value — `File1` is always most recent, others shift down. |
| **Data Format** | REG_SZ values: `File1`, `File2`, `File3`, `File4` (up to 4 entries). Data = full file path. |
| **Windows Versions** | XP through 10 (Classic Paint) |
| **Caveats** | Key and subkeys not created until Paint is first used (also evidence of Paint execution). Windows 11 modern Paint uses a per-app hive under `%LocalAppData%\Packages\Microsoft.Paint_8wekyb3d8bbwe\...`. |

### 10.2 WordPad Recent File List

| Field | Details |
|---|---|
| **Registry Path** | `Software\Microsoft\Windows\CurrentVersion\Applets\Wordpad\Recent File List` |
| **Hive** | NTUSER.DAT |
| **Forensic Value** | Files recently opened with WordPad. Full file paths with MRU ordering. |
| **Timestamp Behavior** | Key LastWrite = most recent WordPad file access. |
| **Data Format** | REG_SZ values: `File1` (most recent), `File2`, etc. Data = full file path. |
| **Windows Versions** | XP through 11 |
| **Caveats** | No user-facing option to clear the list (unlike Office). Recent files do not appear instantly in registry — populated on application close or after delay. |

### 10.3 MMC Recent File List

| Field | Details |
|---|---|
| **Registry Path** | `Software\Microsoft\Microsoft Management Console\Recent File List` |
| **Hive** | NTUSER.DAT |
| **Forensic Value** | Recently opened .msc console files (Event Viewer, Disk Management, Services, etc.). Also includes custom MMCs created by the user. |
| **Timestamp Behavior** | Key LastWrite = last console closed. |
| **Data Format** | REG_SZ values with .msc file paths. |
| **Windows Versions** | XP through 11 |
| **Caveats** | Useful for investigating administrative actions. Can reveal if attacker used management tools. |

---

## 11. Third-Party Application MRUs

### 11.1 Adobe Acrobat/Reader Recent Files

| Field | Details |
|---|---|
| **Registry Path** | `Software\Adobe\Adobe Acrobat\{version}\AVGeneral\cRecentFiles` or `Software\Adobe\Acrobat Reader\{version}\AVGeneral\cRecentFiles` |
| **Hive** | NTUSER.DAT |
| **Forensic Value** | Recently opened PDF files. Subkeys `c1`, `c2`, `c3`, etc. each represent one recent file with path and access metadata. |
| **Timestamp Behavior** | Each subkey (c1, c2, etc.) LastWrite = when that file was accessed. |
| **Data Format** | Numbered subkeys. Values under each include file path, date accessed, and other metadata. |
| **Windows Versions** | Any (version-dependent: 5.0, 8.0, 9.0, 10.0, 11.0, DC, 2020, 2024) |
| **Caveats** | Version number in path changes per Acrobat version. DC and newer use different version strings. Selective deletion of individual entries is possible. |

### 11.2 Adobe MediaBrowser MRU

| Field | Details |
|---|---|
| **Registry Path** | `Software\Adobe\MediaBrowser\MRU` |
| **Hive** | NTUSER.DAT |
| **Forensic Value** | Recent media files browsed via Adobe's media browser component. |
| **Windows Versions** | Varies by Adobe product |

### 11.3 WinRAR ArcHistory

| Field | Details |
|---|---|
| **Registry Path** | `Software\WinRAR\ArcHistory` |
| **Hive** | NTUSER.DAT |
| **Forensic Value** | Recently opened archive files. Critical for data exfiltration investigations — shows which archives were created/opened. |
| **Timestamp Behavior** | Key LastWrite = last archive operation. |
| **Data Format** | REG_SZ values: `0`, `1`, `2`, `3` = archive file paths. |
| **Windows Versions** | Any (third-party) |

### 11.4 WinRAR Dialog Edit History

| Field | Details |
|---|---|
| **Registry Path** | `Software\WinRAR\DialogEditHistory\ArcName` and `...\ExtrPath` |
| **Hive** | NTUSER.DAT |
| **Forensic Value** | `ArcName` = archive names typed in dialogs. `ExtrPath` = extraction paths used. Shows where archives were extracted to. |
| **Timestamp Behavior** | Key LastWrite = last dialog interaction. |
| **Data Format** | REG_SZ values numbered 0, 1, 2... |
| **Windows Versions** | Any (third-party) |

### 11.5 7-Zip MRU

| Field | Details |
|---|---|
| **Registry Path** | `Software\7-Zip\FM` (File Manager settings) and `Software\7-Zip\Compression` |
| **Hive** | NTUSER.DAT |
| **Forensic Value** | 7-Zip file manager browsing history and recent archive paths. |
| **Windows Versions** | Any (third-party) |

---

## 12. Media Player Artifacts

### 12.1 Windows Media Player RecentFileList

| Field | Details |
|---|---|
| **Registry Path** | `Software\Microsoft\MediaPlayer\Player\RecentFileList` |
| **Hive** | NTUSER.DAT |
| **Forensic Value** | Recently played local media files. Full file paths. |
| **Timestamp Behavior** | Key LastWrite = last file played. |
| **Data Format** | REG_SZ values: `File0`, `File1`, etc. Data = full file path. |
| **Windows Versions** | XP through 10 (WMP 7+) |
| **Caveats** | Key is re-created when next file is opened even if previously deleted. May not be present in WMP 12 on some builds. |

### 12.2 Windows Media Player RecentURLList

| Field | Details |
|---|---|
| **Registry Path** | `Software\Microsoft\MediaPlayer\Player\RecentURLList` |
| **Hive** | NTUSER.DAT |
| **Forensic Value** | Recently streamed media URLs. Shows streaming activity. |
| **Timestamp Behavior** | Key LastWrite = last stream accessed. |
| **Data Format** | REG_SZ values with URLs. |
| **Windows Versions** | XP through 10 (WMP 6.4+) |

### 12.3 VLC Recent Files

| Field | Details |
|---|---|
| **Registry Path** | Not stored in registry. VLC stores recent files in `%APPDATA%\vlc\vlc-qt-interface.ini` under `[RecentsMRL]`. |
| **Forensic Value** | Recently played media files via VLC. |
| **Caveats** | File-system artifact, not registry. Included for completeness since VLC is ubiquitous. |

---

## 13. Encryption & Security Artifacts

### 13.1 EFS CurrentKeys

| Field | Details |
|---|---|
| **Registry Path** | `Software\Microsoft\Windows NT\CurrentVersion\EFS\CurrentKeys` |
| **Hive** | NTUSER.DAT |
| **Forensic Value** | Thumbprint (SHA-1 hash) of the current EFS encryption certificate used by this user. Proves EFS was configured. `CertificateHash` = DER-encoded certificate SHA-1. |
| **Timestamp Behavior** | Key LastWrite = last time EFS certificate was configured/changed. |
| **Data Format** | `CertificateHash` (REG_BINARY = SHA-1 hash), `Flag` (DWORD). |
| **Windows Versions** | 2000 through 11 |

### 13.2 EFS Recovery Policy

| Field | Details |
|---|---|
| **Registry Path** | `SOFTWARE\Policies\Microsoft\SystemCertificates\EFS` |
| **Hive** | SOFTWARE (HKLM) |
| **Forensic Value** | EFS recovery agent certificates configured via Group Policy. Subkeys: `Certificates`, `CRLs`, `CTLs`. |
| **Windows Versions** | 2000 through 11 |

### 13.3 BitLocker FVE Configuration

| Field | Details |
|---|---|
| **Registry Path** | `SOFTWARE\Policies\Microsoft\FVE` and `SYSTEM\CurrentControlSet\Control\FVE` |
| **Hive** | SOFTWARE, SYSTEM |
| **Forensic Value** | BitLocker configuration: encryption method, TPM settings, AD backup policy, recovery folder path. Does NOT store recovery keys directly (those go to AD, Microsoft account, or file). |
| **Timestamp Behavior** | Key LastWrite = last policy change. |
| **Data Format** | Multiple DWORD values: `EncryptionMethod`, `UseTPM`, `RequireActiveDirectoryBackup`, `ActiveDirectoryBackup`, `DefaultRecoveryFolderPath` (REG_SZ), etc. |
| **Windows Versions** | Vista through 11 |

### 13.4 User Certificate Store

| Field | Details |
|---|---|
| **Registry Path** | `Software\Microsoft\SystemCertificates\My\Certificates` |
| **Hive** | NTUSER.DAT |
| **Forensic Value** | Personal certificates installed for the user (EFS, code signing, S/MIME, etc.). Each subkey = certificate thumbprint. |
| **Timestamp Behavior** | Each certificate subkey LastWrite = installation/modification time. |
| **Data Format** | Subkeys named by thumbprint. Contains `Blob` value with DER-encoded certificate. |
| **Windows Versions** | 2000 through 11 |

---

## 14. Capability Access Manager

### 14.1 ConsentStore (Camera, Microphone, File System Access)

| Field | Details |
|---|---|
| **Registry Path** | `Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\{capability}` where capability = `webcam`, `microphone`, `broadFileSystemAccess`, `documentsLibrary`, `picturesLibrary`, `videosLibrary`, `location`, etc. |
| **Hive** | NTUSER.DAT (per-user) and SOFTWARE (system-wide) |
| **Forensic Value** | Tracks which applications accessed camera, microphone, file system, location, contacts, etc. NonPackaged subkey = third-party apps (most forensically interesting). Each app has `LastUsedTimeStart` and `LastUsedTimeStop` (FILETIME). |
| **Timestamp Behavior** | `LastUsedTimeStart` = FILETIME when app started using capability. `LastUsedTimeStop` = FILETIME when app stopped. Duration can be calculated. |
| **Data Format** | Capability subkeys contain `NonPackaged` and packaged app subkeys. NonPackaged key names = executable paths with `#` replacing `\`. Values: `LastUsedTimeStart` (QWORD FILETIME), `LastUsedTimeStop` (QWORD FILETIME), `Value` (REG_SZ: "Allow" or "Deny"). |
| **Windows Versions** | Windows 10 v1903+ through 11 |
| **Caveats** | Registry only stores MOST RECENT access per app. Windows 11 also writes historical data to `C:\ProgramData\Microsoft\Windows\CapabilityAccessManager\CapabilityAccessManager.db` (SQLite, 30-day retention). `broadFileSystemAccess` specifically tracks UWP apps with file system access. |

---

## 15. Printer Artifacts

### 15.1 PrinterPorts

| Field | Details |
|---|---|
| **Registry Path** | `Software\Microsoft\Windows NT\CurrentVersion\PrinterPorts` |
| **Hive** | NTUSER.DAT |
| **Forensic Value** | All printers installed/accessible to the user. |
| **Timestamp Behavior** | Key LastWrite = last printer configuration change. |
| **Data Format** | REG_SZ values. Name = printer name. Data = port and driver info. |
| **Windows Versions** | XP through 11 |

### 15.2 Devices (Default Printer)

| Field | Details |
|---|---|
| **Registry Path** | `Software\Microsoft\Windows NT\CurrentVersion\Windows` (value: `Device`) |
| **Hive** | NTUSER.DAT |
| **Forensic Value** | User's default printer. |
| **Data Format** | REG_SZ. Format: `PrinterName,DriverName,Port`. |
| **Windows Versions** | XP through 11 |

### 15.3 Printer Connections (Network Printers)

| Field | Details |
|---|---|
| **Registry Path** | `Printers\Connections` |
| **Hive** | NTUSER.DAT |
| **Forensic Value** | Network printers the user has connected to. Subkeys formatted as `,,servername,printername`. |
| **Timestamp Behavior** | Each connection subkey LastWrite = last connection. |
| **Windows Versions** | XP through 11 |

### 15.4 DevModePerUser / DevModes2

| Field | Details |
|---|---|
| **Registry Path** | `Printers\DevModePerUser` and `Printers\DevModes2` |
| **Hive** | NTUSER.DAT |
| **Forensic Value** | Per-user printer configuration preferences. DevModes2 = preference changes for network printers. Shows which printers the user customized settings for. |
| **Windows Versions** | XP through 11 |

---

## 16. Windows 11 New Artifacts

### 16.1 Notepad TabState (File System Artifact)

| Field | Details |
|---|---|
| **Location** | `%LocalAppData%\Packages\Microsoft.WindowsNotepad_8wekyb3d8bbwe\LocalState\TabState\` |
| **Forensic Value** | Windows 11 tabbed Notepad automatically saves tab contents to disk — even UNSAVED text. Each tab gets a `{GUID}.bin` file containing: for saved files: full file path + SHA-256 hash + content + last write time; for unsaved tabs: full text content as typed. No size limit on content preservation. |
| **Timestamp Behavior** | File modification time = last tab update. Embedded `last_write_time` for saved file tabs (may be 0 on newer versions). |
| **Data Format** | Binary files with CRC32 checksums. Offset 0x03: flag for saved (01) vs unsaved (00). Contains UnsavedChunk data with character-by-character insertions (or full paste blocks). |
| **Windows Versions** | Windows 11 only |
| **Caveats** | File system artifact, not registry. Included because it is one of the most significant new forensic artifacts. Can recover notes, pasted credentials, command drafts, IP lists. Deleted tab data may linger in file slack space. Can be disabled in Notepad settings. |

### 16.2 Notepad WindowState (File System Artifact)

| Field | Details |
|---|---|
| **Location** | `%LocalAppData%\Packages\Microsoft.WindowsNotepad_8wekyb3d8bbwe\LocalState\WindowState\` |
| **Forensic Value** | Notepad window state: total number of tabs, tab order, active tab, window size/position. Files never shrink — deleted tab data persists as slack. |
| **Windows Versions** | Windows 11 only |

### 16.3 Image File Execution Options (Notepad Redirect)

| Field | Details |
|---|---|
| **Registry Path** | `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe\0` |
| **Hive** | SOFTWARE (HKLM) |
| **Forensic Value** | `AppExecutionAliasRedirect = 1` causes classic `notepad.exe` to redirect to the modern Windows App version. Presence confirms Windows 11 Notepad modernization is active. |
| **Windows Versions** | Windows 11 |

---

## 17. Miscellaneous File Access Artifacts

### 17.1 Direct3D MostRecentApplication

| Field | Details |
|---|---|
| **Registry Path** | `Software\Microsoft\Direct3D\MostRecentApplication` |
| **Hive** | NTUSER.DAT |
| **Forensic Value** | Most recently launched application using Direct3D graphics API. |
| **Data Format** | Values include `Name` (REG_SZ = executable filename). |
| **Windows Versions** | XP through 11 |

### 17.2 Clipboard History Configuration

| Field | Details |
|---|---|
| **Registry Path** | `Software\Microsoft\Clipboard` (value: `EnableClipboardHistory`) |
| **Hive** | NTUSER.DAT |
| **Forensic Value** | Whether clipboard history was enabled (DWORD 1) or disabled (0, default). If enabled, user explicitly turned it on. Clipboard history itself is NOT stored in registry (stored in memory/cloud). |
| **Timestamp Behavior** | Key LastWrite = when setting was last changed. |
| **Data Format** | DWORD: 0 = disabled (default), 1 = enabled. |
| **Windows Versions** | Windows 10 v1809+ through 11 |
| **Caveats** | Does NOT store clipboard content — only the configuration setting. Actual clipboard data is in memory/cloud sync. Disabling clears all stored history. Policy override at `HKLM\SOFTWARE\Policies\Microsoft\Windows\System\AllowClipboardHistory`. |

### 17.3 Photos App (MediaDb - File System)

| Field | Details |
|---|---|
| **Location** | `%LocalAppData%\Packages\Microsoft.Windows.Photos_8wekyb3d8bbwe\LocalState\MediaDb.v1.sqlite` |
| **Forensic Value** | SQLite database tracking all images viewed, edited, and managed through the Photos app. |
| **Windows Versions** | Windows 10+ |
| **Caveats** | File system artifact, not registry. |

### 17.4 PowerShell ConsoleHost History (File System)

| Field | Details |
|---|---|
| **Location** | `%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt` |
| **Forensic Value** | Plain-text log of ALL PowerShell commands typed in interactive sessions. Up to 4096 commands. May contain file paths, credentials, and operational commands. |
| **Windows Versions** | Windows 10+ (PowerShell 5.0+ with PSReadLine) |
| **Caveats** | File system artifact, not registry. Only logs interactive console sessions — remote shells, Meterpreter, and terminal-less sessions are NOT logged. Can be disabled via `Set-PSReadlineOption -HistorySaveStyle SaveNothing`. Deletion of file is a strong anti-forensics indicator. |

### 17.5 SYSTEM MountedDevices

| Field | Details |
|---|---|
| **Registry Path** | `MountedDevices` (root of SYSTEM hive) |
| **Hive** | SYSTEM |
| **Forensic Value** | All volumes ever mounted on the system with persistent drive letter assignments. Maps volume GUIDs and drive letters to device identifiers. USB devices create entries here. |
| **Timestamp Behavior** | Key LastWrite = last mount event. |
| **Data Format** | Values named `\DosDevices\C:` etc. or `\??\Volume{GUID}`. Data = binary device identifier (for USB: contains VID/PID). |
| **Windows Versions** | 2000 through 11 |

### 17.6 Taskband (Taskbar Pinned Applications)

| Field | Details |
|---|---|
| **Registry Path** | `Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband` |
| **Hive** | NTUSER.DAT |
| **Forensic Value** | `Favorites` and `FavoritesResolve` values contain binary data about applications pinned to the taskbar. `IconStreams` contains taskbar icon settings. Reveals which applications the user intentionally pinned for frequent use. |
| **Data Format** | Binary blobs requiring specialized parsing. |
| **Windows Versions** | Windows 7 through 11 |

---

## Quick Reference: Artifacts by Hive

### NTUSER.DAT
| # | Artifact | Path (under HKCU / NTUSER.DAT) |
|---|---|---|
| 1 | RecentDocs | `Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs` |
| 2 | RunMRU | `Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` |
| 3 | TypedPaths | `Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths` |
| 4 | WordWheelQuery | `Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery` |
| 5 | FeatureUsage (all subkeys) | `Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\*` |
| 6 | RecentApps (Win10 1607-1709) | `Software\Microsoft\Windows\CurrentVersion\Search\RecentApps` |
| 7 | OpenSavePidlMRU | `...\Explorer\ComDlg32\OpenSavePidlMRU` |
| 8 | OpenSavePidlMRULegacy | `...\Explorer\ComDlg32\OpenSavePidlMRULegacy` |
| 9 | LastVisitedPidlMRU | `...\Explorer\ComDlg32\LastVisitedPidlMRU` |
| 10 | LastVisitedPidlMRULegacy | `...\Explorer\ComDlg32\LastVisitedPidlMRULegacy` |
| 11 | CIDSizeMRU | `...\Explorer\ComDlg32\CIDSizeMRU` |
| 12 | FirstFolder | `...\Explorer\ComDlg32\FirstFolder` |
| 13 | ShellBags (network) | `Software\Microsoft\Windows\Shell\BagMRU` + `Bags` |
| 14 | Office File MRU | `Software\Microsoft\Office\{ver}\{app}\File MRU` |
| 15 | Office Place MRU | `Software\Microsoft\Office\{ver}\{app}\Place MRU` |
| 16 | Office User MRU | `Software\Microsoft\Office\{ver}\{app}\User MRU\{LiveId}\*` |
| 17 | Office TrustRecords | `Software\Microsoft\Office\{ver}\{app}\Security\Trusted Documents\TrustRecords` |
| 18 | Office Reading Locations | `Software\Microsoft\Office\{ver}\Word\Reading Locations` |
| 19 | IE TypedURLs | `Software\Microsoft\Internet Explorer\TypedURLs` |
| 20 | IE TypedURLsTime | `Software\Microsoft\Internet Explorer\TypedURLsTime` |
| 21 | IE Download Directory | `Software\Microsoft\Internet Explorer\Download Directory` |
| 22 | RDP Default (MRU) | `Software\Microsoft\Terminal Server Client\Default` |
| 23 | RDP Servers (complete) | `Software\Microsoft\Terminal Server Client\Servers` |
| 24 | MountPoints2 | `Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2` |
| 25 | Map Network Drive MRU | `Software\Microsoft\Windows\CurrentVersion\Explorer\Map Network Drive MRU` |
| 26 | Network (persistent drives) | `Network` |
| 27 | UserAssist | `Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count` |
| 28 | Paint MRU | `Software\Microsoft\Windows\CurrentVersion\Applets\Paint\Recent File List` |
| 29 | WordPad MRU | `Software\Microsoft\Windows\CurrentVersion\Applets\Wordpad\Recent File List` |
| 30 | MMC MRU | `Software\Microsoft\Microsoft Management Console\Recent File List` |
| 31 | Adobe Acrobat MRU | `Software\Adobe\Adobe Acrobat\{ver}\AVGeneral\cRecentFiles` |
| 32 | Adobe Reader MRU | `Software\Adobe\Acrobat Reader\{ver}\AVGeneral\cRecentFiles` |
| 33 | WinRAR ArcHistory | `Software\WinRAR\ArcHistory` |
| 34 | WinRAR DialogEditHistory | `Software\WinRAR\DialogEditHistory\ArcName` + `ExtrPath` |
| 35 | WMP RecentFileList | `Software\Microsoft\MediaPlayer\Player\RecentFileList` |
| 36 | WMP RecentURLList | `Software\Microsoft\MediaPlayer\Player\RecentURLList` |
| 37 | EFS CurrentKeys | `Software\Microsoft\Windows NT\CurrentVersion\EFS\CurrentKeys` |
| 38 | User Certificates | `Software\Microsoft\SystemCertificates\My\Certificates` |
| 39 | CapabilityAccessManager | `Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\*` |
| 40 | PrinterPorts | `Software\Microsoft\Windows NT\CurrentVersion\PrinterPorts` |
| 41 | Default Printer | `Software\Microsoft\Windows NT\CurrentVersion\Windows` (Device value) |
| 42 | Printer Connections | `Printers\Connections` |
| 43 | Printer DevModePerUser | `Printers\DevModePerUser` |
| 44 | PuTTY SSH Host Keys | `Software\SimonTatham\PuTTY\SshHostKeys` |
| 45 | PuTTY Sessions | `Software\SimonTatham\PuTTY\Sessions` |
| 46 | WinSCP Sessions | `Software\Martin Prikryl\WinSCP 2\Sessions` |
| 47 | Clipboard History Config | `Software\Microsoft\Clipboard` |
| 48 | Direct3D MostRecentApp | `Software\Microsoft\Direct3D\MostRecentApplication` |
| 49 | Taskband | `Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband` |
| 50 | StartPage2 ProgramsCache | `Software\Microsoft\Windows\CurrentVersion\Explorer\StartPage2` |
| 51 | XP Search ACMru | `Software\Microsoft\Search Assistant\ACMru` |
| 52 | XP Explorer Bars Search | `Software\Microsoft\Internet Explorer\Explorer Bars\{CLSID}\FilesNamedMRU` |

### USRCLASS.DAT
| # | Artifact | Path |
|---|---|---|
| 53 | ShellBags (local) | `Local Settings\Software\Microsoft\Windows\Shell\BagMRU` + `Bags` |
| 54 | MuiCache | `Local Settings\Software\Microsoft\Windows\Shell\MuiCache` |

### SYSTEM Hive
| # | Artifact | Path |
|---|---|---|
| 55 | AppCompatCache | `CurrentControlSet\Control\Session Manager\AppCompatCache` |
| 56 | BAM/DAM | `CurrentControlSet\Services\bam\State\UserSettings\{SID}` |
| 57 | MountedDevices | `MountedDevices` |
| 58 | Tcpip Interfaces | `CurrentControlSet\Services\Tcpip\Parameters\Interfaces` |

### SOFTWARE Hive (HKLM)
| # | Artifact | Path |
|---|---|---|
| 59 | NetworkList Profiles | `Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles` |
| 60 | NetworkList Signatures | `Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged` |
| 61 | BitLocker FVE Config | `Policies\Microsoft\FVE` |
| 62 | EFS Recovery Policy | `Policies\Microsoft\SystemCertificates\EFS` |
| 63 | CapabilityAccessManager (system) | `Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\*` |

### Amcache.hve
| # | Artifact | Path |
|---|---|---|
| 64 | Amcache | `Root\InventoryApplicationFile` (Win10+) or `Root\File` (Win8) |

---

## Key File System Artifacts (Not Registry, But Critical Companions)

| # | Artifact | Location |
|---|---|---|
| 65 | PowerShell History | `%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt` |
| 66 | Notepad TabState (Win11) | `%LocalAppData%\Packages\Microsoft.WindowsNotepad_8wekyb3d8bbwe\LocalState\TabState\` |
| 67 | Notepad WindowState (Win11) | Same base path + `\WindowState\` |
| 68 | Photos MediaDb | `%LocalAppData%\Packages\Microsoft.Windows.Photos_8wekyb3d8bbwe\LocalState\MediaDb.v1.sqlite` |
| 69 | VLC Recent Files | `%APPDATA%\vlc\vlc-qt-interface.ini` |
| 70 | Office BackstageInAppNavCache | Under Office app data directories |
| 71 | CapabilityAccessManager.db (Win11) | `C:\ProgramData\Microsoft\Windows\CapabilityAccessManager\CapabilityAccessManager.db` |
| 72 | FileZilla Sessions | `%APPDATA%\FileZilla\sitemanager.xml` |
| 73 | RDP Bitmap Cache | `%LocalAppData%\Microsoft\Terminal Server Client\Cache\` |
| 74 | Default.rdp | `%USERPROFILE%\Documents\Default.rdp` |

---

## Recommended Tools

| Tool | Author | Purpose |
|---|---|---|
| **Registry Explorer** | Eric Zimmerman | GUI registry viewer with bookmarks/plugins |
| **RECmd** | Eric Zimmerman | Command-line registry parser (Kroll_Batch: 100+ NTUSER keys) |
| **ShellBags Explorer** | Eric Zimmerman | Dedicated ShellBag analysis |
| **AppCompatCacheParser** | Eric Zimmerman | ShimCache parsing |
| **RegRipper 4.0** | Harlan Carvey | Plugin-based automated registry extraction |
| **SessionGopher** | Brandon Arvanaghi | Extract PuTTY/WinSCP/FileZilla/RDP sessions |
| **KAPE** | Eric Zimmerman | Live acquisition + artifact parsing |
| **Autopsy** | Basis Technology | Full forensic suite with registry modules |
| **Velociraptor** | Rapid7 | DFIR platform with registry artifact collectors |
| **RegSeek** | Community | 148-artifact reference database: https://regseek.github.io/ |

---

## Sources

- [Cyber Triage - Windows Registry Forensics Cheat Sheet 2025](https://www.cybertriage.com/blog/windows-registry-forensics-cheat-sheet-2025/)
- [Cyber Triage - NTUSER.DAT Forensics Analysis 2026](https://www.cybertriage.com/blog/ntuser-dat-forensics-analysis-2026/)
- [SANS - OpenSaveMRU and LastVisitedMRU](https://www.sans.org/blog/opensavemru-and-lastvisitedmru)
- [SANS - Windows Forensic Analysis Poster](https://www.sans.org/posters/windows-forensic-analysis)
- [SANS - Windows 7 ShellBags](https://www.sans.org/blog/computer-forensic-artifacts-windows-7-shellbags)
- [Magnet Forensics - Forensic Analysis of Windows Shellbags](https://www.magnetforensics.com/blog/forensic-analysis-of-windows-shellbags/)
- [Magnet Forensics - UserAssist Forensic Artifacts](https://www.magnetforensics.com/blog/artifact-profile-userassist/)
- [Magnet Forensics - MuiCache](https://www.magnetforensics.com/blog/forensic-analysis-of-muicache-files-in-windows/)
- [Magnet Forensics - RDP Artifacts in Incident Response](https://www.magnetforensics.com/blog/rdp-artifacts-in-incident-response/)
- [CrowdStrike - FeatureUsage for Taskbar Forensics](https://www.crowdstrike.com/en-us/blog/how-to-employ-featureusage-for-windows-10-taskbar-forensics/)
- [Group-IB - FeatureUsage: Reconstructing User Activity](https://blog.group-ib.com/featureusage)
- [ForenSafe - Multiple artifact blog posts](https://www.forensafe.com/blogs/)
- [Forensics.wiki - List of Windows MRU Locations](https://forensics.wiki/list_of_windows_mru_locations/)
- [RegSeek - 148 Registry Artifacts Database](https://regseek.github.io/)
- [Andrea Fortuna - Windows Registry in Forensic Analysis](https://andreafortuna.org/2017/10/18/windows-registry-in-forensic-analysis/)
- [Harlan Carvey - Windows Incident Response Blog](http://windowsir.blogspot.com/)
- [Securelist (Kaspersky) - Forensic Artifacts in Windows 11](https://securelist.com/forensic-artifacts-in-windows-11/117680/)
- [Mandiant/Google Cloud - Digging Up the Past: Windows Registry Forensics Revisited](https://cloud.google.com/blog/topics/threat-intelligence/digging-up-the-past-windows-registry-forensics-revisited/)
- [Cyber Sundae DFIR - Capability Access Manager Forensics in Windows 11](https://medium.com/@cyber.sundae.dfir/capability-access-manager-forensics-in-windows-11-f586ef8aac79)
- [HawkEye Forensic - Complete Guide](https://hawkeyeforensic.com/windows-registry-forensics-a-complete-guide-to-windows-forensic-investigation/)
- [GIAC - Windows ShellBag Forensics in Depth](https://www.giac.org/paper/gcfa/9576/windows-shellbag-forensics-in-depth/128522)
- [FireEye/Mandiant - Using the Registry to Discover Unix Systems and Jump Boxes](https://www.fireeye.com/blog/threat-research/2017/03/using_the_registryt.html)
- [Sophos - PowerShell Command History Forensics](https://community.sophos.com/sophos-labs/b/blog/posts/powershell-command-history-forensics)
- [ElcomSoft - Investigating Windows Registry](https://blog.elcomsoft.com/2026/02/investigating-windows-registry/)
- [Shlomi Boutnaru - CIDSizeMRU](https://medium.com/@boutnaru/the-windows-forensic-journey-cidsizemru-50b582ca2240)
