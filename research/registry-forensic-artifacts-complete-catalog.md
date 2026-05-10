# Windows Registry Forensic Artifacts: The Definitive Catalog

**Comprehensive Reference for Building a Forensic Registry Parser**

**Date:** 2026-03-27
**Purpose:** Complete catalog of every known forensic artifact in the Windows Registry, organized by hive, with exact paths, value names, data types, binary structures, parsing quirks, and implementation references.

---

## Table of Contents

1. [Registry Fundamentals](#1-registry-fundamentals)
2. [SYSTEM Hive Artifacts](#2-system-hive-artifacts)
3. [SOFTWARE Hive Artifacts](#3-software-hive-artifacts)
4. [NTUSER.DAT Artifacts](#4-ntuser-dat-artifacts)
5. [USRCLASS.DAT Artifacts](#5-usrclass-dat-artifacts)
6. [SAM Hive Artifacts](#6-sam-hive-artifacts)
7. [SECURITY Hive Artifacts](#7-security-hive-artifacts)
8. [Amcache.hve Artifacts](#8-amcache-hve-artifacts)
9. [BCD (Boot Configuration Data)](#9-bcd-boot-configuration-data)
10. [Other Hives](#10-other-hives)
11. [References and Sources](#11-references-and-sources)

---

## 1. Registry Fundamentals

### 1.1 Hive File Locations

| Hive | File Path | Mount Point |
|------|-----------|-------------|
| SYSTEM | `%SystemRoot%\System32\config\SYSTEM` | `HKLM\SYSTEM` |
| SOFTWARE | `%SystemRoot%\System32\config\SOFTWARE` | `HKLM\SOFTWARE` |
| SAM | `%SystemRoot%\System32\config\SAM` | `HKLM\SAM` |
| SECURITY | `%SystemRoot%\System32\config\SECURITY` | `HKLM\SECURITY` |
| DEFAULT | `%SystemRoot%\System32\config\DEFAULT` | `HKU\.DEFAULT` |
| NTUSER.DAT | `%UserProfile%\NTUSER.DAT` | `HKU\{SID}` |
| USRCLASS.DAT | `%UserProfile%\AppData\Local\Microsoft\Windows\UsrClass.dat` | `HKU\{SID}_Classes` |
| Amcache.hve | `%SystemRoot%\AppCompat\Programs\Amcache.hve` | Not mounted in standard registry |
| BCD | `\Boot\BCD` (BIOS) or `\EFI\Microsoft\Boot\BCD` (UEFI) | `HKLM\BCD00000000` |
| COMPONENTS | `%SystemRoot%\System32\config\COMPONENTS` | `HKLM\COMPONENTS` |
| DRIVERS | `%SystemRoot%\System32\config\DRIVERS` | `HKLM\DRIVERS` |

### 1.2 Registry Binary Format (REGF)

The registry is stored in REGF (Registry File) format. Key structural elements:

- **REGF Header** (0x1000 bytes): Signature "regf" at offset 0, sequence numbers, last written timestamp, hive version, root cell offset
- **Hive Bins (HBIN)**: 0x1000-byte aligned blocks. Signature "hbin" at offset 0, offset from start of hive data, size of bin
- **Cells**: Variable-length structures within HBINs. Positive size = unallocated (deleted), negative size = allocated
- **Key Nodes (NK)**: Signature "nk", contain key name, class name offset, number of subkeys/values, timestamps, security descriptor offset
- **Value Nodes (VK)**: Signature "vk", contain value name, data type, data size, data offset
- **Key LastWriteTime**: 8-byte FILETIME timestamp on every key node; updated when key or any of its values are modified

**Reference implementation:** [libregf by Joachim Metz](https://github.com/libyal/libregf), [msuhanov/regf format spec](https://github.com/msuhanov/regf/blob/master/Windows%20registry%20file%20format%20specification.md)

### 1.3 Common Data Types

| Type ID | Name | Description |
|---------|------|-------------|
| 0 (REG_NONE) | None | No defined value type |
| 1 (REG_SZ) | String | Null-terminated Unicode string |
| 2 (REG_EXPAND_SZ) | Expandable String | Contains environment variable references (e.g., `%SystemRoot%`) |
| 3 (REG_BINARY) | Binary | Raw binary data |
| 4 (REG_DWORD) | DWORD | 32-bit unsigned integer (little-endian) |
| 5 (REG_DWORD_BIG_ENDIAN) | DWORD BE | 32-bit unsigned integer (big-endian) — rare |
| 7 (REG_MULTI_SZ) | Multi-String | Sequence of null-terminated strings, terminated by empty string |
| 11 (REG_QWORD) | QWORD | 64-bit unsigned integer (little-endian) |

### 1.4 Timestamp Formats Used in Registry Values

| Format | Size | Description |
|--------|------|-------------|
| FILETIME | 8 bytes | 64-bit value, 100-nanosecond intervals since January 1, 1601 UTC (little-endian) |
| SYSTEMTIME | 16 bytes | 8 x 16-bit values: Year, Month, DayOfWeek, Day, Hour, Minute, Second, Milliseconds |
| FAT Date/Time | 4 bytes | 2 bytes date + 2 bytes time, 2-second resolution (used in shell items) |
| Unix timestamp | 4 bytes | Seconds since January 1, 1970 UTC |

---

## 2. SYSTEM Hive Artifacts

### 2.1 CurrentControlSet Determination (Select Key)

| Field | Details |
|-------|---------|
| **Registry Path** | `SYSTEM\Select` |
| **Values** | `Current` (DWORD), `Default` (DWORD), `Failed` (DWORD), `LastKnownGood` (DWORD) |
| **Forensic Value** | Determines which ControlSet (e.g., `ControlSet001`) was active at last boot. The `Current` value maps to the ControlSet that was loaded. During dead-disk forensics, `CurrentControlSet` does not exist; you must read `Select\Current` to find the active control set number. |
| **Data Format** | DWORD value. E.g., `Current = 1` means `ControlSet001` was active. |
| **Windows Versions** | NT 3.1 through 11 |
| **Parsing Notes** | Always resolve `CurrentControlSet` references through this key first. If `Current = 1`, replace `CurrentControlSet` with `ControlSet001` in all paths. |

### 2.2 Computer Name

| Field | Details |
|-------|---------|
| **Registry Path** | `SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName` |
| **Value** | `ComputerName` (REG_SZ) |
| **Forensic Value** | The NetBIOS computer name assigned to the system. |
| **Windows Versions** | NT 3.1 through 11 |

**Additional path:** `SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName` (the currently active name, may differ from ComputerName if a rename is pending reboot).

### 2.3 Timezone Information

| Field | Details |
|-------|---------|
| **Registry Path** | `SYSTEM\CurrentControlSet\Control\TimeZoneInformation` |
| **Key Values** | `TimeZoneKeyName` (REG_SZ — e.g., "Eastern Standard Time"), `Bias` (DWORD — minutes offset from UTC), `ActiveTimeBias` (DWORD — current active bias including DST), `StandardBias` (DWORD), `DaylightBias` (DWORD), `StandardStart` (REG_BINARY — SYSTEMTIME), `DaylightStart` (REG_BINARY — SYSTEMTIME), `StandardName` (REG_SZ), `DaylightName` (REG_SZ) |
| **Forensic Value** | Critical for timeline analysis. All registry key LastWriteTime values are in UTC, but some file system timestamps and log entries may be in local time. This key establishes the system's configured timezone. |
| **Data Format** | `Bias` = total minutes difference from UTC (positive = west of UTC). `ActiveTimeBias` = current active offset including any DST adjustment. `StandardStart`/`DaylightStart` = 16-byte SYSTEMTIME structures defining when DST transitions occur. |
| **Windows Versions** | NT 3.1 through 11 |
| **Parsing Notes** | Key LastWriteTime indicates when timezone was last changed. If no `TimeZoneKeyName` value exists (pre-Vista), use `StandardName` to identify the timezone. |

### 2.4 Last Shutdown Time

| Field | Details |
|-------|---------|
| **Registry Path** | `SYSTEM\CurrentControlSet\Control\Windows` |
| **Value** | `ShutdownTime` (REG_BINARY, 8 bytes) |
| **Forensic Value** | The last clean shutdown time of the operating system. |
| **Data Format** | 8-byte Windows FILETIME (little-endian, UTC). |
| **Windows Versions** | XP through 11 |
| **Parsing Notes** | This is only updated on clean shutdown. A hard power-off or crash will not update this value. Compare with event logs for consistency. |

### 2.5 Services

| Field | Details |
|-------|---------|
| **Registry Path** | `SYSTEM\CurrentControlSet\Services\{ServiceName}` |
| **Key Values** | See table below |
| **Forensic Value** | Critical for persistence detection, malware analysis, and understanding system configuration. Each subkey under Services represents a service or driver. |
| **Windows Versions** | NT 3.1 through 11 |

**Key values per service:**

| Value Name | Type | Description |
|------------|------|-------------|
| `ImagePath` | REG_EXPAND_SZ | Path to the executable or driver. For svchost-hosted services, this is `%SystemRoot%\system32\svchost.exe -k {group}` |
| `Start` | REG_DWORD | Start type: 0=Boot, 1=System, 2=Automatic, 3=Manual, 4=Disabled |
| `Type` | REG_DWORD | Service type: 0x01=Kernel driver, 0x02=File system driver, 0x10=Own process, 0x20=Share process, 0x100=Interactive |
| `ObjectName` | REG_SZ | Account under which the service runs (e.g., `LocalSystem`, `NT AUTHORITY\NetworkService`) |
| `DisplayName` | REG_SZ | Human-readable service name |
| `Description` | REG_SZ | Service description |
| `Group` | REG_SZ | Load ordering group |
| `DependOnService` | REG_MULTI_SZ | Services this service depends on |
| `FailureActions` | REG_BINARY | Recovery actions configuration (see binary structure below) |
| `FailureCommand` | REG_SZ | Command to run on failure (if configured) |
| `Parameters\ServiceDLL` | REG_EXPAND_SZ | For svchost-hosted services: path to the DLL implementing the service |

**FailureActions Binary Structure (SERVICE_FAILURE_ACTIONS):**

| Offset | Size | Description |
|--------|------|-------------|
| 0 | 4 bytes | `dwResetPeriod` — seconds after which to reset failure count (0 = never) |
| 4 | 4 bytes | Offset to `lpRebootMsg` string (0 if none) |
| 8 | 4 bytes | Offset to `lpCommand` string (0 if none) |
| 12 | 4 bytes | `cActions` — number of SC_ACTION structures following |
| 16+ | 8 bytes each | Array of SC_ACTION: Type (4 bytes DWORD: 0=None, 1=Restart, 2=Reboot, 3=RunCommand) + Delay (4 bytes DWORD: milliseconds) |

**Forensic red flags:**
- `ImagePath` pointing to unusual locations (e.g., `%TEMP%`, user directories)
- `ServiceDLL` pointing to non-system DLLs
- Services with `Type = 0x10` or `0x20` and `Start = 2` (auto-start) that are not recognized
- `ObjectName = LocalSystem` for unknown services (highest privilege)

**Reference implementations:** [Eric Zimmerman's RECmd](https://github.com/EricZimmerman/RECmd), [RegRipper services plugin](https://github.com/keydet89/RegRipper4.0)

### 2.6 AppCompatCache (ShimCache)

| Field | Details |
|-------|---------|
| **Registry Path** | **XP 32-bit:** `SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatibility\AppCompatCache`; **XP 64-bit/Server 2003+:** `SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache\AppCompatCache` |
| **Value** | `AppCompatCache` (REG_BINARY) |
| **Forensic Value** | Tracks executables that were present on the system (and potentially executed). Contains file path, last modification timestamp of the file, and on some versions an execution flag. Data is maintained in kernel memory and flushed to registry only on clean shutdown/reboot. |
| **Windows Versions** | XP through 11 (format differs per version) |

**Binary Format by Windows Version:**

#### Windows XP 32-bit

| Field | Offset | Size | Description |
|-------|--------|------|-------------|
| Header Signature | 0 | 4 bytes | `0xDEADBEEF` |
| Number of entries | 4 | 4 bytes | DWORD, max 96 |
| LRU array | 8 | 384 bytes | 96 x 4-byte indexes |
| Entries | 400 | 552 bytes each | See entry format below |

**XP 32-bit Entry (552 bytes):**

| Offset | Size | Description |
|--------|------|-------------|
| 0 | 528 bytes | File path (Unicode, MAX_PATH x 2, null-padded) |
| 528 | 8 bytes | Last modification time (FILETIME) |
| 536 | 8 bytes | File size (QWORD) |
| 544 | 8 bytes | Last update time (FILETIME) — actually indicates execution/cache time |

#### Windows XP 64-bit / Server 2003

- Header begins with a 4-byte signature
- Max 512 entries
- Entry size: 32 bytes (64-bit) or 24 bytes (32-bit)
- Each entry contains: path length, path offset (variable), last modification time (FILETIME), file size

#### Windows Vista / 7

- Header: 4-byte signature, followed by entry count
- Max 1024 entries
- Each entry: path length (WORD), max path length (WORD), path offset (DWORD/QWORD), last modification time (FILETIME), insert/execution flags (DWORD)
- **Insert Flag**: When set, provides evidence of execution (but debated reliability)

#### Windows 8.x

- Header: 128 bytes, contains signature and entry count
- Entries are variable-length
- **Entry format (EntryWin8):**

| Offset | Size | Description |
|--------|------|-------------|
| 0 | 4 bytes | Signature |
| 4 | 4 bytes | Unknown |
| 8 | 4 bytes | Entry size (DWORD) |
| 12 | 2 bytes | Path size (WORD) — byte count of path string |
| 14 | variable | Path (UTF-16LE string) |
| 14+PathSize | 8 bytes | Last modification time (FILETIME) |
| +8 | 4 bytes | Data size |
| +4 | variable | Data |

#### Windows 10 / 11

- Header: **52 bytes**, signature **"10ts"** (bytes: `31 30 74 73`), max 1024 entries
- Entries are variable-length, each starts with its own "10ts" signature

| Offset | Size | Description |
|--------|------|-------------|
| 0 | 4 bytes | Signature ("10ts") |
| 4 | 4 bytes | Unknown |
| 8 | 4 bytes | Entry length (total including header) |
| 12 | 2 bytes | Path length (bytes) |
| 14 | variable | Path (UTF-16LE string) |
| 14+PathLen | 8 bytes | Last modification time (FILETIME) |
| +8 | 4 bytes | Data size |
| +4 | variable | Data content |
| last 4 | 4 bytes | **Execution indicator**: `01 00 00 00` = high likelihood of execution (non-native binaries only). NOT definitive. |

**Key parsing quirks:**
- Live registry data is STALE; in-memory data is more current
- On Windows 10+, the "execution indicator" in the last 4 bytes has false negatives (executed programs may show 0x00000000)
- Always parse ALL ControlSets — entries may differ between sets
- ShimCache entries are ordered; first entry = most recently added

**Reference implementations:** [Eric Zimmerman's AppCompatCacheParser](https://github.com/EricZimmerman/AppCompatCacheParser), [Mandiant ShimCacheParser.py](https://github.com/mandiant/ShimCacheParser), [libyal/winreg-kb](https://github.com/libyal/winreg-kb)

### 2.7 BAM (Background Activity Moderator) and DAM

| Field | Details |
|-------|---------|
| **Registry Path** | **Win10 1709-1803:** `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}`; **Win10 1809+:** `SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\{SID}`; **DAM:** Same paths under `dam` instead of `bam` |
| **Value Names** | Full executable paths (REG_BINARY) |
| **Forensic Value** | Proves program execution with user attribution (SID-keyed) and last execution timestamp. One of few artifacts that simultaneously proves execution AND identifies the responsible user. |
| **Data Format** | First 8 bytes = Windows FILETIME (little-endian, UTC) representing last execution time. Remaining bytes are unknown/padding. |
| **Windows Versions** | Windows 10 1709+ and Windows 11 |
| **Parsing Notes** | Entries expire after ~7 days of inactivity. Console-only applications may not appear. Applications from network shares/USB may not produce entries. DAM is only populated on devices supporting Connected Standby (tablets/mobile). Timestamps may vary by several minutes from actual execution time. |

**Reference:** [Velociraptor Windows.Forensics.Bam](https://docs.velociraptor.app/artifact_references/pages/windows.forensics.bam/)

### 2.8 Network Interfaces

| Field | Details |
|-------|---------|
| **Registry Path** | `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}` |
| **Key Values** | `DhcpIPAddress` (REG_SZ), `DhcpSubnetMask` (REG_SZ), `DhcpDefaultGateway` (REG_MULTI_SZ), `DhcpServer` (REG_SZ), `DhcpNameServer` (REG_SZ), `LeaseObtainedTime` (REG_DWORD — Unix timestamp), `LeaseTerminatesTime` (REG_DWORD — Unix timestamp), `IPAddress` (REG_MULTI_SZ — static IP), `SubnetMask` (REG_MULTI_SZ — static mask), `DefaultGateway` (REG_MULTI_SZ — static gateway), `NameServer` (REG_SZ — static DNS), `Domain` (REG_SZ) |
| **Forensic Value** | Historical IP configuration for each network adapter (identified by GUID). DHCP lease times establish when the system was connected to a specific network. |
| **Windows Versions** | 2000 through 11 |
| **Parsing Notes** | Interface GUIDs can be correlated with NetworkList profiles. `LeaseObtainedTime` and `LeaseTerminatesTime` are 32-bit Unix timestamps (seconds since 1970-01-01). |

### 2.9 USB Device History

#### 2.9.1 USBSTOR

| Field | Details |
|-------|---------|
| **Registry Path** | `SYSTEM\CurrentControlSet\Enum\USBSTOR\{Ven_xxx&Prod_xxx&Rev_xxx}\{SerialNumber}` |
| **Key Values** | `FriendlyName` (REG_SZ), `HardwareID` (REG_MULTI_SZ), `ParentIdPrefix` (REG_SZ), `ContainerID` (REG_SZ), `ClassGUID` (REG_SZ), `Service` (REG_SZ), `Driver` (REG_SZ) |
| **Forensic Value** | Master list of USB mass storage devices ever connected. Device subkey names encode Vendor, Product, Revision. Serial number subkey uniquely identifies a physical device. |
| **Windows Versions** | XP through 11 |

**Timestamp extraction (Win7+):**

| Property GUID Path | Description |
|---------------------|-------------|
| `Properties\{83da6326-97a6-4088-9453-a1923f573b29}\0064\(Default)` | First install date (FILETIME) |
| `Properties\{83da6326-97a6-4088-9453-a1923f573b29}\0065\(Default)` | First insert date (FILETIME) |
| `Properties\{83da6326-97a6-4088-9453-a1923f573b29}\0066\(Default)` | Last connected timestamp (FILETIME) |
| `Properties\{83da6326-97a6-4088-9453-a1923f573b29}\0067\(Default)` | Last removal timestamp (FILETIME) |

**Parsing notes:**
- If the second character of the serial number is `&`, the device did not report a unique hardware serial number (Windows generated it)
- The `ParentIdPrefix` value links to MountedDevices entries
- USBSTOR subkey LastWriteTime = timestamp of last device connection (first attach during last boot)

#### 2.9.2 USB (All USB Devices)

| Field | Details |
|-------|---------|
| **Registry Path** | `SYSTEM\CurrentControlSet\Enum\USB\VID_{xxxx}&PID_{xxxx}\{SerialOrInstanceID}` |
| **Forensic Value** | Tracks ALL USB devices (not just storage), including keyboards, mice, webcams, Bluetooth adapters. Contains VID (Vendor ID) and PID (Product ID) for device identification. |
| **Windows Versions** | XP through 11 |

#### 2.9.3 WpdBusEnumRoot (Windows Portable Devices)

| Field | Details |
|-------|---------|
| **Registry Path** | `SYSTEM\CurrentControlSet\Enum\SWD\WPDBUSENUM\{identifier}` |
| **Forensic Value** | Tracks portable devices (smartphones, cameras, media players) that use MTP/PTP protocols. |
| **Windows Versions** | Vista through 11 |

#### 2.9.4 DeviceClasses

| Field | Details |
|-------|---------|
| **Registry Path** | `SYSTEM\CurrentControlSet\Control\DeviceClasses\{53f56307-b6bf-11d0-94f2-00a0c91efb8b}` (disk devices), `{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}` (volume devices) |
| **Forensic Value** | Maps device class GUIDs to device instances. Key LastWriteTime provides additional timestamp for device connection. |
| **Windows Versions** | 2000 through 11 |

### 2.10 MountedDevices

| Field | Details |
|-------|---------|
| **Registry Path** | `SYSTEM\MountedDevices` (root key of SYSTEM hive) |
| **Value Names** | `\DosDevices\{DriveLetter}:` (drive letter assignments) and `\??\Volume{GUID}` (volume GUID paths) |
| **Value Type** | REG_BINARY |
| **Forensic Value** | Maps physical devices/volumes to logical drive letters and volume GUIDs. Every volume ever mounted has at least one entry. USB devices and removable media create entries here. Two entries per volume: one with drive letter, one with GUID. |
| **Windows Versions** | 2000 through 11 |

**Binary data format:**

| Scenario | Data Size | Structure |
|----------|-----------|-----------|
| Internal/fixed disk | 12 bytes | 4-byte disk signature + 8-byte partition offset (little-endian) |
| Removable/USB | Variable | Unicode string: `\??\STORAGE#RemovableMedia#...` or `_??_USBSTOR#Disk&Ven_...&Prod_...#SerialNumber#{GUID}` |
| GPT disk | 24 bytes | GPT partition GUID |

**Parsing notes:**
- The `ParentIdPrefix` from USBSTOR entries appears within the binary data of USB device MountedDevices entries, enabling cross-correlation
- Comparing binary data between `\DosDevices\F:` and `\??\Volume{GUID}` entries identifies the drive letter assigned to a GUID
- Key LastWriteTime = last time any mount entry was modified

### 2.11 Prefetch Configuration

| Field | Details |
|-------|---------|
| **Registry Path** | `SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters` |
| **Values** | `EnablePrefetcher` (DWORD), `EnableSuperfetch` (DWORD) |
| **Forensic Value** | Determines if Prefetch files are generated (execution evidence). Value of 0 may indicate anti-forensic tampering. |
| **Data Values** | 0=Disabled, 1=Application only, 2=Boot only, 3=Both (default) |
| **Windows Versions** | XP through 11 (EnableSuperfetch renamed to SysMain in Win10) |
| **Parsing Notes** | On some Win10 builds, setting EnablePrefetcher=0 does NOT fully prevent .pf file generation. Stopping the SysMain service is what truly prevents it. |

### 2.12 Boot Configuration

| Field | Details |
|-------|---------|
| **Registry Path** | `SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute` |
| **Value** | `BootExecute` (REG_MULTI_SZ) |
| **Forensic Value** | Programs executed during boot, before any user login. Default value is `autocheck autochk *`. Additional entries indicate persistence or disk-check utilities. |
| **Windows Versions** | NT 3.1 through 11 |
| **Parsing Notes** | Malware can add entries here for very early persistence. Any value other than the default should be investigated. |

### 2.13 Firewall Rules

| Field | Details |
|-------|---------|
| **Registry Path** | `SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules` |
| **Values** | Each value is a named firewall rule (REG_SZ) with a pipe-delimited format |
| **Forensic Value** | Complete record of Windows Firewall rules. Attackers may add rules to allow inbound traffic (e.g., port 3389 for RDP) or block security tools. |
| **Data Format** | Pipe-delimited string: `v2.31\|Action=Allow\|Active=TRUE\|Dir=In\|Protocol=6\|LPort=3389\|App=%SystemRoot%\system32\svchost.exe\|Name=RDP\|...` |
| **Windows Versions** | Vista through 11 |

**Additional firewall paths:**
- `SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile` — Domain profile settings
- `SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile` — Private profile settings
- `SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile` — Public profile settings
- Each profile has `EnableFirewall` (DWORD) and `DisableNotifications` (DWORD) values

### 2.14 LSA Authentication Packages

| Field | Details |
|-------|---------|
| **Registry Path** | `SYSTEM\CurrentControlSet\Control\Lsa` |
| **Key Values** | See table below |
| **Forensic Value** | Controls how LSASS loads authentication and security providers. Commonly abused for persistence (MITRE ATT&CK T1547.002 and T1547.005). |
| **Windows Versions** | NT 3.5 through 11 |

| Value Name | Type | Default | Forensic Significance |
|------------|------|---------|----------------------|
| `Authentication Packages` | REG_MULTI_SZ | `msv1_0` | DLLs loaded by LSASS at boot. Malicious DLLs added here survive reboots and run inside LSASS. |
| `Security Packages` | REG_MULTI_SZ | `kerberos`, `msv1_0`, `schannel`, `wdigest`, `tspkg`, `pku2u` | Security Support Providers loaded by LSASS. `mimilib` added here intercepts logon passwords. |
| `Notification Packages` | REG_MULTI_SZ | `rassfm`, `scecli` | DLLs notified of password changes. Loaded into LSASS at boot. |
| `RunAsPPL` | REG_DWORD | 0 (or absent) | When set to 1, enables LSASS Protected Process Light (PPL). Prevents unsigned code injection. |

**Additional path:** `SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\Security Packages` — restricted starting Win8.1

### 2.15 Windows Defender Exclusions

| Field | Details |
|-------|---------|
| **Registry Path (local)** | `SOFTWARE\Microsoft\Windows Defender\Exclusions\{Paths,Extensions,Processes}` |
| **Registry Path (policy)** | `SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\{Paths,Extensions,Processes}` |
| **Additional path** | `SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager` — values: `ExcludedPaths`, `ExcludedExtensions`, `ExcludedProcesses` |
| **Forensic Value** | Attackers frequently add exclusions to prevent Defender from scanning malicious files. Any unexpected exclusion is a strong indicator of compromise. |
| **Data Format** | Under `Exclusions\Paths`: each value name = excluded path, value data = 0 (DWORD). Under `Policy Manager`: pipe-delimited strings. |
| **Windows Versions** | Windows 8 through 11 |

### 2.16 Terminal Server / RDP Settings (Server-Side)

| Field | Details |
|-------|---------|
| **Registry Path** | `SYSTEM\CurrentControlSet\Control\Terminal Server` |
| **Key Values** | `fDenyTSConnections` (DWORD: 0=allow RDP, 1=deny), `fSingleSessionPerUser` (DWORD), `TSEnabled` (DWORD) |
| **Forensic Value** | Determines if the system accepts RDP connections. Malware commonly sets `fDenyTSConnections = 0` to enable lateral movement. |
| **Windows Versions** | XP through 11 |

**NLA setting:**
- Path: `SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp`
- `UserAuthentication` (DWORD): 1 = NLA required (secure), 0 = NLA not required (weakened security)
- `PortNumber` (DWORD): RDP listening port (default 3389; non-standard = evasion indicator)

### 2.17 SvcHost Groups

| Field | Details |
|-------|---------|
| **Registry Path** | `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost` |
| **Values** | Group names (REG_MULTI_SZ) — e.g., `netsvcs`, `LocalService`, `NetworkService`, `DcomLaunch` |
| **Forensic Value** | Lists which services run under each svchost.exe group. Attackers add malicious service names to existing groups (especially `netsvcs`) for stealth persistence. |
| **Data Format** | Each value is a REG_MULTI_SZ containing service names. When svchost.exe starts with `-k groupname`, it loads all services listed in that group's value. |
| **Windows Versions** | 2000 through 11 |
| **Parsing Notes** | In Win10 1703+, svchost was redesigned to host one service per process on systems with sufficient RAM, reducing the forensic utility of group analysis for those systems. Compare against a known-good baseline to detect injected service names. |

---

## 3. SOFTWARE Hive Artifacts

### 3.1 Installed Programs (Uninstall Keys)

| Field | Details |
|-------|---------|
| **Registry Path (64-bit)** | `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{GUID or Name}` |
| **Registry Path (32-bit on 64-bit)** | `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{GUID or Name}` |
| **Per-user paths** | `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Uninstall\{GUID or Name}` |
| **Key Values** | `DisplayName` (REG_SZ), `DisplayVersion` (REG_SZ), `Publisher` (REG_SZ), `InstallDate` (REG_SZ — format YYYYMMDD), `InstallLocation` (REG_SZ), `UninstallString` (REG_SZ or REG_EXPAND_SZ), `InstallSource` (REG_SZ), `EstimatedSize` (DWORD — KB), `ModifyPath` (REG_SZ), `URLInfoAbout` (REG_SZ), `HelpLink` (REG_SZ) |
| **Forensic Value** | Comprehensive record of installed software, including installation date, publisher, and location. Remains even after uninstallation if the uninstaller is incomplete. |
| **Windows Versions** | 2000 through 11 |
| **Parsing Notes** | `InstallDate` format varies (YYYYMMDD as string, or sometimes DWORD). Always check both 64-bit and WOW6432Node paths. Key LastWriteTime indicates last modification (install, update, or repair). |

### 3.2 NetworkList Profiles

| Field | Details |
|-------|---------|
| **Registry Path** | `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{GUID}` |
| **Key Values** | `ProfileName` (REG_SZ — SSID or network name), `Description` (REG_SZ), `DateCreated` (REG_BINARY — 16-byte SYSTEMTIME), `DateLastConnected` (REG_BINARY — 16-byte SYSTEMTIME), `NameType` (DWORD: 6=Wired, 71=Wireless, 243=Broadband), `Category` (DWORD: 0=Public, 1=Private, 2=Domain), `Managed` (DWORD: 0=Unmanaged, 1=Managed) |
| **Forensic Value** | Complete history of every network the system has connected to, with first and last connection timestamps. For wireless networks, the SSID is captured. |
| **Windows Versions** | Vista through 11 |

**SYSTEMTIME format (16 bytes):**
```
Offset  Size  Field
0       2     Year (WORD)
2       2     Month (WORD, 1-12)
4       2     DayOfWeek (WORD, 0=Sunday)
6       2     Day (WORD, 1-31)
8       2     Hour (WORD, 0-23)
10      2     Minute (WORD, 0-59)
12      2     Second (WORD, 0-59)
14      2     Milliseconds (WORD, 0-999)
```

**Important:** SYSTEMTIME values in NetworkList are based on the **system's local time** at the moment of connection, NOT UTC. Must be converted using TimeZoneInformation.

### 3.3 NetworkList Signatures

| Field | Details |
|-------|---------|
| **Registry Path (unmanaged)** | `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged\{GUID}` |
| **Registry Path (managed)** | `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed\{GUID}` |
| **Key Values** | `ProfileGuid` (REG_SZ — links to Profiles), `Description` (REG_SZ), `DnsSuffix` (REG_SZ), `FirstNetwork` (REG_SZ), `DefaultGatewayMac` (REG_BINARY — 6 bytes MAC address) |
| **Forensic Value** | Provides the MAC address of the default gateway for each network connection. Combined with the SSID from Profiles, this can be used with geolocation databases (e.g., WiGLE) to determine physical location. |
| **Windows Versions** | Vista through 11 |
| **Parsing Notes** | Gateway MAC is stored as raw 6-byte binary (no delimiters). Managed vs. Unmanaged indicates corporate domain membership. Match `ProfileGuid` to `Profiles\{GUID}` for full context. |

### 3.4 Windows Version and Installation Info

| Field | Details |
|-------|---------|
| **Registry Path** | `SOFTWARE\Microsoft\Windows NT\CurrentVersion` |
| **Key Values** | `ProductName` (REG_SZ — e.g., "Windows 10 Pro"), `CurrentBuild` (REG_SZ — e.g., "19045"), `CurrentBuildNumber` (REG_SZ), `ReleaseId` (REG_SZ — e.g., "2009"), `DisplayVersion` (REG_SZ — e.g., "22H2"), `InstallDate` (DWORD — Unix timestamp), `InstallTime` (QWORD — FILETIME on Win10+), `RegisteredOwner` (REG_SZ), `RegisteredOrganization` (REG_SZ), `ProductId` (REG_SZ), `BuildBranch` (REG_SZ), `EditionID` (REG_SZ), `CompositionEditionID` (REG_SZ), `UBR` (DWORD — Update Build Revision) |
| **Forensic Value** | Exact Windows version, build, edition, installation date, and registered owner. Critical for determining which artifacts are available and which binary formats to expect. |
| **Windows Versions** | NT 3.1 through 11 |
| **Parsing Notes** | `InstallDate` is a 32-bit Unix timestamp (seconds since 1970). `InstallTime` (Win10+) is a 64-bit FILETIME. `ReleaseId` was deprecated after 2009; use `DisplayVersion` for Win10 20H2+. |

### 3.5 Tracing Keys (Program Execution Evidence)

| Field | Details |
|-------|---------|
| **Registry Path** | `SOFTWARE\Microsoft\Tracing\{ExecutableName}_RASAPI32` and `SOFTWARE\Microsoft\Tracing\{ExecutableName}_RASMANCS` |
| **Forensic Value** | Created when an executable first loads `rasapi32.dll` or `rasman.dll` to establish a network connection. The key name contains the executable name (without `.exe` extension). Key LastWriteTime = first time the executable made a network connection via RAS. |
| **Windows Versions** | XP through 11 |
| **Parsing Notes** | Does NOT apply to all network-connected programs. Only those using the Remote Access Service API. The timestamp is NOT updated on subsequent uses — only first use. Useful for detecting first-time malicious downloads. |

### 3.6 ProfileList (SID to Username Mapping)

| Field | Details |
|-------|---------|
| **Registry Path** | `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\{SID}` |
| **Key Values** | `ProfileImagePath` (REG_EXPAND_SZ — e.g., `C:\Users\JohnDoe`), `State` (DWORD: 0=active), `Sid` (REG_BINARY), `FullProfile` (DWORD), `LocalProfileLoadTimeHigh` (DWORD), `LocalProfileLoadTimeLow` (DWORD) |
| **Forensic Value** | Maps Security Identifiers (SIDs) to user profile paths. Essential for dead-disk forensics where you need to associate SID-keyed artifacts (BAM, BAM, etc.) with actual usernames. |
| **Windows Versions** | 2000 through 11 |
| **Parsing Notes** | Deleted user profiles may remain with `.bak` appended to the SID. `ProfileImagePath` typically contains the username in the path (e.g., `C:\Users\JohnDoe`). `State = 0` means active profile. The key LastWriteTime indicates last profile load. |

### 3.7 Run / RunOnce Keys (HKLM)

| Field | Details |
|-------|---------|
| **Registry Paths** | `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`, `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx`, `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`, `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`, `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce` |
| **Value Format** | Value name = arbitrary identifier, Value data (REG_SZ or REG_EXPAND_SZ) = command to execute |
| **Forensic Value** | Primary persistence mechanism. Programs listed here run automatically at every logon (Run) or next logon only (RunOnce). |
| **Windows Versions** | 95 through 11 |
| **Parsing Notes** | `RunOnce` values are deleted before execution by default. Prefix `!` defers deletion until after execution. Prefix `*` forces execution in Safe Mode. Values are ignored in Safe Mode by default. |

### 3.8 AppCompatFlags

| Field | Details |
|-------|---------|
| **Registry Path** | `SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers` |
| **Value Format** | Value name = full executable path, Value data (REG_SZ) = compatibility mode string (e.g., "~ RUNASADMIN", "WIN7RTM") |
| **Forensic Value** | Each entry indicates the program was executed and a compatibility mode was applied. Proves execution on the system. |
| **Windows Versions** | XP through 11 |

### 3.9 Terminal Server / RDP Policy Settings

| Field | Details |
|-------|---------|
| **Registry Path** | `SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services` |
| **Key Values** | `fDenyTSConnections` (DWORD), `fAllowUnsolicitedFullControl` (DWORD), `MaxInstanceCount` (DWORD), `UserAuthentication` (DWORD), `SecurityLayer` (DWORD), `MinEncryptionLevel` (DWORD), `DeleteTempDirsOnExit` (DWORD), `PerSessionTempDir` (DWORD) |
| **Forensic Value** | Group Policy-level RDP configuration. Policy-level settings override local settings. |
| **Windows Versions** | XP through 11 |

### 3.10 Print Spooler / Print Providers

| Field | Details |
|-------|---------|
| **Registry Path** | `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Print\Printers\{PrinterName}` |
| **Key Values** | `Port` (REG_SZ), `Printer Driver` (REG_SZ), `ShareName` (REG_SZ) |
| **Forensic Value** | Lists all printers known to the system. Network printers reveal connections to print servers. |
| **Windows Versions** | NT 3.1 through 11 |

**Print Monitors (persistence vector):**
- `SYSTEM\CurrentControlSet\Control\Print\Monitors\{MonitorName}` — `Driver` value (REG_SZ) = DLL loaded by the spooler service at startup. Abused for persistence (T1547.010).

### 3.11 VolatileEnvironment

| Field | Details |
|-------|---------|
| **Registry Path** | `Volatile Environment` (under HKU\{SID}) |
| **Key Values** | `LOGONSERVER` (REG_SZ), `USERDNSDOMAIN` (REG_SZ), `USERDOMAIN` (REG_SZ), `USERNAME` (REG_SZ), `USERPROFILE` (REG_SZ), `HOMEDRIVE` (REG_SZ), `HOMEPATH` (REG_SZ), `APPDATA` (REG_SZ), `LOCALAPPDATA` (REG_SZ) |
| **Forensic Value** | Reveals the domain controller, domain, and user context for the current session. Volatile — only exists while user is logged in. |
| **Windows Versions** | 2000 through 11 |

---

## 4. NTUSER.DAT Artifacts

### 4.1 UserAssist

| Field | Details |
|-------|---------|
| **Registry Path** | `Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count` |
| **Forensic Value** | Tracks GUI programs and shortcuts launched through Windows Explorer shell. Contains ROT13-encoded program paths, run counts, focus time, and last execution timestamps. |
| **Windows Versions** | 2000 through 11 |

**GUID Subkeys:**

| GUID | Meaning |
|------|---------|
| `{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}` | Executable file execution tracking |
| `{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}` | Shortcut (LNK) file execution tracking |

**Value name encoding:** ROT13 on alphabetic characters only (a-z, A-Z). Numbers, symbols, and paths are not affected. Example: `rundll32.exe` becomes `ehaqyy32.rkr`. Tip: `.rkr` = `.exe`, `.yax` = `.lnk`.

**Version 3 Binary Structure (Windows XP/Vista — 16 bytes):**

| Offset | Size | Field |
|--------|------|-------|
| 0x00 | 4 bytes | Session ID |
| 0x04 | 4 bytes | Run count (starts at 5 on XP; subtract 5 for actual count) |
| 0x08 | 8 bytes | Last execution time (FILETIME, little-endian) |

**Version 5 Binary Structure (Windows 7/8/10/11 — 72 bytes):**

| Offset | Size | Field |
|--------|------|-------|
| 0x00 | 4 bytes | Session ID |
| 0x04 | 4 bytes | Run count (actual count, no offset) |
| 0x08 | 4 bytes | Focus count (number of times window brought to foreground) |
| 0x0C | 4 bytes | Focus time (total milliseconds the application was the active window) |
| 0x10 | 44 bytes | Usage data (per-session usage percentages and rewrite counters for last 10 sessions) |
| 0x3C | 8 bytes | Last execution time (FILETIME, little-endian) |
| 0x44 | 4 bytes | Unknown (always zero; reset on session expiry) |

**Version determination:** Check the `Version` DWORD value directly under the GUID subkey. Version 3 = 16-byte format; Version 5 = 72-byte format.

**Parsing notes:**
- Zero Focus Time + non-zero Run Count = ambiguous (may be shell preloading, not user action)
- Only tracks GUI applications launched through Explorer shell; command-line programs run via cmd.exe are NOT recorded
- Disabling: set `NoLog = 1` under `Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\Settings`
- Disabling encoding: set `NoEncrypt = 1` under the same Settings key
- During session reset, run count/focus count/focus time are zeroed but last execution time is preserved

**Reference implementations:** [Didier Stevens UserAssist tool](https://blog.didierstevens.com/programs/userassist/), [Eric Zimmerman's RegistryPlugins UserAssist.cs](https://github.com/EricZimmerman/RegistryPlugins/blob/master/RegistryPlugin.UserAssist/UserAssist.cs), [Google Rekall userassist.py](https://github.com/google/rekall/blob/master/rekall-core/rekall/plugins/windows/registry/userassist.py), [libyal/winreg-kb User-assist](https://winreg-kb.readthedocs.io/en/latest/sources/explorer-keys/User-assist.html)

### 4.2 RunMRU

| Field | Details |
|-------|---------|
| **Registry Path** | `Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` |
| **Value Names** | `a`, `b`, `c`, ... (REG_SZ — each is a command typed in the Run dialog), `MRUList` (REG_SZ — order string, e.g., "dcba") |
| **Forensic Value** | Commands typed into the Windows Run dialog (Win+R). Each entry records the exact text typed, including executable names, paths, and URLs. |
| **Data Format** | Each value ends with `\1` (backslash-one) as a terminator. `MRUList` contains letters in most-recent-first order. |
| **Windows Versions** | XP through 11 |
| **Parsing Notes** | Maximum ~26 entries (a-z). Key LastWriteTime = when the last command was run. |

### 4.3 TypedPaths

| Field | Details |
|-------|---------|
| **Registry Path** | `Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths` |
| **Value Names** | `url1`, `url2`, ... (REG_SZ — paths typed into Explorer address bar) |
| **Forensic Value** | Paths typed directly into Windows Explorer's address bar (not clicked/browsed). Includes UNC paths (`\\server\share`), URLs, local paths, and shell commands. |
| **Windows Versions** | XP through 11 |

### 4.4 TypedURLs

| Field | Details |
|-------|---------|
| **Registry Path** | `Software\Microsoft\Internet Explorer\TypedURLs` |
| **Value Names** | `url1`, `url2`, ... (REG_SZ) |
| **Forensic Value** | URLs typed into Internet Explorer's address bar. |
| **Windows Versions** | XP through 11 (IE11 was the last version) |

**Companion artifact (Vista+):**
- `Software\Microsoft\Internet Explorer\TypedURLsTime` — Value names match TypedURLs; data = 8-byte FILETIME per URL

### 4.5 RecentDocs

| Field | Details |
|-------|---------|
| **Registry Path** | `Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs` |
| **Subkeys** | Extension-specific subkeys (e.g., `.docx`, `.pdf`, `.jpg`), plus a root key for ALL types |
| **Value Names** | Numeric names (`0`, `1`, `2`, ...) = REG_BINARY; `MRUListEx` = REG_BINARY |
| **Forensic Value** | Files recently opened by the user through Explorer shell. Each extension subkey tracks files of that type. Root key tracks all types combined. |
| **Data Format** | Each numeric value = Unicode filename + embedded LNK target data (PIDL). `MRUListEx` = array of 4-byte little-endian DWORDs indicating access order (first entry = most recent), terminated by `0xFFFFFFFF`. |
| **Windows Versions** | XP through 11 |
| **Parsing Notes** | Extension subkey LastWriteTime = when the last file of that type was opened. Root key LastWriteTime = when any file was last opened. Persists after source file deletion. Max ~150 entries per extension. Not populated by programmatic file access (only Explorer shell). |

### 4.6 ShellBags (NTUSER.DAT)

| Field | Details |
|-------|---------|
| **Registry Path** | `Software\Microsoft\Windows\Shell\BagMRU` (hierarchy) and `Software\Microsoft\Windows\Shell\Bags` (view settings) |
| **Forensic Value** | Stores folder view preferences for network shares and remote machines accessed by the user. |
| **Windows Versions** | Vista through 11 (XP stored under `Software\Microsoft\Windows\ShellNoRoam\BagMRU`) |

See Section 5.1 for complete ShellBag binary format documentation.

### 4.7 ComDlg32 (Common Dialog Artifacts)

#### 4.7.1 OpenSavePidlMRU

| Field | Details |
|-------|---------|
| **Registry Path** | `Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU` (Vista+) or `...\OpenSaveMRU` (XP) |
| **Subkeys** | Extension-specific subkeys plus `*` for all |
| **Forensic Value** | Files opened or saved using Windows common dialog boxes (Open/Save As). Many applications use these dialogs, making this a rich source of file access evidence. |
| **Data Format** | Each value = PIDL (binary Shell Item ID List) pointing to the file. `MRUListEx` = 4-byte DWORD array of access order. |
| **Windows Versions** | XP through 11 |
| **Parsing Notes** | The PIDL can contain full path information including volume, directory, and filename with timestamps. Requires shell item parsing (see Section 5.1). |

#### 4.7.2 LastVisitedPidlMRU

| Field | Details |
|-------|---------|
| **Registry Path** | `Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU` (Vista+) or `...\LastVisitedMRU` (XP) |
| **Forensic Value** | Records which executable opened/saved a file AND the directory that was last accessed by that executable. Pairs executable names with directories. |
| **Data Format** | Each value = binary blob containing: executable name (Unicode, null-terminated) + PIDL of last visited directory. `MRUListEx` = access order. |
| **Windows Versions** | XP through 11 |

#### 4.7.3 CIDSizeMRU

| Field | Details |
|-------|---------|
| **Registry Path** | `Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\CIDSizeMRU` |
| **Forensic Value** | Records the window size/position of common dialog boxes per application. The executable name is embedded in the binary data. |
| **Data Format** | REG_BINARY values containing window dimensions and the executable name. `MRUListEx` for ordering. |
| **Windows Versions** | Vista through 11 |

### 4.8 WordWheelQuery (Windows Search History)

| Field | Details |
|-------|---------|
| **Registry Path** | `Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery` |
| **Value Names** | Numeric (`0`, `1`, `2`, ...) = REG_SZ (search terms); `MRUListEx` = REG_BINARY |
| **Forensic Value** | Search terms entered in Windows Explorer search box and Start Menu search. |
| **Data Format** | Each value = Unicode string of the search query. `MRUListEx` = standard 4-byte DWORD array. |
| **Windows Versions** | 7 through 11 |
| **Legacy (XP):** | `Software\Microsoft\Search Assistant\ACMru\{subkey}` — subkeys: `5001` (Internet), `5603` (Files/Folders name), `5604` (Files/Folders content), `5647` (Printers/People) |

### 4.9 Terminal Server Client (RDP Connection History)

#### 4.9.1 Default (MRU List)

| Field | Details |
|-------|---------|
| **Registry Path** | `Software\Microsoft\Terminal Server Client\Default` |
| **Values** | `MRU0`, `MRU1`, ... `MRU9` (REG_SZ — hostnames or IP addresses) |
| **Forensic Value** | Last 10 RDP connections initiated by this user. MRU0 = most recent. |
| **Windows Versions** | XP through 11 |

#### 4.9.2 Servers (Full History)

| Field | Details |
|-------|---------|
| **Registry Path** | `Software\Microsoft\Terminal Server Client\Servers\{hostname}` |
| **Values** | `UsernameHint` (REG_SZ — username used for connection), `CertHash` (REG_BINARY — RDP server SSL certificate thumbprint) |
| **Forensic Value** | Complete history of ALL RDP connections ever made by this user. Unlike Default, this is not limited to 10 entries. Persists even after failed connection attempts. |
| **Windows Versions** | XP through 11 |
| **Parsing Notes** | The Microsoft Store "Remote Desktop" app does NOT write to this key — it uses its own storage under `%LocalAppData%\Packages\` and ETL logs. |

### 4.10 MUICache

| Field | Details |
|-------|---------|
| **Registry Path** | **Vista+:** `Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache`; **XP:** `Software\Microsoft\Windows\ShellNoRoam\MUICache` |
| **Values** | Two entries per application: `{path}.FriendlyAppName` (REG_SZ) and `{path}.ApplicationCompany` (REG_SZ) |
| **Forensic Value** | Populated when a GUI application is executed. Contains the full path, display name, and publisher of every GUI program the user has launched. |
| **Windows Versions** | XP through 11 |
| **Parsing Notes** | Unlike UserAssist, MUICache values are NOT ROT13-encoded. Provides clear-text paths. Does not include timestamps or counts — only presence. |

### 4.11 AppCompatFlags (User-Level)

| Field | Details |
|-------|---------|
| **Registry Path** | `Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers` |
| **Values** | Value name = executable path, Value data = compatibility settings string |
| **Forensic Value** | Programs with user-specific compatibility flags applied. Each entry proves execution under this user account. |
| **Windows Versions** | XP through 11 |

**Compatibility Assistant Store:**
- **XP-Win7:** `Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Persisted` — value names are executable paths, value data = REG_BINARY (empty)
- **Win8+:** `...\Compatibility Assistant\Store` — same format

### 4.12 Microsoft Office MRU (Per Application)

| Field | Details |
|-------|---------|
| **Registry Path** | `Software\Microsoft\Office\{version}\{app}\File MRU` |
| **Version Numbers** | 11.0 (2003), 12.0 (2007), 14.0 (2010), 15.0 (2013), 16.0 (2016/2019/365) |
| **App Names** | `Word`, `Excel`, `PowerPoint`, `Access`, `Visio`, `Publisher` |
| **Values** | `Item 1`, `Item 2`, ... (REG_SZ — format: `[F00000000][T{hex_filetime}]*{filepath}`) |
| **Forensic Value** | Files opened by each Office application. The embedded FILETIME indicates when the file was last accessed by that application. |
| **Windows Versions** | Any (depends on Office version) |

**Place MRU:** `...\Place MRU` — directories recently navigated to by that Office app

**User MRU (Microsoft 365):** `...\User MRU\{LiveId_xxx}\File MRU` — per-Microsoft-account MRU data. The LiveId identifies the signed-in account.

**TrustRecords:** `...\Security\Trusted Documents\TrustRecords` — value names are file paths; data contains trust timestamp. Proves user opened the file AND chose to enable editing/macros.

**Reading Locations (Word):** `...\Word\Reading Locations\{document}` — contains `Datetime` (REG_SZ — FILETIME as string) and `Position` (REG_SZ — cursor position within the document). Proves the user read a specific Word document.

### 4.13 Printers / Print MRU

| Field | Details |
|-------|---------|
| **Registry Path** | `Software\Microsoft\Windows NT\CurrentVersion\PrinterPorts` |
| **Values** | Printer name = value name, port/driver info = value data (REG_SZ) |
| **Forensic Value** | Printers configured for this user, including network printers. |
| **Windows Versions** | NT 3.1 through 11 |

**Additional paths:**
- `Printers\Connections` — network printer connections
- `Printers\DevModePerUser` or `Printers\DevModes2` — per-printer settings binary data
- `Software\Microsoft\Windows NT\CurrentVersion\Windows\Device` — default printer

### 4.14 Taskbar / Taskband (Pinned Programs)

| Field | Details |
|-------|---------|
| **Registry Path** | `Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband` |
| **Values** | `Favorites` (REG_BINARY — serialized list of pinned taskbar items), `FavoritesResolve` (REG_BINARY) |
| **Forensic Value** | Programs pinned to the taskbar by the user. Indicates user intent and frequent use. |
| **Data Format** | Binary blob containing serialized Shell Link (LNK) data for each pinned item. |
| **Windows Versions** | 7 through 11 |

### 4.15 Notification Area (System Tray)

| Field | Details |
|-------|---------|
| **Registry Path** | `Software\Microsoft\Windows\CurrentVersion\Explorer\TrayNotify` |
| **Values** | `IconStreams` (REG_BINARY), `PastIconsStream` (REG_BINARY) |
| **Forensic Value** | Applications that have appeared in the system tray, including timestamps. Proves applications were running in the background. |
| **Windows Versions** | XP through 11 |
| **Parsing Notes** | Binary format is complex and version-dependent. Contains icon data, executable paths, and timestamps. |

### 4.16 Explorer FeatureUsage

| Field | Details |
|-------|---------|
| **Registry Path** | `Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\{Subkey}` |
| **Subkeys** | `AppSwitched`, `AppBadgeUpdated`, `AppLaunch`, `ShowJumpView`, `TrayButtonClicked` |
| **Forensic Value** | Tracks application usage metrics in the taskbar. `AppSwitched` shows every app switched to via taskbar, with a count. `AppLaunch` shows programs launched from the taskbar. |
| **Data Format** | Value names = application identifiers, Value data = DWORD (count of interactions) |
| **Windows Versions** | Windows 10 1803+ through 11 |

### 4.17 Internet Explorer Download History

| Field | Details |
|-------|---------|
| **Registry Path** | `Software\Microsoft\Internet Explorer\Main` |
| **Values** | `Download Directory` (REG_SZ) — last download location |
| **Forensic Value** | Reveals the user's most recent IE download directory. |
| **Windows Versions** | XP through 11 |

### 4.18 MountPoints2 (User-Level Mount History)

| Field | Details |
|-------|---------|
| **Registry Path** | `Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2\{VolumeGUID}` |
| **Forensic Value** | Maps volume GUIDs to the user who was logged in when the device was connected. Cross-reference with SYSTEM MountedDevices to match GUID to device identity. Key LastWriteTime = last time user interacted with that volume. |
| **Windows Versions** | XP through 11 |

### 4.19 Map Network Drive MRU

| Field | Details |
|-------|---------|
| **Registry Path** | `Software\Microsoft\Windows\CurrentVersion\Explorer\Map Network Drive MRU` |
| **Values** | `a`, `b`, `c`, ... (REG_SZ — UNC paths), `MRUList` (REG_SZ — order) |
| **Forensic Value** | Network shares the user mapped as drive letters. |
| **Windows Versions** | XP through 11 |

### 4.20 Network Persistent Connections

| Field | Details |
|-------|---------|
| **Registry Path** | `Network\{DriveLetter}` (under NTUSER.DAT) |
| **Values** | `RemotePath` (REG_SZ — UNC path), `ProviderName` (REG_SZ), `UserName` (REG_SZ) |
| **Forensic Value** | Persistent (reconnect at logon) network drive mappings. |
| **Windows Versions** | NT 3.1 through 11 |

### 4.21 UserInitMprLogonScript

| Field | Details |
|-------|---------|
| **Registry Path** | `Environment` (under NTUSER.DAT) |
| **Value** | `UserInitMprLogonScript` (REG_SZ) |
| **Forensic Value** | Script executed at logon for this user. Not set by default. Presence indicates possible persistence mechanism. |
| **Windows Versions** | NT 4.0 through 11 |

### 4.22 Winlogon (User-Level)

| Field | Details |
|-------|---------|
| **Registry Path** | `Software\Microsoft\Windows NT\CurrentVersion\Winlogon` |
| **Values** | `Shell` (REG_SZ — default: `explorer.exe`), `Userinit` (REG_SZ) |
| **Forensic Value** | Per-user shell and logon initialization. If `Shell` is set to something other than `explorer.exe`, indicates persistence or custom shell. |
| **Windows Versions** | NT 3.1 through 11 |

### 4.23 Run / RunOnce Keys (HKCU)

| Field | Details |
|-------|---------|
| **Registry Paths** | `Software\Microsoft\Windows\CurrentVersion\Run`, `Software\Microsoft\Windows\CurrentVersion\RunOnce`, `Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run` |
| **Forensic Value** | Per-user auto-start programs. Same format as HKLM Run keys. |
| **Windows Versions** | 95 through 11 |

### 4.24 PuTTY / SSH Artifacts

| Field | Details |
|-------|---------|
| **Registry Path** | `Software\SimonTatham\PuTTY\SshHostKeys` — SSH host key cache |
| **Values** | Value name = `{algorithm}@{port}:{hostname}`, Value data = host key fingerprint (REG_SZ) |
| **Forensic Value** | Every SSH server the user has connected to. Even if PuTTY is uninstalled, these entries persist. |
| **Windows Versions** | Any (third-party) |

**PuTTY Sessions:** `Software\SimonTatham\PuTTY\Sessions\{SessionName}` — saved session configurations including hostname, port, username

**WinSCP Sessions:** `Software\Martin Prikryl\WinSCP 2\Sessions\{SessionName}` — `HostName` (REG_SZ), `UserName` (REG_SZ), `PortNumber` (DWORD), `Password` (REG_SZ — encrypted)

### 4.25 Built-in Application MRUs

| Application | Registry Path | Values |
|-------------|---------------|--------|
| MS Paint | `Software\Microsoft\Windows\CurrentVersion\Applets\Paint\Recent File List` | `File1`, `File2`, ... (REG_SZ) |
| WordPad | `Software\Microsoft\Windows\CurrentVersion\Applets\Wordpad\Recent File List` | `File1`, `File2`, ... (REG_SZ) |
| MMC | `Software\Microsoft\Microsoft Management Console\Recent File List` | `File1`, `File2`, ... (REG_SZ) |
| Windows Media Player | `Software\Microsoft\MediaPlayer\Player\RecentFileList` | `File0`, `File1`, ... (REG_SZ) |
| Windows Media Player URLs | `Software\Microsoft\MediaPlayer\Player\RecentURLList` | `File0`, `File1`, ... (REG_SZ) |

### 4.26 Capability Access Manager (ConsentStore)

| Field | Details |
|-------|---------|
| **Registry Path** | `Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\{capability}` |
| **Capabilities** | `webcam`, `microphone`, `location`, `contacts`, `calendar`, `phoneCall`, `email`, `userDataTasks`, `chat`, `radios`, `bluetoothSync`, `appDiagnostics`, `documentsLibrary`, `picturesLibrary`, `videosLibrary`, `broadFileSystemAccess` |
| **Values per app** | Value = app package family name; Data includes `LastUsedTimeStart` and `LastUsedTimeStop` (QWORD — FILETIME) |
| **Forensic Value** | Records which applications accessed sensitive device capabilities (camera, microphone, location, etc.) and when. |
| **Windows Versions** | Windows 10 1803+ through 11 |

### 4.27 Sysinternals EulaAccepted

| Field | Details |
|-------|---------|
| **Registry Path** | `Software\Sysinternals\{ToolName}` |
| **Value** | `EulaAccepted` (DWORD: 1 = accepted) |
| **Forensic Value** | Each Sysinternals tool creates an `EulaAccepted` entry on first run. Presence proves the tool was executed. Key LastWriteTime = first (or most recent) execution. Important for detecting administrative/hacking tools like PsExec, ProcDump, Autoruns, etc. |
| **Windows Versions** | Any |

### 4.28 Command Processor AutoRun

| Field | Details |
|-------|---------|
| **Registry Path** | `Software\Microsoft\Command Processor` |
| **Value** | `AutoRun` (REG_SZ or REG_EXPAND_SZ) |
| **Forensic Value** | Command executed automatically every time cmd.exe starts. Persistence mechanism. |
| **Windows Versions** | NT 4.0 through 11 |

---

## 5. USRCLASS.DAT Artifacts

### 5.1 ShellBags (Complete Shell Item Format)

| Field | Details |
|-------|---------|
| **Registry Path** | `Local Settings\Software\Microsoft\Windows\Shell\BagMRU` (hierarchy) and `...\Shell\Bags` (view settings) |
| **Forensic Value** | Records EVERY folder browsed via Windows Explorer: local folders, zip files, Windows special folders, virtual folders, Control Panel applets, network shares. USRCLASS.DAT is the PRIMARY location for ShellBags on Vista+. |
| **Windows Versions** | Vista through 11 (XP stored in NTUSER.DAT under ShellNoRoam) |

**BagMRU Structure:**
- Each subkey = a folder in the hierarchy (numeric names: `0`, `1`, `2`, ...)
- Each subkey contains:
  - Numeric values (`0`, `1`, `2`, ...) = REG_BINARY shell item data for child folders
  - `MRUListEx` = REG_BINARY, array of 4-byte DWORDs (access order, most recent first), terminated by `0xFFFFFFFF`
  - `NodeSlot` = DWORD pointing to corresponding entry in `Bags\{slot}` for view settings
- Tree path example: `BagMRU\0\0\2\0\1` = `Desktop\This PC\D:\Documents\Personal\PDFs`

**Shell Item Binary Format (Joachim Metz / libfwsi specification):**

Every shell item starts with:

| Offset | Size | Description |
|--------|------|-------------|
| 0 | 2 bytes | Size of the shell item (including the size field itself) |
| 2 | 1 byte | Class type indicator |

**Shell Item Types by Class Type Indicator:**

| Class Type Range | Type | Description |
|------------------|------|-------------|
| `0x00` | Users property view | Users files folder |
| `0x1F` | Root folder | Desktop, My Computer, Recycle Bin, etc. (identified by 16-byte GUID at offset 4) |
| `0x20-0x2F` | Volume | Drive letters. Flag `0x01` = has name, `0x08` = removable media |
| `0x30-0x3F` | File entry | Files and folders. Flag `0x01` = directory, `0x02` = file, `0x04` = Unicode strings |
| `0x40-0x4F` | Network location | UNC paths, shares, domains. Flag `0x01` = domain, `0x02` = server, `0x03` = share |
| `0x61` | URI | FTP, HTTP, and other URI-based locations |
| `0x71` | Control Panel | Control Panel applets (28 bytes, identified by 16-byte GUID) |

**Root Folder Shell Item (0x1F):**

| Offset | Size | Description |
|--------|------|-------------|
| 0 | 2 | Size |
| 2 | 1 | `0x1F` (class type) |
| 3 | 1 | Sort index (0x00=IE, 0x42=Libraries, 0x44=Users, 0x48=My Documents, 0x50=My Computer, 0x58=Network, 0x60=Recycle Bin) |
| 4 | 16 | Shell folder GUID |

**Volume Shell Item (0x2x):**

| Offset | Size | Description |
|--------|------|-------------|
| 0 | 2 | Size |
| 2 | 1 | Class type (0x20 after mask 0x70) |
| 3 | 1 | Flags |
| 4 | 20 | Volume name (ASCII, null-padded) |
| 24+ | variable | Optional extension blocks |

**File Entry Shell Item (0x3x) — The most forensically rich:**

| Offset | Size | Description |
|--------|------|-------------|
| 0 | 2 | Size |
| 2 | 1 | Class type (0x30 after mask 0x70; 0x31=directory, 0x32=file) |
| 3 | 1 | Unknown |
| 4 | 4 | File size (DWORD; 0 for directories) |
| 8 | 4 | Last modification date/time (FAT format, UTC) |
| 12 | 2 | File attribute flags (lower 16 bits) |
| 14 | variable | Primary name (ASCII or UTF-16 depending on 0x04 flag) |
| variable | 2 | Extension block offset or 0 |

**Extension Block 0xBEEF0004 (the most important — Vista+):**

| Offset | Size | Description |
|--------|------|-------------|
| 0 | 2 | Size of extension block |
| 2 | 2 | Version (minimum 0x0003) |
| 4 | 4 | Signature: `0xBEEF0004` |
| 8 | 4 | File creation date/time (FAT format) |
| 12 | 4 | Last access date/time (FAT format) |
| 16 | 2 | NTFS file reference index (lower 16 bits — Vista+ if version >= 7) |
| 18 | 6 | NTFS file reference sequence (Vista+ if version >= 7) |
| 24+ | variable | Long filename (UTF-16LE, null-terminated) |
| variable | variable | Localized name (if present) |
| last 2 | 2 | Version offset |

**FAT Date/Time Encoding:**
- Date (2 bytes): Bits 15-9 = Year-1980, Bits 8-5 = Month, Bits 4-0 = Day
- Time (2 bytes): Bits 15-11 = Hours, Bits 10-5 = Minutes, Bits 4-0 = Seconds/2

**Network Location Shell Item (0x4x):**

| Offset | Size | Description |
|--------|------|-------------|
| 0 | 2 | Size |
| 2 | 1 | Class type (0x40 after mask 0x70) |
| 3 | 1 | Unknown |
| 4 | 1 | Flags (0x80=has description, 0x40=has comments) |
| 5 | variable | Network name or UNC path (ASCII, null-terminated) |
| variable | variable | Description (if flag 0x80), Comments (if flag 0x40) |

**URI Shell Item (0x61):**

| Offset | Size | Description |
|--------|------|-------------|
| 0 | 2 | Size |
| 2 | 1 | `0x61` |
| 3 | 1 | Flags (0x80 = Unicode strings) |
| 4 | 2 | Data size |
| 6+ | variable | URI data including hostname, username, and embedded FILETIME timestamps |

For FTP URIs, a sub-shell item follows containing: hostname/IP, username, password, FILETIME timestamps for folder access, and directory paths.

**Bags (View Settings):**
- `Bags\{NodeSlot}\Shell\{ViewMode}` contains:
  - `Mode` (DWORD — view mode: 1=Icon, 2=SmallIcon, 3=List, 4=Details, 6=Tiles, 8=Content)
  - `FFlags` (DWORD — folder flags)
  - `Sort` (REG_BINARY — sort column and direction)
  - `ColInfo` (REG_BINARY — column layout)
  - `GroupView` (DWORD)
  - `Vid` (REG_SZ — view identifier GUID)

**Key parsing considerations:**
- Shell items from pre-Windows XP may lack extension blocks
- Extension block version determines which fields are present
- FAT timestamps have 2-second resolution; they are pulled from the MFT at shell item creation time and NOT updated afterward
- Not everything is documented; unknown shell item types should be preserved as raw binary
- Parsing failures should not halt processing — skip unknown items and continue

**Reference implementations:** [Eric Zimmerman's ShellBags Explorer / SBECmd](https://ericzimmerman.github.io/), [libyal/libfwsi](https://github.com/libyal/libfwsi), [Kaitai Struct windows_shell_items](https://formats.kaitai.io/windows_shell_items/), [Willi Ballenthin's Python shellbag parser](https://github.com/williballenthin/shellbags)

### 5.2 CLSID Registrations

| Field | Details |
|-------|---------|
| **Registry Path** | `Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\{PackageFamilyName}\...` |
| **Additional** | `Software\Classes\CLSID\{GUID}` and `Software\Classes\CLSID\{GUID}\InProcServer32` |
| **Forensic Value** | Per-user COM object registrations. COM Hijacking (T1546.015) involves modifying CLSID entries to point to malicious DLLs. User-level CLSIDs override machine-level ones. |
| **Windows Versions** | 2000 through 11 |
| **Parsing Notes** | Unless investigating COM hijacking, browsing millions of GUIDs is not productive. Focus on CLSIDs that differ from the corresponding HKLM entries. |

### 5.3 File Extension Associations

| Field | Details |
|-------|---------|
| **Registry Path** | `Software\Classes\.{ext}` (under USRCLASS.DAT) |
| **Values** | `(Default)` (REG_SZ — ProgID), `OpenWithProgids` (subkey with ProgID values) |
| **Forensic Value** | Per-user file type associations. Overrides system defaults. Changes may indicate a user deliberately associated a file type with a non-standard program. |
| **Windows Versions** | XP through 11 |

### 5.4 MSIX/Helium App-Specific Hives

| Field | Details |
|-------|---------|
| **Location** | `%LocalAppData%\Packages\{AppId}\SystemAppData\Helium\User.dat` |
| **Forensic Value** | Modern MSIX-packaged applications store per-app, per-user registry data in separate hive files. These can contain app-specific artifacts tied to a specific user and application. |
| **Windows Versions** | Windows 10 1809+ |

---

## 6. SAM Hive Artifacts

### 6.1 User Accounts

| Field | Details |
|-------|---------|
| **Registry Path** | `SAM\Domains\Account\Users\{RID_hex}` (e.g., `000001F4` for RID 500 = Administrator) |
| **Key Values** | `F` (REG_BINARY — fixed-length account metadata), `V` (REG_BINARY — variable-length account data) |
| **Forensic Value** | Complete local user account information including login timestamps, login counts, account flags, and password metadata. |
| **Windows Versions** | NT 3.1 through 11 |

**F Value Binary Structure (Fixed — ~80 bytes):**

| Offset | Size | Field |
|--------|------|-------|
| 0x00 | 8 bytes | Revision / Header |
| 0x08 | 8 bytes | **Last Logon Time** (FILETIME) — last successful interactive logon |
| 0x10 | 8 bytes | Unknown (observed as empty or creation-related) |
| 0x18 | 8 bytes | **Password Last Set** (FILETIME) — last password change time |
| 0x20 | 8 bytes | **Account Expires** (FILETIME) — `0x7FFFFFFFFFFFFFFF` = never |
| 0x28 | 8 bytes | **Last Failed Login** (FILETIME) — last incorrect password attempt |
| 0x30 | 4 bytes | **Relative Identifier (RID)** — unique account ID |
| 0x34 | 4 bytes | Unknown / padding |
| 0x38 | 2 bytes | **ACB Flags** (Account Control Block) — account status bitmap |
| 0x3A | 2 bytes | Unknown / country code |
| 0x3C | 2 bytes | Unknown |
| 0x3E | 2 bytes | Unknown |
| 0x40 | 2 bytes | **Failed Login Count** (since last successful login) |
| 0x42 | 2 bytes | **Total Login Count** (lifetime successful logons) |

**ACB Flags Bitmap:**

| Bit | Value | Meaning |
|-----|-------|---------|
| 0 | 0x0001 | Account Disabled |
| 1 | 0x0002 | Home Directory Required |
| 2 | 0x0004 | Password Not Required |
| 3 | 0x0008 | Temp Duplicate Account |
| 4 | 0x0010 | Normal User Account |
| 5 | 0x0020 | MNS Logon Account |
| 6 | 0x0040 | Interdomain Trust Account |
| 7 | 0x0080 | Workstation Trust Account |
| 8 | 0x0100 | Server Trust Account |
| 9 | 0x0200 | Password Does Not Expire |
| 10 | 0x0400 | Account Auto Locked |

**V Value Binary Structure (Variable-length):**
The V value uses an offset/length table at the beginning, with all offsets relative to an adjustment value of `0xCC`:

| Table Offset | Points To | Description |
|-------------|-----------|-------------|
| 0x0C | Offset, 0x10 = Length | **Account Name** (Unicode) |
| 0x18 | Offset, 0x1C = Length | **Full Name** (Unicode) |
| 0x24 | Offset, 0x28 = Length | **Comment** (Unicode) |
| 0x30 | Offset, 0x34 = Length | **User Comment** |
| 0x48 | Offset, 0x4C = Length | **Home Directory** (Unicode) |
| 0x54 | Offset, 0x58 = Length | **Home Directory Connect** |
| 0x60 | Offset, 0x64 = Length | **Script Path** |
| 0x6C | Offset, 0x70 = Length | **Profile Path** |
| 0x9C | Offset, 0xA0 = Length | **LM Password Hash** (encrypted, 16 bytes) |
| 0xA8 | Offset, 0xAC = Length | **NT Password Hash** (encrypted, 16 bytes) |

To compute the actual data offset: `actual_offset = table_offset_value + 0xCC`

**Account Creation Date:** Derived from the registry key's LastWriteTime (the RID subkey under Users), NOT from the F or V binary data.

**Password Hint:** Stored as a separate REG_BINARY value named `UserPasswordHint` under the same RID key, or embedded in the V value in Unicode.

### 6.2 User Account Names Mapping

| Field | Details |
|-------|---------|
| **Registry Path** | `SAM\Domains\Account\Users\Names\{username}` |
| **Forensic Value** | Quick mapping of usernames to RIDs. Each subkey name = a username. The default value's **type** (not data) encodes the RID. |
| **Parsing Notes** | The value type field contains the RID. E.g., type = `0x01F4` (500) = Administrator. This is an unusual use of the value type field. |

### 6.3 Group Membership

| Field | Details |
|-------|---------|
| **Registry Path** | `SAM\Domains\Builtin\Aliases\{RID_hex}` and `SAM\Domains\Account\Aliases\{RID_hex}` |
| **Values** | `C` (REG_BINARY — group member SIDs) |
| **Forensic Value** | Local group membership. Key groups: `000001F0` (Administrators), `000001F1` (Users), `00000220` (Remote Desktop Users). |
| **Windows Versions** | NT 3.1 through 11 |

**Domain Policy:**
- `SAM\Domains\Account\F` — Domain-level F value with global account policy settings including password length, lockout threshold, lockout duration, and password history.

### 6.4 Account Lockout Information

Account lockout status is derived from the F value fields:
- `Failed Login Count` at offset 0x40 compared against the domain policy lockout threshold
- `Last Failed Login` at offset 0x28 compared against the lockout duration
- ACB flag bit 10 (0x0400) = Auto Locked

**Reference implementations:** [yampelo/samparser](https://github.com/yampelo/samparser), [Velociraptor Windows.Forensics.SAM](https://docs.velociraptor.app/artifact_references/pages/windows.forensics.sam/), [beginningtoseethelight.org/ntsecurity](http://www.beginningtoseethelight.org/ntsecurity/), [Impacket secretsdump.py](https://github.com/fortra/impacket/blob/master/examples/secretsdump.py)

---

## 7. SECURITY Hive Artifacts

### 7.1 LSA Secrets

| Field | Details |
|-------|---------|
| **Registry Path** | `SECURITY\Policy\Secrets\{SecretName}\CurrVal` and `...\OldVal` |
| **Common Secret Names** | `$MACHINE.ACC` (machine account password), `DefaultPassword` (auto-logon password), `NL$KM` (cached credentials encryption key), `DPAPI_SYSTEM` (DPAPI master key), `_SC_{ServiceName}` (service account passwords), `L$ASP.NETAutoGenKeysV44` (ASP.NET keys), `L$SQSA_{SID}` (security questions and answers — Win10+) |
| **Forensic Value** | Contains plaintext or lightly encrypted credentials and secrets. Service account passwords, auto-logon credentials, domain trust keys, and DPAPI master keys are stored here. |
| **Windows Versions** | NT 3.1 through 11 |

**Decryption process:**
1. Extract the **Boot Key (SysKey)** from `SYSTEM\CurrentControlSet\Control\Lsa` — stored split across four keys: `JD`, `Skew1`, `GBG`, `Data` (the class name of each key contributes 4 bytes, scrambled by a permutation table)
2. Use the Boot Key to decrypt the **LSA Key** from `SECURITY\Policy\PolEKList` (Win7+) or `SECURITY\Policy\PolSecretEncryptionKey` (pre-Win7)
3. Use the LSA Key to decrypt individual secrets from `SECURITY\Policy\Secrets\{name}\CurrVal`

**Encryption algorithms:**
- Pre-Vista: RC4 + DES
- Vista+: AES-256-CBC

### 7.2 Cached Domain Credentials (DCC2)

| Field | Details |
|-------|---------|
| **Registry Path** | `SECURITY\Cache` |
| **Values** | `NL$1`, `NL$2`, ... `NL$10` (REG_BINARY — each is a cached credential entry) |
| **Configuration** | `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\CachedLogonsCount` (REG_SZ — default "10") |
| **Forensic Value** | Cached domain logon credentials enabling offline authentication. Default stores last 10 domain accounts. DCC2 format uses PBKDF2 with 10,240 iterations (slow to crack). |
| **Windows Versions** | 2000 through 11 (DCC1 on pre-Vista, DCC2 on Vista+) |

**NL$ Entry Binary Structure:**

| Section | Size | Description |
|---------|------|-------------|
| Metadata | 64 bytes | Cleartext: includes data lengths, iteration count, flags |
| CH | 16 bytes | Challenge/salt for key derivation |
| T | 16 bytes | Verification data |
| Encrypted Data | >100 bytes | Contains: cached password hash (first 16 bytes after decryption), then at offset 72 within decrypted data: username, domain, domain name (all Unicode, 4-byte aligned) |

**Decryption:**
1. Decrypt `NL$KM` from LSA Secrets
2. Compute RC4 key = HMAC-MD5(NL$KM, CH)
3. Decrypt the encrypted data block with RC4

**Additional encryption key:** `SECURITY\Policy\Secrets\NL$KM\CurrVal`

### 7.3 Security Policies

| Field | Details |
|-------|---------|
| **Registry Path** | `SECURITY\Policy\PolAdtEv` (audit policy), `SECURITY\Policy\PolPrDmN` (primary domain name), `SECURITY\Policy\PolPrDmS` (primary domain SID), `SECURITY\Policy\PolAcDmN` (account domain name), `SECURITY\Policy\PolAcDmS` (account domain SID) |
| **Forensic Value** | Domain membership information, audit policy configuration. |
| **Windows Versions** | NT 3.1 through 11 |

### 7.4 Audit Policies

| Field | Details |
|-------|---------|
| **Registry Path** | `SECURITY\Policy\PolAdtEv` |
| **Data Format** | REG_BINARY — contains audit flags for each category (account logon, logon events, object access, privilege use, policy change, etc.) |
| **Forensic Value** | Reveals which events are being audited. If audit policies are weaker than expected, may indicate tampering. |
| **Windows Versions** | NT 3.1 through 11 |

**Reference implementations:** [Impacket secretsdump.py](https://github.com/fortra/impacket), [go-secdump](https://github.com/jfjallid/go-secdump), [Mimikatz lsadump module](https://github.com/gentilkiwi/mimikatz)

---

## 8. Amcache.hve Artifacts

### 8.1 Overview

| Field | Details |
|-------|---------|
| **File Location** | `C:\Windows\AppCompat\Programs\Amcache.hve` |
| **Hive Format** | Standard REGF format (not part of the mounted registry) |
| **Forensic Value** | Extensive metadata about applications, drivers, and devices discovered on the system. Includes SHA-1 file hashes, compilation timestamps, and installation metadata. |
| **Windows Versions** | Windows 8 through 11 (replaced RecentFileCache.bcf) |
| **Critical Caveat** | The Amcache structure is tied to the DLL version (not Windows version). Two Win10 systems at different patch levels may have different key structures. |

### 8.2 InventoryApplicationFile (Windows 10+)

| Field | Details |
|-------|---------|
| **Registry Path** | `Root\InventoryApplicationFile\{UniqueKey}` |
| **Key Values** | `ProgramId` (REG_SZ — hash of binary name + version + publisher + language), `FileId` (REG_SZ — "0000" + SHA-1 hash), `LowerCaseLongPath` (REG_SZ — full file path), `Name` (REG_SZ — filename), `Publisher` (REG_SZ), `Version` (REG_SZ), `BinaryType` (REG_SZ — e.g., "pe32_i386", "pe64_amd64"), `BinFileVersion` (REG_SZ), `BinProductVersion` (REG_SZ), `Size` (DWORD — file size in bytes), `Language` (DWORD), `IsPeFile` (DWORD), `IsOsComponent` (DWORD), `LinkDate` (REG_SZ — PE compilation timestamp, ISO 8601 format), `ProductName` (REG_SZ), `ProductVersion` (REG_SZ), `HashBlock` (REG_SZ) |
| **Forensic Value** | Every executable discovered on the system by the compatibility appraiser task. SHA-1 hash enables malware identification even if the file is renamed. |
| **Parsing Notes** | `FileId` format: first 4 characters are always "0000", followed by the actual SHA-1 hash. Files larger than 31,457,280 bytes (30 MB) may have partial or missing hashes. Presence does NOT guarantee execution — the compatibility appraiser scans Program Files, Program Files (x86), and Desktop. Cross-reference with InventoryApplication to determine if the file was formally installed vs. merely present. |

### 8.3 InventoryApplication

| Field | Details |
|-------|---------|
| **Registry Path** | `Root\InventoryApplication\{GUID}` |
| **Key Values** | `ProgramId` (REG_SZ), `Name` (REG_SZ), `Publisher` (REG_SZ), `Version` (REG_SZ), `Source` (REG_SZ — e.g., "Msi", "AddRemoveProgram"), `InstallDate` (REG_SZ — ISO format), `RootDirPath` (REG_SZ), `Type` (REG_SZ), `RegistryKeyPath` (REG_SZ — link to Uninstall key), `UninstallString` (REG_SZ), `MsiPackageCode` (REG_SZ), `MsiProductCode` (REG_SZ) |
| **Forensic Value** | Formally installed applications. `LastScanTime` indicates when the compatibility appraiser last ran. Software installed after the last scan may not appear here. |
| **Parsing Notes** | `ProgramId` links to InventoryApplicationFile entries. Correlate the two to determine if a file was part of an installed application or was a standalone/dropped file. |

### 8.4 InventoryDriverBinary

| Field | Details |
|-------|---------|
| **Registry Path** | `Root\InventoryDriverBinary\{DriverPath}` |
| **Key Values** | `DriverId` (REG_SZ), `DriverName` (REG_SZ), `DriverVersion` (REG_SZ), `DriverCompany` (REG_SZ), `DriverSigned` (DWORD), `DriverTimeStamp` (DWORD — Unix timestamp of PE compilation), `DriverLastWriteTime` (REG_SZ — ISO format), `Product` (REG_SZ), `ProductVersion` (REG_SZ), `Inf` (REG_SZ), `Service` (REG_SZ), `WdfVersion` (REG_SZ) |
| **Forensic Value** | Every driver loaded on the system. Critical for detecting rootkits, malicious drivers, and unsigned driver loading. |
| **Windows Versions** | Windows 10+ |

### 8.5 InventoryDriverPackage

| Field | Details |
|-------|---------|
| **Registry Path** | `Root\InventoryDriverPackage\{PackageId}` |
| **Key Values** | `Class` (REG_SZ), `ClassGuid` (REG_SZ), `Date` (REG_SZ), `Directory` (REG_SZ), `Inf` (REG_SZ), `Provider` (REG_SZ), `SubmissionId` (REG_SZ), `Signer` (REG_SZ), `Version` (REG_SZ) |
| **Forensic Value** | Driver package metadata including signing information. |
| **Windows Versions** | Windows 10+ |

### 8.6 Legacy Format — File Subkey (Windows 8.x)

| Field | Details |
|-------|---------|
| **Registry Path** | `Root\File\{VolumeGUID}\{FileId}` |
| **Key Values** | `0` (REG_SZ — Product name), `1` (REG_SZ — Company name), `2` (REG_SZ — Version), `3` (REG_SZ — Language), `5` (REG_SZ — File version), `6` (DWORD), `f` (DWORD — SHA-1 hash link), `11` (QWORD — Last modification time), `12` (DWORD — PE compilation timestamp), `15` (REG_SZ — Full path), `17` (QWORD — Entry timestamp), `100` (REG_SZ — ProgramId), `101` (REG_SZ — SHA-1 hash) |
| **Forensic Value** | Pre-Win10 Amcache format. Same type of data but different key structure. |
| **Windows Versions** | Windows 8 / 8.1 |

### 8.7 Legacy Format — Programs Subkey (Windows 8.x)

| Field | Details |
|-------|---------|
| **Registry Path** | `Root\Programs\{ProgramId}` |
| **Key Values** | `0` (REG_SZ — Program name), `1` (REG_SZ — Version), `2` (REG_SZ — Publisher), `6` (DWORD — Install source), `a` (REG_SZ — Uninstall key path), `d` (REG_SZ — Install date), `Files` subkey = list of associated files |
| **Windows Versions** | Windows 8 / 8.1 |

### 8.8 InventoryDeviceContainer

| Field | Details |
|-------|---------|
| **Registry Path** | `Root\InventoryDeviceContainer\{ContainerId}` |
| **Key Values** | `ModelName` (REG_SZ), `Manufacturer` (REG_SZ), `ModelId` (REG_SZ), `PrimaryCategory` (REG_SZ), `IsConnected` (DWORD), `IsMachineContainer` (DWORD), `IsNetworked` (DWORD), `IsPaired` (DWORD) |
| **Forensic Value** | Physical device containers — every device plugged in or paired with the system. |
| **Windows Versions** | Windows 10+ |

### 8.9 InventoryApplicationShortcut

| Field | Details |
|-------|---------|
| **Registry Path** | `Root\InventoryApplicationShortcut\{ShortcutPath}` |
| **Key Values** | `LnkFilePath` (REG_SZ — shortcut path), `TargetPath` (REG_SZ — target executable) |
| **Forensic Value** | Maps shortcut files to their target executables. |
| **Windows Versions** | Windows 10+ |

**Reference implementations:** [Eric Zimmerman's AmcacheParser](https://ericzimmerman.github.io/), [AmCache-EvilHunter](https://github.com/yanivsh84/amcache-evilhunter), [RegRipper amcache plugin](https://github.com/keydet89/RegRipper4.0)

---

## 9. BCD (Boot Configuration Data)

### 9.1 BCD Store Structure

| Field | Details |
|-------|---------|
| **File Location** | `\Boot\BCD` (BIOS/MBR) or `\EFI\Microsoft\Boot\BCD` (UEFI) |
| **Live Registry** | `HKLM\BCD00000000` (restricted access) |
| **Format** | Standard REGF hive format |
| **Structure** | `BCD00000000\Objects\{GUID}\Elements\{TypeCode}` |

### 9.2 Key BCD Elements

| Element Type Code | bcdedit Name | Description |
|-------------------|-------------|-------------|
| `0x12000004` | description | Boot entry description string |
| `0x12000005` | locale | Locale (e.g., "en-US") |
| `0x14000006` | inherit | Inherited objects list |
| `0x14000008` | recoverysequence | Recovery sequence GUIDs |
| `0x16000009` | recoveryenabled | Recovery enabled (01=yes, 00=no) |
| `0x22000002` | osdevice | OS device path |
| `0x22000001` | device | Boot device path |
| `0x23000003` | path | Windows loader path |
| `0x250000e0` | bootstatuspolicy | Boot status policy |
| `0x26000081` | nointegritychecks | Disable integrity checks |
| `0x26000010` | detecthal | HAL detection |

### 9.3 Forensic Significance

| Investigation Focus | What to Look For |
|---------------------|-----------------|
| **Malware persistence** | Modified boot entries, custom OS loaders, disabled recovery |
| **Anti-forensics** | `recoveryenabled = 0`, `bootstatuspolicy = ignoreallfailures` (Cerber ransomware signature) |
| **BitLocker interaction** | Changed BCD settings trigger recovery (Event ID 523 reports the hex type code). BitLocker validates BCD settings during boot. |
| **Secure Boot bypass** | `nointegritychecks = 1`, `testsigning = 1` |
| **Boot debugging** | `debug = 1`, `debugtype`, `debugport`, `baudrate` values present |

**Reference:** [forensics.wiki — Windows Boot Configuration Data](https://forensics.wiki/windows_boot_configuration_data/), [Microsoft — BCD settings and BitLocker](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/bcd-settings-and-bitlocker)

---

## 10. Filesystem Execution Evidence (Non-Registry)

### 10.0 PCA (Program Compatibility Assistant) Files — Windows 11 22H2+

| Field | Details |
|-------|---------|
| **File Locations** | `C:\Windows\appcompat\pca\PcaAppLaunchDic.txt`<br>`C:\Windows\appcompat\pca\PcaGeneralDb0.txt`<br>`C:\Windows\appcompat\pca\PcaGeneralDb1.txt` |
| **Encoding** | UTF-16 LE (Little Endian) |
| **Format** | Plain text, one record per line, pipe-delimited: `<full_executable_path>\|<UTC_timestamp>` |
| **Timestamp Format** | `YYYY-MM-DD HH:MM:SS.000` (UTC) |
| **Example Record** | `C:\Users\Alice\Downloads\Quarterly_Review.pdf.exe\|2026-03-15 09:42:11.000` |
| **Service** | `PcaSvc` (Program Compatibility Assistant Service) |
| **Windows Versions** | Windows 11 22H2+ (service exists since Vista but this artifact format introduced in 22H2) |
| **Scope** | System-wide (all users' Explorer-initiated executions) |
| **Forensic Value** | Evidence of execution that **survives file deletion**. Records full path even after binary removed. Captures double-extension filenames (`.pdf.exe`). Captures removable media (`D:\`) and UNC network share paths. |
| **Critical Limitation** | **Explorer-initiated only** — double-click from shell. Does NOT record launches from CMD, PowerShell, WMI, PsExec, scheduled tasks, or services. Absence ≠ non-execution. |
| **MITRE ATT&CK** | T1204.002 (User Execution: Malicious File), T1036.007 (Double File Extension) |
| **Parser Notes** | Decode UTF-16LE → split each line on `\|` → field[0]=path, field[1]=timestamp. No binary parsing. |
| **Related Artifacts** | Amcache.hve (broader execution evidence), ShimCache (compatibility-based), Prefetch (all launch vectors), BAM/DAM (background activity) |
| **References** | [Andrea Fortuna — Windows 11 PCA Artifact (2026-03-19)](https://andreafortuna.org/2026/03/19/windows11-pca-artifact/) |

---

## 11. Other Hives

### 11.1 COMPONENTS Hive

| Field | Details |
|-------|---------|
| **File Location** | `%SystemRoot%\System32\config\COMPONENTS` |
| **Purpose** | Windows servicing/component store. Tracks installed features, updates, packages, and component manifests. |
| **Forensic Value** | Can reveal installed patches, feature state, and servicing history. Contains WCP (Windows Component Platform) data. |
| **Parsing Notes** | Very large hive. Primarily useful for determining patch level and installed features. Not commonly parsed in standard forensic workflows. |

### 11.2 DEFAULT Hive

| Field | Details |
|-------|---------|
| **File Location** | `%SystemRoot%\System32\config\DEFAULT` |
| **Mount Point** | `HKU\.DEFAULT` |
| **Purpose** | Default user profile template. Settings applied to new user profiles and the system account. |
| **Forensic Value** | Run/RunOnce keys here affect the SYSTEM account and new user profiles. Persistence mechanisms targeting this hive affect all future users. |
| **Key Paths** | Same structure as NTUSER.DAT (Run, RunOnce, etc.) |

### 11.3 DRIVERS Hive (Windows 10+)

| Field | Details |
|-------|---------|
| **File Location** | `%SystemRoot%\System32\config\DRIVERS` |
| **Purpose** | Driver configuration data. Separated from SYSTEM hive in Windows 10+. |
| **Forensic Value** | Contains driver-specific configuration that was previously part of the SYSTEM hive. |

### 11.4 MSIX/AppV Application Hives

| Field | Details |
|-------|---------|
| **File Location** | `%LocalAppData%\Packages\{AppId}\SystemAppData\Helium\User.dat` and `Cache\user.dat` |
| **Purpose** | Per-application, per-user registry data for modern (MSIX/AppX) Windows apps. |
| **Forensic Value** | App-specific settings and state data, isolated from the main NTUSER.DAT. Useful for investigating specific modern applications. |
| **Windows Versions** | Windows 10 1809+ |

---

## 12. References and Sources

### Primary Research Sources

1. **Eric Zimmerman's Tools and Documentation**
   - [All tools](https://ericzimmerman.github.io/)
   - [AppCompatCacheParser](https://github.com/EricZimmerman/AppCompatCacheParser)
   - [AmcacheParser](https://github.com/EricZimmerman/AmcacheParser)
   - [Registry Explorer / RECmd](https://github.com/EricZimmerman/RegistryExplorer)
   - [RegistryPlugins (UserAssist, etc.)](https://github.com/EricZimmerman/RegistryPlugins)

2. **Harlan Carvey's RegRipper**
   - [RegRipper 4.0](https://github.com/keydet89/RegRipper4.0)
   - [Windows Incident Response Blog](http://windowsir.blogspot.com/)

3. **Joachim Metz's libyal Project**
   - [libfwsi — Windows Shell Item format specification](https://github.com/libyal/libfwsi/blob/main/documentation/Windows%20Shell%20Item%20format.asciidoc)
   - [libregf — Registry File format](https://github.com/libyal/libregf)
   - [winreg-kb — Windows Registry Knowledge Base](https://winreg-kb.readthedocs.io/)

4. **Maxim Suhanov's Registry Research**
   - [REGF format specification](https://github.com/msuhanov/regf/blob/master/Windows%20registry%20file%20format%20specification.md)

### Forensic Artifact Catalogs

5. **RegSeek** — [148 Registry Artifacts Database](https://regseek.github.io/) ([GitHub](https://github.com/RegSeek/regseek.github.io))
6. **Psmths/windows-forensic-artifacts** — [GitHub repository](https://github.com/Psmths/windows-forensic-artifacts)
7. **SANS DFIR Posters** — Windows Forensics Poster, FOR500 course materials
8. **forensics.wiki** — [Windows category](https://forensics.wiki/windows/)
9. **artefacts.help** — [Windows ShimCache](https://artefacts.help/windows_shimcache.html)

### Comprehensive Forensic Guides

10. **Cyber Triage (2025-2026 Series)**
    - [Windows Registry Forensics 2026](https://www.cybertriage.com/blog/windows-registry-forensics-2026/)
    - [Windows Registry Forensics Cheat Sheet 2026](https://www.cybertriage.com/blog/windows-registry-forensics-cheat-sheet-2026/)
    - [NTUSER.DAT Forensics Analysis 2026](https://www.cybertriage.com/blog/ntuser-dat-forensics-analysis-2026/)
    - [ShimCache and AmCache Forensic Analysis 2026](https://www.cybertriage.com/blog/shimcache-and-amcache-forensic-analysis-2026/)
    - [UserAssist Forensics 2025](https://www.cybertriage.com/blog/userassist-forensics-2025/)
    - [Shellbags Forensic Analysis 2026](https://www.cybertriage.com/blog/shellbags-forensic-analysis-2026/)

11. **Kaspersky Securelist**
    - [UserAssist — forensic value for IR](https://securelist.com/userassist-artifact-forensic-value-for-incident-response/116911/)
    - [AmCache artifact extraction](https://securelist.com/amcache-forensic-artifact/117622/)

12. **Belkasoft**
    - [Windows Registry Forensics: Structure and Acquisition](https://belkasoft.com/windows-registry-forensics-structure-and-aquisition)
    - [Windows Registry Analysis Techniques](https://belkasoft.com/windows-registry-analysis-techniques)

13. **ElcomSoft**
    - [Investigating Windows Registry (Feb 2026)](https://blog.elcomsoft.com/2026/02/investigating-windows-registry/)
    - [USB Device Forensics (Feb 2026)](https://blog.elcomsoft.com/2026/02/usb-device-forensics-on-windows-10-and-11/)

14. **Magnet Forensics Blog**
    - [USB Device Artifacts](https://www.magnetforensics.com/blog/artifact-profile-usb-devices/)
    - [RDP Artifacts in Incident Response](https://www.magnetforensics.com/blog/rdp-artifacts-in-incident-response/)
    - [UserAssist Forensic Artifacts](https://www.magnetforensics.com/blog/artifact-profile-userassist/)
    - [ShellBags Analysis](https://www.magnetforensics.com/blog/forensic-analysis-of-windows-shellbags/)
    - [ShimCache vs AmCache](https://www.magnetforensics.com/blog/shimcache-vs-amcache-key-windows-forensic-artifacts/)

### Binary Structure Deep Dives

15. **nullsec.us** — [Windows 10/11 AppCompatCache Deep Dive](https://nullsec.us/windows-10-11-appcompatcache-deep-dive/)
16. **4n6k** — [UserAssist Forensics](https://www.4n6k.com/2013/05/userassist-forensics-timelines.html), [ShellBags Forensics](https://www.4n6k.com/2013/12/shellbags-forensics-addressing.html)
17. **aldeid wiki** — [Windows UserAssist Keys](https://www.aldeid.com/wiki/Windows-userassist-keys)
18. **beginningtoseethelight.org** — [NT Security / SAM Structure](http://www.beginningtoseethelight.org/ntsecurity/)
19. **moyix.blogspot.com** — [SysKey and the SAM](https://moyix.blogspot.com/2008/02/syskey-and-sam.html), [Cached Domain Credentials](https://moyix.blogspot.com/2008/02/cached-domain-credentials.html)

### Persistence and Detection

20. **MITRE ATT&CK**
    - [T1547.001 — Registry Run Keys](https://attack.mitre.org/techniques/T1547/001/)
    - [T1547.002 — Authentication Packages](https://attack.mitre.org/techniques/T1547/002/)
    - [T1547.005 — Security Support Providers](https://attack.mitre.org/techniques/T1547/005/)
    - [T1543.003 — Windows Service](https://attack.mitre.org/techniques/T1543/003/)
    - [T1003.005 — Cached Domain Credentials](https://attack.mitre.org/techniques/T1003/005/)
    - [T1546.015 — COM Hijacking](https://attack.mitre.org/techniques/T1546/015/)

21. **persistence-info.github.io** — [Complete Windows Persistence Catalog](https://persistence-info.github.io/)
22. **ewilded/Windows_persistence** — [Registry-based persistence](https://github.com/ewilded/Windows_persistence/blob/master/REGISTRY.md)
23. **AllThingsDFIR** — ["Tracing" Malicious Downloads](https://www.allthingsdfir.com/tracing-malicious-downloads/)

### Forensic Analysis Tools

| Tool | Author | Purpose |
|------|--------|---------|
| Registry Explorer / RECmd | Eric Zimmerman | GUI viewer + batch parsing |
| AppCompatCacheParser | Eric Zimmerman | ShimCache parsing |
| AmcacheParser | Eric Zimmerman | Amcache.hve parsing |
| ShellBags Explorer / SBECmd | Eric Zimmerman | ShellBag analysis |
| RegRipper 4.0 | Harlan Carvey | Plugin-based registry parsing |
| Velociraptor | Rapid7 | Endpoint forensic collection and analysis |
| Plaso (log2timeline) | Kristinn Gudjonsson | Timeline creation from registry and other artifacts |
| samparser | Omer Yampel | SAM hive parsing |
| Impacket secretsdump | Fortra | SAM/SECURITY/LSA credential extraction |
| Autopsy | Brian Carrier | Open-source forensic platform with registry modules |
| KAPE | Eric Zimmerman / Kroll | Automated artifact collection and processing |

### Kaitai Struct Specifications

- [Windows Shell Items](https://formats.kaitai.io/windows_shell_items/) — Formal binary specification usable for code generation

---

*This catalog was compiled from extensive web research across authoritative forensic sources including SANS DFIR publications, Eric Zimmerman's documentation and tool source code, Harlan Carvey's RegRipper documentation, Joachim Metz's libyal format specifications, Kaspersky Securelist research papers, Cyber Triage forensic guides (2025-2026), Belkasoft analysis documentation, ElcomSoft research, Magnet Forensics artifact profiles, MITRE ATT&CK persistence techniques, and the RegSeek community artifact database.*
