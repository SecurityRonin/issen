# Comprehensive Third-Party Application Registry Forensics Reference

**Research Date:** 2026-03-24
**Purpose:** Exhaustive Windows registry key paths for forensically significant third-party applications, organized for building Rust-based registry artifact parsers.
**Companion To:** `research/remote-access-detection-artifacts.md` (covers RMM/VPN tools in depth)

---

## Table of Contents

1. [SSH/SFTP/Terminal Clients](#1-sshsftpterminal-clients)
2. [VPN Clients (Supplemental)](#2-vpn-clients-supplemental)
3. [Web Browsers](#3-web-browsers)
4. [Email Clients](#4-email-clients)
5. [Cloud Storage / Sync](#5-cloud-storage--sync)
6. [Messaging / Communication](#6-messaging--communication)
7. [Development Tools](#7-development-tools)
8. [Database / Admin Tools](#8-database--admin-tools)
9. [Security / Privacy Tools](#9-security--privacy-tools)
10. [Virtualization](#10-virtualization)
11. [File Transfer / Sharing](#11-file-transfer--sharing)
12. [Compression / Utilities](#12-compression--utilities)
13. [Office / Productivity](#13-office--productivity)
14. [System / Network Utilities](#14-system--network-utilities)
15. [Remote Access (Supplemental to companion doc)](#15-remote-access-supplemental)
16. [LOLRMM Registry Artifact Master List](#16-lolrmm-registry-artifact-master-list)
17. [Sources & References](#17-sources--references)

---

## 1. SSH/SFTP/Terminal Clients

### 1.1 PuTTY

**Hive:** NTUSER.DAT

| Registry Path | Forensic Value |
|---|---|
| `HKCU\Software\SimonTatham\PuTTY\Sessions\` | All saved sessions — hostnames, ports, protocols, key paths, proxy configs |
| `HKCU\Software\SimonTatham\PuTTY\Sessions\<SessionName>` | Individual session config (HostName, PortNumber, Protocol, UserName, ProxyHost) |
| `HKCU\Software\SimonTatham\PuTTY\SshHostKeys` | SSH host key fingerprint cache — proves connections to specific IP:port combos |
| `HKCU\Software\SimonTatham\PuTTY\Jumplist\Recent sessions` | Recently used sessions list |

**Key Notes:**
- PuTTY does NOT typically store passwords, but stores hostnames, usernames, key file paths, and proxy settings
- SSH host keys prove a connection was made to a specific server even if sessions are deleted
- FileZilla's `fzsftp.exe` shares the same `SshHostKeys` registry path — entries may come from either tool
- SessionGopher (Mandiant) can remotely extract PuTTY sessions via WMI registry queries

### 1.2 WinSCP

**Hive:** NTUSER.DAT

| Registry Path | Forensic Value |
|---|---|
| `HKCU\Software\Martin Prikryl\WinSCP 2\Sessions\` | All saved sessions including hostnames, ports, usernames |
| `HKCU\Software\Martin Prikryl\WinSCP 2\Sessions\<SessionName>\HostName` | Target host |
| `HKCU\Software\Martin Prikryl\WinSCP 2\Sessions\<SessionName>\UserName` | Username |
| `HKCU\Software\Martin Prikryl\WinSCP 2\Sessions\<SessionName>\Password` | Obfuscated password (NOT encrypted — simple bitwise operations) |
| `HKCU\Software\Martin Prikryl\WinSCP 2\Sessions\<SessionName>\PortNumber` | Port number |
| `HKCU\Software\Martin Prikryl\WinSCP 2\Sessions\<SessionName>\FSProtocol` | Protocol type (SFTP, SCP, FTP) |
| `HKCU\Software\Martin Prikryl\WinSCP 2\Configuration\Interface\Commander\LocalPanel\LastPath` | Last local directory browsed |
| `HKCU\Software\Martin Prikryl\WinSCP 2\Configuration\Interface\Commander\RemotePanel\LastPath` | Last remote directory browsed |

**Key Notes:**
- Passwords are obfuscated with bitwise operations, NOT encrypted — trivially reversible without a master password
- SessionGopher automatically deobfuscates WinSCP saved session passwords
- Portable WinSCP versions use an INI file instead of the registry
- WinSCP can import sessions from PuTTY, FileZilla, and other clients

### 1.3 FileZilla

**Hive:** NTUSER.DAT (shared with PuTTY) + File System

| Registry Path | Forensic Value |
|---|---|
| `HKCU\Software\SimonTatham\PuTTY\SshHostKeys` | SSH fingerprint cache (shared with PuTTY's fzsftp.exe module) |

**Primary Storage is File-Based:**
- `%AppData%\Roaming\FileZilla\sitemanager.xml` — Saved sites with credentials
- `%AppData%\Roaming\FileZilla\recentservers.xml` — Recently connected servers
- `%AppData%\Roaming\FileZilla\filezilla.xml` — Configuration and recent local/remote paths
- `%AppData%\Roaming\FileZilla\queue.sqlite3` — Transfer queue database

### 1.4 MobaXterm

**Hive:** NTUSER.DAT

| Registry Path | Forensic Value |
|---|---|
| `HKCU\Software\Mobatek\MobaXterm\M` | Master password (DPAPI encrypted, first 20 bytes removed) |
| `HKCU\Software\Mobatek\MobaXterm\P` | Stored passwords (encrypted with master password or DPAPI) |
| `HKCU\Software\Mobatek\MobaXterm\C` | Stored credentials |
| `HKCU\Software\Mobatek\MobaXterm\<SessionName>` | Individual session configurations |

**Key Notes:**
- Master password is encrypted using DPAPI; the SHA512 hash is used to encrypt/decrypt credentials
- Metasploit module `post/windows/gather/credentials/moba_xterm` extracts stored credentials
- Velociraptor artifact uses glob `HKEY_USERS\S-1-5-21-*\SOFTWARE\Mobatek\MobaXterm\{M,P,C}\**`
- INI-based config: `%AppData%\Roaming\MobaXterm\MobaXterm.ini` or `%USERPROFILE%\Documents\MobaXterm\MobaXterm.ini`

### 1.5 SecureCRT

**Hive:** NTUSER.DAT

| Registry Path | Forensic Value |
|---|---|
| `HKCU\Software\VanDyke\SecureCRT\` | Application settings |
| `HKCU\Software\VanDyke\SecureCRT 3.0\Global\[Config Path]` | Points to configuration directory |
| `HKCU\Software\VanDyke Technologies\SecureCRT\License` | License info proving installation |

**Primary Storage is File-Based:**
- Default config: `%AppData%\VanDyke\Config\Sessions\` — Session files with encrypted credentials
- Sessions stored as individual `.ini` files per connection

### 1.6 Xshell / Xftp (NetSarang)

**Hive:** NTUSER.DAT

| Registry Path | Forensic Value |
|---|---|
| `HKU\<SID>\Software\NetSarang\Common\6\UserData` | Points to session file storage location |
| `HKU\<SID>\Software\NetSarang\Common\5\UserData` | Legacy version data path |
| `HKCU\Software\NetSarang\Xshell\` | Application settings |
| `HKCU\Software\NetSarang\Xftp\` | SFTP client settings |

**Primary Storage is File-Based:**
- Sessions: `%USERPROFILE%\Documents\NetSarang Computer\6\Xshell\Sessions\*.xsh`
- Passwords are Base64-encoded encrypted values; decryption requires user SID
- Metasploit module: `post/windows/gather/credentials/xshell_xftp_password`

### 1.7 KiTTY

**Hive:** NTUSER.DAT

| Registry Path | Forensic Value |
|---|---|
| `HKCU\Software\9bis.com\KiTTY\Sessions\` | Saved sessions (same structure as PuTTY) |
| `HKCU\Software\9bis.com\KiTTY\SshHostKeys` | SSH host key fingerprints |

**Key Notes:**
- KiTTY is a fork of PuTTY; uses `9bis.com\KiTTY` instead of `SimonTatham\PuTTY`
- Can optionally use PuTTY's registry key path instead
- Portable mode stores sessions in `.ini` files alongside the executable

### 1.8 SuperPuTTY

**Storage:** File-based, NOT registry
- Sessions stored in `%AppData%\SuperPuTTY\Sessions.XML`
- Configuration in `%AppData%\SuperPuTTY\SuperPuTTY.settings`

### 1.9 Solar-PuTTY

**Storage:** File-based (encrypted)
- Sessions stored in `%AppData%\SolarWinds\Solar-PuTTY\sessions.dat` (AES encrypted)

### 1.10 mRemoteNG

**Storage:** File-based (XML)

| File Path | Forensic Value |
|---|---|
| `%AppData%\mRemoteNG\confCons.xml` | All connection definitions — hostnames, usernames, AES-encrypted passwords |
| `%AppData%\mRemoteNG\confCons.xml.bak` | Backup — may contain earlier/decrypted versions |

**Key Notes:**
- Passwords encrypted with AES-GCM (v1.75+) or AES-CBC (older)
- CVE-2023-30367: Password dumping vulnerability
- Backup copies may be stored decrypted due to upgrade bugs
- Decryption tools: `mremoteng_decrypt.py`, `decipher_mremoteng.jar`
- Install evidence: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\MRemoteNG_is1`

### 1.11 Royal TS / Royal TSX

**Storage:** File-based (encrypted `.rtsz` documents)
- Install evidence: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{GUID}_is1` (Royal TS)
- Documents stored as encrypted containers with AES-256

---

## 2. VPN Clients (Supplemental)

The companion doc (`remote-access-detection-artifacts.md`) covers OpenVPN, WireGuard, Tailscale, Cisco AnyConnect, GlobalProtect, FortiClient, Pulse Secure/Ivanti, ZScaler, and Cloudflare WARP. Below are supplemental entries.

### 2.1 NordVPN

**Hive:** SOFTWARE, NTUSER.DAT

| Registry Path | Forensic Value |
|---|---|
| `HKLM\SOFTWARE\NordVPN\` | Installation configuration |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\NordVPN` | Install date, version, install path |
| `HKLM\SYSTEM\CurrentControlSet\Services\NordVPN Service` | Service registration |
| `HKLM\SYSTEM\CurrentControlSet\Services\nordlynx` | NordLynx (WireGuard) adapter service |

**File-based artifacts:** `%LocalAppData%\NordVPN\` (logs, connection history)

### 2.2 ExpressVPN

**Hive:** SOFTWARE

| Registry Path | Forensic Value |
|---|---|
| `HKLM\SOFTWARE\ExpressVPN\` | Installation configuration |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{GUID}` | Install metadata |
| `HKLM\SYSTEM\CurrentControlSet\Services\ExpressVPN Lightway` | Lightway protocol service |
| `HKLM\SYSTEM\CurrentControlSet\Services\ExpressVpnService` | Main VPN service |

### 2.3 SoftEther VPN

**Hive:** SOFTWARE

| Registry Path | Forensic Value |
|---|---|
| `HKLM\SOFTWARE\SoftEther VPN\` | Installation info |
| `HKLM\SOFTWARE\SoftEther VPN Developer Edition\` | Developer edition install info |
| `HKLM\SYSTEM\CurrentControlSet\Services\SEVPNBRIDGE` | SoftEther Bridge service |
| `HKLM\SYSTEM\CurrentControlSet\Services\SEVPNCLIENT` | SoftEther Client service |
| `HKLM\SYSTEM\CurrentControlSet\Services\SEVPNSERVER` | SoftEther Server service |

### 2.4 Pritunl

**Hive:** SOFTWARE

| Registry Path | Forensic Value |
|---|---|
| `HKLM\SOFTWARE\Pritunl\` | Installation configuration |
| `HKLM\SYSTEM\CurrentControlSet\Services\pritunl` | Pritunl service |

---

## 3. Web Browsers

### 3.1 Google Chrome

**Hive:** NTUSER.DAT, SOFTWARE

| Registry Path | Forensic Value |
|---|---|
| `HKCU\Software\Google\Chrome\BLBeacon` | Last active version and timestamp |
| `HKCU\Software\Google\Chrome\PreferenceMACs\Default\extensions.settings` | Extension integrity hashes |
| `HKCU\Software\Google\Chrome\NativeMessagingHosts\` | Registered native messaging hosts |
| `HKLM\SOFTWARE\Google\Chrome` | System-wide Chrome installation |
| `HKLM\SOFTWARE\Policies\Google\Chrome\` | Chrome enterprise policies |
| `HKLM\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist` | Force-installed extensions |
| `HKLM\SOFTWARE\Policies\Google\Chrome\ExtensionInstallBlocklist` | Blocked extensions |
| `HKLM\SOFTWARE\Google\Update\Clients\{GUID}` | Chrome update client info |
| `HKCU\Software\Google\Update\ClientState\{GUID}` | Per-user update state |
| `HKLM\SOFTWARE\Clients\StartMenuInternet\Google Chrome` | Default browser registration |
| `HKLM\SOFTWARE\RegisteredApplications` | Chrome as registered handler |

**Profile data (file-based):** `%LocalAppData%\Google\Chrome\User Data\Default\` (History, Cookies, Login Data, Bookmarks, Preferences, Extensions)

### 3.2 Mozilla Firefox

**Hive:** NTUSER.DAT, SOFTWARE

| Registry Path | Forensic Value |
|---|---|
| `HKCU\Software\Mozilla\Firefox\Launcher` | Firefox launcher info |
| `HKCU\Software\Mozilla\Firefox\TaskBarIDs` | Taskbar integration |
| `HKLM\SOFTWARE\Mozilla\Firefox` | System-wide Firefox installation |
| `HKLM\SOFTWARE\Mozilla\Firefox\CurrentVersion` | Installed version |
| `HKLM\SOFTWARE\Mozilla\Firefox\Extensions\` | System-wide extensions |
| `HKLM\SOFTWARE\Clients\StartMenuInternet\FIREFOX.EXE` | Default browser registration |

**Profile data (file-based):** `%AppData%\Mozilla\Firefox\Profiles\<random>.default-release\` (places.sqlite, cookies.sqlite, logins.json, key4.db, prefs.js, extensions.json)

### 3.3 Microsoft Edge (Chromium)

**Hive:** NTUSER.DAT, SOFTWARE

| Registry Path | Forensic Value |
|---|---|
| `HKCU\Software\Microsoft\Edge\BLBeacon` | Last active version and timestamp |
| `HKCU\Software\Microsoft\Edge\PreferenceMACs\Default\extensions.settings` | Extension integrity hashes |
| `HKCU\Software\Microsoft\Edge\TypedURLs` | Typed URLs (Edge-specific, not just IE) |
| `HKLM\SOFTWARE\Microsoft\Edge` | System installation info |
| `HKLM\SOFTWARE\Policies\Microsoft\Edge\` | Enterprise policies |
| `HKLM\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallForcelist` | Force-installed extensions |
| `HKLM\SOFTWARE\Clients\StartMenuInternet\Microsoft Edge` | Default browser registration |

**Profile data (file-based):** `%LocalAppData%\Microsoft\Edge\User Data\Default\`

### 3.4 Brave Browser

**Hive:** NTUSER.DAT, SOFTWARE

| Registry Path | Forensic Value |
|---|---|
| `HKCU\Software\BraveSoftware\Brave-Browser\BLBeacon` | Last active version and timestamp |
| `HKCU\Software\BraveSoftware\Brave-Browser\PreferenceMACs\Default\extensions.settings` | Extension integrity hashes |
| `HKLM\SOFTWARE\BraveSoftware\Brave-Browser` | System installation info |
| `HKLM\SOFTWARE\Clients\StartMenuInternet\Brave` | Default browser registration |

**Profile data:** `%LocalAppData%\BraveSoftware\Brave-Browser\User Data\Default\`

### 3.5 Opera

**Hive:** NTUSER.DAT, SOFTWARE

| Registry Path | Forensic Value |
|---|---|
| `HKCU\Software\Opera Software` | Opera installation path and settings |
| `HKLM\SOFTWARE\Opera Software` | System-wide Opera installation |
| `HKLM\SOFTWARE\Clients\StartMenuInternet\OperaStable` | Default browser registration |

**Profile data:** `%AppData%\Opera Software\Opera Stable\`

### 3.6 Vivaldi

**Hive:** NTUSER.DAT, SOFTWARE

| Registry Path | Forensic Value |
|---|---|
| `HKCU\Software\Vivaldi` | Vivaldi settings |
| `HKLM\SOFTWARE\Vivaldi` | System-wide installation |
| `HKLM\SOFTWARE\Clients\StartMenuInternet\Vivaldi` | Default browser registration |

**Profile data:** `%LocalAppData%\Vivaldi\User Data\Default\`

### 3.7 Tor Browser

**Storage:** Primarily portable/file-based, minimal registry footprint
- Default install: `%USERPROFILE%\Desktop\Tor Browser\` (portable, no installer)
- Evidence of download: Check `RecentDocs`, `OpenSavePidlMRU`, UserAssist for `torbrowser-install-*.exe`
- May leave traces in `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist` if run via Explorer

### 3.8 Internet Explorer / Edge Legacy

**Hive:** NTUSER.DAT, SOFTWARE

| Registry Path | Forensic Value |
|---|---|
| `HKCU\Software\Microsoft\Internet Explorer\TypedURLs` | Typed URLs — populated when browser closes (IE6) or in real-time (IE8+) |
| `HKCU\Software\Microsoft\Internet Explorer\TypedURLsTime` | Timestamps for each TypedURL entry |
| `HKCU\Software\Microsoft\Internet Explorer\Download Directory` | Default download location |
| `HKCU\Software\Microsoft\Internet Explorer\Main\Start Page` | Homepage setting |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ProxyEnable` | Proxy enabled flag |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ProxyServer` | Proxy server address |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ProxyOverride` | Proxy bypass list |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\` | Trusted/restricted sites |

---

## 4. Email Clients

### 4.1 Microsoft Outlook

**Hive:** NTUSER.DAT, SOFTWARE

| Registry Path | Forensic Value |
|---|---|
| `HKCU\Software\Microsoft\Office\16.0\Outlook\Profiles\` | All Outlook profiles — email accounts, data file paths, server configs |
| `HKCU\Software\Microsoft\Office\16.0\Outlook\Profiles\Outlook\9375CFF0413111d3B88A00104B2A6676\` | Individual account settings (binary-encoded) |
| `HKCU\Software\Microsoft\Office\16.0\Outlook\PST\` | PST file paths associated with profiles |
| `HKCU\Software\Microsoft\Office\16.0\Outlook\Search\` | Search index configuration |
| `HKCU\Software\Microsoft\Office\16.0\Outlook\AutoDiscover\` | Auto-discovered email server settings |
| `HKCU\Software\Microsoft\Office\16.0\Outlook\ForceOSTPath` | Forced OST file location |
| `HKCU\Software\Microsoft\Office\16.0\Outlook\ForcePSTPath` | Forced PST file location |
| `HKLM\Software\Microsoft\Office\16.0\Outlook\` | System-wide Outlook settings, add-ins, security |
| `HKLM\Software\Microsoft\Office\ClickToRun\` | Office 365 / Click-to-Run installation metadata |
| `HKCU\Software\Microsoft\Protected Storage System Provider\` | Legacy password storage (Outlook Express, pre-2013) |

**Version mapping:** Replace `16.0` with: `15.0` (2013), `14.0` (2010), `12.0` (2007)

**Data files:**
- PST: `%USERPROFILE%\Documents\Outlook Files\`
- OST: `%LocalAppData%\Microsoft\Outlook\`

**Forensic tip:** Search for value name `001e660b` within profile keys to identify data file paths.

### 4.2 Mozilla Thunderbird

**Hive:** Minimal registry use

| Registry Path | Forensic Value |
|---|---|
| `HKLM\SOFTWARE\Mozilla\Mozilla Thunderbird\` | Installation version and path |
| `HKLM\SOFTWARE\Clients\Mail\Mozilla Thunderbird` | Default mail client registration |
| `HKCU\Software\Mozilla\Thunderbird\` | User-level settings |

**Primary Storage is File-Based:**
- Profile: `%AppData%\Roaming\Thunderbird\Profiles\<random>.default\`
- Email storage: MBOXRD format files (no extension) in profile `Mail\` and `ImapMail\` folders
- Contacts: `history.mab` (Mozilla Address Book)
- Credentials: `logins.json` + `key4.db` + `cert9.db` (NSS database)
- Message index: `global-messages-db.sqlite`

### 4.3 eM Client

**Hive:** NTUSER.DAT

| Registry Path | Forensic Value |
|---|---|
| `HKCU\Software\eM Client\` | Application settings |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{GUID}_is1` | Install metadata |

**Data:** `%AppData%\eM Client\` (SQLite databases)

### 4.4 Mailbird

**Hive:** NTUSER.DAT

| Registry Path | Forensic Value |
|---|---|
| `HKCU\Software\Mailbird\` | Application settings |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Mailbird` | Install metadata |

**Data:** `%LocalAppData%\Mailbird\Store\` (SQLite databases)

---

## 5. Cloud Storage / Sync

### 5.1 Microsoft OneDrive

**Hive:** NTUSER.DAT, SOFTWARE

| Registry Path | Forensic Value |
|---|---|
| `HKCU\Software\Microsoft\OneDrive` | OneDrive root config — account info, sync status |
| `HKCU\Software\Microsoft\OneDrive\Accounts\Personal` | Personal account details (email, CID, folder path) |
| `HKCU\Software\Microsoft\OneDrive\Accounts\Business1` | Business/M365 account details (SPOResourceID, tenant) |
| `HKCU\Software\Microsoft\OneDrive\Accounts\Personal\Tenants` | Shared folders tracking (Teams, SharePoint) |
| `HKCU\Software\Microsoft\OneDrive\Accounts\Business1\Tenants` | Business shared folder tracking |
| `HKCU\Software\Microsoft\OneDrive\UserNameCollection` | All associated Microsoft account usernames |
| `HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive` | Admin/GPO OneDrive policies |
| `HKLM\SOFTWARE\Microsoft\OneDrive` | System-level OneDrive config |

**File artifacts:** `%LocalAppData%\Microsoft\OneDrive\` (logs, `<CID>.ini`, `<CID>.dat`)

### 5.2 Dropbox

**Hive:** NTUSER.DAT, SOFTWARE

| Registry Path | Forensic Value |
|---|---|
| `HKCU\Software\Dropbox\ks\client` | DPAPI-encrypted key blob |
| `HKCU\Software\Dropbox\` | User Dropbox configuration |
| `HKLM\SOFTWARE\Dropbox\` | System-level Dropbox install |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Dropbox` | Install metadata |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Dropbox` | Auto-start entry |

**File artifacts:**
- `%AppData%\Dropbox\` — Config databases (SQLite)
- `%AppData%\Dropbox\instance1\` — `filecache.db` (all synced file metadata), `config.dbx`

### 5.3 Google Drive (Drive for Desktop)

**Hive:** NTUSER.DAT, SOFTWARE

| Registry Path | Forensic Value |
|---|---|
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\GoogleDriveFS` | Auto-start entry (user-level) |
| `HKLM\SOFTWARE\Google\DriveFS` | System-level installation |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{GUID}` | Install metadata |

**File artifacts:**
- `%LocalAppData%\Google\DriveFS\<account_hash>\` — SQLite databases
- `%LocalAppData%\Google\DriveFS\Logs\` — `Sync_log.log` (email, filenames, timestamps, MD5 hashes)
- `%LocalAppData%\Google\DriveFS\<hash>\content_cache\` — Cached file content

### 5.4 Box Drive

**Hive:** NTUSER.DAT, SOFTWARE

| Registry Path | Forensic Value |
|---|---|
| `HKCU\Software\Box\Box` | User-level Box configuration |
| `HKLM\SOFTWARE\Box\Box` | System-level installation |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{GUID}` | Install metadata |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Box` | Auto-start entry |

### 5.5 iCloud for Windows

**Hive:** NTUSER.DAT, SOFTWARE

| Registry Path | Forensic Value |
|---|---|
| `HKLM\SOFTWARE\Apple Inc.\iCloud` | iCloud installation and config |
| `HKCU\Software\Apple Inc.\iCloud` | User iCloud settings |
| `HKLM\SOFTWARE\Apple Inc.\Internet Services\` | Apple ID service config |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{GUID}` | Install metadata |

### 5.6 MEGA

**Hive:** NTUSER.DAT

| Registry Path | Forensic Value |
|---|---|
| `HKCU\Software\Mega Limited\MEGAsync` | MEGA sync client settings |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\MEGAsync` | Install metadata |

### 5.7 pCloud

**Hive:** NTUSER.DAT

| Registry Path | Forensic Value |
|---|---|
| `HKCU\Software\pCloud\pCloud` | pCloud settings |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\pCloud` | Install metadata |

### 5.8 Nextcloud

**Hive:** NTUSER.DAT, SOFTWARE

| Registry Path | Forensic Value |
|---|---|
| `HKCU\Software\Nextcloud\Nextcloud` | User sync config |
| `HKLM\SOFTWARE\Nextcloud\Nextcloud` | System installation |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Nextcloud` | Install metadata |

### 5.9 Syncthing

**Storage:** File-based, minimal registry
- Config: `%LocalAppData%\Syncthing\config.xml` (device IDs, folder shares, connection addresses)
- Install evidence via standard Uninstall registry keys

---

## 6. Messaging / Communication

### 6.1 Microsoft Teams

**Hive:** NTUSER.DAT

| Registry Path | Forensic Value |
|---|---|
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\Teams` | User-level Teams install (Electron-based, per-user) |
| `HKLM\SOFTWARE\Microsoft\Teams` | New Teams (MSIX/system-wide) installation |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\MSTeams` | New Teams uninstall info |
| `HKCU\Software\Microsoft\Office\16.0\Teams\` | Teams integration with Office |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\com.squirrel.Teams.Teams` | Auto-start (old Teams) |

**File artifacts:** `%AppData%\Microsoft\Teams\` (IndexedDB, Local Storage, Cookies — Chromium-based cache structure)

### 6.2 Slack

**Hive:** NTUSER.DAT

| Registry Path | Forensic Value |
|---|---|
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\slack` | Slack install (Electron, per-user via Squirrel) |
| `HKCU\Software\Slack Technologies\` | Slack settings |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\com.squirrel.slack.slack` | Auto-start entry |

**File artifacts:** `%AppData%\Slack\` (Chromium-based cache, Local Storage, IndexedDB)

### 6.3 Discord

**Hive:** NTUSER.DAT

| Registry Path | Forensic Value |
|---|---|
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\Discord` | Discord install (Electron, per-user) |
| `HKCU\Software\Discord\` | Discord settings |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Discord` | Auto-start entry |

**File artifacts:**
- `%AppData%\discord\` — Chromium-based cache (Local Storage, Cache)
- Plaintext messages and unencrypted files stored as cached files
- `%LocalAppData%\Discord\` — Executable and updates

### 6.4 Zoom

**Hive:** NTUSER.DAT, SOFTWARE

| Registry Path | Forensic Value |
|---|---|
| `HKCU\Software\Zoom\` | User Zoom settings |
| `HKCU\Software\ZoomUMX\` | Zoom universal settings |
| `HKLM\SOFTWARE\Zoom\` | System-level Zoom installation |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\ZoomUMX` | Install metadata |
| `HKLM\SOFTWARE\Policies\Zoom\Zoom Meetings\` | Enterprise policies |

**File artifacts:** `%AppData%\Zoom\` (logs, `data\zoomus.enc` — encrypted config)

### 6.5 Skype

**Hive:** NTUSER.DAT (UWP app)

| Registry Path | Forensic Value |
|---|---|
| `HKU\<SID>\Software\Classes\LocalSettings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\Microsoft.SkypeApp_*` | UWP app data |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Lync` | Skype for Business auto-start |
| `HKCU\Software\Skype\` | Legacy Skype desktop settings |

**File artifacts:**
- `%AppData%\Local\Packages\Microsoft.SkypeApp_*\LocalState\` — SQLite databases (unencrypted messages)
- `%AppData%\Skype\<username>\main.db` — Legacy Skype message database

### 6.6 Telegram Desktop

**Hive:** Minimal registry use

| Registry Path | Forensic Value |
|---|---|
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\{GUID}_is1` | Install metadata |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Telegram` | Auto-start |

**File artifacts:**
- `%AppData%\Roaming\Telegram Desktop\` — Encrypted database, media cache
- Database is encrypted; memory forensics may be required for message recovery
- Secret chats are only accessible on the creating device

### 6.7 Signal Desktop

**Hive:** Minimal registry use

| Registry Path | Forensic Value |
|---|---|
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\{GUID}` | Install metadata |

**File artifacts:**
- `%AppData%\Signal\` — `sql\db.sqlite` (AES-GCM encrypted database)
- Key stored in `%AppData%\Signal\config.json` (`key` field) or USERKEY_SignalSecret
- Decryption requires access to the `config.json` key

### 6.8 WhatsApp Desktop

**Hive:** NTUSER.DAT

| Registry Path | Forensic Value |
|---|---|
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\WhatsApp` | Install metadata |
| `HKCU\Software\WhatsApp\` | WhatsApp settings |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WhatsApp` | Auto-start |

**File artifacts:** `%LocalAppData%\WhatsApp\` (Chromium-based cache, IndexedDB)

### 6.9 Cisco Webex

**Hive:** NTUSER.DAT, SOFTWARE

| Registry Path | Forensic Value |
|---|---|
| `HKCU\Software\Cisco Spark Native\` | Webex App (Spark) user settings |
| `HKCU\Software\Cisco Spark Native\PreventPreloginUpdates` | Update suppression flag |
| `HKLM\Software\Cisco Spark Native\` | System-level Webex config |
| `HKLM\SOFTWARE\Cisco\WebexConnect\` | Webex Connect settings |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{GUID}` | Install metadata |

---

## 7. Development Tools

### 7.1 Visual Studio Code

**Hive:** NTUSER.DAT, SOFTWARE

| Registry Path | Forensic Value |
|---|---|
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\{GUID}_is1` | User-level VS Code install |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{GUID}_is1` | System-level VS Code install |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\code.exe` | Application path |
| `HKCR\Applications\Code.exe\` | File associations |
| `HKCU\Software\Classes\vscode\` | URI protocol handler |

**File artifacts:** `%AppData%\Code\` (settings.json, extensions, workspaceStorage, globalStorage)

### 7.2 Visual Studio

**Hive:** NTUSER.DAT, SOFTWARE

| Registry Path | Forensic Value |
|---|---|
| `HKLM\SOFTWARE\Microsoft\VisualStudio\<version>\` | Visual Studio installation |
| `HKCU\Software\Microsoft\VisualStudio\<version>\` | User settings |
| `HKLM\SOFTWARE\Microsoft\VisualStudio\SxS\VS7` | Side-by-side VS installations (version -> install path) |
| `HKLM\SOFTWARE\WOW6432Node\Microsoft\VisualStudio\SxS\VS7` | 32-bit VS installs on 64-bit OS |
| `HKCU\Software\Microsoft\VisualStudio\<version>\MRUFiles` | Recent files |
| `HKCU\Software\Microsoft\VisualStudio\<version>\ProjectMRUList` | Recent projects |

### 7.3 JetBrains IDEs (IntelliJ, PyCharm, WebStorm, etc.)

**Hive:** NTUSER.DAT, SOFTWARE

| Registry Path | Forensic Value |
|---|---|
| `HKCU\Software\JetBrains\<ProductName>\<version>\` | Per-product user settings |
| `HKLM\SOFTWARE\JetBrains\` | Installation info |
| `HKCU\Software\JetBrains\Toolbox\` | JetBrains Toolbox manager |
| `HKCR\jetbrains-*.exe\` | URI protocol handlers (e.g., `jetbrains-idea://`) |

**File artifacts:** `%AppData%\JetBrains\<Product><version>\` (config, plugins, recent projects)

### 7.4 Git for Windows

**Hive:** SOFTWARE

| Registry Path | Forensic Value |
|---|---|
| `HKLM\SOFTWARE\GitForWindows` | `InstallPath`, `CurrentVersion`, `LibExecPath` |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Git_is1` | Install metadata, version |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\App Paths\git.exe` | Per-user Git path |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\git.exe` | System-wide Git path |

**File artifacts:** `%USERPROFILE%\.gitconfig` (user identity, credential helper), `%USERPROFILE%\.git-credentials` (plaintext credentials if store helper used)

### 7.5 Docker Desktop

**Hive:** SOFTWARE

| Registry Path | Forensic Value |
|---|---|
| `HKLM\SOFTWARE\Docker Inc.\Docker Desktop` | Installation path and settings |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Docker Desktop` | Install metadata |
| `HKLM\SYSTEM\CurrentControlSet\Services\com.docker.service` | Docker service |
| `HKLM\SYSTEM\CurrentControlSet\Services\docker` | Docker Engine service |

**File artifacts:** `%AppData%\Docker\` (settings.json), `%USERPROFILE%\.docker\config.json` (registry auth)

### 7.6 Windows Subsystem for Linux (WSL)

**Hive:** NTUSER.DAT, SOFTWARE

| Registry Path | Forensic Value |
|---|---|
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Lxss\` | WSL distribution registrations |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Lxss\{GUID}\` | Per-distro config (DistributionName, BasePath, DefaultUid, State) |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Lxss\` | System-level WSL config |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlocks\` | Developer mode / sideload settings |

**Key Notes:** Each WSL distribution has a GUID subkey containing `DistributionName`, `BasePath` (VHD path), and `DefaultUid`.

### 7.7 Python

**Hive:** SOFTWARE, NTUSER.DAT

| Registry Path | Forensic Value |
|---|---|
| `HKLM\SOFTWARE\Python\PythonCore\<version>\InstallPath` | System-wide Python install location |
| `HKCU\Software\Python\PythonCore\<version>\InstallPath` | Per-user Python install location |
| `HKLM\SOFTWARE\Python\PythonCore\<version>\PythonPath` | Module search path |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\python.exe` | Python executable path |

### 7.8 Anaconda / Miniconda

**Hive:** SOFTWARE, NTUSER.DAT

| Registry Path | Forensic Value |
|---|---|
| `HKLM\SOFTWARE\Python\ContinuumAnalytics\Anaconda<version>-<arch>\InstallPath` | Anaconda install location |
| `HKCU\Software\Python\ContinuumAnalytics\Anaconda<version>-<arch>\InstallPath` | Per-user Anaconda install |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Anaconda<version>` | Install metadata |

### 7.9 Node.js

**Hive:** SOFTWARE

| Registry Path | Forensic Value |
|---|---|
| `HKLM\SOFTWARE\Node.js` | `InstallPath`, `Version` |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{GUID}` | Install metadata |

---

## 8. Database / Admin Tools

### 8.1 SQL Server Management Studio (SSMS)

**Hive:** SOFTWARE, NTUSER.DAT

| Registry Path | Forensic Value |
|---|---|
| `HKLM\SOFTWARE\WOW6432Node\Microsoft\Microsoft SQL Server Management Studio` | SSMS installation |
| `HKLM\SOFTWARE\Microsoft\Microsoft SQL Server\<InstanceID>\` | SQL Server instance config |
| `HKCU\Software\Microsoft\Microsoft SQL Server\` | Per-user SQL Server settings |
| `HKCU\Software\Microsoft\SQL Server Management Studio\<version>\` | SSMS user preferences, MRU |
| `HKLM\SOFTWARE\Microsoft\MSSQLServer\` | SQL Server root config |

### 8.2 MySQL Workbench

**Hive:** SOFTWARE

| Registry Path | Forensic Value |
|---|---|
| `HKLM\SOFTWARE\MySQL AB\MySQL Server <version>` | MySQL Server installation |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{GUID}` | MySQL Workbench install metadata |
| `HKLM\SYSTEM\CurrentControlSet\Services\MySQL<version>` | MySQL service |

**File artifacts:** `%AppData%\MySQL\Workbench\` (connections.xml — server connections with credentials, sql_history/)

### 8.3 HeidiSQL

**Hive:** NTUSER.DAT

| Registry Path | Forensic Value |
|---|---|
| `HKCU\Software\HeidiSQL\` | Application settings |
| `HKCU\Software\HeidiSQL\Servers\` | All saved server connections |
| `HKCU\Software\HeidiSQL\Servers\<ServerName>\Host` | Server hostname |
| `HKCU\Software\HeidiSQL\Servers\<ServerName>\User` | Username |
| `HKCU\Software\HeidiSQL\Servers\<ServerName>\Password` | Encrypted password (trivially reversible) |
| `HKCU\Software\HeidiSQL\Servers\<ServerName>\Port` | Port number |
| `HKCU\Software\HeidiSQL\Servers\<ServerName>\NetType` | Connection type (MySQL, PostgreSQL, MSSQL, etc.) |

**Key Notes:** HeidiSQL passwords are stored with simple encoding — multiple tools can decrypt them. Portable mode uses `portable_settings.txt`.

### 8.4 pgAdmin 4

**Hive:** Minimal registry use (Python/web-based)

| Registry Path | Forensic Value |
|---|---|
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\pgAdmin 4` | Install metadata |

**File artifacts:** `%AppData%\pgAdmin\` (servers.json, pgadmin4.db SQLite database with connection configs)

### 8.5 DBeaver

**Hive:** Minimal registry use (Java-based)

| Registry Path | Forensic Value |
|---|---|
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\DBeaver*` | Install metadata |

**File artifacts:** `%AppData%\DBeaverData\workspace6\General\.dbeaver\` (data-sources.json — all connections with credentials)

### 8.6 MongoDB Compass

**Hive:** NTUSER.DAT

| Registry Path | Forensic Value |
|---|---|
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\{GUID}` | Install metadata (Electron app) |

**File artifacts:** `%AppData%\MongoDB Compass\` (Chromium-based storage, connection strings in local storage)

---

## 9. Security / Privacy Tools

### 9.1 Wireshark

**Hive:** SOFTWARE

| Registry Path | Forensic Value |
|---|---|
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Wireshark` | Install metadata, version |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\Wireshark.exe` | Application path |

**File artifacts:** `%AppData%\Wireshark\` (preferences, recent capture files, display filter macros, profiles)

### 9.2 Nmap / Zenmap

**Hive:** SOFTWARE

| Registry Path | Forensic Value |
|---|---|
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Nmap` | Install metadata |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\nmap.exe` | Application path |

### 9.3 Burp Suite

**Hive:** Minimal registry (Java-based)

| Registry Path | Forensic Value |
|---|---|
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Burp Suite*` | Install metadata |

**File artifacts:** `%USERPROFILE%\.BurpSuite\` (project files, config, captured data)

### 9.4 Process Hacker / System Informer

**Hive:** SOFTWARE

| Registry Path | Forensic Value |
|---|---|
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Process_Hacker2_is1` | Install metadata |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\SystemInformer_is1` | System Informer (successor) |

### 9.5 CCleaner

**Hive:** NTUSER.DAT, SOFTWARE

| Registry Path | Forensic Value |
|---|---|
| `HKCU\Software\Piriform\CCleaner` | User settings — (App) prefixed values show what was cleaned |
| `HKLM\SOFTWARE\Piriform\CCleaner` | System-level CCleaner config |
| `HKCU\Software\Piriform\CCleaner\(App)*.FileType` | File types selected for cleaning |

**Key Notes:**
- The Last Write Timestamp on `HKCU\Software\Piriform\CCleaner` correlates with last execution time
- Values prefixed with `(App)` set to `True` indicate items selected for cleaning
- Custom RegRipper plugin available (cheeky4n6monkey blog)

### 9.6 VeraCrypt

**Hive:** SOFTWARE

| Registry Path | Forensic Value |
|---|---|
| `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\VeraCrypt` | Install metadata |
| `HKLM\SYSTEM\MountedDevices` | Mounted VeraCrypt volumes (device mappings) |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\VeraCrypt.exe` | Application path |

**Key Notes:**
- ShellBag entries may reveal access to VeraCrypt mount points (drive letters)
- Windows assigns drive letters to mounted volumes, leaving traces in MountedDevices
- Issue #276: ShellBag leak documentation for VeraCrypt containers

### 9.7 KeePass

**Hive:** Minimal registry use (file-based config)

| Registry Path | Forensic Value |
|---|---|
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\KeePassPasswordSafe2_is1` | Install metadata |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\KeePass.exe` | Application path |

**File artifacts:** `KeePass.config.xml` (in app directory or `%AppData%\KeePass\`)

**Key Notes:**
- Key file paths may appear in `OpenSavePidlMRU` registry
- Database file paths appear in `RecentDocs` and `OpenSavePidlMRU`
- KeePass config is XML-based, not registry-based

### 9.8 1Password

**Hive:** NTUSER.DAT

| Registry Path | Forensic Value |
|---|---|
| `HKCU\Software\AgileBits\1Password\` | User settings |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{GUID}` | Install metadata |

**File artifacts:** `%LocalAppData%\1Password\` (encrypted vault, logs)

### 9.9 Bitwarden

**Hive:** NTUSER.DAT

| Registry Path | Forensic Value |
|---|---|
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\{GUID}` | Install metadata (Electron app) |
| `HKCU\Software\Bitwarden\` | User settings |

**File artifacts:** `%AppData%\Bitwarden\` (encrypted vault, Chromium-based storage)

---

## 10. Virtualization

### 10.1 VMware Workstation / Player

**Hive:** SOFTWARE

| Registry Path | Forensic Value |
|---|---|
| `HKLM\SOFTWARE\VMware, Inc.\VMware Workstation` | Installation path, version, license |
| `HKLM\SOFTWARE\VMware, Inc.\VMware Player` | VMware Player installation |
| `HKLM\SOFTWARE\VMware, Inc.\` | VMware root key — presence indicates VMware was installed |
| `HKLM\SYSTEM\CurrentControlSet\Services\VMware NAT Service` | VMware NAT service |
| `HKLM\SYSTEM\CurrentControlSet\Services\VMnetDHCP` | VMware DHCP service |
| `HKLM\SYSTEM\CurrentControlSet\Services\VMwareHostd` | VMware Workstation Server service |
| `HKLM\SYSTEM\CurrentControlSet\Services\VMAuthdService` | VMware Authorization service |
| `HKCU\Software\VMware, Inc.\VMware Workstation\MRU` | Recent VM files |

**VM detection keys (for detecting if running INSIDE a VM):**
- `HKLM\HARDWARE\DEVICEMAP\Scsi\...\Identifier` containing `VMWARE`
- `HKLM\SYSTEM\CurrentControlSet\Services\VMTools`
- `HKLM\SOFTWARE\VMware, Inc.\VMware Tools`

### 10.2 Oracle VirtualBox

**Hive:** SOFTWARE

| Registry Path | Forensic Value |
|---|---|
| `HKLM\SOFTWARE\Oracle\VirtualBox` | Installation path, version |
| `HKLM\SOFTWARE\Oracle\VirtualBox\Instdir` | Install directory |
| `HKLM\SYSTEM\CurrentControlSet\Services\VBoxDrv` | VirtualBox driver service |
| `HKLM\SYSTEM\CurrentControlSet\Services\VBoxNetAdp` | VirtualBox network adapter service |
| `HKLM\SYSTEM\CurrentControlSet\Services\VBoxNetLwf` | VirtualBox network filter service |
| `HKLM\SYSTEM\CurrentControlSet\Services\VBoxSup` | VirtualBox support driver |
| `HKLM\SYSTEM\CurrentControlSet\Services\VBoxUSBMon` | VirtualBox USB monitor |
| `HKCU\Software\Oracle\VirtualBox\` | Per-user VirtualBox settings |

**VM detection keys:**
- `HKLM\SYSTEM\CurrentControlSet\Services\VBoxGuest` — Guest Additions installed
- `HKLM\HARDWARE\DEVICEMAP\Scsi\...\Identifier` containing `VBOX`
- MAC address prefix: `08:00:27`

### 10.3 Hyper-V

**Hive:** SOFTWARE, SYSTEM

| Registry Path | Forensic Value |
|---|---|
| `HKLM\SOFTWARE\Microsoft\Hyper-V` | Hyper-V installation presence |
| `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization` | Virtualization settings |
| `HKLM\SYSTEM\CurrentControlSet\Services\vmms` | Virtual Machine Management Service |
| `HKLM\SYSTEM\CurrentControlSet\Services\vmcompute` | Hyper-V Host Compute Service |
| `HKLM\SYSTEM\CurrentControlSet\Services\vmicheartbeat` | Hyper-V Heartbeat Service (guest) |
| `HKLM\SYSTEM\CurrentControlSet\Services\vmicshutdown` | Hyper-V Guest Shutdown Service |
| `HKLM\SYSTEM\CurrentControlSet\Services\vmicvss` | Hyper-V Volume Shadow Copy |

**VM detection keys:**
- `HKLM\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\Protocol_Catalog9\Catalog_Entries\*\ProtocolName` containing `Hyper-V RAW`
- `HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E968-E325-11CE-BFC1-08002BE10318}\000\DriverDesc` containing `Microsoft Hyper-V Video`

---

## 11. File Transfer / Sharing

### 11.1 qBittorrent

**Hive:** NTUSER.DAT

| Registry Path | Forensic Value |
|---|---|
| `HKCU\Software\qBittorrent\` | Application settings |
| `HKCU\Software\qBittorrent\qBittorrent` | Detailed config (download path, listen port) |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\qBittorrent` | Install metadata |
| `HKCR\.torrent` | Torrent file association |
| `HKCR\magnet` | Magnet link protocol handler |

**File artifacts:** `%LocalAppData%\qBittorrent\` (BT_backup/ — resume data for all torrents)

### 11.2 uTorrent / BitTorrent

**Hive:** NTUSER.DAT, UsrClass.dat

| Registry Path | Forensic Value |
|---|---|
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\uTorrent` | Install metadata (user-level install) |
| `HKU\{SID}_CLASSES\utorrent` | URI protocol handler (default value: "utorrent URI") |
| `HKU\{SID}_CLASSES\utorrent\shell\open\command` | Points to uTorrent executable |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.torrent` | Recently accessed .torrent files |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU\torrent` | Torrent files opened/saved via Windows dialog |
| `HKCR\.torrent` | Torrent file association |
| `HKCR\magnet` | Magnet link handler |

**File artifacts:** `%AppData%\uTorrent\` (resume.dat, settings.dat, dht.dat, *.torrent files)

**UsrClass.dat:** `Local Settings\Software\Microsoft\Windows\Shell\MuiCache` — records executed application names including torrent clients

### 11.3 Transmission

**Hive:** Minimal registry use

| Registry Path | Forensic Value |
|---|---|
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Transmission` | Install metadata |

**File artifacts:** `%LocalAppData%\Transmission\` (torrents/, resume/, stats.json)

### 11.4 ShareX

**Hive:** NTUSER.DAT

| Registry Path | Forensic Value |
|---|---|
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\ShareX_is1` | Install metadata |
| `HKCU\Software\ShareX\` | ShareX settings |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\ShareX` | Auto-start |

**File artifacts:** `%USERPROFILE%\Documents\ShareX\` (screenshots, upload history, settings)

---

## 12. Compression / Utilities

### 12.1 7-Zip

**Hive:** SOFTWARE, NTUSER.DAT

| Registry Path | Forensic Value |
|---|---|
| `HKLM\SOFTWARE\7-Zip` | `Path`, `Path64` — installation directories |
| `HKCU\Software\7-Zip\` | User preferences |
| `HKCU\Software\7-Zip\FM\` | File Manager settings, last accessed paths |
| `HKCU\Software\7-Zip\Extraction\` | Default extraction path |
| `HKCU\Software\7-Zip\Compression\` | Default compression settings |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\7-Zip` | Install metadata |
| `HKCR\.7z` | 7-Zip file association |
| `HKCR\7-Zip.7z` | 7z file type handler |

### 12.2 WinRAR

**Hive:** SOFTWARE, NTUSER.DAT

| Registry Path | Forensic Value |
|---|---|
| `HKLM\SOFTWARE\WinRAR` | Installation path, version |
| `HKCU\Software\WinRAR\` | User settings |
| `HKCU\Software\WinRAR\ArcHistory` | Recently opened archives |
| `HKCU\Software\WinRAR\DialogEditHistory\ExtrPath` | Recent extraction paths |
| `HKCU\Software\WinRAR\DialogEditHistory\ArcName` | Recent archive names |
| `HKCU\Software\WinRAR\General\ExtrPath` | Default extraction path |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\WinRAR archiver` | Install metadata |
| `HKCR\.rar` | RAR file association |
| `HKCR\WinRAR` | WinRAR file type handler |

### 12.3 WinZip

**Hive:** SOFTWARE, NTUSER.DAT

| Registry Path | Forensic Value |
|---|---|
| `HKLM\SOFTWARE\WinZip Computing\WinZip` | Installation path, version |
| `HKCU\Software\Nico Mak Computing\WinZip\` | User settings (legacy vendor name) |
| `HKCU\Software\WinZip Computing\WinZip\` | User settings |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{GUID}` | Install metadata |
| `HKCR\.zip\` | ZIP file association |

### 12.4 PeaZip

**Hive:** SOFTWARE

| Registry Path | Forensic Value |
|---|---|
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{GUID}_is1` | Install metadata |
| `HKCR\.pea` | PeaZip archive association |

---

## 13. Office / Productivity

### 13.1 Adobe Acrobat / Reader

**Hive:** NTUSER.DAT, SOFTWARE

| Registry Path | Forensic Value |
|---|---|
| `HKCU\Software\Adobe\Acrobat Reader\DC\AVGeneral\cRecentFiles` | Recently opened PDFs — file path, name, size, page count, timestamps |
| `HKCU\Software\Adobe\Acrobat Reader\DC\AVGeneral\cRecentFiles\c<N>\tDIText` | Individual file path |
| `HKCU\Software\Adobe\Acrobat Reader\DC\AVGeneral\cRecentFiles\c<N>\tFileName` | File name |
| `HKCU\Software\Adobe\Acrobat Reader\DC\SessionManagement` | Session recovery data |
| `HKCU\Software\Adobe\Acrobat Reader\DC\ShareIdentity` | Adobe Sign-in identity |
| `HKCU\Software\Adobe\Adobe Acrobat\DC\AVGeneral\cRecentFiles` | Acrobat Pro recent files |
| `HKCU\Software\Adobe\<Product>\<Version>\TrustManager\cTrustedFolders` | Trusted folder locations |
| `HKCU\Software\Adobe\<Product>\<Version>\TrustManager\bEnhancedSecurityStandalone` | Enhanced security flag |
| `HKLM\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown` | Admin-locked security policies |
| `HKLM\SOFTWARE\Adobe\Acrobat Reader\DC\Installer` | Installation metadata |

**Forensic value:** Recent files include: File Name, Path, Size, Source, Page Count, Host OS, Favorite status, Last Accessed, Last Update timestamps.

### 13.2 LibreOffice

**Hive:** SOFTWARE (minimal registry use)

| Registry Path | Forensic Value |
|---|---|
| `HKLM\SOFTWARE\LibreOffice\LibreOffice\` | Installation info |
| `HKLM\SOFTWARE\Policies\LibreOffice\org.openoffice.Office.Common\` | GPO policies |
| `HKCU\Software\Policies\LibreOffice\` | User-level policies |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{GUID}` | Install metadata |

**File artifacts:** `%AppData%\LibreOffice\user\registrymodifications.xcu` (XML config, recent files)

### 13.3 Notepad++

**Hive:** SOFTWARE, NTUSER.DAT

| Registry Path | Forensic Value |
|---|---|
| `HKLM\SOFTWARE\Notepad++` | Installation path |
| `HKCU\Software\Notepad++\` | User preferences |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Notepad++` | Install metadata |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\notepad++.exe` | Application path |
| `HKCU\Software\Classes\Applications\notepad++.exe\` | File association data |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts` | Extension association entries |

**File artifacts:**
- `%AppData%\Notepad++\` (session.xml — open files, backup/ — unsaved content, config.xml)
- `%AppData%\Notepad++\session.xml` — Lists all open files with their paths

### 13.4 Sublime Text

**Hive:** Minimal registry use

| Registry Path | Forensic Value |
|---|---|
| `HKCR\Directory\Background\shell\sublime_text\` | Context menu integration |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Sublime Text_is1` | Install metadata |

**File artifacts:** `%AppData%\Sublime Text\Local\Session.sublime_session` (JSON — all open files, recent files, unsaved content)

---

## 14. System / Network Utilities

### 14.1 Sysinternals Tools (EulaAccepted)

**Hive:** NTUSER.DAT

| Registry Path | Forensic Value |
|---|---|
| `HKCU\Software\Sysinternals\<ToolName>\EulaAccepted` | Proves execution of specific Sysinternals tool |
| `HKCU\Software\Sysinternals\PsExec\EulaAccepted` | PsExec was run (lateral movement indicator) |
| `HKCU\Software\Sysinternals\PsKill\EulaAccepted` | PsKill was run |
| `HKCU\Software\Sysinternals\PsList\EulaAccepted` | PsList was run |
| `HKCU\Software\Sysinternals\Process Explorer\EulaAccepted` | Process Explorer was run |
| `HKCU\Software\Sysinternals\Process Monitor\EulaAccepted` | Process Monitor was run |
| `HKCU\Software\Sysinternals\Autoruns\EulaAccepted` | Autoruns was run |
| `HKCU\Software\Sysinternals\TCPView\EulaAccepted` | TCPView was run |
| `HKCU\Software\Sysinternals\Sysmon\EulaAccepted` | Sysmon was installed/configured |
| `HKCU\Software\Sysinternals\ProcDump\EulaAccepted` | ProcDump was run (credential dumping indicator) |
| `HKU\.DEFAULT\Software\Sysinternals\<ToolName>\EulaAccepted` | Tool run under SYSTEM account |

**Key Notes:**
- SIGMA detection rule exists for renamed Sysinternals tools (non-standard names setting EulaAccepted)
- Velociraptor uses glob `HKEY_USERS\*\Software\Sysinternals\*` for detection
- `EulaAccepted = 1` means accepted, `0` means declined
- PsExec EULA acceptance under a non-admin account is a strong indicator of lateral movement

### 14.2 PowerShell Configuration

**Hive:** SOFTWARE

| Registry Path | Forensic Value |
|---|---|
| `HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell\ExecutionPolicy` | PowerShell execution policy |
| `HKCU\Software\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell\ExecutionPolicy` | Per-user execution policy |
| `HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ExecutionPolicy` | GPO execution policy |
| `HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\EnableModuleLogging` | Module logging enabled |
| `HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames` | Logged modules (`*` = all) |
| `HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging` | Script block logging |
| `HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription\EnableTranscripting` | Transcription enabled |
| `HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription\OutputDirectory` | Transcript output directory |
| `HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription\EnableInvocationHeader` | Include invocation headers |
| `HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\*` | 32-bit PowerShell policies |

**Key Notes:**
- Module logging: Event ID 4103
- Script block logging: Event ID 4104 (captures de-obfuscated code)
- Console history: `%AppData%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_History.txt`
- Changes to logging keys monitored via Event ID 4657

### 14.3 Windows Terminal

**Hive:** NTUSER.DAT

| Registry Path | Forensic Value |
|---|---|
| `HKCU\Software\Classes\LocalSettings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\Microsoft.WindowsTerminal_*` | UWP app data |

**File artifacts:** `%LocalAppData%\Packages\Microsoft.WindowsTerminal_*\LocalState\settings.json`

### 14.4 Cygwin

**Hive:** SOFTWARE

| Registry Path | Forensic Value |
|---|---|
| `HKLM\SOFTWARE\Cygwin\setup` | Cygwin installation root path |
| `HKCU\Software\Cygwin\` | User Cygwin settings |

### 14.5 MSYS2

**Hive:** SOFTWARE

| Registry Path | Forensic Value |
|---|---|
| `HKLM\SOFTWARE\MSYS2` | MSYS2 installation info |

---

## 15. Remote Access (Supplemental)

These entries supplement the companion doc `remote-access-detection-artifacts.md`.

### 15.1 Remote Desktop Plus

**Hive:** NTUSER.DAT

| Registry Path | Forensic Value |
|---|---|
| `HKCU\Software\Donkz\Remote Desktop Plus\` | Application config and saved connections |
| `HKCU\Software\Donkz\Remote Desktop Plus\Connections\` | Saved connection details |

### 15.2 DameWare (SolarWinds)

**Hive:** SOFTWARE, SYSTEM

| Registry Path | Forensic Value |
|---|---|
| `HKLM\SOFTWARE\DameWare Development\` | DameWare installation config |
| `HKLM\SOFTWARE\SolarWinds\DameWare\` | SolarWinds DameWare config |
| `HKLM\SYSTEM\CurrentControlSet\Services\dwmrcs` | DameWare Mini Remote Control Service |
| `HKLM\SOFTWARE\Wow6432Node\DameWare Development\` | 32-bit DameWare on 64-bit OS |

### 15.3 Datto RMM

**Hive:** SOFTWARE, SYSTEM

| Registry Path | Forensic Value |
|---|---|
| `HKLM\SOFTWARE\CentraStage\` | Datto RMM (formerly CentraStage) installation |
| `HKLM\SYSTEM\CurrentControlSet\Services\CagService` | Datto RMM agent service |

### 15.4 NinjaRMM (NinjaOne)

**Hive:** SOFTWARE, SYSTEM

| Registry Path | Forensic Value |
|---|---|
| `HKLM\SOFTWARE\NinjaRMM\` | NinjaRMM agent installation |
| `HKLM\SYSTEM\CurrentControlSet\Services\NinjaRMMAgent` | NinjaRMM agent service |

---

## 16. LOLRMM Registry Artifact Master List

The following is the complete list of 63 unique registry paths from the LOLRMM project (16 of 294 tools have registry artifacts defined). Cross-reference with [lolrmm.io](https://lolrmm.io) for updates.

### Tools With Registry Artifacts in LOLRMM

| Tool | Registry Path Count | Key Paths |
|---|---|---|
| **TeamViewer** | 16 | `HKLM\SOFTWARE\TeamViewer\*`, `HKU\<SID>\SOFTWARE\TeamViewer\*`, `HKLM\SYSTEM\CurrentControlSet\Services\TeamViewer\*`, `HKLM\SOFTWARE\TeamViewer\ConnectionHistory` |
| **AnyDesk** | 8 | `HKLM\SOFTWARE\Clients\Media\AnyDesk`, `HKLM\SYSTEM\CurrentControlSet\Services\AnyDesk`, `HKLM\SOFTWARE\Classes\.anydesk\shell\open\command`, `HKLM\SOFTWARE\Classes\AnyDesk\shell\open\command`, `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Print\Printers\AnyDesk Printer\*`, `HKLM\DRIVERS\DriverDatabase\DeviceIds\USBPRINT\AnyDesk`, `HKLM\DRIVERS\DriverDatabase\DeviceIds\WSDPRINT\AnyDesk`, `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\AnyDesk` |
| **Splashtop** | 11 | `HKLM\SOFTWARE\WOW6432Node\Splashtop Inc.\*`, `HKLM\SYSTEM\CurrentControlSet\Services\SplashtopRemoteService`, `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Splashtop-*`, `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Network\SplashtopRemoteService`, `HKU\.DEFAULT\Software\Splashtop Inc.\*`, `HKU\<SID>\Software\Splashtop Inc.\*` |
| **Atera** | 9 | `HKLM\SOFTWARE\ATERA Networks\AlphaAgent`, `HKLM\SYSTEM\CurrentControlSet\Services\AteraAgent`, `HKLM\SOFTWARE\Microsoft\Tracing\AteraAgent_RASAPI32`, `HKLM\SOFTWARE\Microsoft\Tracing\AteraAgent_RASMANCS`, `HKLM\SYSTEM\ControlSet\Services\EventLog\Application\{AlphaAgent,AteraAgent}` |
| **GoToMyPC** | 4 | `HKLM\WOW6432Node\Citrix\GoToMyPc`, `HKLM\WOW6432Node\Citrix\GoToMyPc\GuestInvite`, `HKCU\SOFTWARE\Citrix\GoToMyPc\FileTransfer\history`, `HKU\<SID>\SOFTWARE\Citrix\GoToMyPc\FileTransfer\history` |
| **RAdmin** | 1 | `HKLM\SOFTWARE\WOW6432Node\Radmin\v3.0\Server\Parameters\Radmin Security` |
| **Action1** | 1 | `HKLM\SOFTWARE\WOW6432Node\Action1` |
| **Veyon** | 2 | `HKLM\SOFTWARE\Veyon Solutions`, `HKLM\SYSTEM\CurrentControlSet\Services\VeyonService` |
| **GoTo Resolve** | 1 | `HKLM\SOFTWARE\GoTo Resolve Unattended\` |
| **RdClient** | 1 | `HKLM\SOFTWARE\RdClient` |
| **FleetDeck** | 1 | `HKLM\SYSTEM\CurrentControlSet\Services\FleetDeck Agent Service` |
| **HopToDesk** | 2 | `HKCU\Software\Classes\HopToDesk\shell\open\command`, `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\HopToDesk` |
| **iDrive** | 2 | `HKLM\SOFTWARE\IDrive\*`, `HKCU\SOFTWARE\IDrive\*` |

**API Access:** `curl https://lolrmm.io/api/rmm_tools.json` for full programmatic access.

---

## 17. Sources & References

### Primary Research Sources

- [Eric Zimmerman's Registry Explorer Bookmarks](https://github.com/EricZimmerman/RegistryExplorerBookmarks) — Community-maintained forensic bookmark definitions
- [Eric Zimmerman's Registry Plugins](https://github.com/EricZimmerman/RegistryPlugins) — Parser plugins for Registry Explorer and RECmd
- [RECmd Batch Files](https://github.com/EricZimmerman/RECmd) — Command-line registry parsing artifacts (Kroll_Batch: 100+ keys)
- [RegSeek](https://regseek.github.io/) — 148 registry artifacts across 14 categories
- [LOLRMM Project](https://lolrmm.io) — 294 RMM tool definitions with registry/disk/network/process artifacts
- [LOLRMM GitHub](https://github.com/magicsword-io/LOLRMM) — YAML source files and Sigma detection rules
- [Arizona ACTRA rmm-detection](https://github.com/Arizona-Cyber-Threat-Response-Alliance/rmm-detection) — Multi-SIEM detection rules from LOLRMM data

### Forensic Analysis Papers & Blog Posts

- [Synacktiv: Legitimate RATs](https://www.synacktiv.com/en/publications/legitimate-rats-a-comprehensive-forensic-analysis-of-the-usual-suspects) — TeamViewer, AnyDesk, Atera, SplashTop forensic analysis
- [Cyber Triage: Windows Registry Forensics 2025](https://www.cybertriage.com/blog/windows-registry-forensics-2025/) — Updated registry forensics guide
- [Cyber Triage: Registry Forensics Cheat Sheet 2025](https://www.cybertriage.com/blog/windows-registry-forensics-cheat-sheet-2025/) — Quick reference
- [FireEye/Mandiant: Using the Registry to Discover Unix Systems](https://www.fireeye.com/blog/threat-research/2017/03/using_the_registryt.html) — PuTTY, WinSCP, RDP session artifacts
- [Didier Stevens: FileZilla Uses PuTTY Registry Keys](https://blog.didierstevens.com/2021/03/27/filezilla-uses-puttys-registry-fingerprint-cache/) — Shared SSH fingerprint cache
- [SANS ISC: PuTTY And FileZilla Use The Same Fingerprint Registry Keys](https://isc.sans.edu/diary/27376)
- [Magnet Forensics: PowerShell Logs in Digital Forensics](https://www.magnetforensics.com/blog/the-importance-of-powershell-logs-in-digital-forensics/)
- [Mandiant: Greater Visibility Through PowerShell Logging](https://cloud.google.com/blog/topics/threat-intelligence/greater-visibility/)
- [Cheeky4n6Monkey: Writing a CCleaner RegRipper Plugin](http://cheeky4n6monkey.blogspot.com/2012/02/writing-ccleaner-regripper-plugin-part.html)
- [ForenSafe: Adobe Acrobat Reader Artifacts](https://www.forensafe.com/blogs/adobeacrobat.html)
- [ForenSafe: Thunderbird Artifacts](https://www.forensafe.com/blogs/thunderbird.html)
- [ForenSafe: Notepad++ Artifacts](https://forensafe.com/blogs/windows_notepad++.html)

### Detection & Threat Hunting

- [Velociraptor: Windows.Registry.Sysinternals.Eulacheck](https://docs.velociraptor.app/artifact_references/pages/windows.registry.sysinternals.eulacheck/) — Sysinternals EULA detection
- [Velociraptor: Windows.MobaXterm.Passwords](https://docs.velociraptor.app/exchange/artifacts/pages/custom.windows.mobaxterm.passwords/) — MobaXterm credential extraction
- [Metasploit: MobaXterm Passwords](https://www.infosecmatter.com/metasploit-module-library/?mm=post/windows/gather/credentials/moba_xterm)
- [Metasploit: Xshell/Xftp Passwords](https://www.infosecmatter.com/metasploit-module-library/?mm=post/windows/gather/credentials/xshell_xftp_password)
- [PasswordDecrypts (frizb)](https://github.com/frizb/PasswordDecrypts) — VNC, RDP, and other stored password decryption
- [RemoteManagementMonitoringTools (jischell-msft)](https://github.com/jischell-msft/RemoteManagementMonitoringTools) — RMM artifact collection for forensics

### Credential Extraction Tools

- [SessionGopher](https://github.com/Arvanaghi/SessionGopher) — PuTTY, WinSCP, RDP credential extraction via WMI
- [MobaXterm Decryptor](https://github.com/xillwillx/MobaXterm-Decryptor) — MobaXterm password decryption
- [mRemoteNG Decrypt](https://github.com/gquere/mRemoteNG_password_decrypt) — mRemoteNG configuration decryption
- [HeidiSQL Password Decrypt](https://gist.github.com/jpatters/4553139) — HeidiSQL registry password decoding
- [Xdecrypt (Xshell/Xftp)](https://github.com/dzxs/Xdecrypt) — Xshell session password decryption
- [VMAware](https://github.com/kernelwernel/VMAware) — VM detection library (70+ VM brands)

### DFIR Cheat Sheets & Quick References

- [SANS DFIR Cheat Sheet](https://www.scribd.com/document/414230960/Cheatsheet-dfir)
- [Jai Minton DFIR Cheat Sheet](https://www.jaiminton.com/cheatsheet/DFIR/)
- [DFIR Training: Registry Artifacts](https://www.dfir.training/artifact/win-os/registry)
- [HackTricks: Local Cloud Storage](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/local-cloud-storage.html)
- [Windows Forensic Artifacts (Psmths)](https://github.com/Psmths/windows-forensic-artifacts)
