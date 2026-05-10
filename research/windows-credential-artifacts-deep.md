# Windows Credential Storage Artifacts — Comprehensive Forensic Catalog

**Compiled:** 2026-04-13  
**Scope:** Windows credential and authentication material storage locations, formats, and forensic extraction approaches  
**Methodology:** Sources cross-referenced from MITRE ATT&CK, SANS, Passcape, Microsoft Learn, Mimikatz wiki, DSInternals, and security research blogs

---

## Table of Contents

1. [DPAPI User Master Key Files](#1-dpapi-user-master-key-files)
2. [DPAPI System Master Key Files](#2-dpapi-system-master-key-files)
3. [DPAPI Credential Blob Files (User)](#3-dpapi-credential-blob-files-user)
4. [DPAPI CREDHIST File](#4-dpapi-credhist-file)
5. [DPAPI Domain Backup Key (Active Directory)](#5-dpapi-domain-backup-key-active-directory)
6. [SAM Hive — Local Account NTLM Hashes](#6-sam-hive--local-account-ntlm-hashes)
7. [LSA Secrets](#7-lsa-secrets)
8. [Domain Cached Credentials (DCC2 / mscash2)](#8-domain-cached-credentials-dcc2--mscash2)
9. [NTDS.dit — Active Directory Database](#9-ntdsdit--active-directory-database)
10. [LSASS Process Memory](#10-lsass-process-memory)
11. [Windows Credential Manager / Vault — VCRD + VPOL Files](#11-windows-credential-manager--vault--vcrd--vpol-files)
12. [Chrome / Edge (Chromium) Login Data](#12-chrome--edge-chromium-login-data)
13. [Chrome / Edge (Chromium) Cookies](#13-chrome--edge-chromium-cookies)
14. [Firefox logins.json + key4.db](#14-firefox-loginsjson--key4db)
15. [IE / Edge Legacy — WebCacheV01.dat](#15-ie--edge-legacy--webcachev01dat)
16. [RDP Saved Connections and UsernameHint](#16-rdp-saved-connections-and-usernamehint)
17. [WDigest Credential Caching](#17-wdigest-credential-caching)
18. [Windows Wireless Network Profiles (WPA2-PSK / Enterprise)](#18-windows-wireless-network-profiles-wpa2-psk--enterprise)
19. [VPN Credentials — RAS Phonebook](#19-vpn-credentials--ras-phonebook)
20. [Kerberos Ticket Cache (LSASS)](#20-kerberos-ticket-cache-lsass)
21. [User Certificate Store — Private Keys](#21-user-certificate-store--private-keys)
22. [Machine Certificate Store — Private Keys](#22-machine-certificate-store--private-keys)
23. [Windows Hello / NGC Folder](#23-windows-hello--ngc-folder)
24. [Scheduled Task Credential Blobs](#24-scheduled-task-credential-blobs)

---

## 1. DPAPI User Master Key Files

| Field | Value |
|-------|-------|
| **Location** | `C:\Users\{username}\AppData\Roaming\Microsoft\Protect\{SID}\{GUID}` (files are hidden; use `dir /a`) |
| **Format** | Proprietary binary; three sections: (1) user-password-encrypted master key, (2) legacy local encryption key (Windows 2000 only, still present as stub), (3) CREDHIST pointer GUID. Files named by GUID. |
| **Key Fields** | 512-bit master key material encrypted via PBKDF2 (SHA-1, random 16-byte salt, iteration count from `HKLM\Software\Microsoft\Cryptography\Protect\Providers\{GUID}`). Master key itself is not used directly; a per-blob symmetric session key is derived from it. |
| **Forensic Value** | Required to decrypt all DPAPI-protected user data: browser credentials, Windows Vault blobs, Wi-Fi PSKs, Outlook PST keys, and any application that calls `CryptProtectData`. Keys expire after 90 days but are never deleted, so old keys remain on disk for decrypting historical blobs. |
| **OS Scope** | Windows XP through Windows 11 |
| **Data Scope** | Per-user |
| **Decoder Approach** | Decrypt using user's password hash (NT hash → PBKDF2 → AES/3DES key → unwrap master key). Offline: Mimikatz `dpapi::masterkey /in:<file> /password:<pw>` or Impacket `dpapi.py masterkey`. Online (LSASS cache): `sekurlsa::dpapi`. Domain-joined: DC backup key via `lsadump::backupkeys`. |
| **MITRE ATT&CK** | T1555, T1552.002 |
| **References** | [Passcape DPAPI Master Key](https://www.passcape.com/windows_password_recovery_dpapi_master_key) · [HackTricks DPAPI](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/dpapi-extracting-passwords) · [Sygnia DPAPI analysis](https://www.sygnia.co/blog/the-downfall-of-dpapis-top-secret-weapon/) · [Tom O'Neill Medium](https://medium.com/@toneillcodes/extracting-dpapi-masterkey-data-1381168ad5b8) |

---

## 2. DPAPI System Master Key Files

| Field | Value |
|-------|-------|
| **Location** | `C:\Windows\System32\Microsoft\Protect\S-1-5-18\` (machine account) and `C:\Windows\System32\Microsoft\Protect\S-1-5-18\User\` (LocalService, NetworkService accounts) |
| **Format** | Same binary format as user master key files (GUID-named, three-section structure). |
| **Key Fields** | Protected not by a user password but by the **DPAPI_SYSTEM LSA secret** (`HKLM\SECURITY\Policy\Secrets\DPAPI_SYSTEM`), which is itself encrypted by the LsaKey derived from the BootKey (SYSKEY). |
| **Forensic Value** | Enables decryption of machine-scope DPAPI blobs: scheduled task credentials, Wi-Fi PSKs, IIS application pool passwords, service account secrets. Offline access requires SYSTEM + SECURITY hive export. |
| **OS Scope** | Windows XP through Windows 11 |
| **Data Scope** | System / machine |
| **Decoder Approach** | (1) Extract BootKey from SYSTEM hive; (2) decrypt LsaKey; (3) decrypt `DPAPI_SYSTEM` LSA secret; (4) use the extracted key material to decrypt GUID-named master key files. Mimikatz: `lsadump::secrets` then `dpapi::masterkey /in:<file> /system:<dpapi_system_key>`. SharpDPAPI `machinemasterkeys`. |
| **MITRE ATT&CK** | T1555, T1003.004 |
| **References** | [HackTricks DPAPI](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/dpapi-extracting-passwords) · [The Hacker Recipes DPAPI](https://www.thehacker.recipes/ad/movement/credentials/dumping/dpapi-protected-secrets) · [Tier Zero Security DPAPI](https://tierzerosecurity.co.nz/2024/01/22/data-protection-windows-api.html) |

---

## 3. DPAPI Credential Blob Files (User)

| Field | Value |
|-------|-------|
| **Location** | Local: `C:\Users\{username}\AppData\Local\Microsoft\Credentials\{GUID}` · Roaming: `C:\Users\{username}\AppData\Roaming\Microsoft\Credentials\{GUID}` · System-scope (scheduled tasks, IIS): `C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Credentials\{GUID}` |
| **Format** | Binary DPAPI blob; contains a `guidMasterKey` field identifying which master key to use for decryption, along with AES-CBC or 3DES ciphertext, HMAC, salt, and optional additional entropy. |
| **Key Fields** | Stores encrypted credential material written by Credential Manager, scheduled task engine, Internet Explorer, and any application using `CryptProtectData`. The decrypted plaintext contains `TargetName`, `UserName`, and `CredentialBlob` fields in `CREDENTIAL` struct format. |
| **Forensic Value** | Contains plaintext passwords for network shares, web accounts, RDP sessions, scheduled tasks, and domain credentials cached by Windows. `TargetName` reveals what service the password is for (e.g., `Domain:batch=TaskScheduler:Task:{GUID}` for task credentials, `TERMSRV/hostname` for RDP). |
| **OS Scope** | Windows Vista through Windows 11 |
| **Data Scope** | Per-user (Local) or per-user roaming (Roaming) |
| **Decoder Approach** | Identify `guidMasterKey` via Mimikatz `dpapi::cred /in:<file>`, then supply master key: `dpapi::cred /in:<file> /masterkey:<sha1>`. Online shortcut: `dpapi::cred /in:<file>` after `sekurlsa::dpapi` caches master keys. SharpDPAPI `credentials` command. |
| **MITRE ATT&CK** | T1555.004, T1003 |
| **References** | [Mimikatz dpapi::cred](https://tools.thehacker.recipes/mimikatz/modules/dpapi/cred) · [Synacktiv Windows Secrets Summary](https://www.synacktiv.com/en/publications/windows-secrets-extraction-a-summary) · [Scheduled Task Credential dump gist](https://gist.github.com/alexdhital/156077d873ea06a7a3058e56747f2dd6) |

---

## 4. DPAPI CREDHIST File

| Field | Value |
|-------|-------|
| **Location** | `C:\Users\{username}\AppData\Roaming\Microsoft\Protect\CREDHIST` |
| **Format** | Binary; stack of entries, each entry defined as `_KULL_M_DPAPI_MASTERKEY_CREDHIST` (`DWORD dwVersion` + `GUID`). Encrypted with user's current password; each entry in turn decryptable reveals the prior password, enabling a chain walk. |
| **Key Fields** | Ordered list of previous user passwords (as derived key material). Each master key file's Section 3 contains a GUID pointing into this file, linking the master key to the password that was used to protect it. |
| **Forensic Value** | Enables decryption of DPAPI master keys created under old passwords — critical when a user has changed their password multiple times. Password history chain allows recovery of all historical DPAPI-protected data. Also a lateral movement pivot: access reveals historical plaintext passwords. |
| **OS Scope** | Windows XP through Windows 11 |
| **Data Scope** | Per-user |
| **Decoder Approach** | Mimikatz `dpapi::credhist /in:<CREDHIST_path>`. Passcape Windows Password Recovery toolkit. After obtaining one password entry, iteratively decrypt older master keys. Detection rule: Sigma rule flags unexpected process access to `\Microsoft\Protect\CREDHIST`. |
| **MITRE ATT&CK** | T1555, T1552.002 |
| **References** | [Passcape CREDHIST analysis](https://www.passcape.com/windows_password_recovery_dpapi_credhist) · [Passcape CREDHIST dump](https://www.passcape.com/windows_password_recovery_dpapi_credhist_dump) · [Exploit-DB DPAPI abuse paper](https://www.exploit-db.com/docs/48589) · [Detection.FYI Sigma rule](https://detection.fyi/sigmahq/sigma/windows/file/file_access/file_access_win_susp_credhist/) |

---

## 5. DPAPI Domain Backup Key (Active Directory)

| Field | Value |
|-------|-------|
| **Location** | AD object: `CN=BCKUPKEY_*,CN=System,DC=domain,DC=com` (schema class `secret`) in NTDS.dit. Accessible via LSA RPC on any DC: Mimikatz `lsadump::backupkeys /system:<DC>`. Also stored as LSA secrets `G$BCKUPKEY_PREFERRED` and `G$BCKUPKEY_P` accessible via `LsaRetrievePrivateData`. |
| **Format** | RSA-2048 private key (PEM/PVK) for domain-joined systems (Windows 2003+); symmetric key for Windows 2000 DCs. Stored as AD `secret` object binary value. |
| **Key Fields** | DC's RSA private key corresponding to the public key used to encrypt user DPAPI master keys as a domain backup. Possession of this key allows offline decryption of every domain user's master keys — and therefore every DPAPI secret in the forest. |
| **Forensic Value** | The "golden key" of DPAPI forensics. A single exfiltration enables decryption of all historical and current DPAPI credentials for all domain users. Microsoft provides no supported rotation mechanism; key persists indefinitely once established. |
| **OS Scope** | Domain Controllers running Windows Server 2003 through 2025 |
| **Data Scope** | Forest-wide / all domain users |
| **Decoder Approach** | Live extraction: Mimikatz `lsadump::backupkeys /system:<DC_hostname> /export`. Offline from NTDS.dit: DSInternals `Get-BootKey` → `Get-ADDBBackupKey` → `Save-DPAPIBlob`. Detection: Event ID 4662 on DC with `SecretObject` type and `BACKUPKEY` in object name; Wireshark filter `lsarpc.opnum == 43`. |
| **MITRE ATT&CK** | T1003.003, T1552.004 |
| **References** | [DSInternals DPAPI Backup Keys](https://www.dsinternals.com/en/retrieving-dpapi-backup-keys-from-active-directory/) · [DSInternals backup key theft detection](https://www.dsinternals.com/en/dpapi-backup-key-theft-auditing/) · [Microsoft CNG DPAPI Backup Keys](https://learn.microsoft.com/en-us/windows/win32/seccng/cng-dpapi-backup-keys-on-ad-domain-controllers) · [Threat Hunter Playbook](https://threathunterplaybook.com/hunts/windows/190620-DomainDPAPIBackupKeyExtraction/notebook.html) |

---

## 6. SAM Hive — Local Account NTLM Hashes

| Field | Value |
|-------|-------|
| **Location** | Registry: `HKLM\SAM\Domains\Account\Users\{RID}\` · File system: `C:\Windows\System32\config\SAM` (locked by kernel at runtime) |
| **Format** | Registry binary values; NTLM hashes (MD4 of UTF-16LE password) stored double-encrypted: first with SysKey (RC4/AES-128 depending on OS version), then with a per-account derived key. Windows 10 v1607+ uses AES-128-CBC instead of RC4. LM hashes stored separately but disabled by default since Vista. |
| **Key Fields** | NT hash (32 hex chars) and optionally LM hash for each local user account. Also stores RID, account flags, last password change, login count, and last login timestamp. |
| **Forensic Value** | Enables offline password cracking or pass-the-hash attacks against all local accounts. Every local administrator account (including built-in Administrator) is present. Reveals account usage patterns via login metadata. |
| **OS Scope** | Windows NT 3.51 through Windows 11 |
| **Data Scope** | System / local accounts only (not domain accounts) |
| **Decoder Approach** | Export hives offline: `reg save HKLM\SAM sam.hiv && reg save HKLM\SYSTEM system.hiv`. Parse with Impacket `secretsdump.py -sam sam.hiv -system system.hiv LOCAL`. Live: Mimikatz `lsadump::sam`. Event ID 4656 fires on `reg.exe save` of SAM hive. |
| **MITRE ATT&CK** | T1003.002 |
| **References** | [Praetorian credential dump detection](https://www.praetorian.com/blog/how-to-detect-and-dump-credentials-from-the-windows-registry/) · [SAM hive GitHub forensic artifact](https://github.com/Psmths/windows-forensic-artifacts/blob/main/account/sam-hive.md) · [HackTricks SAM](https://www.hackingarticles.in/credential-dumping-sam/) · [Wikipedia SAM](https://en.wikipedia.org/wiki/Security_Account_Manager) |

---

## 7. LSA Secrets

| Field | Value |
|-------|-------|
| **Location** | `HKLM\SECURITY\Policy\Secrets\` (subkeys: `_SC_<ServiceName>` for service accounts, `DPAPI_SYSTEM`, `DefaultPassword`, `NL$KM` for DCC key, `$MACHINE.ACC` for machine account hash, `_RASKEY#<n>` for RAS/VPN, `G$BCKUPKEY_*` for DPAPI domain backup) · File: `C:\Windows\System32\config\SECURITY` |
| **Format** | Registry REG_BINARY values (`CurrVal`, `OldVal`) encrypted with the LsaKey. LsaKey derived from BootKey (SYSKEY) via RC4. On Windows 2012+, AES-256-CBC replaces RC4 for LsaKey derivation. Each secret has `CurrVal` (current) and `OldVal` (previous) sub-values enabling password history recovery. |
| **Key Fields** | Service account passwords in cleartext after decryption; machine account NTLM hash (`$MACHINE.ACC`); DPAPI_SYSTEM key for machine master key decryption; NL$KM key for DCC2 hash decryption; default autologon password (`DefaultPassword`); dial-up/VPN pre-shared keys. |
| **Forensic Value** | Single highest-value registry artifact after NTDS.dit on a DC. Service account passwords often reused across systems, enabling lateral movement. `DefaultPassword` reveals autologon credentials in plaintext. `$MACHINE.ACC` enables Silver Ticket attacks. |
| **OS Scope** | Windows NT through Windows 11 (ACL restricts access to SYSTEM only) |
| **Data Scope** | System-wide |
| **Decoder Approach** | Export: `reg save HKLM\SECURITY security.hiv && reg save HKLM\SYSTEM system.hiv`. Parse offline: Impacket `secretsdump.py -security security.hiv -system system.hiv LOCAL`. Live: Mimikatz `lsadump::secrets`. SYSTEM privilege required. Detection: Event ID 4663 on `HKLM\SECURITY\Policy\Secrets` with object access auditing enabled; Event ID 4656 on reg.exe save commands. |
| **MITRE ATT&CK** | T1003.004 |
| **References** | [MITRE ATT&CK T1003.004](https://attack.mitre.org/techniques/T1003/004/) · [SANS LSA Secrets](https://www.sans.org/blog/protecting-privileged-domain-accounts-lsa-secrets-good/) · [Synacktiv Windows Secrets](https://www.synacktiv.com/en/publications/windows-secrets-extraction-a-summary) · [Atomic Red Team T1003.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.004/T1003.004.md) |

---

## 8. Domain Cached Credentials (DCC2 / mscash2)

| Field | Value |
|-------|-------|
| **Location** | `HKLM\SECURITY\Cache` · Value names: `NL$1` through `NL$<n>` (default n=10, configurable via `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\CachedLogonsCount`) |
| **Format** | Binary; each `NL$` value is an encrypted structure containing a DCC2 hash. DCC2 algorithm: `PBKDF2(HMAC-SHA1, iterations=10240, password=DCC1_hash, salt=lowercase_username_unicode)`, truncated to 128 bits. DCC1 = `MD4(MD4(password) + unicode(username))`. Encrypted by `NL$KM` key (stored in LSA Secrets). |
| **Key Fields** | Username, domain, and DCC2 hash for each recently logged-on domain user. By default up to 10 entries; oldest overwritten when full. Entries never expire on their own. |
| **Forensic Value** | Proves which domain accounts have logged into this machine. DCC2 hashes cannot be used for pass-the-hash — they require offline cracking. Cracking rate: ~330 hashes/sec on modest hardware (vs. 58M/sec for DCC1). Cracked credentials reveal domain user passwords enabling lateral movement when network unavailable. Event ID 4624 Logon Type 11 (CachedInteractive) indicates cached credential use. |
| **OS Scope** | Windows Vista through Windows 11 (DCC2 format); Windows XP / 2003 used DCC1 |
| **Data Scope** | System; caches domain user credentials |
| **Decoder Approach** | Export SECURITY + SYSTEM hives. Impacket `secretsdump.py` outputs hashes as `$DCC2$10240#username#hash`. Crack with Hashcat `-m 2100` or John the Ripper `--format=mscash2`. Mimikatz `lsadump::cache`. |
| **MITRE ATT&CK** | T1003.005 |
| **References** | [MITRE ATT&CK T1003.005](https://attack.mitre.org/techniques/T1003/005/) · [Passlib msdcc2 docs](https://passlib.readthedocs.io/en/stable/lib/passlib.hash.msdcc2.html) · [Openwall MSCash2 wiki](https://openwall.info/wiki/john/MSCash2) · [Hacking Articles DCC](https://www.hackingarticles.in/credential-dumping-domain-cache-credential/) |

---

## 9. NTDS.dit — Active Directory Database

| Field | Value |
|-------|-------|
| **Location** | Primary: `C:\Windows\NTDS\NTDS.dit` (default, configurable via `HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\DSA Database file`). Distribution copy: `C:\Windows\System32\ntds.dit`. Accompanied by transaction logs `EDB*.log`, checkpoint `EDB.chk` in `C:\Windows\NTDS\`. |
| **Format** | Microsoft ESE (Extensible Storage Engine / JET Blue) database. Password hashes stored under the `datatable` in columns `ATT_UNICODE_PWD` (NT hash) encrypted with three layers: (1) RC4 decrypt PEK using BootKey; (2) RC4 decrypt with PEK; (3) DES decrypt using account RID. |
| **Key Fields** | NT hash and LM hash for every domain account (users, computers, service accounts, KRBTGT). Also contains Kerberos keys, password history (up to 24 entries), SIDs, group membership, last logon, and trust relationship credentials. |
| **Forensic Value** | Crown jewel of Active Directory forensics — contains credentials for every account in the domain/forest. KRBTGT hash enables Golden Ticket forgery. Computer account hashes enable Silver Tickets. Password history enables historical password analysis. |
| **OS Scope** | Domain Controllers: Windows Server 2000 through 2025 |
| **Data Scope** | Entire domain / forest |
| **Decoder Approach** | File is locked at runtime; acquire via: (1) VSS snapshot (`vssadmin create shadow /for=C:`), (2) NTDSUtil IFM (`ntdsutil "activate instance ntds" "ifm" "create full C:\IFM" quit quit`), (3) Invoke-NinjaCopy PowerShell, (4) DCSync (no file needed; Mimikatz `lsadump::dcsync /all`). Parse offline: Impacket `secretsdump.py -ntds ntds.dit -system system.hiv LOCAL`. Detection: ESENT Event ID 325 (database created) and 327 (database detached) in Application log. |
| **MITRE ATT&CK** | T1003.003 |
| **References** | [ADSecurity NTDS.dit dump](https://adsecurity.org/?p=2398) · [MITRE ATT&CK T1003.003](https://attack.mitre.org/techniques/T1003/003/) · [Semperis NTDS explanation](https://www.semperis.com/blog/ntds-dit-extraction-explained/) · [Hacking Articles NTDS](https://www.hackingarticles.in/credential-dumping-ntds-dit/) |

---

## 10. LSASS Process Memory

| Field | Value |
|-------|-------|
| **Location** | Live memory of `lsass.exe` (PID varies). Dump file if created: `C:\Windows\lsass.dmp` or attacker-chosen path. |
| **Format** | Windows process memory (no file format at rest). If dumped as minidump: Windows Minidump format (`.dmp`), parseable by WinDbg, Mimikatz, or pypykatz. |
| **Key Fields** | MSV1_0 package: NT/LM hashes, SHA1 hashes. Kerberos package: TGTs and service tickets (`.kirbi` format). WDigest package: cleartext passwords (when `UseLogonCredential=1`). CredSSP / TsPkg: RDP session credentials. LiveSSP: Microsoft Account credentials. DPAPI cached master key material (`sekurlsa::dpapi`). |
| **Forensic Value** | Highest-yield live credential source. Provides all currently authenticated users' credential material. NTLM hashes usable for pass-the-hash; Kerberos tickets for pass-the-ticket; cleartext passwords directly usable. Service accounts logged on interactively have credentials here. |
| **OS Scope** | Windows XP through Windows 11 (Credential Guard (VBS) on Win10+ removes NTLM hashes and TGTs from standard LSASS memory into isolated `LsaIso.exe`; WDigest disabled by default since Win8.1) |
| **Data Scope** | All users with active logon sessions on the system |
| **Decoder Approach** | Requires SYSTEM or SeDebugPrivilege. Mimikatz `sekurlsa::logonpasswords`. Dump then parse: `procdump -ma lsass.exe lsass.dmp` → Mimikatz `sekurlsa::minidump lsass.dmp`. pypykatz offline parsing. Detection: Sysmon Event ID 10 (ProcessAccess to lsass.exe with `PROCESS_VM_READ`); Windows Defender Credential Guard blocks extraction on modern systems. |
| **MITRE ATT&CK** | T1003.001 |
| **References** | [MITRE ATT&CK T1003.001](https://attack.mitre.org/techniques/T1003/001/) · [ADSecurity Mimikatz](https://adsecurity.org/?page_id=1821) · [Security Scientist LSASS](https://www.securityscientist.net/blog/12-questions-and-answers-about-lsass-memory-t1003-001/) · [Microsoft Credential Guard](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/how-it-works) |

---

## 11. Windows Credential Manager / Vault — VCRD + VPOL Files

| Field | Value |
|-------|-------|
| **Location** | Per-user: `C:\Users\{username}\AppData\Local\Microsoft\Vault\{GUID}\` and `C:\Users\{username}\AppData\Roaming\Microsoft\Vault\{GUID}\` · System-wide: `C:\ProgramData\Microsoft\Vault\` · System profile: `C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Vault\` |
| **Format** | `.vpol` (Vault Policy) — binary, DPAPI-encrypted, contains AES keys used to decrypt `.vcrd` files in the same directory. `.vcrd` (Vault Credential) — binary, encrypted with keys from `.vpol`. `.vsch` (Vault Schema) — binary, describes field layout of decrypted credential. |
| **Key Fields** | "Web Credentials" (browser-saved form credentials, HTTP auth) vs. "Windows Credentials" (network shares, RDP, domain join tokens). Each credential contains TargetName, UserName, and password blob. |
| **Forensic Value** | Stores passwords for network resources, RDP (as `TERMSRV/` prefixed entries), SharePoint / O365 tokens, and browser form credentials for IE/Edge legacy. Distinguishing Web vs. Windows credential types guides investigation scope. |
| **OS Scope** | Windows 7 through Windows 11 |
| **Data Scope** | Per-user (user Vault) or System (system Vault) |
| **Decoder Approach** | Enumerate: `vaultcmd /list` and `vaultcmd /listcreds:"Vault Name"`. Windows API: `CredEnumerateA`. Mimikatz: `dpapi::vault /cred:<file>.vcrd /policy:Policy.vpol /masterkey:<sha1>`. SharpDPAPI `vaults` command. Raw: parse `.vpol` (DPAPI blob) to extract AES key, then decrypt `.vcrd`. |
| **MITRE ATT&CK** | T1555.004 |
| **References** | [MITRE ATT&CK T1555.004](https://attack.mitre.org/techniques/T1555/004/) · [Windows ReVaulting (digital-forensics.it)](https://blog.digital-forensics.it/2016/01/windows-revaulting.html) · [Passcape Vault Explorer](https://www.passcape.com/windows_password_recovery_vault_explorer) · [Mimikatz dpapi::vault](https://tools.thehacker.recipes/mimikatz/modules/dpapi/vault) |

---

## 12. Chrome / Edge (Chromium) Login Data

| Field | Value |
|-------|-------|
| **Location** | Chrome: `C:\Users\{username}\AppData\Local\Google\Chrome\User Data\Default\Login Data` · Edge: `C:\Users\{username}\AppData\Local\Microsoft\Edge\User Data\Default\Login Data` · Local State (AES key): `...\User Data\Local State` |
| **Format** | SQLite 3 database. Key table: `logins`. Key columns: `signon_realm` (URL), `username_value` (plaintext), `password_value` (DPAPI blob, or AES-256-GCM ciphertext prefixed `v10`/`v20` for App-Bound Encryption on Chrome 127+). `blacklisted_by_user=1` rows indicate "Never save" decisions — still forensically useful. |
| **Key Fields** | `Local State` JSON contains `encrypted_key` (DPAPI blob over AES-256 key). For Chrome 127+ (App-Bound Encryption): decryption requires the browser's own elevated service process, making offline decryption significantly harder. Legacy (pre-127): `CryptUnprotectData` with user context decrypts password directly. |
| **Forensic Value** | Yields plaintext usernames and passwords for all sites where user saved credentials. `blacklisted` entries reveal sites visited but where user declined saving. SQLite free list / WAL file may contain deleted credentials. Windows Event ID 5379 fires for each Chrome password decryption, leaving a decryption trail. |
| **OS Scope** | Windows 7 through Windows 11 (Chrome 127+ App-Bound Encryption changes forensic approach) |
| **Data Scope** | Per-user, per-browser-profile |
| **Decoder Approach** | Pre-Chrome 127: extract `encrypted_key` from `Local State`, `CryptUnprotectData` it (requires user context), then AES-256-GCM decrypt `password_value`. SharpChrome, LaZagne, HackBrowserData. Post-127: requires live user session or browser process injection. SQL: `SELECT signon_realm, username_value, password_value FROM logins`. |
| **MITRE ATT&CK** | T1555.003 |
| **References** | [ElcomSoft Browser Forensics 2026](https://blog.elcomsoft.com/2026/01/browser-forensics-in-2026-app-bound-encryption-and-live-triage/) · [Group-IB Edge Forensics](https://www.group-ib.com/blog/forensics-edge/) · [Pentestlab Browser Credentials](https://pentestlab.blog/2024/08/20/web-browser-stored-credentials/) · [Medium Chrome Forensic Recovery](https://palmenas.medium.com/forensic-recovery-of-chrome-based-browser-passwords-e8df90d4a3cd) |

---

## 13. Chrome / Edge (Chromium) Cookies

| Field | Value |
|-------|-------|
| **Location** | Chrome: `C:\Users\{username}\AppData\Local\Google\Chrome\User Data\Default\Network\Cookies` (moved to `Network\` subfolder in newer versions; older: `Default\Cookies`) · Edge: `C:\Users\{username}\AppData\Local\Microsoft\Edge\User Data\Default\Network\Cookies` |
| **Format** | SQLite 3 database. Key table: `cookies`. Key columns: `host_key`, `name`, `encrypted_value` (DPAPI / App-Bound encrypted), `expires_utc`, `is_httponly`, `is_secure`, `samesite`. |
| **Key Fields** | Session tokens, authentication cookies (`sessionid`, `auth_token`, `SAML`, OAuth tokens), "Remember Me" persistent cookies. `encrypted_value` uses same encryption scheme as Login Data passwords. App-Bound Encryption was applied to cookies first (Chrome 127) before passwords. |
| **Forensic Value** | Cookie theft enables session hijacking without credentials (passes MFA). `is_httponly` flag indicates server-set auth cookies. Long-lived `expires_utc` values identify persistent session tokens. Deleted cookie records may be recoverable from SQLite unallocated pages (WAL / free list carving). |
| **OS Scope** | Windows 7 through Windows 11 |
| **Data Scope** | Per-user, per-browser-profile |
| **Decoder Approach** | Same decryption chain as Login Data. `SELECT host_key, name, encrypted_value, expires_utc FROM cookies`. For expired or deleted rows, use SQLite WAL journal recovery tools (e.g., `sqlitebiter`, `sqlite-dissect`). |
| **MITRE ATT&CK** | T1539, T1555.003 |
| **References** | [HackTricks DPAPI](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/dpapi-extracting-passwords) · [ElcomSoft 2026 browser forensics](https://blog.elcomsoft.com/2026/01/browser-forensics-in-2026-app-bound-encryption-and-live-triage/) · [CyberEngage browser credential forensics](https://www.cyberengage.org/post/browser-credential-storage-and-forensic-password-recovery) |

---

## 14. Firefox logins.json + key4.db

| Field | Value |
|-------|-------|
| **Location** | `C:\Users\{username}\AppData\Roaming\Mozilla\Firefox\Profiles\{profile-name}\logins.json` · `C:\Users\{username}\AppData\Roaming\Mozilla\Firefox\Profiles\{profile-name}\key4.db` · Legacy key file: `key3.db` (Berkeley DB, pre-Firefox 58) |
| **Format** | `logins.json` — JSON array of credential objects with fields `encryptedUsername`, `encryptedPassword` (ASN.1 DER, Base64-encoded, 3DES-CBC encrypted). `key4.db` — SQLite 3 database containing the NSS (Network Security Services) key store; stores master key encrypted with user's master password (or empty password if none set) using PBKDF2-SHA256 + 3DES. |
| **Key Fields** | `logins.json`: `hostname`, `formSubmitURL`, `encryptedUsername`, `encryptedPassword`, `timeCreated`, `timeLastUsed`, `timesUsed`. `key4.db` table `metadata`: `password-check` value for master password validation. Firefox 144+ changed encryption algorithm (breaks some older tools). |
| **Forensic Value** | Plaintext usernames and passwords for all browser-saved sites. `timesUsed` counter identifies frequently-used accounts. If no master password set (default), credentials decryptable with zero user interaction. NSS library path (`nss3.dll`) required by some tools. BeaverTail malware specifically targets these files. 85+ known threat groups exploit this technique. |
| **OS Scope** | Windows XP through Windows 11 (Firefox 58+ uses key4.db; older: key3.db + signons.sqlite) |
| **Data Scope** | Per-user, per-Firefox-profile |
| **Decoder Approach** | Tools: `firefox_decrypt` (Python, uses system nss3.dll), `firepwd.py` (pure Python, no NSS dependency, supports up to FF ~75). Both require `logins.json` + `key4.db`. Sysmon Event ID 11 detects copies; alert on non-Firefox processes loading `nss3.dll` or `softokn3.dll`. |
| **MITRE ATT&CK** | T1555.003 |
| **References** | [GitHub firefox_decrypt](https://github.com/unode/firefox_decrypt) · [Medium Firefox password dump](https://medium.com/@s12deff/steal-firefox-passwords-from-windows-linux-9d9a87906c7d) · [Mozilla Bugzilla key4.db migration](https://bugzilla.mozilla.org/show_bug.cgi?id=1615382) · [LaZagneForensic mozilla.py](https://github.com/AlessandroZ/LaZagneForensic/blob/master/LaZagneForensic/lazagne/softwares/browsers/mozilla.py) |

---

## 15. IE / Edge Legacy — WebCacheV01.dat

| Field | Value |
|-------|-------|
| **Location** | `C:\Users\{username}\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat` (locked at runtime by `taskhostw.exe`) · Supplementary log files in same directory: `V01.log`, `V0100000.log`, etc. |
| **Format** | Microsoft ESE (Extensible Storage Engine) database. Key tables: `Container_*` (variable IDs for History, Cache, Cookies, Downloads). Each container row has `Url`, `AccessedTime` (Windows FILETIME), `Flags` (InPrivate = `0x8`), `UserData`. |
| **Key Fields** | Cookie jar entries with `UserData` containing cookie name=value pairs. Form credentials cached by IE AutoComplete (separate `autocomplete.dat` artifact). InPrivate sessions flagged with `Flags=8` — still written to database. History entries including `file://` URIs revealing local file access. |
| **Forensic Value** | Recovers browsing history and cookies for IE and legacy Edge even after InPrivate sessions (Flags=8). Deleted records reclaimed only when ESE reorganizes pages — carving recovers these. Timestamps in 64-bit FILETIME (big-endian hex). Useful for establishing timeline of web-based authentication events. |
| **OS Scope** | Windows 8 through Windows 10 (legacy Edge removed in Windows 10 20H2; IE mode in Chromium Edge does not use this file) |
| **Data Scope** | Per-user |
| **Decoder Approach** | Acquire by killing `taskhostw` or using VSS. Parse with `esentutl /r V01 /d` for recovery then ESEDatabaseView, `esedbexport`, or Nirsoft's IECacheView. `esentutl /mh WebCacheV01.dat` checks consistency state. FTK/EnCase/X-Ways have built-in parsers. Timestamps: decode 64-bit Windows FILETIME via DCode. |
| **MITRE ATT&CK** | T1539, T1217 |
| **References** | [Forensic Focus ESE analysis](https://www.forensicfocus.com/articles/forensic-analysis-of-the-ese-database-in-internet-explorer-10/) · [Forensafe Microsoft Edge blog](https://www.forensafe.com/blogs/microsoftedge.html) · [InfoSec Notes browser forensics](https://notes.qazeer.io/dfir/common/browsers_forensics) |

---

## 16. RDP Saved Connections and UsernameHint

| Field | Value |
|-------|-------|
| **Location** | MRU list: `HKCU\Software\Microsoft\Terminal Server Client\Default` (values `MRU0`–`MRU9`, last 10 hosts) · Per-server details: `HKCU\Software\Microsoft\Terminal Server Client\Servers\{hostname}\UsernameHint` and `CertHash` · Saved credentials in Credential Manager: `TERMSRV/{hostname}` entries · RDP file: `%HOMEPATH%\Documents\Default.rdp` · Bitmap cache: `%LOCALAPPDATA%\Microsoft\Terminal Server Client\Cache\bcache24.bmc`, `Cache000*.bin` |
| **Format** | Registry REG_SZ (hostname strings). `UsernameHint`: plaintext username or `DOMAIN\username`. `CertHash`: SHA-1 thumbprint of server's TLS certificate. Saved credentials in Credential Manager (DPAPI blob, see artifact 11). `Default.rdp`: INI-style text file with connection parameters. Bitmap cache: proprietary BMC format (BCAPI/RDPCache). |
| **Key Fields** | `UsernameHint` reveals username and potentially domain for each RDP target. `MRU` list reveals all servers connected to (ordered by recency). `CertHash` enables server fingerprinting. Bitmap cache contains pixel-level fragments of the RDP session (potentially containing rendered credentials, sensitive data). |
| **Forensic Value** | Reveals lateral movement targets and accounts used. Entries persist after failed connections. Can fingerprint attackers' pivot chain. `TERMSRV/` Credential Manager entries contain saved passwords. Microsoft Store RDP app does NOT create UsernameHint or Jump List entries — forensic blind spot for detection. Bitmap cache analysis can recover screen content. |
| **OS Scope** | Windows XP through Windows 11 (stored in `NTUSER.DAT` per user profile) |
| **Data Scope** | Per-user |
| **Decoder Approach** | Registry: parse NTUSER.DAT hive offline with RegRipper plugin `rdphint`. Velociraptor artifact `Windows.Registry.RDP`. Credential Manager: `cmdkey /list | findstr TERMSRV`. Bitmap cache: RDP Cached Bitmap Extractor (rbcx), RDPCache. Event ID 4624 Logon Type 10 on target system. |
| **MITRE ATT&CK** | T1021.001, T1078 |
| **References** | [Forensafe RDC MRU blog](https://forensafe.com/blogs/rdc.html) · [Magnet Forensics RDP artifacts](https://www.magnetforensics.com/blog/rdp-artifacts-in-incident-response/) · [Velociraptor Windows.Registry.RDP](https://docs.velociraptor.app/artifact_references/pages/windows.registry.rdp/) · [ZeroFox RDP forensics](https://www.zerofox.com/blog/remote-desktop-application-vs-mstsc-forensics-the-rdp-artifacts-you-might-be-missing/) |

---

## 17. WDigest Credential Caching

| Field | Value |
|-------|-------|
| **Location** | Registry control: `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest` value `UseLogonCredential` (REG_DWORD: 1 = enable cleartext caching, 0 = disable). Actual credentials: LSASS process memory (not on disk). |
| **Format** | Registry DWORD control key. Credential material stored in LSASS memory as cleartext strings within the WDigest security package's memory structures. Readable via Mimikatz `sekurlsa::wdigest`. |
| **Key Fields** | Cleartext (plaintext) user password for every interactively logged-on user since last reboot — if `UseLogonCredential=1`. Persists in memory until system restart, not cleared by logoff of the user in question. |
| **Forensic Value** | When enabled (default on Win7/2008 before KB2871997; re-enabled by attackers on modern systems), yields plaintext passwords directly — bypassing any need for hash cracking. TrickBot and other malware re-enable this key then lock the screen to force re-authentication, capturing credentials. Registry modification timestamp indicates when attacker enabled caching. |
| **OS Scope** | Windows XP / 2003 through Windows 11 (disabled by default since Win8.1 / Server 2012 R2; can be re-enabled by attackers on any version) |
| **Data Scope** | All interactive logon sessions on the system |
| **Decoder Approach** | Check key: `Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name UseLogonCredential`. If =1, extract from LSASS: Mimikatz `sekurlsa::wdigest`. Detection: monitor registry writes to WDigest key (Sysmon Event ID 13); baseline expected value. |
| **MITRE ATT&CK** | T1003.001, T1112 |
| **References** | [XPN InfoSec WDigest exploration](https://blog.xpnsec.com/exploring-mimikatz-part-1/) · [Red Team Notes WDigest](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/forcing-wdigest-to-store-credentials-in-plaintext) · [Microsoft Security Advisory KB2871997](https://support.microsoft.com/en-us/topic/microsoft-security-advisory-update-to-improve-credentials-protection-and-management-may-13-2014-93434251-04ac-b7f3-52aa-9f951c14b649) · [Cryptika Windows 11 WDigest](https://www.cryptika.com/windows-11-and-server-2025-will-start-caching-plaintext-credentials-by-enabling-wdigest-authentication/) |

---

## 18. Windows Wireless Network Profiles (WPA2-PSK / Enterprise)

| Field | Value |
|-------|-------|
| **Location** | WPA2-PSK profiles: `C:\ProgramData\Microsoft\Wlansvc\Profiles\Interfaces\{InterfaceGUID}\{ProfileGUID}.xml` · Enterprise per-user credentials: `HKCU\Software\Microsoft\Wlansvc\UserData\Profiles\{ProfileGUID}` (value `MSMUserData`, REG_BINARY) · Enterprise machine credentials: `HKLM\Software\Microsoft\Wlansvc\UserData\Profiles\{ProfileGUID}` |
| **Format** | WPA2-PSK: XML file; SSID in `WLANProfile/name` (cleartext), pre-shared key in `WLANProfile/MSM/security/sharedKey/keyMaterial` as hex-encoded DPAPI blob (machine-scope). Enterprise: binary registry blob (`MSMUserData`) containing DPAPI-encrypted domain username+password. |
| **Key Fields** | WPA2-PSK: entire pre-shared key (after DPAPI decryption, `ProtectedData.Unprotect` with `DataProtectionScope.LocalMachine`). Enterprise: domain credentials (username, password) used for 802.1X authentication — often the user's AD password. |
| **Forensic Value** | WPA2-PSK: network infiltration pivot, SSID history (all networks ever connected). Enterprise: reveals Active Directory credentials for users who connected to 802.1X enterprise WiFi — frequently domain password. Decryption requires machine context (SYSTEM privilege). `netsh wlan show profile name="<SSID>" key=clear` reveals PSK live. |
| **OS Scope** | Windows Vista through Windows 11 |
| **Data Scope** | Machine (PSK XML files) or per-user registry (enterprise 802.1X) |
| **Decoder Approach** | Live: `netsh wlan show profile key=clear`. Offline: Mimikatz `dpapi::wifi /in:<profile_xml>` (uses machine DPAPI master key). Enterprise: Invoke-WifiSquid, EnterpriseWifiPasswordRecover. Raw: extract `keyMaterial` hex → convert to binary → DPAPI decrypt with machine key. |
| **MITRE ATT&CK** | T1555, T1040 |
| **References** | [Hacking Articles WiFi credential dump](https://www.hackingarticles.in/credential-dumping-wireless/) · [Medium WlanSvc passphrases](https://medium.com/@b3n_j4m1n/extracting-wlan-passphrases-from-windows-b2f2d9c11bd6) · [Invoke-WifiSquid](https://kylemistele.medium.com/dumping-stored-enterprise-wifi-credentials-with-invoke-wifisquid-5a7fe76f800) · [Mimikatz dpapi::wifi](https://tools.thehacker.recipes/mimikatz/modules/dpapi/wifi) |

---

## 19. VPN Credentials — RAS Phonebook

| Field | Value |
|-------|-------|
| **Location** | Per-user phonebook: `%APPDATA%\Microsoft\Network\Connections\Pbk\rasphone.pbk` · System-wide: `%PROGRAMDATA%\Microsoft\Network\Connections\Pbk\rasphone.pbk` · System default: `%SystemRoot%\System32\Ras\Rasphone.pbk` · Hidden (API-only): `%APPDATA%\Microsoft\Network\Connections\Pbk\_hiddenPbk\rasphone.pbk` · Credentials in LSA Secrets: `HKLM\SECURITY\Policy\Secrets\_RASKEY#*` |
| **Format** | `.pbk` (phonebook): INI-style text file; each `[EntryName]` section contains connection parameters. `UseRasCredentials` key (0/1) controls whether VPN credentials propagate as wildcard domain credentials in Credential Manager. Actual credentials stored as DPAPI blobs via `RasSetCredentials` API, retrievable via `RasGetCredentials`. LSA Secrets: encrypted binary values. |
| **Key Fields** | VPN server hostnames, protocol (PPTP/L2TP/SSTP/IKEv2), username, and encrypted password. `UseRasCredentials=1` (default) causes Windows to create a wildcard `*` Credential Manager entry for the VPN session domain — visible via `cmdkey /list`. |
| **Forensic Value** | Reveals VPN infrastructure (server hostnames, protocols). `UseRasCredentials` enables credential propagation that can overwrite Credential Manager entries, potentially disrupting investigation. LSA Secrets `_RASKEY#*` entries store L2TP/IPSEC pre-shared keys and dial-up passwords. Malware (e.g., banking trojans) abuses `rasphone.exe` to tunnel traffic. |
| **OS Scope** | Windows XP through Windows 11 |
| **Data Scope** | Per-user or system-wide |
| **Decoder Approach** | Read `.pbk` as text (INI format). Retrieve credentials: `RasGetCredentials()` API (requires user context). LSA Secrets extraction: same as artifact 7. `cmdkey /list` shows VPN Credential Manager entries live. TrustedSec research on abusing Windows VPN providers: `rasphone.exe /d <entry>`. |
| **MITRE ATT&CK** | T1555, T1003.004 |
| **References** | [TrustedSec Windows VPN abuse](https://trustedsec.com/blog/abusing-windows-built-in-vpn-providers) · [Praetorian credential dump detection](https://www.praetorian.com/blog/how-to-detect-and-dump-credentials-from-the-windows-registry/) · [Microsoft RAS Phone Books](https://learn.microsoft.com/en-us/windows/win32/rras/ras-phone-books) · [Richard Hicks UseRasCredentials](https://directaccess.richardhicks.com/tag/userascredentials/) |

---

## 20. Kerberos Ticket Cache (LSASS)

| Field | Value |
|-------|-------|
| **Location** | LSASS process memory (Kerberos SSP structures). Exported tickets: `.kirbi` files (attacker-chosen path). Registry key `HKLM\SECURITY\Policy\PolTDat` stores the KDC target domain data (not tickets themselves). |
| **Format** | In-memory: Kerberos Ticket structures (proprietary Windows Kerberos SSP format). Exported: `.kirbi` / MIT ccache format — KRB_CRED ASN.1 DER structure containing `KrbCredInfo` and `EncTicketPart`. Default TGT lifetime: 10 hours; service ticket lifetime: configurable (minutes to hours). |
| **Key Fields** | TGT: Ticket-Granting Ticket for the user, signed by KRBTGT; reusable for 10 hours, renewable for 7 days. TGS/Service Tickets: per-service tickets signed by target service account key. Session keys, authenticators, and PAC (Privilege Attribute Certificate) with group memberships. |
| **Forensic Value** | TGT theft enables pass-the-ticket (authentication to any domain service as the user). KRBTGT hash enables Golden Ticket forgery (forgeable TGT valid for any user). Service account hash enables Silver Ticket. Forensic detection: Event ID 4768 (TGT request), 4769 (service ticket request), 4771 (TGT failure). PtT leaves no Event 4768 on target DC — the ticket appeared without a request. |
| **OS Scope** | Windows 2000 domain environments through Windows Server 2025. Credential Guard (Win10+) moves TGTs into `LsaIso.exe` (VTL1), making standard extraction fail. |
| **Data Scope** | All active Kerberos sessions on the system |
| **Decoder Approach** | Extract: Mimikatz `sekurlsa::tickets /export` (dumps `.kirbi` files). Import/inject: `kerberos::ptt <ticket.kirbi>`. Rubeus `dump` / `harvest`. Offline `.kirbi` analysis: `kerberos::describe`. Detection: Sysmon Event ID 10 (LSASS access). Network: Wireshark Kerberos AS-REQ/TGS-REQ analysis. |
| **MITRE ATT&CK** | T1558, T1550.003 |
| **References** | [ADSecurity Kerberos Attacks](https://adsecurity.org/?p=556) · [Netwrix Pass-the-Ticket](https://www.netwrix.com/pass_the_ticket.html) · [Hacking Dream Event Log Kerberos](https://www.hackingdream.net/2026/02/windows-event-log-analysis-investigating-kerberos-ad-attacks.html) · [Microsoft Credential Guard](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/how-it-works) |

---

## 21. User Certificate Store — Private Keys

| Field | Value |
|-------|-------|
| **Location** | Public keys (registry): `HKCU\Software\Microsoft\SystemCertificates\My\Certificates\{Thumbprint}` · Private keys (filesystem): `%APPDATA%\Microsoft\SystemCertificates\My\Keys\{ContainerName}` · Private keys (crypto provider): `%APPDATA%\Microsoft\Crypto\RSA\{SID}\{ContainerGUID}` (legacy CryptoAPI) or `%APPDATA%\Microsoft\Crypto\Keys\{ContainerGUID}` (CNG / DPAPI-NG protected) |
| **Format** | Registry: binary blob containing DER-encoded X.509 certificate. Private key files: DPAPI-encrypted blob (CNG KSP) or RC4/3DES encrypted PVK-format blob (legacy RSACryptoAPI). Certificate thumbprint (SHA-1) is used as identifier in both registry and filesystem. |
| **Key Fields** | RSA/ECC private key material (encrypted). Certificate subject, issuer, validity, key usage (Client Authentication, Email, Code Signing). Hardware-protected keys (smart card / TPM) have only key references, not extractable material. |
| **Forensic Value** | Client authentication certificates used for VPN, 802.1X, S/MIME email, and code signing. If private key is software-stored (not TPM/smart card), DPAPI decryption yields exportable private key enabling identity impersonation. Discovery of rogue code-signing certificates indicates malware persistence capability. |
| **OS Scope** | Windows XP through Windows 11 |
| **Data Scope** | Per-user |
| **Decoder Approach** | Export via `certutil -exportPFX -p <password> My <thumbprint> output.pfx`. Registry extraction: PowerShell `Get-Item "HKCU:\Software\Microsoft\SystemCertificates\My\Certificates"`, convert binary blob to `X509Certificate2`. Private key: DPAPI decrypt with user master key then parse PFX/PVK. NVISO extraction guide for offline registry hives. |
| **MITRE ATT&CK** | T1552.004, T1553.004 |
| **References** | [NVISO certificate extraction from registry](https://blog.nviso.eu/2019/08/28/extracting-certificates-from-the-windows-registry/) · [Windows OS Hub certificate storage](https://woshub.com/windows-certificates-private-keys-store/) · [Microsoft SystemCertificates store locations](https://learn.microsoft.com/en-us/windows/win32/seccrypto/system-store-locations) |

---

## 22. Machine Certificate Store — Private Keys

| Field | Value |
|-------|-------|
| **Location** | Public keys (registry): `HKLM\SOFTWARE\Microsoft\SystemCertificates\My\Certificates\{Thumbprint}` · Private keys: `C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys\{ContainerGUID}` (legacy) or `C:\ProgramData\Microsoft\Crypto\Keys\{ContainerGUID}` (CNG) · Group Policy certs: `HKLM\Software\Policies\Microsoft\SystemCertificates` |
| **Format** | Same binary formats as user store. Machine-scope private keys protected by DPAPI machine master key (S-1-5-18 key material) rather than user master key. TPM-backed machine keys are non-exportable at the key blob level. |
| **Key Fields** | TLS server certificates (IIS, RDP), machine authentication certificates for 802.1X, domain controller certificates, NPS/RADIUS server certificates. RDP server certificate (`HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\SSLCertificateSHA1Hash`) references machine store. |
| **Forensic Value** | RDP server certificate thumbprint in registry links to machine store certificate — fingerprinting DC/server identity. Rogue machine certificates indicate PKI compromise or mis-issuance. Expired/revoked certificates still present in store. Machine key theft enables server impersonation in MitM attacks. |
| **OS Scope** | Windows XP through Windows 11 |
| **Data Scope** | System / machine |
| **Decoder Approach** | `certutil -store My` lists machine personal certificates. `certlm.msc` for GUI. Private key export: requires SYSTEM context + DPAPI machine master key. Registry extraction same approach as user store but from HKLM hive. |
| **MITRE ATT&CK** | T1552.004 |
| **References** | [Windows OS Hub certificate storage](https://woshub.com/windows-certificates-private-keys-store/) · [Microsoft local machine certificate stores](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/local-machine-and-current-user-certificate-stores) · [Encryption Consulting Windows certificate stores](https://www.encryptionconsulting.com/digital-certificate-and-windows-certificate-stores/) |

---

## 23. Windows Hello / NGC Folder

| Field | Value |
|-------|-------|
| **Location** | `C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc\` (NGC = Next Generation Credential). GUID subfolders per provider/user. `Protectors\` subfolder contains `.dat` files with protected key material. Registry (PIN-encrypted password, non-TPM): `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\NgcPin\Credentials\{SID}\encryptedPassword` |
| **Format** | Encrypted `.dat` files (DPAPI-NG / DPAPI protected). Metadata `.dat` files contain user SID and provider GUID associations. Private key material in TPM: non-exportable (TPM-bound); without TPM: RSA Private Key Blob stored in NGC Protectors folder, decryptable via DPAPI chain using PIN as entropy. |
| **Key Fields** | RSA-2048 asymmetric key pair per user per provider. Public key registered with cloud (Entra ID) or local AD. Private key used to sign authentication challenges. PIN is PBKDF2-SHA256 derived and used as entropy to decrypt the RSA private key blob from the Protectors folder (software-only scenario). Primary Refresh Token (PRT) for Entra ID encrypted with session key stored on TPM. |
| **Forensic Value** | Without TPM: PIN brute-force recovers private key → recovers user's Windows password from registry encrypted blob. With TPM: only limited metadata accessible offline. NGC key material confirms whether Windows Hello was enrolled (PIN, fingerprint, face). `certutil -csp NGC -key` lists enrolled keys. `dsregcmd /status` shows device registration state. |
| **OS Scope** | Windows 10 through Windows 11 (Windows Hello introduced in Win10 build 10240) |
| **Data Scope** | Per-user within SYSTEM-owned folder (requires SYSTEM privileges to access) |
| **Decoder Approach** | Enumerate: `certutil -csp "Microsoft Passport Key Storage Provider" -key`. Forensic parsing: Synacktiv research (WHFB + Entra ID cache flow) documents decryption chain. Passcape Windows Hello credential module. ACLs prevent standard admin access — requires SYSTEM. Without TPM: extract `encryptedPassword` registry value → DPAPI-NG decrypt → PBKDF2-SHA256 → RSA decrypt → plaintext password. |
| **MITRE ATT&CK** | T1555, T1003 |
| **References** | [Synacktiv WHFB Entra ID cache flow](https://www.synacktiv.com/en/publications/whfb-and-entra-id-say-hello-to-your-new-cache-flow) · [Passcape Windows Hello credentials](https://www.passcape.com/windows_password_recovery_windows_hello_credentials) · [Grokipedia NGC folder](https://grokipedia.com/page/NGC_folder_Windows) · [Helge Klein TPM vs Software key](https://helgeklein.com/blog/checking-windows-hello-for-business-whfb-key-storage-tpm-hardware-or-software/) |

---

## 24. Scheduled Task Credential Blobs

| Field | Value |
|-------|-------|
| **Location** | User-context tasks: `C:\Users\{username}\AppData\Local\Microsoft\Credentials\{GUID}` and `C:\Users\{username}\AppData\Roaming\Microsoft\Credentials\{GUID}` (same location as standard DPAPI credential blobs, distinguished by `TargetName` prefix `Domain:batch=TaskScheduler:Task:{TaskGUID}`) · SYSTEM-context tasks: `C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Credentials\{GUID}` · Task XML definitions: `C:\Windows\System32\Tasks\` (XML files, no embedded credentials; credentials referenced by GUID) |
| **Format** | DPAPI credential blob (same binary structure as artifact 3). `TargetName` field within decrypted blob explicitly identifies the scheduled task by its GUID. Task XML files are plaintext XML (no credential material embedded — only task metadata and trigger/action definitions). |
| **Key Fields** | Username and password of the account the task runs as. `TargetName` format: `Domain:batch=TaskScheduler:Task:{813565C4-C976-4E78-A1CA-8BDAE749E965}`. `guidMasterKey` in blob header identifies which DPAPI master key to use. |
| **Forensic Value** | Reveals service account passwords for all scheduled tasks requiring explicit credentials (not SYSTEM/Network Service). Stale credentials (task created with old password that was since changed) still present as decryptable blobs — useful for password recovery. Tasks running as Domain Admin are highest-value targets. TaskHound tool automates enumeration and stale credential detection. |
| **OS Scope** | Windows Vista through Windows 11 |
| **Data Scope** | Per-user (user-context tasks) or System (SYSTEM-context tasks) |
| **Decoder Approach** | Enumerate via `schtasks /query /fo LIST /v` (shows run-as username). Credential blob: Mimikatz `dpapi::cred /in:<credential_blob>` to identify `guidMasterKey`, then `dpapi::cred /in:<blob> /masterkey:<key>` to decrypt. SharpDPAPI `credentials`. TaskHound for automated SMB-based enumeration. Task XML at `C:\Windows\System32\Tasks\` for task metadata. |
| **MITRE ATT&CK** | T1053.005, T1555 |
| **References** | [Mimikatz scheduled task credentials wiki](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-scheduled-tasks-credentials) · [ProSec Networks TaskHound](https://www.prosec-networks.com/en/blog/verdeckte-angriffspfade-in-scheduled-tasks-effizient-aufdecken-taskhound-hilft/) · [CyberPress TaskHound](https://cyberpress.org/taskhound-tool-for-detecting-privileged-windows-scheduled-tasks-and-stored-credentials/) · [Synacktiv Windows Secrets Summary](https://www.synacktiv.com/en/publications/windows-secrets-extraction-a-summary) |

---

## Quick Reference: MITRE ATT&CK Coverage

| Technique | ID | Artifacts Covered |
|-----------|-----|-------------------|
| OS Credential Dumping: LSASS Memory | T1003.001 | #10, #17 |
| OS Credential Dumping: SAM | T1003.002 | #6 |
| OS Credential Dumping: NTDS | T1003.003 | #9, #5 |
| OS Credential Dumping: LSA Secrets | T1003.004 | #7, #2 |
| OS Credential Dumping: Cached Domain Credentials | T1003.005 | #8 |
| Credentials from Web Browsers | T1555.003 | #12, #13, #14, #15 |
| Credentials from Windows Credential Manager | T1555.004 | #11, #3 |
| Steal or Forge Kerberos Tickets | T1558 | #20 |
| Pass the Ticket | T1550.003 | #20 |
| Unsecured Credentials: Private Keys | T1552.004 | #21, #22 |
| Scheduled Task / Job | T1053.005 | #24 |
| Steal Web Session Cookie | T1539 | #13, #15 |
| Modify Registry | T1112 | #17 |
| Subvert Trust Controls: Install Root Certificate | T1553.004 | #21 |

---

## Decoder Tool Reference

| Tool | Primary Use | Source |
|------|-------------|--------|
| **Mimikatz** | Live LSASS dump, DPAPI, LSA, SAM, Kerberos | [gentilkiwi/mimikatz](https://github.com/gentilkiwi/mimikatz) |
| **Impacket secretsdump.py** | Offline SAM/LSA/DCC2/NTDS.dit parsing | [SecureAuthCorp/impacket](https://github.com/SecureAuthCorp/impacket) |
| **SharpDPAPI** | DPAPI master keys, credentials, vaults | [GhostPack/SharpDPAPI](https://github.com/GhostPack/SharpDPAPI) |
| **DSInternals** | NTDS.dit offline, DPAPI backup key | [MichaelGrafnetter/DSInternals](https://github.com/MichaelGrafnetter/DSInternals) |
| **firefox_decrypt** | Firefox logins.json + key4.db | [unode/firefox_decrypt](https://github.com/unode/firefox_decrypt) |
| **firepwd.py** | Firefox offline without NSS | Integrated into LaZagne |
| **LaZagne** | Multi-application credential extraction | [AlessandroZ/LaZagneForensic](https://github.com/AlessandroZ/LaZagneForensic) |
| **TaskHound** | Scheduled task credential enumeration | [ProSec Networks](https://www.prosec-networks.com/en/blog/verdeckte-angriffspfade-in-scheduled-tasks-effizient-aufdecken-taskhound-hilft/) |
| **RegRipper** | Offline registry hive forensics | [keydet89/RegRipper3.0](https://github.com/keydet89/RegRipper3.0) |
| **ESEDatabaseView** | WebCacheV01.dat / NTDS.dit ESE parsing | [Nirsoft](https://www.nirsoft.net/) |
| **Rubeus** | Kerberos ticket manipulation | [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus) |
