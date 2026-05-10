# Windows Persistence Deep Catalog

A comprehensive, authoritative catalog of Windows persistence mechanisms beyond simple Run key registry entries. Each artifact documents exact paths, forensic fields, MITRE ATT&CK technique IDs, and primary references. All claims are sourced from MITRE ATT&CK, PersistenceSniper, Atomic Red Team, and pentestlab.blog among others.

---

## Registry-Based Persistence

### 1. Run Keys / RunOnce Keys

| Field | Value |
|-------|-------|
| **Location** | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, `HKLM\...\RunOnce`, `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, `HKCU\...\RunOnce`, `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run` |
| **Format** | REG_SZ or REG_EXPAND_SZ — value name is arbitrary, data is path to executable |
| **Key Fields** | Value name (attacker-chosen label), value data (full executable path, optionally with arguments) |
| **Forensic Value** | Executes arbitrary payload on every user logon (HKCU) or system boot (HKLM). Most prevalent persistence technique in the wild — observed in 54 threat actor groups. RunOnce entries self-delete after first execution but are still critical to capture. |
| **OS Scope** | Windows XP through Windows 11, Windows Server 2003 through 2025 |
| **Data Scope** | HKLM = System; HKCU = User |
| **Decoder Approach** | Identity (string read); also check `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders` for redirected startup folder paths |
| **MITRE ATT&CK** | T1547.001 |
| **References** | [MITRE T1547.001](https://attack.mitre.org/techniques/T1547/001/), [Atomic Red Team T1547.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1547.001/T1547.001.md) |

---

### 2. Winlogon Shell Value

| Field | Value |
|-------|-------|
| **Location** | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon` value `Shell` (also `HKCU` variant) |
| **Format** | REG_SZ; default is `explorer.exe` |
| **Key Fields** | Shell value data — can be a comma-separated list of executables; any entry beyond `explorer.exe` is suspicious |
| **Forensic Value** | Any program listed in `Shell` is launched by Winlogon at user logon as the desktop shell. Replacing or appending to this value gives attacker-level process execution at every logon with the logged-in user's context. |
| **OS Scope** | Windows XP through Windows 11 |
| **Data Scope** | System (HKLM) or User (HKCU) |
| **Decoder Approach** | Identity; alert on any value other than `explorer.exe` or `explorer.exe,<legitimate_app>` |
| **MITRE ATT&CK** | T1547.004 |
| **References** | [MITRE T1547.004](https://attack.mitre.org/techniques/T1547/004/), [ired.team Winlogon Helper](https://www.ired.team/offensive-security/persistence/windows-logon-helper), [sensei-infosec registry persistence](https://sensei-infosec.netlify.app/forensics/registry/persistence/2020/04/15/malware-persistence-registry.html) |

---

### 3. Winlogon Userinit Value

| Field | Value |
|-------|-------|
| **Location** | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon` value `Userinit` |
| **Format** | REG_SZ; default is `C:\Windows\system32\userinit.exe,` (trailing comma is required) |
| **Key Fields** | Any path appended after the trailing comma is also executed; the appended path survives reboots |
| **Forensic Value** | Winlogon passes this value to CreateProcess at logon. An additional executable appended here runs in the user's session on every logon. |
| **OS Scope** | Windows XP through Windows 11 |
| **Data Scope** | System (HKLM) |
| **Decoder Approach** | Identity; split on comma; flag any entry beyond `userinit.exe` |
| **MITRE ATT&CK** | T1547.004 |
| **References** | [MITRE T1547.004](https://attack.mitre.org/techniques/T1547/004/), [registry persistence blog](https://sensei-infosec.netlify.app/forensics/registry/persistence/2020/04/15/malware-persistence-registry.html) |

---

### 4. Winlogon Notify Subkeys (Legacy)

| Field | Value |
|-------|-------|
| **Location** | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify\*` |
| **Format** | REG subkey with REG_SZ values: `DLLName` (path to DLL), event handler names (e.g., `Logon`, `Logoff`, `Startup`, `Shutdown`) |
| **Key Fields** | DLLName value, exported function names referenced by the event handler values, Asynchronous DWORD |
| **Forensic Value** | Loads a DLL into the Winlogon process when security events (logon, logoff, SAS/Ctrl+Alt+Del, startup, shutdown) occur. Provides SYSTEM-context DLL injection that persists across reboots. Used by rootkits on pre-Vista systems; subkey parsing still relevant for legacy image analysis. |
| **OS Scope** | Windows 2000 through Windows XP/2003 (removed in Vista+); legacy forensic relevance for historical cases |
| **Data Scope** | System (HKLM) |
| **Decoder Approach** | Enumerate subkeys; extract DLLName and function name values |
| **MITRE ATT&CK** | T1547.004 |
| **References** | [MITRE T1547.004](https://attack.mitre.org/techniques/T1547/004/), [hadess.io art of persistence](https://hadess.io/the-art-of-windows-persistence/) |

---

### 5. BootExecute

| Field | Value |
|-------|-------|
| **Location** | `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager` value `BootExecute` |
| **Format** | REG_MULTI_SZ; default single entry is `autocheck autochk *` |
| **Key Fields** | Each line of the multi-string is a native executable path run by smss.exe before the Win32 subsystem loads; path is relative to `\SystemRoot\System32` |
| **Forensic Value** | Executes before Windows subsystem initializes — runs with kernel-level trust in the native API environment. Any entry beyond `autocheck autochk *` is highly suspicious. Malware uses this to hook the boot process, ensure pre-AV execution, and circumvent early-boot protections. |
| **OS Scope** | Windows NT through Windows 11 |
| **Data Scope** | System (HKLM) |
| **Decoder Approach** | MultiSz — split on null bytes; baseline against `autocheck autochk *`; alert on any additional entries |
| **MITRE ATT&CK** | T1547.001 (boot-phase autostart) |
| **References** | [MITRE T1547](https://attack.mitre.org/techniques/T1547/), [infosecinstitute common malware persistence](https://resources.infosecinstitute.com/topic/common-malware-persistence-mechanisms/), [hadess.io](https://hadess.io/the-art-of-windows-persistence/) |

---

### 6. Services (Windows Services)

| Field | Value |
|-------|-------|
| **Location** | `HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\` |
| **Format** | REG subkey with multiple typed values |
| **Key Fields** | `Type` (DWORD: 0x10=own process, 0x20=shared, 0x110=own+interactive), `Start` (DWORD: 0=boot, 1=system, 2=auto, 3=demand, 4=disabled), `ImagePath` (REG_EXPAND_SZ: executable or `%SystemRoot%\System32\svchost.exe -k <group>`), `ServiceDll` (REG_EXPAND_SZ under `Parameters\` subkey for svchost-hosted services), `ObjectName` (account: LocalSystem/LocalService/NetworkService/domain account) |
| **Forensic Value** | Auto-start services (Start=2) execute at boot with the account specified in ObjectName (often SYSTEM). Malicious services achieve persistent SYSTEM-level code execution; ServiceDll indirection into svchost makes detection harder. Used by 26 documented threat actor groups. |
| **OS Scope** | Windows NT through Windows 11 |
| **Data Scope** | System (HKLM) |
| **Decoder Approach** | BinaryRecord for `Start`/`Type` DWORDs; Identity for ImagePath/ServiceDll; cross-reference ServiceDll with known-good baseline |
| **MITRE ATT&CK** | T1543.003 |
| **References** | [MITRE T1543.003](https://attack.mitre.org/techniques/T1543/003/), [Psmths windows-forensic-artifacts services](https://github.com/Psmths/windows-forensic-artifacts/blob/main/persistence/registry-services.md) |

---

### 7. Active Setup

| Field | Value |
|-------|-------|
| **Location** | `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components\<CLSID>\` and `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components\<CLSID>\` |
| **Format** | REG subkeys; key values: `StubPath` (REG_SZ/REG_EXPAND_SZ), `Version` (REG_SZ, e.g., `"1,0,0,0"`), `IsInstalled` (REG_DWORD, 1=enabled) |
| **Key Fields** | StubPath (command executed on logon when HKLM version > HKCU version), Version (controls per-user re-execution), IsInstalled, component display name |
| **Forensic Value** | Windows executes StubPath for each user logon when the HKLM version is newer than the HKCU tracking entry. Gives per-user code execution at logon with low detection coverage. Legitimate entries exist (IE, WMP setup), so baseline comparison is essential. Abused by APT groups for persistent per-user payloads. |
| **OS Scope** | Windows 95 through Windows 11 |
| **Data Scope** | System (HKLM) triggers; User (HKCU) tracks execution state |
| **Decoder Approach** | Identity for StubPath; DWORD for Version components; compare HKLM vs HKCU Version strings per user |
| **MITRE ATT&CK** | T1547.014 |
| **References** | [MITRE T1547.014](https://attack.mitre.org/techniques/T1547/014/), [Picus T1547.014](https://www.picussecurity.com/resource/blog/t1547-014-active-setup) |

---

### 8. AppCert DLLs

| Field | Value |
|-------|-------|
| **Location** | `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls` |
| **Format** | REG values under this key; each value name is arbitrary, data (REG_SZ) is full DLL path |
| **Key Fields** | Each DLL path listed is injected into any process that calls `CreateProcess`, `CreateProcessAsUser`, `CreateProcessWithLogonW`, `CreateProcessWithTokenW`, or `WinExec`; DLL must export `CreateProcessNotify` |
| **Forensic Value** | Nearly universal DLL injection — virtually every process launch triggers injection. Gives persistent code execution across all process creations system-wide. Requires admin rights but is stealthy because the injection is invisible to most process monitors. |
| **OS Scope** | Windows 2000 through Windows 11 |
| **Data Scope** | System (HKLM) |
| **Decoder Approach** | Enumerate all values; baseline against empty (no legitimate entries exist in default Windows installs) |
| **MITRE ATT&CK** | T1546.009 |
| **References** | [MITRE T1546.009](https://attack.mitre.org/techniques/T1546/009/), [infosecinstitute malware persistence](https://resources.infosecinstitute.com/topic/common-malware-persistence-mechanisms/), [hadess.io](https://hadess.io/the-art-of-windows-persistence/) |

---

### 9. AppInit DLLs

| Field | Value |
|-------|-------|
| **Location** | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows` values `AppInit_DLLs` (REG_SZ) and `LoadAppInit_DLLs` (REG_DWORD) |
| **Format** | REG_SZ comma/space-separated list of DLL paths; LoadAppInit_DLLs DWORD must be 1 to activate; `RequireSignedAppInit_DLLs` DWORD (1=only load signed DLLs) |
| **Key Fields** | AppInit_DLLs list, LoadAppInit_DLLs flag, RequireSignedAppInit_DLLs flag |
| **Forensic Value** | Injects listed DLLs into every process that loads user32.dll (all GUI applications). Deprecated in Windows 8+ when Secure Boot is enabled (RequireSignedAppInit_DLLs=1 by default), but still functional on many systems. Legacy malware favorite. |
| **OS Scope** | Windows XP through Windows 11 (restricted by Secure Boot in Win8+) |
| **Data Scope** | System (HKLM) |
| **Decoder Approach** | Identity for DLL list; DWORD flags; alert on LoadAppInit_DLLs=1 with any non-empty AppInit_DLLs |
| **MITRE ATT&CK** | T1546.010 |
| **References** | [MITRE T1546.010](https://attack.mitre.org/techniques/T1546/010/), [hadess.io](https://hadess.io/the-art-of-windows-persistence/), [amr-git persistence](https://amr-git-dot.github.io/offensive/persistence/) |

---

### 10. LSA Authentication Packages

| Field | Value |
|-------|-------|
| **Location** | `HKLM\SYSTEM\CurrentControlSet\Control\Lsa` value `Authentication Packages` |
| **Format** | REG_MULTI_SZ; default contains `msv1_0`; each line is a DLL name (no extension, resolved from `%SystemRoot%\System32`) |
| **Key Fields** | Each DLL name listed is loaded into lsass.exe at boot; DLL gains access to all authentication operations and plaintext credentials |
| **Forensic Value** | Authentication package DLLs load into LSASS at system startup with SYSTEM privileges and access to plaintext credentials. Adding a malicious DLL here achieves boot-persistent credential harvesting or code injection into the most sensitive Windows process. Blocked by LSA Protection (RunAsPPL). |
| **OS Scope** | Windows NT through Windows 11 |
| **Data Scope** | System (HKLM) |
| **Decoder Approach** | MultiSz; baseline against `msv1_0`; any additional entry is highly suspicious |
| **MITRE ATT&CK** | T1547.002 |
| **References** | [MITRE T1547.002](https://attack.mitre.org/techniques/T1547/002/), [Picus T1547.002](https://www.picussecurity.com/resource/blog/t1547-002-authentication-package), [ired.team SSP](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/intercepting-logon-credentials-via-custom-security-support-provider-and-authentication-package) |

---

### 11. LSA Security Packages (SSP)

| Field | Value |
|-------|-------|
| **Location** | `HKLM\SYSTEM\CurrentControlSet\Control\Lsa` value `Security Packages` and `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig` value `Security Packages` |
| **Format** | REG_MULTI_SZ; defaults include `kerberos`, `msv1_0`, `schannel`, `wdigest`, `tspkg`, `pku2u` |
| **Key Fields** | Each entry is a DLL name loaded into lsass.exe; DLL can also be registered dynamically via `AddSecurityPackage` Windows API (no reboot required) |
| **Forensic Value** | SSP DLLs load into LSASS at boot and can intercept all authentication. Classic technique for credential harvesting (e.g., mimilib.dll from Mimikatz). Can be installed without reboot via API, leaving only the registry as forensic evidence. |
| **OS Scope** | Windows XP through Windows 11 |
| **Data Scope** | System (HKLM) |
| **Decoder Approach** | MultiSz; diff against known-good baseline; check both `Lsa\Security Packages` and `Lsa\OSConfig\Security Packages` |
| **MITRE ATT&CK** | T1547.005 |
| **References** | [MITRE T1547.005](https://attack.mitre.org/techniques/T1547/005/), [ired.team SSP](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/intercepting-logon-credentials-via-custom-security-support-provider-and-authentication-package), [hadess.io](https://hadess.io/the-art-of-windows-persistence/) |

---

### 12. LSASS Driver (LsaDbExtPt)

| Field | Value |
|-------|-------|
| **Location** | `HKLM\SYSTEM\CurrentControlSet\Services\NTDS` value `LsaDbExtPt` |
| **Format** | REG_SZ; full path to a DLL |
| **Key Fields** | The DLL path is loaded into lsass.exe as an LSA database extension; undocumented mechanism |
| **Forensic Value** | Undocumented registry-based method to load an arbitrary DLL into LSASS. Provides highly covert SYSTEM-level persistence via a registry value in the NTDS service key that most detection tools do not monitor. |
| **OS Scope** | Windows Server with Active Directory (NTDS service present) |
| **Data Scope** | System (HKLM) |
| **Decoder Approach** | Identity; presence of this value with any data is immediately suspicious |
| **MITRE ATT&CK** | T1547.008 |
| **References** | [MITRE T1547.008](https://attack.mitre.org/techniques/T1547/008/), [Picus T1547.008](https://www.picussecurity.com/resource/blog/t1547-008-lsass-driver), [SOC Prime T1547.008](https://socprime.com/active-threats/t1547-008-lsass-driver-in-mitre-attck-explained/) |

---

### 13. Port Monitors

| Field | Value |
|-------|-------|
| **Location** | `HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors\<MonitorName>\` value `Driver` |
| **Format** | REG_SZ; DLL filename (resolved from `%SystemRoot%\System32`) |
| **Key Fields** | Monitor name (subkey), Driver value (DLL filename), physical DLL in `C:\Windows\System32\` |
| **Forensic Value** | Port monitor DLLs are loaded by the Print Spooler service (spoolsv.exe) at boot with SYSTEM privileges. Registration requires `SeLoadDriverPrivilege` or direct registry write. Survived the PrintNightmare era as a persistence vector (CVE-2020-1048). DLL executes as SYSTEM on every reboot. |
| **OS Scope** | Windows XP through Windows 11 |
| **Data Scope** | System (HKLM) |
| **Decoder Approach** | Enumerate subkeys under `Print\Monitors`; extract Driver value; baseline against known monitors (`WSD Port Monitor`, `Local Port`, `Standard TCP/IP Port`, `USB Monitor`) |
| **MITRE ATT&CK** | T1547.010 |
| **References** | [MITRE T1547.010](https://attack.mitre.org/techniques/T1547/010/), [pentestlab.blog port monitors](https://pentestlab.blog/2019/10/28/persistence-port-monitors/), [Picus T1547.010](https://www.picussecurity.com/resource/blog/t1547-010-port-monitors), [PrintDemon](https://windows-internals.com/printdemon-cve-2020-1048/) |

---

### 14. Print Processors

| Field | Value |
|-------|-------|
| **Location** | `HKLM\SYSTEM\CurrentControlSet\Control\Print\Environments\Windows x64\Print Processors\<ProcessorName>\` value `Driver` |
| **Format** | REG_SZ; DLL filename resolved from the processor path |
| **Key Fields** | Processor name (subkey), Driver value, DLL file in system directory |
| **Forensic Value** | Print processor DLLs are loaded by the Print Spooler (spoolsv.exe) at boot with SYSTEM privileges. The path differs by architecture (`Windows x64` vs `Windows NT x86`). Abused in same class of attacks as Port Monitors. Both mechanisms survived PrintNightmare mitigations and require monitoring. |
| **OS Scope** | Windows XP through Windows 11 |
| **Data Scope** | System (HKLM) |
| **Decoder Approach** | Enumerate subkeys; Driver value; baseline against `winprint` (the only default processor) |
| **MITRE ATT&CK** | T1547.012 |
| **References** | [MITRE T1547.012](https://attack.mitre.org/techniques/T1547/012/), [Elastic detection rule](https://www.elastic.co/guide/en/security/8.19/prebuilt-rule-1-0-2-potential-port-monitor-or-print-processor-registration-abuse.html) |

---

### 15. Time Provider DLLs

| Field | Value |
|-------|-------|
| **Location** | `HKLM\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\<ProviderName>\` values `DllName` (REG_EXPAND_SZ) and `Enabled` (REG_DWORD) |
| **Format** | REG subkeys; DllName is full path to the provider DLL; Enabled=1 activates it |
| **Key Fields** | DllName, Enabled, InputProvider (DWORD, 1=input, 0=output), ProviderType |
| **Forensic Value** | Time provider DLLs are loaded by the W32Time service (runs as LocalSystem) when the service starts. DLL must export `TimeProvOpen`, `TimeProvCommand`, and `TimeProvClose`. Legitimate providers: `NtpClient`, `NtpServer`, `VMICTimeProvider`. Any additional provider DLL is suspicious. |
| **OS Scope** | Windows XP through Windows 11 |
| **Data Scope** | System (HKLM) |
| **Decoder Approach** | Enumerate subkeys; baseline against known providers; flag any DllName pointing outside `%SystemRoot%\System32` |
| **MITRE ATT&CK** | T1547.003 |
| **References** | [MITRE T1547.003](https://attack.mitre.org/techniques/T1547/003/), [amr-git persistence](https://amr-git-dot.github.io/offensive/persistence/), [pentestlab.blog time provider](https://pentestlab.blog/2019/10/22/persistence-time-providers/) |

---

### 16. Netsh Helper DLLs

| Field | Value |
|-------|-------|
| **Location** | `HKLM\SOFTWARE\Microsoft\NetSh` |
| **Format** | REG values; each value name is a label, data (REG_SZ) is DLL filename or full path |
| **Key Fields** | Each value data is a DLL that netsh.exe loads on startup; DLL must export `InitHelperDll`; registration via `netsh add helper <path>` also writes this key |
| **Forensic Value** | Netsh is a system administration utility that loads helper DLLs at startup. Any VPN, firewall, or network tool may invoke netsh automatically, causing the malicious DLL to load without explicit Run key. Provides code execution within the netsh.exe process context. Requires admin rights to register. |
| **OS Scope** | Windows XP through Windows 11 |
| **Data Scope** | System (HKLM) |
| **Decoder Approach** | Enumerate all values; baseline against known helpers (dhcpmon.dll, dot3cfg.dll, eappcfg.dll, etc.); flag any unexpected DLL path |
| **MITRE ATT&CK** | T1546.007 |
| **References** | [MITRE T1546.007](https://attack.mitre.org/techniques/T1546/007/), [ired.team netsh](https://www.ired.team/offensive-security/persistence/t1128-netsh-helper-dll), [pentestlab.blog netsh](https://pentestlab.blog/2019/10/29/persistence-netsh-helper-dll/) |

---

### 17. Winsock LSP (Layered Service Providers)

| Field | Value |
|-------|-------|
| **Location** | `HKLM\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\Protocol_Catalog9\Catalog_Entries\<ID>\` (32-bit) and `Catalog_Entries64\` (64-bit); `NameSpace_Catalog5\Catalog_Entries\` for namespace providers |
| **Format** | REG_BINARY binary record per entry; key field within: `PackedCatalogItem` contains the DLL path, layer order, and protocol info |
| **Key Fields** | DLL path embedded in PackedCatalogItem binary blob, Protocol chain (layer order), ProtocolName, ServiceFlags |
| **Forensic Value** | LSPs intercept all Winsock calls before `ws2_32.dll` processes them — enabling transparent credential capture, traffic redirection, or C2 proxying. Deprecated since Windows Server 2012 but may still be present on legacy systems. Malicious removal without using WinSock APIs corrupts the entire TCP/IP stack. Inspect with `netsh winsock show catalog`. |
| **OS Scope** | Windows 95 through Windows 11 (deprecated in Win8/2012+) |
| **Data Scope** | System (HKLM) |
| **Decoder Approach** | BinaryRecord (PackedCatalogItem); use `netsh winsock show catalog` or LSP inspection APIs; flag DLL paths outside `%SystemRoot%\System32` |
| **MITRE ATT&CK** | T1574.001 (DLL search order hijacking of network stack) |
| **References** | [Wikipedia LSP](https://en.wikipedia.org/wiki/Layered_Service_Provider), [Microsoft Winsock LSP categorization](https://learn.microsoft.com/en-us/windows/win32/winsock/categorizing-layered-service-providers-and-applications) |

---

### 18. Network Provider Order / Malicious Network Provider DLL

| Field | Value |
|-------|-------|
| **Location** | `HKLM\SYSTEM\CurrentControlSet\Control\NetworkProvider\Order` value `ProviderOrder` (REG_SZ, comma-separated provider names); `HKLM\SYSTEM\CurrentControlSet\Services\<ProviderName>\NetworkProvider\` subkey values: `Class` (REG_DWORD=2), `ProviderPath` (REG_EXPAND_SZ=DLL path), `Name` (REG_SZ) |
| **Format** | ProviderOrder is REG_SZ comma-separated; per-provider config is REG_DWORD/REG_EXPAND_SZ/REG_SZ under the service's NetworkProvider subkey |
| **Key Fields** | ProviderOrder list, ProviderPath (DLL), Class, Name; DLL must export `NPLogonNotify`, `NPPasswordChangeNotify`, `NPGetCaps` |
| **Forensic Value** | Malicious network provider DLLs receive cleartext credentials via `NPLogonNotify()` from `mpnotify.exe` on every logon (before encryption). Highly stealthy — abuses a legitimate Windows authentication hook. NPPSpy is a public PoC. Default legitimate providers: RDPNP, LanmanWorkstation, webclient. |
| **OS Scope** | Windows XP through Windows 11 |
| **Data Scope** | System (HKLM) |
| **Decoder Approach** | Parse ProviderOrder CSV; enumerate each provider's NetworkProvider subkey; ProviderPath outside `%SystemRoot%\System32` or non-default provider names are suspicious |
| **MITRE ATT&CK** | T1556.008 |
| **References** | [MITRE T1556.008](https://attack.mitre.org/techniques/T1556/008/), [ricardojoserf network providers](https://ricardojoserf.github.io/networkproviders/), [GIAC network provider exploit](https://www.giac.org/paper/gcih/117/microsoft-network-provider-exploit/101145), [SocInvestigation credential dumping](https://www.socinvestigation.com/credential-dumping-using-windows-network-providers-how-to-respond/) |

---

### 19. RDP Startup Programs

| Field | Value |
|-------|-------|
| **Location** | `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\Wds\rdpwd\StartupPrograms` (REG_SZ) and `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services` value `InitialProgram` |
| **Format** | REG_SZ; executable path launched when an RDP session is established |
| **Key Fields** | StartupPrograms value (executed for all RDP sessions), InitialProgram (Group Policy controlled per-session initial application) |
| **Forensic Value** | Any program listed in StartupPrograms executes when a Remote Desktop connection is established, even before the user's shell loads. This provides persistent execution triggered by remote access events — useful for attackers maintaining RDP-based access. |
| **OS Scope** | Windows XP through Windows 11 (Terminal Services component) |
| **Data Scope** | System (HKLM) |
| **Decoder Approach** | Identity; any non-empty value or non-default program path is suspicious |
| **MITRE ATT&CK** | T1547.001 (autostart via terminal services) |
| **References** | [PersistenceSniper wiki detections](https://github.com/last-byte/PersistenceSniper/wiki/3-%E2%80%90-Detections), [amr-git persistence](https://amr-git-dot.github.io/offensive/persistence/) |

---

### 20. COM Hijacking via HKCU Classes

| Field | Value |
|-------|-------|
| **Location** | `HKCU\Software\Classes\CLSID\{<GUID>}\InprocServer32` value `(Default)` and `ThreadingModel` |
| **Format** | REG_SZ; DLL path; ThreadingModel = Apartment / Both / Free |
| **Key Fields** | CLSID GUID (matches a legitimate COM object in HKLM), DLL path (attacker-controlled), ThreadingModel |
| **Forensic Value** | Windows COM resolution checks HKCU before HKLM. A CLSID registered under HKCU overrides the system registration, causing any application that instantiates that COM object to load the attacker's DLL instead. Requires only user-level privileges, making it very accessible. Activated by legitimate application use patterns (e.g., Explorer, Task Scheduler). |
| **OS Scope** | Windows Vista through Windows 11 |
| **Data Scope** | User (HKCU) |
| **Decoder Approach** | Enumerate HKCU Classes CLSID subkeys; cross-reference each GUID against HKLM; any HKCU CLSID with InprocServer32 pointing outside `%SystemRoot%\System32` or user-writable paths is suspicious |
| **MITRE ATT&CK** | T1546.015 |
| **References** | [MITRE T1546.015](https://attack.mitre.org/techniques/T1546/015/), [hadess.io](https://hadess.io/the-art-of-windows-persistence/), [amr-git persistence](https://amr-git-dot.github.io/offensive/persistence/) |

---

### 21. Image File Execution Options (IFEO) Injection

| Field | Value |
|-------|-------|
| **Location** | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<executable.exe>\` values `Debugger` (REG_SZ) and/or `GlobalFlag` (REG_DWORD); `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\<executable.exe>\` values `MonitorProcess` (REG_SZ) and `ReportingMode` (REG_DWORD=1) |
| **Format** | Debugger: REG_SZ path to a program prepended at launch; GlobalFlag: DWORD 0x200 (512) enables SilentProcessExit; MonitorProcess: REG_SZ path to program launched on target exit |
| **Key Fields** | Debugger value (launched instead of target), GlobalFlag (0x200 = SilentProcessExit monitoring), MonitorProcess (executed when monitored process exits), VerifierDlls (DLL injected via Application Verifier) |
| **Forensic Value** | IFEO Debugger: any launch of the target binary instead launches the Debugger value — SYSTEM-level if the target runs as SYSTEM (e.g., accessibility tools at the lock screen: sethc.exe, utilman.exe). SilentProcessExit: triggers MonitorProcess on target exit — survives reboots, evades Autoruns. Used by SUNBURST, SDBbot. Accessibility backdoor bypasses authentication. |
| **OS Scope** | Windows XP through Windows 11 |
| **Data Scope** | System (HKLM) |
| **Decoder Approach** | Enumerate all IFEO subkeys; flag any with Debugger value; check SilentProcessExit key for MonitorProcess; GlobalFlag 0x200 without legitimate debugging justification is suspicious |
| **MITRE ATT&CK** | T1546.012, T1546.008 (accessibility features) |
| **References** | [MITRE T1546.012](https://attack.mitre.org/techniques/T1546/012/), [MITRE T1546.008](https://attack.mitre.org/techniques/T1546/008/), [Jaiminton T1546.012](https://www.jaiminton.com/Mitreatt&ck/T1546-012), [Atomic Red Team T1546.012](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1546.012/T1546.012.md) |

---

### 22. Application Shimming (SDB Shim Database)

| Field | Value |
|-------|-------|
| **Location** | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB\{<GUID>}` and `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom\<executable.exe>\{<GUID>}`; shim file: `%WINDIR%\AppPatch\Custom\<GUID>.sdb` or `%WINDIR%\AppPatch\AppPatch64\Custom\` |
| **Format** | InstalledSDB subkey with metadata; Custom subkey with executable name → GUID; `.sdb` binary shim database file |
| **Key Fields** | SDB GUID, DatabasePath, DatabaseType, DatabaseDescription; within .sdb: PATCH tags, INJECT_DLL, RedirectEXE, InjectDLL, DisableNX, DisableSEH |
| **Forensic Value** | Shim cache intercepts process creation — shim can inject DLLs, redirect execution, bypass UAC (RedirectEXE on auto-elevating binaries), and disable security features. Installed via `sdbinst.exe`. Used by FIN7, TA505. Survives reboots through registry and .sdb file on disk. ShimCache (Amcache) records shim use. |
| **OS Scope** | Windows XP through Windows 11 |
| **Data Scope** | System (HKLM) |
| **Decoder Approach** | Parse .sdb binary using sdb-explorer or similar; check AppCompatFlags registry; monitor sdbinst.exe process creation (Sysmon EID 1) |
| **MITRE ATT&CK** | T1546.011 |
| **References** | [MITRE T1546.011](https://attack.mitre.org/techniques/T1546/011/), [Atomic Red Team T1546.011](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1546.011/T1546.011.md), [CISA T1546.011](https://www.cisa.gov/eviction-strategies-tool/info-attack/T1546.011) |

---

### 23. WMI Event Subscriptions (Registry Side)

| Field | Value |
|-------|-------|
| **Location** | `HKLM\SOFTWARE\Microsoft\Wbem\CIMOM` value `Autorecover MOFs` (REG_MULTI_SZ) lists compiled MOF paths; WMI database: `C:\Windows\System32\wbem\Repository\OBJECTS.DATA` |
| **Format** | Autorecover MOFs: REG_MULTI_SZ of file paths; WMI repository: proprietary binary CIM database |
| **Key Fields** | `__EventFilter` (WQL query defining trigger), `__EventConsumer` (action: CommandLineEventConsumer or ActiveScriptEventConsumer), `__FilterToConsumerBinding` (links filter to consumer); CommandLineEventConsumer fields: ExecutablePath, CommandLineTemplate |
| **Forensic Value** | WMI subscriptions survive reboots, are fileless (stored in OBJECTS.DATA), invisible to most autorun scanners, and execute under WmiPrvSE.exe or scrcons.exe (trusted processes, often SYSTEM). Used by APT groups for highly stealthy long-term persistence. Autorecover MOFs outside `%SystemRoot%\System32\wbem` are red flags. |
| **OS Scope** | Windows XP through Windows 11 |
| **Data Scope** | System |
| **Decoder Approach** | Parse OBJECTS.DATA with PyWMIPersistenceFinder.py or Kansa; query WMI `root\subscription` namespace; Sysmon EID 19/20/21; WMI-Activity EID 5861 |
| **MITRE ATT&CK** | T1546.003 |
| **References** | [MITRE T1546.003](https://attack.mitre.org/techniques/T1546/003/), [SANS finding evil WMI](https://www.sans.org/blog/finding-evil-wmi-event-consumers-with-disk-forensics/), [Medium DFIR deep dive](https://medium.com/@roeybartov.rb/windows-persistence-through-wmi-event-subscriptions-a-dfir-deep-dive-010929a67708), [pentestlab.blog WMI](https://pentestlab.blog/2020/01/21/persistence-wmi-event-subscription/) |

---

### 24. Scheduled Task Cache (Registry Side)

| Field | Value |
|-------|-------|
| **Location** | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{<GUID>}\` (per-task binary data) and `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\<TaskName>\` (task hierarchy) |
| **Format** | TaskCache\Tasks: binary REG_BINARY values (`Actions`, `Triggers`, `DynamicInfo`); TaskCache\Tree: `Id` (GUID, REG_SZ), `Index` (DWORD: 1=Boot, 2=Logon, 3=Plain, 4=Maintenance), `SD` (REG_BINARY security descriptor) |
| **Key Fields** | Actions (binary-encoded commands), Triggers (encoded schedule), Id (links Tree to Tasks), Index (task type), SD (security descriptor — deletion hides task from Task Scheduler UI and `schtasks /query`) |
| **Forensic Value** | Scheduled tasks persist across reboots and can execute as SYSTEM, a specific user, or any domain account. The **GhostTask / Tarrask technique** (HAFNIUM) writes task registry keys directly without using the Task Scheduler API, bypassing Event IDs 4698/106. Deleting the SD value (requires SYSTEM) makes the task invisible to `schtasks /query` and Task Scheduler GUI. XML files in `C:\Windows\System32\Tasks\` may be deleted while the task still runs until next reboot. |
| **OS Scope** | Windows Vista through Windows 11 |
| **Data Scope** | System (HKLM) |
| **Decoder Approach** | BinaryRecord for Actions/Triggers blobs (decode with schtask parser); Identity for Id/Index; absence of SD value = hidden task; cross-reference with `C:\Windows\System32\Tasks\` XML files |
| **MITRE ATT&CK** | T1053.005 |
| **References** | [MITRE T1053.005](https://attack.mitre.org/techniques/T1053/005/), [GhostTask GitHub](https://github.com/netero1010/GhostTask), [pentestlab scheduled task tampering](https://pentestlab.blog/2023/11/20/persistence-scheduled-task-tampering/), [SecurityBlueTeam scheduled tasks](https://www.securityblue.team/blog/posts/persistence-mechanisms-windows-scheduled-tasks) |

---

### 25. Browser Helper Objects (BHO)

| Field | Value |
|-------|-------|
| **Location** | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects\{<CLSID>}\` and `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects\{<CLSID>}\` |
| **Format** | REG subkey keyed by CLSID GUID; CLSID must resolve via HKCR to an InprocServer32 DLL |
| **Key Fields** | CLSID subkey (present = enabled), `NoExplorer` DWORD value (1 = skip loading in Explorer), associated CLSID InprocServer32 DLL path in HKCR |
| **Forensic Value** | BHOs are DLLs loaded into every Internet Explorer and Windows Explorer process. Though IE is deprecated (retired June 2022), BHOs still load into Explorer.exe in some configurations. Historically used by banking trojans and adware for persistent browser-context code execution (credential theft, traffic interception). |
| **OS Scope** | Windows XP through Windows 10 (IE-era); Explorer BHO loading may persist in Win11 |
| **Data Scope** | System (HKLM) or User (HKCU) |
| **Decoder Approach** | Enumerate BHO CLSIDs; resolve each CLSID to InprocServer32 DLL via HKCR; verify DLL signature and path; flag unsigned or user-directory DLLs |
| **MITRE ATT&CK** | T1176 (Browser Extensions), T1546.015 (COM Hijacking) |
| **References** | [MITRE T1176](https://attack.mitre.org/techniques/T1176/), [dfirtnt registry persistence paths](https://dfirtnt.wordpress.com/registry-persistence-paths/) |

---

### 26. Password Filter DLL

| Field | Value |
|-------|-------|
| **Location** | `HKLM\SYSTEM\CurrentControlSet\Control\Lsa` value `Notification Packages` |
| **Format** | REG_MULTI_SZ; default contains `scecli`; each line is a DLL name (without extension, resolved from `%SystemRoot%\System32`) |
| **Key Fields** | Each DLL is loaded into lsass.exe and receives plaintext passwords via `PasswordFilter()` on every password set/change operation |
| **Forensic Value** | Password filter DLLs receive every new plaintext password as it is validated (must call `PasswordFilter`, `PasswordChangeNotify`, `InitializeChangeNotify`). Provides persistent credential harvesting on DCs and workstations without touching disk-based credential stores. Survives password rotation — the attacker harvests each new password in plaintext. |
| **OS Scope** | Windows 2000 through Windows 11 |
| **Data Scope** | System (HKLM) |
| **Decoder Approach** | MultiSz; baseline against `scecli`; any additional entry is suspicious |
| **MITRE ATT&CK** | T1556.002 |
| **References** | [MITRE T1556.002](https://attack.mitre.org/techniques/T1556/002/), [CISA T1556.002](https://www.cisa.gov/eviction-strategies-tool/info-attack/T1556.008) |

---

### 27. Screensaver Hijacking

| Field | Value |
|-------|-------|
| **Location** | `HKCU\Control Panel\Desktop\` values: `SCRNSAVE.exe` (REG_SZ), `ScreenSaveActive` (REG_SZ "1"), `ScreenSaverIsSecure` (REG_SZ "0"), `ScreenSaveTimeout` (REG_SZ, seconds) |
| **Format** | REG_SZ string values |
| **Key Fields** | SCRNSAVE.exe (path to malicious PE or .scr), ScreenSaveActive (must be "1" to trigger), ScreenSaveTimeout (lower value = faster trigger), ScreenSaverIsSecure (0 = no lock on resume) |
| **Forensic Value** | Screensaver executes after user inactivity with the logged-in user's privileges. The parent process is winlogon.exe — a forensic red flag if the screensaver is not `scrnsave.scr` or another legitimate .scr file. Requires only user-level (HKCU) write access. Disabled if screensavers are blocked by Group Policy. |
| **OS Scope** | Windows XP through Windows 11 |
| **Data Scope** | User (HKCU) |
| **Decoder Approach** | Identity; SCRNSAVE.exe path pointing outside `%SystemRoot%\System32\` is suspicious; winlogon.exe as parent process of unexpected executable at investigation time |
| **MITRE ATT&CK** | T1546.002 |
| **References** | [MITRE T1546.002](https://attack.mitre.org/techniques/T1546/002/), [pentestlab.blog screensaver](https://pentestlab.blog/2019/10/09/persistence-screensaver/), [ired.team screensaver](https://www.ired.team/offensive-security/persistence/t1180-screensaver-hijack) |

---

### 28. Change Default File Association

| Field | Value |
|-------|-------|
| **Location** | `HKEY_CLASSES_ROOT\<ProgID>\shell\open\command` value `(Default)` (effective merge of HKLM\SOFTWARE\Classes + HKCU\SOFTWARE\Classes); user-level overrides at `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.<ext>\UserChoice` |
| **Format** | REG_SZ; shell command string with `%1` as the file argument placeholder |
| **Key Fields** | The ProgID pointed to by the file extension, the `shell\open\command` default value, UserChoice\ProgID (user-selected default), UserChoice\Hash (tamper-detection hash) |
| **Forensic Value** | Any file of the associated extension triggers the malicious command when double-clicked, without registry keys that autorun tools typically check. Execution is user-space triggered but persistent across reboots. Used by Kimsuky (HWP), APT41, FIN7, TrickBot. Sysmon Event ID 13 (registry value set) is primary detection signal. |
| **OS Scope** | Windows XP through Windows 11 |
| **Data Scope** | System (HKCR/HKLM) or User (HKCU) |
| **Decoder Approach** | Resolve extension → ProgID → shell\open\command chain; diff HKCU Classes against HKLM Classes; flag command values containing unexpected executables or double-execution patterns (`malware.exe "%1" && legit.exe "%1"`) |
| **MITRE ATT&CK** | T1546.001 |
| **References** | [MITRE T1546.001](https://attack.mitre.org/techniques/T1546/001/), [Jaiminton T1546.001](https://www.jaiminton.com/Mitreatt&ck/T1546-001), [Atomic Red Team T1546.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1546.001/T1546.001.md) |

---

### 29. Logon Scripts (UserInitMprLogonScript)

| Field | Value |
|-------|-------|
| **Location** | `HKCU\Environment` value `UserInitMprLogonScript` |
| **Format** | REG_SZ; path to script or executable |
| **Key Fields** | Value data (path executed by userinit.exe at logon); per-user (no HKLM equivalent); value is not present by default |
| **Forensic Value** | Executed by userinit.exe at logon for the specific user account. Absence of a default value means any non-empty entry is suspicious. Sigma rule "Windows: Logon Scripts UserInitMprLogonScript" detects creation. Per-user scope limits impact but makes it harder to detect via system-wide scans. |
| **OS Scope** | Windows XP through Windows 11 |
| **Data Scope** | User (HKCU only) |
| **Decoder Approach** | Identity; any non-empty value is anomalous (not present by default) |
| **MITRE ATT&CK** | T1037.001 |
| **References** | [MITRE T1037.001](https://attack.mitre.org/techniques/T1037/001/), [Fortinet SIEM rule UserInitMprLogonScript](https://help.fortinet.com/fsiem/Public_Resource_Access/7_1_3/rules/PH_RULE_Logon_Scripts_UserInitMprLogonScript.htm), [SecurityDatasets](https://securitydatasets.com/notebooks/atomic/windows/persistence/SDWIN-201019224718.html) |

---

### 30. Office Application Startup — Office Test Registry Key

| Field | Value |
|-------|-------|
| **Location** | `HKCU\Software\Microsoft\Office test\Special\Perf` and `HKLM\Software\Microsoft\Office test\Special\Perf` |
| **Format** | REG_SZ; full path to a DLL |
| **Key Fields** | Default value — the DLL path; key does not exist by default; affects all Office applications (Word, Excel, PowerPoint, etc.) |
| **Forensic Value** | An undocumented Microsoft testing registry key. When present, the referenced DLL is loaded into every Office application on startup. Used by APT-level attackers for Office-context persistence that survives updates and is invisible to standard Office add-in inventory. Key does not exist in clean installs — any presence is immediately suspicious. |
| **OS Scope** | Windows with Microsoft Office installed (Office 2007+) |
| **Data Scope** | User (HKCU) or System (HKLM) |
| **Decoder Approach** | Identity; presence of the key at all is anomalous |
| **MITRE ATT&CK** | T1137.002 |
| **References** | [MITRE T1137.002](https://attack.mitre.org/techniques/T1137/002/), [Atomic Red Team T1137.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1137.002/T1137.002.md) |

---

### 31. Office Template Macros (Normal.dotm / PERSONAL.XLSB)

| Field | Value |
|-------|-------|
| **Location** | Word: `%APPDATA%\Microsoft\Templates\Normal.dotm`; Excel: `%APPDATA%\Microsoft\Excel\XLSTART\PERSONAL.XLSB`; GlobalDotName registry: `HKCU\Software\Microsoft\Office\<version>\Word\Options` value `GlobalDotName` |
| **Format** | Binary Office document file (dotm/xlsb) with embedded VBA macro module; GlobalDotName is REG_SZ path override |
| **Key Fields** | VBA project AutoOpen/AutoExec/Workbook_Open event handlers; GlobalDotName (specifies alternative template location); Trusted Locations registry key |
| **Forensic Value** | Macros in Normal.dotm execute in every Word session; PERSONAL.XLSB macros execute in every Excel session. GlobalDotName allows pointing to a remote or unusual path for the template. Requires user-level access only. Common delivery vector for initial access tools repurposed for persistence. |
| **OS Scope** | Windows with Microsoft Office (Office 2007+) |
| **Data Scope** | User |
| **Decoder Approach** | Inspect VBA project in template files (using oletools/olevba); check GlobalDotName registry value; check Trusted Locations for unusual paths |
| **MITRE ATT&CK** | T1137.001 |
| **References** | [MITRE T1137.001](https://attack.mitre.org/techniques/T1137/001/), [pentestlab.blog Office startup](https://pentestlab.blog/2019/12/11/persistence-office-application-startup/) |

---

### 32. Office Add-ins (WLL / XLL / XLAM)

| Field | Value |
|-------|-------|
| **Location** | Word startup: `%APPDATA%\Microsoft\Word\STARTUP\*.wll`; Excel XLSTART: `%APPDATA%\Microsoft\Excel\XLSTART\*.xlam`; Excel XLL registry: `HKCU\Software\Microsoft\Office\<version>\Excel\Options` values `OPEN`, `OPEN1`, `OPEN2`, ... |
| **Format** | WLL/XLL: DLL with Office add-in exports; XLAM: Excel macro-enabled workbook; registry OPEN value: `/R <filename.xll>` |
| **Key Fields** | DLL file path, exported function `xlAutoOpen` (for XLL), `xlAutoClose`; OPEN registry values (increment suffix for multiple add-ins) |
| **Forensic Value** | Add-in DLLs/workbooks are loaded on every Office application startup. XLL add-ins can execute arbitrary native code. Used by Lazarus Group (Operation DreamJob) to deliver payloads via Excel XLL files. WLL persistence is well-documented but rarely monitored. |
| **OS Scope** | Windows with Microsoft Office (Office 2007+) |
| **Data Scope** | User |
| **Decoder Approach** | Enumerate STARTUP folder contents; check OPEN/OPENx registry values; inspect XLL/WLL DLL imports and exports |
| **MITRE ATT&CK** | T1137.006 |
| **References** | [MITRE T1137.006](https://attack.mitre.org/techniques/T1137/006/), [Atomic Red Team T1137.006](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1137.006/T1137.006.md) |

---

### 33. Outlook Home Page (T1137.004)

| Field | Value |
|-------|-------|
| **Location** | `HKCU\Software\Microsoft\Office\<version>\Outlook\WebView\<FolderName>\` value `URL` |
| **Format** | REG_SZ; URL (http/https/file path) to an HTML page |
| **Key Fields** | URL value (local HTML file path or remote URL), FolderName (e.g., Inbox, Calendar) |
| **Forensic Value** | The HTML page at the URL is rendered every time the Outlook folder is opened. Can contain embedded JavaScript or ActiveX that executes code. Malicious home pages survive mailbox migrations and roaming profiles. Used in real-world phishing + persistence chains. Patched in newer Outlook but still functional in older deployments. |
| **OS Scope** | Windows with Outlook (Office 2007 through 2019; patched by MS23-023 in newer builds) |
| **Data Scope** | User (HKCU) |
| **Decoder Approach** | Identity; any non-Microsoft or non-empty URL is suspicious; check for file:// URLs pointing to local scripts |
| **MITRE ATT&CK** | T1137.004 |
| **References** | [MITRE T1137.004](https://attack.mitre.org/techniques/T1137/004/), [Atomic Red Team T1137.004](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1137.004/T1137.004.md) |

---

### 34. PowerShell Profile Persistence

| Field | Value |
|-------|-------|
| **Location** | `%HOMEPATH%\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1` (CurrentUser/CurrentHost); `%HOMEPATH%\Documents\WindowsPowerShell\profile.ps1` (CurrentUser/AllHosts); `%SystemRoot%\System32\WindowsPowerShell\v1.0\Microsoft.PowerShell_profile.ps1` (AllUsers) |
| **Format** | Plain text PowerShell script |
| **Key Fields** | File contents (arbitrary PowerShell executed on every shell start); profile loading order (AllUsers→CurrentUser→AllHosts→CurrentHost) |
| **Forensic Value** | PowerShell profiles execute on every PowerShell invocation — including logon scripts, administrative tools, remoting sessions. Attacker payload embedded here is invisible to registry-focused scanners. Triggered by both interactive and non-interactive PowerShell sessions depending on profile scope. |
| **OS Scope** | Windows with PowerShell (Windows 7+, all versions with PowerShell 2.0+) |
| **Data Scope** | User or System depending on profile path |
| **Decoder Approach** | Read profile files; flag non-empty profiles; check `$PROFILE` variable paths; diff against known-good baseline |
| **MITRE ATT&CK** | T1546.013 |
| **References** | [MITRE T1546.013](https://attack.mitre.org/techniques/T1546/013/), [amr-git persistence](https://amr-git-dot.github.io/offensive/persistence/) |

---

## Filesystem-Based Persistence

### 35. Scheduled Task XML Files

| Field | Value |
|-------|-------|
| **Location** | `C:\Windows\System32\Tasks\` (system tasks) and `C:\Windows\SysWOW64\Tasks\` (32-bit tasks); user tasks: `C:\Users\<username>\AppData\Local\Microsoft\Windows\Tasks\` |
| **Format** | XML (Task Scheduler XML schema v1.1/1.3); key elements: `<Actions>` (Exec/ComHandler), `<Triggers>`, `<Principals>` |
| **Key Fields** | `<Actions><Exec><Command>` (payload path), `<Triggers>` (time/event/logon/boot/idle), `<Principals><Principal><RunLevel>` (HighestAvailable=elevated), `<UserId>` (account context), `<LogonType>`, hidden flag via absent SD in registry |
| **Forensic Value** | XML files are the human-readable complement to the binary registry cache. Critical for recovering task details when registry entries are tampered. GhostTask/Tarrask attackers may delete XML files while task continues executing until next reboot. Sysmon EID 11 (file create) captures new task XML creation. |
| **OS Scope** | Windows Vista through Windows 11 |
| **Data Scope** | System or User |
| **Decoder Approach** | XML parse; extract Command, Arguments, Triggers, Principal; cross-reference with registry TaskCache; flag tasks with no corresponding XML (or no corresponding registry entry) |
| **MITRE ATT&CK** | T1053.005 |
| **References** | [MITRE T1053.005](https://attack.mitre.org/techniques/T1053/005/), [Diverto forensic analysis](https://diverto.hr/en/blog/2024-04-09-forensic-analysis-mitre-attack-3/), [SecurityBlueTeam](https://www.securityblue.team/blog/posts/persistence-mechanisms-windows-scheduled-tasks) |

---

### 36. WMI MOF Subscriptions (Filesystem)

| Field | Value |
|-------|-------|
| **Location** | `C:\Windows\System32\wbem\Repository\OBJECTS.DATA` (WMI database); `C:\Windows\System32\wbem\AutoRecover\` (MOF auto-recovery directory) |
| **Format** | OBJECTS.DATA: proprietary binary CIM database (B-tree structure); AutoRecover: compiled .mof text files |
| **Key Fields** | `__EventFilter` (WQL trigger query), `__EventConsumer` (CommandLineEventConsumer or ActiveScriptEventConsumer), `__FilterToConsumerBinding`; within CommandLineEventConsumer: ExecutablePath, CommandLineTemplate, WorkingDirectory, RunInteractively |
| **Forensic Value** | OBJECTS.DATA persists WMI subscriptions across reboots and survives log clearing. PyWMIPersistenceFinder.py can extract subscriptions from offline images. AutoRecover MOF paths outside `%SystemRoot%\System32\wbem` are red flags. The repository is a dedicated forensic artifact not covered by most autorun tools. |
| **OS Scope** | Windows XP through Windows 11 |
| **Data Scope** | System |
| **Decoder Approach** | Parse OBJECTS.DATA with PyWMIPersistenceFinder, Kansa WMI modules, or live WMI query `Get-WMIObject -Namespace root\subscription -Class __EventFilter`; cross-reference Autorecover MOF registry value |
| **MITRE ATT&CK** | T1546.003 |
| **References** | [MITRE T1546.003](https://attack.mitre.org/techniques/T1546/003/), [SANS finding evil WMI](https://www.sans.org/blog/finding-evil-wmi-event-consumers-with-disk-forensics/), [Elastic WMI subscription](https://www.elastic.co/guide/en/security/8.19/persistence-via-wmi-event-subscription.html) |

---

### 37. Startup Folders

| Field | Value |
|-------|-------|
| **Location** | System (All Users): `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\`; Current User: `C:\Users\<username>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\`; paths also stored in `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders` value `Common Startup` and `HKCU\...\Shell Folders` value `Startup` |
| **Format** | Files: .exe, .bat, .cmd, .lnk, .vbs, .ps1, .js (any executable or shortcut); LNK shortcuts parsed for target path and arguments |
| **Key Fields** | File name, file type, LNK target path (if shortcut), LNK arguments, file creation/modification timestamps, digital signature |
| **Forensic Value** | Files dropped here execute on every user logon (user startup) or any user logon (all-users startup). Simple, well-known, and high-detection but still heavily used by commodity malware. Sysinternals Autoruns is the canonical enumeration tool. Sysmon EID 1 captures resulting process creation. |
| **OS Scope** | Windows 95 through Windows 11 |
| **Data Scope** | System (ProgramData) or User (AppData\Roaming) |
| **Decoder Approach** | Enumerate directory; parse LNK files for target and arguments; verify digital signatures; check creation timestamps against incident timeline |
| **MITRE ATT&CK** | T1547.001 |
| **References** | [MITRE T1547.001](https://attack.mitre.org/techniques/T1547/001/), [Picus T1547](https://www.picussecurity.com/resource/blog/t1547-boot-or-logon-autostart-execution) |

---

### 38. BITS Jobs (Background Intelligent Transfer Service)

| Field | Value |
|-------|-------|
| **Location** | `C:\ProgramData\Microsoft\Network\Downloader\qmgr.dat` (Windows 10: ESE database); `C:\Windows\System32\Winevt\Logs\Microsoft-Windows-Bits-Client%4Operational.evtx`; temp files: `%TEMP%\BITSXXXX.tmp` during transfer |
| **Format** | qmgr.dat: ESE (Extensible Storage Engine) database; Event log: EVTX; temp files: named `BITSXXXX.tmp` before rename |
| **Key Fields** | Job name, Job ID (GUID), RemoteURL (source), LocalName (destination), NotifyCmdLine (executed on completion), TransferType, State, ErrorCount |
| **Forensic Value** | BITS jobs are self-contained in qmgr.dat — no registry or startup folder entries needed. The `NotifyCmdLine` field executes an arbitrary command on job completion or error (including after reboot). Default 90-day lifetime (extendable). Runs under BITS service (LocalSystem). Used by APT29 (Cozy Bear) and Sandworm. Invisible to autorun scanners. |
| **OS Scope** | Windows XP through Windows 11 |
| **Data Scope** | System |
| **Decoder Approach** | ESE database parse for active jobs; enumerate via `bitsadmin /list /allusers /verbose`; PowerShell `Get-BitsTransfer -AllUsers`; inspect NotifyCmdLine for unusual commands |
| **MITRE ATT&CK** | T1197 |
| **References** | [MITRE T1197](https://attack.mitre.org/techniques/T1197/), [cyberforensicator BITS forensics](https://cyberforensicator.com/2019/05/12/using-mitre-attck-for-forensics-bits-jobs-t1197/), [Atomic Red Team T1197](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1197/T1197.md) |

---

### 39. DLL Side-Loading / DLL Search Order Hijacking

| Field | Value |
|-------|-------|
| **Location** | Application directory of a legitimate signed binary (e.g., `C:\Program Files\<vendor>\`); also WinSxS-adjacent directories (`C:\Windows\WinSxS\` exploitation via current-directory hijack) |
| **Format** | Malicious DLL file placed with the exact name of an expected but missing DLL; optionally a proxy DLL that forwards to the legitimate one |
| **Key Fields** | DLL name (matches missing import), DLL file creation timestamp, application that loads it (signed/trusted binary), exports (proxy vs. malicious-only), digital signature absence |
| **Forensic Value** | Malicious code executes within the address space of a legitimate signed binary — defeating process-based allowlisting. No registry modification required. WinSxS variant exploits trusted Windows binaries (e.g., ngentask.exe, aspnet_wp.exe) to load attacker DLL from current directory. Used by APT3, APT10, Lazarus, and many others. `NAME NOT FOUND` results in Procmon are the primary hunting signal. |
| **OS Scope** | Windows XP through Windows 11 |
| **Data Scope** | System or User (depends on application directory permissions) |
| **Decoder Approach** | Process Monitor filter for `NAME NOT FOUND` on DLL loads from writable directories; file system monitoring on application directories; compare loaded DLL paths against expected system paths |
| **MITRE ATT&CK** | T1574.001 (DLL Search Order Hijacking), T1574.002 (DLL Side-Loading) |
| **References** | [MITRE T1574.001](https://attack.mitre.org/techniques/T1574/001/), [MITRE T1574.002](https://attack.mitre.org/techniques/T1574/002/), [wietzebeukema hijacking DLLs](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows), [SecurityJoes WinSxS](https://www.securityjoes.com/post/hide-and-seek-in-windows-closet-unmasking-the-winsxs-hijacking-hideout) |

---

### 40. NTFS Alternate Data Streams (ADS) as Forensic Marker

| Field | Value |
|-------|-------|
| **Location** | Any NTFS file; format: `<filename>:<stream_name>` (e.g., `malware.exe:payload`, `C:\legitimate.txt:evil.js`); `Zone.Identifier` stream is the canonical download-origin marker |
| **Format** | NTFS stream data — arbitrary binary; Zone.Identifier is INI-format text with `[ZoneTransfer]` section, `ZoneId` (3=Internet), `HostUrl`, `ReferrerUrl` |
| **Key Fields** | Stream name, stream size (hidden from `dir` without `/r`), Zone.Identifier ZoneId value, HostUrl (origin of download), ReferrerUrl |
| **Forensic Value** | ADS can hide executables, scripts, and configuration data invisible to standard directory listings and many forensic tools. Attackers can embed payloads in ADS and execute via `wscript <file.txt:script.js>` or `powershell -Command "Get-Content -Path C:\file.txt -Stream evil.ps1 | Invoke-Expression"`. Zone.Identifier absence (stripped ADS) indicates potential cleanup or local origin. ADS presence on system files is a strong IOC. |
| **OS Scope** | Windows NT through Windows 11 (NTFS volumes only) |
| **Data Scope** | Any NTFS file/directory |
| **Decoder Approach** | `dir /r` or `Get-Item -Stream *`; Sysinternals Streams.exe; forensic tools (X-Ways, Autopsy) enumerate all streams; compare $DATA stream count against expected baseline |
| **MITRE ATT&CK** | T1564.004 (Hide Artifacts: NTFS File Attributes) |
| **References** | [MITRE T1564.004](https://attack.mitre.org/techniques/T1564/004/), [amr-git persistence](https://amr-git-dot.github.io/offensive/persistence/) |

---

### 41. Pre-OS Boot: UEFI / Bootkit

| Field | Value |
|-------|-------|
| **Location** | MBR (sector 0, 512 bytes) on BIOS systems; EFI System Partition (ESP, FAT32, typically `/EFI/Boot/bootx64.efi` or `\EFI\Microsoft\Boot\bootmgfw.efi`) on UEFI systems; UEFI firmware flash (non-volatile storage); `%SystemRoot%\Wpbbin.exe` (UEFI firmware persistence indicator on some systems) |
| **Format** | Binary; x86 boot code for MBR; UEFI PE/COFF for ESP; firmware-specific binary for flash |
| **Key Fields** | MBR signature (0x55AA at bytes 510-511), boot code bytes 0-445, partition table (bytes 446-509); ESP: boot file paths, modification timestamps; Secure Boot bypass CVE references (e.g., CVE-2022-21894 BlackLotus) |
| **Forensic Value** | Bootkit code executes before the OS, before any security software, and before Windows integrity checks. Survives OS reinstallation (MBR/firmware level) and hard drive replacement (firmware level). Secure Boot can be bypassed via signed bootloader vulnerabilities. Detection requires comparison against known-good MBR/ESP images or CHIPSEC analysis. |
| **OS Scope** | All Windows versions (MBR); Windows 8+ (UEFI Secure Boot context) |
| **Data Scope** | Pre-OS / Firmware |
| **Decoder Approach** | Raw sector comparison (dd/X-Ways); CHIPSEC platform security assessment; Volatility for in-memory boot artifact analysis; check for Wpbbin.exe in %SystemRoot% |
| **MITRE ATT&CK** | T1542.003 (Bootkit), T1542.001 (System Firmware) |
| **References** | [MITRE T1542.003](https://attack.mitre.org/techniques/T1542/003/), [MITRE T1542.001](https://attack.mitre.org/techniques/T1542/001/), [UEFI memory forensics arxiv](https://arxiv.org/html/2501.16962v1) |

---

## Summary: MITRE ATT&CK Coverage

| MITRE ID | Technique Name | Artifacts in This Catalog |
|----------|----------------|--------------------------|
| T1037.001 | Logon Script (Windows) | #29 Logon Scripts |
| T1053.005 | Scheduled Task | #24 TaskCache Registry, #35 XML Files |
| T1137.001 | Office Template Macros | #31 Normal.dotm / PERSONAL.XLSB |
| T1137.002 | Office Test Registry | #30 Office Test Key |
| T1137.004 | Outlook Home Page | #33 Outlook WebView |
| T1137.006 | Office Add-ins | #32 WLL/XLL/XLAM |
| T1176 | Browser Extensions | #25 BHOs |
| T1197 | BITS Jobs | #38 BITS Jobs |
| T1543.003 | Windows Service | #6 Services |
| T1546.001 | Change Default File Association | #28 File Association |
| T1546.002 | Screensaver | #27 Screensaver |
| T1546.003 | WMI Event Subscription | #23 WMI Registry, #36 WMI Filesystem |
| T1546.007 | Netsh Helper DLL | #16 Netsh |
| T1546.008 | Accessibility Features | #21 IFEO/utilman/sethc |
| T1546.009 | AppCert DLLs | #8 AppCert |
| T1546.010 | AppInit DLLs | #9 AppInit |
| T1546.011 | Application Shimming | #22 SDB Shim |
| T1546.012 | IFEO Injection | #21 IFEO / SilentProcessExit |
| T1546.013 | PowerShell Profile | #34 PS Profile |
| T1546.015 | COM Hijacking | #20 HKCU COM, #25 BHO |
| T1547.001 | Registry Run Keys / Startup Folder | #1 Run Keys, #37 Startup Folders |
| T1547.002 | Authentication Package | #10 LSA Auth Packages |
| T1547.003 | Time Providers | #15 W32Time DLLs |
| T1547.004 | Winlogon Helper DLL | #2 Winlogon Shell, #3 Winlogon Userinit, #4 Winlogon Notify |
| T1547.005 | Security Support Provider | #11 LSA Security Packages |
| T1547.008 | LSASS Driver | #12 LsaDbExtPt |
| T1547.010 | Port Monitors | #13 Port Monitors |
| T1547.012 | Print Processors | #14 Print Processors |
| T1547.014 | Active Setup | #7 Active Setup |
| T1556.002 | Password Filter DLL | #26 Notification Packages |
| T1556.008 | Network Provider DLL | #18 Network Provider |
| T1542.001 | System Firmware | #41 UEFI |
| T1542.003 | Bootkit | #41 UEFI Bootkit |
| T1564.004 | NTFS File Attributes (ADS) | #40 ADS |
| T1574.001 | DLL Search Order Hijacking | #17 Winsock LSP, #39 DLL Hijacking |
| T1574.002 | DLL Side-Loading | #39 DLL Side-Loading |

---

## Key Detection Tools

| Tool | Primary Use |
|------|-------------|
| **Sysinternals Autoruns** | Enumerate all autostart locations (Run keys, services, BHOs, scheduled tasks, LSA packages, AppInit, etc.) |
| **PersistenceSniper** | PowerShell module — `Find-AllPersistence` covers 60+ techniques with ATT&CK classification |
| **Sysmon** | Event IDs 1 (process), 11 (file create), 12/13/14 (registry), 19/20/21 (WMI subscription) |
| **PyWMIPersistenceFinder** | Parse OBJECTS.DATA offline for WMI subscriptions |
| **Volatility 3** | Memory forensics — shimcache, shellbags, malfind, dlllist for in-memory artifacts |
| **RegRipper** | Plugin-based registry artifact extraction including Run keys, services, AppInit, Winlogon |
| **KAPE** | Artifact collection targeting all persistence locations for triage |
| **Process Monitor** | Real-time DLL load monitoring (filter: NAME NOT FOUND) for search order hijacking |
| **bitsadmin / Get-BitsTransfer** | Enumerate active and completed BITS jobs |
| **CHIPSEC** | UEFI / firmware integrity validation for bootkit detection |

---

## Primary References

- [MITRE ATT&CK Persistence Tactic TA0003](https://attack.mitre.org/tactics/TA0003/)
- [PersistenceSniper — last-byte/PersistenceSniper](https://github.com/last-byte/PersistenceSniper)
- [PersistenceSniper Detection Wiki](https://github.com/last-byte/PersistenceSniper/wiki/3-%E2%80%90-Detections)
- [PayloadsAllTheThings Windows Persistence](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Persistence.md)
- [ired.team Offensive Security Persistence](https://www.ired.team/offensive-security/persistence)
- [Atomic Red Team — redcanaryco](https://github.com/redcanaryco/atomic-red-team)
- [Psmths Windows Forensic Artifacts](https://github.com/Psmths/windows-forensic-artifacts)
- [pentestlab.blog Persistence Category](https://pentestlab.blog/category/persistence/)
- [hadess.io — The Art of Windows Persistence](https://hadess.io/the-art-of-windows-persistence/)
- [SANS Blog — Finding Evil WMI Event Consumers](https://www.sans.org/blog/finding-evil-wmi-event-consumers-with-disk-forensics/)
- [Picus Security ATT&CK Technique Explanations](https://www.picussecurity.com/resource/blog/)
- [Elastic Security Prebuilt Rules](https://www.elastic.co/guide/en/security/current/prebuilt-rules.html)
- [Microsoft Learn — Authentication Registry Keys](https://learn.microsoft.com/en-us/windows/win32/secauthn/authentication-registry-keys)
- [GhostTask — netero1010](https://github.com/netero1010/GhostTask)
- [Karneades Awesome Malware Persistence](https://github.com/Karneades/awesome-malware-persistence)
