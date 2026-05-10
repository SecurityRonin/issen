# PyrsistenceSniper Persistence Detection Research

**Source**: https://github.com/hexastrike/PyrsistenceSniper
**Version**: v0.7.1 (2026-03-22)
**License**: MIT
**Purpose**: Offline Windows persistence detection for forensic images

## Overview

PyrsistenceSniper is a Python-based offline Windows persistence scanner that parses KAPE dumps, Velociraptor collections, or mounted disk images. It uses libregf for native registry hive parsing and runs on Windows, Linux, and macOS. 117 persistence checks across 9 MITRE ATT&CK techniques.

---

## 1. Complete Persistence Mechanisms Detected (117 Checks)

### T1037 - Boot/Logon Initialization Scripts (2 checks)

| Check ID | Technique | Description |
|----------|-----------|-------------|
| `gp_scripts` | Group Policy Scripts | GPO startup/shutdown/logon/logoff scripts |
| `logon_scripts` | Logon Scripts (UserInitMprLogonScript) | Script run at user logon before desktop loads |

### T1053 - Scheduled Task/Job (2 checks)

| Check ID | Technique | Description |
|----------|-----------|-------------|
| `ghost_task` | Ghost Scheduled Task | Registry entry in TaskCache\Tree with NO corresponding XML file - invisible to schtasks.exe and Task Scheduler UI |
| `scheduled_task_files` | Scheduled Task (XML Files) | Extracts all Exec actions from XML files under System32\Tasks |

### T1098 - Account Manipulation (2 checks)

| Check ID | Technique | Description |
|----------|-----------|-------------|
| `rid_hijacking` | RID Hijacking | Modified RID values in SAM hive user accounts |
| `rid_suborner` | RID Suborner | RID suborner attack detection in SAM |

### T1137 - Office Application Startup (7 checks)

| Check ID | Technique | Description |
|----------|-----------|-------------|
| `office_addins` | Office Add-ins | Registry-registered Office add-in DLLs |
| `office_ai_hijack` | Office AI Hijack | Office AI feature hijacking |
| `office_dll_override` | Office DLL Override | Overridden Office DLL paths |
| `office_templates` | Office Templates | Custom template paths (Normal.dotm, etc.) |
| `office_test_dll` | Office Test DLL | Office test DLL injection via registry |
| `outlook_home_page` | Outlook Home Page | Outlook folder home page URL persistence |
| `vba_monitors` | VBA Monitors | VBA monitor DLL persistence |

### T1543 - Create or Modify System Process (3 checks)

| Check ID | Technique | Description |
|----------|-----------|-------------|
| `service_failure_command` | Service Failure Command | FailureCommand values in service configurations |
| `windows_service_dll` | Windows Service (ServiceDll) | svchost-hosted service DLL values |
| `windows_service_image_path` | Windows Service (ImagePath) | Service executable paths |

### T1546 - Event Triggered Execution (36 checks)

| Check ID | Technique | Description |
|----------|-----------|-------------|
| `accessibility_tools` | Accessibility Features Backdoor | sethc.exe, osk.exe, utilman.exe, etc. replaced with cmd/powershell (hash comparison) |
| `ae_debug` | AeDebug Debugger | Post-mortem debugger registration |
| `ae_debug_protected` | AeDebug Protected Mode | Protected AeDebug configuration |
| `amsi_providers` | AMSI Providers | Anti-Malware Scan Interface provider DLLs |
| `app_paths` | App Paths | Application path registry hijacking |
| `appcert_dlls` | AppCertDLLs | DLLs loaded into every CreateProcess call |
| `appinit_dlls` | AppInit_DLLs | DLLs loaded into every GUI process |
| `assistive_technology` | Assistive Technology | Assistive technology DLL registration |
| `cmd_autorun` | Command Processor AutoRun | cmd.exe auto-run command |
| `com_treat_as` | COM TreatAs | CLSID TreatAs redirection |
| `disk_cleanup_handler` | Disk Cleanup Handler | Disk cleanup handler DLLs |
| `dotnet_dbg_managed_debugger` | .NET DbgManagedDebugger | .NET managed debugger registration |
| `error_handler_cmd` | Error Handler Command | Error handler command execution |
| `explorer_clsid_hijack` | Explorer CLSID Hijack | Explorer shell CLSID hijacking |
| `file_association_hijack` | File Association Hijack | Default file handler replacement |
| `ifeo_debugger` | IFEO Debugger | Image File Execution Options Debugger value |
| `ifeo_delegated_ntdll` | IFEO Delegated NTDLL | IFEO delegated NTDLL injection |
| `ifeo_silent_process_exit` | Silent Process Exit Monitor | MonitorProcess invoked on target process termination |
| `lsm_debugger` | LSM Debugger | Local Session Manager debugger |
| `netsh_helper` | Netsh Helper DLL | Netsh helper DLLs loaded on netsh execution |
| `power_automate` | Power Automate | Power Automate persistence mechanism |
| `powershell_profiles` | PowerShell Profiles | PowerShell profile script existence |
| `protocol_handler_hijack` | Protocol Handler Hijack | URL protocol handler redirection |
| `recycle_bin_com_extension` | Recycle Bin COM Extension | Recycle bin COM extension hijacking |
| `screensaver` | Screensaver | Screensaver executable path modification |
| `search_protocol_handler` | Search Protocol Handler | Windows Search protocol handler |
| `shared_task_scheduler` | Shared Task Scheduler | Shared task scheduler COM object |
| `shell_execute_hooks` | Shell Execute Hooks | ShellExecuteHooks DLLs |
| `telemetry_controller` | Telemetry Controller | Telemetry controller command |
| `typelib_hijack` | TypeLib Hijack | COM TypeLib path hijacking |
| `wer_debugger` | WER Debugger | Windows Error Reporting debugger |
| `wer_hangs` | WER Hangs | WER hang debugger |
| `wer_reflect_debugger` | WER Reflect Debugger | WER reflect debugger |
| `wer_runtime_exception` | WER Runtime Exception | WER runtime exception handler modules |
| `windows_terminal` | Windows Terminal | Windows Terminal profile persistence |
| `wmi_event_subscription` | WMI Event Subscription | CommandLineEventConsumer and ActiveScriptEventConsumer in CIM repository |

### T1547 - Boot/Logon Autostart Execution (37 checks)

| Check ID | Technique | Description |
|----------|-----------|-------------|
| `active_setup` | Active Setup | StubPath execution on new user logon |
| `authentication_packages` | Authentication Packages | LSA authentication package DLLs |
| `boot_execute` | BootExecute | Session Manager BootExecute programs |
| `boot_verification_program` | Boot Verification Program | Boot verification program path |
| `dsrm_backdoor` | DSRM Backdoor | Directory Services Restore Mode backdoor (DC) |
| `explorer_app_key` | Explorer App Key | Explorer application key registration |
| `explorer_bho` | Browser Helper Objects | IE/Edge Browser Helper Object DLLs |
| `explorer_context_menu` | Explorer Context Menu | Context menu handler DLLs |
| `explorer_load` | Explorer Load | Explorer Load registry value |
| `font_drivers` | Font Drivers | Font driver DLL paths |
| `lsa_cfg_flags` | LSA CfgFlags | LSA configuration flags |
| `lsa_run_as_ppl` | LSA RunAsPPL | LSA Protected Process Light setting |
| `platform_execute` | Platform Execute | Platform execute programs |
| `print_monitors` | Print Monitors | Print monitor DLL paths |
| `print_processors` | Print Processors | Print processor DLL paths |
| `rdp_clx_dll` | RDP CLX DLL | RDP client extension DLL |
| `rdp_virtual_channel` | RDP Virtual Channel | RDP virtual channel DLL |
| `rdp_wds_startup` | RDP WDS Startup | RDP WDS startup programs |
| `run_keys` | Registry Run Keys | Run, RunOnce, RunEx, RunOnceEx (HKLM + HKU, including WoW64 and Policies\Explorer\Run) |
| `run_services` | RunServices | RunServices registry key |
| `run_services_once` | RunServicesOnce | RunServicesOnce registry key |
| `s0_initial_command` | S0 Initial Command | Session 0 initial command |
| `scm_extension` | SCM Extension | Service Control Manager extension DLL |
| `security_packages` | Security Packages | LSA security package DLLs |
| `session_manager_execute` | Session Manager Execute | Session Manager execute value |
| `session_manager_subsystems` | Session Manager Subsystems | Required/Optional subsystem definitions |
| `setup_execute` | Setup Execute | Setup execute programs |
| `shell_folders_startup` | Shell Folders Startup | Redirected startup folder path |
| `shell_launcher` | Shell Launcher | Shell launcher replacement (explorer.exe substitute) |
| `startup_folder` | Startup Folder | Files in per-user and system-wide startup folders |
| `time_providers` | Time Providers | Time provider DLL paths |
| `ts_initial_program` | TS Initial Program | Terminal Services initial program |
| `winlogon_mpnotify` | Winlogon mpnotify | Winlogon mpnotify DLL |
| `winlogon_notify_packages` | Winlogon Notify Packages | Winlogon notification package DLLs |
| `winlogon_shell` | Winlogon Shell | Winlogon Shell value replacement |
| `winlogon_userinit` | Winlogon Userinit | Winlogon Userinit chain |

### T1556 - Modify Authentication Process (2 checks)

| Check ID | Technique | Description |
|----------|-----------|-------------|
| `lsa_password_filter` | LSA Password Filter | Password filter DLLs in SYSTEM\CurrentControlSet\Control\Lsa |
| `network_provider_dll` | Network Provider DLL | Network provider DLL order manipulation |

### T1574 - Hijack Execution Flow (26 checks)

| Check ID | Technique | Description |
|----------|-----------|-------------|
| `appdomain_manager` | AppDomain Manager | .NET AppDomain manager injection via registry |
| `autodial_dll` | Autodial DLL | Winsock autodial DLL path |
| `chm_helper_dll` | CHM Helper DLL | Compiled HTML Help helper DLL |
| `content_index_dll` | Content Index DLL | Windows Search content index DLL |
| `cor_profiler` | COR_PROFILER | CLR profiler injection via environment variable |
| `coreclr_profiler` | CoreCLR Profiler | .NET Core/5+ profiler injection |
| `crypto_expo_offload` | Crypto Exponentiation Offload | Cryptographic exponentiation offload DLL |
| `diagtrack_dll` | DiagTrack DLL | Diagnostic tracking DLL hijack |
| `diagtrack_listener_dll` | DiagTrack Listener DLL | DiagTrack listener DLL hijack |
| `direct3d_dll` | Direct3D DLL | Direct3D DLL path override |
| `dotnet_framework_profiler` | .NET Framework Profiler | .NET Framework profiler via registry |
| `dotnet_startup_hooks` | .NET Startup Hooks | DOTNET_STARTUP_HOOKS environment variable |
| `gp_extension_dlls` | GP Extension DLLs | Group Policy client-side extension DLLs |
| `hhctrl_ocx_dll` | HHCtrl.ocx DLL | HTML Help control DLL |
| `known_dlls` | KnownDLLs | Modifications to KnownDLLs registry entries |
| `known_managed_debugging_dlls` | Known Managed Debugging DLLs | Managed debugging infrastructure DLLs |
| `lsa_extensions` | LSA Extensions | LSA extension DLLs |
| `mapi32_dll_path` | MAPI32 DLL Path | MAPI32 DLL path override |
| `minidump_auxiliary_dlls` | Minidump Auxiliary DLLs | Minidump auxiliary DLL loading |
| `msdtc_xa_dll` | MSDTC XA DLL | Microsoft Distributed Transaction Coordinator DLL |
| `nldp_dll` | NLDP DLL | Natural Language Development Platform DLL |
| `rdp_test_dvc_plugin` | RDP Test DVC Plugin | RDP test dynamic virtual channel plugin |
| `search_indexer_dll` | Search Indexer DLL | Windows Search indexer DLL |
| `server_level_plugin_dll` | Server Level Plugin DLL | Server level plugin DLL path |
| `snmp_extension_agent` | SNMP Extension Agent | SNMP extension agent DLLs |
| `winsock_auto_proxy` | Winsock Auto Proxy | Winsock automatic proxy DLL |
| `wu_service_startup_dll` | WU Service Startup DLL | Windows Update service startup DLL |

---

## 2. Registry Paths/Keys Checked

### Run/Autostart Keys (HKLM + HKU)
```
SOFTWARE\Microsoft\Windows\CurrentVersion\Run
SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
SOFTWARE\Microsoft\Windows\CurrentVersion\RunEx
SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx
SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run
SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce
SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx
SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices
SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce
```

### Winlogon
```
SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell
SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit
SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\mpnotify
SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify
```

### Session Manager (SYSTEM hive)
```
SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute
SYSTEM\CurrentControlSet\Control\Session Manager\Execute
SYSTEM\CurrentControlSet\Control\Session Manager\SubSystems
SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs
```

### Services (SYSTEM hive)
```
SYSTEM\CurrentControlSet\Services\*\ImagePath
SYSTEM\CurrentControlSet\Services\*\Parameters\ServiceDll
SYSTEM\CurrentControlSet\Services\*\FailureCommand
```

### LSA / Security (SYSTEM hive)
```
SYSTEM\CurrentControlSet\Control\Lsa\Authentication Packages
SYSTEM\CurrentControlSet\Control\Lsa\Security Packages
SYSTEM\CurrentControlSet\Control\Lsa\Notification Packages (password filters)
SYSTEM\CurrentControlSet\Control\Lsa\Extensions
SYSTEM\CurrentControlSet\Control\Lsa\CfgFlags
SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL
SYSTEM\CurrentControlSet\Control\NetworkProvider\Order
```

### IFEO
```
SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\*\Debugger
SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\*\MonitorProcess
SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\*\VerifierDlls (delegated NTDLL)
```

### COM / CLSID (SOFTWARE hive)
```
SOFTWARE\Classes\CLSID\*\InprocServer32
SOFTWARE\Classes\CLSID\*\TreatAs
SOFTWARE\Classes\TypeLib\*\*\*\win32 (TypeLib hijacking)
```

### Scheduled Tasks (SOFTWARE hive)
```
SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree
SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks
```

### Active Setup
```
SOFTWARE\Microsoft\Active Setup\Installed Components\*\StubPath
```

### Explorer
```
SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders
SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders
SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects
SOFTWARE\Classes\*\shell\open\command (file associations)
SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks
```

### AppInit / AppCert
```
SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs
SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\LoadAppInit_DLLs
SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs
SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDLLs
```

### Windows Error Reporting
```
SOFTWARE\Microsoft\Windows\Windows Error Reporting\Debugger
SOFTWARE\Microsoft\Windows\Windows Error Reporting\Hangs\Debugger
SOFTWARE\Microsoft\Windows\Windows Error Reporting\ReflectDebugger
SOFTWARE\Microsoft\Windows\Windows Error Reporting\RuntimeExceptionHelperModules
```

### Print Services
```
SYSTEM\CurrentControlSet\Control\Print\Monitors\*\Driver
SYSTEM\CurrentControlSet\Control\Print\Environments\*\Print Processors\*\Driver
```

### .NET / CLR Profiling
```
SOFTWARE\Microsoft\.NETFramework\COR_PROFILER (environment)
SOFTWARE\Microsoft\.NETFramework\DbgManagedDebugger
HKCU\Environment\COR_PROFILER / CORECLR_PROFILER
HKCU\Environment\DOTNET_STARTUP_HOOKS
```

### Miscellaneous DLL Hijacking
```
SYSTEM\CurrentControlSet\Control\ContentIndex\DLLsToRegister
SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\*\DllName
SOFTWARE\Microsoft\Netsh\HelperDLLs
SOFTWARE\Microsoft\MAPI\MSIMapi32DLL
SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\DiagTrack\*
SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ExtensionAgents
```

### Office (SOFTWARE hive, per-user)
```
SOFTWARE\Microsoft\Office\*\*\Addins
SOFTWARE\Microsoft\Office\ClickToRun\REGISTRY\MACHINE\Software\Microsoft\Office\*
Various template and DLL paths per Office application
```

### RDP
```
SYSTEM\CurrentControlSet\Control\Terminal Server\Wds\rdpwd\StartupPrograms
SYSTEM\CurrentControlSet\Control\Terminal Server\*\InitialProgram
SOFTWARE\Microsoft\Terminal Server Client\Default\AddIns (virtual channel DLLs)
```

### Account Manipulation (SAM hive)
```
SAM\SAM\Domains\Account\Users\* (RID values in F binary data)
```

---

## 3. Filesystem Locations Monitored

| Location | Check | Description |
|----------|-------|-------------|
| `ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\` | `startup_folder` | System-wide startup folder |
| `Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\` | `startup_folder` | Per-user startup folders |
| `Windows\System32\Tasks\**` (recursive) | `scheduled_task_files` | Scheduled task XML definitions |
| `Windows\System32\wbem\Repository\OBJECTS.DATA` | `wmi_event_subscription` | WMI CIM repository (binary pattern matching) |
| `Windows\System32\wbem\Repository\FS\OBJECTS.DATA` | `wmi_event_subscription` | Alternate WMI repository location |
| `Windows\System32\sethc.exe` | `accessibility_tools` | Sticky Keys (hash comparison) |
| `Windows\System32\osk.exe` | `accessibility_tools` | On-Screen Keyboard |
| `Windows\System32\Narrator.exe` | `accessibility_tools` | Narrator |
| `Windows\System32\Magnify.exe` | `accessibility_tools` | Magnifier |
| `Windows\System32\utilman.exe` | `accessibility_tools` | Utility Manager |
| `Windows\System32\AtBroker.exe` | `accessibility_tools` | Assistive Technology Broker |
| `Windows\System32\DisplaySwitch.exe` | `accessibility_tools` | Display Switch |
| PowerShell profile directories | `powershell_profiles` | Multiple profile script locations |
| Office template directories | `office_templates` | Normal.dotm and application-specific templates |

---

## 4. Technique Categories (MITRE ATT&CK Mapping)

| MITRE ID | Category | Check Count | Primary Data Source |
|----------|----------|-------------|---------------------|
| T1037 | Boot/Logon Initialization Scripts | 2 | Registry (HKU) |
| T1053 | Scheduled Task/Job | 2 | Registry + Filesystem |
| T1098 | Account Manipulation | 2 | SAM hive |
| T1137 | Office Application Startup | 7 | Registry + Filesystem |
| T1543 | Create or Modify System Process | 3 | SYSTEM hive |
| T1546 | Event Triggered Execution | 36 | Registry + Filesystem + WMI |
| T1547 | Boot/Logon Autostart Execution | 37 | Registry + Filesystem |
| T1556 | Modify Authentication Process | 2 | SYSTEM hive |
| T1574 | Hijack Execution Flow | 26 | Registry |

---

## 5. Data Sources

| Source | Hive/Artifact | What It Provides |
|--------|--------------|------------------|
| Registry: SOFTWARE | `SOFTWARE` hive | Run keys, IFEO, COM CLSIDs, Active Setup, Office, WER, scheduled task cache, .NET |
| Registry: SYSTEM | `SYSTEM` hive | Services, Session Manager, LSA, Print, ContentIndex, Time Providers, SNMP |
| Registry: NTUSER.DAT | Per-user `NTUSER.DAT` | User Run keys, Environment variables, Explorer Load, Office per-user, Shell Folders |
| Registry: SAM | `SAM` hive | RID hijacking, RID suborner |
| Filesystem | Startup folders | Files dropped for autostart |
| Filesystem | System32\Tasks | Scheduled task XML parsing |
| Filesystem | System32 binaries | Accessibility tool binary comparison |
| WMI Repository | OBJECTS.DATA | Binary pattern matching for event subscriptions |
| LOLBin Database | lolbins.json (bundled) | Living-off-the-land binary classification |
| Authenticode | PE binary signatures | Signer validation via LIEF library |

---

## 6. Detection Logic Structure

### Architecture Overview

```
pyrsistencesniper/
  plugins/            # Detection plugins, grouped by MITRE technique ID
    base.py           # PersistencePlugin base class
    T1037/            # Boot/logon scripts (2 plugins)
    T1053/            # Scheduled tasks (2 plugins)
    T1098/            # Account manipulation (2 plugins)
    T1137/            # Office startup (7 plugins)
    T1543/            # Services (3 plugins)
    T1546/            # Event-triggered execution (36 plugins)
    T1547/            # Boot/logon autostart (37 plugins)
    T1556/            # Auth process modification (2 plugins)
    T1574/            # Execution flow hijacking (26 plugins)
  core/
    models.py         # CheckDefinition, RegistryTarget, FilterRule, Finding, HiveScope
    registry.py       # Offline registry parsing via libregf, declarative engine
    pipeline.py       # Discovery, execution, filtering, enrichment pipeline
    context.py        # AnalysisContext with hive paths, user profiles, filesystem
    filesystem.py     # Image root filesystem operations
    profile.py        # YAML detection profile loading
  config/
    default_profile.yaml   # Default allow/block rules
  data/
    lolbins.json      # LOLBin classification database
  enrichment/         # SHA-256, signer, LOLBin, file existence enrichment
```

### Two Detection Modes

**1. Declarative (majority of checks)**:
Plugin defines a `CheckDefinition` with `RegistryTarget` entries. The base class `execute_definition()` engine automatically:
- Iterates targets across HKLM, HKU, or both scopes
- Resolves ControlSet templates (`{controlset}` -> `ControlSet001`)
- Loads registry subtrees via libregf
- Enumerates values (all or filtered)
- Creates Finding objects

Example (logon_scripts):
```python
CheckDefinition(
    id="logon_scripts",
    targets=(
        RegistryTarget(
            path=r"Environment",
            values="UserInitMprLogonScript",
            scope=HiveScope.HKU,
        ),
    ),
)
```

**2. Custom run() override (complex checks)**:
Plugins that need filesystem walking, binary parsing, cross-hive correlation, or hash comparison override `run()`. Examples:
- `scheduled_task_files` - Walks System32\Tasks, parses XML
- `ghost_task` - Cross-references TaskCache registry vs filesystem
- `wmi_event_subscription` - Binary pattern matching on OBJECTS.DATA
- `accessibility_tools` - SHA-256 comparison of system binaries
- `startup_folder` - Resolves paths from registry, then walks folders
- `windows_services` - Enumerates service subkeys, extracts ImagePath/ServiceDll

### FilterRule System

Each check can define `allow` and `block` rules with:
- `value_matches` - Regex against finding value
- `path_matches` - Regex against registry/file path
- `signer` - Authenticode signer name match
- `hash` - Exact SHA-256 match
- `not_lolbin` - Must not be a known LOLBin

Severity assignment:
- **HIGH** - Matches a block rule (known-bad)
- **MEDIUM** - No rule matches (unknown, investigate)
- **LOW** - Partial allow match (some but not all conditions met)
- **INFO** - Full allow match (known-good)

### Finding Model

Each finding contains:
- `path` - Registry key or file path
- `value` - Registry value, command line, or DLL path
- `technique` - Human-readable technique name
- `mitre_id` - MITRE ATT&CK ID
- `access_gained` - USER or SYSTEM
- `severity` - INFO / LOW / MEDIUM / HIGH
- `sha256` - Hash of referenced binary
- `signer` - Authenticode signer
- `is_lolbin` - LOLBin classification
- `exists` - Whether the referenced file exists on disk
- `hostname` - Source hostname
- `check_id` - Plugin identifier
- `references` - MITRE ATT&CK URLs

---

## 7. Integration Opportunities for Issen

### Tier 1: Filesystem-Only (No Registry Parsing Needed)
These can leverage the existing MFT tree and file content capabilities:

| Capability | PyrsistenceSniper Check | Issen Integration |
|------------|------------------------|------------------------|
| Startup folder files | `startup_folder` | Flag files at known startup paths in MFT tree |
| Scheduled task XMLs | `scheduled_task_files` | Detect/parse XML files under System32\Tasks |
| Ghost tasks | `ghost_task` (partial) | Detect XML files presence (registry correlation later) |
| Accessibility backdoors | `accessibility_tools` | Compare hashes of sethc.exe, utilman.exe, etc. |
| WMI subscriptions | `wmi_event_subscription` | Pattern match OBJECTS.DATA binary |
| PowerShell profiles | `powershell_profiles` | Detect profile.ps1 files in known locations |
| Office templates | `office_templates` | Detect suspicious Normal.dotm files |

### Tier 2: Registry Parsing Required
These need offline registry hive parsing (libregf equivalent in Rust: nt-hive2, notatin):

| Priority | Capability | Impact |
|----------|-----------|--------|
| Critical | Run keys (8 paths, HKLM+HKU) | Most common persistence mechanism |
| Critical | Services (ImagePath, ServiceDll) | Very common, high-impact |
| High | IFEO injection (Debugger, SilentProcessExit) | Stealthy, often missed |
| High | Winlogon hijacking (Shell, Userinit) | Classic persistence |
| High | Scheduled task cache (ghost tasks) | Registry side of ghost task detection |
| High | LSA packages (Auth, Security, Password Filters) | Credential theft enabler |
| Medium | COM hijacking (CLSID, TreatAs, TypeLib) | Very stealthy |
| Medium | Active Setup (StubPath) | Common in targeted attacks |
| Medium | AppInit_DLLs / AppCertDLLs | Process-wide injection |
| Medium | Boot/Session Manager programs | Pre-boot persistence |
| Lower | 26 DLL hijacking checks | Niche but comprehensive |
| Lower | Office add-ins/DLL overrides | Application-specific |
| Lower | WER debugger handlers | Rare but stealthy |
| Lower | RID hijacking | Requires SAM hive parsing |

### Architecture Recommendation

The declarative `CheckDefinition` + `RegistryTarget` pattern maps well to a YAML/TOML-based rule engine in Rust. Key design elements to adopt:

1. **Hive scope abstraction** (HKLM/HKU/BOTH) - iterate system and per-user automatically
2. **ControlSet templating** - `{controlset}` expansion for SYSTEM hive paths
3. **Value filtering** - specific value names or `*` for all values
4. **Allow/Block FilterRules** - regex-based known-good/known-bad classification
5. **Severity model** - HIGH/MEDIUM/LOW/INFO based on rule matching
6. **Finding enrichment** - SHA-256, signer, LOLBin, file existence as separate pipeline stage
