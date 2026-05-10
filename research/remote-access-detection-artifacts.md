# Comprehensive Remote Access Infrastructure Detection for Forensic Triage

**Research Date:** 2026-03-23
**Purpose:** Definitive artifact reference for detecting ALL forms of remote access to Windows, macOS, and Linux systems

---

## Table of Contents

1. [Commercial Remote Desktop/Control Tools](#1-commercial-remote-desktopcontrol-tools)
2. [Built-in Remote Access](#2-built-in-remote-access)
3. [VPN & ZTNA](#3-vpn--ztna)
4. [Reverse Connections / Tunneling / C2](#4-reverse-connections--tunneling--c2)
5. [Physical / Hardware Remote Access](#5-physical--hardware-remote-access)
6. [Lateral Movement Indicators](#6-lateral-movement-indicators)
7. [Firewall & Network Configuration](#7-firewall--network-configuration)
8. [Attack Surface Management / OSINT](#8-attack-surface-management--osint)
9. [Cross-Cutting Detection Strategies](#9-cross-cutting-detection-strategies)
10. [Detection Logic Architecture](#10-detection-logic-architecture)

---

## 1. Commercial Remote Desktop/Control Tools

### 1.1 TeamViewer

**Rides on existing login sessions. Requires account association for outgoing connections.**

#### Windows Registry Keys
- `HKLM\SOFTWARE\TeamViewer\*` - Main configuration
- `HKLM\SYSTEM\ControlSet001\Services\TeamViewer\*` - Service registration
- `HKLM\SYSTEM\CurrentControlSet\Services\TeamViewer\*` - Active service config
- `HKU\<SID>\SOFTWARE\TeamViewer\*` - Per-user settings
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\TeamViewer\*` - Uninstall info

#### Registry Keys Modified During Use
- Target side:
  - `HKU\<SID>\SOFTWARE\TeamViewer\MainWindowHandle`
  - `HKU\<SID>\SOFTWARE\TeamViewer\DesktopWallpaperSingleImage`
  - `HKU\<SID>\SOFTWARE\TeamViewer\DesktopWallpaperSingleImagePath`
  - `HKU\<SID>\SOFTWARE\TeamViewer\DesktopWallpaperSingleImagePosition`
  - `HKU\<SID>\SOFTWARE\TeamViewer\MinimizeToTray`
  - `HKU\<SID>\SOFTWARE\TeamViewer\MultiMedia\*`
- Client side:
  - `HKLM\SOFTWARE\TeamViewer\ConnectionHistory`
  - `HKU\<SID>\SOFTWARE\TeamViewer\ClientWindow_Mode`
  - `HKU\<SID>\SOFTWARE\TeamViewer\ClientWindowPositions`

#### File System Artifacts
- `C:\Program Files\TeamViewer\` - Installation directory
- `C:\Program Files\TeamViewer\Connections_incoming.txt` - Incoming connection log (remote hostname, TV ID, connection date)
- `C:\Users\<user>\AppData\Roaming\TeamViewer\Connections.txt` - Outgoing connection history
- `C:\Program Files\TeamViewer\TeamViewer<ver>_Logfile.log` - Detailed operational log (incoming/outgoing connections, machine info, denied connections, local timestamps)
- `C:\Users\<user>\AppData\Local\Temp\TeamViewer\TV15Install.log` - Installation log (user who installed)

#### Event Logs
- `System.evtx` Event ID 7045 - Service creation "TeamViewer"
- `Application.evtx` Event ID 11707 (MsiInstaller) - Installation completed
- `Microsoft-Windows-Shell-Core/Operational` Event ID 28115 - Shortcut added to App Resolver Cache

#### Network Indicators
- `router15.teamviewer.com:443`
- `client.teamviewer.com:443`
- `taf.teamviewer.com:443`
- `*.teamviewer.com` (various subdomains)

#### Determining Installation Date
1. Creation date of `C:\Program Files\TeamViewer`
2. Last modification of `HKLM\SOFTWARE\TeamViewer`
3. `System.evtx` Event ID 7045 showing service creation
4. Last modification of `HKLM\SYSTEM\CurrentControlSet\Services\TeamViewer`

#### Active Use vs Just Installed
- Check `Connections_incoming.txt` for actual connection records
- Check `TeamViewer<ver>_Logfile.log` for session start/end timestamps
- Prefetch for `teamviewer.exe` execution count and timestamps
- UserAssist entries for GUI launches
- `ConnectionHistory` registry key on client side

---

### 1.2 AnyDesk

**Can run as portable (no install required). Single exe for all scenarios. Significant threat actor abuse (ransomware persistence).**

#### Windows Registry Keys
- `HKLM\SOFTWARE\Clients\Media\AnyDesk` - Registration
- `HKLM\SOFTWARE\Classes\.anydesk\shell\open\command` - File association
- `HKLM\SOFTWARE\Classes\AnyDesk\shell\open\command` - Protocol handler
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Print\Printers\AnyDesk Printer\*` - Printer driver
- `HKLM\DRIVERS\DriverDatabase\DeviceIds\USBPRINT\AnyDesk` - Printer driver DB
- `HKLM\DRIVERS\DriverDatabase\DeviceIds\WSDPRINT\AnyDesk` - Printer driver DB
- `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\AnyDesk` - Uninstall
- `HKLM\SYSTEM\ControlSet001\Services\AnyDesk` - Service registration

#### File System Artifacts
- `C:\Program Files (x86)\AnyDesk\` - Default install path (customizable)
- `%PROGRAMDATA%\AnyDesk\connection_trace.txt` - Incoming connection logs (timestamp, auth method, Client ID)
- `%APPDATA%\AnyDesk\ad.trace` - User interface log (remote IP, Client ID, file transfer events)
- `%APPDATA%\AnyDesk\ad_svc.trace` - Service log
- `%APPDATA%\AnyDesk\user.conf` - Configuration (remote participant username)
- `%APPDATA%\AnyDesk\system.conf` - System configuration
- `%APPDATA%\AnyDesk\printer_driver\` - Printer driver setup (identifies installing user)
- `C:\Windows\inf\setupapi.dev.log` - Printer driver installation log

#### Event Logs
- `System.evtx` Event ID 7045 - Service creation "AnyDesk"
- `Microsoft-Windows-Shell-Core/Operational` Event ID 28115 - App Resolver Cache entry (contains UserID of installer)
- `Microsoft-Windows-DeviceSetupManager/Admin.evtx` Event ID 112 - Printer driver setup

#### Network Indicators
- Setup: `boot.net.anydesk.com:443`
- In use: `relay-[a-f0-9]{8}.net.anydesk.com:443` (e.g., `relay-ad3345a7.net.anydesk.com:443`)

#### Portable Mode Detection
- No service installation
- Files in `%APPDATA%\AnyDesk\` still created
- Check for portable executable in Downloads, Desktop, temp directories
- Prefetch entries for `anydesk.exe` from non-standard paths

#### Determining Installation Date
1. Creation date of `C:\Program Files (x86)\AnyDesk`
2. Last modification of `HKLM\SOFTWARE\Clients\Media\AnyDesk`
3. `System.evtx` Event ID 7045
4. Last modification of `HKLM\SYSTEM\CurrentControlSet\Services\AnyDesk`
5. Creation date of `%APPDATA%\AnyDesk` (earliest across users)

#### Active Use vs Just Installed
- `connection_trace.txt` entries with timestamps and auth method
- `ad.trace` log entries showing remote IP and Client ID
- Prefetch execution count
- Network connection to relay servers in DNS cache

---

### 1.3 Splashtop

**Has low-level integration that can bypass Windows login prompts. Often bundled with Atera.**

#### Windows Registry Keys
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Splashtop-Splashtop Streamer-Remote Session/Operational`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Splashtop-Splashtop Streamer-Status/Operational`
- `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Splashtop Software Updater`
- `HKLM\SOFTWARE\WOW6432Node\Splashtop Inc.\*`
- `HKLM\SYSTEM\ControlSet001\Control\SafeBoot\Network\SplashtopRemoteService`
- `HKLM\SYSTEM\ControlSet001\Services\SplashtopRemoteService`
- `HKU\.DEFAULT\Software\Splashtop Inc.\*`
- `HKU\<SID>\Software\Splashtop Inc.\*`

#### File System Artifacts
- `C:\Program Files (x86)\Splashtop\` - Installation directory
- `C:\Program Files (x86)\Splashtop\Splashtop Remote\Server\log\` - Server logs
- `C:\ProgramData\Splashtop\Temp\log\` - Temp logs
- `%PROGRAMDATA%\Splashtop\Temp\log\FTCLog.txt` - **File transfer log** (user account, IP address of client)
- `SPLog.txt` - Connection log (start/end of connections, hostname, user display name, IP of remote host)

#### Event Logs
- `System.evtx` Event ID 7045 - Service creation "SplashtopRemoteService"
- `Splashtop-Splashtop Streamer-Remote Session/Operational` - Remote session creation, file transfer, client hostname
- `Splashtop-Splashtop Streamer-Status/Operational` - Status events

#### Network Indicators
- `*.splashtop.com` (api.splashtop.com, relay.splashtop.com)

---

### 1.4 Atera (RMM Platform + Splashtop)

**SaaS-based RMM. Installs agent + Splashtop. Used by Conti ransomware group.**

#### Windows Registry Keys
- `HKLM\SOFTWARE\Microsoft\Tracing\AteraAgent_RASAPI32`
- `HKLM\SOFTWARE\Microsoft\Tracing\AteraAgent_RASMANCS`
- `HKLM\SOFTWARE\ATERA Networks\*`
- `HKLM\SYSTEM\ControlSet001\Services\EventLog\Application\AlphaAgent`
- `HKLM\SYSTEM\ControlSet001\Services\EventLog\Application\AteraAgent`
- `HKLM\SYSTEM\ControlSet001\Services\AteraAgent`

#### File System Artifacts
- `C:\Program Files\ATERA Networks\AteraAgent\` - Installation directory
- `C:\Program Files (x86)\ATERA Networks\AteraAgent\` - Alternative path
- `C:\Program Files\ATERA Networks\AteraAgent\Packages\AgentPackageRunCommandInteractive\log.txt` - **Remote command execution log** (input/output of commands)
- `C:\Program Files\ATERA Networks\AteraAgent\Packages\*\` - Check all package folders for log.txt

#### Event Logs
- `System.evtx` Event ID 7045 - Service creation "AteraAgent"
- `Application.evtx` Event ID 11707 (MsiInstaller) - Installation completed (includes UserID)
- `Application.evtx` - AlphaAgent and AteraAgent provider entries
- `Security.evtx` Event ID 4688 - Process creation for AgentPackageFileExplorer (file transfer/script execution)

#### Network Indicators
- `pubsub.atera.com`, `pubsub.pubnub.com`
- `agentreporting.atera.com`, `getalphacontrol.com`
- `app.atera.com`, `agenthb.atera.com`
- `packagesstore.blob.core.windows.net`
- `ps.pndsn.com`, `agent-api.atera.com`
- `agentreportingstore.blob.core.windows.net`
- `atera-agent-heartbeat.servicebus.windows.net`
- `ps.atera.com`, `atera.pubnubapi.com`, `appcdn.atera.com`

---

### 1.5 ConnectWise ScreenConnect (formerly ConnectWise Control)

**Widely abused by threat actors. Has anti-forensics capabilities.**

#### File System Artifacts
- `C:\Program Files (x86)\ScreenConnect Client\` - Client installation
- `C:\Program Files\ScreenConnect\App_Data\Session.db` - Session database
- `C:\Program Files\ScreenConnect\App_Data\User.xml` - User configuration
- `C:\ProgramData\ScreenConnect Client*\user.config` - Client config (hostnames, encrypted keys, session metadata)
- `C:\ProgramData\ScreenConnect Client*\system.config` - System config
- Commands are written to `.cmd` or `.ps1` files before execution (carveable)

#### Service
- `ScreenConnect.ClientService.exe` - Background service
- `ScreenConnect.WindowsClient.exe` - Client process (under `C:\Program Files (x86)\ScreenConnect Client`)

#### Event Logs
- `Application.evtx` Event IDs 100, 101 - Remote session activities
- Event ID 4573 - Initial connection attempt
- **Anti-forensics warning:** Attackers can patch out `EventLog.WriteEntry()` call to suppress event generation

#### Network Indicators
- Varies per deployment (self-hosted or cloud)
- Cloud: `*.screenconnect.com`, `*.connectwise.com`

---

### 1.6 BeyondTrust (formerly Bomgar)

#### Detection Indicators
- Display names: "Remote Support Jump Client", "Jumpoint"
- Process names: `bomgar-jpt.exe`, `bomgar-scc.exe`
- Service registration in Windows Services
- Check LOLRMM for full artifact list

---

### 1.7 LogMeIn / GoTo

#### File System Artifacts
- `C:\Users\%user%\AppData\Local\temp\LogMeInLogs\` - Temporary logs
- `C:\ProgramData\LogMeIn\Logs\` - Persistent logs
- Check registry SOFTWARE hive and NTUSER.dat for "recent connections" entries

#### Detection Indicators
- Code signer: "LogMeIn, Inc."
- Process: `LMIIgnition.exe`
- Service registration

---

### 1.8 Google Chrome Remote Desktop (Chromoting)

#### Windows Registry Keys
- `HKLM\Software\Google\Chrome Remote Desktop\paired-clients\clients`
- `HKLM\Software\Google\Chrome Remote Desktop\paired-clients\secrets`

#### File System Artifacts
- `C:\ProgramData\Google\Chrome Remote Desktop\host.json` - Configuration file (stores info for Google host-online alerting)
- Chrome browser cache and history entries (when program is executed)
- `remoting_core.dll`, `remoting_host.exe` - Core binaries

#### Attack Considerations
- Can be installed silently over a Meterpreter session using pre-configured `host.json`
- Attacker can make compromised host assume identity of their test VM
- After uninstall, registry variables and Chrome cache artifacts remain

---

### 1.9 VNC Variants (RealVNC, UltraVNC, TigerVNC, TightVNC)

#### Registry Keys - Password Storage (Weakly Encrypted)
| Variant | Registry/Config Path | Value Name |
|---------|---------------------|------------|
| **RealVNC** | `HKLM\SOFTWARE\RealVNC\vncserver` | `Password` |
| **TightVNC** | `HKCU\Software\TightVNC\Server` | `Password`, `PasswordViewOnly` |
| **TightVNC** | `HKLM\SOFTWARE\TightVNC\Server` | `ControlPassword` |
| **TigerVNC** | `HKLM\SOFTWARE\TigerVNC\WinVNC4` | `Password` |
| **UltraVNC** | `C:\Program Files\UltraVNC\ultravnc.ini` | `passwd`, `passwd2` |

**Note:** All use weak DES-based encryption with static key `e84ad660c4721ae0` and zero IV. Max 8-character passwords.

#### Additional Registry Keys to Monitor
- `HKLM\SOFTWARE\TightVNC`
- `HKLM\SOFTWARE\ORL\WinVNC`
- `HKCU\Software\RealVNC`

#### Process Detection
- `tvnserver.exe` (TightVNC)
- `uvnc_service.exe` (UltraVNC)
- `vncserver.exe` / `winvnc.exe` (generic)

#### Event Logs
- Sysmon Event ID 1 - VNC process creation
- Sysmon Event ID 11 - VNC binary file creation
- `System.evtx` Event ID 7045 - Service creation
- TightVNC logs in Application Event Viewer (includes client IP addresses)

#### Threat Actor Usage (MITRE T1021.005)
- Gamaredon Group: UltraVNC
- FIN7: TightVNC
- GCMAN: VNC for lateral movement
- Fox Kitten: TightVNC on compromised servers

---

### 1.10 RustDesk

**Open-source, cross-platform. Free and increasingly abused by scammers and threat actors.**

#### File System Artifacts
- `C:\Users\%username%\AppData\Local\rustdesk\` - Primary working directory
- `C:\Users\%username%\AppData\Local\rustdesk\rustdesk.exe` - Main binary

#### Detection
- Digital signature: "Open Source Developer, Huabing Zhou"
- Directory creation at `AppData\Local\rustdesk` is key forensic indicator
- Cross-platform: Windows, macOS, Linux

---

### 1.11 MeshCentral / MeshAgent

**Open-source, self-hosted. Difficult to detect by hash due to unique builds.**

#### Windows Registry Keys
- `HKLM\System\CurrentControlSet\Services\Mesh Agent` - Service configuration
- `HKLM\System\CurrentControlSet\Control\SafeBoot\Network\MeshAgent` - Safe Mode network access
- `HKLM\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules\` - Firewall rule for WebRTC
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\MeshUserTask` - Scheduled task

#### File System Artifacts
- `C:\Program Files\Mesh Agent\MeshAgent.exe` - Default install path
- Installation flag: `-fullinstall`

#### Behavioral Indicators
- Creates Windows service, establishes network connection via MeshCentral IP
- Creates pipe communication channel
- Operations executed as `NT AUTHORITY\SYSTEM`
- Uses ports 80 and 443 (bypasses port-based firewalls)
- Unique per-build file hashes (hash-based detection unreliable)

#### Sigma Detection
- Parent process `meshagent.exe` spawning `cmd.exe`, `powershell.exe`, or `pwsh.exe`
- Uses `win-console` and `win-dispatcher` for command execution via IPC

---

### 1.12 DWService

**Browser-based remote access. Used by Scattered Spider for social engineering attacks.**

#### Detection
- Check for DWAgent service/process
- Browser-based access makes endpoint detection harder
- Look for `dwagent` service, installation directories
- Network indicators: `*.dwservice.net`

---

### 1.13 Other Commercial Tools (Detection via LOLRMM)

For **Dameware**, **Parallels Access**, **Zoho Assist**, **RemotePC**, **ISL Online**, **Iperius Remote**, and 250+ other RMM tools, use the LOLRMM project:

- **Website:** https://lolrmm.io
- **GitHub:** https://github.com/magicsword-io/LOLRMM
- **API:** JSON/CSV format for programmatic access
- **Sigma Rules:** `detections/sigma/` directory in the repository
- **Velociraptor Artifact:** `Windows.Detection.RMMs` (checks installed programs + DNS cache against LOLRMM data)

Each LOLRMM entry provides:
- Installation paths
- Registry artifacts
- Process names and code signers
- Network domains
- Sigma detection rules

---

## 2. Built-in Remote Access

### 2.1 Remote Desktop Protocol (RDP)

#### Registry Artifacts

**Server Configuration:**
- `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\fDenyTSConnections` - 0=enabled, 1=disabled
- `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\PortNumber` - Default 3389, check for changes
- `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\UserAuthentication` - NLA setting (1=enabled)
- `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\SecurityLayer` - 0=RDP, 1=Negotiate, 2=TLS
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\TSAppAllowList` - Permitted RemoteApp applications

**Client History (Source Machine):**
- `HKCU\Software\Microsoft\Terminal Server Client\Servers\<hostname>` - Recently connected RDP targets (IP/hostname, UsernameHint)
- `HKCU\Software\Microsoft\Terminal Server Client\Default\MRU*` - MRU list of RDP connections

#### Event Logs

**Destination (Server) Side:**

| Provider | Event ID | Description | Notes |
|----------|----------|-------------|-------|
| Security | 4624 | Successful logon | Type 10 (RemoteInteractive), Type 7 (Reconnect), Type 3 (NLA pre-auth) |
| Security | 4625 | Failed logon | Brute force detection |
| Security | 4634/4647 | Logoff | Session end |
| Security | 4672 | Special privileges assigned | Admin logon |
| TerminalServices-RemoteConnectionManager | 1149 | User authentication succeeded | **Misleading name** - only means login screen was reached, not full auth |
| TerminalServices-RemoteConnectionManager | 261 | Listener received connection | |
| TerminalServices-LocalSessionManager | 21 | Session logon succeeded | |
| TerminalServices-LocalSessionManager | 22 | Shell start | |
| TerminalServices-LocalSessionManager | 23 | Session logoff | |
| TerminalServices-LocalSessionManager | 24 | Session disconnected | |
| TerminalServices-LocalSessionManager | 25 | Session reconnection | |
| TerminalServices-RemoteConnectionManager | 131 | TCP connection accepted from client | Source IP:Port |

**Source (Client) Side:**

| Provider | Event ID | Description |
|----------|----------|-------------|
| TerminalServices-ClientActiveXCore | 1024 | RDP client connection initialized |
| TerminalServices-RDPClient | 1102 | Client connected (destination IP) |

**NLA Complication:**
- NLA causes initial Type 3 (Network) logon before Type 10 (RemoteInteractive)
- Sequence: 4624 Type 3 -> 4624 Type 10
- Reconnecting to existing session: Type 7 (Unlock)
- Console connection (`mstsc /admin`): Type 5

#### File System Artifacts

- **Bitmap Cache:** `%LOCALAPPDATA%\Microsoft\Terminal Server Client\Cache\` - 64x64 pixel tiles of remote screen (reconstructable)
- **Default.rdp:** `%USERPROFILE%\Documents\Default.rdp` - Last RDP session config (target IP, username in plaintext)
- **Jump Lists:** `%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations\` - mstsc.exe connection history
- **Prefetch:** `MSTSC.EXE-*.pf` - Execution evidence
- **ETL Files:** Contain username and remote computer name for connections

#### EVTX File Locations
- `%SystemRoot%\System32\winevt\Logs\Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx`
- `%SystemRoot%\System32\winevt\Logs\Microsoft-Windows-TerminalServices-RDPClient%4Operational.evtx`
- `%SystemRoot%\System32\winevt\Logs\Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx`

#### Shadow Sessions
- `qwinsta` / `query session` - Lists active sessions, IDs, states
- Shadow sessions allow viewing/controlling active user sessions
- Check for `tscon.exe` usage (session hijacking)

#### RDP Port Change Detection
- Check `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\PortNumber`
- Scan for non-standard ports with RDP service
- Check firewall rules for non-3389 inbound allows

#### Device Redirection Artifacts
- `TerminalServices-Printers` logs - Mapped printer names (can reveal attacker's network domain)
- `TerminalServices-DeviceRedirect` logs - Drive/device redirection
- `rdpclip.exe` memory - Clipboard data (passwords, sensitive info)

#### SRUM for RDP Traffic
- `C:\Windows\System32\sru\srudb.dat` - Network data transfer per process
- Large transfers or unusual timing may indicate exfiltration

---

### 2.2 SSH / OpenSSH

#### Windows (OpenSSH Server/Client)

**Server-Side File Artifacts:**
- `C:\ProgramData\ssh\sshd_config` - Server configuration
- `C:\ProgramData\ssh\administrators_authorized_keys` - System-wide authorized keys
- `%USERPROFILE%\.ssh\authorized_keys` - Per-user authorized keys
- `C:\ProgramData\ssh\logs\sshd.log` - Server log (if file logging enabled)
- `C:\Windows\System32\OpenSSH\sshd.exe` - Server binary

**Client-Side File Artifacts:**
- `%USERPROFILE%\.ssh\known_hosts` - Known hosts (Windows does NOT hash by default, unlike Linux)
- `%USERPROFILE%\.ssh\id_*` - Key pairs
- `%USERPROFILE%\.ssh\config` - Client configuration

**Registry:**
- `HKLM\SOFTWARE\Policies\Microsoft\Windows\SSH-Server` - SSH server policy
- `HKLM\System\CurrentControlSet\Services\SSH-Server\Parameters` - Server parameters
- Windows Registry stores ssh-agent private keys (persist across sessions)

**Event Logs:**

| Provider | Event ID | Description |
|----------|----------|-------------|
| OpenSSH (Operational) | Various | Successful public key login, connection events |
| Security | 4648 | sshd.exe RUNAS logon |
| Security | 4624 | Logon (via virtual account `sshd_XXXX`) |
| Security | 4625 | Failed SSH authentication |
| Security | 4672 | Special privileges (impersonation) |
| Security | 4634 | Logoff (both virtual and actual accounts) |

**Key forensic note:** SSH creates temporary virtual user accounts (`sshd_XXXX` in domain `VIRTUAL USERS`), which then impersonate the actual user. Match `authorized_keys` public key values across machines to trace client-server relationships.

#### Linux

**File Artifacts:**
- `/etc/ssh/sshd_config` - Server configuration
- `/etc/ssh/ssh_config` - Client configuration
- `~/.ssh/authorized_keys` - Per-user authorized keys
- `~/.ssh/known_hosts` - Known hosts (often hashed by default)
- `~/.ssh/id_*` - Key pairs
- `/var/log/auth.log` or `/var/log/secure` - Authentication logs
- `/var/log/btmp` - Failed login attempts (`lastb` command)
- `/var/log/wtmp` - Login records (`last` command)
- `/var/log/lastlog` - Last login per user

**Detection:**
- Check `ListenAddress` and `Port` in sshd_config for non-standard ports
- Check `PermitRootLogin`, `PasswordAuthentication`, `PubkeyAuthentication` settings
- Review `authorized_keys` for unauthorized keys
- Check `~/.bash_history`, `~/.zsh_history` for SSH commands

#### macOS

**File Artifacts:**
- `/etc/ssh/sshd_config` - Server configuration
- `~/.ssh/authorized_keys`, `~/.ssh/known_hosts`, `~/.ssh/id_*` - Standard SSH files
- SSH login activity in Unified Logs, Apple System Logs (ASL), and `/var/log/system.log`

**Remote Login (SSH) Status:**
- Check `systemsetup -getremotelogin`
- LaunchDaemon: `/System/Library/LaunchDaemons/ssh.plist`

---

### 2.3 Windows Remote Management (WinRM) / PowerShell Remoting

#### Registry
- `HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell` - Execution policy
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\*` - Persistence via Run keys
- WinRM configuration in `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\*`

#### Event Logs

**Target (Remote) System:**

| Provider | Event ID | Description |
|----------|----------|-------------|
| WinRM/Operational | 169 | User authenticated (includes username, auth mechanism) |
| WinRM/Operational | 91 | Creating WSMan shell on server |
| WinRM/Operational | 81 | Processing client request for CreateShell |
| WinRM/Operational | 82, 134 | Background session actions (timeframe indicator) |
| WinRM/Operational | 142 | Remoting disabled error |
| Security | 4624 | Logon Type 3 (Network) |
| Security | 4672 | Special logon |
| PowerShell | 400 | Engine state changed to Available (HostName=ServerRemoteHost) |
| PowerShell | 403 | Engine state changed to Stopped |
| PowerShell | 600 | Provider started |
| WMI-Activity/Operational | 5857 | Various WMI providers started |
| System | 7040 | WinRM service start type changed to auto |
| System | 10148 | WinRM listening for WS-Management requests |

**Source (Client) System:**

| Provider | Event ID | Description |
|----------|----------|-------------|
| WinRM/Operational | 6 | Creating WSMan Session (includes destination) |

#### File System Artifacts
- `WSMPROVHOST.EXE` in Prefetch - Strong indicator of PSRemoting use
- Two `__PSScriptPolicyTest_<random>.ps1` scripts created for AppLocker testing
- `%APPDATA%\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt` - **NOT populated** by PSRemoting (commands not logged here)

#### Network
- Port 5985 (HTTP) / Port 5986 (HTTPS)
- NTLMSSP authentication in network traffic

#### Enhanced Logging (Group Policy)
- Module Logging: Event ID 4103 (Microsoft-Windows-PowerShell/Operational)
- Script Block Logging: Event ID 4104
- Transcription: Creates transcript files on disk
- Path: `Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell`

#### Key Limitation
Commands are **NOT logged by default** in any EventID or PowerShell history. Enhanced logging must be explicitly enabled.

---

### 2.4 Windows Admin Shares (C$, ADMIN$, IPC$)

#### Detection
- Security Event ID 5145 - Network share access (requires Audit Detailed File Share)
- Monitor access to `\\<host>\ADMIN$`, `\\<host>\C$`, `\\<host>\IPC$`
- Named pipe access: `svcctl` (service control), `atsvc` (scheduled tasks), `ITaskSchedulerService`
- Security Event ID 4624 Type 3 - Network logon

#### Registry
- `HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\AutoShareWks` - Admin share config (workstation)
- `HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\AutoShareServer` - Admin share config (server)

---

### 2.5 macOS Screen Sharing (VNC-based)

#### Configuration Files
- `/System/Library/LaunchDaemons/com.apple.screensharing.plist` - Screen Sharing daemon
- `/Library/Preferences/com.apple.VNCSettings.txt` - VNC password storage
- `/Library/Preferences/com.apple.RemoteManagement.plist` - Remote Management config
- `/Library/Preferences/com.apple.RemoteDesktop.plist` - Remote Desktop config
- `/Library/Preferences/com.apple.ARDAgent.plist` - ARD Agent config

#### Logs
- Unified Logs: `screensharingd: Authentication: SUCCEEDED :: User Name: <user> :: Viewer Address: <IP>`
- `system.log` entries for screen sharing connections

#### Enabling Detection
- Check: `sudo launchctl list | grep screensharing`
- `kickstart` command usage in Unified Logs indicates remote access enablement

---

### 2.6 macOS Apple Remote Desktop (ARD)

#### File System Artifacts
- `/Library/Application Support/Apple/Remote Desktop/RemoteManagement.launchd` - Contains "enabled" when active
- `~/Library/Containers/com.apple.RemoteDesktop/Data/Library/Preferences/com.apple.RemoteDesktop.plist` - Admin app plist
- `/Library/Preferences/com.apple.RemoteManagement.plist` - Client plist
- `/Library/Preferences/com.apple.ARDAgent.plist` - Agent plist
- `/private/var/db/RemoteManagement/caches/` - Client data cache
- `/private/var/db/RemoteManagement/caches/AppUsage.plist` - Application usage per path
- `/private/var/db/RemoteManagement/caches/UserAcct.tmp` - User account data

#### Key Capabilities
- VNC-based remote control
- "Curtain Mode" - hides remote actions from local screen
- File transfer, remote command execution
- ARDvark tool for extracting user activity from RMDB

#### Detection
- `kickstart` command in Unified Logs
- ARD Agent running: `ps aux | grep ARDAgent`
- Check Remote Management status: `sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -checknetwork`

---

### 2.7 Linux X11 Forwarding

#### Detection
- `sshd_config`: Check `X11Forwarding yes`
- `DISPLAY` environment variable set (e.g., `localhost:10.0`)
- `~/.Xauthority` file modifications
- SSH session with `-X` or `-Y` flags in process list or history

---

## 3. VPN & ZTNA

### 3.1 General VPN Detection Strategy

#### Windows Network Indicators
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\*` - Past network connections with timestamps
- Virtual network adapters created by VPN clients (TAP adapters, WireGuard adapters, etc.)
- `HKLM\SYSTEM\CurrentControlSet\Services\*` - VPN service entries
- Amcache/Shimcache - VPN client execution history
- Prefetch - VPN client execution evidence
- UserAssist - GUI-launched VPN clients
- SRUM (`C:\Windows\System32\sru\srudb.dat`) - Network data per VPN process

### 3.2 OpenVPN

#### File System Artifacts
- `%APPDATA%\OpenVPN Connect\profiles\` - VPN profiles (server addresses, config)
- `%APPDATA%\OpenVPN Connect\log\` - Connection logs
- `C:\Program Files\OpenVPN\` - Installation directory
- `C:\Program Files\OpenVPN\config\` - Configuration files (.ovpn)
- `C:\Program Files\OpenVPN\log\` - Log files

#### Linux
- `/etc/openvpn/` - Server/client configurations
- `/var/log/openvpn.log` or syslog entries

#### macOS
- `~/Library/Application Support/OpenVPN Connect/` - Client data

### 3.3 WireGuard

#### Windows
- `C:\Windows\System32\config\systemprofile\AppData\Local\WireGuard\` - Configuration/state
- `HKLM\SYSTEM\CurrentControlSet\Services\WireGuardTunnel$*` - Tunnel services
- Virtual adapter: `wg0`, `wg1`, etc.

#### Linux
- `/etc/wireguard/` - Configuration files (wg0.conf, etc.)
- `wg show` command output
- systemd service: `wg-quick@wg0.service`

#### macOS
- WireGuard app data in `~/Library/Containers/com.wireguard.macos/`

### 3.4 Tailscale

#### Windows
- Registry: `HKLM\Software\Tailscale IPN` - Policy settings and state
- Installation: `C:\Program Files\Tailscale\`
- Logs: `C:\ProgramData\Tailscale\Logs\`
- State: `C:\ProgramData\Tailscale\tailscaled.state`
- Environment: `C:\ProgramData\Tailscale\tailscaled-env.txt`
- Service: "Tailscale" Windows service

#### Linux
- State: `/var/lib/tailscale/*`
- Socket: `/run/tailscale/tailscaled.sock`
- Config: `/etc/default/tailscaled` (FLAGS)
- Service: `tailscaled.service` (systemd)
- Optional: `--encrypt-state` flag for TPM encryption

#### macOS
- LaunchDaemon: `/Library/LaunchDaemons/com.tailscale.tailscaled.plist`
- Logs: Console.app search for "Tailscale" or "IPNExtension"
- System policies in user defaults
- GUI variants: `IPNExtension` (App Store) or `io.tailscale.ipn.macsys.network-extension` (zip)

#### Network
- Creates `tailscale0` virtual interface
- WireGuard-based traffic on UDP (various ports)
- Coordination server: `controlplane.tailscale.com`

### 3.5 ZeroTier

#### Windows
- Working directory: `C:\ProgramData\ZeroTier\One\`
- Service: `ZeroTierOneService` (Automatic start, restart on failure)
- `networks.d\<network-id>.conf` - Joined networks (settings: allowManaged, allowGlobal, allowDefault, allowDNS)
- `identity.secret` - Full identity with private key
- `identity.public` - 10-digit hex address + public key
- `authtoken.secret` - Authentication token

#### Linux
- Working directory: `/var/lib/zerotier-one/`
- `local.conf` - Manual configuration (only if created)
- `identity.secret`, `identity.public`, `authtoken.secret`
- Service: `zerotier-one.service` (systemd)

#### macOS
- Working directory: `/Library/Application Support/ZeroTier/One/`
- Application: `/Applications/ZeroTier.app`
- LaunchDaemon manages the service

#### Network
- Default port: 9993 (UDP)
- Creates `zt*` virtual network interfaces

### 3.6 Cisco AnyConnect / Secure Client

#### Windows
- Installation: `C:\Program Files (x86)\Cisco\Cisco AnyConnect Secure Mobility Client\`
- Logs: `C:\ProgramData\Cisco\Cisco AnyConnect Secure Mobility Client\Logs\`
- Registry: `HKLM\SOFTWARE\Cisco\Cisco AnyConnect Secure Mobility Client\*`
- Profile files: `C:\ProgramData\Cisco\Cisco AnyConnect Secure Mobility Client\Profile\`

#### Forensic Note
- Akira ransomware used AnyConnect VPN as initial access vector
- RADIUS authentication logs on NPS servers are crucial for investigation
- Network-related logs often non-existent on many environments

### 3.7 Palo Alto GlobalProtect

#### Windows
- Installation: `C:\Program Files\Palo Alto Networks\GlobalProtect\`
- Logs: Tech support files contain forensic artifacts
- Portal/Gateway connections logged

#### Forensic Note
- CVE-2024-3400 zero-day exploitation documented by Volexity
- Do NOT wipe/rebuild compromised appliance - collect tech support file and preserve forensic evidence first

### 3.8 Other VPN Clients

| VPN Client | Key Artifact Locations (Windows) |
|------------|----------------------------------|
| **Fortinet FortiClient** | `C:\Program Files\Fortinet\FortiClient\`, registry `HKLM\SOFTWARE\Fortinet\*` |
| **Pulse Secure / Ivanti** | `C:\Program Files (x86)\Pulse Secure\`, `%APPDATA%\Pulse Secure\` |
| **SoftEther VPN** | `C:\Program Files\SoftEther VPN Client\`, `vpn_client.config` |
| **strongSwan** | Linux: `/etc/ipsec.conf`, `/etc/ipsec.secrets`, `/etc/swanctl/` |
| **L2TP/IPsec** | Windows: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Telephony\*`, RAS connection entries |
| **PPTP** | Legacy, check RAS phonebook entries and network adapter configs |
| **Cloudflare WARP** | `C:\ProgramData\Cloudflare\`, service `CloudflareWARP` |
| **Zscaler** | `C:\Program Files (x86)\Zscaler\`, `C:\ProgramData\Zscaler\` |
| **Netskope** | `C:\Program Files (x86)\Netskope\`, Netskope Client service |
| **Twingate** | Look for Twingate service, `%LOCALAPPDATA%\Twingate\` |
| **Pritunl** | `C:\Program Files\Pritunl\`, OpenVPN-based configs |

### 3.9 Microsoft Built-in VPN (RRAS)

#### Registry
- `HKCU\SOFTWARE\Microsoft\RAS EAP\UserEapInfo` - Cached VPN credentials (when "Remember my sign-in info" selected)
- `HKLM\SYSTEM\CurrentControlSet\Services\RasMan\*` - RAS Manager configuration
- RAS phonebook: `%APPDATA%\Microsoft\Network\Connections\Pbk\rasphone.pbk`

---

## 4. Reverse Connections / Tunneling / C2

### 4.1 ngrok

#### Detection
- Process: `ngrok.exe` / `ngrok`
- Config: `%USERPROFILE%\.ngrok2\ngrok.yml` (Windows), `~/.ngrok2/ngrok.yml` (Linux/macOS)
- Default tunnels on `*.ngrok.io` / `*.ngrok-free.app` domains
- DNS queries to `tunnel.us.ngrok.com`, `tunnel.eu.ngrok.com`, etc.
- Creates outbound TCP connections to ngrok edge servers
- Look for in Prefetch, Shimcache, Amcache

### 4.2 Cloudflare Tunnel (cloudflared)

#### Detection
- Process: `cloudflared.exe` / `cloudflared`
- Config: `%USERPROFILE%\.cloudflared\config.yml` (Windows), `~/.cloudflared/config.yml` (Linux)
- Credentials: `%USERPROFILE%\.cloudflared\<tunnel-id>.json`
- Service: Can be installed as Windows service or systemd unit
- DNS queries to `*.trycloudflare.com` (quick tunnels), custom domains
- Outbound connections to Cloudflare edge on HTTPS

### 4.3 Other Tunneling Tools

| Tool | Process | Config/Artifacts | Network Indicators |
|------|---------|-----------------|-------------------|
| **chisel** | `chisel.exe` / `chisel` | Command-line args in Prefetch/process logs | Reverse SOCKS over HTTP/HTTPS |
| **frp** | `frpc.exe`, `frps.exe` | `frpc.ini`/`frpc.toml` config | Custom ports, TLS optional |
| **bore** | `bore` | Command-line args | TCP tunneling |
| **SSH reverse tunnel** | `ssh` / `sshd` | `-R` flag in command history, `~/.ssh/config` | Standard SSH ports or custom |
| **socat** | `socat` | Command-line args | Various protocols |
| **netcat** | `nc`, `ncat` | Command-line args | Raw TCP/UDP |

### 4.4 Cobalt Strike

#### Event Log Indicators
- `System.evtx` Event ID 7045 - Randomly named service creation (then deletion)
- `Security.evtx` Event ID 4624 - Network logon (Type 3)
- `Security.evtx` Event ID 4688 - Process creation (if command-line logging enabled)
- `Security.evtx` Event ID 4697 - Service installation (if audit enabled)

#### Named Pipes (Sysmon Events 17/18)
- Default pipe names used for post-exploitation tool output
- Configurable via malleable C2 profile
- Pattern: `\\.\pipe\MSSE-<4-digit>-server` (default)

#### Process Indicators
- `rundll32.exe` executed without arguments (DLL injection for post-exploitation)
- Process chain: `service.exe -> beacon.exe -> rundll32.exe`
- `cmd.exe` with args `/c echo` and `\pipe\` (getsystem named pipe impersonation)

#### File System
- Randomly named executables in system folders
- Prefetch for beacon binary and `rundll32.exe` in quick succession
- Persistence: Registry Run keys with misleading names (e.g., "Windows Defender")

#### Memory Indicators
- Function pointers and decoded loader stages
- Injected code in spawned processes
- CobaltStrike-specific memory patterns (base64 config, watermark)

#### Network
- Beaconing patterns (periodic C2 check-in)
- RC4 or XOR encrypted traffic
- Malleable C2 profiles can mimic legitimate HTTP/HTTPS traffic
- HTTPS stager: valid URL is 4-char alphanumeric with valid 8-bit checksum

### 4.5 Meterpreter

#### Indicators
- Compatible with Cobalt Strike foreign listeners
- Process injection into legitimate processes
- In-memory execution (minimal disk artifacts)
- Network: Various transports (reverse_tcp, reverse_https, bind_tcp)
- Check for `metsvc` service (persistent Meterpreter)
- Prefetch for `metsrv.dll` loading

### 4.6 Web Shells

#### Detection by Platform

**Windows/IIS:**
- Monitor `w3wp.exe` spawning: `cmd.exe`, `powershell.exe`, `net.exe`, `ping.exe`, `systeminfo.exe`, `hostname.exe`
- Web roots: `%SystemDrive%\inetpub\wwwroot\`, application directories
- Exchange-specific: `MSExchangeOWAAppPool` process spawning `cmd.exe`
- Sysmon Event ID 11 (FileCreate) in web directories
- Sysmon Event ID 1 - Web server process spawning command interpreters

**Linux/Apache/Nginx:**
- Monitor web server processes spawning `/bin/sh`, `/bin/bash`
- Web roots: `/var/www/`, configured DocumentRoot paths
- PHP shells: Look for `eval()`, `assert()`, `base64_decode()`, `gzinflate()`, `system()`, `exec()`, `passthru()`

**File Integrity Monitoring:**
- Monitor for new/modified files with web-executable extensions: `.php`, `.asp`, `.aspx`, `.jsp`, `.jspx`, `.cfm`, `.pl`
- Check timestamps against approved update windows
- Files in upload directories with executable extensions

**Web Log Analysis:**
- Repeated POST requests to single URL from limited IP set
- HTTP 200 responses to URLs not linked from any page
- POST requests to static file paths (images, CSS)
- China Chopper: User-Agent `Mozilla/4.0+(compatible;+MSIE+6.0;+Windows+NT+5.1)`
- Base64-encoded command strings in POST bodies
- Unusual response sizes for expected-static content

**Common Web Shell Families:**
- China Chopper (ASP, ASPX, PHP, JSP)
- Godzilla (ASP.NET, JSP, PHP)
- WSO, C99, B374K, R57

### 4.7 LOLBins for Remote Access

#### Key Binaries to Monitor

| Binary | Abuse Pattern | Detection |
|--------|--------------|-----------|
| `certutil.exe` | `-urlcache -split` download, `-decode` payload reconstruction | Unusual parent process, URL arguments |
| `mshta.exe` | Execute HTA files with embedded scripts | URL arguments, unusual parent (e.g., winword.exe) |
| `bitsadmin.exe` | Background file download/upload, persists across reboots | `/transfer` with external URLs |
| `rundll32.exe` | Execute malicious DLLs | No arguments (Cobalt Strike), temp directory DLLs |
| `regsvr32.exe` | `/s /n /u /i:URL` for script execution | Network URLs in arguments |
| `wmic.exe` | Remote command execution via WMI | `process call create` with remote targets |
| `msiexec.exe` | Remote MSI installation | `/q /i http://` pattern |
| `powershell.exe` | Encoded commands, download cradles | `-enc`, `IEX`, `Invoke-Expression`, `Net.WebClient` |
| `cscript.exe/wscript.exe` | Script execution | Unusual script paths, network activity |

#### Detection Strategy
- Baseline normal LOLBin usage (30-day profile)
- Monitor command-line arguments (Event ID 4688 + Sysmon Event ID 1)
- Parent-child process analysis (unusual parents spawning LOLBins)
- AppLocker/WDAC restrictions on non-essential LOLBins

**Reference:** https://lolbas-project.github.io/
**Linux equivalent:** https://gtfobins.github.io/

### 4.8 RAT (Remote Access Trojan) Common Indicators

- Unexpected outbound connections to unusual ports
- DNS queries to dynamic DNS providers (no-ip.com, dyndns.org, etc.)
- Beaconing patterns (regular interval connections)
- Process injection / hollowing
- Startup persistence (Run keys, scheduled tasks, services)
- Mutex creation for single-instance enforcement
- Encrypted/obfuscated C2 traffic
- Use of legitimate cloud services as C2 (Slack, Discord, Telegram, Dropbox, OneDrive)

### 4.9 Port Forwarding / SOCKS Proxies

#### Detection
- `netsh interface portproxy show all` - Windows port forwarding rules
- `netsh interface portproxy show v4tov4` - IPv4 port forwarding
- `HKLM\SYSTEM\CurrentControlSet\Services\PortProxy\v4tov4\tcp` - Registry persistence
- Check for `ssh -D` (SOCKS proxy), `ssh -L` (local forward), `ssh -R` (remote forward) in process lists
- Linux: Check `iptables -t nat -L` for DNAT/SNAT rules
- Check for `3proxy`, `microsocks`, `ssocks` processes

---

## 5. Physical / Hardware Remote Access

### 5.1 BMC / IPMI / iLO / iDRAC

#### Detection
- Check for BMC network interface (usually separate NIC or shared)
- IPMI port: UDP 623
- HP iLO: HTTPS on dedicated management port (typically 443 on management NIC)
- Dell iDRAC: HTTPS on dedicated management port
- Check BIOS/UEFI settings for BMC configuration
- `ipmitool lan print` (Linux) - BMC network configuration
- Look for iLO/iDRAC virtual media connections in system logs

### 5.2 Intel AMT / vPro

#### Detection
- Intel AMT port: 16992 (HTTP) / 16993 (HTTPS)
- `HKLM\SOFTWARE\Intel\Setup and Configuration Software\*` - AMT configuration
- Check BIOS for AMT enablement
- Intel Management Engine Interface (MEI) driver present
- `C:\Program Files (x86)\Intel\AMT\*` or similar installation paths
- `LMS.exe` (Local Manageability Service) process
- Network scan for port 16992/16993 on local subnet

### 5.3 Secure Boot / Insecure Mode

#### Detection
- Windows: `Confirm-SecureBootUEFI` (PowerShell)
- `msinfo32.exe` -> Secure Boot State
- `HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State\UEFISecureBootEnabled`
- Linux: `mokutil --sb-state`

---

## 6. Lateral Movement Indicators

### 6.1 PsExec / SMB Lateral Movement

#### Event Logs (Target System)

| Provider | Event ID | Description |
|----------|----------|-------------|
| Security | 4624 | Logon Type 3 (Network) |
| Security | 4672 | Special logon (SC_MANAGER_CREATE_SERVICE privilege) |
| Service Control Manager | 7045 | Service installed (service name, executable, account) |
| Service Control Manager | 7036 | Service state changed (running/stopped) |
| Security | 4697 | Service installed (if Audit Security System Extension enabled) |
| Security | 5145 | Share access (if Audit Detailed File Share enabled) - Monitor ADMIN$, C$, IPC$ |

#### Artifacts
- Prefetch for randomly named service executable
- Named pipe access: `svcctl` (service control), `RemCom_communication`
- PSEXESVC.exe (SysInternals) or randomly named .exe (Impacket)
- Service created then deleted pattern

#### PsExec Variants
- SysInternals PsExec: Creates PSEXESVC service
- Impacket smbexec.py: Random service name
- Impacket psexec.py: Random service name + file upload to ADMIN$
- CrackMapExec: Configurable service name

### 6.2 WMI Lateral Movement

#### Event Logs

| Provider | Event ID | Description |
|----------|----------|-------------|
| Security | 4624 | Logon Type 3 (multiple: DCOM, iWbemLevel1Login, SMB) |
| Security | 4672 | Special logon (admin privileges) |
| WMI-Activity/Operational | 5857 | WMI provider started (wmiprvse.exe) |

#### Artifacts
- `WMIPRVSE.EXE` as parent process spawning `CMD.EXE` or `POWERSHELL.EXE`
- Prefetch: CONNHOST.EXE + WMIPRVSE.EXE + CMD.EXE in short timeframe
- USN journal: Temporary output files in `C:\Windows\Temp\` (Impacket wmiexec pattern)
- Network: DCOM/RPC port 135 + dynamic ports

### 6.3 DCOM Lateral Movement

#### Event Logs
- Security 4624/4672 - Logon/Special logon
- Minimal logging by default for successful attacks
- PowerShell events 400, 403, 600 if PowerShell shell used (HostApplication parameter)

#### Artifacts
- Prefetch: MMC.EXE + CONNHOST.EXE + CMD.EXE (MMC technique)
- USN journal: Temporary output files (Impacket dcomexec pattern)
- DCOM Event ID 10016 (warnings) in System log

### 6.4 Scheduled Task Remote Execution

#### Artifacts
- `C:\Windows\System32\Tasks\<task-name>` - XML task definition (created then deleted)
- `C:\Windows\Temp\<task-name>.tmp` - Command output file (Impacket atexec)
- Named pipe access: `atsvc`, `ITaskSchedulerService`
- Security Event ID 4698 - Scheduled task created (if auditing enabled)
- Security Event ID 4702 - Scheduled task updated

### 6.5 Pass-the-Hash / Pass-the-Ticket

#### Indicators
- Security Event ID 4624 with LogonType 9 (NewCredentials) - common for PTH
- Security Event ID 4624 with NTLM authentication from unexpected sources
- Security Event ID 4768 - TGT requested (Kerberos)
- Security Event ID 4769 - TGS requested
- Security Event ID 4771 - Kerberos pre-authentication failed
- Tools: mimikatz, secretsdump, rubeus, impacket
- LSASS memory access indicators

### 6.6 Kerberoasting

#### Indicators
- Security Event ID 4769 - Service ticket requests with RC4 encryption (0x17)
- Anomalous TGS request volume for service accounts
- Service accounts with SPNs and weak passwords
- Tools: Rubeus, GetUserSPNs.py (Impacket)

### 6.7 BloodHound / SharpHound Collection

#### Artifacts
- LDAP query patterns (bulk enumeration)
- SMB session enumeration
- JSON/ZIP output files (bloodhound data)
- Process names: `SharpHound.exe`, `sharphound.ps1`
- Prefetch/Amcache entries for SharpHound

---

## 7. Firewall & Network Configuration

### 7.1 Windows Firewall

#### Artifacts
- **Firewall Log:** `%SystemRoot%\Windows\System32\LogFiles\Firewall\pfirewall.log` (if logging enabled)
- **Historical Log:** `pfirewall.log.old`
- **Rules:** `netsh advfirewall firewall show rule name=all` or PowerShell `Get-NetFirewallRule`
- **Registry:** `HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\*`

#### Key Checks
- Inbound allow rules for non-standard ports
- Rules created by remote access tools (MeshAgent creates WebRTC rules)
- Rules with "any" source address
- Recently modified rules (check timestamps)
- Disabled firewall profiles

### 7.2 Linux Firewalls

#### iptables/nftables
- `iptables -L -n -v` / `iptables-save` - Current rules
- `nft list ruleset` - nftables rules
- `/etc/iptables/rules.v4`, `/etc/iptables/rules.v6` - Persistent rules
- `/etc/nftables.conf` - nftables configuration
- Check for NAT/DNAT/SNAT rules: `iptables -t nat -L -n -v`
- Check for port forwarding in `/proc/sys/net/ipv4/ip_forward`

### 7.3 macOS Firewall (pf)

- `/etc/pf.conf` - Packet filter configuration
- Application Firewall: `socketfilterfw` settings
- `/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate`
- Check for anchor rules that might allow external access

### 7.4 Listening Ports & Services

#### Detection Commands
- Windows: `netstat -ano`, `Get-NetTCPConnection`, `Get-NetUDPEndpoint`
- Linux: `ss -tlnp`, `netstat -tlnp`
- macOS: `lsof -i -P -n`, `netstat -an`
- Cross-platform: Compare listening ports against known service baselines
- Check for services listening on 0.0.0.0 (all interfaces) vs 127.0.0.1 (local only)

---

## 8. Attack Surface Management / OSINT

### 8.1 Passive Reconnaissance Tools

| Tool | Purpose | Key Data |
|------|---------|----------|
| **Shodan** | Internet-connected device scanning | Open ports, services, banners, vulnerabilities |
| **Censys** | Internet asset discovery | TLS certificates, protocols, services, ASM |
| **Criminal IP** | Threat intelligence search | IP reputation, vulnerability scanning |
| **Netlas** | Internet intelligence | DNS, WHOIS, certificates, open ports |
| **SecurityTrails** | DNS/domain intelligence | Historical DNS records, subdomains |
| **VirusTotal** | File/URL/IP reputation | Malware associations, community feedback |
| **Certificate Transparency** | Certificate monitoring | crt.sh for subdomain enumeration |
| **BGPView** | ASN/IP intelligence | BGP routing, IP prefixes, AS paths |
| **ipapi/ipinfo** | IP geolocation | Geographic location, ISP, ASN |

### 8.2 Assessment Checks

| Check | Tool/Method | What It Reveals |
|-------|------------|-----------------|
| **SPF Record** | DNS TXT lookup | Email sending authorization |
| **DMARC Record** | DNS TXT lookup (`_dmarc.domain`) | Email authentication policy |
| **DKIM Record** | DNS TXT lookup (`selector._domainkey.domain`) | Email signing |
| **SSL/TLS Grade** | SSL Labs | Cipher strength, protocol support, certificate validity |
| **WHOIS** | WHOIS lookup | Domain ownership, registration dates, nameservers |
| **Exposed Services** | Shodan/Censys queries | RDP, SSH, VNC, web services exposed to internet |
| **DNS History** | PassiveDNS, SecurityTrails | Historical A/AAAA/CNAME records, infrastructure changes |
| **PhishTank** | PhishTank API | Known phishing URLs targeting the domain |

### 8.3 Key Exposure Checks for Remote Access

- Shodan: `port:3389 org:"Target"` - Exposed RDP
- Shodan: `port:22 org:"Target"` - Exposed SSH
- Shodan: `port:5900 org:"Target"` - Exposed VNC
- Shodan: `port:5985 OR port:5986 org:"Target"` - Exposed WinRM
- Shodan: `port:445 org:"Target"` - Exposed SMB
- Shodan: `"TeamViewer" org:"Target"` - TeamViewer instances
- Censys: Search by certificate subjects/SANs for organizational infrastructure

---

## 9. Cross-Cutting Detection Strategies

### 9.1 Universal Windows Artifacts for Any Remote Tool

| Artifact | Location | What It Proves |
|----------|----------|----------------|
| **Prefetch** | `C:\Windows\Prefetch\` | Execution evidence (first/last run, count) |
| **Amcache** | `C:\Windows\appcompat\Programs\Amcache.hve` | Program execution with file path, hash, timestamp |
| **Shimcache** | `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache` | Program execution evidence |
| **UserAssist** | `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\*` | GUI-launched programs with count/timestamp |
| **SRUM** | `C:\Windows\System32\sru\srudb.dat` | Network data per process, execution duration |
| **Jump Lists** | `%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations\` | Recent program-specific file/connection history |
| **BAM/DAM** | `HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\*` | Program execution with timestamp |
| **Services** | `HKLM\SYSTEM\CurrentControlSet\Services\*` | Installed services (start type, binary path) |
| **Scheduled Tasks** | `C:\Windows\System32\Tasks\` | Scheduled task definitions |
| **Startup** | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\*` and HKCU | Auto-start programs |
| **Installed Programs** | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*` | Software inventory |
| **DNS Cache** | `ipconfig /displaydns` or `Get-DnsClientCache` | Recent DNS queries (remote access domains) |
| **Event Logs** | `%SystemRoot%\System32\winevt\Logs\` | System, Security, Application, and provider-specific logs |

### 9.2 Detection Priority Matrix

**Tier 1 - High Confidence (Definitive proof of remote access):**
- Active services for known remote access tools
- Connection logs with timestamps and remote IPs
- Event log entries (Event ID 4624 Type 10, 7045 service creation)
- Active listening ports for known remote protocols

**Tier 2 - Medium Confidence (Installation/presence evidence):**
- Registry keys for remote access tools
- Installation directories present
- Prefetch/Amcache execution evidence
- Firewall rules allowing inbound connections

**Tier 3 - Contextual (Requires correlation):**
- DNS cache entries for remote access domains
- Network adapter changes (VPN virtual adapters)
- SRUM data showing network activity for remote access processes
- File transfer logs

### 9.3 macOS Universal Detection

| Artifact | Location | Purpose |
|----------|----------|---------|
| **Unified Logs** | `log show` / Console.app | All system activity |
| **ASL Logs** | `/var/log/asl/` | Legacy system logs |
| **Launch Daemons** | `/Library/LaunchDaemons/` | System-level persistent processes |
| **Launch Agents** | `~/Library/LaunchAgents/`, `/Library/LaunchAgents/` | User-level persistent processes |
| **Applications** | `/Applications/`, `~/Applications/` | Installed applications |
| **Preferences** | `/Library/Preferences/`, `~/Library/Preferences/` | Application configuration |
| **Login Items** | `~/Library/Application Support/com.apple.backgroundtaskmanagementagent/` | Auto-start items |
| **TCC Database** | `~/Library/Application Support/com.apple.TCC/TCC.db` | Privacy permissions (screen recording, accessibility) |
| **Aftermath** | Jamf open-source IR framework | Comprehensive artifact collection |

### 9.4 Linux Universal Detection

| Artifact | Location | Purpose |
|----------|----------|---------|
| **Auth Logs** | `/var/log/auth.log` or `/var/log/secure` | Authentication events |
| **Syslog** | `/var/log/syslog` or `/var/log/messages` | System events |
| **wtmp/btmp** | `/var/log/wtmp`, `/var/log/btmp` | Login records, failed logins |
| **lastlog** | `/var/log/lastlog` | Last login per user |
| **systemd services** | `/etc/systemd/system/`, `/lib/systemd/system/` | Service definitions |
| **cron** | `/etc/crontab`, `/var/spool/cron/`, `/etc/cron.*` | Scheduled tasks |
| **Network config** | `/etc/network/`, `/etc/netplan/`, `/etc/sysconfig/network-scripts/` | Network configuration |
| **Process list** | `/proc/*/` | Running processes and their details |
| **Open files** | `lsof` output | Open files, network connections |
| **Installed packages** | `dpkg -l`, `rpm -qa`, `pacman -Q` | Software inventory |

---

## 10. Detection Logic Architecture

### 10.1 Scanner Module Structure

```
Remote Access Scanner
├── Commercial RMM Detection
│   ├── Registry Scanner (per-tool registry key checks)
│   ├── File System Scanner (installation paths, log files, configs)
│   ├── Service Scanner (known service names and binaries)
│   ├── Process Scanner (running processes + code signers)
│   ├── DNS Cache Scanner (known RMM domains from LOLRMM)
│   └── LOLRMM Integration (API-driven, 260+ tools)
│
├── Built-in Remote Access Detection
│   ├── RDP Configuration & History
│   ├── SSH Server/Client Status & Keys
│   ├── WinRM/PSRemoting Status
│   ├── Admin Share Configuration
│   ├── macOS Remote Management Status
│   └── X11 Forwarding Detection
│
├── VPN/ZTNA Detection
│   ├── VPN Client Installation Detection
│   ├── Virtual Network Adapter Detection
│   ├── VPN Service Detection
│   ├── VPN Configuration File Detection
│   └── Network Connection Profile History
│
├── Tunneling/C2 Detection
│   ├── Known Tunnel Tool Detection (ngrok, cloudflared, chisel, frp)
│   ├── Web Shell Detection (FIM on web directories)
│   ├── LOLBin Abuse Detection (unusual command-line patterns)
│   ├── Named Pipe Analysis (Cobalt Strike indicators)
│   └── Beaconing Pattern Detection
│
├── Hardware Remote Access
│   ├── BMC/IPMI Detection
│   ├── Intel AMT/vPro Detection
│   └── Secure Boot Status
│
├── Lateral Movement Indicators
│   ├── PsExec/SMB Service Creation
│   ├── WMI Remote Execution
│   ├── DCOM Execution
│   ├── Scheduled Task Abuse
│   ├── Kerberos Attack Indicators
│   └── Credential Theft Indicators
│
├── Firewall & Network Analysis
│   ├── Inbound Rule Analysis
│   ├── Listening Port Baseline
│   ├── Port Forwarding Detection
│   └── Firewall Log Analysis
│
└── OSINT/ASM (External)
    ├── Shodan/Censys Queries
    ├── Certificate Transparency
    ├── DNS/WHOIS Analysis
    └── Email Security (SPF/DMARC/DKIM)
```

### 10.2 Evidence Grading

For each detected artifact, assign:
- **Confidence:** High / Medium / Low
- **Status:** Active (currently running/enabled) / Historical (was present/used) / Installed (present but unclear if used)
- **Risk:** Critical / High / Medium / Low / Informational
- **Platform:** Windows / macOS / Linux / Cross-platform

---

## References

### Research Papers & Articles
- [Synacktiv - Legitimate RATs: Comprehensive Forensic Analysis](https://www.synacktiv.com/en/publications/legitimate-rats-a-comprehensive-forensic-analysis-of-the-usual-suspects)
- [Synacktiv - Traces of Windows Remote Command Execution](https://www.synacktiv.com/en/publications/traces-of-windows-remote-command-execution)
- [Synacktiv - Forensic Aspects of Microsoft Remote Access VPN](https://www.synacktiv.com/en/publications/forensic-aspects-of-microsoft-remote-access-vpn)
- [MDPI - Forensic Analysis of File Exfiltrations Using AnyDesk, TeamViewer and Chrome Remote Desktop](https://www.mdpi.com/2079-9292/13/8/1429)
- [Edith Cowan University - Remote Desktop Application Artefacts on Windows](https://ro.ecu.edu.au/cgi/viewcontent.cgi?article=1166&context=adf)
- [Mandiant - Leveraging Apple Remote Desktop for Good and Evil](https://cloud.google.com/blog/topics/threat-intelligence/leveraging-apple-remote-desktop-for-good-and-evil)

### Detection & Threat Hunting
- [LOLRMM Project](https://lolrmm.io) - 260+ RMM tools with detection artifacts
- [LOLBAS Project](https://lolbas-project.github.io/) - Living Off the Land Binaries
- [GTFOBins](https://gtfobins.github.io/) - Unix LOLBins
- [LOLDrivers](https://www.loldrivers.io/) - Vulnerable/malicious drivers
- [MITRE ATT&CK T1219](https://attack.mitre.org/techniques/T1219/) - Remote Access Software
- [MITRE ATT&CK T1021](https://attack.mitre.org/techniques/T1021/) - Remote Services
- [MITRE ATT&CK T1505.003](https://attack.mitre.org/techniques/T1505/003/) - Web Shell
- [Elastic Security Detection Rules](https://www.elastic.co/guide/en/security/current/detection-engine-overview.html)

### Forensic Tools & Resources
- [Cyber Triage - Windows Registry Forensics 2025](https://www.cybertriage.com/blog/windows-registry-forensics-2025/)
- [Eric Zimmerman Tools](https://ericzimmerman.github.io/) - PECmd, LECmd, ShellBagsExplorer, Registry Explorer, SrumECmd
- [Velociraptor](https://docs.velociraptor.app/) - DFIR artifact collection
- [KAPE](https://www.kroll.com/en/services/cyber-risk/incident-response-litigation-support/kape) - Forensic triage collection
- [Magnet Forensics - RDP Artifacts in Incident Response](https://www.magnetforensics.com/blog/rdp-artifacts-in-incident-response/)

### Incident Response & Case Studies
- [The DFIR Report - Cobalt Strike Defender's Guide](https://thedfirreport.com/2021/08/29/cobalt-strike-a-defenders-guide/)
- [Lexfo - Cobalt Strike Investigation Part 1](https://blog.lexfo.fr/Cobalt%20Strike%20Investigation%20Part%201.html)
- [Palo Alto Unit 42 - Cobalt Strike Memory Analysis](https://unit42.paloaltonetworks.com/cobalt-strike-memory-analysis/)
- [CrowdStrike - Detecting Impacket wmiexec](https://www.crowdstrike.com/en-us/blog/how-to-detect-and-prevent-impackets-wmiexec/)
- [RSM War Room - Chromoting for Access](https://warroom.rsmus.com/chromoting-acccess/)
- [NSA/CISA - Detect and Prevent Web Shell Malware](https://media.defense.gov/2020/Jun/09/2002313081/-1/-1/0/CSI-DETECT-AND-PREVENT-WEB-SHELL-MALWARE-20200422.PDF)

### SSH Forensics
- [ogmini - SSH Artifacts in Windows 11 (Parts 1-2)](https://ogmini.github.io/2025/03/26/Windows-SSH-Testing-Part-1.html)
- [Infosec Institute - PowerShell Remoting Artifacts](https://www.infosecinstitute.com/resources/malware-analysis/powershell-remoting-artifacts-part-1/)
- [MCSI Library - Linux Forensics: SSH Artifacts](https://library.mosse-institute.com/articles/2022/07/linux-forensics-ssh-artifacts/linux-forensics-ssh-artifacts.html)

### RDP Forensics
- [Ponderthebits - Windows RDP-Related Event Logs](https://ponderthebits.com/2018/02/windows-rdp-related-event-logs-identification-tracking-and-investigation/)
- [Mahyar Notes - RDP Authentication Artifacts for DFIR](https://tajdini.net/blog/forensics-and-security/rdp-authentication-artifacts-for-dfir-purpose/)
- [GitHub BetaHydri/RDP-Forensic](https://github.com/BetaHydri/RDP-Forensic) - PowerShell RDP forensics toolkit

### Windows Firewall
- [Forensic Focus - Finding and Interpreting Windows Firewall Rules](https://www.forensicfocus.com/articles/finding-and-interpreting-windows-firewall-rules/)

### Community Detection Projects
- [Arizona ACTRA - RMM Detection](https://github.com/Arizona-Cyber-Threat-Response-Alliance/rmm-detection) - 200+ Sigma rules
- [jischell-msft - RemoteManagementMonitoringTools](https://github.com/jischell-msft/RemoteManagementMonitoringTools)
- [ForensicArtifacts/artifacts](https://github.com/ForensicArtifacts/artifacts) - Digital Forensics artifact definitions
- [Wazuh - MeshAgent Detection](https://wazuh.com/blog/how-to-detect-meshagent-with-wazuh/)
- [Jai Minton - DFIR Cheatsheet](https://www.jaiminton.com/cheatsheet/DFIR/)
