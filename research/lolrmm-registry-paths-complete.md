# LOLRMM Registry Paths - Complete Extraction
# Source: https://github.com/magicsword-io/LOLRMM (294 YAML files)
# Date: 2026-03-24
#
# Total YAML files processed: 294
# Tools with registry artifacts: 16 of 294
# Total registry path entries: 65
# Unique registry paths: 63

================================================================================
SECTION 1: REGISTRY PATHS GROUPED BY TOOL (16 tools, 65 entries)
================================================================================

## Action1 (3 registry paths)
   Source file: action1.yaml
   [1] HKLM\System\CurrentControlSet\Services\A1Agent
       Indicates: Service installation event as result of Action1 installation.
   [2] HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\Windows Error Reporting\LocalDumps\action1_agent.exe
       Indicates: Ensures that detailed crash information is available for analysis, which aids in maintaining the stability and reliability of the software.
   [3] HKLM\SOFTWARE\WOW6432Node\Action1
       Indicates: Storing its configuration settings and other relevant information

## Alpemix (1 registry path)
   Source file: alpemix.yaml
   [1] HKLM\SYSTEM\CurrentControlSet\Services\AlpemixSrvcx
       Indicates: N/A

## Ammyy Admin (2 registry paths)
   Source file: ammyyadmin.yml
   [1] HKU\.DEFAULT\Software\Ammyy\Admin
       Indicates: Writing the hr3 binary in the registry. The hr3 is likely used to store admin-related information.
   [2] HKLM\SYSTEM\ControlSet001\Control\SafeBoot\Network\AmmyyAdmin
       Indicates: Ammyy Admin service allows AMMYY admin to run in safe mode.

## AnyDesk (8 registry paths)
   Source file: anydesk.yaml
   [1] HKLM\SOFTWARE\Clients\Media\AnyDesk
       Indicates: N/A
   [2] HKLM\SYSTEM\CurrentControlSet\Services\AnyDesk
       Indicates: N/A
   [3] HKLM\SOFTWARE\Classes\.anydesk\shell\open\command
       Indicates: N/A
   [4] HKLM\SOFTWARE\Classes\AnyDesk\shell\open\command
       Indicates: N/A
   [5] HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Print\Printers\AnyDesk Printer\*
       Indicates: N/A
   [6] HKLM\DRIVERS\DriverDatabase\DeviceIds\USBPRINT\AnyDesk
       Indicates: N/A
   [7] HKLM\DRIVERS\DriverDatabase\DeviceIds\WSDPRINT\AnyDesk
       Indicates: N/A
   [8] HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\AnyDesk
       Indicates: N/A

## Atera (9 registry paths)
   Source file: atera.yaml
   [1] HKLM\SOFTWARE\ATERA Networks\AlphaAgent
       Indicates: N/A
   [2] HKLM\SYSTEM\CurrentControlSet\Services\AteraAgent
       Indicates: N/A
   [3] KLM\SOFTWARE\WOW6432Node\Splashtop Inc.
       Indicates: N/A (note: likely a typo in source, missing leading H)
   [4] HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Splashtop Software Updater
       Indicates: N/A (Splashtop is bundled with Atera)
   [5] HKLM\SYSTEM\ControlSet\Services\EventLog\Application\AlphaAgent
       Indicates: N/A
   [6] HKLM\SYSTEM\ControlSet\Services\EventLog\Application\AteraAgent
       Indicates: N/A
   [7] HKLM\SOFTWARE\Microsoft\Tracing\AteraAgent_RASAPI32
       Indicates: N/A
   [8] HKLM\SOFTWARE\Microsoft\Tracing\AteraAgent_RASMANCS
       Indicates: N/A
   [9] HKLM\SOFTWARE\ATERA Networks\*
       Indicates: N/A

## FleetDeck.io (1 registry path)
   Source file: fleetdeck.yaml
   [1] HKLM\SYSTEM\CurrentControlSet\Services\FleetDeck Agent Service
       Indicates: FleetDeck service registry key

## GoToAssist (GoTo Resolve) (1 registry path)
   Source file: gotoassist_(goto_resolve).yaml
   [1] HKLM\SOFTWARE\GoTo Resolve Unattended\
       Indicates: N/A

## GoToMyPC (4 registry paths)
   Source file: gotomypc.yaml
   [1] HKEY_LOCAL_MACHINE\WOW6432Node\Citrix\GoToMyPc
       Indicates: Configuration settings including registration email
   [2] HKEY_LOCAL_MACHINE\WOW6432Node\Citrix\GoToMyPc\GuestInvite
       Indicates: Guest invites send to connect
   [3] HKEY_CURRENT_USER\SOFTWARE\Citrix\GoToMyPc\FileTransfer\history
       Indicates: hostname of the computer making connections and location of transferred files
   [4] HKEY_USERS\<SID>\SOFTWARE\Citrix\GoToMyPc\FileTransfer\history
       Indicates: hostname of the computer making connections and location of transferred files

## HopToDesk (2 registry paths)
   Source file: hoptodesk.yaml
   [1] HKEY_CURRENT_USER\Software\Classes\HopToDesk\shell\open\command
       Indicates: HopToDesk URL protocol handler
   [2] HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\HopToDesk
       Indicates: HopToDesk uninstall registry key

## iDrive (2 registry paths)
   Source file: idrive.yaml
   [1] HKEY_LOCAL_MACHINE\SOFTWARE\IDrive\*
       Indicates: iDrive configuration registry keys
   [2] HKEY_CURRENT_USER\SOFTWARE\IDrive\*
       Indicates: iDrive user configuration registry keys

## ManageEngine ServiceDesk Plus (1 registry path)
   Source file: manageengine_servicedesk_plus.yaml
   [1] HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{*}
       Indicates: ManageEngine ServiceDesk Plus uninstall registry keys (verified via VirusTotal sandbox)

## RAdmin (1 registry path)
   Source file: radmin.yaml
   [1] HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Radmin\v3.0\Server\Parameters\Radmin Security
       Indicates: N/A

## RdClient (1 registry path)
   Source file: rdclient.yaml
   [1] HKLM\SOFTWARE\RdClient
       Indicates: RdClient Installation

## Splashtop (11 registry paths)
   Source file: splashtop.yaml
   [1] KLM\SOFTWARE\WOW6432Node\Splashtop Inc.\*
       Indicates: Splashtop Inc. registry key (note: likely a typo in source, missing leading H)
   [2] HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Splashtop Software Updater
       Indicates: Splashtop Software Updater uninstall key
   [3] HKLM\SYSTEM\CurrentControlSet\Services\SplashtopRemoteService
       Indicates: Splashtop Remote Service registry key
   [4] HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Splashtop-Splashtop Streamer-Remote Session/Operational
       Indicates: Splashtop Streamer Remote Session event log channel
   [5] HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Splashtop-Splashtop Streamer-Status/Operational
       Indicates: Splashtop Streamer Status event log channel
   [6] HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Splashtop Software Updater\InstallRefCount
       Indicates: Splashtop Software Updater install reference count
   [7] HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Network\SplashtopRemoteService
       Indicates: Splashtop Remote Service safe boot configuration
   [8] HKU\.DEFAULT\Software\Splashtop Inc.\*
       Indicates: Default user Splashtop Inc. registry key
   [9] HKU\SID\Software\Splashtop Inc.\*
       Indicates: User-specific Splashtop Inc. registry key
   [10] HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Print\Printers\Splashtop PDF Remote Printer
       Indicates: Splashtop PDF Remote Printer configuration
   [11] HKLM\SOFTWARE\WOW6432Node\Splashtop Inc.\Splashtop Remote Server\ClientInfo\*
       Indicates: Splashtop Remote Server client information

## TeamViewer (16 registry paths)
   Source file: teamviewer.yaml
   [1] HKLM\SOFTWARE\TeamViewer\*
       Indicates: N/A
   [2] HKU\<SID>\SOFTWARE\TeamViewer\*
       Indicates: N/A
   [3] HKLM\SYSTEM\CurrentControlSet\Services\TeamViewer\*
       Indicates: N/A
   [4] HKLM\SOFTWARE\TeamViewer\ConnectionHistory
       Indicates: N/A
   [5] HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\TeamViewer\*
       Indicates: N/A
   [6] HKU\SID\SOFTWARE\TeamViewer\MainWindowHandle
       Indicates: N/A
   [7] HKU\SID\SOFTWARE\TeamViewer\DesktopWallpaperSingleImage
       Indicates: N/A
   [8] HKU\SID\SOFTWARE\TeamViewer\DesktopWallpaperSingleImagePath
       Indicates: N/A
   [9] HKU\SID\SOFTWARE\TeamViewer\DesktopWallpaperSingleImagePosition
       Indicates: N/A
   [10] HKU\SID\SOFTWARE\TeamViewer\MinimizeToTray
       Indicates: N/A
   [11] HKU\SID\SOFTWARE\TeamViewer\MultiMedia\AudioUserSelectedCapturingEndpoint
       Indicates: N/A
   [12] HKU\SID\SOFTWARE\TeamViewer\MultiMedia\AudioSendingVolumeV2
       Indicates: N/A
   [13] HKU\SID\SOFTWARE\TeamViewer\MultiMedia\AudioUserSelectedRenderingEndpoint
       Indicates: N/A
   [14] HKLM\SOFTWARE\TeamViewer\ConnectionHistory
       Indicates: N/A (duplicate of #4, appears twice in source)
   [15] HKU\SID\SOFTWARE\TeamViewer\ClientWindow_Mode
       Indicates: N/A
   [16] HKU\SID\SOFTWARE\TeamViewer\ClientWindowPositions
       Indicates: N/A

## Veyon (2 registry paths)
   Source file: veyon.yaml
   [1] HKLM\SOFTWARE\Veyon Solutions
       Indicates: Main Veyon configuration registry key containing all service and application settings
   [2] HKLM\SYSTEM\CurrentControlSet\Services\VeyonService
       Indicates: Veyon service registration and configuration

================================================================================
SECTION 2: ALL 63 UNIQUE REGISTRY PATHS (SORTED ALPHABETICALLY)
================================================================================

HKEY_CURRENT_USER\SOFTWARE\Citrix\GoToMyPc\FileTransfer\history
HKEY_CURRENT_USER\SOFTWARE\IDrive\*
HKEY_CURRENT_USER\Software\Classes\HopToDesk\shell\open\command
HKEY_LOCAL_MACHINE\SOFTWARE\IDrive\*
HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Radmin\v3.0\Server\Parameters\Radmin Security
HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\HopToDesk
HKEY_LOCAL_MACHINE\WOW6432Node\Citrix\GoToMyPc
HKEY_LOCAL_MACHINE\WOW6432Node\Citrix\GoToMyPc\GuestInvite
HKEY_USERS\<SID>\SOFTWARE\Citrix\GoToMyPc\FileTransfer\history
HKLM\DRIVERS\DriverDatabase\DeviceIds\USBPRINT\AnyDesk
HKLM\DRIVERS\DriverDatabase\DeviceIds\WSDPRINT\AnyDesk
HKLM\SOFTWARE\ATERA Networks\*
HKLM\SOFTWARE\ATERA Networks\AlphaAgent
HKLM\SOFTWARE\Classes\.anydesk\shell\open\command
HKLM\SOFTWARE\Classes\AnyDesk\shell\open\command
HKLM\SOFTWARE\Clients\Media\AnyDesk
HKLM\SOFTWARE\GoTo Resolve Unattended\
HKLM\SOFTWARE\Microsoft\Tracing\AteraAgent_RASAPI32
HKLM\SOFTWARE\Microsoft\Tracing\AteraAgent_RASMANCS
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Print\Printers\AnyDesk Printer\*
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Print\Printers\Splashtop PDF Remote Printer
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\TeamViewer\*
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Splashtop-Splashtop Streamer-Remote Session/Operational
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Splashtop-Splashtop Streamer-Status/Operational
HKLM\SOFTWARE\RdClient
HKLM\SOFTWARE\TeamViewer\*
HKLM\SOFTWARE\TeamViewer\ConnectionHistory
HKLM\SOFTWARE\Veyon Solutions
HKLM\SOFTWARE\WOW6432Node\Action1
HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\AnyDesk
HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Splashtop Software Updater
HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Splashtop Software Updater\InstallRefCount
HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{*}
HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\Windows Error Reporting\LocalDumps\action1_agent.exe
HKLM\SOFTWARE\WOW6432Node\Splashtop Inc.\Splashtop Remote Server\ClientInfo\*
HKLM\SYSTEM\ControlSet\Services\EventLog\Application\AlphaAgent
HKLM\SYSTEM\ControlSet\Services\EventLog\Application\AteraAgent
HKLM\SYSTEM\ControlSet001\Control\SafeBoot\Network\AmmyyAdmin
HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Network\SplashtopRemoteService
HKLM\SYSTEM\CurrentControlSet\Services\AlpemixSrvcx
HKLM\SYSTEM\CurrentControlSet\Services\AnyDesk
HKLM\SYSTEM\CurrentControlSet\Services\AteraAgent
HKLM\SYSTEM\CurrentControlSet\Services\FleetDeck Agent Service
HKLM\SYSTEM\CurrentControlSet\Services\SplashtopRemoteService
HKLM\SYSTEM\CurrentControlSet\Services\TeamViewer\*
HKLM\SYSTEM\CurrentControlSet\Services\VeyonService
HKLM\System\CurrentControlSet\Services\A1Agent
HKU\<SID>\SOFTWARE\TeamViewer\*
HKU\.DEFAULT\Software\Ammyy\Admin
HKU\.DEFAULT\Software\Splashtop Inc.\*
HKU\SID\SOFTWARE\TeamViewer\ClientWindowPositions
HKU\SID\SOFTWARE\TeamViewer\ClientWindow_Mode
HKU\SID\SOFTWARE\TeamViewer\DesktopWallpaperSingleImage
HKU\SID\SOFTWARE\TeamViewer\DesktopWallpaperSingleImagePath
HKU\SID\SOFTWARE\TeamViewer\DesktopWallpaperSingleImagePosition
HKU\SID\SOFTWARE\TeamViewer\MainWindowHandle
HKU\SID\SOFTWARE\TeamViewer\MinimizeToTray
HKU\SID\SOFTWARE\TeamViewer\MultiMedia\AudioSendingVolumeV2
HKU\SID\SOFTWARE\TeamViewer\MultiMedia\AudioUserSelectedCapturingEndpoint
HKU\SID\SOFTWARE\TeamViewer\MultiMedia\AudioUserSelectedRenderingEndpoint
HKU\SID\Software\Splashtop Inc.\*
KLM\SOFTWARE\WOW6432Node\Splashtop Inc.
KLM\SOFTWARE\WOW6432Node\Splashtop Inc.\*

================================================================================
SECTION 3: NOTES
================================================================================

- 278 of 294 LOLRMM tools (94.6%) have NO registry artifacts defined
- Only 16 tools (5.4%) have registry-based detection indicators
- TeamViewer has the most registry paths (16), followed by Splashtop (11) and Atera (9)
- Two paths beginning with "KLM\" (missing "H" prefix) appear to be typos in the source data:
    KLM\SOFTWARE\WOW6432Node\Splashtop Inc.\*  (in splashtop.yaml)
    KLM\SOFTWARE\WOW6432Node\Splashtop Inc.    (in atera.yaml)
- Some LOLRMM files use full hive names (HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER, HKEY_USERS)
  while others use abbreviations (HKLM, HKU) -- there is no consistency in the dataset
- The LOLRMM YAML schema stores registry artifacts under: Artifacts > Registry > [{Path, Description}]
- Atera bundles Splashtop, so Atera's registry artifacts include Splashtop paths
- TeamViewer's ConnectionHistory path appears twice (duplicate in source YAML)
