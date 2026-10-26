# SPDX-License-Identifier: 0BSD
#Requires -Version 5.1

<#
.SYNOPSIS
    Builds a forensic workstation from fresh and keeps it current: installs
    the forensic tools in its catalogue and the prerequisites they need,
    downloads only what has changed, and removes what is no longer needed.

.DESCRIPTION
    One run does everything: on a fresh machine it installs every tool; later
    it checks each tool's source and downloads only what has changed. Tools go
    under Program Files\ForensicTools\<Family>\<Tool>\. Command-line tools are
    put on the machine PATH, so they run by name from any terminal; GUI tools
    get shortcuts on the Desktop and in the Start Menu, grouped by family.

    Prerequisites follow the tools: each .NET runtime line a tool's build
    needs (the Desktop Runtime only where a GUI tool needs it, since it also
    covers the plain runtime of its line), each kept at its latest patch. The ancillary content of EvtxECmd,
    RECmd and SQLECmd (maps, batch files) is checked on every run and synced
    when it has changed upstream.

    Every download is hashed (SHA-256), checked against the vendor's
    published hash where there is one and against the vendor's Authenticode
    signer, and recorded. The script only ever removes what it installed
    itself (recorded in state.json). Records are written under
    ProgramData\ForensicWorkstation\: a log per run, inventory.csv (what is
    installed, from where, with which hashes) and files.csv (SHA-256 of
    every installed file).

    Exit codes: 0 PASS, 1 WARN, 2 FAIL, 3 stopped before any work (a
    precondition failed).

.PARAMETER CheckOnly
    The dry run: checks every source and lists each action an update would
    take, changes nothing, and ends with the result block. Needs no
    elevation. -WhatIf does the same.

.PARAMETER Verify
    Re-hashes every installed file against files.csv and reports files
    missing, changed or not on record. No network access, no changes. Needs
    no elevation.

.PARAMETER Family
    Limits the run to the tools of these families (and the prerequisites
    they need). A run with -Family or -Tool removes nothing.

.PARAMETER Tool
    Limits the run to these tools (and the prerequisites they need).

.EXAMPLE
    .\Update-ForensicWorkstation.ps1

    From an elevated Windows PowerShell 5.1 prompt: installs or updates
    everything.

.EXAMPLE
    .\Update-ForensicWorkstation.ps1 -CheckOnly

    Is the workstation current? Lists what an update would do.

.EXAMPLE
    .\Update-ForensicWorkstation.ps1 -Family NirSoft -Tool EvtxECmd

    Updates the NirSoft tools and EvtxECmd only.

.NOTES
    Version: $WorkstationVersion below (semver); changes are in CHANGELOG.md.
    Requires Windows PowerShell 5.1 on 64-bit Windows (amd64), no modules.
    License: 0BSD.
#>

# Every empty catch {} in this script is deliberate: it guards a step whose
# failure leaves the documented default in place (a fact stays unknown, a
# close is skipped) and must never stop the rest. Every skip of real work has
# its own catch that records the outcome.
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingEmptyCatchBlock', '',
    Justification = 'Each empty catch guards a step whose failure leaves the documented default in place; it must never stop the rest of the run.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
    Justification = 'The dry run (-CheckOnly / -WhatIf) is decided once, in MAIN: no function that changes anything is called in a dry run.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '',
    Justification = 'Console output on a desktop terminal, with colour for PASS/WARN/FAIL; every line is also written to the run log.')]
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [switch]$CheckOnly,
    [switch]$Verify,
    [string[]]$Family = @(),
    [string[]]$Tool = @()
)

# ============================== CONFIG ==============================

$WorkstationVersion = '0.2.1'

# No script-wide error suppression: every unit of work has its own try/catch.
# Progress bars are off: Invoke-WebRequest in PowerShell 5.1 is many times
# slower with one.
$ProgressPreference = 'SilentlyContinue'

# Where things go. Folders are resolved from Windows, never assumed.
$InstallFolderName = 'ForensicTools'          # under Program Files
$RecordsFolderName = 'ForensicWorkstation'    # under ProgramData (and, for a run without elevation, LocalAppData)

# Console text keeps to this width (shared rules); longer values that can't
# be broken (a hash, a path) run past it. A path's spaces are held as this
# character while text is wrapped (Format-Unbreakable).
$ConsoleWidth = 80
$UnbreakableSpace = [char]0x1F
$PlanActionWidth = 10       # the plan's action column ("Reinstall" and a space)
$CheckNameWidth = 24        # the name column of the check lines; a longer name has its line to itself

# Network: every request has a timeout; the system proxy of the running
# account is used (Invoke-WebRequest's default).
$HttpTimeoutSeconds = 120
$GitHubApiRoot = 'https://api.github.com'

# How long an installer or a tool's --sync may run before it is stopped.
$ProcessTimeoutMinutes = 15

# Installer exit codes that mean success. 3010: success, a restart is needed
# to complete (reported as a WARN).
$InstallerSuccessExitCodes = @(0, 3010)
$RestartRequiredExitCode = 3010

# --- Families ---
# Fields:
#   Name             what -Family takes; the family's folder under the install
#                    root
#   ShortcutFolder   the Desktop and Start Menu folder for its GUI tools (used
#                    when the family has more than one GUI tool; a family with
#                    one gets its shortcut directly on the Desktop)
#   ExpectedSigner   the Authenticode signer (certificate CN) of its exes
#   UnsignedAllowed  $true where the vendor ships some builds unsigned: an
#                    unsigned exe is then recorded as unsigned (its SHA-256 is
#                    the record), a signature by anyone else is still a FAIL
$Families = @(
    [pscustomobject]@{ Name = 'Zimmerman';    ShortcutFolder = 'EZ Tools';     ExpectedSigner = 'ZimTech LLC';                      UnsignedAllowed = $false }
    [pscustomobject]@{ Name = 'NirSoft';      ShortcutFolder = 'NirSoft';      ExpectedSigner = 'Nir Sofer';                        UnsignedAllowed = $true }
    [pscustomobject]@{ Name = 'Sysinternals'; ShortcutFolder = 'Sysinternals'; ExpectedSigner = 'Microsoft Corporation';            UnsignedAllowed = $false }
    [pscustomobject]@{ Name = 'Arsenal';      ShortcutFolder = 'Arsenal';      ExpectedSigner = 'Arsenal Consulting, Inc.';         UnsignedAllowed = $false }
)

# Arsenal Image Mounter's zip holds builds for other platforms and features
# not installed (owner, 2026-10-23: GUI and CLI only): left out of both its
# tools. Of its runtimes\ folders only x64 Windows' (and the generic
# Windows one) are kept.
$ArsenalNotInstalled = @(
    'ArsenalImageMounter_ARM64.exe'                          # the ARM64 GUI
    'aim_cli', 'aim_pro'                                     # the Linux CLI builds
    'readme_cli_linux.txt'
    'PowerShell\*', 'readme_PowerShell.txt'                  # AIM's PowerShell module
    'remote\*', 'readme_remote.txt'                          # AIM Remote Agent
    'runtimes\*'
)
$ArsenalKept = @('runtimes\win-x64\*', 'runtimes\win\*')

# Zimmerman zips that ship other platforms' native libraries beside the
# Windows x64 one (2026.10): left out (owner, 2026-10-23: only the chosen
# build is installed).
$EzSqliteOtherPlatforms = @('libe_sqlite3.so', 'libe_sqlite3.dylib')     # AmcacheParser, WxTCmd: Linux, macOS
$EzRuntimesOtherPlatforms = @('runtimes\*')                              # SQLECmd: all but...
$EzRuntimesKept = @('runtimes\win-x64\*')                               # ...its x64 Windows SQLite.Interop.dll

# --- Tool catalogue ---
# One row per tool. Adding a tool is adding a row. Fields:
#   Name           what -Tool takes; the tool's folder under its family's
#   DisplayName    the shortcut's name (GUI tools)
#   Family         a Name in $Families
#   Source         the adapter that checks and downloads it:
#                    EZTools       download.ericzimmermanstools.com; the build
#                                  on the newest .NET line on the vendor's page
#                    NirSoft       nirsoft.net; the first build in
#                                  $NirSoftBuilds that exists
#                    Sysinternals  download.sysinternals.com
#                    ArsenalRecon  the version from the vendor's downloads
#                                  page; the zip downloaded by hand into the
#                                  account's Downloads folder (the vendor
#                                  ships it through MEGA)
#   Package        the adapter's name for it: EZTools and Sysinternals the
#                  zip's name; NirSoft the name in its PAD and zip URLs;
#                  ArsenalRecon the downloads page. Two rows may share a zip
#                  (Autoruns and autorunsc), each installing its own Files
#   Gui            the exe a shortcut opens, relative to the tool's folder,
#                  or $null
#   Cli            the exes run by name from a terminal; a tool with any has
#                  its folder on the machine PATH
#   Requires       prerequisites, as capabilities: 'DotNet:<Flavour>' means
#                  that flavour (a $DotNetFlavours row) of the .NET line the
#                  chosen build targets (EZTools builds name their line, e.g.
#                  net9)
#   KeepPaths      folders inside the tool's folder kept across an update
#                  (user data); not verified by -Verify
#   WritablePaths  folders inside the tool's folder the running account may
#                  write to (settings a tool saves beside its exe, a CLI
#                  tool's Temp); created if missing, kept across an update,
#                  not verified. A CLI tool may have them: its folder on
#                  PATH stays protected, and a subfolder isn't searched for
#                  exes or DLLs
# Optional fields (a row without one has none):
#   WritableFiles  files inside the tool's folder the running account may
#                  write to, and nothing else there (NirSoft's <tool>.cfg):
#                  created empty if missing, kept, not verified. A tool with
#                  writable files and Cli entries is refused: no folder on
#                  PATH is writable by the account
#   Files          the files to install from the zip (after its top-level
#                  folder is dropped); the rest are left out. A name missing
#                  from the zip fails the install. Without it, every file
#   ExcludeFiles   patterns (-like, on the path after the top-level folder
#                  is dropped) of files left out of the install: other
#                  platforms' builds, features not wanted
#   KeepFiles      patterns kept even where an ExcludeFiles pattern matches
#   RuntimeConfig  ArsenalRecon: the runtimeconfig.json in the zip that names
#                  the build's .NET line (its zip names no line)
#   ShortcutOutsideFolder  $true: the shortcuts sit directly on the Desktop
#                  and in the Start Menu, not in the family's folder
#                  (Timeline Explorer, used with every family)
#   EulaKeys       Sysinternals: subkeys of HKCU\Software\Sysinternals that
#                  get EulaAccepted = 1
$Catalogue = @(
    # Zimmerman: GUI tools (their .NET builds need the .NET Desktop Runtime of their line)
    [pscustomobject]@{ Name = 'JumpListExplorer';  DisplayName = 'JumpList Explorer';  Family = 'Zimmerman'; Source = 'EZTools'; Package = 'JumpListExplorer.zip';  Gui = 'JumpListExplorer.exe';  Cli = @(); Requires = @('DotNet:WindowsDesktop'); KeepPaths = @(); WritablePaths = @(); WritableFiles = @('Settings.xml') }
    [pscustomobject]@{ Name = 'MFTExplorer';       DisplayName = 'MFT Explorer';       Family = 'Zimmerman'; Source = 'EZTools'; Package = 'MFTExplorer.zip';       Gui = 'MFTExplorer.exe';       Cli = @(); Requires = @('DotNet:WindowsDesktop'); KeepPaths = @(); WritablePaths = @() }
    [pscustomobject]@{ Name = 'RegistryExplorer';  DisplayName = 'Registry Explorer';  Family = 'Zimmerman'; Source = 'EZTools'; Package = 'RegistryExplorer.zip';  Gui = 'RegistryExplorer.exe';  Cli = @(); Requires = @('DotNet:WindowsDesktop'); KeepPaths = @(); WritablePaths = @('Bookmarks\User') }
    [pscustomobject]@{ Name = 'SDBExplorer';       DisplayName = 'SDB Explorer';       Family = 'Zimmerman'; Source = 'EZTools'; Package = 'SDBExplorer.zip';       Gui = 'SDBExplorer.exe';       Cli = @(); Requires = @('DotNet:WindowsDesktop'); KeepPaths = @(); WritablePaths = @(); WritableFiles = @('Settings.xml') }
    [pscustomobject]@{ Name = 'ShellBagsExplorer'; DisplayName = 'ShellBags Explorer'; Family = 'Zimmerman'; Source = 'EZTools'; Package = 'ShellBagsExplorer.zip'; Gui = 'ShellBagsExplorer.exe'; Cli = @(); Requires = @('DotNet:WindowsDesktop'); KeepPaths = @(); WritablePaths = @('Settings', 'logs') }
    [pscustomobject]@{ Name = 'TimelineExplorer';  DisplayName = 'Timeline Explorer';  Family = 'Zimmerman'; Source = 'EZTools'; Package = 'TimelineExplorer.zip';  Gui = 'TimelineExplorer.exe';  Cli = @(); Requires = @('DotNet:WindowsDesktop'); KeepPaths = @(); WritablePaths = @('Settings'); ShortcutOutsideFolder = $true }
    # Zimmerman: command-line tools (their .NET builds need the .NET Runtime of their line). Since 2026.10, five of them copy the
    # evidence databases they read into a Temp folder beside their exe (unless --temp is given): a writable subfolder
    [pscustomobject]@{ Name = 'AmcacheParser';         DisplayName = 'AmcacheParser';         Family = 'Zimmerman'; Source = 'EZTools'; Package = 'AmcacheParser.zip';         Gui = $null; Cli = @('AmcacheParser.exe');         Requires = @('DotNet:NETCore'); KeepPaths = @(); WritablePaths = @('Temp'); ExcludeFiles = @($EzSqliteOtherPlatforms) }
    [pscustomobject]@{ Name = 'AppCompatCacheParser';  DisplayName = 'AppCompatCacheParser';  Family = 'Zimmerman'; Source = 'EZTools'; Package = 'AppCompatCacheParser.zip';  Gui = $null; Cli = @('AppCompatCacheParser.exe');  Requires = @('DotNet:NETCore'); KeepPaths = @(); WritablePaths = @() }
    [pscustomobject]@{ Name = 'EvtxECmd';              DisplayName = 'EvtxECmd';              Family = 'Zimmerman'; Source = 'EZTools'; Package = 'EvtxECmd.zip';              Gui = $null; Cli = @('EvtxECmd.exe');              Requires = @('DotNet:NETCore'); KeepPaths = @(); WritablePaths = @() }
    [pscustomobject]@{ Name = 'JLECmd';                DisplayName = 'JLECmd';                Family = 'Zimmerman'; Source = 'EZTools'; Package = 'JLECmd.zip';                Gui = $null; Cli = @('JLECmd.exe');                Requires = @('DotNet:NETCore'); KeepPaths = @(); WritablePaths = @() }
    [pscustomobject]@{ Name = 'LECmd';                 DisplayName = 'LECmd';                 Family = 'Zimmerman'; Source = 'EZTools'; Package = 'LECmd.zip';                 Gui = $null; Cli = @('LECmd.exe');                 Requires = @('DotNet:NETCore'); KeepPaths = @(); WritablePaths = @() }
    [pscustomobject]@{ Name = 'MFTECmd';               DisplayName = 'MFTECmd';               Family = 'Zimmerman'; Source = 'EZTools'; Package = 'MFTECmd.zip';               Gui = $null; Cli = @('MFTECmd.exe');               Requires = @('DotNet:NETCore'); KeepPaths = @(); WritablePaths = @() }
    [pscustomobject]@{ Name = 'PECmd';                 DisplayName = 'PECmd';                 Family = 'Zimmerman'; Source = 'EZTools'; Package = 'PECmd.zip';                 Gui = $null; Cli = @('PECmd.exe');                 Requires = @('DotNet:NETCore'); KeepPaths = @(); WritablePaths = @() }
    [pscustomobject]@{ Name = 'RBCmd';                 DisplayName = 'RBCmd';                 Family = 'Zimmerman'; Source = 'EZTools'; Package = 'RBCmd.zip';                 Gui = $null; Cli = @('RBCmd.exe');                 Requires = @('DotNet:NETCore'); KeepPaths = @(); WritablePaths = @() }
    [pscustomobject]@{ Name = 'RecentFileCacheParser'; DisplayName = 'RecentFileCacheParser'; Family = 'Zimmerman'; Source = 'EZTools'; Package = 'RecentFileCacheParser.zip'; Gui = $null; Cli = @('RecentFileCacheParser.exe'); Requires = @('DotNet:NETCore'); KeepPaths = @(); WritablePaths = @() }
    [pscustomobject]@{ Name = 'RECmd';                 DisplayName = 'RECmd';                 Family = 'Zimmerman'; Source = 'EZTools'; Package = 'RECmd.zip';                 Gui = $null; Cli = @('RECmd.exe');                 Requires = @('DotNet:NETCore'); KeepPaths = @(); WritablePaths = @() }
    [pscustomobject]@{ Name = 'SBECmd';                DisplayName = 'SBECmd';                Family = 'Zimmerman'; Source = 'EZTools'; Package = 'SBECmd.zip';                Gui = $null; Cli = @('SBECmd.exe');                Requires = @('DotNet:NETCore'); KeepPaths = @(); WritablePaths = @() }
    [pscustomobject]@{ Name = 'SQLECmd';               DisplayName = 'SQLECmd';               Family = 'Zimmerman'; Source = 'EZTools'; Package = 'SQLECmd.zip';               Gui = $null; Cli = @('SQLECmd.exe');               Requires = @('DotNet:NETCore'); KeepPaths = @(); WritablePaths = @('Temp'); ExcludeFiles = @($EzRuntimesOtherPlatforms); KeepFiles = @($EzRuntimesKept) }
    [pscustomobject]@{ Name = 'SrumECmd';              DisplayName = 'SrumECmd';              Family = 'Zimmerman'; Source = 'EZTools'; Package = 'SrumECmd.zip';              Gui = $null; Cli = @('SrumECmd.exe');              Requires = @('DotNet:NETCore'); KeepPaths = @(); WritablePaths = @('Temp') }
    [pscustomobject]@{ Name = 'SumECmd';               DisplayName = 'SumECmd';               Family = 'Zimmerman'; Source = 'EZTools'; Package = 'SumECmd.zip';               Gui = $null; Cli = @('SumECmd.exe');               Requires = @('DotNet:NETCore'); KeepPaths = @(); WritablePaths = @('Temp') }
    [pscustomobject]@{ Name = 'WxTCmd';                DisplayName = 'WxTCmd';                Family = 'Zimmerman'; Source = 'EZTools'; Package = 'WxTCmd.zip';                Gui = $null; Cli = @('WxTCmd.exe');                Requires = @('DotNet:NETCore'); KeepPaths = @(); WritablePaths = @('Temp'); ExcludeFiles = @($EzSqliteOtherPlatforms) }
    # NirSoft (GUI tools, no prerequisites)
    [pscustomobject]@{ Name = 'FullEventLogView';      DisplayName = 'FullEventLogView';      Family = 'NirSoft'; Source = 'NirSoft'; Package = 'fulleventlogview';      Gui = 'FullEventLogView.exe';      Cli = @(); Requires = @(); KeepPaths = @(); WritablePaths = @(); WritableFiles = @('FullEventLogView.cfg') }
    [pscustomobject]@{ Name = 'OfflineRegistryView';   DisplayName = 'OfflineRegistryView';   Family = 'NirSoft'; Source = 'NirSoft'; Package = 'offlineregistryview';   Gui = 'OfflineRegistryView.exe';   Cli = @(); Requires = @(); KeepPaths = @(); WritablePaths = @(); WritableFiles = @('OfflineRegistryView.cfg') }
    [pscustomobject]@{ Name = 'OfflineRegistryFinder'; DisplayName = 'OfflineRegistryFinder'; Family = 'NirSoft'; Source = 'NirSoft'; Package = 'offlineregistryfinder'; Gui = 'OfflineRegistryFinder.exe'; Cli = @(); Requires = @(); KeepPaths = @(); WritablePaths = @(); WritableFiles = @('OfflineRegistryFinder.cfg') }
    [pscustomobject]@{ Name = 'ShortcutsMan';          DisplayName = 'ShortcutsMan';          Family = 'NirSoft'; Source = 'NirSoft'; Package = 'shman';                 Gui = 'shman.exe';                 Cli = @(); Requires = @(); KeepPaths = @(); WritablePaths = @(); WritableFiles = @('shman.cfg') }
    [pscustomobject]@{ Name = 'JumpListsView';         DisplayName = 'JumpListsView';         Family = 'NirSoft'; Source = 'NirSoft'; Package = 'jumplistsview';         Gui = 'JumpListsView.exe';         Cli = @(); Requires = @(); KeepPaths = @(); WritablePaths = @(); WritableFiles = @('JumpListsView.cfg') }
    [pscustomobject]@{ Name = 'ShellBagsView';         DisplayName = 'ShellBagsView';         Family = 'NirSoft'; Source = 'NirSoft'; Package = 'shellbagsview';         Gui = 'ShellBagsView.exe';         Cli = @(); Requires = @(); KeepPaths = @(); WritablePaths = @(); WritableFiles = @('ShellBagsView.cfg') }
    [pscustomobject]@{ Name = 'RecentFilesView';       DisplayName = 'RecentFilesView';       Family = 'NirSoft'; Source = 'NirSoft'; Package = 'recentfilesview';       Gui = 'RecentFilesView.exe';       Cli = @(); Requires = @(); KeepPaths = @(); WritablePaths = @(); WritableFiles = @('RecentFilesView.cfg') }
    [pscustomobject]@{ Name = 'AppCompatibilityView';  DisplayName = 'AppCompatibilityView';  Family = 'NirSoft'; Source = 'NirSoft'; Package = 'appcompatibilityview';  Gui = 'AppCompatibilityView.exe';  Cli = @(); Requires = @(); KeepPaths = @(); WritablePaths = @(); WritableFiles = @('AppCompatibilityView.cfg') }
    [pscustomobject]@{ Name = 'AppResourcesUsageView'; DisplayName = 'AppResourcesUsageView'; Family = 'NirSoft'; Source = 'NirSoft'; Package = 'appresourcesusageview'; Gui = 'AppResourcesUsageView.exe'; Cli = @(); Requires = @(); KeepPaths = @(); WritablePaths = @(); WritableFiles = @('AppResourcesUsageView.cfg') }
    [pscustomobject]@{ Name = 'WinPrefetchView';       DisplayName = 'WinPrefetchView';       Family = 'NirSoft'; Source = 'NirSoft'; Package = 'winprefetchview';       Gui = 'WinPrefetchView.exe';       Cli = @(); Requires = @(); KeepPaths = @(); WritablePaths = @(); WritableFiles = @('WinPrefetchView.cfg') }
    [pscustomobject]@{ Name = 'UserAssistView';        DisplayName = 'UserAssistView';        Family = 'NirSoft'; Source = 'NirSoft'; Package = 'userassistview';        Gui = 'UserAssistView.exe';        Cli = @(); Requires = @(); KeepPaths = @(); WritablePaths = @(); WritableFiles = @('UserAssistView.cfg') }
    [pscustomobject]@{ Name = 'USBDeview';             DisplayName = 'USBDeview';             Family = 'NirSoft'; Source = 'NirSoft'; Package = 'usbdeview';             Gui = 'USBDeview.exe';             Cli = @(); Requires = @(); KeepPaths = @(); WritablePaths = @(); WritableFiles = @('USBDeview.cfg') }
    # Sysinternals (each zip holds 32-bit, 64-bit and ARM64 builds; only the 64-bit ones are installed)
    [pscustomobject]@{ Name = 'ProcessExplorer'; DisplayName = 'Process Explorer'; Family = 'Sysinternals'; Source = 'Sysinternals'; Package = 'ProcessExplorer.zip'; Gui = 'procexp64.exe';  Cli = @();                  Requires = @(); KeepPaths = @(); WritablePaths = @(); Files = @('procexp64.exe', 'Eula.txt'); EulaKeys = @('Process Explorer') }
    [pscustomobject]@{ Name = 'Autoruns';        DisplayName = 'Autoruns';         Family = 'Sysinternals'; Source = 'Sysinternals'; Package = 'Autoruns.zip';        Gui = 'Autoruns64.exe'; Cli = @();                  Requires = @(); KeepPaths = @(); WritablePaths = @(); Files = @('Autoruns64.exe', 'Eula.txt'); EulaKeys = @('AutoRuns') }
    # autorunsc from the same zip as Autoruns, in a folder of its own: only it goes on PATH
    [pscustomobject]@{ Name = 'Autorunsc';       DisplayName = 'autorunsc';        Family = 'Sysinternals'; Source = 'Sysinternals'; Package = 'Autoruns.zip';        Gui = $null;            Cli = @('autorunsc64.exe'); Requires = @(); KeepPaths = @(); WritablePaths = @(); Files = @('autorunsc64.exe', 'Eula.txt'); EulaKeys = @('Autorunsc') }
    [pscustomobject]@{ Name = 'Disk2vhd';        DisplayName = 'Disk2vhd';         Family = 'Sysinternals'; Source = 'Sysinternals'; Package = 'Disk2vhd.zip';        Gui = 'disk2vhd64.exe'; Cli = @();                  Requires = @(); KeepPaths = @(); WritablePaths = @(); Files = @('disk2vhd64.exe', 'Disk2vhd.chm', 'Eula.txt'); EulaKeys = @('Disk2Vhd') }
    # Arsenal Image Mounter: the zip downloaded by hand; the GUI and the CLI as two tools, so only the CLI's folder is on PATH. It needs the Visual C++ Redistributable (the GUI) and its driver (both), prerequisites of their own.
    [pscustomobject]@{ Name = 'ArsenalImageMounter'; DisplayName = 'Arsenal Image Mounter'; Family = 'Arsenal'; Source = 'ArsenalRecon'; Package = 'https://arsenalrecon.com/products/arsenal-image-mounter/downloads'; RuntimeConfig = 'ArsenalImageMounter.runtimeconfig.json'
        Gui = 'ArsenalImageMounter.exe'; Cli = @(); Requires = @('DotNet:WindowsDesktop', 'VCRedist:x64', 'AimDriver'); KeepPaths = @(); WritablePaths = @(); WritableFiles = @('ArsenalImageMounter.log'); ExcludeFiles = @($ArsenalNotInstalled) + @('aim_cli.exe', 'aim_pro.exe'); KeepFiles = @($ArsenalKept) }
    [pscustomobject]@{ Name = 'AimCli'; DisplayName = 'AIM CLI'; Family = 'Arsenal'; Source = 'ArsenalRecon'; Package = 'https://arsenalrecon.com/products/arsenal-image-mounter/downloads'; RuntimeConfig = 'aim_cli.runtimeconfig.json'
        Gui = $null; Cli = @('aim_cli.exe', 'aim_pro.exe'); Requires = @('DotNet:NETCore', 'AimDriver'); KeepPaths = @(); WritablePaths = @(); ExcludeFiles = @($ArsenalNotInstalled) + @('ArsenalImageMounter.*'); KeepFiles = @($ArsenalKept) }
)

# Arsenal: the newest release on the downloads page (listed newest first),
# with the MD5 the vendor publishes for its zip (missing for some releases).
$ArsenalReleasePattern = 'Arsenal-Image-Mounter[-_]v(\d+(?:\.\d+){1,3})\.zip\s*MD5\s*Hash\s*=\s*([0-9a-fA-F]{32})?'

# --- Source adapters' settings ---

# Zimmerman: the vendor's index (tools.ericzimmermanstools.com redirects to
# it), and the net-line zips on it that are left out on purpose, so they
# aren't reported as "not in the catalogue": iisGeolocate, TimeApp and XWFIM
# (the vendor's "Other tools"), Hasher, bstrings, rla, EZViewer and VSCMount
# (not wanted on the workstation).
$EzIndexUrl = 'https://raw.githubusercontent.com/EricZimmerman/ericzimmerman.github.io/refs/heads/master/docs/index.md'
# Its .NET builds are linked as /net<line>/<zip> or, since 2026-10-24, as
# /net/<zip> for the vendor's current line, whose number the page's table
# header gives ("Version (.net 4 | 10)"); links at the root are the .NET
# Framework builds, never used.
$EzDownloadPattern = 'https://download\.ericzimmermanstools\.com/net(\d*)/([A-Za-z0-9_.-]+\.zip)'
$EzCurrentLinePattern = 'Version \(\.net 4 (?:&vert;|\|) (\d+)\)'
$EzOutOfScope = @('iisGeolocate.zip', 'TimeApp.zip', 'XWFIM.zip', 'hasher.zip', 'bstrings.zip', 'rla.zip', 'EZViewer.zip', 'VSCMount.zip')

# NirSoft: version from the PAD file; builds in order of preference.
$NirSoftPadUrl = 'https://www.nirsoft.net/pad/{0}.xml'
$NirSoftZipUrl = 'https://www.nirsoft.net/utils/{0}{1}.zip'
$NirSoftBuilds = @(
    [pscustomobject]@{ Build = 'x64'; Suffix = '-x64' }
    [pscustomobject]@{ Build = 'x86'; Suffix = '' }
)

$SysinternalsZipUrl = 'https://download.sysinternals.com/files/{0}'

# --- Ancillary content ---
# Content a tool syncs from GitHub with its own --sync, checked every run.
# Fields: Tool (a catalogue Name), Folder (inside the tool's folder; what
# --sync writes), Repository, RepositoryPath (the folder upstream), Branch
# (what --sync downloads).
$AncillaryContent = @(
    [pscustomobject]@{ Tool = 'EvtxECmd'; Folder = 'Maps';          Repository = 'EricZimmerman/evtx';    RepositoryPath = 'evtx/Maps';     Branch = 'master'; Description = 'EvtxECmd maps' }
    [pscustomobject]@{ Tool = 'RECmd';    Folder = 'BatchExamples'; Repository = 'EricZimmerman/RECmd';   RepositoryPath = 'BatchExamples'; Branch = 'master'; Description = 'RECmd batch files' }
    [pscustomobject]@{ Tool = 'SQLECmd';  Folder = 'Maps';          Repository = 'EricZimmerman/SQLECmd'; RepositoryPath = 'SQLMap/Maps';   Branch = 'master'; Description = 'SQLECmd maps' }
)

# --- Prerequisites ---

# .NET runtime flavours. Each major version of each flavour is a product
# line of its own; the line a tool needs comes from its build. Fields:
#   Flavour          the capability name ('DotNet:<Flavour>:<major>')
#   DisplayName      shown with the version
#   MetadataKey      the flavour's key in Microsoft's release metadata
#   SharedFramework  the folder under Program Files\dotnet\shared that shows
#                    an installed version
#   Covers           the flavours an install of it provides (the Desktop
#                    Runtime installs the plain runtime of its line too)
$DotNetFlavours = @(
    [pscustomobject]@{ Flavour = 'WindowsDesktop'; DisplayName = '.NET Desktop Runtime'; MetadataKey = 'windowsdesktop'; SharedFramework = 'Microsoft.WindowsDesktop.App'; Covers = @('WindowsDesktop', 'NETCore') }
    [pscustomobject]@{ Flavour = 'NETCore';        DisplayName = '.NET Runtime';         MetadataKey = 'runtime';        SharedFramework = 'Microsoft.NETCore.App';        Covers = @('NETCore') }
)
$DotNetIndexUrl = 'https://builds.dotnet.microsoft.com/dotnet/release-metadata/releases-index.json'
# A .NET single-file exe carries its runtimeconfig.json inside: its apphost
# holds this signature, preceded by the bundle header's offset (Int64); the
# header gives the runtimeconfig's offset and size (manifest version 2 and
# later). The signature is searched for in the exe's first bytes only.
$SingleFileBundleSignature = '8b1202b96a612038727b930214d7a03213f5b9e6efae3318ee3b2dce24b36aae'
$SingleFileSignatureSearchBytes = 4MB
$RuntimeConfigMaximumBytes = 1MB
$DotNetExpectedSigner = '.NET'
$DotNetInstallArguments = @('/install', '/quiet', '/norestart')
$DotNetUninstallArguments = @('/uninstall', '/quiet', '/norestart')

# Other prerequisites, one row each, named by Capability in a catalogue row's
# Requires. Each is installed and kept at its latest version, in place, and
# never removed by this script (RemovalNote says why, and how by hand).
# Fields:
#   Capability, DisplayName
#   Source          VisualCppRedist: Microsoft's permanent link, which
#                     redirects to a URL holding the file's SHA-256
#                   ArsenalDriver: Arsenal's driver package on GitHub; its
#                     version from the last commit's message, its git blob
#                     hash from the API, the download pinned to that commit
#   Url             VisualCppRedist: the permanent link
#   Repository, RepositoryPath, Branch   ArsenalDriver: where the package is
#   ExpectedSigner  the installer's signer (ArsenalDriver: aim_ll.exe's)
#   DriverSigner    ArsenalDriver: the signer of the driver's catalogue, on
#                     whose strength Windows installs and loads the driver
#   InstallArguments  VisualCppRedist: for its installer
#   RemovalNote     why the script never removes it
$OtherPrerequisites = @(
    [pscustomobject]@{ Capability = 'VCRedist:x64'; DisplayName = 'Visual C++ Redistributable (x64)'; Source = 'VisualCppRedist'
        Url = 'https://aka.ms/vs/17/release/vc_redist.x64.exe'; ExpectedSigner = 'Microsoft Corporation'; InstallArguments = @('/install', '/quiet', '/norestart')
        RemovalNote = 'other programs share it' }
    [pscustomobject]@{ Capability = 'AimDriver'; DisplayName = 'Arsenal Image Mounter driver'; Source = 'ArsenalDriver'
        Repository = 'ArsenalRecon/Arsenal-Image-Mounter'; RepositoryPath = 'DriverSetup/DriverSetup.7z'; Branch = 'master'
        ExpectedSigner = 'Arsenal Consulting, Inc.'; DriverSigner = 'Microsoft Windows Hardware Compatibility Publisher'
        RemovalNote = "removing it needs a restart: run aim_ll.exe --uninstall from Arsenal's DriverSetup package, elevated, then restart" }
)
# The Visual C++ installer's success codes: 3010 a restart is needed, 1638
# a newer version is already installed.
$VcRedistSuccessExitCodes = @(0, 3010, 1638)
$VcRedistRegistryKeys = @('HKLM:\SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\VisualStudio\14.0\VC\Runtimes\x64')
# Arsenal's driver: the version in its package's commit message, the
# driver's service, and the files inside the package the script uses. The
# driver files' own embedded signatures are Arsenal's, with Microsoft's
# nested inside (which Get-AuthenticodeSignature never reads): what Windows
# goes by is the package's catalogue, signed by Microsoft, which names each
# file's hash. So the catalogue's signer is checked, and the INF and every
# binary in the driver folder are verified as members of it, as Windows
# verifies them (Test-CatalogueMember).
$ArsenalDriverVersionPattern = 'Driver/API (\d+(?:\.\d+){3})'
$ArsenalDriverService = 'phdskmnt'
$ArsenalDriverInstaller = 'cli\x64\aim_ll.exe'
$ArsenalDriverCatalogue = 'Win10\phdskmnt.cat'
$ArsenalDriverInf = 'Win10\phdskmnt.inf'
$ArsenalDriverFolder = 'Win10\x64'
$ArsenalDriverCataloguedPatterns = @('*.sys', '*.exe', '*.dll')    # every such file in the folder must be a member
# A catalogue's members are hashed with SHA-256 (older catalogues SHA-1):
# tried in this order.
$CatalogueHashAlgorithms = @('SHA256', 'SHA1')
# WinVerifyTrust's results, as it returns them (HRESULT, hex), and what each
# means for a catalogue member; one not listed is shown as its hex value.
$WinVerifyTrustResultNames = @{
    '80092004' = 'CRYPT_E_NOT_FOUND: not a member of the catalogue'
    '800B0100' = 'TRUST_E_NOSIGNATURE: the file is not in the catalogue, or the catalogue''s signature does not verify'
    '80092003' = 'CRYPT_E_FILE_ERROR: the catalogue can''t be read (damaged, or not a catalogue)'
    '80096010' = 'TRUST_E_BAD_DIGEST: the catalogue has been altered since it was signed'
    '800B0004' = 'TRUST_E_SUBJECT_NOT_TRUSTED: the catalogue is not trusted'
    '800B0101' = 'CERT_E_EXPIRED: a certificate in the catalogue signer''s chain has expired'
    '800B0109' = 'CERT_E_UNTRUSTEDROOT: the catalogue signer''s chain does not end in a trusted root'
    '800B010A' = 'CERT_E_CHAINING: the catalogue signer''s chain could not be built'
}

# --- Host ---
# The OS architecture, by machine type (Win32_Processor.Architecture, a
# number), as the run's header names it; the script runs only on X64.
$ProcessorArchitectureNames = @{ 0 = 'X86'; 5 = 'Arm'; 9 = 'X64'; 12 = 'Arm64' }
# The machine's own PROCESSOR_ARCHITECTURE (not the process's), the
# fallback, and the names it maps to.
$MachineEnvironmentKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
$ProcessorArchitectureRegistryNames = @{ 'AMD64' = 'X64'; 'ARM64' = 'Arm64'; 'x86' = 'X86' }

# --- Records ---
# Column names: part of the tool's contract once at 1.0 (AGENTS.md).
$InventoryColumns = @('Kind', 'Family', 'Name', 'Version', 'Build', 'Owned', 'SourceUrl', 'DownloadSha256', 'VendorHashAlgorithm', 'VendorHash', 'VendorHashMatched', 'Signer', 'ChangeMarker', 'InstalledUtc', 'Location')
$FilesColumns = @('Family', 'Tool', 'Class', 'RelativePath', 'Length', 'Sha256', 'RecordedUtc')
$StateSchemaVersion = 1

# ============================= FUNCTIONS =============================
#
# Conventions:
# - A function returns its outcome; script state is limited to the run log,
#   the console, the results and warnings lists, the network caches and the
#   state (see MAIN), each named where it is changed.
# - A function returning a list returns an array; callers wrap the call in
#   @() so one item and none behave like many.
# - Every path the script removes is checked first to lie inside a folder it
#   owns (Assert-PathInside): a record can never point a removal elsewhere.

# --- Text and console ---

# An error's message on one line, for the console and the log.
function Get-OneLineMessage {
    param($ErrorRecord)
    return (($ErrorRecord.Exception.Message -replace '\s*[\r\n]+\s*', ' ').Trim())
}

# Text as lines of at most $Width columns, broken at spaces: the first line
# starts at $Indent, continuation lines at $ContinuationIndent (shared rules:
# a wrapped line never starts where a new item would). A word longer than the
# room (a path, a hash) stays whole on its own line.
function Format-WrappedText {
    param([string]$Text, [int]$Indent = 0, [int]$ContinuationIndent = 2, [int]$Width = $script:ConsoleWidth)
    $lines = New-Object System.Collections.Generic.List[string]
    $current = ''
    $currentIndent = $Indent
    foreach ($word in ($Text -split ' ')) {
        if ($current -eq '') {
            $current = $word
            continue
        }
        if (($currentIndent + $current.Length + 1 + $word.Length) -le $Width) {
            $current = "$current $word"
        } else {
            $lines.Add((' ' * $currentIndent) + $current)
            $currentIndent = $ContinuationIndent
            $current = $word
        }
    }
    $lines.Add((' ' * $currentIndent) + $current)
    return $lines.ToArray()
}

# A path (or other value that must not be broken) for a message: its spaces
# become a placeholder the wrapping doesn't break at, turned back into
# spaces when the line is written (shared rules: a path may run past 80
# columns rather than be split).
function Format-Unbreakable {
    param([string]$Text)
    return $Text.Replace(' ', $script:UnbreakableSpace)
}

# A version as shown in the console: without the build metadata after "+"
# (the Zimmerman tools' commit id); the records keep the whole string.
function Format-DisplayVersion {
    param([string]$Version)
    return ($Version -split '\+', 2)[0]
}

# Print one line as it is and keep it in the run log, without colour codes.
function Write-RawLine {
    param([string]$Text = '', [string]$Colour = '')
    $Text = $Text.Replace($script:UnbreakableSpace, ' ')
    if ($Colour -and $script:useColour) { Write-Host $Text -ForegroundColor $Colour } else { Write-Host $Text }
    Add-LogLine -Text $Text
}

# Print text, wrapped, and keep it in the run log.
function Write-ConsoleLine {
    param([string]$Text = '', [int]$Indent = 0, [int]$ContinuationIndent = -1, [string]$Colour = '')
    if ($ContinuationIndent -lt 0) { $ContinuationIndent = $Indent + 2 }
    foreach ($line in @(Format-WrappedText -Text $Text -Indent $Indent -ContinuationIndent $ContinuationIndent)) {
        Write-RawLine -Text $line -Colour $Colour
    }
}

# One line in the log (the console has it already). Until the log file
# exists, lines are kept and written when it is created (MAIN).
function Add-LogLine {
    param([string]$Text)
    if ($script:logPath) {
        try { [System.IO.File]::AppendAllText($script:logPath, $Text + "`r`n", $script:utf8NoBom) } catch {}
    } else {
        $script:pendingLogLines.Add($Text)
    }
}

# A "Label : value" line. A wrapped value continues one column right of where
# the value starts (shared rules), so it can't be read as a new label.
function Write-LabelValue {
    param([string]$Label, [string]$Value, [int]$LabelWidth = 10)
    $prefix = $Label.PadRight($LabelWidth) + ' : '
    $lines = @(Format-WrappedText -Text $Value -Indent $prefix.Length -ContinuationIndent ($prefix.Length + 1))
    Write-RawLine -Text ($prefix + $lines[0].Substring($prefix.Length))
    for ($index = 1; $index -lt $lines.Count; $index++) { Write-RawLine -Text $lines[$index] }
}

# Stop before any work, with the reason and, where given, a list (one item
# per line) (exit code 3).
function Stop-Run {
    param([string]$Reason, [string[]]$List = @())
    Write-ConsoleLine -Text ''
    Write-ConsoleLine -Text "Stopped before any work: $Reason" -ContinuationIndent 2
    foreach ($item in $List) { Write-ConsoleLine -Text "- $item" -Indent 2 -ContinuationIndent 4 }
    exit 3
}

# A section opens the same way every time: a blank line, a rule, the title.
function Write-SectionHeading {
    param([string]$Title)
    Write-ConsoleLine -Text ''
    Write-ConsoleLine -Text ('-' * $script:ConsoleWidth)
    Write-ConsoleLine -Text $Title
}

# The console colour of a status word: emphasis only, the word is always
# there (shared rules).
function Get-StatusColour {
    param([string]$Status)
    switch ($Status) {
        'PASS' { return 'Green' }
        'WARN' { return 'Yellow' }
        'FAIL' { return 'Red' }
    }
    return ''
}

# "  PASS  text": the status word in colour, the rest plain, wrapped with the
# continuation two columns right of the text's start.
function Write-StatusLine {
    param([string]$Status, [string]$Text, [int]$Indent = 2)
    $prefix = (' ' * $Indent) + $Status.PadRight(6)
    $lines = @(Format-WrappedText -Text $Text -Indent 0 -ContinuationIndent 0 -Width ($script:ConsoleWidth - $prefix.Length - 2))
    $colour = Get-StatusColour -Status $Status
    if ($colour -and $script:useColour) {
        $firstLine = $lines[0].Replace($script:UnbreakableSpace, ' ')
        Write-Host (' ' * $Indent) -NoNewline
        Write-Host $Status -ForegroundColor $colour -NoNewline
        Write-Host ((' ' * (6 - $Status.Length)) + $firstLine)
        Add-LogLine -Text ($prefix + $firstLine)
    } else {
        Write-RawLine -Text ($prefix + $lines[0])
    }
    for ($index = 1; $index -lt $lines.Count; $index++) { Write-RawLine -Text ((' ' * ($prefix.Length + 2)) + $lines[$index]) }
}

# One line of the plan: the action in a column of its own, then what it acts
# on.
function Format-PlanLine {
    param([string]$Action, [string]$Text)
    return ($Action.PadRight($script:PlanActionWidth) + $Text)
}

# The line under an update section with nothing to act on, so it isn't left
# empty: "Nothing to install or update." (or the section's own words, such
# as "Nothing to sync.") only when every check is current;
# otherwise the checks that couldn't be acted on are pointed to (never read
# as all done).
function Write-NothingToDoLine {
    param([string[]]$Statuses, [string[]]$NoActionStatuses, [string]$NothingText = 'Nothing to install or update.')
    if (@($Statuses | Where-Object { $NoActionStatuses -notcontains $_ }).Count -gt 0) { return }
    if (@($Statuses | Where-Object { $_ -ne 'Current' }).Count -eq 0) {
        Write-ConsoleLine -Text $NothingText -Indent 2
    } else {
        Write-ConsoleLine -Text 'Nothing installed (see Warnings and Failures).' -Indent 2
    }
}

# One line of Checking sources: the name in a column of its own, then the
# check's outcome. A name longer than the column has its line to itself and
# the outcome starts the next line at the outcome's column.
function Write-CheckLine {
    param([string]$Name, [string]$Detail)
    $detailColumn = 2 + $script:CheckNameWidth + 1
    if ($Name.Length -gt $script:CheckNameWidth) {
        Write-ConsoleLine -Text $Name -Indent 2
        Write-ConsoleLine -Text $Detail -Indent $detailColumn -ContinuationIndent $detailColumn
        return
    }
    Write-ConsoleLine -Text ($Name.PadRight($script:CheckNameWidth) + ' ' + $Detail) -Indent 2 -ContinuationIndent $detailColumn
}

# The status a check gives in a dry run's result: is the workstation
# current? Anything that would change, or couldn't be checked, is a WARN; a
# tool its vendor no longer offers is a FAIL.
function Get-CheckStatus {
    param([string]$CheckStatus)
    switch ($CheckStatus) {
        'Current'     { return 'PASS' }
        'Unavailable' { return 'FAIL' }
    }
    return 'WARN'
}

# One CSV line: every cell quoted, a quote inside a cell doubled (RFC 4180).
function ConvertTo-CsvLine {
    param([object[]]$Cells)
    $quotedCells = foreach ($cell in $Cells) { '"' + ([string]$cell -replace '"', '""') + '"' }
    return ($quotedCells -join ',')
}

# A time for the records: ISO 8601, UTC, trailing Z.
function Format-UtcTime {
    param([DateTime]$Time)
    return $Time.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
}

# --- Results and warnings ---

# Record an item's outcome for the result block. Group: a family, or
# 'Prerequisites', 'Ancillary content', 'PATH and shortcuts', 'Clean-up',
# 'Records'.
function Add-Result {
    param([string]$Group, [string]$Name, [string]$Status, [string]$Detail)
    $script:results.Add([pscustomobject]@{ Group = $Group; Name = $Name; Status = $Status; Detail = $Detail })
}

# Add a warning to the Warnings list, printed before the result block.
function Add-RunWarning {
    param([string]$Message)
    $script:runWarnings.Add($Message)
}

# Add a failure to the Failures list, printed before the result block.
function Add-RunFailure {
    param([string]$Message)
    $script:runFailures.Add($Message)
}

# The worst of a set of statuses (FAIL > WARN > PASS); none is a FAIL, since
# a check that covers nothing has shown nothing.
function Get-WorstStatus {
    param([string[]]$Statuses)
    if (-not $Statuses -or $Statuses.Count -eq 0) { return 'FAIL' }
    if ($Statuses -contains 'FAIL') { return 'FAIL' }
    if ($Statuses -contains 'WARN') { return 'WARN' }
    return 'PASS'
}

# --- Host facts ---

# A registry value, or $null when it (or its key) is missing.
function Get-RegistryValue {
    param([string]$Path, [string]$Name)
    try {
        return (Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop).$Name
    } catch { return $null }
}

# The OS as a person names it (shared rules): CIM's caption plus the release
# (DisplayVersion, else ReleaseId); without CIM, "Microsoft " + the registry's
# ProductName, corrected from Windows 10 to 11 from build 22000.
function Get-OsName {
    $currentVersionKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $caption = $null
    try { $caption = (Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop).Caption.Trim() } catch {}
    $release = Get-RegistryValue -Path $currentVersionKey -Name 'DisplayVersion'
    if (-not $release) { $release = Get-RegistryValue -Path $currentVersionKey -Name 'ReleaseId' }
    if (-not $caption) {
        $productName = Get-RegistryValue -Path $currentVersionKey -Name 'ProductName'
        $build = Get-RegistryValue -Path $currentVersionKey -Name 'CurrentBuild'
        if ($productName) {
            $caption = 'Microsoft ' + $productName
            if ($build -and [int]$build -ge 22000) { $caption = $caption -replace 'Windows 10', 'Windows 11' }
        }
    }
    if (-not $caption) { return 'unknown' }
    if ($release) { return "$caption $release" }
    return $caption
}

# The OS architecture (X64, Arm64, ...), not the process's (an x64
# PowerShell on ARM64 Windows has AMD64 in its own environment). From the
# processor's machine type, else the machine's PROCESSOR_ARCHITECTURE in
# the registry; an empty or unknown answer falls through to the next
# source, and "unknown" when none answers. Not
# [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture: at
# an interactive prompt PSReadLine's own type of that name hides .NET's and
# answers nothing.
function Get-OsArchitecture {
    try {
        $processor = @(Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop) | Select-Object -First 1
        if ($processor -and $null -ne $processor.Architecture -and $script:ProcessorArchitectureNames.ContainsKey([int]$processor.Architecture)) {
            return $script:ProcessorArchitectureNames[[int]$processor.Architecture]
        }
    } catch {}
    $registryArchitecture = [string](Get-RegistryValue -Path $script:MachineEnvironmentKey -Name 'PROCESSOR_ARCHITECTURE')
    if ($registryArchitecture -and $script:ProcessorArchitectureRegistryNames.ContainsKey($registryArchitecture)) { return $script:ProcessorArchitectureRegistryNames[$registryArchitecture] }
    if ($registryArchitecture) { return $registryArchitecture }
    return 'unknown'
}

function Test-Elevated {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# --- Hashes and signatures ---

# A file's hash as lower-case hex (SHA256 or SHA512), read with sharing so a
# file in use can still be hashed.
function Get-FileHashHex {
    param([string]$Path, [string]$Algorithm = 'SHA256')
    $stream = $null
    $hasher = $null
    try {
        $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        $hasher = [System.Security.Cryptography.HashAlgorithm]::Create($Algorithm)
        $digest = $hasher.ComputeHash($stream)
        return (($digest | ForEach-Object { $_.ToString('x2') }) -join '')
    } finally {
        if ($hasher) { try { $hasher.Dispose() } catch {} }
        if ($stream) { try { $stream.Dispose() } catch {} }
    }
}

# A file's git blob hash: SHA-1 over "blob <length>", a NUL byte, then the
# file's bytes (GitHub's contents API gives it for each file).
function Get-GitBlobSha1 {
    param([string]$Path)
    $stream = $null
    $hasher = $null
    try {
        $stream = [System.IO.File]::OpenRead($Path)
        $hasher = [System.Security.Cryptography.SHA1]::Create()
        $header = [System.Text.Encoding]::ASCII.GetBytes("blob $($stream.Length)") + [byte[]]@(0)
        $null = $hasher.TransformBlock($header, 0, $header.Length, $null, 0)
        $buffer = New-Object byte[] 1048576
        while (($read = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) { $null = $hasher.TransformBlock($buffer, 0, $read, $null, 0) }
        $null = $hasher.TransformFinalBlock($buffer, 0, 0)
        return (($hasher.Hash | ForEach-Object { $_.ToString('x2') }) -join '')
    } finally {
        if ($hasher) { try { $hasher.Dispose() } catch {} }
        if ($stream) { try { $stream.Dispose() } catch {} }
    }
}

# A file's Authenticode signature: Status (Valid, NotSigned, HashMismatch,
# ...) and the signer certificate's CN.
function Get-SignerInfo {
    param([string]$Path)
    $signature = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
    $subject = ''
    if ($signature.SignerCertificate) {
        $subject = $signature.SignerCertificate.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
    }
    return [pscustomobject]@{ Status = [string]$signature.Status; Subject = $subject }
}

# Whether a signature is acceptable: valid and by the expected signer, or
# (where allowed) not signed at all. Returns Accepted and a description for
# the records ("ZimTech LLC (valid)", "unsigned", ...).
function Test-SignerAccepted {
    param($SignerInfo, [string]$ExpectedSigner, [bool]$UnsignedAllowed)
    if ($SignerInfo.Status -eq 'NotSigned') {
        return [pscustomobject]@{ Accepted = $UnsignedAllowed; Description = 'unsigned' }
    }
    $description = "$($SignerInfo.Subject) ($($SignerInfo.Status))"
    $accepted = ($SignerInfo.Status -eq 'Valid' -and $SignerInfo.Subject -eq $ExpectedSigner)
    return [pscustomobject]@{ Accepted = $accepted; Description = $description }
}

# Windows' own verifier for a file against a signed catalogue, the check
# Windows makes when a driver package is installed: WinVerifyTrust with
# WINTRUST_CATALOG_INFO verifies the catalogue's signature chain to a trusted
# root and that the file's hash is among the catalogue's members. The hash
# is computed as Windows computes it (CryptCATAdminCalcHashFromFileHandle2:
# the Authenticode hash of an executable, the plain hash of any other file).
# No revocation check and no network (the same as Get-AuthenticodeSignature,
# which the other signer checks use). Loaded once, on first use.
function Add-CatalogueMemberType {
    if ('ForensicWorkstation.CatalogueMember' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;

namespace ForensicWorkstation
{
    public static class CatalogueMember
    {
        [StructLayout(LayoutKind.Sequential)]
        struct WINTRUST_CATALOG_INFO
        {
            public uint cbStruct;
            public uint dwCatalogVersion;
            [MarshalAs(UnmanagedType.LPWStr)] public string pcwszCatalogFilePath;
            [MarshalAs(UnmanagedType.LPWStr)] public string pcwszMemberTag;
            [MarshalAs(UnmanagedType.LPWStr)] public string pcwszMemberFilePath;
            public IntPtr hMemberFile;
            public IntPtr pbCalculatedFileHash;
            public uint cbCalculatedFileHash;
            public IntPtr pcCatalogContext;
            public IntPtr hCatAdmin;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct WINTRUST_DATA
        {
            public uint cbStruct;
            public IntPtr pPolicyCallbackData;
            public IntPtr pSIPClientData;
            public uint dwUIChoice;
            public uint fdwRevocationChecks;
            public uint dwUnionChoice;
            public IntPtr pCatalog;          // the union: WINTRUST_CATALOG_INFO here
            public uint dwStateAction;
            public IntPtr hWVTStateData;
            public IntPtr pwszURLReference;
            public uint dwProvFlags;
            public uint dwUIContext;
            public IntPtr pSignatureSettings;
        }

        [DllImport("wintrust.dll", CharSet = CharSet.Unicode)]
        static extern int WinVerifyTrust(IntPtr hwnd, [MarshalAs(UnmanagedType.LPStruct)] Guid pgActionID, IntPtr pWVTData);

        [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool CryptCATAdminAcquireContext2(out IntPtr phCatAdmin, IntPtr pgSubsystem, string pwszHashAlgorithm, IntPtr pStrongHashPolicy, uint dwFlags);

        [DllImport("wintrust.dll", SetLastError = true)]
        static extern bool CryptCATAdminCalcHashFromFileHandle2(IntPtr hCatAdmin, IntPtr hFile, ref uint pcbHash, byte[] pbHash, uint dwFlags);

        [DllImport("wintrust.dll", SetLastError = true)]
        static extern bool CryptCATAdminReleaseContext(IntPtr hCatAdmin, uint dwFlags);

        static readonly Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 = new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
        const uint WTD_UI_NONE = 2;
        const uint WTD_REVOKE_NONE = 0;
        const uint WTD_CHOICE_CATALOG = 2;
        const uint WTD_STATEACTION_IGNORE = 0;
        const uint WTD_REVOCATION_CHECK_NONE = 0x00000010;
        const uint WTD_CACHE_ONLY_URL_RETRIEVAL = 0x00001000;

        // 0 when the catalogue's signature is valid and the file is one of its
        // members; otherwise WinVerifyTrust's HRESULT.
        public static int Verify(string cataloguePath, string memberPath, string hashAlgorithm)
        {
            IntPtr catalogueAdmin;
            if (!CryptCATAdminAcquireContext2(out catalogueAdmin, IntPtr.Zero, hashAlgorithm, IntPtr.Zero, 0))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            try
            {
                byte[] hash = HashAsWindowsDoes(catalogueAdmin, memberPath);
                string memberTag = BitConverter.ToString(hash).Replace("-", "");
                IntPtr hashBuffer = Marshal.AllocHGlobal(hash.Length);
                IntPtr catalogueInfoBuffer = IntPtr.Zero;
                IntPtr dataBuffer = IntPtr.Zero;
                try
                {
                    Marshal.Copy(hash, 0, hashBuffer, hash.Length);
                    WINTRUST_CATALOG_INFO catalogueInfo = new WINTRUST_CATALOG_INFO();
                    catalogueInfo.cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_CATALOG_INFO));
                    catalogueInfo.pcwszCatalogFilePath = cataloguePath;
                    catalogueInfo.pcwszMemberTag = memberTag;
                    catalogueInfo.pcwszMemberFilePath = memberPath;
                    catalogueInfo.pbCalculatedFileHash = hashBuffer;
                    catalogueInfo.cbCalculatedFileHash = (uint)hash.Length;
                    catalogueInfo.hCatAdmin = catalogueAdmin;
                    catalogueInfoBuffer = Marshal.AllocHGlobal((int)catalogueInfo.cbStruct);
                    Marshal.StructureToPtr(catalogueInfo, catalogueInfoBuffer, false);

                    WINTRUST_DATA data = new WINTRUST_DATA();
                    data.cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_DATA));
                    data.dwUIChoice = WTD_UI_NONE;
                    data.fdwRevocationChecks = WTD_REVOKE_NONE;
                    data.dwUnionChoice = WTD_CHOICE_CATALOG;
                    data.pCatalog = catalogueInfoBuffer;
                    data.dwStateAction = WTD_STATEACTION_IGNORE;
                    data.dwProvFlags = WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL;
                    dataBuffer = Marshal.AllocHGlobal((int)data.cbStruct);
                    Marshal.StructureToPtr(data, dataBuffer, false);

                    return WinVerifyTrust(IntPtr.Zero, WINTRUST_ACTION_GENERIC_VERIFY_V2, dataBuffer);
                }
                finally
                {
                    if (dataBuffer != IntPtr.Zero) { Marshal.FreeHGlobal(dataBuffer); }
                    if (catalogueInfoBuffer != IntPtr.Zero)
                    {
                        Marshal.DestroyStructure(catalogueInfoBuffer, typeof(WINTRUST_CATALOG_INFO));   // frees the strings it copied
                        Marshal.FreeHGlobal(catalogueInfoBuffer);
                    }
                    Marshal.FreeHGlobal(hashBuffer);
                }
            }
            finally
            {
                CryptCATAdminReleaseContext(catalogueAdmin, 0);
            }
        }

        // The file's hash as a catalogue member tag: asked once for its size,
        // then computed.
        static byte[] HashAsWindowsDoes(IntPtr catalogueAdmin, string path)
        {
            using (FileStream file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                IntPtr handle = file.SafeFileHandle.DangerousGetHandle();
                uint size = 0;
                CryptCATAdminCalcHashFromFileHandle2(catalogueAdmin, handle, ref size, null, 0);
                if (size == 0) { throw new Win32Exception(Marshal.GetLastWin32Error()); }
                byte[] hash = new byte[size];
                if (!CryptCATAdminCalcHashFromFileHandle2(catalogueAdmin, handle, ref size, hash, 0))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
                return hash;
            }
        }
    }
}
'@ -ErrorAction Stop
}

# A WinVerifyTrust result for the records: its hex value and, where known,
# its name and meaning.
function Get-WinVerifyTrustResultName {
    param([int]$Result)
    $hex = '{0:X8}' -f $Result
    if ($script:WinVerifyTrustResultNames.ContainsKey($hex)) { return "0x$hex ($($script:WinVerifyTrustResultNames[$hex]))" }
    return "0x$hex (a WinVerifyTrust result not listed in the script)"
}

# Whether a file is a member of a signed catalogue, by Windows' own verdict
# (Add-CatalogueMemberType), with each hash algorithm the catalogue may use.
# Returns Accepted and a description for the records; a refusal reports the
# first algorithm's result (SHA-256, the catalogues' own), and another
# algorithm's only where it differs.
function Test-CatalogueMember {
    param([string]$CataloguePath, [string]$MemberPath)
    Add-CatalogueMemberType
    $refusals = New-Object System.Collections.Generic.List[object]
    foreach ($algorithm in $script:CatalogueHashAlgorithms) {
        $result = [ForensicWorkstation.CatalogueMember]::Verify($CataloguePath, $MemberPath, $algorithm)
        if ($result -eq 0) { return [pscustomobject]@{ Accepted = $true; Description = "a member ($algorithm)" } }
        $refusals.Add([pscustomobject]@{ Algorithm = $algorithm; Result = $result })
    }
    $description = Get-WinVerifyTrustResultName -Result $refusals[0].Result
    foreach ($other in @($refusals | Select-Object -Skip 1 | Where-Object { $_.Result -ne $refusals[0].Result })) {
        $description += "; with $($other.Algorithm): $(Get-WinVerifyTrustResultName -Result $other.Result)"
    }
    return [pscustomobject]@{ Accepted = $false; Description = $description }
}

# --- Paths ---

# Throws unless $Path lies inside $Root: every removal goes through this, so
# no record or name can point a removal outside the script's own folders.
function Assert-PathInside {
    param([string]$Path, [string]$Root)
    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $fullRoot = [System.IO.Path]::GetFullPath($Root).TrimEnd('\') + '\'
    if (-not $fullPath.StartsWith($fullRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "refused: '$fullPath' is outside '$fullRoot'"
    }
}

# Remove a folder the script owns (inside $Root), with everything in it.
function Remove-OwnedFolder {
    param([string]$Path, [string]$Root)
    Assert-PathInside -Path $Path -Root $Root
    if ([System.IO.Directory]::Exists($Path)) { [System.IO.Directory]::Delete($Path, $true) }
}

# Remove a file the script owns (inside $Root).
function Remove-OwnedFile {
    param([string]$Path, [string]$Root)
    Assert-PathInside -Path $Path -Root $Root
    if ([System.IO.File]::Exists($Path)) { [System.IO.File]::Delete($Path) }
}

# The path of $Path relative to $Root (inside it), with backslashes.
function Get-RelativePath {
    param([string]$Path, [string]$Root)
    $fullRoot = [System.IO.Path]::GetFullPath($Root).TrimEnd('\') + '\'
    return [System.IO.Path]::GetFullPath($Path).Substring($fullRoot.Length)
}

# Create the records folder with an ACL of its own: Administrators and
# SYSTEM full control, Users read. ProgramData's inherited ACL would let any
# user add files to it.
function New-ProtectedFolder {
    param([string]$Path)
    if (-not [System.IO.Directory]::Exists($Path)) { $null = [System.IO.Directory]::CreateDirectory($Path) }
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $inherit = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    $propagate = [System.Security.AccessControl.PropagationFlags]::None
    $grants = @(
        @{ Sid = 'S-1-5-32-544'; Rights = 'FullControl' }       # BUILTIN\Administrators
        @{ Sid = 'S-1-5-18';     Rights = 'FullControl' }       # NT AUTHORITY\SYSTEM
        @{ Sid = 'S-1-5-32-545'; Rights = 'ReadAndExecute' }    # BUILTIN\Users
    )
    foreach ($grant in $grants) {
        $identity = New-Object System.Security.Principal.SecurityIdentifier($grant.Sid)
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($identity, $grant.Rights, $inherit, $propagate, 'Allow')
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $Path -AclObject $acl -ErrorAction Stop
}

# Let the running account modify one folder inside a tool's folder (settings
# a GUI tool writes beside its exe). Never used for a folder on PATH.
function Grant-WritablePath {
    param([string]$Path)
    if (-not [System.IO.Directory]::Exists($Path)) { $null = [System.IO.Directory]::CreateDirectory($Path) }
    $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    $inherit = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($identity, 'Modify', $inherit, [System.Security.AccessControl.PropagationFlags]::None, 'Allow')
    $acl.AddAccessRule($rule)
    Set-Acl -LiteralPath $Path -AclObject $acl -ErrorAction Stop
}

# Let the running account modify one file inside a tool's folder, and
# nothing else there: the file is created empty if missing (NirSoft tools
# read and write their <tool>.cfg in place).
function Grant-WritableFile {
    param([string]$Path)
    if (-not [System.IO.File]::Exists($Path)) { [System.IO.File]::WriteAllBytes($Path, [byte[]]@()) }
    $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($identity, 'Modify', 'Allow')
    $acl.AddAccessRule($rule)
    Set-Acl -LiteralPath $Path -AclObject $acl -ErrorAction Stop
}

# --- State ---
# state.json records what the script installed and owns. It is read as plain
# hashtables and arrays (ConvertFrom-Json gives PSCustomObjects in 5.1).

function ConvertTo-PlainData {
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [System.Management.Automation.PSCustomObject]) {
        $table = @{}
        foreach ($property in $Value.PSObject.Properties) { $table[$property.Name] = ConvertTo-PlainData -Value $property.Value }
        return $table
    }
    if ($Value -is [System.Array]) {
        $items = @(foreach ($item in $Value) { ConvertTo-PlainData -Value $item })
        return , $items
    }
    return $Value
}

function New-EmptyState {
    return @{ SchemaVersion = $script:StateSchemaVersion; Tools = @{}; Prerequisites = @{}; Ancillary = @{}; PathEntries = @(); ShortcutFolders = @() }
}

# The state, or a new empty one when there is no file yet. A file that can't
# be read stops the run: without it the script can't tell what it owns.
function Read-State {
    param([string]$Path)
    if (-not [System.IO.File]::Exists($Path)) { return (New-EmptyState) }
    $text = [System.IO.File]::ReadAllText($Path)
    $state = ConvertTo-PlainData -Value (ConvertFrom-Json -InputObject $text -ErrorAction Stop)
    if ($state.SchemaVersion -ne $script:StateSchemaVersion) { throw "state.json has schema version $($state.SchemaVersion), expected $($script:StateSchemaVersion)" }
    # An empty JSON array can come back as $null in 5.1: every list is made a
    # list again, so loops over it never see a $null item.
    foreach ($key in @('Tools', 'Prerequisites', 'Ancillary')) { if ($null -eq $state[$key]) { $state[$key] = @{} } }
    foreach ($key in @('PathEntries', 'ShortcutFolders')) { $state[$key] = @($state[$key] | Where-Object { $_ }) }
    foreach ($record in @($state.Tools.Values)) {
        $record.Shortcuts = @($record.Shortcuts | Where-Object { $_ })
        $record.Files = @($record.Files | Where-Object { $_ })
    }
    foreach ($record in @($state.Prerequisites.Values)) { if ($null -eq $record.Versions) { $record.Versions = @{} } }
    return $state
}

# Write the state: after every change, so a run that stops part-way still
# knows what it owns. Written to a temporary file first, then moved over.
function Save-State {
    param($State, [string]$Path)
    $json = ConvertTo-Json -InputObject $State -Depth 12
    $temporaryPath = "$Path.new"
    [System.IO.File]::WriteAllText($temporaryPath, (($json -replace "`r?`n", "`r`n") + "`r`n"), $script:utf8NoBom)
    # No backup file: File.Replace takes a null backup path. PowerShell 5.1
    # passes $null to a .NET string as '' (which File.Replace refuses), so
    # the null is [NullString]::Value.
    if ([System.IO.File]::Exists($Path)) { [System.IO.File]::Replace($temporaryPath, $Path, [NullString]::Value) } else { [System.IO.File]::Move($temporaryPath, $Path) }
}

# --- Network ---
# Every request has a timeout and uses basic parsing (no Internet Explorer
# engine). A failure throws, except Invoke-HttpHead's "not found" (a build
# that doesn't exist, e.g. no x64 zip).

function Invoke-HttpHead {
    param([string]$Uri)
    try {
        $response = Invoke-WebRequest -Uri $Uri -Method Head -UseBasicParsing -TimeoutSec $script:HttpTimeoutSeconds -ErrorAction Stop
    } catch [System.Net.WebException] {
        $httpResponse = $_.Exception.Response
        if ($httpResponse -and [int]$httpResponse.StatusCode -eq 404) { return $null }
        throw
    }
    return [pscustomobject]@{
        ETag          = Get-HeaderValue -Headers $response.Headers -Name 'ETag'
        LastModified  = Get-HeaderValue -Headers $response.Headers -Name 'Last-Modified'
        ContentLength = Get-HeaderValue -Headers $response.Headers -Name 'Content-Length'
    }
}

# A response header's value, its name matched without regard to case, or ''
# when the server didn't send it.
function Get-HeaderValue {
    param($Headers, [string]$Name)
    foreach ($key in @($Headers.Keys)) {
        if ($key -ieq $Name) { return [string]$Headers[$key] }
    }
    return ''
}

function Get-HttpText {
    param([string]$Uri)
    return (Invoke-WebRequest -Uri $Uri -UseBasicParsing -TimeoutSec $script:HttpTimeoutSeconds -ErrorAction Stop).Content
}

function Get-HttpJson {
    param([string]$Uri, [hashtable]$Headers = @{})
    $response = Invoke-WebRequest -Uri $Uri -Headers $Headers -UseBasicParsing -TimeoutSec $script:HttpTimeoutSeconds -ErrorAction Stop
    return (ConvertFrom-Json -InputObject $response.Content -ErrorAction Stop)
}

# A GitHub REST API call (unauthenticated: 60 calls an hour, a run needs
# about six).
function Get-GitHubJson {
    param([string]$Path)
    $headers = @{ 'Accept' = 'application/vnd.github+json'; 'X-GitHub-Api-Version' = '2022-11-28' }
    return (Get-HttpJson -Uri ($script:GitHubApiRoot + $Path) -Headers $headers)
}

function Save-HttpFile {
    param([string]$Uri, [string]$Path)
    Invoke-WebRequest -Uri $Uri -OutFile $Path -UseBasicParsing -TimeoutSec ($script:HttpTimeoutSeconds * 10) -ErrorAction Stop
}

# A version string ("v2.3.1.1000", "5.19", "9.0.21") as [version], or $null.
function ConvertTo-VersionOrNull {
    param([string]$Text)
    $match = [regex]::Match($Text, '^v?(\d+(?:\.\d+){1,3})$')
    if (-not $match.Success) { return $null }
    $parts = $match.Groups[1].Value
    if ($parts -notmatch '\.') { $parts = "$parts.0" }
    return [version]$parts
}

# --- Source adapters ---
# Each returns what the source offers now ("remote"): Available, Version (if
# the source says), Build, Marker (the change marker compared with the one
# recorded at install), Url, FileName, VendorHashAlgorithm and VendorHash
# (where the vendor publishes one), Detail (why it isn't available, or what
# to download by hand), LocalFile (a file downloaded by hand, used in place
# of a download) and NeedsManualDownload (that file isn't there yet).

function New-Remote {
    param([bool]$Available, [string]$Version = '', [string]$Build = '', [string]$Marker = '', [string]$Url = '', [string]$FileName = '',
        [string]$VendorHashAlgorithm = '', [string]$VendorHash = '', [string]$Detail = '', [string]$LocalFile = '', [bool]$NeedsManualDownload = $false)
    return [pscustomobject]@{ Available = $Available; Version = $Version; Build = $Build; Marker = $Marker; Url = $Url; FileName = $FileName
        VendorHashAlgorithm = $VendorHashAlgorithm; VendorHash = $VendorHash; Detail = $Detail; LocalFile = $LocalFile; NeedsManualDownload = $NeedsManualDownload }
}

# The marker of a download from its HTTP headers: every header the server
# gives, so any change on the server means a download.
function Get-HeaderMarker {
    param($Head)
    return "$($Head.ETag)|$($Head.LastModified)|$($Head.ContentLength)"
}

# The Zimmerman index: for each zip on the vendor's page, the newest .NET
# line it is offered for and its URL. A /net/ link is the line the page's
# table header names; a page with such links and no such header can't be
# read (the line would be a guess). Read once per run ($script:ezIndex).
function Get-EzToolIndex {
    if ($script:ezIndex) { return $script:ezIndex }
    $text = Get-HttpText -Uri $script:EzIndexUrl
    $currentLine = 0
    $headerMatch = [regex]::Match($text, $script:EzCurrentLinePattern, 'IgnoreCase')
    if ($headerMatch.Success) { $currentLine = [int]$headerMatch.Groups[1].Value }
    $index = @{}
    foreach ($match in [regex]::Matches($text, $script:EzDownloadPattern, 'IgnoreCase')) {
        if ($match.Groups[1].Value) {
            $line = [int]$match.Groups[1].Value
        } elseif ($currentLine -gt 0) {
            $line = $currentLine
        } else {
            throw "$($script:EzIndexUrl) links /net/ builds but doesn't say which .NET line they are: the page's format may have changed"
        }
        $zipName = $match.Groups[2].Value
        $key = $zipName.ToLowerInvariant()
        if (-not $index.ContainsKey($key) -or $index[$key].Line -lt $line) {
            $index[$key] = [pscustomobject]@{ Line = $line; Url = $match.Value; ZipName = $zipName }
        }
    }
    if ($index.Count -eq 0) { throw "no tool downloads found on $($script:EzIndexUrl): the page's format may have changed" }
    $script:ezIndex = $index
    return $index
}

function Get-EzToolRemote {
    param($CatalogueTool)
    $index = Get-EzToolIndex
    $entry = $index[$CatalogueTool.Package.ToLowerInvariant()]
    if (-not $entry) { return (New-Remote -Available $false -Detail "not on the vendor's page") }
    $head = Invoke-HttpHead -Uri $entry.Url
    if (-not $head) { return (New-Remote -Available $false -Detail "listed but not downloadable: $($entry.Url)") }
    return (New-Remote -Available $true -Build "net$($entry.Line)" -Marker ("net$($entry.Line)|" + (Get-HeaderMarker -Head $head)) -Url $entry.Url -FileName $entry.ZipName)
}

# Zips on the Zimmerman page in a .NET line that the catalogue doesn't list:
# reported as "available, not in the catalogue", never installed.
function Get-EzToolNotInCatalogue {
    $index = Get-EzToolIndex
    $known = @($script:Catalogue | Where-Object { $_.Source -eq 'EZTools' } | ForEach-Object { $_.Package.ToLowerInvariant() })
    $outOfScope = @($script:EzOutOfScope | ForEach-Object { $_.ToLowerInvariant() })
    $unknown = foreach ($key in $index.Keys) {
        if ($known -notcontains $key -and $outOfScope -notcontains $key) { $index[$key].ZipName }
    }
    return @($unknown | Sort-Object)
}

function Get-NirSoftRemote {
    param($CatalogueTool)
    $pad = Get-HttpText -Uri ($script:NirSoftPadUrl -f $CatalogueTool.Package)
    $versionMatch = [regex]::Match($pad, '<Program_Version>([^<]+)</Program_Version>')
    if (-not $versionMatch.Success) { throw "no version in the PAD file for $($CatalogueTool.Package)" }
    $version = $versionMatch.Groups[1].Value.Trim()
    foreach ($build in $script:NirSoftBuilds) {
        $url = $script:NirSoftZipUrl -f $CatalogueTool.Package, $build.Suffix
        $head = Invoke-HttpHead -Uri $url
        if ($head) {
            $marker = "$version|$($build.Build)|$($head.LastModified)|$($head.ContentLength)"
            return (New-Remote -Available $true -Version $version -Build $build.Build -Marker $marker -Url $url -FileName "$($CatalogueTool.Package)$($build.Suffix).zip")
        }
    }
    return (New-Remote -Available $false -Detail 'no build found (x64 or x86)')
}

function Get-SysinternalsRemote {
    param($CatalogueTool)
    $url = $script:SysinternalsZipUrl -f $CatalogueTool.Package
    $head = Invoke-HttpHead -Uri $url
    if (-not $head) { return (New-Remote -Available $false -Detail "not found: $url") }
    return (New-Remote -Available $true -Build 'x64' -Marker (Get-HeaderMarker -Head $head) -Url $url -FileName $CatalogueTool.Package)
}

# The account's Downloads folder (the known folder, wherever it was moved;
# else the profile's Downloads).
function Get-DownloadsFolder {
    $configured = Get-RegistryValue -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -Name '{374DE290-123F-4565-9164-39C4925E467B}'
    if ($configured) { return [Environment]::ExpandEnvironmentVariables($configured) }
    return (Join-Path $env:USERPROFILE 'Downloads')
}

# The .NET line a build in a zip targets ('net10'), from one runtimeconfig.json
# in it (after its top-level folder), or ''.
function Get-ZipDotNetBuild {
    param([string]$ZipPath, [string]$RuntimeConfigName)
    $archive = [System.IO.Compression.ZipFile]::OpenRead($ZipPath)
    try {
        foreach ($entry in $archive.Entries) {
            $name = $entry.FullName.Replace('\', '/')
            if ($name -notlike "*/$RuntimeConfigName" -and $name -ne $RuntimeConfigName) { continue }
            if ($name.Split('/').Count -gt 2) { continue }
            $reader = New-Object System.IO.StreamReader($entry.Open())
            try { $config = ConvertFrom-Json -InputObject $reader.ReadToEnd() -ErrorAction Stop } finally { $reader.Dispose() }
            $match = [regex]::Match([string]$config.runtimeOptions.tfm, '^net(\d+)\.\d+$')
            if ($match.Success) { return "net$($match.Groups[1].Value)" }
        }
    } finally {
        try { $archive.Dispose() } catch {}
    }
    return ''
}

# Arsenal Image Mounter: the newest version on the vendor's downloads page and
# the MD5 it publishes for that release's zip (where it gives one). The zip is
# downloaded by hand (the vendor ships it through MEGA) into the account's
# Downloads folder under the vendor's name; until it is there, the remote's
# LocalFile is '' and its Detail says what to download and where.
function Get-ArsenalRemote {
    param($CatalogueTool)
    $page = Get-HttpText -Uri $CatalogueTool.Package
    $match = [regex]::Match($page, $script:ArsenalReleasePattern)
    if (-not $match.Success) { throw "no release found on $($CatalogueTool.Package): the page's format may have changed" }
    $version = $match.Groups[1].Value
    $md5 = $match.Groups[2].Value.ToLowerInvariant()
    $algorithm = ''
    if ($md5) { $algorithm = 'MD5' }
    $fileName = "Arsenal-Image-Mounter-v$version.zip"
    $zipPath = Join-Path (Get-DownloadsFolder) $fileName
    $localFile = ''
    $build = ''
    $detail = "download $fileName from $($CatalogueTool.Package) into $(Format-Unbreakable -Text (Get-DownloadsFolder)), then run again"
    if ([System.IO.File]::Exists($zipPath)) {
        $localFile = $zipPath
        $build = Get-ZipDotNetBuild -ZipPath $zipPath -RuntimeConfigName $CatalogueTool.RuntimeConfig
        if (-not $build) { throw "$fileName names no .NET line in its $($CatalogueTool.RuntimeConfig)" }
        $detail = ''
    }
    return (New-Remote -Available $true -Version $version -Build $build -Marker $version -Url $CatalogueTool.Package -FileName $fileName `
            -VendorHashAlgorithm $algorithm -VendorHash $md5 -Detail $detail -LocalFile $localFile -NeedsManualDownload (-not $localFile))
}

function Get-ToolRemote {
    param($CatalogueTool)
    switch ($CatalogueTool.Source) {
        'EZTools'       { return (Get-EzToolRemote -CatalogueTool $CatalogueTool) }
        'NirSoft'       { return (Get-NirSoftRemote -CatalogueTool $CatalogueTool) }
        'Sysinternals'  { return (Get-SysinternalsRemote -CatalogueTool $CatalogueTool) }
        'ArsenalRecon'  { return (Get-ArsenalRemote -CatalogueTool $CatalogueTool) }
    }
    throw "unknown source '$($CatalogueTool.Source)' for $($CatalogueTool.Name)"
}

# Microsoft's index of .NET lines, read once per run.
function Get-DotNetIndex {
    if (-not $script:dotNetIndex) { $script:dotNetIndex = Get-HttpJson -Uri $script:DotNetIndexUrl }
    return $script:dotNetIndex
}

# The latest patch of one .NET line (a flavour and a major version): its
# x64 installer, SHA-512 and support dates.
function Get-DotNetLineRemote {
    param($FlavourRow, [int]$Major)
    $index = Get-DotNetIndex
    $channel = @($index.'releases-index' | Where-Object { $_.'channel-version' -eq "$Major.0" }) | Select-Object -First 1
    if (-not $channel) { return (New-Remote -Available $false -Detail ".NET $Major is not in Microsoft's release metadata") }
    $channelReleases = Get-HttpJson -Uri $channel.'releases.json'
    $key = $FlavourRow.MetadataKey
    $latest = @($channelReleases.releases | Where-Object { $_.$key -and $_.$key.version }) | Select-Object -First 1
    if (-not $latest) { return (New-Remote -Available $false -Detail "no $($FlavourRow.DisplayName) $Major release in the metadata") }
    $version = $latest.$key.version
    $file = @($latest.$key.files | Where-Object { $_.rid -eq 'win-x64' -and $_.name -like '*.exe' }) | Select-Object -First 1
    if (-not $file) { return (New-Remote -Available $false -Detail "no win-x64 installer for $($FlavourRow.DisplayName) $version") }
    $remote = New-Remote -Available $true -Version $version -Build 'x64' -Marker $version -Url $file.url -FileName ([System.IO.Path]::GetFileName(([uri]$file.url).AbsolutePath)) `
        -VendorHashAlgorithm 'SHA512' -VendorHash ($file.hash.ToLowerInvariant())
    $remote | Add-Member -NotePropertyName EndOfLife -NotePropertyValue ([string]$channel.'eol-date')
    $remote | Add-Member -NotePropertyName SupportPhase -NotePropertyValue ([string]$channel.'support-phase')
    return $remote
}

# The last commit touching an ancillary folder upstream, on the branch
# --sync downloads.
function Get-AncillaryRemote {
    param($AncillaryRow)
    $path = "/repos/$($AncillaryRow.Repository)/commits?path=$($AncillaryRow.RepositoryPath)&sha=$($AncillaryRow.Branch)&per_page=1"
    $commits = @(Get-GitHubJson -Path $path)
    if ($commits.Count -eq 0 -or -not $commits[0].sha) { return (New-Remote -Available $false -Detail "no commit found for $($AncillaryRow.RepositoryPath)") }
    $remote = New-Remote -Available $true -Version $commits[0].sha -Marker $commits[0].sha -Url "https://github.com/$($AncillaryRow.Repository)/commit/$($commits[0].sha)"
    $remote | Add-Member -NotePropertyName CommitUtc -NotePropertyValue ([string]$commits[0].commit.committer.date)
    return $remote
}

# --- Prerequisites: what is installed ---

# Installed versions of a .NET shared framework, from its folders under
# Program Files\dotnet\shared (each version is a folder).
function Get-InstalledDotNetVersion {
    param([string]$SharedFramework)
    $folder = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) "dotnet\shared\$SharedFramework"
    if (-not [System.IO.Directory]::Exists($folder)) { return @() }
    return @([System.IO.Directory]::GetDirectories($folder) | ForEach-Object { [System.IO.Path]::GetFileName($_) } | Where-Object { ConvertTo-VersionOrNull -Text $_ })
}

# --- Prerequisites: what is needed ---

# The capabilities a tool needs, given the build chosen for it: 'net10'
# turns 'DotNet:<Flavour>' into 'DotNet:<Flavour>:10'; the others are rows of
# $OtherPrerequisites.
function Get-ToolCapability {
    param($CatalogueTool, [string]$Build)
    $capabilities = foreach ($requirement in $CatalogueTool.Requires) {
        if ($requirement -notlike 'DotNet:*') {
            if (-not ($script:OtherPrerequisites | Where-Object { $_.Capability -eq $requirement })) { throw "$($CatalogueTool.Name): unknown requirement '$requirement'" }
            $requirement
            continue
        }
        $lineMatch = [regex]::Match($Build, '^net(\d+)$')
        if (-not $lineMatch.Success) { throw "$($CatalogueTool.Name): build '$Build' names no .NET line" }
        "$requirement`:$($lineMatch.Groups[1].Value)"
    }
    return @($capabilities)
}

# The prerequisites (.NET product lines) that cover a set of capabilities,
# the smallest set: per .NET major version, the flavour that covers every
# flavour needed with the fewest extra (the Desktop Runtime only where a GUI
# tool needs it). The lines are those of $Capabilities (the tools this run
# covers); $OtherInstalledCapabilities (installed tools outside a selection)
# only widen the flavour of those lines, so a selective run keeps the line a
# full run would. Each result as Get-PrerequisiteFromId gives it.
function Resolve-Prerequisite {
    param([string[]]$Capabilities, [string[]]$OtherInstalledCapabilities = @())
    $resolved = New-Object System.Collections.Generic.List[object]
    $dotNetNeeds = @{}     # major -> list of flavours
    foreach ($capability in ($Capabilities | Sort-Object -Unique)) {
        if ($capability -notlike 'DotNet:*') { $resolved.Add((Get-PrerequisiteFromId -Id $capability)); continue }
        $parts = $capability -split ':'
        $major = [int]$parts[2]
        if (-not $dotNetNeeds.ContainsKey($major)) { $dotNetNeeds[$major] = New-Object System.Collections.Generic.List[string] }
        $dotNetNeeds[$major].Add($parts[1])
    }
    foreach ($capability in ($OtherInstalledCapabilities | Sort-Object -Unique)) {
        if ($capability -notlike 'DotNet:*') { continue }
        $parts = $capability -split ':'
        $major = [int]$parts[2]
        if ($dotNetNeeds.ContainsKey($major)) { $dotNetNeeds[$major].Add($parts[1]) }
    }
    foreach ($major in ($dotNetNeeds.Keys | Sort-Object)) {
        $needed = @($dotNetNeeds[$major] | Sort-Object -Unique)
        $candidates = @($script:DotNetFlavours | Where-Object { $covers = $_.Covers; @($needed | Where-Object { $covers -notcontains $_ }).Count -eq 0 } | Sort-Object { $_.Covers.Count })
        if ($candidates.Count -eq 0) { throw ".NET ${major}: no flavour covers $($needed -join ', ')" }
        $resolved.Add((Get-PrerequisiteFromId -Id "DotNet:$($candidates[0].Flavour):$major"))
    }
    return $resolved.ToArray()
}

# A prerequisite from its id: a .NET line ('DotNet:WindowsDesktop:10') or
# an $OtherPrerequisites capability ('VCRedist:x64'). Id, Kind ('DotNet' or
# the row's Source), DisplayName, Row, Major (the .NET major; 0 otherwise).
function Get-PrerequisiteFromId {
    param([string]$Id)
    $parts = $Id -split ':'
    if ($parts[0] -eq 'DotNet') {
        $flavour = @($script:DotNetFlavours | Where-Object { $_.Flavour -eq $parts[1] }) | Select-Object -First 1
        if (-not $flavour) { throw "unknown prerequisite '$Id'" }
        return [pscustomobject]@{ Id = $Id; Kind = 'DotNet'; DisplayName = "$($flavour.DisplayName) $($parts[2])"; Row = $flavour; Major = [int]$parts[2] }
    }
    $row = @($script:OtherPrerequisites | Where-Object { $_.Capability -eq $Id }) | Select-Object -First 1
    if (-not $row) { throw "unknown prerequisite '$Id'" }
    return [pscustomobject]@{ Id = $Id; Kind = $row.Source; DisplayName = $row.DisplayName; Row = $row; Major = 0 }
}

# What a prerequisite offers now.
function Get-PrerequisiteRemote {
    param($Prerequisite)
    switch ($Prerequisite.Kind) {
        'DotNet'          { return (Get-DotNetLineRemote -FlavourRow $Prerequisite.Row -Major $Prerequisite.Major) }
        'VisualCppRedist' { return (Get-VcRedistRemote -Row $Prerequisite.Row) }
        'ArsenalDriver'   { return (Get-ArsenalDriverRemote -Row $Prerequisite.Row) }
    }
    throw "unknown prerequisite kind '$($Prerequisite.Kind)'"
}

# The versions of a prerequisite installed on this machine, whoever installed
# them (one at most for those updated in place).
function Get-PrerequisiteInstalledVersion {
    param($Prerequisite)
    switch ($Prerequisite.Kind) {
        'DotNet'          { return @(Get-InstalledDotNetVersion -SharedFramework $Prerequisite.Row.SharedFramework) }
        'VisualCppRedist' { return @(Get-InstalledVcRedistVersion) }
        'ArsenalDriver'   { return @(Get-InstalledArsenalDriverVersion) }
    }
    throw "unknown prerequisite kind '$($Prerequisite.Kind)'"
}

# Whether a prerequisite installed is the one offered: a .NET line has that
# patch side by side with others; one updated in place (Visual C++, the
# driver) has that version or a newer one. Without a version from the source
# (Visual C++), the file's marker recorded at the last check decides.
function Test-PrerequisiteCurrent {
    param($Prerequisite, $Remote, [string[]]$Installed, [string]$RecordedMarker)
    if ($Remote.Version) {
        if ($Prerequisite.Kind -eq 'DotNet') { return [bool]($Installed | Where-Object { Test-SameVersion -First $_ -Second $Remote.Version }) }
        $offered = ConvertTo-VersionOrNull -Text $Remote.Version
        return [bool]($Installed | Where-Object { $present = ConvertTo-VersionOrNull -Text $_; $present -and $offered -and $present -ge $offered })
    }
    return ($Installed.Count -gt 0 -and $RecordedMarker -and $RecordedMarker -eq $Remote.Marker)
}

# The Visual C++ Redistributable: Microsoft's permanent link redirects to the
# current file, whose URL holds its SHA-256. The marker is that URL and its
# headers; the version is read from the file once it is downloaded.
function Get-VcRedistRemote {
    param($Row)
    $response = Invoke-WebRequest -Uri $Row.Url -Method Head -UseBasicParsing -TimeoutSec $script:HttpTimeoutSeconds -ErrorAction Stop
    $finalUrl = [string]$response.BaseResponse.ResponseUri.AbsoluteUri
    $hashMatch = [regex]::Match($finalUrl, '/([0-9A-Fa-f]{64})/[^/]+$')
    $vendorHash = ''
    $vendorHashAlgorithm = ''
    if ($hashMatch.Success) { $vendorHash = $hashMatch.Groups[1].Value.ToLowerInvariant(); $vendorHashAlgorithm = 'SHA256' }
    $marker = "$finalUrl|$(Get-HeaderValue -Headers $response.Headers -Name 'ETag')|$(Get-HeaderValue -Headers $response.Headers -Name 'Content-Length')"
    return (New-Remote -Available $true -Build 'x64' -Marker $marker -Url $finalUrl -FileName ([System.IO.Path]::GetFileName(([uri]$finalUrl).AbsolutePath)) `
            -VendorHashAlgorithm $vendorHashAlgorithm -VendorHash $vendorHash)
}

# The Visual C++ Redistributable (x64) installed, from its registry key.
function Get-InstalledVcRedistVersion {
    foreach ($key in $script:VcRedistRegistryKeys) {
        if ((Get-RegistryValue -Path $key -Name 'Installed') -eq 1) {
            $version = [string](Get-RegistryValue -Path $key -Name 'Version')
            # The registry writes "v14.44.35211.00"; the file says 14.44.35211.0.
            $parsed = ConvertTo-VersionOrNull -Text $version.TrimStart('v')
            if ($parsed) { return @($parsed.ToString()) }
            if ($version) { return @($version.TrimStart('v')) }
        }
    }
    return @()
}

# Arsenal's driver package: the last commit to it on its branch (its message
# names the driver version), the download pinned to that commit, and the git
# blob hash GitHub gives for the file at that commit.
function Get-ArsenalDriverRemote {
    param($Row)
    $commits = @(Get-GitHubJson -Path "/repos/$($Row.Repository)/commits?path=$($Row.RepositoryPath)&sha=$($Row.Branch)&per_page=1")
    if ($commits.Count -eq 0 -or -not $commits[0].sha) { return (New-Remote -Available $false -Detail "no commit found for $($Row.RepositoryPath)") }
    $commit = $commits[0]
    $versionMatch = [regex]::Match([string]$commit.commit.message, $script:ArsenalDriverVersionPattern)
    if (-not $versionMatch.Success) { throw "the last commit to $($Row.RepositoryPath) ($($commit.sha.Substring(0, 12))) names no driver version" }
    $content = Get-GitHubJson -Path "/repos/$($Row.Repository)/contents/$($Row.RepositoryPath)?ref=$($commit.sha)"
    $url = "https://raw.githubusercontent.com/$($Row.Repository)/$($commit.sha)/$($Row.RepositoryPath)"
    return (New-Remote -Available $true -Version $versionMatch.Groups[1].Value -Build 'x64' -Marker $commit.sha -Url $url -FileName ([System.IO.Path]::GetFileName($Row.RepositoryPath)) `
            -VendorHashAlgorithm 'GitBlobSHA1' -VendorHash ([string]$content.sha).ToLowerInvariant())
}

# Arsenal's driver installed: its device present (a Plug and Play device on
# its service) and the driver file's version; none when the device is gone
# (e.g. removed, its files waiting for a restart).
function Get-InstalledArsenalDriverVersion {
    $devices = @(Get-CimInstance -ClassName Win32_PnPEntity -Filter "Service='$($script:ArsenalDriverService)'" -ErrorAction Stop)
    $driverPath = Join-Path ([Environment]::SystemDirectory) "drivers\$($script:ArsenalDriverService).sys"
    if ($devices.Count -eq 0 -or -not [System.IO.File]::Exists($driverPath)) { return @() }
    $info = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($driverPath)
    return @('{0}.{1}.{2}.{3}' -f $info.FileMajorPart, $info.FileMinorPart, $info.FileBuildPart, $info.FilePrivatePart)
}

# Two version strings name the same version ("2.3.1.1000" and "v2.3.1.1000",
# "9.0.21" and "9.0.21").
function Test-SameVersion {
    param([string]$First, [string]$Second)
    $firstVersion = ConvertTo-VersionOrNull -Text $First
    $secondVersion = ConvertTo-VersionOrNull -Text $Second
    if ($firstVersion -and $secondVersion) { return ($firstVersion -eq $secondVersion) }
    return ($First -eq $Second)
}

# --- Archives ---

# A zip entry's name as a safe relative path (backslashes as written by
# some vendors become separators), or throws: no rooted path, drive, empty
# segment, '.' or '..' (shared rules: names are inert data).
function ConvertTo-SafeEntryPath {
    param([string]$EntryName)
    $name = $EntryName.Replace('\', '/')
    if ($name.StartsWith('/') -or $name -match ':') { throw "unsafe entry name '$EntryName'" }
    $segments = $name.TrimEnd('/') -split '/'
    foreach ($segment in $segments) {
        if ($segment -eq '' -or $segment -eq '.' -or $segment -eq '..') { throw "unsafe entry name '$EntryName'" }
    }
    return ($segments -join '\')
}

# Extract a zip into an empty folder, hashing each file as it is written.
# Where every entry sits under one top-level folder, that folder is dropped
# (EZ tools ship as "EvtxeCmd/..."). With -IncludeOnly, only those files
# (relative paths after the drop) are extracted, and each must be there.
# Files matching an -Exclude pattern (-like) are left out, unless they match
# a -Keep pattern.
# Returns the files: RelativePath, Length, Sha256.
function Expand-VerifiedZip {
    param([string]$ZipPath, [string]$Destination, [string[]]$IncludeOnly = @(), [string[]]$Exclude = @(), [string[]]$Keep = @())
    $archive = [System.IO.Compression.ZipFile]::OpenRead($ZipPath)
    try {
        $entries = @($archive.Entries | ForEach-Object { [pscustomobject]@{ Entry = $_; Path = (ConvertTo-SafeEntryPath -EntryName $_.FullName); IsFolder = ($_.FullName.EndsWith('/') -or $_.FullName.EndsWith('\')) } })
        $fileEntries = @($entries | Where-Object { -not $_.IsFolder })
        if ($fileEntries.Count -eq 0) { throw 'the zip holds no files' }
        $topFolders = @($fileEntries | ForEach-Object { if ($_.Path -match '\\') { ($_.Path -split '\\')[0] } else { '' } } | Sort-Object -Unique)
        $dropPrefix = ''
        if ($topFolders.Count -eq 1 -and $topFolders[0] -ne '') { $dropPrefix = $topFolders[0] + '\' }
        $files = New-Object System.Collections.Generic.List[object]
        foreach ($item in $fileEntries) {
            $relativePath = $item.Path
            if ($dropPrefix) { $relativePath = $relativePath.Substring($dropPrefix.Length) }
            if ($IncludeOnly.Count -gt 0 -and -not ($IncludeOnly | Where-Object { $_ -ieq $relativePath })) { continue }
            $excluded = [bool]($Exclude | Where-Object { $relativePath -like $_ })
            if ($excluded -and -not ($Keep | Where-Object { $relativePath -like $_ })) { continue }
            $target = Join-Path $Destination $relativePath
            Assert-PathInside -Path $target -Root $Destination
            $null = [System.IO.Directory]::CreateDirectory([System.IO.Path]::GetDirectoryName($target))
            $files.Add((Copy-ZipEntryHashed -Entry $item.Entry -Target $target -RelativePath $relativePath))
        }
        foreach ($wanted in $IncludeOnly) {
            if (-not ($files | Where-Object { $_.RelativePath -ieq $wanted })) { throw "the zip has no $wanted" }
        }
        return $files.ToArray()
    } finally {
        try { $archive.Dispose() } catch {}
    }
}

# Write one zip entry to a file, hashing the bytes as they are written.
function Copy-ZipEntryHashed {
    param($Entry, [string]$Target, [string]$RelativePath)
    $source = $null
    $output = $null
    $hasher = $null
    try {
        $source = $Entry.Open()
        $output = [System.IO.File]::Create($Target)
        $hasher = [System.Security.Cryptography.SHA256]::Create()
        $buffer = New-Object byte[] 1048576
        $length = 0L
        while (($read = $source.Read($buffer, 0, $buffer.Length)) -gt 0) {
            $output.Write($buffer, 0, $read)
            $null = $hasher.TransformBlock($buffer, 0, $read, $null, 0)
            $length += $read
        }
        $null = $hasher.TransformFinalBlock($buffer, 0, 0)
        $digest = (($hasher.Hash | ForEach-Object { $_.ToString('x2') }) -join '')
        return [pscustomobject]@{ RelativePath = $RelativePath; Length = $length; Sha256 = $digest }
    } finally {
        if ($hasher) { try { $hasher.Dispose() } catch {} }
        if ($output) { try { $output.Dispose() } catch {} }
        if ($source) { try { $source.Dispose() } catch {} }
    }
}

# Re-read extracted files from disk: a file missing or changed since it was
# written (e.g. removed by antivirus) is listed. Returns problem lines.
function Test-ExtractedFile {
    param([string]$Folder, [object[]]$Files)
    $problems = foreach ($file in $Files) {
        $path = Join-Path $Folder $file.RelativePath
        if (-not [System.IO.File]::Exists($path)) { "missing after extraction: $($file.RelativePath)"; continue }
        $hash = Get-FileHashHex -Path $path
        if ($hash -ne $file.Sha256) { "changed after extraction: $($file.RelativePath)" }
    }
    return @($problems)
}

# Remove the Zone.Identifier stream (Mark of the Web) from files that have
# one; returns how many had it.
function Remove-ZoneIdentifier {
    param([string]$Folder)
    $count = 0
    foreach ($file in @(Get-ChildItem -LiteralPath $Folder -Recurse -File -Force -ErrorAction Stop)) {
        $stream = Get-Item -LiteralPath $file.FullName -Stream 'Zone.Identifier' -ErrorAction SilentlyContinue
        if ($stream) {
            Unblock-File -LiteralPath $file.FullName -ErrorAction Stop
            $count++
        }
    }
    return $count
}

# Every file in a folder (recursively) with its SHA-256, relative to the
# folder; folders named in $Exclude (relative, top level) are skipped.
function Get-FolderSnapshot {
    param([string]$Folder, [string[]]$Exclude = @())
    $snapshot = @{}
    if (-not [System.IO.Directory]::Exists($Folder)) { return $snapshot }
    foreach ($file in @(Get-ChildItem -LiteralPath $Folder -Recurse -File -Force -ErrorAction Stop)) {
        $relativePath = Get-RelativePath -Path $file.FullName -Root $Folder
        $topSegment = ($relativePath -split '\\')[0]
        if ($relativePath -match '\\' -and $Exclude -contains $topSegment) { continue }
        $snapshot[$relativePath] = [pscustomobject]@{ Length = $file.Length; Sha256 = (Get-FileHashHex -Path $file.FullName) }
    }
    return $snapshot
}

# Compare two snapshots: Added, Changed, Removed (relative paths).
function Compare-FolderSnapshot {
    param([hashtable]$Before, [hashtable]$After)
    $added = @($After.Keys | Where-Object { -not $Before.ContainsKey($_) } | Sort-Object)
    $removed = @($Before.Keys | Where-Object { -not $After.ContainsKey($_) } | Sort-Object)
    $changed = @($After.Keys | Where-Object { $Before.ContainsKey($_) -and $Before[$_].Sha256 -ne $After[$_].Sha256 } | Sort-Object)
    return [pscustomobject]@{ Added = $added; Changed = $changed; Removed = $removed }
}

# --- Installers ---

# Run an installer or a tool, wait (up to $ProcessTimeoutMinutes), and
# return its exit code; a process that overruns is stopped and throws.
# Standard output and error go to files when given (a tool's --sync).
function Invoke-ProcessAndWait {
    param([string]$FilePath, [string[]]$Arguments, [string]$WorkingDirectory = '', [string]$OutputPath = '', [string]$ErrorPath = '')
    $startArguments = @{ FilePath = $FilePath; ArgumentList = $Arguments; PassThru = $true }
    if ($WorkingDirectory) { $startArguments['WorkingDirectory'] = $WorkingDirectory }
    if ($OutputPath) {
        $startArguments['RedirectStandardOutput'] = $OutputPath
        $startArguments['RedirectStandardError'] = $ErrorPath
        $startArguments['NoNewWindow'] = $true
    } else {
        $startArguments['WindowStyle'] = 'Hidden'
    }
    $process = Start-Process @startArguments -ErrorAction Stop
    $null = $process.Handle          # keeps the handle, so ExitCode is readable after the exit (PowerShell 5.1)
    if (-not $process.WaitForExit($script:ProcessTimeoutMinutes * 60 * 1000)) {
        try { $process.Kill() } catch {}
        throw "$([System.IO.Path]::GetFileName($FilePath)) did not finish within $($script:ProcessTimeoutMinutes) minutes and was stopped"
    }
    return $process.ExitCode
}

# Download a file into the staging folder, hash it, compare the vendor's
# hash where one is published, and check its signer where $ExpectedSigner is
# given (installers; a zip's exes are checked after extraction). Returns
# the download's facts, or throws on a mismatch (the file is deleted).
function Save-VerifiedDownload {
    param($Remote, [string]$StagingFolder, [string]$ExpectedSigner = '', [bool]$UnsignedAllowed = $false)
    $path = Join-Path $StagingFolder $Remote.FileName
    Assert-PathInside -Path $path -Root $StagingFolder
    if ($Remote.LocalFile) {
        Copy-Item -LiteralPath $Remote.LocalFile -Destination $path -Force -ErrorAction Stop     # downloaded by hand; the copy is checked as a download is
    } else {
        Save-HttpFile -Uri $Remote.Url -Path $path
    }
    $sha256 = Get-FileHashHex -Path $path -Algorithm 'SHA256'
    $vendorHashMatched = 'not published'
    if ($Remote.VendorHash) {
        $vendorDigest = $sha256
        if ($Remote.VendorHashAlgorithm -eq 'GitBlobSHA1') { $vendorDigest = Get-GitBlobSha1 -Path $path }
        elseif ($Remote.VendorHashAlgorithm -ne 'SHA256') { $vendorDigest = Get-FileHashHex -Path $path -Algorithm $Remote.VendorHashAlgorithm }
        if ($vendorDigest -ne $Remote.VendorHash) {
            Remove-OwnedFile -Path $path -Root $StagingFolder
            throw "$($Remote.FileName): $($Remote.VendorHashAlgorithm) does not match the vendor's published hash"
        }
        $vendorHashMatched = 'yes'
    }
    $signer = ''
    if ($ExpectedSigner) {
        $check = Test-SignerAccepted -SignerInfo (Get-SignerInfo -Path $path) -ExpectedSigner $ExpectedSigner -UnsignedAllowed $UnsignedAllowed
        if (-not $check.Accepted) {
            Remove-OwnedFile -Path $path -Root $StagingFolder
            throw "$($Remote.FileName): signed by $($check.Description), expected $ExpectedSigner"
        }
        $signer = $check.Description
    }
    return [pscustomobject]@{ Path = $path; Sha256 = $sha256; VendorHashMatched = $vendorHashMatched; Signer = $signer }
}

# --- Prerequisite actions ---

# Install (or update) a prerequisite to what its source offers now. Returns
# the result's detail text; throws on failure.
function Install-PrerequisiteVersion {
    param($Prerequisite, $Remote, $State)
    switch ($Prerequisite.Kind) {
        'DotNet'          { return (Install-DotNetVersion -Prerequisite $Prerequisite -Remote $Remote -State $State) }
        'VisualCppRedist' { return (Install-VcRedist -Prerequisite $Prerequisite -Remote $Remote -State $State) }
        'ArsenalDriver'   { return (Install-ArsenalDriver -Prerequisite $Prerequisite -Remote $Remote -State $State) }
    }
    throw "unknown prerequisite kind '$($Prerequisite.Kind)'"
}

# The state record of a prerequisite updated in place: its marker, and the
# one version this script installed (an earlier one it installed is gone,
# replaced in place). Signer: what was checked, where the download itself
# carries no signature (the driver package); else the download's signer.
function Set-InPlacePrerequisiteRecord {
    param($Prerequisite, $Remote, $State, [string]$Version, $Download, [bool]$InstalledByScript, [string]$Signer = '')
    if (-not $State.Prerequisites.ContainsKey($Prerequisite.Id)) { $State.Prerequisites[$Prerequisite.Id] = @{ DisplayName = $Prerequisite.DisplayName; Versions = @{} } }
    $record = $State.Prerequisites[$Prerequisite.Id]
    $record.Marker = $Remote.Marker
    if (-not $InstalledByScript) { return }
    $record.Versions = @{
        $Version = @{ InstallerFile = ''; InstallerSha256 = $Download.Sha256; SourceUrl = $Remote.Url; VendorHashAlgorithm = $Remote.VendorHashAlgorithm
            VendorHash = $Remote.VendorHash; VendorHashMatched = $Download.VendorHashMatched; Signer = $(if ($Signer) { $Signer } else { $Download.Signer }); InstalledUtc = (Format-UtcTime -Time (Get-Date)) }
    }
}

# The Visual C++ Redistributable: download, check (Microsoft's SHA-256 from
# the URL, the signer), read the file's version; install it unless the one
# installed is that or newer. Never removed.
function Install-VcRedist {
    param($Prerequisite, $Remote, $State)
    $download = Save-VerifiedDownload -Remote $Remote -StagingFolder $script:stagingFolder -ExpectedSigner $Prerequisite.Row.ExpectedSigner
    try {
        Write-ConsoleLine -Text "Downloaded $($Remote.FileName) (SHA-256 $($download.Sha256); vendor hash: $($download.VendorHashMatched); signer: $($download.Signer))" -Indent 4
        $fileInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($download.Path)
        $fileVersion = '{0}.{1}.{2}.{3}' -f $fileInfo.FileMajorPart, $fileInfo.FileMinorPart, $fileInfo.FileBuildPart, $fileInfo.FilePrivatePart
        $offered = ConvertTo-VersionOrNull -Text $fileVersion
        $installedBefore = @(Get-InstalledVcRedistVersion)
        if ($installedBefore | Where-Object { $present = ConvertTo-VersionOrNull -Text $_; $present -and $present -ge $offered }) {
            Set-InPlacePrerequisiteRecord -Prerequisite $Prerequisite -Remote $Remote -State $State -Version $fileVersion -Download $download -InstalledByScript $false
            return "$($Prerequisite.DisplayName): $($installedBefore -join ', ') installed, Microsoft's file is ${fileVersion}: nothing to do"
        }
        Write-ConsoleLine -Text "Installing $fileVersion (installed: $(if ($installedBefore) { $installedBefore -join ', ' } else { 'none' }))" -Indent 4
        $exitCode = Invoke-ProcessAndWait -FilePath $download.Path -Arguments $Prerequisite.Row.InstallArguments
        Write-ConsoleLine -Text "Installer exit code: $exitCode" -Indent 4
        if ($script:VcRedistSuccessExitCodes -notcontains $exitCode) { throw "the installer of $($Prerequisite.DisplayName) $fileVersion exited with $exitCode" }
        $installedAfter = @(Get-InstalledVcRedistVersion)
        if (-not ($installedAfter | Where-Object { $present = ConvertTo-VersionOrNull -Text $_; $present -and $present -ge $offered })) {
            throw "the installer of $($Prerequisite.DisplayName) $fileVersion exited with $exitCode, but $($installedAfter -join ', ') is installed"
        }
    } finally {
        try { Remove-OwnedFile -Path $download.Path -Root $script:stagingFolder } catch {}
    }
    Set-InPlacePrerequisiteRecord -Prerequisite $Prerequisite -Remote $Remote -State $State -Version $fileVersion -Download $download -InstalledByScript $true
    $detail = "$($Prerequisite.DisplayName) $fileVersion installed"
    if ($exitCode -eq $script:RestartRequiredExitCode) {
        Add-RunWarning -Message "$($Prerequisite.DisplayName) $($fileVersion): the installer asks for a restart to complete."
        $detail += ' (restart needed)'
    }
    return $detail
}

# Arsenal's driver: download its package (pinned to the commit, checked
# against GitHub's git blob hash), extract it with Windows' own tar.exe,
# check the signers of aim_ll.exe and the driver, install with
# aim_ll.exe --install, and check the driver's version. Never removed.
function Install-ArsenalDriver {
    param($Prerequisite, $Remote, $State)
    $row = $Prerequisite.Row
    $download = Save-VerifiedDownload -Remote $Remote -StagingFolder $script:stagingFolder
    $packageFolder = Join-Path $script:stagingFolder 'ArsenalDriver'
    try {
        Write-ConsoleLine -Text "Downloaded $($Remote.FileName) (SHA-256 $($download.Sha256); vendor hash: $($download.VendorHashMatched))" -Indent 4
        $tar = Join-Path ([Environment]::SystemDirectory) 'tar.exe'
        if (-not [System.IO.File]::Exists($tar)) { throw "Windows' own tar.exe isn't there ($(Format-Unbreakable -Text $tar)): it extracts the driver package" }
        $null = [System.IO.Directory]::CreateDirectory($packageFolder)
        $tarExit = Invoke-ProcessAndWait -FilePath $tar -Arguments @('-xf', "`"$($download.Path)`"", '-C', "`"$packageFolder`"")
        if ($tarExit -ne 0) { throw "tar.exe could not extract $($Remote.FileName) (exit code $tarExit)" }
        # The vendor's installer carries the vendor's signature; the driver
        # is taken on its catalogue's (see $ArsenalDriverCatalogue).
        $installer = Join-Path $packageFolder $script:ArsenalDriverInstaller
        $catalogue = Join-Path $packageFolder $script:ArsenalDriverCatalogue
        $signerDescriptions = @{}
        foreach ($expected in @(@{ Path = $installer; Signer = $row.ExpectedSigner }, @{ Path = $catalogue; Signer = $row.DriverSigner })) {
            if (-not [System.IO.File]::Exists($expected.Path)) { throw "the package has no $(Get-RelativePath -Path $expected.Path -Root $packageFolder)" }
            $check = Test-SignerAccepted -SignerInfo (Get-SignerInfo -Path $expected.Path) -ExpectedSigner $expected.Signer -UnsignedAllowed $false
            if (-not $check.Accepted) { throw "$(Get-RelativePath -Path $expected.Path -Root $packageFolder) is signed by $($check.Description), expected $($expected.Signer)" }
            $signerDescriptions[$expected.Path] = $check.Description
        }
        $driverFolder = Join-Path $packageFolder $script:ArsenalDriverFolder
        if (-not [System.IO.Directory]::Exists($driverFolder)) { throw "the package has no $($script:ArsenalDriverFolder) folder" }
        $memberPaths = @(Join-Path $packageFolder $script:ArsenalDriverInf)
        $memberPaths += @(Get-ChildItem -LiteralPath $driverFolder -File -ErrorAction Stop | Where-Object { $name = $_.Name; @($script:ArsenalDriverCataloguedPatterns | Where-Object { $name -like $_ }).Count -gt 0 } | Sort-Object Name | ForEach-Object { $_.FullName })
        foreach ($memberPath in $memberPaths) {
            if (-not [System.IO.File]::Exists($memberPath)) { throw "the package has no $(Get-RelativePath -Path $memberPath -Root $packageFolder)" }
            $member = Test-CatalogueMember -CataloguePath $catalogue -MemberPath $memberPath
            if (-not $member.Accepted) { throw "$(Get-RelativePath -Path $memberPath -Root $packageFolder) is not verified by $($script:ArsenalDriverCatalogue): $($member.Description)" }
        }
        Write-ConsoleLine -Text "$($script:ArsenalDriverCatalogue): $($signerDescriptions[$catalogue]); $($memberPaths.Count) file(s) verified as its members" -Indent 4
        $outputPath = Join-Path $script:stagingFolder 'aim_ll-output.txt'
        $errorPath = Join-Path $script:stagingFolder 'aim_ll-errors.txt'
        $exitCode = Invoke-ProcessAndWait -FilePath $installer -Arguments @('--install', "`"$packageFolder`"") -WorkingDirectory $packageFolder -OutputPath $outputPath -ErrorPath $errorPath
        foreach ($outputFile in @($outputPath, $errorPath)) {
            if ([System.IO.File]::Exists($outputFile)) {
                foreach ($line in [System.IO.File]::ReadAllLines($outputFile)) { Add-LogLine -Text "    | $line" }     # aim_ll's own output, as it wrote it
                Remove-OwnedFile -Path $outputFile -Root $script:stagingFolder
            }
        }
        Write-ConsoleLine -Text "aim_ll.exe --install exit code: $exitCode" -Indent 4
        if ($exitCode -ne 0) { throw "aim_ll.exe --install exited with $exitCode" }
        $installed = @(Get-InstalledArsenalDriverVersion)
        if (-not ($installed | Where-Object { Test-SameVersion -First $_ -Second $Remote.Version })) {
            throw "aim_ll.exe --install exited with 0, but the driver installed is $(if ($installed) { $installed -join ', ' } else { 'none' }), not $($Remote.Version) (a restart may be needed)"
        }
    } finally {
        try { Remove-OwnedFolder -Path $packageFolder -Root $script:stagingFolder } catch {}
        try { Remove-OwnedFile -Path $download.Path -Root $script:stagingFolder } catch {}
    }
    $checkedSigners = "$($script:ArsenalDriverCatalogue): $($signerDescriptions[$catalogue]); $(Split-Path -Leaf $script:ArsenalDriverInstaller): $($signerDescriptions[$installer])"
    Set-InPlacePrerequisiteRecord -Prerequisite $Prerequisite -Remote $Remote -State $State -Version $Remote.Version -Download $download -InstalledByScript $true -Signer $checkedSigners
    return "$($Prerequisite.DisplayName) $($Remote.Version) installed (commit $($Remote.Marker.Substring(0, 12)))"
}

# A .NET line's latest patch; its installer is kept under Records\Installers
# (its SHA-256 in the state) for a later uninstall. Returns the result's
# detail text; throws on failure.
function Install-DotNetVersion {
    param($Prerequisite, $Remote, $State)
    $download = Save-VerifiedDownload -Remote $Remote -StagingFolder $script:installersFolder -ExpectedSigner $script:DotNetExpectedSigner
    Write-ConsoleLine -Text "Downloaded $($Remote.FileName) (SHA-256 $($download.Sha256); vendor hash: $($download.VendorHashMatched); signer: $($download.Signer))" -Indent 4
    try {
        $exitCode = Invoke-ProcessAndWait -FilePath $download.Path -Arguments $script:DotNetInstallArguments
        Write-ConsoleLine -Text "Installer exit code: $exitCode" -Indent 4
        if ($script:InstallerSuccessExitCodes -notcontains $exitCode) { throw "the installer of $($Prerequisite.DisplayName) $($Remote.Version) exited with $exitCode" }
        $installed = @(Get-PrerequisiteInstalledVersion -Prerequisite $Prerequisite)
        if (-not @($installed | Where-Object { Test-SameVersion -First $_ -Second $Remote.Version })) {
            throw "the installer of $($Prerequisite.DisplayName) $($Remote.Version) exited with $exitCode, but that version is not installed"
        }
    } catch {
        # An installer that didn't install is not kept: nothing on record uses it.
        try { Remove-OwnedFile -Path $download.Path -Root $script:installersFolder } catch {}
        throw
    }
    if (-not $State.Prerequisites.ContainsKey($Prerequisite.Id)) { $State.Prerequisites[$Prerequisite.Id] = @{ DisplayName = $Prerequisite.DisplayName; Versions = @{} } }
    $State.Prerequisites[$Prerequisite.Id].Versions[$Remote.Version] = @{
        InstallerFile = [System.IO.Path]::GetFileName($download.Path); InstallerSha256 = $download.Sha256; SourceUrl = $Remote.Url
        VendorHashAlgorithm = $Remote.VendorHashAlgorithm; VendorHash = $Remote.VendorHash; VendorHashMatched = $download.VendorHashMatched
        Signer = $download.Signer; InstalledUtc = (Format-UtcTime -Time (Get-Date))
    }
    $detail = "$($Prerequisite.DisplayName) $($Remote.Version) installed"
    if ($exitCode -eq $script:RestartRequiredExitCode) {
        Add-RunWarning -Message "$($Prerequisite.DisplayName) $($Remote.Version): the installer asks for a restart to complete."
        $detail += ' (restart needed)'
    }
    return $detail
}

# Uninstall one version of a prerequisite that the script installed, with
# the installer it kept (re-hashed first: a changed file is never run). A
# version already gone (a newer installer replaced it in place) only leaves
# the record. Returns the detail text; throws on failure.
function Uninstall-PrerequisiteVersion {
    param($Prerequisite, [string]$Version, $State)
    $record = $State.Prerequisites[$Prerequisite.Id].Versions[$Version]
    $installerPath = Join-Path $script:installersFolder $record.InstallerFile
    Assert-PathInside -Path $installerPath -Root $script:installersFolder
    $installedBefore = @(Get-PrerequisiteInstalledVersion -Prerequisite $Prerequisite | Where-Object { Test-SameVersion -First $_ -Second $Version })
    if ($installedBefore.Count -eq 0) {
        $State.Prerequisites[$Prerequisite.Id].Versions.Remove($Version)
        Remove-OwnedFile -Path $installerPath -Root $script:installersFolder
        return "$($Prerequisite.DisplayName) $Version was already gone (replaced in place by a newer version); record and kept installer removed"
    }
    if (-not [System.IO.File]::Exists($installerPath)) { throw "the kept installer $($record.InstallerFile) is missing: uninstall $($Prerequisite.DisplayName) $Version by hand" }
    if ((Get-FileHashHex -Path $installerPath) -ne $record.InstallerSha256) { throw "the kept installer $($record.InstallerFile) has changed since it was used: not run" }
    $exitCode = Invoke-ProcessAndWait -FilePath $installerPath -Arguments $script:DotNetUninstallArguments
    if ($script:InstallerSuccessExitCodes -notcontains $exitCode) { throw "uninstalling $($Prerequisite.DisplayName) $Version exited with $exitCode" }
    $installedAfter = @(Get-PrerequisiteInstalledVersion -Prerequisite $Prerequisite | Where-Object { Test-SameVersion -First $_ -Second $Version })
    if ($installedAfter.Count -gt 0) { throw "uninstalling $($Prerequisite.DisplayName) $Version exited with $exitCode, but it is still installed" }
    $State.Prerequisites[$Prerequisite.Id].Versions.Remove($Version)
    Remove-OwnedFile -Path $installerPath -Root $script:installersFolder
    return "$($Prerequisite.DisplayName) $Version removed (exit code $exitCode)"
}

# --- Tool actions ---

# A tool's user data, relative to its folder: Folders (KeepPaths and
# WritablePaths) and Files (WritableFiles). Kept across an update, not
# verified by -Verify.
function Get-ToolUserDataPath {
    param($CatalogueTool)
    return [pscustomobject]@{
        Folders = @(@($CatalogueTool.KeepPaths) + @($CatalogueTool.WritablePaths) | Where-Object { $_ })
        Files   = @(@($CatalogueTool.WritableFiles) | Where-Object { $_ })
    }
}

# Whether the running account may write in a tool's folder itself, not
# only in a subfolder of it: a writable file (counted wherever it lies), or a
# writable path that names the folder. Such a folder is never put on PATH.
function Test-ToolFolderWritable {
    param($CatalogueTool)
    if (@($CatalogueTool.WritableFiles | Where-Object { $_ }).Count -gt 0) { return $true }
    foreach ($writablePath in @($CatalogueTool.WritablePaths | Where-Object { $_ })) {
        if ($writablePath.Trim('\', '/', '.', ' ') -eq '') { return $true }
    }
    return $false
}

# A fingerprint of what a catalogue row says about installing its tool
# (source, package, exes, files, user data paths), recorded with the tool:
# when the row changes (e.g. its Files), the installed copy no longer
# matches it and is reinstalled.
function Get-CatalogueRowFingerprint {
    param($CatalogueTool)
    $parts = @(
        $CatalogueTool.Source, $CatalogueTool.Package, $CatalogueTool.Gui,
        (@($CatalogueTool.Cli) -join ','), (@($CatalogueTool.Files) -join ','),
        (@($CatalogueTool.KeepPaths) -join ','), (@($CatalogueTool.WritablePaths) -join ','), (@($CatalogueTool.WritableFiles) -join ',')
    )
    # Fields added since 0.1.3 count only where a row sets them, so adding a
    # field to the catalogue never changes every tool's fingerprint (and
    # reinstalls them all).
    foreach ($laterField in @('ExcludeFiles', 'KeepFiles')) {
        $value = @($CatalogueTool.$laterField | Where-Object { $_ })
        if ($value.Count -gt 0) { $parts += "${laterField}=$($value -join ',')" }
    }
    $bytes = [System.Text.Encoding]::UTF8.GetBytes(($parts -join '|'))
    $hasher = [System.Security.Cryptography.SHA256]::Create()
    try { return (($hasher.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') }) -join '') } finally { $hasher.Dispose() }
}

# The tool's folder under the install root.
function Get-ToolFolder {
    param($CatalogueTool)
    return (Join-Path (Join-Path $script:installRoot $CatalogueTool.Family) $CatalogueTool.Name)
}

function Get-FamilyRow {
    param([string]$Name)
    return (@($script:Families | Where-Object { $_.Name -eq $Name }) | Select-Object -First 1)
}

# The runtimeconfig.json embedded in a .NET single-file exe (see
# $SingleFileBundleSignature), as text; empty when the exe isn't one.
function Get-SingleFileRuntimeConfigText {
    param([string]$ExePath)
    $stream = [System.IO.File]::OpenRead($ExePath)
    try {
        $reader = New-Object System.IO.BinaryReader($stream)
        $head = $reader.ReadBytes([int][Math]::Min($stream.Length, $script:SingleFileSignatureSearchBytes))
        # Latin-1 maps each byte to one character, so a string search finds
        # the byte sequence.
        $latin1 = [System.Text.Encoding]::GetEncoding(28591)
        $signature = [byte[]]@(for ($index = 0; $index -lt $script:SingleFileBundleSignature.Length; $index += 2) { [Convert]::ToByte($script:SingleFileBundleSignature.Substring($index, 2), 16) })
        $position = $latin1.GetString($head).IndexOf($latin1.GetString($signature), [System.StringComparison]::Ordinal)
        if ($position -lt 8) { return '' }
        $headerOffset = [BitConverter]::ToInt64($head, $position - 8)
        if ($headerOffset -le 0 -or $headerOffset -ge $stream.Length) { throw "its single-file bundle header offset ($headerOffset) lies outside the file" }
        $null = $stream.Seek($headerOffset, [System.IO.SeekOrigin]::Begin)
        $majorVersion = $reader.ReadUInt32()
        $null = $reader.ReadUInt32()     # minor version
        $null = $reader.ReadInt32()      # file count
        $null = $reader.ReadString()     # bundle id (length-prefixed, as BinaryReader reads it)
        if ($majorVersion -lt 2) { throw "its single-file bundle (version $majorVersion) doesn't say where its runtimeconfig.json is" }
        $null = $reader.ReadInt64()      # deps.json offset
        $null = $reader.ReadInt64()      # deps.json size
        $configOffset = $reader.ReadInt64()
        $configSize = $reader.ReadInt64()
        if ($configSize -le 0) { return '' }
        if ($configSize -gt $script:RuntimeConfigMaximumBytes -or $configOffset -le 0 -or ($configOffset + $configSize) -gt $stream.Length) { throw "its single-file bundle names a runtimeconfig.json outside the file or too large ($configSize bytes at $configOffset)" }
        $null = $stream.Seek($configOffset, [System.IO.SeekOrigin]::Begin)
        return [System.Text.Encoding]::UTF8.GetString($reader.ReadBytes([int]$configSize)).TrimStart([char]0xFEFF)     # a BOM, as ReadAllText drops it
    } finally {
        $stream.Dispose()
    }
}

# An entry point's runtimeconfig.json, as text: <exe name>.runtimeconfig.json
# beside it, else the one inside a single-file exe; empty when it has none
# (a native exe).
function Get-EntryPointRuntimeConfigText {
    param([string]$Folder, [string]$EntryPoint)
    $besidePath = Join-Path $Folder ([System.IO.Path]::GetFileNameWithoutExtension($EntryPoint) + '.runtimeconfig.json')
    if ([System.IO.File]::Exists($besidePath)) { return [System.IO.File]::ReadAllText($besidePath) }
    $exePath = Join-Path $Folder $EntryPoint
    if (-not [System.IO.File]::Exists($exePath)) { return '' }
    return (Get-SingleFileRuntimeConfigText -ExePath $exePath)
}

# The .NET frameworks a tool's own exes need ("DotNet:NETCore:10",
# "DotNet:WindowsDesktop:10"), from each entry point's runtimeconfig.json
# (beside it or inside a single-file exe; none for a native exe). Other
# runtimeconfig files in the folder (a zip shared by two tools) don't count.
function Get-RuntimeConfigCapability {
    param([string]$Folder, [string[]]$EntryPoints)
    $configTexts = @($EntryPoints | ForEach-Object { Get-EntryPointRuntimeConfigText -Folder $Folder -EntryPoint $_ } | Where-Object { $_ })
    $capabilities = foreach ($configText in $configTexts) {
        $config = ConvertFrom-Json -InputObject $configText -ErrorAction Stop
        $frameworks = @()
        if ($config.runtimeOptions.frameworks) { $frameworks = @($config.runtimeOptions.frameworks) }
        if ($config.runtimeOptions.framework) { $frameworks += $config.runtimeOptions.framework }
        foreach ($framework in $frameworks) {
            $flavour = @($script:DotNetFlavours | Where-Object { $_.SharedFramework -eq $framework.name }) | Select-Object -First 1
            $version = ConvertTo-VersionOrNull -Text $framework.version
            if ($flavour -and $version) { "DotNet:$($flavour.Flavour):$($version.Major)" } else { "unknown framework $($framework.name) $($framework.version)" }
        }
    }
    return @($capabilities | Sort-Object -Unique)
}

# Check the signer of each exe the catalogue names for a tool, in a folder,
# against its family's expected signer. Returns "exe: signer" lines; throws
# on the first exe missing or not accepted.
function Test-ToolSigner {
    param($CatalogueTool, [string]$Folder)
    $familyRow = Get-FamilyRow -Name $CatalogueTool.Family
    $descriptions = foreach ($exe in @(@($CatalogueTool.Gui) + @($CatalogueTool.Cli) | Where-Object { $_ })) {
        $exePath = Join-Path $Folder $exe
        if (-not [System.IO.File]::Exists($exePath)) { throw "$exe is missing" }
        $check = Test-SignerAccepted -SignerInfo (Get-SignerInfo -Path $exePath) -ExpectedSigner $familyRow.ExpectedSigner -UnsignedAllowed $familyRow.UnsignedAllowed
        if (-not $check.Accepted) { throw "$exe is signed by $($check.Description), expected $($familyRow.ExpectedSigner)" }
        "${exe}: $($check.Description)"
    }
    return @($descriptions)
}

# The processes running an exe from inside a folder (name and id), from
# their image paths: a tool in use is never swapped or removed.
function Get-ProcessRunningFrom {
    param([string]$Folder)
    $prefix = [System.IO.Path]::GetFullPath($Folder).TrimEnd('\') + '\'
    $running = foreach ($process in @(Get-CimInstance -ClassName Win32_Process -ErrorAction Stop)) {
        if ($process.ExecutablePath -and $process.ExecutablePath.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) { "$($process.Name) ($($process.ProcessId))" }
    }
    return @($running)
}

# Install or update a tool: download, verify, extract to a new folder, check
# its files and signer, then swap it in for the old one. Returns the tool's
# new state record; throws on failure (the old copy stays in place).
function Install-Tool {
    param($CatalogueTool, $Remote, $State, [switch]$Reinstall)
    $finalFolder = Get-ToolFolder -CatalogueTool $CatalogueTool
    $newFolder = "$finalFolder.new"
    $oldFolder = "$finalFolder.old"
    Remove-OwnedFolder -Path $newFolder -Root $script:installRoot
    Remove-OwnedFolder -Path $oldFolder -Root $script:installRoot

    $download = Save-VerifiedDownload -Remote $Remote -StagingFolder $script:stagingFolder
    Write-ConsoleLine -Text "Downloaded $($Remote.FileName) (SHA-256 $($download.Sha256); vendor hash: $($download.VendorHashMatched))" -Indent 4
    $entryPoint = @(@($CatalogueTool.Gui) + @($CatalogueTool.Cli) | Where-Object { $_ }) | Select-Object -First 1
    $installedIsWhole = [System.IO.File]::Exists((Join-Path $finalFolder $entryPoint))
    if (-not $Reinstall -and $installedIsWhole -and $State.Tools.ContainsKey($CatalogueTool.Name) -and $State.Tools[$CatalogueTool.Name].DownloadSha256 -eq $download.Sha256) {
        # Same bytes as installed: only the marker changed. The installed
        # exes are still checked against today's expected signer.
        Remove-OwnedFile -Path $download.Path -Root $script:stagingFolder
        $null = @(Test-ToolSigner -CatalogueTool $CatalogueTool -Folder $finalFolder)
        return $null
    }
    $null = [System.IO.Directory]::CreateDirectory($newFolder)
    try {
        $files = @(Expand-VerifiedZip -ZipPath $download.Path -Destination $newFolder -IncludeOnly @($CatalogueTool.Files | Where-Object { $_ }) `
                -Exclude @($CatalogueTool.ExcludeFiles | Where-Object { $_ }) -Keep @($CatalogueTool.KeepFiles | Where-Object { $_ }))
        $problems = @(Test-ExtractedFile -Folder $newFolder -Files $files)
        if ($problems.Count -gt 0) { throw ("files did not survive extraction (antivirus?): " + ($problems -join '; ')) }

        $signerDescriptions = @(Test-ToolSigner -CatalogueTool $CatalogueTool -Folder $newFolder)

        # The build's own runtimeconfig.json must name what the catalogue
        # said it needs (the prerequisites were installed for that). A .NET
        # tool whose entry point has none can't be confirmed: refused.
        $entryPoints = @(@($CatalogueTool.Gui) + @($CatalogueTool.Cli) | Where-Object { $_ })
        $expected = @(Get-ToolCapability -CatalogueTool $CatalogueTool -Build $Remote.Build | Where-Object { $_ -like 'DotNet:*' } | Sort-Object -Unique)
        if ($expected.Count -gt 0) {
            $unconfirmed = @($entryPoints | Where-Object { -not (Get-EntryPointRuntimeConfigText -Folder $newFolder -EntryPoint $_) })
            if ($unconfirmed.Count -gt 0) { throw ("can't confirm the .NET line it needs: no runtimeconfig.json for " + ($unconfirmed -join ', ') + ", beside it or inside it") }
        }
        $declared = @(Get-RuntimeConfigCapability -Folder $newFolder -EntryPoints $entryPoints)
        if ($expected.Count -gt 0 -or $declared.Count -gt 0) {
            $notCovered = @($declared | Where-Object { $expected -notcontains $_ -and -not ($_ -like 'DotNet:NETCore:*' -and $expected -contains ($_ -replace 'NETCore', 'WindowsDesktop')) })
            if ($notCovered.Count -gt 0) { throw ("its runtimeconfig.json needs " + ($notCovered -join ', ') + ", not what the catalogue says (" + ($expected -join ', ') + ")") }
        }

        $zoneCount = Remove-ZoneIdentifier -Folder $newFolder
        if ($zoneCount -gt 0) { Write-ConsoleLine -Text "Mark of the Web removed from $zoneCount file(s)." -Indent 4 }

        $userData = Get-ToolUserDataPath -CatalogueTool $CatalogueTool
        foreach ($keptFolder in $userData.Folders) {
            $keptSource = Join-Path $finalFolder $keptFolder
            if ([System.IO.Directory]::Exists($keptSource)) {
                $keptTarget = Join-Path $newFolder $keptFolder
                Remove-OwnedFolder -Path $keptTarget -Root $newFolder
                $null = [System.IO.Directory]::CreateDirectory([System.IO.Path]::GetDirectoryName($keptTarget))
                Copy-Item -LiteralPath $keptSource -Destination $keptTarget -Recurse -Force -ErrorAction Stop
            }
        }
        foreach ($keptFile in $userData.Files) {
            $keptSource = Join-Path $finalFolder $keptFile
            if ([System.IO.File]::Exists($keptSource)) { Copy-Item -LiteralPath $keptSource -Destination (Join-Path $newFolder $keptFile) -Force -ErrorAction Stop }
        }
    } catch {
        try { Remove-OwnedFolder -Path $newFolder -Root $script:installRoot } catch {}
        throw
    } finally {
        try { Remove-OwnedFile -Path $download.Path -Root $script:stagingFolder } catch {}
    }

    # The swap. A tool running from its folder is left alone: Windows lets
    # the folder be renamed under it, but the running tool would then load
    # files from the new copy. The new copy is discarded and the old one
    # stays. A rename that fails for another reason does the same.
    if ([System.IO.Directory]::Exists($finalFolder)) {
        $running = @(Get-ProcessRunningFrom -Folder $finalFolder)
        if ($running.Count -gt 0) {
            try { Remove-OwnedFolder -Path $newFolder -Root $script:installRoot } catch {}
            throw [System.InvalidOperationException]::new("in use, not updated (close it and run again): $($running -join ', ')")
        }
        try {
            [System.IO.Directory]::Move($finalFolder, $oldFolder)
        } catch {
            try { Remove-OwnedFolder -Path $newFolder -Root $script:installRoot } catch {}
            throw [System.InvalidOperationException]::new("in use, not updated (close it and run again): $(Get-OneLineMessage -ErrorRecord $_)")
        }
    }
    [System.IO.Directory]::Move($newFolder, $finalFolder)
    try { Remove-OwnedFolder -Path $oldFolder -Root $script:installRoot } catch { Add-RunWarning -Message "$($CatalogueTool.Name): the previous copy could not be deleted ($(Format-Unbreakable -Text $oldFolder)); the next run removes it." }

    foreach ($writablePath in @($CatalogueTool.WritablePaths | Where-Object { $_ })) { Grant-WritablePath -Path (Join-Path $finalFolder $writablePath) }
    foreach ($writableFile in @($CatalogueTool.WritableFiles | Where-Object { $_ })) { Grant-WritableFile -Path (Join-Path $finalFolder $writableFile) }

    $version = $Remote.Version
    $entryPoint = @(@($CatalogueTool.Gui) + @($CatalogueTool.Cli) | Where-Object { $_ }) | Select-Object -First 1
    if (-not $version -and $entryPoint) {
        $versionInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo((Join-Path $finalFolder $entryPoint))
        $version = [string]$versionInfo.ProductVersion
        if (-not $version) { $version = [string]$versionInfo.FileVersion }
    }
    return @{
        Family = $CatalogueTool.Family; Folder = (Get-RelativePath -Path $finalFolder -Root $script:installRoot); Version = $version; Build = $Remote.Build
        Marker = $Remote.Marker; SourceUrl = $Remote.Url; DownloadSha256 = $download.Sha256; VendorHashAlgorithm = $Remote.VendorHashAlgorithm
        VendorHash = $Remote.VendorHash; VendorHashMatched = $download.VendorHashMatched; Signer = ($signerDescriptions -join '; ')
        CatalogueFingerprint = (Get-CatalogueRowFingerprint -CatalogueTool $CatalogueTool)
        InstalledUtc = (Format-UtcTime -Time (Get-Date)); Files = @($files | ForEach-Object { @{ RelativePath = $_.RelativePath; Length = $_.Length; Sha256 = $_.Sha256; Class = 'Vendor' } })
        Shortcuts = @()
    }
}

# Remove a tool the script installed: its folder (PATH entries and shortcuts
# are reconciled afterwards).
function Remove-Tool {
    param([string]$Name, $State)
    $record = $State.Tools[$Name]
    $folder = Join-Path $script:installRoot $record.Folder
    $running = @(Get-ProcessRunningFrom -Folder $folder)
    if ($running.Count -gt 0) { throw [System.InvalidOperationException]::new("in use, not removed (close it and run again): $($running -join ', ')") }
    Remove-OwnedFolder -Path $folder -Root $script:installRoot
    $removedShortcuts = 0
    foreach ($shortcut in @($record.Shortcuts)) {
        try { Remove-OwnedShortcut -Path $shortcut; $removedShortcuts++ } catch { Add-RunWarning -Message "${Name}: shortcut $(Format-Unbreakable -Text $shortcut) could not be removed: $(Get-OneLineMessage -ErrorRecord $_)" }
    }
    $State.Tools.Remove($Name)
    $State.Ancillary.Remove($Name)       # its synced content went with its folder
    $detail = "$Name removed ($(Format-Unbreakable -Text $folder)), $removedShortcuts shortcut(s) with it"
    if (@($record.EulaKeys | Where-Object { $_ }).Count -gt 0) {
        $detail += "; EulaAccepted left under HKCU\Software\Sysinternals ($($record.EulaKeys -join ', ')): the acceptance may predate this script"
    }
    return $detail
}

# Sync a tool's ancillary content with its own --sync. The content folder is
# moved aside first, since --sync never removes a file retired upstream; on
# success the old folder is deleted and the differences counted, on failure
# it is put back.
function Sync-AncillaryContent {
    param($AncillaryRow, $Remote, $State)
    $catalogueTool = @($script:Catalogue | Where-Object { $_.Name -eq $AncillaryRow.Tool }) | Select-Object -First 1
    $toolFolder = Get-ToolFolder -CatalogueTool $catalogueTool
    $exePath = Join-Path $toolFolder $catalogueTool.Cli[0]
    if (-not [System.IO.File]::Exists($exePath)) { throw "$($AncillaryRow.Tool) is not installed" }
    $contentFolder = Join-Path $toolFolder $AncillaryRow.Folder
    $previousFolder = "$contentFolder.previous"
    Remove-OwnedFolder -Path $previousFolder -Root $toolFolder

    $before = Get-FolderSnapshot -Folder $contentFolder
    $outsideBefore = Get-FolderSnapshot -Folder $toolFolder -Exclude @($AncillaryRow.Folder)
    if ([System.IO.Directory]::Exists($contentFolder)) { [System.IO.Directory]::Move($contentFolder, $previousFolder) }

    $outputPath = Join-Path $script:stagingFolder "$($AncillaryRow.Tool)-sync-output.txt"
    $errorPath = Join-Path $script:stagingFolder "$($AncillaryRow.Tool)-sync-errors.txt"
    $exitCode = -1
    $syncError = ''
    try {
        $exitCode = Invoke-ProcessAndWait -FilePath $exePath -Arguments @('--sync') -WorkingDirectory $toolFolder -OutputPath $outputPath -ErrorPath $errorPath
    } catch {
        $syncError = Get-OneLineMessage -ErrorRecord $_
    }
    foreach ($outputFile in @($outputPath, $errorPath)) {
        if ([System.IO.File]::Exists($outputFile)) {
            foreach ($line in [System.IO.File]::ReadAllLines($outputFile)) { Add-LogLine -Text "    | $line" }     # the tool's own output, as it wrote it
            Remove-OwnedFile -Path $outputFile -Root $script:stagingFolder
        }
    }
    if ($exitCode -ne 0 -or -not [System.IO.Directory]::Exists($contentFolder)) {
        try { Remove-OwnedFolder -Path $contentFolder -Root $toolFolder } catch {}
        if ([System.IO.Directory]::Exists($previousFolder)) { [System.IO.Directory]::Move($previousFolder, $contentFolder) }
        if ($syncError) { throw "--sync failed: $syncError; the previous content was put back" }
        throw "--sync exited with $exitCode; the previous content was put back"
    }
    Remove-OwnedFolder -Path $previousFolder -Root $toolFolder

    $after = Get-FolderSnapshot -Folder $contentFolder
    $difference = Compare-FolderSnapshot -Before $before -After $after
    $outsideAfter = Get-FolderSnapshot -Folder $toolFolder -Exclude @($AncillaryRow.Folder)
    $outsideDifference = Compare-FolderSnapshot -Before $outsideBefore -After $outsideAfter
    $outsideChanges = @($outsideDifference.Added) + @($outsideDifference.Changed) + @($outsideDifference.Removed)
    if ($outsideChanges.Count -gt 0) {
        Add-RunWarning -Message ("$($AncillaryRow.Tool) --sync changed files outside $($AncillaryRow.Folder): " + ($outsideChanges -join ', '))
    }

    # The tool's file record: its vendor files as they are now, plus the
    # synced content.
    $record = $State.Tools[$AncillaryRow.Tool]
    $contentPrefix = $AncillaryRow.Folder + '\'
    $files = @($record.Files | Where-Object { $_.Class -eq 'Vendor' -and -not $_.RelativePath.StartsWith($contentPrefix, [System.StringComparison]::OrdinalIgnoreCase) -and $outsideAfter.ContainsKey($_.RelativePath) } |
            ForEach-Object { @{ RelativePath = $_.RelativePath; Length = $outsideAfter[$_.RelativePath].Length; Sha256 = $outsideAfter[$_.RelativePath].Sha256; Class = 'Vendor' } })
    $files += @($after.Keys | Sort-Object | ForEach-Object { @{ RelativePath = ($contentPrefix + $_); Length = $after[$_].Length; Sha256 = $after[$_].Sha256; Class = 'Ancillary' } })
    $record.Files = $files

    $State.Ancillary[$AncillaryRow.Tool] = @{
        Commit = $Remote.Marker; CommitUtc = $Remote.CommitUtc; CommitUrl = $Remote.Url; SyncedUtc = (Format-UtcTime -Time (Get-Date))
        FileCount = $after.Count; Added = $difference.Added.Count; Changed = $difference.Changed.Count; Removed = $difference.Removed.Count
    }
    return ("{0}: {1} files ({2} added, {3} changed, {4} removed), commit {5}" -f $AncillaryRow.Description, $after.Count, $difference.Added.Count, $difference.Changed.Count, $difference.Removed.Count, $Remote.Marker.Substring(0, 12))
}

# --- PATH, shortcuts, EULA ---

# The machine PATH as written in the registry (unexpanded, so entries such
# as %SystemRoot% stay as they are).
function Get-MachinePathValue {
    $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SYSTEM\CurrentControlSet\Control\Session Manager\Environment', $false)
    try { return [string]$key.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames) } finally { $key.Close() }
}

# Write the machine PATH as REG_EXPAND_SZ and tell running programs
# (WM_SETTINGCHANGE "Environment"). [Environment]::SetEnvironmentVariable
# is not used: it writes REG_SZ, expanding every %variable% for good.
function Set-MachinePathValue {
    param([string]$Value)
    $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SYSTEM\CurrentControlSet\Control\Session Manager\Environment', $true)
    try { $key.SetValue('Path', $Value, [Microsoft.Win32.RegistryValueKind]::ExpandString) } finally { $key.Close() }
    if (-not ('ForensicWorkstation.NativeMethods' -as [type])) {
        Add-Type -Namespace 'ForensicWorkstation' -Name 'NativeMethods' -MemberDefinition @'
[DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
public static extern IntPtr SendMessageTimeout(IntPtr hWnd, uint Msg, UIntPtr wParam, string lParam, uint fuFlags, uint uTimeout, out UIntPtr lpdwResult);
'@
    }
    $result = [UIntPtr]::Zero
    $hwndBroadcast = [IntPtr]0xffff
    $wmSettingChange = 0x1A
    $smtoAbortIfHung = 0x2
    $null = [ForensicWorkstation.NativeMethods]::SendMessageTimeout($hwndBroadcast, $wmSettingChange, [UIntPtr]::Zero, 'Environment', $smtoAbortIfHung, 5000, [ref]$result)
}

# Bring the machine PATH in line with the installed command-line tools: add
# each CLI tool's folder; in a full run, remove entries under the install
# root that no installed tool needs. A tool dropped from the catalogue but
# still installed (its removal refused or failed) keeps its entry until it is
# removed. Two tools exposing the same exe name are refused (the second is
# not added). Returns result lines.
function Update-MachinePath {
    param($State, [bool]$AllowRemoval)
    $wanted = New-Object System.Collections.Generic.List[string]
    $exeOwners = @{}
    $refused = New-Object System.Collections.Generic.List[string]
    foreach ($catalogueTool in $script:Catalogue) {
        if (@($catalogueTool.Cli).Count -eq 0 -or -not $State.Tools.ContainsKey($catalogueTool.Name)) { continue }
        if (Test-ToolFolderWritable -CatalogueTool $catalogueTool) { $refused.Add("$($catalogueTool.Name): its folder is writable by the account, so it is never put on PATH"); continue }
        $folder = Get-ToolFolder -CatalogueTool $catalogueTool
        $clash = $null
        foreach ($exe in @(Get-ChildItem -LiteralPath $folder -Filter '*.exe' -File -ErrorAction SilentlyContinue)) {
            $exeName = $exe.Name.ToLowerInvariant()
            if ($exeOwners.ContainsKey($exeName)) { $clash = "$($exe.Name) is also in $($exeOwners[$exeName])"; break }
        }
        if ($clash) { $refused.Add("$($catalogueTool.Name): not put on PATH, $clash"); continue }
        foreach ($exe in @(Get-ChildItem -LiteralPath $folder -Filter '*.exe' -File -ErrorAction SilentlyContinue)) { $exeOwners[$exe.Name.ToLowerInvariant()] = $catalogueTool.Name }
        $wanted.Add($folder)
    }

    $stillInstalledNotInCatalogue = @($State.Tools.Keys | Where-Object { $name = $_; -not ($script:Catalogue | Where-Object { $_.Name -eq $name }) } |
            ForEach-Object { Join-Path $script:installRoot $State.Tools[$_].Folder })
    $current = @((Get-MachinePathValue).TrimEnd(';') -split ';')
    $rootPrefix = $script:installRoot.TrimEnd('\') + '\'
    $keptForInstalled = New-Object System.Collections.Generic.List[string]
    $kept = foreach ($entry in $current) {
        $isOurs = $entry -ne '' -and $entry.StartsWith($rootPrefix, [System.StringComparison]::OrdinalIgnoreCase)
        $isWanted = [bool]($wanted | Where-Object { $_ -ieq $entry.TrimEnd('\') })
        $isStillInstalled = [bool]($stillInstalledNotInCatalogue | Where-Object { $_ -ieq $entry.TrimEnd('\') })
        if ($isOurs -and $AllowRemoval -and -not $isWanted -and -not $isStillInstalled) { continue }
        if ($isOurs -and -not $isWanted -and $isStillInstalled) { $keptForInstalled.Add([System.IO.Path]::GetFileName($entry.TrimEnd('\'))) }
        $entry
    }
    $kept = @($kept)
    $added = @($wanted | Where-Object { $entry = $_; -not ($kept | Where-Object { $_.TrimEnd('\') -ieq $entry }) })
    $removedCount = $current.Count - $kept.Count
    $newValue = (@($kept) + $added) -join ';'
    $lines = New-Object System.Collections.Generic.List[string]
    $keptText = ''
    if ($keptForInstalled.Count -gt 0) { $keptText = ", $($keptForInstalled.Count) kept (still installed, no longer in the catalogue): $($keptForInstalled -join ', ')" }
    if ($added.Count -eq 0 -and $removedCount -eq 0 -and -not $keptText) {
        $lines.Add("machine PATH already has every tool folder ($($wanted.Count))")
    } elseif ($added.Count -eq 0 -and $removedCount -eq 0) {
        $lines.Add("machine PATH: 0 folder(s) added, 0 removed$keptText")
    } elseif ($newValue.Length -gt 2047) {
        throw "the machine PATH would be $($newValue.Length) characters, over 2047: not changed"
    } else {
        Set-MachinePathValue -Value $newValue
        $lines.Add("machine PATH: $($added.Count) folder(s) added, $removedCount removed$keptText")
    }
    $State.PathEntries = @($wanted)
    foreach ($refusal in $refused) { Add-RunFailure -Message "PATH: $refusal" }
    return [pscustomobject]@{ Lines = $lines.ToArray(); Refused = $refused.ToArray() }
}

# Where a GUI tool's shortcuts go: the Desktop and the Start Menu, in the
# family's folder when the family has several GUI tools, else directly (and
# directly for a row with ShortcutOutsideFolder). The Desktop and the Start
# Menu are always laid out alike.
function Get-ShortcutPath {
    param($CatalogueTool)
    $familyRow = Get-FamilyRow -Name $CatalogueTool.Family
    $guiCount = @($script:Catalogue | Where-Object { $_.Family -eq $CatalogueTool.Family -and $_.Gui }).Count
    $paths = foreach ($base in @($script:desktopFolder, $script:startMenuFolder)) {
        if ($guiCount -le 1 -or $CatalogueTool.ShortcutOutsideFolder) { Join-Path $base "$($CatalogueTool.DisplayName).lnk" } else { Join-Path (Join-Path $base $familyRow.ShortcutFolder) "$($CatalogueTool.DisplayName).lnk" }
    }
    return @($paths)
}

# Remove a shortcut the script made: only .lnk files on the Desktop or in
# the Start Menu.
function Remove-OwnedShortcut {
    param([string]$Path)
    if (-not $Path.EndsWith('.lnk', [System.StringComparison]::OrdinalIgnoreCase)) { throw "refused: $Path is not a shortcut" }
    $insideDesktop = $true
    try { Assert-PathInside -Path $Path -Root $script:desktopFolder } catch { $insideDesktop = $false }
    if (-not $insideDesktop) { Assert-PathInside -Path $Path -Root $script:startMenuFolder }
    if ([System.IO.File]::Exists($Path)) { [System.IO.File]::Delete($Path) }
}

# Create one shortcut, or correct it: a shortcut that already has the
# target, working folder and description is left as it is. Returns 'made',
# 'corrected' or 'unchanged'; throws when it can't be saved.
function Set-Shortcut {
    param([string]$Path, [string]$Target, [string]$Description)
    $null = [System.IO.Directory]::CreateDirectory([System.IO.Path]::GetDirectoryName($Path))
    $workingDirectory = [System.IO.Path]::GetDirectoryName($Target)
    $existed = [System.IO.File]::Exists($Path)
    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $null
    try {
        $shortcut = $shell.CreateShortcut($Path)        # reads the shortcut when it exists
        if ($existed -and $shortcut.TargetPath -ieq $Target -and $shortcut.WorkingDirectory -ieq $workingDirectory -and $shortcut.Description -eq $Description) { return 'unchanged' }
        $shortcut.TargetPath = $Target
        $shortcut.WorkingDirectory = $workingDirectory
        $shortcut.Description = $Description
        $shortcut.Save()
        if ($existed) { return 'corrected' }
        return 'made'
    } finally {
        if ($shortcut) { try { $null = [System.Runtime.InteropServices.Marshal]::ReleaseComObject($shortcut) } catch {} }
        try { $null = [System.Runtime.InteropServices.Marshal]::ReleaseComObject($shell) } catch {}
    }
}

# Shortcuts for every installed GUI tool, each on its own (one that can't
# be saved doesn't stop the others); in a full run, shortcuts the script
# made that are no longer wanted (a tool's layout changed) are removed, and
# empty family folders with them. A tool's record lists its shortcuts that
# exist. Returns Detail and Failures (one line each).
function Update-ToolShortcut {
    param($State, [bool]$AllowRemoval)
    $counts = @{ made = 0; corrected = 0; unchanged = 0; removed = 0 }
    $failures = New-Object System.Collections.Generic.List[string]
    foreach ($catalogueTool in $script:Catalogue) {
        if (-not $catalogueTool.Gui -or -not $State.Tools.ContainsKey($catalogueTool.Name)) { continue }
        $record = $State.Tools[$catalogueTool.Name]
        $target = Join-Path (Get-ToolFolder -CatalogueTool $catalogueTool) $catalogueTool.Gui
        $wanted = @(Get-ShortcutPath -CatalogueTool $catalogueTool)
        foreach ($path in $wanted) {
            try {
                $outcome = Set-Shortcut -Path $path -Target $target -Description "$($catalogueTool.DisplayName) ($($catalogueTool.Family))"
                $counts[$outcome]++
            } catch {
                $message = Get-OneLineMessage -ErrorRecord $_
                if ($message.IndexOf($path, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                    $failures.Add("$($catalogueTool.Name): shortcut not saved: $($message.Replace($path, (Format-Unbreakable -Text $path)))")
                } else {
                    $failures.Add("$($catalogueTool.Name): $(Format-Unbreakable -Text $path) not saved: $message")
                }
            }
        }
        $kept = @($record.Shortcuts)
        if ($AllowRemoval) {
            foreach ($old in @($record.Shortcuts | Where-Object { $wanted -notcontains $_ })) {
                try { Remove-OwnedShortcut -Path $old; $counts.removed++ } catch { $failures.Add("$($catalogueTool.Name): $(Format-Unbreakable -Text $old) not removed: $(Get-OneLineMessage -ErrorRecord $_)") }
            }
            $kept = @()
        }
        $record.Shortcuts = @(@($kept) + $wanted | Where-Object { [System.IO.File]::Exists($_) } | Sort-Object -Unique)
    }
    $folders = @($script:Families | ForEach-Object { $name = $_.ShortcutFolder; foreach ($base in @($script:desktopFolder, $script:startMenuFolder)) { Join-Path $base $name } })
    if ($AllowRemoval) {
        foreach ($folder in $folders) {
            if ([System.IO.Directory]::Exists($folder) -and @([System.IO.Directory]::GetFileSystemEntries($folder)).Count -eq 0 -and $State.ShortcutFolders -contains $folder) {
                [System.IO.Directory]::Delete($folder)
            }
        }
    }
    $State.ShortcutFolders = @($folders | Where-Object { [System.IO.Directory]::Exists($_) })
    $detail = "{0} made, {1} corrected, {2} unchanged, {3} removed" -f $counts.made, $counts.corrected, $counts.unchanged, $counts.removed
    if ($failures.Count -gt 0) { $detail += ", $($failures.Count) failed" }
    return [pscustomobject]@{ Detail = $detail; Failures = $failures.ToArray() }
}

# Accept the Sysinternals EULA for the running account (no first-run
# prompt).
function Set-SysinternalsEula {
    param($CatalogueTool)
    foreach ($keyName in @($CatalogueTool.EulaKeys)) {
        $keyPath = "HKCU:\Software\Sysinternals\$keyName"
        if (-not (Test-Path -LiteralPath $keyPath)) { $null = New-Item -Path $keyPath -Force -ErrorAction Stop }
        $null = New-ItemProperty -LiteralPath $keyPath -Name 'EulaAccepted' -Value 1 -PropertyType DWord -Force -ErrorAction Stop
    }
}

# --- Records ---

# Write a records file: UTF-8 without BOM, CRLF (shared rules).
function Write-RecordFile {
    param([string]$Path, [string[]]$Lines)
    [System.IO.File]::WriteAllText($Path, (($Lines | ForEach-Object { $_ + "`r`n" }) -join ''), $script:utf8NoBom)
}

# inventory.csv: every tool and prerequisite version on record, the
# prerequisite versions present that the script didn't install, and the
# ancillary content.
function Get-InventoryLine {
    param($State)
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add((ConvertTo-CsvLine -Cells $script:InventoryColumns))
    foreach ($name in ($State.Tools.Keys | Sort-Object)) {
        $record = $State.Tools[$name]
        $lines.Add((ConvertTo-CsvLine -Cells @('Tool', $record.Family, $name, $record.Version, $record.Build, 'yes', $record.SourceUrl, $record.DownloadSha256,
                    $record.VendorHashAlgorithm, $record.VendorHash, $record.VendorHashMatched, $record.Signer, $record.Marker, $record.InstalledUtc, (Join-Path $script:installRoot $record.Folder))))
    }
    foreach ($id in ($State.Prerequisites.Keys | Sort-Object)) {
        $prerequisiteRecord = $State.Prerequisites[$id]
        # A .NET line's change marker is its version; a prerequisite updated
        # in place keeps its own (the driver's commit, Visual C++'s file).
        $changeMarker = [string]$prerequisiteRecord.Marker
        foreach ($version in ($prerequisiteRecord.Versions.Keys | Sort-Object)) {
            $versionRecord = $prerequisiteRecord.Versions[$version]
            $versionMarker = $version
            if ($changeMarker) { $versionMarker = $changeMarker }
            $lines.Add((ConvertTo-CsvLine -Cells @('Prerequisite', '', $prerequisiteRecord.DisplayName, $version, 'x64', 'yes', $versionRecord.SourceUrl, $versionRecord.InstallerSha256,
                        $versionRecord.VendorHashAlgorithm, $versionRecord.VendorHash, $versionRecord.VendorHashMatched, $versionRecord.Signer, $versionMarker, $versionRecord.InstalledUtc, '')))
        }
    }
    foreach ($present in $script:prerequisitesNotOwned) {
        $lines.Add((ConvertTo-CsvLine -Cells @('Prerequisite', '', $present.DisplayName, $present.Version, '', 'no', '', '', '', '', '', '', '', '', '')))
    }
    foreach ($toolName in ($State.Ancillary.Keys | Sort-Object)) {
        $ancillaryRecord = $State.Ancillary[$toolName]
        $row = @($script:AncillaryContent | Where-Object { $_.Tool -eq $toolName }) | Select-Object -First 1
        $description = $toolName
        if ($row) { $description = $row.Description }
        $lines.Add((ConvertTo-CsvLine -Cells @('Ancillary', 'Zimmerman', $description, $ancillaryRecord.Commit, '', 'yes', $ancillaryRecord.CommitUrl, '', '', '', '', '', $ancillaryRecord.Commit, $ancillaryRecord.SyncedUtc, '')))
    }
    return $lines.ToArray()
}

# files.csv: the SHA-256 of every installed file (vendor files and synced
# content), relative to the install root, and one UserData row per user data
# path (no length or hash: listed, not verified).
function Get-FileRecordLine {
    param($State)
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add((ConvertTo-CsvLine -Cells $script:FilesColumns))
    foreach ($name in ($State.Tools.Keys | Sort-Object)) {
        $record = $State.Tools[$name]
        foreach ($file in @($record.Files)) {
            $lines.Add((ConvertTo-CsvLine -Cells @($record.Family, $name, $file.Class, (Join-Path $record.Folder $file.RelativePath), $file.Length, $file.Sha256, $record.InstalledUtc)))
        }
        $catalogueTool = @($script:Catalogue | Where-Object { $_.Name -eq $name }) | Select-Object -First 1
        if ($catalogueTool) {
            $userData = Get-ToolUserDataPath -CatalogueTool $catalogueTool
            foreach ($userDataPath in @($userData.Folders) + @($userData.Files)) {
                $lines.Add((ConvertTo-CsvLine -Cells @($record.Family, $name, 'UserData', (Join-Path $record.Folder $userDataPath), '', '', $record.InstalledUtc)))
            }
        }
    }
    return $lines.ToArray()
}

# --- Verify mode ---

# Re-hash every file in files.csv; list files missing, changed, and files in
# a tool's folder that aren't on record (its user data aside).
function Invoke-Verification {
    param([string]$FilesCsvPath, [string[]]$ToolNames)
    if (-not [System.IO.File]::Exists($FilesCsvPath)) { throw "no files.csv at ${FilesCsvPath}: nothing to verify against" }
    $rows = @(Import-Csv -LiteralPath $FilesCsvPath -Encoding UTF8)
    $byTool = $rows | Group-Object -Property Tool
    foreach ($group in $byTool) {
        $toolName = $group.Name
        if ($ToolNames -notcontains $toolName) { continue }
        $familyName = $group.Group[0].Family
        $missing = New-Object System.Collections.Generic.List[string]
        $changed = New-Object System.Collections.Generic.List[string]
        $recorded = @{}
        $verifiedRows = @($group.Group | Where-Object { $_.Class -ne 'UserData' })     # user data is listed, never verified
        foreach ($row in $verifiedRows) {
            $path = Join-Path $script:installRoot $row.RelativePath
            $recorded[$row.RelativePath.ToLowerInvariant()] = $true
            if (-not [System.IO.File]::Exists($path)) { $missing.Add($row.RelativePath); continue }
            if ((Get-FileHashHex -Path $path) -ne $row.Sha256) { $changed.Add($row.RelativePath) }
        }
        $catalogueTool = @($script:Catalogue | Where-Object { $_.Name -eq $toolName }) | Select-Object -First 1
        $extra = New-Object System.Collections.Generic.List[string]
        $toolFolder = Join-Path (Join-Path $script:installRoot $familyName) $toolName
        $userDataFolders = @()
        $userDataFiles = @()
        if ($catalogueTool) {
            $userData = Get-ToolUserDataPath -CatalogueTool $catalogueTool
            $userDataFolders = $userData.Folders
            $userDataFiles = $userData.Files
        }
        if ([System.IO.Directory]::Exists($toolFolder)) {
            foreach ($file in @(Get-ChildItem -LiteralPath $toolFolder -Recurse -File -Force)) {
                $relativeToRoot = Get-RelativePath -Path $file.FullName -Root $script:installRoot
                if ($recorded.ContainsKey($relativeToRoot.ToLowerInvariant())) { continue }
                $relativeToTool = Get-RelativePath -Path $file.FullName -Root $toolFolder
                if ($userDataFolders | Where-Object { $relativeToTool.StartsWith("$_\", [System.StringComparison]::OrdinalIgnoreCase) }) { continue }
                if ($userDataFiles | Where-Object { $relativeToTool -ieq $_ }) { continue }
                $extra.Add($relativeToRoot)
            }
        }
        $total = $verifiedRows.Count
        if ($missing.Count -gt 0 -or $changed.Count -gt 0) {
            Add-Result -Group $familyName -Name $toolName -Status 'FAIL' -Detail "$($missing.Count) missing, $($changed.Count) changed of $total (see Failures)"
            foreach ($path in $missing) { Add-RunFailure -Message "missing: $path" }
            foreach ($path in $changed) { Add-RunFailure -Message "changed: $path" }
        } elseif ($extra.Count -gt 0) {
            Add-Result -Group $familyName -Name $toolName -Status 'WARN' -Detail "$total of $total match; $($extra.Count) file(s) not on record (see Warnings)"
        } else {
            Add-Result -Group $familyName -Name $toolName -Status 'PASS' -Detail "$total of $total files match files.csv"
        }
        foreach ($path in $extra) { Add-RunWarning -Message "not on record: $path" }
    }
}

# --- The end of the run ---

# Whether a result's detail already starts with its name, as a word of its
# own ("EvtxECmd: in use"; not Autoruns in "Autorunsc ...").
function Test-DetailNamesResult {
    param($Result)
    return ($Result.Detail -match ('^' + [regex]::Escape([string]$Result.Name) + '(?![A-Za-z0-9_])'))
}

# A group of one result, as one block line that names what it covers: "Arsenal:
# ArsenalImageMounter: ...". The name is left out where it repeats the group
# ("Records: records") or the detail starts with it already.
function Format-SingleResultText {
    param([string]$Group, $Result)
    if ($Result.Name -ieq $Group -or (Test-DetailNamesResult -Result $Result)) { return "${Group}: $($Result.Detail)" }
    return "${Group}: $($Result.Name): $($Result.Detail)"
}

# An item's line under its group in the result block: its name, then its
# detail, the name once where the detail already starts with it.
function Format-ResultItemText {
    param($Result)
    if (Test-DetailNamesResult -Result $Result) { return $Result.Detail }
    return "$($Result.Name): $($Result.Detail)"
}

# Warnings and failures, then the result block: the overall verdict, one
# line per group, and a line for each item not PASS with a pointer to its
# explanation.
function Write-ResultBlock {
    param([string]$Coverage)
    if ($script:runWarnings.Count -gt 0) {
        Write-SectionHeading -Title 'Warnings'
        foreach ($warning in $script:runWarnings) { Write-ConsoleLine -Text "- $warning" -Indent 2 -ContinuationIndent 4 }
    }
    if ($script:runFailures.Count -gt 0) {
        Write-SectionHeading -Title 'Failures'
        foreach ($failure in $script:runFailures) { Write-ConsoleLine -Text "- $failure" -Indent 2 -ContinuationIndent 4 }
    }
    # Every warning and failure counts towards the verdict, also those raised
    # without a result of their own (e.g. an old copy that couldn't be
    # deleted): none can leave the run PASS.
    $statuses = @($script:results | ForEach-Object { $_.Status })
    if ($script:runWarnings.Count -gt 0) { $statuses += 'WARN' }
    if ($script:runFailures.Count -gt 0) { $statuses += 'FAIL' }
    $overall = Get-WorstStatus -Statuses $statuses
    Write-ConsoleLine -Text ''
    Write-ConsoleLine -Text ('=' * $script:ConsoleWidth)
    $verdictText = "RESULT: $overall - $Coverage"
    if ($script:useColour) {
        # Wrapped as the plain line is, then the verdict word coloured on
        # the first line only.
        $verdictPrefix = 'RESULT: '
        $verdictLines = @(Format-WrappedText -Text $verdictText -Indent 0 -ContinuationIndent 2)
        $firstLine = $verdictLines[0].Replace($script:UnbreakableSpace, ' ')
        Write-Host $verdictPrefix -NoNewline
        Write-Host $overall -ForegroundColor (Get-StatusColour -Status $overall) -NoNewline
        Write-Host $firstLine.Substring($verdictPrefix.Length + $overall.Length)
        Add-LogLine -Text $firstLine
        for ($index = 1; $index -lt $verdictLines.Count; $index++) { Write-RawLine -Text $verdictLines[$index] }
    } else {
        Write-ConsoleLine -Text $verdictText
    }
    Write-ConsoleLine -Text ('=' * $script:ConsoleWidth)
    $groups = @($script:results | ForEach-Object { $_.Group } | Select-Object -Unique)
    foreach ($group in $groups) {
        $groupResults = @($script:results | Where-Object { $_.Group -eq $group })
        $status = Get-WorstStatus -Statuses @($groupResults | ForEach-Object { $_.Status })
        $passCount = @($groupResults | Where-Object { $_.Status -eq 'PASS' }).Count
        if ($groupResults.Count -eq 1) {
            Write-StatusLine -Status $status -Text (Format-SingleResultText -Group $group -Result $groupResults[0])
            continue
        }
        Write-StatusLine -Status $status -Text "${group}: $passCount of $($groupResults.Count) PASS"
        foreach ($item in @($groupResults | Where-Object { $_.Status -ne 'PASS' })) {
            Write-StatusLine -Status $item.Status -Text (Format-ResultItemText -Result $item) -Indent 8
        }
    }
    if ($script:runWarnings.Count -gt 0) { Write-StatusLine -Status 'WARN' -Text "Warnings: $($script:runWarnings.Count) (see Warnings)" }
    if ($script:runFailures.Count -gt 0) { Write-StatusLine -Status 'FAIL' -Text "Failures: $($script:runFailures.Count) (see Failures)" }
    Write-ConsoleLine -Text ('=' * $script:ConsoleWidth)
    return $overall
}

# =============================== MAIN ===============================

# --- Run facts and mode ---
$runStartUtc = (Get-Date).ToUniversalTime()
$runStamp = $runStartUtc.ToString('yyyyMMddTHHmmssZ')
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
$pendingLogLines = New-Object System.Collections.Generic.List[string]
$logPath = ''
$results = New-Object System.Collections.Generic.List[object]
$runWarnings = New-Object System.Collections.Generic.List[string]
$runFailures = New-Object System.Collections.Generic.List[string]
$prerequisitesNotOwned = New-Object System.Collections.Generic.List[object]
$ezIndex = $null
$dotNetIndex = $null
$useColour = -not [Console]::IsOutputRedirected

# -Confirm would make every cmdlet below ask before it acts; the run's plan
# is shown by -CheckOnly instead.
if ($PSBoundParameters.ContainsKey('Confirm')) {
    Write-Host 'Stopped: -Confirm is not supported. Run with -CheckOnly to see what an update would do.'
    exit 3
}
# One dry run: -CheckOnly, or -WhatIf (ShouldProcess answers no under -WhatIf
# and prints its own "What if" line).
$dryRun = $CheckOnly -or -not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Install, update and clean up the forensic tools')
# The dry run is decided; -WhatIf has done its job. Left on, it would reach
# every cmdlet (module loading prints "What if: Set Alias" lines), though
# nothing in a dry run changes anything.
$WhatIfPreference = $false
if ($dryRun -and $Verify) {
    Write-Host 'Stopped: -Verify and -CheckOnly (or -WhatIf) are separate modes; run one at a time.'
    exit 3
}
$mode = 'update'
if ($dryRun) { $mode = 'dry run (nothing is changed)' }
if ($Verify) { $mode = 'verify (re-hash installed files)' }
$selectionGiven = ($Family.Count -gt 0 -or $Tool.Count -gt 0)

$elevated = Test-Elevated
$osName = Get-OsName
$osArchitecture = Get-OsArchitecture
$account = [Security.Principal.WindowsIdentity]::GetCurrent().Name
$scriptSha256 = ''
try { $scriptSha256 = Get-FileHashHex -Path $PSCommandPath } catch { $scriptSha256 = 'unknown' }

$installRoot = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) $InstallFolderName
$recordsRoot = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) $RecordsFolderName
$statePath = Join-Path $recordsRoot 'state.json'
$installersFolder = Join-Path $recordsRoot 'Installers'
$stagingFolder = Join-Path $recordsRoot "Staging\$runStamp"
$desktopFolder = [Environment]::GetFolderPath('Desktop')
$startMenuFolder = [Environment]::GetFolderPath('Programs')

# --- The run log ---
# An update writes its log under the records folder; a dry run or -Verify
# writes there when it can, else under LocalAppData (they need no
# elevation, and the records folder is writable by administrators only).
$readOnlyMode = $dryRun -or $Verify
$logUnderRecords = $elevated -and (-not $readOnlyMode -or [System.IO.Directory]::Exists($recordsRoot))
$runFolder = Join-Path $recordsRoot "Runs\$runStamp"
if (-not $logUnderRecords) { $runFolder = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) "$RecordsFolderName\Runs\$runStamp" }

Write-ConsoleLine -Text ('=' * $ConsoleWidth)
Write-ConsoleLine -Text "Forensic workstation update $WorkstationVersion"
Write-ConsoleLine -Text ('=' * $ConsoleWidth)
Write-LabelValue -Label 'Started' -Value (Format-UtcTime -Time $runStartUtc)
Write-LabelValue -Label 'Host' -Value $env:COMPUTERNAME
Write-LabelValue -Label 'OS' -Value "$osName ($osArchitecture)"
$elevationText = 'not elevated'
if ($elevated) { $elevationText = 'elevated' }
Write-LabelValue -Label 'Account' -Value "$account ($elevationText)"
Write-LabelValue -Label 'Mode' -Value $mode
$selectionText = 'every tool in the catalogue'
if ($selectionGiven) {
    $selectionParts = @()
    if ($Family.Count -gt 0) { $selectionParts += "family $($Family -join ', ')" }
    if ($Tool.Count -gt 0) { $selectionParts += "tool $($Tool -join ', ')" }
    $selectionText = ($selectionParts -join '; ') + ' (nothing is removed)'
}
Write-LabelValue -Label 'Selection' -Value $selectionText
Write-LabelValue -Label 'Script' -Value (Format-Unbreakable -Text $PSCommandPath)
Write-LabelValue -Label 'SHA-256' -Value $scriptSha256
Write-LabelValue -Label 'Tools' -Value (Format-Unbreakable -Text $installRoot)
Write-LabelValue -Label 'Records' -Value (Format-Unbreakable -Text $recordsRoot)

# --- Preconditions: anything that fails here stops before any work ---

if ($osArchitecture -ne 'X64') { Stop-Run -Reason "this script is for amd64 (x64) Windows; this machine is $osArchitecture." }
if (-not [Environment]::Is64BitProcess) { Stop-Run -Reason 'run it from 64-bit Windows PowerShell (this is the 32-bit one).' }
if (-not $dryRun -and -not $Verify -and -not $elevated) { Stop-Run -Reason 'an update needs an elevated prompt (Run as administrator). -CheckOnly and -Verify do not.' }

# The selection: every name must be in the catalogue.
$familyNames = @($Families | ForEach-Object { $_.Name })
$toolNames = @($Catalogue | ForEach-Object { $_.Name })
$unknownFamilies = @($Family | Where-Object { $name = $_; -not ($familyNames | Where-Object { $_ -ieq $name }) })
$unknownTools = @($Tool | Where-Object { $name = $_; -not ($toolNames | Where-Object { $_ -ieq $name }) })
if ($unknownFamilies.Count -gt 0) { Stop-Run -Reason "unknown family: $($unknownFamilies -join ', '). The families are:" -List $familyNames }
if ($unknownTools.Count -gt 0) { Stop-Run -Reason "unknown tool: $($unknownTools -join ', '). The tools are:" -List $toolNames }
$selectedTools = @($Catalogue)
if ($selectionGiven) {
    $selectedTools = @($Catalogue | Where-Object { $row = $_; ($Family | Where-Object { $_ -ieq $row.Family }) -or ($Tool | Where-Object { $_ -ieq $row.Name }) })
}

try {
    if (-not $readOnlyMode) { New-ProtectedFolder -Path $recordsRoot }    # before anything is created inside it
    $null = [System.IO.Directory]::CreateDirectory($runFolder)
    $logPath = Join-Path $runFolder 'run.log'
    [System.IO.File]::WriteAllText($logPath, (($pendingLogLines | ForEach-Object { $_ + "`r`n" }) -join ''), $utf8NoBom)
} catch {
    Stop-Run -Reason "the run log can't be written in $(Format-Unbreakable -Text $runFolder) ($(Get-OneLineMessage -ErrorRecord $_))."
}
Write-LabelValue -Label 'Log' -Value (Format-Unbreakable -Text $logPath)
Write-ConsoleLine -Text ''
Write-ConsoleLine -Text 'Warnings found during the run are listed at the end, before the result.'

try {
    Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem -ErrorAction Stop
    $state = Read-State -Path $statePath
} catch {
    Stop-Run -Reason "state.json ($(Format-Unbreakable -Text $statePath)) can't be read, so what this script installed is unknown: $(Get-OneLineMessage -ErrorRecord $_)"
}

# --- Verify mode ---
if ($Verify) {
    Write-SectionHeading -Title 'Verifying installed files against files.csv'
    try {
        Invoke-Verification -FilesCsvPath (Join-Path $recordsRoot 'files.csv') -ToolNames @($selectedTools | ForEach-Object { $_.Name })
    } catch {
        Add-Result -Group 'Verify' -Name 'files.csv' -Status 'FAIL' -Detail (Get-OneLineMessage -ErrorRecord $_)
    }
    $overall = Write-ResultBlock -Coverage 'every file installed by this script, re-hashed against files.csv'
    switch ($overall) { 'PASS' { exit 0 } 'WARN' { exit 1 } default { exit 2 } }
}

# --- TLS ---
# Windows PowerShell 5.1 may default to TLS 1.0; every source needs 1.2.
try {
    $protocols = [Net.SecurityProtocolType]::Tls12
    if ([enum]::GetNames([Net.SecurityProtocolType]) -contains 'Tls13') { $protocols = $protocols -bor [Net.SecurityProtocolType]::Tls13 }
    [Net.ServicePointManager]::SecurityProtocol = $protocols
} catch {
    Stop-Run -Reason "TLS 1.2 can't be enabled: $(Get-OneLineMessage -ErrorRecord $_)"
}

# --- Check every source ---
Write-SectionHeading -Title 'Checking sources'
$toolChecks = New-Object System.Collections.Generic.List[object]
foreach ($catalogueTool in $selectedTools) {
    $record = $null
    if ($state.Tools.ContainsKey($catalogueTool.Name)) { $record = $state.Tools[$catalogueTool.Name] }
    $check = [pscustomobject]@{ Tool = $catalogueTool; Record = $record; Remote = $null; Status = ''; Detail = '' }
    try {
        $check.Remote = Get-ToolRemote -CatalogueTool $catalogueTool
        $entryPoint = @(@($catalogueTool.Gui) + @($catalogueTool.Cli) | Where-Object { $_ }) | Select-Object -First 1
        $installedAndWhole = $record -and [System.IO.File]::Exists((Join-Path (Get-ToolFolder -CatalogueTool $catalogueTool) $entryPoint))
        if (-not $check.Remote.Available) {
            $check.Status = 'Unavailable'; $check.Detail = $check.Remote.Detail
        } elseif (-not $record) {
            $check.Status = 'NotInstalled'; $check.Detail = "not installed; $($check.Remote.Build) available"
        } elseif (-not $installedAndWhole) {
            $check.Status = 'Damaged'; $check.Detail = "on record but $entryPoint is missing: reinstall"
        } elseif ($record.CatalogueFingerprint -ne (Get-CatalogueRowFingerprint -CatalogueTool $catalogueTool)) {
            $check.Status = 'CatalogueChanged'; $check.Detail = "the catalogue's entry for it changed: reinstall (installed $(Format-DisplayVersion -Version $record.Version))"
        } elseif ($record.Marker -ne $check.Remote.Marker) {
            $check.Status = 'Changed'; $check.Detail = "update available (installed $(Format-DisplayVersion -Version $record.Version))"
        } else {
            $check.Status = 'Current'; $check.Detail = "current ($(Format-DisplayVersion -Version $record.Version))"
        }
        # A tool the user downloads by hand can't be installed until the file
        # is there: the check says what to download and where.
        if (@('NotInstalled', 'Changed', 'Damaged', 'CatalogueChanged') -contains $check.Status -and $check.Remote.NeedsManualDownload) {
            $check.Status = 'AwaitingDownload'; $check.Detail = "$($check.Detail -replace '; [^;]*available$', ''): v$($check.Remote.Version) is out; $($check.Remote.Detail)"
        }
    } catch {
        $check.Status = 'Unknown'; $check.Detail = "can't check: $(Get-OneLineMessage -ErrorRecord $_)"
    }
    Write-CheckLine -Name $catalogueTool.Name -Detail $check.Detail
    $toolChecks.Add($check)
}

if (@($selectedTools | Where-Object { $_.Source -eq 'EZTools' }).Count -gt 0) {
    try {
        $notInCatalogue = @(Get-EzToolNotInCatalogue)
        if ($notInCatalogue.Count -gt 0) { Write-ConsoleLine -Text "Available from Zimmerman, not in the catalogue: $($notInCatalogue -join ', ')" -Indent 2 }
    } catch {}
}

# The prerequisites the selected tools need, from the builds that will be
# installed (or, for a tool that can't be checked, the build on record).
$capabilities = New-Object System.Collections.Generic.List[string]
foreach ($check in $toolChecks) {
    $build = ''
    if ($check.Remote -and $check.Remote.Available -and $check.Remote.Build) { $build = $check.Remote.Build } elseif ($check.Record) { $build = $check.Record.Build }
    if (-not $build -and @($check.Tool.Requires | Where-Object { $_ -like 'DotNet:*' }).Count -gt 0) { continue }
    try { foreach ($capability in @(Get-ToolCapability -CatalogueTool $check.Tool -Build $build)) { $capabilities.Add($capability) } } catch { Add-RunWarning -Message (Get-OneLineMessage -ErrorRecord $_) }
}
# Installed tools outside the selection, from their builds on record.
$otherInstalledCapabilities = New-Object System.Collections.Generic.List[string]
foreach ($catalogueTool in @($Catalogue | Where-Object { $selectedTools -notcontains $_ -and $state.Tools.ContainsKey($_.Name) })) {
    try { foreach ($capability in @(Get-ToolCapability -CatalogueTool $catalogueTool -Build $state.Tools[$catalogueTool.Name].Build)) { $otherInstalledCapabilities.Add($capability) } } catch {}
}
$neededPrerequisites = @()
try {
    $neededPrerequisites = @(Resolve-Prerequisite -Capabilities $capabilities.ToArray() -OtherInstalledCapabilities $otherInstalledCapabilities.ToArray())
} catch {
    Add-Result -Group 'Prerequisites' -Name 'resolve' -Status 'FAIL' -Detail (Get-OneLineMessage -ErrorRecord $_)
}

$prerequisiteChecks = New-Object System.Collections.Generic.List[object]
foreach ($prerequisite in $neededPrerequisites) {
    $check = [pscustomobject]@{ Prerequisite = $prerequisite; Remote = $null; Status = ''; Detail = ''; Installed = @(); Owned = @() }
    try {
        $check.Installed = @(Get-PrerequisiteInstalledVersion -Prerequisite $prerequisite)
        if ($state.Prerequisites.ContainsKey($prerequisite.Id)) { $check.Owned = @($state.Prerequisites[$prerequisite.Id].Versions.Keys) }
        $notOwned = @($check.Installed | Where-Object { $version = $_; -not ($check.Owned | Where-Object { Test-SameVersion -First $_ -Second $version }) })
        foreach ($version in $notOwned) { $prerequisitesNotOwned.Add([pscustomobject]@{ DisplayName = $prerequisite.DisplayName; Version = $version }) }
        $check.Remote = Get-PrerequisiteRemote -Prerequisite $prerequisite
        $recordedMarker = ''
        if ($state.Prerequisites.ContainsKey($prerequisite.Id)) { $recordedMarker = [string]$state.Prerequisites[$prerequisite.Id].Marker }
        # A source that names no version (Visual C++) offers "its current file".
        $offered = $check.Remote.Version
        if (-not $offered) { $offered = "the vendor's current file" }
        if (-not $check.Remote.Available) {
            $check.Status = 'Unavailable'; $check.Detail = $check.Remote.Detail
        } elseif (Test-PrerequisiteCurrent -Prerequisite $prerequisite -Remote $check.Remote -Installed $check.Installed -RecordedMarker $recordedMarker) {
            $check.Status = 'Current'; $check.Detail = "current ($(@(@($check.Remote.Version) + @($check.Installed) | Where-Object { $_ })[0]))"
        } elseif ($check.Installed.Count -eq 0) {
            $check.Status = 'NotInstalled'; $check.Detail = "not installed; $offered available"
        } else {
            $check.Status = 'Changed'; $check.Detail = "to check against $offered (installed $($check.Installed -join ', '))"
            if ($check.Remote.Version) { $check.Detail = "update available: $offered (installed $($check.Installed -join ', '))" }
        }
        if ($check.Remote.Available -and $check.Remote.EndOfLife) {
            $endOfLife = [DateTime]::MinValue
            if ([DateTime]::TryParse($check.Remote.EndOfLife, [ref]$endOfLife) -and $endOfLife.Date -le $runStartUtc.Date) {
                Add-RunWarning -Message "$($prerequisite.DisplayName) reached the end of Microsoft support on $($check.Remote.EndOfLife); a tool still needs it."
            }
        }
        # A version the detail already names is marked once; others are listed.
        $notOwnedUnnamed = @($notOwned | Where-Object { $check.Detail.IndexOf($_, [System.StringComparison]::OrdinalIgnoreCase) -lt 0 })
        if ($notOwnedUnnamed.Count -gt 0) {
            $check.Detail += "; also present, not installed by this script (never removed): $($notOwnedUnnamed -join ', ')"
        } elseif ($notOwned.Count -gt 0) {
            $check.Detail += '; not installed by this script (never removed)'
        }
    } catch {
        $check.Status = 'Unknown'; $check.Detail = "can't check: $(Get-OneLineMessage -ErrorRecord $_)"
    }
    Write-CheckLine -Name $prerequisite.DisplayName -Detail $check.Detail
    $prerequisiteChecks.Add($check)
}
# The inventory lists every prerequisite version something else installed,
# whatever the run's selection: the prerequisites of installed tools outside
# it are read here too (on this machine only, nothing downloaded), so a
# selective run doesn't write an inventory without them.
$checkedPrerequisiteIds = @($prerequisiteChecks | ForEach-Object { $_.Prerequisite.Id })
$unselectedPrerequisites = @()
try { $unselectedPrerequisites = @(Resolve-Prerequisite -Capabilities $otherInstalledCapabilities.ToArray()) } catch { Add-RunWarning -Message "The inventory may miss prerequisites of tools outside the selection: $(Get-OneLineMessage -ErrorRecord $_)" }
foreach ($prerequisite in @($unselectedPrerequisites | Where-Object { $checkedPrerequisiteIds -notcontains $_.Id })) {
    try {
        $owned = @()
        if ($state.Prerequisites.ContainsKey($prerequisite.Id)) { $owned = @($state.Prerequisites[$prerequisite.Id].Versions.Keys) }
        foreach ($version in @(Get-PrerequisiteInstalledVersion -Prerequisite $prerequisite)) {
            if (-not ($owned | Where-Object { Test-SameVersion -First $_ -Second $version })) { $prerequisitesNotOwned.Add([pscustomobject]@{ DisplayName = $prerequisite.DisplayName; Version = $version }) }
        }
    } catch {
        Add-RunWarning -Message "$($prerequisite.DisplayName): the installed versions couldn't be read for the inventory ($(Get-OneLineMessage -ErrorRecord $_))."
    }
}

$ancillaryChecks = New-Object System.Collections.Generic.List[object]
foreach ($ancillaryRow in @($AncillaryContent | Where-Object { $name = $_.Tool; $selectedTools | Where-Object { $_.Name -eq $name } })) {
    $toolWillChange = @($toolChecks | Where-Object { $_.Tool.Name -eq $ancillaryRow.Tool -and @('NotInstalled', 'Changed', 'Damaged', 'CatalogueChanged') -contains $_.Status }).Count -gt 0
    $check = [pscustomobject]@{ Row = $ancillaryRow; Remote = $null; Status = ''; Detail = ''; ToolWillChange = $toolWillChange }
    try {
        $check.Remote = Get-AncillaryRemote -AncillaryRow $ancillaryRow
        $record = $null
        if ($state.Ancillary.ContainsKey($ancillaryRow.Tool)) { $record = $state.Ancillary[$ancillaryRow.Tool] }
        # A record is current only while its content is there: the tool on
        # record and its content folder on disk.
        $catalogueTool = @($Catalogue | Where-Object { $_.Name -eq $ancillaryRow.Tool }) | Select-Object -First 1
        $contentPresent = $state.Tools.ContainsKey($ancillaryRow.Tool) -and [System.IO.Directory]::Exists((Join-Path (Get-ToolFolder -CatalogueTool $catalogueTool) $ancillaryRow.Folder))
        if (-not $check.Remote.Available) { $check.Status = 'Unavailable'; $check.Detail = $check.Remote.Detail }
        elseif (-not $state.Tools.ContainsKey($ancillaryRow.Tool)) { $check.Status = 'NotInstalled'; $check.Detail = "not installed: $($ancillaryRow.Tool) isn't; commit $($check.Remote.Marker.Substring(0, 12)) available" }
        elseif (-not $contentPresent) { $check.Status = 'NotInstalled'; $check.Detail = "not installed: no $($ancillaryRow.Folder) folder; commit $($check.Remote.Marker.Substring(0, 12)) available" }
        elseif (-not $record) { $check.Status = 'NotInstalled'; $check.Detail = "not synced yet; commit $($check.Remote.Marker.Substring(0, 12))" }
        elseif ($record.Commit -ne $check.Remote.Marker) { $check.Status = 'Changed'; $check.Detail = "changed upstream: commit $($check.Remote.Marker.Substring(0, 12)) of $($check.Remote.CommitUtc)" }
        else { $check.Status = 'Current'; $check.Detail = "current (commit $($record.Commit.Substring(0, 12)))" }
    } catch {
        $check.Status = 'Unknown'; $check.Detail = "can't check: $(Get-OneLineMessage -ErrorRecord $_)"
    }
    Write-CheckLine -Name $ancillaryRow.Description -Detail $check.Detail
    $ancillaryChecks.Add($check)
}

# --- The plan ---
# Every action an update takes, in the order it takes them. A dry run lists
# them and stops here.
$removableTools = @()
$removablePrerequisiteVersions = New-Object System.Collections.Generic.List[object]
$unneededPrerequisitesKept = New-Object System.Collections.Generic.List[object]
if (-not $selectionGiven) {
    $removableTools = @($state.Tools.Keys | Where-Object { $name = $_; -not ($Catalogue | Where-Object { $_.Name -eq $name }) } | Sort-Object)
    foreach ($id in @($state.Prerequisites.Keys)) {
        $neededCheck = @($prerequisiteChecks | Where-Object { $_.Prerequisite.Id -eq $id }) | Select-Object -First 1
        # Only .NET lines are ever removed; the others are updated in place
        # and never removed (their RemovalNote says why). One no tool needs
        # any more is listed in the plan as kept, every run, not as a
        # warning: keeping it is the rule, not a problem.
        if ($id -notlike 'DotNet:*') {
            $otherRow = @($OtherPrerequisites | Where-Object { $_.Capability -eq $id }) | Select-Object -First 1
            if (-not $neededCheck -and $otherRow -and $state.Prerequisites[$id].Versions.Count -gt 0) {
                $unneededPrerequisitesKept.Add($otherRow)
            }
            continue
        }
        foreach ($version in @($state.Prerequisites[$id].Versions.Keys)) {
            $keep = $neededCheck -and $neededCheck.Remote -and (Test-SameVersion -First $version -Second $neededCheck.Remote.Version)
            $neededButUnchecked = $neededCheck -and (-not $neededCheck.Remote -or -not $neededCheck.Remote.Available)
            if ($keep -or $neededButUnchecked) { continue }
            $latestVersion = ''
            if ($neededCheck) { $latestVersion = $neededCheck.Remote.Version }
            $removablePrerequisiteVersions.Add([pscustomobject]@{ Id = $id; Version = $version; DisplayName = $state.Prerequisites[$id].DisplayName; Needed = [bool]$neededCheck; LatestVersion = $latestVersion })
        }
    }
}

$plan = New-Object System.Collections.Generic.List[string]
foreach ($check in @($prerequisiteChecks | Where-Object { @('NotInstalled', 'Changed') -contains $_.Status })) {
    # The Visual C++ Redistributable's offer has no version until it is
    # downloaded: its file is named instead, and with a version installed
    # the download is only compared with it (installed when newer).
    if (-not $check.Remote.Version -and $check.Installed.Count -gt 0) {
        $plan.Add((Format-PlanLine -Action 'Check' -Text "$($check.Prerequisite.DisplayName) $($check.Installed -join ', ') against the vendor's current file ($($check.Remote.FileName)); installed if newer"))
        continue
    }
    $offeredText = $check.Remote.Version
    if (-not $offeredText) { $offeredText = "(the vendor's current file)" }
    $plan.Add((Format-PlanLine -Action 'Install' -Text "$($check.Prerequisite.DisplayName) $offeredText ($($check.Remote.FileName))"))
}
foreach ($check in @($toolChecks | Where-Object { @('NotInstalled', 'Changed', 'Damaged', 'CatalogueChanged') -contains $_.Status })) {
    $action = 'Install'
    if ($check.Status -eq 'Changed') { $action = 'Update' }
    if ($check.Status -eq 'Damaged') { $action = 'Repair' }
    if ($check.Status -eq 'CatalogueChanged') { $action = 'Reinstall' }
    $plan.Add((Format-PlanLine -Action $action -Text "$($check.Tool.Family)\$($check.Tool.Name) ($($check.Remote.Build), $($check.Remote.FileName))"))
}
foreach ($check in @($ancillaryChecks | Where-Object { @('NotInstalled', 'Changed') -contains $_.Status -or $_.ToolWillChange })) {
    $plan.Add((Format-PlanLine -Action 'Sync' -Text "$($check.Row.Description) ($($check.Row.Tool) --sync)"))
}
foreach ($check in @($toolChecks | Where-Object { $_.Status -eq 'AwaitingDownload' })) { $plan.Add((Format-PlanLine -Action 'Download' -Text "by hand: $($check.Remote.FileName) from $($check.Remote.Url) into $(Format-Unbreakable -Text (Get-DownloadsFolder)); this run can't install $($check.Tool.Name)")) }
foreach ($name in $removableTools) { $plan.Add((Format-PlanLine -Action 'Remove' -Text "$name (no longer in the catalogue)")) }
foreach ($item in $removablePrerequisiteVersions) {
    $reason = 'no tool needs it'
    if ($item.Needed) { $reason = 'superseded by the latest version' }
    $plan.Add((Format-PlanLine -Action 'Remove' -Text "$($item.DisplayName) $($item.Version) ($reason)"))
}
foreach ($row in $unneededPrerequisitesKept) { $plan.Add((Format-PlanLine -Action 'Keep' -Text "$($row.DisplayName) (no tool needs it; never removed by this script: $($row.RemovalNote))")) }
$plan.Add((Format-PlanLine -Action 'Check' -Text 'machine PATH, Desktop and Start Menu shortcuts, Sysinternals EULA'))

Write-SectionHeading -Title 'Plan'
foreach ($line in $plan) { Write-ConsoleLine -Text $line -Indent 2 -ContinuationIndent ($PlanActionWidth + 2) }

if ($dryRun) {
    foreach ($check in $prerequisiteChecks) { Add-Result -Group 'Prerequisites' -Name $check.Prerequisite.DisplayName -Status (Get-CheckStatus -CheckStatus $check.Status) -Detail $check.Detail }
    foreach ($check in $toolChecks) { Add-Result -Group $check.Tool.Family -Name $check.Tool.Name -Status (Get-CheckStatus -CheckStatus $check.Status) -Detail $check.Detail }
    foreach ($check in $ancillaryChecks) { Add-Result -Group 'Ancillary content' -Name $check.Row.Description -Status (Get-CheckStatus -CheckStatus $check.Status) -Detail $check.Detail }
    foreach ($item in $removablePrerequisiteVersions) { Add-Result -Group 'Clean-up' -Name "$($item.DisplayName) $($item.Version)" -Status 'WARN' -Detail 'would be removed' }
    foreach ($name in $removableTools) { Add-Result -Group 'Clean-up' -Name $name -Status 'WARN' -Detail 'would be removed' }
    $coverage = 'dry run: is every selected tool current? Nothing was changed.'
    $overall = Write-ResultBlock -Coverage $coverage
    Write-ConsoleLine -Text "Log: $(Format-Unbreakable -Text $logPath)"
    switch ($overall) { 'PASS' { exit 0 } 'WARN' { exit 1 } default { exit 2 } }
}

# --- Update: prerequisites first (tools and --sync need them) ---
try {
    $null = [System.IO.Directory]::CreateDirectory($installersFolder)
    $null = [System.IO.Directory]::CreateDirectory($stagingFolder)
    $null = [System.IO.Directory]::CreateDirectory($installRoot)
} catch {
    Stop-Run -Reason "the working folders can't be created: $(Get-OneLineMessage -ErrorRecord $_)"
}

# Leftovers of an interrupted run (a tool's .new or .old folder) are the
# script's own: removed before anything else.
foreach ($familyRow in $Families) {
    $familyFolder = Join-Path $installRoot $familyRow.Name
    if (-not [System.IO.Directory]::Exists($familyFolder)) { continue }
    foreach ($leftover in @([System.IO.Directory]::GetDirectories($familyFolder) | Where-Object { $_ -match '\.(new|old)$' })) {
        try { Remove-OwnedFolder -Path $leftover -Root $installRoot; Write-ConsoleLine -Text "Removed a leftover of an earlier run: $(Format-Unbreakable -Text $leftover)" -Indent 2 }
        catch { Add-RunWarning -Message "A leftover of an earlier run could not be removed: $(Format-Unbreakable -Text $leftover) ($(Get-OneLineMessage -ErrorRecord $_))" }
    }
}

Write-SectionHeading -Title 'Prerequisites'
foreach ($check in $prerequisiteChecks) {
    $name = $check.Prerequisite.DisplayName
    switch ($check.Status) {
        'Current'     { Add-Result -Group 'Prerequisites' -Name $name -Status 'PASS' -Detail $check.Detail }
        'Unknown'     { Add-Result -Group 'Prerequisites' -Name $name -Status 'WARN' -Detail "$($check.Detail) (see Warnings)"; Add-RunWarning -Message "${name}: $($check.Detail)" }
        'Unavailable' { Add-Result -Group 'Prerequisites' -Name $name -Status 'FAIL' -Detail "$($check.Detail) (see Failures)"; Add-RunFailure -Message "${name}: $($check.Detail)" }
        default {
            # Without a version to offer (Visual C++), the download is first
            # compared with what is installed: "Installing" comes from the
            # installer step itself.
            if ($check.Remote.Version) { Write-ConsoleLine -Text "Installing $name $($check.Remote.Version)" -Indent 2 } else { Write-ConsoleLine -Text "Checking $name" -Indent 2 }
            try {
                $detail = Install-PrerequisiteVersion -Prerequisite $check.Prerequisite -Remote $check.Remote -State $state
                Save-State -State $state -Path $statePath
                $status = 'PASS'
                if ($detail -like '*restart needed*') { $status = 'WARN' }
                Add-Result -Group 'Prerequisites' -Name $name -Status $status -Detail $detail
                Write-ConsoleLine -Text $detail -Indent 4
            } catch {
                $message = Get-OneLineMessage -ErrorRecord $_
                Add-Result -Group 'Prerequisites' -Name $name -Status 'FAIL' -Detail "not installed (see Failures)"
                Add-RunFailure -Message "${name}: $message"
                Write-ConsoleLine -Text "FAILED: $message" -Indent 4
            }
        }
    }
}
if ($prerequisiteChecks.Count -eq 0 -and $neededPrerequisites.Count -eq 0) {
    Write-ConsoleLine -Text 'None needed by the selected tools.' -Indent 2
} else {
    Write-NothingToDoLine -Statuses @($prerequisiteChecks | ForEach-Object { $_.Status }) -NoActionStatuses @('Current', 'Unknown', 'Unavailable')
}

# --- Update: tools ---
Write-SectionHeading -Title 'Tools'
Write-NothingToDoLine -Statuses @($toolChecks | ForEach-Object { $_.Status }) -NoActionStatuses @('Current', 'Unknown', 'Unavailable', 'AwaitingDownload')
foreach ($check in $toolChecks) {
    $catalogueTool = $check.Tool
    $group = $catalogueTool.Family
    switch ($check.Status) {
        'Current'     { Add-Result -Group $group -Name $catalogueTool.Name -Status 'PASS' -Detail $check.Detail }
        'Unknown'     {
            $detail = $check.Detail
            if ($check.Record) { $detail += "; installed $($check.Record.Version) kept" }
            Add-Result -Group $group -Name $catalogueTool.Name -Status 'WARN' -Detail "$detail (see Warnings)"
            Add-RunWarning -Message "$($catalogueTool.Name): $detail"
        }
        'Unavailable' { Add-Result -Group $group -Name $catalogueTool.Name -Status 'FAIL' -Detail "$($check.Detail) (see Failures)"; Add-RunFailure -Message "$($catalogueTool.Name): $($check.Detail)" }
        'AwaitingDownload' { Add-Result -Group $group -Name $catalogueTool.Name -Status 'WARN' -Detail "to download by hand (see Warnings)"; Add-RunWarning -Message "$($catalogueTool.Name): $($check.Detail)" }
        default {
            Write-ConsoleLine -Text "$($catalogueTool.Family)\$($catalogueTool.Name): $($check.Detail)" -Indent 2
            try {
                $reinstall = @('Damaged', 'CatalogueChanged') -contains $check.Status
                $newRecord = Install-Tool -CatalogueTool $catalogueTool -Remote $check.Remote -State $state -Reinstall:$reinstall
                if ($null -eq $newRecord) {
                    $state.Tools[$catalogueTool.Name].Marker = $check.Remote.Marker
                    $detail = "current ($(Format-DisplayVersion -Version $check.Record.Version)); the server's marker changed, the content did not"
                } else {
                    if ($check.Record -and $check.Record.Shortcuts) { $newRecord.Shortcuts = @($check.Record.Shortcuts) }
                    $state.Tools[$catalogueTool.Name] = $newRecord
                    $detail = "$(Format-DisplayVersion -Version $newRecord.Version) installed ($($newRecord.Build)); signer $($newRecord.Signer)"
                }
                Save-State -State $state -Path $statePath
                Add-Result -Group $group -Name $catalogueTool.Name -Status 'PASS' -Detail $detail
                Write-ConsoleLine -Text $detail -Indent 4
            } catch {
                $message = Get-OneLineMessage -ErrorRecord $_
                $status = 'FAIL'
                if ($_.Exception -is [System.InvalidOperationException] -and $message -like 'in use*') { $status = 'WARN'; Add-RunWarning -Message "$($catalogueTool.Name): $message" } else { Add-RunFailure -Message "$($catalogueTool.Name): $message" }
                $pointer = '(see Failures)'
                if ($status -eq 'WARN') { $pointer = '(see Warnings)' }
                Add-Result -Group $group -Name $catalogueTool.Name -Status $status -Detail "not updated $pointer"
                Write-ConsoleLine -Text "NOT DONE: $message" -Indent 4
            }
        }
    }
}

# The Sysinternals EULA, for tools already installed too (the account may be
# new to them).
# The keys set are recorded with the tool, so its removal can name them.
foreach ($catalogueTool in @($selectedTools | Where-Object { $_.EulaKeys -and $state.Tools.ContainsKey($_.Name) })) {
    try {
        Set-SysinternalsEula -CatalogueTool $catalogueTool
        $state.Tools[$catalogueTool.Name].EulaKeys = @($catalogueTool.EulaKeys)
        Save-State -State $state -Path $statePath
    } catch { Add-RunWarning -Message "$($catalogueTool.Name): EulaAccepted could not be set ($(Get-OneLineMessage -ErrorRecord $_))" }
}

# --- Update: ancillary content ---
# A selective run without a tool that has ancillary content shows no section.
if ($ancillaryChecks.Count -gt 0) {
    Write-SectionHeading -Title 'Ancillary content'
    $ancillaryStatuses = @($ancillaryChecks | ForEach-Object {
            if (-not $state.Tools.ContainsKey($_.Row.Tool)) { 'ToolNotInstalled' } elseif ($_.Status -eq 'Current' -and $_.ToolWillChange) { 'ToolChanged' } else { $_.Status } })
    Write-NothingToDoLine -Statuses $ancillaryStatuses -NoActionStatuses @('Current', 'Unknown', 'Unavailable', 'ToolNotInstalled') -NothingText 'Nothing to sync.'
}
foreach ($check in $ancillaryChecks) {
    $toolInstalled = $state.Tools.ContainsKey($check.Row.Tool)
    $name = $check.Row.Description
    if (-not $toolInstalled) {
        Add-Result -Group 'Ancillary content' -Name $name -Status 'FAIL' -Detail "not synced: $($check.Row.Tool) is not installed (see Failures)"
        Add-RunFailure -Message "${name}: not synced, $($check.Row.Tool) is not installed"
        continue
    }
    if (@('Unknown', 'Unavailable') -contains $check.Status) {
        Add-Result -Group 'Ancillary content' -Name $name -Status 'WARN' -Detail "$($check.Detail) (see Warnings)"
        Add-RunWarning -Message "${name}: $($check.Detail)"
        continue
    }
    if ($check.Status -eq 'Current' -and -not $check.ToolWillChange) {
        Add-Result -Group 'Ancillary content' -Name $name -Status 'PASS' -Detail $check.Detail
        continue
    }
    Write-ConsoleLine -Text "Syncing $name" -Indent 2
    try {
        $detail = Sync-AncillaryContent -AncillaryRow $check.Row -Remote $check.Remote -State $state
        Save-State -State $state -Path $statePath
        Add-Result -Group 'Ancillary content' -Name $name -Status 'PASS' -Detail $detail
        Write-ConsoleLine -Text $detail -Indent 4
    } catch {
        $message = Get-OneLineMessage -ErrorRecord $_
        Add-Result -Group 'Ancillary content' -Name $name -Status 'FAIL' -Detail 'not synced (see Failures)'
        Add-RunFailure -Message "${name}: $message"
        Write-ConsoleLine -Text "FAILED: $message" -Indent 4
    }
}

# --- Update: clean-up (a full run only) ---
if (-not $selectionGiven) {
    Write-SectionHeading -Title 'Clean-up'
    if ($removableTools.Count -eq 0 -and $removablePrerequisiteVersions.Count -eq 0) { Write-ConsoleLine -Text 'Nothing to remove.' -Indent 2 }
    foreach ($name in $removableTools) {
        try {
            $detail = Remove-Tool -Name $name -State $state
            Save-State -State $state -Path $statePath
            Add-Result -Group 'Clean-up' -Name $name -Status 'PASS' -Detail $detail
            Write-ConsoleLine -Text $detail -Indent 2
        } catch {
            $message = Get-OneLineMessage -ErrorRecord $_
            if ($_.Exception -is [System.InvalidOperationException] -and $message -like 'in use*') {
                Add-Result -Group 'Clean-up' -Name $name -Status 'WARN' -Detail "${name}: in use, not removed (see Warnings)"
                Add-RunWarning -Message "removing ${name}: $message"
                Write-ConsoleLine -Text "${name}: in use, not removed (see Warnings)" -Indent 2
            } else {
                Add-Result -Group 'Clean-up' -Name $name -Status 'FAIL' -Detail "${name}: not removed (see Failures)"
                Add-RunFailure -Message "removing ${name}: $message"
                Write-ConsoleLine -Text "${name}: not removed (see Failures)" -Indent 2
            }
        }
    }
    foreach ($item in $removablePrerequisiteVersions) {
        $label = "$($item.DisplayName) $($item.Version)"
        try {
            $prerequisite = Get-PrerequisiteFromId -Id $item.Id
            if ($item.Needed) {
                $latestNow = @(Get-PrerequisiteInstalledVersion -Prerequisite $prerequisite | Where-Object { Test-SameVersion -First $_ -Second $item.LatestVersion })
                if ($latestNow.Count -eq 0) {
                    Add-Result -Group 'Clean-up' -Name $label -Status 'WARN' -Detail "kept: $($item.LatestVersion) is not installed (see Warnings)"
                    Add-RunWarning -Message "$label kept: the latest version of its line, $($item.LatestVersion), is not installed."
                    continue
                }
            }
            $detail = Uninstall-PrerequisiteVersion -Prerequisite $prerequisite -Version $item.Version -State $state
            if ($state.Prerequisites[$item.Id].Versions.Count -eq 0) { $state.Prerequisites.Remove($item.Id) }
            Save-State -State $state -Path $statePath
            Add-Result -Group 'Clean-up' -Name $label -Status 'PASS' -Detail $detail
            Write-ConsoleLine -Text $detail -Indent 2
        } catch {
            Add-Result -Group 'Clean-up' -Name $label -Status 'FAIL' -Detail 'not removed (see Failures)'
            Add-RunFailure -Message "removing ${label}: $(Get-OneLineMessage -ErrorRecord $_)"
        }
    }
}

# --- Update: PATH and shortcuts ---
Write-SectionHeading -Title 'PATH and shortcuts'
try {
    $pathOutcome = Update-MachinePath -State $state -AllowRemoval (-not $selectionGiven)
    foreach ($line in $pathOutcome.Lines) { Write-ConsoleLine -Text $line -Indent 2 }
    $status = 'PASS'
    if ($pathOutcome.Refused.Count -gt 0) { $status = 'FAIL' }
    Add-Result -Group 'PATH and shortcuts' -Name 'machine PATH' -Status $status -Detail (($pathOutcome.Lines -join '; ') + $(if ($status -eq 'FAIL') { ' (see Failures)' } else { '' }))
} catch {
    Add-Result -Group 'PATH and shortcuts' -Name 'machine PATH' -Status 'FAIL' -Detail 'not updated (see Failures)'
    Add-RunFailure -Message "machine PATH: $(Get-OneLineMessage -ErrorRecord $_)"
}
try {
    $shortcutOutcome = Update-ToolShortcut -State $state -AllowRemoval (-not $selectionGiven)
    Write-ConsoleLine -Text "shortcuts: $($shortcutOutcome.Detail)" -Indent 2
    foreach ($failure in $shortcutOutcome.Failures) { Add-RunFailure -Message "shortcut: $failure" }
    if ($shortcutOutcome.Failures.Count -gt 0) {
        Add-Result -Group 'PATH and shortcuts' -Name 'shortcuts' -Status 'FAIL' -Detail "$($shortcutOutcome.Detail) (see Failures)"
    } else {
        Add-Result -Group 'PATH and shortcuts' -Name 'shortcuts' -Status 'PASS' -Detail $shortcutOutcome.Detail
    }
} catch {
    Add-Result -Group 'PATH and shortcuts' -Name 'shortcuts' -Status 'FAIL' -Detail 'not all made (see Failures)'
    Add-RunFailure -Message "shortcuts: $(Get-OneLineMessage -ErrorRecord $_)"
}

# --- Records ---
Write-SectionHeading -Title 'Records'
try {
    Save-State -State $state -Path $statePath
    $inventoryLines = Get-InventoryLine -State $state
    $filesLines = Get-FileRecordLine -State $state
    foreach ($folder in @($recordsRoot, $runFolder)) {
        Write-RecordFile -Path (Join-Path $folder 'inventory.csv') -Lines $inventoryLines
        Write-RecordFile -Path (Join-Path $folder 'files.csv') -Lines $filesLines
    }
    $detail = "state.json, inventory.csv ($($inventoryLines.Count - 1) rows) and files.csv ($($filesLines.Count - 1) rows) written"
    Write-ConsoleLine -Text $detail -Indent 2
    Write-LabelValue -Label 'Inventory' -Value (Format-Unbreakable -Text (Join-Path $recordsRoot 'inventory.csv'))
    Write-LabelValue -Label 'Files' -Value (Format-Unbreakable -Text (Join-Path $recordsRoot 'files.csv'))
    Add-Result -Group 'Records' -Name 'records' -Status 'PASS' -Detail $detail
} catch {
    Add-Result -Group 'Records' -Name 'records' -Status 'FAIL' -Detail 'not written (see Failures)'
    Add-RunFailure -Message "records: $(Get-OneLineMessage -ErrorRecord $_)"
}
try { Remove-OwnedFolder -Path $stagingFolder -Root $recordsRoot } catch { Add-RunWarning -Message "The staging folder could not be removed: $(Format-Unbreakable -Text $stagingFolder)" }

$coverage = 'every tool in the catalogue, its prerequisites and ancillary content'
if ($selectionGiven) { $coverage = "the selected tools only ($selectionText)" }
$overall = Write-ResultBlock -Coverage $coverage
Write-ConsoleLine -Text "Log: $(Format-Unbreakable -Text $logPath)"
switch ($overall) { 'PASS' { exit 0 } 'WARN' { exit 1 } default { exit 2 } }
