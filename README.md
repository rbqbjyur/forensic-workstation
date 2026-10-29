# forensic-workstation

My own set-up of the common Windows forensic tools, shared as it is: one
Windows PowerShell script that installs them on a fresh DFIR workstation and
keeps them current, downloading only what has changed since the last run and
removing what is no longer needed.

It isn't a forensic suite. It keeps the many small standalone tools up to
date, so the workstation is ready before an investigation: Eric Zimmerman's
tools (EZ Tools) with their EvtxECmd maps, RECmd batch files and SQLECmd
maps, the NirSoft utilities that read collected artefacts, Sysinternals tools, SRUM-DUMP,
Velociraptor, DB Browser for SQLite and Arsenal Image Mounter with its
driver, with the .NET runtimes and Visual C++ Redistributable they need;
FTK Imager and DCode, which have installers of their own, are watched for
new versions where installed. Every download is hashed, checked against the
vendor's published hash and signer, and recorded, so the tool versions
behind an analysis can be cited later.

The selection is mine. Use it as it is, or adapt it: adding or
dropping a tool is a row in a table, and another vendor's set needs only a
small function that finds its downloads (see [Adapting it](#adapting-it)).

<img src="docs/images/demo.webp" alt="Console, 80 columns: .\Update-ForensicWorkstation.ps1 typed at a Windows PowerShell prompt; the header (version 1.0.0, host, OS, elevated account, the script's SHA-256, the tools and records folders, GitHub without a token, the log); Script, this script current and the installed copy this file; Checking sources, each of the 62 tools, the driver, the Visual C++ Redistributable, the .NET Desktop Runtime 10 and the three ancillary sets current except EvtxECmd and USBDeview (update available) and the EvtxECmd maps (changed upstream), and the watched tools FTK Imager and DCode not installed; the plan (update Event Logs\EvtxECmd, update Connected Devices\USBDeview, sync the EvtxECmd maps); both downloads with their SHA-256 and signer; the maps synced (475 files); nothing to remove; PATH and shortcuts unchanged; the records written; RESULT: PASS with the script and every category PASS, and INFO, the scheduled task disabled">

An update with two tools and the EvtxECmd maps due, typed at a Windows
PowerShell prompt (in Windows Sandbox), in real time; the last frame is held
for four seconds.

## Table of contents

- [What it does](#what-it-does)
- [Install](#install)
- [Usage](#usage)
- [The catalogue](#the-catalogue)
- [Adapting it](#adapting-it)
- [Where things go](#where-things-go)
- [Compatibility](#compatibility)
- [What the output shows](#what-the-output-shows)
- [What it does not do](#what-it-does-not-do)
- [Contributing](#contributing)
- [Licence](#licence)

## What it does

- Installs every tool in its catalogue, or updates those whose source has
  changed: each source's change marker (HTTP headers, a release tag, a
  version) is compared with the one recorded at install, so an unchanged tool
  is never downloaded again.
- Picks each tool's newest build: x64 over x86, the newest .NET line the
  vendor offers.
- Installs the runtimes those builds need, and only those: each .NET runtime
  line a tool targets (the Desktop Runtime only where a GUI tool needs it,
  since it covers the plain runtime of its line). Each line is kept at its
  latest patch; .NET 9 and .NET 10 are separate lines.
- Checks EvtxECmd's maps, RECmd's batch files and SQLECmd's maps on every run
  by the last commit to their folder upstream, and runs the tool's own
  `--sync` when it has changed. Files retired upstream are removed (`--sync`
  alone keeps them). Outside the content folder `--sync` should change
  nothing, and that part of the tool's folder is compared after every
  `--sync`, failed or not, graded as `-Verify` grades it: a tool file on
  record changed or removed is a FAIL, a file not on record there
  afterwards a WARN. The tool's files stay on record as installed, so
  `-Verify` reports the same.
- Verifies every download: SHA-256, the vendor's published hash where there
  is one (.NET, Arsenal Image Mounter, the Visual C++ Redistributable, AIM's
  driver package), the Authenticode signer of every exe it installs, AIM's
  driver against its Microsoft-signed catalogue, and a
  re-read of every extracted file before it is used. An update is swapped in
  only when all of that passes; a tool running from its folder is left as it
  is.
- Lays the workstation out by what each tool examines: a folder per
  category (System, Accounts, File Activity, Execution, Commands,
  Persistence, Lateral Movement, Connected Devices, Registry, Event Logs,
  Browsers, Acquisition, Other; a category with no tool has none) under
  Program Files, on the
  Desktop and in the Start Menu alike. Command-line tools go on the machine
  PATH, so they run by name from any terminal; GUI tools get shortcuts in
  their category's folder (Timeline Explorer directly, used with
  everything).
- Removes what it installed and no longer needs: tools dropped from the
  catalogue, superseded prerequisite versions, runtime lines no tool needs.
  It never removes anything it didn't install, nor a runtime line an
  installed tool still runs on (its update failed or was skipped).
- Writes a log per run, and an inventory and per-file SHA-256 record of what
  is installed.
- Keeps a copy of itself under Program Files, with a Desktop and Start Menu
  shortcut, *Update forensic workstation*, that asks for administrator
  rights and runs that copy; a run started without them asks the same way
  (UAC) and finishes in its own window.
- Keeps itself current: an update run installs this repository's latest
  release, checked against GitHub's SHA-256 digest of the file and the
  SHA-256 in the release notes, and hands the run over to it before any
  other source is checked.
- Opens Arsenal Image Mounter's downloads page in the default browser when
  its zip is due and missing.
- Watches tools that have installers of their own (FTK Imager, DCode): where
  one is installed and a newer version is out, it warns and opens the
  vendor's page; it never installs them.
- Optionally keeps the workstation current by itself: a daily scheduled
  update, elevated without a prompt, silent unless something fails or a
  zip has to be downloaded by hand.

## Install

```powershell
# Download Update-ForensicWorkstation-<version>.ps1 from the latest release, then:
Get-FileHash .\Update-ForensicWorkstation-*.ps1 -Algorithm SHA256
# compare with the SHA-256 in the release notes
Unblock-File .\Update-ForensicWorkstation-*.ps1
# Run it once: right-click, "Run with PowerShell", or at a prompt. Windows
# asks for administrator rights; the tools are installed; a copy of the
# script goes to C:\Program Files\ForensicTools with the shortcut "Update
# forensic workstation" on the Desktop and in the Start Menu. From then on,
# run the shortcut.
```

### Requirements

- 64-bit Windows (amd64), Windows PowerShell 5.1, no modules. Tested on
  Windows 11 24H2; not tested on Windows 10.
- An elevated prompt for an update, as the account whose desktop it is;
  `-CheckOnly` and `-Verify` run without. One update runs at a time on a
  machine.
- Internet access to the vendors' download sites, GitHub (the maps, and
  this script's releases) and Microsoft's .NET release metadata, through
  the account's system proxy settings. GitHub limits calls from an address
  without an account; when the limit is reached, the run says so until it
  resets:

  | | Calls |
  |---|---|
  | GitHub allows, per address, an hour | 60 |
  | With a token (below), an hour | 5,000 |
  | A full run makes | about 9 |
  | So full runs in an hour from one address, without a token | about 6 |

## Usage

```powershell
# Install or update everything (elevated):
.\Update-ForensicWorkstation.ps1

# Is the workstation current? Lists what an update would do, changes nothing:
.\Update-ForensicWorkstation.ps1 -CheckOnly

# Only some families, categories or tools (nothing is removed in a selective run):
.\Update-ForensicWorkstation.ps1 -Family Zimmerman
.\Update-ForensicWorkstation.ps1 -Category Execution, 'Event Logs'
.\Update-ForensicWorkstation.ps1 -Tool EvtxECmd, ProcessExplorer

# Re-hash every installed file against the record:
.\Update-ForensicWorkstation.ps1 -Verify

# Update every day by itself (elevated; -ScheduledUpdate Disable removes it):
.\Update-ForensicWorkstation.ps1 -ScheduledUpdate Enable
```

| Parameter | Effect |
|---|---|
| `-CheckOnly` | The dry run: every source is checked and every action an update would take is listed; nothing changes. `-WhatIf` does the same. |
| `-Verify` | Re-hashes the installed files against `files.csv` and lists files missing, changed or not on record; a tool on record in `state.json` with no files in `files.csv` is a FAIL. No network access. |
| `-Family` | Limits the run to these families (where the tools come from): `Zimmerman`, `NirSoft`, `Sysinternals`, `Arsenal`, `SRUM-DUMP`, `Velocidex`, `sqlitebrowser`. |
| `-Category` | Limits the run to these categories (what the tools examine; the table below). A name may be given without its spaces: `-Category FileActivity`. |
| `-Tool` | Limits the run to these tools (names as in the catalogue). |
| `-Pause` | Keeps the window open at the end, for a run started from a shortcut (the script's own shortcut passes it; a run started from Explorer pauses anyway). |
| `-NoSelfUpdate` | Runs this copy as it is, without checking for a newer release. The run handed over after a self-update uses it. |
| `-ScheduledUpdate` | `Enable` sets up the scheduled update (below), `Disable` removes it; nothing else is done in that run. |

Set by the script itself, not for typing at a prompt:

| Parameter | Effect |
|---|---|
| `-ElevatedRelaunch` | On the run it starts elevated: such a run that still has no administrator rights stops instead of relaunching again. |
| `-Scheduled` | The scheduled update's own run, as its task starts it: a full update, unattended. |

A GitHub token, optional: set the environment variable
`FORENSIC_WORKSTATION_GITHUB_TOKEN` (for your account, so the elevated run
and the scheduled one see it) to a fine-grained token with read-only
access to public repositories and no permissions. The script sends it only
to GitHub's API (`api.github.com`), never with a download, and writes it
nowhere; the header says whether the run has one. A token GitHub refuses
makes every GitHub check a WARN saying so, never a quiet fall-back.

Exit codes: 0 PASS, 1 WARN, 2 FAIL, 3 stopped before any work (e.g.
another update run in progress, an update elevated as another account, or
administrator rights declined). After a self-update the run ends with the
new release's exit code, or 2 when the new release could not be started.

### The scheduled update

Off unless you set it up. `-ScheduledUpdate Enable`, run after an update
has installed the script's copy under Program Files, registers a task,
`\ForensicWorkstation\Update forensic workstation`, for your account:

- once a day at 08:00 local time; a run missed while the machine was off
  starts as soon as it is next on, once however many days were missed;
- elevated without a UAC prompt ("Run with highest privileges"), and only
  while you are logged on, so it updates your shortcuts and settings as an
  update you run yourself does; it needs the network, and may run on
  battery;
- the installed copy of the script, `-Scheduled`: a full update with no
  window (started through `conhost.exe --headless`), with its log as any
  run's.

It doesn't interrupt you: a tool you have open stays as it is until the
next day's run. It tells you only three things, as Windows notifications:
a run that failed (a click opens its log); a zip the script can't
download itself (Arsenal Image Mounter's), one per vendor page (a click
opens the page); and a newer version of a watched tool (a click opens its
page). It never opens a page itself. Every run's result block
ends with the scheduled update's state (What the output shows).

## The catalogue

| Family | Tools | Source |
|---|---|---|
| Zimmerman | GUI: JumpList Explorer, MFT Explorer, Registry Explorer, SDB Explorer, ShellBags Explorer, Timeline Explorer. CLI: AmcacheParser, AppCompatCacheParser, EvtxECmd, JLECmd, LECmd, MFTECmd, PECmd, RBCmd, RecentFileCacheParser, RECmd, SBECmd, SQLECmd, SrumECmd, SumECmd, WxTCmd | download.ericzimmermanstools.com |
| NirSoft | AppCrashView, AppResourcesUsageView, BootPerformanceView, BrowserDownloadsView, BrowsingHistoryView, DevManView, ESEDatabaseView, FullEventLogView, InstalledAppView, InstalledPackagesView, JumpListsView, MyLastSearch, NetworkUsageView, OfflineRegistryFinder, OfflineRegistryView, RecentFilesView, RegFileExport (console), RegistryChangesView, ShellBagsView, ShortcutsMan, ShutdownPerformanceView, TurnedOnTimesView, UninstallView, USBDeview, USBDriveLog, WhatInStartup, WifiHistoryView, WinDefLogView, WinLogOnView, WinPrefetchView | nirsoft.net |
| Sysinternals | Autoruns (and autorunsc), Disk2vhd, Process Explorer | download.sysinternals.com |
| Arsenal | Arsenal Image Mounter (GUI, and `aim_cli`, `aim_pro`) | arsenalrecon.com: version and MD5; the zip downloaded by hand (MEGA) |
| SRUM-DUMP | SRUM-DUMP (GUI, and `srum_dump` on the PATH: one exe, two copies) | GitHub releases (MarkBaggett/srum-dump), the asset's SHA-256 digest |
| Velocidex | Velociraptor (a shortcut that runs `velociraptor.exe gui`, and `velociraptor` on the PATH: one exe, two copies) | GitHub releases (Velocidex/velociraptor), the asset's SHA-256 digest; the highest version of the 64-bit exe |
| sqlitebrowser | DB Browser for SQLite (and DB Browser for SQLCipher, in its zip) | GitHub releases (sqlitebrowser/sqlitebrowser), the "no installer" 64-bit zip; no digest published, so both exes' signers are the check |

Zimmerman tools are those of the vendor's "Forensic tools" section with a
build on a current .NET line, all .NET 10 today; Hasher, bstrings, rla, EZ
Viewer and VSCMount are not included. A
tool the vendor adds is reported as available, not installed, until it is in
the catalogue. The NirSoft tools are those that read collected artefacts
(a collector's output or a Velociraptor collection), not only the running
system, and only NirSoft's browser tools that cover many browsers; those
with no x64 build are installed as x86. Each starts with the settings for
collected artefacts: times in UTC (NirSoft calls it GMT), no time filter
(FullEventLogView's default shows only the last 7 days), and a header line
in exports, written into its `.cfg` while the file is new or empty; once
the tool has saved its own settings there, the file is left as it is.
SRUM-DUMP's exe is unsigned; it is checked against
GitHub's digest and recorded by its SHA-256. Velociraptor's `gui` keeps its
datastore in your temporary folder and serves its web interface on
localhost, with a local client that collects from this machine.

The family says where a tool comes from; its category says what it
examines, and that is how the workstation is laid out (Where things go):

| Category | Tools |
|---|---|
| System | TurnedOnTimesView, BootPerformanceView, ShutdownPerformanceView, WifiHistoryView, Process Explorer |
| Accounts | SumECmd, WinLogOnView |
| File Activity | MFT Explorer, MFTECmd, RBCmd, ShortcutsMan, LECmd, JumpList Explorer, JumpListsView, JLECmd, RecentFilesView, ShellBags Explorer, ShellBagsView, SBECmd, SDB Explorer, AppCompatCacheParser |
| Execution | WinPrefetchView, PECmd, AppResourcesUsageView, SrumECmd, SRUM-DUMP, AmcacheParser, RecentFileCacheParser, AppCrashView, NetworkUsageView, UninstallView, InstalledAppView, InstalledPackagesView |
| Persistence | Autoruns, autorunsc, WhatInStartup |
| Connected Devices | USBDeview, DevManView, USBDriveLog |
| Registry | Registry Explorer, OfflineRegistryView, RECmd, OfflineRegistryFinder, RegistryChangesView, RegFileExport |
| Event Logs | FullEventLogView, EvtxECmd, WinDefLogView |
| Browsers | BrowsingHistoryView, BrowserDownloadsView, MyLastSearch |
| Acquisition | Disk2vhd, Arsenal Image Mounter, AIM CLI, Velociraptor |
| Other | Timeline Explorer, SQLECmd, WxTCmd, ESEDatabaseView, DB Browser for SQLite |

A tool for one area goes in that area's category even when it reads the
registry or an event log; Registry, Event Logs and Other hold the tools
that cover many. Commands and Lateral Movement have no tool yet.

| Prerequisite | When | Source |
|---|---|---|
| .NET Desktop Runtime, per major version | a GUI tool targets that version | Microsoft's release metadata (SHA-512) |
| .NET Runtime, per major version | only CLI tools target that version | Microsoft's release metadata (SHA-512) |

A runtime version something else installed is used, and listed in the
inventory as not installed by the script; it is never removed.

**Arsenal Image Mounter** is installed like the others, except that you
download it: its vendor ships it through MEGA. When an install or update is
due, the run says which zip to download from the vendor's downloads page
into your Downloads folder; the next run checks it against the vendor's MD5
and signer and installs the GUI (a Desktop shortcut) and the command-line
`aim_cli` and `aim_pro` (on the PATH), with the .NET Desktop Runtime 10, the
Visual C++ Redistributable (x64) and AIM's driver (Arsenal's package from
GitHub: its catalogue must be signed by Microsoft's hardware compatibility
publisher and name every driver file, verified by Windows' own verifier,
then installed with their `aim_ll.exe`). Visual C++ and the driver are
kept current and never removed: other programs share Visual C++, and
removing the driver needs a restart.

**Watched only.** Tools that come with an installer of their own are not
installed or updated by the script; it only keeps loose tools. Where one of
these is installed, each run without a selection compares its version (from
Windows' list of installed programs) with the vendor's latest and, when a
newer one is out, warns with the vendor's page (opened in an update run, a
notification in a scheduled one), as for a hand download:

| Tool | Version read from |
|---|---|
| FTK Imager | exterro.com/ftk-downloads (the newest release's page) |
| DCode | digital-detective.net/dcode (the build it states) |

The versions are compared to the precision the vendor gives: 8.3 against an
installed 8.3.0.27 is current to the vendor's page, so a patch build
released under the same name (an 8.3.0.30) is not seen. They are listed in
the inventory as `Tool` rows owned `no`.

## Adapting it

Everything specific to a tool, a vendor or a prerequisite sits in tables at
the top of the script (CONFIG), each field documented beside it; the rest
is shared.

| To | Change |
|---|---|
| Add a Zimmerman tool left out | Take its zip out of the `EZTools` source's `OutOfScope` and add a `$Catalogue` row, copied from a similar tool's |
| Drop a tool | Remove its `$Catalogue` row: the next full run removes it from the workstation, with its PATH entry and shortcuts |
| Add a NirSoft tool | A `$Catalogue` row; `Package` is the name in its PAD and zip URLs, the x64 build is picked when there is one |
| Add a Sysinternals tool | A `$Catalogue` row; `Package` is the zip's name, `Files` its x64 files, `EulaKeys` its key under `HKCU\Software\Sysinternals` |
| Add a tool released on GitHub | A `$Families` row (its signer) and a `$Catalogue` row with `Source = 'GitHub'`, `Package` the `owner/repository`, `AssetPattern` the asset's name (SRUM-DUMP is one). An asset that is a zip is extracted; one that is the exe itself is installed as it is (decompressed if it ends in `.gz`), under `InstalledFileName` where its own name carries its version; a `version` group in `AssetPattern` takes the highest of several (Velociraptor) |
| Give a GUI tool's shortcut arguments | `GuiArguments` on its row (Velociraptor's `gui`) |
| Check the signer of an exe that is neither the GUI nor a command-line one | `OtherExes` on its row (DB Browser for SQLCipher) |
| Watch a tool that has its own installer | A `$WatchedTools` row: the pattern its name matches among Windows' installed programs, and a `VersionPage` source read for the vendor's latest version (FTK Imager, DCode). It is never installed |
| Add a vendor of a known kind (below) | A `$Sources` row with that `Kind` and its settings, a `$Families` row, and its `$Catalogue` rows naming the source. No code |
| Add a vendor of a new kind | A `$Sources` row with a new `Kind`, one function `Get-<Kind>Remote` returning `New-Remote` (the contract, below), and its line in `Get-SourceRemote` |
| Add a prerequisite | A `$Sources` row for where it comes from, and an `$OtherPrerequisites` row naming it, its `Detect` kind (how the installed version is read) and its `Install` kind, with their settings; its `Capability` in the `Requires` of the tools that need it |
| Put a tool in another category, or add a category | The row's `Category`; a new name in `$Categories`. The next update run moves the tool's folder as it is (nothing downloaded) and remakes its shortcuts |
| Add a .NET runtime flavour, or maps synced like EvtxECmd's | A row of `$DotNetFlavours` or `$AncillaryContent` |
| Run the scheduled update at another time | `$ScheduledUpdateTime` (local time), then `-ScheduledUpdate Enable` again |

A `$Catalogue` row's `Build` names the build where the source doesn't
(`x64`, or a .NET tool's line such as `net10`, which its runtimeconfig.json
must confirm at install).

An adapted copy's SHA-256 isn't the one published for its version, so it
never updates itself from this repository; set `$SelfUpdateRepository` to
`''`, or to your own repository's releases (the same asset and notes
layout), to say so plainly.

### The source kinds

| Kind | What it fetches | Settings on the `$Sources` row | Used by |
|---|---|---|---|
| `EzIndex` | One index page listing every zip with its .NET line; zips in that line not in the catalogue are reported as available | `IndexUrl`, `DownloadPattern`, `CurrentLinePattern`, `OutOfScope` | Zimmerman |
| `VersionPage` | One page or feed per tool, the version (and the vendor's hash, where published) read by a pattern; then download URLs tried by build, or a hand download expected in the Downloads folder | `PageUrl`, `VersionPattern` (named groups `version`, `hash`), `HashAlgorithm`, `FileName`, `Downloads` (`Build`, `Suffix`, `Url`) or `ManualDownload` (with `DownloadPageUrl`, the page you download from, where it isn't `PageUrl`); `HighestVersion` (the highest match, not the first), `VersionSeparator` (a character written in place of a dot) | NirSoft; Arsenal Image Mounter; the watched tools' versions |
| `DirectUrl` | A file at a fixed URL; the server's headers are the change marker | `Url` (a template; `{0}` where `Package` is the URL) | Sysinternals |
| `GitHubRelease` | The latest release's asset, its SHA-256 digest from the API the vendor's hash | none (`Package`, `AssetPattern` and `InstalledFileName` on the tool's row) | SRUM-DUMP, Velociraptor, DB Browser for SQLite |
| `RedirectedUrl` | A permanent link that redirects to the current file; the vendor's hash read from the final URL | `Url`, `HashInUrlPattern`, `HashAlgorithm` | Visual C++ Redistributable |
| `GitHubFile` | A file in a repository at the last commit to it, the version from the commit's message, the git blob hash the vendor's hash | `VersionPattern` (`Package`, `RepositoryPath` and `Branch` on the row) | AIM's driver package |

In a template, `{0}` is the row's `Package`, `{1}` the version the source
states, `{2}` the build's suffix.

### The adapter contract

An adapter only says what the source offers now; everything after that is
shared: downloading, the hash and signer checks, extraction, the install and
swap, PATH, shortcuts, writable folders, clean-up and the records. It takes
the `$Sources` row and the tool's (or prerequisite's) row, and returns
`New-Remote` with:

| Field | Meaning |
|---|---|
| `Available` | `$false` with `Detail` saying why (not found, no release) when the source has nothing; the tool is then a FAIL, never silently skipped |
| `Version` | The version the source states, where it states one |
| `Build` | The build's name: `x64`, or a .NET tool's line (`net10`), which the file's `runtimeconfig.json` must confirm at install |
| `Marker` | The change marker compared with the one recorded at install: any difference means a download (HTTP headers, a version, a release tag with the asset's digest) |
| `Url`, `FileName` | Where the file is, and what to call it |
| `VendorHashAlgorithm`, `VendorHash` | The vendor's published hash of the file, where there is one (`SHA256`, `SHA512`, `MD5`, `GitBlobSHA1`); the download is refused when it differs |
| `LocalFile`, `NeedsManualDownload`, `Detail` | For a file the user downloads by hand (Arsenal Image Mounter): the file's path once it is there, and what to download and where until then |

`Get-DirectUrlRemote` (six lines) is the smallest adapter; `Get-VersionPageRemote`
the one with the most settings.

## Where things go

| What | Where |
|---|---|
| Tools | `%ProgramFiles%\ForensicTools\<Category>\<Tool>\` |
| CLI tools | each one's folder on the machine PATH |
| GUI shortcuts | Desktop and Start Menu, in a folder per category (`System`, `File Activity`, `Execution`, ...); Timeline Explorer directly |
| The script | `%ProgramFiles%\ForensicTools\Update-ForensicWorkstation.ps1`, with its shortcut directly on the Desktop and in the Start Menu; the copy you ran it from stays where it is |
| Records | `%ProgramData%\ForensicWorkstation\`, writable by administrators only |
| Kept installers | `%ProgramData%\ForensicWorkstation\Installers\`, for a later uninstall |
| The scheduled update, when set up | Task Scheduler's `\ForensicWorkstation\Update forensic workstation`; the notifications' name under `HKCU\Software\Classes\AppUserModelId\ForensicWorkstation.Update` |

Program Files is used because only elevated processes write there: a folder on
the PATH that a standard process could write to would let it replace a binary
that later runs elevated. The account may write only to the settings the
tools save beside their exe, and nothing else in their folders: each NirSoft
tool's `.cfg` file, Registry Explorer's `Bookmarks\User`, ShellBags
Explorer's and Timeline Explorer's `Settings`, ShellBags Explorer's `logs`,
JumpList Explorer's and SDB Explorer's `Settings.xml`, and the `Temp` folder
where
AmcacheParser, SQLECmd, SrumECmd, SumECmd and WxTCmd copy the databases
they read. A tool folder on the PATH is never writable; only a subfolder
of it may be. These are kept across updates and are not verified; one
that holds a junction or link (a standard process can make one there) is
never followed: that tool's update fails, and `-Verify` fails it. Only the
x64 builds of the Sysinternals tools are installed; autorunsc has a folder of
its own, so `autorunsc64` is on the PATH and the Autoruns GUI is not;
SRUM-DUMP likewise: the GUI's copy has the shortcut, the `srum_dump` copy
is on the PATH.

A workstation built by an earlier version is laid out by today's
categories on its first update run (before 0.3.0, folders were by family;
1.0.0 moved Autoruns, autorunsc and WxTCmd): each tool's folder is moved as it
is, settings and grants with it, nothing downloaded, and its shortcuts and
PATH entry remade. A tool in use stays where it is until the next run.

<img src="docs/images/desktop.webp" alt="The Desktop's icons: Recycle Bin, a Microsoft Edge shortcut, the folders File Activity, Other, Accounts, Persistence, Acquisition, Registry, Browsers, System, Connected Devices, Event Logs and Execution, and the shortcuts Timeline Explorer and Update forensic workstation">

*The Desktop after a fresh build: a folder per category, Timeline Explorer
and the script's own shortcut directly.*

## Compatibility

From 1.0.0, every 1.x release keeps these as they are. A 1.x may add to
them (a parameter or a parameter value, a column at the end of a CSV, a
field of a JSON record, a `Kind` or `Class` value); removing, renaming,
reordering or changing the meaning of any of them is a new major version.

- How it is run: `Update-ForensicWorkstation.ps1`, its parameters (the
  tables under Usage), the environment variable
  `FORENSIC_WORKSTATION_GITHUB_TOKEN` and its exit codes (0 PASS, 1 WARN, 2 FAIL, 3
  stopped before any work; after a self-update, the new release's).
- Where it puts things: the install tree
  `%ProgramFiles%\ForensicTools\<Category>\<Tool>\` (`<Tool>` the
  catalogue's name, e.g. `JumpListExplorer`), the script's own copy
  `%ProgramFiles%\ForensicTools\Update-ForensicWorkstation.ps1`, the
  shortcut names (`Update forensic workstation`, and each GUI tool's in
  its category's folder), the records root
  `%ProgramData%\ForensicWorkstation\` with `Runs\<UTC time>\run.log`
  (`%LocalAppData%\ForensicWorkstation\` for a run without elevation) and
  `Installers\`.
- The records: the names and columns of `inventory.csv` and `files.csv`,
  their `Kind`, `Owned`, `VendorHashMatched` and `Class` values, the date
  format (`yyyy-MM-ddTHH:mm:ssZ`) and the bytes (UTF-8 without BOM, CRLF,
  every cell quoted); `scheduled-run.json` with its fields; `state.json`
  by its `SchemaVersion`: every 1.x reads what an earlier 1.x wrote (its
  keys are the script's own and may change).
- The console's `RESULT:` line (`RESULT: PASS`, `WARN` or `FAIL`, then
  what it covers); no other console wording, and not the log's layout.
- The scheduled update's task, `\ForensicWorkstation\Update forensic
  workstation`, and its notifications' name, `ForensicWorkstation.Update`
  under `HKCU\Software\Classes\AppUserModelId`: a 1.x finds, replaces and
  removes what an earlier one set up.

The catalogue is not part of it: a minor release may add, drop or move a
tool, a family or a category (a moved tool's folder moves with it,
nothing downloaded).

## What the output shows

Each run writes `Runs\<UTC time>\run.log` under the records folder (a dry run
or `-Verify` without elevation writes under `%LocalAppData%` instead): what
the console shows, with the address of every download. An
update also writes, at the records folder's root and in the run's folder:

| File | Holds |
|---|---|
| `inventory.csv` | Per tool, prerequisite version, ancillary set and the script's own installed copy (`Kind`: `Tool`, `Prerequisite`, `Ancillary`, `Script`): version (a commit for ancillary content), build, whether the script installed it (`Owned`: `yes`, or `no` for a runtime or watched tool installed otherwise), source URL, SHA-256 of the download, the vendor's hash and whether it matched (`VendorHashMatched`: `yes`, or `not published`; a mismatch is never installed), the signer, the change marker, the install time (UTC), the location |
| `files.csv` | The SHA-256 of every file the script installed (its own installed copy included), by `Class`: `Vendor`, `Ancillary` (synced content), `UserData` (kept and granted paths: listed, no length or SHA-256); `RelativePath` relative to the install root |
| `state.json` | What the script installed and owns (what clean-up may remove) |
| `scheduled-run.json` | The last scheduled run's start, end, script version, exit code, what it means (`PASS`, `WARN`, `FAIL` or `STOPPED`) and log (written by that run; Task Scheduler sees only the console host's exit code) |

<img src="docs/images/inventory.webp" alt="Timeline Explorer with inventory.csv open: 69 lines, the columns Kind, Family, Category, Name and Version in view, one row per tool (AimCli, AmcacheParser, AppCompatCacheParser, AppCrashView, AppResourcesUsageView, ArsenalImageMounter, Autoruns, Autorunsc, BootPerformanceView and the others)">

*`inventory.csv` in Timeline Explorer (first columns).*

Records are UTF-8 without BOM, CRLF, every CSV cell quoted. The console ends
with a result block: PASS (current and verified), WARN (an update not applied,
a source that couldn't be checked, a tool in use, a runtime past its end of
support), FAIL (an install or a check that failed), per category and for
the script, prerequisites, ancillary content, PATH and shortcuts, clean-up
and records. Its last line, INFO, is the scheduled update's state, for
information: disabled, not run yet (with its first run), running, or its
last run and its exit code, read from `scheduled-run.json`, or unknown
where that run left no record (with the next run). It never changes the
verdict, except a scheduled update set up whose task has gone from Task
Scheduler, a WARN.

<img src="docs/images/end-of-update.webp" alt="Console: the result block of an update, RESULT: PASS for every tool in the catalogue, its prerequisites and ancillary content, then Script, Prerequisites 3 of 3, File Activity 14 of 14, Registry 6 of 6, Other 5 of 5, Execution 13 of 13, Event Logs 3 of 3, Accounts 2 of 2, Connected Devices 3 of 3, System 5 of 5, Browsers 3 of 3, Persistence 3 of 3, Acquisition 5 of 5, Ancillary content 3 of 3, PATH and shortcuts 2 of 2 PASS, the records written (inventory.csv 69 rows, files.csv 1640 rows), INFO Scheduled task: disabled, and the log's location">

*The result block: the verdict and each group.*

The records show what was installed, from where, with which hashes, and when,
and `-Verify` shows whether the files are still those bytes. The commit
recorded for synced content is the one upstream when the run checked;
`--sync` downloads the branch moments later. They don't show how a tool was
used, and they say nothing about a file changed or replaced by anything
else between runs beyond what `-Verify` finds.

## What it does not do

- It isn't a forensic suite: it installs and updates a chosen set of
  standalone tools, and nothing it doesn't list.
- Its self-update trusts GitHub: the release file's SHA-256 digest from the
  API and the SHA-256 in the release notes, over TLS; the script isn't
  code-signed. `-NoSelfUpdate` skips it for a run; `$SelfUpdateRepository =
  ''` in your copy turns it off for good. A copy whose SHA-256 isn't the one
  published for its version (an adapted copy) never updates itself.
- It installs nothing for other accounts on the machine: per-user items
  (shortcuts, settings grants, the Sysinternals EULA) are for the account
  that runs it, which must be the account whose desktop it is. An update
  elevated with another administrator's credentials stops.
- It doesn't keep custom EvtxECmd or SQLECmd maps or RECmd batch files across
  a sync.
- No Microsoft Defender exclusions yet.
- It doesn't download Arsenal Image Mounter (you do; see the catalogue).
- It never removes the Visual C++ Redistributable or AIM's driver; Windows'
  driver store keeps each AIM driver package installed.
- arm64 Windows is not supported.
- Some downloads have no signature to check. Unsigned NirSoft builds and
  SRUM-DUMP are installed on TLS and the vendor's hash or GitHub's digest
  alone. DB Browser for SQLite publishes no hash: its two exes' signatures
  are the check, and its DLLs aren't covered by one. The recorded SHA-256
  of every file is the audit trail.
- A watched tool's "current" comes from the vendor's web page over TLS,
  with nothing signed behind it.
- Velociraptor's `gui` is a local server with a login, reachable by every
  process on the machine; its datastore is in your temporary folder. For a
  case, run `velociraptor` from the PATH with a configuration of your own.
- The records under `%ProgramData%\ForensicWorkstation\` are readable by
  every account on the machine (only administrators can change them).
- Self-update is the largest single trust it places: `-NoSelfUpdate` and
  `$SelfUpdateRepository` are the controls.

## Contributing

Questions and bug reports: GitHub issues. Pull requests are welcome.

Adding tools and sources: see [Adapting it](#adapting-it). A change to the
script is a release with its SHA-256 in the notes, as self-update needs.
Code: Windows PowerShell 5.1, no modules, PSScriptAnalyzer-clean, ASCII.

## Licence

[0BSD](LICENSE) (Zero-Clause BSD). Copyright (C) 2026 by outis.
Use it for anything, with no attribution required; provided as is, with no
warranty.
