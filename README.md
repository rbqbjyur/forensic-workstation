# forensic-workstation

My own set-up of the common Windows forensic tools, shared as it is: one
Windows PowerShell script that installs them on a fresh DFIR workstation and
keeps them current, downloading only what has changed since the last run and
removing what is no longer needed.

It isn't a forensic suite. It keeps the many small standalone tools up to
date, so the workstation is ready before an investigation: Eric Zimmerman's
tools (EZ Tools) with their EvtxECmd maps, RECmd batch files and SQLECmd
maps, NirSoft's forensic utilities, Sysinternals tools and Arsenal Image
Mounter with its driver, with the .NET runtimes and Visual C++
Redistributable they need. Every download is hashed, checked against the
vendor's published hash and signer, and recorded, so the tool versions
behind an analysis can be cited later.

The selection is mine. Use it as it is, or adapt it: adding or
dropping a tool is a row in a table, and another vendor's set needs only a
small function that finds its downloads (see [Adapting it](#adapting-it)).

<img src="docs/images/demo.webp" alt="Console, 80 columns: .\Update-ForensicWorkstation.ps1 typed at a Windows PowerShell prompt; the header (version 0.3.0, host, OS, elevated account, the script's SHA-256, the tools and records folders, the log); Script, this script current and the installed copy this file; Checking sources, each of the 43 tools, the driver, the Visual C++ Redistributable, the .NET Desktop Runtime 10 and the three ancillary sets current except EvtxECmd and USBDeview (update available) and the EvtxECmd maps (changed upstream); the plan (update Event Logs\EvtxECmd, update Connected Devices\USBDeview, sync the EvtxECmd maps); both downloads with their SHA-256 and signer; the maps synced (475 files); nothing to remove; PATH and shortcuts unchanged; the records written; RESULT: PASS with the script and every category PASS">

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
  alone keeps them).
- Verifies every download: SHA-256, the vendor's published hash where there
  is one (.NET, Arsenal Image Mounter, the Visual C++ Redistributable, AIM's
  driver package), the Authenticode signer of every exe it installs, AIM's
  driver against its Microsoft-signed catalogue, and a
  re-read of every extracted file before it is used. An update is swapped in
  only when all of that passes; a tool running from its folder is left as it
  is.
- Lays the workstation out by what each tool examines: a folder per
  category (System, Accounts, File Activity, Execution, Connected Devices,
  Registry, Event Logs, Acquisition, Other) under Program Files, on the
  Desktop and in the Start Menu alike. Command-line tools go on the machine
  PATH, so they run by name from any terminal; GUI tools get shortcuts in
  their category's folder (Timeline Explorer directly, used with
  everything).
- Removes what it installed and no longer needs: tools dropped from the
  catalogue, superseded prerequisite versions, runtime lines no tool needs.
  It never removes anything it didn't install.
- Writes a log per run, and an inventory and per-file SHA-256 record of what
  is installed.
- Keeps a copy of itself under Program Files, with a Desktop and Start Menu
  shortcut, *Update forensic workstation*, that asks for administrator
  rights and runs that copy; a run started without them asks the same way
  (UAC) and finishes in its own window.
- Keeps itself current: an update run installs this repository's latest
  release, checked against GitHub's SHA-256 digest of the file and the
  SHA-256 in the release notes, and hands the run over to it.
- Opens Arsenal Image Mounter's downloads page in the default browser when
  its zip is due and missing.

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
- An elevated prompt for an update; `-CheckOnly` and `-Verify` run without.
- Internet access to the vendors' download sites, GitHub (the maps, and
  this script's releases) and Microsoft's .NET release metadata, through
  the account's system proxy settings. GitHub allows 60 calls an hour per
  address without an account; a run makes about six, so a dozen runs in an
  hour from one address reach it, and the run says so until it resets.

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
```

| Parameter | Effect |
|---|---|
| `-CheckOnly` | The dry run: every source is checked and every action an update would take is listed; nothing changes. `-WhatIf` does the same. |
| `-Verify` | Re-hashes the installed files against `files.csv` and lists files missing, changed or not on record. No network access. |
| `-Family` | Limits the run to these families (where the tools come from): `Zimmerman`, `NirSoft`, `Sysinternals`, `Arsenal`, `SRUM-DUMP`. |
| `-Category` | Limits the run to these categories (what the tools examine; the table below). A name may be given without its spaces: `-Category FileActivity`. |
| `-Tool` | Limits the run to these tools (names as in the catalogue). |
| `-Pause` | Keeps the window open at the end, for a run started from a shortcut (the script's own shortcut passes it; a run started from Explorer pauses anyway). |
| `-NoSelfUpdate` | Runs this copy as it is, without checking for a newer release. The run handed over after a self-update uses it. |
| `-ElevatedRelaunch` | Set by the script itself on the run it starts elevated; such a run that still has no administrator rights stops instead of relaunching again. |

Exit codes: 0 PASS, 1 WARN, 2 FAIL, 3 stopped before any work.

## The catalogue

| Family | Tools | Source |
|---|---|---|
| Zimmerman | GUI: JumpList Explorer, MFT Explorer, Registry Explorer, SDB Explorer, ShellBags Explorer, Timeline Explorer. CLI: AmcacheParser, AppCompatCacheParser, EvtxECmd, JLECmd, LECmd, MFTECmd, PECmd, RBCmd, RecentFileCacheParser, RECmd, SBECmd, SQLECmd, SrumECmd, SumECmd, WxTCmd | download.ericzimmermanstools.com |
| NirSoft | AppCompatibilityView, AppResourcesUsageView, FullEventLogView, JumpListsView, OfflineRegistryFinder, OfflineRegistryView, RecentFilesView, ShellBagsView, ShortcutsMan, TurnedOnTimesView, USBDeview, UserAssistView, UserProfilesView, WinPrefetchView | nirsoft.net |
| Sysinternals | Autoruns (and autorunsc), Disk2vhd, Process Explorer | download.sysinternals.com |
| Arsenal | Arsenal Image Mounter (GUI, and `aim_cli`, `aim_pro`) | arsenalrecon.com: version and MD5; the zip downloaded by hand (MEGA) |
| SRUM-DUMP | SRUM-DUMP (GUI, and `srum_dump` on the PATH: one exe, two copies) | GitHub releases (MarkBaggett/srum-dump), the asset's SHA-256 digest |

Zimmerman tools are those of the vendor's "Forensic tools" section with a
build on a current .NET line, all .NET 10 today; Hasher, bstrings, rla, EZ
Viewer and VSCMount are not included. A
tool the vendor adds is reported as available, not installed, until it is in
the catalogue. Seven of the NirSoft tools have no x64 build and are
installed as x86. SRUM-DUMP's exe is unsigned; it is checked against
GitHub's digest and recorded by its SHA-256.

The family says where a tool comes from; its category says what it
examines, and that is how the workstation is laid out (Where things go):

| Category | Tools |
|---|---|
| System | TurnedOnTimesView, Process Explorer, Autoruns, autorunsc |
| Accounts | UserProfilesView, SumECmd |
| File Activity | MFT Explorer, MFTECmd, RBCmd, ShortcutsMan, LECmd, JumpList Explorer, JumpListsView, JLECmd, RecentFilesView, ShellBags Explorer, ShellBagsView, SBECmd, SDB Explorer, AppCompatCacheParser, AppCompatibilityView |
| Execution | WinPrefetchView, PECmd, AppResourcesUsageView, SrumECmd, SRUM-DUMP, WxTCmd, AmcacheParser, UserAssistView, RecentFileCacheParser |
| Connected Devices | USBDeview |
| Registry | Registry Explorer, OfflineRegistryView, RECmd, OfflineRegistryFinder |
| Event Logs | FullEventLogView, EvtxECmd |
| Acquisition | Disk2vhd, Arsenal Image Mounter, AIM CLI |
| Other | Timeline Explorer, SQLECmd |

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

## Adapting it

Everything specific to a tool or vendor sits in tables at the top of the
script (CONFIG), each field documented beside it; the rest is shared.

| To | Change |
|---|---|
| Add a Zimmerman tool left out | Take its zip out of `$EzOutOfScope` and add a `$Catalogue` row, copied from a similar tool's |
| Drop a tool | Remove its `$Catalogue` row: the next full run removes it from the workstation, with its PATH entry and shortcuts |
| Add a NirSoft tool | A `$Catalogue` row; `Package` is the name in its PAD and zip URLs, the x64 build is picked when there is one (`$NirSoftBuilds`) |
| Add a Sysinternals tool | A `$Catalogue` row; `Package` is the zip's name, `Files` its x64 files, `EulaKeys` its key under `HKCU\Software\Sysinternals` |
| Add a tool released on GitHub, or published at a fixed URL | A `$Families` row (its signer) and a `$Catalogue` row with `Source = 'GitHubRelease'` (`Package` the `owner/repository`, `AssetPattern` the asset's name; SRUM-DUMP is one) or `Source = 'DirectUrl'` (`Package` the URL); `Build` names the build where the source doesn't (`x64`, or a .NET tool's line such as `net10`). An asset that is a zip is extracted; one that is the exe itself is installed as it is. No code |
| Add a vendor with its own download page or feed | A `$Families` row, its `$Catalogue` rows, and a source adapter: a function `Get-<Source>Remote` returning `New-Remote` (below), with its line in `Get-ToolRemote` |
| Put a tool in another category, or add a category | The row's `Category`; a new name in `$Categories`. The next update run moves the tool's folder as it is (nothing downloaded) and remakes its shortcuts |
| Add a .NET runtime flavour, or maps synced like EvtxECmd's | A row of `$DotNetFlavours` or `$AncillaryContent` |

An adapted copy's SHA-256 isn't the one published for its version, so it
never updates itself from this repository; set `$SelfUpdateRepository` to
`''`, or to your own repository's releases (the same asset and notes
layout), to say so plainly.

### The adapter contract

An adapter only says what the source offers now; everything after that is
shared: downloading, the hash and signer checks, extraction, the install and
swap, PATH, shortcuts, writable folders, clean-up and the records. It
returns `New-Remote` with:

| Field | Meaning |
|---|---|
| `Available` | `$false` with `Detail` saying why (not found, no release) when the source has nothing; the tool is then a FAIL, never silently skipped |
| `Version` | The version the source states, where it states one |
| `Build` | The build's name: `x64`, or a .NET tool's line (`net10`), which the file's `runtimeconfig.json` must confirm at install |
| `Marker` | The change marker compared with the one recorded at install: any difference means a download (HTTP headers, a version, a release tag with the asset's digest) |
| `Url`, `FileName` | Where the file is, and what to call it |
| `VendorHashAlgorithm`, `VendorHash` | The vendor's published hash of the file, where there is one (`SHA256`, `SHA512`, `MD5`, `GitBlobSHA1`); the download is refused when it differs |
| `LocalFile`, `NeedsManualDownload`, `Detail` | For a file the user downloads by hand (Arsenal Image Mounter): the file's path once it is there, and what to download and where until then |

`Get-DirectUrlRemote` (five lines) and `Get-GitHubReleaseRemote` are the
generic adapters; `Get-SysinternalsRemote` shows a vendor-specific one that
only builds the URL and calls the generic one.

## Where things go

| What | Where |
|---|---|
| Tools | `%ProgramFiles%\ForensicTools\<Category>\<Tool>\` |
| CLI tools | each one's folder on the machine PATH |
| GUI shortcuts | Desktop and Start Menu, in a folder per category (`System`, `File Activity`, `Execution`, ...); Timeline Explorer directly |
| The script | `%ProgramFiles%\ForensicTools\Update-ForensicWorkstation.ps1`, with its shortcut directly on the Desktop and in the Start Menu; the copy you ran it from stays where it is |
| Records | `%ProgramData%\ForensicWorkstation\`, writable by administrators only |
| Kept installers | `%ProgramData%\ForensicWorkstation\Installers\`, for a later uninstall |

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
of it may be. These are kept across updates and are not verified. Only the
x64 builds of the Sysinternals tools are installed; autorunsc has a folder of
its own, so `autorunsc64` is on the PATH and the Autoruns GUI is not;
SRUM-DUMP likewise: the GUI's copy has the shortcut, the `srum_dump` copy
is on the PATH.

A workstation built by a version before 0.3.0 (folders by family) is laid
out by category on its first update run: each tool's folder is moved as it
is, settings and grants with it, nothing downloaded, and its shortcuts and
PATH entry remade. A tool in use stays where it is until the next run.

<img src="docs/images/desktop.webp" alt="The Desktop's icons: Recycle Bin, two Microsoft Edge shortcuts, the folders Accounts, Acquisition, Connected Devices, Event Logs, Execution, File Activity, Registry and System, and the shortcuts Timeline Explorer and Update forensic workstation">

*The Desktop after a fresh build: a folder per category, Timeline Explorer
and the script's own shortcut directly.*

## What the output shows

Each run writes `Runs\<UTC time>\run.log` under the records folder (a dry run
or `-Verify` without elevation writes under `%LocalAppData%` instead). An
update also writes, at the records folder's root and in the run's folder:

| File | Holds |
|---|---|
| `inventory.csv` | Per tool, prerequisite version, ancillary set and the script's own installed copy: version, build, whether the script installed it, source URL, SHA-256 of the download, the vendor's hash and whether it matched, the signer, the change marker, the install time (UTC), the location |
| `files.csv` | The SHA-256 of every file the script installed (its own installed copy included), vendor files and synced content apart |
| `state.json` | What the script installed and owns (what clean-up may remove) |

<img src="docs/images/inventory.webp" alt="Timeline Explorer with inventory.csv open: 50 lines, the columns Kind, Family, Category, Name and Version in view, one row per tool (AimCli, AmcacheParser, AppCompatCacheParser, AppCompatibilityView and the others)">

*`inventory.csv` in Timeline Explorer (first columns).*

Records are UTF-8 without BOM, CRLF, every CSV cell quoted. The console ends
with a result block: PASS (current and verified), WARN (an update not applied,
a source that couldn't be checked, a tool in use, a runtime past its end of
support), FAIL (an install or a check that failed), per category and for
the script, prerequisites, ancillary content, PATH and shortcuts, clean-up
and records.

<img src="docs/images/end-of-update.webp" alt="Console: the result block of an update, RESULT: PASS for every tool in the catalogue, its prerequisites and ancillary content, then Script, Prerequisites 3 of 3, File Activity 15 of 15, Registry 4 of 4, Other 2 of 2, Execution 10 of 10, Event Logs 2 of 2, Accounts 2 of 2, Connected Devices (USBDeview 3.10 installed, unsigned), System 4 of 4, Acquisition 3 of 3, Ancillary content 3 of 3, PATH and shortcuts 2 of 2 PASS, the records written (inventory.csv 50 rows, files.csv 1468 rows), and the log's location">

*The result block: the verdict and each group.*

The records show what was installed, from where, with which hashes, and when,
and `-Verify` shows whether the files are still those bytes. They don't show
how a tool was used, and they say nothing about a file changed or replaced by
anything else between runs beyond what `-Verify` finds.

## What it does not do

- It isn't a forensic suite: it installs and updates a chosen set of
  standalone tools, and nothing it doesn't list.
- Its self-update trusts GitHub: the release file's SHA-256 digest from the
  API and the SHA-256 in the release notes, over TLS; the script isn't
  code-signed. `-NoSelfUpdate` skips it for a run; `$SelfUpdateRepository =
  ''` in your copy turns it off for good. A copy whose SHA-256 isn't the one
  published for its version (an adapted copy) never updates itself.
- It installs nothing for other accounts on the machine: per-user items
  (shortcuts, the Sysinternals EULA) are for the account that runs it.
- It doesn't keep custom EvtxECmd or SQLECmd maps or RECmd batch files across
  a sync.
- No scheduled runs, no Microsoft Defender exclusions and no self-update yet.
- It doesn't download Arsenal Image Mounter (you do; see the catalogue).
- It never removes the Visual C++ Redistributable or AIM's driver; Windows'
  driver store keeps each AIM driver package installed.
- MemProcFS and KAPE are not in the catalogue.
- arm64 Windows is not supported.

## Contributing

Questions and bug reports: GitHub issues. Pull requests are welcome.

Adding tools and sources: see [Adapting it](#adapting-it). A change to the
script is a release with its SHA-256 in the notes, as self-update needs.
Code: Windows PowerShell 5.1, no modules, PSScriptAnalyzer-clean, ASCII.

## Licence

[0BSD](LICENSE) (Zero-Clause BSD). Copyright (C) 2026 by outis.
Use it for anything, with no attribution required; provided as is, with no
warranty.
