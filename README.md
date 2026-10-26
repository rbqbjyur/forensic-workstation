# forensic-workstation

A Windows PowerShell script that builds a forensic workstation from fresh and
keeps it current: it installs the analysis tools and the prerequisites they
need, downloads only what has changed since the last run, and removes what is
no longer needed.

Built for the DFIR workstation that has to be ready before an incoming
investigation: a fresh build, or a machine not started for a while. One run
installs or updates Eric Zimmerman's tools (EZ Tools) with their EvtxECmd
maps, RECmd batch files and SQLECmd maps, NirSoft's forensic utilities and
Sysinternals tools, and the .NET runtimes they depend on. Every download is hashed and checked against the vendor's
published hash and signer, and recorded, so the tool versions behind an
analysis can be cited later.

A second run on a workstation that is already current (real output, names
anonymised; the per-tool check lines shortened):

```
================================================================================
Forensic workstation update 0.1.3
================================================================================
Started    : 2026-10-23T05:52:31Z
Host       : WORKSTATION
OS         : Microsoft Windows 11 Enterprise 24H2 (X64)
Account    : WORKSTATION\analyst (elevated)
Mode       : update
Selection  : every tool in the catalogue
Script     : C:\Users\analyst\Downloads\Update-ForensicWorkstation.ps1
SHA-256    : a1327cf33b6007d6122f5fb4a8012795f4670396368de57c534915e50e8f1618
Tools      : C:\Program Files\ForensicTools
Records    : C:\ProgramData\ForensicWorkstation
Log        : C:\ProgramData\ForensicWorkstation\Runs\20261023T055231Z\run.log

Warnings found during the run are listed at the end, before the result.

--------------------------------------------------------------------------------
Checking sources
  EZViewer                 current
                           (2026.5.0+1cdf49c9a34eaadf0414e454ded7495d420a5945)
  JumpListExplorer         current
                           (2026.5.0+13be9bd7e53ff0f33fe8ddf0279c0dc648d6ec54)
  MFTExplorer              current
  ...


--------------------------------------------------------------------------------
Clean-up
  Nothing to remove.

--------------------------------------------------------------------------------
PATH and shortcuts
  machine PATH already has every tool folder (19)
  shortcuts: 0 made, 0 corrected, 44 unchanged, 0 removed

--------------------------------------------------------------------------------
Records
  state.json, inventory.csv (45 rows) and files.csv (1118 rows) written
Inventory  : C:\ProgramData\ForensicWorkstation\inventory.csv
Files      : C:\ProgramData\ForensicWorkstation\files.csv

================================================================================
RESULT: PASS - every tool in the catalogue, its prerequisites and ancillary
  content
================================================================================
  PASS  Prerequisites: current (9.0.21)
  PASS  Zimmerman: 25 of 25 PASS
  PASS  NirSoft: 12 of 12 PASS
  PASS  Sysinternals: 4 of 4 PASS
  PASS  Ancillary content: 3 of 3 PASS
  PASS  PATH and shortcuts: 2 of 2 PASS
  PASS  Records: state.json, inventory.csv (45 rows) and files.csv (1118 rows)
          written
================================================================================
Log: C:\ProgramData\ForensicWorkstation\Runs\20261023T055231Z\run.log
```

## Table of contents

- [What it does](#what-it-does)
- [Install](#install)
- [Usage](#usage)
- [The catalogue](#the-catalogue)
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
  is one (.NET), the Authenticode signer of every exe it installs, and a
  re-read of every extracted file before it is used. An update is swapped in
  only when all of that passes; a tool running from its folder is left as it
  is.
- Puts command-line tools on the machine PATH, so they run by name from any
  terminal, and GUI tools on the Desktop and in the Start Menu, in a folder
  per family.
- Removes what it installed and no longer needs: tools dropped from the
  catalogue, superseded prerequisite versions, runtime lines no tool needs.
  It never removes anything it didn't install.
- Writes a log per run, and an inventory and per-file SHA-256 record of what
  is installed.

## Install

```powershell
# Download Update-ForensicWorkstation.ps1 from the latest release, then:
Get-FileHash .\Update-ForensicWorkstation.ps1 -Algorithm SHA256
# compare with the SHA-256 in the release notes
Unblock-File .\Update-ForensicWorkstation.ps1
```

### Requirements

- 64-bit Windows (amd64), Windows PowerShell 5.1, no modules. Tested on
  Windows 11 24H2; not tested on Windows 10.
- An elevated prompt for an update; `-CheckOnly` and `-Verify` run without.
- Internet access to the vendors' download sites, GitHub (the maps) and
  Microsoft's .NET release metadata, through the account's system proxy settings.

## Usage

```powershell
# Install or update everything (elevated):
.\Update-ForensicWorkstation.ps1

# Is the workstation current? Lists what an update would do, changes nothing:
.\Update-ForensicWorkstation.ps1 -CheckOnly

# Only some families or tools (nothing is removed in a selective run):
.\Update-ForensicWorkstation.ps1 -Family Zimmerman
.\Update-ForensicWorkstation.ps1 -Tool EvtxECmd, ProcessExplorer

# Re-hash every installed file against the record:
.\Update-ForensicWorkstation.ps1 -Verify
```

| Parameter | Effect |
|---|---|
| `-CheckOnly` | The dry run: every source is checked and every action an update would take is listed; nothing changes. `-WhatIf` does the same. |
| `-Verify` | Re-hashes the installed files against `files.csv` and lists files missing, changed or not on record. No network access. |
| `-Family` | Limits the run to these families: `Zimmerman`, `NirSoft`, `Sysinternals`. |
| `-Tool` | Limits the run to these tools (names as in the catalogue). |

Exit codes: 0 PASS, 1 WARN, 2 FAIL, 3 stopped before any work.

## The catalogue

| Family | Tools | Source |
|---|---|---|
| Zimmerman | GUI: JumpList Explorer, MFT Explorer, Registry Explorer, SDB Explorer, ShellBags Explorer, Timeline Explorer. CLI: AmcacheParser, AppCompatCacheParser, EvtxECmd, JLECmd, LECmd, MFTECmd, PECmd, RBCmd, RecentFileCacheParser, RECmd, SBECmd, SQLECmd, SrumECmd, SumECmd, WxTCmd | download.ericzimmermanstools.com |
| NirSoft | AppCompatibilityView, AppResourcesUsageView, FullEventLogView, JumpListsView, OfflineRegistryFinder, OfflineRegistryView, RecentFilesView, ShellBagsView, ShortcutsMan, USBDeview, UserAssistView, WinPrefetchView | nirsoft.net |
| Sysinternals | Autoruns (and autorunsc), Disk2vhd, Process Explorer | download.sysinternals.com |
| Arsenal | Arsenal Image Mounter (GUI, and `aim_cli`, `aim_pro`) | arsenalrecon.com: version and MD5; the zip downloaded by hand (MEGA) |

Zimmerman tools are those of the vendor's "Forensic tools" section with a
build on a current .NET line, all .NET 10 today; Hasher, bstrings, rla, EZ
Viewer and VSCMount are not included. A
tool the vendor adds is reported as available, not installed, until it is in
the catalogue. Five of the NirSoft tools have no x64 build and are installed
as x86.

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

## Where things go

| What | Where |
|---|---|
| Tools | `%ProgramFiles%\ForensicTools\<Family>\<Tool>\` |
| CLI tools | each one's folder on the machine PATH |
| GUI shortcuts | Desktop and Start Menu, in a folder per family (`EZ Tools`, `NirSoft`, `Sysinternals`) |
| Records | `%ProgramData%\ForensicWorkstation\`, writable by administrators only |
| Kept installers | `%ProgramData%\ForensicWorkstation\Installers\`, for a later uninstall |

Program Files is used because only elevated processes write there: a folder on
the PATH that a standard process could write to would let it replace a binary
that later runs elevated. The account may write only to the settings the
tools save beside their exe, and nothing else in their folders: each NirSoft
tool's `.cfg` file, Registry Explorer's `Bookmarks\User`, ShellBags
Explorer's and Timeline Explorer's `Settings`, JumpList Explorer's and SDB
Explorer's `Settings.xml`, and the `Temp` folder where
AmcacheParser, SQLECmd, SrumECmd, SumECmd and WxTCmd copy the databases
they read. A tool folder on the PATH is never writable; only a subfolder
of it may be. These are kept across updates and are not verified. Only the x64 builds of the Sysinternals tools are
installed; autorunsc has a folder of its own, so `autorunsc64` is on the PATH
and the Autoruns GUI is not.

## What the output shows

Each run writes `Runs\<UTC time>\run.log` under the records folder (a dry run
or `-Verify` without elevation writes under `%LocalAppData%` instead). An
update also writes, at the records folder's root and in the run's folder:

| File | Holds |
|---|---|
| `inventory.csv` | Per tool, prerequisite version and ancillary set: version, build, whether the script installed it, source URL, SHA-256 of the download, the vendor's hash and whether it matched, the signer, the change marker, the install time (UTC), the location |
| `files.csv` | The SHA-256 of every file the script installed, vendor files and synced content apart |
| `state.json` | What the script installed and owns (what clean-up may remove) |

Records are UTF-8 without BOM, CRLF, every CSV cell quoted. The console ends
with a result block: PASS (current and verified), WARN (an update not applied,
a source that couldn't be checked, a tool in use, a runtime past its end of
support), FAIL (an install or a check that failed), per family and for
prerequisites, ancillary content, PATH and shortcuts, clean-up and records.

The records show what was installed, from where, with which hashes, and when,
and `-Verify` shows whether the files are still those bytes. They don't show
how a tool was used, and they say nothing about a file changed or replaced by
anything else between runs beyond what `-Verify` finds.

## What it does not do

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

Adding a tool is adding a row to `$Catalogue` (its fields are documented
beside it); a new source is an adapter function (`Get-<Source>Remote`) and a
line in `Get-ToolRemote`. .NET runtime flavours are rows of `$DotNetFlavours`;
ancillary content is a row of `$AncillaryContent`.
Code: Windows PowerShell 5.1, no modules, PSScriptAnalyzer-clean, ASCII.

## Licence

[0BSD](LICENSE) (Zero-Clause BSD). Copyright (C) 2026 by outis.
Use it for anything, with no attribution required; provided as is, with no
warranty.
