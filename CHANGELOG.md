# Changelog

Notable changes to `Update-ForensicWorkstation.ps1`. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.6.0 - 2026-10-28

### Added
- The scheduled update, off unless set up: `-ScheduledUpdate Enable` registers
  a task that runs the installed copy once a day at 08:00 local time (a
  missed run as soon as the machine is next on, once), elevated without a
  UAC prompt, while the account is logged on, with no window (through
  `conhost.exe --headless`); `-ScheduledUpdate Disable` removes it, and
  its empty folder in Task Scheduler. Neither does anything else.
- `-Scheduled`, the task's run: a full update, unattended (no pause, no
  window). It tells the analyst only of a run that failed or stopped (a
  click opens the log) and of each page awaiting a hand download (a click
  opens the page), as Windows notifications; it opens no page itself, and
  another run holding the update lock stops it without a notification.
- The result block ends with an INFO line (cyan) on the scheduled update:
  disabled, not run yet (its first run), running, or its last run and exit
  code, with the next run, in UTC. It doesn't change the verdict, except a
  scheduled update set up whose task is gone from Task Scheduler (WARN).
  The exit code is the one the scheduled run records in
  `scheduled-run.json` (Task Scheduler sees the console host's).

### Changed
- A signer refusal says what is wrong: "has a signature by X that is not
  valid (HashMismatch)" for a changed signed file, "is not signed" for an
  unsigned one (both read "is signed by X (...), expected Y" before).

### Fixed
- Arsenal Image Mounter's hand download pointed at the product's page,
  which has the version and MD5 but no download link: the check line,
  the plan, the page opened and `SourceUrl` now give
  `https://arsenalrecon.com/downloads`. The version and MD5 are still read
  from the product's page.

## 0.5.0 - 2026-10-28

### Changed
- Every source is a row of one `$Sources` table in CONFIG, with its kind and
  that kind's settings: `EzIndex` (Zimmerman's index page), `VersionPage`
  (a version read from a page or feed, then download URLs by build, or a
  hand download: NirSoft and Arsenal Image Mounter), `DirectUrl`
  (Sysinternals), `GitHubRelease` (SRUM-DUMP), `RedirectedUrl` (the Visual
  C++ Redistributable) and `GitHubFile` (AIM's driver package). A catalogue
  row's `Source` names a row. A vendor of a known kind is rows, not code;
  Arsenal Image Mounter has no adapter of its own any more.
- The Visual C++ Redistributable and AIM's driver are rows of
  `$OtherPrerequisites` naming their source, how their installed version is
  read (`RegistryVersion`, `DriverService`) and how they are installed
  (`Installer`, `DriverPackage`), with every setting on the row.
- After the update: SRUM-DUMP's two copies and Arsenal Image Mounter
  reinstall once (their rows changed; AIM from its zip in Downloads, or,
  if the zip is gone, a WARN asking for it as for an update, the installed
  copy kept meanwhile), and each NirSoft tool downloads once without being
  swapped in (its change marker gained a field for the server's ETag,
  which nirsoft.net leaves empty). Nothing else is downloaded.
- "Available from EZTools, not in the catalogue" names the source (was
  "from Zimmerman").
- A zip downloaded by hand is said as read from the Downloads folder (was
  "Downloaded"); the run log names the address of every download.

## 0.4.0 - 2026-10-28

### Added
- One update run at a time: an update holds a machine-wide lock, and a
  second update run stops before any work (exit 3). The dry run and
  `-Verify` don't take it.
- An update stops before any work (exit 3) when it runs as an account other
  than the one whose desktop it is (elevated with another administrator's
  credentials), or when that account can't be read: shortcuts, grants and
  the Sysinternals EULA would go to the wrong account.

### Changed
- After `--sync`, a tool file on record outside the content folder that was
  changed or removed is a FAIL (was a WARN); a file not on record there
  afterwards stays a WARN, and one removed is logged. The same comparison
  follows a `--sync` that failed or was stopped. User data (granted and
  kept paths) is no longer compared. Files not on record are warned of
  once per top-level entry (a folder with its count), each file listed in
  the log.
- The section line of a synced content set carries what changed outside its
  folder, as its result line does.
- An update removes the staging folders earlier runs left (a run stopped,
  or one that handed over to a newer release).
- A tool's writable grants are set on the new copy before the swap, so a
  grant that fails leaves the installed copy in place.
- `-Verify` with a selection names it in the verdict line; tools in the
  selection that aren't installed are listed.
- A run log that can't be written is said on the console at once and is a
  WARN.

### Fixed
- `-Verify` could PASS while a tool on record had no files in `files.csv`
  (or only user data); that is now a FAIL. A tool that can't be read fails
  alone instead of ending the verification, and a tool folder that can't be
  listed whole is a FAIL.
- `--sync` re-recorded the tool's own files with their hashes after the
  sync, so a file it changed or removed passed `-Verify` from then on. They
  stay on record as installed.
- Clean-up could remove a .NET runtime line a tool still ran on, when that
  tool's update to a newer line failed or was skipped (in use). The line is
  now kept, with a WARN, until no tool on record needs it.
- A new copy that couldn't be moved into place left the tool only in its
  `.old` folder, which the next run deleted. The previous copy is now put
  back; one an interrupted update left aside is put back at the start of
  the next run.
- A junction or link in a folder the account may write (`Temp`, `Settings`,
  ...) could be followed by the elevated update when it carried the user
  data over, copying or granting wherever it pointed. No folder walk follows
  one now: such user data fails the tool's update, `-Verify` fails any
  junction or link in a tool's folder, and the `--sync` comparison fails on
  one.
- `inventory.csv` and `files.csv` are written through a temporary file, as
  `state.json` is, so an interrupted write can't leave them truncated.
- A process stopped at its timeout was reported as stopped even when it
  wasn't.
- A path quoted in a warning or failure (an exception's message) was wrapped
  at a space inside it; it is kept whole.

## 0.3.0 - 2026-10-27

### Added
- `-Category`: a run limited to the tools of one or more categories, as
  `-Family` and `-Tool` limit it. A name may be given without its spaces.
- TurnedOnTimesView and UserProfilesView (NirSoft, 32-bit builds), and
  SRUM-DUMP (GitHub releases; unsigned, checked against GitHub's SHA-256
  digest) as a GUI tool and as the command-line `srum_dump` on the PATH.
- A download that is the tool itself (one exe, not a zip) is installed as
  it is.
- A selection may be given as one comma-separated string
  (`-Family "Zimmerman,NirSoft"`), as a shortcut or `-File` passes it.
- A copy of the script under `%ProgramFiles%\ForensicTools\`, with the
  shortcut "Update forensic workstation" on the Desktop and in the Start
  Menu, which asks for administrator rights (UAC) and runs that copy. The
  first update run from anywhere (Downloads) installs them.
- An update run started without administrator rights runs itself again
  elevated (UAC asks), in its own window kept open at the end; before, it
  stopped. A relaunched run that still has no administrator rights (UAC
  off for a filtered account) stops rather than relaunching again.
- Self-update: an update run installs this repository's latest release,
  checked against GitHub's SHA-256 digest and the SHA-256 in the release
  notes, and hands the run over to it. A copy whose SHA-256 isn't the
  published one for its version (an adapted copy) never updates itself.
  `-NoSelfUpdate` skips the check.
- `-Pause` keeps the window open at the end; a run started from Explorer
  (a shortcut, "Run with PowerShell") pauses anyway.
- When Arsenal Image Mounter's zip is due and missing, an update run
  opens the vendor's downloads page in the default browser, at the
  desktop's own rights.
- Two generic sources for adapted catalogues: `DirectUrl` (a file at a
  fixed URL) and `GitHubRelease` (a release's asset, verified against
  GitHub's digest); the catalogue fields `Build` and `AssetPattern`; the
  adapter contract in the README.

### Changed
- The workstation is laid out by category (what a tool examines: System,
  Accounts, File Activity, Execution, Connected Devices, Registry, Event
  Logs, Acquisition, Other), not by family (where it comes from): the
  folders under `ForensicTools`, the Desktop and the Start Menu alike, a
  folder per category; Timeline Explorer's shortcut stays directly on
  both. A workstation built by an earlier version is moved into that
  layout on its first update run: each tool's folder as it is, settings
  and grants with it, nothing downloaded; its shortcuts and PATH entry are
  remade. A tool in use stays where it is, with a warning, until the next
  run. The dry run lists each move.
- `inventory.csv` and `files.csv` carry a `Category` column after
  `Family`; the result block groups tools by category.
- A refusal by GitHub for its hourly limit of unauthenticated calls says
  so, with the time it resets, instead of a bare "403 Forbidden".
- A full run removes a category's folder under the install root once its
  last tool is removed.
- `inventory.csv` and `files.csv` carry the script's installed copy;
  `-Verify` re-hashes it with the tools.
- Sysinternals is checked through the `DirectUrl` adapter (no change in
  what is checked).

### Fixed
- A dropped tool whose folder another process holds (e.g. as its working
  folder) is left whole and reported as in use (WARN), as an update does;
  before, its files were deleted, its folder, record and PATH entry left,
  and the run failed. A removed copy that can't be deleted is removed by
  the next run, with the category folder it leaves empty.
- The dry run lists a source it couldn't check under Warnings, and one
  that failed under Failures, as an update does; before, only the result
  block showed them.

## 0.2.1 - 2026-10-26

### Fixed
- Typed at an interactive Windows PowerShell prompt (PSReadLine loaded),
  the script no longer stops before any work with "this machine is ."; the
  OS architecture is read from the processor's machine type, then the
  registry.
- The coloured verdict line in the console wraps at 80 columns like the
  rest.
- The driver's row in inventory.csv names what was checked (the package
  catalogue's signer and `aim_ll.exe`'s) and its change marker is the
  package's commit, as for the other prerequisites updated in place; a
  workstation installed with 0.2.0 gets them at its next driver update.

### Changed
- The README shows a demo and pictures, says how to adapt the catalogue
  ("Adapting it"), and lists `Arsenal` among `-Family`'s names.
- ShellBags Explorer's `logs` folder (beside its exe, where it logs a hive's
  transaction logs being applied) is writable by the account.
- A driver file the catalogue check refuses is reported with the SHA-256
  result (and the SHA-1 one only where it differs); the result names
  include CRYPT_E_FILE_ERROR, and TRUST_E_NOSIGNATURE reads as what it
  means.

## 0.2.0 - 2026-10-26

Known issue: typed at an interactive Windows PowerShell prompt, where
PSReadLine is loaded (the default), it stops before any work ("this script
is for amd64 (x64) Windows; this machine is ."), changing nothing. Run it
as `powershell.exe -NoProfile -File .\Update-ForensicWorkstation.ps1`, or
use 0.2.1, which fixes it.

0.1.3 can't check or install the Zimmerman tools since the vendor moved them
to new download paths on 2026-10-24 (it reports them as "can't check");
0.2.0 follows the move.

### Added
- Arsenal Image Mounter: the GUI and its CLI (`aim_cli`, `aim_pro`), with
  the .NET Desktop Runtime 10, the Visual C++ Redistributable (x64) and
  AIM's driver. The vendor ships the tool through MEGA, so you download the
  zip into Downloads when the run asks; the script verifies it (vendor MD5,
  signer) and installs it. The driver comes from Arsenal's package on
  GitHub (git blob hash, signers checked) and is installed and updated with
  their `aim_ll.exe`; the driver's Microsoft-signed catalogue is verified
  by Windows' own verifier, with every driver file a member of it. Visual
  C++ and the driver are never removed.

### Removed
- bstrings, rla, EZ Viewer and VSCMount from the catalogue: a full run
  removes them from a workstation that has them (folders, PATH entries,
  shortcuts).

### Changed
- The Zimmerman tools follow the vendor to .NET 10: they need the .NET
  Desktop Runtime 10 line, and a full run removes the Desktop Runtime 9 line
  the script installed for them.
- AmcacheParser, SQLECmd, SrumECmd, SumECmd and WxTCmd get a `Temp`
  folder the account may write to (their 2026.10 builds copy evidence
  databases there); their folders stay protected and on the PATH.
- The .NET check reads the runtimeconfig.json inside a single-file exe (the
  2026.10 Zimmerman GUI tools); a .NET tool with none is refused.
- Other platforms' SQLite libraries in AmcacheParser, WxTCmd and SQLECmd
  are left out.
- JumpList Explorer and SDB Explorer keep their settings (`Settings.xml`
  beside the exe, writable by the account).
- A dry run lists a Visual C++ Redistributable already installed as
  "Check", not "Install".
- Zimmerman versions are shown without their commit id (the records keep
  it); a check line with a long name puts its outcome on the next line; a
  result-block line names its tool once; a selective run without ancillary
  content shows no empty section; an update section with nothing to do
  says so ("Nothing to sync." for ancillary content); a version the script
  didn't install is named once on its check line; Visual C++ versions are
  shown in one form, and announced as "Checking" until its installer runs.
- A result-block group with one tool names that tool.
- Timeline Explorer's shortcuts sit directly on the Desktop and in the
  Start Menu, outside "EZ Tools".
- When a tool no longer in the catalogue keeps its PATH entry (it couldn't
  be removed), the one PATH line says so, with its name.

### Fixed
- A run limited with `-Family` or `-Tool` no longer writes inventory.csv
  without the prerequisite versions something else installed for tools
  outside the selection.

## 0.1.3 - 2026-10-23

Known issue: typed at an interactive Windows PowerShell prompt, where
PSReadLine is loaded (the default), it stops before any work ("this script
is for amd64 (x64) Windows; this machine is ."), changing nothing. Run it
as `powershell.exe -NoProfile -File .\Update-ForensicWorkstation.ps1`, or
use 0.2.1 (0.1.3 also can't update the Zimmerman tools since
2026-10-24).

First release. 0.1.0 to 0.1.2 were test builds only, never released.

### Added
- Installs and updates 25 Zimmerman (EZ) tools, 12 NirSoft tools and the
  Sysinternals Process Explorer, Autoruns, autorunsc and Disk2vhd, each from
  its vendor.
- Prerequisites from the builds chosen: each .NET runtime line a tool
  needs (the Desktop Runtime only for GUI tools), each kept at its latest
  patch.
- Only what changed is downloaded: each source's change marker is compared
  with the one recorded at install.
- EvtxECmd maps, RECmd batch files and SQLECmd maps checked on every run by
  their last upstream commit, synced with the tool's own `--sync` when it
  changed; files retired upstream are removed.
- Every download hashed (SHA-256), checked against the vendor's published
  hash where there is one and against the vendor's Authenticode signer;
  extracted files re-read from disk before use. A download with the same
  bytes as the installed copy is not swapped in; the installed exes' signer
  is checked instead.
- A tool running from its folder is neither updated nor removed (WARN).
- Only the x64 builds of the Sysinternals tools are installed; autorunsc
  has a folder of its own, so only command-line tools are on the PATH.
- A tool whose catalogue entry changed is reinstalled.
- The account may write only to the tools' settings: each NirSoft tool's
  `.cfg` file, and Registry Explorer's, ShellBags Explorer's and Timeline
  Explorer's settings folders; these are kept across updates.
- CLI tools on the machine PATH; GUI tools on the Desktop and in the Start
  Menu, in a folder per family.
- Clean-up of what the script installed and no longer needs: tools dropped
  from the catalogue, superseded prerequisite versions, unneeded runtime
  lines.
- Records under `ProgramData\ForensicWorkstation\`: a log per run,
  `state.json`, `inventory.csv`, `files.csv`.
- `-CheckOnly` (or `-WhatIf`): the dry run. `-Verify`: re-hash installed
  files against `files.csv`. `-Family`, `-Tool`: limit a run.
