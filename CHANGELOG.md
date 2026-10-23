# Changelog

Notable changes to `Update-ForensicWorkstation.ps1`. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.1.3 - 2026-10-23

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
