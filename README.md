# Utilities

<!-- markdownlint-disable MD013 -->
[![CI](https://github.com/balakar94/utilities/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/balakar94/utilities/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Platforms](https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20Windows-informational.svg)](#requirements)
[![Languages](https://img.shields.io/badge/tools-bash%20%7C%20python%20%7C%20powershell%20%7C%20ruby-9cf.svg)](#requirements)
[![PRs welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)
<!-- markdownlint-enable MD013 -->

A curated collection of handy utilities for the everyday life of any developer, sysadmin, or DevOps.<br>
One folder = one isolated tool — dependency-free and non-invasive by default.

## Overview

This repo holds small utilities that solve one concrete problem and stay in use.

If a tool falls out of use or outgrows this repo, it gets archived or promoted to its own repo.

This is not an awesome-list nor a services monorepo. It is a shared baseline.

## Quickstart (30 seconds)

**macOS / Linux (bash):**

```bash
git clone https://github.com/balakar94/utilities.git
cd utilities
ls tools/
```

**Windows (PowerShell 7+):**

```powershell
git clone https://github.com/balakar94/utilities.git
Set-Location utilities
Get-ChildItem tools
```

Then:

1. Pick a tool from the [catalog](docs/index.md).
2. Open its folder `tools/<name>/` and read its `README.md`.
3. Follow its quickstart. Every tool runs isolated in its own folder.

## Requirements

- **macOS 14+** or **Linux** with bash 3.2+ (macOS) / bash 5.x (Linux).
- **Windows 10+** with PowerShell 7+ (`pwsh`). Bash tools need Git for Windows or WSL.
- **Python 3.11+** and **Ruby 3.0+** only when the tool you use needs them.

Each tool declares its exact `compat` in its own `metadata.yaml`.

## Tool index

Browse the curated catalog in [`docs/index.md`](docs/index.md), grouped by problem.
The complete, always-current table is generated in [`TOOLS.md`](TOOLS.md) by
`scripts/list-tools.sh` — never edited by hand.

To propose the first tool, open an Issue with the `proposal` label.

## How to choose

Choose by problem, not by stack: read `Use for / Not for` on each tool card.

If torn between two, pick the simpler, better-documented one.

## Ground rules

- One folder = one tool, `kebab-case` name, no cross-dependencies.
- Every tool ships `README.md` + `metadata.yaml` + executable entrypoint + 1 example + 1 test,
  with a bash twin and a PowerShell twin.
- No secrets, no `curl | bash`, no `sudo` by default, no `chmod 777`.
- Everything must be triable in <5 min by following its README.

Details in [`CONTRIBUTING.md`](CONTRIBUTING.md) and [`docs/conventions.md`](docs/conventions.md).

## Dependencies & impact

Tools are dependency-free and non-invasive by default: Python uses the standard library, shell uses
builtins, and nothing installs globally or writes outside its own folder. Every tool declares its
impact in `metadata.yaml` (`impact:`) and details it in its own `README.md`:

- **read-only** — changes nothing on your machine. Remote effects (API calls) are expected here and
  belong in the tool's `Impact` section.
- **local** — writes only inside its own folder or an output directory you pass.
- **system** — installs software, modifies files outside its folder, or needs `sudo`/root.

A `system` tool, or one with third-party dependencies, is the exception. It must declare exactly what
it touches (paths, packages, privileges) plus a rollback, default to a dry run, pin and checksum
anything it downloads, use `sudo` only behind an explicit flag, and pass a stricter review. If it
cannot meet this, it is not accepted.

## Contribute

Propose before coding: short Issue → discussion → small PR.

**macOS / Linux:**

```bash
bash scripts/new-tool.sh --lang bash my-tool
bash scripts/list-tools.sh --check
```

**Windows:** use the PowerShell twins (no bash required):

```powershell
pwsh scripts/new-tool.ps1 -Lang powershell my-tool
pwsh scripts/list-tools.ps1 -Check
```

Read [`CONTRIBUTING.md`](CONTRIBUTING.md) for the template, checklist, and archival policy.

## License

`Apache-2.0` by default (see [`LICENSE`](LICENSE)). A tool may declare another compatible license
in its own `README.md`; the tool license wins for that folder.

Keep notices and attribution when reusing code.
