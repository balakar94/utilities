# Conventions

Minimum contract so the baseline scales from 0 to 50 tools.

## Layout

- Flat under `tools/`: `tools/<kebab-name>/`. `tools/<category>/<name>` is forbidden.
- Category lives only in `metadata.yaml` + `docs/index.md`.
- `TOOLS.md` is generated, never edit by hand.

## Naming

- `kebab-case`, `^[a-z0-9]+(-[a-z0-9]+)*$`, 2–48 chars. Verb first when possible.
- Reserved: `common`, `template`, `test`, `scripts`, `tools`, `templates`.

## metadata.yaml

```yaml
name: my-tool            # == folder name
description: What it does in max 12 words
category: automation|text-data|network-system|dev
owner: "@user"
status: incubating|stable|deprecated
compat: all              # or macOS, Linux | Windows 10+ | ...
impact: read-only|local|system
last_verified: 2026-09-12  # keep current; CI enforces presence
```

`compat` is an OS claim, not a formality: use `all` when the tool has no OS-specific code (the
runtime lives in the README `Requirements`); list only real targets otherwise. CI validates: file
exists, has all 8 keys, `name == folder`, valid `status`, valid `impact`,
exactly one executable entrypoint and its native `tests/test_basic.<ext>`.

## Languages

First-class (the four): `bash` (`main.sh`), `python` (`main.py`, >= 3.11),
`powershell` (`main.ps1`, pwsh 7+), `ruby` (`main.rb`, >= 3.0).

- Scaffold with `bash scripts/new-tool.sh --lang bash|python|powershell|ruby <kebab-name>`
  (`ps1` accepted as alias of `powershell`; `--no-examples` skips `examples/`).
- CI per language, all green on empty discovery: `shellcheck` + `shfmt` (bash),
  `py_compile` (python), `ruby -c` (ruby), PSParser tokenize (powershell).
- Local runners: macOS ships `ruby`; `pwsh` needs `brew install --cask powershell`.
  Native tests are plain scripts with no skip path; CI always has all four runtimes.
- Each tool ships ONE test, native to its entrypoint: `main.sh` → `tests/test_basic.sh`,
  `main.py` → `tests/test_basic.py`, `main.ps1` → `tests/test_basic.ps1`,
  `main.rb` → `tests/test_basic.rb`. CI runs it on every OS runner that matches its `compat`
  declaration (`main.sh` on Linux, `main.ps1` on Windows, `main.py`/`main.rb` on runners
  matching `compat`). See `docs/adr/0002-per-language-tests.md` and `docs/adr/0003-os-compat-in-ci-smoke.md`.
- `examples/` is optional. If present, it must contain `basic.<ext>` matching the entrypoint.
- The repo scripts still ship both twins: `scripts/*.sh` and `scripts/*.ps1`. They validate the same
  contract and must generate byte-identical `TOOLS.md`; CI cross-checks this on both OSes.
- Proposing a fifth language: template entrypoint + native test + `new-tool.sh` lang +
  `list-tools.sh` check + CI job + this section. One PR, ADR entry if it adds a toolchain.

## Dependencies & impact

Default: dependency-free and non-invasive. Python uses the standard library; shell uses builtins.
Nothing installs globally, nothing writes outside the tool folder.

Every tool declares its impact in `metadata.yaml` (`impact:`) and details it in its `README.md`:

- `read-only` — changes nothing on your machine (no local writes). Remote effects (API calls) are
  expected here and must be documented in the README `Impact` section.
- `local` — writes only inside its own folder or an output directory passed in.
- `system` — installs software, modifies files outside its folder, or needs `sudo`/root.

A `system` tool, or one with third-party dependencies, is the exception and must:

- declare paths, packages and privileges in the README `Impact` section, plus a rollback;
- default to a dry run; destructive actions need an explicit flag;
- pin every dependency and verify checksums; no `curl | bash`, no post-install scripts, no telemetry;
- keep `sudo` behind an explicit flag, never by default;
- pass a stricter review. If it cannot meet this, it is rejected.

## Portable shell (macOS + Linux)

- `#!/usr/bin/env bash` + `set -euo pipefail`.
- Bash 3.2 compatible: no assoc arrays, `mapfile`, or `&>>`.
- Portable `sed -i.bak` + `rm *.bak`. No `realpath`, no `date --iso-8601`. Use `pwd -P`.
- Logs to stderr, data to stdout. Exit codes: `0` ok, `2` usage error, `1` failure.

## Forbidden

Secrets, `curl | bash`, `sudo` by default, `chmod 777`, binaries without source,
`/Users/...` paths, cross-dependencies between `tools/*`, undisclosed installs or writes outside the
tool folder.
