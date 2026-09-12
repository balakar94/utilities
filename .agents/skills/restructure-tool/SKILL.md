---
name: restructure-tool
description: Use ONLY when the user asks to restructure, migrate, or import an existing script or utility into the tools/ baseline contract.
---

# Restructure Tool

Migrate an EXISTING messy script or utility into the baseline contract. This is the full restructuring order, end to end. Working language: English.

## When to use

Use ONLY when the user asks to restructure, migrate, import, or normalize an existing script, repo folder, gist, or snippet into `tools/<kebab-name>/`.
For greenfield creation use `new-tool`; for quality gates use `verify-tool`.

## Full order

### 1. Audit the candidate (before touching anything)

- Read the original code fully. List: purpose in one sentence, runtime and version, OS assumptions, args/flags, hardcoded paths, network calls, privilege needs (`sudo`?), destructive operations, secrets or tokens, external downloads.
- Decide: import as-is, harden first, or REJECT (one-off script with no reuse, binary without source, GUI-only flow, duplicate of an existing tool). State the decision and why.
- Pick the target name (`kebab-case`, verb first) and category (`automation|text-data|network-system|dev`). Check `tools/` and `docs/index.md` for collisions.

### 2. Scaffold the target

```bash
bash scripts/new-tool.sh --lang bash|python|powershell|ruby <kebab-name>
```

Never copy `templates/` by hand and never paste the old code over the scaffold blindly.

### 3. Migrate the logic

- Move the core logic into `main.sh`, `main.py`, `main.ps1`, or `main.rb` (keep ONE), preserving behavior first; refactor second.
- Normalize the CLI to the contract: `--help` (exit 0, prints `Usage:`), `--version`, no-arg run exits non-zero without destroying anything.
- Replace hardcoded `/Users/...` paths with args or env vars, document every path/port/env var.
- Pin everything: no `latest` tags, no unpinned actions/images/downloads; remote artifacts need SHA256 verification.
- Preserve provenance: keep original author/copyright notices, note the source in the README and `CHANGELOG.md`.

### 4. Harden to secure defaults

- Remove secrets, tokens, `.env` contents, private keys. Sample-only `.env.example` if needed.
- Remove `curl | bash` installers (clone → inspect → pinned tag instead).
- `sudo` only behind an explicit flag with README justification; default run must be unprivileged.
- No `chmod 777`, no setuid/setgid, no world-writable files; files `644`, dirs/executables `755` only with shebang.
- Destructive tools default to `--dry-run` or confirmation, with `--force` to proceed. Document undo/rollback in the README.
- Make it portable: bash 3.2 compatible, `sed -i.bak`, no `realpath`, no `date --iso-8601`, `pwd -P`.

### 5. Fill metadata.yaml and README.md

- `metadata.yaml`: `name == folder`, `description <= 12 words`, real `category`, `owner`, `status: incubating` (migrations always start as incubating), honest `compat`.
- `README.md` with the fixed template (max 300 words excluding code): Use for / Not for (+ pointer to the alternative when close), Requirements, Impact (`read-only` | `local` | `system` + writes/privileges/rollback), Quickstart (<5 min, expected output + exit code), Options, Failure modes table (symptom → cause → fix), Limitations, License & credits including the original source.

### 6. Test, example, and verify (same gate as CI)

- `tests/test_basic.<ext>`: native to the entrypoint; keep the scaffolded asserts green (executable,
  `--help`, no-arg safety, idempotent double run). Extend with real fixtures.
- `examples/basic.<ext>`: OPTIONAL; add one copy-pasteable run against a checked-in deterministic
  fixture when it earns its place.
- Run (native test + example if present):

```bash
bash tools/<name>/tests/test_basic.sh          # or test_basic.py | .rb | .ps1
bash tools/<name>/examples/basic.sh            # only if present
bash scripts/list-tools.sh --check
git ls-files '*.sh' | xargs -r shellcheck -S warning
```

- Equivalence check: run old vs new on the same fixture and `diff` the outputs before declaring the migration done.
- Finish with a `CHANGELOG.md` entry under `[Unreleased]` noting source + behavior changes, and open ONE single-purpose PR.

## Forbidden

- Importing secrets, absolute private paths, or unpinned dependencies into the baseline.
- `tools/category/tool` nesting, hand-editing `TOOLS.md`, cross-dependencies between `tools/*`.
- Silent behavior changes: any intentional change vs the original must be listed in the PR and README.
- Deleting or archiving the original source without explicit user approval and a noted replacement link.
