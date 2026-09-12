---
name: verify-tool
description: Use ONLY when the user asks to validate a tool or the repo baseline. Runs list-tools.sh --check, smoke tests, per-language lint (shellcheck/shfmt, py_compile, ruby -c, PSParser), and secret scans.
---

# Verify Tool

Validate one tool or the whole repo without bureaucracy. The base must stay green with 0 tools.

## When to use

Use ONLY when the user asks to verify, validate, or QA a tool or the repo baseline.
Creation belongs to `new-tool`, migration belongs to `restructure-tool`.

## Full order

### 1. Structure and metadata

```bash
bash scripts/list-tools.sh --check
```

Empty discovery = success, not failure. Per tool it enforces: `README.md` + `metadata.yaml` exist,
all 8 keys present (`name, description, category, owner, status, compat, impact, last_verified`),
`name == folder`, `status in incubating|stable|deprecated`, exactly one executable
`main.sh|main.py|main.ps1|main.rb` and its native `tests/test_basic.<ext>`. `examples/` is optional,
but if present must contain `basic.<ext>` matching the entrypoint.

`list-tools` does not read README prose: confirm manually that the tool README declares `Requirements`
and `Impact` (`read-only` | `local` | `system`).

### 2. Per-tool smoke (if any tools exist)

Run the ONE native test for the tool's language:

```bash
bash tools/<name>/tests/test_basic.sh          # bash tool
python3 tools/<name>/tests/test_basic.py       # python tool
ruby tools/<name>/tests/test_basic.rb          # ruby tool
```

```powershell
pwsh -NoProfile -NonInteractive -File tools/<name>/tests/test_basic.ps1   # powershell tool
```

If `examples/basic.<ext>` exists, run it with the same runner.

Expected asserts: entrypoint exists and is executable, `--help` exits 0 and prints `Usage:`,
no-arg run exits non-zero without side effects, double `--help` is idempotent (`diff` clean),
`trap` removes temp dirs. SKIP (exit 0, loud `SKIP:`) when the `pwsh`/`ruby` runner is missing locally.

### 3. Per-language lint and format (whichever files exist; empty = pass)

```bash
git ls-files '*.sh' | xargs -r shellcheck -S warning
shfmt -d -i 2 -ci -sr scripts templates tools
git ls-files '*.py' | xargs -r -n1 python3 -m py_compile
git ls-files '*.rb' | xargs -r -n1 ruby -c
```

Powershell (`.ps1`) is checked by PSParser tokenize in CI; locally ensure `pwsh -NoProfile -NonInteractive -File <tool>/main.ps1 --help` exits 0.

Note: tests are plain scripts with no skip path — a missing runtime is a real failure, not a pass.
CI has all four runtimes.

### 4. Secrets, risks, and permissions

```bash
grep -R "curl.*|.*\(ba\)\?sh" tools/ scripts/ templates/ || true
grep -R "/Users/" tools/ scripts/ templates/ || true
grep -R "chmod 777" tools/ scripts/ templates/ || true
find tools scripts templates -perm -o+w -o -perm -4000 -o -perm -2000 2>/dev/null || true
```

Zero hits expected. Any hit blocks the PR. For Python tools also run `python3 -m py_compile`.

## Report

State what ran (exact commands + exit codes + first stderr lines). Never invent APIs, config keys, repo facts, or test results. On failure give a minimal repro:

```bash
rm -rf /tmp/verify-<tool> && bash tools/<tool>/tests/test_basic.sh
```
