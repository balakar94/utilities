# ADR 0002: Per-language tests, optional examples

- Status: accepted
- Date: 2026-09-12

## Context

The per-tool contract required both `tests/test_basic.sh` and `tests/test_basic.ps1` for every tool,
plus both example twins. For a Python or Ruby tool that is duplication: the harness was a shell
wrapper whose only job was to exec the interpreter the tool already requires. Worse, the PowerShell
twin dispatched `.py` to `python3` and silently skipped (`exit 0`) when it was missing — on Windows
the launcher is usually `python`, so a Python tool could pass Windows CI without ever running.

## Decision

- Tests are native to the tool's language. Exactly one entrypoint (`main.*`) and its matching
  `tests/test_basic.<ext>`:
  `main.sh` → `test_basic.sh`, `main.py` → `test_basic.py`, `main.ps1` → `test_basic.ps1`,
  `main.rb` → `test_basic.rb`.
- `examples/` is optional. If present it must contain `basic.<ext>` matching the entrypoint.
- CI runs each tool's native test on every OS that ships its runtime: `main.sh` on Linux,
  `main.ps1` on Windows, `main.py`/`main.rb` on both.
- The repo-level `scripts/*.sh` + `scripts/*.ps1` twins stay: they are the baseline's own tooling,
  and both must still generate byte-identical `TOOLS.md`.

## Consequences

- One test file per tool instead of two; no shell wrapper around Python/Ruby logic.
- Python and Ruby tools are actually exercised on both CI OSes (the silent-skip false green is gone).
- Language-aware discovery in `scripts/list-tools.{sh,ps1}` and `.github/workflows/ci.yml`.
- `examples/` no longer blocks a tool; the README Quickstart is the mandatory on-ramp.
- Scaffold removes every non-chosen language, its test and its example, so nothing mismatched ships.
