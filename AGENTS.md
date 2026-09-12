# AGENTS.md

> Instructions for AI agents (humans: see `README.md` and `CONTRIBUTING.md`).

## What this repo is

A curated baseline of general-purpose utilities. One folder = one isolated tool in `tools/<kebab-name>/`.
Zero tools installed yet; the base must stay green with 0 tools.

## Structure (do not change without ADR)

```text
README.md / CHANGELOG.md / TOOLS.md (generated, never edit by hand)
docs/index.md (catalog) / docs/conventions.md / docs/new-tool-checklist.md / docs/adr/
templates/tool-template/ (scaffold source)
scripts/common + new-tool + list-tools (.sh and .ps1 twins)
tools/<name>/{README.md, metadata.yaml, main.sh|main.py|main.ps1|main.rb,
  tests/test_basic.sh|.py|.ps1|.rb (native to the entrypoint),
  examples/basic.sh|.py|.ps1|.rb (optional, native to the entrypoint)}
.agents/skills/{new-tool,verify-tool,restructure-tool}/SKILL.md (harness-neutral, auto-loaded by several harnesses)
.github/{CODEOWNERS, pull_request_template.md, workflows/ci.yml, ISSUE_TEMPLATE/}
```

- Flat under `tools/`: `tools/category/tool` is forbidden. The category goes in `metadata.yaml`.
- `TOOLS.md` regenerates with `scripts/list-tools.sh`. Never edit by hand.
- Language: English everywhere. Fixed template headings.

## Per-tool contract (required)

`README.md` + `metadata.yaml` (keys: `name, description, category, owner, status, compat, impact,
last_verified`; `name == folder`, `status ∈ incubating|stable|deprecated`,
`impact ∈ read-only|local|system`) + exactly one executable entrypoint
`main.sh|main.py|main.ps1|main.rb` + its native test `tests/test_basic.<ext>` (required) and
`examples/basic.<ext>` (optional). `ext` follows the entrypoint: `sh`, `py`, `ps1` or `rb`.
The README must declare `Requirements` and `Impact`. See `docs/adr/0002-per-language-tests.md`.

Rules: `kebab-case` 2–48 chars, no cross-dependencies, no secrets, no `curl|bash`, no `sudo` by default,
no `chmod 777`, no absolute `/Users/...` paths, bash 3.2 (macOS) and bash 5 (Linux) compatible.
Portable `sed -i.bak`, no `realpath`, no `date --iso-8601`. Dependency-free and non-invasive by
default; a `system` tool or one with third-party deps must declare impact, default to a dry run,
document a rollback and pass a stricter review.

## Commands

```bash
# macOS / Linux
bash scripts/new-tool.sh --lang bash|python|powershell|ruby <kebab-name>
bash scripts/list-tools.sh --check
bash tools/<name>/tests/test_basic.sh          # native test (bash tool)
python3 tools/<name>/tests/test_basic.py       # native test (python tool)
ruby tools/<name>/tests/test_basic.rb          # native test (ruby tool)
git ls-files '*.sh' | xargs -r shellcheck -S warning
```

```powershell
# Windows (PowerShell 7+) — native twins, no bash needed
pwsh scripts/new-tool.ps1 -Lang bash|python|powershell|ruby <kebab-name>
pwsh scripts/list-tools.ps1 -Check
pwsh tools/<name>/tests/test_basic.ps1         # native test (powershell tool)
```

Both twins must agree: they validate the same contract and generate the same `TOOLS.md`.
CI cross-checks this on Linux and Windows. Per-tool tests are native to each entrypoint.

CI must pass with 0 tools (empty discovery = success, not failure).

## Skills

- `new-tool`: only when the user asks to create/add a tool. Use `scripts/new-tool.sh`, never copy by hand.
- `verify-tool`: only to validate a tool (`--check` + smoke + lint + secrets).
- `restructure-tool`: only to migrate an existing script into the baseline contract.
- Single source of truth: `docs/` (conventions + checklists). Skills are thin pointers, not parallel
  docs — change `docs/` first, then the skill, or the skill lies.
- Never invent APIs, config keys, repo facts, or test results. Verify with real commands.

## Permissions & safety

No commits, pushes, or PRs unless explicitly requested. Before commit: `git status`, `git diff`.
Never secrets. Minimal reversible changes.
