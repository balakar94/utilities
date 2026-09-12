# Changelog

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/). This project uses SemVer.

## [Unreleased]

- Impact levels clarified: `impact` describes what the tool changes on **your machine**. A tool that
  only calls a remote API (like `ionos-dnssec`) is `read-only`; remote effects stay documented in the
  README `Impact` section.
- `TOOLS.md` keeps its table, but tool names and categories are written with a non-breaking hyphen
  (U+2011): GitHub's `overflow-wrap: break-word` no longer split `ionos-dnssec` and
  `network-system` at narrow viewports (verified at 700px and 900px). The description column just
  wraps more.
- `compat` convention: `all` when the tool has no OS-specific code (runtime goes in `Requirements`);
  the README header drops the redundant `Compat:` field, which stays machine-readable in
  `metadata.yaml`.
- Per-language tests: each tool ships ONE native `tests/test_basic.<ext>` matching its entrypoint
  (`sh`|`py`|`ps1`|`rb`) instead of both `.sh` and `.ps1` twins; `examples/` is now optional
  (`new-tool --no-examples`). CI dispatches by language and runs `main.py`/`main.rb` on both OSes,
  which removes the PowerShell twin's silent `python3` skip (false green on Windows). Scaffold and
  `list-tools` now enforce exactly one entrypoint. See `docs/adr/0002-per-language-tests.md`.
- Initial repo skeleton with zero tools.
- First-class language support for all four: bash, python, powershell (`main.ps1`), ruby (`main.rb`) —
  template entrypoints, `new-tool.sh --lang`, `list-tools.sh` check, per-language CI jobs
  (`shellcheck`/`shfmt`, `py_compile`, `ruby -c`, PSParser), `restructure-tool` skill.
- Harness-neutral agent config: skills live in `.agents/skills/`, no harness-specific config files
  (`AGENTS.md` stays as the universal entry point).
- Pre-commit audit fixes: `last_verified` key enforced by `list-tools.sh`, per-language PR checklist,
  per-`--lang` README entrypoint, SKIP guards in examples, English-only `.gitignore`.
- Windows support: `.gitignore` covers Windows/Ruby/Linux junk; every tool ships pwsh twins
  (`examples/basic.ps1`, `tests/test_basic.ps1`); new `smoke-windows` CI job on windows-latest.
- CI now runs tool behavior: new `smoke-linux` job (tests + examples on ubuntu-24.04);
  `smoke-windows` also runs examples. Removed hand-maintained index tables from `README.md`
  and `docs/index.md` to kill drift (`TOOLS.md` stays the generated source of truth).
- Governance: `.github/dependabot.yml` for pinned actions, `.gitattributes` covers rb/ps1/json,
  anti-drift note in `AGENTS.md` (docs canonical, skills are pointers).
- Docs polish: `README.md` gains status badges, correct clone URL, and explicit Windows guidance;
  `CODEOWNERS` points at the real maintainer handle.
- CI polish: readable job names (`CI / Shell: shellcheck`, `CI / Smoke: Windows`, ...) and a
  required `GITHUB_TOKEN` passed to the gitleaks secret scan.
- PowerShell twins for the repo scripts: `scripts/common.ps1`, `scripts/new-tool.ps1`,
  `scripts/list-tools.ps1`. Windows no longer needs bash to scaffold or validate; CI cross-checks
  that both twins generate the same `TOOLS.md`.
- Dependency bumps: `actions/checkout` v7, `actions/setup-node` v7, `actions/setup-python` v7,
  `gitleaks/gitleaks-action` v3 (Dependabot PRs reconciled in one verified bump).
- Policy: tools are dependency-free and non-invasive by default. Every tool README must declare
  `Requirements` and `Impact` (`read-only` | `local` | `system`); `system` tools or ones with
  third-party deps need a dry run, a documented rollback, pinned + checksummed installs and a
  stricter review. The impact is enforced: `metadata.yaml` requires `impact:` and both
  `list-tools` twins validate it.
- Removed `.pre-commit-config.yaml` (it was never installed and only duplicated CI).

## [0.1.0] - 2026-09-12

### Added

- Base structure: `README.md`, `docs/`, `templates/tool-template/`, `scripts/`, `tools/`.
- Governance: `LICENSE`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SECURITY.md`, `CODEOWNERS`.
- Automation: `scripts/new-tool.sh`, `scripts/list-tools.sh`, `scripts/common.sh`, CI in `.github/workflows/ci.yml`.
- Agent config: `AGENTS.md`, `new-tool` and `verify-tool` skills.
