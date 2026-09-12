# New tool checklist

Copy into the PR. All checked or the PR does not merge.

- [ ] Free `kebab-case` name and isolated `tools/<name>/` folder
- [ ] Valid `metadata.yaml` (`name == folder`, `status: incubating`, `impact: read-only|local|system`,
  `compat` real: `all` unless the tool is OS-specific)
- [ ] Full-template `README.md` (≤300 words excluding code)
- [ ] `README.md` declares `Requirements` and `Impact`
- [ ] If `system` or third-party deps: dry run by default, rollback documented, stricter review
- [ ] Exactly ONE executable entrypoint (`main.sh`|`main.py`|`main.ps1`|`main.rb`, `chmod +x`)
- [ ] Native test `tests/test_basic.<ext>` matches the entrypoint and is green (`--help`, happy path, idempotency)
- [ ] (Optional) `examples/basic.<ext>` runs copy-paste in <5 min
- [ ] `scripts/list-tools.sh --check` (or `list-tools.ps1 -Check`) green
- [ ] Lint clean for its language: `shellcheck`+`shfmt` (bash), `py_compile` (python), `ruby -c` (ruby), PSParser (powershell)
- [ ] No secrets, no `curl | bash`, no default `sudo`, no absolute paths
- [ ] `docs/index.md` and `TOOLS.md` updated (via `list-tools.sh`)
- [ ] `CHANGELOG.md` entry under `[Unreleased]`
