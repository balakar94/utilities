## What / Why (1-3 lines)

## How tested

```bash
bash scripts/list-tools.sh --check
bash tools/<name>/tests/test_basic.sh   # or the native test: test_basic.py | .rb | .ps1
```

## Checklist

- [ ] Single purpose: adds/updates one tool only (or justifies why multi-tool)
- [ ] Native test `tests/test_basic.<ext>` (matching the entrypoint) passes locally
- [ ] Lint clean for its language: `shellcheck`+`shfmt` (bash), `py_compile` (python),
  `ruby -c` (ruby), PSParser (powershell)
- [ ] Docs: `README.md` (purpose, example, requirements) + valid `metadata.yaml`
  (`name == folder`) + `CHANGELOG.md` entry; `TOOLS.md` regenerated, never hand-edited
- [ ] Impact declared in README (`read-only` / `local` / `system`); `system` or third-party deps
  mean dry run by default, documented rollback, pinned + checksummed installs
- [ ] No side effects by default: safe re-run, no network/`sudo`/`rm -rf $HOME` without explicit flag
- [ ] No secrets or private paths: no tokens, keys, or `/Users/...`
- [ ] Manual run pasted or `gh run view` link under "How tested"
- [ ] Safe rollback: deleting `tools/<name>/` restores the previous state
