# Contributing

> Read this before opening an Issue or PR.

## 1. What we accept

Small utilities, with an owner, with real recurrent use.

Good candidate: solves one concrete problem in <5 min, fits in one folder, has a reproducible example.
Bad candidate: one-off script, binary without source, wrapper requiring manual GUI steps, duplicate of something existing.

Tools are dependency-free and non-invasive by default. A tool that installs software, modifies files
outside its own folder, or needs `sudo` is the exception: declare it (see `Requirements` and `Impact`
below) and expect a stricter review.

Describe: problem → user → usage frequency. Max 40 words.

## 2. How to propose

1. Search `tools/` and `docs/index.md` to make sure it does not exist yet.
2. Open an Issue `[proposal] kebab-case-name — problem in 6 words`.
3. Wait for 1 approval before coding.

## 3. How to add

```bash
# macOS / Linux
bash scripts/new-tool.sh --lang bash my-tool   # add --no-examples to skip examples/
# 1. Edit tools/my-tool/metadata.yaml (description, category, owner)
# 2. Edit tools/my-tool/README.md (full template)
# 3. Implement tools/my-tool/main.sh
# 4. Keep tools/my-tool/tests/test_basic.sh green (native to the language)
# 5. bash scripts/list-tools.sh --check
```

```powershell
# Windows (PowerShell 7+), no bash required
pwsh scripts/new-tool.ps1 -Lang powershell my-tool
pwsh scripts/list-tools.ps1 -Check
```

One folder per tool. One tool per PR (unless you justify why multi-tool).

## 4. Naming & layout

- `kebab-case`, lowercase, no accents, 2–48 chars. Verb first when possible: `rename-photos`, `check-latency`.
- Forbidden: `CamelCase`, spaces, `_`, cryptic abbreviations (`util1`, `mytool-final-v2`).
- Required layout:

```text
tools/<name>/
  README.md
  metadata.yaml
  main.sh | main.py | main.ps1 | main.rb    (executable, keep ONE)
  tests/test_basic.sh | .py | .ps1 | .rb   (native to the entrypoint, required)
  examples/basic.sh | .py | .ps1 | .rb     (optional, native to the entrypoint)
```

## 5. PR checklist (required)

- [ ] `kebab-case` name and isolated folder, no cross-dependencies
- [ ] Tool `README.md` with full template (purpose, non-goals, requirements, example)
- [ ] `README.md` declares `Requirements` and `Impact` (`read-only` | `local` | `system`)
- [ ] If `system` or third-party deps: dry run by default, rollback documented, deps pinned + checksummed
- [ ] Valid `metadata.yaml` (`name == folder`, `status: incubating|stable|deprecated`)
- [ ] Tested clean in <5 min (README steps are copy-paste)
- [ ] Native test `tests/test_basic.<ext>` green locally (matches the entrypoint)
- [ ] `shellcheck -S warning` + `shfmt -d` clean (bash), `python3 -m py_compile` (python),
  `ruby -c` (ruby), PSParser clean (powershell)
- [ ] No secrets, no `curl | bash`, no `sudo` by default, no `chmod 777`, no `/Users/...` paths
- [ ] Owner + `last-verified` date set; not a duplicate
- [ ] Safe rollback: deleting `tools/<name>/` restores the previous state

## 6. How to deprecate / archive

1. Open an Issue `[retire] <name> — reason + replacement + date`.
2. Set `status: deprecated` in `metadata.yaml` and a banner on top of the README for 30 days.
3. After the period, move to `tools/_archived/<name>/` or delete if unused.

Lifecycle: `incubating (90 days to prove use) → stable → deprecated (6 months) → archived`.

## 7. Conduct & licenses

Be brief, kind, and specific. Respect each tool license (`Apache-2.0` by default).
See `CODE_OF_CONDUCT.md` and `SECURITY.md`.
