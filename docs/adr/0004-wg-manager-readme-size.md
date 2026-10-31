# ADR 0004: Reference README exception for wg-manager

- Status: accepted
- Date: 2026-10-31

## Context

`docs/new-tool-checklist.md` asks for a full-template `README.md` of at most 300 words excluding
code. `wg-manager` is a `system` tool with a large operational surface: two network backends, three
firewall engines, four IPv6 modes, a declarative spec, an installer with a manifest, exit codes,
recovery and a real-host validation matrix. Its README is intentionally the operator reference and
is far above that limit; splitting it would either duplicate the source of truth or hide recovery
steps from the person running the tool at 3 a.m.

The 300-word rule is a checklist guideline, not a CI gate: `scripts/list-tools.sh` validates the
required keys and sections, not the word count.

## Decision

`tools/wg-manager/README.md` is an accepted exception to the 300-word guideline:

- It remains the single source of truth for commands, flags, impact, rollback and troubleshooting.
- It must keep the required headings (`Requirements`, `Impact`, and the template sections) and stay
  current with the code; every behavior change updates it in the same PR.
- Real-host validation lives in `docs/validation/wg-manager.md`, linked from `Limits & status`.
- New tools still follow the 300-word guideline; a tool that outgrows it must add its own ADR rather
  than silently ignoring the checklist.

## Consequences

- Operators get complete, searchable recovery documentation in the tool folder.
- The checklist remains meaningful for new tools without forcing a docs split that would drift.
- If the README becomes unmaintainable, revisit this ADR and split the reference into
  `docs/wg-manager/` with the README as a short index.
