# __TOOL_NAME__

> 1 line: what it does + for whom. Max 20 words.

Owner: `@user` | Last-verified: `YYYY-MM-DD` | Status: `incubating` | License: `Apache-2.0`

## Use for

- Yes-case 1
- Yes-case 2

Max 30 words.

## Not for

- No-case 1 → use X instead
- No-case 2 → use Y instead

## Requirements

- Runtime: none beyond the OS (or `python >= 3.11`, stdlib only).
- Environment: none (or `SOMETHING_API_KEY`).
- Network: none (or the hosts it contacts).

## Impact

- Level: `read-only` (or `local` / `system`).
- Writes: none (or the paths it creates or modifies).
- Privileges: none (or the explicit flag needed for `sudo`).
- Rollback: n/a (or how to undo).

Max 40 words. A `system` tool must run as a dry run by default and document a rollback.

## Quickstart

Must run in <5 min.

```bash
./tools/__TOOL_NAME__/main.sh --help
```

Expected result: `...` / exit `0`.

## Options

- `--help`: show help. Example: `main.sh --help`.
- `--version`: show version. Example: `main.sh --version`.

Max 6 bullets, real flags only. Bullets (not a table) so any flag length passes lint.

## Limits & status

- Known failure 1 → fix.
- Not tested with: ...

## License & credits

License: `Apache-2.0` · Owner: `@___` · Contact: `___`
