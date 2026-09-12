# ionos-dnssec

> Interactive manager for DNSSEC DS records on IONOS DNS zones (create, update, delete).

Owner: `@balakar94` | Last-verified: `2026-09-12` | Status: `incubating` | License: `Apache-2.0`

## Use for

- Adding, updating or deleting the DS record IONOS accepts for a DNSSEC-signed zone.
- Operators who prefer a guided, confirm-before-send flow.

## Not for

- Generating keys or signing a zone → use your signer (BIND, Knot, registrar).
- Unattended or bulk automation → it is interactive only.

## Requirements

- Runtime: Python >= 3.11, standard library only.
- Environment: `IONOS_COLOR` (`always|auto|never`) and `IONOS_NO_CLEAR` optional; `NO_COLOR` is ignored.
- Network: HTTPS to `api.hosting.ionos.com`. Needs an IONOS API key (public prefix + secret).

## Impact

- Level: `read-only` — it writes nothing to this machine (no files, installs or `sudo`).
- Remote effect: creates, updates and deletes DS records on your IONOS zones via the API.
- Privileges: none; needs network access and a valid API key.
- Safeguard: every change is shown and confirmed first; delete confirms twice.
- Rollback: restore the content/TTL shown before the change, or re-create a deleted record.

## Quickstart

```bash
python3 tools/ionos-dnssec/main.py --lang en
```

Expected: boxed menu (Language → API key → zone → DS action), exit `0`; `Ctrl-C` exits `130`.
Credential-free check: `--self-test`.

## Options

- `--lang {en,es,de}`: skip language selection.
- `--color {always,auto,never}` / `--no-color`: force or disable ANSI colors.
- `--no-clear`: keep the screen between menu jumps.
- `--self-test`: run offline self-checks (`0` pass, `1` fail).
- `--version` / `--help`: version and usage.

## Limits & status

- Interactive only: no `--dry-run`, no unattended mode.
- CI never calls the live API, so HTTP paths are unexercised there.
- DS changes are manual to roll back.

## License & credits

License: `Apache-2.0` · Owner: `@balakar94` · Contact: `@balakar94`
