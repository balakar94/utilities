# Security Policy

## Scope

Utilities and docs in this repo. Covers code someone clones and runs on their machine or CI.

Out of scope: forks, downstream modifications, deployments you build with these tools.

## Reporting a vulnerability

- **Do not open a public Issue.** Use the repo's GitHub Private Vulnerability Reporting.
- Include: affected tool, commit/tag, minimal PoC, impact, reproduction steps.
- Target: triage in 3 days, fix per severity, advisory via GitHub Security Advisory. 90-day coordinated disclosure.

## Secure-defaults policy (normative)

- No `curl | bash` / `wget | sh`. Only: clone → inspect → pinned tag.
- No `sudo` by default. If a tool needs privileges: explicit flag + justification in README.
- No `chmod 777`, setuid/setgid, or world-writable files.
- Remote artifacts require a verified SHA256 checksum before running. No unpinned `latest` tags.
- **Zero secrets in the repo:** no tokens, keys, `.env`, `.pem`. Use env vars + a secret manager. Sample-only `.env.example`.
- Fail-closed, least-privilege, no auto-update or telemetry by default.

## Contribution bar

- Signed commits (SSH/GPG) recommended.
- `secret-scan` (gitleaks + push protection) must pass.
- CODEOWNERS review for `scripts/`, `.github/`, `SECURITY.md`, `LICENSE*`.

## After a leak

Rotate and revoke the secret, purge with `git filter-repo` (deleting in a new commit is not enough), and notify maintainers.
